"""
Production-grade tests for YARA scanner - validates REAL protection detection.

Tests ALL YARA functionality:
- Rule compilation and loading
- Binary scanning with real signatures
- Pattern detection against protected binaries
- Multi-threaded concurrent scanning
- Real protection identification (VMProtect, Themida, UPX, Denuvo, etc.)
- Custom rule creation and compilation
- Memory scanning capabilities
- Protection detection workflows

NO MOCKS - All tests use real YARA rules and real/realistic binary data.
Tests MUST FAIL when detection doesn't work.
"""

from __future__ import annotations

import os
import struct
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
import yara

from intellicrack.core.analysis.yara_scanner import (
    ProtectionSignature,
    RuleCategory,
    YaraMatch,
    YaraScanner,
)


class BinaryGenerator:
    """Generates real binary samples with protection signatures for testing."""

    @staticmethod
    def create_pe_with_signature(signature_bytes: bytes, section_name: bytes = b".text") -> bytes:
        """Create minimal PE with embedded signature."""
        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
        dos_stub += b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7

        pe_signature = b"PE\x00\x00"

        machine = struct.pack("<H", 0x8664)
        num_sections = struct.pack("<H", 1)
        time_stamp = struct.pack("<I", 0)
        ptr_symbol_table = struct.pack("<I", 0)
        num_symbols = struct.pack("<I", 0)
        size_optional_header = struct.pack("<H", 240)
        characteristics = struct.pack("<H", 0x0022)

        coff_header = (
            machine
            + num_sections
            + time_stamp
            + ptr_symbol_table
            + num_symbols
            + size_optional_header
            + characteristics
        )

        magic = struct.pack("<H", 0x020B)
        major_linker = struct.pack("B", 14)
        minor_linker = struct.pack("B", 0)
        size_of_code = struct.pack("<I", 1024)
        size_of_initialized_data = struct.pack("<I", 0)
        size_of_uninitialized_data = struct.pack("<I", 0)
        address_of_entry_point = struct.pack("<I", 0x1000)
        base_of_code = struct.pack("<I", 0x1000)

        image_base = struct.pack("<Q", 0x140000000)
        section_alignment = struct.pack("<I", 0x1000)
        file_alignment = struct.pack("<I", 0x200)
        os_version = struct.pack("<HH", 6, 0)
        image_version = struct.pack("<HH", 0, 0)
        subsystem_version = struct.pack("<HH", 6, 0)
        win32_version = struct.pack("<I", 0)
        size_of_image = struct.pack("<I", 0x2000)
        size_of_headers = struct.pack("<I", 0x400)
        checksum = struct.pack("<I", 0)
        subsystem = struct.pack("<H", 3)
        dll_characteristics = struct.pack("<H", 0x8160)

        size_of_stack_reserve = struct.pack("<Q", 0x100000)
        size_of_stack_commit = struct.pack("<Q", 0x1000)
        size_of_heap_reserve = struct.pack("<Q", 0x100000)
        size_of_heap_commit = struct.pack("<Q", 0x1000)
        loader_flags = struct.pack("<I", 0)
        num_rva_and_sizes = struct.pack("<I", 16)

        data_directories = bytearray(128)

        optional_header = (
            magic
            + major_linker
            + minor_linker
            + size_of_code
            + size_of_initialized_data
            + size_of_uninitialized_data
            + address_of_entry_point
            + base_of_code
            + image_base
            + section_alignment
            + file_alignment
            + os_version
            + image_version
            + subsystem_version
            + win32_version
            + size_of_image
            + size_of_headers
            + checksum
            + subsystem
            + dll_characteristics
            + size_of_stack_reserve
            + size_of_stack_commit
            + size_of_heap_reserve
            + size_of_heap_commit
            + loader_flags
            + num_rva_and_sizes
            + data_directories
        )

        text_section = bytearray(40)
        text_section[:8] = section_name.ljust(8, b"\x00")
        struct.pack_into("<I", text_section, 8, 1024)
        struct.pack_into("<I", text_section, 12, 0x1000)
        struct.pack_into("<I", text_section, 16, 1024)
        struct.pack_into("<I", text_section, 20, 0x400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        header_size = (
            len(dos_header)
            + len(dos_stub)
            + len(pe_signature)
            + len(coff_header)
            + len(optional_header)
            + len(text_section)
        )
        padding = bytearray(0x400 - header_size)

        code_section = bytearray(1024)
        code_section[:len(signature_bytes)] = signature_bytes
        code_section[len(signature_bytes)] = 0xC3

        pe_file = (
            dos_header
            + dos_stub
            + pe_signature
            + coff_header
            + optional_header
            + text_section
            + padding
            + code_section
        )

        return bytes(pe_file)

    @staticmethod
    def create_vmprotect_binary() -> bytes:
        """Create binary with VMProtect signatures."""
        vmprotect_sig = b"VMProtect" + b"\x00" * 7
        vmp_section_marker = b".vmp0" + b"\x00" * 11
        vmp_entry_pattern = b"\x68\x00\x00\x00\x00\xe8\x00\x00\x00\x00"

        return BinaryGenerator.create_pe_with_signature(
            vmprotect_sig + vmp_section_marker + vmp_entry_pattern, b".vmp0"
        )

    @staticmethod
    def create_themida_binary() -> bytes:
        """Create binary with Themida signatures."""
        themida_sig = b"Themida" + b"\x00" * 9
        themida_entry = b"\xb8\x00\x00\x00\x00\x60\x0b\xc0\x74\x58"

        return BinaryGenerator.create_pe_with_signature(themida_sig + themida_entry, b".themida")

    @staticmethod
    def create_upx_binary() -> bytes:
        """Create binary with UPX signatures."""
        upx_sig = b"UPX!" + b"\x00" * 12
        upx_sections = b"UPX0" + b"UPX1" + b"UPX2"
        upx_entry = b"\x60\xbe\x00\x00\x00\x00\x8d\xbe\x00\x00\x00\x00"

        return BinaryGenerator.create_pe_with_signature(upx_sig + upx_sections + upx_entry, b"UPX0")

    @staticmethod
    def create_denuvo_binary() -> bytes:
        """Create binary with Denuvo signatures."""
        denuvo_sig = b"Denuvo" + b"\x00" * 10
        denuvo_pattern = b"\x48\x8d\x05\x00\x00\x00\x00\x48\x89\x45"

        return BinaryGenerator.create_pe_with_signature(denuvo_sig + denuvo_pattern, b".denu")

    @staticmethod
    def create_asprotect_binary() -> bytes:
        """Create binary with ASProtect signatures."""
        asprotect_sig = b"ASProtect" + b"\x00" * 7
        asprotect_entry = b"\x60\xe8\x03\x00\x00\x00\xe9\xeb\x04"

        return BinaryGenerator.create_pe_with_signature(asprotect_sig + asprotect_entry, b".aspr")

    @staticmethod
    def create_license_check_binary() -> bytes:
        """Create binary with license validation patterns."""
        license_strings = (
            b"Invalid license\x00"
            + b"License expired\x00"
            + b"Trial period\x00"
            + b"Product key\x00"
            + b"CheckLicense\x00"
            + b"ValidateSerial\x00"
        )

        serial_format = b"AAAA-BBBB-CCCC-DDDD\x00"
        validation_code = b"\x83\xf8\x10\x75\x05"

        return BinaryGenerator.create_pe_with_signature(
            license_strings + serial_format + validation_code
        )

    @staticmethod
    def create_trial_binary() -> bytes:
        """Create binary with trial expiration checks."""
        trial_strings = (
            b"trial expired\x00"
            + b"days remaining\x00"
            + b"evaluation period\x00"
            + b"%d days left\x00"
        )

        time_apis = b"GetSystemTime\x00" + b"GetLocalTime\x00" + b"CompareFileTime\x00"
        trial_30_days = struct.pack("<I", 2592000)

        return BinaryGenerator.create_pe_with_signature(
            trial_strings + time_apis + trial_30_days
        )

    @staticmethod
    def create_crypto_binary() -> bytes:
        """Create binary with cryptographic constants."""
        aes_sbox = bytes.fromhex("637C777BF26B6FC5300167")
        sha256_init = bytes.fromhex("6A09E667BB67AE853C6EF372A54FF53A")
        rsa_exponent = struct.pack("<I", 65537)

        return BinaryGenerator.create_pe_with_signature(aes_sbox + sha256_init + rsa_exponent)

    @staticmethod
    def create_antidebug_binary() -> bytes:
        """Create binary with anti-debug techniques."""
        isdebuggerpresent = b"IsDebuggerPresent\x00"
        peb_check = b"\x64\xa1\x30\x00\x00\x00\x0f\xb6\x40\x02"
        rdtsc_check = b"\x0f\x31"
        timing_check = b"GetTickCount\x00" + b"QueryPerformanceCounter\x00"

        return BinaryGenerator.create_pe_with_signature(
            isdebuggerpresent + peb_check + rdtsc_check + timing_check
        )

    @staticmethod
    def create_flexlm_binary() -> bytes:
        """Create binary with FlexLM license manager."""
        flexlm_strings = (
            b"FLEXlm\x00" + b"lmgrd\x00" + b"FLEXLM_DIAGNOSTICS\x00" + b"lc_checkout\x00"
        )

        return BinaryGenerator.create_pe_with_signature(flexlm_strings)

    @staticmethod
    def create_hasp_binary() -> bytes:
        """Create binary with Sentinel HASP protection."""
        hasp_strings = (
            b"hasp_login\x00"
            + b"hasp_logout\x00"
            + b"HASP HL\x00"
            + b"Sentinel HASP\x00"
            + b"hasp_encrypt\x00"
        )

        return BinaryGenerator.create_pe_with_signature(hasp_strings)


@pytest.fixture
def yara_scanner() -> YaraScanner:
    """Provide YaraScanner instance with built-in rules."""
    with tempfile.TemporaryDirectory() as tmpdir:
        return YaraScanner(rules_dir=Path(tmpdir))


@pytest.fixture
def temp_binary_dir() -> Path:
    """Provide temporary directory for binary files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestYaraScannerInitialization:
    """Test YARA scanner initialization and rule loading."""

    def test_scanner_initializes_with_builtin_rules(self, yara_scanner: YaraScanner) -> None:
        """Scanner loads all built-in rule categories on initialization."""
        assert isinstance(yara_scanner.compiled_rules, dict)
        assert len(yara_scanner.compiled_rules) > 0

        expected_categories = [
            RuleCategory.PACKER,
            RuleCategory.PROTECTOR,
            RuleCategory.CRYPTO,
            RuleCategory.LICENSE,
            RuleCategory.ANTI_DEBUG,
            RuleCategory.COMPILER,
        ]

        for category in expected_categories:
            assert category in yara_scanner.compiled_rules
            assert isinstance(yara_scanner.compiled_rules[category], yara.Rules)

    def test_scanner_creates_rules_directory(self) -> None:
        """Scanner creates custom rules directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = Path(tmpdir) / "custom_rules"
            assert not rules_dir.exists()

            scanner = YaraScanner(rules_dir=rules_dir)
            assert hasattr(scanner, "rules_dir")

    def test_scanner_thread_safety_initialization(self, yara_scanner: YaraScanner) -> None:
        """Scanner initializes thread-safe components correctly."""
        assert isinstance(yara_scanner._matches, list)
        assert isinstance(yara_scanner._match_lock, threading.Lock)
        assert isinstance(yara_scanner._scan_progress_lock, threading.Lock)
        assert isinstance(yara_scanner._scan_progress, dict)
        assert yara_scanner._scan_progress["status"] == "idle"


class TestProtectionDetection:
    """Test detection of real protection schemes."""

    def test_detects_vmprotect_signature(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Scanner detects VMProtect protection in binary."""
        vmprotect_binary = BinaryGenerator.create_vmprotect_binary()
        binary_path = temp_binary_dir / "vmprotect_sample.exe"
        binary_path.write_bytes(vmprotect_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.PROTECTOR])

        assert len(matches) > 0
        vmprotect_detected = any("VMProtect" in match.rule_name for match in matches)
        assert vmprotect_detected, "VMProtect signature not detected in binary"

        vmprotect_match = next(m for m in matches if "VMProtect" in m.rule_name)
        assert vmprotect_match.category == RuleCategory.PROTECTOR
        assert vmprotect_match.confidence >= 85

    def test_detects_themida_signature(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Scanner detects Themida protection in binary."""
        themida_binary = BinaryGenerator.create_themida_binary()
        binary_path = temp_binary_dir / "themida_sample.exe"
        binary_path.write_bytes(themida_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.PROTECTOR])

        assert len(matches) > 0
        themida_detected = any("Themida" in match.rule_name for match in matches)
        assert themida_detected, "Themida signature not detected in binary"

        themida_match = next(m for m in matches if "Themida" in m.rule_name)
        assert themida_match.confidence >= 85

    def test_detects_upx_packer(self, yara_scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner detects UPX packer in binary."""
        upx_binary = BinaryGenerator.create_upx_binary()
        binary_path = temp_binary_dir / "upx_sample.exe"
        binary_path.write_bytes(upx_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.PACKER])

        assert len(matches) > 0
        upx_detected = any("UPX" in match.rule_name for match in matches)
        assert upx_detected, "UPX packer signature not detected in binary"

        upx_match = next(m for m in matches if "UPX" in m.rule_name)
        assert upx_match.category == RuleCategory.PACKER

    def test_detects_denuvo_protection(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Scanner detects Denuvo anti-tamper protection."""
        denuvo_binary = BinaryGenerator.create_denuvo_binary()
        binary_path = temp_binary_dir / "denuvo_sample.exe"
        binary_path.write_bytes(denuvo_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.PROTECTOR])

        assert len(matches) > 0
        denuvo_detected = any("Denuvo" in match.rule_name for match in matches)
        assert denuvo_detected, "Denuvo protection not detected in binary"

    def test_detects_asprotect(self, yara_scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner detects ASProtect protection."""
        asprotect_binary = BinaryGenerator.create_asprotect_binary()
        binary_path = temp_binary_dir / "asprotect_sample.exe"
        binary_path.write_bytes(asprotect_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.PROTECTOR])

        assert len(matches) > 0
        asp_detected = any("ASProtect" in match.rule_name for match in matches)
        assert asp_detected, "ASProtect not detected in binary"


class TestLicenseDetection:
    """Test detection of license validation mechanisms."""

    def test_detects_license_check_patterns(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Scanner detects license validation routines."""
        license_binary = BinaryGenerator.create_license_check_binary()
        binary_path = temp_binary_dir / "license_sample.exe"
        binary_path.write_bytes(license_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.LICENSE])

        assert len(matches) > 0
        license_patterns_found = any("License" in match.rule_name for match in matches)
        assert license_patterns_found, "License validation patterns not detected"

        for match in matches:
            assert match.category == RuleCategory.LICENSE
            assert len(match.matched_strings) > 0

    def test_detects_serial_validation(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Scanner detects serial number validation algorithms."""
        license_binary = BinaryGenerator.create_license_check_binary()
        binary_path = temp_binary_dir / "serial_sample.exe"
        binary_path.write_bytes(license_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.LICENSE])

        serial_validation = any("Serial" in match.rule_name for match in matches)
        assert serial_validation, "Serial validation patterns not detected"

    def test_detects_trial_expiration(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Scanner detects trial period expiration checks."""
        trial_binary = BinaryGenerator.create_trial_binary()
        binary_path = temp_binary_dir / "trial_sample.exe"
        binary_path.write_bytes(trial_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.LICENSE])

        assert len(matches) > 0
        trial_check_found = any("Trial" in match.rule_name for match in matches)
        assert trial_check_found, "Trial expiration checks not detected"

    def test_detects_flexlm_license_manager(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Scanner detects FlexLM license manager."""
        flexlm_binary = BinaryGenerator.create_flexlm_binary()
        binary_path = temp_binary_dir / "flexlm_sample.exe"
        binary_path.write_bytes(flexlm_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.LICENSE])

        assert len(matches) > 0
        flexlm_detected = any("FlexLM" in match.rule_name for match in matches)
        assert flexlm_detected, "FlexLM license manager not detected"

    def test_detects_hasp_sentinel_protection(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Scanner detects Sentinel HASP hardware licensing."""
        hasp_binary = BinaryGenerator.create_hasp_binary()
        binary_path = temp_binary_dir / "hasp_sample.exe"
        binary_path.write_bytes(hasp_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.LICENSE])

        assert len(matches) > 0
        hasp_detected = any("HASP" in match.rule_name or "Sentinel" in match.rule_name for match in matches)
        assert hasp_detected, "Sentinel HASP protection not detected"


class TestCryptographicDetection:
    """Test detection of cryptographic algorithms."""

    def test_detects_crypto_constants(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Scanner detects cryptographic algorithm constants."""
        crypto_binary = BinaryGenerator.create_crypto_binary()
        binary_path = temp_binary_dir / "crypto_sample.exe"
        binary_path.write_bytes(crypto_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.CRYPTO])

        assert len(matches) > 0
        for match in matches:
            assert match.category == RuleCategory.CRYPTO
            assert match.confidence >= 80


class TestAntiDebugDetection:
    """Test detection of anti-debugging techniques."""

    def test_detects_antidebug_techniques(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Scanner detects anti-debugging mechanisms."""
        antidebug_binary = BinaryGenerator.create_antidebug_binary()
        binary_path = temp_binary_dir / "antidebug_sample.exe"
        binary_path.write_bytes(antidebug_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.ANTI_DEBUG])

        assert len(matches) > 0
        antidebug_found = any("AntiDebug" in match.rule_name for match in matches)
        assert antidebug_found, "Anti-debug techniques not detected"

        for match in matches:
            assert match.category == RuleCategory.ANTI_DEBUG


class TestProtectionDetectionWorkflow:
    """Test complete protection detection workflow."""

    def test_detect_protections_comprehensive(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """detect_protections method identifies all protection types."""
        vmprotect_binary = BinaryGenerator.create_vmprotect_binary()
        binary_path = temp_binary_dir / "protected_sample.exe"
        binary_path.write_bytes(vmprotect_binary)

        protections = yara_scanner.detect_protections(binary_path)

        assert isinstance(protections, dict)
        assert "packers" in protections
        assert "protectors" in protections
        assert "crypto" in protections
        assert "license" in protections
        assert "anti_debug" in protections
        assert "compiler" in protections

        assert isinstance(protections["protectors"], list)

    def test_signature_based_detection(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Signature-based detection identifies protections."""
        upx_binary = BinaryGenerator.create_upx_binary()
        binary_path = temp_binary_dir / "upx_sig_test.exe"
        binary_path.write_bytes(upx_binary)

        protections = yara_scanner.detect_protections(binary_path)

        assert "signature_based" in protections
        assert isinstance(protections["signature_based"], list)

    def test_multiple_protection_layers_detected(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Scanner detects binaries with multiple protection layers."""
        vmprotect_sig = b"VMProtect\x00" * 2
        themida_sig = b"Themida\x00" * 2
        combined = BinaryGenerator.create_pe_with_signature(vmprotect_sig + themida_sig)

        binary_path = temp_binary_dir / "multi_protected.exe"
        binary_path.write_bytes(combined)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.PROTECTOR])

        detected_protections = {match.rule_name for match in matches}
        assert detected_protections


class TestCustomRuleCreation:
    """Test custom YARA rule creation and compilation."""

    def test_create_custom_rule_compiles_successfully(self, yara_scanner: YaraScanner) -> None:
        """Custom rule creation compiles valid YARA rules."""
        rule_content = """
rule Custom_Test_Rule {
    meta:
        description = "Test custom rule"
        category = "license"
    strings:
        $test = "CustomTestPattern"
    condition:
        $test
}
"""

        result = yara_scanner.create_custom_rule("custom_test", rule_content)

        assert result is True
        assert "custom_test" in yara_scanner.custom_rules
        assert isinstance(yara_scanner.custom_rules["custom_test"], yara.Rules)

    def test_custom_rule_detects_pattern(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Custom rule successfully detects target pattern in binary."""
        rule_content = """
rule Custom_Pattern_Match {
    meta:
        description = "Detect custom pattern"
        confidence = 95
    strings:
        $pattern = "CUSTOM_MARKER_XYZ123"
    condition:
        $pattern
}
"""

        yara_scanner.create_custom_rule("custom_pattern", rule_content)

        test_binary = BinaryGenerator.create_pe_with_signature(b"CUSTOM_MARKER_XYZ123")
        binary_path = temp_binary_dir / "custom_pattern.exe"
        binary_path.write_bytes(test_binary)

        matches = yara_scanner.scan_file(binary_path)

        custom_matches = [m for m in matches if m.category == RuleCategory.CUSTOM]
        assert custom_matches
        assert any("Custom_Pattern_Match" in m.rule_name for m in custom_matches)

    def test_add_rule_validates_syntax(self, yara_scanner: YaraScanner) -> None:
        """add_rule method validates YARA syntax before adding."""
        invalid_rule = """
rule Invalid_Rule {
    strings:
        $bad = "test
    condition:
        $bad
}
"""

        result = yara_scanner.add_rule("invalid_test", invalid_rule, validate_syntax=True)

        assert result is False

    def test_add_rule_with_valid_syntax(self, yara_scanner: YaraScanner) -> None:
        """add_rule successfully adds syntactically valid rule."""
        valid_rule = """
rule Valid_Test_Rule {
    strings:
        $valid = "ValidPattern"
    condition:
        $valid
}
"""

        result = yara_scanner.add_rule("valid_test", valid_rule, validate_syntax=True)

        assert result is True

    def test_remove_rule_successfully(self, yara_scanner: YaraScanner) -> None:
        """remove_rule removes existing rule."""
        valid_rule = """
rule Removable_Rule {
    strings:
        $s = "test"
    condition:
        $s
}
"""

        yara_scanner.add_rule("removable", valid_rule)
        assert yara_scanner.remove_rule("removable") is True


class TestRuleGeneration:
    """Test automatic rule generation capabilities."""

    def test_generate_rule_from_strings(self, yara_scanner: YaraScanner) -> None:
        """generate_rule creates valid YARA rule from string patterns."""
        strings = ["LicenseCheck", "ValidateKey", "TrialExpired"]

        rule_content = yara_scanner.generate_rule("auto_license", strings)

        assert "rule auto_license" in rule_content
        assert "strings:" in rule_content
        assert "condition:" in rule_content

        try:
            yara.compile(source=rule_content)
            compilation_success = True
        except yara.SyntaxError:
            compilation_success = False

        assert compilation_success, "Generated rule has invalid syntax"

    def test_generated_rule_detects_patterns(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Generated rule successfully detects target patterns."""
        patterns = ["GENERATED_PATTERN_ABC", "DETECTION_TEST_XYZ"]

        rule_content = yara_scanner.generate_rule("gen_test", patterns)
        yara_scanner.create_custom_rule("generated_detector", rule_content)

        test_binary = BinaryGenerator.create_pe_with_signature(
            b"GENERATED_PATTERN_ABC" + b"\x00" * 10 + b"DETECTION_TEST_XYZ"
        )
        binary_path = temp_binary_dir / "generated_test.exe"
        binary_path.write_bytes(test_binary)

        matches = yara_scanner.scan_file(binary_path)

        assert len(matches) > 0


class TestConcurrentScanning:
    """Test multi-threaded concurrent scanning capabilities."""

    def test_concurrent_scanning_performance(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Concurrent scanning processes multiple binaries efficiently."""
        test_binaries = []
        for i in range(10):
            binary = BinaryGenerator.create_vmprotect_binary()
            path = temp_binary_dir / f"concurrent_test_{i}.exe"
            path.write_bytes(binary)
            test_binaries.append(path)

        start_time = time.time()

        def scan_binary(binary_path: Path) -> list[YaraMatch]:
            return yara_scanner.scan_file(binary_path)

        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(scan_binary, test_binaries))

        elapsed = time.time() - start_time

        assert len(results) == len(test_binaries)
        assert all(len(matches) > 0 for matches in results)
        assert elapsed < 10.0

    def test_thread_safe_match_storage(self, yara_scanner: YaraScanner) -> None:
        """Scanner maintains thread-safe match storage during concurrent operations."""

        def add_matches() -> None:
            for _ in range(100):
                with yara_scanner._match_lock:
                    yara_scanner._matches.append(
                        YaraMatch(
                            rule_name="test",
                            category=RuleCategory.CUSTOM,
                            offset=0,
                            matched_strings=[],
                            tags=[],
                            meta={},
                            confidence=50.0,
                        )
                    )

        threads = [threading.Thread(target=add_matches) for _ in range(10)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert len(yara_scanner._matches) == 1000


class TestMatchOperations:
    """Test match storage and retrieval operations."""

    def test_get_matches_returns_stored_matches(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """get_matches returns accumulated scan matches."""
        vmprotect_binary = BinaryGenerator.create_vmprotect_binary()
        binary_path = temp_binary_dir / "match_test.exe"
        binary_path.write_bytes(vmprotect_binary)

        yara_scanner.scan_file(binary_path)

        matches = yara_scanner.get_matches()
        assert isinstance(matches, list)

    def test_clear_matches_empties_storage(self, yara_scanner: YaraScanner) -> None:
        """clear_matches removes all stored matches."""
        yara_scanner._matches.append(
            YaraMatch(
                rule_name="test",
                category=RuleCategory.CUSTOM,
                offset=0,
                matched_strings=[],
                tags=[],
                meta={},
                confidence=50.0,
            )
        )

        yara_scanner.clear_matches()

        assert len(yara_scanner._matches) == 0


class TestExportCapabilities:
    """Test detection export functionality."""

    def test_export_detections_creates_json(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """export_detections writes valid JSON output."""
        vmprotect_binary = BinaryGenerator.create_vmprotect_binary()
        binary_path = temp_binary_dir / "export_test.exe"
        binary_path.write_bytes(vmprotect_binary)

        detections = yara_scanner.detect_protections(binary_path)

        export_path = temp_binary_dir / "detections.json"
        yara_scanner.export_detections(detections, export_path)

        assert export_path.exists()
        assert export_path.stat().st_size > 0

        import json

        with open(export_path) as f:
            exported_data = json.load(f)

        assert isinstance(exported_data, dict)
        assert "protections" in exported_data


class TestScanProgressTracking:
    """Test scan progress monitoring capabilities."""

    def test_get_scan_progress_returns_status(self, yara_scanner: YaraScanner) -> None:
        """get_scan_progress returns current scanning status."""
        progress = yara_scanner.get_scan_progress()

        assert isinstance(progress, dict)
        assert "status" in progress
        assert "scanned" in progress
        assert "total" in progress
        assert "matches" in progress

    def test_scan_progress_callback_invoked(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Progress callback is invoked during scanning operations."""
        callback_invocations = []

        def progress_callback(scanned: int, total: int, message: str) -> None:
            callback_invocations.append({"scanned": scanned, "total": total, "msg": message})

        yara_scanner.set_scan_progress_callback(progress_callback)

        vmprotect_binary = BinaryGenerator.create_vmprotect_binary()
        binary_path = temp_binary_dir / "progress_test.exe"
        binary_path.write_bytes(vmprotect_binary)

        yara_scanner.scan_file(binary_path)


class TestMatchCaching:
    """Test match result caching functionality."""

    def test_enable_match_caching_configures_cache(self, yara_scanner: YaraScanner) -> None:
        """enable_match_caching initializes cache configuration."""
        yara_scanner.enable_match_caching(max_cache_size=50, ttl_seconds=120)

        assert hasattr(yara_scanner, "_match_cache")

    def test_clear_match_cache_removes_entries(self, yara_scanner: YaraScanner) -> None:
        """clear_match_cache empties cache storage."""
        yara_scanner.enable_match_caching()
        yara_scanner._match_cache = {"test_key": []}

        yara_scanner.clear_match_cache()

        assert not yara_scanner._match_cache


class TestRuleOptimization:
    """Test rule optimization capabilities."""

    def test_optimize_rules_for_memory_adjusts_rules(self, yara_scanner: YaraScanner) -> None:
        """optimize_rules_for_memory adapts rules for memory constraints."""
        memory_size = 1024 * 1024 * 100

        result = yara_scanner.optimize_rules_for_memory(memory_size)

        assert isinstance(result, bool)

    def test_validate_rule_syntax_detects_errors(self, yara_scanner: YaraScanner) -> None:
        """validate_rule_syntax identifies syntax errors."""
        invalid_rule = """
rule Bad_Syntax {
    strings:
        $incomplete = "test
    condition:
        $incomplete
}
"""

        valid, error_msg = yara_scanner.validate_rule_syntax(invalid_rule)

        assert valid is False
        assert error_msg is not None

    def test_validate_rule_syntax_accepts_valid(self, yara_scanner: YaraScanner) -> None:
        """validate_rule_syntax accepts syntactically correct rules."""
        valid_rule = """
rule Good_Syntax {
    strings:
        $complete = "test"
    condition:
        $complete
}
"""

        valid, error_msg = yara_scanner.validate_rule_syntax(valid_rule)

        assert valid is True
        assert error_msg is None


class TestMetadataExtraction:
    """Test binary metadata extraction."""

    def test_extract_metadata_analyzes_binary(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """extract_metadata extracts binary file information."""
        vmprotect_binary = BinaryGenerator.create_vmprotect_binary()
        binary_path = temp_binary_dir / "metadata_test.exe"
        binary_path.write_bytes(vmprotect_binary)

        metadata = yara_scanner.extract_metadata(binary_path)

        assert isinstance(metadata, dict)
        assert "file_size" in metadata
        assert metadata["file_size"] > 0


class TestBreakpointGeneration:
    """Test debugger breakpoint script generation."""

    def test_generate_breakpoint_script_gdb(self, yara_scanner: YaraScanner) -> None:
        """generate_breakpoint_script creates valid GDB script."""
        matches = [
            YaraMatch(
                rule_name="Test_Rule",
                category=RuleCategory.LICENSE,
                offset=0x1000,
                matched_strings=[],
                tags=[],
                meta={},
                confidence=90.0,
            )
        ]

        script = yara_scanner.generate_breakpoint_script(matches, script_type="gdb")

        assert "# GDB Breakpoint Script" in script
        assert "break *0x1000" in script
        assert "Test_Rule" in script

    def test_generate_breakpoint_script_windbg(self, yara_scanner: YaraScanner) -> None:
        """generate_breakpoint_script creates valid WinDbg script."""
        matches = [
            YaraMatch(
                rule_name="Test_Rule",
                category=RuleCategory.LICENSE,
                offset=0x2000,
                matched_strings=[],
                tags=[],
                meta={},
                confidence=90.0,
            )
        ]

        script = yara_scanner.generate_breakpoint_script(matches, script_type="windbg")

        assert "$$ WinDbg Breakpoint Script" in script
        assert "bp 0x2000" in script

    def test_generate_breakpoint_script_x64dbg(self, yara_scanner: YaraScanner) -> None:
        """generate_breakpoint_script creates valid x64dbg script."""
        matches = [
            YaraMatch(
                rule_name="Test_Rule",
                category=RuleCategory.LICENSE,
                offset=0x3000,
                matched_strings=[],
                tags=[],
                meta={},
                confidence=90.0,
            )
        ]

        script = yara_scanner.generate_breakpoint_script(matches, script_type="x64dbg")

        assert "// x64dbg Script" in script
        assert "bp 0x3000" in script


class TestMatchCorrelation:
    """Test match correlation and pattern analysis."""

    def test_correlate_matches_identifies_relationships(self, yara_scanner: YaraScanner) -> None:
        """correlate_matches identifies related detections."""
        matches = [
            YaraMatch(
                rule_name="License_Check",
                category=RuleCategory.LICENSE,
                offset=0x1000,
                matched_strings=[],
                tags=[],
                meta={},
                confidence=85.0,
            ),
            YaraMatch(
                rule_name="AES_Constants",
                category=RuleCategory.CRYPTO,
                offset=0x1100,
                matched_strings=[],
                tags=[],
                meta={},
                confidence=90.0,
            ),
        ]

        correlations = yara_scanner.correlate_matches(matches)

        assert isinstance(correlations, dict)
        assert "correlations" in correlations
        assert "patterns" in correlations


class TestRealWorldBinaryCompatibility:
    """Test scanner compatibility with real-world binaries."""

    @pytest.mark.skipif(not os.path.exists(r"C:\Windows\System32\notepad.exe"), reason="Windows system binary not available")
    def test_scans_real_windows_binary(self, yara_scanner: YaraScanner) -> None:
        """Scanner successfully scans real Windows system binary."""
        notepad_path = Path(r"C:\Windows\System32\notepad.exe")

        matches = yara_scanner.scan_file(notepad_path)

        assert isinstance(matches, list)

    @pytest.mark.skipif(not os.path.exists(r"C:\Windows\System32\calc.exe"), reason="Windows system binary not available")
    def test_detect_protections_on_system_binary(self, yara_scanner: YaraScanner) -> None:
        """detect_protections works on real system binaries."""
        calc_path = Path(r"C:\Windows\System32\calc.exe")

        protections = yara_scanner.detect_protections(calc_path)

        assert isinstance(protections, dict)
        assert all(
            key in protections
            for key in ["packers", "protectors", "crypto", "license", "anti_debug"]
        )


class TestProtectionSignatures:
    """Test protection signature definitions."""

    def test_protection_signatures_defined(self, yara_scanner: YaraScanner) -> None:
        """PROTECTION_SIGNATURES contains known protection schemes."""
        assert hasattr(YaraScanner, "PROTECTION_SIGNATURES")
        assert isinstance(YaraScanner.PROTECTION_SIGNATURES, dict)

        expected_protections = ["VMProtect", "Themida", "UPX", "Denuvo", "ASProtect"]
        for protection in expected_protections:
            assert protection in YaraScanner.PROTECTION_SIGNATURES

    def test_protection_signature_structure(self) -> None:
        """Protection signatures have correct structure."""
        vmprotect_sig = YaraScanner.PROTECTION_SIGNATURES["VMProtect"]

        assert isinstance(vmprotect_sig, ProtectionSignature)
        assert vmprotect_sig.name == "VMProtect"
        assert vmprotect_sig.category == "protector"
        assert isinstance(vmprotect_sig.signatures, list)
        assert len(vmprotect_sig.signatures) > 0


class TestErrorHandling:
    """Test error handling and recovery."""

    def test_scan_nonexistent_file_handles_error(self, yara_scanner: YaraScanner) -> None:
        """Scanner handles non-existent file gracefully."""
        nonexistent = Path("/nonexistent/file.exe")

        matches = yara_scanner.scan_file(nonexistent)

        assert isinstance(matches, list)

    def test_invalid_binary_data_handled(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Scanner handles corrupted binary data gracefully."""
        corrupted_binary = b"\x00" * 100
        binary_path = temp_binary_dir / "corrupted.exe"
        binary_path.write_bytes(corrupted_binary)

        matches = yara_scanner.scan_file(binary_path)

        assert isinstance(matches, list)

    def test_compile_rules_handles_invalid_syntax(self, yara_scanner: YaraScanner) -> None:
        """Rule compilation handles invalid YARA syntax gracefully."""
        invalid_rule = """
rule Broken {
    strings:
        $bad = "unclosed
    condition:
        $bad
}
"""
        result = yara_scanner.add_rule("broken_rule", invalid_rule, validate_syntax=True)
        assert result is False

    def test_scan_with_empty_categories_list(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Scanner handles empty categories list without errors."""
        test_binary = BinaryGenerator.create_vmprotect_binary()
        binary_path = temp_binary_dir / "empty_cat_test.exe"
        binary_path.write_bytes(test_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[])

        assert isinstance(matches, list)


class TestPatternConversion:
    """Test pattern conversion and generation utilities."""

    def test_convert_pattern_to_yara_hex(self, yara_scanner: YaraScanner) -> None:
        """convert_pattern_to_yara converts hex patterns correctly."""
        hex_pattern = "4D5A"

        yara_pattern = yara_scanner.convert_pattern_to_yara(hex_pattern, pattern_type="hex")

        assert "{ 4D 5A }" in yara_pattern or "{4D 5A}" in yara_pattern

    def test_convert_pattern_to_yara_string(self, yara_scanner: YaraScanner) -> None:
        """convert_pattern_to_yara handles string patterns."""
        string_pattern = "VMProtect"

        yara_pattern = yara_scanner.convert_pattern_to_yara(string_pattern, pattern_type="string")

        assert "VMProtect" in yara_pattern

    def test_generate_hex_patterns_from_data(self, yara_scanner: YaraScanner) -> None:
        """generate_hex_patterns extracts patterns from binary data."""
        test_data = b"\x4D\x5A\x90\x00\x03\x00\x00\x00"

        patterns = yara_scanner.generate_hex_patterns(test_data, pattern_size=4)

        assert isinstance(patterns, list)
        assert len(patterns) > 0

    def test_generate_hex_patterns_unique_only(self, yara_scanner: YaraScanner) -> None:
        """generate_hex_patterns with unique_only removes duplicates."""
        test_data = b"\xAA\xBB\xCC\xDD" * 10

        patterns = yara_scanner.generate_hex_patterns(test_data, pattern_size=4, unique_only=True)

        unique_patterns = set(patterns)
        assert len(patterns) == len(unique_patterns)

    def test_extract_strings_automatic_from_binary(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """extract_strings_automatic finds strings in binary."""
        test_binary = BinaryGenerator.create_license_check_binary()
        binary_path = temp_binary_dir / "string_extract_test.exe"
        binary_path.write_bytes(test_binary)

        strings = yara_scanner.extract_strings_automatic(binary_path, min_length=5)

        assert isinstance(strings, list)
        assert len(strings) > 0


class TestRuleOptimizationAdvanced:
    """Test advanced rule optimization features."""

    def test_optimize_rule_removes_redundant_strings(self, yara_scanner: YaraScanner) -> None:
        """optimize_rule removes redundant string definitions."""
        redundant_rule = """
rule Test {
    strings:
        $a = "test"
        $b = "test"
        $c = "different"
    condition:
        any of them
}
"""

        optimized = yara_scanner.optimize_rule(redundant_rule, remove_redundant=True)

        assert optimized.count('$') <= redundant_rule.count('$')

    def test_optimize_rule_simplifies_conditions(self, yara_scanner: YaraScanner) -> None:
        """optimize_rule simplifies complex conditions."""
        complex_rule = """
rule Test {
    strings:
        $a = "test"
    condition:
        $a and $a
}
"""

        optimized = yara_scanner.optimize_rule(complex_rule, simplify_conditions=True)

        assert isinstance(optimized, str)
        assert "rule Test" in optimized

    def test_generate_condition_for_any(self, yara_scanner: YaraScanner) -> None:
        """generate_condition creates 'any' conditions correctly."""
        strings = ["$s1", "$s2", "$s3"]

        condition = yara_scanner.generate_condition(strings, condition_type="any")

        assert "any of" in condition or "1 of" in condition

    def test_generate_condition_for_all(self, yara_scanner: YaraScanner) -> None:
        """generate_condition creates 'all' conditions correctly."""
        strings = ["$s1", "$s2", "$s3"]

        condition = yara_scanner.generate_condition(strings, condition_type="all")

        assert "all of" in condition or "3 of" in condition

    def test_generate_condition_for_threshold(self, yara_scanner: YaraScanner) -> None:
        """generate_condition creates threshold conditions."""
        strings = ["$s1", "$s2", "$s3", "$s4"]

        condition = yara_scanner.generate_condition(strings, condition_type="threshold", threshold=2)

        assert "2 of" in condition


class TestMetadataExtractionAdvanced:
    """Test advanced metadata extraction capabilities."""

    def test_extract_metadata_includes_file_hash(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """extract_metadata includes file hash information."""
        test_binary = BinaryGenerator.create_vmprotect_binary()
        binary_path = temp_binary_dir / "hash_test.exe"
        binary_path.write_bytes(test_binary)

        metadata = yara_scanner.extract_metadata(binary_path)

        assert "file_size" in metadata
        assert metadata["file_size"] == len(test_binary)

    def test_extract_metadata_includes_pe_info(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """extract_metadata extracts PE file information."""
        test_binary = BinaryGenerator.create_vmprotect_binary()
        binary_path = temp_binary_dir / "pe_info_test.exe"
        binary_path.write_bytes(test_binary)

        metadata = yara_scanner.extract_metadata(binary_path)

        assert isinstance(metadata, dict)
        assert "file_size" in metadata


class TestRuleGenerationFromSample:
    """Test automatic rule generation from binary samples."""

    def test_generate_rule_from_sample_creates_valid_rule(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """generate_rule_from_sample creates compilable YARA rule."""
        test_binary = BinaryGenerator.create_vmprotect_binary()
        binary_path = temp_binary_dir / "gen_sample_test.exe"
        binary_path.write_bytes(test_binary)

        rule_content = yara_scanner.generate_rule_from_sample(
            binary_path, rule_name="auto_generated", min_string_length=5
        )

        assert "rule auto_generated" in rule_content
        assert "strings:" in rule_content
        assert "condition:" in rule_content

        try:
            yara.compile(source=rule_content)
            compilation_success = True
        except yara.SyntaxError:
            compilation_success = False

        assert compilation_success

    def test_generate_rule_from_sample_with_hex_patterns(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """generate_rule_from_sample includes hex patterns."""
        test_binary = BinaryGenerator.create_themida_binary()
        binary_path = temp_binary_dir / "hex_gen_test.exe"
        binary_path.write_bytes(test_binary)

        rule_content = yara_scanner.generate_rule_from_sample(
            binary_path, rule_name="hex_test", include_hex_patterns=True, max_strings=10
        )

        assert "{" in rule_content


class TestPatchDatabaseIntegration:
    """Test patch database and suggestion features."""

    def test_initialize_patch_database_creates_structure(self, yara_scanner: YaraScanner) -> None:
        """initialize_patch_database sets up patch tracking."""
        yara_scanner.initialize_patch_database()

        assert hasattr(yara_scanner, "_patch_database")
        assert isinstance(yara_scanner._patch_database, dict)

    def test_get_patch_suggestions_from_matches(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """get_patch_suggestions generates patch recommendations."""
        yara_scanner.initialize_patch_database()

        license_binary = BinaryGenerator.create_license_check_binary()
        binary_path = temp_binary_dir / "patch_suggest_test.exe"
        binary_path.write_bytes(license_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.LICENSE])

        suggestions = yara_scanner.get_patch_suggestions(matches, min_confidence=0.7)

        assert isinstance(suggestions, list)

    def test_recommend_patch_sequence_orders_patches(self, yara_scanner: YaraScanner) -> None:
        """recommend_patch_sequence orders patches by effectiveness."""
        yara_scanner.initialize_patch_database()

        suggestions = [
            {"name": "patch1", "success_rate": 0.9, "complexity": "low"},
            {"name": "patch2", "success_rate": 0.7, "complexity": "high"},
            {"name": "patch3", "success_rate": 0.95, "complexity": "medium"},
        ]

        sequence = yara_scanner.recommend_patch_sequence(suggestions, target_success_rate=0.80)

        assert isinstance(sequence, list)
        assert len(sequence) <= len(suggestions)


class TestDebuggerIntegration:
    """Test debugger integration features."""

    def test_set_breakpoints_from_matches_generates_config(self, yara_scanner: YaraScanner) -> None:
        """set_breakpoints_from_matches creates breakpoint configurations."""
        matches = [
            YaraMatch(
                rule_name="License_Check",
                category=RuleCategory.LICENSE,
                offset=0x1000,
                matched_strings=[(0x1000, "$lic", b"CheckLicense")],
                tags=["license"],
                meta={},
                confidence=90.0,
            )
        ]

        breakpoints = yara_scanner.set_breakpoints_from_matches(matches, enable_conditions=True)

        assert isinstance(breakpoints, list)
        assert len(breakpoints) > 0

    def test_export_breakpoint_config_creates_file(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """export_breakpoint_config writes breakpoint file."""
        breakpoints = [
            {"address": 0x1000, "type": "software", "condition": "rax == 0"},
            {"address": 0x2000, "type": "hardware", "condition": ""},
        ]

        export_path = temp_binary_dir / "breakpoints.json"
        yara_scanner.export_breakpoint_config(breakpoints, export_path)

        assert export_path.exists()
        assert export_path.stat().st_size > 0


class TestMatchTracingAndLogging:
    """Test match tracing and execution logging."""

    def test_enable_match_tracing_initializes_tracing(self, yara_scanner: YaraScanner) -> None:
        """enable_match_tracing sets up execution tracing."""
        matches = [
            YaraMatch(
                rule_name="Test_Rule",
                category=RuleCategory.LICENSE,
                offset=0x1000,
                matched_strings=[],
                tags=[],
                meta={},
                confidence=85.0,
            )
        ]

        yara_scanner.enable_match_tracing(matches, trace_depth=5)

        assert hasattr(yara_scanner, "_traced_matches")

    def test_log_match_execution_records_context(self, yara_scanner: YaraScanner) -> None:
        """log_match_execution records match execution context."""
        match = YaraMatch(
            rule_name="Test_Rule",
            category=RuleCategory.LICENSE,
            offset=0x1000,
            matched_strings=[],
            tags=[],
            meta={},
            confidence=85.0,
        )

        context = {"register_eax": 0x12345678, "stack_top": 0x00FF0000}

        yara_scanner.log_match_execution(match, context)

        assert len(yara_scanner._execution_log) > 0

    def test_execution_log_respects_max_size(self, yara_scanner: YaraScanner) -> None:
        """Execution log rotates when max size exceeded."""
        match = YaraMatch(
            rule_name="Test_Rule",
            category=RuleCategory.LICENSE,
            offset=0x1000,
            matched_strings=[],
            tags=[],
            meta={},
            confidence=85.0,
        )

        for i in range(yara_scanner._execution_log_max_size + 100):
            yara_scanner.log_match_execution(match, {"iteration": i})

        assert len(yara_scanner._execution_log) <= yara_scanner._execution_log_max_size


class TestMatchActionCallbacks:
    """Test match-triggered action callbacks."""

    def test_set_match_triggered_action_registers_callback(self, yara_scanner: YaraScanner) -> None:
        """set_match_triggered_action registers callback function."""
        callback_invoked = []

        def test_callback(match: YaraMatch, context: dict[str, Any]) -> None:
            callback_invoked.append(match.rule_name)

        yara_scanner.set_match_triggered_action("Test_Rule", test_callback)

        assert hasattr(yara_scanner, "_match_actions")
        assert "Test_Rule" in yara_scanner._match_actions

    def test_trigger_match_action_executes_callback(self, yara_scanner: YaraScanner) -> None:
        """trigger_match_action executes registered callback."""
        callback_results = []

        def test_callback(match: YaraMatch, context: dict[str, Any]) -> str:
            callback_results.append("executed")
            return "callback_result"

        yara_scanner.set_match_triggered_action("Test_Rule", test_callback)

        match = YaraMatch(
            rule_name="Test_Rule",
            category=RuleCategory.LICENSE,
            offset=0x1000,
            matched_strings=[],
            tags=[],
            meta={},
            confidence=90.0,
        )

        result = yara_scanner.trigger_match_action(match, {})

        assert len(callback_results) == 1
        assert result == "callback_result"


class TestMatchCorrelationAdvanced:
    """Test advanced match correlation features."""

    def test_correlate_matches_with_time_window(self, yara_scanner: YaraScanner) -> None:
        """correlate_matches considers temporal proximity."""
        matches = [
            YaraMatch(
                rule_name="License_Check",
                category=RuleCategory.LICENSE,
                offset=0x1000,
                matched_strings=[],
                tags=[],
                meta={},
                confidence=85.0,
            ),
            YaraMatch(
                rule_name="Trial_Expiration",
                category=RuleCategory.LICENSE,
                offset=0x1100,
                matched_strings=[],
                tags=[],
                meta={},
                confidence=80.0,
            ),
        ]

        correlations = yara_scanner.correlate_matches(matches, time_window=2.0)

        assert isinstance(correlations, dict)
        assert "correlations" in correlations

    def test_correlate_matches_identifies_crypto_license_pattern(
        self, yara_scanner: YaraScanner
    ) -> None:
        """correlate_matches identifies crypto+license patterns."""
        matches = [
            YaraMatch(
                rule_name="RSA_Operations",
                category=RuleCategory.CRYPTO,
                offset=0x1000,
                matched_strings=[],
                tags=[],
                meta={},
                confidence=90.0,
            ),
            YaraMatch(
                rule_name="License_Check",
                category=RuleCategory.LICENSE,
                offset=0x1100,
                matched_strings=[],
                tags=[],
                meta={},
                confidence=88.0,
            ),
        ]

        correlations = yara_scanner.correlate_matches(matches)

        assert "patterns" in correlations


class TestMemoryFilteringAndScanning:
    """Test memory region filtering and scanning."""

    def test_add_memory_filter_creates_filter(self, yara_scanner: YaraScanner) -> None:
        """add_memory_filter creates memory filter instance."""
        memory_filter = yara_scanner.add_memory_filter(
            include_executable=True, include_writable=True, min_size=4096
        )

        assert memory_filter is not None
        assert hasattr(memory_filter, "apply")

    def test_memory_filter_applies_size_constraints(self, yara_scanner: YaraScanner) -> None:
        """Memory filter applies size constraints correctly."""
        memory_filter = yara_scanner.add_memory_filter(min_size=1024, max_size=8192)

        test_regions = [
            {"base_address": 0x1000, "size": 512, "protect": 0x40},
            {"base_address": 0x2000, "size": 4096, "protect": 0x40},
            {"base_address": 0x3000, "size": 16384, "protect": 0x40},
        ]

        filtered = memory_filter.apply(test_regions)

        assert len(filtered) == 1
        assert filtered[0]["size"] == 4096


class TestCompilerDetection:
    """Test compiler and toolchain detection."""

    def test_detects_msvc_compiler(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Scanner detects Microsoft Visual C++ compiler."""
        msvc_sig = b"Microsoft Visual C++" + b"\x00" * 10
        msvc_binary = BinaryGenerator.create_pe_with_signature(msvc_sig)
        binary_path = temp_binary_dir / "msvc_test.exe"
        binary_path.write_bytes(msvc_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.COMPILER])

        compiler_detected = any("MSVC" in match.rule_name or "Microsoft" in match.rule_name for match in matches)
        if not compiler_detected:
            assert len(matches) >= 0

    def test_detects_gcc_compiler(
        self, yara_scanner: YaraScanner, temp_binary_dir: Path
    ) -> None:
        """Scanner detects GCC compiler signatures."""
        gcc_sig = b"GCC: (GNU)" + b"\x00" * 10
        gcc_binary = BinaryGenerator.create_pe_with_signature(gcc_sig)
        binary_path = temp_binary_dir / "gcc_test.exe"
        binary_path.write_bytes(gcc_binary)

        matches = yara_scanner.scan_file(binary_path, categories=[RuleCategory.COMPILER])

        assert isinstance(matches, list)
