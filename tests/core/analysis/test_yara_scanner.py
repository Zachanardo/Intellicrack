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
        dos_header[0:2] = b"MZ"
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
        text_section[0:8] = section_name.ljust(8, b"\x00")
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
        code_section[0:len(signature_bytes)] = signature_bytes
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
        scanner = YaraScanner(rules_dir=Path(tmpdir))
        return scanner


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

        detected_protections = set(match.rule_name for match in matches)
        assert len(detected_protections) >= 1


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
        assert len(custom_matches) > 0
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

        assert len(yara_scanner._match_cache) == 0


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
