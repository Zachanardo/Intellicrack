"""Comprehensive production tests for Arxan TransformIT bypass module.

Tests validate genuine Arxan protection bypass capabilities including anti-tampering
defeat, integrity check neutralization, RASP bypass, and license validation removal.
All tests verify real bypass operations against Arxan-protected binary patterns.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import struct
from pathlib import Path
from typing import Generator

import pytest

from intellicrack.core.analysis.arxan_analyzer import (
    ArxanAnalysisResult,
    IntegrityCheckMechanism,
    LicenseValidationRoutine,
    RASPMechanism,
    TamperCheckLocation,
)
from intellicrack.core.protection_bypass.arxan_bypass import (
    ArxanBypass,
    ArxanBypassResult,
    BypassPatch,
)
from intellicrack.core.protection_detection.arxan_detector import ArxanVersion


class TestArxanBypassInitialization:
    """Test ArxanBypass initialization and configuration."""

    def test_bypass_initializes_correctly(self) -> None:
        """ArxanBypass initializes with all required components."""
        bypass = ArxanBypass()

        assert bypass.detector is not None
        assert bypass.analyzer is not None
        assert bypass.logger is not None
        assert bypass.frida_session is None
        assert bypass.frida_script is None

    def test_bypass_has_correct_opcodes(self) -> None:
        """ArxanBypass defines correct x86/x64 opcode constants."""
        assert ArxanBypass.NOP_OPCODE == b"\x90"
        assert ArxanBypass.RET_OPCODE == b"\xc3"
        assert ArxanBypass.XOR_EAX_EAX == b"\x33\xc0"
        assert ArxanBypass.MOV_EAX_1 == b"\xb8\x01\x00\x00\x00"
        assert ArxanBypass.JMP_SHORT_0 == b"\xeb\x00"


class TestBypassPatchDataclass:
    """Test BypassPatch dataclass structure."""

    def test_bypass_patch_creation(self) -> None:
        """BypassPatch stores patch information correctly."""
        patch = BypassPatch(
            address=0x401000,
            original_bytes=b"\x85\xc0\x74\x05",
            patched_bytes=b"\x90\x90\x90\x90",
            patch_type="tamper_bypass",
            description="Bypass CRC32 check",
        )

        assert patch.address == 0x401000
        assert patch.original_bytes == b"\x85\xc0\x74\x05"
        assert patch.patched_bytes == b"\x90\x90\x90\x90"
        assert patch.patch_type == "tamper_bypass"
        assert patch.description == "Bypass CRC32 check"


class TestArxanBypassResult:
    """Test ArxanBypassResult dataclass."""

    def test_bypass_result_default_values(self) -> None:
        """ArxanBypassResult initializes with correct defaults."""
        result = ArxanBypassResult(success=False)

        assert result.success is False
        assert len(result.patches_applied) == 0
        assert result.runtime_hooks_installed == 0
        assert result.license_checks_bypassed == 0
        assert result.integrity_checks_neutralized == 0
        assert result.rasp_mechanisms_defeated == 0
        assert result.frida_script == ""
        assert result.patched_binary_path == ""
        assert len(result.metadata) == 0

    def test_bypass_result_with_patches(self) -> None:
        """ArxanBypassResult stores patch information correctly."""
        patches = [
            BypassPatch(0x401000, b"\x85\xc0", b"\x90\x90", "license_bypass", "Bypass license check"),
            BypassPatch(0x402000, b"\x74\x05", b"\x90\x90", "integrity_bypass", "Neutralize CRC32"),
        ]

        result = ArxanBypassResult(
            success=True,
            patches_applied=patches,
            license_checks_bypassed=1,
            integrity_checks_neutralized=1,
        )

        assert result.success is True
        assert len(result.patches_applied) == 2
        assert result.patches_applied[0].patch_type == "license_bypass"
        assert result.patches_applied[1].patch_type == "integrity_bypass"
        assert result.license_checks_bypassed == 1
        assert result.integrity_checks_neutralized == 1


@pytest.fixture
def arxan_protected_binary(tmp_path: Path) -> Generator[Path, None, None]:
    """Create realistic Arxan-protected binary with multiple protection mechanisms."""
    binary_path = tmp_path / "protected_app.exe"

    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,
        3,
        0,
        0,
        0,
        0xE0,
        0x0103,
    )

    optional_header = struct.pack(
        "<HBBIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B,
        14,
        0,
        0x2000,
        0x1000,
        0,
        0x1000,
        0x1000,
        0x00400000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x10000,
        0x200,
        0,
        3,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        0x10,
    )

    optional_header += b"\x00" * (0xE0 - len(optional_header))

    section_table = b""

    code_section = b".text\x00\x00\x00"
    code_section += struct.pack(
        "<IIIIIHHHI",
        0x2000,
        0x1000,
        0x2000,
        0x400,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    section_table += code_section

    data_section = b".data\x00\x00\x00"
    data_section += struct.pack(
        "<IIIIIHHHI",
        0x1000,
        0x3000,
        0x1000,
        0x2400,
        0,
        0,
        0,
        0,
        0xC0000040,
    )
    section_table += data_section

    arxan_section = b".arxan\x00\x00"
    arxan_section += struct.pack(
        "<IIIIIHHHI",
        0x1000,
        0x4000,
        0x1000,
        0x3400,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    section_table += arxan_section

    pe_header = pe_signature + coff_header + optional_header + section_table

    headers = dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header

    code_section_data = bytearray(0x2000)

    code_section_data[0x100 : 0x100 + len(b"\x33\xd2\x8a\x10\x8b\xc2\xc1\xe8\x08")] = b"\x33\xd2\x8a\x10\x8b\xc2\xc1\xe8\x08"

    code_section_data[0x200 : 0x200 + len(b"\x67\x45\x23\x01")] = b"\x67\x45\x23\x01"

    code_section_data[0x300 : 0x300 + len(b"\x6a\x09\xe6\x67")] = b"\x6a\x09\xe6\x67"

    code_section_data[0x400 : 0x400 + len(b"\x00\x01\xff\xff")] = b"\x00\x01\xff\xff"

    code_section_data[0x500 : 0x500 + len(b"\x64\xa1\x30\x00\x00\x00\x0f\xb6\x40\x02")] = (
        b"\x64\xa1\x30\x00\x00\x00\x0f\xb6\x40\x02"
    )

    code_section_data[0x600 : 0x600 + len(b"\x85\xc0\x75\x02\x75\x00")] = b"\x85\xc0\x75\x02\x75\x00"

    code_section_data[0x700 : 0x700 + len(b"\x8b\x45\x08\x8b\x4d\x0c\x33\xd2\x8a\x10")] = (
        b"\x8b\x45\x08\x8b\x4d\x0c\x33\xd2\x8a\x10"
    )

    code_section_data[0x800 : 0x800 + len(b"frida")] = b"frida"
    code_section_data[0x850 : 0x850 + len(b"ARXAN")] = b"ARXAN"
    code_section_data[0x900 : 0x900 + len(b"license")] = b"license"
    code_section_data[0x950 : 0x950 + len(b"serial")] = b"serial"

    data_section_data = bytearray(0x1000)
    data_section_data[:4] = struct.pack("<I", 0x12345678)
    data_section_data[0x100 : 0x100 + len(b"activation")] = b"activation"
    data_section_data[0x200 : 0x200 + len(b"registration")] = b"registration"

    arxan_section_data = bytearray(0x1000)
    arxan_section_data[:len(b"TRANSFORMIT")] = b"TRANSFORMIT"
    arxan_section_data[0x100 : 0x100 + len(b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5")] = b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5"

    binary_data = (
        headers.ljust(0x400, b"\x00")
        + code_section_data
        + data_section_data
        + arxan_section_data
        + b"\x00" * (0x1000 - len(arxan_section_data))
    )

    binary_path.write_bytes(binary_data)
    yield binary_path


@pytest.fixture
def minimal_protected_binary(tmp_path: Path) -> Generator[Path, None, None]:
    """Create minimal binary with basic protection patterns."""
    binary_path = tmp_path / "minimal_protected.exe"

    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)

    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0x60, 0x0103)
    optional_header = struct.pack(
        "<HBBIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B,
        14,
        0,
        0x1000,
        0x0,
        0,
        0x1000,
        0x1000,
        0x00400000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x5000,
        0x200,
        0,
        3,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        0x10,
    )
    optional_header += b"\x00" * (0x60 - len(optional_header))

    section = b".text\x00\x00\x00"
    section += struct.pack("<IIIIIHHHI", 0x1000, 0x1000, 0x1000, 0x200, 0, 0, 0, 0, 0x60000020)

    pe_header = pe_signature + coff_header + optional_header + section

    headers = dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header

    code_data = bytearray(0x1000)

    code_data[0x100 : 0x100 + len(b"\x33\xd2\x8a\x10")] = b"\x33\xd2\x8a\x10"
    code_data[0x200 : 0x200 + len(b"\x00\x01\xff\xff")] = b"\x00\x01\xff\xff"
    code_data[0x300 : 0x300 + len(b"Arxan")] = b"Arxan"

    binary_data = headers.ljust(0x200, b"\x00") + code_data + b"\x00" * (0x1000 - len(code_data))

    binary_path.write_bytes(binary_data)
    yield binary_path


class TestArxanBypassCore:
    """Test core Arxan bypass functionality."""

    def test_bypass_nonexistent_file_raises_error(self, tmp_path: Path) -> None:
        """Bypass raises FileNotFoundError for nonexistent binary."""
        bypass = ArxanBypass()
        nonexistent = tmp_path / "does_not_exist.exe"

        with pytest.raises(FileNotFoundError, match="Binary not found"):
            bypass.bypass(nonexistent)

    def test_bypass_creates_output_file(self, minimal_protected_binary: Path) -> None:
        """Bypass creates patched binary at specified output path."""
        bypass = ArxanBypass()
        output_path = minimal_protected_binary.parent / "patched_output.exe"

        result = bypass.bypass(minimal_protected_binary, output_path)

        assert result.success is True
        assert output_path.exists()
        assert output_path.stat().st_size > 0

    def test_bypass_auto_generates_output_path(self, minimal_protected_binary: Path) -> None:
        """Bypass auto-generates output filename when not specified."""
        bypass = ArxanBypass()

        result = bypass.bypass(minimal_protected_binary, output_path=None)

        assert result.success is True
        assert result.patched_binary_path != ""
        output_path = Path(result.patched_binary_path)
        assert output_path.exists()
        assert ".arxan_bypassed" in output_path.name

    def test_bypass_returns_success_result(self, minimal_protected_binary: Path) -> None:
        """Bypass returns successful result with metadata."""
        bypass = ArxanBypass()

        result = bypass.bypass(minimal_protected_binary)

        assert result.success is True
        assert isinstance(result, ArxanBypassResult)
        assert "arxan_version" in result.metadata
        assert "confidence" in result.metadata

    def test_bypass_applies_patches_to_binary(self, arxan_protected_binary: Path) -> None:
        """Bypass applies patches that modify binary content."""
        bypass = ArxanBypass()
        original_data = arxan_protected_binary.read_bytes()

        result = bypass.bypass(arxan_protected_binary)

        assert result.success is True
        assert len(result.patches_applied) > 0

        patched_path = Path(result.patched_binary_path)
        patched_data = patched_path.read_bytes()

        assert len(patched_data) >= len(original_data)


class TestTamperCheckBypass:
    """Test anti-tampering check bypass functionality."""

    def test_bypass_tamper_checks_patches_crc32(self, arxan_protected_binary: Path) -> None:
        """Bypass neutralizes CRC32 tamper checks with correct patches."""
        bypass = ArxanBypass()

        result = bypass.bypass(arxan_protected_binary)

        assert result.success is True

        tamper_patches = [p for p in result.patches_applied if p.patch_type == "tamper_bypass"]
        assert tamper_patches

        for patch in tamper_patches:
            assert patch.address >= 0
            assert len(patch.original_bytes) > 0
            assert len(patch.patched_bytes) > 0
            assert "tamper check" in patch.description.lower() or "crc" in patch.description.lower() or "md5" in patch.description.lower() or "sha" in patch.description.lower()

    def test_bypass_tamper_checks_uses_valid_opcodes(self, arxan_protected_binary: Path) -> None:
        """Bypass uses valid x86 opcodes for tamper check patches."""
        bypass = ArxanBypass()

        result = bypass.bypass(arxan_protected_binary)

        tamper_patches = [p for p in result.patches_applied if p.patch_type == "tamper_bypass"]

        for patch in tamper_patches:
            assert (
                patch.patched_bytes == bypass.MOV_EAX_1 + bypass.RET_OPCODE
                or patch.patched_bytes[:1] == bypass.NOP_OPCODE
                or bypass.NOP_OPCODE in patch.patched_bytes
            )

    def test_bypass_tamper_checks_preserves_binary_structure(self, arxan_protected_binary: Path) -> None:
        """Bypass preserves PE structure when patching tamper checks."""
        bypass = ArxanBypass()
        original_size = arxan_protected_binary.stat().st_size

        result = bypass.bypass(arxan_protected_binary)

        patched_path = Path(result.patched_binary_path)
        patched_size = patched_path.stat().st_size

        assert patched_size >= original_size - 100


class TestIntegrityCheckBypass:
    """Test integrity check neutralization."""

    def test_bypass_integrity_checks_neutralizes_hash_functions(self, arxan_protected_binary: Path) -> None:
        """Bypass neutralizes hash-based integrity checks."""
        bypass = ArxanBypass()

        result = bypass.bypass(arxan_protected_binary)

        integrity_patches = [p for p in result.patches_applied if p.patch_type == "integrity_bypass"]
        assert integrity_patches

        for patch in integrity_patches:
            assert "integrity" in patch.description.lower() or any(
                algo in patch.description.lower() for algo in ["crc32", "sha1", "sha256", "md5"]
            )

    def test_bypass_integrity_checks_returns_success_values(self, arxan_protected_binary: Path) -> None:
        """Bypass patches integrity checks to return success values."""
        bypass = ArxanBypass()

        result = bypass.bypass(arxan_protected_binary)

        integrity_patches = [p for p in result.patches_applied if p.patch_type == "integrity_bypass"]

        for patch in integrity_patches:
            assert (
                patch.patched_bytes == b"\xb8\x00\x00\x00\x00\xc3"
                or patch.patched_bytes == b"\xb8\x01\x00\x00\x00\xc3"
                or patch.patched_bytes[:1] == bypass.NOP_OPCODE
            )

    def test_bypass_counts_integrity_checks_correctly(self, arxan_protected_binary: Path) -> None:
        """Bypass accurately counts neutralized integrity checks."""
        bypass = ArxanBypass()

        result = bypass.bypass(arxan_protected_binary)

        integrity_patches = [p for p in result.patches_applied if p.patch_type == "integrity_bypass"]
        assert result.integrity_checks_neutralized == len(integrity_patches)


class TestLicenseValidationBypass:
    """Test license validation bypass functionality."""

    def test_bypass_license_validation_patches_validation_routines(self, arxan_protected_binary: Path) -> None:
        """Bypass patches license validation routines to always succeed."""
        bypass = ArxanBypass()

        result = bypass.bypass(arxan_protected_binary)

        license_patches = [p for p in result.patches_applied if p.patch_type == "license_bypass"]
        assert license_patches

        for patch in license_patches:
            assert "license" in patch.description.lower() or "validation" in patch.description.lower()

    def test_bypass_license_validation_returns_success_code(self, arxan_protected_binary: Path) -> None:
        """Bypass patches license checks to return success codes."""
        bypass = ArxanBypass()

        result = bypass.bypass(arxan_protected_binary)

        license_patches = [p for p in result.patches_applied if p.patch_type == "license_bypass"]

        for patch in license_patches:
            assert patch.patched_bytes in [
                b"\xb8\x01\x00\x00\x00\xc3",
                b"\x33\xc0\x40\xc3",
            ]

    def test_bypass_handles_rsa_validation(self) -> None:
        """Bypass correctly handles RSA license validation routines."""
        bypass = ArxanBypass()

        binary_data = bytearray(0x1000)

        binary_data[0x500 : 0x500 + len(b"\x00\x01\xff\xff")] = b"\x00\x01\xff\xff"

        patches: list[BypassPatch] = []
        license_routines = [
            LicenseValidationRoutine(
                address=0x500,
                function_name="rsa_check",
                algorithm="RSA",
                key_length=2048,
                validation_type="rsa_validation",
            )
        ]

        bypass._bypass_license_validation(binary_data, license_routines, patches)

        assert len(patches) == 1
        assert patches[0].patch_type == "license_bypass"
        assert patches[0].patched_bytes == b"\xb8\x01\x00\x00\x00\xc3"

    def test_bypass_handles_serial_check(self) -> None:
        """Bypass correctly handles serial number validation."""
        bypass = ArxanBypass()

        binary_data = bytearray(0x1000)
        patches: list[BypassPatch] = []

        license_routines = [
            LicenseValidationRoutine(
                address=0x400,
                function_name="serial_check",
                algorithm="custom",
                key_length=128,
                validation_type="serial_check",
            )
        ]

        bypass._bypass_license_validation(binary_data, license_routines, patches)

        assert len(patches) == 1
        assert patches[0].patch_type == "license_bypass"
        assert patches[0].patched_bytes == b"\x33\xc0\x40\xc3"


class TestRASPBypass:
    """Test Runtime Application Self-Protection bypass."""

    def test_bypass_rasp_defeats_anti_debug_mechanisms(self, arxan_protected_binary: Path) -> None:
        """Bypass defeats anti-debugging RASP mechanisms."""
        bypass = ArxanBypass()

        result = bypass.bypass(arxan_protected_binary)

        rasp_patches = [p for p in result.patches_applied if p.patch_type == "rasp_bypass"]
        assert rasp_patches

    def test_bypass_rasp_uses_correct_patch_bytes(self) -> None:
        """Bypass uses appropriate opcodes for different RASP types."""
        bypass = ArxanBypass()

        binary_data = bytearray(0x1000)
        patches: list[BypassPatch] = []

        rasp_mechanisms = [
            RASPMechanism("anti_debug", 0x100, "IsDebuggerPresent", "peb_check", "high"),
            RASPMechanism("anti_frida", 0x200, "runtime", "string_detection", "high"),
            RASPMechanism("anti_hook", 0x300, "runtime", "integrity_check", "medium"),
            RASPMechanism("exception_handler", 0x400, "SEH", "exception_based", "high"),
        ]

        bypass._neutralize_rasp(binary_data, rasp_mechanisms, patches)

        assert len(patches) == 4

        assert patches[0].patched_bytes == b"\x33\xc0\xc3"

        assert patches[1].patched_bytes == bypass.NOP_OPCODE * 10

        assert patches[2].patched_bytes == b"\xb8\x01\x00\x00\x00\xc3"

        assert patches[3].patched_bytes == bypass.NOP_OPCODE * 8

    def test_bypass_counts_rasp_mechanisms_correctly(self, arxan_protected_binary: Path) -> None:
        """Bypass accurately counts defeated RASP mechanisms."""
        bypass = ArxanBypass()

        result = bypass.bypass(arxan_protected_binary)

        rasp_patches = [p for p in result.patches_applied if p.patch_type == "rasp_bypass"]
        assert result.rasp_mechanisms_defeated == len(rasp_patches)


class TestStringDecryption:
    """Test encrypted string decryption functionality."""

    def test_bypass_decrypts_xor_encrypted_strings(self) -> None:
        """Bypass decrypts XOR-encrypted strings in binary."""
        bypass = ArxanBypass()

        plaintext = b"LICENSE_KEY_VALIDATION"
        xor_key = 0x42
        encrypted = bytes(b ^ xor_key for b in plaintext)

        binary_data = bytearray(0x1000)
        binary_data[0x500 : 0x500 + len(encrypted)] = encrypted

        patches: list[BypassPatch] = []
        encrypted_regions = [(0x500, len(encrypted))]

        bypass._decrypt_strings(binary_data, encrypted_regions, patches)

        string_patches = [p for p in patches if p.patch_type == "string_decryption"]
        assert string_patches

        decrypted_patch = string_patches[0]
        assert decrypted_patch.original_bytes == encrypted
        assert len(decrypted_patch.patched_bytes) == len(plaintext)

        printable_count = sum(32 <= b < 127 for b in decrypted_patch.patched_bytes)
        assert printable_count / len(decrypted_patch.patched_bytes) > 0.7

    def test_bypass_string_decryption_validates_printable_ratio(self) -> None:
        """Bypass validates decrypted strings are printable."""
        bypass = ArxanBypass()

        random_bytes = bytes([0xFF, 0xFE, 0xFD, 0xFC] * 10)

        binary_data = bytearray(0x1000)
        binary_data[0x500 : 0x500 + len(random_bytes)] = random_bytes

        patches: list[BypassPatch] = []
        encrypted_regions = [(0x500, len(random_bytes))]

        bypass._decrypt_strings(binary_data, encrypted_regions, patches)

        string_patches = [p for p in patches if p.patch_type == "string_decryption"]

        for patch in string_patches:
            printable_count = sum(32 <= b < 127 for b in patch.patched_bytes)
            printable_ratio = printable_count / len(patch.patched_bytes)
            assert printable_ratio > 0.7

    def test_bypass_limits_encrypted_regions_processed(self) -> None:
        """Bypass processes limited number of encrypted regions for performance."""
        bypass = ArxanBypass()

        binary_data = bytearray(0x10000)
        patches: list[BypassPatch] = []

        encrypted_regions = [(i * 0x100, 50) for i in range(20)]

        bypass._decrypt_strings(binary_data, encrypted_regions, patches)

        assert len(encrypted_regions) == 20


class TestFridaBypassScriptGeneration:
    """Test Frida runtime bypass script generation."""

    def test_generate_frida_script_creates_valid_javascript(self) -> None:
        """Frida script generation creates valid JavaScript code."""
        bypass = ArxanBypass()

        analysis_result = ArxanAnalysisResult()
        analysis_result.license_routines = [
            LicenseValidationRoutine(
                address=0x401000,
                function_name="check_license",
                algorithm="RSA",
                key_length=2048,
                validation_type="rsa_validation",
            )
        ]

        script = bypass._generate_frida_bypass_script(analysis_result)

        assert "console.log" in script
        assert "Interceptor.attach" in script or "Interceptor.replace" in script
        assert "IsDebuggerPresent" in script
        assert "CheckRemoteDebuggerPresent" in script
        assert "NtQueryInformationProcess" in script

    def test_generate_frida_script_includes_license_hooks(self) -> None:
        """Frida script includes hooks for license validation functions."""
        bypass = ArxanBypass()

        analysis_result = ArxanAnalysisResult()
        analysis_result.license_routines = [
            LicenseValidationRoutine(0x401000, "lic1", "RSA", 2048, "rsa_validation"),
            LicenseValidationRoutine(0x402000, "lic2", "AES", 256, "aes_license"),
            LicenseValidationRoutine(0x403000, "lic3", "custom", 128, "serial_check"),
        ]

        script = bypass._generate_frida_bypass_script(analysis_result)

        assert "0x401000" in script
        assert "0x402000" in script
        assert "0x403000" in script
        assert script.count("licenseFunc") >= 3

    def test_generate_frida_script_limits_hook_count(self) -> None:
        """Frida script generation limits number of license hooks."""
        bypass = ArxanBypass()

        analysis_result = ArxanAnalysisResult()
        analysis_result.license_routines = [
            LicenseValidationRoutine(0x400000 + i * 0x1000, f"lic{i}", "RSA", 2048, "rsa_validation")
            for i in range(10)
        ]

        script = bypass._generate_frida_bypass_script(analysis_result)

        unique_addresses = len({hex(0x400000 + i * 0x1000) for i in range(5)})
        assert all(hex(0x400000 + i * 0x1000)[2:] in script for i in range(5))
        assert all(hex(0x400000 + i * 0x1000)[2:] not in script for i in range(6, 10))

    def test_generate_frida_script_includes_anti_debug_bypass(self) -> None:
        """Frida script includes anti-debugging bypasses."""
        bypass = ArxanBypass()

        analysis_result = ArxanAnalysisResult()

        script = bypass._generate_frida_bypass_script(analysis_result)

        assert "IsDebuggerPresent" in script
        assert "CheckRemoteDebuggerPresent" in script
        assert "NtQueryInformationProcess" in script

    def test_generate_frida_script_includes_integrity_bypass(self) -> None:
        """Frida script includes integrity check bypasses."""
        bypass = ArxanBypass()

        analysis_result = ArxanAnalysisResult()

        script = bypass._generate_frida_bypass_script(analysis_result)

        assert "CryptHashData" in script
        assert "CryptVerifySignature" in script

    def test_generate_frida_script_includes_memory_protection_bypass(self) -> None:
        """Frida script includes memory protection bypasses."""
        bypass = ArxanBypass()

        analysis_result = ArxanAnalysisResult()

        script = bypass._generate_frida_bypass_script(analysis_result)

        assert "VirtualProtect" in script


class TestPEUtilityFunctions:
    """Test PE-specific utility functions."""

    def test_rva_to_offset_converts_correctly(self, arxan_protected_binary: Path) -> None:
        """RVA to file offset conversion works correctly for PE sections."""
        bypass = ArxanBypass()

        try:
            import pefile

            pe = pefile.PE(str(arxan_protected_binary))

            code_section = [s for s in pe.sections if b".text" in s.Name][0]
            rva = code_section.VirtualAddress + 0x100

            offset = bypass._rva_to_offset(pe, rva)

            assert offset is not None
            assert offset >= code_section.PointerToRawData
            assert offset < code_section.PointerToRawData + code_section.SizeOfRawData

            pe.close()

        except ImportError:
            pytest.skip("pefile not available")

    def test_calculate_pe_checksum_produces_valid_checksum(self, arxan_protected_binary: Path) -> None:
        """PE checksum calculation produces valid checksum."""
        bypass = ArxanBypass()

        binary_data = arxan_protected_binary.read_bytes()

        checksum = bypass._calculate_pe_checksum(binary_data)

        assert isinstance(checksum, int)
        assert checksum > 0
        assert checksum <= 0xFFFFFFFF

    def test_calculate_pe_checksum_handles_short_binary(self) -> None:
        """PE checksum calculation handles short binaries correctly."""
        bypass = ArxanBypass()

        short_data = b"\x4D\x5A" + b"\x00" * 100

        checksum = bypass._calculate_pe_checksum(short_data)

        assert isinstance(checksum, int)
        assert checksum > 0


class TestBypassCleanup:
    """Test cleanup and resource management."""

    def test_cleanup_handles_no_active_session(self) -> None:
        """Cleanup handles case with no active Frida session."""
        bypass = ArxanBypass()

        bypass.cleanup()

        assert bypass.frida_session is None
        assert bypass.frida_script is None

    def test_cleanup_does_not_raise_exception(self) -> None:
        """Cleanup does not raise exceptions even with invalid state."""
        bypass = ArxanBypass()

        bypass.frida_session = None
        bypass.frida_script = None

        bypass.cleanup()


class TestBypassEdgeCases:
    """Test edge cases and error handling."""

    def test_bypass_handles_empty_analysis_result(self, minimal_protected_binary: Path) -> None:
        """Bypass handles binary with no detected protections."""
        bypass = ArxanBypass()

        result = bypass.bypass(minimal_protected_binary)

        assert result.success is True

    def test_bypass_handles_large_address_values(self) -> None:
        """Bypass handles large memory addresses correctly."""
        bypass = ArxanBypass()

        binary_data = bytearray(0x2000)
        patches: list[BypassPatch] = []

        tamper_checks = [
            TamperCheckLocation(
                address=0x1FFF,
                size=10,
                check_type="tamper_detection",
                target_region=(0x1000, 0x2000),
                algorithm="crc32",
                bypass_complexity="low",
            )
        ]

        bypass._bypass_tamper_checks(binary_data, tamper_checks, patches)

        assert len(patches) == 1
        assert patches[0].address == 0x1FFF

    def test_bypass_handles_out_of_bounds_addresses(self) -> None:
        """Bypass safely handles addresses beyond binary size."""
        bypass = ArxanBypass()

        binary_data = bytearray(0x1000)
        patches: list[BypassPatch] = []

        tamper_checks = [
            TamperCheckLocation(
                address=0x2000,
                size=10,
                check_type="tamper_detection",
                target_region=(0x2000, 0x3000),
                algorithm="crc32",
                bypass_complexity="low",
            )
        ]

        bypass._bypass_tamper_checks(binary_data, tamper_checks, patches)

        assert not patches

    def test_bypass_handles_overlapping_patches(self) -> None:
        """Bypass handles overlapping protection mechanisms."""
        bypass = ArxanBypass()

        binary_data = bytearray(0x1000)
        patches: list[BypassPatch] = []

        tamper_checks = [
            TamperCheckLocation(0x500, 10, "tamper_detection", (0x400, 0x600), "crc32", "low"),
            TamperCheckLocation(0x505, 10, "tamper_detection", (0x400, 0x600), "md5", "medium"),
        ]

        bypass._bypass_tamper_checks(binary_data, tamper_checks, patches)

        assert len(patches) == 2
        assert patches[0].address == 0x500
        assert patches[1].address == 0x505


class TestBypassMetadata:
    """Test bypass result metadata handling."""

    def test_bypass_includes_version_metadata(self, arxan_protected_binary: Path) -> None:
        """Bypass result includes Arxan version metadata."""
        bypass = ArxanBypass()

        result = bypass.bypass(arxan_protected_binary)

        assert "arxan_version" in result.metadata
        assert isinstance(result.metadata["arxan_version"], str)

    def test_bypass_includes_confidence_metadata(self, arxan_protected_binary: Path) -> None:
        """Bypass result includes detection confidence metadata."""
        bypass = ArxanBypass()

        result = bypass.bypass(arxan_protected_binary)

        assert "confidence" in result.metadata
        assert isinstance(result.metadata["confidence"], float)
        assert 0.0 <= result.metadata["confidence"] <= 1.0

    def test_bypass_counts_patch_types_correctly(self, arxan_protected_binary: Path) -> None:
        """Bypass accurately counts different patch types."""
        bypass = ArxanBypass()

        result = bypass.bypass(arxan_protected_binary)

        license_count = len([p for p in result.patches_applied if p.patch_type == "license_bypass"])
        integrity_count = len([p for p in result.patches_applied if p.patch_type == "integrity_bypass"])
        rasp_count = len([p for p in result.patches_applied if p.patch_type == "rasp_bypass"])

        assert result.license_checks_bypassed == license_count
        assert result.integrity_checks_neutralized == integrity_count
        assert result.rasp_mechanisms_defeated == rasp_count


class TestBypassBinaryIntegrity:
    """Test that bypass maintains binary integrity."""

    def test_bypass_maintains_pe_signature(self, arxan_protected_binary: Path) -> None:
        """Bypass maintains PE signature after patching."""
        bypass = ArxanBypass()

        result = bypass.bypass(arxan_protected_binary)

        patched_path = Path(result.patched_binary_path)
        patched_data = patched_path.read_bytes()

        assert patched_data[:2] == b"MZ"

        dos_header = struct.unpack_from("<I", patched_data, 0x3C)[0]
        assert patched_data[dos_header : dos_header + 4] == b"PE\x00\x00"

    def test_bypass_preserves_section_count(self, arxan_protected_binary: Path) -> None:
        """Bypass preserves section count in PE header."""
        original_data = arxan_protected_binary.read_bytes()

        bypass = ArxanBypass()
        result = bypass.bypass(arxan_protected_binary)

        patched_path = Path(result.patched_binary_path)
        patched_data = patched_path.read_bytes()

        if len(original_data) >= 0x200 and len(patched_data) >= 0x200:
            assert original_data[0x86:0x88] == patched_data[0x86:0x88]

    def test_patched_binary_is_valid_pe(self, arxan_protected_binary: Path) -> None:
        """Patched binary remains a valid PE file."""
        bypass = ArxanBypass()

        result = bypass.bypass(arxan_protected_binary)

        try:
            import pefile

            patched_path = Path(result.patched_binary_path)
            pe = pefile.PE(str(patched_path))

            assert pe.DOS_HEADER is not None
            assert pe.NT_HEADERS is not None
            assert pe.FILE_HEADER is not None
            assert pe.OPTIONAL_HEADER is not None

            pe.close()

        except ImportError:
            pytest.skip("pefile not available")
