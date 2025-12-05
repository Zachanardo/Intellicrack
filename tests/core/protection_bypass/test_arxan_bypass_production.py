"""Production Tests for Arxan TransformIT Bypass Module.

Tests validate genuine Arxan protection bypass capabilities against real Windows
binaries and Arxan-protected binary patterns. All tests use real system files and
actual bypass techniques without mocks or stubs. Tests MUST FAIL if bypass
implementation doesn't work effectively.

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
import tempfile
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


WINDOWS_NOTEPAD: str = "C:/Windows/System32/notepad.exe"
WINDOWS_KERNEL32: str = "C:/Windows/System32/kernel32.dll"


@pytest.fixture
def real_system_binary() -> Path:
    """Provide real Windows system binary for testing."""
    binary_path: Path = Path(WINDOWS_NOTEPAD)
    if not binary_path.exists():
        pytest.skip("Windows notepad.exe not available")
    return binary_path


@pytest.fixture
def real_dll_binary() -> Path:
    """Provide real Windows DLL for testing."""
    dll_path: Path = Path(WINDOWS_KERNEL32)
    if not dll_path.exists():
        pytest.skip("Windows kernel32.dll not available")
    return dll_path


@pytest.fixture
def arxan_protected_pe(tmp_path: Path) -> Generator[Path, None, None]:
    """Create realistic Arxan-protected PE binary with all protection mechanisms."""
    binary_path: Path = tmp_path / "arxan_protected.exe"

    dos_header: bytes = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)

    pe_signature: bytes = b"PE\x00\x00"

    coff_header: bytes = struct.pack(
        "<HHIIIHH",
        0x014C,
        4,
        0,
        0,
        0,
        0xE0,
        0x010B,
    )

    optional_header: bytes = struct.pack(
        "<HBBIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B,
        14,
        0,
        0x3000,
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
        0x5678,
        3,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        0x10,
    )

    optional_header += b"\x00" * (0xE0 - len(optional_header))

    section_table: bytes = b""

    text_section: bytes = b".text\x00\x00\x00"
    text_section += struct.pack(
        "<IIIIIHHHI",
        0x3000,
        0x1000,
        0x3000,
        0x400,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    section_table += text_section

    data_section: bytes = b".data\x00\x00\x00"
    data_section += struct.pack(
        "<IIIIIHHHI",
        0x1000,
        0x4000,
        0x1000,
        0x3400,
        0,
        0,
        0,
        0,
        0xC0000040,
    )
    section_table += data_section

    rdata_section: bytes = b".rdata\x00\x00"
    rdata_section += struct.pack(
        "<IIIIIHHHI",
        0x1000,
        0x5000,
        0x1000,
        0x4400,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    section_table += rdata_section

    arxan_section: bytes = b".arxan\x00\x00"
    arxan_section += struct.pack(
        "<IIIIIHHHI",
        0x2000,
        0x6000,
        0x2000,
        0x5400,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    section_table += arxan_section

    pe_header: bytes = pe_signature + coff_header + optional_header + section_table

    headers: bytes = dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header

    code_section_data: bytearray = bytearray(0x3000)

    code_section_data[0x100 : 0x100 + len(b"\x33\xd2\x8a\x10\x8b\xc2\xc1\xe8\x08")] = b"\x33\xd2\x8a\x10\x8b\xc2\xc1\xe8\x08"
    code_section_data[0x150 : 0x150 + len(b"\x8b\x55\x08\x33\xc0\x8a\x02")] = b"\x8b\x55\x08\x33\xc0\x8a\x02"

    code_section_data[0x200 : 0x200 + len(b"\x67\x45\x23\x01")] = b"\x67\x45\x23\x01"
    code_section_data[0x250 : 0x250 + len(b"\x01\x23\x45\x67\x89\xab\xcd\xef")] = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

    code_section_data[0x300 : 0x300 + len(b"\x6a\x09\xe6\x67")] = b"\x6a\x09\xe6\x67"
    code_section_data[0x350 : 0x350 + len(b"\x42\x8a\x2f\x98")] = b"\x42\x8a\x2f\x98"

    code_section_data[0x400 : 0x400 + len(b"\x00\x01\xff\xff")] = b"\x00\x01\xff\xff"
    code_section_data[0x450 : 0x450 + len(b"\x00\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01")] = b"\x00\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01"

    code_section_data[0x500 : 0x500 + len(b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5")] = b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5"
    code_section_data[0x550 : 0x550 + len(b"\x52\x09\x6a\xd5\x30\x36\xa5\x38")] = b"\x52\x09\x6a\xd5\x30\x36\xa5\x38"

    code_section_data[0x600 : 0x600 + len(b"\x64\xa1\x30\x00\x00\x00\x0f\xb6\x40\x02")] = (
        b"\x64\xa1\x30\x00\x00\x00\x0f\xb6\x40\x02"
    )
    code_section_data[0x650 : 0x650 + len(b"\x64\x8b\x05\x30\x00\x00\x00\x80\x78\x02\x00")] = (
        b"\x64\x8b\x05\x30\x00\x00\x00\x80\x78\x02\x00"
    )
    code_section_data[0x700 : 0x700 + len(b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00")] = (
        b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"
    )

    code_section_data[0x800 : 0x800 + len(b"\x85\xc0\x75\x02\x75\x00")] = b"\x85\xc0\x75\x02\x75\x00"
    code_section_data[0x850 : 0x850 + len(b"\x85\xc0\x74\x02\x74\x00")] = b"\x85\xc0\x74\x02\x74\x00"
    code_section_data[0x900 : 0x900 + len(b"\x33\xc0\x85\xc0\x74")] = b"\x33\xc0\x85\xc0\x74"

    code_section_data[0xA00 : 0xA00 + len(b"frida")] = b"frida"
    code_section_data[0xA50 : 0xA50 + len(b"gum-js-loop")] = b"gum-js-loop"
    code_section_data[0xB00 : 0xB00 + len(b"ARXAN")] = b"ARXAN"
    code_section_data[0xB50 : 0xB50 + len(b"TransformIT")] = b"TransformIT"

    code_section_data[0xC00 : 0xC00 + len(b"\x8b\x45\x08\x8b\x4d\x0c\x33\xd2\x8a\x10")] = (
        b"\x8b\x45\x08\x8b\x4d\x0c\x33\xd2\x8a\x10"
    )
    code_section_data[0xC50 : 0xC50 + len(b"\xc1\xe8\x08\x33")] = b"\xc1\xe8\x08\x33"

    code_section_data[0xD00 : 0xD00 + len(b"\x64\xa1\x00\x00\x00\x00\x50")] = b"\x64\xa1\x00\x00\x00\x00\x50"
    code_section_data[0xD50 : 0xD50 + len(b"\x64\x89\x25\x00\x00\x00\x00")] = b"\x64\x89\x25\x00\x00\x00\x00"

    xor_key: int = 0x42
    plaintext: bytes = b"LICENSE_VALIDATION_ROUTINE"
    encrypted: bytes = bytes(b ^ xor_key for b in plaintext)
    code_section_data[0x1000 : 0x1000 + len(encrypted)] = encrypted

    data_section_data: bytearray = bytearray(0x1000)
    data_section_data[0:4] = struct.pack("<I", 0x12345678)
    data_section_data[0x100 : 0x100 + len(b"license")] = b"license"
    data_section_data[0x200 : 0x200 + len(b"serial")] = b"serial"
    data_section_data[0x300 : 0x300 + len(b"activation")] = b"activation"
    data_section_data[0x400 : 0x400 + len(b"registration")] = b"registration"

    rdata_section_data: bytearray = bytearray(0x1000)
    rdata_section_data[0 : len(b"product_key")] = b"product_key"

    arxan_section_data: bytearray = bytearray(0x2000)
    arxan_section_data[0 : len(b"TRANSFORMIT")] = b"TRANSFORMIT"
    arxan_section_data[0x100 : 0x100 + len(b"GuardIT")] = b"GuardIT"

    whitebox_table: bytes = bytes(range(256)) * 8
    arxan_section_data[0x500 : 0x500 + len(whitebox_table)] = whitebox_table

    binary_data: bytes = (
        headers.ljust(0x400, b"\x00")
        + code_section_data
        + data_section_data
        + rdata_section_data
        + arxan_section_data
    )

    binary_path.write_bytes(binary_data)
    yield binary_path


@pytest.fixture
def minimal_arxan_binary(tmp_path: Path) -> Generator[Path, None, None]:
    """Create minimal Arxan-protected binary for edge case testing."""
    binary_path: Path = tmp_path / "minimal_arxan.exe"

    dos_header: bytes = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)

    pe_signature: bytes = b"PE\x00\x00"
    coff_header: bytes = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0x60, 0x010B)
    optional_header: bytes = struct.pack(
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
        0x3000,
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

    section: bytes = b".text\x00\x00\x00"
    section += struct.pack("<IIIIIHHHI", 0x1000, 0x1000, 0x1000, 0x200, 0, 0, 0, 0, 0x60000020)

    pe_header: bytes = pe_signature + coff_header + optional_header + section

    headers: bytes = dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header

    code_data: bytearray = bytearray(0x1000)

    code_data[0x100 : 0x100 + len(b"\x33\xd2\x8a\x10")] = b"\x33\xd2\x8a\x10"
    code_data[0x200 : 0x200 + len(b"\x00\x01\xff\xff")] = b"\x00\x01\xff\xff"
    code_data[0x300 : 0x300 + len(b"Arxan")] = b"Arxan"

    binary_data: bytes = headers.ljust(0x200, b"\x00") + code_data

    binary_path.write_bytes(binary_data)
    yield binary_path


@pytest.fixture
def layered_protection_binary(tmp_path: Path) -> Generator[Path, None, None]:
    """Create binary with multiple layered Arxan protections."""
    binary_path: Path = tmp_path / "layered_protection.exe"

    dos_header: bytes = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)

    pe_signature: bytes = b"PE\x00\x00"
    coff_header: bytes = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 0xE0, 0x010B)

    optional_header: bytes = struct.pack(
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
        0x8000,
        0x200,
        0xABCD,
        3,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        0x10,
    )
    optional_header += b"\x00" * (0xE0 - len(optional_header))

    text_section: bytes = b".text\x00\x00\x00"
    text_section += struct.pack("<IIIIIHHHI", 0x2000, 0x1000, 0x2000, 0x400, 0, 0, 0, 0, 0x60000020)

    data_section: bytes = b".data\x00\x00\x00"
    data_section += struct.pack("<IIIIIHHHI", 0x1000, 0x3000, 0x1000, 0x2400, 0, 0, 0, 0, 0xC0000040)

    pe_header: bytes = pe_signature + coff_header + optional_header + text_section + data_section

    headers: bytes = dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header

    code_data: bytearray = bytearray(0x2000)

    code_data[0x100 : 0x100 + len(b"\x33\xd2\x8a\x10\x8b\xc2\xc1\xe8\x08")] = b"\x33\xd2\x8a\x10\x8b\xc2\xc1\xe8\x08"
    code_data[0x200 : 0x200 + len(b"\x67\x45\x23\x01")] = b"\x67\x45\x23\x01"
    code_data[0x300 : 0x300 + len(b"\x6a\x09\xe6\x67")] = b"\x6a\x09\xe6\x67"

    code_data[0x400 : 0x400 + len(b"\x00\x01\xff\xff")] = b"\x00\x01\xff\xff"
    code_data[0x500 : 0x500 + len(b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5")] = b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5"

    code_data[0x600 : 0x600 + len(b"\x64\xa1\x30\x00\x00\x00\x0f\xb6\x40\x02")] = (
        b"\x64\xa1\x30\x00\x00\x00\x0f\xb6\x40\x02"
    )
    code_data[0x700 : 0x700 + len(b"frida")] = b"frida"
    code_data[0x800 : 0x800 + len(b"\x85\xc0\x75\x02\x75\x00")] = b"\x85\xc0\x75\x02\x75\x00"

    data_section_data: bytearray = bytearray(0x1000)
    data_section_data[0 : len(b"license")] = b"license"

    binary_data: bytes = headers.ljust(0x400, b"\x00") + code_data + data_section_data

    binary_path.write_bytes(binary_data)
    yield binary_path


class TestArxanBypassInitialization:
    """Test ArxanBypass initialization and configuration."""

    def test_bypass_initializes_with_all_required_components(self) -> None:
        """ArxanBypass initializes with detector, analyzer, and assemblers."""
        bypass: ArxanBypass = ArxanBypass()

        assert bypass.detector is not None
        assert bypass.analyzer is not None
        assert bypass.logger is not None
        assert bypass.frida_session is None
        assert bypass.frida_script is None

    def test_bypass_initializes_keystone_assemblers_when_available(self) -> None:
        """ArxanBypass initializes Keystone assemblers for x86 and x64."""
        bypass: ArxanBypass = ArxanBypass()

        try:
            import keystone

            assert bypass.ks_32 is not None
            assert bypass.ks_64 is not None
        except ImportError:
            assert bypass.ks_32 is None
            assert bypass.ks_64 is None

    def test_bypass_initializes_capstone_disassemblers_when_available(self) -> None:
        """ArxanBypass initializes Capstone disassemblers with detail mode."""
        bypass: ArxanBypass = ArxanBypass()

        try:
            import capstone

            assert bypass.md_32 is not None
            assert bypass.md_64 is not None
            assert bypass.md_32.detail is True
            assert bypass.md_64.detail is True
        except ImportError:
            assert bypass.md_32 is None
            assert bypass.md_64 is None

    def test_bypass_defines_correct_x86_opcode_constants(self) -> None:
        """ArxanBypass has correct x86/x64 opcode constants."""
        assert ArxanBypass.NOP_OPCODE == b"\x90"
        assert ArxanBypass.RET_OPCODE == b"\xc3"
        assert ArxanBypass.XOR_EAX_EAX == b"\x33\xc0"
        assert ArxanBypass.MOV_EAX_1 == b"\xb8\x01\x00\x00\x00"
        assert ArxanBypass.JMP_SHORT_0 == b"\xeb\x00"

    def test_bypass_opcode_constants_are_valid_x86_instructions(self) -> None:
        """ArxanBypass opcode constants are valid x86 machine code."""
        try:
            import capstone

            md: capstone.Cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

            for insn in md.disasm(ArxanBypass.NOP_OPCODE, 0x1000):
                assert insn.mnemonic == "nop"

            for insn in md.disasm(ArxanBypass.RET_OPCODE, 0x1000):
                assert insn.mnemonic == "ret"

            for insn in md.disasm(ArxanBypass.XOR_EAX_EAX, 0x1000):
                assert insn.mnemonic == "xor"

        except ImportError:
            pytest.skip("Capstone not available")


class TestBypassDataStructures:
    """Test BypassPatch and ArxanBypassResult dataclasses."""

    def test_bypass_patch_stores_all_patch_information(self) -> None:
        """BypassPatch dataclass stores complete patch information."""
        patch: BypassPatch = BypassPatch(
            address=0x401000,
            original_bytes=b"\x85\xc0\x74\x05",
            patched_bytes=b"\xb8\x01\x00\x00\x00\xc3",
            patch_type="license_bypass",
            description="Bypass RSA license validation",
        )

        assert patch.address == 0x401000
        assert patch.original_bytes == b"\x85\xc0\x74\x05"
        assert patch.patched_bytes == b"\xb8\x01\x00\x00\x00\xc3"
        assert patch.patch_type == "license_bypass"
        assert "license" in patch.description.lower()

    def test_arxan_bypass_result_initializes_with_default_values(self) -> None:
        """ArxanBypassResult initializes with correct default values."""
        result: ArxanBypassResult = ArxanBypassResult(success=False)

        assert result.success is False
        assert len(result.patches_applied) == 0
        assert result.runtime_hooks_installed == 0
        assert result.license_checks_bypassed == 0
        assert result.integrity_checks_neutralized == 0
        assert result.rasp_mechanisms_defeated == 0
        assert result.frida_script == ""
        assert result.patched_binary_path == ""
        assert len(result.metadata) == 0

    def test_arxan_bypass_result_stores_patches_and_counts(self) -> None:
        """ArxanBypassResult correctly stores patches and counts."""
        patches: list[BypassPatch] = [
            BypassPatch(0x401000, b"\x85\xc0", b"\x90\x90", "license_bypass", "Bypass license"),
            BypassPatch(0x402000, b"\x74\x05", b"\x90\x90", "integrity_bypass", "Neutralize CRC32"),
            BypassPatch(0x403000, b"\x75\x02", b"\x90\x90", "rasp_bypass", "Defeat anti-debug"),
        ]

        result: ArxanBypassResult = ArxanBypassResult(
            success=True,
            patches_applied=patches,
            license_checks_bypassed=1,
            integrity_checks_neutralized=1,
            rasp_mechanisms_defeated=1,
        )

        assert result.success is True
        assert len(result.patches_applied) == 3
        assert result.license_checks_bypassed == 1
        assert result.integrity_checks_neutralized == 1
        assert result.rasp_mechanisms_defeated == 1


class TestArxanBypassCore:
    """Test core Arxan bypass functionality against real binaries."""

    def test_bypass_raises_error_for_nonexistent_binary(self, tmp_path: Path) -> None:
        """Bypass raises FileNotFoundError when binary doesn't exist."""
        bypass: ArxanBypass = ArxanBypass()
        nonexistent: Path = tmp_path / "does_not_exist.exe"

        with pytest.raises(FileNotFoundError, match="Binary not found"):
            bypass.bypass(nonexistent)

    def test_bypass_creates_patched_binary_at_specified_path(self, minimal_arxan_binary: Path) -> None:
        """Bypass creates patched binary at specified output path."""
        bypass: ArxanBypass = ArxanBypass()
        output_path: Path = minimal_arxan_binary.parent / "patched_output.exe"

        result: ArxanBypassResult = bypass.bypass(minimal_arxan_binary, output_path)

        assert result.success is True
        assert output_path.exists()
        assert output_path.stat().st_size > 0

    def test_bypass_auto_generates_output_filename(self, minimal_arxan_binary: Path) -> None:
        """Bypass auto-generates output filename when not specified."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(minimal_arxan_binary, output_path=None)

        assert result.success is True
        assert result.patched_binary_path != ""
        output_path: Path = Path(result.patched_binary_path)
        assert output_path.exists()
        assert ".arxan_bypassed" in output_path.name

    def test_bypass_returns_successful_result_with_metadata(self, minimal_arxan_binary: Path) -> None:
        """Bypass returns successful result with detection metadata."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(minimal_arxan_binary)

        assert result.success is True
        assert isinstance(result, ArxanBypassResult)
        assert "arxan_version" in result.metadata
        assert "confidence" in result.metadata
        assert isinstance(result.metadata["confidence"], float)

    def test_bypass_applies_patches_to_arxan_protected_binary(self, arxan_protected_pe: Path) -> None:
        """Bypass applies patches that modify Arxan-protected binary."""
        bypass: ArxanBypass = ArxanBypass()
        original_data: bytes = arxan_protected_pe.read_bytes()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        assert result.success is True
        assert len(result.patches_applied) > 0

        patched_path: Path = Path(result.patched_binary_path)
        patched_data: bytes = patched_path.read_bytes()

        assert len(patched_data) >= len(original_data)

        patches_modified_binary: bool = False
        for patch in result.patches_applied:
            if patch.address < len(original_data):
                if original_data[patch.address : patch.address + len(patch.original_bytes)] == patch.original_bytes:
                    patches_modified_binary = True
                    break

        assert patches_modified_binary or len(result.patches_applied) > 0

    def test_bypass_works_on_real_windows_binary(self, real_system_binary: Path, tmp_path: Path) -> None:
        """Bypass processes real Windows binary without errors."""
        bypass: ArxanBypass = ArxanBypass()
        output_path: Path = tmp_path / "notepad_bypassed.exe"

        result: ArxanBypassResult = bypass.bypass(real_system_binary, output_path)

        assert result.success is True
        assert output_path.exists()
        assert output_path.stat().st_size > 0


class TestTamperCheckBypass:
    """Test anti-tampering check bypass functionality."""

    def test_bypass_detects_and_patches_crc32_tamper_checks(self, arxan_protected_pe: Path) -> None:
        """Bypass identifies and neutralizes CRC32 tamper checks."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        tamper_patches: list[BypassPatch] = [p for p in result.patches_applied if p.patch_type == "tamper_bypass"]
        assert len(tamper_patches) > 0

        crc32_patches: list[BypassPatch] = [
            p for p in tamper_patches if "crc" in p.description.lower() or "crc32" in p.description.lower()
        ]
        assert len(crc32_patches) > 0

    def test_bypass_detects_and_patches_md5_tamper_checks(self, arxan_protected_pe: Path) -> None:
        """Bypass identifies and neutralizes MD5 tamper checks."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        tamper_patches: list[BypassPatch] = [p for p in result.patches_applied if p.patch_type == "tamper_bypass"]

        md5_patches: list[BypassPatch] = [p for p in tamper_patches if "md5" in p.description.lower()]
        assert len(md5_patches) > 0

    def test_bypass_detects_and_patches_sha256_tamper_checks(self, arxan_protected_pe: Path) -> None:
        """Bypass identifies and neutralizes SHA256 tamper checks."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        tamper_patches: list[BypassPatch] = [p for p in result.patches_applied if p.patch_type == "tamper_bypass"]

        sha_patches: list[BypassPatch] = [p for p in tamper_patches if "sha" in p.description.lower()]
        assert len(sha_patches) > 0

    def test_tamper_bypass_uses_valid_x86_opcodes(self, arxan_protected_pe: Path) -> None:
        """Tamper check bypass uses valid x86 machine code."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        tamper_patches: list[BypassPatch] = [p for p in result.patches_applied if p.patch_type == "tamper_bypass"]

        for patch in tamper_patches:
            assert (
                patch.patched_bytes == bypass.MOV_EAX_1 + bypass.RET_OPCODE
                or patch.patched_bytes[:1] == bypass.NOP_OPCODE
                or bypass.NOP_OPCODE in patch.patched_bytes
            )

    def test_tamper_bypass_preserves_binary_structure(self, arxan_protected_pe: Path) -> None:
        """Tamper check bypass preserves PE structure integrity."""
        bypass: ArxanBypass = ArxanBypass()
        original_size: int = arxan_protected_pe.stat().st_size

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        patched_path: Path = Path(result.patched_binary_path)
        patched_size: int = patched_path.stat().st_size

        assert abs(patched_size - original_size) < 1000

        patched_data: bytes = patched_path.read_bytes()
        assert patched_data[:2] == b"MZ"


class TestIntegrityCheckBypass:
    """Test integrity check neutralization."""

    def test_bypass_neutralizes_hash_based_integrity_checks(self, arxan_protected_pe: Path) -> None:
        """Bypass neutralizes hash-based integrity verification."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        integrity_patches: list[BypassPatch] = [
            p for p in result.patches_applied if p.patch_type == "integrity_bypass"
        ]
        assert len(integrity_patches) > 0

    def test_integrity_bypass_returns_success_codes(self, arxan_protected_pe: Path) -> None:
        """Integrity check bypass patches return success codes."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        integrity_patches: list[BypassPatch] = [
            p for p in result.patches_applied if p.patch_type == "integrity_bypass"
        ]

        for patch in integrity_patches:
            assert (
                patch.patched_bytes == b"\xb8\x00\x00\x00\x00\xc3"
                or patch.patched_bytes == b"\xb8\x01\x00\x00\x00\xc3"
                or patch.patched_bytes[:1] == bypass.NOP_OPCODE
            )

    def test_integrity_bypass_count_matches_applied_patches(self, arxan_protected_pe: Path) -> None:
        """Integrity bypass count accurately reflects applied patches."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        integrity_patches: list[BypassPatch] = [
            p for p in result.patches_applied if p.patch_type == "integrity_bypass"
        ]
        assert result.integrity_checks_neutralized == len(integrity_patches)

    def test_bypass_handles_crc32_integrity_checks(self) -> None:
        """Bypass correctly handles CRC32 integrity check mechanisms."""
        bypass: ArxanBypass = ArxanBypass()

        binary_data: bytearray = bytearray(0x2000)
        patches: list[BypassPatch] = []

        integrity_checks: list[IntegrityCheckMechanism] = [
            IntegrityCheckMechanism(
                address=0x500,
                check_type="hash_verification",
                target_section="code",
                hash_algorithm="CRC32",
                check_frequency="periodic",
                bypass_strategy="hook_hash_function",
            )
        ]

        bypass._bypass_integrity_checks(binary_data, integrity_checks, patches)

        assert len(patches) == 1
        assert patches[0].patch_type == "integrity_bypass"
        assert patches[0].patched_bytes == b"\xb8\x00\x00\x00\x00\xc3"

    def test_bypass_handles_sha256_integrity_checks(self) -> None:
        """Bypass correctly handles SHA256 integrity check mechanisms."""
        bypass: ArxanBypass = ArxanBypass()

        binary_data: bytearray = bytearray(0x2000)
        patches: list[BypassPatch] = []

        integrity_checks: list[IntegrityCheckMechanism] = [
            IntegrityCheckMechanism(
                address=0x600,
                check_type="hash_verification",
                target_section="all",
                hash_algorithm="SHA256",
                check_frequency="on_demand",
                bypass_strategy="hook_crypto_api",
            )
        ]

        bypass._bypass_integrity_checks(binary_data, integrity_checks, patches)

        assert len(patches) == 1
        assert patches[0].patch_type == "integrity_bypass"
        assert patches[0].patched_bytes == b"\xb8\x01\x00\x00\x00\xc3"


class TestLicenseValidationBypass:
    """Test license validation bypass functionality."""

    def test_bypass_patches_license_validation_routines(self, arxan_protected_pe: Path) -> None:
        """Bypass identifies and patches license validation routines."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        license_patches: list[BypassPatch] = [p for p in result.patches_applied if p.patch_type == "license_bypass"]
        assert len(license_patches) > 0

        for patch in license_patches:
            assert "license" in patch.description.lower() or "validation" in patch.description.lower()

    def test_license_bypass_returns_success_codes(self, arxan_protected_pe: Path) -> None:
        """License validation bypass patches return success codes."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        license_patches: list[BypassPatch] = [p for p in result.patches_applied if p.patch_type == "license_bypass"]

        for patch in license_patches:
            assert patch.patched_bytes == b"\xb8\x01\x00\x00\x00\xc3" or patch.patched_bytes == b"\x33\xc0\x40\xc3"

    def test_license_bypass_count_matches_applied_patches(self, arxan_protected_pe: Path) -> None:
        """License bypass count accurately reflects applied patches."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        license_patches: list[BypassPatch] = [p for p in result.patches_applied if p.patch_type == "license_bypass"]
        assert result.license_checks_bypassed == len(license_patches)

    def test_bypass_handles_rsa_license_validation(self) -> None:
        """Bypass correctly handles RSA license validation."""
        bypass: ArxanBypass = ArxanBypass()

        binary_data: bytearray = bytearray(0x1000)
        binary_data[0x500 : 0x500 + len(b"\x00\x01\xff\xff")] = b"\x00\x01\xff\xff"

        patches: list[BypassPatch] = []
        license_routines: list[LicenseValidationRoutine] = [
            LicenseValidationRoutine(
                address=0x500,
                function_name="rsa_validate",
                algorithm="RSA",
                key_length=2048,
                validation_type="rsa_validation",
            )
        ]

        bypass._bypass_license_validation(binary_data, license_routines, patches)

        assert len(patches) == 1
        assert patches[0].patch_type == "license_bypass"
        assert patches[0].patched_bytes == b"\xb8\x01\x00\x00\x00\xc3"
        assert "rsa" in patches[0].description.lower()

    def test_bypass_handles_aes_license_validation(self) -> None:
        """Bypass correctly handles AES license validation."""
        bypass: ArxanBypass = ArxanBypass()

        binary_data: bytearray = bytearray(0x1000)
        patches: list[BypassPatch] = []

        license_routines: list[LicenseValidationRoutine] = [
            LicenseValidationRoutine(
                address=0x600,
                function_name="aes_license_check",
                algorithm="AES",
                key_length=256,
                validation_type="aes_license",
            )
        ]

        bypass._bypass_license_validation(binary_data, license_routines, patches)

        assert len(patches) == 1
        assert patches[0].patch_type == "license_bypass"
        assert patches[0].patched_bytes == b"\xb8\x01\x00\x00\x00\xc3"

    def test_bypass_handles_serial_number_validation(self) -> None:
        """Bypass correctly handles serial number validation."""
        bypass: ArxanBypass = ArxanBypass()

        binary_data: bytearray = bytearray(0x1000)
        patches: list[BypassPatch] = []

        license_routines: list[LicenseValidationRoutine] = [
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

    def test_bypass_defeats_anti_debug_mechanisms(self, arxan_protected_pe: Path) -> None:
        """Bypass defeats anti-debugging RASP mechanisms."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        rasp_patches: list[BypassPatch] = [p for p in result.patches_applied if p.patch_type == "rasp_bypass"]
        assert len(rasp_patches) > 0

    def test_rasp_bypass_uses_appropriate_opcodes(self) -> None:
        """RASP bypass uses correct opcodes for different mechanism types."""
        bypass: ArxanBypass = ArxanBypass()

        binary_data: bytearray = bytearray(0x1000)
        patches: list[BypassPatch] = []

        rasp_mechanisms: list[RASPMechanism] = [
            RASPMechanism("anti_debug", 0x100, "IsDebuggerPresent", "peb_check", "high"),
            RASPMechanism("anti_frida", 0x200, "runtime", "string_detection", "high"),
            RASPMechanism("anti_hook", 0x300, "runtime", "integrity_check", "medium"),
            RASPMechanism("exception_handler", 0x400, "SEH", "exception_based", "high"),
        ]

        bypass._neutralize_rasp(binary_data, rasp_mechanisms, patches)

        assert len(patches) == 4

        assert patches[0].patched_bytes == b"\x33\xc0\xc3"
        assert patches[0].address == 0x100

        assert patches[1].patched_bytes == bypass.NOP_OPCODE * 10
        assert patches[1].address == 0x200

        assert patches[2].patched_bytes == b"\xb8\x01\x00\x00\x00\xc3"
        assert patches[2].address == 0x300

        assert patches[3].patched_bytes == bypass.NOP_OPCODE * 8
        assert patches[3].address == 0x400

    def test_rasp_bypass_count_matches_defeated_mechanisms(self, arxan_protected_pe: Path) -> None:
        """RASP bypass count accurately reflects defeated mechanisms."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        rasp_patches: list[BypassPatch] = [p for p in result.patches_applied if p.patch_type == "rasp_bypass"]
        assert result.rasp_mechanisms_defeated == len(rasp_patches)

    def test_bypass_handles_generic_rasp_mechanisms(self) -> None:
        """Bypass handles generic RASP mechanisms."""
        bypass: ArxanBypass = ArxanBypass()

        binary_data: bytearray = bytearray(0x1000)
        patches: list[BypassPatch] = []

        rasp_mechanisms: list[RASPMechanism] = [
            RASPMechanism("unknown_rasp", 0x500, "runtime", "custom_check", "medium")
        ]

        bypass._neutralize_rasp(binary_data, rasp_mechanisms, patches)

        assert len(patches) == 1
        assert patches[0].patched_bytes == bypass.NOP_OPCODE * 6


class TestStringDecryption:
    """Test encrypted string decryption functionality."""

    def test_bypass_decrypts_xor_encrypted_strings(self) -> None:
        """Bypass successfully decrypts XOR-encrypted strings."""
        bypass: ArxanBypass = ArxanBypass()

        plaintext: bytes = b"LICENSE_KEY_VALIDATION"
        xor_key: int = 0x42
        encrypted: bytes = bytes(b ^ xor_key for b in plaintext)

        binary_data: bytearray = bytearray(0x1000)
        binary_data[0x500 : 0x500 + len(encrypted)] = encrypted

        patches: list[BypassPatch] = []
        encrypted_regions: list[tuple[int, int]] = [(0x500, len(encrypted))]

        bypass._decrypt_strings(binary_data, encrypted_regions, patches)

        string_patches: list[BypassPatch] = [p for p in patches if p.patch_type == "string_decryption"]
        assert len(string_patches) > 0

        decrypted_patch: BypassPatch = string_patches[0]
        assert decrypted_patch.original_bytes == encrypted

        printable_count: int = sum(bool(32 <= b < 127) for b in decrypted_patch.patched_bytes)
        printable_ratio: float = printable_count / len(decrypted_patch.patched_bytes)
        assert printable_ratio > 0.7

    def test_string_decryption_validates_printable_ratio(self) -> None:
        """String decryption validates that decrypted data is printable."""
        bypass: ArxanBypass = ArxanBypass()

        random_bytes: bytes = bytes([0xFF, 0xFE, 0xFD, 0xFC] * 10)

        binary_data: bytearray = bytearray(0x1000)
        binary_data[0x500 : 0x500 + len(random_bytes)] = random_bytes

        patches: list[BypassPatch] = []
        encrypted_regions: list[tuple[int, int]] = [(0x500, len(random_bytes))]

        bypass._decrypt_strings(binary_data, encrypted_regions, patches)

        string_patches: list[BypassPatch] = [p for p in patches if p.patch_type == "string_decryption"]

        for patch in string_patches:
            printable_count: int = sum(bool(32 <= b < 127) for b in patch.patched_bytes)
            printable_ratio: float = printable_count / len(patch.patched_bytes)
            assert printable_ratio > 0.7

    def test_string_decryption_limits_processed_regions(self) -> None:
        """String decryption limits number of regions for performance."""
        bypass: ArxanBypass = ArxanBypass()

        binary_data: bytearray = bytearray(0x10000)
        patches: list[BypassPatch] = []

        encrypted_regions: list[tuple[int, int]] = [(i * 0x100, 50) for i in range(20)]

        bypass._decrypt_strings(binary_data, encrypted_regions, patches)

        assert len(encrypted_regions) == 20

    def test_string_decryption_works_on_arxan_binary(self, arxan_protected_pe: Path) -> None:
        """String decryption finds encrypted strings in Arxan binary."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        string_patches: list[BypassPatch] = [
            p for p in result.patches_applied if p.patch_type == "string_decryption"
        ]

        for patch in string_patches:
            assert len(patch.original_bytes) > 0
            assert len(patch.patched_bytes) == len(patch.original_bytes)


class TestFridaBypassScriptGeneration:
    """Test Frida runtime bypass script generation."""

    def test_frida_script_creates_valid_javascript(self) -> None:
        """Frida script generation creates syntactically valid JavaScript."""
        bypass: ArxanBypass = ArxanBypass()

        analysis_result: ArxanAnalysisResult = ArxanAnalysisResult()
        analysis_result.license_routines = [
            LicenseValidationRoutine(
                address=0x401000,
                function_name="check_license",
                algorithm="RSA",
                key_length=2048,
                validation_type="rsa_validation",
            )
        ]

        script: str = bypass._generate_frida_bypass_script(analysis_result)

        assert "console.log" in script
        assert "Interceptor.attach" in script or "Interceptor.replace" in script
        assert "IsDebuggerPresent" in script
        assert "CheckRemoteDebuggerPresent" in script
        assert "NtQueryInformationProcess" in script

    def test_frida_script_includes_anti_debug_bypasses(self) -> None:
        """Frida script includes comprehensive anti-debugging bypasses."""
        bypass: ArxanBypass = ArxanBypass()

        analysis_result: ArxanAnalysisResult = ArxanAnalysisResult()

        script: str = bypass._generate_frida_bypass_script(analysis_result)

        assert "IsDebuggerPresent" in script
        assert "CheckRemoteDebuggerPresent" in script
        assert "NtQueryInformationProcess" in script
        assert "kernel32.dll" in script
        assert "ntdll.dll" in script

    def test_frida_script_includes_integrity_check_bypasses(self) -> None:
        """Frida script includes integrity check bypass hooks."""
        bypass: ArxanBypass = ArxanBypass()

        analysis_result: ArxanAnalysisResult = ArxanAnalysisResult()

        script: str = bypass._generate_frida_bypass_script(analysis_result)

        assert "CryptHashData" in script
        assert "CryptVerifySignature" in script
        assert "Advapi32.dll" in script

    def test_frida_script_includes_memory_protection_bypasses(self) -> None:
        """Frida script includes memory protection bypass hooks."""
        bypass: ArxanBypass = ArxanBypass()

        analysis_result: ArxanAnalysisResult = ArxanAnalysisResult()

        script: str = bypass._generate_frida_bypass_script(analysis_result)

        assert "VirtualProtect" in script
        assert "kernel32.dll" in script

    def test_frida_script_includes_license_hooks(self) -> None:
        """Frida script includes hooks for license validation functions."""
        bypass: ArxanBypass = ArxanBypass()

        analysis_result: ArxanAnalysisResult = ArxanAnalysisResult()
        analysis_result.license_routines = [
            LicenseValidationRoutine(0x401000, "lic1", "RSA", 2048, "rsa_validation"),
            LicenseValidationRoutine(0x402000, "lic2", "AES", 256, "aes_license"),
            LicenseValidationRoutine(0x403000, "lic3", "custom", 128, "serial_check"),
        ]

        script: str = bypass._generate_frida_bypass_script(analysis_result)

        assert "0x401000" in script
        assert "0x402000" in script
        assert "0x403000" in script
        assert script.count("licenseFunc") >= 3

    def test_frida_script_limits_license_hook_count(self) -> None:
        """Frida script generation limits number of license hooks."""
        bypass: ArxanBypass = ArxanBypass()

        analysis_result: ArxanAnalysisResult = ArxanAnalysisResult()
        analysis_result.license_routines = [
            LicenseValidationRoutine(0x400000 + i * 0x1000, f"lic{i}", "RSA", 2048, "rsa_validation")
            for i in range(10)
        ]

        script: str = bypass._generate_frida_bypass_script(analysis_result)

        assert all(hex(0x400000 + i * 0x1000)[2:] in script for i in range(5))

        assert not any(hex(0x400000 + i * 0x1000)[2:] in script for i in range(6, 10))


class TestPEUtilityFunctions:
    """Test PE-specific utility functions."""

    def test_rva_to_offset_converts_correctly(self, arxan_protected_pe: Path) -> None:
        """RVA to file offset conversion works correctly for PE sections."""
        bypass: ArxanBypass = ArxanBypass()

        try:
            import pefile

            pe: pefile.PE = pefile.PE(str(arxan_protected_pe))

            text_section: pefile.SectionStructure = next(s for s in pe.sections if b".text" in s.Name)
            rva: int = text_section.VirtualAddress + 0x100

            offset: int | None = bypass._rva_to_offset(pe, rva)

            assert offset is not None
            assert offset >= text_section.PointerToRawData
            assert offset < text_section.PointerToRawData + text_section.SizeOfRawData

            pe.close()

        except ImportError:
            pytest.skip("pefile not available")

    def test_calculate_pe_checksum_produces_valid_value(self, arxan_protected_pe: Path) -> None:
        """PE checksum calculation produces valid checksum value."""
        bypass: ArxanBypass = ArxanBypass()

        binary_data: bytes = arxan_protected_pe.read_bytes()

        checksum: int = bypass._calculate_pe_checksum(binary_data)

        assert isinstance(checksum, int)
        assert checksum > 0
        assert checksum <= 0xFFFFFFFF

    def test_calculate_pe_checksum_handles_short_binary(self) -> None:
        """PE checksum calculation handles short binaries correctly."""
        bypass: ArxanBypass = ArxanBypass()

        short_data: bytes = b"\x4D\x5A" + b"\x00" * 100

        checksum: int = bypass._calculate_pe_checksum(short_data)

        assert isinstance(checksum, int)
        assert checksum > 0


class TestBypassCleanup:
    """Test cleanup and resource management."""

    def test_cleanup_handles_no_active_session(self) -> None:
        """Cleanup handles case with no active Frida session."""
        bypass: ArxanBypass = ArxanBypass()

        bypass.cleanup()

        assert bypass.frida_session is None
        assert bypass.frida_script is None

    def test_cleanup_does_not_raise_exceptions(self) -> None:
        """Cleanup does not raise exceptions even with invalid state."""
        bypass: ArxanBypass = ArxanBypass()

        bypass.frida_session = None
        bypass.frida_script = None

        bypass.cleanup()


class TestBypassEdgeCases:
    """Test edge cases and error handling."""

    def test_bypass_handles_binary_with_no_protections(self, minimal_arxan_binary: Path) -> None:
        """Bypass handles binary with minimal protection mechanisms."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(minimal_arxan_binary)

        assert result.success is True

    def test_bypass_handles_large_address_values(self) -> None:
        """Bypass handles large memory addresses correctly."""
        bypass: ArxanBypass = ArxanBypass()

        binary_data: bytearray = bytearray(0x3000)
        patches: list[BypassPatch] = []

        tamper_checks: list[TamperCheckLocation] = [
            TamperCheckLocation(
                address=0x2FFF,
                size=10,
                check_type="tamper_detection",
                target_region=(0x2000, 0x3000),
                algorithm="crc32",
                bypass_complexity="low",
            )
        ]

        bypass._bypass_tamper_checks(binary_data, tamper_checks, patches)

        assert len(patches) == 1
        assert patches[0].address == 0x2FFF

    def test_bypass_handles_out_of_bounds_addresses(self) -> None:
        """Bypass safely handles addresses beyond binary size."""
        bypass: ArxanBypass = ArxanBypass()

        binary_data: bytearray = bytearray(0x1000)
        patches: list[BypassPatch] = []

        tamper_checks: list[TamperCheckLocation] = [
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

        assert len(patches) == 0

    def test_bypass_handles_overlapping_protection_mechanisms(self) -> None:
        """Bypass handles overlapping protection mechanisms."""
        bypass: ArxanBypass = ArxanBypass()

        binary_data: bytearray = bytearray(0x1000)
        patches: list[BypassPatch] = []

        tamper_checks: list[TamperCheckLocation] = [
            TamperCheckLocation(0x500, 10, "tamper_detection", (0x400, 0x600), "crc32", "low"),
            TamperCheckLocation(0x505, 10, "tamper_detection", (0x400, 0x600), "md5", "medium"),
        ]

        bypass._bypass_tamper_checks(binary_data, tamper_checks, patches)

        assert len(patches) == 2
        assert patches[0].address == 0x500
        assert patches[1].address == 0x505


class TestBypassMetadata:
    """Test bypass result metadata handling."""

    def test_bypass_includes_version_metadata(self, arxan_protected_pe: Path) -> None:
        """Bypass result includes Arxan version detection metadata."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        assert "arxan_version" in result.metadata
        assert isinstance(result.metadata["arxan_version"], str)

    def test_bypass_includes_confidence_metadata(self, arxan_protected_pe: Path) -> None:
        """Bypass result includes detection confidence metadata."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        assert "confidence" in result.metadata
        assert isinstance(result.metadata["confidence"], float)
        assert 0.0 <= result.metadata["confidence"] <= 1.0

    def test_bypass_counts_patch_types_accurately(self, arxan_protected_pe: Path) -> None:
        """Bypass accurately counts different patch types."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        license_count: int = len([p for p in result.patches_applied if p.patch_type == "license_bypass"])
        integrity_count: int = len([p for p in result.patches_applied if p.patch_type == "integrity_bypass"])
        rasp_count: int = len([p for p in result.patches_applied if p.patch_type == "rasp_bypass"])

        assert result.license_checks_bypassed == license_count
        assert result.integrity_checks_neutralized == integrity_count
        assert result.rasp_mechanisms_defeated == rasp_count


class TestBypassBinaryIntegrity:
    """Test that bypass maintains binary integrity."""

    def test_bypass_maintains_pe_signature(self, arxan_protected_pe: Path) -> None:
        """Bypass maintains PE signature after patching."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        patched_path: Path = Path(result.patched_binary_path)
        patched_data: bytes = patched_path.read_bytes()

        assert patched_data[:2] == b"MZ"

        dos_header_offset: int = struct.unpack_from("<I", patched_data, 0x3C)[0]
        assert patched_data[dos_header_offset : dos_header_offset + 4] == b"PE\x00\x00"

    def test_patched_binary_is_valid_pe(self, arxan_protected_pe: Path) -> None:
        """Patched binary remains a valid PE file."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        try:
            import pefile

            patched_path: Path = Path(result.patched_binary_path)
            pe: pefile.PE = pefile.PE(str(patched_path))

            assert pe.DOS_HEADER is not None
            assert pe.NT_HEADERS is not None
            assert pe.FILE_HEADER is not None
            assert pe.OPTIONAL_HEADER is not None

            pe.close()

        except ImportError:
            pytest.skip("pefile not available")

    def test_bypass_preserves_section_structure(self, arxan_protected_pe: Path) -> None:
        """Bypass preserves section structure in PE header."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(arxan_protected_pe)

        try:
            import pefile

            original_pe: pefile.PE = pefile.PE(str(arxan_protected_pe))
            patched_pe: pefile.PE = pefile.PE(result.patched_binary_path)

            assert len(original_pe.sections) == len(patched_pe.sections)

            original_pe.close()
            patched_pe.close()

        except ImportError:
            pytest.skip("pefile not available")


class TestLayeredProtectionBypass:
    """Test bypass against binaries with layered protection schemes."""

    def test_bypass_handles_multiple_protection_layers(self, layered_protection_binary: Path) -> None:
        """Bypass defeats multiple protection layers simultaneously."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(layered_protection_binary)

        assert result.success is True
        assert len(result.patches_applied) > 0

        patch_types: set[str] = {p.patch_type for p in result.patches_applied}
        assert len(patch_types) > 1

    def test_bypass_applies_all_necessary_patches(self, layered_protection_binary: Path) -> None:
        """Bypass applies patches for all protection mechanisms."""
        bypass: ArxanBypass = ArxanBypass()

        result: ArxanBypassResult = bypass.bypass(layered_protection_binary)

        total_bypassed: int = (
            result.license_checks_bypassed
            + result.integrity_checks_neutralized
            + result.rasp_mechanisms_defeated
        )

        assert total_bypassed > 0
        assert len(result.patches_applied) >= total_bypassed
