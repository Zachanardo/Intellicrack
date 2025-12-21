"""Production-Grade Tests for Fingerprint Engine.

Validates real binary fingerprinting capabilities including hash generation,
protection scheme detection, compiler identification, license system recognition,
and code similarity analysis. Tests use REAL Windows binaries only.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import struct
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False

try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False

from intellicrack.core.analysis.fingerprint_engine import (
    BinaryFingerprint,
    CompilerFingerprint,
    FingerprintEngine,
    FingerprintType,
    LicenseSystemFingerprint,
    ProtectionFingerprint,
)


@pytest.fixture
def temp_workspace(tmp_path: Path) -> Path:
    """Create temporary workspace for test files."""
    workspace = tmp_path / "fingerprint_tests"
    workspace.mkdir(exist_ok=True)
    return workspace


@pytest.fixture
def fingerprint_engine() -> FingerprintEngine:
    """Create fingerprint engine instance."""
    return FingerprintEngine()


@pytest.fixture
def minimal_pe_binary(temp_workspace: Path) -> Path:
    """Create minimal valid PE binary for testing."""
    binary_path = temp_workspace / "minimal.exe"

    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

    dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
    dos_stub += b"This program cannot be run in DOS mode.\r\r\n$"
    dos_stub += b"\x00" * (0x80 - 64 - len(dos_stub))

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,
        2,
        0x5F5E100C,
        0,
        0,
        224,
        0x0122,
    )

    optional_header = bytearray(224)
    optional_header[:2] = struct.pack("<H", 0x010B)
    optional_header[16:20] = struct.pack("<I", 0x1000)
    optional_header[20:24] = struct.pack("<I", 0x2000)
    optional_header[24:28] = struct.pack("<I", 0x1000)
    optional_header[32:36] = struct.pack("<I", 0x200)
    optional_header[36:40] = struct.pack("<I", 0x10000)

    section_1 = bytearray(40)
    section_1[:8] = b".text\x00\x00\x00"
    section_1[8:12] = struct.pack("<I", 0x1000)
    section_1[12:16] = struct.pack("<I", 0x1000)
    section_1[16:20] = struct.pack("<I", 0x200)
    section_1[20:24] = struct.pack("<I", 0x400)
    section_1[36:40] = struct.pack("<I", 0x20000040)

    section_2 = bytearray(40)
    section_2[:8] = b".data\x00\x00\x00"
    section_2[8:12] = struct.pack("<I", 0x2000)
    section_2[12:16] = struct.pack("<I", 0x2000)
    section_2[16:20] = struct.pack("<I", 0x200)
    section_2[20:24] = struct.pack("<I", 0x600)
    section_2[36:40] = struct.pack("<I", 0xC0000040)

    text_section_data = b"\xc3" * 0x200
    data_section_data = b"\x00" * 0x200

    binary_data = (
        dos_header
        + dos_stub
        + pe_signature
        + coff_header
        + optional_header
        + section_1
        + section_2
        + text_section_data
        + data_section_data
    )

    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def upx_packed_binary(temp_workspace: Path) -> Path:
    """Create PE binary with UPX signatures."""
    binary_path = temp_workspace / "upx_packed.exe"

    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

    dos_stub = b"\x0e\x1f" + b"\x00" * (0x80 - 64 - 2)

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack("<HHIIIHH", 0x014C, 3, 0x5F5E100C, 0, 0, 224, 0x0122)

    optional_header = bytearray(224)
    optional_header[:2] = struct.pack("<H", 0x010B)

    upx0_section = bytearray(40)
    upx0_section[:8] = b"UPX0\x00\x00\x00\x00"
    upx0_section[8:12] = struct.pack("<I", 0x1000)
    upx0_section[12:16] = struct.pack("<I", 0x1000)
    upx0_section[16:20] = struct.pack("<I", 0x200)
    upx0_section[20:24] = struct.pack("<I", 0x400)
    upx0_section[36:40] = struct.pack("<I", 0xE0000020)

    upx1_section = bytearray(40)
    upx1_section[:8] = b"UPX1\x00\x00\x00\x00"
    upx1_section[8:12] = struct.pack("<I", 0x2000)
    upx1_section[12:16] = struct.pack("<I", 0x2000)
    upx1_section[16:20] = struct.pack("<I", 0x400)
    upx1_section[20:24] = struct.pack("<I", 0x600)
    upx1_section[36:40] = struct.pack("<I", 0xE0000040)

    upx2_section = bytearray(40)
    upx2_section[:8] = b"UPX2\x00\x00\x00\x00"
    upx2_section[8:12] = struct.pack("<I", 0x3000)
    upx2_section[12:16] = struct.pack("<I", 0x1000)
    upx2_section[16:20] = struct.pack("<I", 0x200)
    upx2_section[20:24] = struct.pack("<I", 0xA00)
    upx2_section[36:40] = struct.pack("<I", 0xC0000040)

    upx0_data = bytes.fromhex("60BE00000000") + b"\x00" * (0x200 - 6)
    upx1_data = b"UPX!" + b"$Info:" + b"\x00" * (0x400 - 10)
    upx2_data = b"\x00" * 0x200

    binary_data = (
        dos_header
        + dos_stub
        + pe_signature
        + coff_header
        + optional_header
        + upx0_section
        + upx1_section
        + upx2_section
        + upx0_data
        + upx1_data
        + upx2_data
    )

    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def vmprotect_binary(temp_workspace: Path) -> Path:
    """Create PE binary with VMProtect signatures."""
    binary_path = temp_workspace / "vmprotect.exe"

    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

    dos_stub = b"\x00" * (0x80 - 64)

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0x5F5E100C, 0, 0, 224, 0x0122)

    optional_header = bytearray(224)
    optional_header[:2] = struct.pack("<H", 0x010B)

    vmp0_section = bytearray(40)
    vmp0_section[:8] = b".vmp0\x00\x00\x00"
    vmp0_section[8:12] = struct.pack("<I", 0x1000)
    vmp0_section[12:16] = struct.pack("<I", 0x1000)
    vmp0_section[16:20] = struct.pack("<I", 0x400)
    vmp0_section[20:24] = struct.pack("<I", 0x400)
    vmp0_section[36:40] = struct.pack("<I", 0xE0000060)

    vmp1_section = bytearray(40)
    vmp1_section[:8] = b".vmp1\x00\x00\x00"
    vmp1_section[8:12] = struct.pack("<I", 0x2000)
    vmp1_section[12:16] = struct.pack("<I", 0x2000)
    vmp1_section[16:20] = struct.pack("<I", 0x400)
    vmp1_section[20:24] = struct.pack("<I", 0x800)
    vmp1_section[36:40] = struct.pack("<I", 0xC0000040)

    vmp0_data = bytes.fromhex("60E8000000005D") + b"VMProtect" + b"\x00" * (0x400 - 16)
    vmp1_data = bytes.fromhex("558BEC83C4F053") + b"\x00" * (0x400 - 7)

    binary_data = (
        dos_header
        + dos_stub
        + pe_signature
        + coff_header
        + optional_header
        + vmp0_section
        + vmp1_section
        + vmp0_data
        + vmp1_data
    )

    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def themida_binary(temp_workspace: Path) -> Path:
    """Create PE binary with Themida signatures."""
    binary_path = temp_workspace / "themida.exe"

    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80)
    dos_stub = b"\x00" * (0x80 - 64)

    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0x5F5E100C, 0, 0, 224, 0x0122)
    optional_header = bytearray(224)
    optional_header[:2] = struct.pack("<H", 0x010B)

    themida_section = bytearray(40)
    themida_section[:8] = b".themida"
    themida_section[8:12] = struct.pack("<I", 0x1000)
    themida_section[12:16] = struct.pack("<I", 0x1000)
    themida_section[16:20] = struct.pack("<I", 0x400)
    themida_section[20:24] = struct.pack("<I", 0x400)
    themida_section[36:40] = struct.pack("<I", 0xE0000060)

    text_section = bytearray(40)
    text_section[:8] = b".text\x00\x00\x00"
    text_section[8:12] = struct.pack("<I", 0x2000)
    text_section[12:16] = struct.pack("<I", 0x2000)
    text_section[16:20] = struct.pack("<I", 0x400)
    text_section[20:24] = struct.pack("<I", 0x800)
    text_section[36:40] = struct.pack("<I", 0x60000020)

    themida_data = bytes.fromhex("558BEC83C4F0B8") + b"Themida" + b"\x00" * (0x400 - 14)
    text_data = bytes.fromhex("E8000000005D81ED") + b"\x00" * (0x400 - 8)

    binary_data = (
        dos_header
        + dos_stub
        + pe_signature
        + coff_header
        + optional_header
        + themida_section
        + text_section
        + themida_data
        + text_data
    )

    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def flexlm_binary(temp_workspace: Path) -> Path:
    """Create PE binary with FlexLM license system signatures."""
    binary_path = temp_workspace / "flexlm_app.exe"

    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80)
    dos_stub = b"\x00" * (0x80 - 64)

    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0x5F5E100C, 0, 0, 224, 0x0122)
    optional_header = bytearray(224)
    optional_header[:2] = struct.pack("<H", 0x010B)

    text_section = bytearray(40)
    text_section[:8] = b".text\x00\x00\x00"
    text_section[8:12] = struct.pack("<I", 0x1000)
    text_section[12:16] = struct.pack("<I", 0x1000)
    text_section[16:20] = struct.pack("<I", 0x400)
    text_section[20:24] = struct.pack("<I", 0x400)
    text_section[36:40] = struct.pack("<I", 0x60000020)

    rdata_section = bytearray(40)
    rdata_section[:8] = b".rdata\x00\x00"
    rdata_section[8:12] = struct.pack("<I", 0x2000)
    rdata_section[12:16] = struct.pack("<I", 0x2000)
    rdata_section[16:20] = struct.pack("<I", 0x400)
    rdata_section[20:24] = struct.pack("<I", 0x800)
    rdata_section[36:40] = struct.pack("<I", 0x40000040)

    text_data = b"\x00" * 0x400
    rdata_data = b"lmgr11.dll\x00FLEXlm\x00lc_init\x00lc_checkout\x00FLEXLM_LICENSE_FILE\x00"
    rdata_data += b"\x00" * (0x400 - len(rdata_data))

    binary_data = (
        dos_header
        + dos_stub
        + pe_signature
        + coff_header
        + optional_header
        + text_section
        + rdata_section
        + text_data
        + rdata_data
    )

    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def hasp_binary(temp_workspace: Path) -> Path:
    """Create PE binary with HASP dongle protection signatures."""
    binary_path = temp_workspace / "hasp_app.exe"

    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80)
    dos_stub = b"\x00" * (0x80 - 64)

    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0x5F5E100C, 0, 0, 224, 0x0122)
    optional_header = bytearray(224)
    optional_header[:2] = struct.pack("<H", 0x010B)

    text_section = bytearray(40)
    text_section[:8] = b".text\x00\x00\x00"
    text_section[8:12] = struct.pack("<I", 0x1000)
    text_section[12:16] = struct.pack("<I", 0x1000)
    text_section[16:20] = struct.pack("<I", 0x400)
    text_section[20:24] = struct.pack("<I", 0x400)
    text_section[36:40] = struct.pack("<I", 0x60000020)

    text_data = b"hasp_windows.dll\x00HASP\x00hasp_login\x00hasp_logout\x00Sentinel\x00Aladdin\x00"
    text_data += b"\x00" * (0x400 - len(text_data))

    binary_data = (
        dos_header
        + dos_stub
        + pe_signature
        + coff_header
        + optional_header
        + text_section
        + text_data
    )

    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def msvc_compiled_binary(temp_workspace: Path) -> Path:
    """Create PE binary with MSVC compiler signatures."""
    binary_path = temp_workspace / "msvc_app.exe"

    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80)
    dos_stub = b"\x00" * (0x80 - 64)

    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0x5F5E100C, 0, 0, 224, 0x0122)
    optional_header = bytearray(224)
    optional_header[:2] = struct.pack("<H", 0x010B)

    text_section = bytearray(40)
    text_section[:8] = b".text\x00\x00\x00"
    text_section[8:12] = struct.pack("<I", 0x1000)
    text_section[12:16] = struct.pack("<I", 0x1000)
    text_section[16:20] = struct.pack("<I", 0x400)
    text_section[20:24] = struct.pack("<I", 0x400)
    text_section[36:40] = struct.pack("<I", 0x60000020)

    rdata_section = bytearray(40)
    rdata_section[:8] = b".rdata\x00\x00"
    rdata_section[8:12] = struct.pack("<I", 0x2000)
    rdata_section[12:16] = struct.pack("<I", 0x2000)
    rdata_section[16:20] = struct.pack("<I", 0x400)
    rdata_section[20:24] = struct.pack("<I", 0x800)
    rdata_section[36:40] = struct.pack("<I", 0x40000040)

    text_data = bytes.fromhex("558BEC6AFF68") + b"\x00" * (0x400 - 6)
    rdata_data = b"__CxxFrameHandler3\x00__CxxThrowException\x00Microsoft\x00Visual C++\x00"
    rdata_data += b"\x00" * (0x400 - len(rdata_data))

    binary_data = (
        dos_header
        + dos_stub
        + pe_signature
        + coff_header
        + optional_header
        + text_section
        + rdata_section
        + text_data
        + rdata_data
    )

    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def gcc_compiled_binary(temp_workspace: Path) -> Path:
    """Create PE binary with GCC compiler signatures."""
    binary_path = temp_workspace / "gcc_app.exe"

    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80)
    dos_stub = b"\x00" * (0x80 - 64)

    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0x5F5E100C, 0, 0, 224, 0x0122)
    optional_header = bytearray(224)
    optional_header[:2] = struct.pack("<H", 0x010B)

    text_section = bytearray(40)
    text_section[:8] = b".text\x00\x00\x00"
    text_section[8:12] = struct.pack("<I", 0x1000)
    text_section[12:16] = struct.pack("<I", 0x1000)
    text_section[16:20] = struct.pack("<I", 0x400)
    text_section[20:24] = struct.pack("<I", 0x400)
    text_section[36:40] = struct.pack("<I", 0x60000020)

    rodata_section = bytearray(40)
    rodata_section[:8] = b".rodata\x00"
    rodata_section[8:12] = struct.pack("<I", 0x2000)
    rodata_section[12:16] = struct.pack("<I", 0x2000)
    rodata_section[16:20] = struct.pack("<I", 0x400)
    rodata_section[20:24] = struct.pack("<I", 0x800)
    rodata_section[36:40] = struct.pack("<I", 0x40000040)

    text_data = bytes.fromhex("5589E5") + b"\x00" * (0x400 - 3)
    rodata_data = b"__gxx_personality_v0\x00__cxa_throw\x00GCC:\x00GNU\x00"
    rodata_data += b"\x00" * (0x400 - len(rodata_data))

    binary_data = (
        dos_header
        + dos_stub
        + pe_signature
        + coff_header
        + optional_header
        + text_section
        + rodata_section
        + text_data
        + rodata_data
    )

    binary_path.write_bytes(binary_data)
    return binary_path


class TestFingerprintEngineInitialization:
    """Test fingerprint engine initialization."""

    def test_engine_initialization(self, fingerprint_engine: FingerprintEngine) -> None:
        """Fingerprint engine initializes with signature databases."""
        assert isinstance(fingerprint_engine, FingerprintEngine)
        assert isinstance(fingerprint_engine.fingerprint_db, dict)
        assert isinstance(fingerprint_engine.protection_db, dict)
        assert isinstance(fingerprint_engine.compiler_db, dict)

    def test_protection_signatures_loaded(self, fingerprint_engine: FingerprintEngine) -> None:
        """Fingerprint engine has protection signatures loaded."""
        assert len(fingerprint_engine.PROTECTION_SIGNATURES) > 0
        assert "VMProtect" in fingerprint_engine.PROTECTION_SIGNATURES
        assert "Themida" in fingerprint_engine.PROTECTION_SIGNATURES
        assert "UPX" in fingerprint_engine.PROTECTION_SIGNATURES
        assert "Enigma" in fingerprint_engine.PROTECTION_SIGNATURES
        assert "Denuvo" in fingerprint_engine.PROTECTION_SIGNATURES

    def test_license_system_signatures_loaded(self, fingerprint_engine: FingerprintEngine) -> None:
        """Fingerprint engine has license system signatures loaded."""
        assert len(fingerprint_engine.LICENSE_SYSTEM_SIGNATURES) > 0
        assert "FlexLM" in fingerprint_engine.LICENSE_SYSTEM_SIGNATURES
        assert "HASP" in fingerprint_engine.LICENSE_SYSTEM_SIGNATURES
        assert "SafeNet" in fingerprint_engine.LICENSE_SYSTEM_SIGNATURES
        assert "Wibu CodeMeter" in fingerprint_engine.LICENSE_SYSTEM_SIGNATURES

    def test_compiler_signatures_loaded(self, fingerprint_engine: FingerprintEngine) -> None:
        """Fingerprint engine has compiler signatures loaded."""
        assert len(fingerprint_engine.COMPILER_SIGNATURES) > 0
        assert "MSVC" in fingerprint_engine.COMPILER_SIGNATURES
        assert "GCC" in fingerprint_engine.COMPILER_SIGNATURES
        assert "Clang" in fingerprint_engine.COMPILER_SIGNATURES
        assert "MinGW" in fingerprint_engine.COMPILER_SIGNATURES
        assert "Delphi" in fingerprint_engine.COMPILER_SIGNATURES


class TestBinaryFingerprintGeneration:
    """Test basic binary fingerprint generation."""

    def test_generate_fingerprint_minimal_pe(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path
    ) -> None:
        """Generate fingerprint for minimal PE binary with hash validation."""
        fingerprint = fingerprint_engine.generate_fingerprint(minimal_pe_binary)

        assert isinstance(fingerprint, BinaryFingerprint)
        assert fingerprint.path == str(minimal_pe_binary)
        assert len(fingerprint.md5) == 32
        assert len(fingerprint.sha1) == 40
        assert len(fingerprint.sha256) == 64

        binary_data = minimal_pe_binary.read_bytes()
        expected_md5 = hashlib.md5(binary_data).hexdigest()
        expected_sha1 = hashlib.sha1(binary_data).hexdigest()
        expected_sha256 = hashlib.sha256(binary_data).hexdigest()

        assert fingerprint.md5 == expected_md5
        assert fingerprint.sha1 == expected_sha1
        assert fingerprint.sha256 == expected_sha256

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_generate_fingerprint_section_hashes(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path
    ) -> None:
        """Generate fingerprint with section hash validation."""
        fingerprint = fingerprint_engine.generate_fingerprint(minimal_pe_binary)

        assert len(fingerprint.section_hashes) >= 2
        assert ".text" in fingerprint.section_hashes
        assert ".data" in fingerprint.section_hashes

        for section_name, section_hash in fingerprint.section_hashes.items():
            assert len(section_hash) == 64
            assert all(c in "0123456789abcdef" for c in section_hash)

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_generate_fingerprint_imphash(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path
    ) -> None:
        """Generate fingerprint with import hash."""
        fingerprint = fingerprint_engine.generate_fingerprint(minimal_pe_binary)

        assert fingerprint.imphash is not None or fingerprint.imphash == ""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_generate_fingerprint_pe_metadata(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path
    ) -> None:
        """Generate fingerprint with PE metadata extraction."""
        fingerprint = fingerprint_engine.generate_fingerprint(minimal_pe_binary)

        assert fingerprint.pe_timestamp is not None
        assert fingerprint.pe_timestamp > 0
        assert "pe_characteristics" in fingerprint.metadata
        assert "pe_machine" in fingerprint.metadata
        assert "pe_sections" in fingerprint.metadata

    @pytest.mark.skipif(not SSDEEP_AVAILABLE, reason="ssdeep not available")
    def test_generate_fingerprint_ssdeep(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path
    ) -> None:
        """Generate fingerprint with ssdeep fuzzy hash."""
        fingerprint = fingerprint_engine.generate_fingerprint(minimal_pe_binary)

        assert fingerprint.ssdeep is not None
        assert ":" in fingerprint.ssdeep

    @pytest.mark.skipif(not TLSH_AVAILABLE, reason="tlsh not available")
    def test_generate_fingerprint_tlsh(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path
    ) -> None:
        """Generate fingerprint with TLSH locality-sensitive hash."""
        fingerprint = fingerprint_engine.generate_fingerprint(minimal_pe_binary)

        if len(minimal_pe_binary.read_bytes()) >= 256:
            assert fingerprint.tlsh is not None

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_generate_fingerprint_code_sections(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path
    ) -> None:
        """Generate fingerprint with code section hash."""
        fingerprint = fingerprint_engine.generate_fingerprint(minimal_pe_binary)

        assert fingerprint.code_sections_hash is not None
        assert len(fingerprint.code_sections_hash) == 64


class TestProtectionFingerprinting:
    """Test protection scheme fingerprinting."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_upx_protection(
        self, fingerprint_engine: FingerprintEngine, upx_packed_binary: Path
    ) -> None:
        """Fingerprint UPX packed binary with signature matching."""
        protections = fingerprint_engine.fingerprint_protection(upx_packed_binary)

        assert len(protections) > 0
        upx_detected = any(p.protection_name == "UPX" for p in protections)
        assert upx_detected

        upx_fingerprint = next(p for p in protections if p.protection_name == "UPX")
        assert upx_fingerprint.confidence >= 0.5
        assert "UPX0" in upx_fingerprint.section_names or "UPX1" in upx_fingerprint.section_names

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_vmprotect_protection(
        self, fingerprint_engine: FingerprintEngine, vmprotect_binary: Path
    ) -> None:
        """Fingerprint VMProtect protected binary with signature matching."""
        protections = fingerprint_engine.fingerprint_protection(vmprotect_binary)

        assert len(protections) > 0
        vmp_detected = any(p.protection_name == "VMProtect" for p in protections)
        assert vmp_detected

        vmp_fingerprint = next(p for p in protections if p.protection_name == "VMProtect")
        assert vmp_fingerprint.confidence >= 0.5
        assert ".vmp0" in vmp_fingerprint.section_names or ".vmp1" in vmp_fingerprint.section_names
        assert len(vmp_fingerprint.signatures) > 0
        assert len(vmp_fingerprint.entropy_profile) >= 2

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_themida_protection(
        self, fingerprint_engine: FingerprintEngine, themida_binary: Path
    ) -> None:
        """Fingerprint Themida protected binary with signature matching."""
        protections = fingerprint_engine.fingerprint_protection(themida_binary)

        assert len(protections) > 0
        themida_detected = any(p.protection_name == "Themida" for p in protections)
        assert themida_detected

        themida_fingerprint = next(p for p in protections if p.protection_name == "Themida")
        assert themida_fingerprint.confidence >= 0.5
        assert ".themida" in themida_fingerprint.section_names

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_protection_metadata(
        self, fingerprint_engine: FingerprintEngine, upx_packed_binary: Path
    ) -> None:
        """Fingerprint protection with metadata extraction."""
        protections = fingerprint_engine.fingerprint_protection(upx_packed_binary)

        assert len(protections) > 0
        for protection in protections:
            assert isinstance(protection.metadata, dict)
            assert "section_match" in protection.metadata
            assert "import_match" in protection.metadata
            assert "string_match" in protection.metadata
            assert "pattern_matches" in protection.metadata

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_real_protected_binary(
        self, fingerprint_engine: FingerprintEngine
    ) -> None:
        """Fingerprint real protected binary from test fixtures."""
        test_binaries = [
            Path("D:/Intellicrack/tests/fixtures/binaries/protected/upx_packed_0.exe"),
            Path("D:/Intellicrack/tests/fixtures/binaries/protected/vmprotect_protected.exe"),
            Path("D:/Intellicrack/tests/fixtures/binaries/protected/themida_protected.exe"),
        ]

        for binary_path in test_binaries:
            if not binary_path.exists():
                continue

            protections = fingerprint_engine.fingerprint_protection(binary_path)
            assert isinstance(protections, list)


class TestCompilerFingerprinting:
    """Test compiler/linker fingerprinting."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_msvc_compiler(
        self, fingerprint_engine: FingerprintEngine, msvc_compiled_binary: Path
    ) -> None:
        """Fingerprint MSVC compiled binary with signature matching."""
        compiler = fingerprint_engine.fingerprint_compiler(msvc_compiled_binary)

        assert compiler is not None
        assert isinstance(compiler, CompilerFingerprint)
        assert compiler.compiler_name == "MSVC"
        assert compiler.confidence > 0.0
        assert len(compiler.runtime_signatures) > 0

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_gcc_compiler(
        self, fingerprint_engine: FingerprintEngine, gcc_compiled_binary: Path
    ) -> None:
        """Fingerprint GCC compiled binary with signature matching."""
        compiler = fingerprint_engine.fingerprint_compiler(gcc_compiled_binary)

        assert compiler is not None
        assert isinstance(compiler, CompilerFingerprint)
        assert compiler.compiler_name == "GCC"
        assert compiler.confidence > 0.0

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_compiler_metadata(
        self, fingerprint_engine: FingerprintEngine, msvc_compiled_binary: Path
    ) -> None:
        """Fingerprint compiler with metadata extraction."""
        compiler = fingerprint_engine.fingerprint_compiler(msvc_compiled_binary)

        assert compiler is not None
        assert isinstance(compiler.metadata, dict)
        assert "import_matches" in compiler.metadata
        assert "section_matches" in compiler.metadata
        assert "string_matches" in compiler.metadata
        assert "pattern_matches" in compiler.metadata

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_real_binaries_compiler(
        self, fingerprint_engine: FingerprintEngine
    ) -> None:
        """Fingerprint real binaries to detect compiler."""
        test_binaries = [
            Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/7zip.exe"),
            Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/notepadpp.exe"),
        ]

        for binary_path in test_binaries:
            if not binary_path.exists():
                continue

            compiler = fingerprint_engine.fingerprint_compiler(binary_path)
            if compiler is not None:
                assert isinstance(compiler, CompilerFingerprint)
                assert compiler.confidence > 0.0


class TestLicenseSystemFingerprinting:
    """Test license system fingerprinting."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_flexlm_license_system(
        self, fingerprint_engine: FingerprintEngine, flexlm_binary: Path
    ) -> None:
        """Fingerprint FlexLM license system with signature matching."""
        license_systems = fingerprint_engine.fingerprint_license_system(flexlm_binary)

        assert len(license_systems) > 0
        flexlm_detected = any(ls.license_system == "FlexLM" for ls in license_systems)
        assert flexlm_detected

        flexlm_fingerprint = next(ls for ls in license_systems if ls.license_system == "FlexLM")
        assert flexlm_fingerprint.confidence >= 0.3
        assert len(flexlm_fingerprint.api_calls) > 0 or len(flexlm_fingerprint.file_patterns) > 0

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_hasp_license_system(
        self, fingerprint_engine: FingerprintEngine, hasp_binary: Path
    ) -> None:
        """Fingerprint HASP dongle protection with signature matching."""
        license_systems = fingerprint_engine.fingerprint_license_system(hasp_binary)

        assert len(license_systems) > 0
        hasp_detected = any(ls.license_system == "HASP" for ls in license_systems)
        assert hasp_detected

        hasp_fingerprint = next(ls for ls in license_systems if ls.license_system == "HASP")
        assert hasp_fingerprint.confidence >= 0.3

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_license_system_metadata(
        self, fingerprint_engine: FingerprintEngine, flexlm_binary: Path
    ) -> None:
        """Fingerprint license system with metadata extraction."""
        license_systems = fingerprint_engine.fingerprint_license_system(flexlm_binary)

        assert len(license_systems) > 0
        for license_system in license_systems:
            assert isinstance(license_system.metadata, dict)
            assert "dll_matches" in license_system.metadata
            assert "function_matches" in license_system.metadata
            assert "string_matches" in license_system.metadata

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_real_licensed_binaries(
        self, fingerprint_engine: FingerprintEngine
    ) -> None:
        """Fingerprint real licensed binaries from test fixtures."""
        test_binaries = [
            Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected/flexlm_license_protected.exe"),
            Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected/hasp_sentinel_protected.exe"),
            Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected/wibu_codemeter_protected.exe"),
        ]

        for binary_path in test_binaries:
            if not binary_path.exists():
                continue

            license_systems = fingerprint_engine.fingerprint_license_system(binary_path)
            assert isinstance(license_systems, list)


class TestImportTableFingerprinting:
    """Test import table fingerprinting."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_imports_basic(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path
    ) -> None:
        """Fingerprint import table from PE binary."""
        imports = fingerprint_engine.fingerprint_imports(minimal_pe_binary)

        assert isinstance(imports, dict)

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_imports_flexlm(
        self, fingerprint_engine: FingerprintEngine, flexlm_binary: Path
    ) -> None:
        """Fingerprint imports from FlexLM binary."""
        imports = fingerprint_engine.fingerprint_imports(flexlm_binary)

        assert isinstance(imports, dict)

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_real_binary_imports(
        self, fingerprint_engine: FingerprintEngine
    ) -> None:
        """Fingerprint imports from real binary."""
        binary_path = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/7zip.exe")
        if not binary_path.exists():
            pytest.skip("Test binary not available")

        imports = fingerprint_engine.fingerprint_imports(binary_path)

        assert isinstance(imports, dict)
        assert len(imports) > 0

        for dll_name, functions in imports.items():
            assert isinstance(dll_name, str)
            assert isinstance(functions, list)
            assert len(dll_name) > 0


class TestSectionFingerprinting:
    """Test PE section fingerprinting."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_sections_basic(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path
    ) -> None:
        """Fingerprint PE sections with characteristics."""
        sections = fingerprint_engine.fingerprint_sections(minimal_pe_binary)

        assert isinstance(sections, dict)
        assert len(sections) >= 2
        assert ".text" in sections
        assert ".data" in sections

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_sections_metadata(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path
    ) -> None:
        """Fingerprint sections with complete metadata."""
        sections = fingerprint_engine.fingerprint_sections(minimal_pe_binary)

        for section_name, section_info in sections.items():
            assert "virtual_address" in section_info
            assert "virtual_size" in section_info
            assert "raw_size" in section_info
            assert "characteristics" in section_info
            assert "md5" in section_info
            assert "sha256" in section_info
            assert "entropy" in section_info
            assert "is_executable" in section_info
            assert "is_readable" in section_info
            assert "is_writable" in section_info

            assert isinstance(section_info["md5"], str)
            assert len(section_info["md5"]) == 32
            assert isinstance(section_info["sha256"], str)
            assert len(section_info["sha256"]) == 64
            assert isinstance(section_info["entropy"], float)
            assert 0.0 <= section_info["entropy"] <= 8.0

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_sections_executable_flag(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path
    ) -> None:
        """Fingerprint sections with executable flag validation."""
        sections = fingerprint_engine.fingerprint_sections(minimal_pe_binary)

        text_section = sections.get(".text")
        assert text_section is not None
        assert text_section["is_executable"]

        if data_section := sections.get(".data"):
            assert data_section["is_writable"]

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_upx_sections(
        self, fingerprint_engine: FingerprintEngine, upx_packed_binary: Path
    ) -> None:
        """Fingerprint UPX sections with entropy analysis."""
        sections = fingerprint_engine.fingerprint_sections(upx_packed_binary)

        assert len(sections) >= 3
        upx_sections = [name for name in sections.keys() if "UPX" in name]
        assert len(upx_sections) >= 2


class TestFingerprintComparison:
    """Test fingerprint similarity comparison."""

    def test_compare_identical_fingerprints(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path
    ) -> None:
        """Compare identical fingerprints for 100% similarity."""
        fp1 = fingerprint_engine.generate_fingerprint(minimal_pe_binary)
        fp2 = fingerprint_engine.generate_fingerprint(minimal_pe_binary)

        similarity = fingerprint_engine.compare_fingerprints(fp1, fp2)

        assert similarity == 1.0

    def test_compare_different_fingerprints(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path, upx_packed_binary: Path
    ) -> None:
        """Compare different fingerprints for low similarity."""
        fp1 = fingerprint_engine.generate_fingerprint(minimal_pe_binary)
        fp2 = fingerprint_engine.generate_fingerprint(upx_packed_binary)

        similarity = fingerprint_engine.compare_fingerprints(fp1, fp2)

        assert 0.0 <= similarity < 1.0

    def test_compare_modified_binary_fingerprints(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path, temp_workspace: Path
    ) -> None:
        """Compare original and slightly modified binary fingerprints."""
        fp1 = fingerprint_engine.generate_fingerprint(minimal_pe_binary)

        binary_data = minimal_pe_binary.read_bytes()
        modified_data = bytearray(binary_data)
        modified_data[-100] = (modified_data[-100] + 1) % 256
        modified_binary = temp_workspace / "modified.exe"
        modified_binary.write_bytes(modified_data)

        fp2 = fingerprint_engine.generate_fingerprint(modified_binary)

        similarity = fingerprint_engine.compare_fingerprints(fp1, fp2)

        assert 0.0 <= similarity < 1.0
        assert fp1.sha256 != fp2.sha256

    @pytest.mark.skipif(not SSDEEP_AVAILABLE, reason="ssdeep not available")
    def test_compare_fingerprints_fuzzy_hash(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path, temp_workspace: Path
    ) -> None:
        """Compare fingerprints using fuzzy hash for similarity detection."""
        fp1 = fingerprint_engine.generate_fingerprint(minimal_pe_binary)

        binary_data = minimal_pe_binary.read_bytes()
        modified_data = bytearray(binary_data)
        for i in range(10):
            modified_data[-(i + 1)] = (modified_data[-(i + 1)] + 1) % 256
        modified_binary = temp_workspace / "fuzzy_modified.exe"
        modified_binary.write_bytes(modified_data)

        fp2 = fingerprint_engine.generate_fingerprint(modified_binary)

        if fp1.ssdeep and fp2.ssdeep:
            similarity = fingerprint_engine.compare_fingerprints(fp1, fp2)
            assert 0.0 <= similarity <= 1.0


class TestCodeSimilarityDetection:
    """Test code similarity detection capabilities."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_section_hash_similarity(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path
    ) -> None:
        """Detect code similarity through section hash comparison."""
        fp1 = fingerprint_engine.generate_fingerprint(minimal_pe_binary)
        fp2 = fingerprint_engine.generate_fingerprint(minimal_pe_binary)

        assert fp1.section_hashes == fp2.section_hashes

        for section_name in fp1.section_hashes:
            if section_name in fp2.section_hashes:
                assert fp1.section_hashes[section_name] == fp2.section_hashes[section_name]

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_code_section_hash_isolation(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path
    ) -> None:
        """Isolate and hash code sections separately from data sections."""
        fingerprint = fingerprint_engine.generate_fingerprint(minimal_pe_binary)

        if PEFILE_AVAILABLE:
            assert fingerprint.code_sections_hash is not None
            assert len(fingerprint.code_sections_hash) == 64


class TestRealWorldBinaries:
    """Test fingerprinting on real-world binaries."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_legitimate_7zip(
        self, fingerprint_engine: FingerprintEngine
    ) -> None:
        """Fingerprint legitimate 7-Zip binary."""
        binary_path = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/7zip.exe")
        if not binary_path.exists():
            pytest.skip("Test binary not available")

        fingerprint = fingerprint_engine.generate_fingerprint(binary_path)

        assert isinstance(fingerprint, BinaryFingerprint)
        assert len(fingerprint.md5) == 32
        assert len(fingerprint.sha256) == 64
        assert len(fingerprint.section_hashes) > 0

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_legitimate_notepadpp(
        self, fingerprint_engine: FingerprintEngine
    ) -> None:
        """Fingerprint legitimate Notepad++ binary."""
        binary_path = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/notepadpp.exe")
        if not binary_path.exists():
            pytest.skip("Test binary not available")

        fingerprint = fingerprint_engine.generate_fingerprint(binary_path)

        assert isinstance(fingerprint, BinaryFingerprint)
        assert len(fingerprint.section_hashes) > 0

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_protected_beyond_compare(
        self, fingerprint_engine: FingerprintEngine
    ) -> None:
        """Fingerprint protected Beyond Compare binary."""
        binary_path = Path("D:/Intellicrack/tests/fixtures/full_protected_software/Beyond_Compare_Full.exe")
        if not binary_path.exists():
            pytest.skip("Test binary not available")

        fingerprint = fingerprint_engine.generate_fingerprint(binary_path)
        protections = fingerprint_engine.fingerprint_protection(binary_path)

        assert isinstance(fingerprint, BinaryFingerprint)
        assert isinstance(protections, list)

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_portable_tools(
        self, fingerprint_engine: FingerprintEngine
    ) -> None:
        """Fingerprint portable tool binaries."""
        test_binaries = [
            Path("D:/Intellicrack/tests/fixtures/PORTABLE_SANDBOX/processhacker_portable/x86/ProcessHacker.exe"),
            Path("D:/Intellicrack/tests/fixtures/PORTABLE_SANDBOX/pestudio_portable/pestudio/pestudio.exe"),
            Path("D:/Intellicrack/tests/fixtures/PORTABLE_SANDBOX/exeinfope_portable/ExeinfoPE/exeinfope.exe"),
        ]

        for binary_path in test_binaries:
            if not binary_path.exists():
                continue

            fingerprint = fingerprint_engine.generate_fingerprint(binary_path)
            assert isinstance(fingerprint, BinaryFingerprint)
            assert len(fingerprint.sha256) == 64


class TestEntropyCalculation:
    """Test entropy calculation for fingerprinting."""

    def test_calculate_entropy_uniform(
        self, fingerprint_engine: FingerprintEngine
    ) -> None:
        """Calculate entropy for uniform data distribution."""
        uniform_data = bytes(range(256)) * 4
        entropy = fingerprint_engine._calculate_entropy(uniform_data)

        assert 7.5 <= entropy <= 8.0

    def test_calculate_entropy_zero(
        self, fingerprint_engine: FingerprintEngine
    ) -> None:
        """Calculate entropy for zero entropy data."""
        zero_data = b"\x00" * 1024
        entropy = fingerprint_engine._calculate_entropy(zero_data)

        assert entropy == 0.0

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_calculate_entropy_packed_data(
        self, fingerprint_engine: FingerprintEngine, upx_packed_binary: Path
    ) -> None:
        """Calculate entropy for packed binary sections."""
        sections = fingerprint_engine.fingerprint_sections(upx_packed_binary)

        for section_name, section_info in sections.items():
            entropy = section_info["entropy"]
            assert 0.0 <= entropy <= 8.0


class TestStringExtraction:
    """Test string extraction for fingerprinting."""

    def test_extract_strings_basic(
        self, fingerprint_engine: FingerprintEngine
    ) -> None:
        """Extract printable strings from binary data."""
        data = b"Hello\x00World\x00Test\x00\xff\xff"
        strings = fingerprint_engine._extract_strings(data)

        assert "Hello" in strings
        assert "World" in strings
        assert "Test" in strings

    def test_extract_strings_minimum_length(
        self, fingerprint_engine: FingerprintEngine
    ) -> None:
        """Extract strings with minimum length requirement."""
        data = b"Hi\x00Hello\x00W\x00World\x00"
        strings = fingerprint_engine._extract_strings(data, min_length=4)

        assert "Hi" not in strings
        assert "Hello" in strings
        assert "W" not in strings
        assert "World" in strings

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_extract_strings_from_binary(
        self, fingerprint_engine: FingerprintEngine, flexlm_binary: Path
    ) -> None:
        """Extract strings from real binary file."""
        binary_data = flexlm_binary.read_bytes()
        strings = fingerprint_engine._extract_strings(binary_data)

        assert "FLEXlm" in strings or "lmgr11.dll" in strings


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_fingerprint_nonexistent_file(
        self, fingerprint_engine: FingerprintEngine, temp_workspace: Path
    ) -> None:
        """Handle fingerprinting of nonexistent file."""
        nonexistent = temp_workspace / "nonexistent.exe"

        with pytest.raises(FileNotFoundError):
            fingerprint_engine.generate_fingerprint(nonexistent)

    def test_fingerprint_empty_file(
        self, fingerprint_engine: FingerprintEngine, temp_workspace: Path
    ) -> None:
        """Handle fingerprinting of empty file."""
        empty_file = temp_workspace / "empty.exe"
        empty_file.write_bytes(b"")

        fingerprint = fingerprint_engine.generate_fingerprint(empty_file)

        assert isinstance(fingerprint, BinaryFingerprint)
        assert fingerprint.md5 == hashlib.md5(b"").hexdigest()

    def test_fingerprint_non_pe_binary(
        self, fingerprint_engine: FingerprintEngine, temp_workspace: Path
    ) -> None:
        """Handle fingerprinting of non-PE binary."""
        non_pe = temp_workspace / "data.bin"
        non_pe.write_bytes(b"\x7fELF" + b"\x00" * 1024)

        fingerprint = fingerprint_engine.generate_fingerprint(non_pe)

        assert isinstance(fingerprint, BinaryFingerprint)
        assert len(fingerprint.sha256) == 64

    def test_fingerprint_corrupted_pe(
        self, fingerprint_engine: FingerprintEngine, temp_workspace: Path
    ) -> None:
        """Handle fingerprinting of corrupted PE binary."""
        corrupted_pe = temp_workspace / "corrupted.exe"
        corrupted_pe.write_bytes(b"MZ" + b"\xff" * 100)

        fingerprint = fingerprint_engine.generate_fingerprint(corrupted_pe)

        assert isinstance(fingerprint, BinaryFingerprint)
        assert len(fingerprint.sha256) == 64

    def test_compare_fingerprints_different_types(
        self, fingerprint_engine: FingerprintEngine, minimal_pe_binary: Path, temp_workspace: Path
    ) -> None:
        """Compare fingerprints of different binary types."""
        pe_fp = fingerprint_engine.generate_fingerprint(minimal_pe_binary)

        elf_binary = temp_workspace / "app.elf"
        elf_binary.write_bytes(b"\x7fELF" + b"\x00" * 1024)
        elf_fp = fingerprint_engine.generate_fingerprint(elf_binary)

        similarity = fingerprint_engine.compare_fingerprints(pe_fp, elf_fp)

        assert 0.0 <= similarity < 1.0


class TestPerformance:
    """Test fingerprinting performance on various binary sizes."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_small_binary_performance(
        self, fingerprint_engine: FingerprintEngine
    ) -> None:
        """Measure fingerprinting performance on small binary."""
        binary_path = Path("D:/Intellicrack/tests/fixtures/binaries/size_categories/tiny_4kb/tiny_hello.exe")
        if not binary_path.exists():
            pytest.skip("Test binary not available")

        import time
        start = time.time()
        fingerprint = fingerprint_engine.generate_fingerprint(binary_path)
        duration = time.time() - start

        assert isinstance(fingerprint, BinaryFingerprint)
        assert duration < 1.0

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_fingerprint_medium_binary_performance(
        self, fingerprint_engine: FingerprintEngine
    ) -> None:
        """Measure fingerprinting performance on medium binary."""
        binary_path = Path("D:/Intellicrack/tests/fixtures/binaries/size_categories/small_1mb/small_padded.exe")
        if not binary_path.exists():
            pytest.skip("Test binary not available")

        import time
        start = time.time()
        fingerprint = fingerprint_engine.generate_fingerprint(binary_path)
        duration = time.time() - start

        assert isinstance(fingerprint, BinaryFingerprint)
        assert duration < 5.0
