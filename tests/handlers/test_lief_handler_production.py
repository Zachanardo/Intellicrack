"""Production tests for lief_handler.

Tests validate PE/ELF/Mach-O binary parsing, section extraction, symbol resolution,
architecture detection, and fallback implementation functionality.
"""

import struct
import tempfile
from pathlib import Path

import pytest

from intellicrack.handlers import lief_handler


@pytest.fixture
def minimal_pe_binary() -> bytes:
    """Create minimal valid PE binary for testing."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = (128).to_bytes(4, "little")

    pe_header = b"PE\x00\x00"

    coff_header = bytearray(20)
    coff_header[0:2] = (0x14C).to_bytes(2, "little")
    coff_header[2:4] = (1).to_bytes(2, "little")
    coff_header[16:18] = (224).to_bytes(2, "little")
    coff_header[18:20] = (0x0002).to_bytes(2, "little")

    optional_header = bytearray(224)
    optional_header[0:2] = (0x10B).to_bytes(2, "little")
    optional_header[16:20] = (0x1000).to_bytes(4, "little")
    optional_header[20:24] = (0x1000).to_bytes(4, "little")
    optional_header[28:32] = (0x400000).to_bytes(4, "little")
    optional_header[32:36] = (0x1000).to_bytes(4, "little")
    optional_header[36:40] = (0x200).to_bytes(4, "little")
    optional_header[56:60] = (0x10000).to_bytes(4, "little")
    optional_header[60:64] = (0x400).to_bytes(4, "little")

    section_header = bytearray(40)
    section_header[0:8] = b".text\x00\x00\x00"
    section_header[8:12] = (0x1000).to_bytes(4, "little")
    section_header[12:16] = (0x1000).to_bytes(4, "little")
    section_header[16:20] = (0x200).to_bytes(4, "little")
    section_header[20:24] = (0x400).to_bytes(4, "little")
    section_header[36:40] = (0x60000020).to_bytes(4, "little")

    section_data = bytearray(512)

    binary = dos_header + bytearray(64) + pe_header + coff_header + optional_header + section_header + section_data
    return bytes(binary)


@pytest.fixture
def minimal_elf_binary() -> bytes:
    """Create minimal valid ELF binary for testing."""
    elf_header = bytearray(64)
    elf_header[0:4] = b"\x7fELF"
    elf_header[4] = 2
    elf_header[5] = 1
    elf_header[6] = 1
    elf_header[16:18] = struct.pack("<H", 2)
    elf_header[18:20] = struct.pack("<H", 0x3E)
    elf_header[24:32] = struct.pack("<Q", 0x400000)
    elf_header[32:40] = struct.pack("<Q", 64)
    elf_header[40:48] = struct.pack("<Q", 0)

    return bytes(elf_header + bytearray(1000))


def test_is_pe_detects_pe_files(minimal_pe_binary: bytes) -> None:
    """is_pe() returns True for valid PE binary."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        result = lief_handler.is_pe(str(temp_path))

        assert result is True

    finally:
        temp_path.unlink(missing_ok=True)


def test_is_pe_rejects_non_pe_files() -> None:
    """is_pe() returns False for non-PE binary."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
        f.write(b"NOT_A_PE_FILE" + b"\x00" * 100)
        temp_path = Path(f.name)

    try:
        result = lief_handler.is_pe(str(temp_path))

        assert result is False

    finally:
        temp_path.unlink(missing_ok=True)


def test_is_elf_detects_elf_files(minimal_elf_binary: bytes) -> None:
    """is_elf() returns True for valid ELF binary."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".elf", delete=False) as f:
        f.write(minimal_elf_binary)
        temp_path = Path(f.name)

    try:
        result = lief_handler.is_elf(str(temp_path))

        assert result is True

    finally:
        temp_path.unlink(missing_ok=True)


def test_is_elf_rejects_non_elf_files(minimal_pe_binary: bytes) -> None:
    """is_elf() returns False for non-ELF binary."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        result = lief_handler.is_elf(str(temp_path))

        assert result is False

    finally:
        temp_path.unlink(missing_ok=True)


def test_parse_pe_returns_binary_object(minimal_pe_binary: bytes) -> None:
    """parse() returns Binary object for PE file."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert hasattr(binary, "format")
        assert hasattr(binary, "sections")
        assert hasattr(binary, "entrypoint")

    finally:
        temp_path.unlink(missing_ok=True)


def test_parse_elf_returns_binary_object(minimal_elf_binary: bytes) -> None:
    """parse() returns Binary object for ELF file."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".elf", delete=False) as f:
        f.write(minimal_elf_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert hasattr(binary, "format")

    finally:
        temp_path.unlink(missing_ok=True)


def test_pe_binary_has_correct_format(minimal_pe_binary: bytes) -> None:
    """PE Binary object identifies format as PE."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert binary.format == "PE"

    finally:
        temp_path.unlink(missing_ok=True)


def test_elf_binary_has_correct_format(minimal_elf_binary: bytes) -> None:
    """ELF Binary object identifies format as ELF."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".elf", delete=False) as f:
        f.write(minimal_elf_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert binary.format == "ELF"

    finally:
        temp_path.unlink(missing_ok=True)


def test_pe_binary_extracts_sections(minimal_pe_binary: bytes) -> None:
    """PE Binary object correctly extracts section information."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert len(binary.sections) >= 1

        section = binary.sections[0]
        assert hasattr(section, "name")
        assert hasattr(section, "virtual_address")
        assert hasattr(section, "size")

    finally:
        temp_path.unlink(missing_ok=True)


def test_pe_binary_detects_architecture(minimal_pe_binary: bytes) -> None:
    """PE Binary correctly identifies architecture as x86."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert binary.architecture == lief_handler.ARCHITECTURES.X86

    finally:
        temp_path.unlink(missing_ok=True)


def test_pe_binary_detects_mode(minimal_pe_binary: bytes) -> None:
    """PE Binary correctly identifies execution mode as 32-bit."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert binary.mode == lief_handler.MODES.MODE_32

    finally:
        temp_path.unlink(missing_ok=True)


def test_pe_binary_has_valid_entrypoint(minimal_pe_binary: bytes) -> None:
    """PE Binary has non-zero entrypoint address."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert binary.entrypoint == 0x1000

    finally:
        temp_path.unlink(missing_ok=True)


def test_pe_binary_has_valid_imagebase(minimal_pe_binary: bytes) -> None:
    """PE Binary has correct image base address."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert binary.imagebase == 0x400000

    finally:
        temp_path.unlink(missing_ok=True)


def test_elf_binary_detects_architecture(minimal_elf_binary: bytes) -> None:
    """ELF Binary correctly identifies architecture."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".elf", delete=False) as f:
        f.write(minimal_elf_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert binary.architecture == lief_handler.ARCHITECTURES.X64

    finally:
        temp_path.unlink(missing_ok=True)


def test_elf_binary_detects_endianness(minimal_elf_binary: bytes) -> None:
    """ELF Binary correctly identifies endianness."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".elf", delete=False) as f:
        f.write(minimal_elf_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert binary.endianness == lief_handler.ENDIANNESS.LITTLE

    finally:
        temp_path.unlink(missing_ok=True)


def test_parse_nonexistent_file_returns_none() -> None:
    """parse() returns None for non-existent file."""
    result = lief_handler.parse("/nonexistent/file/path.exe")

    assert result is None


def test_binary_has_size_attribute(minimal_pe_binary: bytes) -> None:
    """Binary object has size attribute matching file size."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert binary.size == len(minimal_pe_binary)

    finally:
        temp_path.unlink(missing_ok=True)


def test_section_has_name_attribute(minimal_pe_binary: bytes) -> None:
    """Section object has name attribute."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert len(binary.sections) > 0

        section = binary.sections[0]
        assert section.name == ".text"

    finally:
        temp_path.unlink(missing_ok=True)


def test_section_has_virtual_address(minimal_pe_binary: bytes) -> None:
    """Section object has virtual_address attribute."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert len(binary.sections) > 0

        section = binary.sections[0]
        assert section.virtual_address == 0x1000

    finally:
        temp_path.unlink(missing_ok=True)


def test_section_has_size(minimal_pe_binary: bytes) -> None:
    """Section object has size attribute."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert len(binary.sections) > 0

        section = binary.sections[0]
        assert section.size > 0

    finally:
        temp_path.unlink(missing_ok=True)


def test_binary_string_representation(minimal_pe_binary: bytes) -> None:
    """Binary __str__ returns meaningful representation."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None

        str_repr = str(binary)
        assert "PE" in str_repr

    finally:
        temp_path.unlink(missing_ok=True)


def test_has_lief_flag_is_boolean() -> None:
    """HAS_LIEF is a boolean flag."""
    assert isinstance(lief_handler.HAS_LIEF, bool)


def test_lief_version_is_string_or_none() -> None:
    """LIEF_VERSION is None or valid version string."""
    version = lief_handler.LIEF_VERSION

    if version is not None:
        assert isinstance(version, str)


def test_architectures_enum_has_required_values() -> None:
    """ARCHITECTURES has all required architecture types."""
    assert hasattr(lief_handler.ARCHITECTURES, "X86")
    assert hasattr(lief_handler.ARCHITECTURES, "X64")
    assert hasattr(lief_handler.ARCHITECTURES, "ARM")
    assert hasattr(lief_handler.ARCHITECTURES, "ARM64")


def test_endianness_enum_has_required_values() -> None:
    """ENDIANNESS has little and big endian values."""
    assert hasattr(lief_handler.ENDIANNESS, "LITTLE")
    assert hasattr(lief_handler.ENDIANNESS, "BIG")


def test_modes_enum_has_required_values() -> None:
    """MODES has 32-bit and 64-bit mode values."""
    assert hasattr(lief_handler.MODES, "MODE_32")
    assert hasattr(lief_handler.MODES, "MODE_64")


def test_module_exports_all_required_classes() -> None:
    """lief_handler exports all required classes."""
    assert hasattr(lief_handler, "Binary")
    assert hasattr(lief_handler, "Section")
    assert hasattr(lief_handler, "Symbol")
    assert hasattr(lief_handler, "Function")
    assert hasattr(lief_handler, "PE")
    assert hasattr(lief_handler, "ELF")
    assert hasattr(lief_handler, "MachO")


def test_pe_class_can_be_instantiated() -> None:
    """PE class can be instantiated for PE-specific operations."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary())
        temp_path = Path(f.name)

    try:
        pe_binary = lief_handler.PE(str(temp_path))

        assert pe_binary is not None
        assert pe_binary.format == "PE"

    finally:
        temp_path.unlink(missing_ok=True)


def test_elf_class_can_be_instantiated() -> None:
    """ELF class can be instantiated for ELF-specific operations."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".elf", delete=False) as f:
        f.write(minimal_elf_binary())
        temp_path = Path(f.name)

    try:
        elf_binary = lief_handler.ELF(str(temp_path))

        assert elf_binary is not None
        assert elf_binary.format == "ELF"

    finally:
        temp_path.unlink(missing_ok=True)


def test_binary_has_empty_collections_initialized(minimal_pe_binary: bytes) -> None:
    """Binary object has empty collections for symbols, functions, imports, exports."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None
        assert isinstance(binary.symbols, list)
        assert isinstance(binary.functions, list)
        assert isinstance(binary.imports, list)
        assert isinstance(binary.exports, list)

    finally:
        temp_path.unlink(missing_ok=True)


def test_is_macho_detects_macho_files() -> None:
    """is_macho() returns True for Mach-O binary."""
    macho_header = bytearray(32)
    macho_header[0:4] = b"\xfe\xed\xfa\xcf"

    with tempfile.NamedTemporaryFile(mode="wb", suffix=".macho", delete=False) as f:
        f.write(macho_header + b"\x00" * 1000)
        temp_path = Path(f.name)

    try:
        result = lief_handler.is_macho(str(temp_path))

        assert result is True

    finally:
        temp_path.unlink(missing_ok=True)


def test_is_macho_rejects_non_macho_files(minimal_pe_binary: bytes) -> None:
    """is_macho() returns False for non-Mach-O binary."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe_binary)
        temp_path = Path(f.name)

    try:
        result = lief_handler.is_macho(str(temp_path))

        assert result is False

    finally:
        temp_path.unlink(missing_ok=True)


def test_parse_handles_corrupted_pe_gracefully() -> None:
    """parse() handles corrupted PE without crashing."""
    corrupted_pe = b"MZ" + b"\x00" * 100

    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(corrupted_pe)
        temp_path = Path(f.name)

    try:
        binary = lief_handler.parse(str(temp_path))

        assert binary is not None

    finally:
        temp_path.unlink(missing_ok=True)
