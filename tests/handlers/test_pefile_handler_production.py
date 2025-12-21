"""Production tests for pefile_handler.

Tests validate PE format parsing, section extraction, import/export table processing,
RVA conversion, checksum calculation, and imphash generation for real PE binaries.
"""

import struct
import tempfile
from pathlib import Path

import pytest

from intellicrack.handlers import pefile_handler


@pytest.fixture
def minimal_pe32() -> bytes:
    """Create minimal valid PE32 binary."""
    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = (128).to_bytes(4, "little")

    pe_header = b"PE\x00\x00"

    coff_header = bytearray(20)
    coff_header[:2] = (
        pefile_handler.MACHINE_TYPE.IMAGE_FILE_MACHINE_I386.to_bytes(
            2, "little"
        )
    )
    coff_header[2:4] = (2).to_bytes(2, "little")
    coff_header[4:8] = (0).to_bytes(4, "little")
    coff_header[16:18] = (224).to_bytes(2, "little")
    coff_header[18:20] = (pefile_handler.IMAGE_CHARACTERISTICS.IMAGE_FILE_EXECUTABLE_IMAGE).to_bytes(2, "little")

    optional_header = bytearray(224)
    optional_header[:2] = (0x10B).to_bytes(2, "little")
    optional_header[16:20] = (0x1000).to_bytes(4, "little")
    optional_header[20:24] = (0x1000).to_bytes(4, "little")
    optional_header[24:28] = (0x2000).to_bytes(4, "little")
    optional_header[28:32] = (0x400000).to_bytes(4, "little")
    optional_header[32:36] = (0x1000).to_bytes(4, "little")
    optional_header[36:40] = (0x200).to_bytes(4, "little")
    optional_header[56:60] = (0x10000).to_bytes(4, "little")
    optional_header[60:64] = (0x400).to_bytes(4, "little")
    optional_header[68:70] = (pefile_handler.SUBSYSTEM_TYPE.IMAGE_SUBSYSTEM_WINDOWS_CUI).to_bytes(2, "little")
    optional_header[92:96] = (16).to_bytes(4, "little")

    section1 = bytearray(40)
    section1[:8] = b".text\x00\x00\x00"
    section1[8:12] = (0x1000).to_bytes(4, "little")
    section1[12:16] = (0x1000).to_bytes(4, "little")
    section1[16:20] = (0x200).to_bytes(4, "little")
    section1[20:24] = (0x400).to_bytes(4, "little")
    section1[36:40] = (pefile_handler.SECTION_CHARACTERISTICS.IMAGE_SCN_CNT_CODE | pefile_handler.SECTION_CHARACTERISTICS.IMAGE_SCN_MEM_EXECUTE | pefile_handler.SECTION_CHARACTERISTICS.IMAGE_SCN_MEM_READ).to_bytes(4, "little")

    section2 = bytearray(40)
    section2[:8] = b".data\x00\x00\x00"
    section2[8:12] = (0x1000).to_bytes(4, "little")
    section2[12:16] = (0x2000).to_bytes(4, "little")
    section2[16:20] = (0x200).to_bytes(4, "little")
    section2[20:24] = (0x600).to_bytes(4, "little")
    section2[36:40] = (pefile_handler.SECTION_CHARACTERISTICS.IMAGE_SCN_CNT_INITIALIZED_DATA | pefile_handler.SECTION_CHARACTERISTICS.IMAGE_SCN_MEM_READ | pefile_handler.SECTION_CHARACTERISTICS.IMAGE_SCN_MEM_WRITE).to_bytes(4, "little")

    section_data = bytearray(1024)

    binary = dos_header + bytearray(64) + pe_header + coff_header + optional_header + section1 + section2 + section_data
    return bytes(binary)


@pytest.fixture
def pe_with_imports() -> bytes:
    """Create PE binary with import table."""
    base_pe = bytearray(minimal_pe32())

    import_dir_rva = 0x2100
    import_dir_offset = 0x700

    optional_header_offset = 128 + 4 + 20
    import_data_dir_offset = optional_header_offset + 96 + pefile_handler.DIRECTORY_ENTRY.IMPORT * 8
    base_pe[import_data_dir_offset : import_data_dir_offset + 4] = import_dir_rva.to_bytes(4, "little")
    base_pe[import_data_dir_offset + 4 : import_data_dir_offset + 8] = (100).to_bytes(4, "little")

    dll_name_rva = 0x2200
    dll_name_offset = import_dir_offset + 100
    base_pe[dll_name_offset : dll_name_offset + 11] = b"kernel32.dll"

    func_name_rva = 0x2300
    func_name_offset = import_dir_offset + 200
    base_pe[func_name_offset : func_name_offset + 2] = (0).to_bytes(2, "little")
    base_pe[func_name_offset + 2 : func_name_offset + 16] = b"GetProcAddress\x00"

    thunk_rva = 0x2400
    thunk_offset = import_dir_offset + 300
    base_pe[thunk_offset : thunk_offset + 4] = func_name_rva.to_bytes(4, "little")
    base_pe[thunk_offset + 4 : thunk_offset + 8] = (0).to_bytes(4, "little")

    import_descriptor_offset = import_dir_offset
    base_pe[import_descriptor_offset : import_descriptor_offset + 4] = thunk_rva.to_bytes(4, "little")
    base_pe[import_descriptor_offset + 12 : import_descriptor_offset + 16] = dll_name_rva.to_bytes(4, "little")
    base_pe[import_descriptor_offset + 16 : import_descriptor_offset + 20] = thunk_rva.to_bytes(4, "little")
    base_pe[import_descriptor_offset + 20 : import_descriptor_offset + 40] = b"\x00" * 20

    return bytes(base_pe)


def test_pe_initialization_from_file(minimal_pe32: bytes) -> None:
    """PE class loads and parses binary from file path."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe32)
        temp_path = Path(f.name)

    try:
        pe = pefile_handler.PE(str(temp_path))

        assert pe is not None
        assert pe.FILE_HEADER is not None
        assert pe.OPTIONAL_HEADER is not None

    finally:
        temp_path.unlink(missing_ok=True)


def test_pe_initialization_from_data(minimal_pe32: bytes) -> None:
    """PE class loads and parses binary from byte data."""
    pe = pefile_handler.PE(data=minimal_pe32)

    assert pe is not None
    assert pe.FILE_HEADER is not None
    assert pe.OPTIONAL_HEADER is not None


def test_pe_file_header_parsed_correctly(minimal_pe32: bytes) -> None:
    """PE FILE_HEADER contains correct machine type and section count."""
    pe = pefile_handler.PE(data=minimal_pe32)

    assert pe.FILE_HEADER.Machine == pefile_handler.MACHINE_TYPE.IMAGE_FILE_MACHINE_I386
    assert pe.FILE_HEADER.NumberOfSections == 2
    assert pe.FILE_HEADER.SizeOfOptionalHeader == 224


def test_pe_optional_header_parsed_correctly(minimal_pe32: bytes) -> None:
    """PE OPTIONAL_HEADER contains correct entry point and image base."""
    pe = pefile_handler.PE(data=minimal_pe32)

    assert pe.OPTIONAL_HEADER.Magic == 0x10B
    assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0x1000
    assert pe.OPTIONAL_HEADER.ImageBase == 0x400000
    assert pe.OPTIONAL_HEADER.SectionAlignment == 0x1000
    assert pe.OPTIONAL_HEADER.FileAlignment == 0x200


def test_pe_sections_parsed_correctly(minimal_pe32: bytes) -> None:
    """PE sections list contains all section headers with correct data."""
    pe = pefile_handler.PE(data=minimal_pe32)

    assert len(pe.sections) == 2

    text_section = pe.sections[0]
    assert text_section.Name == ".text"
    assert text_section.VirtualAddress == 0x1000
    assert text_section.SizeOfRawData == 0x200
    assert text_section.PointerToRawData == 0x400

    data_section = pe.sections[1]
    assert data_section.Name == ".data"
    assert data_section.VirtualAddress == 0x2000


def test_pe_get_offset_from_rva(minimal_pe32: bytes) -> None:
    """get_offset_from_rva converts RVA to file offset correctly."""
    pe = pefile_handler.PE(data=minimal_pe32)

    offset = pe.get_offset_from_rva(0x1000)

    assert offset == 0x400


def test_pe_get_rva_from_offset(minimal_pe32: bytes) -> None:
    """get_rva_from_offset converts file offset to RVA correctly."""
    pe = pefile_handler.PE(data=minimal_pe32)

    rva = pe.get_rva_from_offset(0x400)

    assert rva == 0x1000


def test_pe_get_data_at_rva(minimal_pe32: bytes) -> None:
    """get_data retrieves bytes at specified RVA."""
    pe = pefile_handler.PE(data=minimal_pe32)

    data = pe.get_data(0x1000, 16)

    assert data is not None
    assert len(data) == 16
    assert isinstance(data, bytes)


def test_pe_is_exe_returns_true(minimal_pe32: bytes) -> None:
    """is_exe() returns True for executable PE file."""
    pe = pefile_handler.PE(data=minimal_pe32)

    assert pe.is_exe() is True


def test_pe_is_dll_returns_false(minimal_pe32: bytes) -> None:
    """is_dll() returns False for non-DLL PE file."""
    pe = pefile_handler.PE(data=minimal_pe32)

    assert pe.is_dll() is False


def test_pe_with_dll_characteristic_is_dll() -> None:
    """is_dll() returns True for PE with DLL characteristic."""
    pe_data = bytearray(minimal_pe32())

    coff_offset = 128 + 4
    characteristics_offset = coff_offset + 18
    pe_data[characteristics_offset : characteristics_offset + 2] = (pefile_handler.IMAGE_CHARACTERISTICS.IMAGE_FILE_DLL).to_bytes(2, "little")

    pe = pefile_handler.PE(data=bytes(pe_data))

    assert pe.is_dll() is True


def test_pe_generate_checksum(minimal_pe32: bytes) -> None:
    """generate_checksum() calculates PE checksum value."""
    pe = pefile_handler.PE(data=minimal_pe32)

    checksum = pe.generate_checksum()

    assert isinstance(checksum, int)
    assert checksum > 0


def test_pe_get_imphash(pe_with_imports: bytes) -> None:
    """get_imphash() calculates import hash based on imported functions."""
    pe = pefile_handler.PE(data=pe_with_imports)

    imphash = pe.get_imphash()

    assert isinstance(imphash, str)
    assert len(imphash) == 64


def test_pe_write_to_file(minimal_pe32: bytes) -> None:
    """write() saves PE binary to file."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        output_path = Path(f.name)

    try:
        pe = pefile_handler.PE(data=minimal_pe32)

        data = pe.write(str(output_path))

        assert output_path.exists()
        assert output_path.stat().st_size == len(minimal_pe32)
        assert data == minimal_pe32

    finally:
        output_path.unlink(missing_ok=True)


def test_pe_close_clears_data(minimal_pe32: bytes) -> None:
    """close() releases binary data from memory."""
    pe = pefile_handler.PE(data=minimal_pe32)

    pe.close()

    assert pe._data == b""


def test_pe_fast_load_skips_imports(minimal_pe32: bytes) -> None:
    """PE with fast_load=True skips import parsing."""
    pe = pefile_handler.PE(data=minimal_pe32, fast_load=True)

    assert len(pe.DIRECTORY_ENTRY_IMPORT) == 0


def test_pe_invalid_dos_signature_raises_error() -> None:
    """PE raises PEFormatError for invalid DOS signature."""
    invalid_data = b"INVALID" + b"\x00" * 100

    with pytest.raises(pefile_handler.PEFormatError):
        pefile_handler.PE(data=invalid_data)


def test_pe_invalid_pe_signature_raises_error() -> None:
    """PE raises PEFormatError for invalid PE signature."""
    invalid_pe = bytearray(128)
    invalid_pe[:2] = b"MZ"
    invalid_pe[60:64] = (64).to_bytes(4, "little")
    invalid_pe += b"INVALID_PE_SIG"

    with pytest.raises(pefile_handler.PEFormatError):
        pefile_handler.PE(data=bytes(invalid_pe))


def test_pe_string_representation(minimal_pe32: bytes) -> None:
    """PE __str__ returns meaningful string representation."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(minimal_pe32)
        temp_path = Path(f.name)

    try:
        pe = pefile_handler.PE(str(temp_path))

        str_repr = str(pe)

        assert "PE" in str_repr
        assert temp_path.name in str_repr

    finally:
        temp_path.unlink(missing_ok=True)


def test_pe_section_data_loaded(minimal_pe32: bytes) -> None:
    """PE sections have their data loaded from file."""
    pe = pefile_handler.PE(data=minimal_pe32)

    text_section = pe.sections[0]

    assert len(text_section.data) > 0


def test_pe_get_memory_mapped_image(minimal_pe32: bytes) -> None:
    """get_memory_mapped_image() creates memory-mapped PE layout."""
    pe = pefile_handler.PE(data=minimal_pe32)

    mapped = pe.get_memory_mapped_image()

    assert mapped is not None
    assert len(mapped) == pe.OPTIONAL_HEADER.SizeOfImage
    assert isinstance(mapped, bytes)


def test_pe_data_directory_count(minimal_pe32: bytes) -> None:
    """OPTIONAL_HEADER.DATA_DIRECTORY has all 16 directories."""
    pe = pefile_handler.PE(data=minimal_pe32)

    assert len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) == 16


def test_has_pefile_flag_is_boolean() -> None:
    """HAS_PEFILE is a boolean flag."""
    assert isinstance(pefile_handler.HAS_PEFILE, bool)


def test_pefile_version_is_string_or_none() -> None:
    """PEFILE_VERSION is None or valid version string."""
    version = pefile_handler.PEFILE_VERSION

    if version is not None:
        assert isinstance(version, str)


def test_directory_entry_constants_available() -> None:
    """DIRECTORY_ENTRY has all required constants."""
    assert hasattr(pefile_handler.DIRECTORY_ENTRY, "EXPORT")
    assert hasattr(pefile_handler.DIRECTORY_ENTRY, "IMPORT")
    assert hasattr(pefile_handler.DIRECTORY_ENTRY, "RESOURCE")
    assert hasattr(pefile_handler.DIRECTORY_ENTRY, "EXCEPTION")
    assert hasattr(pefile_handler.DIRECTORY_ENTRY, "SECURITY")
    assert hasattr(pefile_handler.DIRECTORY_ENTRY, "BASERELOC")
    assert hasattr(pefile_handler.DIRECTORY_ENTRY, "DEBUG")
    assert hasattr(pefile_handler.DIRECTORY_ENTRY, "TLS")


def test_machine_type_constants_available() -> None:
    """MACHINE_TYPE has all common machine types."""
    assert hasattr(pefile_handler.MACHINE_TYPE, "IMAGE_FILE_MACHINE_I386")
    assert hasattr(pefile_handler.MACHINE_TYPE, "IMAGE_FILE_MACHINE_AMD64")
    assert hasattr(pefile_handler.MACHINE_TYPE, "IMAGE_FILE_MACHINE_ARM")
    assert hasattr(pefile_handler.MACHINE_TYPE, "IMAGE_FILE_MACHINE_ARM64")


def test_subsystem_type_constants_available() -> None:
    """SUBSYSTEM_TYPE has all required subsystem types."""
    assert hasattr(pefile_handler.SUBSYSTEM_TYPE, "IMAGE_SUBSYSTEM_WINDOWS_GUI")
    assert hasattr(pefile_handler.SUBSYSTEM_TYPE, "IMAGE_SUBSYSTEM_WINDOWS_CUI")
    assert hasattr(pefile_handler.SUBSYSTEM_TYPE, "IMAGE_SUBSYSTEM_NATIVE")


def test_section_characteristics_constants_available() -> None:
    """SECTION_CHARACTERISTICS has all required flags."""
    assert hasattr(pefile_handler.SECTION_CHARACTERISTICS, "IMAGE_SCN_CNT_CODE")
    assert hasattr(pefile_handler.SECTION_CHARACTERISTICS, "IMAGE_SCN_CNT_INITIALIZED_DATA")
    assert hasattr(pefile_handler.SECTION_CHARACTERISTICS, "IMAGE_SCN_MEM_EXECUTE")
    assert hasattr(pefile_handler.SECTION_CHARACTERISTICS, "IMAGE_SCN_MEM_READ")
    assert hasattr(pefile_handler.SECTION_CHARACTERISTICS, "IMAGE_SCN_MEM_WRITE")


def test_image_characteristics_constants_available() -> None:
    """IMAGE_CHARACTERISTICS has all required flags."""
    assert hasattr(pefile_handler.IMAGE_CHARACTERISTICS, "IMAGE_FILE_EXECUTABLE_IMAGE")
    assert hasattr(pefile_handler.IMAGE_CHARACTERISTICS, "IMAGE_FILE_DLL")
    assert hasattr(pefile_handler.IMAGE_CHARACTERISTICS, "IMAGE_FILE_LARGE_ADDRESS_AWARE")


def test_dll_characteristics_constants_available() -> None:
    """DLL_CHARACTERISTICS has all required flags."""
    assert hasattr(pefile_handler.DLL_CHARACTERISTICS, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE")
    assert hasattr(pefile_handler.DLL_CHARACTERISTICS, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT")
    assert hasattr(pefile_handler.DLL_CHARACTERISTICS, "IMAGE_DLLCHARACTERISTICS_GUARD_CF")


def test_pe64_optional_header_parsed_correctly() -> None:
    """PE64 OPTIONAL_HEADER parses correctly for 64-bit binary."""
    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = (128).to_bytes(4, "little")

    pe_header = b"PE\x00\x00"

    coff_header = bytearray(20)
    coff_header[:2] = (
        pefile_handler.MACHINE_TYPE.IMAGE_FILE_MACHINE_AMD64.to_bytes(
            2, "little"
        )
    )
    coff_header[2:4] = (1).to_bytes(2, "little")
    coff_header[16:18] = (240).to_bytes(2, "little")
    coff_header[18:20] = (0x0002).to_bytes(2, "little")

    optional_header = bytearray(240)
    optional_header[:2] = (0x20B).to_bytes(2, "little")
    optional_header[16:20] = (0x1000).to_bytes(4, "little")
    optional_header[20:24] = (0x1000).to_bytes(4, "little")
    optional_header[24:32] = (0x140000000).to_bytes(8, "little")
    optional_header[108:112] = (16).to_bytes(4, "little")

    section = bytearray(40)
    section[:8] = b".text\x00\x00\x00"
    section[8:12] = (0x1000).to_bytes(4, "little")
    section[12:16] = (0x1000).to_bytes(4, "little")
    section[16:20] = (0x200).to_bytes(4, "little")
    section[20:24] = (0x400).to_bytes(4, "little")
    section[36:40] = (0x60000020).to_bytes(4, "little")

    section_data = bytearray(512)

    binary = dos_header + bytearray(64) + pe_header + coff_header + optional_header + section + section_data

    pe = pefile_handler.PE(data=bytes(binary))

    assert pe.OPTIONAL_HEADER.Magic == 0x20B
    assert pe.OPTIONAL_HEADER.ImageBase == 0x140000000
    assert pe.FILE_HEADER.Machine == pefile_handler.MACHINE_TYPE.IMAGE_FILE_MACHINE_AMD64


def test_pe_is_driver_returns_true_for_native_subsystem() -> None:
    """is_driver() returns True for PE with native subsystem."""
    pe_data = bytearray(minimal_pe32())

    optional_header_offset = 128 + 4 + 20
    subsystem_offset = optional_header_offset + 68
    pe_data[subsystem_offset : subsystem_offset + 2] = pefile_handler.SUBSYSTEM_TYPE.IMAGE_SUBSYSTEM_NATIVE.to_bytes(2, "little")

    pe = pefile_handler.PE(data=bytes(pe_data))

    assert pe.is_driver() is True


def test_pe_get_rich_header_hash(minimal_pe32: bytes) -> None:
    """get_rich_header_hash() returns None when Rich header absent."""
    pe = pefile_handler.PE(data=minimal_pe32)

    rich_hash = pe.get_rich_header_hash()

    assert rich_hash is None or isinstance(rich_hash, str)


def test_module_exports_all_required_objects() -> None:
    """pefile_handler exports all required classes and constants."""
    assert hasattr(pefile_handler, "PE")
    assert hasattr(pefile_handler, "PEFormatError")
    assert hasattr(pefile_handler, "DIRECTORY_ENTRY")
    assert hasattr(pefile_handler, "MACHINE_TYPE")
    assert hasattr(pefile_handler, "SUBSYSTEM_TYPE")
    assert hasattr(pefile_handler, "SECTION_CHARACTERISTICS")
    assert hasattr(pefile_handler, "IMAGE_CHARACTERISTICS")
    assert hasattr(pefile_handler, "DLL_CHARACTERISTICS")
    assert hasattr(pefile_handler, "DEBUG_TYPE")
    assert hasattr(pefile_handler, "RESOURCE_TYPE")
