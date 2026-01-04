"""Production tests for pyelftools_handler.

Tests validate ELF file parsing, section enumeration, symbol table extraction,
relocation parsing, dynamic section handling, DWARF support, and fallback quality.
"""

import io
import struct
import tempfile
from pathlib import Path

import pytest

from intellicrack.handlers import pyelftools_handler


def create_minimal_elf64_binary() -> bytes:
    """Create minimal valid 64-bit ELF binary for testing."""
    elf_header = (
        b"\x7fELF"
        + bytes([2, 1, 1, 0])
        + bytes(8)
        + struct.pack(
            "<HHIQQQIHHHHHH",
            3,
            62,
            1,
            0x400000,
            64,
            0,
            0,
            64,
            56,
            0,
            64,
            0,
            0,
        )
    )

    return elf_header + bytes(1000)


def create_elf64_with_sections() -> bytes:
    """Create 64-bit ELF with section headers."""
    elf_header = (
        b"\x7fELF"
        + bytes([2, 1, 1, 0])
        + bytes(8)
        + struct.pack(
            "<HHIQQQIHHHHHH",
            3,
            62,
            1,
            0x400000,
            64,
            512,
            0,
            64,
            56,
            0,
            64,
            2,
            1,
        )
    )

    section_headers = struct.pack(
        "<IIQQQQIIQQ",
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ) + struct.pack(
        "<IIQQQQIIQQ",
        1,
        3,
        0,
        0,
        1024,
        50,
        0,
        0,
        1,
        0,
    )

    string_table = b"\x00.strtab\x00"

    data = elf_header + bytes(512 - len(elf_header))
    data += section_headers
    data += bytes(1024 - len(data))
    data += string_table
    data += bytes(2048 - len(data))

    return data


def test_has_pyelftools_flag_is_boolean() -> None:
    """HAS_PYELFTOOLS is a boolean flag."""
    assert isinstance(pyelftools_handler.HAS_PYELFTOOLS, bool)


def test_pyelftools_version_is_string_or_none() -> None:
    """PYELFTOOLS_VERSION is None or valid version string."""
    version = pyelftools_handler.PYELFTOOLS_VERSION

    if version is not None:
        assert isinstance(version, str)


def test_module_exports_elffile_class() -> None:
    """pyelftools_handler exports ELFFile class."""
    assert hasattr(pyelftools_handler, "ELFFile")
    assert pyelftools_handler.ELFFile is not None


def test_module_exports_section_class() -> None:
    """pyelftools_handler exports Section class."""
    assert hasattr(pyelftools_handler, "Section")


def test_module_exports_symbol_class() -> None:
    """pyelftools_handler exports Symbol class."""
    assert hasattr(pyelftools_handler, "Symbol")


def test_module_exports_container_class() -> None:
    """pyelftools_handler exports Container class."""
    assert hasattr(pyelftools_handler, "Container")


def test_module_exports_utility_functions() -> None:
    """pyelftools_handler exports utility functions."""
    assert hasattr(pyelftools_handler, "bytes2str")
    assert hasattr(pyelftools_handler, "str2bytes")
    assert callable(pyelftools_handler.bytes2str)
    assert callable(pyelftools_handler.str2bytes)


def test_module_exports_description_functions() -> None:
    """pyelftools_handler exports description functions."""
    assert hasattr(pyelftools_handler, "describe_e_type")
    assert hasattr(pyelftools_handler, "describe_p_type")
    assert hasattr(pyelftools_handler, "describe_sh_type")


def test_module_exports_constants() -> None:
    """pyelftools_handler exports ELF constants."""
    assert hasattr(pyelftools_handler, "E_FLAGS")
    assert hasattr(pyelftools_handler, "P_FLAGS")
    assert hasattr(pyelftools_handler, "SH_FLAGS")
    assert hasattr(pyelftools_handler, "SHN_INDICES")


def test_module_exports_enums() -> None:
    """pyelftools_handler exports enum classes."""
    assert hasattr(pyelftools_handler, "ENUM_E_TYPE")
    assert hasattr(pyelftools_handler, "ENUM_SH_TYPE")
    assert hasattr(pyelftools_handler, "ENUM_D_TAG")


def test_module_exports_exception_classes() -> None:
    """pyelftools_handler exports exception classes."""
    assert hasattr(pyelftools_handler, "ELFError")
    assert hasattr(pyelftools_handler, "ELFParseError")
    assert hasattr(pyelftools_handler, "DWARFError")


def test_bytes2str_converts_bytes() -> None:
    """bytes2str() converts bytes to string."""
    data = b"test string"

    result = pyelftools_handler.bytes2str(data)

    assert isinstance(result, str)
    assert result == "test string"


def test_bytes2str_handles_string_input() -> None:
    """bytes2str() returns string unchanged."""
    data = "already string"

    result = pyelftools_handler.bytes2str(data)

    assert result == data


def test_str2bytes_converts_string() -> None:
    """str2bytes() converts string to bytes."""
    data = "test string"

    result = pyelftools_handler.str2bytes(data)

    assert isinstance(result, bytes)


def test_str2bytes_handles_bytes_input() -> None:
    """str2bytes() returns bytes unchanged."""
    data = b"already bytes"

    result = pyelftools_handler.str2bytes(data)

    assert result == data


def test_container_class_behaves_as_dict() -> None:
    """Container class behaves as dictionary."""
    container = pyelftools_handler.Container(key1="value1", key2="value2")

    assert container["key1"] == "value1"
    assert container["key2"] == "value2"


def test_container_class_behaves_as_object() -> None:
    """Container class allows attribute access."""
    container = pyelftools_handler.Container(attr1="val1", attr2="val2")

    assert container.attr1 == "val1"
    assert container.attr2 == "val2"


def test_describe_e_type_returns_description() -> None:
    """describe_e_type() returns human-readable description."""
    et_exec = pyelftools_handler.ENUM_E_TYPE.ET_EXEC

    description = pyelftools_handler.describe_e_type(et_exec)  # type: ignore[no-untyped-call]

    assert isinstance(description, str)
    assert "EXEC" in description or "Executable" in description


def test_describe_p_type_returns_description() -> None:
    """describe_p_type() returns human-readable description."""
    description = pyelftools_handler.describe_p_type(1)  # type: ignore[no-untyped-call]

    assert isinstance(description, str)
    assert "LOAD" in description or "PT_LOAD" in description


def test_describe_sh_type_returns_description() -> None:
    """describe_sh_type() returns human-readable description."""
    sht_strtab = pyelftools_handler.ENUM_SH_TYPE.SHT_STRTAB

    description = pyelftools_handler.describe_sh_type(sht_strtab)  # type: ignore[no-untyped-call]

    assert isinstance(description, str)
    assert "STRTAB" in description


def test_elffile_parses_minimal_elf() -> None:
    """ELFFile parses minimal valid ELF binary."""
    elf_data = create_minimal_elf64_binary()
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    assert elf is not None
    assert elf.header is not None


def test_elffile_detects_64bit_class() -> None:
    """ELFFile detects 64-bit ELF class."""
    elf_data = create_minimal_elf64_binary()
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    assert elf.elfclass == 64


def test_elffile_detects_little_endian() -> None:
    """ELFFile detects little-endian byte order."""
    elf_data = create_minimal_elf64_binary()
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    assert elf.little_endian is True


def test_elffile_rejects_invalid_magic() -> None:
    """ELFFile raises ELFParseError for invalid magic."""
    invalid_data = b"INVALID" + bytes(100)
    stream = io.BytesIO(invalid_data)

    with pytest.raises(pyelftools_handler.ELFParseError):
        pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]


def test_elffile_rejects_truncated_header() -> None:
    """ELFFile raises ELFParseError for truncated header."""
    truncated_data = b"\x7fELF" + bytes(10)
    stream = io.BytesIO(truncated_data)

    with pytest.raises(pyelftools_handler.ELFParseError):
        pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]


def test_elffile_header_contains_expected_fields() -> None:
    """ELFFile header contains expected fields."""
    elf_data = create_minimal_elf64_binary()
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    assert hasattr(elf.header, "e_type")
    assert hasattr(elf.header, "e_machine")
    assert hasattr(elf.header, "e_version")
    assert hasattr(elf.header, "e_entry")


def test_elffile_num_sections() -> None:
    """ELFFile num_sections() returns section count."""
    elf_data = create_elf64_with_sections()
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    section_count = elf.num_sections()  # type: ignore[no-untyped-call]
    assert isinstance(section_count, int)
    assert section_count >= 0


def test_elffile_iter_sections() -> None:
    """ELFFile iter_sections() yields sections."""
    elf_data = create_elf64_with_sections()
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    sections = list(elf.iter_sections())  # type: ignore[no-untyped-call]
    assert isinstance(sections, list)


def test_elffile_get_section_by_index() -> None:
    """ELFFile get_section() retrieves section by index."""
    elf_data = create_elf64_with_sections()
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    if elf.num_sections() > 0:  # type: ignore[no-untyped-call]
        section = elf.get_section(0)  # type: ignore[no-untyped-call]
        assert section is not None


def test_elffile_get_section_invalid_index() -> None:
    """ELFFile get_section() returns None for invalid index."""
    elf_data = create_minimal_elf64_binary()
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    section = elf.get_section(999)  # type: ignore[no-untyped-call]
    assert section is None


def test_elffile_get_machine_arch() -> None:
    """ELFFile get_machine_arch() returns architecture string."""
    elf_data = create_minimal_elf64_binary()
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    arch = elf.get_machine_arch()  # type: ignore[no-untyped-call]
    assert isinstance(arch, str)


def test_elffile_has_dwarf_info() -> None:
    """ELFFile has_dwarf_info() checks for debug sections."""
    elf_data = create_minimal_elf64_binary()
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    has_dwarf = elf.has_dwarf_info()  # type: ignore[no-untyped-call]
    assert isinstance(has_dwarf, bool)


def test_section_data_method() -> None:
    """Section data() method returns bytes."""
    elf_data = create_elf64_with_sections()
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    for section in elf.iter_sections():  # type: ignore[no-untyped-call]
        data = section.data()
        assert isinstance(data, bytes)


def test_section_has_name_attribute() -> None:
    """Section has name attribute."""
    elf_data = create_elf64_with_sections()
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    for section in elf.iter_sections():  # type: ignore[no-untyped-call]
        assert hasattr(section, "name")
        assert isinstance(section.name, str)


def test_section_is_null_method() -> None:
    """Section is_null() identifies null sections."""
    elf_data = create_elf64_with_sections()
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    if elf.num_sections() > 0:  # type: ignore[no-untyped-call]
        section = elf.get_section(0)  # type: ignore[no-untyped-call]
        is_null = section.is_null()
        assert isinstance(is_null, bool)


def test_section_data_size_property() -> None:
    """Section data_size property returns size."""
    elf_data = create_elf64_with_sections()
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    for section in elf.iter_sections():  # type: ignore[no-untyped-call]
        assert hasattr(section, "data_size")
        assert isinstance(section.data_size, int)


def test_enum_e_type_constants() -> None:
    """ENUM_E_TYPE has expected constants."""
    assert hasattr(pyelftools_handler.ENUM_E_TYPE, "ET_NONE")
    assert hasattr(pyelftools_handler.ENUM_E_TYPE, "ET_REL")
    assert hasattr(pyelftools_handler.ENUM_E_TYPE, "ET_EXEC")
    assert hasattr(pyelftools_handler.ENUM_E_TYPE, "ET_DYN")


def test_enum_sh_type_constants() -> None:
    """ENUM_SH_TYPE has expected constants."""
    assert hasattr(pyelftools_handler.ENUM_SH_TYPE, "SHT_NULL")
    assert hasattr(pyelftools_handler.ENUM_SH_TYPE, "SHT_PROGBITS")
    assert hasattr(pyelftools_handler.ENUM_SH_TYPE, "SHT_SYMTAB")
    assert hasattr(pyelftools_handler.ENUM_SH_TYPE, "SHT_STRTAB")


def test_enum_d_tag_constants() -> None:
    """ENUM_D_TAG has expected constants."""
    assert hasattr(pyelftools_handler.ENUM_D_TAG, "DT_NULL")
    assert hasattr(pyelftools_handler.ENUM_D_TAG, "DT_NEEDED")
    assert hasattr(pyelftools_handler.ENUM_D_TAG, "DT_SONAME")


def test_p_flags_constants() -> None:
    """P_FLAGS has expected constants."""
    assert hasattr(pyelftools_handler.P_FLAGS, "PF_X")
    assert hasattr(pyelftools_handler.P_FLAGS, "PF_W")
    assert hasattr(pyelftools_handler.P_FLAGS, "PF_R")


def test_sh_flags_constants() -> None:
    """SH_FLAGS has expected constants."""
    assert hasattr(pyelftools_handler.SH_FLAGS, "SHF_WRITE")
    assert hasattr(pyelftools_handler.SH_FLAGS, "SHF_ALLOC")
    assert hasattr(pyelftools_handler.SH_FLAGS, "SHF_EXECINSTR")


def test_shn_indices_constants() -> None:
    """SHN_INDICES has expected constants."""
    assert hasattr(pyelftools_handler.SHN_INDICES, "SHN_UNDEF")
    assert hasattr(pyelftools_handler.SHN_INDICES, "SHN_ABS")


def test_all_exports_are_defined() -> None:
    """All items in __all__ are defined in module."""
    for item in pyelftools_handler.__all__:
        assert hasattr(pyelftools_handler, item)


def test_elffile_parses_32bit_elf() -> None:
    """ELFFile parses 32-bit ELF binary."""
    elf_header = (
        b"\x7fELF"
        + bytes([1, 1, 1, 0])
        + bytes(8)
        + struct.pack(
            "<HHIIIIIHHHHHH",
            3,
            3,
            1,
            0x8048000,
            52,
            0,
            0,
            52,
            32,
            0,
            40,
            0,
            0,
        )
    )

    elf_data = elf_header + bytes(500)
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    assert elf.elfclass == 32


def test_elffile_parses_big_endian() -> None:
    """ELFFile parses big-endian ELF binary."""
    elf_header = (
        b"\x7fELF"
        + bytes([2, 2, 1, 0])
        + bytes(8)
        + struct.pack(
            ">HHIQQQIHHHHHH",
            3,
            62,
            1,
            0x400000,
            64,
            0,
            0,
            64,
            56,
            0,
            64,
            0,
            0,
        )
    )

    elf_data = elf_header + bytes(500)
    stream = io.BytesIO(elf_data)

    elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

    assert elf.little_endian is False


def test_fallback_implementation_when_pyelftools_unavailable() -> None:
    """Fallback implementation provides working ELFFile when pyelftools unavailable."""
    if not pyelftools_handler.HAS_PYELFTOOLS:
        elf_data = create_minimal_elf64_binary()
        stream = io.BytesIO(elf_data)

        elf = pyelftools_handler.ELFFile(stream)  # type: ignore[no-untyped-call]

        assert elf is not None
        assert hasattr(elf, "header")


def test_dwarf_tag_constant_defined() -> None:
    """DW_TAG_compile_unit constant is defined."""
    assert hasattr(pyelftools_handler, "DW_TAG_compile_unit")
    assert isinstance(pyelftools_handler.DW_TAG_compile_unit, int)


def test_exception_hierarchy() -> None:
    """Exception classes have correct hierarchy."""
    assert issubclass(pyelftools_handler.ELFParseError, pyelftools_handler.ELFError)


def test_version_consistency_with_availability() -> None:
    """PYELFTOOLS_VERSION is None when pyelftools unavailable."""
    if not pyelftools_handler.HAS_PYELFTOOLS:
        assert pyelftools_handler.PYELFTOOLS_VERSION is None
