"""Production tests for PE file model.

Validates real PE file parsing including section analysis, RVA/offset conversion,
import/export extraction, certificate validation, and structure building for
binary analysis and hex viewer integration.
"""

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ui.widgets.pe_file_model import (
    ExportInfo,
    FileStructure,
    ImportInfo,
    PEFileModel,
    SectionInfo,
    create_file_model,
)

try:
    from intellicrack.handlers.pefile_handler import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


def create_minimal_pe(path: Path) -> None:
    """Create minimal valid PE file for testing."""
    with open(path, "wb") as f:
        dos_header = bytearray(64)
        struct.pack_into("<H", dos_header, 0, 0x5A4D)
        struct.pack_into("<I", dos_header, 60, 128)
        f.write(dos_header)

        dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"
        f.write(dos_stub)
        f.write(b"\x00" * (128 - 64 - len(dos_stub)))

        nt_headers = bytearray(248)
        struct.pack_into("<I", nt_headers, 0, 0x00004550)
        struct.pack_into("<H", nt_headers, 4, 0x014C)
        struct.pack_into("<H", nt_headers, 6, 1)
        struct.pack_into("<I", nt_headers, 8, 0)
        struct.pack_into("<I", nt_headers, 12, 0)
        struct.pack_into("<H", nt_headers, 16, 0)
        struct.pack_into("<H", nt_headers, 18, 224)
        struct.pack_into("<H", nt_headers, 20, 0x010B)
        struct.pack_into("<I", nt_headers, 40, 0x1000)
        struct.pack_into("<I", nt_headers, 52, 0x00400000)
        struct.pack_into("<I", nt_headers, 56, 0x1000)
        struct.pack_into("<I", nt_headers, 60, 0x200)
        struct.pack_into("<H", nt_headers, 92, 16)
        f.write(nt_headers)

        section_header = bytearray(40)
        section_header[0:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", section_header, 8, 0x1000)
        struct.pack_into("<I", section_header, 12, 0x1000)
        struct.pack_into("<I", section_header, 16, 0x200)
        struct.pack_into("<I", section_header, 20, 0x400)
        struct.pack_into("<I", section_header, 36, 0x60000020)
        f.write(section_header)

        f.write(b"\x00" * (0x400 - f.tell()))
        f.write(b"\x90" * 0x200)


@pytest.fixture
def sample_pe(tmp_path: Path) -> Path:
    """Create sample PE file for testing."""
    pe_path = tmp_path / "test.exe"
    create_minimal_pe(pe_path)
    return pe_path


@pytest.fixture
def non_pe_file(tmp_path: Path) -> Path:
    """Create non-PE file for testing."""
    file_path = tmp_path / "test.bin"
    file_path.write_bytes(b"\x7fELF\x00\x00\x00\x00" + b"\x00" * 100)
    return file_path


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_pe_file_model_initialization(sample_pe: Path) -> None:
    """PE file model initializes and parses file."""
    model = PEFileModel(str(sample_pe))

    assert model.file_path == sample_pe
    assert model.pe is not None
    assert model._parsed is True


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_pe_file_model_raises_on_missing_file(tmp_path: Path) -> None:
    """PE file model raises FileNotFoundError for missing file."""
    missing_path = tmp_path / "nonexistent.exe"

    with pytest.raises(FileNotFoundError):
        PEFileModel(str(missing_path))


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_section_info_properties(sample_pe: Path) -> None:
    """Section info contains correct properties."""
    model = PEFileModel(str(sample_pe))

    assert len(model.sections) > 0

    section = model.sections[0]
    assert isinstance(section, SectionInfo)
    assert section.name == ".text"
    assert section.virtual_address > 0
    assert section.raw_offset > 0
    assert section.characteristics > 0


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_section_is_executable_flag(sample_pe: Path) -> None:
    """Section executable flag correctly identifies executable sections."""
    model = PEFileModel(str(sample_pe))

    text_section = next((s for s in model.sections if s.name == ".text"), None)
    assert text_section is not None
    assert text_section.is_executable is True


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_section_is_writable_flag() -> None:
    """Section writable flag correctly identifies writable sections."""
    section = SectionInfo(
        name=".data",
        virtual_address=0x2000,
        virtual_size=0x1000,
        raw_offset=0x800,
        raw_size=0x1000,
        characteristics=0xC0000040,
    )

    assert section.is_writable is True


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_section_is_readable_flag() -> None:
    """Section readable flag correctly identifies readable sections."""
    section = SectionInfo(
        name=".rdata",
        virtual_address=0x3000,
        virtual_size=0x500,
        raw_offset=0x1800,
        raw_size=0x600,
        characteristics=0x40000040,
    )

    assert section.is_readable is True


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rva_to_offset_conversion(sample_pe: Path) -> None:
    """RVA to offset conversion works correctly."""
    model = PEFileModel(str(sample_pe))

    if len(model.sections) > 0:
        section = model.sections[0]
        test_rva = section.virtual_address + 0x10

        offset = model.rva_to_offset(test_rva)

        assert offset is not None
        assert offset > 0


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_offset_to_rva_conversion(sample_pe: Path) -> None:
    """Offset to RVA conversion works correctly."""
    model = PEFileModel(str(sample_pe))

    if len(model.sections) > 0:
        section = model.sections[0]
        test_offset = section.raw_offset + 0x10

        rva = model.offset_to_rva(test_offset)

        assert rva is not None
        assert rva > 0


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rva_to_offset_invalid_rva(sample_pe: Path) -> None:
    """RVA to offset returns None for invalid RVA."""
    model = PEFileModel(str(sample_pe))

    offset = model.rva_to_offset(0xFFFFFFFF)

    assert offset is None


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_get_sections_returns_list(sample_pe: Path) -> None:
    """Get sections returns list of SectionInfo objects."""
    model = PEFileModel(str(sample_pe))

    sections = model.get_sections()

    assert isinstance(sections, list)
    assert len(sections) > 0
    assert all(isinstance(s, SectionInfo) for s in sections)


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_get_structures_returns_list(sample_pe: Path) -> None:
    """Get structures returns list of FileStructure objects."""
    model = PEFileModel(str(sample_pe))

    structures = model.get_structures()

    assert isinstance(structures, list)
    assert len(structures) > 0
    assert all(isinstance(s, FileStructure) for s in structures)


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_structures_include_dos_header(sample_pe: Path) -> None:
    """Structures include DOS header."""
    model = PEFileModel(str(sample_pe))

    dos_header = next((s for s in model.structures if s.name == "DOS Header"), None)

    assert dos_header is not None
    assert dos_header.offset == 0
    assert dos_header.size == 64
    assert dos_header.structure_type == "header"


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_structures_include_nt_headers(sample_pe: Path) -> None:
    """Structures include NT headers."""
    model = PEFileModel(str(sample_pe))

    nt_header = next((s for s in model.structures if s.name == "NT Headers"), None)

    assert nt_header is not None
    assert nt_header.offset > 0
    assert nt_header.structure_type == "header"


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_structures_include_sections(sample_pe: Path) -> None:
    """Structures include section entries."""
    model = PEFileModel(str(sample_pe))

    section_structures = [s for s in model.structures if s.structure_type == "section"]

    assert len(section_structures) > 0
    assert any(".text" in s.name for s in section_structures)


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_get_section_at_rva(sample_pe: Path) -> None:
    """Get section at RVA returns correct section."""
    model = PEFileModel(str(sample_pe))

    if len(model.sections) > 0:
        section = model.sections[0]
        test_rva = section.virtual_address + 0x50

        found_section = model.get_section_at_rva(test_rva)

        assert found_section is not None
        assert found_section.name == section.name


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_get_section_at_rva_invalid(sample_pe: Path) -> None:
    """Get section at RVA returns None for invalid RVA."""
    model = PEFileModel(str(sample_pe))

    section = model.get_section_at_rva(0xFFFFFFFF)

    assert section is None


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_get_section_at_offset(sample_pe: Path) -> None:
    """Get section at offset returns correct section."""
    model = PEFileModel(str(sample_pe))

    if len(model.sections) > 0:
        section = model.sections[0]
        test_offset = section.raw_offset + 0x50

        found_section = model.get_section_at_offset(test_offset)

        assert found_section is not None
        assert found_section.name == section.name


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_get_section_at_offset_invalid(sample_pe: Path) -> None:
    """Get section at offset returns None for invalid offset."""
    model = PEFileModel(str(sample_pe))

    section = model.get_section_at_offset(0xFFFFFFFF)

    assert section is None


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_is_valid_rva(sample_pe: Path) -> None:
    """Is valid RVA correctly identifies valid RVAs."""
    model = PEFileModel(str(sample_pe))

    if len(model.sections) > 0:
        section = model.sections[0]
        valid_rva = section.virtual_address

        assert model.is_valid_rva(valid_rva) is True
        assert model.is_valid_rva(0xFFFFFFFF) is False


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_is_valid_offset(sample_pe: Path) -> None:
    """Is valid offset correctly identifies valid offsets."""
    model = PEFileModel(str(sample_pe))

    assert model.is_valid_offset(0) is True
    assert model.is_valid_offset(100) is True
    assert model.is_valid_offset(model.file_size + 100) is False
    assert model.is_valid_offset(-1) is False


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_get_file_info_structure(sample_pe: Path) -> None:
    """Get file info returns comprehensive information dictionary."""
    model = PEFileModel(str(sample_pe))

    info = model.get_file_info()

    assert isinstance(info, dict)
    assert "file_path" in info
    assert "file_size" in info
    assert "image_base" in info
    assert "entry_point" in info
    assert "sections_count" in info
    assert "imports_count" in info
    assert "exports_count" in info
    assert "parsed" in info


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_get_file_info_values(sample_pe: Path) -> None:
    """Get file info returns correct values."""
    model = PEFileModel(str(sample_pe))

    info = model.get_file_info()

    assert info["file_path"] == str(sample_pe)
    assert info["file_size"] > 0
    assert info["sections_count"] == len(model.sections)
    assert info["parsed"] is True


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_get_imports_returns_list(sample_pe: Path) -> None:
    """Get imports returns list of ImportInfo objects."""
    model = PEFileModel(str(sample_pe))

    imports = model.get_imports()

    assert isinstance(imports, list)


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_get_exports_returns_list(sample_pe: Path) -> None:
    """Get exports returns list of ExportInfo objects."""
    model = PEFileModel(str(sample_pe))

    exports = model.get_exports()

    assert isinstance(exports, list)


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_get_certificates_returns_info(sample_pe: Path) -> None:
    """Get certificates returns CodeSigningInfo."""
    model = PEFileModel(str(sample_pe))

    certs = model.get_certificates()

    assert certs is not None
    assert hasattr(certs, "is_signed")


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_entropy_calculation(sample_pe: Path) -> None:
    """Entropy calculation produces valid values."""
    model = PEFileModel(str(sample_pe))

    if len(model.sections) > 0:
        section = model.sections[0]

        if section.entropy is not None:
            assert 0.0 <= section.entropy <= 8.0


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_create_file_model_pe_format(sample_pe: Path) -> None:
    """Create file model recognizes PE format."""
    model = create_file_model(str(sample_pe))

    assert model is not None
    assert isinstance(model, PEFileModel)


def test_create_file_model_non_pe_format(non_pe_file: Path) -> None:
    """Create file model returns None for non-PE format."""
    model = create_file_model(str(non_pe_file))

    assert model is None


def test_create_file_model_missing_file(tmp_path: Path) -> None:
    """Create file model returns None for missing file."""
    missing_path = tmp_path / "missing.exe"

    model = create_file_model(str(missing_path))

    assert model is None


def test_import_info_dataclass() -> None:
    """ImportInfo dataclass stores import information."""
    import_info = ImportInfo(
        dll_name="kernel32.dll",
        function_name="CreateFileA",
        ordinal=None,
        address=0x1000,
        hint=42,
    )

    assert import_info.dll_name == "kernel32.dll"
    assert import_info.function_name == "CreateFileA"
    assert import_info.ordinal is None
    assert import_info.address == 0x1000
    assert import_info.hint == 42


def test_export_info_dataclass() -> None:
    """ExportInfo dataclass stores export information."""
    export_info = ExportInfo(
        function_name="MyFunction",
        ordinal=1,
        address=0x2000,
        forwarder=None,
    )

    assert export_info.function_name == "MyFunction"
    assert export_info.ordinal == 1
    assert export_info.address == 0x2000
    assert export_info.forwarder is None


def test_file_structure_dataclass() -> None:
    """FileStructure dataclass stores structure information."""
    structure = FileStructure(
        name="Test Header",
        offset=0x100,
        size=64,
        description="Test structure",
        structure_type="header",
        properties={"key": "value"},
    )

    assert structure.name == "Test Header"
    assert structure.offset == 0x100
    assert structure.size == 64
    assert structure.description == "Test structure"
    assert structure.structure_type == "header"
    assert structure.properties["key"] == "value"


def test_section_info_default_entropy() -> None:
    """SectionInfo entropy defaults to None."""
    section = SectionInfo(
        name=".test",
        virtual_address=0x1000,
        virtual_size=0x500,
        raw_offset=0x400,
        raw_size=0x600,
        characteristics=0x60000020,
    )

    assert section.entropy is None


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_image_base_extraction(sample_pe: Path) -> None:
    """Image base extracted correctly from PE."""
    model = PEFileModel(str(sample_pe))

    assert model.image_base > 0


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_entry_point_extraction(sample_pe: Path) -> None:
    """Entry point extracted correctly from PE."""
    model = PEFileModel(str(sample_pe))

    assert model.entry_point >= 0


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_section_properties_in_structures(sample_pe: Path) -> None:
    """Section structures include property information."""
    model = PEFileModel(str(sample_pe))

    section_structures = [s for s in model.structures if s.structure_type == "section"]

    if len(section_structures) > 0:
        section = section_structures[0]
        assert "virtual_address" in section.properties
        assert "characteristics" in section.properties
        assert "executable" in section.properties
        assert "writable" in section.properties
        assert "readable" in section.properties
