"""PE File Model for Hex Viewer Integration.

Provides structured access to PE file information with RVA/offset conversion capabilities.
Serves as the foundational data layer for hex viewer structure visualization.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...utils.binary.certificate_extractor import CodeSigningInfo, extract_pe_certificates
from ...utils.logger import get_logger

logger = get_logger(__name__)

try:
    from intellicrack.handlers.pefile_handler import pefile

    PEFILE_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in pe_file_model: %s", e)
    PEFILE_AVAILABLE = False


@dataclass
class FileStructure:
    """Provide file structure information."""

    name: str
    offset: int
    size: int
    description: str
    structure_type: str  # header, section, directory, etc.
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class SectionInfo:
    """PE section information."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    entropy: float | None = None

    @property
    def is_executable(self) -> bool:
        """Check if section is executable."""
        return bool(self.characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE

    @property
    def is_writable(self) -> bool:
        """Check if section is writable."""
        return bool(self.characteristics & 0x80000000)  # IMAGE_SCN_MEM_WRITE

    @property
    def is_readable(self) -> bool:
        """Check if section is readable."""
        return bool(self.characteristics & 0x40000000)  # IMAGE_SCN_MEM_READ


@dataclass
class ImportInfo:
    """Import information."""

    dll_name: str
    function_name: str
    ordinal: int | None
    address: int
    hint: int | None = None


@dataclass
class ExportInfo:
    """Export information."""

    function_name: str
    ordinal: int
    address: int
    forwarder: str | None = None


class BinaryFileModel(ABC):
    """Abstract base class for binary file models."""

    def __init__(self, file_path: str):
        """Initialize binary file model with file path validation and basic file information."""
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        self.file_size = self.file_path.stat().st_size
        self._parsed = False

    @abstractmethod
    def parse_file(self) -> None:
        """Parse the binary file structure."""

    @abstractmethod
    def rva_to_offset(self, rva: int) -> int | None:
        """Convert RVA to file offset."""

    @abstractmethod
    def offset_to_rva(self, offset: int) -> int | None:
        """Convert file offset to RVA."""

    @abstractmethod
    def get_sections(self) -> list[SectionInfo]:
        """Get file sections."""

    @abstractmethod
    def get_structures(self) -> list[FileStructure]:
        """Get file structures for tree view."""


class PEFileModel(BinaryFileModel):
    """PE file model with comprehensive structure parsing."""

    def __init__(self, file_path: str):
        """Initialize PE file model with comprehensive analysis of Portable Executable structure."""
        super().__init__(file_path)

        if not PEFILE_AVAILABLE:
            raise ImportError("pefile library is required for PE analysis")

        self.pe: pefile.PE | None = None
        self.sections: list[SectionInfo] = []
        self.imports: list[ImportInfo] = []
        self.exports: list[ExportInfo] = []
        self.structures: list[FileStructure] = []
        self.certificates: CodeSigningInfo | None = None
        self.image_base: int = 0
        self.entry_point: int = 0

        # Parse the file
        self.parse_file()

    def parse_file(self) -> None:
        """Parse PE file structure."""
        try:
            logger.debug(f"Parsing PE file: {self.file_path}")

            # Load PE file
            self.pe = pefile.PE(str(self.file_path))

            # Get basic info
            # pylint: disable=no-member
            self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
            self.entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            # pylint: enable=no-member

            # Parse sections
            self._parse_sections()

            # Parse imports
            self._parse_imports()

            # Parse exports
            self._parse_exports()

            # Extract certificates
            self._extract_certificates()

            # Build structure tree
            self._build_structures()

            self._parsed = True
            logger.info(f"Successfully parsed PE file with {len(self.sections)} sections")

        except Exception as e:
            logger.error(f"Failed to parse PE file {self.file_path}: {e}")
            raise

    def _parse_sections(self) -> None:
        """Parse PE sections."""
        self.sections = []

        for section in self.pe.sections:
            section_info = SectionInfo(
                name=section.Name.decode("utf-8", errors="ignore").rstrip("\x00"),
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_offset=section.PointerToRawData,
                raw_size=section.SizeOfRawData,
                characteristics=section.Characteristics,
            )

            # Calculate entropy if section has data
            if section_info.raw_size > 0:
                section_info.entropy = self._calculate_section_entropy(section_info)

            self.sections.append(section_info)

    def _calculate_section_entropy(self, section: SectionInfo) -> float:
        """Calculate entropy for a section."""
        try:
            with open(self.file_path, "rb") as f:
                f.seek(section.raw_offset)
                data = f.read(min(section.raw_size, 8192))  # Sample for performance

            if not data:
                return 0.0

            # Calculate entropy
            import math

            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            # Calculate entropy
            entropy = 0.0
            data_len = len(data)

            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)

            return entropy

        except Exception as e:
            logger.warning(f"Failed to calculate entropy for section {section.name}: {e}")
            return 0.0

    def _parse_imports(self) -> None:
        """Parse PE imports."""
        self.imports = []

        if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return

        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:  # pylint: disable=no-member
                dll_name = entry.dll.decode("utf-8", errors="ignore")

                for imp in entry.imports:
                    import_info = ImportInfo(
                        dll_name=dll_name,
                        function_name=imp.name.decode("utf-8", errors="ignore") if imp.name else f"Ordinal_{imp.ordinal}",
                        ordinal=imp.ordinal,
                        address=imp.address,
                        hint=imp.hint,
                    )
                    self.imports.append(import_info)

        except Exception as e:
            logger.warning(f"Failed to parse imports: {e}")

    def _parse_exports(self) -> None:
        """Parse PE exports."""
        self.exports = []

        if not hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            return

        try:
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:  # pylint: disable=no-member
                export_info = ExportInfo(
                    function_name=exp.name.decode("utf-8", errors="ignore") if exp.name else f"Ordinal_{exp.ordinal}",
                    ordinal=exp.ordinal,
                    address=exp.address,
                    forwarder=exp.forwarder.decode("utf-8", errors="ignore") if exp.forwarder else None,
                )
                self.exports.append(export_info)

        except Exception as e:
            logger.warning(f"Failed to parse exports: {e}")

    def _extract_certificates(self) -> None:
        """Extract digital certificates from PE file."""
        try:
            self.certificates = extract_pe_certificates(str(self.file_path))
            logger.debug(f"Certificate extraction completed. Signed: {self.certificates.is_signed}")
        except Exception as e:
            logger.warning(f"Failed to extract certificates: {e}")
            self.certificates = CodeSigningInfo(is_signed=False)

    def _build_structures(self) -> None:
        """Build structure hierarchy for tree view."""
        self.structures = []

        # DOS Header
        dos_header = FileStructure(
            name="DOS Header",
            offset=0,
            size=64,
            description="MS-DOS Header",
            structure_type="header",
            properties={
                # pylint: disable=no-member
                "e_magic": self.pe.DOS_HEADER.e_magic,
                "e_lfanew": self.pe.DOS_HEADER.e_lfanew,
                # pylint: enable=no-member
            },
        )
        self.structures.append(dos_header)

        # NT Headers
        # pylint: disable=no-member
        nt_offset = self.pe.DOS_HEADER.e_lfanew
        nt_header = FileStructure(
            name="NT Headers",
            offset=nt_offset,
            size=248,  # Standard NT header size
            description="PE NT Headers",
            structure_type="header",
            properties={
                "signature": self.pe.NT_HEADERS.Signature,
                "machine": self.pe.FILE_HEADER.Machine,
                "timestamp": self.pe.FILE_HEADER.TimeDateStamp,
                "sections": self.pe.FILE_HEADER.NumberOfSections,
                "entry_point": self.entry_point,
                "image_base": self.image_base,
            },
            # pylint: enable=no-member
        )
        self.structures.append(nt_header)

        # Sections
        for section in self.sections:
            section_struct = FileStructure(
                name=f"Section: {section.name}",
                offset=section.raw_offset,
                size=section.raw_size,
                description=f"PE Section ({section.name})",
                structure_type="section",
                properties={
                    "virtual_address": f"0x{section.virtual_address:X}",
                    "virtual_size": section.virtual_size,
                    "characteristics": f"0x{section.characteristics:X}",
                    "executable": section.is_executable,
                    "writable": section.is_writable,
                    "readable": section.is_readable,
                    "entropy": f"{section.entropy:.2f}" if section.entropy else "N/A",
                },
            )
            self.structures.append(section_struct)

        # Data Directories
        if hasattr(self.pe, "OPTIONAL_HEADER") and hasattr(self.pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            # pylint: disable=no-member
            for i, directory in enumerate(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY):
                if directory.VirtualAddress and directory.Size:
                    dir_names = [
                        "Export Table",
                        "Import Table",
                        "Resource Table",
                        "Exception Table",
                        "Certificate Table",
                        "Base Relocation Table",
                        "Debug",
                        "Architecture",
                        "Global Ptr",
                        "TLS Table",
                        "Load Config Table",
                        "Bound Import",
                        "IAT",
                        "Delay Import Descriptor",
                        "COM+ Runtime Header",
                        "Reserved",
                    ]

                    dir_name = dir_names[i] if i < len(dir_names) else f"Directory {i}"

                    # Convert RVA to file offset
                    file_offset = self.rva_to_offset(directory.VirtualAddress)

                    if file_offset is not None:
                        dir_struct = FileStructure(
                            name=dir_name,
                            offset=file_offset,
                            size=directory.Size,
                            description=f"Data Directory: {dir_name}",
                            structure_type="directory",
                            properties={
                                "rva": f"0x{directory.VirtualAddress:X}",
                                "size": directory.Size,
                            },
                        )
                        self.structures.append(dir_struct)
            # pylint: enable=no-member

    def rva_to_offset(self, rva: int) -> int | None:
        """Convert RVA to file offset."""
        if not self.pe:
            return None

        try:
            return self.pe.get_offset_from_rva(rva)
        except Exception as e:
            logger.error("Exception in pe_file_model: %s", e)
            return None

    def offset_to_rva(self, offset: int) -> int | None:
        """Convert file offset to RVA."""
        if not self.pe:
            return None

        try:
            return self.pe.get_rva_from_offset(offset)
        except Exception as e:
            logger.error("Exception in pe_file_model: %s", e)
            return None

    def get_sections(self) -> list[SectionInfo]:
        """Get PE sections."""
        return self.sections

    def get_structures(self) -> list[FileStructure]:
        """Get file structures for tree view."""
        return self.structures

    def get_imports(self) -> list[ImportInfo]:
        """Get PE imports."""
        return self.imports

    def get_exports(self) -> list[ExportInfo]:
        """Get PE exports."""
        return self.exports

    def get_certificates(self) -> CodeSigningInfo | None:
        """Get digital certificate information."""
        return self.certificates

    def get_section_at_rva(self, rva: int) -> SectionInfo | None:
        """Get section containing the given RVA."""
        for section in self.sections:
            if section.virtual_address <= rva < section.virtual_address + section.virtual_size:
                return section
        return None

    def get_section_at_offset(self, offset: int) -> SectionInfo | None:
        """Get section containing the given file offset."""
        for section in self.sections:
            if section.raw_offset <= offset < section.raw_offset + section.raw_size:
                return section
        return None

    def is_valid_rva(self, rva: int) -> bool:
        """Check if RVA is valid."""
        return self.rva_to_offset(rva) is not None

    def is_valid_offset(self, offset: int) -> bool:
        """Check if file offset is valid."""
        return 0 <= offset < self.file_size

    def get_file_info(self) -> dict[str, Any]:
        """Get comprehensive file information."""
        info = {
            "file_path": str(self.file_path),
            "file_size": self.file_size,
            "image_base": f"0x{self.image_base:X}",
            "entry_point": f"0x{self.entry_point:X}",
            "sections_count": len(self.sections),
            "imports_count": len(self.imports),
            "exports_count": len(self.exports),
            "machine_type": self.pe.FILE_HEADER.Machine if self.pe else "Unknown",  # pylint: disable=no-member
            "timestamp": self.pe.FILE_HEADER.TimeDateStamp if self.pe else 0,  # pylint: disable=no-member
            "parsed": self._parsed,
            "is_signed": self.certificates.is_signed if self.certificates else False,
        }

        # Add certificate details if signed
        if self.certificates and self.certificates.is_signed:
            signing_cert = self.certificates.signing_certificate
            if signing_cert:
                info.update(
                    {
                        "certificate_subject": signing_cert.subject,
                        "certificate_issuer": signing_cert.issuer,
                        "certificate_valid": signing_cert.is_valid,
                        "certificate_expired": signing_cert.is_expired,
                        "trust_status": self.certificates.trust_status,
                        "certificate_count": len(self.certificates.certificates),
                    }
                )

        return info


def create_file_model(file_path: str) -> BinaryFileModel | None:
    """Create appropriate file model."""
    try:
        # Check file format
        with open(file_path, "rb") as f:
            header = f.read(4)

        # Check for PE format (MZ signature)
        if header[:2] == b"MZ":
            return PEFileModel(file_path)

        # Future: Add ELF support
        # elif header == b'\x7fELF':
        #     return ELFFileModel(file_path)

        logger.warning(f"Unsupported file format: {file_path}")
        return None

    except Exception as e:
        logger.error(f"Failed to create file model for {file_path}: {e}")
        return None
