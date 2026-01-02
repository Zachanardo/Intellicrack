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
    logger.exception("Import error in pe_file_model: %s", e)
    PEFILE_AVAILABLE = False


@dataclass
class FileStructure:
    """Represent a file structure component with metadata and properties.

    Contains information about a specific structure within a binary file,
    such as headers, sections, or data directories, including its location,
    size, and associated properties.

    Attributes:
        name: Name identifying the structure component.
        offset: File offset where this structure begins.
        size: Size in bytes of this structure.
        description: Human-readable description of the structure.
        structure_type: Classification of structure (header, section, directory, etc.).
        properties: Dictionary mapping property names to property values.
    """

    name: str
    offset: int
    size: int
    description: str
    structure_type: str  # header, section, directory, etc.
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class SectionInfo:
    """Encapsulate PE section information and permission attributes.

    Stores metadata about a PE section including its virtual and raw addresses,
    sizes, and characteristics, with helper properties for permission checking.

    Attributes:
        name: Section name as a null-terminated string.
        virtual_address: Virtual address of the section in memory.
        virtual_size: Size of the section in memory.
        raw_offset: File offset of the section's raw data.
        raw_size: Size of the section's raw data in the file.
        characteristics: Section characteristics flags (executable, writable, readable).
        entropy: Calculated Shannon entropy of the section data, or None if not calculated.
    """

    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    entropy: float | None = None

    @property
    def is_executable(self) -> bool:
        """Check if section is executable.

        Returns:
            True if section has execute permissions, False otherwise.
        """
        return bool(self.characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE

    @property
    def is_writable(self) -> bool:
        """Check if section is writable.

        Returns:
            True if section has write permissions, False otherwise.
        """
        return bool(self.characteristics & 0x80000000)  # IMAGE_SCN_MEM_WRITE

    @property
    def is_readable(self) -> bool:
        """Check if section is readable.

        Returns:
            True if section has read permissions, False otherwise.
        """
        return bool(self.characteristics & 0x40000000)  # IMAGE_SCN_MEM_READ


@dataclass
class ImportInfo:
    """Represent a PE import table entry with function resolution details.

    Stores information about an imported function including the source DLL,
    function name, ordinal, virtual address, and hint value for lookup optimization.

    Attributes:
        dll_name: Name of the DLL exporting the function.
        function_name: Name of the imported function.
        ordinal: Function ordinal for ordinal-based imports, or None for name-based imports.
        address: Virtual address of the imported function.
        hint: Import name table index for optimization, or None if not available.
    """

    dll_name: str
    function_name: str
    ordinal: int | None
    address: int
    hint: int | None = None


@dataclass
class ExportInfo:
    """Represent a PE export table entry with forwarding information.

    Stores metadata about an exported function including its name, ordinal,
    virtual address, and optional forwarder reference for re-export handling.

    Attributes:
        function_name: Name of the exported function.
        ordinal: Ordinal number assigned to the function in the export table.
        address: Virtual address of the exported function.
        forwarder: Optional re-export reference in the format "DLL.Function" or None.
    """

    function_name: str
    ordinal: int
    address: int
    forwarder: str | None = None


class BinaryFileModel(ABC):
    """Abstract base class for binary file format models.

    Defines the interface for parsing and analyzing different binary file formats,
    with methods for RVA/offset conversion, section retrieval, and structure extraction.
    Subclasses must implement format-specific parsing logic.
    """

    def __init__(self, file_path: str) -> None:
        """Initialize binary file model with file path validation and basic file information.

        Args:
            file_path: Path to the binary file to analyze.

        Raises:
            FileNotFoundError: If the specified file does not exist.

        Returns:
            None.
        """
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            error_msg = f"File not found: {file_path}"
            logger.exception(error_msg)
            raise FileNotFoundError(error_msg)

        self.file_size = self.file_path.stat().st_size
        self._parsed = False

    @abstractmethod
    def parse_file(self) -> None:
        """Parse the binary file structure.

        Parses format-specific headers, sections, imports, exports, and other
        structural information from the binary file.

        Raises:
            Exception: If parsing fails or the file format is invalid.
        """

    @abstractmethod
    def rva_to_offset(self, rva: int) -> int | None:
        """Convert RVA to file offset.

        Args:
            rva: Relative Virtual Address to convert.

        Returns:
            File offset corresponding to the RVA, or None if conversion fails.
        """

    @abstractmethod
    def offset_to_rva(self, offset: int) -> int | None:
        """Convert file offset to RVA.

        Args:
            offset: File offset to convert.

        Returns:
            Relative Virtual Address corresponding to the offset, or None if conversion fails.
        """

    @abstractmethod
    def get_sections(self) -> list[SectionInfo]:
        """Get file sections.

        Returns:
            list[SectionInfo]: List of section information objects from the binary file.
        """

    @abstractmethod
    def get_structures(self) -> list[FileStructure]:
        """Get file structures for tree view.

        Returns:
            list[FileStructure]: List of file structure objects for hierarchical visualization.
        """


class PEFileModel(BinaryFileModel):
    """PE file model implementing comprehensive Portable Executable format parsing.

    Provides complete analysis of PE structures including headers, sections,
    imports, exports, and digital certificates with RVA/offset conversion capabilities.
    Requires the pefile library for PE parsing functionality.
    """

    def __init__(self, file_path: str) -> None:
        """Initialize PE file model with comprehensive analysis of Portable Executable structure.

        Parses the PE file immediately upon initialization, loading all structural
        information including headers, sections, imports, exports, and certificates.

        Args:
            file_path: Path to the PE file to analyze.

        Raises:
            ImportError: If pefile library is not available for PE parsing.

        Returns:
            None.
        """
        super().__init__(file_path)

        if not PEFILE_AVAILABLE:
            error_msg = "pefile library is required for PE analysis"
            logger.exception(error_msg)
            raise ImportError(error_msg)

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
        """Parse PE file structure and populate internal data structures.

        Performs comprehensive parsing of the PE file including DOS header,
        NT headers, sections, imports, exports, certificates, and builds
        a hierarchical structure tree for visualization.

        Raises:
            Exception: If PE file parsing fails or the PE library encounters errors.

        Returns:
            None.
        """
        try:
            logger.debug("Parsing PE file: %s", self.file_path)

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
            logger.info("Successfully parsed PE file with %s sections", len(self.sections))

        except Exception as e:
            logger.exception("Failed to parse PE file %s: %s", self.file_path, e, exc_info=True)
            raise

    def _parse_sections(self) -> None:
        """Parse PE sections from the loaded PE object.

        Extracts all sections from the PE file and calculates entropy for
        each section containing raw data. Populates self.sections list.
        """
        self.sections = []

        if self.pe is None:
            return

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
        """Calculate entropy for a section.

        Args:
            section: Section information object to analyze.

        Returns:
            Shannon entropy value for the section data (0.0-8.0 range).
        """
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
            logger.warning("Failed to calculate entropy for section %s: %s", section.name, e, exc_info=True)
            return 0.0

    def _parse_imports(self) -> None:
        """Parse PE imports from import address table.

        Extracts all imported functions from the PE import directory,
        including DLL names, function names, ordinals, and addresses.
        Populates self.imports list. Handles missing import directories gracefully.
        """
        self.imports = []

        if self.pe is None or not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
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
            logger.warning("Failed to parse imports: %s", e, exc_info=True)
            return

    def _parse_exports(self) -> None:
        """Parse PE exports from export address table.

        Extracts all exported functions from the PE export directory,
        including function names, ordinals, addresses, and forwarders.
        Populates self.exports list. Handles missing export directories gracefully.
        """
        self.exports = []

        if self.pe is None or not hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
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
            logger.warning("Failed to parse exports: %s", e, exc_info=True)
            return

    def _extract_certificates(self) -> None:
        """Extract digital certificates from PE file.

        Extracts certificate information from the PE Authenticode data directory
        and populates self.certificates with CodeSigningInfo containing signing details,
        trust status, and certificate chain information. Handles extraction failures gracefully.
        """
        try:
            self.certificates = extract_pe_certificates(str(self.file_path))
            logger.debug("Certificate extraction completed. Signed: %s", self.certificates.is_signed)
        except Exception as e:
            logger.warning("Failed to extract certificates: %s", e, exc_info=True)
            self.certificates = CodeSigningInfo(is_signed=False)
            return

    def _build_structures(self) -> None:
        """Build structure hierarchy for tree view visualization.

        Constructs a hierarchical representation of the PE file structure including
        DOS header, NT headers, sections, and data directories. Populates self.structures
        with FileStructure objects containing metadata and properties for visualization.
        """
        self.structures = []

        if self.pe is None:
            return

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
        if self.pe is not None and hasattr(self.pe, "OPTIONAL_HEADER") and hasattr(self.pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
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
        """Convert RVA to file offset.

        Args:
            rva: Relative Virtual Address to convert.

        Returns:
            File offset corresponding to the RVA, or None if conversion fails or PE is not loaded.
        """
        if not self.pe:
            return None

        try:
            offset = self.pe.get_offset_from_rva(rva)
            if isinstance(offset, int):
                return offset
            return None
        except Exception as e:
            logger.exception("Exception in pe_file_model: %s", e)
            return None

    def offset_to_rva(self, offset: int) -> int | None:
        """Convert file offset to RVA.

        Args:
            offset: File offset to convert.

        Returns:
            Relative Virtual Address corresponding to the offset, or None if conversion fails or PE is not loaded.
        """
        if not self.pe:
            return None

        try:
            rva = self.pe.get_rva_from_offset(offset)
            if isinstance(rva, int):
                return rva
            return None
        except Exception as e:
            logger.exception("Exception in pe_file_model: %s", e)
            return None

    def get_sections(self) -> list[SectionInfo]:
        """Get PE sections.

        Returns:
            List of section information objects containing virtual/raw addresses,
            sizes, characteristics, and entropy values.
        """
        return self.sections

    def get_structures(self) -> list[FileStructure]:
        """Get file structures for tree view.

        Returns:
            List of file structure objects for hierarchical visualization including
            headers, sections, and data directories.
        """
        return self.structures

    def get_imports(self) -> list[ImportInfo]:
        """Get all PE imported functions.

        Returns:
            List of import information objects containing DLL names, function names,
            ordinals, and addresses.
        """
        return self.imports

    def get_exports(self) -> list[ExportInfo]:
        """Get all PE exported functions.

        Returns:
            List of export information objects containing function names, ordinals,
            addresses, and forwarder references.
        """
        return self.exports

    def get_certificates(self) -> CodeSigningInfo | None:
        """Get digital certificate information.

        Returns:
            CodeSigningInfo object with certificate details, trust status, and
            certificate chain, or None if not extracted.
        """
        return self.certificates

    def get_section_at_rva(self, rva: int) -> SectionInfo | None:
        """Get section containing the given RVA.

        Args:
            rva: Relative Virtual Address to search for.

        Returns:
            Section information object containing the RVA, or None if no section
            contains the specified address.
        """
        return next(
            (section for section in self.sections if section.virtual_address <= rva < section.virtual_address + section.virtual_size),
            None,
        )

    def get_section_at_offset(self, offset: int) -> SectionInfo | None:
        """Get section containing the given file offset.

        Args:
            offset: File offset to search for.

        Returns:
            Section information object containing the offset, or None if no section
            contains the specified offset.
        """
        return next(
            (section for section in self.sections if section.raw_offset <= offset < section.raw_offset + section.raw_size),
            None,
        )

    def is_valid_rva(self, rva: int) -> bool:
        """Check if RVA is valid.

        Args:
            rva: Relative Virtual Address to validate.

        Returns:
            True if the RVA can be converted to a valid file offset, False otherwise.
        """
        return self.rva_to_offset(rva) is not None

    def is_valid_offset(self, offset: int) -> bool:
        """Check if file offset is valid.

        Args:
            offset: File offset to validate.

        Returns:
            True if the offset is within the file bounds, False otherwise.
        """
        return 0 <= offset < self.file_size

    def get_file_info(self) -> dict[str, Any]:
        """Get comprehensive file information.

        Returns:
            Dictionary containing file metadata including path, size, image base,
            entry point, section/import/export counts, machine type, timestamp,
            parsing status, and digital signing information.
        """
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
            if signing_cert := self.certificates.signing_certificate:
                info |= {
                    "certificate_subject": signing_cert.subject,
                    "certificate_issuer": signing_cert.issuer,
                    "certificate_valid": signing_cert.is_valid,
                    "certificate_expired": signing_cert.is_expired,
                    "trust_status": self.certificates.trust_status,
                    "certificate_count": len(self.certificates.certificates),
                }

        return info


def create_file_model(file_path: str) -> BinaryFileModel | None:
    """Create appropriate file model based on binary file format.

    Detects the file format by examining the file header and instantiates
    the appropriate BinaryFileModel subclass for the detected format.
    Currently supports PE (Portable Executable) format with extensibility
    for ELF and other binary formats.

    Args:
        file_path: Path to the binary file to analyze.

    Returns:
        Appropriate BinaryFileModel instance for the detected file format
        (e.g., PEFileModel), or None if the format is unsupported.
    """
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

        logger.warning("Unsupported file format: %s", file_path)
        return None

    except Exception as e:
        logger.exception("Failed to create file model for %s: %s", file_path, e, exc_info=True)
        return None
