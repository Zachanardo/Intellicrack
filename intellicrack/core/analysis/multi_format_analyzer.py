"""Multi-format binary analyzer for comprehensive executable format support.

This module provides unified analysis capabilities for various executable formats
including PE, ELF, Mach-O, DEX, APK, JAR, MSI, and COM files, enabling comprehensive
binary analysis across multiple platforms and architectures within the Intellicrack
security research framework.

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

import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from intellicrack.utils.logger import logger

# Import common patterns from centralized module
from ...utils.core.import_patterns import (
    LIEF_AVAILABLE,
    MACHOLIB_AVAILABLE,
    PEFILE_AVAILABLE,
    PYELFTOOLS_AVAILABLE,
    XML_AVAILABLE,
    ZIPFILE_AVAILABLE,
    ELFFile,
    MachO,
    lief,
    pefile,
    zipfile,
)
from ...utils.protection_utils import calculate_entropy


if TYPE_CHECKING:
    from collections.abc import Callable


class BinaryInfo:
    """Container for binary file information used in script generation."""

    def __init__(
        self,
        file_path: str = "",
        file_size: int = 0,
        file_type: str = "",
        architecture: str = "",
        endianness: str = "",
        entry_point: int = 0,
        sections: list[Any] | None = None,
        imports: dict[Any, Any] | None = None,
        exports: dict[Any, Any] | None = None,
        strings: list[Any] | None = None,
        md5: str = "",
        sha256: str = "",
    ) -> None:
        """Initialize binary information container."""
        self.file_path = file_path
        self.file_size = file_size
        self.file_type = file_type
        self.architecture = architecture
        self.endianness = endianness
        self.entry_point = entry_point
        self.sections = sections or []
        self.imports = imports or {}
        self.exports = exports or {}
        self.strings = strings or []
        self.md5 = md5
        self.sha256 = sha256


class MultiFormatBinaryAnalyzer:
    """Multi-format binary analyzer supporting PE, ELF, Mach-O, and other formats.

    This class provides a unified interface for analyzing different binary formats
    and extracting relevant information for security research and reverse engineering.
    """

    def __init__(self) -> None:
        """Initialize the multi-format binary analyzer.

        Sets up the multi-format binary analyzer with support for PE, ELF,
        Mach-O, DEX, APK, JAR, MSI, and COM files. Initializes format detection
        capabilities and available analysis backends for comprehensive binary
        examination across multiple platforms and architectures.
        """
        self.logger = logging.getLogger(__name__)

        # Check for required dependencies
        self.lief_available = LIEF_AVAILABLE
        self.pefile_available = PEFILE_AVAILABLE
        self.pyelftools_available = PYELFTOOLS_AVAILABLE
        self.macholib_available = MACHOLIB_AVAILABLE
        self.zipfile_available = ZIPFILE_AVAILABLE
        self.xml_available = XML_AVAILABLE

        self._check_available_backends()

    def _check_available_backends(self) -> None:
        """Check which binary analysis backends are available."""
        if self.lief_available:
            self.logger.info("LIEF multi-format binary analysis available")
        else:
            self.logger.info("LIEF multi-format binary analysis not available")

        if self.pefile_available:
            self.logger.info("pefile PE analysis available")
        else:
            self.logger.info("pefile PE analysis not available")

        if self.pyelftools_available:
            self.logger.info("pyelftools ELF analysis available")
        else:
            self.logger.info("pyelftools ELF analysis not available")

        if self.macholib_available:
            self.logger.info("macholib Mach-O analysis available")
        else:
            self.logger.info("macholib Mach-O analysis not available")

        if self.zipfile_available:
            self.logger.info("zipfile archive analysis available")
        else:
            self.logger.info("zipfile archive analysis not available")

        if self.xml_available:
            self.logger.info("XML parsing available")
        else:
            self.logger.info("XML parsing not available")

    def identify_format(self, binary_path: str | Path) -> str:
        """Identify the format of a binary file.

        Args:
            binary_path: Path to the binary file

        Returns:
            Format of the binary ('PE', 'ELF', 'MACHO', 'DOTNET', 'CLASS', 'DEX', 'APK', 'JAR', 'MSI', 'COM', 'UNKNOWN')

        """
        try:
            with open(binary_path, "rb") as f:
                magic = f.read(4)

                # Check for PE format (MZ header)
                if magic.startswith(b"MZ"):
                    # Need to check if it's a .NET assembly
                    f.seek(0x3C)
                    pe_offset = int.from_bytes(f.read(4), byteorder="little")
                    f.seek(pe_offset + 0x18)
                    pe_magic = f.read(2)
                    if pe_magic in [b"\x0b\x01", b"\x07\x01"]:  # 32-bit or 64-bit
                        # Check for CLI header
                        f.seek(pe_offset + 0x18 + 0x60)
                        cli_header = f.read(8)
                        if any(cli_header):
                            return "DOTNET"
                    return "PE"

                # Check for ELF format
                if magic.startswith(b"\x7fELF"):
                    return "ELF"

                # Check for Mach-O format (32-bit or 64-bit)
                if magic in [
                    b"\xfe\xed\xfa\xce",
                    b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe",
                    b"\xcf\xfa\xed\xfe",
                ]:
                    return "MACHO"

                # Check for Java class file
                if magic.startswith(b"\xca\xfe\xba\xbe"):
                    return "CLASS"

                # Check for DEX (Android Dalvik Executable)
                if magic.startswith(b"dex\n"):
                    return "DEX"

                # Check for ZIP-based formats (JAR, APK)
                if magic.startswith(b"PK\x03\x04") or magic.startswith(b"PK\x05\x06"):
                    # This is a ZIP file, need to check for specific types
                    file_extension = str(binary_path).lower().split(".")[-1]
                    if file_extension in ["apk", "xapk"]:
                        return "APK"
                    if file_extension in ["jar", "war", "ear"]:
                        return "JAR"
                    # Check if it's an APK by looking for AndroidManifest.xml
                    try:
                        import zipfile as zf

                        with zf.ZipFile(binary_path, "r") as zip_file:
                            if "AndroidManifest.xml" in zip_file.namelist():
                                return "APK"
                            if "META-INF/MANIFEST.MF" in zip_file.namelist():
                                return "JAR"
                    except Exception as e:
                        self.logger.debug("Failed to check ZIP sub-type: %s", e)
                    return "ZIP"

                # Check for MSI (Microsoft Installer)
                if magic.startswith(b"\xd0\xcf\x11\xe0"):
                    # This is a compound document format, could be MSI
                    file_extension = str(binary_path).lower().split(".")[-1]
                    if file_extension == "msi":
                        return "MSI"

                # Check for COM (DOS executable) based on file extension and size
                file_extension = str(binary_path).lower().split(".")[-1]
                if file_extension == "com":
                    try:
                        file_size = Path(binary_path).stat().st_size
                        if file_size <= 65536:  # 64KB limit for COM files
                            return "COM"
                    except Exception as e:
                        self.logger.debug("Failed to check COM file size: %s", e)

                return "UNKNOWN"

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error identifying binary format: %s", e)
            return "UNKNOWN"

    def analyze_binary(self, binary_path: str | Path) -> dict[str, Any]:
        """Analyze a binary file of any supported format.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary

        """
        # Identify format
        binary_format = self.identify_format(binary_path)

        # Choose appropriate analysis method
        if binary_format == "PE":
            return self.analyze_pe(binary_path)
        if binary_format == "ELF":
            return self.analyze_elf(binary_path)
        if binary_format == "MACHO":
            return self.analyze_macho(binary_path)
        if binary_format == "DOTNET":
            return self.analyze_dotnet(binary_path)
        if binary_format == "CLASS":
            return self.analyze_java(binary_path)
        if binary_format == "DEX":
            return self.analyze_dex(binary_path)
        if binary_format == "APK":
            return self.analyze_apk(binary_path)
        if binary_format == "JAR":
            return self.analyze_jar(binary_path)
        if binary_format == "MSI":
            return self.analyze_msi(binary_path)
        if binary_format == "COM":
            return self.analyze_com(binary_path)
        return {
            "format": binary_format,
            "error": "Unsupported binary format",
        }

    def analyze_pe(self, binary_path: str | Path) -> dict[str, Any]:
        """Analyze a PE (Windows) binary.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary

        """
        if not self.pefile_available:
            return {
                "format": "PE",
                "error": "pefile library not available",
            }

        try:
            pe = pefile.PE(str(binary_path))

            # Basic information
            info: dict[str, Any] = {
                "format": "PE",
                "machine": self._get_machine_type(getattr(pe.FILE_HEADER, "Machine", 0)),
                "timestamp": self._get_pe_timestamp(getattr(pe.FILE_HEADER, "TimeDateStamp", 0)),
                "subsystem": getattr(pe.OPTIONAL_HEADER, "Subsystem", 0),
                "characteristics": self._get_characteristics(getattr(pe.FILE_HEADER, "Characteristics", 0)),
                "sections": [],
                "imports": [],
                "exports": [],
            }

            # Section information
            for section in pe.sections:
                section_name = section.Name.decode("utf-8", "ignore").strip("\x00")
                section_info = {
                    "name": section_name,
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "characteristics": hex(section.Characteristics),
                    "entropy": calculate_entropy(section.get_data()),
                }
                info["sections"].append(section_info)

            # Import information
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", "ignore")
                    imports = []

                    for imp in entry.imports:
                        if imp.name:
                            import_name = imp.name.decode("utf-8", "ignore")
                            imports.append(import_name)

                    info["imports"].append(
                        {
                            "dll": dll_name,
                            "functions": imports,
                        },
                    )

            # Export information
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        export_name = exp.name.decode("utf-8", "ignore")
                        info["exports"].append(
                            {
                                "name": export_name,
                                "address": hex(exp.address),
                            },
                        )

            return info

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error analyzing PE binary: %s", e)
            return {
                "format": "PE",
                "error": str(e),
            }

    def analyze_elf(self, binary_path: str | Path) -> dict[str, Any]:
        """Analyze an ELF (Linux) binary.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary

        """
        if not self.lief_available and not self.pyelftools_available:
            return {
                "format": "ELF",
                "error": "No ELF analysis backend available",
            }

        try:
            # Use LIEF if available
            if self.lief_available and hasattr(lief, "parse"):
                binary = lief.parse(str(binary_path))

                # Basic information
                if binary is None:
                    return {
                        "format": "ELF",
                        "error": "Failed to parse binary with LIEF",
                    }

                info: dict[str, Any] = {
                    "format": "ELF",
                    "machine": getattr(binary.header.machine_type, "name", str(binary.header.machine_type))
                    if hasattr(binary, "header") and hasattr(binary.header, "machine_type")
                    else "Unknown",
                    "class": "64-bit"
                    if (
                        hasattr(binary, "header")
                        and hasattr(binary.header, "identity_class")
                        and binary.header.identity_class.name == "CLASS64"
                    )
                    else "32-bit",
                    "type": getattr(binary.header.file_type, "name", str(binary.header.file_type))
                    if hasattr(binary, "header") and hasattr(binary.header, "file_type")
                    else "Unknown",
                    "entry_point": hex(binary.header.entrypoint)
                    if hasattr(binary, "header") and hasattr(binary.header, "entrypoint")
                    else "0x0",
                    "sections": [],
                    "symbols": [],
                    "dynamic": [],
                }

                # Section information
                if hasattr(binary, "sections"):
                    for section in binary.sections:
                        section_info: dict[str, Any] = {
                            "name": section.name,
                            "type": getattr(section.type, "name", str(section.type)) if hasattr(section, "type") else "Unknown",
                            "address": hex(section.virtual_address),
                            "size": section.size,
                        }

                        # Calculate entropy if section has content
                        if section.content and section.size > 0:
                            section_info["entropy"] = calculate_entropy(bytes(section.content))

                        info["sections"].append(section_info)

                # Symbol information
                if hasattr(binary, "symbols"):
                    for symbol in binary.symbols:
                        if symbol.name:
                            symbol_info: dict[str, Any] = {
                                "name": symbol.name,
                                "type": getattr(symbol.type, "name", str(symbol.type)) if hasattr(symbol, "type") else "Unknown",
                                "value": hex(symbol.value),
                                "size": symbol.size,
                            }
                            info["symbols"].append(symbol_info)

                return info

            # Use pyelftools if LIEF not available
            if self.pyelftools_available:
                with open(binary_path, "rb") as f:
                    elf_file_func: Callable[..., Any] = cast("Callable[..., Any]", ELFFile)
                    elf_obj: Any = elf_file_func(f)

                # Basic information
                elf_info: dict[str, Any] = {
                    "format": "ELF",
                    "machine": elf_obj.header["e_machine"],
                    "class": elf_obj.header["e_ident"]["EI_CLASS"],
                    "type": elf_obj.header["e_type"],
                    "entry_point": hex(elf_obj.header["e_entry"]),
                    "sections": [],
                    "symbols": [],
                }

                # Section information
                for section in elf_obj.iter_sections():
                    elf_section_info: dict[str, Any] = {
                        "name": section.name,
                        "type": section["sh_type"],
                        "address": hex(section["sh_addr"]),
                        "size": section["sh_size"],
                    }

                    elf_info["sections"].append(elf_section_info)

                return elf_info

            return {
                "format": "ELF",
                "error": "No pyelftools backend available",
            }

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error analyzing ELF binary: %s", e)

        return {
            "format": "ELF",
            "error": "Unknown error analyzing ELF binary",
        }

    def analyze_macho(self, binary_path: str | Path) -> dict[str, Any]:
        """Analyze a Mach-O (macOS) binary.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary

        """
        if not self.lief_available and not self.macholib_available:
            return {
                "format": "MACHO",
                "error": "No Mach-O analysis backend available",
            }

        try:
            # Use LIEF if available
            if self.lief_available and hasattr(lief, "parse"):
                binary = lief.parse(str(binary_path))

                # Basic information
                if binary is None:
                    return {
                        "format": "MACHO",
                        "error": "Failed to parse binary with LIEF",
                    }

                info: dict[str, Any] = {
                    "format": "MACHO",
                    "headers": [],
                    "segments": [],
                    "symbols": [],
                    "libraries": [],
                }

                # Header information
                if hasattr(binary, "magic") and hasattr(binary, "header"):
                    header_info: dict[str, Any] = {
                        "magic": hex(binary.magic) if isinstance(binary.magic, int) else str(binary.magic),
                        "cpu_type": getattr(binary.header.cpu_type, "name", str(binary.header.cpu_type))
                        if hasattr(binary.header, "cpu_type")
                        else "Unknown",
                        "file_type": getattr(binary.header.file_type, "name", str(binary.header.file_type))
                        if hasattr(binary.header, "file_type")
                        else "Unknown",
                    }
                    info["headers"].append(header_info)

                # Segment information
                if hasattr(binary, "segments"):
                    for segment in binary.segments:
                        segment_info: dict[str, Any] = {
                            "name": getattr(segment, "name", "Unknown"),
                            "address": hex(segment.virtual_address),
                            "size": segment.virtual_size,
                            "sections": [],
                        }

                        # Section information
                        if hasattr(segment, "sections"):
                            for section in segment.sections:
                                section_info: dict[str, Any] = {
                                    "name": section.name,
                                    "address": hex(section.virtual_address),
                                    "size": section.size,
                                }

                                segment_info["sections"].append(section_info)

                        info["segments"].append(segment_info)

                return info

            # Use macholib if LIEF not available
            if self.macholib_available:
                macho = MachO(str(binary_path))

                # Basic information
                macho_info: dict[str, Any] = {
                    "format": "MACHO",
                    "headers": [],
                    "segments": [],
                    "libraries": [],
                }

                # Process each header
                for header in macho.headers:
                    macho_header_info: dict[str, Any] = {
                        "magic": hex(header.MH_MAGIC),
                        "cpu_type": header.header.cputype,
                        "cpu_subtype": header.header.cpusubtype,
                        "filetype": header.header.filetype,
                    }
                    macho_info["headers"].append(macho_header_info)

                return macho_info

            return {
                "format": "MACHO",
                "error": "No macholib backend available",
            }

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error analyzing Mach-O binary: %s", e)
            return {
                "format": "MACHO",
                "error": str(e),
            }

    def analyze_dotnet(self, binary_path: str | Path) -> dict[str, Any]:
        """Analyze a .NET assembly.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary

        """
        # For now, return basic PE analysis with .NET note
        result = self.analyze_pe(binary_path)
        if "error" not in result:
            result["note"] = "This is a .NET assembly. Consider using specialized .NET analysis tools."
        return result

    def analyze_java(self, _binary_path: str | Path) -> dict[str, Any]:  # pylint: disable=unused-argument
        """Analyze a Java class file.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary

        """
        return {
            "format": "CLASS",
            "note": "Java class file analysis not yet implemented",
        }

    def analyze_dex(self, binary_path: str | Path) -> dict[str, Any]:
        """Analyze an Android DEX (Dalvik Executable) file.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary

        """
        try:
            with open(binary_path, "rb") as f:
                # Read DEX header
                magic = f.read(8)
                if not magic.startswith(b"dex\n"):
                    return {
                        "format": "DEX",
                        "error": "Invalid DEX magic bytes",
                    }

                # Read basic header information
                f.seek(8)
                checksum = int.from_bytes(f.read(4), byteorder="little")

                f.seek(12)
                sha1_signature = f.read(20)

                f.seek(32)
                file_size = int.from_bytes(f.read(4), byteorder="little")
                header_size = int.from_bytes(f.read(4), byteorder="little")
                endian_tag = int.from_bytes(f.read(4), byteorder="little")

                f.seek(48)
                link_size = int.from_bytes(f.read(4), byteorder="little")
                link_off = int.from_bytes(f.read(4), byteorder="little")

                f.seek(56)
                map_off = int.from_bytes(f.read(4), byteorder="little")
                string_ids_size = int.from_bytes(f.read(4), byteorder="little")
                string_ids_off = int.from_bytes(f.read(4), byteorder="little")

                f.seek(68)
                type_ids_size = int.from_bytes(f.read(4), byteorder="little")
                type_ids_off = int.from_bytes(f.read(4), byteorder="little")

                f.seek(76)
                proto_ids_size = int.from_bytes(f.read(4), byteorder="little")
                proto_ids_off = int.from_bytes(f.read(4), byteorder="little")

                f.seek(84)
                field_ids_size = int.from_bytes(f.read(4), byteorder="little")
                field_ids_off = int.from_bytes(f.read(4), byteorder="little")

                f.seek(92)
                method_ids_size = int.from_bytes(f.read(4), byteorder="little")
                method_ids_off = int.from_bytes(f.read(4), byteorder="little")

                f.seek(100)
                class_defs_size = int.from_bytes(f.read(4), byteorder="little")
                class_defs_off = int.from_bytes(f.read(4), byteorder="little")

                # Basic information
                info: dict[str, Any] = {
                    "format": "DEX",
                    "dex_version": magic[4:7].decode("ascii"),
                    "checksum": f"0x{checksum:08X}",
                    "sha1_signature": sha1_signature.hex(),
                    "file_size": file_size,
                    "header_size": header_size,
                    "endian_tag": f"0x{endian_tag:08X}",
                    "link_size": link_size,
                    "link_offset": f"0x{link_off:08X}" if link_off else "None",
                    "map_offset": f"0x{map_off:08X}",
                    "string_ids_count": string_ids_size,
                    "type_ids_count": type_ids_size,
                    "proto_ids_count": proto_ids_size,
                    "field_ids_count": field_ids_size,
                    "method_ids_count": method_ids_size,
                    "class_defs_count": class_defs_size,
                    "sections": [],
                }

                # Add section information
                if string_ids_size > 0:
                    info["sections"].append(
                        {
                            "name": "String IDs",
                            "offset": f"0x{string_ids_off:08X}",
                            "count": string_ids_size,
                        },
                    )

                if type_ids_size > 0:
                    info["sections"].append(
                        {
                            "name": "Type IDs",
                            "offset": f"0x{type_ids_off:08X}",
                            "count": type_ids_size,
                        },
                    )

                if proto_ids_size > 0:
                    info["sections"].append(
                        {
                            "name": "Proto IDs",
                            "offset": f"0x{proto_ids_off:08X}",
                            "count": proto_ids_size,
                        },
                    )

                if field_ids_size > 0:
                    info["sections"].append(
                        {
                            "name": "Field IDs",
                            "offset": f"0x{field_ids_off:08X}",
                            "count": field_ids_size,
                        },
                    )

                if method_ids_size > 0:
                    info["sections"].append(
                        {
                            "name": "Method IDs",
                            "offset": f"0x{method_ids_off:08X}",
                            "count": method_ids_size,
                        },
                    )

                if class_defs_size > 0:
                    info["sections"].append(
                        {
                            "name": "Class Definitions",
                            "offset": f"0x{class_defs_off:08X}",
                            "count": class_defs_size,
                        },
                    )

                return info

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error analyzing DEX binary: %s", e)
            return {
                "format": "DEX",
                "error": str(e),
            }

    def analyze_apk(self, binary_path: str | Path) -> dict[str, Any]:
        """Analyze an Android APK (Android Package) file.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary

        """
        if not self.zipfile_available:
            return {
                "format": "APK",
                "error": "zipfile library not available",
            }

        if not self.xml_available:
            return {
                "format": "APK",
                "error": "XML parsing not available",
            }

        try:
            info: dict[str, Any] = {
                "format": "APK",
                "files": [],
                "dex_files": [],
                "native_libs": [],
                "resources": [],
                "manifest_info": {},
                "certificates": [],
                "total_files": 0,
            }

            with zipfile.ZipFile(binary_path, "r") as apk_file:
                file_list = apk_file.namelist()

                # Basic file information
                info["total_files"] = len(file_list)

                # Categorize files
                for file_name in file_list:
                    file_info = apk_file.getinfo(file_name)

                    entry = {
                        "name": file_name,
                        "compressed_size": file_info.compress_size,
                        "uncompressed_size": file_info.file_size,
                        "compression_type": file_info.compress_type,
                    }

                    if file_name.endswith(".dex"):
                        info["dex_files"].append(entry)
                    elif file_name.startswith("lib/"):
                        info["native_libs"].append(entry)
                    elif file_name.startswith("res/"):
                        info["resources"].append(entry)
                    elif file_name.startswith("META-INF/"):
                        info["certificates"].append(entry)

                    info["files"].append(entry)

                # Parse AndroidManifest.xml if available
                if "AndroidManifest.xml" in file_list:
                    try:
                        manifest_data = apk_file.read("AndroidManifest.xml")
                        # Note: AndroidManifest.xml is binary XML, would need specialized parser
                        info["manifest_info"] = {
                            "present": True,
                            "size": len(manifest_data),
                            "note": "Binary XML format - specialized parser required for full analysis",
                        }
                    except Exception as e:
                        logger.exception("Exception in multi_format_analyzer: %s", e)
                        info["manifest_info"] = {
                            "present": True,
                            "error": f"Failed to read manifest: {e!s}",
                        }
                else:
                    info["manifest_info"] = {"present": False}

                # Summary statistics
                info["summary"] = {
                    "dex_count": len(info["dex_files"]),
                    "native_lib_count": len(info["native_libs"]),
                    "resource_count": len(info["resources"]),
                    "certificate_count": len(info["certificates"]),
                    "total_uncompressed_size": sum(int(f.get("uncompressed_size", 0)) for f in info["files"]),
                    "total_compressed_size": sum(int(f.get("compressed_size", 0)) for f in info["files"]),
                }

                return info

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error analyzing APK binary: %s", e)
            return {
                "format": "APK",
                "error": str(e),
            }

    def analyze_jar(self, binary_path: str | Path) -> dict[str, Any]:
        """Analyze a Java JAR (Java Archive) file.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary

        """
        if not self.zipfile_available:
            return {
                "format": "JAR",
                "error": "zipfile library not available",
            }

        try:
            info: dict[str, Any] = {
                "format": "JAR",
                "files": [],
                "class_files": [],
                "resources": [],
                "manifest_info": {},
                "meta_inf": [],
                "total_files": 0,
            }

            with zipfile.ZipFile(binary_path, "r") as jar_file:
                file_list = jar_file.namelist()

                # Basic file information
                info["total_files"] = len(file_list)

                # Categorize files
                for file_name in file_list:
                    file_info = jar_file.getinfo(file_name)

                    entry = {
                        "name": file_name,
                        "compressed_size": file_info.compress_size,
                        "uncompressed_size": file_info.file_size,
                        "compression_type": file_info.compress_type,
                    }

                    if file_name.endswith(".class"):
                        info["class_files"].append(entry)
                    elif file_name.startswith("META-INF/"):
                        info["meta_inf"].append(entry)
                    else:
                        info["resources"].append(entry)

                    info["files"].append(entry)

                # Parse MANIFEST.MF if available
                if "META-INF/MANIFEST.MF" in file_list:
                    try:
                        manifest_data = jar_file.read("META-INF/MANIFEST.MF").decode("utf-8")
                        manifest_lines = manifest_data.strip().split("\n")

                        manifest_attrs = {}
                        for line in manifest_lines:
                            if ":" in line:
                                key, value = line.split(":", 1)
                                manifest_attrs[key.strip()] = value.strip()

                        info["manifest_info"] = {
                            "present": True,
                            "attributes": manifest_attrs,
                            "main_class": manifest_attrs.get("Main-Class", "Not specified"),
                            "manifest_version": manifest_attrs.get("Manifest-Version", "Unknown"),
                            "created_by": manifest_attrs.get("Created-By", "Unknown"),
                        }
                    except Exception as e:
                        logger.exception("Exception in multi_format_analyzer: %s", e)
                        info["manifest_info"] = {
                            "present": True,
                            "error": f"Failed to parse manifest: {e!s}",
                        }
                else:
                    info["manifest_info"] = {"present": False}

                # Summary statistics
                info["summary"] = {
                    "class_count": len(info["class_files"]),
                    "resource_count": len(info["resources"]),
                    "meta_inf_count": len(info["meta_inf"]),
                    "total_uncompressed_size": sum(int(f.get("uncompressed_size", 0)) for f in info["files"]),
                    "total_compressed_size": sum(int(f.get("compressed_size", 0)) for f in info["files"]),
                }

                return info

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error analyzing JAR binary: %s", e)
            return {
                "format": "JAR",
                "error": str(e),
            }

    def analyze_msi(self, binary_path: str | Path) -> dict[str, Any]:
        """Analyze a Microsoft Installer (MSI) file.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary

        """
        try:
            with open(binary_path, "rb") as f:
                # Read compound document header
                header = f.read(512)

                if not header.startswith(b"\\xd0\\xcf\\x11\\xe0"):
                    return {
                        "format": "MSI",
                        "error": "Invalid compound document signature",
                    }

                # Basic MSI analysis (compound document format)
                info = {
                    "format": "MSI",
                    "compound_document": True,
                    "file_size": Path(binary_path).stat().st_size,
                    "note": "MSI files use compound document format - specialized parser needed for full analysis",
                }

                # Extract basic compound document information
                minor_version = int.from_bytes(header[24:26], byteorder="little")
                major_version = int.from_bytes(header[26:28], byteorder="little")
                byte_order = int.from_bytes(header[28:30], byteorder="little")
                sector_size = int.from_bytes(header[30:32], byteorder="little")
                mini_sector_size = int.from_bytes(header[32:34], byteorder="little")

                info |= {
                    "minor_version": minor_version,
                    "major_version": major_version,
                    "byte_order": f"0x{byte_order:04X}",
                    "sector_size": 2**sector_size,
                    "mini_sector_size": 2**mini_sector_size,
                    "compound_doc_info": {
                        "sectors_in_directory_chain": int.from_bytes(header[44:48], byteorder="little"),
                        "sectors_in_fat": int.from_bytes(header[48:52], byteorder="little"),
                        "directory_first_sector": int.from_bytes(header[52:56], byteorder="little"),
                        "transaction_signature": int.from_bytes(header[56:60], byteorder="little"),
                        "mini_stream_cutoff": int.from_bytes(header[60:64], byteorder="little"),
                    },
                }

                return info

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error analyzing MSI binary: %s", e)
            return {
                "format": "MSI",
                "error": str(e),
            }

    def analyze_com(self, binary_path: str | Path) -> dict[str, Any]:
        """Analyze a DOS COM (Command) executable.

        Args:
            binary_path: Path to the binary file

        Returns:
            Analysis results dictionary

        """
        try:
            file_size = Path(binary_path).stat().st_size

            if file_size > 65536:  # 64KB limit for COM files
                return {
                    "format": "COM",
                    "error": "File too large for COM format (>64KB)",
                }

            with open(binary_path, "rb") as f:
                # Read first few bytes to analyze
                header_bytes = f.read(min(512, file_size))

                # Basic COM file analysis
                info: dict[str, Any] = {
                    "format": "COM",
                    "file_size": file_size,
                    "load_address": "0x0100",  # COM files load at CS:0100
                    "max_size": "64KB",
                    "header_analysis": {
                        "first_bytes": header_bytes[:16].hex(),
                        "possible_instructions": [],
                    },
                }

                # Try to identify common COM file patterns
                if header_bytes.startswith(b"\xe9"):  # JMP instruction
                    jump_offset = int.from_bytes(header_bytes[1:3], byteorder="little", signed=True)
                    info["header_analysis"]["first_instruction"] = f"JMP {jump_offset:+d}"
                    cast("list[str]", info["header_analysis"]["possible_instructions"]).append("Near jump")

                elif header_bytes.startswith(b"\xeb"):  # Short JMP instruction
                    jump_offset = int.from_bytes(header_bytes[1:2], byteorder="little", signed=True)
                    info["header_analysis"]["first_instruction"] = f"JMP SHORT {jump_offset:+d}"
                    cast("list[str]", info["header_analysis"]["possible_instructions"]).append("Short jump")

                elif header_bytes.startswith(b"\xb8"):  # MOV AX, imm16
                    immediate = int.from_bytes(header_bytes[1:3], byteorder="little")
                    info["header_analysis"]["first_instruction"] = f"MOV AX, 0x{immediate:04X}"
                    cast("list[str]", info["header_analysis"]["possible_instructions"]).append("Load immediate to AX")

                # Check for common DOS system calls
                if b"\xcd\x21" in header_bytes:  # INT 21h (DOS interrupt)
                    cast("list[str]", info["header_analysis"]["possible_instructions"]).append("DOS system call (INT 21h)")

                if b"\xcd\x20" in header_bytes:  # INT 20h (terminate program)
                    cast("list[str]", info["header_analysis"]["possible_instructions"]).append("Program termination (INT 20h)")

                # Calculate basic entropy
                if len(header_bytes) > 0:
                    byte_counts = [0] * 256
                    for byte in header_bytes:
                        byte_counts[byte] += 1

                    import math

                    entropy = 0.0
                    data_len = len(header_bytes)

                    for count in byte_counts:
                        if count > 0:
                            probability = count / data_len
                            entropy -= probability * math.log2(probability)

                    info["entropy"] = round(entropy, 2)

                return info

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error analyzing COM binary: %s", e)
            return {
                "format": "COM",
                "error": str(e),
            }

    # Helper methods
    def _get_machine_type(self, machine_value: int) -> str:
        """Get readable machine type from Machine value."""
        machine_types = {
            0x0: "UNKNOWN",
            0x1D3: "AM33",
            0x8664: "AMD64",
            0x1C0: "ARM",
            0xAA64: "ARM64",
            0x1C4: "ARMNT",
            0xEBC: "EBC",
            0x14C: "I386",
            0x200: "IA64",
            0x9041: "M32R",
            0x266: "MIPS16",
            0x366: "MIPSFPU",
            0x466: "MIPSFPU16",
            0x1F0: "POWERPC",
            0x1F1: "POWERPCFP",
            0x166: "R4000",
            0x5032: "RISCV32",
            0x5064: "RISCV64",
            0x5128: "RISCV128",
            0x1A2: "SH3",
            0x1A3: "SH3DSP",
            0x1A6: "SH4",
            0x1A8: "SH5",
            0x1C2: "THUMB",
            0x169: "WCEMIPSV2",
        }
        return machine_types.get(machine_value, f"UNKNOWN (0x{machine_value:04X})")

    def _get_pe_timestamp(self, timestamp: int) -> str:
        """Convert PE timestamp to readable date string."""
        try:
            return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            self.logger.exception("Exception in multi_format_analyzer: %s", e)
            return f"Invalid timestamp ({timestamp})"

    def _get_characteristics(self, characteristics: int) -> list[str]:
        """Convert PE characteristics flags to readable descriptions."""
        char_flags = {
            0x0001: "Relocation info stripped",
            0x0002: "Executable image",
            0x0004: "Line numbers stripped",
            0x0008: "Local symbols stripped",
            0x0010: "Aggressive WS trim",
            0x0020: "Large address aware",
            0x0080: "Bytes reversed lo",
            0x0100: "32-bit machine",
            0x0200: "Debug info stripped",
            0x0400: "Removable run from swap",
            0x0800: "Net run from swap",
            0x1000: "System file",
            0x2000: "DLL",
            0x4000: "Uniprocessor machine only",
            0x8000: "Bytes reversed hi",
        }

        return [desc for flag, desc in char_flags.items() if characteristics & flag]

    def analyze(self, binary_path: str | Path) -> dict[str, Any]:
        """Analyze a binary file and extract structure information.

        Args:
            binary_path: Path to the binary file

        Returns:
            Dictionary containing structure analysis results

        """
        binary_path = Path(binary_path)

        if not binary_path.exists():
            return {"error": f"File not found: {binary_path}"}

        # Identify format
        format_type = self.identify_format(binary_path)

        result = {
            "format": format_type,
            "file_path": str(binary_path),
            "file_size": binary_path.stat().st_size,
            "timestamp": datetime.now().isoformat(),
        }

        # Analyze based on format
        if format_type == "PE":
            result |= self.analyze_pe(binary_path)
        elif format_type == "ELF":
            result.update(self.analyze_elf(binary_path))
        elif format_type == "MACHO":
            result.update(self.analyze_macho(binary_path))
        elif self.lief_available:
            try:
                if binary := lief.parse(str(binary_path)):
                    result.update(self._analyze_lief_binary(binary))
            except Exception as e:
                self.logger.exception("LIEF analysis failed: %s", e)

        return result

    def _analyze_lief_binary(self, binary: object) -> dict[str, Any]:
        """Analyze a binary using LIEF.

        Args:
            binary: LIEF binary object to analyze.

        Returns:
            Dictionary containing analyzed binary information including architecture,
            endianness, and section details.

        """
        result: dict[str, Any] = {
            "architecture": (
                str(binary.header.architecture) if hasattr(binary, "header") and hasattr(binary.header, "architecture") else "Unknown"
            ),
            "endianness": (
                str(binary.header.endianness) if hasattr(binary, "header") and hasattr(binary.header, "endianness") else "Unknown"
            ),
        }

        # Get sections
        if hasattr(binary, "sections"):
            sections: list[dict[str, Any]] = [
                {
                    "name": section.name,
                    "virtual_address": section.virtual_address,
                    "virtual_size": section.virtual_size,
                    "size": section.size,
                    "entropy": (section.entropy if hasattr(section, "entropy") else 0),
                }
                for section in binary.sections
            ]
            result["sections"] = sections

        return result


def run_multi_format_analysis(app: object, binary_path: str | Path | None = None) -> dict[str, Any]:
    """Run analysis on a binary of any supported format.

    Args:
        app: Application instance with update_output signal for logging analysis progress.
        binary_path: Optional path to binary file to analyze (uses app.binary_path if not provided).

    Returns:
        Analysis results dictionary containing detected format and format-specific analysis data.

    """
    # Use provided path or get from app
    path = binary_path or getattr(app, "binary_path", None)
    if not path:
        if hasattr(app, "update_output") and hasattr(app.update_output, "emit"):
            app.update_output.emit("[Multi-Format] No binary selected.")
        return {"error": "No binary selected"}

    if hasattr(app, "update_output") and hasattr(app.update_output, "emit"):
        app.update_output.emit("[Multi-Format] Starting multi-format binary analysis...")

    # Create multi-format analyzer
    analyzer = MultiFormatBinaryAnalyzer()

    # Identify format
    binary_format = analyzer.identify_format(path)
    if hasattr(app, "update_output") and hasattr(app.update_output, "emit"):
        app.update_output.emit(f"[Multi-Format] Detected format: {binary_format}")

    # Run analysis
    if hasattr(app, "update_output") and hasattr(app.update_output, "emit"):
        app.update_output.emit(f"[Multi-Format] Analyzing {binary_format} binary...")
    results = analyzer.analyze_binary(path)

    # Check for error
    if "error" in results:
        if hasattr(app, "update_output") and hasattr(app.update_output, "emit"):
            app.update_output.emit(f"[Multi-Format] Error: {results['error']}")
        return results

    # Display results
    if hasattr(app, "update_output") and hasattr(app.update_output, "emit"):
        app.update_output.emit(f"[Multi-Format] Analysis completed for {binary_format} binary")

    # Add to analyze results
    if not hasattr(app, "analyze_results"):
        app.analyze_results = []

    analyze_results: list[str] = getattr(app, "analyze_results", [])

    analyze_results.append(f"\n=== MULTI-FORMAT BINARY ANALYSIS ({binary_format}) ===")

    # Format-specific information
    if binary_format == "PE":
        analyze_results.append(f"Machine: {results['machine']}")
        analyze_results.append(f"Timestamp: {results['timestamp']}")
        analyze_results.extend((f"Characteristics: {results['characteristics']}", "\nSections:"))
        for section in results["sections"]:
            entropy_str = f", Entropy: {section['entropy']:.2f}" if "entropy" in section else ""
            analyze_results.append(
                f"  {section['name']} - VA: {section['virtual_address']}, Size: {section['virtual_size']}{entropy_str}",
            )

        analyze_results.append("\nImports:")
        for imp in results["imports"]:
            analyze_results.append(f"  {imp['dll']} - {len(imp['functions'])} functions")

        analyze_results.append("\nExports:")
        for exp in results["exports"][:10]:  # Limit to first 10
            analyze_results.append(f"  {exp['name']} - {exp['address']}")

    elif binary_format == "ELF":
        analyze_results.append(f"Machine: {results['machine']}")
        analyze_results.append(f"Class: {results['class']}")
        analyze_results.append(f"Type: {results['type']}")
        analyze_results.extend((f"Entry Point: {results['entry_point']}", "\nSections:"))
        for section in results["sections"]:
            entropy_str = f", Entropy: {section['entropy']:.2f}" if "entropy" in section else ""
            analyze_results.append(f"  {section['name']} - Addr: {section['address']}, Size: {section['size']}{entropy_str}")

        analyze_results.append("\nSymbols:")
        for symbol in results["symbols"][:10]:  # Limit to first 10
            analyze_results.append(f"  {symbol['name']} - {symbol['value']}")

    elif binary_format == "MACHO":
        analyze_results.append(f"CPU Type: {results['headers'][0]['cpu_type']}")
        analyze_results.extend((f"File Type: {results['headers'][0]['file_type']}", "\nSegments:"))
        for segment in results["segments"]:
            analyze_results.extend((
                f"  {segment['name']} - Addr: {segment['address']}, Size: {segment['size']}",
                "  Sections:",
            ))
            for section in segment["sections"]:
                analyze_results.append(f"    {section['name']} - Addr: {section['address']}, Size: {section['size']}")

    elif binary_format == "DEX":
        analyze_results.append(f"DEX Version: {results['dex_version']}")
        analyze_results.append(f"File Size: {results['file_size']} bytes")
        analyze_results.append(f"Checksum: {results['checksum']}")
        analyze_results.append(f"String IDs: {results['string_ids_count']}")
        analyze_results.append(f"Type IDs: {results['type_ids_count']}")
        analyze_results.append(f"Method IDs: {results['method_ids_count']}")
        analyze_results.append(f"Class Definitions: {results['class_defs_count']}")

    elif binary_format == "APK":
        analyze_results.append(f"Total Files: {results['total_files']}")
        analyze_results.append(f"DEX Files: {results['summary']['dex_count']}")
        analyze_results.append(f"Native Libraries: {results['summary']['native_lib_count']}")
        analyze_results.append(f"Resources: {results['summary']['resource_count']}")
        analyze_results.append(f"Certificates: {results['summary']['certificate_count']}")

        if results["manifest_info"]["present"]:
            analyze_results.append("\nAndroidManifest.xml: Present")
        else:
            analyze_results.append("\nAndroidManifest.xml: Missing")

    elif binary_format == "JAR":
        analyze_results.append(f"Total Files: {results['total_files']}")
        analyze_results.append(f"Class Files: {results['summary']['class_count']}")
        analyze_results.append(f"Resources: {results['summary']['resource_count']}")
        analyze_results.append(f"META-INF Files: {results['summary']['meta_inf_count']}")

        if results["manifest_info"]["present"]:
            analyze_results.append("\nManifest Information:")
            manifest = results["manifest_info"]
            analyze_results.append(f"  Main Class: {manifest.get('main_class', 'Not specified')}")
            analyze_results.append(f"  Manifest Version: {manifest.get('manifest_version', 'Unknown')}")
            analyze_results.append(f"  Created By: {manifest.get('created_by', 'Unknown')}")

    elif binary_format == "MSI":
        analyze_results.extend((
            f"File Size: {results['file_size']} bytes",
            "Format: Compound Document",
        ))
        analyze_results.append(f"Version: {results['major_version']}.{results['minor_version']}")
        analyze_results.append(f"Sector Size: {results['sector_size']} bytes")

    elif binary_format == "COM":
        analyze_results.append(f"File Size: {results['file_size']} bytes (Max: 64KB)")
        analyze_results.append(f"Load Address: {results['load_address']}")
        analyze_results.append(f"Entropy: {results.get('entropy', 'N/A')}")

        if "first_instruction" in results["header_analysis"]:
            analyze_results.append(f"First Instruction: {results['header_analysis']['first_instruction']}")

    # Add recommendations based on format
    analyze_results.append("\nRecommendations:")
    if binary_format == "PE":
        analyze_results.extend((
            "- Use standard Windows PE analysis techniques",
            "- Check for high-entropy sections that may indicate packing or encryption",
        ))
    elif binary_format == "ELF":
        analyze_results.extend((
            "- Use specialized ELF analysis tools for deeper inspection",
            "- Consider using dynamic analysis with Linux-specific tools",
        ))
    elif binary_format == "MACHO":
        analyze_results.extend((
            "- Use macOS-specific analysis tools for deeper inspection",
            "- Check for code signing and entitlements",
        ))
    elif binary_format == "DEX":
        analyze_results.extend((
            "- Use Android-specific analysis tools like JADX or dex2jar",
            "- Consider using dynamic analysis with Android emulators",
        ))
    elif binary_format == "APK":
        analyze_results.extend(
            (
                "- Extract and analyze DEX files for code analysis",
                "- Check native libraries for potential security issues",
                "- Verify certificate signatures and permissions",
            )
        )
    elif binary_format == "JAR":
        analyze_results.extend(
            (
                "- Decompile class files for source code analysis",
                "- Check for dependency vulnerabilities",
                "- Verify manifest security attributes",
            )
        )
    elif binary_format == "MSI":
        analyze_results.extend(
            (
                "- Use specialized MSI analysis tools for full inspection",
                "- Check for custom actions and embedded scripts",
            )
        )
    elif binary_format == "COM":
        analyze_results.extend(
            (
                "- Use 16-bit disassemblers for code analysis",
                "- Consider DOS-era analysis techniques and tools",
            )
        )
    return results
