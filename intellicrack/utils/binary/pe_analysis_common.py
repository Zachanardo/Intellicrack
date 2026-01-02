"""PE analysis common utilities for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

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

Common PE file analysis utilities.

This module consolidates PE parsing patterns to reduce code duplication.
"""

import io
import logging
import struct
from typing import TYPE_CHECKING, Any

from PIL import Image


if TYPE_CHECKING:
    from PIL.ImageFile import ImageFile


logger = logging.getLogger(__name__)


def analyze_pe_imports(pe: Any, target_apis: dict[str, list[str]]) -> dict[str, list[str]]:
    """Analyze PE imports for specific API categories.

    Args:
        pe: pefile.PE object from pefile library representing the PE file
        target_apis: Dictionary mapping categories to API lists

    Returns:
        Dictionary mapping categories to detected APIs in the PE file.

    """
    from ..network_api_common import analyze_network_apis

    result: dict[str, list[str]] = analyze_network_apis(pe, target_apis)
    return result


def get_pe_sections_info(pe: Any) -> list[dict[str, Any]]:
    """Extract PE section information.

    Args:
        pe: pefile.PE object from pefile library representing the PE file

    Returns:
        List of section information dictionaries with name, addresses, and characteristics.

    """
    sections: list[dict[str, Any]] = []

    for section in pe.sections:
        section_info: dict[str, Any] = {
            "name": section.Name.decode("utf-8", errors="ignore").rstrip("\x00"),
            "virtual_address": section.VirtualAddress,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "characteristics": section.Characteristics,
        }
        sections.append(section_info)

    return sections


def extract_pe_icon(pe_path: str, output_path: str | None = None) -> Image.Image | None:
    """Extract icon from PE file.

    Args:
        pe_path: Path to PE file
        output_path: Optional path to save extracted icon

    Returns:
        PIL Image object if icon found, None otherwise.

    """
    try:
        from intellicrack.handlers.pefile_handler import pefile

        pe = pefile.PE(pe_path)

        # Find .rsrc section
        for section in pe.sections:
            if section.Name.startswith(b".rsrc\x00") and hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                if icon_data := extract_icon_from_resources(pe):
                    # Create PIL Image from icon data
                    icon_image = create_image_from_icon_data(icon_data)

                    if icon_image and output_path:
                        # Save the icon
                        icon_image.save(output_path, format="PNG")
                        logger.info("Icon extracted and saved to %s", output_path)

                    return icon_image

        logger.debug("No icon resource found in PE file")
        return None

    except Exception as e:
        logger.exception("Error extracting PE icon: %s", e, exc_info=True)
        return None


def extract_icon_from_resources(pe: Any) -> bytes | None:
    """Extract icon data from PE resources.

    Args:
        pe: pefile.PE object representing the PE file

    Returns:
        Icon data bytes if found, None otherwise.

    """
    try:
        icon_groups: dict[int, bytes] = {}
        icons: dict[int, bytes] = {}

        # Extract icon groups and individual icons
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            # RT_ICON = 3, RT_GROUP_ICON = 14
            RT_ICON = 3
            RT_GROUP_ICON = 14

            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, "id"):
                    for resource_id in resource_type.directory.entries:
                        if resource_type.id == RT_GROUP_ICON:
                            if hasattr(resource_id, "directory"):
                                for resource_lang in resource_id.directory.entries:
                                    data_rva = resource_lang.data.struct.OffsetToData
                                    size = resource_lang.data.struct.Size
                                    memory_image: bytes = pe.get_memory_mapped_image()
                                    data: bytes = memory_image[data_rva : data_rva + size]
                                    icon_groups[resource_id.id] = data

                        elif resource_type.id == RT_ICON:
                            if hasattr(resource_id, "directory"):
                                for resource_lang in resource_id.directory.entries:
                                    data_rva = resource_lang.data.struct.OffsetToData
                                    size = resource_lang.data.struct.Size
                                    memory_image = pe.get_memory_mapped_image()
                                    data = memory_image[data_rva : data_rva + size]
                                    icons[resource_id.id] = data

        # Parse icon group to find best icon
        if icon_groups:
            # Get first icon group
            group_id = next(iter(icon_groups.keys()))
            group_data = icon_groups[group_id]

            # Parse GRPICONDIR structure
            # WORD idReserved, WORD idType, WORD idCount
            _, _, count = struct.unpack("<HHH", group_data[:6])

            best_icon_id: int | None = None
            best_size = 0

            # Find largest icon
            offset = 6
            for _i in range(count):
                if offset + 14 <= len(group_data):
                    # GRPICONDIRENTRY structure
                    width, height, _colors, _, _planes, _bits, size, icon_id = struct.unpack(
                        "<BBBBHHIH",
                        group_data[offset : offset + 14],
                    )
                    offset += 14

                    # Calculate actual dimensions (0 means 256)
                    actual_width = width if width != 0 else 256
                    actual_height = height if height != 0 else 256
                    actual_size = actual_width * actual_height

                    if actual_size > best_size and icon_id in icons:
                        best_size = actual_size
                        best_icon_id = icon_id

            if best_icon_id and best_icon_id in icons:
                result: bytes = icons[best_icon_id]
                return result

        return None

    except Exception as e:
        logger.exception("Error extracting icon from resources: %s", e, exc_info=True)
        return None


def create_image_from_icon_data(icon_data: bytes) -> Image.Image | None:
    """Create PIL Image from icon data.

    Args:
        icon_data: Raw icon data bytes

    Returns:
        PIL Image object if successfully created, None otherwise.

    """
    try:
        # Try to load as ICO format first
        try:
            icon_io = io.BytesIO(icon_data)
            return Image.open(icon_io)
        except Exception as e:
            logger.debug("Error parsing icon as image: %s", e)

        # If that fails, try parsing as DIB (BMP without header)
        if len(icon_data) >= 40:
            # Check if it's a BITMAPINFOHEADER
            header_size = struct.unpack("<I", icon_data[:4])[0]
            if header_size == 40:  # BITMAPINFOHEADER
                width, height = struct.unpack("<ii", icon_data[4:12])

                # Icons are stored bottom-up, height is doubled for mask
                actual_height = abs(height) // 2

                # Create BMP header
                bmp_header = b"BM"
                bmp_header += struct.pack("<I", len(icon_data) + 14)  # File size
                bmp_header += b"\x00\x00\x00\x00"  # Reserved
                bmp_header += struct.pack("<I", 14 + header_size)  # Offset to pixel data

                # Combine header with DIB data
                bmp_data = bmp_header + icon_data

                # Load as BMP
                bmp_io = io.BytesIO(bmp_data)
                img_opened: ImageFile = Image.open(bmp_io)

                # Crop to remove mask (bottom half)
                img: Image.Image = img_opened.crop((0, 0, width, actual_height))

                return img

        # Try other formats
        for _fmt in ["PNG", "JPEG", "GIF"]:
            try:
                icon_io = io.BytesIO(icon_data)
                img_result: ImageFile = Image.open(icon_io)
                return img_result
            except Exception as e:
                logger.debug("Failed to parse icon data as image format: %s", e)
                continue

        logger.debug("Could not parse icon data as any known format")
        return None

    except Exception as e:
        logger.exception("Error creating image from icon data: %s", e, exc_info=True)
        return None


def extract_all_pe_icons(pe_path: str, output_dir: str) -> list[str]:
    """Extract all icons from PE file.

    Args:
        pe_path: Path to PE file
        output_dir: Directory to save extracted icons

    Returns:
        List of file paths where icons were saved.

    """
    saved_icons = []

    try:
        import os

        from intellicrack.handlers.pefile_handler import pefile

        pe = pefile.PE(pe_path)
        base_name = os.path.splitext(os.path.basename(pe_path))[0]

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            # Extract all icons
            RT_ICON = 3
            icon_index = 0

            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, "id") and resource_type.id == RT_ICON:
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, "directory"):
                            for resource_lang in resource_id.directory.entries:
                                try:
                                    data_rva = resource_lang.data.struct.OffsetToData
                                    size = resource_lang.data.struct.Size
                                    icon_data = pe.get_memory_mapped_image()[data_rva : data_rva + size]

                                    if icon_image := create_image_from_icon_data(icon_data):
                                        # Save icon
                                        icon_path = os.path.join(output_dir, f"{base_name}_icon_{icon_index}.png")
                                        icon_image.save(icon_path, format="PNG")
                                        saved_icons.append(icon_path)
                                        icon_index += 1
                                        logger.info("Extracted icon: %s", icon_path)
                                except Exception as e:
                                    logger.exception("Error extracting icon %s: %s", icon_index, e, exc_info=True)

        if not saved_icons:
            logger.info("No icons found in PE file")
        else:
            logger.info("Extracted %s icons from PE file", len(saved_icons))

        return saved_icons

    except Exception as e:
        logger.exception("Error extracting all PE icons: %s", e, exc_info=True)
        return saved_icons


def get_pe_icon_info(pe_path: str) -> dict[str, Any]:
    """Get information about icons in PE file.

    Args:
        pe_path: Path to PE file

    Returns:
        Dictionary containing icon count, sizes, and metadata.

    """
    icon_info: dict[str, Any] = {
        "has_icon": False,
        "icon_count": 0,
        "icon_groups": 0,
        "icon_sizes": [],
        "largest_icon": None,
    }

    try:
        from intellicrack.handlers.pefile_handler import pefile

        pe = pefile.PE(pe_path)

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            icon_count = 0
            group_count = 0
            icon_sizes: list[int] = []

            RT_ICON = 3
            RT_GROUP_ICON = 14

            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, "id"):
                    if resource_type.id == RT_ICON:
                        # Count individual icons
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, "directory"):
                                icon_count += len(resource_id.directory.entries)

                                # Get icon sizes
                                icon_sizes.extend(resource_lang.data.struct.Size for resource_lang in resource_id.directory.entries)
                    elif resource_type.id == RT_GROUP_ICON:
                        # Count icon groups
                        group_count += len(resource_type.directory.entries)

            if icon_count > 0:
                icon_info["has_icon"] = True
                icon_info["icon_count"] = icon_count
                icon_info["icon_groups"] = group_count
                icon_info["icon_sizes"] = sorted(icon_sizes)
                if icon_sizes:
                    icon_info["largest_icon"] = {
                        "size": max(icon_sizes),
                        "size_kb": max(icon_sizes) / 1024,
                    }

        return icon_info

    except Exception as e:
        logger.exception("Error getting PE icon info: %s", e, exc_info=True)
        return icon_info


class PEAnalyzer:
    """Production-ready PE file analyzer for comprehensive binary analysis."""

    def __init__(self) -> None:
        """Initialize PE analyzer with logger instance."""
        self.logger = logger

    def analyze(self, file_path: str) -> dict[str, Any]:
        """Analyze PE file and extract comprehensive metadata.

        Args:
            file_path: Path to PE file to analyze

        Returns:
            Dictionary containing PE analysis results including imports, exports, sections, and headers.

        """
        try:
            from intellicrack.handlers.pefile_handler import pefile

            pe = pefile.PE(file_path)

            return {
                "imports": self._extract_imports(pe),
                "exports": self._extract_exports(pe),
                "sections": get_pe_sections_info(pe),
                "headers": self._extract_headers(pe),
                "resources": self._extract_resources(pe),
                "certificates": self._extract_certificates(pe),
                "icon_info": get_pe_icon_info(file_path),
                "architecture": self._get_architecture(pe),
                "compilation_timestamp": pe.FILE_HEADER.TimeDateStamp,
                "is_dll": pe.is_dll(),
                "is_exe": pe.is_exe(),
                "checksum": pe.OPTIONAL_HEADER.CheckSum,
                "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            }
        except Exception as e:
            self.logger.exception("PE analysis failed for %s: %s", file_path, e, exc_info=True)
            return {"error": str(e)}

    def _extract_imports(self, pe: Any) -> list[dict[str, Any]]:
        """Extract import information from PE file.

        Args:
            pe: pefile.PE object representing the PE file

        Returns:
            List of dictionaries containing DLL names and imported function details.

        """
        imports: list[dict[str, Any]] = []

        try:
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                    functions: list[dict[str, Any]] = [
                        {
                            "name": imp.name.decode("utf-8", errors="ignore"),
                            "address": imp.address,
                            "ordinal": imp.ordinal,
                        }
                        for imp in entry.imports
                        if imp.name
                    ]
                    imports.append({"dll": dll_name, "functions": functions})
        except Exception as e:
            self.logger.debug("Import extraction failed: %s", e)

        return imports

    def _extract_exports(self, pe: Any) -> list[dict[str, Any]]:
        """Extract export information from PE file.

        Args:
            pe: pefile.PE object representing the PE file

        Returns:
            List of dictionaries containing exported function names, addresses, and ordinals.

        """
        exports: list[dict[str, Any]] = []

        try:
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                export_list: list[dict[str, Any]] = [
                    {
                        "name": (exp.name.decode("utf-8", errors="ignore") if exp.name else None),
                        "address": exp.address,
                        "ordinal": exp.ordinal,
                    }
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols
                ]
                exports.extend(export_list)
        except Exception as e:
            self.logger.debug("Export extraction failed: %s", e)

        return exports

    def _extract_headers(self, pe: Any) -> dict[str, Any]:
        """Extract PE header information.

        Args:
            pe: pefile.PE object representing the PE file

        Returns:
            Dictionary containing DOS, file, and optional header data.

        """
        headers: dict[str, Any] = {}

        try:
            if hasattr(pe, "DOS_HEADER"):
                headers["dos_header"] = {
                    "signature": pe.DOS_HEADER.e_magic,
                    "bytes_in_last_page": pe.DOS_HEADER.e_cblp,
                    "pages_in_file": pe.DOS_HEADER.e_cp,
                }

            if hasattr(pe, "FILE_HEADER"):
                headers["file_header"] = {
                    "machine": pe.FILE_HEADER.Machine,
                    "number_of_sections": pe.FILE_HEADER.NumberOfSections,
                    "timestamp": pe.FILE_HEADER.TimeDateStamp,
                    "characteristics": pe.FILE_HEADER.Characteristics,
                }

            if hasattr(pe, "OPTIONAL_HEADER"):
                headers["optional_header"] = {
                    "magic": pe.OPTIONAL_HEADER.Magic,
                    "major_linker_version": pe.OPTIONAL_HEADER.MajorLinkerVersion,
                    "minor_linker_version": pe.OPTIONAL_HEADER.MinorLinkerVersion,
                    "size_of_code": pe.OPTIONAL_HEADER.SizeOfCode,
                    "size_of_initialized_data": pe.OPTIONAL_HEADER.SizeOfInitializedData,
                    "address_of_entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                    "image_base": pe.OPTIONAL_HEADER.ImageBase,
                    "section_alignment": pe.OPTIONAL_HEADER.SectionAlignment,
                    "file_alignment": pe.OPTIONAL_HEADER.FileAlignment,
                }
        except Exception as e:
            self.logger.debug("Header extraction failed: %s", e)

        return headers

    def _extract_resources(self, pe: Any) -> dict[str, Any]:
        """Extract resource information from PE file.

        Args:
            pe: pefile.PE object representing the PE file

        Returns:
            Dictionary containing resource types, counts, and metadata.

        """
        resources: dict[str, Any] = {"has_resources": False, "resource_types": [], "total_resources": 0}

        try:
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                resources["has_resources"] = True
                resource_type_list: list[dict[str, Any]] = []

                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, "id"):
                        resource_type_list.append({
                            "type_id": resource_type.id,
                            "name": resource_type.name if hasattr(resource_type, "name") else None,
                        })
                        total_count: int = resources["total_resources"]
                        resources["total_resources"] = total_count + 1

                resources["resource_types"] = resource_type_list
        except Exception as e:
            self.logger.debug("Resource extraction failed: %s", e)

        return resources

    def _extract_certificates(self, pe: Any) -> dict[str, Any]:
        """Extract certificate information from PE file.

        Args:
            pe: pefile.PE object representing the PE file

        Returns:
            Dictionary containing certificate presence flag and count.

        """
        certs: dict[str, Any] = {"has_certificates": False, "certificate_count": 0}

        try:
            if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
                certs["has_certificates"] = True
                certs["certificate_count"] = len(pe.DIRECTORY_ENTRY_SECURITY)
        except Exception as e:
            self.logger.debug("Certificate extraction failed: %s", e)

        return certs

    def _get_architecture(self, pe: Any) -> str:
        """Determine PE file architecture.

        Args:
            pe: pefile.PE object representing the PE file

        Returns:
            String representation of the PE file architecture.

        """
        try:
            if hasattr(pe, "FILE_HEADER"):
                machine_type: int = pe.FILE_HEADER.Machine
                architecture_map: dict[int, str] = {
                    0x014C: "x86",  # IMAGE_FILE_MACHINE_I386
                    0x8664: "x64",  # IMAGE_FILE_MACHINE_AMD64
                    0x01C0: "ARM",  # IMAGE_FILE_MACHINE_ARM
                    0xAA64: "ARM64",  # IMAGE_FILE_MACHINE_ARM64
                }
                return architecture_map.get(machine_type, f"Unknown (0x{machine_type:04x})")
            return "Unknown"
        except Exception as e:
            self.logger.debug("Architecture detection failed: %s", e)
            return "Unknown"
