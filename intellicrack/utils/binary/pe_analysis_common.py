"""
This file is part of Intellicrack.
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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Common PE file analysis utilities.

This module consolidates PE parsing patterns to reduce code duplication.
"""

import io
import logging
import struct
from typing import Dict, List, Optional

from PIL import Image

logger = logging.getLogger(__name__)

def analyze_pe_imports(pe, target_apis: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """
    Analyze PE imports for specific API categories.

    Args:
        pe: PE file object
        target_apis: Dictionary mapping categories to API lists

    Returns:
        Dictionary mapping categories to detected APIs
    """
    from ..network_api_common import analyze_network_apis
    return analyze_network_apis(pe, target_apis)

def get_pe_sections_info(pe) -> List[Dict]:
    """
    Extract PE section information.

    Args:
        pe: PE file object

    Returns:
        List of section information dictionaries
    """
    sections = []

    for section in pe.sections:
        section_info = {
            "name": section.Name.decode("utf-8", errors="ignore").rstrip("\x00"),
            "virtual_address": section.VirtualAddress,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "characteristics": section.Characteristics
        }
        sections.append(section_info)

    return sections

def extract_pe_icon(pe_path: str, output_path: Optional[str] = None) -> Optional[Image.Image]:
    """
    Extract icon from PE file.

    Args:
        pe_path: Path to PE file
        output_path: Optional path to save extracted icon

    Returns:
        PIL Image object or None if no icon found
    """
    try:
        import pefile
        pe = pefile.PE(pe_path)

        # Find .rsrc section
        for section in pe.sections:
            if section.Name.startswith(b".rsrc\x00"):
                # Get resource directory
                if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                    icon_data = extract_icon_from_resources(pe)
                    if icon_data:
                        # Create PIL Image from icon data
                        icon_image = create_image_from_icon_data(icon_data)

                        if icon_image and output_path:
                            # Save the icon
                            icon_image.save(output_path, format="PNG")
                            logger.info(f"Icon extracted and saved to {output_path}")

                        return icon_image

        logger.debug("No icon resource found in PE file")
        return None

    except Exception as e:
        logger.error(f"Error extracting PE icon: {e}")
        return None

def extract_icon_from_resources(pe) -> Optional[bytes]:
    """
    Extract icon data from PE resources.

    Args:
        pe: pefile.PE object

    Returns:
        Icon data bytes or None
    """
    try:
        # RT_ICON = 3, RT_GROUP_ICON = 14
        RT_ICON = 3
        RT_GROUP_ICON = 14

        icon_groups = {}
        icons = {}

        # Extract icon groups and individual icons
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, "id"):
                if resource_type.id == RT_GROUP_ICON:
                    # Found icon group
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, "directory"):
                            for resource_lang in resource_id.directory.entries:
                                data_rva = resource_lang.data.struct.OffsetToData
                                size = resource_lang.data.struct.Size
                                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                                icon_groups[resource_id.id] = data

                elif resource_type.id == RT_ICON:
                    # Found individual icon
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, "directory"):
                            for resource_lang in resource_id.directory.entries:
                                data_rva = resource_lang.data.struct.OffsetToData
                                size = resource_lang.data.struct.Size
                                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                                icons[resource_id.id] = data

        # Parse icon group to find best icon
        if icon_groups:
            # Get first icon group
            group_id = list(icon_groups.keys())[0]
            group_data = icon_groups[group_id]

            # Parse GRPICONDIR structure
            # WORD idReserved, WORD idType, WORD idCount
            _, _, count = struct.unpack("<HHH", group_data[:6])

            best_icon_id = None
            best_size = 0

            # Find largest icon
            offset = 6
            for _i in range(count):
                if offset + 14 <= len(group_data):
                    # GRPICONDIRENTRY structure
                    width, height, colors, _, planes, bits, size, icon_id = struct.unpack(
                        "<BBBBHHIH", group_data[offset:offset+14]
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
                return icons[best_icon_id]

        return None

    except Exception as e:
        logger.error(f"Error extracting icon from resources: {e}")
        return None

def create_image_from_icon_data(icon_data: bytes) -> Optional[Image.Image]:
    """
    Create PIL Image from icon data.

    Args:
        icon_data: Raw icon data bytes

    Returns:
        PIL Image object or None
    """
    try:
        # Try to load as ICO format first
        try:
            icon_io = io.BytesIO(icon_data)
            return Image.open(icon_io)
        except:
            pass

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
                img = Image.open(bmp_io)

                # Crop to remove mask (bottom half)
                img = img.crop((0, 0, width, actual_height))

                return img

        # Try other formats
        for _fmt in ["PNG", "JPEG", "GIF"]:
            try:
                icon_io = io.BytesIO(icon_data)
                img = Image.open(icon_io)
                return img
            except:
                continue

        logger.debug("Could not parse icon data as any known format")
        return None

    except Exception as e:
        logger.error(f"Error creating image from icon data: {e}")
        return None

def extract_all_pe_icons(pe_path: str, output_dir: str) -> List[str]:
    """
    Extract all icons from PE file.

    Args:
        pe_path: Path to PE file
        output_dir: Directory to save extracted icons

    Returns:
        List of saved icon file paths
    """
    saved_icons = []

    try:
        import os

        import pefile

        pe = pefile.PE(pe_path)
        base_name = os.path.splitext(os.path.basename(pe_path))[0]

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Extract all icons
        RT_ICON = 3
        icon_index = 0

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, "id") and resource_type.id == RT_ICON:
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, "directory"):
                            for resource_lang in resource_id.directory.entries:
                                try:
                                    data_rva = resource_lang.data.struct.OffsetToData
                                    size = resource_lang.data.struct.Size
                                    icon_data = pe.get_memory_mapped_image()[data_rva:data_rva+size]

                                    # Create image from icon data
                                    icon_image = create_image_from_icon_data(icon_data)
                                    if icon_image:
                                        # Save icon
                                        icon_path = os.path.join(output_dir, f"{base_name}_icon_{icon_index}.png")
                                        icon_image.save(icon_path, format="PNG")
                                        saved_icons.append(icon_path)
                                        icon_index += 1
                                        logger.info(f"Extracted icon: {icon_path}")
                                except Exception as e:
                                    logger.error(f"Error extracting icon {icon_index}: {e}")

        if not saved_icons:
            logger.info("No icons found in PE file")
        else:
            logger.info(f"Extracted {len(saved_icons)} icons from PE file")

        return saved_icons

    except Exception as e:
        logger.error(f"Error extracting all PE icons: {e}")
        return saved_icons

def get_pe_icon_info(pe_path: str) -> Dict[str, any]:
    """
    Get information about icons in PE file.

    Args:
        pe_path: Path to PE file

    Returns:
        Dictionary with icon information
    """
    icon_info = {
        "has_icon": False,
        "icon_count": 0,
        "icon_groups": 0,
        "icon_sizes": [],
        "largest_icon": None
    }

    try:
        import pefile
        pe = pefile.PE(pe_path)

        RT_ICON = 3
        RT_GROUP_ICON = 14

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            icon_count = 0
            group_count = 0
            icon_sizes = []

            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, "id"):
                    if resource_type.id == RT_ICON:
                        # Count individual icons
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, "directory"):
                                icon_count += len(resource_id.directory.entries)

                                # Get icon sizes
                                for resource_lang in resource_id.directory.entries:
                                    size = resource_lang.data.struct.Size
                                    icon_sizes.append(size)

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
                        "size_kb": max(icon_sizes) / 1024
                    }

        return icon_info

    except Exception as e:
        logger.error(f"Error getting PE icon info: {e}")
        return icon_info
