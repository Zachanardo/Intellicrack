"""Patching utilities for the Intellicrack framework.

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
import re
import shutil
import time
from pathlib import Path
from typing import Any


# Module logger
logger = logging.getLogger(__name__)

try:
    from intellicrack.handlers.pefile_handler import pefile
except ImportError as e:
    logger.error("Import error in patch_utils: %s", e)
    pefile = None


def parse_patch_instructions(text: str) -> list[dict[str, Any]]:
    """Parse patch instructions from AI-generated or formatted text.

    Handles variations in formatting and logs skipped lines.
    Expected format: "Address: 0x12345 NewBytes: 90 90 90 // Comment"

    Args:
        text: Text containing patch instructions

    Returns:
        list: Patch instructions with address (int), new_bytes (bytes), and description (str)

    """
    instructions = []

    # Regex to find lines with Address and NewBytes
    pattern = re.compile(
        r"^\s*Address:\s*(?:0x)?([0-9A-Fa-f]+)\s*NewBytes:\s*([0-9A-Fa-f\s]+)(?:\s*//\s*(.*))?$",
        re.IGNORECASE | re.MULTILINE,
    )

    logger.info("Parsing patch instructions from text...")
    lines_processed = 0
    potential_matches = 0

    for match in pattern.finditer(text):
        lines_processed += 1
        potential_matches += 1
        address_hex = match.group(1)
        new_bytes_hex_raw = match.group(2)
        description = match.group(3).strip() if match.group(3) else "Patch"

        # Clean up hex bytes string (remove spaces)
        new_bytes_hex = "".join(new_bytes_hex_raw.split())

        # Validate and convert
        try:
            # Ensure hex bytes string has an even number of characters
            if len(new_bytes_hex) % 2 != 0:
                logger.warning(
                    f"Skipped line {lines_processed}: Odd number of hex characters: '{new_bytes_hex_raw}'",
                )
                continue

            address = int(address_hex, 16)
            new_bytes = bytes.fromhex(new_bytes_hex)

            if not new_bytes:
                logger.warning(
                    f"Skipped line {lines_processed}: Empty byte string for '{new_bytes_hex_raw}'",
                )
                continue

            instructions.append(
                {
                    "address": address,
                    "new_bytes": new_bytes,
                    "description": description,
                },
            )
            logger.info(
                f"Parsed instruction: Address=0x{address:X}, Bytes='{new_bytes.hex().upper()}', Desc='{description}'",
            )

        except ValueError as e:
            logger.warning(
                f"Skipped line {lines_processed}: Error parsing hex values: "
                f"Address='{address_hex}', Bytes='{new_bytes_hex_raw}'. Error: {e}",
            )
        except (OSError, RuntimeError) as e:
            logger.error("Unexpected error parsing line %s: %s", lines_processed, e)

    # Log summary
    if not potential_matches:
        logger.warning("No lines matching patch format were found")
    else:
        logger.info(
            f"Found {len(instructions)} valid patch instruction(s) out of {potential_matches} potential matches",
        )

    return instructions


def create_patch(original_data: bytes, modified_data: bytes, base_address: int = 0) -> list[dict[str, Any]]:
    """Create patch instructions by comparing original and modified data.

    Args:
        original_data: Original binary data
        modified_data: Modified binary data
        base_address: Base address for patch offsets

    Returns:
        list: Patch instructions for the differences

    """
    patches = []

    if len(original_data) != len(modified_data):
        logger.warning("Data lengths differ - comparison may be incomplete")

    i = 0
    while i < min(len(original_data), len(modified_data)):
        if original_data[i] != modified_data[i]:
            # Found difference, collect consecutive changed bytes
            start = i
            changed_bytes = bytearray()

            while i < min(len(original_data), len(modified_data)) and original_data[i] != modified_data[i]:
                changed_bytes.append(modified_data[i])
                i += 1

            patches.append(
                {
                    "address": base_address + start,
                    "new_bytes": bytes(changed_bytes),
                    "description": f"Patch at offset 0x{start:X}",
                },
            )
        else:
            i += 1

    logger.info(f"Created {len(patches)} patch(es) from data comparison")
    return patches


def apply_patch(file_path: str | Path, patches: list[dict[str, Any]], create_backup: bool = True) -> tuple[bool, str | None]:
    """Apply patches to a binary file.

    Args:
        file_path: Path to the file to patch
        patches: List of patch instructions
        create_backup: Whether to create a backup

    Returns:
        tuple: (success, patched_file_path)

    """
    file_path = Path(file_path)

    if not file_path.exists():
        logger.error("File not found: %s", file_path)
        return False, None

    if not patches:
        logger.warning("No patches to apply")
        return False, None

    # Create backup if requested
    if create_backup:
        backup_path = file_path.with_suffix(f"{file_path.suffix}.backup_{int(time.time())}")
        try:
            shutil.copy2(file_path, backup_path)
            logger.info("Created backup: %s", backup_path)
        except OSError as e:
            logger.error("Failed to create backup: %s", e)
            return False, None

    # Create patched file
    patched_path = file_path.with_stem(f"{file_path.stem}_patched")

    try:
        # Copy original to patched path
        shutil.copy2(file_path, patched_path)

        # Apply patches
        with open(patched_path, "r+b") as f:
            applied_count = 0

            for i, patch in enumerate(patches):
                address = patch.get("address", 0)
                new_bytes = patch.get("new_bytes", b"")
                description = patch.get("description", "")

                if not new_bytes:
                    logger.warning(f"Patch {i + 1}: No bytes to write")
                    continue

                try:
                    f.seek(address)
                    f.write(new_bytes)
                    applied_count += 1
                    logger.info(
                        f"Applied patch {i + 1}: {len(new_bytes)} bytes at 0x{address:X} - {description}",
                    )
                except (OSError, ValueError, RuntimeError) as e:
                    logger.error(f"Failed to apply patch {i + 1}: {e}")

        if applied_count > 0:
            logger.info("Successfully applied %s patches to %s", applied_count, patched_path)
            return True, str(patched_path)
        logger.warning("No patches were applied")
        # Clean up unused file
        patched_path.unlink(missing_ok=True)
        return False, None

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error during patching: %s", e)
        # Clean up on error
        if patched_path.exists():
            patched_path.unlink(missing_ok=True)
        return False, None


def validate_patch(file_path: str | Path, patches: list[dict[str, Any]]) -> bool:
    """Validate that patches have been correctly applied.

    Args:
        file_path: Path to the patched file
        patches: List of patches that should have been applied

    Returns:
        bool: True if all patches are validated

    """
    file_path = Path(file_path)

    if not file_path.exists():
        logger.error("File not found for validation: %s", file_path)
        return False

    try:
        with open(file_path, "rb") as f:
            for i, patch in enumerate(patches):
                address = patch.get("address", 0)
                expected_bytes = patch.get("new_bytes", b"")

                f.seek(address)
                actual_bytes = f.read(len(expected_bytes))

                if actual_bytes != expected_bytes:
                    logger.error(
                        f"Patch {i + 1} validation failed at 0x{address:X}: Expected {expected_bytes.hex()}, got {actual_bytes.hex()}",
                    )
                    return False
                logger.debug(f"Patch {i + 1} validated successfully")

        logger.info("All patches validated successfully")
        return True

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error during patch validation: %s", e)
        return False


def convert_rva_to_offset(file_path: str | Path, rva: int) -> int | None:
    """Convert RVA (Relative Virtual Address) to file offset for PE files.

    Args:
        file_path: Path to PE file
        rva: Relative Virtual Address

    Returns:
        Optional[int]: File offset, or None if conversion fails

    """
    if pefile is None:
        logger.error("pefile module not available")
        return None

    try:
        pe = pefile.PE(str(file_path))
        offset = pe.get_offset_from_rva(rva)
        pe.close()
        return offset
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error converting RVA to offset: %s", e)
        return None


def get_section_info(file_path: str | Path) -> list[dict[str, Any]]:
    """Get section information from a PE file.

    Args:
        file_path: Path to PE file

    Returns:
        list: Section information including names, addresses, and sizes

    """
    if pefile is None:
        logger.error("pefile module not available")
        return []

    sections = []

    try:
        pe = pefile.PE(str(file_path))

        for section in pe.sections:
            section_info = {
                "name": section.Name.decode("utf-8", "ignore").strip("\x00"),
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_address": section.PointerToRawData,
                "raw_size": section.SizeOfRawData,
                "characteristics": section.Characteristics,
            }
            sections.append(section_info)

        pe.close()

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error reading section info: %s", e)

    return sections


def create_nop_patch(address: int, length: int, arch: str = "x86") -> dict[str, Any]:
    """Create a NOP (No Operation) patch of specified length.

    Args:
        address: Address to patch
        length: Number of bytes to NOP
        arch: Architecture (x86, x64, arm, etc.)

    Returns:
        dict: Patch instruction with NOP bytes

    """
    nop_bytes = {
        "x86": b"\x90",  # NOP
        "x64": b"\x90",  # NOP (same as x86)
        "arm": b"\x00\xbf",  # NOP (Thumb)
        "arm64": b"\x1f\x20\x03\xd5",  # NOP
    }

    nop = nop_bytes.get(arch.lower(), b"\x90")

    nop_count, remainder = divmod(length, len(nop))
    if remainder != 0:
        logger.warning(
            f"Length {length} not divisible by NOP size {len(nop)} for {arch}. Padding with {remainder} extra bytes.",
        )

    return {
        "address": address,
        "new_bytes": nop * nop_count + nop[:remainder],
        "description": f"NOP patch ({length} bytes)",
    }


# Exported functions
__all__ = [
    "apply_patch",
    "convert_rva_to_offset",
    "create_nop_patch",
    "create_patch",
    "get_section_info",
    "parse_patch_instructions",
    "validate_patch",
]
