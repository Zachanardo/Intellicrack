"""
Patching utilities for the Intellicrack framework.

This module provides utilities for binary patching including parsing patch instructions,
applying patches, creating backups, and validating patches.
"""

import logging
import re
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    import pefile
except ImportError:
    pefile = None

# Module logger
logger = logging.getLogger(__name__)


def parse_patch_instructions(text: str) -> List[Dict[str, Any]]:
    """
    Parse patch instructions from AI-generated or formatted text.

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
        re.IGNORECASE | re.MULTILINE
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
                    f"Skipped line {lines_processed}: Odd number of hex characters: '{new_bytes_hex_raw}'"
                )
                continue

            address = int(address_hex, 16)
            new_bytes = bytes.fromhex(new_bytes_hex)

            if not new_bytes:
                logger.warning(
                    f"Skipped line {lines_processed}: Empty byte string for '{new_bytes_hex_raw}'"
                )
                continue

            instructions.append({
                "address": address,
                "new_bytes": new_bytes,
                "description": description
            })
            logger.info(
                f"Parsed instruction: Address=0x{address:X}, "
                f"Bytes='{new_bytes.hex().upper()}', Desc='{description}'"
            )

        except ValueError as e:
            logger.warning(
                f"Skipped line {lines_processed}: Error parsing hex values: "
                f"Address='{address_hex}', Bytes='{new_bytes_hex_raw}'. Error: {e}"
            )
        except Exception as e:
            logger.error(f"Unexpected error parsing line {lines_processed}: {e}")

    # Log summary
    if not potential_matches:
        logger.warning("No lines matching patch format were found")
    else:
        logger.info(
            f"Found {len(instructions)} valid patch instruction(s) "
            f"out of {potential_matches} potential matches"
        )

    return instructions


def create_patch(original_data: bytes, modified_data: bytes,
                 base_address: int = 0) -> List[Dict[str, Any]]:
    """
    Create patch instructions by comparing original and modified data.

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

            while i < min(len(original_data), len(modified_data)) and \
                  original_data[i] != modified_data[i]:
                changed_bytes.append(modified_data[i])
                i += 1

            patches.append({
                "address": base_address + start,
                "new_bytes": bytes(changed_bytes),
                "description": f"Patch at offset 0x{start:X}"
            })
        else:
            i += 1

    logger.info(f"Created {len(patches)} patch(es) from data comparison")
    return patches


def apply_patch(file_path: Union[str, Path], patches: List[Dict[str, Any]],
                create_backup: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Apply patches to a binary file.

    Args:
        file_path: Path to the file to patch
        patches: List of patch instructions
        create_backup: Whether to create a backup

    Returns:
        tuple: (success, patched_file_path)
    """
    file_path = Path(file_path)

    if not file_path.exists():
        logger.error(f"File not found: {file_path}")
        return False, None

    if not patches:
        logger.warning("No patches to apply")
        return False, None

    # Create backup if requested
    if create_backup:
        backup_path = file_path.with_suffix(file_path.suffix + f".backup_{int(time.time())}")
        try:
            shutil.copy2(file_path, backup_path)
            logger.info(f"Created backup: {backup_path}")
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            return False, None

    # Create patched file
    patched_path = file_path.with_stem(file_path.stem + "_patched")

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
                    logger.warning(f"Patch {i+1}: No bytes to write")
                    continue

                try:
                    f.seek(address)
                    f.write(new_bytes)
                    applied_count += 1
                    logger.info(
                        f"Applied patch {i+1}: {len(new_bytes)} bytes "
                        f"at 0x{address:X} - {description}"
                    )
                except Exception as e:
                    logger.error(f"Failed to apply patch {i+1}: {e}")

        if applied_count > 0:
            logger.info(f"Successfully applied {applied_count} patches to {patched_path}")
            return True, str(patched_path)
        else:
            logger.warning("No patches were applied")
            # Clean up unused file
            patched_path.unlink(missing_ok=True)
            return False, None

    except Exception as e:
        logger.error(f"Error during patching: {e}")
        # Clean up on error
        if patched_path.exists():
            patched_path.unlink(missing_ok=True)
        return False, None


def validate_patch(file_path: Union[str, Path], patches: List[Dict[str, Any]]) -> bool:
    """
    Validate that patches have been correctly applied.

    Args:
        file_path: Path to the patched file
        patches: List of patches that should have been applied

    Returns:
        bool: True if all patches are validated
    """
    file_path = Path(file_path)

    if not file_path.exists():
        logger.error(f"File not found for validation: {file_path}")
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
                        f"Patch {i+1} validation failed at 0x{address:X}: "
                        f"Expected {expected_bytes.hex()}, got {actual_bytes.hex()}"
                    )
                    return False
                else:
                    logger.debug(f"Patch {i+1} validated successfully")

        logger.info("All patches validated successfully")
        return True

    except Exception as e:
        logger.error(f"Error during patch validation: {e}")
        return False


def convert_rva_to_offset(file_path: Union[str, Path], rva: int) -> Optional[int]:
    """
    Convert RVA (Relative Virtual Address) to file offset for PE files.

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
    except Exception as e:
        logger.error(f"Error converting RVA to offset: {e}")
        return None


def get_section_info(file_path: Union[str, Path]) -> List[Dict[str, Any]]:
    """
    Get section information from a PE file.

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
                'name': section.Name.decode('utf-8', 'ignore').strip('\x00'),
                'virtual_address': section.VirtualAddress,
                'virtual_size': section.Misc_VirtualSize,
                'raw_address': section.PointerToRawData,
                'raw_size': section.SizeOfRawData,
                'characteristics': section.Characteristics
            }
            sections.append(section_info)

        pe.close()

    except Exception as e:
        logger.error(f"Error reading section info: {e}")

    return sections


def create_nop_patch(address: int, length: int, arch: str = "x86") -> Dict[str, Any]:
    """
    Create a NOP (No Operation) patch of specified length.

    Args:
        address: Address to patch
        length: Number of bytes to NOP
        arch: Architecture (x86, x64, arm, etc.)

    Returns:
        dict: Patch instruction with NOP bytes
    """
    nop_bytes = {
        "x86": b"\x90",      # NOP
        "x64": b"\x90",      # NOP (same as x86)
        "arm": b"\x00\xBF",  # NOP (Thumb)
        "arm64": b"\x1F\x20\x03\xD5"  # NOP
    }

    nop = nop_bytes.get(arch.lower(), b"\x90")

    # Calculate how many NOPs we need
    nop_count = length // len(nop)
    remainder = length % len(nop)

    if remainder != 0:
        logger.warning(
            f"Length {length} not divisible by NOP size {len(nop)} for {arch}. "
            f"Padding with {remainder} extra bytes."
        )

    return {
        "address": address,
        "new_bytes": nop * nop_count + nop[:remainder],
        "description": f"NOP patch ({length} bytes)"
    }


# Exported functions
__all__ = [
    'parse_patch_instructions',
    'create_patch',
    'apply_patch',
    'validate_patch',
    'convert_rva_to_offset',
    'get_section_info',
    'create_nop_patch',
]
