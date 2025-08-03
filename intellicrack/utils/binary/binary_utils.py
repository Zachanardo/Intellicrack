"""
Binary file utilities for the Intellicrack framework.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import hashlib
import logging
import os
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Union

# Module logger
logger = logging.getLogger(__name__)


def compute_file_hash(file_path: Union[str, Path], algorithm: str = "sha256",
                     progress_signal: Optional[Callable[[int], None]] = None) -> str:
    """
    Computes the hash of a file using the specified algorithm with optional progress updates.

    Calculates the cryptographic hash of the specified file using the given algorithm, reading it
    in chunks to handle large files efficiently. Can provide progress updates
    through a signal mechanism for _UI integration.

    Args:
        file_path: Path to the file to hash
        algorithm: The hashing algorithm to use (e.g., 'sha256', 'md5'). Defaults to 'sha256'.
        progress_signal: Optional signal to emit progress updates (0-100%)

    Returns:
        str: Hexadecimal representation of the computed hash, empty string on error
    """
    try:
        hasher = hashlib.new(algorithm.lower())
        file_size = os.path.getsize(file_path)
        chunk_size = 4096 * 1024  # 4MB chunks
        processed = 0

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hasher.update(chunk)
                processed += len(chunk)
                if progress_signal and file_size > 0:
                    progress_percent = int((processed / file_size) * 100)
                    # Handle both signal objects and function callbacks
                    if hasattr(progress_signal, "emit"):
                        # If it's a signal object with emit method
                        progress_signal.emit(progress_percent)
                    else:
                        # If it's a function callback
                        progress_signal(progress_percent)

        return hasher.hexdigest()
    except (OSError, ValueError, RuntimeError) as e:
        error_message = f"Error computing hash for {file_path} with algorithm {algorithm}: {e}"
        error_type = type(e).__name__

        # Add more context to the error message
        if isinstance(e, FileNotFoundError):
            error_message = f"File not found when computing hash: {file_path}"
        elif isinstance(e, PermissionError):
            error_message = f"Permission denied when computing hash: {file_path}"
        elif isinstance(e, IOError):
            error_message = f"IO Error when computing hash: {file_path} - {str(e)}"
        elif isinstance(e, ValueError) and "unsupported hash type" in str(e).lower():
            error_message = f"Unsupported hash algorithm '{algorithm}': {e}"

        # Log the exception
        logger.exception(f"{error_type} - {error_message}")

        # Include traceback information for debugging
        traceback_info = traceback.format_exc()
        logger.debug("Traceback: %s", traceback_info)

        return ""


def get_file_hash(file_path: Union[str, Path], algorithm: str = "sha256") -> str:
    """
    Simple wrapper for compute_file_hash without progress callback.

    Args:
        file_path: Path to the file to hash
        algorithm: The hashing algorithm to use

    Returns:
        str: Hexadecimal hash string
    """
    return compute_file_hash(file_path, algorithm)


def read_binary(file_path: Union[str, Path], chunk_size: int = 8192) -> bytes:
    """
    Read a binary file in chunks.

    Args:
        file_path: Path to the binary file
        chunk_size: Size of chunks to read (default: 8192)

    Returns:
        bytes: File contents

    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file cannot be read
    """
    try:
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "rb") as f:
            chunks = []
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error reading binary file %s: %s", file_path, e)
        raise


def write_binary(file_path: Union[str, Path], data: bytes, create_backup: bool = True) -> bool:
    """
    Write binary data to a file with optional backup.

    Args:
        file_path: Path to write to
        data: Binary data to write
        create_backup: Whether to create a backup of existing file

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        file_path = Path(file_path)

        # Create backup if file exists and backup requested
        if create_backup and file_path.exists():
            backup_path = file_path.with_suffix(file_path.suffix + ".bak")
            import shutil
            shutil.copy2(file_path, backup_path)
            logger.info("Created backup: %s", backup_path)

        # Write the data
        with open(file_path, "wb") as f:
            f.write(data)

        logger.info(f"Successfully wrote {len(data)} bytes to {file_path}")
        return True

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error writing binary file %s: %s", file_path, e)
        return False


def analyze_binary_format(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Analyze the format of a binary file.

    Args:
        file_path: Path to the binary file

    Returns:
        dict: Format information including type, architecture, etc.
    """
    try:
        file_path = Path(file_path)
        if not file_path.exists():
            return {"error": "File not found"}

        # Read file header
        with open(file_path, "rb") as f:
            header = f.read(512)

        format_info = {
            "path": str(file_path),
            "size": file_path.stat().st_size,
            "type": "unknown",
            "architecture": "unknown"
        }

        # Check for common binary formats
        if header.startswith(b"MZ"):
            format_info["type"] = "PE"
            # Check for PE signature
            if len(header) > 0x3C:
                pe_offset = int.from_bytes(header[0x3C:0x40], "little")
                if len(header) > pe_offset + 4:
                    if header[pe_offset:pe_offset+4] == b"PE\x00\x00":
                        format_info["type"] = "PE32/PE32+"

        elif header.startswith(b"\x7fELF"):
            format_info["type"] = "ELF"
            if len(header) > 4:
                if header[4] == 1:
                    format_info["architecture"] = "32-bit"
                elif header[4] == 2:
                    format_info["architecture"] = "64-bit"

        elif header.startswith(b"\xCE\xFA\xED\xFE") or header.startswith(b"\xCF\xFA\xED\xFE"):
            format_info["type"] = "Mach-O"
            format_info["architecture"] = "32-bit"
        elif header.startswith(b"\xFE\xED\xFA\xCE") or header.startswith(b"\xFE\xED\xFA\xCF"):
            format_info["type"] = "Mach-O"
            format_info["architecture"] = "64-bit"

        elif header.startswith(b"PK\x03\x04"):
            format_info["type"] = "ZIP/JAR/APK"
            # Check if it's an APK
            if file_path.suffix.lower() == ".apk":
                format_info["type"] = "APK"

        return format_info

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error analyzing binary format for %s: %s", file_path, e)
        return {"error": str(e)}


def is_binary_file(file_path: Union[str, Path], sample_size: int = 8192) -> bool:
    """
    Check if a file is binary by looking for null bytes.

    Args:
        file_path: Path to check
        sample_size: Number of bytes to sample

    Returns:
        bool: True if file appears to be binary
    """
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(sample_size)
            return b"\x00" in chunk
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error checking if file is binary: %s", e)
        return False


def get_file_entropy(file_path: Union[str, Path], block_size: int = 256) -> float:
    """
    Calculate the entropy of a file (useful for detecting encryption/packing).

    Args:
        file_path: Path to the file
        block_size: Size of blocks to analyze

    Returns:
        float: Entropy value (0-8)
    """
    try:
        import math

        with open(file_path, "rb") as f:
            data = f.read(block_size)

        if not data:
            return 0.0

        # Calculate byte frequency
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in frequency.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error calculating file entropy: %s", e)
        return 0.0


def check_suspicious_pe_sections(pe_obj) -> list:
    """
    Check for suspicious PE sections that are both writable and executable.

    Args:
        pe_obj: A pefile PE object

    Returns:
        list: List of suspicious section names
    """
    suspicious_sections = []
    try:
        if hasattr(pe_obj, "sections"):
            for section in pe_obj.sections:
                section_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")

                # Check if section is both writable and executable (security risk)
                if (section.Characteristics & 0x20000000) and (section.Characteristics & 0x80000000):
                    suspicious_sections.append(section_name)
    except (AttributeError, ValueError) as e:
        logger.debug("Error checking PE sections: %s", e)

    return suspicious_sections


def validate_binary_path(binary_path: str, logger_instance=None) -> bool:
    """
    Validate that a binary path exists and log appropriate error.

    This is the common pattern extracted from duplicate code in analysis modules.

    Args:
        binary_path: Path to binary file to validate
        logger_instance: Logger instance to use (optional)

    Returns:
        bool: True if binary exists, False otherwise
    """
    use_logger = logger_instance or logger

    if not binary_path:
        use_logger.error("Binary path is empty")
        return False

    if not os.path.exists(binary_path):
        use_logger.error("Binary not found: %s", binary_path)
        return False

    return True


# Exported functions
__all__ = [
    "compute_file_hash",
    "get_file_hash",
    "read_binary",
    "write_binary",
    "analyze_binary_format",
    "is_binary_file",
    "get_file_entropy",
    "check_suspicious_pe_sections",
    "validate_binary_path",
]
