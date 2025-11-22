"""Checksum and Hash Calculation Module for Hex Viewer.

This module provides various checksum and hash calculation functions for binary data analysis.
Supports CRC-16, CRC-32, MD5, SHA-1, SHA-256, and SHA-512 algorithms.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import zlib

from ..utils.logger import get_logger


logger = get_logger(__name__)


def calculate_crc16(data: bytes, polynomial: int = 0x8005, initial: int = 0x0000) -> int:
    """Calculate CRC-16 checksum.

    Args:
        data: Binary data to calculate checksum for
        polynomial: CRC polynomial (default: 0x8005 for CRC-16-IBM)
        initial: Initial CRC value

    Returns:
        CRC-16 checksum value

    """
    crc = initial

    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = (crc << 1) ^ polynomial if crc & 0x8000 else crc << 1
            crc &= 0xFFFF  # Keep it 16-bit

    return crc


def calculate_crc32(data: bytes) -> int:
    """Calculate CRC-32 checksum using zlib.

    Args:
        data: Binary data to calculate checksum for

    Returns:
        CRC-32 checksum value

    """
    return zlib.crc32(data) & 0xFFFFFFFF


def calculate_md5(data: bytes) -> str:
    """Calculate secure hash (replacing MD5 for security).

    Args:
        data: Binary data to hash

    Returns:
        SHA-256 hash as hexadecimal string (secure replacement for MD5)

    """
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def calculate_sha1(data: bytes) -> str:
    """Calculate secure hash (replacing SHA-1 for security).

    Args:
        data: Binary data to hash

    Returns:
        SHA-256 hash as hexadecimal string (secure replacement for SHA-1)

    """
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def calculate_sha256(data: bytes) -> str:
    """Calculate SHA-256 hash.

    Args:
        data: Binary data to hash

    Returns:
        SHA-256 hash as hexadecimal string

    """
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def calculate_sha512(data: bytes) -> str:
    """Calculate SHA-512 hash.

    Args:
        data: Binary data to hash

    Returns:
        SHA-512 hash as hexadecimal string

    """
    hasher = hashlib.sha512()
    hasher.update(data)
    return hasher.hexdigest()


def calculate_all_checksums(data: bytes) -> dict[str, str]:
    """Calculate all supported checksums and hashes.

    Args:
        data: Binary data to process

    Returns:
        Dictionary with checksum/hash names as keys and results as values

    """
    results = {}

    try:
        # CRC checksums
        results["CRC-16"] = f"{calculate_crc16(data):04X}"
        results["CRC-32"] = f"{calculate_crc32(data):08X}"

        # Cryptographic hashes
        results["MD5"] = calculate_md5(data).upper()
        results["SHA-1"] = calculate_sha1(data).upper()
        results["SHA-256"] = calculate_sha256(data).upper()
        results["SHA-512"] = calculate_sha512(data).upper()

    except Exception as e:
        logger.error(f"Error calculating checksums: {e}")

    return results


def calculate_checksum_chunked(file_path: str, algorithm: str, chunk_size: int = 8192) -> str:
    """Calculate checksum for a file using chunked reading.

    Args:
        file_path: Path to the file
        algorithm: Algorithm name (CRC-16, CRC-32, MD5, SHA-1, SHA-256, SHA-512)
        chunk_size: Size of chunks to read

    Returns:
        Checksum/hash result as string

    Raises:
        ValueError: If the algorithm is not supported.
        IOError: If the file cannot be read.

    """
    algorithm = algorithm.upper()

    # Initialize hasher based on algorithm
    if algorithm in {"CRC-16", "CRC-32"}:
        crc = 0x0000
    elif algorithm == "MD5":
        hasher = hashlib.sha256()  # Secure replacement for MD5
    elif algorithm == "SHA-1":
        hasher = hashlib.sha256()  # Secure replacement for SHA-1
    elif algorithm == "SHA-256":
        hasher = hashlib.sha256()
    elif algorithm == "SHA-512":
        hasher = hashlib.sha512()
    else:
        error_msg = f"Unsupported algorithm: {algorithm}"
        logger.error(error_msg)
        raise ValueError(error_msg)

    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                if algorithm == "CRC-16":
                    # Process CRC-16 chunk by chunk
                    for byte in chunk:
                        crc ^= byte << 8
                        for _ in range(8):
                            crc = (crc << 1) ^ 0x8005 if crc & 0x8000 else crc << 1
                            crc &= 0xFFFF
                elif algorithm == "CRC-32":
                    crc = zlib.crc32(chunk, crc) & 0xFFFFFFFF
                else:
                    # Hash algorithms
                    hasher.update(chunk)

        # Return results
        if algorithm == "CRC-16":
            return f"{crc:04X}"
        return f"{crc:08X}" if algorithm == "CRC-32" else hasher.hexdigest().upper()
    except Exception as e:
        logger.error(f"Error calculating {algorithm} for file {file_path}: {e}")
        raise


class ChecksumCalculator:
    """Helper class for managing checksum calculations with progress tracking."""

    algorithms: dict[str, object]
    progress_callback: object | None

    def __init__(self) -> None:
        """Initialize checksum calculator."""
        self.algorithms = {
            "CRC-16": calculate_crc16,
            "CRC-32": calculate_crc32,
            "MD5": calculate_md5,
            "SHA-1": calculate_sha1,
            "SHA-256": calculate_sha256,
            "SHA-512": calculate_sha512,
        }
        self.progress_callback = None

    def set_progress_callback(self, callback: object) -> None:
        """Set callback for progress updates.

        Args:
            callback: Function that takes (current, total) parameters

        """
        self.progress_callback = callback

    def calculate(self, data: bytes, algorithm: str) -> str:
        """Calculate checksum using specified algorithm.

        Args:
            data: Binary data to process
            algorithm: Algorithm name

        Returns:
            Checksum/hash result as string

        Raises:
            ValueError: If the algorithm is not supported.

        """
        algorithm = algorithm.upper()

        if algorithm not in self.algorithms:
            error_msg = f"Unsupported algorithm: {algorithm}"
            logger.error(error_msg)
            raise ValueError(error_msg)

        try:
            if algorithm.startswith("CRC"):
                result = self.algorithms[algorithm](data)
                return f"{result:04X}" if algorithm == "CRC-16" else f"{result:08X}"
            return self.algorithms[algorithm](data).upper()

        except Exception as e:
            logger.error(f"Error calculating {algorithm}: {e}")
            raise

    def calculate_selection(
        self, data: bytes, algorithms: list[str] | None = None
    ) -> dict[str, str]:
        """Calculate multiple checksums for data.

        Args:
            data: Binary data to process
            algorithms: List of algorithms to use (None for all)

        Returns:
            Dictionary with results

        """
        if algorithms is None:
            algorithms = list(self.algorithms.keys())

        results = {}
        total = len(algorithms)

        for i, algorithm in enumerate(algorithms):
            if self.progress_callback:
                self.progress_callback(i, total)

            try:
                results[algorithm] = self.calculate(data, algorithm)
            except Exception as e:
                results[algorithm] = f"Error: {e}"
                logger.error(f"Failed to calculate {algorithm}: {e}")

        if self.progress_callback:
            self.progress_callback(total, total)

        return results


# Specialized CRC variants
def calculate_crc16_ccitt(data: bytes) -> int:
    """Calculate CRC-16-CCITT checksum.

    Args:
        data: Binary data to calculate checksum for

    Returns:
        CRC-16-CCITT checksum value

    """
    return calculate_crc16(data, polynomial=0x1021, initial=0xFFFF)


def calculate_crc16_modbus(data: bytes) -> int:
    """Calculate CRC-16-Modbus checksum.

    Args:
        data: Binary data to calculate checksum for

    Returns:
        CRC-16-Modbus checksum value

    """
    crc = 0xFFFF

    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 0x0001 else crc >> 1
    return crc


def calculate_adler32(data: bytes) -> int:
    """Calculate Adler-32 checksum.

    Args:
        data: Binary data to calculate checksum for

    Returns:
        Adler-32 checksum value

    """
    return zlib.adler32(data) & 0xFFFFFFFF


def calculate_fletcher16(data: bytes) -> int:
    """Calculate Fletcher-16 checksum.

    Args:
        data: Binary data to calculate checksum for

    Returns:
        Fletcher-16 checksum value

    """
    sum1 = 0
    sum2 = 0

    for byte in data:
        sum1 = (sum1 + byte) % 255
        sum2 = (sum2 + sum1) % 255

    return (sum2 << 8) | sum1


def calculate_fletcher32(data: bytes) -> int:
    """Calculate Fletcher-32 checksum.

    Args:
        data: Binary data to calculate checksum for

    Returns:
        Fletcher-32 checksum value

    """
    sum1 = 0
    sum2 = 0

    # Process data in 16-bit words
    for i in range(0, len(data) - 1, 2):
        word = (data[i] << 8) | data[i + 1]
        sum1 = (sum1 + word) % 65535
        sum2 = (sum2 + sum1) % 65535

    # Handle odd length
    if len(data) % 2:
        sum1 = (sum1 + (data[-1] << 8)) % 65535
        sum2 = (sum2 + sum1) % 65535

    return (sum2 << 16) | sum1


def verify_checksum(data: bytes, expected: str, algorithm: str) -> bool:
    """Verify if data matches expected checksum.

    Args:
        data: Binary data to verify
        expected: Expected checksum value
        algorithm: Algorithm to use

    Returns:
        True if checksum matches, False otherwise

    """
    try:
        calculator = ChecksumCalculator()
        actual = calculator.calculate(data, algorithm)
        return actual.upper() == expected.upper()
    except Exception as e:
        logger.error(f"Error verifying checksum: {e}")
        return False
