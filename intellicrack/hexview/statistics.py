"""Statistical Analysis Module for Hex Viewer.

This module provides statistical analysis functions for binary data including
character distribution, entropy calculation, and pattern detection.

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

import math
from collections import Counter
from typing import Any, Callable

from ..utils.logger import get_logger

logger = get_logger(__name__)


def calculate_byte_distribution(data: bytes) -> dict[int, int]:
    """Calculate the distribution of byte values in the data.

    Args:
        data: Binary data to analyze

    Returns:
        Dictionary mapping byte values (0-255) to their occurrence counts

    """
    distribution = Counter(data)
    # Ensure all byte values are represented
    for i in range(256):
        if i not in distribution:
            distribution[i] = 0
    return dict(distribution)


def calculate_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of the data.

    Higher entropy indicates more randomness/encryption.

    Args:
        data: Binary data to analyze

    Returns:
        Entropy value (0-8 bits)

    """
    if not data:
        return 0.0

    # Count byte occurrences
    byte_counts = Counter(data)
    data_len = len(data)

    # Calculate entropy
    entropy = 0.0
    for count in byte_counts.values():
        if count > 0:
            probability = count / data_len
            entropy -= probability * math.log2(probability)

    return entropy


def calculate_statistics(data: bytes) -> dict[str, Any]:
    """Calculate comprehensive statistics for binary data.

    Args:
        data: Binary data to analyze

    Returns:
        Dictionary containing various statistics

    """
    if not data:
        return {
            "size": 0,
            "entropy": 0.0,
            "min_byte": 0,
            "max_byte": 0,
            "mean_byte": 0.0,
            "null_bytes": 0,
            "printable_chars": 0,
            "control_chars": 0,
            "high_bytes": 0,
        }

    # Basic statistics
    size = len(data)
    distribution = calculate_byte_distribution(data)
    entropy = calculate_entropy(data)

    # Min/max/mean
    min_byte = min(data)
    max_byte = max(data)
    mean_byte = sum(data) / size

    # Character type counts
    null_bytes = distribution[0]
    printable_chars = sum(distribution[i] for i in range(32, 127))
    control_chars = sum(distribution[i] for i in range(1, 32))
    high_bytes = sum(distribution[i] for i in range(128, 256))

    # Detect likely file type based on patterns
    file_type_hints = detect_file_type_hints(data, distribution)

    return {
        "size": size,
        "entropy": entropy,
        "min_byte": min_byte,
        "max_byte": max_byte,
        "mean_byte": mean_byte,
        "null_bytes": null_bytes,
        "null_percentage": (null_bytes / size) * 100,
        "printable_chars": printable_chars,
        "printable_percentage": (printable_chars / size) * 100,
        "control_chars": control_chars,
        "control_percentage": (control_chars / size) * 100,
        "high_bytes": high_bytes,
        "high_bytes_percentage": (high_bytes / size) * 100,
        "distribution": distribution,
        "file_type_hints": file_type_hints,
    }


def detect_file_type_hints(data: bytes, distribution: dict[int, int]) -> list[str]:
    """Detect hints about the file type based on byte patterns.

    Args:
        data: Binary data to analyze
        distribution: Byte distribution dictionary

    Returns:
        List of file type hints

    """
    hints = []
    size = len(data)

    if size == 0:
        return hints

    # Check entropy levels
    entropy = calculate_entropy(data)
    if entropy > 7.5:
        hints.append("High entropy - likely compressed or encrypted")
    elif entropy < 4.0:
        hints.append("Low entropy - likely text or structured data")

    # Check for text file patterns
    printable_ratio = sum(distribution[i] for i in range(32, 127)) / size
    if printable_ratio > 0.85:
        hints.append("Mostly printable ASCII - likely text file")

    # Check for binary patterns
    null_ratio = distribution[0] / size
    if null_ratio > 0.3:
        hints.append("High null byte count - likely binary format")

    # Check for common file signatures (magic bytes)
    if size >= 4:
        # PE executable
        if data[:2] == b"MZ":
            hints.append("PE executable (MZ header)")
        # ELF
        elif data[:4] == b"\x7fELF":
            hints.append("ELF executable")
        # PDF
        elif data[:4] == b"%PDF":
            hints.append("PDF document")
        # ZIP/JAR/Office
        elif data[:4] == b"PK\x03\x04":
            hints.append("ZIP archive (or Office/JAR file)")
        # PNG
        elif data[:8] == b"\x89PNG\r\n\x1a\n":
            hints.append("PNG image")
        # JPEG
        elif data[:3] == b"\xff\xd8\xff":
            hints.append("JPEG image")
        # GIF
        elif data[:6] in (b"GIF87a", b"GIF89a"):
            hints.append("GIF image")
        # RAR
        elif data[:7] == b"Rar!\x1a\x07\x00":
            hints.append("RAR archive")
        # 7z
        elif data[:6] == b"7z\xbc\xaf\x27\x1c":
            hints.append("7-Zip archive")

    # Check for UTF-8 BOM
    if size >= 3 and data[:3] == b"\xef\xbb\xbf":
        hints.append("UTF-8 with BOM")

    # Check for UTF-16 BOM
    if size >= 2:
        if data[:2] == b"\xff\xfe":
            hints.append("UTF-16 LE with BOM")
        elif data[:2] == b"\xfe\xff":
            hints.append("UTF-16 BE with BOM")

    return hints


def calculate_histogram(data: bytes, bins: int = 16) -> list[tuple[str, int]]:
    """Calculate a histogram of byte values.

    Args:
        data: Binary data to analyze
        bins: Number of bins for the histogram

    Returns:
        List of (range_label, count) tuples

    """
    if not data or bins <= 0:
        return []

    # Calculate bin size
    bin_size = 256 // bins
    histogram = []

    # Count bytes in each bin
    distribution = calculate_byte_distribution(data)

    for i in range(bins):
        start = i * bin_size
        end = min((i + 1) * bin_size, 256)
        count = sum(distribution[j] for j in range(start, end))

        # Create range label
        if end - start == 1:
            label = f"{start:02X}"
        else:
            label = f"{start:02X}-{end - 1:02X}"

        histogram.append((label, count))

    return histogram


def find_patterns(data: bytes, min_length: int = 4, max_patterns: int = 10) -> list[tuple[bytes, int]]:
    """Find repeating patterns in the data.

    Args:
        data: Binary data to analyze
        min_length: Minimum pattern length to detect
        max_patterns: Maximum number of patterns to return

    Returns:
        List of (pattern, count) tuples sorted by frequency

    """
    if not data or len(data) < min_length:
        return []

    patterns = Counter()
    data_len = len(data)

    # Look for patterns of various lengths
    for pattern_len in range(min_length, min(data_len // 2, 32)):
        for i in range(data_len - pattern_len + 1):
            pattern = data[i : i + pattern_len]
            # Only count patterns that appear more than once
            if data.count(pattern) > 1:
                patterns[pattern] = data.count(pattern)

    # Return most common patterns
    return patterns.most_common(max_patterns)


def calculate_chi_square(data: bytes) -> float:
    """Calculate chi-square test statistic for randomness.

    Lower values indicate more uniform distribution (randomness).

    Args:
        data: Binary data to analyze

    Returns:
        Chi-square test statistic

    """
    if not data:
        return 0.0

    # Expected frequency for uniform distribution
    expected = len(data) / 256.0

    # Count actual frequencies
    distribution = calculate_byte_distribution(data)

    # Calculate chi-square
    chi_square = 0.0
    for i in range(256):
        observed = distribution[i]
        chi_square += ((observed - expected) ** 2) / expected

    return chi_square


def analyze_compression_ratio(data: bytes) -> float:
    """Estimate the compression ratio of the data.

    Uses entropy to estimate how compressible the data is.

    Args:
        data: Binary data to analyze

    Returns:
        Estimated compression ratio (0-1, lower is more compressible)

    """
    if not data:
        return 0.0

    entropy = calculate_entropy(data)
    # Normalize entropy to 0-1 range (max entropy is 8 bits)
    return entropy / 8.0


class StatisticsCalculator:
    """Helper class for calculating statistics with progress tracking."""

    def __init__(self) -> None:
        """Initialize statistics calculator."""
        self.progress_callback = None

    def set_progress_callback(self, callback: Callable[[int, int], None]) -> None:
        """Set callback for progress updates.

        Args:
            callback: Function that takes (current, total) parameters

        """
        self.progress_callback = callback

    def calculate_all(self, data: bytes) -> dict[str, Any]:
        """Calculate all statistics with progress tracking.

        Args:
            data: Binary data to analyze

        Returns:
            Dictionary containing all statistics

        """
        total_steps = 7
        current_step = 0

        if self.progress_callback:
            self.progress_callback(current_step, total_steps)

        # Basic statistics
        stats = calculate_statistics(data)
        current_step += 1
        if self.progress_callback:
            self.progress_callback(current_step, total_steps)

        # Histogram
        stats["histogram"] = calculate_histogram(data)
        current_step += 1
        if self.progress_callback:
            self.progress_callback(current_step, total_steps)

        # Patterns
        stats["patterns"] = find_patterns(data)
        current_step += 1
        if self.progress_callback:
            self.progress_callback(current_step, total_steps)

        # Chi-square
        stats["chi_square"] = calculate_chi_square(data)
        current_step += 1
        if self.progress_callback:
            self.progress_callback(current_step, total_steps)

        # Compression estimate
        stats["compression_ratio"] = analyze_compression_ratio(data)
        current_step += 1
        if self.progress_callback:
            self.progress_callback(current_step, total_steps)

        # Final calculations
        if stats["size"] > 0:
            stats["entropy_percentage"] = (stats["entropy"] / 8.0) * 100
            stats["randomness_score"] = min(100, (stats["entropy"] / 8.0) * 100)
        else:
            stats["entropy_percentage"] = 0
            stats["randomness_score"] = 0

        current_step += 1
        if self.progress_callback:
            self.progress_callback(current_step, total_steps)

        return stats
