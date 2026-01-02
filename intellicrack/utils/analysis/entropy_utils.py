"""Entropy calculation utilities for Intellicrack.

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

Entropy Calculation Utilities

Shared entropy calculation functions to eliminate code duplication.
"""

import math


def calculate_entropy(data: bytes | str) -> float:
    """Calculate Shannon entropy of data.

    Args:
        data: Input data to analyze.

    Returns:
        Shannon entropy value as a float.
    """
    if not data:
        return 0.0

    freq: dict[int | str, int] = {}
    for item in data:
        freq[item] = freq.get(item, 0) + 1

    # Calculate entropy
    entropy = 0.0
    data_len = len(data)

    for count in freq.values():
        p = count / data_len
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def calculate_byte_entropy(data: bytes) -> float:
    """Calculate Shannon entropy specifically for byte data.

    Args:
        data: Input byte data to analyze.

    Returns:
        Shannon entropy value as a float.
    """
    return calculate_entropy(data)


def calculate_string_entropy(data: str) -> float:
    """Calculate Shannon entropy specifically for string data.

    Args:
        data: Input string data to analyze.

    Returns:
        Shannon entropy value as a float.
    """
    return calculate_entropy(data)


def safe_entropy_calculation(data: bytes, max_entropy: float | None = None) -> float:
    """Safe entropy calculation with optional maximum cap.

    Args:
        data: Input byte data to analyze.
        max_entropy: Optional maximum entropy value to cap result.

    Returns:
        Shannon entropy value, optionally capped at max_entropy.
    """
    if not data:
        return 0.0

    entropy = calculate_byte_entropy(data)

    return min(entropy, max_entropy) if max_entropy is not None else entropy


def calculate_frequency_distribution(data: bytes | str) -> dict[int | str, dict[str, int | float]]:
    """Calculate frequency distribution of data.

    Args:
        data: Input data to analyze.

    Returns:
        Dictionary mapping each unique byte/character to its frequency and probability.
    """
    if not data:
        return {}

    freq: dict[int | str, int] = {}
    for item in data:
        freq[item] = freq.get(item, 0) + 1

    data_len = len(data)

    return {
        item: {
            "count": count,
            "probability": count / data_len,
        }
        for item, count in freq.items()
    }


def is_high_entropy(data: bytes | str, threshold: float = 7.0) -> bool:
    """Check if data has high entropy (likely encrypted/compressed).

    Args:
        data: Input data to analyze.
        threshold: Entropy threshold for determining high entropy.

    Returns:
        True if entropy is above the threshold, False otherwise.
    """
    entropy = calculate_entropy(data)
    return entropy >= threshold


def analyze_entropy_sections(
    data: bytes, block_size: int = 256
) -> dict[str, float | list[dict[str, int | float | bool]] | dict[str, float | int]]:
    """Analyze entropy across different sections of data.

    Args:
        data: Input byte data to analyze.
        block_size: Size of each block to analyze in bytes.

    Returns:
        Dictionary containing overall entropy, per-block entropy analysis, and statistical summaries.
    """
    if not data:
        return {}

    sections = []
    overall_entropy = calculate_entropy(data)

    # Analyze blocks
    for i in range(0, len(data), block_size):
        block = data[i : i + block_size]
        if len(block) > 0:
            block_entropy = calculate_entropy(block)
            sections.append(
                {
                    "offset": i,
                    "size": len(block),
                    "entropy": block_entropy,
                    "is_high_entropy": is_high_entropy(block),
                },
            )

    # Calculate statistics
    if sections:
        entropies = [s["entropy"] for s in sections]
        avg_entropy = sum(entropies) / len(entropies)
        min_entropy = min(entropies)
        max_entropy = max(entropies)
        variance = sum((e - avg_entropy) ** 2 for e in entropies) / len(entropies)
    else:
        avg_entropy = min_entropy = max_entropy = variance = 0.0

    return {
        "overall_entropy": overall_entropy,
        "sections": sections,
        "statistics": {
            "average_entropy": avg_entropy,
            "min_entropy": min_entropy,
            "max_entropy": max_entropy,
            "variance": variance,
            "section_count": len(sections),
        },
    }
