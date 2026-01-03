"""Comprehensive tests for entropy utility functions.

Tests validate real Shannon entropy calculations on actual data.
NO mocks - only real functionality validation.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import math
import os
from typing import Any, cast

import pytest

from intellicrack.utils.analysis.entropy_utils import (
    analyze_entropy_sections,
    calculate_byte_entropy,
    calculate_entropy,
    calculate_frequency_distribution,
    calculate_string_entropy,
    is_high_entropy,
    safe_entropy_calculation,
)


def get_sections(
    result: dict[str, float | list[dict[str, int | float | bool]] | dict[str, float | int]]
) -> list[dict[str, Any]]:
    """Extract sections list from entropy analysis result."""
    sections = result.get("sections", [])
    if isinstance(sections, list):
        return cast(list[dict[str, Any]], sections)
    return []


def get_statistics(
    result: dict[str, float | list[dict[str, int | float | bool]] | dict[str, float | int]]
) -> dict[str, Any]:
    """Extract statistics dict from entropy analysis result."""
    stats = result.get("statistics", {})
    if isinstance(stats, dict):
        return cast(dict[str, Any], stats)
    return {}


def get_overall_entropy(
    result: dict[str, float | list[dict[str, int | float | bool]] | dict[str, float | int]]
) -> float:
    """Extract overall entropy value from analysis result."""
    value = result.get("overall_entropy", 0.0)
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


class TestCalculateEntropy:
    """Test Shannon entropy calculation."""

    def test_calculate_entropy_empty_data(self) -> None:
        """calculate_entropy handles empty data correctly."""
        assert calculate_entropy(b"") == 0.0
        assert calculate_entropy("") == 0.0

    def test_calculate_entropy_zero_entropy(self) -> None:
        """calculate_entropy returns 0 for identical bytes."""
        data = b"\x00" * 1000
        entropy = calculate_entropy(data)

        assert entropy == 0.0

    def test_calculate_entropy_maximum_entropy(self) -> None:
        """calculate_entropy approaches 8.0 for random data."""
        data = bytes(range(256))
        entropy = calculate_entropy(data)

        assert 7.9 < entropy <= 8.0

    def test_calculate_entropy_medium_entropy(self) -> None:
        """calculate_entropy calculates intermediate values correctly."""
        data = b"AAAABBBB"
        entropy = calculate_entropy(data)

        expected = -2 * (0.5 * math.log2(0.5))
        assert abs(entropy - expected) < 0.001
        assert abs(entropy - 1.0) < 0.001

    def test_calculate_entropy_string_data(self) -> None:
        """calculate_entropy handles string data."""
        text = "Hello World! This is a test string."
        entropy = calculate_entropy(text)

        assert entropy > 0.0
        assert entropy < 8.0

    def test_calculate_entropy_bytes_data(self) -> None:
        """calculate_entropy handles bytes data."""
        data = b"Binary data with some entropy"
        entropy = calculate_entropy(data)

        assert entropy > 0.0
        assert entropy < 8.0

    def test_calculate_entropy_single_character(self) -> None:
        """calculate_entropy handles single character correctly."""
        assert calculate_entropy(b"A") == 0.0
        assert calculate_entropy("X") == 0.0

    def test_calculate_entropy_two_characters(self) -> None:
        """calculate_entropy handles two distinct characters."""
        entropy = calculate_entropy(b"AB")

        expected = -2 * (0.5 * math.log2(0.5))
        assert abs(entropy - expected) < 0.001

    def test_calculate_entropy_random_data(self) -> None:
        """calculate_entropy produces high values for random data."""
        random_data = os.urandom(1024)
        entropy = calculate_entropy(random_data)

        assert entropy > 7.0


class TestCalculateByteEntropy:
    """Test byte-specific entropy calculation."""

    def test_calculate_byte_entropy_delegates_to_calculate_entropy(self) -> None:
        """calculate_byte_entropy produces same result as calculate_entropy."""
        data = os.urandom(512)

        byte_entropy = calculate_byte_entropy(data)
        general_entropy = calculate_entropy(data)

        assert byte_entropy == general_entropy

    def test_calculate_byte_entropy_handles_empty(self) -> None:
        """calculate_byte_entropy handles empty bytes."""
        assert calculate_byte_entropy(b"") == 0.0


class TestCalculateStringEntropy:
    """Test string-specific entropy calculation."""

    def test_calculate_string_entropy_delegates_to_calculate_entropy(self) -> None:
        """calculate_string_entropy produces same result as calculate_entropy."""
        text = "License validation string with characters"

        string_entropy = calculate_string_entropy(text)
        general_entropy = calculate_entropy(text)

        assert string_entropy == general_entropy

    def test_calculate_string_entropy_handles_empty(self) -> None:
        """calculate_string_entropy handles empty strings."""
        assert calculate_string_entropy("") == 0.0


class TestSafeEntropyCalculation:
    """Test safe entropy calculation with capping."""

    def test_safe_entropy_calculation_no_cap(self) -> None:
        """safe_entropy_calculation without max returns actual entropy."""
        data = os.urandom(256)
        safe_entropy = safe_entropy_calculation(data, max_entropy=None)
        regular_entropy = calculate_byte_entropy(data)

        assert safe_entropy == regular_entropy

    def test_safe_entropy_calculation_with_cap(self) -> None:
        """safe_entropy_calculation caps entropy at maximum."""
        high_entropy_data = os.urandom(512)
        capped_entropy = safe_entropy_calculation(high_entropy_data, max_entropy=5.0)

        assert capped_entropy <= 5.0

    def test_safe_entropy_calculation_below_cap(self) -> None:
        """safe_entropy_calculation doesn't modify values below cap."""
        low_entropy_data = b"AAAA" * 100
        entropy = safe_entropy_calculation(low_entropy_data, max_entropy=5.0)
        regular_entropy = calculate_byte_entropy(low_entropy_data)

        assert entropy == regular_entropy
        assert entropy < 5.0

    def test_safe_entropy_calculation_empty_data(self) -> None:
        """safe_entropy_calculation handles empty data."""
        assert safe_entropy_calculation(b"", max_entropy=None) == 0.0
        assert safe_entropy_calculation(b"", max_entropy=10.0) == 0.0


class TestCalculateFrequencyDistribution:
    """Test frequency distribution calculation."""

    def test_calculate_frequency_distribution_empty_data(self) -> None:
        """calculate_frequency_distribution handles empty data."""
        assert calculate_frequency_distribution(b"") == {}
        assert calculate_frequency_distribution("") == {}

    def test_calculate_frequency_distribution_single_byte(self) -> None:
        """calculate_frequency_distribution calculates single byte correctly."""
        data = b"\x00" * 10
        dist = calculate_frequency_distribution(data)

        assert len(dist) == 1
        assert 0 in dist
        assert dist[0]["count"] == 10
        assert dist[0]["probability"] == 1.0

    def test_calculate_frequency_distribution_multiple_bytes(self) -> None:
        """calculate_frequency_distribution calculates multiple bytes."""
        data = b"AABBCC"
        dist = calculate_frequency_distribution(data)

        assert len(dist) == 3
        assert ord('A') in dist
        assert ord('B') in dist
        assert ord('C') in dist
        assert dist[ord('A')]["count"] == 2
        assert dist[ord('A')]["probability"] == 2/6

    def test_calculate_frequency_distribution_string_data(self) -> None:
        """calculate_frequency_distribution handles string data."""
        text = "Hello"
        dist = calculate_frequency_distribution(text)

        assert 'H' in dist
        assert 'e' in dist
        assert 'l' in dist
        assert 'o' in dist
        assert dist['l']["count"] == 2
        assert dist['l']["probability"] == 2/5

    def test_calculate_frequency_distribution_probabilities_sum_to_one(self) -> None:
        """calculate_frequency_distribution probabilities sum to 1.0."""
        data = os.urandom(1000)
        dist = calculate_frequency_distribution(data)

        total_prob = sum(item["probability"] for item in dist.values())

        assert abs(total_prob - 1.0) < 0.001


class TestIsHighEntropy:
    """Test high entropy detection."""

    def test_is_high_entropy_detects_random_data(self) -> None:
        """is_high_entropy detects high entropy in random data."""
        random_data = os.urandom(1024)

        assert is_high_entropy(random_data, threshold=7.0) is True

    def test_is_high_entropy_rejects_low_entropy(self) -> None:
        """is_high_entropy rejects low entropy data."""
        low_entropy_data = b"\x00" * 1000

        assert is_high_entropy(low_entropy_data, threshold=7.0) is False

    def test_is_high_entropy_custom_threshold(self) -> None:
        """is_high_entropy respects custom threshold."""
        medium_entropy_data = b"AABBCCDD" * 100

        assert is_high_entropy(medium_entropy_data, threshold=1.0) is True
        assert is_high_entropy(medium_entropy_data, threshold=7.5) is False

    def test_is_high_entropy_string_data(self) -> None:
        """is_high_entropy works with string data."""
        text = "a" * 1000
        assert is_high_entropy(text, threshold=7.0) is False

        varied_text = "abcdefghijklmnopqrstuvwxyz" * 40
        entropy = calculate_entropy(varied_text)
        assert is_high_entropy(varied_text, threshold=entropy - 0.5) is True


class TestAnalyzeEntropySections:
    """Test entropy section analysis."""

    def test_analyze_entropy_sections_empty_data(self) -> None:
        """analyze_entropy_sections handles empty data."""
        result = analyze_entropy_sections(b"")

        assert result == {}

    def test_analyze_entropy_sections_creates_sections(self) -> None:
        """analyze_entropy_sections divides data into sections."""
        data = os.urandom(1024)
        result = analyze_entropy_sections(data, block_size=256)

        assert "overall_entropy" in result
        assert "sections" in result
        assert "statistics" in result
        sections = get_sections(result)
        assert len(sections) == 4

    def test_analyze_entropy_sections_calculates_overall_entropy(self) -> None:
        """analyze_entropy_sections calculates overall entropy."""
        data = os.urandom(512)
        result = analyze_entropy_sections(data, block_size=128)

        assert "overall_entropy" in result
        overall = get_overall_entropy(result)
        assert overall > 0.0

    def test_analyze_entropy_sections_includes_section_details(self) -> None:
        """analyze_entropy_sections includes detailed section information."""
        data = b"\x00" * 512 + os.urandom(512)
        result = analyze_entropy_sections(data, block_size=256)

        sections = get_sections(result)
        assert len(sections) > 0

        section = sections[0]
        assert "offset" in section
        assert "size" in section
        assert "entropy" in section
        assert "is_high_entropy" in section

    def test_analyze_entropy_sections_detects_high_entropy_sections(self) -> None:
        """analyze_entropy_sections identifies high entropy sections."""
        low_entropy = b"\x00" * 512
        high_entropy = os.urandom(512)
        data = low_entropy + high_entropy

        result = analyze_entropy_sections(data, block_size=512)

        sections = get_sections(result)
        assert len(sections) == 2

        low_section = sections[0]
        high_section = sections[1]

        assert low_section["is_high_entropy"] is False
        assert high_section["is_high_entropy"] is True

    def test_analyze_entropy_sections_calculates_statistics(self) -> None:
        """analyze_entropy_sections calculates correct statistics."""
        data = os.urandom(2048)
        result = analyze_entropy_sections(data, block_size=256)

        stats = get_statistics(result)
        sections = get_sections(result)

        assert "average_entropy" in stats
        assert "min_entropy" in stats
        assert "max_entropy" in stats
        assert "variance" in stats
        assert "section_count" in stats

        min_ent = float(stats.get("min_entropy", 0))
        avg_ent = float(stats.get("average_entropy", 0))
        max_ent = float(stats.get("max_entropy", 0))
        variance = float(stats.get("variance", 0))
        section_count = int(stats.get("section_count", 0))

        assert min_ent <= avg_ent <= max_ent
        assert variance >= 0.0
        assert section_count == len(sections)

    def test_analyze_entropy_sections_handles_small_data(self) -> None:
        """analyze_entropy_sections handles data smaller than block size."""
        data = b"Small"
        result = analyze_entropy_sections(data, block_size=256)

        assert "sections" in result
        sections = get_sections(result)
        assert len(sections) == 1

    def test_analyze_entropy_sections_different_block_sizes(self) -> None:
        """analyze_entropy_sections works with different block sizes."""
        data = os.urandom(1024)

        result_small = analyze_entropy_sections(data, block_size=128)
        result_large = analyze_entropy_sections(data, block_size=512)

        sections_small = get_sections(result_small)
        sections_large = get_sections(result_large)
        assert len(sections_small) > len(sections_large)

    def test_analyze_entropy_sections_section_offsets_correct(self) -> None:
        """analyze_entropy_sections sets correct section offsets."""
        data = os.urandom(768)
        result = analyze_entropy_sections(data, block_size=256)

        sections = get_sections(result)
        assert sections[0]["offset"] == 0
        assert sections[1]["offset"] == 256
        assert sections[2]["offset"] == 512

    def test_analyze_entropy_sections_variance_calculation(self) -> None:
        """analyze_entropy_sections calculates variance correctly."""
        uniform_data = bytes(range(256)) * 4
        result = analyze_entropy_sections(uniform_data, block_size=256)

        stats = get_statistics(result)
        variance = float(stats.get("variance", 0))
        assert variance < 0.5

    def test_analyze_entropy_sections_mixed_entropy_data(self) -> None:
        """analyze_entropy_sections handles mixed entropy data."""
        section1 = b"\x00" * 256
        section2 = os.urandom(256)
        section3 = b"ASCII text content goes here" * 10

        data = section1 + section2 + section3[:256]
        result = analyze_entropy_sections(data, block_size=256)

        sections = get_sections(result)
        entropies = [float(s.get("entropy", 0)) for s in sections]

        assert min(entropies) < 2.0
        assert max(entropies) > 6.0


class TestEntropyEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_entropy_calculation_large_data(self) -> None:
        """Entropy calculation handles large data efficiently."""
        large_data = os.urandom(10 * 1024 * 1024)[:100000]
        entropy = calculate_entropy(large_data)

        assert 7.0 < entropy <= 8.0

    def test_entropy_calculation_all_same_byte_values(self) -> None:
        """Entropy calculation with all identical bytes."""
        for byte_val in [0, 127, 255]:
            data = bytes([byte_val] * 1000)
            entropy = calculate_entropy(data)
            assert entropy == 0.0

    def test_entropy_calculation_binary_sequence(self) -> None:
        """Entropy calculation with binary sequence."""
        data = b"\x00\xFF" * 500
        entropy = calculate_entropy(data)

        expected = -2 * (0.5 * math.log2(0.5))
        assert abs(entropy - expected) < 0.001

    def test_frequency_distribution_all_bytes_present(self) -> None:
        """Frequency distribution with all 256 byte values."""
        data = bytes(range(256)) * 4
        dist = calculate_frequency_distribution(data)

        assert len(dist) == 256
        for i in range(256):
            assert dist[i]["count"] == 4
            assert abs(dist[i]["probability"] - 1/256) < 0.001

    def test_is_high_entropy_boundary_cases(self) -> None:
        """is_high_entropy at boundary threshold values."""
        data_exact = bytes(range(128)) * 2
        entropy_exact = calculate_entropy(data_exact)

        assert is_high_entropy(data_exact, threshold=entropy_exact) is True
        assert is_high_entropy(data_exact, threshold=entropy_exact + 0.001) is False
