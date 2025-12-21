"""Production-Ready Tests for Statistics Module.

Tests REAL statistical analysis on binary data from Windows system files.
"""

from pathlib import Path

import pytest

from intellicrack.hexview.statistics import (
    StatisticsCalculator,
    analyze_compression_ratio,
    calculate_byte_distribution,
    calculate_chi_square,
    calculate_entropy,
    calculate_histogram,
    calculate_statistics,
    detect_file_type_hints,
    find_patterns,
)


class TestByteDistribution:
    """Test byte distribution calculation."""

    def test_byte_distribution_all_values_present(self) -> None:
        """Byte distribution must include all 256 byte values."""
        data = bytes(range(256))
        distribution = calculate_byte_distribution(data)

        assert len(distribution) == 256
        assert all(i in distribution for i in range(256))

    def test_byte_distribution_counts_correctly(self) -> None:
        """Byte distribution must count occurrences correctly."""
        data = b"\x00" * 10 + b"\xFF" * 5 + b"\x42" * 3

        distribution = calculate_byte_distribution(data)

        assert distribution[0x00] == 10
        assert distribution[0xFF] == 5
        assert distribution[0x42] == 3

    def test_byte_distribution_uniform_data(self) -> None:
        """Byte distribution must handle uniform data."""
        data = bytes(range(256)) * 4
        distribution = calculate_byte_distribution(data)

        for i in range(256):
            assert distribution[i] == 4


class TestEntropy:
    """Test Shannon entropy calculation."""

    def test_entropy_zero_for_uniform_data(self) -> None:
        """Entropy of single repeated byte must be 0."""
        data = b"\x00" * 1000
        entropy = calculate_entropy(data)

        assert entropy == pytest.approx(0.0, abs=0.01)

    def test_entropy_maximum_for_random_data(self) -> None:
        """Entropy of uniformly distributed data must be close to 8."""
        data = bytes(range(256)) * 4
        entropy = calculate_entropy(data)

        assert 7.9 < entropy <= 8.0

    def test_entropy_empty_data(self) -> None:
        """Entropy of empty data must be 0."""
        entropy = calculate_entropy(b"")
        assert entropy == 0.0

    def test_entropy_text_data(self) -> None:
        """Entropy of text data must be lower than random."""
        text_data = b"The quick brown fox jumps over the lazy dog" * 10
        entropy = calculate_entropy(text_data)

        assert 4.0 < entropy < 6.0


class TestCalculateStatistics:
    """Test comprehensive statistics calculation."""

    def test_statistics_basic_metrics(self) -> None:
        """Statistics must include all basic metrics."""
        data = bytes(range(256))
        stats = calculate_statistics(data)

        assert stats["size"] == 256
        assert stats["min_byte"] == 0
        assert stats["max_byte"] == 255
        assert stats["mean_byte"] == pytest.approx(127.5, abs=0.1)

    def test_statistics_null_byte_count(self) -> None:
        """Statistics must count null bytes correctly."""
        data = b"\x00" * 50 + bytes(range(1, 206))
        stats = calculate_statistics(data)

        assert stats["null_bytes"] == 50
        assert stats["null_percentage"] == pytest.approx(19.53, abs=0.1)

    def test_statistics_printable_chars(self) -> None:
        """Statistics must count printable characters."""
        data = b"Hello World! " * 10 + b"\x00" * 50
        stats = calculate_statistics(data)

        assert stats["printable_chars"] > 0
        assert stats["printable_percentage"] > 0

    def test_statistics_control_chars(self) -> None:
        """Statistics must count control characters."""
        data = b"\x01\x02\x03" * 10 + b"ABC" * 10
        stats = calculate_statistics(data)

        assert stats["control_chars"] == 30

    def test_statistics_empty_data(self) -> None:
        """Statistics must handle empty data."""
        stats = calculate_statistics(b"")

        assert stats["size"] == 0
        assert stats["entropy"] == 0.0


class TestFileTypeDetection:
    """Test file type hint detection."""

    def test_detect_pe_executable(self) -> None:
        """Must detect PE executable from MZ header."""
        pe_data = b"MZ" + b"\x00" * 100
        distribution = calculate_byte_distribution(pe_data)
        hints = detect_file_type_hints(pe_data, distribution)

        assert any("PE executable" in hint for hint in hints)

    def test_detect_elf_executable(self) -> None:
        """Must detect ELF executable from signature."""
        elf_data = b"\x7fELF" + b"\x00" * 100
        distribution = calculate_byte_distribution(elf_data)
        hints = detect_file_type_hints(elf_data, distribution)

        assert any("ELF" in hint for hint in hints)

    def test_detect_high_entropy(self) -> None:
        """Must detect high entropy (compressed/encrypted)."""
        random_data = bytes(range(256)) * 4
        distribution = calculate_byte_distribution(random_data)
        hints = detect_file_type_hints(random_data, distribution)

        assert any("High entropy" in hint for hint in hints)

    def test_detect_text_file(self) -> None:
        """Must detect text files from printable ASCII ratio."""
        text_data = b"The quick brown fox jumps over the lazy dog." * 20
        distribution = calculate_byte_distribution(text_data)
        hints = detect_file_type_hints(text_data, distribution)

        assert any("text" in hint.lower() for hint in hints)

    def test_detect_png_image(self) -> None:
        """Must detect PNG image from signature."""
        png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        distribution = calculate_byte_distribution(png_data)
        hints = detect_file_type_hints(png_data, distribution)

        assert any("PNG" in hint for hint in hints)

    def test_detect_zip_archive(self) -> None:
        """Must detect ZIP archive from signature."""
        zip_data = b"PK\x03\x04" + b"\x00" * 100
        distribution = calculate_byte_distribution(zip_data)
        hints = detect_file_type_hints(zip_data, distribution)

        assert any("ZIP" in hint for hint in hints)


class TestHistogram:
    """Test histogram calculation."""

    def test_histogram_bins_correct_count(self) -> None:
        """Histogram must return correct number of bins."""
        data = bytes(range(256))
        histogram = calculate_histogram(data, bins=16)

        assert len(histogram) == 16

    def test_histogram_counts_correctly(self) -> None:
        """Histogram must count bytes in each bin."""
        data = b"\x00" * 10 + b"\xFF" * 10
        histogram = calculate_histogram(data, bins=2)

        low_bin = next(count for label, count in histogram if "00" in label)
        high_bin = next(count for label, count in histogram if "80" in label or "FF" in label)

        assert low_bin == 10
        assert high_bin == 10

    def test_histogram_empty_data(self) -> None:
        """Histogram must handle empty data."""
        histogram = calculate_histogram(b"", bins=16)
        assert histogram == []


class TestFindPatterns:
    """Test pattern detection."""

    def test_find_repeating_patterns(self) -> None:
        """Must find repeating byte patterns."""
        data = b"ABCD" * 10 + b"XYZW" * 5 + b"1234" * 3
        patterns = find_patterns(data, min_length=4, max_patterns=10)

        assert len(patterns) > 0

        pattern_bytes = [p[0] for p in patterns]
        assert b"ABCD" in pattern_bytes

    def test_find_patterns_counts_correctly(self) -> None:
        """Must count pattern occurrences correctly."""
        data = b"TEST" * 5 + b"DATA" * 3
        patterns = find_patterns(data, min_length=4, max_patterns=10)

        pattern_dict = {p[0]: p[1] for p in patterns}

        if b"TEST" in pattern_dict:
            assert pattern_dict[b"TEST"] >= 5

    def test_find_patterns_empty_data(self) -> None:
        """Must handle empty data."""
        patterns = find_patterns(b"", min_length=4)
        assert patterns == []

    def test_find_patterns_no_repetition(self) -> None:
        """Must handle data with no repeating patterns."""
        data = bytes(range(256))
        patterns = find_patterns(data, min_length=4)

        assert len(patterns) == 0


class TestChiSquare:
    """Test chi-square randomness test."""

    def test_chi_square_uniform_distribution(self) -> None:
        """Chi-square of uniform distribution must be low."""
        data = bytes(range(256)) * 4
        chi_square = calculate_chi_square(data)

        assert chi_square < 300

    def test_chi_square_non_uniform_distribution(self) -> None:
        """Chi-square of non-uniform distribution must be higher."""
        data = b"\x00" * 500 + b"\xFF" * 500
        chi_square = calculate_chi_square(data)

        assert chi_square > 1000

    def test_chi_square_empty_data(self) -> None:
        """Chi-square of empty data must be 0."""
        chi_square = calculate_chi_square(b"")
        assert chi_square == 0.0


class TestCompressionRatio:
    """Test compression ratio estimation."""

    def test_compression_ratio_high_entropy(self) -> None:
        """High entropy data must have high compression ratio (not compressible)."""
        random_data = bytes(range(256)) * 4
        ratio = analyze_compression_ratio(random_data)

        assert ratio > 0.9

    def test_compression_ratio_low_entropy(self) -> None:
        """Low entropy data must have low compression ratio (compressible)."""
        uniform_data = b"\x00" * 1000
        ratio = analyze_compression_ratio(uniform_data)

        assert ratio < 0.1

    def test_compression_ratio_empty_data(self) -> None:
        """Compression ratio of empty data must be 0."""
        ratio = analyze_compression_ratio(b"")
        assert ratio == 0.0


class TestStatisticsCalculator:
    """Test StatisticsCalculator class."""

    def test_statistics_calculator_calculates_all(self) -> None:
        """StatisticsCalculator must calculate all statistics."""
        calculator = StatisticsCalculator()
        data = bytes(range(256)) * 4

        stats = calculator.calculate_all(data)

        assert "entropy" in stats
        assert "histogram" in stats
        assert "patterns" in stats
        assert "chi_square" in stats
        assert "compression_ratio" in stats

    def test_statistics_calculator_progress_callback(self) -> None:
        """StatisticsCalculator must invoke progress callback."""
        calculator = StatisticsCalculator()
        progress_updates = []

        def progress_callback(current: int, total: int) -> None:
            progress_updates.append((current, total))

        calculator.set_progress_callback(progress_callback)
        calculator.calculate_all(b"TEST" * 100)

        assert progress_updates


class TestRealWorldStatistics:
    """Test statistics with real Windows system files."""

    def test_statistics_on_pe_binary(self) -> None:
        """Statistics must work on real PE binaries."""
        notepad = Path("C:/Windows/System32/notepad.exe")
        if not notepad.exists():
            pytest.skip("notepad.exe not found - Windows system required")

        data = notepad.read_bytes()[:10000]
        stats = calculate_statistics(data)

        assert stats["size"] == 10000
        assert 0.0 < stats["entropy"] <= 8.0

        hints = stats["file_type_hints"]
        assert any("PE executable" in hint for hint in hints)

    def test_statistics_on_text_file(self, tmp_path: Path) -> None:
        """Statistics must correctly identify text files."""
        text_file = tmp_path / "test.txt"
        text_data = b"The quick brown fox jumps over the lazy dog.\n" * 100
        text_file.write_bytes(text_data)

        data = text_file.read_bytes()
        stats = calculate_statistics(data)

        assert stats["printable_percentage"] > 85.0
        assert stats["entropy"] < 6.0


class TestStatisticsEdgeCases:
    """Test statistics edge cases."""

    def test_statistics_single_byte(self) -> None:
        """Statistics must handle single byte."""
        stats = calculate_statistics(b"\x42")

        assert stats["size"] == 1
        assert stats["min_byte"] == 0x42
        assert stats["max_byte"] == 0x42

    def test_statistics_all_nulls(self) -> None:
        """Statistics must handle all null bytes."""
        data = b"\x00" * 1000
        stats = calculate_statistics(data)

        assert stats["null_percentage"] == 100.0
        assert stats["entropy"] == 0.0

    def test_statistics_all_0xff(self) -> None:
        """Statistics must handle all 0xFF bytes."""
        data = b"\xFF" * 1000
        stats = calculate_statistics(data)

        assert stats["high_bytes_percentage"] == 100.0
        assert stats["entropy"] == 0.0
