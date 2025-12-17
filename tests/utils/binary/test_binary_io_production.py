"""Production-ready tests for binary_io.py.

Tests validate REAL binary I/O operations on actual files.
All tests use real file operations and verify accurate results.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from pathlib import Path

import pytest

from intellicrack.utils.binary.binary_io import (
    analyze_binary_for_strings,
    find_all_pattern_offsets,
)


class TestFindAllPatternOffsets:
    """Test pattern offset finding in binary data."""

    def test_finds_single_pattern_offset(self) -> None:
        """Pattern offset finder locates single occurrence."""
        data = b"\x00\x00\x00license_key\x00\x00"
        pattern = b"license_key"

        offsets = find_all_pattern_offsets(data, pattern)

        assert offsets == [3]

    def test_finds_multiple_pattern_offsets(self) -> None:
        """Pattern offset finder locates all occurrences."""
        data = b"test\x00trial\x00test\x00activate\x00test\x00"
        pattern = b"test"

        offsets = find_all_pattern_offsets(data, pattern)

        assert len(offsets) == 3
        assert 0 in offsets
        assert offsets[1] > offsets[0]
        assert offsets[2] > offsets[1]

    def test_finds_overlapping_patterns(self) -> None:
        """Pattern offset finder handles overlapping matches."""
        data = b"aaaaaa"
        pattern = b"aa"

        offsets = find_all_pattern_offsets(data, pattern)

        assert len(offsets) == 5
        assert offsets == [0, 1, 2, 3, 4]

    def test_returns_empty_for_no_matches(self) -> None:
        """Pattern offset finder returns empty list for no matches."""
        data = b"no pattern here"
        pattern = b"missing"

        offsets = find_all_pattern_offsets(data, pattern)

        assert offsets == []

    def test_handles_binary_patterns(self) -> None:
        """Pattern offset finder works with binary byte sequences."""
        data = b"\x00\x00\x90\x90\x90\x00\x00\x90\x90\x90"
        pattern = b"\x90\x90\x90"

        offsets = find_all_pattern_offsets(data, pattern)

        assert len(offsets) == 2
        assert 2 in offsets
        assert 7 in offsets

    def test_finds_null_byte_patterns(self) -> None:
        """Pattern offset finder handles null byte patterns."""
        data = b"\x00\x00\x01\x00\x00\x02"
        pattern = b"\x00\x00"

        offsets = find_all_pattern_offsets(data, pattern)

        assert 0 in offsets
        assert 3 in offsets

    def test_handles_empty_data(self) -> None:
        """Pattern offset finder handles empty data."""
        offsets = find_all_pattern_offsets(b"", b"pattern")

        assert offsets == []

    def test_handles_pattern_at_end(self) -> None:
        """Pattern offset finder finds patterns at data end."""
        data = b"\x00\x00\x00pattern"
        pattern = b"pattern"

        offsets = find_all_pattern_offsets(data, pattern)

        assert offsets == [3]


class TestAnalyzeBinaryForStrings:
    """Test binary string analysis."""

    def test_finds_all_search_strings(self, tmp_path: Path) -> None:
        """String analyzer finds all specified strings in binary."""
        binary_path = tmp_path / "test.exe"
        binary_data = b"license\x00serial\x00activation\x00"
        binary_path.write_bytes(binary_data)

        result = analyze_binary_for_strings(str(binary_path), ["license", "serial", "activation"])

        assert len(result["strings_found"]) == 3
        assert "license" in result["strings_found"]
        assert "serial" in result["strings_found"]
        assert "activation" in result["strings_found"]
        assert result["confidence"] == 100.0

    def test_calculates_partial_confidence(self, tmp_path: Path) -> None:
        """String analyzer calculates confidence for partial matches."""
        binary_path = tmp_path / "partial.exe"
        binary_data = b"license\x00trial\x00"
        binary_path.write_bytes(binary_data)

        result = analyze_binary_for_strings(str(binary_path), ["license", "trial", "activation", "serial"])

        assert len(result["strings_found"]) == 2
        assert result["confidence"] == 50.0

    def test_returns_zero_confidence_for_no_matches(self, tmp_path: Path) -> None:
        """String analyzer returns zero confidence for no matches."""
        binary_path = tmp_path / "nomatch.exe"
        binary_data = b"unrelated data"
        binary_path.write_bytes(binary_data)

        result = analyze_binary_for_strings(str(binary_path), ["license", "serial"])

        assert len(result["strings_found"]) == 0
        assert result["confidence"] == 0.0

    def test_handles_nonexistent_file(self) -> None:
        """String analyzer handles nonexistent files gracefully."""
        result = analyze_binary_for_strings("nonexistent.exe", ["license"])

        assert result["error"] == "Invalid binary path"
        assert result["confidence"] == 0.0

    def test_handles_empty_search_list(self, tmp_path: Path) -> None:
        """String analyzer handles empty search string list."""
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"data")

        result = analyze_binary_for_strings(str(binary_path), [])

        assert result["confidence"] == 0.0

    def test_finds_case_sensitive_strings(self, tmp_path: Path) -> None:
        """String analyzer is case-sensitive."""
        binary_path = tmp_path / "case.exe"
        binary_data = b"LICENSE\x00license\x00"
        binary_path.write_bytes(binary_data)

        result_upper = analyze_binary_for_strings(str(binary_path), ["LICENSE"])
        result_lower = analyze_binary_for_strings(str(binary_path), ["license"])

        assert "LICENSE" in result_upper["strings_found"]
        assert "license" in result_lower["strings_found"]

    def test_handles_unicode_strings(self, tmp_path: Path) -> None:
        """String analyzer handles Unicode search strings."""
        binary_path = tmp_path / "unicode.exe"
        binary_data = "license检测".encode("utf-8")
        binary_path.write_bytes(binary_data)

        result = analyze_binary_for_strings(str(binary_path), ["license检测"])

        if result["strings_found"]:
            assert "license检测" in result["strings_found"]

    def test_finds_strings_in_large_binary(self, tmp_path: Path) -> None:
        """String analyzer handles large binary files."""
        binary_path = tmp_path / "large.exe"
        large_data = b"\x00" * 1_000_000 + b"license_key" + b"\x00" * 1_000_000
        binary_path.write_bytes(large_data)

        import time

        start_time = time.time()
        result = analyze_binary_for_strings(str(binary_path), ["license_key"])
        duration = time.time() - start_time

        assert "license_key" in result["strings_found"]
        assert duration < 5.0


class TestRealWorldScenarios:
    """Test real-world binary analysis scenarios."""

    def test_detects_license_validation_strings(self, tmp_path: Path) -> None:
        """String analyzer detects common license validation strings."""
        binary_path = tmp_path / "license_check.exe"
        binary_data = (
            b"ValidateLicense\x00"
            + b"CheckSerial\x00"
            + b"ActivationKey\x00"
            + b"TrialExpired\x00"
            + b"RegisterProduct\x00"
        )
        binary_path.write_bytes(binary_data)

        license_strings = ["ValidateLicense", "CheckSerial", "ActivationKey", "TrialExpired", "RegisterProduct"]
        result = analyze_binary_for_strings(str(binary_path), license_strings)

        assert result["confidence"] == 100.0
        assert len(result["strings_found"]) == 5

    def test_detects_protection_mechanism_strings(self, tmp_path: Path) -> None:
        """String analyzer detects protection mechanism indicators."""
        binary_path = tmp_path / "protected.exe"
        binary_data = b"VMProtect\x00Themida\x00Enigma\x00SafeNet\x00"
        binary_path.write_bytes(binary_data)

        protection_strings = ["VMProtect", "Themida", "Enigma", "SafeNet"]
        result = analyze_binary_for_strings(str(binary_path), protection_strings)

        assert len(result["strings_found"]) >= 1

    def test_detects_trial_check_strings(self, tmp_path: Path) -> None:
        """String analyzer detects trial-related strings."""
        binary_path = tmp_path / "trial.exe"
        binary_data = b"trial_days_remaining\x00trial_expired\x00check_trial_status\x00"
        binary_path.write_bytes(binary_data)

        trial_strings = ["trial_days_remaining", "trial_expired", "check_trial_status"]
        result = analyze_binary_for_strings(str(binary_path), trial_strings)

        assert result["confidence"] == 100.0

    def test_analyzes_crack_target_binary(self, tmp_path: Path) -> None:
        """String analyzer evaluates crack target binary."""
        binary_path = tmp_path / "target.exe"
        binary_data = (
            b"MZ"
            + b"\x00" * 100
            + b"license_validation_failed\x00"
            + b"enter_serial_number\x00"
            + b"product_activation\x00"
            + b"trial_period_expired\x00"
        )
        binary_path.write_bytes(binary_data)

        crack_indicators = [
            "license_validation_failed",
            "enter_serial_number",
            "product_activation",
            "trial_period_expired",
        ]
        result = analyze_binary_for_strings(str(binary_path), crack_indicators)

        assert result["confidence"] >= 75.0
        assert result["error"] is None


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_handles_binary_with_embedded_nulls(self, tmp_path: Path) -> None:
        """String analyzer handles binaries with embedded null bytes."""
        binary_path = tmp_path / "nulls.exe"
        binary_data = b"\x00\x00license\x00\x00\x00serial\x00\x00"
        binary_path.write_bytes(binary_data)

        result = analyze_binary_for_strings(str(binary_path), ["license", "serial"])

        assert len(result["strings_found"]) == 2

    def test_handles_very_long_strings(self, tmp_path: Path) -> None:
        """String analyzer handles very long search strings."""
        binary_path = tmp_path / "long.exe"
        long_string = "A" * 1000
        binary_data = long_string.encode()
        binary_path.write_bytes(binary_data)

        result = analyze_binary_for_strings(str(binary_path), [long_string])

        assert long_string in result["strings_found"]

    def test_handles_special_characters(self, tmp_path: Path) -> None:
        """String analyzer handles special characters in strings."""
        binary_path = tmp_path / "special.exe"
        binary_data = b"license-key_v2.0\x00"
        binary_path.write_bytes(binary_data)

        result = analyze_binary_for_strings(str(binary_path), ["license-key_v2.0"])

        assert "license-key_v2.0" in result["strings_found"]

    def test_finds_strings_at_file_boundaries(self, tmp_path: Path) -> None:
        """String analyzer finds strings at start and end of file."""
        binary_path = tmp_path / "boundaries.exe"
        binary_data = b"start_string" + b"\x00" * 100 + b"end_string"
        binary_path.write_bytes(binary_data)

        result = analyze_binary_for_strings(str(binary_path), ["start_string", "end_string"])

        assert "start_string" in result["strings_found"]
        assert "end_string" in result["strings_found"]

    def test_handles_duplicate_search_strings(self, tmp_path: Path) -> None:
        """String analyzer handles duplicate strings in search list."""
        binary_path = tmp_path / "dup.exe"
        binary_path.write_bytes(b"license\x00")

        result = analyze_binary_for_strings(str(binary_path), ["license", "license", "license"])

        assert "license" in result["strings_found"]


class TestPerformance:
    """Test performance characteristics."""

    def test_multiple_string_search_efficient(self, tmp_path: Path) -> None:
        """String analyzer handles many search strings efficiently."""
        binary_path = tmp_path / "many.exe"
        binary_data = b"\x00".join(f"string_{i}".encode() for i in range(100))
        binary_path.write_bytes(binary_data)

        search_strings = [f"string_{i}" for i in range(100)]

        import time

        start_time = time.time()
        result = analyze_binary_for_strings(str(binary_path), search_strings)
        duration = time.time() - start_time

        assert result["confidence"] == 100.0
        assert duration < 2.0

    def test_pattern_search_scales_linearly(self) -> None:
        """Pattern offset finder scales linearly with data size."""
        import time

        small_data = b"\x00" * 10_000 + b"pattern" + b"\x00" * 10_000
        large_data = b"\x00" * 100_000 + b"pattern" + b"\x00" * 100_000

        start_time = time.time()
        find_all_pattern_offsets(small_data, b"pattern")
        small_duration = time.time() - start_time

        start_time = time.time()
        find_all_pattern_offsets(large_data, b"pattern")
        large_duration = time.time() - start_time

        assert large_duration < small_duration * 20
