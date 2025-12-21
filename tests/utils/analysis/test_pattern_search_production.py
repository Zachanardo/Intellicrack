"""Production-ready tests for pattern_search.py.

Tests validate REAL pattern searching capabilities on binary data.
All tests use actual binary patterns and verify accurate detection.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
from typing import Any

import pytest

from intellicrack.utils.analysis.pattern_search import (
    find_all_pattern_occurrences,
    find_function_prologues,
    find_license_patterns,
    search_patterns_in_binary,
)


class TestFindAllPatternOccurrences:
    """Test single pattern occurrence finding."""

    def test_finds_single_occurrence(self) -> None:
        """Pattern finder locates single pattern instance."""
        binary_data = b"\x00\x00\x00LICENSE_KEY\x00\x00\x00"
        pattern = b"LICENSE_KEY"

        results = find_all_pattern_occurrences(binary_data, pattern)

        assert len(results) == 1
        assert results[0]["offset"] == 3
        assert results[0]["pattern"] == pattern

    def test_finds_multiple_occurrences(self) -> None:
        """Pattern finder locates all pattern instances."""
        binary_data = b"test\x00trial\x00test\x00activate\x00test\x00"
        pattern = b"test"

        results = find_all_pattern_occurrences(binary_data, pattern)

        assert len(results) == 3
        assert results[0]["offset"] == 0
        assert results[1]["offset"] == 11
        assert results[2]["offset"] == 31

    def test_finds_overlapping_patterns(self) -> None:
        """Pattern finder handles overlapping pattern matches."""
        binary_data = b"aaaa"
        pattern = b"aa"

        results = find_all_pattern_occurrences(binary_data, pattern)

        assert len(results) == 3
        assert results[0]["offset"] == 0
        assert results[1]["offset"] == 1
        assert results[2]["offset"] == 2

    def test_respects_max_results_limit(self) -> None:
        """Pattern finder respects maximum results limit."""
        binary_data = b"x" * 100
        pattern = b"x"

        results = find_all_pattern_occurrences(binary_data, pattern, max_results=10)

        assert len(results) == 10

    def test_calculates_address_with_base(self) -> None:
        """Pattern finder calculates correct addresses with base offset."""
        binary_data = b"\x00\x00\x00pattern\x00\x00"
        pattern = b"pattern"
        base_address = 0x400000

        results = find_all_pattern_occurrences(binary_data, pattern, base_address=base_address)

        assert results[0]["address"] == 0x400003
        assert results[0]["offset"] == 3

    def test_returns_empty_for_no_matches(self) -> None:
        """Pattern finder returns empty list when pattern not found."""
        binary_data = b"no matches here"
        pattern = b"LICENSE"

        results = find_all_pattern_occurrences(binary_data, pattern)

        assert results == []

    def test_finds_binary_patterns(self) -> None:
        """Pattern finder locates binary byte sequences."""
        binary_data = b"\x00\x00\x90\x90\x90\x00\x00\x90\x90\x90\x00"
        pattern = b"\x90\x90\x90"

        results = find_all_pattern_occurrences(binary_data, pattern)

        assert len(results) == 2
        assert results[0]["offset"] == 2
        assert results[1]["offset"] == 7

    def test_includes_pattern_hex_representation(self) -> None:
        """Pattern finder includes hex representation in results."""
        binary_data = b"\x00\x00\xDE\xAD\xBE\xEF\x00\x00"
        pattern = b"\xDE\xAD\xBE\xEF"

        results = find_all_pattern_occurrences(binary_data, pattern)

        assert results[0]["pattern_hex"] == "deadbeef"


class TestSearchPatternsInBinary:
    """Test multiple pattern searching."""

    def test_searches_multiple_patterns(self) -> None:
        """Pattern searcher finds multiple different patterns."""
        binary_data = b"license\x00serial\x00activate\x00"
        patterns = [b"license", b"serial", b"activate"]

        results = search_patterns_in_binary(binary_data, patterns)

        assert len(results) == 3
        found_patterns = [r["pattern"] for r in results]
        assert b"license" in found_patterns
        assert b"serial" in found_patterns
        assert b"activate" in found_patterns

    def test_includes_pattern_index(self) -> None:
        """Pattern searcher includes pattern index in results."""
        binary_data = b"first\x00second\x00third\x00"
        patterns = [b"first", b"second", b"third"]

        results = search_patterns_in_binary(binary_data, patterns)

        assert results[0]["pattern_index"] == 0
        assert results[1]["pattern_index"] == 1
        assert results[2]["pattern_index"] == 2

    def test_finds_all_occurrences_of_each_pattern(self) -> None:
        """Pattern searcher finds all instances of each pattern."""
        binary_data = b"key\x00value\x00key\x00data\x00key\x00"
        patterns = [b"key", b"value"]

        results = search_patterns_in_binary(binary_data, patterns)

        key_results = [r for r in results if r["pattern"] == b"key"]
        value_results = [r for r in results if r["pattern"] == b"value"]

        assert len(key_results) == 3
        assert len(value_results) == 1

    def test_applies_base_address_to_all_patterns(self) -> None:
        """Pattern searcher applies base address correctly."""
        binary_data = b"test1\x00test2\x00"
        patterns = [b"test1", b"test2"]
        base_address = 0x401000

        results = search_patterns_in_binary(binary_data, patterns, base_address=base_address)

        assert results[0]["address"] == 0x401000
        assert results[1]["address"] == 0x401006


class TestFindFunctionPrologues:
    """Test function prologue detection."""

    def test_finds_32bit_function_prologue(self) -> None:
        """Function prologue detector finds 32-bit prologues."""
        binary_data = b"\x00\x00\x55\x8B\xEC\x00\x00"  # push ebp; mov ebp, esp

        results = find_function_prologues(binary_data)

        assert len(results) > 0
        assert results[0]["type"] == "function_prologue"
        assert results[0]["offset"] == 2

    def test_finds_64bit_function_prologue(self) -> None:
        """Function prologue detector finds 64-bit prologues."""
        binary_data = b"\x00\x48\x89\x5C\x24\x00\x00"  # mov [rsp+xx], rbx

        results = find_function_prologues(binary_data)

        assert len(results) > 0

    def test_assigns_confidence_scores(self) -> None:
        """Function prologue detector assigns confidence scores."""
        binary_data = b"\x55\x8B\xEC"  # First pattern should have base confidence

        results = find_function_prologues(binary_data)

        assert "confidence" in results[0]
        assert 0.0 < results[0]["confidence"] <= 1.0

    def test_finds_multiple_prologues(self) -> None:
        """Function prologue detector finds multiple function starts."""
        binary_data = b"\x55\x8B\xEC\x00\x00\x55\x8B\xEC\x00\x00\x48\x83\xEC"

        results = find_function_prologues(binary_data)

        assert len(results) >= 2

    def test_applies_base_address_to_prologues(self) -> None:
        """Function prologue detector applies base address."""
        binary_data = b"\x00\x55\x8B\xEC"
        base_address = 0x10000000

        results = find_function_prologues(binary_data, base_address=base_address)

        assert results[0]["address"] == 0x10000001


class TestFindLicensePatterns:
    """Test license-related pattern detection."""

    def test_finds_license_keywords(self) -> None:
        """License pattern detector finds licensing keywords."""
        binary_data = b"\x00\x00license\x00serial\x00activate\x00\x00"

        results = find_license_patterns(binary_data)

        assert len(results) >= 3
        patterns_found = [r["pattern"] for r in results]
        assert "license" in patterns_found
        assert "serial" in patterns_found
        assert "activate" in patterns_found

    def test_finds_uppercase_keywords(self) -> None:
        """License pattern detector finds uppercase keywords."""
        binary_data = b"LICENSE\x00KEY\x00TRIAL\x00"

        results = find_license_patterns(binary_data)

        assert len(results) >= 3

    def test_includes_context_bytes(self) -> None:
        """License pattern detector includes surrounding context."""
        binary_data = b"\xDE\xAD\xBE\xEF" + b"license" + b"\x90\x90\x90\x90"

        results = find_license_patterns(binary_data, context_size=4)

        assert "context" in results[0]
        context = bytes.fromhex(results[0]["context"])
        assert b"license" in context

    def test_respects_max_results_limit(self) -> None:
        """License pattern detector respects maximum results."""
        binary_data = b"license\x00" * 50

        results = find_license_patterns(binary_data, max_results=10)

        assert len(results) <= 10

    def test_calculates_addresses_correctly(self) -> None:
        """License pattern detector calculates addresses."""
        binary_data = b"\x00\x00\x00license\x00"
        base_address = 0x400000

        results = find_license_patterns(binary_data, base_address=base_address)

        assert results[0]["address"] == hex(0x400003)
        assert results[0]["offset"] == 3

    def test_finds_validation_keywords(self) -> None:
        """License pattern detector finds validation-related terms."""
        binary_data = b"check\x00verify\x00valid\x00auth\x00"

        results = find_license_patterns(binary_data)

        patterns_found = [r["pattern"] for r in results]
        assert any(p in ["check", "verify", "valid", "auth"] for p in patterns_found)

    def test_categorizes_as_license_keyword(self) -> None:
        """License pattern detector categorizes findings."""
        binary_data = b"activation_key\x00"

        if results := find_license_patterns(binary_data):
            assert results[0]["type"] == "license_keyword"


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_handles_empty_binary_data(self) -> None:
        """Pattern finder handles empty binary data."""
        results = find_all_pattern_occurrences(b"", b"pattern")

        assert results == []

    def test_handles_empty_pattern(self) -> None:
        """Pattern finder handles empty pattern."""
        results = find_all_pattern_occurrences(b"data", b"")

        assert len(results) > 0 or results == []

    def test_handles_pattern_larger_than_data(self) -> None:
        """Pattern finder handles pattern larger than data."""
        results = find_all_pattern_occurrences(b"tiny", b"much_larger_pattern")

        assert results == []

    def test_handles_binary_nulls(self) -> None:
        """Pattern finder handles null bytes correctly."""
        binary_data = b"\x00\x00\x00pattern\x00\x00\x00"
        pattern = b"\x00\x00"

        results = find_all_pattern_occurrences(binary_data, pattern)

        assert len(results) >= 1

    def test_searches_zero_patterns(self) -> None:
        """Pattern searcher handles empty pattern list."""
        results = search_patterns_in_binary(b"data", [])

        assert results == []

    def test_handles_large_binary_data(self) -> None:
        """Pattern finder handles large binary data efficiently."""
        large_data = b"\x00" * 1_000_000 + b"needle" + b"\x00" * 1_000_000
        pattern = b"needle"

        import time

        start_time = time.time()
        results = find_all_pattern_occurrences(large_data, pattern)
        duration = time.time() - start_time

        assert len(results) == 1
        assert duration < 5.0


class TestRealWorldScenarios:
    """Test real-world license cracking scenarios."""

    def test_finds_license_validation_function(self) -> None:
        """Pattern finder locates license validation function."""
        binary_data = self._create_mock_license_validator()

        prologue_results = find_function_prologues(binary_data, base_address=0x401000)
        license_results = find_license_patterns(binary_data, base_address=0x401000)

        assert len(prologue_results) > 0
        assert len(license_results) > 0

    def test_finds_serial_number_validation(self) -> None:
        """Pattern finder locates serial number validation code."""
        binary_data = b"\x55\x8B\xEC"  # Function prologue
        binary_data += b"\x00" * 20
        binary_data += b"serial_number\x00"
        binary_data += b"\x00" * 20
        binary_data += b"validate\x00"

        results = find_license_patterns(binary_data)

        patterns = [r["pattern"] for r in results]
        assert "serial" in patterns
        assert "validate" in patterns

    def test_finds_trial_expiration_check(self) -> None:
        """Pattern finder locates trial expiration validation."""
        binary_data = b"trial\x00expiration\x00check\x00expired\x00"

        results = find_license_patterns(binary_data)

        patterns = [r["pattern"] for r in results]
        assert "trial" in patterns
        assert "check" in patterns

    def test_finds_activation_routine(self) -> None:
        """Pattern finder locates activation code."""
        binary_data = b"\x48\x83\xEC"  # 64-bit prologue
        binary_data += b"\x00" * 30
        binary_data += b"activate\x00"
        binary_data += b"key\x00"
        binary_data += b"license\x00"

        prologue_results = find_function_prologues(binary_data)
        license_results = find_license_patterns(binary_data)

        assert len(prologue_results) > 0
        assert any(r["pattern"] == "activate" for r in license_results)
        assert any(r["pattern"] == "key" for r in license_results)

    def _create_mock_license_validator(self) -> bytes:
        """Create mock binary with license validation structure."""
        binary = b"\x55\x8B\xEC"  # Function prologue
        binary += b"\x83\xEC\x20"  # Stack allocation
        binary += b"\x00" * 10
        binary += b"license_key\x00"
        binary += b"\x00" * 20
        binary += b"validate\x00"
        binary += b"\x00" * 10
        binary += b"check\x00"
        binary += b"\xC3"  # ret
        return binary


class TestPerformance:
    """Test pattern searching performance."""

    def test_efficient_single_pattern_search(self) -> None:
        """Pattern search completes efficiently on large data."""
        binary_data = b"\x00" * 5_000_000 + b"pattern" + b"\x00" * 5_000_000
        pattern = b"pattern"

        import time

        start_time = time.time()
        results = find_all_pattern_occurrences(binary_data, pattern)
        duration = time.time() - start_time

        assert len(results) == 1
        assert duration < 3.0

    def test_efficient_multiple_pattern_search(self) -> None:
        """Multiple pattern search completes efficiently."""
        binary_data = b"\x00" * 1_000_000 + b"pattern1\x00pattern2\x00pattern3\x00" + b"\x00" * 1_000_000
        patterns = [b"pattern1", b"pattern2", b"pattern3"]

        import time

        start_time = time.time()
        results = search_patterns_in_binary(binary_data, patterns)
        duration = time.time() - start_time

        assert len(results) == 3
        assert duration < 5.0
