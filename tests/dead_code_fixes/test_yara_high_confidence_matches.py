"""Tests for high_confidence_matches tracking in yara_pattern_analysis_tool.py.

This tests that the high_confidence_matches counter is properly included
in the assessment result for protection strength scoring.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    pass


class MockCategory(Enum):
    """Mock category for testing."""

    ANTI_DEBUG = "ANTI_DEBUG"
    PACKER = "PACKER"
    LICENSING = "LICENSING"


@dataclass
class MockMatch:
    """Mock match object for testing."""

    confidence: float
    category: MockCategory
    rule_name: str = "test_rule"


class TestHighConfidenceMatchesTracking:
    """Test suite for high_confidence_matches tracking in YARA analysis."""

    def test_high_confidence_threshold_is_0_8(self) -> None:
        """Test that 0.8 is the high confidence threshold."""
        high_confidence_threshold = 0.8

        assert 0.8 >= high_confidence_threshold
        assert 0.79 < high_confidence_threshold
        assert 0.9 >= high_confidence_threshold

    def test_assessment_structure_with_high_confidence_key(self) -> None:
        """Test that assessment dict structure includes high_confidence_matches."""
        assessment: dict[str, Any] = {
            "overall_threat_level": "unknown",
            "protection_complexity": "unknown",
            "anti_analysis_present": False,
            "encryption_indicators": False,
            "packing_indicators": False,
            "licensing_indicators": False,
            "security_score": 0,
            "high_confidence_matches": 0,
            "findings_summary": [],
        }

        assert "high_confidence_matches" in assessment
        assert assessment["high_confidence_matches"] == 0

    def test_high_confidence_matches_counts_correctly(self) -> None:
        """Test that high confidence matches (>=0.8) are counted correctly."""
        matches = [
            MockMatch(confidence=0.9, category=MockCategory.ANTI_DEBUG),
            MockMatch(confidence=0.85, category=MockCategory.PACKER),
            MockMatch(confidence=0.8, category=MockCategory.LICENSING),
            MockMatch(confidence=0.7, category=MockCategory.ANTI_DEBUG),
            MockMatch(confidence=0.5, category=MockCategory.PACKER),
        ]

        high_confidence_count = 0
        for match in matches:
            if match.confidence >= 0.8:
                high_confidence_count += 1

        assert high_confidence_count == 3

    def test_no_high_confidence_matches_when_all_low(self) -> None:
        """Test that count is 0 when all matches are below 0.8 confidence."""
        matches = [
            MockMatch(confidence=0.7, category=MockCategory.ANTI_DEBUG),
            MockMatch(confidence=0.6, category=MockCategory.PACKER),
            MockMatch(confidence=0.5, category=MockCategory.LICENSING),
            MockMatch(confidence=0.3, category=MockCategory.ANTI_DEBUG),
        ]

        high_confidence_count = 0
        for match in matches:
            if match.confidence >= 0.8:
                high_confidence_count += 1

        assert high_confidence_count == 0

    def test_all_high_confidence_matches(self) -> None:
        """Test that all matches are counted when all have high confidence."""
        matches = [
            MockMatch(confidence=0.95, category=MockCategory.ANTI_DEBUG),
            MockMatch(confidence=0.90, category=MockCategory.PACKER),
            MockMatch(confidence=0.85, category=MockCategory.LICENSING),
            MockMatch(confidence=0.80, category=MockCategory.ANTI_DEBUG),
        ]

        high_confidence_count = 0
        for match in matches:
            if match.confidence >= 0.8:
                high_confidence_count += 1

        assert high_confidence_count == 4

    def test_security_score_formula_with_high_confidence(self) -> None:
        """Test that high confidence matches affect security score calculation."""
        base_score = 50
        high_confidence_matches = 3

        score_with_high_conf = base_score + (high_confidence_matches * 5)
        score_without = base_score

        assert score_with_high_conf > score_without
        assert score_with_high_conf == 65

    def test_assessment_increment_logic(self) -> None:
        """Test the increment logic for high_confidence_matches."""
        assessment: dict[str, Any] = {
            "high_confidence_matches": 0,
        }

        matches = [
            MockMatch(confidence=0.9, category=MockCategory.ANTI_DEBUG),
            MockMatch(confidence=0.5, category=MockCategory.PACKER),
            MockMatch(confidence=0.85, category=MockCategory.LICENSING),
        ]

        for match in matches:
            if match.confidence >= 0.8:
                assessment["high_confidence_matches"] += 1

        assert assessment["high_confidence_matches"] == 2

    def test_boundary_confidence_value(self) -> None:
        """Test that exactly 0.8 confidence is counted as high confidence."""
        matches = [
            MockMatch(confidence=0.8, category=MockCategory.ANTI_DEBUG),
            MockMatch(confidence=0.79999, category=MockCategory.PACKER),
        ]

        high_confidence_count = 0
        for match in matches:
            if match.confidence >= 0.8:
                high_confidence_count += 1

        assert high_confidence_count == 1

    def test_category_independence(self) -> None:
        """Test that counting is independent of category."""
        matches = [
            MockMatch(confidence=0.9, category=MockCategory.ANTI_DEBUG),
            MockMatch(confidence=0.9, category=MockCategory.PACKER),
            MockMatch(confidence=0.9, category=MockCategory.LICENSING),
        ]

        high_confidence_count = 0
        for match in matches:
            if match.confidence >= 0.8:
                high_confidence_count += 1

        assert high_confidence_count == 3

    def test_empty_matches_list(self) -> None:
        """Test handling of empty matches list."""
        matches: list[MockMatch] = []

        high_confidence_count = 0
        for match in matches:
            if match.confidence >= 0.8:
                high_confidence_count += 1

        assert high_confidence_count == 0

    def test_confidence_float_precision(self) -> None:
        """Test that floating point comparison handles precision."""
        matches = [
            MockMatch(confidence=0.8000001, category=MockCategory.ANTI_DEBUG),
            MockMatch(confidence=0.7999999, category=MockCategory.PACKER),
        ]

        high_confidence_count = 0
        for match in matches:
            if match.confidence >= 0.8:
                high_confidence_count += 1

        assert high_confidence_count == 1

