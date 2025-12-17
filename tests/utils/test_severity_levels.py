"""Production tests for utils/severity_levels.py.

This module validates severity level enums, risk calculation, and finding
prioritization for Intellicrack's vulnerability analysis reporting.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any

import pytest

from intellicrack.utils.severity_levels import (
    CONFIDENCE_MULTIPLIERS,
    SEVERITY_COLORS,
    SEVERITY_SCORES,
    THREAT_SCORES,
    ConfidenceLevel,
    SecurityRelevance,
    SeverityLevel,
    ThreatLevel,
    VulnerabilityLevel,
    aggregate_severity_stats,
    calculate_risk_score,
    format_severity_report,
    get_severity_color,
    get_severity_from_score,
    get_threat_from_score,
    prioritize_findings,
)


class TestSeverityLevelEnum:
    """Test SeverityLevel enumeration."""

    def test_severity_level_values(self) -> None:
        """SeverityLevel enum contains all required severity levels."""
        assert SeverityLevel.CRITICAL.value == "critical"
        assert SeverityLevel.HIGH.value == "high"
        assert SeverityLevel.MEDIUM.value == "medium"
        assert SeverityLevel.LOW.value == "low"
        assert SeverityLevel.INFO.value == "info"

    def test_severity_level_count(self) -> None:
        """SeverityLevel enum has exactly 5 levels."""
        assert len(list(SeverityLevel)) == 5

    def test_severity_level_uniqueness(self) -> None:
        """SeverityLevel enum values are unique."""
        values = [level.value for level in SeverityLevel]
        assert len(values) == len(set(values))


class TestVulnerabilityLevelEnum:
    """Test VulnerabilityLevel enumeration (alias for SeverityLevel)."""

    def test_vulnerability_level_matches_severity(self) -> None:
        """VulnerabilityLevel has same values as SeverityLevel."""
        assert VulnerabilityLevel.CRITICAL.value == SeverityLevel.CRITICAL.value
        assert VulnerabilityLevel.HIGH.value == SeverityLevel.HIGH.value
        assert VulnerabilityLevel.MEDIUM.value == SeverityLevel.MEDIUM.value
        assert VulnerabilityLevel.LOW.value == SeverityLevel.LOW.value
        assert VulnerabilityLevel.INFO.value == SeverityLevel.INFO.value


class TestSecurityRelevanceEnum:
    """Test SecurityRelevance enumeration (alias for SeverityLevel)."""

    def test_security_relevance_matches_severity(self) -> None:
        """SecurityRelevance has same values as SeverityLevel."""
        assert SecurityRelevance.CRITICAL.value == SeverityLevel.CRITICAL.value
        assert SecurityRelevance.HIGH.value == SeverityLevel.HIGH.value
        assert SecurityRelevance.MEDIUM.value == SeverityLevel.MEDIUM.value
        assert SecurityRelevance.LOW.value == SeverityLevel.LOW.value
        assert SecurityRelevance.INFO.value == SeverityLevel.INFO.value


class TestThreatLevelEnum:
    """Test ThreatLevel enumeration."""

    def test_threat_level_values(self) -> None:
        """ThreatLevel enum contains all threat assessment levels."""
        assert ThreatLevel.IMMINENT.value == "imminent"
        assert ThreatLevel.LIKELY.value == "likely"
        assert ThreatLevel.POSSIBLE.value == "possible"
        assert ThreatLevel.UNLIKELY.value == "unlikely"
        assert ThreatLevel.NONE.value == "none"

    def test_threat_level_count(self) -> None:
        """ThreatLevel enum has exactly 5 levels."""
        assert len(list(ThreatLevel)) == 5


class TestConfidenceLevelEnum:
    """Test ConfidenceLevel enumeration."""

    def test_confidence_level_values(self) -> None:
        """ConfidenceLevel enum contains all confidence levels."""
        assert ConfidenceLevel.VERY_HIGH.value == "very_high"
        assert ConfidenceLevel.HIGH.value == "high"
        assert ConfidenceLevel.MEDIUM.value == "medium"
        assert ConfidenceLevel.LOW.value == "low"
        assert ConfidenceLevel.VERY_LOW.value == "very_low"

    def test_confidence_level_count(self) -> None:
        """ConfidenceLevel enum has exactly 5 levels."""
        assert len(list(ConfidenceLevel)) == 5


class TestSeverityConstants:
    """Test severity-related constant dictionaries."""

    def test_severity_colors_completeness(self) -> None:
        """SEVERITY_COLORS contains color for each severity level."""
        assert len(SEVERITY_COLORS) == 5
        for level in SeverityLevel:
            assert level in SEVERITY_COLORS
            assert isinstance(SEVERITY_COLORS[level], str)
            assert SEVERITY_COLORS[level].startswith("#")

    def test_severity_colors_values(self) -> None:
        """SEVERITY_COLORS uses appropriate colors for each level."""
        assert SEVERITY_COLORS[SeverityLevel.CRITICAL] == "#FF0000"
        assert SEVERITY_COLORS[SeverityLevel.HIGH] == "#FF6600"
        assert SEVERITY_COLORS[SeverityLevel.MEDIUM] == "#FFAA00"
        assert SEVERITY_COLORS[SeverityLevel.LOW] == "#FFFF00"
        assert SEVERITY_COLORS[SeverityLevel.INFO] == "#00AA00"

    def test_severity_scores_completeness(self) -> None:
        """SEVERITY_SCORES contains score for each severity level."""
        assert len(SEVERITY_SCORES) == 5
        for level in SeverityLevel:
            assert level in SEVERITY_SCORES
            assert isinstance(SEVERITY_SCORES[level], float)

    def test_severity_scores_ordering(self) -> None:
        """SEVERITY_SCORES are ordered from highest to lowest."""
        scores = [
            SEVERITY_SCORES[SeverityLevel.CRITICAL],
            SEVERITY_SCORES[SeverityLevel.HIGH],
            SEVERITY_SCORES[SeverityLevel.MEDIUM],
            SEVERITY_SCORES[SeverityLevel.LOW],
            SEVERITY_SCORES[SeverityLevel.INFO],
        ]
        assert scores == sorted(scores, reverse=True)

    def test_threat_scores_completeness(self) -> None:
        """THREAT_SCORES contains score for each threat level."""
        assert len(THREAT_SCORES) == 5
        for level in ThreatLevel:
            assert level in THREAT_SCORES
            assert isinstance(THREAT_SCORES[level], float)

    def test_threat_scores_ordering(self) -> None:
        """THREAT_SCORES are ordered from highest to lowest."""
        scores = [
            THREAT_SCORES[ThreatLevel.IMMINENT],
            THREAT_SCORES[ThreatLevel.LIKELY],
            THREAT_SCORES[ThreatLevel.POSSIBLE],
            THREAT_SCORES[ThreatLevel.UNLIKELY],
            THREAT_SCORES[ThreatLevel.NONE],
        ]
        assert scores == sorted(scores, reverse=True)

    def test_confidence_multipliers_completeness(self) -> None:
        """CONFIDENCE_MULTIPLIERS contains multiplier for each confidence level."""
        assert len(CONFIDENCE_MULTIPLIERS) == 5
        for level in ConfidenceLevel:
            assert level in CONFIDENCE_MULTIPLIERS
            assert isinstance(CONFIDENCE_MULTIPLIERS[level], float)

    def test_confidence_multipliers_range(self) -> None:
        """CONFIDENCE_MULTIPLIERS are between 0 and 1."""
        for multiplier in CONFIDENCE_MULTIPLIERS.values():
            assert 0.0 <= multiplier <= 1.0


class TestGetSeverityFromScore:
    """Test get_severity_from_score function."""

    @pytest.mark.parametrize(
        "score,expected_severity",
        [
            (10.0, SeverityLevel.CRITICAL),
            (9.5, SeverityLevel.CRITICAL),
            (9.0, SeverityLevel.CRITICAL),
            (8.5, SeverityLevel.HIGH),
            (7.0, SeverityLevel.HIGH),
            (6.0, SeverityLevel.MEDIUM),
            (4.0, SeverityLevel.MEDIUM),
            (3.5, SeverityLevel.LOW),
            (2.0, SeverityLevel.LOW),
            (1.5, SeverityLevel.INFO),
            (0.0, SeverityLevel.INFO),
        ],
    )
    def test_severity_from_score_mapping(self, score: float, expected_severity: SeverityLevel) -> None:
        """get_severity_from_score maps scores to correct severity levels."""
        result = get_severity_from_score(score)
        assert result == expected_severity

    def test_severity_from_score_boundary_critical(self) -> None:
        """get_severity_from_score correctly handles critical boundary."""
        assert get_severity_from_score(9.0) == SeverityLevel.CRITICAL
        assert get_severity_from_score(8.99) == SeverityLevel.HIGH

    def test_severity_from_score_boundary_high(self) -> None:
        """get_severity_from_score correctly handles high boundary."""
        assert get_severity_from_score(7.0) == SeverityLevel.HIGH
        assert get_severity_from_score(6.99) == SeverityLevel.MEDIUM


class TestGetThreatFromScore:
    """Test get_threat_from_score function."""

    @pytest.mark.parametrize(
        "score,expected_threat",
        [
            (10.0, ThreatLevel.IMMINENT),
            (8.0, ThreatLevel.IMMINENT),
            (7.5, ThreatLevel.LIKELY),
            (6.0, ThreatLevel.LIKELY),
            (5.0, ThreatLevel.POSSIBLE),
            (3.0, ThreatLevel.POSSIBLE),
            (2.5, ThreatLevel.UNLIKELY),
            (1.0, ThreatLevel.UNLIKELY),
            (0.5, ThreatLevel.NONE),
            (0.0, ThreatLevel.NONE),
        ],
    )
    def test_threat_from_score_mapping(self, score: float, expected_threat: ThreatLevel) -> None:
        """get_threat_from_score maps scores to correct threat levels."""
        result = get_threat_from_score(score)
        assert result == expected_threat


class TestCalculateRiskScore:
    """Test calculate_risk_score function."""

    def test_risk_score_critical_imminent_high_confidence(self) -> None:
        """calculate_risk_score produces highest risk for critical imminent high confidence."""
        risk = calculate_risk_score(
            SeverityLevel.CRITICAL,
            ThreatLevel.IMMINENT,
            ConfidenceLevel.VERY_HIGH,
        )
        assert risk == 10.0

    def test_risk_score_info_none_low_confidence(self) -> None:
        """calculate_risk_score produces lowest risk for info none low confidence."""
        risk = calculate_risk_score(
            SeverityLevel.INFO,
            ThreatLevel.NONE,
            ConfidenceLevel.VERY_LOW,
        )
        assert risk == 0.0

    def test_risk_score_formula_correctness(self) -> None:
        """calculate_risk_score uses correct formula: (severity * threat) / 10 * confidence."""
        severity = SeverityLevel.HIGH
        threat = ThreatLevel.LIKELY
        confidence = ConfidenceLevel.MEDIUM

        severity_score = SEVERITY_SCORES[severity]
        threat_score = THREAT_SCORES[threat]
        confidence_mult = CONFIDENCE_MULTIPLIERS[confidence]

        expected = (severity_score * threat_score / 10.0) * confidence_mult

        result = calculate_risk_score(severity, threat, confidence)
        assert abs(result - expected) < 0.001

    def test_risk_score_range(self) -> None:
        """calculate_risk_score produces values in valid range 0-10."""
        for severity in SeverityLevel:
            for threat in ThreatLevel:
                for confidence in ConfidenceLevel:
                    risk = calculate_risk_score(severity, threat, confidence)
                    assert 0.0 <= risk <= 10.0


class TestGetSeverityColor:
    """Test get_severity_color function."""

    def test_severity_color_critical(self) -> None:
        """get_severity_color returns red for critical."""
        color = get_severity_color(SeverityLevel.CRITICAL)
        assert color == "#FF0000"

    def test_severity_color_all_levels(self) -> None:
        """get_severity_color returns correct color for all severity levels."""
        for level in SeverityLevel:
            color = get_severity_color(level)
            assert color == SEVERITY_COLORS[level]

    def test_severity_color_unknown_default(self) -> None:
        """get_severity_color returns gray for unknown severity."""
        color = get_severity_color("unknown")  # type: ignore[arg-type]
        assert color == "#808080"


class TestFormatSeverityReport:
    """Test format_severity_report function."""

    def test_format_empty_findings(self) -> None:
        """format_severity_report handles empty findings list."""
        report = format_severity_report([])
        assert report == "No findings to report."

    def test_format_single_finding(self) -> None:
        """format_severity_report formats single finding correctly."""
        findings = [
            {
                "severity": SeverityLevel.HIGH,
                "title": "License check bypass detected",
                "description": "Binary allows trial reset",
            }
        ]
        report = format_severity_report(findings)

        assert "Severity Report" in report
        assert "HIGH: 1 finding(s)" in report
        assert "License check bypass detected" in report

    def test_format_multiple_findings_grouped(self) -> None:
        """format_severity_report groups findings by severity."""
        findings = [
            {
                "severity": SeverityLevel.CRITICAL,
                "title": "Critical finding 1",
                "description": "Description 1",
            },
            {
                "severity": SeverityLevel.CRITICAL,
                "title": "Critical finding 2",
                "description": "Description 2",
            },
            {
                "severity": SeverityLevel.HIGH,
                "title": "High finding 1",
                "description": "Description 3",
            },
        ]
        report = format_severity_report(findings)

        assert "CRITICAL: 2 finding(s)" in report
        assert "HIGH: 1 finding(s)" in report
        assert "Critical finding 1" in report
        assert "Critical finding 2" in report

    def test_format_truncates_long_descriptions(self) -> None:
        """format_severity_report truncates descriptions longer than 80 characters."""
        long_desc = "A" * 100
        findings = [
            {
                "severity": SeverityLevel.MEDIUM,
                "title": "Test finding",
                "description": long_desc,
            }
        ]
        report = format_severity_report(findings)

        assert "..." in report
        assert long_desc not in report

    def test_format_limits_findings_per_severity(self) -> None:
        """format_severity_report shows maximum 5 findings per severity."""
        findings = [
            {
                "severity": SeverityLevel.LOW,
                "title": f"Finding {i}",
                "description": f"Description {i}",
            }
            for i in range(10)
        ]
        report = format_severity_report(findings)

        assert "... and 5 more" in report


class TestAggregateSeverityStats:
    """Test aggregate_severity_stats function."""

    def test_aggregate_empty_findings(self) -> None:
        """aggregate_severity_stats handles empty findings list."""
        stats = aggregate_severity_stats([])

        assert stats["total_findings"] == 0
        assert stats["by_severity"] == {}
        assert stats["risk_distribution"] == {}
        assert stats["average_risk_score"] == 0.0

    def test_aggregate_counts_by_severity(self) -> None:
        """aggregate_severity_stats counts findings by severity level."""
        findings = [
            {
                "severity": SeverityLevel.CRITICAL,
                "threat": ThreatLevel.IMMINENT,
                "confidence": ConfidenceLevel.HIGH,
            },
            {
                "severity": SeverityLevel.CRITICAL,
                "threat": ThreatLevel.LIKELY,
                "confidence": ConfidenceLevel.HIGH,
            },
            {
                "severity": SeverityLevel.HIGH,
                "threat": ThreatLevel.POSSIBLE,
                "confidence": ConfidenceLevel.MEDIUM,
            },
        ]
        stats = aggregate_severity_stats(findings)

        assert stats["total_findings"] == 3
        assert stats["by_severity"]["critical"] == 2
        assert stats["by_severity"]["high"] == 1

    def test_aggregate_calculates_risk_distribution(self) -> None:
        """aggregate_severity_stats categorizes findings by risk level."""
        findings = [
            {
                "severity": SeverityLevel.CRITICAL,
                "threat": ThreatLevel.IMMINENT,
                "confidence": ConfidenceLevel.VERY_HIGH,
            },
            {
                "severity": SeverityLevel.MEDIUM,
                "threat": ThreatLevel.POSSIBLE,
                "confidence": ConfidenceLevel.MEDIUM,
            },
            {
                "severity": SeverityLevel.LOW,
                "threat": ThreatLevel.UNLIKELY,
                "confidence": ConfidenceLevel.LOW,
            },
        ]
        stats = aggregate_severity_stats(findings)

        assert "high_risk" in stats["risk_distribution"]
        assert "medium_risk" in stats["risk_distribution"]
        assert "low_risk" in stats["risk_distribution"]

    def test_aggregate_calculates_average_risk(self) -> None:
        """aggregate_severity_stats computes average risk score correctly."""
        findings = [
            {
                "severity": SeverityLevel.HIGH,
                "threat": ThreatLevel.LIKELY,
                "confidence": ConfidenceLevel.HIGH,
            },
            {
                "severity": SeverityLevel.LOW,
                "threat": ThreatLevel.UNLIKELY,
                "confidence": ConfidenceLevel.LOW,
            },
        ]
        stats = aggregate_severity_stats(findings)

        risk1 = calculate_risk_score(SeverityLevel.HIGH, ThreatLevel.LIKELY, ConfidenceLevel.HIGH)
        risk2 = calculate_risk_score(SeverityLevel.LOW, ThreatLevel.UNLIKELY, ConfidenceLevel.LOW)
        expected_avg = (risk1 + risk2) / 2

        assert abs(stats["average_risk_score"] - expected_avg) < 0.001


class TestPrioritizeFindings:
    """Test prioritize_findings function."""

    def test_prioritize_empty_list(self) -> None:
        """prioritize_findings handles empty findings list."""
        result = prioritize_findings([])
        assert result == []

    def test_prioritize_sorts_by_risk_score(self) -> None:
        """prioritize_findings sorts findings by risk score descending."""
        findings = [
            {
                "severity": SeverityLevel.LOW,
                "threat": ThreatLevel.UNLIKELY,
                "confidence": ConfidenceLevel.LOW,
            },
            {
                "severity": SeverityLevel.CRITICAL,
                "threat": ThreatLevel.IMMINENT,
                "confidence": ConfidenceLevel.VERY_HIGH,
            },
            {
                "severity": SeverityLevel.MEDIUM,
                "threat": ThreatLevel.POSSIBLE,
                "confidence": ConfidenceLevel.MEDIUM,
            },
        ]
        prioritized = prioritize_findings(findings)

        assert prioritized[0]["severity"] == SeverityLevel.CRITICAL
        assert prioritized[-1]["severity"] == SeverityLevel.LOW

    def test_prioritize_preserves_all_findings(self) -> None:
        """prioritize_findings preserves all findings without loss."""
        findings = [
            {
                "severity": SeverityLevel.HIGH,
                "threat": ThreatLevel.LIKELY,
                "confidence": ConfidenceLevel.HIGH,
                "id": i,
            }
            for i in range(10)
        ]
        prioritized = prioritize_findings(findings)

        assert len(prioritized) == len(findings)
        ids = {f["id"] for f in prioritized}
        assert ids == {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

    def test_prioritize_correct_order(self) -> None:
        """prioritize_findings orders findings from highest to lowest risk."""
        findings = [
            {
                "severity": SeverityLevel.CRITICAL,
                "threat": ThreatLevel.IMMINENT,
                "confidence": ConfidenceLevel.VERY_HIGH,
            },
            {
                "severity": SeverityLevel.HIGH,
                "threat": ThreatLevel.LIKELY,
                "confidence": ConfidenceLevel.HIGH,
            },
            {
                "severity": SeverityLevel.MEDIUM,
                "threat": ThreatLevel.POSSIBLE,
                "confidence": ConfidenceLevel.MEDIUM,
            },
        ]
        prioritized = prioritize_findings(findings)

        risks = [
            calculate_risk_score(f["severity"], f["threat"], f["confidence"])
            for f in prioritized
        ]
        assert risks == sorted(risks, reverse=True)
