"""Severity level enumerations and utilities for security analysis reporting.

This module provides severity, threat, and confidence level enumerations
used throughout Intellicrack for security findings classification. It includes
scoring systems, color mappings, and utility functions for risk assessment
and finding prioritization.

Copyright (C) 2025 Zachary Flint.

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

from enum import Enum
from typing import Any


class SeverityLevel(Enum):
    """Enumeration of severity levels for security findings.

    Used to classify the severity or impact of security vulnerabilities,
    protection weaknesses, and licensing bypass opportunities identified during
    analysis. Severity levels range from CRITICAL (highest impact) to INFO
    (lowest impact).

    Attributes:
        CRITICAL: Most severe findings requiring immediate attention.
        HIGH: Significant vulnerabilities with major impact.
        MEDIUM: Moderate findings that should be addressed.
        LOW: Minor issues with limited impact.
        INFO: Informational findings and low-priority observations.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityLevel(Enum):
    """Enumeration of vulnerability severity levels.

    Alias enumeration for SeverityLevel used in specific contexts where
    vulnerability assessment is emphasized. Provides identical severity
    classifications for consistency across different analysis modules.

    Attributes:
        CRITICAL: Most severe vulnerabilities requiring immediate attention.
        HIGH: Significant vulnerabilities with major impact.
        MEDIUM: Moderate vulnerabilities that should be addressed.
        LOW: Minor vulnerabilities with limited impact.
        INFO: Informational vulnerabilities and low-priority observations.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityRelevance(Enum):
    """Enumeration of security relevance levels for findings.

    Provides severity classification based on security research relevance and
    importance. Used to categorize the relevance of protection mechanisms,
    licensing systems, and security controls discovered during analysis.

    Attributes:
        CRITICAL: Most relevant security mechanisms requiring focused analysis.
        HIGH: Significant security controls with major impact on protection.
        MEDIUM: Moderately relevant security mechanisms worth investigating.
        LOW: Minor security mechanisms with limited relevance.
        INFO: Informational security observations with low relevance.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatLevel(Enum):
    """Enumeration of threat assessment levels.

    Classifies the likelihood or urgency of threats and vulnerabilities
    discovered during security analysis. Threat levels indicate how probable
    or imminent a protection bypass or licensing crack is.

    Attributes:
        IMMINENT: Threat is imminent or actively exploitable.
        LIKELY: Threat is probable and should be addressed soon.
        POSSIBLE: Threat is possible but not certain.
        UNLIKELY: Threat is unlikely but still possible.
        NONE: No threat present or vulnerability not exploitable.
    """

    IMMINENT = "imminent"
    LIKELY = "likely"
    POSSIBLE = "possible"
    UNLIKELY = "unlikely"
    NONE = "none"


class ConfidenceLevel(Enum):
    """Enumeration of confidence levels for analysis findings.

    Represents the confidence or certainty in security analysis results.
    Confidence levels are used as multipliers in risk score calculations to
    weight findings based on how certain the analysis is about them.

    Attributes:
        VERY_HIGH: Very high confidence in the finding (90-100% certain).
        HIGH: High confidence in the finding (70-90% certain).
        MEDIUM: Medium confidence in the finding (50-70% certain).
        LOW: Low confidence in the finding (30-50% certain).
        VERY_LOW: Very low confidence in the finding (0-30% certain).
    """

    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"


SEVERITY_COLORS: dict[SeverityLevel, str] = {
    SeverityLevel.CRITICAL: "#FF0000",
    SeverityLevel.HIGH: "#FF6600",
    SeverityLevel.MEDIUM: "#FFAA00",
    SeverityLevel.LOW: "#FFFF00",
    SeverityLevel.INFO: "#00AA00",
}

SEVERITY_SCORES: dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 10.0,
    SeverityLevel.HIGH: 7.5,
    SeverityLevel.MEDIUM: 5.0,
    SeverityLevel.LOW: 2.5,
    SeverityLevel.INFO: 1.0,
}

THREAT_SCORES: dict[ThreatLevel, float] = {
    ThreatLevel.IMMINENT: 10.0,
    ThreatLevel.LIKELY: 7.0,
    ThreatLevel.POSSIBLE: 5.0,
    ThreatLevel.UNLIKELY: 2.0,
    ThreatLevel.NONE: 0.0,
}

CONFIDENCE_MULTIPLIERS: dict[ConfidenceLevel, float] = {
    ConfidenceLevel.VERY_HIGH: 1.0,
    ConfidenceLevel.HIGH: 0.9,
    ConfidenceLevel.MEDIUM: 0.7,
    ConfidenceLevel.LOW: 0.5,
    ConfidenceLevel.VERY_LOW: 0.3,
}


def get_severity_from_score(score: float) -> SeverityLevel:
    """Convert numeric score to severity level.

    Args:
        score: Numeric severity score (typically 0.0-10.0).

    Returns:
        Corresponding severity level enum based on the score.
    """
    if score >= 9.0:
        return SeverityLevel.CRITICAL
    if score >= 7.0:
        return SeverityLevel.HIGH
    if score >= 4.0:
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW if score >= 2.0 else SeverityLevel.INFO


def get_threat_from_score(score: float) -> ThreatLevel:
    """Convert numeric score to threat level.

    Args:
        score: Numeric threat score (typically 0.0-10.0).

    Returns:
        Corresponding threat level enum based on the score.
    """
    if score >= 8.0:
        return ThreatLevel.IMMINENT
    if score >= 6.0:
        return ThreatLevel.LIKELY
    if score >= 3.0:
        return ThreatLevel.POSSIBLE
    return ThreatLevel.UNLIKELY if score >= 1.0 else ThreatLevel.NONE


def calculate_risk_score(severity: SeverityLevel, threat: ThreatLevel, confidence: ConfidenceLevel) -> float:
    """Calculate overall risk score from severity, threat, and confidence.

    Args:
        severity: SeverityLevel of the vulnerability or finding.
        threat: ThreatLevel of the threat.
        confidence: ConfidenceLevel in the analysis results.

    Returns:
        Calculated risk score combining all three factors.
    """
    severity_score = SEVERITY_SCORES.get(severity, 1.0)
    threat_score = THREAT_SCORES.get(threat, 0.0)
    confidence_multiplier = CONFIDENCE_MULTIPLIERS.get(confidence, 0.5)

    # Risk = (Severity * Threat) * Confidence
    base_risk = (severity_score * threat_score) / 10.0
    return base_risk * confidence_multiplier


def get_severity_color(severity: SeverityLevel) -> str:
    """Get color code for severity level.

    Args:
        severity: SeverityLevel to get color for.

    Returns:
        Hex color code for the severity level.
    """
    return SEVERITY_COLORS.get(severity, "#808080")


def format_severity_report(findings: list[dict[str, Any]]) -> str:
    """Format a list of findings into a severity report.

    Args:
        findings: List of finding dictionaries with 'severity' key.

    Returns:
        Formatted report grouped and sorted by severity.
    """
    if not findings:
        return "No findings to report."

    # Group by severity
    severity_groups: dict[SeverityLevel, list[dict[str, Any]]] = {}
    for finding in findings:
        severity = finding.get("severity", SeverityLevel.INFO)
        if severity not in severity_groups:
            severity_groups[severity] = []
        severity_groups[severity].append(finding)

    # Sort by severity (critical first)
    severity_order = [
        SeverityLevel.CRITICAL,
        SeverityLevel.HIGH,
        SeverityLevel.MEDIUM,
        SeverityLevel.LOW,
        SeverityLevel.INFO,
    ]

    report_lines = ["Severity Report", "=" * 40]

    for severity in severity_order:
        if severity in severity_groups:
            count = len(severity_groups[severity])
            report_lines.extend((f"\n{severity.value.upper()}: {count} finding(s)", "-" * 30))
            for i, finding in enumerate(severity_groups[severity][:5], 1):
                title = finding.get("title", "Unknown finding")
                description = finding.get("description", "No description")
                report_lines.append(f"{i}. {title}")
                if len(description) > 80:
                    description = f"{description[:77]}..."
                report_lines.append(f"   {description}")

            if count > 5:
                report_lines.append(f"   ... and {count - 5} more")

    return "\n".join(report_lines)


def aggregate_severity_stats(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate severity statistics from findings.

    Args:
        findings: List of finding dictionaries to aggregate statistics from.

    Returns:
        Dictionary with aggregated severity statistics including by_severity,
            risk_distribution, and average_risk_score keys.
    """
    stats: dict[str, Any] = {
        "total_findings": len(findings),
        "by_severity": {},
        "risk_distribution": {},
        "average_risk_score": 0.0,
    }

    total_risk = 0.0

    for finding in findings:
        severity = finding.get("severity", SeverityLevel.INFO)
        threat = finding.get("threat", ThreatLevel.UNLIKELY)
        confidence = finding.get("confidence", ConfidenceLevel.MEDIUM)

        # Count by severity
        severity_key = severity.value if hasattr(severity, "value") else str(severity)
        by_severity = stats["by_severity"]
        by_severity[severity_key] = by_severity.get(severity_key, 0) + 1

        # Calculate risk score
        risk_score = calculate_risk_score(severity, threat, confidence)
        total_risk += risk_score

        # Categorize risk
        if risk_score >= 7.0:
            risk_cat = "high_risk"
        elif risk_score >= 4.0:
            risk_cat = "medium_risk"
        else:
            risk_cat = "low_risk"

        stats["risk_distribution"][risk_cat] = stats["risk_distribution"].get(risk_cat, 0) + 1

    if findings:
        stats["average_risk_score"] = total_risk / len(findings)

    return stats


def prioritize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort findings by priority based on risk score.

    Args:
        findings: List of finding dictionaries to prioritize.

    Returns:
        Sorted list of findings ordered by risk score in descending order.
    """

    def get_priority_score(finding: dict[str, Any]) -> float:
        severity = finding.get("severity", SeverityLevel.INFO)
        threat = finding.get("threat", ThreatLevel.UNLIKELY)
        confidence = finding.get("confidence", ConfidenceLevel.MEDIUM)
        return calculate_risk_score(severity, threat, confidence)

    return sorted(findings, key=get_priority_score, reverse=True)


__all__: list[str] = [
    "CONFIDENCE_MULTIPLIERS",
    "ConfidenceLevel",
    "SEVERITY_COLORS",
    "SEVERITY_SCORES",
    "SecurityRelevance",
    "SeverityLevel",
    "THREAT_SCORES",
    "ThreatLevel",
    "VulnerabilityLevel",
    "aggregate_severity_stats",
    "calculate_risk_score",
    "format_severity_report",
    "get_severity_color",
    "get_severity_from_score",
    "get_threat_from_score",
    "prioritize_findings",
]
