"""Copyright (C) 2025 Zachary Flint.

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

# Import the shared SeverityLevel enum to avoid duplication
from .analysis.severity_levels import SeverityLevel


class ThreatLevel(Enum):
    """Enumeration for threat assessment levels."""

    IMMINENT = "imminent"
    LIKELY = "likely"
    POSSIBLE = "possible"
    UNLIKELY = "unlikely"
    NONE = "none"


class ConfidenceLevel(Enum):
    """Enumeration for analysis confidence levels."""

    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"


# Severity level mappings and utilities
SEVERITY_COLORS = {
    SeverityLevel.CRITICAL: "#FF0000",  # Red
    SeverityLevel.HIGH: "#FF6600",  # Orange
    SeverityLevel.MEDIUM: "#FFAA00",  # Yellow-orange
    SeverityLevel.LOW: "#FFFF00",  # Yellow
    SeverityLevel.INFO: "#00AA00",  # Green
}

SEVERITY_SCORES = {
    SeverityLevel.CRITICAL: 10.0,
    SeverityLevel.HIGH: 7.5,
    SeverityLevel.MEDIUM: 5.0,
    SeverityLevel.LOW: 2.5,
    SeverityLevel.INFO: 1.0,
}

THREAT_SCORES = {
    ThreatLevel.IMMINENT: 10.0,
    ThreatLevel.LIKELY: 7.0,
    ThreatLevel.POSSIBLE: 5.0,
    ThreatLevel.UNLIKELY: 2.0,
    ThreatLevel.NONE: 0.0,
}

CONFIDENCE_MULTIPLIERS = {
    ConfidenceLevel.VERY_HIGH: 1.0,
    ConfidenceLevel.HIGH: 0.9,
    ConfidenceLevel.MEDIUM: 0.7,
    ConfidenceLevel.LOW: 0.5,
    ConfidenceLevel.VERY_LOW: 0.3,
}


def get_severity_from_score(score: float) -> SeverityLevel:
    """Convert numeric score to severity level."""
    if score >= 9.0:
        return SeverityLevel.CRITICAL
    if score >= 7.0:
        return SeverityLevel.HIGH
    if score >= 4.0:
        return SeverityLevel.MEDIUM
    if score >= 2.0:
        return SeverityLevel.LOW
    return SeverityLevel.INFO


def get_threat_from_score(score: float) -> ThreatLevel:
    """Convert numeric score to threat level."""
    if score >= 8.0:
        return ThreatLevel.IMMINENT
    if score >= 6.0:
        return ThreatLevel.LIKELY
    if score >= 3.0:
        return ThreatLevel.POSSIBLE
    if score >= 1.0:
        return ThreatLevel.UNLIKELY
    return ThreatLevel.NONE


def calculate_risk_score(severity: SeverityLevel, threat: ThreatLevel, confidence: ConfidenceLevel) -> float:
    """Calculate overall risk score from severity, threat, and confidence."""
    severity_score = SEVERITY_SCORES.get(severity, 1.0)
    threat_score = THREAT_SCORES.get(threat, 0.0)
    confidence_multiplier = CONFIDENCE_MULTIPLIERS.get(confidence, 0.5)

    # Risk = (Severity * Threat) * Confidence
    base_risk = (severity_score * threat_score) / 10.0
    return base_risk * confidence_multiplier


def get_severity_color(severity: SeverityLevel) -> str:
    """Get color code for severity level."""
    return SEVERITY_COLORS.get(severity, "#808080")


def format_severity_report(findings: list[dict]) -> str:
    """Format a list of findings into a severity report."""
    if not findings:
        return "No findings to report."

    # Group by severity
    severity_groups = {}
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
            report_lines.append(f"\n{severity.value.upper()}: {count} finding(s)")
            report_lines.append("-" * 30)

            for i, finding in enumerate(severity_groups[severity][:5], 1):
                title = finding.get("title", "Unknown finding")
                description = finding.get("description", "No description")
                report_lines.append(f"{i}. {title}")
                if len(description) > 80:
                    description = description[:77] + "..."
                report_lines.append(f"   {description}")

            if count > 5:
                report_lines.append(f"   ... and {count - 5} more")

    return "\n".join(report_lines)


def aggregate_severity_stats(findings: list[dict]) -> dict:
    """Aggregate severity statistics from findings."""
    stats = {
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
        stats["by_severity"][severity_key] = stats["by_severity"].get(severity_key, 0) + 1

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


def prioritize_findings(findings: list[dict]) -> list[dict]:
    """Sort findings by priority (risk score)."""

    def get_priority_score(finding):
        severity = finding.get("severity", SeverityLevel.INFO)
        threat = finding.get("threat", ThreatLevel.UNLIKELY)
        confidence = finding.get("confidence", ConfidenceLevel.MEDIUM)
        return calculate_risk_score(severity, threat, confidence)

    return sorted(findings, key=get_priority_score, reverse=True)


# Export commonly used classes and functions
__all__ = [
    "SEVERITY_COLORS",
    "SEVERITY_SCORES",
    "ConfidenceLevel",
    "SeverityLevel",
    "ThreatLevel",
    "aggregate_severity_stats",
    "calculate_risk_score",
    "format_severity_report",
    "get_severity_color",
    "get_severity_from_score",
    "get_threat_from_score",
    "prioritize_findings",
]
