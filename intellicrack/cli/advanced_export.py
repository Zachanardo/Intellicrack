#!/usr/bin/env python3
"""Advanced Export Options - Comprehensive reporting system for CLI.

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

import csv
import json
import logging
import os
import xml.etree.ElementTree as StdET
from datetime import datetime
from typing import Any, Protocol, TypedDict, Unpack, runtime_checkable


try:
    import defusedxml.ElementTree as ET  # noqa: N817
except ImportError:
    ET = StdET

logger = logging.getLogger(__name__)

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from jinja2 import Template

    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    import xlsxwriter

    XLSX_AVAILABLE = True
except ImportError:
    XLSX_AVAILABLE = False


@runtime_checkable
class WorkbookProtocol(Protocol):
    """Protocol defining the interface for xlsxwriter Workbook objects."""

    def add_worksheet(self, name: str = "") -> "WorksheetProtocol":
        """Add a new worksheet to the workbook.

        Args:
            name: Optional name for the worksheet.

        Returns:
            The created worksheet object.

        """
        ...

    def add_format(self, properties: dict[str, Any] | None = None) -> object:
        """Create a format object for cell styling.

        Args:
            properties: Dictionary of format properties.

        Returns:
            Format object for use with write operations.

        """
        ...

    def close(self) -> None:
        """Close the workbook and write to disk."""
        ...


@runtime_checkable
class WorksheetProtocol(Protocol):
    """Protocol defining the interface for xlsxwriter Worksheet objects."""

    def write(self, row: int, col: int, data: Any, format_obj: object | None = None) -> int:
        """Write data to a cell in the worksheet.

        Args:
            row: Zero-indexed row number.
            col: Zero-indexed column number.
            data: Data to write to the cell.
            format_obj: Optional format object for cell styling.

        Returns:
            Integer status code (0 for success).

        """
        ...


class ExportOptions(TypedDict, total=False):
    """Type definition for export function options.

    Attributes:
        include_raw_data: Whether to include raw binary data samples in JSON export
        data_type: Type of data to export in CSV format

    """

    include_raw_data: bool
    data_type: str


class XlsxWorkbookProxy:
    """Proxy for xlsxwriter Workbook objects to avoid direct Any typing."""

    def __init__(self, workbook: object) -> None:
        """Initialize proxy with actual workbook.

        Args:
            workbook: The actual xlsxwriter Workbook instance

        Raises:
            TypeError: If workbook doesn't have required xlsxwriter methods

        """
        if not hasattr(workbook, "add_worksheet"):
            raise TypeError("Invalid workbook: missing add_worksheet method")
        if not hasattr(workbook, "add_format"):
            raise TypeError("Invalid workbook: missing add_format method")
        if not hasattr(workbook, "close"):
            raise TypeError("Invalid workbook: missing close method")
        self._workbook = workbook

    def add_worksheet(self, name: str = "") -> object:
        """Add a worksheet to the workbook.

        Args:
            name: Name of the worksheet

        Returns:
            The worksheet object

        """
        if not hasattr(self._workbook, "add_worksheet"):
            raise TypeError("Invalid workbook: missing add_worksheet method")
        return self._workbook.add_worksheet(name)

    def add_format(self, properties: dict[str, Any] | None = None) -> object:
        """Add a format to the workbook.

        Args:
            properties: Format properties dictionary

        Returns:
            The format object

        """
        if properties is None:
            properties = {}
        if not hasattr(self._workbook, "add_format"):
            raise TypeError("Invalid workbook: missing add_format method")
        return self._workbook.add_format(properties)

    def close(self) -> None:
        """Close the workbook."""
        if not hasattr(self._workbook, "close"):
            raise TypeError("Invalid workbook: missing close method")
        self._workbook.close()


class AdvancedExporter:
    """Advanced export system with multiple formats and detailed reporting."""

    def __init__(self, binary_path: str, analysis_results: dict[str, Any]) -> None:
        """Initialize exporter with analysis data.

        Args:
            binary_path: Path to analyzed binary
            analysis_results: Dictionary of analysis results

        """
        self.binary_path = binary_path
        self.analysis_results = analysis_results
        self.export_metadata: dict[str, Any] = {
            "export_time": datetime.now().isoformat(),
            "binary_path": binary_path,
            "binary_name": os.path.basename(binary_path),
            "export_version": "2.0",
            "tool": "Intellicrack CLI",
        }

    def export_detailed_json(self, output_path: str, include_raw_data: bool = True) -> bool:
        """Export detailed JSON with metadata and structured analysis results.

        Args:
            output_path: Output file path
            include_raw_data: Whether to include raw binary data excerpts

        Returns:
            True if export successful

        """
        try:
            export_data: dict[str, Any] = {
                "metadata": self.export_metadata,
                "summary": self._generate_summary(),
                "analysis_results": self.analysis_results,
                "statistics": self._generate_statistics(),
                "recommendations": self._generate_recommendations(),
            }

            if include_raw_data:
                export_data["raw_data_samples"] = self._extract_raw_data_samples()

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, default=str, ensure_ascii=False)

            return True
        except Exception as e:
            logger.exception("JSON export failed: %s", e)
            return False

    def export_executive_summary(self, output_path: str, format_type: str = "markdown") -> bool:
        """Export executive summary in various formats.

        Args:
            output_path: Output file path
            format_type: Format (markdown, html, txt)

        Returns:
            True if export successful

        """
        summary_data = self._generate_executive_summary()

        try:
            if format_type.lower() == "markdown":
                return self._export_markdown_summary(output_path, summary_data)
            if format_type.lower() == "html":
                return self._export_html_summary(output_path, summary_data)
            if format_type.lower() == "txt":
                return self._export_text_summary(output_path, summary_data)
            logger.warning("Unsupported format: %s", format_type)
            return False
        except Exception as e:
            logger.exception("Executive summary export failed: %s", e)
            return False

    def export_vulnerability_report(self, output_path: str) -> bool:
        """Export detailed vulnerability report.

        Args:
            output_path: Output file path

        Returns:
            True if export successful

        """
        try:
            vuln_data = self.analysis_results.get("vulnerabilities", {})

            report: dict[str, Any] = {
                "metadata": self.export_metadata,
                "executive_summary": {
                    "total_vulnerabilities": len(vuln_data.get("vulnerabilities", [])) if isinstance(vuln_data, dict) else 0,
                    "critical_count": self._count_vulnerabilities_by_severity(vuln_data if isinstance(vuln_data, dict) else {}, "critical"),
                    "high_count": self._count_vulnerabilities_by_severity(vuln_data if isinstance(vuln_data, dict) else {}, "high"),
                    "medium_count": self._count_vulnerabilities_by_severity(vuln_data if isinstance(vuln_data, dict) else {}, "medium"),
                    "low_count": self._count_vulnerabilities_by_severity(vuln_data if isinstance(vuln_data, dict) else {}, "low"),
                    "risk_score": self._calculate_risk_score(vuln_data if isinstance(vuln_data, dict) else {}),
                },
                "detailed_findings": self._format_vulnerability_details(vuln_data if isinstance(vuln_data, dict) else {}),
                "mitigation_strategies": self._generate_mitigation_strategies(vuln_data if isinstance(vuln_data, dict) else {}),
                "compliance_notes": self._generate_compliance_notes(vuln_data if isinstance(vuln_data, dict) else {}),
            }

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=str, ensure_ascii=False)

            return True
        except Exception as e:
            logger.exception("Vulnerability report export failed: %s", e)
            return False

    def export_csv_data(self, output_path: str, data_type: str = "all") -> bool:
        """Export analysis data in CSV format.

        Args:
            output_path: Output file path
            data_type: Type of data to export (all, vulnerabilities, strings, imports)

        Returns:
            True if export successful

        """
        try:
            if data_type == "vulnerabilities":
                return self._export_vulnerabilities_csv(output_path)
            if data_type == "strings":
                return self._export_strings_csv(output_path)
            if data_type == "imports":
                return self._export_imports_csv(output_path)
            if data_type == "all":
                return self._export_comprehensive_csv(output_path)
            logger.warning("Unsupported CSV data type: %s", data_type)
            return False
        except Exception as e:
            logger.exception("CSV export failed: %s", e)
            return False

    def export_xml_report(self, output_path: str) -> bool:
        """Export structured XML report.

        Args:
            output_path: Output file path

        Returns:
            True if export successful

        """
        try:
            root = ET.Element("intellicrack_report")

            metadata_elem = ET.SubElement(root, "metadata")
            for key, value in self.export_metadata.items():
                elem = ET.SubElement(metadata_elem, key.replace(" ", "_"))
                elem.text = str(value)

            analysis_elem = ET.SubElement(root, "analysis_results")
            self._dict_to_xml(self.analysis_results, analysis_elem)

            summary_elem = ET.SubElement(root, "summary")
            summary_data = self._generate_summary()
            self._dict_to_xml(summary_data, summary_elem)

            tree = ET.ElementTree(root)
            ET.indent(tree, space="  ", level=0)
            tree.write(output_path, encoding="utf-8", xml_declaration=True)

            return True
        except Exception as e:
            logger.exception("XML export failed: %s", e)
            return False

    def export_html_report(self, output_path: str) -> bool:
        """Export analysis results as interactive HTML report.

        Args:
            output_path: Output file path

        Returns:
            True if export successful

        """
        if not JINJA2_AVAILABLE:
            logger.warning("HTML report generation not available. Install Jinja2: pip install Jinja2")
            return False

        try:
            html_template = Template("""
<!DOCTYPE html>
<html>
<head>
    <title>Intellicrack Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { display: flex; justify-content: space-around; margin: 20px 0; }
        .metric { text-align: center; padding: 10px; background-color: #e9e9e9; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Intellicrack Binary Analysis Report</h1>
        <p>File: {{ metadata.get('Binary File', 'Unknown') }}</p>
        <p>Generated: {{ metadata.get('Export Time', 'Unknown') }}</p>
    </div>

    <div class="summary">
        <div class="metric">
            <h3>Analysis Results</h3>
            <p>{{ analysis_count }} findings</p>
        </div>
    </div>

    <h2>Analysis Details</h2>
    <table>
        <thead>
            <tr>
                <th>Analysis Type</th>
                <th>Results</th>
            </tr>
        </thead>
        <tbody>
            {% for analysis_type, results in analysis_results.items() %}
            <tr>
                <td>{{ analysis_type }}</td>
                <td>{{ results|string|truncate(100) }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
            """)

            html_content = html_template.render(
                metadata=self.export_metadata,
                analysis_results=self.analysis_results,
                analysis_count=len(self.analysis_results),
            )

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            return True
        except Exception as e:
            logger.exception("HTML export failed: %s", e)
            return False

    def export_yaml_config(self, output_path: str) -> bool:
        """Export analysis results as YAML configuration.

        Args:
            output_path: Output file path

        Returns:
            True if export successful

        """
        if not YAML_AVAILABLE:
            logger.warning("YAML export not available. Install PyYAML: pip install PyYAML")
            return False

        try:
            export_data: dict[str, Any] = {
                "metadata": self.export_metadata,
                "analysis_config": self._generate_analysis_config(),
                "findings_summary": self._generate_summary(),
                "detection_rules": self._generate_detection_rules(),
            }

            with open(output_path, "w", encoding="utf-8") as f:
                yaml.dump(export_data, f, default_flow_style=False, allow_unicode=True)

            return True
        except Exception as e:
            logger.exception("YAML export failed: %s", e)
            return False

    def export_excel_workbook(self, output_path: str) -> bool:
        """Export comprehensive Excel workbook with multiple sheets.

        Args:
            output_path: Output file path

        Returns:
            True if export successful

        """
        if not XLSX_AVAILABLE:
            logger.warning("Excel export not available. Install xlsxwriter: pip install xlsxwriter")
            return False

        try:
            workbook = xlsxwriter.Workbook(output_path)

            header_format = workbook.add_format(
                {
                    "bold": True,
                    "bg_color": "#4472C4",
                    "font_color": "white",
                    "border": 1,
                },
            )

            cell_format = workbook.add_format({"border": 1})

            self._create_summary_sheet(workbook, header_format, cell_format)
            self._create_vulnerabilities_sheet(workbook, header_format, cell_format)
            self._create_strings_sheet(workbook, header_format, cell_format)
            self._create_imports_sheet(workbook, header_format, cell_format)
            self._create_statistics_sheet(workbook, header_format, cell_format)

            workbook.close()
            return True
        except Exception as e:
            logger.exception("Excel export failed: %s", e)
            return False

    def _generate_summary(self) -> dict[str, Any]:
        """Generate analysis summary."""
        summary: dict[str, Any] = {
            "file_info": {
                "name": os.path.basename(self.binary_path),
                "path": self.binary_path,
                "size": os.path.getsize(self.binary_path) if os.path.exists(self.binary_path) else 0,
            },
            "analysis_overview": {},
            "key_findings": [],
            "security_assessment": {},
        }

        analysis_overview: dict[str, int] = {}
        key_findings: list[str] = []

        for analysis_type, results in self.analysis_results.items():
            if isinstance(results, (dict, list)):
                analysis_overview[analysis_type] = len(results)
            else:
                analysis_overview[analysis_type] = 1

        summary["analysis_overview"] = analysis_overview

        if "vulnerabilities" in self.analysis_results:
            vuln_data = self.analysis_results["vulnerabilities"]
            if isinstance(vuln_data, dict) and "vulnerabilities" in vuln_data:
                vuln_count = len(vuln_data["vulnerabilities"])
                if vuln_count > 0:
                    key_findings.append(f"{vuln_count} potential vulnerabilities detected")

        if "protections" in self.analysis_results:
            prot_data = self.analysis_results["protections"]
            if isinstance(prot_data, dict):
                if enabled_protections := [k for k, v in prot_data.items() if v]:
                    key_findings.append(f"Security protections: {', '.join(enabled_protections)}")

        summary["key_findings"] = key_findings

        return summary

    def _generate_statistics(self) -> dict[str, Any]:
        """Generate analysis statistics."""
        categories: dict[str, int] = {}
        data_points: int = 0

        for category, data in self.analysis_results.items():
            count = len(data) if isinstance(data, (dict, list)) else 1
            categories[category] = count
            data_points += count

        stats: dict[str, Any] = {
            "analysis_time": self.export_metadata["export_time"],
            "total_categories": len(self.analysis_results),
            "data_points": data_points,
            "categories": categories,
        }

        return stats

    def _generate_recommendations(self) -> list[str]:
        """Generate security recommendations based on analysis."""
        recommendations: list[str] = []

        vuln_data = self.analysis_results.get("vulnerabilities", {})
        if isinstance(vuln_data, dict) and vuln_data.get("vulnerabilities"):
            recommendations.extend((
                "Address identified vulnerabilities before deployment",
                "Implement input validation and bounds checking",
            ))
        prot_data = self.analysis_results.get("protections", {})
        if isinstance(prot_data, dict):
            if not prot_data.get("aslr", True):
                recommendations.append("Enable ASLR (Address Space Layout Randomization)")
            if not prot_data.get("dep", True):
                recommendations.append("Enable DEP/NX (Data Execution Prevention)")
            if not prot_data.get("canary", True):
                recommendations.append("Enable stack canaries for buffer overflow protection")

        recommendations.extend(
            [
                "Regular security audits and penetration testing",
                "Keep all dependencies and libraries updated",
                "Implement proper error handling and logging",
                "Use secure coding practices and code reviews",
            ],
        )

        return recommendations

    def _generate_executive_summary(self) -> dict[str, Any]:
        """Generate executive summary data."""
        return {
            "title": f"Security Analysis Report: {os.path.basename(self.binary_path)}",
            "analysis_date": self.export_metadata["export_time"],
            "binary_info": {
                "name": os.path.basename(self.binary_path),
                "size": os.path.getsize(self.binary_path) if os.path.exists(self.binary_path) else 0,
            },
            "risk_assessment": self._assess_overall_risk(),
            "key_findings": self._extract_key_findings(),
            "recommendations": self._generate_recommendations()[:5],
            "next_steps": [
                "Review and address critical vulnerabilities",
                "Implement recommended security controls",
                "Conduct follow-up testing after remediation",
            ],
        }

    def _export_markdown_summary(self, output_path: str, summary_data: dict[str, Any]) -> bool:
        """Export executive summary as Markdown."""
        content = f"""# {summary_data["title"]}

**Analysis Date:** {summary_data["analysis_date"]}

## Binary Information
- **Name:** {summary_data["binary_info"]["name"]}
- **Size:** {summary_data["binary_info"]["size"]:,} bytes

## Risk Assessment
**Overall Risk:** {summary_data["risk_assessment"]["level"]}

{summary_data["risk_assessment"]["description"]}

## Key Findings
"""

        for finding in summary_data["key_findings"]:
            content += f"- {finding}\n"

        content += "\n## Recommendations\n"
        for i, rec in enumerate(summary_data["recommendations"], 1):
            content += f"{i}. {rec}\n"

        content += "\n## Next Steps\n"
        for step in summary_data["next_steps"]:
            content += f"- {step}\n"

        content += f"\n---\n*Generated by Intellicrack CLI v{self.export_metadata['export_version']}*\n"

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        return True

    def _export_html_summary(self, output_path: str, summary_data: dict[str, Any]) -> bool:
        """Export executive summary as HTML."""
        html_template = """<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .risk-high {{ color: #d9534f; }}
        .risk-medium {{ color: #f0ad4e; }}
        .risk-low {{ color: #5cb85c; }}
        .findings {{ background-color: #f9f9f9; padding: 15px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{title}</h1>
        <p><strong>Analysis Date:</strong> {analysis_date}</p>
    </div>

    <h2>Binary Information</h2>
    <ul>
        <li><strong>Name:</strong> {binary_name}</li>
        <li><strong>Size:</strong> {binary_size:,} bytes</li>
    </ul>

    <h2>Risk Assessment</h2>
    <p class="risk-{risk_class}"><strong>Overall Risk:</strong> {risk_level}</p>
    <p>{risk_description}</p>

    <h2>Key Findings</h2>
    <div class="findings">
        <ul>
            {findings_list}
        </ul>
    </div>

    <h2>Recommendations</h2>
    <ol>
        {recommendations_list}
    </ol>

    <hr>
    <p><em>Generated by Intellicrack CLI v{version}</em></p>
</body>
</html>"""

        findings_html = "".join(f"<li>{finding}</li>" for finding in summary_data["key_findings"])
        recommendations_html = "".join(f"<li>{rec}</li>" for rec in summary_data["recommendations"])

        risk_level = summary_data["risk_assessment"]["level"]
        risk_class = risk_level.lower() if risk_level.lower() in ["high", "medium", "low"] else "medium"

        html_content = html_template.format(
            title=summary_data["title"],
            analysis_date=summary_data["analysis_date"],
            binary_name=summary_data["binary_info"]["name"],
            binary_size=summary_data["binary_info"]["size"],
            risk_level=risk_level,
            risk_class=risk_class,
            risk_description=summary_data["risk_assessment"]["description"],
            findings_list=findings_html,
            recommendations_list=recommendations_html,
            version=self.export_metadata["export_version"],
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return True

    def _export_text_summary(self, output_path: str, summary_data: dict[str, Any]) -> bool:
        """Export executive summary as plain text."""
        content = f"""{summary_data["title"]}
{"=" * len(summary_data["title"])}

Analysis Date: {summary_data["analysis_date"]}

BINARY INFORMATION
------------------
Name: {summary_data["binary_info"]["name"]}
Size: {summary_data["binary_info"]["size"]:,} bytes

RISK ASSESSMENT
---------------
Overall Risk: {summary_data["risk_assessment"]["level"]}

{summary_data["risk_assessment"]["description"]}

KEY FINDINGS
------------
"""

        for finding in summary_data["key_findings"]:
            content += f" {finding}\n"

        content += "\nRECOMMENDATIONS\n---------------\n"
        for i, rec in enumerate(summary_data["recommendations"], 1):
            content += f"{i}. {rec}\n"

        content += f"\n\nGenerated by Intellicrack CLI v{self.export_metadata['export_version']}\n"

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        return True

    def _assess_overall_risk(self) -> dict[str, str]:
        """Assess overall security risk."""
        vuln_data = self.analysis_results.get("vulnerabilities", {})

        if isinstance(vuln_data, dict):
            vulns = vuln_data.get("vulnerabilities", [])
            critical_count = self._count_vulnerabilities_by_severity(vuln_data, "critical")
            high_count = self._count_vulnerabilities_by_severity(vuln_data, "high")

            if critical_count > 0:
                return {
                    "level": "HIGH",
                    "description": f"Critical vulnerabilities detected ({critical_count} critical, {high_count} high severity). Immediate action required.",
                }
            if high_count > 2:
                return {
                    "level": "MEDIUM",
                    "description": f"Multiple high-severity vulnerabilities detected ({high_count}). Prompt remediation recommended.",
                }
            if len(vulns) > 0:
                return {
                    "level": "LOW",
                    "description": f"Some vulnerabilities detected ({len(vulns)} total). Review and address as appropriate.",
                }

        return {
            "level": "LOW",
            "description": "No critical vulnerabilities detected. Continue monitoring and regular assessments.",
        }

    def _extract_key_findings(self) -> list[str]:
        """Extract key findings from analysis results."""
        findings: list[str] = []

        vuln_data = self.analysis_results.get("vulnerabilities", {})
        if isinstance(vuln_data, dict):
            if vulns := vuln_data.get("vulnerabilities", []):
                findings.append(f"{len(vulns)} potential vulnerabilities identified")

        prot_data = self.analysis_results.get("protections", {})
        if isinstance(prot_data, dict):
            if missing_protections := [k for k, v in prot_data.items() if not v]:
                findings.append(f"Missing security protections: {', '.join(missing_protections)}")

        strings_data = self.analysis_results.get("strings", [])
        if isinstance(strings_data, list) and len(strings_data) > 100:
            findings.append(f"Large number of embedded strings detected ({len(strings_data)})")

        return findings

    def _count_vulnerabilities_by_severity(self, vuln_data: dict[str, Any], severity: str) -> int:
        """Count vulnerabilities by severity level."""
        vulns = vuln_data.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            return 0

        return sum(isinstance(vuln, dict) and vuln.get("severity", "").lower() == severity.lower() for vuln in vulns)

    def _calculate_risk_score(self, vuln_data: dict[str, Any]) -> float:
        """Calculate overall risk score."""
        vulns = vuln_data.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            return 0.0

        score = 0.0
        for vuln in vulns:
            if isinstance(vuln, dict):
                severity = vuln.get("severity", "").lower()
                if severity == "critical":
                    score += 10.0
                elif severity == "high":
                    score += 7.0
                elif severity == "medium":
                    score += 4.0
                elif severity == "low":
                    score += 1.0

        return min(score, 100.0)

    def _dict_to_xml(self, data: dict[str, Any] | list[Any] | str | float | bool | None, parent: StdET.Element) -> None:
        """Convert dictionary to XML elements.

        Args:
            data: Data to convert to XML elements
            parent: Parent XML element to attach converted data to

        """
        if isinstance(data, dict):
            for key, value in data.items():
                elem = ET.SubElement(parent, str(key).replace(" ", "_"))
                self._dict_to_xml(value, elem)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                elem = ET.SubElement(parent, f"item_{i}")
                self._dict_to_xml(item, elem)
        else:
            parent.text = str(data)

    def _extract_raw_data_samples(self) -> dict[str, str]:
        """Extract sample raw data from binary."""
        samples: dict[str, str] = {}

        try:
            if os.path.exists(self.binary_path):
                with open(self.binary_path, "rb") as f:
                    header_data = f.read(256)
                    samples["header_hex"] = header_data.hex()

                    file_size = os.path.getsize(self.binary_path)
                    if file_size > 512:
                        f.seek(file_size // 2)
                        middle_data = f.read(128)
                        samples["middle_hex"] = middle_data.hex()
        except Exception as e:
            logger.debug("Failed to read file samples: %s", e, exc_info=True)

        return samples

    def _export_vulnerabilities_csv(self, output_path: str) -> bool:
        """Export vulnerabilities as CSV."""
        vuln_data = self.analysis_results.get("vulnerabilities", {})
        vulns = vuln_data.get("vulnerabilities", []) if isinstance(vuln_data, dict) else []

        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = ["severity", "type", "location", "description", "impact", "recommendation"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for vuln in vulns:
                if isinstance(vuln, dict):
                    writer.writerow(
                        {
                            "severity": vuln.get("severity", "Unknown"),
                            "type": vuln.get("type", "Unknown"),
                            "location": vuln.get("location", "Unknown"),
                            "description": vuln.get("description", "No description"),
                            "impact": vuln.get("impact", "Unknown"),
                            "recommendation": vuln.get("recommendation", "Review manually"),
                        },
                    )

        return True

    def _format_vulnerability_details(self, vuln_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Format vulnerability details for reporting."""
        vulns = vuln_data.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            return []

        formatted: list[dict[str, Any]] = []
        formatted.extend(
            {
                "id": len(formatted) + 1,
                "severity": vuln.get("severity", "Unknown"),
                "type": vuln.get("type", "Unknown"),
                "location": vuln.get("location", "Unknown"),
                "description": vuln.get("description", "No description available"),
                "impact": vuln.get("impact", "Potential security compromise"),
                "recommendation": vuln.get("recommendation", "Manual review required"),
                "cve_references": vuln.get("cve_references", []),
                "exploit_likelihood": vuln.get("exploit_likelihood", "Unknown"),
            }
            for vuln in vulns
            if isinstance(vuln, dict)
        )
        return formatted

    def _generate_mitigation_strategies(self, vuln_data: dict[str, Any]) -> list[str]:
        """Generate mitigation strategies based on vulnerabilities."""
        return [
            "Implement input validation and sanitization",
            "Use safe string handling functions",
            "Enable compiler security features (stack canaries, ASLR, DEP)",
            "Conduct regular security code reviews",
            "Implement proper error handling",
            "Use memory-safe programming languages where appropriate",
            "Regular security testing and vulnerability assessments",
        ]

    def _generate_compliance_notes(self, vuln_data: dict[str, Any]) -> dict[str, list[str]]:
        """Generate compliance-related notes."""
        return {
            "OWASP_Top_10": [
                "Review against OWASP Top 10 vulnerabilities",
                "Implement OWASP secure coding practices",
            ],
            "NIST": [
                "Follow NIST Cybersecurity Framework guidelines",
                "Implement NIST security controls",
            ],
            "ISO_27001": [
                "Ensure compliance with ISO 27001 security standards",
                "Document security policies and procedures",
            ],
        }

    def _export_strings_csv(self, output_path: str) -> bool:
        """Export strings data to CSV format."""
        try:
            strings_data = self.analysis_results.get("strings", []) or []

            with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["String", "Address", "Section", "Type", "Length"])

                for string_item in strings_data:
                    if isinstance(string_item, dict):
                        writer.writerow(
                            [
                                string_item.get("value", ""),
                                string_item.get("address", ""),
                                string_item.get("section", ""),
                                string_item.get("type", ""),
                                string_item.get("length", 0),
                            ],
                        )
                    else:
                        writer.writerow([str(string_item), "", "", "", len(str(string_item))])

            return True
        except Exception as e:
            logger.exception("Strings CSV export failed: %s", e)
            return False

    def _export_imports_csv(self, output_path: str) -> bool:
        """Export imports data to CSV format."""
        try:
            imports_data = self.analysis_results.get("imports", {}) or {}

            with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Library", "Function", "Address", "Ordinal"])

                for library, functions in imports_data.items():
                    if isinstance(functions, list):
                        for func in functions:
                            if isinstance(func, dict):
                                writer.writerow(
                                    [
                                        library,
                                        func.get("name", ""),
                                        func.get("address", ""),
                                        func.get("ordinal", ""),
                                    ],
                                )
                            else:
                                writer.writerow([library, str(func), "", ""])
                    else:
                        writer.writerow([library, str(functions), "", ""])

            return True
        except Exception as e:
            logger.exception("Imports CSV export failed: %s", e)
            return False

    def _export_comprehensive_csv(self, output_path: str) -> bool:
        """Export comprehensive analysis data to CSV format."""
        try:
            base_path = os.path.splitext(output_path)[0]

            success = True
            success &= self._export_vulnerabilities_csv(f"{base_path}_vulnerabilities.csv")
            success &= self._export_strings_csv(f"{base_path}_strings.csv")
            success &= self._export_imports_csv(f"{base_path}_imports.csv")

            with open(f"{base_path}_summary.csv", "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Category", "Count", "Details"])

                vulnerabilities = self.analysis_results.get("vulnerabilities", {})
                strings = self.analysis_results.get("strings", [])
                imports = self.analysis_results.get("imports", {})

                writer.writerow(
                    [
                        "Vulnerabilities",
                        len(vulnerabilities),
                        f"Found {len(vulnerabilities)} vulnerabilities",
                    ],
                )
                writer.writerow(["Strings", len(strings), f"Extracted {len(strings)} strings"])
                writer.writerow(["Imports", len(imports), f"Found {len(imports)} imported libraries"])

            return success
        except Exception as e:
            logger.exception("Comprehensive CSV export failed: %s", e)
            return False

    def _generate_analysis_config(self) -> dict[str, Any]:
        """Generate analysis configuration for YAML export."""
        return {
            "analysis_settings": {
                "deep_scan": True,
                "include_strings": True,
                "include_imports": True,
                "vulnerability_detection": True,
                "entropy_analysis": True,
            },
            "export_settings": {
                "include_raw_data": False,
                "detailed_reports": True,
                "executive_summary": True,
            },
            "tool_configuration": {
                "name": "Intellicrack",
                "version": "2.0",
                "scan_date": self.export_metadata["export_time"],
            },
        }

    def _generate_detection_rules(self) -> dict[str, Any]:
        """Generate detection rules based on analysis results."""
        yara_rules: list[dict[str, Any]] = []
        snort_rules: list[dict[str, Any]] = []
        sigma_rules: list[dict[str, Any]] = []

        binary_info = self.analysis_results.get("basic_info", {})
        if not isinstance(binary_info, dict):
            binary_info = {}
        file_hash = binary_info.get("md5", "") if isinstance(binary_info.get("md5"), str) else ""
        file_size = binary_info.get("size", 0) if isinstance(binary_info.get("size"), int) else 0

        strings_data = self.analysis_results.get("strings", [])
        if not isinstance(strings_data, list):
            strings_data = []

        suspicious_strings: list[str] = []
        for string in strings_data[:50]:
            if isinstance(string, str) and any(
                pattern in string.lower()
                for pattern in [
                    "crack",
                    "patch",
                    "keygen",
                    "license",
                    "trial",
                    "eval",
                    "debug",
                    "admin",
                    "root",
                    "bypass",
                ]
            ):
                suspicious_strings.append(string)

        if file_hash or suspicious_strings:
            yara_strings: list[str] = []

            for idx, string in enumerate(suspicious_strings[:10]):
                safe_string = string.replace('"', '\\"')
                yara_strings.append(f'$s{idx} = "{safe_string}"')

            vuln_data = self.analysis_results.get("vulnerabilities", {})
            if isinstance(vuln_data, dict):
                vulns = vuln_data.get("vulnerabilities", [])
                if isinstance(vulns, list):
                    for vuln in vulns[:5]:
                        if isinstance(vuln, dict) and vuln.get("pattern"):
                            pattern = vuln["pattern"]
                            if isinstance(pattern, str) and len(pattern) <= 32:
                                yara_strings.append(f"$vuln_{len(yara_strings)} = {{ {pattern} }}")

            yara_condition: str
            if yara_strings:
                yara_condition = "uint16(0) == 0x5A4D and any of them"
            else:
                yara_condition = f"uint16(0) == 0x5A4D and filesize == {file_size}"

            yara_rule: dict[str, Any] = {
                "rule_name": f"Intellicrack_Detection_{os.path.basename(self.binary_path).replace('.', '_')}",
                "meta": {
                    "author": "Intellicrack CLI",
                    "description": f"Detection rule for {os.path.basename(self.binary_path)}",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "md5": file_hash,
                    "file_size": str(file_size),
                },
                "strings": yara_strings,
                "condition": yara_condition,
            }

            yara_rules.append(yara_rule)

        network_indicators = self.analysis_results.get("network_indicators", [])
        if isinstance(network_indicators, list):
            for idx, indicator in enumerate(network_indicators[:5]):
                if isinstance(indicator, dict):
                    snort_rule: dict[str, Any] = {
                        "action": "alert",
                        "protocol": indicator.get("protocol", "tcp"),
                        "src_ip": "$HOME_NET",
                        "src_port": "any",
                        "direction": "->",
                        "dst_ip": indicator.get("destination", "$EXTERNAL_NET"),
                        "dst_port": indicator.get("port", "any"),
                        "options": {
                            "msg": f'"Intellicrack: Potential {os.path.basename(self.binary_path)} activity"',
                            "flow": "to_server,established",
                            "content": f'"{indicator.get("pattern", "")}"' if indicator.get("pattern") else None,
                            "sid": 1000000 + idx,
                            "rev": 1,
                        },
                    }
                    snort_rules.append(snort_rule)

        vuln_data = self.analysis_results.get("vulnerabilities", {})
        if suspicious_strings or (isinstance(vuln_data, dict) and vuln_data):
            sigma_rule: dict[str, Any] = {
                "title": f"Potential {os.path.basename(self.binary_path)} Execution",
                "id": f"intellicrack-{file_hash[:8] if file_hash else 'unknown'}",
                "status": "experimental",
                "description": f"Detects potential execution of {os.path.basename(self.binary_path)}",
                "author": "Intellicrack CLI",
                "date": datetime.now().strftime("%Y/%m/%d"),
                "references": ["https://github.com/zachanardo/intellicrack"],
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "EventID": 4688,
                        "NewProcessName|endswith": os.path.basename(self.binary_path),
                    },
                    "filter": {"ParentProcessName|contains": ["explorer.exe", "cmd.exe"]},
                    "condition": "selection and not filter",
                },
                "falsepositives": ["Legitimate software execution"],
                "level": "medium",
                "tags": ["attack.execution", "attack.t1204"],
            }

            if file_hash:
                sigma_rule["detection"]["selection"]["Hashes|contains"] = file_hash

            sigma_rules.append(sigma_rule)

        rules: dict[str, Any] = {
            "yara_rules": yara_rules,
            "snort_rules": snort_rules,
            "sigma_rules": sigma_rules,
        }

        return rules

    def _create_summary_sheet(
        self,
        workbook: object,
        header_format: object | None = None,
        cell_format: object | None = None,
        worksheet_name: str = "Summary",
    ) -> WorksheetProtocol | None:
        """Create summary sheet for Excel export.

        Args:
            workbook: xlsxwriter Workbook instance
            header_format: Header format object (unused, generated internally)
            cell_format: Cell format object (unused, generated internally)
            worksheet_name: Name for the worksheet

        Returns:
            The worksheet object or None if creation failed

        """
        try:
            if not isinstance(workbook, WorkbookProtocol):
                raise TypeError("Invalid workbook: does not conform to WorkbookProtocol")

            worksheet: WorksheetProtocol = workbook.add_worksheet(worksheet_name)

            header_fmt: object = workbook.add_format(
                {
                    "bold": True,
                    "bg_color": "#D7E4BC",
                    "border": 1,
                },
            )

            headers = ["Category", "Count", "Status", "Risk Level"]
            for col, header in enumerate(headers):
                worksheet.write(0, col, header, header_fmt)

            summary = self._generate_summary()
            row = 1

            worksheet.write(row, 0, "Binary Analysis", None)
            worksheet.write(row, 1, 1, None)
            worksheet.write(row, 2, "Complete", None)
            risk_assessment = summary.get("risk_assessment", {})
            if isinstance(risk_assessment, dict):
                worksheet.write(row, 3, risk_assessment.get("level", "Unknown"), None)
            else:
                worksheet.write(row, 3, "Unknown", None)
            row += 1

            vuln_count = len(self.analysis_results.get("vulnerabilities", {}))
            worksheet.write(row, 0, "Vulnerabilities", None)
            worksheet.write(row, 1, vuln_count, None)
            worksheet.write(row, 2, "Found" if vuln_count > 0 else "None", None)
            worksheet.write(row, 3, "High" if vuln_count > 5 else "Medium" if vuln_count > 0 else "Low", None)
            row += 1

            protections = self.analysis_results.get("protections", [])
            worksheet.write(row, 0, "Protections", None)
            worksheet.write(row, 1, len(protections), None)
            worksheet.write(row, 2, "Detected" if protections else "None", None)
            worksheet.write(row, 3, "High" if len(protections) > 3 else "Medium" if protections else "Low", None)

            return worksheet
        except Exception as e:
            logger.exception("Failed to create summary sheet: %s", e)
            return None

    def _create_vulnerabilities_sheet(
        self,
        workbook: object,
        header_format: object | None = None,
        cell_format: object | None = None,
        worksheet_name: str = "Vulnerabilities",
    ) -> WorksheetProtocol | None:
        """Create vulnerabilities sheet for Excel export.

        Args:
            workbook: xlsxwriter Workbook instance
            header_format: Header format object (unused, generated internally)
            cell_format: Cell format object (unused, generated internally)
            worksheet_name: Name for the worksheet

        Returns:
            The worksheet object or None if creation failed

        """
        try:
            if not isinstance(workbook, WorkbookProtocol):
                raise TypeError("Invalid workbook: does not conform to WorkbookProtocol")

            worksheet: WorksheetProtocol = workbook.add_worksheet(worksheet_name)

            header_fmt: object = workbook.add_format(
                {
                    "bold": True,
                    "bg_color": "#FFB3B3",
                    "border": 1,
                },
            )

            headers = ["Type", "Severity", "Description", "Location", "Recommendation"]
            for col, header in enumerate(headers):
                worksheet.write(0, col, header, header_fmt)

            vulnerabilities = self.analysis_results.get("vulnerabilities", {})
            row = 1

            if isinstance(vulnerabilities, dict):
                for vuln_type, vuln_data in vulnerabilities.items():
                    if isinstance(vuln_data, dict):
                        worksheet.write(row, 0, vuln_type, None)
                        worksheet.write(row, 1, vuln_data.get("severity", "Medium"), None)
                        worksheet.write(row, 2, vuln_data.get("description", ""), None)
                        worksheet.write(row, 3, vuln_data.get("location", ""), None)
                        worksheet.write(row, 4, vuln_data.get("recommendation", ""), None)
                        row += 1

            return worksheet
        except Exception as e:
            logger.exception("Failed to create vulnerabilities sheet: %s", e)
            return None

    def _create_strings_sheet(
        self,
        workbook: object,
        header_format: object | None = None,
        cell_format: object | None = None,
        worksheet_name: str = "Strings",
    ) -> WorksheetProtocol | None:
        """Create strings sheet for Excel export.

        Args:
            workbook: xlsxwriter Workbook instance
            header_format: Header format object (unused, generated internally)
            cell_format: Cell format object (unused, generated internally)
            worksheet_name: Name for the worksheet

        Returns:
            The worksheet object or None if creation failed

        """
        try:
            if not isinstance(workbook, WorkbookProtocol):
                raise TypeError("Invalid workbook: does not conform to WorkbookProtocol")

            worksheet: WorksheetProtocol = workbook.add_worksheet(worksheet_name)

            header_fmt: object = workbook.add_format(
                {
                    "bold": True,
                    "bg_color": "#B3D9FF",
                    "border": 1,
                },
            )

            headers = ["String", "Address", "Section", "Type", "Length"]
            for col, header in enumerate(headers):
                worksheet.write(0, col, header, header_fmt)

            strings_data = self.analysis_results.get("strings", [])
            if isinstance(strings_data, list):
                for row, string_item in enumerate(strings_data, start=1):
                    if isinstance(string_item, dict):
                        worksheet.write(row, 0, string_item.get("value", ""), None)
                        worksheet.write(row, 1, string_item.get("address", ""), None)
                        worksheet.write(row, 2, string_item.get("section", ""), None)
                        worksheet.write(row, 3, string_item.get("type", ""), None)
                        worksheet.write(row, 4, string_item.get("length", 0), None)
                    else:
                        worksheet.write(row, 0, str(string_item), None)
                        worksheet.write(row, 4, len(str(string_item)), None)
            return worksheet
        except Exception as e:
            logger.exception("Failed to create strings sheet: %s", e)
            return None

    def _create_imports_sheet(
        self,
        workbook: object,
        header_format: object | None = None,
        cell_format: object | None = None,
        worksheet_name: str = "Imports",
    ) -> WorksheetProtocol | None:
        """Create imports sheet for Excel export.

        Args:
            workbook: xlsxwriter Workbook instance
            header_format: Header format object (unused, generated internally)
            cell_format: Cell format object (unused, generated internally)
            worksheet_name: Name for the worksheet

        Returns:
            The worksheet object or None if creation failed

        """
        try:
            if not isinstance(workbook, WorkbookProtocol):
                raise TypeError("Invalid workbook: does not conform to WorkbookProtocol")

            worksheet: WorksheetProtocol = workbook.add_worksheet(worksheet_name)

            header_fmt: object = workbook.add_format(
                {
                    "bold": True,
                    "bg_color": "#FFE6B3",
                    "border": 1,
                },
            )

            headers = ["Library", "Function", "Address", "Ordinal"]
            for col, header in enumerate(headers):
                worksheet.write(0, col, header, header_fmt)

            imports_data = self.analysis_results.get("imports", {})
            row = 1

            if isinstance(imports_data, dict):
                for library, functions in imports_data.items():
                    if isinstance(functions, list):
                        for func in functions:
                            worksheet.write(row, 0, library, None)
                            if isinstance(func, dict):
                                worksheet.write(row, 1, func.get("name", ""), None)
                                worksheet.write(row, 2, func.get("address", ""), None)
                                worksheet.write(row, 3, func.get("ordinal", ""), None)
                            else:
                                worksheet.write(row, 1, str(func), None)
                            row += 1
                    else:
                        worksheet.write(row, 0, library, None)
                        worksheet.write(row, 1, str(functions), None)
                        row += 1

            return worksheet
        except Exception as e:
            logger.exception("Failed to create imports sheet: %s", e)
            return None

    def _create_statistics_sheet(
        self,
        workbook: object,
        header_format: object | None = None,
        cell_format: object | None = None,
        worksheet_name: str = "Statistics",
    ) -> WorksheetProtocol | None:
        """Create statistics sheet for Excel export.

        Args:
            workbook: xlsxwriter Workbook instance
            header_format: Header format object (unused, generated internally)
            cell_format: Cell format object (unused, generated internally)
            worksheet_name: Name for the worksheet

        Returns:
            The worksheet object or None if creation failed

        """
        try:
            if not isinstance(workbook, WorkbookProtocol):
                raise TypeError("Invalid workbook: does not conform to WorkbookProtocol")

            worksheet: WorksheetProtocol = workbook.add_worksheet(worksheet_name)

            header_fmt: object = workbook.add_format(
                {
                    "bold": True,
                    "bg_color": "#E6E6FA",
                    "border": 1,
                },
            )

            headers = ["Metric", "Value", "Category", "Notes"]
            for col, header in enumerate(headers):
                worksheet.write(0, col, header, header_fmt)

            statistics = self._generate_statistics()
            row = 1

            for category, stats in statistics.items():
                if isinstance(stats, dict):
                    for metric, value in stats.items():
                        worksheet.write(row, 0, metric, None)
                        worksheet.write(row, 1, str(value), None)
                        worksheet.write(row, 2, category, None)
                        worksheet.write(row, 3, f"Part of {category} analysis", None)
                        row += 1
                else:
                    worksheet.write(row, 0, category, None)
                    worksheet.write(row, 1, str(stats), None)
                    worksheet.write(row, 2, "General", None)
                    row += 1

            return worksheet
        except Exception as e:
            logger.exception("Failed to create statistics sheet: %s", e)
            return None


def get_available_formats() -> list[str]:
    """Get list of available export formats."""
    formats = ["json", "markdown", "html", "txt", "csv", "xml"]

    if YAML_AVAILABLE:
        formats.append("yaml")
    if XLSX_AVAILABLE:
        formats.append("xlsx")

    return formats


def export_analysis_results(
    binary_path: str,
    analysis_results: dict[str, Any],
    output_path: str,
    format_type: str,
    **kwargs: Unpack[ExportOptions],
) -> bool:
    """Export analysis results in specified format.

    Exports analysis results from binary analysis to various formats including
    JSON, CSV, XML, HTML, Markdown, YAML, and Excel with comprehensive metadata
    and structured reporting capabilities for software licensing analysis.

    Args:
        binary_path: Path to analyzed binary file
        analysis_results: Dictionary containing analysis results from protection detection,
            vulnerability scanning, and licensing mechanism analysis
        output_path: Output file path where results will be written
        format_type: Export format (json, markdown, html, txt, csv, xml, yaml, xlsx, vulnerability)
        **kwargs: Additional format-specific options:
            - include_raw_data (bool): Include raw binary data samples in JSON export
            - data_type (str): Type of data for CSV export (all, vulnerabilities, strings, imports)

    Returns:
        True if export was successful, False otherwise

    """
    exporter = AdvancedExporter(binary_path, analysis_results)

    format_type = format_type.lower()

    if format_type == "json":
        return exporter.export_detailed_json(output_path, kwargs.get("include_raw_data", True))
    if format_type in {"markdown", "html", "txt"}:
        return exporter.export_executive_summary(output_path, format_type)
    if format_type == "vulnerability":
        return exporter.export_vulnerability_report(output_path)
    if format_type == "csv":
        return exporter.export_csv_data(output_path, kwargs.get("data_type", "all"))
    if format_type == "xml":
        return exporter.export_xml_report(output_path)
    if format_type == "yaml":
        return exporter.export_yaml_config(output_path)
    if format_type == "xlsx":
        return exporter.export_excel_workbook(output_path)
    logger.error("Unsupported format: %s", format_type)
    logger.info("Available formats: %s", ", ".join(get_available_formats()))
    return False
