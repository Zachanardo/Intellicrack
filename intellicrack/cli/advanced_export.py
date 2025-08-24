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
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any

# Create logger for this module
logger = logging.getLogger(__name__)

# Optional imports for enhanced export capabilities
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


class AdvancedExporter:
    """Advanced export system with multiple formats and detailed reporting."""

    def __init__(self, binary_path: str, analysis_results: dict[str, Any]):
        """Initialize exporter with analysis data.

        Args:
            binary_path: Path to analyzed binary
            analysis_results: Dictionary of analysis results

        """
        self.binary_path = binary_path
        self.analysis_results = analysis_results
        self.export_metadata = {
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
            export_data = {
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
            print(f"JSON export failed: {e}")
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
            print(f"Unsupported format: {format_type}")
            return False
        except Exception as e:
            print(f"Executive summary export failed: {e}")
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

            report = {
                "metadata": self.export_metadata,
                "executive_summary": {
                    "total_vulnerabilities": len(vuln_data.get("vulnerabilities", [])),
                    "critical_count": self._count_vulnerabilities_by_severity(
                        vuln_data, "critical"
                    ),
                    "high_count": self._count_vulnerabilities_by_severity(vuln_data, "high"),
                    "medium_count": self._count_vulnerabilities_by_severity(vuln_data, "medium"),
                    "low_count": self._count_vulnerabilities_by_severity(vuln_data, "low"),
                    "risk_score": self._calculate_risk_score(vuln_data),
                },
                "detailed_findings": self._format_vulnerability_details(vuln_data),
                "mitigation_strategies": self._generate_mitigation_strategies(vuln_data),
                "compliance_notes": self._generate_compliance_notes(vuln_data),
            }

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=str, ensure_ascii=False)

            return True
        except Exception as e:
            print(f"Vulnerability report export failed: {e}")
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
            print(f"Unsupported CSV data type: {data_type}")
            return False
        except Exception as e:
            print(f"CSV export failed: {e}")
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

            # Metadata
            metadata_elem = ET.SubElement(root, "metadata")
            for key, value in self.export_metadata.items():
                elem = ET.SubElement(metadata_elem, key.replace(" ", "_"))
                elem.text = str(value)

            # Analysis results
            analysis_elem = ET.SubElement(root, "analysis_results")
            self._dict_to_xml(self.analysis_results, analysis_elem)

            # Summary
            summary_elem = ET.SubElement(root, "summary")
            summary_data = self._generate_summary()
            self._dict_to_xml(summary_data, summary_elem)

            # Write XML
            tree = ET.ElementTree(root)
            ET.indent(tree, space="  ", level=0)
            tree.write(output_path, encoding="utf-8", xml_declaration=True)

            return True
        except Exception as e:
            print(f"XML export failed: {e}")
            return False

    def export_html_report(self, output_path: str) -> bool:
        """Export analysis results as interactive HTML report.

        Args:
            output_path: Output file path

        Returns:
            True if export successful

        """
        if not JINJA2_AVAILABLE:
            print("HTML report generation not available. Install Jinja2: pip install Jinja2")
            return False

        try:
            # Basic HTML template for analysis report
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

            # Render template with data
            html_content = html_template.render(
                metadata=self.export_metadata,
                analysis_results=self.analysis_results,
                analysis_count=len(self.analysis_results),
            )

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            return True
        except Exception as e:
            print(f"HTML export failed: {e}")
            return False

    def export_yaml_config(self, output_path: str) -> bool:
        """Export analysis results as YAML configuration.

        Args:
            output_path: Output file path

        Returns:
            True if export successful

        """
        if not YAML_AVAILABLE:
            print("YAML export not available. Install PyYAML: pip install PyYAML")
            return False

        try:
            export_data = {
                "metadata": self.export_metadata,
                "analysis_config": self._generate_analysis_config(),
                "findings_summary": self._generate_summary(),
                "detection_rules": self._generate_detection_rules(),
            }

            with open(output_path, "w", encoding="utf-8") as f:
                yaml.dump(export_data, f, default_flow_style=False, allow_unicode=True)

            return True
        except Exception as e:
            print(f"YAML export failed: {e}")
            return False

    def export_excel_workbook(self, output_path: str) -> bool:
        """Export comprehensive Excel workbook with multiple sheets.

        Args:
            output_path: Output file path

        Returns:
            True if export successful

        """
        if not XLSX_AVAILABLE:
            print("Excel export not available. Install xlsxwriter: pip install xlsxwriter")
            return False

        try:
            workbook = xlsxwriter.Workbook(output_path)

            # Define formats
            header_format = workbook.add_format(
                {
                    "bold": True,
                    "bg_color": "#4472C4",
                    "font_color": "white",
                    "border": 1,
                }
            )

            cell_format = workbook.add_format({"border": 1})

            # Summary sheet
            self._create_summary_sheet(workbook, header_format, cell_format)

            # Vulnerabilities sheet
            self._create_vulnerabilities_sheet(workbook, header_format, cell_format)

            # Strings sheet
            self._create_strings_sheet(workbook, header_format, cell_format)

            # Imports sheet
            self._create_imports_sheet(workbook, header_format, cell_format)

            # Statistics sheet
            self._create_statistics_sheet(workbook, header_format, cell_format)

            workbook.close()
            return True
        except Exception as e:
            print(f"Excel export failed: {e}")
            return False

    def _generate_summary(self) -> dict[str, Any]:
        """Generate analysis summary."""
        summary = {
            "file_info": {
                "name": os.path.basename(self.binary_path),
                "path": self.binary_path,
                "size": os.path.getsize(self.binary_path)
                if os.path.exists(self.binary_path)
                else 0,
            },
            "analysis_overview": {},
            "key_findings": [],
            "security_assessment": {},
        }

        # Count different analysis types
        for analysis_type, results in self.analysis_results.items():
            if isinstance(results, dict) or isinstance(results, list):
                summary["analysis_overview"][analysis_type] = len(results)
            else:
                summary["analysis_overview"][analysis_type] = 1

        # Extract key findings
        if "vulnerabilities" in self.analysis_results:
            vuln_data = self.analysis_results["vulnerabilities"]
            if isinstance(vuln_data, dict) and "vulnerabilities" in vuln_data:
                vuln_count = len(vuln_data["vulnerabilities"])
                if vuln_count > 0:
                    summary["key_findings"].append(
                        f"{vuln_count} potential vulnerabilities detected"
                    )

        if "protections" in self.analysis_results:
            prot_data = self.analysis_results["protections"]
            if isinstance(prot_data, dict):
                enabled_protections = [k for k, v in prot_data.items() if v]
                if enabled_protections:
                    summary["key_findings"].append(
                        f"Security protections: {', '.join(enabled_protections)}"
                    )

        return summary

    def _generate_statistics(self) -> dict[str, Any]:
        """Generate analysis statistics."""
        stats = {
            "analysis_time": self.export_metadata["export_time"],
            "total_categories": len(self.analysis_results),
            "data_points": 0,
            "categories": {},
        }

        for category, data in self.analysis_results.items():
            if isinstance(data, dict) or isinstance(data, list):
                count = len(data)
            else:
                count = 1

            stats["categories"][category] = count
            stats["data_points"] += count

        return stats

    def _generate_recommendations(self) -> list[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []

        # Check for vulnerabilities
        vuln_data = self.analysis_results.get("vulnerabilities", {})
        if isinstance(vuln_data, dict) and vuln_data.get("vulnerabilities"):
            recommendations.append("Address identified vulnerabilities before deployment")
            recommendations.append("Implement input validation and bounds checking")

        # Check for protections
        prot_data = self.analysis_results.get("protections", {})
        if isinstance(prot_data, dict):
            if not prot_data.get("aslr", True):
                recommendations.append("Enable ASLR (Address Space Layout Randomization)")
            if not prot_data.get("dep", True):
                recommendations.append("Enable DEP/NX (Data Execution Prevention)")
            if not prot_data.get("canary", True):
                recommendations.append("Enable stack canaries for buffer overflow protection")

        # General recommendations
        recommendations.extend(
            [
                "Regular security audits and penetration testing",
                "Keep all dependencies and libraries updated",
                "Implement proper error handling and logging",
                "Use secure coding practices and code reviews",
            ]
        )

        return recommendations

    def _generate_executive_summary(self) -> dict[str, Any]:
        """Generate executive summary data."""
        return {
            "title": f"Security Analysis Report: {os.path.basename(self.binary_path)}",
            "analysis_date": self.export_metadata["export_time"],
            "binary_info": {
                "name": os.path.basename(self.binary_path),
                "size": os.path.getsize(self.binary_path)
                if os.path.exists(self.binary_path)
                else 0,
            },
            "risk_assessment": self._assess_overall_risk(),
            "key_findings": self._extract_key_findings(),
            "recommendations": self._generate_recommendations()[:5],  # Top 5
            "next_steps": [
                "Review and address critical vulnerabilities",
                "Implement recommended security controls",
                "Conduct follow-up testing after remediation",
            ],
        }

    def _export_markdown_summary(self, output_path: str, summary_data: dict[str, Any]) -> bool:
        """Export executive summary as Markdown."""
        content = f"""# {summary_data['title']}

**Analysis Date:** {summary_data['analysis_date']}

## Binary Information
- **Name:** {summary_data['binary_info']['name']}
- **Size:** {summary_data['binary_info']['size']:,} bytes

## Risk Assessment
**Overall Risk:** {summary_data['risk_assessment']['level']}

{summary_data['risk_assessment']['description']}

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

        content += (
            f"\n---\n*Generated by Intellicrack CLI v{self.export_metadata['export_version']}*\n"
        )

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
        risk_class = (
            risk_level.lower() if risk_level.lower() in ["high", "medium", "low"] else "medium"
        )

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
        content = f"""{summary_data['title']}
{'=' * len(summary_data['title'])}

Analysis Date: {summary_data['analysis_date']}

BINARY INFORMATION
------------------
Name: {summary_data['binary_info']['name']}
Size: {summary_data['binary_info']['size']:,} bytes

RISK ASSESSMENT
---------------
Overall Risk: {summary_data['risk_assessment']['level']}

{summary_data['risk_assessment']['description']}

KEY FINDINGS
------------
"""

        for finding in summary_data["key_findings"]:
            content += f"• {finding}\n"

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
        findings = []

        # Vulnerability findings
        vuln_data = self.analysis_results.get("vulnerabilities", {})
        if isinstance(vuln_data, dict):
            vulns = vuln_data.get("vulnerabilities", [])
            if vulns:
                findings.append(f"{len(vulns)} potential vulnerabilities identified")

        # Protection findings
        prot_data = self.analysis_results.get("protections", {})
        if isinstance(prot_data, dict):
            missing_protections = [k for k, v in prot_data.items() if not v]
            if missing_protections:
                findings.append(f"Missing security protections: {', '.join(missing_protections)}")

        # String analysis findings
        strings_data = self.analysis_results.get("strings", [])
        if isinstance(strings_data, list) and len(strings_data) > 100:
            findings.append(f"Large number of embedded strings detected ({len(strings_data)})")

        return findings

    def _count_vulnerabilities_by_severity(self, vuln_data: dict[str, Any], severity: str) -> int:
        """Count vulnerabilities by severity level."""
        if not isinstance(vuln_data, dict):
            return 0

        vulns = vuln_data.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            return 0

        count = 0
        for vuln in vulns:
            if isinstance(vuln, dict) and vuln.get("severity", "").lower() == severity.lower():
                count += 1

        return count

    def _calculate_risk_score(self, vuln_data: dict[str, Any]) -> float:
        """Calculate overall risk score."""
        if not isinstance(vuln_data, dict):
            return 0.0

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

    def _dict_to_xml(self, data: Any, parent: ET.Element):
        """Convert dictionary to XML elements."""
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
        samples = {}

        try:
            if os.path.exists(self.binary_path):
                with open(self.binary_path, "rb") as f:
                    # Read first 256 bytes
                    header_data = f.read(256)
                    samples["header_hex"] = header_data.hex()

                    # Read some data from middle
                    file_size = os.path.getsize(self.binary_path)
                    if file_size > 512:
                        f.seek(file_size // 2)
                        middle_data = f.read(128)
                        samples["middle_hex"] = middle_data.hex()
        except Exception as e:
            # File access errors during sampling are expected and non-critical
            logger.debug(f"Failed to read file samples: {e}")

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
                        }
                    )

        return True

    def _format_vulnerability_details(self, vuln_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Format vulnerability details for reporting."""
        if not isinstance(vuln_data, dict):
            return []

        vulns = vuln_data.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            return []

        formatted = []
        for vuln in vulns:
            if isinstance(vuln, dict):
                formatted.append(
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
                )

        return formatted

    def _generate_mitigation_strategies(self, vuln_data: dict[str, Any]) -> list[str]:
        """Generate mitigation strategies based on vulnerabilities."""
        strategies = [
            "Implement input validation and sanitization",
            "Use safe string handling functions",
            "Enable compiler security features (stack canaries, ASLR, DEP)",
            "Conduct regular security code reviews",
            "Implement proper error handling",
            "Use memory-safe programming languages where appropriate",
            "Regular security testing and vulnerability assessments",
        ]
        return strategies

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
            strings_data = self.analysis_results.get("strings", [])
            if not strings_data:
                strings_data = []

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
                            ]
                        )
                    else:
                        # Fallback for simple string list
                        writer.writerow([str(string_item), "", "", "", len(str(string_item))])

            return True
        except Exception as e:
            print(f"Strings CSV export failed: {e}")
            return False

    def _export_imports_csv(self, output_path: str) -> bool:
        """Export imports data to CSV format."""
        try:
            imports_data = self.analysis_results.get("imports", {})
            if not imports_data:
                imports_data = {}

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
                                    ]
                                )
                            else:
                                writer.writerow([library, str(func), "", ""])
                    else:
                        writer.writerow([library, str(functions), "", ""])

            return True
        except Exception as e:
            print(f"Imports CSV export failed: {e}")
            return False

    def _export_comprehensive_csv(self, output_path: str) -> bool:
        """Export comprehensive analysis data to CSV format."""
        try:
            # Use base filename to create multiple files
            base_path = os.path.splitext(output_path)[0]

            # Export different data types to separate files
            success = True
            success &= self._export_vulnerabilities_csv(f"{base_path}_vulnerabilities.csv")
            success &= self._export_strings_csv(f"{base_path}_strings.csv")
            success &= self._export_imports_csv(f"{base_path}_imports.csv")

            # Create summary CSV
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
                    ]
                )
                writer.writerow(["Strings", len(strings), f"Extracted {len(strings)} strings"])
                writer.writerow(
                    ["Imports", len(imports), f"Found {len(imports)} imported libraries"]
                )

            return success
        except Exception as e:
            print(f"Comprehensive CSV export failed: {e}")
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
        rules = {
            "yara_rules": [],
            "snort_rules": [],
            "sigma_rules": [],
        }

        # Extract binary metadata for rule generation
        binary_info = self.analysis_results.get("basic_info", {})
        file_hash = binary_info.get("md5", "")
        file_size = binary_info.get("size", 0)

        # Extract strings for pattern matching
        strings_data = self.analysis_results.get("strings", [])
        suspicious_strings = []
        for string in strings_data[:50]:  # Analyze first 50 strings
            if isinstance(string, str):
                # Look for suspicious patterns
                if any(
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

        # Generate YARA rules
        if file_hash or suspicious_strings:
            yara_rule = {
                "rule_name": f"Intellicrack_Detection_{os.path.basename(self.binary_path).replace('.', '_')}",
                "meta": {
                    "author": "Intellicrack CLI",
                    "description": f"Detection rule for {os.path.basename(self.binary_path)}",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "md5": file_hash,
                    "file_size": str(file_size),
                },
                "strings": [],
                "condition": "",
            }

            # Add string patterns
            for idx, string in enumerate(suspicious_strings[:10]):
                safe_string = string.replace('"', '\\"')
                yara_rule["strings"].append(f'$s{idx} = "{safe_string}"')

            # Add hex patterns for common vulnerability signatures
            vuln_data = self.analysis_results.get("vulnerabilities", {})
            if isinstance(vuln_data, dict):
                vulns = vuln_data.get("vulnerabilities", [])
                for vuln in vulns[:5]:
                    if isinstance(vuln, dict) and vuln.get("pattern"):
                        pattern = vuln["pattern"]
                        if len(pattern) <= 32:  # Reasonable hex pattern length
                            yara_rule["strings"].append(
                                f'$vuln_{len(yara_rule["strings"])} = {{ {pattern} }}'
                            )

            # Build condition
            if yara_rule["strings"]:
                yara_rule["condition"] = (
                    "uint16(0) == 0x5A4D and any of them"  # PE file check + any string
                )
            else:
                yara_rule["condition"] = f"uint16(0) == 0x5A4D and filesize == {file_size}"

            rules["yara_rules"].append(yara_rule)

        # Generate Snort rules for network detection
        network_indicators = self.analysis_results.get("network_indicators", [])
        for idx, indicator in enumerate(network_indicators[:5]):
            if isinstance(indicator, dict):
                snort_rule = {
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
                        "content": f'"{indicator.get("pattern", "")}"'
                        if indicator.get("pattern")
                        else None,
                        "sid": 1000000 + idx,
                        "rev": 1,
                    },
                }
                rules["snort_rules"].append(snort_rule)

        # Generate Sigma rules for log detection
        if suspicious_strings or vuln_data:
            sigma_rule = {
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

            # Add hash-based detection if available
            if file_hash:
                sigma_rule["detection"]["selection"]["Hashes|contains"] = file_hash

            rules["sigma_rules"].append(sigma_rule)

        return rules

    def _create_summary_sheet(
        self, workbook, header_format=None, cell_format=None, worksheet_name: str = "Summary"
    ):
        """Create summary sheet for Excel export."""
        try:
            worksheet = workbook.add_worksheet(worksheet_name)

            # Header format
            header_format = workbook.add_format(
                {
                    "bold": True,
                    "bg_color": "#D7E4BC",
                    "border": 1,
                }
            )

            # Write headers
            headers = ["Category", "Count", "Status", "Risk Level"]
            for col, header in enumerate(headers):
                worksheet.write(0, col, header, header_format)

            # Write summary data
            summary = self._generate_summary()
            row = 1

            # Binary info
            worksheet.write(row, 0, "Binary Analysis")
            worksheet.write(row, 1, 1)
            worksheet.write(row, 2, "Complete")
            worksheet.write(row, 3, summary.get("risk_assessment", {}).get("level", "Unknown"))
            row += 1

            # Vulnerabilities
            vuln_count = len(self.analysis_results.get("vulnerabilities", {}))
            worksheet.write(row, 0, "Vulnerabilities")
            worksheet.write(row, 1, vuln_count)
            worksheet.write(row, 2, "Found" if vuln_count > 0 else "None")
            worksheet.write(
                row, 3, "High" if vuln_count > 5 else "Medium" if vuln_count > 0 else "Low"
            )
            row += 1

            # Protections
            protections = self.analysis_results.get("protections", [])
            worksheet.write(row, 0, "Protections")
            worksheet.write(row, 1, len(protections))
            worksheet.write(row, 2, "Detected" if protections else "None")
            worksheet.write(
                row, 3, "High" if len(protections) > 3 else "Medium" if protections else "Low"
            )

            return worksheet
        except Exception as e:
            print(f"Failed to create summary sheet: {e}")
            return None

    def _create_vulnerabilities_sheet(
        self,
        workbook,
        header_format=None,
        cell_format=None,
        worksheet_name: str = "Vulnerabilities",
    ):
        """Create vulnerabilities sheet for Excel export."""
        try:
            worksheet = workbook.add_worksheet(worksheet_name)

            # Header format
            header_format = workbook.add_format(
                {
                    "bold": True,
                    "bg_color": "#FFB3B3",
                    "border": 1,
                }
            )

            # Write headers
            headers = ["Type", "Severity", "Description", "Location", "Recommendation"]
            for col, header in enumerate(headers):
                worksheet.write(0, col, header, header_format)

            # Write vulnerability data
            vulnerabilities = self.analysis_results.get("vulnerabilities", {})
            row = 1

            for vuln_type, vuln_data in vulnerabilities.items():
                if isinstance(vuln_data, dict):
                    worksheet.write(row, 0, vuln_type)
                    worksheet.write(row, 1, vuln_data.get("severity", "Medium"))
                    worksheet.write(row, 2, vuln_data.get("description", ""))
                    worksheet.write(row, 3, vuln_data.get("location", ""))
                    worksheet.write(row, 4, vuln_data.get("recommendation", ""))
                    row += 1

            return worksheet
        except Exception as e:
            print(f"Failed to create vulnerabilities sheet: {e}")
            return None

    def _create_strings_sheet(
        self, workbook, header_format=None, cell_format=None, worksheet_name: str = "Strings"
    ):
        """Create strings sheet for Excel export."""
        try:
            worksheet = workbook.add_worksheet(worksheet_name)

            # Header format
            header_format = workbook.add_format(
                {
                    "bold": True,
                    "bg_color": "#B3D9FF",
                    "border": 1,
                }
            )

            # Write headers
            headers = ["String", "Address", "Section", "Type", "Length"]
            for col, header in enumerate(headers):
                worksheet.write(0, col, header, header_format)

            # Write strings data
            strings_data = self.analysis_results.get("strings", [])
            row = 1

            for string_item in strings_data:
                if isinstance(string_item, dict):
                    worksheet.write(row, 0, string_item.get("value", ""))
                    worksheet.write(row, 1, string_item.get("address", ""))
                    worksheet.write(row, 2, string_item.get("section", ""))
                    worksheet.write(row, 3, string_item.get("type", ""))
                    worksheet.write(row, 4, string_item.get("length", 0))
                else:
                    worksheet.write(row, 0, str(string_item))
                    worksheet.write(row, 4, len(str(string_item)))
                row += 1

            return worksheet
        except Exception as e:
            print(f"Failed to create strings sheet: {e}")
            return None

    def _create_imports_sheet(
        self, workbook, header_format=None, cell_format=None, worksheet_name: str = "Imports"
    ):
        """Create imports sheet for Excel export."""
        try:
            worksheet = workbook.add_worksheet(worksheet_name)

            # Header format
            header_format = workbook.add_format(
                {
                    "bold": True,
                    "bg_color": "#FFE6B3",
                    "border": 1,
                }
            )

            # Write headers
            headers = ["Library", "Function", "Address", "Ordinal"]
            for col, header in enumerate(headers):
                worksheet.write(0, col, header, header_format)

            # Write imports data
            imports_data = self.analysis_results.get("imports", {})
            row = 1

            for library, functions in imports_data.items():
                if isinstance(functions, list):
                    for func in functions:
                        if isinstance(func, dict):
                            worksheet.write(row, 0, library)
                            worksheet.write(row, 1, func.get("name", ""))
                            worksheet.write(row, 2, func.get("address", ""))
                            worksheet.write(row, 3, func.get("ordinal", ""))
                        else:
                            worksheet.write(row, 0, library)
                            worksheet.write(row, 1, str(func))
                        row += 1
                else:
                    worksheet.write(row, 0, library)
                    worksheet.write(row, 1, str(functions))
                    row += 1

            return worksheet
        except Exception as e:
            print(f"Failed to create imports sheet: {e}")
            return None

    def _create_statistics_sheet(
        self, workbook, header_format=None, cell_format=None, worksheet_name: str = "Statistics"
    ):
        """Create statistics sheet for Excel export."""
        try:
            worksheet = workbook.add_worksheet(worksheet_name)

            # Header format
            header_format = workbook.add_format(
                {
                    "bold": True,
                    "bg_color": "#E6E6FA",
                    "border": 1,
                }
            )

            # Write headers
            headers = ["Metric", "Value", "Category", "Notes"]
            for col, header in enumerate(headers):
                worksheet.write(0, col, header, header_format)

            # Write statistics
            statistics = self._generate_statistics()
            row = 1

            for category, stats in statistics.items():
                if isinstance(stats, dict):
                    for metric, value in stats.items():
                        worksheet.write(row, 0, metric)
                        worksheet.write(row, 1, str(value))
                        worksheet.write(row, 2, category)
                        worksheet.write(row, 3, f"Part of {category} analysis")
                        row += 1
                else:
                    worksheet.write(row, 0, category)
                    worksheet.write(row, 1, str(stats))
                    worksheet.write(row, 2, "General")
                    row += 1

            return worksheet
        except Exception as e:
            print(f"Failed to create statistics sheet: {e}")
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
    binary_path: str, analysis_results: dict[str, Any], output_path: str, format_type: str, **kwargs
) -> bool:
    """Export analysis results in specified format.

    Args:
        binary_path: Path to analyzed binary
        analysis_results: Analysis results dictionary
        output_path: Output file path
        format_type: Export format
        **kwargs: Additional format-specific options

    Returns:
        True if export successful

    """
    exporter = AdvancedExporter(binary_path, analysis_results)

    format_type = format_type.lower()

    if format_type == "json":
        return exporter.export_detailed_json(output_path, kwargs.get("include_raw_data", True))
    if format_type in ["markdown", "html", "txt"]:
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
    print(f"Unsupported format: {format_type}")
    print(f"Available formats: {', '.join(get_available_formats())}")
    return False
