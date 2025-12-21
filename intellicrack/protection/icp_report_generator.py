"""ICP (Intellicrack Protection Engine) Report Generator.

Generates comprehensive analysis reports from ICP engine results.
Supports multiple output formats including HTML, PDF, and text.

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

import datetime
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger
from .unified_protection_engine import UnifiedProtectionResult


logger = get_logger(__name__)


@dataclass
class ReportOptions:
    """Options for report generation.

    Attributes:
        include_raw_json: Whether to include raw JSON analysis data in report
        include_bypass_methods: Whether to include bypass method recommendations
        include_entropy_graph: Whether to include entropy analysis graphs
        include_recommendations: Whether to include analysis recommendations
        include_technical_details: Whether to include technical details section
        output_format: Report output format (html, pdf, text, or json)

    """

    include_raw_json: bool = False
    include_bypass_methods: bool = True
    include_entropy_graph: bool = True
    include_recommendations: bool = True
    include_technical_details: bool = True
    output_format: str = "html"


class ICPReportGenerator:
    """Generate comprehensive reports from ICP analysis results."""

    def __init__(self) -> None:
        """Initialize the ICP report generator with template and output directory paths."""
        self.report_template_path = Path(__file__).parent / "templates"
        self.report_output_path = Path.home() / "Intellicrack_Reports"
        self.report_output_path.mkdir(exist_ok=True)

    def generate_report(
        self,
        result: UnifiedProtectionResult,
        options: ReportOptions | None = None,
    ) -> str:
        """Generate a comprehensive report from analysis results.

        Args:
            result: Unified protection analysis result containing all detected
                protections and analysis data.
            options: Report generation options. If None, defaults are used.

        Returns:
            Path to generated report file as string.

        Raises:
            ValueError: If output format specified in options is unsupported.

        """
        if options is None:
            options = ReportOptions()

        # Generate report filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = Path(result.file_path).stem
        report_name = f"{base_name}_analysis_{timestamp}"

        # Generate report based on format
        if options.output_format == "html":
            return self._generate_html_report(result, options, report_name)
        if options.output_format == "text":
            return self._generate_text_report(result, options, report_name)
        if options.output_format == "json":
            return self._generate_json_report(result, options, report_name)
        error_msg = f"Unsupported output format: {options.output_format}"
        logger.error(error_msg)
        raise ValueError(error_msg)

    def _generate_html_report(
        self,
        result: UnifiedProtectionResult,
        options: ReportOptions,
        report_name: str,
    ) -> str:
        """Generate HTML formatted protection analysis report.

        Creates a comprehensive HTML report with styled sections including
        protection detections, analysis recommendations, and bypass strategies.

        Args:
            result: Unified protection analysis result to include in report.
            options: Report generation options controlling which sections to include.
            report_name: Base filename for the report (without extension).

        Returns:
            Path to generated HTML report file as string.

        """
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intellicrack Protection Analysis Report - {Path(result.file_path).name}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        h3 {{
            color: #7f8c8d;
        }}
        .summary {{
            background-color: #ecf0f1;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .detection {{
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
        }}
        .detection.critical {{
            border-left: 5px solid #e74c3c;
        }}
        .detection.high {{
            border-left: 5px solid #f39c12;
        }}
        .detection.medium {{
            border-left: 5px solid #3498db;
        }}
        .detection.low {{
            border-left: 5px solid #2ecc71;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 5px;
        }}
        .badge.packer {{
            background-color: #f39c12;
            color: white;
        }}
        .badge.protector {{
            background-color: #e74c3c;
            color: white;
        }}
        .badge.license {{
            background-color: #3498db;
            color: white;
        }}
        .badge.drm {{
            background-color: #9b59b6;
            color: white;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #34495e;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .code {{
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 14px;
            overflow-x: auto;
        }}
        .timestamp {{
            color: #7f8c8d;
            font-size: 14px;
        }}
        .confidence {{
            font-weight: bold;
        }}
        .confidence.high {{
            color: #27ae60;
        }}
        .confidence.medium {{
            color: #f39c12;
        }}
        .confidence.low {{
            color: #e74c3c;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Intellicrack Protection Analysis Report</h1>
        <p class="timestamp">Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

        {self._generate_summary_section(result)}

        {self._generate_file_info_section(result)}

        {self._generate_protections_section(result, options)}

        {self._generate_icp_analysis_section(result)}

        {(options.include_recommendations and self._generate_recommendations_section(result)) or ""}

        {(options.include_bypass_methods and self._generate_bypass_methods_section(result)) or ""}

        {(options.include_technical_details and self._generate_technical_details_section(result)) or ""}

        {(options.include_raw_json and self._generate_raw_data_section(result)) or ""}

        <hr>
        <p style="text-align: center; color: #7f8c8d;">
            Report generated by Intellicrack v{self._get_version()} |
            ICP Engine Analysis |
            © 2025 Zachary Flint
        </p>
    </div>
</body>
</html>"""

        # Save report
        report_path = self.report_output_path / f"{report_name}.html"
        report_path.write_text(html_content, encoding="utf-8")

        logger.info("HTML report generated: %s", report_path)
        return str(report_path)

    def _generate_summary_section(self, result: UnifiedProtectionResult) -> str:
        """Generate summary section HTML content.

        Args:
            result: Unified protection analysis result for creating summary.

        Returns:
            HTML string containing executive summary section.

        """
        confidence_class = "high" if result.confidence_score >= 80 else "medium" if result.confidence_score >= 50 else "low"

        return f"""
        <div class="summary">
            <h2>Executive Summary</h2>
            <p><strong>File:</strong> {Path(result.file_path).name}</p>
            <p><strong>File Type:</strong> {result.file_type}</p>
            <p><strong>Architecture:</strong> {result.architecture}</p>
            <p><strong>Protection Status:</strong> {"Protected" if result.is_protected else "Not Protected"}</p>
            <p><strong>Packed:</strong> {"Yes" if result.is_packed else "No"}</p>
            <p><strong>Total Protections Found:</strong> {len(result.protections)}</p>
            <p><strong>Overall Confidence:</strong> <span class="confidence {confidence_class}">{result.confidence_score:.1f}%</span></p>
            <p><strong>Analysis Time:</strong> {result.analysis_time:.2f} seconds</p>
            <p><strong>Engines Used:</strong> {", ".join(result.engines_used)}</p>
        </div>
        """

    def _generate_file_info_section(self, result: UnifiedProtectionResult) -> str:
        """Generate file information section HTML.

        Args:
            result: Unified protection analysis result containing file metadata.

        Returns:
            HTML string containing file information table.

        """
        file_path = Path(result.file_path)
        file_size = file_path.stat().st_size if file_path.exists() else 0

        html = """
        <h2>File Information</h2>
        <table>
            <tr>
                <th>Property</th>
                <th>Value</th>
            </tr>
        """

        html += f"""
            <tr><td>Full Path</td><td>{result.file_path}</td></tr>
            <tr><td>File Name</td><td>{file_path.name}</td></tr>
            <tr><td>File Size</td><td>{self._format_size(file_size)}</td></tr>
            <tr><td>File Type</td><td>{result.file_type}</td></tr>
            <tr><td>Architecture</td><td>{result.architecture}</td></tr>
        """

        if result.icp_analysis and result.icp_analysis.file_infos:
            for info in result.icp_analysis.file_infos:
                html += f"""
                    <tr><td>ICP File Type</td><td>{info.filetype}</td></tr>
                    <tr><td>ICP Size</td><td>{info.size}</td></tr>
                """

        html += "</table>"
        return html

    def _generate_protections_section(
        self,
        result: UnifiedProtectionResult,
        options: ReportOptions,
    ) -> str:
        """Generate detected protections section HTML.

        Args:
            result: Unified protection analysis result containing detections.
            options: Report generation options controlling bypass recommendations display.

        Returns:
            HTML string containing detected protections section with details.

        """
        if not result.protections:
            return "<h2>Detected Protections</h2><p>No protections detected.</p>"

        html = "<h2>Detected Protections</h2>"

        for protection in result.protections:
            severity_class = self._get_severity_class(protection.get("type", ""))
            badge_class = protection.get("type", "unknown").lower().replace("-", "")

            html += f"""
            <div class="detection {severity_class}">
                <h3>{protection["name"]} <span class="badge {badge_class}">{protection["type"]}</span></h3>
                <p><strong>Confidence:</strong> {protection.get("confidence", 0):.1f}%</p>
                <p><strong>Source:</strong> {protection.get("source", "Unknown")}</p>
            """

            if protection.get("version"):
                html += f"<p><strong>Version:</strong> {protection['version']}</p>"

            if protection.get("details"):
                html += f"<p><strong>Details:</strong> {self._format_details(protection['details'])}</p>"

            if options.include_bypass_methods and protection.get("bypass_recommendations"):
                html += "<h4>Bypass Recommendations:</h4><ul>"
                for rec in protection["bypass_recommendations"]:
                    html += f"<li>{rec}</li>"
                html += "</ul>"

            html += "</div>"

        return html

    def _generate_icp_analysis_section(self, result: UnifiedProtectionResult) -> str:
        """Generate ICP engine analysis section HTML.

        Args:
            result: Unified protection analysis result containing ICP engine data.

        Returns:
            HTML string containing ICP engine analysis section.

        """
        if not result.icp_analysis:
            return ""

        html = "<h2>ICP Engine Analysis</h2>"

        if result.icp_analysis.error:
            html += f'<p style="color: #e74c3c;">Error: {result.icp_analysis.error}</p>'
            return html

        for file_info in result.icp_analysis.file_infos:
            html += f"<h3>File: {file_info.filetype}</h3>"

            if file_info.detections:
                html += "<table><tr><th>Detection</th><th>Type</th><th>Version</th><th>Info</th></tr>"

                for detection in file_info.detections:
                    html += f"""
                    <tr>
                        <td>{detection.name}</td>
                        <td><span class="badge {detection.type.lower()}">{detection.type}</span></td>
                        <td>{detection.version or "N/A"}</td>
                        <td>{detection.info or "N/A"}</td>
                    </tr>
                    """

                html += "</table>"
            else:
                html += "<p>No specific detections for this file.</p>"

        return html

    def _generate_recommendations_section(self, result: UnifiedProtectionResult) -> str:
        """Generate analysis recommendations section HTML.

        Args:
            result: Unified protection analysis result for generating recommendations.

        Returns:
            HTML string containing analysis recommendations section.

        """
        html = "<h2>Analysis Recommendations</h2>"

        recommendations = []

        if result.is_packed:
            recommendations.append(
                {
                    "title": "Unpacking Required",
                    "desc": "The file is packed. Use dynamic analysis tools to unpack before further analysis.",
                    "tools": ["x64dbg", "Process Dump", "Scylla"],
                },
            )

        if result.has_anti_debug:
            recommendations.append(
                {
                    "title": "Anti-Debug Bypass Needed",
                    "desc": "Anti-debugging mechanisms detected. Use kernel-mode debuggers or anti-anti-debug plugins.",
                    "tools": ["ScyllaHide", "TitanHide", "VirtualKD"],
                },
            )

        if result.has_licensing:
            recommendations.append(
                {
                    "title": "License Analysis",
                    "desc": "Licensing system detected. Analyze license validation routines and key algorithms.",
                    "tools": ["Ghidra", "API Monitor", "WinAPIOverride"],
                },
            )

        if not recommendations:
            html += "<p>Standard analysis approach recommended.</p>"
        else:
            for rec in recommendations:
                html += f"""
                <div class="detection medium">
                    <h3>{rec["title"]}</h3>
                    <p>{rec["desc"]}</p>
                    <p><strong>Recommended Tools:</strong> {", ".join(rec["tools"])}</p>
                </div>
                """

        return html

    def _generate_bypass_methods_section(self, result: UnifiedProtectionResult) -> str:
        """Generate bypass strategies section HTML.

        Args:
            result: Unified protection analysis result containing bypass strategies.

        Returns:
            HTML string containing bypass strategies section.

        """
        if not result.bypass_strategies:
            return ""

        html = "<h2>Bypass Strategies</h2>"

        for strategy in result.bypass_strategies:
            html += f"""
            <div class="detection low">
                <h3>{strategy["name"]}</h3>
                <p>{strategy["description"]}</p>
                <p><strong>Difficulty:</strong> {strategy["difficulty"]}</p>
                <p><strong>Tools:</strong> {", ".join(strategy["tools"])}</p>
                <h4>Steps:</h4>
                <ol>
            """

            for step in strategy["steps"]:
                html += f"<li>{step}</li>"

            html += "</ol></div>"

        return html

    def _generate_technical_details_section(self, result: UnifiedProtectionResult) -> str:
        """Generate technical details section HTML.

        Args:
            result: Unified protection analysis result containing technical details.

        Returns:
            HTML string containing technical details and feature status table.

        """
        html = "<h2>Technical Details</h2>"

        # Add entropy information if available
        if hasattr(result, "entropy_data"):
            html += "<h3>Entropy Analysis</h3>"
            html += "<p>High entropy sections may indicate packing or encryption.</p>"
            # Would add entropy graph here if matplotlib is available

        # Add feature flags
        html += "<h3>Protection Features</h3>"
        html += "<table><tr><th>Feature</th><th>Status</th></tr>"

        features = [
            ("Packed", result.is_packed),
            ("Protected", result.is_protected),
            ("Obfuscated", result.is_obfuscated),
            ("Anti-Debug", result.has_anti_debug),
            ("Anti-VM", result.has_anti_vm),
            ("Licensing", result.has_licensing),
        ]

        for feature, status in features:
            status_text = "Yes" if status else "No"
            color = "#27ae60" if status else "#95a5a6"
            html += f'<tr><td>{feature}</td><td style="color: {color}; font-weight: bold;">{status_text}</td></tr>'

        html += "</table>"

        return html

    def _generate_raw_data_section(self, result: UnifiedProtectionResult) -> str:
        """Generate raw analysis data section HTML.

        Args:
            result: Unified protection analysis result containing raw JSON data.

        Returns:
            HTML string containing raw data section.

        """
        html = "<h2>Raw Analysis Data</h2>"

        if result.icp_analysis and result.icp_analysis.raw_json:
            json_str = json.dumps(result.icp_analysis.raw_json, indent=2)
            html += f'<div class="code"><pre>{json_str}</pre></div>'

        return html

    def _generate_text_report(
        self,
        result: UnifiedProtectionResult,
        options: ReportOptions,
        report_name: str,
    ) -> str:
        """Generate plain text formatted protection analysis report.

        Args:
            result: Unified protection analysis result to include in report.
            options: Report generation options controlling which sections to include.
            report_name: Base filename for the report (without extension).

        Returns:
            Path to generated text report file as string.

        """
        lines = [
            "=" * 80,
            "INTELLICRACK PROTECTION ANALYSIS REPORT",
            "=" * 80,
            f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "FILE INFORMATION:",
        ]
        lines.extend((
            f"  File: {result.file_path}",
            f"  Type: {result.file_type}",
            f"  Architecture: {result.architecture}",
            f"  Protected: {'Yes' if result.is_protected else 'No'}",
            f"  Packed: {'Yes' if result.is_packed else 'No'}",
            f"  Confidence: {result.confidence_score:.1f}%",
            "",
            "DETECTED PROTECTIONS:",
        ))
        if result.protections:
            for i, protection in enumerate(result.protections, 1):
                lines.extend((
                    f"  {i}. {protection['name']}",
                    f"     Type: {protection['type']}",
                ))
                lines.append(f"     Confidence: {protection.get('confidence', 0):.1f}%")
                lines.append(f"     Source: {protection.get('source', 'Unknown')}")
                if protection.get("version"):
                    lines.append(f"     Version: {protection['version']}")
                lines.append("")
        else:
            lines.extend(("  No protections detected", ""))
        # ICP Analysis
        if result.icp_analysis and result.icp_analysis.all_detections:
            lines.append("ICP ENGINE DETECTIONS:")
            for detection in result.icp_analysis.all_detections:
                lines.append(f"  - {detection.name} [{detection.type}]")
                if detection.version:
                    lines.append(f"    Version: {detection.version}")
            lines.append("")

        # Recommendations
        if options.include_recommendations:
            lines.append("RECOMMENDATIONS:")
            if result.is_packed:
                lines.append("  - Unpack the binary before static analysis")
            if result.has_anti_debug:
                lines.append("  - Use anti-anti-debug techniques")
            if result.has_licensing:
                lines.append("  - Analyze license validation routines")
            lines.append("")

        # Save report
        report_path = self.report_output_path / f"{report_name}.txt"
        report_path.write_text("\n".join(lines), encoding="utf-8")

        logger.info("Text report generated: %s", report_path)
        return str(report_path)

    def _generate_json_report(
        self,
        result: UnifiedProtectionResult,
        options: ReportOptions,
        report_name: str,
    ) -> str:
        """Generate JSON formatted protection analysis report.

        Args:
            result: Unified protection analysis result to include in report.
            options: Report generation options controlling which sections to include.
            report_name: Base filename for the report (without extension).

        Returns:
            Path to generated JSON report file as string.

        """
        report_data = {
            "metadata": {
                "generated": datetime.datetime.now().isoformat(),
                "version": self._get_version(),
                "file_path": result.file_path,
                "file_name": Path(result.file_path).name,
            },
            "summary": {
                "file_type": result.file_type,
                "architecture": result.architecture,
                "is_protected": result.is_protected,
                "is_packed": result.is_packed,
                "is_obfuscated": result.is_obfuscated,
                "has_anti_debug": result.has_anti_debug,
                "has_anti_vm": result.has_anti_vm,
                "has_licensing": result.has_licensing,
                "confidence_score": result.confidence_score,
                "analysis_time": result.analysis_time,
                "engines_used": result.engines_used,
            },
            "protections": [
                {
                    "name": p["name"],
                    "type": p["type"],
                    "confidence": p.get("confidence", 0),
                    "source": p.get("source", "Unknown"),
                    "version": p.get("version", ""),
                    "details": p.get("details", {}),
                }
                for p in result.protections
            ],
            "bypass_strategies": result.bypass_strategies,
        }

        # Add ICP analysis if available
        if result.icp_analysis:
            report_data["icp_analysis"] = {
                "detections": [
                    {
                        "name": d.name,
                        "type": d.type,
                        "version": d.version,
                        "info": d.info,
                        "confidence": d.confidence,
                    }
                    for d in result.icp_analysis.all_detections
                ],
                "error": result.icp_analysis.error,
            }

            if options.include_raw_json and result.icp_analysis.raw_json:
                report_data["icp_raw"] = result.icp_analysis.raw_json

        # Save report
        report_path = self.report_output_path / f"{report_name}.json"
        report_path.write_text(
            json.dumps(report_data, indent=2),
            encoding="utf-8",
        )

        logger.info("JSON report generated: %s", report_path)
        return str(report_path)

    def _get_severity_class(self, protection_type: str) -> str:
        """Get CSS class for protection severity level.

        Args:
            protection_type: Type of protection mechanism.

        Returns:
            CSS class name corresponding to severity level.

        """
        severity_map = {
            "protector": "critical",
            "license": "high",
            "drm": "high",
            "packer": "medium",
            "obfuscator": "medium",
            "anti-debug": "medium",
            "anti-vm": "low",
        }
        return severity_map.get(protection_type.lower(), "low")

    def _format_size(self, size: int) -> str:
        """Format file size in human readable format.

        Args:
            size: File size in bytes.

        Returns:
            Human readable file size string with units (B, KB, MB, GB, TB).

        """
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

    def _format_details(self, details: object) -> str:
        """Format details object for display in reports.

        Args:
            details: Details object (dict, list, or string) to format.

        Returns:
            Formatted string representation suitable for display.

        """
        if isinstance(details, dict):
            items = [f"{key}: {value}" for key, value in details.items()]
            return ", ".join(items)
        return str(details)

    def _get_version(self) -> str:
        """Get Intellicrack version string.

        Returns:
            Version string from package metadata or default version.

        """
        try:
            import intellicrack

            return getattr(intellicrack, "__version__", "1.0.0")
        except Exception:
            return "1.0.0"
