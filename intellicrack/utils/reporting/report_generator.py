"""
Report generation utilities for the Intellicrack framework.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import datetime
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Module logger
logger = logging.getLogger(__name__)


class ReportGenerator:
    """Base class for report generation with common functionality."""

    def __init__(self, output_dir: str = "reports"):
        """
        Initialize the report generator.

        Args:
            output_dir: Directory to save generated reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.sections = []
        self.metadata = {
            'title': 'Analysis Report',
            'author': 'Intellicrack',
            'generated': datetime.datetime.now().isoformat()
        }

    def set_metadata(self, title: str = None, author: str = None, **kwargs):
        """Set report metadata."""
        if title:
            self.metadata['title'] = title
        if author:
            self.metadata['author'] = author
        self.metadata.update(kwargs)

    def add_section(self, title: str, content: Any) -> int:
        """
        Add a section to the report.

        Args:
            title: Section title
            content: Section content

        Returns:
            int: Section index
        """
        section = {
            'title': title,
            'content': content,
            'timestamp': datetime.datetime.now().isoformat()
        }
        self.sections.append(section)
        return len(self.sections) - 1


def generate_report(analysis_results: Dict[str, Any], output_format: str = 'text',
                   output_path: Optional[Union[str, Path]] = None) -> str:
    """
    Generate an analysis report in the specified format.

    Args:
        analysis_results: Dictionary containing analysis results
        output_format: Report format (text, json, html)
        output_path: Optional output path

    Returns:
        str: Path to the generated report
    """
    if output_path is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.{output_format}"
        output_path = Path("reports") / filename
    else:
        output_path = Path(output_path)

    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_format == 'text':
        content = generate_text_report(analysis_results)
    elif output_format == 'json':
        content = json.dumps(analysis_results, indent=2, default=str)
    elif output_format == 'html':
        content = generate_html_report(analysis_results)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")

    # Write report
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)

    logger.info("Report generated: %s", output_path)
    return str(output_path)


def generate_text_report(results: Dict[str, Any]) -> str:
    """
    Generate a text-based report.

    Args:
        results: Analysis results

    Returns:
        str: Text report content
    """
    lines = []
    lines.append("=" * 80)
    lines.append("INTELLICRACK ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append(f"Generated: {datetime.datetime.now()}")
    lines.append("")

    # Binary information
    if 'binary_info' in results:
        lines.append("BINARY INFORMATION")
        lines.append("-" * 40)
        for key, value in results['binary_info'].items():
            lines.append(f"  {key}: {value}")
        lines.append("")

    # Vulnerabilities
    if 'vulnerabilities' in results:
        lines.append("VULNERABILITIES")
        lines.append("-" * 40)
        for vulnerability in results['vulnerabilities']:
            lines.append(f"  [{vulnerability.get('severity', 'UNKNOWN')}] {vulnerability.get('name', 'Unknown')}")
            if 'description' in vulnerability:
                lines.append(f"    {vulnerability['description']}")
        lines.append("")

    # Protection mechanisms
    if 'protections' in results:
        lines.append("PROTECTION MECHANISMS")
        lines.append("-" * 40)
        for protection_item in results['protections']:
            lines.append(f"  - {protection_item}")
        lines.append("")

    # Analysis summary
    if 'summary' in results:
        lines.append("SUMMARY")
        lines.append("-" * 40)
        lines.append(results['summary'])
        lines.append("")

    lines.append("=" * 80)
    lines.append("END OF REPORT")
    lines.append("=" * 80)

    return '\n'.join(lines)


def generate_html_report(results: Dict[str, Any]) -> str:
    """
    Generate an HTML report.

    Args:
        results: Analysis results

    Returns:
        str: HTML report content
    """
    html_parts = ["""
<!DOCTYPE html>
<html>
<head>
    <title>Intellicrack Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }
        h2 { color: #666; margin-top: 30px; }
        .section { margin-bottom: 30px; }
        .info-table { border-collapse: collapse; width: 100%; }
        .info-table td, .info-table th { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .info-table tr:nth-child(even) { background-color: #f2f2f2; }
        .vulnerability { padding: 10px; margin: 10px 0; border-radius: 5px; }
        .critical { background-color: #ffcccc; }
        .high { background-color: #ffe6cc; }
        .medium { background-color: #ffffcc; }
        .low { background-color: #e6ffcc; }
        .info { background-color: #ccf2ff; }
        .timestamp { color: #999; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>Intellicrack Analysis Report</h1>
    <p class="timestamp">Generated: """ + str(datetime.datetime.now()) + """</p>
"""]

    # Binary information section
    if 'binary_info' in results:
        html_parts.append("""
    <div class="section">
        <h2>Binary Information</h2>
        <table class="info-table">
""")
        for key, value in results['binary_info'].items():
            html_parts.append(f"            <tr><td><strong>{key}</strong></td><td>{value}</td></tr>")
        html_parts.append("        </table>\n    </div>")

    # Vulnerabilities section
    if 'vulnerabilities' in results:
        html_parts.append("""
    <div class="section">
        <h2>Vulnerabilities</h2>
""")
        for vulnerability in results['vulnerabilities']:
            severity = vulnerability.get('severity', 'info').lower()
            html_parts.append(f'        <div class="vulnerability {severity}">')
            html_parts.append(f'            <strong>[{vulnerability.get("severity", "UNKNOWN")}]</strong> {vulnerability.get("name", "Unknown")}')
            if 'description' in vulnerability:
                html_parts.append(f'            <p>{vulnerability["description"]}</p>')
            html_parts.append('        </div>')
        html_parts.append("    </div>")

    # Add more sections as needed

    html_parts.append("""
</body>
</html>
""")

    return '\n'.join(html_parts)


def export_report(report_data: Dict[str, Any], format: str = 'pdf') -> Optional[str]:  # pylint: disable=redefined-builtin
    """
    Export report in various formats.

    Args:
        report_data: Report data to export
        format: Export format (pdf, docx, etc.)

    Returns:
        Optional[str]: Path to exported file
    """
    try:
        import json
        import tempfile

        # Generate timestamp for unique filename
        from datetime import datetime
        from pathlib import Path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Validate report_data structure
        if not isinstance(report_data, dict):
            logger.error("Invalid report data format - expected dictionary")
            return None

        if not report_data:
            logger.warning("Empty report data provided")
            return None

        # Create output directory
        output_dir = Path(tempfile.gettempdir()) / "intellicrack_reports"
        output_dir.mkdir(exist_ok=True)

        # Generate filename based on report content
        report_title = report_data.get('title', 'intellicrack_report')
        safe_title = "".join(c for c in report_title if c.isalnum() or c in (' ', '-', '_')).rstrip()
        filename = f"{safe_title}_{timestamp}"

        if format.lower() == 'pdf':
            # For now, export as HTML that can be converted to PDF
            output_file = output_dir / f"{filename}.html"
            html_content = _generate_html_report(report_data)

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

            logger.info("Report exported as HTML (ready for PDF conversion): %s", output_file)

        elif format.lower() == 'json':
            output_file = output_dir / f"{filename}.json"

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)

            logger.info("Report exported as JSON: %s", output_file)

        elif format.lower() == 'txt':
            output_file = output_dir / f"{filename}.txt"
            text_content = _generate_text_report(report_data)

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(text_content)

            logger.info("Report exported as text: %s", output_file)

        else:
            logger.warning("Export format '%s' not supported, exporting as JSON", format)
            output_file = output_dir / f"{filename}.json"

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)

        return str(output_file)

    except Exception as e:
        logger.error("Failed to export report: %s", e)
        return None


def _generate_html_report(report_data: Dict[str, Any]) -> str:
    """Generate HTML report from report data"""
    html_parts = [
        "<html><head><title>Intellicrack Analysis Report</title>",
        "<style>body{font-family:Arial,sans-serif;margin:40px;}",
        "h1{color:#2c3e50;}h2{color:#34495e;border-bottom:1px solid #bdc3c7;}",
        ".finding{margin:10px 0;padding:10px;border-left:4px solid #3498db;}",
        ".high{border-color:#e74c3c;}.medium{border-color:#f39c12;}.low{border-color:#27ae60;}",
        "</style></head><body>"
    ]

    # Title and metadata
    html_parts.append(f"<h1>{report_data.get('title', 'Analysis Report')}</h1>")

    if 'metadata' in report_data:
        metadata = report_data['metadata']
        html_parts.append("<h2>Report Metadata</h2>")
        html_parts.append(f"<p><strong>Target:</strong> {metadata.get('target', 'Unknown')}</p>")
        html_parts.append(f"<p><strong>Timestamp:</strong> {metadata.get('timestamp', 'Unknown')}</p>")
        html_parts.append(f"<p><strong>Analysis Type:</strong> {metadata.get('analysis_type', 'Unknown')}</p>")

    # Executive Summary
    if 'summary' in report_data:
        html_parts.append("<h2>Executive Summary</h2>")
        html_parts.append(f"<p>{report_data['summary']}</p>")

    # Findings
    if 'findings' in report_data:
        html_parts.append("<h2>Findings</h2>")
        for finding in report_data['findings']:
            severity = finding.get('severity', 'low').lower()
            html_parts.append(f"<div class='finding {severity}'>")
            html_parts.append(f"<h3>{finding.get('title', 'Finding')}</h3>")
            html_parts.append(f"<p><strong>Severity:</strong> {finding.get('severity', 'Unknown')}</p>")
            html_parts.append(f"<p>{finding.get('description', 'No description')}</p>")
            if 'recommendation' in finding:
                html_parts.append(f"<p><strong>Recommendation:</strong> {finding['recommendation']}</p>")
            html_parts.append("</div>")

    html_parts.append("</body></html>")
    return '\n'.join(html_parts)


def _generate_text_report(report_data: Dict[str, Any]) -> str:
    """Generate plain text report from report data"""
    text_parts = [
        "=" * 60,
        f"  {report_data.get('title', 'INTELLICRACK ANALYSIS REPORT')}",
        "=" * 60,
        ""
    ]

    # Metadata
    if 'metadata' in report_data:
        metadata = report_data['metadata']
        text_parts.extend([
            "REPORT METADATA",
            "-" * 40,
            f"Target: {metadata.get('target', 'Unknown')}",
            f"Timestamp: {metadata.get('timestamp', 'Unknown')}",
            f"Analysis Type: {metadata.get('analysis_type', 'Unknown')}",
            ""
        ])

    # Summary
    if 'summary' in report_data:
        text_parts.extend([
            "EXECUTIVE SUMMARY",
            "-" * 40,
            report_data['summary'],
            ""
        ])

    # Findings
    if 'findings' in report_data:
        text_parts.extend([
            "FINDINGS",
            "-" * 40
        ])

        for i, finding in enumerate(report_data['findings'], 1):
            text_parts.extend([
                f"{i}. {finding.get('title', 'Finding')}",
                f"   Severity: {finding.get('severity', 'Unknown')}",
                f"   Description: {finding.get('description', 'No description')}"
            ])

            if 'recommendation' in finding:
                text_parts.append(f"   Recommendation: {finding['recommendation']}")

            text_parts.append("")

    return '\n'.join(text_parts)


def format_findings(findings: List[Dict[str, Any]], include_remediation: bool = True) -> str:
    """
    Format analysis findings for _report inclusion.

    Args:
        findings: List of finding dictionaries
        include_remediation: Whether to include remediation suggestions

    Returns:
        str: Formatted findings text
    """
    formatted = []

    for i, finding in enumerate(findings, 1):
        formatted.append(f"{i}. {finding.get('title', 'Finding')}")

        if 'severity' in finding:
            formatted.append(f"   Severity: {finding['severity']}")

        if 'description' in finding:
            formatted.append(f"   Description: {finding['description']}")

        if include_remediation and 'remediation' in finding:
            formatted.append(f"   Remediation: {finding['remediation']}")

        formatted.append("")  # Empty line between findings

    return '\n'.join(formatted)


def create_summary_report(binary_path: str, key_findings: List[str]) -> Dict[str, Any]:
    """
    Create a summary report structure.

    Args:
        binary_path: Path to analyzed binary
        key_findings: List of key findings

    Returns:
        dict: Summary report structure
    """
    return {
        'binary': binary_path,
        'timestamp': datetime.datetime.now().isoformat(),
        'summary': {
            'total_findings': len(key_findings),
            'key_findings': key_findings
        }
    }


# Exported functions
__all__ = [
    'ReportGenerator',
    'generate_report',
    'generate_text_report',
    'generate_html_report',
    'export_report',
    'format_findings',
    'create_summary_report',
]
