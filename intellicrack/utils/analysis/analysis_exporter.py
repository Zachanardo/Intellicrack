"""Analysis exporter utilities for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.

Analysis Exporter Utilities

Shared export functionality for analysis results to eliminate code duplication
between binary_differ.py and vulnerability_analyzer.py.
"""

import csv
import json
import logging
from typing import Any


logger = logging.getLogger(__name__)


class AnalysisExporter:
    """Shared exporter for analysis results across different analysis engines.

    Provides consistent export formats and error handling.
    """

    @staticmethod
    def export_analysis(
        result: dict[str, Any],
        output_file: str,
        format: str = "json",
        analysis_type: str = "generic",
    ) -> bool:
        """Export analysis results to file in specified format.

        Args:
            result: Analysis results dictionary
            output_file: Output file path
            format: Export format ('json', 'html', 'csv', 'text')
            analysis_type: Type of analysis for specialized formatting

        Returns:
            True if export successful, False otherwise

        """
        try:
            if format == "json":
                return AnalysisExporter._export_json(result, output_file)
            if format == "html":
                return AnalysisExporter._export_html(result, output_file, analysis_type)
            if format == "csv":
                return AnalysisExporter._export_csv(result, output_file, analysis_type)
            if format == "text":
                return AnalysisExporter._export_text(result, output_file)
            logger.exception("Unsupported export format: %s", format)
            return False

        except Exception as e:
            logger.exception("Analysis export failed: %s", e, exc_info=True)
            return False

    @staticmethod
    def _export_json(result: dict[str, Any], output_file: str) -> bool:
        """Export results as JSON."""
        try:
            with open(output_file, "w") as f:
                json.dump(result, f, indent=2, default=str)
            return True
        except Exception as e:
            logger.exception("JSON export failed: %s", e, exc_info=True)
            return False

    @staticmethod
    def _export_html(result: dict[str, Any], output_file: str, analysis_type: str) -> bool:
        """Export results as HTML."""
        try:
            if analysis_type == "vulnerability":
                html_content = AnalysisExporter._generate_vulnerability_html(result)
            elif analysis_type == "binary_diff":
                html_content = AnalysisExporter._generate_diff_html(result)
            else:
                html_content = AnalysisExporter._generate_generic_html(result)

            with open(output_file, "w") as f:
                f.write(html_content)
            return True
        except Exception as e:
            logger.exception("HTML export failed: %s", e, exc_info=True)
            return False

    @staticmethod
    def _export_csv(result: dict[str, Any], output_file: str, analysis_type: str) -> bool:
        """Export results as CSV."""
        try:
            with open(output_file, "w", newline="") as f:
                writer = csv.writer(f)

                if analysis_type == "vulnerability":
                    AnalysisExporter._write_vulnerability_csv(writer, result)
                elif analysis_type == "binary_diff":
                    AnalysisExporter._write_diff_csv(writer, result)
                else:
                    AnalysisExporter._write_generic_csv(writer, result)

            return True
        except Exception as e:
            logger.exception("CSV export failed: %s", e, exc_info=True)
            return False

    @staticmethod
    def _export_text(result: dict[str, Any], output_file: str) -> bool:
        """Export results as plain text."""
        try:
            with open(output_file, "w") as f:
                f.write(str(result))
            return True
        except Exception as e:
            logger.exception("Text export failed: %s", e, exc_info=True)
            return False

    @staticmethod
    def _write_vulnerability_csv(writer: object, result: dict[str, Any]) -> None:
        """Write vulnerability-specific CSV format."""
        writer.writerow(["Type", "File", "Line", "Severity", "Confidence", "Description"])

        for vuln in result.get("vulnerabilities", []):
            writer.writerow(
                [
                    vuln.get("type", ""),
                    vuln.get("file", ""),
                    vuln.get("line", ""),
                    vuln.get("severity", ""),
                    vuln.get("confidence", ""),
                    vuln.get("description", ""),
                ],
            )

    @staticmethod
    def _write_diff_csv(writer: object, result: dict[str, Any]) -> None:
        """Write binary diff-specific CSV format."""
        writer.writerow(["Type", "Old_Value", "New_Value", "Severity", "Description"])

        for diff in result.get("differences", []):
            writer.writerow(
                [
                    diff.get("type", ""),
                    diff.get("old_value", ""),
                    diff.get("new_value", ""),
                    diff.get("severity", ""),
                    diff.get("description", ""),
                ],
            )

    @staticmethod
    def _write_generic_csv(writer: object, result: dict[str, Any]) -> None:
        """Write generic CSV format."""
        if not result:
            return

        # Write headers based on first item structure
        if isinstance(result, dict):
            first_key = next(iter(result.keys()))
            first_value = result[first_key]

            if isinstance(first_value, dict):
                headers = list(first_value.keys())
                writer.writerow(headers)

                for key, value in result.items():
                    if isinstance(value, dict):
                        row = [value.get(h, "") for h in headers]
                        writer.writerow([key, *row])

    @staticmethod
    def _generate_vulnerability_html(result: dict[str, Any]) -> str:
        """Generate HTML report for vulnerability analysis."""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f5f5f5; padding: 15px; border-radius: 5px; }
        .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 10px; border-radius: 5px; }
        .high { border-left: 5px solid #dc3545; }
        .medium { border-left: 5px solid #ffc107; }
        .low { border-left: 5px solid #28a745; }
        .stats { background-color: #e9ecef; padding: 10px; margin: 10px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Vulnerability Analysis Report</h1>
        <p>Generated: {timestamp}</p>
    </div>

    <div class="stats">
        <h2>Summary Statistics</h2>
        <ul>
            <li>Total Vulnerabilities: {total_vulns}</li>
            <li>High Severity: {high_count}</li>
            <li>Medium Severity: {medium_count}</li>
            <li>Low Severity: {low_count}</li>
        </ul>
    </div>

    <h2>Vulnerabilities</h2>
    {vulnerability_list}
</body>
</html>
        """.strip()

        # Extract data for template
        import time

        vulns = result.get("vulnerabilities", [])
        stats = result.get("statistics", {})

        logger.debug("Exporting HTML report with %d vulnerabilities and stats: %s", len(vulns), stats)

        # Count by severity
        high_count = len([v for v in vulns if v.get("severity") == "high"])
        medium_count = len([v for v in vulns if v.get("severity") == "medium"])
        low_count = len([v for v in vulns if v.get("severity") == "low"])

        # Generate vulnerability list
        vuln_html = ""
        for vuln in vulns:
            severity = vuln.get("severity", "low")
            vuln_html += f"""
            <div class="vulnerability {severity}">
                <h3>{vuln.get("type", "Unknown")}</h3>
                <p><strong>File:</strong> {vuln.get("file", "N/A")}</p>
                <p><strong>Line:</strong> {vuln.get("line", "N/A")}</p>
                <p><strong>Severity:</strong> {severity.upper()}</p>
                <p><strong>Confidence:</strong> {vuln.get("confidence", "N/A")}</p>
                <p><strong>Description:</strong> {vuln.get("description", "No description available")}</p>
            </div>
            """

        return html.format(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            total_vulns=len(vulns),
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            vulnerability_list=vuln_html,
        )

    @staticmethod
    def _generate_diff_html(result: dict[str, Any]) -> str:
        """Generate HTML report for binary diff analysis."""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>Binary Diff Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f5f5f5; padding: 15px; border-radius: 5px; }
        .difference { border: 1px solid #ddd; margin: 10px 0; padding: 10px; border-radius: 5px; }
        .added { border-left: 5px solid #28a745; }
        .removed { border-left: 5px solid #dc3545; }
        .modified { border-left: 5px solid #ffc107; }
        .stats { background-color: #e9ecef; padding: 10px; margin: 10px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Binary Diff Analysis Report</h1>
        <p>Generated: {timestamp}</p>
    </div>

    <div class="stats">
        <h2>Summary Statistics</h2>
        <ul>
            <li>Total Differences: {total_diffs}</li>
            <li>Functions Added: {added_count}</li>
            <li>Functions Removed: {removed_count}</li>
            <li>Functions Modified: {modified_count}</li>
        </ul>
    </div>

    <h2>Differences</h2>
    {difference_list}
</body>
</html>
        """.strip()

        # Extract data for template
        import time

        diffs = result.get("differences", [])

        # Count by type
        added_count = len([d for d in diffs if d.get("type") == "function_added"])
        removed_count = len([d for d in diffs if d.get("type") == "function_removed"])
        modified_count = len([d for d in diffs if d.get("type") == "function_modified"])

        # Generate difference list
        diff_html = ""
        for diff in diffs:
            diff_type = diff.get("type", "unknown")
            css_class = "added" if "added" in diff_type else "removed" if "removed" in diff_type else "modified"

            diff_html += f"""
            <div class="difference {css_class}">
                <h3>{diff.get("type", "Unknown").replace("_", " ").title()}</h3>
                <p><strong>Description:</strong> {diff.get("description", "No description available")}</p>
                <p><strong>Old Value:</strong> {diff.get("old_value", "N/A")}</p>
                <p><strong>New Value:</strong> {diff.get("new_value", "N/A")}</p>
            </div>
            """

        return html.format(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            total_diffs=len(diffs),
            added_count=added_count,
            removed_count=removed_count,
            modified_count=modified_count,
            difference_list=diff_html,
        )

    @staticmethod
    def _generate_generic_html(result: dict[str, Any]) -> str:
        """Generate generic HTML report."""
        import time

        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; }}
        pre {{ background-color: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Analysis Report</h1>
        <p>Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>

    <h2>Results</h2>
    <pre>{json.dumps(result, indent=2, default=str)}</pre>
</body>
</html>
        """


# Export main class
__all__ = ["AnalysisExporter"]
