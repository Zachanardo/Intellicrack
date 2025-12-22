"""Report generator for Intellicrack analysis results.

This module provides comprehensive report generation and viewing capabilities
for binary analysis results, protection assessments, and security findings.

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

import json
import logging
import os
import sys
import tempfile
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any, TYPE_CHECKING

from intellicrack.utils.logger import logger
from intellicrack.utils.subprocess_security import secure_run

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget
    from jinja2 import Environment, Template
else:
    QWidget = object
    Environment = object
    Template = object

try:
    from PyQt6.QtWidgets import QFileDialog, QMessageBox, QWidget

    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False
    logger.warning("PyQt6 not available, file dialogs will use fallback methods")

try:
    from jinja2 import Environment, FileSystemLoader, Template

    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False
    logger.warning("Jinja2 not available, HTML reports will use basic formatting")


class ReportGenerator:
    """Comprehensive report generator for Intellicrack analysis results."""

    def __init__(self) -> None:
        """Initialize the report generator."""
        self.logger = logging.getLogger(__name__)
        self.reports_dir = self._get_reports_directory()
        self.templates_dir = self._get_templates_directory()
        self.jinja_env: Any = None

        if JINJA_AVAILABLE and self.templates_dir.exists() and Environment is not None:
            self.jinja_env = Environment(loader=FileSystemLoader(str(self.templates_dir)), autoescape=True)

    def _get_reports_directory(self) -> Path:
        """Get or create the reports directory.

        Returns:
            Path to the reports directory

        """
        reports_dir: Path
        try:
            from intellicrack.utils.core.plugin_paths import get_reports_dir

            reports_dir = get_reports_dir()
        except ImportError:
            # Fallback to default location
            reports_dir = Path.home() / ".intellicrack" / "reports"

        reports_dir.mkdir(parents=True, exist_ok=True)
        return reports_dir

    def _get_templates_directory(self) -> Path:
        """Get the templates directory.

        Returns:
            Path to the templates directory

        """
        # Check multiple possible locations
        possible_paths = [
            Path(__file__).parent / "templates",
            Path(__file__).parent.parent.parent / "resources" / "templates",
            Path.cwd() / "templates",
        ]

        for path in possible_paths:
            if path.exists() and path.is_dir():
                return path

        # Create default templates directory
        default_path = Path(__file__).parent / "templates"
        default_path.mkdir(parents=True, exist_ok=True)
        return default_path

    def generate_html_report(self, data: dict[str, Any]) -> str:
        """Generate an HTML report from analysis data.

        Args:
            data: Analysis results data

        Returns:
            HTML content as string

        """
        if self.jinja_env:
            try:
                # Try to load template
                template = self.jinja_env.get_template("report_template.html")
                result = template.render(data=data, timestamp=datetime.now())
                return str(result)
            except Exception as e:
                # Fall back to basic HTML generation
                logger.debug(f"Template loading failed, using basic HTML generation: {e}")

        # Basic HTML generation without templates
        html_parts = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<title>Intellicrack Analysis Report</title>",
            "<style>",
            self._get_default_css(),
            "</style>",
            "</head>",
            "<body>",
            "<div class='container'>",
            "<h1>Intellicrack Analysis Report</h1>",
            f"<p class='timestamp'>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        ]

        # Add analysis summary
        if "summary" in data:
            html_parts.extend(("<section class='summary'>", "<h2>Summary</h2>"))
            html_parts.extend((f"<p>{data['summary']}</p>", "</section>"))
        # Add binary information
        if "binary_info" in data:
            html_parts.extend((
                "<section class='binary-info'>",
                "<h2>Binary Information</h2>",
                "<table>",
            ))
            html_parts.extend(
                f"<tr><td><strong>{key}:</strong></td><td>{value}</td></tr>"
                for key, value in data["binary_info"].items()
            )
            html_parts.extend(("</table>", "</section>"))
        # Add protection analysis
        if "protections" in data:
            html_parts.extend((
                "<section class='protections'>",
                "<h2>Protection Analysis</h2>",
                "<ul>",
            ))
            for protection in data["protections"]:
                status = "OK" if protection.get("bypassed") else "FAIL"
                html_parts.append(f"<li>{status} {protection.get('name', 'Unknown')}: {protection.get('description', '')}</li>")
            html_parts.extend(("</ul>", "</section>"))
        # Add vulnerabilities
        if "vulnerabilities" in data:
            html_parts.extend((
                "<section class='vulnerabilities'>",
                "<h2>Vulnerabilities Found</h2>",
                "<table>",
                "<tr><th>Severity</th><th>Type</th><th>Description</th><th>Location</th></tr>",
            ))
            for vuln in data["vulnerabilities"]:
                severity_class = vuln.get("severity", "unknown").lower()
                html_parts.append(f"<tr class='severity-{severity_class}'>")
                html_parts.append(f"<td>{vuln.get('severity', 'Unknown')}</td>")
                html_parts.append(f"<td>{vuln.get('type', 'Unknown')}</td>")
                html_parts.append(f"<td>{vuln.get('description', '')}</td>")
                html_parts.extend((f"<td>{vuln.get('location', 'N/A')}</td>", "</tr>"))
            html_parts.extend(("</table>", "</section>"))
        # Add exploitation results
        if "exploitation" in data:
            html_parts.extend(("<section class='exploitation'>", "<h2>Exploitation Results</h2>"))
            for exploit in data["exploitation"]:
                html_parts.append("<div class='exploit-result'>")
                html_parts.append(f"<h3>{exploit.get('technique', 'Unknown Technique')}</h3>")
                html_parts.append(f"<p><strong>Status:</strong> {exploit.get('status', 'Unknown')}</p>")
                if exploit.get("payload"):
                    html_parts.append(f"<p><strong>Payload:</strong> <code>{exploit['payload'][:100]}...</code></p>")
                if exploit.get("output"):
                    html_parts.append(f"<pre class='output'>{exploit['output']}</pre>")
                html_parts.append("</div>")
            html_parts.append("</section>")

        # Add recommendations
        if "recommendations" in data:
            html_parts.extend(
                (
                    "<section class='recommendations'>",
                    "<h2>Security Recommendations</h2>",
                    "<ol>",
                )
            )
            html_parts.extend(f"<li>{rec}</li>" for rec in data["recommendations"])
            html_parts.extend(("</ol>", "</section>"))
        html_parts.extend(["</div>", "</body>", "</html>"])

        return "\n".join(html_parts)

    def _get_default_css(self) -> str:
        """Get default CSS styles for HTML reports.

        Returns:
            CSS styles as string

        """
        return """
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f4f4f4;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
            border-bottom: 1px solid #ecf0f1;
            padding-bottom: 5px;
        }
        h3 {
            color: #7f8c8d;
        }
        .timestamp {
            color: #95a5a6;
            font-style: italic;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border: 1px solid #ddd;
        }
        th {
            background: #3498db;
            color: white;
        }
        tr:nth-child(even) {
            background: #f9f9f9;
        }
        .severity-critical { background: #ffcccc; }
        .severity-high { background: #ffe6cc; }
        .severity-medium { background: #ffffcc; }
        .severity-low { background: #e6ffcc; }
        code {
            background: #f1f1f1;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        pre {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }
        section {
            margin-bottom: 30px;
        }
        .exploit-result {
            background: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #3498db;
            border-radius: 5px;
        }
        """

    def generate_json_report(self, data: dict[str, Any]) -> str:
        """Generate a JSON report from analysis data.

        Args:
            data: Analysis results data

        Returns:
            JSON content as string

        """
        # Add metadata
        report_data = {
            "metadata": {
                "generator": "Intellicrack Report Generator",
                "version": "2.0.0",
                "timestamp": datetime.now().isoformat(),
            },
            "data": data,
        }

        return json.dumps(report_data, indent=2, default=str)

    def generate_text_report(self, data: dict[str, Any]) -> str:
        """Generate a text report from analysis data.

        Args:
            data: Analysis results data

        Returns:
            Text content as string

        """
        lines = [
            "=" * 80,
            "INTELLICRACK ANALYSIS REPORT",
            "=" * 80,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]
        # Add sections
        if "summary" in data:
            lines.extend(("SUMMARY", "-" * 40))
            lines.extend((data["summary"], ""))
        if "binary_info" in data:
            lines.extend(("BINARY INFORMATION", "-" * 40))
            lines.extend(f"  {key}: {value}" for key, value in data["binary_info"].items())
            lines.append("")

        if "protections" in data:
            lines.extend(("PROTECTION ANALYSIS", "-" * 40))
            for protection in data["protections"]:
                status = "[BYPASSED]" if protection.get("bypassed") else "[ACTIVE]"
                lines.append(f"  {status} {protection.get('name', 'Unknown')}")
                if protection.get("description"):
                    lines.append(f"    {protection['description']}")
            lines.append("")

        if "vulnerabilities" in data:
            lines.extend(("VULNERABILITIES FOUND", "-" * 40))
            for vuln in data["vulnerabilities"]:
                lines.append(f"  [{vuln.get('severity', 'UNKNOWN')}] {vuln.get('type', 'Unknown')}")
                lines.append(f"    {vuln.get('description', 'No description')}")
                lines.append(f"    Location: {vuln.get('location', 'N/A')}")
            lines.append("")

        if "exploitation" in data:
            lines.extend(("EXPLOITATION RESULTS", "-" * 40))
            for exploit in data["exploitation"]:
                lines.append(f"  Technique: {exploit.get('technique', 'Unknown')}")
                lines.append(f"  Status: {exploit.get('status', 'Unknown')}")
                if exploit.get("output"):
                    lines.append(f"  Output: {exploit['output'][:200]}")
            lines.append("")

        if "recommendations" in data:
            lines.extend(("SECURITY RECOMMENDATIONS", "-" * 40))
            lines.extend(
                f"  {i}. {rec}" for i, rec in enumerate(data["recommendations"], 1)
            )
            lines.append("")

        lines.extend(("=" * 80, "END OF REPORT", "=" * 80))
        return "\n".join(lines)

    def save_report(self, content: str, format: str, filename: str | None = None) -> str:
        """Save report content to file.

        Args:
            content: Report content
            format: Report format (html, json, txt)
            filename: Optional custom filename

        Returns:
            Path to saved report file

        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"intellicrack_report_{timestamp}.{format}"

        filepath = self.reports_dir / filename

        # Write content to file
        mode = "w" if format in {"html", "json", "txt"} else "wb"
        encoding = "utf-8" if format in {"html", "json", "txt"} else None

        with open(filepath, mode, encoding=encoding) as f:
            f.write(content)

        self.logger.info("Report saved to: %s", filepath)
        return str(filepath)

    def create_temporary_report(self, content: str, format: str) -> str:
        """Create a temporary report file for preview or processing.

        Args:
            content: Report content
            format: Report format extension

        Returns:
            Path to temporary report file

        """
        # Use tempfile to create secure temporary file
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=f".{format}",
            prefix="intellicrack_temp_",
            delete=False,
            encoding="utf-8" if format in {"html", "json", "txt"} else None,
        ) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name

        self.logger.debug("Temporary report created: %s", temp_path)
        return temp_path

    def get_supported_formats(self) -> list[str]:
        """Get list of supported report formats.

        Returns:
            List of supported format extensions

        """
        basic_formats: list[str] = ["html", "json", "txt"]

        # Add PDF if available
        try:
            from .pdf_generator import PDFReportGenerator

            return [*basic_formats, "pdf"]
        except ImportError:
            return basic_formats

    def get_format_mime_types(self) -> dict[str, str | list[str]]:
        """Get MIME types for supported formats.

        Returns:
            Dictionary mapping formats to MIME types

        """
        return {
            "html": "text/html",
            "json": "application/json",
            "txt": "text/plain",
            "pdf": "application/pdf",
        }

    def create_template_from_string(self, template_string: str) -> Any:
        """Create a Jinja2 template from string content.

        Args:
            template_string: Template content as string

        Returns:
            Jinja2 Template object or None if creation fails

        """
        if JINJA_AVAILABLE and Template is not None:
            try:
                return Template(template_string)
            except Exception as e:
                self.logger.warning("Failed to create template from string: %s", e)
        return None


def generate_report(app_instance: object, format: str = "html", save: bool = True, filename: str | None = None) -> str | None:
    """Generate an analysis report in the specified format.

    Args:
        app_instance: The Intellicrack application instance
        format: Report format (html, json, txt, pdf)
        save: Whether to save the report to file
        filename: Optional custom filename

    Returns:
        Path to saved report or report content if not saved

    """
    try:
        generator = ReportGenerator()

        # Collect analysis data from app instance
        data: dict[str, Any] = {}

        # Get analysis results
        if hasattr(app_instance, "analyze_results"):
            results = app_instance.analyze_results
            if isinstance(results, list):
                summary_lines: list[Any] = results[:5] if results else []
                data["summary"] = "\n".join(str(line) for line in summary_lines) if summary_lines else "No analysis results available"
                data["full_results"] = results
            elif isinstance(results, dict):
                data |= results

        # Get binary information
        if hasattr(app_instance, "binary_path") and app_instance.binary_path:
            data["binary_info"] = {
                "Path": app_instance.binary_path,
                "Size": os.path.getsize(app_instance.binary_path) if os.path.exists(app_instance.binary_path) else "Unknown",
            }

        # Get protection analysis
        if hasattr(app_instance, "protections_detected"):
            protections = getattr(app_instance, "protections_detected", None)
            if protections is not None:
                data["protections"] = protections

        # Get vulnerabilities
        if hasattr(app_instance, "vulnerabilities"):
            vulnerabilities = getattr(app_instance, "vulnerabilities", None)
            if vulnerabilities is not None:
                data["vulnerabilities"] = vulnerabilities

        # Get exploitation results
        if hasattr(app_instance, "exploitation_results"):
            exploitation = getattr(app_instance, "exploitation_results", None)
            if exploitation is not None:
                data["exploitation"] = exploitation

        # Get recommendations
        if hasattr(app_instance, "recommendations"):
            recommendations = getattr(app_instance, "recommendations", None)
            if recommendations is not None:
                data["recommendations"] = recommendations
        if "recommendations" not in data:
            # Generate default recommendations
            data["recommendations"] = [
                "Implement stronger anti-debugging mechanisms",
                "Use code obfuscation and virtualization",
                "Implement integrity checks throughout the application",
                "Use hardware-based protection where possible",
                "Regularly update protection mechanisms",
            ]

        # Generate report content based on format
        content: str
        if format == "html":
            content = generator.generate_html_report(data)
        elif format == "json":
            content = generator.generate_json_report(data)
        elif format == "pdf":
            # Generate HTML first, then convert to PDF if possible
            html_content = generator.generate_html_report(data)
            try:
                from intellicrack.core.reporting.pdf_generator import PDFReportGenerator

                pdf_gen = PDFReportGenerator()
                pdf_result = pdf_gen.generate_from_html(html_content)
                if pdf_result is not None:
                    return str(pdf_result)
                logger.warning("PDF generation returned None, saving as HTML instead")
                content = html_content
            except ImportError:
                logger.warning("PDF generation not available, saving as HTML instead")
                content = html_content
        elif format == "txt":
            content = generator.generate_text_report(data)
        else:
            logger.error(f"Unsupported report format: {format}")
            return None

        # Save or return content
        if save:
            filepath = generator.save_report(content, format, filename)

            # Update UI if available
            if hasattr(app_instance, "update_output"):
                app_instance.update_output.emit(f"Report saved to: {filepath}")

            return filepath
        return content

    except Exception as e:
        logger.error(f"Error generating report: {e}")
        if hasattr(app_instance, "update_output"):
            app_instance.update_output.emit(f"Error generating report: {e}")
        return None


def view_report(app_instance: object, filepath: str | None = None) -> bool:
    """View a generated report in the appropriate viewer.

    Args:
        app_instance: The Intellicrack application instance
        filepath: Path to report file, or None to browse

    Returns:
        True if report was opened successfully

    """
    try:
        # Determine parent widget for dialogs
        parent_widget: Any = None
        if PYQT_AVAILABLE and QWidget is not None and isinstance(app_instance, QWidget):
            parent_widget = app_instance

        # If no filepath provided, show file dialog
        if filepath is None:
            if PYQT_AVAILABLE and hasattr(app_instance, "window") and QWidget is not None:
                filepath, _ = QFileDialog.getOpenFileName(
                    parent_widget,
                    "Select Report to View",
                    str(Path.home() / ".intellicrack" / "reports"),
                    "Report Files (*.html *.json *.txt *.pdf);;All Files (*.*)",
                )

                if not filepath:
                    return False
            # Use last generated report if available
            elif hasattr(app_instance, "last_report_path"):
                filepath = app_instance.last_report_path
            else:
                logger.error("No report file specified")
                return False

        # Check if file exists
        if not os.path.exists(filepath):
            logger.error(f"Report file not found: {filepath}")
            if PYQT_AVAILABLE and hasattr(app_instance, "window") and QWidget is not None:
                QMessageBox.critical(parent_widget, "Error", f"Report file not found: {filepath}")
            return False

        # Determine file type and open appropriately
        file_ext = Path(filepath).suffix.lower()

        if file_ext in [".html", ".htm"]:
            # Open in web browser
            webbrowser.open(f"file://{os.path.abspath(filepath)}")
        elif file_ext == ".pdf":
            # Open with system PDF viewer
            if os.name == "nt":  # Windows
                secure_run(["cmd", "/c", "start", "", filepath], shell=False)
            elif os.name == "posix":  # macOS and Linux
                secure_run(["open" if sys.platform == "darwin" else "xdg-open", filepath], shell=False)
        elif file_ext in [".json", ".txt"]:
            # Open with system text editor
            if os.name == "nt":  # Windows
                secure_run(["cmd", "/c", "start", "", filepath], shell=False)
            else:
                secure_run(["open" if sys.platform == "darwin" else "xdg-open", filepath], shell=False)
        else:
            logger.warning(f"Unknown report format: {file_ext}")
            # Try to open with system default
            if os.name == "nt":
                secure_run(["cmd", "/c", "start", "", filepath], shell=False)
            else:
                secure_run(["open" if sys.platform == "darwin" else "xdg-open", filepath], shell=False)

        logger.info(f"Opened report: {filepath}")

        # Update UI if available
        if hasattr(app_instance, "update_output"):
            app_instance.update_output.emit(f"Viewing report: {filepath}")

        return True

    except Exception as e:
        logger.error(f"Error viewing report: {e}")
        if PYQT_AVAILABLE and hasattr(app_instance, "window") and QWidget is not None:
            error_parent_widget: Any = None
            if isinstance(app_instance, QWidget):
                error_parent_widget = app_instance
            QMessageBox.critical(error_parent_widget, "Error", f"Failed to open report: {e}")
        return False


__all__ = ["ReportGenerator", "generate_report", "view_report"]
