"""Report common utilities for Intellicrack.

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

Common reporting utilities for generating analysis reports.

Common report generation utilities to avoid code duplication.
"""

from collections.abc import Callable
from typing import Any

from intellicrack.utils.logger import logger


def generate_analysis_report(
    app: object,
    report_type: str,
    results_data: object,
    generator_func: Callable[[str, object], str] | None = None,
) -> str | None:
    """Generate analysis reports.

    Args:
        app: Application instance for UI dialogs
        report_type: Type of report (e.g., "ROP chain generation", "taint analysis")
        results_data: Data to include in the report
        generator_func: Optional function to generate the report content

    Returns:
        str or None: Path to generated report file, or None if cancelled

    """
    try:
        from ..ui.ui_common import ask_yes_no_question, show_file_dialog
    except ImportError as e:
        logger.error("Import error in report_common: %s", e)
        # Fallback if UI common not available
        return None

    generate_report = ask_yes_no_question(
        app,
        "Generate Report",
        f"Do you want to generate a report of the {report_type} results?",
    )

    if not generate_report:
        return None

    filename = show_file_dialog(app, "Save Report")

    if not filename:
        return None

    if not filename.endswith(".html"):
        filename += ".html"

    return generator_func(filename, results_data) if generator_func else _generate_default_report(filename, report_type, results_data)


def _generate_default_report(filename: str, report_type: str, results_data: object) -> str | None:
    """Generate a default HTML report.

    Args:
        filename: Output filename
        report_type: Type of analysis
        results_data: Results to include

    Returns:
        str: Path to generated report

    """
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{report_type.title()} Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            .results {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
            pre {{ background: #eee; padding: 10px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <h1>{report_type.title()} Report</h1>
        <div class="results">
            <h2>Results</h2>
            <pre>{results_data!s}</pre>
        </div>
    </body>
    </html>
    """

    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        return filename
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in report_common: %s", e)
        print(f"Error generating report: {e}")
        return None


def ensure_html_extension(filename: str) -> str:
    """Ensure filename has .html extension.

    Args:
        filename: Input filename

    Returns:
        Filename with .html extension

    """
    return filename if filename.endswith(".html") else f"{filename}.html"


def handle_pyqt6_report_generation(app: object, report_type: str, generator: object) -> str | None:
    """Handle PyQt6 report generation workflow.

    Args:
        app: Application instance for UI dialogs
        report_type: Type of report for dialog message
        generator: Object with generate_report method

    Returns:
        Path to generated report file, or None if cancelled

    """
    try:
        # Check if PyQt6 is available
        import importlib.util

        PYQT6_AVAILABLE = importlib.util.find_spec("PyQt6") is not None
    except ImportError as e:
        logger.error("Import error in report_common: %s", e)
        PYQT6_AVAILABLE = False

    if not PYQT6_AVAILABLE:
        return None

    from ..ui.ui_helpers import ask_yes_no_question, show_file_dialog

    if generate_report := ask_yes_no_question(
        app,
        "Generate Report",
        f"Do you want to generate a report of the {report_type} results?",
    ):
        logger.info(f"User requested report generation: {generate_report}")
        if filename := show_file_dialog(app, "Save Report"):
            if not filename.endswith(".html"):
                filename += ".html"

            return generator.generate_report(filename)
    return None
