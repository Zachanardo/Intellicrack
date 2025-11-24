"""Report Generation Handler.

Manages the generation of comprehensive analysis reports in multiple formats
(HTML, Markdown, PDF) based on protection analysis results.

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
# pylint: disable=cyclic-import

from datetime import datetime


try:
    from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal
    from PyQt6.QtWidgets import QCheckBox, QComboBox, QDialog, QFileDialog, QGroupBox, QHBoxLayout, QPushButton, QVBoxLayout

    PYQT6_AVAILABLE = True
except ImportError:
    # Fallback classes when PyQt6 is not available
    class QObject:
        """Fallback QObject class when PyQt6 is not available."""

    class QRunnable:
        """Fallback QRunnable class when PyQt6 is not available."""

        def run(self) -> None:
            """Execute the runnable task."""

    class QThreadPool:
        """Fallback QThreadPool class when PyQt6 is not available."""

        @staticmethod
        def globalInstance() -> None:
            """Return the global thread pool instance."""
            return

    def pyqtSignal(*args: object) -> None:
        """Fallback pyqtSignal function when PyQt6 is not available."""
        return

    # Fallback widget classes
    class QCheckBox:
        """Fallback QCheckBox class when PyQt6 is not available."""

    class QComboBox:
        """Fallback QComboBox class when PyQt6 is not available."""

    class QDialog:
        """Fallback QDialog class when PyQt6 is not available."""

    class QFileDialog:
        """Fallback QFileDialog class when PyQt6 is not available."""

    class QGroupBox:
        """Fallback QGroupBox class when PyQt6 is not available."""

    class QHBoxLayout:
        """Fallback QHBoxLayout class when PyQt6 is not available."""

    class QPushButton:
        """Fallback QPushButton class when PyQt6 is not available."""

    class QVBoxLayout:
        """Fallback QVBoxLayout class when PyQt6 is not available."""

    PYQT6_AVAILABLE = False

try:
    from ...protection.unified_protection_engine import UnifiedProtectionResult
except ImportError:
    UnifiedProtectionResult = None

try:
    from ...utils.logger import get_logger
except ImportError:
    import logging

    def get_logger(name: str) -> logging.Logger:
        """Create a logger instance with the given name.

        Args:
            name: The name for the logger instance

        Returns:
            A logging.Logger instance

        """
        return logging.getLogger(name)


logger = get_logger(__name__)


class ReportGeneratorWorkerSignals(QObject):
    """Signals for report generation worker."""

    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(dict)
    progress = pyqtSignal(str)


class ReportGeneratorWorker(QRunnable):
    """Worker thread for report generation."""

    def __init__(self, result: UnifiedProtectionResult, format_type: str, output_path: str, options: dict) -> None:
        """Initialize the report generator worker.

        Args:
            result: The unified protection result to generate a report for.
            format_type: The format type for the report (e.g., 'pdf', 'html').
            output_path: The path where the report should be saved.
            options: Additional options for report generation.

        """
        super().__init__()
        self.result = result
        self.format_type = format_type
        self.output_path = output_path
        self.options = options
        self.signals = ReportGeneratorWorkerSignals()

    def run(self) -> None:
        """Generate the report."""
        try:
            from ...protection.icp_report_generator import ICPReportGenerator, ReportOptions

            self.signals.progress.emit(f"Generating {self.format_type.upper()} report...")

            # Use the new ICP report generator
            generator = ICPReportGenerator()

            # Convert options to ReportOptions
            report_options = ReportOptions(
                include_raw_json=self.options.get("include_raw_json", False),
                include_bypass_methods=self.options.get("include_bypass", True),
                include_entropy_graph=self.options.get("include_entropy", True),
                include_recommendations=self.options.get("include_recommendations", True),
                include_technical_details=self.options.get("include_technical", True),
                output_format=self.format_type.lower(),
            )

            # Generate report (returns path)
            report_path = generator.generate_report(self.result, report_options)

            self.signals.result.emit(
                {
                    "success": True,
                    "path": report_path,
                    "format": self.format_type,
                },
            )

        except Exception as e:
            logger.error("Exception in report_generation_handler: %s", e)
            import traceback

            self.signals.error.emit((type(e), e, traceback.format_exc()))
        finally:
            self.signals.finished.emit()


class ReportOptionsDialog(QDialog):
    """Dialog for selecting report generation options."""

    def __init__(self, parent: QObject | None = None) -> None:
        """Initialize the report options dialog.

        Args:
            parent: Optional parent widget for Qt integration.

        """
        super().__init__(parent)
        self.setWindowTitle("Report Generation Options")
        self.setMinimumWidth(400)
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the user interface for the report options dialog."""
        layout = QVBoxLayout()

        # Format selection
        format_group = QGroupBox("Report Format")
        format_layout = QVBoxLayout()

        self.format_combo = QComboBox()
        self.format_combo.addItems(["HTML", "Markdown", "JSON"])
        self.format_combo.currentTextChanged.connect(self._on_format_changed)
        format_layout.addWidget(self.format_combo)

        format_group.setLayout(format_layout)
        layout.addWidget(format_group)

        # Content options
        content_group = QGroupBox("Include in Report")
        content_layout = QVBoxLayout()

        self.include_summary = QCheckBox("Executive Summary")
        self.include_summary.setChecked(True)
        content_layout.addWidget(self.include_summary)

        self.include_technical = QCheckBox("Technical Details")
        self.include_technical.setChecked(True)
        content_layout.addWidget(self.include_technical)

        self.include_strings = QCheckBox("String Analysis")
        self.include_strings.setChecked(True)
        content_layout.addWidget(self.include_strings)

        self.include_entropy = QCheckBox("Entropy Visualization")
        self.include_entropy.setChecked(True)
        content_layout.addWidget(self.include_entropy)

        self.include_bypass = QCheckBox("Bypass Strategies")
        self.include_bypass.setChecked(True)
        content_layout.addWidget(self.include_bypass)

        self.include_recommendations = QCheckBox("Recommendations")
        self.include_recommendations.setChecked(True)
        content_layout.addWidget(self.include_recommendations)

        self.include_raw_json = QCheckBox("Raw ICP JSON Data")
        self.include_raw_json.setChecked(False)
        content_layout.addWidget(self.include_raw_json)

        content_group.setLayout(content_layout)
        layout.addWidget(content_group)

        # Buttons
        button_layout = QHBoxLayout()

        self.generate_btn = QPushButton("Generate Report")
        self.generate_btn.clicked.connect(self.accept)
        button_layout.addWidget(self.generate_btn)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)

        layout.addLayout(button_layout)

        self.setLayout(layout)

    def _on_format_changed(self, format_text: str) -> None:
        """Handle format change."""
        # Disable entropy visualization for non-HTML formats
        if format_text != "HTML":
            self.include_entropy.setChecked(False)
            self.include_entropy.setEnabled(False)
        else:
            self.include_entropy.setEnabled(True)

    def get_options(self) -> dict:
        """Get selected options."""
        return {
            "format": self.format_combo.currentText().lower(),
            "include_summary": self.include_summary.isChecked(),
            "include_technical": self.include_technical.isChecked(),
            "include_strings": self.include_strings.isChecked(),
            "include_entropy": self.include_entropy.isChecked(),
            "include_bypass": self.include_bypass.isChecked(),
            "include_recommendations": self.include_recommendations.isChecked(),
            "include_raw_json": self.include_raw_json.isChecked(),
        }


class ReportGenerationHandler(QObject):
    """Handle comprehensive report generation based on protection analysis.

    Supports multiple output formats and customizable content.
    """

    # Signals
    report_ready = pyqtSignal(dict)
    report_error = pyqtSignal(str)
    report_progress = pyqtSignal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        """Initialize the report generation handler.

        Args:
            parent: Optional parent widget for Qt integration.

        """
        super().__init__(parent)
        self.thread_pool = QThreadPool.globalInstance()
        self.current_result: UnifiedProtectionResult | None = None

    def on_analysis_complete(self, result: UnifiedProtectionResult) -> None:
        """Handle slot when protection analysis completes."""
        self.current_result = result
        logger.info(f"Report generation handler received analysis for: {result.file_path}")

    def generate_report(self, parent_widget: QObject | None = None) -> None:
        """Show options dialog and generate report based on user selection."""
        if not self.current_result:
            self.report_error.emit("No analysis result available")
            return

        # Show options dialog
        dialog = ReportOptionsDialog(parent_widget)
        if dialog.exec() != QDialog.Accepted:
            return

        options = dialog.get_options()
        format_type = options["format"]

        # Get output file path
        default_name = f"protection_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        if format_type == "html":
            file_filter = "HTML Files (*.html);;All Files (*.*)"
            default_name += ".html"
        elif format_type == "markdown":
            file_filter = "Markdown Files (*.md);;All Files (*.*)"
            default_name += ".md"
        else:  # JSON
            file_filter = "JSON Files (*.json);;All Files (*.*)"
            default_name += ".json"

        output_path, _ = QFileDialog.getSaveFileName(
            parent_widget,
            "Save Report",
            default_name,
            file_filter,
        )

        if not output_path:
            return

        # Generate report in background
        worker = ReportGeneratorWorker(
            self.current_result,
            format_type,
            output_path,
            options,
        )

        worker.signals.result.connect(self._on_report_ready)
        worker.signals.error.connect(self._on_worker_error)
        worker.signals.progress.connect(self.report_progress.emit)

        self.thread_pool.start(worker)

    def _on_report_ready(self, result: dict) -> None:
        """Handle report generation completion."""
        if result["success"]:
            self.report_ready.emit(result)

            # Show success message if we have a parent
            msg = f"Report saved to:\n{result['path']}"
            logger.info(msg)

    def _on_worker_error(self, error_tuple: tuple[type[BaseException], BaseException, str]) -> None:
        """Handle worker thread errors."""
        _exc_type, exc_value, exc_traceback = error_tuple
        error_msg = f"Report generation failed: {exc_value}"
        logger.error(f"{error_msg}\n{exc_traceback}")
        self.report_error.emit(error_msg)
