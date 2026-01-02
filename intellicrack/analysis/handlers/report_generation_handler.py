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

import contextlib
from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, Any


PYQT6_AVAILABLE: bool = False

if TYPE_CHECKING:
    from PyQt6.QtCore import (
        QObject as _QObject,
        QRunnable as _QRunnable,
        QThreadPool as _QThreadPool,
        pyqtSignal as _pyqtSignal,
    )
    from PyQt6.QtWidgets import (
        QCheckBox as _QCheckBox,
        QComboBox as _QComboBox,
        QDialog as _QDialog,
        QFileDialog as _QFileDialog,
        QGroupBox as _QGroupBox,
        QHBoxLayout as _QHBoxLayout,
        QPushButton as _QPushButton,
        QVBoxLayout as _QVBoxLayout,
        QWidget as _QWidget,
    )

    QObject = _QObject
    QRunnable = _QRunnable
    QThreadPool = _QThreadPool
    pyqtSignal = _pyqtSignal
    QCheckBox = _QCheckBox
    QComboBox = _QComboBox
    QDialog = _QDialog
    QFileDialog = _QFileDialog
    QGroupBox = _QGroupBox
    QHBoxLayout = _QHBoxLayout
    QPushButton = _QPushButton
    QVBoxLayout = _QVBoxLayout
    QWidget = _QWidget
else:
    try:
        from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal
        from PyQt6.QtWidgets import QCheckBox, QComboBox, QDialog, QFileDialog, QGroupBox, QHBoxLayout, QPushButton, QVBoxLayout, QWidget

        PYQT6_AVAILABLE = True
    except ImportError:
        PYQT6_AVAILABLE = False

        QWidget = object

        class QObject:
            """Fallback QObject class when PyQt6 is not available."""

            def __init__(self, parent: object | None = None) -> None:
                """Initialize the QObject with an optional parent.

                Args:
                    parent: Optional parent object for ownership hierarchy.

                """

        class QRunnable:
            """Fallback QRunnable class when PyQt6 is not available."""

            def run(self) -> None:
                """Execute the runnable task."""

        class QThreadPool:
            """Fallback QThreadPool class when PyQt6 is not available."""

            @staticmethod
            def globalInstance() -> "QThreadPool | None":
                """Return the global thread pool instance.

                Returns:
                    Global thread pool instance or None if unavailable.

                """
                return None

            def start(self, runnable: "QRunnable") -> None:
                """Start a runnable task.

                Args:
                    runnable: QRunnable task to start.

                """

        class _SignalConnector:
            """Production-ready signal connector that manages callbacks when PyQt6 is unavailable."""

            def __init__(self) -> None:
                """Initialize the signal connector with an empty callbacks list."""
                self._callbacks: list[Callable[..., Any]] = []

            def connect(self, callback: Callable[..., Any]) -> None:
                """Connect a callback to this signal.

                Args:
                    callback: Callable to invoke when signal is emitted.

                """
                if callback not in self._callbacks:
                    self._callbacks.append(callback)

            def disconnect(self, callback: Callable[..., Any] | None = None) -> None:
                """Disconnect a callback or all callbacks from this signal.

                Args:
                    callback: Callable to disconnect, or None to clear all.

                """
                if callback is None:
                    self._callbacks.clear()
                elif callback in self._callbacks:
                    self._callbacks.remove(callback)

            def emit(self, *args: object, **kwargs: object) -> None:
                """Emit the signal to all connected callbacks.

                Args:
                    *args: Positional arguments to pass to callbacks.
                    **kwargs: Keyword arguments to pass to callbacks.

                """
                for callback in self._callbacks[:]:
                    with contextlib.suppress(Exception):
                        callback(*args, **kwargs)

            def __call__(self, *args: object, **kwargs: object) -> None:
                """Allow direct calling of the signal.

                Args:
                    *args: Positional arguments to pass to callbacks.
                    **kwargs: Keyword arguments to pass to callbacks.

                """
                self.emit(*args, **kwargs)

        def pyqtSignal(*args: object, **kwargs: object) -> Callable[..., _SignalConnector]:
            """Fallback pyqtSignal function when PyQt6 is not available.

            Args:
                *args: Signal argument types (ignored in fallback).
                **kwargs: Signal keyword arguments (ignored in fallback).

            Returns:
                A callable that creates signal connector instances.

            """

            def signal_property() -> _SignalConnector:
                return _SignalConnector()

            return signal_property

        class QCheckBox:
            """Fallback QCheckBox class when PyQt6 is not available."""

            def setChecked(self, checked: bool) -> None:
                """Set the checkbox checked state.

                Args:
                    checked: True to check the box, False to uncheck.

                """

            def isChecked(self) -> bool:
                """Return whether the checkbox is currently checked.

                Returns:
                    True if checked, False otherwise.

                """
                return False

            def setEnabled(self, enabled: bool) -> None:
                """Enable or disable the checkbox.

                Args:
                    enabled: True to enable, False to disable.

                """

        class QComboBox:
            """Fallback QComboBox class when PyQt6 is not available."""

            def __init__(self) -> None:
                """Initialize the combo box with empty items list."""
                self.currentTextChanged: _SignalConnector = _SignalConnector()
                self._items: list[str] = []
                self._current_index: int = 0

            def addItems(self, items: list[str]) -> None:
                """Add items to the combo box.

                Args:
                    items: List of item strings to add.

                """
                self._items.extend(items)

            def currentText(self) -> str:
                """Get the current text.

                Returns:
                    The text of the current item, or empty string if out of bounds.

                """
                if 0 <= self._current_index < len(self._items):
                    return self._items[self._current_index]
                return ""

            def setCurrentIndex(self, index: int) -> None:
                """Set the current index.

                Args:
                    index: The index to set as current.

                """
                if 0 <= index < len(self._items):
                    old_text = self.currentText()
                    self._current_index = index
                    new_text = self.currentText()
                    if old_text != new_text:
                        self.currentTextChanged.emit(new_text)

            def setCurrentText(self, text: str) -> None:
                """Set the current text.

                Args:
                    text: The text to set as current.

                """
                try:
                    index = self._items.index(text)
                    self.setCurrentIndex(index)
                except ValueError:
                    pass

        class QDialog:
            """Fallback QDialog class when PyQt6 is not available."""

            Accepted: int = 1
            Rejected: int = 0

            def __init__(self, parent: object | None = None) -> None:
                """Initialize the dialog with an optional parent.

                Args:
                    parent: Optional parent widget for the dialog.

                """

            def setWindowTitle(self, title: str) -> None:
                """Set the dialog window title.

                Args:
                    title: Title text to display in the window bar.

                """

            def setMinimumWidth(self, width: int) -> None:
                """Set the minimum width of the dialog.

                Args:
                    width: Minimum width in pixels.

                """

            def exec(self) -> int:
                """Execute the dialog modally.

                Returns:
                    Dialog result code (Accepted or Rejected).

                """
                return 0

            def accept(self) -> None:
                """Accept and close the dialog with Accepted result."""

            def reject(self) -> None:
                """Reject and close the dialog with Rejected result."""

            def setLayout(self, layout: object) -> None:
                """Set the layout manager for the dialog.

                Args:
                    layout: Layout object to manage widget positioning.

                """

        class QFileDialog:
            """Fallback QFileDialog class when PyQt6 is not available."""

            @staticmethod
            def getSaveFileName(
                parent: object | None = None,
                caption: str = "",
                directory: str = "",
                file_filter: str = "",
            ) -> tuple[str, str]:
                """Display a save file dialog and return the selected path.

                Args:
                    parent: Parent widget for the dialog.
                    caption: Dialog window title.
                    directory: Initial directory to display.
                    file_filter: File filter string (e.g., "Text Files (*.txt)").

                Returns:
                    Tuple containing selected file path and selected filter.

                """
                return ("", "")

        class QGroupBox:
            """Fallback QGroupBox class when PyQt6 is not available."""

            def __init__(self, title: str = "") -> None:
                """Initialize the group box with an optional title.

                Args:
                    title: Title text displayed on the group box border.

                """

            def setLayout(self, layout: object) -> None:
                """Set the layout manager for the group box.

                Args:
                    layout: Layout object to manage widget positioning.

                """

        class QHBoxLayout:
            """Fallback QHBoxLayout class when PyQt6 is not available."""

            def addWidget(self, widget: object) -> None:
                """Add a widget to the horizontal layout.

                Args:
                    widget: Widget to add to the layout.

                """

        class QPushButton:
            """Fallback QPushButton class when PyQt6 is not available."""

            def __init__(self, text: str = "") -> None:
                """Initialize the push button with optional text.

                Args:
                    text: Button label text.

                """
                self.clicked: _SignalConnector = _SignalConnector()
                self._text: str = text

            def setText(self, text: str) -> None:
                """Set the button text.

                Args:
                    text: The text to display on the button.

                """
                self._text = text

            def text(self) -> str:
                """Get the button text.

                Returns:
                    The current button text.

                """
                return self._text

        class QVBoxLayout:
            """Fallback QVBoxLayout class when PyQt6 is not available."""

            def addWidget(self, widget: object) -> None:
                """Add a widget to the vertical layout.

                Args:
                    widget: Widget to add to the layout.

                """

            def addLayout(self, layout: object) -> None:
                """Add a nested layout to the vertical layout.

                Args:
                    layout: Layout object to add.

                """


if TYPE_CHECKING:
    from ...protection.unified_protection_engine import UnifiedProtectionResult
else:
    try:
        from ...protection.unified_protection_engine import UnifiedProtectionResult
    except ImportError:

        class UnifiedProtectionResult:
            """Fallback UnifiedProtectionResult when module is not available."""

            def __init__(self) -> None:
                """Initialize the protection result with default values."""
                self.file_path: str = ""


try:
    from ...utils.logger import get_logger
except ImportError:
    import logging

    def get_logger(name: str | None = None) -> logging.Logger:
        """Create a logger instance with the given name.

        Args:
            name: The name for the logger instance.

        Returns:
            A logging.Logger instance.

        """
        return logging.getLogger(name)


logger = get_logger(__name__)


class ReportGeneratorWorkerSignals(QObject):
    """Signals for report generation worker.

    Attributes:
        finished: Signal emitted when report generation completes.
        error: Signal emitted with error tuple (exc_type, exc_value, traceback).
        result: Signal emitted with report generation result dict.
        progress: Signal emitted with progress message string.
    """

    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(dict)
    progress = pyqtSignal(str)


class ReportGeneratorWorker(QRunnable):
    """Worker thread for report generation.

    Attributes:
        result: The unified protection analysis result.
        format_type: Report output format (html, markdown, json).
        output_path: Filesystem path where report will be saved.
        options: Dictionary of report generation configuration options.
        signals: Signal emitter for work progress and completion.
    """

    def __init__(self, result: UnifiedProtectionResult, format_type: str, output_path: str, options: dict[str, Any]) -> None:
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
        """Generate the report.

        Generates a report in the specified format using the unified protection
        result and emits progress/result signals. Handles report generation
        with error recovery and finally emits completion signal.

        Raises:
            Exception: Any exception during report generation is caught,
                logged, and propagated via the error signal.
        """
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
            logger.exception("Exception in report_generation_handler: %s", e)
            import traceback

            self.signals.error.emit((type(e), e, traceback.format_exc()))
        finally:
            self.signals.finished.emit()


class ReportOptionsDialog(QDialog):
    """Dialog for selecting report generation options.

    Attributes:
        format_combo: Combo box for selecting report format (HTML, Markdown, JSON).
        include_summary: Checkbox for including executive summary in report.
        include_technical: Checkbox for including technical details section.
        include_strings: Checkbox for including string analysis results.
        include_entropy: Checkbox for including entropy visualization.
        include_bypass: Checkbox for including bypass strategy recommendations.
        include_recommendations: Checkbox for including security recommendations.
        include_raw_json: Checkbox for including raw ICP JSON data.
        generate_btn: Button to generate the report with selected options.
        cancel_btn: Button to cancel report generation dialog.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the report options dialog.

        Args:
            parent: Optional parent widget for Qt integration.

        """
        super().__init__(parent)
        self.setWindowTitle("Report Generation Options")
        self.setMinimumWidth(400)
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the user interface for the report options dialog.

        Creates and configures the dialog layout with format selection,
        content options, and action buttons. Sets up all checkboxes, combo
        boxes, and pushbuttons with appropriate connections.

        """
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
        """Handle format change.

        Adjusts available options based on selected report format. Entropy
        visualization is disabled for non-HTML formats since it requires
        HTML rendering capabilities.

        Args:
            format_text: The new format text selected.

        """
        # Disable entropy visualization for non-HTML formats
        if format_text != "HTML":
            self.include_entropy.setChecked(False)
            self.include_entropy.setEnabled(False)
        else:
            self.include_entropy.setEnabled(True)

    def get_options(self) -> dict[str, Any]:
        """Get selected options.

        Collects the current state of all dialog controls and returns them
        as a dictionary for use in report generation configuration.

        Returns:
            Dictionary mapping option names to their selected boolean values
                and the selected report format. Keys include: format, include_summary,
                include_technical, include_strings, include_entropy, include_bypass,
                include_recommendations, and include_raw_json.

        """
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

    Supports multiple output formats (HTML, Markdown, JSON) and customizable
    content options. Manages report generation in background worker threads
    using PyQt signals for progress and completion notification.

    Attributes:
        report_ready: Signal emitted with successful report generation dict.
        report_error: Signal emitted with error message string.
        report_progress: Signal emitted with progress message string.
        thread_pool: Global thread pool for background report generation.
        current_result: Most recent unified protection analysis result.
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
        self.thread_pool: QThreadPool | None = QThreadPool.globalInstance()
        self.current_result: UnifiedProtectionResult | None = None

    def on_analysis_complete(self, result: UnifiedProtectionResult) -> None:
        """Handle slot when protection analysis completes.

        Stores the protection analysis result for use in subsequent report
        generation operations. Logs the receipt of analysis data.

        Args:
            result: The unified protection analysis result.

        """
        self.current_result = result
        logger.info("Report generation handler received analysis for: %s", result.file_path)

    def generate_report(self, parent_widget: QWidget | None = None) -> None:
        """Show options dialog and generate report based on user selection.

        Displays a dialog for the user to select report format and content
        options. If the user confirms, prompts for output file location and
        initiates background report generation with signal notifications.

        Args:
            parent_widget: Optional parent widget for the dialog.

        """
        if not self.current_result:
            self.report_error.emit("No analysis result available")
            return

        # Show options dialog
        dialog = ReportOptionsDialog(parent_widget)
        dialog_result: int = dialog.exec()
        if dialog_result != 1:
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

        if self.thread_pool is not None:
            self.thread_pool.start(worker)

    def _on_report_ready(self, result: dict[str, Any]) -> None:
        """Handle report generation completion.

        Checks for successful report generation and emits the result signal.
        Logs the output path for reference by the user.

        Args:
            result: Dictionary containing report generation result data with
                keys 'success', 'path', and 'format'.

        """
        if result.get("success"):
            self.report_ready.emit(result)

            msg = f"Report saved to:\n{result.get('path', '')}"
            logger.info(msg)

    def _on_worker_error(self, error_tuple: tuple[type[BaseException], BaseException, str]) -> None:
        """Handle worker thread errors.

        Logs the error details including exception type, value, and formatted
        traceback. Emits the error signal with a user-friendly error message.

        Args:
            error_tuple: Tuple containing exception type, value, and traceback
                string from the worker thread.

        """
        _exc_type, exc_value, exc_traceback = error_tuple
        error_msg = f"Report generation failed: {exc_value}"
        logger.error("%s\n%s", error_msg, exc_traceback)
        self.report_error.emit(error_msg)
