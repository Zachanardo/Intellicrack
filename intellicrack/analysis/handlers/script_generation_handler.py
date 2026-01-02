"""Script Generation Handler.

Manages the generation of bypass scripts (Frida/Ghidra) based on detected
protections using the ProtectionAwareScriptGenerator. Provides threaded
execution of script generation with UI dialogs for script display and
export.

This module implements the ScriptGenerationHandler class which coordinates
with protection analysis results to generate specialized bypass scripts
targeting identified licensing protection mechanisms. Worker threads ensure
long-running script generation operations don't block the UI.

Key Classes:
    ScriptGenerationWorkerSignals: Qt signals for worker thread communication.
    ScriptGenerationWorker: QRunnable worker thread for script generation.
    ScriptDisplayDialog: Dialog for viewing and saving generated scripts.
    ScriptGenerationHandler: Main handler coordinating script generation.

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

from __future__ import annotations

from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from logging import Logger

# Module-level type declarations for cross-branch assignment compatibility
QObject: type[Any]
QRunnable: type[Any]
QThreadPool: type[Any]
QTimer: type[Any]
pyqtSignal: type[Any]
QFont: type[Any]
QTextDocument: type[Any]
QDialog: type[Any]
QFileDialog: type[Any]
QHBoxLayout: type[Any]
QLabel: type[Any]
QMessageBox: type[Any]
QPushButton: type[Any]
QTextEdit: type[Any]
QVBoxLayout: type[Any]
QWidget: type[Any]
ProtectionAwareScriptGenerator: type[Any] | None
UnifiedProtectionResult: type[Any] | None

try:
    from PyQt6.QtCore import QObject, QRunnable, QThreadPool, QTimer, pyqtSignal
    from PyQt6.QtGui import QFont, QTextDocument
    from PyQt6.QtWidgets import QDialog, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPushButton, QTextEdit, QVBoxLayout, QWidget

    PYQT6_AVAILABLE = True
except ImportError:

    class QObject:
        """Fallback QObject class when PyQt6 is not available."""

        pass

    class QRunnable:
        """Fallback QRunnable class when PyQt6 is not available."""

        def run(self) -> None:
            """Execute the runnable task."""

    class QThreadPool:
        """Fallback QThreadPool class when PyQt6 is not available."""

        @staticmethod
        def globalInstance() -> QThreadPool | None:
            """Return the global thread pool instance.

            Returns:
                A thread pool instance or None.
            """
            return QThreadPool()

        def start(self, runnable: QRunnable) -> None:
            """Start a runnable.

            Args:
                runnable: The runnable to execute.
            """

    class QTimer:
        """Fallback QTimer class when PyQt6 is not available."""

        @staticmethod
        def singleShot(msec: int, func: Any) -> None:
            """Single shot timer.

            Args:
                msec: Time in milliseconds until the timer fires.
                func: The function to call when the timer fires.
            """

    class pyqtSignal:
        """Fallback pyqtSignal class when PyQt6 is not available."""

        def __init__(self, *args: Any) -> None:
            """Initialize signal.

            Args:
                *args: Signal argument types (unused in fallback).
            """
            self._callbacks: list[Any] = []

        def emit(self, *args: Any) -> None:
            """Emit signal.

            Args:
                *args: Arguments to pass to connected callbacks.
            """
            for callback in self._callbacks:
                callback(*args)

        def connect(self, callback: Any) -> None:
            """Connect signal.

            Args:
                callback: The callback function to connect to this signal.
            """
            self._callbacks.append(callback)

    class QFont:
        """Fallback QFont class when PyQt6 is not available."""

        class Weight:
            """Font weight enumeration.

            Attributes:
                Bold: The bold font weight value.
            """

            Bold: int = 75

    class QTextDocument:
        """Fallback QTextDocument class when PyQt6 is not available."""

        class FindFlag:
            """Find flags.

            Attributes:
                FindWholeWords: Flag value for finding whole words only.
            """

            FindWholeWords: int = 2

    class QDialog:
        """Fallback QDialog class when PyQt6 is not available."""

        def __init__(self, parent: Any = None) -> None:
            """Initialize dialog.

            Args:
                parent: Optional parent widget.
            """

        def setWindowTitle(self, title: str) -> None:
            """Set window title.

            Args:
                title: The title to set for the dialog window.
            """

        def setMinimumSize(self, width: int, height: int) -> None:
            """Set minimum size.

            Args:
                width: Minimum width in pixels.
                height: Minimum height in pixels.
            """

        def setLayout(self, layout: Any) -> None:
            """Set layout.

            Args:
                layout: The layout to set for the dialog.
            """

        def exec(self) -> int:
            """Execute dialog.

            Returns:
                The dialog result code.
            """
            return 0

        def accept(self) -> None:
            """Accept dialog."""

    class QFileDialog:
        """Fallback QFileDialog class when PyQt6 is not available."""

        @staticmethod
        def getSaveFileName(
            parent: Any = None,
            caption: str = "",
            directory: str = "",
            file_filter: str = "",
        ) -> tuple[str, str]:
            """Get save file name.

            Args:
                parent: Parent widget for the dialog.
                caption: Dialog caption/title.
                directory: Initial directory to browse.
                file_filter: File type filter string.

            Returns:
                Tuple of (filename, selected_filter) or empty strings if cancelled.
            """
            return ("", "")

    class QHBoxLayout:
        """Fallback QHBoxLayout class when PyQt6 is not available."""

        def addWidget(self, widget: Any) -> None:
            """Add widget.

            Args:
                widget: The widget to add to the layout.
            """

        def addStretch(self) -> None:
            """Add stretch."""

    class QLabel:
        """Fallback QLabel class when PyQt6 is not available."""

        def __init__(self, text: str = "") -> None:
            """Initialize label.

            Args:
                text: The initial text to display in the label.
            """

        def setStyleSheet(self, style: str) -> None:
            """Set style sheet.

            Args:
                style: CSS-style sheet string to apply to the label.
            """

        def setWordWrap(self, wrap: bool) -> None:
            """Set word wrap.

            Args:
                wrap: Whether to enable word wrapping.
            """

    class QMessageBox:
        """Fallback QMessageBox class when PyQt6 is not available."""

        @staticmethod
        def information(parent: Any, title: str, message: str) -> None:
            """Show information message.

            Args:
                parent: Parent widget for the dialog.
                title: Dialog title.
                message: Message text to display.
            """

        @staticmethod
        def critical(parent: Any, title: str, message: str) -> None:
            """Show critical message.

            Args:
                parent: Parent widget for the dialog.
                title: Dialog title.
                message: Message text to display.
            """

        @staticmethod
        def warning(parent: Any, title: str, message: str) -> None:
            """Show warning message.

            Args:
                parent: Parent widget for the dialog.
                title: Dialog title.
                message: Message text to display.
            """

    class QPushButton:
        """Fallback QPushButton class when PyQt6 is not available."""

        def __init__(self, text: str = "") -> None:
            """Initialize button.

            Args:
                text: Initial button text.
            """
            self.clicked: pyqtSignal = pyqtSignal()

        def setText(self, text: str) -> None:
            """Set button text.

            Args:
                text: The text to display on the button.
            """

    class QTextEdit:
        """Fallback QTextEdit class when PyQt6 is not available."""

        def setReadOnly(self, readonly: bool) -> None:
            """Set read only.

            Args:
                readonly: Whether the text edit should be read-only.
            """

        def setFont(self, font: Any) -> None:
            """Set font.

            Args:
                font: The font to apply to the text edit.
            """

        def setPlainText(self, text: str) -> None:
            """Set plain text.

            Args:
                text: The plain text to set.
            """

        def textCursor(self) -> Any:
            """Get text cursor.

            Returns:
                The text cursor object or None.
            """
            return None

        def document(self) -> Any:
            """Get document.

            Returns:
                The QTextDocument or None.
            """
            return None

    class QVBoxLayout:
        """Fallback QVBoxLayout class when PyQt6 is not available."""

        def addWidget(self, widget: Any) -> None:
            """Add widget.

            Args:
                widget: The widget to add to the layout.
            """

        def addLayout(self, layout: Any) -> None:
            """Add layout.

            Args:
                layout: The layout to add to this layout.
            """

    class QWidget:
        """Fallback QWidget class when PyQt6 is not available."""

        pass

    PYQT6_AVAILABLE = False

try:
    from ...ai.protection_aware_script_gen import ProtectionAwareScriptGenerator
except ImportError:
    ProtectionAwareScriptGenerator = None

try:
    from ...protection.unified_protection_engine import UnifiedProtectionResult
except ImportError:
    UnifiedProtectionResult = None

try:
    from ...utils.logger import get_logger as _get_logger

    logger: Logger = _get_logger(__name__)
except ImportError:
    import logging

    logger = logging.getLogger(__name__)


class ScriptGenerationWorkerSignals(QObject):
    """Signals for script generation worker."""

    finished: pyqtSignal = pyqtSignal()
    error: pyqtSignal = pyqtSignal(tuple)
    result: pyqtSignal = pyqtSignal(dict)
    progress: pyqtSignal = pyqtSignal(str)


class ScriptGenerationWorker(QRunnable):
    """Worker thread for script generation."""

    def __init__(self, file_path: str, script_type: str, protections: list[str]) -> None:
        """Initialize the script generation worker.

        Args:
            file_path: Path to the file being analyzed.
            script_type: Type of script to generate (e.g., 'frida', 'ghidra').
            protections: List of detected protections to generate scripts for.
        """
        super().__init__()
        self.file_path: str = file_path
        self.script_type: str = script_type
        self.protections: list[str] = protections
        self.signals: ScriptGenerationWorkerSignals = ScriptGenerationWorkerSignals()

    def run(self) -> None:
        """Generate the bypass script with AI enhancement.

        Executes script generation for the configured file and protection types,
        with optional AI enhancements if available. Emits progress, result, and
        error signals during execution.
        """
        try:
            self.signals.progress.emit(f"Generating {self.script_type} script...")

            result: dict[str, Any]
            if ProtectionAwareScriptGenerator is None:
                result = {
                    "success": False,
                    "error": "ProtectionAwareScriptGenerator not available",
                }
            else:
                generator = ProtectionAwareScriptGenerator()

                if self.script_type.lower() == "frida":
                    result = generator.generate_bypass_script(self.file_path, "frida")
                elif self.script_type.lower() == "ghidra":
                    result = generator.generate_bypass_script(self.file_path, "ghidra")
                else:
                    result = {
                        "success": False,
                        "error": f"Unknown script type: {self.script_type}",
                    }

            if result.get("success", False):
                self.signals.progress.emit("Applying AI enhancements...")

                try:
                    from ...ai.protection_aware_script_gen import enhance_ai_script_generation

                    enhanced_result: dict[str, Any] = enhance_ai_script_generation(None, self.file_path)

                    if enhanced_result.get("enhanced_script"):
                        result["script"] = enhanced_result["enhanced_script"]
                        result["ai_enhanced"] = True
                        result["optimization_applied"] = enhanced_result.get("optimization_applied", [])
                        self.signals.progress.emit("AI enhancement complete")

                except ImportError:
                    self.signals.progress.emit("AI enhancement unavailable, using base script")
                except Exception as ai_error:
                    logger.warning("AI enhancement failed: %s", ai_error)
                    self.signals.progress.emit("AI enhancement failed, using base script")

            self.signals.result.emit(result)

        except Exception as e:
            logger.exception("Exception in script_generation_handler: %s", e)
            import traceback

            self.signals.error.emit((type(e), e, traceback.format_exc()))
        finally:
            self.signals.finished.emit()


class ScriptDisplayDialog(QDialog):
    """Dialog for displaying and managing generated scripts."""

    def __init__(self, script_data: dict[str, Any], parent: QWidget | None = None) -> None:
        """Initialize the script display dialog.

        Args:
            script_data: Dictionary containing the generated script data and metadata.
            parent: Optional parent widget for Qt integration.
        """
        super().__init__(parent)
        self.script_data: dict[str, Any] = script_data
        self.script_text: QTextEdit
        self.copy_btn: QPushButton
        self.save_btn: QPushButton
        self.close_btn: QPushButton
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the UI.

        Sets up the dialog layout with script information, display area, warnings,
        and action buttons for copying and saving the generated script.
        """
        self.setWindowTitle("Generated Bypass Script")
        self.setMinimumSize(800, 600)

        layout = QVBoxLayout()

        # Info section
        info_layout = QHBoxLayout()

        # Script type
        info_layout.addWidget(QLabel(f"Type: {self.script_data.get('type', 'Unknown')}"))

        # Approach
        approach = self.script_data.get("approach", "Unknown")
        info_layout.addWidget(QLabel(f"Approach: {approach}"))

        # Confidence
        confidence = self.script_data.get("confidence", 0)
        confidence_label = QLabel(f"Confidence: {confidence:.0%}")
        if confidence >= 0.8:
            confidence_label.setStyleSheet("color: green;")
        elif confidence >= 0.5:
            confidence_label.setStyleSheet("color: orange;")
        else:
            confidence_label.setStyleSheet("color: red;")
        info_layout.addWidget(confidence_label)

        # Difficulty
        difficulty = self.script_data.get("difficulty", "Unknown")
        info_layout.addWidget(QLabel(f"Difficulty: {difficulty}"))

        info_layout.addStretch()
        layout.addLayout(info_layout)

        # Script display with syntax highlighting
        self.script_text = QTextEdit()
        self.script_text.setReadOnly(True)
        self.script_text.setFont(QFont("Consolas", 10))
        self.script_text.setPlainText(self.script_data.get("script", ""))

        # Apply basic syntax highlighting
        self._apply_syntax_highlighting()

        layout.addWidget(self.script_text)

        # Warnings section
        if self.script_data.get("warnings"):
            warnings_label = QLabel("WARNING️ Warnings:")
            warnings_label.setStyleSheet("color: orange; font-weight: bold;")
            layout.addWidget(warnings_label)

            for warning in self.script_data["warnings"]:
                warning_text = QLabel(f"   {warning}")
                warning_text.setWordWrap(True)
                layout.addWidget(warning_text)

        # Button section
        button_layout = QHBoxLayout()

        self.copy_btn = QPushButton("Copy to Clipboard")
        self.copy_btn.clicked.connect(self.copy_script)
        button_layout.addWidget(self.copy_btn)

        self.save_btn = QPushButton("Save Script...")
        self.save_btn.clicked.connect(self.save_script)
        button_layout.addWidget(self.save_btn)

        button_layout.addStretch()

        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.accept)
        button_layout.addWidget(self.close_btn)

        layout.addLayout(button_layout)

        self.setLayout(layout)

    def _apply_syntax_highlighting(self) -> None:
        """Apply basic syntax highlighting based on script type.

        Applies keyword highlighting for Frida (JavaScript) and Ghidra (Python)
        scripts to improve readability in the display area.
        """
        if not PYQT6_AVAILABLE:
            return

        from PyQt6.QtGui import (
            QColor,
            QFont as QFontReal,
            QTextCharFormat,
            QTextDocument as QTextDocumentReal,
        )

        script_type = self.script_data.get("type", "")
        if not isinstance(script_type, str):
            return

        script_type_lower = script_type.lower()

        if script_type_lower == "frida":
            keywords = [
                "function",
                "var",
                "let",
                "const",
                "if",
                "else",
                "for",
                "while",
                "return",
                "true",
                "false",
                "null",
                "undefined",
                "new",
            ]
        elif script_type_lower == "ghidra":
            keywords = [
                "def",
                "class",
                "import",
                "from",
                "if",
                "else",
                "elif",
                "for",
                "while",
                "return",
                "True",
                "False",
                "None",
                "try",
                "except",
            ]
        else:
            keywords = []

        cursor = self.script_text.textCursor()
        if cursor is None:
            return

        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor(0, 0, 255))
        keyword_format.setFontWeight(QFontReal.Weight.Bold)

        string_format = QTextCharFormat()
        string_format.setForeground(QColor(0, 128, 0))

        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor(128, 128, 128))
        comment_format.setFontItalic(True)

        cursor.beginEditBlock()

        doc = self.script_text.document()
        if doc is not None:
            for keyword in keywords:
                cursor.setPosition(0)

                while True:
                    cursor = doc.find(
                        keyword,
                        cursor,
                        QTextDocumentReal.FindFlag.FindWholeWords,
                    )
                    if cursor.isNull():
                        break

                    cursor.mergeCharFormat(keyword_format)

        cursor.endEditBlock()

    def copy_script(self) -> None:
        """Copy script to clipboard.

        Copies the generated script text to the system clipboard and temporarily
        updates the button label to provide visual feedback.
        """
        if not PYQT6_AVAILABLE:
            return

        from PyQt6.QtWidgets import QApplication

        clipboard = QApplication.clipboard()
        if clipboard is not None:
            script_content = self.script_data.get("script", "")
            if isinstance(script_content, str):
                clipboard.setText(script_content)

        self.copy_btn.setText("Copied!")
        QTimer.singleShot(1500, lambda: self.copy_btn.setText("Copy to Clipboard"))

    def save_script(self) -> None:
        """Save script to file.

        Displays a file save dialog and writes the generated script to the selected
        file location. Provides user feedback on success or failure. All exceptions
        are caught and displayed to the user.

        """
        script_type_raw = self.script_data.get("type", "script")
        if not isinstance(script_type_raw, str):
            script_type_raw = "script"

        script_type = script_type_raw.lower()

        if script_type == "frida":
            default_name = "bypass_script.js"
            file_filter = "JavaScript Files (*.js);;All Files (*.*)"
        elif script_type == "ghidra":
            default_name = "bypass_script.py"
            file_filter = "Python Files (*.py);;All Files (*.*)"
        else:
            default_name = "bypass_script.txt"
            file_filter = "Text Files (*.txt);;All Files (*.*)"

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Bypass Script",
            default_name,
            file_filter,
        )

        if file_path:
            try:
                script_content = self.script_data.get("script", "")
                if not isinstance(script_content, str):
                    script_content = ""

                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(script_content)

                QMessageBox.information(
                    self,
                    "Script Saved",
                    f"Script saved to:\n{file_path}",
                )
            except Exception as e:
                logger.exception("Exception in script_generation_handler: %s", e)
                QMessageBox.critical(
                    self,
                    "Save Error",
                    f"Failed to save script:\n{e!s}",
                )


class ScriptGenerationHandler(QObject):
    """Handle bypass script generation based on protection analysis.

    Integrates with ProtectionAwareScriptGenerator to create
    Frida and Ghidra scripts for bypassing detected protections.
    """

    script_ready: pyqtSignal = pyqtSignal(dict)
    script_error: pyqtSignal = pyqtSignal(str)
    script_progress: pyqtSignal = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the script generation handler.

        Args:
            parent: Optional parent widget for Qt integration.
        """
        super().__init__(parent)
        thread_pool_instance = QThreadPool.globalInstance()
        if thread_pool_instance is None:
            thread_pool_instance = QThreadPool()
        self.thread_pool: QThreadPool = thread_pool_instance
        self.current_result: Any | None = None
        self.parent_widget: QWidget | None = parent

    def on_analysis_complete(self, result: Any) -> None:
        """Handle slot when protection analysis completes.

        Stores the analysis result for later script generation. Called when the
        protection analysis workflow finishes.

        Args:
            result: The analysis result containing detected protections.
        """
        self.current_result = result
        if hasattr(result, "file_path"):
            logger.info("Script generation handler received analysis for: %s", result.file_path)

    def generate_script(self, script_type: str = "frida", parent_widget: QWidget | None = None) -> None:
        """Generate a bypass script of the specified type.

        Spawns a worker thread to generate a Frida or Ghidra bypass script based
        on the current analysis result and detected protections.

        Args:
            script_type: Type of script to generate ("frida" or "ghidra").
            parent_widget: Optional parent widget for displaying dialogs.
        """
        if not self.current_result:
            self.script_error.emit("No analysis result available")
            return

        if not hasattr(self.current_result, "protections"):
            self.script_error.emit("Analysis result has no protections attribute")
            return

        protections_list = self.current_result.protections
        if not protections_list:
            self.script_error.emit("No protections detected to bypass")
            return

        if not hasattr(self.current_result, "file_path"):
            self.script_error.emit("Analysis result has no file_path attribute")
            return

        protection_names: list[str] = []
        if isinstance(protections_list, list):
            for p in protections_list:
                if isinstance(p, dict) and "name" in p:
                    name = p["name"]
                    if isinstance(name, str):
                        protection_names.append(name)

        worker = ScriptGenerationWorker(
            str(self.current_result.file_path),
            script_type,
            protection_names,
        )

        worker.signals.result.connect(
            lambda result: self._on_script_ready(result, parent_widget),
        )
        worker.signals.error.connect(self._on_worker_error)
        worker.signals.progress.connect(self.script_progress.emit)

        self.thread_pool.start(worker)

    def _on_script_ready(
        self,
        result: dict[str, Any],
        parent_widget: QWidget | None = None,
    ) -> None:
        """Handle script generation completion.

        Processes successful or failed script generation results and displays
        the script in a dialog or shows an error message to the user.

        Args:
            result: The script generation result dictionary.
            parent_widget: Optional parent widget for dialogs.
        """
        if result.get("success"):
            self.script_ready.emit(result)

            if parent_widget:
                dialog = ScriptDisplayDialog(result, parent_widget)
                dialog.exec()
        else:
            error_msg_raw = result.get("error", "Unknown error during script generation")
            error_msg = str(error_msg_raw) if error_msg_raw is not None else "Unknown error"
            self.script_error.emit(error_msg)

            if parent_widget:
                QMessageBox.warning(
                    parent_widget,
                    "Script Generation Failed",
                    error_msg,
                )

    def _on_worker_error(self, error_tuple: tuple[type[BaseException], BaseException, str]) -> None:
        """Handle worker thread errors.

        Logs the full exception traceback and emits an error signal with a
        human-readable error message.

        Args:
            error_tuple: Tuple containing exception type, value, and traceback.
        """
        _exc_type, exc_value, exc_traceback = error_tuple
        error_msg = f"Script generation failed: {exc_value}"
        logger.error("%s\n%s", error_msg, exc_traceback)
        self.script_error.emit(error_msg)
