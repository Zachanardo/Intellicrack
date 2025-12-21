"""Script Generation Handler.

Manages the generation of bypass scripts (Frida/Ghidra) based on
detected protections using the ProtectionAwareScriptGenerator.

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

    from PyQt6.QtCore import QObject as QObjectType
    from PyQt6.QtCore import QRunnable as QRunnableType
    from PyQt6.QtCore import QThreadPool as QThreadPoolType
    from PyQt6.QtCore import QTimer as QTimerType
    from PyQt6.QtCore import pyqtSignal as pyqtSignalType
    from PyQt6.QtGui import QFont as QFontType
    from PyQt6.QtGui import QTextDocument as QTextDocumentType
    from PyQt6.QtWidgets import QDialog as QDialogType
    from PyQt6.QtWidgets import QFileDialog as QFileDialogType
    from PyQt6.QtWidgets import QHBoxLayout as QHBoxLayoutType
    from PyQt6.QtWidgets import QLabel as QLabelType
    from PyQt6.QtWidgets import QMessageBox as QMessageBoxType
    from PyQt6.QtWidgets import QPushButton as QPushButtonType
    from PyQt6.QtWidgets import QTextEdit as QTextEditType
    from PyQt6.QtWidgets import QVBoxLayout as QVBoxLayoutType
    from PyQt6.QtWidgets import QWidget as QWidgetType

    from ...ai.protection_aware_script_gen import (
        ProtectionAwareScriptGenerator as ProtectionAwareScriptGeneratorType,
    )
    from ...protection.unified_protection_engine import (
        UnifiedProtectionResult as UnifiedProtectionResultType,
    )

try:
    from PyQt6.QtCore import QObject, QRunnable, QThreadPool, QTimer, pyqtSignal
    from PyQt6.QtGui import QFont, QTextDocument
    from PyQt6.QtWidgets import QDialog, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPushButton, QTextEdit, QVBoxLayout, QWidget

    PYQT6_AVAILABLE = True
except ImportError:

    class QObject:  # type: ignore[no-redef]
        """Fallback QObject class when PyQt6 is not available."""

        pass

    class QRunnable:  # type: ignore[no-redef]
        """Fallback QRunnable class when PyQt6 is not available."""

        def run(self) -> None:
            """Execute the runnable task."""

    class QThreadPool:  # type: ignore[no-redef]
        """Fallback QThreadPool class when PyQt6 is not available."""

        @staticmethod
        def globalInstance() -> QThreadPool | None:
            """Return the global thread pool instance."""
            return QThreadPool()

        def start(self, runnable: QRunnable) -> None:
            """Start a runnable."""

    class QTimer:  # type: ignore[no-redef]
        """Fallback QTimer class when PyQt6 is not available."""

        @staticmethod
        def singleShot(msec: int, func: Any) -> None:
            """Single shot timer."""

    class pyqtSignal:  # type: ignore[no-redef]
        """Fallback pyqtSignal class when PyQt6 is not available."""

        def __init__(self, *args: Any) -> None:
            """Initialize signal."""
            self._callbacks: list[Any] = []

        def emit(self, *args: Any) -> None:
            """Emit signal."""
            for callback in self._callbacks:
                callback(*args)

        def connect(self, callback: Any) -> None:
            """Connect signal."""
            self._callbacks.append(callback)

    class QFont:  # type: ignore[no-redef]
        """Fallback QFont class when PyQt6 is not available."""

        class Weight:
            """Font weight enumeration."""

            Bold: int = 75

    class QTextDocument:  # type: ignore[no-redef]
        """Fallback QTextDocument class when PyQt6 is not available."""

        class FindFlag:
            """Find flags."""

            FindWholeWords: int = 2

    class QDialog:  # type: ignore[no-redef]
        """Fallback QDialog class when PyQt6 is not available."""

        def __init__(self, parent: Any = None) -> None:
            """Initialize dialog."""

        def setWindowTitle(self, title: str) -> None:
            """Set window title."""

        def setMinimumSize(self, width: int, height: int) -> None:
            """Set minimum size."""

        def setLayout(self, layout: Any) -> None:
            """Set layout."""

        def exec(self) -> int:
            """Execute dialog."""
            return 0

        def accept(self) -> None:
            """Accept dialog."""

    class QFileDialog:  # type: ignore[no-redef]
        """Fallback QFileDialog class when PyQt6 is not available."""

        @staticmethod
        def getSaveFileName(
            parent: Any = None,
            caption: str = "",
            directory: str = "",
            filter: str = "",
        ) -> tuple[str, str]:
            """Get save file name."""
            return ("", "")

    class QHBoxLayout:  # type: ignore[no-redef]
        """Fallback QHBoxLayout class when PyQt6 is not available."""

        def addWidget(self, widget: Any) -> None:
            """Add widget."""

        def addStretch(self) -> None:
            """Add stretch."""

    class QLabel:  # type: ignore[no-redef]
        """Fallback QLabel class when PyQt6 is not available."""

        def __init__(self, text: str = "") -> None:
            """Initialize label."""

        def setStyleSheet(self, style: str) -> None:
            """Set style sheet."""

        def setWordWrap(self, wrap: bool) -> None:
            """Set word wrap."""

    class QMessageBox:  # type: ignore[no-redef]
        """Fallback QMessageBox class when PyQt6 is not available."""

        @staticmethod
        def information(parent: Any, title: str, message: str) -> None:
            """Show information message."""

        @staticmethod
        def critical(parent: Any, title: str, message: str) -> None:
            """Show critical message."""

        @staticmethod
        def warning(parent: Any, title: str, message: str) -> None:
            """Show warning message."""

    class QPushButton:  # type: ignore[no-redef]
        """Fallback QPushButton class when PyQt6 is not available."""

        def __init__(self, text: str = "") -> None:
            """Initialize button."""
            self.clicked: pyqtSignal = pyqtSignal()

        def setText(self, text: str) -> None:
            """Set button text."""

    class QTextEdit:  # type: ignore[no-redef]
        """Fallback QTextEdit class when PyQt6 is not available."""

        def setReadOnly(self, readonly: bool) -> None:
            """Set read only."""

        def setFont(self, font: Any) -> None:
            """Set font."""

        def setPlainText(self, text: str) -> None:
            """Set plain text."""

        def textCursor(self) -> Any:
            """Get text cursor."""
            return None

        def document(self) -> Any:
            """Get document."""
            return None

    class QVBoxLayout:  # type: ignore[no-redef]
        """Fallback QVBoxLayout class when PyQt6 is not available."""

        def addWidget(self, widget: Any) -> None:
            """Add widget."""

        def addLayout(self, layout: Any) -> None:
            """Add layout."""

    class QWidget:  # type: ignore[no-redef]
        """Fallback QWidget class when PyQt6 is not available."""

        pass

    PYQT6_AVAILABLE = False

try:
    from ...ai.protection_aware_script_gen import ProtectionAwareScriptGenerator
except ImportError:
    ProtectionAwareScriptGenerator = None  # type: ignore[assignment,misc]

try:
    from ...protection.unified_protection_engine import UnifiedProtectionResult
except ImportError:
    UnifiedProtectionResult = None  # type: ignore[assignment,misc]

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
        """Generate the bypass script with AI enhancement."""
        try:
            self.signals.progress.emit(f"Generating {self.script_type} script...")

            result: dict[str, Any]
            if ProtectionAwareScriptGenerator is None:
                result = {  # type: ignore[unreachable]
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
        """Initialize the UI."""
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
        """Apply basic syntax highlighting based on script type."""
        if not PYQT6_AVAILABLE:
            return

        from PyQt6.QtGui import QColor, QTextCharFormat
        from PyQt6.QtGui import QFont as QFontReal
        from PyQt6.QtGui import QTextDocument as QTextDocumentReal

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
            return  # type: ignore[unreachable]

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
        """Copy script to clipboard."""
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
        """Save script to file."""
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

        Args:
            result: The UnifiedProtectionResult from analysis.

        """
        self.current_result = result
        if hasattr(result, "file_path"):
            logger.info("Script generation handler received analysis for: %s", result.file_path)

    def generate_script(self, script_type: str = "frida", parent_widget: QWidget | None = None) -> None:
        """Generate a bypass script of the specified type.

        Args:
            script_type: Type of script to generate ("frida" or "ghidra")
            parent_widget: Parent widget for dialog (optional)

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

    def _on_script_ready(self, result: dict[str, Any], parent_widget: QWidget | None = None) -> None:
        """Handle script generation completion.

        Args:
            result: The script generation result dictionary.
            parent_widget: Optional parent widget for dialogs.

        """
        if result.get("success", False):
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

        Args:
            error_tuple: Tuple containing exception type, value, and traceback.

        """
        _exc_type, exc_value, exc_traceback = error_tuple
        error_msg = f"Script generation failed: {exc_value}"
        logger.error("%s\n%s", error_msg, exc_traceback)
        self.script_error.emit(error_msg)
