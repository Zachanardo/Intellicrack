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

try:
    from PyQt6.QtCore import QObject, QRunnable, QThreadPool, QTimer, pyqtSignal
    from PyQt6.QtGui import QFont, QTextDocument
    from PyQt6.QtWidgets import (
        QDialog,
        QFileDialog,
        QHBoxLayout,
        QLabel,
        QMessageBox,
        QPushButton,
        QTextEdit,
        QVBoxLayout,
    )

    PYQT6_AVAILABLE = True
except ImportError:
    # Fallback classes when PyQt6 is not available
    class QObject:
        """Fallback QObject class when PyQt6 is not available."""

        pass

    class QRunnable:
        """Fallback QRunnable class when PyQt6 is not available."""

        def run(self):
            """Execute the runnable task."""
            pass

    class QThreadPool:
        """Fallback QThreadPool class when PyQt6 is not available."""

        @staticmethod
        def global_instance():
            """Return the global thread pool instance."""
            return None

    class QTimer:
        """Fallback QTimer class when PyQt6 is not available."""

        pass

    def pyqtSignal(*args):
        """Fallback pyqtSignal function when PyQt6 is not available."""
        return None

    class QFont:
        """Fallback QFont class when PyQt6 is not available."""

        pass

    class QTextDocument:
        """Fallback QTextDocument class when PyQt6 is not available."""

        pass

    # Fallback widget classes
    class QDialog:
        """Fallback QDialog class when PyQt6 is not available."""

        pass

    class QFileDialog:
        """Fallback QFileDialog class when PyQt6 is not available."""

        pass

    class QHBoxLayout:
        """Fallback QHBoxLayout class when PyQt6 is not available."""

        pass

    class QLabel:
        """Fallback QLabel class when PyQt6 is not available."""

        pass

    class QMessageBox:
        """Fallback QMessageBox class when PyQt6 is not available."""

        pass

    class QPushButton:
        """Fallback QPushButton class when PyQt6 is not available."""

        pass

    class QTextEdit:
        """Fallback QTextEdit class when PyQt6 is not available."""

        pass

    class QVBoxLayout:
        """Fallback QVBoxLayout class when PyQt6 is not available."""

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
    from ...utils.logger import get_logger
except ImportError:
    import logging

    def get_logger(name):
        """Create a logger instance with the given name.

        Args:
            name: The name for the logger instance

        Returns:
            A logging.Logger instance

        """
        return logging.getLogger(name)


logger = get_logger(__name__)


class ScriptGenerationWorkerSignals(QObject):
    """Signals for script generation worker."""

    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(dict)
    progress = pyqtSignal(str)


class ScriptGenerationWorker(QRunnable):
    """Worker thread for script generation."""

    def __init__(self, file_path: str, script_type: str, protections: list):
        """Initialize the script generation worker.

        Args:
            file_path: Path to the file being analyzed.
            script_type: Type of script to generate (e.g., 'frida', 'ghidra').
            protections: List of detected protections to generate scripts for.

        """
        super().__init__()
        self.file_path = file_path
        self.script_type = script_type
        self.protections = protections
        self.signals = ScriptGenerationWorkerSignals()

    def run(self):
        """Generate the bypass script with AI enhancement."""
        try:
            self.signals.progress.emit(f"Generating {self.script_type} script...")

            generator = ProtectionAwareScriptGenerator()

            # Generate script based on type
            if self.script_type.lower() == "frida":
                result = generator.generate_bypass_script(self.file_path, "frida")
            elif self.script_type.lower() == "ghidra":
                result = generator.generate_bypass_script(self.file_path, "ghidra")
            else:
                result = {
                    "success": False,
                    "error": f"Unknown script type: {self.script_type}",
                }

            # Apply AI enhancement if script generation was successful
            if result.get("success", False):
                self.signals.progress.emit("Applying AI enhancements...")

                try:
                    from ...ai.protection_aware_script_gen import enhance_ai_script_generation

                    # Enhance the script with AI capabilities
                    enhanced_result = enhance_ai_script_generation(None, self.file_path)

                    # If enhanced script was generated, use it
                    if enhanced_result.get("enhanced_script"):
                        result["script"] = enhanced_result["enhanced_script"]
                        result["ai_enhanced"] = True
                        result["optimization_applied"] = enhanced_result.get("optimization_applied", [])
                        self.signals.progress.emit("AI enhancement complete")

                except ImportError:
                    # AI enhancement not available, continue with base script
                    self.signals.progress.emit("AI enhancement unavailable, using base script")
                except Exception as ai_error:
                    # Log AI enhancement error but continue with base script
                    import logging

                    logging.warning(f"AI enhancement failed: {ai_error}")
                    self.signals.progress.emit("AI enhancement failed, using base script")

            self.signals.result.emit(result)

        except Exception as e:
            self.logger.error("Exception in script_generation_handler: %s", e)
            import traceback

            self.signals.error.emit((type(e), e, traceback.format_exc()))
        finally:
            self.signals.finished.emit()


class ScriptDisplayDialog(QDialog):
    """Dialog for displaying and managing generated scripts."""

    def __init__(self, script_data: dict, parent=None):
        """Initialize the script display dialog.

        Args:
            script_data: Dictionary containing the generated script data and metadata.
            parent: Optional parent widget for Qt integration.

        """
        super().__init__(parent)
        self.script_data = script_data
        self.init_ui()

    def init_ui(self):
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
                warning_text = QLabel(f"  • {warning}")
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

    def _apply_syntax_highlighting(self):
        """Apply basic syntax highlighting based on script type."""
        from PyQt6.QtGui import QColor, QFont, QTextCharFormat

        # This is a simplified version - could be enhanced with proper syntax highlighter
        script_type = self.script_data.get("type", "").lower()

        if script_type == "frida":
            # JavaScript highlighting for Frida
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
        elif script_type == "ghidra":
            # Python highlighting for Ghidra
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

        # Simple keyword highlighting (could be improved with QSyntaxHighlighter)
        cursor = self.script_text.textCursor()

        # Keyword format
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor(0, 0, 255))
        keyword_format.setFontWeight(QFont.Bold)

        # String format
        string_format = QTextCharFormat()
        string_format.setForeground(QColor(0, 128, 0))

        # Comment format
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor(128, 128, 128))
        comment_format.setFontItalic(True)

        # Apply keyword highlighting
        cursor.beginEditBlock()

        # Highlight keywords
        for keyword in keywords:
            # Reset cursor position
            cursor.setPosition(0)

            # Find all occurrences of the keyword
            while True:
                cursor = self.script_text.document().find(
                    keyword,
                    cursor,
                    QTextDocument.FindWholeWords,
                )
                if cursor.isNull():
                    break

                cursor.mergeCharFormat(keyword_format)

        cursor.endEditBlock()

    def copy_script(self):
        """Copy script to clipboard."""
        from PyQt6.QtWidgets import QApplication

        QApplication.clipboard().setText(self.script_data.get("script", ""))

        # Show brief confirmation
        self.copy_btn.setText("Copied!")
        QTimer.singleShot(1500, lambda: self.copy_btn.setText("Copy to Clipboard"))

    def save_script(self):
        """Save script to file."""
        script_type = self.script_data.get("type", "script").lower()
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
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(self.script_data.get("script", ""))

                QMessageBox.information(
                    self,
                    "Script Saved",
                    f"Script saved to:\n{file_path}",
                )
            except Exception as e:
                logger.error("Exception in script_generation_handler: %s", e)
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

    # Signals
    script_ready = pyqtSignal(dict)
    script_error = pyqtSignal(str)
    script_progress = pyqtSignal(str)

    def __init__(self, parent=None):
        """Initialize the script generation handler.

        Args:
            parent: Optional parent widget for Qt integration.

        """
        super().__init__(parent)
        self.thread_pool = QThreadPool.global_instance()
        self.current_result: UnifiedProtectionResult | None = None
        self.parent_widget = parent

    def on_analysis_complete(self, result: UnifiedProtectionResult):
        """Handle slot when protection analysis completes."""
        self.current_result = result
        logger.info(f"Script generation handler received analysis for: {result.file_path}")

    def generate_script(self, script_type: str = "frida", parent_widget=None):
        """Generate a bypass script of the specified type.

        Args:
            script_type: Type of script to generate ("frida" or "ghidra")
            parent_widget: Parent widget for dialog (optional)

        """
        if not self.current_result:
            self.script_error.emit("No analysis result available")
            return

        if not self.current_result.protections:
            self.script_error.emit("No protections detected to bypass")
            return

        # Get protection list
        protections = [p["name"] for p in self.current_result.protections]

        # Start generation in background
        worker = ScriptGenerationWorker(
            self.current_result.file_path,
            script_type,
            protections,
        )

        worker.signals.result.connect(
            lambda result: self._on_script_ready(result, parent_widget),
        )
        worker.signals.error.connect(self._on_worker_error)
        worker.signals.progress.connect(self.script_progress.emit)

        self.thread_pool.start(worker)

    def _on_script_ready(self, result: dict, parent_widget=None):
        """Handle script generation completion."""
        if result["success"]:
            # Emit signal
            self.script_ready.emit(result)

            # Show dialog if we have a parent widget
            if parent_widget:
                dialog = ScriptDisplayDialog(result, parent_widget)
                dialog.exec()
        else:
            error_msg = result.get("error", "Unknown error during script generation")
            self.script_error.emit(error_msg)

            if parent_widget:
                QMessageBox.warning(
                    parent_widget,
                    "Script Generation Failed",
                    error_msg,
                )

    def _on_worker_error(self, error_tuple):
        """Handle worker thread errors."""
        exc_type, exc_value, exc_traceback = error_tuple
        error_msg = f"Script generation failed: {exc_value}"
        logger.error(f"{error_msg}\n{exc_traceback}")
        self.script_error.emit(error_msg)


# Import for QTimer
