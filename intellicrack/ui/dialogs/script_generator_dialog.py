"""Script generator dialog for creating analysis scripts."""
import os
import time

from intellicrack.ai.ai_tools import AIAssistant
from intellicrack.logger import logger

from ..common_imports import (
    QCheckBox,
    QColor,
    QComboBox,
    QFileDialog,
    QFont,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    Qt,
    QTabWidget,
    QTextEdit,
    QThread,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)
from .base_dialog import BinarySelectionDialog

"""
Script Generation Dialog for Intellicrack.

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




try:
    from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat
    from PyQt6.QtWidgets import QPlainTextEdit
except ImportError as e:
    logger.error("Import error in script_generator_dialog: %s", e)


class PythonHighlighter(QSyntaxHighlighter):
    """Simple Python syntax highlighter."""

    def __init__(self, parent=None):
        """Initialize the PythonHighlighter with default values."""
        super().__init__(parent)
        self.highlighting_rules = []

        # Keywords
        keyword_format = QTextCharFormat()
        keyword_format.setColor(QColor(128, 0, 255))
        keyword_format.setFontWeight(QFont.Bold)
        keywords = [
            "def", "class", "if", "else", "elif", "while", "for",
            "try", "except", "import", "from", "return", "with",
        ]
        for _keyword in keywords:
            pattern = f"\\b{_keyword}\\b"
            self.highlighting_rules.append((pattern, keyword_format))

        # Strings
        string_format = QTextCharFormat()
        string_format.setColor(QColor(0, 128, 0))
        self.highlighting_rules.append(('".*"', string_format))
        self.highlighting_rules.append("'.*'", string_format)

        # Comments
        comment_format = QTextCharFormat()
        comment_format.setColor(QColor(128, 128, 128))
        self.highlighting_rules.append(("#.*", comment_format))

    def highlightBlock(self, text):
        """Highlight a block of text."""
        import re
        for pattern, text_format in self.highlighting_rules:
            for _match in re.finditer(pattern, text):
                start, end = _match.span()
                self.setFormat(start, end - start, text_format)


class ScriptGeneratorWorker(QThread):
    """Background worker for script generation."""

    script_generated = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, binary_path: str, script_type: str, **kwargs):
        """Initialize the ScriptGeneratorWorker with default values."""
        super().__init__()
        self.binary_path = binary_path
        self.script_type = script_type
        self.kwargs = kwargs
        self.logger = logger
        self.ai_generator = None

    def run(self):
        """Execute the script generation."""
        try:
            if self.script_type == "bypass":
                self._generate_bypass_script()
            elif self.script_type == "exploit":
                self._generate_exploit_script()
            elif self.script_type == "strategy":
                self._generate_exploit_strategy()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in script_generator_dialog: %s", e)
            self.error_occurred.emit(str(e))

    def _generate_bypass_script(self):
        """Generate bypass script."""
        # Try AI-powered generation first
        try:
            from ...ai.ai_script_generator import AIScriptGenerator

            if not self.ai_generator:
                self.ai_generator = AIScriptGenerator()

            # Prepare protection info
            protection_info = {
                "type": self.kwargs.get("protection_type", "license"),
                "methods": self.kwargs.get("methods", ["patch"]),
                "target_platform": "frida" if self.kwargs.get("language") == "javascript" else "python",
            }

            # Generate script using AI
            if self.kwargs.get("language") == "javascript":
                result = self.ai_generator.generate_frida_script(
                    self.binary_path,
                    protection_info,
                )
            else:
                # For Python/other languages, generate Ghidra script
                result = self.ai_generator.generate_ghidra_script(
                    self.binary_path,
                    protection_info,
                )

            self.script_generated.emit(result)

        except Exception as e:
            self.logger.warning(f"AI script generation failed: {e}. Falling back to template-based generation.")
            # Fallback to template-based generation
            from ...utils.exploitation import generate_bypass_script

            result = generate_bypass_script(
                self.binary_path,
                protection_type=self.kwargs.get("protection_type", "license"),
                language=self.kwargs.get("language", "python"),
            )
            self.script_generated.emit(result)

    def _generate_exploit_script(self):
        """Generate exploit script."""
        from ...utils.exploitation import generate_exploit

        result = generate_exploit(
            vulnerability=self.kwargs.get("exploit_type", "buffer_overflow"),
            target_arch=self.kwargs.get("target_arch", "x86"),
            payload_type=self.kwargs.get("payload_type", "shellcode"),
        )
        self.script_generated.emit(result)

    def _generate_exploit_strategy(self):
        """Generate exploit strategy."""
        from ...utils.exploitation import generate_exploit_strategy

        result = generate_exploit_strategy(
            self.binary_path,
            vulnerability_type=self.kwargs.get("vulnerability_type", "buffer_overflow"),
        )
        self.script_generated.emit(result)


class ScriptGeneratorDialog(BinarySelectionDialog):
    """Script Generation Dialog with multiple script types."""

    def __init__(self, parent=None, binary_path: str = ""):
        """Initialize the ScriptGeneratorDialog with default values."""
        # Initialize UI attributes
        self.analysis_depth = None
        self.analyze_btn = None
        self.bypass_config = None
        self.bypass_language = None
        self.bypass_output = None
        self.close_btn = None
        self.copy_btn = None
        self.doc_display = None
        self.exploit_advanced = None
        self.exploit_config = None
        self.exploit_type = None
        self.highlighter = None
        self.include_analysis = None
        self.include_exploitation = None
        self.include_options = None
        self.include_persistence = None
        self.include_recon = None
        self.method_hook = None
        self.method_loader = None
        self.method_memory = None
        self.method_patch = None
        self.method_registry = None
        self.payload_type = None
        self.save_btn = None
        self.script_display = None
        self.script_tabs = None
        self.status_label = None
        self.strategy_config = None
        self.strategy_type = None
        self.target_function = None
        self.template_display = None
        self.test_btn = None
        super().__init__(parent)
        self.binary_path = binary_path
        self.worker = None
        self.generated_scripts = {}

        self.setWindowTitle("Script Generator")
        self.setMinimumSize(1000, 700)
        self.setModal(True)

        self.setup_ui()
        self.connect_signals()

    def setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)

        # Header
        self.setup_header(layout)

        # Main content
        self.setup_main_content(layout)

        # Footer
        self.setup_footer(layout)

    def setup_header(self, layout):
        """Setup header with binary selection."""
        # Use the base class method
        super().setup_header(layout, show_label=True)

    def setup_main_content(self, layout):
        """Setup main content area."""
        splitter = QSplitter(Qt.Horizontal)

        # Left panel - Script types and configuration
        self.setup_left_panel(splitter)

        # Right panel - Generated script display
        self.setup_right_panel(splitter)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter)

    def setup_left_panel(self, splitter):
        """Setup left configuration panel."""
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)

        # Script type selection
        type_group = QGroupBox("Script Type")
        type_layout = QVBoxLayout(type_group)

        self.script_type_combo = QComboBox()
        self.script_type_combo.addItems([
            "Bypass Script",
            "Exploit Script",
            "Exploit Strategy",
            "Custom Script",
        ])
        self.script_type_combo.currentTextChanged.connect(self.on_script_type_changed)

        type_layout.addWidget(self.script_type_combo)
        left_layout.addWidget(type_group)

        # Configuration stack for different script types
        self.config_stack = QWidget()
        self.config_layout = QVBoxLayout(self.config_stack)

        self.setup_bypass_config()
        self.setup_exploit_config()
        self.setup_strategy_config()

        left_layout.addWidget(self.config_stack)

        # Generate button
        self.generate_btn = QPushButton("Generate Script")
        self.generate_btn.clicked.connect(self.generate_script)
        self.generate_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 10px; }")
        left_layout.addWidget(self.generate_btn)

        left_layout.addStretch()
        splitter.addWidget(left_widget)

    def setup_bypass_config(self):
        """Setup bypass script configuration."""
        self.bypass_config = QGroupBox("Bypass Script Configuration")
        layout = QGridLayout(self.bypass_config)

        # Language selection
        layout.addWidget(QLabel("Language:"), 0, 0)
        self.bypass_language = QComboBox()
        self.bypass_language.addItems(["Python", "JavaScript", "PowerShell", "Batch"])
        layout.addWidget(self.bypass_language, 0, 1)

        # Bypass methods
        layout.addWidget(QLabel("Methods:"), 1, 0)
        self.bypass_methods = QWidget()
        methods_layout = QVBoxLayout(self.bypass_methods)

        self.method_patch = QCheckBox("Binary Patching")
        self.method_patch.setChecked(True)
        self.method_loader = QCheckBox("DLL Injection/Loading")
        self.method_hook = QCheckBox("API Hooking")
        self.method_memory = QCheckBox("Memory Patching")
        self.method_registry = QCheckBox("Registry Modification")

        methods_layout.addWidget(self.method_patch)
        methods_layout.addWidget(self.method_loader)
        methods_layout.addWidget(self.method_hook)
        methods_layout.addWidget(self.method_memory)
        methods_layout.addWidget(self.method_registry)

        layout.addWidget(self.bypass_methods, 1, 1)

        # Output format
        layout.addWidget(QLabel("Output:"), 2, 0)
        self.bypass_output = QComboBox()
        self.bypass_output.addItems(["Script", "Executable", "Library"])
        layout.addWidget(self.bypass_output, 2, 1)

        self.config_layout.addWidget(self.bypass_config)

    def setup_exploit_config(self):
        """Setup exploit script configuration."""
        self.exploit_config = QGroupBox("Exploit Script Configuration")
        layout = QGridLayout(self.exploit_config)

        # Exploit type
        layout.addWidget(QLabel("Exploit Type:"), 0, 0)
        self.exploit_type = QComboBox()
        self.exploit_type.addItems([
            "License Bypass",
            "Trial Extension",
            "Feature Unlock",
            "Authentication Bypass",
            "Custom Exploit",
        ])
        layout.addWidget(self.exploit_type, 0, 1)

        # Target function
        layout.addWidget(QLabel("Target Function:"), 1, 0)
        self.target_function = QLineEdit()
        self.target_function.setPlaceholderText("e.g., CheckLicense, ValidateUser")
        layout.addWidget(self.target_function, 1, 1)

        # Payload type
        layout.addWidget(QLabel("Payload Type:"), 2, 0)
        self.payload_type = QComboBox()
        self.payload_type.addItems(["Patch", "Hook", "Replace", "Redirect"])
        layout.addWidget(self.payload_type, 2, 1)

        # Advanced options
        self.exploit_advanced = QCheckBox("Include Anti-Detection")
        layout.addWidget(self.exploit_advanced, 3, 0, 1, 2)

        self.config_layout.addWidget(self.exploit_config)
        self.exploit_config.hide()

    def setup_strategy_config(self):
        """Setup strategy configuration."""
        self.strategy_config = QGroupBox("Exploit Strategy Configuration")
        layout = QGridLayout(self.strategy_config)

        # Strategy type
        layout.addWidget(QLabel("Strategy Type:"), 0, 0)
        self.strategy_type = QComboBox()
        self.strategy_type.addItems([
            "Comprehensive Analysis",
            "Quick Bypass",
            "Stealth Approach",
            "Brute Force",
            "Custom Strategy",
        ])
        layout.addWidget(self.strategy_type, 0, 1)

        # Analysis depth
        layout.addWidget(QLabel("Analysis Depth:"), 1, 0)
        self.analysis_depth = QComboBox()
        self.analysis_depth.addItems(["Light", "Medium", "Deep", "Exhaustive"])
        layout.addWidget(self.analysis_depth, 1, 1)

        # Include sections
        layout.addWidget(QLabel("Include:"), 2, 0)
        self.include_options = QWidget()
        include_layout = QVBoxLayout(self.include_options)

        self.include_recon = QCheckBox("Reconnaissance")
        self.include_recon.setChecked(True)
        self.include_analysis = QCheckBox("Vulnerability Analysis")
        self.include_analysis.setChecked(True)
        self.include_exploitation = QCheckBox("Exploitation Steps")
        self.include_exploitation.setChecked(True)
        self.include_persistence = QCheckBox("Persistence Methods")

        include_layout.addWidget(self.include_recon)
        include_layout.addWidget(self.include_analysis)
        include_layout.addWidget(self.include_exploitation)
        include_layout.addWidget(self.include_persistence)

        layout.addWidget(self.include_options, 2, 1)

        self.config_layout.addWidget(self.strategy_config)
        self.strategy_config.hide()

    def setup_right_panel(self, splitter):
        """Setup right script display panel."""
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        # Script tabs
        self.script_tabs = QTabWidget()

        # Generated script tab
        self.script_display = QPlainTextEdit()
        self.script_display.setFont(QFont("Consolas", 10))
        self.script_display.setLineWrapMode(QPlainTextEdit.NoWrap)

        # Add syntax highlighting
        self.highlighter = PythonHighlighter(self.script_display.document())

        self.script_tabs.addTab(self.script_display, "Generated Script")

        # Documentation tab
        self.doc_display = QTextEdit()
        self.doc_display.setFont(QFont("Consolas", 10))
        self.script_tabs.addTab(self.doc_display, "Documentation")

        # Template tab
        self.template_display = QTextEdit()
        self.template_display.setFont(QFont("Consolas", 10))
        self.script_tabs.addTab(self.template_display, "Template Code")

        right_layout.addWidget(self.script_tabs)

        # Action buttons
        actions_layout = QHBoxLayout()

        self.copy_btn = QPushButton("Copy Script")
        self.copy_btn.clicked.connect(self.copy_script)

        self.save_btn = QPushButton("Save Script")
        self.save_btn.clicked.connect(self.save_script)

        self.test_btn = QPushButton("Test Script")
        self.test_btn.clicked.connect(self.test_script)

        self.analyze_btn = QPushButton("Analyze Script")
        self.analyze_btn.clicked.connect(self.analyze_script)

        actions_layout.addWidget(self.copy_btn)
        actions_layout.addWidget(self.save_btn)
        actions_layout.addWidget(self.test_btn)
        actions_layout.addWidget(self.analyze_btn)
        actions_layout.addStretch()

        right_layout.addLayout(actions_layout)

        splitter.addWidget(right_widget)

    def setup_footer(self, layout):
        """Setup footer with status and close button."""
        footer_layout = QHBoxLayout()

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("QLabel { color: #666; }")

        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.close)

        footer_layout.addWidget(self.status_label)
        footer_layout.addStretch()
        footer_layout.addWidget(self.close_btn)

        layout.addLayout(footer_layout)

    def connect_signals(self):
        """Connect internal signals."""
        self.binary_path_edit.textChanged.connect(self.on_binary_path_changed)


    def on_binary_path_changed(self, text):
        """Handle binary path change."""
        self.binary_path = text

    def on_script_type_changed(self, script_type):
        """Handle script type change."""
        # Hide all config groups
        self.bypass_config.hide()
        self.exploit_config.hide()
        self.strategy_config.hide()

        # Show relevant config
        if script_type == "Bypass Script":
            self.bypass_config.show()
        elif script_type == "Exploit Script":
            self.exploit_config.show()
        elif script_type == "Exploit Strategy":
            self.strategy_config.show()

    def generate_script(self):
        """Generate script based on configuration."""
        if not self.binary_path or not os.path.exists(self.binary_path):
            QMessageBox.warning(self, "Warning", "Please select a valid binary file first.")
            return

        script_type = self.script_type_combo.currentText()
        self.status_label.setText(f"Generating {script_type.lower()}...")
        self.generate_btn.setEnabled(False)

        # Get configuration based on script type
        if script_type == "Bypass Script":
            kwargs = self.get_bypass_config()
            worker_type = "bypass"
        elif script_type == "Exploit Script":
            kwargs = self.get_exploit_config()
            worker_type = "exploit"
        elif script_type == "Exploit Strategy":
            kwargs = self.get_strategy_config()
            worker_type = "strategy"
        else:
            QMessageBox.warning(self, "Warning", "Custom scripts not yet implemented.")
            self.generate_btn.setEnabled(True)
            return

        # Start worker thread
        self.worker = ScriptGeneratorWorker(self.binary_path, worker_type, **kwargs)
        self.worker.script_generated.connect(self.on_script_generated)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def get_bypass_config(self):
        """Get bypass script configuration."""
        methods = []
        if self.method_patch.isChecked():
            methods.append("patch")
        if self.method_loader.isChecked():
            methods.append("loader")
        if self.method_hook.isChecked():
            methods.append("hook")
        if self.method_memory.isChecked():
            methods.append("memory")
        if self.method_registry.isChecked():
            methods.append("registry")

        return {
            "language": self.bypass_language.currentText().lower(),
            "methods": methods,
            "output_format": self.bypass_output.currentText().lower(),
        }

    def get_exploit_config(self):
        """Get exploit script configuration."""
        return {
            "exploit_type": self.exploit_type.currentText().lower().replace(" ", "_"),
            "target_function": self.target_function.text(),
            "payload_type": self.payload_type.currentText().lower(),
            "include_anti_detection": self.exploit_advanced.isChecked(),
        }

    def get_strategy_config(self):
        """Get strategy configuration."""
        return {
            "strategy_type": self.strategy_type.currentText().lower().replace(" ", "_"),
            "analysis_depth": self.analysis_depth.currentText().lower(),
            "include_recon": self.include_recon.isChecked(),
            "include_analysis": self.include_analysis.isChecked(),
            "include_exploitation": self.include_exploitation.isChecked(),
            "include_persistence": self.include_persistence.isChecked(),
        }

    def on_script_generated(self, result):
        """Handle script generation completion."""
        self.generated_scripts[self.script_type_combo.currentText()] = result

        # Display script
        script_content = result.get("script", result.get("strategy", "No script generated"))
        self.script_display.setPlainText(script_content)

        # Display documentation
        doc_content = result.get("documentation", result.get("description", "No documentation available"))
        self.doc_display.setPlainText(doc_content)

        # Display template if available
        template_content = result.get("template", "No template available")
        self.template_display.setPlainText(template_content)

        self.status_label.setText("Script generated successfully")
        self.generate_btn.setEnabled(True)

    def copy_script(self):
        """Copy script to clipboard."""
        script_content = self.script_display.toPlainText()
        if script_content:
            try:
                from PyQt6.QtWidgets import QApplication
                QApplication.clipboard().setText(script_content)
                self.status_label.setText("Script copied to clipboard")
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.error("Error in script_generator_dialog: %s", e)
                QMessageBox.information(self, "Copy", "Script copied to clipboard (fallback)")

    def save_script(self):
        """Save script to file."""
        script_content = self.script_display.toPlainText()
        if not script_content:
            QMessageBox.warning(self, "Warning", "No script to save. Generate a script first.")
            return

        # Determine file extension based on content/type
        script_type = self.script_type_combo.currentText()
        if "python" in script_content.lower() or script_type == "Exploit Strategy":
            ext = "py"
            filter_str = "Python Files (*.py);;All Files (*)"
        elif "javascript" in script_content.lower():
            ext = "js"
            filter_str = "JavaScript Files (*.js);;All Files (*)"
        elif "powershell" in script_content.lower():
            ext = "ps1"
            filter_str = "PowerShell Files (*.ps1);;All Files (*)"
        else:
            ext = "txt"
            filter_str = "Text Files (*.txt);;All Files (*)"

        default_name = f"{script_type.lower().replace(' ', '_')}_{int(time.time())}.{ext}"

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Script", default_name, filter_str,
        )

        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(script_content)
                self.status_label.setText(f"Script saved to {os.path.basename(file_path)}")
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in script_generator_dialog: %s", e)
                QMessageBox.critical(self, "Save Error", f"Failed to save script: {e!s}")

    def test_script(self):
        """Test the generated script (placeholder)."""
        QMessageBox.information(
            self, "Test Script",
            "Script testing functionality would be implemented here.\n\n"
            "This would include:\n"
            "• Syntax validation\n"
            "• Safe execution in sandbox\n"
            "• Effectiveness testing\n"
            "• Performance analysis",
        )

    def analyze_script(self):
        """Analyze the generated script for vulnerabilities, patterns, and improvements."""
        script_content = self.script_display.toPlainText()
        if not script_content:
            QMessageBox.warning(self, "Warning", "No script to analyze. Generate a script first.")
            return

        try:
            # Create AI tools instance
            ai_tools = AIAssistant()

            # Determine language based on script type or content
            script_type = self.script_type_combo.currentText()
            # Check if bypass_language exists and use it, otherwise detect from content
            if hasattr(self, "bypass_language") and self.bypass_language.isVisible():
                language = "javascript" if "javascript" in self.bypass_language.currentText().lower() else "python"
            # Auto-detect language from script type and content
            elif "frida" in script_type.lower() or "javascript" in script_type.lower():
                language = "javascript"
            elif "python" in script_type.lower() or "ghidra" in script_type.lower():
                language = "python"
            else:
                language = "auto"

            # Update status
            self.status_label.setText("Analyzing script...")

            # Perform analysis
            analysis_result = ai_tools.analyze_code(script_content, language)

            # Format and display results
            if analysis_result.get("status") == "success":
                formatted_analysis = self._format_analysis_results(analysis_result)

                # Create a new tab for analysis results
                analysis_display = QTextEdit()
                analysis_display.setFont(QFont("Consolas", 10))
                analysis_display.setReadOnly(True)
                analysis_display.setPlainText(formatted_analysis)

                # Add the analysis tab
                self.script_tabs.addTab(analysis_display, "Analysis Results")
                self.script_tabs.setCurrentWidget(analysis_display)

                self.status_label.setText("Script analysis completed")

                # Show warning if security issues found
                if analysis_result.get("security_issues"):
                    QMessageBox.warning(
                        self, "Security Issues",
                        f"Found {len(analysis_result['security_issues'])} security issue(s) in the script.\n"
                        "Please review the analysis results.",
                    )
            else:
                error_msg = analysis_result.get("error", "Unknown error occurred")
                QMessageBox.critical(self, "Analysis Error", f"Script analysis failed: {error_msg}")
                self.status_label.setText("Analysis failed")

        except Exception as e:
            logger.error(f"Script analysis error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to analyze script: {e!s}")
            self.status_label.setText("Error occurred")

    def _format_analysis_results(self, analysis_result):
        """Format code analysis results for display."""
        lines = ["Script Analysis Results", "=" * 50, ""]

        # Basic info
        lines.append(f"Language: {analysis_result.get('language', 'Unknown')}")
        lines.append(f"Lines of Code: {analysis_result.get('lines_of_code', 0)}")
        lines.append(f"Complexity: {analysis_result.get('complexity', 'Unknown')}")
        lines.append(f"AI Analysis: {'Enabled' if analysis_result.get('ai_enabled', False) else 'Disabled'}")
        lines.append("")

        # Insights
        insights = analysis_result.get("insights", [])
        if insights:
            lines.append("Insights:")
            for insight in insights:
                lines.append(f"  • {insight}")
            lines.append("")

        # Security Issues
        security_issues = analysis_result.get("security_issues", [])
        if security_issues:
            lines.append("SECURITY ISSUES:")
            for issue in security_issues:
                lines.append(f"  ⚠️  {issue}")
            lines.append("")

        # Suggestions
        suggestions = analysis_result.get("suggestions", [])
        if suggestions:
            lines.append("Suggestions:")
            for suggestion in suggestions:
                lines.append(f"  • {suggestion}")
            lines.append("")

        # Patterns
        patterns = analysis_result.get("patterns", [])
        if patterns:
            lines.append("Detected Patterns:")
            for pattern in patterns:
                lines.append(f"  • {pattern}")
            lines.append("")

        # Timestamp
        timestamp = analysis_result.get("analysis_timestamp", "")
        if timestamp:
            lines.append(f"\nAnalysis performed at: {timestamp}")

        return "\n".join(lines)

    def on_error(self, error_msg):
        """Handle worker thread errors."""
        QMessageBox.critical(self, "Error", f"Script generation failed: {error_msg}")
        self.status_label.setText("Error occurred")
        self.generate_btn.setEnabled(True)

    def closeEvent(self, event):
        """Handle dialog close event."""
        if self.worker and self.worker.isRunning():
            self.worker.wait()
        event.accept()


# Convenience function for main app integration
def show_script_generator_dialog(parent=None, binary_path: str = ""):
    """Show the script generator dialog."""
    dialog = ScriptGeneratorDialog(parent, binary_path)
    return dialog.exec()
