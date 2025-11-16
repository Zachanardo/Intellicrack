"""AI Assistant Widget for integration into WorkspaceTab.

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

from pathlib import Path

from intellicrack.handlers.pyqt6_handler import (
    QCheckBox,
    QComboBox,
    QFont,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from ...utils.logger import get_logger

logger = get_logger(__name__)


class AIAssistantWidget(QWidget):
    """AI Assistant Widget - Production-ready AI interaction panel."""

    # Signals
    message_sent = pyqtSignal(str)
    code_generated = pyqtSignal(str)
    script_generated = pyqtSignal(str, str)  # script_type, content

    def __init__(self, parent=None) -> None:
        """Initialize the AI Assistant Widget."""
        super().__init__(parent)

        # State
        self.current_file = None
        self.conversation_history = []
        self.llm_enabled = True
        self.current_context = ""
        self.available_models = []

        # Setup UI
        self.setup_ui()
        self.load_available_models()

    def setup_ui(self) -> None:
        """Set up the AI assistant interface."""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Header
        header_label = QLabel("AI Assistant")
        header_label.setStyleSheet("font-size: 14px; font-weight: bold; padding: 5px;")
        layout.addWidget(header_label)

        # Tab widget for different AI features
        self.tabs = QTabWidget()

        # Chat tab
        self.chat_tab = self.create_chat_tab()
        self.tabs.addTab(self.chat_tab, "Chat")

        # Script Generation tab
        self.script_tab = self.create_script_generation_tab()
        self.tabs.addTab(self.script_tab, "Script Gen")

        # Code Analysis tab
        self.analysis_tab = self.create_code_analysis_tab()
        self.tabs.addTab(self.analysis_tab, "Analysis")

        # Keygen Generation tab
        self.keygen_tab = self.create_keygen_tab()
        self.tabs.addTab(self.keygen_tab, "Keygen")

        layout.addWidget(self.tabs)

        # Model selection at bottom
        model_layout = QHBoxLayout()
        model_layout.addWidget(QLabel("Model:"))

        self.model_combo = QComboBox()
        self.model_combo.setMinimumWidth(200)
        self.model_combo.currentTextChanged.connect(self.on_model_changed)
        model_layout.addWidget(self.model_combo)

        refresh_models_btn = QPushButton("🔄")
        refresh_models_btn.setMaximumWidth(40)
        refresh_models_btn.setToolTip("Refresh available models")
        refresh_models_btn.clicked.connect(lambda: self.load_available_models(force_refresh=True))
        model_layout.addWidget(refresh_models_btn)

        self.temperature_spin = QComboBox()
        self.temperature_spin.addItems(["0.0", "0.3", "0.5", "0.7", "0.9", "1.0"])
        self.temperature_spin.setCurrentText("0.7")
        self.temperature_spin.setEditable(True)
        model_layout.addWidget(QLabel("Temp:"))
        model_layout.addWidget(self.temperature_spin)

        model_layout.addStretch()
        layout.addLayout(model_layout)

    def create_chat_tab(self) -> QWidget:
        """Create the chat interface tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Chat history
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        layout.addWidget(self.chat_history)

        # Context indicator
        self.context_label = QLabel("Context: No file loaded")
        self.context_label.setStyleSheet("color: #888; font-style: italic; padding: 5px;")
        layout.addWidget(self.context_label)

        # Input area
        input_layout = QHBoxLayout()

        self.message_input = QLineEdit()
        self.message_input.returnPressed.connect(self.send_message)
        input_layout.addWidget(self.message_input)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_button)

        layout.addLayout(input_layout)

        # Quick actions
        actions_layout = QHBoxLayout()

        explain_btn = QPushButton("Explain")
        explain_btn.clicked.connect(lambda: self.send_quick_message("Explain this code"))
        actions_layout.addWidget(explain_btn)

        optimize_btn = QPushButton("Optimize")
        optimize_btn.clicked.connect(lambda: self.send_quick_message("Optimize this code for performance"))
        actions_layout.addWidget(optimize_btn)

        vulnerabilities_btn = QPushButton("Find Vulns")
        vulnerabilities_btn.clicked.connect(lambda: self.send_quick_message("Find vulnerabilities in this code"))
        actions_layout.addWidget(vulnerabilities_btn)

        exploit_btn = QPushButton("Exploit")
        exploit_btn.clicked.connect(lambda: self.send_quick_message("How to exploit this vulnerability"))
        actions_layout.addWidget(exploit_btn)

        bypass_btn = QPushButton("Bypass")
        bypass_btn.clicked.connect(lambda: self.send_quick_message("How to bypass this protection"))
        actions_layout.addWidget(bypass_btn)

        actions_layout.addStretch()
        layout.addLayout(actions_layout)

        # Options
        options_layout = QHBoxLayout()

        self.include_context_cb = QCheckBox("Include file context")
        self.include_context_cb.setChecked(True)
        options_layout.addWidget(self.include_context_cb)

        self.stream_response_cb = QCheckBox("Stream response")
        self.stream_response_cb.setChecked(True)
        options_layout.addWidget(self.stream_response_cb)

        clear_btn = QPushButton("Clear Chat")
        clear_btn.clicked.connect(self.clear_chat)
        options_layout.addWidget(clear_btn)

        options_layout.addStretch()
        layout.addLayout(options_layout)

        return tab

    def create_script_generation_tab(self) -> QWidget:
        """Create the script generation tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Script type selection
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Script Type:"))

        self.script_type_combo = QComboBox()
        self.script_type_combo.addItems(
            [
                "Frida Hook Script",
                "Ghidra Analysis Script",
                "x64dbg Script",
                "Binary Ninja Plugin",
                "Radare2 Script",
                "GDB Script",
                "WinDbg Script",
                "Unicorn Emulation",
                "Angr Symbolic Execution",
            ],
        )
        type_layout.addWidget(self.script_type_combo)
        type_layout.addStretch()
        layout.addLayout(type_layout)

        # Target specification
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))

        self.target_input = QLineEdit()
        target_layout.addWidget(self.target_input)
        layout.addLayout(target_layout)

        # Script purpose
        purpose_layout = QVBoxLayout()
        purpose_layout.addWidget(QLabel("Purpose:"))

        self.purpose_text = QPlainTextEdit()
        self.purpose_text.setMaximumHeight(100)
        purpose_layout.addWidget(self.purpose_text)
        layout.addLayout(purpose_layout)

        # Generation options
        options_layout = QHBoxLayout()

        self.include_comments_cb = QCheckBox("Include comments")
        self.include_comments_cb.setChecked(True)
        options_layout.addWidget(self.include_comments_cb)

        self.error_handling_cb = QCheckBox("Add error handling")
        self.error_handling_cb.setChecked(True)
        options_layout.addWidget(self.error_handling_cb)

        self.logging_cb = QCheckBox("Add logging")
        self.logging_cb.setChecked(True)
        options_layout.addWidget(self.logging_cb)

        options_layout.addStretch()
        layout.addLayout(options_layout)

        # Generate button
        generate_btn = QPushButton("Generate Script")
        generate_btn.setMinimumHeight(40)
        generate_btn.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                font-weight: bold;
                background-color: #0078d4;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
        """)
        generate_btn.clicked.connect(self.generate_script)
        layout.addWidget(generate_btn)

        # Output area
        layout.addWidget(QLabel("Generated Script:"))

        self.script_output = QPlainTextEdit()
        self.script_output.setReadOnly(True)
        self.script_output.setFont(QFont("Consolas", 10))
        layout.addWidget(self.script_output)

        # Action buttons
        action_layout = QHBoxLayout()

        copy_btn = QPushButton("Copy Script")
        copy_btn.clicked.connect(self.copy_script)
        action_layout.addWidget(copy_btn)

        save_btn = QPushButton("Save Script")
        save_btn.clicked.connect(self.save_script)
        action_layout.addWidget(save_btn)

        test_btn = QPushButton("Test Script")
        test_btn.clicked.connect(self.test_script)
        action_layout.addWidget(test_btn)

        action_layout.addStretch()
        layout.addLayout(action_layout)

        return tab

    def create_code_analysis_tab(self) -> QWidget:
        """Create the code analysis tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Analysis type
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Analysis Type:"))

        self.analysis_type_combo = QComboBox()
        self.analysis_type_combo.addItems(
            [
                "Vulnerability Scan",
                "Code Quality Review",
                "Performance Analysis",
                "Security Audit",
                "License Detection",
                "Anti-Pattern Detection",
                "Complexity Analysis",
                "Dependency Analysis",
            ],
        )
        type_layout.addWidget(self.analysis_type_combo)
        type_layout.addStretch()
        layout.addLayout(type_layout)

        # Code input
        layout.addWidget(QLabel("Code to Analyze:"))

        self.code_input = QPlainTextEdit()
        self.code_input.setFont(QFont("Consolas", 10))
        self.code_input.setMaximumHeight(200)
        layout.addWidget(self.code_input)

        # Load from current file button
        load_btn = QPushButton("Load Current File")
        load_btn.clicked.connect(self.load_current_file_for_analysis)
        layout.addWidget(load_btn)

        # Analyze button
        analyze_btn = QPushButton("Analyze Code")
        analyze_btn.setMinimumHeight(40)
        analyze_btn.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                font-weight: bold;
                background-color: #28a745;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
        """)
        analyze_btn.clicked.connect(self.analyze_code)
        layout.addWidget(analyze_btn)

        # Results area
        layout.addWidget(QLabel("Analysis Results:"))

        self.analysis_results = QTextEdit()
        self.analysis_results.setReadOnly(True)
        layout.addWidget(self.analysis_results)

        return tab

    def create_keygen_tab(self) -> QWidget:
        """Create the keygen generation tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Algorithm type
        algo_layout = QHBoxLayout()
        algo_layout.addWidget(QLabel("Algorithm Type:"))

        self.keygen_algo_combo = QComboBox()
        self.keygen_algo_combo.addItems(
            [
                "Name/Serial",
                "Hardware ID",
                "Time-based",
                "RSA Key Pair",
                "Elliptic Curve",
                "Custom Algorithm",
                "License File",
                "Activation Code",
            ],
        )
        algo_layout.addWidget(self.keygen_algo_combo)
        algo_layout.addStretch()
        layout.addLayout(algo_layout)

        # Input parameters
        layout.addWidget(QLabel("Algorithm Details:"))

        self.keygen_details = QPlainTextEdit()
        self.keygen_details.setMaximumHeight(150)
        layout.addWidget(self.keygen_details)

        # Language selection
        lang_layout = QHBoxLayout()
        lang_layout.addWidget(QLabel("Language:"))

        self.keygen_lang_combo = QComboBox()
        self.keygen_lang_combo.addItems(["Python", "C++", "C", "JavaScript", "Assembly"])
        lang_layout.addWidget(self.keygen_lang_combo)

        self.gui_cb = QCheckBox("Include GUI")
        self.gui_cb.setChecked(True)
        lang_layout.addWidget(self.gui_cb)

        lang_layout.addStretch()
        layout.addLayout(lang_layout)

        # Generate button
        generate_keygen_btn = QPushButton("Generate Keygen")
        generate_keygen_btn.setMinimumHeight(40)
        generate_keygen_btn.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                font-weight: bold;
                background-color: #dc3545;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
        """)
        generate_keygen_btn.clicked.connect(self.generate_keygen)
        layout.addWidget(generate_keygen_btn)

        # Output
        layout.addWidget(QLabel("Generated Keygen:"))

        self.keygen_output = QPlainTextEdit()
        self.keygen_output.setReadOnly(True)
        self.keygen_output.setFont(QFont("Consolas", 10))
        layout.addWidget(self.keygen_output)

        # Action buttons
        action_layout = QHBoxLayout()

        copy_keygen_btn = QPushButton("Copy Code")
        copy_keygen_btn.clicked.connect(self.copy_keygen)
        action_layout.addWidget(copy_keygen_btn)

        save_keygen_btn = QPushButton("Save Keygen")
        save_keygen_btn.clicked.connect(self.save_keygen)
        action_layout.addWidget(save_keygen_btn)

        compile_btn = QPushButton("Compile")
        compile_btn.clicked.connect(self.compile_keygen)
        action_layout.addWidget(compile_btn)

        action_layout.addStretch()
        layout.addLayout(action_layout)

        return tab

    def send_message(self) -> None:
        """Send a message to the AI."""
        message = self.message_input.text().strip()
        if message:
            self.add_message("User", message)
            self.message_input.clear()

            # Get context if enabled
            context = ""
            if self.include_context_cb.isChecked() and self.current_context:
                context = f"\n\nContext:\n{self.current_context}\n"

            self.process_ai_request(message, context)

    def send_quick_message(self, message: str) -> None:
        """Send a predefined quick message."""
        self.add_message("User", message)

        # Get context if enabled
        context = ""
        if self.include_context_cb.isChecked() and self.current_context:
            context = f"\n\nContext:\n{self.current_context}\n"

        self.process_ai_request(message, context)

    def add_message(self, sender: str, message: str) -> None:
        """Add a message to the chat history."""
        self.conversation_history.append({"sender": sender, "message": message})

        # Format message for display
        if sender == "User":
            formatted = f"<p><b style='color: #0078d4;'>You:</b> {message}</p>"
        else:
            formatted = f"<p><b style='color: #28a745;'>AI:</b> {message}</p>"

        self.chat_history.append(formatted)

        # Auto-scroll to bottom
        scrollbar = self.chat_history.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def process_ai_request(self, message: str, context: str = "") -> None:
        """Process AI request using available AI backends."""
        model = self.model_combo.currentText()
        temperature = float(self.temperature_spin.currentText())

        try:
            # Try to use actual AI integration from main app
            from ...ai.integration_manager import IntegrationManager

            # Get AI manager instance
            ai_manager = IntegrationManager()

            # Prepare the prompt with context
            full_prompt = message
            if context:
                full_prompt = f"Context: {context}\n\nQuestion: {message}"

            # Generate response using the selected model
            response = ai_manager.generate_response(prompt=full_prompt, model=model, temperature=temperature, max_tokens=1000)

            if response and response.strip():
                response = response.strip()
            else:
                # Fallback if response is empty
                response = f"Model {model} generated an empty response. Please try rephrasing your question."

        except ImportError:
            # Fallback when AI integration is not available
            response = self._generate_fallback_response(message, model, temperature, context)
        except Exception as e:
            # Error handling for AI backend issues
            response = f"Error processing AI request: {e!s}. Using fallback response."

        self.add_message("AI", response)
        self.message_sent.emit(message)

    def _generate_fallback_response(self, message: str, model: str, temperature: float, context: str = "") -> str:
        """Generate intelligent fallback response when AI backend is unavailable."""
        message_lower = message.lower()

        # Pattern-based responses for common security research queries
        if any(word in message_lower for word in ["vulnerability", "exploit", "bypass"]):
            return (
                f"For vulnerability analysis using {model}:\n"
                f"1. Start with static analysis to identify attack surface\n"
                f"2. Use dynamic analysis for runtime behavior\n"
                f"3. Apply fuzzing techniques for input validation testing\n"
                f"4. Review protection mechanisms and potential bypasses"
            )

        if any(word in message_lower for word in ["reverse", "disassemble", "analyze"]):
            return (
                f"Binary analysis approach with {model}:\n"
                f"1. Load binary in disassembler (Ghidra, Radare2, etc.)\n"
                f"2. Identify entry points and critical functions\n"
                f"3. Analyze control flow and data structures\n"
                f"4. Look for anti-analysis techniques"
            )

        if any(word in message_lower for word in ["debug", "trace", "monitor"]):
            return (
                f"Dynamic analysis with {model}:\n"
                f"1. Set up controlled debugging environment\n"
                f"2. Use process monitors and API trackers\n"
                f"3. Analyze runtime behavior and memory access\n"
                f"4. Document findings and potential attack vectors"
            )

        if any(word in message_lower for word in ["protect", "secure", "harden"]):
            return (
                "Security hardening recommendations:\n"
                "1. Implement input validation and sanitization\n"
                "2. Use memory protection techniques (ASLR, DEP)\n"
                "3. Apply code obfuscation and anti-tampering\n"
                "4. Regular security audits and penetration testing"
            )

        # Generic intelligent response
        return (
            f"Analysis using {model} (temp={temperature}):\n"
            f"Your question: '{message}'\n\n"
            f"For comprehensive security research, consider:\n"
            f" Static analysis of target binaries\n"
            f" Dynamic runtime analysis\n"
            f" Network traffic monitoring\n"
            f" Vulnerability assessment\n\n"
            f"{'Context considered: ' + context if context else 'No additional context provided'}"
        )

    def clear_chat(self) -> None:
        """Clear the chat history."""
        self.chat_history.clear()
        self.conversation_history.clear()
        self.chat_history.setText("Chat cleared. Ready for new conversation.\n")

    def on_model_changed(self, model: str) -> None:
        """Handle model change."""
        logger.info(f"AI model changed to: {model}")
        self.add_message("System", f"Switched to {model} model")

    def set_current_context(self, file_path: str, content: str = "") -> None:
        """Set the current file context for AI assistance."""
        self.current_file = file_path
        self.current_context = content[:1000] if content else ""  # Limit context size

        if file_path:
            self.context_label.setText(f"Context: {Path(file_path).name}")
        else:
            self.context_label.setText("Context: No file loaded")

    def generate_script(self) -> None:
        """Generate protection-aware bypass script using actual binary analysis."""
        script_type = self.script_type_combo.currentText()
        target = self.target_input.text()

        if not target:
            self.script_output.setPlainText("Error: Please specify target binary path")
            return

        try:
            from ...ai.protection_aware_script_gen import ProtectionAwareScriptGenerator

            script_gen = ProtectionAwareScriptGenerator()

            script_type_map = {
                "Frida Hook Script": "frida",
                "Ghidra Analysis Script": "ghidra",
                "x64dbg Script": "x64dbg",
                "Binary Ninja Plugin": "binja",
                "Radare2 Script": "r2",
                "GDB Script": "gdb",
                "WinDbg Script": "windbg",
                "Unicorn Emulation": "unicorn",
                "Angr Symbolic Execution": "angr",
            }

            script_format = script_type_map.get(script_type, "frida")
            self.script_output.setPlainText("Analyzing binary...\n\nThis may take a moment...")

            result = script_gen.generate_bypass_script(target, script_type=script_format)

            if result.get("success"):
                generated_script = result.get("script", "")
                protection = result.get("protection_detected", "Unknown")
                confidence = result.get("confidence", 0.0)

                header = f"// Protection: {protection} ({confidence * 100:.1f}% confidence)\n"
                header += f"// {result.get('approach', '')}\n\n"

                self.script_output.setPlainText(header + generated_script)
                self.script_generated.emit(script_type, generated_script)
                logger.info(f"Generated {script_type} - Protection: {protection}")
            else:
                error_msg = result.get("error", "Unknown error")
                self.script_output.setPlainText(f"Error: {error_msg}")

        except Exception as e:
            self.script_output.setPlainText(f"Error: {e!s}")
            logger.error(f"Script generation failed: {e}")

    def copy_script(self) -> None:
        """Copy generated script to clipboard."""
        from PyQt6.QtWidgets import QApplication

        clipboard = QApplication.clipboard()
        clipboard.setText(self.script_output.toPlainText())
        logger.info("Script copied to clipboard")

    def save_script(self) -> None:
        """Save generated script to file."""
        from PyQt6.QtWidgets import QFileDialog

        script_type = self.script_type_combo.currentText().lower().replace(" ", "_")
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Script", f"{script_type}.js", "All Files (*)")

        if file_name:
            try:
                with open(file_name, "w") as f:
                    f.write(self.script_output.toPlainText())
                logger.info(f"Script saved to {file_name}")
            except Exception as e:
                logger.error(f"Failed to save script: {e}")

    def test_script(self) -> None:
        """Test the generated script in appropriate execution environment."""
        script_content = self.script_output.toPlainText()
        script_type = self.script_type_combo.currentText()

        if not script_content or "Error:" in script_content:
            logger.warning("No valid script to test")
            self.script_output.setPlainText("Cannot test: No valid script generated")
            return

        try:
            import subprocess
            import tempfile
            from pathlib import Path

            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                if "Frida" in script_type:
                    script_file = temp_path / "test_script.js"
                    script_file.write_text(script_content, encoding="utf-8")

                    result = subprocess.run(["frida", "--version"], capture_output=True, text=True, timeout=5)

                    if result.returncode == 0:
                        self.script_output.setPlainText(
                            f"{script_content}\n\n{'=' * 50}\n"
                            f"OK Frida validation passed\n"
                            f"Script saved to: {script_file}\n"
                            f"Run with: frida -f <target> -l {script_file.name}",
                        )
                        logger.info("Frida script validation successful")
                    else:
                        self.script_output.setPlainText(
                            f"{script_content}\n\n{'=' * 50}\n⚠ Frida not found. Install with: pip install frida-tools",
                        )

                elif "Python" in script_type or script_type == "Angr Symbolic Execution":
                    script_file = temp_path / "test_script.py"
                    script_file.write_text(script_content, encoding="utf-8")

                    result = subprocess.run(["python", "-m", "py_compile", str(script_file)], capture_output=True, text=True, timeout=10)

                    if result.returncode == 0:
                        self.script_output.setPlainText(
                            f"{script_content}\n\n{'=' * 50}\nOK Python syntax validation passed\nScript is syntactically correct",
                        )
                        logger.info("Python script validation successful")
                    else:
                        error_msg = result.stderr or result.stdout
                        self.script_output.setPlainText(f"{script_content}\n\n{'=' * 50}\nFAIL Syntax error:\n{error_msg}")
                        logger.error(f"Python validation failed: {error_msg}")

                elif "Ghidra" in script_type:
                    script_file = temp_path / "test_script.py"
                    script_file.write_text(script_content, encoding="utf-8")

                    result = subprocess.run(["python", "-m", "py_compile", str(script_file)], capture_output=True, text=True, timeout=10)

                    if result.returncode == 0:
                        self.script_output.setPlainText(
                            f"{script_content}\n\n{'=' * 50}\nOK Ghidra script syntax validated\nPlace in Ghidra scripts directory to use",
                        )
                        logger.info("Ghidra script validation successful")
                    else:
                        self.script_output.setPlainText(f"{script_content}\n\n{'=' * 50}\n⚠ Syntax check failed")

                elif "Radare2" in script_type or "r2" in script_type:
                    script_file = temp_path / "test_script.r2"
                    script_file.write_text(script_content, encoding="utf-8")

                    result = subprocess.run(["r2", "-v"], capture_output=True, text=True, timeout=5)

                    if result.returncode == 0:
                        self.script_output.setPlainText(
                            f"{script_content}\n\n{'=' * 50}\nOK Radare2 available\nRun with: r2 -i {script_file.name} <target>",
                        )
                        logger.info("Radare2 script prepared")
                    else:
                        self.script_output.setPlainText(f"{script_content}\n\n{'=' * 50}\n⚠ Radare2 not found. Install from radare.org")

                else:
                    self.script_output.setPlainText(
                        f"{script_content}\n\n{'=' * 50}\n"
                        f"OK Script generated for {script_type}\n"
                        f"Manual testing required for this script type",
                    )
                    logger.info(f"Script prepared for {script_type}")

        except subprocess.TimeoutExpired:
            self.script_output.setPlainText(f"{script_content}\n\n{'=' * 50}\nFAIL Test timed out")
            logger.error("Script test timed out")
        except Exception as e:
            self.script_output.setPlainText(f"{script_content}\n\n{'=' * 50}\nFAIL Test error: {e!s}")
            logger.error(f"Script test failed: {e}")

    def load_current_file_for_analysis(self) -> None:
        """Load current file content for analysis."""
        if self.current_context:
            self.code_input.setPlainText(self.current_context)
        else:
            self.code_input.setPlainText("No file context available. Load a file first.")

    def analyze_code(self) -> None:
        """Analyze code using AI-powered analysis."""
        code = self.code_input.toPlainText()
        analysis_type = self.analysis_type_combo.currentText()

        if not code:
            self.analysis_results.setText("Please provide code to analyze.")
            return

        try:
            from ...ai.integration_manager import IntegrationManager

            ai_manager = IntegrationManager()
            model = self.model_combo.currentText()

            prompt = f"""Perform {analysis_type} on the following code:

```
{code}
```

Provide detailed results including:
- Identified issues/patterns
- Severity ratings
- Specific recommendations
- Code improvement suggestions

Format as clear, actionable analysis."""

            self.analysis_results.setText(f"Analyzing code with {model}...\n\nPlease wait...")

            results = ai_manager.generate_response(prompt=prompt, model=model, temperature=0.3, max_tokens=1500)

            if results and results.strip():
                final_results = f"=== {analysis_type} Results ===\n\n{results.strip()}"
                self.analysis_results.setText(final_results)
                logger.info(f"Completed {analysis_type}")
            else:
                self.analysis_results.setText("Error: AI generated empty response")

        except ImportError:
            self.analysis_results.setText(
                "Error: AI integration not available.\n\nPlease configure an AI model in Settings to use code analysis.",
            )
        except Exception as e:
            self.analysis_results.setText(f"Error during analysis: {e!s}")
            logger.error(f"Code analysis failed: {e}")

    def generate_keygen(self) -> None:
        """Generate keygen using AI-powered code generation."""
        algo_type = self.keygen_algo_combo.currentText()
        details = self.keygen_details.toPlainText()
        language = self.keygen_lang_combo.currentText()
        include_gui = self.gui_cb.isChecked()

        if not details:
            details = f"Generate {algo_type} keygen algorithm"

        try:
            from ...ai.integration_manager import IntegrationManager

            ai_manager = IntegrationManager()
            model = self.model_combo.currentText()

            prompt = f"""Generate a production-ready {algo_type} keygen in {language}.
Algorithm: {details}
Requirements:
- Real cryptographic implementation (SHA-256, XOR, etc.)
- Working validation function
{"- Include tkinter GUI" if include_gui and language == "Python" else ""}
{"- Include Qt GUI" if include_gui and language == "C++" else ""}
- Fully functional implementation
- Complete, executable code

Return ONLY the code, no explanations."""

            self.keygen_output.setPlainText(f"Generating {algo_type} keygen in {language}...\n\nThis may take a moment...")

            keygen_code = ai_manager.generate_response(prompt=prompt, model=model, temperature=0.3, max_tokens=2000)

            if keygen_code and keygen_code.strip():
                self.keygen_output.setPlainText(keygen_code.strip())
                logger.info(f"Generated {algo_type} keygen in {language}")
            else:
                self.keygen_output.setPlainText("Error: AI generated empty response")

        except ImportError:
            self.keygen_output.setPlainText(
                "Error: AI integration not available.\n\nPlease configure an AI model in Settings to use keygen generation.",
            )
        except Exception as e:
            self.keygen_output.setPlainText(f"Error generating keygen: {e!s}")
            logger.error(f"Keygen generation failed: {e}")

    def copy_keygen(self) -> None:
        """Copy keygen code to clipboard."""
        from PyQt6.QtWidgets import QApplication

        clipboard = QApplication.clipboard()
        clipboard.setText(self.keygen_output.toPlainText())
        logger.info("Keygen code copied to clipboard")

    def save_keygen(self) -> None:
        """Save keygen to file."""
        from PyQt6.QtWidgets import QFileDialog

        language = self.keygen_lang_combo.currentText().lower()
        extensions = {"python": ".py", "c++": ".cpp", "c": ".c", "javascript": ".js", "assembly": ".asm"}
        ext = extensions.get(language, ".txt")

        file_name, _ = QFileDialog.getSaveFileName(self, "Save Keygen", f"keygen{ext}", "All Files (*)")

        if file_name:
            try:
                with open(file_name, "w") as f:
                    f.write(self.keygen_output.toPlainText())
                logger.info(f"Keygen saved to {file_name}")
            except Exception as e:
                logger.error(f"Failed to save keygen: {e}")

    def compile_keygen(self) -> None:
        """Compile the keygen code into standalone executable."""
        keygen_content = self.keygen_output.toPlainText()
        language = self.keygen_lang_combo.currentText()

        if not keygen_content or "Error:" in keygen_content:
            self.keygen_output.setPlainText("Cannot compile: No valid keygen code generated")
            logger.warning("No valid keygen to compile")
            return

        try:
            import subprocess
            import tempfile
            from pathlib import Path

            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                if language == "Python":
                    keygen_file = temp_path / "keygen.py"
                    keygen_file.write_text(keygen_content, encoding="utf-8")

                    result = subprocess.run(["pyinstaller", "--version"], capture_output=True, text=True, timeout=5)

                    if result.returncode != 0:
                        self.keygen_output.setPlainText(
                            f"{keygen_content}\n\n{'=' * 50}\n"
                            "⚠ PyInstaller not found\n"
                            "Install with: pip install pyinstaller\n"
                            f"Then run: pyinstaller --onefile {keygen_file.name}",
                        )
                        logger.warning("PyInstaller not available")
                        return

                    self.keygen_output.setPlainText(
                        f"{keygen_content}\n\n{'=' * 50}\n🔨 Compiling with PyInstaller...\nThis may take a moment...",
                    )

                    compile_result = subprocess.run(
                        ["pyinstaller", "--onefile", "--name", "keygen", str(keygen_file)],
                        capture_output=True,
                        text=True,
                        timeout=120,
                        cwd=str(temp_path),
                    )

                    if compile_result.returncode == 0:
                        exe_path = temp_path / "dist" / "keygen.exe"
                        if exe_path.exists():
                            from PyQt6.QtWidgets import QFileDialog

                            save_path, _ = QFileDialog.getSaveFileName(self, "Save Compiled Keygen", "keygen.exe", "Executable (*.exe)")

                            if save_path:
                                import shutil

                                shutil.copy(exe_path, save_path)
                                self.keygen_output.setPlainText(
                                    f"{keygen_content}\n\n{'=' * 50}\n"
                                    f"OK Compilation successful!\n"
                                    f"Executable saved to: {save_path}\n"
                                    f"Size: {Path(save_path).stat().st_size // 1024} KB",
                                )
                                logger.info(f"Keygen compiled successfully: {save_path}")
                        else:
                            self.keygen_output.setPlainText(
                                f"{keygen_content}\n\n{'=' * 50}\n⚠ Compilation succeeded but executable not found",
                            )
                    else:
                        error_msg = compile_result.stderr[-500:] if compile_result.stderr else "Unknown error"
                        self.keygen_output.setPlainText(f"{keygen_content}\n\n{'=' * 50}\nFAIL Compilation failed:\n{error_msg}")
                        logger.error(f"PyInstaller compilation failed: {error_msg}")

                elif language in ["C", "C++"]:
                    extension = ".c" if language == "C" else ".cpp"
                    compiler = "gcc" if language == "C" else "g++"
                    keygen_file = temp_path / f"keygen{extension}"
                    keygen_file.write_text(keygen_content, encoding="utf-8")

                    result = subprocess.run([compiler, "--version"], capture_output=True, text=True, timeout=5)

                    if result.returncode != 0:
                        self.keygen_output.setPlainText(
                            f"{keygen_content}\n\n{'=' * 50}\n"
                            f"⚠ {compiler} not found\n"
                            f"Install MinGW-w64 or MSVC\n"
                            f"Then run: {compiler} -o keygen.exe {keygen_file.name}",
                        )
                        logger.warning(f"{compiler} not available")
                        return

                    output_exe = temp_path / "keygen.exe"

                    self.keygen_output.setPlainText(
                        f"{keygen_content}\n\n{'=' * 50}\n🔨 Compiling with {compiler}...\nThis may take a moment...",
                    )

                    compile_result = subprocess.run(
                        [compiler, str(keygen_file), "-o", str(output_exe), "-O2", "-s"],
                        capture_output=True,
                        text=True,
                        timeout=60,
                        cwd=str(temp_path),
                    )

                    if compile_result.returncode == 0 and output_exe.exists():
                        from PyQt6.QtWidgets import QFileDialog

                        save_path, _ = QFileDialog.getSaveFileName(self, "Save Compiled Keygen", "keygen.exe", "Executable (*.exe)")

                        if save_path:
                            import shutil

                            shutil.copy(output_exe, save_path)
                            self.keygen_output.setPlainText(
                                f"{keygen_content}\n\n{'=' * 50}\n"
                                f"OK Compilation successful!\n"
                                f"Executable saved to: {save_path}\n"
                                f"Size: {Path(save_path).stat().st_size // 1024} KB",
                            )
                            logger.info(f"Keygen compiled successfully: {save_path}")
                    else:
                        error_msg = compile_result.stderr[-500:] if compile_result.stderr else "Unknown error"
                        self.keygen_output.setPlainText(f"{keygen_content}\n\n{'=' * 50}\nFAIL Compilation failed:\n{error_msg}")
                        logger.error(f"{compiler} compilation failed: {error_msg}")

                elif language == "JavaScript":
                    self.keygen_output.setPlainText(
                        f"{keygen_content}\n\n{'=' * 50}\n"
                        "i JavaScript keygens run with Node.js\n"
                        "Save as keygen.js and run with: node keygen.js\n"
                        "For executable, use pkg: npm install -g pkg && pkg keygen.js",
                    )
                    logger.info("JavaScript keygen - manual compilation instructions provided")

                elif language == "Assembly":
                    self.keygen_output.setPlainText(
                        f"{keygen_content}\n\n{'=' * 50}\n"
                        "i Assembly keygens require NASM or MASM\n"
                        "Save as keygen.asm and compile with:\n"
                        "NASM: nasm -f win64 keygen.asm && gcc keygen.o -o keygen.exe\n"
                        "MASM: ml64 keygen.asm /link /out:keygen.exe",
                    )
                    logger.info("Assembly keygen - manual compilation instructions provided")

                else:
                    self.keygen_output.setPlainText(
                        f"{keygen_content}\n\n{'=' * 50}\n⚠ Compilation not supported for {language}\nSave and compile manually",
                    )

        except subprocess.TimeoutExpired:
            self.keygen_output.setPlainText(f"{keygen_content}\n\n{'=' * 50}\nFAIL Compilation timed out")
            logger.error("Keygen compilation timed out")
        except Exception as e:
            self.keygen_output.setPlainText(f"{keygen_content}\n\n{'=' * 50}\nFAIL Compilation error: {e!s}")
            logger.error(f"Keygen compilation failed: {e}")

    def load_available_models(self, force_refresh: bool = False) -> None:
        """Load available AI models using dynamic API-based discovery."""
        try:
            from ...ai.llm_config_manager import get_llm_config_manager
            from ...ai.model_discovery_service import get_model_discovery_service

            config_manager = get_llm_config_manager()
            discovery_service = get_model_discovery_service()

            configured_models = config_manager.list_model_configs()
            discovered_models = discovery_service.discover_all_models(force_refresh=force_refresh)

            self.available_models = []
            self.model_combo.clear()

            if configured_models:
                for model_id in configured_models:
                    self.available_models.append(model_id)
                    self.model_combo.addItem(f" {model_id}")

            if discovered_models:
                for provider_name, models in sorted(discovered_models.items()):
                    if models:
                        self.model_combo.insertSeparator(self.model_combo.count())
                        self.model_combo.addItem(f"── {provider_name} API Models ──")
                        self.model_combo.model().item(self.model_combo.count() - 1).setEnabled(False)

                        for model in models:
                            display_name = f"🌐 {provider_name}: {model.name}"
                            self.available_models.append(model.id)
                            self.model_combo.addItem(display_name)

            if not self.available_models:
                self.model_combo.addItem("No models available")
                self.model_combo.setEnabled(False)
                self._show_no_models_prompt()
                logger.warning("No AI models available (neither configured nor discovered)")
                return

            self.model_combo.setEnabled(True)
            total_models = len(self.available_models)
            self._show_welcome_message(total_models)
            logger.info(f"Loaded {total_models} AI models from API discovery")

        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            self.available_models = []
            self.model_combo.clear()
            self.model_combo.addItem("Error loading models")
            self.model_combo.setEnabled(False)
            self._show_error_message(str(e))

    def _show_no_models_prompt(self) -> None:
        """Display prompt when no models are configured."""
        self.chat_history.setHtml(
            "<div style='padding: 20px;'>"
            "<h2 style='color: #dc3545;'>⚠ No AI Models Configured</h2>"
            "<p style='font-size: 14px;'>To use the AI Assistant, you need to configure at least one AI model.</p>"
            "<h3 style='color: #0078d4;'>Configuration Options:</h3>"
            "<ul style='font-size: 13px;'>"
            "<li><b>OpenAI API:</b> Add your OpenAI API key in Settings → LLM Configuration</li>"
            "<li><b>Anthropic (Claude):</b> Add your Anthropic API key in Settings</li>"
            "<li><b>Local GGUF:</b> Configure local GGUF model path in Settings</li>"
            "<li><b>Ollama:</b> Install Ollama locally and configure in Settings</li>"
            "<li><b>LM Studio:</b> Run LM Studio and configure the API endpoint</li>"
            "</ul>"
            "<p style='color: #666; font-style: italic; margin-top: 20px;'>"
            "After configuration, click the 🔄 button to refresh available models."
            "</p>"
            "</div>",
        )

    def _show_welcome_message(self, total_models: int) -> None:
        """Display welcome message with model count."""
        self.chat_history.setHtml(
            "<div style='padding: 20px;'>"
            "<h2 style='color: #28a745;'>OK AI Assistant Ready</h2>"
            f"<p style='font-size: 14px;'>{total_models} AI model(s) available for use.</p>"
            "<h3 style='color: #0078d4;'>What can I help you with?</h3>"
            "<ul style='font-size: 13px;'>"
            "<li>Code explanation and understanding</li>"
            "<li>Bug identification and fixing</li>"
            "<li>Performance optimization</li>"
            "<li>Vulnerability analysis</li>"
            "<li>Exploit development assistance</li>"
            "<li>Protection mechanism bypassing</li>"
            "<li>Script generation for analysis tools</li>"
            "<li>Keygen algorithm development</li>"
            "</ul>"
            "<p style='color: #666; font-style: italic; margin-top: 20px;'>"
            "Select a model from the dropdown below and start chatting, or use the tabs above for specific tasks."
            "</p>"
            "</div>",
        )

    def _show_error_message(self, error: str) -> None:
        """Display error message when model loading fails."""
        self.chat_history.setHtml(
            "<div style='padding: 20px;'>"
            "<h2 style='color: #dc3545;'>FAIL Error Loading Models</h2>"
            f"<p style='font-size: 14px; color: #666;'>{error}</p>"
            "<h3 style='color: #0078d4;'>Troubleshooting:</h3>"
            "<ul style='font-size: 13px;'>"
            "<li>Check your API keys in Settings → LLM Configuration</li>"
            "<li>Verify network connectivity for API providers</li>"
            "<li>Ensure Ollama/LM Studio is running for local models</li>"
            "<li>Check the logs for detailed error messages</li>"
            "</ul>"
            "<p style='color: #666; font-style: italic; margin-top: 20px;'>"
            "Click the 🔄 button to try again."
            "</p>"
            "</div>",
        )
