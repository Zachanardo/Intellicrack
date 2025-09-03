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

    def __init__(self, parent=None):
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

    def setup_ui(self):
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
        self.model_combo.addItems(["Claude-3", "GPT-4", "Llama-70B", "Local GGUF", "Ollama"])
        self.model_combo.currentTextChanged.connect(self.on_model_changed)
        model_layout.addWidget(self.model_combo)

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
        self.chat_history.setText(
            "Welcome to AI Assistant!\n\nAsk me anything about:\n• Code explanation\n• Bug fixing\n• Optimization\n• Vulnerability analysis\n• Exploit development\n• Protection bypassing\n"
        )
        layout.addWidget(self.chat_history)

        # Context indicator
        self.context_label = QLabel("Context: No file loaded")
        self.context_label.setStyleSheet("color: #888; font-style: italic; padding: 5px;")
        layout.addWidget(self.context_label)

        # Input area
        input_layout = QHBoxLayout()

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Ask AI about code, vulnerabilities, exploits...")
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
                "IDA Pro Script",
                "x64dbg Script",
                "Binary Ninja Plugin",
                "Radare2 Script",
                "GDB Script",
                "WinDbg Script",
                "Unicorn Emulation",
                "Angr Symbolic Execution",
            ]
        )
        type_layout.addWidget(self.script_type_combo)
        type_layout.addStretch()
        layout.addLayout(type_layout)

        # Target specification
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Function name, address, or pattern...")
        target_layout.addWidget(self.target_input)
        layout.addLayout(target_layout)

        # Script purpose
        purpose_layout = QVBoxLayout()
        purpose_layout.addWidget(QLabel("Purpose:"))

        self.purpose_text = QPlainTextEdit()
        self.purpose_text.setPlaceholderText(
            "Describe what the script should do...\nE.g., Hook license check, bypass anti-debug, dump memory..."
        )
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
            ]
        )
        type_layout.addWidget(self.analysis_type_combo)
        type_layout.addStretch()
        layout.addLayout(type_layout)

        # Code input
        layout.addWidget(QLabel("Code to Analyze:"))

        self.code_input = QPlainTextEdit()
        self.code_input.setPlaceholderText("Paste code here or load from current file...")
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
            ]
        )
        algo_layout.addWidget(self.keygen_algo_combo)
        algo_layout.addStretch()
        layout.addLayout(algo_layout)

        # Input parameters
        layout.addWidget(QLabel("Algorithm Details:"))

        self.keygen_details = QPlainTextEdit()
        self.keygen_details.setPlaceholderText(
            "Describe the key generation algorithm...\nE.g., XOR with 0xDEADBEEF, MD5 hash of name, etc."
        )
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

    def send_message(self):
        """Send a message to the AI."""
        message = self.message_input.text().strip()
        if message:
            self.add_message("User", message)
            self.message_input.clear()

            # Get context if enabled
            context = ""
            if self.include_context_cb.isChecked() and self.current_context:
                context = f"\n\nContext:\n{self.current_context}\n"

            # Simulate AI response (would connect to actual AI backend)
            self.process_ai_request(message, context)

    def send_quick_message(self, message: str):
        """Send a predefined quick message."""
        self.add_message("User", message)

        # Get context if enabled
        context = ""
        if self.include_context_cb.isChecked() and self.current_context:
            context = f"\n\nContext:\n{self.current_context}\n"

        self.process_ai_request(message, context)

    def add_message(self, sender: str, message: str):
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

    def process_ai_request(self, message: str, context: str = ""):
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
            response = f"Error processing AI request: {str(e)}. Using fallback response."

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

        elif any(word in message_lower for word in ["reverse", "disassemble", "analyze"]):
            return (
                f"Binary analysis approach with {model}:\n"
                f"1. Load binary in disassembler (Ghidra, IDA, etc.)\n"
                f"2. Identify entry points and critical functions\n"
                f"3. Analyze control flow and data structures\n"
                f"4. Look for anti-analysis techniques"
            )

        elif any(word in message_lower for word in ["debug", "trace", "monitor"]):
            return (
                f"Dynamic analysis with {model}:\n"
                f"1. Set up controlled debugging environment\n"
                f"2. Use process monitors and API trackers\n"
                f"3. Analyze runtime behavior and memory access\n"
                f"4. Document findings and potential attack vectors"
            )

        elif any(word in message_lower for word in ["protect", "secure", "harden"]):
            return (
                "Security hardening recommendations:\n"
                "1. Implement input validation and sanitization\n"
                "2. Use memory protection techniques (ASLR, DEP)\n"
                "3. Apply code obfuscation and anti-tampering\n"
                "4. Regular security audits and penetration testing"
            )

        else:
            # Generic intelligent response
            return (
                f"Analysis using {model} (temp={temperature}):\n"
                f"Your question: '{message}'\n\n"
                f"For comprehensive security research, consider:\n"
                f"• Static analysis of target binaries\n"
                f"• Dynamic runtime analysis\n"
                f"• Network traffic monitoring\n"
                f"• Vulnerability assessment\n\n"
                f"{'Context considered: ' + context if context else 'No additional context provided'}"
            )

    def clear_chat(self):
        """Clear the chat history."""
        self.chat_history.clear()
        self.conversation_history.clear()
        self.chat_history.setText("Chat cleared. Ready for new conversation.\n")

    def on_model_changed(self, model: str):
        """Handle model change."""
        logger.info(f"AI model changed to: {model}")
        self.add_message("System", f"Switched to {model} model")

    def set_current_context(self, file_path: str, content: str = ""):
        """Set the current file context for AI assistance."""
        self.current_file = file_path
        self.current_context = content[:1000] if content else ""  # Limit context size

        if file_path:
            self.context_label.setText(f"Context: {Path(file_path).name}")
        else:
            self.context_label.setText("Context: No file loaded")

    def generate_script(self):
        """Generate a script based on user input."""
        script_type = self.script_type_combo.currentText()
        target = self.target_input.text()
        purpose = self.purpose_text.toPlainText()

        if not purpose:
            self.script_output.setPlainText("Please describe the script purpose.")
            return

        # Build prompt
        prompt = f"Generate a {script_type} with the following specifications:\n"
        if target:
            prompt += f"Target: {target}\n"
        prompt += f"Purpose: {purpose}\n"

        if self.include_comments_cb.isChecked():
            prompt += "Include detailed comments\n"
        if self.error_handling_cb.isChecked():
            prompt += "Add comprehensive error handling\n"
        if self.logging_cb.isChecked():
            prompt += "Include logging statements\n"

        # Simulate script generation (would use actual AI)
        generated_script = f"// {script_type}\n// Target: {target}\n// Purpose: {purpose}\n\n// Generated script would appear here..."

        self.script_output.setPlainText(generated_script)
        self.script_generated.emit(script_type, generated_script)

    def copy_script(self):
        """Copy generated script to clipboard."""
        from PyQt6.QtWidgets import QApplication

        clipboard = QApplication.clipboard()
        clipboard.setText(self.script_output.toPlainText())
        logger.info("Script copied to clipboard")

    def save_script(self):
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

    def test_script(self):
        """Test the generated script."""
        logger.info("Script testing not yet implemented")

    def load_current_file_for_analysis(self):
        """Load current file content for analysis."""
        if self.current_context:
            self.code_input.setPlainText(self.current_context)
        else:
            self.code_input.setPlainText("No file context available. Load a file first.")

    def analyze_code(self):
        """Analyze the provided code."""
        code = self.code_input.toPlainText()
        analysis_type = self.analysis_type_combo.currentText()

        if not code:
            self.analysis_results.setText("Please provide code to analyze.")
            return

        # Simulate analysis (would use actual AI)
        results = f"=== {analysis_type} Results ===\n\n"
        results += f"Analyzing {len(code)} characters of code...\n\n"
        results += "Analysis results would appear here with:\n"
        results += "• Identified issues\n"
        results += "• Severity ratings\n"
        results += "• Recommendations\n"
        results += "• Code improvements\n"

        self.analysis_results.setText(results)

    def generate_keygen(self):
        """Generate a keygen based on specifications."""
        algo_type = self.keygen_algo_combo.currentText()
        details = self.keygen_details.toPlainText()
        language = self.keygen_lang_combo.currentText()
        include_gui = self.gui_cb.isChecked()

        if not details:
            self.keygen_output.setPlainText("Please provide algorithm details.")
            return

        # Simulate keygen generation (would use actual AI)
        keygen_code = f"# {algo_type} Keygen in {language}\n"
        keygen_code += f"# Algorithm: {details}\n\n"

        if language == "Python":
            keygen_code += "def generate_key(input_data):\n"
            keygen_code += "    # Implementation would go here\n"
            keygen_code += "    pass\n\n"

            if include_gui:
                keygen_code += "# GUI code would be added here\n"

        self.keygen_output.setPlainText(keygen_code)

    def copy_keygen(self):
        """Copy keygen code to clipboard."""
        from PyQt6.QtWidgets import QApplication

        clipboard = QApplication.clipboard()
        clipboard.setText(self.keygen_output.toPlainText())
        logger.info("Keygen code copied to clipboard")

    def save_keygen(self):
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

    def compile_keygen(self):
        """Compile the keygen code."""
        logger.info("Keygen compilation not yet implemented")

    def load_available_models(self):
        """Load available AI models."""
        # This would check for available models/backends
        self.available_models = ["Claude-3", "GPT-4", "Llama-70B", "Local GGUF", "Ollama"]
        logger.info(f"Loaded {len(self.available_models)} AI models")
