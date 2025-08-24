"""AI Assistant Tab for Intellicrack GUI.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from intellicrack.ai.ai_assistant_enhanced import IntellicrackAIAssistant
from intellicrack.handlers.pyqt6_handler import (
    QApplication,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSplitter,
    Qt,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)


class AIAssistantTab(QWidget):
    """AI Assistant tab providing AI-powered analysis and script generation."""

    def __init__(self, shared_context=None, parent=None):
        """Initialize the AI Assistant tab."""
        super().__init__(parent)
        self.shared_context = shared_context
        self.ai_assistant = None
        self.init_ui()
        self.setup_ai_assistant()

    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()

        # Model selection
        model_group = QGroupBox("AI Model Configuration")
        model_layout = QVBoxLayout()

        # Model selector
        model_selector_layout = QHBoxLayout()
        model_selector_layout.addWidget(QLabel("Model:"))

        self.model_combo = QComboBox()
        self.model_combo.addItems(
            ["GPT-4", "Claude-3", "Gemini Pro", "Llama 3", "CodeLlama", "Mixtral", "Local Model"]
        )
        model_selector_layout.addWidget(self.model_combo)

        self.configure_btn = QPushButton("Configure")
        self.configure_btn.clicked.connect(self.configure_model)
        model_selector_layout.addWidget(self.configure_btn)

        model_layout.addLayout(model_selector_layout)
        model_group.setLayout(model_layout)
        layout.addWidget(model_group)

        # Main content area
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Input area
        input_group = QGroupBox("Input")
        input_layout = QVBoxLayout()

        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter your query or paste code/binary analysis here...")
        input_layout.addWidget(self.input_text)

        # Action buttons
        button_layout = QHBoxLayout()

        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.clicked.connect(self.perform_analysis)
        button_layout.addWidget(self.analyze_btn)

        self.generate_script_btn = QPushButton("Generate Script")
        self.generate_script_btn.clicked.connect(self.generate_script)
        button_layout.addWidget(self.generate_script_btn)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_all)
        button_layout.addWidget(self.clear_btn)

        input_layout.addLayout(button_layout)
        input_group.setLayout(input_layout)
        splitter.addWidget(input_group)

        # Output area
        output_group = QGroupBox("AI Response")
        output_layout = QVBoxLayout()

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)

        # Export buttons
        export_layout = QHBoxLayout()

        self.export_script_btn = QPushButton("Export Script")
        self.export_script_btn.clicked.connect(self.export_script)
        self.export_script_btn.setEnabled(False)
        export_layout.addWidget(self.export_script_btn)

        self.copy_btn = QPushButton("Copy to Clipboard")
        self.copy_btn.clicked.connect(self.copy_to_clipboard)
        export_layout.addWidget(self.copy_btn)

        output_layout.addLayout(export_layout)
        output_group.setLayout(output_layout)
        splitter.addWidget(output_group)

        layout.addWidget(splitter)

        # Status bar
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def setup_ai_assistant(self):
        """Initialize the AI assistant."""
        try:
            self.ai_assistant = IntellicrackAIAssistant()
            self.status_label.setText("AI Assistant initialized")
            logger.info("AI Assistant initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize AI Assistant: {e}")
            self.status_label.setText(f"Error: {e}")

    def configure_model(self):
        """Configure the selected AI model."""
        model = self.model_combo.currentText()

        # Configuration dialog would go here
        QMessageBox.information(
            self,
            "Model Configuration",
            f"Configuration for {model} model.\n\n"
            "API keys and model parameters can be set in Settings.",
        )

        logger.info(f"Configuring model: {model}")

    def perform_analysis(self):
        """Perform AI-powered analysis on input."""
        input_text = self.input_text.toPlainText()

        if not input_text:
            QMessageBox.warning(self, "Warning", "Please enter some input to analyze")
            return

        self.status_label.setText("Analyzing...")
        self.analyze_btn.setEnabled(False)

        try:
            if self.ai_assistant:
                # Perform analysis
                result = self.ai_assistant.analyze(input_text)
                self.output_text.setPlainText(result)
                self.status_label.setText("Analysis complete")
                self.export_script_btn.setEnabled(True)
            else:
                self.output_text.setPlainText(
                    "AI Assistant not initialized. Please check settings."
                )
                self.status_label.setText("Error: AI Assistant not available")
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            self.output_text.setPlainText(f"Analysis failed: {str(e)}")
            self.status_label.setText("Analysis failed")
        finally:
            self.analyze_btn.setEnabled(True)

    def generate_script(self):
        """Generate script based on input."""
        input_text = self.input_text.toPlainText()

        if not input_text:
            QMessageBox.warning(self, "Warning", "Please enter requirements for script generation")
            return

        self.status_label.setText("Generating script...")
        self.generate_script_btn.setEnabled(False)

        try:
            if self.ai_assistant:
                # Generate script
                script = self.ai_assistant.generate_script(
                    input_text,
                    script_type="frida",  # Default to Frida
                )
                self.output_text.setPlainText(script)
                self.status_label.setText("Script generated")
                self.export_script_btn.setEnabled(True)
            else:
                self.output_text.setPlainText(
                    "AI Assistant not initialized. Please check settings."
                )
                self.status_label.setText("Error: AI Assistant not available")
        except Exception as e:
            logger.error(f"Script generation failed: {e}")
            self.output_text.setPlainText(f"Script generation failed: {str(e)}")
            self.status_label.setText("Script generation failed")
        finally:
            self.generate_script_btn.setEnabled(True)

    def export_script(self):
        """Export generated script to file."""
        from intellicrack.handlers.pyqt6_handler import QFileDialog

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Script",
            "",
            "JavaScript Files (*.js);;Python Files (*.py);;All Files (*.*)",
        )

        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(self.output_text.toPlainText())

                QMessageBox.information(self, "Success", f"Script exported to {file_path}")
                logger.info(f"Script exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export script: {str(e)}")
                logger.error(f"Failed to export script: {e}")

    def copy_to_clipboard(self):
        """Copy output to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.output_text.toPlainText())

        self.status_label.setText("Copied to clipboard")

    def clear_all(self):
        """Clear all text fields."""
        self.input_text.clear()
        self.output_text.clear()
        self.status_label.setText("Ready")
        self.export_script_btn.setEnabled(False)
