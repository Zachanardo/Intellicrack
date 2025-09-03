"""AI Assistant Tab for Intellicrack GUI.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from intellicrack.ai.ai_assistant_enhanced import IntellicrackAIAssistant
from intellicrack.handlers.pyqt6_handler import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    Qt,
    QTextEdit,
    QVBoxLayout,
)
from intellicrack.utils.logger import get_logger

from .base_tab import BaseTab

logger = get_logger(__name__)


class APIKeyConfigDialog(QDialog):
    """Dialog for configuring API keys and model settings."""

    def __init__(self, model_name, parent=None):
        super().__init__(parent)
        self.model_name = model_name
        self.setWindowTitle(f"Configure {model_name}")
        self.setModal(True)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Form layout for settings
        form_layout = QFormLayout()

        # API Key
        self.api_key_edit = QLineEdit()
        self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_edit.setPlaceholderText("Enter your API key here...")
        form_layout.addRow("API Key:", self.api_key_edit)

        # Base URL (for custom endpoints)
        self.base_url_edit = QLineEdit()
        self.base_url_edit.setPlaceholderText("https://api.openai.com/v1 (leave empty for default)")
        form_layout.addRow("Base URL:", self.base_url_edit)

        # Model selection
        self.model_edit = QLineEdit()
        if "GPT" in self.model_name:
            self.model_edit.setPlaceholderText("gpt-4o, gpt-4-turbo, gpt-3.5-turbo")
        elif "Claude" in self.model_name:
            self.model_edit.setPlaceholderText("claude-3-5-sonnet-20241022, claude-3-haiku-20240307")
        elif "Gemini" in self.model_name:
            self.model_edit.setPlaceholderText("gemini-pro, gemini-pro-vision")
        else:
            self.model_edit.setPlaceholderText("Model name")
        form_layout.addRow("Model:", self.model_edit)

        # Temperature
        self.temperature_spin = QSpinBox()
        self.temperature_spin.setRange(0, 200)
        self.temperature_spin.setValue(70)
        self.temperature_spin.setSuffix(" (0.7)")
        form_layout.addRow("Temperature:", self.temperature_spin)

        # Max tokens
        self.max_tokens_spin = QSpinBox()
        self.max_tokens_spin.setRange(100, 32000)
        self.max_tokens_spin.setValue(4000)
        form_layout.addRow("Max Tokens:", self.max_tokens_spin)

        layout.addLayout(form_layout)

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_config(self):
        return {
            "api_key": self.api_key_edit.text(),
            "base_url": self.base_url_edit.text() or None,
            "model": self.model_edit.text(),
            "temperature": self.temperature_spin.value() / 100.0,
            "max_tokens": self.max_tokens_spin.value(),
        }

    def set_config(self, config):
        if config.get("api_key"):
            self.api_key_edit.setText(config["api_key"])
        if config.get("base_url"):
            self.base_url_edit.setText(config["base_url"])
        if config.get("model"):
            self.model_edit.setText(config["model"])
        if config.get("temperature") is not None:
            self.temperature_spin.setValue(int(config["temperature"] * 100))
        if config.get("max_tokens"):
            self.max_tokens_spin.setValue(config["max_tokens"])


class AIAssistantTab(BaseTab):
    """AI Assistant tab providing AI-powered analysis and script generation."""

    def __init__(self, shared_context=None, parent=None):
        """Initialize the AI Assistant tab."""
        super().__init__(shared_context, parent)
        self.ai_assistant = None
        self.model_configs = {}

    def setup_content(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()

        # Model selection
        model_group = QGroupBox("AI Model Configuration")
        model_layout = QVBoxLayout()

        # Model selector
        model_selector_layout = QHBoxLayout()
        model_selector_layout.addWidget(QLabel("Model:"))

        self.model_combo = QComboBox()
        model_selector_layout.addWidget(self.model_combo)

        self.configure_btn = QPushButton("Configure")
        self.configure_btn.clicked.connect(self.configure_model)
        model_selector_layout.addWidget(self.configure_btn)

        # Upload local model button
        self.upload_model_btn = QPushButton("Upload Local Model")
        self.upload_model_btn.clicked.connect(self.upload_local_model)
        model_selector_layout.addWidget(self.upload_model_btn)

        # Open model manager button
        self.model_manager_btn = QPushButton("Model Manager")
        self.model_manager_btn.clicked.connect(self.open_model_manager)
        model_selector_layout.addWidget(self.model_manager_btn)

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

        # Initialize AI assistant after UI setup
        self.setup_ai_assistant()
        # Load available models dynamically
        self.load_available_models()
        self.is_loaded = True

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

        # Handle special cases for local models and managers
        if "Upload Local Model" in model or "Local:" in model:
            self.upload_local_model()
            return
        elif "Model Manager" in model:
            self.open_model_manager()
            return
        elif "Configure API Model" in model:
            # Show API key configuration
            dialog = APIKeyConfigDialog("API Model", self)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                config = dialog.get_config()
                try:
                    # Register the API key with LLM manager
                    from intellicrack.ai.llm_backends import get_llm_manager

                    llm_manager = get_llm_manager()

                    # Configure API key based on model type
                    if config["model"] and "gpt" in config["model"].lower():
                        llm_manager.configure_openai_api(config["api_key"], config["base_url"])
                    elif config["model"] and "claude" in config["model"].lower():
                        llm_manager.configure_anthropic_api(config["api_key"])
                    elif config["model"] and "gemini" in config["model"].lower():
                        llm_manager.configure_gemini_api(config["api_key"])

                    self.status_label.setText("API key configured successfully")
                    # Refresh model list
                    self.load_available_models()

                except Exception as e:
                    logger.error(f"Failed to configure API: {e}")
                    QMessageBox.warning(self, "Configuration Error", f"Failed to configure API: {str(e)}")
            return

        # Standard model configuration
        dialog = APIKeyConfigDialog(model, self)

        # Load existing config if available
        if model in self.model_configs:
            dialog.set_config(self.model_configs[model])

        if dialog.exec() == QDialog.DialogCode.Accepted:
            config = dialog.get_config()
            self.model_configs[model] = config

            # Validate API key
            if config["api_key"]:
                self.status_label.setText(f"{model} configured successfully")
                logger.info(f"Model {model} configured with API key")

                # Reinitialize AI assistant with new config
                self.setup_ai_assistant()
            else:
                QMessageBox.warning(
                    self, "Configuration Warning", "No API key provided. The model may not work without proper authentication."
                )
                self.status_label.setText(f"{model} configured (no API key)")

        logger.info(f"Configuration dialog opened for: {model}")

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
                self.output_text.setPlainText("AI Assistant not initialized. Please check settings.")
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
                self.output_text.setPlainText("AI Assistant not initialized. Please check settings.")
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

    def load_available_models(self):
        """Load all available AI models dynamically."""
        try:
            self.model_combo.clear()
            available_models = []

            # Load API-based models from LLM backends
            try:
                from intellicrack.ai.llm_backends import get_llm_manager

                llm_manager = get_llm_manager()

                # Get configured API models
                api_models = llm_manager.list_models()
                for model_id in api_models:
                    available_models.append(f"API: {model_id}")

            except Exception as e:
                logger.warning(f"Could not load API models: {e}")

            # Load local GGUF models
            try:
                from intellicrack.ai.local_gguf_server import gguf_manager

                local_models = gguf_manager.list_models()

                for model_name, model_info in local_models.items():
                    size_mb = model_info.get("size_mb", 0)
                    available_models.append(f"Local: {model_name} ({size_mb}MB)")

            except Exception as e:
                logger.warning(f"Could not load local models: {e}")

            # Load models from model repositories
            try:
                from intellicrack.models.model_manager import ModelManager

                model_manager = ModelManager()

                for repo_name in ["huggingface", "lmstudio", "ollama"]:
                    try:
                        repo_models = model_manager.list_available_models(repo_name)
                        for model_info in repo_models:
                            model_name = model_info.get("name", model_info.get("model_id", "Unknown"))
                            available_models.append(f"{repo_name.title()}: {model_name}")
                    except Exception as repo_e:
                        logger.debug(f"Could not load {repo_name} models: {repo_e}")

            except Exception as e:
                logger.warning(f"Could not load repository models: {e}")

            # Add fallback models if no models found
            if not available_models:
                available_models = [
                    "Configure API Model...",
                    "Upload Local Model...",
                    "Download from Hugging Face...",
                    "Connect to Ollama...",
                    "Connect to LMStudio...",
                ]

            self.model_combo.addItems(available_models)
            logger.info(f"Loaded {len(available_models)} AI models")

        except Exception as e:
            logger.error(f"Failed to load available models: {e}")
            # Fallback to basic options
            self.model_combo.addItems(["Configure API Model...", "Upload Local Model...", "Open Model Manager..."])

    def upload_local_model(self):
        """Upload a local model file."""
        from intellicrack.handlers.pyqt6_handler import QFileDialog, QMessageBox

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Model File", "", "GGUF Files (*.gguf);;ONNX Files (*.onnx);;All Files (*.*)"
        )

        if file_path:
            try:
                # Import local model through model manager
                from intellicrack.models.model_manager import ModelManager

                model_manager = ModelManager()

                model_info = model_manager.import_local_model(file_path)

                if model_info:
                    QMessageBox.information(self, "Success", f"Model '{model_info.name}' uploaded successfully!")
                    # Refresh model list
                    self.load_available_models()

                    # Select the newly uploaded model
                    for i in range(self.model_combo.count()):
                        if model_info.name in self.model_combo.itemText(i):
                            self.model_combo.setCurrentIndex(i)
                            break
                else:
                    QMessageBox.warning(self, "Error", "Failed to upload model file.")

            except Exception as e:
                logger.error(f"Failed to upload model: {e}")
                QMessageBox.critical(self, "Error", f"Failed to upload model: {str(e)}")

    def open_model_manager(self):
        """Open the model manager dialog."""
        try:
            from intellicrack.ui.dialogs.model_manager_dialog import ModelManagerDialog

            dialog = ModelManagerDialog(self)
            if dialog.exec() == dialog.Accepted:
                # Refresh model list after model manager closes
                self.load_available_models()

        except Exception as e:
            logger.error(f"Failed to open model manager: {e}")
            from intellicrack.handlers.pyqt6_handler import QMessageBox

            QMessageBox.critical(self, "Error", f"Failed to open model manager: {str(e)}")

    def clear_all(self):
        """Clear all text fields."""
        self.input_text.clear()
        self.output_text.clear()
        self.status_label.setText("Ready")
        self.export_script_btn.setEnabled(False)
