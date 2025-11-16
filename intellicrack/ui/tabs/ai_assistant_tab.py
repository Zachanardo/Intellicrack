"""AI Assistant Tab for Intellicrack GUI.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from intellicrack.ai.interactive_assistant import IntellicrackAIAssistant
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
    """Enhanced dialog for configuring API providers with dynamic model discovery."""

    def __init__(self, parent: QDialog | None = None) -> None:
        """Initialize the API configuration dialog.

        Args:
            parent: Parent widget for the dialog

        """
        super().__init__(parent)
        self.setWindowTitle("Configure API Model")
        self.setModal(True)
        self.setMinimumWidth(500)
        self.current_provider_client = None
        self.available_models = []
        self.setup_ui()

    def setup_ui(self) -> None:
        """Set up the user interface with provider selection and dynamic model discovery."""
        layout = QVBoxLayout(self)

        form_layout = QFormLayout()

        self.provider_combo = QComboBox()
        self.provider_combo.addItems(
            [
                "OpenAI",
                "Anthropic",
                "Ollama (Local)",
                "LM Studio (Local)",
                "Custom OpenAI-Compatible",
            ],
        )
        self.provider_combo.currentTextChanged.connect(self.on_provider_changed)
        form_layout.addRow("Provider:", self.provider_combo)

        self.api_key_edit = QLineEdit()
        self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_edit.setText("")
        self.api_key_label = QLabel("API Key:")
        form_layout.addRow(self.api_key_label, self.api_key_edit)

        self.base_url_edit = QLineEdit()
        self.base_url_edit.setText("")
        self.base_url_label = QLabel("Base URL:")
        form_layout.addRow(self.base_url_label, self.base_url_edit)

        model_row_layout = QHBoxLayout()
        self.model_combo = QComboBox()
        self.model_combo.setEditable(True)
        model_row_layout.addWidget(self.model_combo, 1)

        self.fetch_models_btn = QPushButton("Refresh Models")
        self.fetch_models_btn.clicked.connect(self.fetch_available_models)
        model_row_layout.addWidget(self.fetch_models_btn)

        form_layout.addRow("Model:", model_row_layout)

        self.model_info_label = QLabel("")
        self.model_info_label.setWordWrap(True)
        self.model_info_label.setStyleSheet("color: #666; font-size: 10px;")
        form_layout.addRow("", self.model_info_label)

        self.temperature_spin = QSpinBox()
        self.temperature_spin.setRange(0, 200)
        self.temperature_spin.setValue(70)
        self.temperature_spin.setSuffix(" (0.7)")
        form_layout.addRow("Temperature:", self.temperature_spin)

        self.max_tokens_spin = QSpinBox()
        self.max_tokens_spin.setRange(100, 200000)
        self.max_tokens_spin.setValue(4000)
        form_layout.addRow("Max Tokens:", self.max_tokens_spin)

        layout.addLayout(form_layout)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #666; font-style: italic;")
        layout.addWidget(self.status_label)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.model_combo.currentTextChanged.connect(self.on_model_selected)

        self.on_provider_changed(self.provider_combo.currentText())

    def on_provider_changed(self, provider_name: str) -> None:
        """Handle provider selection change."""
        self.model_combo.clear()
        self.model_info_label.clear()
        self.available_models = []

        if "Ollama" in provider_name:
            self.api_key_label.setVisible(False)
            self.api_key_edit.setVisible(False)
            self.base_url_label.setVisible(True)
            self.base_url_edit.setVisible(True)
            self.base_url_edit.setText("http://localhost:11434")
        elif "LM Studio" in provider_name:
            self.api_key_label.setVisible(False)
            self.api_key_edit.setVisible(False)
            self.base_url_label.setVisible(True)
            self.base_url_edit.setVisible(True)
            self.base_url_edit.setText("http://localhost:1234/v1")
        elif "Custom" in provider_name:
            self.api_key_label.setVisible(True)
            self.api_key_edit.setVisible(True)
            self.base_url_label.setVisible(True)
            self.base_url_edit.setVisible(True)
            self.base_url_edit.setText("https://your-api-endpoint.com/v1")
        else:
            self.api_key_label.setVisible(True)
            self.api_key_edit.setVisible(True)
            self.base_url_label.setVisible(False)
            self.base_url_edit.setVisible(False)

            if provider_name == "OpenAI":
                self.base_url_edit.setText("https://api.openai.com/v1")
            elif provider_name == "Anthropic":
                self.base_url_edit.setText("https://api.anthropic.com")

        self.status_label.setText("Click 'Refresh Models' to load available models")

    def fetch_available_models(self) -> None:
        """Fetch available models from the selected provider."""
        provider_name = self.provider_combo.currentText()
        api_key = self.api_key_edit.text() if self.api_key_edit.isVisible() else None
        base_url = self.base_url_edit.text() if self.base_url_edit.text() else None

        self.status_label.setText("Fetching models...")
        self.fetch_models_btn.setEnabled(False)
        self.model_combo.clear()

        try:
            from intellicrack.ai.api_provider_clients import (
                AnthropicProviderClient,
                LMStudioProviderClient,
                OllamaProviderClient,
                OpenAIProviderClient,
            )

            if "OpenAI" in provider_name or "Custom" in provider_name:
                client = OpenAIProviderClient(api_key, base_url)
            elif "Anthropic" in provider_name:
                client = AnthropicProviderClient(api_key, base_url)
            elif "Ollama" in provider_name:
                client = OllamaProviderClient(None, base_url)
            elif "LM Studio" in provider_name:
                client = LMStudioProviderClient(None, base_url)
            else:
                self.status_label.setText("Unknown provider")
                self.fetch_models_btn.setEnabled(True)
                return

            self.current_provider_client = client
            models = client.fetch_models()

            if not models:
                self.status_label.setText("No models found or API connection failed")
                self.fetch_models_btn.setEnabled(True)
                return

            self.available_models = models
            self.model_combo.clear()

            for model in models:
                display_name = f"{model.name}"
                if model.context_length and model.context_length != 4096:
                    display_name += f" ({model.context_length // 1000}K)"
                self.model_combo.addItem(display_name, model.id)

            self.status_label.setText(f"Loaded {len(models)} models")
            logger.info(f"Fetched {len(models)} models from {provider_name}")

        except Exception as e:
            logger.error(f"Error fetching models: {e}")
            self.status_label.setText(f"Error: {e!s}")

        finally:
            self.fetch_models_btn.setEnabled(True)

    def on_model_selected(self, model_display_name: str) -> None:
        """Handle model selection and show model information."""
        if not self.available_models:
            return

        current_index = self.model_combo.currentIndex()
        if current_index < 0 or current_index >= len(self.available_models):
            return

        model = self.available_models[current_index]

        info_parts = []
        if model.description:
            info_parts.append(model.description)
        if model.context_length:
            info_parts.append(f"Context: {model.context_length:,} tokens")
        if model.capabilities:
            info_parts.append(f"Capabilities: {', '.join(model.capabilities)}")

        self.model_info_label.setText("  ".join(info_parts))

        if model.context_length:
            self.max_tokens_spin.setMaximum(min(model.context_length, 200000))

    def get_config(self) -> dict[str, object]:
        """Retrieve the current configuration."""
        model_id = self.model_combo.currentData()
        if not model_id:
            model_id = self.model_combo.currentText()

        return {
            "provider": self.provider_combo.currentText(),
            "api_key": self.api_key_edit.text() if self.api_key_edit.isVisible() else None,
            "base_url": self.base_url_edit.text() if self.base_url_edit.isVisible() else None,
            "model": model_id,
            "temperature": self.temperature_spin.value() / 100.0,
            "max_tokens": self.max_tokens_spin.value(),
        }

    def set_config(self, config: dict[str, object]) -> None:
        """Populate the dialog with existing configuration."""
        if config.get("provider"):
            index = self.provider_combo.findText(config["provider"])
            if index >= 0:
                self.provider_combo.setCurrentIndex(index)

        if config.get("api_key"):
            self.api_key_edit.setText(config["api_key"])

        if config.get("base_url"):
            self.base_url_edit.setText(config["base_url"])

        if config.get("model"):
            self.model_combo.setEditText(config["model"])

        if config.get("temperature") is not None:
            self.temperature_spin.setValue(int(config["temperature"] * 100))

        if config.get("max_tokens"):
            self.max_tokens_spin.setValue(config["max_tokens"])


class AIAssistantTab(BaseTab):
    """AI Assistant tab providing AI-powered analysis and script generation."""

    def __init__(self, shared_context: object | None = None, parent: object | None = None) -> None:
        """Initialize the AI Assistant tab."""
        super().__init__(shared_context, parent)
        self.ai_assistant = None
        self.model_configs = {}

    def setup_content(self) -> None:
        """Initialize the user interface."""
        layout = self.layout()  # Use existing layout from BaseTab

        # Model selection
        model_group = QGroupBox("AI Model Configuration")
        model_layout = QVBoxLayout()

        # Model selector
        model_selector_layout = QHBoxLayout()
        model_selector_layout.addWidget(QLabel("Model:"))

        self.model_combo = QComboBox()
        self.model_combo.setToolTip("Select the AI model to use for analysis. Configure API keys through the Configure button")
        model_selector_layout.addWidget(self.model_combo)

        self.configure_btn = QPushButton("Configure")
        self.configure_btn.setToolTip("Set up API keys, endpoints, and parameters for the selected AI model")
        self.configure_btn.clicked.connect(self.configure_model)
        model_selector_layout.addWidget(self.configure_btn)

        # Upload local model button
        self.upload_model_btn = QPushButton("Upload Local Model")
        self.upload_model_btn.setToolTip("Load a locally hosted AI model for offline analysis capabilities")
        self.upload_model_btn.clicked.connect(self.upload_local_model)
        model_selector_layout.addWidget(self.upload_model_btn)

        # Open model manager button
        self.model_manager_btn = QPushButton("Model Manager")
        self.model_manager_btn.setToolTip("Manage installed AI models, download new models, and configure model parameters")
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
        self.input_text.setToolTip(
            "Input area for questions, code snippets, or analysis requests. Supports multiple languages and binary formats",
        )
        input_layout.addWidget(self.input_text)

        # Action buttons
        button_layout = QHBoxLayout()

        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.setToolTip("Send your query to the AI model for comprehensive analysis and insights")
        self.analyze_btn.clicked.connect(self.perform_analysis)
        button_layout.addWidget(self.analyze_btn)

        self.generate_script_btn = QPushButton("Generate Script")
        self.generate_script_btn.setToolTip("Generate custom Frida, Ghidra, or IDA scripts based on your requirements")
        self.generate_script_btn.clicked.connect(self.generate_script)
        button_layout.addWidget(self.generate_script_btn)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setToolTip("Clear both input and output fields to start a new analysis session")
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
        self.output_text.setToolTip("AI model responses and generated analysis results. Content can be exported using the buttons below")
        output_layout.addWidget(self.output_text)

        # Export buttons
        export_layout = QHBoxLayout()

        self.export_script_btn = QPushButton("Export Script")
        self.export_script_btn.setToolTip("Save the generated script to a file for use with Frida, Ghidra, or other tools")
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

        # Initialize AI assistant after UI setup
        self.setup_ai_assistant()
        # Load available models dynamically
        self.load_available_models()
        self.is_loaded = True

    def setup_ai_assistant(self) -> None:
        """Initialize the AI assistant."""
        try:
            self.ai_assistant = IntellicrackAIAssistant()
            self.status_label.setText("AI Assistant initialized")
            logger.info("AI Assistant initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize AI Assistant: {e}")
            self.status_label.setText(f"Error: {e}")

    def configure_model(self) -> None:
        """Configure API model with provider selection and dynamic model discovery."""
        model = self.model_combo.currentText()

        if "Upload Local Model" in model or "Local:" in model:
            self.upload_local_model()
            return
        if "Model Manager" in model:
            self.open_model_manager()
            return

        dialog = APIKeyConfigDialog(self)

        if model in self.model_configs:
            dialog.set_config(self.model_configs[model])

        if dialog.exec() == QDialog.DialogCode.Accepted:
            config = dialog.get_config()

            if not config.get("model"):
                QMessageBox.warning(self, "Configuration Error", "No model selected. Please select a model.")
                return

            model_key = f"{config['provider']}:{config['model']}"
            self.model_configs[model_key] = config

            try:
                from intellicrack.ai.llm_backends import LLMConfig, LLMProvider, get_llm_manager

                llm_manager = get_llm_manager()

                provider_map = {
                    "OpenAI": LLMProvider.OPENAI,
                    "Anthropic": LLMProvider.ANTHROPIC,
                    "Ollama (Local)": LLMProvider.OLLAMA,
                    "LM Studio (Local)": LLMProvider.LOCAL_API,
                    "Custom OpenAI-Compatible": LLMProvider.LOCAL_API,
                }

                provider = provider_map.get(config["provider"], LLMProvider.OPENAI)

                llm_config = LLMConfig(
                    provider=provider,
                    model_name=config["model"],
                    api_key=config.get("api_key"),
                    api_base=config.get("base_url"),
                    temperature=config.get("temperature", 0.7),
                    max_tokens=config.get("max_tokens", 4000),
                    tools_enabled=True,
                )

                if llm_manager.register_llm(model_key, llm_config):
                    self.status_label.setText(f"{config['provider']} - {config['model']} configured successfully")
                    logger.info(f"Model {model_key} configured and registered")

                    self.model_combo.addItem(f"{config['provider']}: {config['model']}")
                    self.model_combo.setCurrentText(f"{config['provider']}: {config['model']}")

                    self.setup_ai_assistant()

                    QMessageBox.information(
                        self,
                        "Success",
                        f"Model '{config['model']}' from {config['provider']} has been configured successfully!",
                    )
                else:
                    error_msg = "Failed to register model with LLM manager"
                    logger.error(error_msg)
                    raise Exception(error_msg)

            except Exception as e:
                logger.error(f"Failed to configure model: {e}")
                QMessageBox.critical(self, "Configuration Error", f"Failed to configure model: {e!s}")
                self.status_label.setText("Configuration failed")

        logger.info("Model configuration dialog completed")

    def perform_analysis(self) -> None:
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
            self.output_text.setPlainText(f"Analysis failed: {e!s}")
            self.status_label.setText("Analysis failed")
        finally:
            self.analyze_btn.setEnabled(True)

    def generate_script(self) -> None:
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
            self.output_text.setPlainText(f"Script generation failed: {e!s}")
            self.status_label.setText("Script generation failed")
        finally:
            self.generate_script_btn.setEnabled(True)

    def export_script(self) -> None:
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
                QMessageBox.critical(self, "Error", f"Failed to export script: {e!s}")
                logger.error(f"Failed to export script: {e}")

    def copy_to_clipboard(self) -> None:
        """Copy output to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.output_text.toPlainText())

        self.status_label.setText("Copied to clipboard")

    def load_available_models(self) -> None:
        """Load all available AI models dynamically from configured providers."""
        try:
            self.model_combo.clear()
            available_models = []

            try:
                from intellicrack.ai.model_discovery_service import get_model_discovery_service

                discovery_service = get_model_discovery_service()
                flat_models = discovery_service.get_flat_model_list(force_refresh=False)

                for display_name, _model_info in flat_models:
                    available_models.append(display_name)
                    logger.debug(f"Found model: {display_name}")

            except Exception as e:
                logger.warning(f"Could not load models from ModelDiscoveryService: {e}")

            try:
                from intellicrack.ai.llm_backends import get_llm_manager

                llm_manager = get_llm_manager()

                api_models = llm_manager.list_models()
                for model_id in api_models:
                    if model_id not in available_models:
                        available_models.append(f"Configured: {model_id}")

            except Exception as e:
                logger.warning(f"Could not load configured API models: {e}")

            try:
                from intellicrack.ai.local_gguf_server import gguf_manager

                local_models = gguf_manager.list_models()

                for model_name, model_info in local_models.items():
                    size_mb = model_info.get("size_mb", 0)
                    display_name = f"Local GGUF: {model_name} ({size_mb}MB)"
                    available_models.append(display_name)

            except Exception as e:
                logger.warning(f"Could not load local GGUF models: {e}")

            try:
                from intellicrack.models.model_manager import ModelManager

                model_manager = ModelManager()

                for repo_name in ["huggingface", "lmstudio", "ollama"]:
                    try:
                        repo_models = model_manager.list_available_models(repo_name)
                        for model_info in repo_models:
                            model_name = model_info.get("name", model_info.get("model_id", "Unknown"))
                            display_name = f"{repo_name.title()}: {model_name}"
                            available_models.append(display_name)
                    except Exception as repo_e:
                        logger.debug(f"Could not load {repo_name} models: {repo_e}")

            except Exception as e:
                logger.warning(f"Could not load repository models: {e}")

            if not available_models:
                self.model_combo.addItem("WARNING No models configured - Click 'Configure' to add")
                self.model_combo.setEnabled(False)
                logger.warning("No AI models found - user needs to configure models")
            else:
                self.model_combo.addItems(available_models)
                self.model_combo.setEnabled(True)
                logger.info(f"Loaded {len(available_models)} AI models dynamically")

        except Exception as e:
            logger.error(f"Failed to load available models: {e}")
            self.model_combo.addItem("FAIL Error loading models - Check configuration")
            self.model_combo.setEnabled(False)

    def upload_local_model(self) -> None:
        """Upload a local model file."""
        from intellicrack.handlers.pyqt6_handler import QFileDialog, QMessageBox

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Model File", "", "GGUF Files (*.gguf);;ONNX Files (*.onnx);;All Files (*.*)",
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
                QMessageBox.critical(self, "Error", f"Failed to upload model: {e!s}")

    def open_model_manager(self) -> None:
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

            QMessageBox.critical(self, "Error", f"Failed to open model manager: {e!s}")

    def clear_all(self) -> None:
        """Clear all text fields."""
        self.input_text.clear()
        self.output_text.clear()
        self.status_label.setText("Ready")
        self.export_script_btn.setEnabled(False)
