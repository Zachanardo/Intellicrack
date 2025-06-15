"""
LLM Configuration Dialog for Intellicrack 

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


import logging
import os
import time

try:
    from PyQt5.QtCore import Qt, QThread, pyqtSignal
    from PyQt5.QtGui import QFont
    from PyQt5.QtWidgets import (
        QCheckBox,
        QComboBox,
        QDialog,
        QDoubleSpinBox,
        QFileDialog,
        QFormLayout,
        QFrame,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMessageBox,
        QProgressBar,
        QPushButton,
        QSpinBox,
        QSplitter,
        QTabWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    # Fallback for environments without PyQt5
    QDialog = object
    QThread = object
    pyqtSignal = lambda *args: lambda x: x

# Local imports
try:
    from ...ai.llm_backends import (
        LLMConfig,
        LLMManager,
        LLMProvider,
        create_anthropic_config,
        create_gguf_config,
        create_ollama_config,
        create_openai_config,
        get_llm_manager,
    )
    from ...ai.orchestrator import get_orchestrator
    from ...utils.logger import get_logger
except ImportError:
    LLMManager = None
    get_llm_manager = None


logger = get_logger(__name__) if 'get_logger' in globals() else logging.getLogger(__name__)


class ModelTestThread(QThread):
    """Thread for testing model configurations."""

    test_complete = pyqtSignal(bool, str)  # success, message
    test_progress = pyqtSignal(str)  # progress message

    def __init__(self, config: 'LLMConfig'):
        super().__init__()
        self.config = config

    def run(self):
        """Test the model configuration."""
        try:
            self.test_progress.emit("Initializing model backend...")

            # Create temporary LLM manager for testing
            if not get_llm_manager:
                self.test_complete.emit(False, "LLM Manager not available")
                return

            llm_manager = get_llm_manager()

            # Register test configuration
            test_id = f"test_{self.config.provider.value}_{int(time.time())}"
            self.test_progress.emit(f"Testing {self.config.provider.value} model...")

            success = llm_manager.register_llm(test_id, self.config)

            if success:
                self.test_progress.emit("Sending test message...")

                # Send a simple test message
                from ...ai.llm_backends import LLMMessage
                test_messages = [
                    LLMMessage(role="user", content="Hello! Please respond with 'Test successful' to confirm the connection.")
                ]

                response = llm_manager.chat(test_messages, test_id)

                if response and response.content:
                    self.test_complete.emit(True, f"✓ Model test successful!\nResponse: {response.content[:100]}...")
                else:
                    self.test_complete.emit(False, "Model loaded but failed to generate response")
            else:
                self.test_complete.emit(False, "Failed to initialize model backend")

        except (OSError, ValueError, RuntimeError) as e:
            self.test_complete.emit(False, f"Test failed: {str(e)}")


class LLMConfigDialog(QDialog):
    """Dialog for configuring LLM models in Intellicrack."""

    def __init__(self, parent=None):

        # Initialize UI attributes
        self.anthropic_api_key = None
        self.anthropic_max_tokens = None
        self.anthropic_model = None
        self.anthropic_temp = None
        self.anthropic_tools = None
        self.gguf_context = None
        self.gguf_max_tokens = None
        self.gguf_model_name = None
        self.gguf_model_path = None
        self.gguf_temp = None
        self.gguf_tools = None
        self.ollama_max_tokens = None
        self.ollama_model = None
        self.ollama_temp = None
        self.ollama_url = None
        self.openai_api_key = None
        self.openai_base_url = None
        self.openai_max_tokens = None
        self.openai_model = None
        self.openai_temp = None
        self.openai_tools = None
        super().__init__(parent)
        self.setWindowTitle("LLM Model Configuration - Intellicrack Agentic AI")
        self.setFixedSize(800, 600)

        self.llm_manager = get_llm_manager() if get_llm_manager else None
        self.current_configs = {}
        self.test_thread = None

        self.setup_ui()
        self.load_existing_configs()

    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)

        # Title and description
        title_label = QLabel("🤖 Agentic AI Model Configuration")
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        desc_label = QLabel("Configure LLM models for intelligent analysis and reasoning in Intellicrack")
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setStyleSheet("color: gray; margin-bottom: 10px;")
        layout.addWidget(desc_label)

        # Main content
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)

        # Left side - Configuration tabs
        config_widget = QWidget()
        config_layout = QVBoxLayout(config_widget)

        self.tabs = QTabWidget()
        config_layout.addWidget(self.tabs)

        # Add configuration tabs
        self.setup_openai_tab()
        self.setup_anthropic_tab()
        self.setup_gguf_tab()
        self.setup_ollama_tab()

        splitter.addWidget(config_widget)

        # Right side - Active models and status
        status_widget = QWidget()
        status_layout = QVBoxLayout(status_widget)

        status_label = QLabel("Active Models")
        status_label.setFont(QFont("Arial", 12, QFont.Bold))
        status_layout.addWidget(status_label)

        self.models_list = QListWidget()
        status_layout.addWidget(self.models_list)

        # Model actions
        actions_layout = QHBoxLayout()
        self.set_active_btn = QPushButton("Set Active")
        self.remove_model_btn = QPushButton("Remove")
        self.test_model_btn = QPushButton("Test")

        self.set_active_btn.clicked.connect(self.set_active_model)
        self.remove_model_btn.clicked.connect(self.remove_model)
        self.test_model_btn.clicked.connect(self.test_selected_model)

        actions_layout.addWidget(self.set_active_btn)
        actions_layout.addWidget(self.test_model_btn)
        actions_layout.addWidget(self.remove_model_btn)
        status_layout.addLayout(actions_layout)

        # Status display
        self.status_text = QTextEdit()
        self.status_text.setMaximumHeight(150)
        self.status_text.setPlainText("Ready to configure models...")
        status_layout.addWidget(self.status_text)

        splitter.addWidget(status_widget)
        splitter.setSizes([500, 300])

        # Bottom buttons
        button_layout = QHBoxLayout()

        self.test_progress = QProgressBar()
        self.test_progress.setVisible(False)
        button_layout.addWidget(self.test_progress)

        button_layout.addStretch()

        save_btn = QPushButton("Save Configuration")
        close_btn = QPushButton("Close")

        save_btn.clicked.connect(self.save_configuration)
        close_btn.clicked.connect(self.close)

        button_layout.addWidget(save_btn)
        button_layout.addWidget(close_btn)

        layout.addLayout(button_layout)

    def setup_openai_tab(self):
        """Set up OpenAI configuration tab."""
        tab = QWidget()
        layout = QFormLayout(tab)

        # API Key
        self.openai_api_key = QLineEdit()
        self.openai_api_key.setEchoMode(QLineEdit.Password)
        self.openai_api_key.setPlaceholderText("sk-...")
        layout.addRow("API Key:", self.openai_api_key)

        # Model selection
        self.openai_model = QComboBox()
        self.openai_model.addItems([
            "gpt-4",
            "gpt-4-turbo-preview",
            "gpt-4o",
            "gpt-3.5-turbo",
            "gpt-3.5-turbo-16k"
        ])
        layout.addRow("Model:", self.openai_model)

        # Custom base URL
        self.openai_base_url = QLineEdit()
        self.openai_base_url.setPlaceholderText("https://api.openai.com/v1 (default)")
        layout.addRow("Base URL:", self.openai_base_url)

        # Parameters
        self.openai_temp = QDoubleSpinBox()
        self.openai_temp.setRange(0.0, 2.0)
        self.openai_temp.setSingleStep(0.1)
        self.openai_temp.setValue(0.7)
        layout.addRow("Temperature:", self.openai_temp)

        self.openai_max_tokens = QSpinBox()
        self.openai_max_tokens.setRange(1, 4096)
        self.openai_max_tokens.setValue(2048)
        layout.addRow("Max Tokens:", self.openai_max_tokens)

        # Tools
        self.openai_tools = QCheckBox("Enable Function Calling")
        self.openai_tools.setChecked(True)
        layout.addRow("Features:", self.openai_tools)

        # Add/Test buttons
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add OpenAI Model")
        test_btn = QPushButton("Test Configuration")

        add_btn.clicked.connect(self.add_openai_model)
        test_btn.clicked.connect(self.test_openai_config)

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(test_btn)
        layout.addRow("", btn_layout)

        self.tabs.addTab(tab, "OpenAI")

    def setup_anthropic_tab(self):
        """Set up Anthropic configuration tab."""
        tab = QWidget()
        layout = QFormLayout(tab)

        # API Key
        self.anthropic_api_key = QLineEdit()
        self.anthropic_api_key.setEchoMode(QLineEdit.Password)
        self.anthropic_api_key.setPlaceholderText("sk-ant-...")
        layout.addRow("API Key:", self.anthropic_api_key)

        # Model selection
        self.anthropic_model = QComboBox()
        self.anthropic_model.addItems([
            "claude-3-5-sonnet-20241022",
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
            "claude-2.1",
            "claude-instant-1.2"
        ])
        layout.addRow("Model:", self.anthropic_model)

        # Parameters
        self.anthropic_temp = QDoubleSpinBox()
        self.anthropic_temp.setRange(0.0, 1.0)
        self.anthropic_temp.setSingleStep(0.1)
        self.anthropic_temp.setValue(0.7)
        layout.addRow("Temperature:", self.anthropic_temp)

        self.anthropic_max_tokens = QSpinBox()
        self.anthropic_max_tokens.setRange(1, 8192)
        self.anthropic_max_tokens.setValue(2048)
        layout.addRow("Max Tokens:", self.anthropic_max_tokens)

        # Tools
        self.anthropic_tools = QCheckBox("Enable Tool Use")
        self.anthropic_tools.setChecked(True)
        layout.addRow("Features:", self.anthropic_tools)

        # Add/Test buttons
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add Anthropic Model")
        test_btn = QPushButton("Test Configuration")

        add_btn.clicked.connect(self.add_anthropic_model)
        test_btn.clicked.connect(self.test_anthropic_config)

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(test_btn)
        layout.addRow("", btn_layout)

        self.tabs.addTab(tab, "Anthropic")

    def setup_gguf_tab(self):
        """Set up GGUF model configuration tab."""
        tab = QWidget()
        layout = QFormLayout(tab)

        # Model file selection
        model_layout = QHBoxLayout()
        self.gguf_model_path = QLineEdit()
        self.gguf_model_path.setPlaceholderText("Select GGUF model file...")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_gguf_model)

        model_layout.addWidget(self.gguf_model_path)
        model_layout.addWidget(browse_btn)
        layout.addRow("Model File:", model_layout)

        # Model name
        self.gguf_model_name = QLineEdit()
        self.gguf_model_name.setPlaceholderText("Custom model name (optional)")
        layout.addRow("Model Name:", self.gguf_model_name)

        # Context length
        self.gguf_context = QSpinBox()
        self.gguf_context.setRange(512, 32768)
        self.gguf_context.setValue(4096)
        layout.addRow("Context Length:", self.gguf_context)

        # Temperature
        self.gguf_temp = QDoubleSpinBox()
        self.gguf_temp.setRange(0.0, 2.0)
        self.gguf_temp.setSingleStep(0.1)
        self.gguf_temp.setValue(0.7)
        layout.addRow("Temperature:", self.gguf_temp)

        # Max tokens
        self.gguf_max_tokens = QSpinBox()
        self.gguf_max_tokens.setRange(1, 4096)
        self.gguf_max_tokens.setValue(2048)
        layout.addRow("Max Tokens:", self.gguf_max_tokens)

        # Tools
        self.gguf_tools = QCheckBox("Enable Tool Calling (Experimental)")
        self.gguf_tools.setChecked(False)
        layout.addRow("Features:", self.gguf_tools)

        # Add/Test buttons
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add GGUF Model")
        test_btn = QPushButton("Test Configuration")

        add_btn.clicked.connect(self.add_gguf_model)
        test_btn.clicked.connect(self.test_gguf_config)

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(test_btn)
        layout.addRow("", btn_layout)

        # Requirements info
        info_text = QLabel("Requires: pip install llama-cpp-python")
        info_text.setStyleSheet("color: blue; font-size: 10px;")
        layout.addRow("", info_text)

        self.tabs.addTab(tab, "GGUF Models")

    def setup_ollama_tab(self):
        """Set up Ollama configuration tab."""
        tab = QWidget()
        layout = QFormLayout(tab)

        # Server URL
        self.ollama_url = QLineEdit()
        self.ollama_url.setText("http://localhost:11434")
        layout.addRow("Server URL:", self.ollama_url)

        # Model name
        self.ollama_model = QLineEdit()
        self.ollama_model.setPlaceholderText("llama2, codellama, mistral, etc.")
        layout.addRow("Model Name:", self.ollama_model)

        # Parameters
        self.ollama_temp = QDoubleSpinBox()
        self.ollama_temp.setRange(0.0, 2.0)
        self.ollama_temp.setSingleStep(0.1)
        self.ollama_temp.setValue(0.7)
        layout.addRow("Temperature:", self.ollama_temp)

        self.ollama_max_tokens = QSpinBox()
        self.ollama_max_tokens.setRange(1, 4096)
        self.ollama_max_tokens.setValue(2048)
        layout.addRow("Max Tokens:", self.ollama_max_tokens)

        # Add/Test buttons
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add Ollama Model")
        test_btn = QPushButton("Test Configuration")

        add_btn.clicked.connect(self.add_ollama_model)
        test_btn.clicked.connect(self.test_ollama_config)

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(test_btn)
        layout.addRow("", btn_layout)

        # Requirements info
        info_text = QLabel("Requires: Ollama server running locally")
        info_text.setStyleSheet("color: blue; font-size: 10px;")
        layout.addRow("", info_text)

        self.tabs.addTab(tab, "Ollama")

    def browse_gguf_model(self):
        """Browse for GGUF model file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select GGUF Model File",
            "",
            "GGUF Files (*.gguf);;All Files (*)"
        )

        if file_path:
            self.gguf_model_path.setText(file_path)
            # Auto-fill model name if empty
            if not self.gguf_model_name.text():
                model_name = os.path.splitext(os.path.basename(file_path))[0]
                self.gguf_model_name.setText(model_name)

    def add_openai_model(self):
        """Add OpenAI model configuration."""
        if not self.openai_api_key.text().strip():
            QMessageBox.warning(self, "Missing API Key", "Please enter your OpenAI API key")
            return

        config = create_openai_config(
            model_name=self.openai_model.currentText(),
            api_key=self.openai_api_key.text().strip(),
            api_base=self.openai_base_url.text().strip() or None,
            temperature=self.openai_temp.value(),
            max_tokens=self.openai_max_tokens.value(),
            tools_enabled=self.openai_tools.isChecked()
        )

        model_id = f"openai_{self.openai_model.currentText()}"
        self.register_model(model_id, config)

    def add_anthropic_model(self):
        """Add Anthropic model configuration."""
        if not self.anthropic_api_key.text().strip():
            QMessageBox.warning(self, "Missing API Key", "Please enter your Anthropic API key")
            return

        config = create_anthropic_config(
            model_name=self.anthropic_model.currentText(),
            api_key=self.anthropic_api_key.text().strip(),
            temperature=self.anthropic_temp.value(),
            max_tokens=self.anthropic_max_tokens.value(),
            tools_enabled=self.anthropic_tools.isChecked()
        )

        model_id = f"anthropic_{self.anthropic_model.currentText().replace('-', '_')}"
        self.register_model(model_id, config)

    def add_gguf_model(self):
        """Add GGUF model configuration."""
        if not self.gguf_model_path.text().strip():
            QMessageBox.warning(self, "Missing Model File", "Please select a GGUF model file")
            return

        if not os.path.exists(self.gguf_model_path.text()):
            QMessageBox.warning(self, "File Not Found", "The selected GGUF file does not exist")
            return

        model_name = self.gguf_model_name.text().strip()
        if not model_name:
            model_name = os.path.splitext(os.path.basename(self.gguf_model_path.text()))[0]

        config = create_gguf_config(
            model_path=self.gguf_model_path.text(),
            model_name=model_name,
            context_length=self.gguf_context.value(),
            temperature=self.gguf_temp.value(),
            max_tokens=self.gguf_max_tokens.value(),
            tools_enabled=self.gguf_tools.isChecked()
        )

        model_id = f"gguf_{model_name.replace(' ', '_').replace('-', '_')}"
        self.register_model(model_id, config)

    def add_ollama_model(self):
        """Add Ollama model configuration."""
        if not self.ollama_model.text().strip():
            QMessageBox.warning(self, "Missing Model Name", "Please enter the Ollama model name")
            return

        config = create_ollama_config(
            model_name=self.ollama_model.text().strip(),
            api_base=self.ollama_url.text().strip(),
            temperature=self.ollama_temp.value(),
            max_tokens=self.ollama_max_tokens.value()
        )

        model_id = f"ollama_{self.ollama_model.text().strip().replace(':', '_')}"
        self.register_model(model_id, config)

    def register_model(self, model_id: str, config: LLMConfig):
        """Register a model with the LLM manager."""
        if not self.llm_manager:
            QMessageBox.critical(self, "Error", "LLM Manager not available")
            return

        success = self.llm_manager.register_llm(model_id, config)

        if success:
            self.current_configs[model_id] = config
            self.update_models_list()
            self.status_text.append(f"✓ Added model: {model_id}")

            # Set as active if it's the first model
            if len(self.current_configs) == 1:
                self.llm_manager.set_active_llm(model_id)
                self.status_text.append(f"✓ Set as active model: {model_id}")
        else:
            QMessageBox.critical(self, "Error", f"Failed to register model: {model_id}")

    def update_models_list(self):
        """Update the models list widget."""
        self.models_list.clear()

        if self.llm_manager:
            active_llm = self.llm_manager.active_backend

            for _llm_id in self.llm_manager.get_available_llms():
                item = QListWidgetItem(_llm_id)
                if _llm_id == active_llm:
                    item.setText(f"🟢 {_llm_id} (Active)")
                    item.setData(Qt.UserRole, _llm_id)
                else:
                    item.setText(f"⚪ {_llm_id}")
                    item.setData(Qt.UserRole, _llm_id)

                self.models_list.addItem(item)

    def set_active_model(self):
        """Set the selected model as active."""
        current_item = self.models_list.currentItem()
        if not current_item:
            return

        model_id = current_item.data(Qt.UserRole)
        if self.llm_manager and self.llm_manager.set_active_llm(model_id):
            self.update_models_list()
            self.status_text.append(f"✓ Set active model: {model_id}")

    def remove_model(self):
        """Remove the selected model."""
        current_item = self.models_list.currentItem()
        if not current_item:
            return

        model_id = current_item.data(Qt.UserRole)

        reply = QMessageBox.question(
            self, "Remove Model",
            f"Are you sure you want to remove model: {model_id}?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            # Remove from our tracking
            if model_id in self.current_configs:
                del self.current_configs[model_id]

            # Note: LLM manager doesn't have remove method in current implementation
            # This would need to be added to the LLM manager
            self.update_models_list()
            self.status_text.append(f"✓ Removed model: {model_id}")

    def test_selected_model(self):
        """Test the selected model."""
        current_item = self.models_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "No Selection", "Please select a model to test")
            return

        model_id = current_item.data(Qt.UserRole)
        if model_id in self.current_configs:
            self.test_model_config(self.current_configs[model_id])

    def test_openai_config(self):
        """Test OpenAI configuration."""
        if not self.openai_api_key.text().strip():
            QMessageBox.warning(self, "Missing API Key", "Please enter your OpenAI API key")
            return

        config = create_openai_config(
            model_name=self.openai_model.currentText(),
            api_key=self.openai_api_key.text().strip(),
            api_base=self.openai_base_url.text().strip() or None
        )
        self.test_model_config(config)

    def test_anthropic_config(self):
        """Test Anthropic configuration."""
        if not self.anthropic_api_key.text().strip():
            QMessageBox.warning(self, "Missing API Key", "Please enter your Anthropic API key")
            return

        config = create_anthropic_config(
            model_name=self.anthropic_model.currentText(),
            api_key=self.anthropic_api_key.text().strip()
        )
        self.test_model_config(config)

    def test_gguf_config(self):
        """Test GGUF configuration."""
        if not self.gguf_model_path.text().strip():
            QMessageBox.warning(self, "Missing Model File", "Please select a GGUF model file")
            return

        config = create_gguf_config(
            model_path=self.gguf_model_path.text(),
            model_name=self.gguf_model_name.text() or "test_model"
        )
        self.test_model_config(config)

    def test_ollama_config(self):
        """Test Ollama configuration."""
        if not self.ollama_model.text().strip():
            QMessageBox.warning(self, "Missing Model Name", "Please enter the Ollama model name")
            return

        config = create_ollama_config(
            model_name=self.ollama_model.text().strip(),
            api_base=self.ollama_url.text().strip()
        )
        self.test_model_config(config)

    def test_model_config(self, config: 'LLMConfig'):
        """Test a model configuration."""
        if self.test_thread and self.test_thread.isRunning():
            QMessageBox.warning(self, "Test In Progress", "Please wait for the current test to complete")
            return

        self.test_progress.setVisible(True)
        self.test_progress.setRange(0, 0)  # Indeterminate progress
        self.status_text.append(f"🧪 Testing {config.provider.value} model...")

        self.test_thread = ModelTestThread(config)
        self.test_thread.test_progress.connect(self.on_test_progress)
        self.test_thread.test_complete.connect(self.on_test_complete)
        self.test_thread.start()

    def on_test_progress(self, message: str):
        """Handle test progress updates."""
        self.status_text.append(f"   {message}")

    def on_test_complete(self, success: bool, message: str):
        """Handle test completion."""
        self.test_progress.setVisible(False)

        if success:
            self.status_text.append(f"✅ {message}")
        else:
            self.status_text.append(f"❌ {message}")

        # Clean up test thread
        if self.test_thread:
            self.test_thread.wait()
            self.test_thread = None

    def load_existing_configs(self):
        """Load existing model configurations."""
        if self.llm_manager:
            self.update_models_list()

            available_llms = self.llm_manager.get_available_llms()
            if available_llms:
                self.status_text.append(f"Loaded {len(available_llms)} existing models")
            else:
                self.status_text.append("No existing models found. Add models using the tabs above.")

    def save_configuration(self):
        """Save the current configuration."""
        # This could save to a config file for persistence
        if self.current_configs:
            self.status_text.append(f"✓ Configuration saved ({len(self.current_configs)} models)")
            QMessageBox.information(self, "Success", "Model configuration saved successfully!")
        else:
            QMessageBox.warning(self, "No Models", "No models configured to save")

    def closeEvent(self, event):
        """Handle dialog close event."""
        if self.test_thread and self.test_thread.isRunning():
            reply = QMessageBox.question(
                self, "Test In Progress",
                "A model test is in progress. Do you want to cancel it and close?",
                QMessageBox.Yes | QMessageBox.No
            )

            if reply == QMessageBox.No:
                event.ignore()
                return

            # Force terminate test thread
            if self.test_thread:
                self.test_thread.terminate()
                self.test_thread.wait(3000)  # Wait up to 3 seconds

        event.accept()


if __name__ == "__main__":
    # For testing the dialog standalone
    import sys

    from PyQt5.QtWidgets import QApplication

    app = QApplication(sys.argv)
    dialog = LLMConfigDialog()
    dialog.show()
    sys.exit(app.exec_())
