"""LLM configuration dialog for AI model settings."""

import logging
import os
import time

from intellicrack.handlers.pyqt6_handler import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFont,
    QFormLayout,
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
    Qt,
    QTabWidget,
    QTextEdit,
    QThread,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)
from intellicrack.utils.logger import logger

from ...utils.env_file_manager import EnvFileManager
from ...utils.secrets_manager import get_secret
from .base_dialog import BaseDialog

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

# Local imports
try:
    from ...ai.llm_backends import (
        LLMConfig,
        LLMManager,
        create_anthropic_config,
        create_gguf_config,
        create_gptq_config,
        create_huggingface_local_config,
        create_ollama_config,
        create_onnx_config,
        create_openai_config,
        create_pytorch_config,
        create_safetensors_config,
        create_tensorflow_config,
        get_llm_manager,
    )
    from ...ai.llm_config_manager import get_llm_config_manager
    from ...utils.logger import get_logger
except ImportError as e:
    logger.error("Import error in llm_config_dialog: %s", e)
    LLMManager = None
    get_llm_manager = None
    get_llm_config_manager = None


logger = get_logger(__name__) if "get_logger" in globals() else logging.getLogger(__name__)


class ModelTestThread(QThread):
    """Thread for testing model configurations."""

    #: success, message (type: bool, str)
    validation_complete = pyqtSignal(bool, str)
    #: progress message (type: str)
    validation_progress = pyqtSignal(str)

    def __init__(self, config: "LLMConfig"):
        """Initialize the ModelTestThread with default values."""
        super().__init__()
        self.config = config

    def run(self):
        """Test the model configuration."""
        try:
            self.validation_progress.emit("Initializing model backend...")

            # Create temporary LLM manager for testing
            if not get_llm_manager:
                self.validation_complete.emit(False, "LLM Manager not available")
                return

            llm_manager = get_llm_manager()

            # Register test configuration
            validation_id = f"validation_{self.config.provider.value}_{int(time.time())}"
            self.validation_progress.emit(f"Testing {self.config.provider.value} model...")

            success = llm_manager.register_llm(validation_id, self.config)

            if success:
                self.validation_progress.emit("Sending test message...")

                # Send a simple test message
                from ...ai.llm_backends import LLMMessage

                validation_messages = [
                    LLMMessage(
                        role="user",
                        content="Hello! Please respond with 'Test successful' to confirm the connection.",
                    ),
                ]

                response = llm_manager.chat(validation_messages, validation_id)

                if response and response.content:
                    self.validation_complete.emit(True, f"✓ Model test successful!\nResponse: {response.content[:100]}...")
                else:
                    self.validation_complete.emit(False, "Model loaded but failed to generate response")
            else:
                self.validation_complete.emit(False, "Failed to initialize model backend")

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in llm_config_dialog: %s", e)
            self.validation_complete.emit(False, f"Test failed: {e!s}")


class LLMConfigDialog(BaseDialog):
    """Dialog for configuring LLM models in Intellicrack."""

    def __init__(self, parent=None):
        """Initialize the LLMConfigDialog with default values."""
        # Initialize EnvFileManager
        self.env_manager = EnvFileManager()

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

        # PyTorch attributes
        self.pytorch_model_path = None
        self.pytorch_model_name = None
        self.pytorch_device = None
        self.pytorch_temp = None
        self.pytorch_max_tokens = None

        # TensorFlow attributes
        self.tensorflow_model_path = None
        self.tensorflow_model_name = None
        self.tensorflow_device = None
        self.tensorflow_temp = None
        self.tensorflow_max_tokens = None

        # ONNX attributes
        self.onnx_model_path = None
        self.onnx_model_name = None
        self.onnx_providers = None
        self.onnx_temp = None
        self.onnx_max_tokens = None

        # Safetensors attributes
        self.safetensors_model_path = None
        self.safetensors_model_name = None
        self.safetensors_device = None
        self.safetensors_temp = None
        self.safetensors_max_tokens = None

        # GPTQ attributes
        self.gptq_model_path = None
        self.gptq_model_name = None
        self.gptq_device = None
        self.gptq_temp = None
        self.gptq_max_tokens = None

        # AWQ attributes

        # Hugging Face Local attributes
        self.huggingface_model_path = None
        self.huggingface_model_name = None
        self.huggingface_device = None
        self.huggingface_temp = None
        self.huggingface_max_tokens = None

        # LoRA adapter attributes
        self.lora_base_model = None
        self.lora_adapter_path = None
        self.lora_adapter_name = None
        self.lora_merge_adapter = None
        self.lora_adapter_type = None
        self.lora_rank = None
        self.lora_alpha = None
        self.lora_dropout = None

        super().__init__(parent, "LLM Model Configuration - Intellicrack Agentic AI")
        self.setFixedSize(800, 600)

        self.llm_manager = get_llm_manager() if get_llm_manager else None
        self.config_manager = get_llm_config_manager() if get_llm_config_manager else None
        self.current_configs = {}
        self.validation_thread = None

        self.setup_content(self.content_widget.layout() or QVBoxLayout(self.content_widget))
        self.load_existing_configs()
        self.load_existing_api_keys()  # Load API keys from .env file

        # Auto-load saved models
        if self.config_manager and self.llm_manager:
            loaded, failed = self.config_manager.auto_load_models(self.llm_manager)
            if loaded > 0:
                self.status_text.append(f"✓ Auto-loaded {loaded} saved models")
            if failed > 0:
                self.status_text.append(f"⚠ Failed to load {failed} models")

    def setup_content(self, layout):
        """Set up the user interface content."""
        if layout is None:
            layout = QVBoxLayout(self.content_widget)

        # Title and description
        title_label = QLabel("🤖 Agentic AI Model Configuration")
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        desc_label = QLabel("Configure LLM models for intelligent analysis and reasoning in Intellicrack")
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setObjectName("descriptionText")
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
        self.setup_pytorch_tab()
        self.setup_tensorflow_tab()
        self.setup_onnx_tab()
        self.setup_safetensors_tab()
        self.setup_gptq_tab()
        self.setup_huggingface_tab()
        self.setup_lora_tab()

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
        self.validate_model_btn = QPushButton("Test")

        self.set_active_btn.clicked.connect(self.set_active_model)
        self.remove_model_btn.clicked.connect(self.remove_model)
        self.validate_model_btn.clicked.connect(self.validate_selected_model)

        actions_layout.addWidget(self.set_active_btn)
        actions_layout.addWidget(self.validate_model_btn)
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
        self.openai_api_key.setToolTip("Enter your OpenAI API key starting with sk-")
        layout.addRow("API Key:", self.openai_api_key)

        # Model selection
        self.openai_model = QComboBox()
        self.openai_model.addItems(
            [
                "gpt-4",
                "gpt-4-turbo-preview",
                "gpt-4o",
                "gpt-3.5-turbo",
                "gpt-3.5-turbo-16k",
            ]
        )
        layout.addRow("Model:", self.openai_model)

        # Custom base URL
        self.openai_base_url = QLineEdit()
        self.openai_base_url.setText("https://api.openai.com/v1")
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
        test_config_btn = QPushButton("Test Configuration")
        test_key_btn = QPushButton("Test API Key")

        add_btn.clicked.connect(self.add_openai_model)
        test_config_btn.clicked.connect(self.test_openai_config)
        test_key_btn.clicked.connect(lambda: self.test_api_key("openai", self.openai_api_key))

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(test_config_btn)
        btn_layout.addWidget(test_key_btn)
        layout.addRow("", btn_layout)

        self.tabs.addTab(tab, "OpenAI")

    def setup_anthropic_tab(self):
        """Set up Anthropic configuration tab."""
        tab = QWidget()
        layout = QFormLayout(tab)

        # API Key
        self.anthropic_api_key = QLineEdit()
        self.anthropic_api_key.setEchoMode(QLineEdit.Password)
        self.anthropic_api_key.setToolTip("Enter your Anthropic API key starting with sk-ant-")
        layout.addRow("API Key:", self.anthropic_api_key)

        # Model selection
        self.anthropic_model = QComboBox()
        self.anthropic_model.addItems(
            [
                "claude-3-5-sonnet-20241022",
                "claude-3-opus-20240229",
                "claude-3-sonnet-20240229",
                "claude-3-haiku-20240307",
                "claude-2.1",
                "claude-instant-1.2",
            ]
        )
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
        test_config_btn = QPushButton("Test Configuration")
        test_key_btn = QPushButton("Test API Key")

        add_btn.clicked.connect(self.add_anthropic_model)
        test_config_btn.clicked.connect(self.test_anthropic_config)
        test_key_btn.clicked.connect(lambda: self.test_api_key("anthropic", self.anthropic_api_key))

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(test_config_btn)
        btn_layout.addWidget(test_key_btn)
        layout.addRow("", btn_layout)

        self.tabs.addTab(tab, "Anthropic")

    def setup_gguf_tab(self):
        """Set up GGUF model configuration tab."""
        tab = QWidget()
        layout = QFormLayout(tab)

        # Model file selection
        model_layout = QHBoxLayout()
        self.gguf_model_path = QLineEdit()
        self.gguf_model_path.setToolTip("Path to GGUF model file")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_gguf_model)

        model_layout.addWidget(self.gguf_model_path)
        model_layout.addWidget(browse_btn)
        layout.addRow("Model File:", model_layout)

        # Model name
        self.gguf_model_name = QLineEdit()
        self.gguf_model_name.setToolTip("Custom model name (optional)")
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
        info_text.setObjectName("infoText")
        layout.addRow("", info_text)

        self.tabs.addTab(tab, "GGUF Models")

    def setup_ollama_tab(self):
        """Set up Ollama configuration tab."""
        tab = QWidget()
        layout = QFormLayout(tab)

        # Server URL
        self.ollama_url = QLineEdit()
        self.ollama_url.setText(get_secret("OLLAMA_API_BASE", "http://localhost:11434"))
        layout.addRow("Server URL:", self.ollama_url)

        # Model name
        self.ollama_model = QLineEdit()
        self.ollama_model.setToolTip("Examples: llama2, codellama, mistral")
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
        info_text.setObjectName("infoText")
        layout.addRow("", info_text)

        self.tabs.addTab(tab, "Ollama")

    def setup_pytorch_tab(self):
        """Set up PyTorch model configuration tab."""
        tab = QWidget()
        layout = QFormLayout(tab)

        # Model file/directory selection
        model_layout = QHBoxLayout()
        self.pytorch_model_path = QLineEdit()
        self.pytorch_model_path.setToolTip("Path to PyTorch model file or directory")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_pytorch_model)

        model_layout.addWidget(self.pytorch_model_path)
        model_layout.addWidget(browse_btn)
        layout.addRow("Model Path:", model_layout)

        # Model name
        self.pytorch_model_name = QLineEdit()
        self.pytorch_model_name.setToolTip("Custom model name (optional)")
        layout.addRow("Model Name:", self.pytorch_model_name)

        # Device selection
        self.pytorch_device = QComboBox()
        self.pytorch_device.addItems(["cpu", "cuda", "mps"])
        layout.addRow("Device:", self.pytorch_device)

        # Temperature
        self.pytorch_temp = QDoubleSpinBox()
        self.pytorch_temp.setRange(0.0, 2.0)
        self.pytorch_temp.setSingleStep(0.1)
        self.pytorch_temp.setValue(0.7)
        layout.addRow("Temperature:", self.pytorch_temp)

        # Max tokens
        self.pytorch_max_tokens = QSpinBox()
        self.pytorch_max_tokens.setRange(1, 8192)
        self.pytorch_max_tokens.setValue(2048)
        layout.addRow("Max Tokens:", self.pytorch_max_tokens)

        # Add/Test buttons
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add PyTorch Model")
        test_btn = QPushButton("Test Configuration")

        add_btn.clicked.connect(self.add_pytorch_model)
        test_btn.clicked.connect(self.test_pytorch_config)

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(test_btn)
        layout.addRow("", btn_layout)

        # Requirements info
        info_text = QLabel("Supports: .pth, .pt, .bin files or Hugging Face model directories")
        info_text.setObjectName("infoText")
        layout.addRow("", info_text)

        self.tabs.addTab(tab, "PyTorch")

    def setup_tensorflow_tab(self):
        """Set up TensorFlow model configuration tab."""
        tab = QWidget()
        layout = QFormLayout(tab)

        # Model file/directory selection
        model_layout = QHBoxLayout()
        self.tensorflow_model_path = QLineEdit()
        self.tensorflow_model_path.setToolTip("Path to TensorFlow model file or directory")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_tensorflow_model)

        model_layout.addWidget(self.tensorflow_model_path)
        model_layout.addWidget(browse_btn)
        layout.addRow("Model Path:", model_layout)

        # Model name
        self.tensorflow_model_name = QLineEdit()
        self.tensorflow_model_name.setToolTip("Custom model name (optional)")
        layout.addRow("Model Name:", self.tensorflow_model_name)

        # Device selection
        self.tensorflow_device = QComboBox()
        self.tensorflow_device.addItems(["cpu", "gpu"])
        layout.addRow("Device:", self.tensorflow_device)

        # Temperature
        self.tensorflow_temp = QDoubleSpinBox()
        self.tensorflow_temp.setRange(0.0, 2.0)
        self.tensorflow_temp.setSingleStep(0.1)
        self.tensorflow_temp.setValue(0.7)
        layout.addRow("Temperature:", self.tensorflow_temp)

        # Max tokens
        self.tensorflow_max_tokens = QSpinBox()
        self.tensorflow_max_tokens.setRange(1, 8192)
        self.tensorflow_max_tokens.setValue(2048)
        layout.addRow("Max Tokens:", self.tensorflow_max_tokens)

        # Add/Test buttons
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add TensorFlow Model")
        test_btn = QPushButton("Test Configuration")

        add_btn.clicked.connect(self.add_tensorflow_model)
        test_btn.clicked.connect(self.test_tensorflow_config)

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(test_btn)
        layout.addRow("", btn_layout)

        # Requirements info
        info_text = QLabel("Supports: .h5 files or SavedModel directories")
        info_text.setObjectName("infoText")
        layout.addRow("", info_text)

        self.tabs.addTab(tab, "TensorFlow")

    def setup_onnx_tab(self):
        """Set up ONNX model configuration tab."""
        tab = QWidget()
        layout = QFormLayout(tab)

        # Model file selection
        model_layout = QHBoxLayout()
        self.onnx_model_path = QLineEdit()
        self.onnx_model_path.setToolTip("Path to ONNX model file")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_onnx_model)

        model_layout.addWidget(self.onnx_model_path)
        model_layout.addWidget(browse_btn)
        layout.addRow("Model File:", model_layout)

        # Model name
        self.onnx_model_name = QLineEdit()
        self.onnx_model_name.setToolTip("Custom model name (optional)")
        layout.addRow("Model Name:", self.onnx_model_name)

        # Provider selection
        self.onnx_providers = QComboBox()
        self.onnx_providers.addItems(["CPUExecutionProvider", "CUDAExecutionProvider", "TensorrtExecutionProvider"])
        layout.addRow("Provider:", self.onnx_providers)

        # Temperature
        self.onnx_temp = QDoubleSpinBox()
        self.onnx_temp.setRange(0.0, 2.0)
        self.onnx_temp.setSingleStep(0.1)
        self.onnx_temp.setValue(0.7)
        layout.addRow("Temperature:", self.onnx_temp)

        # Max tokens
        self.onnx_max_tokens = QSpinBox()
        self.onnx_max_tokens.setRange(1, 8192)
        self.onnx_max_tokens.setValue(2048)
        layout.addRow("Max Tokens:", self.onnx_max_tokens)

        # Add/Test buttons
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add ONNX Model")
        test_btn = QPushButton("Test Configuration")

        add_btn.clicked.connect(self.add_onnx_model)
        test_btn.clicked.connect(self.test_onnx_config)

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(test_btn)
        layout.addRow("", btn_layout)

        # Requirements info
        info_text = QLabel("Requires: onnxruntime or onnxruntime-gpu")
        info_text.setObjectName("infoText")
        layout.addRow("", info_text)

        self.tabs.addTab(tab, "ONNX")

    def setup_safetensors_tab(self):
        """Set up Safetensors model configuration tab."""
        tab = QWidget()
        layout = QFormLayout(tab)

        # Model file/directory selection
        model_layout = QHBoxLayout()
        self.safetensors_model_path = QLineEdit()
        self.safetensors_model_path.setToolTip("Path to Safetensors model file or directory")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_safetensors_model)

        model_layout.addWidget(self.safetensors_model_path)
        model_layout.addWidget(browse_btn)
        layout.addRow("Model Path:", model_layout)

        # Model name
        self.safetensors_model_name = QLineEdit()
        self.safetensors_model_name.setToolTip("Custom model name (optional)")
        layout.addRow("Model Name:", self.safetensors_model_name)

        # Device selection
        self.safetensors_device = QComboBox()
        self.safetensors_device.addItems(["cpu", "cuda", "mps"])
        layout.addRow("Device:", self.safetensors_device)

        # Temperature
        self.safetensors_temp = QDoubleSpinBox()
        self.safetensors_temp.setRange(0.0, 2.0)
        self.safetensors_temp.setSingleStep(0.1)
        self.safetensors_temp.setValue(0.7)
        layout.addRow("Temperature:", self.safetensors_temp)

        # Max tokens
        self.safetensors_max_tokens = QSpinBox()
        self.safetensors_max_tokens.setRange(1, 8192)
        self.safetensors_max_tokens.setValue(2048)
        layout.addRow("Max Tokens:", self.safetensors_max_tokens)

        # Add/Test buttons
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add Safetensors Model")
        test_btn = QPushButton("Test Configuration")

        add_btn.clicked.connect(self.add_safetensors_model)
        test_btn.clicked.connect(self.test_safetensors_config)

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(test_btn)
        layout.addRow("", btn_layout)

        # Requirements info
        info_text = QLabel("Supports: .safetensors files with model configs")
        info_text.setObjectName("infoText")
        layout.addRow("", info_text)

        self.tabs.addTab(tab, "Safetensors")

    def setup_gptq_tab(self):
        """Set up GPTQ model configuration tab."""
        tab = QWidget()
        layout = QFormLayout(tab)

        # Model directory selection
        model_layout = QHBoxLayout()
        self.gptq_model_path = QLineEdit()
        self.gptq_model_path.setToolTip("Path to GPTQ model directory")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_gptq_model)

        model_layout.addWidget(self.gptq_model_path)
        model_layout.addWidget(browse_btn)
        layout.addRow("Model Directory:", model_layout)

        # Model name
        self.gptq_model_name = QLineEdit()
        self.gptq_model_name.setToolTip("Custom model name (optional)")
        layout.addRow("Model Name:", self.gptq_model_name)

        # Device selection
        self.gptq_device = QComboBox()
        self.gptq_device.addItems(["cuda"])  # GPTQ typically requires CUDA
        layout.addRow("Device:", self.gptq_device)

        # Temperature
        self.gptq_temp = QDoubleSpinBox()
        self.gptq_temp.setRange(0.0, 2.0)
        self.gptq_temp.setSingleStep(0.1)
        self.gptq_temp.setValue(0.7)
        layout.addRow("Temperature:", self.gptq_temp)

        # Max tokens
        self.gptq_max_tokens = QSpinBox()
        self.gptq_max_tokens.setRange(1, 8192)
        self.gptq_max_tokens.setValue(2048)
        layout.addRow("Max Tokens:", self.gptq_max_tokens)

        # Add/Test buttons
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add GPTQ Model")
        test_btn = QPushButton("Test Configuration")

        add_btn.clicked.connect(self.add_gptq_model)
        test_btn.clicked.connect(self.test_gptq_config)

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(test_btn)
        layout.addRow("", btn_layout)

        # Requirements info
        info_text = QLabel("Requires: auto-gptq and CUDA GPU")
        info_text.setObjectName("infoText")
        layout.addRow("", info_text)

        self.tabs.addTab(tab, "GPTQ")

    def setup_huggingface_tab(self):
        """Set up Hugging Face local model configuration tab."""
        tab = QWidget()
        layout = QFormLayout(tab)

        # Model directory selection
        model_layout = QHBoxLayout()
        self.huggingface_model_path = QLineEdit()
        self.huggingface_model_path.setToolTip("Path to Hugging Face model directory")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_huggingface_model)

        model_layout.addWidget(self.huggingface_model_path)
        model_layout.addWidget(browse_btn)
        layout.addRow("Model Directory:", model_layout)

        # Model name
        self.huggingface_model_name = QLineEdit()
        self.huggingface_model_name.setToolTip("Custom model name (optional)")
        layout.addRow("Model Name:", self.huggingface_model_name)

        # Device selection
        self.huggingface_device = QComboBox()
        self.huggingface_device.addItems(["cpu", "cuda", "mps"])
        layout.addRow("Device:", self.huggingface_device)

        # Temperature
        self.huggingface_temp = QDoubleSpinBox()
        self.huggingface_temp.setRange(0.0, 2.0)
        self.huggingface_temp.setSingleStep(0.1)
        self.huggingface_temp.setValue(0.7)
        layout.addRow("Temperature:", self.huggingface_temp)

        # Max tokens
        self.huggingface_max_tokens = QSpinBox()
        self.huggingface_max_tokens.setRange(1, 8192)
        self.huggingface_max_tokens.setValue(2048)
        layout.addRow("Max Tokens:", self.huggingface_max_tokens)

        # Add/Test buttons
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add HF Model")
        test_btn = QPushButton("Test Configuration")

        add_btn.clicked.connect(self.add_huggingface_model)
        test_btn.clicked.connect(self.test_huggingface_config)

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(test_btn)
        layout.addRow("", btn_layout)

        # Requirements info
        info_text = QLabel("Supports: Local Hugging Face model directories with config.json")
        info_text.setObjectName("infoText")
        layout.addRow("", info_text)

        self.tabs.addTab(tab, "HF Local")

    def setup_lora_tab(self):
        """Set up LoRA adapter configuration tab."""
        tab = QWidget()
        layout = QFormLayout(tab)

        # Base model selection
        model_layout = QHBoxLayout()
        self.lora_base_model = QComboBox()
        self.lora_base_model.setEditable(True)
        self.lora_base_model.setToolTip("Select or enter base model ID")

        # Populate with registered models
        if self.llm_manager:
            model_ids = list(self.llm_manager.backends.keys())
            self.lora_base_model.addItems(model_ids)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_lora_models)

        model_layout.addWidget(self.lora_base_model)
        model_layout.addWidget(refresh_btn)
        layout.addRow("Base Model:", model_layout)

        # Adapter path selection
        adapter_layout = QHBoxLayout()
        self.lora_adapter_path = QLineEdit()
        self.lora_adapter_path.setToolTip("Path to LoRA adapter directory")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_lora_adapter)

        adapter_layout.addWidget(self.lora_adapter_path)
        adapter_layout.addWidget(browse_btn)
        layout.addRow("Adapter Path:", adapter_layout)

        # Adapter name
        self.lora_adapter_name = QLineEdit()
        self.lora_adapter_name.setToolTip("Adapter name (optional)")
        self.lora_adapter_name.setText("default")
        layout.addRow("Adapter Name:", self.lora_adapter_name)

        # Adapter type
        self.lora_adapter_type = QComboBox()
        self.lora_adapter_type.addItems(["lora", "qlora", "adalora"])
        layout.addRow("Adapter Type:", self.lora_adapter_type)

        # LoRA parameters
        self.lora_rank = QSpinBox()
        self.lora_rank.setRange(1, 256)
        self.lora_rank.setValue(16)
        layout.addRow("LoRA Rank (r):", self.lora_rank)

        self.lora_alpha = QSpinBox()
        self.lora_alpha.setRange(1, 256)
        self.lora_alpha.setValue(32)
        layout.addRow("LoRA Alpha:", self.lora_alpha)

        self.lora_dropout = QDoubleSpinBox()
        self.lora_dropout.setRange(0.0, 1.0)
        self.lora_dropout.setSingleStep(0.05)
        self.lora_dropout.setValue(0.1)
        layout.addRow("Dropout:", self.lora_dropout)

        # Merge option
        self.lora_merge_adapter = QCheckBox("Merge adapter into base model")
        layout.addRow("", self.lora_merge_adapter)

        # Add/Test buttons
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Load LoRA Adapter")
        test_btn = QPushButton("Test Adapter")
        create_btn = QPushButton("Create New Adapter")

        add_btn.clicked.connect(self.add_lora_adapter)
        test_btn.clicked.connect(self.test_lora_adapter)
        create_btn.clicked.connect(self.create_lora_adapter)

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(test_btn)
        btn_layout.addWidget(create_btn)
        layout.addRow("", btn_layout)

        # Requirements info
        info_text = QLabel("Requires: PEFT library and a compatible base model")
        info_text.setObjectName("infoText")
        layout.addRow("", info_text)

        self.tabs.addTab(tab, "LoRA Adapters")

    def browse_gguf_model(self):
        """Browse for GGUF model file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select GGUF Model File",
            "",
            "GGUF Files (*.gguf);;All Files (*)",
        )

        if file_path:
            self.gguf_model_path.setText(file_path)
            # Auto-fill model name if empty
            if not self.gguf_model_name.text():
                model_name = os.path.splitext(os.path.basename(file_path))[0]
                self.gguf_model_name.setText(model_name)

    def browse_pytorch_model(self):
        """Browse for PyTorch model file or directory."""
        options = QFileDialog.Options()
        path = (
            QFileDialog.getExistingDirectory(self, "Select PyTorch Model Directory")
            or QFileDialog.getOpenFileName(
                self,
                "Select PyTorch Model File",
                "",
                "PyTorch Files (*.pth *.pt *.bin);;All Files (*)",
                options=options,
            )[0]
        )

        if path:
            self.pytorch_model_path.setText(path)
            if not self.pytorch_model_name.text():
                model_name = os.path.basename(path).replace(".pth", "").replace(".pt", "").replace(".bin", "")
                self.pytorch_model_name.setText(model_name)

    def browse_tensorflow_model(self):
        """Browse for TensorFlow model file or directory."""
        options = QFileDialog.Options()
        path = (
            QFileDialog.getExistingDirectory(self, "Select TensorFlow SavedModel Directory")
            or QFileDialog.getOpenFileName(
                self,
                "Select TensorFlow Model File",
                "",
                "TensorFlow Files (*.h5);;All Files (*)",
                options=options,
            )[0]
        )

        if path:
            self.tensorflow_model_path.setText(path)
            if not self.tensorflow_model_name.text():
                model_name = os.path.basename(path).replace(".h5", "")
                self.tensorflow_model_name.setText(model_name)

    def browse_onnx_model(self):
        """Browse for ONNX model file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select ONNX Model File",
            "",
            "ONNX Files (*.onnx);;All Files (*)",
        )

        if file_path:
            self.onnx_model_path.setText(file_path)
            if not self.onnx_model_name.text():
                model_name = os.path.splitext(os.path.basename(file_path))[0]
                self.onnx_model_name.setText(model_name)

    def browse_safetensors_model(self):
        """Browse for Safetensors model file or directory."""
        options = QFileDialog.Options()
        path = (
            QFileDialog.getExistingDirectory(self, "Select Safetensors Model Directory")
            or QFileDialog.getOpenFileName(
                self,
                "Select Safetensors Model File",
                "",
                "Safetensors Files (*.safetensors);;All Files (*)",
                options=options,
            )[0]
        )

        if path:
            self.safetensors_model_path.setText(path)
            if not self.safetensors_model_name.text():
                model_name = os.path.basename(path).replace(".safetensors", "")
                self.safetensors_model_name.setText(model_name)

    def browse_gptq_model(self):
        """Browse for GPTQ model directory."""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select GPTQ Model Directory",
        )

        if directory:
            self.gptq_model_path.setText(directory)
            if not self.gptq_model_name.text():
                model_name = os.path.basename(directory)
                self.gptq_model_name.setText(model_name)

    def browse_huggingface_model(self):
        """Browse for Hugging Face model directory."""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Hugging Face Model Directory",
        )

        if directory:
            self.huggingface_model_path.setText(directory)
            if not self.huggingface_model_name.text():
                model_name = os.path.basename(directory)
                self.huggingface_model_name.setText(model_name)

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
            tools_enabled=self.openai_tools.isChecked(),
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
            tools_enabled=self.anthropic_tools.isChecked(),
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
            tools_enabled=self.gguf_tools.isChecked(),
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
            max_tokens=self.ollama_max_tokens.value(),
        )

        model_id = f"ollama_{self.ollama_model.text().strip().replace(':', '_')}"
        self.register_model(model_id, config)

    def add_pytorch_model(self):
        """Add PyTorch model configuration."""
        if not self.pytorch_model_path.text().strip():
            QMessageBox.warning(self, "Missing Model Path", "Please select a PyTorch model file or directory")
            return

        if not os.path.exists(self.pytorch_model_path.text()):
            QMessageBox.warning(self, "Path Not Found", "The selected model path does not exist")
            return

        model_name = self.pytorch_model_name.text().strip()
        if not model_name:
            model_name = os.path.basename(self.pytorch_model_path.text()).replace(".pth", "").replace(".pt", "").replace(".bin", "")

        config = create_pytorch_config(
            model_path=self.pytorch_model_path.text(),
            model_name=model_name,
            temperature=self.pytorch_temp.value(),
            max_tokens=self.pytorch_max_tokens.value(),
            device=self.pytorch_device.currentText(),
        )

        model_id = f"pytorch_{model_name.replace(' ', '_').replace('-', '_')}"
        self.register_model(model_id, config)

    def add_tensorflow_model(self):
        """Add TensorFlow model configuration."""
        if not self.tensorflow_model_path.text().strip():
            QMessageBox.warning(self, "Missing Model Path", "Please select a TensorFlow model file or directory")
            return

        if not os.path.exists(self.tensorflow_model_path.text()):
            QMessageBox.warning(self, "Path Not Found", "The selected model path does not exist")
            return

        model_name = self.tensorflow_model_name.text().strip()
        if not model_name:
            model_name = os.path.basename(self.tensorflow_model_path.text()).replace(".h5", "")

        config = create_tensorflow_config(
            model_path=self.tensorflow_model_path.text(),
            model_name=model_name,
            temperature=self.tensorflow_temp.value(),
            max_tokens=self.tensorflow_max_tokens.value(),
            device=self.tensorflow_device.currentText(),
        )

        model_id = f"tensorflow_{model_name.replace(' ', '_').replace('-', '_')}"
        self.register_model(model_id, config)

    def add_onnx_model(self):
        """Add ONNX model configuration."""
        if not self.onnx_model_path.text().strip():
            QMessageBox.warning(self, "Missing Model File", "Please select an ONNX model file")
            return

        if not os.path.exists(self.onnx_model_path.text()):
            QMessageBox.warning(self, "File Not Found", "The selected ONNX file does not exist")
            return

        model_name = self.onnx_model_name.text().strip()
        if not model_name:
            model_name = os.path.splitext(os.path.basename(self.onnx_model_path.text()))[0]

        config = create_onnx_config(
            model_path=self.onnx_model_path.text(),
            model_name=model_name,
            temperature=self.onnx_temp.value(),
            max_tokens=self.onnx_max_tokens.value(),
            providers=[self.onnx_providers.currentText()],
        )

        model_id = f"onnx_{model_name.replace(' ', '_').replace('-', '_')}"
        self.register_model(model_id, config)

    def add_safetensors_model(self):
        """Add Safetensors model configuration."""
        if not self.safetensors_model_path.text().strip():
            QMessageBox.warning(self, "Missing Model Path", "Please select a Safetensors model file or directory")
            return

        if not os.path.exists(self.safetensors_model_path.text()):
            QMessageBox.warning(self, "Path Not Found", "The selected model path does not exist")
            return

        model_name = self.safetensors_model_name.text().strip()
        if not model_name:
            model_name = os.path.basename(self.safetensors_model_path.text()).replace(".safetensors", "")

        config = create_safetensors_config(
            model_path=self.safetensors_model_path.text(),
            model_name=model_name,
            temperature=self.safetensors_temp.value(),
            max_tokens=self.safetensors_max_tokens.value(),
            device=self.safetensors_device.currentText(),
        )

        model_id = f"safetensors_{model_name.replace(' ', '_').replace('-', '_')}"
        self.register_model(model_id, config)

    def add_gptq_model(self):
        """Add GPTQ model configuration."""
        if not self.gptq_model_path.text().strip():
            QMessageBox.warning(self, "Missing Model Directory", "Please select a GPTQ model directory")
            return

        if not os.path.exists(self.gptq_model_path.text()):
            QMessageBox.warning(self, "Directory Not Found", "The selected model directory does not exist")
            return

        model_name = self.gptq_model_name.text().strip()
        if not model_name:
            model_name = os.path.basename(self.gptq_model_path.text())

        config = create_gptq_config(
            model_path=self.gptq_model_path.text(),
            model_name=model_name,
            temperature=self.gptq_temp.value(),
            max_tokens=self.gptq_max_tokens.value(),
            device=self.gptq_device.currentText(),
        )

        model_id = f"gptq_{model_name.replace(' ', '_').replace('-', '_')}"
        self.register_model(model_id, config)

    def add_huggingface_model(self):
        """Add Hugging Face local model configuration."""
        if not self.huggingface_model_path.text().strip():
            QMessageBox.warning(self, "Missing Model Directory", "Please select a Hugging Face model directory")
            return

        if not os.path.exists(self.huggingface_model_path.text()):
            QMessageBox.warning(self, "Directory Not Found", "The selected model directory does not exist")
            return

        model_name = self.huggingface_model_name.text().strip()
        if not model_name:
            model_name = os.path.basename(self.huggingface_model_path.text())

        config = create_huggingface_local_config(
            model_path=self.huggingface_model_path.text(),
            model_name=model_name,
            temperature=self.huggingface_temp.value(),
            max_tokens=self.huggingface_max_tokens.value(),
            device=self.huggingface_device.currentText(),
        )

        model_id = f"huggingface_{model_name.replace(' ', '_').replace('-', '_')}"
        self.register_model(model_id, config)

    def register_model(self, model_id: str, config: LLMConfig):
        """Register a model with the LLM manager."""
        if not self.llm_manager:
            QMessageBox.critical(self, "Error", "LLM Manager not available")
            return

        success = self.llm_manager.register_llm(model_id, config)

        if success:
            self.current_configs[model_id] = config

            # Save to configuration manager
            if self.config_manager:
                metadata = {
                    "auto_load": True,
                    "created_by": "llm_config_dialog",
                }
                self.config_manager.save_model_config(model_id, config, metadata)

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
            self,
            "Remove Model",
            f"Are you sure you want to remove model: {model_id}?",
            QMessageBox.Yes | QMessageBox.No,
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
            api_base=self.openai_base_url.text().strip() or None,
        )
        self.test_model_config(config)

    def test_anthropic_config(self):
        """Test Anthropic configuration."""
        if not self.anthropic_api_key.text().strip():
            QMessageBox.warning(self, "Missing API Key", "Please enter your Anthropic API key")
            return

        config = create_anthropic_config(
            model_name=self.anthropic_model.currentText(),
            api_key=self.anthropic_api_key.text().strip(),
        )
        self.test_model_config(config)

    def test_gguf_config(self):
        """Test GGUF configuration."""
        if not self.gguf_model_path.text().strip():
            QMessageBox.warning(self, "Missing Model File", "Please select a GGUF model file")
            return

        config = create_gguf_config(
            model_path=self.gguf_model_path.text(),
            model_name=self.gguf_model_name.text() or "test_model",
        )
        self.test_model_config(config)

    def test_ollama_config(self):
        """Test Ollama configuration."""
        if not self.ollama_model.text().strip():
            QMessageBox.warning(self, "Missing Model Name", "Please enter the Ollama model name")
            return

        config = create_ollama_config(
            model_name=self.ollama_model.text().strip(),
            api_base=self.ollama_url.text().strip(),
        )
        self.test_model_config(config)

    def test_pytorch_config(self):
        """Test PyTorch configuration."""
        if not self.pytorch_model_path.text().strip():
            QMessageBox.warning(self, "Missing Model Path", "Please select a PyTorch model file or directory")
            return

        config = create_pytorch_config(
            model_path=self.pytorch_model_path.text(),
            model_name=self.pytorch_model_name.text() or "test_model",
            device=self.pytorch_device.currentText(),
        )
        self.test_model_config(config)

    def test_tensorflow_config(self):
        """Test TensorFlow configuration."""
        if not self.tensorflow_model_path.text().strip():
            QMessageBox.warning(self, "Missing Model Path", "Please select a TensorFlow model file or directory")
            return

        config = create_tensorflow_config(
            model_path=self.tensorflow_model_path.text(),
            model_name=self.tensorflow_model_name.text() or "test_model",
            device=self.tensorflow_device.currentText(),
        )
        self.test_model_config(config)

    def test_onnx_config(self):
        """Test ONNX configuration."""
        if not self.onnx_model_path.text().strip():
            QMessageBox.warning(self, "Missing Model File", "Please select an ONNX model file")
            return

        config = create_onnx_config(
            model_path=self.onnx_model_path.text(),
            model_name=self.onnx_model_name.text() or "test_model",
            providers=[self.onnx_providers.currentText()],
        )
        self.test_model_config(config)

    def test_safetensors_config(self):
        """Test Safetensors configuration."""
        if not self.safetensors_model_path.text().strip():
            QMessageBox.warning(self, "Missing Model Path", "Please select a Safetensors model file or directory")
            return

        config = create_safetensors_config(
            model_path=self.safetensors_model_path.text(),
            model_name=self.safetensors_model_name.text() or "test_model",
            device=self.safetensors_device.currentText(),
        )
        self.test_model_config(config)

    def test_gptq_config(self):
        """Test GPTQ configuration."""
        if not self.gptq_model_path.text().strip():
            QMessageBox.warning(self, "Missing Model Directory", "Please select a GPTQ model directory")
            return

        config = create_gptq_config(
            model_path=self.gptq_model_path.text(),
            model_name=self.gptq_model_name.text() or "test_model",
            device=self.gptq_device.currentText(),
        )
        self.test_model_config(config)

    def test_huggingface_config(self):
        """Test Hugging Face local configuration."""
        if not self.huggingface_model_path.text().strip():
            QMessageBox.warning(self, "Missing Model Directory", "Please select a Hugging Face model directory")
            return

        config = create_huggingface_local_config(
            model_path=self.huggingface_model_path.text(),
            model_name=self.huggingface_model_name.text() or "test_model",
            device=self.huggingface_device.currentText(),
        )
        self.test_model_config(config)

    def test_model_config(self, config: "LLMConfig"):
        """Test a model configuration."""
        if self.validation_thread and self.validation_thread.isRunning():
            QMessageBox.warning(self, "Test In Progress", "Please wait for the current test to complete")
            return

        self.test_progress.setVisible(True)
        self.test_progress.setRange(0, 0)  # Indeterminate progress
        self.status_text.append(f"🧪 Testing {config.provider.value} model...")

        self.validation_thread = ModelTestThread(config)
        self.validation_thread.test_progress.connect(self.on_test_progress)
        self.validation_thread.test_complete.connect(self.on_test_complete)
        self.validation_thread.start()

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
        if self.validation_thread:
            self.validation_thread.wait()
            self.validation_thread = None

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
        """Save the current configuration including API keys to .env file."""
        try:
            # Collect all API keys from the UI
            api_keys = {}

            # OpenAI
            if hasattr(self, "openai_api_key") and self.openai_api_key and self.openai_api_key.text():
                api_keys["OPENAI_API_KEY"] = self.openai_api_key.text()

            # Anthropic
            if hasattr(self, "anthropic_api_key") and self.anthropic_api_key and self.anthropic_api_key.text():
                api_keys["ANTHROPIC_API_KEY"] = self.anthropic_api_key.text()

            # Google (if there's a Google tab)
            if hasattr(self, "google_api_key") and self.google_api_key and self.google_api_key.text():
                api_keys["GOOGLE_API_KEY"] = self.google_api_key.text()

            # HuggingFace (if there's a HuggingFace tab)
            if hasattr(self, "huggingface_api_token") and self.huggingface_api_token and self.huggingface_api_token.text():
                api_keys["HUGGINGFACE_API_TOKEN"] = self.huggingface_api_token.text()

            # OpenRouter (if there's an OpenRouter tab)
            if hasattr(self, "openrouter_api_key") and self.openrouter_api_key and self.openrouter_api_key.text():
                api_keys["OPENROUTER_API_KEY"] = self.openrouter_api_key.text()

            # Groq (if there's a Groq tab)
            if hasattr(self, "groq_api_key") and self.groq_api_key and self.groq_api_key.text():
                api_keys["GROQ_API_KEY"] = self.groq_api_key.text()

            # Cohere (if there's a Cohere tab)
            if hasattr(self, "cohere_api_key") and self.cohere_api_key and self.cohere_api_key.text():
                api_keys["COHERE_API_KEY"] = self.cohere_api_key.text()

            # Together (if there's a Together tab)
            if hasattr(self, "together_api_key") and self.together_api_key and self.together_api_key.text():
                api_keys["TOGETHER_API_KEY"] = self.together_api_key.text()

            # Ollama URL (special case - not an API key but a URL)
            if hasattr(self, "ollama_url") and self.ollama_url and self.ollama_url.text():
                api_keys["OLLAMA_API_BASE"] = self.ollama_url.text()

            # Save API keys to .env file
            if api_keys:
                self.env_manager.update_keys(api_keys)
                self.status_text.append(f"✓ Saved {len(api_keys)} API keys to .env file")

            # Save model configurations
            if self.current_configs:
                self.status_text.append(f"✓ Configuration saved ({len(self.current_configs)} models)")
                QMessageBox.information(
                    self,
                    "Success",
                    f"Configuration saved successfully!\n"
                    f"- {len(api_keys)} API keys saved to .env\n"
                    f"- {len(self.current_configs)} models configured",
                )
            else:
                if api_keys:
                    QMessageBox.information(
                        self,
                        "Success",
                        f"API keys saved successfully!\n{len(api_keys)} keys saved to .env file",
                    )
                else:
                    QMessageBox.warning(self, "No Configuration", "No API keys or models to save")

        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save configuration: {str(e)}")

    def load_existing_api_keys(self):
        """Load existing API keys from .env file and populate UI fields."""
        try:
            # Read all API keys from .env file
            api_keys = self.env_manager.get_all_api_keys()

            # Populate OpenAI
            if "OPENAI_API_KEY" in api_keys and hasattr(self, "openai_api_key"):
                self.openai_api_key.setText(api_keys["OPENAI_API_KEY"])

            # Populate Anthropic
            if "ANTHROPIC_API_KEY" in api_keys and hasattr(self, "anthropic_api_key"):
                self.anthropic_api_key.setText(api_keys["ANTHROPIC_API_KEY"])

            # Populate Google
            if "GOOGLE_API_KEY" in api_keys and hasattr(self, "google_api_key"):
                self.google_api_key.setText(api_keys["GOOGLE_API_KEY"])

            # Populate HuggingFace
            if "HUGGINGFACE_API_TOKEN" in api_keys and hasattr(self, "huggingface_api_token"):
                self.huggingface_api_token.setText(api_keys["HUGGINGFACE_API_TOKEN"])

            # Populate OpenRouter
            if "OPENROUTER_API_KEY" in api_keys and hasattr(self, "openrouter_api_key"):
                self.openrouter_api_key.setText(api_keys["OPENROUTER_API_KEY"])

            # Populate Groq
            if "GROQ_API_KEY" in api_keys and hasattr(self, "groq_api_key"):
                self.groq_api_key.setText(api_keys["GROQ_API_KEY"])

            # Populate Cohere
            if "COHERE_API_KEY" in api_keys and hasattr(self, "cohere_api_key"):
                self.cohere_api_key.setText(api_keys["COHERE_API_KEY"])

            # Populate Together
            if "TOGETHER_API_KEY" in api_keys and hasattr(self, "together_api_key"):
                self.together_api_key.setText(api_keys["TOGETHER_API_KEY"])

            # Populate Ollama URL
            if "OLLAMA_API_BASE" in api_keys and hasattr(self, "ollama_url"):
                self.ollama_url.setText(api_keys["OLLAMA_API_BASE"])

            if api_keys:
                self.status_text.append(f"✓ Loaded {len(api_keys)} API keys from .env file")

        except Exception as e:
            logger.error(f"Error loading API keys from .env: {e}")
            self.status_text.append(f"⚠ Could not load API keys: {str(e)}")

    def test_api_key(self, service: str, api_key_widget: QLineEdit):
        """Test an API key for a specific service.

        Args:
            service: Service name (openai, anthropic, google, etc.)
            api_key_widget: The QLineEdit widget containing the API key

        """
        api_key = api_key_widget.text()
        if not api_key:
            QMessageBox.warning(self, "No API Key", f"Please enter an API key for {service}")
            return

        # Use EnvFileManager's test_api_key method for validation
        success, message = self.env_manager.test_api_key(service, api_key)

        if success:
            QMessageBox.information(self, "API Key Valid", message)
            self.status_text.append(f"✓ {service} API key is valid")
        else:
            QMessageBox.warning(self, "API Key Invalid", message)
            self.status_text.append(f"✗ {service} API key is invalid: {message}")

    def validate_all_api_keys(self):
        """Validate all API keys before saving."""
        valid_keys = {}
        invalid_keys = []

        # Check OpenAI
        if hasattr(self, "openai_api_key") and self.openai_api_key.text():
            api_key = self.openai_api_key.text()
            success, _ = self.env_manager.test_api_key("openai", api_key)
            if success:
                valid_keys["OPENAI_API_KEY"] = api_key
            else:
                invalid_keys.append("OpenAI")

        # Check Anthropic
        if hasattr(self, "anthropic_api_key") and self.anthropic_api_key.text():
            api_key = self.anthropic_api_key.text()
            success, _ = self.env_manager.test_api_key("anthropic", api_key)
            if success:
                valid_keys["ANTHROPIC_API_KEY"] = api_key
            else:
                invalid_keys.append("Anthropic")

        # Check other services similarly...
        # (Can be expanded for all services)

        if invalid_keys:
            response = QMessageBox.question(
                self,
                "Invalid API Keys",
                f"The following API keys appear to be invalid:\n{', '.join(invalid_keys)}\n\nSave anyway?",
                QMessageBox.Yes | QMessageBox.No,
            )
            return response == QMessageBox.Yes, valid_keys

        return True, valid_keys

    def refresh_lora_models(self):
        """Refresh the list of available base models for LoRA."""
        self.lora_base_model.clear()
        if self.llm_manager:
            model_ids = list(self.llm_manager.backends.keys())
            self.lora_base_model.addItems(model_ids)

    def browse_lora_adapter(self):
        """Browse for LoRA adapter directory."""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select LoRA Adapter Directory",
        )

        if directory:
            self.lora_adapter_path.setText(directory)
            if not self.lora_adapter_name.text() or self.lora_adapter_name.text() == "default":
                adapter_name = os.path.basename(directory)
                self.lora_adapter_name.setText(adapter_name)

    def add_lora_adapter(self):
        """Load a LoRA adapter onto a base model."""
        base_model_id = self.lora_base_model.currentText()
        if not base_model_id:
            QMessageBox.warning(self, "Missing Base Model", "Please select a base model")
            return

        if not self.lora_adapter_path.text().strip():
            QMessageBox.warning(self, "Missing Adapter Path", "Please select a LoRA adapter directory")
            return

        if not os.path.exists(self.lora_adapter_path.text()):
            QMessageBox.warning(self, "Path Not Found", "The selected adapter directory does not exist")
            return

        try:
            from ...ai.lora_adapter_manager import get_adapter_manager

            adapter_manager = get_adapter_manager()

            # Get base model
            if self.llm_manager and base_model_id in self.llm_manager.backends:
                base_llm = self.llm_manager.backends[base_model_id]
                if hasattr(base_llm, "model") and base_llm.model is not None:
                    # Load adapter
                    adapter_name = self.lora_adapter_name.text() or "default"
                    model_with_adapter = adapter_manager.load_adapter(
                        base_llm.model,
                        self.lora_adapter_path.text(),
                        adapter_name=adapter_name,
                        merge_adapter=self.lora_merge_adapter.isChecked(),
                    )

                    if model_with_adapter:
                        # Update the base model
                        base_llm.model = model_with_adapter

                        # Create new model ID for the adapted model
                        new_model_id = f"{base_model_id}_lora_{adapter_name}"

                        self.status_text.append(f"✓ Loaded LoRA adapter '{adapter_name}' onto {base_model_id}")
                        self.status_text.append(f"✓ Model available as: {new_model_id}")

                        # Update UI
                        self.update_models_list()
                        QMessageBox.information(
                            self,
                            "Success",
                            f"LoRA adapter loaded successfully!\nModel ID: {new_model_id}",
                        )
                    else:
                        QMessageBox.critical(self, "Error", "Failed to load LoRA adapter")
                else:
                    QMessageBox.warning(
                        self,
                        "Model Not Loaded",
                        "The base model is not loaded. Please ensure it's properly initialized.",
                    )
            else:
                QMessageBox.warning(self, "Model Not Found", f"Base model '{base_model_id}' not found")

        except Exception as e:
            logger.error(f"Failed to load LoRA adapter: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load LoRA adapter: {e!s}")

    def test_lora_adapter(self):
        """Test a LoRA adapter configuration."""
        base_model_id = self.lora_base_model.currentText()
        if not base_model_id:
            QMessageBox.warning(self, "Missing Base Model", "Please select a base model")
            return

        if not self.lora_adapter_path.text().strip():
            QMessageBox.warning(self, "Missing Adapter Path", "Please select a LoRA adapter directory")
            return

        try:
            from ...ai.lora_adapter_manager import get_adapter_manager

            adapter_manager = get_adapter_manager()

            # Get adapter info
            adapter_info = adapter_manager.get_adapter_info(self.lora_adapter_path.text())

            info_text = "LoRA Adapter Information:\n\n"
            info_text += f"Path: {adapter_info['path']}\n"
            info_text += f"Exists: {adapter_info['exists']}\n"
            info_text += f"Size: {adapter_info['size_mb']:.2f} MB\n"

            if adapter_info["config"]:
                info_text += "\nConfiguration:\n"
                info_text += f"  Task Type: {adapter_info['config'].get('task_type', 'N/A')}\n"
                info_text += f"  LoRA Rank: {adapter_info['config'].get('r', 'N/A')}\n"
                info_text += f"  LoRA Alpha: {adapter_info['config'].get('lora_alpha', 'N/A')}\n"
                info_text += f"  Target Modules: {', '.join(adapter_info['config'].get('target_modules', []))}\n"

            QMessageBox.information(self, "LoRA Adapter Info", info_text)

        except Exception as e:
            logger.error("Exception in llm_config_dialog: %s", e)
            QMessageBox.critical(self, "Error", f"Failed to get adapter info: {e!s}")

    def create_lora_adapter(self):
        """Create a new LoRA adapter configuration."""
        base_model_id = self.lora_base_model.currentText()
        if not base_model_id:
            QMessageBox.warning(self, "Missing Base Model", "Please select a base model")
            return

        try:
            from ...ai.lora_adapter_manager import get_adapter_manager

            adapter_manager = get_adapter_manager()

            # Create LoRA config
            lora_config = adapter_manager.create_lora_config(
                adapter_type=self.lora_adapter_type.currentText(),
                r=self.lora_rank.value(),
                lora_alpha=self.lora_alpha.value(),
                lora_dropout=self.lora_dropout.value(),
            )

            if lora_config:
                # Get base model
                if self.llm_manager and base_model_id in self.llm_manager.backends:
                    base_llm = self.llm_manager.backends[base_model_id]
                    if hasattr(base_llm, "model") and base_llm.model is not None:
                        # Apply LoRA to model
                        adapter_name = self.lora_adapter_name.text() or "new_adapter"
                        peft_model = adapter_manager.apply_lora_to_model(
                            base_llm.model,
                            lora_config,
                            adapter_name=adapter_name,
                        )

                        if peft_model:
                            # Ask where to save
                            save_path = QFileDialog.getExistingDirectory(
                                self,
                                "Save LoRA Adapter To",
                            )

                            if save_path:
                                # Save adapter
                                success = adapter_manager.save_adapter(
                                    peft_model,
                                    save_path,
                                    adapter_name=adapter_name,
                                )

                                if success:
                                    self.status_text.append(
                                        f"✓ Created new LoRA adapter '{adapter_name}' with rank={self.lora_rank.value()}",
                                    )
                                    QMessageBox.information(
                                        self,
                                        "Success",
                                        f"LoRA adapter created and saved to:\n{save_path}",
                                    )
                                else:
                                    QMessageBox.critical(self, "Error", "Failed to save LoRA adapter")
                        else:
                            QMessageBox.critical(self, "Error", "Failed to create LoRA adapter")
                    else:
                        QMessageBox.warning(
                            self,
                            "Model Not Loaded",
                            "The base model is not loaded. Please ensure it's properly initialized.",
                        )
                else:
                    QMessageBox.warning(self, "Model Not Found", f"Base model '{base_model_id}' not found")
            else:
                QMessageBox.critical(self, "Error", "Failed to create LoRA configuration")

        except Exception as e:
            logger.error(f"Failed to create LoRA adapter: {e}")
            QMessageBox.critical(self, "Error", f"Failed to create LoRA adapter: {e!s}")

    def closeEvent(self, event):
        """Handle dialog close event."""
        if self.validation_thread and self.validation_thread.isRunning():
            reply = QMessageBox.question(
                self,
                "Test In Progress",
                "A model test is in progress. Do you want to cancel it and close?",
                QMessageBox.Yes | QMessageBox.No,
            )

            if reply == QMessageBox.No:
                event.ignore()
                return

            # Force terminate test thread
            if self.validation_thread:
                self.validation_thread.terminate()
                self.validation_thread.wait(3000)  # Wait up to 3 seconds

        event.accept()


if __name__ == "__main__":
    # For testing the dialog standalone
    import sys

    app = QApplication(sys.argv)
    dialog = LLMConfigDialog()
    dialog.show()
    sys.exit(app.exec())
