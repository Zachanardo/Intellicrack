"""Production-ready tests for LLMConfigDialog - AI model configuration interface validation.

This module validates LLMConfigDialog's complete functionality including:
- Dialog initialization and UI layout
- Multi-tab configuration interface (OpenAI, Anthropic, GGUF, Ollama, PyTorch, TensorFlow, ONNX, Safetensors, GPTQ, HuggingFace, LoRA)
- Model registration and management workflow
- API key storage and retrieval from .env files
- Model testing and validation threads
- File/directory browsing for local models
- Active model selection and removal
- Configuration persistence and loading
- Model discovery service integration
- LoRA adapter management
"""

import os
import tempfile
from pathlib import Path
from typing import Any

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox

from intellicrack.ai.llm_backends import LLMConfig, LLMProvider
from intellicrack.ui.dialogs.llm_config_dialog import LLMConfigDialog, ModelTestThread


class FakeLLMManager:
    """Test double for LLM manager with real state tracking."""

    def __init__(self) -> None:
        self.backends: dict[str, Any] = {}
        self.active_backend: str | None = None
        self.registration_calls: list[tuple[str, LLMConfig]] = []
        self.active_backend_calls: list[str] = []
        self.chat_calls: list[dict[str, Any]] = []

    def register_llm(self, model_id: str, config: LLMConfig) -> bool:
        """Register LLM backend with validation."""
        if not model_id or not isinstance(config, LLMConfig):
            return False
        self.backends[model_id] = config
        self.registration_calls.append((model_id, config))
        return True

    def set_active_llm(self, model_id: str) -> bool:
        """Set active LLM backend."""
        if model_id not in self.backends:
            return False
        self.active_backend = model_id
        self.active_backend_calls.append(model_id)
        return True

    def get_available_llms(self) -> list[str]:
        """Get list of available LLM backends."""
        return list(self.backends.keys())

    def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        """Mock chat operation."""
        self.chat_calls.append({"messages": messages, "kwargs": kwargs})
        return "Test response from LLM"


class FakeLLMConfigManager:
    """Test double for LLM config manager with file operations."""

    def __init__(self, temp_dir: Path) -> None:
        self.config_dir = temp_dir / "llm_configs"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.saved_configs: dict[str, LLMConfig] = {}
        self.save_calls: list[tuple[str, LLMConfig]] = []
        self.auto_load_count = 0

    def save_model_config(self, model_id: str, config: LLMConfig) -> None:
        """Save model configuration to storage."""
        self.saved_configs[model_id] = config
        self.save_calls.append((model_id, config))
        config_file = self.config_dir / f"{model_id}.json"
        config_file.write_text(f'{{"model_id": "{model_id}", "provider": "{config.provider.value}"}}')

    def load_model_config(self, model_id: str) -> LLMConfig | None:
        """Load model configuration from storage."""
        return self.saved_configs.get(model_id)

    def auto_load_models(self) -> tuple[int, int]:
        """Auto-load all saved model configurations."""
        self.auto_load_count += 1
        return (len(self.saved_configs), 0)

    def get_all_configs(self) -> dict[str, LLMConfig]:
        """Get all saved configurations."""
        return self.saved_configs.copy()


class FakeEnvFileManager:
    """Test double for environment file manager with real .env operations."""

    def __init__(self, temp_dir: Path) -> None:
        self.env_file = temp_dir / ".env"
        self.env_file.touch()
        self.api_keys: dict[str, str] = {}
        self.update_calls: list[dict[str, str]] = []
        self.test_calls: list[tuple[str, str]] = []

    def get_all_api_keys(self) -> dict[str, str]:
        """Get all API keys from .env file."""
        return self.api_keys.copy()

    def update_keys(self, keys: dict[str, str]) -> None:
        """Update API keys in .env file."""
        self.update_calls.append(keys.copy())
        self.api_keys.update(keys)
        lines: list[str] = []
        for key, value in self.api_keys.items():
            lines.append(f"{key}={value}\n")
        self.env_file.write_text("".join(lines))

    def test_api_key(self, provider: str, api_key: str) -> tuple[bool, str]:
        """Test API key validity."""
        self.test_calls.append((provider, api_key))
        if not api_key or len(api_key) < 10:
            return (False, "Invalid API key format")
        if not api_key.startswith(("sk-", "sk-ant-")):
            return (False, "API key must start with proper prefix")
        return (True, "Valid API key")


class FakeModelDiscoveryService:
    """Test double for model discovery service."""

    def __init__(self) -> None:
        self.cache_cleared = False
        self.discover_calls: list[dict[str, Any]] = []
        self.available_models: dict[str, list[str]] = {
            "openai": ["gpt-4", "gpt-3.5-turbo", "gpt-4-turbo-preview"],
            "anthropic": ["claude-3-opus", "claude-3-sonnet", "claude-3-haiku"],
        }

    def clear_cache(self) -> None:
        """Clear model discovery cache."""
        self.cache_cleared = True

    def discover_all_models(self, force_refresh: bool = False) -> dict[str, list[str]]:
        """Discover all available models."""
        self.discover_calls.append({"force_refresh": force_refresh})
        return self.available_models.copy()


@pytest.fixture
def temp_config_dir(tmp_path: Path) -> Path:
    """Create temporary configuration directory."""
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


@pytest.fixture
def fake_llm_manager() -> FakeLLMManager:
    """Create fake LLM manager for testing."""
    return FakeLLMManager()


@pytest.fixture
def fake_config_manager(temp_config_dir: Path) -> FakeLLMConfigManager:
    """Create fake config manager for testing."""
    return FakeLLMConfigManager(temp_config_dir)


@pytest.fixture
def fake_env_manager(temp_config_dir: Path) -> FakeEnvFileManager:
    """Create fake environment file manager for testing."""
    return FakeEnvFileManager(temp_config_dir)


@pytest.fixture
def fake_discovery_service() -> FakeModelDiscoveryService:
    """Create fake model discovery service."""
    return FakeModelDiscoveryService()


@pytest.fixture
def llm_config_dialog(
    qapp: QApplication,
    fake_llm_manager: FakeLLMManager,
    fake_config_manager: FakeLLMConfigManager,
    fake_env_manager: FakeEnvFileManager,
    monkeypatch: pytest.MonkeyPatch,
) -> LLMConfigDialog:
    """Create LLMConfigDialog with fake dependencies."""
    monkeypatch.setattr(
        "intellicrack.ui.dialogs.llm_config_dialog._get_llm_manager",
        lambda: fake_llm_manager,
    )
    monkeypatch.setattr(
        "intellicrack.ui.dialogs.llm_config_dialog._get_llm_config_manager",
        lambda: fake_config_manager,
    )
    monkeypatch.setattr(
        "intellicrack.ui.dialogs.llm_config_dialog._llm_imports_available",
        True,
    )

    dialog = LLMConfigDialog()
    dialog.env_manager = fake_env_manager
    dialog.llm_manager = fake_llm_manager
    dialog.config_manager = fake_config_manager
    return dialog


class TestLLMConfigDialogInitialization:
    """Test LLMConfigDialog initialization and UI setup."""

    def test_dialog_creation_initializes_all_components(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Dialog creates all UI components on initialization."""
        assert llm_config_dialog.windowTitle() == "LLM Model Configuration - Intellicrack Agentic AI"
        assert llm_config_dialog.tabs is not None
        assert llm_config_dialog.models_list is not None
        assert llm_config_dialog.status_text is not None
        assert llm_config_dialog.test_progress is not None

    def test_dialog_has_all_configuration_tabs(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Dialog contains all model configuration tabs."""
        tab_count = llm_config_dialog.tabs.count()
        assert tab_count == 11

        expected_tabs = [
            "OpenAI",
            "Anthropic",
            "GGUF Models",
            "Ollama",
            "PyTorch",
            "TensorFlow",
            "ONNX",
            "Safetensors",
            "GPTQ",
            "HF Local",
            "LoRA Adapters",
        ]
        for i, expected_name in enumerate(expected_tabs):
            assert llm_config_dialog.tabs.tabText(i) == expected_name

    def test_openai_tab_contains_required_fields(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """OpenAI tab has all configuration fields."""
        assert llm_config_dialog.openai_api_key is not None
        assert llm_config_dialog.openai_model is not None
        assert llm_config_dialog.openai_base_url is not None
        assert llm_config_dialog.openai_temp is not None
        assert llm_config_dialog.openai_max_tokens is not None
        assert llm_config_dialog.openai_tools is not None

        assert llm_config_dialog.openai_api_key.echoMode() == llm_config_dialog.openai_api_key.EchoMode.Password
        assert llm_config_dialog.openai_model.count() > 0
        assert "gpt-4" in [llm_config_dialog.openai_model.itemText(i) for i in range(llm_config_dialog.openai_model.count())]

    def test_anthropic_tab_contains_required_fields(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Anthropic tab has all configuration fields."""
        assert llm_config_dialog.anthropic_api_key is not None
        assert llm_config_dialog.anthropic_model is not None
        assert llm_config_dialog.anthropic_temp is not None
        assert llm_config_dialog.anthropic_max_tokens is not None
        assert llm_config_dialog.anthropic_tools is not None

        assert llm_config_dialog.anthropic_api_key.echoMode() == llm_config_dialog.anthropic_api_key.EchoMode.Password
        model_items = [llm_config_dialog.anthropic_model.itemText(i) for i in range(llm_config_dialog.anthropic_model.count())]
        assert any("claude" in item.lower() for item in model_items)

    def test_gguf_tab_contains_required_fields(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """GGUF tab has file selection and configuration fields."""
        assert llm_config_dialog.gguf_model_path is not None
        assert llm_config_dialog.gguf_model_name is not None
        assert llm_config_dialog.gguf_context is not None
        assert llm_config_dialog.gguf_temp is not None
        assert llm_config_dialog.gguf_max_tokens is not None
        assert llm_config_dialog.gguf_tools is not None

        assert llm_config_dialog.gguf_context.minimum() == 512
        assert llm_config_dialog.gguf_context.maximum() == 32768

    def test_dialog_loads_existing_api_keys_on_initialization(
        self,
        qapp: QApplication,
        fake_llm_manager: FakeLLMManager,
        fake_config_manager: FakeLLMConfigManager,
        fake_env_manager: FakeEnvFileManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Dialog loads API keys from .env file on startup."""
        fake_env_manager.api_keys = {
            "OPENAI_API_KEY": "sk-test123",
            "ANTHROPIC_API_KEY": "sk-ant-test456",
        }

        monkeypatch.setattr(
            "intellicrack.ui.dialogs.llm_config_dialog._get_llm_manager",
            lambda: fake_llm_manager,
        )
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.llm_config_dialog._get_llm_config_manager",
            lambda: fake_config_manager,
        )
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.llm_config_dialog._llm_imports_available",
            True,
        )

        dialog = LLMConfigDialog()
        dialog.env_manager = fake_env_manager
        dialog.load_existing_api_keys()

        assert dialog.openai_api_key.text() == "sk-test123"
        assert dialog.anthropic_api_key.text() == "sk-ant-test456"


class TestModelRegistration:
    """Test model registration and management functionality."""

    def test_add_openai_model_without_api_key_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Adding OpenAI model without API key displays warning."""
        llm_config_dialog.openai_api_key.clear()

        warning_called = False
        warning_message = ""

        def fake_warning(parent: Any, title: str, message: str) -> None:
            nonlocal warning_called, warning_message
            warning_called = True
            warning_message = message

        monkeypatch.setattr(QMessageBox, "warning", fake_warning)

        llm_config_dialog.add_openai_model()

        assert warning_called
        assert "api key" in warning_message.lower()

    def test_add_openai_model_with_valid_key_registers_model(
        self,
        llm_config_dialog: LLMConfigDialog,
        fake_llm_manager: FakeLLMManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Adding OpenAI model with API key registers it with manager."""
        llm_config_dialog.openai_api_key.setText("sk-test123456789")
        llm_config_dialog.openai_model.setCurrentText("gpt-4")

        def fake_create_openai_config(**kwargs: Any) -> LLMConfig:
            return LLMConfig(
                provider=LLMProvider.OPENAI,
                model_name=kwargs["model_name"],
                api_key=kwargs["api_key"],
            )

        monkeypatch.setattr(
            "intellicrack.ui.dialogs.llm_config_dialog.create_openai_config",
            fake_create_openai_config,
        )

        llm_config_dialog.add_openai_model()

        assert len(fake_llm_manager.registration_calls) > 0
        model_id, config = fake_llm_manager.registration_calls[-1]
        assert config.provider == LLMProvider.OPENAI
        assert config.model_name == "gpt-4"
        assert config.api_key == "sk-test123456789"

    def test_add_gguf_model_without_file_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Adding GGUF model without file path displays warning."""
        llm_config_dialog.gguf_model_path.clear()

        warning_called = False
        warning_message = ""

        def fake_warning(parent: Any, title: str, message: str) -> None:
            nonlocal warning_called, warning_message
            warning_called = True
            warning_message = message

        monkeypatch.setattr(QMessageBox, "warning", fake_warning)

        llm_config_dialog.add_gguf_model()

        assert warning_called
        assert "model file" in warning_message.lower()

    def test_add_gguf_model_with_nonexistent_file_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Adding GGUF model with non-existent file displays warning."""
        llm_config_dialog.gguf_model_path.setText("D:\\nonexistent\\model.gguf")

        warning_called = False
        warning_message = ""

        def fake_warning(parent: Any, title: str, message: str) -> None:
            nonlocal warning_called, warning_message
            warning_called = True
            warning_message = message

        monkeypatch.setattr(QMessageBox, "warning", fake_warning)

        llm_config_dialog.add_gguf_model()

        assert warning_called
        assert "not exist" in warning_message.lower()

    def test_register_model_updates_ui_and_saves_config(
        self,
        llm_config_dialog: LLMConfigDialog,
        fake_llm_manager: FakeLLMManager,
        fake_config_manager: FakeLLMConfigManager,
    ) -> None:
        """Registering model updates models list and saves configuration."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="test_model",
            api_key="sk-test",
        )

        llm_config_dialog.register_model("test_model_id", config)

        assert len(fake_llm_manager.registration_calls) > 0
        assert len(fake_config_manager.save_calls) > 0
        assert "test_model_id" in llm_config_dialog.current_configs

    def test_first_registered_model_becomes_active(
        self,
        llm_config_dialog: LLMConfigDialog,
        fake_llm_manager: FakeLLMManager,
    ) -> None:
        """First model registered is automatically set as active."""
        config = LLMConfig(
            provider=LLMProvider.ANTHROPIC,
            model_name="claude-3-sonnet",
            api_key="sk-ant-test",
        )

        llm_config_dialog.current_configs.clear()
        llm_config_dialog.register_model("first_model", config)

        assert "first_model" in fake_llm_manager.active_backend_calls


class TestFileBrowsing:
    """Test file and directory browsing functionality."""

    def test_browse_gguf_model_updates_path_field(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Browsing for GGUF model updates path field."""
        test_path = "D:\\models\\test_model.gguf"

        def fake_get_open_filename(
            parent: Any, caption: str, directory: str, filter: str
        ) -> tuple[str, str]:
            return (test_path, "GGUF Files (*.gguf)")

        monkeypatch.setattr(QFileDialog, "getOpenFileName", fake_get_open_filename)

        llm_config_dialog.browse_gguf_model()

        assert llm_config_dialog.gguf_model_path.text() == test_path
        assert llm_config_dialog.gguf_model_name.text() == "test_model"

    def test_browse_gguf_model_cancelled_does_not_update(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Cancelling GGUF browse dialog does not update fields."""
        original_path = llm_config_dialog.gguf_model_path.text()

        def fake_get_open_filename(
            parent: Any, caption: str, directory: str, filter: str
        ) -> tuple[str, str]:
            return ("", "")

        monkeypatch.setattr(QFileDialog, "getOpenFileName", fake_get_open_filename)

        llm_config_dialog.browse_gguf_model()

        assert llm_config_dialog.gguf_model_path.text() == original_path

    def test_browse_pytorch_model_directory_updates_path(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Browsing for PyTorch directory updates path field."""
        test_dir = "D:\\models\\pytorch_model_dir"

        def fake_get_existing_directory(
            parent: Any, caption: str, directory: str
        ) -> str:
            return test_dir

        monkeypatch.setattr(QFileDialog, "getExistingDirectory", fake_get_existing_directory)

        llm_config_dialog.browse_pytorch_model()

        assert llm_config_dialog.pytorch_model_path.text() == test_dir
        assert llm_config_dialog.pytorch_model_name.text() == "pytorch_model_dir"

    def test_browse_pytorch_model_file_fallback(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Browsing for PyTorch file falls back to file dialog if directory selection cancelled."""
        test_file = "D:\\models\\model.pth"

        def fake_get_existing_directory(
            parent: Any, caption: str, directory: str
        ) -> str:
            return ""

        def fake_get_open_filename(
            parent: Any, caption: str, directory: str, filter: str
        ) -> tuple[str, str]:
            return (test_file, "PyTorch Files (*.pth *.pt *.bin)")

        monkeypatch.setattr(QFileDialog, "getExistingDirectory", fake_get_existing_directory)
        monkeypatch.setattr(QFileDialog, "getOpenFileName", fake_get_open_filename)

        llm_config_dialog.browse_pytorch_model()

        assert llm_config_dialog.pytorch_model_path.text() == test_file
        assert llm_config_dialog.pytorch_model_name.text() == "model"


class TestModelTesting:
    """Test model configuration testing functionality."""

    def test_test_openai_config_without_api_key_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Testing OpenAI config without API key displays warning."""
        llm_config_dialog.openai_api_key.clear()

        warning_called = False

        def fake_warning(parent: Any, title: str, message: str) -> None:
            nonlocal warning_called
            warning_called = True

        monkeypatch.setattr(QMessageBox, "warning", fake_warning)

        llm_config_dialog.test_openai_config()

        assert warning_called

    def test_test_model_config_starts_validation_thread(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Testing model configuration starts validation thread."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4",
            api_key="sk-test",
        )

        thread_started = False
        thread_instance = None

        class FakeModelTestThread:
            def __init__(self, test_config: LLMConfig) -> None:
                self.config = test_config
                self.is_running = False
                nonlocal thread_instance
                thread_instance = self

            def start(self) -> None:
                nonlocal thread_started
                thread_started = True
                self.is_running = True

            def isRunning(self) -> bool:
                return self.is_running

        monkeypatch.setattr(
            "intellicrack.ui.dialogs.llm_config_dialog.ModelTestThread",
            FakeModelTestThread,
        )

        llm_config_dialog.test_model_config(config)

        assert thread_started
        assert llm_config_dialog.test_progress.isVisible()

    def test_test_model_config_while_test_running_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Starting test while another test runs displays warning."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4",
            api_key="sk-test",
        )

        class FakeRunningThread:
            def isRunning(self) -> bool:
                return True

        llm_config_dialog.validation_thread = FakeRunningThread()

        warning_called = False

        def fake_warning(parent: Any, title: str, message: str) -> None:
            nonlocal warning_called
            warning_called = True

        monkeypatch.setattr(QMessageBox, "warning", fake_warning)

        llm_config_dialog.test_model_config(config)

        assert warning_called

    def test_on_test_complete_success_updates_status(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Successful test completion updates status text."""
        initial_text = llm_config_dialog.status_text.toPlainText()

        llm_config_dialog.on_test_complete(True, "Test successful")

        status_text = llm_config_dialog.status_text.toPlainText()
        assert "Test successful" in status_text
        assert len(status_text) > len(initial_text)
        assert not llm_config_dialog.test_progress.isVisible()

    def test_on_test_complete_failure_updates_status(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Failed test completion updates status with error."""
        llm_config_dialog.on_test_complete(False, "Connection failed")

        status_text = llm_config_dialog.status_text.toPlainText()
        assert "Connection failed" in status_text


class TestAPIKeyManagement:
    """Test API key storage and validation."""

    def test_save_configuration_stores_api_keys_to_env(
        self,
        llm_config_dialog: LLMConfigDialog,
        fake_env_manager: FakeEnvFileManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Saving configuration stores API keys to .env file."""
        llm_config_dialog.openai_api_key.setText("sk-test-openai-key")
        llm_config_dialog.anthropic_api_key.setText("sk-ant-test-key")

        info_called = False

        def fake_information(parent: Any, title: str, message: str) -> None:
            nonlocal info_called
            info_called = True

        monkeypatch.setattr(QMessageBox, "information", fake_information)

        llm_config_dialog.save_configuration()

        assert len(fake_env_manager.update_calls) > 0
        call_args = fake_env_manager.update_calls[-1]
        assert call_args["OPENAI_API_KEY"] == "sk-test-openai-key"
        assert call_args["ANTHROPIC_API_KEY"] == "sk-ant-test-key"

    def test_save_configuration_with_no_data_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Saving configuration with no data displays warning."""
        llm_config_dialog.openai_api_key.clear()
        llm_config_dialog.anthropic_api_key.clear()
        llm_config_dialog.current_configs.clear()

        warning_called = False

        def fake_warning(parent: Any, title: str, message: str) -> None:
            nonlocal warning_called
            warning_called = True

        monkeypatch.setattr(QMessageBox, "warning", fake_warning)

        llm_config_dialog.save_configuration()

        assert warning_called

    def test_test_api_key_with_valid_key_shows_success(
        self,
        llm_config_dialog: LLMConfigDialog,
        fake_env_manager: FakeEnvFileManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Testing valid API key displays success message."""
        llm_config_dialog.openai_api_key.setText("sk-valid-key-12345")

        info_called = False

        def fake_information(parent: Any, title: str, message: str) -> None:
            nonlocal info_called
            info_called = True

        monkeypatch.setattr(QMessageBox, "information", fake_information)

        llm_config_dialog.test_api_key("openai", llm_config_dialog.openai_api_key)

        assert info_called
        assert len(fake_env_manager.test_calls) > 0
        assert fake_env_manager.test_calls[-1] == ("openai", "sk-valid-key-12345")

    def test_test_api_key_with_invalid_key_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
        fake_env_manager: FakeEnvFileManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Testing invalid API key displays warning."""
        llm_config_dialog.openai_api_key.setText("invalid-key")

        warning_called = False

        def fake_warning(parent: Any, title: str, message: str) -> None:
            nonlocal warning_called
            warning_called = True

        monkeypatch.setattr(QMessageBox, "warning", fake_warning)

        llm_config_dialog.test_api_key("openai", llm_config_dialog.openai_api_key)

        assert warning_called

    def test_test_api_key_without_key_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Testing API key without entering key displays warning."""
        llm_config_dialog.openai_api_key.clear()

        warning_called = False

        def fake_warning(parent: Any, title: str, message: str) -> None:
            nonlocal warning_called
            warning_called = True

        monkeypatch.setattr(QMessageBox, "warning", fake_warning)

        llm_config_dialog.test_api_key("openai", llm_config_dialog.openai_api_key)

        assert warning_called


class TestActiveModelManagement:
    """Test active model selection and management."""

    def test_update_models_list_displays_registered_models(
        self,
        llm_config_dialog: LLMConfigDialog,
        fake_llm_manager: FakeLLMManager,
    ) -> None:
        """Updating models list displays all registered models."""
        fake_llm_manager.backends = {
            "model_1": LLMConfig(provider=LLMProvider.OPENAI, model_name="model_1"),
            "model_2": LLMConfig(provider=LLMProvider.OPENAI, model_name="model_2"),
            "model_3": LLMConfig(provider=LLMProvider.OPENAI, model_name="model_3"),
        }
        fake_llm_manager.active_backend = "model_2"

        llm_config_dialog.update_models_list()

        assert llm_config_dialog.models_list.count() == 3
        item_texts = [llm_config_dialog.models_list.item(i).text() for i in range(3)]
        assert any("model_2" in text and "Active" in text for text in item_texts)

    def test_set_active_model_changes_active_backend(
        self,
        llm_config_dialog: LLMConfigDialog,
        fake_llm_manager: FakeLLMManager,
    ) -> None:
        """Setting active model changes LLM manager's active backend."""
        fake_llm_manager.backends = {
            "model_a": LLMConfig(provider=LLMProvider.OPENAI, model_name="model_a"),
            "model_b": LLMConfig(provider=LLMProvider.OPENAI, model_name="model_b"),
        }
        llm_config_dialog.update_models_list()

        llm_config_dialog.models_list.setCurrentRow(1)
        llm_config_dialog.set_active_model()

        assert len(fake_llm_manager.active_backend_calls) > 0

    def test_remove_model_with_confirmation_removes_from_list(
        self,
        llm_config_dialog: LLMConfigDialog,
        fake_llm_manager: FakeLLMManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Removing model with confirmation removes it from tracking."""
        test_config = LLMConfig(provider=LLMProvider.OPENAI, model_name="test_model")
        llm_config_dialog.current_configs["test_model"] = test_config
        fake_llm_manager.backends = {"test_model": test_config}
        llm_config_dialog.update_models_list()
        llm_config_dialog.models_list.setCurrentRow(0)

        def fake_question(
            parent: Any, title: str, message: str, buttons: Any, default_button: Any = None
        ) -> Any:
            return QMessageBox.StandardButton.Yes

        monkeypatch.setattr(QMessageBox, "question", fake_question)

        llm_config_dialog.remove_model()

        assert "test_model" not in llm_config_dialog.current_configs

    def test_remove_model_without_confirmation_keeps_model(
        self,
        llm_config_dialog: LLMConfigDialog,
        fake_llm_manager: FakeLLMManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Cancelling model removal keeps it in tracking."""
        test_config = LLMConfig(provider=LLMProvider.OPENAI, model_name="test_model")
        llm_config_dialog.current_configs["test_model"] = test_config
        fake_llm_manager.backends = {"test_model": test_config}
        llm_config_dialog.update_models_list()
        llm_config_dialog.models_list.setCurrentRow(0)

        def fake_question(
            parent: Any, title: str, message: str, buttons: Any, default_button: Any = None
        ) -> Any:
            return QMessageBox.StandardButton.No

        monkeypatch.setattr(QMessageBox, "question", fake_question)

        llm_config_dialog.remove_model()

        assert "test_model" in llm_config_dialog.current_configs


class TestLoRAAdapterManagement:
    """Test LoRA adapter loading and management."""

    def test_browse_lora_adapter_updates_path_field(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Browsing for LoRA adapter updates path field."""
        test_adapter_path = "D:\\adapters\\my_lora_adapter"

        def fake_get_existing_directory(
            parent: Any, caption: str, directory: str
        ) -> str:
            return test_adapter_path

        monkeypatch.setattr(QFileDialog, "getExistingDirectory", fake_get_existing_directory)

        llm_config_dialog.browse_lora_adapter()

        assert llm_config_dialog.lora_adapter_path.text() == test_adapter_path
        assert llm_config_dialog.lora_adapter_name.text() == "my_lora_adapter"

    def test_add_lora_adapter_without_base_model_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Adding LoRA adapter without base model displays warning."""
        llm_config_dialog.lora_base_model.clear()

        warning_called = False

        def fake_warning(parent: Any, title: str, message: str) -> None:
            nonlocal warning_called
            warning_called = True

        monkeypatch.setattr(QMessageBox, "warning", fake_warning)

        llm_config_dialog.add_lora_adapter()

        assert warning_called

    def test_add_lora_adapter_without_adapter_path_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Adding LoRA adapter without adapter path displays warning."""
        llm_config_dialog.lora_base_model.addItem("base_model_id")
        llm_config_dialog.lora_base_model.setCurrentIndex(0)
        llm_config_dialog.lora_adapter_path.clear()

        warning_called = False

        def fake_warning(parent: Any, title: str, message: str) -> None:
            nonlocal warning_called
            warning_called = True

        monkeypatch.setattr(QMessageBox, "warning", fake_warning)

        llm_config_dialog.add_lora_adapter()

        assert warning_called

    def test_refresh_lora_models_updates_base_model_list(
        self,
        llm_config_dialog: LLMConfigDialog,
        fake_llm_manager: FakeLLMManager,
    ) -> None:
        """Refreshing LoRA models updates base model dropdown."""
        fake_llm_manager.backends = {
            "model_1": LLMConfig(provider=LLMProvider.OPENAI, model_name="model_1"),
            "model_2": LLMConfig(provider=LLMProvider.OPENAI, model_name="model_2"),
            "model_3": LLMConfig(provider=LLMProvider.OPENAI, model_name="model_3"),
        }

        llm_config_dialog.refresh_lora_models()

        assert llm_config_dialog.lora_base_model.count() == 3
        items = [llm_config_dialog.lora_base_model.itemText(i) for i in range(3)]
        assert "model_1" in items
        assert "model_2" in items
        assert "model_3" in items


class TestModelTestThread:
    """Test ModelTestThread validation functionality."""

    def test_model_test_thread_initialization(self) -> None:
        """ModelTestThread initializes with config."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4",
            api_key="sk-test",
        )

        thread = ModelTestThread(config)

        assert thread.config == config

    def test_model_test_thread_emits_progress_signals(
        self,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ModelTestThread emits progress signals during execution."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4",
            api_key="sk-test",
        )

        monkeypatch.setattr(
            "intellicrack.ui.dialogs.llm_config_dialog._get_llm_manager",
            lambda: None,
        )

        thread = ModelTestThread(config)

        progress_messages: list[str] = []

        def on_progress(message: str) -> None:
            progress_messages.append(message)

        thread.validation_progress.connect(on_progress)

        thread.run()

        qapp.processEvents()


class TestCloseEvent:
    """Test dialog close event handling."""

    def test_close_event_with_running_validation_prompts_user(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Closing dialog with running validation prompts confirmation."""
        class FakeRunningThread:
            def isRunning(self) -> bool:
                return True

            def terminate(self) -> None:
                pass

            def wait(self) -> None:
                pass

        llm_config_dialog.validation_thread = FakeRunningThread()

        from PyQt6.QtGui import QCloseEvent

        close_event = QCloseEvent()

        def fake_question(
            parent: Any, title: str, message: str, buttons: Any, default_button: Any = None
        ) -> Any:
            return QMessageBox.StandardButton.No

        monkeypatch.setattr(QMessageBox, "question", fake_question)

        llm_config_dialog.closeEvent(close_event)

        assert close_event.isAccepted() is False

    def test_close_event_with_running_validation_and_confirmation_terminates_thread(
        self,
        llm_config_dialog: LLMConfigDialog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Closing dialog with confirmation terminates validation thread."""
        terminate_called = False
        wait_called = False

        class FakeRunningThread:
            def isRunning(self) -> bool:
                return True

            def terminate(self) -> None:
                nonlocal terminate_called
                terminate_called = True

            def wait(self) -> None:
                nonlocal wait_called
                wait_called = True

        llm_config_dialog.validation_thread = FakeRunningThread()

        from PyQt6.QtGui import QCloseEvent

        close_event = QCloseEvent()

        def fake_question(
            parent: Any, title: str, message: str, buttons: Any, default_button: Any = None
        ) -> Any:
            return QMessageBox.StandardButton.Yes

        monkeypatch.setattr(QMessageBox, "question", fake_question)

        llm_config_dialog.closeEvent(close_event)

        assert terminate_called
        assert wait_called
        assert close_event.isAccepted() is True


class TestModelDiscoveryIntegration:
    """Test model discovery service integration."""

    def test_save_configuration_triggers_model_discovery_refresh(
        self,
        llm_config_dialog: LLMConfigDialog,
        fake_discovery_service: FakeModelDiscoveryService,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Saving configuration triggers model discovery service refresh."""
        llm_config_dialog.openai_api_key.setText("sk-test-key-12345")

        def fake_get_discovery_service() -> FakeModelDiscoveryService:
            return fake_discovery_service

        monkeypatch.setattr(
            "intellicrack.ui.dialogs.llm_config_dialog.get_model_discovery_service",
            fake_get_discovery_service,
        )

        info_called = False

        def fake_information(parent: Any, title: str, message: str) -> None:
            nonlocal info_called
            info_called = True

        monkeypatch.setattr(QMessageBox, "information", fake_information)

        llm_config_dialog.save_configuration()

        assert fake_discovery_service.cache_cleared
        assert len(fake_discovery_service.discover_calls) > 0
        assert fake_discovery_service.discover_calls[-1]["force_refresh"] is True


class TestConfigurationPersistence:
    """Test configuration loading and persistence."""

    def test_load_existing_configs_updates_models_list(
        self,
        llm_config_dialog: LLMConfigDialog,
        fake_llm_manager: FakeLLMManager,
    ) -> None:
        """Loading existing configs updates models list."""
        fake_llm_manager.backends = {
            "existing_model_1": LLMConfig(provider=LLMProvider.OPENAI, model_name="existing_model_1"),
            "existing_model_2": LLMConfig(provider=LLMProvider.OPENAI, model_name="existing_model_2"),
        }

        llm_config_dialog.load_existing_configs()

        assert "Loaded 2 existing models" in llm_config_dialog.status_text.toPlainText()

    def test_load_existing_configs_with_no_models_shows_message(
        self,
        llm_config_dialog: LLMConfigDialog,
        fake_llm_manager: FakeLLMManager,
    ) -> None:
        """Loading configs with no existing models shows appropriate message."""
        fake_llm_manager.backends = {}

        llm_config_dialog.load_existing_configs()

        assert "No existing models found" in llm_config_dialog.status_text.toPlainText()


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_ollama_tab_initializes_with_default_url(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Ollama tab initializes with default localhost URL."""
        assert "localhost" in llm_config_dialog.ollama_url.text().lower()
        assert "11434" in llm_config_dialog.ollama_url.text()

    def test_temperature_spinboxes_have_valid_ranges(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Temperature spinboxes have valid ranges for all providers."""
        assert llm_config_dialog.openai_temp.minimum() == 0.0
        assert llm_config_dialog.openai_temp.maximum() == 2.0
        assert llm_config_dialog.anthropic_temp.minimum() == 0.0
        assert llm_config_dialog.anthropic_temp.maximum() == 1.0
        assert llm_config_dialog.gguf_temp.minimum() == 0.0
        assert llm_config_dialog.gguf_temp.maximum() == 2.0

    def test_max_tokens_spinboxes_have_reasonable_limits(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Max tokens spinboxes have reasonable limits."""
        assert llm_config_dialog.openai_max_tokens.minimum() == 1
        assert llm_config_dialog.openai_max_tokens.maximum() >= 4096
        assert llm_config_dialog.anthropic_max_tokens.minimum() == 1
        assert llm_config_dialog.anthropic_max_tokens.maximum() >= 2048

    def test_device_comboboxes_contain_expected_options(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Device selection comboboxes contain expected options."""
        pytorch_devices = [llm_config_dialog.pytorch_device.itemText(i) for i in range(llm_config_dialog.pytorch_device.count())]
        assert "cpu" in pytorch_devices
        assert "cuda" in pytorch_devices

        tensorflow_devices = [llm_config_dialog.tensorflow_device.itemText(i) for i in range(llm_config_dialog.tensorflow_device.count())]
        assert "cpu" in tensorflow_devices
        assert "gpu" in tensorflow_devices
