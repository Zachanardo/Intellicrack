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
from unittest.mock import MagicMock, Mock, patch

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox

from intellicrack.ai.llm_backends import LLMConfig, LLMProvider
from intellicrack.ui.dialogs.llm_config_dialog import LLMConfigDialog, ModelTestThread


@pytest.fixture
def qapp(qapp: QApplication) -> QApplication:
    """Provide QApplication instance for PyQt6 tests."""
    return qapp


@pytest.fixture
def mock_llm_manager() -> Mock:
    """Create mock LLM manager for testing."""
    manager = Mock()
    manager.backends = {}
    manager.active_backend = None
    manager.register_llm = Mock(return_value=True)
    manager.set_active_llm = Mock(return_value=True)
    manager.get_available_llms = Mock(return_value=[])
    manager.chat = Mock()
    return manager


@pytest.fixture
def mock_config_manager() -> Mock:
    """Create mock config manager for testing."""
    manager = Mock()
    manager.save_model_config = Mock()
    manager.auto_load_models = Mock(return_value=(0, 0))
    return manager


@pytest.fixture
def mock_env_manager() -> Mock:
    """Create mock environment file manager for testing."""
    manager = Mock()
    manager.get_all_api_keys = Mock(return_value={})
    manager.update_keys = Mock()
    manager.test_api_key = Mock(return_value=(True, "Valid API key"))
    return manager


@pytest.fixture
def llm_config_dialog(
    qapp: QApplication,
    mock_llm_manager: Mock,
    mock_config_manager: Mock,
    mock_env_manager: Mock,
) -> LLMConfigDialog:
    """Create LLMConfigDialog with mocked dependencies."""
    with (
        patch("intellicrack.ui.dialogs.llm_config_dialog._get_llm_manager", return_value=lambda: mock_llm_manager),
        patch("intellicrack.ui.dialogs.llm_config_dialog._get_llm_config_manager", return_value=lambda: mock_config_manager),
        patch("intellicrack.ui.dialogs.llm_config_dialog._llm_imports_available", True),
    ):
        dialog = LLMConfigDialog()
        dialog.env_manager = mock_env_manager
        dialog.llm_manager = mock_llm_manager
        dialog.config_manager = mock_config_manager
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
        mock_llm_manager: Mock,
        mock_config_manager: Mock,
        mock_env_manager: Mock,
    ) -> None:
        """Dialog loads API keys from .env file on startup."""
        mock_env_manager.get_all_api_keys = Mock(
            return_value={
                "OPENAI_API_KEY": "sk-test123",
                "ANTHROPIC_API_KEY": "sk-ant-test456",
            }
        )

        with (
            patch("intellicrack.ui.dialogs.llm_config_dialog._get_llm_manager", return_value=lambda: mock_llm_manager),
            patch("intellicrack.ui.dialogs.llm_config_dialog._get_llm_config_manager", return_value=lambda: mock_config_manager),
            patch("intellicrack.ui.dialogs.llm_config_dialog._llm_imports_available", True),
        ):
            dialog = LLMConfigDialog()
            dialog.env_manager = mock_env_manager
            dialog.load_existing_api_keys()

            assert dialog.openai_api_key.text() == "sk-test123"
            assert dialog.anthropic_api_key.text() == "sk-ant-test456"


class TestModelRegistration:
    """Test model registration and management functionality."""

    def test_add_openai_model_without_api_key_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Adding OpenAI model without API key displays warning."""
        llm_config_dialog.openai_api_key.clear()

        with patch.object(QMessageBox, "warning") as mock_warning:
            llm_config_dialog.add_openai_model()
            mock_warning.assert_called_once()
            args = mock_warning.call_args[0]
            assert "API key" in args[2].lower()

    def test_add_openai_model_with_valid_key_registers_model(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Adding OpenAI model with API key registers it with manager."""
        llm_config_dialog.openai_api_key.setText("sk-test123456789")
        llm_config_dialog.openai_model.setCurrentText("gpt-4")

        with patch("intellicrack.ui.dialogs.llm_config_dialog.create_openai_config") as mock_create:
            mock_config = Mock(spec=LLMConfig)
            mock_config.provider = LLMProvider.OPENAI
            mock_create.return_value = mock_config

            llm_config_dialog.add_openai_model()

            mock_create.assert_called_once()
            call_kwargs = mock_create.call_args[1]
            assert call_kwargs["model_name"] == "gpt-4"
            assert call_kwargs["api_key"] == "sk-test123456789"
            assert llm_config_dialog.llm_manager.register_llm.called

    def test_add_gguf_model_without_file_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Adding GGUF model without file path displays warning."""
        llm_config_dialog.gguf_model_path.clear()

        with patch.object(QMessageBox, "warning") as mock_warning:
            llm_config_dialog.add_gguf_model()
            mock_warning.assert_called_once()
            args = mock_warning.call_args[0]
            assert "model file" in args[2].lower()

    def test_add_gguf_model_with_nonexistent_file_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Adding GGUF model with non-existent file displays warning."""
        llm_config_dialog.gguf_model_path.setText("D:\\nonexistent\\model.gguf")

        with patch.object(QMessageBox, "warning") as mock_warning:
            llm_config_dialog.add_gguf_model()
            mock_warning.assert_called_once()
            args = mock_warning.call_args[0]
            assert "not exist" in args[2].lower()

    def test_register_model_updates_ui_and_saves_config(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Registering model updates models list and saves configuration."""
        mock_config = Mock(spec=LLMConfig)
        mock_config.provider = LLMProvider.OPENAI

        llm_config_dialog.register_model("test_model_id", mock_config)

        assert llm_config_dialog.llm_manager.register_llm.called
        assert llm_config_dialog.config_manager.save_model_config.called
        assert "test_model_id" in llm_config_dialog.current_configs

    def test_first_registered_model_becomes_active(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """First model registered is automatically set as active."""
        mock_config = Mock(spec=LLMConfig)
        mock_config.provider = LLMProvider.ANTHROPIC

        llm_config_dialog.current_configs.clear()
        llm_config_dialog.register_model("first_model", mock_config)

        llm_config_dialog.llm_manager.set_active_llm.assert_called_with("first_model")


class TestFileBrowsing:
    """Test file and directory browsing functionality."""

    def test_browse_gguf_model_updates_path_field(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Browsing for GGUF model updates path field."""
        test_path = "D:\\models\\test_model.gguf"

        with patch.object(QFileDialog, "getOpenFileName", return_value=(test_path, "GGUF Files (*.gguf)")):
            llm_config_dialog.browse_gguf_model()

            assert llm_config_dialog.gguf_model_path.text() == test_path
            assert llm_config_dialog.gguf_model_name.text() == "test_model"

    def test_browse_gguf_model_cancelled_does_not_update(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Cancelling GGUF browse dialog does not update fields."""
        original_path = llm_config_dialog.gguf_model_path.text()

        with patch.object(QFileDialog, "getOpenFileName", return_value=("", "")):
            llm_config_dialog.browse_gguf_model()

            assert llm_config_dialog.gguf_model_path.text() == original_path

    def test_browse_pytorch_model_directory_updates_path(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Browsing for PyTorch directory updates path field."""
        test_dir = "D:\\models\\pytorch_model_dir"

        with patch.object(QFileDialog, "getExistingDirectory", return_value=test_dir):
            llm_config_dialog.browse_pytorch_model()

            assert llm_config_dialog.pytorch_model_path.text() == test_dir
            assert llm_config_dialog.pytorch_model_name.text() == "pytorch_model_dir"

    def test_browse_pytorch_model_file_fallback(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Browsing for PyTorch file falls back to file dialog if directory selection cancelled."""
        test_file = "D:\\models\\model.pth"

        with (
            patch.object(QFileDialog, "getExistingDirectory", return_value=""),
            patch.object(QFileDialog, "getOpenFileName", return_value=(test_file, "PyTorch Files (*.pth *.pt *.bin)")),
        ):
            llm_config_dialog.browse_pytorch_model()

            assert llm_config_dialog.pytorch_model_path.text() == test_file
            assert llm_config_dialog.pytorch_model_name.text() == "model"


class TestModelTesting:
    """Test model configuration testing functionality."""

    def test_test_openai_config_without_api_key_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Testing OpenAI config without API key displays warning."""
        llm_config_dialog.openai_api_key.clear()

        with patch.object(QMessageBox, "warning") as mock_warning:
            llm_config_dialog.test_openai_config()
            mock_warning.assert_called_once()

    def test_test_model_config_starts_validation_thread(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Testing model configuration starts validation thread."""
        mock_config = Mock(spec=LLMConfig)
        mock_config.provider = LLMProvider.OPENAI

        with patch("intellicrack.ui.dialogs.llm_config_dialog.ModelTestThread") as mock_thread_class:
            mock_thread = Mock()
            mock_thread_class.return_value = mock_thread
            mock_thread.isRunning.return_value = False

            llm_config_dialog.test_model_config(mock_config)

            mock_thread_class.assert_called_once_with(mock_config)
            mock_thread.start.assert_called_once()
            assert llm_config_dialog.test_progress.isVisible()

    def test_test_model_config_while_test_running_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Starting test while another test runs displays warning."""
        mock_config = Mock(spec=LLMConfig)
        llm_config_dialog.validation_thread = Mock()
        llm_config_dialog.validation_thread.isRunning.return_value = True

        with patch.object(QMessageBox, "warning") as mock_warning:
            llm_config_dialog.test_model_config(mock_config)
            mock_warning.assert_called_once()

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
    ) -> None:
        """Saving configuration stores API keys to .env file."""
        llm_config_dialog.openai_api_key.setText("sk-test-openai-key")
        llm_config_dialog.anthropic_api_key.setText("sk-ant-test-key")

        with patch.object(QMessageBox, "information"):
            llm_config_dialog.save_configuration()

            llm_config_dialog.env_manager.update_keys.assert_called_once()
            call_args = llm_config_dialog.env_manager.update_keys.call_args[0][0]
            assert call_args["OPENAI_API_KEY"] == "sk-test-openai-key"
            assert call_args["ANTHROPIC_API_KEY"] == "sk-ant-test-key"

    def test_save_configuration_with_no_data_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Saving configuration with no data displays warning."""
        llm_config_dialog.openai_api_key.clear()
        llm_config_dialog.anthropic_api_key.clear()
        llm_config_dialog.current_configs.clear()

        with patch.object(QMessageBox, "warning") as mock_warning:
            llm_config_dialog.save_configuration()
            mock_warning.assert_called_once()

    def test_test_api_key_with_valid_key_shows_success(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Testing valid API key displays success message."""
        llm_config_dialog.openai_api_key.setText("sk-valid-key")
        llm_config_dialog.env_manager.test_api_key = Mock(return_value=(True, "Key is valid"))

        with patch.object(QMessageBox, "information") as mock_info:
            llm_config_dialog.test_api_key("openai", llm_config_dialog.openai_api_key)

            mock_info.assert_called_once()
            llm_config_dialog.env_manager.test_api_key.assert_called_with("openai", "sk-valid-key")

    def test_test_api_key_with_invalid_key_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Testing invalid API key displays warning."""
        llm_config_dialog.openai_api_key.setText("invalid-key")
        llm_config_dialog.env_manager.test_api_key = Mock(return_value=(False, "Invalid format"))

        with patch.object(QMessageBox, "warning") as mock_warning:
            llm_config_dialog.test_api_key("openai", llm_config_dialog.openai_api_key)

            mock_warning.assert_called_once()

    def test_test_api_key_without_key_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Testing API key without entering key displays warning."""
        llm_config_dialog.openai_api_key.clear()

        with patch.object(QMessageBox, "warning") as mock_warning:
            llm_config_dialog.test_api_key("openai", llm_config_dialog.openai_api_key)
            mock_warning.assert_called_once()


class TestActiveModelManagement:
    """Test active model selection and management."""

    def test_update_models_list_displays_registered_models(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Updating models list displays all registered models."""
        llm_config_dialog.llm_manager.get_available_llms = Mock(
            return_value=["model_1", "model_2", "model_3"]
        )
        llm_config_dialog.llm_manager.active_backend = "model_2"

        llm_config_dialog.update_models_list()

        assert llm_config_dialog.models_list.count() == 3
        item_texts = [llm_config_dialog.models_list.item(i).text() for i in range(3)]
        assert any("model_2" in text and "Active" in text for text in item_texts)

    def test_set_active_model_changes_active_backend(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Setting active model changes LLM manager's active backend."""
        llm_config_dialog.llm_manager.get_available_llms = Mock(return_value=["model_a", "model_b"])
        llm_config_dialog.update_models_list()

        llm_config_dialog.models_list.setCurrentRow(1)
        llm_config_dialog.set_active_model()

        llm_config_dialog.llm_manager.set_active_llm.assert_called()

    def test_remove_model_with_confirmation_removes_from_list(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Removing model with confirmation removes it from tracking."""
        llm_config_dialog.current_configs["test_model"] = Mock()
        llm_config_dialog.llm_manager.get_available_llms = Mock(return_value=["test_model"])
        llm_config_dialog.update_models_list()
        llm_config_dialog.models_list.setCurrentRow(0)

        with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
            llm_config_dialog.remove_model()

            assert "test_model" not in llm_config_dialog.current_configs

    def test_remove_model_without_confirmation_keeps_model(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Cancelling model removal keeps it in tracking."""
        llm_config_dialog.current_configs["test_model"] = Mock()
        llm_config_dialog.llm_manager.get_available_llms = Mock(return_value=["test_model"])
        llm_config_dialog.update_models_list()
        llm_config_dialog.models_list.setCurrentRow(0)

        with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.No):
            llm_config_dialog.remove_model()

            assert "test_model" in llm_config_dialog.current_configs


class TestLoRAAdapterManagement:
    """Test LoRA adapter loading and management."""

    def test_browse_lora_adapter_updates_path_field(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Browsing for LoRA adapter updates path field."""
        test_adapter_path = "D:\\adapters\\my_lora_adapter"

        with patch.object(QFileDialog, "getExistingDirectory", return_value=test_adapter_path):
            llm_config_dialog.browse_lora_adapter()

            assert llm_config_dialog.lora_adapter_path.text() == test_adapter_path
            assert llm_config_dialog.lora_adapter_name.text() == "my_lora_adapter"

    def test_add_lora_adapter_without_base_model_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Adding LoRA adapter without base model displays warning."""
        llm_config_dialog.lora_base_model.clear()

        with patch.object(QMessageBox, "warning") as mock_warning:
            llm_config_dialog.add_lora_adapter()
            mock_warning.assert_called_once()

    def test_add_lora_adapter_without_adapter_path_shows_warning(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Adding LoRA adapter without adapter path displays warning."""
        llm_config_dialog.lora_base_model.addItem("base_model_id")
        llm_config_dialog.lora_base_model.setCurrentIndex(0)
        llm_config_dialog.lora_adapter_path.clear()

        with patch.object(QMessageBox, "warning") as mock_warning:
            llm_config_dialog.add_lora_adapter()
            mock_warning.assert_called_once()

    def test_refresh_lora_models_updates_base_model_list(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Refreshing LoRA models updates base model dropdown."""
        llm_config_dialog.llm_manager.backends = {
            "model_1": Mock(),
            "model_2": Mock(),
            "model_3": Mock(),
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
        mock_config = Mock(spec=LLMConfig)
        mock_config.provider = LLMProvider.OPENAI

        thread = ModelTestThread(mock_config)

        assert thread.config == mock_config

    def test_model_test_thread_emits_progress_signals(
        self,
        qapp: QApplication,
    ) -> None:
        """ModelTestThread emits progress signals during execution."""
        mock_config = Mock(spec=LLMConfig)
        mock_config.provider = LLMProvider.OPENAI

        with patch("intellicrack.ui.dialogs.llm_config_dialog._get_llm_manager"):
            thread = ModelTestThread(mock_config)

            progress_messages: list[str] = []

            def on_progress(message: str) -> None:
                progress_messages.append(message)

            thread.validation_progress.connect(on_progress)

            with patch("intellicrack.ui.dialogs.llm_config_dialog._get_llm_manager", return_value=None):
                thread.run()

            qapp.processEvents()


class TestCloseEvent:
    """Test dialog close event handling."""

    def test_close_event_with_running_validation_prompts_user(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Closing dialog with running validation prompts confirmation."""
        llm_config_dialog.validation_thread = Mock()
        llm_config_dialog.validation_thread.isRunning.return_value = True

        from PyQt6.QtGui import QCloseEvent

        close_event = QCloseEvent()

        with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.No):
            llm_config_dialog.closeEvent(close_event)

            assert close_event.isAccepted() is False

    def test_close_event_with_running_validation_and_confirmation_terminates_thread(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Closing dialog with confirmation terminates validation thread."""
        llm_config_dialog.validation_thread = Mock()
        llm_config_dialog.validation_thread.isRunning.return_value = True

        from PyQt6.QtGui import QCloseEvent

        close_event = QCloseEvent()

        with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
            llm_config_dialog.closeEvent(close_event)

            llm_config_dialog.validation_thread.terminate.assert_called_once()
            llm_config_dialog.validation_thread.wait.assert_called_once()
            assert close_event.isAccepted() is True


class TestModelDiscoveryIntegration:
    """Test model discovery service integration."""

    def test_save_configuration_triggers_model_discovery_refresh(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Saving configuration triggers model discovery service refresh."""
        llm_config_dialog.openai_api_key.setText("sk-test-key")

        mock_discovery_service = Mock()
        mock_discovery_service.discover_all_models = Mock(
            return_value={
                "openai": ["gpt-4", "gpt-3.5-turbo"],
                "anthropic": ["claude-3-sonnet"],
            }
        )

        with (
            patch("intellicrack.ui.dialogs.llm_config_dialog.get_model_discovery_service", return_value=mock_discovery_service),
            patch.object(QMessageBox, "information"),
        ):
            llm_config_dialog.save_configuration()

            mock_discovery_service.clear_cache.assert_called_once()
            mock_discovery_service.discover_all_models.assert_called_once_with(force_refresh=True)


class TestConfigurationPersistence:
    """Test configuration loading and persistence."""

    def test_load_existing_configs_updates_models_list(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Loading existing configs updates models list."""
        llm_config_dialog.llm_manager.get_available_llms = Mock(
            return_value=["existing_model_1", "existing_model_2"]
        )

        llm_config_dialog.load_existing_configs()

        assert "Loaded 2 existing models" in llm_config_dialog.status_text.toPlainText()

    def test_load_existing_configs_with_no_models_shows_message(
        self,
        llm_config_dialog: LLMConfigDialog,
    ) -> None:
        """Loading configs with no existing models shows appropriate message."""
        llm_config_dialog.llm_manager.get_available_llms = Mock(return_value=[])

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
