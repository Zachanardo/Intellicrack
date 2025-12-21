"""Production tests for Model Loading Dialog.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from intellicrack.ai.background_loader import LoadingState, LoadingTask
from intellicrack.ai.llm_config_manager import LLMConfig, LLMProvider
from intellicrack.handlers.pyqt6_handler import QApplication, QMessageBox
from intellicrack.ui.dialogs.model_loading_dialog import ModelLoadingDialog


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def mock_llm_manager() -> MagicMock:
    """Create mock LLM manager."""
    manager = MagicMock()
    manager.get_available_llms.return_value = []
    manager.get_all_loading_tasks.return_value = {}
    manager.get_llm_info.return_value = None
    return manager


@pytest.fixture
def dialog(qapp: QApplication, mock_llm_manager: MagicMock) -> ModelLoadingDialog:
    """Create model loading dialog for testing."""
    with patch("intellicrack.ui.dialogs.model_loading_dialog.get_llm_manager", return_value=mock_llm_manager):
        dlg = ModelLoadingDialog()
        yield dlg
        dlg.deleteLater()


def test_dialog_initialization(dialog: ModelLoadingDialog) -> None:
    """Dialog initializes with all required components."""
    assert dialog.windowTitle() == "Model Loading Manager"
    assert dialog.minimumWidth() == 800
    assert dialog.minimumHeight() == 600

    assert hasattr(dialog, "llm_manager")
    assert hasattr(dialog, "progress_widget")
    assert hasattr(dialog, "provider_combo")
    assert hasattr(dialog, "model_name_combo")
    assert hasattr(dialog, "api_url_combo")
    assert hasattr(dialog, "priority_spin")
    assert hasattr(dialog, "models_list")


def test_tab_structure(dialog: ModelLoadingDialog) -> None:
    """Dialog contains three required tabs."""
    tabs = dialog.findChild(type(dialog.content_widget).__bases__[0], None)
    tab_widget = None
    for child in dialog.content_widget.findChildren(type(dialog.content_widget).__bases__[0]):
        if hasattr(child, "count") and callable(child.count):
            if child.count() == 3:
                tab_widget = child
                break

    assert tab_widget is not None
    assert tab_widget.count() == 3


def test_provider_combo_populated(dialog: ModelLoadingDialog) -> None:
    """Provider combo box is populated with all LLM providers."""
    combo = dialog.provider_combo
    assert combo.count() == len(LLMProvider)

    providers = []
    for i in range(combo.count()):
        providers.append(combo.itemData(i))

    for provider in LLMProvider:
        assert provider in providers


def test_model_name_combo_has_default_models(dialog: ModelLoadingDialog) -> None:
    """Model name combo box has default model suggestions."""
    combo = dialog.model_name_combo
    assert combo.isEditable()
    assert combo.count() > 0

    items = [combo.itemText(i) for i in range(combo.count())]
    assert "llama2" in items
    assert "gpt-3.5-turbo" in items
    assert "claude-2" in items


def test_api_url_combo_has_default_urls(dialog: ModelLoadingDialog) -> None:
    """API URL combo box has default API endpoints."""
    combo = dialog.api_url_combo
    assert combo.isEditable()
    assert combo.count() > 0

    items = [combo.itemText(i) for i in range(combo.count())]
    assert "http://localhost:11434" in items
    assert "http://localhost:1234" in items
    assert "https://api.openai.com/v1" in items
    assert "https://api.anthropic.com/v1" in items


def test_priority_spin_range(dialog: ModelLoadingDialog) -> None:
    """Priority spinner has correct range and default value."""
    spin = dialog.priority_spin
    assert spin.minimum() == 0
    assert spin.maximum() == 10
    assert spin.value() == 5


@patch.object(QMessageBox, "warning")
def test_load_model_empty_name_shows_warning(
    mock_warning: MagicMock, dialog: ModelLoadingDialog
) -> None:
    """Loading model with empty name shows warning."""
    dialog.model_name_combo.setCurrentText("")
    dialog.load_new_model()

    mock_warning.assert_called_once()
    args = mock_warning.call_args[0]
    assert "model name" in args[1].lower()


@patch.object(QMessageBox, "information")
def test_load_model_success_creates_task(
    mock_info: MagicMock, dialog: ModelLoadingDialog, mock_llm_manager: MagicMock
) -> None:
    """Successfully loading model creates background task."""
    mock_task = LoadingTask(
        model_id="test_model",
        config=LLMConfig(provider=LLMProvider.OLLAMA, model_name="llama2"),
        priority=5,
    )
    mock_llm_manager.load_model_in_background.return_value = mock_task

    dialog.provider_combo.setCurrentIndex(0)
    dialog.model_name_combo.setCurrentText("llama2")
    dialog.api_url_combo.setCurrentText("http://localhost:11434")
    dialog.priority_spin.setValue(7)

    dialog.load_new_model()

    mock_llm_manager.load_model_in_background.assert_called_once()
    call_args = mock_llm_manager.load_model_in_background.call_args
    assert "llm_id" in call_args.kwargs
    assert "config" in call_args.kwargs
    assert call_args.kwargs["priority"] == 7

    config = call_args.kwargs["config"]
    assert isinstance(config, LLMConfig)
    assert config.model_name == "llama2"
    assert config.api_url == "http://localhost:11434"

    mock_info.assert_called_once()


@patch.object(QMessageBox, "critical")
def test_load_model_failure_shows_error(
    mock_error: MagicMock, dialog: ModelLoadingDialog, mock_llm_manager: MagicMock
) -> None:
    """Failed model loading shows error message."""
    mock_llm_manager.load_model_in_background.return_value = None

    dialog.model_name_combo.setCurrentText("test-model")
    dialog.load_new_model()

    mock_error.assert_called_once()


@patch.object(QMessageBox, "critical")
def test_load_model_exception_shows_error(
    mock_error: MagicMock, dialog: ModelLoadingDialog, mock_llm_manager: MagicMock
) -> None:
    """Exception during model loading shows error message."""
    mock_llm_manager.load_model_in_background.side_effect = RuntimeError("Test error")

    dialog.model_name_combo.setCurrentText("test-model")
    dialog.load_new_model()

    mock_error.assert_called_once()
    args = mock_error.call_args[0]
    assert "Test error" in args[2]


def test_refresh_loaded_models_empty(dialog: ModelLoadingDialog, mock_llm_manager: MagicMock) -> None:
    """Refreshing with no models shows empty list."""
    mock_llm_manager.get_available_llms.return_value = []
    mock_llm_manager.get_all_loading_tasks.return_value = {}

    dialog.refresh_loaded_models()

    assert dialog.models_list.count() == 0


def test_refresh_loaded_models_with_initialized_models(
    dialog: ModelLoadingDialog, mock_llm_manager: MagicMock
) -> None:
    """Refreshing with initialized models displays them correctly."""
    mock_llm_manager.get_available_llms.return_value = ["model1", "model2"]
    mock_llm_manager.get_llm_info.side_effect = [
        {"provider": "ollama", "model_name": "llama2", "is_initialized": True},
        {"provider": "openai", "model_name": "gpt-4", "is_initialized": True},
    ]
    mock_llm_manager.get_all_loading_tasks.return_value = {}

    dialog.refresh_loaded_models()

    assert dialog.models_list.count() == 2

    item1_text = dialog.models_list.item(0).text()
    item2_text = dialog.models_list.item(1).text()

    assert "model1" in item1_text
    assert "ollama" in item1_text
    assert "llama2" in item1_text
    assert "OK" in item1_text

    assert "model2" in item2_text
    assert "openai" in item2_text
    assert "gpt-4" in item2_text
    assert "OK" in item2_text


def test_refresh_loaded_models_with_loading_tasks(
    dialog: ModelLoadingDialog, mock_llm_manager: MagicMock
) -> None:
    """Refreshing with active loading tasks displays them with progress."""
    mock_llm_manager.get_available_llms.return_value = []

    loading_task = LoadingTask(
        model_id="loading_model",
        config=LLMConfig(provider=LLMProvider.OLLAMA, model_name="test"),
        priority=5,
    )
    loading_task.state = LoadingState.LOADING
    loading_task.progress = 0.65

    mock_llm_manager.get_all_loading_tasks.return_value = {"loading_model": loading_task}

    dialog.refresh_loaded_models()

    assert dialog.models_list.count() == 1

    item_text = dialog.models_list.item(0).text()
    assert "loading_model" in item_text
    assert LoadingState.LOADING.value in item_text
    assert "65%" in item_text


def test_refresh_loaded_models_skips_completed_tasks(
    dialog: ModelLoadingDialog, mock_llm_manager: MagicMock
) -> None:
    """Completed and failed loading tasks are not shown in loading section."""
    mock_llm_manager.get_available_llms.return_value = []

    completed_task = LoadingTask(
        model_id="completed",
        config=LLMConfig(provider=LLMProvider.OLLAMA, model_name="test"),
        priority=5,
    )
    completed_task.state = LoadingState.COMPLETED

    failed_task = LoadingTask(
        model_id="failed",
        config=LLMConfig(provider=LLMProvider.OLLAMA, model_name="test2"),
        priority=5,
    )
    failed_task.state = LoadingState.FAILED

    mock_llm_manager.get_all_loading_tasks.return_value = {
        "completed": completed_task,
        "failed": failed_task,
    }

    dialog.refresh_loaded_models()

    assert dialog.models_list.count() == 0


def test_get_next_id_increments(dialog: ModelLoadingDialog, mock_llm_manager: MagicMock) -> None:
    """get_next_id returns incremented ID based on existing tasks."""
    mock_llm_manager.get_all_loading_tasks.return_value = {"task1": None, "task2": None}

    next_id = dialog.get_next_id()
    assert next_id == 3


def test_get_next_id_empty(dialog: ModelLoadingDialog, mock_llm_manager: MagicMock) -> None:
    """get_next_id returns 1 when no tasks exist."""
    mock_llm_manager.get_all_loading_tasks.return_value = {}

    next_id = dialog.get_next_id()
    assert next_id == 1


@patch.object(QMessageBox, "information")
def test_on_model_loaded_emits_signal(
    mock_info: MagicMock, dialog: ModelLoadingDialog, mock_llm_manager: MagicMock
) -> None:
    """on_model_loaded emits signal and refreshes models list."""
    signal_received = []

    def on_signal(model_id: str) -> None:
        signal_received.append(model_id)

    dialog.model_loaded.connect(on_signal)

    mock_llm_manager.get_available_llms.return_value = []
    mock_llm_manager.get_all_loading_tasks.return_value = {}

    dialog.on_model_loaded("test_model_123")

    assert len(signal_received) == 1
    assert signal_received[0] == "test_model_123"

    mock_info.assert_called_once()
    args = mock_info.call_args[0]
    assert "test_model_123" in args[2]


def test_progress_widget_connected(dialog: ModelLoadingDialog) -> None:
    """Progress widget model_loaded signal is connected to dialog handler."""
    assert dialog.progress_widget is not None

    signal_obj = dialog.progress_widget.model_loaded
    receivers_count = signal_obj.receivers(signal_obj)
    assert receivers_count > 0


def test_close_event_calls_cleanup(dialog: ModelLoadingDialog, mock_llm_manager: MagicMock) -> None:
    """Closing dialog calls cleanup on progress widget."""
    with patch.object(dialog.progress_widget, "cleanup") as mock_cleanup:
        from intellicrack.handlers.pyqt6_handler import QCloseEvent

        close_event = QCloseEvent()
        dialog.closeEvent(close_event)

        mock_cleanup.assert_called_once()


def test_load_model_generates_unique_id(
    dialog: ModelLoadingDialog, mock_llm_manager: MagicMock
) -> None:
    """Each model load generates a unique ID."""
    mock_task = LoadingTask(
        model_id="test",
        config=LLMConfig(provider=LLMProvider.OLLAMA, model_name="test"),
        priority=5,
    )
    mock_llm_manager.load_model_in_background.return_value = mock_task

    dialog.model_name_combo.setCurrentText("llama2")

    with patch.object(QMessageBox, "information"):
        dialog.load_new_model()

        first_call = mock_llm_manager.load_model_in_background.call_args
        first_id = first_call.kwargs["llm_id"]

        mock_llm_manager.get_all_loading_tasks.return_value = {"task1": None}

        dialog.load_new_model()

        second_call = mock_llm_manager.load_model_in_background.call_args
        second_id = second_call.kwargs["llm_id"]

        assert first_id != second_id


def test_load_model_uses_configured_priority(
    dialog: ModelLoadingDialog, mock_llm_manager: MagicMock
) -> None:
    """Model loading uses priority from spinner."""
    mock_task = LoadingTask(
        model_id="test",
        config=LLMConfig(provider=LLMProvider.OLLAMA, model_name="test"),
        priority=5,
    )
    mock_llm_manager.load_model_in_background.return_value = mock_task

    dialog.model_name_combo.setCurrentText("test-model")
    dialog.priority_spin.setValue(8)

    with patch.object(QMessageBox, "information"):
        dialog.load_new_model()

        call_args = mock_llm_manager.load_model_in_background.call_args
        assert call_args.kwargs["priority"] == 8


def test_load_model_creates_config_with_correct_parameters(
    dialog: ModelLoadingDialog, mock_llm_manager: MagicMock
) -> None:
    """Model configuration includes all required parameters."""
    mock_task = LoadingTask(
        model_id="test",
        config=LLMConfig(provider=LLMProvider.OLLAMA, model_name="test"),
        priority=5,
    )
    mock_llm_manager.load_model_in_background.return_value = mock_task

    dialog.provider_combo.setCurrentIndex(1)
    provider = dialog.provider_combo.currentData()

    dialog.model_name_combo.setCurrentText("custom-model")
    dialog.api_url_combo.setCurrentText("https://custom.api.com/v1")

    with patch.object(QMessageBox, "information"):
        dialog.load_new_model()

        call_args = mock_llm_manager.load_model_in_background.call_args
        config = call_args.kwargs["config"]

        assert isinstance(config, LLMConfig)
        assert config.provider == provider
        assert config.model_name == "custom-model"
        assert config.api_url == "https://custom.api.com/v1"
        assert config.max_tokens == 2048
        assert config.temperature == 0.7


def test_load_model_handles_empty_api_url(
    dialog: ModelLoadingDialog, mock_llm_manager: MagicMock
) -> None:
    """Empty API URL is converted to None in configuration."""
    mock_task = LoadingTask(
        model_id="test",
        config=LLMConfig(provider=LLMProvider.OLLAMA, model_name="test"),
        priority=5,
    )
    mock_llm_manager.load_model_in_background.return_value = mock_task

    dialog.model_name_combo.setCurrentText("test-model")
    dialog.api_url_combo.setCurrentText("")

    with patch.object(QMessageBox, "information"):
        dialog.load_new_model()

        call_args = mock_llm_manager.load_model_in_background.call_args
        config = call_args.kwargs["config"]
        assert config.api_url is None


def test_model_id_includes_provider_and_name(
    dialog: ModelLoadingDialog, mock_llm_manager: MagicMock
) -> None:
    """Generated model ID includes provider and model name."""
    mock_task = LoadingTask(
        model_id="test",
        config=LLMConfig(provider=LLMProvider.OLLAMA, model_name="test"),
        priority=5,
    )
    mock_llm_manager.load_model_in_background.return_value = mock_task

    dialog.provider_combo.setCurrentIndex(0)
    provider = dialog.provider_combo.currentData()
    dialog.model_name_combo.setCurrentText("llama2")

    with patch.object(QMessageBox, "information"):
        dialog.load_new_model()

        call_args = mock_llm_manager.load_model_in_background.call_args
        model_id = call_args.kwargs["llm_id"]

        assert provider.value in model_id
        assert "llama2" in model_id


def test_refresh_button_updates_models_list(
    dialog: ModelLoadingDialog, mock_llm_manager: MagicMock
) -> None:
    """Clicking refresh button updates models list."""
    mock_llm_manager.get_available_llms.return_value = ["model1"]
    mock_llm_manager.get_llm_info.return_value = {
        "provider": "ollama",
        "model_name": "llama2",
        "is_initialized": True,
    }
    mock_llm_manager.get_all_loading_tasks.return_value = {}

    dialog.refresh_loaded_models()

    assert dialog.models_list.count() == 1


def test_loaded_models_with_uninitialized_flag(
    dialog: ModelLoadingDialog, mock_llm_manager: MagicMock
) -> None:
    """Uninitialized models do not show OK status."""
    mock_llm_manager.get_available_llms.return_value = ["model1"]
    mock_llm_manager.get_llm_info.return_value = {
        "provider": "ollama",
        "model_name": "llama2",
        "is_initialized": False,
    }
    mock_llm_manager.get_all_loading_tasks.return_value = {}

    dialog.refresh_loaded_models()

    item_text = dialog.models_list.item(0).text()
    assert "OK" not in item_text


def test_loaded_models_without_info_skipped(
    dialog: ModelLoadingDialog, mock_llm_manager: MagicMock
) -> None:
    """Models without info are skipped in display."""
    mock_llm_manager.get_available_llms.return_value = ["model1", "model2"]
    mock_llm_manager.get_llm_info.side_effect = [
        None,
        {"provider": "openai", "model_name": "gpt-4", "is_initialized": True},
    ]
    mock_llm_manager.get_all_loading_tasks.return_value = {}

    dialog.refresh_loaded_models()

    assert dialog.models_list.count() == 1
    item_text = dialog.models_list.item(0).text()
    assert "model2" in item_text


def test_dialog_minimum_size_enforced(dialog: ModelLoadingDialog) -> None:
    """Dialog enforces minimum size constraints."""
    assert dialog.minimumSize().width() >= 800
    assert dialog.minimumSize().height() >= 600
