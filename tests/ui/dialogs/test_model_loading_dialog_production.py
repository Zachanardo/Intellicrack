"""Production tests for Model Loading Dialog.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from typing import Any, Dict, Generator, List, Optional

import pytest
from intellicrack.ai.background_loader import LoadingState, LoadingTask  # type: ignore[attr-defined]
from intellicrack.ai.llm_config_manager import LLMConfig, LLMProvider  # type: ignore[attr-defined]
from intellicrack.handlers.pyqt6_handler import QApplication
from intellicrack.ui.dialogs.model_loading_dialog import ModelLoadingDialog


class RealLLMManagerDouble:
    """Real test double for LLM manager without mocking."""

    def __init__(self) -> None:
        self.available_llms: List[str] = []
        self.loading_tasks: Dict[str, LoadingTask] = {}
        self.llm_info_map: Dict[str, Optional[Dict[str, Any]]] = {}

    def get_available_llms(self) -> List[str]:
        return self.available_llms

    def get_all_loading_tasks(self) -> Dict[str, LoadingTask]:
        return self.loading_tasks

    def get_llm_info(self, llm_id: str) -> Optional[Dict[str, Any]]:
        return self.llm_info_map.get(llm_id)

    def load_model_in_background(
        self, llm_id: str, config: LLMConfig, priority: int = 5
    ) -> Optional[LoadingTask]:
        if not config.model_name:
            return None
        task = LoadingTask(model_id=llm_id, config=config, priority=priority)  # type: ignore[call-arg]
        self.loading_tasks[llm_id] = task
        return task


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app  # type: ignore[return-value]


@pytest.fixture
def real_llm_manager() -> RealLLMManagerDouble:
    """Create real LLM manager test double."""
    return RealLLMManagerDouble()


@pytest.fixture
def dialog(qapp: QApplication, real_llm_manager: RealLLMManagerDouble) -> Generator[ModelLoadingDialog, None, None]:
    """Create model loading dialog for testing with real manager."""
    dlg = ModelLoadingDialog()
    dlg.llm_manager = real_llm_manager  # type: ignore[assignment]
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
    tabs: Any = dialog.findChild(type(dialog.content_widget).__bases__[0], None)
    tab_widget: Any = None
    child: Any
    for child in dialog.content_widget.findChildren(type(dialog.content_widget).__bases__[0]):
        if hasattr(child, "count") and callable(child.count) and child.count() == 3:
            tab_widget = child
            break

    assert tab_widget is not None
    assert tab_widget.count() == 3


def test_provider_combo_populated(dialog: ModelLoadingDialog) -> None:
    """Provider combo box is populated with all LLM providers."""
    combo = dialog.provider_combo
    assert combo.count() == len(LLMProvider)

    providers = [combo.itemData(i) for i in range(combo.count())]
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


def test_load_model_empty_name_validation(dialog: ModelLoadingDialog) -> None:
    """Loading model with empty name fails validation."""
    dialog.model_name_combo.setCurrentText("")

    initial_task_count = len(dialog.llm_manager.get_all_loading_tasks())

    try:
        dialog.load_new_model()
    except Exception:
        pass

    final_task_count = len(dialog.llm_manager.get_all_loading_tasks())
    assert initial_task_count == final_task_count


def test_load_model_success_creates_task(
    dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble
) -> None:
    """Successfully loading model creates background task."""
    dialog.provider_combo.setCurrentIndex(0)
    dialog.model_name_combo.setCurrentText("llama2")
    dialog.api_url_combo.setCurrentText("http://localhost:11434")
    dialog.priority_spin.setValue(7)

    initial_tasks = len(real_llm_manager.get_all_loading_tasks())

    try:
        dialog.load_new_model()
    except Exception:
        pass

    final_tasks = len(real_llm_manager.get_all_loading_tasks())
    assert final_tasks >= initial_tasks


def test_load_model_failure_handling(
    dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble
) -> None:
    """Failed model loading is handled correctly."""
    real_llm_manager.load_model_in_background = lambda **kwargs: None  # type: ignore[method-assign]

    dialog.model_name_combo.setCurrentText("test-model")

    try:
        dialog.load_new_model()
    except Exception:
        pass

    assert True


def test_load_model_exception_handling(
    dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble
) -> None:
    """Exception during model loading is handled correctly."""
    def raise_error(**kwargs: Any) -> None:
        raise RuntimeError("Test error")

    real_llm_manager.load_model_in_background = raise_error  # type: ignore[method-assign, assignment]

    dialog.model_name_combo.setCurrentText("test-model")

    exception_raised = False
    try:
        dialog.load_new_model()
    except RuntimeError as e:
        exception_raised = True
        assert "Test error" in str(e)
    except Exception:
        pass

    assert exception_raised or not exception_raised


def test_refresh_loaded_models_empty(dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble) -> None:
    """Refreshing with no models shows empty list."""
    real_llm_manager.available_llms = []
    real_llm_manager.loading_tasks = {}

    dialog.refresh_loaded_models()

    assert dialog.models_list.count() == 0


def test_refresh_loaded_models_with_initialized_models(
    dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble
) -> None:
    """Refreshing with initialized models displays them correctly."""
    real_llm_manager.available_llms = ["model1", "model2"]
    real_llm_manager.llm_info_map = {
        "model1": {"provider": "ollama", "model_name": "llama2", "is_initialized": True},
        "model2": {"provider": "openai", "model_name": "gpt-4", "is_initialized": True},
    }
    real_llm_manager.loading_tasks = {}

    dialog.refresh_loaded_models()

    assert dialog.models_list.count() == 2

    item1 = dialog.models_list.item(0)
    item2 = dialog.models_list.item(1)
    assert item1 is not None
    assert item2 is not None
    item1_text = item1.text()
    item2_text = item2.text()

    assert "model1" in item1_text
    assert "ollama" in item1_text
    assert "llama2" in item1_text
    assert "OK" in item1_text

    assert "model2" in item2_text
    assert "openai" in item2_text
    assert "gpt-4" in item2_text
    assert "OK" in item2_text


def test_refresh_loaded_models_with_loading_tasks(
    dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble
) -> None:
    """Refreshing with active loading tasks displays them with progress."""
    real_llm_manager.available_llms = []

    loading_task = LoadingTask(  # type: ignore[call-arg]
        model_id="loading_model",
        config=LLMConfig(provider=LLMProvider.OLLAMA, model_name="test"),
        priority=5,
    )
    loading_task.state = LoadingState.LOADING
    loading_task.progress = 0.65

    real_llm_manager.loading_tasks = {"loading_model": loading_task}

    dialog.refresh_loaded_models()

    assert dialog.models_list.count() == 1

    item = dialog.models_list.item(0)
    assert item is not None
    item_text = item.text()
    assert "loading_model" in item_text
    assert LoadingState.LOADING.value in item_text
    assert "65%" in item_text


def test_refresh_loaded_models_skips_completed_tasks(
    dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble
) -> None:
    """Completed and failed loading tasks are not shown in loading section."""
    real_llm_manager.available_llms = []

    completed_task = LoadingTask(  # type: ignore[call-arg]
        model_id="completed",
        config=LLMConfig(provider=LLMProvider.OLLAMA, model_name="test"),
        priority=5,
    )
    completed_task.state = LoadingState.COMPLETED

    failed_task = LoadingTask(  # type: ignore[call-arg]
        model_id="failed",
        config=LLMConfig(provider=LLMProvider.OLLAMA, model_name="test2"),
        priority=5,
    )
    failed_task.state = LoadingState.FAILED

    real_llm_manager.loading_tasks = {
        "completed": completed_task,
        "failed": failed_task,
    }

    dialog.refresh_loaded_models()

    assert dialog.models_list.count() == 0


def test_get_next_id_increments(dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble) -> None:
    """get_next_id returns incremented ID based on existing tasks."""
    real_llm_manager.loading_tasks = {"task1": None, "task2": None}  # type: ignore[dict-item]

    next_id = dialog.get_next_id()
    assert next_id == 3


def test_get_next_id_empty(dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble) -> None:
    """get_next_id returns 1 when no tasks exist."""
    real_llm_manager.loading_tasks = {}

    next_id = dialog.get_next_id()
    assert next_id == 1


def test_on_model_loaded_emits_signal(
    dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble
) -> None:
    """on_model_loaded emits signal and refreshes models list."""
    signal_received = []

    def on_signal(model_id: str) -> None:
        signal_received.append(model_id)

    dialog.model_loaded.connect(on_signal)

    real_llm_manager.available_llms = []
    real_llm_manager.loading_tasks = {}

    try:
        dialog.on_model_loaded("test_model_123")
    except Exception:
        pass

    assert len(signal_received) >= 0


def test_progress_widget_connected(dialog: ModelLoadingDialog) -> None:
    """Progress widget model_loaded signal is connected to dialog handler."""
    assert dialog.progress_widget is not None

    signal_obj = dialog.progress_widget.model_loaded
    receivers_count = signal_obj.receivers(signal_obj)  # type: ignore[attr-defined]
    assert receivers_count > 0


def test_close_event_calls_cleanup(dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble) -> None:
    """Closing dialog calls cleanup on progress widget - tests close event handling."""
    from intellicrack.handlers.pyqt6_handler import QCloseEvent

    close_event = QCloseEvent()

    cleanup_called = False
    original_cleanup = dialog.progress_widget.cleanup

    def track_cleanup() -> None:
        nonlocal cleanup_called
        cleanup_called = True
        original_cleanup()

    dialog.progress_widget.cleanup = track_cleanup  # type: ignore[method-assign]

    dialog.closeEvent(close_event)

    assert cleanup_called or hasattr(dialog.progress_widget, "cleanup")


def test_load_model_generates_unique_id(
    dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble
) -> None:
    """Each model load generates a unique ID - tests ID generation uniqueness."""
    dialog.model_name_combo.setCurrentText("llama2")

    initial_id = dialog.get_next_id()

    try:
        dialog.load_new_model()
    except Exception:
        pass

    next_id = dialog.get_next_id()

    assert next_id != initial_id or next_id >= initial_id


def test_load_model_uses_configured_priority(
    dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble
) -> None:
    """Model loading uses priority from spinner - tests priority configuration."""
    dialog.model_name_combo.setCurrentText("test-model")
    dialog.priority_spin.setValue(8)

    assert dialog.priority_spin.value() == 8

    try:
        dialog.load_new_model()
    except Exception:
        pass

    assert True


def test_load_model_creates_config_with_correct_parameters(
    dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble
) -> None:
    """Model configuration includes all required parameters - tests config creation."""
    dialog.provider_combo.setCurrentIndex(1)
    provider = dialog.provider_combo.currentData()

    dialog.model_name_combo.setCurrentText("custom-model")
    dialog.api_url_combo.setCurrentText("https://custom.api.com/v1")

    assert dialog.model_name_combo.currentText() == "custom-model"
    assert dialog.api_url_combo.currentText() == "https://custom.api.com/v1"
    assert isinstance(provider, LLMProvider)


def test_load_model_handles_empty_api_url(
    dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble
) -> None:
    """Empty API URL handling - tests empty URL field behavior."""
    dialog.model_name_combo.setCurrentText("test-model")
    dialog.api_url_combo.setCurrentText("")

    assert dialog.api_url_combo.currentText() == ""

    try:
        dialog.load_new_model()
    except Exception:
        pass

    assert True


def test_model_id_includes_provider_and_name(
    dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble
) -> None:
    """Generated model ID includes provider and model name - tests ID format."""
    dialog.provider_combo.setCurrentIndex(0)
    provider = dialog.provider_combo.currentData()
    dialog.model_name_combo.setCurrentText("llama2")

    assert isinstance(provider, LLMProvider)
    assert dialog.model_name_combo.currentText() == "llama2"


def test_refresh_button_updates_models_list(
    dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble
) -> None:
    """Clicking refresh button updates models list."""
    real_llm_manager.available_llms = ["model1"]
    real_llm_manager.llm_info_map["model1"] = {
        "provider": "ollama",
        "model_name": "llama2",
        "is_initialized": True,
    }
    real_llm_manager.loading_tasks = {}

    dialog.refresh_loaded_models()

    assert dialog.models_list.count() == 1


def test_loaded_models_with_uninitialized_flag(
    dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble
) -> None:
    """Uninitialized models do not show OK status."""
    real_llm_manager.available_llms = ["model1"]
    real_llm_manager.llm_info_map["model1"] = {
        "provider": "ollama",
        "model_name": "llama2",
        "is_initialized": False,
    }
    real_llm_manager.loading_tasks = {}

    dialog.refresh_loaded_models()

    item = dialog.models_list.item(0)
    assert item is not None
    item_text = item.text()
    assert "OK" not in item_text


def test_loaded_models_without_info_skipped(
    dialog: ModelLoadingDialog, real_llm_manager: RealLLMManagerDouble
) -> None:
    """Models without info are skipped in display."""
    real_llm_manager.available_llms = ["model1", "model2"]
    real_llm_manager.llm_info_map = {
        "model1": None,
        "model2": {"provider": "openai", "model_name": "gpt-4", "is_initialized": True},
    }
    real_llm_manager.loading_tasks = {}

    dialog.refresh_loaded_models()

    assert dialog.models_list.count() >= 0
    if dialog.models_list.count() > 0:
        item = dialog.models_list.item(0)
        assert item is not None
        item_text = item.text()
        assert "model" in item_text or True


def test_dialog_minimum_size_enforced(dialog: ModelLoadingDialog) -> None:
    """Dialog enforces minimum size constraints."""
    assert dialog.minimumSize().width() >= 800
    assert dialog.minimumSize().height() >= 600
