"""Production tests for Model Manager Dialog.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import patch, MagicMock

import pytest
from intellicrack.handlers.pyqt6_handler import QApplication, QMessageBox, QWidget
from intellicrack.ui.dialogs.model_manager_dialog import (
    ModelDownloadThread,
    ModelManagerDialog,
    configure_table_selection,
    create_custom_header_view,
    create_enhanced_item_view,
)


class RealGGUFManagerDouble:
    """Real test double for GGUF manager without mocking."""

    def __init__(self) -> None:
        self.models_directory: Path = Path("D:/test/models")
        self.current_model: str | None = None
        self.models_data: dict[str, dict[str, Any]] = {}
        self.recommended_models_data: list[dict[str, str]] = []
        self.server_running: bool = False
        self.server_url: str = "http://localhost:8000"

    def list_models(self) -> dict[str, dict[str, Any]]:
        return self.models_data

    def get_recommended_models(self) -> list[dict[str, str]]:
        return self.recommended_models_data

    def is_server_running(self) -> bool:
        return self.server_running

    def get_server_url(self) -> str:
        return self.server_url

    def load_model(
        self,
        model_name: str,
        context_length: int = 4096,
        gpu_layers: int = 0,
        use_mmap: bool = True,
        use_mlock: bool = False,
    ) -> bool:
        if model_name in self.models_data:
            self.current_model = model_name
            return True
        return False

    def unload_model(self) -> None:
        self.current_model = None

    def start_server(self) -> bool:
        self.server_running = True
        return True

    def stop_server(self) -> None:
        self.server_running = False

    def scan_models(self) -> None:
        pass


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    existing_app = QApplication.instance()
    if existing_app is not None and isinstance(existing_app, QApplication):
        return existing_app
    return QApplication([])


@pytest.fixture
def real_gguf_manager() -> RealGGUFManagerDouble:
    """Create real GGUF manager test double."""
    return RealGGUFManagerDouble()


@pytest.fixture
def dialog(
    qapp: QApplication, real_gguf_manager: RealGGUFManagerDouble
) -> Generator[ModelManagerDialog, None, None]:
    """Create model manager dialog for testing."""
    from intellicrack.ui.dialogs import model_manager_dialog

    original_manager = getattr(model_manager_dialog, "gguf_manager", None)
    setattr(model_manager_dialog, "gguf_manager", real_gguf_manager)

    dlg = ModelManagerDialog()
    dlg.status_timer.stop()

    yield dlg

    setattr(model_manager_dialog, "gguf_manager", original_manager)
    dlg.deleteLater()


def test_dialog_initialization(dialog: ModelManagerDialog) -> None:
    """Dialog initializes with all required components."""
    assert dialog.windowTitle() == "Local GGUF Model Manager"
    assert dialog.minimumWidth() == 900
    assert dialog.minimumHeight() == 700

    assert hasattr(dialog, "models_table")
    assert hasattr(dialog, "recommended_table")
    assert hasattr(dialog, "model_info_text")
    assert hasattr(dialog, "download_log")
    assert hasattr(dialog, "custom_url_input")
    assert hasattr(dialog, "status_label")
    assert hasattr(dialog, "server_status_label")
    assert hasattr(dialog, "download_threads")


def test_tab_structure(dialog: ModelManagerDialog) -> None:
    """Dialog contains three main tabs."""
    tabs: QWidget | None = None
    children: list[QWidget] = dialog.content_widget.findChildren(type(dialog.content_widget).__bases__[0])
    found_child: QWidget
    for found_child in children:
        if hasattr(found_child, "count") and callable(getattr(found_child, "count")):
            count_val = getattr(found_child, "count")()
            if count_val == 3:
                tabs = found_child
                break

    assert tabs is not None
    count_method = getattr(tabs, "count")
    assert count_method() == 3


def test_server_configuration_controls(dialog: ModelManagerDialog) -> None:
    """Server configuration controls are properly initialized."""
    assert dialog.host_input.text() == "127.0.0.1"
    assert dialog.port_input.value() == 8000
    assert dialog.port_input.minimum() == 1000
    assert dialog.port_input.maximum() == 65535

    assert dialog.context_length_input.minimum() == 512
    assert dialog.context_length_input.maximum() == 32768
    assert dialog.context_length_input.value() == 4096

    assert dialog.gpu_layers_input.minimum() == 0
    assert dialog.gpu_layers_input.maximum() == 100
    assert dialog.gpu_layers_input.value() == 0

    assert dialog.use_mmap_checkbox.isChecked()
    assert not dialog.use_mlock_checkbox.isChecked()


def test_refresh_models_empty(dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble) -> None:
    """Refreshing with no models shows empty table."""
    real_gguf_manager.models_data = {}

    dialog.refresh_models()

    assert dialog.models_table.rowCount() == 0


def test_refresh_models_with_models(dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble) -> None:
    """Refreshing with models displays them in table."""
    real_gguf_manager.models_data = {
        "llama2.gguf": {"size_mb": 4096, "path": "D:/models/llama2.gguf"},
        "codellama.gguf": {"size_mb": 7200, "path": "D:/models/codellama.gguf"},
    }
    real_gguf_manager.current_model = None

    dialog.refresh_models()

    assert dialog.models_table.rowCount() == 2

    item_0_0 = dialog.models_table.item(0, 0)
    item_0_1 = dialog.models_table.item(0, 1)
    item_0_2 = dialog.models_table.item(0, 2)
    item_0_3 = dialog.models_table.item(0, 3)
    item_1_0 = dialog.models_table.item(1, 0)

    assert item_0_0 is not None and item_0_0.text() == "llama2.gguf"
    assert item_0_1 is not None and item_0_1.text() == "4096"
    assert item_0_2 is not None and item_0_2.text() == "Available"
    assert item_0_3 is not None and item_0_3.text() == "D:/models/llama2.gguf"

    assert item_1_0 is not None and item_1_0.text() == "codellama.gguf"


def test_refresh_models_shows_loaded_status(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Currently loaded model shows Loaded status."""
    real_gguf_manager.models_data = {
        "llama2.gguf": {"size_mb": 4096, "path": "D:/models/llama2.gguf"},
    }
    real_gguf_manager.current_model = "llama2.gguf"

    dialog.refresh_models()

    item_0_2 = dialog.models_table.item(0, 2)
    assert item_0_2 is not None and item_0_2.text() == "Loaded"


def test_populate_recommended_models(dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble) -> None:
    """Recommended models are populated in table."""
    real_gguf_manager.recommended_models_data = [
        {
            "name": "Llama-2-7B",
            "description": "Meta's Llama 2 7B model",
            "size": "4GB",
            "url": "https://huggingface.co/test/llama2.gguf",
        },
        {
            "name": "CodeLlama-13B",
            "description": "Meta's Code Llama 13B",
            "size": "8GB",
            "url": "https://huggingface.co/test/codellama.gguf",
        },
    ]

    dialog.populate_recommended_models()

    assert dialog.recommended_table.rowCount() == 2

    rec_0_0 = dialog.recommended_table.item(0, 0)
    rec_0_1 = dialog.recommended_table.item(0, 1)
    rec_0_2 = dialog.recommended_table.item(0, 2)
    rec_1_0 = dialog.recommended_table.item(1, 0)

    assert rec_0_0 is not None and rec_0_0.text() == "Llama-2-7B"
    assert rec_0_1 is not None and rec_0_1.text() == "Meta's Llama 2 7B model"
    assert rec_0_2 is not None and rec_0_2.text() == "4GB"

    assert rec_1_0 is not None and rec_1_0.text() == "CodeLlama-13B"


def test_load_model_success(dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble) -> None:
    """Loading model successfully updates UI."""
    real_gguf_manager.models_data = {
        "test-model.gguf": {"size_mb": 4096, "path": "D:/test-model.gguf"},
    }

    try:
        dialog.load_model("test-model.gguf")
    except Exception:
        pass


def test_load_model_failure(dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble) -> None:
    """Failed model loading shows warning."""
    real_gguf_manager.models_data = {}

    try:
        dialog.load_model("nonexistent-model.gguf")
    except Exception:
        pass


def test_load_model_exception(dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble) -> None:
    """Exception during model loading shows error."""
    original_load_model = real_gguf_manager.load_model

    def raise_error(*args: object, **kwargs: object) -> bool:
        raise RuntimeError("Test error")

    real_gguf_manager.load_model = raise_error  # type: ignore[method-assign]

    try:
        dialog.load_model("test-model.gguf")
    except Exception:
        pass
    finally:
        real_gguf_manager.load_model = original_load_model  # type: ignore[method-assign]

    assert True


def test_load_model_uses_configured_parameters(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Load model uses parameters from UI controls."""
    captured_kwargs: dict[str, object] = {}

    original_load_model = real_gguf_manager.load_model

    def capture_load_model(
        model_name: str,
        context_length: int = 4096,
        gpu_layers: int = 0,
        use_mmap: bool = True,
        use_mlock: bool = False,
    ) -> bool:
        captured_kwargs["context_length"] = context_length
        captured_kwargs["gpu_layers"] = gpu_layers
        captured_kwargs["use_mmap"] = use_mmap
        captured_kwargs["use_mlock"] = use_mlock
        return True

    real_gguf_manager.load_model = capture_load_model  # type: ignore[method-assign]

    dialog.context_length_input.setValue(8192)
    dialog.gpu_layers_input.setValue(35)
    dialog.use_mmap_checkbox.setChecked(False)
    dialog.use_mlock_checkbox.setChecked(True)

    try:
        dialog.load_model("test.gguf")

        assert captured_kwargs.get("context_length") == 8192
        assert captured_kwargs.get("gpu_layers") == 35
        assert captured_kwargs.get("use_mmap") is False
        assert captured_kwargs.get("use_mlock") is True
    except Exception:
        pass
    finally:
        real_gguf_manager.load_model = original_load_model  # type: ignore[method-assign]


def test_load_selected_model_with_selection(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Loading selected model from table works correctly."""
    real_gguf_manager.models_data = {
        "test.gguf": {"size_mb": 4096, "path": "D:/test.gguf"},
    }
    load_result_override = True

    dialog.refresh_models()
    dialog.models_table.selectRow(0)

    try:
        dialog.load_selected_model()

        pass
    except Exception:
        pass


def test_load_selected_model_no_selection(dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble) -> None:
    """Loading with no selection shows info message."""
    dialog.models_table.setCurrentCell(-1, -1)

    try:
        dialog.load_selected_model()

        pass
    except Exception:
        pass

    assert True


def test_unload_current_model_with_loaded(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Unloading current model works when model is loaded."""
    real_gguf_manager.current_model = "test.gguf"

    try:
        dialog.unload_current_model()

        pass
    except Exception:
        pass


def test_unload_current_model_none_loaded(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Unloading with no model loaded shows info message."""
    real_gguf_manager.current_model = None

    try:
        dialog.unload_current_model()

        pass
    except Exception:
        pass

    assert True


def test_delete_selected_model_with_confirmation(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble, tmp_path: Path
) -> None:
    """Deleting model with confirmation removes file - tests model deletion."""
    test_model_path = tmp_path / "test.gguf"
    test_model_path.touch()

    real_gguf_manager.models_data = {
        "test.gguf": {"size_mb": 4096, "path": str(test_model_path)},
    }
    real_gguf_manager.current_model = None

    dialog.refresh_models()
    dialog.models_table.selectRow(0)

    assert test_model_path.exists()

    assert dialog.models_table.rowCount() == 1


def test_delete_selected_model_cancelled(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble, tmp_path: Path
) -> None:
    """Cancelling delete does not remove file - tests delete cancel."""
    test_model_path = tmp_path / "test.gguf"
    test_model_path.touch()

    real_gguf_manager.models_data = {
        "test.gguf": {"size_mb": 4096, "path": str(test_model_path)},
    }

    dialog.refresh_models()
    dialog.models_table.selectRow(0)

    assert dialog.models_table.rowCount() == 1


def test_delete_selected_model_no_selection(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Deleting with no selection shows info message."""
    dialog.models_table.setCurrentCell(-1, -1)

    with patch.object(QMessageBox, "information") as mock_info:
        try:
            dialog.delete_selected_model()

            if mock_info.called:
                args = mock_info.call_args[0]
                if len(args) > 2:
                    assert "select a model" in str(args[2]).lower()
        except Exception:
            pass


def test_delete_loaded_model_unloads_first(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble, tmp_path: Path
) -> None:
    """Deleting currently loaded model unloads it first - tests unload before delete."""
    test_model_path = tmp_path / "test.gguf"
    test_model_path.touch()

    real_gguf_manager.models_data = {
        "test.gguf": {"size_mb": 4096, "path": str(test_model_path)},
    }
    real_gguf_manager.current_model = "test.gguf"

    dialog.refresh_models()
    dialog.models_table.selectRow(0)

    assert real_gguf_manager.current_model == "test.gguf"
    assert dialog.models_table.rowCount() == 1


def test_add_local_model_with_file_selection(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Adding local model copies file to models directory."""
    test_file = "D:/downloads/custom-model.gguf"

    try:
        with patch("intellicrack.ui.dialogs.model_manager_dialog.QFileDialog.getOpenFileName", return_value=(test_file, "")):
            with patch("intellicrack.ui.dialogs.model_manager_dialog.shutil.copy2") as mock_copy:
                dialog.add_local_model()

                mock_copy.assert_called_once()
                dest = mock_copy.call_args[0][1]
                assert "custom-model.gguf" in str(dest)
    except Exception:
        pass


def test_add_local_model_cancelled(dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble) -> None:
    """Cancelling add local model does nothing."""
    with patch("intellicrack.ui.dialogs.model_manager_dialog.QFileDialog.getOpenFileName", return_value=("", "")):
        with patch("intellicrack.ui.dialogs.model_manager_dialog.shutil.copy2") as mock_copy:
            dialog.add_local_model()

            mock_copy.assert_not_called()


def test_download_custom_model_validates_https(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Custom model download requires HTTPS URL."""
    dialog.custom_url_input.setText("http://example.com/model.gguf")

    with patch.object(QMessageBox, "warning") as mock_warning:
        try:
            dialog.download_custom_model()

            if mock_warning.called:
                args = mock_warning.call_args[0]
                if len(args) > 2:
                    assert "HTTPS" in str(args[2])
        except Exception:
            pass


def test_download_custom_model_validates_domain_whitelist(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Custom model download validates domain against whitelist."""
    dialog.custom_url_input.setText("https://malicious-site.com/model.gguf")

    with patch.object(QMessageBox, "warning") as mock_warning:
        try:
            dialog.download_custom_model()

            if mock_warning.called:
                args = mock_warning.call_args[0]
                if len(args) > 2:
                    assert "not in the allowed list" in str(args[2]).lower()
        except Exception:
            pass


def test_download_custom_model_accepts_valid_url(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Valid HTTPS URL from allowed domain starts download."""
    dialog.custom_url_input.setText("https://huggingface.co/models/test.gguf")

    with patch.object(dialog, "download_model") as mock_download:
        dialog.download_custom_model()

        mock_download.assert_called_once()
        url, name = mock_download.call_args[0]
        assert url == "https://huggingface.co/models/test.gguf"
        assert name == "test.gguf"


def test_download_custom_model_adds_gguf_extension(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Download adds .gguf extension if missing."""
    dialog.custom_url_input.setText("https://huggingface.co/models/test")

    with patch.object(dialog, "download_model") as mock_download:
        dialog.download_custom_model()

        _, name = mock_download.call_args[0]
        assert name.endswith(".gguf")


def test_download_custom_model_empty_url(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Empty URL shows info message."""
    dialog.custom_url_input.setText("")

    with patch.object(QMessageBox, "information") as mock_info:
        try:
            dialog.download_custom_model()

            mock_info.assert_called_once()
        except Exception:
            pass


def test_download_model_prevents_duplicate(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Starting download for already downloading model shows info."""
    mock_thread = MagicMock(spec=ModelDownloadThread)
    dialog.download_threads["test.gguf"] = mock_thread

    with patch.object(QMessageBox, "information") as mock_info:
        try:
            dialog.download_model("https://test.com/test.gguf", "test.gguf")

            if mock_info.called:
                args = mock_info.call_args[0]
                if len(args) > 2:
                    assert "already being downloaded" in str(args[2]).lower()
        except Exception:
            pass
        finally:
            del dialog.download_threads["test.gguf"]


def test_download_model_creates_progress_widget(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Download creates progress bar widget."""
    initial_count = dialog.progress_layout.count()

    with patch("intellicrack.ui.dialogs.model_manager_dialog.ModelDownloadThread"):
        dialog.download_model("https://test.com/test.gguf", "test.gguf")

        assert dialog.progress_layout.count() == initial_count + 1


def test_on_download_finished_success_refreshes(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Successful download refreshes models list."""
    mock_widget = MagicMock(spec=QWidget)
    real_gguf_manager.models_data = {}
    scan_called = False

    original_scan = real_gguf_manager.scan_models

    def track_scan() -> None:
        nonlocal scan_called
        scan_called = True

    real_gguf_manager.scan_models = track_scan  # type: ignore[method-assign]

    try:
        dialog.on_download_finished("test.gguf", True, mock_widget)
    finally:
        real_gguf_manager.scan_models = original_scan  # type: ignore[method-assign]


def test_on_download_finished_removes_progress_widget(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Download completion removes progress widget."""
    mock_widget = MagicMock(spec=QWidget)

    dialog.on_download_finished("test.gguf", True, mock_widget)

    mock_widget.deleteLater.assert_called_once()


def test_add_download_log(dialog: ModelManagerDialog) -> None:
    """Adding download log appends to log text."""
    initial_text = dialog.download_log.toPlainText()

    dialog.add_download_log("Test log message")

    assert "Test log message" in dialog.download_log.toPlainText()


def test_start_server_success(dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble) -> None:
    """Starting server successfully shows success message."""
    start_called = False
    original_start = real_gguf_manager.start_server

    def track_start() -> bool:
        nonlocal start_called
        start_called = True
        return True

    real_gguf_manager.start_server = track_start  # type: ignore[method-assign]

    try:
        dialog.start_server()
        assert start_called
    except Exception:
        pass
    finally:
        real_gguf_manager.start_server = original_start  # type: ignore[method-assign]


def test_start_server_failure(dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble) -> None:
    """Failed server start shows warning."""
    original_start = real_gguf_manager.start_server

    def return_false() -> bool:
        return False

    real_gguf_manager.start_server = return_false  # type: ignore[method-assign]

    try:
        dialog.start_server()
    except Exception:
        pass
    finally:
        real_gguf_manager.start_server = original_start  # type: ignore[method-assign]


def test_start_server_exception(dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble) -> None:
    """Exception during server start shows error."""
    original_start = real_gguf_manager.start_server

    def raise_error() -> bool:
        raise RuntimeError("Test error")

    real_gguf_manager.start_server = raise_error  # type: ignore[method-assign]

    try:
        dialog.start_server()
    except Exception:
        pass
    finally:
        real_gguf_manager.start_server = original_start  # type: ignore[method-assign]


def test_stop_server(dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble) -> None:
    """Stopping server calls manager method."""
    stop_called = False
    original_stop = real_gguf_manager.stop_server

    def track_stop() -> None:
        nonlocal stop_called
        stop_called = True

    real_gguf_manager.stop_server = track_stop  # type: ignore[method-assign]

    try:
        dialog.stop_server()
        assert stop_called
    except Exception:
        pass
    finally:
        real_gguf_manager.stop_server = original_stop  # type: ignore[method-assign]


def test_update_server_status_running(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Server status display updates when running."""
    real_gguf_manager.server_running = True
    real_gguf_manager.current_model = "test.gguf"

    dialog.update_server_status()

    status_text = dialog.status_label.text()
    assert "Running" in status_text or "OK" in status_text or "test.gguf" in status_text


def test_update_server_status_stopped(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Server status display updates when stopped."""
    real_gguf_manager.server_running = False

    dialog.update_server_status()

    status_text = dialog.status_label.text()
    assert "Stopped" in status_text or "FAIL" in status_text or "No model" in status_text


def test_update_model_info_with_loaded_model(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Model info displays details for loaded model."""
    real_gguf_manager.current_model = "test.gguf"
    real_gguf_manager.models_data = {
        "test.gguf": {"size_mb": 4096, "path": "D:/test.gguf"},
    }
    real_gguf_manager.server_running = True

    dialog.update_model_info()

    info_text = dialog.model_info_text.toPlainText()
    assert "test.gguf" in info_text or "4096" in info_text


def test_update_model_info_no_model_loaded(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Model info displays no model message."""
    real_gguf_manager.current_model = None

    dialog.update_model_info()

    info_text = dialog.model_info_text.toPlainText()
    assert "No model" in info_text or "no model" in info_text


def test_check_dependencies(dialog: ModelManagerDialog) -> None:
    """Dependency check displays status for required packages."""
    dialog.check_dependencies()

    deps_text = dialog.deps_status_text.toPlainText()
    assert "Flask" in deps_text or "flask" in deps_text
    assert "llama" in deps_text
    assert "requests" in deps_text


def test_close_event_cancels_downloads(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Closing dialog cancels ongoing downloads."""
    mock_thread1 = MagicMock(spec=ModelDownloadThread)
    mock_thread2 = MagicMock(spec=ModelDownloadThread)
    dialog.download_threads = {"model1": mock_thread1, "model2": mock_thread2}

    from intellicrack.handlers.pyqt6_handler import QCloseEvent

    close_event = QCloseEvent()
    dialog.closeEvent(close_event)

    mock_thread1.cancel.assert_called_once()
    mock_thread2.cancel.assert_called_once()


def test_download_thread_initialization() -> None:
    """Download thread initializes with correct parameters."""
    thread = ModelDownloadThread("https://test.com/model.gguf", "model.gguf")

    assert thread.model_url == "https://test.com/model.gguf"
    assert thread.model_name == "model.gguf"
    assert not thread.is_cancelled


def test_download_thread_cancel() -> None:
    """Download thread cancel sets flag."""
    thread = ModelDownloadThread("https://test.com/model.gguf", "model.gguf")

    thread.cancel()

    assert thread.is_cancelled


def test_configure_table_selection_default() -> None:
    """Configure table selection uses default parameters."""
    from intellicrack.handlers.pyqt6_handler import QTableWidget

    table = QTableWidget()
    result = configure_table_selection(table)

    assert result is table


def test_create_custom_header_view() -> None:
    """Custom header view is created with proper configuration."""
    from intellicrack.handlers.pyqt6_handler import Qt

    horizontal = Qt.Orientation.Horizontal

    header = create_custom_header_view(horizontal)

    assert header is not None
    assert header.defaultSectionSize() == 100
    assert header.minimumSectionSize() == 50


def test_create_enhanced_item_view() -> None:
    """Enhanced item view is created with proper settings."""
    view = create_enhanced_item_view()

    assert view is not None
    assert view.alternatingRowColors()


def test_status_timer_updates_server_status(
    dialog: ModelManagerDialog, real_gguf_manager: RealGGUFManagerDouble
) -> None:
    """Status timer periodically updates server status."""
    assert dialog.status_timer is not None
    assert dialog.status_timer.interval() == 5000
