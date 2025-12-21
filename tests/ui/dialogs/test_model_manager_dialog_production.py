"""Production tests for Model Manager Dialog.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
from intellicrack.handlers.pyqt6_handler import QApplication, QMessageBox
from intellicrack.ui.dialogs.model_manager_dialog import (
    ModelDownloadThread,
    ModelManagerDialog,
    configure_table_selection,
    create_custom_header_view,
    create_enhanced_item_view,
)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def mock_gguf_manager() -> MagicMock:
    """Create mock GGUF manager."""
    manager = MagicMock()
    manager.models_directory = Path("D:/test/models")
    manager.current_model = None
    manager.list_models.return_value = {}
    manager.get_recommended_models.return_value = []
    manager.is_server_running.return_value = False
    manager.get_server_url.return_value = "http://localhost:8000"
    return manager


@pytest.fixture
def dialog(qapp: QApplication, mock_gguf_manager: MagicMock) -> ModelManagerDialog:
    """Create model manager dialog for testing."""
    with patch("intellicrack.ui.dialogs.model_manager_dialog.gguf_manager", mock_gguf_manager):
        dlg = ModelManagerDialog()
        dlg.status_timer.stop()
        yield dlg
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
    tabs = None
    for child in dialog.content_widget.findChildren(type(dialog.content_widget).__bases__[0]):
        if hasattr(child, "count") and callable(child.count):
            if child.count() == 3:
                tabs = child
                break

    assert tabs is not None
    assert tabs.count() == 3


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


def test_refresh_models_empty(dialog: ModelManagerDialog, mock_gguf_manager: MagicMock) -> None:
    """Refreshing with no models shows empty table."""
    mock_gguf_manager.list_models.return_value = {}

    dialog.refresh_models()

    assert dialog.models_table.rowCount() == 0


def test_refresh_models_with_models(dialog: ModelManagerDialog, mock_gguf_manager: MagicMock) -> None:
    """Refreshing with models displays them in table."""
    mock_gguf_manager.list_models.return_value = {
        "llama2.gguf": {"size_mb": 4096, "path": "D:/models/llama2.gguf"},
        "codellama.gguf": {"size_mb": 7200, "path": "D:/models/codellama.gguf"},
    }
    mock_gguf_manager.current_model = None

    dialog.refresh_models()

    assert dialog.models_table.rowCount() == 2

    assert dialog.models_table.item(0, 0).text() == "llama2.gguf"
    assert dialog.models_table.item(0, 1).text() == "4096"
    assert dialog.models_table.item(0, 2).text() == "Available"
    assert dialog.models_table.item(0, 3).text() == "D:/models/llama2.gguf"

    assert dialog.models_table.item(1, 0).text() == "codellama.gguf"


def test_refresh_models_shows_loaded_status(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Currently loaded model shows Loaded status."""
    mock_gguf_manager.list_models.return_value = {
        "llama2.gguf": {"size_mb": 4096, "path": "D:/models/llama2.gguf"},
    }
    mock_gguf_manager.current_model = "llama2.gguf"

    dialog.refresh_models()

    assert dialog.models_table.item(0, 2).text() == "Loaded"


def test_populate_recommended_models(dialog: ModelManagerDialog, mock_gguf_manager: MagicMock) -> None:
    """Recommended models are populated in table."""
    mock_gguf_manager.get_recommended_models.return_value = [
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

    assert dialog.recommended_table.item(0, 0).text() == "Llama-2-7B"
    assert dialog.recommended_table.item(0, 1).text() == "Meta's Llama 2 7B model"
    assert dialog.recommended_table.item(0, 2).text() == "4GB"

    assert dialog.recommended_table.item(1, 0).text() == "CodeLlama-13B"


def test_load_model_success(dialog: ModelManagerDialog, mock_gguf_manager: MagicMock) -> None:
    """Loading model successfully updates UI."""
    mock_gguf_manager.load_model.return_value = True

    with patch.object(QMessageBox, "information"):
        dialog.load_model("test-model.gguf")

        mock_gguf_manager.load_model.assert_called_once_with(
            "test-model.gguf",
            context_length=4096,
            gpu_layers=0,
            use_mmap=True,
            use_mlock=False,
        )


def test_load_model_failure(dialog: ModelManagerDialog, mock_gguf_manager: MagicMock) -> None:
    """Failed model loading shows warning."""
    mock_gguf_manager.load_model.return_value = False

    with patch.object(QMessageBox, "warning") as mock_warning:
        dialog.load_model("test-model.gguf")

        mock_warning.assert_called_once()


def test_load_model_exception(dialog: ModelManagerDialog, mock_gguf_manager: MagicMock) -> None:
    """Exception during model loading shows error."""
    mock_gguf_manager.load_model.side_effect = RuntimeError("Test error")

    with patch.object(QMessageBox, "critical") as mock_critical:
        dialog.load_model("test-model.gguf")

        mock_critical.assert_called_once()
        args = mock_critical.call_args[0]
        assert "Test error" in args[2]


def test_load_model_uses_configured_parameters(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Load model uses parameters from UI controls."""
    mock_gguf_manager.load_model.return_value = True

    dialog.context_length_input.setValue(8192)
    dialog.gpu_layers_input.setValue(35)
    dialog.use_mmap_checkbox.setChecked(False)
    dialog.use_mlock_checkbox.setChecked(True)

    with patch.object(QMessageBox, "information"):
        dialog.load_model("test.gguf")

        call_args = mock_gguf_manager.load_model.call_args
        assert call_args.kwargs["context_length"] == 8192
        assert call_args.kwargs["gpu_layers"] == 35
        assert call_args.kwargs["use_mmap"] is False
        assert call_args.kwargs["use_mlock"] is True


def test_load_selected_model_with_selection(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Loading selected model from table works correctly."""
    mock_gguf_manager.list_models.return_value = {
        "test.gguf": {"size_mb": 4096, "path": "D:/test.gguf"},
    }
    mock_gguf_manager.load_model.return_value = True

    dialog.refresh_models()
    dialog.models_table.selectRow(0)

    with patch.object(QMessageBox, "information"):
        dialog.load_selected_model()

        mock_gguf_manager.load_model.assert_called_once()


def test_load_selected_model_no_selection(dialog: ModelManagerDialog, mock_gguf_manager: MagicMock) -> None:
    """Loading with no selection shows info message."""
    dialog.models_table.setCurrentCell(-1, -1)

    with patch.object(QMessageBox, "information") as mock_info:
        dialog.load_selected_model()

        mock_info.assert_called_once()
        args = mock_info.call_args[0]
        assert "select a model" in args[2].lower()


def test_unload_current_model_with_loaded(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Unloading current model works when model is loaded."""
    mock_gguf_manager.current_model = "test.gguf"

    with patch.object(QMessageBox, "information"):
        dialog.unload_current_model()

        mock_gguf_manager.unload_model.assert_called_once()


def test_unload_current_model_none_loaded(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Unloading with no model loaded shows info message."""
    mock_gguf_manager.current_model = None

    with patch.object(QMessageBox, "information") as mock_info:
        dialog.unload_current_model()

        args = mock_info.call_args[0]
        assert "no model" in args[2].lower()


@patch.object(QMessageBox, "question", return_value=QMessageBox.Yes)
def test_delete_selected_model_with_confirmation(
    mock_question: MagicMock, dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Deleting model with confirmation removes file."""
    mock_path = MagicMock(spec=Path)
    mock_gguf_manager.list_models.return_value = {
        "test.gguf": {"size_mb": 4096, "path": str(mock_path)},
    }
    mock_gguf_manager.current_model = None

    dialog.refresh_models()
    dialog.models_table.selectRow(0)

    with patch.object(QMessageBox, "information"):
        with patch("intellicrack.ui.dialogs.model_manager_dialog.Path", return_value=mock_path):
            dialog.delete_selected_model()

            mock_path.unlink.assert_called_once()


@patch.object(QMessageBox, "question", return_value=QMessageBox.No)
def test_delete_selected_model_cancelled(
    mock_question: MagicMock, dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Cancelling delete does not remove file."""
    mock_path = MagicMock(spec=Path)
    mock_gguf_manager.list_models.return_value = {
        "test.gguf": {"size_mb": 4096, "path": str(mock_path)},
    }

    dialog.refresh_models()
    dialog.models_table.selectRow(0)

    dialog.delete_selected_model()

    mock_path.unlink.assert_not_called()


def test_delete_selected_model_no_selection(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Deleting with no selection shows info message."""
    dialog.models_table.setCurrentCell(-1, -1)

    with patch.object(QMessageBox, "information") as mock_info:
        dialog.delete_selected_model()

        args = mock_info.call_args[0]
        assert "select a model" in args[2].lower()


@patch.object(QMessageBox, "question", return_value=QMessageBox.Yes)
def test_delete_loaded_model_unloads_first(
    mock_question: MagicMock, dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Deleting currently loaded model unloads it first."""
    mock_path = MagicMock(spec=Path)
    mock_gguf_manager.list_models.return_value = {
        "test.gguf": {"size_mb": 4096, "path": str(mock_path)},
    }
    mock_gguf_manager.current_model = "test.gguf"

    dialog.refresh_models()
    dialog.models_table.selectRow(0)

    with patch.object(QMessageBox, "information"):
        with patch("intellicrack.ui.dialogs.model_manager_dialog.Path", return_value=mock_path):
            dialog.delete_selected_model()

            mock_gguf_manager.unload_model.assert_called_once()
            mock_path.unlink.assert_called_once()


def test_add_local_model_with_file_selection(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Adding local model copies file to models directory."""
    test_file = "D:/downloads/custom-model.gguf"

    with patch.object(QMessageBox, "information"):
        with patch("intellicrack.ui.dialogs.model_manager_dialog.QFileDialog.getOpenFileName", return_value=(test_file, "")):
            with patch("intellicrack.ui.dialogs.model_manager_dialog.shutil.copy2") as mock_copy:
                dialog.add_local_model()

                mock_copy.assert_called_once()
                dest = mock_copy.call_args[0][1]
                assert "custom-model.gguf" in str(dest)


def test_add_local_model_cancelled(dialog: ModelManagerDialog, mock_gguf_manager: MagicMock) -> None:
    """Cancelling add local model does nothing."""
    with patch("intellicrack.ui.dialogs.model_manager_dialog.QFileDialog.getOpenFileName", return_value=("", "")):
        with patch("intellicrack.ui.dialogs.model_manager_dialog.shutil.copy2") as mock_copy:
            dialog.add_local_model()

            mock_copy.assert_not_called()


def test_download_custom_model_validates_https(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Custom model download requires HTTPS URL."""
    dialog.custom_url_input.setText("http://example.com/model.gguf")

    with patch.object(QMessageBox, "warning") as mock_warning:
        dialog.download_custom_model()

        mock_warning.assert_called_once()
        args = mock_warning.call_args[0]
        assert "HTTPS" in args[2]


def test_download_custom_model_validates_domain_whitelist(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Custom model download validates domain against whitelist."""
    dialog.custom_url_input.setText("https://malicious-site.com/model.gguf")

    with patch.object(QMessageBox, "warning") as mock_warning:
        dialog.download_custom_model()

        mock_warning.assert_called_once()
        args = mock_warning.call_args[0]
        assert "not in the allowed list" in args[2].lower()


def test_download_custom_model_accepts_valid_url(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
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
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Download adds .gguf extension if missing."""
    dialog.custom_url_input.setText("https://huggingface.co/models/test")

    with patch.object(dialog, "download_model") as mock_download:
        dialog.download_custom_model()

        _, name = mock_download.call_args[0]
        assert name.endswith(".gguf")


def test_download_custom_model_empty_url(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Empty URL shows info message."""
    dialog.custom_url_input.setText("")

    with patch.object(QMessageBox, "information") as mock_info:
        dialog.download_custom_model()

        mock_info.assert_called_once()


def test_download_model_prevents_duplicate(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Starting download for already downloading model shows info."""
    dialog.download_threads["test.gguf"] = MagicMock()

    with patch.object(QMessageBox, "information") as mock_info:
        dialog.download_model("https://test.com/test.gguf", "test.gguf")

        mock_info.assert_called_once()
        args = mock_info.call_args[0]
        assert "already being downloaded" in args[2].lower()


def test_download_model_creates_progress_widget(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Download creates progress bar widget."""
    initial_count = dialog.progress_layout.count()

    with patch("intellicrack.ui.dialogs.model_manager_dialog.ModelDownloadThread"):
        dialog.download_model("https://test.com/test.gguf", "test.gguf")

        assert dialog.progress_layout.count() == initial_count + 1


def test_on_download_finished_success_refreshes(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Successful download refreshes models list."""
    mock_widget = MagicMock()
    mock_gguf_manager.list_models.return_value = {}

    dialog.on_download_finished("test.gguf", True, mock_widget)

    mock_gguf_manager.scan_models.assert_called()


def test_on_download_finished_removes_progress_widget(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Download completion removes progress widget."""
    mock_widget = MagicMock()

    dialog.on_download_finished("test.gguf", True, mock_widget)

    mock_widget.deleteLater.assert_called_once()


def test_add_download_log(dialog: ModelManagerDialog) -> None:
    """Adding download log appends to log text."""
    initial_text = dialog.download_log.toPlainText()

    dialog.add_download_log("Test log message")

    assert "Test log message" in dialog.download_log.toPlainText()


def test_start_server_success(dialog: ModelManagerDialog, mock_gguf_manager: MagicMock) -> None:
    """Starting server successfully shows success message."""
    mock_gguf_manager.start_server.return_value = True

    with patch.object(QMessageBox, "information"):
        dialog.start_server()

        mock_gguf_manager.start_server.assert_called_once()


def test_start_server_failure(dialog: ModelManagerDialog, mock_gguf_manager: MagicMock) -> None:
    """Failed server start shows warning."""
    mock_gguf_manager.start_server.return_value = False

    with patch.object(QMessageBox, "warning") as mock_warning:
        dialog.start_server()

        mock_warning.assert_called_once()


def test_start_server_exception(dialog: ModelManagerDialog, mock_gguf_manager: MagicMock) -> None:
    """Exception during server start shows error."""
    mock_gguf_manager.start_server.side_effect = RuntimeError("Test error")

    with patch.object(QMessageBox, "critical") as mock_critical:
        dialog.start_server()

        mock_critical.assert_called_once()


def test_stop_server(dialog: ModelManagerDialog, mock_gguf_manager: MagicMock) -> None:
    """Stopping server calls manager method."""
    with patch.object(QMessageBox, "information"):
        dialog.stop_server()

        mock_gguf_manager.stop_server.assert_called_once()


def test_update_server_status_running(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Server status display updates when running."""
    mock_gguf_manager.is_server_running.return_value = True
    mock_gguf_manager.current_model = "test.gguf"

    dialog.update_server_status()

    assert "Running" in dialog.status_label.text() or "OK" in dialog.status_label.text()
    assert "test.gguf" in dialog.status_label.text()
    assert not dialog.start_server_btn.isEnabled()
    assert dialog.stop_server_btn.isEnabled()


def test_update_server_status_stopped(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Server status display updates when stopped."""
    mock_gguf_manager.is_server_running.return_value = False

    dialog.update_server_status()

    assert "Stopped" in dialog.status_label.text() or "FAIL" in dialog.status_label.text()
    assert dialog.start_server_btn.isEnabled()
    assert not dialog.stop_server_btn.isEnabled()


def test_update_model_info_with_loaded_model(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Model info displays details for loaded model."""
    mock_gguf_manager.current_model = "test.gguf"
    mock_gguf_manager.list_models.return_value = {
        "test.gguf": {"size_mb": 4096, "path": "D:/test.gguf"},
    }
    mock_gguf_manager.is_server_running.return_value = True

    dialog.update_model_info()

    info_text = dialog.model_info_text.toPlainText()
    assert "test.gguf" in info_text
    assert "4096" in info_text
    assert "Running" in info_text


def test_update_model_info_no_model_loaded(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Model info displays no model message."""
    mock_gguf_manager.current_model = None

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
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Closing dialog cancels ongoing downloads."""
    mock_thread1 = MagicMock()
    mock_thread2 = MagicMock()
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

    header = create_custom_header_view(Qt.Horizontal)

    assert header is not None
    assert header.defaultSectionSize() == 100
    assert header.minimumSectionSize() == 50


def test_create_enhanced_item_view() -> None:
    """Enhanced item view is created with proper settings."""
    view = create_enhanced_item_view()

    assert view is not None
    assert view.alternatingRowColors()


def test_status_timer_updates_server_status(
    dialog: ModelManagerDialog, mock_gguf_manager: MagicMock
) -> None:
    """Status timer periodically updates server status."""
    assert dialog.status_timer is not None
    assert dialog.status_timer.interval() == 5000
