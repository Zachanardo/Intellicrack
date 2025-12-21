"""Production tests for Node.js Setup Dialog.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from intellicrack.handlers.pyqt6_handler import QApplication, QMessageBox
from intellicrack.ui.dialogs.nodejs_setup_dialog import (
    NodeJSInstallWorker,
    NodeJSSetupDialog,
)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def dialog(qapp: QApplication) -> NodeJSSetupDialog:
    """Create Node.js setup dialog for testing."""
    dlg = NodeJSSetupDialog()
    yield dlg
    dlg.deleteLater()


def test_dialog_initialization(dialog: NodeJSSetupDialog) -> None:
    """Dialog initializes with correct title and components."""
    assert dialog.windowTitle() == "Node.js Setup Required"
    assert dialog.width() == 600
    assert dialog.height() == 500

    assert hasattr(dialog, "auto_install_radio")
    assert hasattr(dialog, "custom_path_radio")
    assert hasattr(dialog, "path_input")
    assert hasattr(dialog, "browse_btn")
    assert hasattr(dialog, "progress_bar")
    assert hasattr(dialog, "progress_text")


def test_auto_install_selected_by_default(dialog: NodeJSSetupDialog) -> None:
    """Auto-install radio button is selected by default."""
    assert dialog.auto_install_radio.isChecked()
    assert not dialog.custom_path_radio.isChecked()


def test_custom_path_controls_disabled_initially(dialog: NodeJSSetupDialog) -> None:
    """Custom path input and browse button are disabled when auto-install selected."""
    assert not dialog.path_input.isEnabled()
    assert not dialog.browse_btn.isEnabled()


def test_switching_to_custom_path_enables_controls(dialog: NodeJSSetupDialog) -> None:
    """Switching to custom path enables input and browse button."""
    dialog.custom_path_radio.setChecked(True)

    assert dialog.path_input.isEnabled()
    assert dialog.browse_btn.isEnabled()


def test_switching_to_auto_install_disables_controls(dialog: NodeJSSetupDialog) -> None:
    """Switching back to auto-install disables custom controls."""
    dialog.custom_path_radio.setChecked(True)
    assert dialog.path_input.isEnabled()

    dialog.auto_install_radio.setChecked(True)

    assert not dialog.path_input.isEnabled()
    assert not dialog.browse_btn.isEnabled()


def test_path_input_has_default_nodejs_path(dialog: NodeJSSetupDialog) -> None:
    """Path input has default Node.js installation path."""
    path = dialog.path_input.text()
    assert len(path) > 0
    assert "nodejs" in path.lower()


def test_browse_button_opens_directory_dialog(dialog: NodeJSSetupDialog) -> None:
    """Browse button opens directory selection dialog."""
    test_path = "C:\\Test\\nodejs"

    with patch(
        "intellicrack.ui.dialogs.nodejs_setup_dialog.QFileDialog.getExistingDirectory",
        return_value=test_path,
    ):
        dialog.custom_path_radio.setChecked(True)
        dialog.browse_nodejs_path()

        assert dialog.path_input.text() == test_path


def test_browse_button_cancelled_does_not_change_path(dialog: NodeJSSetupDialog) -> None:
    """Cancelling browse dialog does not change path."""
    original_path = dialog.path_input.text()

    with patch(
        "intellicrack.ui.dialogs.nodejs_setup_dialog.QFileDialog.getExistingDirectory",
        return_value="",
    ):
        dialog.custom_path_radio.setChecked(True)
        dialog.browse_nodejs_path()

        assert dialog.path_input.text() == original_path


def test_validate_input_auto_install_starts_installation(dialog: NodeJSSetupDialog) -> None:
    """Validate with auto-install starts installation process."""
    dialog.auto_install_radio.setChecked(True)

    with patch.object(dialog, "start_installation") as mock_start:
        result = dialog.validate_input()

        mock_start.assert_called_once()
        assert result is False


def test_validate_input_custom_path_empty_shows_error(dialog: NodeJSSetupDialog) -> None:
    """Validate with empty custom path shows error."""
    dialog.custom_path_radio.setChecked(True)
    dialog.path_input.setText("")

    with patch.object(dialog, "show_error") as mock_error:
        result = dialog.validate_input()

        mock_error.assert_called_once()
        assert result is False


def test_validate_input_custom_path_valid_succeeds(dialog: NodeJSSetupDialog) -> None:
    """Validate with valid Node.js path succeeds."""
    dialog.custom_path_radio.setChecked(True)
    test_path = "C:\\Program Files\\nodejs"
    dialog.path_input.setText(test_path)

    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "v20.15.1"

    with patch("subprocess.run", return_value=mock_result):
        with patch.object(QMessageBox, "information"):
            result = dialog.validate_input()

            assert result is True


def test_validate_input_custom_path_invalid_shows_error(dialog: NodeJSSetupDialog) -> None:
    """Validate with invalid Node.js path shows error."""
    dialog.custom_path_radio.setChecked(True)
    dialog.path_input.setText("C:\\Invalid\\Path")

    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = ""

    with patch("subprocess.run", return_value=mock_result):
        with patch.object(dialog, "show_error") as mock_error:
            result = dialog.validate_input()

            mock_error.assert_called_once()
            assert result is False


def test_validate_input_custom_path_timeout_shows_error(dialog: NodeJSSetupDialog) -> None:
    """Validate with timeout exception shows error."""
    dialog.custom_path_radio.setChecked(True)
    dialog.path_input.setText("C:\\Test\\nodejs")

    import subprocess

    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("node", 5)):
        with patch.object(dialog, "show_error") as mock_error:
            result = dialog.validate_input()

            mock_error.assert_called_once()
            assert result is False


def test_validate_input_sanitizes_node_exe_path(dialog: NodeJSSetupDialog) -> None:
    """Validate sanitizes node.exe path to prevent command injection."""
    dialog.custom_path_radio.setChecked(True)
    dialog.path_input.setText("C:\\nodejs")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v20.15.1"

        dialog.validate_input()

        call_args = mock_run.call_args
        assert call_args.kwargs.get("shell") is False


def test_start_installation_shows_progress_ui(dialog: NodeJSSetupDialog) -> None:
    """Start installation shows progress bar and text."""
    with patch.object(NodeJSInstallWorker, "start"):
        dialog.start_installation()

        assert dialog.progress_bar.isVisible()
        assert dialog.progress_text.isVisible()
        assert dialog.progress_bar.value() == 0


def test_start_installation_disables_controls(dialog: NodeJSSetupDialog) -> None:
    """Start installation disables all input controls."""
    with patch.object(NodeJSInstallWorker, "start"):
        dialog.start_installation()

        assert not dialog.auto_install_radio.isEnabled()
        assert not dialog.custom_path_radio.isEnabled()


def test_start_installation_creates_worker_thread(dialog: NodeJSSetupDialog) -> None:
    """Start installation creates and starts worker thread."""
    with patch.object(NodeJSInstallWorker, "start") as mock_start:
        dialog.start_installation()

        assert dialog.install_worker is not None
        mock_start.assert_called_once()


def test_on_install_progress_updates_text(dialog: NodeJSSetupDialog) -> None:
    """Install progress updates progress text."""
    initial_text = dialog.progress_text.toPlainText()

    dialog.on_install_progress("Test progress message")

    assert "Test progress message" in dialog.progress_text.toPlainText()


def test_on_install_finished_success_closes_dialog(dialog: NodeJSSetupDialog) -> None:
    """Successful installation shows success and closes dialog."""
    with patch.object(dialog, "show_success"):
        with patch.object(dialog, "accept") as mock_accept:
            dialog.on_install_finished(True, "Installation complete")

            mock_accept.assert_called_once()


def test_on_install_finished_failure_shows_error(dialog: NodeJSSetupDialog) -> None:
    """Failed installation shows error and keeps dialog open."""
    with patch.object(dialog, "show_error") as mock_error:
        with patch.object(dialog, "accept") as mock_accept:
            dialog.on_install_finished(False, "Installation failed")

            mock_error.assert_called_once()
            mock_accept.assert_not_called()


def test_on_install_finished_reenables_controls(dialog: NodeJSSetupDialog) -> None:
    """Install completion re-enables controls."""
    with patch.object(NodeJSInstallWorker, "start"):
        dialog.start_installation()

    with patch.object(dialog, "show_error"):
        dialog.on_install_finished(False, "Test failure")

        assert dialog.auto_install_radio.isEnabled()
        assert dialog.custom_path_radio.isEnabled()


def test_on_install_finished_hides_progress_bar(dialog: NodeJSSetupDialog) -> None:
    """Install completion hides progress bar."""
    dialog.progress_bar.setVisible(True)

    with patch.object(dialog, "show_success"):
        with patch.object(dialog, "accept"):
            dialog.on_install_finished(True, "Complete")

            assert not dialog.progress_bar.isVisible()


def test_install_worker_initialization() -> None:
    """Install worker initializes correctly."""
    worker = NodeJSInstallWorker()

    assert worker is not None


def test_install_worker_emits_progress_signals() -> None:
    """Install worker emits progress signals during run."""
    worker = NodeJSInstallWorker()

    progress_messages = []
    progress_values = []

    def on_progress(msg: str) -> None:
        progress_messages.append(msg)

    def on_progress_value(val: int) -> None:
        progress_values.append(val)

    worker.progress.connect(on_progress)
    worker.progress_value.connect(on_progress_value)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.raw = MagicMock()
            mock_get.return_value = mock_response

            worker.run()

            assert progress_messages
            assert progress_values
            assert 100 in progress_values


def test_install_worker_validates_url_scheme() -> None:
    """Install worker validates URL scheme to prevent file:// attacks."""
    worker = NodeJSInstallWorker()

    finished_calls = []

    def on_finished(success: bool, message: str) -> None:
        finished_calls.append((success, message))

    worker.finished.connect(on_finished)

    with patch("intellicrack.ui.dialogs.nodejs_setup_dialog.urlparse") as mock_urlparse:
        mock_parsed = MagicMock()
        mock_parsed.scheme = "file"
        mock_urlparse.return_value = mock_parsed

        worker.run()

        assert len(finished_calls) == 1
        assert not finished_calls[0][0]


def test_install_worker_sanitizes_temp_installer_path() -> None:
    """Install worker sanitizes temp installer path to prevent injection."""
    worker = NodeJSInstallWorker()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.raw = MagicMock()
            mock_get.return_value = mock_response

            with patch("builtins.open", MagicMock()):
                worker.run()

                call_args = mock_run.call_args
                assert call_args.kwargs.get("shell") is False

                command = call_args[0][0]
                assert isinstance(command, list)
                assert command[0] == "msiexec"


def test_install_worker_uses_https_url() -> None:
    """Install worker uses HTTPS URL for Node.js download."""
    worker = NodeJSInstallWorker()

    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.raw = MagicMock()
        mock_get.return_value = mock_response

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0

            with patch("builtins.open", MagicMock()):
                worker.run()

                call_args = mock_get.call_args
                url = call_args[0][0]
                assert url.startswith("https://")
                assert "nodejs.org" in url


def test_install_worker_handles_download_exception() -> None:
    """Install worker handles download exceptions gracefully."""
    worker = NodeJSInstallWorker()

    finished_calls = []

    def on_finished(success: bool, message: str) -> None:
        finished_calls.append((success, message))

    worker.finished.connect(on_finished)

    with patch("requests.get", side_effect=Exception("Network error")):
        worker.run()

        assert len(finished_calls) == 1
        assert not finished_calls[0][0]


def test_install_worker_handles_subprocess_exception() -> None:
    """Install worker handles subprocess exceptions gracefully."""
    worker = NodeJSInstallWorker()

    finished_calls = []

    def on_finished(success: bool, message: str) -> None:
        finished_calls.append((success, message))

    worker.finished.connect(on_finished)

    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.raw = MagicMock()
        mock_get.return_value = mock_response

        with patch("subprocess.run", side_effect=Exception("Subprocess error")):
            with patch("builtins.open", MagicMock()):
                worker.run()

                assert len(finished_calls) == 1
                assert not finished_calls[0][0]


def test_install_worker_emits_progress_values_incrementally() -> None:
    """Install worker emits progress values in incremental steps."""
    worker = NodeJSInstallWorker()

    progress_values = []

    def on_progress_value(val: int) -> None:
        progress_values.append(val)

    worker.progress_value.connect(on_progress_value)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.raw = MagicMock()
            mock_get.return_value = mock_response

            with patch("builtins.open", MagicMock()):
                worker.run()

                assert len(progress_values) > 3
                assert progress_values[0] < progress_values[-1]


def test_install_worker_success_emits_100_percent(dialog: NodeJSSetupDialog) -> None:
    """Successful installation emits 100% progress."""
    worker = NodeJSInstallWorker()

    progress_values = []

    def on_progress_value(val: int) -> None:
        progress_values.append(val)

    worker.progress_value.connect(on_progress_value)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.raw = MagicMock()
            mock_get.return_value = mock_response

            with patch("builtins.open", MagicMock()):
                worker.run()

                assert 100 in progress_values


def test_install_worker_failure_resets_progress(dialog: NodeJSSetupDialog) -> None:
    """Failed installation resets progress to 0."""
    worker = NodeJSInstallWorker()

    progress_values = []

    def on_progress_value(val: int) -> None:
        progress_values.append(val)

    worker.progress_value.connect(on_progress_value)

    with patch("requests.get", side_effect=Exception("Test error")):
        worker.run()

        assert 0 in progress_values


def test_path_detection_checks_common_locations(dialog: NodeJSSetupDialog) -> None:
    """Path detection checks common Node.js installation locations."""
    path_text = dialog.path_input.text()

    assert "Program Files" in path_text or "nodejs" in path_text.lower()


def test_progress_bar_range_set_correctly(dialog: NodeJSSetupDialog) -> None:
    """Progress bar is configured with 0-100 range."""
    with patch.object(NodeJSInstallWorker, "start"):
        dialog.start_installation()

        assert dialog.progress_bar.minimum() == 0
        assert dialog.progress_bar.maximum() == 100


def test_progress_text_cleared_on_installation_start(dialog: NodeJSSetupDialog) -> None:
    """Progress text is cleared when installation starts."""
    dialog.progress_text.setText("Previous text")

    with patch.object(NodeJSInstallWorker, "start"):
        dialog.start_installation()

        assert dialog.progress_text.toPlainText() == ""


def test_worker_progress_signal_connected_to_progress_bar(dialog: NodeJSSetupDialog) -> None:
    """Worker progress_value signal is connected to progress bar."""
    with patch.object(NodeJSInstallWorker, "start"):
        dialog.start_installation()

        assert dialog.install_worker is not None

        signal_obj = dialog.install_worker.progress_value
        receivers_count = signal_obj.receivers(signal_obj)
        assert receivers_count > 0
