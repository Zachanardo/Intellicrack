"""Production tests for Node.js Setup Dialog.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import os
import subprocess
from collections.abc import Generator
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple
from urllib.parse import ParseResult

import pytest
from intellicrack.handlers.pyqt6_handler import QApplication, QMessageBox
from intellicrack.ui.dialogs.nodejs_setup_dialog import (
    NodeJSInstallWorker,
    NodeJSSetupDialog,
)


class FakeSubprocessResult:
    """Fake subprocess.CompletedProcess for testing."""

    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeHTTPResponse:
    """Fake HTTP response for testing."""

    def __init__(self, content: bytes = b"") -> None:
        self.raw = FakeRawResponse(content)
        self.content = content


class FakeRawResponse:
    """Fake raw HTTP response stream."""

    def __init__(self, content: bytes = b"") -> None:
        self._content = content
        self._position = 0

    def read(self, chunk_size: int = 8192) -> bytes:
        """Read chunk from response."""
        if self._position >= len(self._content):
            return b""
        chunk = self._content[self._position : self._position + chunk_size]
        self._position += chunk_size
        return chunk


class FakeFileDialog:
    """Fake QFileDialog for testing."""

    def __init__(self, return_path: str = "") -> None:
        self._return_path = return_path

    def getExistingDirectory(
        self,
        parent: Any = None,
        caption: str = "",
        directory: str = "",
        options: Any = None,
    ) -> str:
        """Return configured path."""
        return self._return_path


class FakeMessageBox:
    """Fake QMessageBox for testing."""

    def __init__(self) -> None:
        self.information_calls: List[Tuple[Any, str, str]] = []

    def information(self, parent: Any, title: str, message: str) -> None:
        """Record information dialog call."""
        self.information_calls.append((parent, title, message))


class FakeURLParseResult:
    """Fake URL parse result for testing."""

    def __init__(self, scheme: str) -> None:
        self.scheme = scheme
        self.netloc = "nodejs.org"
        self.path = "/download/node.msi"


class FakeFile:
    """Fake file object for testing."""

    def __init__(self) -> None:
        self.written_data: List[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> int:
        """Record written data."""
        self.written_data.append(data)
        return len(data)

    def close(self) -> None:
        """Mark file as closed."""
        self.closed = True

    def __enter__(self) -> "FakeFile":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class RecordingNodeJSSetupDialog(NodeJSSetupDialog):
    """Test double for NodeJSSetupDialog that records method calls."""

    def __init__(self) -> None:
        super().__init__()
        self.start_installation_calls: int = 0
        self.show_error_calls: List[str] = []
        self.show_success_calls: List[str] = []
        self.accept_calls: int = 0
        self._should_accept = False

    def start_installation(self) -> None:
        """Record start_installation call."""
        self.start_installation_calls += 1
        if hasattr(super(), "start_installation"):
            super().start_installation()

    def show_error(self, message: str) -> None:
        """Record show_error call."""
        self.show_error_calls.append(message)

    def show_success(self, message: str) -> None:
        """Record show_success call."""
        self.show_success_calls.append(message)

    def accept(self) -> None:
        """Record accept call."""
        self.accept_calls += 1
        self._should_accept = True


class SubprocessRunner:
    """Fake subprocess runner for testing."""

    def __init__(self) -> None:
        self.run_calls: List[Tuple[Any, ...]] = []
        self.return_result: Optional[FakeSubprocessResult] = FakeSubprocessResult(0, "v20.15.1")
        self.raise_exception: Optional[Exception] = None

    def run(self, *args: Any, **kwargs: Any) -> FakeSubprocessResult:
        """Record run call and return configured result."""
        self.run_calls.append((args, kwargs))
        if self.raise_exception:
            raise self.raise_exception
        if self.return_result is None:
            return FakeSubprocessResult(1, "")
        return self.return_result


class RequestsGetter:
    """Fake requests.get for testing."""

    def __init__(self) -> None:
        self.get_calls: List[Tuple[str, Any]] = []
        self.return_response: Optional[FakeHTTPResponse] = FakeHTTPResponse(b"installer_data")
        self.raise_exception: Optional[Exception] = None

    def get(self, url: str, **kwargs: Any) -> FakeHTTPResponse:
        """Record get call and return configured response."""
        self.get_calls.append((url, kwargs))
        if self.raise_exception:
            raise self.raise_exception
        if self.return_response is None:
            return FakeHTTPResponse(b"")
        return self.return_response


class URLParser:
    """Fake urlparse for testing."""

    def __init__(self, scheme: str = "https") -> None:
        self.parse_calls: List[str] = []
        self.return_scheme = scheme

    def __call__(self, url: str) -> FakeURLParseResult:
        """Record parse call and return configured result."""
        self.parse_calls.append(url)
        return FakeURLParseResult(self.return_scheme)


class FileOpener:
    """Fake file opener for testing."""

    def __init__(self) -> None:
        self.open_calls: List[Tuple[str, str]] = []
        self.fake_file = FakeFile()

    def __call__(self, path: str, mode: str = "r") -> FakeFile:
        """Record open call and return fake file."""
        self.open_calls.append((path, mode))
        return self.fake_file


@pytest.fixture(scope="module")
def qapp() -> Any:
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def dialog(qapp: Any) -> Generator[NodeJSSetupDialog, None, None]:
    """Create Node.js setup dialog for testing."""
    dlg = NodeJSSetupDialog()
    yield dlg
    dlg.deleteLater()


@pytest.fixture
def recording_dialog(qapp: Any) -> Generator[RecordingNodeJSSetupDialog, None, None]:
    """Create recording Node.js setup dialog for testing."""
    dlg = RecordingNodeJSSetupDialog()
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

    import intellicrack.ui.dialogs.nodejs_setup_dialog as dialog_module
    original_file_dialog = getattr(dialog_module, 'QFileDialog', None)
    fake_file_dialog = FakeFileDialog(test_path)

    try:
        setattr(dialog_module, 'QFileDialog', fake_file_dialog)
        dialog.custom_path_radio.setChecked(True)
        dialog.browse_nodejs_path()

        assert dialog.path_input.text() == test_path
    finally:
        if original_file_dialog is not None:
            setattr(dialog_module, 'QFileDialog', original_file_dialog)


def test_browse_button_cancelled_does_not_change_path(dialog: NodeJSSetupDialog) -> None:
    """Cancelling browse dialog does not change path."""
    original_path = dialog.path_input.text()

    import intellicrack.ui.dialogs.nodejs_setup_dialog as dialog_module
    orig_file_dialog = getattr(dialog_module, 'QFileDialog', None)
    fake_file_dialog = FakeFileDialog("")

    try:
        setattr(dialog_module, 'QFileDialog', fake_file_dialog)
        dialog.custom_path_radio.setChecked(True)
        dialog.browse_nodejs_path()

        assert dialog.path_input.text() == original_path
    finally:
        if orig_file_dialog is not None:
            setattr(dialog_module, 'QFileDialog', orig_file_dialog)


def test_validate_input_auto_install_starts_installation(recording_dialog: RecordingNodeJSSetupDialog) -> None:
    """Validate with auto-install starts installation process."""
    recording_dialog.auto_install_radio.setChecked(True)

    result = recording_dialog.validate_input()

    assert recording_dialog.start_installation_calls == 1
    assert result is False


def test_validate_input_custom_path_empty_shows_error(recording_dialog: RecordingNodeJSSetupDialog) -> None:
    """Validate with empty custom path shows error."""
    recording_dialog.custom_path_radio.setChecked(True)
    recording_dialog.path_input.setText("")

    result = recording_dialog.validate_input()

    assert len(recording_dialog.show_error_calls) == 1
    assert result is False


def test_validate_input_custom_path_valid_succeeds(dialog: NodeJSSetupDialog) -> None:
    """Validate with valid Node.js path succeeds."""
    dialog.custom_path_radio.setChecked(True)
    test_path = "C:\\Program Files\\nodejs"
    dialog.path_input.setText(test_path)

    import subprocess as subprocess_module
    original_run = subprocess_module.run
    subprocess_runner = SubprocessRunner()
    subprocess_runner.return_result = FakeSubprocessResult(0, "v20.15.1")

    import intellicrack.handlers.pyqt6_handler as pyqt_handler
    original_messagebox = pyqt_handler.QMessageBox
    fake_messagebox = FakeMessageBox()

    try:
        subprocess_module.run = subprocess_runner.run  # type: ignore[assignment]
        pyqt_handler.QMessageBox = fake_messagebox  # type: ignore[misc, assignment]

        result = dialog.validate_input()

        assert result is True
        assert len(fake_messagebox.information_calls) == 1
    finally:
        subprocess_module.run = original_run
        pyqt_handler.QMessageBox = original_messagebox  # type: ignore[misc]


def test_validate_input_custom_path_invalid_shows_error(recording_dialog: RecordingNodeJSSetupDialog) -> None:
    """Validate with invalid Node.js path shows error."""
    recording_dialog.custom_path_radio.setChecked(True)
    recording_dialog.path_input.setText("C:\\Invalid\\Path")

    import subprocess as subprocess_module
    original_run = subprocess_module.run
    subprocess_runner = SubprocessRunner()
    subprocess_runner.return_result = FakeSubprocessResult(1, "")

    try:
        subprocess_module.run = subprocess_runner.run  # type: ignore[assignment]

        result = recording_dialog.validate_input()

        assert len(recording_dialog.show_error_calls) == 1
        assert result is False
    finally:
        subprocess_module.run = original_run


def test_validate_input_custom_path_timeout_shows_error(recording_dialog: RecordingNodeJSSetupDialog) -> None:
    """Validate with timeout exception shows error."""
    recording_dialog.custom_path_radio.setChecked(True)
    recording_dialog.path_input.setText("C:\\Test\\nodejs")

    import subprocess as subprocess_module
    original_run = subprocess_module.run
    subprocess_runner = SubprocessRunner()
    subprocess_runner.raise_exception = subprocess.TimeoutExpired("node", 5)

    try:
        subprocess_module.run = subprocess_runner.run  # type: ignore[assignment]

        result = recording_dialog.validate_input()

        assert len(recording_dialog.show_error_calls) == 1
        assert result is False
    finally:
        subprocess_module.run = original_run


def test_validate_input_sanitizes_node_exe_path(dialog: NodeJSSetupDialog) -> None:
    """Validate sanitizes node.exe path to prevent command injection."""
    dialog.custom_path_radio.setChecked(True)
    dialog.path_input.setText("C:\\nodejs")

    import subprocess as subprocess_module
    original_run = subprocess_module.run
    subprocess_runner = SubprocessRunner()
    subprocess_runner.return_result = FakeSubprocessResult(0, "v20.15.1")

    try:
        subprocess_module.run = subprocess_runner.run  # type: ignore[assignment]

        dialog.validate_input()

        assert len(subprocess_runner.run_calls) == 1
        call_kwargs = subprocess_runner.run_calls[0][1]
        assert call_kwargs.get("shell") is False
    finally:
        subprocess_module.run = original_run


def test_start_installation_shows_progress_ui(dialog: NodeJSSetupDialog) -> None:
    """Start installation shows progress bar and text."""
    import intellicrack.ui.dialogs.nodejs_setup_dialog as dialog_module
    original_worker = dialog_module.NodeJSInstallWorker

    class FakeWorker:
        def __init__(self) -> None:
            pass
        def start(self) -> None:
            pass

    try:
        dialog_module.NodeJSInstallWorker = FakeWorker  # type: ignore[misc, assignment]
        dialog.start_installation()

        assert dialog.progress_bar.isVisible()
        assert dialog.progress_text.isVisible()
        assert dialog.progress_bar.value() == 0
    finally:
        dialog_module.NodeJSInstallWorker = original_worker  # type: ignore[misc]


def test_start_installation_disables_controls(dialog: NodeJSSetupDialog) -> None:
    """Start installation disables all input controls."""
    import intellicrack.ui.dialogs.nodejs_setup_dialog as dialog_module
    original_worker = dialog_module.NodeJSInstallWorker

    class FakeWorker:
        def __init__(self) -> None:
            pass
        def start(self) -> None:
            pass

    try:
        dialog_module.NodeJSInstallWorker = FakeWorker  # type: ignore[misc, assignment]
        dialog.start_installation()

        assert not dialog.auto_install_radio.isEnabled()
        assert not dialog.custom_path_radio.isEnabled()
    finally:
        dialog_module.NodeJSInstallWorker = original_worker  # type: ignore[misc]


def test_start_installation_creates_worker_thread(dialog: NodeJSSetupDialog) -> None:
    """Start installation creates and starts worker thread."""
    import intellicrack.ui.dialogs.nodejs_setup_dialog as dialog_module
    original_worker = dialog_module.NodeJSInstallWorker

    class FakeWorker:
        def __init__(self) -> None:
            self.started = False
        def start(self) -> None:
            self.started = True

    try:
        dialog_module.NodeJSInstallWorker = FakeWorker  # type: ignore[misc, assignment]
        dialog.start_installation()

        assert dialog.install_worker is not None
        assert hasattr(dialog.install_worker, "started")
        assert getattr(dialog.install_worker, "started", False) is True
    finally:
        dialog_module.NodeJSInstallWorker = original_worker  # type: ignore[misc]


def test_on_install_progress_updates_text(dialog: NodeJSSetupDialog) -> None:
    """Install progress updates progress text."""
    initial_text = dialog.progress_text.toPlainText()

    dialog.on_install_progress("Test progress message")

    assert "Test progress message" in dialog.progress_text.toPlainText()


def test_on_install_finished_success_closes_dialog(recording_dialog: RecordingNodeJSSetupDialog) -> None:
    """Successful installation shows success and closes dialog."""
    recording_dialog.on_install_finished(True, "Installation complete")

    assert len(recording_dialog.show_success_calls) == 1
    assert recording_dialog.accept_calls == 1


def test_on_install_finished_failure_shows_error(recording_dialog: RecordingNodeJSSetupDialog) -> None:
    """Failed installation shows error and keeps dialog open."""
    recording_dialog.on_install_finished(False, "Installation failed")

    assert len(recording_dialog.show_error_calls) == 1
    assert recording_dialog.accept_calls == 0


def test_on_install_finished_reenables_controls(dialog: NodeJSSetupDialog) -> None:
    """Install completion re-enables controls."""
    import intellicrack.ui.dialogs.nodejs_setup_dialog as dialog_module
    original_worker = dialog_module.NodeJSInstallWorker

    class FakeWorker:
        def __init__(self) -> None:
            pass
        def start(self) -> None:
            pass

    try:
        dialog_module.NodeJSInstallWorker = FakeWorker  # type: ignore[misc, assignment]
        dialog.start_installation()

        dialog.on_install_finished(False, "Test failure")

        assert dialog.auto_install_radio.isEnabled()
        assert dialog.custom_path_radio.isEnabled()
    finally:
        dialog_module.NodeJSInstallWorker = original_worker  # type: ignore[misc]


def test_on_install_finished_hides_progress_bar(recording_dialog: RecordingNodeJSSetupDialog) -> None:
    """Install completion hides progress bar."""
    recording_dialog.progress_bar.setVisible(True)

    recording_dialog.on_install_finished(True, "Complete")

    assert not recording_dialog.progress_bar.isVisible()


def test_install_worker_initialization() -> None:
    """Install worker initializes correctly."""
    worker = NodeJSInstallWorker()

    assert worker is not None


def test_install_worker_emits_progress_signals() -> None:
    """Install worker emits progress signals during run."""
    worker = NodeJSInstallWorker()

    progress_messages: List[str] = []
    progress_values: List[int] = []

    def on_progress(msg: str) -> None:
        progress_messages.append(msg)

    def on_progress_value(val: int) -> None:
        progress_values.append(val)

    worker.progress.connect(on_progress)
    worker.progress_value.connect(on_progress_value)

    import subprocess as subprocess_module
    original_run = subprocess_module.run
    subprocess_runner = SubprocessRunner()
    subprocess_runner.return_result = FakeSubprocessResult(0)

    import requests as requests_module
    original_get = requests_module.get
    requests_getter = RequestsGetter()
    requests_getter.return_response = FakeHTTPResponse(b"installer_data")

    import builtins
    original_open = builtins.open
    file_opener = FileOpener()

    try:
        subprocess_module.run = subprocess_runner.run  # type: ignore[assignment]
        requests_module.get = requests_getter.get  # type: ignore[assignment]
        builtins.open = file_opener  # type: ignore[assignment]

        worker.run()

        assert len(progress_messages) > 0
        assert len(progress_values) > 0
        assert 100 in progress_values
    finally:
        subprocess_module.run = original_run
        requests_module.get = original_get
        builtins.open = original_open


def test_install_worker_validates_url_scheme() -> None:
    """Install worker validates URL scheme to prevent file:// attacks."""
    worker = NodeJSInstallWorker()

    finished_calls: List[Tuple[bool, str]] = []

    def on_finished(success: bool, message: str) -> None:
        finished_calls.append((success, message))

    worker.finished.connect(on_finished)

    import intellicrack.ui.dialogs.nodejs_setup_dialog as dialog_module
    original_urlparse = getattr(dialog_module, 'urlparse', None)
    url_parser = URLParser("file")

    try:
        setattr(dialog_module, 'urlparse', url_parser)

        worker.run()

        assert len(finished_calls) == 1
        assert not finished_calls[0][0]
    finally:
        setattr(dialog_module, 'urlparse', original_urlparse)


def test_install_worker_sanitizes_temp_installer_path() -> None:
    """Install worker sanitizes temp installer path to prevent injection."""
    worker = NodeJSInstallWorker()

    import subprocess as subprocess_module
    original_run = subprocess_module.run
    subprocess_runner = SubprocessRunner()
    subprocess_runner.return_result = FakeSubprocessResult(0)

    import requests as requests_module
    original_get = requests_module.get
    requests_getter = RequestsGetter()
    requests_getter.return_response = FakeHTTPResponse(b"installer_data")

    import builtins
    original_open = builtins.open
    file_opener = FileOpener()

    try:
        subprocess_module.run = subprocess_runner.run  # type: ignore[assignment]
        requests_module.get = requests_getter.get  # type: ignore[assignment]
        builtins.open = file_opener  # type: ignore[assignment]

        worker.run()

        assert len(subprocess_runner.run_calls) == 1
        call_kwargs = subprocess_runner.run_calls[0][1]
        assert call_kwargs.get("shell") is False

        command = subprocess_runner.run_calls[0][0][0]
        assert isinstance(command, list)
        assert command[0] == "msiexec"
    finally:
        subprocess_module.run = original_run
        requests_module.get = original_get
        builtins.open = original_open


def test_install_worker_uses_https_url() -> None:
    """Install worker uses HTTPS URL for Node.js download."""
    worker = NodeJSInstallWorker()

    import requests as requests_module
    original_get = requests_module.get
    requests_getter = RequestsGetter()
    requests_getter.return_response = FakeHTTPResponse(b"installer_data")

    import subprocess as subprocess_module
    original_run = subprocess_module.run
    subprocess_runner = SubprocessRunner()
    subprocess_runner.return_result = FakeSubprocessResult(0)

    import builtins
    original_open = builtins.open
    file_opener = FileOpener()

    try:
        requests_module.get = requests_getter.get  # type: ignore[assignment]
        subprocess_module.run = subprocess_runner.run  # type: ignore[assignment]
        builtins.open = file_opener  # type: ignore[assignment]

        worker.run()

        assert len(requests_getter.get_calls) == 1
        url = requests_getter.get_calls[0][0]
        assert url.startswith("https://")
        assert "nodejs.org" in url
    finally:
        requests_module.get = original_get
        subprocess_module.run = original_run
        builtins.open = original_open


def test_install_worker_handles_download_exception() -> None:
    """Install worker handles download exceptions gracefully."""
    worker = NodeJSInstallWorker()

    finished_calls: List[Tuple[bool, str]] = []

    def on_finished(success: bool, message: str) -> None:
        finished_calls.append((success, message))

    worker.finished.connect(on_finished)

    import requests as requests_module
    original_get = requests_module.get
    requests_getter = RequestsGetter()
    requests_getter.raise_exception = Exception("Network error")

    try:
        requests_module.get = requests_getter.get  # type: ignore[assignment]

        worker.run()

        assert len(finished_calls) == 1
        assert not finished_calls[0][0]
    finally:
        requests_module.get = original_get


def test_install_worker_handles_subprocess_exception() -> None:
    """Install worker handles subprocess exceptions gracefully."""
    worker = NodeJSInstallWorker()

    finished_calls: List[Tuple[bool, str]] = []

    def on_finished(success: bool, message: str) -> None:
        finished_calls.append((success, message))

    worker.finished.connect(on_finished)

    import requests as requests_module
    original_get = requests_module.get
    requests_getter = RequestsGetter()
    requests_getter.return_response = FakeHTTPResponse(b"installer_data")

    import subprocess as subprocess_module
    original_run = subprocess_module.run
    subprocess_runner = SubprocessRunner()
    subprocess_runner.raise_exception = Exception("Subprocess error")

    import builtins
    original_open = builtins.open
    file_opener = FileOpener()

    try:
        requests_module.get = requests_getter.get  # type: ignore[assignment]
        subprocess_module.run = subprocess_runner.run  # type: ignore[assignment]
        builtins.open = file_opener  # type: ignore[assignment]

        worker.run()

        assert len(finished_calls) == 1
        assert not finished_calls[0][0]
    finally:
        requests_module.get = original_get
        subprocess_module.run = original_run
        builtins.open = original_open


def test_install_worker_emits_progress_values_incrementally() -> None:
    """Install worker emits progress values in incremental steps."""
    worker = NodeJSInstallWorker()

    progress_values: List[int] = []

    def on_progress_value(val: int) -> None:
        progress_values.append(val)

    worker.progress_value.connect(on_progress_value)

    import subprocess as subprocess_module
    original_run = subprocess_module.run
    subprocess_runner = SubprocessRunner()
    subprocess_runner.return_result = FakeSubprocessResult(0)

    import requests as requests_module
    original_get = requests_module.get
    requests_getter = RequestsGetter()
    requests_getter.return_response = FakeHTTPResponse(b"installer_data")

    import builtins
    original_open = builtins.open
    file_opener = FileOpener()

    try:
        subprocess_module.run = subprocess_runner.run  # type: ignore[assignment]
        requests_module.get = requests_getter.get  # type: ignore[assignment]
        builtins.open = file_opener  # type: ignore[assignment]

        worker.run()

        assert len(progress_values) > 3
        assert progress_values[0] < progress_values[-1]
    finally:
        subprocess_module.run = original_run
        requests_module.get = original_get
        builtins.open = original_open


def test_install_worker_success_emits_100_percent(dialog: NodeJSSetupDialog) -> None:
    """Successful installation emits 100% progress."""
    worker = NodeJSInstallWorker()

    progress_values: List[int] = []

    def on_progress_value(val: int) -> None:
        progress_values.append(val)

    worker.progress_value.connect(on_progress_value)

    import subprocess as subprocess_module
    original_run = subprocess_module.run
    subprocess_runner = SubprocessRunner()
    subprocess_runner.return_result = FakeSubprocessResult(0)

    import requests as requests_module
    original_get = requests_module.get
    requests_getter = RequestsGetter()
    requests_getter.return_response = FakeHTTPResponse(b"installer_data")

    import builtins
    original_open = builtins.open
    file_opener = FileOpener()

    try:
        subprocess_module.run = subprocess_runner.run  # type: ignore[assignment]
        requests_module.get = requests_getter.get  # type: ignore[assignment]
        builtins.open = file_opener  # type: ignore[assignment]

        worker.run()

        assert 100 in progress_values
    finally:
        subprocess_module.run = original_run
        requests_module.get = original_get
        builtins.open = original_open


def test_install_worker_failure_resets_progress(dialog: NodeJSSetupDialog) -> None:
    """Failed installation resets progress to 0."""
    worker = NodeJSInstallWorker()

    progress_values: List[int] = []

    def on_progress_value(val: int) -> None:
        progress_values.append(val)

    worker.progress_value.connect(on_progress_value)

    import requests as requests_module
    original_get = requests_module.get
    requests_getter = RequestsGetter()
    requests_getter.raise_exception = Exception("Test error")

    try:
        requests_module.get = requests_getter.get  # type: ignore[assignment]

        worker.run()

        assert 0 in progress_values
    finally:
        requests_module.get = original_get


def test_path_detection_checks_common_locations(dialog: NodeJSSetupDialog) -> None:
    """Path detection checks common Node.js installation locations."""
    path_text = dialog.path_input.text()

    assert "Program Files" in path_text or "nodejs" in path_text.lower()


def test_progress_bar_range_set_correctly(dialog: NodeJSSetupDialog) -> None:
    """Progress bar is configured with 0-100 range."""
    import intellicrack.ui.dialogs.nodejs_setup_dialog as dialog_module
    original_worker = dialog_module.NodeJSInstallWorker

    class FakeWorker:
        def __init__(self) -> None:
            pass
        def start(self) -> None:
            pass

    try:
        dialog_module.NodeJSInstallWorker = FakeWorker  # type: ignore[misc, assignment]
        dialog.start_installation()

        assert dialog.progress_bar.minimum() == 0
        assert dialog.progress_bar.maximum() == 100
    finally:
        dialog_module.NodeJSInstallWorker = original_worker  # type: ignore[misc]


def test_progress_text_cleared_on_installation_start(dialog: NodeJSSetupDialog) -> None:
    """Progress text is cleared when installation starts."""
    dialog.progress_text.setText("Previous text")

    import intellicrack.ui.dialogs.nodejs_setup_dialog as dialog_module
    original_worker = dialog_module.NodeJSInstallWorker

    class FakeWorker:
        def __init__(self) -> None:
            pass
        def start(self) -> None:
            pass

    try:
        dialog_module.NodeJSInstallWorker = FakeWorker  # type: ignore[misc, assignment]
        dialog.start_installation()

        assert dialog.progress_text.toPlainText() == ""
    finally:
        dialog_module.NodeJSInstallWorker = original_worker  # type: ignore[misc]


def test_worker_progress_signal_connected_to_progress_bar(dialog: NodeJSSetupDialog) -> None:
    """Worker progress_value signal is connected to progress bar."""
    import intellicrack.ui.dialogs.nodejs_setup_dialog as dialog_module
    original_worker = dialog_module.NodeJSInstallWorker

    class FakeWorker:
        def __init__(self) -> None:
            from intellicrack.handlers.pyqt6_handler import QObject, pyqtSignal
            self.progress_value = pyqtSignal(int)
        def start(self) -> None:
            pass

    try:
        dialog_module.NodeJSInstallWorker = FakeWorker  # type: ignore[misc, assignment]
        dialog.start_installation()

        assert dialog.install_worker is not None

        signal_obj = dialog.install_worker.progress_value
        receivers_count = signal_obj.receivers(signal_obj)  # type: ignore[attr-defined]
        assert receivers_count > 0
    finally:
        dialog_module.NodeJSInstallWorker = original_worker  # type: ignore[misc]
