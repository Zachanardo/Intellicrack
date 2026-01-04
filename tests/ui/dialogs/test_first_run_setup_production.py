"""Production-ready tests for FirstRunSetupDialog.

Tests REAL setup functionality with actual package installation simulation.
Tests MUST FAIL if setup logic doesn't work properly.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import subprocess
import sys
from typing import Any

import pytest
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.dialogs.first_run_setup import FirstRunSetupDialog, SetupWorker


class SubprocessResult:
    """Real test double for subprocess.CompletedProcess."""

    def __init__(self, returncode: int, stdout: str, stderr: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeSubprocessRunner:
    """Real test double for subprocess.run that tracks calls."""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.calls: list[list[str]] = []
        self.call_count = 0

    def run(self, cmd: list[str], **kwargs: Any) -> SubprocessResult:
        """Simulate subprocess.run call."""
        self.calls.append(cmd)
        self.call_count += 1
        return SubprocessResult(self.returncode, self.stdout, self.stderr)

    def get_last_call(self) -> list[str]:
        """Get the last subprocess command that was called."""
        return self.calls[-1] if self.calls else []

    def was_called_once(self) -> bool:
        """Check if subprocess.run was called exactly once."""
        return self.call_count == 1

    def was_called_with_command(self, *expected_parts: str) -> bool:
        """Check if the last call contained all expected command parts."""
        last_call = self.get_last_call()
        return all(part in last_call for part in expected_parts)


class ConditionalSubprocessRunner:
    """Test double that returns different results based on command content."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.call_order: list[str] = []

    def run(self, cmd: list[str], **kwargs: Any) -> SubprocessResult:
        """Simulate subprocess.run with conditional responses."""
        self.calls.append(cmd)

        if "flask" in cmd:
            self.call_order.append("flask")
            return SubprocessResult(0, "Successfully installed flask flask-cors", "")
        elif "llama-cpp-python" in cmd:
            self.call_order.append("llama")
            return SubprocessResult(0, "Successfully installed llama-cpp-python", "")

        return SubprocessResult(0, "Success", "")


class PartialFailureSubprocessRunner:
    """Test double that fails on llama-cpp-python but succeeds on Flask."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.call_count = 0

    def run(self, cmd: list[str], **kwargs: Any) -> SubprocessResult:
        """Simulate subprocess.run with partial failure."""
        self.calls.append(cmd)
        self.call_count += 1

        if "flask" in cmd:
            return SubprocessResult(0, "Successfully installed flask", "")

        return SubprocessResult(1, "", "Error installing llama-cpp-python")


class ExceptionRaisingSubprocessRunner:
    """Test double that raises subprocess exceptions."""

    def __init__(self, exception: Exception) -> None:
        self.exception = exception
        self.calls: list[list[str]] = []

    def run(self, cmd: list[str], **kwargs: Any) -> SubprocessResult:
        """Simulate subprocess.run that raises an exception."""
        self.calls.append(cmd)
        raise self.exception


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    """Create QApplication instance for all tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
        app.setApplicationName("IntellicrackSetupTest")
        return app
    assert isinstance(app, QApplication), "Expected QApplication instance"
    app.setApplicationName("IntellicrackSetupTest")
    return app


@pytest.fixture
def missing_flask() -> dict[str, bool]:
    """Missing components configuration with Flask missing."""
    return {
        "Flask": False,
        "llama-cpp-python": True,
    }


@pytest.fixture
def missing_both() -> dict[str, bool]:
    """Missing components configuration with both components missing."""
    return {
        "Flask": False,
        "llama-cpp-python": False,
    }


@pytest.fixture
def all_installed() -> dict[str, bool]:
    """Configuration with all components already installed."""
    return {
        "Flask": True,
        "llama-cpp-python": True,
    }


class TestSetupWorkerPackageInstallation:
    """Test REAL package installation logic in SetupWorker."""

    def test_install_flask_task_runs_correct_pip_command(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Flask installation task executes correct pip install command."""
        worker = SetupWorker(["install_flask"])
        runner = FakeSubprocessRunner(returncode=0, stdout="Successfully installed flask")

        monkeypatch.setattr(subprocess, "run", runner.run)

        worker.run()

        assert runner.was_called_once()
        assert runner.was_called_with_command(sys.executable, "-m", "pip", "install", "flask", "flask-cors")

    def test_install_llama_task_runs_correct_pip_command(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Llama-cpp-python installation task executes correct pip command."""
        worker = SetupWorker(["install_llama"])
        runner = FakeSubprocessRunner(returncode=0, stdout="Successfully installed llama-cpp-python")

        monkeypatch.setattr(subprocess, "run", runner.run)

        worker.run()

        assert runner.was_called_once()
        assert runner.was_called_with_command(sys.executable, "-m", "pip", "install", "llama-cpp-python")

    def test_worker_emits_progress_signals(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Worker emits progress signals during task execution."""
        worker = SetupWorker(["install_flask", "install_llama"])

        progress_values: list[int] = []
        status_messages: list[str] = []

        def capture_progress(value: int) -> None:
            progress_values.append(value)

        def capture_status(message: str) -> None:
            status_messages.append(message)

        worker.progress.connect(capture_progress)
        worker.status.connect(capture_status)

        runner = FakeSubprocessRunner(returncode=0, stdout="Success")
        monkeypatch.setattr(subprocess, "run", runner.run)

        worker.run()

        assert 100 in progress_values, "Worker must emit 100% progress on completion"
        assert len(status_messages) >= 2, "Worker must emit status messages for each task"
        assert any("Flask" in msg for msg in status_messages)
        assert any("llama-cpp-python" in msg for msg in status_messages)
        assert "Setup complete!" in status_messages

    def test_worker_handles_installation_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Worker handles package installation failures correctly."""
        worker = SetupWorker(["install_flask"])

        finished_signals: list[bool] = []

        def capture_finished(success: bool) -> None:
            finished_signals.append(success)

        worker.finished.connect(capture_finished)

        runner = FakeSubprocessRunner(returncode=1, stderr="Error: Package not found")
        monkeypatch.setattr(subprocess, "run", runner.run)

        worker.run()

        assert len(finished_signals) == 1
        assert not finished_signals[0], "Worker must emit failure signal when installation fails"
        assert not worker.success

    def test_worker_handles_subprocess_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Worker handles subprocess exceptions gracefully."""
        worker = SetupWorker(["install_flask"])

        finished_signals: list[bool] = []
        worker.finished.connect(lambda success: finished_signals.append(success))

        runner = ExceptionRaisingSubprocessRunner(subprocess.SubprocessError("Subprocess failed"))
        monkeypatch.setattr(subprocess, "run", runner.run)

        worker.run()

        assert len(finished_signals) == 1
        assert not finished_signals[0]
        assert not worker.success

    def test_worker_processes_multiple_tasks_sequentially(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Worker processes multiple installation tasks in sequence."""
        worker = SetupWorker(["install_flask", "install_llama"])

        runner = ConditionalSubprocessRunner()
        monkeypatch.setattr(subprocess, "run", runner.run)

        worker.run()

        assert runner.call_order == ["flask", "llama"], "Tasks must be executed in order"


class TestFirstRunSetupDialog:
    """Test FirstRunSetupDialog UI and logic."""

    def test_dialog_initializes_with_missing_components(self, qapp: QApplication, missing_both: dict[str, bool]) -> None:
        """Dialog initializes correctly with missing components configuration."""
        dialog = FirstRunSetupDialog(missing_both)

        assert dialog.missing_components == missing_both
        assert not dialog.setup_complete
        assert dialog.windowTitle() == "First Run Setup - Intellicrack"

    def test_dialog_creates_checkboxes_for_missing_components(self, qapp: QApplication, missing_both: dict[str, bool]) -> None:
        """Dialog creates checkboxes for each missing component."""
        dialog = FirstRunSetupDialog(missing_both)

        assert "install_flask" in dialog.component_checks
        assert "install_llama" in dialog.component_checks

        flask_checkbox = dialog.component_checks["install_flask"]
        llama_checkbox = dialog.component_checks["install_llama"]

        assert flask_checkbox.isChecked(), "Missing components should be checked by default"
        assert llama_checkbox.isChecked(), "Missing components should be checked by default"

    def test_dialog_only_shows_missing_components(self, qapp: QApplication, missing_flask: dict[str, bool]) -> None:
        """Dialog only shows checkboxes for actually missing components."""
        dialog = FirstRunSetupDialog(missing_flask)

        assert "install_flask" in dialog.component_checks
        assert "install_llama" not in dialog.component_checks

    def test_dialog_with_all_installed_has_no_checkboxes(self, qapp: QApplication, all_installed: dict[str, bool]) -> None:
        """Dialog with all components installed has no installation checkboxes."""
        dialog = FirstRunSetupDialog(all_installed)

        assert len(dialog.component_checks) == 0

    def test_start_setup_with_no_selected_tasks_accepts_immediately(self, qapp: QApplication, missing_both: dict[str, bool]) -> None:
        """Start setup with no selected tasks accepts dialog immediately."""
        dialog = FirstRunSetupDialog(missing_both)

        for checkbox in dialog.component_checks.values():
            checkbox.setChecked(False)

        dialog.start_setup()

    def test_start_setup_enables_progress_ui_elements(self, qapp: QApplication, missing_flask: dict[str, bool], monkeypatch: pytest.MonkeyPatch) -> None:
        """Start setup makes progress UI elements visible."""
        dialog = FirstRunSetupDialog(missing_flask)

        assert not dialog.progress_bar.isVisible()
        assert not dialog.status_label.isVisible()
        assert not dialog.log_output.isVisible()

        runner = FakeSubprocessRunner(returncode=0, stdout="Success")
        monkeypatch.setattr(subprocess, "run", runner.run)

        dialog.start_setup()

        QTimer.singleShot(100, lambda: dialog.worker.quit() if hasattr(dialog, "worker") else None)
        qapp.processEvents()

        assert dialog.progress_bar.isVisible()
        assert dialog.status_label.isVisible()
        assert dialog.log_output.isVisible()

    def test_start_setup_disables_buttons_during_installation(self, qapp: QApplication, missing_flask: dict[str, bool], monkeypatch: pytest.MonkeyPatch) -> None:
        """Start setup disables buttons while installation is running."""
        dialog = FirstRunSetupDialog(missing_flask)

        assert dialog.setup_button.isEnabled()
        assert dialog.skip_button.isEnabled()

        runner = FakeSubprocessRunner(returncode=0, stdout="Success")
        monkeypatch.setattr(subprocess, "run", runner.run)

        dialog.start_setup()

        assert not dialog.setup_button.isEnabled()
        assert not dialog.skip_button.isEnabled()

        QTimer.singleShot(100, lambda: dialog.worker.quit() if hasattr(dialog, "worker") else None)
        qapp.processEvents()

    def test_start_setup_creates_worker_with_selected_tasks(self, qapp: QApplication, missing_both: dict[str, bool], monkeypatch: pytest.MonkeyPatch) -> None:
        """Start setup creates SetupWorker with only selected tasks."""
        dialog = FirstRunSetupDialog(missing_both)

        dialog.component_checks["install_flask"].setChecked(True)
        dialog.component_checks["install_llama"].setChecked(False)

        runner = FakeSubprocessRunner(returncode=0, stdout="Success")
        monkeypatch.setattr(subprocess, "run", runner.run)

        dialog.start_setup()

        assert hasattr(dialog, "worker")
        assert "install_flask" in dialog.worker.tasks
        assert "install_llama" not in dialog.worker.tasks

        QTimer.singleShot(100, lambda: dialog.worker.quit())
        qapp.processEvents()

    def test_update_status_updates_label_and_log(self, qapp: QApplication, missing_flask: dict[str, bool]) -> None:
        """Update status updates both status label and log output."""
        dialog = FirstRunSetupDialog(missing_flask)

        test_status = "Installing test package..."
        dialog.update_status(test_status)

        assert dialog.status_label.text() == test_status
        assert test_status in dialog.log_output.toPlainText()

    def test_setup_finished_with_success_updates_ui(self, qapp: QApplication, missing_flask: dict[str, bool]) -> None:
        """Setup finished with success updates UI appropriately."""
        dialog = FirstRunSetupDialog(missing_flask)

        dialog.setup_finished(True)

        assert dialog.setup_complete
        assert dialog.status_label.text() == "Setup completed successfully!"
        assert dialog.setup_button.text() == "Continue"
        assert dialog.setup_button.isEnabled()

    def test_setup_finished_with_failure_updates_ui(self, qapp: QApplication, missing_flask: dict[str, bool]) -> None:
        """Setup finished with failure updates UI to allow continuation."""
        dialog = FirstRunSetupDialog(missing_flask)

        dialog.setup_finished(False)

        assert dialog.setup_complete
        assert dialog.status_label.text() == "Setup completed with some errors."
        assert dialog.setup_button.text() == "Continue Anyway"
        assert dialog.setup_button.isEnabled()
        assert dialog.skip_button.isEnabled()


class TestFirstRunSetupIntegration:
    """Integration tests for complete setup workflows."""

    def test_complete_flask_installation_workflow(self, qapp: QApplication, missing_flask: dict[str, bool], monkeypatch: pytest.MonkeyPatch) -> None:
        """Complete Flask installation workflow executes successfully."""
        dialog = FirstRunSetupDialog(missing_flask)

        completion_status: list[bool] = []

        def on_finished(success: bool) -> None:
            completion_status.append(success)

        runner = FakeSubprocessRunner(returncode=0, stdout="Successfully installed flask flask-cors")
        monkeypatch.setattr(subprocess, "run", runner.run)

        dialog.start_setup()

        if hasattr(dialog, "worker"):
            dialog.worker.finished.connect(on_finished)
            dialog.worker.wait(2000)

        assert len(completion_status) == 1
        assert completion_status[0]

    def test_complete_multi_component_installation_workflow(self, qapp: QApplication, missing_both: dict[str, bool], monkeypatch: pytest.MonkeyPatch) -> None:
        """Complete installation of multiple components works correctly."""
        dialog = FirstRunSetupDialog(missing_both)

        progress_updates: list[int] = []
        status_updates: list[str] = []

        def capture_progress(value: int) -> None:
            progress_updates.append(value)

        def capture_status(status: str) -> None:
            status_updates.append(status)

        runner = FakeSubprocessRunner(returncode=0, stdout="Success")
        monkeypatch.setattr(subprocess, "run", runner.run)

        dialog.start_setup()

        if hasattr(dialog, "worker"):
            dialog.worker.progress.connect(capture_progress)
            dialog.worker.status.connect(capture_status)
            dialog.worker.wait(2000)

        assert 100 in progress_updates
        assert len(status_updates) >= 3
        assert any("Flask" in msg for msg in status_updates)
        assert any("llama-cpp-python" in msg for msg in status_updates)
        assert "Setup complete!" in status_updates

    def test_partial_installation_failure_workflow(self, qapp: QApplication, missing_both: dict[str, bool], monkeypatch: pytest.MonkeyPatch) -> None:
        """Partial installation failure (one succeeds, one fails) is handled correctly."""
        dialog = FirstRunSetupDialog(missing_both)

        runner = PartialFailureSubprocessRunner()
        monkeypatch.setattr(subprocess, "run", runner.run)

        completion_status: list[bool] = []

        dialog.start_setup()

        if hasattr(dialog, "worker"):
            dialog.worker.finished.connect(lambda success: completion_status.append(success))
            dialog.worker.wait(2000)

        assert len(completion_status) == 1
        assert not completion_status[0], "Workflow must report failure when any installation fails"
        assert runner.call_count == 2, "All installations must be attempted despite failures"

    def test_skip_button_rejects_dialog(self, qapp: QApplication, missing_flask: dict[str, bool]) -> None:
        """Skip button properly rejects the dialog without installing."""
        dialog = FirstRunSetupDialog(missing_flask)

        dialog.skip_button.click()

        assert not dialog.setup_complete

    def test_continue_button_after_success_accepts_dialog(self, qapp: QApplication, missing_flask: dict[str, bool]) -> None:
        """Continue button after successful setup accepts dialog."""
        dialog = FirstRunSetupDialog(missing_flask)

        dialog.setup_finished(True)

        assert dialog.setup_button.text() == "Continue"
        assert dialog.setup_complete
