"""Production tests for project workspace tab (DashboardTab in project_workspace_tab.py).

This module tests the project management, binary loading, and workspace
operations provided by the DashboardTab class.

Copyright (C) 2025 Zachary Flint
This file is part of Intellicrack and follows GPL v3 licensing.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.pyqt6_handler import QMessageBox
from intellicrack.ui.tabs.project_workspace_tab import DashboardTab


class FakeMainWindow:
    """Test double for main window."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __getattr__(self, name: str) -> Any:
        def method(*args: Any, **kwargs: Any) -> None:
            self.calls.append(f"{name}({args}, {kwargs})")

        return method


class FakeLogMessage:
    """Test double for log message function."""

    def __init__(self) -> None:
        self.messages: list[tuple[str, ...]] = []

    def __call__(self, *args: str) -> None:
        self.messages.append(args)


class FakeAppContext:
    """Test double for application context."""

    def __init__(self) -> None:
        self.data: dict[str, Any] = {}

    def __getattr__(self, name: str) -> Any:
        return self.data.get(name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "data":
            object.__setattr__(self, name, value)
        else:
            self.data[name] = value


class FakeTaskManager:
    """Test double for task manager."""

    def __init__(self) -> None:
        self.tasks: list[str] = []

    def add_task(self, task: str) -> None:
        self.tasks.append(task)

    def __getattr__(self, name: str) -> Any:
        def method(*args: Any, **kwargs: Any) -> None:
            pass

        return method


class FakeFileDialog:
    """Test double for QFileDialog."""

    def __init__(self, return_path: str = "", return_filter: str = "") -> None:
        self.return_path: str = return_path
        self.return_filter: str = return_filter

    def getSaveFileName(
        self,
        parent: Any = None,
        caption: str = "",
        directory: str = "",
        filter: str = "",
        initialFilter: str = "",
    ) -> tuple[str, str]:
        return (self.return_path, self.return_filter)

    def getOpenFileName(
        self,
        parent: Any = None,
        caption: str = "",
        directory: str = "",
        filter: str = "",
        initialFilter: str = "",
    ) -> tuple[str, str]:
        return (self.return_path, self.return_filter)


class FakeMessageBox:
    """Test double for QMessageBox."""

    def __init__(self) -> None:
        self.information_called: bool = False
        self.warning_called: bool = False
        self.critical_called: bool = False
        self.question_called: bool = False
        self.question_response: Any = QMessageBox.StandardButton.No
        self.last_parent: Any = None
        self.last_title: str = ""
        self.last_message: str = ""

    def information(self, parent: Any, title: str, message: str) -> None:
        self.information_called = True
        self.last_parent = parent
        self.last_title = title
        self.last_message = message

    def warning(self, parent: Any, title: str, message: str) -> None:
        self.warning_called = True
        self.last_parent = parent
        self.last_title = title
        self.last_message = message

    def critical(self, parent: Any, title: str, message: str) -> None:
        self.critical_called = True
        self.last_parent = parent
        self.last_title = title
        self.last_message = message

    def question(
        self,
        parent: Any,
        title: str,
        message: str,
        buttons: Any = None,
        defaultButton: Any = None,
    ) -> Any:
        self.question_called = True
        self.last_parent = parent
        self.last_title = title
        self.last_message = message
        return self.question_response


class TestProjectWorkspaceTabInitialization:
    """Test suite for DashboardTab initialization."""

    @pytest.fixture
    def shared_context(self) -> dict[str, object]:
        """Create shared context for tab."""
        return {
            "main_window": FakeMainWindow(),
            "log_message": FakeLogMessage(),
            "app_context": FakeAppContext(),
            "task_manager": FakeTaskManager(),
        }

    @pytest.fixture
    def dashboard_tab(
        self,
        shared_context: dict[str, object],
        qtbot: object,
    ) -> DashboardTab:
        """Create DashboardTab instance."""
        tab = DashboardTab(shared_context)
        qtbot.addWidget(tab)
        return tab

    def test_dashboard_tab_initialization(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Dashboard tab initializes with default state."""
        assert dashboard_tab.current_binary_path is None
        assert dashboard_tab.recent_files == []
        assert dashboard_tab.binary_info_label is not None
        assert dashboard_tab.activity_log is not None

    def test_dashboard_tab_creates_ui_components(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Dashboard tab creates all required UI components."""
        assert dashboard_tab.binary_icon_label is not None
        assert dashboard_tab.binary_info_label is not None
        assert dashboard_tab.file_size_label is not None
        assert dashboard_tab.architecture_label is not None
        assert dashboard_tab.entry_point_label is not None
        assert dashboard_tab.vulns_found_label is not None
        assert dashboard_tab.protections_label is not None
        assert dashboard_tab.patches_label is not None
        assert dashboard_tab.activity_log is not None

    def test_dashboard_tab_initial_labels(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Dashboard tab has correct initial label values."""
        assert "No binary loaded" in dashboard_tab.binary_info_label.text()
        assert "File Size: -" in dashboard_tab.file_size_label.text()
        assert "Architecture: -" in dashboard_tab.architecture_label.text()
        assert "Entry Point: -" in dashboard_tab.entry_point_label.text()


class TestProjectManagement:
    """Test suite for project management operations."""

    @pytest.fixture
    def dashboard_tab(self, qtbot: object) -> DashboardTab:
        """Create DashboardTab instance."""
        tab = DashboardTab()
        qtbot.addWidget(tab)
        return tab

    @pytest.fixture
    def temp_project_dir(self) -> str:
        """Create temporary project directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_create_new_project_resets_state(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Creating new project resets all state."""
        dashboard_tab.current_binary_path = "test.exe"
        dashboard_tab.recent_files = ["file1.exe", "file2.dll"]

        dashboard_tab.create_new_project()

        assert dashboard_tab.current_binary_path is None
        assert not dashboard_tab.recent_files
        assert "No binary loaded" in dashboard_tab.binary_info_label.text()

    def test_create_new_project_resets_labels(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Creating new project resets all information labels."""
        dashboard_tab.create_new_project()

        assert "File Size: -" in dashboard_tab.file_size_label.text()
        assert "Architecture: -" in dashboard_tab.architecture_label.text()
        assert "Entry Point: -" in dashboard_tab.entry_point_label.text()
        assert "Vulnerabilities Found: 0" in dashboard_tab.vulns_found_label.text()

    def test_save_project_creates_project_file(
        self,
        dashboard_tab: DashboardTab,
        temp_project_dir: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Saving project creates valid project file."""
        dashboard_tab.current_binary_path = os.path.join(temp_project_dir, "test.exe")
        Path(dashboard_tab.current_binary_path).touch()

        project_file = os.path.join(temp_project_dir, "test.icp")

        fake_dialog = FakeFileDialog(project_file, "")
        monkeypatch.setattr(
            "intellicrack.ui.tabs.project_workspace_tab.QFileDialog",
            fake_dialog,
        )

        dashboard_tab.save_project()

        assert os.path.exists(project_file)

        with open(project_file, encoding="utf-8") as f:
            project_data = json.load(f)

        assert "binary_path" in project_data
        assert "recent_files" in project_data

    def test_save_project_without_binary(
        self,
        dashboard_tab: DashboardTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Saving project without binary shows information message."""
        dashboard_tab.current_binary_path = None

        fake_messagebox = FakeMessageBox()
        monkeypatch.setattr(QMessageBox, "information", fake_messagebox.information)

        dashboard_tab.save_project()

        assert fake_messagebox.information_called

    def test_open_project_loads_binary(
        self,
        dashboard_tab: DashboardTab,
        temp_project_dir: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Opening project loads associated binary."""
        binary_path = os.path.join(temp_project_dir, "test.exe")
        Path(binary_path).write_bytes(b"MZ\x90\x00" + b"\x00" * 60)

        project_file = os.path.join(temp_project_dir, "test.icp")
        project_data = {"binary_path": binary_path}
        with open(project_file, "w", encoding="utf-8") as f:
            json.dump(project_data, f)

        fake_dialog = FakeFileDialog(project_file, "")
        monkeypatch.setattr(
            "intellicrack.ui.tabs.project_workspace_tab.QFileDialog",
            fake_dialog,
        )

        dashboard_tab.open_project()

        assert dashboard_tab.current_binary_path == binary_path

    def test_open_project_handles_missing_binary(
        self,
        dashboard_tab: DashboardTab,
        temp_project_dir: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Opening project handles missing binary file."""
        project_file = os.path.join(temp_project_dir, "test.icp")
        project_data = {"binary_path": "/nonexistent/test.exe"}
        with open(project_file, "w", encoding="utf-8") as f:
            json.dump(project_data, f)

        fake_dialog = FakeFileDialog(project_file, "")
        fake_messagebox = FakeMessageBox()

        monkeypatch.setattr(
            "intellicrack.ui.tabs.project_workspace_tab.QFileDialog",
            fake_dialog,
        )
        monkeypatch.setattr(QMessageBox, "warning", fake_messagebox.warning)

        dashboard_tab.open_project()

        assert fake_messagebox.warning_called

    def test_open_project_handles_invalid_file(
        self,
        dashboard_tab: DashboardTab,
        temp_project_dir: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Opening invalid project file shows error."""
        project_file = os.path.join(temp_project_dir, "invalid.icp")
        with open(project_file, "w", encoding="utf-8") as f:
            f.write("invalid json")

        fake_dialog = FakeFileDialog(project_file, "")
        fake_messagebox = FakeMessageBox()

        monkeypatch.setattr(
            "intellicrack.ui.tabs.project_workspace_tab.QFileDialog",
            fake_dialog,
        )
        monkeypatch.setattr(QMessageBox, "critical", fake_messagebox.critical)

        dashboard_tab.open_project()

        assert fake_messagebox.critical_called


class TestBinaryManagement:
    """Test suite for binary loading and management."""

    @pytest.fixture
    def dashboard_tab(self, qtbot: object) -> DashboardTab:
        """Create DashboardTab instance."""
        tab = DashboardTab()
        qtbot.addWidget(tab)
        return tab

    @pytest.fixture
    def temp_binary(self) -> str:
        """Create temporary binary file."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00")
            temp_path = f.name

        yield temp_path

        if os.path.exists(temp_path):
            os.unlink(temp_path)

    def test_load_binary_updates_ui(
        self,
        dashboard_tab: DashboardTab,
        temp_binary: str,
    ) -> None:
        """Loading binary updates all UI components."""
        dashboard_tab.load_binary(temp_binary)

        assert dashboard_tab.current_binary_path == temp_binary
        assert os.path.basename(temp_binary) in dashboard_tab.binary_info_label.text()
        assert "File Size:" in dashboard_tab.file_size_label.text()
        assert dashboard_tab.file_size_label.text() != "File Size: -"

    def test_load_binary_emits_signal(
        self,
        dashboard_tab: DashboardTab,
        temp_binary: str,
        qtbot: object,
    ) -> None:
        """Loading binary emits binary_selected signal."""
        with qtbot.waitSignal(dashboard_tab.binary_selected, timeout=1000) as blocker:
            dashboard_tab.load_binary(temp_binary)

        assert blocker.args[0] == temp_binary

    def test_load_binary_adds_to_recent_files(
        self,
        dashboard_tab: DashboardTab,
        temp_binary: str,
    ) -> None:
        """Loading binary adds to recent files list."""
        dashboard_tab.load_binary(temp_binary)

        assert temp_binary in dashboard_tab.recent_files
        assert dashboard_tab.recent_files[0] == temp_binary

    def test_load_binary_formats_file_size(
        self,
        dashboard_tab: DashboardTab,
        temp_binary: str,
    ) -> None:
        """Loading binary formats file size correctly."""
        dashboard_tab.load_binary(temp_binary)

        file_size_text = dashboard_tab.file_size_label.text()
        assert any(unit in file_size_text for unit in ["B", "KB", "MB", "GB"])

    def test_close_binary_resets_ui(
        self,
        dashboard_tab: DashboardTab,
        temp_binary: str,
    ) -> None:
        """Closing binary resets UI to initial state."""
        dashboard_tab.load_binary(temp_binary)
        dashboard_tab.close_binary()

        assert dashboard_tab.current_binary_path is None
        assert "No binary loaded" in dashboard_tab.binary_info_label.text()
        assert "File Size: -" in dashboard_tab.file_size_label.text()
        assert "Architecture: -" in dashboard_tab.architecture_label.text()

    def test_recent_files_maintains_order(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Recent files list maintains chronological order."""
        files = ["file1.exe", "file2.dll", "file3.exe"]

        for file_path in files:
            dashboard_tab.add_to_recent_files(file_path)

        assert dashboard_tab.recent_files == list(reversed(files))

    def test_recent_files_removes_duplicates(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Adding duplicate file moves it to top of recent files."""
        dashboard_tab.add_to_recent_files("file1.exe")
        dashboard_tab.add_to_recent_files("file2.exe")
        dashboard_tab.add_to_recent_files("file1.exe")

        assert dashboard_tab.recent_files[0] == "file1.exe"
        assert dashboard_tab.recent_files.count("file1.exe") == 1

    def test_recent_files_limits_to_ten(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Recent files list limited to 10 entries."""
        for i in range(15):
            dashboard_tab.add_to_recent_files(f"file{i}.exe")

        assert len(dashboard_tab.recent_files) == 10


class TestAnalysisOperations:
    """Test suite for analysis-related operations."""

    @pytest.fixture
    def dashboard_tab(self, qtbot: object) -> DashboardTab:
        """Create DashboardTab instance."""
        tab = DashboardTab()
        qtbot.addWidget(tab)
        return tab

    @pytest.fixture
    def temp_binary(self) -> str:
        """Create temporary binary file."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 62 + b"PE\x00\x00")
            temp_path = f.name

        yield temp_path

        if os.path.exists(temp_path):
            os.unlink(temp_path)

    def test_save_analysis_results_without_binary(
        self,
        dashboard_tab: DashboardTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Saving analysis without binary shows information message."""
        fake_messagebox = FakeMessageBox()
        monkeypatch.setattr(QMessageBox, "information", fake_messagebox.information)

        dashboard_tab.save_analysis_results()

        assert fake_messagebox.information_called

    def test_save_analysis_results_emits_signal(
        self,
        dashboard_tab: DashboardTab,
        temp_binary: str,
        qtbot: object,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Saving analysis emits analysis_saved signal."""
        dashboard_tab.load_binary(temp_binary)

        results_file = tempfile.mktemp(suffix=".json")

        fake_dialog = FakeFileDialog(results_file, "")
        monkeypatch.setattr(
            "intellicrack.ui.tabs.project_workspace_tab.QFileDialog",
            fake_dialog,
        )

        with qtbot.waitSignal(dashboard_tab.analysis_saved, timeout=1000) as blocker:
            dashboard_tab.save_analysis_results()

        assert blocker.args[0] == results_file

    def test_export_results_without_binary(
        self,
        dashboard_tab: DashboardTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exporting results without binary shows information message."""
        fake_messagebox = FakeMessageBox()
        monkeypatch.setattr(QMessageBox, "information", fake_messagebox.information)

        dashboard_tab.export_results()

        assert fake_messagebox.information_called

    def test_export_results_as_csv(
        self,
        dashboard_tab: DashboardTab,
        temp_binary: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exporting results as CSV creates valid file."""
        dashboard_tab.load_binary(temp_binary)

        csv_file = tempfile.mktemp(suffix=".csv")

        fake_dialog = FakeFileDialog(csv_file, "")
        monkeypatch.setattr(
            "intellicrack.ui.tabs.project_workspace_tab.QFileDialog",
            fake_dialog,
        )

        dashboard_tab.export_results()

        assert os.path.exists(csv_file)

        with open(csv_file, encoding="utf-8") as f:
            content = f.read()
            assert "Analysis Results Export" in content
            assert "Binary:" in content

        os.unlink(csv_file)

    def test_export_results_as_json(
        self,
        dashboard_tab: DashboardTab,
        temp_binary: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exporting results as JSON creates valid file."""
        dashboard_tab.load_binary(temp_binary)

        json_file = tempfile.mktemp(suffix=".json")

        fake_dialog = FakeFileDialog(json_file, "")
        monkeypatch.setattr(
            "intellicrack.ui.tabs.project_workspace_tab.QFileDialog",
            fake_dialog,
        )

        dashboard_tab.export_results()

        assert os.path.exists(json_file)

        with open(json_file, encoding="utf-8") as f:
            data = json.load(f)
            assert "binary_path" in data
            assert data["binary_path"] == temp_binary

        os.unlink(json_file)

    def test_export_results_as_text(
        self,
        dashboard_tab: DashboardTab,
        temp_binary: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exporting results as text creates valid file."""
        dashboard_tab.load_binary(temp_binary)

        txt_file = tempfile.mktemp(suffix=".txt")

        fake_dialog = FakeFileDialog(txt_file, "")
        monkeypatch.setattr(
            "intellicrack.ui.tabs.project_workspace_tab.QFileDialog",
            fake_dialog,
        )

        dashboard_tab.export_results()

        assert os.path.exists(txt_file)

        with open(txt_file, encoding="utf-8") as f:
            content = f.read()
            assert "INTELLICRACK ANALYSIS RESULTS" in content
            assert "Binary Path:" in content

        os.unlink(txt_file)

    def test_export_handles_io_error(
        self,
        dashboard_tab: DashboardTab,
        temp_binary: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Export handles I/O errors gracefully."""
        dashboard_tab.load_binary(temp_binary)

        fake_dialog = FakeFileDialog("/invalid/path/file.json", "")
        fake_messagebox = FakeMessageBox()

        monkeypatch.setattr(
            "intellicrack.ui.tabs.project_workspace_tab.QFileDialog",
            fake_dialog,
        )
        monkeypatch.setattr(QMessageBox, "critical", fake_messagebox.critical)

        dashboard_tab.export_results()

        assert fake_messagebox.critical_called

    def test_clear_analysis_confirms_action(
        self,
        dashboard_tab: DashboardTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clear analysis requests confirmation."""
        fake_messagebox = FakeMessageBox()
        fake_messagebox.question_response = QMessageBox.StandardButton.No

        monkeypatch.setattr(QMessageBox, "question", fake_messagebox.question)

        dashboard_tab.clear_analysis()

        assert fake_messagebox.question_called

    def test_clear_analysis_resets_on_confirmation(
        self,
        dashboard_tab: DashboardTab,
        temp_binary: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clear analysis resets data when confirmed."""
        dashboard_tab.load_binary(temp_binary)

        fake_messagebox = FakeMessageBox()
        fake_messagebox.question_response = QMessageBox.StandardButton.Yes

        monkeypatch.setattr(QMessageBox, "question", fake_messagebox.question)

        dashboard_tab.clear_analysis()

        assert "No binary loaded" in dashboard_tab.binary_info_label.text()
        assert "Vulnerabilities Found: 0" in dashboard_tab.vulns_found_label.text()


class TestActivityLogging:
    """Test suite for activity logging functionality."""

    @pytest.fixture
    def dashboard_tab(self, qtbot: object) -> DashboardTab:
        """Create DashboardTab instance."""
        tab = DashboardTab()
        qtbot.addWidget(tab)
        return tab

    def test_log_activity_adds_message(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Log activity adds message to activity log."""
        initial_text = dashboard_tab.activity_log.toPlainText()
        dashboard_tab.log_activity("Test message")

        new_text = dashboard_tab.activity_log.toPlainText()
        assert len(new_text) > len(initial_text)
        assert "Test message" in new_text

    def test_log_activity_includes_timestamp(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Log activity includes timestamp."""
        dashboard_tab.log_activity("Test message")

        log_text = dashboard_tab.activity_log.toPlainText()
        assert ":" in log_text
        assert "Test message" in log_text

    def test_clear_activity_log_clears_content(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Clear activity log removes all content."""
        dashboard_tab.log_activity("Test message 1")
        dashboard_tab.log_activity("Test message 2")

        dashboard_tab.clear_activity_log()

        log_text = dashboard_tab.activity_log.toPlainText()
        assert len(log_text) == 0 or "Activity log cleared" in log_text


class TestFileFormatting:
    """Test suite for file size formatting."""

    @pytest.fixture
    def dashboard_tab(self, qtbot: object) -> DashboardTab:
        """Create DashboardTab instance."""
        tab = DashboardTab()
        qtbot.addWidget(tab)
        return tab

    def test_format_file_size_bytes(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Format file size handles bytes correctly."""
        result = dashboard_tab.format_file_size(512)
        assert "512" in result
        assert "B" in result

    def test_format_file_size_kilobytes(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Format file size handles kilobytes correctly."""
        result = dashboard_tab.format_file_size(2048)
        assert "KB" in result

    def test_format_file_size_megabytes(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Format file size handles megabytes correctly."""
        result = dashboard_tab.format_file_size(2 * 1024 * 1024)
        assert "MB" in result

    def test_format_file_size_gigabytes(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Format file size handles gigabytes correctly."""
        result = dashboard_tab.format_file_size(3 * 1024 * 1024 * 1024)
        assert "GB" in result

    def test_format_file_size_zero(
        self,
        dashboard_tab: DashboardTab,
    ) -> None:
        """Format file size handles zero bytes."""
        result = dashboard_tab.format_file_size(0)
        assert result == "0 B"
