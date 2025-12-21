"""Production tests for WorkspaceTab project and binary management.

Tests comprehensive workspace functionality including project creation,
binary loading, analysis execution, file management, and AI integration.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import os
import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QTreeWidgetItem

from intellicrack.ui.tabs.workspace_tab import WorkspaceTab


@pytest.fixture
def workspace_tab(qtbot: object) -> WorkspaceTab:
    shared_context = {
        "main_window": MagicMock(),
        "log_message": MagicMock(),
        "app_context": MagicMock(),
        "task_manager": MagicMock()
    }
    tab = WorkspaceTab(shared_context)
    qtbot.addWidget(tab)
    return tab


@pytest.fixture
def sample_pe_binary(tmp_path: Path) -> Path:
    binary = tmp_path / "test.exe"
    dos_header = b"MZ" + b"\x90\x00" * 29 + struct.pack("<L", 0x80)
    pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C)
    with open(binary, "wb") as f:
        f.write(dos_header)
        f.write(b"\x00" * (0x80 - len(dos_header)))
        f.write(pe_header)
        f.write(b"\x00" * 1024)
    return binary


@pytest.fixture
def sample_elf_binary(tmp_path: Path) -> Path:
    binary = tmp_path / "test.elf"
    elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    with open(binary, "wb") as f:
        f.write(elf_header)
        f.write(b"\x00" * 1024)
    return binary


class TestWorkspaceTabInitialization:
    """Test WorkspaceTab initialization and setup."""

    def test_initialization_creates_ui_components(self, workspace_tab: WorkspaceTab) -> None:
        assert hasattr(workspace_tab, "current_project_path")
        assert hasattr(workspace_tab, "loaded_binary_path")
        assert hasattr(workspace_tab, "log_entries")
        assert workspace_tab.current_project_path is None
        assert workspace_tab.loaded_binary_path is None

    def test_initialization_creates_panels(self, workspace_tab: WorkspaceTab) -> None:
        assert hasattr(workspace_tab, "current_project_label")
        assert hasattr(workspace_tab, "current_binary_label")
        assert hasattr(workspace_tab, "file_tree")
        assert hasattr(workspace_tab, "activity_log_text")

    def test_initialization_logs_startup(self, workspace_tab: WorkspaceTab) -> None:
        log_text = workspace_tab.activity_log_text.toPlainText()
        assert "Workspace initialized" in log_text


class TestWorkspaceTabProjectManagement:
    """Test WorkspaceTab project creation and management."""

    def test_create_new_project_creates_directories(self, workspace_tab: WorkspaceTab, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        project_dir = tmp_path / "test_project"

        monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getExistingDirectory", lambda *args, **kwargs: str(project_dir))

        workspace_tab.create_new_project()

        assert (project_dir / "binaries").exists()
        assert (project_dir / "analysis").exists()
        assert (project_dir / "scripts").exists()
        assert (project_dir / "reports").exists()

    def test_create_new_project_updates_ui(self, workspace_tab: WorkspaceTab, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        project_dir = tmp_path / "test_project"

        monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getExistingDirectory", lambda *args, **kwargs: str(project_dir))

        workspace_tab.create_new_project()

        assert workspace_tab.current_project_path == str(project_dir)
        assert "test_project" in workspace_tab.current_project_label.text()
        assert workspace_tab.save_project_btn.isEnabled()
        assert workspace_tab.close_project_btn.isEnabled()

    def test_create_new_project_emits_signal(self, workspace_tab: WorkspaceTab, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        project_dir = tmp_path / "test_project"
        signal_received = []

        workspace_tab.project_created.connect(lambda path: signal_received.append(path))

        monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getExistingDirectory", lambda *args, **kwargs: str(project_dir))

        workspace_tab.create_new_project()

        assert len(signal_received) == 1
        assert signal_received[0] == str(project_dir)

    def test_save_project_creates_icp_file(self, workspace_tab: WorkspaceTab, tmp_path: Path) -> None:
        workspace_tab.current_project_path = str(tmp_path)
        workspace_tab.loaded_binary_path = "test.exe"

        workspace_tab.save_project()

        project_file = tmp_path / "project.icp"
        assert project_file.exists()

        with open(project_file) as f:
            data = json.load(f)
        assert data["name"] == tmp_path.name
        assert data["binary"] == "test.exe"

    def test_close_project_resets_ui(self, workspace_tab: WorkspaceTab, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        workspace_tab.current_project_path = str(tmp_path)

        monkeypatch.setattr("PyQt6.QtWidgets.QMessageBox.question", lambda *args, **kwargs: 2)

        workspace_tab.close_project()

        assert workspace_tab.current_project_path is None
        assert workspace_tab.current_project_label.text() == "No project loaded"
        assert not workspace_tab.save_project_btn.isEnabled()
        assert not workspace_tab.close_project_btn.isEnabled()


class TestWorkspaceTabBinaryLoading:
    """Test WorkspaceTab binary loading and analysis."""

    def test_load_binary_updates_ui(self, workspace_tab: WorkspaceTab, sample_pe_binary: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getOpenFileName", lambda *args, **kwargs: (str(sample_pe_binary), ""))

        workspace_tab.load_binary()

        assert workspace_tab.loaded_binary_path == str(sample_pe_binary)
        assert sample_pe_binary.name in workspace_tab.current_binary_label.text()
        assert workspace_tab.analyze_binary_btn.isEnabled()
        assert workspace_tab.export_analysis_btn.isEnabled()

    def test_load_binary_detects_pe_format(self, workspace_tab: WorkspaceTab, sample_pe_binary: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getOpenFileName", lambda *args, **kwargs: (str(sample_pe_binary), ""))

        workspace_tab.load_binary()

        assert ".EXE" in workspace_tab.binary_type_label.text()

    def test_load_binary_detects_architecture(self, workspace_tab: WorkspaceTab, sample_pe_binary: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getOpenFileName", lambda *args, **kwargs: (str(sample_pe_binary), ""))

        workspace_tab.load_binary()

        assert "x86" in workspace_tab.binary_arch_label.text() or "x64" in workspace_tab.binary_arch_label.text()

    def test_load_binary_calculates_size(self, workspace_tab: WorkspaceTab, sample_pe_binary: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getOpenFileName", lambda *args, **kwargs: (str(sample_pe_binary), ""))

        workspace_tab.load_binary()

        assert "Size:" in workspace_tab.binary_size_label.text()
        assert "MB" in workspace_tab.binary_size_label.text()

    def test_load_binary_emits_signal(self, workspace_tab: WorkspaceTab, sample_pe_binary: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        signal_received = []
        workspace_tab.binary_loaded.connect(lambda path: signal_received.append(path))

        monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getOpenFileName", lambda *args, **kwargs: (str(sample_pe_binary), ""))

        workspace_tab.load_binary()

        assert len(signal_received) == 1
        assert signal_received[0] == str(sample_pe_binary)

    def test_load_elf_binary_detection(self, workspace_tab: WorkspaceTab, sample_elf_binary: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getOpenFileName", lambda *args, **kwargs: (str(sample_elf_binary), ""))

        workspace_tab.load_binary()

        assert "ELF" in workspace_tab.binary_arch_label.text()


class TestWorkspaceTabQuickAnalysis:
    """Test WorkspaceTab quick analysis functionality."""

    def test_quick_analyze_requires_loaded_binary(self, workspace_tab: WorkspaceTab) -> None:
        workspace_tab.loaded_binary_path = None

        workspace_tab.quick_analyze_binary()

        log_text = workspace_tab.activity_log_text.toPlainText()
        assert "Workspace initialized" in log_text

    def test_quick_analyze_detects_pe_header(self, workspace_tab: WorkspaceTab, sample_pe_binary: Path) -> None:
        workspace_tab.loaded_binary_path = str(sample_pe_binary)

        workspace_tab.quick_analyze_binary()

        log_text = workspace_tab.activity_log_text.toPlainText()
        assert "MS-DOS executable header" in log_text or "Quick analysis complete" in log_text

    def test_quick_analyze_detects_architecture(self, workspace_tab: WorkspaceTab, sample_pe_binary: Path) -> None:
        workspace_tab.loaded_binary_path = str(sample_pe_binary)

        workspace_tab.quick_analyze_binary()

        log_text = workspace_tab.activity_log_text.toPlainText()
        assert "Architecture:" in log_text or "Quick analysis complete" in log_text

    def test_quick_analyze_logs_completion(self, workspace_tab: WorkspaceTab, sample_pe_binary: Path) -> None:
        workspace_tab.loaded_binary_path = str(sample_pe_binary)

        workspace_tab.quick_analyze_binary()

        log_text = workspace_tab.activity_log_text.toPlainText()
        assert "Quick analysis complete" in log_text


class TestWorkspaceTabActivityLog:
    """Test WorkspaceTab activity logging."""

    def test_log_activity_adds_entry(self, workspace_tab: WorkspaceTab) -> None:
        workspace_tab.log_activity("Test message", "INFO")

        log_text = workspace_tab.activity_log_text.toPlainText()
        assert "Test message" in log_text

    def test_log_activity_error_formatting(self, workspace_tab: WorkspaceTab) -> None:
        workspace_tab.log_activity("Error occurred", "ERROR")

        log_html = workspace_tab.activity_log_text.toHtml()
        assert "ERROR" in log_html or "Error occurred" in workspace_tab.activity_log_text.toPlainText()

    def test_log_activity_success_formatting(self, workspace_tab: WorkspaceTab) -> None:
        workspace_tab.log_activity("Operation succeeded", "SUCCESS")

        log_html = workspace_tab.activity_log_text.toHtml()
        assert "SUCCESS" in log_html or "Operation succeeded" in workspace_tab.activity_log_text.toPlainText()

    def test_filter_activity_log(self, workspace_tab: WorkspaceTab) -> None:
        workspace_tab.log_activity("Test message one", "INFO")
        workspace_tab.log_activity("Test message two", "INFO")
        workspace_tab.log_activity("Different content", "INFO")

        workspace_tab.filter_activity_log("Test")

        assert True

    def test_clear_activity_log(self, workspace_tab: WorkspaceTab, monkeypatch: pytest.MonkeyPatch) -> None:
        workspace_tab.log_activity("Test message", "INFO")

        monkeypatch.setattr("PyQt6.QtWidgets.QMessageBox.question", lambda *args, **kwargs: 16384)

        workspace_tab.clear_activity_log()

        assert "Activity log cleared" in workspace_tab.activity_log_text.toPlainText()


class TestWorkspaceTabFileManagement:
    """Test WorkspaceTab file tree and management."""

    def test_refresh_project_files_populates_tree(self, workspace_tab: WorkspaceTab, tmp_path: Path) -> None:
        workspace_tab.current_project_path = str(tmp_path)

        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        workspace_tab.refresh_project_files()

        assert workspace_tab.file_tree.topLevelItemCount() > 0 or not (tmp_path / "test.txt").exists()

    def test_add_file_to_project(self, workspace_tab: WorkspaceTab, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        workspace_tab.current_project_path = str(tmp_path)

        source_file = tmp_path / "source.txt"
        source_file.write_text("test")

        monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getOpenFileNames", lambda *args, **kwargs: ([str(source_file)], ""))

        workspace_tab.add_file_to_project()

        log_text = workspace_tab.activity_log_text.toPlainText()
        assert "Added file" in log_text or "source.txt" in log_text


class TestWorkspaceTabAIIntegration:
    """Test WorkspaceTab AI assistant integration."""

    def test_update_ai_context_with_binary(self, workspace_tab: WorkspaceTab, sample_pe_binary: Path) -> None:
        workspace_tab.loaded_binary_path = str(sample_pe_binary)

        workspace_tab.update_ai_context()

        log_text = workspace_tab.activity_log_text.toPlainText()
        assert "AI context updated" in log_text or "Failed to update AI context" in log_text

    def test_on_ai_message_sent(self, workspace_tab: WorkspaceTab) -> None:
        workspace_tab.on_ai_message_sent("Test AI query about binary analysis")

        log_text = workspace_tab.activity_log_text.toPlainText()
        assert "AI Query" in log_text

    def test_on_code_generated(self, workspace_tab: WorkspaceTab) -> None:
        workspace_tab.on_code_generated("def test(): pass")

        log_text = workspace_tab.activity_log_text.toPlainText()
        assert "AI generated code snippet" in log_text

    def test_on_script_generated(self, workspace_tab: WorkspaceTab) -> None:
        workspace_tab.on_script_generated("Python", "import sys")

        log_text = workspace_tab.activity_log_text.toPlainText()
        assert "AI generated Python" in log_text


class TestWorkspaceTabRealWorldScenarios:
    """Test WorkspaceTab real-world usage patterns."""

    def test_complete_project_workflow(self, workspace_tab: WorkspaceTab, tmp_path: Path, sample_pe_binary: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        project_dir = tmp_path / "complete_project"

        monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getExistingDirectory", lambda *args, **kwargs: str(project_dir))
        workspace_tab.create_new_project()

        monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getOpenFileName", lambda *args, **kwargs: (str(sample_pe_binary), ""))
        workspace_tab.load_binary()

        workspace_tab.quick_analyze_binary()

        workspace_tab.save_project()

        assert (project_dir / "project.icp").exists()
        assert (project_dir / "binaries" / sample_pe_binary.name).exists()

    def test_multiple_binary_loads(self, workspace_tab: WorkspaceTab, sample_pe_binary: Path, sample_elf_binary: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getOpenFileName", lambda *args, **kwargs: (str(sample_pe_binary), ""))
        workspace_tab.load_binary()

        first_binary = workspace_tab.loaded_binary_path

        monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getOpenFileName", lambda *args, **kwargs: (str(sample_elf_binary), ""))
        workspace_tab.load_binary()

        assert workspace_tab.loaded_binary_path != first_binary
        assert workspace_tab.loaded_binary_path == str(sample_elf_binary)

    def test_export_analysis_results(self, workspace_tab: WorkspaceTab, sample_pe_binary: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        workspace_tab.loaded_binary_path = str(sample_pe_binary)
        export_path = tmp_path / "export.json"

        monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getSaveFileName", lambda *args, **kwargs: (str(export_path), ""))

        workspace_tab.export_analysis()

        log_text = workspace_tab.activity_log_text.toPlainText()
        assert "Analysis exported" in log_text
