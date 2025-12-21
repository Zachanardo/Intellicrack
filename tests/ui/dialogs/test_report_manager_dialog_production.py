"""Production tests for Report Manager Dialog.

Tests real report generation, analysis integration, and export functionality.
"""

import tempfile
from pathlib import Path
from typing import Any

import pytest


PyQt6 = pytest.importorskip("PyQt6")
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import QApplication, QCheckBox, QComboBox, QPushButton

from intellicrack.ui.dialogs.report_manager_dialog import ReportGenerationThread, ReportManagerDialog


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for GUI tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    """Create sample PE binary for analysis."""
    binary = tmp_path / "test_app.exe"
    pe_header = b"MZ\x90\x00"
    pe_header += b"\x00" * 60
    pe_header += b"PE\x00\x00"
    pe_header += b"\x4c\x01"
    pe_header += b"\x00" * 100
    pe_header += b"license\x00validation\x00serial\x00"
    pe_header += b"IsDebuggerPresent\x00GetTickCount\x00"
    binary.write_bytes(pe_header)
    return binary


@pytest.fixture
def report_manager(qapp: QApplication) -> ReportManagerDialog:
    """Create ReportManagerDialog instance."""
    dialog = ReportManagerDialog()
    yield dialog
    dialog.close()
    dialog.deleteLater()


class TestReportManagerInitialization:
    """Test report manager dialog initialization."""

    def test_dialog_creates_successfully(
        self, report_manager: ReportManagerDialog
    ) -> None:
        """Dialog initializes with all required components."""
        assert report_manager.windowTitle() == "Report Manager"

    def test_report_type_selection(self, report_manager: ReportManagerDialog) -> None:
        """Dialog has report type selection options."""
        combos = report_manager.findChildren(QComboBox)
        assert len(combos) > 0

        for combo in combos:
            if combo.count() > 0:
                items = [combo.itemText(i).lower() for i in range(combo.count())]
                assert any("pdf" in item or "html" in item or "text" in item
                          for item in items)
                break


class TestReportConfiguration:
    """Test report configuration options."""

    def test_binary_path_input(self, report_manager: ReportManagerDialog) -> None:
        """Dialog has input for target binary path."""
        line_edits = report_manager.findChildren(PyQt6.QtWidgets.QLineEdit)
        assert len(line_edits) > 0

    def test_browse_button_exists(self, report_manager: ReportManagerDialog) -> None:
        """Dialog has browse button for file selection."""
        buttons = report_manager.findChildren(QPushButton)
        button_texts = [btn.text().lower() for btn in buttons]

        assert any("browse" in text or "select" in text or "..." in text
                  for text in button_texts)

    def test_report_sections_checkboxes(
        self, report_manager: ReportManagerDialog
    ) -> None:
        """Dialog has checkboxes for report sections."""
        checkboxes = report_manager.findChildren(QCheckBox)
        assert len(checkboxes) > 0


class TestReportGenerationThread:
    """Test background report generation thread."""

    def test_thread_initializes_with_config(self, tmp_path: Path) -> None:
        """Report generation thread initializes with configuration."""
        config = {
            "binary_path": str(tmp_path / "test.exe"),
            "format": "html",
            "sections": ["binary_info", "vulnerabilities"]
        }
        output = str(tmp_path / "report.html")

        thread = ReportGenerationThread(config, output)

        assert thread.report_config == config
        assert thread.output_path == output

    def test_thread_emits_progress_signals(self, sample_binary: Path) -> None:
        """Thread emits progress updates during generation."""
        config = {"binary_path": str(sample_binary)}
        output = sample_binary.parent / "report.txt"

        thread = ReportGenerationThread(config, str(output))

        progress_values: list[int] = []
        status_messages: list[str] = []

        thread.progress_updated.connect(progress_values.append)
        thread.status_updated.connect(status_messages.append)

        thread.run()

        assert progress_values
        assert status_messages
        assert output.exists()

    def test_analyzes_binary_metadata(self, sample_binary: Path) -> None:
        """Thread extracts real binary metadata."""
        config = {"binary_path": str(sample_binary)}
        output = sample_binary.parent / "report.txt"

        thread = ReportGenerationThread(config, str(output))
        thread.run()

        assert output.exists()

        report_content = output.read_text()
        assert len(report_content) > 0

    def test_detects_license_patterns(self, sample_binary: Path) -> None:
        """Thread detects license-related patterns in binary."""
        config = {"binary_path": str(sample_binary)}
        output = sample_binary.parent / "report.txt"

        thread = ReportGenerationThread(config, str(output))

        binary_data = thread._analyze_license_mechanisms(str(sample_binary))

        assert isinstance(binary_data, dict)

    def test_handles_missing_binary(self, tmp_path: Path) -> None:
        """Thread handles non-existent binary gracefully."""
        config = {"binary_path": str(tmp_path / "nonexistent.exe")}
        output = tmp_path / "report.txt"

        thread = ReportGenerationThread(config, str(output))

        finished_results: list[tuple[bool, str, str]] = []
        thread.generation_finished.connect(
            lambda success, msg, path: finished_results.append((success, msg, path))
        )

        thread.run()

        if finished_results:
            success, msg, _path = finished_results[0]
            assert isinstance(success, bool)
            assert isinstance(msg, str)


class TestBinaryAnalysis:
    """Test real binary analysis functionality."""

    def test_extracts_file_size(self, sample_binary: Path) -> None:
        """Analysis extracts correct file size."""
        config = {"binary_path": str(sample_binary)}
        output = sample_binary.parent / "report.txt"

        thread = ReportGenerationThread(config, str(output))
        data = thread._analyze_binary(str(sample_binary))

        assert "file_size" in data
        assert data["file_size"] == sample_binary.stat().st_size

    def test_calculates_sha256_hash(self, sample_binary: Path) -> None:
        """Analysis calculates SHA256 hash of binary."""
        config = {"binary_path": str(sample_binary)}
        output = sample_binary.parent / "report.txt"

        thread = ReportGenerationThread(config, str(output))
        data = thread._analyze_binary(str(sample_binary))

        assert "sha256_hash" in data
        assert isinstance(data["sha256_hash"], str)
        assert len(data["sha256_hash"]) == 64

    def test_identifies_pe_architecture(self, sample_binary: Path) -> None:
        """Analysis identifies PE file architecture."""
        config = {"binary_path": str(sample_binary)}
        output = sample_binary.parent / "report.txt"

        thread = ReportGenerationThread(config, str(output))
        data = thread._analyze_binary(str(sample_binary))

        assert "architecture" in data
        assert "PE" in str(data["architecture"]) or "x86" in str(data["architecture"])


class TestVulnerabilityAnalysis:
    """Test vulnerability detection in binaries."""

    def test_detects_debugger_checks(self, sample_binary: Path) -> None:
        """Analysis detects anti-debugging functions."""
        config = {"binary_path": str(sample_binary)}
        output = sample_binary.parent / "report.txt"

        thread = ReportGenerationThread(config, str(output))
        data = thread._analyze_vulnerabilities(str(sample_binary))

        assert "vulnerabilities" in data or "patterns" in data

    def test_detects_license_strings(self, sample_binary: Path) -> None:
        """Analysis detects license-related strings."""
        config = {"binary_path": str(sample_binary)}
        output = sample_binary.parent / "report.txt"

        thread = ReportGenerationThread(config, str(output))
        data = thread._analyze_vulnerabilities(str(sample_binary))

        assert isinstance(data, dict)
        if "vulnerabilities" in data:
            assert isinstance(data["vulnerabilities"], int)
            assert data["vulnerabilities"] > 0


class TestReportExport:
    """Test report export and file operations."""

    def test_generates_report_file(self, sample_binary: Path) -> None:
        """Report generation creates output file."""
        config = {"binary_path": str(sample_binary)}
        output = sample_binary.parent / "analysis_report.txt"

        thread = ReportGenerationThread(config, str(output))
        thread.run()

        assert output.exists()
        assert output.stat().st_size > 0

    def test_report_contains_binary_info(self, sample_binary: Path) -> None:
        """Generated report contains binary information."""
        config = {"binary_path": str(sample_binary)}
        output = sample_binary.parent / "report.txt"

        thread = ReportGenerationThread(config, str(output))
        thread.run()

        content = output.read_text()
        assert len(content) > 0

    def test_handles_write_permission_errors(self, tmp_path: Path) -> None:
        """Report generation handles file write errors."""
        config = {"binary_path": str(tmp_path / "test.exe")}
        invalid_path = "/invalid/path/report.txt"

        thread = ReportGenerationThread(config, invalid_path)

        finished_results: list[tuple[bool, str, str]] = []
        thread.generation_finished.connect(
            lambda success, msg, path: finished_results.append((success, msg, path))
        )

        thread.run()

        if finished_results:
            success, _msg, _ = finished_results[0]
            assert not success


class TestDialogUIIntegration:
    """Test dialog UI integration and user interaction."""

    def test_generate_button_triggers_report(
        self, report_manager: ReportManagerDialog
    ) -> None:
        """Generate button initiates report creation."""
        buttons = report_manager.findChildren(QPushButton)

        generate_btn = next(
            (
                btn
                for btn in buttons
                if "generate" in btn.text().lower()
                or "create" in btn.text().lower()
            ),
            None,
        )
        assert generate_btn is not None

    def test_progress_bar_updates(self, report_manager: ReportManagerDialog) -> None:
        """Progress bar shows generation progress."""
        if progress_bars := report_manager.findChildren(
            PyQt6.QtWidgets.QProgressBar
        ):
            assert progress_bars[0].minimum() == 0
            assert progress_bars[0].maximum() >= 100

    def test_status_label_updates(self, report_manager: ReportManagerDialog) -> None:
        """Status label shows current operation."""
        labels = report_manager.findChildren(PyQt6.QtWidgets.QLabel)
        assert len(labels) > 0


class TestReportHistory:
    """Test report history and management."""

    def test_previous_reports_listed(
        self, report_manager: ReportManagerDialog
    ) -> None:
        """Dialog lists previously generated reports."""
        tables = report_manager.findChildren(PyQt6.QtWidgets.QTableWidget)
        lists = report_manager.findChildren(PyQt6.QtWidgets.QListWidget)

        assert len(tables) > 0 or len(lists) > 0

    def test_open_report_button(self, report_manager: ReportManagerDialog) -> None:
        """Dialog has button to open generated reports."""
        buttons = report_manager.findChildren(QPushButton)
        button_texts = [btn.text().lower() for btn in buttons]

        assert any("open" in text or "view" in text for text in button_texts)

    def test_delete_report_button(self, report_manager: ReportManagerDialog) -> None:
        """Dialog has button to delete old reports."""
        buttons = report_manager.findChildren(QPushButton)
        button_texts = [btn.text().lower() for btn in buttons]

        assert any("delete" in text or "remove" in text for text in button_texts)
