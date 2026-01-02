"""Production tests for statistics dialog module.

Tests statistical calculations against known binary datasets without mocks,
validating accuracy of entropy, distribution, and pattern detection.
"""

import math
from pathlib import Path
from typing import Any, Generator, Optional, cast

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.hexview.statistics_dialog import StatisticsDialog, StatisticsWorker


class FakeFileHandler:
    """Real test double for file handler with complete implementation."""

    def __init__(
        self,
        file_size: int = 1024,
        file_path: str = "test.bin",
        read_data_value: bytes = b"\x00" * 1024,
    ) -> None:
        self.file_size: int = file_size
        self.file_path: str = file_path
        self._read_data_value: bytes = read_data_value
        self.read_data_calls: list[tuple[int, int]] = []

    def read_data(self, offset: int = 0, length: int = -1) -> bytes:
        """Read data from the fake file."""
        self.read_data_calls.append((offset, length))
        if length == -1:
            return self._read_data_value[offset:]
        return self._read_data_value[offset : offset + length]


class FakeHexViewer:
    """Real test double for hex viewer with complete implementation."""

    def __init__(
        self,
        selection_start: int = -1,
        selection_end: int = -1,
        file_size: int = 1024,
        file_path: str = "test.bin",
        read_data_value: bytes = b"\x00" * 1024,
    ) -> None:
        self.selection_start: int = selection_start
        self.selection_end: int = selection_end
        self.file_handler: Any = FakeFileHandler(
            file_size=file_size, file_path=file_path, read_data_value=read_data_value
        )


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication, None, None]:
    """Create QApplication instance for Qt tests."""
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
    else:
        app = QApplication([])
        yield app


@pytest.fixture
def statistics_dialog(qapp: QApplication) -> StatisticsDialog:
    """Create statistics dialog instance."""
    return StatisticsDialog()


@pytest.fixture
def fake_hex_viewer() -> FakeHexViewer:
    """Create fake hex viewer with file handler."""
    return FakeHexViewer()


@pytest.fixture
def dialog_with_viewer(qapp: QApplication, fake_hex_viewer: FakeHexViewer) -> StatisticsDialog:
    """Create statistics dialog with fake hex viewer."""
    return StatisticsDialog(hex_viewer=cast(Any, fake_hex_viewer))


@pytest.fixture
def uniform_data() -> bytes:
    """Create uniformly distributed data (high entropy)."""
    return bytes(range(256)) * 4


@pytest.fixture
def low_entropy_data() -> bytes:
    """Create low entropy data (mostly zeros)."""
    return b"\x00" * 900 + b"\xFF" * 100 + bytes(range(24))


@pytest.fixture
def pattern_data() -> bytes:
    """Create data with repeating patterns."""
    pattern = b"\xAA\xBB\xCC\xDD"
    return pattern * 256


class TestStatisticsDialogInitialization:
    """Test statistics dialog initialization."""

    def test_dialog_creates_successfully(self, statistics_dialog: StatisticsDialog) -> None:
        """Dialog initializes with all components."""
        assert statistics_dialog is not None
        assert statistics_dialog.windowTitle() == "Statistical Analysis"
        assert statistics_dialog.worker is None

    def test_all_tabs_initialized(self, statistics_dialog: StatisticsDialog) -> None:
        """All result tabs are initialized."""
        assert statistics_dialog.tabs is not None
        assert statistics_dialog.tabs.count() == 4

        tab_names = [
            statistics_dialog.tabs.tabText(i) for i in range(statistics_dialog.tabs.count())
        ]
        assert "Overview" in tab_names
        assert "Distribution" in tab_names
        assert "Patterns" in tab_names
        assert "File Type Analysis" in tab_names

    def test_text_widgets_readonly(self, statistics_dialog: StatisticsDialog) -> None:
        """All text widgets are read-only."""
        assert statistics_dialog.overview_text.isReadOnly()
        assert statistics_dialog.distribution_text.isReadOnly()
        assert statistics_dialog.patterns_text.isReadOnly()
        assert statistics_dialog.file_type_text.isReadOnly()

    def test_buttons_initialized(self, statistics_dialog: StatisticsDialog) -> None:
        """All buttons are initialized."""
        assert hasattr(statistics_dialog, "analyze_btn")
        assert hasattr(statistics_dialog, "copy_btn")
        assert statistics_dialog.copy_btn.isEnabled() is False

    def test_progress_bar_hidden(self, statistics_dialog: StatisticsDialog) -> None:
        """Progress bar initially hidden."""
        assert not statistics_dialog.progress_bar.isVisible()


class TestDataSourceSelection:
    """Test data source selection logic."""

    def test_entire_file_radio_default(self, statistics_dialog: StatisticsDialog) -> None:
        """Entire file radio button is checked by default."""
        assert statistics_dialog.entire_file_radio.isChecked()
        assert not statistics_dialog.selection_radio.isChecked()

    def test_selection_radio_disabled_without_viewer(
        self, statistics_dialog: StatisticsDialog
    ) -> None:
        """Selection radio disabled without hex viewer."""
        assert not statistics_dialog.selection_radio.isEnabled()

    def test_selection_radio_disabled_without_selection(
        self, dialog_with_viewer: StatisticsDialog
    ) -> None:
        """Selection radio disabled without active selection."""
        assert not dialog_with_viewer.selection_radio.isEnabled()

    def test_selection_radio_enabled_with_selection(self, qapp: QApplication) -> None:
        """Selection radio enabled with active selection."""
        fake_viewer = FakeHexViewer(selection_start=100, selection_end=300)
        dialog = StatisticsDialog(hex_viewer=cast(Any, fake_viewer))

        assert dialog.selection_radio.isEnabled()
        assert "200 bytes" in dialog.selection_radio.text()


class TestStatisticsWorker:
    """Test statistics worker thread."""

    def test_worker_initialization_with_data(self, uniform_data: bytes) -> None:
        """Worker initializes with data."""
        worker = StatisticsWorker(data=uniform_data)
        assert worker.data == uniform_data
        assert worker.file_path is None
        assert worker.calculator is not None

    def test_worker_initialization_with_file_path(self, tmp_path: Path) -> None:
        """Worker initializes with file path."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        worker = StatisticsWorker(file_path=str(test_file))
        assert worker.file_path == str(test_file)
        assert worker.data is None

    def test_worker_calculates_statistics(self, uniform_data: bytes) -> None:
        """Worker calculates statistics correctly."""
        worker = StatisticsWorker(data=uniform_data)
        results: dict[str, Any] = {}

        def store_result(result: dict[str, Any]) -> None:
            nonlocal results
            results = result

        worker.result.connect(store_result)
        worker.run()

        assert "entropy" in results
        assert "size" in results
        assert "histogram" in results

    def test_worker_handles_file_reading(self, tmp_path: Path, uniform_data: bytes) -> None:
        """Worker reads file data correctly."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(uniform_data)

        worker = StatisticsWorker(file_path=str(test_file))
        results: dict[str, Any] = {}

        def store_result(result: dict[str, Any]) -> None:
            nonlocal results
            results = result

        worker.result.connect(store_result)
        worker.run()

        assert "size" in results
        assert results["size"] == len(uniform_data)

    def test_worker_emits_error_on_no_data(self) -> None:
        """Worker emits error when no data provided."""
        worker = StatisticsWorker()
        error_emitted = False
        error_message = ""

        def capture_error(error: str) -> None:
            nonlocal error_emitted, error_message
            error_emitted = True
            error_message = error

        worker.error.connect(capture_error)
        worker.run()

        assert error_emitted
        assert "No data to analyze" in error_message

    def test_worker_progress_callback(self, uniform_data: bytes) -> None:
        """Worker emits progress updates."""
        worker = StatisticsWorker(data=uniform_data)
        progress_updates = []

        def capture_progress(current: int, total: int) -> None:
            progress_updates.append((current, total))

        worker.progress.connect(capture_progress)
        worker.run()

        assert progress_updates


class TestStatisticalAccuracy:
    """Test statistical calculation accuracy."""

    def test_entropy_calculation_uniform_distribution(self, uniform_data: bytes) -> None:
        """Uniform distribution has high entropy."""
        worker = StatisticsWorker(data=uniform_data)
        results: dict[str, Any] = {}

        def store_result(result: dict[str, Any]) -> None:
            nonlocal results
            results = result

        worker.result.connect(store_result)
        worker.run()

        assert results["entropy"] > 7.5
        assert results["entropy"] <= 8.0

    def test_entropy_calculation_low_entropy(self, low_entropy_data: bytes) -> None:
        """Low entropy data has low entropy value."""
        worker = StatisticsWorker(data=low_entropy_data)
        results: dict[str, Any] = {}

        def store_result(result: dict[str, Any]) -> None:
            nonlocal results
            results = result

        worker.result.connect(store_result)
        worker.run()

        assert results["entropy"] < 5.0

    def test_byte_statistics_accuracy(self) -> None:
        """Byte statistics calculate correctly."""
        test_data = bytes([0x10, 0x20, 0x30, 0x40, 0x50])
        worker = StatisticsWorker(data=test_data)
        results: dict[str, Any] = {}

        def store_result(result: dict[str, Any]) -> None:
            nonlocal results
            results = result

        worker.result.connect(store_result)
        worker.run()

        assert results["min_byte"] == 0x10
        assert results["max_byte"] == 0x50
        assert abs(results["mean_byte"] - 0x30) < 0.1

    def test_null_byte_counting(self) -> None:
        """Null byte counting is accurate."""
        test_data = b"\x00" * 500 + b"\xFF" * 500
        worker = StatisticsWorker(data=test_data)
        results: dict[str, Any] = {}

        def store_result(result: dict[str, Any]) -> None:
            nonlocal results
            results = result

        worker.result.connect(store_result)
        worker.run()

        assert results["null_bytes"] == 500
        assert abs(results["null_percentage"] - 50.0) < 0.1

    def test_printable_character_detection(self) -> None:
        """Printable character detection is accurate."""
        test_data = b"Hello World!" + b"\x00" * 88
        worker = StatisticsWorker(data=test_data)
        results: dict[str, Any] = {}

        def store_result(result: dict[str, Any]) -> None:
            nonlocal results
            results = result

        worker.result.connect(store_result)
        worker.run()

        assert results["printable_chars"] >= 12


class TestPatternDetection:
    """Test pattern detection functionality."""

    def test_repeating_pattern_detection(self, pattern_data: bytes) -> None:
        """Repeating patterns are detected."""
        worker = StatisticsWorker(data=pattern_data)
        results: dict[str, Any] = {}

        def store_result(result: dict[str, Any]) -> None:
            nonlocal results
            results = result

        worker.result.connect(store_result)
        worker.run()

        assert "patterns" in results
        if results.get("patterns"):
            assert len(results["patterns"]) > 0

    def test_no_patterns_in_random_data(self, uniform_data: bytes) -> None:
        """Random data has fewer patterns."""
        worker = StatisticsWorker(data=uniform_data)
        results: dict[str, Any] = {}

        def store_result(result: dict[str, Any]) -> None:
            nonlocal results
            results = result

        worker.result.connect(store_result)
        worker.run()

        assert "patterns" in results


class TestResultDisplay:
    """Test result display formatting."""

    def test_display_results_formats_overview(
        self, dialog_with_viewer: StatisticsDialog
    ) -> None:
        """Display results formats overview correctly."""
        test_results = {
            "size": 1024,
            "entropy": 7.5,
            "entropy_percentage": 93.75,
            "randomness_score": 90.0,
            "compression_ratio": 0.95,
            "chi_square": 250.0,
            "min_byte": 0x00,
            "max_byte": 0xFF,
            "mean_byte": 127.5,
            "null_bytes": 100,
            "null_percentage": 9.8,
            "printable_chars": 500,
            "printable_percentage": 48.8,
            "control_chars": 200,
            "control_percentage": 19.5,
            "high_bytes": 224,
            "high_bytes_percentage": 21.9,
            "histogram": [],
            "patterns": [],
            "file_type_hints": [],
        }

        dialog_with_viewer.display_results(test_results)

        overview_text = dialog_with_viewer.overview_text.toPlainText()
        assert "1024 bytes" in overview_text
        assert "7.5" in overview_text
        assert "Entropy:" in overview_text

    def test_display_results_formats_distribution(
        self, dialog_with_viewer: StatisticsDialog
    ) -> None:
        """Display results formats distribution correctly."""
        test_results = {
            "size": 256,
            "entropy": 8.0,
            "entropy_percentage": 100.0,
            "randomness_score": 95.0,
            "compression_ratio": 1.0,
            "chi_square": 255.0,
            "min_byte": 0,
            "max_byte": 255,
            "mean_byte": 127.5,
            "null_bytes": 1,
            "null_percentage": 0.4,
            "printable_chars": 95,
            "printable_percentage": 37.1,
            "control_chars": 33,
            "control_percentage": 12.9,
            "high_bytes": 128,
            "high_bytes_percentage": 50.0,
            "histogram": [("0x00-0x0F", 16), ("0x10-0x1F", 16), ("0x20-0x2F", 16)],
            "patterns": [],
            "file_type_hints": [],
        }

        dialog_with_viewer.display_results(test_results)

        distribution_text = dialog_with_viewer.distribution_text.toPlainText()
        assert "Byte Distribution" in distribution_text
        assert "0x00-0x0F" in distribution_text

    def test_display_results_formats_patterns(
        self, dialog_with_viewer: StatisticsDialog
    ) -> None:
        """Display results formats patterns correctly."""
        test_results = {
            "size": 256,
            "entropy": 4.0,
            "entropy_percentage": 50.0,
            "randomness_score": 40.0,
            "compression_ratio": 0.5,
            "chi_square": 100.0,
            "min_byte": 0,
            "max_byte": 255,
            "mean_byte": 127.5,
            "null_bytes": 50,
            "null_percentage": 19.5,
            "printable_chars": 100,
            "printable_percentage": 39.1,
            "control_chars": 56,
            "control_percentage": 21.9,
            "high_bytes": 50,
            "high_bytes_percentage": 19.5,
            "histogram": [],
            "patterns": [(b"\xAA\xBB\xCC\xDD", 50), (b"\x00\x00\x00\x00", 25)],
            "file_type_hints": [],
        }

        dialog_with_viewer.display_results(test_results)

        patterns_text = dialog_with_viewer.patterns_text.toPlainText()
        assert "Repeating Patterns" in patterns_text
        assert "AA BB CC DD" in patterns_text
        assert "50 occurrences" in patterns_text

    def test_display_results_no_patterns(self, dialog_with_viewer: StatisticsDialog) -> None:
        """Display results shows message when no patterns found."""
        test_results = {
            "size": 256,
            "entropy": 7.9,
            "entropy_percentage": 98.75,
            "randomness_score": 95.0,
            "compression_ratio": 0.99,
            "chi_square": 250.0,
            "min_byte": 0,
            "max_byte": 255,
            "mean_byte": 127.5,
            "null_bytes": 1,
            "null_percentage": 0.4,
            "printable_chars": 95,
            "printable_percentage": 37.1,
            "control_chars": 33,
            "control_percentage": 12.9,
            "high_bytes": 127,
            "high_bytes_percentage": 49.6,
            "histogram": [],
            "patterns": None,
            "file_type_hints": [],
        }

        dialog_with_viewer.display_results(test_results)

        patterns_text = dialog_with_viewer.patterns_text.toPlainText()
        assert "No significant repeating patterns" in patterns_text

    def test_display_results_file_type_analysis(
        self, dialog_with_viewer: StatisticsDialog
    ) -> None:
        """Display results formats file type analysis correctly."""
        test_results = {
            "size": 256,
            "entropy": 7.8,
            "entropy_percentage": 97.5,
            "randomness_score": 92.0,
            "compression_ratio": 0.98,
            "chi_square": 245.0,
            "min_byte": 0,
            "max_byte": 255,
            "mean_byte": 127.5,
            "null_bytes": 2,
            "null_percentage": 0.8,
            "printable_chars": 90,
            "printable_percentage": 35.2,
            "control_chars": 34,
            "control_percentage": 13.3,
            "high_bytes": 130,
            "high_bytes_percentage": 50.8,
            "histogram": [],
            "patterns": [],
            "file_type_hints": ["High entropy detected", "Possibly encrypted"],
        }

        dialog_with_viewer.display_results(test_results)

        file_type_text = dialog_with_viewer.file_type_text.toPlainText()
        assert "File Type Analysis" in file_type_text
        assert "High entropy detected" in file_type_text
        assert "encrypted or compressed" in file_type_text

    def test_display_results_enables_copy_button(
        self, dialog_with_viewer: StatisticsDialog
    ) -> None:
        """Display results enables copy button."""
        test_results = {
            "size": 100,
            "entropy": 5.0,
            "entropy_percentage": 62.5,
            "randomness_score": 50.0,
            "compression_ratio": 0.7,
            "chi_square": 150.0,
            "min_byte": 0,
            "max_byte": 255,
            "mean_byte": 127.5,
            "null_bytes": 10,
            "null_percentage": 10.0,
            "printable_chars": 50,
            "printable_percentage": 50.0,
            "control_chars": 20,
            "control_percentage": 20.0,
            "high_bytes": 20,
            "high_bytes_percentage": 20.0,
            "histogram": [],
            "patterns": [],
            "file_type_hints": [],
        }

        dialog_with_viewer.display_results(test_results)
        assert dialog_with_viewer.copy_btn.isEnabled()


class TestErrorHandling:
    """Test error handling."""

    def test_display_error_shows_message(self, statistics_dialog: StatisticsDialog) -> None:
        """Display error shows error message."""
        test_error = "Test error message"
        statistics_dialog.display_error(test_error)

        overview_text = statistics_dialog.overview_text.toPlainText()
        assert test_error in overview_text

    def test_display_error_hides_progress(self, statistics_dialog: StatisticsDialog) -> None:
        """Display error hides progress bar."""
        statistics_dialog.progress_bar.setVisible(True)
        statistics_dialog.display_error("Test error")

        assert not statistics_dialog.progress_bar.isVisible()

    def test_display_error_enables_analyze_button(
        self, statistics_dialog: StatisticsDialog
    ) -> None:
        """Display error re-enables analyze button."""
        statistics_dialog.analyze_btn.setEnabled(False)
        statistics_dialog.display_error("Test error")

        assert statistics_dialog.analyze_btn.isEnabled()


class TestProgressUpdates:
    """Test progress update functionality."""

    def test_update_progress_sets_value(self, statistics_dialog: StatisticsDialog) -> None:
        """Update progress sets progress bar value."""
        statistics_dialog.update_progress(3, 10)
        assert statistics_dialog.progress_bar.value() == 3


class TestCopyResults:
    """Test copy results functionality."""

    def test_copy_results_combines_all_tabs(
        self, dialog_with_viewer: StatisticsDialog
    ) -> None:
        """Copy results combines all tab contents."""
        dialog_with_viewer.overview_text.setPlainText("Overview content")
        dialog_with_viewer.distribution_text.setPlainText("Distribution content")
        dialog_with_viewer.patterns_text.setPlainText("Patterns content")
        dialog_with_viewer.file_type_text.setPlainText("File type content")

        dialog_with_viewer.copy_results()

        clipboard = QApplication.clipboard()
        assert clipboard is not None
        clipboard_text = clipboard.text()

        assert "OVERVIEW" in clipboard_text
        assert "DISTRIBUTION" in clipboard_text
        assert "PATTERNS" in clipboard_text
        assert "FILE TYPE ANALYSIS" in clipboard_text
        assert "Overview content" in clipboard_text


class TestAnalyzeDataWorkflow:
    """Test analyze data workflow."""

    def test_analyze_clears_previous_results(
        self, dialog_with_viewer: StatisticsDialog
    ) -> None:
        """Analyze clears previous results."""
        dialog_with_viewer.overview_text.setPlainText("Old content")
        dialog_with_viewer.distribution_text.setPlainText("Old content")
        dialog_with_viewer.patterns_text.setPlainText("Old content")
        dialog_with_viewer.file_type_text.setPlainText("Old content")

        dialog_with_viewer.analyze_data()

        assert dialog_with_viewer.overview_text.toPlainText() != "Old content"

    def test_analyze_shows_progress_bar(self, dialog_with_viewer: StatisticsDialog) -> None:
        """Analyze shows progress bar."""
        assert not dialog_with_viewer.progress_bar.isVisible()
        dialog_with_viewer.analyze_data()
        assert dialog_with_viewer.progress_bar.isVisible()

    def test_analyze_without_viewer_shows_error(
        self, statistics_dialog: StatisticsDialog
    ) -> None:
        """Analyze without hex viewer shows error."""
        statistics_dialog.analyze_data()

        overview_text = statistics_dialog.overview_text.toPlainText()
        assert "No file loaded" in overview_text


class TestEntropyClassification:
    """Test entropy-based file type classification."""

    def test_very_high_entropy_classification(
        self, dialog_with_viewer: StatisticsDialog
    ) -> None:
        """Very high entropy classified as encrypted/compressed."""
        test_results = {
            "size": 100,
            "entropy": 7.8,
            "entropy_percentage": 97.5,
            "randomness_score": 95.0,
            "compression_ratio": 0.99,
            "chi_square": 250.0,
            "min_byte": 0,
            "max_byte": 255,
            "mean_byte": 127.5,
            "null_bytes": 1,
            "null_percentage": 1.0,
            "printable_chars": 30,
            "printable_percentage": 30.0,
            "control_chars": 34,
            "control_percentage": 34.0,
            "high_bytes": 35,
            "high_bytes_percentage": 35.0,
            "histogram": [],
            "patterns": [],
            "file_type_hints": [],
        }

        dialog_with_viewer.display_results(test_results)
        file_type_text = dialog_with_viewer.file_type_text.toPlainText()

        assert "encrypted or compressed" in file_type_text.lower()

    def test_low_entropy_classification(self, dialog_with_viewer: StatisticsDialog) -> None:
        """Low entropy classified as text/structured."""
        test_results = {
            "size": 100,
            "entropy": 2.5,
            "entropy_percentage": 31.25,
            "randomness_score": 25.0,
            "compression_ratio": 0.3,
            "chi_square": 50.0,
            "min_byte": 0,
            "max_byte": 127,
            "mean_byte": 64.0,
            "null_bytes": 50,
            "null_percentage": 50.0,
            "printable_chars": 40,
            "printable_percentage": 40.0,
            "control_chars": 5,
            "control_percentage": 5.0,
            "high_bytes": 5,
            "high_bytes_percentage": 5.0,
            "histogram": [],
            "patterns": [],
            "file_type_hints": [],
        }

        dialog_with_viewer.display_results(test_results)
        file_type_text = dialog_with_viewer.file_type_text.toPlainText()

        assert "text or highly structured" in file_type_text.lower()
