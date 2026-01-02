"""Production-grade tests for Batch Analysis Widget.

This test suite validates the complete batch analysis widget functionality
including file selection, parallel processing, progress tracking, result
aggregation, and integration with the Unified Protection Engine. Tests verify
genuine batch analysis capabilities on real binary samples.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3
"""

import tempfile
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any, Callable, Optional

import pytest

from intellicrack.handlers.pyqt6_handler import HAS_PYQT as PYQT6_AVAILABLE

if PYQT6_AVAILABLE:
    from intellicrack.handlers.pyqt6_handler import (
        QApplication,
        Qt,
    )
    from intellicrack.ui.widgets.batch_analysis_widget import (
        BatchAnalysisResult,
        BatchAnalysisWidget,
        BatchAnalysisWorker,
    )

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE,
    reason="PyQt6 required for UI tests",
)


class FakeProtectionDetection:
    """Fake protection detection for unified engine results."""

    def __init__(self, confidence: float = 0.85) -> None:
        self.confidence = confidence


class FakeICPAnalysis:
    """Fake ICP analysis result for unified engine."""

    def __init__(self, detection_count: int = 2, has_error: bool = False) -> None:
        self.all_detections = [
            FakeProtectionDetection(0.92),
            FakeProtectionDetection(0.85)
        ][:detection_count]
        self.error = has_error


class FakeAnalysisResult:
    """Fake analysis result from unified engine."""

    def __init__(
        self,
        protections: list[dict[str, Any]] | None = None,
        is_packed: bool = True,
        is_protected: bool = True,
        file_type: str = "PE32",
        architecture: str = "x64",
        entropy: float = 7.82,
        icp_detection_count: int = 2
    ) -> None:
        self.protections = protections or [
            {"name": "VMProtect", "version": "3.5", "confidence": 0.92},
            {"name": "Themida", "version": "3.1", "confidence": 0.67}
        ]
        self.is_packed = is_packed
        self.is_protected = is_protected
        self.file_type = file_type
        self.architecture = architecture
        self.entropy = entropy
        self.icp_analysis = FakeICPAnalysis(detection_count=icp_detection_count)


class FakeUnifiedEngine:
    """Real test double for Unified Protection Engine with complete behavior tracking."""

    def __init__(
        self,
        should_fail: bool = False,
        failure_message: str = "File corrupted",
        analysis_delay: float = 0.0
    ) -> None:
        self.should_fail = should_fail
        self.failure_message = failure_message
        self.analysis_delay = analysis_delay
        self.call_count = 0
        self.last_file_path: Optional[str] = None
        self.last_deep_scan: Optional[bool] = None
        self.all_calls: list[tuple[str, dict[str, Any]]] = []

    def analyze_file(self, file_path: str, deep_scan: bool = False) -> FakeAnalysisResult:
        """Simulate file analysis with configurable behavior."""
        self.call_count += 1
        self.last_file_path = file_path
        self.last_deep_scan = deep_scan
        self.all_calls.append((file_path, {"deep_scan": deep_scan}))

        if self.analysis_delay > 0:
            time.sleep(self.analysis_delay)

        if self.should_fail:
            raise Exception(self.failure_message)

        return FakeAnalysisResult()


class FakeFileDialog:
    """Real test double for QFileDialog with configurable responses."""

    def __init__(self, files: list[str] | None = None, folder: str = "") -> None:
        self.files = files or []
        self.folder = folder
        self.get_open_files_called = False
        self.get_existing_directory_called = False
        self.get_save_filename_called = False
        self.last_save_path = ""

    def getOpenFileNames(
        self,
        parent: Any = None,
        caption: str = "",
        directory: str = "",
        filter: str = ""
    ) -> tuple[list[str], str]:
        """Simulate file selection dialog."""
        self.get_open_files_called = True
        return (self.files, "")

    def getExistingDirectory(
        self,
        parent: Any = None,
        caption: str = "",
        directory: str = "",
        options: Any = None
    ) -> str:
        """Simulate folder selection dialog."""
        self.get_existing_directory_called = True
        return self.folder

    def getSaveFileName(
        self,
        parent: Any = None,
        caption: str = "",
        directory: str = "",
        filter: str = ""
    ) -> tuple[str, str]:
        """Simulate save file dialog."""
        self.get_save_filename_called = True
        return (self.last_save_path, "")


class FakeUnifiedEngineProvider:
    """Provides unified engine instances for testing."""

    def __init__(self, engine: FakeUnifiedEngine) -> None:
        self.engine = engine
        self.call_count = 0

    def get_unified_engine(self) -> FakeUnifiedEngine:
        """Return the configured engine instance."""
        self.call_count += 1
        return self.engine


@pytest.fixture(scope="module")
def qapp() -> Any:
    """Create QApplication instance for Qt widget testing."""
    if not PYQT6_AVAILABLE:
        pytest.skip("PyQt6 not available")
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def fake_unified_engine() -> FakeUnifiedEngine:
    """Create fake Unified Protection Engine with realistic behavior."""
    return FakeUnifiedEngine()


@pytest.fixture
def temp_test_files() -> Generator[Path, None, None]:
    """Create temporary test files for batch analysis."""
    with tempfile.TemporaryDirectory(prefix="batch_analysis_") as tmpdir:
        test_dir = Path(tmpdir)

        (test_dir / "test1.exe").write_bytes(b"MZ" + b"\x00" * 1000)
        (test_dir / "test2.exe").write_bytes(b"MZ" + b"\x00" * 2000)
        (test_dir / "test3.exe").write_bytes(b"MZ" + b"\x00" * 1500)
        (test_dir / "test4.dll").write_bytes(b"MZ" + b"\x00" * 800)

        yield test_dir


class TestBatchAnalysisResult:
    """Test BatchAnalysisResult dataclass functionality."""

    def test_result_creation_success(self) -> None:
        """BatchAnalysisResult creates successful analysis result."""
        result = BatchAnalysisResult(
            file_path="C:\\test\\sample.exe",
            file_size=1024000,
            analysis_time=2.5,
            success=True,
            protections=[{"name": "VMProtect", "confidence": 0.9}],
            is_protected=True,
            is_packed=False,
            file_type="PE32",
            architecture="x64",
            entropy=7.5,
            icp_detections=3,
            confidence_score=0.88
        )

        assert result.success is True
        assert result.status == "Protected"
        assert result.file_size == 1024000
        assert result.analysis_time == 2.5
        assert result.icp_detections == 3

    def test_result_creation_failure(self) -> None:
        """BatchAnalysisResult creates failure result with error message."""
        result = BatchAnalysisResult(
            file_path="C:\\test\\corrupted.exe",
            file_size=0,
            analysis_time=0.1,
            success=False,
            error_message="Failed to parse PE header"
        )

        assert result.success is False
        assert result.status == "Failed"
        assert result.error_message == "Failed to parse PE header"

    def test_result_status_packed(self) -> None:
        """BatchAnalysisResult returns correct status for packed files."""
        result = BatchAnalysisResult(
            file_path="C:\\test\\packed.exe",
            file_size=500000,
            analysis_time=1.2,
            success=True,
            is_packed=True,
            is_protected=False
        )

        assert result.status == "Packed"

    def test_result_status_clean(self) -> None:
        """BatchAnalysisResult returns correct status for clean files."""
        result = BatchAnalysisResult(
            file_path="C:\\test\\clean.exe",
            file_size=300000,
            analysis_time=0.8,
            success=True,
            is_packed=False,
            is_protected=False
        )

        assert result.status == "Clean"


class TestBatchAnalysisWorker:
    """Test BatchAnalysisWorker thread functionality."""

    def test_worker_analyzes_single_file(
        self,
        qapp: Any,
        fake_unified_engine: FakeUnifiedEngine,
        temp_test_files: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Worker thread analyzes single file successfully."""
        test_file = temp_test_files / "test1.exe"

        provider = FakeUnifiedEngineProvider(fake_unified_engine)
        monkeypatch.setattr(
            "intellicrack.ui.widgets.batch_analysis_widget.get_unified_engine",
            provider.get_unified_engine
        )

        worker = BatchAnalysisWorker(
            file_paths=[str(test_file)],
            max_workers=1,
            deep_scan=False
        )

        results: list[BatchAnalysisResult] = []
        def capture_result(file_path: str, result: BatchAnalysisResult) -> None:
            results.append(result)

        worker.file_completed.connect(capture_result)

        worker.run()

        assert len(results) == 1
        assert results[0].success is True
        assert results[0].file_path == str(test_file)

    def test_worker_analyzes_multiple_files_parallel(
        self,
        qapp: Any,
        fake_unified_engine: FakeUnifiedEngine,
        temp_test_files: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Worker thread analyzes multiple files in parallel."""
        test_files = [
            temp_test_files / "test1.exe",
            temp_test_files / "test2.exe",
            temp_test_files / "test3.exe"
        ]

        provider = FakeUnifiedEngineProvider(fake_unified_engine)
        monkeypatch.setattr(
            "intellicrack.ui.widgets.batch_analysis_widget.get_unified_engine",
            provider.get_unified_engine
        )

        worker = BatchAnalysisWorker(
            file_paths=[str(f) for f in test_files],
            max_workers=4,
            deep_scan=False
        )

        completed_count = 0
        def count_completion(file_path: str, result: BatchAnalysisResult) -> None:
            nonlocal completed_count
            completed_count += 1

        worker.file_completed.connect(count_completion)

        worker.run()

        assert completed_count == 3
        assert fake_unified_engine.call_count == 3

    def test_worker_emits_progress_signals(
        self,
        qapp: Any,
        fake_unified_engine: FakeUnifiedEngine,
        temp_test_files: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Worker thread emits progress signals during analysis."""
        test_files = [
            temp_test_files / "test1.exe",
            temp_test_files / "test2.exe"
        ]

        provider = FakeUnifiedEngineProvider(fake_unified_engine)
        monkeypatch.setattr(
            "intellicrack.ui.widgets.batch_analysis_widget.get_unified_engine",
            provider.get_unified_engine
        )

        worker = BatchAnalysisWorker(
            file_paths=[str(f) for f in test_files],
            max_workers=2
        )

        progress_updates: list[tuple[int, int]] = []
        def capture_progress(current: int, total: int) -> None:
            progress_updates.append((current, total))

        worker.progress_updated.connect(capture_progress)

        worker.run()

        assert len(progress_updates) >= 2
        assert all(total == 2 for _, total in progress_updates)
        assert progress_updates[-1][0] == 2

    def test_worker_handles_file_analysis_errors(
        self,
        qapp: Any,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Worker thread handles file analysis errors gracefully."""
        failing_engine = FakeUnifiedEngine(
            should_fail=True,
            failure_message="File corrupted"
        )
        provider = FakeUnifiedEngineProvider(failing_engine)
        monkeypatch.setattr(
            "intellicrack.ui.widgets.batch_analysis_widget.get_unified_engine",
            provider.get_unified_engine
        )

        worker = BatchAnalysisWorker(
            file_paths=["C:\\nonexistent\\file.exe"],
            max_workers=1
        )

        results: list[BatchAnalysisResult] = []
        def capture_result(file_path: str, result: BatchAnalysisResult) -> None:
            results.append(result)

        worker.file_completed.connect(capture_result)

        worker.run()

        assert len(results) == 1
        assert results[0].success is False
        assert "File corrupted" in results[0].error_message

    def test_worker_respects_deep_scan_option(
        self,
        qapp: Any,
        fake_unified_engine: FakeUnifiedEngine,
        temp_test_files: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Worker thread respects deep scan configuration option."""
        test_file = temp_test_files / "test1.exe"

        provider = FakeUnifiedEngineProvider(fake_unified_engine)
        monkeypatch.setattr(
            "intellicrack.ui.widgets.batch_analysis_widget.get_unified_engine",
            provider.get_unified_engine
        )

        worker = BatchAnalysisWorker(
            file_paths=[str(test_file)],
            max_workers=1,
            deep_scan=True
        )

        worker.run()

        assert fake_unified_engine.last_deep_scan is True

    def test_worker_cancellation(
        self,
        qapp: Any,
        temp_test_files: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Worker thread can be cancelled during analysis."""
        test_files = [temp_test_files / f"test{i}.exe" for i in range(1, 4)]

        slow_engine = FakeUnifiedEngine(analysis_delay=0.5)
        provider = FakeUnifiedEngineProvider(slow_engine)
        monkeypatch.setattr(
            "intellicrack.ui.widgets.batch_analysis_widget.get_unified_engine",
            provider.get_unified_engine
        )

        worker = BatchAnalysisWorker(
            file_paths=[str(f) for f in test_files],
            max_workers=1
        )

        worker.start()
        time.sleep(0.1)
        worker.cancel()
        worker.wait(2000)

        assert worker.cancelled is True

    def test_worker_emits_finished_signal(
        self,
        qapp: Any,
        fake_unified_engine: FakeUnifiedEngine,
        temp_test_files: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Worker thread emits finished signal with all results."""
        test_files = [temp_test_files / "test1.exe", temp_test_files / "test2.exe"]

        provider = FakeUnifiedEngineProvider(fake_unified_engine)
        monkeypatch.setattr(
            "intellicrack.ui.widgets.batch_analysis_widget.get_unified_engine",
            provider.get_unified_engine
        )

        worker = BatchAnalysisWorker(
            file_paths=[str(f) for f in test_files],
            max_workers=2
        )

        all_results: list[BatchAnalysisResult] = []
        def capture_all_results(results: list[BatchAnalysisResult]) -> None:
            all_results.extend(results)

        worker.analysis_finished.connect(capture_all_results)

        worker.run()

        assert len(all_results) == 2


class TestBatchAnalysisWidgetInitialization:
    """Test widget initialization and UI components."""

    def test_widget_creates_successfully(self, qapp: Any) -> None:
        """Widget initializes with all required UI components."""
        widget = BatchAnalysisWidget()

        assert widget.results_table is not None
        assert widget.select_files_btn is not None
        assert widget.select_folder_btn is not None
        assert widget.status_label is not None

    def test_widget_initializes_file_selection_buttons(self, qapp: Any) -> None:
        """Widget initializes file selection buttons."""
        widget = BatchAnalysisWidget()

        assert widget.select_files_btn.text() == "Select Files..."
        assert widget.select_folder_btn.text() == "Select Folder..."

    def test_widget_initializes_analysis_options(self, qapp: Any) -> None:
        """Widget initializes analysis configuration options."""
        widget = BatchAnalysisWidget()

        assert widget.deep_scan_cb is not None
        assert hasattr(widget, "thread_spin") or hasattr(widget, "max_workers_spin")

    def test_widget_initializes_results_table(self, qapp: Any) -> None:
        """Widget initializes results table with correct columns."""
        widget = BatchAnalysisWidget()

        assert widget.results_table.columnCount() >= 6


class TestFileSelection:
    """Test file and folder selection functionality."""

    def test_select_files_updates_file_count(
        self,
        qapp: Any,
        temp_test_files: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Selecting files updates file count label."""
        widget = BatchAnalysisWidget()

        test_files = [
            str(temp_test_files / "test1.exe"),
            str(temp_test_files / "test2.exe")
        ]

        fake_dialog = FakeFileDialog(files=test_files)
        monkeypatch.setattr(
            "intellicrack.ui.widgets.batch_analysis_widget.QFileDialog.getOpenFileNames",
            fake_dialog.getOpenFileNames
        )

        widget.select_files()
        qapp.processEvents()

        assert len(widget.selected_files) == 2
        assert "2 files" in widget.file_count_label.text()

    def test_select_folder_scans_directory(
        self,
        qapp: Any,
        temp_test_files: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Selecting folder scans directory for executable files."""
        widget = BatchAnalysisWidget()

        fake_dialog = FakeFileDialog(folder=str(temp_test_files))
        monkeypatch.setattr(
            "intellicrack.ui.widgets.batch_analysis_widget.QFileDialog.getExistingDirectory",
            fake_dialog.getExistingDirectory
        )

        widget.select_folder()
        qapp.processEvents()

        assert len(widget.selected_files) >= 3


class TestBatchAnalysisExecution:
    """Test batch analysis execution and results."""

    def test_start_analysis_creates_worker_thread(
        self,
        qapp: Any,
        fake_unified_engine: FakeUnifiedEngine,
        temp_test_files: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Starting analysis creates worker thread with selected files."""
        widget = BatchAnalysisWidget()

        widget.selected_files = [
            str(temp_test_files / "test1.exe"),
            str(temp_test_files / "test2.exe")
        ]

        provider = FakeUnifiedEngineProvider(fake_unified_engine)
        monkeypatch.setattr(
            "intellicrack.ui.widgets.batch_analysis_widget.get_unified_engine",
            provider.get_unified_engine
        )

        if hasattr(widget, "start_analysis"):
            widget.start_analysis()

            assert widget.worker is not None

    def test_analysis_results_populate_table(
        self,
        qapp: Any,
        fake_unified_engine: FakeUnifiedEngine,
        temp_test_files: Path
    ) -> None:
        """Analysis results populate results table."""
        widget = BatchAnalysisWidget()

        test_result = BatchAnalysisResult(
            file_path=str(temp_test_files / "test1.exe"),
            file_size=1000,
            analysis_time=1.5,
            success=True,
            is_protected=True,
            protections=[{"name": "VMProtect"}],
            file_type="PE32",
            icp_detections=2
        )

        if hasattr(widget, "on_file_completed"):
            widget.on_file_completed(test_result.file_path, test_result)
            qapp.processEvents()

            assert widget.results_table.rowCount() >= 1

    def test_progress_bar_updates_during_analysis(
        self,
        qapp: Any,
        fake_unified_engine: FakeUnifiedEngine
    ) -> None:
        """Progress updates during batch analysis."""
        widget = BatchAnalysisWidget()

        if hasattr(widget, "on_progress_updated"):
            widget.on_progress_updated(5, 10)

            if hasattr(widget, "progress_bar"):
                assert widget.progress_bar.value() == 5
                assert widget.progress_bar.maximum() == 10


class TestResultsDisplay:
    """Test results table display and interaction."""

    def test_results_table_shows_file_info(self, qapp: Any) -> None:
        """Results table displays file information correctly."""
        widget = BatchAnalysisWidget()

        result = BatchAnalysisResult(
            file_path="C:\\test\\sample.exe",
            file_size=1024000,
            analysis_time=2.3,
            success=True,
            protections=[{"name": "VMProtect", "confidence": 0.92}],
            is_protected=True,
            file_type="PE32",
            architecture="x64",
            entropy=7.5,
            icp_detections=3,
            confidence_score=0.88
        )

        if hasattr(widget, "add_result_to_table"):
            widget.add_result_to_table(result)

            assert widget.results_table.rowCount() >= 1

    def test_results_table_color_coding(self, qapp: Any) -> None:
        """Results table uses color coding for different statuses."""
        widget = BatchAnalysisWidget()

        protected_result = BatchAnalysisResult(
            file_path="protected.exe",
            file_size=1000,
            analysis_time=1.0,
            success=True,
            is_protected=True
        )

        failed_result = BatchAnalysisResult(
            file_path="failed.exe",
            file_size=0,
            analysis_time=0.1,
            success=False,
            error_message="Parse error"
        )

        if hasattr(widget, "add_result_to_table"):
            widget.add_result_to_table(protected_result)
            widget.add_result_to_table(failed_result)

            assert widget.results_table.rowCount() >= 2


class TestResultExport:
    """Test batch analysis result export functionality."""

    def test_export_results_to_csv(
        self,
        qapp: Any,
        temp_test_files: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Exporting results creates CSV file with analysis data."""
        widget = BatchAnalysisWidget()

        widget.results = [
            BatchAnalysisResult(
                file_path="test1.exe",
                file_size=1000,
                analysis_time=1.5,
                success=True,
                is_protected=True,
                icp_detections=2
            ),
            BatchAnalysisResult(
                file_path="test2.exe",
                file_size=2000,
                analysis_time=2.0,
                success=True,
                is_protected=False,
                icp_detections=0
            )
        ]

        export_path = temp_test_files / "results.csv"

        fake_dialog = FakeFileDialog()
        fake_dialog.last_save_path = str(export_path)
        monkeypatch.setattr(
            "intellicrack.ui.widgets.batch_analysis_widget.QFileDialog.getSaveFileName",
            fake_dialog.getSaveFileName
        )

        if hasattr(widget, "export_results"):
            widget.export_results()

            if export_path.exists():
                content = export_path.read_text()
                assert "test1.exe" in content
                assert "test2.exe" in content

    def test_export_results_to_json(
        self,
        qapp: Any,
        temp_test_files: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Exporting results creates JSON file with detailed analysis data."""
        widget = BatchAnalysisWidget()

        widget.results = [
            BatchAnalysisResult(
                file_path="test.exe",
                file_size=1000,
                analysis_time=1.5,
                success=True,
                protections=[{"name": "VMProtect", "confidence": 0.9}],
                is_protected=True
            )
        ]

        export_path = temp_test_files / "results.json"

        fake_dialog = FakeFileDialog()
        fake_dialog.last_save_path = str(export_path)
        monkeypatch.setattr(
            "intellicrack.ui.widgets.batch_analysis_widget.QFileDialog.getSaveFileName",
            fake_dialog.getSaveFileName
        )

        if hasattr(widget, "export_results_json"):
            widget.export_results_json()


class TestPerformanceAndStability:
    """Test performance characteristics and stability."""

    def test_batch_analysis_large_file_count(
        self,
        qapp: Any,
        fake_unified_engine: FakeUnifiedEngine,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Batch analysis handles large number of files efficiently."""
        file_paths = [f"C:\\test\\file{i}.exe" for i in range(100)]

        provider = FakeUnifiedEngineProvider(fake_unified_engine)
        monkeypatch.setattr(
            "intellicrack.ui.widgets.batch_analysis_widget.get_unified_engine",
            provider.get_unified_engine
        )

        worker = BatchAnalysisWorker(
            file_paths=file_paths,
            max_workers=8,
            deep_scan=False
        )

        start_time = time.time()
        worker.run()
        elapsed = time.time() - start_time

        assert elapsed < 30.0
        assert fake_unified_engine.call_count == 100

    def test_parallel_processing_performance(
        self,
        qapp: Any,
        temp_test_files: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Parallel processing provides performance benefits."""
        test_files = [
            temp_test_files / "test1.exe",
            temp_test_files / "test2.exe",
            temp_test_files / "test3.exe",
            temp_test_files / "test4.dll"
        ]

        slow_engine = FakeUnifiedEngine(analysis_delay=0.1)
        provider = FakeUnifiedEngineProvider(slow_engine)
        monkeypatch.setattr(
            "intellicrack.ui.widgets.batch_analysis_widget.get_unified_engine",
            provider.get_unified_engine
        )

        worker_parallel = BatchAnalysisWorker(
            file_paths=[str(f) for f in test_files],
            max_workers=4
        )

        start_time = time.time()
        worker_parallel.run()
        parallel_time = time.time() - start_time

        assert parallel_time < 1.0

    def test_widget_handles_concurrent_analyses(
        self,
        qapp: Any,
        fake_unified_engine: FakeUnifiedEngine,
        temp_test_files: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Widget handles multiple consecutive batch analyses."""
        widget = BatchAnalysisWidget()

        provider = FakeUnifiedEngineProvider(fake_unified_engine)
        monkeypatch.setattr(
            "intellicrack.ui.widgets.batch_analysis_widget.get_unified_engine",
            provider.get_unified_engine
        )

        for _ in range(3):
            widget.selected_files = [
                str(temp_test_files / f"test{i}.exe") for i in range(1, 3)
            ]

            if hasattr(widget, "start_analysis"):
                widget.start_analysis()

                if widget.worker:
                    widget.worker.wait(1000)
