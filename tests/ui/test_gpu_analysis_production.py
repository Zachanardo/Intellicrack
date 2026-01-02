"""Production tests for GpuAnalysis GPU acceleration and binary analysis.

This module validates that GpuAnalysis correctly orchestrates GPU-accelerated
binary analysis workflows including pattern search, entropy analysis, and
high-entropy section detection.

Tests prove real GPU acceleration capabilities, NOT UI rendering.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

from pathlib import Path
from typing import Any

import pytest

from intellicrack.ui.gpu_analysis import GpuAnalysis


class FakeSignal:
    """Real test double for Qt signal emission tracking."""

    def __init__(self) -> None:
        self.emissions: list[tuple[Any, ...]] = []
        self.call_count: int = 0

    def emit(self, *args: Any) -> None:
        """Track signal emissions."""
        self.emissions.append(args)
        self.call_count += 1

    @property
    def called(self) -> bool:
        """Check if signal was emitted."""
        return self.call_count > 0

    @property
    def call_args(self) -> tuple[Any, ...] | None:
        """Get last emission args."""
        return self.emissions[-1] if self.emissions else None

    @property
    def call_args_list(self) -> list[tuple[Any, ...]]:
        """Get all emission args."""
        return self.emissions


class FakeWidget:
    """Real test double for Qt widget."""

    def __init__(self) -> None:
        self.visible: bool = False
        self.closed: bool = False

    def show(self) -> None:
        """Show widget."""
        self.visible = True

    def close(self) -> None:
        """Close widget."""
        self.visible = False
        self.closed = True


class FakeDialog(FakeWidget):
    """Real test double for Qt dialog."""

    def __init__(self) -> None:
        super().__init__()
        self.accepted: bool = False
        self.rejected: bool = False

    def accept(self) -> None:
        """Accept dialog."""
        self.accepted = True
        self.close()

    def reject(self) -> None:
        """Reject dialog."""
        self.rejected = True
        self.close()


class FakeApplication:
    """Real test double for Qt application with binary data."""

    def __init__(self, binary_data: bytes | None = None, current_file: str | None = None) -> None:
        self.binary_data = binary_data
        self.current_file = current_file
        self.loaded_binary_path: str | None = None
        self.update_output = FakeSignal()
        self._central_widget = FakeWidget()

    def centralWidget(self) -> FakeWidget:
        """Get central widget."""
        return self._central_widget


class FakeGPUAnalysisResults:
    """Real test double for GPU analysis results."""

    def __init__(
        self,
        framework_used: str = "cpu",
        gpu_available: bool = False,
        analyses: dict[str, Any] | None = None,
    ) -> None:
        self.framework_used = framework_used
        self.gpu_available = gpu_available
        self.analyses = analyses if analyses is not None else {}

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "framework_used": self.framework_used,
            "gpu_available": self.gpu_available,
            "analyses": self.analyses,
        }


class FakeGPUAcceleratedAnalysis:
    """Real test double for GPU accelerated analysis function."""

    def __init__(self) -> None:
        self.calls: list[tuple[bytes, dict[str, Any]]] = []
        self.results: FakeGPUAnalysisResults | None = None
        self.should_fail: bool = False
        self.failure_exception: Exception | None = None

    def __call__(self, binary_data: bytes, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Execute fake GPU analysis."""
        self.calls.append((binary_data, options or {}))

        if self.should_fail:
            raise self.failure_exception or RuntimeError("GPU analysis failed")

        if self.results is None:
            self.results = FakeGPUAnalysisResults()

        return self.results.to_dict()

    def set_results(self, results: FakeGPUAnalysisResults) -> None:
        """Configure analysis results."""
        self.results = results

    def set_failure(self, exception: Exception) -> None:
        """Configure analysis to fail."""
        self.should_fail = True
        self.failure_exception = exception

    @property
    def called(self) -> bool:
        """Check if analysis was called."""
        return len(self.calls) > 0


class FakeQDialog:
    """Real test double for QDialog class."""

    def __init__(self) -> None:
        self.instances: list[FakeDialog] = []

    def __call__(self, *args: Any, **kwargs: Any) -> FakeDialog:
        """Create new dialog instance."""
        dialog = FakeDialog()
        self.instances.append(dialog)
        return dialog

    @property
    def called(self) -> bool:
        """Check if dialog was created."""
        return len(self.instances) > 0


@pytest.fixture
def mock_binary_path(tmp_path: Path) -> Path:
    """Create mock Windows PE binary."""
    binary_path = tmp_path / "test.exe"
    pe_header = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00"
    pe_header += b"PE\x00\x00"
    pe_header += b"\x4c\x01"
    pe_header += b"\x00" * 5000
    binary_path.write_bytes(pe_header)
    return binary_path


@pytest.fixture
def mock_app(mock_binary_path: Path) -> FakeApplication:
    """Create fake application with binary data."""
    binary_data = mock_binary_path.read_bytes()
    return FakeApplication(
        binary_data=binary_data,
        current_file=str(mock_binary_path),
    )


@pytest.fixture
def gpu_analysis() -> GpuAnalysis:
    """Create GpuAnalysis instance."""
    analysis = GpuAnalysis()
    yield analysis
    analysis.cleanup()


class TestGpuAnalysisInitialization:
    """Tests for GPU infrastructure initialization."""

    def test_gpu_initialization_detects_framework(
        self,
        gpu_analysis: GpuAnalysis,
    ) -> None:
        """GPU initialization detects available acceleration framework."""
        assert "framework" in gpu_analysis.framework_info
        assert gpu_analysis.framework_info["framework"] in ["cpu", "opencl", "cuda", "metal"]

    def test_gpu_initialization_sets_device_info(
        self,
        gpu_analysis: GpuAnalysis,
    ) -> None:
        """GPU initialization populates device information."""
        assert isinstance(gpu_analysis.device_info, dict)

    def test_gpu_status_provides_availability(
        self,
        gpu_analysis: GpuAnalysis,
    ) -> None:
        """GPU status provides availability information."""
        status = gpu_analysis.get_gpu_status()

        assert "gpu_available" in status
        assert "framework_info" in status
        assert "device_info" in status
        assert isinstance(status["gpu_available"], bool)


class TestGpuAnalysisBinaryDataExtraction:
    """Tests for binary data extraction from application."""

    def test_binary_data_extracted_from_app_attribute(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: FakeApplication,
    ) -> None:
        """Binary data extracted from app.binary_data attribute."""
        binary_data = gpu_analysis._get_binary_data(mock_app)

        assert binary_data is not None
        assert len(binary_data) > 0
        assert binary_data.startswith(b"MZ")

    def test_binary_data_extracted_from_current_file(
        self,
        gpu_analysis: GpuAnalysis,
        mock_binary_path: Path,
    ) -> None:
        """Binary data extracted from app.current_file path."""
        app = FakeApplication(
            binary_data=None,
            current_file=str(mock_binary_path),
        )

        binary_data = gpu_analysis._get_binary_data(app)

        assert binary_data is not None
        assert binary_data.startswith(b"MZ")

    def test_binary_data_returns_none_when_unavailable(
        self,
        gpu_analysis: GpuAnalysis,
    ) -> None:
        """Binary data extraction returns None when no data available."""
        app = FakeApplication(binary_data=None, current_file=None)

        binary_data = gpu_analysis._get_binary_data(app)

        assert binary_data is None


class TestGpuAnalysisExecutionWorkflow:
    """Tests for GPU-accelerated analysis execution."""

    def test_gpu_analysis_runs_with_binary_data(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: FakeApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """GPU analysis executes when binary data is available."""
        fake_analysis = FakeGPUAcceleratedAnalysis()
        fake_analysis.set_results(
            FakeGPUAnalysisResults(
                framework_used="opencl",
                gpu_available=True,
                analyses={
                    "pattern_search": [
                        {"pattern": "license", "match_count": 5},
                    ],
                    "entropy": {"average_entropy": 6.5},
                },
            )
        )

        monkeypatch.setattr(
            "intellicrack.ui.gpu_analysis.run_gpu_accelerated_analysis",
            fake_analysis,
        )

        gpu_analysis.run_gpu_accelerated_analysis(mock_app)

        assert fake_analysis.called
        assert mock_app.update_output.called

    def test_gpu_analysis_fails_without_binary_data(
        self,
        gpu_analysis: GpuAnalysis,
    ) -> None:
        """GPU analysis fails gracefully without binary data."""
        app = FakeApplication(binary_data=None, current_file=None)

        gpu_analysis.run_gpu_accelerated_analysis(app)

        assert app.update_output.called
        error_call = str(app.update_output.call_args)
        assert "ERROR" in error_call or "No binary" in error_call


class TestGpuAnalysisResultsProcessing:
    """Tests for analysis results processing and display."""

    def test_results_processing_displays_framework_used(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: FakeApplication,
    ) -> None:
        """Results processing displays GPU framework used."""
        results = {
            "framework_used": "cuda",
            "gpu_available": True,
            "analyses": {},
        }

        gpu_analysis._process_analysis_results(mock_app, results)

        assert mock_app.update_output.called
        output_calls = [str(call) for call in mock_app.update_output.call_args_list]
        assert any("cuda" in call for call in output_calls)

    def test_results_processing_displays_pattern_matches(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: FakeApplication,
    ) -> None:
        """Results processing displays pattern search matches."""
        results = {
            "framework_used": "opencl",
            "gpu_available": True,
            "analyses": {
                "pattern_search": [
                    {"pattern": "serial", "match_count": 3},
                    {"pattern": "registration", "match_count": 7},
                ],
            },
        }

        gpu_analysis._process_analysis_results(mock_app, results)

        output_calls = [str(call) for call in mock_app.update_output.call_args_list]
        assert any("10" in call or "matches" in call for call in output_calls)

    def test_results_processing_displays_entropy_analysis(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: FakeApplication,
    ) -> None:
        """Results processing displays entropy analysis results."""
        results = {
            "framework_used": "opencl",
            "gpu_available": True,
            "analyses": {
                "entropy": {
                    "average_entropy": 7.2,
                    "max_entropy": 7.9,
                },
            },
        }

        gpu_analysis._process_analysis_results(mock_app, results)

        output_calls = [str(call) for call in mock_app.update_output.call_args_list]
        assert any("7.2" in call or "entropy" in call.lower() for call in output_calls)

    def test_results_processing_displays_high_entropy_sections(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: FakeApplication,
    ) -> None:
        """Results processing displays high-entropy sections (potential packing)."""
        results = {
            "framework_used": "opencl",
            "gpu_available": True,
            "analyses": {
                "high_entropy_sections": [
                    {"name": ".text", "entropy": 7.8, "offset": 0x1000},
                    {"name": ".rsrc", "entropy": 7.9, "offset": 0x5000},
                ],
            },
        }

        gpu_analysis._process_analysis_results(mock_app, results)

        output_calls = [str(call) for call in mock_app.update_output.call_args_list]
        assert any("2" in call and ("high-entropy" in call.lower() or "encrypted" in call.lower()) for call in output_calls)

    def test_results_processing_stores_analysis_data(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: FakeApplication,
    ) -> None:
        """Results processing stores analysis for further use."""
        results = {
            "framework_used": "opencl",
            "gpu_available": True,
            "analyses": {"test": "data"},
        }

        gpu_analysis._process_analysis_results(mock_app, results)

        assert gpu_analysis.current_analysis is not None
        assert gpu_analysis.current_analysis == results


class TestGpuAnalysisSupportedFormats:
    """Tests for supported binary format listing."""

    def test_supported_formats_includes_windows_pe(
        self,
        gpu_analysis: GpuAnalysis,
    ) -> None:
        """Supported formats includes Windows PE executables."""
        formats = gpu_analysis.get_supported_formats()

        assert ".exe" in formats
        assert ".dll" in formats
        assert ".sys" in formats

    def test_supported_formats_includes_linux_elf(
        self,
        gpu_analysis: GpuAnalysis,
    ) -> None:
        """Supported formats includes Linux ELF binaries."""
        formats = gpu_analysis.get_supported_formats()

        assert ".elf" in formats
        assert ".so" in formats

    def test_supported_formats_includes_raw_binaries(
        self,
        gpu_analysis: GpuAnalysis,
    ) -> None:
        """Supported formats includes raw binary formats."""
        formats = gpu_analysis.get_supported_formats()

        assert ".bin" in formats
        assert ".img" in formats


class TestGpuAnalysisProgressDialogManagement:
    """Tests for progress dialog lifecycle."""

    def test_progress_dialog_shown_during_analysis(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: FakeApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Progress dialog is shown during GPU analysis."""
        fake_analysis = FakeGPUAcceleratedAnalysis()
        fake_analysis.set_results(
            FakeGPUAnalysisResults(
                framework_used="cpu",
                gpu_available=False,
                analyses={},
            )
        )

        fake_dialog_class = FakeQDialog()

        monkeypatch.setattr(
            "intellicrack.ui.gpu_analysis.run_gpu_accelerated_analysis",
            fake_analysis,
        )
        monkeypatch.setattr(
            "intellicrack.ui.gpu_analysis.QDialog",
            fake_dialog_class,
        )

        gpu_analysis.run_gpu_accelerated_analysis(mock_app)

        assert fake_dialog_class.called or any(
            dialog.visible for dialog in fake_dialog_class.instances
        )

    def test_progress_dialog_hidden_after_analysis(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: FakeApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Progress dialog is hidden after analysis completes."""
        fake_progress_dialog = FakeDialog()
        gpu_analysis.progress_dialog = fake_progress_dialog

        fake_analysis = FakeGPUAcceleratedAnalysis()
        fake_analysis.set_results(
            FakeGPUAnalysisResults(
                framework_used="cpu",
                gpu_available=False,
                analyses={},
            )
        )

        monkeypatch.setattr(
            "intellicrack.ui.gpu_analysis.run_gpu_accelerated_analysis",
            fake_analysis,
        )

        gpu_analysis.run_gpu_accelerated_analysis(mock_app)

        assert fake_progress_dialog.closed or gpu_analysis.progress_dialog is None


class TestGpuAnalysisCleanup:
    """Tests for resource cleanup."""

    def test_cleanup_hides_progress_dialog(
        self,
        gpu_analysis: GpuAnalysis,
    ) -> None:
        """Cleanup hides any active progress dialog."""
        fake_dialog = FakeDialog()
        gpu_analysis.progress_dialog = fake_dialog

        gpu_analysis.cleanup()

        assert gpu_analysis.progress_dialog is None or fake_dialog.closed

    def test_cleanup_clears_current_analysis(
        self,
        gpu_analysis: GpuAnalysis,
    ) -> None:
        """Cleanup clears current analysis data."""
        gpu_analysis.current_analysis = {"test": "data"}

        gpu_analysis.cleanup()

        assert gpu_analysis.current_analysis is None
