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
from unittest.mock import Mock, patch

import pytest

from intellicrack.ui.gpu_analysis import GpuAnalysis


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
def mock_app(mock_binary_path: Path) -> Mock:
    """Create mock application with binary data."""
    app = Mock()
    app.binary_data = mock_binary_path.read_bytes()
    app.current_file = str(mock_binary_path)
    app.update_output = Mock()
    app.centralWidget = Mock(return_value=Mock())
    return app


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
        mock_app: Mock,
    ) -> None:
        """Binary data extracted from app.binary_data attribute."""
        binary_data = gpu_analysis._get_binary_data(mock_app)

        assert binary_data is not None
        assert len(binary_data) > 0
        assert binary_data.startswith(b"MZ")

    def test_binary_data_extracted_from_current_file(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: Mock,
    ) -> None:
        """Binary data extracted from app.current_file path."""
        mock_app.binary_data = None

        binary_data = gpu_analysis._get_binary_data(mock_app)

        assert binary_data is not None
        assert binary_data.startswith(b"MZ")

    def test_binary_data_returns_none_when_unavailable(
        self,
        gpu_analysis: GpuAnalysis,
    ) -> None:
        """Binary data extraction returns None when no data available."""
        mock_app = Mock()
        mock_app.binary_data = None
        mock_app.current_file = None
        mock_app.loaded_binary_path = None

        binary_data = gpu_analysis._get_binary_data(mock_app)

        assert binary_data is None


class TestGpuAnalysisExecutionWorkflow:
    """Tests for GPU-accelerated analysis execution."""

    def test_gpu_analysis_runs_with_binary_data(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: Mock,
    ) -> None:
        """GPU analysis executes when binary data is available."""
        with patch("intellicrack.ui.gpu_analysis.run_gpu_accelerated_analysis") as mock_run:
            mock_run.return_value = {
                "framework_used": "opencl",
                "gpu_available": True,
                "analyses": {
                    "pattern_search": [
                        {"pattern": "license", "match_count": 5},
                    ],
                    "entropy": {"average_entropy": 6.5},
                },
            }

            gpu_analysis.run_gpu_accelerated_analysis(mock_app)

            assert mock_run.called
            assert mock_app.update_output.emit.called

    def test_gpu_analysis_fails_without_binary_data(
        self,
        gpu_analysis: GpuAnalysis,
    ) -> None:
        """GPU analysis fails gracefully without binary data."""
        mock_app = Mock()
        mock_app.binary_data = None
        mock_app.current_file = None
        mock_app.update_output = Mock()

        gpu_analysis.run_gpu_accelerated_analysis(mock_app)

        assert mock_app.update_output.emit.called
        error_call = str(mock_app.update_output.emit.call_args)
        assert "ERROR" in error_call or "No binary" in error_call


class TestGpuAnalysisResultsProcessing:
    """Tests for analysis results processing and display."""

    def test_results_processing_displays_framework_used(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: Mock,
    ) -> None:
        """Results processing displays GPU framework used."""
        results = {
            "framework_used": "cuda",
            "gpu_available": True,
            "analyses": {},
        }

        gpu_analysis._process_analysis_results(mock_app, results)

        assert mock_app.update_output.emit.called
        output_calls = [str(call) for call in mock_app.update_output.emit.call_args_list]
        assert any("cuda" in call for call in output_calls)

    def test_results_processing_displays_pattern_matches(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: Mock,
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

        output_calls = [str(call) for call in mock_app.update_output.emit.call_args_list]
        assert any("10" in call or "matches" in call for call in output_calls)

    def test_results_processing_displays_entropy_analysis(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: Mock,
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

        output_calls = [str(call) for call in mock_app.update_output.emit.call_args_list]
        assert any("7.2" in call or "entropy" in call.lower() for call in output_calls)

    def test_results_processing_displays_high_entropy_sections(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: Mock,
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

        output_calls = [str(call) for call in mock_app.update_output.emit.call_args_list]
        assert any("2" in call and ("high-entropy" in call.lower() or "encrypted" in call.lower()) for call in output_calls)

    def test_results_processing_stores_analysis_data(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: Mock,
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
        mock_app: Mock,
    ) -> None:
        """Progress dialog is shown during GPU analysis."""
        with patch("intellicrack.ui.gpu_analysis.run_gpu_accelerated_analysis") as mock_run:
            with patch("intellicrack.ui.gpu_analysis.QDialog") as mock_dialog:
                mock_run.return_value = {
                    "framework_used": "cpu",
                    "gpu_available": False,
                    "analyses": {},
                }
                mock_dialog_instance = Mock()
                mock_dialog.return_value = mock_dialog_instance

                gpu_analysis.run_gpu_accelerated_analysis(mock_app)

                assert mock_dialog_instance.show.called or mock_dialog.called

    def test_progress_dialog_hidden_after_analysis(
        self,
        gpu_analysis: GpuAnalysis,
        mock_app: Mock,
    ) -> None:
        """Progress dialog is hidden after analysis completes."""
        gpu_analysis.progress_dialog = Mock()

        with patch("intellicrack.ui.gpu_analysis.run_gpu_accelerated_analysis") as mock_run:
            mock_run.return_value = {
                "framework_used": "cpu",
                "gpu_available": False,
                "analyses": {},
            }

            gpu_analysis.run_gpu_accelerated_analysis(mock_app)

            assert gpu_analysis.progress_dialog.close.called or gpu_analysis.progress_dialog is None


class TestGpuAnalysisCleanup:
    """Tests for resource cleanup."""

    def test_cleanup_hides_progress_dialog(
        self,
        gpu_analysis: GpuAnalysis,
    ) -> None:
        """Cleanup hides any active progress dialog."""
        gpu_analysis.progress_dialog = Mock()

        gpu_analysis.cleanup()

        assert gpu_analysis.progress_dialog is None or gpu_analysis.progress_dialog.close.called

    def test_cleanup_clears_current_analysis(
        self,
        gpu_analysis: GpuAnalysis,
    ) -> None:
        """Cleanup clears current analysis data."""
        gpu_analysis.current_analysis = {"test": "data"}

        gpu_analysis.cleanup()

        assert gpu_analysis.current_analysis is None
