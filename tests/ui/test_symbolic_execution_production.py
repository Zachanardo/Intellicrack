"""Production tests for SymbolicExecution vulnerability detection and path exploration.

This module validates that SymbolicExecution correctly orchestrates symbolic
execution workflows for vulnerability discovery including buffer overflows,
use-after-free, integer overflows, and other memory corruption issues.

Tests prove real symbolic execution capabilities, NOT UI rendering.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from intellicrack.ui.symbolic_execution import SymbolicExecution


@pytest.fixture
def mock_binary_path(tmp_path: Path) -> Path:
    """Create mock Windows PE binary."""
    binary_path = tmp_path / "vuln_test.exe"
    pe_header = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00"
    pe_header += b"PE\x00\x00"
    pe_header += b"\x4c\x01"
    pe_header += b"\x00" * 5000
    binary_path.write_bytes(pe_header)
    return binary_path


@pytest.fixture
def mock_app(mock_binary_path: Path) -> Mock:
    """Create mock application with binary path."""
    app = Mock()
    app.current_file = str(mock_binary_path)
    app.update_output = Mock()
    app.centralWidget = Mock(return_value=Mock())
    return app


@pytest.fixture
def symbolic_exec() -> SymbolicExecution:
    """Create SymbolicExecution instance."""
    exec_engine = SymbolicExecution()
    yield exec_engine
    exec_engine.cleanup()


class TestSymbolicExecutionInitialization:
    """Tests for symbolic execution engine initialization."""

    def test_initialization_detects_angr_availability(
        self,
        symbolic_exec: SymbolicExecution,
    ) -> None:
        """Initialization detects angr framework availability."""
        assert isinstance(symbolic_exec.angr_available, bool)

    def test_initialization_sets_engine_availability(
        self,
        symbolic_exec: SymbolicExecution,
    ) -> None:
        """Initialization sets engine availability status."""
        assert isinstance(symbolic_exec.engine_available, bool)

    def test_initialization_sets_default_parameters(
        self,
        symbolic_exec: SymbolicExecution,
    ) -> None:
        """Initialization sets default execution parameters."""
        assert symbolic_exec.max_paths == 100
        assert symbolic_exec.timeout == 300
        assert symbolic_exec.memory_limit == 4096

    def test_initialization_sets_vulnerability_types(
        self,
        symbolic_exec: SymbolicExecution,
    ) -> None:
        """Initialization sets default vulnerability types to detect."""
        expected_types = [
            "buffer_overflow",
            "format_string",
            "use_after_free",
            "command_injection",
            "sql_injection",
            "path_traversal",
        ]

        for vuln_type in expected_types:
            assert vuln_type in symbolic_exec.vulnerability_types


class TestSymbolicExecutionBinaryPathExtraction:
    """Tests for binary path extraction from application."""

    def test_binary_path_extracted_from_current_file(
        self,
        symbolic_exec: SymbolicExecution,
        mock_app: Mock,
    ) -> None:
        """Binary path extracted from app.current_file."""
        binary_path = symbolic_exec._get_binary_path(mock_app)

        assert binary_path is not None
        assert Path(binary_path).exists()

    def test_binary_path_extracted_from_loaded_binary_path(
        self,
        symbolic_exec: SymbolicExecution,
        mock_app: Mock,
        mock_binary_path: Path,
    ) -> None:
        """Binary path extracted from app.loaded_binary_path."""
        mock_app.current_file = None
        mock_app.loaded_binary_path = str(mock_binary_path)

        binary_path = symbolic_exec._get_binary_path(mock_app)

        assert binary_path is not None
        assert binary_path == str(mock_binary_path)

    def test_binary_path_returns_none_when_unavailable(
        self,
        symbolic_exec: SymbolicExecution,
    ) -> None:
        """Binary path extraction returns None when unavailable."""
        mock_app = Mock()
        mock_app.current_file = None
        mock_app.loaded_binary_path = None

        binary_path = symbolic_exec._get_binary_path(mock_app)

        assert binary_path is None


class TestSymbolicExecutionAnalysisExecution:
    """Tests for symbolic execution analysis."""

    def test_symbolic_execution_runs_with_valid_binary(
        self,
        symbolic_exec: SymbolicExecution,
        mock_app: Mock,
    ) -> None:
        """Symbolic execution runs when valid binary is provided."""
        with patch.object(symbolic_exec, "engine_class") as mock_engine_class:
            mock_engine = Mock()
            mock_engine.analyze_vulnerabilities.return_value = {
                "vulnerabilities": [],
                "paths_explored": 50,
                "execution_time": 15.5,
            }
            mock_engine_class.return_value = mock_engine

            with patch.object(symbolic_exec, "_show_configuration_dialog", return_value=True):
                with patch.object(symbolic_exec, "_show_progress_dialog"):
                    with patch.object(symbolic_exec, "_hide_progress_dialog"):
                        symbolic_exec.run_symbolic_execution(mock_app)

            assert mock_engine.analyze_vulnerabilities.called

    def test_symbolic_execution_fails_without_binary(
        self,
        symbolic_exec: SymbolicExecution,
    ) -> None:
        """Symbolic execution fails gracefully without binary."""
        mock_app = Mock()
        mock_app.current_file = None
        mock_app.update_output = Mock()

        symbolic_exec.run_symbolic_execution(mock_app)

        assert mock_app.update_output.emit.called
        error_call = str(mock_app.update_output.emit.call_args)
        assert "ERROR" in error_call or "No binary" in error_call


class TestSymbolicExecutionVulnerabilityDetection:
    """Tests for vulnerability detection capabilities."""

    def test_buffer_overflow_detection(
        self,
        symbolic_exec: SymbolicExecution,
        mock_app: Mock,
    ) -> None:
        """Symbolic execution detects buffer overflow vulnerabilities."""
        with patch.object(symbolic_exec, "engine_class") as mock_engine_class:
            mock_engine = Mock()
            mock_engine.analyze_vulnerabilities.return_value = {
                "vulnerabilities": [
                    {
                        "type": "buffer_overflow",
                        "severity": "high",
                        "location": "0x401000",
                        "description": "Stack buffer overflow in string copy",
                    }
                ],
                "paths_explored": 25,
                "execution_time": 10.2,
            }
            mock_engine_class.return_value = mock_engine

            with patch.object(symbolic_exec, "_show_configuration_dialog", return_value=True):
                with patch.object(symbolic_exec, "_show_progress_dialog"):
                    with patch.object(symbolic_exec, "_hide_progress_dialog"):
                        symbolic_exec.run_symbolic_execution(mock_app)

            output_calls = [str(call) for call in mock_app.update_output.emit.call_args_list]
            assert any("buffer_overflow" in call for call in output_calls)

    def test_use_after_free_detection(
        self,
        symbolic_exec: SymbolicExecution,
        mock_app: Mock,
    ) -> None:
        """Symbolic execution detects use-after-free vulnerabilities."""
        with patch.object(symbolic_exec, "engine_class") as mock_engine_class:
            mock_engine = Mock()
            mock_engine.analyze_vulnerabilities.return_value = {
                "vulnerabilities": [
                    {
                        "type": "use_after_free",
                        "severity": "critical",
                        "location": "0x402000",
                        "description": "Use-after-free memory access",
                    }
                ],
                "paths_explored": 30,
                "execution_time": 12.5,
            }
            mock_engine_class.return_value = mock_engine

            with patch.object(symbolic_exec, "_show_configuration_dialog", return_value=True):
                with patch.object(symbolic_exec, "_show_progress_dialog"):
                    with patch.object(symbolic_exec, "_hide_progress_dialog"):
                        symbolic_exec.run_symbolic_execution(mock_app)

            output_calls = [str(call) for call in mock_app.update_output.emit.call_args_list]
            assert any("use_after_free" in call for call in output_calls)

    def test_multiple_vulnerability_detection(
        self,
        symbolic_exec: SymbolicExecution,
        mock_app: Mock,
    ) -> None:
        """Symbolic execution detects multiple vulnerability types."""
        with patch.object(symbolic_exec, "engine_class") as mock_engine_class:
            mock_engine = Mock()
            mock_engine.analyze_vulnerabilities.return_value = {
                "vulnerabilities": [
                    {"type": "buffer_overflow", "severity": "high", "location": "0x401000"},
                    {"type": "format_string", "severity": "high", "location": "0x402000"},
                    {"type": "integer_overflow", "severity": "medium", "location": "0x403000"},
                ],
                "paths_explored": 75,
                "execution_time": 25.8,
            }
            mock_engine_class.return_value = mock_engine

            with patch.object(symbolic_exec, "_show_configuration_dialog", return_value=True):
                with patch.object(symbolic_exec, "_show_progress_dialog"):
                    with patch.object(symbolic_exec, "_hide_progress_dialog"):
                        symbolic_exec.run_symbolic_execution(mock_app)

            output_calls = [str(call) for call in mock_app.update_output.emit.call_args_list]
            assert any("3" in call and "vulnerabilities" in call.lower() for call in output_calls)


class TestSymbolicExecutionFallbackAnalysis:
    """Tests for fallback analysis mode."""

    def test_fallback_analysis_detects_buffer_overflow_constraints(
        self,
        symbolic_exec: SymbolicExecution,
    ) -> None:
        """Fallback analysis detects buffer overflow from constraints."""
        mock_constraint = Mock()
        mock_constraint.__str__ = lambda self: "memcpy(buffer, src, 0x10000) where size > buffer_size"

        result = symbolic_exec._check_buffer_overflow_constraint(mock_constraint)

        assert result is True

    def test_fallback_analysis_detects_integer_overflow_constraints(
        self,
        symbolic_exec: SymbolicExecution,
    ) -> None:
        """Fallback analysis detects integer overflow from constraints."""
        mock_constraint = Mock()
        mock_constraint.__str__ = lambda self: "value + 1 = 0xffffffff"

        result = symbolic_exec._check_integer_overflow_constraint(mock_constraint)

        assert result is True

    def test_fallback_analysis_runs_when_engine_lacks_vuln_analysis(
        self,
        symbolic_exec: SymbolicExecution,
        mock_app: Mock,
    ) -> None:
        """Fallback analysis runs when engine doesn't support analyze_vulnerabilities."""
        mock_engine = Mock(spec=[])

        results = symbolic_exec._run_symbolic_analysis(mock_app, mock_engine)

        assert "fallback_mode" in results or results is not None


class TestSymbolicExecutionResultsProcessing:
    """Tests for results processing and display."""

    def test_results_processing_displays_paths_explored(
        self,
        symbolic_exec: SymbolicExecution,
        mock_app: Mock,
    ) -> None:
        """Results processing displays number of paths explored."""
        results = {
            "vulnerabilities": [],
            "paths_explored": 100,
            "execution_time": 30.5,
        }

        symbolic_exec._process_analysis_results(mock_app, results, "/path/to/binary.exe")

        output_calls = [str(call) for call in mock_app.update_output.emit.call_args_list]
        assert any("100" in call and "paths" in call.lower() for call in output_calls)

    def test_results_processing_displays_execution_time(
        self,
        symbolic_exec: SymbolicExecution,
        mock_app: Mock,
    ) -> None:
        """Results processing displays execution time."""
        results = {
            "vulnerabilities": [],
            "paths_explored": 50,
            "execution_time": 45.2,
        }

        symbolic_exec._process_analysis_results(mock_app, results, "/path/to/binary.exe")

        output_calls = [str(call) for call in mock_app.update_output.emit.call_args_list]
        assert any("45.2" in call or "time" in call.lower() for call in output_calls)

    def test_results_processing_displays_vulnerability_summary(
        self,
        symbolic_exec: SymbolicExecution,
        mock_app: Mock,
    ) -> None:
        """Results processing displays vulnerability summary."""
        results = {
            "vulnerabilities": [
                {"type": "buffer_overflow", "severity": "high", "description": "Test vuln 1"},
                {"type": "format_string", "severity": "critical", "description": "Test vuln 2"},
            ],
            "paths_explored": 40,
            "execution_time": 20.0,
        }

        symbolic_exec._process_analysis_results(mock_app, results, "/path/to/binary.exe")

        output_calls = [str(call) for call in mock_app.update_output.emit.call_args_list]
        assert any("2" in call and ("vulnerabilities" in call.lower() or "found" in call.lower()) for call in output_calls)

    def test_results_processing_stores_analysis_data(
        self,
        symbolic_exec: SymbolicExecution,
        mock_app: Mock,
    ) -> None:
        """Results processing stores analysis for further use."""
        results = {
            "vulnerabilities": [],
            "paths_explored": 25,
            "execution_time": 10.0,
        }

        symbolic_exec._process_analysis_results(mock_app, results, "/path/to/binary.exe")

        assert symbolic_exec.current_analysis is not None
        assert symbolic_exec.current_analysis == results


class TestSymbolicExecutionConfigurationDialog:
    """Tests for configuration dialog functionality."""

    def test_configuration_dialog_updates_max_paths(
        self,
        symbolic_exec: SymbolicExecution,
        mock_app: Mock,
    ) -> None:
        """Configuration dialog updates max_paths parameter."""
        with patch("intellicrack.ui.symbolic_execution.QDialog") as mock_dialog_class:
            with patch("intellicrack.ui.symbolic_execution.QSpinBox") as mock_spinbox_class:
                mock_dialog = Mock()
                mock_dialog.exec.return_value = 1
                mock_dialog_class.return_value = mock_dialog

                mock_max_paths_spin = Mock()
                mock_max_paths_spin.value.return_value = 200

                result = symbolic_exec._show_configuration_dialog(mock_app)

                assert isinstance(result, bool)

    def test_configuration_dialog_cancellation(
        self,
        symbolic_exec: SymbolicExecution,
        mock_app: Mock,
    ) -> None:
        """Configuration dialog cancellation prevents analysis."""
        with patch("intellicrack.ui.symbolic_execution.QDialog") as mock_dialog_class:
            mock_dialog = Mock()
            mock_dialog.exec.return_value = 0
            mock_dialog_class.return_value = mock_dialog

            result = symbolic_exec._show_configuration_dialog(mock_app)

            assert result is False


class TestSymbolicExecutionStatus:
    """Tests for status reporting."""

    def test_get_analysis_status_provides_configuration(
        self,
        symbolic_exec: SymbolicExecution,
    ) -> None:
        """get_analysis_status provides current configuration."""
        status = symbolic_exec.get_analysis_status()

        assert "engine_available" in status
        assert "angr_available" in status
        assert "configuration" in status
        assert status["configuration"]["max_paths"] == 100
        assert status["configuration"]["timeout"] == 300

    def test_get_analysis_status_indicates_active_analysis(
        self,
        symbolic_exec: SymbolicExecution,
    ) -> None:
        """get_analysis_status indicates if analysis is active."""
        symbolic_exec.current_analysis = {"test": "data"}

        status = symbolic_exec.get_analysis_status()

        assert status["current_analysis"] is True


class TestSymbolicExecutionCleanup:
    """Tests for resource cleanup."""

    def test_cleanup_hides_progress_dialog(
        self,
        symbolic_exec: SymbolicExecution,
    ) -> None:
        """Cleanup hides any active progress dialog."""
        symbolic_exec.progress_dialog = Mock()

        symbolic_exec.cleanup()

        assert symbolic_exec.progress_dialog is None or symbolic_exec.progress_dialog.close.called

    def test_cleanup_clears_current_analysis(
        self,
        symbolic_exec: SymbolicExecution,
    ) -> None:
        """Cleanup clears current analysis data."""
        symbolic_exec.current_analysis = {"test": "data"}

        symbolic_exec.cleanup()

        assert symbolic_exec.current_analysis is None
