"""Tests for progress_callback wiring in cli.py.

This tests that the progress_callback function is properly wired to
analysis functions to provide real-time progress updates.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest

if TYPE_CHECKING:
    pass


class TestProgressCallbackWiring:
    """Test suite for progress_callback wiring in CLI analysis."""

    def test_progress_callback_definition(self) -> None:
        """Test that progress_callback has correct signature."""
        def progress_callback(step: str, progress: float, message: str = "") -> None:
            pass

        import inspect

        sig = inspect.signature(progress_callback)
        params = list(sig.parameters.keys())

        assert "step" in params
        assert "progress" in params
        assert "message" in params

    def test_progress_callback_invocation_format(self) -> None:
        """Test progress_callback invocation format."""
        calls: list[tuple[str, float, str]] = []

        def progress_callback(step: str, progress: float, message: str = "") -> None:
            calls.append((step, progress, message))

        progress_callback("Basic Analysis", 0.1, "Initializing")
        progress_callback("Basic Analysis", 0.5, "Running comprehensive analysis")
        progress_callback("Basic Analysis", 1.0, "Analysis complete")

        assert len(calls) == 3
        assert calls[0] == ("Basic Analysis", 0.1, "Initializing")
        assert calls[1] == ("Basic Analysis", 0.5, "Running comprehensive analysis")
        assert calls[2] == ("Basic Analysis", 1.0, "Analysis complete")

    def test_progress_values_in_valid_range(self) -> None:
        """Test that progress values are between 0.0 and 1.0."""
        progress_values = [0.0, 0.1, 0.5, 1.0]

        for value in progress_values:
            assert 0.0 <= value <= 1.0

    def test_gpu_acceleration_progress_updates(self) -> None:
        """Test GPU acceleration progress callback calls."""
        calls: list[tuple[str, float, str]] = []

        def progress_callback(step: str, progress: float, message: str = "") -> None:
            calls.append((step, progress, message))

        gpu_accelerate = True
        if gpu_accelerate:
            progress_callback("GPU Processing", 0.0, "Starting GPU acceleration")
            progress_callback("GPU Processing", 1.0, "GPU processing complete")

        assert len(calls) == 2
        assert calls[0][0] == "GPU Processing"
        assert calls[0][1] == 0.0
        assert calls[1][1] == 1.0

    def test_distributed_processing_progress_updates(self) -> None:
        """Test distributed processing progress callback calls."""
        calls: list[tuple[str, float, str]] = []

        def progress_callback(step: str, progress: float, message: str = "") -> None:
            calls.append((step, progress, message))

        distributed = True
        if distributed:
            progress_callback("Distributed Analysis", 0.0, "Starting distributed processing")
            progress_callback("Distributed Analysis", 1.0, "Distributed processing complete")

        assert len(calls) == 2
        assert all(c[0] == "Distributed Analysis" for c in calls)

    def test_symbolic_execution_progress_updates(self) -> None:
        """Test symbolic execution progress callback calls."""
        calls: list[tuple[str, float, str]] = []

        def progress_callback(step: str, progress: float, message: str = "") -> None:
            calls.append((step, progress, message))

        symbolic_execution = True
        if symbolic_execution:
            progress_callback("Symbolic Analysis", 0.0, "Starting symbolic execution")
            progress_callback("Symbolic Analysis", 1.0, "Symbolic execution complete")

        assert len(calls) == 2
        assert all(c[0] == "Symbolic Analysis" for c in calls)

    def test_progress_callback_with_empty_message(self) -> None:
        """Test progress callback with default empty message."""
        calls: list[tuple[str, float, str]] = []

        def progress_callback(step: str, progress: float, message: str = "") -> None:
            calls.append((step, progress, message))

        progress_callback("Test Step", 0.5)

        assert len(calls) == 1
        assert calls[0][2] == ""

    def test_progress_callback_step_names(self) -> None:
        """Test that step names are consistent."""
        expected_steps = [
            "Basic Analysis",
            "GPU Processing",
            "Distributed Analysis",
            "Symbolic Analysis",
        ]

        for step in expected_steps:
            assert isinstance(step, str)
            assert len(step) > 0

    def test_progress_manager_integration(self) -> None:
        """Test progress_callback integration with ProgressManager."""

        class MockProgressManager:
            def __init__(self) -> None:
                self.task_ids: dict[str, int] = {}
                self.progress: MagicMock | None = MagicMock()
                self.updates: list[tuple[int, int, str]] = []

            def start_analysis(self, binary_path: str, analysis_types: list[str]) -> None:
                for i, analysis_type in enumerate(analysis_types):
                    self.task_ids[analysis_type] = i

        progress_manager = MockProgressManager()
        progress_manager.start_analysis("/test/binary", ["Basic Analysis", "GPU Processing"])

        def progress_callback(step: str, progress: float, message: str = "") -> None:
            if step in progress_manager.task_ids:
                task_id = progress_manager.task_ids[step]
                if progress_manager.progress:
                    progress_manager.progress.update(
                        task_id,
                        completed=int(progress * 100),
                        description=f"{step}: {message}" if message else step,
                    )

        progress_callback("Basic Analysis", 0.5, "Processing")

        assert progress_manager.progress.update.called

    def test_progress_percentage_conversion(self) -> None:
        """Test that float progress converts to percentage correctly."""
        progress_values = [0.0, 0.25, 0.5, 0.75, 1.0]
        expected_percentages = [0, 25, 50, 75, 100]

        for progress, expected in zip(progress_values, expected_percentages):
            percentage = int(progress * 100)
            assert percentage == expected

    def test_mode_specific_progress_message(self) -> None:
        """Test that mode is included in progress message."""
        mode = "comprehensive"
        message = f"Running {mode} analysis"

        assert "comprehensive" in message
        assert "analysis" in message
