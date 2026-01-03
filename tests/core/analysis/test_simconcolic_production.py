"""Production tests for simconcolic module.

This module tests the SimConcolic binary analysis framework which provides
plugin-based analysis for binary symbolic execution and monitoring.

Copyright (C) 2025 Zachary Flint
"""

import time
from typing import Any

import pytest

from intellicrack.core.analysis.simconcolic import BinaryAnalyzer, Plugin, State


class FakeState:
    """Real test double for State objects in tests."""

    def __init__(self, address: int = 0x400000, state_id: str = "test_state_1") -> None:
        """Initialize a fake state for testing.

        Args:
            address: The instruction pointer address for this state.
            state_id: The unique identifier for this state.

        """
        self.address: int = address
        self.state_id: str = state_id
        self.terminated: bool = False
        self.termination_reason: str = "running"
        self.constraints: list[Any] = []
        self.input_symbols: dict[str, bytes | list[bytes]] = {
            "stdin": b"",
            "argv": [],
        }

    def is_terminated(self) -> bool:
        """Check if state is terminated.

        Returns:
            True if state has been terminated, False otherwise.

        """
        return self.terminated


class TestPluginBase:
    """Test Plugin base class functionality."""

    def test_plugin_initialization(self) -> None:
        """Plugin initializes with correct attributes."""
        plugin = Plugin()

        assert plugin.analyzer is None

    def test_will_run_callback_initialization(self) -> None:
        """will_run_callback initializes analysis metadata."""
        plugin = Plugin()

        plugin.will_run_callback()

        assert hasattr(plugin, "analysis_start_time")
        assert hasattr(plugin, "total_states_analyzed")
        assert hasattr(plugin, "analysis_metadata")

    def test_will_run_callback_metadata_structure(self) -> None:
        """will_run_callback creates proper metadata structure."""
        plugin = Plugin()

        plugin.will_run_callback(arg1="test", kwarg1=123)

        assert "start_time" in plugin.analysis_metadata
        assert "initial_memory_usage" in plugin.analysis_metadata
        assert "callback_args" in plugin.analysis_metadata
        assert "callback_kwargs" in plugin.analysis_metadata

    def test_did_finish_run_callback_completion(self) -> None:
        """did_finish_run_callback completes analysis metadata."""
        plugin = Plugin()

        plugin.will_run_callback()
        time.sleep(0.1)
        plugin.did_finish_run_callback()

        assert "end_time" in plugin.analysis_metadata
        assert "duration" in plugin.analysis_metadata
        assert plugin.analysis_metadata["duration"] > 0

    def test_will_fork_state_callback(self) -> None:
        """will_fork_state_callback executes without error."""
        plugin = Plugin()
        fake_state = FakeState(address=0x401000, state_id="fork_test_1")

        plugin.will_fork_state_callback(fake_state)  # type: ignore[arg-type]

    def test_will_terminate_state_callback(self) -> None:
        """will_terminate_state_callback executes without error."""
        plugin = Plugin()
        fake_state = FakeState(address=0x402000, state_id="term_test_1")

        plugin.will_terminate_state_callback(fake_state)  # type: ignore[arg-type]

    def test_did_terminate_state_callback(self) -> None:
        """did_terminate_state_callback executes without error."""
        plugin = Plugin()
        fake_state = FakeState(address=0x402000, state_id="term_test_2")

        plugin.did_terminate_state_callback(fake_state)  # type: ignore[arg-type]


class TestPluginLifecycle:
    """Test plugin lifecycle management."""

    def test_full_analysis_lifecycle(self) -> None:
        """Plugin handles full analysis lifecycle."""
        plugin = Plugin()

        plugin.will_run_callback()

        time.sleep(0.05)

        fake_state = FakeState(address=0x403000, state_id="lifecycle_1")
        plugin.will_fork_state_callback(fake_state)  # type: ignore[arg-type]

        plugin.will_terminate_state_callback(fake_state)  # type: ignore[arg-type]
        plugin.did_terminate_state_callback(fake_state)  # type: ignore[arg-type]

        plugin.did_finish_run_callback()

        assert hasattr(plugin, "analysis_metadata")
        assert "duration" in plugin.analysis_metadata

    def test_multiple_state_operations(self) -> None:
        """Plugin handles multiple state operations."""
        plugin = Plugin()

        plugin.will_run_callback()

        for i in range(5):
            fake_state = FakeState(address=0x404000 + (i * 0x100), state_id=f"multi_state_{i}")
            plugin.will_fork_state_callback(fake_state)  # type: ignore[arg-type]

        plugin.did_finish_run_callback()

        assert hasattr(plugin, "analysis_metadata")

    def test_state_termination_sequence(self) -> None:
        """Plugin handles state termination correctly."""
        plugin = Plugin()

        fake_state = FakeState(address=0x405000, state_id="term_seq_1")

        plugin.will_terminate_state_callback(fake_state)  # type: ignore[arg-type]
        plugin.did_terminate_state_callback(fake_state)  # type: ignore[arg-type]


class TestPluginStatistics:
    """Test plugin statistics tracking."""

    def test_analysis_duration_tracking(self) -> None:
        """Plugin tracks analysis duration."""
        plugin = Plugin()

        plugin.will_run_callback()
        time.sleep(0.1)
        plugin.did_finish_run_callback()

        duration = plugin.analysis_metadata["duration"]

        assert duration >= 0.1
        assert duration < 1.0

    def test_state_counter_initialization(self) -> None:
        """Plugin initializes state counter."""
        plugin = Plugin()

        plugin.will_run_callback()

        assert plugin.total_states_analyzed == 0

    def test_memory_usage_tracking(self) -> None:
        """Plugin tracks memory usage."""
        plugin = Plugin()

        plugin.will_run_callback()

        assert "initial_memory_usage" in plugin.analysis_metadata

        plugin.did_finish_run_callback()

        assert "final_memory_usage" in plugin.analysis_metadata


class TestBinaryAnalyzer:
    """Test BinaryAnalyzer functionality."""

    def test_binary_analyzer_initialization(self) -> None:
        """BinaryAnalyzer initializes correctly."""
        analyzer = BinaryAnalyzer("test_binary.exe")

        assert analyzer is not None

    def test_binary_analyzer_with_plugins(self) -> None:
        """BinaryAnalyzer works with plugins."""
        analyzer = BinaryAnalyzer("test_binary.exe")
        plugin = Plugin()

        plugin.analyzer = analyzer

        assert plugin.analyzer is analyzer


class TestPluginIntegration:
    """Test plugin integration with BinaryAnalyzer."""

    def test_plugin_analyzer_reference(self) -> None:
        """Plugin maintains reference to analyzer."""
        analyzer = BinaryAnalyzer("test_binary.exe")
        plugin = Plugin()

        plugin.analyzer = analyzer

        assert plugin.analyzer is not None
        assert plugin.analyzer is analyzer

    def test_multiple_plugins_on_analyzer(self) -> None:
        """Multiple plugins can reference same analyzer."""
        analyzer = BinaryAnalyzer("test_binary.exe")

        plugin1 = Plugin()
        plugin2 = Plugin()

        plugin1.analyzer = analyzer
        plugin2.analyzer = analyzer

        assert plugin1.analyzer is analyzer
        assert plugin2.analyzer is analyzer


class TestPluginCallbackOrder:
    """Test plugin callback execution order."""

    def test_run_callbacks_sequence(self) -> None:
        """Plugin callbacks execute in correct sequence."""
        plugin = Plugin()

        plugin.will_run_callback()

        assert hasattr(plugin, "analysis_start_time")

        plugin.did_finish_run_callback()

        assert "duration" in plugin.analysis_metadata

    def test_state_callbacks_sequence(self) -> None:
        """State callbacks execute in correct sequence."""
        plugin = Plugin()
        fake_state = FakeState(address=0x406000, state_id="seq_test_1")

        plugin.will_fork_state_callback(fake_state)  # type: ignore[arg-type]

    def test_termination_callbacks_sequence(self) -> None:
        """Termination callbacks execute in correct sequence."""
        plugin = Plugin()
        fake_state = FakeState(address=0x407000, state_id="term_seq_test")

        plugin.will_terminate_state_callback(fake_state)  # type: ignore[arg-type]

        plugin.did_terminate_state_callback(fake_state)  # type: ignore[arg-type]


class TestPluginCallbackArguments:
    """Test plugin callback argument handling."""

    def test_will_run_callback_with_args(self) -> None:
        """will_run_callback accepts arbitrary arguments."""
        plugin = Plugin()

        plugin.will_run_callback("arg1", "arg2", kwarg1="value1")

        assert "callback_args" in plugin.analysis_metadata
        assert "callback_kwargs" in plugin.analysis_metadata

    def test_did_finish_run_callback_with_args(self) -> None:
        """did_finish_run_callback accepts arbitrary arguments."""
        plugin = Plugin()

        plugin.will_run_callback()
        plugin.did_finish_run_callback("result", status="completed")

        assert "completion_args" in plugin.analysis_metadata
        assert "completion_kwargs" in plugin.analysis_metadata

    def test_state_callbacks_with_args(self) -> None:
        """State callbacks accept arbitrary arguments."""
        plugin = Plugin()
        fake_state = FakeState(address=0x408000, state_id="args_test")

        plugin.will_fork_state_callback(fake_state, "extra_arg", extra_kwarg="value")  # type: ignore[arg-type]


class TestPluginErrorHandling:
    """Test plugin error handling."""

    def test_callback_without_initialization(self) -> None:
        """Callback handles missing initialization gracefully."""
        plugin = Plugin()

        plugin.did_finish_run_callback()

    def test_multiple_will_run_calls(self) -> None:
        """Multiple will_run_callback calls don't break state."""
        plugin = Plugin()

        plugin.will_run_callback()
        first_start = plugin.analysis_start_time

        time.sleep(0.01)

        plugin.will_run_callback()
        second_start = plugin.analysis_start_time

        assert second_start >= first_start


class TestPluginPerformance:
    """Test plugin performance characteristics."""

    def test_callback_overhead_minimal(self) -> None:
        """Plugin callbacks have minimal overhead."""
        plugin = Plugin()

        start = time.time()

        for i in range(1000):
            fake_state = FakeState(address=0x500000 + i, state_id=f"perf_state_{i}")
            plugin.will_fork_state_callback(fake_state)  # type: ignore[arg-type]

        duration = time.time() - start

        assert duration < 1.0

    def test_metadata_collection_efficient(self) -> None:
        """Metadata collection is efficient."""
        plugin = Plugin()

        start = time.time()

        for _ in range(100):
            plugin.will_run_callback()
            plugin.did_finish_run_callback()

        duration = time.time() - start

        assert duration < 1.0
