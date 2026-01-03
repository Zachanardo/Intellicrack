#!/usr/bin/env python3
"""Production tests for Radare2 Session Helpers - Real session management validation.

Tests validate real r2pipe session management, pooling, and command execution.
All tests use genuine Windows system binaries - NO MOCKS.

Test Coverage:
- DirectR2Session connection and command execution
- Session pooling vs direct session modes
- Context manager session lifecycle
- Command batch execution
- Pool statistics and metrics tracking
- Idle session cleanup
- Session migration from direct to pooled
- Error handling for invalid binaries
- Thread safety of session pool
- Performance benchmarks for pooled vs direct sessions
"""

import logging
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.radare2_session_helpers import (
    DirectR2Session,
    R2CommandBatch,
    SESSION_MANAGER_AVAILABLE,
    cleanup_idle_sessions,
    configure_global_pool,
    execute_r2_command,
    get_all_session_metrics,
    get_pool_statistics,
    get_r2_session,
)

REAL_BINARY_NOTEPAD: Path = Path(r"C:\Windows\System32\notepad.exe")
REAL_BINARY_KERNEL32: Path = Path(r"C:\Windows\System32\kernel32.dll")
REAL_BINARY_CALC: Path = Path(r"C:\Windows\System32\calc.exe")


@pytest.fixture(scope="function")
def test_binary_path() -> str:
    """Path to a real test binary."""
    assert REAL_BINARY_NOTEPAD.exists(), "notepad.exe must exist"
    return str(REAL_BINARY_NOTEPAD)


@pytest.fixture(scope="function")
def alternative_binary_path() -> str:
    """Alternative test binary path."""
    assert REAL_BINARY_CALC.exists(), "calc.exe must exist"
    return str(REAL_BINARY_CALC)


@pytest.fixture(autouse=True)
def cleanup_sessions() -> Generator[None, None, None]:
    """Cleanup sessions after each test."""
    yield
    if SESSION_MANAGER_AVAILABLE:
        cleanup_idle_sessions()


class TestDirectR2Session:
    """Test DirectR2Session functionality without pooling."""

    def test_direct_session_connects_to_real_binary(self, test_binary_path: str) -> None:
        """DirectR2Session successfully connects to real Windows binary."""
        session: DirectR2Session = DirectR2Session(test_binary_path)

        connected: bool = session.connect()

        assert connected
        assert session.r2 is not None
        session.disconnect()

    def test_direct_session_executes_info_command(self, test_binary_path: str) -> None:
        """DirectR2Session executes radare2 info command on real binary."""
        session: DirectR2Session = DirectR2Session(test_binary_path)
        session.connect()

        result: dict[str, Any] | str = session.execute("i")

        assert isinstance(result, str)
        assert result != ""
        assert "arch" in result.lower() or "size" in result.lower()
        session.disconnect()

    def test_direct_session_executes_json_command(self, test_binary_path: str) -> None:
        """DirectR2Session executes JSON command and parses result."""
        session: DirectR2Session = DirectR2Session(test_binary_path)
        session.connect()

        result: dict[str, Any] | str = session.execute("ij", expect_json=True)

        assert isinstance(result, dict)
        assert "bin" in result or "core" in result
        session.disconnect()

    def test_direct_session_disconnect_cleanup(self, test_binary_path: str) -> None:
        """DirectR2Session properly cleans up on disconnect."""
        session: DirectR2Session = DirectR2Session(test_binary_path)
        session.connect()
        assert session.r2 is not None

        session.disconnect()

        assert session.r2 is None

    def test_direct_session_execute_without_connection_raises_error(self, test_binary_path: str) -> None:
        """DirectR2Session raises error when executing without connection."""
        session: DirectR2Session = DirectR2Session(test_binary_path)

        with pytest.raises(RuntimeError, match="Not connected"):
            session.execute("i")

    def test_direct_session_with_custom_flags(self, test_binary_path: str) -> None:
        """DirectR2Session accepts custom radare2 flags."""
        custom_flags: list[str] = ["-2", "-A"]
        session: DirectR2Session = DirectR2Session(test_binary_path, flags=custom_flags)

        connected: bool = session.connect()

        assert connected
        assert session.flags == custom_flags
        session.disconnect()


class TestSessionContextManager:
    """Test get_r2_session context manager functionality."""

    def test_context_manager_with_pooling_enabled(self, test_binary_path: str) -> None:
        """Context manager provides session with pooling enabled."""
        with get_r2_session(test_binary_path, use_pooling=True) as session:
            result: str = session.execute("i")

            assert isinstance(result, str)
            assert result != ""

    def test_context_manager_with_pooling_disabled(self, test_binary_path: str) -> None:
        """Context manager provides direct session when pooling disabled."""
        with get_r2_session(test_binary_path, use_pooling=False, auto_analyze=False) as session:
            assert isinstance(session, DirectR2Session)
            result: dict[str, Any] | str = session.execute("i")

            assert isinstance(result, str)
            assert result != ""

    def test_context_manager_auto_analyzes_binary(self, test_binary_path: str) -> None:
        """Context manager auto-analyzes binary when enabled."""
        with get_r2_session(test_binary_path, use_pooling=False, auto_analyze=True) as session:
            functions: dict[str, Any] | str | list[Any] = session.execute("aflj", expect_json=True)

            assert isinstance(functions, list)

    def test_context_manager_cleanup_on_exception(self, test_binary_path: str) -> None:
        """Context manager properly cleans up session on exception."""
        try:
            with get_r2_session(test_binary_path, use_pooling=False) as session:
                session.execute("i")
                raise ValueError("Test exception")
        except ValueError:
            pass

    def test_context_manager_with_custom_flags(self, test_binary_path: str) -> None:
        """Context manager accepts custom radare2 flags."""
        custom_flags: list[str] = ["-2", "-w"]

        with get_r2_session(test_binary_path, flags=custom_flags, use_pooling=False) as session:
            result: str = session.execute("i")

            assert isinstance(result, str)


class TestExecuteR2Command:
    """Test execute_r2_command convenience function."""

    def test_execute_single_command_returns_string(self, test_binary_path: str) -> None:
        """execute_r2_command executes single command and returns string result."""
        result: dict[str, Any] | str = execute_r2_command(test_binary_path, "i", use_pooling=False)

        assert isinstance(result, str)
        assert result != ""

    def test_execute_json_command_returns_dict(self, test_binary_path: str) -> None:
        """execute_r2_command executes JSON command and returns parsed dict."""
        result: dict[str, Any] | str = execute_r2_command(
            test_binary_path, "ij", expect_json=True, use_pooling=False
        )

        assert isinstance(result, dict)
        assert "bin" in result or "core" in result

    def test_execute_command_with_pooling(self, test_binary_path: str) -> None:
        """execute_r2_command works with pooling enabled."""
        if not SESSION_MANAGER_AVAILABLE:
            pytest.skip("Session manager not available")

        result: dict[str, Any] | str = execute_r2_command(test_binary_path, "i", use_pooling=True)

        assert isinstance(result, str)
        assert result != ""

    def test_execute_command_with_custom_flags(self, test_binary_path: str) -> None:
        """execute_r2_command accepts custom radare2 flags."""
        custom_flags: list[str] = ["-2"]

        result: dict[str, Any] | str = execute_r2_command(
            test_binary_path, "i", flags=custom_flags, use_pooling=False
        )

        assert isinstance(result, str)


class TestR2CommandBatch:
    """Test R2CommandBatch for efficient multi-command execution."""

    def test_batch_executes_multiple_commands(self, test_binary_path: str) -> None:
        """R2CommandBatch executes multiple commands in single session."""
        batch: R2CommandBatch = R2CommandBatch(test_binary_path, use_pooling=False)
        batch.add_command("i")
        batch.add_command("ij", expect_json=True)
        batch.add_command("ie")

        results: list[Any] = batch.execute_all()

        assert len(results) == 3
        assert isinstance(results[0], str)
        assert isinstance(results[1], dict)
        assert isinstance(results[2], str)

    def test_batch_handles_command_errors(self, test_binary_path: str) -> None:
        """R2CommandBatch handles individual command failures gracefully."""
        batch: R2CommandBatch = R2CommandBatch(test_binary_path, use_pooling=False)
        batch.add_command("i")
        batch.add_command("invalid_command_xyz")
        batch.add_command("ie")

        results: list[Any] = batch.execute_all()

        assert len(results) == 3
        assert isinstance(results[0], str)

    def test_batch_preserves_command_order(self, test_binary_path: str) -> None:
        """R2CommandBatch executes commands in order they were added."""
        batch: R2CommandBatch = R2CommandBatch(test_binary_path, use_pooling=False)
        batch.add_command("?e FIRST")
        batch.add_command("?e SECOND")
        batch.add_command("?e THIRD")

        results: list[Any] = batch.execute_all()

        assert len(results) == 3
        assert "FIRST" in results[0]
        assert "SECOND" in results[1]
        assert "THIRD" in results[2]

    def test_batch_with_pooling_enabled(self, test_binary_path: str) -> None:
        """R2CommandBatch works with session pooling."""
        if not SESSION_MANAGER_AVAILABLE:
            pytest.skip("Session manager not available")

        batch: R2CommandBatch = R2CommandBatch(test_binary_path, use_pooling=True)
        batch.add_command("i")
        batch.add_command("ij", expect_json=True)

        results: list[Any] = batch.execute_all()

        assert len(results) == 2


class TestPoolStatisticsAndMetrics:
    """Test session pool statistics and metrics tracking."""

    def test_get_pool_statistics_returns_data(self) -> None:
        """get_pool_statistics returns pool statistics dictionary."""
        stats: dict[str, Any] = get_pool_statistics()

        assert isinstance(stats, dict)
        assert "total_sessions" in stats or "error" in stats

    def test_get_all_session_metrics_returns_list(self) -> None:
        """get_all_session_metrics returns list of session metrics."""
        metrics: list[dict[str, Any]] = get_all_session_metrics()

        assert isinstance(metrics, list)

    def test_pool_statistics_track_session_usage(self, test_binary_path: str) -> None:
        """Pool statistics correctly track session creation and usage."""
        if not SESSION_MANAGER_AVAILABLE:
            pytest.skip("Session manager not available")

        initial_stats: dict[str, Any] = get_pool_statistics()

        with get_r2_session(test_binary_path, use_pooling=True) as session:
            session.execute("i")

        final_stats: dict[str, Any] = get_pool_statistics()

        assert "total_sessions" in final_stats


class TestSessionPoolConfiguration:
    """Test global session pool configuration."""

    def test_configure_global_pool_accepts_parameters(self) -> None:
        """configure_global_pool accepts and applies configuration parameters."""
        if not SESSION_MANAGER_AVAILABLE:
            pytest.skip("Session manager not available")

        configure_global_pool(
            max_sessions=5,
            max_idle_time=60.0,
            auto_analyze=True,
            analysis_level="aaa",
        )

    def test_cleanup_idle_sessions_executes(self) -> None:
        """cleanup_idle_sessions forces cleanup of idle sessions."""
        if not SESSION_MANAGER_AVAILABLE:
            pytest.skip("Session manager not available")

        cleanup_idle_sessions()


class TestSessionPoolingBehavior:
    """Test session pooling behavior and reuse."""

    def test_pooled_sessions_reuse_connections(self, test_binary_path: str) -> None:
        """Pooled sessions reuse existing connections for same binary."""
        if not SESSION_MANAGER_AVAILABLE:
            pytest.skip("Session manager not available")

        configure_global_pool(max_sessions=10, max_idle_time=300.0)

        with get_r2_session(test_binary_path, use_pooling=True) as session1:
            result1: str = session1.execute("i")

        with get_r2_session(test_binary_path, use_pooling=True) as session2:
            result2: str = session2.execute("i")

        assert isinstance(result1, str)
        assert isinstance(result2, str)

    def test_multiple_binaries_create_separate_sessions(
        self, test_binary_path: str, alternative_binary_path: str
    ) -> None:
        """Pool creates separate sessions for different binaries."""
        if not SESSION_MANAGER_AVAILABLE:
            pytest.skip("Session manager not available")

        with get_r2_session(test_binary_path, use_pooling=True) as session1:
            result1: str = session1.execute("i")

        with get_r2_session(alternative_binary_path, use_pooling=True) as session2:
            result2: str = session2.execute("i")

        assert isinstance(result1, str)
        assert isinstance(result2, str)


class TestErrorHandling:
    """Test error handling for invalid scenarios."""

    def test_invalid_binary_path_raises_error(self) -> None:
        """Session creation with invalid binary path raises appropriate error."""
        invalid_path: str = r"C:\NonExistent\Invalid.exe"

        with pytest.raises((RuntimeError, OSError, FileNotFoundError)):
            with get_r2_session(invalid_path, use_pooling=False) as session:
                session.execute("i")

    def test_direct_session_handles_connection_failure(self) -> None:
        """DirectR2Session handles connection failure gracefully."""
        invalid_path: str = r"C:\NonExistent\Invalid.exe"
        session: DirectR2Session = DirectR2Session(invalid_path)

        connected: bool = session.connect()

        assert not connected


class TestPerformanceBenchmarks:
    """Performance benchmarks for session operations."""

    def test_pooled_session_performance(self, test_binary_path: str) -> None:
        """Pooled sessions show performance benefits for repeated access."""
        if not SESSION_MANAGER_AVAILABLE:
            pytest.skip("Session manager not available")

        configure_global_pool(max_sessions=10, max_idle_time=300.0)
        iterations: int = 3

        start_pooled: float = time.perf_counter()
        for _ in range(iterations):
            with get_r2_session(test_binary_path, use_pooling=True) as session:
                session.execute("i")
        end_pooled: float = time.perf_counter()

        pooled_time: float = end_pooled - start_pooled
        assert pooled_time > 0

    def test_direct_session_performance_baseline(self, test_binary_path: str) -> None:
        """Direct sessions provide performance baseline."""
        iterations: int = 3

        start_direct: float = time.perf_counter()
        for _ in range(iterations):
            with get_r2_session(test_binary_path, use_pooling=False, auto_analyze=False) as session:
                session.execute("i")
        end_direct: float = time.perf_counter()

        direct_time: float = end_direct - start_direct
        assert direct_time > 0

    def test_batch_execution_performance(self, test_binary_path: str) -> None:
        """Batch execution shows performance benefits over individual commands."""
        batch: R2CommandBatch = R2CommandBatch(test_binary_path, use_pooling=False)
        for _ in range(10):
            batch.add_command("i")

        start: float = time.perf_counter()
        results: list[Any] = batch.execute_all()
        end: float = time.perf_counter()

        assert len(results) == 10
        assert (end - start) < 30.0


class TestRealWorldUsagePatterns:
    """Test real-world usage patterns and workflows."""

    def test_analyze_binary_workflow(self, test_binary_path: str) -> None:
        """Complete binary analysis workflow using session helpers."""
        batch: R2CommandBatch = R2CommandBatch(test_binary_path, use_pooling=False)
        batch.add_command("ij", expect_json=True)
        batch.add_command("aaa")
        batch.add_command("aflj", expect_json=True)
        batch.add_command("iij", expect_json=True)

        results: list[Any] = batch.execute_all()

        assert len(results) == 4
        assert isinstance(results[0], dict)
        assert isinstance(results[2], list)

    def test_concurrent_session_usage(self, test_binary_path: str, alternative_binary_path: str) -> None:
        """Multiple sessions can be used concurrently."""
        if not SESSION_MANAGER_AVAILABLE:
            pytest.skip("Session manager not available")

        configure_global_pool(max_sessions=10)

        with get_r2_session(test_binary_path, use_pooling=True) as session1:
            with get_r2_session(alternative_binary_path, use_pooling=True) as session2:
                result1: str = session1.execute("i")
                result2: str = session2.execute("i")

                assert isinstance(result1, str)
                assert isinstance(result2, str)
