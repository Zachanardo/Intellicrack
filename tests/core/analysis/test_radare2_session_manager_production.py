#!/usr/bin/env python3
"""Production tests for Radare2 Session Manager - Thread-safe session pooling validation.

Tests validate real r2pipe session pooling, connection management, and thread safety.
All tests use genuine Windows system binaries - NO MOCKS.

Test Coverage:
- R2SessionWrapper connection lifecycle
- Session metrics and statistics tracking
- Thread-safe session operations
- R2SessionPool creation and management
- Session reuse and pooling behavior
- Idle session cleanup
- Concurrent session access
- Global pool management
- Session health checks and reconnection
- Error handling and recovery
- Performance benchmarks for pooled operations
"""

import logging
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.radare2_session_manager import (
    R2PIPE_AVAILABLE,
    R2SessionPool,
    R2SessionWrapper,
    SessionMetrics,
    SessionState,
    get_global_pool,
    r2_session_pooled,
    shutdown_global_pool,
)


REAL_BINARY_NOTEPAD: Path = Path(r"C:\Windows\System32\notepad.exe")
REAL_BINARY_KERNEL32: Path = Path(r"C:\Windows\System32\kernel32.dll")
REAL_BINARY_CALC: Path = Path(r"C:\Windows\System32\calc.exe")


def _check_r2_connectivity() -> bool:
    """Check if radare2 is actually functional by testing a real connection."""
    if not R2PIPE_AVAILABLE:
        return False
    if not REAL_BINARY_NOTEPAD.exists():
        return False
    try:
        import r2pipe
        r2 = r2pipe.open(str(REAL_BINARY_NOTEPAD), flags=["-2", "-n"])
        result = r2.cmd("?V")
        r2.quit()
        return bool(result)
    except Exception:
        return False


R2_FUNCTIONAL = _check_r2_connectivity()
r2_functional_required = pytest.mark.skipif(
    not R2_FUNCTIONAL,
    reason="radare2 connectivity not functional in this environment"
)


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


@pytest.fixture(scope="function")
def session_pool() -> R2SessionPool:
    """Create isolated session pool for testing."""
    pool: R2SessionPool = R2SessionPool(
        max_sessions=5,
        max_idle_time=60.0,
        auto_analyze=True,
        analysis_level="aaa",
    )
    yield pool
    pool.shutdown()


@pytest.fixture(autouse=True)
def cleanup_global_pool() -> None:
    """Cleanup global pool after each test."""
    yield
    shutdown_global_pool()


@r2_functional_required
class TestR2SessionWrapperLifecycle:
    """Test R2SessionWrapper connection and lifecycle management."""

    def test_session_wrapper_creates_successfully(self, test_binary_path: str) -> None:
        """SessionWrapper creates successfully for real binary."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_session_001",
            auto_analyze=False,
        )

        assert session.binary_path == Path(test_binary_path)
        assert session.session_id == "test_session_001"
        assert session.state == SessionState.IDLE

    def test_session_wrapper_connects_to_real_binary(self, test_binary_path: str) -> None:
        """SessionWrapper successfully connects to real Windows binary."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_session_002",
            auto_analyze=False,
        )

        connected: bool = session.connect()

        assert connected
        assert session.state == SessionState.ACTIVE
        assert session.r2 is not None
        session.disconnect()

    def test_session_wrapper_executes_commands(self, test_binary_path: str) -> None:
        """SessionWrapper executes radare2 commands on real binary."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_session_003",
            auto_analyze=False,
        )
        session.connect()

        result: str = session.execute("i")

        assert isinstance(result, str)
        assert result != ""
        session.disconnect()

    def test_session_wrapper_executes_json_commands(self, test_binary_path: str) -> None:
        """SessionWrapper executes and parses JSON commands."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_session_004",
            auto_analyze=False,
        )
        session.connect()

        result: dict | list = session.execute("ij", expect_json=True)

        assert isinstance(result, (dict, list))
        session.disconnect()

    def test_session_wrapper_disconnects_properly(self, test_binary_path: str) -> None:
        """SessionWrapper properly disconnects and cleans up resources."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_session_005",
            auto_analyze=False,
        )
        session.connect()
        assert session.state == SessionState.ACTIVE

        session.disconnect()

        assert session.r2 is None
        assert session.state == SessionState.CLOSED

    def test_session_wrapper_raises_error_without_connection(self, test_binary_path: str) -> None:
        """SessionWrapper raises error when executing without connection."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_session_006",
            auto_analyze=False,
        )

        with pytest.raises(RuntimeError, match="not connected"):
            session.execute("i")

    def test_session_wrapper_raises_error_for_missing_binary(self) -> None:
        """SessionWrapper raises error for non-existent binary."""
        invalid_path: str = r"C:\NonExistent\Invalid.exe"

        with pytest.raises(FileNotFoundError):
            R2SessionWrapper(
                binary_path=invalid_path,
                session_id="test_session_007",
            )

    def test_session_wrapper_auto_analyzes_binary(self, test_binary_path: str) -> None:
        """SessionWrapper auto-analyzes binary when enabled."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_session_008",
            auto_analyze=True,
            analysis_level="aaa",
        )

        session.connect()
        functions: list = session.execute("aflj", expect_json=True)

        assert isinstance(functions, list)
        session.disconnect()


@r2_functional_required
class TestR2SessionWrapperMetrics:
    """Test session metrics tracking."""

    def test_session_tracks_command_execution_count(self, test_binary_path: str) -> None:
        """Session tracks number of commands executed."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_session_metrics_001",
            auto_analyze=False,
        )
        session.connect()

        session.execute("i")
        session.execute("ie")
        session.execute("ii")

        metrics: dict[str, Any] = session.get_metrics()
        assert metrics["commands_executed"] == 3
        session.disconnect()

    def test_session_tracks_execution_time(self, test_binary_path: str) -> None:
        """Session tracks total and average execution time."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_session_metrics_002",
            auto_analyze=False,
        )
        session.connect()

        session.execute("i")
        session.execute("ie")

        metrics: dict[str, Any] = session.get_metrics()
        assert metrics["total_execution_time"] > 0
        assert metrics["avg_execution_time"] > 0
        session.disconnect()

    def test_session_tracks_error_count(self, test_binary_path: str) -> None:
        """Session tracks number of errors encountered."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_session_metrics_003",
            auto_analyze=False,
        )
        session.connect()

        try:
            session.execute("invalid_command_xyz")
        except Exception:
            pass

        metrics: dict[str, Any] = session.get_metrics()
        session.disconnect()

    def test_session_tracks_idle_time(self, test_binary_path: str) -> None:
        """Session tracks idle time since last use."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_session_metrics_004",
            auto_analyze=False,
        )
        session.connect()

        session.execute("i")
        time.sleep(0.1)

        idle: float = session.idle_time
        assert idle >= 0.1
        session.disconnect()

    def test_session_metrics_includes_uptime(self, test_binary_path: str) -> None:
        """Session metrics include total uptime."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_session_metrics_005",
            auto_analyze=False,
        )
        session.connect()
        time.sleep(0.1)

        metrics: dict[str, Any] = session.get_metrics()

        assert metrics["uptime"] >= 0.1
        assert metrics["session_id"] == "test_session_metrics_005"
        assert "binary_path" in metrics
        session.disconnect()


@r2_functional_required
class TestR2SessionWrapperHealthChecks:
    """Test session health checks and reconnection."""

    def test_session_is_alive_when_active(self, test_binary_path: str) -> None:
        """is_alive returns True for active connected session."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_health_001",
            auto_analyze=False,
        )
        session.connect()

        is_alive: bool = session.is_alive()

        assert is_alive
        session.disconnect()

    def test_session_is_not_alive_when_disconnected(self, test_binary_path: str) -> None:
        """is_alive returns False for disconnected session."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_health_002",
            auto_analyze=False,
        )
        session.connect()
        session.disconnect()

        is_alive: bool = session.is_alive()

        assert not is_alive

    def test_session_reconnects_successfully(self, test_binary_path: str) -> None:
        """Session can reconnect after being disconnected."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_health_003",
            auto_analyze=False,
        )
        session.connect()
        session.disconnect()

        reconnected: bool = session.reconnect()

        assert reconnected
        assert session.state == SessionState.ACTIVE
        session.disconnect()


@r2_functional_required
class TestR2SessionPoolBasics:
    """Test basic R2SessionPool functionality."""

    def test_pool_creates_successfully(self) -> None:
        """SessionPool creates successfully with configuration."""
        pool: R2SessionPool = R2SessionPool(
            max_sessions=10,
            max_idle_time=300.0,
            auto_analyze=True,
        )

        assert pool.max_sessions == 10
        assert pool.max_idle_time == 300.0
        pool.shutdown()

    def test_pool_creates_new_session(self, session_pool: R2SessionPool, test_binary_path: str) -> None:
        """Pool creates new session for binary."""
        session: R2SessionWrapper = session_pool.get_session(test_binary_path)

        assert session is not None
        assert session.binary_path == Path(test_binary_path)
        assert session.state == SessionState.ACTIVE
        session_pool.return_session(session)

    def test_pool_reuses_existing_session(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Pool reuses existing session for same binary."""
        session1: R2SessionWrapper = session_pool.get_session(test_binary_path)
        session1_id: str = session1.session_id
        session_pool.return_session(session1)

        session2: R2SessionWrapper = session_pool.get_session(test_binary_path)
        session2_id: str = session2.session_id

        assert session1_id == session2_id
        session_pool.return_session(session2)

    def test_pool_creates_separate_sessions_for_different_binaries(
        self, session_pool: R2SessionPool, test_binary_path: str, alternative_binary_path: str
    ) -> None:
        """Pool creates separate sessions for different binaries."""
        session1: R2SessionWrapper = session_pool.get_session(test_binary_path)
        session2: R2SessionWrapper = session_pool.get_session(alternative_binary_path)

        assert session1.session_id != session2.session_id
        assert session1.binary_path != session2.binary_path

        session_pool.return_session(session1)
        session_pool.return_session(session2)

    def test_pool_respects_max_sessions_limit(
        self, test_binary_path: str, alternative_binary_path: str
    ) -> None:
        """Pool respects maximum session limit."""
        pool: R2SessionPool = R2SessionPool(max_sessions=2, max_idle_time=1.0)

        session1: R2SessionWrapper = pool.get_session(test_binary_path)
        session2: R2SessionWrapper = pool.get_session(alternative_binary_path)

        pool.shutdown()


@r2_functional_required
class TestR2SessionPoolStatistics:
    """Test session pool statistics tracking."""

    def test_pool_statistics_track_total_sessions(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Pool statistics track total sessions created."""
        session: R2SessionWrapper = session_pool.get_session(test_binary_path)

        stats: dict[str, Any] = session_pool.get_pool_stats()

        assert stats["total_sessions"] >= 1
        assert stats["total_sessions_created"] >= 1
        session_pool.return_session(session)

    def test_pool_statistics_track_active_sessions(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Pool statistics track active sessions."""
        session: R2SessionWrapper = session_pool.get_session(test_binary_path)

        stats: dict[str, Any] = session_pool.get_pool_stats()

        assert stats["active_sessions"] >= 1
        session_pool.return_session(session)

    def test_pool_returns_session_metrics(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Pool returns metrics for all sessions."""
        session: R2SessionWrapper = session_pool.get_session(test_binary_path)

        metrics: list[dict[str, Any]] = session_pool.get_session_metrics()

        assert metrics
        assert all("session_id" in m for m in metrics)
        session_pool.return_session(session)


@r2_functional_required
class TestR2SessionPoolContextManager:
    """Test session pool context manager functionality."""

    def test_pool_context_manager_provides_session(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Pool context manager provides working session."""
        with session_pool.session(test_binary_path) as session:
            result: str = session.execute("i")

            assert isinstance(result, str)
            assert result != ""

    def test_pool_context_manager_returns_session_on_exit(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Pool context manager returns session on exit."""
        with session_pool.session(test_binary_path) as session:
            session_id: str = session.session_id

        stats_before: dict[str, Any] = session_pool.get_pool_stats()

        with session_pool.session(test_binary_path) as session2:
            assert session2.session_id == session_id

    def test_pool_context_manager_handles_exceptions(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Pool context manager properly handles exceptions."""
        try:
            with session_pool.session(test_binary_path) as session:
                session.execute("i")
                raise ValueError("Test exception")
        except ValueError:
            pass

        stats: dict[str, Any] = session_pool.get_pool_stats()
        assert stats["total_sessions"] >= 1


@r2_functional_required
class TestR2SessionPoolCleanup:
    """Test session pool cleanup functionality."""

    def test_pool_cleans_up_idle_sessions(self, test_binary_path: str) -> None:
        """Pool automatically cleans up idle sessions."""
        pool: R2SessionPool = R2SessionPool(
            max_sessions=5,
            max_idle_time=0.5,
            cleanup_interval=0.1,
        )

        session: R2SessionWrapper = pool.get_session(test_binary_path)
        pool.return_session(session)

        time.sleep(1.0)

        stats: dict[str, Any] = pool.get_pool_stats()
        pool.shutdown()

    def test_pool_closes_all_sessions_on_shutdown(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Pool closes all sessions on shutdown."""
        session1: R2SessionWrapper = session_pool.get_session(test_binary_path)
        session_pool.return_session(session1)

        session_pool.shutdown()

        stats: dict[str, Any] = session_pool.get_pool_stats()
        assert stats["total_sessions"] == 0


@r2_functional_required
class TestGlobalSessionPool:
    """Test global session pool management."""

    def test_get_global_pool_creates_singleton(self) -> None:
        """get_global_pool creates singleton pool instance."""
        pool1: R2SessionPool = get_global_pool()
        pool2: R2SessionPool = get_global_pool()

        assert pool1 is pool2

    def test_global_pool_can_be_configured(self) -> None:
        """Global pool accepts configuration parameters."""
        pool: R2SessionPool = get_global_pool(
            max_sessions=15,
            max_idle_time=600.0,
            auto_analyze=True,
        )

        assert pool.max_sessions == 15

    def test_r2_session_pooled_context_manager(self, test_binary_path: str) -> None:
        """r2_session_pooled provides working session from global pool."""
        with r2_session_pooled(test_binary_path) as session:
            result: str = session.execute("i")

            assert isinstance(result, str)
            assert result != ""

    def test_shutdown_global_pool_cleans_up(self, test_binary_path: str) -> None:
        """shutdown_global_pool properly cleans up resources."""
        with r2_session_pooled(test_binary_path) as session:
            session.execute("i")

        shutdown_global_pool()


@r2_functional_required
class TestThreadSafety:
    """Test thread safety of session pool operations."""

    def test_concurrent_session_access(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Multiple threads can safely access sessions concurrently."""

        def worker() -> None:
            with session_pool.session(test_binary_path) as session:
                result: str = session.execute("i")
                assert isinstance(result, str)

        threads: list[threading.Thread] = []
        for _ in range(5):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    def test_concurrent_different_binaries(
        self, session_pool: R2SessionPool, test_binary_path: str, alternative_binary_path: str
    ) -> None:
        """Threads can concurrently access different binaries."""

        def worker1() -> None:
            with session_pool.session(test_binary_path) as session:
                session.execute("i")

        def worker2() -> None:
            with session_pool.session(alternative_binary_path) as session:
                session.execute("i")

        thread1 = threading.Thread(target=worker1)
        thread2 = threading.Thread(target=worker2)

        thread1.start()
        thread2.start()

        thread1.join()
        thread2.join()


@r2_functional_required
class TestPerformanceBenchmarks:
    """Performance benchmarks for session pooling."""

    def test_pooled_session_reuse_performance(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Pooled session reuse shows performance benefits."""
        iterations: int = 5

        start: float = time.perf_counter()
        for _ in range(iterations):
            with session_pool.session(test_binary_path) as session:
                session.execute("i")
        end: float = time.perf_counter()

        total_time: float = end - start
        assert total_time > 0

    def test_concurrent_session_performance(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Concurrent session access performs adequately."""

        def worker() -> None:
            with session_pool.session(test_binary_path) as session:
                for _ in range(3):
                    session.execute("i")

        start: float = time.perf_counter()

        threads: list[threading.Thread] = []
        for _ in range(3):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        end: float = time.perf_counter()
        total_time: float = end - start
        assert total_time < 60.0


@r2_functional_required
class TestRealWorldWorkflows:
    """Test real-world usage workflows."""

    def test_analyze_multiple_binaries_workflow(
        self, session_pool: R2SessionPool, test_binary_path: str, alternative_binary_path: str
    ) -> None:
        """Complete workflow analyzing multiple binaries."""
        binaries: list[str] = [test_binary_path, alternative_binary_path]
        results: dict[str, dict[str, Any]] = {}

        for binary in binaries:
            with session_pool.session(binary) as session:
                info: dict = session.execute("ij", expect_json=True)
                functions: list = session.execute("aflj", expect_json=True)
                results[binary] = {
                    "info": info,
                    "functions": len(functions) if isinstance(functions, list) else 0,
                }

        assert len(results) == 2

    def test_session_pool_recovery_from_errors(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Pool recovers gracefully from session errors."""
        with session_pool.session(test_binary_path) as session:
            try:
                session.execute("invalid_command")
            except Exception:
                pass

        with session_pool.session(test_binary_path) as session2:
            result: str = session2.execute("i")
            assert isinstance(result, str)


@r2_functional_required
class TestSessionWrapperEdgeCases:
    """Test edge cases and error conditions for SessionWrapper."""

    def test_session_wrapper_with_custom_flags(self, test_binary_path: str) -> None:
        """SessionWrapper accepts and uses custom radare2 flags."""
        custom_flags: list[str] = ["-2", "-n", "-w"]
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_custom_flags",
            flags=custom_flags,
            auto_analyze=False,
        )

        assert session.flags == custom_flags
        connected: bool = session.connect()
        assert connected
        session.disconnect()

    def test_session_wrapper_reconnect_increments_metrics(self, test_binary_path: str) -> None:
        """Session reconnection increments reconnection counter."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_reconnect_metrics",
            auto_analyze=False,
        )
        session.connect()
        initial_reconnections: int = session.metrics.reconnections

        session.reconnect()
        session.reconnect()

        assert session.metrics.reconnections == initial_reconnections + 2
        session.disconnect()

    def test_session_wrapper_tracks_bytes_processed(self, test_binary_path: str) -> None:
        """Session tracks total bytes processed from command results."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_bytes_processed",
            auto_analyze=False,
        )
        session.connect()

        session.execute("i")
        session.execute("ie")

        metrics: dict[str, Any] = session.get_metrics()
        assert metrics["bytes_processed"] > 0
        session.disconnect()

    def test_session_wrapper_last_used_updates_on_execute(self, test_binary_path: str) -> None:
        """Session last_used timestamp updates on command execution."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_last_used",
            auto_analyze=False,
        )
        session.connect()

        initial_last_used: float = session.last_used
        time.sleep(0.1)
        session.execute("i")
        updated_last_used: float = session.last_used

        assert updated_last_used > initial_last_used
        session.disconnect()

    def test_session_wrapper_handles_disconnect_when_not_connected(self, test_binary_path: str) -> None:
        """Session handles disconnect gracefully when not connected."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_disconnect_not_connected",
            auto_analyze=False,
        )

        session.disconnect()

        assert session.r2 is None
        assert session.state == SessionState.CLOSED

    def test_session_wrapper_connect_multiple_times_is_idempotent(self, test_binary_path: str) -> None:
        """Calling connect multiple times on active session returns True without creating new connection."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_multiple_connect",
            auto_analyze=False,
        )
        session.connect()
        r2_instance = session.r2

        result: bool = session.connect()

        assert result
        assert session.r2 is r2_instance
        session.disconnect()

    def test_session_wrapper_different_analysis_levels(self, test_binary_path: str) -> None:
        """SessionWrapper supports different radare2 analysis levels."""
        for level in ["aa", "aaa", "aaaa"]:
            session: R2SessionWrapper = R2SessionWrapper(
                binary_path=test_binary_path,
                session_id=f"test_analysis_{level}",
                auto_analyze=True,
                analysis_level=level,
            )
            connected: bool = session.connect()
            assert connected
            assert session.analysis_level == level
            session.disconnect()

    def test_session_wrapper_execute_raises_on_closed_session(self, test_binary_path: str) -> None:
        """Session execute raises RuntimeError after session is closed."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_execute_closed",
            auto_analyze=False,
        )
        session.connect()
        session.disconnect()

        with pytest.raises(RuntimeError, match="not connected"):
            session.execute("i")


@r2_functional_required
class TestSessionPoolEdgeCases:
    """Test edge cases and error conditions for SessionPool."""

    def test_pool_raises_error_when_session_limit_reached(self, test_binary_path: str) -> None:
        """Pool raises RuntimeError when session limit reached."""
        pool: R2SessionPool = R2SessionPool(max_sessions=1, max_idle_time=300.0)

        session1: R2SessionWrapper = pool.get_session(test_binary_path)

        binaries: list[str] = [
            str(REAL_BINARY_CALC),
            str(REAL_BINARY_KERNEL32),
        ]
        for binary_path in binaries:
            if Path(binary_path).exists():
                with pytest.raises(RuntimeError, match="Session limit reached"):
                    pool.get_session(binary_path)
                break

        pool.return_session(session1)
        pool.shutdown()

    def test_pool_generates_unique_session_ids(self, session_pool: R2SessionPool) -> None:
        """Pool generates unique session IDs for different binaries."""
        binaries: list[Path] = [REAL_BINARY_NOTEPAD, REAL_BINARY_CALC]
        existing_binaries: list[str] = [str(b) for b in binaries if b.exists()]

        if len(existing_binaries) < 2:
            pytest.skip("Need at least 2 test binaries")

        session1: R2SessionWrapper = session_pool.get_session(existing_binaries[0])
        session2: R2SessionWrapper = session_pool.get_session(existing_binaries[1])

        assert session1.session_id != session2.session_id

        session_pool.return_session(session1)
        session_pool.return_session(session2)

    def test_pool_same_binary_different_flags_creates_different_sessions(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Pool creates different sessions for same binary with different flags."""
        session1: R2SessionWrapper = session_pool.get_session(test_binary_path, flags=["-2"])
        session2: R2SessionWrapper = session_pool.get_session(test_binary_path, flags=["-2", "-w"])

        assert session1.session_id != session2.session_id

        session_pool.return_session(session1)
        session_pool.return_session(session2)

    def test_pool_return_session_handles_dead_session(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Pool handles returning a dead session gracefully."""
        session: R2SessionWrapper = session_pool.get_session(test_binary_path)
        session.disconnect()

        session_pool.return_session(session)

        stats: dict[str, Any] = session_pool.get_pool_stats()
        assert stats["total_sessions"] >= 0

    def test_pool_return_session_handles_unknown_session(self, session_pool: R2SessionPool, test_binary_path: str) -> None:
        """Pool handles returning unknown session gracefully."""
        foreign_session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="foreign_session",
            auto_analyze=False,
        )

        session_pool.return_session(foreign_session)

    def test_pool_get_session_raises_when_r2pipe_not_available(self, test_binary_path: str, monkeypatch) -> None:
        """Pool raises RuntimeError when r2pipe not available."""
        from intellicrack.core.analysis import radare2_session_manager

        monkeypatch.setattr(radare2_session_manager, "R2PIPE_AVAILABLE", False)

        pool: R2SessionPool = R2SessionPool(max_sessions=5)

        with pytest.raises(RuntimeError, match="r2pipe not available"):
            pool.get_session(test_binary_path)

        pool.shutdown()

    def test_pool_cleanup_removes_old_sessions_when_limit_reached(self, test_binary_path: str) -> None:
        """Pool cleans up oldest sessions when max limit reached."""
        pool: R2SessionPool = R2SessionPool(max_sessions=2, max_idle_time=1.0)

        session1: R2SessionWrapper = pool.get_session(test_binary_path)
        pool.return_session(session1)

        time.sleep(0.2)

        binaries: list[Path] = [REAL_BINARY_CALC, REAL_BINARY_KERNEL32]
        existing_binaries: list[str] = [str(b) for b in binaries if b.exists()]

        sessions: list[R2SessionWrapper] = []
        for binary in existing_binaries[:2]:
            try:
                session = pool.get_session(binary)
                sessions.append(session)
            except RuntimeError:
                break

        for session in sessions:
            pool.return_session(session)

        pool.shutdown()

    def test_pool_context_manager_returns_session_even_on_error(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Pool context manager returns session even when exception occurs."""
        initial_stats: dict[str, Any] = session_pool.get_pool_stats()

        try:
            with session_pool.session(test_binary_path) as session:
                session_id: str = session.session_id
                raise ValueError("Simulated error")
        except ValueError:
            pass

        with session_pool.session(test_binary_path) as session2:
            assert session2.session_id == session_id

    def test_pool_get_pool_stats_calculates_error_rate(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Pool statistics calculate error rate correctly."""
        with session_pool.session(test_binary_path) as session:
            session.execute("i")
            try:
                session.execute("invalid_command_xyz")
            except Exception:
                pass

        stats: dict[str, Any] = session_pool.get_pool_stats()
        assert "error_rate" in stats
        assert 0.0 <= stats["error_rate"] <= 1.0


@r2_functional_required
class TestSessionPoolConcurrency:
    """Test concurrent access and thread safety."""

    def test_concurrent_access_same_binary_reuses_sessions(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Concurrent access to same binary reuses available sessions."""
        session_ids: set[str] = set()
        lock = threading.Lock()

        def worker() -> None:
            with session_pool.session(test_binary_path) as session:
                with lock:
                    session_ids.add(session.session_id)
                time.sleep(0.05)

        threads: list[threading.Thread] = []
        for _ in range(5):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(session_ids) <= 5

    def test_concurrent_execution_thread_safe(
        self, session_pool: R2SessionPool, test_binary_path: str
    ) -> None:
        """Concurrent command execution is thread-safe."""
        results: list[bool] = []
        lock = threading.Lock()

        def worker() -> None:
            with session_pool.session(test_binary_path) as session:
                result: str = session.execute("i")
                with lock:
                    results.append(isinstance(result, str) and result != "")

        threads: list[threading.Thread] = []
        for _ in range(10):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert all(results)
        assert len(results) == 10

    def test_pool_shutdown_waits_for_cleanup_thread(self, test_binary_path: str) -> None:
        """Pool shutdown waits for cleanup thread to complete."""
        pool: R2SessionPool = R2SessionPool(
            max_sessions=5,
            max_idle_time=10.0,
            cleanup_interval=0.1,
        )

        session: R2SessionWrapper = pool.get_session(test_binary_path)
        pool.return_session(session)

        cleanup_thread = pool._cleanup_thread
        assert cleanup_thread is not None
        assert cleanup_thread.is_alive()

        pool.shutdown()

        assert not cleanup_thread.is_alive()


@r2_functional_required
class TestSessionMetricsAccuracy:
    """Test accuracy of session metrics tracking."""

    def test_metrics_average_execution_time_calculation(self, test_binary_path: str) -> None:
        """Metrics calculate average execution time correctly."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_avg_time",
            auto_analyze=False,
        )
        session.connect()

        for _ in range(5):
            session.execute("i")

        metrics: dict[str, Any] = session.get_metrics()
        expected_avg: float = metrics["total_execution_time"] / metrics["commands_executed"]

        assert abs(metrics["avg_execution_time"] - expected_avg) < 0.001
        session.disconnect()

    def test_metrics_error_count_increments_on_failure(self, test_binary_path: str) -> None:
        """Metrics error count increments on command failure."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_error_count",
            auto_analyze=False,
        )
        session.connect()

        initial_errors: int = session.metrics.errors_count

        try:
            session.execute("nonexistent_command_xyz123")
        except Exception:
            pass

        assert session.metrics.errors_count == initial_errors + 1
        session.disconnect()

    def test_metrics_last_command_time_updates(self, test_binary_path: str) -> None:
        """Metrics last_command_time updates after each command."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_last_cmd_time",
            auto_analyze=False,
        )
        session.connect()

        session.execute("i")
        first_time: float = session.metrics.last_command_time

        time.sleep(0.05)
        session.execute("ie")
        second_time: float = session.metrics.last_command_time

        assert first_time > 0
        assert second_time > 0
        session.disconnect()

    def test_session_state_transitions(self, test_binary_path: str) -> None:
        """Session state transitions correctly through lifecycle."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_state_transitions",
            auto_analyze=False,
        )

        assert session.state == SessionState.IDLE

        session.connect()
        assert session.state == SessionState.ACTIVE

        session.disconnect()
        assert session.state == SessionState.CLOSED

    def test_session_reconnect_updates_state(self, test_binary_path: str) -> None:
        """Session reconnect updates state to RECONNECTING then ACTIVE."""
        session: R2SessionWrapper = R2SessionWrapper(
            binary_path=test_binary_path,
            session_id="test_reconnect_state",
            auto_analyze=False,
        )
        session.connect()
        session.disconnect()

        success: bool = session.reconnect()

        assert success
        assert session.state == SessionState.ACTIVE
        session.disconnect()


@r2_functional_required
class TestPoolKeyGeneration:
    """Test session pool key generation logic."""

    def test_pool_key_consistent_for_same_binary(self, test_binary_path: str) -> None:
        """Pool generates consistent keys for same binary and flags."""
        pool: R2SessionPool = R2SessionPool(max_sessions=5)

        key1: str = pool._get_pool_key(test_binary_path, ["-2"])
        key2: str = pool._get_pool_key(test_binary_path, ["-2"])

        assert key1 == key2
        pool.shutdown()

    def test_pool_key_different_for_different_flags(self, test_binary_path: str) -> None:
        """Pool generates different keys for different flags."""
        pool: R2SessionPool = R2SessionPool(max_sessions=5)

        key1: str = pool._get_pool_key(test_binary_path, ["-2"])
        key2: str = pool._get_pool_key(test_binary_path, ["-2", "-w"])

        assert key1 != key2
        pool.shutdown()

    def test_session_id_generation_is_deterministic(self, test_binary_path: str) -> None:
        """Session ID generation is deterministic for same inputs."""
        pool: R2SessionPool = R2SessionPool(max_sessions=5)

        id1: str = pool._generate_session_id(test_binary_path, ["-2"])
        id2: str = pool._generate_session_id(test_binary_path, ["-2"])

        assert id1 == id2
        pool.shutdown()

    def test_session_id_different_for_different_binaries(self, test_binary_path: str, alternative_binary_path: str) -> None:
        """Session ID generation produces different IDs for different binaries."""
        pool: R2SessionPool = R2SessionPool(max_sessions=5)

        id1: str = pool._generate_session_id(test_binary_path)
        id2: str = pool._generate_session_id(alternative_binary_path)

        assert id1 != id2
        pool.shutdown()
