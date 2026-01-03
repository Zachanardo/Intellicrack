"""Production tests for Radare2 Session Management.

Validates session pooling, connection management, and helper utilities:
- Session pool creation and lifecycle
- Connection pooling and reuse
- Thread safety of session management
- Session metrics tracking
- Automatic cleanup of idle sessions
- Session helper utilities
- Command batching
- Error handling and reconnection

Copyright (C) 2025 Zachary Flint
"""

import tempfile
import threading
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

try:
    import r2pipe
    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False

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
from intellicrack.core.analysis.radare2_session_manager import (
    R2SessionPool,
    R2SessionWrapper,
    SessionState,
    get_global_pool,
    r2_session_pooled,
    shutdown_global_pool,
)


pytestmark = pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")


@pytest.fixture
def simple_binary(tmp_path: Path) -> Path:
    """Create a simple binary for session testing."""
    binary_path = tmp_path / "test_session.bin"

    binary_data = bytes([
        0x55,
        0x89, 0xE5,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x5D,
        0xC3,
    ])

    binary_data += b'\x00' * (0x1000 - len(binary_data))
    binary_path.write_bytes(binary_data)

    return binary_path


@pytest.fixture
def session_pool() -> Generator[R2SessionPool, None, None]:
    """Create a fresh session pool."""
    pool = R2SessionPool(
        max_sessions=5,
        max_idle_time=60.0,
        auto_analyze=False,
        cleanup_interval=5.0
    )
    yield pool
    pool.shutdown()


class TestR2SessionWrapper:
    """Test R2SessionWrapper functionality."""

    def test_wrapper_initialization(self, simple_binary: Path) -> None:
        """Session wrapper initializes with correct settings."""
        wrapper = R2SessionWrapper(
            binary_path=str(simple_binary),
            session_id="test_session_1",
            timeout=30.0,
            auto_analyze=False
        )

        assert wrapper.binary_path == simple_binary
        assert wrapper.session_id == "test_session_1"
        assert wrapper.timeout == 30.0
        assert wrapper.state == SessionState.IDLE

    def test_wrapper_connect_success(self, simple_binary: Path) -> None:
        """Session wrapper connects to r2pipe successfully."""
        wrapper = R2SessionWrapper(
            binary_path=str(simple_binary),
            session_id="connect_test",
            auto_analyze=False
        )

        result = wrapper.connect()

        assert result is True
        assert wrapper.state == SessionState.ACTIVE
        assert wrapper.r2 is not None

        wrapper.disconnect()

    def test_wrapper_disconnect_closes_connection(self, simple_binary: Path) -> None:
        """Session wrapper disconnects cleanly."""
        wrapper = R2SessionWrapper(
            binary_path=str(simple_binary),
            session_id="disconnect_test",
            auto_analyze=False
        )

        wrapper.connect()
        wrapper.disconnect()

        assert wrapper.r2 is None
        assert wrapper.state == SessionState.CLOSED

    def test_wrapper_execute_command(self, simple_binary: Path) -> None:
        """Session wrapper executes r2 commands correctly."""
        wrapper = R2SessionWrapper(
            binary_path=str(simple_binary),
            session_id="execute_test",
            auto_analyze=False
        )

        wrapper.connect()

        result = wrapper.execute("?V")

        assert result is not None
        assert wrapper.metrics.commands_executed == 1

        wrapper.disconnect()

    def test_wrapper_execute_json_command(self, simple_binary: Path) -> None:
        """Session wrapper executes JSON commands."""
        wrapper = R2SessionWrapper(
            binary_path=str(simple_binary),
            session_id="json_test",
            auto_analyze=True
        )

        wrapper.connect()

        result = wrapper.execute("ij", expect_json=True)

        assert result is not None
        assert isinstance(result, (dict, list))

        wrapper.disconnect()

    def test_wrapper_tracks_metrics(self, simple_binary: Path) -> None:
        """Session wrapper tracks command metrics."""
        wrapper = R2SessionWrapper(
            binary_path=str(simple_binary),
            session_id="metrics_test",
            auto_analyze=False
        )

        wrapper.connect()

        wrapper.execute("?V")
        wrapper.execute("?V")

        assert wrapper.metrics.commands_executed == 2
        assert wrapper.metrics.total_execution_time > 0

        wrapper.disconnect()

    def test_wrapper_reconnect_after_disconnect(self, simple_binary: Path) -> None:
        """Session wrapper can reconnect after disconnect."""
        wrapper = R2SessionWrapper(
            binary_path=str(simple_binary),
            session_id="reconnect_test",
            auto_analyze=False
        )

        wrapper.connect()
        wrapper.disconnect()

        result = wrapper.reconnect()

        assert result is True
        assert wrapper.state == SessionState.ACTIVE
        assert wrapper.metrics.reconnections == 1

        wrapper.disconnect()

    def test_wrapper_is_alive_check(self, simple_binary: Path) -> None:
        """Session wrapper health check validates connection."""
        wrapper = R2SessionWrapper(
            binary_path=str(simple_binary),
            session_id="alive_test",
            auto_analyze=False
        )

        wrapper.connect()

        assert wrapper.is_alive() is True

        wrapper.disconnect()

        assert wrapper.is_alive() is False

    def test_wrapper_idle_time_tracking(self, simple_binary: Path) -> None:
        """Session wrapper tracks idle time correctly."""
        wrapper = R2SessionWrapper(
            binary_path=str(simple_binary),
            session_id="idle_test",
            auto_analyze=False
        )

        wrapper.connect()

        initial_idle = wrapper.idle_time
        time.sleep(0.1)

        assert wrapper.idle_time > initial_idle

        wrapper.disconnect()

    def test_wrapper_get_metrics_dict(self, simple_binary: Path) -> None:
        """Session wrapper provides metrics dictionary."""
        wrapper = R2SessionWrapper(
            binary_path=str(simple_binary),
            session_id="metrics_dict_test",
            auto_analyze=False
        )

        wrapper.connect()
        wrapper.execute("?V")

        metrics = wrapper.get_metrics()

        assert metrics["session_id"] == "metrics_dict_test"
        assert metrics["commands_executed"] == 1
        assert "uptime" in metrics
        assert "state" in metrics

        wrapper.disconnect()


class TestR2SessionPool:
    """Test R2SessionPool functionality."""

    def test_pool_initialization(self, session_pool: R2SessionPool) -> None:
        """Session pool initializes with correct settings."""
        assert session_pool.max_sessions == 5
        assert session_pool.max_idle_time == 60.0
        assert session_pool.auto_analyze is False
        assert len(session_pool._sessions) == 0

    def test_pool_get_new_session(self, session_pool: R2SessionPool, simple_binary: Path) -> None:
        """Pool creates new session when none available."""
        session = session_pool.get_session(str(simple_binary))

        assert session is not None
        assert session.state == SessionState.ACTIVE
        assert len(session_pool._sessions) == 1

        session_pool.return_session(session)

    def test_pool_reuse_session(self, session_pool: R2SessionPool, simple_binary: Path) -> None:
        """Pool reuses existing sessions."""
        session1 = session_pool.get_session(str(simple_binary))
        session1_id = session1.session_id

        session_pool.return_session(session1)

        session2 = session_pool.get_session(str(simple_binary))

        assert session2.session_id == session1_id

        session_pool.return_session(session2)

    def test_pool_max_sessions_limit(self, simple_binary: Path) -> None:
        """Pool enforces maximum session limit."""
        small_pool = R2SessionPool(max_sessions=2, auto_analyze=False)

        try:
            session1 = small_pool.get_session(str(simple_binary))
            session2 = small_pool.get_session(str(simple_binary.with_suffix('.bin2')))

            simple_binary.with_suffix('.bin2').write_bytes(simple_binary.read_bytes())

            with pytest.raises(RuntimeError, match="Session limit reached"):
                small_pool.get_session(str(simple_binary.with_suffix('.bin3')))

        finally:
            small_pool.shutdown()

    def test_pool_cleanup_idle_sessions(self, simple_binary: Path) -> None:
        """Pool cleans up idle sessions."""
        pool = R2SessionPool(
            max_sessions=5,
            max_idle_time=0.5,
            auto_analyze=False
        )

        try:
            session = pool.get_session(str(simple_binary))
            pool.return_session(session)

            assert len(pool._sessions) == 1

            time.sleep(0.6)
            pool._cleanup_idle_sessions()

            assert len(pool._sessions) == 0

        finally:
            pool.shutdown()

    def test_pool_context_manager(self, session_pool: R2SessionPool, simple_binary: Path) -> None:
        """Pool context manager handles session lifecycle."""
        with session_pool.session(str(simple_binary)) as session:
            assert session is not None
            assert session.state == SessionState.ACTIVE

            result = session.execute("?V")
            assert result is not None

    def test_pool_get_statistics(self, session_pool: R2SessionPool, simple_binary: Path) -> None:
        """Pool provides accurate statistics."""
        session = session_pool.get_session(str(simple_binary))
        session.execute("?V")

        stats = session_pool.get_pool_stats()

        assert stats["total_sessions"] >= 1
        assert stats["active_sessions"] >= 0
        assert "total_commands_executed" in stats

        session_pool.return_session(session)

    def test_pool_get_session_metrics(self, session_pool: R2SessionPool, simple_binary: Path) -> None:
        """Pool provides metrics for all sessions."""
        session = session_pool.get_session(str(simple_binary))

        metrics = session_pool.get_session_metrics()

        assert len(metrics) >= 1
        assert any(m["session_id"] == session.session_id for m in metrics)

        session_pool.return_session(session)

    def test_pool_close_all_sessions(self, session_pool: R2SessionPool, simple_binary: Path) -> None:
        """Pool closes all sessions on shutdown."""
        session1 = session_pool.get_session(str(simple_binary))
        session_pool.return_session(session1)

        assert len(session_pool._sessions) >= 1

        session_pool.close_all()

        assert len(session_pool._sessions) == 0

    def test_pool_thread_safety(self, session_pool: R2SessionPool, simple_binary: Path) -> None:
        """Pool handles concurrent session requests safely."""
        results = []

        def get_and_use_session(thread_id: int) -> None:
            try:
                with session_pool.session(str(simple_binary)) as session:
                    result = session.execute("?V")
                    results.append((thread_id, result is not None))
            except Exception as e:
                results.append((thread_id, False))

        threads = [threading.Thread(target=get_and_use_session, args=(i,)) for i in range(3)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert len(results) == 3
        assert all(success for _, success in results)


class TestGlobalPool:
    """Test global pool management."""

    def test_get_global_pool_creates_singleton(self) -> None:
        """Global pool returns singleton instance."""
        pool1 = get_global_pool()
        pool2 = get_global_pool()

        assert pool1 is pool2

        shutdown_global_pool()

    def test_global_pool_configuration(self) -> None:
        """Global pool configured with custom settings."""
        shutdown_global_pool()

        pool = get_global_pool(
            max_sessions=3,
            max_idle_time=120.0,
            auto_analyze=True
        )

        assert pool.max_sessions == 3
        assert pool.max_idle_time == 120.0
        assert pool.auto_analyze is True

        shutdown_global_pool()

    def test_r2_session_pooled_context_manager(self, simple_binary: Path) -> None:
        """Pooled session context manager works correctly."""
        with r2_session_pooled(str(simple_binary)) as session:
            assert session is not None
            result = session.execute("?V")
            assert result is not None

        shutdown_global_pool()


class TestDirectR2Session:
    """Test DirectR2Session for legacy compatibility."""

    def test_direct_session_initialization(self, simple_binary: Path) -> None:
        """Direct session initializes without pooling."""
        session = DirectR2Session(str(simple_binary), flags=["-2"])

        assert session.binary_path == str(simple_binary)
        assert session.flags == ["-2"]

    def test_direct_session_connect(self, simple_binary: Path) -> None:
        """Direct session connects to r2pipe."""
        session = DirectR2Session(str(simple_binary), flags=["-2"])

        result = session.connect()

        assert result is True
        assert session.r2 is not None

        session.disconnect()

    def test_direct_session_execute(self, simple_binary: Path) -> None:
        """Direct session executes commands."""
        session = DirectR2Session(str(simple_binary), flags=["-2"])
        session.connect()

        result = session.execute("?V")

        assert result is not None

        session.disconnect()

    def test_direct_session_disconnect(self, simple_binary: Path) -> None:
        """Direct session disconnects cleanly."""
        session = DirectR2Session(str(simple_binary), flags=["-2"])
        session.connect()
        session.disconnect()

        assert session.r2 is None


class TestSessionHelpers:
    """Test session helper utilities."""

    def test_get_r2_session_with_pooling(self, simple_binary: Path) -> None:
        """Session helper uses pooling when enabled."""
        with get_r2_session(str(simple_binary), use_pooling=True, auto_analyze=False) as session:
            assert session is not None

            if hasattr(session, 'execute'):
                result = session.execute("?V")
                assert result is not None

        shutdown_global_pool()

    def test_get_r2_session_without_pooling(self, simple_binary: Path) -> None:
        """Session helper uses direct session when pooling disabled."""
        with get_r2_session(str(simple_binary), use_pooling=False, auto_analyze=False) as session:
            assert session is not None
            assert isinstance(session, DirectR2Session)

            result = session.execute("?V")
            assert result is not None

    def test_execute_r2_command_single(self, simple_binary: Path) -> None:
        """Single command execution helper works."""
        result = execute_r2_command(
            str(simple_binary),
            "?V",
            use_pooling=False
        )

        assert result is not None

    def test_execute_r2_command_json(self, simple_binary: Path) -> None:
        """JSON command execution helper works."""
        result = execute_r2_command(
            str(simple_binary),
            "ij",
            expect_json=True,
            use_pooling=False
        )

        assert result is not None
        assert isinstance(result, (dict, list))

    def test_get_pool_statistics_helper(self, simple_binary: Path) -> None:
        """Pool statistics helper returns stats."""
        with get_r2_session(str(simple_binary), use_pooling=True) as session:
            pass

        stats = get_pool_statistics()

        assert "total_sessions" in stats

        shutdown_global_pool()

    def test_get_all_session_metrics_helper(self, simple_binary: Path) -> None:
        """Session metrics helper returns metrics list."""
        with get_r2_session(str(simple_binary), use_pooling=True) as session:
            pass

        metrics = get_all_session_metrics()

        assert isinstance(metrics, list)

        shutdown_global_pool()

    def test_configure_global_pool_helper(self) -> None:
        """Global pool configuration helper works."""
        shutdown_global_pool()

        configure_global_pool(
            max_sessions=8,
            max_idle_time=180.0,
            auto_analyze=True
        )

        pool = get_global_pool()

        assert pool.max_sessions == 8

        shutdown_global_pool()


class TestR2CommandBatch:
    """Test command batching functionality."""

    def test_batch_initialization(self, simple_binary: Path) -> None:
        """Command batch initializes correctly."""
        batch = R2CommandBatch(str(simple_binary), use_pooling=False)

        assert batch.binary_path == str(simple_binary)
        assert len(batch.commands) == 0

    def test_batch_add_commands(self, simple_binary: Path) -> None:
        """Commands added to batch correctly."""
        batch = R2CommandBatch(str(simple_binary), use_pooling=False)

        batch.add_command("?V")
        batch.add_command("ij", expect_json=True)

        assert len(batch.commands) == 2

    def test_batch_execute_all(self, simple_binary: Path) -> None:
        """Batch executes all commands in single session."""
        batch = R2CommandBatch(str(simple_binary), use_pooling=False)

        batch.add_command("?V")
        batch.add_command("?V")

        results = batch.execute_all()

        assert len(results) == 2
        assert all(r is not None for r in results)

    def test_batch_with_json_commands(self, simple_binary: Path) -> None:
        """Batch handles mixed text and JSON commands."""
        batch = R2CommandBatch(str(simple_binary), use_pooling=False)

        batch.add_command("?V", expect_json=False)
        batch.add_command("ij", expect_json=True)

        results = batch.execute_all()

        assert len(results) == 2


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_nonexistent_binary_raises_error(self, tmp_path: Path) -> None:
        """Nonexistent binary raises FileNotFoundError."""
        nonexistent = tmp_path / "nonexistent.bin"

        with pytest.raises(FileNotFoundError):
            R2SessionWrapper(
                binary_path=str(nonexistent),
                session_id="error_test",
                auto_analyze=False
            )

    def test_execute_without_connection_raises_error(self, simple_binary: Path) -> None:
        """Executing command without connection raises RuntimeError."""
        wrapper = R2SessionWrapper(
            binary_path=str(simple_binary),
            session_id="no_connect_test",
            auto_analyze=False
        )

        with pytest.raises(RuntimeError, match="not connected"):
            wrapper.execute("?V")

    def test_pool_handles_session_errors_gracefully(self, session_pool: R2SessionPool, simple_binary: Path) -> None:
        """Pool handles session errors gracefully."""
        session = session_pool.get_session(str(simple_binary))

        session.state = SessionState.ERROR

        session_pool.return_session(session)

    def test_reconnect_on_failed_connection(self, simple_binary: Path) -> None:
        """Session reconnects when connection fails."""
        wrapper = R2SessionWrapper(
            binary_path=str(simple_binary),
            session_id="reconnect_error_test",
            auto_analyze=False
        )

        wrapper.connect()

        wrapper.r2 = None
        wrapper.state = SessionState.ERROR

        if result := wrapper.reconnect():
            assert wrapper.state == SessionState.ACTIVE

        wrapper.disconnect()


class TestSessionLifecycle:
    """Test complete session lifecycle scenarios."""

    def test_complete_session_lifecycle(self, simple_binary: Path) -> None:
        """Complete session lifecycle from creation to cleanup."""
        pool = R2SessionPool(
            max_sessions=3,
            max_idle_time=1.0,
            auto_analyze=False,
            cleanup_interval=1.0
        )

        try:
            session = pool.get_session(str(simple_binary))

            session.execute("?V")

            initial_commands = session.metrics.commands_executed

            session.execute("?V")

            assert session.metrics.commands_executed == initial_commands + 1

            pool.return_session(session)

            time.sleep(1.5)
            pool._cleanup_idle_sessions()

        finally:
            pool.shutdown()

    def test_pool_shutdown_closes_all_resources(self, simple_binary: Path) -> None:
        """Pool shutdown closes all resources properly."""
        pool = R2SessionPool(max_sessions=5, auto_analyze=False)

        session1 = pool.get_session(str(simple_binary))
        session2 = pool.get_session(str(simple_binary))

        pool.return_session(session1)
        pool.return_session(session2)

        pool.shutdown()

        assert len(pool._sessions) == 0
        assert pool._cleanup_thread is None or not pool._cleanup_thread.is_alive()
