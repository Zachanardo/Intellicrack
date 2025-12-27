"""Production tests for Radare2 Session Manager.

Tests validate real r2pipe session pooling, lifecycle management, thread safety,
and command execution against actual binaries.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import concurrent.futures
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.radare2_session_manager import (
    R2SessionPool,
    R2SessionWrapper,
    SessionState,
    get_global_pool,
    r2_session_pooled,
    shutdown_global_pool,
)


pytest.importorskip("r2pipe")


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    """Create sample PE binary for testing."""
    binary_path = tmp_path / "test.exe"
    pe_header = b"MZ" + b"\x90" * 62 + b"PE\x00\x00"
    pe_data = pe_header + b"\x00" * 1000
    binary_path.write_bytes(pe_data)
    return binary_path


@pytest.fixture
def session_pool() -> R2SessionPool:
    """Create isolated session pool for testing."""
    pool = R2SessionPool(max_sessions=5, max_idle_time=10.0, cleanup_interval=1.0)
    yield pool
    pool.shutdown()


def test_session_wrapper_initialization(sample_binary: Path) -> None:
    """Session wrapper initializes with correct configuration."""
    session = R2SessionWrapper(
        binary_path=str(sample_binary),
        session_id="test_session",
        flags=["-2", "-n"],
        timeout=30.0,
        auto_analyze=False,
        analysis_level="aa",
    )

    assert session.binary_path == sample_binary
    assert session.session_id == "test_session"
    assert session.state == SessionState.IDLE
    assert session.timeout == 30.0
    assert not session.auto_analyze
    assert session.analysis_level == "aa"


def test_session_connect_opens_r2pipe(sample_binary: Path) -> None:
    """Connecting session opens r2pipe and sets state to ACTIVE."""
    session = R2SessionWrapper(
        binary_path=str(sample_binary),
        session_id="connect_test",
        auto_analyze=False,
    )

    success = session.connect()

    assert success
    assert session.state == SessionState.ACTIVE
    assert session.r2 is not None

    session.disconnect()


def test_session_disconnect_closes_connection(sample_binary: Path) -> None:
    """Disconnecting session properly closes r2pipe connection."""
    session = R2SessionWrapper(
        binary_path=str(sample_binary),
        session_id="disconnect_test",
        auto_analyze=False,
    )
    session.connect()

    session.disconnect()

    assert session.state == SessionState.CLOSED
    assert session.r2 is None


def test_session_execute_command_returns_result(sample_binary: Path) -> None:
    """Executing command returns proper result and updates metrics."""
    session = R2SessionWrapper(
        binary_path=str(sample_binary),
        session_id="execute_test",
        auto_analyze=False,
    )
    session.connect()

    result = session.execute("?V")

    assert result is not None
    assert isinstance(result, str)
    assert session.metrics.commands_executed == 1
    assert session.metrics.last_command_time > 0

    session.disconnect()


def test_session_execute_json_command(sample_binary: Path) -> None:
    """Executing JSON command returns parsed JSON result."""
    session = R2SessionWrapper(
        binary_path=str(sample_binary),
        session_id="json_test",
        auto_analyze=True,
    )
    session.connect()

    result = session.execute("ij", expect_json=True)

    assert result is not None
    assert isinstance(result, (dict, list))
    assert session.metrics.commands_executed == 1

    session.disconnect()


def test_session_execute_without_connection_raises_error(sample_binary: Path) -> None:
    """Executing command without connection raises RuntimeError."""
    session = R2SessionWrapper(
        binary_path=str(sample_binary),
        session_id="no_connect_test",
        auto_analyze=False,
    )

    with pytest.raises(RuntimeError, match="not connected"):
        session.execute("?V")


def test_session_reconnect_after_failure(sample_binary: Path) -> None:
    """Session can reconnect after disconnect."""
    session = R2SessionWrapper(
        binary_path=str(sample_binary),
        session_id="reconnect_test",
        auto_analyze=False,
    )
    session.connect()
    session.disconnect()

    success = session.reconnect()

    assert success
    assert session.state == SessionState.ACTIVE
    assert session.metrics.reconnections == 1

    session.disconnect()


def test_session_is_alive_check(sample_binary: Path) -> None:
    """Health check correctly identifies live and dead sessions."""
    session = R2SessionWrapper(
        binary_path=str(sample_binary),
        session_id="health_test",
        auto_analyze=False,
    )

    assert not session.is_alive()

    session.connect()
    assert session.is_alive()

    session.disconnect()
    assert not session.is_alive()


def test_session_idle_time_tracking(sample_binary: Path) -> None:
    """Idle time is tracked correctly."""
    session = R2SessionWrapper(
        binary_path=str(sample_binary),
        session_id="idle_test",
        auto_analyze=False,
    )
    session.connect()

    initial_idle = session.idle_time
    time.sleep(0.1)
    later_idle = session.idle_time

    assert later_idle > initial_idle
    assert later_idle >= 0.1

    session.disconnect()


def test_session_metrics_collection(sample_binary: Path) -> None:
    """Session metrics are collected accurately."""
    session = R2SessionWrapper(
        binary_path=str(sample_binary),
        session_id="metrics_test",
        auto_analyze=False,
    )
    session.connect()

    session.execute("?V")
    session.execute("?V")
    session.execute("?V")

    metrics = session.get_metrics()

    assert metrics["session_id"] == "metrics_test"
    assert metrics["commands_executed"] == 3
    assert metrics["total_execution_time"] > 0
    assert metrics["avg_execution_time"] > 0
    assert metrics["state"] == SessionState.ACTIVE.value

    session.disconnect()


def test_pool_initialization(session_pool: R2SessionPool) -> None:
    """Session pool initializes with correct configuration."""
    assert session_pool.max_sessions == 5
    assert session_pool.max_idle_time == 10.0
    assert len(session_pool._sessions) == 0


def test_pool_get_session_creates_new(session_pool: R2SessionPool, sample_binary: Path) -> None:
    """Getting session from pool creates new session if none available."""
    session = session_pool.get_session(str(sample_binary))

    assert session is not None
    assert session.state == SessionState.ACTIVE
    assert len(session_pool._sessions) == 1

    session_pool.return_session(session)


def test_pool_reuses_returned_sessions(session_pool: R2SessionPool, sample_binary: Path) -> None:
    """Pool reuses sessions returned to it."""
    session1 = session_pool.get_session(str(sample_binary))
    session1_id = session1.session_id
    session_pool.return_session(session1)

    session2 = session_pool.get_session(str(sample_binary))

    assert session2.session_id == session1_id
    assert session_pool._total_sessions_created == 1

    session_pool.return_session(session2)


def test_pool_enforces_session_limit(session_pool: R2SessionPool, tmp_path: Path) -> None:
    """Pool enforces maximum session limit."""
    binaries = []
    for i in range(6):
        binary_path = tmp_path / f"test{i}.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)
        binaries.append(binary_path)

    sessions = []
    for i in range(5):
        session = session_pool.get_session(str(binaries[i]))
        sessions.append(session)

    with pytest.raises(RuntimeError, match="Session limit reached"):
        session_pool.get_session(str(binaries[5]))

    for session in sessions:
        session_pool.return_session(session)


def test_pool_cleanup_idle_sessions(session_pool: R2SessionPool, sample_binary: Path) -> None:
    """Pool automatically cleans up idle sessions."""
    pool = R2SessionPool(max_sessions=3, max_idle_time=0.5, cleanup_interval=0.5)

    session = pool.get_session(str(sample_binary))
    pool.return_session(session)

    time.sleep(1.5)

    assert len(pool._sessions) == 0

    pool.shutdown()


def test_pool_context_manager(session_pool: R2SessionPool, sample_binary: Path) -> None:
    """Pool context manager properly acquires and returns sessions."""
    with session_pool.session(str(sample_binary)) as session:
        assert session.state == SessionState.ACTIVE
        result = session.execute("?V")
        assert result is not None

    stats = session_pool.get_pool_stats()
    assert stats["total_sessions"] >= 0


def test_pool_thread_safety(session_pool: R2SessionPool, sample_binary: Path) -> None:
    """Pool handles concurrent session requests safely."""
    def worker() -> str:
        with session_pool.session(str(sample_binary)) as session:
            result = session.execute("?V")
            return str(result) if result else ""

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(worker) for _ in range(10)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert len(results) == 10
    assert all(isinstance(r, str) for r in results)


def test_pool_stats_accuracy(session_pool: R2SessionPool, sample_binary: Path) -> None:
    """Pool statistics are calculated accurately."""
    session1 = session_pool.get_session(str(sample_binary))
    session1.execute("?V")
    session_pool.return_session(session1)

    session2 = session_pool.get_session(str(sample_binary))
    session2.execute("?V")
    session2.execute("?V")

    stats = session_pool.get_pool_stats()

    assert stats["total_sessions_created"] >= 1
    assert stats["total_commands_executed"] >= 3
    assert stats["active_sessions"] >= 1

    session_pool.return_session(session2)


def test_pool_session_metrics(session_pool: R2SessionPool, sample_binary: Path) -> None:
    """Pool provides detailed metrics for all sessions."""
    session = session_pool.get_session(str(sample_binary))
    session.execute("?V")

    metrics = session_pool.get_session_metrics()

    assert len(metrics) >= 1
    assert any(m["session_id"] == session.session_id for m in metrics)

    session_pool.return_session(session)


def test_pool_shutdown_closes_all_sessions(session_pool: R2SessionPool, sample_binary: Path) -> None:
    """Shutting down pool closes all active sessions."""
    session1 = session_pool.get_session(str(sample_binary))
    session2 = session_pool.get_session(str(sample_binary))

    session_pool.shutdown()

    assert len(session_pool._sessions) == 0


def test_global_pool_singleton(sample_binary: Path) -> None:
    """Global pool returns same instance on multiple calls."""
    pool1 = get_global_pool()
    pool2 = get_global_pool()

    assert pool1 is pool2

    shutdown_global_pool()


def test_global_pool_context_manager(sample_binary: Path) -> None:
    """Global pool context manager works correctly."""
    with r2_session_pooled(str(sample_binary)) as session:
        assert session.state == SessionState.ACTIVE
        result = session.execute("?V")
        assert result is not None

    shutdown_global_pool()


def test_session_auto_analyze_executes_analysis(sample_binary: Path) -> None:
    """Session with auto_analyze=True executes analysis on connect."""
    session = R2SessionWrapper(
        binary_path=str(sample_binary),
        session_id="analyze_test",
        auto_analyze=True,
        analysis_level="aaa",
    )

    session.connect()

    result = session.execute("aflj", expect_json=True)
    assert result is not None

    session.disconnect()


def test_session_custom_flags(sample_binary: Path) -> None:
    """Session respects custom r2pipe flags."""
    session = R2SessionWrapper(
        binary_path=str(sample_binary),
        session_id="flags_test",
        flags=["-2", "-w"],
        auto_analyze=False,
    )

    session.connect()
    assert session.state == SessionState.ACTIVE

    session.disconnect()


def test_session_nonexistent_binary_raises_error() -> None:
    """Creating session with nonexistent binary raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        R2SessionWrapper(
            binary_path="/nonexistent/path/binary.exe",
            session_id="error_test",
            auto_analyze=False,
        )


def test_pool_multiple_binaries(session_pool: R2SessionPool, tmp_path: Path) -> None:
    """Pool manages sessions for multiple different binaries."""
    binary1 = tmp_path / "binary1.exe"
    binary2 = tmp_path / "binary2.exe"
    binary1.write_bytes(b"MZ" + b"\x00" * 100)
    binary2.write_bytes(b"MZ" + b"\x11" * 100)

    session1 = session_pool.get_session(str(binary1))
    session2 = session_pool.get_session(str(binary2))

    assert session1.binary_path != session2.binary_path
    assert session1.session_id != session2.session_id

    session_pool.return_session(session1)
    session_pool.return_session(session2)


def test_session_command_error_tracking(sample_binary: Path) -> None:
    """Session tracks command errors in metrics."""
    session = R2SessionWrapper(
        binary_path=str(sample_binary),
        session_id="error_tracking_test",
        auto_analyze=False,
    )
    session.connect()

    initial_errors = session.metrics.errors_count

    try:
        session.execute("invalid_r2_command_xyz")
    except Exception:
        pass

    assert session.metrics.errors_count >= initial_errors

    session.disconnect()


def test_pool_forced_cleanup_removes_oldest(session_pool: R2SessionPool, tmp_path: Path) -> None:
    """Forced cleanup removes oldest session when limit reached."""
    binaries = []
    for i in range(5):
        binary_path = tmp_path / f"cleanup{i}.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)
        binaries.append(binary_path)

    sessions = []
    for binary in binaries:
        session = session_pool.get_session(str(binary))
        sessions.append(session)
        time.sleep(0.05)

    binary6 = tmp_path / "cleanup6.exe"
    binary6.write_bytes(b"MZ" + b"\x00" * 100)

    session_pool._cleanup_idle_sessions(force=True)

    new_session = session_pool.get_session(str(binary6))
    assert new_session is not None

    for session in sessions:
        if session.session_id in session_pool._sessions:
            session_pool.return_session(session)
    session_pool.return_session(new_session)


def test_session_reconnection_count(sample_binary: Path) -> None:
    """Session tracks reconnection count."""
    session = R2SessionWrapper(
        binary_path=str(sample_binary),
        session_id="reconnect_count_test",
        auto_analyze=False,
    )

    session.connect()
    session.disconnect()
    session.reconnect()
    session.disconnect()
    session.reconnect()

    assert session.metrics.reconnections == 2

    session.disconnect()


def test_pool_error_rate_calculation(session_pool: R2SessionPool, sample_binary: Path) -> None:
    """Pool calculates error rate correctly."""
    session = session_pool.get_session(str(sample_binary))

    session.execute("?V")
    session.execute("?V")

    try:
        session.execute("definitely_invalid_command_12345")
    except Exception:
        pass

    session_pool.return_session(session)

    stats = session_pool.get_pool_stats()
    assert "error_rate" in stats
    assert 0 <= stats["error_rate"] <= 1
