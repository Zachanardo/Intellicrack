"""Integration tests for radare2 session manager.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import os
import tempfile
import time
import threading
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.radare2_session_manager import (
    R2SessionWrapper,
    R2SessionPool,
    SessionState,
    get_global_pool,
    r2_session_pooled,
    shutdown_global_pool,
)
from intellicrack.core.analysis.radare2_session_helpers import (
    get_r2_session,
    execute_r2_command,
    get_pool_statistics,
    R2CommandBatch,
)

try:
    import r2pipe
    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")


@pytest.fixture(autouse=True)
def configure_global_pool() -> Generator[None, None, None]:
    """Configure global pool for testing with auto_analyze=False."""
    from intellicrack.core.analysis.radare2_session_helpers import configure_global_pool as config_pool

    config_pool(
        max_sessions=10,
        max_idle_time=10.0,
        auto_analyze=False,
        analysis_level="aaa"
    )
    yield
    shutdown_global_pool()


@pytest.fixture
def test_binary(tmp_path: Path) -> str:
    """Create a simple test binary."""
    binary_path = tmp_path / "test.exe"

    with open(binary_path, "wb") as f:
        f.write(b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 200)

    return str(binary_path)


@pytest.fixture
def session_pool() -> Generator[R2SessionPool, None, None]:
    """Create a fresh session pool for testing."""
    pool = R2SessionPool(
        max_sessions=5,
        max_idle_time=10.0,
        auto_analyze=False,
        cleanup_interval=5.0
    )
    yield pool
    pool.shutdown()


class TestR2SessionWrapper:
    """Test R2SessionWrapper functionality."""

    def test_session_creation(self, test_binary: str) -> None:
        """Test creating a session wrapper."""
        session = R2SessionWrapper(
            binary_path=test_binary,
            session_id="test_session",
            auto_analyze=False
        )

        assert session.binary_path.exists()
        assert session.session_id == "test_session"
        assert session.state == SessionState.IDLE

    def test_session_connect(self, test_binary: str) -> None:
        """Test connecting a session."""
        session = R2SessionWrapper(
            binary_path=test_binary,
            session_id="test_connect",
            auto_analyze=False
        )

        assert session.connect()
        assert session.state == SessionState.ACTIVE
        assert session.r2 is not None

        session.disconnect()
        assert session.state in (SessionState.CLOSED, SessionState.IDLE)

    def test_session_execute_command(self, test_binary: str) -> None:
        """Test executing commands."""
        session = R2SessionWrapper(
            binary_path=test_binary,
            session_id="test_execute",
            auto_analyze=False
        )

        session.connect()

        version = session.execute("?V")
        assert version is not None
        assert isinstance(version, str)

        info = session.execute("ij", expect_json=True)
        assert isinstance(info, dict)

        session.disconnect()

    def test_session_metrics(self, test_binary: str) -> None:
        """Test session metrics tracking."""
        session = R2SessionWrapper(
            binary_path=test_binary,
            session_id="test_metrics",
            auto_analyze=False
        )

        session.connect()

        session.execute("?V")
        session.execute("ij", expect_json=True)

        metrics = session.get_metrics()

        assert metrics["session_id"] == "test_metrics"
        assert metrics["commands_executed"] == 2
        assert metrics["errors_count"] == 0
        assert metrics["state"] == "active"

        session.disconnect()

    def test_session_reconnect(self, test_binary: str) -> None:
        """Test session reconnection."""
        session = R2SessionWrapper(
            binary_path=test_binary,
            session_id="test_reconnect",
            auto_analyze=False
        )

        session.connect()
        original_r2 = session.r2

        session.disconnect()
        assert session.state in (SessionState.CLOSED, SessionState.IDLE)

        assert session.reconnect()
        assert session.state == SessionState.ACTIVE
        assert session.r2 is not original_r2

        session.disconnect()

    def test_session_health_check(self, test_binary: str) -> None:
        """Test session health checking."""
        session = R2SessionWrapper(
            binary_path=test_binary,
            session_id="test_health",
            auto_analyze=False
        )

        assert not session.is_alive()

        session.connect()
        assert session.is_alive()

        session.disconnect()
        assert not session.is_alive()


class TestR2SessionPool:
    """Test R2SessionPool functionality."""

    def test_pool_creation(self) -> None:
        """Test creating a session pool."""
        pool = R2SessionPool(max_sessions=5)
        assert pool.max_sessions == 5

        stats = pool.get_pool_stats()
        assert stats["total_sessions"] == 0
        assert stats["max_sessions"] == 5

        pool.shutdown()

    def test_pool_get_session(self, session_pool: R2SessionPool, test_binary: str) -> None:
        """Test getting a session from pool."""
        session = session_pool.get_session(test_binary)

        assert isinstance(session, R2SessionWrapper)
        assert session.state == SessionState.ACTIVE

        session_pool.return_session(session)

    def test_pool_session_reuse(self, session_pool: R2SessionPool, test_binary: str) -> None:
        """Test session reuse from pool."""
        session1 = session_pool.get_session(test_binary)
        session1_id = session1.session_id

        session_pool.return_session(session1)

        session2 = session_pool.get_session(test_binary)
        session2_id = session2.session_id

        assert session1_id == session2_id

        session_pool.return_session(session2)

    def test_pool_max_sessions(self, test_binary: str) -> None:
        """Test pool session limit enforcement."""
        pool = R2SessionPool(max_sessions=2)

        session1 = pool.get_session(test_binary)
        session2 = pool.get_session(f"{test_binary}.2")

        with pytest.raises(RuntimeError, match="Session limit reached"):
            pool.get_session(f"{test_binary}.3")

        pool.return_session(session1)
        pool.return_session(session2)
        pool.shutdown()

    def test_pool_context_manager(self, session_pool: R2SessionPool, test_binary: str) -> None:
        """Test pool context manager."""
        with session_pool.session(test_binary) as session:
            assert session.state == SessionState.ACTIVE
            version = session.execute("?V")
            assert version is not None

        stats = session_pool.get_pool_stats()
        assert stats["available_sessions"] >= 0

    def test_pool_parallel_access(self, session_pool: R2SessionPool, test_binary: str) -> None:
        """Test concurrent pool access."""
        results: list[Any] = []

        def worker() -> None:
            with session_pool.session(test_binary) as session:
                result = session.execute("ij", expect_json=True)
                results.append(result)

        threads = [threading.Thread(target=worker) for _ in range(5)]

        for t in threads:
            t.start()

        for t in threads:
            t.join(timeout=10.0)

        assert len(results) == 5
        for result in results:
            assert isinstance(result, dict)

    def test_pool_cleanup(self, test_binary: str) -> None:
        """Test pool cleanup of idle sessions."""
        pool = R2SessionPool(
            max_sessions=5,
            max_idle_time=1.0,
            cleanup_interval=0.5
        )

        session = pool.get_session(test_binary)
        pool.return_session(session)

        time.sleep(2.0)

        stats = pool.get_pool_stats()
        assert stats["total_sessions"] == 0

        pool.shutdown()

    def test_pool_statistics(self, session_pool: R2SessionPool, test_binary: str) -> None:
        """Test pool statistics."""
        with session_pool.session(test_binary) as session:
            session.execute("?V")
            session.execute("ij", expect_json=True)

        stats = session_pool.get_pool_stats()

        assert "total_sessions" in stats
        assert "active_sessions" in stats
        assert "total_commands_executed" in stats

        assert stats["total_commands_executed"] >= 2


class TestGlobalPool:
    """Test global pool functionality."""

    def test_global_pool_access(self, test_binary: str) -> None:
        """Test accessing global pool."""
        pool = get_global_pool()
        assert isinstance(pool, R2SessionPool)

        with r2_session_pooled(test_binary) as session:
            assert session.state == SessionState.ACTIVE

        shutdown_global_pool()

    def test_global_pool_singleton(self) -> None:
        """Test global pool is singleton."""
        pool1 = get_global_pool()
        pool2 = get_global_pool()

        assert pool1 is pool2

        shutdown_global_pool()


class TestSessionHelpers:
    """Test session helper functions."""

    def test_get_r2_session(self, test_binary: str) -> None:
        """Test get_r2_session helper."""
        with get_r2_session(test_binary) as session:
            result = session.execute("?V")
            assert result is not None

    def test_execute_r2_command(self, test_binary: str) -> None:
        """Test execute_r2_command helper."""
        result = execute_r2_command(test_binary, "?V")
        assert result is not None

        info = execute_r2_command(test_binary, "ij", expect_json=True)
        assert isinstance(info, dict)

    def test_pool_statistics_helper(self, test_binary: str) -> None:
        """Test get_pool_statistics helper."""
        execute_r2_command(test_binary, "?V")

        stats = get_pool_statistics()
        assert "total_sessions" in stats
        assert "active_sessions" in stats

        shutdown_global_pool()

    def test_command_batch(self, test_binary: str) -> None:
        """Test R2CommandBatch."""
        batch = R2CommandBatch(test_binary)

        batch.add_command("?V")
        batch.add_command("ij", expect_json=True)

        results = batch.execute_all()

        assert len(results) == 2
        assert isinstance(results[0], str)
        assert isinstance(results[1], dict)


class TestSessionIntegration:
    """Integration tests for real-world usage."""

    def test_multiple_binaries(self, tmp_path: Path) -> None:
        """Test handling multiple different binaries."""
        binaries = []
        for i in range(3):
            binary_path = tmp_path / f"test{i}.exe"
            with open(binary_path, "wb") as f:
                f.write(b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 200)
            binaries.append(str(binary_path))

        pool = R2SessionPool(max_sessions=10)

        sessions = []
        for binary in binaries:
            session = pool.get_session(binary)
            sessions.append(session)
            session.execute("?V")

        for session in sessions:
            pool.return_session(session)

        stats = pool.get_pool_stats()
        assert stats["total_sessions"] == 3

        pool.shutdown()

    def test_long_running_session(self, test_binary: str) -> None:
        """Test long-running session usage."""
        with r2_session_pooled(test_binary) as session:
            for _ in range(10):
                result = session.execute("?V")
                assert result is not None

            metrics = session.get_metrics()
            assert metrics["commands_executed"] == 10

    def test_error_recovery(self, test_binary: str) -> None:
        """Test error handling and recovery."""
        pool = R2SessionPool(max_sessions=5)

        with pool.session(test_binary) as session:
            session.execute("?V")

            try:
                session.execute("invalid_command_xyz_123")
            except Exception:
                pass

            result = session.execute("?V")
            assert result is not None

        pool.shutdown()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
