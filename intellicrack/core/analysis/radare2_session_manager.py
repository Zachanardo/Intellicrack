"""Production-ready r2pipe session management system.

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

import hashlib
import logging
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from queue import Empty, Queue
from typing import Any

try:
    import r2pipe
    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False

logger = logging.getLogger(__name__)


class SessionState(Enum):
    """Session connection states."""

    IDLE = "idle"
    ACTIVE = "active"
    RECONNECTING = "reconnecting"
    CLOSED = "closed"
    ERROR = "error"


@dataclass
class SessionMetrics:
    """Metrics for a session."""

    created_at: float = field(default_factory=time.time)
    commands_executed: int = 0
    last_command_time: float = 0.0
    total_execution_time: float = 0.0
    errors_count: int = 0
    reconnections: int = 0
    bytes_processed: int = 0


class R2SessionWrapper:
    """Thread-safe wrapper for r2pipe session with lifecycle management."""

    def __init__(
        self,
        binary_path: str,
        session_id: str,
        flags: list[str] | None = None,
        timeout: float = 30.0,
        auto_analyze: bool = True,
        analysis_level: str = "aaa",
    ) -> None:
        """Initialize session wrapper.

        Args:
            binary_path: Path to binary file
            session_id: Unique session identifier
            flags: Optional r2pipe flags
            timeout: Command timeout in seconds
            auto_analyze: Whether to run analysis on connect
            analysis_level: radare2 analysis level (a, aa, aaa, aaaa)

        """
        self.binary_path = Path(binary_path)
        self.session_id = session_id
        default_flags = ["-2"]
        if not auto_analyze:
            default_flags.append("-n")
        self.flags = flags if flags is not None else default_flags
        self.timeout = timeout
        self.auto_analyze = auto_analyze
        self.analysis_level = analysis_level

        self.r2: r2pipe.open | None = None
        self.state = SessionState.IDLE
        self.metrics = SessionMetrics()
        self._lock = threading.RLock()
        self._last_used = time.time()

        if not R2PIPE_AVAILABLE:
            raise RuntimeError("r2pipe not available - please install radare2-r2pipe")

        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

    def connect(self) -> bool:
        """Establish connection to radare2.

        Returns:
            True if connection successful, False otherwise

        """
        with self._lock:
            try:
                if self.state == SessionState.ACTIVE and self.r2 is not None:
                    return True

                self.state = SessionState.RECONNECTING
                logger.info(f"Opening r2pipe session {self.session_id} for {self.binary_path}")

                self.r2 = r2pipe.open(str(self.binary_path), flags=self.flags)

                if self.auto_analyze:
                    self.r2.cmd(self.analysis_level)

                self.state = SessionState.ACTIVE
                self._last_used = time.time()
                return True

            except Exception as e:
                logger.error(f"Failed to connect session {self.session_id}: {e}")
                self.state = SessionState.ERROR
                self.metrics.errors_count += 1
                return False

    def disconnect(self) -> None:
        """Close the session connection."""
        with self._lock:
            if self.r2 is not None:
                try:
                    self.r2.quit()
                except Exception as e:
                    logger.warning(f"Error closing session {self.session_id}: {e}")
                finally:
                    self.r2 = None
                    self.state = SessionState.CLOSED
                    logger.debug(f"Session {self.session_id} closed")

    def execute(self, command: str, expect_json: bool = False) -> str | dict | list | None:
        """Execute radare2 command with error handling.

        Args:
            command: radare2 command to execute
            expect_json: Whether to parse result as JSON

        Returns:
            Command result as string, dict, list, or None depending on expect_json flag

        Raises:
            RuntimeError: If session not connected
            TimeoutError: If command times out

        """
        with self._lock:
            if self.state != SessionState.ACTIVE or self.r2 is None:
                raise RuntimeError(f"Session {self.session_id} not connected")

            start_time = time.time()
            try:
                if expect_json:
                    result = self.r2.cmdj(command)
                else:
                    result = self.r2.cmd(command)

                execution_time = time.time() - start_time
                self.metrics.commands_executed += 1
                self.metrics.last_command_time = execution_time
                self.metrics.total_execution_time += execution_time
                self._last_used = time.time()

                if result and isinstance(result, (str, bytes)):
                    self.metrics.bytes_processed += len(result)

                return result

            except Exception as e:
                self.metrics.errors_count += 1
                logger.error(f"Command failed in session {self.session_id}: {command}, Error: {e}")
                raise

    def reconnect(self) -> bool:
        """Attempt to reconnect the session.

        Returns:
            True if reconnection successful, False otherwise

        """
        with self._lock:
            logger.info(f"Attempting to reconnect session {self.session_id}")
            self.disconnect()
            self.metrics.reconnections += 1
            return self.connect()

    def is_alive(self) -> bool:
        """Check if session is alive.

        Returns:
            True if session is connected and responsive

        """
        with self._lock:
            if self.state != SessionState.ACTIVE or self.r2 is None:
                return False

            try:
                self.r2.cmd("?V")
                return True
            except Exception as e:
                logger.warning(f"Session {self.session_id} health check failed: {e}")
                return False

    @property
    def last_used(self) -> float:
        """Get timestamp of last use.

        Returns:
            Timestamp of last use

        """
        with self._lock:
            return self._last_used

    @property
    def idle_time(self) -> float:
        """Get idle time in seconds.

        Returns:
            Seconds since last use

        """
        with self._lock:
            return time.time() - self._last_used

    def get_metrics(self) -> dict[str, Any]:
        """Get session metrics.

        Returns:
            Dictionary of session metrics

        """
        with self._lock:
            avg_execution_time = (
                self.metrics.total_execution_time / max(1, self.metrics.commands_executed)
            )

            return {
                "session_id": self.session_id,
                "binary_path": str(self.binary_path),
                "state": self.state.value,
                "uptime": time.time() - self.metrics.created_at,
                "idle_time": self.idle_time,
                "commands_executed": self.metrics.commands_executed,
                "total_execution_time": self.metrics.total_execution_time,
                "avg_execution_time": avg_execution_time,
                "errors_count": self.metrics.errors_count,
                "reconnections": self.metrics.reconnections,
                "bytes_processed": self.metrics.bytes_processed,
                "last_used": self._last_used,
            }


class R2SessionPool:
    """Thread-safe session pool with automatic lifecycle management."""

    def __init__(
        self,
        max_sessions: int = 10,
        max_idle_time: float = 300.0,
        session_timeout: float = 30.0,
        auto_analyze: bool = True,
        analysis_level: str = "aaa",
        cleanup_interval: float = 60.0,
    ) -> None:
        """Initialize session pool.

        Args:
            max_sessions: Maximum number of concurrent sessions
            max_idle_time: Maximum idle time before session cleanup (seconds)
            session_timeout: Command timeout for sessions
            auto_analyze: Whether to auto-analyze binaries on connect
            analysis_level: radare2 analysis level
            cleanup_interval: Interval for cleanup thread (seconds)

        """
        self.max_sessions = max_sessions
        self.max_idle_time = max_idle_time
        self.session_timeout = session_timeout
        self.auto_analyze = auto_analyze
        self.analysis_level = analysis_level
        self.cleanup_interval = cleanup_interval

        self._sessions: dict[str, R2SessionWrapper] = {}
        self._available_sessions: dict[str, Queue] = {}
        self._lock = threading.RLock()
        self._cleanup_thread: threading.Thread | None = None
        self._stop_cleanup = threading.Event()

        self._total_sessions_created = 0
        self._total_commands_executed = 0

        if not R2PIPE_AVAILABLE:
            logger.warning("r2pipe not available - session pool will be non-functional")

        self._start_cleanup_thread()

    def _generate_session_id(self, binary_path: str, flags: list[str] | None = None) -> str:
        """Generate unique session ID.

        Args:
            binary_path: Path to binary
            flags: Optional r2 flags

        Returns:
            Unique session identifier

        """
        key = f"{binary_path}:{','.join(flags or [])}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _get_pool_key(self, binary_path: str, flags: list[str] | None = None) -> str:
        """Get pool key for binary.

        Args:
            binary_path: Path to binary
            flags: Optional r2 flags

        Returns:
            Pool key

        """
        return f"{Path(binary_path).resolve()}:{','.join(sorted(flags or []))}"

    def get_session(
        self,
        binary_path: str,
        flags: list[str] | None = None,
        timeout: float | None = None,
    ) -> R2SessionWrapper:
        """Get or create a session from the pool.

        Args:
            binary_path: Path to binary file
            flags: Optional r2pipe flags
            timeout: Optional command timeout override

        Returns:
            R2SessionWrapper instance

        Raises:
            RuntimeError: If session limit reached or creation fails

        """
        if not R2PIPE_AVAILABLE:
            raise RuntimeError("r2pipe not available")

        pool_key = self._get_pool_key(binary_path, flags)

        with self._lock:
            if pool_key not in self._available_sessions:
                self._available_sessions[pool_key] = Queue()

            try:
                session = self._available_sessions[pool_key].get_nowait()
                if session.is_alive():
                    logger.debug(f"Reusing session {session.session_id} from pool")
                    return session
                logger.info(f"Session {session.session_id} not alive, reconnecting")
                if session.reconnect():
                    return session
                session.disconnect()
            except Empty:
                pass

            if len(self._sessions) >= self.max_sessions:
                self._cleanup_idle_sessions(force=True)

                if len(self._sessions) >= self.max_sessions:
                    raise RuntimeError(f"Session limit reached ({self.max_sessions})")

            session_id = self._generate_session_id(binary_path, flags)
            session = R2SessionWrapper(
                binary_path=binary_path,
                session_id=session_id,
                flags=flags,
                timeout=timeout or self.session_timeout,
                auto_analyze=self.auto_analyze,
                analysis_level=self.analysis_level,
            )

            if not session.connect():
                raise RuntimeError(f"Failed to create session for {binary_path}")

            self._sessions[session_id] = session
            self._total_sessions_created += 1

            logger.info(f"Created new session {session_id} for {binary_path}")
            return session

    def return_session(self, session: R2SessionWrapper) -> None:
        """Return a session to the pool.

        Args:
            session: Session to return

        """
        if not session or session.session_id not in self._sessions:
            return

        pool_key = self._get_pool_key(str(session.binary_path), session.flags)

        with self._lock:
            if session.is_alive():
                if pool_key in self._available_sessions:
                    self._available_sessions[pool_key].put(session)
                    logger.debug(f"Returned session {session.session_id} to pool")
            else:
                logger.warning(f"Session {session.session_id} not alive, removing from pool")
                self._remove_session(session.session_id)

    def _remove_session(self, session_id: str) -> None:
        """Remove session from pool.

        Args:
            session_id: Session ID to remove

        """
        with self._lock:
            if session_id in self._sessions:
                session = self._sessions[session_id]
                session.disconnect()
                del self._sessions[session_id]
                logger.debug(f"Removed session {session_id} from pool")

    def _cleanup_idle_sessions(self, force: bool = False) -> None:
        """Clean up idle sessions.

        Args:
            force: Whether to force cleanup of oldest sessions

        """
        with self._lock:
            sessions_to_remove = []

            for session_id, session in self._sessions.items():
                if session.idle_time > self.max_idle_time or (force and session.state == SessionState.IDLE):
                    sessions_to_remove.append(session_id)

            if force and not sessions_to_remove and self._sessions:
                oldest_session = min(
                    self._sessions.values(),
                    key=lambda s: s.last_used,
                )
                sessions_to_remove.append(oldest_session.session_id)

            for session_id in sessions_to_remove:
                self._remove_session(session_id)

            if sessions_to_remove:
                logger.info(f"Cleaned up {len(sessions_to_remove)} idle sessions")

    def _cleanup_loop(self) -> None:
        """Background cleanup thread."""
        logger.info("Session pool cleanup thread started")

        while not self._stop_cleanup.is_set():
            try:
                self._cleanup_idle_sessions()
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")

            self._stop_cleanup.wait(self.cleanup_interval)

        logger.info("Session pool cleanup thread stopped")

    def _start_cleanup_thread(self) -> None:
        """Start the cleanup thread."""
        if self._cleanup_thread is None or not self._cleanup_thread.is_alive():
            self._stop_cleanup.clear()
            self._cleanup_thread = threading.Thread(
                target=self._cleanup_loop,
                daemon=True,
                name="R2SessionPoolCleanup",
            )
            self._cleanup_thread.start()

    def close_all(self) -> None:
        """Close all sessions in the pool."""
        with self._lock:
            logger.info(f"Closing all {len(self._sessions)} sessions in pool")

            for session_id in list(self._sessions.keys()):
                self._remove_session(session_id)

            self._available_sessions.clear()

    def shutdown(self) -> None:
        """Shutdown the session pool."""
        logger.info("Shutting down session pool")
        self._stop_cleanup.set()

        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5.0)

        self.close_all()

    def get_pool_stats(self) -> dict[str, Any]:
        """Get pool statistics.

        Returns:
            Dictionary of pool statistics

        """
        with self._lock:
            active_sessions = sum(
                1 for s in self._sessions.values()
                if s.state == SessionState.ACTIVE
            )

            total_commands = sum(
                s.metrics.commands_executed for s in self._sessions.values()
            )

            total_errors = sum(
                s.metrics.errors_count for s in self._sessions.values()
            )

            available_count = sum(
                q.qsize() for q in self._available_sessions.values()
            )

            return {
                "total_sessions": len(self._sessions),
                "active_sessions": active_sessions,
                "available_sessions": available_count,
                "max_sessions": self.max_sessions,
                "total_sessions_created": self._total_sessions_created,
                "total_commands_executed": total_commands,
                "total_errors": total_errors,
                "error_rate": total_errors / max(1, total_commands),
            }

    def get_session_metrics(self) -> list[dict[str, Any]]:
        """Get metrics for all sessions.

        Returns:
            List of session metrics

        """
        with self._lock:
            return [session.get_metrics() for session in self._sessions.values()]

    @contextmanager
    def session(
        self,
        binary_path: str,
        flags: list[str] | None = None,
        timeout: float | None = None,
    ) -> Generator[R2SessionWrapper, None, None]:
        """Context manager for session pooling.

        Args:
            binary_path: Path to binary file
            flags: Optional r2pipe flags
            timeout: Optional command timeout

        Yields:
            R2SessionWrapper instance

        """
        session = None
        try:
            session = self.get_session(binary_path, flags, timeout)
            yield session
        finally:
            if session:
                self.return_session(session)


_global_pool: R2SessionPool | None = None
_pool_lock = threading.Lock()


def get_global_pool(
    max_sessions: int = 10,
    max_idle_time: float = 300.0,
    auto_analyze: bool = True,
    analysis_level: str = "aaa",
) -> R2SessionPool:
    """Get or create the global session pool.

    Args:
        max_sessions: Maximum number of concurrent sessions
        max_idle_time: Maximum idle time before cleanup
        auto_analyze: Whether to auto-analyze binaries
        analysis_level: radare2 analysis level

    Returns:
        Global R2SessionPool instance

    """
    global _global_pool

    with _pool_lock:
        if _global_pool is None:
            _global_pool = R2SessionPool(
                max_sessions=max_sessions,
                max_idle_time=max_idle_time,
                auto_analyze=auto_analyze,
                analysis_level=analysis_level,
            )

        return _global_pool


@contextmanager
def r2_session_pooled(
    binary_path: str,
    flags: list[str] | None = None,
    timeout: float | None = None,
    pool: R2SessionPool | None = None,
) -> Generator[R2SessionWrapper, None, None]:
    """Context manager for pooled r2pipe sessions.

    Args:
        binary_path: Path to binary file
        flags: Optional r2pipe flags
        timeout: Optional command timeout
        pool: Optional session pool (uses global pool if not provided)

    Yields:
        R2SessionWrapper instance

    """
    session_pool = pool or get_global_pool()

    with session_pool.session(binary_path, flags, timeout) as session:
        yield session


def shutdown_global_pool() -> None:
    """Shutdown the global session pool."""
    global _global_pool

    with _pool_lock:
        if _global_pool is not None:
            _global_pool.shutdown()
            _global_pool = None


__all__ = [
    "SessionState",
    "SessionMetrics",
    "R2SessionWrapper",
    "R2SessionPool",
    "get_global_pool",
    "r2_session_pooled",
    "shutdown_global_pool",
]
