"""Helper utilities for radare2 session management migration.

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

import logging
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

try:
    from .radare2_session_manager import (
        R2SessionWrapper,
        get_global_pool,
        r2_session_pooled,
    )

    SESSION_MANAGER_AVAILABLE = True
except ImportError:
    SESSION_MANAGER_AVAILABLE = False

try:
    import r2pipe
    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False

logger = logging.getLogger(__name__)


class DirectR2Session:
    """Direct r2pipe session without pooling for legacy compatibility."""

    def __init__(self, binary_path: str, flags: list[str] | None = None) -> None:
        """Initialize direct session.

        Args:
            binary_path: Path to binary file
            flags: Optional r2 flags

        """
        self.binary_path = binary_path
        self.flags = flags or ["-2"]
        self.r2: r2pipe.open | None = None

        if not R2PIPE_AVAILABLE:
            raise RuntimeError("r2pipe not available")

    def connect(self) -> bool:
        """Connect to radare2.

        Returns:
            True if successful

        """
        try:
            self.r2 = r2pipe.open(self.binary_path, flags=self.flags)
            return True
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            return False

    def disconnect(self) -> None:
        """Disconnect from radare2."""
        if self.r2:
            try:
                self.r2.quit()
            except Exception as e:
                logger.warning(f"Error closing session: {e}")
            finally:
                self.r2 = None

    def execute(self, command: str, expect_json: bool = False) -> dict[str, Any] | str:
        """Execute command.

        Args:
            command: radare2 command
            expect_json: Whether to parse JSON

        Returns:
            Command result as JSON dictionary if expect_json is True, else as string

        """
        if not self.r2:
            raise RuntimeError("Not connected")

        if expect_json:
            return self.r2.cmdj(command)
        return self.r2.cmd(command)


@contextmanager
def get_r2_session(
    binary_path: str,
    flags: list[str] | None = None,
    use_pooling: bool = True,
    auto_analyze: bool = True,
) -> Generator[R2SessionWrapper | DirectR2Session, None, None]:
    """Get an r2 session with automatic pooling.

    Args:
        binary_path: Path to binary file
        flags: Optional r2 flags
        use_pooling: Whether to use session pooling
        auto_analyze: Whether to auto-analyze binary

    Yields:
        R2SessionWrapper or DirectR2Session

    """
    if use_pooling and SESSION_MANAGER_AVAILABLE:
        with r2_session_pooled(binary_path, flags=flags) as session:
            yield session
    else:
        session = DirectR2Session(binary_path, flags)
        try:
            if session.connect():
                if auto_analyze:
                    session.execute("aaa")
                yield session
            else:
                raise RuntimeError(f"Failed to connect to {binary_path}")
        finally:
            session.disconnect()


def execute_r2_command(
    binary_path: str,
    command: str,
    expect_json: bool = False,
    flags: list[str] | None = None,
    use_pooling: bool = True,
) -> dict[str, Any] | str:
    """Execute a single r2 command on a binary.

    Args:
        binary_path: Path to binary file
        command: radare2 command to execute
        expect_json: Whether to parse result as JSON
        flags: Optional r2 flags
        use_pooling: Whether to use session pooling

    Returns:
        Command result as JSON dictionary if expect_json is True, else as string

    """
    with get_r2_session(binary_path, flags, use_pooling) as session:
        return session.execute(command, expect_json)


def get_pool_statistics() -> dict[str, Any]:
    """Get session pool statistics.

    Returns:
        Dictionary of pool statistics

    """
    if SESSION_MANAGER_AVAILABLE:
        pool = get_global_pool()
        return pool.get_pool_stats()
    return {
        "error": "Session manager not available",
        "total_sessions": 0,
        "active_sessions": 0,
    }


def get_all_session_metrics() -> list[dict[str, Any]]:
    """Get metrics for all sessions in the pool.

    Returns:
        List of session metrics

    """
    if SESSION_MANAGER_AVAILABLE:
        pool = get_global_pool()
        return pool.get_session_metrics()
    return []


def cleanup_idle_sessions() -> None:
    """Force cleanup of idle sessions in the pool."""
    if SESSION_MANAGER_AVAILABLE:
        pool = get_global_pool()
        pool._cleanup_idle_sessions(force=True)
        logger.info("Forced cleanup of idle sessions")


def configure_global_pool(
    max_sessions: int = 10,
    max_idle_time: float = 300.0,
    auto_analyze: bool = True,
    analysis_level: str = "aaa",
) -> None:
    """Configure the global session pool.

    Args:
        max_sessions: Maximum concurrent sessions
        max_idle_time: Maximum idle time before cleanup
        auto_analyze: Whether to auto-analyze binaries
        analysis_level: radare2 analysis level

    """
    if SESSION_MANAGER_AVAILABLE:
        get_global_pool(
            max_sessions=max_sessions,
            max_idle_time=max_idle_time,
            auto_analyze=auto_analyze,
            analysis_level=analysis_level,
        )
        logger.info(
            f"Configured global pool: max_sessions={max_sessions}, "
            f"max_idle_time={max_idle_time}, analysis_level={analysis_level}",
        )


class R2CommandBatch:
    """Batch multiple r2 commands for efficient execution."""

    def __init__(self, binary_path: str, use_pooling: bool = True) -> None:
        """Initialize command batch.

        Args:
            binary_path: Path to binary file
            use_pooling: Whether to use session pooling

        """
        self.binary_path = binary_path
        self.use_pooling = use_pooling
        self.commands: list[tuple[str, bool]] = []

    def add_command(self, command: str, expect_json: bool = False) -> None:
        """Add command to batch.

        Args:
            command: radare2 command
            expect_json: Whether to parse as JSON

        """
        self.commands.append((command, expect_json))

    def execute_all(self) -> list[Any]:
        """Execute all batched commands in a single session.

        Returns:
            List of command results

        """
        results = []

        with get_r2_session(self.binary_path, use_pooling=self.use_pooling) as session:
            for command, expect_json in self.commands:
                try:
                    result = session.execute(command, expect_json)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Command failed: {command}, Error: {e}")
                    results.append({"error": str(e)})

        return results


def migrate_r2pipe_to_pooled(
    original_r2: r2pipe.open,
    binary_path: str,
    flags: list[str] | None = None,
) -> R2SessionWrapper:
    """Migrate from direct r2pipe usage to pooled sessions.

    Args:
        original_r2: Original r2pipe instance (will be closed)
        binary_path: Path to binary file
        flags: Optional r2 flags

    Returns:
        New R2SessionWrapper instance

    """
    if not SESSION_MANAGER_AVAILABLE:
        raise RuntimeError("Session manager not available")

    try:
        original_r2.quit()
    except Exception as e:
        logger.warning(f"Error closing original r2pipe: {e}")

    pool = get_global_pool()
    return pool.get_session(binary_path, flags)


__all__ = [
    "DirectR2Session",
    "get_r2_session",
    "execute_r2_command",
    "get_pool_statistics",
    "get_all_session_metrics",
    "cleanup_idle_sessions",
    "configure_global_pool",
    "R2CommandBatch",
    "migrate_r2pipe_to_pooled",
    "SESSION_MANAGER_AVAILABLE",
]
