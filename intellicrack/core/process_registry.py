"""Centralized process registry for tracking and managing spawned processes.

Provides automatic cleanup via atexit handlers and __del__ destructors,
preventing orphaned processes when the application exits abnormally.

Copyright (C) 2024 Intellicrack Team
License: GPL-3.0
"""

from __future__ import annotations

import atexit
import contextlib
import logging
import subprocess
import threading
import time
import weakref
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import psutil


if TYPE_CHECKING:
    from collections.abc import Generator

logger = logging.getLogger(__name__)


@dataclass
class ProcessEntry:
    """Entry representing a tracked process in the registry."""

    process: subprocess.Popen[Any]
    name: str
    created_at: float = field(default_factory=time.time)
    psutil_handle: psutil.Process | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Initialize psutil handle for enhanced process control."""
        if self.psutil_handle is None:
            with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                self.psutil_handle = psutil.Process(self.process.pid)

    @property
    def pid(self) -> int:
        """Return the process ID."""
        return self.process.pid

    @property
    def is_alive(self) -> bool:
        """Check if the process is still running."""
        return self.process.poll() is None

    @property
    def age_seconds(self) -> float:
        """Return how long the process has been tracked."""
        return time.time() - self.created_at


class ProcessRegistry:
    """Singleton registry for tracking all spawned processes.

    Provides centralized management of subprocess lifecycle with automatic
    cleanup on application exit. Implements both atexit handlers and supports
    __del__ destructors in client classes.

    Features:
        - Thread-safe singleton pattern
        - Automatic atexit cleanup
        - Optional background cleanup thread for stale processes
        - Context manager support for automatic tracking/cleanup
        - Graceful termination with timeout and kill fallback

    Usage:
        # Get the singleton instance
        registry = ProcessRegistry.get_instance()

        # Register a process
        proc = subprocess.Popen([...])
        registry.register(proc, "my-process")

        # Or use the context manager
        with registry.track(subprocess.Popen([...]), "my-process") as proc:
            # use proc
        # automatically cleaned up

        # Manual cleanup
        registry.terminate_process(proc.pid)
        registry.unregister(proc.pid)
    """

    _instance: ProcessRegistry | None = None
    _instance_lock: threading.Lock = threading.Lock()
    _initialized: bool = False

    def __new__(cls) -> ProcessRegistry:
        """Create singleton instance with thread-safe double-checked locking."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    cls._instance = instance
        return cls._instance

    def __init__(self) -> None:
        """Initialize the registry (only runs once due to singleton pattern)."""
        if ProcessRegistry._initialized:
            return

        with ProcessRegistry._instance_lock:
            if ProcessRegistry._initialized:
                return

            self._processes: dict[int, ProcessEntry] = {}
            self._lock: threading.Lock = threading.Lock()
            self._cleanup_thread: threading.Thread | None = None
            self._cleanup_stop_event: threading.Event = threading.Event()
            self._atexit_registered: bool = False
            self._finalizer: weakref.finalize[None] | None = None

            self._register_atexit()
            self._start_background_cleanup()

            ProcessRegistry._initialized = True
            logger.debug("ProcessRegistry initialized")

    @classmethod
    def get_instance(cls) -> ProcessRegistry:
        """Get the singleton ProcessRegistry instance."""
        return cls()

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (for testing purposes only)."""
        with cls._instance_lock:
            if cls._instance is not None:
                cls._instance._stop_background_cleanup()
                cls._instance._cleanup_all()
            cls._instance = None
            cls._initialized = False

    def _register_atexit(self) -> None:
        """Register cleanup handler with atexit."""
        if not self._atexit_registered:
            atexit.register(self._atexit_handler)
            self._finalizer = weakref.finalize(self, self._static_cleanup, self._processes, self._lock)
            self._atexit_registered = True
            logger.debug("Registered atexit handler for process cleanup")

    @staticmethod
    def _static_cleanup(processes: dict[int, ProcessEntry], lock: threading.Lock) -> None:
        """Static cleanup method for weakref.finalize."""
        with lock:
            for _pid, entry in list(processes.items()):
                with contextlib.suppress(Exception):
                    if entry.is_alive:
                        entry.process.terminate()
                        try:
                            entry.process.wait(timeout=2.0)
                        except subprocess.TimeoutExpired:
                            entry.process.kill()
                            entry.process.wait(timeout=1.0)

    def _atexit_handler(self) -> None:
        """Handler called by atexit to clean up all processes."""
        self._stop_background_cleanup()
        self._cleanup_all()

    def _start_background_cleanup(self) -> None:
        """Start background thread for periodic stale process cleanup."""
        if self._cleanup_thread is not None and self._cleanup_thread.is_alive():
            return

        self._cleanup_stop_event.clear()
        self._cleanup_thread = threading.Thread(
            target=self._background_cleanup_loop,
            name="ProcessRegistry-Cleanup",
            daemon=True,
        )
        self._cleanup_thread.start()
        logger.debug("Started background cleanup thread")

    def _stop_background_cleanup(self) -> None:
        """Stop the background cleanup thread."""
        if self._cleanup_thread is not None:
            self._cleanup_stop_event.set()
            self._cleanup_thread.join(timeout=2.0)
            self._cleanup_thread = None

    def _background_cleanup_loop(self) -> None:
        """Background loop to clean up stale/zombie processes."""
        cleanup_interval = 30.0
        while not self._cleanup_stop_event.wait(timeout=cleanup_interval):
            self._cleanup_stale_processes()

    def _cleanup_stale_processes(self) -> None:
        """Remove entries for processes that have already terminated."""
        with self._lock:
            stale_pids: list[int] = []
            for pid, entry in self._processes.items():
                if not entry.is_alive:
                    stale_pids.append(pid)
                    logger.debug(
                        "Detected stale process: %s (pid=%d)",
                        entry.name,
                        pid,
                    )

            for pid in stale_pids:
                del self._processes[pid]

            if stale_pids:
                logger.debug("Cleaned up %d stale process entries", len(stale_pids))

    def register(
        self,
        process: subprocess.Popen[Any],
        name: str,
    ) -> subprocess.Popen[Any]:
        """Register a process for tracking.

        Args:
            process: The subprocess.Popen instance to track.
            name: A descriptive name for logging and identification.

        Returns:
            The same process for chaining.
        """
        with self._lock:
            if process.pid in self._processes:
                logger.warning(
                    "Process already registered: %s (pid=%d)",
                    name,
                    process.pid,
                )
                return process

            entry = ProcessEntry(process=process, name=name)
            self._processes[process.pid] = entry
            logger.debug("Registered process: %s (pid=%d)", name, process.pid)
            return process

    def unregister(self, pid: int) -> bool:
        """Unregister a process from tracking.

        Args:
            pid: The process ID to unregister.

        Returns:
            True if the process was found and removed, False otherwise.
        """
        with self._lock:
            if pid in self._processes:
                entry = self._processes.pop(pid)
                logger.debug(
                    "Unregistered process: %s (pid=%d)",
                    entry.name,
                    pid,
                )
                return True
            return False

    def get_entry(self, pid: int) -> ProcessEntry | None:
        """Get a process entry by PID.

        Args:
            pid: The process ID to look up.

        Returns:
            The ProcessEntry if found, None otherwise.
        """
        with self._lock:
            return self._processes.get(pid)

    def get_active_processes(self) -> list[ProcessEntry]:
        """Get all currently active (running) processes.

        Returns:
            List of ProcessEntry objects for running processes.
        """
        with self._lock:
            return [entry for entry in self._processes.values() if entry.is_alive]

    def get_all_entries(self) -> list[ProcessEntry]:
        """Get all registered process entries.

        Returns:
            List of all ProcessEntry objects.
        """
        with self._lock:
            return list(self._processes.values())

    def terminate_process(
        self,
        pid: int,
        timeout: float = 5.0,
        force_timeout: float = 3.0,
    ) -> bool:
        """Gracefully terminate a specific process with fallback to force kill.

        Args:
            pid: The process ID to terminate.
            timeout: Seconds to wait for graceful termination.
            force_timeout: Seconds to wait after kill before giving up.

        Returns:
            True if process was terminated successfully, False otherwise.
        """
        entry = self.get_entry(pid)
        if entry is None:
            logger.warning("Cannot terminate unknown process: pid=%d", pid)
            return False

        if not entry.is_alive:
            logger.debug(
                "Process already terminated: %s (pid=%d)",
                entry.name,
                pid,
            )
            self.unregister(pid)
            return True

        try:
            logger.debug(
                "Terminating process: %s (pid=%d)",
                entry.name,
                pid,
            )
            entry.process.terminate()

            try:
                entry.process.wait(timeout=timeout)
                logger.debug(
                    "Process terminated gracefully: %s (pid=%d)",
                    entry.name,
                    pid,
                )
            except subprocess.TimeoutExpired:
                logger.warning(
                    "Graceful termination timed out, killing: %s (pid=%d)",
                    entry.name,
                    pid,
                )
                entry.process.kill()
                try:
                    entry.process.wait(timeout=force_timeout)
                except subprocess.TimeoutExpired:
                    logger.warning(
                        "Failed to kill process: %s (pid=%d)",
                        entry.name,
                        pid,
                    )
                    return False

            self.unregister(pid)
            return True

        except OSError:
            logger.exception(
                "Error terminating process %s (pid=%d)",
                entry.name,
                pid,
            )
            return False

    def terminate_all(self, timeout: float = 5.0) -> int:
        """Terminate all registered processes.

        Args:
            timeout: Seconds to wait for each process termination.

        Returns:
            Number of processes successfully terminated.
        """
        with self._lock:
            pids = list(self._processes.keys())

        terminated = 0
        for pid in pids:
            if self.terminate_process(pid, timeout=timeout):
                terminated += 1

        return terminated

    def _cleanup_all(self) -> None:
        """Clean up all registered processes (called by atexit)."""
        with self._lock:
            if not self._processes:
                return

            logger.info(
                "Cleaning up %d registered processes",
                len(self._processes),
            )

            for pid, entry in list(self._processes.items()):
                if entry.is_alive:
                    try:
                        entry.process.terminate()
                        try:
                            entry.process.wait(timeout=3.0)
                        except subprocess.TimeoutExpired:
                            entry.process.kill()
                            entry.process.wait(timeout=2.0)
                        logger.debug(
                            "Cleaned up process: %s (pid=%d)",
                            entry.name,
                            pid,
                        )
                    except Exception as e:
                        logger.warning(
                            "Failed to clean up process %s (pid=%d): %s",
                            entry.name,
                            pid,
                            e,
                        )

            self._processes.clear()

    @contextmanager
    def track(
        self,
        process: subprocess.Popen[Any],
        name: str,
    ) -> Generator[subprocess.Popen[Any], None, None]:
        """Context manager for automatic process tracking and cleanup.

        Args:
            process: The subprocess.Popen instance to track.
            name: A descriptive name for logging.

        Yields:
            The tracked process.

        Example:
            with registry.track(subprocess.Popen([...]), "my-proc") as proc:
                # use proc
            # automatically terminated and unregistered
        """
        self.register(process, name)
        try:
            yield process
        finally:
            if process.poll() is None:
                self.terminate_process(process.pid)
            else:
                self.unregister(process.pid)

    def __len__(self) -> int:
        """Return the number of registered processes."""
        with self._lock:
            return len(self._processes)

    def __contains__(self, pid: int) -> bool:
        """Check if a PID is registered."""
        with self._lock:
            return pid in self._processes


def get_process_registry() -> ProcessRegistry:
    """Get the global ProcessRegistry singleton.

    Returns:
        The ProcessRegistry singleton instance.
    """
    return ProcessRegistry.get_instance()


process_registry = ProcessRegistry.get_instance()
