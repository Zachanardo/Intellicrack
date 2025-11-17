"""Base Monitor Abstract Class.

Defines the interface and common functionality for all monitoring backends.
Follows SOLID principles for clean extensibility.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventSource(Enum):
    """Event source types."""

    API = "api"
    REGISTRY = "registry"
    FILE = "file"
    NETWORK = "network"
    MEMORY = "memory"


class EventType(Enum):
    """Event operation types."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    CONNECT = "connect"
    SEND = "send"
    RECEIVE = "receive"
    SCAN = "scan"
    CREATE = "create"
    MODIFY = "modify"
    ACCESS = "access"


class EventSeverity(Enum):
    """Event severity levels."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class ProcessInfo:
    """Process information."""

    pid: int
    name: str
    path: str


@dataclass
class MonitorEvent:
    """Standardized monitoring event structure."""

    timestamp: float
    source: EventSource
    event_type: EventType
    severity: EventSeverity
    details: dict[str, Any]
    process_info: ProcessInfo | None = None
    call_stack: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary."""
        return {
            "timestamp": self.timestamp,
            "source": self.source.value,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "details": self.details,
            "process_info": {"pid": self.process_info.pid, "name": self.process_info.name, "path": self.process_info.path}
            if self.process_info
            else None,
            "call_stack": self.call_stack,
        }


class MonitorStats:
    """Monitor statistics tracking."""

    def __init__(self) -> None:
        """Initialize statistics."""
        self.total_events = 0
        self.events_by_type: dict[str, int] = {}
        self.events_per_second = 0.0
        self.start_time = time.time()
        self.last_event_time = 0.0
        self._lock = threading.Lock()

    def record_event(self, event: MonitorEvent) -> None:
        """Record an event for statistics.

        Args:
            event: The event to record.

        """
        with self._lock:
            self.total_events += 1
            event_type = event.event_type.value
            self.events_by_type[event_type] = self.events_by_type.get(event_type, 0) + 1
            self.last_event_time = event.timestamp

            elapsed = time.time() - self.start_time
            if elapsed > 0:
                self.events_per_second = self.total_events / elapsed

    def get_stats(self) -> dict[str, Any]:
        """Get current statistics.

        Returns:
            Dictionary of statistics.

        """
        with self._lock:
            return {
                "total_events": self.total_events,
                "events_by_type": self.events_by_type.copy(),
                "events_per_second": self.events_per_second,
                "uptime": time.time() - self.start_time,
                "last_event": self.last_event_time,
            }

    def reset(self) -> None:
        """Reset statistics."""
        with self._lock:
            self.total_events = 0
            self.events_by_type.clear()
            self.events_per_second = 0.0
            self.start_time = time.time()
            self.last_event_time = 0.0


class BaseMonitor(ABC):
    """Abstract base class for all monitors.

    Implements Single Responsibility Principle: Each monitor handles one aspect.
    Implements Open/Closed Principle: Easy to extend with new monitor types.
    Implements Liskov Substitution: All monitors are interchangeable via this interface.
    Implements Interface Segregation: Clean, minimal interface.
    Implements Dependency Inversion: Depends on abstractions, not implementations.
    """

    def __init__(self, name: str, process_info: ProcessInfo | None = None) -> None:
        """Initialize base monitor.

        Args:
            name: Monitor name for identification.
            process_info: Target process information.

        """
        self.name = name
        self.process_info = process_info
        self._running = False
        self._thread: threading.Thread | None = None
        self._callbacks: list[Callable[[MonitorEvent], None]] = []
        self._stats = MonitorStats()
        self._error_count = 0
        self._max_errors = 10
        self._lock = threading.Lock()

    @abstractmethod
    def _start_monitoring(self) -> bool:
        """Start the monitoring implementation.

        Returns:
            True if monitoring started successfully, False otherwise.

        """

    @abstractmethod
    def _stop_monitoring(self) -> None:
        """Stop the monitoring implementation."""

    def start(self) -> bool:
        """Start monitoring.

        Returns:
            True if started successfully, False otherwise.

        """
        with self._lock:
            if self._running:
                return True

            try:
                if self._start_monitoring():
                    self._running = True
                    self._stats.reset()
                    return True
                return False
            except Exception as e:
                print(f"[{self.name}] Failed to start: {e}")
                return False

    def stop(self) -> None:
        """Stop monitoring."""
        with self._lock:
            if not self._running:
                return

            try:
                self._stop_monitoring()
            except Exception as e:
                print(f"[{self.name}] Error stopping: {e}")
            finally:
                self._running = False

    def is_running(self) -> bool:
        """Check if monitor is running.

        Returns:
            True if running, False otherwise.

        """
        return self._running

    def get_stats(self) -> dict[str, Any]:
        """Get monitoring statistics.

        Returns:
            Dictionary of statistics.

        """
        stats = self._stats.get_stats()
        stats["monitor_name"] = self.name
        stats["error_count"] = self._error_count
        stats["running"] = self._running
        return stats

    def on_event(self, callback: Callable[[MonitorEvent], None]) -> None:
        """Register event callback.

        Args:
            callback: Function to call when event occurs.

        """
        self._callbacks.append(callback)

    def _emit_event(self, event: MonitorEvent) -> None:
        """Emit an event to all registered callbacks.

        Args:
            event: The event to emit.

        """
        self._stats.record_event(event)

        for callback in self._callbacks:
            try:
                callback(event)
            except Exception as e:
                print(f"[{self.name}] Error in callback: {e}")

    def _handle_error(self, error: Exception) -> bool:
        """Handle monitoring error.

        Args:
            error: The exception that occurred.

        Returns:
            True if monitoring should continue, False if it should stop.

        """
        self._error_count += 1
        print(f"[{self.name}] Error ({self._error_count}/{self._max_errors}): {error}")

        if self._error_count >= self._max_errors:
            print(f"[{self.name}] Max errors reached, stopping monitor")
            self.stop()
            return False

        return True

    def reset_errors(self) -> None:
        """Reset error counter."""
        self._error_count = 0
