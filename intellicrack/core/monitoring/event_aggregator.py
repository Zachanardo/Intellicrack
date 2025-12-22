"""Event Aggregator for centralized event collection and distribution.

Thread-safe event queue management with rate limiting, filtering, and
distribution to GUI and logging systems.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import queue
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from typing import Any

from intellicrack.core.monitoring.base_monitor import MonitorEvent


class EventAggregator:
    """Centralized event collection and distribution system.

    Collects events from all monitors via thread-safe queue,
    applies rate limiting and filtering, and distributes to callbacks.
    """

    def __init__(self, max_queue_size: int = 10000) -> None:
        """Initialize event aggregator.

        Args:
            max_queue_size: Maximum events to hold in queue.

        """
        self._event_queue: queue.Queue[MonitorEvent] = queue.Queue(maxsize=max_queue_size)
        self._running = False
        self._thread: threading.Thread | None = None
        self._callbacks: list[Callable[[MonitorEvent], None]] = []
        self._stats_callbacks: list[Callable[[dict[str, Any]], None]] = []
        self._error_callbacks: list[Callable[[str], None]] = []

        self._total_events = 0
        self._events_by_source: dict[str, int] = defaultdict(int)
        self._events_by_severity: dict[str, int] = defaultdict(int)
        self._dropped_events = 0

        self._rate_limiter = RateLimiter(max_events_per_second=100)
        self._event_history: deque[MonitorEvent] = deque(maxlen=1000)

        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the event aggregator thread."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._process_events, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the event aggregator thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def submit_event(self, event: MonitorEvent) -> bool:
        """Submit an event for processing.

        Args:
            event: The monitoring event to process.

        Returns:
            True if event was queued, False if dropped (queue full).

        """
        try:
            self._event_queue.put_nowait(event)
            return True
        except queue.Full:
            self._dropped_events += 1
            return False

    def on_event(self, callback: Callable[[MonitorEvent], None]) -> None:
        """Register callback for events.

        Args:
            callback: Function to call for each event.

        """
        self._callbacks.append(callback)

    def on_stats_update(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Register callback for statistics updates.

        Args:
            callback: Function to call with statistics.

        """
        self._stats_callbacks.append(callback)

    def on_error(self, callback: Callable[[str], None]) -> None:
        """Register callback for errors.

        Args:
            callback: Function to call with error message.

        """
        self._error_callbacks.append(callback)

    def get_stats(self) -> dict[str, Any]:
        """Get aggregator statistics.

        Returns:
            Dictionary of statistics.

        """
        with self._lock:
            return {
                "total_events": self._total_events,
                "events_by_source": dict(self._events_by_source),
                "events_by_severity": dict(self._events_by_severity),
                "dropped_events": self._dropped_events,
                "queue_size": self._event_queue.qsize(),
                "events_per_second": self._rate_limiter.get_current_rate(),
            }

    def clear_history(self) -> None:
        """Clear event history."""
        with self._lock:
            self._event_history.clear()

    def get_history(self, limit: int = 100) -> list[MonitorEvent]:
        """Get recent event history.

        Args:
            limit: Maximum number of events to return.

        Returns:
            List of recent events.

        """
        with self._lock:
            return list(self._event_history)[-limit:]

    def _process_events(self) -> None:
        """Process events from queue in dedicated thread."""
        stats_update_interval = 1.0
        last_stats_update = time.time()

        while self._running:
            try:
                event = self._event_queue.get(timeout=0.1)

                if self._rate_limiter.should_process():
                    self._process_single_event(event)
                else:
                    self._dropped_events += 1

                current_time = time.time()
                if current_time - last_stats_update >= stats_update_interval:
                    self._emit_stats()
                    last_stats_update = current_time

            except queue.Empty:
                continue
            except Exception as e:
                self._emit_error(f"Event processing error: {e}")

    def _process_single_event(self, event: MonitorEvent) -> None:
        """Process a single event.

        Args:
            event: The event to process.

        """
        with self._lock:
            self._total_events += 1
            self._events_by_source[event.source.value] += 1
            self._events_by_severity[event.severity.value] += 1
            self._event_history.append(event)

        for callback in self._callbacks:
            try:
                callback(event)
            except Exception as e:
                self._emit_error(f"Event callback error: {e}")

    def _emit_stats(self) -> None:
        """Emit statistics update to callbacks."""
        stats = self.get_stats()
        for callback in self._stats_callbacks:
            try:
                callback(stats)
            except Exception as e:
                print(f"Stats callback error: {e}")

    def _emit_error(self, error: str) -> None:
        """Emit error to callbacks.

        Args:
            error: Error message.

        """
        for callback in self._error_callbacks:
            try:
                callback(error)
            except Exception as e:
                print(f"Error callback error: {e}")


class RateLimiter:
    """Token bucket rate limiter for event processing."""

    def __init__(self, max_events_per_second: int = 100) -> None:
        """Initialize rate limiter.

        Args:
            max_events_per_second: Maximum events to process per second.

        """
        self._max_rate = max_events_per_second
        self._tokens = float(max_events_per_second)
        self._last_update = time.time()
        self._lock = threading.Lock()
        self._event_count = 0
        self._window_start = time.time()

    def should_process(self) -> bool:
        """Check if event should be processed based on rate limit.

        Returns:
            True if event can be processed, False if rate limit exceeded.

        """
        with self._lock:
            current_time = time.time()
            elapsed = current_time - self._last_update

            self._tokens = min(self._max_rate, self._tokens + elapsed * self._max_rate)
            self._last_update = current_time

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                self._event_count += 1
                return True

            return False

    def get_current_rate(self) -> float:
        """Get current event processing rate.

        Returns:
            Events per second.

        """
        with self._lock:
            elapsed = time.time() - self._window_start
            if elapsed >= 1.0:
                rate = self._event_count / elapsed
                self._event_count = 0
                self._window_start = time.time()
                return rate
            return 0.0 if elapsed == 0 else self._event_count / elapsed
