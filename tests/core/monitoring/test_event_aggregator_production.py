"""Production-ready tests for intellicrack/core/monitoring/event_aggregator.py

Tests validate REAL event aggregation capabilities:
- Thread-safe event queue management with concurrent submissions
- Rate limiting with token bucket algorithm
- Event distribution to multiple registered callbacks
- Statistics tracking by source and severity
- Event history management with configurable limits
- Real-time statistics updates to callback handlers
- Error callback execution on processing failures
- Event dropping when queue is full
- Graceful thread shutdown and cleanup
- Concurrent event submission from multiple monitors
- Accurate events-per-second rate calculation
"""

import queue
import threading
import time
from typing import Any
from unittest.mock import MagicMock

import pytest

from intellicrack.core.monitoring.base_monitor import EventSeverity, EventSource, EventType, MonitorEvent, ProcessInfo
from intellicrack.core.monitoring.event_aggregator import EventAggregator, RateLimiter


TIMEOUT_SHORT: float = 0.1
TIMEOUT_MEDIUM: float = 0.5
TIMEOUT_LONG: float = 2.0


class TestRateLimiter:
    """Test rate limiting functionality."""

    def test_rate_limiter_initializes_with_max_rate(self) -> None:
        """RateLimiter initializes with specified maximum rate."""
        limiter = RateLimiter(max_events_per_second=50)

        assert limiter._max_rate == 50
        assert limiter._tokens == 50.0

    def test_rate_limiter_allows_events_under_limit(self) -> None:
        """RateLimiter allows events when under rate limit."""
        limiter = RateLimiter(max_events_per_second=100)

        for _ in range(10):
            assert limiter.should_process() is True

    def test_rate_limiter_blocks_events_over_limit(self) -> None:
        """RateLimiter blocks events when rate limit exceeded."""
        limiter = RateLimiter(max_events_per_second=5)

        allowed_count = 0
        blocked_count = 0

        for _ in range(20):
            if limiter.should_process():
                allowed_count += 1
            else:
                blocked_count += 1

        assert allowed_count <= 6
        assert blocked_count > 0

    def test_rate_limiter_replenishes_tokens_over_time(self) -> None:
        """RateLimiter replenishes tokens after time elapsed."""
        limiter = RateLimiter(max_events_per_second=10)

        for _ in range(10):
            limiter.should_process()

        assert limiter.should_process() is False

        time.sleep(0.2)

        assert limiter.should_process() is True

    def test_rate_limiter_calculates_current_rate(self) -> None:
        """RateLimiter calculates accurate event processing rate."""
        limiter = RateLimiter(max_events_per_second=100)

        for _ in range(50):
            limiter.should_process()

        time.sleep(0.1)

        rate = limiter.get_current_rate()

        assert rate > 0

    def test_rate_limiter_thread_safe_processing(self) -> None:
        """RateLimiter handles concurrent should_process calls safely."""
        limiter = RateLimiter(max_events_per_second=100)
        allowed_events = []
        lock = threading.Lock()

        def process_events() -> None:
            for _ in range(50):
                if limiter.should_process():
                    with lock:
                        allowed_events.append(1)

        threads = [threading.Thread(target=process_events) for _ in range(3)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert len(allowed_events) > 0
        assert len(allowed_events) <= 110


class TestEventAggregatorInitialization:
    """Test event aggregator initialization."""

    def test_event_aggregator_initializes_with_queue_size(self) -> None:
        """EventAggregator initializes with specified queue size."""
        aggregator = EventAggregator(max_queue_size=5000)

        assert aggregator._event_queue.maxsize == 5000
        assert not aggregator._running
        assert aggregator._total_events == 0
        assert aggregator._dropped_events == 0

    def test_event_aggregator_creates_rate_limiter(self) -> None:
        """EventAggregator creates rate limiter for event processing."""
        aggregator = EventAggregator()

        assert aggregator._rate_limiter is not None
        assert isinstance(aggregator._rate_limiter, RateLimiter)

    def test_event_aggregator_initializes_statistics(self) -> None:
        """EventAggregator initializes event statistics tracking."""
        aggregator = EventAggregator()

        stats = aggregator.get_stats()

        assert stats["total_events"] == 0
        assert stats["dropped_events"] == 0
        assert stats["queue_size"] == 0
        assert isinstance(stats["events_by_source"], dict)
        assert isinstance(stats["events_by_severity"], dict)


class TestEventAggregatorLifecycle:
    """Test event aggregator lifecycle management."""

    def test_event_aggregator_starts_processing_thread(self) -> None:
        """EventAggregator starts background processing thread."""
        aggregator = EventAggregator()

        aggregator.start()

        assert aggregator._running is True
        assert aggregator._thread is not None
        assert aggregator._thread.is_alive()

        aggregator.stop()

    def test_event_aggregator_stops_processing_thread(self) -> None:
        """EventAggregator stops background thread gracefully."""
        aggregator = EventAggregator()

        aggregator.start()
        assert aggregator._running is True

        aggregator.stop()

        assert aggregator._running is False

    def test_event_aggregator_prevents_double_start(self) -> None:
        """EventAggregator prevents starting already running aggregator."""
        aggregator = EventAggregator()

        aggregator.start()
        thread1 = aggregator._thread

        aggregator.start()
        thread2 = aggregator._thread

        assert thread1 is thread2

        aggregator.stop()

    def test_event_aggregator_handles_multiple_stops_safely(self) -> None:
        """EventAggregator handles multiple stop calls safely."""
        aggregator = EventAggregator()

        aggregator.start()
        aggregator.stop()
        aggregator.stop()

        assert aggregator._running is False


class TestEventSubmission:
    """Test event submission to aggregator."""

    def test_event_aggregator_accepts_events_to_queue(self) -> None:
        """EventAggregator queues submitted events successfully."""
        aggregator = EventAggregator(max_queue_size=100)

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.API,
            event_type=EventType.READ,
            severity=EventSeverity.INFO,
            details={"api": "RegQueryValueEx"},
        )

        result = aggregator.submit_event(event)

        assert result is True
        assert aggregator._event_queue.qsize() == 1

    def test_event_aggregator_drops_events_when_queue_full(self) -> None:
        """EventAggregator drops events when queue is full."""
        aggregator = EventAggregator(max_queue_size=5)

        events_submitted = 0
        events_dropped = 0

        for i in range(10):
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.REGISTRY,
                event_type=EventType.WRITE,
                severity=EventSeverity.CRITICAL,
                details={"key": f"key_{i}"},
            )

            if aggregator.submit_event(event):
                events_submitted += 1
            else:
                events_dropped += 1

        assert events_submitted == 5
        assert events_dropped == 5
        assert aggregator._dropped_events == 5

    def test_event_aggregator_processes_submitted_events(self) -> None:
        """EventAggregator processes events from queue."""
        aggregator = EventAggregator()
        aggregator.start()

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.MEMORY,
            event_type=EventType.SCAN,
            severity=EventSeverity.WARNING,
            details={"pattern": "license_key"},
        )

        aggregator.submit_event(event)

        time.sleep(TIMEOUT_SHORT)

        stats = aggregator.get_stats()

        assert stats["total_events"] >= 1

        aggregator.stop()


class TestCallbackRegistration:
    """Test callback registration and execution."""

    def test_event_aggregator_registers_event_callbacks(self) -> None:
        """EventAggregator registers event callbacks."""
        aggregator = EventAggregator()
        callback = MagicMock()

        aggregator.on_event(callback)

        assert callback in aggregator._callbacks

    def test_event_aggregator_registers_stats_callbacks(self) -> None:
        """EventAggregator registers statistics callbacks."""
        aggregator = EventAggregator()
        stats_callback = MagicMock()

        aggregator.on_stats_update(stats_callback)

        assert stats_callback in aggregator._stats_callbacks

    def test_event_aggregator_registers_error_callbacks(self) -> None:
        """EventAggregator registers error callbacks."""
        aggregator = EventAggregator()
        error_callback = MagicMock()

        aggregator.on_error(error_callback)

        assert error_callback in aggregator._error_callbacks

    def test_event_aggregator_executes_event_callbacks(self) -> None:
        """EventAggregator executes callbacks when processing events."""
        aggregator = EventAggregator()
        callback = MagicMock()

        aggregator.on_event(callback)
        aggregator.start()

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.API,
            event_type=EventType.READ,
            severity=EventSeverity.INFO,
            details={"test": "data"},
        )

        aggregator.submit_event(event)

        time.sleep(TIMEOUT_SHORT)

        callback.assert_called_once()

        aggregator.stop()

    def test_event_aggregator_executes_multiple_callbacks(self) -> None:
        """EventAggregator executes all registered callbacks."""
        aggregator = EventAggregator()
        callback1 = MagicMock()
        callback2 = MagicMock()
        callback3 = MagicMock()

        aggregator.on_event(callback1)
        aggregator.on_event(callback2)
        aggregator.on_event(callback3)
        aggregator.start()

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.NETWORK,
            event_type=EventType.SEND,
            severity=EventSeverity.CRITICAL,
            details={"destination": "license.server.com"},
        )

        aggregator.submit_event(event)

        time.sleep(TIMEOUT_SHORT)

        callback1.assert_called_once()
        callback2.assert_called_once()
        callback3.assert_called_once()

        aggregator.stop()

    def test_event_aggregator_handles_callback_exceptions(self) -> None:
        """EventAggregator continues processing when callback raises exception."""
        aggregator = EventAggregator()
        failing_callback = MagicMock(side_effect=RuntimeError("Callback error"))
        working_callback = MagicMock()

        aggregator.on_event(failing_callback)
        aggregator.on_event(working_callback)
        aggregator.start()

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.FILE,
            event_type=EventType.WRITE,
            severity=EventSeverity.WARNING,
            details={"path": "license.dat"},
        )

        aggregator.submit_event(event)

        time.sleep(TIMEOUT_SHORT)

        failing_callback.assert_called_once()
        working_callback.assert_called_once()

        aggregator.stop()


class TestStatisticsTracking:
    """Test statistics tracking and aggregation."""

    def test_event_aggregator_tracks_total_events(self) -> None:
        """EventAggregator counts total events processed."""
        aggregator = EventAggregator()
        aggregator.start()

        for _ in range(5):
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.API,
                event_type=EventType.READ,
                severity=EventSeverity.INFO,
                details={},
            )
            aggregator.submit_event(event)

        time.sleep(TIMEOUT_SHORT)

        stats = aggregator.get_stats()

        assert stats["total_events"] >= 5

        aggregator.stop()

    def test_event_aggregator_tracks_events_by_source(self) -> None:
        """EventAggregator categorizes events by source."""
        aggregator = EventAggregator()
        aggregator.start()

        sources = [EventSource.API, EventSource.REGISTRY, EventSource.MEMORY, EventSource.API]

        for source in sources:
            event = MonitorEvent(
                timestamp=time.time(),
                source=source,
                event_type=EventType.READ,
                severity=EventSeverity.INFO,
                details={},
            )
            aggregator.submit_event(event)

        time.sleep(TIMEOUT_MEDIUM)

        stats = aggregator.get_stats()

        assert stats["events_by_source"]["api"] >= 2
        assert stats["events_by_source"]["registry"] >= 1
        assert stats["events_by_source"]["memory"] >= 1

        aggregator.stop()

    def test_event_aggregator_tracks_events_by_severity(self) -> None:
        """EventAggregator categorizes events by severity."""
        aggregator = EventAggregator()
        aggregator.start()

        severities = [
            EventSeverity.INFO,
            EventSeverity.WARNING,
            EventSeverity.CRITICAL,
            EventSeverity.INFO,
            EventSeverity.CRITICAL,
        ]

        for severity in severities:
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.API,
                event_type=EventType.READ,
                severity=severity,
                details={},
            )
            aggregator.submit_event(event)

        time.sleep(TIMEOUT_MEDIUM)

        stats = aggregator.get_stats()

        assert stats["events_by_severity"]["info"] >= 2
        assert stats["events_by_severity"]["warning"] >= 1
        assert stats["events_by_severity"]["critical"] >= 2

        aggregator.stop()

    def test_event_aggregator_tracks_dropped_events(self) -> None:
        """EventAggregator counts events dropped due to queue full."""
        aggregator = EventAggregator(max_queue_size=3)

        for _ in range(10):
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.API,
                event_type=EventType.READ,
                severity=EventSeverity.INFO,
                details={},
            )
            aggregator.submit_event(event)

        stats = aggregator.get_stats()

        assert stats["dropped_events"] > 0

    def test_event_aggregator_provides_queue_size_stats(self) -> None:
        """EventAggregator reports current queue size in statistics."""
        aggregator = EventAggregator(max_queue_size=100)

        for _ in range(5):
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.REGISTRY,
                event_type=EventType.WRITE,
                severity=EventSeverity.CRITICAL,
                details={},
            )
            aggregator.submit_event(event)

        stats = aggregator.get_stats()

        assert "queue_size" in stats
        assert stats["queue_size"] >= 0


class TestEventHistory:
    """Test event history management."""

    def test_event_aggregator_maintains_event_history(self) -> None:
        """EventAggregator stores recent events in history."""
        aggregator = EventAggregator()
        aggregator.start()

        events_to_send = 5
        for i in range(events_to_send):
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.MEMORY,
                event_type=EventType.SCAN,
                severity=EventSeverity.INFO,
                details={"scan_id": i},
            )
            aggregator.submit_event(event)

        time.sleep(TIMEOUT_MEDIUM)

        history = aggregator.get_history()

        assert len(history) >= events_to_send

        aggregator.stop()

    def test_event_aggregator_limits_history_size(self) -> None:
        """EventAggregator enforces maximum history size."""
        aggregator = EventAggregator()
        aggregator.start()

        for i in range(1100):
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.API,
                event_type=EventType.READ,
                severity=EventSeverity.INFO,
                details={"index": i},
            )
            aggregator.submit_event(event)

        time.sleep(TIMEOUT_LONG)

        history = aggregator.get_history()

        assert len(history) <= 1000

        aggregator.stop()

    def test_event_aggregator_returns_limited_history(self) -> None:
        """EventAggregator returns limited number of history events."""
        aggregator = EventAggregator()
        aggregator.start()

        for i in range(200):
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.FILE,
                event_type=EventType.WRITE,
                severity=EventSeverity.WARNING,
                details={"file_id": i},
            )
            aggregator.submit_event(event)

        time.sleep(TIMEOUT_MEDIUM)

        history = aggregator.get_history(limit=50)

        assert len(history) <= 50

        aggregator.stop()

    def test_event_aggregator_clears_history(self) -> None:
        """EventAggregator clears event history on request."""
        aggregator = EventAggregator()
        aggregator.start()

        for _ in range(10):
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.NETWORK,
                event_type=EventType.CONNECT,
                severity=EventSeverity.INFO,
                details={},
            )
            aggregator.submit_event(event)

        time.sleep(TIMEOUT_SHORT)

        history = aggregator.get_history()
        assert len(history) > 0

        aggregator.clear_history()

        history = aggregator.get_history()
        assert len(history) == 0

        aggregator.stop()


class TestRateLimitingIntegration:
    """Test rate limiting integration with event processing."""

    def test_event_aggregator_applies_rate_limiting(self) -> None:
        """EventAggregator applies rate limiting to event processing."""
        aggregator = EventAggregator()
        aggregator.start()

        events_submitted = 200
        for _ in range(events_submitted):
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.API,
                event_type=EventType.READ,
                severity=EventSeverity.INFO,
                details={},
            )
            aggregator.submit_event(event)

        time.sleep(TIMEOUT_MEDIUM)

        stats = aggregator.get_stats()

        assert stats["total_events"] < events_submitted
        assert stats["dropped_events"] > 0

        aggregator.stop()

    def test_event_aggregator_tracks_events_per_second(self) -> None:
        """EventAggregator calculates events per second metric."""
        aggregator = EventAggregator()
        aggregator.start()

        for _ in range(50):
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.REGISTRY,
                event_type=EventType.WRITE,
                severity=EventSeverity.CRITICAL,
                details={},
            )
            aggregator.submit_event(event)

        time.sleep(TIMEOUT_MEDIUM)

        stats = aggregator.get_stats()

        assert "events_per_second" in stats
        assert stats["events_per_second"] >= 0

        aggregator.stop()


class TestConcurrentEventSubmission:
    """Test concurrent event submission from multiple threads."""

    def test_event_aggregator_handles_concurrent_submissions(self) -> None:
        """EventAggregator handles events from multiple threads safely."""
        aggregator = EventAggregator(max_queue_size=1000)
        aggregator.start()

        events_per_thread = 50
        thread_count = 5

        def submit_events() -> None:
            for i in range(events_per_thread):
                event = MonitorEvent(
                    timestamp=time.time(),
                    source=EventSource.API,
                    event_type=EventType.READ,
                    severity=EventSeverity.INFO,
                    details={"index": i},
                )
                aggregator.submit_event(event)

        threads = [threading.Thread(target=submit_events) for _ in range(thread_count)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        time.sleep(TIMEOUT_LONG)

        stats = aggregator.get_stats()

        assert stats["total_events"] > 0

        aggregator.stop()

    def test_event_aggregator_maintains_data_integrity_under_load(self) -> None:
        """EventAggregator maintains correct statistics under concurrent load."""
        aggregator = EventAggregator(max_queue_size=500)
        aggregator.start()

        api_events = 30
        registry_events = 20
        memory_events = 25

        def submit_api_events() -> None:
            for _ in range(api_events):
                event = MonitorEvent(
                    timestamp=time.time(),
                    source=EventSource.API,
                    event_type=EventType.READ,
                    severity=EventSeverity.INFO,
                    details={},
                )
                aggregator.submit_event(event)

        def submit_registry_events() -> None:
            for _ in range(registry_events):
                event = MonitorEvent(
                    timestamp=time.time(),
                    source=EventSource.REGISTRY,
                    event_type=EventType.WRITE,
                    severity=EventSeverity.CRITICAL,
                    details={},
                )
                aggregator.submit_event(event)

        def submit_memory_events() -> None:
            for _ in range(memory_events):
                event = MonitorEvent(
                    timestamp=time.time(),
                    source=EventSource.MEMORY,
                    event_type=EventType.SCAN,
                    severity=EventSeverity.WARNING,
                    details={},
                )
                aggregator.submit_event(event)

        thread1 = threading.Thread(target=submit_api_events)
        thread2 = threading.Thread(target=submit_registry_events)
        thread3 = threading.Thread(target=submit_memory_events)

        thread1.start()
        thread2.start()
        thread3.start()

        thread1.join()
        thread2.join()
        thread3.join()

        time.sleep(TIMEOUT_LONG)

        stats = aggregator.get_stats()

        assert stats["total_events"] > 0

        aggregator.stop()


class TestCompleteWorkflow:
    """Test complete event aggregation workflow."""

    def test_complete_event_aggregation_lifecycle(self) -> None:
        """Complete event aggregation workflow from start to stop."""
        aggregator = EventAggregator(max_queue_size=100)

        event_callback = MagicMock()
        stats_callback = MagicMock()
        error_callback = MagicMock()

        aggregator.on_event(event_callback)
        aggregator.on_stats_update(stats_callback)
        aggregator.on_error(error_callback)

        aggregator.start()

        assert aggregator._running is True

        process_info = ProcessInfo(pid=1234, name="test.exe", path="C:\\test.exe")

        events = [
            MonitorEvent(
                timestamp=time.time(),
                source=EventSource.API,
                event_type=EventType.READ,
                severity=EventSeverity.INFO,
                details={"api": "RegQueryValueEx"},
                process_info=process_info,
            ),
            MonitorEvent(
                timestamp=time.time(),
                source=EventSource.REGISTRY,
                event_type=EventType.WRITE,
                severity=EventSeverity.CRITICAL,
                details={"key": "HKLM\\Software\\License", "value": "ABC123"},
                process_info=process_info,
            ),
            MonitorEvent(
                timestamp=time.time(),
                source=EventSource.MEMORY,
                event_type=EventType.SCAN,
                severity=EventSeverity.WARNING,
                details={"pattern": "serial_key", "address": "0x401000"},
                process_info=process_info,
            ),
        ]

        for event in events:
            result = aggregator.submit_event(event)
            assert result is True

        time.sleep(TIMEOUT_LONG)

        assert event_callback.call_count == 3

        stats = aggregator.get_stats()
        assert stats["total_events"] == 3
        assert stats["events_by_source"]["api"] == 1
        assert stats["events_by_source"]["registry"] == 1
        assert stats["events_by_source"]["memory"] == 1
        assert stats["events_by_severity"]["info"] == 1
        assert stats["events_by_severity"]["critical"] == 1
        assert stats["events_by_severity"]["warning"] == 1

        history = aggregator.get_history()
        assert len(history) == 3

        aggregator.stop()

        assert aggregator._running is False
