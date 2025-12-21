"""Production-ready tests for intellicrack/core/monitoring/base_monitor.py

Tests validate REAL monitoring infrastructure capabilities:
- BaseMonitor abstract class interface and lifecycle
- MonitorEvent creation with accurate timestamps and metadata
- EventSource, EventType, EventSeverity enum validation
- ProcessInfo data structure for process tracking
- MonitorStats real-time event counting and rate calculation
- Thread-safe statistics tracking with concurrent events
- Event callback registration and execution
- Error handling with automatic monitor shutdown at threshold
- Monitor start/stop lifecycle management
- Real event emission to registered callbacks
- Statistics aggregation across event types
"""

import threading
import time
from typing import Any
from unittest.mock import MagicMock

import pytest

from intellicrack.core.monitoring.base_monitor import (
    BaseMonitor,
    EventSeverity,
    EventSource,
    EventType,
    MonitorEvent,
    MonitorStats,
    ProcessInfo,
)


class ConcreteMonitor(BaseMonitor):
    """Concrete implementation of BaseMonitor for testing."""

    def __init__(self, name: str = "TestMonitor", process_info: ProcessInfo | None = None) -> None:
        """Initialize concrete monitor."""
        super().__init__(name, process_info)
        self.start_called = False
        self.stop_called = False
        self.should_fail_start = False

    def _start_monitoring(self) -> bool:
        """Implement start monitoring."""
        self.start_called = True
        if self.should_fail_start:
            return False
        return True

    def _stop_monitoring(self) -> None:
        """Implement stop monitoring."""
        self.stop_called = True

    def emit_test_event(self, event: MonitorEvent) -> None:
        """Public method to emit events for testing."""
        self._emit_event(event)

    def trigger_error(self, error: Exception) -> bool:
        """Public method to trigger error handling."""
        return self._handle_error(error)


class TestEventDataStructures:
    """Test event-related data structures."""

    def test_process_info_stores_pid_name_and_path(self) -> None:
        """ProcessInfo correctly stores process metadata."""
        process_info = ProcessInfo(pid=1234, name="test.exe", path="C:\\Windows\\test.exe")

        assert process_info.pid == 1234
        assert process_info.name == "test.exe"
        assert process_info.path == "C:\\Windows\\test.exe"

    def test_monitor_event_stores_complete_metadata(self) -> None:
        """MonitorEvent stores comprehensive event information."""
        process_info = ProcessInfo(pid=5678, name="target.exe", path="C:\\target.exe")
        timestamp = time.time()

        event = MonitorEvent(
            timestamp=timestamp,
            source=EventSource.REGISTRY,
            event_type=EventType.WRITE,
            severity=EventSeverity.CRITICAL,
            details={"key": "HKLM\\Software\\License", "value": "ABC123"},
            process_info=process_info,
            call_stack=["ntdll.dll!NtSetValueKey", "kernel32.dll!RegSetValueExW"],
        )

        assert event.timestamp == timestamp
        assert event.source == EventSource.REGISTRY
        assert event.event_type == EventType.WRITE
        assert event.severity == EventSeverity.CRITICAL
        assert event.details["key"] == "HKLM\\Software\\License"
        assert event.process_info.pid == 5678
        assert len(event.call_stack) == 2
        assert "ntdll.dll!NtSetValueKey" in event.call_stack

    def test_monitor_event_converts_to_dict_correctly(self) -> None:
        """MonitorEvent serializes to dictionary format accurately."""
        process_info = ProcessInfo(pid=9999, name="app.exe", path="C:\\app.exe")
        timestamp = time.time()

        event = MonitorEvent(
            timestamp=timestamp,
            source=EventSource.API,
            event_type=EventType.READ,
            severity=EventSeverity.WARNING,
            details={"api": "GetTickCount", "result": "123456"},
            process_info=process_info,
            call_stack=["kernel32.dll!GetTickCount"],
        )

        event_dict = event.to_dict()

        assert event_dict["timestamp"] == timestamp
        assert event_dict["source"] == "api"
        assert event_dict["event_type"] == "read"
        assert event_dict["severity"] == "warning"
        assert event_dict["details"]["api"] == "GetTickCount"
        assert event_dict["process_info"]["pid"] == 9999
        assert event_dict["process_info"]["name"] == "app.exe"
        assert event_dict["call_stack"][0] == "kernel32.dll!GetTickCount"

    def test_monitor_event_handles_missing_process_info(self) -> None:
        """MonitorEvent correctly handles None process_info."""
        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.MEMORY,
            event_type=EventType.SCAN,
            severity=EventSeverity.INFO,
            details={"pattern": "license_key"},
            process_info=None,
        )

        event_dict = event.to_dict()

        assert event_dict["process_info"] is None


class TestEventEnums:
    """Test event enumeration types."""

    def test_event_source_enum_values(self) -> None:
        """EventSource enum contains all expected monitoring sources."""
        assert EventSource.API.value == "api"
        assert EventSource.REGISTRY.value == "registry"
        assert EventSource.FILE.value == "file"
        assert EventSource.NETWORK.value == "network"
        assert EventSource.MEMORY.value == "memory"

    def test_event_type_enum_values(self) -> None:
        """EventType enum contains all expected operation types."""
        assert EventType.READ.value == "read"
        assert EventType.WRITE.value == "write"
        assert EventType.DELETE.value == "delete"
        assert EventType.CONNECT.value == "connect"
        assert EventType.SEND.value == "send"
        assert EventType.RECEIVE.value == "receive"
        assert EventType.SCAN.value == "scan"
        assert EventType.CREATE.value == "create"
        assert EventType.MODIFY.value == "modify"
        assert EventType.ACCESS.value == "access"

    def test_event_severity_enum_values(self) -> None:
        """EventSeverity enum contains severity levels."""
        assert EventSeverity.INFO.value == "info"
        assert EventSeverity.WARNING.value == "warning"
        assert EventSeverity.CRITICAL.value == "critical"


class TestMonitorStats:
    """Test monitoring statistics tracking."""

    def test_monitor_stats_initializes_with_zero_counts(self) -> None:
        """MonitorStats initializes with zero event counts."""
        stats = MonitorStats()

        assert stats.total_events == 0
        assert len(stats.events_by_type) == 0
        assert stats.events_per_second == 0.0
        assert stats.last_event_time == 0.0

    def test_monitor_stats_records_events_accurately(self) -> None:
        """MonitorStats counts events correctly."""
        stats = MonitorStats()

        event1 = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.API,
            event_type=EventType.READ,
            severity=EventSeverity.INFO,
            details={},
        )

        event2 = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.REGISTRY,
            event_type=EventType.WRITE,
            severity=EventSeverity.CRITICAL,
            details={},
        )

        event3 = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.API,
            event_type=EventType.READ,
            severity=EventSeverity.WARNING,
            details={},
        )

        stats.record_event(event1)
        stats.record_event(event2)
        stats.record_event(event3)

        assert stats.total_events == 3
        assert stats.events_by_type["read"] == 2
        assert stats.events_by_type["write"] == 1

    def test_monitor_stats_calculates_events_per_second(self) -> None:
        """MonitorStats calculates accurate event rate."""
        stats = MonitorStats()

        start_time = time.time()
        for _ in range(5):
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.MEMORY,
                event_type=EventType.SCAN,
                severity=EventSeverity.INFO,
                details={},
            )
            stats.record_event(event)

        time.sleep(0.1)

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.MEMORY,
            event_type=EventType.SCAN,
            severity=EventSeverity.INFO,
            details={},
        )
        stats.record_event(event)

        assert stats.total_events == 6
        assert stats.events_per_second > 0

    def test_monitor_stats_thread_safe_recording(self) -> None:
        """MonitorStats handles concurrent event recording safely."""
        stats = MonitorStats()
        events_to_record = 100

        def record_events() -> None:
            for _ in range(events_to_record // 10):
                event = MonitorEvent(
                    timestamp=time.time(),
                    source=EventSource.API,
                    event_type=EventType.READ,
                    severity=EventSeverity.INFO,
                    details={},
                )
                stats.record_event(event)

        threads = [threading.Thread(target=record_events) for _ in range(10)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert stats.total_events == events_to_record

    def test_monitor_stats_get_stats_returns_complete_data(self) -> None:
        """MonitorStats returns comprehensive statistics dictionary."""
        stats = MonitorStats()

        for i in range(5):
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.NETWORK,
                event_type=EventType.SEND if i % 2 == 0 else EventType.RECEIVE,
                severity=EventSeverity.INFO,
                details={},
            )
            stats.record_event(event)

        stats_dict = stats.get_stats()

        assert "total_events" in stats_dict
        assert "events_by_type" in stats_dict
        assert "events_per_second" in stats_dict
        assert "uptime" in stats_dict
        assert "last_event" in stats_dict

        assert stats_dict["total_events"] == 5
        assert stats_dict["events_by_type"]["send"] == 3
        assert stats_dict["events_by_type"]["receive"] == 2

    def test_monitor_stats_resets_correctly(self) -> None:
        """MonitorStats resets all counters to initial state."""
        stats = MonitorStats()

        for _ in range(10):
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.FILE,
                event_type=EventType.WRITE,
                severity=EventSeverity.WARNING,
                details={},
            )
            stats.record_event(event)

        assert stats.total_events == 10

        stats.reset()

        assert stats.total_events == 0
        assert len(stats.events_by_type) == 0
        assert stats.events_per_second == 0.0
        assert stats.last_event_time == 0.0


class TestBaseMonitorInitialization:
    """Test BaseMonitor initialization."""

    def test_base_monitor_initializes_with_name(self) -> None:
        """BaseMonitor initializes with monitor name."""
        monitor = ConcreteMonitor(name="TestAPIMonitor")

        assert monitor.name == "TestAPIMonitor"
        assert not monitor.is_running()
        assert monitor._error_count == 0

    def test_base_monitor_initializes_with_process_info(self) -> None:
        """BaseMonitor stores process information."""
        process_info = ProcessInfo(pid=1234, name="target.exe", path="C:\\target.exe")
        monitor = ConcreteMonitor(name="Monitor", process_info=process_info)

        assert monitor.process_info == process_info
        assert monitor.process_info.pid == 1234

    def test_base_monitor_creates_statistics_tracker(self) -> None:
        """BaseMonitor initializes statistics tracking."""
        monitor = ConcreteMonitor()

        stats = monitor.get_stats()

        assert "monitor_name" in stats
        assert "total_events" in stats
        assert "error_count" in stats
        assert "running" in stats

        assert stats["monitor_name"] == "TestMonitor"
        assert stats["total_events"] == 0
        assert stats["error_count"] == 0
        assert stats["running"] is False


class TestBaseMonitorLifecycle:
    """Test BaseMonitor lifecycle management."""

    def test_base_monitor_starts_successfully(self) -> None:
        """BaseMonitor starts monitoring and updates state."""
        monitor = ConcreteMonitor()

        result = monitor.start()

        assert result is True
        assert monitor.is_running()
        assert monitor.start_called is True

        monitor.stop()

    def test_base_monitor_stops_successfully(self) -> None:
        """BaseMonitor stops monitoring and updates state."""
        monitor = ConcreteMonitor()

        monitor.start()
        assert monitor.is_running()

        monitor.stop()

        assert not monitor.is_running()
        assert monitor.stop_called is True

    def test_base_monitor_handles_start_failure(self) -> None:
        """BaseMonitor handles start failure gracefully."""
        monitor = ConcreteMonitor()
        monitor.should_fail_start = True

        result = monitor.start()

        assert result is False
        assert not monitor.is_running()

    def test_base_monitor_prevents_double_start(self) -> None:
        """BaseMonitor prevents starting already running monitor."""
        monitor = ConcreteMonitor()

        monitor.start()
        assert monitor.start_called is True

        monitor.start_called = False
        result = monitor.start()

        assert result is True
        assert monitor.start_called is False

        monitor.stop()

    def test_base_monitor_handles_double_stop_safely(self) -> None:
        """BaseMonitor handles multiple stop calls safely."""
        monitor = ConcreteMonitor()

        monitor.start()
        monitor.stop()

        assert monitor.stop_called is True

        monitor.stop_called = False
        monitor.stop()

        assert monitor.stop_called is False

    def test_base_monitor_resets_stats_on_start(self) -> None:
        """BaseMonitor resets statistics when starting."""
        monitor = ConcreteMonitor()

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.API,
            event_type=EventType.READ,
            severity=EventSeverity.INFO,
            details={},
        )

        monitor.start()
        monitor.emit_test_event(event)

        assert monitor.get_stats()["total_events"] == 1

        monitor.stop()
        monitor.start()

        assert monitor.get_stats()["total_events"] == 0

        monitor.stop()


class TestEventCallbacks:
    """Test event callback registration and execution."""

    def test_base_monitor_registers_event_callbacks(self) -> None:
        """BaseMonitor registers event callbacks successfully."""
        monitor = ConcreteMonitor()
        callback = MagicMock()

        monitor.on_event(callback)

        assert callback in monitor._callbacks

    def test_base_monitor_executes_callbacks_on_event(self) -> None:
        """BaseMonitor executes all registered callbacks on event emission."""
        monitor = ConcreteMonitor()
        callback1 = MagicMock()
        callback2 = MagicMock()

        monitor.on_event(callback1)
        monitor.on_event(callback2)

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.REGISTRY,
            event_type=EventType.WRITE,
            severity=EventSeverity.CRITICAL,
            details={"key": "HKLM\\Software\\License"},
        )

        monitor.emit_test_event(event)

        callback1.assert_called_once_with(event)
        callback2.assert_called_once_with(event)

    def test_base_monitor_handles_callback_exceptions(self) -> None:
        """BaseMonitor continues operation when callback raises exception."""
        monitor = ConcreteMonitor()
        failing_callback = MagicMock(side_effect=RuntimeError("Callback error"))
        working_callback = MagicMock()

        monitor.on_event(failing_callback)
        monitor.on_event(working_callback)

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.MEMORY,
            event_type=EventType.SCAN,
            severity=EventSeverity.WARNING,
            details={},
        )

        monitor.emit_test_event(event)

        failing_callback.assert_called_once()
        working_callback.assert_called_once()

    def test_base_monitor_updates_stats_on_event(self) -> None:
        """BaseMonitor updates statistics when emitting events."""
        monitor = ConcreteMonitor()

        event1 = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.API,
            event_type=EventType.READ,
            severity=EventSeverity.INFO,
            details={},
        )

        event2 = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.REGISTRY,
            event_type=EventType.WRITE,
            severity=EventSeverity.CRITICAL,
            details={},
        )

        monitor.emit_test_event(event1)
        monitor.emit_test_event(event2)

        stats = monitor.get_stats()

        assert stats["total_events"] == 2


class TestErrorHandling:
    """Test error handling and recovery."""

    def test_base_monitor_increments_error_count(self) -> None:
        """BaseMonitor tracks error count accurately."""
        monitor = ConcreteMonitor()

        assert monitor._error_count == 0

        monitor.trigger_error(RuntimeError("Test error 1"))

        assert monitor._error_count == 1

        monitor.trigger_error(ValueError("Test error 2"))

        assert monitor._error_count == 2

    def test_base_monitor_continues_after_error(self) -> None:
        """BaseMonitor continues operation after non-fatal errors."""
        monitor = ConcreteMonitor()

        result = monitor.trigger_error(RuntimeError("Non-fatal error"))

        assert result is True
        assert monitor._error_count == 1

    def test_base_monitor_stops_at_max_errors(self) -> None:
        """BaseMonitor stops after reaching maximum error threshold."""
        monitor = ConcreteMonitor()
        monitor.start()

        assert monitor.is_running()

        for _ in range(monitor._max_errors):
            monitor.trigger_error(RuntimeError("Repeated error"))

        assert not monitor.is_running()
        assert monitor._error_count == monitor._max_errors

    def test_base_monitor_resets_error_count(self) -> None:
        """BaseMonitor resets error counter."""
        monitor = ConcreteMonitor()

        for _ in range(5):
            monitor.trigger_error(RuntimeError("Error"))

        assert monitor._error_count == 5

        monitor.reset_errors()

        assert monitor._error_count == 0

    def test_base_monitor_includes_error_count_in_stats(self) -> None:
        """BaseMonitor includes error count in statistics."""
        monitor = ConcreteMonitor()

        monitor.trigger_error(RuntimeError("Test error"))
        monitor.trigger_error(ValueError("Another error"))

        stats = monitor.get_stats()

        assert stats["error_count"] == 2


class TestThreadSafety:
    """Test thread-safe operations."""

    def test_base_monitor_handles_concurrent_starts(self) -> None:
        """BaseMonitor handles concurrent start requests safely."""
        monitor = ConcreteMonitor()

        def start_monitor() -> None:
            monitor.start()

        threads = [threading.Thread(target=start_monitor) for _ in range(5)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert monitor.is_running()

        monitor.stop()

    def test_base_monitor_handles_concurrent_event_emission(self) -> None:
        """BaseMonitor handles concurrent event emission safely."""
        monitor = ConcreteMonitor()
        events_per_thread = 20

        def emit_events() -> None:
            for _ in range(events_per_thread):
                event = MonitorEvent(
                    timestamp=time.time(),
                    source=EventSource.API,
                    event_type=EventType.READ,
                    severity=EventSeverity.INFO,
                    details={},
                )
                monitor.emit_test_event(event)

        threads = [threading.Thread(target=emit_events) for _ in range(5)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        stats = monitor.get_stats()

        assert stats["total_events"] == events_per_thread * 5

    def test_base_monitor_thread_safe_stop_during_events(self) -> None:
        """BaseMonitor safely stops during concurrent event processing."""
        monitor = ConcreteMonitor()
        monitor.start()

        stop_executed = threading.Event()

        def emit_events() -> None:
            for _ in range(100):
                event = MonitorEvent(
                    timestamp=time.time(),
                    source=EventSource.MEMORY,
                    event_type=EventType.SCAN,
                    severity=EventSeverity.INFO,
                    details={},
                )
                monitor.emit_test_event(event)
                time.sleep(0.001)

        def stop_monitor() -> None:
            time.sleep(0.05)
            monitor.stop()
            stop_executed.set()

        event_thread = threading.Thread(target=emit_events)
        stop_thread = threading.Thread(target=stop_monitor)

        event_thread.start()
        stop_thread.start()

        stop_thread.join()
        event_thread.join()

        assert stop_executed.is_set()
        assert not monitor.is_running()


class TestMonitorIntegration:
    """Test complete monitoring workflow integration."""

    def test_complete_monitoring_lifecycle_with_events(self) -> None:
        """Complete monitor lifecycle with event processing."""
        process_info = ProcessInfo(pid=1234, name="test.exe", path="C:\\test.exe")
        monitor = ConcreteMonitor(name="IntegrationTest", process_info=process_info)

        callback = MagicMock()
        monitor.on_event(callback)

        assert monitor.start() is True
        assert monitor.is_running()

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
                details={"key": "HKLM\\Software\\License", "value": "ABC-123"},
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
            monitor.emit_test_event(event)

        stats = monitor.get_stats()

        assert stats["total_events"] == 3
        assert stats["events_by_type"]["read"] == 1
        assert stats["events_by_type"]["write"] == 1
        assert stats["events_by_type"]["scan"] == 1
        assert stats["monitor_name"] == "IntegrationTest"

        assert callback.call_count == 3

        monitor.stop()

        assert not monitor.is_running()
        assert monitor.stop_called is True
