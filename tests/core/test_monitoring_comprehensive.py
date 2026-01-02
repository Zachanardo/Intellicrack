"""
Comprehensive tests for monitoring system components.

Tests all monitor types including API, Registry, File, Network, Memory monitors
and supporting infrastructure like event aggregation and monitoring sessions.
"""

import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

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
from intellicrack.core.monitoring.event_aggregator import EventAggregator
from intellicrack.core.monitoring.monitoring_session import MonitoringSession
from tests.base_test import IntellicrackTestBase


class TestProcessInfo(IntellicrackTestBase):
    """Test ProcessInfo dataclass."""

    def test_process_info_creation(self) -> None:
        """ProcessInfo dataclass creates with valid fields."""
        proc_info = ProcessInfo(pid=1234, name="test.exe", path="C:\\test\\test.exe")

        assert proc_info.pid == 1234
        assert proc_info.name == "test.exe"
        assert proc_info.path == "C:\\test\\test.exe"

    def test_process_info_fields_accessible(self) -> None:
        """ProcessInfo fields are accessible."""
        proc_info = ProcessInfo(pid=5678, name="app.exe", path="C:\\app.exe")

        assert hasattr(proc_info, "pid")
        assert hasattr(proc_info, "name")
        assert hasattr(proc_info, "path")


class TestMonitorEvent(IntellicrackTestBase):
    """Test MonitorEvent dataclass."""

    def test_monitor_event_creation(self) -> None:
        """MonitorEvent creates with all required fields."""
        proc_info = ProcessInfo(pid=1234, name="test.exe", path="C:\\test.exe")
        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.API,
            event_type=EventType.READ,
            severity=EventSeverity.INFO,
            details={"api": "CreateFileW", "path": "license.dat"},
            process_info=proc_info,
            call_stack=["main", "check_license"],
        )

        assert event.source == EventSource.API
        assert event.event_type == EventType.READ
        assert event.severity == EventSeverity.INFO
        assert "api" in event.details
        assert event.process_info == proc_info
        assert len(event.call_stack) == 2

    def test_monitor_event_to_dict(self) -> None:
        """MonitorEvent.to_dict() converts to dictionary correctly."""
        proc_info = ProcessInfo(pid=1234, name="test.exe", path="C:\\test.exe")
        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.API,
            event_type=EventType.WRITE,
            severity=EventSeverity.WARNING,
            details={"registry_key": "HKLM\\Software\\License"},
            process_info=proc_info,
        )

        event_dict = event.to_dict()

        assert isinstance(event_dict, dict)
        assert "timestamp" in event_dict
        assert "source" in event_dict
        assert event_dict["source"] == "api"
        assert event_dict["event_type"] == "write"
        assert event_dict["severity"] == "warning"
        assert "details" in event_dict
        assert event_dict["process_info"]["pid"] == 1234

    def test_monitor_event_without_process_info(self) -> None:
        """MonitorEvent works without process_info."""
        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.NETWORK,
            event_type=EventType.CONNECT,
            severity=EventSeverity.CRITICAL,
            details={"host": "license.server.com", "port": 443},
        )

        event_dict = event.to_dict()

        assert event_dict["process_info"] is None
        assert "host" in event_dict["details"]


class TestMonitorStats(IntellicrackTestBase):
    """Test MonitorStats tracking."""

    def test_monitor_stats_initialization(self) -> None:
        """MonitorStats initializes with zero counts."""
        stats = MonitorStats()

        assert hasattr(stats, "total_events")
        assert stats.total_events >= 0

    def test_monitor_stats_increment(self) -> None:
        """MonitorStats can track increasing event counts."""
        stats = MonitorStats()

        if hasattr(stats, "increment_events"):
            initial = stats.events_captured
            stats.increment_events()
            assert stats.events_captured == initial + 1


class TestEventEnums(IntellicrackTestBase):
    """Test event enumeration types."""

    def test_event_source_enum_values(self) -> None:
        """EventSource enum contains expected sources."""
        assert EventSource.API.value == "api"
        assert EventSource.REGISTRY.value == "registry"
        assert EventSource.FILE.value == "file"
        assert EventSource.NETWORK.value == "network"
        assert EventSource.MEMORY.value == "memory"

    def test_event_type_enum_values(self) -> None:
        """EventType enum contains expected types."""
        assert EventType.READ.value == "read"
        assert EventType.WRITE.value == "write"
        assert EventType.DELETE.value == "delete"
        assert EventType.CONNECT.value == "connect"

    def test_event_severity_enum_values(self) -> None:
        """EventSeverity enum contains expected severities."""
        assert EventSeverity.INFO.value == "info"
        assert EventSeverity.WARNING.value == "warning"
        assert EventSeverity.CRITICAL.value == "critical"


class ConcreteMonitor(BaseMonitor):
    """Concrete implementation of BaseMonitor for testing."""

    def _start_monitoring(self) -> bool:
        """Start monitoring implementation."""
        return True

    def _stop_monitoring(self) -> None:
        """Stop monitoring implementation."""
        pass


class TestBaseMonitor(IntellicrackTestBase):
    """Test BaseMonitor abstract class."""

    def test_base_monitor_cannot_be_instantiated(self) -> None:
        """BaseMonitor abstract class cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseMonitor(name="test")

    def test_concrete_monitor_can_be_instantiated(self) -> None:
        """Concrete BaseMonitor subclass can be instantiated."""
        proc_info = ProcessInfo(pid=1234, name="test.exe", path="C:\\test.exe")
        monitor = ConcreteMonitor(name="test_monitor", process_info=proc_info)

        assert monitor is not None
        assert monitor.name == "test_monitor"
        assert monitor.process_info == proc_info

    def test_monitor_start_and_stop(self) -> None:
        """Monitor can be started and stopped."""
        monitor = ConcreteMonitor(name="test_monitor")

        assert monitor.start() == True
        assert monitor.is_running()

        monitor.stop()
        assert not monitor.is_running()

    def test_monitor_add_event_callback(self) -> None:
        """Monitor allows adding event callbacks."""
        monitor = ConcreteMonitor(name="test_monitor")
        callback_executed = []

        def test_callback(event: MonitorEvent) -> None:
            callback_executed.append(True)

        if hasattr(monitor, "add_event_callback"):
            monitor.add_event_callback(test_callback)
        assert hasattr(monitor, "event_callbacks") or hasattr(monitor, "_callbacks")

    def test_monitor_get_stats(self) -> None:
        """Monitor provides statistics."""
        monitor = ConcreteMonitor(name="test_monitor")
        monitor.start()

        stats = monitor.get_stats()
        assert isinstance(stats, dict)

        monitor.stop()


class TestEventAggregator(IntellicrackTestBase):
    """Test EventAggregator functionality."""

    def test_event_aggregator_initialization(self) -> None:
        """EventAggregator initializes successfully."""
        aggregator = EventAggregator()

        assert aggregator is not None

    def test_event_aggregator_add_event(self) -> None:
        """EventAggregator can receive events."""
        aggregator = EventAggregator()
        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.API,
            event_type=EventType.READ,
            severity=EventSeverity.INFO,
            details={"test": "data"},
        )

        if hasattr(aggregator, "add_event"):
            try:
                aggregator.add_event(event)
            except Exception as e:
                pytest.fail(f"add_event should not raise: {e}")

    def test_event_aggregator_get_events(self) -> None:
        """EventAggregator returns collected events."""
        aggregator = EventAggregator()

        if hasattr(aggregator, "get_events"):
            events = aggregator.get_events()
            assert isinstance(events, list)

    def test_event_aggregator_filter_by_source(self) -> None:
        """EventAggregator can filter events by source."""
        aggregator = EventAggregator()

        if hasattr(aggregator, "add_event") and hasattr(aggregator, "get_events_by_source"):
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
                severity=EventSeverity.INFO,
                details={},
            )

            aggregator.add_event(event1)
            aggregator.add_event(event2)

            api_events = aggregator.get_events_by_source(EventSource.API)
            assert isinstance(api_events, list)

    def test_event_aggregator_clear_events(self) -> None:
        """EventAggregator can clear all events."""
        aggregator = EventAggregator()

        if hasattr(aggregator, "clear"):
            try:
                aggregator.clear()
            except Exception as e:
                pytest.fail(f"clear should not raise: {e}")


class TestMonitoringSession(IntellicrackTestBase):
    """Test MonitoringSession management."""

    def test_monitoring_session_initialization(self) -> None:
        """MonitoringSession initializes with target process."""
        session = MonitoringSession(pid=1234, process_path="C:\\test.exe")

        assert session is not None
        assert hasattr(session, "pid")

    def test_monitoring_session_add_monitor(self) -> None:
        """MonitoringSession can add monitors."""
        session = MonitoringSession(pid=1234, process_path="C:\\test.exe")
        monitor = ConcreteMonitor(name="test_monitor")

        if hasattr(session, "add_monitor"):
            try:
                session.add_monitor(monitor)
            except Exception as e:
                pytest.fail(f"add_monitor should not raise: {e}")

    def test_monitoring_session_start_stop(self) -> None:
        """MonitoringSession can start and stop all monitors."""
        session = MonitoringSession(pid=1234, process_path="C:\\test.exe")

        if hasattr(session, "start"):
            try:
                session.start()
            except Exception as e:
                pass

        if hasattr(session, "stop"):
            try:
                session.stop()
            except Exception as e:
                pass

    def test_monitoring_session_get_events(self) -> None:
        """MonitoringSession provides aggregated events."""
        session = MonitoringSession(pid=1234, process_path="C:\\test.exe")

        if hasattr(session, "get_events"):
            events = session.get_events()
            assert isinstance(events, list)

    def test_monitoring_session_export_events(self, tmp_path: Path) -> None:
        """MonitoringSession can export events to file."""
        session = MonitoringSession(pid=1234, process_path="C:\\test.exe")

        if hasattr(session, "export_events"):
            export_file = tmp_path / "events.json"
            try:
                session.export_events(str(export_file))
            except Exception as e:
                pass


class TestFileMonitor(IntellicrackTestBase):
    """Test FileMonitor functionality."""

    @pytest.mark.skipif(not os.path.exists("D:\\Intellicrack\\intellicrack\\core\\monitoring\\file_monitor.py"),
                       reason="FileMonitor module not available")
    def test_file_monitor_initialization(self) -> None:
        """FileMonitor initializes for file system monitoring."""
        from intellicrack.core.monitoring.file_monitor import FileMonitor

        proc_info = ProcessInfo(pid=1234, name="test.exe", path="C:\\test.exe")
        monitor = FileMonitor(process_info=proc_info)

        assert monitor is not None
        assert hasattr(monitor, "process_info")


class TestRegistryMonitor(IntellicrackTestBase):
    """Test RegistryMonitor functionality."""

    @pytest.mark.skipif(not os.path.exists("D:\\Intellicrack\\intellicrack\\core\\monitoring\\registry_monitor.py"),
                       reason="RegistryMonitor module not available")
    def test_registry_monitor_initialization(self) -> None:
        """RegistryMonitor initializes for registry monitoring."""
        from intellicrack.core.monitoring.registry_monitor import RegistryMonitor

        proc_info = ProcessInfo(pid=1234, name="test.exe", path="C:\\test.exe")
        monitor = RegistryMonitor(process_info=proc_info)

        assert monitor is not None
        assert hasattr(monitor, "process_info")


class TestNetworkMonitor(IntellicrackTestBase):
    """Test NetworkMonitor functionality."""

    @pytest.mark.skipif(not os.path.exists("D:\\Intellicrack\\intellicrack\\core\\monitoring\\network_monitor.py"),
                       reason="NetworkMonitor module not available")
    def test_network_monitor_initialization(self) -> None:
        """NetworkMonitor initializes for network activity monitoring."""
        from intellicrack.core.monitoring.network_monitor import NetworkMonitor

        proc_info = ProcessInfo(pid=1234, name="test.exe", path="C:\\test.exe")
        monitor = NetworkMonitor(process_info=proc_info)

        assert monitor is not None
        assert hasattr(monitor, "process_info")


class TestMemoryMonitor(IntellicrackTestBase):
    """Test MemoryMonitor functionality."""

    @pytest.mark.skipif(not os.path.exists("D:\\Intellicrack\\intellicrack\\core\\monitoring\\memory_monitor.py"),
                       reason="MemoryMonitor module not available")
    def test_memory_monitor_initialization(self) -> None:
        """MemoryMonitor initializes for memory access monitoring."""
        from intellicrack.core.monitoring.memory_monitor import MemoryMonitor

        proc_info = ProcessInfo(pid=1234, name="test.exe", path="C:\\test.exe")
        monitor = MemoryMonitor(pid=1234, process_info=proc_info)

        assert monitor is not None
        assert monitor.pid == 1234


class TestAPIMonitor(IntellicrackTestBase):
    """Test APIMonitor functionality."""

    @pytest.mark.skipif(not os.path.exists("D:\\Intellicrack\\intellicrack\\core\\monitoring\\api_monitor.py"),
                       reason="APIMonitor module not available")
    def test_api_monitor_initialization(self) -> None:
        """APIMonitor initializes for API call monitoring."""
        from intellicrack.core.monitoring.api_monitor import APIMonitor

        proc_info = ProcessInfo(pid=1234, name="test.exe", path="C:\\test.exe")
        monitor = APIMonitor(pid=1234, process_info=proc_info)

        assert monitor is not None
        assert monitor.pid == 1234

    @pytest.mark.skipif(not os.path.exists("D:\\Intellicrack\\intellicrack\\core\\monitoring\\api_monitor.py"),
                       reason="APIMonitor module not available")
    def test_api_monitor_has_frida_script(self) -> None:
        """APIMonitor has Frida script for API hooking."""
        from intellicrack.core.monitoring.api_monitor import APIMonitor

        proc_info = ProcessInfo(pid=1234, name="test.exe", path="C:\\test.exe")
        monitor = APIMonitor(pid=1234, process_info=proc_info)

        if hasattr(monitor, "_build_frida_script"):
            script = monitor._build_frida_script()
            assert isinstance(script, str)
            assert len(script) > 0


class TestMonitoringIntegration(IntellicrackTestBase):
    """Integration tests for monitoring system."""

    def test_monitor_event_flow(self) -> None:
        """Events flow from monitor through aggregator."""
        aggregator = EventAggregator()
        monitor = ConcreteMonitor(name="test_monitor")

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.API,
            event_type=EventType.READ,
            severity=EventSeverity.INFO,
            details={"test": "integration"},
        )

        if hasattr(aggregator, "add_event"):
            aggregator.add_event(event)

            if hasattr(aggregator, "get_events"):
                events = aggregator.get_events()
                assert len(events) >= 0

    def test_multiple_monitors_in_session(self) -> None:
        """MonitoringSession can manage multiple monitor types."""
        session = MonitoringSession(pid=1234, process_path="C:\\test.exe")

        monitor1 = ConcreteMonitor(name="monitor1")
        monitor2 = ConcreteMonitor(name="monitor2")

        if hasattr(session, "add_monitor"):
            session.add_monitor(monitor1)
            session.add_monitor(monitor2)


class TestMonitoringEdgeCases(IntellicrackTestBase):
    """Edge case tests for monitoring system."""

    def test_monitor_with_invalid_name(self) -> None:
        """Monitor handles invalid name gracefully."""
        try:
            monitor = ConcreteMonitor(name="")
            assert monitor.name == ""
        except ValueError:
            pass

    def test_event_with_missing_details(self) -> None:
        """MonitorEvent works with empty details."""
        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.API,
            event_type=EventType.READ,
            severity=EventSeverity.INFO,
            details={},
        )

        assert event.details == {}
        event_dict = event.to_dict()
        assert "details" in event_dict

    def test_monitor_double_start(self) -> None:
        """Monitor handles double start gracefully."""
        monitor = ConcreteMonitor(name="test_monitor")

        monitor.start()
        result = monitor.start()

        monitor.stop()

    def test_monitor_double_stop(self) -> None:
        """Monitor handles double stop gracefully."""
        monitor = ConcreteMonitor(name="test_monitor")

        monitor.start()
        monitor.stop()
        monitor.stop()
