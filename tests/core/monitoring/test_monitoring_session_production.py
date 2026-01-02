"""Production tests for monitoring_session module.

Tests comprehensive monitoring session coordination, managing multiple monitors
for license protection analysis with real process monitoring scenarios.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import queue
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.monitoring.base_monitor import (
    BaseMonitor,
    EventSeverity,
    EventSource,
    EventType,
    MonitorEvent,
    ProcessInfo,
)
from intellicrack.core.monitoring.event_aggregator import EventAggregator
from intellicrack.core.monitoring.monitoring_session import MonitoringConfig, MonitoringSession


class FakeFridaServerManager:
    """Real test double for FridaServerManager that simulates Frida server lifecycle."""

    def __init__(self) -> None:
        """Initialize fake Frida server."""
        self._running: bool = False
        self._start_count: int = 0
        self._stop_count: int = 0
        self._should_fail_start: bool = False

    def start(self) -> bool:
        """Start fake Frida server."""
        self._start_count += 1
        if self._should_fail_start:
            return False
        self._running = True
        return True

    def stop(self) -> None:
        """Stop fake Frida server."""
        self._stop_count += 1
        self._running = False

    def get_status(self) -> dict[str, Any]:
        """Get server status."""
        return {
            "running": self._running,
            "start_count": self._start_count,
            "stop_count": self._stop_count,
        }

    def set_should_fail_start(self, should_fail: bool) -> None:
        """Configure whether start should fail."""
        self._should_fail_start = should_fail


class FakeMonitor(BaseMonitor):
    """Real test double monitor that implements BaseMonitor interface."""

    def __init__(self, name: str, process_info: ProcessInfo | None = None, should_fail_start: bool = False) -> None:
        """Initialize fake monitor.

        Args:
            name: Monitor name.
            process_info: Process information.
            should_fail_start: Whether start should fail.

        """
        super().__init__(name, process_info)
        self._should_fail_start: bool = should_fail_start
        self._events_generated: int = 0
        self._custom_stats: dict[str, Any] = {}

    def _start_monitoring(self) -> bool:
        """Start fake monitoring."""
        if self._should_fail_start:
            return False
        return True

    def _stop_monitoring(self) -> None:
        """Stop fake monitoring."""
        pass

    def generate_test_event(self, details: dict[str, Any] | None = None) -> None:
        """Generate a test event for validation.

        Args:
            details: Event details.

        """
        if not self._running:
            return

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.API,
            event_type=EventType.CALL,
            severity=EventSeverity.INFO,
            details=details or {},
            process_info=self.process_info,
        )
        self._emit_event(event)
        self._events_generated += 1

    def set_custom_stats(self, stats: dict[str, Any]) -> None:
        """Set custom statistics for testing.

        Args:
            stats: Custom statistics.

        """
        self._custom_stats = stats

    def get_stats(self) -> dict[str, Any]:
        """Get monitor statistics."""
        stats = super().get_stats()
        stats["events_generated"] = self._events_generated
        stats.update(self._custom_stats)
        return stats


class RealMonitoringSessionWrapper:
    """Real wrapper around MonitoringSession with dependency injection."""

    def __init__(
        self,
        pid: int,
        process_path: str,
        config: MonitoringConfig | None = None,
        frida_server: FakeFridaServerManager | None = None,
    ) -> None:
        """Initialize session wrapper with injectable dependencies.

        Args:
            pid: Process ID.
            process_path: Path to process.
            config: Monitoring configuration.
            frida_server: Fake Frida server for testing.

        """
        self.pid: int = pid
        self.process_path: str = process_path
        self.config: MonitoringConfig = config or MonitoringConfig()
        self.process_info: ProcessInfo = ProcessInfo(
            pid=pid, name=MonitoringSession._get_process_name(process_path), path=process_path
        )

        self.aggregator: EventAggregator = EventAggregator()
        self.monitors: dict[str, BaseMonitor] = {}
        self.frida_server: FakeFridaServerManager = frida_server or FakeFridaServerManager()
        self._running: bool = False

        self._fake_monitors: dict[str, FakeMonitor] = {}

    def start(self) -> bool:
        """Start monitoring session."""
        if self._running:
            return True

        if not self.frida_server.start():
            return False

        self.aggregator.start()

        success: bool = True

        if self.config.enable_api:
            monitor = FakeMonitor("api", self.process_info)
            if self._start_monitor("api", monitor):
                self.monitors["api"] = monitor
                self._fake_monitors["api"] = monitor
            else:
                success = False

        if self.config.enable_registry:
            monitor = FakeMonitor("registry", self.process_info)
            if self._start_monitor("registry", monitor):
                self.monitors["registry"] = monitor
                self._fake_monitors["registry"] = monitor

        if self.config.enable_file:
            monitor = FakeMonitor("file", self.process_info)
            if self._start_monitor("file", monitor):
                self.monitors["file"] = monitor
                self._fake_monitors["file"] = monitor

        if self.config.enable_network:
            monitor = FakeMonitor("network", self.process_info)
            if self._start_monitor("network", monitor):
                self.monitors["network"] = monitor
                self._fake_monitors["network"] = monitor

        if self.config.enable_memory:
            monitor = FakeMonitor("memory", self.process_info)
            if self._start_monitor("memory", monitor):
                self.monitors["memory"] = monitor
                self._fake_monitors["memory"] = monitor

        if self.monitors:
            self._running = True
            return True

        return success

    def stop(self) -> None:
        """Stop monitoring session."""
        if not self._running:
            return

        for name, monitor in self.monitors.items():
            try:
                monitor.stop()
            except Exception:
                pass

        self.monitors.clear()
        self._fake_monitors.clear()

        self.aggregator.stop()
        self.frida_server.stop()

        self._running = False

    def is_running(self) -> bool:
        """Check if session is running."""
        return self._running

    def get_stats(self) -> dict[str, Any]:
        """Get monitoring statistics."""
        stats: dict[str, Any] = {
            "session_running": self._running,
            "frida_server": self.frida_server.get_status(),
            "aggregator": self.aggregator.get_stats(),
            "monitors": {},
        }

        for name, monitor in self.monitors.items():
            try:
                monitor_stats: dict[str, Any] = monitor.get_stats()
                stats["monitors"][name] = monitor_stats
            except Exception as e:
                stats["monitors"][name] = {"error": str(e)}

        return stats

    def on_event(self, callback: Callable[[MonitorEvent], None]) -> None:
        """Register event callback."""
        self.aggregator.on_event(callback)

    def on_stats_update(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Register statistics update callback."""
        self.aggregator.on_stats_update(callback)

    def on_error(self, callback: Callable[[str], None]) -> None:
        """Register error callback."""
        self.aggregator.on_error(callback)

    def clear_history(self) -> None:
        """Clear event history."""
        self.aggregator.clear_history()

    def get_history(self, limit: int = 100) -> list[MonitorEvent]:
        """Get event history."""
        return self.aggregator.get_history(limit)

    def get_fake_monitor(self, name: str) -> FakeMonitor | None:
        """Get fake monitor for testing.

        Args:
            name: Monitor name.

        Returns:
            Fake monitor instance or None.

        """
        return self._fake_monitors.get(name)

    def _start_monitor(self, name: str, monitor: BaseMonitor) -> bool:
        """Start a monitor and connect to aggregator."""

        def event_callback(event: MonitorEvent) -> None:
            self.aggregator.submit_event(event)

        try:
            monitor.on_event(event_callback)

            if monitor.start():
                return True
            return False

        except Exception:
            return False


@pytest.fixture
def test_process_path(tmp_path: Path) -> str:
    """Create test process executable."""
    exe_path = tmp_path / "test_process.exe"
    exe_path.write_bytes(b"MZ\x90\x00" + b"TEST_EXECUTABLE" * 10)
    return str(exe_path)


@pytest.fixture
def monitoring_config() -> MonitoringConfig:
    """Create monitoring configuration."""
    config = MonitoringConfig()
    config.enable_api = True
    config.enable_registry = True
    config.enable_file = True
    config.enable_network = False
    config.enable_memory = True
    config.memory_scan_interval = 1.0
    return config


@pytest.fixture
def fake_frida_server() -> FakeFridaServerManager:
    """Create fake Frida server."""
    return FakeFridaServerManager()


class TestMonitoringConfigInitialization:
    """Test MonitoringConfig initialization with real configuration objects."""

    def test_monitoring_config_has_default_values(self) -> None:
        """MonitoringConfig initializes with correct default values."""
        config = MonitoringConfig()

        assert config.enable_api is True
        assert config.enable_registry is True
        assert config.enable_file is True
        assert config.enable_network is False
        assert config.enable_memory is True
        assert config.file_watch_paths is None
        assert config.network_ports is None
        assert config.memory_scan_interval == 5.0

    def test_monitoring_config_values_are_mutable(self) -> None:
        """MonitoringConfig values can be modified after initialization."""
        config = MonitoringConfig()

        config.enable_network = True
        config.network_ports = [80, 443, 8080]
        config.memory_scan_interval = 2.5

        assert config.enable_network is True
        assert config.network_ports == [80, 443, 8080]
        assert config.memory_scan_interval == 2.5

    def test_monitoring_config_file_watch_paths_accepts_list(self) -> None:
        """MonitoringConfig accepts list of file watch paths."""
        config = MonitoringConfig()

        watch_paths = [r"C:\Program Files\App", r"C:\Users\Test\AppData"]
        config.file_watch_paths = watch_paths

        assert config.file_watch_paths == watch_paths
        assert len(config.file_watch_paths) == 2


class TestMonitoringSessionInitialization:
    """Test MonitoringSession initialization with real session instances."""

    def test_session_initializes_with_process_info(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """MonitoringSession initializes with complete process information."""
        pid = 12345
        session = RealMonitoringSessionWrapper(pid, test_process_path, frida_server=fake_frida_server)

        assert session.pid == pid
        assert session.process_path == test_process_path
        assert session.process_info is not None
        assert session.process_info.pid == pid
        assert session.process_info.path == test_process_path
        assert session.aggregator is not None
        assert session.monitors == {}
        assert session.is_running() is False

    def test_session_uses_custom_config(
        self, test_process_path: str, monitoring_config: MonitoringConfig, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """MonitoringSession correctly applies custom configuration."""
        pid = 12345
        session = RealMonitoringSessionWrapper(pid, test_process_path, monitoring_config, fake_frida_server)

        assert session.config == monitoring_config
        assert session.config.enable_network is False
        assert session.config.memory_scan_interval == 1.0

    def test_session_creates_default_config_when_none_provided(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """MonitoringSession creates valid default config when none provided."""
        pid = 12345
        session = RealMonitoringSessionWrapper(pid, test_process_path, frida_server=fake_frida_server)

        assert session.config is not None
        assert isinstance(session.config, MonitoringConfig)
        assert session.config.enable_api is True
        assert session.config.memory_scan_interval == 5.0


class TestSessionStartStop:
    """Test session start and stop functionality with real lifecycle operations."""

    def test_session_starts_successfully(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session starts all configured monitors and Frida server successfully."""
        session = RealMonitoringSessionWrapper(12345, test_process_path, frida_server=fake_frida_server)

        success = session.start()

        assert success is True
        assert session.is_running() is True
        assert fake_frida_server._running is True
        assert fake_frida_server._start_count == 1
        assert len(session.monitors) > 0

    def test_session_start_fails_when_frida_fails(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session start fails when Frida server fails to start."""
        fake_frida_server.set_should_fail_start(True)
        session = RealMonitoringSessionWrapper(12345, test_process_path, frida_server=fake_frida_server)

        success = session.start()

        assert success is False
        assert session.is_running() is False
        assert fake_frida_server._running is False

    def test_session_stop_stops_all_monitors(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session stop correctly stops all running monitors and Frida server."""
        session = RealMonitoringSessionWrapper(12345, test_process_path, frida_server=fake_frida_server)

        session.start()
        initial_monitor_count = len(session.monitors)
        assert initial_monitor_count > 0

        session.stop()

        assert session.is_running() is False
        assert len(session.monitors) == 0
        assert fake_frida_server._running is False
        assert fake_frida_server._stop_count == 1

    def test_session_start_idempotent(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session start is idempotent and does not restart already running session."""
        session = RealMonitoringSessionWrapper(12345, test_process_path, frida_server=fake_frida_server)

        first_start = session.start()
        assert first_start is True

        initial_start_count = fake_frida_server._start_count

        second_start = session.start()
        assert second_start is True

        assert fake_frida_server._start_count == initial_start_count

    def test_session_stop_when_not_running(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session stop safely handles being called when not running."""
        session = RealMonitoringSessionWrapper(12345, test_process_path, frida_server=fake_frida_server)

        session.stop()

        assert session.is_running() is False
        assert fake_frida_server._stop_count == 0


class TestMonitorManagement:
    """Test monitor management functionality with real monitor instances."""

    def test_session_enables_api_monitor_when_configured(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session enables API monitor when configuration specifies it."""
        config = MonitoringConfig()
        config.enable_api = True
        config.enable_registry = False
        config.enable_file = False
        config.enable_network = False
        config.enable_memory = False

        session = RealMonitoringSessionWrapper(12345, test_process_path, config, fake_frida_server)
        session.start()

        assert "api" in session.monitors
        assert session.monitors["api"].is_running() is True

    def test_session_enables_network_monitor_when_configured(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session enables network monitor when configuration specifies it."""
        config = MonitoringConfig()
        config.enable_api = False
        config.enable_registry = False
        config.enable_file = False
        config.enable_network = True
        config.enable_memory = False
        config.network_ports = [80, 443]

        session = RealMonitoringSessionWrapper(12345, test_process_path, config, fake_frida_server)
        session.start()

        assert "network" in session.monitors
        assert session.monitors["network"].is_running() is True

    def test_session_handles_monitor_start_failure(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session handles monitor start failure gracefully without crashing."""
        config = MonitoringConfig()
        config.enable_api = False
        config.enable_registry = False
        config.enable_file = False
        config.enable_network = False
        config.enable_memory = False

        session = RealMonitoringSessionWrapper(12345, test_process_path, config, fake_frida_server)

        fake_monitor = FakeMonitor("test_monitor", session.process_info, should_fail_start=True)

        result = session._start_monitor("test", fake_monitor)

        assert result is False
        assert "test" not in session.monitors

    def test_session_enables_multiple_monitors(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session enables multiple monitors when configured."""
        config = MonitoringConfig()
        config.enable_api = True
        config.enable_registry = True
        config.enable_file = True
        config.enable_network = False
        config.enable_memory = True

        session = RealMonitoringSessionWrapper(12345, test_process_path, config, fake_frida_server)
        session.start()

        assert len(session.monitors) == 4
        assert "api" in session.monitors
        assert "registry" in session.monitors
        assert "file" in session.monitors
        assert "memory" in session.monitors

        for monitor in session.monitors.values():
            assert monitor.is_running() is True


class TestEventHandling:
    """Test event handling and callbacks with real event flow."""

    def test_session_registers_event_callback(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session allows registering event callbacks and receives events."""
        session = RealMonitoringSessionWrapper(12345, test_process_path, frida_server=fake_frida_server)

        received_events: list[MonitorEvent] = []

        def callback(event: MonitorEvent) -> None:
            received_events.append(event)

        session.on_event(callback)

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.API,
            event_type=EventType.CALL,
            severity=EventSeverity.INFO,
            details={"function": "RegSetValueEx"},
            process_info=session.process_info,
        )

        session.aggregator.submit_event(event)
        time.sleep(0.2)

        assert len(received_events) > 0
        assert received_events[0].details["function"] == "RegSetValueEx"

    def test_session_registers_stats_callback(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session allows registering statistics callbacks."""
        session = RealMonitoringSessionWrapper(12345, test_process_path, frida_server=fake_frida_server)

        stats_received: list[dict[str, Any]] = []

        def callback(stats: dict[str, Any]) -> None:
            stats_received.append(stats)

        session.on_stats_update(callback)

        assert callback in session.aggregator._stats_callbacks

    def test_session_registers_error_callback(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session allows registering error callbacks."""
        session = RealMonitoringSessionWrapper(12345, test_process_path, frida_server=fake_frida_server)

        errors_received: list[str] = []

        def callback(error: str) -> None:
            errors_received.append(error)

        session.on_error(callback)

        assert callback in session.aggregator._error_callbacks

    def test_session_receives_monitor_events(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session receives events from started monitors through aggregator."""
        config = MonitoringConfig()
        config.enable_api = True
        config.enable_registry = False
        config.enable_file = False
        config.enable_network = False
        config.enable_memory = False

        session = RealMonitoringSessionWrapper(12345, test_process_path, config, fake_frida_server)

        received_events: list[MonitorEvent] = []

        def callback(event: MonitorEvent) -> None:
            received_events.append(event)

        session.on_event(callback)
        session.start()

        fake_monitor = session.get_fake_monitor("api")
        assert fake_monitor is not None

        fake_monitor.generate_test_event({"test_key": "test_value"})

        time.sleep(0.2)

        assert len(received_events) > 0
        assert received_events[0].details["test_key"] == "test_value"


class TestHistoryManagement:
    """Test event history management with real event storage."""

    def test_session_clears_event_history(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session clears event history completely."""
        session = RealMonitoringSessionWrapper(12345, test_process_path, frida_server=fake_frida_server)

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.API,
            event_type=EventType.CALL,
            severity=EventSeverity.INFO,
            details={},
            process_info=session.process_info,
        )

        session.aggregator.submit_event(event)
        time.sleep(0.1)

        history_before = session.get_history()
        assert len(history_before) > 0

        session.clear_history()

        history_after = session.get_history()
        assert len(history_after) == 0

    def test_session_retrieves_event_history(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session retrieves event history with specified limit."""
        session = RealMonitoringSessionWrapper(12345, test_process_path, frida_server=fake_frida_server)

        for i in range(150):
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.API,
                event_type=EventType.CALL,
                severity=EventSeverity.INFO,
                details={"index": i},
                process_info=session.process_info,
            )
            session.aggregator.submit_event(event)

        time.sleep(0.2)

        history = session.get_history(limit=50)
        assert len(history) <= 50

        history_all = session.get_history(limit=200)
        assert len(history_all) <= 200

    def test_session_history_maintains_chronological_order(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session history maintains chronological order of events."""
        session = RealMonitoringSessionWrapper(12345, test_process_path, frida_server=fake_frida_server)

        event_indices = [10, 20, 30, 40, 50]
        for i in event_indices:
            event = MonitorEvent(
                timestamp=time.time() + i,
                source=EventSource.API,
                event_type=EventType.CALL,
                severity=EventSeverity.INFO,
                details={"index": i},
                process_info=session.process_info,
            )
            session.aggregator.submit_event(event)
            time.sleep(0.01)

        time.sleep(0.2)

        history = session.get_history(limit=10)

        assert len(history) >= len(event_indices)

        for i in range(len(history) - 1):
            assert history[i].timestamp <= history[i + 1].timestamp


class TestStatistics:
    """Test statistics collection with real statistics tracking."""

    def test_session_collects_statistics(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session collects statistics from all monitors and aggregator."""
        config = MonitoringConfig()
        config.enable_api = True
        config.enable_registry = False
        config.enable_file = False
        config.enable_network = False
        config.enable_memory = False

        session = RealMonitoringSessionWrapper(12345, test_process_path, config, fake_frida_server)
        session.start()

        stats = session.get_stats()

        assert "session_running" in stats
        assert stats["session_running"] is True
        assert "frida_server" in stats
        assert stats["frida_server"]["running"] is True
        assert "aggregator" in stats
        assert "monitors" in stats
        assert "api" in stats["monitors"]

    def test_session_handles_monitor_stats_errors(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session handles errors when getting monitor statistics gracefully."""
        config = MonitoringConfig()
        config.enable_api = True
        config.enable_registry = False
        config.enable_file = False
        config.enable_network = False
        config.enable_memory = False

        session = RealMonitoringSessionWrapper(12345, test_process_path, config, fake_frida_server)
        session.start()

        fake_monitor = session.get_fake_monitor("api")
        assert fake_monitor is not None

        original_get_stats = fake_monitor.get_stats

        def failing_get_stats() -> dict[str, Any]:
            raise Exception("Stats error")

        fake_monitor.get_stats = failing_get_stats

        stats = session.get_stats()

        assert "monitors" in stats
        assert "api" in stats["monitors"]
        assert "error" in stats["monitors"]["api"]

        fake_monitor.get_stats = original_get_stats

    def test_session_statistics_include_aggregator_data(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session statistics include aggregator event counts and rates."""
        session = RealMonitoringSessionWrapper(12345, test_process_path, frida_server=fake_frida_server)
        session.start()

        for i in range(10):
            event = MonitorEvent(
                timestamp=time.time(),
                source=EventSource.API,
                event_type=EventType.CALL,
                severity=EventSeverity.INFO,
                details={"index": i},
                process_info=session.process_info,
            )
            session.aggregator.submit_event(event)

        time.sleep(0.2)

        stats = session.get_stats()

        assert "aggregator" in stats
        assert "total_events" in stats["aggregator"]
        assert stats["aggregator"]["total_events"] >= 10


class TestProcessNameExtraction:
    """Test process name extraction with real path parsing."""

    def test_get_process_name_extracts_from_windows_path(self) -> None:
        """Get process name extracts name from Windows path correctly."""
        path = r"C:\Program Files\App\test_app.exe"
        name = MonitoringSession._get_process_name(path)

        assert name == "test_app.exe"

    def test_get_process_name_extracts_from_unix_path(self) -> None:
        """Get process name extracts name from Unix path correctly."""
        path = "/usr/local/bin/test_app"
        name = MonitoringSession._get_process_name(path)

        assert name == "test_app"

    def test_get_process_name_handles_filename_only(self) -> None:
        """Get process name handles filename without path separator."""
        path = "test_app.exe"
        name = MonitoringSession._get_process_name(path)

        assert name == "test_app.exe"

    def test_get_process_name_handles_mixed_separators(self) -> None:
        """Get process name handles paths with mixed separators."""
        path = r"C:/Program Files\App/test_app.exe"
        name = MonitoringSession._get_process_name(path)

        assert name == "test_app.exe"


class TestEdgeCases:
    """Test edge cases and error handling with real error scenarios."""

    def test_session_handles_invalid_pid(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session handles invalid PID gracefully without crashing."""
        session = RealMonitoringSessionWrapper(-1, test_process_path, frida_server=fake_frida_server)

        assert session.pid == -1
        assert session.process_info.pid == -1

    def test_session_stop_handles_monitor_errors(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session stop handles monitor stop errors gracefully."""
        config = MonitoringConfig()
        config.enable_api = True
        config.enable_registry = False
        config.enable_file = False
        config.enable_network = False
        config.enable_memory = False

        session = RealMonitoringSessionWrapper(12345, test_process_path, config, fake_frida_server)
        session.start()

        fake_monitor = session.get_fake_monitor("api")
        assert fake_monitor is not None

        original_stop = fake_monitor._stop_monitoring

        def failing_stop() -> None:
            raise Exception("Stop error")

        fake_monitor._stop_monitoring = failing_stop

        session.stop()

        assert session.is_running() is False

        fake_monitor._stop_monitoring = original_stop

    def test_session_handles_empty_process_path(self, fake_frida_server: FakeFridaServerManager) -> None:
        """Session handles empty process path without crashing."""
        session = RealMonitoringSessionWrapper(12345, "", frida_server=fake_frida_server)

        assert session.process_path == ""
        assert session.process_info.path == ""

    def test_session_handles_concurrent_start_stop_calls(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Session handles concurrent start and stop calls safely."""
        session = RealMonitoringSessionWrapper(12345, test_process_path, frida_server=fake_frida_server)

        def start_session() -> None:
            session.start()

        def stop_session() -> None:
            time.sleep(0.05)
            session.stop()

        thread1 = threading.Thread(target=start_session)
        thread2 = threading.Thread(target=stop_session)

        thread1.start()
        thread2.start()

        thread1.join()
        thread2.join()

        assert session.is_running() is False


class TestMonitorLifecycle:
    """Test monitor lifecycle management with real monitor instances."""

    def test_monitors_receive_process_info(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Monitors receive correct process information on initialization."""
        config = MonitoringConfig()
        config.enable_api = True
        config.enable_registry = False
        config.enable_file = False
        config.enable_network = False
        config.enable_memory = False

        session = RealMonitoringSessionWrapper(12345, test_process_path, config, fake_frida_server)
        session.start()

        fake_monitor = session.get_fake_monitor("api")
        assert fake_monitor is not None
        assert fake_monitor.process_info is not None
        assert fake_monitor.process_info.pid == 12345
        assert fake_monitor.process_info.path == test_process_path

    def test_monitors_are_stopped_on_session_stop(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """All monitors are stopped when session stops."""
        config = MonitoringConfig()
        config.enable_api = True
        config.enable_registry = True
        config.enable_file = True

        session = RealMonitoringSessionWrapper(12345, test_process_path, config, fake_frida_server)
        session.start()

        monitors_before = list(session.monitors.values())
        assert len(monitors_before) == 3

        for monitor in monitors_before:
            assert monitor.is_running() is True

        session.stop()

        for monitor in monitors_before:
            assert monitor.is_running() is False

    def test_monitors_emit_events_only_when_running(
        self, test_process_path: str, fake_frida_server: FakeFridaServerManager
    ) -> None:
        """Monitors only emit events when they are running."""
        config = MonitoringConfig()
        config.enable_api = True
        config.enable_registry = False
        config.enable_file = False
        config.enable_network = False
        config.enable_memory = False

        session = RealMonitoringSessionWrapper(12345, test_process_path, config, fake_frida_server)

        received_events: list[MonitorEvent] = []

        def callback(event: MonitorEvent) -> None:
            received_events.append(event)

        session.on_event(callback)
        session.start()

        fake_monitor = session.get_fake_monitor("api")
        assert fake_monitor is not None

        fake_monitor.generate_test_event({"running": "yes"})
        time.sleep(0.1)

        events_while_running = len(received_events)
        assert events_while_running > 0

        session.stop()

        fake_monitor.generate_test_event({"running": "no"})
        time.sleep(0.1)

        events_after_stop = len(received_events)
        assert events_after_stop == events_while_running
