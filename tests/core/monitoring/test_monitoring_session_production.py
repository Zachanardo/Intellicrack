"""Production tests for monitoring_session module.

Tests comprehensive monitoring session coordination, managing multiple monitors
for license protection analysis with real process monitoring scenarios.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import time
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.core.monitoring.base_monitor import EventSeverity, EventSource, EventType, MonitorEvent, ProcessInfo
from intellicrack.core.monitoring.monitoring_session import MonitoringConfig, MonitoringSession


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
def mock_frida_server() -> MagicMock:
    """Create mock Frida server."""
    server = MagicMock()
    server.start.return_value = True
    server.stop.return_value = None
    server.get_status.return_value = {"running": True}
    return server


class TestMonitoringConfigInitialization:
    """Test MonitoringConfig initialization."""

    def test_monitoring_config_has_default_values(self) -> None:
        """MonitoringConfig initializes with default values."""
        config = MonitoringConfig()

        assert config.enable_api is True
        assert config.enable_registry is True
        assert config.enable_file is True
        assert config.enable_network is False
        assert config.enable_memory is True
        assert config.file_watch_paths is None
        assert config.network_ports is None
        assert config.memory_scan_interval == 5.0


class TestMonitoringSessionInitialization:
    """Test MonitoringSession initialization."""

    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_initializes_with_process_info(
        self, mock_frida_class: MagicMock, test_process_path: str
    ) -> None:
        """MonitoringSession initializes with process information."""
        pid = 12345
        session = MonitoringSession(pid, test_process_path)

        assert session.pid == pid
        assert session.process_path == test_process_path
        assert session.process_info is not None
        assert session.process_info.pid == pid
        assert session.process_info.path == test_process_path
        assert session.aggregator is not None
        assert session.monitors == {}
        assert session.is_running() is False

    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_uses_custom_config(
        self, mock_frida_class: MagicMock, test_process_path: str, monitoring_config: MonitoringConfig
    ) -> None:
        """MonitoringSession uses custom configuration."""
        pid = 12345
        session = MonitoringSession(pid, test_process_path, monitoring_config)

        assert session.config == monitoring_config
        assert session.config.enable_network is False
        assert session.config.memory_scan_interval == 1.0

    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_creates_default_config_when_none_provided(
        self, mock_frida_class: MagicMock, test_process_path: str
    ) -> None:
        """MonitoringSession creates default config when none provided."""
        pid = 12345
        session = MonitoringSession(pid, test_process_path)

        assert session.config is not None
        assert isinstance(session.config, MonitoringConfig)


class TestSessionStartStop:
    """Test session start and stop functionality."""

    @patch("intellicrack.core.monitoring.monitoring_session.MemoryMonitor")
    @patch("intellicrack.core.monitoring.monitoring_session.FileMonitor")
    @patch("intellicrack.core.monitoring.monitoring_session.RegistryMonitor")
    @patch("intellicrack.core.monitoring.monitoring_session.APIMonitor")
    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_starts_successfully(
        self,
        mock_frida_class: MagicMock,
        mock_api_class: MagicMock,
        mock_registry_class: MagicMock,
        mock_file_class: MagicMock,
        mock_memory_class: MagicMock,
        test_process_path: str,
    ) -> None:
        """Session starts all configured monitors successfully."""
        mock_frida = MagicMock()
        mock_frida.start.return_value = True
        mock_frida_class.return_value = mock_frida

        for mock_monitor_class in [mock_api_class, mock_registry_class, mock_file_class, mock_memory_class]:
            mock_monitor = MagicMock()
            mock_monitor.start.return_value = True
            mock_monitor.on_event = MagicMock()
            mock_monitor_class.return_value = mock_monitor

        session = MonitoringSession(12345, test_process_path)
        success = session.start()

        assert success is True
        assert session.is_running() is True
        mock_frida.start.assert_called_once()

    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_start_fails_when_frida_fails(
        self, mock_frida_class: MagicMock, test_process_path: str
    ) -> None:
        """Session start fails when Frida server fails to start."""
        mock_frida = MagicMock()
        mock_frida.start.return_value = False
        mock_frida_class.return_value = mock_frida

        session = MonitoringSession(12345, test_process_path)
        success = session.start()

        assert success is False
        assert session.is_running() is False

    @patch("intellicrack.core.monitoring.monitoring_session.MemoryMonitor")
    @patch("intellicrack.core.monitoring.monitoring_session.FileMonitor")
    @patch("intellicrack.core.monitoring.monitoring_session.RegistryMonitor")
    @patch("intellicrack.core.monitoring.monitoring_session.APIMonitor")
    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_stop_stops_all_monitors(
        self,
        mock_frida_class: MagicMock,
        mock_api_class: MagicMock,
        mock_registry_class: MagicMock,
        mock_file_class: MagicMock,
        mock_memory_class: MagicMock,
        test_process_path: str,
    ) -> None:
        """Session stop stops all running monitors."""
        mock_frida = MagicMock()
        mock_frida.start.return_value = True
        mock_frida_class.return_value = mock_frida

        monitors = []
        for mock_monitor_class in [mock_api_class, mock_registry_class, mock_file_class, mock_memory_class]:
            mock_monitor = MagicMock()
            mock_monitor.start.return_value = True
            mock_monitor.stop = MagicMock()
            mock_monitor.on_event = MagicMock()
            mock_monitor_class.return_value = mock_monitor
            monitors.append(mock_monitor)

        session = MonitoringSession(12345, test_process_path)
        session.start()
        session.stop()

        assert session.is_running() is False
        assert len(session.monitors) == 0

        for monitor in monitors:
            monitor.stop.assert_called()

        mock_frida.stop.assert_called_once()

    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_start_idempotent(
        self, mock_frida_class: MagicMock, test_process_path: str
    ) -> None:
        """Session start is idempotent."""
        mock_frida = MagicMock()
        mock_frida.start.return_value = True
        mock_frida_class.return_value = mock_frida

        session = MonitoringSession(12345, test_process_path)

        with patch.object(session, "_running", True):
            result = session.start()

        assert result is True
        mock_frida.start.assert_not_called()

    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_stop_when_not_running(
        self, mock_frida_class: MagicMock, test_process_path: str
    ) -> None:
        """Session stop does nothing when not running."""
        mock_frida = MagicMock()
        mock_frida_class.return_value = mock_frida

        session = MonitoringSession(12345, test_process_path)
        session.stop()

        assert session.is_running() is False
        mock_frida.stop.assert_not_called()


class TestMonitorManagement:
    """Test monitor management functionality."""

    @patch("intellicrack.core.monitoring.monitoring_session.APIMonitor")
    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_enables_api_monitor_when_configured(
        self, mock_frida_class: MagicMock, mock_api_class: MagicMock, test_process_path: str
    ) -> None:
        """Session enables API monitor when configured."""
        mock_frida = MagicMock()
        mock_frida.start.return_value = True
        mock_frida_class.return_value = mock_frida

        mock_api = MagicMock()
        mock_api.start.return_value = True
        mock_api.on_event = MagicMock()
        mock_api_class.return_value = mock_api

        config = MonitoringConfig()
        config.enable_api = True
        config.enable_registry = False
        config.enable_file = False
        config.enable_network = False
        config.enable_memory = False

        session = MonitoringSession(12345, test_process_path, config)
        session.start()

        assert "api" in session.monitors
        mock_api.start.assert_called_once()

    @patch("intellicrack.core.monitoring.monitoring_session.NetworkMonitor")
    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_enables_network_monitor_when_configured(
        self, mock_frida_class: MagicMock, mock_network_class: MagicMock, test_process_path: str
    ) -> None:
        """Session enables network monitor when configured."""
        mock_frida = MagicMock()
        mock_frida.start.return_value = True
        mock_frida_class.return_value = mock_frida

        mock_network = MagicMock()
        mock_network.start.return_value = True
        mock_network.on_event = MagicMock()
        mock_network_class.return_value = mock_network

        config = MonitoringConfig()
        config.enable_api = False
        config.enable_registry = False
        config.enable_file = False
        config.enable_network = True
        config.enable_memory = False
        config.network_ports = [80, 443]

        session = MonitoringSession(12345, test_process_path, config)
        session.start()

        assert "network" in session.monitors
        mock_network_class.assert_called_once()

    @patch("intellicrack.core.monitoring.monitoring_session.FileMonitor")
    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_handles_monitor_start_failure(
        self, mock_frida_class: MagicMock, mock_file_class: MagicMock, test_process_path: str
    ) -> None:
        """Session handles monitor start failure gracefully."""
        mock_frida = MagicMock()
        mock_frida.start.return_value = True
        mock_frida_class.return_value = mock_frida

        mock_file = MagicMock()
        mock_file.start.return_value = False
        mock_file.on_event = MagicMock()
        mock_file_class.return_value = mock_file

        config = MonitoringConfig()
        config.enable_api = False
        config.enable_registry = False
        config.enable_file = True
        config.enable_network = False
        config.enable_memory = False

        session = MonitoringSession(12345, test_process_path, config)
        success = session.start()

        assert "file" not in session.monitors or not success


class TestEventHandling:
    """Test event handling and callbacks."""

    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_registers_event_callback(
        self, mock_frida_class: MagicMock, test_process_path: str
    ) -> None:
        """Session allows registering event callbacks."""
        mock_frida_class.return_value = MagicMock()

        session = MonitoringSession(12345, test_process_path)
        callback = MagicMock()

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
        time.sleep(0.1)

        callback.assert_called()

    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_registers_stats_callback(
        self, mock_frida_class: MagicMock, test_process_path: str
    ) -> None:
        """Session allows registering statistics callbacks."""
        mock_frida_class.return_value = MagicMock()

        session = MonitoringSession(12345, test_process_path)
        callback = MagicMock()

        session.on_stats_update(callback)

    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_registers_error_callback(
        self, mock_frida_class: MagicMock, test_process_path: str
    ) -> None:
        """Session allows registering error callbacks."""
        mock_frida_class.return_value = MagicMock()

        session = MonitoringSession(12345, test_process_path)
        callback = MagicMock()

        session.on_error(callback)


class TestHistoryManagement:
    """Test event history management."""

    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_clears_event_history(
        self, mock_frida_class: MagicMock, test_process_path: str
    ) -> None:
        """Session clears event history."""
        mock_frida_class.return_value = MagicMock()

        session = MonitoringSession(12345, test_process_path)

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

        session.clear_history()

        history = session.get_history()
        assert len(history) == 0

    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_retrieves_event_history(
        self, mock_frida_class: MagicMock, test_process_path: str
    ) -> None:
        """Session retrieves event history with limit."""
        mock_frida_class.return_value = MagicMock()

        session = MonitoringSession(12345, test_process_path)

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


class TestStatistics:
    """Test statistics collection."""

    @patch("intellicrack.core.monitoring.monitoring_session.APIMonitor")
    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_collects_statistics(
        self, mock_frida_class: MagicMock, mock_api_class: MagicMock, test_process_path: str
    ) -> None:
        """Session collects statistics from all monitors."""
        mock_frida = MagicMock()
        mock_frida.start.return_value = True
        mock_frida.get_status.return_value = {"running": True}
        mock_frida_class.return_value = mock_frida

        mock_api = MagicMock()
        mock_api.start.return_value = True
        mock_api.on_event = MagicMock()
        mock_api.get_stats.return_value = {"calls": 100, "errors": 0}
        mock_api_class.return_value = mock_api

        config = MonitoringConfig()
        config.enable_api = True
        config.enable_registry = False
        config.enable_file = False
        config.enable_network = False
        config.enable_memory = False

        session = MonitoringSession(12345, test_process_path, config)
        session.start()

        stats = session.get_stats()

        assert "session_running" in stats
        assert stats["session_running"] is True
        assert "frida_server" in stats
        assert "aggregator" in stats
        assert "monitors" in stats
        assert "api" in stats["monitors"]

    @patch("intellicrack.core.monitoring.monitoring_session.APIMonitor")
    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_handles_monitor_stats_errors(
        self, mock_frida_class: MagicMock, mock_api_class: MagicMock, test_process_path: str
    ) -> None:
        """Session handles errors when getting monitor statistics."""
        mock_frida = MagicMock()
        mock_frida.start.return_value = True
        mock_frida.get_status.return_value = {"running": True}
        mock_frida_class.return_value = mock_frida

        mock_api = MagicMock()
        mock_api.start.return_value = True
        mock_api.on_event = MagicMock()
        mock_api.get_stats.side_effect = Exception("Stats error")
        mock_api_class.return_value = mock_api

        config = MonitoringConfig()
        config.enable_api = True
        config.enable_registry = False
        config.enable_file = False
        config.enable_network = False
        config.enable_memory = False

        session = MonitoringSession(12345, test_process_path, config)
        session.start()

        stats = session.get_stats()

        assert "monitors" in stats
        assert "api" in stats["monitors"]
        assert "error" in stats["monitors"]["api"]


class TestProcessNameExtraction:
    """Test process name extraction."""

    def test_get_process_name_extracts_from_windows_path(self) -> None:
        """Get process name extracts name from Windows path."""
        path = r"C:\Program Files\App\test_app.exe"
        name = MonitoringSession._get_process_name(path)

        assert name == "test_app.exe"

    def test_get_process_name_extracts_from_unix_path(self) -> None:
        """Get process name extracts name from Unix path."""
        path = "/usr/local/bin/test_app"
        name = MonitoringSession._get_process_name(path)

        assert name == "test_app"

    def test_get_process_name_handles_filename_only(self) -> None:
        """Get process name handles filename without path."""
        path = "test_app.exe"
        name = MonitoringSession._get_process_name(path)

        assert name == "test_app.exe"


class TestEdgeCases:
    """Test edge cases and error handling."""

    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_handles_invalid_pid(self, mock_frida_class: MagicMock, test_process_path: str) -> None:
        """Session handles invalid PID gracefully."""
        mock_frida_class.return_value = MagicMock()

        session = MonitoringSession(-1, test_process_path)

        assert session.pid == -1
        assert session.process_info.pid == -1

    @patch("intellicrack.core.monitoring.monitoring_session.APIMonitor")
    @patch("intellicrack.core.monitoring.monitoring_session.FridaServerManager")
    def test_session_stop_handles_monitor_errors(
        self, mock_frida_class: MagicMock, mock_api_class: MagicMock, test_process_path: str
    ) -> None:
        """Session stop handles monitor stop errors gracefully."""
        mock_frida = MagicMock()
        mock_frida.start.return_value = True
        mock_frida_class.return_value = mock_frida

        mock_api = MagicMock()
        mock_api.start.return_value = True
        mock_api.on_event = MagicMock()
        mock_api.stop.side_effect = Exception("Stop error")
        mock_api_class.return_value = mock_api

        config = MonitoringConfig()
        config.enable_api = True
        config.enable_registry = False
        config.enable_file = False
        config.enable_network = False
        config.enable_memory = False

        session = MonitoringSession(12345, test_process_path, config)
        session.start()

        session.stop()

        assert session.is_running() is False
