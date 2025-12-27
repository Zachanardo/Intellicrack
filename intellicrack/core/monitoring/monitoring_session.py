"""Monitoring Session Coordinator.

Manages multiple monitors and coordinates their lifecycle.
Provides unified interface for starting/stopping monitoring and event handling.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from collections.abc import Callable
from typing import Any

from intellicrack.core.monitoring.api_monitor import APIMonitor
from intellicrack.core.monitoring.base_monitor import BaseMonitor, MonitorEvent, ProcessInfo
from intellicrack.core.monitoring.event_aggregator import EventAggregator
from intellicrack.core.monitoring.file_monitor import FileMonitor
from intellicrack.core.monitoring.frida_server_manager import FridaServerManager
from intellicrack.core.monitoring.memory_monitor import MemoryMonitor
from intellicrack.core.monitoring.network_monitor import NetworkMonitor
from intellicrack.core.monitoring.registry_monitor import RegistryMonitor


class MonitoringConfig:
    """Configuration for monitoring session."""

    def __init__(self) -> None:
        """Initialize default configuration."""
        self.enable_api: bool = True
        self.enable_registry: bool = True
        self.enable_file: bool = True
        self.enable_network: bool = False
        self.enable_memory: bool = True

        self.file_watch_paths: list[str] | None = None
        self.network_ports: list[int] | None = None
        self.memory_scan_interval: float = 5.0


class MonitoringSession:
    """Coordinates multiple monitors for comprehensive license monitoring.

    Manages API, registry, file, network, and memory monitors.
    Provides unified interface for event handling and session control.
    """

    def __init__(self, pid: int, process_path: str, config: MonitoringConfig | None = None) -> None:
        """Initialize monitoring session.

        Args:
            pid: Process ID to monitor.
            process_path: Path to process executable.
            config: Monitoring configuration.

        """
        self.pid: int = pid
        self.process_path: str = process_path
        self.config: MonitoringConfig = config or MonitoringConfig()

        self.process_info: ProcessInfo = ProcessInfo(pid=pid, name=self._get_process_name(process_path), path=process_path)

        self.aggregator: EventAggregator = EventAggregator()
        self.monitors: dict[str, BaseMonitor] = {}
        self.frida_server: FridaServerManager = FridaServerManager()
        self._running: bool = False

    def start(self) -> bool:
        """Start monitoring session.

        Returns:
            True if started successfully.

        """
        if self._running:
            return True

        if not self.frida_server.start():
            print("[MonitoringSession] Failed to start frida-server")
            return False

        self.aggregator.start()

        success: bool = True

        if self.config.enable_api:
            api_monitor: APIMonitor = APIMonitor(self.pid, self.process_info)
            if self._start_monitor("api", api_monitor):
                self.monitors["api"] = api_monitor
            else:
                success = False

        if self.config.enable_registry:
            registry_monitor: RegistryMonitor = RegistryMonitor(self.process_info)
            if self._start_monitor("registry", registry_monitor):
                self.monitors["registry"] = registry_monitor

        if self.config.enable_file:
            file_monitor: FileMonitor = FileMonitor(self.process_info, self.config.file_watch_paths)
            if self._start_monitor("file", file_monitor):
                self.monitors["file"] = file_monitor

        if self.config.enable_network:
            network_monitor: NetworkMonitor = NetworkMonitor(self.process_info, self.config.network_ports)
            if self._start_monitor("network", network_monitor):
                self.monitors["network"] = network_monitor

        if self.config.enable_memory:
            memory_monitor: MemoryMonitor = MemoryMonitor(self.pid, self.process_info, self.config.memory_scan_interval)
            if self._start_monitor("memory", memory_monitor):
                self.monitors["memory"] = memory_monitor

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
            except Exception as e:
                print(f"[MonitoringSession] Error stopping {name}: {e}")

        self.monitors.clear()

        self.aggregator.stop()

        self.frida_server.stop()

        self._running = False

    def is_running(self) -> bool:
        """Check if session is running.

        Returns:
            True if running.

        """
        return self._running

    def get_stats(self) -> dict[str, Any]:
        """Get monitoring statistics.

        Returns:
            Dictionary of statistics from all monitors.

        """
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
        """Register callback for monitoring events.

        Args:
            callback: Function to call for each event.

        """
        self.aggregator.on_event(callback)

    def on_stats_update(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Register callback for statistics updates.

        Args:
            callback: Function to call with statistics.

        """
        self.aggregator.on_stats_update(callback)

    def on_error(self, callback: Callable[[str], None]) -> None:
        """Register callback for errors.

        Args:
            callback: Function to call with error message.

        """
        self.aggregator.on_error(callback)

    def clear_history(self) -> None:
        """Clear event history."""
        self.aggregator.clear_history()

    def get_history(self, limit: int = 100) -> list[MonitorEvent]:
        """Get recent event history.

        Args:
            limit: Maximum events to return.

        Returns:
            List of recent events.

        """
        return self.aggregator.get_history(limit)

    def _start_monitor(self, name: str, monitor: BaseMonitor) -> bool:
        """Start a monitor and connect it to aggregator.

        Args:
            name: Monitor name.
            monitor: Monitor instance.

        Returns:
            True if started successfully.

        """

        def event_callback(event: MonitorEvent) -> None:
            self.aggregator.submit_event(event)

        try:
            monitor.on_event(event_callback)

            if monitor.start():
                return True
            print(f"[MonitoringSession] Failed to start {name} monitor")
            return False

        except Exception as e:
            print(f"[MonitoringSession] Error starting {name} monitor: {e}")
            return False

    @staticmethod
    def _get_process_name(process_path: str) -> str:
        """Extract process name from path.

        Args:
            process_path: Full path to process.

        Returns:
            Process name.

        """
        import os

        return os.path.basename(process_path)
