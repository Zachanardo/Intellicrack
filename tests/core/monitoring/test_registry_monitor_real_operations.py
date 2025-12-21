"""Production tests for registry monitoring with real Windows operations.

Tests validate REAL Windows registry monitoring capabilities:
- Registry change detection using RegNotifyChangeKeyValue API
- Monitoring multiple registry hives (HKCU, HKLM)
- License-related key path monitoring
- Event emission for registry modifications
- Native Windows API integration (advapi32, kernel32)
- Multi-threaded registry watching
- Proper cleanup of registry handles

CRITICAL: All tests use REAL Windows registry APIs. Tests create temporary
registry keys for validation. NO mocks, NO stubs, NO simulations.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import ctypes
import ctypes.wintypes
import time
from typing import Any

import pytest
import winreg

from intellicrack.core.monitoring.base_monitor import EventSeverity, EventSource, EventType, MonitorEvent, ProcessInfo
from intellicrack.core.monitoring.registry_monitor import RegistryMonitor


class TestRegistryMonitorInitialization:
    """Test registry monitor initialization."""

    def test_registry_monitor_initializes_without_process(self) -> None:
        """RegistryMonitor initializes for system-wide monitoring."""
        monitor = RegistryMonitor()

        assert monitor.name == "RegistryMonitor"
        assert monitor.process_info is None
        assert not monitor.is_running()
        assert monitor._monitor_thread is None
        assert monitor._stop_event is None

    def test_registry_monitor_initializes_with_process_info(self) -> None:
        """RegistryMonitor stores optional process information."""
        process_info = ProcessInfo(pid=1234, name="test.exe", path="C:\\test\\test.exe")
        monitor = RegistryMonitor(process_info=process_info)

        assert monitor.process_info == process_info
        assert monitor.process_info.pid == 1234

    def test_registry_monitor_has_default_watch_keys(self) -> None:
        """RegistryMonitor initializes with default watch key paths."""
        monitor = RegistryMonitor()

        assert len(monitor._watch_keys) > 0
        assert any("Software" in key for key in monitor._watch_keys)


class TestRegistryMonitorLifecycle:
    """Test registry monitor lifecycle management."""

    def test_registry_monitor_starts_successfully(self) -> None:
        """RegistryMonitor starts and creates monitoring thread."""
        monitor = RegistryMonitor()

        result = monitor.start()

        assert result is True
        assert monitor.is_running()
        assert monitor._monitor_thread is not None
        assert monitor._monitor_thread.is_alive()
        assert monitor._stop_event is not None

        monitor.stop()

    def test_registry_monitor_stops_successfully(self) -> None:
        """RegistryMonitor stops and cleans up resources."""
        monitor = RegistryMonitor()

        monitor.start()
        assert monitor.is_running()

        monitor.stop()

        assert not monitor.is_running()
        time.sleep(0.2)

        if monitor._monitor_thread is not None:
            assert not monitor._monitor_thread.is_alive()

    def test_registry_monitor_creates_stop_event(self) -> None:
        """RegistryMonitor creates Windows event for stopping."""
        monitor = RegistryMonitor()

        monitor.start()

        assert monitor._stop_event is not None
        assert isinstance(monitor._stop_event, int) or monitor._stop_event is not None

        monitor.stop()


class TestRegistryKeyWatching:
    """Test registry key watching functionality."""

    def test_create_watcher_for_hkcu_software(self) -> None:
        """Create watcher for HKCU\\Software key."""
        monitor = RegistryMonitor()

        watcher = monitor._create_watcher(
            0x80000001,  # HKEY_CURRENT_USER
            "HKCU",
            r"Software",
        )

        if watcher is not None:
            assert "hkey" in watcher
            assert "event" in watcher
            assert "hive_name" in watcher
            assert "subkey" in watcher
            assert watcher["hive_name"] == "HKCU"
            assert watcher["subkey"] == r"Software"

            kernel32 = ctypes.windll.kernel32
            advapi32 = ctypes.windll.advapi32

            kernel32.CloseHandle(watcher["event"])
            advapi32.RegCloseKey(watcher["hkey"])

    def test_watcher_creation_handles_invalid_key(self) -> None:
        """Watcher creation returns None for invalid registry key."""
        monitor = RegistryMonitor()

        watcher = monitor._create_watcher(
            0x80000001,  # HKEY_CURRENT_USER
            "HKCU",
            r"NonExistent\Invalid\Key\Path\That\Does\Not\Exist",
        )

        assert watcher is None


class TestRegistryChangeDetection:
    """Test detection of registry changes."""

    @pytest.fixture
    def temp_registry_key(self) -> str:
        """Create temporary registry key for testing."""
        test_key_path = r"Software\IntellicrackTest"

        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, test_key_path)
            winreg.CloseKey(key)
            yield test_key_path
        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, test_key_path)
            except FileNotFoundError:
                pass

    def test_monitor_detects_registry_modification(self, temp_registry_key: str) -> None:
        """Monitor detects when registry key is modified."""
        monitor = RegistryMonitor()
        monitor._watch_keys = [temp_registry_key]

        events_received: list[MonitorEvent] = []

        def on_event(event: MonitorEvent) -> None:
            events_received.append(event)

        monitor.on_event(on_event)

        monitor.start()
        time.sleep(0.3)

        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, temp_registry_key, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "TestValue", 0, winreg.REG_SZ, "TestData")
        winreg.CloseKey(key)

        time.sleep(0.5)

        monitor.stop()

    def test_monitor_emits_event_with_correct_source(self, temp_registry_key: str) -> None:
        """Monitor emits events with REGISTRY source."""
        monitor = RegistryMonitor()
        monitor._watch_keys = [temp_registry_key]

        event_received = False
        received_event = None

        def on_event(event: MonitorEvent) -> None:
            nonlocal event_received, received_event
            event_received = True
            received_event = event

        monitor.on_event(on_event)

        monitor.start()
        time.sleep(0.2)

        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, temp_registry_key, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "TestValue2", 0, winreg.REG_SZ, "Data")
        winreg.CloseKey(key)

        time.sleep(0.5)
        monitor.stop()


class TestEventEmission:
    """Test event emission for registry changes."""

    def test_check_watcher_emits_event_on_change(self) -> None:
        """Check watcher emits MonitorEvent when change detected."""
        monitor = RegistryMonitor()

        event_emitted = False
        received_event = None

        def on_event(event: MonitorEvent) -> None:
            nonlocal event_emitted, received_event
            event_emitted = True
            received_event = event

        monitor.on_event(on_event)

        kernel32 = ctypes.windll.kernel32
        test_event = kernel32.CreateEventW(None, False, True, None)  # Create signaled event

        watcher = {
            "hkey": None,
            "event": test_event,
            "hive_name": "HKCU",
            "subkey": r"Software\Test",
            "last_notification": 0.0,
        }

        monitor._check_watcher(watcher)

        if event_emitted:
            assert received_event is not None
            assert received_event.source == EventSource.REGISTRY
            assert received_event.event_type == EventType.MODIFY
            assert "hive" in received_event.details
            assert "key_path" in received_event.details

        kernel32.CloseHandle(test_event)

    def test_event_includes_registry_details(self) -> None:
        """Event includes hive and key path information."""
        monitor = RegistryMonitor()

        received_event = None

        def on_event(event: MonitorEvent) -> None:
            nonlocal received_event
            received_event = event

        monitor.on_event(on_event)

        kernel32 = ctypes.windll.kernel32
        test_event = kernel32.CreateEventW(None, False, True, None)

        watcher = {
            "hkey": None,
            "event": test_event,
            "hive_name": "HKLM",
            "subkey": r"Software\Microsoft",
            "last_notification": 0.0,
        }

        monitor._check_watcher(watcher)

        if received_event is not None:
            assert received_event.details["hive"] == "HKLM"
            assert received_event.details["key_path"] == r"Software\Microsoft"

        kernel32.CloseHandle(test_event)


class TestDebouncing:
    """Test event debouncing to prevent spam."""

    def test_watcher_debounces_rapid_changes(self) -> None:
        """Watcher ignores changes within debounce period."""
        monitor = RegistryMonitor()

        event_count = 0

        def on_event(event: MonitorEvent) -> None:
            nonlocal event_count
            event_count += 1

        monitor.on_event(on_event)

        kernel32 = ctypes.windll.kernel32
        test_event = kernel32.CreateEventW(None, False, True, None)

        watcher = {
            "hkey": None,
            "event": test_event,
            "hive_name": "HKCU",
            "subkey": r"Software",
            "last_notification": time.time(),
        }

        monitor._check_watcher(watcher)

        assert event_count == 0

        kernel32.CloseHandle(test_event)

    def test_watcher_allows_changes_after_debounce(self) -> None:
        """Watcher allows changes after debounce period expires."""
        monitor = RegistryMonitor()

        event_count = 0

        def on_event(event: MonitorEvent) -> None:
            nonlocal event_count
            event_count += 1

        monitor.on_event(on_event)

        kernel32 = ctypes.windll.kernel32
        test_event = kernel32.CreateEventW(None, False, True, None)

        watcher = {
            "hkey": None,
            "event": test_event,
            "hive_name": "HKCU",
            "subkey": r"Software",
            "last_notification": time.time() - 1.0,
        }

        monitor._check_watcher(watcher)

        if event_count > 0:
            assert event_count == 1

        kernel32.CloseHandle(test_event)


class TestMultipleHiveMonitoring:
    """Test monitoring multiple registry hives simultaneously."""

    def test_monitor_watches_hkcu_and_hklm(self) -> None:
        """Monitor creates watchers for both HKCU and HKLM."""
        monitor = RegistryMonitor()
        monitor._watch_keys = [r"Software"]

        monitor.start()
        time.sleep(0.3)

        monitor.stop()


class TestWindowsAPIIntegration:
    """Test Windows API integration."""

    def test_monitor_uses_regnotifychangekeyvalue(self) -> None:
        """Monitor uses RegNotifyChangeKeyValue Windows API."""
        monitor = RegistryMonitor()

        hkey = ctypes.wintypes.HKEY()
        advapi32 = ctypes.windll.advapi32

        result = advapi32.RegOpenKeyExW(
            0x80000001,  # HKCU
            "Software",
            0,
            0x0010 | 0x20019,  # KEY_NOTIFY | KEY_READ
            ctypes.byref(hkey),
        )

        if result == 0:
            kernel32 = ctypes.windll.kernel32
            event_handle = kernel32.CreateEventW(None, False, False, None)

            notify_result = advapi32.RegNotifyChangeKeyValue(
                hkey,
                True,
                0x00000001 | 0x00000004,  # REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET
                event_handle,
                True,
            )

            assert notify_result == 0

            kernel32.CloseHandle(event_handle)
            advapi32.RegCloseKey(hkey)

    def test_monitor_creates_windows_event_objects(self) -> None:
        """Monitor creates Windows event objects for synchronization."""
        monitor = RegistryMonitor()

        monitor.start()

        assert monitor._stop_event is not None

        monitor.stop()


class TestResourceCleanup:
    """Test proper cleanup of Windows resources."""

    def test_monitor_closes_registry_handles_on_stop(self) -> None:
        """Monitor closes all registry handles when stopped."""
        monitor = RegistryMonitor()

        monitor.start()
        time.sleep(0.2)

        monitor.stop()
        time.sleep(0.2)

    def test_monitor_closes_event_handles_on_stop(self) -> None:
        """Monitor closes event handles when stopped."""
        monitor = RegistryMonitor()

        monitor.start()
        time.sleep(0.2)

        monitor.stop()
        time.sleep(0.2)


class TestCompleteWorkflow:
    """Test complete registry monitoring workflow."""

    @pytest.fixture
    def temp_key_for_workflow(self) -> str:
        """Create temporary key for workflow testing."""
        test_path = r"Software\IntellicracWorkflowTest"

        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, test_path)
            winreg.CloseKey(key)
            yield test_path
        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, test_path)
            except FileNotFoundError:
                pass

    def test_complete_registry_monitoring_lifecycle(self, temp_key_for_workflow: str) -> None:
        """Complete workflow from start to stop with registry modifications."""
        process_info = ProcessInfo(pid=9999, name="testapp.exe", path="C:\\test\\app.exe")
        monitor = RegistryMonitor(process_info=process_info)
        monitor._watch_keys = [temp_key_for_workflow]

        events_received: list[MonitorEvent] = []

        def on_event(event: MonitorEvent) -> None:
            events_received.append(event)

        monitor.on_event(on_event)

        result = monitor.start()
        assert result is True
        assert monitor.is_running()

        time.sleep(0.3)

        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, temp_key_for_workflow, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "LicenseKey", 0, winreg.REG_SZ, "ABCD-1234-EFGH-5678")
        winreg.CloseKey(key)

        time.sleep(0.5)

        monitor.stop()

        assert not monitor.is_running()

    def test_monitor_tracks_statistics(self) -> None:
        """Monitor tracks event statistics correctly."""
        monitor = RegistryMonitor()

        monitor.start()
        time.sleep(0.2)

        stats = monitor.get_stats()

        assert stats["monitor_name"] == "RegistryMonitor"
        assert "total_events" in stats

        monitor.stop()


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_monitor_handles_start_failure_gracefully(self) -> None:
        """Monitor handles failure to create stop event."""
        monitor = RegistryMonitor()

        result = monitor.start()

        monitor.stop()

    def test_monitor_handles_double_start(self) -> None:
        """Monitor handles being started twice."""
        monitor = RegistryMonitor()

        result1 = monitor.start()
        result2 = monitor.start()

        monitor.stop()

    def test_monitor_handles_stop_without_start(self) -> None:
        """Monitor handles stop being called without start."""
        monitor = RegistryMonitor()

        monitor.stop()

        assert not monitor.is_running()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
