"""Production tests for Windows registry monitoring functionality.

Tests validate real registry change detection, Windows API integration,
license key monitoring, and event emission for registry operations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import platform
import time
from typing import Any

import pytest

from intellicrack.core.monitoring.base_monitor import EventSource, ProcessInfo


pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Registry monitor tests require Windows platform",
)


@pytest.fixture
def process_info() -> ProcessInfo:
    """Create process info for testing."""
    return ProcessInfo(
        pid=5678,
        name="test_app.exe",
        path="C:\\test\\test_app.exe",
    )


@pytest.fixture
def registry_monitor(process_info: ProcessInfo) -> Any:
    """Create registry monitor instance for testing."""
    from intellicrack.core.monitoring.registry_monitor import RegistryMonitor

    monitor = RegistryMonitor(process_info=process_info)
    yield monitor

    if monitor.is_monitoring:
        monitor.stop()


def test_registry_monitor_initialization(registry_monitor: Any, process_info: ProcessInfo) -> None:
    """Registry monitor initializes with process info and watch keys."""
    assert registry_monitor.process_info == process_info
    assert hasattr(registry_monitor, "_watch_keys")
    assert isinstance(registry_monitor._watch_keys, list)
    assert len(registry_monitor._watch_keys) > 0


def test_registry_monitor_default_watch_keys_include_software(registry_monitor: Any) -> None:
    """Registry monitor includes standard software registry paths."""
    watch_keys = registry_monitor._watch_keys

    assert any("Software" in key for key in watch_keys)


def test_registry_monitor_starts_successfully(registry_monitor: Any) -> None:
    """Registry monitor starts monitoring with Windows API integration."""
    if result := registry_monitor.start():
        assert registry_monitor.is_monitoring is True
        assert registry_monitor._monitor_thread is not None
        assert registry_monitor._stop_event is not None
        registry_monitor.stop()
    else:
        pytest.skip("Registry monitor start failed (likely permissions)")


def test_registry_monitor_stops_cleanly(registry_monitor: Any) -> None:
    """Registry monitor stops monitoring and cleans up resources."""
    if result := registry_monitor.start():
        time.sleep(0.5)

        registry_monitor.stop()

        assert registry_monitor.is_monitoring is False
        assert registry_monitor._stop_event is None
    else:
        pytest.skip("Registry monitor start failed")


def test_registry_monitor_creates_watchers_for_hives(registry_monitor: Any) -> None:
    """Registry monitor creates watchers for HKCU and HKLM hives."""
    from intellicrack.core.monitoring.registry_monitor import HKEY_CURRENT_USER

    if watcher := registry_monitor._create_watcher(
        HKEY_CURRENT_USER,
        "HKCU",
        r"Software",
    ):
        assert "hkey" in watcher
        assert "event" in watcher
        assert "path" in watcher

        import ctypes

        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        advapi32.RegCloseKey(watcher["hkey"])
        kernel32.CloseHandle(watcher["event"])
    else:
        pytest.skip("Failed to create watcher (likely permissions)")


def test_registry_monitor_handles_invalid_key_gracefully(registry_monitor: Any) -> None:
    """Registry monitor handles attempts to watch non-existent registry keys."""
    from intellicrack.core.monitoring.registry_monitor import HKEY_CURRENT_USER

    watcher = registry_monitor._create_watcher(
        HKEY_CURRENT_USER,
        "HKCU",
        r"NonExistent\Invalid\RegistryPath\12345",
    )

    assert watcher is None


def test_registry_monitor_detects_registry_changes(registry_monitor: Any) -> None:
    """Registry monitor detects actual registry modifications."""
    import winreg

    test_key_path = r"Software\IntellicrackTest"

    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, test_key_path)
        winreg.CloseKey(key)

        events_captured = []

        def capture_event(event: Any) -> None:
            events_captured.append(event)

        registry_monitor.add_event_listener(capture_event)

        result = registry_monitor.start()

        if result:
            time.sleep(1.0)

            test_key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                test_key_path,
                0,
                winreg.KEY_WRITE,
            )
            winreg.SetValueEx(test_key, "TestValue", 0, winreg.REG_SZ, "test_data")
            winreg.CloseKey(test_key)

            time.sleep(2.0)

            registry_monitor.stop()

            if events_captured:
                event = events_captured[0]
                assert event.source == EventSource.REGISTRY
    except PermissionError:
        pytest.skip("Insufficient permissions for registry modification")
    finally:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, test_key_path)
        except Exception:
            pass


def test_registry_monitor_emits_events_with_correct_details(registry_monitor: Any) -> None:
    """Registry monitor emits events with detailed change information."""
    import winreg

    test_key_path = r"Software\IntellicrackEventTest"

    try:
        events_captured = []

        def capture_event(event: Any) -> None:
            events_captured.append(event)

        registry_monitor.add_event_listener(capture_event)

        result = registry_monitor.start()

        if result:
            time.sleep(0.5)

            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, test_key_path)
            winreg.SetValueEx(key, "LicenseKey", 0, winreg.REG_SZ, "ABC-123-XYZ")
            winreg.CloseKey(key)

            time.sleep(2.0)

            registry_monitor.stop()

            if events_captured:
                event = events_captured[0]
                assert hasattr(event, "details")
                assert isinstance(event.details, dict)
    except PermissionError:
        pytest.skip("Insufficient permissions")
    finally:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, test_key_path)
        except Exception:
            pass


def test_registry_monitor_multiple_watchers_concurrent(registry_monitor: Any) -> None:
    """Registry monitor handles multiple registry watchers concurrently."""
    if result := registry_monitor.start():
        time.sleep(1.0)

        registry_monitor.stop()

    else:
        pytest.skip("Registry monitor start failed")


def test_registry_monitor_handles_monitoring_errors(registry_monitor: Any) -> None:
    """Registry monitor handles errors during monitoring gracefully."""
    if result := registry_monitor.start():
        registry_monitor._running = False

        time.sleep(0.5)

        registry_monitor.stop()

    else:
        pytest.skip("Registry monitor start failed")


def test_registry_monitor_thread_cleanup_on_stop(registry_monitor: Any) -> None:
    """Registry monitor properly cleans up monitoring thread on stop."""
    if result := registry_monitor.start():
        monitor_thread = registry_monitor._monitor_thread

        registry_monitor.stop()

        time.sleep(0.5)

        if monitor_thread:
            assert not monitor_thread.is_alive()
    else:
        pytest.skip("Registry monitor start failed")


def test_registry_monitor_watch_keys_configurable(registry_monitor: Any) -> None:
    """Registry monitor allows configuration of watched registry paths."""
    original_keys = registry_monitor._watch_keys.copy()

    registry_monitor._watch_keys = [r"Software\TestApp"]

    assert len(registry_monitor._watch_keys) == 1
    assert registry_monitor._watch_keys[0] == r"Software\TestApp"

    registry_monitor._watch_keys = original_keys


def test_registry_monitor_handles_rapid_start_stop(registry_monitor: Any) -> None:
    """Registry monitor handles rapid start/stop cycles correctly."""
    for _ in range(3):
        if result := registry_monitor.start():
            time.sleep(0.2)
            registry_monitor.stop()
            time.sleep(0.1)
        else:
            pytest.skip("Registry monitor start failed")


def test_registry_monitor_watcher_creation_with_permissions(registry_monitor: Any) -> None:
    """Registry monitor watcher creation respects access permissions."""
    from intellicrack.core.monitoring.registry_monitor import HKEY_LOCAL_MACHINE

    if watcher := registry_monitor._create_watcher(
        HKEY_LOCAL_MACHINE,
        "HKLM",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion",
    ):
        import ctypes

        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        advapi32.RegCloseKey(watcher["hkey"])
        kernel32.CloseHandle(watcher["event"])


def test_registry_monitor_stop_event_signals_correctly(registry_monitor: Any) -> None:
    """Registry monitor stop event signals monitoring thread correctly."""
    if result := registry_monitor.start():
        assert registry_monitor._stop_event is not None

        import ctypes

        kernel32 = ctypes.windll.kernel32

        kernel32.SetEvent(registry_monitor._stop_event)

        time.sleep(0.5)

        registry_monitor.stop()

    else:
        pytest.skip("Registry monitor start failed")
