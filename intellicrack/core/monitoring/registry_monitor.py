"""Registry Monitor using Windows native notifications.

Uses RegNotifyChangeKeyValue API for OS-level registry change detection,
complementing Frida API hooks with direct Windows notifications.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import ctypes
import ctypes.wintypes
import threading
import time

from intellicrack.core.monitoring.base_monitor import (
    BaseMonitor,
    EventSeverity,
    EventSource,
    EventType,
    MonitorEvent,
    ProcessInfo,
)

advapi32 = ctypes.windll.advapi32
kernel32 = ctypes.windll.kernel32

HKEY_CURRENT_USER = 0x80000001
HKEY_LOCAL_MACHINE = 0x80000002

KEY_NOTIFY = 0x0010
KEY_READ = 0x20019

REG_NOTIFY_CHANGE_NAME = 0x00000001
REG_NOTIFY_CHANGE_ATTRIBUTES = 0x00000002
REG_NOTIFY_CHANGE_LAST_SET = 0x00000004
REG_NOTIFY_CHANGE_SECURITY = 0x00000008

ERROR_SUCCESS = 0
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102


class RegistryMonitor(BaseMonitor):
    """Native Windows registry change monitoring.

    Uses RegNotifyChangeKeyValue for OS-level registry notifications,
    providing comprehensive coverage independent of API hooks.
    """

    def __init__(self, process_info: ProcessInfo | None = None) -> None:
        """Initialize registry monitor.

        Args:
            process_info: Process information (optional for system-wide monitoring).

        """
        super().__init__("RegistryMonitor", process_info)
        self._monitor_thread: threading.Thread | None = None
        self._stop_event: ctypes.wintypes.HANDLE | None = None
        self._watch_keys: list[str] = [
            r"Software",
            r"Software\Microsoft\Windows\CurrentVersion",
            r"Software\Classes\Licenses",
        ]

    def _start_monitoring(self) -> bool:
        """Start registry monitoring.

        Returns:
            True if started successfully.

        """
        try:
            self._stop_event = kernel32.CreateEventW(None, True, False, None)
            if not self._stop_event:
                return False

            self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._monitor_thread.start()
            return True

        except Exception as e:
            return not self._handle_error(e)

    def _stop_monitoring(self) -> None:
        """Stop registry monitoring."""
        if self._stop_event:
            kernel32.SetEvent(self._stop_event)

        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=2.0)

        if self._stop_event:
            kernel32.CloseHandle(self._stop_event)
            self._stop_event = None

    def _monitor_loop(self) -> None:
        """Monitor registry changes in dedicated thread."""
        hives = [
            (HKEY_CURRENT_USER, "HKCU"),
            (HKEY_LOCAL_MACHINE, "HKLM"),
        ]

        watchers = []

        for hive_key, hive_name in hives:
            for subkey in self._watch_keys:
                try:
                    watcher = self._create_watcher(hive_key, hive_name, subkey)
                    if watcher:
                        watchers.append(watcher)
                except Exception as e:
                    print(f"[RegistryMonitor] Failed to watch {hive_name}\\{subkey}: {e}")

        if not watchers:
            return

        while self._running:
            try:
                for watcher in watchers:
                    self._check_watcher(watcher)

                if kernel32.WaitForSingleObject(self._stop_event, 100) == WAIT_OBJECT_0:
                    break

            except Exception as e:
                if not self._handle_error(e):
                    break

        for watcher in watchers:
            try:
                advapi32.RegCloseKey(watcher["hkey"])
                kernel32.CloseHandle(watcher["event"])
            except Exception as e:
                print(f"[RegistryMonitor] Error closing watcher: {e}")

    def _create_watcher(self, hive_key: int, hive_name: str, subkey: str) -> dict | None:
        """Create registry watcher for a key.

        Args:
            hive_key: Registry hive constant.
            hive_name: Hive name for display.
            subkey: Subkey path to watch.

        Returns:
            Watcher dictionary or None if failed.

        """
        hkey = ctypes.wintypes.HKEY()

        result = advapi32.RegOpenKeyExW(hive_key, subkey, 0, KEY_NOTIFY | KEY_READ, ctypes.byref(hkey))

        if result != ERROR_SUCCESS:
            return None

        event_handle = kernel32.CreateEventW(None, False, False, None)
        if not event_handle:
            advapi32.RegCloseKey(hkey)
            return None

        notify_filter = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET

        result = advapi32.RegNotifyChangeKeyValue(
            hkey,
            True,  # Watch subtree
            notify_filter,
            event_handle,
            True,  # Asynchronous
        )

        if result != ERROR_SUCCESS:
            kernel32.CloseHandle(event_handle)
            advapi32.RegCloseKey(hkey)
            return None

        return {"hkey": hkey, "event": event_handle, "hive_name": hive_name, "subkey": subkey, "last_notification": time.time()}

    def _check_watcher(self, watcher: dict) -> None:
        """Check if watcher has detected changes.

        Args:
            watcher: Watcher dictionary.

        """
        result = kernel32.WaitForSingleObject(watcher["event"], 0)

        if result == WAIT_OBJECT_0:
            current_time = time.time()

            if current_time - watcher["last_notification"] < 0.1:
                return

            watcher["last_notification"] = current_time

            event = MonitorEvent(
                timestamp=current_time,
                source=EventSource.REGISTRY,
                event_type=EventType.MODIFY,
                severity=EventSeverity.WARNING,
                details={"hive": watcher["hive_name"], "key_path": watcher["subkey"], "change_type": "registry_modified"},
                process_info=self.process_info,
            )

            self._emit_event(event)

            notify_filter = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET

            advapi32.RegNotifyChangeKeyValue(watcher["hkey"], True, notify_filter, watcher["event"], True)
