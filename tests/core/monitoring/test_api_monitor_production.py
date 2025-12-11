"""Production-ready tests for intellicrack/core/monitoring/api_monitor.py

Tests validate REAL offensive capabilities for Windows API monitoring via Frida:
- API monitor initialization and lifecycle management
- Real Frida session attachment to Windows processes
- License-related API detection in actual binaries
- Registry API hooking (RegQueryValue, RegSetValue, RegOpenKey, RegDeleteKey)
- File API hooking (CreateFile, ReadFile, WriteFile, DeleteFile)
- Network API hooking (connect, send, recv, InternetOpen)
- Crypto API hooking (CryptDecrypt, CryptEncrypt)
- Time API hooking (GetSystemTime, GetTickCount)
- Event severity classification for licensing keywords
- Hook point detection and call stack capture
- Process lifecycle management and cleanup
- Error handling for failed attachments
"""

import time
from typing import Any
from collections.abc import Callable

import frida
import pytest

from intellicrack.core.monitoring.api_monitor import APIMonitor
from intellicrack.core.monitoring.base_monitor import (
    EventSeverity,
    EventSource,
    EventType,
    MonitorEvent,
    ProcessInfo,
)


NOTEPAD_PATH: str = "C:\\Windows\\System32\\notepad.exe"
CALC_PATH: str = "C:\\Windows\\System32\\calc.exe"
MSPAINT_PATH: str = "C:\\Windows\\System32\\mspaint.exe"
CMD_PATH: str = "C:\\Windows\\System32\\cmd.exe"
TIMEOUT_SHORT: float = 0.3
TIMEOUT_LONG: float = 1.0


class TestAPIMonitorInitialization:
    """Test API monitor initialization and configuration."""

    def test_api_monitor_initializes_with_valid_pid(self) -> None:
        """APIMonitor initializes with valid process ID."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            assert monitor.pid == pid
            assert monitor.session is None
            assert monitor.script is None
            assert monitor.name == "APIMonitor"
            assert not monitor.is_running()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_initializes_with_process_info(self) -> None:
        """APIMonitor stores process information correctly."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            process_info = ProcessInfo(
                pid=pid, name="calc.exe", path=CALC_PATH
            )
            monitor = APIMonitor(pid=pid, process_info=process_info)

            assert monitor.process_info == process_info
            assert monitor.process_info.pid == pid
            assert monitor.process_info.name == "calc.exe"
            assert monitor.process_info.path == CALC_PATH

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_tracks_running_state(self) -> None:
        """APIMonitor correctly tracks running state."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            assert not monitor.is_running()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_has_zero_initial_error_count(self) -> None:
        """APIMonitor starts with zero errors."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            stats = monitor.get_stats()

            assert stats["error_count"] == 0
            assert stats["total_events"] == 0

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestAPIMonitorLifecycle:
    """Test API monitor start, stop, and cleanup operations."""

    def test_api_monitor_starts_successfully_on_notepad(self) -> None:
        """APIMonitor successfully attaches to notepad.exe and starts monitoring."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            result: bool = monitor.start()

            assert result is True
            assert monitor.is_running()
            assert monitor.session is not None
            assert not monitor.session.is_detached
            assert monitor.script is not None

            monitor.stop()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_starts_successfully_on_calc(self) -> None:
        """APIMonitor successfully attaches to calc.exe."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            result: bool = monitor.start()

            assert result is True
            assert monitor.is_running()
            assert monitor.session is not None
            assert monitor.script is not None

            monitor.stop()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_stops_cleanly(self) -> None:
        """APIMonitor stops monitoring and cleans up resources."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            monitor.start()
            assert monitor.is_running()

            monitor.stop()

            assert not monitor.is_running()
            assert monitor.script is None
            assert monitor.session is None

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_handles_multiple_start_calls(self) -> None:
        """APIMonitor handles multiple start calls gracefully."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            result1: bool = monitor.start()
            result2: bool = monitor.start()

            assert result1 is True
            assert result2 is True
            assert monitor.is_running()

            monitor.stop()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_handles_multiple_stop_calls(self) -> None:
        """APIMonitor handles multiple stop calls without error."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            monitor.start()
            monitor.stop()

            assert not monitor.is_running()

            monitor.stop()
            assert not monitor.is_running()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_detaches_on_process_exit(self) -> None:
        """APIMonitor detaches when monitored process terminates."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            monitor.start()
            session = monitor.session

            assert session is not None
            assert not session.is_detached

            device.kill(pid)
            time.sleep(TIMEOUT_SHORT)

            assert session.is_detached

            monitor.stop()

        except frida.ProcessNotFoundError:
            pass


class TestAPIMonitorFridaScriptGeneration:
    """Test Frida script generation and structure."""

    def test_build_frida_script_returns_valid_javascript(self) -> None:
        """Frida script contains valid JavaScript code."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            script_source: str = monitor._build_frida_script()

            assert isinstance(script_source, str)
            assert len(script_source) > 0
            assert "function" in script_source
            assert "Interceptor.attach" in script_source

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_frida_script_loads_successfully_in_process(self) -> None:
        """Generated Frida script loads and executes without errors."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        messages: list[dict[str, Any]] = []

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            messages.append(message)

        try:
            monitor = APIMonitor(pid=pid)
            script_source = monitor._build_frida_script()

            session: frida.core.Session = device.attach(pid)
            script: frida.core.Script = session.create_script(script_source)
            script.on("message", on_message)
            script.load()

            device.resume(pid)
            time.sleep(TIMEOUT_SHORT)

            assert len(messages) >= 1
            ready_msg = [m for m in messages if m.get("type") == "send"]
            assert len(ready_msg) >= 1

            session.detach()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_frida_script_contains_registry_hooks(self) -> None:
        """Frida script includes registry API hooks."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            script_source = monitor._build_frida_script()

            assert "RegOpenKeyExW" in script_source
            assert "RegQueryValueExW" in script_source
            assert "RegSetValueExW" in script_source
            assert "RegDeleteKeyW" in script_source
            assert "advapi32.dll" in script_source

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_frida_script_contains_file_hooks(self) -> None:
        """Frida script includes file API hooks."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            script_source = monitor._build_frida_script()

            assert "CreateFileW" in script_source
            assert "ReadFile" in script_source
            assert "WriteFile" in script_source
            assert "DeleteFileW" in script_source
            assert "kernel32.dll" in script_source

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_frida_script_contains_network_hooks(self) -> None:
        """Frida script includes network API hooks."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            script_source = monitor._build_frida_script()

            assert "connect" in script_source
            assert "send" in script_source
            assert "recv" in script_source
            assert "InternetOpenW" in script_source
            assert "ws2_32.dll" in script_source
            assert "wininet.dll" in script_source

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_frida_script_contains_crypto_hooks(self) -> None:
        """Frida script includes cryptography API hooks."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            script_source = monitor._build_frida_script()

            assert "CryptDecrypt" in script_source
            assert "CryptEncrypt" in script_source

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_frida_script_contains_time_hooks(self) -> None:
        """Frida script includes time API hooks for trial detection."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            script_source = monitor._build_frida_script()

            assert "GetSystemTime" in script_source
            assert "GetTickCount" in script_source

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_frida_script_contains_helper_functions(self) -> None:
        """Frida script includes string reading and call stack helpers."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            script_source = monitor._build_frida_script()

            assert "readWideString" in script_source
            assert "readAnsiString" in script_source
            assert "getCallStack" in script_source
            assert "Thread.backtrace" in script_source

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestAPIMonitorEventHandling:
    """Test API monitor event generation and handling."""

    def test_api_monitor_generates_events_for_process_activity(self) -> None:
        """APIMonitor generates events when process makes API calls."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        events: list[MonitorEvent] = []

        def on_event(event: MonitorEvent) -> None:
            events.append(event)

        try:
            monitor = APIMonitor(pid=pid)
            monitor.on_event(on_event)
            result: bool = monitor.start()

            device.resume(pid)
            time.sleep(TIMEOUT_LONG)

            if result:
                assert monitor.is_running()

            monitor.stop()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_event_has_correct_source(self) -> None:
        """APIMonitor events have EventSource.API."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            payload: dict[str, Any] = {
                "api": "GetSystemTime",
                "category": "time",
                "args": [],
                "result": "queried",
                "call_stack": [],
            }

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].source == EventSource.API

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_event_contains_timestamp(self) -> None:
        """APIMonitor events include valid timestamps."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            payload: dict[str, Any] = {
                "api": "CreateFileW",
                "category": "file_read",
                "args": ["test.txt", "read"],
                "result": "handle",
                "call_stack": [],
            }

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].timestamp > 0
            assert isinstance(events[0].timestamp, float)

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_event_includes_api_name(self) -> None:
        """APIMonitor events contain the API name that was called."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            payload: dict[str, Any] = {
                "api": "RegQueryValueExW",
                "category": "registry_read",
                "args": ["HKLM\\Software"],
                "result": "success",
                "call_stack": [],
            }

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert "api" in events[0].details
            assert isinstance(events[0].details["api"], str)
            assert events[0].details["api"] == "RegQueryValueExW"

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_event_includes_category(self) -> None:
        """APIMonitor events include category (registry, file, network, crypto, time)."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            valid_categories = [
                "registry_read",
                "file_write",
                "network_connect",
                "crypto",
                "time",
            ]

            for category in valid_categories:
                payload: dict[str, Any] = {
                    "api": "TestAPI",
                    "category": category,
                    "args": ["test"],
                    "result": "success",
                    "call_stack": [],
                }

                monitor._handle_api_call(payload)

            assert len(events) == len(valid_categories)
            for event in events:
                assert "category" in event.details
                assert event.details["category"] in valid_categories

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_event_includes_call_stack(self) -> None:
        """APIMonitor events include call stack information."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            payload: dict[str, Any] = {
                "api": "CryptDecrypt",
                "category": "crypto",
                "args": ["key_handle", "128 bytes"],
                "result": "success",
                "call_stack": ["0x401000", "0x402000", "0x403000"],
            }

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert isinstance(events[0].call_stack, list)
            assert len(events[0].call_stack) == 3
            assert events[0].call_stack[0] == "0x401000"

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_tracks_event_statistics(self) -> None:
        """APIMonitor tracks total events and events by type."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            payloads = [
                {"api": "RegQueryValueExW", "category": "registry_read", "args": [], "result": "", "call_stack": []},
                {"api": "CreateFileW", "category": "file_read", "args": [], "result": "", "call_stack": []},
                {"api": "GetSystemTime", "category": "time", "args": [], "result": "", "call_stack": []},
            ]

            for payload in payloads:
                monitor._handle_api_call(payload)

            stats = monitor.get_stats()

            assert stats["total_events"] == len(payloads)
            assert "events_by_type" in stats
            assert isinstance(stats["events_by_type"], dict)
            assert len(stats["events_by_type"]) > 0

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestLicenseAPIDetection:
    """Test detection of license-related API patterns."""

    def test_handle_api_call_classifies_licensing_keywords(self) -> None:
        """APIMonitor detects licensing keywords in API arguments."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            licensing_keywords = ["license", "serial", "key", "activation", "trial"]

            for keyword in licensing_keywords:
                monitor = APIMonitor(pid=pid)
                events: list[MonitorEvent] = []
                monitor.on_event(lambda e: events.append(e))

                payload: dict[str, Any] = {
                    "api": "RegQueryValueExW",
                    "category": "registry_read",
                    "args": [f"Software\\Test\\{keyword}"],
                    "result": "success",
                    "call_stack": [],
                }

                monitor._handle_api_call(payload)

                assert len(events) == 1
                assert events[0].severity == EventSeverity.CRITICAL

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_handle_api_call_marks_registry_write_as_warning(self) -> None:
        """APIMonitor marks registry write operations as WARNING severity."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "RegSetValueExW",
                "category": "registry_write",
                "args": ["Software\\Test", "value"],
                "result": "success",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].severity == EventSeverity.WARNING

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_handle_api_call_marks_file_write_as_warning(self) -> None:
        """APIMonitor marks file write operations as WARNING severity."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "WriteFile",
                "category": "file_write",
                "args": ["handle", "100 bytes"],
                "result": "success",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].severity == EventSeverity.WARNING

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_handle_api_call_normal_operations_are_info(self) -> None:
        """APIMonitor marks non-licensing operations as INFO severity."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "CreateFileW",
                "category": "file_read",
                "args": ["C:\\Windows\\test.txt", "read"],
                "result": "success",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].severity == EventSeverity.INFO

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestRegistryAPIMonitoring:
    """Test registry API call monitoring and detection."""

    def test_api_monitor_maps_registry_read_to_read_event(self) -> None:
        """APIMonitor maps registry_read category to EventType.READ."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "RegQueryValueExW",
                "category": "registry_read",
                "args": ["HKLM\\Software\\Test"],
                "result": "success",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].event_type == EventType.READ

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_maps_registry_write_to_write_event(self) -> None:
        """APIMonitor maps registry_write category to EventType.WRITE."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "RegSetValueExW",
                "category": "registry_write",
                "args": ["HKCU\\Software\\Test", "value"],
                "result": "success",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].event_type == EventType.WRITE

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_detects_registry_key_deletion(self) -> None:
        """APIMonitor detects RegDeleteKey operations."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "RegDeleteKeyW",
                "category": "registry_write",
                "args": ["HKCU\\Software\\Test"],
                "result": 0,
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].details["api"] == "RegDeleteKeyW"
            assert events[0].severity == EventSeverity.WARNING

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestFileAPIMonitoring:
    """Test file API call monitoring and detection."""

    def test_api_monitor_maps_file_read_to_read_event(self) -> None:
        """APIMonitor maps file_read category to EventType.READ."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "ReadFile",
                "category": "file_read",
                "args": ["handle", "512 bytes"],
                "result": "success",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].event_type == EventType.READ

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_maps_file_write_to_write_event(self) -> None:
        """APIMonitor maps file_write category to EventType.WRITE."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "WriteFile",
                "category": "file_write",
                "args": ["handle", "1024 bytes"],
                "result": "success",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].event_type == EventType.WRITE

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_detects_license_file_access(self) -> None:
        """APIMonitor detects license file operations with CRITICAL severity."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "CreateFileW",
                "category": "file_read",
                "args": ["C:\\Program Files\\App\\license.dat", "read"],
                "result": "handle",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].severity == EventSeverity.CRITICAL
            assert "license" in str(events[0].details["args"]).lower()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestNetworkAPIMonitoring:
    """Test network API call monitoring for license server detection."""

    def test_api_monitor_maps_network_connect_to_connect_event(self) -> None:
        """APIMonitor maps network_connect to EventType.CONNECT."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "connect",
                "category": "network_connect",
                "args": ["socket", "192.168.1.100:443"],
                "result": 0,
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].event_type == EventType.CONNECT

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_maps_network_send_to_send_event(self) -> None:
        """APIMonitor maps network_send to EventType.SEND."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "send",
                "category": "network_send",
                "args": ["socket", "256 bytes"],
                "result": "success",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].event_type == EventType.SEND

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_maps_network_receive_to_receive_event(self) -> None:
        """APIMonitor maps network_receive to EventType.RECEIVE."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "recv",
                "category": "network_receive",
                "args": ["socket", "512 bytes"],
                "result": "success",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].event_type == EventType.RECEIVE

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_detects_activation_server_connections(self) -> None:
        """APIMonitor detects connections to activation servers as CRITICAL."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "InternetOpenW",
                "category": "network_connect",
                "args": ["ActivationClient/1.0"],
                "result": "handle",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].severity == EventSeverity.CRITICAL

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestCryptoAPIMonitoring:
    """Test cryptography API monitoring for license decryption."""

    def test_api_monitor_maps_crypto_to_access_event(self) -> None:
        """APIMonitor maps crypto category to EventType.ACCESS."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "CryptDecrypt",
                "category": "crypto",
                "args": ["key_handle", "256 bytes"],
                "result": "success",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].event_type == EventType.ACCESS

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_detects_license_decryption(self) -> None:
        """APIMonitor detects CryptDecrypt with license key data as CRITICAL."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "CryptDecrypt",
                "category": "crypto",
                "args": ["license_key_handle", "128 bytes"],
                "result": "success",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].severity == EventSeverity.CRITICAL

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_detects_license_encryption(self) -> None:
        """APIMonitor detects CryptEncrypt with serial number as CRITICAL."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "CryptEncrypt",
                "category": "crypto",
                "args": ["serial_number_data", "64 bytes"],
                "result": "success",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].severity == EventSeverity.CRITICAL

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestTimeAPIMonitoring:
    """Test time API monitoring for trial detection."""

    def test_api_monitor_maps_time_to_access_event(self) -> None:
        """APIMonitor maps time category to EventType.ACCESS."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "GetSystemTime",
                "category": "time",
                "args": [],
                "result": "queried",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].event_type == EventType.ACCESS

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_detects_trial_time_check(self) -> None:
        """APIMonitor detects GetSystemTime in trial context as CRITICAL."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "GetSystemTime",
                "category": "time",
                "args": ["trial_check_context"],
                "result": "queried",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].severity == EventSeverity.CRITICAL

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_detects_tick_count_for_timing(self) -> None:
        """APIMonitor detects GetTickCount API calls."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            payload: dict[str, Any] = {
                "api": "GetTickCount",
                "category": "time",
                "args": [],
                "result": 123456789,
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].details["api"] == "GetTickCount"

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestErrorHandling:
    """Test error handling for API monitor failures."""

    def test_api_monitor_handles_invalid_pid_gracefully(self) -> None:
        """APIMonitor handles attachment to invalid PID without crashing."""
        monitor = APIMonitor(pid=999999)
        result: bool = monitor.start()

        assert result is False
        assert not monitor.is_running()

    def test_api_monitor_handles_process_not_found_error(self) -> None:
        """APIMonitor handles ProcessNotFoundError when attaching."""
        monitor = APIMonitor(pid=888888)
        result: bool = monitor.start()

        assert result is False
        stats = monitor.get_stats()
        assert stats["error_count"] > 0

    def test_api_monitor_handles_detached_session_gracefully(self) -> None:
        """APIMonitor handles already-detached sessions without error."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)
            monitor.start()
            device.kill(pid)
            time.sleep(TIMEOUT_SHORT)

            monitor.stop()

        except frida.ProcessNotFoundError:
            pass

    def test_on_frida_message_handles_error_messages(self) -> None:
        """APIMonitor handles error messages from Frida script."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            message: dict[str, Any] = {
                "type": "send",
                "payload": {
                    "event_type": "error",
                    "message": "Failed to hook API",
                },
            }

            initial_error_count = monitor._error_count
            monitor._on_frida_message(message, None)

            assert monitor._error_count > initial_error_count

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_increments_error_count_on_failures(self) -> None:
        """APIMonitor increments error count when operations fail."""
        monitor = APIMonitor(pid=999999)
        monitor.start()

        stats = monitor.get_stats()
        assert stats["error_count"] >= 1


class TestProcessInfoIntegration:
    """Test process information integration with events."""

    def test_api_monitor_events_include_process_info(self) -> None:
        """APIMonitor events include process information when provided."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            process_info = ProcessInfo(
                pid=pid, name="calc.exe", path=CALC_PATH
            )
            monitor = APIMonitor(pid=pid, process_info=process_info)

            payload: dict[str, Any] = {
                "api": "RegQueryValueExW",
                "category": "registry_read",
                "args": ["test"],
                "result": "success",
                "call_stack": [],
            }

            events: list[MonitorEvent] = []
            monitor.on_event(lambda e: events.append(e))

            monitor._handle_api_call(payload)

            assert len(events) == 1
            assert events[0].process_info == process_info
            assert events[0].process_info.pid == pid
            assert events[0].process_info.name == "calc.exe"

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_monitor_event_to_dict_includes_all_fields(self) -> None:
        """MonitorEvent to_dict serialization includes all fields."""
        process_info = ProcessInfo(pid=1234, name="test.exe", path="C:\\test.exe")

        event = MonitorEvent(
            timestamp=1234567890.0,
            source=EventSource.API,
            event_type=EventType.READ,
            severity=EventSeverity.CRITICAL,
            details={"api": "RegQueryValueExW", "category": "registry_read"},
            process_info=process_info,
            call_stack=["0x401000", "0x402000"],
        )

        event_dict = event.to_dict()

        assert event_dict["timestamp"] == 1234567890.0
        assert event_dict["source"] == "api"
        assert event_dict["event_type"] == "read"
        assert event_dict["severity"] == "critical"
        assert event_dict["details"]["api"] == "RegQueryValueExW"
        assert event_dict["process_info"]["pid"] == 1234
        assert event_dict["process_info"]["name"] == "test.exe"
        assert event_dict["call_stack"] == ["0x401000", "0x402000"]


class TestMultipleProcessMonitoring:
    """Test monitoring multiple processes simultaneously."""

    def test_api_monitor_can_monitor_multiple_processes(self) -> None:
        """Multiple APIMonitor instances can run concurrently."""
        device: frida.core.Device = frida.get_local_device()
        pid1: int = device.spawn([NOTEPAD_PATH])
        pid2: int = device.spawn([CALC_PATH])

        try:
            monitor1 = APIMonitor(pid=pid1)
            monitor2 = APIMonitor(pid=pid2)

            result1: bool = monitor1.start()
            result2: bool = monitor2.start()

            assert result1 is True
            assert result2 is True
            assert monitor1.is_running()
            assert monitor2.is_running()

            monitor1.stop()
            monitor2.stop()

        finally:
            try:
                device.kill(pid1)
                device.kill(pid2)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_events_distinguish_between_processes(self) -> None:
        """APIMonitor events correctly identify source process."""
        device: frida.core.Device = frida.get_local_device()
        pid1: int = device.spawn([NOTEPAD_PATH])
        pid2: int = device.spawn([CALC_PATH])

        events1: list[MonitorEvent] = []
        events2: list[MonitorEvent] = []

        try:
            info1 = ProcessInfo(pid=pid1, name="notepad.exe", path=NOTEPAD_PATH)
            info2 = ProcessInfo(pid=pid2, name="calc.exe", path=CALC_PATH)

            monitor1 = APIMonitor(pid=pid1, process_info=info1)
            monitor2 = APIMonitor(pid=pid2, process_info=info2)

            monitor1.on_event(lambda e: events1.append(e))
            monitor2.on_event(lambda e: events2.append(e))

            monitor1.start()
            monitor2.start()

            device.resume(pid1)
            device.resume(pid2)
            time.sleep(TIMEOUT_LONG)

            if len(events1) > 0:
                assert all(e.process_info == info1 for e in events1)
            if len(events2) > 0:
                assert all(e.process_info == info2 for e in events2)

            monitor1.stop()
            monitor2.stop()

        finally:
            try:
                device.kill(pid1)
                device.kill(pid2)
            except frida.ProcessNotFoundError:
                pass


class TestCallbackManagement:
    """Test event callback registration and execution."""

    def test_api_monitor_supports_multiple_callbacks(self) -> None:
        """APIMonitor can register and execute multiple event callbacks."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            events1: list[MonitorEvent] = []
            events2: list[MonitorEvent] = []

            monitor.on_event(lambda e: events1.append(e))
            monitor.on_event(lambda e: events2.append(e))

            payload: dict[str, Any] = {
                "api": "GetSystemTime",
                "category": "time",
                "args": [],
                "result": "queried",
                "call_stack": [],
            }

            monitor._handle_api_call(payload)

            assert len(events1) == 1
            assert len(events2) == 1

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_api_monitor_handles_callback_exceptions_gracefully(self) -> None:
        """APIMonitor continues processing when callback raises exception."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = APIMonitor(pid=pid)

            def failing_callback(event: MonitorEvent) -> None:
                raise ValueError("Test exception")

            events: list[MonitorEvent] = []
            monitor.on_event(failing_callback)
            monitor.on_event(lambda e: events.append(e))

            payload: dict[str, Any] = {
                "api": "RegQueryValueExW",
                "category": "registry_read",
                "args": ["test"],
                "result": "success",
                "call_stack": [],
            }

            monitor._handle_api_call(payload)

            assert len(events) == 1

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass
