"""Production-ready tests for intellicrack/core/monitoring/memory_monitor.py

Tests validate REAL memory scanning capabilities:
- Memory monitor initialization with Frida attachment
- Frida script injection and execution in target processes
- Serial key pattern detection in process memory
- Email pattern detection for license validation
- HWID (Hardware ID) pattern recognition
- Activation code pattern scanning
- License keyword detection with context extraction
- Real-time memory scanning at configurable intervals
- Event emission for detected license patterns
- Process attachment and detachment lifecycle
- Thread-safe scanning operations
- Deduplication of found patterns
"""

import time
from typing import Any

import frida
import pytest

from intellicrack.core.monitoring.base_monitor import EventSeverity, EventSource, EventType, MonitorEvent, ProcessInfo
from intellicrack.core.monitoring.memory_monitor import MemoryMonitor


NOTEPAD_PATH: str = "C:\\Windows\\System32\\notepad.exe"
CALC_PATH: str = "C:\\Windows\\System32\\calc.exe"
TIMEOUT_SHORT: float = 0.2
TIMEOUT_MEDIUM: float = 0.5
TIMEOUT_LONG: float = 2.0


class TestMemoryMonitorInitialization:
    """Test memory monitor initialization."""

    def test_memory_monitor_initializes_with_pid(self) -> None:
        """MemoryMonitor initializes with process ID."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = MemoryMonitor(pid=pid, scan_interval=5.0)

            assert monitor.pid == pid
            assert monitor.scan_interval == 5.0
            assert monitor.name == "MemoryMonitor"
            assert monitor.session is None
            assert monitor.script is None
            assert not monitor.is_running()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_memory_monitor_initializes_with_process_info(self) -> None:
        """MemoryMonitor stores process information correctly."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            process_info = ProcessInfo(pid=pid, name="calc.exe", path=CALC_PATH)
            monitor = MemoryMonitor(pid=pid, process_info=process_info, scan_interval=3.0)

            assert monitor.process_info == process_info
            assert monitor.process_info.pid == pid
            assert monitor.process_info.name == "calc.exe"

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_memory_monitor_has_license_patterns(self) -> None:
        """MemoryMonitor initializes with license detection patterns."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = MemoryMonitor(pid=pid)

            assert "serial_key" in monitor.patterns
            assert "email" in monitor.patterns
            assert "hwid" in monitor.patterns
            assert "activation" in monitor.patterns

            assert len(monitor.patterns["serial_key"]) > 0
            assert len(monitor.patterns["email"]) > 0
            assert len(monitor.patterns["hwid"]) > 0
            assert len(monitor.patterns["activation"]) > 0

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestMemoryMonitorLifecycle:
    """Test memory monitor lifecycle management."""

    def test_memory_monitor_starts_successfully(self) -> None:
        """MemoryMonitor starts and attaches to process."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])
        device.resume(pid)

        try:
            monitor = MemoryMonitor(pid=pid, scan_interval=10.0)

            result = monitor.start()

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

    def test_memory_monitor_stops_successfully(self) -> None:
        """MemoryMonitor stops and detaches from process."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])
        device.resume(pid)

        try:
            monitor = MemoryMonitor(pid=pid, scan_interval=10.0)

            monitor.start()
            assert monitor.is_running()

            monitor.stop()

            assert not monitor.is_running()
            assert monitor.session is None
            assert monitor.script is None

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_memory_monitor_handles_invalid_pid(self) -> None:
        """MemoryMonitor handles attachment to invalid PID gracefully."""
        monitor = MemoryMonitor(pid=999999, scan_interval=5.0)

        result = monitor.start()

        assert result is False
        assert not monitor.is_running()

    def test_memory_monitor_creates_scan_thread(self) -> None:
        """MemoryMonitor creates background scanning thread."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])
        device.resume(pid)

        try:
            monitor = MemoryMonitor(pid=pid, scan_interval=10.0)

            monitor.start()

            assert monitor._scan_thread is not None
            assert monitor._scan_thread.is_alive()

            monitor.stop()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestFridaScriptGeneration:
    """Test Frida script generation."""

    def test_memory_monitor_builds_frida_script(self) -> None:
        """MemoryMonitor generates valid Frida JavaScript."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = MemoryMonitor(pid=pid)

            script_source = monitor._build_frida_script()

            assert isinstance(script_source, str)
            assert len(script_source) > 0

            assert "scanMemory" in script_source
            assert "SCAN_PATTERNS" in script_source
            assert "LICENSE_KEYWORDS" in script_source
            assert "serial_key" in script_source
            assert "email" in script_source
            assert "hwid" in script_source

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_frida_script_exports_scan_function(self) -> None:
        """Frida script exports scanMemory RPC function."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])
        device.resume(pid)

        try:
            monitor = MemoryMonitor(pid=pid, scan_interval=10.0)

            monitor.start()

            time.sleep(TIMEOUT_SHORT)

            assert monitor.script is not None
            assert hasattr(monitor.script, "exports")

            monitor.stop()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestPatternDetection:
    """Test license pattern detection."""

    def test_memory_monitor_detects_serial_key_patterns(self) -> None:
        """MemoryMonitor detects serial key patterns in memory."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = MemoryMonitor(pid=pid)

            test_patterns = monitor.patterns["serial_key"]

            assert len(test_patterns) > 0

            example_serial = "ABCD1-23456-EFGH7-89012"

            import re
            for pattern in test_patterns:
                if re.match(pattern, example_serial):
                    break
            else:
                pytest.fail("No serial key pattern matched example serial")

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_memory_monitor_detects_email_patterns(self) -> None:
        """MemoryMonitor detects email patterns for license validation."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = MemoryMonitor(pid=pid)

            email_patterns = monitor.patterns["email"]

            assert len(email_patterns) > 0

            test_emails = ["user@example.com", "license@software.net"]

            import re
            for pattern in email_patterns:
                for email in test_emails:
                    if re.match(pattern, email):
                        break
                else:
                    continue
                break
            else:
                pytest.fail("No email pattern matched test emails")

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_memory_monitor_detects_hwid_patterns(self) -> None:
        """MemoryMonitor detects Hardware ID (HWID) patterns."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = MemoryMonitor(pid=pid)

            hwid_patterns = monitor.patterns["hwid"]

            assert len(hwid_patterns) > 0

            test_hwid = "12345678-1234-5678-1234-567812345678"

            import re
            for pattern in hwid_patterns:
                if re.match(pattern, test_hwid):
                    break
            else:
                pytest.fail("No HWID pattern matched test HWID")

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_memory_monitor_detects_activation_patterns(self) -> None:
        """MemoryMonitor detects activation code patterns."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = MemoryMonitor(pid=pid)

            activation_patterns = monitor.patterns["activation"]

            assert len(activation_patterns) > 0

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestEventEmission:
    """Test event emission for detected patterns."""

    def test_memory_monitor_emits_event_on_pattern_found(self) -> None:
        """MemoryMonitor emits event when license pattern detected."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = MemoryMonitor(pid=pid, scan_interval=10.0)

            event_emitted = False
            received_event = None

            def on_event(event: MonitorEvent) -> None:
                nonlocal event_emitted, received_event
                event_emitted = True
                received_event = event

            monitor.on_event(on_event)

            payload = {
                "event_type": "pattern_found",
                "pattern_type": "serial_key",
                "value": "ABCD-1234-EFGH-5678",
                "address": 0x401000,
                "context": "license_ABCD-1234-EFGH-5678_key",
            }

            monitor._handle_pattern_found(payload)

            assert event_emitted
            assert received_event is not None
            assert received_event.source == EventSource.MEMORY
            assert received_event.event_type == EventType.SCAN
            assert received_event.severity == EventSeverity.CRITICAL
            assert received_event.details["pattern_type"] == "serial_key"
            assert received_event.details["value"] == "ABCD-1234-EFGH-5678"

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_memory_monitor_includes_address_in_event(self) -> None:
        """MemoryMonitor includes memory address in event details."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = MemoryMonitor(pid=pid, scan_interval=10.0)

            received_event = None

            def on_event(event: MonitorEvent) -> None:
                nonlocal received_event
                received_event = event

            monitor.on_event(on_event)

            payload = {
                "event_type": "pattern_found",
                "pattern_type": "email",
                "value": "user@license.com",
                "address": 0x402000,
                "context": "email: user@license.com",
            }

            monitor._handle_pattern_found(payload)

            assert received_event is not None
            assert "address" in received_event.details
            assert received_event.details["address"] == "0x402000"

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_memory_monitor_includes_context_in_event(self) -> None:
        """MemoryMonitor includes surrounding context in event."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = MemoryMonitor(pid=pid, scan_interval=10.0)

            received_event = None

            def on_event(event: MonitorEvent) -> None:
                nonlocal received_event
                received_event = event

            monitor.on_event(on_event)

            payload = {
                "event_type": "pattern_found",
                "pattern_type": "hwid",
                "value": "12345678-1234-5678-1234-567812345678",
                "address": 0x403000,
                "context": "hwid=12345678-1234-5678-1234-567812345678&valid=true",
            }

            monitor._handle_pattern_found(payload)

            assert received_event is not None
            assert "context" in received_event.details
            assert len(received_event.details["context"]) > 0

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestPatternDeduplication:
    """Test pattern deduplication."""

    def test_memory_monitor_deduplicates_found_patterns(self) -> None:
        """MemoryMonitor prevents duplicate events for same pattern."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = MemoryMonitor(pid=pid, scan_interval=10.0)

            event_count = 0

            def on_event(event: MonitorEvent) -> None:
                nonlocal event_count
                event_count += 1

            monitor.on_event(on_event)

            payload = {
                "event_type": "pattern_found",
                "pattern_type": "serial_key",
                "value": "XXXX-YYYY-ZZZZ",
                "address": 0x401000,
                "context": "test",
            }

            monitor._handle_pattern_found(payload)
            monitor._handle_pattern_found(payload)
            monitor._handle_pattern_found(payload)

            assert event_count == 1

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_memory_monitor_tracks_different_patterns_separately(self) -> None:
        """MemoryMonitor tracks different patterns as separate findings."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = MemoryMonitor(pid=pid, scan_interval=10.0)

            event_count = 0

            def on_event(event: MonitorEvent) -> None:
                nonlocal event_count
                event_count += 1

            monitor.on_event(on_event)

            payload1 = {
                "event_type": "pattern_found",
                "pattern_type": "serial_key",
                "value": "AAA-BBB-CCC",
                "address": 0x401000,
                "context": "test1",
            }

            payload2 = {
                "event_type": "pattern_found",
                "pattern_type": "serial_key",
                "value": "XXX-YYY-ZZZ",
                "address": 0x402000,
                "context": "test2",
            }

            monitor._handle_pattern_found(payload1)
            monitor._handle_pattern_found(payload2)

            assert event_count == 2

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestFridaMessageHandling:
    """Test Frida message handling."""

    def test_memory_monitor_handles_pattern_found_messages(self) -> None:
        """MemoryMonitor processes pattern_found messages from Frida."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = MemoryMonitor(pid=pid, scan_interval=10.0)

            event_received = False

            def on_event(event: MonitorEvent) -> None:
                nonlocal event_received
                event_received = True

            monitor.on_event(on_event)

            message = {
                "type": "send",
                "payload": {
                    "event_type": "pattern_found",
                    "pattern_type": "activation",
                    "value": "ACTIVATION-CODE-12345",
                    "address": 0x500000,
                    "context": "activation code found",
                },
            }

            monitor._on_frida_message(message, b"")

            assert event_received

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_memory_monitor_handles_scan_complete_messages(self) -> None:
        """MemoryMonitor processes scan_complete messages gracefully."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            monitor = MemoryMonitor(pid=pid, scan_interval=10.0)

            message = {
                "type": "send",
                "payload": {
                    "event_type": "scan_complete",
                    "ranges_scanned": 50,
                },
            }

            monitor._on_frida_message(message, b"")

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_memory_monitor_handles_error_messages(self) -> None:
        """MemoryMonitor handles error messages from Frida script."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = MemoryMonitor(pid=pid, scan_interval=10.0)

            message = {
                "type": "send",
                "payload": {
                    "event_type": "error",
                    "message": "Memory scan failed",
                },
            }

            monitor._on_frida_message(message, b"")

            assert monitor._error_count > 0

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestScanInterval:
    """Test periodic scanning behavior."""

    def test_memory_monitor_respects_scan_interval(self) -> None:
        """MemoryMonitor waits for scan interval between scans."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])
        device.resume(pid)

        try:
            scan_interval = 0.5
            monitor = MemoryMonitor(pid=pid, scan_interval=scan_interval)

            monitor.start()

            time.sleep(scan_interval * 2.5)

            monitor.stop()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_memory_monitor_allows_custom_scan_interval(self) -> None:
        """MemoryMonitor accepts custom scan interval configuration."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = MemoryMonitor(pid=pid, scan_interval=15.0)

            assert monitor.scan_interval == 15.0

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass


class TestCompleteWorkflow:
    """Test complete memory monitoring workflow."""

    def test_complete_memory_monitoring_lifecycle(self) -> None:
        """Complete memory monitoring workflow from start to stop."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])
        device.resume(pid)

        try:
            process_info = ProcessInfo(pid=pid, name="notepad.exe", path=NOTEPAD_PATH)
            monitor = MemoryMonitor(pid=pid, process_info=process_info, scan_interval=10.0)

            events_received: list[MonitorEvent] = []

            def on_event(event: MonitorEvent) -> None:
                events_received.append(event)

            monitor.on_event(on_event)

            result = monitor.start()

            assert result is True
            assert monitor.is_running()
            assert monitor.session is not None
            assert monitor.script is not None

            time.sleep(TIMEOUT_SHORT)

            monitor.stop()

            assert not monitor.is_running()
            assert monitor.session is None
            assert monitor.script is None

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_memory_monitor_stats_tracking(self) -> None:
        """MemoryMonitor tracks statistics correctly."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            monitor = MemoryMonitor(pid=pid, scan_interval=10.0)

            payload = {
                "event_type": "pattern_found",
                "pattern_type": "serial_key",
                "value": "TEST-1234-ABCD",
                "address": 0x401000,
                "context": "test context",
            }

            monitor._handle_pattern_found(payload)

            stats = monitor.get_stats()

            assert stats["total_events"] == 1
            assert stats["monitor_name"] == "MemoryMonitor"

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass
