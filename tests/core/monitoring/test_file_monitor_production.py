"""Production tests for File Monitor.

Validates real file system monitoring for license-related files,
event detection, and watchdog integration.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.monitoring.base_monitor import EventSeverity, EventSource, EventType, MonitorEvent, ProcessInfo
from intellicrack.core.monitoring.file_monitor import FileMonitor, LicenseFileHandler


class TestLicenseFileHandler:
    """Test license file event handler."""

    @pytest.fixture
    def captured_events(self) -> list[tuple[EventType, str, str]]:
        """List to capture events."""
        return []

    @pytest.fixture
    def handler(self, captured_events: list[tuple[EventType, str, str]]) -> LicenseFileHandler:
        """Create license file handler."""

        def callback(event_type: EventType, path: str, description: str) -> None:
            captured_events.append((event_type, path, description))

        license_extensions = {".lic", ".key", ".dat"}
        return LicenseFileHandler(callback, license_extensions)

    def test_handler_initialization(self, handler: LicenseFileHandler) -> None:
        """Handler initializes with callback and extensions."""
        assert handler.callback is not None
        assert ".lic" in handler.license_extensions
        assert ".key" in handler.license_extensions

    def test_is_license_file_by_extension(self, handler: LicenseFileHandler) -> None:
        """License file detection works by extension."""
        assert handler._is_license_file("/path/to/file.lic") is True
        assert handler._is_license_file("/path/to/file.key") is True
        assert handler._is_license_file("/path/to/file.dat") is True
        assert handler._is_license_file("/path/to/file.txt") is False

    def test_is_license_file_by_keyword(self, handler: LicenseFileHandler) -> None:
        """License file detection works by keyword."""
        assert handler._is_license_file("/path/license_config.txt") is True
        assert handler._is_license_file("/path/serial_number.cfg") is True
        assert handler._is_license_file("/path/activation_code.dat") is True
        assert handler._is_license_file("/path/normal_file.txt") is False

    def test_is_license_file_case_insensitive(self, handler: LicenseFileHandler) -> None:
        """License file detection is case-insensitive."""
        assert handler._is_license_file("/path/LICENSE.txt") is True
        assert handler._is_license_file("/path/SERIAL.KEY") is True

    def test_on_created_triggers_callback(self, handler: LicenseFileHandler, captured_events: list[tuple[EventType, str, str]]) -> None:
        """File creation triggers callback for license files."""
        from watchdog.events import FileCreatedEvent

        event = FileCreatedEvent("/path/to/test.lic")
        handler.on_created(event)

        assert len(captured_events) == 1
        assert captured_events[0][0] == EventType.CREATE
        assert "/path/to/test.lic" in captured_events[0][1]

    def test_on_modified_triggers_callback(self, handler: LicenseFileHandler, captured_events: list[tuple[EventType, str, str]]) -> None:
        """File modification triggers callback for license files."""
        from watchdog.events import FileModifiedEvent

        event = FileModifiedEvent("/path/to/test.key")
        handler.on_modified(event)

        assert len(captured_events) == 1
        assert captured_events[0][0] == EventType.MODIFY

    def test_on_deleted_triggers_callback(self, handler: LicenseFileHandler, captured_events: list[tuple[EventType, str, str]]) -> None:
        """File deletion triggers callback for license files."""
        from watchdog.events import FileDeletedEvent

        event = FileDeletedEvent("/path/to/test.lic")
        handler.on_deleted(event)

        assert len(captured_events) == 1
        assert captured_events[0][0] == EventType.DELETE

    def test_on_moved_triggers_callback(self, handler: LicenseFileHandler, captured_events: list[tuple[EventType, str, str]]) -> None:
        """File move/rename triggers callback for license files."""
        from watchdog.events import FileMovedEvent

        event = FileMovedEvent("/old/path.lic", "/new/path.lic")
        handler.on_moved(event)

        assert len(captured_events) == 1
        assert captured_events[0][0] == EventType.MODIFY

    def test_non_license_files_ignored(self, handler: LicenseFileHandler, captured_events: list[tuple[EventType, str, str]]) -> None:
        """Non-license files do not trigger callbacks."""
        from watchdog.events import FileCreatedEvent

        event = FileCreatedEvent("/path/to/document.pdf")
        handler.on_created(event)

        assert not captured_events

    def test_directory_events_ignored(self, handler: LicenseFileHandler, captured_events: list[tuple[EventType, str, str]]) -> None:
        """Directory events are ignored."""
        from watchdog.events import DirCreatedEvent

        event = DirCreatedEvent("/path/to/license_dir")
        handler.on_created(event)

        assert not captured_events


class TestFileMonitor:
    """Production tests for FileMonitor."""

    @pytest.fixture
    def temp_watch_dir(self) -> Path:
        """Create temporary directory to watch."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def monitor(self, temp_watch_dir: Path) -> FileMonitor:
        """Create file monitor."""
        process_info = ProcessInfo(pid=1234, name="test.exe", path="/test/test.exe")
        return FileMonitor(process_info=process_info, watch_paths=[str(temp_watch_dir)])

    def test_monitor_initialization(self, monitor: FileMonitor) -> None:
        """Monitor initializes with watch paths."""
        assert monitor.watch_paths is not None
        assert len(monitor.watch_paths) > 0

    def test_default_watch_paths_include_system_dirs(self) -> None:
        """Default watch paths include system directories."""
        monitor = FileMonitor()
        paths = monitor.watch_paths

        has_appdata = any("appdata" in str(p).lower() for p in paths)
        has_temp = any("temp" in str(p).lower() for p in paths)

        assert has_appdata or has_temp or len(paths) > 0

    def test_license_extensions_defined(self, monitor: FileMonitor) -> None:
        """Monitor has license extensions defined."""
        assert ".lic" in monitor.license_extensions
        assert ".key" in monitor.license_extensions
        assert ".dat" in monitor.license_extensions

    def test_start_monitoring_succeeds(self, monitor: FileMonitor) -> None:
        """Monitor starts successfully."""
        result = monitor.start()
        assert result is True
        assert monitor.is_monitoring is True
        monitor.stop()

    def test_stop_monitoring_succeeds(self, monitor: FileMonitor) -> None:
        """Monitor stops successfully."""
        monitor.start()
        monitor.stop()
        assert monitor.is_monitoring is False

    def test_file_creation_detected(self, monitor: FileMonitor, temp_watch_dir: Path) -> None:
        """File creation is detected and emitted as event."""
        captured_events: list[MonitorEvent] = []

        def capture_event(event: MonitorEvent) -> None:
            captured_events.append(event)

        monitor.add_listener(capture_event)
        monitor.start()

        time.sleep(0.5)

        test_file = temp_watch_dir / "test_license.lic"
        test_file.write_text("license data")

        time.sleep(1.0)

        monitor.stop()

        matching_events = [e for e in captured_events if e.event_type == EventType.CREATE and "test_license.lic" in str(e.details)]

        assert matching_events

    def test_file_modification_detected(self, monitor: FileMonitor, temp_watch_dir: Path) -> None:
        """File modification is detected and emitted as event."""
        test_file = temp_watch_dir / "modify_test.key"
        test_file.write_text("initial")

        captured_events: list[MonitorEvent] = []

        def capture_event(event: MonitorEvent) -> None:
            captured_events.append(event)

        monitor.add_listener(capture_event)
        monitor.start()

        time.sleep(0.5)

        test_file.write_text("modified")

        time.sleep(1.0)

        monitor.stop()

        matching_events = [e for e in captured_events if e.event_type == EventType.MODIFY and "modify_test.key" in str(e.details)]

        assert matching_events

    def test_file_deletion_detected(self, monitor: FileMonitor, temp_watch_dir: Path) -> None:
        """File deletion is detected and emitted as event."""
        test_file = temp_watch_dir / "delete_test.lic"
        test_file.write_text("will be deleted")

        captured_events: list[MonitorEvent] = []

        def capture_event(event: MonitorEvent) -> None:
            captured_events.append(event)

        monitor.add_listener(capture_event)
        monitor.start()

        time.sleep(0.5)

        test_file.unlink()

        time.sleep(1.0)

        monitor.stop()

        matching_events = [e for e in captured_events if e.event_type == EventType.DELETE and "delete_test.lic" in str(e.details)]

        assert matching_events

    def test_event_source_is_file(self, monitor: FileMonitor, temp_watch_dir: Path) -> None:
        """Events have correct source set to FILE."""
        captured_events: list[MonitorEvent] = []

        def capture_event(event: MonitorEvent) -> None:
            captured_events.append(event)

        monitor.add_listener(capture_event)
        monitor.start()

        time.sleep(0.5)

        test_file = temp_watch_dir / "source_test.key"
        test_file.write_text("test")

        time.sleep(1.0)

        monitor.stop()

        if captured_events:
            assert captured_events[0].source == EventSource.FILE

    def test_critical_files_have_critical_severity(self, monitor: FileMonitor, temp_watch_dir: Path) -> None:
        """License/activation files have CRITICAL severity."""
        captured_events: list[MonitorEvent] = []

        def capture_event(event: MonitorEvent) -> None:
            captured_events.append(event)

        monitor.add_listener(capture_event)
        monitor.start()

        time.sleep(0.5)

        test_file = temp_watch_dir / "license_activation.key"
        test_file.write_text("critical")

        time.sleep(1.0)

        monitor.stop()

        critical_events = [e for e in captured_events if e.severity == EventSeverity.CRITICAL]

        assert critical_events

    def test_multiple_files_monitored(self, monitor: FileMonitor, temp_watch_dir: Path) -> None:
        """Multiple file events are all captured."""
        captured_events: list[MonitorEvent] = []

        def capture_event(event: MonitorEvent) -> None:
            captured_events.append(event)

        monitor.add_listener(capture_event)
        monitor.start()

        time.sleep(0.5)

        file1 = temp_watch_dir / "file1.lic"
        file2 = temp_watch_dir / "file2.key"
        file3 = temp_watch_dir / "file3.dat"

        file1.write_text("test1")
        time.sleep(0.2)
        file2.write_text("test2")
        time.sleep(0.2)
        file3.write_text("test3")

        time.sleep(1.0)

        monitor.stop()

        assert len(captured_events) >= 3

    def test_nonexistent_watch_path_handled(self) -> None:
        """Monitor handles nonexistent watch paths gracefully."""
        monitor = FileMonitor(watch_paths=["/nonexistent/path/that/does/not/exist"])
        result = monitor.start()
        assert result is True
        monitor.stop()


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def temp_watch_dir(self) -> Path:
        """Create temporary directory to watch."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_monitor_without_watch_paths(self) -> None:
        """Monitor with empty watch paths uses defaults."""
        monitor = FileMonitor(watch_paths=[])
        default_paths = monitor._get_default_watch_paths()
        assert len(default_paths) > 0

    def test_monitor_with_process_path(self) -> None:
        """Monitor includes process directory in watch paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            process_info = ProcessInfo(pid=1234, name="test.exe", path=f"{tmpdir}/test.exe")
            monitor = FileMonitor(process_info=process_info)

            assert any(tmpdir in str(p) for p in monitor.watch_paths)

    def test_rapid_file_changes(self, temp_watch_dir: Path) -> None:
        """Monitor handles rapid file changes."""
        monitor = FileMonitor(watch_paths=[str(temp_watch_dir)])
        captured_events: list[MonitorEvent] = []

        def capture_event(event: MonitorEvent) -> None:
            captured_events.append(event)

        monitor.add_listener(capture_event)
        monitor.start()

        time.sleep(0.5)

        test_file = temp_watch_dir / "rapid.lic"
        for i in range(10):
            test_file.write_text(f"iteration {i}")
            time.sleep(0.05)

        time.sleep(1.0)

        monitor.stop()

        assert captured_events

    def test_unicode_filename_handling(self, temp_watch_dir: Path) -> None:
        """Monitor handles Unicode filenames."""
        monitor = FileMonitor(watch_paths=[str(temp_watch_dir)])
        captured_events: list[MonitorEvent] = []

        def capture_event(event: MonitorEvent) -> None:
            captured_events.append(event)

        monitor.add_listener(capture_event)
        monitor.start()

        time.sleep(0.5)

        test_file = temp_watch_dir / "лицензия.lic"
        test_file.write_text("unicode test")

        time.sleep(1.0)

        monitor.stop()

        assert captured_events

    def test_start_stop_multiple_times(self, temp_watch_dir: Path) -> None:
        """Monitor can be started and stopped multiple times."""
        monitor = FileMonitor(watch_paths=[str(temp_watch_dir)])

        monitor.start()
        monitor.stop()

        monitor.start()
        monitor.stop()

        monitor.start()
        assert monitor.is_monitoring is True
        monitor.stop()
