"""File System Monitor using watchdog library.

Monitors file system for license-related file operations:
.lic, .key, .dat, .cfg, and other licensing files.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from intellicrack.core.monitoring.base_monitor import BaseMonitor, EventSeverity, EventSource, EventType, MonitorEvent, ProcessInfo


class LicenseFileHandler(FileSystemEventHandler):
    """File system event handler for license-related files."""

    def __init__(
        self,
        callback: Callable[[Any, str, str], None],
        license_extensions: set[str],
    ) -> None:
        """Initialize file handler.

        Args:
            callback: Function to call on license file events.
            license_extensions: Set of file extensions to monitor.

        """
        super().__init__()
        self.callback: Callable[[Any, str, str], None] = callback
        self.license_extensions: set[str] = license_extensions
        self.license_keywords: set[str] = {
            "license",
            "licence",
            "serial",
            "key",
            "activation",
            "register",
            "trial",
            "crack",
            "patch",
            ".lic",
            ".key",
        }

    def _is_license_file(self, path: str) -> bool:
        """Check if file is license-related.

        Args:
            path: File path to check.

        Returns:
            True if file is license-related.

        """
        path_lower = path.lower()

        if any(ext in path_lower for ext in self.license_extensions):
            return True

        return any(keyword in path_lower for keyword in self.license_keywords)

    def on_created(self, event: FileSystemEvent) -> None:
        """Handle file creation.

        Args:
            event: File system event.

        """
        if not event.is_directory and self._is_license_file(event.src_path):
            self.callback(EventType.CREATE, event.src_path, "file_created")

    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle file modification.

        Args:
            event: File system event.

        """
        if not event.is_directory and self._is_license_file(event.src_path):
            self.callback(EventType.MODIFY, event.src_path, "file_modified")

    def on_deleted(self, event: FileSystemEvent) -> None:
        """Handle file deletion.

        Args:
            event: File system event.

        """
        if not event.is_directory and self._is_license_file(event.src_path):
            self.callback(EventType.DELETE, event.src_path, "file_deleted")

    def on_moved(self, event: FileSystemEvent) -> None:
        """Handle file move/rename.

        Args:
            event: File system event.

        """
        if not event.is_directory and (
            self._is_license_file(event.src_path) or self._is_license_file(event.dest_path)
        ):
            self.callback(EventType.MODIFY, f"{event.src_path} -> {event.dest_path}", "file_moved")


class FileMonitor(BaseMonitor):
    """File system monitoring for license-related files.

    Uses watchdog library to monitor directories for license file operations.
    Complementary to API monitor's file API hooks.
    """

    def __init__(
        self,
        process_info: ProcessInfo | None = None,
        watch_paths: list[str] | None = None,
    ) -> None:
        """Initialize file monitor.

        Args:
            process_info: Process information.
            watch_paths: Specific paths to watch (defaults to common license locations).

        """
        super().__init__("FileMonitor", process_info)
        self.observer: Observer | None = None
        self.watch_paths: list[str] = watch_paths or self._get_default_watch_paths()
        self.license_extensions: set[str] = {
            ".lic",
            ".key",
            ".dat",
            ".cfg",
            ".reg",
            ".ini",
            ".license",
            ".licence",
            ".serial",
            ".activation",
        }

    def _get_default_watch_paths(self) -> list[str]:
        """Get default paths to monitor.

        Returns:
            List of paths to watch.

        """
        paths = []

        if appdata := os.getenv("APPDATA"):
            paths.append(appdata)

        if programdata := os.getenv("PROGRAMDATA"):
            paths.append(programdata)

        if localappdata := os.getenv("LOCALAPPDATA"):
            paths.append(localappdata)

        if temp := os.getenv("TEMP"):
            paths.append(temp)

        if self.process_info and self.process_info.path:
            try:
                exe_dir = str(Path(self.process_info.path).parent)
                if os.path.exists(exe_dir):
                    paths.append(exe_dir)
            except Exception as e:
                print(f"[FileMonitor] Error getting process directory: {e}")

        return [p for p in paths if os.path.exists(p)]

    def _start_monitoring(self) -> bool:
        """Start file monitoring.

        Returns:
            True if started successfully.

        """
        try:
            self.observer = Observer()

            event_handler = LicenseFileHandler(self._on_file_event, self.license_extensions)

            for path in self.watch_paths:
                try:
                    if os.path.exists(path):
                        self.observer.schedule(event_handler, path, recursive=True)
                except Exception as e:
                    print(f"[FileMonitor] Failed to watch {path}: {e}")

            self.observer.start()
            return True

        except Exception as e:
            return not self._handle_error(e)

    def _stop_monitoring(self) -> None:
        """Stop file monitoring."""
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=2.0)
            except Exception as e:
                print(f"[FileMonitor] Error stopping observer: {e}")
            self.observer = None

    def _on_file_event(self, event_type: EventType, path: str, description: str) -> None:
        """Handle file system event.

        Args:
            event_type: Type of event.
            path: File path.
            description: Event description.

        """
        severity = EventSeverity.WARNING
        if any(keyword in path.lower() for keyword in ["license", "serial", "key", "activation"]):
            severity = EventSeverity.CRITICAL

        event = MonitorEvent(
            timestamp=time.time(),
            source=EventSource.FILE,
            event_type=event_type,
            severity=severity,
            details={
                "file_path": path,
                "operation": description,
                "file_name": os.path.basename(path),
            },
            process_info=self.process_info,
        )

        self._emit_event(event)
