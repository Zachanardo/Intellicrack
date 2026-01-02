#!/usr/bin/env python3
"""Dashboard Manager for Intellicrack application.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import datetime
import logging
import os
from pathlib import Path
from typing import Any

from ..utils.logger import log_all_methods


@log_all_methods
class DashboardManager:
    """Comprehensive dashboard manager with project statistics and activity tracking.

    This class manages the dashboard UI, providing an intuitive interface with
    project statistics, recent activities, and quick access to common functions.
    Supports real-time updates and comprehensive monitoring of application state.

    Attributes:
        app: Reference to the main application instance.
        logger: Logger instance for dashboard operations.
        stats: Dictionary containing current dashboard statistics.
        recent_activities: List of recent activities with timestamps.
        max_recent_activities: Maximum number of recent activities to retain.

    """

    def __init__(self, app: object) -> None:
        """Initialize the dashboard manager with the main application instance.

        Args:
            app: Main application instance for accessing application state.

        """
        self.app: Any = app
        self.logger: logging.Logger = logging.getLogger(__name__)
        self.stats: dict[str, Any] = {}
        self.recent_activities: list[dict[str, str]] = []
        self.max_recent_activities: int = 20

    def update_stats(self) -> None:
        """Update all dashboard statistics.

        Calls individual update methods to refresh binary, patch, analysis,
        license, and advanced analysis statistics in the stats dictionary.
        """
        if not hasattr(self, "stats"):
            self.stats = {}

        self._update_binary_stats()
        self._update_patch_stats()
        self._update_analysis_stats()
        self._update_license_stats()
        self._update_advanced_analysis_stats()

    def _update_binary_stats(self) -> None:
        """Update binary file statistics.

        Gathers information about the currently loaded binary file including
        size, path, and last modified timestamp. Updates stats dictionary.
        """
        if hasattr(self.app, "binary_path") and self.app.binary_path and os.path.exists(self.app.binary_path):
            try:
                binary_size: int = os.path.getsize(self.app.binary_path)
                binary_name: str = os.path.basename(self.app.binary_path)
                last_modified: float = Path(self.app.binary_path).stat().st_mtime

                self.stats["binary"] = {
                    "name": binary_name,
                    "path": self.app.binary_path,
                    "size": binary_size,
                    "size_formatted": self._format_size(binary_size),
                    "last_modified": datetime.datetime.fromtimestamp(last_modified).strftime("%Y-%m-%d %H:%M:%S"),
                }
            except (OSError, ValueError):
                self.logger.exception("Failed to update binary stats.")
                self.stats["binary"] = None
        else:
            self.stats["binary"] = None

    def _update_patch_stats(self) -> None:
        """Update binary patching statistics.

        Tracks information about applied patches and modifications to binaries.
        """
        applied_count = 0
        pending_count = 0
        last_patch_time: str | None = None

        if hasattr(self.app, "patches") and isinstance(self.app.patches, list):
            applied_count = len(self.app.patches)

        if hasattr(self.app, "potential_patches") and isinstance(self.app.potential_patches, list):
            pending_count = len(self.app.potential_patches)

        patch_activities = [
            a for a in self.recent_activities
            if a.get("type", "").lower() in {"patch", "patching", "binary_patch"}
        ]
        if patch_activities:
            last_patch_time = patch_activities[0].get("timestamp")

        self.stats["patches"] = {
            "applied_count": applied_count,
            "pending_count": pending_count,
            "last_patch_time": last_patch_time,
        }

    def _update_analysis_stats(self) -> None:
        """Update analysis operation statistics.

        Tracks metrics related to analysis operations including number of files
        analyzed and analysis timestamps.
        """
        analysis_types = ("analysis", "analyze", "scan", "detection", "protection")
        analysis_activities = [
            a for a in self.recent_activities
            if any(t in a.get("type", "").lower() for t in analysis_types)
        ]
        total_analyses = len(analysis_activities)

        recent_analysis_time: str | None = None
        if analysis_activities:
            recent_analysis_time = analysis_activities[0].get("timestamp")

        protection_activities = [
            a for a in self.recent_activities
            if "protection" in a.get("type", "").lower() or "detect" in a.get("description", "").lower()
        ]
        protection_detections = len(protection_activities)

        if hasattr(self.app, "analysis_count"):
            total_analyses = max(total_analyses, int(self.app.analysis_count))

        self.stats["analysis"] = {
            "total_analyses": total_analyses,
            "recent_analysis_time": recent_analysis_time,
            "protection_detections": protection_detections,
        }

    def _update_license_stats(self) -> None:
        """Update license-related statistics.

        Tracks information about license validations, serials generated, and
        licensing protection analysis.
        """
        license_types = ("license", "validation", "serial", "keygen", "activation")
        license_activities = [
            a for a in self.recent_activities
            if any(t in a.get("type", "").lower() for t in license_types)
        ]

        validations_performed = sum(
            1 for a in license_activities
            if "validation" in a.get("type", "").lower() or "validate" in a.get("description", "").lower()
        )

        serials_generated = sum(
            1 for a in license_activities
            if any(s in a.get("type", "").lower() for s in ("serial", "keygen"))
            or "generated" in a.get("description", "").lower()
        )

        last_validation_time: str | None = None
        validation_activities = [
            a for a in license_activities
            if "validation" in a.get("type", "").lower()
        ]
        if validation_activities:
            last_validation_time = validation_activities[0].get("timestamp")

        if hasattr(self.app, "serial_count"):
            serials_generated = max(serials_generated, int(self.app.serial_count))

        self.stats["licensing"] = {
            "validations_performed": validations_performed,
            "serials_generated": serials_generated,
            "last_validation_time": last_validation_time,
        }

    def _update_advanced_analysis_stats(self) -> None:
        """Update advanced analysis statistics.

        Tracks metrics for advanced analysis features including dynamic analysis,
        vulnerability detection, and exploitation attempts.
        """
        dynamic_types = ("dynamic", "runtime", "frida", "debug", "trace")
        dynamic_activities = [
            a for a in self.recent_activities
            if any(t in a.get("type", "").lower() for t in dynamic_types)
        ]
        dynamic_analyses = len(dynamic_activities)

        vuln_types = ("vulnerability", "vuln", "cve", "weakness", "flaw")
        vuln_activities = [
            a for a in self.recent_activities
            if any(t in a.get("type", "").lower() for t in vuln_types)
            or any(t in a.get("description", "").lower() for t in vuln_types)
        ]
        vulnerabilities_found = len(vuln_activities)

        exploit_types = ("exploit", "payload", "rop", "shellcode", "bypass")
        exploit_activities = [
            a for a in self.recent_activities
            if any(t in a.get("type", "").lower() for t in exploit_types)
        ]
        exploits_generated = len(exploit_activities)

        if hasattr(self.app, "exploit_count"):
            exploits_generated = max(exploits_generated, int(self.app.exploit_count))

        self.stats["advanced_analysis"] = {
            "dynamic_analyses": dynamic_analyses,
            "vulnerabilities_found": vulnerabilities_found,
            "exploits_generated": exploits_generated,
        }

    def get_stats(self) -> dict[str, Any]:
        """Get current statistics dictionary.

        Returns:
            Dictionary containing all current dashboard statistics.

        """
        return self.stats

    def get_recent_activities(self) -> list[dict[str, str]]:
        """Get list of recent activities.

        Returns:
            List of recent activity dictionaries with type, description, and timestamp.

        """
        return self.recent_activities

    def _format_size(self, size: float) -> str:
        """Format file size in human readable format.

        Args:
            size: File size in bytes.

        Returns:
            Human readable file size string with units (B, KB, MB, GB, TB).

        """
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

    def add_activity(self, activity_type: str, description: str) -> None:
        """Add an activity to the recent activities list.

        Args:
            activity_type: Type or category of the activity.
            description: Human-readable description of the activity.

        """
        activity: dict[str, str] = {
            "type": activity_type,
            "description": description,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.recent_activities.insert(0, activity)
        if len(self.recent_activities) > self.max_recent_activities:
            self.recent_activities = self.recent_activities[: self.max_recent_activities]

    def export_stats(self, filepath: str) -> bool:
        """Export current statistics to a file.

        Args:
            filepath: Path to file where statistics will be exported.

        Returns:
            True if export was successful, False otherwise.

        """
        try:
            import json

            export_data: dict[str, Any] = {
                "timestamp": datetime.datetime.now().isoformat(),
                "statistics": self.get_stats(),
                "recent_activities": self.get_recent_activities(),
            }

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, default=str)

            return True

        except Exception:
            self.logger.exception("Failed to export statistics to %s", filepath)
            return False
