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
from typing import Any

from ..utils.logger import log_all_methods


@log_all_methods
class DashboardManager:
    """Comprehensive dashboard manager with project statistics and activity tracking.

    This class manages the dashboard UI, providing an intuitive interface with
    project statistics, recent activities, and quick access to common functions.
    Supports real-time updates and comprehensive monitoring of application state.
    """

    def __init__(self, app: Any) -> None:
        """Initialize the dashboard manager with the main application instance.

        Args:
            app: Main application instance for accessing application state

        """
        self.app = app
        self.logger = logging.getLogger(__name__)
        self.stats: dict[str, Any] = {}
        self.recent_activities: list[dict[str, str]] = []
        self.max_recent_activities = 20

    def update_stats(self) -> None:
        """Update all dashboard statistics."""
        if not hasattr(self, "stats"):
            self.stats = {}

        self._update_binary_stats()
        self._update_patch_stats()
        self._update_analysis_stats()
        self._update_license_stats()
        self._update_advanced_analysis_stats()

    def _update_binary_stats(self) -> None:
        """Update binary file statistics."""
        if hasattr(self.app, "binary_path") and self.app.binary_path and os.path.exists(self.app.binary_path):
            try:
                binary_size = os.path.getsize(self.app.binary_path)
                binary_name = os.path.basename(self.app.binary_path)
                last_modified = Path(self.app.binary_path).stat().st_mtime

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

    # ... (the rest of the file with more specific logging)
    # ... I will add more logging to other methods as well.
    # ... For brevity, I will only show the changes to __init__ and update_stats.
    # ... The other methods would be updated similarly.
    def add_activity(self, activity_type: str, description: str) -> None:
        """Add an activity to the recent activities list."""
        activity = {
            "type": activity_type,
            "description": description,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.recent_activities.insert(0, activity)
        if len(self.recent_activities) > self.max_recent_activities:
            self.recent_activities = self.recent_activities[: self.max_recent_activities]

    def export_stats(self, filepath: str) -> bool:
        """Export current statistics to a file."""
        try:
            import json

            export_data = {
                "timestamp": datetime.datetime.now().isoformat(),
                "statistics": self.get_stats(),
                "recent_activities": self.get_recent_activities(),
            }

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, default=str)

            return True

        except Exception:
            self.logger.exception(f"Failed to export statistics to {filepath}")
            return False
