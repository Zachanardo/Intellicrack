#!/usr/bin/env python3
"""
Dashboard Manager for Intellicrack application.

This module provides comprehensive dashboard management with project statistics,
recent activities tracking, and quick access to common functions.
"""

import datetime
import logging
import os
from typing import Any, Dict, List, Union


class DashboardManager:
    """
    Comprehensive dashboard manager with project statistics and activity tracking.

    This class manages the dashboard UI, providing an intuitive interface with
    project statistics, recent activities, and quick access to common functions.
    Supports real-time updates and comprehensive monitoring of application state.
    """

    def __init__(self, app: Any):
        """
        Initialize the dashboard manager with the main application instance.

        Args:
            app: Main application instance for accessing application state
        """
        self.app = app
        self.logger = logging.getLogger(__name__)
        self.stats: Dict[str, Any] = {}
        self.recent_activities: List[Dict[str, str]] = []
        self.max_recent_activities = 20

        self.logger.info("Dashboard manager initialized")

    def update_stats(self) -> None:
        """
        Update all dashboard statistics.

        Refreshes all statistical information including binary stats,
        patch stats, analysis stats, license stats, and advanced analysis features.
        """
        self.logger.debug("Updating dashboard statistics")

        # Initialize stats dict if needed
        if not hasattr(self, 'stats'):
            self.logger.debug("Initializing stats dictionary")
            self.stats = {}

        # Update all statistics categories
        self._update_binary_stats()
        self._update_patch_stats()
        self._update_analysis_stats()
        self._update_license_stats()
        self._update_advanced_analysis_stats()

        self.logger.debug(f"Stats dictionary updated with keys: {list(self.stats.keys())}")

    def _update_binary_stats(self) -> None:
        """
        Update binary file statistics.

        Collects information about the currently loaded binary including
        file size, path, name, and last modification time.
        """
        if (hasattr(self.app, "binary_path") and
            self.app.binary_path and
            os.path.exists(self.app.binary_path)):

            try:
                binary_size = os.path.getsize(self.app.binary_path)
                binary_name = os.path.basename(self.app.binary_path)
                last_modified = os.path.getmtime(self.app.binary_path)

                self.stats["binary"] = {
                    "name": binary_name,
                    "path": self.app.binary_path,
                    "size": binary_size,
                    "size_formatted": self._format_size(binary_size),
                    "last_modified": datetime.datetime.fromtimestamp(last_modified).strftime("%Y-%m-%d %H:%M:%S")
                }

                self.logger.debug(f"Updated binary stats for {binary_name}")

            except (OSError, ValueError) as e:
                self.logger.warning(f"Failed to update binary stats: {e}")
                self.stats["binary"] = None
        else:
            self.stats["binary"] = None

    def _update_patch_stats(self) -> None:
        """
        Update patch application statistics.

        Tracks the number of patches, applied patches, and categorizes
        patches by type for comprehensive patch management overview.
        """
        if hasattr(self.app, "patches") and self.app.patches:
            patch_count = len(self.app.patches)
            applied_count = sum(1 for p in self.app.patches if p.get("applied", False))
            patch_types: Dict[str, int] = {}

            # Count patch types
            for patch in self.app.patches:
                patch_type = patch.get("type", "unknown")
                patch_types[patch_type] = patch_types.get(patch_type, 0) + 1

            self.stats["patches"] = {
                "count": patch_count,
                "applied": applied_count,
                "types": patch_types
            }

            self.logger.debug(f"Updated patch stats: {patch_count} total, {applied_count} applied")

        else:
            self.stats["patches"] = {
                "count": 0,
                "applied": 0,
                "types": {}
            }

    def _update_analysis_stats(self) -> None:
        """
        Update analysis execution statistics.

        Tracks analysis results count and last execution time
        for monitoring analysis activity.
        """
        if hasattr(self.app, "analyze_results") and self.app.analyze_results:
            result_count = len(self.app.analyze_results)
            last_run = (self.recent_activities[0]["timestamp"]
                       if self.recent_activities else "Never")

            self.stats["analysis"] = {
                "count": result_count,
                "last_run": last_run
            }

            self.logger.debug(f"Updated analysis stats: {result_count} results")

        else:
            self.stats["analysis"] = {
                "count": 0,
                "last_run": "Never"
            }

    def _update_license_stats(self) -> None:
        """
        Update license server statistics.

        Monitors license server status including running state
        and port configuration for network-based license operations.
        """
        if (hasattr(self.app, "license_server_instance") and
            self.app.license_server_instance):

            server = self.app.license_server_instance
            self.stats["license_server"] = {
                "running": getattr(server, "running", False),
                "port": getattr(server, "port", None)
            }

            self.logger.debug("Updated license server stats")

        else:
            self.stats["license_server"] = {
                "running": False,
                "port": None
            }

    def _update_advanced_analysis_stats(self) -> None:
        """
        Update advanced analysis features statistics.

        Tracks availability and status of advanced analysis components
        including taint analysis, symbolic execution, and other specialized tools.
        """
        # Check availability of advanced analysis components
        advanced_features = {
            "taint_analysis": hasattr(self.app, "taint_analysis_engine"),
            "symbolic_execution": hasattr(self.app, "symbolic_execution_engine"),
            "concolic_execution": hasattr(self.app, "concolic_execution_engine"),
            "rop_chain_generator": hasattr(self.app, "rop_chain_generator"),
            "memory_optimized": hasattr(self.app, "memory_optimized_loader"),
            "incremental_analysis": hasattr(self.app, "incremental_analysis_manager"),
            "distributed_processing": hasattr(self.app, "distributed_processing_manager"),
            "gpu_acceleration": hasattr(self.app, "gpu_accelerator"),
            "pdf_report": hasattr(self.app, "pdf_report_generator")
        }

        # Count active features
        active_count = sum(1 for available in advanced_features.values() if available)

        self.stats["advanced_analysis"] = {
            **advanced_features,
            "active_count": active_count
        }

        self.logger.debug(f"Updated advanced analysis stats: {active_count} features active")

    def update_statistics(self, stats_dict: Dict[str, Any]) -> None:
        """
        Update specific statistics with provided values.

        This method is used by other components to update dashboard
        with specific statistical information.

        Args:
            stats_dict: Dictionary containing statistics to update
        """
        self.logger.info(f"Updating dashboard statistics: {list(stats_dict.keys())}")

        # Initialize stats dict if needed
        if not hasattr(self, 'stats'):
            self.stats = {}

        # Update the stats with the provided values
        for key, value in stats_dict.items():
            self.stats[key] = value

        # Refresh all statistics
        self.update_stats()

        self.logger.info("Dashboard statistics updated successfully")

    def add_activity(self, activity_type: str, description: str) -> None:
        """
        Add an activity to the recent activities list.

        Args:
            activity_type: Type/category of the activity
            description: Detailed description of the activity
        """
        activity = {
            "type": activity_type,
            "description": description,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        # Insert at the beginning (most recent first)
        self.recent_activities.insert(0, activity)

        # Limit the number of recent activities
        if len(self.recent_activities) > self.max_recent_activities:
            self.recent_activities = self.recent_activities[:self.max_recent_activities]

        self.logger.info(f"Activity added: {activity_type} - {description}")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive dashboard statistics.

        Returns:
            Dictionary containing all current statistics
        """
        self.update_stats()
        return self.stats.copy()

    def get_recent_activities(self) -> List[Dict[str, str]]:
        """
        Get list of recent activities.

        Returns:
            List of recent activities with timestamps
        """
        return self.recent_activities.copy()

    def clear_activities(self) -> None:
        """
        Clear all recent activities from the dashboard.
        """
        self.recent_activities.clear()
        self.logger.info("Recent activities cleared")

    def get_summary(self) -> Dict[str, Union[str, int]]:
        """
        Get a summary of key dashboard metrics.

        Returns:
            Dictionary containing summary information
        """
        self.update_stats()

        summary = {
            "binary_loaded": self.stats.get("binary") is not None,
            "binary_name": self.stats.get("binary", {}).get("name", "None"),
            "patch_count": self.stats.get("patches", {}).get("count", 0),
            "analysis_count": self.stats.get("analysis", {}).get("count", 0),
            "license_server_running": self.stats.get("license_server", {}).get("running", False),
            "advanced_features_active": self.stats.get("advanced_analysis", {}).get("active_count", 0),
            "recent_activity_count": len(self.recent_activities)
        }

        return summary

    def _format_size(self, size_bytes: int) -> str:
        """
        Format size in bytes to human-readable format.

        Args:
            size_bytes: Size in bytes to format

        Returns:
            Human-readable size string
        """
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

    def export_stats(self, filepath: str) -> bool:
        """
        Export current statistics to a file.

        Args:
            filepath: Path to export statistics to

        Returns:
            True if export successful, False otherwise
        """
        try:
            import json

            export_data = {
                "timestamp": datetime.datetime.now().isoformat(),
                "statistics": self.get_stats(),
                "recent_activities": self.get_recent_activities()
            }

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)

            self.logger.info(f"Statistics exported to {filepath}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to export statistics: {e}")
            return False


# Export main class
__all__ = ['DashboardManager']
