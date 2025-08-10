"""Integration example for file metadata display functionality.

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

import logging

from intellicrack.handlers.pyqt6_handler import (
    QDateTime,
    QFileInfo,
    QTimer,
)

logger = logging.getLogger(__name__)


def add_file_metadata_to_app(app_instance):
    """Add file metadata display functionality to the main application.

    Args:
        app_instance: Main application instance

    """
    from .file_metadata_widget import FileMetadataWidget, FileTimestampTracker

    # Create metadata widget
    metadata_widget = FileMetadataWidget(app_instance)

    # Create timestamp tracker
    timestamp_tracker = FileTimestampTracker()

    # Add to app instance
    app_instance.file_metadata_widget = metadata_widget
    app_instance.timestamp_tracker = timestamp_tracker

    # Connect to file loading
    if hasattr(app_instance, "binary_path"):
        # Analyze the currently loaded binary
        if app_instance.binary_path:
            metadata = metadata_widget.analyze_file(app_instance.binary_path)
            timestamp_tracker.track_file(app_instance.binary_path)

            # Log metadata
            logger.info(f"File metadata analyzed: {app_instance.binary_path}")
            logger.info(f"Size: {metadata.get('size_formatted', 'Unknown')}")
            logger.info(f"Modified: {metadata.get('modified', 'Unknown')}")

    # Add metadata display to UI if possible
    if hasattr(app_instance, "file_info_tab") or hasattr(app_instance, "tab_widget"):
        # Add as a new tab
        if hasattr(app_instance, "tab_widget"):
            app_instance.tab_widget.addTab(metadata_widget, "File Metadata")

        # Or add to existing file info area
        elif hasattr(app_instance, "file_info_layout"):
            app_instance.file_info_layout.addWidget(metadata_widget)

    return metadata_widget, timestamp_tracker


def update_status_with_timestamp(app_instance, message: str):
    """Update application status with timestamp.

    Args:
        app_instance: Main application instance
        message: Status message to display

    """
    current_time = QDateTime.currentDateTime()
    timestamp = current_time.toString("yyyy-MM-dd hh:mm:ss")

    timestamped_message = f"[{timestamp}] {message}"

    if hasattr(app_instance, "update_output"):
        app_instance.update_output.emit(timestamped_message)
    elif hasattr(app_instance, "status_bar"):
        app_instance.status_bar.showMessage(timestamped_message)
    else:
        logger.info(timestamped_message)


def track_binary_modifications(app_instance):
    """Track modifications to the loaded binary file.

    Args:
        app_instance: Main application instance

    """
    if not hasattr(app_instance, "timestamp_tracker"):
        from .file_metadata_widget import FileTimestampTracker

        app_instance.timestamp_tracker = FileTimestampTracker()

    if hasattr(app_instance, "binary_path") and app_instance.binary_path:
        # Check for modifications
        check_result = app_instance.timestamp_tracker.check_file(app_instance.binary_path)

        if check_result.get("changed", False):
            update_status_with_timestamp(
                app_instance,
                f"Binary file modified: {app_instance.binary_path}",
            )

            # Update metadata display if available
            if hasattr(app_instance, "file_metadata_widget"):
                app_instance.file_metadata_widget.refresh_metadata()


def display_pe_timestamps(app_instance, pe_file):
    """Display PE file timestamps using QDateTime.

    Args:
        app_instance: Main application instance
        pe_file: pefile.PE object

    """
    if not hasattr(pe_file, "FILE_HEADER"):
        return

    # Get PE timestamp
    timestamp = getattr(pe_file.FILE_HEADER, "TimeDateStamp", 0)

    if timestamp:
        # Convert to QDateTime
        compile_time = QDateTime.fromSecsSinceEpoch(timestamp)

        # Format for display
        formatted_time = compile_time.toString("yyyy-MM-dd hh:mm:ss AP")

        message = f"PE Compile Time: {formatted_time}"

        # Calculate age
        current_time = QDateTime.currentDateTime()
        days_old = compile_time.daysTo(current_time)

        if days_old > 0:
            years = days_old // 365
            months = (days_old % 365) // 30
            days = (days_old % 365) % 30

            age_parts = []
            if years > 0:
                age_parts.append(f"{years} year{'s' if years > 1 else ''}")
            if months > 0:
                age_parts.append(f"{months} month{'s' if months > 1 else ''}")
            if days > 0:
                age_parts.append(f"{days} day{'s' if days > 1 else ''}")

            if age_parts:
                message += f" (Age: {', '.join(age_parts)})"

        update_status_with_timestamp(app_instance, message)


def get_file_metadata_summary(file_path: str) -> str:
    """Get a formatted summary of file metadata.

    Args:
        file_path: Path to the file

    Returns:
        Formatted metadata summary string

    """
    file_info = QFileInfo(file_path)

    if not file_info.exists():
        return f"File not found: {file_path}"

    # Build summary
    summary_parts = [
        f"File: {file_info.fileName()}",
        f"Size: {_format_size(file_info.size())}",
        f"Type: {'Directory' if file_info.isDir() else file_info.suffix().upper() or 'Unknown'}",
        f"Modified: {file_info.lastModified().toString('yyyy-MM-dd hh:mm:ss')}",
    ]

    if file_info.isSymLink():
        summary_parts.append(f"Links to: {file_info.symLinkTarget()}")

    permissions = []
    if file_info.isReadable():
        permissions.append("R")
    if file_info.isWritable():
        permissions.append("W")
    if file_info.isExecutable():
        permissions.append("X")

    if permissions:
        summary_parts.append(f"Permissions: {''.join(permissions)}")

    return " | ".join(summary_parts)


def _format_size(size: int) -> str:
    """Format file size in human-readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}PB"


# Example usage in main_app.py
def integrate_file_metadata_display(app):
    """Example integration function for main_app.py

    This function shows how to integrate the file metadata functionality
    into the main application.
    """
    # Add metadata widget to the application
    metadata_widget, timestamp_tracker = add_file_metadata_to_app(app)

    # Connect to binary loading events
    if hasattr(app, "binary_loaded"):
        app.binary_loaded.connect(lambda path: metadata_widget.analyze_file(path))

    # Set up periodic modification checking
    if hasattr(app, "timer"):
        # Check for file modifications every 5 seconds
        app.modification_timer = QTimer()
        app.modification_timer.timeout.connect(lambda: track_binary_modifications(app))
        app.modification_timer.start(5000)

    # Add status updates with timestamps
    original_update = app.update_output.emit if hasattr(app, "update_output") else None
    if original_update:

        def timestamped_update(message):
            update_status_with_timestamp(app, message)

        # Optional: Replace the original update method
        # app.update_output.emit = timestamped_update

    logger.info("File metadata display integrated successfully")
