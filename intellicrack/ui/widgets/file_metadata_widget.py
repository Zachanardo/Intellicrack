"""File metadata display widget using QDateTime and QFileInfo.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import os

from PyQt6.QtCore import QDateTime, QFileInfo, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

logger = logging.getLogger(__name__)


class FileMetadataWidget(QWidget):
    """Widget for displaying file metadata using QFileInfo and QDateTime."""

    # Signal emitted when a file is analyzed
    file_analyzed = pyqtSignal(str, dict)

    def __init__(self, parent=None):
        """Initialize the file metadata widget."""
        super().__init__(parent)
        self.current_file = None
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()

        # Create metadata display group
        self.metadata_group = QGroupBox("File Metadata")
        metadata_layout = QGridLayout()

        # File path
        metadata_layout.addWidget(QLabel("<b>File Path:</b>"), 0, 0)
        self.path_label = QLabel("No file loaded")
        self.path_label.setWordWrap(True)
        metadata_layout.addWidget(self.path_label, 0, 1)

        # File name
        metadata_layout.addWidget(QLabel("<b>File Name:</b>"), 1, 0)
        self.name_label = QLabel("-")
        metadata_layout.addWidget(self.name_label, 1, 1)

        # File size
        metadata_layout.addWidget(QLabel("<b>Size:</b>"), 2, 0)
        self.size_label = QLabel("-")
        metadata_layout.addWidget(self.size_label, 2, 1)

        # Creation time
        metadata_layout.addWidget(QLabel("<b>Created:</b>"), 3, 0)
        self.created_label = QLabel("-")
        metadata_layout.addWidget(self.created_label, 3, 1)

        # Last modified
        metadata_layout.addWidget(QLabel("<b>Modified:</b>"), 4, 0)
        self.modified_label = QLabel("-")
        metadata_layout.addWidget(self.modified_label, 4, 1)

        # Last accessed
        metadata_layout.addWidget(QLabel("<b>Accessed:</b>"), 5, 0)
        self.accessed_label = QLabel("-")
        metadata_layout.addWidget(self.accessed_label, 5, 1)

        # File type/extension
        metadata_layout.addWidget(QLabel("<b>Type:</b>"), 6, 0)
        self.type_label = QLabel("-")
        metadata_layout.addWidget(self.type_label, 6, 1)

        # Permissions
        metadata_layout.addWidget(QLabel("<b>Permissions:</b>"), 7, 0)
        self.permissions_label = QLabel("-")
        metadata_layout.addWidget(self.permissions_label, 7, 1)

        # Owner (if available)
        metadata_layout.addWidget(QLabel("<b>Owner:</b>"), 8, 0)
        self.owner_label = QLabel("-")
        metadata_layout.addWidget(self.owner_label, 8, 1)

        # Is executable
        metadata_layout.addWidget(QLabel("<b>Executable:</b>"), 9, 0)
        self.executable_label = QLabel("-")
        metadata_layout.addWidget(self.executable_label, 9, 1)

        # Is symbolic link
        metadata_layout.addWidget(QLabel("<b>Symbolic Link:</b>"), 10, 0)
        self.symlink_label = QLabel("-")
        metadata_layout.addWidget(self.symlink_label, 10, 1)

        self.metadata_group.setLayout(metadata_layout)
        layout.addWidget(self.metadata_group)

        # Timestamps group
        self.timestamps_group = QGroupBox("Detailed Timestamps")
        timestamps_layout = QVBoxLayout()

        self.timestamps_text = QTextEdit()
        self.timestamps_text.setReadOnly(True)
        self.timestamps_text.setMaximumHeight(150)
        timestamps_layout.addWidget(self.timestamps_text)

        self.timestamps_group.setLayout(timestamps_layout)
        layout.addWidget(self.timestamps_group)

        # Refresh button
        button_layout = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh Metadata")
        self.refresh_button.clicked.connect(self.refresh_metadata)
        self.refresh_button.setEnabled(False)
        button_layout.addWidget(self.refresh_button)
        button_layout.addStretch()

        layout.addLayout(button_layout)
        layout.addStretch()

        self.setLayout(layout)

    def analyze_file(self, file_path: str) -> dict:
        """Analyze a file and update the display.

        Args:
            file_path: Path to the file to analyze

        Returns:
            Dictionary containing file metadata

        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return {}

        self.current_file = file_path
        self.refresh_button.setEnabled(True)

        # Create QFileInfo object
        file_info = QFileInfo(file_path)

        # Update labels
        self.path_label.setText(file_info.absoluteFilePath())
        self.name_label.setText(file_info.fileName())
        self.size_label.setText(self._format_size(file_info.size()))

        # Get timestamps using QDateTime
        created_time = file_info.birthTime()
        modified_time = file_info.lastModified()
        accessed_time = file_info.lastRead()

        # Format timestamps
        datetime_format = "yyyy-MM-dd hh:mm:ss AP"

        if created_time.isValid():
            self.created_label.setText(created_time.toString(datetime_format))
        else:
            self.created_label.setText("Not available")

        self.modified_label.setText(modified_time.toString(datetime_format))
        self.accessed_label.setText(accessed_time.toString(datetime_format))

        # File type and attributes
        if file_info.isDir():
            file_type = "Directory"
        elif file_info.isSymLink():
            file_type = f"Symbolic Link → {file_info.symLinkTarget()}"
        else:
            suffix = file_info.suffix()
            if suffix:
                file_type = f"{suffix.upper()} file"
            else:
                file_type = "Unknown"

        self.type_label.setText(file_type)

        # Permissions
        permissions = []
        if file_info.isReadable():
            permissions.append("Read")
        if file_info.isWritable():
            permissions.append("Write")
        if file_info.isExecutable():
            permissions.append("Execute")

        self.permissions_label.setText(", ".join(permissions) if permissions else "None")

        # Owner
        self.owner_label.setText(file_info.owner() if file_info.owner() else "Unknown")

        # Executable and symlink status
        self.executable_label.setText("Yes" if file_info.isExecutable() else "No")
        self.symlink_label.setText("Yes" if file_info.isSymLink() else "No")

        # Detailed timestamps
        timestamps_text = "<b>Detailed Timestamp Information</b><br><br>"

        # Creation time (birth time)
        if created_time.isValid():
            timestamps_text += "<b>Created:</b><br>"
            timestamps_text += f"  Date: {created_time.toString('dddd, MMMM d, yyyy')}<br>"
            timestamps_text += f"  Time: {created_time.toString('h:mm:ss AP')}<br>"
            timestamps_text += f"  ISO: {created_time.toString(Qt.ISODate)}<br>"
            timestamps_text += f"  Unix: {created_time.toSecsSinceEpoch()}<br><br>"

        # Modified time
        timestamps_text += "<b>Last Modified:</b><br>"
        timestamps_text += f"  Date: {modified_time.toString('dddd, MMMM d, yyyy')}<br>"
        timestamps_text += f"  Time: {modified_time.toString('h:mm:ss AP')}<br>"
        timestamps_text += f"  ISO: {modified_time.toString(Qt.ISODate)}<br>"
        timestamps_text += f"  Unix: {modified_time.toSecsSinceEpoch()}<br><br>"

        # Accessed time
        timestamps_text += "<b>Last Accessed:</b><br>"
        timestamps_text += f"  Date: {accessed_time.toString('dddd, MMMM d, yyyy')}<br>"
        timestamps_text += f"  Time: {accessed_time.toString('h:mm:ss AP')}<br>"
        timestamps_text += f"  ISO: {accessed_time.toString(Qt.ISODate)}<br>"
        timestamps_text += f"  Unix: {accessed_time.toSecsSinceEpoch()}<br><br>"

        # Time since last modification
        current_time = QDateTime.currentDateTime()
        secs_since_modified = modified_time.secsTo(current_time)
        days_since_modified = secs_since_modified // 86400
        hours_since_modified = (secs_since_modified % 86400) // 3600

        timestamps_text += "<b>Time Since Last Modification:</b><br>"
        timestamps_text += f"  {days_since_modified} days, {hours_since_modified} hours<br>"

        self.timestamps_text.setHtml(timestamps_text)

        # Create metadata dictionary
        metadata = {
            "path": file_info.absoluteFilePath(),
            "name": file_info.fileName(),
            "size": file_info.size(),
            "size_formatted": self._format_size(file_info.size()),
            "created": created_time.toString(Qt.ISODate) if created_time.isValid() else None,
            "modified": modified_time.toString(Qt.ISODate),
            "accessed": accessed_time.toString(Qt.ISODate),
            "created_unix": created_time.toSecsSinceEpoch() if created_time.isValid() else None,
            "modified_unix": modified_time.toSecsSinceEpoch(),
            "accessed_unix": accessed_time.toSecsSinceEpoch(),
            "type": file_type,
            "is_dir": file_info.isDir(),
            "is_file": file_info.isFile(),
            "is_symlink": file_info.isSymLink(),
            "is_readable": file_info.isReadable(),
            "is_writable": file_info.isWritable(),
            "is_executable": file_info.isExecutable(),
            "owner": file_info.owner() if file_info.owner() else None,
            "suffix": file_info.suffix(),
            "complete_suffix": file_info.completeSuffix(),
        }

        # Emit signal
        self.file_analyzed.emit(file_path, metadata)

        return metadata

    def refresh_metadata(self):
        """Refresh the metadata for the current file."""
        if self.current_file:
            self.analyze_file(self.current_file)

    def clear(self):
        """Clear all metadata displays."""
        self.current_file = None
        self.refresh_button.setEnabled(False)

        self.path_label.setText("No file loaded")
        self.name_label.setText("-")
        self.size_label.setText("-")
        self.created_label.setText("-")
        self.modified_label.setText("-")
        self.accessed_label.setText("-")
        self.type_label.setText("-")
        self.permissions_label.setText("-")
        self.owner_label.setText("-")
        self.executable_label.setText("-")
        self.symlink_label.setText("-")
        self.timestamps_text.clear()

    def _format_size(self, size: int) -> str:
        """Format file size in human-readable format.

        Args:
            size: Size in bytes

        Returns:
            Formatted size string

        """
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"


class FileTimestampTracker:
    """Helper class for tracking file timestamps and changes."""

    def __init__(self):
        """Initialize the timestamp tracker."""
        self.tracked_files = {}

    def track_file(self, file_path: str) -> dict:
        """Start tracking a file's timestamps.

        Args:
            file_path: Path to the file to track

        Returns:
            Dictionary with initial timestamp data

        """
        if not os.path.exists(file_path):
            return {}

        file_info = QFileInfo(file_path)

        timestamp_data = {
            "path": file_path,
            "initial_modified": file_info.lastModified(),
            "initial_accessed": file_info.lastRead(),
            "initial_size": file_info.size(),
            "checks": [],
        }

        self.tracked_files[file_path] = timestamp_data
        return timestamp_data

    def check_file(self, file_path: str) -> dict:
        """Check if a tracked file has changed.

        Args:
            file_path: Path to the file to check

        Returns:
            Dictionary with change information

        """
        if file_path not in self.tracked_files:
            return {"error": "File not being tracked"}

        if not os.path.exists(file_path):
            return {"error": "File no longer exists"}

        file_info = QFileInfo(file_path)
        tracked = self.tracked_files[file_path]

        current_modified = file_info.lastModified()
        current_accessed = file_info.lastRead()
        current_size = file_info.size()

        check_data = {
            "timestamp": QDateTime.currentDateTime(),
            "modified_changed": current_modified != tracked["initial_modified"],
            "accessed_changed": current_accessed != tracked["initial_accessed"],
            "size_changed": current_size != tracked["initial_size"],
            "current_modified": current_modified,
            "current_accessed": current_accessed,
            "current_size": current_size,
        }

        tracked["checks"].append(check_data)

        return {
            "file": file_path,
            "changed": check_data["modified_changed"] or check_data["size_changed"],
            "details": check_data,
        }

    def get_file_history(self, file_path: str) -> dict:
        """Get the tracking history for a file.

        Args:
            file_path: Path to the file

        Returns:
            Dictionary with tracking history

        """
        if file_path not in self.tracked_files:
            return {}

        return self.tracked_files[file_path]

    def stop_tracking(self, file_path: str):
        """Stop tracking a file.

        Args:
            file_path: Path to the file to stop tracking

        """
        if file_path in self.tracked_files:
            del self.tracked_files[file_path]

    def clear_all(self):
        """Stop tracking all files."""
        self.tracked_files.clear()
