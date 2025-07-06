"""
Intellicrack Hex Protection Integration Module

Integrates protection analysis hex viewer features with Intellicrack's advanced hex viewer.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
from typing import Dict, Optional

from PyQt5.QtCore import QObject, QProcess, pyqtSignal
from PyQt5.QtWidgets import QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from ..protection.intellicrack_protection_core import IntellicrackProtectionCore
from ..utils.logger import get_logger

logger = get_logger(__name__)


class IntellicrackHexProtectionIntegration(QObject):
    """
    Integrates protection analysis hex viewer with Intellicrack's hex viewer
    """

    # Signals
    offset_requested = pyqtSignal(int)  # Request jump to offset
    section_requested = pyqtSignal(str)  # Request jump to section

    def __init__(self, hex_widget=None):
        """
        Initialize hex protection integration

        Args:
            hex_widget: Reference to Intellicrack's hex viewer widget
        """
        super().__init__()
        self.hex_widget = hex_widget
        self.protection_detector = IntellicrackProtectionCore()
        self.engine_process = None

    def open_in_protection_viewer(self, file_path: str, offset: Optional[int] = None):
        """
        Open file in protection analysis hex viewer

        Args:
            file_path: Path to file to open
            offset: Optional offset to jump to
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return

        try:
            # Get protection viewer path
            protection_viewer_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "extensions", "engines", "protection_viewer", "protection_viewer.exe"
            )

            if not os.path.exists(protection_viewer_path):
                logger.error(f"Protection viewer not found at: {protection_viewer_path}")
                return

            # Build command
            cmd = [protection_viewer_path, file_path]
            
            # Handle offset parameter for better integration
            if offset is not None:
                # Try command-line offset support first
                cmd.extend(['--offset', hex(offset)])
                logger.info(f"Attempting to open {file_path} at offset {hex(offset)} in protection viewer")
                
                # Create offset sync file for advanced integration
                try:
                    sync_dir = os.path.join(os.path.dirname(protection_viewer_path), 'sync')
                    os.makedirs(sync_dir, exist_ok=True)
                    sync_file = os.path.join(sync_dir, 'initial_offset.txt')
                    with open(sync_file, 'w') as f:
                        f.write(f"{offset}\n{hex(offset)}\n{file_path}")
                    logger.debug(f"Created offset sync file: {sync_file}")
                except (OSError, IOError) as e:
                    logger.debug(f"Failed to create offset sync file: {e}")
            else:
                logger.info(f"Opening {file_path} in protection viewer (no specific offset)")

            # Start protection viewer
            self.engine_process = QProcess()
            self.engine_process.start(cmd[0], cmd[1:])
            
            # Schedule offset sync if process starts successfully and offset provided
            if offset is not None:
                self.engine_process.finished.connect(lambda: self._cleanup_sync_files())
                # Set up timer to sync offset once process is running
                QTimer.singleShot(2000, lambda: self.sync_offset_to_protection_viewer(offset))

            logger.info(f"Protection viewer process started for {file_path}")

        except Exception as e:
            logger.error(f"Error opening file in protection viewer: {e}")

    def _cleanup_sync_files(self):
        """Clean up temporary sync files after protection viewer closes."""
        try:
            protection_viewer_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "extensions", "engines", "protection_viewer", "protection_viewer.exe"
            )
            sync_dir = os.path.join(os.path.dirname(protection_viewer_path), 'sync')
            sync_file = os.path.join(sync_dir, 'initial_offset.txt')
            if os.path.exists(sync_file):
                os.remove(sync_file)
                logger.debug("Cleaned up offset sync file")
        except (OSError, IOError) as e:
            logger.debug(f"Failed to cleanup sync files: {e}")

    def sync_offset_from_protection_viewer(self, offset: int):
        """
        Sync offset from protection viewer to our hex viewer

        Args:
            offset: Offset to sync
        """
        if self.hex_widget:
            self.hex_widget.goto_offset(offset)
            self.offset_requested.emit(offset)

    def sync_offset_to_protection_viewer(self, offset: int):
        """
        Sync offset from our hex viewer to protection viewer

        Args:
            offset: Offset to sync
        """
        # protection viewer doesn't have an API for external control
        # This would require protection viewer modification or automation
        logger.debug(f"Cannot sync offset {offset} to protection viewer (no API)")

    def get_section_offsets(self, file_path: str) -> Dict[str, int]:
        """
        Get section offsets from protection viewer analysis

        Args:
            file_path: Path to file

        Returns:
            Dictionary mapping section names to offsets
        """
        try:
            analysis = self.die_detector.detect_protections(file_path)
            section_offsets = {}

            if analysis and analysis.sections:
                for section in analysis.sections:
                    name = section.get('name', '')
                    offset = section.get('offset', 0)
                    if name and offset:
                        section_offsets[name] = offset

            return section_offsets

        except Exception as e:
            logger.error(f"Error getting section offsets: {e}")
            return {}

    def compare_features(self) -> Dict[str, Dict[str, bool]]:
        """
        Compare features between protection viewer hex viewer and our hex viewer

        Returns:
            Feature comparison dictionary
        """
        return {
            "protection viewer Hex Viewer": {
                "Basic Viewing": True,
                "Text Search": True,
                "ANSI/Unicode Search": True,
                "Data Export": True,
                "Integrated with Analysis": True,
                "Hotkey Access": True,
                "Section Navigation": False,
                "Hex Editing": False,
                "Bookmarks": False,
                "Pattern Matching": False,
                "Multi-View": False,
                "Performance Monitoring": False,
                "Advanced Search": False,
                "Highlighting": False,
                "Templates": False
            },
            "Intellicrack Hex Viewer": {
                "Basic Viewing": True,
                "Text Search": True,
                "ANSI/Unicode Search": True,
                "Data Export": True,
                "Integrated with Analysis": True,
                "Hotkey Access": True,
                "Section Navigation": True,
                "Hex Editing": True,
                "Bookmarks": True,
                "Pattern Matching": True,
                "Multi-View": True,
                "Performance Monitoring": True,
                "Advanced Search": True,
                "Highlighting": True,
                "Templates": False  # We could add this
            }
        }


class ProtectionIntegrationWidget(QWidget):
    """
    Widget for protection viewer hex viewer integration controls
    """

    def __init__(self, hex_widget=None, parent=None):
        """
        Initialize protection viewer integration widget

        Args:
            hex_widget: Reference to hex viewer widget
            parent: Parent widget
        """
        super().__init__(parent)
        self.hex_widget = hex_widget
        self.integration = IntellicrackHexProtectionIntegration(hex_widget)
        self.init_ui()

    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout()

        # Header
        header = QLabel("Protection Viewer Integration")
        header.setStyleSheet("font-weight: bold;")
        layout.addWidget(header)

        # Buttons
        button_layout = QHBoxLayout()

        self.open_in_protection_viewer_btn = QPushButton("Open in Protection Viewer")
        self.open_in_protection_viewer_btn.clicked.connect(self._open_in_protection_viewer)
        self.open_in_protection_viewer_btn.setToolTip("Open current file in protection viewer (press H for hex viewer)")
        button_layout.addWidget(self.open_in_protection_viewer_btn)

        self.sync_sections_btn = QPushButton("Sync Sections")
        self.sync_sections_btn.clicked.connect(self.sync_sections_from_die)
        self.sync_sections_btn.setToolTip("Get section information from protection viewer analysis")
        button_layout.addWidget(self.sync_sections_btn)

        layout.addLayout(button_layout)

        # Info label
        self.info_label = QLabel("protection viewer provides basic hex viewing with search")
        self.info_label.setStyleSheet("color: #666;")
        layout.addWidget(self.info_label)

        layout.addStretch()
        self.setLayout(layout)

    def _open_in_protection_viewer(self):
        """Open current file in protection viewer"""
        if self.hex_widget and hasattr(self.hex_widget, 'file_path'):
            file_path = self.hex_widget.file_path
            if file_path:
                self.integration.open_in_die(file_path)
                self.info_label.setText("Opened in protection viewer - Press 'H' for hex viewer")
            else:
                self.info_label.setText("No file loaded")
        else:
            self.info_label.setText("Hex viewer not available")

    def sync_sections_from_die(self):
        """Sync section information from protection viewer"""
        if self.hex_widget and hasattr(self.hex_widget, 'file_path'):
            file_path = self.hex_widget.file_path
            if file_path:
                sections = self.integration.get_section_offsets(file_path)
                if sections:
                    # Add bookmarks for sections
                    for name, offset in sections.items():
                        if hasattr(self.hex_widget, 'add_bookmark'):
                            self.hex_widget.add_bookmark(offset, f"Section: {name}")
                    self.info_label.setText(f"Synced {len(sections)} sections from protection viewer")
                else:
                    self.info_label.setText("No sections found")
            else:
                self.info_label.setText("No file loaded")


def create_intellicrack_hex_integration(hex_widget=None) -> IntellicrackHexProtectionIntegration:
    """
    Factory function to create Intellicrack hex viewer integration

    Args:
        hex_widget: Optional hex viewer widget to integrate with

    Returns:
        IntellicrackHexProtectionIntegration instance
    """
    return IntellicrackHexProtectionIntegration(hex_widget)
