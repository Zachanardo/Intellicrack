"""Intellicrack Hex Protection Integration Module

Integrates protection analysis hex viewer features with Intellicrack's advanced hex viewer.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os

from PyQt6.QtCore import QObject, QProcess, QTimer, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from ..protection.intellicrack_protection_core import IntellicrackProtectionCore
from ..utils.logger import get_logger

logger = get_logger(__name__)


class IntellicrackHexProtectionIntegration(QObject):
    """Integrates protection analysis hex viewer with Intellicrack's hex viewer"""

    # Signals
    #: Signal to request jumping to a specific offset (type: int)
    offset_requested = pyqtSignal(int)
    #: Signal to request jumping to a specific section (type: str)
    section_requested = pyqtSignal(str)

    def __init__(self, hex_widget=None):
        """Initialize hex protection integration

        Args:
            hex_widget: Reference to Intellicrack's hex viewer widget

        """
        super().__init__()
        self.hex_widget = hex_widget
        self.protection_detector = IntellicrackProtectionCore()
        self.icp_detector = self.protection_detector
        self.engine_process = None

        # Setup two-way synchronization monitoring
        self.sync_timer = QTimer()
        self.sync_timer.timeout.connect(self._monitor_protection_viewer_offset)
        self.last_synced_offset = -1
        self.sync_timer.start(500)  # Check every 500ms

    def open_in_protection_viewer(self, file_path: str, offset: int | None = None):
        """Open file in protection analysis hex viewer

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
                "extensions",
                "engines",
                "protection_viewer",
                "protection_viewer.exe",
            )

            if not os.path.exists(protection_viewer_path):
                logger.error(f"Protection viewer not found at: {protection_viewer_path}")
                return

            # Build command
            cmd = [protection_viewer_path, file_path]

            # Handle offset parameter for better integration
            if offset is not None:
                # Try command-line offset support first
                cmd.extend(["--offset", hex(offset)])
                logger.info(
                    f"Attempting to open {file_path} at offset {hex(offset)} in protection viewer"
                )

                # Create offset sync file for advanced integration
                try:
                    sync_dir = os.path.join(os.path.dirname(protection_viewer_path), "sync")
                    os.makedirs(sync_dir, exist_ok=True)
                    sync_file = os.path.join(sync_dir, "initial_offset.txt")
                    with open(sync_file, "w") as f:
                        f.write(f"{offset}\n{hex(offset)}\n{file_path}")
                    logger.debug(f"Created offset sync file: {sync_file}")
                except OSError as e:
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

    def open_in_icp(self, file_path: str, offset: int | None = None):
        """Alias for open_in_protection_viewer to maintain ICP naming consistency"""
        return self.open_in_protection_viewer(file_path, offset)

    def _cleanup_sync_files(self):
        """Clean up temporary sync files after protection viewer closes."""
        # Stop the sync timer
        if hasattr(self, 'sync_timer') and self.sync_timer:
            self.sync_timer.stop()

        try:
            protection_viewer_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "extensions",
                "engines",
                "protection_viewer",
                "protection_viewer.exe",
            )
            sync_dir = os.path.join(os.path.dirname(protection_viewer_path), "sync")
            sync_file = os.path.join(sync_dir, "initial_offset.txt")
            if os.path.exists(sync_file):
                os.remove(sync_file)
                logger.debug("Cleaned up offset sync file")
        except OSError as e:
            logger.debug(f"Failed to cleanup sync files: {e}")

    def sync_offset_from_protection_viewer(self, offset: int):
        """Sync offset from protection viewer to our hex viewer

        Args:
            offset: Offset to sync

        """
        if self.hex_widget:
            self.hex_widget.goto_offset(offset)
            self.offset_requested.emit(offset)

    def sync_offset_to_protection_viewer(self, offset: int):
        """Sync offset from our hex viewer to protection viewer

        Args:
            offset: Offset to sync

        """
        # Implement file-based two-way synchronization
        sync_dir = os.path.join(os.path.expanduser("~"), ".intellicrack", "hex_sync")

        # Ensure sync directory exists
        os.makedirs(sync_dir, exist_ok=True)

        # Write offset to a sync file that protection viewer can monitor
        outgoing_sync_file = os.path.join(sync_dir, "hex_to_protection_offset.txt")
        try:
            with open(outgoing_sync_file, "w") as f:
                f.write(str(offset))
            logger.debug(f"Synced offset {offset:#x} to protection viewer via {outgoing_sync_file}")
        except Exception as e:
            logger.error(f"Failed to sync offset to protection viewer: {e}")

        # If we have a running process, try to send via stdin as well
        if self.engine_process and self.engine_process.state() == QProcess.ProcessState.Running:
            try:
                # Send offset command through stdin
                command = f"goto:{offset}\n"
                self.engine_process.write(command.encode())
                logger.debug(f"Sent goto command to protection viewer process: {command.strip()}")
            except Exception as e:
                logger.error(f"Failed to send command to protection viewer process: {e}")

    def _monitor_protection_viewer_offset(self):
        """Monitor for offset changes from protection viewer."""
        sync_dir = os.path.join(os.path.expanduser("~"), ".intellicrack", "hex_sync")
        incoming_sync_file = os.path.join(sync_dir, "protection_to_hex_offset.txt")

        if not os.path.exists(incoming_sync_file):
            return

        try:
            with open(incoming_sync_file, "r") as f:
                offset_str = f.read().strip()
                if offset_str:
                    offset = int(offset_str, 0)  # Support both decimal and hex (0x prefix)

                    # Only sync if this is a new offset
                    if offset != self.last_synced_offset:
                        self.last_synced_offset = offset
                        self.sync_offset_from_protection_viewer(offset)

                        # Clear the file after reading
                        with open(incoming_sync_file, "w") as f:
                            f.write("")
        except Exception as e:
            logger.debug(f"Error monitoring protection viewer offset: {e}")

    def get_section_offsets(self, file_path: str) -> dict[str, int]:
        """Get section offsets from protection viewer analysis

        Args:
            file_path: Path to file

        Returns:
            Dictionary mapping section names to offsets

        """
        try:
            analysis = self.icp_detector.detect_protections(file_path)
            section_offsets = {}

            if analysis and analysis.sections:
                for section in analysis.sections:
                    name = section.get("name", "")
                    offset = section.get("offset", 0)
                    if name and offset:
                        section_offsets[name] = offset

            return section_offsets

        except Exception as e:
            logger.error(f"Error getting section offsets: {e}")
            return {}

    def compare_features(self) -> dict[str, dict[str, bool]]:
        """Compare features between protection viewer hex viewer and our hex viewer

        Returns:
            Feature comparison dictionary

        """
        # Dynamically check for Intellicrack hex viewer features
        intellicrack_features = self._detect_intellicrack_features()

        # Protection viewer features (these are known/documented)
        protection_viewer_features = {
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
            "Templates": False,
        }

        return {
            "protection viewer Hex Viewer": protection_viewer_features,
            "Intellicrack Hex Viewer": intellicrack_features,
        }

    def _detect_intellicrack_features(self) -> dict[str, bool]:
        """Dynamically detect features available in Intellicrack hex viewer

        Returns:
            Dictionary of feature availability
        """
        features = {
            "Basic Viewing": False,
            "Text Search": False,
            "ANSI/Unicode Search": False,
            "Data Export": False,
            "Integrated with Analysis": False,
            "Hotkey Access": False,
            "Section Navigation": False,
            "Hex Editing": False,
            "Bookmarks": False,
            "Pattern Matching": False,
            "Multi-View": False,
            "Performance Monitoring": False,
            "Advanced Search": False,
            "Highlighting": False,
            "Templates": False,
            "File Comparison": False,
            "Printing": False,
            "Unlimited Undo/Redo": False,
        }

        # Check if we have a hex widget reference
        if not self.hex_widget:
            # Try to import and check the hex widget class
            try:
                from .hex_widget import HexViewerWidget
                widget_class = HexViewerWidget
            except ImportError:
                return features
        else:
            widget_class = self.hex_widget.__class__

        # Check for basic viewing (always present if widget exists)
        features["Basic Viewing"] = True

        # Check for search capabilities
        if hasattr(widget_class, 'search') or hasattr(widget_class, 'find_text'):
            features["Text Search"] = True

        # Check for advanced search module
        try:
            from .advanced_search import AdvancedSearchEngine
            _ = AdvancedSearchEngine.__name__  # Verify advanced search capabilities
            features["Advanced Search"] = True
            features["ANSI/Unicode Search"] = True
            features["Pattern Matching"] = True
        except ImportError:
            pass

        # Check for export capabilities
        try:
            from .export_dialog import ExportDialog
            _ = ExportDialog.__name__  # Verify export dialog capabilities
            features["Data Export"] = True
        except ImportError:
            pass

        # Check for hex editing
        if hasattr(widget_class, 'set_read_only') or hasattr(widget_class, 'edit_mode'):
            features["Hex Editing"] = True

        # Check for bookmarks
        if hasattr(widget_class, 'add_bookmark') or hasattr(widget_class, 'bookmarks'):
            features["Bookmarks"] = True

        # Check for highlighting
        try:
            from .hex_highlighter import HexHighlighter
            _ = HexHighlighter.__name__  # Verify highlighting capabilities are available
            features["Highlighting"] = True
        except ImportError:
            pass

        # Check for multi-view capabilities
        if self.hex_widget:
            parent = self.hex_widget.parent()
            if parent and hasattr(parent, 'split_view_horizontal'):
                features["Multi-View"] = True
        else:
            # Check if split view methods exist in dialog
            try:
                from .hex_dialog import HexViewerDialog
                if hasattr(HexViewerDialog, 'split_view_horizontal'):
                    features["Multi-View"] = True
            except ImportError:
                pass

        # Check for performance monitoring
        try:
            from .performance_monitor import PerformanceMonitor
            _ = PerformanceMonitor.__name__  # Verify performance monitoring capabilities are available
            features["Performance Monitoring"] = True
        except ImportError:
            pass

        # Check for templates
        try:
            from .templates import TemplateEngine
            _ = TemplateEngine.__name__  # Verify template engine capabilities are available
            features["Templates"] = True
        except ImportError:
            pass

        # Check for file comparison
        try:
            from .file_compare import BinaryComparer
            _ = BinaryComparer.__name__  # Verify binary comparison capabilities are available
            features["File Comparison"] = True
        except ImportError:
            pass

        # Check for printing
        try:
            from .print_dialog import PrintOptionsDialog
            _ = PrintOptionsDialog.__name__  # Verify printing capabilities are available
            features["Printing"] = True
        except ImportError:
            pass

        # Check for unlimited undo/redo
        try:
            # Check if the CommandManager has sys.maxsize as default
            import inspect
            import sys

            from .hex_commands import CommandManager
            sig = inspect.signature(CommandManager.__init__)
            if 'max_history' in sig.parameters:
                default_value = sig.parameters['max_history'].default
                if default_value == sys.maxsize:
                    features["Unlimited Undo/Redo"] = True
        except ImportError:
            pass

        # Check for hotkey access
        if self.hex_widget:
            if hasattr(self.hex_widget, 'keyPressEvent'):
                features["Hotkey Access"] = True
        else:
            features["Hotkey Access"] = True  # Usually present in Qt widgets

        # Check for section navigation
        if hasattr(widget_class, 'goto_offset') or hasattr(widget_class, 'jump_to_offset'):
            features["Section Navigation"] = True

        # Integration with analysis is present through this module
        features["Integrated with Analysis"] = True

        return features


class ProtectionIntegrationWidget(QWidget):
    """Widget for protection viewer hex viewer integration controls"""

    def __init__(self, hex_widget=None, parent=None):
        """Initialize protection viewer integration widget

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
        self.open_in_protection_viewer_btn.setToolTip(
            "Open current file in protection viewer (press H for hex viewer)"
        )
        button_layout.addWidget(self.open_in_protection_viewer_btn)

        self.sync_sections_btn = QPushButton("Sync Sections")
        self.sync_sections_btn.clicked.connect(self.sync_sections_from_icp)
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
        if self.hex_widget and hasattr(self.hex_widget, "file_path"):
            file_path = self.hex_widget.file_path
            if file_path:
                self.integration.open_in_icp(file_path)
                self.info_label.setText("Opened in protection viewer - Press 'H' for hex viewer")
            else:
                self.info_label.setText("No file loaded")
        else:
            self.info_label.setText("Hex viewer not available")

    def sync_sections_from_icp(self):
        """Sync section information from protection viewer"""
        if self.hex_widget and hasattr(self.hex_widget, "file_path"):
            file_path = self.hex_widget.file_path
            if file_path:
                sections = self.integration.get_section_offsets(file_path)
                if sections:
                    # Add bookmarks for sections
                    for name, offset in sections.items():
                        if hasattr(self.hex_widget, "add_bookmark"):
                            self.hex_widget.add_bookmark(offset, f"Section: {name}")
                    self.info_label.setText(
                        f"Synced {len(sections)} sections from protection viewer"
                    )
                else:
                    self.info_label.setText("No sections found")
            else:
                self.info_label.setText("No file loaded")


def create_intellicrack_hex_integration(hex_widget=None) -> IntellicrackHexProtectionIntegration:
    """Factory function to create Intellicrack hex viewer integration

    Args:
        hex_widget: Optional hex viewer widget to integrate with

    Returns:
        IntellicrackHexProtectionIntegration instance

    """
    return IntellicrackHexProtectionIntegration(hex_widget)
