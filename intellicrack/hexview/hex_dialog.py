"""Dialog for the Hex Viewer/Editor.

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
import os

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMenuBar,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QSplitter,
    QStatusBar,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from intellicrack.handlers.pyqt6_handler import QAction

from .compare_dialog import CompareDialog, ComparisonWorker
from .file_compare import BinaryComparer
from .hex_highlighter import HighlightType
from .hex_renderer import ViewMode
from .hex_widget import HexViewerWidget

logger = logging.getLogger("Intellicrack.HexView")


class HexViewerDialog(QDialog):
    """Dialog window for hex viewer/editor.

    This dialog integrates the hex viewer widget with additional controls
    for navigation, searching, and display options.
    """

    def __init__(self, parent=None, file_path: str | None = None, read_only: bool = True):
        """Initialize the hex viewer dialog.

        Args:
            parent: Parent widget
            file_path: Path to the file to open (optional)
            read_only: Whether to open the file in read-only mode

        """
        super().__init__(parent)

        # Dialog settings
        self.setWindowTitle("Enhanced Hex Viewer")
        self.resize(1200, 800)  # Larger default size (was 800x600)
        self.setModal(False)  # Non-modal dialog

        # Center dialog on screen
        screen = QApplication.primaryScreen().geometry()
        size = self.geometry()
        self.move(
            (screen.width() - size.width()) // 2,
            (screen.height() - size.height()) // 2,
        )

        # Create main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)

        # Create menu bar
        self.menu_bar = self.create_menus()
        layout.setMenuBar(self.menu_bar)

        # Create toolbar
        self.toolbar = self.create_toolbar()
        layout.addWidget(self.toolbar)

        # Create main horizontal splitter for sidebar and content
        self.main_splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(self.main_splitter)

        # Add sidebar
        self.sidebar = self.create_sidebar()
        self.main_splitter.addWidget(self.sidebar)

        # Create container for hex viewers
        self.viewer_container = QWidget()
        self.viewer_layout = QVBoxLayout(self.viewer_container)
        self.viewer_layout.setContentsMargins(0, 0, 0, 0)

        # Create splitter for hex viewers (initially contains one)
        self.viewer_splitter = QSplitter(Qt.Vertical)
        self.viewer_layout.addWidget(self.viewer_splitter)

        # Create the primary hex viewer widget
        self.hex_viewer = HexViewerWidget(self)
        self.hex_viewer.setProperty("primary", True)
        self.viewer_splitter.addWidget(self.hex_viewer)

        # Keep track of all viewers
        self.viewers = [self.hex_viewer]
        self.active_viewer = self.hex_viewer

        # Add viewer container to main splitter
        self.main_splitter.addWidget(self.viewer_container)

        # Set split sizes (20% sidebar, 80% hex viewer)
        self.main_splitter.setSizes([200, 800])

        # Set background colors for better contrast
        sidebar_palette = self.sidebar.palette()
        sidebar_palette.setColor(self.sidebar.backgroundRole(), Qt.GlobalColor.lightGray)
        self.sidebar.setPalette(sidebar_palette)
        self.sidebar.setAutoFillBackground(True)

        # Apply style sheet for better visibility
        self.setStyleSheet("""
            QDialog {
                background-color: #E8E8E8;
            }
            QToolBar {
                background-color: #D0D0D0;
                border-bottom: 1px solid #A0A0A0;
            }
            QLabel {
                color: #202020;
            }
            QComboBox {
                background-color: white;
                color: black;
            }
            QListWidget {
                background-color: white;
                color: black;
            }
        """)

        # Create status bar
        self.status_bar = QStatusBar()
        layout.addWidget(self.status_bar)

        # Connect signals
        self.hex_viewer.selection_changed.connect(self.update_status_bar)
        self.hex_viewer.offset_changed.connect(self.update_status_bar)
        self.hex_viewer.data_changed.connect(self.update_status_bar)
        self.hex_viewer.view_mode_changed.connect(self.update_view_mode_combo)

        # Load file if provided
        if file_path:
            self.load_file(file_path, read_only)

        logger.debug("HexViewerDialog initialized")

    def create_toolbar(self) -> QToolBar:
        """Create the toolbar with controls.

        Returns:
            Configured toolbar

        """
        toolbar = QToolBar()
        toolbar.setIconSize(QSize(16, 16))
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)

        # File operations
        open_action = QAction("Open", self)
        open_action.setStatusTip("Open a file")
        open_action.triggered.connect(self.open_file)
        toolbar.addAction(open_action)

        save_action = QAction("Save", self)
        save_action.setStatusTip("Save changes")
        save_action.triggered.connect(self.save_file)
        toolbar.addAction(save_action)

        export_action = QAction("Export...", self)
        export_action.setStatusTip("Export file or selection")
        export_action.triggered.connect(self.show_export_dialog)
        toolbar.addAction(export_action)

        # Toggle edit mode
        self.edit_mode_action = QAction("Enable Editing", self)
        self.edit_mode_action.setStatusTip("Toggle between read-only and editable mode")
        self.edit_mode_action.triggered.connect(self.toggle_edit_mode)
        toolbar.addAction(self.edit_mode_action)

        toolbar.addSeparator()

        toolbar.addSeparator()

        # Navigation
        goto_action = QAction("Jump To", self)
        goto_action.setStatusTip("Jump to offset")
        goto_action.triggered.connect(self.hex_viewer.show_jump_dialog)
        toolbar.addAction(goto_action)

        search_action = QAction("Search", self)
        search_action.setStatusTip("Search for pattern")
        search_action.triggered.connect(self.hex_viewer.show_search_dialog)
        toolbar.addAction(search_action)

        perf_action = QAction("Performance", self)
        perf_action.setStatusTip("Show performance statistics")
        perf_action.triggered.connect(self.hex_viewer.show_performance_dialog)
        toolbar.addAction(perf_action)

        toolbar.addSeparator()

        # Tools menu
        checksum_action = QAction("Checksums", self)
        checksum_action.setStatusTip("Calculate checksums and hashes")
        checksum_action.triggered.connect(self.show_checksum_dialog)
        toolbar.addAction(checksum_action)

        statistics_action = QAction("Statistics", self)
        statistics_action.setStatusTip("Analyze statistical properties of data")
        statistics_action.triggered.connect(self.show_statistics_dialog)
        toolbar.addAction(statistics_action)

        toolbar.addSeparator()

        # View options
        view_mode_label = QLabel("View Mode:")
        toolbar.addWidget(view_mode_label)

        self.view_mode_combo = QComboBox()
        self.view_mode_combo.addItems(ViewMode.names())
        self.view_mode_combo.setCurrentText(ViewMode.HEX.name.capitalize())
        self.view_mode_combo.currentTextChanged.connect(self.change_view_mode)
        toolbar.addWidget(self.view_mode_combo)

        bytes_row_label = QLabel("Bytes/Row:")
        toolbar.addWidget(bytes_row_label)

        self.bytes_row_combo = QComboBox()
        self.bytes_row_combo.addItems(["8", "16", "24", "32", "64"])
        self.bytes_row_combo.setCurrentText("16")
        self.bytes_row_combo.currentTextChanged.connect(self.change_bytes_per_row)
        toolbar.addWidget(self.bytes_row_combo)

        group_label = QLabel("Grouping:")
        toolbar.addWidget(group_label)

        self.group_combo = QComboBox()
        self.group_combo.addItems(["1", "2", "4", "8"])
        self.group_combo.setCurrentText("1")
        self.group_combo.currentTextChanged.connect(self.change_group_size)
        toolbar.addWidget(self.group_combo)

        toolbar.addSeparator()

        # Bookmarks
        bookmark_action = QAction("Bookmark", self)
        bookmark_action.setStatusTip("Add bookmark")
        bookmark_action.triggered.connect(self.hex_viewer.add_bookmark_dialog)
        toolbar.addAction(bookmark_action)

        return toolbar

    def create_menus(self) -> QMenuBar:
        """Create the menu bar with menus.
        
        Returns:
            Configured menu bar
        """
        menu_bar = QMenuBar()

        # File menu
        file_menu = menu_bar.addMenu("File")

        open_action = QAction("Open...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)

        save_action = QAction("Save", self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self.save_file)
        file_menu.addAction(save_action)

        file_menu.addSeparator()

        export_action = QAction("Export...", self)
        export_action.triggered.connect(self.show_export_dialog)
        file_menu.addAction(export_action)

        file_menu.addSeparator()

        compare_action = QAction("Compare...", self)
        compare_action.setShortcut("Ctrl+Shift+C")
        compare_action.triggered.connect(self.show_compare_dialog)
        file_menu.addAction(compare_action)

        file_menu.addSeparator()

        print_action = QAction("Print...", self)
        print_action.setShortcut("Ctrl+P")
        print_action.triggered.connect(self.show_print_dialog)
        file_menu.addAction(print_action)

        print_preview_action = QAction("Print Preview...", self)
        print_preview_action.triggered.connect(self.show_print_preview)
        file_menu.addAction(print_preview_action)

        # View menu
        view_menu = menu_bar.addMenu("View")

        split_vertical_action = QAction("Split Vertical", self)
        split_vertical_action.setShortcut("Ctrl+Shift+V")
        split_vertical_action.triggered.connect(self.split_view_vertical)
        view_menu.addAction(split_vertical_action)

        split_horizontal_action = QAction("Split Horizontal", self)
        split_horizontal_action.setShortcut("Ctrl+Shift+H")
        split_horizontal_action.triggered.connect(self.split_view_horizontal)
        view_menu.addAction(split_horizontal_action)

        view_menu.addSeparator()

        close_split_action = QAction("Close Active Split", self)
        close_split_action.setShortcut("Ctrl+W")
        close_split_action.triggered.connect(self.close_active_split)
        view_menu.addAction(close_split_action)

        close_all_splits_action = QAction("Close All Splits", self)
        close_all_splits_action.triggered.connect(self.close_all_splits)
        view_menu.addAction(close_all_splits_action)

        view_menu.addSeparator()

        sync_scrolling_action = QAction("Synchronize Scrolling", self)
        sync_scrolling_action.setCheckable(True)
        sync_scrolling_action.setChecked(True)
        sync_scrolling_action.triggered.connect(self.toggle_sync_scrolling)
        view_menu.addAction(sync_scrolling_action)
        self.sync_scrolling_action = sync_scrolling_action

        # Tools menu
        tools_menu = menu_bar.addMenu("Tools")

        checksum_action = QAction("Checksums...", self)
        checksum_action.triggered.connect(self.show_checksum_dialog)
        tools_menu.addAction(checksum_action)

        statistics_action = QAction("Statistics...", self)
        statistics_action.triggered.connect(self.show_statistics_dialog)
        tools_menu.addAction(statistics_action)

        return menu_bar

    def split_view_vertical(self):
        """Split the view vertically."""
        self.split_view(Qt.Orientation.Vertical)

    def split_view_horizontal(self):
        """Split the view horizontally."""
        self.split_view(Qt.Orientation.Horizontal)

    def split_view(self, orientation: Qt.Orientation):
        """Split the current view.
        
        Args:
            orientation: Split orientation (Vertical or Horizontal)
        """
        if len(self.viewers) >= 4:
            QMessageBox.warning(self, "Maximum Splits", "Maximum of 4 views is already reached.")
            return

        # Create new hex viewer
        new_viewer = HexViewerWidget(self)

        # Copy file from active viewer if one is loaded
        if self.active_viewer and hasattr(self.active_viewer, 'file_handler'):
            if self.active_viewer.file_handler and hasattr(self.active_viewer.file_handler, 'file_path'):
                file_path = self.active_viewer.file_handler.file_path
                read_only = self.active_viewer.file_handler.read_only
                new_viewer.load_file(file_path, read_only)

                # Sync position
                if self.sync_scrolling_action.isChecked():
                    new_viewer.vertical_scroll_bar.setValue(
                        self.active_viewer.vertical_scroll_bar.value()
                    )

        # Set up synchronization if enabled
        if self.sync_scrolling_action.isChecked():
            self.setup_viewer_sync(new_viewer)

        # Track focus changes
        new_viewer.focusInEvent = lambda event: self.set_active_viewer(new_viewer)

        # Add to tracking
        self.viewers.append(new_viewer)

        # Handle layout based on current state
        if len(self.viewers) == 2:
            # First split - set orientation and add
            self.viewer_splitter.setOrientation(orientation)
            self.viewer_splitter.addWidget(new_viewer)
        else:
            # Multiple splits - need nested splitters
            # Remove all widgets from main splitter
            widgets = []
            for i in range(self.viewer_splitter.count()):
                widgets.append(self.viewer_splitter.widget(i))

            # Clear the splitter
            for widget in widgets:
                widget.setParent(None)

            # Create new nested layout
            if orientation == Qt.Orientation.Vertical:
                # Create horizontal splitter containing vertical splits
                new_splitter = QSplitter(Qt.Orientation.Horizontal)

                # Add existing viewers to left split
                left_split = QSplitter(Qt.Orientation.Vertical)
                for widget in widgets:
                    left_split.addWidget(widget)
                new_splitter.addWidget(left_split)

                # Add new viewer to right
                new_splitter.addWidget(new_viewer)
            else:
                # Create vertical splitter containing horizontal splits
                new_splitter = QSplitter(Qt.Orientation.Vertical)

                # Add existing viewers to top split
                top_split = QSplitter(Qt.Orientation.Horizontal)
                for widget in widgets:
                    top_split.addWidget(widget)
                new_splitter.addWidget(top_split)

                # Add new viewer to bottom
                new_splitter.addWidget(new_viewer)

            # Replace the viewer splitter
            self.viewer_layout.removeWidget(self.viewer_splitter)
            self.viewer_splitter.deleteLater()
            self.viewer_splitter = new_splitter
            self.viewer_layout.addWidget(self.viewer_splitter)

        # Set equal sizes
        sizes = [100] * self.viewer_splitter.count()
        self.viewer_splitter.setSizes(sizes)

    def close_active_split(self):
        """Close the active split view."""
        if len(self.viewers) <= 1:
            return

        if self.active_viewer and self.active_viewer != self.hex_viewer:
            # Remove from list
            self.viewers.remove(self.active_viewer)

            # Remove widget
            self.active_viewer.setParent(None)
            self.active_viewer.deleteLater()

            # Set new active viewer
            self.active_viewer = self.viewers[0] if self.viewers else self.hex_viewer

            # Reorganize splitter if needed
            if len(self.viewers) == 1:
                # Back to single view
                self.viewer_splitter.setOrientation(Qt.Orientation.Vertical)

    def close_all_splits(self):
        """Close all split views except the primary."""
        for viewer in self.viewers[:]:
            if viewer != self.hex_viewer:
                viewer.setParent(None)
                viewer.deleteLater()
                self.viewers.remove(viewer)

        self.viewers = [self.hex_viewer]
        self.active_viewer = self.hex_viewer

        # Reset splitter
        self.viewer_splitter.setOrientation(Qt.Orientation.Vertical)

    def toggle_sync_scrolling(self, checked: bool):
        """Toggle synchronized scrolling between views.
        
        Args:
            checked: Whether sync is enabled
        """
        if checked:
            # Set up synchronization for all viewers
            for viewer in self.viewers:
                self.setup_viewer_sync(viewer)
        else:
            # Remove synchronization
            for viewer in self.viewers:
                try:
                    viewer.vertical_scroll_bar.valueChanged.disconnect()
                    viewer.horizontal_scroll_bar.valueChanged.disconnect()
                except:
                    pass

    def setup_viewer_sync(self, viewer: HexViewerWidget):
        """Set up scrolling synchronization for a viewer.
        
        Args:
            viewer: Viewer to set up sync for
        """
        def sync_vertical(value):
            if not self.sync_scrolling_action.isChecked():
                return
            for other in self.viewers:
                if other != viewer and hasattr(other, 'vertical_scroll_bar'):
                    other.vertical_scroll_bar.blockSignals(True)
                    other.vertical_scroll_bar.setValue(value)
                    other.vertical_scroll_bar.blockSignals(False)

        def sync_horizontal(value):
            if not self.sync_scrolling_action.isChecked():
                return
            for other in self.viewers:
                if other != viewer and hasattr(other, 'horizontal_scroll_bar'):
                    other.horizontal_scroll_bar.blockSignals(True)
                    other.horizontal_scroll_bar.setValue(value)
                    other.horizontal_scroll_bar.blockSignals(False)

        viewer.vertical_scroll_bar.valueChanged.connect(sync_vertical)
        viewer.horizontal_scroll_bar.valueChanged.connect(sync_horizontal)

    def set_active_viewer(self, viewer: HexViewerWidget):
        """Set the active viewer.
        
        Args:
            viewer: Viewer to make active
        """
        self.active_viewer = viewer

        # Update UI to reflect active viewer
        for v in self.viewers:
            if v == viewer:
                v.setStyleSheet("border: 2px solid #4080ff;")
            else:
                v.setStyleSheet("border: 1px solid #808080;")

    def create_sidebar(self) -> QFrame:
        """Create the sidebar with bookmark list and other panels.

        Returns:
            Configured sidebar frame

        """
        sidebar = QFrame()
        sidebar.setFrameShape(QFrame.StyledPanel)
        sidebar.setFrameShadow(QFrame.Sunken)

        # Sidebar layout
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        # Bookmarks section
        bookmarks_label = QLabel("Bookmarks")
        bookmarks_label.setAlignment(Qt.AlignCenter)
        bookmarks_label.setStyleSheet("background-color: #E0E0E0; padding: 2px;")
        sidebar_layout.addWidget(bookmarks_label)

        self.bookmarks_list = QListWidget()
        self.bookmarks_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.bookmarks_list.customContextMenuRequested.connect(self.show_bookmark_context_menu)
        self.bookmarks_list.itemDoubleClicked.connect(self.jump_to_bookmark)
        sidebar_layout.addWidget(self.bookmarks_list)

        # Search results section
        search_label = QLabel("Search Results")
        search_label.setAlignment(Qt.AlignCenter)
        search_label.setStyleSheet("background-color: #E0E0E0; padding: 2px;")
        sidebar_layout.addWidget(search_label)

        self.search_list = QListWidget()
        self.search_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.search_list.customContextMenuRequested.connect(self.show_search_context_menu)
        self.search_list.itemDoubleClicked.connect(self.jump_to_search_result)
        sidebar_layout.addWidget(self.search_list)

        return sidebar

    def load_file(self, file_path: str, read_only: bool = True) -> bool:
        """Load a file into the hex viewer.

        Args:
            file_path: Path to the file to load
            read_only: Whether to open the file in read-only mode

        Returns:
            True if the file was loaded successfully, False otherwise

        """
        try:
            logger.info(
                "HexDialog.load_file: Attempting to load %s, read_only=%s", file_path, read_only
            )

            # Check if file exists and is accessible
            if not os.path.exists(file_path):
                error_msg = f"File does not exist: {file_path}"
                logger.error(error_msg)
                self.status_bar.showMessage(error_msg)
                return False

            # Check if file is readable
            if not os.access(file_path, os.R_OK):
                error_msg = f"No permission to read file: {file_path}"
                logger.error(error_msg)
                self.status_bar.showMessage(error_msg)
                return False

            # Get file size before loading
            try:
                file_size = os.path.getsize(file_path)
                logger.debug("File size: %s bytes", file_size)
            except (OSError, ValueError, RuntimeError) as e:
                logger.warning("Could not get file size: %s", e)

            # Attempt to load the file
            result = self.hex_viewer.load_file(file_path, read_only)

            if result:
                # Update window title
                filename = os.path.basename(file_path)
                mode_str = "Read-Only" if read_only else "Editable"
                self.setWindowTitle(f"Enhanced Hex Viewer - {filename} ({mode_str})")

                # Update Edit mode button text
                self.edit_mode_action.setText(
                    "Enable Editing" if read_only else "Switch to Read-Only"
                )

                # Update status bar
                self.update_status_bar(0, 0)

                # Force UI update
                self.hex_viewer.viewport().update()
                QApplication.processEvents()  # Process pending UI events

                logger.info("Successfully loaded file %s in %s mode", file_path, mode_str)
            else:
                error_msg = f"Failed to load file: {file_path}"
                logger.error(error_msg)
                self.status_bar.showMessage(error_msg)

            return result
        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"Error loading file: {e!s}"
            logger.error(error_msg, exc_info=True)
            self.status_bar.showMessage(error_msg)
            return False

    def open_file(self):
        """Show file open dialog and load the selected file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open File",
            "",
            "All Files (*)",
        )

        if file_path:
            # Ask if the file should be opened in read-only mode
            read_only = (
                QMessageBox.question(
                    self,
                    "Open Mode",
                    "Open file in read-only mode?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.Yes,
                )
                == QMessageBox.Yes
            )

            self.load_file(file_path, read_only)

    def save_file(self):
        """Save changes to the currently open file."""
        if not hasattr(self.hex_viewer, "file_handler") or not self.hex_viewer.file_handler:
            return

        if self.hex_viewer.file_handler.read_only:
            QMessageBox.information(self, "Read-Only", "The file is opened in read-only mode.")
            return

        # Apply pending edits
        result = self.hex_viewer.apply_edits()

        if result:
            self.status_bar.showMessage("Changes saved successfully")

            # Clear modification highlights
            self.hex_viewer.highlighter.clear_highlights(HighlightType.MODIFICATION)
            self.hex_viewer.viewport().update()
        else:
            self.status_bar.showMessage("Failed to save changes")

    def toggle_edit_mode(self):
        """Toggle between read-only and editable mode."""
        if not hasattr(self.hex_viewer, "file_handler") or not self.hex_viewer.file_handler:
            return

        # Get current file path
        file_path = self.hex_viewer.file_path
        if not file_path:
            return

        # Close current file
        self.hex_viewer.close()

        # Reload in opposite mode
        new_mode = not getattr(self.hex_viewer.file_handler, "read_only", True)

        # Reload file in new mode
        success = self.load_file(file_path, read_only=new_mode)

        if success:
            # Update UI to reflect mode change
            mode_str = "Read-Only" if new_mode else "Editable"
            self.status_bar.showMessage(f"Switched to {mode_str} mode")
            self.edit_mode_action.setText("Enable Editing" if new_mode else "Switch to Read-Only")

            # Update window title
            filename = os.path.basename(file_path)
            self.setWindowTitle(f"Enhanced Hex Viewer - {filename} ({mode_str})")
        else:
            self.status_bar.showMessage(f"Failed to switch edit mode for {file_path}")

        # Force UI update
        self.hex_viewer.viewport().update()

    def show_checksum_dialog(self):
        """Show the checksum calculation dialog."""
        from .checksum_dialog import ChecksumDialog

        if not hasattr(self.hex_viewer, "file_handler") or not self.hex_viewer.file_handler:
            QMessageBox.warning(self, "No File", "Please open a file first.")
            return

        dialog = ChecksumDialog(self, self.hex_viewer)
        dialog.exec()

    def show_statistics_dialog(self):
        """Show the statistical analysis dialog."""
        from .statistics_dialog import StatisticsDialog

        if not hasattr(self.hex_viewer, "file_handler") or not self.hex_viewer.file_handler:
            QMessageBox.warning(self, "No File", "Please open a file first.")
            return

        dialog = StatisticsDialog(self, self.hex_viewer)
        dialog.exec()

    def show_export_dialog(self):
        """Show the export dialog."""
        from .export_dialog import ExportDialog

        if not hasattr(self.hex_viewer, "file_handler") or not self.hex_viewer.file_handler:
            QMessageBox.warning(self, "No File", "Please open a file first.")
            return

        dialog = ExportDialog(self, self.hex_viewer)
        dialog.exec()

    def show_print_dialog(self):
        """Show the print dialog."""
        from .print_dialog import PrintOptionsDialog

        if not hasattr(self.hex_viewer, "file_handler") or not self.hex_viewer.file_handler:
            QMessageBox.warning(self, "No File", "Please open a file first.")
            return

        # Use the active viewer if in split view
        viewer = self.active_viewer if hasattr(self, 'active_viewer') else self.hex_viewer
        dialog = PrintOptionsDialog(self, viewer)
        dialog.exec()

    def show_print_preview(self):
        """Show print preview directly."""
        from .print_dialog import PrintOptionsDialog

        if not hasattr(self.hex_viewer, "file_handler") or not self.hex_viewer.file_handler:
            QMessageBox.warning(self, "No File", "Please open a file first.")
            return

        # Use the active viewer if in split view
        viewer = self.active_viewer if hasattr(self, 'active_viewer') else self.hex_viewer
        dialog = PrintOptionsDialog(self, viewer)
        dialog.show_preview()

    def show_compare_dialog(self):
        """Show the file comparison dialog."""
        # Get current file as initial file if one is open
        initial_file = None
        if hasattr(self.hex_viewer, "file_handler") and self.hex_viewer.file_handler:
            initial_file = self.hex_viewer.file_path

        # Show comparison dialog
        dialog = CompareDialog(self, initial_file)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            settings = dialog.get_settings()
            self.perform_comparison(settings)

    def perform_comparison(self, settings: dict):
        """Perform file comparison and display results.
        
        Args:
            settings: Dictionary with comparison settings
        """
        file1 = settings['file1']
        file2 = settings['file2']
        mode = settings['mode']

        # Create progress dialog
        progress = QProgressDialog("Comparing files...", "Cancel", 0, 100, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setAutoClose(False)
        progress.show()

        # Create comparer
        comparer = BinaryComparer()

        # Create worker thread
        worker = ComparisonWorker(comparer, file1, file2)

        # Connect signals
        def update_progress(current, total):
            if total > 0:
                progress.setValue(int(current * 100 / total))

        def on_finished(differences):
            progress.close()

            if mode == "visual":
                self.show_visual_comparison(file1, file2, differences, settings)
            elif mode == "byte":
                self.show_byte_comparison(differences, settings)
            else:  # structural
                self.show_structural_comparison(differences, settings)

        def on_error(error_msg):
            progress.close()
            QMessageBox.critical(self, "Comparison Error", f"Error comparing files: {error_msg}")

        worker.progress.connect(update_progress)
        worker.finished.connect(on_finished)
        worker.error.connect(on_error)

        # Connect cancel button
        progress.canceled.connect(worker.quit)

        # Start comparison
        worker.start()

    def show_visual_comparison(self, file1: str, file2: str, differences: list, settings: dict):
        """Show visual side-by-side comparison.
        
        Args:
            file1: Path to first file
            file2: Path to second file
            differences: List of DifferenceBlock objects
            settings: Comparison settings
        """
        # Clear existing viewers if in split view
        if hasattr(self, 'viewers') and len(self.viewers) > 1:
            # Remove extra viewers
            while len(self.viewers) > 1:
                viewer = self.viewers.pop()
                viewer.deleteLater()

        # Set up side-by-side view
        self.split_view_horizontal()

        # Load files into viewers
        self.viewers[0].open_file(file1)
        self.viewers[1].open_file(file2)

        # Apply difference highlighting if enabled
        if settings['highlight_differences']:
            self.highlight_comparison_differences(differences)

        # Set up synchronized scrolling if enabled
        if settings['sync_scrolling']:
            self.sync_scrolling = True
            self.setup_synchronized_scrolling()

        # Update window title
        self.setWindowTitle(f"Hex Compare: {os.path.basename(file1)} vs {os.path.basename(file2)}")

        # Show statistics in status bar
        self.show_comparison_stats(differences)

    def highlight_comparison_differences(self, differences: list):
        """Highlight differences in both viewers.
        
        Args:
            differences: List of DifferenceBlock objects
        """
        from .hex_highlighter import Highlight, HighlightType

        # Define colors for different types
        colors = {
            "modified": "#FFE5B4",  # Peach
            "inserted": "#C1FFC1",  # Light green
            "deleted": "#FFB6C1",   # Light pink
        }

        # Highlight in first viewer
        for diff in differences:
            if diff.length1 > 0:
                # Determine color based on type
                diff_type_str = str(diff.diff_type).split('.')[-1].lower()
                color = colors.get(diff_type_str, "#FFFF00")

                # Create highlight
                highlight = Highlight(
                    start=diff.offset1,
                    end=diff.offset1 + diff.length1,
                    color=color,
                    highlight_type=HighlightType.CUSTOM,
                    description=f"{diff_type_str.capitalize()} block"
                )

                # Add to first viewer
                if len(self.viewers) > 0:
                    self.viewers[0].highlighter.add_highlight(highlight)

        # Highlight in second viewer
        for diff in differences:
            if diff.length2 > 0:
                # Determine color based on type
                diff_type_str = str(diff.diff_type).split('.')[-1].lower()
                color = colors.get(diff_type_str, "#FFFF00")

                # Create highlight
                highlight = Highlight(
                    start=diff.offset2,
                    end=diff.offset2 + diff.length2,
                    color=color,
                    highlight_type=HighlightType.CUSTOM,
                    description=f"{diff_type_str.capitalize()} block"
                )

                # Add to second viewer
                if len(self.viewers) > 1:
                    self.viewers[1].highlighter.add_highlight(highlight)

        # Refresh both viewers
        for viewer in self.viewers:
            viewer.viewport().update()

    def show_comparison_stats(self, differences: list):
        """Show comparison statistics in status bar.
        
        Args:
            differences: List of DifferenceBlock objects
        """
        if not differences:
            self.statusBar().showMessage("Files are identical")
        else:
            # Count difference types
            modified = sum(1 for d in differences if "modified" in str(d.diff_type).lower())
            inserted = sum(1 for d in differences if "inserted" in str(d.diff_type).lower())
            deleted = sum(1 for d in differences if "deleted" in str(d.diff_type).lower())

            # Build message
            msg = f"Found {len(differences)} difference blocks: "
            parts = []
            if modified:
                parts.append(f"{modified} modified")
            if inserted:
                parts.append(f"{inserted} inserted")
            if deleted:
                parts.append(f"{deleted} deleted")

            msg += ", ".join(parts)
            self.statusBar().showMessage(msg)

    def show_byte_comparison(self, differences: list, settings: dict):
        """Show detailed byte-by-byte comparison results.
        
        Args:
            differences: List of DifferenceBlock objects
            settings: Comparison settings
        """
        from PyQt6.QtWidgets import QTextEdit

        # Create text view for differences
        text_widget = QTextEdit()
        text_widget.setReadOnly(True)
        text_widget.setFont(QFont("Courier", 10))

        # Format differences
        html = "<html><body>"
        html += "<h2>File Comparison Results</h2>"

        if not differences:
            html += "<p style='color: green;'><b>Files are identical</b></p>"
        else:
            html += f"<p>Found <b>{len(differences)}</b> difference blocks:</p>"
            html += "<table border='1' cellpadding='5'>"
            html += "<tr><th>Type</th><th>File 1 Offset</th><th>File 1 Size</th>"
            html += "<th>File 2 Offset</th><th>File 2 Size</th></tr>"

            for diff in differences:
                diff_type = str(diff.diff_type).split('.')[-1]
                color = {"MODIFIED": "orange", "INSERTED": "green", "DELETED": "red"}.get(diff_type, "black")

                html += f"<tr style='color: {color};'>"
                html += f"<td>{diff_type}</td>"
                html += f"<td>0x{diff.offset1:08X}</td>"
                html += f"<td>{diff.length1}</td>"
                html += f"<td>0x{diff.offset2:08X}</td>"
                html += f"<td>{diff.length2}</td>"
                html += "</tr>"

            html += "</table>"

        html += "</body></html>"
        text_widget.setHtml(html)

        # Create dialog to show results
        result_dialog = QDialog(self)
        result_dialog.setWindowTitle("Comparison Results")
        result_dialog.resize(600, 400)

        layout = QVBoxLayout(result_dialog)
        layout.addWidget(text_widget)

        # Add close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(result_dialog.close)
        layout.addWidget(close_button)

        result_dialog.exec()

    def show_structural_comparison(self, differences: list, settings: dict):
        """Show structural block-level comparison.
        
        Args:
            differences: List of DifferenceBlock objects
            settings: Comparison settings
        """
        from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem

        # Create tree widget for structural view
        tree = QTreeWidget()
        tree.setHeaderLabels(["Block", "Type", "File 1", "File 2", "Size Change"])

        # Group differences by proximity
        grouped = []
        current_group = []
        last_end = -1

        for diff in differences:
            # Check if this difference is close to the last one
            if last_end >= 0 and diff.offset1 - last_end < 256:
                # Add to current group
                current_group.append(diff)
            else:
                # Start new group
                if current_group:
                    grouped.append(current_group)
                current_group = [diff]

            last_end = diff.offset1 + diff.length1

        if current_group:
            grouped.append(current_group)

        # Add groups to tree
        for i, group in enumerate(grouped):
            # Create group item
            group_item = QTreeWidgetItem(tree)
            group_item.setText(0, f"Block {i+1}")

            # Calculate group statistics
            total_modified = sum(d.length1 for d in group if "modified" in str(d.diff_type).lower())
            total_inserted = sum(d.length2 for d in group if "inserted" in str(d.diff_type).lower())
            total_deleted = sum(d.length1 for d in group if "deleted" in str(d.diff_type).lower())

            # Set group type
            if total_modified > total_inserted + total_deleted:
                group_item.setText(1, "Modified")
            elif total_inserted > total_deleted:
                group_item.setText(1, "Expanded")
            elif total_deleted > total_inserted:
                group_item.setText(1, "Reduced")
            else:
                group_item.setText(1, "Changed")

            # Set offsets
            start_offset = group[0].offset1
            end_offset = group[-1].offset1 + group[-1].length1
            group_item.setText(2, f"0x{start_offset:08X}-0x{end_offset:08X}")

            start_offset2 = group[0].offset2
            end_offset2 = group[-1].offset2 + group[-1].length2
            group_item.setText(3, f"0x{start_offset2:08X}-0x{end_offset2:08X}")

            # Set size change
            size_change = (total_inserted - total_deleted)
            if size_change > 0:
                group_item.setText(4, f"+{size_change} bytes")
            elif size_change < 0:
                group_item.setText(4, f"{size_change} bytes")
            else:
                group_item.setText(4, "No change")

            # Add individual differences as children
            for diff in group:
                diff_item = QTreeWidgetItem(group_item)
                diff_type = str(diff.diff_type).split('.')[-1]
                diff_item.setText(1, diff_type)
                diff_item.setText(2, f"0x{diff.offset1:08X} ({diff.length1} bytes)")
                diff_item.setText(3, f"0x{diff.offset2:08X} ({diff.length2} bytes)")

                size_diff = diff.length2 - diff.length1
                if size_diff > 0:
                    diff_item.setText(4, f"+{size_diff}")
                elif size_diff < 0:
                    diff_item.setText(4, f"{size_diff}")
                else:
                    diff_item.setText(4, "0")

        # Expand all items
        tree.expandAll()

        # Create dialog to show results
        result_dialog = QDialog(self)
        result_dialog.setWindowTitle("Structural Comparison")
        result_dialog.resize(700, 500)

        layout = QVBoxLayout(result_dialog)
        layout.addWidget(tree)

        # Add close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(result_dialog.close)
        layout.addWidget(close_button)

        result_dialog.exec()

    def update_status_bar(self, start: int = 0, end: int = None):
        """Update the status bar with current selection and offset information.

        Args:
            start: Start offset of selection or current position
            end: End offset of selection (optional)

        """
        if not hasattr(self.hex_viewer, "file_handler") or not self.hex_viewer.file_handler:
            self.status_bar.showMessage("No file loaded")
            return

        # If end is not provided, use start as both the start and end
        if end is None:
            end = start

        file_size = self.hex_viewer.file_handler.get_file_size()
        current_offset = self.hex_viewer.current_offset

        # Format information
        info = f"Offset: 0x{current_offset:X} ({current_offset}) | File Size: {file_size:,} bytes"

        # Add selection information if there is a selection
        if start >= 0 and end > start:
            selection_size = end - start
            value_str = ""

            # Add selected value if it's a reasonable size
            if selection_size <= 8:
                data = self.hex_viewer.get_selected_data()
                if data:
                    _hex_str = " ".join(f"{b:02X}" for b in data)

                    # Try to interpret as various types based on size
                    if selection_size == 1:
                        # Byte
                        value_str = f" | Value: {data[0]} (0x{data[0]:02X})"
                    elif selection_size == 2:
                        # 16-bit
                        import struct

                        value_le = struct.unpack("<H", data)[0]
                        value_be = struct.unpack(">H", data)[0]
                        value_str = f" | Value: {value_le} LE, {value_be} BE"
                    elif selection_size == 4:
                        # 32-bit
                        import struct

                        try:
                            # Make sure we have exactly 4 bytes
                            if len(data) == 4:
                                value_le = struct.unpack("<I", data)[0]
                                value_be = struct.unpack(">I", data)[0]
                                value_str = f" | Value: {value_le} LE, {value_be} BE"
                            else:
                                # Log the issue but don't crash
                                value_str = f" | Value: <insufficient data: {len(data)}/4 bytes>"
                                logger.debug(
                                    f"Can't show 32-bit value - got {len(data)} bytes, need 4"
                                )
                        except (OSError, ValueError, RuntimeError) as e:
                            value_str = " | Value: <error>"
                            logger.error("Error unpacking 32-bit value: %s", e)
                    elif selection_size == 8:
                        # 64-bit
                        import struct

                        try:
                            # Make sure we have exactly 8 bytes
                            if len(data) == 8:
                                value_le = struct.unpack("<Q", data)[0]
                                value_be = struct.unpack(">Q", data)[0]
                                value_str = f" | Value: {value_le} LE, {value_be} BE"
                            else:
                                # Log the issue but don't crash
                                value_str = f" | Value: <insufficient data: {len(data)}/8 bytes>"
                                logger.debug(
                                    f"Can't show 64-bit value - got {len(data)} bytes, need 8"
                                )
                        except (OSError, ValueError, RuntimeError) as e:
                            value_str = " | Value: <error>"
                            logger.error("Error unpacking 64-bit value: %s", e)

            info += f" | Selection: 0x{start:X}-0x{end-1:X} ({end-start} bytes){value_str}"

        self.status_bar.showMessage(info)

    def update_view_mode_combo(self, mode: ViewMode):
        """Update the view mode combo box to match the current view mode.

        Args:
            mode: Current view mode

        """
        self.view_mode_combo.setCurrentText(mode.name.capitalize())

    def change_view_mode(self, mode_text: str):
        """Change the view mode based on combo box selection.

        Args:
            mode_text: View mode name

        """
        for mode in ViewMode:
            if mode.name.capitalize() == mode_text:
                self.hex_viewer.set_view_mode(mode)
                break

    def change_bytes_per_row(self, value_text: str):
        """Change the number of bytes per row.

        Args:
            value_text: Number of bytes per row as string

        """
        try:
            value = int(value_text)
            self.hex_viewer.set_bytes_per_row(value)
        except ValueError as e:
            self.logger.error("Value error in hex_dialog: %s", e)

    def change_group_size(self, value_text: str):
        """Change the byte grouping size.

        Args:
            value_text: Group size as string

        """
        try:
            value = int(value_text)
            self.hex_viewer.set_group_size(value)
        except ValueError as e:
            self.logger.error("Value error in hex_dialog: %s", e)

    def show_bookmark_context_menu(self, position):
        """Show context menu for bookmarks list.

        Args:
            position: Position where the menu should be shown

        """
        item = self.bookmarks_list.itemAt(position)
        if not item:
            return

        menu = QMenu()

        goto_action = menu.addAction("Jump to Bookmark")
        goto_action.triggered.connect(lambda: self.jump_to_bookmark(item))

        remove_action = menu.addAction("Remove Bookmark")
        remove_action.triggered.connect(lambda: self.remove_bookmark(item))

        menu.exec_(self.bookmarks_list.mapToGlobal(position))

    def show_search_context_menu(self, position):
        """Show context menu for search results list.

        Args:
            position: Position where the menu should be shown

        """
        item = self.search_list.itemAt(position)
        if not item:
            return

        menu = QMenu()

        goto_action = menu.addAction("Jump to Result")
        goto_action.triggered.connect(lambda: self.jump_to_search_result(item))

        clear_action = menu.addAction("Clear Results")
        clear_action.triggered.connect(self.clear_search_results)

        menu.exec_(self.search_list.mapToGlobal(position))

    def jump_to_bookmark(self, item):
        """Jump to the location of a bookmark.

        Args:
            item: List widget item for the bookmark

        """
        highlight_id = item.data(Qt.UserRole)
        highlight = self.hex_viewer.highlighter.get_highlight_by_id(highlight_id)

        if highlight:
            self.hex_viewer.select_range(highlight.start, highlight.end)

    def remove_bookmark(self, item):
        """Remove a bookmark.

        Args:
            item: List widget item for the bookmark

        """
        highlight_id = item.data(Qt.UserRole)
        if self.hex_viewer.highlighter.remove_highlight(highlight_id):
            # Remove from list
            row = self.bookmarks_list.row(item)
            self.bookmarks_list.takeItem(row)

            # Update the view
            self.hex_viewer.viewport().update()

    def jump_to_search_result(self, item):
        """Jump to the location of a search result.

        Args:
            item: List widget item for the search result

        """
        highlight_id = item.data(Qt.UserRole)
        highlight = self.hex_viewer.highlighter.get_highlight_by_id(highlight_id)

        if highlight:
            self.hex_viewer.select_range(highlight.start, highlight.end)

    def clear_search_results(self):
        """Clear all search results."""
        # Clear search highlights
        self.hex_viewer.highlighter.clear_highlights(HighlightType.SEARCH_RESULT)

        # Clear the list
        self.search_list.clear()

        # Update the view
        self.hex_viewer.viewport().update()

    def update_bookmark_list(self):
        """Update the bookmarks list from current highlights."""
        self.bookmarks_list.clear()

        # Get all bookmark highlights
        for h in self.hex_viewer.highlighter.highlights:
            if h.highlight_type == HighlightType.BOOKMARK:
                # Create list item
                text = f"0x{h.start:X}: {h.description or 'Bookmark'} ({h.size} bytes)"
                item = QListWidgetItem(text)
                item.setData(Qt.UserRole, h.id)

                # Add to list
                self.bookmarks_list.addItem(item)

    def update_search_list(self):
        """Update the search results list from current highlights."""
        self.search_list.clear()

        # Get all search result highlights
        for h in self.hex_viewer.highlighter.highlights:
            if h.highlight_type == HighlightType.SEARCH_RESULT:
                # Create list item
                query = h.metadata.get("query", "")
                text = f"0x{h.start:X}: {query} ({h.size} bytes)"
                item = QListWidgetItem(text)
                item.setData(Qt.UserRole, h.id)

                # Add to list
                self.search_list.addItem(item)
