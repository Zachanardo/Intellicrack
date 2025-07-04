"""
Dialog for the Hex Viewer/Editor.

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
from typing import Optional

from PyQt5.QtCore import QSize, Qt
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QSplitter,
    QStatusBar,
    QToolBar,
    QVBoxLayout,
)

from .hex_highlighter import HighlightType
from .hex_renderer import ViewMode
from .hex_widget import HexViewerWidget

logger = logging.getLogger('Intellicrack.HexView')


class HexViewerDialog(QDialog):
    """
    Dialog window for hex viewer/editor.

    This dialog integrates the hex viewer widget with additional controls
    for navigation, searching, and display options.
    """

    def __init__(self, parent=None, file_path: Optional[str] = None, read_only: bool = True):
        """
        Initialize the hex viewer dialog.

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
            (screen.height() - size.height()) // 2
        )

        # Create main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)

        # Create the hex viewer widget
        self.hex_viewer = HexViewerWidget(self)

        # Create toolbar
        self.toolbar = self.create_toolbar()
        layout.addWidget(self.toolbar)

        # Create splitter for main content
        self.splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(self.splitter)

        # Add sidebar
        self.sidebar = self.create_sidebar()
        self.splitter.addWidget(self.sidebar)

        # Add hex viewer
        self.splitter.addWidget(self.hex_viewer)

        # Set split sizes (20% sidebar, 80% hex viewer)
        self.splitter.setSizes([200, 800])

        # Set background colors for better contrast
        sidebar_palette = self.sidebar.palette()
        sidebar_palette.setColor(self.sidebar.backgroundRole(), Qt.lightGray)
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
        """
        Create the toolbar with controls.

        Returns:
            Configured toolbar
        """
        toolbar = QToolBar()
        toolbar.setIconSize(QSize(16, 16))
        toolbar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)

        # File operations
        open_action = QAction("Open", self)
        open_action.setStatusTip("Open a file")
        open_action.triggered.connect(self.open_file)
        toolbar.addAction(open_action)

        save_action = QAction("Save", self)
        save_action.setStatusTip("Save changes")
        save_action.triggered.connect(self.save_file)
        toolbar.addAction(save_action)

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

    def create_sidebar(self) -> QFrame:
        """
        Create the sidebar with bookmark list and other panels.

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
        """
        Load a file into the hex viewer.

        Args:
            file_path: Path to the file to load
            read_only: Whether to open the file in read-only mode

        Returns:
            True if the file was loaded successfully, False otherwise
        """
        try:
            logger.info("HexDialog.load_file: Attempting to load %s, read_only=%s", file_path, read_only)

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
                self.edit_mode_action.setText("Enable Editing" if read_only else "Switch to Read-Only")

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
            error_msg = f"Error loading file: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.status_bar.showMessage(error_msg)
            return False

    def open_file(self):
        """Show file open dialog and load the selected file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "All Files (*)"
        )

        if file_path:
            # Ask if the file should be opened in read-only mode
            read_only = QMessageBox.question(
                self, "Open Mode",
                "Open file in read-only mode?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            ) == QMessageBox.Yes

            self.load_file(file_path, read_only)

    def save_file(self):
        """Save changes to the currently open file."""
        if not hasattr(self.hex_viewer, 'file_handler') or not self.hex_viewer.file_handler:
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
        if not hasattr(self.hex_viewer, 'file_handler') or not self.hex_viewer.file_handler:
            return

        # Get current file path
        file_path = self.hex_viewer.file_path
        if not file_path:
            return

        # Close current file
        self.hex_viewer.close()

        # Reload in opposite mode
        new_mode = not getattr(self.hex_viewer.file_handler, 'read_only', True)

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


    def update_status_bar(self, start: int = 0, end: int = None):
        """
        Update the status bar with current selection and offset information.

        Args:
            start: Start offset of selection or current position
            end: End offset of selection (optional)
        """
        if not hasattr(self.hex_viewer, 'file_handler') or not self.hex_viewer.file_handler:
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
                                logger.debug(f"Can't show 32-bit value - got {len(data)} bytes, need 4")
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
                                logger.debug(f"Can't show 64-bit value - got {len(data)} bytes, need 8")
                        except (OSError, ValueError, RuntimeError) as e:
                            value_str = " | Value: <error>"
                            logger.error("Error unpacking 64-bit value: %s", e)

            info += f" | Selection: 0x{start:X}-0x{end-1:X} ({end-start} bytes){value_str}"

        self.status_bar.showMessage(info)

    def update_view_mode_combo(self, mode: ViewMode):
        """
        Update the view mode combo box to match the current view mode.

        Args:
            mode: Current view mode
        """
        self.view_mode_combo.setCurrentText(mode.name.capitalize())

    def change_view_mode(self, mode_text: str):
        """
        Change the view mode based on combo box selection.

        Args:
            mode_text: View mode name
        """
        for mode in ViewMode:
            if mode.name.capitalize() == mode_text:
                self.hex_viewer.set_view_mode(mode)
                break

    def change_bytes_per_row(self, value_text: str):
        """
        Change the number of bytes per row.

        Args:
            value_text: Number of bytes per row as string
        """
        try:
            value = int(value_text)
            self.hex_viewer.set_bytes_per_row(value)
        except ValueError as e:
            self.logger.error("Value error in hex_dialog: %s", e)
            pass

    def change_group_size(self, value_text: str):
        """
        Change the byte grouping size.

        Args:
            value_text: Group size as string
        """
        try:
            value = int(value_text)
            self.hex_viewer.set_group_size(value)
        except ValueError as e:
            self.logger.error("Value error in hex_dialog: %s", e)
            pass

    def show_bookmark_context_menu(self, position):
        """
        Show context menu for bookmarks list.

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
        """
        Show context menu for search results list.

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
        """
        Jump to the location of a bookmark.

        Args:
            item: List widget item for the bookmark
        """
        highlight_id = item.data(Qt.UserRole)
        highlight = self.hex_viewer.highlighter.get_highlight_by_id(highlight_id)

        if highlight:
            self.hex_viewer.select_range(highlight.start, highlight.end)

    def remove_bookmark(self, item):
        """
        Remove a bookmark.

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
        """
        Jump to the location of a search result.

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
                query = h.metadata.get('query', '')
                text = f"0x{h.start:X}: {query} ({h.size} bytes)"
                item = QListWidgetItem(text)
                item.setData(Qt.UserRole, h.id)

                # Add to list
                self.search_list.addItem(item)
