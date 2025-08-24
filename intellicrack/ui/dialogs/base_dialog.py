"""Production-ready base dialog class for consistent UI patterns.

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
from typing import Optional

from intellicrack.handlers.pyqt6_handler import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QKeySequence,
    QLabel,
    QPushButton,
    QShortcut,
    Qt,
    QVBoxLayout,
    QWidget,
)

logger = logging.getLogger(__name__)


class BaseDialog(QDialog):
    """Production-ready base dialog class for consistent UI patterns across Intellicrack.

    Features:
    - Consistent dark theme styling
    - Standardized button placement and behavior
    - Keyboard shortcuts (Esc to cancel, Enter to accept)
    - Proper focus management
    - Error state handling
    - Loading state support
    - Automatic size constraints
    - Memory cleanup on close
    """

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        title: str = "Dialog",
        width: int = 600,
        height: int = 400,
        resizable: bool = True,
        show_help: bool = False,
        help_text: str = "",
    ):
        """Initialize the BaseDialog with standardized layout and behavior.

        Args:
            parent: Parent widget
            title: Dialog window title
            width: Initial dialog width
            height: Initial dialog height
            resizable: Whether dialog can be resized
            show_help: Whether to show help button
            help_text: Help text to display when help is clicked
        """
        super().__init__(parent)

        self.logger = logger
        self._help_text = help_text
        self._is_loading = False
        self._error_state = False

        # Window setup
        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(width, height)

        if not resizable:
            self.setFixedSize(width, height)

        # Main layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(15)

        # Content area
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.addWidget(self.content_widget, 1)

        # Status/error label (hidden by default)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.hide()
        self.main_layout.addWidget(self.status_label)

        # Button box
        self._setup_buttons(show_help)

        # Keyboard shortcuts
        self._setup_shortcuts()

        # Apply dark theme styling
        self._apply_theme()

        # Focus management
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

    def _setup_buttons(self, show_help: bool) -> None:
        """Setup standardized button box with OK/Cancel and optional Help."""
        buttons = QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel

        if show_help:
            buttons |= QDialogButtonBox.StandardButton.Help

        self.button_box = QDialogButtonBox(buttons)

        # Connect standard buttons
        self.button_box.accepted.connect(self._on_accept)
        self.button_box.rejected.connect(self._on_reject)

        if show_help:
            self.button_box.helpRequested.connect(self._on_help)

        # Custom button access
        self.ok_button = self.button_box.button(QDialogButtonBox.StandardButton.Ok)
        self.cancel_button = self.button_box.button(QDialogButtonBox.StandardButton.Cancel)

        # Button layout
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(self.button_box)
        self.main_layout.addLayout(button_layout)

    def _setup_shortcuts(self) -> None:
        """Setup keyboard shortcuts for the dialog."""
        # Escape to cancel
        escape_shortcut = QShortcut(QKeySequence(Qt.Key.Key_Escape), self)
        escape_shortcut.activated.connect(self._on_reject)

        # Ctrl+Enter to accept (Enter alone might be used in text fields)
        accept_shortcut = QShortcut(QKeySequence("Ctrl+Return"), self)
        accept_shortcut.activated.connect(self._on_accept)

    def _apply_theme(self) -> None:
        """Apply consistent dark theme styling to the dialog."""
        self.setStyleSheet("""
            QDialog {
                background-color: #1e1e1e;
                color: #ffffff;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 10pt;
            }

            QLabel {
                color: #ffffff;
                padding: 2px;
            }

            QLabel#status_error {
                color: #ff4444;
                background-color: #3a1515;
                border: 1px solid #ff4444;
                border-radius: 4px;
                padding: 8px;
            }

            QLabel#status_success {
                color: #44ff44;
                background-color: #153a15;
                border: 1px solid #44ff44;
                border-radius: 4px;
                padding: 8px;
            }

            QLabel#status_info {
                color: #4488ff;
                background-color: #15253a;
                border: 1px solid #4488ff;
                border-radius: 4px;
                padding: 8px;
            }

            QPushButton {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #3d3d3d;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: 500;
                min-width: 80px;
            }

            QPushButton:hover {
                background-color: #3d3d3d;
                border-color: #00ff00;
            }

            QPushButton:pressed {
                background-color: #1d1d1d;
            }

            QPushButton:disabled {
                background-color: #1a1a1a;
                color: #666666;
                border-color: #2d2d2d;
            }

            QPushButton#primary_button {
                background-color: #00802b;
                border-color: #00ff00;
            }

            QPushButton#primary_button:hover {
                background-color: #00a038;
            }

            QPushButton#danger_button {
                background-color: #801515;
                border-color: #ff4444;
            }

            QPushButton#danger_button:hover {
                background-color: #a01818;
            }

            QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {
                background-color: #252525;
                color: #ffffff;
                border: 1px solid #3d3d3d;
                padding: 6px;
                border-radius: 4px;
            }

            QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus,
            QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {
                border-color: #00ff00;
                outline: none;
            }

            QLineEdit:disabled, QTextEdit:disabled, QPlainTextEdit:disabled,
            QSpinBox:disabled, QDoubleSpinBox:disabled, QComboBox:disabled {
                background-color: #1a1a1a;
                color: #666666;
            }

            QGroupBox {
                color: #ffffff;
                border: 1px solid #3d3d3d;
                border-radius: 4px;
                margin-top: 12px;
                padding-top: 12px;
                font-weight: bold;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                background-color: #1e1e1e;
            }

            QCheckBox, QRadioButton {
                color: #ffffff;
                spacing: 8px;
            }

            QCheckBox::indicator, QRadioButton::indicator {
                width: 16px;
                height: 16px;
                background-color: #252525;
                border: 1px solid #3d3d3d;
                border-radius: 3px;
            }

            QRadioButton::indicator {
                border-radius: 8px;
            }

            QCheckBox::indicator:checked, QRadioButton::indicator:checked {
                background-color: #00ff00;
                border-color: #00ff00;
            }

            QCheckBox::indicator:hover, QRadioButton::indicator:hover {
                border-color: #00ff00;
            }

            QTabWidget::pane {
                background-color: #1e1e1e;
                border: 1px solid #3d3d3d;
            }

            QTabBar::tab {
                background-color: #2d2d2d;
                color: #ffffff;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }

            QTabBar::tab:selected {
                background-color: #1e1e1e;
                border-bottom: 2px solid #00ff00;
            }

            QTabBar::tab:hover {
                background-color: #3d3d3d;
            }

            QScrollBar:vertical {
                background-color: #1e1e1e;
                width: 12px;
                border-radius: 6px;
            }

            QScrollBar::handle:vertical {
                background-color: #3d3d3d;
                border-radius: 6px;
                min-height: 20px;
            }

            QScrollBar::handle:vertical:hover {
                background-color: #4d4d4d;
            }

            QScrollBar:horizontal {
                background-color: #1e1e1e;
                height: 12px;
                border-radius: 6px;
            }

            QScrollBar::handle:horizontal {
                background-color: #3d3d3d;
                border-radius: 6px;
                min-width: 20px;
            }

            QScrollBar::handle:horizontal:hover {
                background-color: #4d4d4d;
            }

            QProgressBar {
                background-color: #252525;
                border: 1px solid #3d3d3d;
                border-radius: 4px;
                text-align: center;
                color: #ffffff;
            }

            QProgressBar::chunk {
                background-color: #00ff00;
                border-radius: 3px;
            }
        """)

    def set_content_layout(self, layout: QVBoxLayout) -> None:
        """Set a custom layout for the content area.

        Args:
            layout: Layout to use for content area
        """
        # Clear existing layout
        while self.content_layout.count():
            item = self.content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Add new layout items
        for i in range(layout.count()):
            item = layout.itemAt(i)
            if item.widget():
                self.content_layout.addWidget(item.widget())
            elif item.layout():
                self.content_layout.addLayout(item.layout())

    def add_content_widget(self, widget: QWidget) -> None:
        """Add a widget to the content area.

        Args:
            widget: Widget to add to content area
        """
        self.content_layout.addWidget(widget)

    def add_content_layout(self, layout) -> None:
        """Add a layout to the content area.

        Args:
            layout: Layout to add to content area
        """
        self.content_layout.addLayout(layout)

    def set_loading(self, loading: bool, message: str = "Loading...") -> None:
        """Set the dialog loading state.

        Args:
            loading: Whether dialog is in loading state
            message: Loading message to display
        """
        self._is_loading = loading
        self.ok_button.setEnabled(not loading)

        if loading:
            self.show_status(message, "info")
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        else:
            self.hide_status()
            QApplication.restoreOverrideCursor()

    def show_error(self, message: str) -> None:
        """Show an error message in the dialog.

        Args:
            message: Error message to display
        """
        self._error_state = True
        self.show_status(message, "error")
        self.logger.error(f"Dialog error: {message}")

    def show_success(self, message: str) -> None:
        """Show a success message in the dialog.

        Args:
            message: Success message to display
        """
        self.show_status(message, "success")

    def show_status(self, message: str, status_type: str = "info") -> None:
        """Show a status message in the dialog.

        Args:
            message: Status message to display
            status_type: Type of status ('info', 'error', 'success')
        """
        self.status_label.setText(message)
        self.status_label.setObjectName(f"status_{status_type}")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
        self.status_label.show()

    def hide_status(self) -> None:
        """Hide the status message."""
        self.status_label.hide()
        self.status_label.clear()
        self._error_state = False

    def set_ok_enabled(self, enabled: bool) -> None:
        """Enable or disable the OK button.

        Args:
            enabled: Whether OK button should be enabled
        """
        self.ok_button.setEnabled(enabled)

    def set_ok_text(self, text: str) -> None:
        """Set custom text for the OK button.

        Args:
            text: Text to display on OK button
        """
        self.ok_button.setText(text)

    def set_cancel_text(self, text: str) -> None:
        """Set custom text for the Cancel button.

        Args:
            text: Text to display on Cancel button
        """
        self.cancel_button.setText(text)

    def add_custom_button(
        self,
        text: str,
        callback,
        button_type: str = "default"
    ) -> QPushButton:
        """Add a custom button to the button box.

        Args:
            text: Button text
            callback: Function to call when button is clicked
            button_type: Button style ('default', 'primary', 'danger')

        Returns:
            The created button
        """
        button = QPushButton(text)
        button.clicked.connect(callback)

        if button_type == "primary":
            button.setObjectName("primary_button")
        elif button_type == "danger":
            button.setObjectName("danger_button")

        self.button_box.addButton(button, QDialogButtonBox.ButtonRole.ActionRole)
        return button

    def validate_input(self) -> bool:
        """Validate dialog input before accepting.

        Override this method in subclasses to provide custom validation.

        Returns:
            True if input is valid, False otherwise
        """
        return True

    def _on_accept(self) -> None:
        """Handle dialog acceptance with validation."""
        if self._is_loading:
            return

        self.hide_status()

        if self.validate_input():
            self.accept()
        else:
            if not self._error_state:
                self.show_error("Please correct the errors before continuing.")

    def _on_reject(self) -> None:
        """Handle dialog rejection."""
        if self._is_loading:
            return

        self.reject()

    def _on_help(self) -> None:
        """Handle help button click."""
        if self._help_text:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(self, "Help", self._help_text)

    def get_result(self) -> dict:
        """Get the dialog result data.

        Override this method in subclasses to return dialog data.

        Returns:
            Dictionary containing dialog result data
        """
        return {}

    def closeEvent(self, event) -> None:
        """Handle dialog close event for cleanup.

        Args:
            event: Close event
        """
        # Restore cursor if it was changed
        if self._is_loading:
            QApplication.restoreOverrideCursor()

        # Clean up any resources
        self.deleteLater()

        super().closeEvent(event)

    def showEvent(self, event) -> None:
        """Handle dialog show event for focus management.

        Args:
            event: Show event
        """
        super().showEvent(event)

        # Set initial focus to first focusable widget
        for widget in self.content_widget.findChildren(QWidget):
            if widget.isEnabled() and widget.focusPolicy() != Qt.FocusPolicy.NoFocus:
                widget.setFocus()
                break
