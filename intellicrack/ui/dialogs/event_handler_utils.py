"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Event Handler Utilities for Dialog Management

This module provides reusable event handling patterns to reduce
code duplication across dialog implementations.
"""

from typing import Callable, Dict, Optional

from PyQt5.QtCore import QThread, QTimer
from PyQt5.QtGui import QCloseEvent
from PyQt5.QtWidgets import QDialog, QMenu, QMessageBox, QWidget


class DialogEventHandler:
    """Base event handler for dialog common patterns."""

    @staticmethod
    def create_close_confirmation(
        dialog: QDialog,
        condition_check: Callable[[], bool],
        title: str,
        message: str,
        cleanup_action: Optional[Callable] = None,
    ) -> Callable[[QCloseEvent], None]:
        """
        Create a close event handler with confirmation dialog.

        Args:
            dialog: The dialog instance
            condition_check: Function that returns True if confirmation is needed
            title: Title for confirmation dialog
            message: Message for confirmation dialog
            cleanup_action: Optional cleanup function to call before closing

        Returns:
            Close event handler function
        """

        def close_event_handler(event: QCloseEvent):
            if condition_check():
                reply = QMessageBox.question(
                    dialog, title, message, QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    if cleanup_action:
                        cleanup_action()
                    event.accept()
                else:
                    event.ignore()
            else:
                event.accept()

        return close_event_handler

    @staticmethod
    def connect_thread_signals(thread: QThread, signal_connections: Dict[str, Callable]):
        """
        Connect multiple thread signals to their handlers.

        Args:
            thread: The thread instance
            signal_connections: Dict mapping signal names to handler functions
        """
        for signal_name, handler in signal_connections.items():
            signal = getattr(thread, signal_name, None)
            if signal:
                signal.connect(handler)

    @staticmethod
    def create_context_menu(
        parent: QWidget,
        position_widget: QWidget,
        actions: Dict[str, Callable],
        condition_check: Optional[Callable] = None,
    ) -> Callable:
        """
        Create a context menu handler.

        Args:
            parent: Parent widget for the menu
            position_widget: Widget to map position from
            actions: Dict mapping action names to callback functions
            condition_check: Optional function to check if menu should be shown

        Returns:
            Context menu handler function
        """

        def context_menu_handler(position):
            if condition_check and not condition_check():
                return

            menu = QMenu(parent)
            for action_text, callback in actions.items():
                action = menu.addAction(action_text)
                action.triggered.connect(callback)

            menu.exec_(position_widget.mapToGlobal(position))

        return context_menu_handler

    @staticmethod
    def create_periodic_timer(interval_ms: int, callback: Callable) -> QTimer:
        """
        Create a timer that calls a function periodically.

        Args:
            interval_ms: Interval in milliseconds
            callback: Function to call on timeout

        Returns:
            Configured QTimer
        """
        timer = QTimer()
        timer.timeout.connect(callback)
        timer.start(interval_ms)
        return timer

    @staticmethod
    def cleanup_thread(thread: QThread, timeout_seconds: int = 2):
        """
        Safely cleanup a thread.

        Args:
            thread: Thread to cleanup
            timeout_seconds: Timeout for waiting
        """
        if thread and thread.isRunning():
            thread.quit()
            if not thread.wait(timeout_seconds * 1000):
                thread.terminate()
                thread.wait()


class UIStateManager:
    """Manages UI state transitions for dialogs."""

    def __init__(self):
        self.state_mappings = {}

    def register_state_mapping(self, state_name: str, widget_states: Dict[QWidget, bool]):
        """
        Register a state mapping for widgets.

        Args:
            state_name: Name of the state
            widget_states: Dict mapping widgets to their enabled state
        """
        self.state_mappings[state_name] = widget_states

    def apply_state(self, state_name: str):
        """
        Apply a registered state to all widgets.

        Args:
            state_name: Name of the state to apply
        """
        if state_name in self.state_mappings:
            for widget, enabled in self.state_mappings[state_name].items():
                widget.setEnabled(enabled)


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted size string
    """
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0

    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1

    return f"{size_bytes:.1f} {size_names[i]}"


def create_colored_message(message: str, message_type: str = "info") -> str:
    """
    Create a colored message with appropriate formatting.

    Args:
        message: The message text
        message_type: Type of message (info, warning, error, success)

    Returns:
        Formatted message string
    """
    colors = {
        "info": "#0066cc",
        "warning": "#ff9900",
        "error": "#cc0000",
        "success": "#009900",
        "debug": "#666666",
    }

    color = colors.get(message_type, colors["info"])
    return f'<span style="color: {color};">{message}</span>'


__all__ = ["DialogEventHandler", "UIStateManager", "format_file_size", "create_colored_message"]
