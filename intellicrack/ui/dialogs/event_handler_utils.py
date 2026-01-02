"""Event handler utilities for Intellicrack UI dialogs.

This module provides reusable event handling patterns to reduce code duplication
across dialog implementations. It includes utilities for managing thread signals,
context menus, timers, and UI state transitions.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from collections.abc import Callable

from intellicrack.handlers.pyqt6_handler import QAction, QCloseEvent, QDialog, QMenu, QMessageBox, QPoint, QThread, QTimer, QWidget


class DialogEventHandler:
    """Base event handler for dialog common patterns.

    Provides static methods for creating and managing event handlers used in
    dialog-based UI components, including close confirmations, thread signal
    connections, and context menu creation.
    """

    @staticmethod
    def create_close_confirmation(
        dialog: QDialog,
        condition_check: Callable[[], bool],
        title: str,
        message: str,
        cleanup_action: Callable[[], None] | None = None,
    ) -> Callable[[QCloseEvent], None]:
        """Create a close event handler with confirmation dialog.

        Returns a callable that handles close events, optionally prompting for
        confirmation before allowing the dialog to close.

        Args:
            dialog: The dialog instance to attach the handler to
            condition_check: Function that returns True if confirmation is needed
            title: Title text for the confirmation dialog
            message: Message text for the confirmation dialog
            cleanup_action: Optional cleanup function to call before closing

        Returns:
            Callable that handles QCloseEvent instances and manages confirmation flow.

        """

        def close_event_handler(event: QCloseEvent) -> None:
            if condition_check():
                reply = QMessageBox.question(
                    dialog,
                    title,
                    message,
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if reply == QMessageBox.StandardButton.Yes:
                    if cleanup_action:
                        cleanup_action()
                    event.accept()
                else:
                    event.ignore()
            else:
                event.accept()

        return close_event_handler

    @staticmethod
    def connect_thread_signals(thread: QThread, signal_connections: dict[str, Callable[..., None]]) -> None:
        """Connect multiple thread signals to their handlers.

        Safely connects signal handlers to a thread instance by iterating through
        a mapping of signal names to handler functions. Uses getattr for safe
        attribute access to handle missing signals gracefully.

        Args:
            thread: The QThread instance to attach signals to
            signal_connections: Dict mapping signal attribute names to handler callables

        """
        for signal_name, handler in signal_connections.items():
            if signal := getattr(thread, signal_name, None):
                signal.connect(handler)

    @staticmethod
    def create_context_menu(
        parent: QWidget,
        position_widget: QWidget,
        actions: dict[str, Callable[[], None]],
        condition_check: Callable[[], bool] | None = None,
    ) -> Callable[[QPoint], None]:
        """Create a context menu handler.

        Returns a callable that creates and displays a context menu at a given
        position. Optionally checks a condition before showing the menu.

        Args:
            parent: Parent widget for the context menu
            position_widget: Widget to map the context menu position from
            actions: Dict mapping action display text to callback functions
            condition_check: Optional function to check if menu should be shown

        Returns:
            Callable that accepts a QPoint and displays the context menu.

        """

        def context_menu_handler(position: QPoint) -> None:
            if condition_check and not condition_check():
                return

            menu = QMenu(parent)
            for action_text, callback in actions.items():
                action: QAction | None = menu.addAction(action_text)
                if action is not None:
                    action.triggered.connect(callback)

            menu.exec(position_widget.mapToGlobal(position))

        return context_menu_handler

    @staticmethod
    def create_periodic_timer(interval_ms: int, callback: Callable[[], None]) -> QTimer:
        """Create a timer that calls a function periodically.

        Creates a configured QTimer instance that calls the provided callback
        function repeatedly at the specified interval in milliseconds.

        Args:
            interval_ms: Timer interval in milliseconds
            callback: Function to call on each timeout event

        Returns:
            Configured and started QTimer instance.

        """
        timer = QTimer()
        timer.timeout.connect(callback)
        timer.start(interval_ms)
        return timer

    @staticmethod
    def cleanup_thread(thread: QThread, timeout_seconds: int = 2) -> None:
        """Safely cleanup a thread.

        Gracefully shuts down a QThread by first requesting it to quit, then
        waiting for it to finish. If the thread does not finish within the
        timeout period, forcefully terminates it.

        Args:
            thread: QThread instance to cleanup
            timeout_seconds: Timeout in seconds for waiting for thread to finish

        """
        if thread and thread.isRunning():
            thread.quit()
            if not thread.wait(timeout_seconds * 1000):
                thread.terminate()
                thread.wait()


class UIStateManager:
    """Manages UI state transitions for dialogs.

    Provides functionality to register and apply named UI states that control
    the enabled/disabled status of multiple widgets. Useful for managing
    complex dialog states where multiple widgets need synchronized updates.
    """

    def __init__(self) -> None:
        """Initialize the UIStateManager with default values.

        Creates an empty state mappings dictionary for storing registered states.
        """
        self.state_mappings: dict[str, dict[QWidget, bool]] = {}

    def register_state_mapping(self, state_name: str, widget_states: dict[QWidget, bool]) -> None:
        """Register a state mapping for widgets.

        Stores a named state configuration that maps widgets to their desired
        enabled/disabled status. This state can later be applied with apply_state.

        Args:
            state_name: Unique identifier for the state
            widget_states: Dict mapping QWidget instances to their enabled status

        """
        self.state_mappings[state_name] = widget_states

    def apply_state(self, state_name: str) -> None:
        """Apply a registered state to all widgets.

        Updates all widgets in the registered state mapping by setting their
        enabled status accordingly. Does nothing if the state_name is not found.

        Args:
            state_name: Name of the registered state to apply

        """
        if state_name in self.state_mappings:
            for widget, enabled in self.state_mappings[state_name].items():
                widget.setEnabled(enabled)


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format.

    Converts a byte count to a human-readable string representation with
    appropriate unit suffixes (B, KB, MB, GB, TB).

    Args:
        size_bytes: File size in bytes

    Returns:
        Formatted size string with appropriate unit suffix.

    """
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size_float: float = float(size_bytes)

    while size_float >= 1024 and i < len(size_names) - 1:
        size_float /= 1024.0
        i += 1

    return f"{size_float:.1f} {size_names[i]}"


def create_colored_message(message: str, message_type: str = "info") -> str:
    """Create a colored message with appropriate formatting.

    Wraps a message text in HTML span tags with color styling based on the
    message type. Supports info, warning, error, success, and debug types.

    Args:
        message: The message text to format
        message_type: Type of message determining color (info, warning, error,
            success, debug). Defaults to "info".

    Returns:
        HTML-formatted message string with color styling.

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


__all__ = ["DialogEventHandler", "UIStateManager", "create_colored_message", "format_file_size"]
