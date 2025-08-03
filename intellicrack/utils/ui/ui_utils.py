"""User Interface utilities for the Intellicrack framework.

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
from collections.abc import Callable
from enum import Enum
from typing import Any

# Module logger
logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Message types for UI display."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    SUCCESS = "success"
    DEBUG = "debug"


class ProgressTracker:
    """Track and manage progress updates."""

    def __init__(self, total: int = 100, callback: Callable[[int], None] | None = None):
        """Initialize progress tracker.

        Args:
            total: Total progress value
            callback: Optional callback for progress updates

        """
        self.total = total
        self.current = 0
        self.callback = callback
        self.is_cancelled = False

    def update(self, value: int = None, increment: int = None):
        """Update progress value."""
        if self.is_cancelled:
            return

        if increment is not None:
            self.current = min(self.current + increment, self.total)
        elif value is not None:
            self.current = min(value, self.total)

        if self.callback:
            self.callback(self.get_percentage())

    def get_percentage(self) -> int:
        """Get current progress as percentage."""
        if self.total == 0:
            return 100
        return int((self.current / self.total) * 100)

    def cancel(self):
        """Cancel the progress operation."""
        self.is_cancelled = True

    def reset(self):
        """Reset progress to zero."""
        self.current = 0
        self.is_cancelled = False


def show_message(message: str, msg_type: MessageType = MessageType.INFO,
                 title: str = None, parent: Any = None) -> None:
    """Display a message to the user.

    Args:
        message: Message text to display
        msg_type: Type of message (affects styling/icon)
        title: Optional title for the message
        parent: Optional parent widget/window for proper dialog positioning

    """
    if title is None:
        title = msg_type.value.capitalize()

    # Log the message with context if parent is provided
    parent_context = ""
    if parent and hasattr(parent, "objectName"):
        parent_name = parent.objectName()
        if parent_name:
            parent_context = f" (from {parent_name})"
    elif parent and hasattr(parent, "__class__"):
        parent_context = f" (from {parent.__class__.__name__})"

    # Log the message
    if msg_type == MessageType.ERROR:
        logger.error("%s: %s%s", title, message, parent_context)
    elif msg_type == MessageType.WARNING:
        logger.warning("%s: %s%s", title, message, parent_context)
    elif msg_type == MessageType.DEBUG:
        logger.debug("%s: %s%s", title, message, parent_context)
    else:
        logger.info("%s: %s%s", title, message, parent_context)

    # In a real UI implementation, this would show a dialog
    # For now, we print to console with parent context
    parent_info = f" (Parent: {parent.__class__.__name__})" if parent else ""
    print(f"[{msg_type.value.upper()}] {title}: {message}{parent_info}")

    # Store message in parent if it has a message history
    if parent and hasattr(parent, "message_history"):
        parent.message_history.append({
            "type": msg_type.value,
            "title": title,
            "message": message,
            "timestamp": str(type(logger).__module__),  # Simple timestamp placeholder
        })


def get_user_input(prompt: str, default: str = "",
                  title: str = "Input Required", parent: Any = None) -> str | None:
    """Get text input from the user.

    Args:
        prompt: Prompt text to display
        default: Default value
        title: Dialog title
        parent: Optional parent widget for context and positioning

    Returns:
        Optional[str]: User input or None if cancelled

    """
    # Log the input request with parent context
    parent_context = ""
    if parent and hasattr(parent, "objectName"):
        parent_name = parent.objectName()
        if parent_name:
            parent_context = f" (from {parent_name})"
    elif parent and hasattr(parent, "__class__"):
        parent_context = f" (from {parent.__class__.__name__})"

    logger.info("User input requested: %s%s", title, parent_context)

    # In a real UI implementation, this would show an input dialog
    # For now, we use console input with parent information
    try:
        # Sanitize prompt to prevent injection
        safe_prompt = prompt.replace("\n", " ").replace("\r", " ")
        safe_default = default.replace("\n", " ").replace("\r", " ") if default else ""

        # Display context if parent is available
        context_info = f" [{parent.__class__.__name__}]" if parent else ""

        if safe_default:
            user_input = input(f"{title}{context_info} - {safe_prompt} [{safe_default}]: ").strip()
            # Sanitize user input - remove null bytes and newlines
            sanitized = user_input.replace("\0", "").replace("\n", "").replace("\r", "")
            result = sanitized if sanitized else safe_default
        else:
            user_input = input(f"{title}{context_info} - {safe_prompt}: ").strip()
            # Sanitize user input - remove null bytes and newlines
            result = user_input.replace("\0", "").replace("\n", "").replace("\r", "")

        # Store input history in parent if available
        if parent and hasattr(parent, "input_history"):
            parent.input_history.append({
                "prompt": prompt,
                "result": result,
                "title": title,
            })

        return result
    except (KeyboardInterrupt, EOFError) as e:
        logger.error("Error in ui_utils: %s", e)
        return None


def update_progress(progress: int, message: str = None,
                   callback: Callable[[int, str], None] | None = None) -> None:
    """Update progress display.

    Args:
        progress: Progress percentage (0-100)
        message: Optional status message
        callback: Optional callback function

    """
    if callback:
        callback(progress, message)
    # Default console output
    elif message:
        print(f"Progress: {progress}% - {message}")
    else:
        print(f"Progress: {progress}%")


def confirm_action(message: str, title: str = "Confirm Action",
                  parent: Any = None) -> bool:
    """Ask user to confirm an action.

    Args:
        message: Confirmation message
        title: Dialog title
        parent: Optional parent widget

    Returns:
        bool: True if confirmed, False otherwise

    """
    # In a real UI implementation, this would show a confirmation dialog
    # For now, we use console input (parent parameter reserved for future GUI integration)
    logger.debug(f"Console confirmation dialog (parent: {parent is not None})")
    try:
        # Sanitize title and message to prevent injection
        safe_title = title.replace("\n", " ").replace("\r", " ")
        safe_message = message.replace("\n", " ").replace("\r", " ")
        response = input(f"{safe_title}: {safe_message} (y/n): ").strip().lower()  # Input validated below
        # Validate response - only accept specific values (y/yes)
        return response in ("y", "yes")
    except (KeyboardInterrupt, EOFError) as e:
        logger.error("Error in ui_utils: %s", e)
        return False


def select_from_list(items: list[str], prompt: str = "Select an item",
                    title: str = "Selection", allow_multiple: bool = False,
                    parent: Any = None) -> list[str] | None:
    """Let user select from a list of items.

    Args:
        items: List of items to choose from
        prompt: Selection prompt
        title: Dialog title
        allow_multiple: Whether to allow multiple selection
        parent: Optional parent widget

    Returns:
        Optional[List[str]]: Selected items or None if cancelled

    """
    if not items:
        return None

    # Console implementation (parent parameter reserved for future GUI integration)
    logger.debug(f"Console selection dialog (parent: {parent is not None})")
    print(f"\n{title}: {prompt}")
    for i, item in enumerate(items, 1):
        print(f"  {i}. {item}")

    try:
        if allow_multiple:
            user_input = input("Enter numbers separated by commas (or 'all'): ").strip()
            # Sanitize input
            selections = user_input.replace("\0", "").replace("\n", "").replace("\r", "")

            if selections.lower() == "all":
                return items

            selected = []
            for s in selections.split(","):
                try:
                    # Validate that input is a number
                    s_clean = s.strip()
                    if not s_clean.isdigit():
                        continue
                    idx = int(s_clean) - 1
                    if 0 <= idx < len(items):
                        selected.append(items[idx])
                except ValueError as e:
                    logger.error("Value error in ui_utils: %s", e)
                    continue
            return selected if selected else None
        user_input = input("Enter number: ").strip()
        # Sanitize and validate input
        selection = user_input.replace("\0", "").replace("\n", "").replace("\r", "")
        if not selection.isdigit():
            return None
        idx = int(selection) - 1
        if 0 <= idx < len(items):
            return [items[idx]]
        return None

    except (KeyboardInterrupt, EOFError, ValueError) as e:
        logger.error("Error in ui_utils: %s", e)
        return None


def create_status_bar_message(message: str, timeout: int = 5000) -> dict[str, Any]:
    """Create a status bar message configuration.

    Args:
        message: Status message
        timeout: Display timeout in milliseconds

    Returns:
        dict: Status bar configuration

    """
    return {
        "message": message,
        "timeout": timeout,
        "timestamp": None,  # Will be set when displayed
    }


def format_table_data(headers: list[str], rows: list[list[Any]],
                     max_width: int = 80) -> str:
    """Format data as a text table.

    Args:
        headers: Column headers
        rows: Data rows
        max_width: Maximum table width

    Returns:
        str: Formatted table

    """
    if not headers or not rows:
        return ""

    # Calculate column widths
    col_widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))

    # Adjust widths if total exceeds max_width
    total_width = sum(col_widths) + len(col_widths) * 3 - 1
    if total_width > max_width:
        scale = max_width / total_width
        col_widths = [int(w * scale) for w in col_widths]

    # Format table
    lines = []

    # Header
    header_parts = []
    for i, header in enumerate(headers):
        if i < len(col_widths):
            header_parts.append(str(header).ljust(col_widths[i])[:col_widths[i]])
    lines.append(" | ".join(header_parts))

    # Separator
    sep_parts = ["-" * w for w in col_widths[:len(headers)]]
    lines.append("-+-".join(sep_parts))

    # Rows
    for row in rows:
        row_parts = []
        for i, cell in enumerate(row):
            if i < len(col_widths):
                row_parts.append(str(cell).ljust(col_widths[i])[:col_widths[i]])
        lines.append(" | ".join(row_parts))

    return "\n".join(lines)


class UIUpdateQueue:
    """Queue for batching UI updates."""

    def __init__(self):
        """Initialize the update queue."""
        self.updates: list[tuple[str, Any]] = []

    def add_update(self, update_type: str, data: Any):
        """Add an update to the queue."""
        self.updates.append((update_type, data))

    def flush(self, callback: Callable[[str, Any], None]):
        """Flush all queued updates.

        Args:
            callback: Function to process each update

        """
        for update_type, data in self.updates:
            callback(update_type, data)
        self.updates.clear()

    def clear(self):
        """Clear all queued updates."""
        self.updates.clear()


# Exported functions and classes
__all__ = [
    "MessageType",
    "ProgressTracker",
    "UIUpdateQueue",
    "confirm_action",
    "create_status_bar_message",
    "format_table_data",
    "get_user_input",
    "select_from_list",
    "show_message",
    "update_progress",
]
