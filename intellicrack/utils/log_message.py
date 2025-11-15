"""Log message utility for Intellicrack.

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

import logging
import threading
from datetime import datetime
from enum import Enum
from typing import Any, Callable

from intellicrack.utils.logger import logger as main_logger


class MessageLevel(Enum):
    """Message severity levels for log_message function."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class MessageCategory(Enum):
    """Message categories for organized logging."""

    GENERAL = "GENERAL"
    ANALYSIS = "ANALYSIS"
    UI = "UI"
    SECURITY = "SECURITY"
    PERFORMANCE = "PERFORMANCE"
    NETWORK = "NETWORK"
    FILE_IO = "FILE_IO"
    BINARY_PROCESSING = "BINARY_PROCESSING"


# Thread-safe message queue for UI updates
_message_queue = []
_queue_lock = threading.Lock()
_message_callbacks: list[Callable[[str, str, str], None]] = []


def register_message_callback(callback: Callable[[str, str, str], None]) -> None:
    """Register a callback function to receive log messages.

    Args:
        callback: Function that receives (level, category, message) parameters

    """
    with _queue_lock:
        if callback not in _message_callbacks:
            _message_callbacks.append(callback)


def unregister_message_callback(callback: Callable[[str, str, str], None]) -> None:
    """Unregister a message callback function.

    Args:
        callback: Callback function to remove

    """
    with _queue_lock:
        if callback in _message_callbacks:
            _message_callbacks.remove(callback)


def get_message_queue() -> list[dict[str, Any]]:
    """Get a copy of the current message queue.

    Returns:
        List of message dictionaries with timestamp, level, category, and message

    """
    with _queue_lock:
        return _message_queue.copy()


def clear_message_queue() -> None:
    """Clear the message queue."""
    with _queue_lock:
        _message_queue.clear()


def log_message(
    message: str,
    level: str | MessageLevel = MessageLevel.INFO,
    category: str | MessageCategory = MessageCategory.GENERAL,
    *,
    context: dict[str, Any] | None = None,
    exception: Exception | None = None,
    source: str | None = None,
    timestamp: datetime | None = None,
    persist: bool = True,
    notify_ui: bool = True,
) -> None:
    """Enhanced logging function for Intellicrack.

    This function provides centralized logging with UI integration, categorization,
    and context tracking. It's designed to support both console logging and
    GUI message display.

    Args:
        message: The log message to record
        level: Message severity level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        category: Message category for organization and filtering
        context: Optional dictionary with additional context information
        exception: Optional exception object for error logging
        source: Optional source identifier (module, function, etc.)
        timestamp: Optional custom timestamp (defaults to current time)
        persist: Whether to add message to persistent queue for UI display
        notify_ui: Whether to notify registered UI callbacks

    Examples:
        Basic usage:
        >>> log_message("Analysis started")

        With error level and category:
        >>> log_message("Failed to load binary", level="ERROR", category="ANALYSIS")

        With context and exception:
        >>> log_message(
        ...     "Network connection failed",
        ...     level="ERROR",
        ...     category="NETWORK",
        ...     context={"host": "example.com", "port": 443},
        ...     exception=connection_error
        ... )

    """
    # Convert enums to strings if needed
    if isinstance(level, MessageLevel):
        level_str = level.value
    else:
        level_str = str(level).upper()

    if isinstance(category, MessageCategory):
        category_str = category.value
    else:
        category_str = str(category).upper()

    # Use current timestamp if not provided
    if timestamp is None:
        timestamp = datetime.now()

    # Build the full message with context
    full_message_parts = [message]

    if context:
        context_str = ", ".join([f"{k}={v}" for k, v in context.items()])
        full_message_parts.append(f"[Context: {context_str}]")

    if source:
        full_message_parts.append(f"[Source: {source}]")

    if exception:
        full_message_parts.append(f"[Exception: {type(exception).__name__}: {exception}]")

    full_message = " ".join(full_message_parts)

    # Log to standard logging system
    logger_level = getattr(logging, level_str, logging.INFO)
    categorized_message = f"[{category_str}] {full_message}"

    try:
        main_logger.log(logger_level, categorized_message)

        # Also log exception traceback if provided
        if exception and logger_level >= logging.ERROR:
            main_logger.debug("Exception traceback:", exc_info=exception)

    except Exception as log_error:
        # Fallback to print if logging fails
        print(f"[LOGGING ERROR] {categorized_message}")
        print(f"[LOGGING ERROR] Failed to log: {log_error}")

    # Add to message queue for UI persistence
    if persist:
        message_entry = {
            "timestamp": timestamp.isoformat(),
            "level": level_str,
            "category": category_str,
            "message": message,
            "full_message": full_message,
            "context": context,
            "source": source,
            "exception": str(exception) if exception else None,
        }

        with _queue_lock:
            _message_queue.append(message_entry)

            # Limit queue size to prevent memory issues
            max_queue_size = 1000
            if len(_message_queue) > max_queue_size:
                _message_queue.pop(0)

    # Notify registered UI callbacks
    if notify_ui:
        with _queue_lock:
            callbacks_copy = _message_callbacks.copy()

        for callback in callbacks_copy:
            try:
                callback(level_str, category_str, full_message)
            except Exception as callback_error:
                # Don't let callback errors break logging
                try:
                    main_logger.warning(f"Message callback error: {callback_error}")
                except Exception:
                    print(f"[CALLBACK ERROR] {callback_error}")


def log_debug(message: str, **kwargs) -> None:
    """Log for debug purposes."""
    log_message(message, level=MessageLevel.DEBUG, **kwargs)


def log_info(message: str, **kwargs) -> None:
    """Log for info purposes."""
    log_message(message, level=MessageLevel.INFO, **kwargs)


def log_warning(message: str, **kwargs) -> None:
    """Log for warning purposes."""
    log_message(message, level=MessageLevel.WARNING, **kwargs)


def log_error(message: str, **kwargs) -> None:
    """Log for error purposes."""
    log_message(message, level=MessageLevel.ERROR, **kwargs)


def log_critical(message: str, **kwargs) -> None:
    """Log for critical purposes."""
    log_message(message, level=MessageLevel.CRITICAL, **kwargs)


def log_analysis(message: str, level: str | MessageLevel = MessageLevel.INFO, **kwargs) -> None:
    """Log for analysis-related purposes."""
    log_message(message, level=level, category=MessageCategory.ANALYSIS, **kwargs)


def log_ui(message: str, level: str | MessageLevel = MessageLevel.INFO, **kwargs) -> None:
    """Log for UI-related purposes."""
    log_message(message, level=level, category=MessageCategory.UI, **kwargs)


def log_security(message: str, level: str | MessageLevel = MessageLevel.WARNING, **kwargs) -> None:
    """Log for security-related purposes."""
    log_message(message, level=level, category=MessageCategory.SECURITY, **kwargs)


def log_performance(message: str, level: str | MessageLevel = MessageLevel.INFO, **kwargs) -> None:
    """Log for performance-related purposes."""
    log_message(message, level=level, category=MessageCategory.PERFORMANCE, **kwargs)


def log_binary_processing(message: str, level: str | MessageLevel = MessageLevel.INFO, **kwargs) -> None:
    """Log for binary processing purposes."""
    log_message(message, level=level, category=MessageCategory.BINARY_PROCESSING, **kwargs)


# Legacy compatibility aliases
def log_msg(*args, **kwargs) -> None:
    """Legacy alias for log_message."""
    log_message(*args, **kwargs)


def message_log(*args, **kwargs) -> None:
    """Legacy alias for log_message."""
    log_message(*args, **kwargs)
