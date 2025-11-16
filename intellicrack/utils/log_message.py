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
from typing import Any, Callable, TypedDict, Unpack

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


class LogMessageKwargs(TypedDict, total=False):
    """Type definition for log_message keyword arguments.

    Attributes:
        context: Optional dictionary with additional context information
        exception: Optional exception object for error logging
        source: Optional source identifier (module, function, etc.)
        timestamp: Optional custom timestamp (defaults to current time)
        persist: Whether to add message to persistent queue for UI display
        notify_ui: Whether to notify registered UI callbacks

    """

    context: dict[str, Any] | None
    exception: Exception | None
    source: str | None
    timestamp: datetime | None
    persist: bool
    notify_ui: bool


# Thread-safe message queue for UI updates
_message_queue: list[dict[str, Any]] = []
_queue_lock: threading.Lock = threading.Lock()
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


def log_debug(message: str, **kwargs: Unpack[LogMessageKwargs]) -> None:
    """Log a debug message with optional context.

    Args:
        message: The debug message to log
        **kwargs: Additional keyword arguments from LogMessageKwargs

    """
    log_message(message, level=MessageLevel.DEBUG, **kwargs)


def log_info(message: str, **kwargs: Unpack[LogMessageKwargs]) -> None:
    """Log an info message with optional context.

    Args:
        message: The info message to log
        **kwargs: Additional keyword arguments from LogMessageKwargs

    """
    log_message(message, level=MessageLevel.INFO, **kwargs)


def log_warning(message: str, **kwargs: Unpack[LogMessageKwargs]) -> None:
    """Log a warning message with optional context.

    Args:
        message: The warning message to log
        **kwargs: Additional keyword arguments from LogMessageKwargs

    """
    log_message(message, level=MessageLevel.WARNING, **kwargs)


def log_error(message: str, **kwargs: Unpack[LogMessageKwargs]) -> None:
    """Log an error message with optional context.

    Args:
        message: The error message to log
        **kwargs: Additional keyword arguments from LogMessageKwargs

    """
    log_message(message, level=MessageLevel.ERROR, **kwargs)


def log_critical(message: str, **kwargs: Unpack[LogMessageKwargs]) -> None:
    """Log a critical message with optional context.

    Args:
        message: The critical message to log
        **kwargs: Additional keyword arguments from LogMessageKwargs

    """
    log_message(message, level=MessageLevel.CRITICAL, **kwargs)


def log_analysis(message: str, level: str | MessageLevel = MessageLevel.INFO, **kwargs: Unpack[LogMessageKwargs]) -> None:
    """Log an analysis-related message with optional context.

    Args:
        message: The analysis message to log
        level: Message severity level (default: INFO)
        **kwargs: Additional keyword arguments from LogMessageKwargs

    """
    log_message(message, level=level, category=MessageCategory.ANALYSIS, **kwargs)


def log_ui(message: str, level: str | MessageLevel = MessageLevel.INFO, **kwargs: Unpack[LogMessageKwargs]) -> None:
    """Log a UI-related message with optional context.

    Args:
        message: The UI message to log
        level: Message severity level (default: INFO)
        **kwargs: Additional keyword arguments from LogMessageKwargs

    """
    log_message(message, level=level, category=MessageCategory.UI, **kwargs)


def log_security(message: str, level: str | MessageLevel = MessageLevel.WARNING, **kwargs: Unpack[LogMessageKwargs]) -> None:
    """Log a security-related message with optional context.

    Args:
        message: The security message to log
        level: Message severity level (default: WARNING)
        **kwargs: Additional keyword arguments from LogMessageKwargs

    """
    log_message(message, level=level, category=MessageCategory.SECURITY, **kwargs)


def log_performance(message: str, level: str | MessageLevel = MessageLevel.INFO, **kwargs: Unpack[LogMessageKwargs]) -> None:
    """Log a performance-related message with optional context.

    Args:
        message: The performance message to log
        level: Message severity level (default: INFO)
        **kwargs: Additional keyword arguments from LogMessageKwargs

    """
    log_message(message, level=level, category=MessageCategory.PERFORMANCE, **kwargs)


def log_binary_processing(message: str, level: str | MessageLevel = MessageLevel.INFO, **kwargs: Unpack[LogMessageKwargs]) -> None:
    """Log a binary processing message with optional context.

    Args:
        message: The binary processing message to log
        level: Message severity level (default: INFO)
        **kwargs: Additional keyword arguments from LogMessageKwargs

    """
    log_message(message, level=level, category=MessageCategory.BINARY_PROCESSING, **kwargs)


# Legacy compatibility aliases
def log_msg(
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
    """Log a message using legacy alias for backward compatibility.

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

    """
    log_message(
        message,
        level=level,
        category=category,
        context=context,
        exception=exception,
        source=source,
        timestamp=timestamp,
        persist=persist,
        notify_ui=notify_ui,
    )


def message_log(
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
    """Log a message using legacy alias for backward compatibility.

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

    """
    log_message(
        message,
        level=level,
        category=category,
        context=context,
        exception=exception,
        source=source,
        timestamp=timestamp,
        persist=persist,
        notify_ui=notify_ui,
    )
