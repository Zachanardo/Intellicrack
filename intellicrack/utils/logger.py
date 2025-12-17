"""Logging utilities for the Intellicrack framework.

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

import functools
import inspect
import logging
import sys
from collections.abc import Callable
from typing import Any, TypeVar, cast


F = TypeVar("F", bound=Callable[..., Any])
C = TypeVar("C", bound=type)

# Module logger
logger = logging.getLogger(__name__)


def log_message(message: str, level: str = "INFO") -> None:
    """Log a message at the specified level.

    Args:
        message: The message to log
        level: The log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    """
    level = level.upper()
    if level == "CRITICAL":
        logger.critical(message)
    elif level == "DEBUG":
        logger.debug(message)
    elif level == "ERROR":
        logger.error(message)
    elif level == "WARNING":
        logger.warning(message)
    else:
        logger.info(message)


def log_function_call[F: Callable[..., Any]](func: F) -> F:
    """Log function entry, exit, arguments, return value, and exceptions.

    Args:
        func: The function to decorate

    Returns:
        The wrapped function with logging

    """
    # Thread-local storage to prevent recursion
    import threading

    local = threading.local()

    @functools.wraps(func)
    def wrapper(*args: object, **kwargs: object) -> object:
        """Wrap function for debug logging."""
        # Check if we're already in a logging call to prevent recursion
        if hasattr(local, "in_logger") and local.in_logger:
            # Just call the function without logging to avoid recursion
            return func(*args, **kwargs)

        func_name = func.__qualname__

        # Skip logging for certain problematic functions
        if any(skip in func_name for skip in ["__str__", "__repr__", "as_posix", "getline", "getlines"]):
            return func(*args, **kwargs)

        try:
            local.in_logger = True
            # Log function call with arguments
            arg_names = inspect.getfullargspec(func).args
            arg_values = args[: len(arg_names)]

            # Safely represent arguments to avoid issues with large objects
            def safe_repr(obj: object, max_len: int = 100) -> str:
                """Safely represent an object as a string."""
                try:
                    r = repr(obj)
                    if len(r) > max_len:
                        return r[:max_len] + "..."
                    return r
                except (TypeError, ValueError, AttributeError, RecursionError) as e:
                    logger.error("Error in logger: %s", e)
                    return "<repr_failed>"

            arg_strs = [f"{name}={safe_repr(value)}" for name, value in zip(arg_names, arg_values, strict=False)]
            if kwargs:
                arg_strs += [f"{k}={safe_repr(v)}" for k, v in kwargs.items()]

            logger.debug("Entering %s(%s)", func_name, ", ".join(arg_strs))
            result = func(*args, **kwargs)
            logger.debug("Exiting %s with result: %s", func_name, safe_repr(result))
            return result
        except (OSError, ValueError, RuntimeError) as e:
            # Don't use logger.exception to avoid recursion - just log the error
            try:
                logger.error("Exception in %s: %s", func_name, e, exc_info=True)
            except (RuntimeError, OSError) as e:
                logger.error("Error in logger: %s", e)
                print(f"Exception in {func_name}: {e}")
            raise
        finally:
            local.in_logger = False

    # Support async functions
    if inspect.iscoroutinefunction(func):

        @functools.wraps(func)
        async def async_wrapper(*args: object, **kwargs: object) -> object:
            # Check if we're already in a logging call to prevent recursion
            if hasattr(local, "in_logger") and local.in_logger:
                return await func(*args, **kwargs)

            func_name = func.__qualname__

            # Skip logging for certain problematic functions
            if any(skip in func_name for skip in ["__str__", "__repr__", "as_posix", "getline", "getlines"]):
                return await func(*args, **kwargs)

            try:
                local.in_logger = True
                arg_names = inspect.getfullargspec(func).args
                arg_values = args[: len(arg_names)]

                # Use the same safe_repr function for async too
                def safe_repr(obj: object, max_len: int = 100) -> str:
                    """Safely represent an object as a string."""
                    try:
                        r = repr(obj)
                        if len(r) > max_len:
                            return r[:max_len] + "..."
                        return r
                    except (TypeError, ValueError, AttributeError, RecursionError) as e:
                        logger.error("Error in logger: %s", e)
                        return "<repr_failed>"

                arg_strs = [f"{name}={safe_repr(value)}" for name, value in zip(arg_names, arg_values, strict=False)]
                if kwargs:
                    arg_strs += [f"{k}={safe_repr(v)}" for k, v in kwargs.items()]

                logger.debug("Entering async %s(%s)", func_name, ", ".join(arg_strs))
                result = await func(*args, **kwargs)
                logger.debug("Exiting async %s with result: %s", func_name, safe_repr(result))
                return result
            except (OSError, ValueError, RuntimeError) as e:
                # Don't use logger.exception to avoid recursion
                try:
                    logger.error("Exception in async %s: %s", func_name, e, exc_info=True)
                except (RuntimeError, OSError) as e:
                    logger.error("Error in logger: %s", e)
                    print(f"Exception in async {func_name}: {e}")
                raise
            finally:
                local.in_logger = False

        return cast("F", async_wrapper)

    return cast("F", wrapper)


def log_all_methods[C: type](cls: C) -> C:
    """Class decorator to apply log_function_call to all methods of a class.

    Args:
        cls: The class to decorate

    Returns:
        The class with all methods decorated

    """
    for attr_name, attr_value in cls.__dict__.items():
        if callable(attr_value) and not attr_name.startswith("__"):
            setattr(cls, attr_name, log_function_call(attr_value))
    return cls


def setup_logger(
    name: str = "Intellicrack",
    level: int = logging.INFO,
    log_file: str | None = None,
    format_string: str | None = None,
) -> logging.Logger:
    """Set up a logger with the specified configuration.

    Args:
        name: Logger name
        level: Logging level (default: INFO)
        log_file: Optional log file path
        format_string: Optional format string for log messages

    Returns:
        Configured logger instance

    """
    target_logger = logging.getLogger(name)
    target_logger.setLevel(level)

    # Default format if not specified
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    formatter = logging.Formatter(format_string)

    import codecs
    import io

    if sys.platform == "win32":
        try:
            if hasattr(sys.stdout, "reconfigure") and callable(sys.stdout.reconfigure):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            if hasattr(sys.stderr, "reconfigure") and callable(sys.stderr.reconfigure):
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
            elif hasattr(sys.stdout, "buffer"):
                stdout_buffer = getattr(sys.stdout, "buffer", None)
                stderr_buffer = getattr(sys.stderr, "buffer", None)
                if stdout_buffer is not None:
                    sys.stdout = io.TextIOWrapper(stdout_buffer, encoding="utf-8", errors="replace")
                if stderr_buffer is not None:
                    sys.stderr = io.TextIOWrapper(stderr_buffer, encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    target_logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        target_logger.addHandler(file_handler)

    return target_logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Get a logger instance.

    Args:
        name: Logger name (default: caller's module name)

    Returns:
        Logger instance

    """
    if name is None:
        # Get the caller's module name
        frame = inspect.currentframe()
        if frame and frame.f_back:
            name = frame.f_back.f_globals.get("__name__", "Intellicrack")
        else:
            name = "Intellicrack"

    return logging.getLogger(name)


def configure_logging(
    level: int = logging.INFO,
    log_file: str | None = None,
    format_string: str | None = None,
    enable_comprehensive: bool = False,
) -> None:
    """Configure logging for the entire application.

    Args:
        level: Logging level
        log_file: Optional log file path
        format_string: Optional format string
        enable_comprehensive: Whether to enable comprehensive function logging

    """
    # Set up the root logger
    setup_logger("Intellicrack", level, log_file, format_string)

    # Configure comprehensive logging if enabled
    if enable_comprehensive:
        # Set more verbose logging format for comprehensive mode
        comprehensive_format = "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(funcName)s() - %(message)s"
        setup_logger("Intellicrack", logging.DEBUG, log_file, comprehensive_format)
        logger.debug("Comprehensive logging enabled with detailed function tracking")


def setup_logging(
    level: str = "INFO",
    log_file: str | None = None,
    enable_rotation: bool = True,
    max_bytes: int = 10485760,
    backup_count: int = 5,
    enable_console: bool = True,
) -> None:
    """Set up logging for the application with optional log rotation.

    Args:
        level: The logging level as a string (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        enable_rotation: Whether to enable log rotation
        max_bytes: Max size of each log file before rotation (default: 10MB)
        backup_count: Number of backup files to keep (default: 5)
        enable_console: Whether to enable console logging (default: True)

    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        error_msg = f"Invalid log level: {level}"
        logger.error(error_msg)
        raise TypeError(error_msg)

    # Set up handlers
    handlers: list[logging.Handler] = []

    import io

    if sys.platform == "win32":
        try:
            current_encoding = getattr(sys.stdout, "encoding", None)
            if current_encoding is None or current_encoding.lower() not in ["utf-8", "utf8"]:
                if hasattr(sys.stdout, "reconfigure") and callable(sys.stdout.reconfigure):
                    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
                if hasattr(sys.stderr, "reconfigure") and callable(sys.stderr.reconfigure):
                    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            stdout_buffer = getattr(sys.stdout, "buffer", None)
            stderr_buffer = getattr(sys.stderr, "buffer", None)
            if stdout_buffer is not None:
                sys.stdout = io.TextIOWrapper(stdout_buffer, encoding="utf-8", errors="replace")
            if stderr_buffer is not None:
                sys.stderr = io.TextIOWrapper(stderr_buffer, encoding="utf-8", errors="replace")

    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(formatter)
        handlers.append(console_handler)

    # File handler with rotation if log_file is specified
    if log_file:
        file_handler: logging.Handler
        if enable_rotation:
            from logging.handlers import RotatingFileHandler

            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
            )
        else:
            file_handler = logging.FileHandler(log_file)

        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        handlers=handlers,
        force=True,  # Force reconfiguration
    )


def setup_persistent_logging(
    log_dir: str | None = None,
    log_name: str = "intellicrack",
    enable_rotation: bool = True,
    max_bytes: int = 10485760,
    backup_count: int = 5,
) -> str:
    """Set up persistent logging with automatic rotation.

    Args:
        log_dir: Directory for log files (default: ~/intellicrack/logs)
        log_name: Base name for log files
        enable_rotation: Whether to enable log rotation
        max_bytes: Max size of each log file before rotation (default: 10MB)
        backup_count: Number of backup files to keep (default: 5)

    Returns:
        str: Path to the log file

    """
    import os
    from datetime import datetime

    # Default log directory
    if log_dir is None:
        from intellicrack.utils.core.plugin_paths import get_logs_dir

        log_dir = str(get_logs_dir())

    # Create log directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)

    # Create log file name with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"{log_name}_{timestamp}.log")

    # Set up logging with rotation
    setup_logging(
        level="INFO",
        log_file=log_file,
        enable_rotation=enable_rotation,
        max_bytes=max_bytes,
        backup_count=backup_count,
    )

    logger.info("Persistent logging initialized. Log file: %s", log_file)
    logger.info("Log rotation: %s", "Enabled" if enable_rotation else "Disabled")
    logger.info("Max file size: %.1f MB, Backup count: %s", max_bytes / 1024 / 1024, backup_count)

    return log_file


# Alias for compatibility
log_execution_time = log_function_call
log_exception = log_function_call
log_method_call = log_function_call

# Exported functions and classes
__all__ = [
    "configure_logging",
    "get_logger",
    "log_all_methods",
    "log_exception",
    "log_execution_time",
    "log_function_call",
    "log_message",
    "log_method_call",
    "logger",
    "setup_logger",
    "setup_logging",
    "setup_persistent_logging",
]
