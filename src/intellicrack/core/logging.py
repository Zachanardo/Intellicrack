"""Logging infrastructure for Intellicrack.

This module provides comprehensive logging configuration including
file rotation, console output, and customizable formatting.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, TextIO


if TYPE_CHECKING:
    from .config import LogConfig

_ERR_INVALID_CONFIG = "expected LogConfig"


class ColoredFormatter(logging.Formatter):
    """Custom formatter that adds color codes for console output.

    Attributes:
        COLORS: Mapping of log levels to ANSI color codes.
        RESET: ANSI reset code.
    """

    COLORS: ClassVar[dict[int, str]] = {
        logging.DEBUG: "\033[36m",
        logging.INFO: "\033[32m",
        logging.WARNING: "\033[33m",
        logging.ERROR: "\033[31m",
        logging.CRITICAL: "\033[35m",
    }
    RESET: ClassVar[str] = "\033[0m"

    def __init__(self, fmt: str | None = None, datefmt: str | None = None) -> None:
        """Initialize the colored formatter.

        Args:
            fmt: Log message format string.
            datefmt: Date format string.
        """
        super().__init__(fmt, datefmt)

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record with color codes.

        Args:
            record: The log record to format.

        Returns:
            Formatted and colorized log message string.
        """
        color = self.COLORS.get(record.levelno, "")
        message = super().format(record)
        if color:
            return f"{color}{message}{self.RESET}"
        return message


class IntellicrackLogger:
    """Application logger with file and console handlers.

    This class manages the logging configuration for the entire application,
    providing both file-based logging with rotation and colorized console output.

    Attributes:
        name: The logger name.
        logger: The underlying Python logger instance.
    """

    DEFAULT_FORMAT: str = (
        "%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(message)s"
    )
    DEFAULT_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"

    def __init__(self, name: str = "intellicrack") -> None:
        """Initialize the Intellicrack logger.

        Args:
            name: The name for this logger instance.
        """
        self.name = name
        self.logger = logging.getLogger(name)
        self._file_handler: RotatingFileHandler | None = None
        self._console_handler: logging.StreamHandler[TextIO] | None = None

    def configure(
        self,
        level: str = "INFO",
        log_dir: Path | None = None,
        file_enabled: bool = True,
        console_enabled: bool = True,
        max_file_size_mb: int = 10,
        backup_count: int = 5,
    ) -> None:
        """Configure the logger with handlers.

        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
            log_dir: Directory for log files.
            file_enabled: Whether to enable file logging.
            console_enabled: Whether to enable console logging.
            max_file_size_mb: Maximum log file size in megabytes.
            backup_count: Number of backup files to keep.
        """
        self.logger.setLevel(getattr(logging, level.upper(), logging.INFO))

        self.logger.handlers.clear()

        if console_enabled:
            self._setup_console_handler()

        if file_enabled and log_dir is not None:
            self._setup_file_handler(log_dir, max_file_size_mb, backup_count)

    def _setup_console_handler(self) -> None:
        """Set up the console handler with colored output."""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        formatter = ColoredFormatter(
            fmt=self.DEFAULT_FORMAT,
            datefmt=self.DEFAULT_DATE_FORMAT,
        )
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        self._console_handler = console_handler

    def _setup_file_handler(
        self,
        log_dir: Path,
        max_file_size_mb: int,
        backup_count: int,
    ) -> None:
        """Set up the rotating file handler.

        Args:
            log_dir: Directory to store log files.
            max_file_size_mb: Maximum file size in megabytes.
            backup_count: Number of backup files to retain.
        """
        log_dir.mkdir(parents=True, exist_ok=True)

        today = datetime.now().strftime("%Y-%m-%d")
        log_file = log_dir / f"intellicrack_{today}.log"

        max_bytes = max_file_size_mb * 1024 * 1024

        file_handler = RotatingFileHandler(
            filename=log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            fmt=self.DEFAULT_FORMAT,
            datefmt=self.DEFAULT_DATE_FORMAT,
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        self._file_handler = file_handler

    def get_logger(self, name: str | None = None) -> logging.Logger:
        """Get a logger instance.

        Args:
            name: Optional child logger name. If None, returns the root logger.

        Returns:
            Logger instance for the specified name.
        """
        if name is None:
            return self.logger
        return self.logger.getChild(name)


_app_logger: IntellicrackLogger | None = None


def setup_logging(config: LogConfig) -> IntellicrackLogger:
    """Set up application logging from configuration.

    Args:
        config: LogConfig instance with logging settings.

    Returns:
        Configured IntellicrackLogger instance.

    Raises:
        TypeError: If config is not a LogConfig instance.
    """
    global _app_logger  # noqa: PLW0603

    from .config import LogConfig as LogConfigType  # noqa: PLC0415

    if not isinstance(config, LogConfigType):
        raise TypeError(_ERR_INVALID_CONFIG)

    log_dir = Path("D:/Intellicrack/logs")

    logger = IntellicrackLogger("intellicrack")
    logger.configure(
        level=config.level,
        log_dir=log_dir,
        file_enabled=config.file_enabled,
        console_enabled=config.console_enabled,
        max_file_size_mb=config.max_file_size_mb,
        backup_count=config.backup_count,
    )

    _app_logger = logger
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Get a logger instance for a module.

    Args:
        name: Module name for the logger. If None, returns root app logger.

    Returns:
        Logger instance. Falls back to a basic logger if not configured.
    """
    if _app_logger is None:
        fallback = logging.getLogger("intellicrack")
        if not fallback.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(
                logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
            )
            fallback.addHandler(handler)
            fallback.setLevel(logging.INFO)
        if name:
            return fallback.getChild(name)
        return fallback

    return _app_logger.get_logger(name)


def log_exception(
    logger: logging.Logger,
    message: str,
    exc: BaseException,
    level: int = logging.ERROR,
) -> None:
    """Log an exception with full traceback.

    Args:
        logger: Logger instance to use.
        message: Context message for the exception.
        exc: The exception that occurred.
        level: Log level to use.
    """
    logger.log(level, "%s: %s", message, exc, exc_info=True)


def log_tool_call(
    tool_name: str,
    function_name: str,
    arguments: dict[str, object],
    duration_ms: float | None = None,
) -> None:
    """Log a tool call for debugging and auditing.

    Args:
        tool_name: Name of the tool being called.
        function_name: Name of the function being invoked.
        arguments: Dictionary of function arguments.
        duration_ms: Optional execution duration in milliseconds.
    """
    logger = get_logger("tools")
    args_str = ", ".join(f"{k}={v!r}" for k, v in arguments.items())
    if duration_ms is not None:
        logger.info(
            "Tool call: %s.%s(%s) [%.2fms]",
            tool_name,
            function_name,
            args_str,
            duration_ms,
        )
    else:
        logger.info("Tool call: %s.%s(%s)", tool_name, function_name, args_str)


def log_provider_request(
    provider: str,
    model: str,
    messages_count: int,
    tools_count: int,
) -> None:
    """Log an LLM provider request.

    Args:
        provider: Name of the LLM provider.
        model: Model ID being used.
        messages_count: Number of messages in the request.
        tools_count: Number of tools available.
    """
    logger = get_logger("providers")
    logger.info(
        "LLM request: provider=%s, model=%s, messages=%d, tools=%d",
        provider,
        model,
        messages_count,
        tools_count,
    )


def log_provider_response(
    provider: str,
    model: str,
    tool_calls_count: int,
    duration_ms: float,
) -> None:
    """Log an LLM provider response.

    Args:
        provider: Name of the LLM provider.
        model: Model ID that responded.
        tool_calls_count: Number of tool calls in the response.
        duration_ms: Response time in milliseconds.
    """
    logger = get_logger("providers")
    logger.info(
        "LLM response: provider=%s, model=%s, tool_calls=%d, duration=%.2fms",
        provider,
        model,
        tool_calls_count,
        duration_ms,
    )
