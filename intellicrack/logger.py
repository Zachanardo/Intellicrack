"""This file is part of Intellicrack.
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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import logging

"""
Re-export logger from utils.logger for backward compatibility

This module provides a simple re-export of the logger utilities from
intellicrack.utils.logger to maintain backward compatibility with code
that imports from intellicrack.logger.
"""

# Create a default logger to avoid circular imports
logger = logging.getLogger("IntellicrackLogger")

# Define what's exported from this module
__all__ = [
    "configure_logging",
    "get_logger",
    "log_exception",
    "log_execution_time",
    "log_message",
    "log_method_call",
    "logger",
    "setup_logger",
    "setup_logging",
]

# Import and re-export from utils.logger without wildcards to avoid issues
try:
    from intellicrack.utils.logger import (
        configure_logging,
        get_logger,
        log_message,
        setup_logger,
        setup_logging,
    )
    from intellicrack.utils.logger import log_function_call as log_exception
    from intellicrack.utils.logger import log_function_call as log_execution_time
    from intellicrack.utils.logger import log_function_call as log_method_call
except ImportError:
    # Fallback functions if utils.logger can't be imported
    def get_logger(name=None):
        """Get a logger instance with the specified name.

        This is a fallback implementation used when the main logger utilities
        cannot be imported. It provides basic logging functionality using
        Python's standard logging module.

        Args:
            name: Optional name for the logger. If not provided, uses
                 "IntellicrackLogger" as the default name.

        Returns:
            logging.Logger: A configured logger instance

        Example:
            >>> logger = get_logger("MyModule")
            >>> logger.info("Starting processing")

        """
        return logging.getLogger(name or "IntellicrackLogger")

    def log_execution_time(func):
        """Decorator to log function execution time (fallback implementation).

        This is a no-op fallback that simply returns the function unchanged
        when the main logger utilities are not available.

        Args:
            func: Function to decorate

        Returns:
            The original function unchanged

        Note:
            In production, the actual implementation from utils.logger
            would measure and log execution time.

        """
        return func

    def log_exception(func):
        """Decorator to log exceptions in functions (fallback implementation).

        This is a no-op fallback that simply returns the function unchanged
        when the main logger utilities are not available.

        Args:
            func: Function to decorate

        Returns:
            The original function unchanged

        Note:
            In production, the actual implementation from utils.logger
            would catch and log exceptions before re-raising them.

        """
        return func

    def log_method_call(func):
        """Decorator to log method calls (fallback implementation).

        This is a no-op fallback that simply returns the function unchanged
        when the main logger utilities are not available.

        Args:
            func: Method to decorate

        Returns:
            The original method unchanged

        Note:
            In production, the actual implementation from utils.logger
            would log method entry and exit with parameters.

        """
        return func

    def setup_logger(*args, **kwargs):
        """Set up a logger with the specified configuration (fallback implementation).

        This fallback provides basic logger setup functionality when the main
        logger utilities are not available.

        Args:
            *args: Variable arguments. If first arg is a string, uses it as logger name
            **kwargs: Keyword arguments including:
                     - name: Logger name
                     - level: Logging level
                     - format: Log message format

        Returns:
            logging.Logger: Configured logger instance

        Examples:
            >>> logger = setup_logger("MyModule")
            >>> logger = setup_logger(name="MyModule", level="DEBUG")

        """
        # Use args to configure the logger if provided
        if args and isinstance(args[0], str):
            return logging.getLogger(args[0])
        # Apply any configuration from kwargs
        if "name" in kwargs:
            return logging.getLogger(kwargs["name"])
        return logger

    def configure_logging(*args, **kwargs):
        """Configure the logging system (fallback implementation).

        This fallback provides basic logging configuration when the main
        logger utilities are not available. It sets up logging level and
        format for the default logger.

        Args:
            *args: Variable arguments (unused in fallback)
            **kwargs: Keyword arguments including:
                     - level: Logging level (default: 'INFO')
                     - format: Log message format string

        Side Effects:
            Modifies the global logger configuration

        Example:
            >>> configure_logging(level='DEBUG', format='%(asctime)s - %(message)s')

        """
        # Apply basic configuration using provided arguments
        log_level = kwargs.get("level", "INFO")
        if hasattr(logging, log_level):
            logger.setLevel(getattr(logging, log_level))
        # Configure format if provided
        if "format" in kwargs:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(kwargs["format"]))
            logger.addHandler(handler)

    def setup_logging(*args, **kwargs):
        """Set up logging with file output support (fallback implementation).

        This fallback provides basic logging setup with file handler support
        when the main logger utilities are not available.

        Args:
            *args: Variable arguments:
                  - First arg: filename for log file
                  - Second arg: logging level
            **kwargs: Keyword arguments including:
                     - filename: Log file path
                     - level: Logging level (default: 'INFO')

        Side Effects:
            Configures the global logger with file handler if filename provided

        Example:
            >>> setup_logging('app.log', 'DEBUG')
            >>> setup_logging(filename='app.log', level='INFO')

        """
        # Setup logging with provided configuration
        log_file = kwargs.get("filename", args[0] if args else None)
        if log_file:
            handler = logging.FileHandler(log_file)
            logger.addHandler(handler)
        # Set level from args or kwargs
        level = kwargs.get("level", args[1] if len(args) > 1 else "INFO")
        if hasattr(logging, level):
            logger.setLevel(getattr(logging, level))

    def log_message(message, level="INFO"):
        """Log a message at the specified level (fallback implementation).

        This fallback provides basic message logging functionality when the
        main logger utilities are not available.

        Args:
            message: Message to log
            level: Logging level as string (default: "INFO")
                  Valid levels: DEBUG, INFO, WARNING, ERROR, CRITICAL

        Example:
            >>> log_message("Processing started")
            >>> log_message("Error occurred", "ERROR")

        """
        getattr(logger, level.lower(), logger.info)(message)
