"""
Re-export logger from utils.logger for backward compatibility

This module provides a simple re-export of the logger utilities from
intellicrack.utils.logger to maintain backward compatibility with code
that imports from intellicrack.logger.
"""

import logging

# Create a default logger to avoid circular imports
logger = logging.getLogger("IntellicrackLogger")

# Define what's exported from this module
__all__ = [
    'logger',
    'get_logger',
    'log_execution_time',
    'log_exception',
    'log_method_call',
    'setup_logger',
    'configure_logging',
    'setup_logging',
    'log_message'
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
        return logging.getLogger(name or "IntellicrackLogger")

    def log_execution_time(func):
        return func

    def log_exception(func):
        return func

    def log_method_call(func):
        return func

    def setup_logger(*args, **kwargs):
        # Use args to configure the logger if provided
        if args and isinstance(args[0], str):
            return logging.getLogger(args[0])
        # Apply any configuration from kwargs
        if 'name' in kwargs:
            return logging.getLogger(kwargs['name'])
        return logger

    def configure_logging(*args, **kwargs):
        # Apply basic configuration using provided arguments
        log_level = kwargs.get('level', 'INFO')
        if hasattr(logging, log_level):
            logger.setLevel(getattr(logging, log_level))
        # Configure format if provided
        if 'format' in kwargs:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(kwargs['format']))
            logger.addHandler(handler)

    def setup_logging(*args, **kwargs):
        # Setup logging with provided configuration
        log_file = kwargs.get('filename', args[0] if args else None)
        if log_file:
            handler = logging.FileHandler(log_file)
            logger.addHandler(handler)
        # Set level from args or kwargs
        level = kwargs.get('level', args[1] if len(args) > 1 else 'INFO')
        if hasattr(logging, level):
            logger.setLevel(getattr(logging, level))

    def log_message(message, level="INFO"):
        getattr(logger, level.lower(), logger.info)(message)
