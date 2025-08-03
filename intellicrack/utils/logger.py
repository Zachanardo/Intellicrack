"""
Enhanced logging utilities for the Intellicrack framework with structured JSON logging.

This module provides both traditional logging and modern structured logging capabilities
for comprehensive logging in defensive security research environments.

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

import functools
import inspect
import logging
import sys
import time
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar, Union

# Import structured logging capabilities
try:
    from .structured_logging import (
        configure_structured_logging,
        get_structured_logger,
        bind_context,
        clear_context,
        log_exception as struct_log_exception,
        log_performance,
        log_security_event,
        log_analysis_result,
    )
    STRUCTURED_LOGGING_AVAILABLE = True
except ImportError:
    STRUCTURED_LOGGING_AVAILABLE = False

# Type variable for decorators
F = TypeVar('F', bound=Callable[..., Any])

# Module logger - use structured if available, fallback to standard
if STRUCTURED_LOGGING_AVAILABLE:
    logger = get_structured_logger(__name__)
else:
    logger = logging.getLogger(__name__)


def initialize_logging(
    level: Union[int, str] = logging.INFO,
    log_file: Optional[str] = None,
    enable_structured: bool = True,
    enable_json: bool = True,
    enable_console: bool = True,
    **kwargs
) -> None:
    """
    Initialize logging system with structured logging if available.
    
    Args:
        level: Logging level (int or string)
        log_file: Optional log file path
        enable_structured: Whether to use structured logging
        enable_json: Whether to use JSON formatting
        enable_console: Whether to enable console output
        **kwargs: Additional configuration options
    """
    if STRUCTURED_LOGGING_AVAILABLE and enable_structured:
        configure_structured_logging(
            level=level,
            log_file=log_file,
            enable_json=enable_json,
            enable_console=enable_console,
            **kwargs
        )
        if enable_console:
            print("✓ Structured logging initialized with JSON output")
    else:
        # Fallback to traditional logging
        _setup_traditional_logging(level, log_file, enable_console)
        if enable_console:
            print("! Using traditional logging (structlog not available)")


def _setup_traditional_logging(level, log_file, enable_console):
    """Setup traditional logging as fallback."""
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    
    handlers = []
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    )
    
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        handlers.append(console_handler)
    
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    
    logging.basicConfig(level=level, handlers=handlers, force=True)


def get_logger(name: Optional[str] = None):
    """
    Get a logger instance - structured if available, traditional otherwise.
    
    Args:
        name: Logger name (defaults to caller's module)
        
    Returns:
        Logger instance (structured or traditional)
    """
    if name is None:
        frame = inspect.currentframe()
        if frame and frame.f_back:
            name = frame.f_back.f_globals.get('__name__', 'intellicrack')
        else:
            name = 'intellicrack'
    
    if STRUCTURED_LOGGING_AVAILABLE:
        return get_structured_logger(name)
    else:
        return logging.getLogger(name)


def log_message(message: str, level: str = "INFO", **kwargs) -> None:
    """
    Log a message at the specified level with optional context.
    
    Args:
        message: The message to log
        level: The log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        **kwargs: Additional context for structured logging
    """
    level = level.upper()
    
    if STRUCTURED_LOGGING_AVAILABLE and kwargs:
        # Use structured logging with context
        log_method = getattr(logger, level.lower(), logger.info)
        log_method(message, **kwargs)
    else:
        # Use traditional logging
        if level == "DEBUG":
            logger.debug(message)
        elif level == "INFO":
            logger.info(message)
        elif level == "WARNING":
            logger.warning(message)
        elif level == "ERROR":
            logger.error(message)
        elif level == "CRITICAL":
            logger.critical(message)
        else:
            logger.info(message)


def log_function_call(func: F) -> F:
    """
    Decorator to log function entry, exit, arguments, return value, and exceptions.
    Enhanced with structured logging support.
    
    Args:
        func: The function to decorate
        
    Returns:
        The wrapped function with logging
    """
    import threading
    _local = threading.local()

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if hasattr(_local, 'in_logger') and _local.in_logger:
            return func(*args, **kwargs)

        func_name = func.__qualname__
        
        # Skip problematic functions
        if any(_skip in func_name for _skip in ['__str__', '__repr__', 'as_posix', 'getline', 'getlines']):
            return func(*args, **kwargs)

        try:
            _local.in_logger = True
            
            # Safe argument representation
            def safe_repr(obj, max_len=100):
                try:
                    r = repr(obj)
                    return r[:max_len] + '...' if len(r) > max_len else r
                except (TypeError, ValueError, AttributeError, RecursionError):
                    return '<repr_failed>'

            # Get argument info
            arg_names = inspect.getfullargspec(func).args
            arg_values = args[:len(arg_names)]
            arg_strs = [f"{name}={safe_repr(value)}" for name, value in zip(arg_names, arg_values, strict=False)]
            if kwargs:
                arg_strs += [f"{k}={safe_repr(v)}" for k, v in kwargs.items()]

            start_time = time.time()
            
            if STRUCTURED_LOGGING_AVAILABLE:
                logger.debug(
                    "Function entry",
                    function=func_name,
                    arguments=arg_strs,
                    category="function_trace"
                )
            else:
                logger.debug(f"Entering {func_name}({', '.join(arg_strs)})")
            
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            
            if STRUCTURED_LOGGING_AVAILABLE:
                logger.debug(
                    "Function exit",
                    function=func_name,
                    result=safe_repr(result),
                    duration_seconds=duration,
                    category="function_trace"
                )
            else:
                logger.debug(f"Exiting {func_name} with result: {safe_repr(result)} (took {duration:.3f}s)")
            
            return result
            
        except Exception as e:
            if STRUCTURED_LOGGING_AVAILABLE:
                struct_log_exception(logger, e, function=func_name, category="function_error")
            else:
                logger.error(f"Exception in {func_name}: {e}", exc_info=False)
            raise
        finally:
            _local.in_logger = False

    # Support async functions
    if inspect.iscoroutinefunction(func):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            if hasattr(_local, 'in_logger') and _local.in_logger:
                return await func(*args, **kwargs)

            func_name = func.__qualname__
            
            if any(_skip in func_name for _skip in ['__str__', '__repr__', 'as_posix', 'getline', 'getlines']):
                return await func(*args, **kwargs)

            try:
                _local.in_logger = True
                
                def safe_repr(obj, max_len=100):
                    try:
                        r = repr(obj)
                        return r[:max_len] + '...' if len(r) > max_len else r
                    except (TypeError, ValueError, AttributeError, RecursionError):
                        return '<repr_failed>'

                arg_names = inspect.getfullargspec(func).args
                arg_values = args[:len(arg_names)]
                arg_strs = [f"{name}={safe_repr(value)}" for name, value in zip(arg_names, arg_values, strict=False)]
                if kwargs:
                    arg_strs += [f"{k}={safe_repr(v)}" for k, v in kwargs.items()]

                start_time = time.time()
                
                if STRUCTURED_LOGGING_AVAILABLE:
                    logger.debug(
                        "Async function entry",
                        function=func_name,
                        arguments=arg_strs,
                        category="async_function_trace"
                    )
                else:
                    logger.debug(f"Entering async {func_name}({', '.join(arg_strs)})")
                
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                
                if STRUCTURED_LOGGING_AVAILABLE:
                    logger.debug(
                        "Async function exit",
                        function=func_name,
                        result=safe_repr(result),
                        duration_seconds=duration,
                        category="async_function_trace"
                    )
                else:
                    logger.debug(f"Exiting async {func_name} with result: {safe_repr(result)} (took {duration:.3f}s)")
                
                return result
                
            except Exception as e:
                if STRUCTURED_LOGGING_AVAILABLE:
                    struct_log_exception(logger, e, function=func_name, category="async_function_error")
                else:
                    logger.error(f"Exception in async {func_name}: {e}", exc_info=False)
                raise
            finally:
                _local.in_logger = False
                
        return async_wrapper

    return wrapper


def log_all_methods(cls):
    """
    Class decorator to apply log_function_call to all methods of a class.
    
    Args:
        cls: The class to decorate
        
    Returns:
        The class with all methods decorated
    """
    for attr_name, attr_value in cls.__dict__.items():
        if callable(attr_value) and not attr_name.startswith("__"):
            setattr(cls, attr_name, log_function_call(attr_value))
    return cls


def log_analysis_operation(target: str, operation: str, **context):
    """
    Log binary analysis operations with structured context.
    
    Args:
        target: Target file or binary being analyzed
        operation: Type of analysis operation
        **context: Additional context information
    """
    if STRUCTURED_LOGGING_AVAILABLE:
        log_analysis_result(logger, target, operation, context)
    else:
        logger.info(f"Analysis: {operation} on {target} - {context}")


def log_security_alert(alert_type: str, severity: str = "medium", **details):
    """
    Log security-related alerts with appropriate context.
    
    Args:
        alert_type: Type of security alert
        severity: Severity level (low, medium, high, critical)
        **details: Alert details
    """
    if STRUCTURED_LOGGING_AVAILABLE:
        log_security_event(logger, alert_type, severity, **details)
    else:
        level_map = {"low": "info", "medium": "warning", "high": "error", "critical": "critical"}
        log_method = getattr(logger, level_map.get(severity, "warning"))
        log_method(f"Security Alert [{severity.upper()}]: {alert_type} - {details}")


def log_performance_metric(operation: str, duration: float, **metrics):
    """
    Log performance metrics for operations.
    
    Args:
        operation: Name of the operation
        duration: Duration in seconds
        **metrics: Additional performance metrics
    """
    if STRUCTURED_LOGGING_AVAILABLE:
        log_performance(logger, operation, duration, **metrics)
    else:
        logger.info(f"Performance: {operation} took {duration:.3f}s - {metrics}")


# Maintain backward compatibility with existing functions
def setup_logger(name: str = 'Intellicrack', level: int = logging.INFO,
                 log_file: str = None, format_string: str = None):
    """Backward compatible logger setup."""
    if STRUCTURED_LOGGING_AVAILABLE:
        return get_structured_logger(name)
    else:
        target_logger = logging.getLogger(name)
        target_logger.setLevel(level)
        
        if format_string is None:
            format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        formatter = logging.Formatter(format_string)
        
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        target_logger.addHandler(console_handler)
        
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            target_logger.addHandler(file_handler)
        
        return target_logger


def configure_logging(level: int = logging.INFO, log_file: str = None,
                     format_string: str = None, enable_comprehensive: bool = False):
    """Backward compatible logging configuration."""
    initialize_logging(
        level=level,
        log_file=log_file,
        enable_structured=True,
        enable_json=True,
        enable_console=True
    )


def setup_logging(level: str = "INFO", log_file: str = None,
                  enable_rotation: bool = True, max_bytes: int = 10485760,
                  backup_count: int = 5) -> None:
    """Backward compatible logging setup with rotation."""
    initialize_logging(
        level=level,
        log_file=log_file,
        enable_structured=True,
        enable_json=True,
        enable_console=True,
        max_bytes=max_bytes,
        backup_count=backup_count
    )


def setup_persistent_logging(log_dir: str = None, log_name: str = "intellicrack",
                            enable_rotation: bool = True, max_bytes: int = 10485760,
                            backup_count: int = 5) -> str:
    """Setup persistent logging with structured output."""
    import os
    from datetime import datetime

    if log_dir is None:
        from pathlib import Path
        log_dir = Path.home() / "intellicrack" / "logs"
    
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"{log_name}_{timestamp}.log")
    
    initialize_logging(
        level="INFO",
        log_file=log_file,
        enable_structured=True,
        enable_json=True,
        enable_console=True,
        max_bytes=max_bytes,
        backup_count=backup_count
    )
    
    logger.info("Persistent structured logging initialized", log_file=log_file)
    return log_file


# Backward compatibility aliases
log_execution_time = log_function_call
log_exception = log_function_call
log_method_call = log_function_call

# Export public interface
__all__ = [
    'initialize_logging',
    'get_logger',
    'log_message',
    'log_function_call',
    'log_all_methods',
    'log_analysis_operation',
    'log_security_alert',
    'log_performance_metric',
    'setup_logger',
    'configure_logging',
    'setup_logging',
    'setup_persistent_logging',
    'log_execution_time',
    'log_exception',
    'log_method_call',
    'logger',
    'STRUCTURED_LOGGING_AVAILABLE',
]

# Additional structured logging utilities if available
if STRUCTURED_LOGGING_AVAILABLE:
    __all__.extend([
        'bind_context',
        'clear_context',
    ])
