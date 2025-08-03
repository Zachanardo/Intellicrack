"""
Structured JSON logging configuration using structlog for the Intellicrack framework.

This module provides production-ready structured logging with JSON output,
contextual information, and performance optimizations for defensive security research.

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
import logging.handlers
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, Optional, Union

import structlog


def add_caller_info(logger, method_name, event_dict):
    """
    Add caller information to log entries for better traceability.
    
    Args:
        logger: The logger instance
        method_name: The logging method name
        event_dict: The event dictionary
        
    Returns:
        dict: Enhanced event dictionary with caller information
    """
    # Get the caller frame (skip structlog internals)
    frame = sys._getframe()
    while frame:
        code = frame.f_code
        filename = code.co_filename
        
        # Skip internal structlog and logging frames
        if not any(skip in filename for skip in ['structlog', 'logging', __file__]):
            # Extract relative path from Intellicrack root
            try:
                rel_path = Path(filename).relative_to(Path(__file__).parent.parent.parent)
                event_dict['module'] = str(rel_path).replace('\\', '/').replace('.py', '')
            except ValueError:
                event_dict['module'] = Path(filename).name.replace('.py', '')
            
            event_dict['function'] = code.co_name
            event_dict['line'] = frame.f_lineno
            break
        frame = frame.f_back
    
    return event_dict


def add_process_context(logger, method_name, event_dict):
    """
    Add process context information to log entries.
    
    Args:
        logger: The logger instance
        method_name: The logging method name
        event_dict: The event dictionary
        
    Returns:
        dict: Enhanced event dictionary with process context
    """
    event_dict['process_id'] = os.getpid()
    event_dict['thread_id'] = None  # Will be set by thread-safe processor if needed
    return event_dict


def filter_sensitive_data(logger, method_name, event_dict):
    """
    Filter sensitive data from log entries for security.
    
    Args:
        logger: The logger instance
        method_name: The logging method name
        event_dict: The event dictionary
        
    Returns:
        dict: Filtered event dictionary with sensitive data masked
    """
    sensitive_keys = {'password', 'token', 'key', 'secret', 'credential', 'auth'}
    
    def mask_sensitive(obj, path=""):
        if isinstance(obj, dict):
            return {
                k: mask_sensitive(v, f"{path}.{k}" if path else k)
                for k, v in obj.items()
            }
        elif isinstance(obj, (list, tuple)):
            return [mask_sensitive(item, f"{path}[{i}]") for i, item in enumerate(obj)]
        elif isinstance(obj, str) and any(sens in path.lower() for sens in sensitive_keys):
            return "***MASKED***"
        return obj
    
    return mask_sensitive(event_dict)


def configure_structured_logging(
    level: Union[int, str] = logging.INFO,
    log_file: Optional[str] = None,
    enable_json: bool = True,
    enable_console: bool = True,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    enable_caller_info: bool = True,
    enable_filtering: bool = True
) -> None:
    """
    Configure structured logging for the entire application.
    
    Args:
        level: Logging level (int or string)
        log_file: Optional log file path for file output
        enable_json: Whether to use JSON formatting
        enable_console: Whether to enable console output
        max_bytes: Maximum size of log files before rotation
        backup_count: Number of backup files to keep
        enable_caller_info: Whether to add caller information
        enable_filtering: Whether to filter sensitive data
    """
    # Convert string level to int if needed
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    
    # Build processor chain
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
    ]
    
    if enable_caller_info:
        processors.append(add_caller_info)
        
    processors.append(add_process_context)
    
    if enable_filtering:
        processors.append(filter_sensitive_data)
    
    processors.extend([
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.ExceptionPrettyPrinter(),
    ])
    
    # Configure standard library logging
    logging.basicConfig(format="%(message)s", level=level, handlers=[])
    
    # Set up handlers
    handlers = []
    
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        handlers.append(console_handler)
    
    if log_file:
        # Ensure log directory exists
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Use rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(level)
        handlers.append(file_handler)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(logging.NullHandler())
    
    for handler in handlers:
        root_logger.addHandler(handler)
    root_logger.setLevel(level)
    
    # Configure structlog
    if enable_json:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=enable_console and sys.stdout.isatty())
    
    processors.append(renderer)
    
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.WriteLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_structured_logger(name: Optional[str] = None) -> structlog.BoundLogger:
    """
    Get a structured logger instance.
    
    Args:
        name: Optional logger name (defaults to caller's module)
        
    Returns:
        BoundLogger: Configured structured logger
    """
    if name is None:
        # Get caller's module name
        frame = sys._getframe(1)
        name = frame.f_globals.get('__name__', 'intellicrack')
    
    return structlog.get_logger(name)


def bind_context(**kwargs) -> None:
    """
    Bind context variables that will be included in all subsequent log entries.
    
    Args:
        **kwargs: Context variables to bind
    """
    for key, value in kwargs.items():
        structlog.contextvars.bind_contextvars(**{key: value})


def clear_context() -> None:
    """Clear all bound context variables."""
    structlog.contextvars.clear_contextvars()


def log_exception(logger: structlog.BoundLogger, exc: Exception, **kwargs) -> None:
    """
    Log an exception with full traceback and context.
    
    Args:
        logger: The structured logger
        exc: Exception to log
        **kwargs: Additional context
    """
    logger.error(
        "Exception occurred",
        exception_type=exc.__class__.__name__,
        exception_message=str(exc),
        traceback=traceback.format_exc(),
        **kwargs
    )


def log_performance(logger: structlog.BoundLogger, operation: str, duration: float, **kwargs) -> None:
    """
    Log performance metrics for operations.
    
    Args:
        logger: The structured logger
        operation: Name of the operation
        duration: Duration in seconds
        **kwargs: Additional metrics
    """
    logger.info(
        "Performance metric",
        operation=operation,
        duration_seconds=duration,
        duration_ms=duration * 1000,
        **kwargs
    )


def log_security_event(logger: structlog.BoundLogger, event_type: str, severity: str, **kwargs) -> None:
    """
    Log security-related events with appropriate severity.
    
    Args:
        logger: The structured logger
        event_type: Type of security event
        severity: Severity level (low, medium, high, critical)
        **kwargs: Event details
    """
    log_method = getattr(logger, severity.lower(), logger.info)
    log_method(
        "Security event",
        event_type=event_type,
        severity=severity,
        category="security",
        **kwargs
    )


def log_analysis_result(logger: structlog.BoundLogger, target: str, analysis_type: str, 
                       results: Dict[str, Any], **kwargs) -> None:
    """
    Log binary analysis results in a structured format.
    
    Args:
        logger: The structured logger
        target: Target binary or file being analyzed
        analysis_type: Type of analysis performed
        results: Analysis results dictionary
        **kwargs: Additional context
    """
    logger.info(
        "Analysis completed",
        target=target,
        analysis_type=analysis_type,
        results=results,
        category="analysis",
        **kwargs
    )


def log_performance_metric(operation: str, value: float, unit: str, **kwargs) -> None:
    """
    Log performance metrics with structured data (wrapper without logger parameter).
    
    Args:
        operation: The operation being measured
        value: The performance metric value
        unit: The unit of measurement (e.g., 'ms', 'seconds', 'bytes')
        **kwargs: Additional context fields
    """
    logger = get_structured_logger()
    logger.info(
        "Performance metric recorded",
        operation=operation,
        value=value,
        unit=unit,
        category="performance_metric",
        **kwargs
    )


# Backward compatibility aliases
setup_structured_logging = configure_structured_logging
get_logger = get_structured_logger

# Export public interface
__all__ = [
    'configure_structured_logging',
    'get_structured_logger',
    'bind_context',
    'clear_context',
    'log_exception',
    'log_performance',
    'log_security_event',
    'log_analysis_result',
    'log_performance_metric',
    'setup_structured_logging',  # Alias
    'get_logger',  # Alias
]