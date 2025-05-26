"""
Logging utilities for the Intellicrack framework.

This module provides comprehensive logging functionality including function call logging,
class method logging, and application-wide logging initialization.
"""

import functools
import inspect
import logging
import sys
from typing import Any, Callable, TypeVar

# Type variable for decorators
F = TypeVar('F', bound=Callable[..., Any])

# Module logger
logger = logging.getLogger(__name__)


def log_message(message: str, level: str = "INFO") -> None:
    """
    Log a message at the specified level.
    
    Args:
        message: The message to log
        level: The log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    level = level.upper()
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
    
    Args:
        func: The function to decorate
        
    Returns:
        The wrapped function with logging
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        func_name = func.__qualname__
        try:
            # Log function call with arguments
            arg_names = inspect.getfullargspec(func).args
            arg_values = args[:len(arg_names)]
            
            # Safely represent arguments to avoid issues with large objects
            def safe_repr(obj, max_len=100):
                try:
                    r = repr(obj)
                    if len(r) > max_len:
                        return r[:max_len] + '...'
                    return r
                except:
                    return '<repr_failed>'
            
            arg_strs = [f"{name}={safe_repr(value)}" for name, value in zip(arg_names, arg_values)]
            if kwargs:
                arg_strs += [f"{k}={safe_repr(v)}" for k, v in kwargs.items()]
            
            logger.debug(f"Entering {func_name}({', '.join(arg_strs)})")
            result = func(*args, **kwargs)
            logger.debug(f"Exiting {func_name} with result: {safe_repr(result)}")
            return result
        except Exception as e:
            logger.exception(f"Exception in {func_name}: {e}")
            raise

    # Support async functions
    if inspect.iscoroutinefunction(func):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            func_name = func.__qualname__
            try:
                arg_names = inspect.getfullargspec(func).args
                arg_values = args[:len(arg_names)]
                
                # Use the same safe_repr function for async too
                def safe_repr(obj, max_len=100):
                    try:
                        r = repr(obj)
                        if len(r) > max_len:
                            return r[:max_len] + '...'
                        return r
                    except:
                        return '<repr_failed>'
                
                arg_strs = [f"{name}={safe_repr(value)}" for name, value in zip(arg_names, arg_values)]
                if kwargs:
                    arg_strs += [f"{k}={safe_repr(v)}" for k, v in kwargs.items()]
                
                logger.debug(f"Entering async {func_name}({', '.join(arg_strs)})")
                result = await func(*args, **kwargs)
                logger.debug(f"Exiting async {func_name} with result: {safe_repr(result)}")
                return result
            except Exception as e:
                logger.exception(f"Exception in async {func_name}: {e}")
                raise
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


def initialize_comprehensive_logging(module_name: str = '__main__'):
    """
    Initialize comprehensive logging for the entire application.
    
    This function automatically applies the log_function_call decorator to all
    functions and methods throughout the application, ensuring complete
    visibility into the program's execution flow.
    
    Args:
        module_name: Name of the module to initialize logging for
    """
    logger = logging.getLogger('Intellicrack')
    logger.info("Initializing comprehensive function logging...")
    
    # Get the specified module
    if module_name in sys.modules:
        current_module = sys.modules[module_name]
    else:
        logger.warning(f"Module {module_name} not found in sys.modules")
        return
    
    # Track what we've already processed to avoid infinite loops
    processed = set()
    
    # Helper function to recursively apply logging
    def apply_logging_to_object(obj, obj_name=""):
        # Skip if we've already processed this object
        if id(obj) in processed:
            return
        processed.add(id(obj))
        
        # Apply to functions
        if inspect.isfunction(obj) and not obj_name.startswith("_"):
            try:
                # Get the parent object that contains this function
                parent_name = obj_name.rsplit('.', 1)[0] if '.' in obj_name else module_name
                parent = current_module
                for part in parent_name.split('.')[1:]:  # Skip module name
                    parent = getattr(parent, part, None)
                    if parent is None:
                        break
                
                if parent is not None:
                    # Apply the decorator
                    decorated = log_function_call(obj)
                    setattr(parent, obj.__name__, decorated)
                    logger.debug(f"Applied logging to function: {obj_name}")
            except Exception as e:
                logger.debug(f"Could not apply logging to {obj_name}: {e}")
        
        # Apply to classes
        elif inspect.isclass(obj):
            try:
                # Apply to all methods in the class
                for method_name, method in inspect.getmembers(obj):
                    if callable(method) and not method_name.startswith("_"):
                        try:
                            decorated = log_function_call(method)
                            setattr(obj, method_name, decorated)
                            logger.debug(f"Applied logging to method: {obj_name}.{method_name}")
                        except Exception as e:
                            logger.debug(f"Could not apply logging to {obj_name}.{method_name}: {e}")
            except Exception as e:
                logger.debug(f"Could not process class {obj_name}: {e}")
    
    # Process all objects in the module
    for name, obj in inspect.getmembers(current_module):
        if not name.startswith("_"):
            apply_logging_to_object(obj, f"{module_name}.{name}")
    
    logger.info("Comprehensive logging initialization complete")


def setup_logger(name: str = 'Intellicrack', level: int = logging.INFO, 
                 log_file: str = None, format_string: str = None) -> logging.Logger:
    """
    Set up a logger with the specified configuration.
    
    Args:
        name: Logger name
        level: Logging level (default: INFO)
        log_file: Optional log file path
        format_string: Optional format string for log messages
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Default format if not specified
    if format_string is None:
        format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    formatter = logging.Formatter(format_string)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str = None) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name (default: caller's module name)
        
    Returns:
        Logger instance
    """
    if name is None:
        # Get the caller's module name
        frame = inspect.currentframe()
        if frame and frame.f_back:
            name = frame.f_back.f_globals.get('__name__', 'Intellicrack')
        else:
            name = 'Intellicrack'
    
    return logging.getLogger(name)


def configure_logging(level: int = logging.INFO, log_file: str = None,
                     format_string: str = None, enable_comprehensive: bool = False):
    """
    Configure logging for the entire application.
    
    Args:
        level: Logging level
        log_file: Optional log file path
        format_string: Optional format string
        enable_comprehensive: Whether to enable comprehensive function logging
    """
    # Set up the root logger
    setup_logger('Intellicrack', level, log_file, format_string)
    
    # Enable comprehensive logging if requested
    if enable_comprehensive:
        initialize_comprehensive_logging()


# Exported functions and classes
__all__ = [
    'log_function_call',
    'log_all_methods',
    'initialize_comprehensive_logging',
    'setup_logger',
    'get_logger',
    'configure_logging',
]