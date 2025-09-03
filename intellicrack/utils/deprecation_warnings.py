"""Deprecation warnings for legacy configuration methods.

This module provides deprecation warnings for old configuration methods
that have been migrated to the central IntellicrackConfig system.

Author: Intellicrack Development Team
Date: 2024
"""

import functools
import warnings
from typing import Any, Callable


def deprecated_config_method(replacement: str, version: str = "4.0") -> Callable:
    """Decorator to mark configuration methods as deprecated.

    Args:
        replacement: The new method or approach to use instead
        version: Version when the method will be removed

    Returns:
        Decorated function that emits deprecation warning

    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            warnings.warn(
                f"{func.__name__} is deprecated and will be removed in version {version}. Use {replacement} instead.",
                DeprecationWarning,
                stacklevel=2,
            )
            return func(*args, **kwargs)

        return wrapper

    return decorator


def deprecated_qsettings(func: Callable) -> Callable:
    """Decorator specifically for QSettings-based methods.

    Args:
        func: Function using QSettings

    Returns:
        Decorated function that emits QSettings deprecation warning

    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        warnings.warn(
            f"QSettings usage in {func.__name__} is deprecated. "
            "All configuration now uses central IntellicrackConfig. "
            "QSettings support will be removed in version 4.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        return func(*args, **kwargs)

    return wrapper


def deprecated_llm_file_storage(func: Callable) -> Callable:
    """Decorator for LLM configuration file storage methods.

    Args:
        func: Function using file-based LLM config storage

    Returns:
        Decorated function that emits file storage deprecation warning

    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        warnings.warn(
            f"File-based LLM configuration storage in {func.__name__} is deprecated. "
            "All LLM configurations are now stored in central IntellicrackConfig. "
            "Direct file access will be removed in version 4.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        return func(*args, **kwargs)

    return wrapper


def deprecated_cli_config_file(func: Callable) -> Callable:
    """Decorator for CLI configuration file methods.

    Args:
        func: Function using separate CLI config file

    Returns:
        Decorated function that emits CLI config deprecation warning

    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        warnings.warn(
            f"Separate CLI configuration file usage in {func.__name__} is deprecated. "
            "CLI configuration is now part of central IntellicrackConfig. "
            "Separate CLI config files will be removed in version 4.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        return func(*args, **kwargs)

    return wrapper


def deprecated_legacy_config_path(path: str) -> None:
    """Emit warning for legacy configuration file paths.

    Args:
        path: The legacy path being accessed

    """
    warnings.warn(
        f"Legacy configuration path '{path}' is deprecated. "
        "All configuration is now centralized in config.json. "
        "Legacy paths will be removed in version 4.0.",
        DeprecationWarning,
        stacklevel=2,
    )


def emit_migration_warning(old_system: str, new_system: str = "IntellicrackConfig") -> None:
    """Emit a migration warning for configuration systems.

    Args:
        old_system: Name of the old configuration system
        new_system: Name of the new configuration system

    """
    warnings.warn(
        f"Configuration system '{old_system}' has been migrated to '{new_system}'. "
        f"Please update your code to use the new centralized configuration system. "
        f"Support for '{old_system}' will be removed in version 4.0.",
        DeprecationWarning,
        stacklevel=2,
    )


class DeprecatedConfigAccess:
    """Context manager for deprecated configuration access patterns.

    Usage:
        with DeprecatedConfigAccess("QSettings"):
            # Old code that uses QSettings
            pass
    """

    def __init__(self, system_name: str):
        """Initialize deprecation context.

        Args:
            system_name: Name of the deprecated system

        """
        self.system_name = system_name

    def __enter__(self):
        """Enter context and emit warning."""
        emit_migration_warning(self.system_name)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context."""
        pass


# Specific deprecation messages for common patterns
DEPRECATION_MESSAGES = {
    "qsettings": "QSettings is deprecated. Use IntellicrackConfig.get() and .set() instead.",
    "llm_files": "LLM configuration files are deprecated. Use IntellicrackConfig.get('llm_configuration.*').",
    "cli_config": "Separate CLI config is deprecated. Use IntellicrackConfig.get('cli_configuration.*').",
    "legacy_paths": "Legacy config paths are deprecated. Use centralized config.json.",
    "env_files": "Separate .env file management is deprecated. Use IntellicrackConfig environment handling.",
}


def check_deprecated_import(module_name: str) -> None:
    """Check if an imported module is deprecated for configuration.

    Args:
        module_name: Name of the module being imported

    """
    deprecated_modules = {
        "PyQt6.QtCore.QSettings": "Use intellicrack.core.config_manager.IntellicrackConfig instead",
        "configparser": "Use IntellicrackConfig for all configuration needs",
    }

    if module_name in deprecated_modules:
        warnings.warn(
            f"Import of '{module_name}' for configuration is deprecated. {deprecated_modules[module_name]}",
            DeprecationWarning,
            stacklevel=2,
        )


# Production-ready warning configuration
def configure_deprecation_warnings(show_warnings: bool = True, error_on_deprecated: bool = False):
    """Configure how deprecation warnings are handled.

    Args:
        show_warnings: Whether to show deprecation warnings
        error_on_deprecated: Whether to raise errors instead of warnings

    """
    if error_on_deprecated:
        # Convert deprecation warnings to errors
        warnings.filterwarnings("error", category=DeprecationWarning)
    elif show_warnings:
        # Show deprecation warnings
        warnings.filterwarnings("always", category=DeprecationWarning)
    else:
        # Hide deprecation warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning)
