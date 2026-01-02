"""Configuration Management - Modern Dynamic Configuration System.

Uses the new IntellicrackConfig class with auto-discovery and platform-aware directories.
Provides backward compatibility with legacy configuration access patterns.

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

import logging
import os
from collections.abc import Callable, ItemsView, KeysView, ValuesView
from pathlib import Path
from typing import Any, Protocol


logger = logging.getLogger(__name__)


class IntellicrackConfigProtocol(Protocol):
    """Protocol for IntellicrackConfig to avoid circular imports."""

    config_file: object

    def get_tool_path(self, tool_name: str) -> str | None: ...
    def get_output_dir(self) -> object: ...
    def get_cache_dir(self) -> object: ...
    def get_logs_dir(self) -> object: ...
    def get(self, key: str, default: object = None) -> object: ...
    def set(self, key: str, value: object) -> None: ...
    def is_tool_available(self, tool_name: str) -> bool: ...


_get_new_config: Callable[[], IntellicrackConfigProtocol] | None = None


def _ensure_config_manager_imported() -> Callable[[], IntellicrackConfigProtocol]:
    """Lazy import of config_manager to avoid circular dependencies.

    Imports the IntellicrackConfig factory function from the core.config_manager
    module on first call and caches it globally. Subsequent calls return the cached
    function. This pattern prevents circular import issues that would occur if
    config_manager were imported at module load time.

    Returns:
        Callable[[], IntellicrackConfigProtocol]: Function that returns a new
                                                  config instance.

    Raises:
        ImportError: If config_manager module cannot be imported.
        RuntimeError: If config_manager import fails unexpectedly.

    Note:
        This function uses lazy initialization with caching to improve performance
        on subsequent calls and avoid circular dependency issues at module load
        time.

    """
    global _get_new_config
    if _get_new_config is None:
        logger.debug("Lazily importing config_manager for the first time.")
        try:
            from .core.config_manager import get_config as imported_get_config

            _get_new_config = imported_get_config
            logger.debug("config_manager imported successfully.")
        except ImportError as e:
            logger.critical("Failed to import config_manager: %s", e, exc_info=True)
            raise
    if _get_new_config is None:
        raise RuntimeError("Failed to import config_manager")
    return _get_new_config


# Load environment variables
try:
    from dotenv import load_dotenv

    load_dotenv()
    logger.debug("Environment variables loaded from .env file.")
except ImportError:
    logger.debug("python-dotenv not installed, skipping .env file loading.")
except Exception as e:
    logger.warning("Error loading .env file: %s", e, exc_info=True)

# Global configuration instance
_modern_config = None
_legacy_mode = False


def _get_modern_config() -> IntellicrackConfigProtocol:
    """Get the modern configuration instance.

    This internal function implements a singleton pattern to ensure only one
    configuration instance exists throughout the application lifetime. It lazily
    initializes the modern IntellicrackConfig on first access. The returned
    instance conforms to the IntellicrackConfigProtocol interface.

    Returns:
        IntellicrackConfigProtocol: The global modern configuration instance
                                    providing access to tool paths, directories,
                                    and configuration values.

    Note:
        This is an internal function used by the legacy compatibility layer.
        External code should use get_config() instead.

    """
    global _modern_config  # pylint: disable=global-statement
    if _modern_config is None:
        logger.debug("Initializing modern configuration for the first time.")
        get_new_config = _ensure_config_manager_imported()
        _modern_config = get_new_config()
        logger.info("Modern configuration initialized.")
    return _modern_config


# Tool discovery functions using new system


def find_tool(tool_name: str, required_executables: list[str] | None = None) -> str | None:
    """Find tool executable path using the modern discovery system.

    This function attempts to locate external tools (Ghidra, Radare2, Frida, etc.)
    using the modern configuration system's tool discovery capabilities. If the
    modern system fails, it falls back to a basic PATH search.

    Args:
        tool_name: Name of the tool to find (e.g., 'ghidra', 'radare2', 'frida').
        required_executables: Optional list of required executables for the tool
                              (currently used for logging only).

    Returns:
        str | None: Path to the tool executable if found, None if not found.

    Examples:
        >>> find_tool("ghidra")
        '/opt/ghidra/ghidraRun'

        >>> find_tool(
        ...     "radare2",
        ...     ["r2", "rabin2"],
        ... )
        '/usr/bin/r2'

    """
    if required_executables:
        logger.debug("Tool search for %s with required executables: %s", tool_name, required_executables)
    else:
        logger.debug("Tool search for %s.", tool_name)
    try:
        config = _get_modern_config()
        tool_path = config.get_tool_path(tool_name)
        if tool_path:
            logger.debug("Modern tool discovery found '%s' at '%s'.", tool_name, tool_path)
        else:
            logger.debug("Modern tool discovery did not find '%s'.", tool_name)
        return tool_path
    except (AttributeError, KeyError, ValueError) as e:
        logger.warning(
            "Modern tool discovery failed for %s: %s. Falling back to PATH search.",
            tool_name,
            e,
            exc_info=True,
        )
        # Fallback to basic PATH search
        import shutil

        path_tool = shutil.which(tool_name)
        if path_tool:
            logger.debug("PATH search found '%s' at '%s'.", tool_name, path_tool)
        else:
            logger.debug("PATH search did not find '%s'.", tool_name)
        return path_tool


def get_system_path(path_type: str) -> str | None:
    """Get system-specific paths using modern configuration.

    This function provides a unified interface to retrieve various system paths
    like output directories, cache locations, and user folders. It uses the modern
    configuration system and falls back to OS-specific defaults if needed. When the
    modern configuration system fails to provide a path, the function attempts to
    retrieve the path using platform-appropriate fallback mechanisms before returning
    None.

    Args:
        path_type: Type of system path to retrieve. Valid values are "output"
                   for the output directory, "cache" for temporary data cache,
                   "logs" for log files, "temp" for temporary files, "desktop"
                   for user's desktop folder (fallback only), "documents" for
                   user's documents folder (fallback only), and "downloads" for
                   user's downloads folder (fallback only).

    Returns:
        str | None: Path string if found in modern config or fallback mechanisms,
                    None otherwise.

    Raises:
        ValueError: If path is not found in modern config, triggering fallback
                    mechanism. This is used internally for control flow and does
                    not reach the caller if a fallback path exists.

    Examples:
        >>> get_system_path("output")
        '/home/user/.local/share/intellicrack/output'

        >>> get_system_path("cache")
        '/home/user/.cache/intellicrack'

    """
    logger.debug("Requesting system path for type: '%s'.", path_type)
    try:
        config = _get_modern_config()
        path: str | None = None
        if path_type == "output":
            path = str(config.get_output_dir())
        elif path_type == "cache":
            path = str(config.get_cache_dir())
        elif path_type == "logs":
            path = str(config.get_logs_dir())
        elif path_type == "temp":
            temp_path = config.get("directories.temp")
            path = str(temp_path) if temp_path is not None else None

        if path:
            logger.debug("Modern config found path for '%s': '%s'.", path_type, path)
            return path
        else:
            logger.debug("Modern config did not provide a specific path for '%s'. Checking fallbacks.", path_type)
            raise ValueError("Path not found in modern config, attempting fallback.")
    except (AttributeError, KeyError, ValueError, TypeError) as e:
        logger.warning(
            "Modern system path lookup failed for %s: %s. Attempting fallback.",
            path_type,
            e,
            exc_info=True,
        )
        # Fallback to basic paths
        fallback_path = None
        if path_type == "desktop":
            fallback_path = os.path.join(os.path.expanduser("~"), "Desktop")
        elif path_type == "documents":
            fallback_path = os.path.join(os.path.expanduser("~"), "Documents")
        elif path_type == "downloads":
            fallback_path = os.path.join(os.path.expanduser("~"), "Downloads")
        elif path_type == "temp":
            import tempfile

            fallback_path = tempfile.gettempdir()

        if fallback_path:
            logger.debug("Fallback mechanism found path for '%s': '%s'.", path_type, fallback_path)
        else:
            logger.warning("Fallback mechanism could not find path for '%s'. Returning None.", path_type)
        return fallback_path


class ConfigManager:
    """Legacy configuration manager that wraps the modern IntellicrackConfig.

    Provides backward compatibility for existing code while using the new
    dynamic configuration system under the hood. This class maintains the old
    API interface while delegating to the modern configuration system for
    actual functionality.

    The ConfigManager acts as a bridge between legacy code expecting dictionary-
    style configuration access and the modern object-oriented configuration system.
    It automatically translates legacy keys to modern configuration paths and
    provides fallback values for backward compatibility.

    Attributes:
        config_path: Path to the configuration file (for compatibility).
        _modern_config: Internal reference to the modern IntellicrackConfig
                        instance.

    Examples:
        >>> config = ConfigManager()
        >>> config.get("ghidra_path")
        '/opt/ghidra/ghidraRun'

        >>> config["log_dir"] = (
        ...     "/var/log/intellicrack"
        ... )
        >>> config.save_config()
        True

    """

    def __init__(self, config_path: str | None = None) -> None:
        """Initialize legacy configuration manager wrapper.

        Args:
            config_path: Optional path to configuration file. This parameter is
                         maintained for backward compatibility but is largely ignored
                         as the modern system uses platform-specific config locations.

        """
        logger.debug("Initializing ConfigManager. Provided config_path: '%s'.", config_path)
        self._modern_config = _get_modern_config()
        self.config_path = config_path or str(self._modern_config.config_file)
        logger.info("ConfigManager initialized. Effective config_path: '%s'.", self.config_path)

    @property
    def config(self) -> dict[str, Any]:
        """Get configuration as dictionary for legacy compatibility.

        This property dynamically builds a legacy-compatible configuration dictionary
        from the modern configuration system. The returned dictionary matches the
        structure expected by older code while pulling data from the new system.

        Returns:
            dict[str, Any]: Complete configuration dictionary with all sections
                           including paths, tools, analysis settings, etc.

        Note:
            The dictionary is rebuilt on each access to ensure it reflects
            the current state of the modern configuration.

        """
        logger.debug("Accessing ConfigManager.config property, building legacy config.")
        return self._build_legacy_config()

    def _build_legacy_config(self) -> dict[str, Any]:
        """Build a legacy-compatible configuration dictionary.

        This internal method constructs a configuration dictionary that matches
        the structure expected by legacy code. It maps modern configuration
        values to their legacy equivalents and provides default values where
        necessary.

        Returns:
            dict[str, Any]: Legacy-formatted configuration dictionary with all
                            expected sections and keys.

        Note:
            This method is called by the config property and should not be used
            directly by external code.

        """
        logger.debug("Building legacy configuration dictionary from modern config.")
        config = self._modern_config

        # Create legacy structure from modern config
        legacy_config = {
            # Paths - mapped from modern directories
            "log_dir": str(config.get_logs_dir()),
            "output_dir": str(config.get_output_dir()),
            "temp_dir": config.get("directories.temp", str(config.get_cache_dir())),
            "plugin_directory": "intellicrack/intellicrack/plugins",
            "download_directory": str(Path(str(config.get_cache_dir())) / "downloads"),
            # Tool paths
            "ghidra_path": config.get_tool_path("ghidra"),
            "radare2_path": config.get_tool_path("radare2"),
            "frida_path": config.get_tool_path("frida"),
            # Analysis settings
            "analysis": config.get("analysis", {}),
            # Other sections from modern config
            "patching": config.get("patching", {}),
            "network": config.get("network", {}),
            "ui": config.get("ui", {}),
            "logging": {
                "level": config.get("preferences.log_level", "INFO"),
                "enable_file_logging": True,
                "enable_console_logging": True,
                "max_log_size": 10 * 1024 * 1024,
                "log_rotation": 5,
                "verbose_logging": config.get("preferences.log_level") == "DEBUG",
            },
            "security": config.get("security", {}),
            "performance": {
                "max_memory_usage": 2048,
                "enable_gpu_acceleration": True,
                "cache_size": 100,
                "chunk_size": 4096,
                "enable_multiprocessing": True,
            },
            "runtime": {},
            "plugins": {
                "default_plugins": [],
                "auto_load": True,
                "check_updates": config.get("preferences.check_for_updates", True),
                "allow_third_party": True,
            },
            "general": {
                "first_run_completed": True,
                "auto_backup": config.get("preferences.auto_backup_results", True),
                "auto_save_results": config.get("preferences.auto_backup_results", True),
                "check_for_updates": config.get("preferences.check_for_updates", True),
                "send_analytics": False,
                "language": "en",
            },
            "ai": config.get("ai", {}),
            "ml": {
                "enable_ml_features": config.get("analysis.enable_ml_analysis", True),
                "model_cache_size": 100,
                "prediction_threshold": 0.7,
                "auto_load_models": True,
            },
            "model_repositories": {
                "local": {
                    "type": "local",
                    "enabled": True,
                    "models_directory": str(Path(str(config.get_cache_dir())) / "models"),
                },
            },
            "api_cache": {
                "enabled": True,
                "ttl": 3600,
                "max_size_mb": 100,
            },
            "verify_checksums": True,
            "external_services": {},
            "api": {},
        }
        logger.debug("Legacy configuration dictionary built.")
        return legacy_config

    def load_config(self) -> dict[str, Any]:
        """Load configuration - delegates to modern system.

        Returns:
            dict[str, Any]: Complete configuration dictionary.

        """
        logger.debug("ConfigManager.load_config() called (delegating to modern system).")
        return self.config

    def save_config(self) -> bool:
        """Save configuration - delegates to modern system.

        Returns:
            bool: True if saved successfully (always True for backward compatibility).

        """
        # Modern config auto-saves, so this is just compatibility
        # Always return True for backward compatibility
        logger.debug("ConfigManager.save_config() called (modern config auto-saves).")
        return True

    def get(self, key: str, default: object = None) -> object:
        """Get configuration value with legacy key support.

        Retrieves a configuration value by key, with special handling for legacy
        key names that map to the modern configuration system. If the key is not
        found in the modern config, falls back to the legacy-compatible configuration
        dictionary.

        Args:
            key: Configuration key to retrieve. Special legacy keys include
                 'ghidra_path', 'radare2_path', 'frida_path', 'log_dir',
                 'output_dir', and 'temp_dir'.
            default: Default value if key not found in either modern or legacy
                     config. Defaults to None if not provided.

        Returns:
            object: Configuration value if found, or default parameter if not
                    found.

        """
        logger.debug("ConfigManager.get() called for key: '%s'.", key)
        # Handle legacy key mappings
        if key == "ghidra_path":
            tool_path = self._modern_config.get_tool_path("ghidra")
            logger.debug("Legacy key 'ghidra_path' mapped to modern tool path: '%s'.", tool_path)
            return tool_path or default
        if key == "radare2_path":
            tool_path = self._modern_config.get_tool_path("radare2")
            logger.debug("Legacy key 'radare2_path' mapped to modern tool path: '%s'.", tool_path)
            return tool_path or default
        if key == "frida_path":
            tool_path = self._modern_config.get_tool_path("frida")
            logger.debug("Legacy key 'frida_path' mapped to modern tool path: '%s'.", tool_path)
            return tool_path or default
        if key == "log_dir":
            log_dir = str(self._modern_config.get_logs_dir())
            logger.debug("Legacy key 'log_dir' mapped to modern logs directory: '%s'.", log_dir)
            return log_dir
        if key == "output_dir":
            output_dir = str(self._modern_config.get_output_dir())
            logger.debug("Legacy key 'output_dir' mapped to modern output directory: '%s'.", output_dir)
            return output_dir
        if key == "temp_dir":
            temp_dir = self._modern_config.get("directories.temp", str(self._modern_config.get_cache_dir()))
            logger.debug("Legacy key 'temp_dir' mapped to modern temp directory: '%s'.", temp_dir)
            return temp_dir

        # Try modern config first, then legacy structure
        result = self._modern_config.get(key, None)
        if result is not None:
            logger.debug("Key '%s' found in modern config: '%s'.", key, result)
            return result

        result = self.config.get(key, default)
        logger.debug("Key '%s' not found in modern config, falling back to legacy structure. Result: '%s'.", key, result)
        return result

    def set(self, key: str, value: object) -> None:
        """Set configuration value.

        Updates a configuration value in the modern configuration system. The change
        is delegated to the underlying modern config instance which handles persistence
        and caching of configuration changes.

        Args:
            key: Configuration key to set. Should be a valid configuration key path.
            value: Value to set for the given key.

        """
        logger.debug("ConfigManager.set() called for key: '%s', value: '%s'.", key, value)
        # Update modern config
        self._modern_config.set(key, value)
        logger.debug("Key '%s' set in modern config.", key)

    def update(self, updates: dict[str, Any]) -> None:
        """Update multiple configuration values.

        Applies multiple configuration updates in batch by calling set() for each
        key-value pair in the provided dictionary. This is more convenient than
        calling set() multiple times individually.

        Args:
            updates: Dictionary of configuration updates where keys are configuration
                    keys and values are the new values to set.

        """
        logger.debug("ConfigManager.update() called with updates: %s.", updates)
        for key, value in updates.items():
            self.set(key, value)
        logger.debug("ConfigManager updates applied.")

    def get_model_repositories(self) -> dict[str, Any]:
        """Get model repository configuration.

        Retrieves the complete model repository configuration section from the config,
        which contains settings for where machine learning models are stored and how
        they are accessed. Returns an empty dictionary if the section is missing or
        not a valid dictionary.

        Returns:
            dict[str, Any]: Model repository configuration dictionary with entries for
                           each configured repository (e.g., 'local', 'remote').

        """
        logger.debug("ConfigManager.get_model_repositories() called.")
        result = self.config.get("model_repositories", {})
        return result if isinstance(result, dict) else {}

    def is_repository_enabled(self, repo_name: str) -> bool:
        """Check if a model repository is enabled.

        Checks the model repository configuration to determine whether a specific
        repository is enabled. Returns False if the repository doesn't exist or if
        the 'enabled' field is not a valid boolean.

        Args:
            repo_name: Name of the repository to check (e.g., 'local', 'remote').

        Returns:
            bool: True if repository exists and enabled field is True, False otherwise.

        """
        logger.debug("ConfigManager.is_repository_enabled() called for repo: '%s'.", repo_name)
        repos = self.get_model_repositories()
        repo = repos.get(repo_name, {})
        if not isinstance(repo, dict):
            logger.debug("Repository '%s' enabled status: False.", repo_name)
            return False
        enabled = repo.get("enabled", False)
        if not isinstance(enabled, bool):
            logger.debug("Repository '%s' enabled status: False.", repo_name)
            return False
        logger.debug("Repository '%s' enabled status: %s.", repo_name, enabled)
        return enabled

    def get_ghidra_path(self) -> str | None:
        """Get the Ghidra installation path.

        Retrieves the path to the Ghidra installation directory from the modern
        configuration system. Ghidra is used for binary analysis and reverse engineering
        tasks within Intellicrack.

        Returns:
            str | None: Path to Ghidra installation directory if found, None if not configured.

        """
        logger.debug("ConfigManager.get_ghidra_path() called.")
        return self._modern_config.get_tool_path("ghidra")

    def get_tool_path(self, tool_name: str) -> str | None:
        """Get path for any tool.

        Retrieves the installation path for any configured external tool (Ghidra, Radare2,
        Frida, etc.) from the modern configuration system. The result is validated to
        ensure it is either a string path or None.

        Args:
            tool_name: Name of the tool to look up (e.g., 'ghidra', 'radare2', 'frida').

        Returns:
            str | None: Path to the tool if found and valid, None otherwise.

        """
        logger.debug("ConfigManager.get_tool_path() called for tool: '%s'.", tool_name)
        result = self._modern_config.get_tool_path(tool_name)
        return result if isinstance(result, (str, type(None))) else None

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available.

        Checks whether a specific external tool is installed and available for use.
        This method queries the modern configuration system to determine tool availability.

        Args:
            tool_name: Name of the tool to check (e.g., 'ghidra', 'radare2', 'frida').

        Returns:
            bool: True if tool is available and configured, False otherwise.

        """
        logger.debug("ConfigManager.is_tool_available() called for tool: '%s'.", tool_name)
        available = self._modern_config.is_tool_available(tool_name)
        logger.debug("Tool '%s' availability: %s.", tool_name, available)
        return available

    def get_logs_dir(self) -> object:
        """Get logs directory.

        Retrieves the directory path where application logs are stored. This directory
        is managed by the modern configuration system and is platform-specific.

        Returns:
            object: Logs directory path object.

        """
        logger.debug("ConfigManager.get_logs_dir() called.")
        return self._modern_config.get_logs_dir()

    def get_output_dir(self) -> object:
        """Get output directory.

        Retrieves the directory path where analysis results and outputs are stored.
        This directory is managed by the modern configuration system.

        Returns:
            object: Output directory path object.

        """
        logger.debug("ConfigManager.get_output_dir() called.")
        return self._modern_config.get_output_dir()

    def get_cache_dir(self) -> object:
        """Get cache directory.

        Retrieves the directory path where cached data and temporary files are stored.
        This directory is managed by the modern configuration system.

        Returns:
            object: Cache directory path object.

        """
        logger.debug("ConfigManager.get_cache_dir() called.")
        return self._modern_config.get_cache_dir()

    def validate_config(self) -> bool:
        """Validate the current configuration.

        Validates the current configuration state. The modern configuration system
        handles the actual validation. This method always returns True for backward
        compatibility with legacy code.

        Returns:
            bool: True to indicate configuration is valid (always True for backward compatibility).

        """
        logger.debug("ConfigManager.validate_config() called (delegating to modern system).")
        # Basic validation - modern config handles the real validation
        # Always return True for backward compatibility
        return True

    def items(self) -> object:
        """Return items from the configuration dictionary.

        Provides a view of all key-value pairs in the configuration dictionary,
        allowing iteration over configuration entries.

        Returns:
            object: Items view of configuration dictionary.

        """
        logger.debug("ConfigManager.items() called.")
        return self.config.items()

    def keys(self) -> object:
        """Return keys from the configuration dictionary.

        Provides a view of all keys in the configuration dictionary, allowing
        iteration over configuration key names.

        Returns:
            object: Keys view of configuration dictionary.

        """
        logger.debug("ConfigManager.keys() called.")
        return self.config.keys()

    def values(self) -> object:
        """Return values from the configuration dictionary.

        Provides a view of all values in the configuration dictionary, allowing
        iteration over configuration values.

        Returns:
            object: Values view of configuration dictionary.

        """
        logger.debug("ConfigManager.values() called.")
        return self.config.values()

    def __getitem__(self, key: str) -> object:
        """Allow dictionary-style access.

        Provides dictionary-style access to configuration values using square bracket
        notation, delegating to the get() method for key lookup and type conversion.

        Args:
            key: Configuration key to access.

        Returns:
            object: Configuration value.

        """
        logger.debug("ConfigManager.__getitem__() called for key: '%s'.", key)
        return self.get(key)

    def __setitem__(self, key: str, value: object) -> None:
        """Allow dictionary-style setting.

        Provides dictionary-style setting of configuration values using square bracket
        notation, delegating to the set() method for key assignment.

        Args:
            key: Configuration key to set.
            value: Value to set for the given key.

        """
        logger.debug("ConfigManager.__setitem__() called for key: '%s', value: '%s'.", key, value)
        self.set(key, value)

    def __contains__(self, key: str) -> bool:
        """Check if key exists in configuration.

        Provides support for the 'in' operator to check whether a configuration key
        exists in the configuration dictionary.

        Args:
            key: Configuration key to check.

        Returns:
            bool: True if key exists in configuration, False otherwise.

        """
        logger.debug("ConfigManager.__contains__() called for key: '%s'.", key)
        return key in self.config


# Global configuration instance
_config_manager: ConfigManager | None = None


def load_config(config_path: str | None = None) -> dict[str, Any]:
    """Load configuration using the modern config system.

    This function initializes the global configuration manager if not already
    present and returns a legacy-compatible configuration dictionary. It's
    maintained for backward compatibility with code expecting a dictionary-based
    configuration system. The returned dictionary is a snapshot of the current
    configuration state and is rebuilt on each call to reflect any changes.

    Args:
        config_path: Path to configuration file (ignored in modern system as it
                     uses platform-specific locations automatically). Provided for
                     backward compatibility only.

    Returns:
        dict[str, Any]: Configuration dictionary for legacy compatibility
                        containing all configuration sections and values including
                        paths, tools, analysis settings, logging, performance, and
                        UI configuration.

    Examples:
        >>> config = load_config()
        >>> print(config["ghidra_path"])
        '/opt/ghidra/ghidraRun'

    Note:
        New code should use get_config() to get the ConfigManager instance
        instead of working with raw dictionaries.

    """
    global _config_manager  # pylint: disable=global-statement
    logger.debug("Global load_config() called. Provided config_path: '%s'.", config_path)
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
        logger.info("Global ConfigManager initialized during load_config().")
    return _config_manager.config


def get_config() -> ConfigManager:
    """Get the global configuration manager instance.

    Returns:
        ConfigManager: The global configuration manager instance (legacy wrapper)

    """
    global _config_manager  # pylint: disable=global-statement
    logger.debug("Global get_config() called.")
    if _config_manager is None:
        _config_manager = ConfigManager()
        logger.info("Global ConfigManager initialized during get_config().")
    return _config_manager


def save_config() -> bool:
    """Save the global configuration.

    Saves the current configuration state to the configuration file. This function
    delegates to the modern configuration system which handles automatic persistence
    of configuration changes. It ensures the global ConfigManager instance is
    initialized before attempting to save.

    Returns:
        bool: True if saved successfully, False if the global ConfigManager was not
              initialized and cannot be used.

    """
    logger.debug("Global save_config() called.")
    if _config_manager is not None:
        return _config_manager.save_config()
    logger.warning("Global ConfigManager not initialized, cannot save config.")
    return False


# Lazy initialization of CONFIG to prevent blocking during import
# CONFIG will be loaded on first access via the _LazyConfig class
_config_initialized = False
_config_dict: dict[str, Any] = {}


class _LazyConfig(dict[str, Any]):
    """Lazy-loading configuration dictionary that initializes on first access."""

    def __init__(self) -> None:
        """Initialize lazy-loading configuration dictionary.

        Creates a new lazy-loading configuration dictionary that defers
        initialization until first access to minimize startup time.

        """
        super().__init__()
        self._initialized = False
        logger.debug("_LazyConfig instance created.")

    def _ensure_loaded(self) -> None:
        """Load configuration if not already loaded.

        This internal method ensures the configuration dictionary is populated by
        calling load_config() on first access. Subsequent calls are skipped if
        already loaded. Any errors during loading are logged but do not raise
        exceptions.

        """
        if not self._initialized:
            logger.debug("LazyConfig: Configuration not loaded, triggering load.")
            try:
                config_data = load_config()
                self.update(config_data)
                logger.info("LazyConfig: Configuration loaded successfully.")
            except (FileNotFoundError, PermissionError, ValueError, KeyError, ImportError) as e:
                logger.warning("LazyConfig: Failed to load config, using empty dict: %s", e, exc_info=True)
            except Exception as e:
                logger.exception("LazyConfig: An unexpected error occurred during config loading: %s", e)
            self._initialized = True
        else:
            logger.debug("LazyConfig: Configuration already loaded.")

    def __getitem__(self, key: str) -> object:
        """Get item from lazy-loaded configuration.

        Ensures the configuration is loaded, then retrieves the value for the given
        key from the underlying dictionary.

        Args:
            key: Configuration key to access.

        Returns:
            object: Configuration value for the given key.

        """
        self._ensure_loaded()
        logger.debug("LazyConfig: Accessing item with key '%s'.", key)
        return super().__getitem__(key)

    def __setitem__(self, key: str, value: object) -> None:
        """Set item in lazy-loaded configuration.

        Ensures the configuration is loaded, then sets the given key-value pair in
        the underlying dictionary.

        Args:
            key: Configuration key to set.
            value: Value to set for the given key.

        Returns:
            None

        """
        self._ensure_loaded()
        logger.debug("LazyConfig: Setting item with key '%s' to value '%s'.", key, value)
        super().__setitem__(key, value)

    def __contains__(self, key: object) -> bool:
        """Check if key exists in lazy-loaded configuration.

        Performs a containment check on the lazy-loaded configuration dictionary,
        ensuring the configuration is loaded before checking for key existence.

        Args:
            key: Configuration key to check.

        Returns:
            bool: True if key exists in configuration, False otherwise.

        """
        self._ensure_loaded()
        if isinstance(key, str):
            logger.debug("LazyConfig: Checking containment for key '%s'.", key)
        return super().__contains__(key)

    def get(self, key: str, default: object = None) -> object:
        """Get item from lazy-loaded configuration with default fallback.

        Ensures the configuration is loaded, then retrieves the value for the given
        key or returns the default if the key does not exist.

        Args:
            key: Configuration key to retrieve.
            default: Default value if key not found. Defaults to None if not
                     provided.

        Returns:
            object: Configuration value if found, or default value if not found.

        """
        self._ensure_loaded()
        logger.debug("LazyConfig: Getting item with key '%s'.", key)
        return super().get(key, default)

    def keys(self) -> KeysView[str]:
        """Get keys from lazy-loaded configuration.

        Returns:
            KeysView[str]: Keys view of configuration dictionary.

        """
        self._ensure_loaded()
        logger.debug("LazyConfig: Getting keys.")
        return super().keys()

    def values(self) -> ValuesView[Any]:
        """Get values from lazy-loaded configuration.

        Returns:
            ValuesView[Any]: Values view of configuration dictionary.

        """
        self._ensure_loaded()
        logger.debug("LazyConfig: Getting values.")
        return super().values()

    def items(self) -> ItemsView[str, Any]:
        """Get items from lazy-loaded configuration.

        Returns:
            ItemsView[str, Any]: Items view of configuration dictionary.

        """
        self._ensure_loaded()
        logger.debug("LazyConfig: Getting items.")
        return super().items()


# Create lazy-loading CONFIG instance
CONFIG = _LazyConfig()
DEFAULT_CONFIG = CONFIG

# Export main components
__all__ = [
    "CONFIG",
    "ConfigManager",
    "DEFAULT_CONFIG",
    "find_tool",
    "get_config",
    "get_system_path",
    "load_config",
    "save_config",
]
