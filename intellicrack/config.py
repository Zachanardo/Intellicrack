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
from typing import Any


logger = logging.getLogger(__name__)

# Lazy import of config_manager to prevent circular imports
_get_new_config = None


def _ensure_config_manager_imported() -> object:
    """Lazy import of config_manager to avoid circular dependencies."""
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


def _get_modern_config() -> object:
    """Get the modern configuration instance.

    This internal function implements a singleton pattern to ensure only one
    configuration instance exists throughout the application lifetime. It lazily
    initializes the modern IntellicrackConfig on first access.

    Returns:
        IntellicrackConfig: The global modern configuration instance

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
        tool_name: Name of the tool to find (e.g., 'ghidra', 'radare2', 'frida')
        required_executables: Optional list of required executables for the tool
                            (currently used for logging only)

    Returns:
        Path to the tool executable or None if not found

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
    configuration system and falls back to OS-specific defaults if needed.

    Args:
        path_type: Type of system path to retrieve. Valid values:
                  - "output": Output directory for results
                  - "cache": Cache directory for temporary data
                  - "logs": Log files directory
                  - "temp": Temporary files directory
                  - "desktop": User's desktop folder (fallback only)
                  - "documents": User's documents folder (fallback only)
                  - "downloads": User's downloads folder (fallback only)

    Returns:
        Path string or None if not found

    Examples:
        >>> get_system_path("output")
        '/home/user/.local/share/intellicrack/output'

        >>> get_system_path("cache")
        '/home/user/.cache/intellicrack'

    """
    logger.debug("Requesting system path for type: '%s'.", path_type)
    try:
        config = _get_modern_config()
        path = None
        if path_type == "output":
            path = str(config.get_output_dir())
        elif path_type == "cache":
            path = str(config.get_cache_dir())
        elif path_type == "logs":
            path = str(config.get_logs_dir())
        elif path_type == "temp":
            path = config.get("directories.temp")

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

    The ConfigManager acts as a bridge between legacy code expecting dictionary-style
    configuration access and the modern object-oriented configuration system. It
    automatically translates legacy keys to modern configuration paths and provides
    fallback values for backward compatibility.

    Attributes:
        config_path: Path to the configuration file (for compatibility)
        _modern_config: Internal reference to the modern IntellicrackConfig instance

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

    def __init__(self, config_path: str = None) -> None:
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
            Dict[str, Any]: Complete configuration dictionary with all sections
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
            Dict[str, Any]: Legacy-formatted configuration dictionary with
                           all expected sections and keys

        Note:
            This method is called by the config property and should not be
            used directly by external code.

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
            "download_directory": str(config.get_cache_dir() / "downloads"),
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
                    "models_directory": str(config.get_cache_dir() / "models"),
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
        """Load configuration - delegates to modern system."""
        logger.debug("ConfigManager.load_config() called (delegating to modern system).")
        return self.config

    def save_config(self) -> bool:
        """Save configuration - delegates to modern system."""
        # Modern config auto-saves, so this is just compatibility
        # Always return True for backward compatibility
        logger.debug("ConfigManager.save_config() called (modern config auto-saves).")
        return True

    def get(self, key: str, default: object = None) -> object:
        """Get configuration value with legacy key support."""
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
        """Set configuration value."""
        logger.debug("ConfigManager.set() called for key: '%s', value: '%s'.", key, value)
        # Update modern config
        self._modern_config.set(key, value)
        logger.debug("Key '%s' set in modern config.", key)

    def update(self, updates: dict[str, Any]) -> None:
        """Update multiple configuration values."""
        logger.debug("ConfigManager.update() called with updates: %s.", updates)
        for key, value in updates.items():
            self.set(key, value)
        logger.debug("ConfigManager updates applied.")

    def get_model_repositories(self) -> dict[str, Any]:
        """Get model repository configuration."""
        logger.debug("ConfigManager.get_model_repositories() called.")
        return self.config.get("model_repositories", {})

    def is_repository_enabled(self, repo_name: str) -> bool:
        """Check if a model repository is enabled."""
        logger.debug("ConfigManager.is_repository_enabled() called for repo: '%s'.", repo_name)
        repos = self.get_model_repositories()
        repo = repos.get(repo_name, {})
        enabled = repo.get("enabled", False)
        logger.debug("Repository '%s' enabled status: %s.", repo_name, enabled)
        return enabled

    def get_ghidra_path(self) -> str | None:
        """Get the Ghidra installation path."""
        logger.debug("ConfigManager.get_ghidra_path() called.")
        return self._modern_config.get_tool_path("ghidra")

    def get_tool_path(self, tool_name: str) -> str | None:
        """Get path for any tool."""
        logger.debug("ConfigManager.get_tool_path() called for tool: '%s'.", tool_name)
        return self._modern_config.get_tool_path(tool_name)

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available."""
        logger.debug("ConfigManager.is_tool_available() called for tool: '%s'.", tool_name)
        available = self._modern_config.is_tool_available(tool_name)
        logger.debug("Tool '%s' availability: %s.", tool_name, available)
        return available

    def get_logs_dir(self) -> object:
        """Get logs directory."""
        logger.debug("ConfigManager.get_logs_dir() called.")
        return self._modern_config.get_logs_dir()

    def get_output_dir(self) -> object:
        """Get output directory."""
        logger.debug("ConfigManager.get_output_dir() called.")
        return self._modern_config.get_output_dir()

    def get_cache_dir(self) -> object:
        """Get cache directory."""
        logger.debug("ConfigManager.get_cache_dir() called.")
        return self._modern_config.get_cache_dir()

    def validate_config(self) -> bool:
        """Validate the current configuration."""
        logger.debug("ConfigManager.validate_config() called (delegating to modern system).")
        # Basic validation - modern config handles the real validation
        # Always return True for backward compatibility
        return True

    def items(self) -> object:
        """Return items from the configuration dictionary."""
        logger.debug("ConfigManager.items() called.")
        return self.config.items()

    def keys(self) -> object:
        """Return keys from the configuration dictionary."""
        logger.debug("ConfigManager.keys() called.")
        return self.config.keys()

    def values(self) -> object:
        """Return values from the configuration dictionary."""
        logger.debug("ConfigManager.values() called.")
        return self.config.values()

    def __getitem__(self, key: str) -> object:
        """Allow dictionary-style access."""
        logger.debug("ConfigManager.__getitem__() called for key: '%s'.", key)
        return self.get(key)

    def __setitem__(self, key: str, value: object) -> None:
        """Allow dictionary-style setting."""
        logger.debug("ConfigManager.__setitem__() called for key: '%s', value: '%s'.", key, value)
        self.set(key, value)

    def __contains__(self, key: str) -> bool:
        """Check if key exists in configuration."""
        logger.debug("ConfigManager.__contains__() called for key: '%s'.", key)
        return key in self.config


# Global configuration instance
_config_manager: ConfigManager | None = None


def load_config(config_path: str = None) -> dict[str, Any]:
    """Load configuration using the modern config system.

    This function initializes the global configuration manager if not already
    present and returns a legacy-compatible configuration dictionary. It's
    maintained for backward compatibility with code expecting a dictionary-based
    configuration system.

    Args:
        config_path: Path to configuration file (ignored in modern system as
                    it uses platform-specific locations automatically)

    Returns:
        Configuration dictionary for legacy compatibility containing all
        configuration sections and values

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
        ConfigManager instance (legacy wrapper)

    """
    global _config_manager  # pylint: disable=global-statement
    logger.debug("Global get_config() called.")
    if _config_manager is None:
        _config_manager = ConfigManager()
        logger.info("Global ConfigManager initialized during get_config().")
    return _config_manager


def save_config() -> bool:
    """Save the global configuration.

    Returns:
        True if saved successfully, False otherwise

    """
    logger.debug("Global save_config() called.")
    if _config_manager is not None:
        return _config_manager.save_config()
    logger.warning("Global ConfigManager not initialized, cannot save config.")
    return False


# Lazy initialization of CONFIG to prevent blocking during import
# CONFIG will be loaded on first access via the _LazyConfig class
_config_initialized = False
_config_dict = {}


class _LazyConfig(dict):
    """Lazy-loading configuration dictionary that initializes on first access."""

    def __init__(self) -> None:
        super().__init__()
        self._initialized = False
        logger.debug("_LazyConfig instance created.")

    def _ensure_loaded(self) -> None:
        """Load configuration if not already loaded."""
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
        self._ensure_loaded()
        logger.debug("LazyConfig: Accessing item with key '%s'.", key)
        return super().__getitem__(key)

    def __setitem__(self, key: str, value: object) -> None:
        self._ensure_loaded()
        logger.debug("LazyConfig: Setting item with key '%s' to value '%s'.", key, value)
        return super().__setitem__(key, value)

    def __contains__(self, key: str) -> bool:
        self._ensure_loaded()
        logger.debug("LazyConfig: Checking containment for key '%s'.", key)
        return super().__contains__(key)

    def get(self, key: str, default: object = None) -> object:
        self._ensure_loaded()
        logger.debug("LazyConfig: Getting item with key '%s'.", key)
        return super().get(key, default)

    def keys(self) -> object:
        self._ensure_loaded()
        logger.debug("LazyConfig: Getting keys.")
        return super().keys()

    def values(self) -> object:
        self._ensure_loaded()
        logger.debug("LazyConfig: Getting values.")
        return super().values()

    def items(self) -> object:
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
