"""
Configuration Management - Modern Dynamic Configuration System

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import os
from typing import Any, Dict, Optional

# Import the new configuration system
from .core.config_manager import get_config as get_new_config

logger = logging.getLogger(__name__)

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError as e:
    logger.error("Import error in config: %s", e)
    pass

# Global configuration instance
_modern_config = None
_legacy_mode = False


def _get_modern_config():
    """Get the modern configuration instance."""
    global _modern_config  # pylint: disable=global-statement
    if _modern_config is None:
        _modern_config = get_new_config()
    return _modern_config

# Tool discovery functions using new system


def find_tool(tool_name: str, required_executables=None) -> Optional[str]:
    """
    Find tool executable path using the modern discovery system.

    Args:
        tool_name: Name of the tool to find (e.g., 'ghidra', 'radare2', 'frida')
        required_executables: Optional list of required executables for the tool

    Returns:
        Path to the tool executable or None if not found
    """
    if required_executables:
        logger.debug("Tool search for %s with required executables: %s",
                     tool_name, required_executables)
    try:
        config = _get_modern_config()
        return config.get_tool_path(tool_name)
    except (AttributeError, KeyError, ValueError) as e:
        logger.warning("Modern tool discovery failed for %s: %s",
                       tool_name, e, exc_info=True)
        # Fallback to basic PATH search
        import shutil
        return shutil.which(tool_name)


def get_system_path(path_type: str) -> Optional[str]:
    """
    Get system-specific paths using modern configuration.

    Args:
        path_type: Type of system path to retrieve

    Returns:
        Path string or None if not found
    """
    try:
        config = _get_modern_config()
        if path_type == "output":
            return str(config.get_output_dir())
        if path_type == "cache":
            return str(config.get_cache_dir())
        if path_type == "logs":
            return str(config.get_logs_dir())
        if path_type == "temp":
            return config.get('directories.temp')
        return None
    except (AttributeError, KeyError, ValueError, TypeError) as e:
        logger.warning("System path lookup failed for %s: %s",
                       path_type, e, exc_info=True)
        # Fallback to basic paths
        if path_type == "desktop":
            return os.path.join(os.path.expanduser("~"), "Desktop")
        if path_type == "documents":
            return os.path.join(os.path.expanduser("~"), "Documents")
        if path_type == "downloads":
            return os.path.join(os.path.expanduser("~"), "Downloads")
        if path_type == "temp":
            import tempfile
            return tempfile.gettempdir()
        return None


class ConfigManager:
    """
    Legacy configuration manager that wraps the modern IntellicrackConfig.

    Provides backward compatibility for existing code while using the new
    dynamic configuration system under the hood.
    """

    def __init__(self, config_path: str = None):
        """Initialize legacy configuration manager wrapper."""
        self._modern_config = _get_modern_config()
        self.config_path = config_path or str(self._modern_config.config_file)

    @property
    def config(self) -> Dict[str, Any]:
        """Get configuration as dictionary for legacy compatibility."""
        return self._build_legacy_config()

    def _build_legacy_config(self) -> Dict[str, Any]:
        """Build a legacy-compatible configuration dictionary."""
        config = self._modern_config

        # Create legacy structure from modern config
        legacy_config = {
            # Paths - mapped from modern directories
            "log_dir": str(config.get_logs_dir()),
            "output_dir": str(config.get_output_dir()),
            "temp_dir": config.get('directories.temp', str(config.get_cache_dir())),
            "plugin_directory": "plugins",
            "download_directory": str(config.get_cache_dir() / "downloads"),

            # Tool paths
            "ghidra_path": config.get_tool_path('ghidra'),
            "radare2_path": config.get_tool_path('radare2'),
            "frida_path": config.get_tool_path('frida'),

            # Analysis settings
            "analysis": config.get('analysis', {}),

            # Other sections from modern config
            "patching": config.get('patching', {}),
            "network": config.get('network', {}),
            "ui": config.get('ui', {}),
            "logging": {
                "level": config.get('preferences.log_level', 'INFO'),
                "enable_file_logging": True,
                "enable_console_logging": True,
                "max_log_size": 10 * 1024 * 1024,
                "log_rotation": 5,
                "verbose_logging": config.get('preferences.log_level') == 'DEBUG'
            },
            "security": config.get('security', {}),
            "performance": {
                "max_memory_usage": 2048,
                "enable_gpu_acceleration": True,
                "cache_size": 100,
                "chunk_size": 4096,
                "enable_multiprocessing": True
            },
            "runtime": {},
            "plugins": {
                "default_plugins": [],
                "auto_load": True,
                "check_updates": config.get('preferences.check_for_updates', True),
                "allow_third_party": True
            },
            "general": {
                "first_run_completed": True,
                "auto_backup": config.get('preferences.auto_backup_results', True),
                "auto_save_results": config.get('preferences.auto_backup_results', True),
                "check_for_updates": config.get('preferences.check_for_updates', True),
                "send_analytics": False,
                "language": "en"
            },
            "ai": config.get('ai', {}),
            "ml": {
                "enable_ml_features": config.get('analysis.enable_ml_analysis', True),
                "model_cache_size": 100,
                "prediction_threshold": 0.7,
                "auto_load_models": True
            },
            "model_repositories": {
                "local": {
                    "type": "local",
                    "enabled": True,
                    "models_directory": str(config.get_cache_dir() / "models")
                }
            },
            "c2": {},
            "api_cache": {
                "enabled": True,
                "ttl": 3600,
                "max_size_mb": 100
            },
            "verify_checksums": True,
            "external_services": {},
            "api": {}
        }

        return legacy_config

    def load_config(self) -> Dict[str, Any]:
        """Load configuration - delegates to modern system."""
        return self.config

    def save_config(self) -> bool:
        """Save configuration - delegates to modern system."""
        # Modern config auto-saves, so this is just compatibility
        # Always return True for backward compatibility
        return True

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with legacy key support."""
        # Handle legacy key mappings
        if key == "ghidra_path":
            return self._modern_config.get_tool_path('ghidra') or default
        if key == "radare2_path":
            return self._modern_config.get_tool_path('radare2') or default
        if key == "frida_path":
            return self._modern_config.get_tool_path('frida') or default
        if key == "log_dir":
            return str(self._modern_config.get_logs_dir())
        if key == "output_dir":
            return str(self._modern_config.get_output_dir())
        if key == "temp_dir":
            return self._modern_config.get('directories.temp', str(self._modern_config.get_cache_dir()))

        # Try modern config first, then legacy structure
        result = self._modern_config.get(key, None)
        if result is not None:
            return result
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        # Update modern config
        self._modern_config.set(key, value)

    def update(self, updates: Dict[str, Any]) -> None:
        """Update multiple configuration values."""
        for key, value in updates.items():
            self.set(key, value)

    def get_model_repositories(self) -> Dict[str, Any]:
        """Get model repository configuration."""
        return self.config.get("model_repositories", {})

    def is_repository_enabled(self, repo_name: str) -> bool:
        """Check if a model repository is enabled."""
        repos = self.get_model_repositories()
        repo = repos.get(repo_name, {})
        return repo.get("enabled", False)

    def get_ghidra_path(self) -> Optional[str]:
        """Get the Ghidra installation path."""
        return self._modern_config.get_tool_path('ghidra')

    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """Get path for any tool."""
        return self._modern_config.get_tool_path(tool_name)

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available."""
        return self._modern_config.is_tool_available(tool_name)

    def get_logs_dir(self):
        """Get logs directory."""
        return self._modern_config.get_logs_dir()

    def get_output_dir(self):
        """Get output directory."""
        return self._modern_config.get_output_dir()

    def get_cache_dir(self):
        """Get cache directory."""
        return self._modern_config.get_cache_dir()

    def validate_config(self) -> bool:
        """Validate the current configuration."""
        # Basic validation - modern config handles the real validation
        # Always return True for backward compatibility
        return True

    def items(self):
        """Return items from the configuration dictionary."""
        return self.config.items()

    def keys(self):
        """Return keys from the configuration dictionary."""
        return self.config.keys()

    def values(self):
        """Return values from the configuration dictionary."""
        return self.config.values()

    def __getitem__(self, key):
        """Allow dictionary-style access."""
        return self.config[key]

    def __setitem__(self, key, value):
        """Allow dictionary-style setting."""
        self.set(key, value)

    def __contains__(self, key):
        """Check if key exists in configuration."""
        return key in self.config


# Global configuration instance
_config_manager: Optional[ConfigManager] = None


def load_config(config_path: str = None) -> Dict[str, Any]:
    """
    Load configuration using the modern config system.

    Args:
        config_path: Path to configuration file (ignored in modern system)

    Returns:
        Configuration dictionary for legacy compatibility
    """
    global _config_manager  # pylint: disable=global-statement
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager.config


def get_config() -> ConfigManager:
    """
    Get the global configuration manager instance.

    Returns:
        ConfigManager instance (legacy wrapper)
    """
    global _config_manager  # pylint: disable=global-statement
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def save_config() -> bool:
    """
    Save the global configuration.

    Returns:
        True if saved successfully, False otherwise
    """
    if _config_manager is not None:
        return _config_manager.save_config()
    return False


# Backward compatibility - create a legacy config dict
try:
    _legacy_config_dict = load_config()
    CONFIG = _legacy_config_dict
except (FileNotFoundError, PermissionError, ValueError, KeyError, ImportError) as e:
    logger.warning(
        "Failed to load modern config, using empty dict: %s", e, exc_info=True)
    CONFIG = {}

# Create a DEFAULT_CONFIG for compatibility
DEFAULT_CONFIG = CONFIG

# Export main components
__all__ = [
    'ConfigManager',
    'load_config',
    'get_config',
    'save_config',
    'CONFIG',
    'DEFAULT_CONFIG',
    'find_tool',
    'get_system_path'
]
