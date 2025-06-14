"""
Configuration Management 

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


import json
import logging
import os
import sys
from typing import Any, Dict, Optional

# Configure module logger
logger = logging.getLogger(__name__)

# Define functions for path discovery
def find_tool(tool_name, required_executables=None):
    """
    Find tool executable path using the dynamic path discovery system.
    
    Args:
        tool_name: Name of the tool to find (e.g., 'ghidra', 'radare2', 'frida')
        required_executables: Optional list of required executables for the tool
        
    Returns:
        Path to the tool executable or None if not found
    """
    try:
        from .utils.path_discovery import find_tool as path_discovery_find_tool
        return path_discovery_find_tool(tool_name, required_executables)
    except ImportError:
        logger.warning("Path discovery module not available")
        # Fallback to basic PATH search
        import shutil
        return shutil.which(tool_name)

def get_system_path(path_type):
    """
    Get system-specific paths (e.g., desktop, documents, downloads).
    
    Args:
        path_type: Type of system path to retrieve
        
    Returns:
        Path string or None if not found
    """
    try:
        from .utils.path_discovery import get_system_path as path_discovery_get_system_path
        return path_discovery_get_system_path(path_type)
    except ImportError:
        logger.warning("Path discovery module not available")
        # Fallback to basic paths
        if path_type == "desktop":
            return os.path.join(os.path.expanduser("~"), "Desktop")
        elif path_type == "documents":
            return os.path.join(os.path.expanduser("~"), "Documents")
        elif path_type == "downloads":
            return os.path.join(os.path.expanduser("~"), "Downloads")
        elif path_type == "temp":
            import tempfile
            return tempfile.gettempdir()
        return None

# Default configuration structure
DEFAULT_CONFIG = {
    # Paths and Directories
    "log_dir": os.path.join(os.path.expanduser("~"), "intellicrack", "logs"),
    "ghidra_path": None,  # Will be discovered dynamically
    "radare2_path": None,  # Will be discovered dynamically
    "frida_path": None,  # Will be discovered dynamically
    "output_dir": os.path.join(os.path.expanduser("~"), "intellicrack", "output"),
    "temp_dir": os.path.join(os.path.expanduser("~"), "intellicrack", "temp"),
    "plugin_directory": "plugins",
    "download_directory": "models/downloads",

    # Analysis Settings
    "analysis": {
        "default_timeout": 300,  # 5 minutes
        "max_file_size": 100 * 1024 * 1024,  # 100 MB
        "enable_deep_analysis": True,
        "enable_symbolic_execution": False,  # Requires angr
        "enable_dynamic_analysis": True,
        "enable_network_analysis": True,
        "detect_protections": True,
        "auto_detect_format": True,
        "parallel_threads": 4,
        "cache_results": True,
        "cache_ttl": 3600  # 1 hour
    },

    # Patching Settings
    "patching": {
        "enable_memory_patching": True,
        "backup_before_patch": True,
        "verify_patches": True,
        "max_patch_attempts": 3,
        "patch_timeout": 60,
        "generate_launcher": True,
        "launcher_template": "default"
    },

    # Network Settings
    "network": {
        "enable_ssl_interception": True,
        "proxy_port": 8080,
        "capture_interface": "any",
        "capture_filter": "",
        "save_captures": True,
        "max_capture_size": 50 * 1024 * 1024  # 50 MB
    },

    # UI Settings
    "ui": {
        "theme": "default",
        "window_size": [1200, 800],
        "show_splash": True,
        "auto_save_layout": True,
        "confirm_exit": True,
        "show_tooltips": True,
        "font_size": 10,
        "hex_columns": 16
    },

    # Logging Settings
    "logging": {
        "level": "INFO",
        "enable_file_logging": True,
        "enable_console_logging": True,
        "max_log_size": 10 * 1024 * 1024,  # 10 MB
        "log_rotation": 5,
        "verbose_logging": False
    },

    # Security Settings
    "security": {
        "verify_signatures": True,
        "sandbox_plugins": True,
        "scan_downloads": True,
        "block_suspicious": True,
        "quarantine_malware": True
    },

    # Performance Settings
    "performance": {
        "max_memory_usage": 2048,  # MB
        "enable_gpu_acceleration": True,
        "cache_size": 100,  # MB
        "chunk_size": 4096,  # bytes
        "enable_multiprocessing": True
    },

    # Runtime Settings
    "runtime": {
        "max_runtime_monitoring": 30000,  # 30 seconds
        "runtime_interception": True,
        "hook_delay": 100,  # ms
        "monitor_child_processes": True
    },

    # Plugin Settings
    "plugins": {
        "default_plugins": ["HWID Spoofer", "Anti-Debugger"],
        "auto_load": True,
        "check_updates": True,
        "allow_third_party": True
    },

    # General Settings
    "general": {
        "first_run_completed": False,
        "auto_backup": True,
        "auto_save_results": True,
        "check_for_updates": True,
        "send_analytics": False,
        "language": "en"
    },

    # AI/ML Settings
    "ai": {
        "context_size": 8192,
        "temperature": 0.7,
        "top_p": 0.95,
        "selected_model_path": None,
        "enable_ai_suggestions": True,
        "cache_responses": True
    },

    # ML Model Settings
    "ml": {
        "vulnerability_model_path": os.path.join(os.path.dirname(__file__ or os.getcwd()), "..", "..", "models", "ml_vulnerability_model.joblib") if __file__ else os.path.join(os.getcwd(), "models", "ml_vulnerability_model.joblib"),
        "similarity_model_path": None,
        "enable_ml_features": True,
        "model_cache_size": 100,  # MB
        "prediction_threshold": 0.7,
        "auto_load_models": True
    },

    # Model repository settings
    "model_repositories": {
        "local": {
            "type": "local",
            "enabled": True,
            "models_directory": "models"
        },
        "openai": {
            "type": "openai",
            "enabled": False,
            "api_key": "",
            "endpoint": "https://api.openai.com/v1",
            "timeout": 60,
            "proxy": "",
            "rate_limit": {
                "requests_per_minute": 60,
                "requests_per_day": 1000
            }
        },
        "anthropic": {
            "type": "anthropic",
            "enabled": False,
            "api_key": "",
            "endpoint": "https://api.anthropic.com",
            "timeout": 60,
            "proxy": "",
            "rate_limit": {
                "requests_per_minute": 60,
                "requests_per_day": 1000
            }
        },
        "openrouter": {
            "type": "openrouter",
            "enabled": False,
            "api_key": "",
            "endpoint": "https://openrouter.ai/api",
            "timeout": 60,
            "proxy": "",
            "rate_limit": {
                "requests_per_minute": 60,
                "requests_per_day": 1000
            }
        },
        "lmstudio": {
            "type": "lmstudio",
            "enabled": False,
            "api_key": "",
            "endpoint": "https://api.lmstudio.ai",
            "timeout": 60,
            "proxy": "",
            "rate_limit": {
                "requests_per_minute": 60,
                "requests_per_day": 1000
            }
        },
        "google": {
            "type": "google",
            "enabled": False,
            "api_key": "",
            "endpoint": "https://generativelanguage.googleapis.com",
            "timeout": 60,
            "proxy": "",
            "rate_limit": {
                "requests_per_minute": 60,
                "requests_per_day": 1000
            }
        }
    },
    "api_cache": {
        "enabled": True,
        "ttl": 3600,  # 1 hour
        "max_size_mb": 100
    },
    "verify_checksums": True
}


class ConfigManager:
    """
    Configuration manager for Intellicrack application.

    Handles loading, saving, and management of configuration settings
    with JSON persistence and default fallbacks.
    """

    def __init__(self, config_path: str = "intellicrack_config.json"):
        """
        Initialize configuration manager.

        Args:
            config_path: Path to the configuration file
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.load_config()

    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration from JSON file with fallback to defaults.

        Returns:
            Dictionary containing configuration settings
        """
        logger.debug("Loading configuration...")
        logger.info("Looking for config file at: %s", os.path.abspath(self.config_path))

        if os.path.exists(self.config_path):
            logger.info("Config file exists, loading...")
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded_config = json.load(f)
                    logger.info("Loaded config with keys: %s", ', '.join(loaded_config.keys()))

                # Check if Ghidra path exists
                if "ghidra_path" in loaded_config:
                    ghidra_path = loaded_config["ghidra_path"]
                    logger.info("Checking Ghidra path from config: %s", ghidra_path)

                    # Check if path exists (handle both Windows and WSL contexts)
                    path_exists = False
                    if ghidra_path:
                        if os.path.exists(ghidra_path):
                            path_exists = True
                        elif sys.platform.startswith('linux') and 'microsoft' in os.uname().release.lower():
                            # Running in WSL, try converting Windows path
                            wsl_path = ghidra_path.replace('C:\\', '/mnt/c/').replace('\\', '/')
                            if os.path.exists(wsl_path):
                                path_exists = True
                                loaded_config["ghidra_path"] = wsl_path  # Update to WSL path

                    if path_exists:
                        logger.info("✓ Ghidra path exists at %s", ghidra_path)
                    elif ghidra_path:
                        logger.warning("✗ Ghidra path does not exist at %s", ghidra_path)
                    else:
                        logger.info("Ghidra path not configured (set to None)")

                # Update any missing keys with defaults
                for key, value in DEFAULT_CONFIG.items():
                    if key not in loaded_config:
                        loaded_config[key] = value
                        logger.info("Added missing key '%s' with default value", key)

                # Ensure selected_model_path is loaded, defaulting to None
                loaded_config["selected_model_path"] = loaded_config.get("selected_model_path", None)

                self.config = loaded_config
                logger.debug("Configuration loaded successfully")
                return self.config

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error loading config: %s", e)
                logger.debug("Using default configuration due to error")
                self.config = DEFAULT_CONFIG.copy()
                return self.config
        else:
            logger.info("Config file does not exist, creating with defaults")
            self.config = DEFAULT_CONFIG.copy()
            self.save_config()
            return self.config

    def save_config(self) -> bool:
        """
        Save current configuration to JSON file.

        Returns:
            True if saved successfully, False otherwise
        """
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)
                logger.info("Saved config to %s", os.path.abspath(self.config_path))
            return True
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error saving config: %s", e)
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.

        Args:
            key: Configuration key
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value.

        Args:
            key: Configuration key
            value: Value to set
        """
        self.config[key] = value
        logger.debug("Set config key '%s' to '%s'", key, value)

    def update(self, updates: Dict[str, Any]) -> None:
        """
        Update multiple configuration values.

        Args:
            updates: Dictionary of key-value pairs to update
        """
        self.config.update(updates)
        logger.debug("Updated config with %d values", len(updates))

    def get_model_repositories(self) -> Dict[str, Any]:
        """
        Get model repository configuration.

        Returns:
            Dictionary of model repository settings
        """
        return self.config.get("model_repositories", {})

    def is_repository_enabled(self, repo_name: str) -> bool:
        """
        Check if a model repository is enabled.

        Args:
            repo_name: Name of the repository

        Returns:
            True if repository is enabled, False otherwise
        """
        repos = self.get_model_repositories()
        repo = repos.get(repo_name, {})
        return repo.get("enabled", False)

    def get_ghidra_path(self) -> Optional[str]:
        """
        Get the Ghidra installation path.

        Returns:
            Path to Ghidra or None if not configured
        """
        path = self.get("ghidra_path")
        if path and os.path.exists(path):
            return path

        # Try dynamic discovery
        try:
            from .utils.path_discovery import find_tool as path_discovery_find_tool
            discovered_path = path_discovery_find_tool("ghidra")
            if discovered_path:
                self.config["ghidra_path"] = discovered_path
                self.save_config()
                return discovered_path
        except ImportError:
            logger.warning("Path discovery not available")

        return None

    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """
        Get path for any tool with dynamic discovery.
        
        Args:
            tool_name: Name of the tool (e.g., 'ghidra', 'radare2', 'frida')
            
        Returns:
            Path to tool or None if not found
        """
        # Check config first
        config_key = f"{tool_name}_path"
        path = self.get(config_key)
        if path and os.path.exists(path):
            return path

        # Try dynamic discovery
        try:
            from .utils.path_discovery import find_tool as path_discovery_find_tool
            discovered_path = path_discovery_find_tool(tool_name)
            if discovered_path:
                self.config[config_key] = discovered_path
                self.save_config()
                return discovered_path
        except ImportError:
            logger.warning("Path discovery not available for %s", tool_name)

        return None

    def validate_config(self) -> bool:
        """
        Validate the current configuration.

        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            # Check required keys exist
            required_keys = ["log_dir", "plugin_directory", "model_repositories"]
            for _key in required_keys:
                if _key not in self.config:
                    logger.error("Missing required configuration key: %s", _key)
                    return False

            # Validate model repositories structure
            repos = self.get_model_repositories()
            if not isinstance(repos, dict):
                logger.error("model_repositories must be a dictionary")
                return False

            logger.info("Configuration validation passed")
            return True

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Configuration validation error: %s", e)
            return False


# Global configuration instance
_config_manager: Optional[ConfigManager] = None


def load_config(config_path: str = "intellicrack_config.json") -> Dict[str, Any]:
    """
    Load configuration using the global config manager.

    Args:
        config_path: Path to configuration file

    Returns:
        Configuration dictionary
    """
    global _config_manager  # pylint: disable=global-statement
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager.config


def get_config() -> ConfigManager:
    """
    Get the global configuration manager instance.

    Returns:
        ConfigManager instance
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


# Global CONFIG dictionary for backwards compatibility
CONFIG = load_config()

# Export main components
__all__ = [
    'ConfigManager',
    'load_config',
    'get_config',
    'save_config',
    'CONFIG',
    'DEFAULT_CONFIG'
]
