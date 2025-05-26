"""
Configuration Management

This module handles all configuration loading, saving, and management for Intellicrack.
Provides centralized configuration with JSON persistence and default fallbacks.
"""

import json
import logging
import os
from typing import Dict, Any, Optional

# Configure module logger
logger = logging.getLogger(__name__)

# Default configuration structure
DEFAULT_CONFIG = {
    # Paths and Directories
    "log_dir": os.path.join(os.path.expanduser("~"), "intellicrack", "logs"),
    "ghidra_path": r"C:\Program Files\Ghidra\ghidraRun.bat",
    "radare2_path": "/usr/bin/r2",  # Usually installed via package manager
    "ida_path": r"C:\Program Files\IDA Pro\ida.exe",
    "frida_path": "frida",  # Usually in PATH after pip install
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
        "verbose_logging": False,
        "enable_comprehensive_logging": True
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
    "download_directory": "models/downloads",
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
        logger.info(f"Looking for config file at: {os.path.abspath(self.config_path)}")
        
        if os.path.exists(self.config_path):
            logger.info("Config file exists, loading...")
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded_config = json.load(f)
                    logger.info(f"Loaded config with keys: {', '.join(loaded_config.keys())}")

                # Check if Ghidra path exists
                if "ghidra_path" in loaded_config:
                    ghidra_path = loaded_config["ghidra_path"]
                    logger.info(f"Checking Ghidra path from config: {ghidra_path}")
                    if os.path.exists(ghidra_path):
                        logger.info(f"✓ Ghidra path exists at {ghidra_path}")
                    else:
                        logger.warning(f"✗ Ghidra path does not exist at {ghidra_path}")

                # Update any missing keys with defaults
                for key, value in DEFAULT_CONFIG.items():
                    if key not in loaded_config:
                        loaded_config[key] = value
                        logger.info(f"Added missing key '{key}' with default value")

                # Ensure selected_model_path is loaded, defaulting to None
                loaded_config["selected_model_path"] = loaded_config.get("selected_model_path", None)

                self.config = loaded_config
                logger.debug("Configuration loaded successfully")
                return self.config
                
            except Exception as e:
                logger.error(f"Error loading config: {e}")
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
                logger.info(f"Saved config to {os.path.abspath(self.config_path)}")
            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
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
        logger.debug(f"Set config key '{key}' to '{value}'")
    
    def update(self, updates: Dict[str, Any]) -> None:
        """
        Update multiple configuration values.
        
        Args:
            updates: Dictionary of key-value pairs to update
        """
        self.config.update(updates)
        logger.debug(f"Updated config with {len(updates)} values")
    
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
            for key in required_keys:
                if key not in self.config:
                    logger.error(f"Missing required configuration key: {key}")
                    return False
            
            # Validate model repositories structure
            repos = self.get_model_repositories()
            if not isinstance(repos, dict):
                logger.error("model_repositories must be a dictionary")
                return False
            
            logger.info("Configuration validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Configuration validation error: {e}")
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
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager.config


def get_config() -> ConfigManager:
    """
    Get the global configuration manager instance.
    
    Returns:
        ConfigManager instance
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def save_config() -> bool:
    """
    Save the global configuration.
    
    Returns:
        True if saved successfully, False otherwise
    """
    global _config_manager
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