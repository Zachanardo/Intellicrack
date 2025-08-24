"""Configuration Manager for Intellicrack.

Auto configures itself with platform aware directories and tool discovery.
Creates configuration files dynamically without requiring manual setup.

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

import json
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class IntellicrackConfig:
    """Platform-aware configuration manager that auto-configures Intellicrack."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern for global config access."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize configuration manager."""
        if hasattr(self, "_initialized"):
            return

        self._initialized = True
        self.logger = logging.getLogger(__name__ + ".IntellicrackConfig")
        self._config = {}
        self._config_lock = threading.RLock()

        # Set up directories
        self.config_dir = self._get_user_config_dir()
        self.config_file = self.config_dir / "config.json"
        self.cache_dir = self.config_dir / "cache"
        self.logs_dir = self.config_dir / "logs"
        self.output_dir = self.config_dir / "output"

        # Initialize configuration
        self._ensure_directories_exist()
        self._load_or_create_config()

    def _get_user_config_dir(self) -> Path:
        """Get platform-appropriate user config directory."""
        if sys.platform == "win32":
            base = os.environ.get("APPDATA", os.path.expanduser("~"))
            return Path(base) / "Intellicrack"
        if sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support" / "Intellicrack"
        xdg_config = os.environ.get("XDG_CONFIG_HOME", "~/.config")
        return Path(xdg_config).expanduser() / "intellicrack"

    def _ensure_directories_exist(self):
        """Create necessary directories if they don't exist."""
        for directory in [self.config_dir, self.cache_dir, self.logs_dir, self.output_dir]:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                logger.debug(f"Ensured directory exists: {directory}")
            except Exception as e:
                logger.warning(f"Could not create directory {directory}: {e}")

    def _load_or_create_config(self):
        """Load existing config or create default one."""
        try:
            if self.config_file.exists():
                self._load_config()
            else:
                logger.info("First run detected - creating default configuration")
                self._create_default_config()
        except Exception as e:
            logger.error(f"Configuration initialization failed: {e}")
            self._create_emergency_config()

    def _load_config(self):
        """Load configuration from file."""
        try:
            with open(self.config_file, encoding="utf-8") as f:
                with self._config_lock:
                    self._config = json.load(f)
            logger.info(f"Configuration loaded from {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            self._create_default_config()

    def _create_default_config(self):
        """Create intelligent default configuration."""
        logger.info("Creating default configuration")

        default_config = {
            "version": "2.0",
            "created": str(Path().resolve()),
            "platform": sys.platform,
            "directories": {
                "config": str(self.config_dir),
                "output": str(self.output_dir),
                "logs": str(self.logs_dir),
                "cache": str(self.cache_dir),
            },
            "tools": {},
            "preferences": {
                "log_level": "INFO",
                "ui_theme": "dark",
            },
        }

        with self._config_lock:
            self._config = default_config

        self._save_config()
        logger.info("Default configuration created successfully")

    def _create_emergency_config(self):
        """Create minimal emergency configuration."""
        logger.warning("Creating emergency configuration")

        with self._config_lock:
            self._config = {
                "version": "2.0",
                "emergency_mode": True,
                "directories": {
                    "config": str(self.config_dir),
                    "output": str(Path.home()),
                    "logs": str(Path.home()),
                    "cache": str(Path.home()),
                },
                "tools": {},
                "preferences": {
                    "log_level": "WARNING",
                },
            }

    def _save_config(self):
        """Save configuration to file."""
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                with self._config_lock:
                    json.dump(self._config, f, indent=2, sort_keys=True)
            logger.debug(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with dot notation support."""
        with self._config_lock:
            keys = key.split(".")
            value = self._config

            try:
                for k in keys:
                    value = value[k]
                return value
            except (KeyError, TypeError) as e:
                self.logger.error("Error in config_manager: %s", e)
                return default

    def set(self, key: str, value: Any, save: bool = True):
        """Set configuration value with dot notation support."""
        with self._config_lock:
            keys = key.split(".")
            config = self._config

            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]

            config[keys[-1]] = value

        if save:
            self._save_config()

    def get_output_dir(self) -> Path:
        """Get user's preferred output directory."""
        return Path(self.get("directories.output", self.output_dir))

    def get_cache_dir(self) -> Path:
        """Get cache directory."""
        return Path(self.get("directories.cache", self.cache_dir))

    def get_logs_dir(self) -> Path:
        """Get logs directory."""
        return Path(self.get("directories.logs", self.logs_dir))


# Global instance
_global_config = None


def get_config() -> IntellicrackConfig:
    """Get global configuration instance."""
    global _global_config
    if _global_config is None:
        _global_config = IntellicrackConfig()
    return _global_config
