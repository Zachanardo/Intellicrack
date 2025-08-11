"""Dynamic Configuration Manager for Intellicrack

Auto-configures itself with platform-aware directories and tool discovery.
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
import re
import shutil
import sys
import threading
from pathlib import Path
from typing import Any

from intellicrack.core.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


class IntellicrackConfig:
    """Platform-aware configuration manager that auto-configures Intellicrack.

    Features:
    - Platform-specific config directories (Windows/Linux/macOS)
    - Auto-discovery of tools (Ghidra, radare2, etc.)
    - Dynamic config creation on first run
    - Thread-safe configuration access
    - Version-aware config upgrades
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern for global config access.

        Ensures only one instance of IntellicrackConfig exists throughout
        the application lifecycle. Uses double-checked locking for thread safety.

        Returns:
            IntellicrackConfig: The single global configuration instance

        Complexity:
            Time: O(1) after first instantiation
            Space: O(1)

        """
        if cls._instance is None:
            with cls._lock:
                # Double-check pattern for thread safety
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize configuration manager.

        Sets up platform-specific directories, loads or creates configuration,
        and ensures all necessary directories exist. Uses initialization guard
        to prevent multiple initializations.

        Side Effects:
            - Creates configuration directories if they don't exist
            - Loads existing config or creates default config
            - Sets up logging for the configuration manager
            - Enables auto-save functionality

        Attributes Set:
            - config_dir: Platform-specific config directory
            - config_file: Path to config.json
            - cache_dir: Directory for cached data
            - logs_dir: Directory for log files
            - output_dir: Directory for output files
            - auto_save: Whether to automatically save on changes
        """
        if hasattr(self, "_initialized"):
            return

        self._initialized = True
        self.logger = logging.getLogger(__name__ + ".IntellicrackConfig")
        self._config = {}
        self._config_lock = threading.RLock()
        self.auto_save = True  # Enable auto-save by default

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
        """Get platform-appropriate user config directory.

        Uses unified configuration directory at C:\\Intellicrack\\config
        for all platforms to ensure consistency.

        Returns:
            Path: Configuration directory path (C:\\Intellicrack\\config)

        Example:
            All platforms: C:\\Intellicrack\\config

        """
        # Use unified configuration directory for all platforms
        return Path("C:/Intellicrack/config")

    def _ensure_directories_exist(self):
        """Create necessary directories if they don't exist.

        Creates all required directories for configuration, cache, logs,
        and output. Handles errors gracefully and continues even if some
        directories cannot be created.

        Directories created:
            - config_dir: Main configuration directory
            - cache_dir: For cached analysis results
            - logs_dir: For application logs
            - output_dir: For generated output files

        Side Effects:
            - Creates directories on filesystem
            - Logs success/failure for each directory
        """
        for directory in [self.config_dir, self.cache_dir, self.logs_dir, self.output_dir]:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                logger.debug(f"Ensured directory exists: {directory}")
            except Exception as e:
                # Continue even if directory creation fails
                logger.warning(f"Could not create directory {directory}: {e}")

    def _load_or_create_config(self):
        """Load existing config or create default one."""
        try:
            if self.config_file.exists():
                self._load_config()
                self._upgrade_config_if_needed()
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
        """Create or load unified configuration.

        Attempts to load the unified config.json from C:\\Intellicrack\\config.
        If not found, creates a comprehensive default configuration.

        Side Effects:
            - Sets internal configuration dictionary
            - Saves configuration to disk if created
            - Runs tool discovery if creating new config

        """
        # Try to load existing unified config first
        unified_config_file = Path("C:/Intellicrack/config/config.json")
        if unified_config_file.exists():
            try:
                with open(unified_config_file, encoding="utf-8") as f:
                    with self._config_lock:
                        self._config = json.load(f)
                logger.info(f"Loaded unified configuration from {unified_config_file}")
                return
            except Exception as e:
                logger.error(f"Failed to load unified config: {e}")
        
        # Fall back to creating default config with auto-discovery
        logger.info("Creating default configuration with auto-discovery")

        default_config = {
            "version": "3.0",
            "created": str(Path().resolve()),
            "platform": sys.platform,
            "application": {
                "name": "Intellicrack",
                "version": "3.0.0",
                "environment": "production",
                "debug": False
            },
            "api_endpoints": {
                "openai": "https://api.openai.com/v1",
                "anthropic": "https://api.anthropic.com/v1",
                "google": "https://generativelanguage.googleapis.com/v1",
                "openrouter": "https://openrouter.ai/api/v1",
                "huggingface": "https://api-inference.huggingface.co",
                "groq": "https://api.groq.com/openai/v1",
                "cohere": "https://api.cohere.ai/v1",
                "together": "https://api.together.xyz/v1",
                "ollama": "http://localhost:11434/api",
                "local_llm": "http://localhost:8080/v1"
            },
            "directories": {
                "config": str(self.config_dir),
                "output": str(self.output_dir),
                "logs": str(self.logs_dir),
                "cache": str(self.cache_dir),
                "temp": str(self.cache_dir / "temp"),
                "scripts": "C:\\Intellicrack\\scripts",
                "plugins": "C:\\Intellicrack\\plugins",
                "signatures": "C:\\Intellicrack\\signatures",
                "reports": "C:\\Intellicrack\\reports",
                "backups": "C:\\Intellicrack\\backups"
            },
            "tools": self._auto_discover_tools(),
            "ui_preferences": {
                "theme": "dark",
                "font_size": 10,
                "show_tooltips": True,
                "auto_save_layout": True,
                "hex_view_columns": 16,
                "remember_window_position": True,
                "default_tab": "protection_analysis",
                "show_status_bar": True,
                "show_toolbar": True,
                "language": "en",
                "animations_enabled": True,
                "auto_complete": True,
                "syntax_highlighting": True
            },
            "analysis_settings": {
                "default_timeout": 300,
                "max_memory_usage": "2GB",
                "enable_ml_analysis": True,
                "enable_ai_features": True,
                "save_intermediate_results": True,
                "parallel_analysis": True,
                "max_analysis_threads": os.cpu_count() or 4,
                "auto_backup_results": True,
                "cache_analysis_results": True,
                "verbose_logging": False,
                "deep_analysis_mode": False,
                "heuristic_detection": True,
                "signature_matching": True,
                "behavioral_analysis": True,
                "static_analysis": True,
                "dynamic_analysis": True
            },
            "network": {
                "proxy_enabled": False,
                "proxy_host": "",
                "proxy_port": 8080,
                "proxy_username": "",
                "proxy_password": "",
                "ssl_verify": True,
                "timeout": 30,
                "max_retries": 3,
                "retry_delay": 1,
                "user_agent": "Intellicrack/3.0",
                "follow_redirects": True,
                "max_redirects": 5
            },
            "logging": {
                "level": "INFO",
                "file_logging": True,
                "console_logging": True,
                "log_rotation": True,
                "max_log_size": "50MB",
                "max_log_files": 10,
                "log_format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "log_directory": str(self.logs_dir),
                "separate_error_log": True,
                "performance_logging": False,
                "debug_mode": False
            },
            "security": {
                "sandbox_analysis": True,
                "allow_network_access": False,
                "log_sensitive_data": False,
                "encrypt_config": False,
                "secure_communication": True,
                "verify_signatures": True,
                "sandbox_timeout": 60,
                "max_sandbox_memory": "1GB",
                "isolate_processes": True,
                "monitor_system_calls": True
            },
            "patching": {
                "backup_original": True,
                "verify_patches": True,
                "max_patch_size": "10MB",
                "patch_format": "binary",
                "create_restore_point": True,
                "validate_checksums": True,
                "preserve_timestamps": False,
                "compression_enabled": True,
                "diff_algorithm": "myers"
            },
            "ai_models": {
                "default_provider": "auto",
                "temperature": 0.7,
                "max_tokens": 2048,
                "cache_responses": True,
                "background_loading": True,
                "model_preferences": {
                    "script_generation": "gpt-4",
                    "code_analysis": "claude-3-opus",
                    "vulnerability_detection": "gpt-4-turbo",
                    "patch_generation": "claude-3-sonnet"
                },
                "fallback_models": [
                    "gpt-3.5-turbo",
                    "claude-2",
                    "llama-2-70b"
                ],
                "local_model_settings": {
                    "use_gpu": True,
                    "quantization": "int8",
                    "batch_size": 4,
                    "context_window": 4096
                }
            },
            "service_urls": {
                "update_check": "https://api.intellicrack.com/v1/updates",
                "signature_database": "https://signatures.intellicrack.com/v1",
                "plugin_repository": "https://plugins.intellicrack.com/v1",
                "documentation": "https://docs.intellicrack.com",
                "telemetry": "https://telemetry.intellicrack.com/v1",
                "license_server": "https://license.intellicrack.com/v1"
            },
            "performance": {
                "lazy_loading": True,
                "cache_size": "500MB",
                "memory_limit": "4GB",
                "cpu_cores": 0,
                "gpu_acceleration": True,
                "optimize_for": "balanced",
                "preload_models": False,
                "async_operations": True,
                "batch_processing": True,
                "compression_level": 6
            },
            "updates": {
                "auto_check": True,
                "auto_download": False,
                "auto_install": False,
                "check_interval": 86400,
                "channel": "stable",
                "signature_verification": True,
                "backup_before_update": True
            },
            "plugins": {
                "enabled": True,
                "auto_load": True,
                "safe_mode": False,
                "plugin_directory": "C:\\Intellicrack\\plugins",
                "trusted_sources": [],
                "sandbox_plugins": True,
                "max_plugin_memory": "500MB"
            },
            "export": {
                "default_format": "json",
                "include_metadata": True,
                "compress_output": False,
                "encryption_enabled": False,
                "timestamp_format": "ISO8601",
                "include_screenshots": True,
                "include_logs": False,
                "sanitize_paths": True
            },
            "shortcuts": {
                "new_analysis": "Ctrl+N",
                "open_file": "Ctrl+O",
                "save_results": "Ctrl+S",
                "export_report": "Ctrl+E",
                "quit_application": "Ctrl+Q",
                "toggle_theme": "Ctrl+T",
                "refresh_tools": "F5",
                "show_settings": "Ctrl+,",
                "toggle_fullscreen": "F11"
            }
        }

        with self._config_lock:
            self._config = default_config

        self._save_config()
        logger.info("Default configuration created successfully")

    def _auto_discover_tools(self) -> dict[str, Any]:
        """Auto-discover tools and their configurations.

        Searches for common reverse engineering and analysis tools:
        - Ghidra: Reverse engineering framework
        - Radare2: Command-line RE tool
        - Python3: Script interpreter
        - Frida: Dynamic instrumentation
        - QEMU: System emulator

        Returns:
            Dict mapping tool names to their configuration:
            {
                'tool_name': {
                    'available': bool,
                    'path': str or None,
                    'version': str or None,
                    'auto_discovered': bool,
                    'last_check': float (timestamp)
                }
            }

        Side Effects:
            - Executes tool processes to check versions
            - May take several seconds to complete

        Complexity:
            Time: O(n*m) where n is number of tools, m is search paths
            Space: O(n)

        """
        logger.info("Auto-discovering tools...")
        tools = {}

        # Tool discovery patterns - defines how to find each tool
        tool_patterns = {
            "ghidra": {
                "executables": ["ghidra", "ghidraRun", "ghidraRun.bat"],
                "search_paths": self._get_ghidra_search_paths(),
                "version_flag": "--version",
                "required": False,  # Optional - app works without it
            },
            "radare2": {
                "executables": ["r2", "radare2"],
                "search_paths": self._get_radare2_search_paths(),
                "version_flag": "-v",
                "required": False,
            },
            "python3": {
                "executables": ["python3", "python"],
                "search_paths": [],  # Use PATH only
                "version_flag": "--version",
                "required": True,
            },
            "frida": {
                "executables": ["frida"],
                "search_paths": [],
                "version_flag": "--version",
                "required": False,
            },
            "qemu": {
                "executables": ["qemu-system-x86_64", "qemu-system-i386"],
                "search_paths": self._get_qemu_search_paths(),
                "version_flag": "--version",
                "required": False,
            },
        }

        for tool_name, config in tool_patterns.items():
            try:
                tool_info = self._discover_tool(tool_name, config)
                if tool_info:
                    tools[tool_name] = tool_info
                    logger.info(f"Discovered {tool_name}: {tool_info['path']}")
                else:
                    logger.warning(f"Tool not found: {tool_name}")
                    tools[tool_name] = {
                        "available": False,
                        "path": None,
                        "version": None,
                        "auto_discovered": True,
                        "last_check": None,
                    }
            except Exception as e:
                logger.error(f"Error discovering {tool_name}: {e}")
                tools[tool_name] = {"available": False, "error": str(e)}

        return tools

    def _discover_tool(self, tool_name: str, config: dict[str, Any]) -> dict[str, Any] | None:
        """Discover a specific tool and return its information.

        Searches for tools in the following order:
        1. System PATH (using shutil.which)
        2. Platform-specific search paths

        Args:
            tool_name: Name of the tool to discover
            config: Tool configuration containing:
                    - executables: List of possible executable names
                    - search_paths: List of directories to search
                    - version_flag: Command flag to get version info

        Returns:
            Dict with tool information if found, None otherwise
            Tool info includes: available, path, version, auto_discovered, last_check

        Example:
            >>> config = {'executables': ['ghidra', 'ghidraRun'],
            ...           'search_paths': ['/opt/ghidra'],
            ...           'version_flag': '--version'}
            >>> tool_info = self._discover_tool('ghidra', config)

        """
        logger.debug(f"Discovering tool: {tool_name} with config keys: {list(config.keys())}")
        # First check PATH environment variable
        for executable in config["executables"]:
            tool_path = shutil.which(executable)
            if tool_path:
                return self._validate_tool(tool_path, config.get("version_flag"))

        # Then check platform-specific search paths
        for search_path in config["search_paths"]:
            if not os.path.exists(search_path):
                continue

            for executable in config["executables"]:
                potential_path = Path(search_path) / executable
                if potential_path.exists():
                    return self._validate_tool(str(potential_path), config.get("version_flag"))

        return None

    def _validate_tool(self, tool_path: str, version_flag: str | None = None) -> dict[str, Any]:
        """Validate tool and get version information.

        Executes the tool with version flag to verify it works and extract
        version information. Uses timeout to prevent hanging on broken tools.

        Args:
            tool_path: Full path to the tool executable
            version_flag: Command line flag to get version (e.g., '--version')

        Returns:
            Dict containing:
                - available: True (always, since tool exists)
                - path: Full path to the tool
                - version: Version string (if obtainable)
                - auto_discovered: True
                - last_check: Unix timestamp of validation

        Side Effects:
            - Executes external tool process
            - May take up to 10 seconds (timeout)

        Complexity:
            Time: O(1) + external process time
            Space: O(1)

        """
        import subprocess
        import time

        tool_info = {
            "available": True,
            "path": tool_path,
            "version": None,
            "auto_discovered": True,
            "last_check": time.time(),
        }

        if version_flag:
            try:
                result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                    [tool_path, version_flag],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,  # Prevent hanging on broken tools
                )
                if result.returncode == 0:
                    # Limit version string length to prevent huge outputs
                    tool_info["version"] = result.stdout.strip()[:100]
            except Exception as e:
                logger.debug(f"Could not get version for {tool_path}: {e}")

        return tool_info

    def _get_ghidra_search_paths(self) -> list[str]:
        """Get platform-specific Ghidra search paths."""
        paths = []

        if sys.platform == "win32":
            paths.extend(
                [
                    r"C:\Program Files\Ghidra",
                    r"C:\ghidra",
                    r"C:\Tools\ghidra",
                    os.path.expanduser(r"~\ghidra"),
                    os.path.join(os.environ.get("PROGRAMFILES", ""), "Ghidra"),
                    os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Ghidra"),
                ]
            )
        else:
            paths.extend(
                [
                    "/opt/ghidra",
                    "/usr/local/ghidra",
                    "/usr/share/ghidra",
                    os.path.expanduser("~/ghidra"),
                    os.path.expanduser("~/Tools/ghidra"),
                    "/Applications/ghidra",  # macOS
                ]
            )

        return [p for p in paths if p]  # Remove empty strings

    def _get_radare2_search_paths(self) -> list[str]:
        """Get platform-specific radare2 search paths."""
        paths = []

        if sys.platform == "win32":
            paths.extend(
                [
                    r"C:\Program Files\radare2",
                    r"C:\radare2",
                    r"C:\Tools\radare2",
                    os.path.expanduser(r"~\radare2"),
                ]
            )
        else:
            paths.extend(
                [
                    "/usr/bin",
                    "/usr/local/bin",
                    "/opt/radare2",
                    os.path.expanduser("~/radare2"),
                ]
            )

        return paths

    def _get_qemu_search_paths(self) -> list[str]:
        """Get platform-specific QEMU search paths."""
        paths = []

        if sys.platform == "win32":
            paths.extend(
                [
                    r"C:\Program Files\qemu",
                    r"C:\qemu",
                    os.path.join(os.environ.get("PROGRAMFILES", ""), "qemu"),
                ]
            )
        else:
            paths.extend(
                [
                    "/usr/bin",
                    "/usr/local/bin",
                    "/opt/qemu/bin",
                ]
            )

        return paths

    def _upgrade_config_if_needed(self):
        """Upgrade configuration if version changed."""
        current_version = self._config.get("version", "1.0")
        target_version = "3.0"
        if current_version != target_version:
            logger.info(f"Upgrading configuration from {current_version} to {target_version}")
            self._upgrade_config(current_version)

    def _upgrade_config(self, from_version: str):
        """Upgrade configuration from older version."""
        logger.info(f"Upgrading configuration schema from version: {from_version}")
        # Preserve user settings while updating structure
        user_preferences = self._config.get("preferences", self._config.get("ui_preferences", {}))
        user_tools = self._config.get("tools", {})
        user_api_endpoints = self._config.get("api_endpoints", {})

        # Create new config with current structure
        self._create_default_config()

        # Restore user preferences over defaults
        with self._config_lock:
            if user_preferences:
                if "ui_preferences" in self._config:
                    self._config["ui_preferences"].update(user_preferences)
                elif "preferences" in self._config:
                    self._config["preferences"].update(user_preferences)

            # Merge user tool configurations
            for tool_name, tool_config in user_tools.items():
                if tool_name in self._config["tools"]:
                    # Keep manually configured tools (auto_discovered=False)
                    # but use auto-discovered paths for auto-discovered tools
                    if not tool_config.get("auto_discovered", True):
                        self._config["tools"][tool_name] = tool_config
            
            # Merge user API endpoints
            if user_api_endpoints and "api_endpoints" in self._config:
                self._config["api_endpoints"].update(user_api_endpoints)

        self._save_config()
        logger.info("Configuration upgrade completed")

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

    # Public API methods

    def _expand_environment_variables(self, value: Any) -> Any:
        """Expand environment variables in configuration values.
        
        Supports ${VAR_NAME} and ${VAR_NAME:default_value} syntax.
        
        Args:
            value: Configuration value to expand
            
        Returns:
            Value with environment variables expanded
        """
        if not isinstance(value, str):
            return value
        
        # Pattern to match ${VAR_NAME} or ${VAR_NAME:default}
        env_pattern = r'\$\{([^}:]+)(?::([^}]*))?\}'
        
        def replace_env_var(match):
            var_name = match.group(1)
            default_value = match.group(2) if match.group(2) is not None else ""
            
            # Get environment variable value
            env_value = os.environ.get(var_name)
            
            if env_value is not None:
                return env_value
            elif default_value:
                return default_value
            else:
                # If no default and env var not set, raise error
                raise ConfigurationError(
                    f"Environment variable '{var_name}' is not set and no default provided in config key '{key}'",
                    config_key=key
                )
        
        return re.sub(env_pattern, replace_env_var, value)

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with dot notation support.

        Retrieves nested configuration values using dot-separated keys.
        Thread-safe access using read lock. Expands environment variables.

        Args:
            key: Dot-separated configuration key (e.g., 'tools.ghidra.path')
            default: Default value if key not found

        Returns:
            Configuration value with environment variables expanded, or default if not found

        Example:
            >>> config.get('tools.ghidra.path')
            '/opt/ghidra/ghidraRun'
            >>> config.get('service_urls.c2_server')  # ${C2_SERVER_URL:http://localhost:8888}
            'https://c2.mycompany.com'  # From environment variable

        Complexity:
            Time: O(n) where n is the number of dots in key
            Space: O(1)

        """
        with self._config_lock:
            keys = key.split(".")
            value = self._config

            try:
                for k in keys:
                    value = value[k]
                
                # Expand environment variables in the retrieved value
                return self._expand_environment_variables(value)
                
            except (KeyError, TypeError) as e:
                self.logger.error("Error in config_manager: %s", e)
                return default

    def set(self, key: str, value: Any, save: bool | None = None):
        """Set configuration value with dot notation support.

        Updates nested configuration values using dot-separated keys.
        Creates intermediate dictionaries as needed. Thread-safe.

        Args:
            key: Dot-separated configuration key (e.g., 'tools.ghidra.path')
            value: Value to set
            save: Whether to save config to disk immediately (uses auto_save if None)

        Side Effects:
            - Modifies internal configuration dictionary
            - Saves to disk if save=True or auto_save is enabled
            - Creates intermediate dictionaries if needed

        Example:
            >>> config.set('tools.ghidra.path', '/usr/local/ghidra')
            >>> config.set('preferences.ui_theme', 'dark', save=False)

        Complexity:
            Time: O(n) where n is the number of dots in key
            Space: O(n) for creating intermediate dictionaries

        """
        with self._config_lock:
            keys = key.split(".")
            config = self._config

            # Navigate to parent, creating intermediate dicts as needed
            # Example: 'a.b.c' creates {'a': {'b': {}}} if needed
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]

            # Set the final value at the last key
            config[keys[-1]] = value

        # Use auto_save setting if save not specified
        if save is None:
            save = self.auto_save
        
        if save:
            self._save_config()

    def get_tool_path(self, tool_name: str) -> str | None:
        """Get path to a specific tool.

        Retrieves the filesystem path for an available tool.

        Args:
            tool_name: Name of the tool (e.g., 'ghidra', 'radare2')

        Returns:
            Full path to tool executable if available, None otherwise

        Example:
            >>> path = config.get_tool_path('ghidra')
            >>> if path:
            ...     subprocess.run([path, '--analyze', 'binary.exe'])

        """
        tool_config = self.get(f"tools.{tool_name}")
        if tool_config and tool_config.get("available"):
            return tool_config.get("path")
        return None
    
    def get_api_endpoint(self, service: str) -> str | None:
        """Get API endpoint for a service.
        
        Retrieves the configured API endpoint URL for a service.
        
        Args:
            service: Name of the service (e.g., 'openai', 'anthropic')
            
        Returns:
            API endpoint URL if configured, None otherwise
            
        Example:
            >>> endpoint = config.get_api_endpoint('openai')
            >>> print(endpoint)  # 'https://api.openai.com/v1'
        
        """
        return self.get(f"api_endpoints.{service}")
    
    def set_auto_save(self, enabled: bool):
        """Enable or disable auto-save functionality.
        
        When enabled, configuration changes are automatically saved to disk.
        
        Args:
            enabled: True to enable auto-save, False to disable
            
        Example:
            >>> config.set_auto_save(False)  # Disable auto-save
            >>> config.set('some.key', 'value')  # Won't save automatically
            >>> config.set_auto_save(True)  # Re-enable auto-save
        
        """
        self.auto_save = enabled
        logger.info(f"Auto-save {'enabled' if enabled else 'disabled'}")

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available.

        Verifies whether a tool has been discovered and is available for use.

        Args:
            tool_name: Name of the tool to check

        Returns:
            True if tool is available, False otherwise

        Example:
            >>> if config.is_tool_available('frida'):
            ...     print("Frida dynamic analysis available")

        """
        tool_config = self.get(f"tools.{tool_name}")
        return tool_config and tool_config.get("available", False)

    def refresh_tool_discovery(self):
        """Re-run tool discovery and update configuration.

        Performs a fresh scan for all tools, updating paths and versions.
        Useful after installing new tools or changing system configuration.

        Side Effects:
            - Executes tool discovery for all configured tools
            - Updates tool configuration in memory and on disk
            - May take several seconds to complete

        Example:
            >>> config.refresh_tool_discovery()
            >>> print(f"Ghidra now at: {config.get_tool_path('ghidra')}")

        """
        logger.info("Refreshing tool discovery")
        tools = self._auto_discover_tools()
        self.set("tools", tools)

    def get_output_dir(self) -> Path:
        """Get user's preferred output directory.

        Returns the configured output directory for analysis results,
        reports, and generated files.

        Returns:
            Path: Output directory path

        Example:
            >>> output_dir = config.get_output_dir()
            >>> report_file = output_dir / 'analysis_report.pdf'

        """
        return Path(self.get("directories.output", self.output_dir))

    def get_cache_dir(self) -> Path:
        """Get cache directory.

        Returns the directory for cached analysis results, downloaded
        signatures, and temporary processing files.

        Returns:
            Path: Cache directory path

        Example:
            >>> cache_dir = config.get_cache_dir()
            >>> signature_cache = cache_dir / 'signatures'

        """
        return Path(self.get("directories.cache", self.cache_dir))

    def get_logs_dir(self) -> Path:
        """Get logs directory.

        Returns the directory for application logs, debug output,
        and analysis traces.

        Returns:
            Path: Logs directory path

        Example:
            >>> logs_dir = config.get_logs_dir()
            >>> today_log = logs_dir / f'{datetime.now():%Y-%m-%d}.log'

        """
        return Path(self.get("directories.logs", self.logs_dir))

    def export_config(self, file_path: str | Path) -> bool:
        """Export configuration to a file.

        Saves the current configuration to a JSON file for backup,
        sharing, or migration purposes.

        Args:
            file_path: Path where to save the configuration

        Returns:
            True if export succeeded, False otherwise

        Side Effects:
            - Creates/overwrites file at specified path
            - Logs errors if export fails

        Example:
            >>> success = config.export_config('my_config_backup.json')
            >>> if success:
            ...     print("Configuration exported successfully")

        """
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                with self._config_lock:
                    json.dump(self._config, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to export config: {e}")
            return False

    def import_config(self, file_path: str | Path) -> bool:
        """Import configuration from a file.

        Loads configuration from a JSON file, merging with existing
        configuration. Existing values are overwritten by imported values.

        Args:
            file_path: Path to configuration file to import

        Returns:
            True if import succeeded, False otherwise

        Side Effects:
            - Updates internal configuration
            - Saves merged configuration to disk
            - Logs errors if import fails

        Example:
            >>> success = config.import_config('shared_config.json')
            >>> if success:
            ...     config.refresh_tool_discovery()  # Update tool paths

        Security Note:
            Only import configurations from trusted sources as they
            can modify tool paths and execution settings.

        """
        try:
            with open(file_path, encoding="utf-8") as f:
                imported_config = json.load(f)

            with self._config_lock:
                self._config.update(imported_config)

            self._save_config()
            return True
        except Exception as e:
            logger.error(f"Failed to import config: {e}")
            return False


# Global instance
_global_config = None


def get_config() -> IntellicrackConfig:
    """Get global configuration instance.

    Returns the singleton IntellicrackConfig instance, creating it
    on first access. Thread-safe through singleton pattern in the class.

    Returns:
        IntellicrackConfig: Global configuration manager instance

    Example:
        >>> config = get_config()
        >>> output_dir = config.get_output_dir()

    Side Effects:
        - Creates configuration instance on first call
        - Initializes configuration files and directories

    Complexity:
        Time: O(1) after first call
        Space: O(1)

    """
    global _global_config
    if _global_config is None:
        _global_config = IntellicrackConfig()
    return _global_config
