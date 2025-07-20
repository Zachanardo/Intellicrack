"""
Dynamic Configuration Manager for Intellicrack

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import logging
import os
import shutil
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class IntellicrackConfig:
    """
    Platform-aware configuration manager that auto-configures Intellicrack.

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
        """
        Singleton pattern for global config access.

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
        """
        Initialize configuration manager.

        Sets up platform-specific directories, loads or creates configuration,
        and ensures all necessary directories exist. Uses initialization guard
        to prevent multiple initializations.

        Side Effects:
            - Creates configuration directories if they don't exist
            - Loads existing config or creates default config
            - Sets up logging for the configuration manager

        Attributes Set:
            - config_dir: Platform-specific config directory
            - config_file: Path to config.json
            - cache_dir: Directory for cached data
            - logs_dir: Directory for log files
            - output_dir: Directory for output files
        """
        if hasattr(self, '_initialized'):
            return

        self._initialized = True
        self.logger = logging.getLogger(__name__ + ".IntellicrackConfig")
        self._config = {}
        self._config_lock = threading.RLock()

        # Set up directories
        self.config_dir = self._get_user_config_dir()
        self.config_file = self.config_dir / 'config.json'
        self.cache_dir = self.config_dir / 'cache'
        self.logs_dir = self.config_dir / 'logs'
        self.output_dir = self.config_dir / 'output'

        # Initialize configuration
        self._ensure_directories_exist()
        self._load_or_create_config()

    def _get_user_config_dir(self) -> Path:
        """Get platform-appropriate user config directory.

        Follows platform conventions for configuration storage:
        - Windows: %APPDATA%\\Intellicrack
        - macOS: ~/Library/Application Support/Intellicrack
        - Linux: $XDG_CONFIG_HOME/intellicrack or ~/.config/intellicrack

        Returns:
            Path: Platform-specific configuration directory path

        Example:
            Windows: C:\\Users\\Username\\AppData\\Roaming\\Intellicrack
            macOS: /Users/Username/Library/Application Support/Intellicrack
            Linux: /home/username/.config/intellicrack

        """
        if sys.platform == "win32":
            # Windows: Use APPDATA environment variable
            base = os.environ.get('APPDATA', os.path.expanduser('~'))
            return Path(base) / 'Intellicrack'
        elif sys.platform == "darwin":
            # macOS: Use Application Support directory
            return Path.home() / 'Library' / 'Application Support' / 'Intellicrack'
        else:
            # Linux/Unix: Follow XDG Base Directory specification
            xdg_config = os.environ.get('XDG_CONFIG_HOME', '~/.config')
            return Path(xdg_config).expanduser() / 'intellicrack'

    def _ensure_directories_exist(self):
        """
        Create necessary directories if they don't exist.

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
                logger.info(
                    "First run detected - creating default configuration")
                self._create_default_config()
        except Exception as e:
            logger.error(f"Configuration initialization failed: {e}")
            self._create_emergency_config()

    def _load_config(self):
        """Load configuration from file."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                with self._config_lock:
                    self._config = json.load(f)
            logger.info(f"Configuration loaded from {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            self._create_default_config()

    def _create_default_config(self):
        """
        Create intelligent default configuration.

        Generates a comprehensive default configuration with:
        - Platform-specific paths
        - Auto-discovered tools
        - Sensible default preferences
        - Security-conscious defaults

        Side Effects:
            - Sets internal configuration dictionary
            - Saves configuration to disk
            - Runs tool discovery (may take several seconds)

        Configuration sections:
            - directories: Platform-specific paths
            - tools: Auto-discovered tool locations
            - preferences: User preferences and UI settings
            - analysis: Analysis engine settings
            - network: Network and proxy configuration
            - security: Security and sandboxing options
            - patching: Binary patching preferences
            - ui: User interface settings
            - ai: AI model configuration
        """
        logger.info("Creating default configuration with auto-discovery")

        default_config = {
            'version': '2.0',
            'created': str(Path().resolve()),
            'platform': sys.platform,
            'directories': {
                'config': str(self.config_dir),
                'output': str(self.output_dir),
                'logs': str(self.logs_dir),
                'cache': str(self.cache_dir),
                'temp': str(Path.home() / 'tmp' if sys.platform != 'win32' else Path.home() / 'AppData' / 'Local' / 'Temp')
            },
            'tools': self._auto_discover_tools(),
            'preferences': {
                'auto_update_signatures': True,
                'log_level': 'INFO',
                'parallel_analysis': True,
                'max_analysis_threads': os.cpu_count() or 4,
                'auto_backup_results': True,
                'ui_theme': 'dark',
                'check_for_updates': True
            },
            'analysis': {
                'default_timeout': 300,
                'max_memory_usage': '2GB',
                'enable_ml_analysis': True,
                'enable_ai_features': True,
                'save_intermediate_results': True
            },
            'network': {
                'proxy_enabled': False,
                'proxy_host': '',
                'proxy_port': 8080,
                'ssl_verify': True,
                'timeout': 30
            },
            'security': {
                'sandbox_analysis': True,
                'allow_network_access': False,
                'log_sensitive_data': False,
                'encrypt_config': False
            },
            'patching': {
                'backup_original': True,
                'verify_patches': True,
                'max_patch_size': '10MB',
                'patch_format': 'binary'
            },
            'ui': {
                'theme': 'dark',
                'font_size': 10,
                'show_tooltips': True,
                'auto_save_layout': True,
                'hex_view_columns': 16
            },
            'ai': {
                'enabled': True,
                'model_provider': 'auto',
                'temperature': 0.7,
                'max_tokens': 2048,
                'cache_responses': True,
                'background_loading': True
            }
        }

        with self._config_lock:
            self._config = default_config

        self._save_config()
        logger.info("Default configuration created successfully")

    def _auto_discover_tools(self) -> Dict[str, Any]:
        """
        Auto-discover tools and their configurations.

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
            'ghidra': {
                'executables': ['ghidra', 'ghidraRun', 'ghidraRun.bat'],
                'search_paths': self._get_ghidra_search_paths(),
                'version_flag': '--version',
                'required': False  # Optional - app works without it
            },
            'radare2': {
                'executables': ['r2', 'radare2'],
                'search_paths': self._get_radare2_search_paths(),
                'version_flag': '-v',
                'required': False
            },
            'python3': {
                'executables': ['python3', 'python'],
                'search_paths': [],  # Use PATH only
                'version_flag': '--version',
                'required': True
            },
            'frida': {
                'executables': ['frida'],
                'search_paths': [],
                'version_flag': '--version',
                'required': False
            },
            'qemu': {
                'executables': ['qemu-system-x86_64', 'qemu-system-i386'],
                'search_paths': self._get_qemu_search_paths(),
                'version_flag': '--version',
                'required': False
            }
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
                        'available': False,
                        'path': None,
                        'version': None,
                        'auto_discovered': True,
                        'last_check': None
                    }
            except Exception as e:
                logger.error(f"Error discovering {tool_name}: {e}")
                tools[tool_name] = {'available': False, 'error': str(e)}

        return tools

    def _discover_tool(self, tool_name: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Discover a specific tool and return its information.

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
        logger.debug(
            f"Discovering tool: {tool_name} with config keys: {list(config.keys())}")
        # First check PATH environment variable
        for executable in config['executables']:
            tool_path = shutil.which(executable)
            if tool_path:
                return self._validate_tool(tool_path, config.get('version_flag'))

        # Then check platform-specific search paths
        for search_path in config['search_paths']:
            if not os.path.exists(search_path):
                continue

            for executable in config['executables']:
                potential_path = Path(search_path) / executable
                if potential_path.exists():
                    return self._validate_tool(str(potential_path), config.get('version_flag'))

        return None

    def _validate_tool(self, tool_path: str, version_flag: Optional[str] = None) -> Dict[str, Any]:
        """
        Validate tool and get version information.

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
            'available': True,
            'path': tool_path,
            'version': None,
            'auto_discovered': True,
            'last_check': time.time()
        }

        if version_flag:
            try:
                result = subprocess.run(
                    [tool_path, version_flag],
                    capture_output=True,
                    text=True,
                    timeout=10  # Prevent hanging on broken tools
                )
                if result.returncode == 0:
                    # Limit version string length to prevent huge outputs
                    tool_info['version'] = result.stdout.strip()[:100]
            except Exception as e:
                logger.debug(f"Could not get version for {tool_path}: {e}")

        return tool_info

    def _get_ghidra_search_paths(self) -> List[str]:
        """Get platform-specific Ghidra search paths."""
        paths = []

        if sys.platform == "win32":
            paths.extend([
                r'C:\Program Files\Ghidra',
                r'C:\ghidra',
                r'C:\Tools\ghidra',
                os.path.expanduser(r'~\ghidra'),
                os.path.join(os.environ.get('PROGRAMFILES', ''), 'Ghidra'),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), 'Ghidra')
            ])
        else:
            paths.extend([
                '/opt/ghidra',
                '/usr/local/ghidra',
                '/usr/share/ghidra',
                os.path.expanduser('~/ghidra'),
                os.path.expanduser('~/Tools/ghidra'),
                '/Applications/ghidra'  # macOS
            ])

        return [p for p in paths if p]  # Remove empty strings

    def _get_radare2_search_paths(self) -> List[str]:
        """Get platform-specific radare2 search paths."""
        paths = []

        if sys.platform == "win32":
            paths.extend([
                r'C:\Program Files\radare2',
                r'C:\radare2',
                r'C:\Tools\radare2',
                os.path.expanduser(r'~\radare2')
            ])
        else:
            paths.extend([
                '/usr/bin',
                '/usr/local/bin',
                '/opt/radare2',
                os.path.expanduser('~/radare2')
            ])

        return paths

    def _get_qemu_search_paths(self) -> List[str]:
        """Get platform-specific QEMU search paths."""
        paths = []

        if sys.platform == "win32":
            paths.extend([
                r'C:\Program Files\qemu',
                r'C:\qemu',
                os.path.join(os.environ.get('PROGRAMFILES', ''), 'qemu')
            ])
        else:
            paths.extend([
                '/usr/bin',
                '/usr/local/bin',
                '/opt/qemu/bin'
            ])

        return paths

    def _upgrade_config_if_needed(self):
        """Upgrade configuration if version changed."""
        current_version = self._config.get('version', '1.0')
        if current_version != '2.0':
            logger.info(
                f"Upgrading configuration from {current_version} to 2.0")
            self._upgrade_config(current_version)

    def _upgrade_config(self, from_version: str):
        """Upgrade configuration from older version."""
        logger.info(
            f"Upgrading configuration schema from version: {from_version}")
        # Preserve user settings while updating structure
        user_preferences = self._config.get('preferences', {})
        user_tools = self._config.get('tools', {})

        # Create new config with current structure
        self._create_default_config()

        # Restore user preferences over defaults
        with self._config_lock:
            if user_preferences:
                self._config['preferences'].update(user_preferences)

            # Merge user tool configurations
            for tool_name, tool_config in user_tools.items():
                if tool_name in self._config['tools']:
                    # Keep manually configured tools (auto_discovered=False)
                    # but use auto-discovered paths for auto-discovered tools
                    if not tool_config.get('auto_discovered', True):
                        self._config['tools'][tool_name] = tool_config

        self._save_config()
        logger.info("Configuration upgrade completed")

    def _create_emergency_config(self):
        """Create minimal emergency configuration."""
        logger.warning("Creating emergency configuration")

        with self._config_lock:
            self._config = {
                'version': '2.0',
                'emergency_mode': True,
                'directories': {
                    'config': str(self.config_dir),
                    'output': str(Path.home()),
                    'logs': str(Path.home()),
                    'cache': str(Path.home())
                },
                'tools': {},
                'preferences': {
                    'log_level': 'WARNING'
                }
            }

    def _save_config(self):
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                with self._config_lock:
                    json.dump(self._config, f, indent=2, sort_keys=True)
            logger.debug(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")

    # Public API methods

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value with dot notation support.

        Retrieves nested configuration values using dot-separated keys.
        Thread-safe access using read lock.

        Args:
            key: Dot-separated configuration key (e.g., 'tools.ghidra.path')
            default: Default value if key not found

        Returns:
            Configuration value or default if not found

        Example:
            >>> config.get('tools.ghidra.path')
            '/opt/ghidra/ghidraRun'
            >>> config.get('preferences.ui_theme', 'light')
            'dark'

        Complexity:
            Time: O(n) where n is the number of dots in key
            Space: O(1)
        """
        with self._config_lock:
            keys = key.split('.')
            value = self._config

            try:
                for k in keys:
                    value = value[k]
                return value
            except (KeyError, TypeError) as e:
                self.logger.error("Error in config_manager: %s", e)
                return default

    def set(self, key: str, value: Any, save: bool = True):
        """
        Set configuration value with dot notation support.

        Updates nested configuration values using dot-separated keys.
        Creates intermediate dictionaries as needed. Thread-safe.

        Args:
            key: Dot-separated configuration key (e.g., 'tools.ghidra.path')
            value: Value to set
            save: Whether to save config to disk immediately

        Side Effects:
            - Modifies internal configuration dictionary
            - Saves to disk if save=True
            - Creates intermediate dictionaries if needed

        Example:
            >>> config.set('tools.ghidra.path', '/usr/local/ghidra')
            >>> config.set('preferences.ui_theme', 'dark', save=False)

        Complexity:
            Time: O(n) where n is the number of dots in key
            Space: O(n) for creating intermediate dictionaries
        """
        with self._config_lock:
            keys = key.split('.')
            config = self._config

            # Navigate to parent, creating intermediate dicts as needed
            # Example: 'a.b.c' creates {'a': {'b': {}}} if needed
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]

            # Set the final value at the last key
            config[keys[-1]] = value

        if save:
            self._save_config()

    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """
        Get path to a specific tool.

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
        tool_config = self.get(f'tools.{tool_name}')
        if tool_config and tool_config.get('available'):
            return tool_config.get('path')
        return None

    def is_tool_available(self, tool_name: str) -> bool:
        """
        Check if a tool is available.

        Verifies whether a tool has been discovered and is available for use.

        Args:
            tool_name: Name of the tool to check

        Returns:
            True if tool is available, False otherwise

        Example:
            >>> if config.is_tool_available('frida'):
            ...     print("Frida dynamic analysis available")
        """
        tool_config = self.get(f'tools.{tool_name}')
        return tool_config and tool_config.get('available', False)

    def refresh_tool_discovery(self):
        """
        Re-run tool discovery and update configuration.

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
        self.set('tools', tools)

    def get_output_dir(self) -> Path:
        """
        Get user's preferred output directory.

        Returns the configured output directory for analysis results,
        reports, and generated files.

        Returns:
            Path: Output directory path

        Example:
            >>> output_dir = config.get_output_dir()
            >>> report_file = output_dir / 'analysis_report.pdf'
        """
        return Path(self.get('directories.output', self.output_dir))

    def get_cache_dir(self) -> Path:
        """
        Get cache directory.

        Returns the directory for cached analysis results, downloaded
        signatures, and temporary processing files.

        Returns:
            Path: Cache directory path

        Example:
            >>> cache_dir = config.get_cache_dir()
            >>> signature_cache = cache_dir / 'signatures'
        """
        return Path(self.get('directories.cache', self.cache_dir))

    def get_logs_dir(self) -> Path:
        """
        Get logs directory.

        Returns the directory for application logs, debug output,
        and analysis traces.

        Returns:
            Path: Logs directory path

        Example:
            >>> logs_dir = config.get_logs_dir()
            >>> today_log = logs_dir / f'{datetime.now():%Y-%m-%d}.log'
        """
        return Path(self.get('directories.logs', self.logs_dir))

    def export_config(self, file_path: Union[str, Path]) -> bool:
        """
        Export configuration to a file.

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
            with open(file_path, 'w', encoding='utf-8') as f:
                with self._config_lock:
                    json.dump(self._config, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to export config: {e}")
            return False

    def import_config(self, file_path: Union[str, Path]) -> bool:
        """
        Import configuration from a file.

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
            with open(file_path, 'r', encoding='utf-8') as f:
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
    """
    Get global configuration instance.

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
