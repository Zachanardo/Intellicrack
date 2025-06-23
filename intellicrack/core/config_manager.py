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
        """Singleton pattern for global config access."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize configuration manager."""
        if hasattr(self, '_initialized'):
            return

        self._initialized = True
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
        """Get platform-appropriate user config directory."""
        if sys.platform == "win32":
            # Windows: Use APPDATA
            base = os.environ.get('APPDATA', os.path.expanduser('~'))
            return Path(base) / 'Intellicrack'
        elif sys.platform == "darwin":
            # macOS: Use Application Support
            return Path.home() / 'Library' / 'Application Support' / 'Intellicrack'
        else:
            # Linux/Unix: Use XDG config
            xdg_config = os.environ.get('XDG_CONFIG_HOME', '~/.config')
            return Path(xdg_config).expanduser() / 'intellicrack'

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
            with open(self.config_file, 'r', encoding='utf-8') as f:
                with self._config_lock:
                    self._config = json.load(f)
            logger.info(f"Configuration loaded from {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            self._create_default_config()

    def _create_default_config(self):
        """Create intelligent default configuration."""
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
            }
        }

        with self._config_lock:
            self._config = default_config

        self._save_config()
        logger.info("Default configuration created successfully")

    def _auto_discover_tools(self) -> Dict[str, Any]:
        """Auto-discover tools and their configurations."""
        logger.info("Auto-discovering tools...")
        tools = {}

        # Tool discovery patterns
        tool_patterns = {
            'ghidra': {
                'executables': ['ghidra', 'ghidraRun', 'ghidraRun.bat'],
                'search_paths': self._get_ghidra_search_paths(),
                'version_flag': '--version',
                'required': False
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
        """Discover a specific tool and return its information."""
        logger.debug(f"Discovering tool: {tool_name} with config keys: {list(config.keys())}")
        # First check PATH
        for executable in config['executables']:
            tool_path = shutil.which(executable)
            if tool_path:
                return self._validate_tool(tool_path, config.get('version_flag'))

        # Then check specific search paths
        for search_path in config['search_paths']:
            if not os.path.exists(search_path):
                continue

            for executable in config['executables']:
                potential_path = Path(search_path) / executable
                if potential_path.exists():
                    return self._validate_tool(str(potential_path), config.get('version_flag'))

        return None

    def _validate_tool(self, tool_path: str, version_flag: Optional[str] = None) -> Dict[str, Any]:
        """Validate tool and get version information."""
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
                    timeout=10
                )
                if result.returncode == 0:
                    tool_info['version'] = result.stdout.strip()[:100]  # Limit length
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
            logger.info(f"Upgrading configuration from {current_version} to 2.0")
            self._upgrade_config(current_version)

    def _upgrade_config(self, from_version: str):
        """Upgrade configuration from older version."""
        logger.info(f"Upgrading configuration schema from version: {from_version}")
        # Preserve user settings while updating structure
        user_preferences = self._config.get('preferences', {})
        user_tools = self._config.get('tools', {})

        # Create new config with current structure
        self._create_default_config()

        # Restore user preferences
        with self._config_lock:
            if user_preferences:
                self._config['preferences'].update(user_preferences)

            # Merge user tool configurations
            for tool_name, tool_config in user_tools.items():
                if tool_name in self._config['tools']:
                    if not tool_config.get('auto_discovered', True):
                        # Keep manually configured tools
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
        """Get configuration value with dot notation support."""
        with self._config_lock:
            keys = key.split('.')
            value = self._config

            try:
                for k in keys:
                    value = value[k]
                return value
            except (KeyError, TypeError):
                return default

    def set(self, key: str, value: Any, save: bool = True):
        """Set configuration value with dot notation support."""
        with self._config_lock:
            keys = key.split('.')
            config = self._config

            # Navigate to parent
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]

            # Set value
            config[keys[-1]] = value

        if save:
            self._save_config()

    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """Get path to a specific tool."""
        tool_config = self.get(f'tools.{tool_name}')
        if tool_config and tool_config.get('available'):
            return tool_config.get('path')
        return None

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available."""
        tool_config = self.get(f'tools.{tool_name}')
        return tool_config and tool_config.get('available', False)

    def refresh_tool_discovery(self):
        """Re-run tool discovery and update configuration."""
        logger.info("Refreshing tool discovery")
        tools = self._auto_discover_tools()
        self.set('tools', tools)

    def get_output_dir(self) -> Path:
        """Get user's preferred output directory."""
        return Path(self.get('directories.output', self.output_dir))

    def get_cache_dir(self) -> Path:
        """Get cache directory."""
        return Path(self.get('directories.cache', self.cache_dir))

    def get_logs_dir(self) -> Path:
        """Get logs directory."""
        return Path(self.get('directories.logs', self.logs_dir))

    def export_config(self, file_path: Union[str, Path]) -> bool:
        """Export configuration to a file."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                with self._config_lock:
                    json.dump(self._config, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to export config: {e}")
            return False

    def import_config(self, file_path: Union[str, Path]) -> bool:
        """Import configuration from a file."""
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
    """Get global configuration instance."""
    global _global_config
    if _global_config is None:
        _global_config = IntellicrackConfig()
    return _global_config
