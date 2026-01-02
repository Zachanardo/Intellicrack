"""Dynamic Configuration Manager for Intellicrack.

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
import threading
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


load_dotenv()

logger = logging.getLogger(__name__)


class IntellicrackConfig:
    """Central configuration manager for all Intellicrack components.

    This is the single source of truth for all configuration in Intellicrack.
    All scattered configuration systems (QSettings, LLM configs, CLI configs)
    have been consolidated into this central system.

    Features:
    - Single config.json file for all settings
    - Platform-specific config directories (Windows/Linux/macOS)
    - Auto-discovery of tools (Ghidra, radare2, etc.)
    - Dynamic config creation on first run
    - Thread-safe configuration access
    - Version-aware config upgrades
    - Automatic migration from legacy configuration systems
    - Comprehensive schema with all application settings

    Migration Support:
    - QSettings (Qt registry) → ui_preferences, qemu_testing sections
    - LLM configuration files → llm_configuration section
    - CLI configuration → cli_configuration section
    - Legacy config files → appropriate central sections
    """

    _instance: "IntellicrackConfig | None" = None
    _lock = threading.Lock()

    def __new__(cls) -> "IntellicrackConfig":
        """Singleton pattern for global config access.

        Returns:
            The singleton IntellicrackConfig instance.

        """
        if cls._instance is not None:
            return cls._instance

        with cls._lock:
            if cls._instance is None:
                logger.debug("IntellicrackConfig: Creating new instance.")
                cls._instance = super().__new__(cls)

        return cls._instance

    def __init__(self) -> None:
        """Initialize configuration manager.

        Sets up configuration directories, loads layered configuration (defaults, user config, runtime state),
        and prepares the configuration manager for use.

        """
        if hasattr(self, "_initialized"):
            logger.debug("IntellicrackConfig: Already initialized, skipping re-initialization.")
            return

        self._initialized = True
        self.logger = logging.getLogger(f"{__name__}.IntellicrackConfig")
        self.logger.info("IntellicrackConfig: Initializing configuration manager.")
        self._config: dict[str, object] = {}
        self._config_lock = threading.RLock()
        self._runtime_state: dict[str, object] = {}
        self._runtime_state_lock = threading.RLock()
        self.auto_save = True

        self.config_dir = self._get_user_config_dir()
        self.config_file = self.config_dir / "config.json"
        self.defaults_file = self.config_dir / "config.defaults.json"
        self.user_config_file = Path(os.environ.get("INTELLICRACK_CONFIG_PATH", str(self.config_dir / "intellicrack_config.json")))
        self.state_file = self.config_dir / "runtime.state.json"
        self.cache_dir = self.config_dir / "cache"
        self.logs_dir = self.config_dir / "logs"
        self.output_dir = self.config_dir / "output"

        self.logger.debug("IntellicrackConfig: Config directory: %s", self.config_dir)
        self.logger.debug("IntellicrackConfig: Config file: %s", self.config_file)
        self.logger.debug("IntellicrackConfig: Defaults file: %s", self.defaults_file)
        self.logger.debug("IntellicrackConfig: User config file: %s", self.user_config_file)
        self.logger.debug("IntellicrackConfig: State file: %s", self.state_file)
        self.logger.debug("IntellicrackConfig: Cache directory: %s", self.cache_dir)
        self.logger.debug("IntellicrackConfig: Logs directory: %s", self.logs_dir)
        self.logger.debug("IntellicrackConfig: Output directory: %s", self.output_dir)

        self._ensure_directories_exist()
        self._load_layered_config()
        self.logger.info("IntellicrackConfig: Configuration manager initialized successfully.")

    def _get_intellicrack_root(self) -> Path:
        """Get the Intellicrack installation root directory.

        Returns:
            Path object pointing to the Intellicrack root directory

        """
        if intellicrack_root_env := os.environ.get("INTELLICRACK_ROOT"):
            self.logger.debug("IntellicrackConfig: Found INTELLICRACK_ROOT environment variable: %s", intellicrack_root_env)
            return Path(intellicrack_root_env)

        try:
            root = Path(__file__).parent.parent.parent
            self.logger.debug("IntellicrackConfig: Determined Intellicrack root from module location: %s", root)
            return root
        except (AttributeError, OSError):
            self.logger.exception("Failed to determine Intellicrack root")
            return Path.cwd()

    def _get_user_config_dir(self) -> Path:
        """Get platform-appropriate user config directory.

        Returns:
            Path object for the user configuration directory

        """
        config_dir = self._get_intellicrack_root() / "config"
        self.logger.debug("IntellicrackConfig: Determined user config directory: %s", config_dir)
        return config_dir

    def _ensure_directories_exist(self) -> None:
        """Create necessary directories if they don't exist.

        Creates config, cache, logs, and output directories with proper error handling.
        Logs successful creations and exceptions if directories cannot be created.

        """
        self.logger.debug("IntellicrackConfig: Ensuring all configuration directories exist.")
        for directory in [self.config_dir, self.cache_dir, self.logs_dir, self.output_dir]:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                self.logger.debug("IntellicrackConfig: Directory verified/created: %s", directory)
            except Exception:
                self.logger.exception("IntellicrackConfig: Could not create directory %s", directory)

    def _load_layered_config(self) -> None:
        """Load configuration using layered architecture.

        Loads configuration in order: defaults, user overrides, runtime state.
        Performs version-aware upgrades and handles legacy configurations.
        Creates emergency configuration if critical errors occur.

        """
        self.logger.info("IntellicrackConfig: Loading layered configuration.")
        try:
            if self.defaults_file.exists():
                self.logger.debug("IntellicrackConfig: Defaults file found at %s. Loading defaults.", self.defaults_file)
                self._load_defaults_from_file(self.defaults_file)
            elif self.config_file.exists():
                self.logger.warning(
                    "IntellicrackConfig: Legacy config.json found at %s. Loading as defaults and creating new defaults file.",
                    self.config_file,
                )
                self._load_defaults_from_file(self.config_file)
                self._create_defaults_from_legacy()
            else:
                self.logger.info("IntellicrackConfig: No default config file found. Creating a new one.")
                self._create_default_config()

            if self.user_config_file.exists():
                self.logger.debug("IntellicrackConfig: User config file found at %s. Merging user configuration.", self.user_config_file)
                self._merge_user_config()
            else:
                self.logger.debug("IntellicrackConfig: No user config file found to merge.")

            if self.state_file.exists():
                self.logger.debug("IntellicrackConfig: Runtime state file found at %s. Merging runtime state.", self.state_file)
                self._merge_runtime_state()
            else:
                self.logger.debug("IntellicrackConfig: No runtime state file found to merge.")

            self._upgrade_config_if_needed()
            self.logger.info("IntellicrackConfig: Layered configuration loaded successfully.")
        except Exception:
            self.logger.exception(
                "IntellicrackConfig: Critical error loading layered configuration. Attempting to create emergency config."
            )
            self._create_emergency_config()

    def _load_or_create_config(self) -> None:
        """Legacy method maintained for compatibility.

        Delegates to _load_layered_config() for actual loading. Kept for backward compatibility
        with existing code that may call this method.

        """
        self.logger.debug("IntellicrackConfig: _load_or_create_config() called (legacy method). Delegating to _load_layered_config().")
        self._load_layered_config()

    def _load_config(self) -> None:
        """Load configuration from file.

        Reads JSON configuration from the config file with thread-safe locking.
        Creates default configuration if file load fails due to parse errors or missing file.

        """
        self.logger.debug("IntellicrackConfig: Attempting to load configuration from %s", self.config_file)
        try:
            with open(self.config_file, encoding="utf-8") as f, self._config_lock:
                self._config = json.load(f)
            self.logger.info("IntellicrackConfig: Configuration loaded successfully from %s", self.config_file)
        except Exception:
            self.logger.exception("IntellicrackConfig: Failed to load config from %s. Creating default config.", self.config_file)
            self._create_default_config()

    def _load_defaults_from_file(self, file_path: Path) -> None:
        """Load default configuration from specified file.

        Args:
            file_path: Path to the configuration file to load

        Raises:
            Exception: If the file cannot be read or JSON parsing fails

        """
        self.logger.debug("IntellicrackConfig: Loading defaults from file: %s", file_path)
        try:
            with open(file_path, encoding="utf-8") as f, self._config_lock:
                self._config = json.load(f)
            self.logger.info("IntellicrackConfig: Default configuration loaded from %s", file_path)
        except Exception:
            self.logger.exception("IntellicrackConfig: Failed to load defaults from %s", file_path)
            raise

    def _merge_user_config(self) -> None:
        """Merge user-specific configuration overrides.

        Deep merges user configuration file with the loaded defaults. User configuration
        values take precedence over defaults. Logs errors if merge fails but continues operation.

        """
        self.logger.debug("IntellicrackConfig: Merging user configuration from %s", self.user_config_file)
        try:
            with open(self.user_config_file, encoding="utf-8") as f:
                user_config = json.load(f)
            with self._config_lock:
                self._deep_merge(self._config, user_config)
            self.logger.info("IntellicrackConfig: User configuration merged from %s", self.user_config_file)
        except Exception:
            self.logger.exception("IntellicrackConfig: Failed to merge user config from %s", self.user_config_file)

    def _merge_runtime_state(self) -> None:
        """Merge runtime state into configuration.

        Deep merges runtime state file with loaded configuration if it exists.
        Runtime state values take precedence during merge. Logs errors if merge fails
        but continues operation.

        """
        self.logger.debug("IntellicrackConfig: Merging runtime state from %s", self.state_file)
        try:
            with open(self.state_file, encoding="utf-8") as f:
                state = json.load(f)
            with self._config_lock:
                self._deep_merge(self._config, state)
            self.logger.debug("IntellicrackConfig: Runtime state merged from %s", self.state_file)
        except Exception:
            self.logger.exception("IntellicrackConfig: Failed to merge runtime state from %s", self.state_file)

    def _deep_merge(self, base: dict[str, object], override: dict[str, object]) -> None:
        """Deep merge override dict into base dict.

        Recursively merges nested dictionaries, with override values taking precedence.
        Non-dict values are simply overwritten. Logs merge operations for debugging.

        Args:
            base: Base dictionary to merge into.
            override: Dictionary with override values.

        Returns:
            None. Modifies the base dictionary in place.

        """
        self.logger.debug(
            "IntellicrackConfig: Performing deep merge. Base keys: %s, Override keys: %s", list(base.keys()), list(override.keys())
        )
        for key, value in override.items():
            base_value = base.get(key)
            if isinstance(base_value, dict) and isinstance(value, dict):
                self.logger.debug("IntellicrackConfig: Deep merging nested dictionary for key: '%s'.", key)
                self._deep_merge(base_value, value)
            else:
                self.logger.debug("IntellicrackConfig: Merging key '%s' with value '%s'.", key, value)
                base[key] = value

    def _create_defaults_from_legacy(self) -> None:
        """Create config.defaults.json from legacy config.json.

        Migrates legacy configuration format to new defaults file format,
        removing runtime-specific fields like initialized, emergency_mode, and auto_discovered flags.
        Cleans up transient fields that should not persist in defaults.

        """
        self.logger.info("IntellicrackConfig: Creating new defaults file from legacy config: %s", self.config_file)
        try:
            defaults = self._config.copy()
            runtime_fields = ["initialized", "emergency_mode"]
            for field in runtime_fields:
                if field in defaults:
                    self.logger.debug("IntellicrackConfig: Removing runtime field '%s' from defaults.", field)
                    del defaults[field]

            secrets_section = defaults.get("secrets")
            if isinstance(secrets_section, dict) and "last_sync" in secrets_section:
                self.logger.debug("IntellicrackConfig: Removing 'secrets.last_sync' from defaults.")
                del secrets_section["last_sync"]

            tools_section = defaults.get("tools")
            if isinstance(tools_section, dict):
                for tool_name, tool_data in tools_section.items():
                    if isinstance(tool_data, dict) and "auto_discovered" in tool_data:
                        self.logger.debug("IntellicrackConfig: Removing 'auto_discovered' from tool '%s' defaults.", tool_name)
                        del tool_data["auto_discovered"]

            with open(self.defaults_file, "w", encoding="utf-8") as f:
                json.dump(defaults, f, indent=2, sort_keys=True)
            self.logger.info("IntellicrackConfig: Created %s successfully from legacy config.", self.defaults_file)
        except Exception:
            self.logger.exception("IntellicrackConfig: Failed to create defaults file from legacy config.")

    def _create_default_config(self) -> None:
        """Create or load unified configuration.

        Attempts to load unified config file. If not found, creates new default
        configuration with version 3.0 and saves to disk.

        """
        self.logger.info("IntellicrackConfig: Attempting to create or load unified configuration.")
        unified_config_file = self._get_intellicrack_root() / "config" / "config.json"
        if unified_config_file.exists():
            self.logger.debug("IntellicrackConfig: Unified config file found at %s. Attempting to load.", unified_config_file)
            try:
                with open(unified_config_file, encoding="utf-8") as f, self._config_lock:
                    self._config = json.load(f)
                self.logger.info("IntellicrackConfig: Loaded unified configuration from %s", unified_config_file)
                return
            except Exception:
                self.logger.exception("IntellicrackConfig: Failed to load unified config, creating default.")

        self.logger.info("IntellicrackConfig: Creating new default configuration with auto-discovery.")
        default_config: dict[str, object] = {
            "version": "3.0",
        }
        with self._config_lock:
            self._config = default_config

        self._save_config()
        self.logger.info("IntellicrackConfig: Default configuration created and saved successfully.")

    def get(self, key: str, default: object = None) -> object:
        """Get configuration value with dot notation support.

        Supports dot notation for nested keys (e.g., 'section.subsection.key').
        Expands environment variables in string values.

        Args:
            key: Dot-separated configuration key path
            default: Default value to return if key not found

        Returns:
            Configuration value or default if not found

        """
        self.logger.debug("IntellicrackConfig: Attempting to get config key: '%s' with default: '%s'.", key, default)
        with self._config_lock:
            keys = key.split(".")
            value: object = self._config
            try:
                for k in keys:
                    if isinstance(value, dict):
                        value = value[k]
                    else:
                        self.logger.debug(
                            "IntellicrackConfig: Intermediate key '%s' in path '%s' is not a dictionary. Returning default.", k, key
                        )
                        return default

                expanded_value = self._expand_environment_variables(value)
                if expanded_value != value:
                    self.logger.debug("IntellicrackConfig: Key '%s' value '%s' expanded to '%s'.", key, value, expanded_value)
                else:
                    self.logger.debug("IntellicrackConfig: Successfully retrieved key '%s', value: '%s'.", key, expanded_value)
                return expanded_value
            except (KeyError, TypeError):
                self.logger.debug("IntellicrackConfig: Config key '%s' not found or path invalid, returning default: '%s'.", key, default)
                return default

    def set(self, key: str, value: object, save: bool | None = None) -> None:
        """Set configuration value with dot notation support.

        Supports dot notation for nested keys (e.g., 'section.subsection.key'). Creates intermediate dictionaries
        as needed. Optionally saves the configuration to disk after setting based on the save parameter or auto_save setting.

        Args:
            key: Dot-separated configuration key path.
            value: Value to set for the key.
            save: Whether to save config to disk (None uses auto_save setting).

        """
        self.logger.debug("IntellicrackConfig: Attempting to set config key: '%s' to value: '%s'.", key, value)
        with self._config_lock:
            keys = key.split(".")
            config: object = self._config
            for _i, k in enumerate(keys[:-1]):
                if not isinstance(config, dict):
                    self.logger.error(
                        "IntellicrackConfig: Cannot set key '%s'. Intermediate path segment '%s' is not a dictionary.", key, k
                    )
                    return
                if k not in config:
                    self.logger.debug("IntellicrackConfig: Creating new dictionary for intermediate key '%s'.", k)
                    config[k] = {}
                config = config[k]

            if not isinstance(config, dict):
                self.logger.error("IntellicrackConfig: Cannot set key '%s'. Final path segment parent is not a dictionary.", key)
                return

            config[keys[-1]] = value
            self.logger.info("IntellicrackConfig: Config key '%s' set successfully to '%s'.", key, value)

        if save is None:
            save = self.auto_save
        if save:
            self.logger.debug("IntellicrackConfig: Auto-saving configuration after setting key '%s'.", key)
            self._save_config()
        else:
            self.logger.debug("IntellicrackConfig: Auto-save disabled or explicitly false. Not saving config after setting key '%s'.", key)

    def _save_config(self) -> None:
        """Save the current configuration to the config file.

        Uses atomic write pattern with temporary file to ensure data integrity.
        Writes JSON with indentation and sorted keys. Logs success and exceptions.

        """
        self.logger.debug("IntellicrackConfig: Saving configuration to %s.", self.config_file)
        temp_file = self.config_file.with_suffix(".tmp")
        try:
            with temp_file.open("w", encoding="utf-8") as f, self._config_lock:
                json.dump(self._config, f, indent=2, sort_keys=True)
            temp_file.replace(self.config_file)
            self.logger.info("IntellicrackConfig: Configuration saved successfully to %s.", self.config_file)
        except Exception:
            self.logger.exception("IntellicrackConfig: Failed to save configuration to %s", self.config_file)

    def _expand_environment_variables(self, value: object) -> object:
        """Expand environment variables in a string value.

        Args:
            value: Value to process (only strings are expanded, others returned as-is)

        Returns:
            Expanded string or original value if not a string

        """
        if isinstance(value, str):
            expanded = os.path.expandvars(value)
            if "$" in expanded:  # Check for unexpanded variables
                self.logger.warning(
                    "IntellicrackConfig: Environment variable(s) in '%s' might not have been fully expanded. Result: '%s'", value, expanded
                )
            return expanded
        return value

    def upgrade_config(self) -> None:
        """Public method to trigger configuration upgrade if needed.

        Exposes config upgrade functionality for external callers like
        font_manager that need to trigger migration. Performs version-aware upgrades.

        """
        self.logger.info("IntellicrackConfig: upgrade_config() called - checking for upgrades.")
        self._upgrade_config_if_needed()

    def save(self) -> None:
        """Public method to save configuration to disk.

        Exposes save functionality for external callers that need to
        explicitly persist configuration changes. Calls _save_config() with thread safety.

        """
        self.logger.debug("IntellicrackConfig: save() called - persisting configuration.")
        self._save_config()

    def save_config(self) -> None:
        """Public alias for _save_config for API compatibility.

        Provides a consistent interface matching the expected method name
        in METHOD_IMPLEMENTATION_CHECKLIST.md and external callers. Delegates to _save_config().

        """
        self.logger.debug("IntellicrackConfig: save_config() called.")
        self._save_config()

    def get_api_endpoint(self, provider: str) -> str | None:
        """Get API endpoint URL for a specific AI provider.

        Retrieves the configured API endpoint for AI model providers like
        OpenAI, Anthropic, Google, OpenRouter, and LM Studio.

        Args:
            provider: Provider name (openai, anthropic, google, openrouter, lmstudio)

        Returns:
            Configured endpoint URL or None if not set

        """
        provider_lower = provider.lower().strip()

        endpoint_mappings: dict[str, tuple[str, ...]] = {
            "openai": ("ai", "providers", "openai", "endpoint"),
            "anthropic": ("ai", "providers", "anthropic", "endpoint"),
            "google": ("ai", "providers", "google", "endpoint"),
            "openrouter": ("ai", "providers", "openrouter", "endpoint"),
            "lmstudio": ("ai", "providers", "lmstudio", "endpoint"),
        }

        if provider_lower not in endpoint_mappings:
            self.logger.warning("Unknown API provider: %s", provider)
            return None

        keys = endpoint_mappings[provider_lower]
        value: Any = self._config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                self.logger.debug("API endpoint not configured for provider: %s", provider)
                return None

        return value if isinstance(value, str) and value else None

    def _upgrade_config_if_needed(self) -> None:
        """Perform configuration upgrades based on version.

        Recursively upgrades configuration format when version changes.
        Supports upgrades from 1.0->2.0 and 2.0->3.0. Automatically saves upgraded configuration.

        """
        current_version = self._config.get("version", "1.0")
        self.logger.debug("IntellicrackConfig: Current config version: %s", current_version)

        if not isinstance(current_version, str):
            self.logger.warning("IntellicrackConfig: Version is not a string, defaulting to '1.0'")
            current_version = "1.0"

        if current_version < "2.0":
            self.logger.info("IntellicrackConfig: Upgrading config from <2.0 to 2.0.")
            self._config["version"] = "2.0"
            self._save_config()
            self.logger.info("IntellicrackConfig: Config upgraded to 2.0.")
            self._upgrade_config_if_needed()
        elif current_version < "3.0":
            self.logger.info("IntellicrackConfig: Upgrading config from <3.0 to 3.0.")
            self._config["version"] = "3.0"
            self._save_config()
            self.logger.info("IntellicrackConfig: Config upgraded to 3.0.")
            self._upgrade_config_if_needed()
        else:
            self.logger.debug("IntellicrackConfig: Configuration is up to date.")

    def _create_emergency_config(self) -> None:
        """Create a minimal emergency configuration if critical errors occur.

        Creates minimal configuration with basic logging and safety defaults
        to allow the application to start in degraded mode. Attempts to save
        emergency configuration even if primary config fails.

        """
        self.logger.critical("IntellicrackConfig: Creating emergency configuration due to critical error.")
        try:
            emergency_config = {
                "version": "emergency",
                "emergency_mode": True,
                "logging": {
                    "level": "ERROR",
                    "enable_file_logging": True,
                    "enable_console_logging": True,
                },
                "general": {
                    "first_run_completed": False,
                },
            }
            with self._config_lock:
                self._config = emergency_config
            self._save_config()  # Attempt to save even in emergency
            self.logger.info("IntellicrackConfig: Emergency configuration created and saved to %s.", self.config_file)
        except Exception:
            self.logger.exception("IntellicrackConfig: Failed to create and save emergency configuration")

    def get_tool_path(self, tool_name: str) -> str | None:
        """Get path for a specific tool.

        Retrieves configured tool path or attempts auto-discovery using shutil.which().
        Auto-discovered paths are cached in configuration.

        Args:
            tool_name: Name of the tool (e.g., 'ghidra', 'radare2')

        Returns:
            Full path to the tool executable or None if not found

        """
        self.logger.debug("IntellicrackConfig: Requesting path for tool: '%s'.", tool_name)
        path = self.get(f"tools.{tool_name}.path")
        if isinstance(path, str):
            self.logger.debug("IntellicrackConfig: Found configured path for tool '%s': '%s'.", tool_name, path)
            return path

        self.logger.debug("IntellicrackConfig: No explicit path for '%s', attempting auto-discovery.", tool_name)
        import shutil

        discovered_path = shutil.which(tool_name)
        if discovered_path:
            self.logger.info("IntellicrackConfig: Auto-discovered path for tool '%s': '%s'.", tool_name, discovered_path)
            self.set(f"tools.{tool_name}.path", discovered_path, save=False)
            self.set(f"tools.{tool_name}.auto_discovered", True, save=False)
            return discovered_path

        self.logger.warning("IntellicrackConfig: Tool '%s' not found via configuration or auto-discovery.", tool_name)
        return None

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available.

        Args:
            tool_name: Name of the tool to check

        Returns:
            True if tool is available, False otherwise

        """
        self.logger.debug("IntellicrackConfig: Checking availability for tool: '%s'.", tool_name)
        is_available = self.get_tool_path(tool_name) is not None
        self.logger.debug("IntellicrackConfig: Tool '%s' availability: %s.", tool_name, is_available)
        return is_available

    def get_logs_dir(self) -> Path:
        """Get logs directory as a Path object.

        Returns:
            Path object pointing to the logs directory

        """
        return self.logs_dir

    def get_output_dir(self) -> Path:
        """Get output directory as a Path object.

        Returns:
            Path object pointing to the output directory

        """
        return self.output_dir

    def get_cache_dir(self) -> Path:
        """Get cache directory as a Path object.

        Returns:
            Path object pointing to the cache directory

        """
        return self.cache_dir

    def _get_runtime_state_property(self, key: str, default: object = None) -> object:
        """Get a runtime state property value.

        Runtime state is stored in-memory only and not persisted to configuration files.
        This is used for transient application state that should not survive process restarts.

        Args:
            key: Dot-separated property path (e.g., 'analyzer.active_session_id')
            default: Default value if property doesn't exist

        Returns:
            The property value or default if not found

        """
        with self._runtime_state_lock:
            keys = key.split(".")
            current: object = self._runtime_state

            for k in keys[:-1]:
                if not isinstance(current, dict):
                    return default
                if k not in current:
                    return default
                current = current.get(k, {})
                if not isinstance(current, dict):
                    return default

            if isinstance(current, dict):
                return current.get(keys[-1], default)
            return default

    def _set_runtime_state_property(self, key: str, value: object) -> None:
        """Set a runtime state property value.

        Runtime state is stored in-memory only and not persisted to configuration files.
        This is used for transient application state that should not survive process restarts.
        Creates intermediate dictionaries as needed for nested keys.

        Args:
            key: Dot-separated property path (e.g., 'analyzer.active_session_id').
            value: Value to set.

        """
        with self._runtime_state_lock:
            keys = key.split(".")
            current: object = self._runtime_state

            for k in keys[:-1]:
                if not isinstance(current, dict):
                    return
                if k not in current or not isinstance(current[k], dict):
                    current[k] = {}
                current = current[k]

            if isinstance(current, dict):
                current[keys[-1]] = value


_config_instance: IntellicrackConfig | None = None
_config_lock = threading.Lock()


def get_config() -> IntellicrackConfig:
    """Get the singleton configuration instance.

    Returns:
        IntellicrackConfig: The global configuration instance

    """
    global _config_instance
    if _config_instance is None:
        with _config_lock:
            if _config_instance is None:
                _config_instance = IntellicrackConfig()
    return _config_instance


__all__ = ["IntellicrackConfig", "get_config"]
