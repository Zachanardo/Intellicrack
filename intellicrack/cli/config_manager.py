"""Configuration manager for Intellicrack CLI.

This module provides a compatibility layer for CLI configuration management,
delegating all storage to the central IntellicrackConfig system. The legacy
~/.intellicrack/config.json file is automatically migrated on first use.

IMPORTANT: This is now a wrapper around IntellicrackConfig. All configuration
is stored in the central config.json file under the 'cli_configuration' section.
The separate CLI config file is no longer used except for one-time migration.

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

PRODUCTION-READY: Uses central configuration system as single source of truth.
Legacy JSON files are migrated on first run, then only central config is used.
"""

import json
import sys
from pathlib import Path


# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.core.config_manager import IntellicrackConfig
from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)


class ConfigManager:
    """Production-ready CLI configuration manager using central IntellicrackConfig.

    This class provides a clean API for managing CLI configurations while storing
    all data in the central config.json file. Legacy JSON files are only read
    during migration, never written to. Single source of truth: central config.
    """

    def __init__(self) -> None:
        """Initialize configuration manager with central config delegation.

        Sets up the central configuration system and performs one-time migration
        from legacy CLI configuration files if needed.
        """
        self.central_config = IntellicrackConfig()
        self.config_file = Path.home() / ".intellicrack" / "config.json"
        self._migrate_if_needed()

    def _migrate_if_needed(self) -> None:
        """Perform one-time migration from old JSON file to central config.

        Reads the legacy CLI configuration file (~/.intellicrack/config.json) if it
        exists and hasn't been migrated yet, then merges its contents into the
        central configuration system. The old file is backed up after successful
        migration.
        """
        # Check if we need to migrate
        if not self.config_file.exists() or self.central_config.get("cli_configuration.migrated", False):
            return
        try:
            logger.info("Migrating CLI config from %s to central config", self.config_file)

            # Load old config
            with open(self.config_file) as f:
                old_config: dict[str, object] = json.load(f)

            # Get current CLI config
            cli_config_raw: object = self.central_config.get("cli_configuration", {})
            if not isinstance(cli_config_raw, dict):
                cli_config_raw = {}
            cli_config: dict[str, object] = cli_config_raw

            # Merge old config into CLI section (old values take precedence for first migration)
            for key, value in old_config.items():
                # Map to appropriate subsection or direct field
                if key == "profiles" and isinstance(value, dict):
                    # Merge profiles
                    current_profiles_raw: object = cli_config.get("profiles", {})
                    if not isinstance(current_profiles_raw, dict):
                        current_profiles_raw = {}
                    current_profiles: dict[str, object] = current_profiles_raw
                    current_profiles.update(value)
                    cli_config["profiles"] = current_profiles
                elif key == "aliases" and isinstance(value, dict):
                    cli_config["aliases"] = value
                elif key == "custom_commands" and isinstance(value, dict):
                    cli_config["custom_commands"] = value
                elif key == "startup_commands" and isinstance(value, list):
                    cli_config["startup_commands"] = value
                else:
                    # Direct field mapping
                    cli_config[key] = value

            # Mark as migrated
            cli_config["migrated"] = True

            # Save to central config
            self.central_config.set("cli_configuration", cli_config)
            self.central_config.save()

            logger.info("Successfully migrated CLI configuration to central config")

            # Optionally rename old file to .backup
            backup_file = self.config_file.with_suffix(".json.backup")
            self.config_file.rename(backup_file)
            logger.info("Renamed old config to %s", backup_file)

        except Exception as e:
            logger.exception("Failed to migrate CLI config: %s", e)
            # Continue without migration, use defaults

    def load_config(self) -> None:
        """Load configuration - now a no-op since we use central config directly.

        This method is kept for backward compatibility. The central config is
        already loaded in __init__.
        """

    def save_config(self) -> None:
        """Save configuration to central config immediately.

        Persists all CLI configuration changes to the central configuration file.
        """
        self.central_config.save()
        logger.debug("CLI configuration saved to central config")

    def get(self, key: str, default: object | None = None) -> object:
        """Get configuration value from cli_configuration section.

        Args:
            key: Configuration key (can use dot notation for nested values)
            default: Default value if key not found

        Returns:
            object: Configuration value or default if key not found.

        """
        # Prepend cli_configuration if not already there
        if not key.startswith("cli_configuration."):
            key = f"cli_configuration.{key}"

        return self.central_config.get(key, default)

    def set(self, key: str, value: object) -> None:
        """Set configuration value in cli_configuration section.

        Args:
            key: Configuration key (can use dot notation for nested values)
            value: Value to set
        """
        # Prepend cli_configuration if not already there
        if not key.startswith("cli_configuration."):
            key = f"cli_configuration.{key}"

        self.central_config.set(key, value)
        # Auto-save for production readiness
        self.central_config.save()

    def list_settings(self) -> dict[str, object]:
        """List all CLI configuration settings.

        Returns:
            dict[str, object]: All CLI configuration settings as a dictionary.
        """
        settings_raw: object = self.central_config.get("cli_configuration", {})
        if not isinstance(settings_raw, dict):
            return {}
        return settings_raw


def main() -> int:
    """Run configuration management CLI.

    Executes the CLI interface for managing Intellicrack configuration settings,
    allowing users to get, set, or list configuration values.

    Returns:
        Exit code indicating success or failure (0 for success, 1 for error).
    """
    import argparse

    parser = argparse.ArgumentParser(description="Intellicrack Configuration Manager")
    parser.add_argument("action", choices=["get", "set", "list"], help="Action to perform")
    parser.add_argument("key", nargs="?", help="Configuration key")
    parser.add_argument("value", nargs="?", help="Configuration value (for set)")

    args = parser.parse_args()

    manager = ConfigManager()
    manager.load_config()  # No-op but kept for compatibility

    if args.action == "list":
        settings = manager.list_settings()
        for key, value in settings.items():
            logger.info("%s: %s", key, value)

    elif args.action == "get":
        if not args.key:
            logger.error("Error: Key required for get operation")
            return 1
        value = manager.get(args.key)
        logger.info("%s: %s", args.key, value)

    elif args.action == "set":
        if not args.key or args.value is None:
            logger.error("Error: Key and value required for set operation")
            return 1
        manager.set(args.key, args.value)
        manager.save_config()
        logger.info("Set %s = %s", args.key, args.value)

    return 0


if __name__ == "__main__":
    sys.exit(main())
