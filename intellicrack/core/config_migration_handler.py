"""Comprehensive error handling for configuration migration.

This module provides robust error handling and recovery mechanisms for
configuration migration from legacy systems to the central IntellicrackConfig.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import json
import logging
import traceback
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class MigrationStatus(Enum):
    """Status of migration operations."""

    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
    ROLLED_BACK = "rolled_back"


class MigrationError(Exception):
    """Base exception for migration errors."""

    pass


class MigrationRollbackError(MigrationError):
    """Exception raised when rollback fails."""

    pass


class MigrationValidator:
    """Validates migrated configuration data."""

    @staticmethod
    def validate_structure(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate the structure of migrated configuration.

        Args:
            config: Configuration dictionary to validate

        Returns:
            Tuple of (is_valid, list_of_errors)

        """
        errors = []
        required_sections = [
            "version",
            "application",
            "directories",
            "ui_preferences",
            "analysis_settings",
        ]

        for section in required_sections:
            if section not in config:
                errors.append(f"Missing required section: {section}")

        # Validate version format
        if "version" in config:
            version = config["version"]
            if not isinstance(version, str) or not version.replace(".", "").isdigit():
                errors.append(f"Invalid version format: {version}")

        # Validate application section
        if "application" in config:
            app = config["application"]
            if not isinstance(app, dict):
                errors.append("Application section must be a dictionary")
            elif "name" not in app:
                errors.append("Application section missing 'name' field")

        return len(errors) == 0, errors

    @staticmethod
    def validate_data_types(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate data types in configuration.

        Args:
            config: Configuration dictionary to validate

        Returns:
            Tuple of (is_valid, list_of_errors)

        """
        errors = []

        # Check for None values in critical fields
        def check_none_values(data: Any, path: str = "") -> None:
            if isinstance(data, dict):
                for key, value in data.items():
                    new_path = f"{path}.{key}" if path else key
                    if value is None and key not in ["api_key", "password", "token"]:
                        errors.append(f"Unexpected None value at: {new_path}")
                    else:
                        check_none_values(value, new_path)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    check_none_values(item, f"{path}[{i}]")

        check_none_values(config)

        # Validate specific data types
        if "ui_preferences" in config:
            ui = config["ui_preferences"]
            if "font_size" in ui and not isinstance(ui["font_size"], (int, float)):
                errors.append(f"Invalid font_size type: {type(ui['font_size']).__name__}")
            if "theme" in ui and not isinstance(ui["theme"], str):
                errors.append(f"Invalid theme type: {type(ui['theme']).__name__}")

        return len(errors) == 0, errors


class MigrationBackup:
    """Handles backup and restore for configuration migration."""

    def __init__(self, config_path: Path) -> None:
        """Initialize backup handler.

        Args:
            config_path: Path to the configuration file

        """
        self.config_path = config_path
        self.backup_dir = config_path.parent / "migration_backups"
        self.backup_dir.mkdir(exist_ok=True)

    def create_backup(self, config_data: Dict[str, Any]) -> Path:
        """Create a backup of configuration data.

        Args:
            config_data: Configuration data to backup

        Returns:
            Path to the backup file

        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"config_backup_{timestamp}.json"

        try:
            with open(backup_file, "w") as f:
                json.dump(config_data, f, indent=2)
            logger.info(f"Created backup at: {backup_file}")
            return backup_file
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            raise MigrationError(f"Backup creation failed: {e}") from e

    def restore_backup(self, backup_file: Path) -> Dict[str, Any]:
        """Restore configuration from backup.

        Args:
            backup_file: Path to the backup file

        Returns:
            Restored configuration data

        """
        try:
            with open(backup_file) as f:
                config_data = json.load(f)
            logger.info(f"Restored configuration from: {backup_file}")
            return config_data
        except Exception as e:
            logger.error(f"Failed to restore backup: {e}")
            raise MigrationRollbackError(f"Backup restoration failed: {e}") from e

    def get_latest_backup(self) -> Optional[Path]:
        """Get the most recent backup file.

        Returns:
            Path to the latest backup or None

        """
        backups = list(self.backup_dir.glob("config_backup_*.json"))
        if backups:
            return max(backups, key=lambda p: p.stat().st_mtime)
        return None


class ConfigMigrationHandler:
    """Comprehensive handler for configuration migration with error recovery."""

    def __init__(self, config_path: Path) -> None:
        """Initialize migration handler.

        Args:
            config_path: Path to the main configuration file

        """
        self.config_path = config_path
        self.backup_handler = MigrationBackup(config_path)
        self.validator = MigrationValidator()
        self.migration_log = []
        self.migration_status = MigrationStatus.NOT_STARTED

    def migrate_with_recovery(
        self, config_data: Dict[str, Any], migration_func: callable, migration_name: str,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Execute migration with error handling and recovery.

        Args:
            config_data: Current configuration data
            migration_func: Function to perform migration
            migration_name: Name of the migration for logging

        Returns:
            Tuple of (success, migrated_config_data)

        """
        self.migration_status = MigrationStatus.IN_PROGRESS
        self.log_migration(f"Starting migration: {migration_name}")

        # Create backup before migration
        try:
            backup_file = self.backup_handler.create_backup(config_data)
        except MigrationError as e:
            self.migration_status = MigrationStatus.FAILED
            self.log_migration(f"Failed to create backup: {e}", level="error")
            return False, config_data

        # Attempt migration
        try:
            migrated_data = migration_func(config_data.copy())

            # Validate migrated data
            structure_valid, structure_errors = self.validator.validate_structure(migrated_data)
            if not structure_valid:
                raise MigrationError(f"Structure validation failed: {structure_errors}")

            type_valid, type_errors = self.validator.validate_data_types(migrated_data)
            if not type_valid:
                raise MigrationError(f"Type validation failed: {type_errors}")

            self.migration_status = MigrationStatus.COMPLETED
            self.log_migration(f"Successfully completed migration: {migration_name}")
            return True, migrated_data

        except Exception as e:
            self.migration_status = MigrationStatus.FAILED
            self.log_migration(f"Migration failed: {e}", level="error")
            self.log_migration(f"Stack trace: {traceback.format_exc()}", level="debug")

            # Attempt rollback
            try:
                restored_data = self.backup_handler.restore_backup(backup_file)
                self.migration_status = MigrationStatus.ROLLED_BACK
                self.log_migration(f"Rolled back to backup: {backup_file}")
                return False, restored_data
            except MigrationRollbackError as re:
                self.log_migration(f"Rollback failed: {re}", level="critical")
                # Return original data as last resort
                return False, config_data

    def handle_partial_migration(self, config_data: Dict[str, Any], migrations: Dict[str, callable]) -> Dict[str, Any]:
        """Handle multiple migrations with partial success support.

        Args:
            config_data: Current configuration data
            migrations: Dictionary of migration_name -> migration_function

        Returns:
            Migrated configuration data

        """
        successful_migrations = []
        failed_migrations = []
        current_data = config_data

        for name, func in migrations.items():
            success, migrated_data = self.migrate_with_recovery(current_data, func, name)

            if success:
                successful_migrations.append(name)
                current_data = migrated_data
            else:
                failed_migrations.append(name)
                self.log_migration(f"Continuing with partial migration after {name} failed", level="warning")

        if failed_migrations:
            self.migration_status = MigrationStatus.PARTIAL
            self.log_migration(
                f"Partial migration completed. Successful: {successful_migrations}, Failed: {failed_migrations}",
                level="warning",
            )

        return current_data

    def log_migration(self, message: str, level: str = "info") -> None:
        """Log migration message.

        Args:
            message: Message to log
            level: Log level (info, warning, error, critical, debug)

        """
        timestamp = datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "level": level,
            "message": message,
            "status": self.migration_status.value,
        }
        self.migration_log.append(log_entry)

        # Also log to standard logger
        log_func = getattr(logger, level, logger.info)
        log_func(message)

    def save_migration_log(self) -> None:
        """Save migration log to file."""
        log_file = self.config_path.parent / "migration_log.json"
        try:
            with open(log_file, "w") as f:
                json.dump(self.migration_log, f, indent=2)
            logger.info(f"Migration log saved to: {log_file}")
        except Exception as e:
            logger.error(f"Failed to save migration log: {e}")

    def get_migration_report(self) -> Dict[str, Any]:
        """Get a summary report of the migration.

        Returns:
            Dictionary containing migration report

        """
        errors = [entry for entry in self.migration_log if entry["level"] in ["error", "critical"]]
        warnings = [entry for entry in self.migration_log if entry["level"] == "warning"]

        return {
            "status": self.migration_status.value,
            "total_entries": len(self.migration_log),
            "errors": len(errors),
            "warnings": len(warnings),
            "error_messages": [e["message"] for e in errors],
            "warning_messages": [w["message"] for w in warnings],
            "latest_backup": str(self.backup_handler.get_latest_backup()),
        }


class SafeMigrationWrapper:
    """Wrap to safely execute migration functions with timeout and resource limits."""

    @staticmethod
    def migrate_with_timeout(migration_func: callable, config_data: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
        """Execute migration with timeout protection.

        Args:
            migration_func: Migration function to execute
            config_data: Configuration data
            timeout: Timeout in seconds

        Returns:
            Migrated configuration data

        """
        import threading

        result = [None]
        exception = [None]

        def run_migration() -> None:
            try:
                result[0] = migration_func(config_data)
            except Exception as e:
                exception[0] = e

        thread = threading.Thread(target=run_migration)
        thread.start()
        thread.join(timeout)

        if thread.is_alive():
            # Migration took too long
            raise MigrationError(f"Migration timed out after {timeout} seconds")

        if exception[0]:
            raise exception[0]

        return result[0]

    @staticmethod
    def validate_migration_result(original: Dict[str, Any], migrated: Dict[str, Any]) -> bool:
        """Validate that migration preserved essential data.

        Args:
            original: Original configuration
            migrated: Migrated configuration

        Returns:
            True if validation passes

        """
        # Check that no critical sections were lost
        critical_sections = ["version", "application"]
        for section in critical_sections:
            if section in original and section not in migrated:
                logger.error(f"Critical section '{section}' lost during migration")
                return False

        # Check that configuration didn't shrink too much
        original_size = len(json.dumps(original))
        migrated_size = len(json.dumps(migrated))

        if migrated_size < original_size * 0.5:
            logger.warning(f"Configuration size reduced by more than 50% ({original_size} -> {migrated_size} bytes)")

        return True
