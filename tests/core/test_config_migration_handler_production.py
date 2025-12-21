"""Production tests for configuration migration handler.

Tests validate real configuration migration scenarios including backup creation,
rollback mechanisms, validation, and error recovery.
"""

import json
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.config_migration_handler import (
    ConfigMigrationHandler,
    MigrationBackup,
    MigrationError,
    MigrationRollbackError,
    MigrationStatus,
    MigrationValidator,
    SafeMigrationWrapper,
)


@pytest.fixture
def temp_config_dir(tmp_path: Path) -> Path:
    """Create temporary configuration directory."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    return config_dir


@pytest.fixture
def valid_config() -> dict[str, Any]:
    """Create valid configuration structure."""
    return {
        "version": "1.0.0",
        "application": {
            "name": "Intellicrack",
            "debug": False,
        },
        "directories": {
            "workspace": "/path/to/workspace",
            "output": "/path/to/output",
        },
        "ui_preferences": {
            "theme": "dark",
            "font_size": 12,
        },
        "analysis_settings": {
            "timeout": 300,
            "max_threads": 4,
        },
    }


@pytest.fixture
def invalid_config() -> dict[str, Any]:
    """Create invalid configuration structure."""
    return {
        "version": "1.0.0",
        "application": "not_a_dict",
    }


@pytest.fixture
def config_file(temp_config_dir: Path, valid_config: dict[str, Any]) -> Path:
    """Create configuration file."""
    config_path = temp_config_dir / "config.json"
    with open(config_path, "w") as f:
        json.dump(valid_config, f)
    return config_path


class TestMigrationValidator:
    """Test configuration validation."""

    def test_validate_structure_with_valid_config(self, valid_config: dict[str, Any]) -> None:
        """Validator accepts properly structured configuration."""
        validator = MigrationValidator()
        is_valid, errors = validator.validate_structure(valid_config)

        assert is_valid
        assert not errors

    def test_validate_structure_detects_missing_sections(self) -> None:
        """Validator detects missing required sections."""
        incomplete_config = {
            "version": "1.0.0",
            "application": {"name": "test"},
        }

        validator = MigrationValidator()
        is_valid, errors = validator.validate_structure(incomplete_config)

        assert not is_valid
        assert any("directories" in error for error in errors)
        assert any("ui_preferences" in error for error in errors)
        assert any("analysis_settings" in error for error in errors)

    def test_validate_structure_detects_invalid_version_format(self) -> None:
        """Validator detects malformed version strings."""
        config = {
            "version": "invalid_version_format",
            "application": {"name": "test"},
            "directories": {},
            "ui_preferences": {},
            "analysis_settings": {},
        }

        validator = MigrationValidator()
        is_valid, errors = validator.validate_structure(config)

        assert not is_valid
        assert any("Invalid version format" in error for error in errors)

    def test_validate_structure_detects_invalid_application_section(self) -> None:
        """Validator detects when application section is not a dict."""
        config = {
            "version": "1.0.0",
            "application": "not_a_dict",
            "directories": {},
            "ui_preferences": {},
            "analysis_settings": {},
        }

        validator = MigrationValidator()
        is_valid, errors = validator.validate_structure(config)

        assert not is_valid
        assert any("must be a dictionary" in error for error in errors)

    def test_validate_structure_requires_application_name(self) -> None:
        """Validator ensures application section has name field."""
        config = {
            "version": "1.0.0",
            "application": {},
            "directories": {},
            "ui_preferences": {},
            "analysis_settings": {},
        }

        validator = MigrationValidator()
        is_valid, errors = validator.validate_structure(config)

        assert not is_valid
        assert any("missing 'name'" in error for error in errors)

    def test_validate_data_types_accepts_valid_types(self, valid_config: dict[str, Any]) -> None:
        """Validator accepts correct data types."""
        validator = MigrationValidator()
        is_valid, errors = validator.validate_data_types(valid_config)

        assert is_valid
        assert not errors

    def test_validate_data_types_detects_none_values(self) -> None:
        """Validator detects unexpected None values in configuration."""
        config = {
            "version": "1.0.0",
            "application": {
                "name": "test",
                "debug": None,
            },
        }

        validator = MigrationValidator()
        is_valid, errors = validator.validate_data_types(config)

        assert not is_valid
        assert any("None value" in error for error in errors)

    def test_validate_data_types_allows_none_for_secrets(self) -> None:
        """Validator permits None for API keys and secrets."""
        config = {
            "credentials": {
                "api_key": None,
                "password": None,
                "token": None,
            },
        }

        validator = MigrationValidator()
        is_valid, errors = validator.validate_data_types(config)

        assert is_valid
        assert not errors

    def test_validate_data_types_checks_ui_preferences(self) -> None:
        """Validator enforces correct types in UI preferences."""
        config = {
            "ui_preferences": {
                "font_size": "not_a_number",
                "theme": 123,
            },
        }

        validator = MigrationValidator()
        is_valid, errors = validator.validate_data_types(config)

        assert not is_valid
        assert any("font_size" in error for error in errors)
        assert any("theme" in error for error in errors)

    def test_validate_data_types_handles_nested_structures(self) -> None:
        """Validator recursively checks nested dictionaries and lists."""
        config = {
            "nested": {
                "level1": {
                    "level2": {
                        "invalid": None,
                    },
                },
                "list_data": [
                    {"item": None},
                ],
            },
        }

        validator = MigrationValidator()
        is_valid, errors = validator.validate_data_types(config)

        assert not is_valid
        assert len(errors) == 2


class TestMigrationBackup:
    """Test backup and restore operations."""

    def test_create_backup_generates_file(
        self, temp_config_dir: Path, valid_config: dict[str, Any]
    ) -> None:
        """Backup creation writes configuration to timestamped file."""
        config_path = temp_config_dir / "config.json"
        backup_handler = MigrationBackup(config_path)

        backup_file = backup_handler.create_backup(valid_config)

        assert backup_file.exists()
        assert backup_file.name.startswith("config_backup_")
        assert backup_file.suffix == ".json"

        with open(backup_file) as f:
            backup_data = json.load(f)
        assert backup_data == valid_config

    def test_create_backup_in_dedicated_directory(
        self, temp_config_dir: Path, valid_config: dict[str, Any]
    ) -> None:
        """Backups are stored in migration_backups subdirectory."""
        config_path = temp_config_dir / "config.json"
        backup_handler = MigrationBackup(config_path)

        backup_file = backup_handler.create_backup(valid_config)

        assert backup_file.parent.name == "migration_backups"
        assert backup_file.parent.exists()

    def test_create_backup_handles_write_errors(self, temp_config_dir: Path) -> None:
        """Backup creation raises MigrationError on write failure."""
        config_path = temp_config_dir / "config.json"
        backup_handler = MigrationBackup(config_path)

        readonly_dir = backup_handler.backup_dir
        readonly_dir.mkdir(exist_ok=True)

        invalid_config = {"circular": None}
        invalid_config["circular"] = invalid_config

        with pytest.raises(MigrationError) as exc_info:
            backup_handler.create_backup(invalid_config)

        assert "Backup creation failed" in str(exc_info.value)

    def test_restore_backup_loads_configuration(
        self, temp_config_dir: Path, valid_config: dict[str, Any]
    ) -> None:
        """Restore successfully loads configuration from backup file."""
        config_path = temp_config_dir / "config.json"
        backup_handler = MigrationBackup(config_path)

        backup_file = backup_handler.create_backup(valid_config)
        restored = backup_handler.restore_backup(backup_file)

        assert restored == valid_config

    def test_restore_backup_handles_missing_file(self, temp_config_dir: Path) -> None:
        """Restore raises MigrationRollbackError for missing backup."""
        config_path = temp_config_dir / "config.json"
        backup_handler = MigrationBackup(config_path)

        nonexistent = temp_config_dir / "missing.json"

        with pytest.raises(MigrationRollbackError) as exc_info:
            backup_handler.restore_backup(nonexistent)

        assert "Backup restoration failed" in str(exc_info.value)

    def test_restore_backup_handles_corrupted_json(
        self, temp_config_dir: Path
    ) -> None:
        """Restore raises MigrationRollbackError for malformed JSON."""
        config_path = temp_config_dir / "config.json"
        backup_handler = MigrationBackup(config_path)

        corrupted_backup = backup_handler.backup_dir / "corrupted.json"
        backup_handler.backup_dir.mkdir(exist_ok=True)
        corrupted_backup.write_text("{ invalid json }")

        with pytest.raises(MigrationRollbackError):
            backup_handler.restore_backup(corrupted_backup)

    def test_get_latest_backup_returns_most_recent(
        self, temp_config_dir: Path, valid_config: dict[str, Any]
    ) -> None:
        """Latest backup returns the most recently created file."""
        config_path = temp_config_dir / "config.json"
        backup_handler = MigrationBackup(config_path)

        backup_handler.create_backup(valid_config)
        time.sleep(0.01)
        backup2 = backup_handler.create_backup(valid_config)

        latest = backup_handler.get_latest_backup()
        assert latest == backup2

    def test_get_latest_backup_returns_none_when_empty(
        self, temp_config_dir: Path
    ) -> None:
        """Latest backup returns None when no backups exist."""
        config_path = temp_config_dir / "config.json"
        backup_handler = MigrationBackup(config_path)

        latest = backup_handler.get_latest_backup()
        assert latest is None


class TestConfigMigrationHandler:
    """Test complete migration workflow."""

    def test_migrate_with_recovery_successful_migration(
        self, config_file: Path, valid_config: dict[str, Any]
    ) -> None:
        """Successful migration updates configuration and completes."""
        handler = ConfigMigrationHandler(config_file)

        def add_new_field(config: dict[str, Any]) -> dict[str, Any]:
            config["new_section"] = {"enabled": True}
            return config

        success, result = handler.migrate_with_recovery(
            valid_config, add_new_field, "add_new_section"
        )

        assert success
        assert "new_section" in result
        assert result["new_section"]["enabled"] is True
        assert handler.migration_status == MigrationStatus.COMPLETED

    def test_migrate_with_recovery_creates_backup_before_migration(
        self, config_file: Path, valid_config: dict[str, Any]
    ) -> None:
        """Migration creates backup before attempting changes."""
        handler = ConfigMigrationHandler(config_file)

        def simple_migration(config: dict[str, Any]) -> dict[str, Any]:
            return config

        handler.migrate_with_recovery(valid_config, simple_migration, "test")

        latest_backup = handler.backup_handler.get_latest_backup()
        assert latest_backup is not None
        assert latest_backup.exists()

    def test_migrate_with_recovery_validates_structure(
        self, config_file: Path, valid_config: dict[str, Any]
    ) -> None:
        """Migration fails if structure validation fails."""
        handler = ConfigMigrationHandler(config_file)

        def break_structure(config: dict[str, Any]) -> dict[str, Any]:
            del config["version"]
            return config

        success, result = handler.migrate_with_recovery(
            valid_config, break_structure, "break_structure"
        )

        assert not success
        assert handler.migration_status == MigrationStatus.ROLLED_BACK
        assert "version" in result

    def test_migrate_with_recovery_validates_data_types(
        self, config_file: Path, valid_config: dict[str, Any]
    ) -> None:
        """Migration fails if data type validation fails."""
        handler = ConfigMigrationHandler(config_file)

        def break_types(config: dict[str, Any]) -> dict[str, Any]:
            config["ui_preferences"]["font_size"] = "invalid"
            return config

        success, result = handler.migrate_with_recovery(
            valid_config, break_types, "break_types"
        )

        assert not success
        assert isinstance(result["ui_preferences"]["font_size"], int)

    def test_migrate_with_recovery_rolls_back_on_failure(
        self, config_file: Path, valid_config: dict[str, Any]
    ) -> None:
        """Migration restores backup when migration function fails."""
        handler = ConfigMigrationHandler(config_file)

        def failing_migration(config: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("Migration failed")

        success, result = handler.migrate_with_recovery(
            valid_config, failing_migration, "failing_migration"
        )

        assert not success
        assert handler.migration_status == MigrationStatus.ROLLED_BACK
        assert result == valid_config

    def test_migrate_with_recovery_handles_backup_failure(
        self, config_file: Path
    ) -> None:
        """Migration aborts if backup creation fails."""
        handler = ConfigMigrationHandler(config_file)

        backup_dir = handler.backup_handler.backup_dir
        backup_dir.mkdir(exist_ok=True)
        backup_dir.chmod(0o444)

        try:
            config = {"circular": None}
            config["circular"] = config

            success, result = handler.migrate_with_recovery(
                config, lambda c: c, "test"
            )

            assert not success
            assert handler.migration_status == MigrationStatus.FAILED
        finally:
            backup_dir.chmod(0o755)

    def test_migrate_with_recovery_logs_migration_steps(
        self, config_file: Path, valid_config: dict[str, Any]
    ) -> None:
        """Migration logs all steps including start, success, and errors."""
        handler = ConfigMigrationHandler(config_file)

        def simple_migration(config: dict[str, Any]) -> dict[str, Any]:
            return config

        handler.migrate_with_recovery(valid_config, simple_migration, "test_migration")

        assert len(handler.migration_log) > 0
        assert any("Starting migration" in entry["message"] for entry in handler.migration_log)
        assert any("Successfully completed" in entry["message"] for entry in handler.migration_log)

    def test_handle_partial_migration_with_all_success(
        self, config_file: Path, valid_config: dict[str, Any]
    ) -> None:
        """Partial migration applies all successful migrations."""
        handler = ConfigMigrationHandler(config_file)

        migrations = {
            "add_field1": lambda c: {**c, "field1": "value1"},
            "add_field2": lambda c: {**c, "field2": "value2"},
        }

        result = handler.handle_partial_migration(valid_config, migrations)

        assert "field1" in result
        assert "field2" in result
        assert handler.migration_status == MigrationStatus.COMPLETED

    def test_handle_partial_migration_with_some_failures(
        self, config_file: Path, valid_config: dict[str, Any]
    ) -> None:
        """Partial migration continues after individual migration failures."""
        handler = ConfigMigrationHandler(config_file)

        def failing_migration(config: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("This migration fails")

        migrations = {
            "successful": lambda c: {**c, "success_field": True},
            "failing": failing_migration,
            "another_successful": lambda c: {**c, "another_field": True},
        }

        result = handler.handle_partial_migration(valid_config, migrations)

        assert "success_field" in result
        assert handler.migration_status == MigrationStatus.PARTIAL

    def test_handle_partial_migration_tracks_successes_and_failures(
        self, config_file: Path, valid_config: dict[str, Any]
    ) -> None:
        """Partial migration logs which migrations succeeded and failed."""
        handler = ConfigMigrationHandler(config_file)

        def failing_migration(config: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("Failure")

        migrations = {
            "success1": lambda c: c,
            "failure": failing_migration,
            "success2": lambda c: c,
        }

        handler.handle_partial_migration(valid_config, migrations)

        log_messages = [entry["message"] for entry in handler.migration_log]
        partial_msg = next(msg for msg in log_messages if "Partial migration completed" in msg)
        assert "success1" in partial_msg
        assert "success2" in partial_msg
        assert "failure" in partial_msg

    def test_log_migration_adds_to_log(self, config_file: Path) -> None:
        """Log migration adds entries with timestamp and status."""
        handler = ConfigMigrationHandler(config_file)

        handler.log_migration("Test message", "info")

        assert len(handler.migration_log) == 1
        entry = handler.migration_log[0]
        assert entry["message"] == "Test message"
        assert entry["level"] == "info"
        assert "timestamp" in entry
        assert entry["status"] == MigrationStatus.NOT_STARTED.value

    def test_save_migration_log_writes_to_file(
        self, config_file: Path, valid_config: dict[str, Any]
    ) -> None:
        """Migration log is saved to JSON file."""
        handler = ConfigMigrationHandler(config_file)

        handler.log_migration("Entry 1")
        handler.log_migration("Entry 2")
        handler.save_migration_log()

        log_file = config_file.parent / "migration_log.json"
        assert log_file.exists()

        with open(log_file) as f:
            saved_log = json.load(f)
        assert len(saved_log) == 2

    def test_get_migration_report_summarizes_status(
        self, config_file: Path, valid_config: dict[str, Any]
    ) -> None:
        """Migration report provides summary of errors and warnings."""
        handler = ConfigMigrationHandler(config_file)

        handler.log_migration("Info message", "info")
        handler.log_migration("Warning message", "warning")
        handler.log_migration("Error message", "error")
        handler.log_migration("Critical message", "critical")

        report = handler.get_migration_report()

        assert report["total_entries"] == 4
        assert report["warnings"] == 1
        assert report["errors"] == 2
        assert "Warning message" in report["warning_messages"]
        assert "Error message" in report["error_messages"]
        assert "Critical message" in report["error_messages"]


class TestSafeMigrationWrapper:
    """Test safe migration execution with timeout and validation."""

    def test_migrate_with_timeout_completes_fast_migration(
        self, valid_config: dict[str, Any]
    ) -> None:
        """Fast migrations complete successfully within timeout."""
        def fast_migration(config: dict[str, Any]) -> dict[str, Any]:
            config["fast"] = True
            return config

        result = SafeMigrationWrapper.migrate_with_timeout(
            fast_migration, valid_config, timeout=5
        )

        assert result["fast"] is True

    def test_migrate_with_timeout_raises_on_timeout(
        self, valid_config: dict[str, Any]
    ) -> None:
        """Slow migrations timeout and raise MigrationError."""
        def slow_migration(config: dict[str, Any]) -> dict[str, Any]:
            time.sleep(2)
            return config

        with pytest.raises(MigrationError) as exc_info:
            SafeMigrationWrapper.migrate_with_timeout(
                slow_migration, valid_config, timeout=1
            )

        assert "timed out" in str(exc_info.value)

    def test_migrate_with_timeout_propagates_exceptions(
        self, valid_config: dict[str, Any]
    ) -> None:
        """Exceptions from migration function are propagated."""
        def failing_migration(config: dict[str, Any]) -> dict[str, Any]:
            raise ValueError("Migration error")

        with pytest.raises(ValueError) as exc_info:
            SafeMigrationWrapper.migrate_with_timeout(
                failing_migration, valid_config, timeout=5
            )

        assert "Migration error" in str(exc_info.value)

    def test_validate_migration_result_accepts_valid_migration(
        self, valid_config: dict[str, Any]
    ) -> None:
        """Validation passes for properly migrated configuration."""
        migrated = valid_config.copy()
        migrated["new_field"] = "added"

        is_valid = SafeMigrationWrapper.validate_migration_result(
            valid_config, migrated
        )

        assert is_valid

    def test_validate_migration_result_detects_lost_critical_sections(
        self, valid_config: dict[str, Any]
    ) -> None:
        """Validation fails if critical sections are removed."""
        migrated = valid_config.copy()
        del migrated["version"]

        is_valid = SafeMigrationWrapper.validate_migration_result(
            valid_config, migrated
        )

        assert not is_valid

    def test_validate_migration_result_warns_on_size_reduction(
        self, valid_config: dict[str, Any], caplog: pytest.LogCaptureFixture
    ) -> None:
        """Validation warns if configuration shrinks significantly."""
        migrated = {"version": "1.0.0", "application": {"name": "test"}}

        SafeMigrationWrapper.validate_migration_result(valid_config, migrated)

        assert any("reduced by more than 50%" in record.message for record in caplog.records)


class TestIntegrationScenarios:
    """Test complete migration scenarios."""

    def test_complete_migration_workflow_with_validation(
        self, config_file: Path, valid_config: dict[str, Any]
    ) -> None:
        """Complete migration with backup, validation, and success."""
        handler = ConfigMigrationHandler(config_file)

        def upgrade_config(config: dict[str, Any]) -> dict[str, Any]:
            config["version"] = "2.0.0"
            config["new_features"] = {"feature1": True}
            return config

        success, result = handler.migrate_with_recovery(
            valid_config, upgrade_config, "upgrade_to_v2"
        )

        assert success
        assert result["version"] == "2.0.0"
        assert "new_features" in result
        assert handler.backup_handler.get_latest_backup() is not None

        report = handler.get_migration_report()
        assert report["status"] == MigrationStatus.COMPLETED.value
        assert report["errors"] == 0

    def test_migration_failure_with_successful_rollback(
        self, config_file: Path, valid_config: dict[str, Any]
    ) -> None:
        """Failed migration triggers rollback restoring original state."""
        handler = ConfigMigrationHandler(config_file)
        original_version = valid_config["version"]

        def breaking_migration(config: dict[str, Any]) -> dict[str, Any]:
            del config["version"]
            del config["application"]
            return config

        success, result = handler.migrate_with_recovery(
            valid_config, breaking_migration, "breaking_change"
        )

        assert not success
        assert result["version"] == original_version
        assert "application" in result
        assert handler.migration_status == MigrationStatus.ROLLED_BACK

    def test_multiple_migrations_with_partial_success(
        self, config_file: Path, valid_config: dict[str, Any]
    ) -> None:
        """Multiple migrations with some failures result in partial status."""
        handler = ConfigMigrationHandler(config_file)

        migrations = {
            "add_cache_settings": lambda c: {
                **c,
                "cache": {"enabled": True, "size": 1024}
            },
            "invalid_migration": lambda c: {**c, "ui_preferences": {"font_size": "invalid"}},
            "add_logging": lambda c: {
                **c,
                "logging": {"level": "INFO"}
            },
        }

        result = handler.handle_partial_migration(valid_config, migrations)

        assert "cache" in result
        assert handler.migration_status == MigrationStatus.PARTIAL

        report = handler.get_migration_report()
        assert report["warnings"] > 0

    def test_migration_preserves_data_integrity(
        self, config_file: Path, valid_config: dict[str, Any]
    ) -> None:
        """Migration preserves all existing data while adding new fields."""
        handler = ConfigMigrationHandler(config_file)

        def add_performance_settings(config: dict[str, Any]) -> dict[str, Any]:
            config["performance"] = {
                "gpu_acceleration": True,
                "max_memory": 8192,
            }
            return config

        success, result = handler.migrate_with_recovery(
            valid_config, add_performance_settings, "add_performance"
        )

        assert success
        for key, value in valid_config.items():
            assert key in result
            assert result[key] == value
        assert "performance" in result
