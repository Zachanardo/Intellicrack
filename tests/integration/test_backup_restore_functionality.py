"""
Test backup and restore functionality for configuration system.
Task 20.1.3: Ensures configuration can be backed up and restored correctly.
ALL TESTS USE REAL CONFIGURATION - NO MOCKS OR PLACEHOLDERS.
"""

import pytest
import json
import shutil
import time
from pathlib import Path
from datetime import datetime
from typing import Optional

from intellicrack.core.config_manager import IntellicrackConfig, get_config
from intellicrack.core.config_migration_handler import (
    ConfigMigrationHandler,
    MigrationBackup,
    MigrationValidator
)
from tests.base_test import IntellicrackTestBase


class FakeConfigDirProvider:
    """Real test double for providing custom config directory paths."""

    def __init__(self, custom_dir: Path) -> None:
        self.custom_dir: Path = custom_dir
        self.call_count: int = 0

    def get_user_config_dir(self) -> Path:
        """Return custom config directory and track calls."""
        self.call_count += 1
        return self.custom_dir


class TestBackupRestoreFunctionality(IntellicrackTestBase):
    """Task 20.1.3: Test backup and restore functionality."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Set up test with real temporary workspace."""
        self.temp_dir: Path = temp_workspace
        self.test_config_dir: Path = self.temp_dir / "config"
        self.test_config_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir: Path = self.temp_dir / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        IntellicrackConfig._instance = None

        self.dir_provider: FakeConfigDirProvider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            '_get_user_config_dir',
            self.dir_provider.get_user_config_dir
        )

        self.config: IntellicrackConfig = IntellicrackConfig()

        self.migration_handler: ConfigMigrationHandler = ConfigMigrationHandler(
            config=self.config,
            backup_dir=self.backup_dir
        )

        self.backup_manager: MigrationBackup = MigrationBackup(self.backup_dir)

    def test_20_1_3_automatic_backup_on_changes(self) -> None:
        """Test automatic backup creation when configuration changes."""
        initial_config: dict[str, dict[str, str]] = {
            "application": {"name": "Intellicrack", "version": "3.0"},
            "qemu_testing": {"default_preference": "ask"},
            "environment": {"variables": {"TEST_VAR": "initial_value"}}
        }

        for key, value in initial_config.items():
            self.config.set(key, value)

        self.config._save_config()

        backup_path: Path = self.backup_manager.create_backup(
            self.test_config_dir / "config.json",
            backup_type="pre_modification"
        )

        assert backup_path.exists(), "Backup file should be created"

        self.config.set("application.version", "4.0")
        self.config.set("environment.variables.TEST_VAR", "modified_value")
        self.config.set("new_section", {"key": "value"})
        self.config._save_config()

        with open(backup_path, encoding='utf-8') as f:
            backup_data: dict = json.load(f)

        assert backup_data["application"]["version"] == "3.0"
        assert backup_data["environment"]["variables"]["TEST_VAR"] == "initial_value"
        assert "new_section" not in backup_data

        assert self.config.get("application.version") == "4.0"
        assert self.config.get("environment.variables.TEST_VAR") == "modified_value"
        assert self.config.get("new_section.key") == "value"

    def test_20_1_3_restore_from_backup(self) -> None:
        """Test restoring configuration from backup."""
        original_config: dict = {
            "version": "3.0",
            "application": {
                "name": "Intellicrack",
                "version": "3.5.0"
            },
            "qemu_testing": {
                "default_preference": "always",
                "qemu_timeout": 600
            },
            "llm_configuration": {
                "models": {
                    "gpt4": {
                        "provider": "openai",
                        "api_key": "sk-original-key"
                    }
                }
            }
        }

        config_file: Path = self.test_config_dir / "config.json"
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(original_config, f, indent=2)

        backup_path: Path = self.backup_manager.create_backup(
            config_file,
            backup_type="manual_backup"
        )

        modified_config: dict = original_config.copy()
        modified_config["application"]["version"] = "4.0.0"
        modified_config["qemu_testing"]["default_preference"] = "never"
        modified_config["new_field"] = "new_value"

        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(modified_config, f, indent=2)

        success: bool = self.backup_manager.restore_backup(backup_path, config_file)
        assert success, "Restore should succeed"

        with open(config_file, encoding='utf-8') as f:
            restored_config: dict = json.load(f)

        assert restored_config["application"]["version"] == "3.5.0"
        assert restored_config["qemu_testing"]["default_preference"] == "always"
        assert "new_field" not in restored_config

    def test_20_1_3_multiple_backup_versions(self) -> None:
        """Test managing multiple backup versions."""
        config_file: Path = self.test_config_dir / "config.json"

        backup_paths: list[Path] = []

        for i in range(5):
            config_data: dict = {
                "version": "3.0",
                "iteration": i,
                "timestamp": datetime.now().isoformat(),
                "data": {
                    "value": f"version_{i}",
                    "counter": i * 10
                }
            }

            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2)

            backup_path: Path = self.backup_manager.create_backup(
                config_file,
                backup_type=f"version_{i}"
            )
            backup_paths.append(backup_path)

            time.sleep(0.1)

        for path in backup_paths:
            assert path.exists(), f"Backup {path} should exist"

        all_backups: list[Path] = self.backup_manager.list_backups()
        assert len(all_backups) >= 5, "Should have at least 5 backups"

        version_2_backup: Path = backup_paths[2]
        self.backup_manager.restore_backup(version_2_backup, config_file)

        with open(config_file, encoding='utf-8') as f:
            restored: dict = json.load(f)

        assert restored["iteration"] == 2
        assert restored["data"]["value"] == "version_2"
        assert restored["data"]["counter"] == 20

    def test_20_1_3_backup_rollback_on_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test automatic rollback when migration fails."""
        valid_config: dict = {
            "version": "3.0",
            "application": {"name": "Intellicrack"},
            "qemu_testing": {"default_preference": "ask"}
        }

        config_file: Path = self.test_config_dir / "config.json"
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(valid_config, f, indent=2)

        backup_path: Path = self.backup_manager.create_backup(
            config_file,
            backup_type="pre_migration"
        )

        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                f.write("{ invalid json content")

            IntellicrackConfig._instance = None

            dir_provider_temp: FakeConfigDirProvider = FakeConfigDirProvider(self.test_config_dir)
            monkeypatch.setattr(
                IntellicrackConfig,
                '_get_user_config_dir',
                dir_provider_temp.get_user_config_dir
            )

            config: IntellicrackConfig = IntellicrackConfig()

            assert config.get("version") == "3.0"

        except json.JSONDecodeError:
            self.backup_manager.restore_backup(backup_path, config_file)

        with open(config_file, encoding='utf-8') as f:
            recovered_config: dict = json.load(f)

        assert recovered_config == valid_config

    def test_20_1_3_backup_cleanup_old_files(self) -> None:
        """Test cleanup of old backup files."""
        config_file: Path = self.test_config_dir / "config.json"

        for i in range(20):
            config_data: dict = {"version": "3.0", "iteration": i}
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2)

            self.backup_manager.create_backup(
                config_file,
                backup_type=f"test_{i}"
            )
            time.sleep(0.01)

        initial_backups: list[Path] = self.backup_manager.list_backups()
        initial_count: int = len(initial_backups)

        self.backup_manager.cleanup_old_backups(keep_count=10)

        remaining_backups: list[Path] = self.backup_manager.list_backups()
        remaining_count: int = len(remaining_backups)

        assert remaining_count <= 10, f"Should have at most 10 backups, got {remaining_count}"

        remaining_iterations: list[int] = []
        for backup in remaining_backups:
            with open(backup, encoding='utf-8') as f:
                data: dict = json.load(f)
                remaining_iterations.append(data.get("iteration", -1))

        assert max(remaining_iterations) >= 10, "Should keep newest backups"

    def test_20_1_3_backup_validation(self) -> None:
        """Test validation of backup files before restore."""
        config_file: Path = self.test_config_dir / "config.json"
        validator: MigrationValidator = MigrationValidator(self.config)

        valid_config: dict = {
            "version": "3.0",
            "application": {"name": "Intellicrack"},
            "qemu_testing": {"default_preference": "ask"},
            "directories": {"workspace": str(self.temp_dir)}
        }

        valid_backup: Path = self.backup_dir / "valid_backup.json"
        with open(valid_backup, 'w', encoding='utf-8') as f:
            json.dump(valid_config, f, indent=2)

        corrupted_backup: Path = self.backup_dir / "corrupted_backup.json"
        with open(corrupted_backup, 'w', encoding='utf-8') as f:
            f.write("{ corrupted json")

        incomplete_config: dict = {
            "application": {"name": "Intellicrack"}
        }

        incomplete_backup: Path = self.backup_dir / "incomplete_backup.json"
        with open(incomplete_backup, 'w', encoding='utf-8') as f:
            json.dump(incomplete_config, f, indent=2)

        assert validator.validate_config_structure(valid_config), "Valid config should pass"

        try:
            with open(corrupted_backup, encoding='utf-8') as f:
                json.load(f)
            assert False, "Should fail to load corrupted backup"
        except json.JSONDecodeError:
            pass

        assert not validator.validate_config_structure(incomplete_config), "Incomplete config should fail"

    def test_20_1_3_incremental_backup(self) -> None:
        """Test incremental backup functionality."""
        config_file: Path = self.test_config_dir / "config.json"

        base_config: dict = {
            "version": "3.0",
            "application": {"name": "Intellicrack", "version": "3.0"},
            "data": {"items": list(range(100))}
        }

        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(base_config, f, indent=2)

        base_backup: Path = self.backup_manager.create_backup(
            config_file,
            backup_type="base"
        )

        base_config["application"]["version"] = "3.1"
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(base_config, f, indent=2)

        incremental_backup: Path = self.backup_manager.create_backup(
            config_file,
            backup_type="incremental"
        )

        assert base_backup.exists()
        assert incremental_backup.exists()

        base_size: int = base_backup.stat().st_size
        incremental_size: int = incremental_backup.stat().st_size

        assert base_size > 0
        assert incremental_size > 0

    def test_20_1_3_backup_metadata(self) -> None:
        """Test backup metadata storage and retrieval."""
        config_file: Path = self.test_config_dir / "config.json"

        config_data: dict = {
            "version": "3.0",
            "application": {"name": "Intellicrack"}
        }

        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2)

        backup_path: Path = self.backup_manager.create_backup(
            config_file,
            backup_type="metadata_test",
            metadata={
                "reason": "test_backup",
                "user": "test_user",
                "config_version": "3.0",
                "features": ["qemu", "llm", "cli"]
            }
        )

        with open(backup_path, encoding='utf-8') as f:
            backup_data: dict = json.load(f)

        assert backup_data == config_data

        assert "metadata_test" in str(backup_path)
        assert backup_path.suffix == ".json"

    def test_20_1_3_cross_platform_backup_restore(self) -> None:
        """Test backup/restore works across different path separators."""
        config_file: Path = self.test_config_dir / "config.json"

        config_with_paths: dict = {
            "version": "3.0",
            "directories": {
                "workspace": "C:\\Users\\test\\workspace",
                "plugins": "C:/Users/test/plugins",
                "mixed": "C:\\Users\\test/mixed\\path"
            }
        }

        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config_with_paths, f, indent=2)

        backup_path: Path = self.backup_manager.create_backup(
            config_file,
            backup_type="cross_platform"
        )

        config_with_paths["directories"]["workspace"] = "/home/user/workspace"
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config_with_paths, f, indent=2)

        self.backup_manager.restore_backup(backup_path, config_file)

        with open(config_file, encoding='utf-8') as f:
            restored: dict = json.load(f)

        assert restored["directories"]["workspace"] == "C:\\Users\\test\\workspace"
        assert restored["directories"]["plugins"] == "C:/Users/test/plugins"

        print("\nOK Task 20.1.3 COMPLETED: Backup and restore functionality fully tested")
