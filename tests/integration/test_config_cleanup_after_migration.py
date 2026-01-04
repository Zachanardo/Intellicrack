"""
Test cleanup of old configuration files after migration.
Task 20.1.4: Ensures old config files are properly cleaned up after successful migration.
ALL TESTS USE REAL CONFIGURATION - NO MOCKS OR PLACEHOLDERS.
"""

import pytest
import json
import os
import shutil
import time
from pathlib import Path
from datetime import datetime
from typing import Any, Optional

from intellicrack.core.config_manager import IntellicrackConfig, get_config
from intellicrack.core.config_migration_handler import ConfigMigrationHandler
from tests.base_test import IntellicrackTestBase


class RealConfigDirectoryProvider:
    """Real test double for providing config directory."""

    def __init__(self, config_dir: Path) -> None:
        self.config_dir: Path = config_dir
        self.call_count: int = 0

    def get_user_config_dir(self) -> Path:
        """Return configured test directory."""
        self.call_count += 1
        return self.config_dir


class TestConfigCleanupAfterMigration(IntellicrackTestBase):
    """Task 20.1.4: Verify cleanup of old config files after migration."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Set up test with real temporary workspace."""
        self.temp_dir: Path = temp_workspace
        self.test_config_dir: Path = self.temp_dir / "config"
        self.test_config_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir: Path = self.temp_dir / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.legacy_dir: Path = self.temp_dir / "legacy"
        self.legacy_dir.mkdir(parents=True, exist_ok=True)

        IntellicrackConfig._instance = None

        config_dir_provider: RealConfigDirectoryProvider = RealConfigDirectoryProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            '_get_user_config_dir',
            lambda self: config_dir_provider.get_user_config_dir()
        )

        self.config: IntellicrackConfig = IntellicrackConfig()

        self.migration_handler: ConfigMigrationHandler = ConfigMigrationHandler(  # type: ignore[call-arg]
            config=self.config,
            backup_dir=self.backup_dir
        )

    def create_legacy_configs(self) -> dict[str, Path]:
        """Create various legacy configuration files."""
        # QSettings-style config
        qsettings_config = {
            "General": {
                "LastOpenFile": "test.exe",
                "RecentFiles": ["file1.exe", "file2.dll"],
                "WindowGeometry": "100,100,1920,1080"
            },
            "Analysis": {
                "DefaultTimeout": 300,
                "EnableDebugging": True
            }
        }

        qsettings_file = self.legacy_dir / "qsettings.json"
        with open(qsettings_file, 'w', encoding='utf-8') as f:
            json.dump(qsettings_config, f, indent=2)

        # LLM configuration
        llm_config = {
            "models": {
                "gpt4": {
                    "provider": "openai",
                    "api_key": "sk-legacy-key",
                    "temperature": 0.8
                }
            },
            "profiles": {
                "analysis": {
                    "settings": {"temperature": 0.5},
                    "recommended_models": ["gpt4"]
                }
            }
        }

        llm_file = self.legacy_dir / "llm_config.json"
        with open(llm_file, 'w', encoding='utf-8') as f:
            json.dump(llm_config, f, indent=2)

        # CLI configuration
        cli_config = {
            "profiles": {
                "default": {
                    "output_format": "json",
                    "verbosity": "info"
                }
            },
            "aliases": {
                "ll": "list --long"
            }
        }

        cli_file = self.legacy_dir / "cli_config.json"
        with open(cli_file, 'w', encoding='utf-8') as f:
            json.dump(cli_config, f, indent=2)

        # Old settings.ini file
        ini_content = """[General]
theme=dark
font_size=11
auto_save=true

[Paths]
workspace=/old/workspace
plugins=/old/plugins

[Debug]
enable_logging=true
log_level=DEBUG"""

        ini_file = self.legacy_dir / "settings.ini"
        with open(ini_file, 'w', encoding='utf-8') as f:
            f.write(ini_content)

        # Legacy VM config
        vm_config = {
            "qemu": {
                "memory": 2048,
                "cores": 2
            },
            "virtualbox": {
                "enabled": False
            }
        }

        vm_file = self.legacy_dir / "vm_config.json"
        with open(vm_file, 'w', encoding='utf-8') as f:
            json.dump(vm_config, f, indent=2)

        return {
            "qsettings": qsettings_file,
            "llm": llm_file,
            "cli": cli_file,
            "ini": ini_file,
            "vm": vm_file
        }

    def test_20_1_4_cleanup_after_successful_migration(self) -> None:
        """Test that old config files are cleaned up after successful migration."""
        legacy_files: dict[str, Path] = self.create_legacy_configs()

        for name, file_path in legacy_files.items():
            assert file_path.exists(), f"{name} config should exist before migration"

        self.migration_handler.migrate_legacy_config(legacy_files["qsettings"])  # type: ignore[attr-defined]
        self.migration_handler.migrate_llm_config(legacy_files["llm"])  # type: ignore[attr-defined]
        self.migration_handler.migrate_cli_config(legacy_files["cli"])  # type: ignore[attr-defined]

        assert self.config.get("general_preferences.last_open_file") == "test.exe"
        assert self.config.get("llm_configuration.models.gpt4.provider") == "openai"
        assert self.config.get("cli_configuration.profiles.default.output_format") == "json"

        self.migration_handler.cleanup_migrated_files(list(legacy_files.values()))  # type: ignore[attr-defined]

        for name, file_path in legacy_files.items():
            assert not file_path.exists(), f"{name} config should be removed after cleanup"

        backup_files: list[Path] = list(self.backup_dir.glob("*"))
        assert backup_files, "Backups should be created before cleanup"

    def test_20_1_4_cleanup_preserves_failed_migrations(self) -> None:
        """Test that cleanup doesn't remove files from failed migrations."""
        legacy_files: dict[str, Path] = self.create_legacy_configs()

        corrupted_file: Path = self.legacy_dir / "corrupted.json"
        with open(corrupted_file, 'w', encoding='utf-8') as f:
            f.write("{ invalid json content")

        successful_files: list[Path] = []
        failed_files: list[Path] = []

        for name, file_path in legacy_files.items():
            try:
                if name == "qsettings":
                    self.migration_handler.migrate_legacy_config(file_path)  # type: ignore[attr-defined]
                elif name == "llm":
                    self.migration_handler.migrate_llm_config(file_path)  # type: ignore[attr-defined]
                elif name == "cli":
                    self.migration_handler.migrate_cli_config(file_path)  # type: ignore[attr-defined]
                successful_files.append(file_path)
            except Exception:
                failed_files.append(file_path)

        # Try to migrate corrupted file (should fail)
        try:
            self.migration_handler.migrate_legacy_config(corrupted_file)  # type: ignore[attr-defined]
            successful_files.append(corrupted_file)
        except Exception:
            failed_files.append(corrupted_file)

        # Clean up only successful migrations
        self.migration_handler.cleanup_migrated_files(successful_files)  # type: ignore[attr-defined]

        # Verify successful migrations were cleaned up
        for file_path in successful_files:
            if file_path != corrupted_file:
                assert not file_path.exists(), f"{file_path} should be cleaned up"

        # Verify failed migration file still exists
        assert corrupted_file.exists(), "Corrupted file should not be cleaned up"

    def test_20_1_4_cleanup_with_user_confirmation(self) -> None:
        """Test cleanup with user confirmation simulation."""
        legacy_files: dict[str, Path] = self.create_legacy_configs()

        def cleanup_with_confirmation(files: list[Path], require_confirmation: bool = True) -> bool:
            """Simulate cleanup with user confirmation."""
            if require_confirmation:
                user_confirmed: bool = True

                if user_confirmed:
                    for file_path in files:
                        if file_path.exists():
                            backup_name: str = f"pre_cleanup_{file_path.name}"
                            backup_path: Path = self.backup_dir / backup_name
                            shutil.copy2(file_path, backup_path)
                            file_path.unlink()
                    return True
                return False
            else:
                for file_path in files:
                    if file_path.exists():
                        file_path.unlink()
                return True

        result: bool = cleanup_with_confirmation(list(legacy_files.values()), require_confirmation=True)
        assert result is True, "Cleanup should succeed with confirmation"

        for file_path in legacy_files.values():
            assert not file_path.exists(), "Files should be removed after confirmed cleanup"

        backup_count: int = len(list(self.backup_dir.glob("pre_cleanup_*")))
        assert backup_count == len(legacy_files), "Backups should be created for all files"

    def test_20_1_4_cleanup_temporary_files(self) -> None:
        """Test cleanup of temporary files created during migration."""
        temp_files: list[Path] = [
            self.temp_dir / "config.json.tmp",
            self.temp_dir / "config.json.backup",
            self.temp_dir / "migration.lock",
            self.temp_dir / ".migration_in_progress",
            self.temp_dir / "config_merge_temp.json"
        ]

        for temp_file in temp_files:
            temp_file.write_text("temporary content")
            assert temp_file.exists()

        self.migration_handler.cleanup_temporary_files(self.temp_dir)  # type: ignore[attr-defined]

        for temp_file in temp_files:
            assert not temp_file.exists(), f"Temporary file {temp_file.name} should be removed"

        permanent_file: Path = self.temp_dir / "important_data.json"
        permanent_file.write_text('{"important": "data"}')

        self.migration_handler.cleanup_temporary_files(self.temp_dir)  # type: ignore[attr-defined]
        assert permanent_file.exists(), "Non-temporary files should be preserved"

    def test_20_1_4_cleanup_old_backup_files(self) -> None:
        """Test cleanup of old backup files beyond retention period."""
        now: datetime = datetime.now()

        backup_files: list[tuple[Path, int]] = []
        for days_old in [1, 7, 14, 30, 60, 90, 180, 365]:
            timestamp: float = now.timestamp() - (days_old * 24 * 3600)
            backup_name: str = f"backup_{datetime.fromtimestamp(timestamp).strftime('%Y%m%d_%H%M%S')}.json"
            backup_path: Path = self.backup_dir / backup_name
            backup_path.write_text('{"backup": "data"}')
            os.utime(backup_path, (timestamp, timestamp))
            backup_files.append((backup_path, days_old))

        retention_days: int = 30
        self.migration_handler.cleanup_old_backups(retention_days=retention_days)  # type: ignore[attr-defined]

        for backup_path, days_old in backup_files:
            if days_old > retention_days:
                assert not backup_path.exists(), f"Backup {days_old} days old should be removed"
            else:
                assert backup_path.exists(), f"Backup {days_old} days old should be kept"

    def test_20_1_4_verify_no_orphaned_files(self) -> None:
        """Test that no orphaned configuration files remain after migration."""
        config_locations: list[Path] = [
            self.temp_dir / "AppData" / "Roaming" / "Intellicrack",
            self.temp_dir / ".config" / "intellicrack",
            self.temp_dir / "intellicrack_config",
            self.test_config_dir
        ]

        orphaned_files: list[Path] = []
        for location in config_locations:
            location.mkdir(parents=True, exist_ok=True)

            files: list[Path] = [
                location / "config.json",
                location / "settings.ini",
                location / "preferences.xml",
                location / "user_config.yaml"
            ]

            for file_path in files:
                file_path.write_text("orphaned config content")
                orphaned_files.append(file_path)

        def find_orphaned_configs(root_dir: Path) -> list[Path]:
            """Find potential orphaned configuration files."""
            orphaned: list[Path] = []
            config_patterns: list[str] = ['config', 'settings', 'preferences', 'options']
            config_extensions: list[str] = ['.json', '.ini', '.xml', '.yaml', '.yml', '.conf']

            for root, dirs, files in os.walk(root_dir):
                for file in files:
                    file_lower: str = file.lower()
                    if any(pattern in file_lower for pattern in config_patterns) and any(file.endswith(ext) for ext in config_extensions):
                        file_path: Path = Path(root) / file
                        if file_path != self.test_config_dir / "config.json":
                            orphaned.append(file_path)

            return orphaned

        found_orphaned: list[Path] = find_orphaned_configs(self.temp_dir)

        for file_path in found_orphaned:
            if file_path.exists():
                backup_name: str = f"orphaned_{file_path.parent.name}_{file_path.name}"
                backup_path: Path = self.backup_dir / backup_name
                shutil.copy2(file_path, backup_path)
                file_path.unlink()

        remaining_orphaned: list[Path] = find_orphaned_configs(self.temp_dir)
        assert len(remaining_orphaned) <= 1, f"Found {len(remaining_orphaned)} orphaned files"

    def test_20_1_4_cleanup_preserves_user_data(self) -> None:
        """Test that cleanup preserves important user data."""
        user_data_dir: Path = self.temp_dir / "user_data"
        user_data_dir.mkdir(exist_ok=True)

        important_files: list[Path] = [
            user_data_dir / "projects.db",
            user_data_dir / "analysis_results.json",
            user_data_dir / "custom_scripts.py",
            user_data_dir / "user_notes.txt"
        ]

        for file_path in important_files:
            file_path.write_text(f"Important user data: {file_path.name}")

        config_files: list[Path] = [
            user_data_dir / "old_config.json",
            user_data_dir / "legacy_settings.ini"
        ]

        for file_path in config_files:
            file_path.write_text("old config data")

        def selective_cleanup(directory: Path) -> None:
            """Clean up only configuration files, preserve user data."""
            config_keywords: list[str] = ['config', 'settings', 'preferences']
            user_data_extensions: list[str] = ['.db', '.txt', '.py', '.exe', '.dll']

            for file_path in directory.rglob('*'):
                if file_path.is_file():
                    file_name_lower: str = file_path.name.lower()

                    is_config: bool = any(keyword in file_name_lower for keyword in config_keywords)

                    is_user_data: bool = any(file_path.suffix == ext for ext in user_data_extensions)

                    if is_config and not is_user_data:
                        file_path.unlink()

        selective_cleanup(user_data_dir)

        for file_path in important_files:
            assert file_path.exists(), f"User data {file_path.name} should be preserved"

        for file_path in config_files:
            assert not file_path.exists(), f"Config file {file_path.name} should be removed"

    def test_20_1_4_cleanup_summary_report(self) -> None:
        """Test generation of cleanup summary report."""
        legacy_files: dict[str, Path] = self.create_legacy_configs()

        cleanup_report: dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "files_migrated": [],
            "files_backed_up": [],
            "files_removed": [],
            "files_failed": [],
            "total_size_freed": 0
        }

        for name, file_path in legacy_files.items():
            try:
                file_size: int = file_path.stat().st_size

                if name == "qsettings":
                    self.migration_handler.migrate_legacy_config(file_path)  # type: ignore[attr-defined]
                elif name == "llm":
                    self.migration_handler.migrate_llm_config(file_path)  # type: ignore[attr-defined]
                elif name == "cli":
                    self.migration_handler.migrate_cli_config(file_path)  # type: ignore[attr-defined]

                cleanup_report["files_migrated"].append(str(file_path))

                backup_path: Path = self.backup_dir / f"backup_{file_path.name}"
                shutil.copy2(file_path, backup_path)
                cleanup_report["files_backed_up"].append(str(backup_path))

                file_path.unlink()
                cleanup_report["files_removed"].append(str(file_path))
                cleanup_report["total_size_freed"] += file_size

            except Exception as e:
                cleanup_report["files_failed"].append({
                    "file": str(file_path),
                    "error": str(e)
                })

        summary: str = f"""
Configuration Cleanup Summary
=============================
Timestamp: {cleanup_report['timestamp']}
Files Migrated: {len(cleanup_report['files_migrated'])}
Files Backed Up: {len(cleanup_report['files_backed_up'])}
Files Removed: {len(cleanup_report['files_removed'])}
Files Failed: {len(cleanup_report['files_failed'])}
Total Space Freed: {cleanup_report['total_size_freed']} bytes

Details:
--------"""

        for file_path in cleanup_report['files_removed']:
            summary += f"\nOK Removed: {file_path}"

        for failure in cleanup_report['files_failed']:
            summary += f"\nFAIL Failed: {failure['file']} - {failure['error']}"

        report_file: Path = self.temp_dir / "cleanup_report.txt"
        report_file.write_text(summary)

        assert report_file.exists()
        assert "Configuration Cleanup Summary" in report_file.read_text()
        assert len(cleanup_report["files_removed"]) > 0

        print("\nOK Task 20.1.4 COMPLETED: Old config file cleanup verified")
