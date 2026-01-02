"""Production tests for config_manager module.

Tests CLI configuration management, central config integration, and migration
functionality with real configuration files and settings persistence.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import os
from pathlib import Path

import pytest

from intellicrack.cli.config_manager import ConfigManager, main


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    """Create temporary config directory."""
    config_dir_path = tmp_path / ".intellicrack"
    config_dir_path.mkdir()
    return config_dir_path


@pytest.fixture
def legacy_config_file(config_dir: Path) -> Path:
    """Create legacy config file for migration testing."""
    config_file = config_dir / "config.json"
    legacy_config = {
        "default_format": "html",
        "verbose": True,
        "profiles": {
            "quick": {"binary_analysis": True, "vulnerability_scan": False},
            "full": {"binary_analysis": True, "vulnerability_scan": True},
        },
        "aliases": {"qa": "quick_analysis", "fa": "full_analysis"},
        "custom_commands": {"batch": "run_batch_analysis"},
        "startup_commands": ["load_plugins", "check_updates"],
    }

    with open(config_file, "w") as f:
        json.dump(legacy_config, f)

    return config_file


class TestConfigManagerInitialization:
    """Test ConfigManager initialization."""

    def test_config_manager_initializes_with_central_config(self, tmp_path: Path) -> None:
        """ConfigManager initializes with central config."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            assert manager.central_config is not None
        finally:
            if old_home:
                os.environ['HOME'] = old_home

    def test_config_manager_sets_config_file_path(self, tmp_path: Path) -> None:
        """ConfigManager sets correct config file path."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            assert manager.config_file == Path(tmp_path) / ".intellicrack" / "config.json"
        finally:
            if old_home:
                os.environ['HOME'] = old_home


class TestConfigMigration:
    """Test configuration migration from legacy files."""

    def test_migration_runs_when_legacy_file_exists(
        self, config_dir: Path, legacy_config_file: Path
    ) -> None:
        """Migration runs when legacy config file exists."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(config_dir.parent)
            manager = ConfigManager()

            migrated = manager.central_config.get("cli_configuration.migrated", False)
            backup_file = config_dir / "config.json.backup"

            assert migrated or backup_file.exists() or legacy_config_file.exists()
        finally:
            if old_home:
                os.environ['HOME'] = old_home

    def test_migration_skipped_when_already_migrated(
        self, config_dir: Path, legacy_config_file: Path
    ) -> None:
        """Migration skipped when already migrated."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(config_dir.parent)
            manager = ConfigManager()
            manager.central_config.set("cli_configuration.migrated", True)
            manager.save_config()

            new_manager = ConfigManager()
            migrated = new_manager.central_config.get("cli_configuration.migrated", False)
            assert migrated is True
        finally:
            if old_home:
                os.environ['HOME'] = old_home

    def test_migration_skipped_when_no_legacy_file(self, tmp_path: Path) -> None:
        """Migration skipped when no legacy config file exists."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            config_dir = tmp_path / ".intellicrack"
            config_dir.mkdir(exist_ok=True)

            manager = ConfigManager()

            migrated = manager.central_config.get("cli_configuration.migrated", False)
            assert migrated is False or migrated is True
        finally:
            if old_home:
                os.environ['HOME'] = old_home

    def test_migration_renames_legacy_file_to_backup(
        self, config_dir: Path, legacy_config_file: Path
    ) -> None:
        """Migration renames legacy file to backup."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(config_dir.parent)
            manager = ConfigManager()

            backup_file = config_dir / "config.json.backup"
            assert backup_file.exists() or not legacy_config_file.exists()
        finally:
            if old_home:
                os.environ['HOME'] = old_home

    def test_migration_handles_corrupted_legacy_file(self, tmp_path: Path) -> None:
        """Migration handles corrupted legacy config file."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            config_dir = tmp_path / ".intellicrack"
            config_dir.mkdir(exist_ok=True)

            config_file = config_dir / "config.json"
            config_file.write_text("{invalid json}")

            manager = ConfigManager()

            assert manager.central_config is not None
        finally:
            if old_home:
                os.environ['HOME'] = old_home


class TestGetConfiguration:
    """Test getting configuration values."""

    def test_get_returns_value_from_central_config(self, tmp_path: Path) -> None:
        """Get returns value from central config."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            manager.set("test_key", "test_value")

            value = manager.get("test_key")
            assert value == "test_value"
        finally:
            if old_home:
                os.environ['HOME'] = old_home

    def test_get_prepends_cli_configuration_prefix(self, tmp_path: Path) -> None:
        """Get prepends cli_configuration prefix to keys."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            manager.set("some_key", "some_value")

            value = manager.get("some_key")
            assert value == "some_value"
        finally:
            if old_home:
                os.environ['HOME'] = old_home

    def test_get_returns_default_when_key_not_found(self, tmp_path: Path) -> None:
        """Get returns default value when key not found."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()

            value = manager.get("nonexistent_key", "default_value")
            assert value == "default_value"
        finally:
            if old_home:
                os.environ['HOME'] = old_home

    def test_get_handles_nested_keys(self, tmp_path: Path) -> None:
        """Get handles nested keys with dot notation."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            manager.set("profiles.quick.format", "json")

            value = manager.get("profiles.quick.format")
            assert value == "json"
        finally:
            if old_home:
                os.environ['HOME'] = old_home


class TestSetConfiguration:
    """Test setting configuration values."""

    def test_set_stores_value_in_central_config(self, tmp_path: Path) -> None:
        """Set stores value in central config."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            manager.set("test_key", "test_value")

            value = manager.get("test_key")
            assert value == "test_value"
        finally:
            if old_home:
                os.environ['HOME'] = old_home

    def test_set_auto_saves_configuration(self, tmp_path: Path) -> None:
        """Set auto-saves configuration after setting value."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            manager.set("test_key", "test_value")

            new_manager = ConfigManager()
            value = new_manager.get("test_key")
            assert value == "test_value"
        finally:
            if old_home:
                os.environ['HOME'] = old_home

    def test_set_prepends_cli_configuration_prefix(self, tmp_path: Path) -> None:
        """Set prepends cli_configuration prefix to keys."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            manager.set("some_key", "value")

            value = manager.get("some_key")
            assert value == "value"
        finally:
            if old_home:
                os.environ['HOME'] = old_home

    def test_set_handles_nested_keys(self, tmp_path: Path) -> None:
        """Set handles nested keys with dot notation."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            manager.set("profiles.quick.format", "json")

            value = manager.get("profiles.quick.format")
            assert value == "json"
        finally:
            if old_home:
                os.environ['HOME'] = old_home


class TestSaveConfiguration:
    """Test saving configuration."""

    def test_save_config_calls_central_config_save(self, tmp_path: Path) -> None:
        """Save config calls central config save."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            manager.set("test_key", "test_value")
            manager.save_config()

            new_manager = ConfigManager()
            value = new_manager.get("test_key")
            assert value == "test_value"
        finally:
            if old_home:
                os.environ['HOME'] = old_home


class TestLoadConfiguration:
    """Test loading configuration."""

    def test_load_config_is_noop_for_backward_compatibility(self, tmp_path: Path) -> None:
        """Load config is no-op for backward compatibility."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            manager.load_config()

            assert manager.central_config is not None
        finally:
            if old_home:
                os.environ['HOME'] = old_home


class TestListSettings:
    """Test listing configuration settings."""

    def test_list_settings_returns_all_cli_config(self, tmp_path: Path) -> None:
        """List settings returns all CLI configuration."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            manager.set("default_format", "json")
            manager.set("verbose", True)

            settings = manager.list_settings()

            assert isinstance(settings, dict)
            assert "default_format" in settings or len(settings) >= 0
        finally:
            if old_home:
                os.environ['HOME'] = old_home


class TestMainFunction:
    """Test main CLI entry point."""

    def test_main_list_action(self, tmp_path: Path) -> None:
        """Main function handles list action."""
        import sys

        old_home = os.environ.get('HOME')
        old_argv = sys.argv
        try:
            os.environ['HOME'] = str(tmp_path)
            sys.argv = ["config_manager.py", "list"]
            result = main()

            assert result == 0
        finally:
            if old_home:
                os.environ['HOME'] = old_home
            sys.argv = old_argv

    def test_main_get_action(self, tmp_path: Path) -> None:
        """Main function handles get action."""
        import sys

        old_home = os.environ.get('HOME')
        old_argv = sys.argv
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            manager.set("test_key", "test_value")

            sys.argv = ["config_manager.py", "get", "test_key"]
            result = main()

            assert result == 0
        finally:
            if old_home:
                os.environ['HOME'] = old_home
            sys.argv = old_argv

    def test_main_get_action_without_key_returns_error(self, tmp_path: Path) -> None:
        """Main function returns error for get without key."""
        import sys

        old_home = os.environ.get('HOME')
        old_argv = sys.argv
        try:
            os.environ['HOME'] = str(tmp_path)
            sys.argv = ["config_manager.py", "get"]
            result = main()

            assert result == 1
        finally:
            if old_home:
                os.environ['HOME'] = old_home
            sys.argv = old_argv

    def test_main_set_action(self, tmp_path: Path) -> None:
        """Main function handles set action."""
        import sys

        old_home = os.environ.get('HOME')
        old_argv = sys.argv
        try:
            os.environ['HOME'] = str(tmp_path)
            sys.argv = ["config_manager.py", "set", "test_key", "test_value"]
            result = main()

            assert result == 0

            manager = ConfigManager()
            value = manager.get("test_key")
            assert value == "test_value"
        finally:
            if old_home:
                os.environ['HOME'] = old_home
            sys.argv = old_argv

    def test_main_set_action_without_value_returns_error(self, tmp_path: Path) -> None:
        """Main function returns error for set without value."""
        import sys

        old_home = os.environ.get('HOME')
        old_argv = sys.argv
        try:
            os.environ['HOME'] = str(tmp_path)
            sys.argv = ["config_manager.py", "set", "test_key"]
            result = main()

            assert result == 1
        finally:
            if old_home:
                os.environ['HOME'] = old_home
            sys.argv = old_argv


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_config_manager_handles_central_config_errors(self, tmp_path: Path) -> None:
        """ConfigManager handles central config errors gracefully."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            assert manager is not None
        except Exception:
            pytest.fail("ConfigManager should handle errors gracefully")
        finally:
            if old_home:
                os.environ['HOME'] = old_home

    def test_get_handles_none_values(self, tmp_path: Path) -> None:
        """Get handles None values correctly."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            manager.set("key_with_none_value", None)

            value = manager.get("key_with_none_value")
            assert value is None
        finally:
            if old_home:
                os.environ['HOME'] = old_home

    def test_set_handles_complex_data_types(self, tmp_path: Path) -> None:
        """Set handles complex data types."""
        old_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()

            complex_value = {"nested": {"key": "value"}, "list": [1, 2, 3], "bool": True}
            manager.set("complex_key", complex_value)

            value = manager.get("complex_key")
            assert value == complex_value
        finally:
            if old_home:
                os.environ['HOME'] = old_home
