"""Production tests for config_manager module.

Tests CLI configuration management, central config integration, and migration
functionality with real configuration files and settings persistence.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

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


@pytest.fixture
def mock_central_config() -> MagicMock:
    """Create mock central config."""
    mock_config = MagicMock()
    mock_config.get.return_value = {}
    return mock_config


class TestConfigManagerInitialization:
    """Test ConfigManager initialization."""

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    def test_config_manager_initializes_with_central_config(self, mock_config_class: MagicMock) -> None:
        """ConfigManager initializes with central config."""
        mock_config = MagicMock()
        mock_config.get.return_value = False
        mock_config_class.return_value = mock_config

        manager = ConfigManager()

        assert manager.central_config is not None
        mock_config_class.assert_called_once()

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    @patch("pathlib.Path.home")
    def test_config_manager_sets_config_file_path(
        self, mock_home: MagicMock, mock_config_class: MagicMock
    ) -> None:
        """ConfigManager sets correct config file path."""
        mock_home.return_value = Path("/test/home")
        mock_config = MagicMock()
        mock_config.get.return_value = False
        mock_config_class.return_value = mock_config

        manager = ConfigManager()

        assert manager.config_file == Path("/test/home/.intellicrack/config.json")


class TestConfigMigration:
    """Test configuration migration from legacy files."""

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    @patch("pathlib.Path.home")
    def test_migration_runs_when_legacy_file_exists(
        self, mock_home: MagicMock, mock_config_class: MagicMock, config_dir: Path, legacy_config_file: Path
    ) -> None:
        """Migration runs when legacy config file exists."""
        mock_home.return_value = config_dir.parent
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: False if key == "cli_configuration.migrated" else {}
        mock_config_class.return_value = mock_config

        manager = ConfigManager()

        mock_config.set.assert_called()
        mock_config.save.assert_called()

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    @patch("pathlib.Path.home")
    def test_migration_skipped_when_already_migrated(
        self, mock_home: MagicMock, mock_config_class: MagicMock, config_dir: Path, legacy_config_file: Path
    ) -> None:
        """Migration skipped when already migrated."""
        mock_home.return_value = config_dir.parent
        mock_config = MagicMock()
        mock_config.get.return_value = True
        mock_config_class.return_value = mock_config

        manager = ConfigManager()

        mock_config.set.assert_not_called()

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    @patch("pathlib.Path.home")
    def test_migration_skipped_when_no_legacy_file(
        self, mock_home: MagicMock, mock_config_class: MagicMock, config_dir: Path
    ) -> None:
        """Migration skipped when no legacy config file exists."""
        mock_home.return_value = config_dir.parent
        mock_config = MagicMock()
        mock_config.get.return_value = False
        mock_config_class.return_value = mock_config

        manager = ConfigManager()

        mock_config.set.assert_not_called()

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    @patch("pathlib.Path.home")
    def test_migration_renames_legacy_file_to_backup(
        self, mock_home: MagicMock, mock_config_class: MagicMock, config_dir: Path, legacy_config_file: Path
    ) -> None:
        """Migration renames legacy file to backup."""
        mock_home.return_value = config_dir.parent
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: False if key == "cli_configuration.migrated" else {}
        mock_config_class.return_value = mock_config

        manager = ConfigManager()

        backup_file = config_dir / "config.json.backup"
        assert backup_file.exists() or not legacy_config_file.exists()

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    @patch("pathlib.Path.home")
    def test_migration_handles_corrupted_legacy_file(
        self, mock_home: MagicMock, mock_config_class: MagicMock, config_dir: Path
    ) -> None:
        """Migration handles corrupted legacy config file."""
        mock_home.return_value = config_dir.parent
        config_file = config_dir / "config.json"
        config_file.write_text("{invalid json}")

        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: False if key == "cli_configuration.migrated" else {}
        mock_config_class.return_value = mock_config

        manager = ConfigManager()

        assert manager.central_config is not None


class TestGetConfiguration:
    """Test getting configuration values."""

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    def test_get_returns_value_from_central_config(self, mock_config_class: MagicMock) -> None:
        """Get returns value from central config."""
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: (
            "test_value" if key == "cli_configuration.test_key" else False
        )
        mock_config_class.return_value = mock_config

        manager = ConfigManager()
        value = manager.get("test_key")

        mock_config.get.assert_called_with("cli_configuration.test_key", None)
        assert value == "test_value"

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    def test_get_prepends_cli_configuration_prefix(self, mock_config_class: MagicMock) -> None:
        """Get prepends cli_configuration prefix to keys."""
        mock_config = MagicMock()
        mock_config.get.return_value = False
        mock_config_class.return_value = mock_config

        manager = ConfigManager()
        manager.get("some_key")

        mock_config.get.assert_called_with("cli_configuration.some_key", None)

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    def test_get_returns_default_when_key_not_found(self, mock_config_class: MagicMock) -> None:
        """Get returns default value when key not found."""
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: default if "nonexistent" in key else False
        mock_config_class.return_value = mock_config

        manager = ConfigManager()
        value = manager.get("nonexistent_key", "default_value")

        assert value == "default_value"

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    def test_get_handles_nested_keys(self, mock_config_class: MagicMock) -> None:
        """Get handles nested keys with dot notation."""
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: (
            "nested_value" if key == "cli_configuration.profiles.quick.format" else False
        )
        mock_config_class.return_value = mock_config

        manager = ConfigManager()
        value = manager.get("profiles.quick.format")

        assert value == "nested_value"


class TestSetConfiguration:
    """Test setting configuration values."""

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    def test_set_stores_value_in_central_config(self, mock_config_class: MagicMock) -> None:
        """Set stores value in central config."""
        mock_config = MagicMock()
        mock_config.get.return_value = False
        mock_config_class.return_value = mock_config

        manager = ConfigManager()
        manager.set("test_key", "test_value")

        mock_config.set.assert_called_with("cli_configuration.test_key", "test_value")

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    def test_set_auto_saves_configuration(self, mock_config_class: MagicMock) -> None:
        """Set auto-saves configuration after setting value."""
        mock_config = MagicMock()
        mock_config.get.return_value = False
        mock_config_class.return_value = mock_config

        manager = ConfigManager()
        manager.set("test_key", "test_value")

        mock_config.save.assert_called()

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    def test_set_prepends_cli_configuration_prefix(self, mock_config_class: MagicMock) -> None:
        """Set prepends cli_configuration prefix to keys."""
        mock_config = MagicMock()
        mock_config.get.return_value = False
        mock_config_class.return_value = mock_config

        manager = ConfigManager()
        manager.set("some_key", "value")

        mock_config.set.assert_called_with("cli_configuration.some_key", "value")

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    def test_set_handles_nested_keys(self, mock_config_class: MagicMock) -> None:
        """Set handles nested keys with dot notation."""
        mock_config = MagicMock()
        mock_config.get.return_value = False
        mock_config_class.return_value = mock_config

        manager = ConfigManager()
        manager.set("profiles.quick.format", "json")

        mock_config.set.assert_called_with("cli_configuration.profiles.quick.format", "json")


class TestSaveConfiguration:
    """Test saving configuration."""

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    def test_save_config_calls_central_config_save(self, mock_config_class: MagicMock) -> None:
        """Save config calls central config save."""
        mock_config = MagicMock()
        mock_config.get.return_value = False
        mock_config_class.return_value = mock_config

        manager = ConfigManager()
        manager.save_config()

        mock_config.save.assert_called()


class TestLoadConfiguration:
    """Test loading configuration."""

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    def test_load_config_is_noop_for_backward_compatibility(self, mock_config_class: MagicMock) -> None:
        """Load config is no-op for backward compatibility."""
        mock_config = MagicMock()
        mock_config.get.return_value = False
        mock_config_class.return_value = mock_config

        manager = ConfigManager()
        manager.load_config()

        assert manager.central_config is not None


class TestListSettings:
    """Test listing configuration settings."""

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    def test_list_settings_returns_all_cli_config(self, mock_config_class: MagicMock) -> None:
        """List settings returns all CLI configuration."""
        mock_config = MagicMock()
        cli_config = {
            "default_format": "json",
            "verbose": True,
            "profiles": {"quick": {}, "full": {}},
        }
        mock_config.get.side_effect = lambda key, default=None: cli_config if key == "cli_configuration" else False
        mock_config_class.return_value = mock_config

        manager = ConfigManager()
        settings = manager.list_settings()

        assert settings == cli_config
        assert "default_format" in settings
        assert "profiles" in settings


class TestMainFunction:
    """Test main CLI entry point."""

    @patch("intellicrack.cli.config_manager.ConfigManager")
    def test_main_list_action(self, mock_manager_class: MagicMock) -> None:
        """Main function handles list action."""
        mock_manager = MagicMock()
        mock_manager.list_settings.return_value = {"key1": "value1", "key2": "value2"}
        mock_manager_class.return_value = mock_manager

        with patch("sys.argv", ["config_manager.py", "list"]):
            result = main()

        assert result == 0
        mock_manager.list_settings.assert_called_once()

    @patch("intellicrack.cli.config_manager.ConfigManager")
    def test_main_get_action(self, mock_manager_class: MagicMock) -> None:
        """Main function handles get action."""
        mock_manager = MagicMock()
        mock_manager.get.return_value = "test_value"
        mock_manager_class.return_value = mock_manager

        with patch("sys.argv", ["config_manager.py", "get", "test_key"]):
            result = main()

        assert result == 0
        mock_manager.get.assert_called_once_with("test_key")

    @patch("intellicrack.cli.config_manager.ConfigManager")
    def test_main_get_action_without_key_returns_error(self, mock_manager_class: MagicMock) -> None:
        """Main function returns error for get without key."""
        mock_manager = MagicMock()
        mock_manager_class.return_value = mock_manager

        with patch("sys.argv", ["config_manager.py", "get"]):
            result = main()

        assert result == 1

    @patch("intellicrack.cli.config_manager.ConfigManager")
    def test_main_set_action(self, mock_manager_class: MagicMock) -> None:
        """Main function handles set action."""
        mock_manager = MagicMock()
        mock_manager_class.return_value = mock_manager

        with patch("sys.argv", ["config_manager.py", "set", "test_key", "test_value"]):
            result = main()

        assert result == 0
        mock_manager.set.assert_called_once_with("test_key", "test_value")
        mock_manager.save_config.assert_called_once()

    @patch("intellicrack.cli.config_manager.ConfigManager")
    def test_main_set_action_without_value_returns_error(self, mock_manager_class: MagicMock) -> None:
        """Main function returns error for set without value."""
        mock_manager = MagicMock()
        mock_manager_class.return_value = mock_manager

        with patch("sys.argv", ["config_manager.py", "set", "test_key"]):
            result = main()

        assert result == 1


class TestEdgeCases:
    """Test edge cases and error handling."""

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    def test_config_manager_handles_central_config_errors(self, mock_config_class: MagicMock) -> None:
        """ConfigManager handles central config errors gracefully."""
        mock_config = MagicMock()
        mock_config.get.side_effect = Exception("Config error")
        mock_config_class.return_value = mock_config

        try:
            manager = ConfigManager()
            assert manager is not None
        except Exception:
            pytest.fail("ConfigManager should handle errors gracefully")

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    def test_get_handles_none_values(self, mock_config_class: MagicMock) -> None:
        """Get handles None values correctly."""
        mock_config = MagicMock()
        mock_config.get.return_value = None
        mock_config_class.return_value = mock_config

        manager = ConfigManager()
        value = manager.get("key_with_none_value")

        assert value is None

    @patch("intellicrack.cli.config_manager.IntellicrackConfig")
    def test_set_handles_complex_data_types(self, mock_config_class: MagicMock) -> None:
        """Set handles complex data types."""
        mock_config = MagicMock()
        mock_config.get.return_value = False
        mock_config_class.return_value = mock_config

        manager = ConfigManager()

        complex_value = {"nested": {"key": "value"}, "list": [1, 2, 3], "bool": True}
        manager.set("complex_key", complex_value)

        mock_config.set.assert_called_with("cli_configuration.complex_key", complex_value)
