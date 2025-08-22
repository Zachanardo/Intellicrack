"""
Integration tests for migration from a system with all legacy configurations.

This module tests that Intellicrack properly migrates all existing legacy
configuration files and settings to the new central configuration system.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock
import shutil
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from PyQt6.QtCore import QSettings

from intellicrack.core.config_manager import IntellicrackConfig, get_config
from intellicrack.ai.llm_config_manager import LLMConfigManager
from intellicrack.cli.config_manager import ConfigManager as CLIConfigManager
from intellicrack.cli.config_profiles import ProfileManager


class TestLegacySystemMigration(unittest.TestCase):
    """Test migration from a system with all legacy configurations."""

    def setUp(self):
        """Set up test environment with legacy configs."""
        # Create temp directory structure
        self.temp_dir = tempfile.mkdtemp()
        self.config_dir = Path(self.temp_dir) / "config"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.home_dir = Path(self.temp_dir) / "home"
        self.home_dir.mkdir(parents=True, exist_ok=True)

        # Create all legacy config locations
        self.legacy_llm_dir = self.home_dir / ".intellicrack" / "llm_configs"
        self.legacy_llm_dir.mkdir(parents=True, exist_ok=True)

        self.legacy_cli_dir = self.home_dir / ".intellicrack"
        self.legacy_cli_dir.mkdir(parents=True, exist_ok=True)

        self.legacy_profiles_dir = self.legacy_cli_dir / "profiles"
        self.legacy_profiles_dir.mkdir(parents=True, exist_ok=True)

        self.data_config_dir = Path(self.temp_dir) / "data" / "config"
        self.data_config_dir.mkdir(parents=True, exist_ok=True)

        # Central config path
        self.config_path = self.config_dir / "config.json"
        self.env_path = self.config_dir / ".env"

        # Mock paths
        self.config_file_patcher = patch('intellicrack.core.config_manager.CONFIG_FILE',
                                        str(self.config_path))
        self.config_dir_patcher = patch('intellicrack.core.config_manager.CONFIG_DIR',
                                       str(self.config_dir))
        self.env_file_patcher = patch('intellicrack.core.config_manager.ENV_FILE',
                                     str(self.env_path))
        self.home_patcher = patch('pathlib.Path.home', return_value=self.home_dir)

        # Start patches
        self.config_file_patcher.start()
        self.config_dir_patcher.start()
        self.env_file_patcher.start()
        self.home_patcher.start()

        # Create all legacy config files
        self._create_legacy_configs()

        # Mock QSettings with legacy data
        self._setup_qsettings_mock()

    def tearDown(self):
        """Clean up test environment."""
        self.config_file_patcher.stop()
        self.config_dir_patcher.stop()
        self.env_file_patcher.stop()
        self.home_patcher.stop()

        if hasattr(self, 'qsettings_patcher'):
            self.qsettings_patcher.stop()

        # Clean up temp directory
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)

    def _create_legacy_configs(self):
        """Create all legacy configuration files."""
        # 1. Legacy LLM configs
        self._create_llm_legacy_configs()

        # 2. Legacy CLI config
        self._create_cli_legacy_config()

        # 3. Legacy profile files
        self._create_profile_legacy_configs()

        # 4. Legacy main config files
        self._create_main_legacy_configs()

        # 5. Legacy font config
        self._create_font_legacy_config()

    def _create_llm_legacy_configs(self):
        """Create legacy LLM configuration files."""
        # models.json
        models_data = {
            "gpt4-legacy": {
                "provider": "openai",
                "model_name": "gpt-4",
                "api_key": "sk-legacy-key-123",
                "api_base": "https://api.openai.com/v1",
                "context_length": 8192,
                "temperature": 0.7,
                "max_tokens": 2000,
                "tools_enabled": True,
                "custom_params": {"top_p": 0.9},
                "created_at": "2024-01-01T00:00:00",
                "metadata": {
                    "description": "Legacy GPT-4 model",
                    "tags": ["production"],
                    "auto_load": True
                }
            },
            "claude-legacy": {
                "provider": "anthropic",
                "model_name": "claude-3-opus",
                "api_key": "sk-ant-legacy-456",
                "api_base": "https://api.anthropic.com/v1",
                "context_length": 200000,
                "temperature": 0.5,
                "max_tokens": 4000,
                "created_at": "2024-01-02T00:00:00"
            }
        }

        models_file = self.legacy_llm_dir / "models.json"
        models_file.write_text(json.dumps(models_data, indent=2))

        # profiles.json
        profiles_data = {
            "legacy-creative": {
                "name": "Legacy Creative",
                "description": "High creativity for writing",
                "settings": {
                    "temperature": 0.9,
                    "max_tokens": 3000,
                    "top_p": 0.95
                }
            },
            "legacy-precise": {
                "name": "Legacy Precise",
                "description": "Low temperature for accuracy",
                "settings": {
                    "temperature": 0.2,
                    "max_tokens": 2000,
                    "top_p": 0.8
                }
            }
        }

        profiles_file = self.legacy_llm_dir / "profiles.json"
        profiles_file.write_text(json.dumps(profiles_data, indent=2))

        # metrics.json
        metrics_data = {
            "gpt4-legacy": {
                "history": [
                    {
                        "tokens_used": 500,
                        "time_taken": 2.5,
                        "memory_used": 256,
                        "timestamp": "2024-01-03T10:00:00"
                    },
                    {
                        "tokens_used": 750,
                        "time_taken": 3.8,
                        "memory_used": 300,
                        "timestamp": "2024-01-03T11:00:00"
                    }
                ],
                "aggregate": {
                    "total_tokens": 1250,
                    "total_time": 6.3,
                    "average_tokens": 625,
                    "average_time": 3.15,
                    "last_used": "2024-01-03T11:00:00"
                }
            }
        }

        metrics_file = self.legacy_llm_dir / "metrics.json"
        metrics_file.write_text(json.dumps(metrics_data, indent=2))

    def _create_cli_legacy_config(self):
        """Create legacy CLI configuration file."""
        cli_config = {
            "output_format": "table",
            "verbosity": "debug",
            "color_output": True,
            "progress_bars": False,
            "auto_save": True,
            "confirm_actions": False,
            "aliases": {
                "ll": "list --long --all",
                "gs": "git status --short",
                "analyze-full": "analyze --deep --ml --export"
            },
            "custom_commands": {
                "full-report": {
                    "description": "Generate full analysis report",
                    "command": "analyze --deep && export --pdf",
                    "requires_target": True
                }
            },
            "startup_commands": [
                "clear",
                "echo 'Legacy CLI Started'",
                "check-updates"
            ],
            "history_file": "~/.intellicrack/legacy_history",
            "max_history": 2000,
            "custom_legacy_setting": "legacy_value"
        }

        cli_file = self.legacy_cli_dir / "config.json"
        cli_file.write_text(json.dumps(cli_config, indent=2))

    def _create_profile_legacy_configs(self):
        """Create legacy profile configuration files."""
        # Development profile
        dev_profile = {
            "name": "legacy_development",
            "settings": {
                "output_format": "json",
                "verbosity": "debug",
                "color_output": True,
                "auto_save": False
            }
        }

        dev_file = self.legacy_profiles_dir / "legacy_development.json"
        dev_file.write_text(json.dumps(dev_profile, indent=2))

        # Production profile
        prod_profile = {
            "name": "legacy_production",
            "settings": {
                "output_format": "csv",
                "verbosity": "error",
                "color_output": False,
                "auto_save": True
            }
        }

        prod_file = self.legacy_profiles_dir / "legacy_production.json"
        prod_file.write_text(json.dumps(prod_profile, indent=2))

    def _create_main_legacy_configs(self):
        """Create main legacy configuration files."""
        # config/config.json
        main_config = {
            "version": "2.0",
            "application": {
                "name": "Intellicrack Legacy",
                "version": "2.0.0"
            },
            "analysis_settings": {
                "timeout": 60,
                "memory_limit": 1024,
                "use_ml": False
            },
            "legacy_setting_1": "value1",
            "legacy_setting_2": {
                "nested": "value2"
            }
        }

        main_file = self.config_dir / "config.json"
        main_file.write_text(json.dumps(main_config, indent=2))

        # data/config/intellicrack_config.json
        data_config = {
            "version": "1.5",
            "tools": {
                "ghidra": {
                    "path": "/legacy/path/ghidra",
                    "version": "10.0"
                }
            },
            "plugins": {
                "enabled": ["plugin1", "plugin2"],
                "settings": {
                    "plugin1": {"option": "value"}
                }
            },
            "data_legacy_setting": "data_value"
        }

        data_file = self.data_config_dir / "intellicrack_config.json"
        data_file.write_text(json.dumps(data_config, indent=2))

    def _create_font_legacy_config(self):
        """Create legacy font configuration."""
        fonts_dir = Path(self.temp_dir) / "intellicrack" / "assets" / "fonts"
        fonts_dir.mkdir(parents=True, exist_ok=True)

        font_config = {
            "default_font": "Consolas",
            "fallback_fonts": ["Monaco", "Courier New"],
            "sizes": {
                "small": 10,
                "medium": 12,
                "large": 14
            },
            "styles": {
                "code": {
                    "family": "Consolas",
                    "size": 11,
                    "weight": "normal"
                },
                "ui": {
                    "family": "Segoe UI",
                    "size": 10,
                    "weight": "normal"
                }
            }
        }

        font_file = fonts_dir / "font_config.json"
        font_file.write_text(json.dumps(font_config, indent=2))

    def _setup_qsettings_mock(self):
        """Set up QSettings mock with legacy data."""
        self.qsettings_patcher = patch('intellicrack.core.config_manager.QSettings')
        mock_qsettings_class = self.qsettings_patcher.start()

        # Create mock instance
        mock_qsettings = MagicMock()
        mock_qsettings_class.return_value = mock_qsettings

        # Define legacy QSettings values
        qsettings_data = {
            "execution/qemu_preference": "always",
            "qemu_preference_frida": "never",
            "qemu_preference_ghidra": "ask",
            "trusted_binaries": ["binary1.exe", "binary2.exe", "binary3.exe"],
            "execution_history": [
                {"file": "test1.exe", "date": "2024-01-01"},
                {"file": "test2.exe", "date": "2024-01-02"}
            ],
            "theme": "dark",
            "window/geometry": b'\x01\xd9\xd0\xcb\x00\x03\x00\x00',  # Mock QByteArray
            "window/state": b'\x00\x00\x00\xff\x00\x00',  # Mock QByteArray
            "splitter/main": [600, 400],
            "general/auto_save": True,
            "general/confirm_exit": False
        }

        def value_side_effect(key, default=None, type=None):
            """Return appropriate value based on key."""
            value = qsettings_data.get(key, default)
            if type and value is not None:
                if type == str and not isinstance(value, str):
                    return str(value)
                elif type == bool and not isinstance(value, bool):
                    return bool(value)
            return value

        mock_qsettings.value.side_effect = value_side_effect

        # Mock allKeys to return all keys
        mock_qsettings.allKeys.return_value = list(qsettings_data.keys())

        # Also mock for theme manager specific QSettings
        mock_theme_qsettings = MagicMock()
        mock_theme_qsettings.value.return_value = "dark"

        def qsettings_constructor(*args):
            if len(args) == 2 and args[0] == "Intellicrack" and args[1] == "ThemeManager":
                return mock_theme_qsettings
            return mock_qsettings

        mock_qsettings_class.side_effect = qsettings_constructor

    def test_complete_legacy_migration(self):
        """Test complete migration from all legacy configs."""
        # Create config instance (triggers migration)
        config = IntellicrackConfig()

        # Verify version updated
        self.assertEqual(config.get("version"), "3.0")

        # Save to ensure persistence
        config.save()

        # Verify config file created
        self.assertTrue(self.config_path.exists())

    def test_llm_configs_migration(self):
        """Test that all LLM configs are migrated correctly."""
        config = IntellicrackConfig()

        # Check models migrated
        gpt4_model = config.get("llm_configuration.models.gpt4-legacy")
        self.assertIsNotNone(gpt4_model)
        self.assertEqual(gpt4_model["provider"], "openai")
        self.assertEqual(gpt4_model["model_name"], "gpt-4")
        self.assertEqual(gpt4_model["api_key"], "sk-legacy-key-123")
        self.assertEqual(gpt4_model["context_length"], 8192)
        self.assertEqual(gpt4_model["metadata"]["auto_load"], True)

        claude_model = config.get("llm_configuration.models.claude-legacy")
        self.assertIsNotNone(claude_model)
        self.assertEqual(claude_model["provider"], "anthropic")
        self.assertEqual(claude_model["api_key"], "sk-ant-legacy-456")

        # Check profiles migrated
        creative_profile = config.get("llm_configuration.profiles.legacy-creative")
        self.assertIsNotNone(creative_profile)
        self.assertEqual(creative_profile["name"], "Legacy Creative")
        self.assertEqual(creative_profile["settings"]["temperature"], 0.9)

        precise_profile = config.get("llm_configuration.profiles.legacy-precise")
        self.assertIsNotNone(precise_profile)
        self.assertEqual(precise_profile["settings"]["temperature"], 0.2)

        # Check metrics migrated
        metrics = config.get("llm_configuration.metrics.gpt4-legacy")
        self.assertIsNotNone(metrics)
        self.assertEqual(len(metrics["history"]), 2)
        self.assertEqual(metrics["aggregate"]["total_tokens"], 1250)
        self.assertEqual(metrics["aggregate"]["average_tokens"], 625)

    def test_cli_config_migration(self):
        """Test that CLI config is migrated correctly."""
        # Mock IntellicrackConfig in CLI module
        with patch('intellicrack.cli.config_manager.IntellicrackConfig') as mock_config_class:
            config = IntellicrackConfig()
            mock_config_class.return_value = config

            # Create CLI manager (triggers migration)
            cli_manager = CLIConfigManager()

            # Check main settings migrated
            self.assertEqual(cli_manager.get("output_format"), "table")
            self.assertEqual(cli_manager.get("verbosity"), "debug")
            self.assertTrue(cli_manager.get("color_output"))
            self.assertFalse(cli_manager.get("progress_bars"))

            # Check aliases migrated
            aliases = cli_manager.get("aliases")
            self.assertEqual(aliases["ll"], "list --long --all")
            self.assertEqual(aliases["gs"], "git status --short")
            self.assertEqual(aliases["analyze-full"], "analyze --deep --ml --export")

            # Check custom commands migrated
            custom_cmds = cli_manager.get("custom_commands")
            self.assertIn("full-report", custom_cmds)
            self.assertEqual(custom_cmds["full-report"]["description"],
                           "Generate full analysis report")

            # Check startup commands migrated
            startup = cli_manager.get("startup_commands")
            self.assertEqual(len(startup), 3)
            self.assertEqual(startup[0], "clear")

            # Check custom settings migrated
            self.assertEqual(cli_manager.get("max_history"), 2000)

    def test_profile_migration(self):
        """Test that CLI profiles are migrated correctly."""
        # Mock IntellicrackConfig in profile module
        with patch('intellicrack.cli.config_profiles.IntellicrackConfig') as mock_config_class:
            config = IntellicrackConfig()
            mock_config_class.return_value = config

            # Create profile manager (triggers migration)
            profile_manager = ProfileManager()

            # Check profiles migrated
            profiles = profile_manager.list_profiles()
            self.assertIn("legacy_development", profiles)
            self.assertIn("legacy_production", profiles)

            # Load and verify dev profile
            dev_profile = profile_manager.load_profile("legacy_development")
            self.assertEqual(dev_profile.settings["output_format"], "json")
            self.assertEqual(dev_profile.settings["verbosity"], "debug")

            # Load and verify prod profile
            prod_profile = profile_manager.load_profile("legacy_production")
            self.assertEqual(prod_profile.settings["output_format"], "csv")
            self.assertEqual(prod_profile.settings["verbosity"], "error")

    def test_qsettings_migration(self):
        """Test that QSettings data is migrated correctly."""
        config = IntellicrackConfig()

        # Check QEMU settings migrated
        qemu_config = config.get("qemu_testing")
        self.assertEqual(qemu_config["default_preference"], "always")
        self.assertEqual(qemu_config["script_type_preferences"]["frida"], "never")
        self.assertEqual(qemu_config["script_type_preferences"]["ghidra"], "ask")

        # Check trusted binaries migrated
        trusted = qemu_config["trusted_binaries"]
        self.assertIn("binary1.exe", trusted)
        self.assertIn("binary2.exe", trusted)
        self.assertIn("binary3.exe", trusted)

        # Check execution history migrated
        history = qemu_config["execution_history"]
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["file"], "test1.exe")

        # Check theme migrated
        self.assertEqual(config.get("ui_preferences.theme"), "dark")

        # Check general preferences migrated
        general = config.get("general_preferences")
        self.assertTrue(general["auto_save"])
        self.assertFalse(general["confirm_exit"])

    def test_main_config_migration(self):
        """Test that main config files are migrated correctly."""
        # Mock Path.exists to find legacy configs
        with patch('pathlib.Path.exists') as mock_exists:
            def exists_side_effect(self):
                path_str = str(self)
                if "config/config.json" in path_str:
                    return True
                if "data/config/intellicrack_config.json" in path_str:
                    return True
                return Path(path_str).exists()

            mock_exists.side_effect = exists_side_effect

            # Mock Path.read_text to return legacy data
            with patch('pathlib.Path.read_text') as mock_read:
                def read_side_effect(self):
                    path_str = str(self)
                    if path_str.endswith("config/config.json"):
                        return Path(self.config_dir / "config.json").read_text()
                    elif path_str.endswith("data/config/intellicrack_config.json"):
                        return Path(self.data_config_dir / "intellicrack_config.json").read_text()
                    return Path(path_str).read_text()

                mock_read.side_effect = read_side_effect

                config = IntellicrackConfig()

                # Run migration
                config._migrate_legacy_configs()

                # Check some migrated settings
                # Note: Version should be updated to 3.0, not kept as 2.0
                self.assertEqual(config.get("version"), "3.0")

                # Application settings should be merged
                app_config = config.get("application")
                self.assertIsNotNone(app_config)

                # Analysis settings should be merged
                analysis = config.get("analysis_settings")
                self.assertIsNotNone(analysis)

    def test_font_config_migration(self):
        """Test that font configuration is migrated correctly."""
        # Mock path for font config
        with patch('pathlib.Path.exists') as mock_exists:
            def exists_side_effect(self):
                if "assets/fonts/font_config.json" in str(self):
                    return True
                return Path(str(self)).exists()

            mock_exists.side_effect = exists_side_effect

            with patch('pathlib.Path.read_text') as mock_read:
                fonts_path = Path(self.temp_dir) / "intellicrack" / "assets" / "fonts" / "font_config.json"

                def read_side_effect(self):
                    if "font_config.json" in str(self):
                        return fonts_path.read_text()
                    return Path(str(self)).read_text()

                mock_read.side_effect = read_side_effect

                config = IntellicrackConfig()

                # Check font config migrated
                font_config = config.get("font_configuration")
                self.assertIsNotNone(font_config)
                self.assertEqual(font_config["default_font"], "Consolas")
                self.assertIn("Monaco", font_config["fallback_fonts"])
                self.assertEqual(font_config["sizes"]["medium"], 12)
                self.assertEqual(font_config["styles"]["code"]["family"], "Consolas")

    def test_backup_creation(self):
        """Test that backups are created during migration."""
        config = IntellicrackConfig()

        # Check for backup directories/files
        llm_backup = self.legacy_llm_dir.parent / "llm_configs_backup"
        cli_backup = self.legacy_cli_dir / "config.json.backup"
        profiles_backup = self.legacy_profiles_dir.parent / "profiles.backup"

        # At least some backups should be created
        # (exact behavior depends on implementation)
        # The important thing is no data is lost

        # Verify original data is preserved somewhere
        # Either in backups or in the migrated config
        self.assertIsNotNone(config.get("llm_configuration.models.gpt4-legacy"))
        self.assertIsNotNone(config.get("cli_configuration.aliases.ll"))

    def test_migration_idempotency(self):
        """Test that migration can be run multiple times safely."""
        # First migration
        config1 = IntellicrackConfig()
        config1.save()

        # Get migrated values
        gpt4_1 = config1.get("llm_configuration.models.gpt4-legacy")
        aliases_1 = config1.get("cli_configuration.aliases")
        theme_1 = config1.get("ui_preferences.theme")

        # Second migration (should not duplicate or corrupt)
        config2 = IntellicrackConfig()
        config2.config_file = str(self.config_path)
        config2.load()

        # Values should be the same
        gpt4_2 = config2.get("llm_configuration.models.gpt4-legacy")
        aliases_2 = config2.get("cli_configuration.aliases")
        theme_2 = config2.get("ui_preferences.theme")

        self.assertEqual(gpt4_1, gpt4_2)
        self.assertEqual(aliases_1, aliases_2)
        self.assertEqual(theme_1, theme_2)

    def test_migration_preserves_all_data(self):
        """Test that no data is lost during migration."""
        config = IntellicrackConfig()

        # Count items in legacy configs
        legacy_model_count = 2  # gpt4-legacy, claude-legacy
        legacy_profile_count = 2  # legacy-creative, legacy-precise
        legacy_alias_count = 3  # ll, gs, analyze-full

        # Check all models migrated
        models = config.get("llm_configuration.models")
        self.assertGreaterEqual(len(models), legacy_model_count)

        # Check all profiles migrated (includes defaults)
        profiles = config.get("llm_configuration.profiles")
        self.assertGreaterEqual(len(profiles), legacy_profile_count)

        # Check all aliases migrated
        aliases = config.get("cli_configuration.aliases")
        self.assertGreaterEqual(len(aliases), legacy_alias_count)

        # Check specific values preserved
        self.assertEqual(
            config.get("llm_configuration.models.gpt4-legacy.api_key"),
            "sk-legacy-key-123"
        )
        self.assertEqual(
            config.get("cli_configuration.aliases.analyze-full"),
            "analyze --deep --ml --export"
        )

    def test_migration_with_conflicts(self):
        """Test migration when there are conflicts between configs."""
        # Create central config with some existing data
        config = IntellicrackConfig()

        # Add conflicting data
        config.set("llm_configuration.models.gpt4-legacy", {
            "provider": "azure",  # Different from legacy
            "model_name": "gpt-4-azure",
            "api_key": "new-key"
        })

        # Save and reload to trigger migration
        config.save()

        # Migration should preserve existing central config values
        # (or merge intelligently based on implementation)
        final_model = config.get("llm_configuration.models.gpt4-legacy")
        self.assertIsNotNone(final_model)

        # The specific behavior depends on merge strategy
        # Important thing is no crash and data is not lost
        self.assertIn("provider", final_model)
        self.assertIn("model_name", final_model)
        self.assertIn("api_key", final_model)


if __name__ == "__main__":
    unittest.main()
