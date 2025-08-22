"""
Test migration from partially migrated system.

Tests scenarios where some configuration has been migrated to central config
while legacy configuration still exists in various places.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from PyQt6.QtCore import QSettings

from intellicrack.core.config_manager import IntellicrackConfig


class TestPartialMigration(unittest.TestCase):
    """Test migration from a partially migrated system."""

    def setUp(self):
        """Set up test environment."""
        # Create temporary directories
        self.temp_dir = tempfile.mkdtemp(prefix="intellicrack_partial_test_")
        self.config_dir = Path(self.temp_dir) / ".intellicrack"
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        self.llm_config_dir = self.config_dir / "llm_configs"
        self.llm_config_dir.mkdir(exist_ok=True)

        self.legacy_config_dir = self.config_dir / "legacy"
        self.legacy_config_dir.mkdir(exist_ok=True)

        # Mock environment
        os.environ['INTELLICRACK_CONFIG_DIR'] = str(self.config_dir)

        # Initialize config manager with temporary directory
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))

    def tearDown(self):
        """Clean up test environment."""
        # Remove temporary directory
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)

        # Clean up environment
        if 'INTELLICRACK_CONFIG_DIR' in os.environ:
            del os.environ['INTELLICRACK_CONFIG_DIR']

    def create_partial_central_config(self):
        """Create a central config with some sections already migrated."""
        # Some sections already migrated
        migrated_config = {
            "version": "1.2.0",
            "application": {
                "name": "Intellicrack",
                "version": "3.0.0",
                "environment": "production"
            },
            "ui_preferences": {
                "theme": "dark",
                "font_size": 12,
                "tooltips_enabled": True,
                # Window geometry migrated
                "window_geometry": {
                    "x": 100,
                    "y": 100,
                    "width": 1400,
                    "height": 900
                }
            },
            # LLM configuration partially migrated (only models, no profiles/metrics)
            "llm_configuration": {
                "models": {
                    "gpt-4": {
                        "provider": "openai",
                        "model_name": "gpt-4",
                        "api_key": "sk-migrated-key-123"
                    }
                },
                "profiles": {},  # Empty - not migrated yet
                "metrics": {}    # Empty - not migrated yet
            }
            # CLI configuration NOT migrated yet
            # General preferences NOT migrated yet
            # QEMU testing NOT migrated yet
        }

        # Save partial config
        config_file = self.config_dir / "config.json"
        config_file.write_text(json.dumps(migrated_config, indent=2))
        return migrated_config

    def create_legacy_llm_configs(self):
        """Create legacy LLM configs that haven't been migrated."""
        # Legacy profiles.json (not migrated)
        profiles_data = {
            "fast": {
                "name": "Fast Generation",
                "settings": {
                    "temperature": 0.9,
                    "max_tokens": 1024
                }
            },
            "balanced": {
                "name": "Balanced",
                "settings": {
                    "temperature": 0.7,
                    "max_tokens": 2048
                }
            }
        }

        profiles_file = self.llm_config_dir / "profiles.json"
        profiles_file.write_text(json.dumps(profiles_data, indent=2))

        # Legacy metrics.json (not migrated)
        metrics_data = {
            "gpt-4": {
                "total_uses": 100,
                "total_tokens": 50000,
                "avg_tokens_per_use": 500
            },
            "claude-2": {
                "total_uses": 50,
                "total_tokens": 25000,
                "avg_tokens_per_use": 500
            }
        }

        metrics_file = self.llm_config_dir / "metrics.json"
        metrics_file.write_text(json.dumps(metrics_data, indent=2))

        # Additional model in models.json (not in central config)
        models_data = {
            "claude-2": {
                "provider": "anthropic",
                "model_name": "claude-2",
                "api_key": "sk-ant-legacy-key-456"
            },
            "local-llama": {
                "provider": "gguf",
                "model_name": "llama-2-7b",
                "model_path": "/models/llama-2-7b.gguf"
            }
        }

        models_file = self.llm_config_dir / "models.json"
        models_file.write_text(json.dumps(models_data, indent=2))

        return profiles_data, metrics_data, models_data

    def create_legacy_qsettings(self):
        """Create legacy QSettings that haven't been migrated."""
        settings = QSettings("Intellicrack", "TestPartialMigration")

        # QEMU testing preferences (not migrated)
        settings.setValue("qemu_testing/default_preference", "always")
        settings.setValue("qemu_testing/trusted_binaries", ["test.exe", "sample.bin"])

        # Theme preferences (partially migrated - only theme, not other settings)
        settings.setValue("theme/accent_color", "#007ACC")
        settings.setValue("theme/font_family", "Consolas")

        # General preferences (not migrated)
        settings.setValue("general/auto_save", True)
        settings.setValue("general/auto_save_interval", 300)
        settings.setValue("general/create_backups", True)

        settings.sync()
        return settings

    def create_legacy_cli_config(self):
        """Create legacy CLI configuration file."""
        cli_config = {
            "preferences": {
                "color_output": True,
                "verbose_mode": False,
                "progress_bars": True
            },
            "profiles": {
                "default": {
                    "output_format": "json",
                    "log_level": "INFO"
                },
                "debug": {
                    "output_format": "verbose",
                    "log_level": "DEBUG"
                }
            },
            "aliases": {
                "ll": "list --long",
                "analyze-quick": "analyze --fast"
            }
        }

        cli_config_file = self.legacy_config_dir / "cli_config.json"
        cli_config_file.write_text(json.dumps(cli_config, indent=2))
        return cli_config

    def test_18_1_3_partial_migration_detection(self):
        """Test that system correctly detects partial migration state."""
        # Create partial migration state
        central_config = self.create_partial_central_config()
        legacy_llm = self.create_legacy_llm_configs()
        legacy_cli = self.create_legacy_cli_config()

        # Reload config to pick up saved state
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))

        # Check what's migrated
        self.assertIsNotNone(self.config.get("ui_preferences.window_geometry"))
        self.assertIsNotNone(self.config.get("llm_configuration.models.gpt-4"))

        # Check what's not migrated (should be None or default)
        self.assertEqual(self.config.get("llm_configuration.profiles"), {})
        self.assertEqual(self.config.get("llm_configuration.metrics"), {})
        self.assertIsNone(self.config.get("cli_configuration.preferences.color_output"))

        # Check legacy files exist
        self.assertTrue((self.llm_config_dir / "profiles.json").exists())
        self.assertTrue((self.llm_config_dir / "metrics.json").exists())
        self.assertTrue((self.legacy_config_dir / "cli_config.json").exists())

    def test_18_1_3_merge_partial_llm_configs(self):
        """Test merging partially migrated LLM configurations."""
        # Set up partial state
        self.create_partial_central_config()
        profiles_data, metrics_data, models_data = self.create_legacy_llm_configs()

        # Reload config
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))

        # Run migration
        self.config._migrate_llm_configs()

        # Verify merged models (should have both migrated and legacy)
        gpt4_config = self.config.get("llm_configuration.models.gpt-4")
        self.assertIsNotNone(gpt4_config)
        self.assertEqual(gpt4_config["api_key"], "sk-migrated-key-123")  # Keep migrated

        claude2_config = self.config.get("llm_configuration.models.claude-2")
        self.assertIsNotNone(claude2_config)
        self.assertEqual(claude2_config["api_key"], "sk-ant-legacy-key-456")  # Add legacy

        llama_config = self.config.get("llm_configuration.models.local-llama")
        self.assertIsNotNone(llama_config)
        self.assertEqual(llama_config["model_path"], "/models/llama-2-7b.gguf")

        # Verify profiles migrated
        fast_profile = self.config.get("llm_configuration.profiles.fast")
        self.assertIsNotNone(fast_profile)
        self.assertEqual(fast_profile["settings"]["temperature"], 0.9)

        # Verify metrics migrated
        metrics = self.config.get("llm_configuration.metrics")
        self.assertIsNotNone(metrics)
        self.assertIn("gpt-4", metrics)
        self.assertIn("claude-2", metrics)

    @patch('PyQt6.QtCore.QSettings')
    def test_18_1_3_merge_qsettings_partial(self, mock_qsettings_class):
        """Test merging QSettings when some settings already migrated."""
        # Set up partial state
        self.create_partial_central_config()

        # Mock QSettings
        mock_settings = MagicMock()
        mock_qsettings_class.return_value = mock_settings

        # Configure mock to return legacy values
        mock_settings.value.side_effect = lambda key, default=None: {
            "qemu_testing/default_preference": "always",
            "qemu_testing/trusted_binaries": ["test.exe", "sample.bin"],
            "theme/accent_color": "#007ACC",
            "theme/font_family": "Consolas",
            "general/auto_save": True,
            "general/auto_save_interval": 300,
            "general/create_backups": True
        }.get(key, default)

        # Reload config
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))

        # Run migration
        self.config._migrate_qsettings()

        # Verify theme settings merged (keep existing, add new)
        self.assertEqual(self.config.get("ui_preferences.theme"), "dark")  # Keep existing
        self.assertEqual(self.config.get("ui_preferences.accent_color"), "#007ACC")  # Add new
        self.assertEqual(self.config.get("ui_preferences.font_family"), "Consolas")  # Add new

        # Verify QEMU settings migrated
        self.assertEqual(self.config.get("qemu_testing.default_preference"), "always")
        self.assertEqual(self.config.get("qemu_testing.trusted_binaries"), ["test.exe", "sample.bin"])

        # Verify general preferences migrated
        self.assertTrue(self.config.get("general_preferences.auto_save"))
        self.assertEqual(self.config.get("general_preferences.auto_save_interval"), 300)

    def test_18_1_3_cli_config_migration_partial(self):
        """Test CLI config migration when central config exists."""
        # Set up partial state
        self.create_partial_central_config()
        cli_config = self.create_legacy_cli_config()

        # Reload config
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))

        # Run migration
        self.config._migrate_cli_config()

        # Verify CLI config migrated
        cli_prefs = self.config.get("cli_configuration.preferences")
        self.assertIsNotNone(cli_prefs)
        self.assertTrue(cli_prefs["color_output"])
        self.assertFalse(cli_prefs["verbose_mode"])

        # Verify profiles migrated
        default_profile = self.config.get("cli_configuration.profiles.default")
        self.assertIsNotNone(default_profile)
        self.assertEqual(default_profile["output_format"], "json")

        # Verify aliases migrated
        aliases = self.config.get("cli_configuration.aliases")
        self.assertIsNotNone(aliases)
        self.assertEqual(aliases["ll"], "list --long")

    def test_18_1_3_conflict_resolution(self):
        """Test that newer values in central config take precedence."""
        # Create central config with a model
        central_config = {
            "version": "1.2.0",
            "llm_configuration": {
                "models": {
                    "gpt-4": {
                        "provider": "openai",
                        "model_name": "gpt-4-turbo",  # Newer version
                        "api_key": "sk-new-key-789",
                        "temperature": 0.8
                    }
                }
            }
        }

        config_file = self.config_dir / "config.json"
        config_file.write_text(json.dumps(central_config, indent=2))

        # Create legacy config with same model but older values
        models_data = {
            "gpt-4": {
                "provider": "openai",
                "model_name": "gpt-4",  # Older version
                "api_key": "sk-old-key-123",
                "temperature": 0.7
            }
        }

        models_file = self.llm_config_dir / "models.json"
        models_file.write_text(json.dumps(models_data, indent=2))

        # Reload and migrate
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))
        self.config._migrate_llm_configs()

        # Verify central config values preserved
        gpt4_config = self.config.get("llm_configuration.models.gpt-4")
        self.assertEqual(gpt4_config["model_name"], "gpt-4-turbo")  # Keep newer
        self.assertEqual(gpt4_config["api_key"], "sk-new-key-789")  # Keep newer
        self.assertEqual(gpt4_config["temperature"], 0.8)  # Keep newer

    def test_18_1_3_migration_completeness_check(self):
        """Test that migration completes all missing sections."""
        # Create partial state
        self.create_partial_central_config()
        self.create_legacy_llm_configs()
        self.create_legacy_cli_config()

        # Create mock QSettings
        with patch('PyQt6.QtCore.QSettings') as mock_qsettings_class:
            mock_settings = MagicMock()
            mock_qsettings_class.return_value = mock_settings

            mock_settings.value.side_effect = lambda key, default=None: {
                "qemu_testing/default_preference": "always",
                "general/auto_save": True
            }.get(key, default)

            # Reload and run full migration
            self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))

            # Run all migrations
            self.config._run_migrations()

            # Verify all sections now exist
            self.assertIsNotNone(self.config.get("llm_configuration.profiles"))
            self.assertIsNotNone(self.config.get("llm_configuration.metrics"))
            self.assertIsNotNone(self.config.get("cli_configuration"))
            self.assertIsNotNone(self.config.get("qemu_testing"))
            self.assertIsNotNone(self.config.get("general_preferences"))

            # Verify no data lost
            self.assertEqual(len(self.config.get("llm_configuration.models", {})), 3)  # gpt-4, claude-2, local-llama
            self.assertEqual(len(self.config.get("llm_configuration.profiles", {})), 2)  # fast, balanced
            self.assertTrue(self.config.get("general_preferences.auto_save"))

    def test_18_1_3_idempotent_migration(self):
        """Test that running migration multiple times doesn't duplicate data."""
        # Create partial state
        self.create_partial_central_config()
        self.create_legacy_llm_configs()

        # Reload config
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))

        # Run migration twice
        self.config._migrate_llm_configs()
        first_models = self.config.get("llm_configuration.models")
        first_profiles = self.config.get("llm_configuration.profiles")

        self.config._migrate_llm_configs()
        second_models = self.config.get("llm_configuration.models")
        second_profiles = self.config.get("llm_configuration.profiles")

        # Verify no duplication
        self.assertEqual(first_models, second_models)
        self.assertEqual(first_profiles, second_profiles)
        self.assertEqual(len(second_models), 3)  # Still just 3 models
        self.assertEqual(len(second_profiles), 2)  # Still just 2 profiles

    def test_18_1_3_preserve_custom_settings(self):
        """Test that custom user settings in central config are preserved."""
        # Create central config with custom settings
        central_config = {
            "version": "1.2.0",
            "application": {
                "name": "Intellicrack",
                "custom_field": "user_value"  # Custom field
            },
            "ui_preferences": {
                "theme": "custom_theme",  # Custom theme
                "custom_ui_setting": True  # Custom setting
            },
            "custom_section": {  # Entirely custom section
                "user_data": "important"
            }
        }

        config_file = self.config_dir / "config.json"
        config_file.write_text(json.dumps(central_config, indent=2))

        # Create legacy configs
        self.create_legacy_llm_configs()

        # Reload and migrate
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))
        self.config._run_migrations()

        # Verify custom settings preserved
        self.assertEqual(self.config.get("application.custom_field"), "user_value")
        self.assertEqual(self.config.get("ui_preferences.theme"), "custom_theme")
        self.assertTrue(self.config.get("ui_preferences.custom_ui_setting"))
        self.assertEqual(self.config.get("custom_section.user_data"), "important")


if __name__ == "__main__":
    unittest.main()
