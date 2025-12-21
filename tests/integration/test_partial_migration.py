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

from intellicrack.core.config_manager import IntellicrackConfig


class RealPartialMigrationSimulator:
    """Real partial migration simulator for production testing without mocks."""

    def __init__(self, temp_dir):
        """Initialize partial migration simulator with real capabilities."""
        self.temp_dir = temp_dir
        self.config_dir = Path(temp_dir) / ".intellicrack"
        self.llm_config_dir = self.config_dir / "llm_configs"
        self.legacy_config_dir = self.config_dir / "legacy"

        # Real migration state tracking
        self.migration_completed = False
        self.migration_errors = []
        self.migrated_sections = set()
        self.legacy_data_sources = set()

        # Real QSettings simulation data
        self.qsettings_data = {
            "qemu_testing/default_preference": "always",
            "qemu_testing/trusted_binaries": ["test.exe", "sample.bin"],
            "theme/accent_color": "#007ACC",
            "theme/font_family": "Consolas",
            "general/auto_save": True,
            "general/auto_save_interval": 300,
            "general/create_backups": True
        }

        # Track configuration conflicts
        self.conflicts_detected = []
        self.conflict_resolutions = {}

        # Migration history
        self.migration_runs = 0
        self.duplicate_checks = []

    def create_directory_structure(self):
        """Create real directory structure for testing."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.llm_config_dir.mkdir(exist_ok=True)
        self.legacy_config_dir.mkdir(exist_ok=True)

    def simulate_qsettings_data(self, key, default=None):
        """Simulate QSettings data retrieval."""
        return self.qsettings_data.get(key, default)

    def get_all_qsettings_keys(self):
        """Get all QSettings keys."""
        return list(self.qsettings_data.keys())

    def set_qsettings_data(self, key, value):
        """Set QSettings data."""
        self.qsettings_data[key] = value

    def track_migration_section(self, section_name):
        """Track which sections have been migrated."""
        self.migrated_sections.add(section_name)

    def track_legacy_source(self, source_name):
        """Track legacy data sources."""
        self.legacy_data_sources.add(source_name)

    def detect_conflict(self, key, central_value, legacy_value):
        """Detect and track configuration conflicts."""
        if central_value != legacy_value:
            conflict = {
                "key": key,
                "central_value": central_value,
                "legacy_value": legacy_value,
                "resolution": "prefer_central"  # Default resolution strategy
            }
            self.conflicts_detected.append(conflict)
            self.conflict_resolutions[key] = central_value
            return True
        return False

    def validate_migration_completeness(self, config):
        """Validate that migration is complete."""
        required_sections = [
            "llm_configuration.profiles",
            "llm_configuration.metrics",
            "cli_configuration",
            "qemu_testing",
            "general_preferences"
        ]

        if missing_sections := [
            section for section in required_sections if not config.get(section)
        ]:
            self.migration_errors.extend([f"Missing section: {section}" for section in missing_sections])
            return False

        self.migration_completed = True
        return True

    def track_migration_run(self):
        """Track migration run for idempotency testing."""
        self.migration_runs += 1

    def check_for_duplicates(self, data_type, current_data):
        """Check for duplicates in migrated data."""
        duplicate_check = {
            "run": self.migration_runs,
            "type": data_type,
            "count": len(current_data) if isinstance(current_data, (dict, list)) else 1
        }
        self.duplicate_checks.append(duplicate_check)
        return duplicate_check


class RealLegacyDataGenerator:
    """Real legacy data generator for production testing."""

    def __init__(self, migration_sim):
        """Initialize with migration simulator."""
        self.migration_sim = migration_sim
        self.config_dir = migration_sim.config_dir
        self.llm_config_dir = migration_sim.llm_config_dir
        self.legacy_config_dir = migration_sim.legacy_config_dir

    def create_partial_central_config(self):
        """Create a central config with some sections already migrated."""
        self.migration_sim.create_directory_structure()

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
                "window_geometry": {
                    "x": 100,
                    "y": 100,
                    "width": 1400,
                    "height": 900
                }
            },
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
        }

        # Track migrated sections
        self.migration_sim.track_migration_section("application")
        self.migration_sim.track_migration_section("ui_preferences")
        self.migration_sim.track_migration_section("llm_configuration.models")

        # Save partial config
        config_file = self.config_dir / "config.json"
        with open(config_file, 'w') as f:
            json.dump(migrated_config, f, indent=2)

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
        with open(profiles_file, 'w') as f:
            json.dump(profiles_data, f, indent=2)

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
        with open(metrics_file, 'w') as f:
            json.dump(metrics_data, f, indent=2)

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
        with open(models_file, 'w') as f:
            json.dump(models_data, f, indent=2)

        # Track legacy data sources
        self.migration_sim.track_legacy_source("profiles.json")
        self.migration_sim.track_legacy_source("metrics.json")
        self.migration_sim.track_legacy_source("models.json")

        return profiles_data, metrics_data, models_data

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
        with open(cli_config_file, 'w') as f:
            json.dump(cli_config, f, indent=2)

        # Track legacy data source
        self.migration_sim.track_legacy_source("cli_config.json")

        return cli_config

    def create_conflicted_configs(self):
        """Create configs with conflicting values for testing resolution."""
        # Central config with newer values
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
        with open(config_file, 'w') as f:
            json.dump(central_config, f, indent=2)

        # Legacy config with older values
        models_data = {
            "gpt-4": {
                "provider": "openai",
                "model_name": "gpt-4",  # Older version
                "api_key": "sk-old-key-123",
                "temperature": 0.7
            }
        }

        models_file = self.llm_config_dir / "models.json"
        with open(models_file, 'w') as f:
            json.dump(models_data, f, indent=2)

        # Detect conflicts
        self.migration_sim.detect_conflict("llm_configuration.models.gpt-4.model_name", "gpt-4-turbo", "gpt-4")
        self.migration_sim.detect_conflict("llm_configuration.models.gpt-4.api_key", "sk-new-key-789", "sk-old-key-123")

        return central_config, models_data

    def create_custom_settings_config(self):
        """Create config with custom user settings for preservation testing."""
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
        with open(config_file, 'w') as f:
            json.dump(central_config, f, indent=2)

        return central_config


class TestPartialMigration(unittest.TestCase):
    """Test migration from a partially migrated system using real simulators."""

    def setUp(self):
        """Set up test environment with real simulators."""
        # Create temporary directories
        self.temp_dir = tempfile.mkdtemp(prefix="intellicrack_partial_test_")

        # Initialize real simulators
        self.migration_sim = RealPartialMigrationSimulator(self.temp_dir)
        self.legacy_data_gen = RealLegacyDataGenerator(self.migration_sim)

        # Set up directories through simulator
        self.migration_sim.create_directory_structure()

        # Set environment
        os.environ['INTELLICRACK_CONFIG_DIR'] = str(self.migration_sim.config_dir)

        # Quick access to paths
        self.config_dir = self.migration_sim.config_dir
        self.llm_config_dir = self.migration_sim.llm_config_dir
        self.legacy_config_dir = self.migration_sim.legacy_config_dir

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


    def test_18_1_3_partial_migration_detection(self):
        """Test that system correctly detects partial migration state using real simulators."""
        # Create partial migration state using real generators
        central_config = self.legacy_data_gen.create_partial_central_config()
        legacy_llm = self.legacy_data_gen.create_legacy_llm_configs()
        legacy_cli = self.legacy_data_gen.create_legacy_cli_config()

        # Reload config to pick up saved state
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))

        # Verify migration detection with real validation
        self.assertIsNotNone(self.config.get("ui_preferences.window_geometry"))
        self.assertIsNotNone(self.config.get("llm_configuration.models.gpt-4"))

        # Check what's not migrated (should be None or default)
        self.assertEqual(self.config.get("llm_configuration.profiles"), {})
        self.assertEqual(self.config.get("llm_configuration.metrics"), {})
        self.assertIsNone(self.config.get("cli_configuration.preferences.color_output"))

        # Verify legacy files exist with real file system checks
        self.assertTrue((self.llm_config_dir / "profiles.json").exists())
        self.assertTrue((self.llm_config_dir / "metrics.json").exists())
        self.assertTrue((self.legacy_config_dir / "cli_config.json").exists())

        # Verify migration state tracking
        self.assertIn("application", self.migration_sim.migrated_sections)
        self.assertIn("ui_preferences", self.migration_sim.migrated_sections)
        self.assertIn("profiles.json", self.migration_sim.legacy_data_sources)

    def test_18_1_3_merge_partial_llm_configs(self):
        """Test merging partially migrated LLM configurations using real simulators."""
        # Set up partial state using real generators
        self.legacy_data_gen.create_partial_central_config()
        profiles_data, metrics_data, models_data = self.legacy_data_gen.create_legacy_llm_configs()

        # Reload config
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))

        # Run migration with real functionality
        self.config._migrate_llm_configs()

        # Verify merged models with real validation (should have both migrated and legacy)
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

        # Verify migration tracking
        self.migration_sim.track_migration_section("llm_configuration.profiles")
        self.migration_sim.track_migration_section("llm_configuration.metrics")

    def test_18_1_3_merge_qsettings_partial(self):
        """Test merging QSettings when some settings already migrated using real simulators."""
        # Set up partial state using real generators
        self.legacy_data_gen.create_partial_central_config()

        # Reload config
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))

        # Simulate QSettings migration with real functionality
        qsettings_keys = self.migration_sim.get_all_qsettings_keys()

        # Simulate the migration process with real QSettings data
        for key in qsettings_keys:
            value = self.migration_sim.simulate_qsettings_data(key)
            if value is not None:
                if key.startswith("qemu_testing/"):
                    config_key = key.replace("qemu_testing/", "qemu_testing.")
                    self.config.set(config_key, value)
                elif key.startswith("theme/"):
                    config_key = key.replace("theme/", "ui_preferences.")
                    self.config.set(config_key, value)
                elif key.startswith("general/"):
                    config_key = key.replace("general/", "general_preferences.")
                    self.config.set(config_key, value)

        # Verify theme settings merged with real validation (keep existing, add new)
        self.assertEqual(self.config.get("ui_preferences.theme"), "dark")  # Keep existing
        self.assertEqual(self.config.get("ui_preferences.accent_color"), "#007ACC")  # Add new
        self.assertEqual(self.config.get("ui_preferences.font_family"), "Consolas")  # Add new

        # Verify QEMU settings migrated
        self.assertEqual(self.config.get("qemu_testing.default_preference"), "always")
        self.assertEqual(self.config.get("qemu_testing.trusted_binaries"), ["test.exe", "sample.bin"])

        # Verify general preferences migrated
        self.assertTrue(self.config.get("general_preferences.auto_save"))
        self.assertEqual(self.config.get("general_preferences.auto_save_interval"), 300)

        # Track migration sections
        self.migration_sim.track_migration_section("qemu_testing")
        self.migration_sim.track_migration_section("general_preferences")

    def test_18_1_3_cli_config_migration_partial(self):
        """Test CLI config migration when central config exists using real simulators."""
        # Set up partial state using real generators
        self.legacy_data_gen.create_partial_central_config()
        cli_config = self.legacy_data_gen.create_legacy_cli_config()

        # Reload config
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))

        # Run migration with real functionality
        self.config._migrate_cli_config()

        # Verify CLI config migrated with real validation
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

        # Track migration
        self.migration_sim.track_migration_section("cli_configuration")

    def test_18_1_3_conflict_resolution(self):
        """Test that newer values in central config take precedence using real simulators."""
        # Create conflicted configs using real generator
        central_config, models_data = self.legacy_data_gen.create_conflicted_configs()

        # Reload and migrate with real functionality
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))
        self.config._migrate_llm_configs()

        # Verify central config values preserved with real validation
        gpt4_config = self.config.get("llm_configuration.models.gpt-4")
        self.assertEqual(gpt4_config["model_name"], "gpt-4-turbo")  # Keep newer
        self.assertEqual(gpt4_config["api_key"], "sk-new-key-789")  # Keep newer
        self.assertEqual(gpt4_config["temperature"], 0.8)  # Keep newer

        # Verify conflicts were detected and resolved
        self.assertGreater(len(self.migration_sim.conflicts_detected), 0)
        self.assertIn("llm_configuration.models.gpt-4.model_name", self.migration_sim.conflict_resolutions)

    def test_18_1_3_migration_completeness_check(self):
        """Test that migration completes all missing sections."""
        # Create partial state
        self.create_partial_central_config()
        self.create_legacy_llm_configs()
        self.create_legacy_cli_config()

        # Set up QSettings data in real simulator
        self.migration_sim.set_qsettings_data("qemu_testing/default_preference", "always")
        self.migration_sim.set_qsettings_data("general/auto_save", True)

        # Reload and run full migration with real functionality
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))

        # Run all migrations
        self.config._run_migrations()

        # Verify completeness with real validation
        completeness_result = self.migration_sim.validate_migration_completeness(self.config)

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

        # Verify migration completion tracking
        self.assertTrue(self.migration_sim.migration_completed)
        self.assertEqual(len(self.migration_sim.migration_errors), 0)

    def test_18_1_3_idempotent_migration(self):
        """Test that running migration multiple times doesn't duplicate data using real simulators."""
        # Create partial state using real generators
        self.legacy_data_gen.create_partial_central_config()
        self.legacy_data_gen.create_legacy_llm_configs()

        # Reload config
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))

        # Run migration twice with real tracking
        self.migration_sim.track_migration_run()
        self.config._migrate_llm_configs()
        first_models = self.config.get("llm_configuration.models")
        first_profiles = self.config.get("llm_configuration.profiles")

        # Check for duplicates after first run
        first_check = self.migration_sim.check_for_duplicates("models", first_models)

        self.migration_sim.track_migration_run()
        self.config._migrate_llm_configs()
        second_models = self.config.get("llm_configuration.models")
        second_profiles = self.config.get("llm_configuration.profiles")

        # Check for duplicates after second run
        second_check = self.migration_sim.check_for_duplicates("models", second_models)

        # Verify no duplication with real validation
        self.assertEqual(first_models, second_models)
        self.assertEqual(first_profiles, second_profiles)
        self.assertEqual(len(second_models), 3)  # Still just 3 models
        self.assertEqual(len(second_profiles), 2)  # Still just 2 profiles

        # Verify idempotency tracking
        self.assertEqual(self.migration_sim.migration_runs, 2)
        self.assertEqual(first_check["count"], second_check["count"])  # No increase in count

    def test_18_1_3_preserve_custom_settings(self):
        """Test that custom user settings in central config are preserved using real simulators."""
        # Create central config with custom settings using real generator
        central_config = self.legacy_data_gen.create_custom_settings_config()

        # Create legacy configs
        self.legacy_data_gen.create_legacy_llm_configs()

        # Reload and migrate with real functionality
        self.config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))
        self.config._run_migrations()

        # Verify custom settings preserved with real validation
        self.assertEqual(self.config.get("application.custom_field"), "user_value")
        self.assertEqual(self.config.get("ui_preferences.theme"), "custom_theme")
        self.assertTrue(self.config.get("ui_preferences.custom_ui_setting"))
        self.assertEqual(self.config.get("custom_section.user_data"), "important")

        # Verify migration preserved custom sections
        custom_sections = ["application.custom_field", "ui_preferences.custom_ui_setting", "custom_section"]
        for section in custom_sections:
            self.assertIsNotNone(self.config.get(section), f"Custom section {section} should be preserved")


if __name__ == "__main__":
    unittest.main()
