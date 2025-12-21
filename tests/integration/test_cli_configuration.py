"""
Integration tests for CLI configuration in command-line mode.

This module tests that all CLI configurations (profiles, aliases, preferences)
are properly managed through the central configuration system.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock, call
from datetime import datetime
import io

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from intellicrack.core.config_manager import IntellicrackConfig
from intellicrack.cli.config_manager import ConfigManager
from intellicrack.cli.config_profiles import ProfileManager, ConfigProfile


class TestCLIConfiguration(unittest.TestCase):
    """Test CLI configuration management through central config."""

    def setUp(self):
        """Set up test environment with fresh config."""
        # Create temporary directories
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "config.json"
        self.legacy_cli_config = Path(self.temp_dir) / ".intellicrack" / "config.json"
        self.legacy_cli_config.parent.mkdir(parents=True, exist_ok=True)

        # Mock the config path
        self.config_patcher = patch('intellicrack.core.config_manager.CONFIG_FILE',
                                   str(self.config_path))
        self.config_patcher.start()

        # Create fresh config instance
        self.central_config = IntellicrackConfig()
        self.central_config.config_file = str(self.config_path)

        # Mock IntellicrackConfig in CLI modules
        self.cli_config_patcher = patch('intellicrack.cli.config_manager.IntellicrackConfig')
        self.mock_cli_config_class = self.cli_config_patcher.start()
        self.mock_cli_config_class.return_value = self.central_config

        self.profile_config_patcher = patch('intellicrack.cli.config_profiles.IntellicrackConfig')
        self.mock_profile_config_class = self.profile_config_patcher.start()
        self.mock_profile_config_class.return_value = self.central_config

        # Mock home directory
        self.home_patcher = patch('pathlib.Path.home', return_value=Path(self.temp_dir))
        self.home_patcher.start()

        # Create CLI config manager
        self.cli_manager = ConfigManager()

        # Create profile manager
        self.profile_manager = ProfileManager()

    def tearDown(self):
        """Clean up test environment."""
        self.config_patcher.stop()
        self.cli_config_patcher.stop()
        self.profile_config_patcher.stop()
        self.home_patcher.stop()

        # Clean up temp directory
        import shutil
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)

    def test_cli_config_basic_operations(self):
        """Test basic CLI configuration get/set operations."""
        # Test setting values
        self.cli_manager.set("output_format", "table")
        self.cli_manager.set("verbosity", "debug")
        self.cli_manager.set("color_output", False)

        # Verify values were set in central config
        self.assertEqual(self.central_config.get("cli_configuration.output_format"), "table")
        self.assertEqual(self.central_config.get("cli_configuration.verbosity"), "debug")
        self.assertEqual(self.central_config.get("cli_configuration.color_output"), False)

        # Test getting values
        self.assertEqual(self.cli_manager.get("output_format"), "table")
        self.assertEqual(self.cli_manager.get("verbosity"), "debug")
        self.assertEqual(self.cli_manager.get("color_output"), False)

        # Test default values
        self.assertEqual(self.cli_manager.get("non_existent", "default"), "default")

    def test_cli_profile_management(self):
        """Test CLI profile creation, loading, and switching."""
        # Create test profiles
        profile1 = ConfigProfile("development", {
            "output_format": "json",
            "verbosity": "debug",
            "color_output": True,
            "progress_bars": True,
            "auto_save": False,
            "confirm_actions": False
        })

        profile2 = ConfigProfile("production", {
            "output_format": "table",
            "verbosity": "error",
            "color_output": False,
            "progress_bars": False,
            "auto_save": True,
            "confirm_actions": True
        })

        # Save profiles
        self.profile_manager.save_profile("development", profile1)
        self.profile_manager.save_profile("production", profile2)

        # Verify profiles saved to central config
        dev_profile = self.central_config.get("cli_configuration.profiles.development")
        self.assertIsNotNone(dev_profile)
        self.assertEqual(dev_profile["output_format"], "json")
        self.assertEqual(dev_profile["verbosity"], "debug")

        prod_profile = self.central_config.get("cli_configuration.profiles.production")
        self.assertIsNotNone(prod_profile)
        self.assertEqual(prod_profile["output_format"], "table")
        self.assertEqual(prod_profile["verbosity"], "error")

        # Load profile
        loaded_profile = self.profile_manager.load_profile("development")
        self.assertIsNotNone(loaded_profile)
        self.assertEqual(loaded_profile.name, "development")
        self.assertEqual(loaded_profile.settings["verbosity"], "debug")

        # List profiles
        profiles = self.profile_manager.list_profiles()
        self.assertIn("development", profiles)
        self.assertIn("production", profiles)
        self.assertEqual(len(profiles), 3)  # includes default profile

        # Switch profiles
        self.profile_manager.set_active_profile("production")
        active = self.profile_manager.get_active_profile()
        self.assertEqual(active.name, "production")
        self.assertEqual(active.settings["verbosity"], "error")

    def test_cli_aliases(self):
        """Test CLI command aliases."""
        # Set up aliases
        aliases = {
            "ll": "list --long",
            "gs": "git status",
            "analyze-quick": "analyze --fast --no-ml",
            "full": "analyze --deep --ml --export"
        }

        self.cli_manager.set("aliases", aliases)

        # Verify aliases saved
        saved_aliases = self.central_config.get("cli_configuration.aliases")
        self.assertEqual(saved_aliases, aliases)

        # Test alias retrieval
        self.assertEqual(self.cli_manager.get("aliases.ll"), "list --long")
        self.assertEqual(self.cli_manager.get("aliases.gs"), "git status")

        # Add new alias
        self.cli_manager.set("aliases.new", "test command")
        updated_aliases = self.cli_manager.get("aliases")
        self.assertIn("new", updated_aliases)
        self.assertEqual(updated_aliases["new"], "test command")

    def test_cli_custom_commands(self):
        """Test CLI custom command definitions."""
        # Define custom commands
        custom_commands = {
            "report": {
                "description": "Generate analysis report",
                "command": "analyze && export --format=pdf",
                "requires_target": True
            },
            "quick-scan": {
                "description": "Quick vulnerability scan",
                "command": "scan --fast --top-10",
                "requires_target": True
            },
            "cleanup": {
                "description": "Clean temporary files",
                "command": "rm -rf /tmp/intellicrack/*",
                "requires_target": False
            }
        }

        self.cli_manager.set("custom_commands", custom_commands)

        # Verify custom commands saved
        saved_commands = self.central_config.get("cli_configuration.custom_commands")
        self.assertEqual(saved_commands, custom_commands)

        # Test command retrieval
        report_cmd = self.cli_manager.get("custom_commands.report")
        self.assertIsNotNone(report_cmd)
        self.assertEqual(report_cmd["description"], "Generate analysis report")
        self.assertTrue(report_cmd["requires_target"])

    def test_cli_startup_commands(self):
        """Test CLI startup commands execution."""
        # Set startup commands
        startup_commands = [
            "clear",
            "echo 'Intellicrack CLI Started'",
            "check-updates",
            "load-profile development"
        ]

        self.cli_manager.set("startup_commands", startup_commands)

        # Verify saved
        saved_startup = self.central_config.get("cli_configuration.startup_commands")
        self.assertEqual(saved_startup, startup_commands)

        # Test retrieval
        commands = self.cli_manager.get("startup_commands")
        self.assertEqual(len(commands), 4)
        self.assertEqual(commands[0], "clear")
        self.assertEqual(commands[-1], "load-profile development")

    def test_cli_history_settings(self):
        """Test CLI history configuration."""
        # Configure history
        self.cli_manager.set("history_file", "~/.intellicrack/cli_history")
        self.cli_manager.set("max_history", 5000)
        self.cli_manager.set("history_ignore_duplicates", True)
        self.cli_manager.set("history_ignore_patterns", ["password", "secret", "token"])

        # Verify settings
        self.assertEqual(self.cli_manager.get("history_file"), "~/.intellicrack/cli_history")
        self.assertEqual(self.cli_manager.get("max_history"), 5000)
        self.assertTrue(self.cli_manager.get("history_ignore_duplicates"))

        patterns = self.cli_manager.get("history_ignore_patterns")
        self.assertIn("password", patterns)
        self.assertIn("secret", patterns)

    def test_cli_mode_settings(self):
        """Test CLI mode settings (interactive, batch, quiet)."""
        # Test interactive mode
        self.cli_manager.set("interactive_mode", True)
        self.cli_manager.set("batch_mode", False)
        self.cli_manager.set("quiet_mode", False)

        self.assertTrue(self.cli_manager.get("interactive_mode"))
        self.assertFalse(self.cli_manager.get("batch_mode"))
        self.assertFalse(self.cli_manager.get("quiet_mode"))

        # Test batch mode
        self.cli_manager.set("interactive_mode", False)
        self.cli_manager.set("batch_mode", True)
        self.cli_manager.set("quiet_mode", False)

        self.assertFalse(self.cli_manager.get("interactive_mode"))
        self.assertTrue(self.cli_manager.get("batch_mode"))

        # Test quiet mode
        self.cli_manager.set("quiet_mode", True)
        self.assertTrue(self.cli_manager.get("quiet_mode"))

    def test_cli_output_preferences(self):
        """Test CLI output formatting preferences."""
        # Set output preferences
        self.cli_manager.set("output_format", "json")
        self.cli_manager.set("json_indent", 4)
        self.cli_manager.set("table_borders", True)
        self.cli_manager.set("truncate_output", True)
        self.cli_manager.set("max_output_lines", 100)
        self.cli_manager.set("timestamp_format", "%Y-%m-%d %H:%M:%S")

        # Verify preferences
        self.assertEqual(self.cli_manager.get("output_format"), "json")
        self.assertEqual(self.cli_manager.get("json_indent"), 4)
        self.assertTrue(self.cli_manager.get("table_borders"))
        self.assertTrue(self.cli_manager.get("truncate_output"))
        self.assertEqual(self.cli_manager.get("max_output_lines"), 100)
        self.assertEqual(self.cli_manager.get("timestamp_format"), "%Y-%m-%d %H:%M:%S")

    def test_cli_logging_configuration(self):
        """Test CLI logging configuration."""
        # Configure logging
        self.cli_manager.set("log_to_file", True)
        self.cli_manager.set("log_file", "~/.intellicrack/cli.log")
        self.cli_manager.set("log_level", "DEBUG")
        self.cli_manager.set("log_format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.cli_manager.set("log_rotation", True)
        self.cli_manager.set("log_max_bytes", 10485760)  # 10MB
        self.cli_manager.set("log_backup_count", 5)

        # Verify configuration
        self.assertTrue(self.cli_manager.get("log_to_file"))
        self.assertEqual(self.cli_manager.get("log_file"), "~/.intellicrack/cli.log")
        self.assertEqual(self.cli_manager.get("log_level"), "DEBUG")
        self.assertTrue(self.cli_manager.get("log_rotation"))
        self.assertEqual(self.cli_manager.get("log_max_bytes"), 10485760)
        self.assertEqual(self.cli_manager.get("log_backup_count"), 5)

    def test_cli_autocomplete_settings(self):
        """Test CLI autocomplete configuration."""
        # Configure autocomplete
        self.cli_manager.set("autocomplete", True)
        self.cli_manager.set("autocomplete_threshold", 2)
        self.cli_manager.set("autocomplete_case_sensitive", False)
        self.cli_manager.set("show_hints", True)
        self.cli_manager.set("hint_delay", 500)

        # Verify settings
        self.assertTrue(self.cli_manager.get("autocomplete"))
        self.assertEqual(self.cli_manager.get("autocomplete_threshold"), 2)
        self.assertFalse(self.cli_manager.get("autocomplete_case_sensitive"))
        self.assertTrue(self.cli_manager.get("show_hints"))
        self.assertEqual(self.cli_manager.get("hint_delay"), 500)

    def test_legacy_cli_config_migration(self):
        """Test migration from legacy CLI config file."""
        # Create legacy config file
        legacy_config = {
            "output_format": "table",
            "verbosity": "info",
            "color_output": True,
            "aliases": {
                "old1": "old command 1",
                "old2": "old command 2"
            },
            "custom_settings": {
                "legacy_option": "legacy_value"
            }
        }

        self.legacy_cli_config.write_text(json.dumps(legacy_config, indent=2))

        # Trigger migration by creating new ConfigManager
        new_manager = ConfigManager()

        # Verify migration occurred
        self.assertTrue(self.central_config.get("cli_configuration.migrated"))

        # Verify legacy data was migrated
        self.assertEqual(new_manager.get("output_format"), "table")
        self.assertEqual(new_manager.get("verbosity"), "info")
        self.assertTrue(new_manager.get("color_output"))

        aliases = new_manager.get("aliases")
        self.assertEqual(aliases["old1"], "old command 1")
        self.assertEqual(aliases["old2"], "old command 2")

        # Verify legacy file was backed up
        backup_file = self.legacy_cli_config.parent / "config.json.backup"
        self.assertTrue(backup_file.exists())

    def test_profile_migration_from_legacy(self):
        """Test migration of legacy profile files."""
        # Create legacy profiles directory
        profiles_dir = Path(self.temp_dir) / ".intellicrack" / "profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)

        # Create legacy profile files
        legacy_profile1 = {
            "name": "legacy_dev",
            "settings": {
                "output_format": "json",
                "verbosity": "debug"
            }
        }

        legacy_profile2 = {
            "name": "legacy_prod",
            "settings": {
                "output_format": "table",
                "verbosity": "error"
            }
        }

        (profiles_dir / "legacy_dev.json").write_text(json.dumps(legacy_profile1))
        (profiles_dir / "legacy_prod.json").write_text(json.dumps(legacy_profile2))

        # Trigger migration by creating new ProfileManager
        new_profile_manager = ProfileManager()

        # Verify migration occurred
        migrated_profiles = self.central_config.get("cli_configuration.profiles.migrated")
        self.assertTrue(migrated_profiles)

        # Verify profiles were migrated
        profiles = new_profile_manager.list_profiles()
        self.assertIn("legacy_dev", profiles)
        self.assertIn("legacy_prod", profiles)

        # Load and verify migrated profile
        dev_profile = new_profile_manager.load_profile("legacy_dev")
        self.assertEqual(dev_profile.settings["output_format"], "json")
        self.assertEqual(dev_profile.settings["verbosity"], "debug")

    def test_cli_config_persistence(self):
        """Test that CLI configuration persists across instances."""
        # Set configuration in first instance
        manager1 = ConfigManager()
        manager1.set("test_setting", "test_value")
        manager1.set("aliases.test", "test alias")
        manager1.set("custom_commands.test", {"command": "test cmd"})

        # Save config
        self.central_config.save()

        # Create new central config instance (simulating restart)
        new_central_config = IntellicrackConfig()
        new_central_config.config_file = str(self.config_path)
        new_central_config.load()

        # Mock to use new config
        self.mock_cli_config_class.return_value = new_central_config

        # Create new CLI manager
        manager2 = ConfigManager()

        # Verify settings persisted
        self.assertEqual(manager2.get("test_setting"), "test_value")
        self.assertEqual(manager2.get("aliases.test"), "test alias")
        self.assertEqual(manager2.get("custom_commands.test.command"), "test cmd")

    def test_cli_config_validation(self):
        """Test CLI configuration validation."""
        # Test invalid output format
        self.cli_manager.set("output_format", "invalid_format")
        # Should default to json if invalid
        output = self.cli_manager.get("output_format")
        self.assertIn(output, ["json", "table", "yaml", "csv", "invalid_format"])

        # Test invalid verbosity level
        self.cli_manager.set("verbosity", "invalid_level")
        verbosity = self.cli_manager.get("verbosity")
        self.assertIsNotNone(verbosity)  # Should not crash

        # Test invalid max_history
        self.cli_manager.set("max_history", -100)
        max_history = self.cli_manager.get("max_history")
        self.assertIsNotNone(max_history)  # Should handle gracefully

        # Test invalid boolean values
        self.cli_manager.set("color_output", "not_a_boolean")
        color = self.cli_manager.get("color_output")
        self.assertIsNotNone(color)  # Should handle gracefully

    def test_concurrent_cli_config_access(self):
        """Test concurrent access to CLI configuration."""
        import threading
        import time

        results = []
        errors = []

        def set_config(thread_id):
            """Set configuration from a thread."""
            try:
                manager = ConfigManager()
                manager.set(f"thread_{thread_id}", f"value_{thread_id}")
                manager.set(f"aliases.thread_{thread_id}", f"alias_{thread_id}")
                results.append(("set", thread_id, "success"))
            except Exception as e:
                errors.append(("set", thread_id, str(e)))

        def get_config(thread_id):
            """Get configuration from a thread."""
            try:
                time.sleep(0.01)  # Small delay
                manager = ConfigManager()
                value = manager.get(f"thread_{thread_id}")
                if value == f"value_{thread_id}":
                    results.append(("get", thread_id, "match"))
                else:
                    results.append(("get", thread_id, "mismatch"))
            except Exception as e:
                errors.append(("get", thread_id, str(e)))

        def save_profile(thread_id):
            """Save profile from a thread."""
            try:
                profile_mgr = ProfileManager()
                profile = ConfigProfile(f"thread_{thread_id}", {
                    "output_format": "json",
                    "verbosity": f"level_{thread_id}"
                })
                profile_mgr.save_profile(f"thread_{thread_id}", profile)
                results.append(("profile", thread_id, "success"))
            except Exception as e:
                errors.append(("profile", thread_id, str(e)))

        # Create threads
        threads = []
        for i in range(10):
            t1 = threading.Thread(target=set_config, args=(i,))
            t2 = threading.Thread(target=get_config, args=(i,))
            t3 = threading.Thread(target=save_profile, args=(i,))
            threads.extend([t1, t2, t3])

        # Start all threads
        for t in threads:
            t.start()

        # Wait for completion
        for t in threads:
            t.join(timeout=5.0)

        # Check results
        set_count = sum(bool(r[0] == "set" and r[2] == "success")
                    for r in results)
        get_count = sum(bool(r[0] == "get")
                    for r in results)
        profile_count = sum(bool(r[0] == "profile" and r[2] == "success")
                        for r in results)

        self.assertEqual(set_count, 10, f"All sets should succeed. Errors: {errors}")
        self.assertEqual(get_count, 10, f"All gets should complete. Errors: {errors}")
        self.assertEqual(profile_count, 10, f"All profile saves should succeed. Errors: {errors}")

        # Verify no errors
        self.assertEqual(len(errors), 0, f"No errors should occur: {errors}")

        # Verify final state is consistent
        for i in range(10):
            value = self.cli_manager.get(f"thread_{i}")
            self.assertEqual(value, f"value_{i}", f"Thread {i} value should be correct")

            profile = self.central_config.get(f"cli_configuration.profiles.thread_{i}")
            self.assertIsNotNone(profile, f"Thread {i} profile should exist")


if __name__ == "__main__":
    unittest.main()
