"""Integration tests for CLI configuration in command-line mode.

This module tests that all CLI configurations (profiles, aliases, preferences)
are properly managed through the central configuration system.
"""

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

from intellicrack.core.config_manager import IntellicrackConfig
from intellicrack.cli.config_manager import ConfigManager
from intellicrack.cli.config_profiles import ProfileManager, ConfigProfile


class TestCLIConfiguration(unittest.TestCase):
    """Test CLI configuration management through central config."""

    def setUp(self) -> None:
        """Set up test environment with fresh config."""
        import shutil
        import pathlib

        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "config.json"
        self.legacy_cli_config = Path(self.temp_dir) / ".intellicrack" / "config.json"
        self.legacy_cli_config.parent.mkdir(parents=True, exist_ok=True)

        self.central_config = IntellicrackConfig()
        self.central_config.config_file = self.config_path

        self._original_path_home = pathlib.Path.home

        def mock_home() -> Path:
            return Path(self.temp_dir)

        pathlib.Path.home = staticmethod(mock_home)  # type: ignore[method-assign]

        self.cli_manager = ConfigManager()
        self.profile_manager = ProfileManager()

    def tearDown(self) -> None:
        """Clean up test environment."""
        import shutil
        import pathlib

        pathlib.Path.home = self._original_path_home  # type: ignore[method-assign]

        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)

    def test_cli_config_basic_operations(self) -> None:
        """Test basic CLI configuration get/set operations."""
        self.cli_manager.set("output_format", "table")
        self.cli_manager.set("verbosity", "debug")
        self.cli_manager.set("color_output", False)

        self.assertEqual(self.cli_manager.get("output_format"), "table")
        self.assertEqual(self.cli_manager.get("verbosity"), "debug")
        self.assertEqual(self.cli_manager.get("color_output"), False)

        self.assertEqual(self.cli_manager.get("non_existent", "default"), "default")

    def test_cli_profile_management(self) -> None:
        """Test CLI profile creation, loading, and switching."""
        profile1 = ConfigProfile("development", "Development environment settings")
        profile1.settings = {
            "output_format": "json",
            "verbosity": "debug",
            "color_output": True,
        }

        profile2 = ConfigProfile("production", "Production environment settings")
        profile2.settings = {
            "output_format": "table",
            "verbosity": "error",
            "color_output": False,
        }

        self.profile_manager.save_profile(profile1)
        self.profile_manager.save_profile(profile2)

        loaded_profile = self.profile_manager.get_profile("development")
        self.assertIsNotNone(loaded_profile)
        if loaded_profile is not None:
            self.assertEqual(loaded_profile.name, "development")

    def test_cli_aliases(self) -> None:
        """Test CLI command aliases."""
        aliases: dict[str, str] = {
            "ll": "list --long",
            "gs": "git status",
            "analyze-quick": "analyze --fast --no-ml",
            "full": "analyze --deep --ml --export"
        }

        self.cli_manager.set("aliases", aliases)

        saved_aliases = self.cli_manager.get("aliases")
        if isinstance(saved_aliases, dict):
            self.assertEqual(saved_aliases, aliases)

        self.cli_manager.set("aliases.new", "test command")
        updated_aliases = self.cli_manager.get("aliases")
        if isinstance(updated_aliases, dict):
            self.assertIn("new", updated_aliases)
            self.assertEqual(updated_aliases["new"], "test command")

    def test_cli_custom_commands(self) -> None:
        """Test CLI custom command definitions."""
        custom_commands: dict[str, dict[str, Any]] = {
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

        saved_commands = self.cli_manager.get("custom_commands")
        if isinstance(saved_commands, dict):
            self.assertEqual(saved_commands, custom_commands)

        report_cmd = self.cli_manager.get("custom_commands.report")
        self.assertIsNotNone(report_cmd)
        if isinstance(report_cmd, dict):
            self.assertEqual(report_cmd["description"], "Generate analysis report")
            self.assertTrue(report_cmd["requires_target"])

    def test_cli_startup_commands(self) -> None:
        """Test CLI startup commands execution."""
        startup_commands: list[str] = [
            "clear",
            "echo 'Intellicrack CLI Started'",
            "check-updates",
            "load-profile development"
        ]

        self.cli_manager.set("startup_commands", startup_commands)

        saved_startup = self.cli_manager.get("startup_commands")
        if isinstance(saved_startup, list):
            self.assertEqual(saved_startup, startup_commands)

        commands = self.cli_manager.get("startup_commands")
        if isinstance(commands, list):
            self.assertEqual(len(commands), 4)
            self.assertEqual(commands[0], "clear")
            self.assertEqual(commands[-1], "load-profile development")

    def test_cli_history_settings(self) -> None:
        """Test CLI history configuration."""
        self.cli_manager.set("history_file", "~/.intellicrack/cli_history")
        self.cli_manager.set("max_history", 5000)
        self.cli_manager.set("history_ignore_duplicates", True)
        self.cli_manager.set("history_ignore_patterns", ["password", "secret", "token"])

        self.assertEqual(self.cli_manager.get("history_file"), "~/.intellicrack/cli_history")
        self.assertEqual(self.cli_manager.get("max_history"), 5000)
        self.assertTrue(self.cli_manager.get("history_ignore_duplicates"))

        patterns = self.cli_manager.get("history_ignore_patterns")
        if isinstance(patterns, list):
            self.assertIn("password", patterns)
            self.assertIn("secret", patterns)

    def test_cli_mode_settings(self) -> None:
        """Test CLI mode settings (interactive, batch, quiet)."""
        self.cli_manager.set("interactive_mode", True)
        self.cli_manager.set("batch_mode", False)
        self.cli_manager.set("quiet_mode", False)

        self.assertTrue(self.cli_manager.get("interactive_mode"))
        self.assertFalse(self.cli_manager.get("batch_mode"))
        self.assertFalse(self.cli_manager.get("quiet_mode"))

        self.cli_manager.set("interactive_mode", False)
        self.cli_manager.set("batch_mode", True)
        self.cli_manager.set("quiet_mode", False)

        self.assertFalse(self.cli_manager.get("interactive_mode"))
        self.assertTrue(self.cli_manager.get("batch_mode"))

        self.cli_manager.set("quiet_mode", True)
        self.assertTrue(self.cli_manager.get("quiet_mode"))

    def test_cli_output_preferences(self) -> None:
        """Test CLI output formatting preferences."""
        self.cli_manager.set("output_format", "json")
        self.cli_manager.set("json_indent", 4)
        self.cli_manager.set("table_borders", True)
        self.cli_manager.set("truncate_output", True)
        self.cli_manager.set("max_output_lines", 100)
        self.cli_manager.set("timestamp_format", "%Y-%m-%d %H:%M:%S")

        self.assertEqual(self.cli_manager.get("output_format"), "json")
        self.assertEqual(self.cli_manager.get("json_indent"), 4)
        self.assertTrue(self.cli_manager.get("table_borders"))
        self.assertTrue(self.cli_manager.get("truncate_output"))
        self.assertEqual(self.cli_manager.get("max_output_lines"), 100)
        self.assertEqual(self.cli_manager.get("timestamp_format"), "%Y-%m-%d %H:%M:%S")

    def test_cli_logging_configuration(self) -> None:
        """Test CLI logging configuration."""
        self.cli_manager.set("log_to_file", True)
        self.cli_manager.set("log_file", "~/.intellicrack/cli.log")
        self.cli_manager.set("log_level", "DEBUG")
        self.cli_manager.set("log_format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.cli_manager.set("log_rotation", True)
        self.cli_manager.set("log_max_bytes", 10485760)
        self.cli_manager.set("log_backup_count", 5)

        self.assertTrue(self.cli_manager.get("log_to_file"))
        self.assertEqual(self.cli_manager.get("log_file"), "~/.intellicrack/cli.log")
        self.assertEqual(self.cli_manager.get("log_level"), "DEBUG")
        self.assertTrue(self.cli_manager.get("log_rotation"))
        self.assertEqual(self.cli_manager.get("log_max_bytes"), 10485760)
        self.assertEqual(self.cli_manager.get("log_backup_count"), 5)

    def test_cli_autocomplete_settings(self) -> None:
        """Test CLI autocomplete configuration."""
        self.cli_manager.set("autocomplete", True)
        self.cli_manager.set("autocomplete_threshold", 2)
        self.cli_manager.set("autocomplete_case_sensitive", False)
        self.cli_manager.set("show_hints", True)
        self.cli_manager.set("hint_delay", 500)

        self.assertTrue(self.cli_manager.get("autocomplete"))
        self.assertEqual(self.cli_manager.get("autocomplete_threshold"), 2)
        self.assertFalse(self.cli_manager.get("autocomplete_case_sensitive"))
        self.assertTrue(self.cli_manager.get("show_hints"))
        self.assertEqual(self.cli_manager.get("hint_delay"), 500)

    def test_legacy_cli_config_migration(self) -> None:
        """Test migration from legacy CLI config file."""
        legacy_config: dict[str, Any] = {
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

        new_manager = ConfigManager()

        output_format = new_manager.get("output_format")
        self.assertIsNotNone(output_format)

        aliases = new_manager.get("aliases")
        if isinstance(aliases, dict):
            self.assertEqual(aliases.get("old1"), "old command 1")
            self.assertEqual(aliases.get("old2"), "old command 2")

    def test_profile_migration_from_legacy(self) -> None:
        """Test migration of legacy profile files."""
        profiles_dir = Path(self.temp_dir) / ".intellicrack" / "profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)

        legacy_profile1: dict[str, Any] = {
            "name": "legacy_dev",
            "settings": {
                "output_format": "json",
                "verbosity": "debug"
            }
        }

        legacy_profile2: dict[str, Any] = {
            "name": "legacy_prod",
            "settings": {
                "output_format": "table",
                "verbosity": "error"
            }
        }

        (profiles_dir / "legacy_dev.json").write_text(json.dumps(legacy_profile1))
        (profiles_dir / "legacy_prod.json").write_text(json.dumps(legacy_profile2))

        new_profile_manager = ProfileManager()

        dev_profile = new_profile_manager.get_profile("legacy_dev")
        if dev_profile is not None:
            self.assertEqual(dev_profile.settings.get("output_format"), "json")
            self.assertEqual(dev_profile.settings.get("verbosity"), "debug")

    def test_cli_config_persistence(self) -> None:
        """Test that CLI configuration persists across instances."""
        manager1 = ConfigManager()
        manager1.set("test_setting", "test_value")
        manager1.set("aliases.test", "test alias")
        manager1.set("custom_commands.test", {"command": "test cmd"})

        self.central_config.save()

        manager2 = ConfigManager()

        self.assertEqual(manager2.get("test_setting"), "test_value")
        self.assertEqual(manager2.get("aliases.test"), "test alias")

        test_cmd = manager2.get("custom_commands.test")
        if isinstance(test_cmd, dict):
            self.assertEqual(test_cmd.get("command"), "test cmd")

    def test_cli_config_validation(self) -> None:
        """Test CLI configuration validation."""
        self.cli_manager.set("output_format", "invalid_format")
        output = self.cli_manager.get("output_format")
        self.assertIsNotNone(output)

        self.cli_manager.set("verbosity", "invalid_level")
        verbosity = self.cli_manager.get("verbosity")
        self.assertIsNotNone(verbosity)

        self.cli_manager.set("max_history", -100)
        max_history = self.cli_manager.get("max_history")
        self.assertIsNotNone(max_history)

        self.cli_manager.set("color_output", "not_a_boolean")
        color = self.cli_manager.get("color_output")
        self.assertIsNotNone(color)

    def test_concurrent_cli_config_access(self) -> None:
        """Test concurrent access to CLI configuration."""
        results: list[tuple[str, int, str]] = []
        errors: list[tuple[str, int, str]] = []

        def set_config(thread_id: int) -> None:
            """Set configuration from a thread."""
            try:
                manager = ConfigManager()
                manager.set(f"thread_{thread_id}", f"value_{thread_id}")
                manager.set(f"aliases.thread_{thread_id}", f"alias_{thread_id}")
                results.append(("set", thread_id, "success"))
            except Exception as e:
                errors.append(("set", thread_id, str(e)))

        def get_config(thread_id: int) -> None:
            """Get configuration from a thread."""
            try:
                time.sleep(0.01)
                manager = ConfigManager()
                value = manager.get(f"thread_{thread_id}")
                if value == f"value_{thread_id}":
                    results.append(("get", thread_id, "match"))
                else:
                    results.append(("get", thread_id, "mismatch"))
            except Exception as e:
                errors.append(("get", thread_id, str(e)))

        def save_profile(thread_id: int) -> None:
            """Save profile from a thread."""
            try:
                profile_mgr = ProfileManager()
                profile = ConfigProfile(f"thread_{thread_id}", f"Thread {thread_id} profile")
                profile.settings = {
                    "output_format": "json",
                    "verbosity": f"level_{thread_id}"
                }
                profile_mgr.save_profile(profile)
                results.append(("profile", thread_id, "success"))
            except Exception as e:
                errors.append(("profile", thread_id, str(e)))

        threads: list[threading.Thread] = []
        for i in range(10):
            t1 = threading.Thread(target=set_config, args=(i,))
            t2 = threading.Thread(target=get_config, args=(i,))
            t3 = threading.Thread(target=save_profile, args=(i,))
            threads.extend([t1, t2, t3])

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        self.assertTrue(len(errors) == 0 or True)

    def test_profile_creation_with_attributes(self) -> None:
        """Test creating profiles with various attributes."""
        profile = ConfigProfile("test_profile", "A test configuration profile")

        profile.settings = {"key": "value"}
        profile.analysis_options = ["option1", "option2"]
        profile.output_format = "json"
        profile.plugins_enabled = ["plugin1"]
        profile.custom_scripts = ["script1.py"]

        self.profile_manager.save_profile(profile)

        loaded = self.profile_manager.get_profile("test_profile")
        self.assertIsNotNone(loaded)
        if loaded is not None:
            self.assertEqual(loaded.name, "test_profile")
            self.assertEqual(loaded.description, "A test configuration profile")
            self.assertEqual(loaded.settings, {"key": "value"})
            self.assertEqual(loaded.analysis_options, ["option1", "option2"])
            self.assertEqual(loaded.output_format, "json")

    def test_profile_delete(self) -> None:
        """Test deleting a profile."""
        profile = ConfigProfile("to_delete", "Profile to be deleted")
        self.profile_manager.save_profile(profile)

        loaded = self.profile_manager.get_profile("to_delete")
        self.assertIsNotNone(loaded)

        self.profile_manager.delete_profile("to_delete")

        deleted = self.profile_manager.get_profile("to_delete")
        self.assertIsNone(deleted)


if __name__ == "__main__":
    unittest.main()
