"""
Integration tests for migration from a clean system with no existing configs.

This module tests that Intellicrack properly initializes and creates default
configurations when starting from a completely clean state.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock
import shutil

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from intellicrack.core.config_manager import IntellicrackConfig, get_config
from intellicrack.ai.llm_config_manager import LLMConfigManager
from intellicrack.cli.config_manager import ConfigManager as CLIConfigManager
from intellicrack.cli.config_profiles import ProfileManager
from intellicrack.ui.theme_manager import ThemeManager


class TestCleanSystemMigration(unittest.TestCase):
    """Test migration and initialization from a completely clean system."""

    def setUp(self):
        """Set up test environment with no existing configs."""
        # Create completely empty temp directory
        self.temp_dir = tempfile.mkdtemp()
        self.config_dir = Path(self.temp_dir) / "config"
        self.home_dir = Path(self.temp_dir) / "home"
        self.home_dir.mkdir(parents=True, exist_ok=True)

        # Ensure NO config files exist
        self.config_path = self.config_dir / "config.json"
        self.env_path = self.config_dir / ".env"

        # Mock all config-related paths
        self.config_file_patcher = patch('intellicrack.core.config_manager.CONFIG_FILE',
                                        str(self.config_path))
        self.config_dir_patcher = patch('intellicrack.core.config_manager.CONFIG_DIR',
                                       str(self.config_dir))
        self.env_file_patcher = patch('intellicrack.core.config_manager.ENV_FILE',
                                     str(self.env_path))

        # Mock home directory
        self.home_patcher = patch('pathlib.Path.home', return_value=self.home_dir)

        # Mock QSettings to ensure no registry access
        self.qsettings_patcher = patch('intellicrack.core.config_manager.QSettings')
        self.mock_qsettings_class = self.qsettings_patcher.start()
        self.mock_qsettings = MagicMock()
        self.mock_qsettings_class.return_value = self.mock_qsettings
        self.mock_qsettings.value.return_value = None  # No existing QSettings values

        # Start all patches
        self.config_file_patcher.start()
        self.config_dir_patcher.start()
        self.env_file_patcher.start()
        self.home_patcher.start()

    def tearDown(self):
        """Clean up test environment."""
        self.config_file_patcher.stop()
        self.config_dir_patcher.stop()
        self.env_file_patcher.stop()
        self.home_patcher.stop()
        self.qsettings_patcher.stop()

        # Clean up temp directory
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)

    def test_clean_system_creates_default_config(self):
        """Test that a clean system creates proper default configuration."""
        # Verify no config exists
        self.assertFalse(self.config_path.exists())
        self.assertFalse(self.env_path.exists())

        # Create config instance (should create defaults)
        config = IntellicrackConfig()

        # Verify config directory was created
        self.assertTrue(self.config_dir.exists())

        # Verify default config structure
        self.assertIsNotNone(config.config)
        self.assertIn("version", config.config)
        self.assertIn("application", config.config)
        self.assertIn("directories", config.config)
        self.assertIn("ui_preferences", config.config)
        self.assertIn("analysis_settings", config.config)
        self.assertIn("ai_models", config.config)
        self.assertIn("llm_configuration", config.config)
        self.assertIn("cli_configuration", config.config)
        self.assertIn("qemu_testing", config.config)

        # Verify version is current
        self.assertEqual(config.config["version"], "3.0")

        # Save config
        config.save()

        # Verify config file was created
        self.assertTrue(self.config_path.exists())

        # Verify .env file was created
        self.assertTrue(self.env_path.exists())

    def test_clean_system_ui_preferences_defaults(self):
        """Test that UI preferences have proper defaults on clean system."""
        config = IntellicrackConfig()

        # Check UI preference defaults
        ui_prefs = config.get("ui_preferences")
        self.assertIsNotNone(ui_prefs)

        # Window geometry defaults
        window_geom = ui_prefs.get("window_geometry")
        self.assertEqual(window_geom["width"], 1200)
        self.assertEqual(window_geom["height"], 800)
        self.assertEqual(window_geom["x"], 100)
        self.assertEqual(window_geom["y"], 100)

        # Window state default
        self.assertEqual(ui_prefs.get("window_state"), "normal")

        # Theme default
        self.assertEqual(ui_prefs.get("theme"), "light")

        # Splitter defaults
        splitter_states = ui_prefs.get("splitter_states")
        self.assertIsNotNone(splitter_states)
        self.assertEqual(splitter_states.get("main_splitter"), [700, 500])

        # Toolbar defaults
        toolbar_positions = ui_prefs.get("toolbar_positions")
        self.assertIsNotNone(toolbar_positions)
        self.assertTrue(toolbar_positions.get("main_toolbar", {}).get("visible", True))

    def test_clean_system_llm_configuration_defaults(self):
        """Test that LLM configuration has proper defaults on clean system."""
        config = IntellicrackConfig()

        # Check LLM configuration structure
        llm_config = config.get("llm_configuration")
        self.assertIsNotNone(llm_config)

        # Check default structure
        self.assertIn("models", llm_config)
        self.assertIn("profiles", llm_config)
        self.assertIn("metrics", llm_config)
        self.assertIn("auto_load_models", llm_config)

        # Models should be empty dict by default
        self.assertEqual(llm_config["models"], {})

        # Profiles should have defaults
        profiles = llm_config["profiles"]
        self.assertIn("fast", profiles)
        self.assertIn("balanced", profiles)
        self.assertIn("creative", profiles)
        self.assertIn("precise", profiles)

        # Check a default profile
        fast_profile = profiles["fast"]
        self.assertEqual(fast_profile["name"], "Fast Generation")
        self.assertEqual(fast_profile["settings"]["temperature"], 0.3)
        self.assertEqual(fast_profile["settings"]["max_tokens"], 1000)

        # Metrics should be empty
        self.assertEqual(llm_config["metrics"], {})

        # Auto-load should be disabled by default
        self.assertFalse(llm_config["auto_load_models"])

    def test_clean_system_cli_configuration_defaults(self):
        """Test that CLI configuration has proper defaults on clean system."""
        config = IntellicrackConfig()

        # Check CLI configuration
        cli_config = config.get("cli_configuration")
        self.assertIsNotNone(cli_config)

        # Check default profile
        self.assertIn("profiles", cli_config)
        self.assertIn("default", cli_config["profiles"])

        default_profile = cli_config["profiles"]["default"]
        self.assertEqual(default_profile["output_format"], "json")
        self.assertEqual(default_profile["verbosity"], "info")
        self.assertTrue(default_profile["color_output"])
        self.assertTrue(default_profile["progress_bars"])

        # Check other defaults
        self.assertEqual(cli_config["default_profile"], "default")
        self.assertEqual(cli_config["output_format"], "json")
        self.assertEqual(cli_config["verbosity"], "info")
        self.assertTrue(cli_config["auto_save"])
        self.assertEqual(cli_config["max_history"], 1000)
        self.assertTrue(cli_config["autocomplete"])
        self.assertTrue(cli_config["show_hints"])

        # Check empty collections
        self.assertEqual(cli_config["aliases"], {})
        self.assertEqual(cli_config["custom_commands"], {})
        self.assertEqual(cli_config["startup_commands"], [])

    def test_clean_system_qemu_testing_defaults(self):
        """Test that QEMU testing configuration has proper defaults."""
        config = IntellicrackConfig()

        # Check QEMU testing configuration
        qemu_config = config.get("qemu_testing")
        self.assertIsNotNone(qemu_config)

        # Check defaults
        self.assertEqual(qemu_config["default_preference"], "ask")
        self.assertEqual(qemu_config["script_type_preferences"], {})
        self.assertEqual(qemu_config["trusted_binaries"], [])
        self.assertEqual(qemu_config["execution_history"], [])
        self.assertTrue(qemu_config["enable_sandbox"])
        self.assertEqual(qemu_config["timeout"], 30)
        self.assertEqual(qemu_config["memory_limit"], 512)

    def test_clean_system_tool_discovery(self):
        """Test that tool discovery works on clean system."""
        with patch('shutil.which') as mock_which:
            # Mock tool availability
            def which_side_effect(tool):
                tool_paths = {
                    'ghidra': '/usr/bin/ghidra',
                    'r2': '/usr/bin/r2',
                    'frida': '/usr/local/bin/frida',
                    'x64dbg': None,  # Not available
                    'ida': None,  # Not available
                }
                return tool_paths.get(tool)

            mock_which.side_effect = which_side_effect

            # Create config (triggers tool discovery)
            config = IntellicrackConfig()

            # Check discovered tools
            tools = config.get("tools")
            self.assertIsNotNone(tools)

            # Available tools should be discovered
            self.assertIn("ghidra", tools)
            self.assertEqual(tools["ghidra"]["available"], True)
            self.assertEqual(tools["ghidra"]["path"], "/usr/bin/ghidra")

            self.assertIn("radare2", tools)
            self.assertEqual(tools["radare2"]["available"], True)

            self.assertIn("frida", tools)
            self.assertEqual(tools["frida"]["available"], True)

            # Unavailable tools should be marked as such
            self.assertIn("x64dbg", tools)
            self.assertEqual(tools["x64dbg"]["available"], False)

            self.assertIn("ida", tools)
            self.assertEqual(tools["ida"]["available"], False)

    def test_clean_system_directory_creation(self):
        """Test that required directories are created on clean system."""
        config = IntellicrackConfig()

        # Get directory configuration
        dirs = config.get("directories")

        # Create the directories
        config._ensure_directories()

        # Check that critical directories were created
        for key in ["logs", "output", "cache", "temp"]:
            dir_path = Path(dirs[key])
            self.assertTrue(dir_path.exists(), f"Directory {key} should be created")

    def test_clean_system_env_file_creation(self):
        """Test that .env file is created with defaults on clean system."""
        config = IntellicrackConfig()

        # Trigger env file creation
        config._ensure_env_file()

        # Verify .env file exists
        self.assertTrue(self.env_path.exists())

        # Read .env file
        env_content = self.env_path.read_text()

        # Check for expected environment variables
        self.assertIn("# Intellicrack Environment Configuration", env_content)
        self.assertIn("INTELLICRACK_ENV=", env_content)
        self.assertIn("# API Keys", env_content)
        self.assertIn("# OPENAI_API_KEY=", env_content)
        self.assertIn("# ANTHROPIC_API_KEY=", env_content)

    def test_clean_system_llm_manager_initialization(self):
        """Test LLM config manager initializes properly on clean system."""
        # Mock central config
        with patch('intellicrack.ai.llm_config_manager.get_config') as mock_get_config:
            config = IntellicrackConfig()
            mock_get_config.return_value = config

            # Create LLM manager (should not crash)
            llm_manager = LLMConfigManager()

            # Should have empty models
            models = llm_manager.list_model_configs()
            self.assertEqual(models, {})

            # Should have default profiles
            profiles = llm_manager.list_profiles()
            self.assertIn("fast", profiles)
            self.assertIn("balanced", profiles)

            # Should handle operations gracefully
            result = llm_manager.load_model_config("non_existent")
            self.assertIsNone(result)

            # Should be able to save new config
            from intellicrack.ai.llm_config_manager import LLMConfig
            new_config = LLMConfig(
                provider="test",
                model_name="test-model",
                api_key="test-key"
            )
            llm_manager.save_model_config("test-model", new_config)

            # Should be able to retrieve it
            loaded = llm_manager.load_model_config("test-model")
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.model_name, "test-model")

    def test_clean_system_cli_manager_initialization(self):
        """Test CLI config manager initializes properly on clean system."""
        # Mock central config
        with patch('intellicrack.cli.config_manager.IntellicrackConfig') as mock_config_class:
            config = IntellicrackConfig()
            mock_config_class.return_value = config

            # Create CLI manager (should not crash)
            cli_manager = CLIConfigManager()

            # Should have default values
            self.assertEqual(cli_manager.get("output_format"), "json")
            self.assertEqual(cli_manager.get("verbosity"), "info")

            # Should handle operations gracefully
            cli_manager.set("test_key", "test_value")
            self.assertEqual(cli_manager.get("test_key"), "test_value")

            # Aliases should be empty
            aliases = cli_manager.get("aliases")
            self.assertEqual(aliases, {})

            # Should be able to add aliases
            cli_manager.set("aliases.test", "test command")
            self.assertEqual(cli_manager.get("aliases.test"), "test command")

    def test_clean_system_theme_manager_initialization(self):
        """Test theme manager initializes properly on clean system."""
        # Mock central config and QApplication
        with patch('intellicrack.ui.theme_manager.get_config') as mock_get_config:
            with patch('intellicrack.ui.theme_manager.QApplication') as mock_qapp:
                config = IntellicrackConfig()
                mock_get_config.return_value = config

                # Mock QApplication instance
                mock_app = MagicMock()
                mock_qapp.instance.return_value = mock_app

                # Create theme manager (should not crash)
                theme_manager = ThemeManager()

                # Should have default theme (light)
                self.assertEqual(theme_manager.current_theme, "light")

                # Should be able to change theme
                theme_manager.set_theme("dark")
                self.assertEqual(theme_manager.current_theme, "dark")

                # Change should be saved to config
                saved_theme = config.get("ui_preferences.theme")
                self.assertEqual(saved_theme, "dark")

    def test_clean_system_no_migration_errors(self):
        """Test that no migration errors occur on clean system."""
        # Create config with migration logging
        with patch('intellicrack.core.config_manager.logger') as mock_logger:
            config = IntellicrackConfig()

            # No error logs should occur
            mock_logger.error.assert_not_called()

            # Migration methods should handle missing files gracefully
            config._migrate_qsettings_data()  # Should not error
            config._migrate_llm_configs()     # Should not error
            config._migrate_legacy_configs()  # Should not error
            config._migrate_cli_configs()     # Should not error

            # Still no errors
            mock_logger.error.assert_not_called()

    def test_clean_system_complete_workflow(self):
        """Test complete workflow on clean system."""
        # Step 1: Create central config
        config = IntellicrackConfig()
        self.assertIsNotNone(config)

        # Step 2: Initialize LLM manager
        with patch('intellicrack.ai.llm_config_manager.get_config', return_value=config):
            llm_manager = LLMConfigManager()

            # Add a model
            from intellicrack.ai.llm_config_manager import LLMConfig
            model_config = LLMConfig(
                provider="openai",
                model_name="gpt-4",
                api_key="test-key"
            )
            llm_manager.save_model_config("gpt4", model_config)

        # Step 3: Initialize CLI manager
        with patch('intellicrack.cli.config_manager.IntellicrackConfig', return_value=config):
            cli_manager = CLIConfigManager()

            # Set some preferences
            cli_manager.set("output_format", "table")
            cli_manager.set("aliases.ll", "list --long")

        # Step 4: Initialize theme manager
        with patch('intellicrack.ui.theme_manager.get_config', return_value=config):
            with patch('intellicrack.ui.theme_manager.QApplication'):
                theme_manager = ThemeManager()
                theme_manager.set_theme("dark")

        # Step 5: Save everything
        config.save()

        # Step 6: Verify persistence - create new instance
        config2 = IntellicrackConfig()
        config2.config_file = str(self.config_path)
        config2.load()

        # Verify all settings persisted
        self.assertIsNotNone(config2.get("llm_configuration.models.gpt4"))
        self.assertEqual(config2.get("cli_configuration.output_format"), "table")
        self.assertEqual(config2.get("cli_configuration.aliases.ll"), "list --long")
        self.assertEqual(config2.get("ui_preferences.theme"), "dark")

    def test_clean_system_handles_permission_errors(self):
        """Test that clean system handles permission errors gracefully."""
        # Make config directory read-only (simulate permission issue)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Mock permission error on file write
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with patch('intellicrack.core.config_manager.logger') as mock_logger:
                # Should handle gracefully
                config = IntellicrackConfig()

                # Should log error but not crash
                try:
                    config.save()
                except PermissionError:
                    pass  # Expected

                # Should have logged the error
                self.assertTrue(
                    mock_logger.error.called or mock_logger.warning.called,
                    "Should log permission errors"
                )

    def test_clean_system_concurrent_initialization(self):
        """Test concurrent initialization on clean system."""
        import threading

        results = []
        errors = []

        def create_config(thread_id):
            """Create config from a thread."""
            try:
                config = IntellicrackConfig()
                config.set(f"test.thread_{thread_id}", f"value_{thread_id}")
                results.append((thread_id, "success", config.get("version")))
            except Exception as e:
                errors.append((thread_id, str(e)))

        # Create multiple threads trying to initialize simultaneously
        threads = []
        for i in range(5):
            t = threading.Thread(target=create_config, args=(i,))
            threads.append(t)

        # Start all threads
        for t in threads:
            t.start()

        # Wait for completion
        for t in threads:
            t.join(timeout=10.0)

        # All should succeed
        self.assertEqual(len(results), 5, f"All threads should succeed. Errors: {errors}")
        self.assertEqual(len(errors), 0, "No errors should occur")

        # All should have same version
        versions = [r[2] for r in results]
        self.assertTrue(all(v == "3.0" for v in versions), "All should have same version")

        # Config file should exist
        self.assertTrue(self.config_path.exists())


if __name__ == "__main__":
    unittest.main()
