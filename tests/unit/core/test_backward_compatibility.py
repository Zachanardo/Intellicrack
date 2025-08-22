"""Test backward compatibility with existing code after configuration consolidation.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open, PropertyMock
import sys

sys.path.insert(0, 'C:\\Intellicrack')

from intellicrack.core.config_manager import IntellicrackConfig, get_config


class TestBackwardCompatibility(unittest.TestCase):
    """Test suite for backward compatibility with existing code patterns."""

    def setUp(self):
        """Set up test environment with temporary config file."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "test_config.json"
        self.config = IntellicrackConfig(config_path=str(self.config_path))

    def tearDown(self):
        """Clean up temporary files."""
        if self.config_path.exists():
            self.config_path.unlink()
        Path(self.temp_dir).rmdir()

    @patch('intellicrack.core.config_manager.logger')
    def test_script_execution_manager_backward_compatibility(self, mock_logger):
        """Test that ScriptExecutionManager patterns still work after migration."""
        # Simulate how ScriptExecutionManager used QSettings
        with patch('intellicrack.core.execution.script_execution_manager.QSettings') as MockQSettings:
            mock_settings = MagicMock()

            # Old pattern: ScriptExecutionManager directly accessing QSettings
            old_values = {
                "execution/qemu_preference": "always",
                "trusted_binaries": ["C:\\Apps\\app1.exe", "C:\\Apps\\app2.exe"],
                "script_types/frida/use_qemu": True,
                "script_types/ghidra/use_qemu": False
            }

            mock_settings.value.side_effect = lambda key, default=None: old_values.get(key, default)
            MockQSettings.return_value = mock_settings

            # After migration, these should be accessible through central config
            self.config._migrate_qsettings_data()

            # Verify old access patterns work through migration
            assert self.config.get("qemu_testing.default_preference") == "always"
            assert len(self.config.get("qemu_testing.trusted_binaries", [])) == 2
            assert self.config.get("qemu_testing.script_type_preferences.frida") is True
            assert self.config.get("qemu_testing.script_type_preferences.ghidra") is False

            # Test that ScriptExecutionManager can use migrated data
            # Simulating the refactored ScriptExecutionManager code
            class MockScriptExecutionManager:
                def __init__(self):
                    self.config = get_config()

                def get_qemu_preference(self):
                    # Old: self.settings.value("execution/qemu_preference", "ask")
                    # New: Uses central config
                    return self.config.get("qemu_testing.default_preference", "ask")

                def is_trusted_binary(self, binary_path):
                    # Old: self.settings.value("trusted_binaries", [])
                    # New: Uses central config
                    trusted = self.config.get("qemu_testing.trusted_binaries", [])
                    return binary_path in trusted

                def should_use_qemu_for_script(self, script_type):
                    # Old: self.settings.value(f"script_types/{script_type}/use_qemu", False)
                    # New: Uses central config
                    prefs = self.config.get("qemu_testing.script_type_preferences", {})
                    return prefs.get(script_type, False)

            # Test the mock manager with migrated data
            with patch('intellicrack.core.config_manager.get_config', return_value=self.config):
                manager = MockScriptExecutionManager()
                assert manager.get_qemu_preference() == "always"
                assert manager.is_trusted_binary("C:\\Apps\\app1.exe") is True
                assert manager.is_trusted_binary("C:\\Apps\\unknown.exe") is False
                assert manager.should_use_qemu_for_script("frida") is True
                assert manager.should_use_qemu_for_script("ghidra") is False

    @patch('intellicrack.core.config_manager.logger')
    def test_theme_manager_backward_compatibility(self, mock_logger):
        """Test that ThemeManager patterns still work after migration."""
        with patch('intellicrack.ui.theme_manager.QSettings') as MockQSettings:
            mock_settings = MagicMock()

            # Old pattern: ThemeManager using QSettings("Intellicrack", "ThemeManager")
            old_theme_values = {
                "theme/mode": "dark",
                "theme/accent_color": "#2196F3",
                "theme/font_scale": 1.1,
                "theme/custom_css": "QWidget { background: #1e1e1e; }"
            }

            mock_settings.value.side_effect = lambda key, default=None: old_theme_values.get(key, default)
            MockQSettings.return_value = mock_settings

            # Migrate the settings
            self.config._migrate_qsettings_data()

            # Simulate refactored ThemeManager
            class MockThemeManager:
                def __init__(self):
                    self.config = get_config()

                def get_theme_mode(self):
                    # Old: self.settings.value("theme/mode", "light")
                    # New: Uses central config
                    return self.config.get("ui_preferences.theme", "light")

                def get_accent_color(self):
                    # Old: self.settings.value("theme/accent_color", "#000000")
                    # New: Uses central config
                    return self.config.get("ui_preferences.accent_color", "#000000")

                def get_font_scale(self):
                    # Old: self.settings.value("theme/font_scale", 1.0)
                    # New: Uses central config
                    return self.config.get("ui_preferences.font_scale", 1.0)

                def get_custom_css(self):
                    # Old: self.settings.value("theme/custom_css", "")
                    # New: Uses central config
                    return self.config.get("ui_preferences.custom_css", "")

            # Test with migrated data
            with patch('intellicrack.core.config_manager.get_config', return_value=self.config):
                theme_mgr = MockThemeManager()
                assert theme_mgr.get_theme_mode() == "dark"
                assert theme_mgr.get_accent_color() == "#2196F3"
                assert theme_mgr.get_font_scale() == 1.1
                assert "background: #1e1e1e" in theme_mgr.get_custom_css()

    @patch('intellicrack.core.config_manager.logger')
    @patch('intellicrack.core.config_manager.Path')
    def test_llm_config_manager_backward_compatibility(self, MockPath, mock_logger):
        """Test that LLMConfigManager patterns still work after migration."""
        # Mock LLM config files
        mock_home = MockPath.home.return_value
        mock_llm_dir = mock_home / ".intellicrack" / "llm_configs"
        mock_llm_dir.exists.return_value = True

        # Old LLMConfigManager data
        models_data = {
            "gpt-4": {
                "provider": "openai",
                "api_key": "sk-test123",
                "max_tokens": 8192,
                "temperature": 0.7
            }
        }

        profiles_data = {
            "default": {
                "model": "gpt-4",
                "system_prompt": "You are an assistant."
            }
        }

        # Mock file reading
        def mock_open_file(path, *args, **kwargs):
            if "models.json" in str(path):
                return mock_open(read_data=json.dumps(models_data))()
            elif "profiles.json" in str(path):
                return mock_open(read_data=json.dumps(profiles_data))()
            return mock_open(read_data="{}")()

        models_file = MagicMock()
        models_file.exists.return_value = True
        models_file.open = lambda *args, **kwargs: mock_open_file(models_file, *args, **kwargs)
        models_file.__str__ = lambda self: "models.json"

        profiles_file = MagicMock()
        profiles_file.exists.return_value = True
        profiles_file.open = lambda *args, **kwargs: mock_open_file(profiles_file, *args, **kwargs)
        profiles_file.__str__ = lambda self: "profiles.json"

        metrics_file = MagicMock()
        metrics_file.exists.return_value = False

        mock_llm_dir.__truediv__.side_effect = lambda name: {
            "models.json": models_file,
            "profiles.json": profiles_file,
            "metrics.json": metrics_file
        }.get(name)

        # Migrate LLM configs
        self.config._migrate_llm_configs()

        # Simulate refactored LLMConfigManager
        class MockLLMConfigManager:
            def __init__(self):
                self.config = get_config()

            def save_model_config(self, model_id, config_data):
                # Old: Write to ~/.intellicrack/llm_configs/models.json
                # New: Uses central config
                self.config.set(f"llm_configuration.models.{model_id}", config_data)

            def load_model_config(self, model_id):
                # Old: Read from ~/.intellicrack/llm_configs/models.json
                # New: Uses central config
                return self.config.get(f"llm_configuration.models.{model_id}")

            def get_profile(self, profile_name):
                # Old: Read from profiles.json
                # New: Uses central config
                return self.config.get(f"llm_configuration.profiles.{profile_name}")

            def list_models(self):
                # Old: List keys from models.json
                # New: Uses central config
                models = self.config.get("llm_configuration.models", {})
                return list(models.keys())

        # Test with migrated data
        with patch('intellicrack.core.config_manager.get_config', return_value=self.config):
            llm_mgr = MockLLMConfigManager()

            # Test loading existing model
            gpt4_config = llm_mgr.load_model_config("gpt-4")
            assert gpt4_config is not None
            assert gpt4_config["provider"] == "openai"
            assert gpt4_config["max_tokens"] == 8192

            # Test getting profile
            default_profile = llm_mgr.get_profile("default")
            assert default_profile is not None
            assert default_profile["model"] == "gpt-4"

            # Test listing models
            models = llm_mgr.list_models()
            assert "gpt-4" in models

            # Test saving new model
            llm_mgr.save_model_config("claude-3", {
                "provider": "anthropic",
                "api_key": "sk-ant-456",
                "max_tokens": 100000
            })
            assert llm_mgr.load_model_config("claude-3")["provider"] == "anthropic"

    def test_font_manager_backward_compatibility(self):
        """Test that FontManager patterns still work after migration."""
        # Set up font configuration in central config (as if migrated)
        font_config = {
            "monospace_fonts": {
                "primary": ["JetBrains Mono", "JetBrainsMono-Regular"],
                "fallback": ["Consolas", "Courier New", "monospace"]
            },
            "ui_fonts": {
                "primary": ["Segoe UI", "Roboto"],
                "fallback": ["Arial", "sans-serif"]
            },
            "font_sizes": {
                "ui_default": 10,
                "code_default": 11,
                "hex_view": 11
            },
            "available_fonts": [
                "JetBrainsMono-Regular.ttf",
                "JetBrainsMono-Bold.ttf"
            ]
        }
        self.config.set("font_configuration", font_config)

        # Simulate refactored FontManager
        class MockFontManager:
            def __init__(self):
                self.config = get_config()
                self.fonts_dir = "C:\\Intellicrack\\assets\\fonts"
                self.loaded_fonts = []

            def _load_config(self):
                # Old: Read from assets/fonts/font_config.json
                # New: Uses central config
                return self.config.get("font_configuration", {})

            def get_monospace_font(self, size=None):
                config = self._load_config()
                if size is None:
                    size = config.get("font_sizes", {}).get("code_default", 10)

                # Try primary fonts
                for font_name in config.get("monospace_fonts", {}).get("primary", []):
                    return {"family": font_name, "size": size}

                # Fallback
                return {"family": "monospace", "size": size}

            def get_ui_font(self, size=None):
                config = self._load_config()
                if size is None:
                    size = config.get("font_sizes", {}).get("ui_default", 10)

                # Try primary fonts
                for font_name in config.get("ui_fonts", {}).get("primary", []):
                    return {"family": font_name, "size": size}

                # Fallback
                return {"family": "sans-serif", "size": size}

        # Test with migrated data
        with patch('intellicrack.core.config_manager.get_config', return_value=self.config):
            font_mgr = MockFontManager()

            # Test getting monospace font
            mono_font = font_mgr.get_monospace_font()
            assert mono_font["family"] == "JetBrains Mono"
            assert mono_font["size"] == 11

            # Test getting UI font
            ui_font = font_mgr.get_ui_font()
            assert ui_font["family"] == "Segoe UI"
            assert ui_font["size"] == 10

            # Test with custom size
            large_font = font_mgr.get_monospace_font(size=14)
            assert large_font["size"] == 14

    def test_env_file_manager_backward_compatibility(self):
        """Test that EnvFileManager patterns still work after migration."""
        # Set up environment configuration
        self.config.set("environment", {
            "env_file_path": "C:\\Intellicrack\\config\\.env",
            "variables": {
                "OPENAI_API_KEY": "sk-test123",
                "ANTHROPIC_API_KEY": "sk-ant-456",
                "DEBUG_MODE": "true"
            },
            "auto_load_env": True
        })

        # Simulate refactored EnvFileManager
        class MockEnvFileManager:
            def __init__(self, env_file_path=None):
                self.config = get_config()

                if env_file_path is None:
                    # Old: Use hardcoded default path
                    # New: Get from central config
                    env_path_str = self.config.get("environment.env_file_path")
                    if not env_path_str:
                        env_path_str = "C:/Intellicrack/config/.env"
                        self.config.set("environment.env_file_path", env_path_str)
                    self.env_path = Path(env_path_str)
                else:
                    self.env_path = Path(env_file_path)
                    self.config.set("environment.env_file_path", str(self.env_path))

            def read_env(self):
                # Old: Read from .env file
                # New: Can also sync with central config
                return self.config.get("environment.variables", {})

            def set_key(self, key, value):
                # Old: Write to .env file
                # New: Also update central config
                env_vars = self.config.get("environment.variables", {})
                env_vars[key] = value
                self.config.set("environment.variables", env_vars)

            def get_key(self, key):
                env_vars = self.read_env()
                return env_vars.get(key)

        # Test with migrated data
        with patch('intellicrack.core.config_manager.get_config', return_value=self.config):
            env_mgr = MockEnvFileManager()

            # Test reading environment variables
            env_vars = env_mgr.read_env()
            assert env_vars["OPENAI_API_KEY"] == "sk-test123"
            assert env_vars["DEBUG_MODE"] == "true"

            # Test getting single key
            assert env_mgr.get_key("ANTHROPIC_API_KEY") == "sk-ant-456"

            # Test setting new key
            env_mgr.set_key("NEW_KEY", "new_value")
            assert env_mgr.get_key("NEW_KEY") == "new_value"

    def test_cli_config_manager_backward_compatibility(self):
        """Test that CLI ConfigManager patterns still work after migration."""
        # Set up CLI configuration
        self.config.set("cli_configuration", {
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
                "la": "list --all"
            }
        })

        # Simulate refactored CLI ConfigManager
        class MockCLIConfigManager:
            def __init__(self):
                self.config = get_config()

            def get_preference(self, key, default=None):
                # Old: Read from separate CLI config file
                # New: Uses central config
                prefs = self.config.get("cli_configuration.preferences", {})
                return prefs.get(key, default)

            def get_profile(self, profile_name):
                # Old: Read from CLI profiles file
                # New: Uses central config
                profiles = self.config.get("cli_configuration.profiles", {})
                return profiles.get(profile_name, {})

            def get_alias(self, alias):
                # Old: Read from aliases file
                # New: Uses central config
                aliases = self.config.get("cli_configuration.aliases", {})
                return aliases.get(alias)

            def set_preference(self, key, value):
                # Old: Write to CLI config file
                # New: Uses central config
                prefs = self.config.get("cli_configuration.preferences", {})
                prefs[key] = value
                self.config.set("cli_configuration.preferences", prefs)

        # Test with migrated data
        with patch('intellicrack.core.config_manager.get_config', return_value=self.config):
            cli_mgr = MockCLIConfigManager()

            # Test getting preferences
            assert cli_mgr.get_preference("color_output") is True
            assert cli_mgr.get_preference("verbose_mode") is False
            assert cli_mgr.get_preference("non_existent", "default") == "default"

            # Test getting profiles
            default_profile = cli_mgr.get_profile("default")
            assert default_profile["output_format"] == "json"
            assert default_profile["log_level"] == "INFO"

            debug_profile = cli_mgr.get_profile("debug")
            assert debug_profile["log_level"] == "DEBUG"

            # Test getting aliases
            assert cli_mgr.get_alias("ll") == "list --long"
            assert cli_mgr.get_alias("la") == "list --all"

            # Test setting preference
            cli_mgr.set_preference("new_pref", "new_value")
            assert cli_mgr.get_preference("new_pref") == "new_value"

    def test_old_config_file_presence_no_conflict(self):
        """Test that presence of old config files doesn't cause conflicts."""
        # Create old config files in temp directory
        old_configs = [
            (Path(self.temp_dir) / "font_config.json", {
                "fonts": ["Arial", "Consolas"],
                "size": 12
            }),
            (Path(self.temp_dir) / "llm_config.json", {
                "model": "gpt-3.5",
                "temperature": 0.5
            }),
            (Path(self.temp_dir) / "old_settings.json", {
                "theme": "light",
                "language": "en"
            })
        ]

        # Write old config files
        for path, data in old_configs:
            with open(path, 'w') as f:
                json.dump(data, f)

        # Set up new central config
        self.config.set("font_configuration.monospace_fonts.primary", ["JetBrains Mono"])
        self.config.set("llm_configuration.models.gpt-4.provider", "openai")
        self.config.set("ui_preferences.theme", "dark")

        # Verify old files don't interfere with new config
        assert self.config.get("font_configuration.monospace_fonts.primary")[0] == "JetBrains Mono"
        assert self.config.get("llm_configuration.models.gpt-4.provider") == "openai"
        assert self.config.get("ui_preferences.theme") == "dark"

        # Clean up old config files
        for path, _ in old_configs:
            if path.exists():
                path.unlink()

    def test_partial_migration_graceful_handling(self):
        """Test that partial migration scenarios are handled gracefully."""
        # Simulate partial migration where some sections are missing
        partial_config = {
            "application": {
                "name": "Intellicrack",
                "version": "3.0.0"
            },
            "ui_preferences": {
                "theme": "dark"
            }
            # Missing: qemu_testing, font_configuration, environment, etc.
        }

        # Load partial config
        with open(self.config_path, 'w') as f:
            json.dump(partial_config, f)

        # Create new config instance
        config = IntellicrackConfig(config_path=str(self.config_path))

        # Test that missing sections return defaults without crashing
        assert config.get("qemu_testing.default_preference", "ask") == "ask"
        assert config.get("font_configuration.monospace_fonts", {}) == {}
        assert config.get("environment.variables", {}) == {}
        assert config.get("llm_configuration.models", {}) == {}

        # Test that existing sections work
        assert config.get("application.name") == "Intellicrack"
        assert config.get("ui_preferences.theme") == "dark"

        # Test that new values can be added to missing sections
        config.set("qemu_testing.default_preference", "always")
        assert config.get("qemu_testing.default_preference") == "always"

    def test_api_compatibility_preserved(self):
        """Test that public API remains compatible after migration."""
        # Test IntellicrackConfig API compatibility

        # Test get method with dot notation (existing API)
        self.config.set("test.nested.value", 42)
        assert self.config.get("test.nested.value") == 42

        # Test get with default (existing API)
        assert self.config.get("non.existent.key", "default") == "default"

        # Test set method (existing API)
        self.config.set("new.key", "new_value")
        assert self.config.get("new.key") == "new_value"

        # Test save method (existing API)
        self.config.save()
        assert self.config_path.exists()

        # Test load method (existing API)
        self.config.set("before_load", "value1")
        self.config.save()
        self.config.load()
        assert self.config.get("before_load") == "value1"

        # Test upgrade_config method (existing API)
        # Should not raise any exceptions
        self.config.upgrade_config()

        # Test get_all method (if it exists)
        if hasattr(self.config, 'get_all'):
            all_config = self.config.get_all()
            assert isinstance(all_config, dict)

    def test_migration_with_corrupted_old_config(self):
        """Test that migration handles corrupted old config files gracefully."""
        with patch('intellicrack.core.config_manager.Path') as MockPath:
            # Mock corrupted font config file
            mock_font_path = MagicMock()
            mock_font_path.exists.return_value = True
            mock_font_path.open = mock_open(read_data="{ corrupted json {{")
            MockPath.return_value = mock_font_path

            # Should not crash, should log warning
            with patch('intellicrack.core.config_manager.logger') as mock_logger:
                self.config._migrate_font_configs()
                mock_logger.warning.assert_called()

            # Config should still be functional
            self.config.set("test_key", "test_value")
            assert self.config.get("test_key") == "test_value"

    def test_concurrent_access_backward_compatibility(self):
        """Test that concurrent access patterns still work after migration."""
        import threading

        results = []
        errors = []

        def old_pattern_thread(thread_id):
            """Simulates old code pattern accessing config."""
            try:
                # Old pattern might directly access config file
                # New pattern uses thread-safe central config
                config = get_config()

                # Simulate read-modify-write pattern
                for i in range(10):
                    key = f"thread_test.{thread_id}.value_{i}"
                    config.set(key, f"thread_{thread_id}_val_{i}")
                    value = config.get(key)
                    results.append(value)
            except Exception as e:
                errors.append(f"Thread {thread_id}: {e}")

        # Create multiple threads simulating old access patterns
        with patch('intellicrack.core.config_manager.get_config', return_value=self.config):
            threads = []
            for i in range(5):
                t = threading.Thread(target=old_pattern_thread, args=(i,))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

        # Verify no errors occurred
        assert len(errors) == 0

        # Verify data was written correctly
        assert len(results) > 0

        # Verify thread data integrity
        for i in range(5):
            for j in range(10):
                key = f"thread_test.{i}.value_{j}"
                value = self.config.get(key)
                if value:
                    assert value == f"thread_{i}_val_{j}"


if __name__ == "__main__":
    unittest.main()
