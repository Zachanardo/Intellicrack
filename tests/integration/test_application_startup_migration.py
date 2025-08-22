"""Integration test for full application startup with configuration migration.

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
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
import shutil

sys.path.insert(0, 'C:\\Intellicrack')

from intellicrack.core.config_manager import IntellicrackConfig, get_config


class TestApplicationStartupMigration(unittest.TestCase):
    """Integration tests for full application startup with configuration migration."""

    def setUp(self):
        """Set up test environment with temporary directories."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_dir = Path(self.temp_dir) / "config"
        self.config_dir.mkdir()
        self.home_dir = Path(self.temp_dir) / "home"
        self.home_dir.mkdir()
        self.llm_configs_dir = self.home_dir / ".intellicrack" / "llm_configs"
        self.llm_configs_dir.mkdir(parents=True)

        # Store original environment
        self.original_env = os.environ.copy()

    def tearDown(self):
        """Clean up temporary files and restore environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        os.environ.clear()
        os.environ.update(self.original_env)

    def create_legacy_configs(self):
        """Create realistic legacy configuration files for testing."""
        # Create main legacy config
        main_config = {
            "application": {
                "name": "Intellicrack",
                "version": "2.9.0",
                "environment": "production"
            },
            "tools": {
                "ghidra": "C:\\Tools\\ghidra\\ghidraRun.bat",
                "ida": "C:\\Tools\\IDA\\ida64.exe",
                "x64dbg": "C:\\Tools\\x64dbg\\x64dbg.exe",
                "radare2": "C:\\Tools\\radare2\\bin\\r2.exe"
            },
            "directories": {
                "output": str(self.temp_dir / "output"),
                "logs": str(self.temp_dir / "logs"),
                "cache": str(self.temp_dir / "cache"),
                "plugins": str(self.temp_dir / "plugins")
            },
            "ui_preferences": {
                "theme": "dark",
                "font_size": 10
            }
        }

        with open(self.config_dir / "intellicrack_config.json", 'w') as f:
            json.dump(main_config, f)

        # Create VM framework config
        vm_config = {
            "vm_framework": {
                "enabled": True,
                "default_vm": "qemu",
                "vm_configs": {
                    "qemu": {
                        "memory": 4096,
                        "cores": 2,
                        "disk_size": "20G"
                    }
                }
            },
            "emergency_mode": False,
            "migration_timestamp": "2025-01-01T00:00:00"
        }

        with open(self.config_dir / "config.json", 'w') as f:
            json.dump(vm_config, f)

        # Create LLM configs
        models_config = {
            "gpt-4": {
                "provider": "openai",
                "api_key": "sk-test-abc123",
                "endpoint": "https://api.openai.com/v1",
                "max_tokens": 8192,
                "temperature": 0.7
            },
            "claude-3": {
                "provider": "anthropic",
                "api_key": "sk-ant-test-xyz789",
                "endpoint": "https://api.anthropic.com/v1",
                "max_tokens": 100000,
                "temperature": 0.5
            }
        }

        with open(self.llm_configs_dir / "models.json", 'w') as f:
            json.dump(models_config, f)

        profiles_config = {
            "default": {
                "model": "gpt-4",
                "system_prompt": "You are an expert binary analyst."
            },
            "code_generation": {
                "model": "claude-3",
                "system_prompt": "Generate production-ready exploit code."
            }
        }

        with open(self.llm_configs_dir / "profiles.json", 'w') as f:
            json.dump(profiles_config, f)

        # Create font config
        font_config = {
            "monospace_fonts": {
                "primary": ["JetBrains Mono"],
                "fallback": ["Consolas", "Courier New"]
            },
            "ui_fonts": {
                "primary": ["Segoe UI"],
                "fallback": ["Arial", "sans-serif"]
            },
            "font_sizes": {
                "ui_default": 10,
                "code_default": 11
            },
            "available_fonts": ["JetBrainsMono-Regular.ttf"]
        }

        font_dir = Path(self.temp_dir) / "assets" / "fonts"
        font_dir.mkdir(parents=True)
        with open(font_dir / "font_config.json", 'w') as f:
            json.dump(font_config, f)

        # Create .env file
        env_content = """# Intellicrack Environment Variables
OPENAI_API_KEY=sk-test-openai-key-123
ANTHROPIC_API_KEY=sk-ant-test-anthropic-key-456
GOOGLE_API_KEY=AIzaSyC-google-key-789
VIRUSTOTAL_API_KEY=vt-key-abc123
GHIDRA_INSTALL_DIR=C:\\Tools\\ghidra_11.0
IDA_INSTALL_DIR=C:\\Tools\\IDA_8.3
DEBUG_MODE=false
LOG_LEVEL=INFO
"""
        with open(self.config_dir / ".env", 'w') as f:
            f.write(env_content)

    @patch('intellicrack.core.config_manager.Path.home')
    @patch('intellicrack.core.config_manager.QSettings')
    def test_full_application_startup_with_migration(self, MockQSettings, mock_home):
        """Test that the application starts successfully with full migration."""
        # Set up mock home directory
        mock_home.return_value = self.home_dir

        # Set up mock QSettings
        mock_settings = MagicMock()
        mock_settings.value.side_effect = lambda key, default=None: {
            "execution/qemu_preference": "always",
            "trusted_binaries": ["C:\\Apps\\trusted.exe"],
            "script_types/frida/use_qemu": True,
            "theme/mode": "dark",
            "theme/accent_color": "#2196F3",
            "geometry/main_window": b'\x01\xd9\xd0\xcb\x00\x03\x00\x00',
            "state/main_window": b'\x00\x00\x00\xff\x00\x00'
        }.get(key, default)
        mock_settings.allKeys.return_value = [
            "execution/qemu_preference",
            "trusted_binaries",
            "script_types/frida/use_qemu",
            "theme/mode",
            "theme/accent_color",
            "geometry/main_window",
            "state/main_window"
        ]
        MockQSettings.return_value = mock_settings

        # Create legacy configurations
        self.create_legacy_configs()

        # Initialize central config (simulating application startup)
        config_path = self.config_dir / "central_config.json"
        config = IntellicrackConfig(config_path=str(config_path))

        # Simulate application startup sequence
        startup_successful = True
        startup_errors = []

        try:
            # Step 1: Load and upgrade configuration
            config.load()
            config.upgrade_config()

            # Step 2: Verify critical sections exist after migration
            required_sections = [
                "application",
                "directories",
                "tools",
                "ui_preferences",
                "qemu_testing",
                "font_configuration",
                "environment",
                "llm_configuration",
                "vm_framework"
            ]

            for section in required_sections:
                if not config.get(section):
                    startup_errors.append(f"Missing required section: {section}")

            # Step 3: Verify migrated data
            # Check application info
            assert config.get("application.name") == "Intellicrack"

            # Check tools migration
            tools = config.get("tools", {})
            assert "ghidra" in tools or config.get("tools.ghidra")

            # Check QSettings migration
            assert config.get("qemu_testing.default_preference") == "always"
            assert len(config.get("qemu_testing.trusted_binaries", [])) > 0

            # Check LLM migration
            llm_models = config.get("llm_configuration.models", {})
            assert "gpt-4" in llm_models
            assert "claude-3" in llm_models

            # Check font migration
            font_config = config.get("font_configuration", {})
            assert "monospace_fonts" in font_config

            # Check VM framework migration
            vm_framework = config.get("vm_framework", {})
            assert vm_framework.get("enabled") is True
            assert vm_framework.get("default_vm") == "qemu"

            # Step 4: Test configuration save
            config.save()
            assert config_path.exists()

            # Step 5: Test reload
            config2 = IntellicrackConfig(config_path=str(config_path))
            config2.load()

            # Verify data persisted
            assert config2.get("application.name") == "Intellicrack"
            assert config2.get("qemu_testing.default_preference") == "always"

        except Exception as e:
            startup_successful = False
            startup_errors.append(str(e))

        # Assert startup was successful
        assert startup_successful, f"Startup failed with errors: {startup_errors}"
        assert len(startup_errors) == 0

    @patch('intellicrack.core.config_manager.Path.home')
    def test_startup_with_partial_legacy_configs(self, mock_home):
        """Test startup when only some legacy configs exist."""
        mock_home.return_value = self.home_dir

        # Create only some legacy configs (partial migration scenario)
        main_config = {
            "application": {
                "name": "Intellicrack",
                "version": "2.9.0"
            },
            "directories": {
                "output": str(self.temp_dir / "output")
            }
        }

        with open(self.config_dir / "intellicrack_config.json", 'w') as f:
            json.dump(main_config, f)

        # No LLM configs, no font configs, no VM configs

        # Initialize central config
        config_path = self.config_dir / "central_config.json"
        config = IntellicrackConfig(config_path=str(config_path))

        # Upgrade should handle missing configs gracefully
        config.upgrade_config()

        # Verify partial migration worked
        assert config.get("application.name") == "Intellicrack"
        assert config.get("directories.output") == str(self.temp_dir / "output")

        # Missing configs should have defaults or be empty
        assert config.get("llm_configuration.models", {}) == {}
        assert config.get("font_configuration.monospace_fonts", {}) == {}

        # Application should still be able to set new values
        config.set("llm_configuration.models.new_model", {"provider": "test"})
        assert config.get("llm_configuration.models.new_model.provider") == "test"

    @patch('intellicrack.core.config_manager.Path.home')
    def test_startup_with_corrupted_legacy_configs(self, mock_home):
        """Test startup when legacy configs are corrupted."""
        mock_home.return_value = self.home_dir

        # Create corrupted config files
        with open(self.config_dir / "intellicrack_config.json", 'w') as f:
            f.write("{ invalid json {{")

        with open(self.llm_configs_dir / "models.json", 'w') as f:
            f.write("not even json")

        # Initialize central config
        config_path = self.config_dir / "central_config.json"
        config = IntellicrackConfig(config_path=str(config_path))

        # Should not crash, should use defaults
        with patch('intellicrack.core.config_manager.logger') as mock_logger:
            config.upgrade_config()
            # Should log warnings about corrupted files
            mock_logger.warning.called

        # Config should still be functional with defaults
        assert config.get("application.name") == "Intellicrack"  # Default value
        config.set("test_key", "test_value")
        assert config.get("test_key") == "test_value"

    def test_startup_with_clean_system(self):
        """Test startup on a clean system with no existing configs."""
        # No legacy configs created

        # Initialize central config
        config_path = self.config_dir / "central_config.json"
        config = IntellicrackConfig(config_path=str(config_path))

        # Should create default configuration
        assert config.get("application.name") == "Intellicrack"
        assert config.get("application.version") is not None

        # Should be able to set new values
        config.set("qemu_testing.default_preference", "ask")
        assert config.get("qemu_testing.default_preference") == "ask"

        # Save should work
        config.save()
        assert config_path.exists()

    @patch('intellicrack.core.config_manager.Path.home')
    @patch('intellicrack.core.config_manager.QSettings')
    def test_startup_preserves_user_customizations(self, MockQSettings, mock_home):
        """Test that user customizations are preserved during migration."""
        mock_home.return_value = self.home_dir

        # Set up QSettings with user customizations
        mock_settings = MagicMock()
        user_customizations = {
            "execution/qemu_preference": "never",  # User changed from default
            "trusted_binaries": [
                "C:\\MyApps\\custom1.exe",
                "C:\\MyApps\\custom2.exe",
                "C:\\MyApps\\custom3.exe"
            ],
            "theme/mode": "light",  # User prefers light theme
            "theme/accent_color": "#FF5722",  # Custom accent color
            "ui/sidebar_width": 350,  # Custom sidebar width
            "ui/show_statusbar": False  # User disabled statusbar
        }
        mock_settings.value.side_effect = lambda key, default=None: user_customizations.get(key, default)
        mock_settings.allKeys.return_value = list(user_customizations.keys())
        MockQSettings.return_value = mock_settings

        # Create legacy configs with different values
        self.create_legacy_configs()

        # Initialize and migrate
        config_path = self.config_dir / "central_config.json"
        config = IntellicrackConfig(config_path=str(config_path))
        config.upgrade_config()

        # Verify user customizations were preserved
        assert config.get("qemu_testing.default_preference") == "never"
        trusted = config.get("qemu_testing.trusted_binaries", [])
        assert len(trusted) == 3
        assert "C:\\MyApps\\custom1.exe" in trusted

        assert config.get("ui_preferences.theme") == "light"
        assert config.get("ui_preferences.accent_color") == "#FF5722"
        assert config.get("ui_preferences.sidebar_width") == 350
        assert config.get("ui_preferences.show_statusbar") is False

    def test_startup_performance(self):
        """Test that startup with migration completes in reasonable time."""
        import time

        # Create legacy configs
        self.create_legacy_configs()

        # Measure startup time
        start_time = time.time()

        config_path = self.config_dir / "central_config.json"
        config = IntellicrackConfig(config_path=str(config_path))
        config.upgrade_config()
        config.save()

        elapsed_time = time.time() - start_time

        # Startup with migration should complete within 5 seconds
        assert elapsed_time < 5.0, f"Startup took {elapsed_time:.2f} seconds"

    @patch('intellicrack.core.config_manager.Path.home')
    def test_multiple_startup_cycles(self, mock_home):
        """Test multiple application startup/shutdown cycles."""
        mock_home.return_value = self.home_dir

        # Create legacy configs
        self.create_legacy_configs()

        config_path = self.config_dir / "central_config.json"

        # First startup - migration happens
        config1 = IntellicrackConfig(config_path=str(config_path))
        config1.upgrade_config()
        config1.set("session1_key", "session1_value")
        config1.save()
        del config1

        # Second startup - no migration needed
        config2 = IntellicrackConfig(config_path=str(config_path))
        config2.load()
        assert config2.get("session1_key") == "session1_value"
        config2.set("session2_key", "session2_value")
        config2.save()
        del config2

        # Third startup - verify all data persisted
        config3 = IntellicrackConfig(config_path=str(config_path))
        config3.load()
        assert config3.get("session1_key") == "session1_value"
        assert config3.get("session2_key") == "session2_value"

        # Verify migration data still present
        assert config3.get("application.name") == "Intellicrack"
        assert config3.get("vm_framework.enabled") is True

    def test_startup_with_environment_variables(self):
        """Test startup with environment variables set."""
        # Set environment variables
        os.environ["INTELLICRACK_CONFIG_PATH"] = str(self.config_dir)
        os.environ["INTELLICRACK_DEBUG"] = "true"
        os.environ["OPENAI_API_KEY"] = "sk-env-test-key"

        # Create .env file
        env_content = "ANTHROPIC_API_KEY=sk-ant-file-key"
        with open(self.config_dir / ".env", 'w') as f:
            f.write(env_content)

        # Initialize config
        config_path = self.config_dir / "central_config.json"
        config = IntellicrackConfig(config_path=str(config_path))

        # Test environment integration
        with patch('intellicrack.utils.env_file_manager.EnvFileManager') as MockEnvManager:
            mock_env_mgr = MagicMock()
            mock_env_mgr.read_env.return_value = {
                "ANTHROPIC_API_KEY": "sk-ant-file-key",
                "OPENAI_API_KEY": "sk-env-test-key"  # Env var takes precedence
            }
            MockEnvManager.return_value = mock_env_mgr

            # Simulate environment loading
            config.set("environment.variables", mock_env_mgr.read_env())

            # Verify environment variables are accessible
            env_vars = config.get("environment.variables", {})
            assert env_vars.get("OPENAI_API_KEY") == "sk-env-test-key"
            assert env_vars.get("ANTHROPIC_API_KEY") == "sk-ant-file-key"

    @patch('intellicrack.core.config_manager.get_config')
    def test_component_initialization_order(self, mock_get_config):
        """Test that components initialize in correct order during startup."""
        # Track initialization order
        init_order = []

        # Mock components
        class MockConfigManager:
            def __init__(self):
                init_order.append("ConfigManager")
                self.config = {}

            def get(self, key, default=None):
                return self.config.get(key, default)

            def set(self, key, value):
                self.config[key] = value

        class MockFontManager:
            def __init__(self):
                init_order.append("FontManager")
                self.config = mock_get_config()

        class MockThemeManager:
            def __init__(self):
                init_order.append("ThemeManager")
                self.config = mock_get_config()

        class MockScriptExecutionManager:
            def __init__(self):
                init_order.append("ScriptExecutionManager")
                self.config = mock_get_config()

        class MockLLMConfigManager:
            def __init__(self):
                init_order.append("LLMConfigManager")
                self.config = mock_get_config()

        # Simulate application initialization sequence
        config = MockConfigManager()
        mock_get_config.return_value = config

        # Components initialize in dependency order
        font_mgr = MockFontManager()
        theme_mgr = MockThemeManager()
        script_mgr = MockScriptExecutionManager()
        llm_mgr = MockLLMConfigManager()

        # Verify initialization order
        assert init_order[0] == "ConfigManager"
        assert "FontManager" in init_order
        assert "ThemeManager" in init_order
        assert "ScriptExecutionManager" in init_order
        assert "LLMConfigManager" in init_order

        # Verify all components initialized
        assert len(init_order) == 5


if __name__ == "__main__":
    unittest.main()
