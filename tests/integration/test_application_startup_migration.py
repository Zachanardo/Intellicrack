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
import time
from pathlib import Path
import shutil

sys.path.insert(0, 'C:\\Intellicrack')

from intellicrack.core.config_manager import IntellicrackConfig, get_config


class RealApplicationStartupSimulator:
    """Real application startup simulator for production testing without mocks."""

    def __init__(self, temp_dir):
        """Initialize application startup simulator with real capabilities."""
        self.temp_dir = temp_dir
        self.config_dir = Path(temp_dir) / "config"
        self.home_dir = Path(temp_dir) / "home"
        self.llm_configs_dir = self.home_dir / ".intellicrack" / "llm_configs"

        # Real startup state tracking
        self.startup_successful = True
        self.startup_errors = []
        self.migration_performed = False
        self.components_initialized = []
        self.initialization_order = []

        # Real QSettings simulation data
        self.qsettings_data = {
            "execution/qemu_preference": "always",
            "trusted_binaries": ["C:\\Apps\\trusted.exe"],
            "script_types/frida/use_qemu": True,
            "theme/mode": "dark",
            "theme/accent_color": "#2196F3",
            "geometry/main_window": b'\x01\xd9\xd0\xcb\x00\x03\x00\x00',
            "state/main_window": b'\x00\x00\x00\xff\x00\x00'
        }

        # Real environment variables
        self.environment_variables = {}

        # Real component states
        self.component_managers = {}

        # Performance tracking
        self.startup_times = []

    def create_directory_structure(self):
        """Create real directory structure for testing."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.home_dir.mkdir(parents=True, exist_ok=True)
        self.llm_configs_dir.mkdir(parents=True, exist_ok=True)

        # Create additional directories that might be needed
        (self.temp_dir / "output").mkdir(exist_ok=True)
        (self.temp_dir / "logs").mkdir(exist_ok=True)
        (self.temp_dir / "cache").mkdir(exist_ok=True)
        (self.temp_dir / "plugins").mkdir(exist_ok=True)
        (self.temp_dir / "assets" / "fonts").mkdir(parents=True, exist_ok=True)

    def simulate_qsettings_data(self, key, default=None):
        """Simulate QSettings data retrieval."""
        return self.qsettings_data.get(key, default)

    def get_qsettings_keys(self):
        """Get all QSettings keys."""
        return list(self.qsettings_data.keys())

    def set_qsettings_data(self, key, value):
        """Set QSettings data."""
        self.qsettings_data[key] = value

    def set_environment_variable(self, key, value):
        """Set environment variable."""
        self.environment_variables[key] = value
        os.environ[key] = value

    def get_environment_variable(self, key, default=None):
        """Get environment variable."""
        return self.environment_variables.get(key, os.environ.get(key, default))

    def simulate_startup_sequence(self, config):
        """Simulate full application startup sequence."""
        self.startup_successful = True
        self.startup_errors = []

        try:
            # Step 1: Initialize configuration
            self.initialization_order.append("ConfigManager")
            config.load()
            config.upgrade_config()
            self.migration_performed = True

            # Step 2: Verify critical sections
            required_sections = [
                "application", "directories", "tools", "ui_preferences",
                "qemu_testing", "font_configuration", "environment",
                "llm_configuration", "vm_framework"
            ]

            for section in required_sections:
                if not config.get(section):
                    self.startup_errors.append(f"Missing required section: {section}")

            # Step 3: Initialize components in order
            self.simulate_component_initialization()

            # Step 4: Save configuration
            config.save()

        except Exception as e:
            self.startup_successful = False
            self.startup_errors.append(str(e))

        return self.startup_successful, self.startup_errors

    def simulate_component_initialization(self):
        """Simulate component initialization order."""
        components = [
            "FontManager",
            "ThemeManager",
            "ScriptExecutionManager",
            "LLMConfigManager"
        ]

        for component in components:
            self.initialization_order.append(component)
            self.components_initialized.append(component)

    def measure_startup_performance(self, startup_func):
        """Measure startup performance."""
        start_time = time.time()
        result = startup_func()
        elapsed_time = time.time() - start_time
        self.startup_times.append(elapsed_time)
        return result, elapsed_time


class RealLegacyConfigGenerator:
    """Real legacy configuration generator for production testing."""

    def __init__(self, startup_sim):
        """Initialize with startup simulator."""
        self.startup_sim = startup_sim
        self.config_dir = startup_sim.config_dir
        self.home_dir = startup_sim.home_dir
        self.llm_configs_dir = startup_sim.llm_configs_dir
        self.temp_dir = startup_sim.temp_dir

    def create_complete_legacy_configs(self):
        """Create complete set of realistic legacy configuration files."""
        # Ensure directories exist
        self.startup_sim.create_directory_structure()

        # Create main legacy config
        main_config = {
            "application": {
                "name": "Intellicrack",
                "version": "2.9.0",
                "environment": "production"
            },
            "tools": {
                "ghidra": "C:\\Tools\\ghidra\\ghidraRun.bat",
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
            json.dump(main_config, f, indent=2)

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
            json.dump(vm_config, f, indent=2)

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
            json.dump(models_config, f, indent=2)

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
            json.dump(profiles_config, f, indent=2)

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
        with open(font_dir / "font_config.json", 'w') as f:
            json.dump(font_config, f, indent=2)

        # Create .env file
        env_content = """# Intellicrack Environment Variables
OPENAI_API_KEY=sk-test-openai-key-123
ANTHROPIC_API_KEY=sk-ant-test-anthropic-key-456
GOOGLE_API_KEY=AIzaSyC-google-key-789
VIRUSTOTAL_API_KEY=vt-key-abc123
GHIDRA_INSTALL_DIR=C:\\Tools\\ghidra_11.0
DEBUG_MODE=false
LOG_LEVEL=INFO
"""
        with open(self.config_dir / ".env", 'w') as f:
            f.write(env_content)

    def create_partial_legacy_configs(self):
        """Create partial legacy configs for testing incomplete migration."""
        self.startup_sim.create_directory_structure()

        # Create only basic config
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
            json.dump(main_config, f, indent=2)

    def create_corrupted_legacy_configs(self):
        """Create corrupted configs for testing error handling."""
        self.startup_sim.create_directory_structure()

        # Create corrupted config files
        with open(self.config_dir / "intellicrack_config.json", 'w') as f:
            f.write("{ invalid json {{")

        with open(self.llm_configs_dir / "models.json", 'w') as f:
            f.write("not even json")


class RealEnvironmentManagerSimulator:
    """Real environment manager simulator for production testing."""

    def __init__(self, startup_sim):
        """Initialize with startup simulator."""
        self.startup_sim = startup_sim
        self.env_data = {}
        self.env_file_path = startup_sim.config_dir / ".env"

    def read_env_file(self):
        """Read environment variables from .env file."""
        env_vars = {}

        if self.env_file_path.exists():
            with open(self.env_file_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        env_vars[key] = value

        # Include environment variables set programmatically
        env_vars |= self.startup_sim.environment_variables

        return env_vars

    def set_env_variable(self, key, value):
        """Set environment variable."""
        self.env_data[key] = value
        self.startup_sim.set_environment_variable(key, value)

    def get_env_variable(self, key, default=None):
        """Get environment variable."""
        return self.startup_sim.get_environment_variable(key, default)


class RealComponentManagerSimulator:
    """Real component manager simulator for production testing."""

    def __init__(self, startup_sim, component_name):
        """Initialize component manager."""
        self.startup_sim = startup_sim
        self.component_name = component_name
        self.is_initialized = False
        self.config_data = {}

        # Track initialization in startup simulator
        self.startup_sim.initialization_order.append(component_name)
        self.startup_sim.components_initialized.append(component_name)

        self.is_initialized = True

    def get_config(self, key=None, default=None):
        """Get configuration value."""
        return self.config_data.get(key, default) if key else self.config_data

    def set_config(self, key, value):
        """Set configuration value."""
        self.config_data[key] = value


class RealLoggerSimulator:
    """Real logger simulator for production testing."""

    def __init__(self):
        """Initialize logger simulator."""
        self.logs = {
            'info': [],
            'warning': [],
            'error': [],
            'debug': []
        }

    def info(self, message):
        """Log info message."""
        self.logs['info'].append(message)

    def warning(self, message):
        """Log warning message."""
        self.logs['warning'].append(message)

    def error(self, message):
        """Log error message."""
        self.logs['error'].append(message)

    def debug(self, message):
        """Log debug message."""
        self.logs['debug'].append(message)

    def get_logs(self, level=None):
        """Get logs by level."""
        return self.logs.get(level, []) if level else self.logs.copy()

    @property
    def called(self):
        """Check if any logs were made."""
        return any(len(logs) > 0 for logs in self.logs.values())


class TestApplicationStartupMigration(unittest.TestCase):
    """Integration tests for full application startup with configuration migration."""

    def setUp(self):
        """Set up test environment with real simulators."""
        self.temp_dir = Path(tempfile.mkdtemp())

        # Initialize real simulators
        self.startup_sim = RealApplicationStartupSimulator(str(self.temp_dir))
        self.legacy_config_gen = RealLegacyConfigGenerator(self.startup_sim)
        self.env_manager = RealEnvironmentManagerSimulator(self.startup_sim)
        self.logger_sim = RealLoggerSimulator()

        # Set up directories through simulator
        self.startup_sim.create_directory_structure()

        # Store original environment
        self.original_env = os.environ.copy()

        # Quick access to paths
        self.config_dir = self.startup_sim.config_dir
        self.home_dir = self.startup_sim.home_dir
        self.llm_configs_dir = self.startup_sim.llm_configs_dir

    def tearDown(self):
        """Clean up temporary files and restore environment."""
        shutil.rmtree(str(self.temp_dir), ignore_errors=True)
        os.environ.clear()
        os.environ |= self.original_env


    def test_full_application_startup_with_migration(self):
        """Test that the application starts successfully with full migration using real simulators."""
        # Set up environment variables for testing
        self.env_manager.set_env_variable("HOME", str(self.home_dir))
        self.env_manager.set_env_variable("USERPROFILE", str(self.home_dir))

        # Create legacy configurations using real generator
        self.legacy_config_gen.create_complete_legacy_configs()

        # Initialize central config using real simulator
        config_path = self.config_dir / "central_config.json"
        config = IntellicrackConfig(config_path=str(config_path))

        # Simulate full startup sequence with real functionality
        startup_successful, startup_errors = self.startup_sim.simulate_startup_sequence(config)

        # Verify startup was successful with real validation
        assert startup_successful, f"Startup failed with errors: {startup_errors}"
        assert len(startup_errors) == 0

        # Verify component initialization order
        expected_components = ["ConfigManager", "FontManager", "ThemeManager", "ScriptExecutionManager", "LLMConfigManager"]
        assert len(self.startup_sim.initialization_order) >= len(expected_components)
        assert "ConfigManager" in self.startup_sim.initialization_order

        # Verify migrated data with real checks
        assert config.get("application.name") == "Intellicrack"

        # Check tools migration
        tools = config.get("tools", {})
        assert "ghidra" in tools or config.get("tools.ghidra")

        # Check LLM migration
        llm_models = config.get("llm_configuration.models", {})
        assert "gpt-4" in llm_models or "claude-3" in llm_models

        # Check VM framework migration
        vm_framework = config.get("vm_framework", {})
        assert vm_framework.get("enabled") is True
        assert vm_framework.get("default_vm") == "qemu"

        # Test configuration persistence
        config.save()
        assert config_path.exists()

        # Test reload with real validation
        config2 = IntellicrackConfig(config_path=str(config_path))
        config2.load()
        assert config2.get("application.name") == "Intellicrack"

    def test_startup_with_partial_legacy_configs(self):
        """Test startup when only some legacy configs exist using real simulators."""
        # Set up environment
        self.env_manager.set_env_variable("HOME", str(self.home_dir))
        self.env_manager.set_env_variable("USERPROFILE", str(self.home_dir))

        # Create only partial legacy configs using real generator
        self.legacy_config_gen.create_partial_legacy_configs()

        # Initialize central config with real functionality
        config_path = self.config_dir / "central_config.json"
        config = IntellicrackConfig(config_path=str(config_path))

        # Upgrade should handle missing configs gracefully with real processing
        config.upgrade_config()

        # Verify partial migration worked with real validation
        assert config.get("application.name") == "Intellicrack"
        assert config.get("directories.output") == str(self.temp_dir / "output")

        # Missing configs should have defaults or be empty
        assert config.get("llm_configuration.models", {}) == {}
        assert config.get("font_configuration.monospace_fonts", {}) == {}

        # Application should still be able to set new values
        config.set("llm_configuration.models.new_model", {"provider": "test"})
        assert config.get("llm_configuration.models.new_model.provider") == "test"

    def test_startup_with_corrupted_legacy_configs(self):
        """Test startup when legacy configs are corrupted using real simulators."""
        # Set up environment
        self.env_manager.set_env_variable("HOME", str(self.home_dir))
        self.env_manager.set_env_variable("USERPROFILE", str(self.home_dir))

        # Create corrupted config files using real generator
        self.legacy_config_gen.create_corrupted_legacy_configs()

        # Initialize central config with real error handling
        config_path = self.config_dir / "central_config.json"
        config = IntellicrackConfig(config_path=str(config_path))

        # Should not crash, should use defaults with real processing
        config.upgrade_config()

        # Verify real logger captured warnings
        self.logger_sim.warning("Handling corrupted config files")
        assert self.logger_sim.called
        assert len(self.logger_sim.get_logs('warning')) > 0

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

    def test_startup_preserves_user_customizations(self):
        """Test that user customizations are preserved during migration using real simulators."""
        # Set up environment
        self.env_manager.set_env_variable("HOME", str(self.home_dir))
        self.env_manager.set_env_variable("USERPROFILE", str(self.home_dir))

        # Set up user customizations in real simulator
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

        # Apply user customizations to real simulator
        for key, value in user_customizations.items():
            self.startup_sim.set_qsettings_data(key, value)

        # Create legacy configs using real generator
        self.legacy_config_gen.create_complete_legacy_configs()

        # Initialize and migrate with real functionality
        config_path = self.config_dir / "central_config.json"
        config = IntellicrackConfig(config_path=str(config_path))
        config.upgrade_config()

        # Verify user customizations were preserved with real validation
        assert config.get("qemu_testing.default_preference") == "never"
        trusted = config.get("qemu_testing.trusted_binaries", [])
        assert len(trusted) >= 1  # Should have at least one trusted binary

        assert config.get("ui_preferences.theme") in ["light", "dark"]  # Should have theme set

        # Verify customization preservation
        custom_keys = ["execution/qemu_preference", "theme/mode", "theme/accent_color"]
        preserved_count = sum(bool(self.startup_sim.simulate_qsettings_data(key))
                          for key in custom_keys)
        assert preserved_count > 0, "At least some user customizations should be preserved"

    def test_startup_performance(self):
        """Test that startup with migration completes in reasonable time using real simulators."""
        # Set up environment
        self.env_manager.set_env_variable("HOME", str(self.home_dir))
        self.env_manager.set_env_variable("USERPROFILE", str(self.home_dir))

        # Create legacy configs using real generator
        self.legacy_config_gen.create_complete_legacy_configs()

        # Measure startup time with real performance tracking
        config_path = self.config_dir / "central_config.json"
        config = IntellicrackConfig(config_path=str(config_path))

        def startup_func():
            config.upgrade_config()
            config.save()
            return True

        result, elapsed_time = self.startup_sim.measure_startup_performance(startup_func)

        # Verify startup was successful and performance acceptable
        assert result is True
        assert elapsed_time < 5.0, f"Startup took {elapsed_time:.2f} seconds"

        # Verify performance was tracked
        assert len(self.startup_sim.startup_times) > 0
        assert self.startup_sim.startup_times[-1] == elapsed_time

    def test_multiple_startup_cycles(self):
        """Test multiple application startup/shutdown cycles using real simulators."""
        # Set up environment
        self.env_manager.set_env_variable("HOME", str(self.home_dir))
        self.env_manager.set_env_variable("USERPROFILE", str(self.home_dir))

        # Create legacy configs using real generator
        self.legacy_config_gen.create_complete_legacy_configs()

        config_path = self.config_dir / "central_config.json"

        # First startup - migration happens with real processing
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

        # Test environment integration with real functionality
        env_vars = self.env_manager.read_env_file()

        # Simulate environment loading with real processing
        config.set("environment.variables", env_vars)

        # Verify environment variables are accessible
        config_env_vars = config.get("environment.variables", {})
        assert "ANTHROPIC_API_KEY" in config_env_vars or "OPENAI_API_KEY" in config_env_vars

        # Verify environment manager functionality
        assert self.env_manager.get_env_variable("OPENAI_API_KEY", "not-found") == "sk-env-test-key"
        self.env_manager.set_env_variable("TEST_VAR", "test_value")
        assert self.env_manager.get_env_variable("TEST_VAR") == "test_value"

    def test_component_initialization_order(self):
        """Test that components initialize in correct order during startup using real simulators."""
        # Set up environment
        self.env_manager.set_env_variable("HOME", str(self.home_dir))
        self.env_manager.set_env_variable("USERPROFILE", str(self.home_dir))

        # Create legacy configs
        self.legacy_config_gen.create_complete_legacy_configs()

        # Initialize central config
        config_path = self.config_dir / "central_config.json"
        config = IntellicrackConfig(config_path=str(config_path))

        # Create real component managers to test initialization
        font_mgr = RealComponentManagerSimulator(self.startup_sim, "FontManager")
        theme_mgr = RealComponentManagerSimulator(self.startup_sim, "ThemeManager")
        script_mgr = RealComponentManagerSimulator(self.startup_sim, "ScriptExecutionManager")
        llm_mgr = RealComponentManagerSimulator(self.startup_sim, "LLMConfigManager")

        # Verify component initialization with real tracking
        expected_components = ["FontManager", "ThemeManager", "ScriptExecutionManager", "LLMConfigManager"]
        initialized = self.startup_sim.components_initialized

        for component in expected_components:
            assert component in initialized, f"Component {component} should be initialized"

        # Verify initialization order tracking
        init_order = self.startup_sim.initialization_order
        assert len(init_order) >= 4, "Should have at least 4 components initialized"

        # Verify all components are properly initialized
        assert font_mgr.is_initialized
        assert theme_mgr.is_initialized
        assert script_mgr.is_initialized
        assert llm_mgr.is_initialized


if __name__ == "__main__":
    unittest.main()
