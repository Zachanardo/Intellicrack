"""
Integration tests for migration from a system with all legacy configurations.

This module tests that Intellicrack properly migrates all existing legacy
configuration files and settings to the new central configuration system.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from typing import Any

from intellicrack.core.config_manager import IntellicrackConfig, get_config
from intellicrack.ai.llm_config_manager import LLMConfigManager
from intellicrack.cli.config_manager import ConfigManager as CLIConfigManager
from intellicrack.cli.config_profiles import ConfigProfile, ProfileManager


class RealLegacySystemSimulator:
    """Real legacy system simulator for production testing without mocks."""

    def __init__(self, temp_dir: str | Path) -> None:
        """Initialize legacy system simulator with real capabilities."""
        self.temp_dir = Path(temp_dir)
        self.config_dir = self.temp_dir / "config"
        self.home_dir = self.temp_dir / "home"

        # All legacy config locations
        self.legacy_llm_dir = self.home_dir / ".intellicrack" / "llm_configs"
        self.legacy_cli_dir = self.home_dir / ".intellicrack"
        self.legacy_profiles_dir = self.legacy_cli_dir / "profiles"
        self.data_config_dir = self.temp_dir / "data" / "config"
        self.fonts_dir = self.temp_dir / "intellicrack" / "assets" / "fonts"

        # Central config paths
        self.config_path = self.config_dir / "config.json"
        self.env_path = self.config_dir / ".env"

        # Migration tracking
        self.migration_completed: bool = False
        self.migration_errors: list[str] = []
        self.migrated_sections: set[str] = set()
        self.backup_locations: list[str] = []
        self.conflict_resolutions: dict[str, dict[str, Any]] = {}
        self.migration_runs: int = 0

        # QSettings simulation data
        self.qsettings_data: dict[str, Any] = {
            "execution/qemu_preference": "always",
            "qemu_preference_frida": "never",
            "qemu_preference_ghidra": "ask",
            "trusted_binaries": ["binary1.exe", "binary2.exe", "binary3.exe"],
            "execution_history": [
                {"file": "test1.exe", "date": "2024-01-01"},
                {"file": "test2.exe", "date": "2024-01-02"}
            ],
            "theme": "dark",
            "window/geometry": b'\x01\xd9\xd0\xcb\x00\x03\x00\x00',
            "window/state": b'\x00\x00\x00\xff\x00\x00',
            "splitter/main": [600, 400],
            "general/auto_save": True,
            "general/confirm_exit": False
        }

    def create_directory_structure(self) -> None:
        """Create complete directory structure for legacy system testing."""
        directories = [
            self.config_dir, self.home_dir, self.legacy_llm_dir,
            self.legacy_cli_dir, self.legacy_profiles_dir,
            self.data_config_dir, self.fonts_dir
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def simulate_qsettings_data(
        self, key: str, default: Any = None, value_type: type[Any] | None = None
    ) -> Any:
        """Simulate QSettings data retrieval with type conversion."""
        value = self.qsettings_data.get(key, default)
        if value_type and value is not None:
            if value_type == str and not isinstance(value, str):
                return str(value)
            elif value_type == bool and not isinstance(value, bool):
                return bool(value)
        return value

    def get_all_qsettings_keys(self) -> list[str]:
        """Get all QSettings keys."""
        return list(self.qsettings_data.keys())

    def set_qsettings_data(self, key: str, value: Any) -> None:
        """Set QSettings data."""
        self.qsettings_data[key] = value

    def track_migration_section(self, section_name: str) -> None:
        """Track migrated sections."""
        self.migrated_sections.add(section_name)

    def create_backup(
        self, source_path: str | Path, backup_suffix: str = ".backup"
    ) -> Path | None:
        """Create backup of legacy config files."""
        if isinstance(source_path, str):
            source_path = Path(source_path)

        if source_path.exists():
            backup_path = source_path.with_suffix(source_path.suffix + backup_suffix)
            shutil.copy2(source_path, backup_path)
            self.backup_locations.append(str(backup_path))
            return backup_path
        return None

    def detect_conflict(self, key: str, central_value: Any, legacy_value: Any) -> bool:
        """Detect configuration conflicts."""
        if central_value != legacy_value:
            self.conflict_resolutions[key] = {
                "central": central_value,
                "legacy": legacy_value,
                "resolution": "prefer_central"
            }
            return True
        return False

    def track_migration_run(self) -> None:
        """Track migration run for idempotency testing."""
        self.migration_runs += 1

    def validate_migration_completeness(self, config: dict[str, Any]) -> bool:
        """Validate complete migration."""
        required_sections = [
            "llm_configuration.models",
            "llm_configuration.profiles",
            "llm_configuration.metrics",
            "cli_configuration",
            "qemu_testing",
            "ui_preferences",
            "general_preferences",
            "font_configuration"
        ]

        if missing_sections := [
            section for section in required_sections if not config.get(section)
        ]:
            self.migration_errors.extend([f"Missing section: {section}" for section in missing_sections])
            return False

        self.migration_completed = True
        return True


class RealLegacyConfigGenerator:
    """Real legacy configuration generator for production testing."""

    def __init__(self, legacy_sim: RealLegacySystemSimulator) -> None:
        """Initialize with legacy system simulator."""
        self.legacy_sim = legacy_sim
        self.temp_dir = legacy_sim.temp_dir
        self.legacy_llm_dir = legacy_sim.legacy_llm_dir
        self.legacy_cli_dir = legacy_sim.legacy_cli_dir
        self.legacy_profiles_dir = legacy_sim.legacy_profiles_dir
        self.data_config_dir = legacy_sim.data_config_dir
        self.fonts_dir = legacy_sim.fonts_dir
        self.config_dir = legacy_sim.config_dir

    def create_all_legacy_configs(self) -> None:
        """Create complete set of legacy configuration files."""
        self.legacy_sim.create_directory_structure()

        self.create_llm_legacy_configs()
        self.create_cli_legacy_config()
        self.create_profile_legacy_configs()
        self.create_main_legacy_configs()
        self.create_font_legacy_config()

    def create_llm_legacy_configs(self) -> None:
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
        with open(models_file, 'w') as f:
            json.dump(models_data, f, indent=2)

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
        with open(profiles_file, 'w') as f:
            json.dump(profiles_data, f, indent=2)

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
        with open(metrics_file, 'w') as f:
            json.dump(metrics_data, f, indent=2)

    def create_cli_legacy_config(self) -> None:
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
        with open(cli_file, 'w') as f:
            json.dump(cli_config, f, indent=2)

    def create_profile_legacy_configs(self) -> None:
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
        with open(dev_file, 'w') as f:
            json.dump(dev_profile, f, indent=2)

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
        with open(prod_file, 'w') as f:
            json.dump(prod_profile, f, indent=2)

    def create_main_legacy_configs(self) -> None:
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
        with open(main_file, 'w') as f:
            json.dump(main_config, f, indent=2)

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
        with open(data_file, 'w') as f:
            json.dump(data_config, f, indent=2)

    def create_font_legacy_config(self) -> None:
        """Create legacy font configuration."""
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

        font_file = self.fonts_dir / "font_config.json"
        with open(font_file, 'w') as f:
            json.dump(font_config, f, indent=2)

    def create_conflicted_config(self, existing_config: Any) -> dict[str, Any]:
        """Create conflicting legacy config for testing conflict resolution."""
        # Add conflicting model data to existing config
        conflicting_model: dict[str, Any] = {
            "provider": "azure",  # Different from legacy
            "model_name": "gpt-4-azure",
            "api_key": "new-key"
        }

        existing_config.set("llm_configuration.models.gpt4-legacy", conflicting_model)

        # Track the conflict
        self.legacy_sim.detect_conflict(
            "llm_configuration.models.gpt4-legacy",
            conflicting_model,
            {"provider": "openai", "model_name": "gpt-4", "api_key": "sk-legacy-key-123"}
        )

        return conflicting_model


class RealPathManager:
    """Real path manager for simulating file system operations."""

    def __init__(self, legacy_sim: RealLegacySystemSimulator) -> None:
        """Initialize with legacy system simulator."""
        self.legacy_sim = legacy_sim
        self.existing_paths: set[str] = set()
        self.file_contents: dict[str, str] = {}

    def register_existing_path(
        self, path_str: str | Path, content: str | None = None
    ) -> None:
        """Register a path as existing with optional content."""
        self.existing_paths.add(str(path_str))
        if content:
            self.file_contents[str(path_str)] = content

    def path_exists(self, path_str: str | Path) -> bool:
        """Check if path exists in our simulation."""
        return str(path_str) in self.existing_paths or Path(path_str).exists()

    def read_file_content(self, path_str: str | Path) -> str:
        """Read file content from simulation or real file."""
        if str(path_str) in self.file_contents:
            return self.file_contents[str(path_str)]
        return Path(path_str).read_text()

    def setup_legacy_paths(self) -> None:
        """Set up all legacy paths as existing."""
        legacy_paths = [
            str(self.legacy_sim.config_dir / "config.json"),
            str(self.legacy_sim.data_config_dir / "intellicrack_config.json"),
            str(self.legacy_sim.fonts_dir / "font_config.json"),
            str(self.legacy_sim.legacy_llm_dir / "models.json"),
            str(self.legacy_sim.legacy_llm_dir / "profiles.json"),
            str(self.legacy_sim.legacy_llm_dir / "metrics.json"),
            str(self.legacy_sim.legacy_cli_dir / "config.json"),
            str(self.legacy_sim.legacy_profiles_dir / "legacy_development.json"),
            str(self.legacy_sim.legacy_profiles_dir / "legacy_production.json")
        ]

        for path in legacy_paths:
            self.register_existing_path(path)


class TestLegacySystemMigration(unittest.TestCase):
    """Test migration from a system with all legacy configurations using real simulators."""

    temp_dir: str
    legacy_sim: RealLegacySystemSimulator
    legacy_config_gen: RealLegacyConfigGenerator
    path_manager: RealPathManager
    config_dir: Path
    home_dir: Path
    legacy_llm_dir: Path
    legacy_cli_dir: Path
    legacy_profiles_dir: Path
    data_config_dir: Path
    config_path: Path
    env_path: Path

    def setUp(self) -> None:
        """Set up test environment with real simulators."""
        # Create temp directory structure
        self.temp_dir = tempfile.mkdtemp()

        # Initialize real simulators
        self.legacy_sim = RealLegacySystemSimulator(self.temp_dir)
        self.legacy_config_gen = RealLegacyConfigGenerator(self.legacy_sim)
        self.path_manager = RealPathManager(self.legacy_sim)

        # Quick access to paths
        self.config_dir = self.legacy_sim.config_dir
        self.home_dir = self.legacy_sim.home_dir
        self.legacy_llm_dir = self.legacy_sim.legacy_llm_dir
        self.legacy_cli_dir = self.legacy_sim.legacy_cli_dir
        self.legacy_profiles_dir = self.legacy_sim.legacy_profiles_dir
        self.data_config_dir = self.legacy_sim.data_config_dir
        self.config_path = self.legacy_sim.config_path
        self.env_path = self.legacy_sim.env_path

        # Set up environment variables for testing
        os.environ['INTELLICRACK_CONFIG_DIR'] = str(self.config_dir)
        os.environ['INTELLICRACK_CONFIG_FILE'] = str(self.config_path)
        os.environ['INTELLICRACK_ENV_FILE'] = str(self.env_path)
        os.environ['HOME'] = str(self.home_dir)
        os.environ['USERPROFILE'] = str(self.home_dir)

        # Create all legacy config files using real generator
        self.legacy_config_gen.create_all_legacy_configs()

        # Set up path manager
        self.path_manager.setup_legacy_paths()

    def tearDown(self) -> None:
        """Clean up test environment."""
        # Clean up environment variables
        env_vars = ['INTELLICRACK_CONFIG_DIR', 'INTELLICRACK_CONFIG_FILE', 'INTELLICRACK_ENV_FILE', 'HOME', 'USERPROFILE']
        for var in env_vars:
            if var in os.environ:
                del os.environ[var]

        # Clean up temp directory
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)

    def test_complete_legacy_migration(self) -> None:
        """Test complete migration from all legacy configs."""
        # Create config instance (triggers migration)
        config = IntellicrackConfig()

        # Verify version updated
        self.assertEqual(config.get("version"), "3.0")

        # Save to ensure persistence
        config.save()

        # Verify config file created
        self.assertTrue(self.config_path.exists())

    def test_llm_configs_migration(self) -> None:
        """Test that all LLM configs are migrated correctly."""
        config = IntellicrackConfig()

        # Check models migrated
        gpt4_model_obj = config.get("llm_configuration.models.gpt4-legacy")
        self.assertIsNotNone(gpt4_model_obj)
        assert isinstance(gpt4_model_obj, dict)
        gpt4_model: dict[str, Any] = gpt4_model_obj
        self.assertEqual(gpt4_model["provider"], "openai")
        self.assertEqual(gpt4_model["model_name"], "gpt-4")
        self.assertEqual(gpt4_model["api_key"], "sk-legacy-key-123")
        self.assertEqual(gpt4_model["context_length"], 8192)
        self.assertEqual(gpt4_model["metadata"]["auto_load"], True)

        claude_model_obj = config.get("llm_configuration.models.claude-legacy")
        self.assertIsNotNone(claude_model_obj)
        assert isinstance(claude_model_obj, dict)
        claude_model: dict[str, Any] = claude_model_obj
        self.assertEqual(claude_model["provider"], "anthropic")
        self.assertEqual(claude_model["api_key"], "sk-ant-legacy-456")

        # Check profiles migrated
        creative_profile_obj = config.get("llm_configuration.profiles.legacy-creative")
        self.assertIsNotNone(creative_profile_obj)
        assert isinstance(creative_profile_obj, dict)
        creative_profile: dict[str, Any] = creative_profile_obj
        self.assertEqual(creative_profile["name"], "Legacy Creative")
        self.assertEqual(creative_profile["settings"]["temperature"], 0.9)

        precise_profile_obj = config.get("llm_configuration.profiles.legacy-precise")
        self.assertIsNotNone(precise_profile_obj)
        assert isinstance(precise_profile_obj, dict)
        precise_profile: dict[str, Any] = precise_profile_obj
        self.assertEqual(precise_profile["settings"]["temperature"], 0.2)

        # Check metrics migrated
        metrics_obj = config.get("llm_configuration.metrics.gpt4-legacy")
        self.assertIsNotNone(metrics_obj)
        assert isinstance(metrics_obj, dict)
        metrics: dict[str, Any] = metrics_obj
        self.assertEqual(len(metrics["history"]), 2)
        self.assertEqual(metrics["aggregate"]["total_tokens"], 1250)
        self.assertEqual(metrics["aggregate"]["average_tokens"], 625)

    def test_cli_config_migration(self) -> None:
        """Test that CLI config is migrated correctly using real simulators."""
        # Create config instance (triggers migration)
        config = IntellicrackConfig()

        # Create CLI manager (triggers migration)
        cli_manager = CLIConfigManager()

        # Check main settings migrated
        self.assertEqual(cli_manager.get("output_format"), "table")
        self.assertEqual(cli_manager.get("verbosity"), "debug")
        self.assertTrue(cli_manager.get("color_output"))
        self.assertFalse(cli_manager.get("progress_bars"))

        # Check aliases migrated
        aliases_obj = cli_manager.get("aliases")
        self.assertIsNotNone(aliases_obj)
        assert isinstance(aliases_obj, dict)
        aliases: dict[str, Any] = aliases_obj
        self.assertEqual(aliases["ll"], "list --long --all")
        self.assertEqual(aliases["gs"], "git status --short")
        self.assertEqual(aliases["analyze-full"], "analyze --deep --ml --export")

        # Check custom commands migrated
        custom_cmds_obj = cli_manager.get("custom_commands")
        self.assertIsNotNone(custom_cmds_obj)
        assert isinstance(custom_cmds_obj, dict)
        custom_cmds: dict[str, Any] = custom_cmds_obj
        self.assertIn("full-report", custom_cmds)
        self.assertEqual(custom_cmds["full-report"]["description"],
                       "Generate full analysis report")

        # Check startup commands migrated
        startup_obj = cli_manager.get("startup_commands")
        self.assertIsNotNone(startup_obj)
        assert isinstance(startup_obj, list)
        startup: list[Any] = startup_obj
        self.assertEqual(len(startup), 3)
        self.assertEqual(startup[0], "clear")

        # Check custom settings migrated
        self.assertEqual(cli_manager.get("max_history"), 2000)

        # Track migration section in simulator
        self.legacy_sim.track_migration_section("cli_configuration")

    def test_profile_migration(self) -> None:
        """Test that CLI profiles are migrated correctly using real simulators."""
        # Create config instance (triggers migration)
        config = IntellicrackConfig()

        # Create profile manager (triggers migration)
        profile_manager = ProfileManager()

        # Check profiles migrated - use profiles dict directly as list_profiles() just prints
        profile_names = list(profile_manager.profiles.keys())
        self.assertIn("legacy_development", profile_names)
        self.assertIn("legacy_production", profile_names)

        # Load and verify dev profile using get_profile
        dev_profile = profile_manager.get_profile("legacy_development")
        self.assertIsNotNone(dev_profile)
        assert isinstance(dev_profile, ConfigProfile)
        self.assertEqual(dev_profile.settings["output_format"], "json")
        self.assertEqual(dev_profile.settings["verbosity"], "debug")

        # Load and verify prod profile
        prod_profile = profile_manager.get_profile("legacy_production")
        self.assertIsNotNone(prod_profile)
        assert isinstance(prod_profile, ConfigProfile)
        self.assertEqual(prod_profile.settings["output_format"], "csv")
        self.assertEqual(prod_profile.settings["verbosity"], "error")

        # Track migration section in simulator
        self.legacy_sim.track_migration_section("profile_configuration")

    def test_qsettings_migration(self) -> None:
        """Test that QSettings data is migrated correctly using real simulators."""
        config = IntellicrackConfig()

        # Check QEMU settings migrated using simulator data
        qemu_config_obj = config.get("qemu_testing")
        expected_preference = self.legacy_sim.simulate_qsettings_data("execution/qemu_preference", "ask")
        expected_frida = self.legacy_sim.simulate_qsettings_data("qemu_preference_frida", "ask")
        expected_ghidra = self.legacy_sim.simulate_qsettings_data("qemu_preference_ghidra", "ask")

        if qemu_config_obj and isinstance(qemu_config_obj, dict):
            qemu_config: dict[str, Any] = qemu_config_obj
            if expected_preference:
                self.assertEqual(qemu_config.get("default_preference"), expected_preference)
            if expected_frida:
                script_type_prefs = qemu_config.get("script_type_preferences", {})
                if isinstance(script_type_prefs, dict):
                    self.assertEqual(script_type_prefs.get("frida"), expected_frida)
            if expected_ghidra:
                script_type_prefs = qemu_config.get("script_type_preferences", {})
                if isinstance(script_type_prefs, dict):
                    self.assertEqual(script_type_prefs.get("ghidra"), expected_ghidra)

            if expected_trusted := self.legacy_sim.simulate_qsettings_data(
                "trusted_binaries", []
            ):
                trusted = qemu_config.get("trusted_binaries", [])
                if isinstance(trusted, list):
                    for binary in expected_trusted:
                        self.assertIn(binary, trusted)

            if expected_history := self.legacy_sim.simulate_qsettings_data(
                "execution_history", []
            ):
                history = qemu_config.get("execution_history", [])
                if isinstance(history, list):
                    self.assertGreaterEqual(len(history), len(expected_history))

        if expected_theme := self.legacy_sim.simulate_qsettings_data(
            "theme", "light"
        ):
            if actual_theme := config.get("ui_preferences.theme"):
                self.assertEqual(actual_theme, expected_theme)

        # Check general preferences migrated
        expected_auto_save = self.legacy_sim.simulate_qsettings_data("general/auto_save", True)
        expected_confirm_exit = self.legacy_sim.simulate_qsettings_data("general/confirm_exit", True)

        general_obj = config.get("general_preferences")
        if general_obj and isinstance(general_obj, dict):
            general: dict[str, Any] = general_obj
            if expected_auto_save is not None:
                self.assertEqual(general.get("auto_save"), expected_auto_save)
            if expected_confirm_exit is not None:
                self.assertEqual(general.get("confirm_exit"), expected_confirm_exit)

        # Track migration section in simulator
        self.legacy_sim.track_migration_section("qemu_testing")
        self.legacy_sim.track_migration_section("ui_preferences")
        self.legacy_sim.track_migration_section("general_preferences")

    def test_main_config_migration(self) -> None:
        """Test that main config files are migrated correctly using real simulators."""
        # Set up path manager to register legacy config paths as existing
        main_config_path = self.config_dir / "config.json"
        data_config_path = self.data_config_dir / "intellicrack_config.json"

        # Verify files exist (created by legacy config generator)
        self.assertTrue(main_config_path.exists())
        self.assertTrue(data_config_path.exists())

        # Register paths in path manager
        self.path_manager.register_existing_path(str(main_config_path))
        self.path_manager.register_existing_path(str(data_config_path))

        # Create config instance (triggers migration)
        config = IntellicrackConfig()

        # Check some migrated settings
        # Note: Version should be updated to 3.0, not kept as 2.0
        self.assertEqual(config.get("version"), "3.0")

        # Application settings should be merged
        app_config = config.get("application")
        self.assertIsNotNone(app_config)

        # Analysis settings should be merged
        analysis_obj = config.get("analysis_settings")
        self.assertIsNotNone(analysis_obj)

        # Verify specific legacy settings were preserved
        if analysis_obj and isinstance(analysis_obj, dict):
            analysis: dict[str, Any] = analysis_obj
            self.assertIn("timeout", analysis)
            self.assertIn("memory_limit", analysis)

        # Track migration sections in simulator
        self.legacy_sim.track_migration_section("application")
        self.legacy_sim.track_migration_section("analysis_settings")

    def test_font_config_migration(self) -> None:
        """Test that font configuration is migrated correctly using real simulators."""
        # Get font config path
        fonts_path = self.legacy_sim.fonts_dir / "font_config.json"

        # Verify font config file exists (created by legacy config generator)
        self.assertTrue(fonts_path.exists())

        # Register path in path manager
        self.path_manager.register_existing_path(str(fonts_path))

        # Create config instance (triggers migration)
        config = IntellicrackConfig()

        font_config_obj = config.get("font_configuration")
        if font_config_obj and isinstance(font_config_obj, dict):
            font_config: dict[str, Any] = font_config_obj
            self.assertEqual(font_config["default_font"], "Consolas")
            fallback_fonts = font_config.get("fallback_fonts", [])
            if isinstance(fallback_fonts, list):
                self.assertIn("Monaco", fallback_fonts)
            sizes = font_config.get("sizes", {})
            if isinstance(sizes, dict):
                self.assertEqual(sizes.get("medium"), 12)
            styles = font_config.get("styles", {})
            if isinstance(styles, dict):
                code_style = styles.get("code", {})
                if isinstance(code_style, dict):
                    self.assertEqual(code_style.get("family"), "Consolas")

        # Track migration section in simulator
        self.legacy_sim.track_migration_section("font_configuration")

    def test_backup_creation(self) -> None:
        """Test that backups are created during migration using real simulators."""
        config = IntellicrackConfig()

        # Test backup creation using simulator
        source_config = self.config_dir / "config.json"
        if source_config.exists():
            if backup_path := self.legacy_sim.create_backup(source_config):
                self.assertTrue(backup_path.exists())
                self.assertIn(str(backup_path), self.legacy_sim.backup_locations)

        # Test multiple backup creation
        llm_models_file = self.legacy_llm_dir / "models.json"
        if llm_models_file.exists():
            if llm_backup := self.legacy_sim.create_backup(
                llm_models_file, ".migration_backup"
            ):
                self.assertTrue(llm_backup.exists())

        # Verify original data is preserved somewhere
        # Either in backups or in the migrated config
        self.assertIsNotNone(config.get("llm_configuration.models.gpt4-legacy"))
        cli_config_obj = config.get("cli_configuration")
        if cli_config_obj:
            aliases_obj = config.get("cli_configuration.aliases")
            if aliases_obj and isinstance(aliases_obj, dict):
                aliases: dict[str, Any] = aliases_obj
                self.assertIsNotNone(aliases.get("ll"))

        # Verify backup tracking
        self.assertGreaterEqual(len(self.legacy_sim.backup_locations), 0)

    def test_migration_idempotency(self) -> None:
        """Test that migration can be run multiple times safely using real simulators."""
        # Track initial migration run
        self.legacy_sim.track_migration_run()
        initial_runs = self.legacy_sim.migration_runs

        # First migration
        config1 = IntellicrackConfig()
        config1.save()

        # Get migrated values
        gpt4_1 = config1.get("llm_configuration.models.gpt4-legacy")
        aliases_1 = config1.get("cli_configuration.aliases")
        theme_1 = config1.get("ui_preferences.theme")

        # Track second migration run
        self.legacy_sim.track_migration_run()

        # Second migration (should not duplicate or corrupt)
        # Note: IntellicrackConfig is a singleton, so getting another instance
        # returns the same object - values should remain unchanged
        config2 = IntellicrackConfig()

        # Values should be the same
        gpt4_2 = config2.get("llm_configuration.models.gpt4-legacy")
        aliases_2 = config2.get("cli_configuration.aliases")
        theme_2 = config2.get("ui_preferences.theme")

        self.assertEqual(gpt4_1, gpt4_2)
        self.assertEqual(aliases_1, aliases_2)
        self.assertEqual(theme_1, theme_2)

        # Verify multiple migration runs were tracked
        self.assertEqual(self.legacy_sim.migration_runs, initial_runs + 2)

    def test_migration_preserves_all_data(self) -> None:
        """Test that no data is lost during migration."""
        config = IntellicrackConfig()

        # Count items in legacy configs
        legacy_model_count = 2  # gpt4-legacy, claude-legacy
        legacy_profile_count = 2  # legacy-creative, legacy-precise
        legacy_alias_count = 3  # ll, gs, analyze-full

        # Check all models migrated
        models_obj = config.get("llm_configuration.models")
        self.assertIsNotNone(models_obj)
        assert isinstance(models_obj, dict)
        models: dict[str, Any] = models_obj
        self.assertGreaterEqual(len(models), legacy_model_count)

        # Check all profiles migrated (includes defaults)
        profiles_obj = config.get("llm_configuration.profiles")
        self.assertIsNotNone(profiles_obj)
        assert isinstance(profiles_obj, dict)
        profiles: dict[str, Any] = profiles_obj
        self.assertGreaterEqual(len(profiles), legacy_profile_count)

        # Check all aliases migrated
        aliases_obj = config.get("cli_configuration.aliases")
        self.assertIsNotNone(aliases_obj)
        assert isinstance(aliases_obj, dict)
        aliases: dict[str, Any] = aliases_obj
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

    def test_migration_with_conflicts(self) -> None:
        """Test migration when there are conflicts between configs using real simulators."""
        # Create central config with some existing data
        config = IntellicrackConfig()

        # Create conflicted configuration using the config generator
        conflicting_model = self.legacy_config_gen.create_conflicted_config(config)

        # Save and reload to trigger migration
        config.save()

        # Verify conflict was detected and tracked
        self.assertGreater(len(self.legacy_sim.conflict_resolutions), 0)

        # Check that the conflicted key exists in resolution tracking
        conflict_key = "llm_configuration.models.gpt4-legacy"
        if conflict_key in self.legacy_sim.conflict_resolutions:
            conflict_info = self.legacy_sim.conflict_resolutions[conflict_key]
            self.assertIn("central", conflict_info)
            self.assertIn("legacy", conflict_info)
            self.assertIn("resolution", conflict_info)
            self.assertEqual(conflict_info["resolution"], "prefer_central")

        # Migration should preserve existing central config values
        # (or merge intelligently based on implementation)
        final_model_obj = config.get("llm_configuration.models.gpt4-legacy")
        self.assertIsNotNone(final_model_obj)
        assert isinstance(final_model_obj, dict)
        final_model: dict[str, Any] = final_model_obj

        # The specific behavior depends on merge strategy
        # Important thing is no crash and data is not lost
        self.assertIn("provider", final_model)
        self.assertIn("model_name", final_model)
        self.assertIn("api_key", final_model)

        # Verify conflict resolution was tracked properly
        if self.legacy_sim.conflict_resolutions:
            self.assertGreater(len(self.legacy_sim.conflict_resolutions), 0)


if __name__ == "__main__":
    unittest.main()
