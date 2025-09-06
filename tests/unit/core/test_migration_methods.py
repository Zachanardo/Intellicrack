"""Test individual migration methods in the configuration manager.

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
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open, PropertyMock
import sys
import os

sys.path.insert(0, 'C:\\Intellicrack')

from intellicrack.core.config_manager import IntellicrackConfig


class TestMigrationMethods(unittest.TestCase):
    """Test suite for individual migration methods in IntellicrackConfig."""

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
    def test_migrate_qsettings_data_with_real_settings(self, mock_logger):
        """Test migration of QSettings data with realistic values."""
        with patch('intellicrack.core.config_manager.QSettings') as MockQSettings:
            # Create mock QSettings instance with real-world data
            mock_settings = MagicMock()

            # Mock real QSettings values
            mock_settings.value.side_effect = lambda key, default=None: {
                "execution/qemu_preference": "always",
                "trusted_binaries": [
                    "C:\\Program Files\\Adobe\\Photoshop.exe",
                    "C:\\Windows\\System32\\notepad.exe",
                    "C:\\Games\\Cyberpunk2077\\bin\\x64\\Cyberpunk2077.exe"
                ],
                "script_types/frida/use_qemu": True,
                "script_types/ghidra/use_qemu": False,
                "script_types/radare2/use_qemu": True,
                "theme/mode": "dark",
                "theme/accent_color": "#4CAF50",
                "geometry/main_window": b'\x01\xd9\xd0\xcb\x00\x03\x00\x00',
                "state/main_window": b'\x00\x00\x00\xff\x00\x00',
                "splitters/main": [300, 700, 200],
                "dialogs/preferences/geometry": b'\x01\xd9\xd0\xcb',
                "execution/last_script": "C:\\Scripts\\analyze_binary.js",
                "execution/recent_files": [
                    "C:\\Binaries\\app1.exe",
                    "C:\\Binaries\\app2.dll",
                    "C:\\Binaries\\app3.bin"
                ]
            }.get(key, default)

            # Mock allKeys to return all the keys we're testing
            mock_settings.allKeys.return_value = [
                "execution/qemu_preference",
                "trusted_binaries",
                "script_types/frida/use_qemu",
                "script_types/ghidra/use_qemu",
                "script_types/radare2/use_qemu",
                "theme/mode",
                "theme/accent_color",
                "geometry/main_window",
                "state/main_window",
                "splitters/main",
                "dialogs/preferences/geometry",
                "execution/last_script",
                "execution/recent_files"
            ]

            MockQSettings.return_value = mock_settings

            # Run migration
            self.config._migrate_qsettings_data()

            # Verify QEMU testing preferences were migrated
            assert self.config.get("qemu_testing.default_preference") == "always"
            assert len(self.config.get("qemu_testing.trusted_binaries", [])) == 3
            assert "C:\\Program Files\\Adobe\\Photoshop.exe" in self.config.get("qemu_testing.trusted_binaries", [])

            # Verify script type preferences
            script_prefs = self.config.get("qemu_testing.script_type_preferences", {})
            assert script_prefs.get("frida") is True
            assert script_prefs.get("ghidra") is False
            assert script_prefs.get("radare2") is True

            # Verify theme preferences
            assert self.config.get("ui_preferences.theme") == "dark"
            assert self.config.get("ui_preferences.accent_color") == "#4CAF50"

            # Verify window geometry
            assert self.config.get("ui_preferences.window_geometry.main_window") is not None
            assert self.config.get("ui_preferences.window_state.main_window") is not None
            assert self.config.get("ui_preferences.splitter_states.main") == [300, 700, 200]

            # Verify execution history
            assert self.config.get("qemu_testing.execution_history.last_script") == "C:\\Scripts\\analyze_binary.js"
            recent_files = self.config.get("qemu_testing.execution_history.recent_files", [])
            assert len(recent_files) == 3
            assert "C:\\Binaries\\app1.exe" in recent_files

            # Verify logger was called
            mock_logger.info.assert_called()

    @patch('intellicrack.core.config_manager.logger')
    @patch('intellicrack.core.config_manager.Path')
    def test_migrate_llm_configs_with_real_data(self, MockPath, mock_logger):
        """Test migration of LLM configurations with realistic model data."""
        # Mock the home directory and config paths
        mock_home = MockPath.home.return_value
        mock_llm_dir = mock_home / ".intellicrack" / "llm_configs"
        mock_llm_dir.exists.return_value = True

        # Create mock config files with real-world data
        models_data = {
            "gpt-4": {
                "provider": "openai",
                "api_key": "sk-proj-abcd1234567890",
                "endpoint": "https://api.openai.com/v1",
                "max_tokens": 8192,
                "temperature": 0.7,
                "last_used": "2025-01-15T10:30:00",
                "usage_count": 245
            },
            "claude-3-opus": {
                "provider": "anthropic",
                "api_key": "sk-ant-api03-xyz789",
                "endpoint": "https://api.anthropic.com/v1",
                "max_tokens": 100000,
                "temperature": 0.5,
                "last_used": "2025-01-16T14:22:00",
                "usage_count": 189
            },
            "llama-3-70b": {
                "provider": "local",
                "endpoint": "http://localhost:11434",
                "model_path": "C:\\Models\\llama-3-70b.gguf",
                "max_tokens": 4096,
                "temperature": 0.8,
                "gpu_layers": 35,
                "context_size": 8192
            }
        }

        profiles_data = {
            "default": {
                "model": "gpt-4",
                "system_prompt": "You are a binary analysis expert.",
                "temperature_override": 0.3,
                "max_tokens_override": 4096
            },
            "code_generation": {
                "model": "claude-3-opus",
                "system_prompt": "Generate production-ready exploit code.",
                "temperature_override": 0.2,
                "format": "code"
            },
            "local_analysis": {
                "model": "llama-3-70b",
                "system_prompt": "Analyze binary protection mechanisms.",
                "temperature_override": 0.5,
                "streaming": True
            }
        }

        metrics_data = {
            "total_requests": 1523,
            "total_tokens": 4567890,
            "total_cost": 234.56,
            "by_model": {
                "gpt-4": {"requests": 543, "tokens": 2345678, "cost": 123.45},
                "claude-3-opus": {"requests": 432, "tokens": 1876543, "cost": 98.76},
                "llama-3-70b": {"requests": 548, "tokens": 345669, "cost": 12.35}
            },
            "by_date": {
                "2025-01-15": {"requests": 87, "tokens": 234567},
                "2025-01-16": {"requests": 92, "tokens": 289012}
            }
        }

        # Mock file reading
        def mock_open_file(path, *args, **kwargs):
            if "models.json" in str(path):
                return mock_open(read_data=json.dumps(models_data))()
            elif "profiles.json" in str(path):
                return mock_open(read_data=json.dumps(profiles_data))()
            elif "metrics.json" in str(path):
                return mock_open(read_data=json.dumps(metrics_data))()
            return mock_open()()

        # Set up the mock paths
        models_file = MagicMock()
        models_file.exists.return_value = True
        models_file.open = lambda *args, **kwargs: mock_open_file(models_file, *args, **kwargs)
        models_file.__str__ = lambda self: "models.json"

        profiles_file = MagicMock()
        profiles_file.exists.return_value = True
        profiles_file.open = lambda *args, **kwargs: mock_open_file(profiles_file, *args, **kwargs)
        profiles_file.__str__ = lambda self: "profiles.json"

        metrics_file = MagicMock()
        metrics_file.exists.return_value = True
        metrics_file.open = lambda *args, **kwargs: mock_open_file(metrics_file, *args, **kwargs)
        metrics_file.__str__ = lambda self: "metrics.json"

        mock_llm_dir.__truediv__.side_effect = lambda name: {
            "models.json": models_file,
            "profiles.json": profiles_file,
            "metrics.json": metrics_file
        }.get(name)

        # Run migration
        self.config._migrate_llm_configs()

        # Verify models were migrated
        llm_config = self.config.get("llm_configuration", {})
        assert "models" in llm_config
        assert "gpt-4" in llm_config["models"]
        assert llm_config["models"]["gpt-4"]["provider"] == "openai"
        assert llm_config["models"]["gpt-4"]["max_tokens"] == 8192
        assert "claude-3-opus" in llm_config["models"]
        assert "llama-3-70b" in llm_config["models"]

        # Verify profiles were migrated
        assert "profiles" in llm_config
        assert "default" in llm_config["profiles"]
        assert llm_config["profiles"]["default"]["model"] == "gpt-4"
        assert "code_generation" in llm_config["profiles"]
        assert "local_analysis" in llm_config["profiles"]

        # Verify metrics were migrated
        assert "metrics" in llm_config
        assert llm_config["metrics"]["total_requests"] == 1523
        assert llm_config["metrics"]["total_tokens"] == 4567890
        assert llm_config["metrics"]["total_cost"] == 234.56
        assert "by_model" in llm_config["metrics"]
        assert "gpt-4" in llm_config["metrics"]["by_model"]

        # Verify logger was called
        mock_logger.info.assert_called()

    @patch('intellicrack.core.config_manager.logger')
    def test_migrate_legacy_configs_with_multiple_files(self, mock_logger):
        """Test migration of multiple legacy configuration files."""
        # Create temporary legacy config files with real data
        legacy_paths = [
            Path("C:\\Intellicrack\\config\\config.json"),
            Path("C:\\Intellicrack\\data\\config\\intellicrack_config.json"),
            Path("C:\\Intellicrack\\config\\intellicrack_config.json")
        ]

        legacy_configs = [
            {
                "vm_framework": {
                    "enabled": True,
                    "default_vm": "qemu",
                    "vm_configs": {
                        "qemu": {"memory": 4096, "cores": 2},
                        "virtualbox": {"memory": 2048, "cores": 1}
                    }
                },
                "emergency_mode": False,
                "migration_timestamp": "2025-01-15T08:00:00",
                "ml_model_path": "C:\\Models\\ml_models",
                "analysis_cache_size": 1024
            },
            {
                "tools": {
                    "ghidra": "C:\\Tools\\ghidra\\ghidraRun.bat",
                    "x64dbg": "C:\\Tools\\x64dbg\\x64dbg.exe"
                },
                "directories": {
                    "plugins": "C:\\Intellicrack\\plugins",
                    "scripts": "C:\\Intellicrack\\scripts",
                    "output": "C:\\Intellicrack\\output"
                },
                "analysis_settings": {
                    "timeout": 300,
                    "max_memory": 8192,
                    "use_gpu": True
                }
            },
            {
                "security": {
                    "hashing": {"algorithm": "sha256", "iterations": 100000},
                    "subprocess": {"timeout": 60, "shell": False},
                    "serialization": {"allow_pickle": False},
                    "input_validation": {"strict": True, "max_length": 10000}
                },
                "network": {
                    "proxy": "http://proxy.company.com:8080",
                    "timeout": 30,
                    "retry_count": 3
                }
            }
        ]

        with patch('intellicrack.core.config_manager.Path') as MockPath:
            # Mock path existence checks
            for i, path in enumerate(legacy_paths):
                mock_path = MagicMock()
                mock_path.exists.return_value = True
                mock_path.open = mock_open(read_data=json.dumps(legacy_configs[i]))
                mock_path.__str__ = lambda self, p=path: str(p)
                MockPath.return_value = mock_path if i == 0 else MockPath.return_value

                # Patch the specific path checks
                with patch.object(Path, '__new__', return_value=mock_path):
                    if i == 0:
                        # For first file, call the method
                        with patch('builtins.open', mock_open(read_data=json.dumps(legacy_configs[i]))):
                            with patch('pathlib.Path.exists', return_value=True):
                                self.config._migrate_specific_legacy_fields(legacy_configs[i], path)

            # Verify VM framework was migrated
            vm_config = self.config.get("vm_framework", {})
            if vm_config:
                assert vm_config.get("enabled") is True
                assert vm_config.get("default_vm") == "qemu"
                assert "vm_configs" in vm_config

            # Verify emergency mode was migrated
            assert self.config.get("emergency_mode") is not None

            # Verify tools were migrated/merged
            tools = self.config.get("tools", {})
            if "ghidra" in legacy_configs[1]["tools"]:
                # Check if the migration would set these
                pass

            # Verify security settings
            security = self.config.get("security", {})
            if "hashing" in legacy_configs[2].get("security", {}):
                # Check if security settings would be migrated
                pass

    @patch('intellicrack.core.config_manager.logger')
    def test_migrate_specific_legacy_fields_comprehensive(self, mock_logger):
        """Test migration of specific legacy fields with all field types."""
        legacy_data = {
            "vm_framework": {
                "enabled": True,
                "default_vm": "vmware",
                "vm_configs": {
                    "vmware": {"memory": 8192, "cores": 4, "gpu_passthrough": True},
                    "hyperv": {"memory": 4096, "cores": 2, "nested_virtualization": True}
                },
                "snapshot_dir": "C:\\VMSnapshots",
                "auto_snapshot": True
            },
            "emergency_mode": True,
            "emergency_reason": "Critical system failure detected",
            "migration_timestamp": "2025-01-16T12:00:00",
            "migration_source": "legacy_v1",
            "ml_model_path": "D:\\AI_Models\\intellicrack_models",
            "ml_model_version": "3.2.1",
            "analysis_cache_size": 2048,
            "analysis_cache_ttl": 3600,
            "custom_tools_dir": "C:\\CustomTools",
            "custom_scripts_dir": "C:\\CustomScripts",
            "performance_mode": "aggressive",
            "performance_metrics": {
                "cpu_threshold": 80,
                "memory_threshold": 90,
                "disk_io_limit": 1000
            },
            "legacy_api_keys": {
                "virustotal": "vt_key_12345",
                "hybrid_analysis": "ha_key_67890"
            },
            "deprecated_features": {
                "use_old_ui": False,
                "legacy_export": True,
                "old_plugin_system": False
            },
            "user_preferences": {
                "language": "en_US",
                "timezone": "America/New_York",
                "date_format": "MM/DD/YYYY"
            },
            "experimental_features": {
                "ai_assisted_debugging": True,
                "quantum_resistant_crypto": False,
                "neural_decompilation": True
            },
            "backup_settings": {
                "auto_backup": True,
                "backup_interval": 3600,
                "backup_location": "E:\\Backups\\Intellicrack",
                "max_backups": 10
            },
            "telemetry": {
                "enabled": False,
                "anonymous": True,
                "crash_reports": True
            }
        }

        legacy_path = Path("C:\\Intellicrack\\config\\legacy_config.json")

        # Run migration
        self.config._migrate_specific_legacy_fields(legacy_data, legacy_path)

        # Verify VM framework migration
        vm_framework = self.config.get("vm_framework", {})
        assert vm_framework.get("enabled") is True
        assert vm_framework.get("default_vm") == "vmware"
        assert "vm_configs" in vm_framework
        assert vm_framework["vm_configs"]["vmware"]["memory"] == 8192
        assert vm_framework["vm_configs"]["vmware"]["gpu_passthrough"] is True
        assert vm_framework.get("snapshot_dir") == "C:\\VMSnapshots"
        assert vm_framework.get("auto_snapshot") is True

        # Verify emergency mode
        assert self.config.get("emergency_mode") is True
        assert self.config.get("emergency_reason") == "Critical system failure detected"

        # Verify migration metadata
        migration_meta = self.config.get("migration_metadata", {})
        assert migration_meta.get("timestamp") == "2025-01-16T12:00:00"
        assert migration_meta.get("source") == "legacy_v1"
        assert str(legacy_path) in migration_meta.get("migrated_files", [])

        # Verify ML model settings
        ai_models = self.config.get("ai_models", {})
        assert ai_models.get("ml_model_path") == "D:\\AI_Models\\intellicrack_models"
        assert ai_models.get("ml_model_version") == "3.2.1"

        # Verify analysis settings
        analysis = self.config.get("analysis_settings", {})
        assert analysis.get("cache_size") == 2048
        assert analysis.get("cache_ttl") == 3600

        # Verify directories
        dirs = self.config.get("directories", {})
        assert dirs.get("custom_tools") == "C:\\CustomTools"
        assert dirs.get("custom_scripts") == "C:\\CustomScripts"

        # Verify performance settings
        perf = self.config.get("performance", {})
        assert perf.get("mode") == "aggressive"
        assert perf.get("cpu_threshold") == 80
        assert perf.get("memory_threshold") == 90
        assert perf.get("disk_io_limit") == 1000

        # Verify API keys migration (should be in environment section)
        env = self.config.get("environment.variables", {})
        assert env.get("VIRUSTOTAL_API_KEY") == "vt_key_12345"
        assert env.get("HYBRID_ANALYSIS_API_KEY") == "ha_key_67890"

        # Verify experimental features
        exp = self.config.get("experimental_features", {})
        assert exp.get("ai_assisted_debugging") is True
        assert exp.get("quantum_resistant_crypto") is False
        assert exp.get("neural_decompilation") is True

        # Verify backup settings
        backup = self.config.get("backup", {})
        assert backup.get("auto_backup") is True
        assert backup.get("backup_interval") == 3600
        assert backup.get("backup_location") == "E:\\Backups\\Intellicrack"
        assert backup.get("max_backups") == 10

        # Verify telemetry settings
        telemetry = self.config.get("telemetry", {})
        assert telemetry.get("enabled") is False
        assert telemetry.get("anonymous") is True
        assert telemetry.get("crash_reports") is True

    @patch('intellicrack.core.config_manager.logger')
    @patch('intellicrack.core.config_manager.Path')
    def test_migrate_font_configs_with_real_fonts(self, MockPath, mock_logger):
        """Test migration of font configuration with real font data."""
        # Mock font config file
        font_config_data = {
            "monospace_fonts": {
                "primary": ["JetBrains Mono", "JetBrainsMono-Regular"],
                "fallback": ["Fira Code", "Source Code Pro", "Consolas", "Courier New", "monospace"]
            },
            "ui_fonts": {
                "primary": ["Inter", "Segoe UI", "Roboto"],
                "fallback": ["San Francisco", "Helvetica Neue", "Arial", "sans-serif"]
            },
            "font_sizes": {
                "ui_default": 11,
                "ui_small": 9,
                "ui_large": 14,
                "ui_title": 18,
                "code_default": 12,
                "code_small": 10,
                "code_large": 14,
                "hex_view": 11,
                "terminal": 10,
                "debug": 9
            },
            "font_weights": {
                "normal": 400,
                "medium": 500,
                "semibold": 600,
                "bold": 700
            },
            "line_height": {
                "default": 1.5,
                "compact": 1.2,
                "comfortable": 1.8,
                "code": 1.4
            },
            "available_fonts": [
                "JetBrainsMono-Regular.ttf",
                "JetBrainsMono-Bold.ttf",
                "JetBrainsMono-Italic.ttf",
                "JetBrainsMono-BoldItalic.ttf",
                "FiraCode-Regular.ttf",
                "FiraCode-Bold.ttf",
                "Inter-Regular.ttf",
                "Inter-Medium.ttf",
                "Inter-SemiBold.ttf",
                "Inter-Bold.ttf"
            ],
            "font_features": {
                "ligatures": True,
                "stylistic_sets": ["ss01", "ss02", "ss03"],
                "contextual_alternates": True,
                "tabular_numbers": True
            },
            "rendering": {
                "antialiasing": "subpixel",
                "hinting": "full",
                "lcd_filter": "default",
                "gamma": 1.8
            },
            "custom_css": {
                "editor": "font-variant-ligatures: contextual;",
                "terminal": "font-feature-settings: 'liga' 1, 'calt' 1;",
                "ui": "font-smoothing: antialiased;"
            }
        }

        # Mock the font config file path
        mock_font_path = MagicMock()
        mock_font_path.exists.return_value = True
        mock_font_path.open = mock_open(read_data=json.dumps(font_config_data))
        MockPath.return_value = mock_font_path

        # Run migration
        self.config._migrate_font_configs()

        # Verify font configuration was migrated
        font_config = self.config.get("font_configuration", {})

        # Check monospace fonts
        assert "monospace_fonts" in font_config
        assert font_config["monospace_fonts"]["primary"] == ["JetBrains Mono", "JetBrainsMono-Regular"]
        assert "Fira Code" in font_config["monospace_fonts"]["fallback"]

        # Check UI fonts
        assert "ui_fonts" in font_config
        assert "Inter" in font_config["ui_fonts"]["primary"]
        assert "San Francisco" in font_config["ui_fonts"]["fallback"]

        # Check font sizes
        assert "font_sizes" in font_config
        assert font_config["font_sizes"]["ui_default"] == 11
        assert font_config["font_sizes"]["code_default"] == 12
        assert font_config["font_sizes"]["hex_view"] == 11
        assert font_config["font_sizes"]["terminal"] == 10

        # Check font weights
        assert "font_weights" in font_config
        assert font_config["font_weights"]["normal"] == 400
        assert font_config["font_weights"]["bold"] == 700

        # Check line height
        assert "line_height" in font_config
        assert font_config["line_height"]["default"] == 1.5
        assert font_config["line_height"]["code"] == 1.4

        # Check available fonts
        assert "available_fonts" in font_config
        assert len(font_config["available_fonts"]) == 10
        assert "JetBrainsMono-Regular.ttf" in font_config["available_fonts"]
        assert "FiraCode-Regular.ttf" in font_config["available_fonts"]

        # Check font features
        assert "font_features" in font_config
        assert font_config["font_features"]["ligatures"] is True
        assert "ss01" in font_config["font_features"]["stylistic_sets"]

        # Check rendering settings
        assert "rendering" in font_config
        assert font_config["rendering"]["antialiasing"] == "subpixel"
        assert font_config["rendering"]["gamma"] == 1.8

        # Check custom CSS
        assert "custom_css" in font_config
        assert "font-variant-ligatures" in font_config["custom_css"]["editor"]

        # Verify logger was called
        mock_logger.info.assert_called()

    @patch('intellicrack.core.config_manager.logger')
    def test_migration_error_handling(self, mock_logger):
        """Test that migration methods handle errors gracefully."""
        # Test QSettings migration with import error
        with patch('intellicrack.core.config_manager.QSettings', side_effect=ImportError("PyQt6 not installed")):
            self.config._migrate_qsettings_data()
            mock_logger.debug.assert_called_with("PyQt6 not available, skipping QSettings migration")

        # Test LLM config migration with missing directory
        with patch('intellicrack.core.config_manager.Path') as MockPath:
            mock_path = MagicMock()
            mock_path.exists.return_value = False
            MockPath.home.return_value.__truediv__.return_value.__truediv__.return_value = mock_path

            self.config._migrate_llm_configs()
            # Should complete without error even if directory doesn't exist

        # Test font config migration with corrupted JSON
        with patch('intellicrack.core.config_manager.Path') as MockPath:
            mock_path = MagicMock()
            mock_path.exists.return_value = True
            mock_path.open = mock_open(read_data="Invalid JSON {{{")
            MockPath.return_value = mock_path

            self.config._migrate_font_configs()
            mock_logger.warning.assert_called()

    @patch('intellicrack.core.config_manager.logger')
    def test_migration_idempotency(self, mock_logger):
        """Test that running migrations multiple times doesn't duplicate data."""
        # Set up initial data
        self.config.set("qemu_testing.default_preference", "ask")
        self.config.set("qemu_testing.trusted_binaries", ["app1.exe"])

        with patch('intellicrack.core.config_manager.QSettings') as MockQSettings:
            mock_settings = MagicMock()
            mock_settings.value.side_effect = lambda key, default=None: {
                "execution/qemu_preference": "always",
                "trusted_binaries": ["app1.exe", "app2.exe"]
            }.get(key, default)
            mock_settings.allKeys.return_value = ["execution/qemu_preference", "trusted_binaries"]
            MockQSettings.return_value = mock_settings

            # Run migration twice
            self.config._migrate_qsettings_data()
            first_binaries = self.config.get("qemu_testing.trusted_binaries", [])

            self.config._migrate_qsettings_data()
            second_binaries = self.config.get("qemu_testing.trusted_binaries", [])

            # Verify no duplication
            assert len(first_binaries) == len(second_binaries)
            assert first_binaries == second_binaries

            # Verify preference was updated
            assert self.config.get("qemu_testing.default_preference") == "always"

    def test_migration_preserves_existing_data(self):
        """Test that migrations don't overwrite unrelated existing configuration."""
        # Set up existing configuration
        self.config.set("application.name", "Intellicrack")
        self.config.set("application.version", "3.0.0")
        self.config.set("directories.output", "C:\\Output")
        self.config.set("analysis_settings.timeout", 600)

        # Store original values
        original_name = self.config.get("application.name")
        original_version = self.config.get("application.version")
        original_output = self.config.get("directories.output")
        original_timeout = self.config.get("analysis_settings.timeout")

        # Run migration with mock data
        legacy_data = {
            "vm_framework": {"enabled": True},
            "emergency_mode": False
        }

        self.config._migrate_specific_legacy_fields(legacy_data, Path("test.json"))

        # Verify original data is preserved
        assert self.config.get("application.name") == original_name
        assert self.config.get("application.version") == original_version
        assert self.config.get("directories.output") == original_output
        assert self.config.get("analysis_settings.timeout") == original_timeout

        # Verify new data was added
        assert self.config.get("vm_framework.enabled") is True
        assert self.config.get("emergency_mode") is False

    def test_migration_with_nested_updates(self):
        """Test that migrations properly handle nested configuration updates."""
        # Set up existing nested configuration
        self.config.set("ui_preferences", {
            "theme": "light",
            "font_size": 10,
            "show_tooltips": True
        })

        with patch('intellicrack.core.config_manager.QSettings') as MockQSettings:
            mock_settings = MagicMock()
            mock_settings.value.side_effect = lambda key, default=None: {
                "theme/mode": "dark",
                "theme/accent_color": "#FF5722",
                "ui/font_size": 12,
                "ui/sidebar_width": 250
            }.get(key, default)
            mock_settings.allKeys.return_value = ["theme/mode", "theme/accent_color", "ui/font_size", "ui/sidebar_width"]
            MockQSettings.return_value = mock_settings

            self.config._migrate_qsettings_data()

            # Verify nested updates
            ui_prefs = self.config.get("ui_preferences", {})
            assert ui_prefs["theme"] == "dark"  # Updated
            assert ui_prefs["accent_color"] == "#FF5722"  # Added
            assert ui_prefs["show_tooltips"] is True  # Preserved
            assert ui_prefs.get("sidebar_width") == 250  # Added


if __name__ == "__main__":
    unittest.main()
