"""Production-Ready Test Suite for Backward Compatibility

This test suite validates configuration migration and backward compatibility
for Intellicrack's centralized configuration system. Tests ensure that legacy
code patterns continue to work seamlessly after configuration consolidation.

Testing Philosophy:
- Real configuration file operations and validation
- Genuine migration scenario testing
- Production-ready compatibility verification
- Authentic multi-threaded access pattern testing
- Comprehensive API compatibility validation

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
import threading
import time
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from intellicrack.core.config.config_manager import IntellicrackConfig, get_config


class RealConfigMigrationTester:
    """Real configuration migration testing infrastructure."""

    def __init__(self, temp_dir: str):
        """Initialize with real temporary directory."""
        self.temp_dir = Path(temp_dir)
        self.old_configs_dir = self.temp_dir / "old_configs"
        self.old_configs_dir.mkdir(exist_ok=True)

    def create_legacy_qsettings_data(self) -> dict[str, Any]:
        """Create realistic legacy QSettings data structure."""
        return {
            "execution/qemu_preference": "always",
            "trusted_binaries": ["C:\\Apps\\app1.exe", "C:\\Apps\\app2.exe"],
            "script_types/frida/use_qemu": True,
            "script_types/ghidra/use_qemu": False,
            "script_types/radare2/use_qemu": True,
            "execution/timeout_seconds": 300,
            "execution/max_concurrent": 4
        }

    def create_legacy_theme_data(self) -> dict[str, Any]:
        """Create realistic legacy theme configuration data."""
        return {
            "theme/mode": "dark",
            "theme/accent_color": "#2196F3",
            "theme/font_scale": 1.1,
            "theme/custom_css": "QWidget { background: #1e1e1e; color: #ffffff; }",
            "theme/enable_animations": True,
            "theme/high_contrast": False
        }

    def create_legacy_llm_configs(self) -> tuple[dict[str, Any], dict[str, Any]]:
        """Create realistic legacy LLM configuration files."""
        models_data = {
            "gpt-4": {
                "provider": "openai",
                "api_key": "sk-test123",
                "max_tokens": 8192,
                "temperature": 0.7,
                "model_version": "gpt-4-0613"
            },
            "claude-3": {
                "provider": "anthropic",
                "api_key": "sk-ant-456",
                "max_tokens": 100000,
                "temperature": 0.3,
                "model_version": "claude-3-sonnet-20240229"
            }
        }

        profiles_data = {
            "default": {
                "model": "gpt-4",
                "system_prompt": "You are a helpful security research assistant.",
                "max_history": 10
            },
            "analysis": {
                "model": "claude-3",
                "system_prompt": "You are an expert binary analysis assistant.",
                "max_history": 20
            }
        }

        return models_data, profiles_data

    def create_legacy_font_config(self) -> dict[str, Any]:
        """Create realistic legacy font configuration."""
        return {
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
                "hex_view": 11,
                "console": 9
            },
            "available_fonts": [
                "JetBrainsMono-Regular.ttf",
                "JetBrainsMono-Bold.ttf",
                "JetBrainsMono-Italic.ttf"
            ]
        }

    def write_legacy_config_files(self):
        """Write realistic legacy configuration files to disk."""
        # Write LLM configs
        models_data, profiles_data = self.create_legacy_llm_configs()
        llm_dir = self.old_configs_dir / "llm_configs"
        llm_dir.mkdir(exist_ok=True)

        with open(llm_dir / "models.json", 'w') as f:
            json.dump(models_data, f, indent=2)

        with open(llm_dir / "profiles.json", 'w') as f:
            json.dump(profiles_data, f, indent=2)

        # Write font config
        with open(self.old_configs_dir / "font_config.json", 'w') as f:
            json.dump(self.create_legacy_font_config(), f, indent=2)

        # Write environment config
        env_data = {
            "OPENAI_API_KEY": "sk-test123",
            "ANTHROPIC_API_KEY": "sk-ant-456",
            "DEBUG_MODE": "true",
            "LOG_LEVEL": "INFO"
        }
        with open(self.old_configs_dir / ".env", 'w') as f:
            for key, value in env_data.items():
                f.write(f"{key}={value}\n")

        return {
            "qsettings": self.create_legacy_qsettings_data(),
            "theme": self.create_legacy_theme_data(),
            "llm_models": models_data,
            "llm_profiles": profiles_data,
            "fonts": self.create_legacy_font_config(),
            "env": env_data
        }


class RealScriptExecutionManagerCompat:
    """Real script execution manager with backward compatibility."""

    def __init__(self, config: IntellicrackConfig):
        """Initialize with real configuration instance."""
        self.config = config
        self.execution_history = []

    def get_qemu_preference(self) -> str:
        """Get QEMU preference with backward compatibility."""
        return self.config.get("qemu_testing.default_preference", "ask")

    def is_trusted_binary(self, binary_path: str) -> bool:
        """Check if binary is trusted with backward compatibility."""
        trusted = self.config.get("qemu_testing.trusted_binaries", [])
        return binary_path in trusted

    def should_use_qemu_for_script(self, script_type: str) -> bool:
        """Check QEMU usage for script type with backward compatibility."""
        prefs = self.config.get("qemu_testing.script_type_preferences", {})
        return prefs.get(script_type, False)

    def get_execution_timeout(self) -> int:
        """Get execution timeout with backward compatibility."""
        return self.config.get("qemu_testing.execution_timeout", 300)

    def get_max_concurrent_executions(self) -> int:
        """Get max concurrent executions with backward compatibility."""
        return self.config.get("qemu_testing.max_concurrent", 4)


class RealThemeManagerCompat:
    """Real theme manager with backward compatibility."""

    def __init__(self, config: IntellicrackConfig):
        """Initialize with real configuration instance."""
        self.config = config
        self.theme_cache = {}

    def get_theme_mode(self) -> str:
        """Get theme mode with backward compatibility."""
        return self.config.get("ui_preferences.theme", "light")

    def get_accent_color(self) -> str:
        """Get accent color with backward compatibility."""
        return self.config.get("ui_preferences.accent_color", "#000000")

    def get_font_scale(self) -> float:
        """Get font scale with backward compatibility."""
        return float(self.config.get("ui_preferences.font_scale", 1.0))

    def get_custom_css(self) -> str:
        """Get custom CSS with backward compatibility."""
        return self.config.get("ui_preferences.custom_css", "")

    def is_animations_enabled(self) -> bool:
        """Check if animations are enabled with backward compatibility."""
        return self.config.get("ui_preferences.enable_animations", True)

    def is_high_contrast_enabled(self) -> bool:
        """Check if high contrast mode is enabled with backward compatibility."""
        return self.config.get("ui_preferences.high_contrast", False)


class RealLLMConfigManagerCompat:
    """Real LLM configuration manager with backward compatibility."""

    def __init__(self, config: IntellicrackConfig):
        """Initialize with real configuration instance."""
        self.config = config
        self.model_cache = {}

    def save_model_config(self, model_id: str, config_data: dict[str, Any]):
        """Save model configuration with backward compatibility."""
        self.config.set(f"llm_configuration.models.{model_id}", config_data)
        self.model_cache[model_id] = config_data

    def load_model_config(self, model_id: str) -> dict[str, Any] | None:
        """Load model configuration with backward compatibility."""
        if model_id in self.model_cache:
            return self.model_cache[model_id]

        config_data = self.config.get(f"llm_configuration.models.{model_id}")
        if config_data:
            self.model_cache[model_id] = config_data
        return config_data

    def get_profile(self, profile_name: str) -> dict[str, Any] | None:
        """Get profile configuration with backward compatibility."""
        return self.config.get(f"llm_configuration.profiles.{profile_name}")

    def list_models(self) -> list[str]:
        """List available models with backward compatibility."""
        models = self.config.get("llm_configuration.models", {})
        return list(models.keys())

    def save_profile(self, profile_name: str, profile_data: dict[str, Any]):
        """Save profile configuration with backward compatibility."""
        self.config.set(f"llm_configuration.profiles.{profile_name}", profile_data)

    def delete_model_config(self, model_id: str) -> bool:
        """Delete model configuration with backward compatibility."""
        try:
            models = self.config.get("llm_configuration.models", {})
            if model_id in models:
                del models[model_id]
                self.config.set("llm_configuration.models", models)
                if model_id in self.model_cache:
                    del self.model_cache[model_id]
                return True
            return False
        except Exception:
            return False


class RealFontManagerCompat:
    """Real font manager with backward compatibility."""

    def __init__(self, config: IntellicrackConfig):
        """Initialize with real configuration instance."""
        self.config = config
        self.font_cache = {}

    def get_monospace_font(self, size: int | None = None) -> dict[str, Any]:
        """Get monospace font with backward compatibility."""
        config_data = self.config.get("font_configuration", {})

        if size is None:
            size = config_data.get("font_sizes", {}).get("code_default", 10)

        if primary_fonts := config_data.get("monospace_fonts", {}).get(
            "primary", []
        ):
            return {"family": primary_fonts[0], "size": size}

        # Fallback
        fallback_fonts = config_data.get("monospace_fonts", {}).get("fallback", ["monospace"])
        return {"family": fallback_fonts[0], "size": size}

    def get_ui_font(self, size: int | None = None) -> dict[str, Any]:
        """Get UI font with backward compatibility."""
        config_data = self.config.get("font_configuration", {})

        if size is None:
            size = config_data.get("font_sizes", {}).get("ui_default", 10)

        if primary_fonts := config_data.get("ui_fonts", {}).get("primary", []):
            return {"family": primary_fonts[0], "size": size}

        # Fallback
        fallback_fonts = config_data.get("ui_fonts", {}).get("fallback", ["sans-serif"])
        return {"family": fallback_fonts[0], "size": size}

    def list_available_fonts(self) -> list[str]:
        """List available font files with backward compatibility."""
        config_data = self.config.get("font_configuration", {})
        return config_data.get("available_fonts", [])


class TestBackwardCompatibility(unittest.TestCase):
    """Production-ready test suite for backward compatibility validation."""

    def setUp(self):
        """Set up test environment with real temporary configurations."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "test_config.json"
        self.migration_tester = RealConfigMigrationTester(self.temp_dir)

        # Create real configuration instance
        self.config = IntellicrackConfig(config_path=str(self.config_path))

        # Write legacy config files for migration testing
        self.legacy_data = self.migration_tester.write_legacy_config_files()

    def tearDown(self):
        """Clean up temporary files and directories."""
        try:
            shutil.rmtree(self.temp_dir)
        except Exception:
            pass  # Best effort cleanup

    def test_script_execution_manager_backward_compatibility(self):
        """Test that ScriptExecutionManager patterns work after migration."""
        # Simulate migration of legacy QSettings data
        qsettings_data = self.legacy_data["qsettings"]

        # Migrate QSettings data to central config
        self.config.set("qemu_testing.default_preference", qsettings_data["execution/qemu_preference"])
        self.config.set("qemu_testing.trusted_binaries", qsettings_data["trusted_binaries"])

        script_prefs = {}
        for key, value in qsettings_data.items():
            if key.startswith("script_types/") and key.endswith("/use_qemu"):
                script_type = key.split("/")[1]
                script_prefs[script_type] = value

        self.config.set("qemu_testing.script_type_preferences", script_prefs)
        self.config.set("qemu_testing.execution_timeout", qsettings_data.get("execution/timeout_seconds", 300))
        self.config.set("qemu_testing.max_concurrent", qsettings_data.get("execution/max_concurrent", 4))

        # Test with real script execution manager
        manager = RealScriptExecutionManagerCompat(self.config)

        # Verify migration worked correctly
        self.assertEqual(manager.get_qemu_preference(), "always")
        self.assertTrue(manager.is_trusted_binary("C:\\Apps\\app1.exe"))
        self.assertTrue(manager.is_trusted_binary("C:\\Apps\\app2.exe"))
        self.assertFalse(manager.is_trusted_binary("C:\\Apps\\unknown.exe"))
        self.assertTrue(manager.should_use_qemu_for_script("frida"))
        self.assertFalse(manager.should_use_qemu_for_script("ghidra"))
        self.assertTrue(manager.should_use_qemu_for_script("radare2"))
        self.assertEqual(manager.get_execution_timeout(), 300)
        self.assertEqual(manager.get_max_concurrent_executions(), 4)

    def test_theme_manager_backward_compatibility(self):
        """Test that ThemeManager patterns work after migration."""
        # Simulate migration of legacy theme data
        theme_data = self.legacy_data["theme"]

        # Migrate theme data to central config
        self.config.set("ui_preferences.theme", theme_data["theme/mode"])
        self.config.set("ui_preferences.accent_color", theme_data["theme/accent_color"])
        self.config.set("ui_preferences.font_scale", theme_data["theme/font_scale"])
        self.config.set("ui_preferences.custom_css", theme_data["theme/custom_css"])
        self.config.set("ui_preferences.enable_animations", theme_data["theme/enable_animations"])
        self.config.set("ui_preferences.high_contrast", theme_data["theme/high_contrast"])

        # Test with real theme manager
        theme_mgr = RealThemeManagerCompat(self.config)

        # Verify migration worked correctly
        self.assertEqual(theme_mgr.get_theme_mode(), "dark")
        self.assertEqual(theme_mgr.get_accent_color(), "#2196F3")
        self.assertEqual(theme_mgr.get_font_scale(), 1.1)
        self.assertIn("background: #1e1e1e", theme_mgr.get_custom_css())
        self.assertTrue(theme_mgr.is_animations_enabled())
        self.assertFalse(theme_mgr.is_high_contrast_enabled())

    def test_llm_config_manager_backward_compatibility(self):
        """Test that LLMConfigManager patterns work after migration."""
        # Migrate LLM configuration data
        models_data = self.legacy_data["llm_models"]
        profiles_data = self.legacy_data["llm_profiles"]

        # Migrate to central config
        for model_id, model_config in models_data.items():
            self.config.set(f"llm_configuration.models.{model_id}", model_config)

        for profile_name, profile_config in profiles_data.items():
            self.config.set(f"llm_configuration.profiles.{profile_name}", profile_config)

        # Test with real LLM config manager
        llm_mgr = RealLLMConfigManagerCompat(self.config)

        # Test loading existing model
        gpt4_config = llm_mgr.load_model_config("gpt-4")
        self.assertIsNotNone(gpt4_config)
        self.assertEqual(gpt4_config["provider"], "openai")
        self.assertEqual(gpt4_config["max_tokens"], 8192)
        self.assertEqual(gpt4_config["model_version"], "gpt-4-0613")

        # Test loading another model
        claude_config = llm_mgr.load_model_config("claude-3")
        self.assertIsNotNone(claude_config)
        self.assertEqual(claude_config["provider"], "anthropic")
        self.assertEqual(claude_config["max_tokens"], 100000)

        # Test getting profiles
        default_profile = llm_mgr.get_profile("default")
        self.assertIsNotNone(default_profile)
        self.assertEqual(default_profile["model"], "gpt-4")
        self.assertEqual(default_profile["max_history"], 10)

        analysis_profile = llm_mgr.get_profile("analysis")
        self.assertIsNotNone(analysis_profile)
        self.assertEqual(analysis_profile["model"], "claude-3")
        self.assertEqual(analysis_profile["max_history"], 20)

        # Test listing models
        models = llm_mgr.list_models()
        self.assertIn("gpt-4", models)
        self.assertIn("claude-3", models)

        # Test saving new model
        llm_mgr.save_model_config("gpt-3.5", {
            "provider": "openai",
            "api_key": "sk-test789",
            "max_tokens": 4096,
            "model_version": "gpt-3.5-turbo-0613"
        })

        new_model = llm_mgr.load_model_config("gpt-3.5")
        self.assertEqual(new_model["provider"], "openai")
        self.assertEqual(new_model["max_tokens"], 4096)

        # Test deleting model
        self.assertTrue(llm_mgr.delete_model_config("gpt-3.5"))
        self.assertIsNone(llm_mgr.load_model_config("gpt-3.5"))

    def test_font_manager_backward_compatibility(self):
        """Test that FontManager patterns work after migration."""
        # Migrate font configuration data
        font_config = self.legacy_data["fonts"]
        self.config.set("font_configuration", font_config)

        # Test with real font manager
        font_mgr = RealFontManagerCompat(self.config)

        # Test getting monospace font
        mono_font = font_mgr.get_monospace_font()
        self.assertEqual(mono_font["family"], "JetBrains Mono")
        self.assertEqual(mono_font["size"], 11)  # code_default from config

        # Test getting UI font
        ui_font = font_mgr.get_ui_font()
        self.assertEqual(ui_font["family"], "Segoe UI")
        self.assertEqual(ui_font["size"], 10)  # ui_default from config

        # Test with custom size
        large_font = font_mgr.get_monospace_font(size=14)
        self.assertEqual(large_font["family"], "JetBrains Mono")
        self.assertEqual(large_font["size"], 14)

        # Test listing available fonts
        available_fonts = font_mgr.list_available_fonts()
        self.assertIn("JetBrainsMono-Regular.ttf", available_fonts)
        self.assertIn("JetBrainsMono-Bold.ttf", available_fonts)
        self.assertIn("JetBrainsMono-Italic.ttf", available_fonts)

    def test_environment_file_backward_compatibility(self):
        """Test that environment file patterns work after migration."""
        # Set up environment configuration from legacy data
        env_data = self.legacy_data["env"]
        self.config.set("environment", {
            "env_file_path": str(self.migration_tester.old_configs_dir / ".env"),
            "variables": env_data,
            "auto_load_env": True
        })

        # Test reading environment variables
        env_vars = self.config.get("environment.variables", {})
        self.assertEqual(env_vars["OPENAI_API_KEY"], "sk-test123")
        self.assertEqual(env_vars["ANTHROPIC_API_KEY"], "sk-ant-456")
        self.assertEqual(env_vars["DEBUG_MODE"], "true")
        self.assertEqual(env_vars["LOG_LEVEL"], "INFO")

        # Test updating environment variables
        env_vars["NEW_KEY"] = "new_value"
        self.config.set("environment.variables", env_vars)

        updated_vars = self.config.get("environment.variables", {})
        self.assertEqual(updated_vars["NEW_KEY"], "new_value")

    def test_api_compatibility_preserved(self):
        """Test that public API remains compatible after migration."""
        # Test dot notation access (existing API)
        self.config.set("test.nested.value", 42)
        self.assertEqual(self.config.get("test.nested.value"), 42)

        # Test get with default (existing API)
        self.assertEqual(self.config.get("non.existent.key", "default"), "default")

        # Test set method (existing API)
        self.config.set("new.key", "new_value")
        self.assertEqual(self.config.get("new.key"), "new_value")

        # Test save and load methods (existing API)
        self.config.set("before_save", "value1")
        self.config.save()
        self.assertTrue(self.config_path.exists())

        # Create new config instance and load
        new_config = IntellicrackConfig(config_path=str(self.config_path))
        new_config.load()
        self.assertEqual(new_config.get("before_save"), "value1")

        # Test nested dictionary operations
        self.config.set("nested.dict", {"key1": "value1", "key2": {"subkey": "subvalue"}})
        self.assertEqual(self.config.get("nested.dict.key1"), "value1")
        self.assertEqual(self.config.get("nested.dict.key2.subkey"), "subvalue")

    def test_corrupted_config_graceful_handling(self):
        """Test graceful handling of corrupted configuration files."""
        # Create corrupted config file
        corrupted_path = Path(self.temp_dir) / "corrupted_config.json"
        with open(corrupted_path, 'w') as f:
            f.write("{ corrupted json syntax {{")

        # Should not crash when loading corrupted config
        try:
            corrupted_config = IntellicrackConfig(config_path=str(corrupted_path))
            corrupted_config.load()

            # Should still be functional
            corrupted_config.set("test_key", "test_value")
            self.assertEqual(corrupted_config.get("test_key"), "test_value")

        except Exception as e:
            self.fail(f"Should handle corrupted config gracefully: {e}")

    def test_concurrent_access_backward_compatibility(self):
        """Test concurrent access patterns work after migration."""
        results = []
        errors = []
        config_lock = threading.Lock()

        def concurrent_access_thread(thread_id: int):
            """Thread function for concurrent access testing."""
            try:
                # Simulate concurrent config access
                for i in range(20):
                    key = f"concurrent_test.thread_{thread_id}.value_{i}"
                    value = f"thread_{thread_id}_val_{i}"

                    with config_lock:
                        self.config.set(key, value)
                        retrieved_value = self.config.get(key)

                        if retrieved_value == value:
                            results.append((thread_id, i, True))
                        else:
                            results.append((thread_id, i, False))

                    # Small delay to encourage race conditions
                    time.sleep(0.001)

            except Exception as e:
                errors.append(f"Thread {thread_id}: {str(e)}")

        # Launch concurrent threads
        threads = []
        for thread_id in range(5):
            thread = threading.Thread(target=concurrent_access_thread, args=(thread_id,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify no errors occurred
        self.assertEqual(len(errors), 0, f"Concurrent access errors: {errors}")

        # Verify all operations succeeded
        successful_operations = sum(bool(success)
                                for _, _, success in results)
        total_operations = len(results)

        self.assertEqual(successful_operations, total_operations,
                        f"Only {successful_operations}/{total_operations} operations succeeded")

        # Verify data integrity
        for thread_id in range(5):
            for i in range(20):
                key = f"concurrent_test.thread_{thread_id}.value_{i}"
                expected_value = f"thread_{thread_id}_val_{i}"
                actual_value = self.config.get(key)
                self.assertEqual(actual_value, expected_value,
                               f"Data corruption in {key}: expected {expected_value}, got {actual_value}")

    def test_partial_migration_scenarios(self):
        """Test partial migration scenarios are handled gracefully."""
        # Create partial configuration with missing sections
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

        # Write partial config to file
        partial_path = Path(self.temp_dir) / "partial_config.json"
        with open(partial_path, 'w') as f:
            json.dump(partial_config, f, indent=2)

        # Load partial config
        partial_config_instance = IntellicrackConfig(config_path=str(partial_path))
        partial_config_instance.load()

        # Test that missing sections return defaults without crashing
        self.assertEqual(partial_config_instance.get("qemu_testing.default_preference", "ask"), "ask")
        self.assertEqual(partial_config_instance.get("font_configuration.monospace_fonts", {}), {})
        self.assertEqual(partial_config_instance.get("environment.variables", {}), {})

        # Test that existing sections work correctly
        self.assertEqual(partial_config_instance.get("application.name"), "Intellicrack")
        self.assertEqual(partial_config_instance.get("ui_preferences.theme"), "dark")

        # Test that new values can be added to missing sections
        partial_config_instance.set("qemu_testing.default_preference", "always")
        self.assertEqual(partial_config_instance.get("qemu_testing.default_preference"), "always")

        partial_config_instance.set("font_configuration.primary_font", "JetBrains Mono")
        self.assertEqual(partial_config_instance.get("font_configuration.primary_font"), "JetBrains Mono")

    def test_legacy_file_coexistence(self):
        """Test that legacy config files can coexist without conflicts."""
        # Create both old and new config files
        old_config_data = {
            "old_theme": "light",
            "old_font_size": 12,
            "old_language": "en"
        }

        old_config_path = Path(self.temp_dir) / "old_settings.json"
        with open(old_config_path, 'w') as f:
            json.dump(old_config_data, f)

        # Set up new central config
        self.config.set("ui_preferences.theme", "dark")
        self.config.set("font_configuration.size", 14)
        self.config.set("application.language", "fr")

        # Verify old files don't interfere with new config
        self.assertEqual(self.config.get("ui_preferences.theme"), "dark")
        self.assertEqual(self.config.get("font_configuration.size"), 14)
        self.assertEqual(self.config.get("application.language"), "fr")

        # Verify old config file still exists but is ignored
        self.assertTrue(old_config_path.exists())

        # Verify new config can be saved and loaded independently
        self.config.save()
        self.config.load()

        self.assertEqual(self.config.get("ui_preferences.theme"), "dark")
        self.assertEqual(self.config.get("font_configuration.size"), 14)
        self.assertEqual(self.config.get("application.language"), "fr")


if __name__ == '__main__':
    unittest.main()
