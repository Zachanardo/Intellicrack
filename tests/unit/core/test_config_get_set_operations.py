"""Test config get/set operations with new schema sections.

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
from unittest.mock import MagicMock, patch
import sys
import threading
import time

sys.path.insert(0, 'C:\\Intellicrack')

from intellicrack.core.config_manager import IntellicrackConfig, get_config


class TestConfigGetSetOperations(unittest.TestCase):
    """Test suite for get/set operations on new configuration schema sections."""

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

    def test_qemu_testing_get_set_operations(self):
        """Test get/set operations for QEMU testing configuration."""
        # Test setting default preference
        self.config.set("qemu_testing.default_preference", "always")
        assert self.config.get("qemu_testing.default_preference") == "always"

        # Test setting trusted binaries list
        trusted_binaries = [
            "C:\\Games\\CyberPunk2077\\bin\\x64\\Cyberpunk2077.exe",
            "C:\\Program Files\\Adobe\\Photoshop\\Photoshop.exe"
        ]
        self.config.set("qemu_testing.trusted_binaries", trusted_binaries)
        retrieved_binaries = self.config.get("qemu_testing.trusted_binaries")
        assert retrieved_binaries == trusted_binaries
        assert len(retrieved_binaries) == 2

        # Test setting script type preferences
        script_prefs = {
            "frida": True,
            "ghidra": False,
            "radare2": True,
            "x64dbg": False
        }
        self.config.set("qemu_testing.script_type_preferences", script_prefs)
        retrieved_prefs = self.config.get("qemu_testing.script_type_preferences")
        assert retrieved_prefs == script_prefs
        assert retrieved_prefs["frida"] is True
        assert retrieved_prefs["ghidra"] is False

        # Test setting execution history
        execution_history = {
            "last_script": "C:\\Scripts\\unpack_vmprotect.js",
            "recent_files": [
                "C:\\Samples\\packed.exe",
                "C:\\Samples\\protected.dll",
                "C:\\Samples\\obfuscated.bin"
            ],
            "last_execution_time": "2025-01-16T15:30:00",
            "total_executions": 523
        }
        self.config.set("qemu_testing.execution_history", execution_history)
        retrieved_history = self.config.get("qemu_testing.execution_history")
        assert retrieved_history["last_script"] == "C:\\Scripts\\unpack_vmprotect.js"
        assert len(retrieved_history["recent_files"]) == 3
        assert retrieved_history["total_executions"] == 523

        # Test nested get operations
        assert self.config.get("qemu_testing.execution_history.last_script") == "C:\\Scripts\\unpack_vmprotect.js"
        assert self.config.get("qemu_testing.script_type_preferences.frida") is True

        # Test update operations
        self.config.set("qemu_testing.default_preference", "never")
        assert self.config.get("qemu_testing.default_preference") == "never"

        # Test appending to list
        current_binaries = self.config.get("qemu_testing.trusted_binaries", [])
        current_binaries.append("C:\\NewApp\\app.exe")
        self.config.set("qemu_testing.trusted_binaries", current_binaries)
        assert len(self.config.get("qemu_testing.trusted_binaries")) == 4

    def test_font_configuration_get_set_operations(self):
        """Test get/set operations for font configuration."""
        # Test setting monospace fonts
        monospace_fonts = {
            "primary": ["JetBrains Mono", "Fira Code"],
            "fallback": ["Consolas", "Courier New", "monospace"]
        }
        self.config.set("font_configuration.monospace_fonts", monospace_fonts)
        retrieved_mono = self.config.get("font_configuration.monospace_fonts")
        assert retrieved_mono["primary"] == ["JetBrains Mono", "Fira Code"]
        assert "Consolas" in retrieved_mono["fallback"]

        # Test setting UI fonts
        ui_fonts = {
            "primary": ["Inter", "Segoe UI"],
            "fallback": ["Helvetica", "Arial", "sans-serif"]
        }
        self.config.set("font_configuration.ui_fonts", ui_fonts)
        assert self.config.get("font_configuration.ui_fonts.primary")[0] == "Inter"

        # Test setting font sizes
        font_sizes = {
            "ui_default": 11,
            "ui_small": 9,
            "ui_large": 14,
            "ui_title": 18,
            "code_default": 12,
            "code_small": 10,
            "code_large": 14,
            "hex_view": 11,
            "terminal": 10,
            "debug_console": 9
        }
        self.config.set("font_configuration.font_sizes", font_sizes)
        assert self.config.get("font_configuration.font_sizes.ui_default") == 11
        assert self.config.get("font_configuration.font_sizes.terminal") == 10

        # Test setting available fonts list
        available_fonts = [
            "JetBrainsMono-Regular.ttf",
            "JetBrainsMono-Bold.ttf",
            "FiraCode-Regular.ttf",
            "FiraCode-Bold.ttf",
            "Inter-Regular.ttf",
            "Inter-Bold.ttf"
        ]
        self.config.set("font_configuration.available_fonts", available_fonts)
        assert len(self.config.get("font_configuration.available_fonts")) == 6

        # Test font features
        font_features = {
            "ligatures": True,
            "stylistic_sets": ["ss01", "ss02", "ss03"],
            "contextual_alternates": True,
            "tabular_numbers": True
        }
        self.config.set("font_configuration.font_features", font_features)
        assert self.config.get("font_configuration.font_features.ligatures") is True
        assert "ss02" in self.config.get("font_configuration.font_features.stylistic_sets")

        # Test partial updates
        self.config.set("font_configuration.font_sizes.ui_default", 13)
        assert self.config.get("font_configuration.font_sizes.ui_default") == 13
        assert self.config.get("font_configuration.font_sizes.terminal") == 10  # Unchanged

    def test_environment_configuration_get_set_operations(self):
        """Test get/set operations for environment configuration."""
        # Test setting env file path
        self.config.set("environment.env_file_path", "C:\\Intellicrack\\config\\.env")
        assert self.config.get("environment.env_file_path") == "C:\\Intellicrack\\config\\.env"

        # Test setting environment variables
        env_vars = {
            "OPENAI_API_KEY": "sk-proj-1234567890abcdef",
            "ANTHROPIC_API_KEY": "sk-ant-api03-xyz789",
            "GOOGLE_API_KEY": "AIzaSyC-abcd1234",
            "VIRUSTOTAL_API_KEY": "vt_key_987654321",
            "GHIDRA_INSTALL_DIR": "C:\\Tools\\ghidra_11.0",
            "IDA_INSTALL_DIR": "C:\\Tools\\IDA_8.3",
            "INTELLICRACK_DEBUG": "true",
            "INTELLICRACK_LOG_LEVEL": "DEBUG"
        }
        self.config.set("environment.variables", env_vars)
        retrieved_vars = self.config.get("environment.variables")
        assert retrieved_vars["OPENAI_API_KEY"] == "sk-proj-1234567890abcdef"
        assert retrieved_vars["GHIDRA_INSTALL_DIR"] == "C:\\Tools\\ghidra_11.0"
        assert retrieved_vars["INTELLICRACK_DEBUG"] == "true"

        # Test auto-load setting
        self.config.set("environment.auto_load_env", True)
        assert self.config.get("environment.auto_load_env") is True

        # Test override settings
        self.config.set("environment.override_existing", False)
        assert self.config.get("environment.override_existing") is False

        # Test adding single environment variable
        current_vars = self.config.get("environment.variables", {})
        current_vars["NEW_API_KEY"] = "new_key_value"
        self.config.set("environment.variables", current_vars)
        assert self.config.get("environment.variables.NEW_API_KEY") == "new_key_value"

        # Test nested access
        assert self.config.get("environment.variables.OPENAI_API_KEY") == "sk-proj-1234567890abcdef"

    def test_secrets_configuration_get_set_operations(self):
        """Test get/set operations for secrets configuration."""
        # Test encryption settings
        encryption_settings = {
            "enabled": True,
            "algorithm": "AES-256-GCM",
            "key_derivation": "PBKDF2",
            "iterations": 100000,
            "salt_length": 32
        }
        self.config.set("secrets.encryption", encryption_settings)
        assert self.config.get("secrets.encryption.algorithm") == "AES-256-GCM"
        assert self.config.get("secrets.encryption.iterations") == 100000

        # Test keyring settings
        keyring_settings = {
            "backend": "Windows Credential Manager",
            "service_name": "Intellicrack",
            "username": "intellicrack_user",
            "fallback_to_file": True
        }
        self.config.set("secrets.keyring", keyring_settings)
        assert self.config.get("secrets.keyring.backend") == "Windows Credential Manager"
        assert self.config.get("secrets.keyring.fallback_to_file") is True

        # Test secure storage paths
        storage_paths = {
            "credentials": "C:\\Intellicrack\\secure\\credentials.enc",
            "api_keys": "C:\\Intellicrack\\secure\\api_keys.enc",
            "certificates": "C:\\Intellicrack\\secure\\certs",
            "private_keys": "C:\\Intellicrack\\secure\\private_keys"
        }
        self.config.set("secrets.storage_paths", storage_paths)
        assert self.config.get("secrets.storage_paths.credentials") == "C:\\Intellicrack\\secure\\credentials.enc"

        # Test secret categories
        categories = {
            "api_keys": ["openai", "anthropic", "google", "virustotal"],
            "credentials": ["github", "gitlab", "bitbucket"],
            "certificates": ["ssl_cert", "code_signing"],
            "tokens": ["jwt", "oauth", "session"]
        }
        self.config.set("secrets.categories", categories)
        assert "openai" in self.config.get("secrets.categories.api_keys")
        assert "jwt" in self.config.get("secrets.categories.tokens")

    def test_llm_configuration_get_set_operations(self):
        """Test get/set operations for LLM configuration."""
        # Test setting model configurations
        gpt4_config = {
            "provider": "openai",
            "api_key": "sk-proj-test123",
            "endpoint": "https://api.openai.com/v1",
            "max_tokens": 8192,
            "temperature": 0.7,
            "top_p": 0.95,
            "frequency_penalty": 0.5,
            "presence_penalty": 0.5,
            "system_prompt": "You are an expert binary analyst.",
            "retry_count": 3,
            "timeout": 60
        }
        self.config.set("llm_configuration.models.gpt-4", gpt4_config)
        retrieved_gpt4 = self.config.get("llm_configuration.models.gpt-4")
        assert retrieved_gpt4["provider"] == "openai"
        assert retrieved_gpt4["max_tokens"] == 8192
        assert retrieved_gpt4["temperature"] == 0.7

        # Test setting multiple models
        claude_config = {
            "provider": "anthropic",
            "api_key": "sk-ant-test456",
            "endpoint": "https://api.anthropic.com/v1",
            "max_tokens": 100000,
            "temperature": 0.5
        }
        self.config.set("llm_configuration.models.claude-3-opus", claude_config)

        llama_config = {
            "provider": "local",
            "endpoint": "http://localhost:11434",
            "model_path": "C:\\Models\\llama-3-70b.gguf",
            "max_tokens": 4096,
            "gpu_layers": 35
        }
        self.config.set("llm_configuration.models.llama-3-70b", llama_config)

        # Verify all models
        models = self.config.get("llm_configuration.models", {})
        assert len(models) >= 3
        assert "gpt-4" in models
        assert "claude-3-opus" in models
        assert "llama-3-70b" in models

        # Test profiles
        profiles = {
            "default": {
                "model": "gpt-4",
                "temperature_override": 0.3,
                "system_prompt": "Analyze this binary for vulnerabilities."
            },
            "code_generation": {
                "model": "claude-3-opus",
                "temperature_override": 0.2,
                "system_prompt": "Generate exploit code."
            },
            "local_analysis": {
                "model": "llama-3-70b",
                "temperature_override": 0.5,
                "system_prompt": "Perform static analysis."
            }
        }
        self.config.set("llm_configuration.profiles", profiles)
        assert self.config.get("llm_configuration.profiles.default.model") == "gpt-4"
        assert self.config.get("llm_configuration.profiles.code_generation.temperature_override") == 0.2

        # Test metrics
        metrics = {
            "total_requests": 1523,
            "total_tokens": 4567890,
            "total_cost": 234.56,
            "average_response_time": 2.3,
            "success_rate": 0.98
        }
        self.config.set("llm_configuration.metrics", metrics)
        assert self.config.get("llm_configuration.metrics.total_requests") == 1523
        assert self.config.get("llm_configuration.metrics.success_rate") == 0.98

    def test_cli_configuration_get_set_operations(self):
        """Test get/set operations for CLI configuration."""
        # Test CLI preferences
        cli_prefs = {
            "color_output": True,
            "verbose_mode": False,
            "progress_bars": True,
            "auto_complete": True,
            "history_size": 1000,
            "pager": "less",
            "editor": "vim"
        }
        self.config.set("cli_configuration.preferences", cli_prefs)
        assert self.config.get("cli_configuration.preferences.color_output") is True
        assert self.config.get("cli_configuration.preferences.history_size") == 1000

        # Test CLI profiles
        profiles = {
            "default": {
                "output_format": "json",
                "log_level": "INFO",
                "parallel_jobs": 4
            },
            "debug": {
                "output_format": "verbose",
                "log_level": "DEBUG",
                "parallel_jobs": 1,
                "trace_enabled": True
            },
            "production": {
                "output_format": "minimal",
                "log_level": "ERROR",
                "parallel_jobs": 8,
                "silent_mode": True
            }
        }
        self.config.set("cli_configuration.profiles", profiles)
        assert self.config.get("cli_configuration.profiles.debug.trace_enabled") is True
        assert self.config.get("cli_configuration.profiles.production.parallel_jobs") == 8

        # Test command aliases
        aliases = {
            "ll": "list --long",
            "la": "list --all",
            "analyze": "analyze --deep --export",
            "quick": "analyze --fast --no-ml"
        }
        self.config.set("cli_configuration.aliases", aliases)
        assert self.config.get("cli_configuration.aliases.analyze") == "analyze --deep --export"

        # Test output settings
        output_settings = {
            "format": "table",
            "max_width": 120,
            "truncate_long_strings": True,
            "show_timestamps": True,
            "export_path": "C:\\Intellicrack\\cli_output"
        }
        self.config.set("cli_configuration.output", output_settings)
        assert self.config.get("cli_configuration.output.max_width") == 120
        assert self.config.get("cli_configuration.output.export_path") == "C:\\Intellicrack\\cli_output"

    def test_vm_framework_get_set_operations(self):
        """Test get/set operations for VM framework configuration."""
        # Test VM framework settings
        vm_framework = {
            "enabled": True,
            "default_vm": "qemu",
            "auto_snapshot": True,
            "snapshot_dir": "C:\\VMSnapshots",
            "max_snapshots": 10,
            "vm_configs": {
                "qemu": {
                    "memory": 4096,
                    "cores": 2,
                    "disk_size": "20G",
                    "network": "user",
                    "graphics": "std",
                    "machine_type": "q35"
                },
                "virtualbox": {
                    "memory": 2048,
                    "cores": 1,
                    "disk_size": "10G",
                    "network": "nat",
                    "3d_acceleration": False
                },
                "vmware": {
                    "memory": 8192,
                    "cores": 4,
                    "disk_size": "40G",
                    "network": "bridged",
                    "gpu_passthrough": True
                }
            }
        }
        self.config.set("vm_framework", vm_framework)

        # Test retrieval
        assert self.config.get("vm_framework.enabled") is True
        assert self.config.get("vm_framework.default_vm") == "qemu"
        assert self.config.get("vm_framework.vm_configs.qemu.memory") == 4096
        assert self.config.get("vm_framework.vm_configs.vmware.gpu_passthrough") is True

        # Test updating specific VM config
        self.config.set("vm_framework.vm_configs.qemu.cores", 4)
        assert self.config.get("vm_framework.vm_configs.qemu.cores") == 4

        # Test adding new VM config
        hyperv_config = {
            "memory": 4096,
            "cores": 2,
            "generation": 2,
            "secure_boot": True
        }
        self.config.set("vm_framework.vm_configs.hyperv", hyperv_config)
        assert self.config.get("vm_framework.vm_configs.hyperv.secure_boot") is True

    def test_nested_get_set_operations(self):
        """Test deeply nested get/set operations."""
        # Test setting deeply nested values
        self.config.set("ui_preferences.dialogs.preferences.position.x", 100)
        self.config.set("ui_preferences.dialogs.preferences.position.y", 200)
        self.config.set("ui_preferences.dialogs.preferences.size.width", 800)
        self.config.set("ui_preferences.dialogs.preferences.size.height", 600)

        # Test retrieval
        assert self.config.get("ui_preferences.dialogs.preferences.position.x") == 100
        assert self.config.get("ui_preferences.dialogs.preferences.size.width") == 800

        # Test getting intermediate objects
        position = self.config.get("ui_preferences.dialogs.preferences.position")
        assert position["x"] == 100
        assert position["y"] == 200

        # Test setting entire nested structure at once
        dialog_config = {
            "about": {
                "position": {"x": 300, "y": 400},
                "size": {"width": 400, "height": 300}
            },
            "settings": {
                "position": {"x": 150, "y": 250},
                "size": {"width": 900, "height": 700}
            }
        }
        self.config.set("ui_preferences.dialogs", dialog_config)
        assert self.config.get("ui_preferences.dialogs.about.position.x") == 300
        assert self.config.get("ui_preferences.dialogs.settings.size.height") == 700

    def test_list_operations(self):
        """Test operations on list values in configuration."""
        # Test appending to lists
        self.config.set("qemu_testing.trusted_binaries", ["app1.exe"])
        binaries = self.config.get("qemu_testing.trusted_binaries")
        binaries.append("app2.exe")
        self.config.set("qemu_testing.trusted_binaries", binaries)
        assert len(self.config.get("qemu_testing.trusted_binaries")) == 2

        # Test removing from lists
        binaries = self.config.get("qemu_testing.trusted_binaries")
        binaries.remove("app1.exe")
        self.config.set("qemu_testing.trusted_binaries", binaries)
        assert len(self.config.get("qemu_testing.trusted_binaries")) == 1
        assert self.config.get("qemu_testing.trusted_binaries")[0] == "app2.exe"

        # Test list concatenation
        list1 = ["font1.ttf", "font2.ttf"]
        list2 = ["font3.ttf", "font4.ttf"]
        self.config.set("font_configuration.available_fonts", list1)
        current = self.config.get("font_configuration.available_fonts")
        current.extend(list2)
        self.config.set("font_configuration.available_fonts", current)
        assert len(self.config.get("font_configuration.available_fonts")) == 4

    def test_default_value_handling(self):
        """Test get operations with default values."""
        # Test getting non-existent keys with defaults
        assert self.config.get("non_existent_key", "default_value") == "default_value"
        assert self.config.get("non.existent.nested.key", 42) == 42
        assert self.config.get("another.missing.key", []) == []
        assert self.config.get("missing.dict.key", {}) == {}

        # Test that existing keys ignore defaults
        self.config.set("existing_key", "actual_value")
        assert self.config.get("existing_key", "default_value") == "actual_value"

    def test_type_preservation(self):
        """Test that types are preserved through get/set operations."""
        # Test various types
        test_values = {
            "string_val": "test string",
            "int_val": 42,
            "float_val": 3.14159,
            "bool_true": True,
            "bool_false": False,
            "null_val": None,
            "list_val": [1, 2, 3, "four", 5.0],
            "dict_val": {"nested": {"key": "value"}},
            "mixed_list": [1, "two", 3.0, True, None, {"key": "val"}]
        }

        for key, value in test_values.items():
            self.config.set(f"type_test.{key}", value)
            retrieved = self.config.get(f"type_test.{key}")
            assert type(retrieved) == type(value)
            assert retrieved == value

    def test_concurrent_access(self):
        """Test thread-safe concurrent access to configuration."""
        results = []
        errors = []

        def writer_thread(thread_id, iterations=100):
            """Thread that writes to config."""
            try:
                for i in range(iterations):
                    key = f"concurrent.thread_{thread_id}.value_{i}"
                    value = f"thread_{thread_id}_value_{i}"
                    self.config.set(key, value)
                    time.sleep(0.001)  # Small delay to increase contention
            except Exception as e:
                errors.append(f"Writer {thread_id}: {e}")

        def reader_thread(thread_id, iterations=100):
            """Thread that reads from config."""
            try:
                for i in range(iterations):
                    key = f"concurrent.thread_{thread_id % 3}.value_{i}"
                    value = self.config.get(key)
                    if value:
                        results.append(value)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(f"Reader {thread_id}: {e}")

        # Create and start threads
        threads = []
        for i in range(3):
            writer = threading.Thread(target=writer_thread, args=(i,))
            reader = threading.Thread(target=reader_thread, args=(i + 3,))
            threads.extend([writer, reader])

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        # Verify no errors occurred
        assert len(errors) == 0, f"Concurrent access errors: {errors}"

        # Verify some data was written and read
        assert len(results) > 0

        # Verify data integrity
        for i in range(3):
            for j in range(10):  # Check first 10 values
                key = f"concurrent.thread_{i}.value_{j}"
                value = self.config.get(key)
                if value:
                    assert value == f"thread_{i}_value_{j}"

    def test_save_and_reload(self):
        """Test that configuration persists correctly to disk."""
        # Set various configuration values
        test_data = {
            "qemu_testing": {
                "default_preference": "always",
                "trusted_binaries": ["app1.exe", "app2.exe"]
            },
            "font_configuration": {
                "monospace_fonts": {
                    "primary": ["JetBrains Mono"],
                    "fallback": ["Consolas"]
                }
            },
            "environment": {
                "variables": {
                    "API_KEY": "test_key_123"
                }
            },
            "llm_configuration": {
                "models": {
                    "test_model": {
                        "provider": "test",
                        "max_tokens": 1000
                    }
                }
            }
        }

        # Set all test data
        for section, data in test_data.items():
            self.config.set(section, data)

        # Save configuration
        self.config.save()

        # Create new config instance from same file
        new_config = IntellicrackConfig(config_path=str(self.config_path))

        # Verify all data persisted
        assert new_config.get("qemu_testing.default_preference") == "always"
        assert len(new_config.get("qemu_testing.trusted_binaries")) == 2
        assert new_config.get("font_configuration.monospace_fonts.primary")[0] == "JetBrains Mono"
        assert new_config.get("environment.variables.API_KEY") == "test_key_123"
        assert new_config.get("llm_configuration.models.test_model.max_tokens") == 1000


if __name__ == "__main__":
    unittest.main()
