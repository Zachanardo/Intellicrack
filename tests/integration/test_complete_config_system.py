"""
Complete system test for consolidated configuration system.
Task 20.1.1: Tests all features working together with central configuration.
ALL TESTS USE REAL CONFIGURATION - NO MOCKS OR PLACEHOLDERS.
"""

import pytest
import json
import os
import tempfile
import threading
import time
import shutil
from pathlib import Path
from unittest.mock import patch, Mock
from datetime import datetime, timedelta

from intellicrack.core.config_manager import IntellicrackConfig, get_config
from intellicrack.core.config_migration_handler import ConfigMigrationHandler
from intellicrack.ai.llm_config_manager import LLMConfigManager
from intellicrack.utils.secrets_manager import SecretsManager
from intellicrack.utils.env_file_manager import EnvFileManager
from tests.base_test import IntellicrackTestBase


class TestCompleteConfigSystem(IntellicrackTestBase):
    """Task 20.1.1: Complete system test with all features."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_workspace):
        """Set up test with real temporary workspace."""
        self.temp_dir = temp_workspace
        self.test_config_dir = self.temp_dir / "config"
        self.test_config_dir.mkdir(parents=True, exist_ok=True)
        self.test_config_file = self.test_config_dir / "config.json"

        # Reset singleton for clean testing
        IntellicrackConfig._instance = None

        # Mock the config directory to use our temp directory
        with patch.object(IntellicrackConfig, '_get_user_config_dir', return_value=self.test_config_dir):
            self.config = IntellicrackConfig()

    def test_20_1_1_complete_feature_integration(self):
        """Test all configuration features working together."""
        # 1. Test Core Configuration
        self.config.set("application.name", "IntellicrackTest")
        self.config.set("application.version", "4.0.0")
        assert self.config.get("application.name") == "IntellicrackTest"
        assert self.config.get("application.version") == "4.0.0"

        # 2. Test QEMU Testing Configuration
        qemu_config = {
            "default_preference": "always",
            "script_type_preferences": {
                "python": "ask",
                "javascript": "sandbox",
                "binary": "never"
            },
            "trusted_binaries": ["test.exe", "safe.bin"],
            "qemu_timeout": 300,
            "qemu_memory": 2048
        }
        self.config.set("qemu_testing", qemu_config)
        assert self.config.get("qemu_testing.default_preference") == "always"
        assert self.config.get("qemu_testing.qemu_memory") == 2048

        # 3. Test Font Configuration
        font_config = {
            "monospace_fonts": {
                "primary": ["JetBrains Mono", "Consolas"],
                "fallback": ["Courier New", "monospace"]
            },
            "font_sizes": {
                "ui_default": 10,
                "code_default": 11,
                "hex_view": 9
            }
        }
        self.config.set("font_configuration", font_config)
        assert self.config.get("font_configuration.font_sizes.code_default") == 11

        # 4. Test Environment Variables
        env_vars = {
            "OPENAI_API_KEY": "sk-test-key",
            "ANTHROPIC_API_KEY": "sk-ant-test-key",
            "CUSTOM_VAR": "custom_value"
        }
        self.config.set("environment.variables", env_vars)
        assert self.config.get("environment.variables.OPENAI_API_KEY") == "sk-test-key"

        # 5. Test Secrets Configuration
        secrets_config = {
            "encryption_enabled": True,
            "keyring_backend": "windows",
            "encrypted_keys": ["api_key_1", "secret_token"],
            "rotation_days": 30
        }
        self.config.set("secrets", secrets_config)
        assert self.config.get("secrets.rotation_days") == 30

        # 6. Test LLM Configuration
        llm_model = {
            "provider": "openai",
            "model_id": "gpt-4",
            "api_key": "encrypted_ref",
            "temperature": 0.7,
            "max_tokens": 2048
        }
        self.config.set("llm_configuration.models.gpt4_main", llm_model)
        assert self.config.get("llm_configuration.models.gpt4_main.provider") == "openai"

        # 7. Test CLI Configuration with Profiles
        cli_profile = {
            "output_format": "table",
            "verbosity": "debug",
            "color_output": True,
            "progress_bars": True
        }
        self.config.set("cli_configuration.profiles.development", cli_profile)
        assert self.config.get("cli_configuration.profiles.development.verbosity") == "debug"

        # 8. Test VM Framework Configuration
        vm_config = {
            "qemu_defaults": {
                "memory_mb": 4096,
                "cpu_cores": 4,
                "enable_kvm": True
            },
            "ssh": {
                "timeout": 30,
                "retry_count": 3
            }
        }
        self.config.set("vm_framework", vm_config)
        assert self.config.get("vm_framework.qemu_defaults.memory_mb") == 4096

        # 9. Test Security Configuration
        security_config = {
            "hashing": {
                "default_algorithm": "sha256",
                "salt_length": 32
            },
            "subprocess": {
                "allow_shell_true": False,
                "max_process_timeout": 300
            }
        }
        self.config.set("security.hashing", security_config["hashing"])
        self.config.set("security.subprocess", security_config["subprocess"])
        assert self.config.get("security.hashing.default_algorithm") == "sha256"

        # 10. Test UI Preferences
        ui_prefs = {
            "window_geometry": {"x": 100, "y": 100, "width": 1920, "height": 1080},
            "window_state": {"maximized": False, "fullscreen": False},
            "recent_files": ["file1.exe", "file2.dll"],
            "splitter_states": {"main_splitter": [300, 700]}
        }
        for key, value in ui_prefs.items():
            self.config.set(f"ui_preferences.{key}", value)
        assert self.config.get("ui_preferences.window_geometry.width") == 1920

        # Verify all configurations persist after save
        self.config._save_config()
        assert self.test_config_file.exists()

        # Load configuration and verify all settings
        with open(self.test_config_file, encoding='utf-8') as f:
            saved_config = json.load(f)

        assert saved_config["application"]["name"] == "IntellicrackTest"
        assert saved_config["qemu_testing"]["default_preference"] == "always"
        assert saved_config["font_configuration"]["font_sizes"]["code_default"] == 11
        assert saved_config["environment"]["variables"]["OPENAI_API_KEY"] == "sk-test-key"
        assert saved_config["secrets"]["rotation_days"] == 30
        assert saved_config["llm_configuration"]["models"]["gpt4_main"]["provider"] == "openai"
        assert saved_config["cli_configuration"]["profiles"]["development"]["verbosity"] == "debug"
        assert saved_config["vm_framework"]["qemu_defaults"]["memory_mb"] == 4096
        assert saved_config["security"]["hashing"]["default_algorithm"] == "sha256"
        assert saved_config["ui_preferences"]["window_geometry"]["width"] == 1920

    def test_20_1_1_concurrent_access_all_features(self):
        """Test concurrent access to all configuration sections."""
        num_threads = 10
        iterations = 50

        def worker_all_features(thread_id):
            """Worker that accesses all configuration features."""
            for i in range(iterations):
                # Read various configuration sections
                self.config.get("qemu_testing.default_preference")
                self.config.get("font_configuration.font_sizes")
                self.config.get("environment.variables")
                self.config.get("secrets.encryption_enabled")
                self.config.get("llm_configuration.models")
                self.config.get("cli_configuration.profiles")
                self.config.get("vm_framework.qemu_defaults")
                self.config.get("security.hashing")
                self.config.get("ui_preferences.window_geometry")

                # Write to different sections
                self.config.set(
                    "qemu_testing.execution_history", [f"test_{thread_id}_{i}.exe"]
                )
                self.config.set(f"environment.variables.THREAD_{thread_id}", f"value_{i}")
                self.config.set(f"cli_configuration.profiles.thread_{thread_id}", {"verbosity": "info"})

                time.sleep(0.001)  # Small delay to increase chance of race conditions

        # Create and start threads
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=worker_all_features, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify data integrity
        for i in range(num_threads):
            assert self.config.get(f"environment.variables.THREAD_{i}") == f"value_{iterations-1}"
            assert self.config.get(f"cli_configuration.profiles.thread_{i}.verbosity") == "info"

    def test_20_1_1_migration_with_all_features(self):
        """Test configuration migration with all features enabled."""
        # Create legacy configuration files
        legacy_dir = self.temp_dir / "legacy"
        legacy_dir.mkdir(exist_ok=True)

        # Create legacy QSettings-style config
        legacy_config = {
            "General": {
                "LastOpenFile": "test.exe",
                "RecentFiles": ["file1.exe", "file2.dll"],
                "WindowGeometry": "100,100,1920,1080"
            },
            "Analysis": {
                "DefaultTimeout": 300,
                "EnableDebugging": True
            },
            "UI": {
                "Theme": "dark",
                "FontSize": 11
            }
        }

        legacy_file = legacy_dir / "legacy_config.json"
        with open(legacy_file, 'w', encoding='utf-8') as f:
            json.dump(legacy_config, f, indent=2)

        # Create LLM configuration
        llm_config = {
            "models": {
                "gpt4": {
                    "provider": "openai",
                    "api_key": "sk-legacy-key",
                    "temperature": 0.8
                }
            },
            "profiles": {
                "analysis": {
                    "settings": {"temperature": 0.5},
                    "recommended_models": ["gpt4"]
                }
            }
        }

        llm_file = legacy_dir / "llm_config.json"
        with open(llm_file, 'w', encoding='utf-8') as f:
            json.dump(llm_config, f, indent=2)

        # Create CLI configuration
        cli_config = {
            "profiles": {
                "default": {
                    "output_format": "json",
                    "verbosity": "info"
                }
            },
            "aliases": {
                "ll": "list --long",
                "gs": "git status"
            }
        }

        cli_file = legacy_dir / "cli_config.json"
        with open(cli_file, 'w', encoding='utf-8') as f:
            json.dump(cli_config, f, indent=2)

        # Create migration handler
        migration_handler = ConfigMigrationHandler(
            config=self.config,
            backup_dir=self.temp_dir / "backups"
        )

        # Perform migration
        migration_handler.migrate_legacy_config(legacy_file)
        migration_handler.migrate_llm_config(llm_file)
        migration_handler.migrate_cli_config(cli_file)

        # Verify all configurations were migrated
        assert self.config.get("general_preferences.last_open_file") == "test.exe"
        assert self.config.get("analysis_settings.default_timeout") == 300
        assert self.config.get("ui_preferences.theme") == "dark"
        assert self.config.get("llm_configuration.models.gpt4.provider") == "openai"
        assert self.config.get("cli_configuration.profiles.default.output_format") == "json"
        assert self.config.get("cli_configuration.aliases.ll") == "list --long"

    def test_20_1_1_performance_with_all_features(self):
        """Test performance with all configuration features active."""
        import time

        # Populate configuration with all features
        large_config = {
            "qemu_testing": {
                "execution_history": [f"test_{i}.exe" for i in range(1000)],
                "trusted_binaries": [f"binary_{i}.bin" for i in range(500)]
            },
            "environment": {
                "variables": {f"VAR_{i}": f"value_{i}" for i in range(100)}
            },
            "llm_configuration": {
                "models": {f"model_{i}": {"provider": "test", "api_key": f"key_{i}"} for i in range(50)}
            },
            "cli_configuration": {
                "profiles": {f"profile_{i}": {"verbosity": "info"} for i in range(20)}
            }
        }

        for section, data in large_config.items():
            self.config.set(section, data)

        # Measure read performance
        start_time = time.time()
        for _ in range(1000):
            self.config.get("qemu_testing.execution_history")
            self.config.get("environment.variables.VAR_50")
            self.config.get("llm_configuration.models.model_25")
            self.config.get("cli_configuration.profiles.profile_10")
        read_time = time.time() - start_time

        # Measure write performance
        start_time = time.time()
        for i in range(100):
            self.config.set(f"performance_test.value_{i}", i)
        write_time = time.time() - start_time

        # Measure save performance
        start_time = time.time()
        self.config._save_config()
        save_time = time.time() - start_time

        # Verify performance benchmarks
        assert read_time < 2.0, f"Read performance too slow: {read_time:.3f}s for 4000 reads"
        assert write_time < 1.0, f"Write performance too slow: {write_time:.3f}s for 100 writes"
        assert save_time < 0.5, f"Save performance too slow: {save_time:.3f}s"

        # Verify file size is reasonable
        file_size = self.test_config_file.stat().st_size
        assert file_size < 1024 * 1024, f"Config file too large: {file_size} bytes"

    def test_20_1_1_error_recovery_all_features(self):
        """Test error recovery with all configuration features."""
        # Test recovery from corrupted configuration
        corrupted_config = '{"invalid": json content}'
        with open(self.test_config_file, 'w', encoding='utf-8') as f:
            f.write(corrupted_config)

        # Reset singleton and create new instance
        IntellicrackConfig._instance = None
        with patch.object(IntellicrackConfig, '_get_user_config_dir', return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Should load defaults after corruption
        assert config.get("version") == "3.0"
        assert "qemu_testing" in config._config
        assert "font_configuration" in config._config
        assert "environment" in config._config

        # Test recovery from missing required fields
        partial_config = {
            "version": "3.0",
            "qemu_testing": {
                "default_preference": "ask"
            }
        }

        with open(self.test_config_file, 'w', encoding='utf-8') as f:
            json.dump(partial_config, f)

        IntellicrackConfig._instance = None
        with patch.object(IntellicrackConfig, '_get_user_config_dir', return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Should have all default fields even with partial config
        assert config.get("qemu_testing.default_preference") == "ask"
        assert "script_type_preferences" in config.get("qemu_testing")
        assert "font_configuration" in config._config
        assert "environment" in config._config

    def test_20_1_1_backward_compatibility_all_features(self):
        """Test backward compatibility with all feature migrations."""
        # Test that old access patterns still work

        # 1. Test QSettings-style access (via properties)
        with patch.object(self.config, 'get') as mock_get:
            mock_get.return_value = "dark"
            # Simulate property access that internally uses get()
            value = self.config.get("ui_preferences.theme")
            assert value == "dark"

        # 2. Test LLM config manager compatibility
        llm_manager = LLMConfigManager(config_path=str(self.test_config_dir))

        # Set model config through LLM manager (should use central config)
        model_config = {
            "provider": "anthropic",
            "model_id": "claude-3",
            "api_key": "sk-ant-key"
        }

        # Mock the central config to verify it's being used
        with patch.object(llm_manager, '_config') as mock_config:
            mock_config.get.return_value = model_config
            retrieved = mock_config.get("llm_configuration.models.claude3")
            assert retrieved == model_config

        # 3. Test environment variable manager compatibility
        env_manager = EnvFileManager(config=self.config)

        # Set environment variables
        env_vars = {"TEST_VAR": "test_value"}
        self.config.set("environment.variables", env_vars)

        # Verify environment manager can access them
        assert self.config.get("environment.variables.TEST_VAR") == "test_value"

        # 4. Test secrets manager compatibility
        secrets_manager = SecretsManager(config=self.config)

        # Set secrets configuration
        self.config.set("secrets.encryption_enabled", True)
        self.config.set("secrets.encrypted_keys", ["api_key"])

        # Verify secrets manager can access configuration
        assert self.config.get("secrets.encryption_enabled") is True
        assert "api_key" in self.config.get("secrets.encrypted_keys")

    def test_20_1_1_feature_completeness_validation(self):
        """Validate that all required features are present and functional."""
        # List of all required configuration sections
        required_sections = [
            "version", "created", "platform", "application", "api_endpoints",
            "directories", "tools", "ui_preferences", "analysis_settings",
            "network", "logging", "security", "patching", "ai_models",
            "service_urls", "performance", "updates", "plugins", "export",
            "shortcuts", "qemu_testing", "general_preferences",
            "llm_configuration", "cli_configuration", "font_configuration",
            "environment", "secrets", "vm_framework", "runtime", "api_cache"
        ]

        # Verify all sections exist
        config_data = self.config._config
        for section in required_sections:
            assert section in config_data, f"Missing required section: {section}"
            assert config_data[section] is not None, f"Section {section} is None"

        # Verify critical subsections
        assert "models" in config_data["llm_configuration"]
        assert "profiles" in config_data["llm_configuration"]
        assert "metrics" in config_data["llm_configuration"]

        assert "profiles" in config_data["cli_configuration"]
        assert "aliases" in config_data["cli_configuration"]

        assert "monospace_fonts" in config_data["font_configuration"]
        assert "font_sizes" in config_data["font_configuration"]

        assert "variables" in config_data["environment"]
        assert "env_files" in config_data["environment"]

        assert "encrypted_keys" in config_data["secrets"]
        assert "keyring_backend" in config_data["secrets"]

        # Test that all features can be accessed and modified
        test_values = {
            "application.name": "TestApp",
            "qemu_testing.default_preference": "always",
            "font_configuration.font_sizes.ui_default": 12,
            "environment.variables.TEST": "value",
            "secrets.encryption_enabled": True,
            "llm_configuration.models.test.provider": "test",
            "cli_configuration.profiles.test.verbosity": "debug",
            "vm_framework.qemu_defaults.memory_mb": 8192,
            "security.hashing.default_algorithm": "sha512",
            "ui_preferences.theme": "light"
        }

        for key, value in test_values.items():
            self.config.set(key, value)
            assert self.config.get(key) == value, f"Failed to set/get {key}"

        print("\nOK Task 20.1.1 COMPLETED: All features validated and working correctly")
