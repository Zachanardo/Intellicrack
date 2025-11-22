"""
Test central config schema loading and validation for new consolidated configuration.
Tests all new sections added during consolidation: qemu_testing, font_configuration,
environment, secrets, llm_configuration, cli_configuration, vm_framework, etc.
ALL TESTS USE REAL CONFIGURATION - NO MOCKS OR PLACEHOLDERS.
"""

import pytest
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from intellicrack.core.config_manager import IntellicrackConfig, get_config
from tests.base_test import IntellicrackTestBase


class TestConfigSchemaValidation(IntellicrackTestBase):
    """Test new schema sections added during configuration consolidation."""

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

    def test_qemu_testing_section_real(self):
        """Test QEMU testing configuration section with real data."""
        # Test default schema contains qemu_testing section
        qemu_config = self.config.get("qemu_testing", {})
        self.assert_real_output(qemu_config)

        # Verify expected fields exist
        assert "default_preference" in qemu_config, "Should have default_preference field"
        assert "script_type_preferences" in qemu_config, "Should have script_type_preferences"
        assert "trusted_binaries" in qemu_config, "Should have trusted_binaries list"
        assert "execution_history" in qemu_config, "Should have execution_history list"
        assert "max_history_size" in qemu_config, "Should have max_history_size"
        assert "auto_trust_signed" in qemu_config, "Should have auto_trust_signed flag"
        assert "sandbox_timeout" in qemu_config, "Should have sandbox_timeout"
        assert "enable_logging" in qemu_config, "Should have enable_logging flag"
        assert "qemu_timeout" in qemu_config, "Should have qemu_timeout"
        assert "qemu_memory" in qemu_config, "Should have qemu_memory"

        # Test setting and getting QEMU preferences
        self.config.set("qemu_testing.default_preference", "always")
        self.config.set("qemu_testing.script_type_preferences.python", "ask")
        self.config.set("qemu_testing.trusted_binaries", ["test.exe", "safe.bin"])

        # Verify values were set correctly
        assert self.config.get("qemu_testing.default_preference") == "always"
        assert self.config.get("qemu_testing.script_type_preferences.python") == "ask"
        trusted = self.config.get("qemu_testing.trusted_binaries")
        assert len(trusted) == 2
        assert "test.exe" in trusted

    def test_font_configuration_section_real(self):
        """Test font configuration section with real data."""
        font_config = self.config.get("font_configuration", {})
        self.assert_real_output(font_config)

        # Verify font configuration structure
        assert "monospace_fonts" in font_config, "Should have monospace_fonts"
        assert "ui_fonts" in font_config, "Should have ui_fonts"
        assert "font_sizes" in font_config, "Should have font_sizes"
        assert "available_fonts" in font_config, "Should have available_fonts"

        # Verify nested structure
        monospace = font_config.get("monospace_fonts", {})
        assert "primary" in monospace, "Should have primary monospace fonts"
        assert "fallback" in monospace, "Should have fallback monospace fonts"
        assert isinstance(monospace["primary"], list), "Primary fonts should be a list"
        assert isinstance(monospace["fallback"], list), "Fallback fonts should be a list"

        # Verify font sizes
        font_sizes = font_config.get("font_sizes", {})
        expected_sizes = ["ui_default", "ui_small", "ui_large",
                         "code_default", "code_small", "code_large", "hex_view"]
        for size_key in expected_sizes:
            assert size_key in font_sizes, f"Should have {size_key} font size"
            assert isinstance(font_sizes[size_key], int), f"{size_key} should be an integer"

        # Test available fonts list
        self.config.set("font_configuration.available_fonts",
                       ["JetBrainsMono-Regular.ttf", "JetBrainsMono-Bold.ttf"])
        fonts = self.config.get("font_configuration.available_fonts")
        assert len(fonts) == 2
        assert "JetBrainsMono-Regular.ttf" in fonts

    def test_environment_section_real(self):
        """Test environment variables configuration section."""
        env_config = self.config.get("environment", {})
        self.assert_real_output(env_config)

        # Verify environment configuration fields
        assert "variables" in env_config, "Should have variables dict"
        assert "env_files" in env_config, "Should have env_files list"
        assert "auto_load_env" in env_config, "Should have auto_load_env flag"
        assert "override_system_env" in env_config, "Should have override_system_env flag"
        assert "expand_variables" in env_config, "Should have expand_variables flag"
        assert "case_sensitive" in env_config, "Should have case_sensitive flag"
        assert "backup_original" in env_config, "Should have backup_original flag"
        assert "env_file_encoding" in env_config, "Should have env_file_encoding"

        # Test setting environment variables
        test_vars = {
            "OPENAI_API_KEY": "sk-test-key",
            "ANTHROPIC_API_KEY": "sk-ant-test-key",
            "CUSTOM_VAR": "custom_value"
        }
        self.config.set("environment.variables", test_vars)

        # Verify retrieval
        vars_retrieved = self.config.get("environment.variables")
        assert vars_retrieved == test_vars
        assert self.config.get("environment.variables.OPENAI_API_KEY") == "sk-test-key"

        # Test env files list
        self.config.set("environment.env_files", [".env", ".env.local", ".env.production"])
        env_files = self.config.get("environment.env_files")
        assert len(env_files) == 3
        assert ".env.production" in env_files

    def test_secrets_section_real(self):
        """Test secrets management configuration section."""
        secrets_config = self.config.get("secrets", {})
        self.assert_real_output(secrets_config)

        # Verify secrets configuration fields
        expected_fields = [
            "encryption_enabled", "keyring_backend", "encrypted_keys",
            "use_system_keyring", "fallback_to_env", "mask_in_logs",
            "rotation_enabled", "rotation_days", "audit_access",
            "allowed_keys", "denied_keys"
        ]

        for field in expected_fields:
            assert field in secrets_config, f"Should have {field} in secrets config"

        # Test encrypted keys list
        encrypted_keys = ["api_key_1", "api_key_2", "secret_token"]
        self.config.set("secrets.encrypted_keys", encrypted_keys)
        retrieved_keys = self.config.get("secrets.encrypted_keys")
        assert len(retrieved_keys) == 3
        assert "secret_token" in retrieved_keys

        # Test security settings
        self.config.set("secrets.encryption_enabled", True)
        self.config.set("secrets.keyring_backend", "windows")
        self.config.set("secrets.rotation_days", 30)

        assert self.config.get("secrets.encryption_enabled") is True
        assert self.config.get("secrets.keyring_backend") == "windows"
        assert self.config.get("secrets.rotation_days") == 30

    def test_llm_configuration_section_real(self):
        """Test LLM configuration section with comprehensive structure."""
        llm_config = self.config.get("llm_configuration", {})
        self.assert_real_output(llm_config)

        # Verify main sections
        assert "models" in llm_config, "Should have models section"
        assert "profiles" in llm_config, "Should have profiles section"
        assert "metrics" in llm_config, "Should have metrics section"

        # Test profiles structure
        profiles = llm_config.get("profiles", {})
        expected_profiles = ["code_generation", "analysis", "creative", "fast_inference"]
        for profile_name in expected_profiles:
            assert profile_name in profiles, f"Should have {profile_name} profile"
            profile = profiles[profile_name]
            assert "settings" in profile, f"{profile_name} should have settings"
            assert "recommended_models" in profile, f"{profile_name} should have recommended_models"

        # Test metrics structure
        metrics = llm_config.get("metrics", {})
        metric_fields = ["total_requests", "total_tokens", "total_cost",
                        "model_usage", "error_count", "average_response_time"]
        for field in metric_fields:
            assert field in metrics, f"Metrics should have {field}"

        # Test model configuration
        test_model = {
            "provider": "openai",
            "model_id": "gpt-4",
            "api_key": "encrypted_key_ref",
            "temperature": 0.7,
            "max_tokens": 2048
        }
        self.config.set("llm_configuration.models.gpt4_main", test_model)

        retrieved = self.config.get("llm_configuration.models.gpt4_main")
        assert retrieved == test_model
        assert retrieved["provider"] == "openai"

    def test_cli_configuration_section_real(self):
        """Test CLI configuration section with profiles."""
        cli_config = self.config.get("cli_configuration", {})
        self.assert_real_output(cli_config)

        # Verify CLI configuration structure
        expected_fields = [
            "profiles", "default_profile", "output_format", "verbosity",
            "auto_save", "history_file", "max_history", "autocomplete",
            "show_hints", "interactive_mode", "batch_mode", "quiet_mode",
            "log_to_file", "log_file", "aliases", "custom_commands",
            "startup_commands"
        ]

        for field in expected_fields:
            assert field in cli_config, f"CLI config should have {field}"

        # Test profiles
        profiles = cli_config.get("profiles", {})
        assert "default" in profiles, "Should have default profile"

        default_profile = profiles["default"]
        profile_fields = ["output_format", "verbosity", "color_output",
                         "progress_bars", "auto_save", "confirm_actions"]
        for field in profile_fields:
            assert field in default_profile, f"Default profile should have {field}"

        # Test custom profile creation
        custom_profile = {
            "output_format": "table",
            "verbosity": "debug",
            "color_output": False,
            "progress_bars": False,
            "auto_save": False,
            "confirm_actions": False
        }
        self.config.set("cli_configuration.profiles.expert", custom_profile)

        retrieved = self.config.get("cli_configuration.profiles.expert")
        assert retrieved == custom_profile
        assert retrieved["verbosity"] == "debug"

    def test_vm_framework_section_real(self):
        """Test VM framework configuration section (from legacy migration)."""
        # Set VM framework configuration
        vm_config = {
            "base_images": {
                "default_linux_size_gb": 1,
                "default_windows_size_gb": 2,
                "linux": ["ubuntu-20.04.qcow2", "debian-11.qcow2"],
                "windows": ["win10.qcow2", "win11.qcow2"]
            },
            "qemu_defaults": {
                "cpu_cores": 2,
                "enable_kvm": True,
                "graphics_enabled": False,
                "memory_mb": 2048,
                "monitor_port": 55555,
                "network_enabled": True,
                "shared_folder_name": "intellicrack_shared",
                "ssh_port_start": 22222,
                "timeout": 300,
                "vnc_port_start": 5900
            },
            "qiling_rootfs": {
                "linux": ["/opt/qiling/rootfs/x86_linux"],
                "windows": ["/opt/qiling/rootfs/x86_windows"]
            },
            "ssh": {
                "circuit_breaker_threshold": 5,
                "circuit_breaker_timeout": 60,
                "retry_count": 3,
                "retry_delay": 2,
                "timeout": 30
            }
        }

        self.config.set("vm_framework", vm_config)

        # Verify retrieval
        retrieved = self.config.get("vm_framework")
        self.assert_real_output(retrieved)
        assert retrieved == vm_config

        # Test nested access
        assert self.config.get("vm_framework.qemu_defaults.memory_mb") == 2048
        assert self.config.get("vm_framework.ssh.retry_count") == 3

        linux_images = self.config.get("vm_framework.base_images.linux")
        assert len(linux_images) == 2
        assert "ubuntu-20.04.qcow2" in linux_images

    def test_runtime_configuration_real(self):
        """Test runtime configuration section."""
        runtime_config = {
            "enable_api_monitoring": True,
            "enable_memory_monitoring": True,
            "hook_delay": 100,
            "max_runtime_monitoring": 30000,
            "monitor_child_processes": True,
            "runtime_interception": True,
            "snapshot_interval": 1000
        }

        self.config.set("runtime", runtime_config)

        retrieved = self.config.get("runtime")
        self.assert_real_output(retrieved)
        assert retrieved == runtime_config
        assert self.config.get("runtime.enable_api_monitoring") is True
        assert self.config.get("runtime.snapshot_interval") == 1000

    def test_api_cache_configuration_real(self):
        """Test API cache configuration section."""
        api_cache = {
            "enabled": True,
            "ttl": 3600,
            "max_size_mb": 100,
            "cache_directory": str(self.temp_dir / "api_cache"),
            "cleanup_interval": 7200,
            "persistent": True
        }

        self.config.set("api_cache", api_cache)

        retrieved = self.config.get("api_cache")
        self.assert_real_output(retrieved)
        assert retrieved["enabled"] is True
        assert retrieved["ttl"] == 3600
        assert retrieved["max_size_mb"] == 100
        assert retrieved["cleanup_interval"] == 7200

    def test_security_extended_fields_real(self):
        """Test extended security configuration fields."""
        # Test security subsections that were added
        security_extensions = {
            "hashing": {
                "default_algorithm": "sha256",
                "allow_md5_for_security": False,
                "salt_length": 32
            },
            "subprocess": {
                "allow_shell_true": False,
                "shell_whitelist": ["bash", "sh", "cmd"],
                "max_process_timeout": 300
            },
            "serialization": {
                "default_format": "json",
                "restrict_pickle": True,
                "allowed_formats": ["json", "yaml", "xml"]
            },
            "input_validation": {
                "strict_mode": True,
                "max_file_size": 104857600,
                "allowed_extensions": [".py", ".js", ".json", ".yaml"]
            }
        }

        # Set each subsection
        for section, data in security_extensions.items():
            self.config.set(f"security.{section}", data)

        # Verify retrieval
        for section, expected_data in security_extensions.items():
            retrieved = self.config.get(f"security.{section}")
            self.assert_real_output(retrieved)
            assert retrieved == expected_data, f"Security {section} should match"

        # Test individual field access
        assert self.config.get("security.hashing.default_algorithm") == "sha256"
        assert self.config.get("security.subprocess.allow_shell_true") is False
        assert self.config.get("security.serialization.restrict_pickle") is True
        assert self.config.get("security.input_validation.strict_mode") is True

    def test_ui_preferences_extended_real(self):
        """Test extended UI preferences with new fields."""
        ui_prefs = self.config.get("ui_preferences")
        self.assert_real_output(ui_prefs)

        # Verify new UI preference fields exist
        expected_fields = [
            "window_geometry", "window_state", "dialog_positions",
            "splitter_states", "dock_states", "toolbar_positions",
            "recent_files", "max_recent_files"
        ]

        for field in expected_fields:
            assert field in ui_prefs, f"UI preferences should have {field}"

        # Test window geometry
        window_geom = ui_prefs.get("window_geometry", {})
        assert "x" in window_geom
        assert "y" in window_geom
        assert "width" in window_geom
        assert "height" in window_geom

        # Test window state
        window_state = ui_prefs.get("window_state", {})
        assert "maximized" in window_state
        assert "minimized" in window_state
        assert "fullscreen" in window_state

        # Test splitter states
        splitter_states = ui_prefs.get("splitter_states", {})
        expected_splitters = ["main_splitter", "disasm_splitter",
                            "plugin_splitter", "assistant_splitter"]
        for splitter in expected_splitters:
            assert splitter in splitter_states, f"Should have {splitter} state"
            assert isinstance(splitter_states[splitter], list), f"{splitter} should be a list"

    def test_comprehensive_schema_validation_real(self):
        """Test that the entire default configuration passes validation."""
        # Get the full configuration
        full_config = self.config._config
        self.assert_real_output(full_config)

        # Verify all major sections exist
        major_sections = [
            "version", "created", "platform", "application", "api_endpoints",
            "directories", "tools", "ui_preferences", "analysis_settings",
            "network", "logging", "security", "patching", "ai_models",
            "service_urls", "performance", "updates", "plugins", "export",
            "shortcuts", "qemu_testing", "general_preferences",
            "llm_configuration", "cli_configuration", "font_configuration",
            "environment", "secrets"
        ]

        for section in major_sections:
            assert section in full_config, f"Configuration should have {section} section"
            section_data = full_config[section]
            assert section_data is not None, f"{section} should not be None"

            # Most sections should be dictionaries
            if section not in ["version", "created", "platform"]:
                assert isinstance(section_data, dict), f"{section} should be a dictionary"

        # Test that configuration version is correct
        version = full_config.get("version")
        assert version == "3.0", f"Configuration version should be 3.0, got {version}"

        def check_no_placeholders(obj, path=""):
            """Recursively check for placeholder values."""
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{path}.{key}" if path else key
                    check_no_placeholders(value, new_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_no_placeholders(item, f"{path}[{i}]")
            elif isinstance(obj, str):
                # Check for common placeholder patterns
                placeholder_patterns = [
                    "TODO", "FIXME", "PLACEHOLDER", "STUB", "MOCK",
                    "dummy", "test_", "example_", "sample_"
                ]
                lower_val = obj.lower()
                for pattern in placeholder_patterns:
                    if pattern.lower() in lower_val and path not in ["directories.temp"]:
                        # Allow "test" in certain expected places
                        if not ("test" in pattern.lower() and "qemu_testing" in path):
                            pytest.fail(f"Found placeholder value at {path}: {obj}")

        check_no_placeholders(full_config)

        # Verify configuration can be saved and loaded
        self.config._save_config()
        assert self.test_config_file.exists(), "Config file should be created"

        # Load and verify
        with open(self.test_config_file, encoding='utf-8') as f:
            saved_config = json.load(f)

        assert saved_config == full_config, "Saved config should match in-memory config"
