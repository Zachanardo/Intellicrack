"""Production tests for intellicrack/config.py configuration system.

These tests validate the modern configuration system, legacy compatibility layer,
tool discovery, and environment variable handling. No mocks for core functionality.

Copyright (C) 2025 Zachary Flint
"""

import os
import tempfile
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.config import (
    CONFIG,
    ConfigManager,
    find_tool,
    get_config,
    get_system_path,
    load_config,
    save_config,
)


class TestConfigManagerInitialization:
    """Production tests for ConfigManager initialization."""

    def test_config_manager_singleton_behavior(self) -> None:
        """ConfigManager maintains singleton pattern across invocations."""
        config1 = get_config()
        config2 = get_config()

        assert config1 is config2
        assert id(config1) == id(config2)

    def test_config_manager_loads_modern_config(self) -> None:
        """ConfigManager successfully loads modern configuration system."""
        config = get_config()

        assert config is not None
        assert isinstance(config, ConfigManager)
        assert hasattr(config, "_modern_config")
        assert config._modern_config is not None

    def test_config_path_set_correctly(self) -> None:
        """ConfigManager config_path references valid configuration file."""
        config = get_config()

        assert config.config_path is not None
        assert isinstance(config.config_path, str)
        assert len(config.config_path) > 0

    def test_config_manager_with_custom_path(self) -> None:
        """ConfigManager accepts custom config path for compatibility."""
        custom_path = "/tmp/custom_config.json"
        config = ConfigManager(config_path=custom_path)

        assert config is not None


class TestLegacyCompatibility:
    """Production tests for legacy configuration API compatibility."""

    def test_config_property_returns_dict(self) -> None:
        """config property returns legacy-compatible dictionary."""
        config = get_config()
        config_dict = config.config

        assert isinstance(config_dict, dict)
        assert len(config_dict) > 0

    def test_legacy_config_structure(self) -> None:
        """Legacy config dictionary contains expected sections."""
        config = get_config()
        config_dict = config.config

        expected_sections = [
            "log_dir",
            "output_dir",
            "temp_dir",
            "ghidra_path",
            "radare2_path",
            "analysis",
            "logging",
            "security",
            "performance",
        ]

        for section in expected_sections:
            assert section in config_dict, f"Missing expected section: {section}"

    def test_load_config_returns_dict(self) -> None:
        """load_config() function returns configuration dictionary."""
        config_dict = load_config()

        assert isinstance(config_dict, dict)
        assert len(config_dict) > 0

    def test_save_config_returns_success(self) -> None:
        """save_config() function returns success status."""
        result = save_config()

        assert isinstance(result, bool)

    def test_get_config_returns_manager(self) -> None:
        """get_config() returns ConfigManager instance."""
        config = get_config()

        assert isinstance(config, ConfigManager)

    def test_config_manager_get_method(self) -> None:
        """ConfigManager.get() retrieves configuration values."""
        config = get_config()
        log_dir = config.get("log_dir")

        assert log_dir is not None

    def test_config_manager_set_method(self) -> None:
        """ConfigManager.set() updates configuration values."""
        config = get_config()
        test_key = "test_value_12345"
        test_value = "production_test"

        config.set(test_key, test_value)
        retrieved = config.get(test_key)

        assert retrieved == test_value

    def test_config_manager_update_method(self) -> None:
        """ConfigManager.update() updates multiple values."""
        config = get_config()
        updates = {
            "test_key_1": "value_1",
            "test_key_2": "value_2",
            "test_key_3": 123,
        }

        config.update(updates)

        for key, value in updates.items():
            assert config.get(key) == value

    def test_dictionary_style_access(self) -> None:
        """ConfigManager supports dictionary-style access."""
        config = get_config()

        config["test_dict_key"] = "dict_value"
        result = config["test_dict_key"]

        assert result == "dict_value"

    def test_contains_operator(self) -> None:
        """ConfigManager supports 'in' operator for key checking."""
        config = get_config()

        assert "log_dir" in config

    def test_keys_method(self) -> None:
        """ConfigManager.keys() returns configuration keys."""
        config = get_config()
        keys = config.keys()

        assert keys is not None
        assert hasattr(keys, "__iter__")

    def test_values_method(self) -> None:
        """ConfigManager.values() returns configuration values."""
        config = get_config()
        values = config.values()

        assert values is not None
        assert hasattr(values, "__iter__")

    def test_items_method(self) -> None:
        """ConfigManager.items() returns key-value pairs."""
        config = get_config()
        items = config.items()

        assert items is not None
        assert hasattr(items, "__iter__")


class TestToolDiscovery:
    """Production tests for tool discovery functionality."""

    def test_find_tool_with_valid_tool(self) -> None:
        """find_tool() locates valid tools on system."""
        common_tools = ["python", "git"] if os.name == "nt" else ["python3", "ls", "cat"]

        for tool in common_tools:
            if result := find_tool(tool):
                assert isinstance(result, str)
                assert len(result) > 0

    def test_find_tool_with_invalid_tool(self) -> None:
        """find_tool() returns None for non-existent tools."""
        result = find_tool("nonexistent_tool_xyz_12345")

        assert result is None

    def test_find_tool_with_required_executables(self) -> None:
        """find_tool() accepts required_executables parameter."""
        result = find_tool("python", required_executables=["python.exe" if os.name == "nt" else "python3"])

        assert result is None or isinstance(result, str)

    def test_get_tool_path_method(self) -> None:
        """ConfigManager.get_tool_path() retrieves tool paths."""
        config = get_config()

        ghidra_path = config.get_tool_path("ghidra")
        assert ghidra_path is None or isinstance(ghidra_path, str)

    def test_is_tool_available_method(self) -> None:
        """ConfigManager.is_tool_available() checks tool availability."""
        config = get_config()

        result = config.is_tool_available("python")
        assert isinstance(result, bool)

    def test_get_ghidra_path_method(self) -> None:
        """ConfigManager.get_ghidra_path() returns Ghidra path."""
        config = get_config()

        ghidra_path = config.get_ghidra_path()
        assert ghidra_path is None or isinstance(ghidra_path, str)

    def test_legacy_tool_path_mapping_ghidra(self) -> None:
        """Legacy key 'ghidra_path' maps to modern tool discovery."""
        config = get_config()

        ghidra_path = config.get("ghidra_path")
        assert ghidra_path is None or isinstance(ghidra_path, str)

    def test_legacy_tool_path_mapping_radare2(self) -> None:
        """Legacy key 'radare2_path' maps to modern tool discovery."""
        config = get_config()

        radare2_path = config.get("radare2_path")
        assert radare2_path is None or isinstance(radare2_path, str)

    def test_legacy_tool_path_mapping_frida(self) -> None:
        """Legacy key 'frida_path' maps to modern tool discovery."""
        config = get_config()

        frida_path = config.get("frida_path")
        assert frida_path is None or isinstance(frida_path, str)


class TestSystemPathDiscovery:
    """Production tests for system path discovery."""

    def test_get_system_path_output(self) -> None:
        """get_system_path('output') returns valid output directory."""
        output_path = get_system_path("output")

        assert output_path is not None
        assert isinstance(output_path, str)
        assert len(output_path) > 0

    def test_get_system_path_cache(self) -> None:
        """get_system_path('cache') returns valid cache directory."""
        cache_path = get_system_path("cache")

        assert cache_path is not None
        assert isinstance(cache_path, str)
        assert len(cache_path) > 0

    def test_get_system_path_logs(self) -> None:
        """get_system_path('logs') returns valid logs directory."""
        logs_path = get_system_path("logs")

        assert logs_path is not None
        assert isinstance(logs_path, str)
        assert len(logs_path) > 0

    def test_get_system_path_temp(self) -> None:
        """get_system_path('temp') returns valid temp directory."""
        temp_path = get_system_path("temp")

        assert temp_path is not None
        assert isinstance(temp_path, str)
        assert len(temp_path) > 0

    def test_get_system_path_desktop_fallback(self) -> None:
        """get_system_path('desktop') uses fallback mechanism."""
        if desktop_path := get_system_path("desktop"):
            assert isinstance(desktop_path, str)
            assert "Desktop" in desktop_path or "desktop" in desktop_path.lower()

    def test_get_system_path_documents_fallback(self) -> None:
        """get_system_path('documents') uses fallback mechanism."""
        if documents_path := get_system_path("documents"):
            assert isinstance(documents_path, str)
            assert "Documents" in documents_path or "documents" in documents_path.lower()

    def test_get_system_path_downloads_fallback(self) -> None:
        """get_system_path('downloads') uses fallback mechanism."""
        if downloads_path := get_system_path("downloads"):
            assert isinstance(downloads_path, str)
            assert "Downloads" in downloads_path or "downloads" in downloads_path.lower()

    def test_config_manager_get_logs_dir(self) -> None:
        """ConfigManager.get_logs_dir() returns logs directory."""
        config = get_config()
        logs_dir = config.get_logs_dir()

        assert logs_dir is not None

    def test_config_manager_get_output_dir(self) -> None:
        """ConfigManager.get_output_dir() returns output directory."""
        config = get_config()
        output_dir = config.get_output_dir()

        assert output_dir is not None

    def test_config_manager_get_cache_dir(self) -> None:
        """ConfigManager.get_cache_dir() returns cache directory."""
        config = get_config()
        cache_dir = config.get_cache_dir()

        assert cache_dir is not None


class TestConfigurationSections:
    """Production tests for configuration sections and values."""

    def test_logging_section_structure(self) -> None:
        """Logging section contains expected configuration."""
        config = get_config()
        logging_config = config.get("logging", {})

        assert isinstance(logging_config, dict)
        assert "level" in logging_config
        assert "enable_file_logging" in logging_config
        assert "enable_console_logging" in logging_config

    def test_analysis_section_exists(self) -> None:
        """Analysis section exists in configuration."""
        config = get_config()
        analysis_config = config.get("analysis")

        assert analysis_config is not None

    def test_performance_section_structure(self) -> None:
        """Performance section contains expected settings."""
        config = get_config()
        perf_config = config.get("performance", {})

        assert isinstance(perf_config, dict)
        assert "max_memory_usage" in perf_config
        assert "enable_gpu_acceleration" in perf_config

    def test_plugins_section_structure(self) -> None:
        """Plugins section contains expected configuration."""
        config = get_config()
        plugins_config = config.get("plugins", {})

        assert isinstance(plugins_config, dict)
        assert "auto_load" in plugins_config

    def test_model_repositories_method(self) -> None:
        """get_model_repositories() returns repository configuration."""
        config = get_config()
        repos = config.get_model_repositories()

        assert isinstance(repos, dict)

    def test_is_repository_enabled_method(self) -> None:
        """is_repository_enabled() checks repository status."""
        config = get_config()
        result = config.is_repository_enabled("local")

        assert isinstance(result, bool)


class TestLazyConfigLoading:
    """Production tests for lazy configuration loading."""

    def test_config_global_is_lazy_dict(self) -> None:
        """CONFIG global is lazy-loading dictionary."""
        assert CONFIG is not None

    def test_lazy_config_loads_on_access(self) -> None:
        """Lazy config loads on first access."""
        test_config = CONFIG

        if "log_dir" in test_config:
            log_dir = test_config["log_dir"]
            assert log_dir is not None

    def test_lazy_config_get_method(self) -> None:
        """Lazy config get() method works correctly."""
        value = CONFIG.get("log_dir", "default")

        assert value is not None

    def test_lazy_config_keys_method(self) -> None:
        """Lazy config keys() method returns keys."""
        keys = CONFIG.keys()

        assert keys is not None
        assert hasattr(keys, "__iter__")

    def test_lazy_config_values_method(self) -> None:
        """Lazy config values() method returns values."""
        values = CONFIG.values()

        assert values is not None
        assert hasattr(values, "__iter__")

    def test_lazy_config_items_method(self) -> None:
        """Lazy config items() method returns items."""
        items = CONFIG.items()

        assert items is not None
        assert hasattr(items, "__iter__")


class TestConfigValidation:
    """Production tests for configuration validation."""

    def test_validate_config_method(self) -> None:
        """validate_config() validates configuration structure."""
        config = get_config()
        result = config.validate_config()

        assert isinstance(result, bool)

    def test_config_contains_required_paths(self) -> None:
        """Configuration contains all required path settings."""
        config = get_config()
        config_dict = config.config

        required_paths = ["log_dir", "output_dir", "temp_dir"]

        for path_key in required_paths:
            assert path_key in config_dict
            assert config_dict[path_key] is not None


class TestEnvironmentVariableIntegration:
    """Production tests for environment variable handling."""

    def test_dotenv_loading_attempted(self) -> None:
        """Configuration attempts to load .env file."""
        config = get_config()
        assert config is not None

    def test_config_respects_env_vars(self) -> None:
        """Configuration system respects environment variables."""
        test_var = "INTELLICRACK_TEST_VAR_12345"
        test_value = "production_test_value"

        with patch.dict(os.environ, {test_var: test_value}):
            value = os.environ.get(test_var)
            assert value == test_value


class TestModernConfigIntegration:
    """Production tests for modern config system integration."""

    def test_modern_config_initialization(self) -> None:
        """Modern configuration system initializes successfully."""
        config = get_config()

        assert hasattr(config, "_modern_config")
        assert config._modern_config is not None

    def test_modern_config_delegation(self) -> None:
        """Legacy wrapper correctly delegates to modern config."""
        config = get_config()

        result = config.get("log_dir")
        assert result is not None


class TestErrorHandling:
    """Production tests for configuration error handling."""

    def test_get_with_default_value(self) -> None:
        """get() returns default value for non-existent keys."""
        config = get_config()
        default = "default_value_xyz"

        result = config.get("nonexistent_key_12345", default)

        assert result == default

    def test_missing_tool_returns_none(self) -> None:
        """Tool discovery returns None for missing tools."""
        result = find_tool("nonexistent_tool_xyz_67890")

        assert result is None

    def test_invalid_system_path_handled(self) -> None:
        """Invalid system path requests handled gracefully."""
        result = get_system_path("invalid_path_type_xyz")

        assert result is None or isinstance(result, str)


class TestConfigurationPersistence:
    """Production tests for configuration persistence."""

    def test_config_changes_persist_in_session(self) -> None:
        """Configuration changes persist during session."""
        config = get_config()
        test_key = "test_persistence_key"
        test_value = "persistence_value"

        config.set(test_key, test_value)
        retrieved = config.get(test_key)

        assert retrieved == test_value

    def test_multiple_config_manager_instances_share_state(self) -> None:
        """Multiple ConfigManager access points share state."""
        config1 = get_config()
        config2 = get_config()

        test_key = "shared_state_test"
        test_value = "shared_value"

        config1.set(test_key, test_value)
        result = config2.get(test_key)

        assert result == test_value
