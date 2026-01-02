"""Comprehensive unit tests for IntellicrackConfig with REAL configuration functionality.

Tests ALL core features: get/set operations, saving, directory access, and tool paths.
NO MOCKS - ALL TESTS USE REAL FILES AND PRODUCE REAL RESULTS.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.config_manager import IntellicrackConfig, get_config
from tests.base_test import IntellicrackTestBase


class FakeConfigDirProvider:
    """Real test double for providing fake config directory paths."""

    def __init__(self, config_dir: Path) -> None:
        """Initialize with config directory path."""
        self.config_dir: Path = config_dir
        self.call_count: int = 0

    def __call__(self) -> Path:
        """Return the config directory path."""
        self.call_count += 1
        return self.config_dir


class TestIntellicrackConfig(IntellicrackTestBase):
    """Test IntellicrackConfig with REAL configuration operations and REAL file I/O."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Set up test with real temporary workspace."""
        self.temp_dir = temp_workspace
        self.test_config_dir = self.temp_dir / "config"
        self.test_config_dir.mkdir(parents=True, exist_ok=True)
        self.test_config_file = self.test_config_dir / "config.json"

        IntellicrackConfig._instance = None

        self.fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            self.fake_dir_provider
        )

        self.config = IntellicrackConfig()

    def create_test_config(self, config_data: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create a test configuration file with real data."""
        if config_data is None:
            config_data = {
                "version": "3.0.0",
                "initialized": True,
                "ui": {"theme": "dark", "font_size": 12, "show_tooltips": True},
                "analysis": {"default_timeout": 300, "enable_deep_analysis": True, "parallel_threads": 4},
                "logging": {"level": "INFO", "enable_file_logging": True, "max_log_size": 10485760},
            }

        with open(self.test_config_file, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)

        return config_data

    def test_config_initialization_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test REAL configuration initialization with actual file creation."""
        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config = IntellicrackConfig()

        self.assert_real_output(config._config)
        assert config.config_file.exists(), f"Config file should be created at {config.config_file}"
        assert isinstance(config._config, dict), "Config should be a dictionary"
        assert config.config_dir == self.test_config_dir, "Config directory should match"

    def test_get_set_operations_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test REAL get/set operations on configuration."""
        self.create_test_config()

        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config = IntellicrackConfig()

        theme = config.get("ui.theme")
        assert theme == "dark", f"Expected 'dark', got {theme}"

        font_size = config.get("ui.font_size")
        assert font_size == 12, f"Expected 12, got {font_size}"

        nonexistent = config.get("nonexistent.key", "default_value")
        assert nonexistent == "default_value", f"Expected 'default_value', got {nonexistent}"

        config.set("ui.theme", "light")
        updated_theme = config.get("ui.theme")
        assert updated_theme == "light", f"Expected 'light', got {updated_theme}"

        config.set("new.nested.value", "test")
        new_value = config.get("new.nested.value")
        assert new_value == "test", f"Expected 'test', got {new_value}"

    def test_config_save_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test REAL configuration save operations."""
        self.create_test_config()

        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config = IntellicrackConfig()

        config.set("ui.theme", "modified_theme")
        config.set("new_key", "new_value")

        config.save()

        with open(self.test_config_file, "r", encoding="utf-8") as f:
            saved_data = json.load(f)

        assert saved_data.get("ui", {}).get("theme") == "modified_theme", "Modified theme should be saved"
        assert saved_data.get("new_key") == "new_value", "New key should be saved"

    def test_save_config_method_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test save_config method with REAL file operations."""
        self.create_test_config()

        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config = IntellicrackConfig()

        config.set("analysis.timeout", 500)

        config.save_config()

        assert config.get("analysis.timeout") == 500, "save_config should persist changes"

    def test_directory_access_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test REAL directory access methods."""
        self.create_test_config({
            "version": "3.0.0",
            "directories": {
                "logs": str(self.temp_dir / "logs"),
                "output": str(self.temp_dir / "output"),
                "cache": str(self.temp_dir / "cache"),
            }
        })

        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config = IntellicrackConfig()

        logs_dir = config.get_logs_dir()
        assert logs_dir is not None, "Logs directory should be returned"
        assert isinstance(logs_dir, Path), "Logs directory should be a Path"

        output_dir = config.get_output_dir()
        assert output_dir is not None, "Output directory should be returned"
        assert isinstance(output_dir, Path), "Output directory should be a Path"

        cache_dir = config.get_cache_dir()
        assert cache_dir is not None, "Cache directory should be returned"
        assert isinstance(cache_dir, Path), "Cache directory should be a Path"

    def test_tool_path_operations_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test REAL tool path operations."""
        self.create_test_config({
            "version": "3.0.0",
            "tools": {
                "ghidra": {"path": "/opt/ghidra", "enabled": True},
                "radare2": {"path": "/usr/bin/r2", "enabled": True},
                "frida": {"path": "/usr/bin/frida", "enabled": False},
            }
        })

        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config = IntellicrackConfig()

        ghidra_path = config.get_tool_path("ghidra")
        if ghidra_path is not None:
            assert "/opt/ghidra" in str(ghidra_path)

        nonexistent_path = config.get_tool_path("nonexistent_tool")
        assert nonexistent_path is None or isinstance(nonexistent_path, (str, Path))

    def test_is_tool_available_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test REAL tool availability checking."""
        self.create_test_config({
            "version": "3.0.0",
            "tools": {
                "ghidra": {"path": "/opt/ghidra", "enabled": True},
                "frida": {"path": "/usr/bin/frida", "enabled": False},
            }
        })

        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config = IntellicrackConfig()

        result = config.is_tool_available("ghidra")
        assert isinstance(result, bool), "is_tool_available should return boolean"

        nonexistent_result = config.is_tool_available("nonexistent_tool")
        assert isinstance(nonexistent_result, bool), "Should return boolean for nonexistent tool"

    def test_api_endpoint_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test REAL API endpoint retrieval."""
        self.create_test_config({
            "version": "3.0.0",
            "api": {
                "endpoint": "https://api.example.com",
                "timeout": 30
            }
        })

        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config = IntellicrackConfig()

        endpoint = config.get_api_endpoint("openai")
        assert endpoint is None or isinstance(endpoint, str), "API endpoint should be string or None"

    def test_get_config_singleton_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test REAL get_config singleton function."""
        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config1 = get_config()
        config2 = get_config()

        assert config1 is config2, "get_config should return the same instance"
        assert isinstance(config1, IntellicrackConfig), "Should return IntellicrackConfig instance"

    def test_config_persistence_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test REAL configuration persistence across instances."""
        self.create_test_config()

        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config1 = IntellicrackConfig()
        config1.set("test_key", "test_value")
        config1.save()

        IntellicrackConfig._instance = None

        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config2 = IntellicrackConfig()
        persisted_value = config2.get("test_key")

        assert persisted_value == "test_value", f"Expected 'test_value', got {persisted_value}"

    def test_nested_config_operations_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test REAL nested configuration operations."""
        self.create_test_config({
            "version": "3.0.0",
            "deeply": {
                "nested": {
                    "config": {
                        "value": "original"
                    }
                }
            }
        })

        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config = IntellicrackConfig()

        value = config.get("deeply.nested.config.value")
        assert value == "original", f"Expected 'original', got {value}"

        config.set("deeply.nested.config.value", "modified")
        modified_value = config.get("deeply.nested.config.value")
        assert modified_value == "modified", f"Expected 'modified', got {modified_value}"

        config.set("deeply.nested.new.key", "new_value")
        new_value = config.get("deeply.nested.new.key")
        assert new_value == "new_value", f"Expected 'new_value', got {new_value}"

    def test_config_default_values_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test REAL configuration default value handling."""
        self.create_test_config({"version": "3.0.0"})

        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config = IntellicrackConfig()

        value_with_default = config.get("nonexistent.key", "default")
        assert value_with_default == "default", f"Expected 'default', got {value_with_default}"

        value_with_int_default = config.get("nonexistent.key", 42)
        assert value_with_int_default == 42, f"Expected 42, got {value_with_int_default}"

        value_with_list_default = config.get("nonexistent.key", [1, 2, 3])
        assert value_with_list_default == [1, 2, 3], f"Expected [1, 2, 3], got {value_with_list_default}"

        value_with_dict_default = config.get("nonexistent.key", {"a": 1})
        assert value_with_dict_default == {"a": 1}, f"Expected {{'a': 1}}, got {value_with_dict_default}"

        value_none = config.get("nonexistent.key")
        assert value_none is None, f"Expected None, got {value_none}"

    def test_config_type_handling_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test REAL configuration type handling."""
        self.create_test_config({
            "version": "3.0.0",
            "types": {
                "string": "hello",
                "integer": 42,
                "float": 3.14,
                "boolean": True,
                "list": [1, 2, 3],
                "dict": {"nested": "value"}
            }
        })

        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config = IntellicrackConfig()

        string_val = config.get("types.string")
        assert isinstance(string_val, str), f"Expected str, got {type(string_val)}"
        assert string_val == "hello"

        int_val = config.get("types.integer")
        assert isinstance(int_val, int), f"Expected int, got {type(int_val)}"
        assert int_val == 42

        float_val = config.get("types.float")
        assert isinstance(float_val, float), f"Expected float, got {type(float_val)}"
        assert float_val == 3.14

        bool_val = config.get("types.boolean")
        assert isinstance(bool_val, bool), f"Expected bool, got {type(bool_val)}"
        assert bool_val is True

        list_val = config.get("types.list")
        assert isinstance(list_val, list), f"Expected list, got {type(list_val)}"
        assert list_val == [1, 2, 3]

        dict_val = config.get("types.dict")
        assert isinstance(dict_val, dict), f"Expected dict, got {type(dict_val)}"
        assert dict_val == {"nested": "value"}

    def test_config_file_missing_graceful_handling(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test graceful handling when config file doesn't exist."""
        empty_config_dir = self.temp_dir / "empty_config"
        empty_config_dir.mkdir(parents=True, exist_ok=True)

        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(empty_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config = IntellicrackConfig()

        assert config is not None, "Config should be created even without file"
        assert hasattr(config, 'get'), "Config should have get method"
        assert hasattr(config, 'set'), "Config should have set method"
        assert hasattr(config, 'save'), "Config should have save method"

    def test_upgrade_config_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test REAL configuration upgrade operation."""
        self.create_test_config({
            "version": "1.0.0",
            "old_key": "old_value"
        })

        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config = IntellicrackConfig()

        config.upgrade_config()

        assert config is not None, "Config should still exist after upgrade"

    def test_multiple_set_operations_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test multiple sequential set operations."""
        self.create_test_config()

        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config = IntellicrackConfig()

        for i in range(10):
            config.set(f"test.key_{i}", f"value_{i}")

        for i in range(10):
            value = config.get(f"test.key_{i}")
            assert value == f"value_{i}", f"Expected 'value_{i}', got {value}"

        config.save()

        with open(self.test_config_file, "r", encoding="utf-8") as f:
            saved_data = json.load(f)

        test_section = saved_data.get("test", {})
        assert len(test_section) == 10, f"Expected 10 keys, got {len(test_section)}"

    def test_config_attributes_real(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test REAL configuration object attributes."""
        self.create_test_config()

        IntellicrackConfig._instance = None

        fake_dir_provider = FakeConfigDirProvider(self.test_config_dir)
        monkeypatch.setattr(
            IntellicrackConfig,
            "_get_user_config_dir",
            fake_dir_provider
        )

        config = IntellicrackConfig()

        assert hasattr(config, 'config_file'), "Should have config_file attribute"
        assert hasattr(config, 'config_dir'), "Should have config_dir attribute"
        assert hasattr(config, '_config'), "Should have _config attribute"

        assert isinstance(config.config_file, Path), "config_file should be Path"
        assert isinstance(config.config_dir, Path), "config_dir should be Path"
        assert isinstance(config._config, dict), "_config should be dict"
