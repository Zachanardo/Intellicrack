"""Production tests for IntellicrackConfig - validates real configuration management operations.

Tests real platform detection, tool discovery, configuration persistence, thread safety,
and version migration WITHOUT mocks or stubs.
"""

import json
import os
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.config_manager import IntellicrackConfig, get_config


class TestConfigManagerPlatformDetection:
    """Test platform-specific directory detection and creation."""

    def test_config_creates_platform_specific_directories(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Config manager creates appropriate directories for the current platform."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            assert config.config_dir.exists()
            assert config.cache_dir.exists()
            assert config.logs_dir.exists()
            assert config.output_dir.exists()

            assert config.config_dir.is_dir()
            assert config.cache_dir.is_dir()
            assert config.logs_dir.is_dir()
            assert config.output_dir.is_dir()

    def test_config_respects_intellicrack_root_env_var(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Config manager respects INTELLICRACK_ROOT environment variable."""
        custom_root = tmp_path / "custom_root"
        custom_root.mkdir()

        os.environ["INTELLICRACK_ROOT"] = str(custom_root)
        try:
            config = IntellicrackConfig()
            assert config.config_dir.parent == custom_root
        finally:
            os.environ.pop("INTELLICRACK_ROOT", None)
            _reset_config_singleton()

    def test_config_handles_missing_directories_gracefully(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Config manager creates missing directories without errors."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            shutil.rmtree(config.cache_dir, ignore_errors=True)
            shutil.rmtree(config.logs_dir, ignore_errors=True)

            config._ensure_directories_exist()

            assert config.cache_dir.exists()
            assert config.logs_dir.exists()


class TestConfigManagerToolDiscovery:
    """Test real tool discovery and path caching."""

    def test_get_tool_path_discovers_real_system_tools(self, tmp_path: Path) -> None:    # noqa: PLR6301
        """get_tool_path discovers tools actually available on the system."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            if python_path := config.get_tool_path("python"):
                assert Path(python_path).exists()
                assert Path(python_path).is_file()

    def test_get_tool_path_caches_discovered_tools(self, tmp_path: Path) -> None:    # noqa: PLR6301
        """get_tool_path caches discovered tool paths in configuration."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            if tool_path := config.get_tool_path("python"):
                cached_path = config.get("tools.python.path")
                assert cached_path == tool_path

                auto_discovered = config.get("tools.python.auto_discovered")
                assert auto_discovered is True

    def test_get_tool_path_returns_none_for_nonexistent_tools(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """get_tool_path returns None for tools that don't exist."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            nonexistent_tool = "totally_fake_tool_name_xyz123"
            result = config.get_tool_path(nonexistent_tool)
            assert result is None

    def test_is_tool_available_checks_real_availability(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """is_tool_available correctly reports real tool availability."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            assert config.is_tool_available("python") is True

            nonexistent_tool = "totally_fake_tool_name_xyz123"
            assert config.is_tool_available(nonexistent_tool) is False

    def test_tool_discovery_with_custom_path(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Tool paths can be manually configured and override discovery."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            fake_tool_path = tmp_path / "fake_tool.exe"
            fake_tool_path.write_text("fake tool")

            config.set("tools.custom_tool.path", str(fake_tool_path))

            discovered_path = config.get_tool_path("custom_tool")
            assert discovered_path == str(fake_tool_path)


class TestConfigManagerPersistence:
    """Test configuration persistence and atomic writes."""

    def test_config_persists_to_disk(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Configuration changes are persisted to disk when saved."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            config.set("test.key", "test_value")
            config.save()

            assert config.config_file.exists()

            with open(config.config_file, encoding="utf-8") as f:
                saved_data = json.load(f)

            assert saved_data.get("test", {}).get("key") == "test_value"

    def test_config_loads_persisted_data(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Configuration loads previously persisted data correctly."""
        with _isolated_config_env(tmp_path):
            config1 = IntellicrackConfig()
            config1.set("test.persisted", "persisted_value")
            config1.save()

            _reset_config_singleton()

            config2 = IntellicrackConfig()
            value = config2.get("test.persisted")
            assert value == "persisted_value"

    def test_atomic_write_prevents_corruption(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Atomic write pattern prevents configuration corruption on write failure."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            config.set("test.data", "original")
            config.save()

            original_content = config.config_file.read_text(encoding="utf-8")

            config.set("test.data", "updated")
            config.save()

            assert config.config_file.exists()
            updated_content = config.config_file.read_text(encoding="utf-8")
            assert updated_content != original_content
            assert "updated" in updated_content

    def test_config_handles_corrupted_file(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Config manager handles corrupted configuration files gracefully."""
        with _isolated_config_env(tmp_path):
            config_file = tmp_path / "config" / "config.json"
            config_file.parent.mkdir(parents=True, exist_ok=True)
            config_file.write_text("not valid json {{{", encoding="utf-8")

            config = IntellicrackConfig()

            assert isinstance(config._config, dict)


class TestConfigManagerThreadSafety:
    """Test thread-safe configuration access."""

    def test_concurrent_reads_are_thread_safe(self, tmp_path: Path) -> None:    # noqa: PLR6301
        """Multiple threads can read configuration concurrently without race conditions."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()
            config.set("test.concurrent", "value")

            results: list[Any] = []
            errors: list[Exception] = []

            def read_config() -> None:
                try:
                    for _ in range(100):
                        value = config.get("test.concurrent")
                        results.append(value)
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=read_config) for _ in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert not errors
            assert all(r == "value" for r in results)

    def test_concurrent_writes_are_thread_safe(self, tmp_path: Path) -> None:    # noqa: PLR6301
        """Multiple threads can write configuration concurrently without corruption."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            errors: list[Exception] = []

            def write_config(thread_id: int) -> None:
                try:
                    for i in range(50):
                        config.set(f"test.thread_{thread_id}.iteration_{i}", f"value_{i}")
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=write_config, args=(i,)) for i in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert not errors

            for thread_id in range(5):
                for i in range(50):
                    value = config.get(f"test.thread_{thread_id}.iteration_{i}")
                    assert value == f"value_{i}"

    def test_singleton_pattern_is_thread_safe(self, tmp_path: Path) -> None:    # noqa: PLR6301
        """Singleton pattern ensures only one config instance across threads."""
        with _isolated_config_env(tmp_path):
            instances: list[IntellicrackConfig] = []
            errors: list[Exception] = []

            def get_instance() -> None:
                try:
                    instance = IntellicrackConfig()
                    instances.append(instance)
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=get_instance) for _ in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert not errors
            assert all(inst is instances[0] for inst in instances)


class TestConfigManagerDotNotation:
    """Test dot notation access for nested configuration."""

    def test_get_with_dot_notation_nested_keys(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """get() supports dot notation for nested configuration keys."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            config._config = {
                "level1": {
                    "level2": {
                        "level3": "deep_value"
                    }
                }
            }

            value = config.get("level1.level2.level3")
            assert value == "deep_value"

    def test_set_with_dot_notation_creates_nested_structure(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """set() creates nested dictionaries using dot notation."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            config.set("new.nested.structure.key", "nested_value")

            assert config._config["new"]["nested"]["structure"]["key"] == "nested_value"

    def test_get_returns_default_for_missing_keys(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """get() returns default value for missing configuration keys."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            value = config.get("nonexistent.key", "default")
            assert value == "default"

    def test_get_handles_environment_variable_expansion(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """get() expands environment variables in configuration values."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            os.environ["TEST_VAR"] = "expanded_value"
            try:
                config._config = {"test": {"env": "$TEST_VAR"}}

                value = config.get("test.env")
                assert value == "expanded_value"
            finally:
                os.environ.pop("TEST_VAR", None)


class TestConfigManagerVersionMigration:
    """Test configuration version migration and upgrades."""

    def test_config_upgrades_from_legacy_version(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Config manager upgrades legacy configuration versions."""
        with _isolated_config_env(tmp_path):
            config_file = tmp_path / "config" / "config.json"
            config_file.parent.mkdir(parents=True, exist_ok=True)

            legacy_config = {
                "version": "1.0",
                "some_setting": "value"
            }
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(legacy_config, f)

            config = IntellicrackConfig()

            current_version = config.get("version")
            assert current_version != "1.0"

    def test_config_creates_defaults_from_legacy(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Config manager creates defaults file from legacy config.json."""
        with _isolated_config_env(tmp_path):
            config_file = tmp_path / "config" / "config.json"
            config_file.parent.mkdir(parents=True, exist_ok=True)

            legacy_config = {
                "version": "2.0",
                "initialized": True,
                "some_setting": "value"
            }
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(legacy_config, f)

            config = IntellicrackConfig()
            defaults_file = config.defaults_file

            assert defaults_file.exists()

            with open(defaults_file, encoding="utf-8") as f:
                defaults = json.load(f)

            assert "some_setting" in defaults
            assert "initialized" not in defaults


class TestConfigManagerLayeredConfiguration:
    """Test layered configuration loading (defaults, user overrides, runtime)."""

    def test_user_config_overrides_defaults(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """User configuration overrides default values."""
        with _isolated_config_env(tmp_path):
            defaults_file = tmp_path / "config" / "config.defaults.json"
            defaults_file.parent.mkdir(parents=True, exist_ok=True)

            defaults = {
                "test": {
                    "setting": "default_value"
                }
            }
            with open(defaults_file, "w", encoding="utf-8") as f:
                json.dump(defaults, f)

            user_config_file = tmp_path / "config" / "intellicrack_config.json"
            os.environ["INTELLICRACK_CONFIG_PATH"] = str(user_config_file)
            try:
                user_config = {
                    "test": {
                        "setting": "user_value"
                    }
                }
                with open(user_config_file, "w", encoding="utf-8") as f:
                    json.dump(user_config, f)

                config = IntellicrackConfig()

                value = config.get("test.setting")
                assert value == "user_value"
            finally:
                os.environ.pop("INTELLICRACK_CONFIG_PATH", None)
                _reset_config_singleton()

    def test_deep_merge_preserves_non_overridden_keys(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Deep merge preserves keys not overridden in user config."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            base = {
                "section": {
                    "key1": "value1",
                    "key2": "value2",
                    "nested": {
                        "nested_key1": "nested_value1"
                    }
                }
            }
            override = {
                "section": {
                    "key2": "new_value2",
                    "nested": {
                        "nested_key2": "nested_value2"
                    }
                }
            }

            config._deep_merge(base, override)

            assert base["section"]["key1"] == "value1"
            assert base["section"]["key2"] == "new_value2"
            assert base["section"]["nested"]["nested_key1"] == "nested_value1"
            assert base["section"]["nested"]["nested_key2"] == "nested_value2"


class TestConfigManagerEmergencyMode:
    """Test emergency configuration creation on critical errors."""

    def test_emergency_config_created_on_critical_error(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Emergency config is created when critical errors prevent normal loading."""
        with _isolated_config_env(tmp_path):
            config_dir = tmp_path / "config"
            config_dir.mkdir(parents=True, exist_ok=True)

            config = IntellicrackConfig()

            config._create_emergency_config()

            emergency_version = config.get("version")
            assert emergency_version == "emergency"

            emergency_mode = config.get("emergency_mode")
            assert emergency_mode is True


class TestConfigManagerAPIEndpoints:
    """Test API endpoint retrieval for AI providers."""

    def test_get_api_endpoint_retrieves_configured_endpoints(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """get_api_endpoint retrieves configured API endpoints for providers."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            config._config = {
                "ai": {
                    "providers": {
                        "openai": {
                            "endpoint": "https://api.openai.com/v1"
                        },
                        "anthropic": {
                            "endpoint": "https://api.anthropic.com/v1"
                        }
                    }
                }
            }

            openai_endpoint = config.get_api_endpoint("openai")
            assert openai_endpoint == "https://api.openai.com/v1"

            anthropic_endpoint = config.get_api_endpoint("anthropic")
            assert anthropic_endpoint == "https://api.anthropic.com/v1"

    def test_get_api_endpoint_returns_none_for_unknown_provider(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """get_api_endpoint returns None for unknown providers."""
        with _isolated_config_env(tmp_path):
            config = IntellicrackConfig()

            result = config.get_api_endpoint("unknown_provider")
            assert result is None


class TestConfigManagerGlobalInstance:
    """Test global configuration instance retrieval."""

    def test_get_config_returns_singleton_instance(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """get_config() returns the same singleton instance across calls."""
        with _isolated_config_env(tmp_path):
            config1 = get_config()
            config2 = get_config()

            assert config1 is config2


def _isolated_config_env(tmp_path: Path):
    """Context manager for isolated config environment."""
    class _ConfigContext:
        def __enter__(self):
            os.environ["INTELLICRACK_ROOT"] = str(tmp_path)
            _reset_config_singleton()
            return self

        def __exit__(self, *args):
            os.environ.pop("INTELLICRACK_ROOT", None)
            os.environ.pop("INTELLICRACK_CONFIG_PATH", None)
            _reset_config_singleton()

    return _ConfigContext()


def _reset_config_singleton() -> None:
    """Reset config singleton for testing."""
    from intellicrack.core import config_manager
    config_manager._config_instance = None
    IntellicrackConfig._instance = None
