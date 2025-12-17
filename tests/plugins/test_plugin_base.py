"""Production tests for plugins/plugin_base.py.

This module validates base plugin classes, metadata, and configuration management
for Intellicrack's plugin system used for extensible binary analysis.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.plugins.plugin_base import (
    DEFAULT_ANALYSIS_CONFIG,
    DEFAULT_BINARY_CONFIG,
    DEFAULT_NETWORK_CONFIG,
    BasePlugin,
    PluginConfigManager,
    PluginMetadata,
    create_plugin_info,
    create_register_function,
)


class TestPluginMetadata:
    """Test PluginMetadata class for plugin information storage."""

    def test_metadata_creation(self) -> None:
        """PluginMetadata stores all required plugin information."""
        metadata = PluginMetadata(
            name="TestPlugin",
            version="1.0.0",
            author="Test Author",
            description="Test description",
            categories=["analysis", "binary"],
        )

        assert metadata.name == "TestPlugin"
        assert metadata.version == "1.0.0"
        assert metadata.author == "Test Author"
        assert metadata.description == "Test description"
        assert metadata.categories == ["analysis", "binary"]

    def test_metadata_with_supported_formats(self) -> None:
        """PluginMetadata stores supported file formats."""
        metadata = PluginMetadata(
            name="BinaryPlugin",
            version="1.0",
            author="Author",
            description="Desc",
            categories=["binary"],
            supported_formats=["PE", "ELF", "Mach-O"],
        )

        assert metadata.supported_formats == ["PE", "ELF", "Mach-O"]

    def test_metadata_with_capabilities(self) -> None:
        """PluginMetadata stores plugin capabilities."""
        metadata = PluginMetadata(
            name="AnalysisPlugin",
            version="1.0",
            author="Author",
            description="Desc",
            categories=["analysis"],
            capabilities=["license_detection", "protection_analysis"],
        )

        assert metadata.capabilities == ["license_detection", "protection_analysis"]

    def test_metadata_defaults_empty_lists(self) -> None:
        """PluginMetadata defaults to empty lists for optional fields."""
        metadata = PluginMetadata(
            name="MinimalPlugin",
            version="1.0",
            author="Author",
            description="Desc",
            categories=[],
        )

        assert metadata.supported_formats == []
        assert metadata.capabilities == []

    def test_metadata_to_dict(self) -> None:
        """PluginMetadata.to_dict() converts metadata to dictionary."""
        metadata = PluginMetadata(
            name="DictPlugin",
            version="2.0",
            author="Test",
            description="Test plugin",
            categories=["test"],
            supported_formats=["PE"],
            capabilities=["crack"],
        )

        result = metadata.to_dict()

        assert isinstance(result, dict)
        assert result["name"] == "DictPlugin"
        assert result["version"] == "2.0"
        assert result["author"] == "Test"
        assert result["description"] == "Test plugin"
        assert result["categories"] == ["test"]
        assert result["supported_formats"] == ["PE"]
        assert result["capabilities"] == ["crack"]


class TestPluginConfigManager:
    """Test PluginConfigManager for plugin configuration."""

    def test_config_manager_initialization(self) -> None:
        """PluginConfigManager initializes with default config."""
        default_config = {"timeout": 30, "verbose": True}
        manager = PluginConfigManager(default_config)

        assert manager.config["timeout"] == 30
        assert manager.config["verbose"] is True

    def test_config_manager_get(self) -> None:
        """PluginConfigManager.get() retrieves configuration values."""
        manager = PluginConfigManager({"key1": "value1", "key2": 42})

        assert manager.get("key1") == "value1"
        assert manager.get("key2") == 42

    def test_config_manager_get_default(self) -> None:
        """PluginConfigManager.get() returns default for missing keys."""
        manager = PluginConfigManager({"existing": "value"})

        assert manager.get("missing", "default") == "default"
        assert manager.get("missing") is None

    def test_config_manager_set(self) -> None:
        """PluginConfigManager.set() updates configuration values."""
        manager = PluginConfigManager({"key": "old"})
        manager.set("key", "new")

        assert manager.get("key") == "new"

    def test_config_manager_update(self) -> None:
        """PluginConfigManager.update() updates multiple values."""
        manager = PluginConfigManager({"a": 1, "b": 2})
        manager.update({"b": 20, "c": 30})

        assert manager.get("a") == 1
        assert manager.get("b") == 20
        assert manager.get("c") == 30

    def test_config_manager_to_dict(self) -> None:
        """PluginConfigManager.to_dict() returns config copy."""
        manager = PluginConfigManager({"key": "value"})
        result = manager.to_dict()

        assert result == {"key": "value"}

        result["key"] = "modified"
        assert manager.get("key") == "value"

    def test_config_manager_does_not_modify_default(self) -> None:
        """PluginConfigManager does not modify original default config."""
        original = {"key": "value"}
        manager = PluginConfigManager(original)
        manager.set("key", "new")

        assert original["key"] == "value"


class TestBasePlugin:
    """Test BasePlugin abstract base class."""

    def test_base_plugin_initialization(self) -> None:
        """BasePlugin initializes with metadata and config."""

        class TestPlugin(BasePlugin):
            def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
                return {"status": "success"}

        metadata = PluginMetadata(
            name="Test",
            version="1.0",
            author="Author",
            description="Desc",
            categories=["test"],
        )
        plugin = TestPlugin(metadata, {"timeout": 30})

        assert plugin.name == "Test"
        assert plugin.version == "1.0"
        assert plugin.author == "Author"
        assert plugin.description == "Desc"
        assert plugin.categories == ["test"]

    def test_base_plugin_get_metadata(self) -> None:
        """BasePlugin.get_metadata() returns complete metadata dict."""

        class TestPlugin(BasePlugin):
            def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
                return {}

        metadata = PluginMetadata(
            name="MetaPlugin",
            version="1.0",
            author="Test",
            description="Test",
            categories=["test"],
        )
        plugin = TestPlugin(metadata)

        result = plugin.get_metadata()

        assert result["name"] == "MetaPlugin"
        assert result["version"] == "1.0"
        assert "config" in result
        assert "status" in result

    def test_base_plugin_validate_binary_valid_file(self) -> None:
        """BasePlugin.validate_binary() accepts valid binary files."""

        class TestPlugin(BasePlugin):
            def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
                return {}

        metadata = PluginMetadata("Test", "1.0", "Author", "Desc", [])
        plugin = TestPlugin(metadata)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
            temp_path = f.name
            f.write(b"\x90\x50\x56\x53" * 100)

        try:
            is_valid, message = plugin.validate_binary(temp_path)
            assert is_valid is True
            assert message == "Valid"
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_base_plugin_validate_binary_missing_file(self) -> None:
        """BasePlugin.validate_binary() rejects non-existent files."""

        class TestPlugin(BasePlugin):
            def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
                return {}

        metadata = PluginMetadata("Test", "1.0", "Author", "Desc", [])
        plugin = TestPlugin(metadata)

        is_valid, message = plugin.validate_binary("D:/nonexistent.exe")

        assert is_valid is False
        assert "does not exist" in message

    def test_base_plugin_validate_binary_empty_path(self) -> None:
        """BasePlugin.validate_binary() rejects empty paths."""

        class TestPlugin(BasePlugin):
            def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
                return {}

        metadata = PluginMetadata("Test", "1.0", "Author", "Desc", [])
        plugin = TestPlugin(metadata)

        is_valid, message = plugin.validate_binary("")

        assert is_valid is False
        assert "No binary path" in message

    def test_base_plugin_validate_binary_directory(self) -> None:
        """BasePlugin.validate_binary() rejects directories."""

        class TestPlugin(BasePlugin):
            def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
                return {}

        metadata = PluginMetadata("Test", "1.0", "Author", "Desc", [])
        plugin = TestPlugin(metadata)

        with tempfile.TemporaryDirectory() as temp_dir:
            is_valid, message = plugin.validate_binary(temp_dir)

            assert is_valid is False
            assert "not a file" in message

    def test_base_plugin_validate_binary_size_limit(self) -> None:
        """BasePlugin.validate_binary() enforces max file size."""

        class TestPlugin(BasePlugin):
            def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
                return {}

        metadata = PluginMetadata("Test", "1.0", "Author", "Desc", [])
        plugin = TestPlugin(metadata, {"max_file_size": 100})

        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name
            f.write(b"A" * 200)

        try:
            is_valid, message = plugin.validate_binary(temp_path)
            assert is_valid is False
            assert "too large" in message
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_base_plugin_get_status(self) -> None:
        """BasePlugin.get_status() returns plugin status."""

        class TestPlugin(BasePlugin):
            def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
                return {}

        metadata = PluginMetadata("Test", "1.0", "Author", "Desc", [])
        plugin = TestPlugin(metadata)

        assert plugin.get_status() == "active"

    def test_base_plugin_calculate_entropy(self) -> None:
        """BasePlugin.calculate_entropy() computes data entropy."""

        class TestPlugin(BasePlugin):
            def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
                return {}

        metadata = PluginMetadata("Test", "1.0", "Author", "Desc", [])
        plugin = TestPlugin(metadata)

        low_entropy = plugin.calculate_entropy(b"\x00" * 100)
        high_entropy = plugin.calculate_entropy(os.urandom(100))

        assert 0.0 <= low_entropy <= 8.0
        assert 0.0 <= high_entropy <= 8.0
        assert high_entropy > low_entropy

    def test_base_plugin_cleanup_default(self) -> None:
        """BasePlugin.cleanup() default implementation completes without error."""

        class TestPlugin(BasePlugin):
            def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
                return {}

        metadata = PluginMetadata("Test", "1.0", "Author", "Desc", [])
        plugin = TestPlugin(metadata)

        plugin.cleanup()

    def test_base_plugin_cleanup_custom(self) -> None:
        """BasePlugin.cleanup() can be overridden by subclasses."""

        class TestPlugin(BasePlugin):
            def __init__(
                self,
                metadata: PluginMetadata,
                default_config: dict[str, Any] | None = None,
            ) -> None:
                super().__init__(metadata, default_config)
                self.cleanup_called = False

            def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
                return {}

            def cleanup(self) -> None:
                self.cleanup_called = True

        metadata = PluginMetadata("Test", "1.0", "Author", "Desc", [])
        plugin = TestPlugin(metadata)

        plugin.cleanup()
        assert plugin.cleanup_called is True

    def test_base_plugin_run_must_be_implemented(self) -> None:
        """BasePlugin.run() must be implemented by subclasses."""

        class IncompletePlugin(BasePlugin):
            pass

        metadata = PluginMetadata("Test", "1.0", "Author", "Desc", [])

        with pytest.raises(TypeError):
            IncompletePlugin(metadata)  # type: ignore[abstract]


class TestCreatePluginInfo:
    """Test create_plugin_info helper function."""

    def test_create_plugin_info_basic(self) -> None:
        """create_plugin_info creates PLUGIN_INFO dictionary."""
        metadata = PluginMetadata(
            name="InfoPlugin",
            version="1.0",
            author="Test",
            description="Test plugin",
            categories=["test"],
        )

        info = create_plugin_info(metadata)

        assert info["name"] == "InfoPlugin"
        assert info["version"] == "1.0"
        assert info["entry_point"] == "register"

    def test_create_plugin_info_custom_entry_point(self) -> None:
        """create_plugin_info uses custom entry point."""
        metadata = PluginMetadata("Test", "1.0", "Author", "Desc", [])

        info = create_plugin_info(metadata, entry_point="initialize")

        assert info["entry_point"] == "initialize"

    def test_create_plugin_info_includes_all_metadata(self) -> None:
        """create_plugin_info includes all metadata fields."""
        metadata = PluginMetadata(
            name="CompletePlugin",
            version="2.0",
            author="Author",
            description="Description",
            categories=["cat1", "cat2"],
            supported_formats=["PE", "ELF"],
            capabilities=["crack", "analyze"],
        )

        info = create_plugin_info(metadata)

        assert info["name"] == "CompletePlugin"
        assert info["version"] == "2.0"
        assert info["categories"] == ["cat1", "cat2"]
        assert info["supported_formats"] == ["PE", "ELF"]
        assert info["capabilities"] == ["crack", "analyze"]


class TestCreateRegisterFunction:
    """Test create_register_function helper."""

    def test_create_register_function_basic(self) -> None:
        """create_register_function creates register function."""

        class TestPlugin(BasePlugin):
            def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
                return {}

        metadata = PluginMetadata("Test", "1.0", "Author", "Desc", [])
        register = create_register_function(TestPlugin, metadata)

        plugin = register()

        assert isinstance(plugin, TestPlugin)
        assert plugin.name == "Test"

    def test_create_register_function_without_metadata(self) -> None:
        """create_register_function works without explicit metadata."""

        class TestPlugin(BasePlugin):
            def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
                return {}

        register = create_register_function(TestPlugin)

        plugin = register()

        assert isinstance(plugin, TestPlugin)

    def test_create_register_function_creates_new_instance(self) -> None:
        """create_register_function creates new instance each call."""

        class TestPlugin(BasePlugin):
            def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
                return {}

        metadata = PluginMetadata("Test", "1.0", "Author", "Desc", [])
        register = create_register_function(TestPlugin, metadata)

        plugin1 = register()
        plugin2 = register()

        assert plugin1 is not plugin2


class TestDefaultConfigs:
    """Test default configuration dictionaries."""

    def test_default_analysis_config(self) -> None:
        """DEFAULT_ANALYSIS_CONFIG contains analysis configuration."""
        assert "max_file_size" in DEFAULT_ANALYSIS_CONFIG
        assert "enable_caching" in DEFAULT_ANALYSIS_CONFIG
        assert "detailed_analysis" in DEFAULT_ANALYSIS_CONFIG
        assert "timeout_seconds" in DEFAULT_ANALYSIS_CONFIG

        assert DEFAULT_ANALYSIS_CONFIG["max_file_size"] == 100 * 1024 * 1024

    def test_default_binary_config(self) -> None:
        """DEFAULT_BINARY_CONFIG contains binary analysis configuration."""
        assert "max_file_size" in DEFAULT_BINARY_CONFIG
        assert "detailed_output" in DEFAULT_BINARY_CONFIG
        assert "include_file_hash" in DEFAULT_BINARY_CONFIG
        assert "analysis_timeout" in DEFAULT_BINARY_CONFIG

        assert DEFAULT_BINARY_CONFIG["max_file_size"] == 50 * 1024 * 1024

    def test_default_network_config(self) -> None:
        """DEFAULT_NETWORK_CONFIG contains network capture configuration."""
        assert "capture_timeout" in DEFAULT_NETWORK_CONFIG
        assert "max_packets" in DEFAULT_NETWORK_CONFIG
        assert "enable_deep_inspection" in DEFAULT_NETWORK_CONFIG
        assert "save_pcap" in DEFAULT_NETWORK_CONFIG

        assert DEFAULT_NETWORK_CONFIG["capture_timeout"] == 60
        assert DEFAULT_NETWORK_CONFIG["max_packets"] == 10000


class TestPluginIntegration:
    """Test plugin components working together."""

    def test_complete_plugin_workflow(self) -> None:
        """Plugin components work together in complete workflow."""

        class LicenseAnalyzerPlugin(BasePlugin):
            def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
                binary_path = kwargs.get("binary_path", "")

                is_valid, error = self.validate_binary(str(binary_path))
                if not is_valid:
                    return {"error": error}

                return {
                    "status": "success",
                    "protections": ["vmprotect", "themida"],
                }

        metadata = PluginMetadata(
            name="LicenseAnalyzer",
            version="1.0.0",
            author="Intellicrack Team",
            description="Analyzes license protection mechanisms",
            categories=["license", "analysis"],
            capabilities=["protection_detection", "license_bypass"],
        )

        config = {"max_file_size": 50 * 1024 * 1024, "timeout": 30}

        plugin = LicenseAnalyzerPlugin(metadata, config)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
            temp_path = f.name
            f.write(b"\x90\x50\x56\x53" * 100)

        try:
            result = plugin.run(binary_path=temp_path)

            assert result["status"] == "success"
            assert "protections" in result

            plugin_metadata = plugin.get_metadata()
            assert plugin_metadata["name"] == "LicenseAnalyzer"
            assert plugin_metadata["capabilities"] == ["protection_detection", "license_bypass"]
        finally:
            Path(temp_path).unlink(missing_ok=True)
