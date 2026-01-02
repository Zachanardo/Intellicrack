"""Production tests for intellicrack/plugins/plugin_system.py.

Validates plugin loading, registration, execution, and management for
Intellicrack's extensible binary analysis framework.

NO MOCKS - All tests use real plugin loading and execution.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import importlib.util
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.plugins.plugin_base import BasePlugin, PluginMetadata
from intellicrack.plugins.plugin_system import load_plugins


class TestLoadPlugins:
    """Test plugin loading and discovery."""

    def test_load_plugins_creates_plugin_directory(self, temp_workspace: Path) -> None:
        """load_plugins creates plugin directory if it doesn't exist."""
        plugin_dir = temp_workspace / "plugins"

        assert not plugin_dir.exists()

        plugins = load_plugins(str(plugin_dir))

        assert plugin_dir.exists()
        assert (plugin_dir / "custom_modules").exists()

    def test_load_plugins_returns_categorized_dict(self, temp_workspace: Path) -> None:
        """load_plugins returns dictionary with plugin categories."""
        plugin_dir = temp_workspace / "plugins"
        plugin_dir.mkdir()

        plugins = load_plugins(str(plugin_dir))

        assert isinstance(plugins, dict)
        assert "frida" in plugins
        assert "ghidra" in plugins
        assert "custom" in plugins

    def test_load_plugins_empty_directory_returns_empty(self, temp_workspace: Path) -> None:
        """load_plugins returns empty lists for empty plugin directory."""
        plugin_dir = temp_workspace / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "custom_modules").mkdir()

        plugins = load_plugins(str(plugin_dir))

        assert len(plugins["frida"]) == 0
        assert len(plugins["ghidra"]) == 0
        assert len(plugins["custom"]) == 0

    def test_load_plugins_loads_valid_custom_plugin(self, temp_workspace: Path) -> None:
        """load_plugins loads custom Python plugins with register function."""
        plugin_dir = temp_workspace / "plugins"
        custom_dir = plugin_dir / "custom_modules"
        custom_dir.mkdir(parents=True)

        plugin_code = '''"""Test plugin."""

from intellicrack.plugins.plugin_base import BasePlugin, PluginMetadata
from typing import Any

class TestAnalysisPlugin(BasePlugin):
    """Test plugin for binary analysis."""

    def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
        """Execute plugin analysis."""
        return {"status": "success", "results": "test"}

def register() -> TestAnalysisPlugin:
    """Register this plugin."""
    metadata = PluginMetadata(
        name="Test Analysis Plugin",
        version="1.0.0",
        author="Test Author",
        description="Test plugin for analysis",
        categories=["analysis"]
    )
    return TestAnalysisPlugin(metadata)
'''

        plugin_file = custom_dir / "test_plugin.py"
        plugin_file.write_text(plugin_code)

        if str(custom_dir) not in sys.path:
            sys.path.insert(0, str(custom_dir))

        try:
            plugins = load_plugins(str(plugin_dir))

            assert len(plugins["custom"]) == 1

            plugin_info = plugins["custom"][0]
            assert plugin_info["name"] == "Test Analysis Plugin"
            assert plugin_info["module"] == "test_plugin"
            assert plugin_info["description"] == "Test plugin for analysis"
            assert "instance" in plugin_info
        finally:
            if str(custom_dir) in sys.path:
                sys.path.remove(str(custom_dir))

    def test_load_plugins_skips_invalid_plugins(self, temp_workspace: Path) -> None:
        """load_plugins skips plugins without register function."""
        plugin_dir = temp_workspace / "plugins"
        custom_dir = plugin_dir / "custom_modules"
        custom_dir.mkdir(parents=True)

        invalid_plugin = '''"""Invalid plugin without register."""

def analyze():
    return "no register function"
'''

        plugin_file = custom_dir / "invalid_plugin.py"
        plugin_file.write_text(invalid_plugin)

        if str(custom_dir) not in sys.path:
            sys.path.insert(0, str(custom_dir))

        try:
            plugins = load_plugins(str(plugin_dir))

            assert len(plugins["custom"]) == 0
        finally:
            if str(custom_dir) in sys.path:
                sys.path.remove(str(custom_dir))

    def test_load_plugins_handles_plugin_import_errors(self, temp_workspace: Path) -> None:
        """load_plugins handles plugins with import errors gracefully."""
        plugin_dir = temp_workspace / "plugins"
        custom_dir = plugin_dir / "custom_modules"
        custom_dir.mkdir(parents=True)

        broken_plugin = '''"""Broken plugin with import error."""

import nonexistent_module

def register():
    return None
'''

        plugin_file = custom_dir / "broken_plugin.py"
        plugin_file.write_text(broken_plugin)

        if str(custom_dir) not in sys.path:
            sys.path.insert(0, str(custom_dir))

        try:
            plugins = load_plugins(str(plugin_dir))

            assert isinstance(plugins, dict)
        finally:
            if str(custom_dir) in sys.path:
                sys.path.remove(str(custom_dir))

    def test_load_plugins_loads_multiple_custom_plugins(self, temp_workspace: Path) -> None:
        """load_plugins loads multiple custom plugins from directory."""
        plugin_dir = temp_workspace / "plugins"
        custom_dir = plugin_dir / "custom_modules"
        custom_dir.mkdir(parents=True)

        for i in range(3):
            plugin_code = f'''"""Plugin {i}."""

from intellicrack.plugins.plugin_base import BasePlugin, PluginMetadata
from typing import Any

class Plugin{i}(BasePlugin):
    """Plugin {i}."""

    def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
        """Execute plugin."""
        return {{"plugin_num": {i}}}

def register() -> Plugin{i}:
    """Register plugin."""
    metadata = PluginMetadata(
        name="Plugin {i}",
        version="1.0",
        author="Author",
        description="Description {i}",
        categories=["test"]
    )
    return Plugin{i}(metadata)
'''

            plugin_file = custom_dir / f"plugin_{i}.py"
            plugin_file.write_text(plugin_code)

        if str(custom_dir) not in sys.path:
            sys.path.insert(0, str(custom_dir))

        try:
            plugins = load_plugins(str(plugin_dir))

            assert len(plugins["custom"]) == 3

            plugin_names = [p["name"] for p in plugins["custom"]]
            assert "Plugin 0" in plugin_names
            assert "Plugin 1" in plugin_names
            assert "Plugin 2" in plugin_names
        finally:
            if str(custom_dir) in sys.path:
                sys.path.remove(str(custom_dir))


class TestPluginSystemIntegration:
    """Integration tests for plugin system operations."""

    def test_plugin_execution_workflow(self, temp_workspace: Path) -> None:
        """Complete plugin workflow from loading to execution."""
        plugin_dir = temp_workspace / "plugins"
        custom_dir = plugin_dir / "custom_modules"
        custom_dir.mkdir(parents=True)

        plugin_code = '''"""Functional analysis plugin."""

from intellicrack.plugins.plugin_base import BasePlugin, PluginMetadata
from typing import Any

class FunctionalPlugin(BasePlugin):
    """Plugin that performs real analysis."""

    def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
        """Execute analysis."""
        binary_path = kwargs.get("binary_path", "")
        return {
            "status": "analyzed",
            "binary": binary_path,
            "findings": ["protection_detected", "license_check_found"]
        }

def register() -> FunctionalPlugin:
    """Register plugin."""
    metadata = PluginMetadata(
        name="Functional Plugin",
        version="1.0",
        author="Test",
        description="Functional test plugin",
        categories=["analysis"]
    )
    return FunctionalPlugin(metadata)
'''

        plugin_file = custom_dir / "functional_plugin.py"
        plugin_file.write_text(plugin_code)

        if str(custom_dir) not in sys.path:
            sys.path.insert(0, str(custom_dir))

        try:
            plugins = load_plugins(str(plugin_dir))

            assert len(plugins["custom"]) == 1

            plugin_instance = plugins["custom"][0]["instance"]

            result = plugin_instance.run(binary_path="test.exe")

            assert result["status"] == "analyzed"
            assert result["binary"] == "test.exe"
            assert "findings" in result
        finally:
            if str(custom_dir) in sys.path:
                sys.path.remove(str(custom_dir))

    def test_plugin_metadata_accessible_after_loading(self, temp_workspace: Path) -> None:
        """Plugin metadata is accessible after loading."""
        plugin_dir = temp_workspace / "plugins"
        custom_dir = plugin_dir / "custom_modules"
        custom_dir.mkdir(parents=True)

        plugin_code = '''"""Metadata test plugin."""

from intellicrack.plugins.plugin_base import BasePlugin, PluginMetadata
from typing import Any

class MetadataPlugin(BasePlugin):
    """Plugin with detailed metadata."""

    def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
        """Execute."""
        return {}

def register() -> MetadataPlugin:
    """Register."""
    metadata = PluginMetadata(
        name="Metadata Test",
        version="2.0.0",
        author="Metadata Author",
        description="Plugin for metadata testing",
        categories=["test", "metadata"],
        supported_formats=["PE", "ELF"],
        capabilities=["analysis", "patching"]
    )
    return MetadataPlugin(metadata)
'''

        plugin_file = custom_dir / "metadata_plugin.py"
        plugin_file.write_text(plugin_code)

        if str(custom_dir) not in sys.path:
            sys.path.insert(0, str(custom_dir))

        try:
            plugins = load_plugins(str(plugin_dir))

            plugin_instance = plugins["custom"][0]["instance"]
            metadata = plugin_instance.get_metadata()

            assert metadata["name"] == "Metadata Test"
            assert metadata["version"] == "2.0.0"
            assert metadata["author"] == "Metadata Author"
            assert "test" in metadata["categories"]
            assert "metadata" in metadata["categories"]
            assert "PE" in metadata["supported_formats"]
            assert "ELF" in metadata["supported_formats"]
            assert "analysis" in metadata["capabilities"]
            assert "patching" in metadata["capabilities"]
        finally:
            if str(custom_dir) in sys.path:
                sys.path.remove(str(custom_dir))

    def test_plugin_config_management(self, temp_workspace: Path) -> None:
        """Plugin configuration can be set and retrieved."""
        plugin_dir = temp_workspace / "plugins"
        custom_dir = plugin_dir / "custom_modules"
        custom_dir.mkdir(parents=True)

        plugin_code = '''"""Config test plugin."""

from intellicrack.plugins.plugin_base import BasePlugin, PluginMetadata
from typing import Any

class ConfigPlugin(BasePlugin):
    """Plugin with configuration."""

    def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
        """Execute with config."""
        timeout = self.config_manager.get("timeout", 30)
        verbose = self.config_manager.get("verbose", False)
        return {"timeout": timeout, "verbose": verbose}

def register() -> ConfigPlugin:
    """Register."""
    metadata = PluginMetadata(
        name="Config Test",
        version="1.0",
        author="Test",
        description="Config testing",
        categories=["test"]
    )
    config = {"timeout": 60, "verbose": True}
    return ConfigPlugin(metadata, config)
'''

        plugin_file = custom_dir / "config_plugin.py"
        plugin_file.write_text(plugin_code)

        if str(custom_dir) not in sys.path:
            sys.path.insert(0, str(custom_dir))

        try:
            plugins = load_plugins(str(plugin_dir))

            plugin_instance = plugins["custom"][0]["instance"]

            result = plugin_instance.run()

            assert result["timeout"] == 60
            assert result["verbose"] is True

            plugin_instance.config_manager.set("timeout", 90)

            result2 = plugin_instance.run()

            assert result2["timeout"] == 90
        finally:
            if str(custom_dir) in sys.path:
                sys.path.remove(str(custom_dir))

    def test_plugin_binary_validation(self, temp_workspace: Path) -> None:
        """Plugin validates binary paths correctly."""
        plugin_dir = temp_workspace / "plugins"
        custom_dir = plugin_dir / "custom_modules"
        custom_dir.mkdir(parents=True)

        plugin_code = '''"""Validation test plugin."""

from intellicrack.plugins.plugin_base import BasePlugin, PluginMetadata
from typing import Any

class ValidationPlugin(BasePlugin):
    """Plugin with binary validation."""

    def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
        """Execute with validation."""
        binary_path = kwargs.get("binary_path", "")
        valid, message = self.validate_binary(binary_path)
        return {"valid": valid, "message": message}

def register() -> ValidationPlugin:
    """Register."""
    metadata = PluginMetadata(
        name="Validation Test",
        version="1.0",
        author="Test",
        description="Validation testing",
        categories=["test"]
    )
    return ValidationPlugin(metadata)
'''

        plugin_file = custom_dir / "validation_plugin.py"
        plugin_file.write_text(plugin_code)

        if str(custom_dir) not in sys.path:
            sys.path.insert(0, str(custom_dir))

        try:
            plugins = load_plugins(str(plugin_dir))

            plugin_instance = plugins["custom"][0]["instance"]

            result_empty = plugin_instance.run(binary_path="")
            assert result_empty["valid"] is False

            result_nonexistent = plugin_instance.run(binary_path="/nonexistent/file.exe")
            assert result_nonexistent["valid"] is False

            test_binary = temp_workspace / "test.exe"
            test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

            result_valid = plugin_instance.run(binary_path=str(test_binary))
            assert result_valid["valid"] is True
        finally:
            if str(custom_dir) in sys.path:
                sys.path.remove(str(custom_dir))


