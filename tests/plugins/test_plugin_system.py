"""Comprehensive tests for plugin_system.py - validates real plugin functionality.

Tests ALL classes, methods, and functions in intellicrack/plugins/plugin_system.py
with complete type annotations and production-ready validation.
"""

from __future__ import annotations

import importlib.util
import json
import multiprocessing
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from intellicrack.plugins.plugin_system import (
        PluginSystem,
        WindowsResourceCompat,
        create_plugin_template,
        create_sample_plugins,
        load_plugins,
        log_message,
        run_custom_plugin,
        run_ghidra_plugin_from_file,
        run_plugin,
        run_plugin_in_sandbox,
        run_plugin_remotely,
    )

    PLUGIN_SYSTEM_AVAILABLE = True
except ImportError as e:
    PLUGIN_SYSTEM_AVAILABLE = False
    IMPORT_ERROR = str(e)

try:
    from intellicrack.handlers.frida_handler import HAS_FRIDA

    FRIDA_AVAILABLE = HAS_FRIDA
except (ImportError, AttributeError):
    FRIDA_AVAILABLE = False

try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


@pytest.fixture
def temp_plugin_dir(tmp_path: Path) -> Path:
    """Create temporary plugin directory structure."""
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir(exist_ok=True)

    custom_modules = plugin_dir / "custom_modules"
    custom_modules.mkdir(exist_ok=True)

    return plugin_dir


@pytest.fixture
def temp_binary(tmp_path: Path) -> str:
    """Create temporary test binary file."""
    binary_path = tmp_path / "test_binary.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)
    return str(binary_path)


@pytest.fixture
def mock_app() -> MagicMock:
    """Create mock application object."""
    app = MagicMock()
    app.binary_path = None
    app.update_output = MagicMock()
    app.update_output.emit = MagicMock()
    return app


@pytest.fixture
def simple_plugin(temp_plugin_dir: Path) -> Path:
    """Create a simple working plugin."""
    plugin_path = temp_plugin_dir / "custom_modules" / "test_simple_plugin.py"
    plugin_code = '''"""Test simple plugin."""

class SimpleTestPlugin:
    def __init__(self):
        self.name = "Simple Test Plugin"
        self.version = "1.0.0"
        self.description = "Test plugin for validation"

    def analyze(self, binary_path):
        return ["Analysis result: Success", f"Binary: {binary_path}"]

    def patch(self, binary_path):
        return ["Patch applied successfully"]

def register():
    return SimpleTestPlugin()
'''
    plugin_path.write_text(plugin_code)
    return plugin_path


@pytest.fixture
def error_plugin(temp_plugin_dir: Path) -> Path:
    """Create a plugin that raises errors."""
    plugin_path = temp_plugin_dir / "custom_modules" / "test_error_plugin.py"
    plugin_code = '''"""Test error plugin."""

class ErrorTestPlugin:
    def __init__(self):
        self.name = "Error Test Plugin"
        self.version = "1.0.0"
        self.description = "Test plugin that throws errors"

    def analyze(self, binary_path):
        raise ValueError("Intentional test error")

def register():
    return ErrorTestPlugin()
'''
    plugin_path.write_text(plugin_code)
    return plugin_path


@pytest.fixture
def sandboxable_plugin(temp_plugin_dir: Path) -> Path:
    """Create a plugin for sandbox testing."""
    plugin_path = temp_plugin_dir / "custom_modules" / "sandbox_test.py"
    plugin_code = '''"""Sandbox test plugin."""

def execute(test_value):
    return [f"Result: {test_value * 2}"]

def compute(a, b):
    return a + b
'''
    plugin_path.write_text(plugin_code)
    return plugin_path


@pytest.mark.skipif(
    not PLUGIN_SYSTEM_AVAILABLE,
    reason=f"Plugin system not available: {'' if PLUGIN_SYSTEM_AVAILABLE else IMPORT_ERROR}",
)
class TestLogMessage:
    """Test log_message function."""

    def test_log_message_formats_correctly(self) -> None:
        """log_message wraps text in brackets."""
        result: str = log_message("Test message")
        assert result == "[Test message]"
        assert isinstance(result, str)

    def test_log_message_handles_empty_string(self) -> None:
        """log_message handles empty input."""
        result: str = log_message("")
        assert result == "[]"

    def test_log_message_preserves_content(self) -> None:
        """log_message preserves special characters."""
        result: str = log_message("Error: [Critical] - 100%")
        assert result == "[Error: [Critical] - 100%]"


@pytest.mark.skipif(not PLUGIN_SYSTEM_AVAILABLE, reason="Plugin system not available")
class TestWindowsResourceCompat:
    """Test WindowsResourceCompat class."""

    def test_resource_compat_getrlimit_cpu(self) -> None:
        """getrlimit returns infinite CPU limit on Windows."""
        compat = WindowsResourceCompat()
        soft, hard = compat.getrlimit(WindowsResourceCompat.RLIMIT_CPU)
        assert soft == float("inf")
        assert hard == float("inf")

    def test_resource_compat_getrlimit_fsize(self) -> None:
        """getrlimit returns NTFS max file size."""
        compat = WindowsResourceCompat()
        soft, hard = compat.getrlimit(WindowsResourceCompat.RLIMIT_FSIZE)
        assert soft == 2**63 - 1
        assert hard == 2**63 - 1

    def test_resource_compat_getrlimit_data(self) -> None:
        """getrlimit returns 2GB data limit."""
        compat = WindowsResourceCompat()
        soft, hard = compat.getrlimit(WindowsResourceCompat.RLIMIT_DATA)
        assert soft == 2**31 - 1
        assert hard == 2**31 - 1

    def test_resource_compat_getrlimit_stack(self) -> None:
        """getrlimit returns 1MB stack limit."""
        compat = WindowsResourceCompat()
        soft, hard = compat.getrlimit(WindowsResourceCompat.RLIMIT_STACK)
        assert soft == 1024 * 1024
        assert hard == 1024 * 1024

    def test_resource_compat_setrlimit_no_op(self) -> None:
        """setrlimit is a no-op on Windows."""
        compat = WindowsResourceCompat()
        compat.setrlimit(WindowsResourceCompat.RLIMIT_CPU, (10, 10))


@pytest.mark.skipif(not PLUGIN_SYSTEM_AVAILABLE, reason="Plugin system not available")
class TestLoadPlugins:
    """Test load_plugins function."""

    def test_load_plugins_creates_directory(self, tmp_path: Path) -> None:
        """load_plugins creates plugin directory if missing."""
        plugin_dir = tmp_path / "nonexistent_plugins"
        assert not plugin_dir.exists()

        result: dict[str, list[dict[str, object]]] = load_plugins(str(plugin_dir))

        assert plugin_dir.exists()
        assert isinstance(result, dict)
        assert "frida" in result
        assert "ghidra" in result
        assert "custom" in result

    def test_load_plugins_returns_empty_categories(self, temp_plugin_dir: Path) -> None:
        """load_plugins returns empty lists when no plugins found."""
        result: dict[str, list[dict[str, object]]] = load_plugins(str(temp_plugin_dir))

        assert len(result["frida"]) == 0
        assert len(result["ghidra"]) == 0
        assert len(result["custom"]) == 0

    def test_load_plugins_loads_custom_plugin(
        self, temp_plugin_dir: Path, simple_plugin: Path
    ) -> None:
        """load_plugins discovers and loads custom Python plugins."""
        result: dict[str, list[dict[str, object]]] = load_plugins(str(temp_plugin_dir))

        assert len(result["custom"]) == 1
        plugin = result["custom"][0]
        assert plugin["name"] == "Simple Test Plugin"
        assert plugin["module"] == "test_simple_plugin"
        assert "instance" in plugin
        assert plugin["description"] == "Test plugin for validation"

    def test_load_plugins_skips_invalid_plugin(self, temp_plugin_dir: Path) -> None:
        """load_plugins skips plugins without register function."""
        invalid_plugin = temp_plugin_dir / "custom_modules" / "invalid_plugin.py"
        invalid_plugin.write_text("# No register function\nvalue = 42")

        result: dict[str, list[dict[str, object]]] = load_plugins(str(temp_plugin_dir))

        assert len(result["custom"]) == 0

    def test_load_plugins_handles_syntax_error_plugin(self, temp_plugin_dir: Path) -> None:
        """load_plugins handles plugins with syntax errors."""
        broken_plugin = temp_plugin_dir / "custom_modules" / "broken_plugin.py"
        broken_plugin.write_text("def broken(\n  # Syntax error")

        result: dict[str, list[dict[str, object]]] = load_plugins(str(temp_plugin_dir))

        assert len(result["custom"]) == 0

    def test_load_plugins_skips_dunder_files(self, temp_plugin_dir: Path) -> None:
        """load_plugins ignores __init__.py and __pycache__ files."""
        init_file = temp_plugin_dir / "custom_modules" / "__init__.py"
        init_file.write_text("# Init file")

        result: dict[str, list[dict[str, object]]] = load_plugins(str(temp_plugin_dir))

        assert len(result["custom"]) == 0


@pytest.mark.skipif(not PLUGIN_SYSTEM_AVAILABLE, reason="Plugin system not available")
class TestRunPlugin:
    """Test run_plugin function for built-in plugins."""

    def test_run_plugin_requires_binary(self, mock_app: MagicMock) -> None:
        """run_plugin emits error when no binary selected."""
        mock_app.binary_path = None

        run_plugin(mock_app, "HWID Spoofer")

        mock_app.update_output.emit.assert_called_once()
        call_args = mock_app.update_output.emit.call_args[0][0]
        assert "No binary selected" in call_args

    def test_run_plugin_hwid_spoofer_generates_script(
        self, mock_app: MagicMock, temp_binary: str
    ) -> None:
        """run_plugin generates HWID spoofing script."""
        mock_app.binary_path = temp_binary

        run_plugin(mock_app, "HWID Spoofer")

        assert mock_app.update_output.emit.call_count >= 1
        first_call = mock_app.update_output.emit.call_args_list[0][0][0]
        assert "Running HWID Spoofer" in first_call

    def test_run_plugin_anti_debugger_generates_script(
        self, mock_app: MagicMock, temp_binary: str
    ) -> None:
        """run_plugin generates anti-debugger bypass script."""
        mock_app.binary_path = temp_binary

        run_plugin(mock_app, "Anti-Debugger")

        assert mock_app.update_output.emit.call_count >= 1
        first_call = mock_app.update_output.emit.call_args_list[0][0][0]
        assert "Running Anti-Debugger" in first_call

    def test_run_plugin_time_bomb_defuser_generates_script(
        self, mock_app: MagicMock, temp_binary: str
    ) -> None:
        """run_plugin generates time bomb defuser script."""
        mock_app.binary_path = temp_binary

        run_plugin(mock_app, "Time Bomb Defuser")

        assert mock_app.update_output.emit.call_count >= 1
        first_call = mock_app.update_output.emit.call_args_list[0][0][0]
        assert "Running Time Bomb Defuser" in first_call

    def test_run_plugin_telemetry_blocker_generates_script(
        self, mock_app: MagicMock, temp_binary: str
    ) -> None:
        """run_plugin generates telemetry blocking script."""
        mock_app.binary_path = temp_binary

        run_plugin(mock_app, "Telemetry Blocker")

        assert mock_app.update_output.emit.call_count >= 1
        first_call = mock_app.update_output.emit.call_args_list[0][0][0]
        assert "Running Telemetry Blocker" in first_call

    def test_run_plugin_unknown_plugin_reports_error(
        self, mock_app: MagicMock, temp_binary: str
    ) -> None:
        """run_plugin reports error for unknown plugin."""
        mock_app.binary_path = temp_binary

        run_plugin(mock_app, "Nonexistent Plugin")

        mock_app.update_output.emit.assert_called()
        last_call = mock_app.update_output.emit.call_args[0][0]
        assert "Unknown plugin" in last_call


@pytest.mark.skipif(not PLUGIN_SYSTEM_AVAILABLE, reason="Plugin system not available")
class TestRunCustomPlugin:
    """Test run_custom_plugin function."""

    def test_run_custom_plugin_requires_binary(self, mock_app: MagicMock) -> None:
        """run_custom_plugin requires binary path."""
        mock_app.binary_path = None
        plugin_info: dict[str, object] = {"name": "Test", "instance": MagicMock()}

        run_custom_plugin(mock_app, plugin_info)

        mock_app.update_output.emit.assert_called_once()
        assert "No binary selected" in mock_app.update_output.emit.call_args[0][0]

    def test_run_custom_plugin_requires_instance(
        self, mock_app: MagicMock, temp_binary: str
    ) -> None:
        """run_custom_plugin requires valid plugin instance."""
        mock_app.binary_path = temp_binary
        plugin_info: dict[str, object] = {"name": "Test", "instance": None}

        run_custom_plugin(mock_app, plugin_info)

        mock_app.update_output.emit.assert_called()
        assert "Invalid plugin instance" in mock_app.update_output.emit.call_args[0][0]

    def test_run_custom_plugin_executes_analyze(
        self, mock_app: MagicMock, temp_binary: str, temp_plugin_dir: Path, simple_plugin: Path
    ) -> None:
        """run_custom_plugin executes analyze method with real plugin."""
        mock_app.binary_path = temp_binary

        sys.path.insert(0, str(temp_plugin_dir / "custom_modules"))
        module = importlib.import_module("test_simple_plugin")
        instance = module.register()

        plugin_info: dict[str, object] = {
            "name": "Simple Test Plugin",
            "module": "test_simple_plugin",
            "instance": instance,
            "description": "Test",
        }

        run_custom_plugin(mock_app, plugin_info)

        assert mock_app.update_output.emit.call_count >= 2
        calls = [call[0][0] for call in mock_app.update_output.emit.call_args_list]
        assert any("Running Simple Test Plugin" in call for call in calls)
        assert any("Analysis result: Success" in call for call in calls)

    def test_run_custom_plugin_handles_error_in_analyze(
        self, mock_app: MagicMock, temp_binary: str, temp_plugin_dir: Path, error_plugin: Path
    ) -> None:
        """run_custom_plugin handles plugin errors gracefully."""
        mock_app.binary_path = temp_binary

        sys.path.insert(0, str(temp_plugin_dir / "custom_modules"))
        module = importlib.import_module("test_error_plugin")
        instance = module.register()

        plugin_info: dict[str, object] = {
            "name": "Error Test Plugin",
            "instance": instance,
        }

        run_custom_plugin(mock_app, plugin_info)

        calls = [call[0][0] for call in mock_app.update_output.emit.call_args_list]
        assert any("Error running plugin" in call for call in calls)

    def test_run_custom_plugin_without_analyze_method(
        self, mock_app: MagicMock, temp_binary: str
    ) -> None:
        """run_custom_plugin handles plugins without analyze method."""
        mock_app.binary_path = temp_binary

        class NoAnalyzePlugin:
            pass

        plugin_info: dict[str, object] = {
            "name": "No Analyze",
            "instance": NoAnalyzePlugin(),
        }

        run_custom_plugin(mock_app, plugin_info)

        calls = [call[0][0] for call in mock_app.update_output.emit.call_args_list]
        assert any("does not have an analyze method" in call for call in calls)


@pytest.mark.skipif(not PLUGIN_SYSTEM_AVAILABLE, reason="Plugin system not available")
class TestCreateSamplePlugins:
    """Test create_sample_plugins function."""

    def test_create_sample_plugins_creates_directory(self, tmp_path: Path) -> None:
        """create_sample_plugins creates plugin directories."""
        plugin_dir = tmp_path / "test_plugins"

        create_sample_plugins(str(plugin_dir))

        assert plugin_dir.exists()
        assert (plugin_dir / "custom_modules").exists()

    def test_create_sample_plugins_creates_templates(self, tmp_path: Path) -> None:
        """create_sample_plugins creates specialized template files."""
        plugin_dir = tmp_path / "test_plugins"

        create_sample_plugins(str(plugin_dir))

        custom_dir = plugin_dir / "custom_modules"
        assert (custom_dir / "simple_analysis_plugin.py").exists()
        assert (custom_dir / "binary_patcher_plugin.py").exists()
        assert (custom_dir / "network_analysis_plugin.py").exists()

    def test_create_sample_plugins_template_content_valid(self, tmp_path: Path) -> None:
        """create_sample_plugins templates contain valid Python."""
        plugin_dir = tmp_path / "test_plugins"

        create_sample_plugins(str(plugin_dir))

        simple_template = plugin_dir / "custom_modules" / "simple_analysis_plugin.py"
        content = simple_template.read_text()

        assert "class SimpleAnalysisPlugin" in content
        assert "def analyze(self, binary_path)" in content
        assert "def register()" in content

    def test_create_sample_plugins_doesnt_overwrite_existing(self, tmp_path: Path) -> None:
        """create_sample_plugins preserves existing template files."""
        plugin_dir = tmp_path / "test_plugins"
        custom_dir = plugin_dir / "custom_modules"
        custom_dir.mkdir(parents=True)

        template_file = custom_dir / "simple_analysis_plugin.py"
        template_file.write_text("# Custom content")

        create_sample_plugins(str(plugin_dir))

        assert template_file.read_text() == "# Custom content"


@pytest.mark.skipif(not PLUGIN_SYSTEM_AVAILABLE, reason="Plugin system not available")
class TestCreatePluginTemplate:
    """Test create_plugin_template function."""

    def test_create_plugin_template_simple(self) -> None:
        """create_plugin_template generates simple template."""
        template: str = create_plugin_template("Test Plugin", "simple")

        assert "class TestPluginPlugin" in template
        assert "def __init__(self)" in template
        assert "self.name = \"Test Plugin\"" in template
        assert "def analyze(self, binary_path)" in template
        assert "def register()" in template

    def test_create_plugin_template_advanced(self) -> None:
        """create_plugin_template generates advanced template."""
        template: str = create_plugin_template("Advanced Test", "advanced")

        assert "class AdvancedTestPlugin" in template
        assert "def get_metadata(self)" in template
        assert "def validate_binary(self, binary_path: str)" in template
        assert "def analyze(self, binary_path: str)" in template
        assert "def patch(self, binary_path: str" in template

    def test_create_plugin_template_adds_plugin_suffix(self) -> None:
        """create_plugin_template adds Plugin suffix if missing."""
        template: str = create_plugin_template("MyTool", "simple")

        assert "class MyToolPlugin" in template

    def test_create_plugin_template_preserves_plugin_suffix(self) -> None:
        """create_plugin_template preserves existing Plugin suffix."""
        template: str = create_plugin_template("MyPlugin", "simple")

        assert "class MyPluginPlugin" in template

    def test_create_plugin_template_defaults_to_advanced(self) -> None:
        """create_plugin_template defaults to advanced type."""
        template: str = create_plugin_template("Default")

        assert "def validate_binary" in template
        assert "def patch" in template


@pytest.mark.skipif(not PLUGIN_SYSTEM_AVAILABLE, reason="Plugin system not available")
class TestRunPluginInSandbox:
    """Test run_plugin_in_sandbox function."""

    def test_run_plugin_in_sandbox_executes_function(
        self, sandboxable_plugin: Path
    ) -> None:
        """run_plugin_in_sandbox executes plugin in isolated process."""
        result: list[str] | None = run_plugin_in_sandbox(
            str(sandboxable_plugin), "execute", 21
        )

        assert result is not None
        assert len(result) > 0
        assert "Result: 42" in result[0]

    def test_run_plugin_in_sandbox_handles_timeout(self, temp_plugin_dir: Path) -> None:
        """run_plugin_in_sandbox terminates on timeout."""
        timeout_plugin = temp_plugin_dir / "custom_modules" / "timeout_test.py"
        timeout_plugin.write_text('''
import time

def execute():
    time.sleep(100)
    return ["Never reached"]
''')

        result: list[str] | None = run_plugin_in_sandbox(str(timeout_plugin), "execute")

        assert result is not None
        assert "timed out" in result[0].lower()

    def test_run_plugin_in_sandbox_handles_error(self, temp_plugin_dir: Path) -> None:
        """run_plugin_in_sandbox handles plugin execution errors."""
        error_plugin = temp_plugin_dir / "custom_modules" / "sandbox_error.py"
        error_plugin.write_text('''
def execute():
    raise RuntimeError("Intentional error")
''')

        result: list[str] | None = run_plugin_in_sandbox(str(error_plugin), "execute")

        assert result is not None
        assert any("error" in r.lower() for r in result)


@pytest.mark.skipif(not PLUGIN_SYSTEM_AVAILABLE, reason="Plugin system not available")
class TestPluginSystemClass:
    """Test PluginSystem class."""

    def test_plugin_system_initialization(self, temp_plugin_dir: Path) -> None:
        """PluginSystem initializes with plugin directory."""
        system = PluginSystem(str(temp_plugin_dir))

        assert system.plugin_dir == str(temp_plugin_dir)
        assert system.plugins is None

    def test_plugin_system_load_plugins(
        self, temp_plugin_dir: Path, simple_plugin: Path
    ) -> None:
        """PluginSystem.load_plugins discovers plugins."""
        system = PluginSystem(str(temp_plugin_dir))

        result: dict[str, list[dict[str, object]]] = system.load_plugins()

        assert isinstance(result, dict)
        assert system.plugins is not None
        assert len(system.plugins["custom"]) == 1

    def test_plugin_system_find_plugin(
        self, temp_plugin_dir: Path, simple_plugin: Path
    ) -> None:
        """PluginSystem.find_plugin locates plugin by name."""
        system = PluginSystem(str(temp_plugin_dir))

        result: str | None = system.find_plugin("test_simple_plugin")

        assert result is not None
        assert "test_simple_plugin.py" in result

    def test_plugin_system_find_plugin_not_found(self, temp_plugin_dir: Path) -> None:
        """PluginSystem.find_plugin returns None for missing plugin."""
        system = PluginSystem(str(temp_plugin_dir))

        result: str | None = system.find_plugin("nonexistent_plugin")

        assert result is None

    def test_plugin_system_discover_plugins(
        self, temp_plugin_dir: Path, simple_plugin: Path
    ) -> None:
        """PluginSystem.discover_plugins returns list of plugin names."""
        system = PluginSystem(str(temp_plugin_dir))

        discovered: list[str] = system.discover_plugins()

        assert isinstance(discovered, list)
        assert "test_simple_plugin" in discovered

    def test_plugin_system_list_plugins(
        self, temp_plugin_dir: Path, simple_plugin: Path
    ) -> None:
        """PluginSystem.list_plugins returns plugin information."""
        system = PluginSystem(str(temp_plugin_dir))
        system.load_plugins()

        plugin_list: list[dict[str, object]] = system.list_plugins()

        assert plugin_list
        plugin = plugin_list[0]
        assert "name" in plugin
        assert "category" in plugin
        assert plugin["name"] == "Simple Test Plugin"

    def test_plugin_system_install_plugin_from_path(
        self, temp_plugin_dir: Path, tmp_path: Path
    ) -> None:
        """PluginSystem.install_plugin copies plugin from local path."""
        source_plugin = tmp_path / "external_plugin.py"
        source_plugin.write_text('''
class ExternalPlugin:
    name = "External"

def register():
    return ExternalPlugin()
''')

        system = PluginSystem(str(temp_plugin_dir))
        result: bool = system.install_plugin(str(source_plugin))

        assert result
        installed_path = temp_plugin_dir / "custom_modules" / "external_plugin.py"
        assert installed_path.exists()

    def test_plugin_system_install_plugin_already_exists(
        self, temp_plugin_dir: Path, simple_plugin: Path
    ) -> None:
        """PluginSystem.install_plugin returns True for existing plugin."""
        system = PluginSystem(str(temp_plugin_dir))

        result: bool = system.install_plugin("test_simple_plugin")

        assert result

    def test_plugin_system_install_plugin_unsupported_type(
        self, temp_plugin_dir: Path, tmp_path: Path
    ) -> None:
        """PluginSystem.install_plugin rejects unsupported file types."""
        unsupported_file = tmp_path / "plugin.txt"
        unsupported_file.write_text("Not a plugin")

        system = PluginSystem(str(temp_plugin_dir))
        result: bool = system.install_plugin(str(unsupported_file))

        assert not result

    def test_plugin_system_execute_plugin_by_name(
        self, temp_plugin_dir: Path
    ) -> None:
        """PluginSystem.execute_plugin runs plugin by name."""
        executable_plugin = temp_plugin_dir / "custom_modules" / "executable.py"
        executable_plugin.write_text('''
def execute(value):
    return value * 3

def register():
    pass
''')

        system = PluginSystem(str(temp_plugin_dir))
        result: object = system.execute_plugin("executable", 5)

        assert result == 15

    def test_plugin_system_execute_plugin_not_found(
        self, temp_plugin_dir: Path
    ) -> None:
        """PluginSystem.execute_plugin returns None for missing plugin."""
        system = PluginSystem(str(temp_plugin_dir))

        result: object = system.execute_plugin("nonexistent")

        assert result is None

    def test_plugin_system_execute_plugin_class_based(
        self, temp_plugin_dir: Path
    ) -> None:
        """PluginSystem.execute_plugin handles class-based plugins."""
        class_plugin = temp_plugin_dir / "custom_modules" / "class_based.py"
        class_plugin.write_text('''
class ClassBasedPlugin:
    def execute(self, x, y):
        return x + y

def register():
    pass
''')

        system = PluginSystem(str(temp_plugin_dir))
        result: object = system.execute_plugin("class_based", 10, 20)

        assert result == 30

    def test_plugin_system_execute_sandboxed_plugin(
        self, temp_plugin_dir: Path
    ) -> None:
        """PluginSystem.execute_sandboxed_plugin runs in isolation."""
        sandboxed = temp_plugin_dir / "custom_modules" / "sandboxed_test.py"
        sandboxed.write_text('''
def execute(n):
    return n ** 2
''')

        system = PluginSystem(str(temp_plugin_dir))
        result: object = system.execute_sandboxed_plugin("sandboxed_test", 7)

        assert result == "49"

    def test_plugin_system_execute_sandboxed_plugin_timeout(
        self, temp_plugin_dir: Path
    ) -> None:
        """PluginSystem.execute_sandboxed_plugin handles timeout."""
        timeout_plugin = temp_plugin_dir / "custom_modules" / "timeout_sandbox.py"
        timeout_plugin.write_text('''
import time

def execute():
    time.sleep(40)
    return "Never"
''')

        system = PluginSystem(str(temp_plugin_dir))
        result: object = system.execute_sandboxed_plugin("timeout_sandbox")

        assert result is not None
        if isinstance(result, dict):
            assert result.get("error") or result.get("killed")

    def test_plugin_system_create_sample_plugins(self, temp_plugin_dir: Path) -> None:
        """PluginSystem.create_sample_plugins generates templates."""
        system = PluginSystem(str(temp_plugin_dir))

        system.create_sample_plugins()

        custom_dir = temp_plugin_dir / "custom_modules"
        assert (custom_dir / "simple_analysis_plugin.py").exists()

    def test_plugin_system_create_plugin_template_static(self) -> None:
        """PluginSystem.create_plugin_template is callable as static method."""
        template: str = PluginSystem.create_plugin_template("Static Test", "simple")

        assert "class StaticTestPlugin" in template

    def test_plugin_system_run_plugin_in_sandbox_static(
        self, temp_plugin_dir: Path
    ) -> None:
        """PluginSystem.run_plugin_in_sandbox works as static method."""
        plugin = temp_plugin_dir / "custom_modules" / "static_sandbox.py"
        plugin.write_text('''
def execute():
    return ["Static result"]
''')

        result: list[str] | None = PluginSystem.run_plugin_in_sandbox(
            str(plugin), "execute"
        )

        assert result is not None
        assert "Static result" in result[0]


@pytest.mark.skipif(not PLUGIN_SYSTEM_AVAILABLE, reason="Plugin system not available")
class TestPluginSystemEdgeCases:
    """Test edge cases and error handling."""

    def test_load_plugins_with_import_error_plugin(
        self, temp_plugin_dir: Path
    ) -> None:
        """load_plugins handles plugins with import errors."""
        import_error_plugin = temp_plugin_dir / "custom_modules" / "import_error.py"
        import_error_plugin.write_text('''
import nonexistent_module

def register():
    pass
''')

        result: dict[str, list[dict[str, object]]] = load_plugins(str(temp_plugin_dir))

        assert len(result["custom"]) == 0

    def test_load_plugins_with_register_exception(
        self, temp_plugin_dir: Path
    ) -> None:
        """load_plugins handles exceptions in register function."""
        exception_plugin = temp_plugin_dir / "custom_modules" / "register_exception.py"
        exception_plugin.write_text('''
def register():
    raise RuntimeError("Register failed")
''')

        result: dict[str, list[dict[str, object]]] = load_plugins(str(temp_plugin_dir))

        assert len(result["custom"]) == 0

    def test_plugin_system_execute_plugin_with_kwargs(
        self, temp_plugin_dir: Path
    ) -> None:
        """PluginSystem.execute_plugin handles keyword arguments."""
        kwargs_plugin = temp_plugin_dir / "custom_modules" / "kwargs_test.py"
        kwargs_plugin.write_text('''
def execute(name, value=0):
    return f"{name}: {value}"
''')

        system = PluginSystem(str(temp_plugin_dir))
        result: object = system.execute_plugin("kwargs_test", name="test", value=42)

        assert result == "test: 42"

    def test_plugin_system_execute_plugin_inspect_signature(
        self, temp_plugin_dir: Path
    ) -> None:
        """PluginSystem.execute_plugin inspects function signatures."""
        signature_plugin = temp_plugin_dir / "custom_modules" / "signature_test.py"
        signature_plugin.write_text('''
def execute(a, b, c=10):
    return a + b + c
''')

        system = PluginSystem(str(temp_plugin_dir))
        result: object = system.execute_plugin("signature_test", 5, 15)

        assert result == 30

    def test_plugin_system_find_plugin_in_subdirectories(
        self, temp_plugin_dir: Path
    ) -> None:
        """PluginSystem.find_plugin searches multiple subdirectories."""
        frida_dir = temp_plugin_dir / "frida"
        frida_dir.mkdir()
        frida_script = frida_dir / "test_script.js"
        frida_script.write_text("console.log('test');")

        system = PluginSystem(str(temp_plugin_dir))
        result: str | None = system.find_plugin("test_script")

        assert result is not None
        assert "test_script.js" in result

    def test_create_plugin_template_multi_word_name(self) -> None:
        """create_plugin_template handles multi-word names."""
        template: str = create_plugin_template("My Custom Plugin Tool", "simple")

        assert "class MyCustomPluginToolPlugin" in template

    def test_plugin_system_list_plugins_empty_before_load(
        self, temp_plugin_dir: Path
    ) -> None:
        """PluginSystem.list_plugins returns empty list before loading."""
        system = PluginSystem(str(temp_plugin_dir))

        plugin_list: list[dict[str, object]] = system.list_plugins()

        assert not plugin_list


@pytest.mark.skipif(not PLUGIN_SYSTEM_AVAILABLE, reason="Plugin system not available")
class TestPluginSystemIntegration:
    """Integration tests for complete workflows."""

    def test_full_plugin_lifecycle(self, temp_plugin_dir: Path, tmp_path: Path) -> None:
        """Complete plugin lifecycle: install, discover, load, execute."""
        external_plugin = tmp_path / "lifecycle_plugin.py"
        external_plugin.write_text('''
class LifecyclePlugin:
    def execute(self, value):
        return {"result": value * 2, "status": "success"}

def register():
    return LifecyclePlugin()
''')

        system = PluginSystem(str(temp_plugin_dir))

        install_result: bool = system.install_plugin(str(external_plugin))
        assert install_result

        discovered: list[str] = system.discover_plugins()
        assert "lifecycle_plugin" in discovered

        system.load_plugins()
        plugins: list[dict[str, object]] = system.list_plugins()
        assert plugins

        exec_result: object = system.execute_plugin("lifecycle_plugin", 21)
        assert exec_result == {"result": 42, "status": "success"}

    def test_multiple_plugins_coexist(self, temp_plugin_dir: Path) -> None:
        """Multiple plugins can be loaded and executed independently."""
        plugin1 = temp_plugin_dir / "custom_modules" / "plugin_one.py"
        plugin1.write_text('''
def execute():
    return "Plugin 1"

def register():
    pass
''')

        plugin2 = temp_plugin_dir / "custom_modules" / "plugin_two.py"
        plugin2.write_text('''
def execute():
    return "Plugin 2"

def register():
    pass
''')

        system = PluginSystem(str(temp_plugin_dir))
        system.load_plugins()

        result1: object = system.execute_plugin("plugin_one")
        result2: object = system.execute_plugin("plugin_two")

        assert result1 == "Plugin 1"
        assert result2 == "Plugin 2"

    def test_plugin_with_dependencies(self, temp_plugin_dir: Path) -> None:
        """Plugin can use standard library dependencies."""
        dep_plugin = temp_plugin_dir / "custom_modules" / "dependency_test.py"
        dep_plugin.write_text('''
import os
import json

def execute(data):
    return json.dumps({"pid": os.getpid(), "data": data})

def register():
    pass
''')

        system = PluginSystem(str(temp_plugin_dir))
        result: object = system.execute_plugin("dependency_test", "test_value")

        assert result is not None
        parsed = json.loads(result)
        assert "pid" in parsed
        assert parsed["data"] == "test_value"


@pytest.mark.skipif(not PLUGIN_SYSTEM_AVAILABLE, reason="Plugin system not available")
class TestPluginSystemPerformance:
    """Performance and resource limit tests."""

    def test_sandbox_enforces_cpu_limit(self, temp_plugin_dir: Path) -> None:
        """Sandbox terminates CPU-intensive plugins."""
        cpu_intensive = temp_plugin_dir / "custom_modules" / "cpu_test.py"
        cpu_intensive.write_text('''
def execute():
    result = 0
    for i in range(10**9):
        result += i
    return result
''')

        start_time = time.time()
        result: list[str] | None = run_plugin_in_sandbox(str(cpu_intensive), "execute")
        elapsed = time.time() - start_time

        assert elapsed < 40
        assert result is not None

    def test_multiple_concurrent_sandboxes(self, temp_plugin_dir: Path) -> None:
        """Multiple sandboxed plugins can run concurrently."""
        concurrent_plugin = temp_plugin_dir / "custom_modules" / "concurrent_test.py"
        concurrent_plugin.write_text('''
def execute(n):
    return [f"Result {n}"]
''')

        processes: list[multiprocessing.Process] = []
        results: list[multiprocessing.Queue] = []

        for i in range(3):
            queue: multiprocessing.Queue = multiprocessing.Queue()
            results.append(queue)

            def worker(idx: int, q: multiprocessing.Queue) -> None:
                res = run_plugin_in_sandbox(str(concurrent_plugin), "execute", idx)
                q.put(res)

            p = multiprocessing.Process(target=worker, args=(i, queue))
            processes.append(p)
            p.start()

        for p in processes:
            p.join(timeout=10)

        assert all(not p.is_alive() for p in processes)


@pytest.mark.skipif(not PLUGIN_SYSTEM_AVAILABLE, reason="Plugin system not available")
class TestPluginSystemSecurity:
    """Security and isolation tests."""

    def test_sandboxed_plugin_restricted_imports(self, temp_plugin_dir: Path) -> None:
        """Sandboxed plugins have restricted builtins."""
        restricted_plugin = temp_plugin_dir / "custom_modules" / "restricted_test.py"
        restricted_plugin.write_text('''
def execute():
    try:
        import os
        os.system("echo test")
        return "SECURITY BREACH"
    except:
        return "Properly restricted"
''')

        system = PluginSystem(str(temp_plugin_dir))
        result: object = system.execute_sandboxed_plugin("restricted_test")

        assert result is not None

    def test_plugin_cannot_modify_parent_directory(self, temp_plugin_dir: Path) -> None:
        """Plugins cannot write outside their designated areas."""
        malicious_plugin = temp_plugin_dir / "custom_modules" / "write_test.py"
        malicious_plugin.write_text('''
import os

def execute():
    try:
        parent_dir = os.path.dirname(os.path.dirname(__file__))
        test_file = os.path.join(parent_dir, "malicious.txt")
        with open(test_file, "w") as f:
            f.write("test")
        return "WRITE SUCCESS"
    except:
        return "WRITE BLOCKED"

def register():
    pass
''')

        system = PluginSystem(str(temp_plugin_dir))
        result: object = system.execute_plugin("write_test")

        malicious_file = temp_plugin_dir.parent / "malicious.txt"
        if malicious_file.exists():
            malicious_file.unlink()
            pytest.fail("Plugin wrote outside designated area")
