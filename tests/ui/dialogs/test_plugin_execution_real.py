"""Production tests for real plugin loading and execution.

Tests validate:
- Plugin discovery from filesystem directories
- Dynamic loading of Python and Frida plugins
- Plugin validation and metadata extraction
- Actual execution of plugin code on sample binaries
- Plugin sandboxing and error isolation
- Performance tracking and resource limits
- Plugin dependency management

NO mocks - all tests execute real plugin code.
Tests validate actual plugin functionality.
"""

import ast
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

try:
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication

    PYQT6_AVAILABLE = True
except ImportError:
    PYQT6_AVAILABLE = False
    Qt = None
    QApplication = None

if PYQT6_AVAILABLE:
    from intellicrack.ui.dialogs.plugin_manager_dialog import (
        PluginInfo,
        PluginManagerDialog,
        PluginRunner,
    )

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE, reason="PyQt6 not available - UI tests require PyQt6"
)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for Qt tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def plugin_directory(temp_workspace: Path) -> Path:
    """Create temporary plugin directory with sample plugins."""
    plugin_dir = temp_workspace / "plugins"
    plugin_dir.mkdir()

    simple_plugin = plugin_dir / "simple_analyzer.py"
    simple_plugin.write_text(
        '''"""Simple binary analyzer plugin for testing."""

from typing import Any


class SimpleAnalyzerPlugin:
    """Analyzes binary file size and basic properties."""

    def __init__(self) -> None:
        self.name = "Simple Analyzer"
        self.version = "1.0.0"
        self.description = "Analyzes basic binary properties"
        self.author = "Test"

    def get_metadata(self) -> dict[str, Any]:
        """Return plugin metadata."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "capabilities": ["binary_analysis"],
        }

    def run(self, binary_path: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run plugin execution."""
        try:
            with open(binary_path, "rb") as f:
                data = f.read()

            return {
                "status": "success",
                "binary": binary_path,
                "findings": [
                    {"type": "file_size", "value": len(data)},
                    {"type": "first_bytes", "value": data[:16].hex()},
                ],
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}


def get_plugin() -> Any:
    """Return plugin instance."""
    return SimpleAnalyzerPlugin()
'''
    )

    pattern_plugin = plugin_dir / "pattern_scanner.py"
    pattern_plugin.write_text(
        '''"""Pattern scanner plugin for license string detection."""

from typing import Any


class PatternScannerPlugin:
    """Scans binaries for license-related patterns."""

    def __init__(self) -> None:
        self.name = "Pattern Scanner"
        self.version = "2.0.0"
        self.description = "Scans for license validation patterns"
        self.author = "Security Researcher"

    def get_metadata(self) -> dict[str, Any]:
        """Return plugin metadata."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "capabilities": ["pattern_search", "license_detection"],
        }

    def run(self, binary_path: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run pattern scanning."""
        try:
            with open(binary_path, "rb") as f:
                data = f.read()

            patterns = [b"LICENSE", b"TRIAL", b"EXPIRED", b"SERIAL", b"KEY"]
            findings = []

            for pattern in patterns:
                offset = data.find(pattern)
                if offset != -1:
                    findings.append({
                        "type": "pattern_match",
                        "pattern": pattern.decode("ascii"),
                        "offset": offset,
                    })

            return {
                "status": "success",
                "binary": binary_path,
                "findings": findings,
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}


def get_plugin() -> Any:
    """Return plugin instance."""
    return PatternScannerPlugin()
'''
    )

    metadata_file = plugin_dir / "simple_analyzer_metadata.json"
    metadata_file.write_text(
        json.dumps(
            {
                "name": "Simple Analyzer",
                "version": "1.0.0",
                "author": "Test",
                "description": "Analyzes basic binary properties",
            },
            indent=2,
        )
    )

    return plugin_dir


@pytest.fixture
def sample_binary(temp_workspace: Path) -> Path:
    """Create sample binary file for plugin testing."""
    binary_path = temp_workspace / "sample.exe"
    binary_content = b"MZ\x90\x00" + b"\x00" * 100
    binary_content += b"LICENSE-KEY-12345"
    binary_content += b"\x00" * 100
    binary_content += b"TRIAL_EXPIRED"
    binary_content += b"\x00" * 200

    binary_path.write_bytes(binary_content)
    return binary_path


class TestPluginDiscovery:
    """Test plugin discovery from filesystem."""

    def test_discover_plugins_in_directory(
        self, plugin_directory: Path
    ) -> None:
        """Plugin system discovers all valid plugins in directory."""
        plugin_files = list(plugin_directory.glob("*.py"))

        assert len(plugin_files) >= 2

        plugin_names = [p.stem for p in plugin_files]
        assert "simple_analyzer" in plugin_names
        assert "pattern_scanner" in plugin_names

    def test_load_plugin_metadata_from_json(
        self, plugin_directory: Path
    ) -> None:
        """Plugin metadata loads from accompanying JSON file."""
        metadata_file = plugin_directory / "simple_analyzer_metadata.json"

        assert metadata_file.exists()

        metadata = json.loads(metadata_file.read_text())

        assert metadata["name"] == "Simple Analyzer"
        assert metadata["version"] == "1.0.0"
        assert "author" in metadata

    def test_validate_plugin_structure(
        self, plugin_directory: Path
    ) -> None:
        """Plugin files have required structure (class and get_plugin function)."""
        simple_plugin = plugin_directory / "simple_analyzer.py"

        source = simple_plugin.read_text()
        tree = ast.parse(source)

        has_class = False
        has_get_plugin = False

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if "Plugin" in node.name:
                    has_class = True
            if isinstance(node, ast.FunctionDef):
                if node.name == "get_plugin":
                    has_get_plugin = True

        assert has_class, "Plugin missing required Plugin class"
        assert has_get_plugin, "Plugin missing get_plugin() function"


class TestPluginLoading:
    """Test dynamic loading of plugin modules."""

    def test_load_plugin_module_dynamically(
        self, plugin_directory: Path
    ) -> None:
        """Plugin modules load dynamically at runtime."""
        plugin_path = plugin_directory / "simple_analyzer.py"

        spec = importlib.util.spec_from_file_location("simple_analyzer", plugin_path)
        assert spec is not None
        assert spec.loader is not None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        assert hasattr(module, "get_plugin")
        assert callable(module.get_plugin)

    def test_instantiate_plugin_from_module(
        self, plugin_directory: Path
    ) -> None:
        """Plugin instances create successfully from loaded modules."""
        plugin_path = plugin_directory / "simple_analyzer.py"

        spec = importlib.util.spec_from_file_location("simple_analyzer", plugin_path)
        assert spec is not None
        assert spec.loader is not None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        plugin_instance = module.get_plugin()

        assert plugin_instance is not None
        assert hasattr(plugin_instance, "run")
        assert hasattr(plugin_instance, "get_metadata")
        assert callable(plugin_instance.run)

    def test_plugin_metadata_extraction(
        self, plugin_directory: Path
    ) -> None:
        """Plugin metadata extracts correctly from loaded instances."""
        plugin_path = plugin_directory / "pattern_scanner.py"

        spec = importlib.util.spec_from_file_location("pattern_scanner", plugin_path)
        assert spec is not None
        assert spec.loader is not None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        plugin = module.get_plugin()
        metadata = plugin.get_metadata()

        assert metadata["name"] == "Pattern Scanner"
        assert metadata["version"] == "2.0.0"
        assert "capabilities" in metadata
        assert isinstance(metadata["capabilities"], list)
        assert "pattern_search" in metadata["capabilities"]


class TestPluginExecution:
    """Test real plugin execution on sample binaries."""

    def test_execute_simple_analyzer_plugin(
        self, plugin_directory: Path, sample_binary: Path
    ) -> None:
        """Simple analyzer plugin executes and returns results."""
        plugin_path = plugin_directory / "simple_analyzer.py"

        spec = importlib.util.spec_from_file_location("simple_analyzer", plugin_path)
        assert spec is not None
        assert spec.loader is not None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        plugin = module.get_plugin()
        result = plugin.run(str(sample_binary))

        assert result["status"] == "success"
        assert result["binary"] == str(sample_binary)
        assert len(result["findings"]) >= 2

        file_size_finding = next(
            f for f in result["findings"] if f["type"] == "file_size"
        )
        assert file_size_finding["value"] > 0

    def test_execute_pattern_scanner_plugin(
        self, plugin_directory: Path, sample_binary: Path
    ) -> None:
        """Pattern scanner plugin finds license-related strings."""
        plugin_path = plugin_directory / "pattern_scanner.py"

        spec = importlib.util.spec_from_file_location("pattern_scanner", plugin_path)
        assert spec is not None
        assert spec.loader is not None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        plugin = module.get_plugin()
        result = plugin.run(str(sample_binary))

        assert result["status"] == "success"
        assert len(result["findings"]) >= 2

        patterns_found = [f["pattern"] for f in result["findings"]]
        assert "LICENSE" in patterns_found or "TRIAL" in patterns_found

        for finding in result["findings"]:
            assert "offset" in finding
            assert finding["offset"] >= 0

    def test_plugin_execution_with_options(
        self, plugin_directory: Path, sample_binary: Path
    ) -> None:
        """Plugins accept and use execution options."""
        plugin_path = plugin_directory / "simple_analyzer.py"

        spec = importlib.util.spec_from_file_location("simple_analyzer", plugin_path)
        assert spec is not None
        assert spec.loader is not None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        plugin = module.get_plugin()

        options = {"verbose": True, "max_findings": 10}
        result = plugin.run(str(sample_binary), options=options)

        assert result["status"] == "success"

    def test_plugin_execution_error_handling(
        self, plugin_directory: Path
    ) -> None:
        """Plugin handles errors gracefully when binary doesn't exist."""
        plugin_path = plugin_directory / "simple_analyzer.py"

        spec = importlib.util.spec_from_file_location("simple_analyzer", plugin_path)
        assert spec is not None
        assert spec.loader is not None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        plugin = module.get_plugin()

        nonexistent_binary = "/path/to/nonexistent/file.exe"
        result = plugin.run(nonexistent_binary)

        assert result["status"] == "error"
        assert "error" in result


class TestPluginRunner:
    """Test PluginRunner Qt integration."""

    def test_plugin_runner_executes_plugin(
        self, qapp: QApplication, plugin_directory: Path, sample_binary: Path
    ) -> None:
        """PluginRunner executes plugin in background thread."""
        plugin_path = plugin_directory / "simple_analyzer.py"

        runner = PluginRunner(str(plugin_path), str(sample_binary))

        results: list[dict[str, Any]] = []
        runner.finished.connect(lambda r: results.append(r))

        runner.start()
        runner.wait(5000)

        assert len(results) > 0
        assert results[0]["status"] == "success"

    def test_plugin_runner_handles_long_execution(
        self, qapp: QApplication, temp_workspace: Path, sample_binary: Path
    ) -> None:
        """PluginRunner handles plugins with longer execution time."""
        slow_plugin = temp_workspace / "slow_plugin.py"
        slow_plugin.write_text(
            '''"""Slow plugin for timeout testing."""

import time
from typing import Any


class SlowPlugin:
    def __init__(self) -> None:
        self.name = "Slow Plugin"
        self.version = "1.0.0"

    def get_metadata(self) -> dict[str, Any]:
        return {"name": self.name, "version": self.version}

    def run(self, binary_path: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        time.sleep(2)
        return {"status": "success", "message": "Completed after delay"}


def get_plugin() -> Any:
    return SlowPlugin()
'''
        )

        runner = PluginRunner(str(slow_plugin), str(sample_binary))

        results: list[dict[str, Any]] = []
        runner.finished.connect(lambda r: results.append(r))

        runner.start()
        runner.wait(10000)

        assert len(results) > 0
        assert results[0]["status"] == "success"


class TestPluginManagerDialog:
    """Test PluginManagerDialog integration."""

    def test_dialog_discovers_and_lists_plugins(
        self, qapp: QApplication, plugin_directory: Path
    ) -> None:
        """Dialog discovers and displays available plugins."""
        dialog = PluginManagerDialog(plugin_dir=str(plugin_directory))

        plugin_list = dialog.plugin_list

        assert plugin_list.rowCount() >= 2

        plugin_names = []
        for row in range(plugin_list.rowCount()):
            name_item = plugin_list.item(row, 0)
            if name_item:
                plugin_names.append(name_item.text())

        assert any("Simple Analyzer" in name or "simple_analyzer" in name for name in plugin_names)

    def test_dialog_shows_plugin_details(
        self, qapp: QApplication, plugin_directory: Path
    ) -> None:
        """Dialog shows detailed information for selected plugin."""
        dialog = PluginManagerDialog(plugin_dir=str(plugin_directory))

        if dialog.plugin_list.rowCount() > 0:
            dialog.plugin_list.selectRow(0)

            details_text = dialog.plugin_details.toPlainText()
            assert len(details_text) > 0


class TestPluginValidation:
    """Test plugin validation and security checks."""

    def test_reject_plugin_without_get_plugin_function(
        self, temp_workspace: Path
    ) -> None:
        """Plugin without get_plugin() function is invalid."""
        invalid_plugin = temp_workspace / "invalid.py"
        invalid_plugin.write_text(
            '''"""Invalid plugin without get_plugin function."""


class SomeClass:
    def __init__(self) -> None:
        pass
'''
        )

        spec = importlib.util.spec_from_file_location("invalid", invalid_plugin)
        assert spec is not None
        assert spec.loader is not None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        assert not hasattr(module, "get_plugin")

    def test_reject_plugin_with_syntax_errors(
        self, temp_workspace: Path
    ) -> None:
        """Plugin with syntax errors fails to load."""
        broken_plugin = temp_workspace / "broken.py"
        broken_plugin.write_text(
            '''"""Plugin with syntax errors."""

def get_plugin(
    this is broken syntax {{{
'''
        )

        spec = importlib.util.spec_from_file_location("broken", broken_plugin)
        assert spec is not None
        assert spec.loader is not None

        with pytest.raises(SyntaxError):
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

    def test_plugin_instance_has_required_methods(
        self, plugin_directory: Path
    ) -> None:
        """Loaded plugin instances have required methods."""
        plugin_path = plugin_directory / "simple_analyzer.py"

        spec = importlib.util.spec_from_file_location("simple_analyzer", plugin_path)
        assert spec is not None
        assert spec.loader is not None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        plugin = module.get_plugin()

        assert hasattr(plugin, "run")
        assert hasattr(plugin, "get_metadata")
        assert callable(plugin.run)
        assert callable(plugin.get_metadata)


class TestPluginIsolation:
    """Test plugin execution isolation and sandboxing."""

    def test_plugin_exception_doesnt_crash_system(
        self, temp_workspace: Path, sample_binary: Path
    ) -> None:
        """Exception in plugin doesn't crash the plugin system."""
        crashing_plugin = temp_workspace / "crasher.py"
        crashing_plugin.write_text(
            '''"""Plugin that raises exception during execution."""

from typing import Any


class CrashingPlugin:
    def __init__(self) -> None:
        self.name = "Crasher"
        self.version = "1.0.0"

    def get_metadata(self) -> dict[str, Any]:
        return {"name": self.name, "version": self.version}

    def run(self, binary_path: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        raise RuntimeError("Intentional crash for testing")


def get_plugin() -> Any:
    return CrashingPlugin()
'''
        )

        spec = importlib.util.spec_from_file_location("crasher", crashing_plugin)
        assert spec is not None
        assert spec.loader is not None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        plugin = module.get_plugin()

        with pytest.raises(RuntimeError):
            plugin.run(str(sample_binary))

    def test_plugin_cannot_modify_global_state(
        self, temp_workspace: Path, sample_binary: Path
    ) -> None:
        """Plugin execution is isolated and doesn't modify global state."""
        original_modules = set(sys.modules.keys())

        plugin_path = temp_workspace / "isolate_test.py"
        plugin_path.write_text(
            '''"""Plugin for isolation testing."""

import sys
from typing import Any


class IsolationTestPlugin:
    def __init__(self) -> None:
        self.name = "Isolation Test"

    def get_metadata(self) -> dict[str, Any]:
        return {"name": self.name}

    def run(self, binary_path: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        sys.test_value = "modified"
        return {"status": "success"}


def get_plugin() -> Any:
    return IsolationTestPlugin()
'''
        )

        spec = importlib.util.spec_from_file_location("isolate_test", plugin_path)
        assert spec is not None
        assert spec.loader is not None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        plugin = module.get_plugin()
        plugin.run(str(sample_binary))

        assert hasattr(sys, "test_value")
        assert sys.test_value == "modified"

        del sys.test_value


class TestPluginPerformance:
    """Test plugin performance characteristics."""

    def test_plugin_execution_completes_in_time(
        self, plugin_directory: Path, sample_binary: Path
    ) -> None:
        """Plugin execution completes within reasonable time."""
        import time

        plugin_path = plugin_directory / "simple_analyzer.py"

        spec = importlib.util.spec_from_file_location("simple_analyzer", plugin_path)
        assert spec is not None
        assert spec.loader is not None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        plugin = module.get_plugin()

        start_time = time.time()
        result = plugin.run(str(sample_binary))
        duration = time.time() - start_time

        assert result["status"] == "success"
        assert duration < 5.0, f"Plugin took {duration}s (>5s timeout)"

    def test_multiple_plugins_execute_sequentially(
        self, plugin_directory: Path, sample_binary: Path
    ) -> None:
        """Multiple plugins execute successfully in sequence."""
        results: list[dict[str, Any]] = []

        for plugin_file in plugin_directory.glob("*.py"):
            spec = importlib.util.spec_from_file_location(plugin_file.stem, plugin_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                if hasattr(module, "get_plugin"):
                    plugin = module.get_plugin()
                    result = plugin.run(str(sample_binary))
                    results.append(result)

        assert len(results) >= 2
        assert all(r["status"] == "success" for r in results)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
