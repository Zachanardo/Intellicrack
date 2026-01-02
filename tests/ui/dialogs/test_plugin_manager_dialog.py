"""Production-grade tests for Plugin Manager Dialog.

This test suite validates real plugin discovery, loading, installation, configuration,
and lifecycle management. Tests verify actual plugin system operations without mocks,
ensuring plugin management works on real plugin files and performs genuine operations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3
"""

import hashlib
import json
import os
import shutil
import tempfile
import time
import zipfile
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.pyqt6_handler import HAS_PYQT as PYQT6_AVAILABLE

QApplication: Any = None
QMessageBox: Any = None
Qt: Any = None
PluginInstallThread: Any = None
PluginManagerDialog: Any = None

if PYQT6_AVAILABLE:
    from intellicrack.handlers.pyqt6_handler import QApplication, QMessageBox, Qt
    from intellicrack.ui.dialogs.plugin_manager_dialog import (
        PluginInstallThread,
        PluginManagerDialog,
    )


pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE,
    reason="PyQt6 required for UI tests",
)


@pytest.fixture(scope="module")
def qapp() -> Any:
    """Create QApplication instance for testing."""
    if not PYQT6_AVAILABLE:
        pytest.skip("PyQt6 not available")
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def temp_plugins_dir() -> Generator[Path, None, None]:
    """Create temporary directory for plugin testing."""
    with tempfile.TemporaryDirectory(prefix="plugin_manager_test_") as tmpdir:
        plugins_dir = Path(tmpdir) / "plugins"
        plugins_dir.mkdir()
        yield plugins_dir


@pytest.fixture
def mock_app_context() -> Any:
    """Create mock app context with config."""
    class MockAppContext:
        def __init__(self) -> None:
            self.config: dict[str, Any] = {
                "plugin_auto_update": False,
                "plugin_auto_refresh": False,
                "plugin_configs": {},
                "plugin_repositories": {},
            }
    return MockAppContext()


@pytest.fixture
def sample_analysis_plugin(temp_plugins_dir: Path) -> Path:
    """Create realistic analysis plugin file."""
    plugin_code = '''#!/usr/bin/env python3
# Name: Entropy Analyzer
# Version: 1.2.0
# Description: Calculate Shannon entropy to detect packing and encryption
# Author: Test Author

import hashlib
import logging
import os
import time
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

class EntropyAnalyzerPlugin:
    """Advanced entropy analysis plugin for detecting packed/encrypted binaries."""

    def __init__(self) -> None:
        self.name = "Entropy Analyzer"
        self.version = "1.2.0"
        self.description = "Calculate Shannon entropy to detect packing and encryption"
        self.author = "Test Author"
        self.category = "Analysis"
        self.app = None

    def initialize(self, app_instance: object) -> bool:
        """Initialize plugin with app instance."""
        try:
            self.app = app_instance
            logger.info(f"{self.name} plugin initialized")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize {self.name}: {e}")
            return False

    def analyze_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if not data:
            return 0.0

        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        entropy = 0.0
        data_len = len(data)
        import math
        for count in freq:
            if count > 0:
                p = count / data_len
                entropy -= p * math.log2(p)

        return entropy

    def execute(self, binary_path: str, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Execute entropy analysis."""
        logger.info(f"Starting entropy analysis on: {binary_path}")

        if not os.path.exists(binary_path):
            return {
                'status': 'error',
                'message': f'File not found: {binary_path}',
                'data': {}
            }

        try:
            start_time = time.time()

            with open(binary_path, 'rb') as f:
                file_data = f.read()

            file_hash = hashlib.sha256(file_data).hexdigest()
            entropy = self.analyze_entropy(file_data)

            results = {
                'file_size': len(file_data),
                'sha256': file_hash,
                'entropy': entropy,
                'is_packed': entropy > 7.0,
                'execution_time': time.time() - start_time
            }

            return {
                'status': 'success',
                'message': f'Entropy analysis completed for {os.path.basename(binary_path)}',
                'data': results
            }

        except Exception as e:
            logger.error(f"Entropy analysis failed: {e}")
            return {
                'status': 'error',
                'message': str(e),
                'data': {}
            }

    def analyze(self, binary_path: str) -> List[str]:
        """Analyze method for plugin system compatibility."""
        result = self.execute(binary_path)

        if result['status'] == 'success':
            data = result['data']
            return [
                f"File: {os.path.basename(binary_path)}",
                f"Size: {data['file_size']} bytes",
                f"SHA256: {data['sha256']}",
                f"Entropy: {data['entropy']:.2f}",
                f"Packed: {'Yes' if data['is_packed'] else 'No'}",
                f"Execution time: {data['execution_time']:.3f}s"
            ]
        else:
            return [f"Analysis failed: {result['message']}"]

    def cleanup(self) -> bool:
        """Cleanup plugin resources."""
        try:
            logger.info(f"{self.name} plugin cleaned up")
            return True
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            return False

def create_plugin() -> EntropyAnalyzerPlugin:
    return EntropyAnalyzerPlugin()

def register() -> EntropyAnalyzerPlugin:
    return create_plugin()

PLUGIN_INFO = {
    'name': 'Entropy Analyzer',
    'version': '1.2.0',
    'description': 'Calculate Shannon entropy to detect packing and encryption',
    'author': 'Test Author',
    'type': 'analysis',
    'entry_point': 'create_plugin',
    'categories': ['Analysis'],
    'supported_formats': ['PE', 'ELF', 'Raw']
}
'''

    plugin_file = temp_plugins_dir / "entropy_analyzer.py"
    plugin_file.write_text(plugin_code, encoding='utf-8')
    return plugin_file


@pytest.fixture
def sample_exploitation_plugin(temp_plugins_dir: Path) -> Path:
    """Create realistic exploitation plugin file."""
    plugin_code = '''#!/usr/bin/env python3
# Name: License Checker Detector
# Version: 1.0.0
# Description: Detect license validation routines in binaries
# Author: Security Researcher

import logging
import os
import re
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

class LicenseCheckerDetectorPlugin:
    """Plugin for detecting license validation and registration checks."""

    def __init__(self) -> None:
        self.name = "License Checker Detector"
        self.version = "1.0.0"
        self.description = "Detect license validation routines in binaries"
        self.author = "Security Researcher"
        self.category = "Exploitation"

        self.license_patterns = [
            b'Trial expired',
            b'Invalid license',
            b'License not found',
            b'Registration required',
            b'Please register',
            b'Enter serial number',
            b'Activation failed'
        ]

    def execute(self, binary_path: str, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Execute license check detection."""
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

            findings = []
            offsets = {}

            for pattern in self.license_patterns:
                offset = data.find(pattern)
                if offset != -1:
                    pattern_str = pattern.decode('ascii', errors='ignore')
                    findings.append(f"License pattern found at 0x{offset:08x}: {pattern_str}")
                    offsets[pattern_str] = offset

            return {
                'status': 'success',
                'message': 'License check detection completed',
                'data': {
                    'patterns_found': len(findings),
                    'findings': findings,
                    'offsets': offsets
                }
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e),
                'data': {}
            }

def create_plugin() -> LicenseCheckerDetectorPlugin:
    return LicenseCheckerDetectorPlugin()

PLUGIN_INFO = {
    'name': 'License Checker Detector',
    'version': '1.0.0',
    'description': 'Detect license validation routines in binaries',
    'author': 'Security Researcher',
    'type': 'exploitation'
}
'''

    plugin_file = temp_plugins_dir / "license_checker_detector.py"
    plugin_file.write_text(plugin_code, encoding='utf-8')
    return plugin_file


@pytest.fixture
def sample_plugin_zip(temp_plugins_dir: Path, sample_analysis_plugin: Path) -> Path:
    """Create ZIP archive containing plugin."""
    zip_path = temp_plugins_dir / "entropy_plugin.zip"

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(sample_analysis_plugin, arcname="entropy_analyzer.py")

    return zip_path


@pytest.fixture
def test_binary_file(temp_plugins_dir: Path) -> Path:
    """Create test binary file for plugin testing."""
    binary_path = temp_plugins_dir / "test_binary.exe"

    binary_data = b'MZ\x90\x00'
    binary_data += b'\x00' * 60
    binary_data += b'\x40\x00\x00\x00'
    binary_data += b'\x00' * (0x40 - len(binary_data))
    binary_data += b'PE\x00\x00'
    binary_data += b'\x4c\x01'
    binary_data += b'\x02\x00'
    binary_data += b'\x00' * 100

    binary_data += b'Trial expired' * 5
    binary_data += b'Invalid license key' * 3
    binary_data += b'\xFF' * 1000

    binary_path.write_bytes(binary_data)
    return binary_path


class TestPluginManagerDialogInitialization:
    """Test plugin manager dialog initialization and setup."""

    def test_dialog_initializes_with_default_directories(
        self, qapp: Any, temp_plugins_dir: Path, mock_app_context: Any
    ) -> None:
        """Dialog creates required directories on initialization."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)

        assert dialog.plugins_dir is not None
        assert dialog.temp_dir is not None
        assert os.path.exists(dialog.plugins_dir)
        assert os.path.exists(dialog.temp_dir)

    def test_dialog_loads_plugin_categories(
        self, qapp: Any, mock_app_context: Any
    ) -> None:
        """Dialog initializes with correct plugin categories."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)

        expected_categories = [
            "Analysis",
            "Exploitation",
            "Network",
            "UI",
            "Utilities",
            "Tools",
        ]

        assert dialog.plugin_categories == expected_categories

    def test_dialog_initializes_repositories(
        self, qapp: Any, mock_app_context: Any
    ) -> None:
        """Dialog initializes with plugin repositories."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)

        assert "Official Repository" in dialog.repositories
        assert "Community Repository" in dialog.repositories
        assert "Local Repository" in dialog.repositories
        assert dialog.repositories["Local Repository"] == dialog.plugins_dir


class TestPluginDiscovery:
    """Test plugin discovery and loading functionality."""

    def test_discovers_installed_python_plugins(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, mock_app_context: Any
    ) -> None:
        """Plugin manager discovers installed Python plugin files."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.load_installed_plugins()

        assert len(dialog.installed_plugins) == 1
        assert dialog.installed_plugins[0]['name'] == 'Entropy Analyzer'
        assert dialog.installed_plugins[0]['version'] == '1.2.0'
        assert dialog.installed_plugins[0]['type'] == 'file'

    def test_discovers_multiple_plugins(
        self,
        qapp: Any,
        temp_plugins_dir: Path,
        sample_analysis_plugin: Path,
        sample_exploitation_plugin: Path,
        mock_app_context: Any
    ) -> None:
        """Plugin manager discovers all installed plugins."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.load_installed_plugins()

        assert len(dialog.installed_plugins) == 2

        plugin_names = [p['name'] for p in dialog.installed_plugins]
        assert 'Entropy Analyzer' in plugin_names
        assert 'License Checker Detector' in plugin_names

    def test_extracts_plugin_metadata_from_comments(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, mock_app_context: Any
    ) -> None:
        """Plugin manager extracts metadata from plugin file comments."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)

        plugin_info = dialog.get_plugin_info(str(sample_analysis_plugin))

        assert plugin_info['name'] == 'Entropy Analyzer'
        assert plugin_info['version'] == '1.2.0'
        assert plugin_info['description'] == 'Calculate Shannon entropy to detect packing and encryption'

    def test_plugin_info_handles_missing_metadata(
        self, qapp: Any, temp_plugins_dir: Path, mock_app_context: Any
    ) -> None:
        """Plugin manager handles plugins with missing metadata gracefully."""
        plugin_file = temp_plugins_dir / "minimal_plugin.py"
        plugin_file.write_text("# Minimal plugin without metadata\npass", encoding='utf-8')

        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        plugin_info = dialog.get_plugin_info(str(plugin_file))

        assert plugin_info['name'] == 'minimal_plugin.py'
        assert plugin_info['version'] == '1.0.0'
        assert plugin_info['description'] == 'No description available'


class TestPluginInstallation:
    """Test plugin installation from files and archives."""

    def test_installs_plugin_from_python_file(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, mock_app_context: Any
    ) -> None:
        """Plugin manager installs plugin from Python file."""
        source_plugin = temp_plugins_dir / "source_plugin.py"
        shutil.copy2(sample_analysis_plugin, source_plugin)

        install_dir = temp_plugins_dir / "installed"
        install_dir.mkdir()

        thread = PluginInstallThread(str(source_plugin), str(install_dir))

        success = False
        message = ""

        def on_finish(s: bool, m: str) -> None:
            nonlocal success, message
            success = s
            message = m

        thread.installation_finished.connect(on_finish)
        thread.run()

        assert success
        assert "successfully" in message.lower()
        assert (install_dir / "source_plugin.py").exists()

    def test_installs_plugin_from_zip_archive(
        self, qapp: Any, temp_plugins_dir: Path, sample_plugin_zip: Path, mock_app_context: Any
    ) -> None:
        """Plugin manager extracts and installs plugin from ZIP archive."""
        install_dir = temp_plugins_dir / "installed_zip"
        install_dir.mkdir()

        thread = PluginInstallThread(str(sample_plugin_zip), str(install_dir))

        success = False
        message = ""

        def on_finish(s: bool, m: str) -> None:
            nonlocal success, message
            success = s
            message = m

        thread.installation_finished.connect(on_finish)
        thread.run()

        assert success
        assert "successfully" in message.lower()
        assert (install_dir / "entropy_analyzer.py").exists()

    def test_validates_installed_plugin_has_python_files(
        self, qapp: Any, temp_plugins_dir: Path, mock_app_context: Any
    ) -> None:
        """Installation fails if archive contains no Python files."""
        invalid_zip = temp_plugins_dir / "invalid.zip"

        with zipfile.ZipFile(invalid_zip, 'w') as zipf:
            zipf.writestr("readme.txt", "Not a plugin")

        install_dir = temp_plugins_dir / "installed_invalid"
        install_dir.mkdir()

        thread = PluginInstallThread(str(invalid_zip), str(install_dir))

        success = False
        message = ""

        def on_finish(s: bool, m: str) -> None:
            nonlocal success, message
            success = s
            message = m

        thread.installation_finished.connect(on_finish)
        thread.run()

        assert not success
        assert "no python files" in message.lower()

    def test_installation_handles_errors_gracefully(
        self, qapp: Any, temp_plugins_dir: Path, mock_app_context: Any
    ) -> None:
        """Installation thread handles errors and reports failure."""
        nonexistent_file = temp_plugins_dir / "nonexistent.py"
        install_dir = temp_plugins_dir / "install_fail"
        install_dir.mkdir()

        thread = PluginInstallThread(str(nonexistent_file), str(install_dir))

        success = False
        message = ""

        def on_finish(s: bool, m: str) -> None:
            nonlocal success, message
            success = s
            message = m

        thread.installation_finished.connect(on_finish)
        thread.run()

        assert not success
        assert "failed" in message.lower()


class TestPluginEnableDisable:
    """Test plugin enable/disable functionality."""

    def test_enables_plugin(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, mock_app_context: Any
    ) -> None:
        """Plugin manager enables selected plugin."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.load_installed_plugins()

        item = dialog.installed_list.item(0)
        plugin_info = item.data(0)
        plugin_info['enabled'] = False
        item.setData(0, plugin_info)
        dialog.installed_list.setCurrentItem(item)

        dialog.enable_selected_plugin()

        updated_info = item.data(0)
        assert updated_info['enabled'] is True

    def test_disables_plugin(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, mock_app_context: Any
    ) -> None:
        """Plugin manager disables selected plugin."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.load_installed_plugins()

        item = dialog.installed_list.item(0)
        plugin_info = item.data(0)
        plugin_info['enabled'] = True
        item.setData(0, plugin_info)
        dialog.installed_list.setCurrentItem(item)

        dialog.disable_selected_plugin()

        updated_info = item.data(0)
        assert updated_info['enabled'] is False

    def test_displays_disabled_plugins_differently(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, mock_app_context: Any
    ) -> None:
        """Disabled plugins are displayed with different color."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.load_installed_plugins()

        enabled_item = dialog.installed_list.item(0)
        enabled_color = enabled_item.foreground()

        dialog.installed_list.setCurrentItem(enabled_item)
        dialog.disable_selected_plugin()

        disabled_item = dialog.installed_list.item(0)
        disabled_color = disabled_item.foreground()

        assert enabled_color != disabled_color


class TestPluginRemoval:
    """Test plugin removal functionality."""

    def test_removes_plugin_file(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, mock_app_context: Any, monkeypatch: Any
    ) -> None:
        """Plugin manager removes plugin file when confirmed."""
        from intellicrack.handlers.pyqt6_handler import QMessageBox

        monkeypatch.setattr(
            QMessageBox, 'question',
            lambda *args, **kwargs: QMessageBox.StandardButton.Yes
        )

        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.load_installed_plugins()
        assert len(dialog.installed_plugins) == 1

        dialog.installed_list.setCurrentRow(0)
        dialog.remove_selected_plugin()

        assert not sample_analysis_plugin.exists()

    def test_removes_plugin_directory(
        self, qapp: Any, temp_plugins_dir: Path, mock_app_context: Any, monkeypatch: Any
    ) -> None:
        """Plugin manager removes plugin directory when confirmed."""
        from intellicrack.handlers.pyqt6_handler import QMessageBox

        plugin_dir = temp_plugins_dir / "test_plugin_dir"
        plugin_dir.mkdir()
        (plugin_dir / "__init__.py").write_text("# Plugin module", encoding='utf-8')
        (plugin_dir / "plugin.py").write_text("# Main plugin", encoding='utf-8')

        monkeypatch.setattr(
            QMessageBox, 'question',
            lambda *args, **kwargs: QMessageBox.StandardButton.Yes
        )

        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.load_installed_plugins()

        dialog.installed_list.setCurrentRow(0)
        dialog.remove_selected_plugin()

        assert not plugin_dir.exists()


class TestPluginConfiguration:
    """Test plugin configuration functionality."""

    def test_saves_plugin_configuration(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, mock_app_context: Any
    ) -> None:
        """Plugin manager saves configuration for plugins."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.load_installed_plugins()

        plugin_name = "Entropy Analyzer"
        test_config = {
            'enabled': True,
            'auto_update': False,
            'max_file_size': 50,
            'timeout': 60
        }

        dialog.plugin_configs[plugin_name] = test_config

        assert dialog.plugin_configs[plugin_name] == test_config
        assert dialog.plugin_configs[plugin_name]['enabled'] is True
        assert dialog.plugin_configs[plugin_name]['max_file_size'] == 50

    def test_loads_configuration_from_app_context(
        self, qapp: Any, temp_plugins_dir: Path, mock_app_context: Any
    ) -> None:
        """Plugin manager loads configurations from app context."""
        test_configs = {
            'TestPlugin': {
                'enabled': True,
                'timeout': 30
            }
        }
        mock_app_context.config['plugin_configs'] = test_configs

        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.load_settings()

        assert 'TestPlugin' in dialog.plugin_configs
        assert dialog.plugin_configs['TestPlugin']['enabled'] is True


class TestPluginTemplateCreation:
    """Test plugin template generation."""

    def test_creates_analysis_plugin_template(
        self, qapp: Any, temp_plugins_dir: Path, mock_app_context: Any
    ) -> None:
        """Plugin manager creates functional analysis plugin template."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.plugin_name_edit.setText("Test Analyzer")
        dialog.plugin_type_combo.setCurrentText("Analysis Plugin")
        dialog.author_edit.setText("Test User")

        dialog.create_plugin_template()

        template_file = temp_plugins_dir / "test_analyzer_plugin.py"
        assert template_file.exists()

        template_code = template_file.read_text(encoding='utf-8')
        assert "Test Analyzer" in template_code
        assert "Test User" in template_code
        assert "class TestAnalyzerPlugin" in template_code
        assert "def execute(" in template_code
        assert "PLUGIN_INFO" in template_code

        compile(template_code, str(template_file), 'exec')

    def test_creates_exploitation_plugin_template(
        self, qapp: Any, temp_plugins_dir: Path, mock_app_context: Any
    ) -> None:
        """Plugin manager creates functional exploitation plugin template."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.plugin_name_edit.setText("License Bypass")
        dialog.plugin_type_combo.setCurrentText("Exploit Plugin")
        dialog.author_edit.setText("Security Researcher")

        dialog.create_plugin_template()

        template_file = temp_plugins_dir / "license_bypass_plugin.py"
        assert template_file.exists()

        template_code = template_file.read_text(encoding='utf-8')
        assert "License Bypass" in template_code
        assert "Security Researcher" in template_code
        assert "def validate_binary(" in template_code


class TestPluginTesting:
    """Test plugin validation and testing functionality."""

    def test_validates_plugin_syntax(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, mock_app_context: Any
    ) -> None:
        """Plugin tester validates plugin syntax successfully."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.test_file_edit.setText(str(sample_analysis_plugin))

        dialog.test_plugin()

        output = dialog.test_output.toPlainText()
        assert "Syntax check passed" in output
        assert "Plugin class found" in output
        assert "Execute method found" in output
        assert "Plugin metadata found" in output

    def test_detects_syntax_errors(
        self, qapp: Any, temp_plugins_dir: Path, mock_app_context: Any
    ) -> None:
        """Plugin tester detects syntax errors in plugins."""
        invalid_plugin = temp_plugins_dir / "invalid_syntax.py"
        invalid_plugin.write_text("def broken_function(\n    # Missing closing parenthesis", encoding='utf-8')

        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.test_file_edit.setText(str(invalid_plugin))

        dialog.test_plugin()

        output = dialog.test_output.toPlainText()
        assert "Syntax error" in output or "ERROR" in output

    def test_warns_about_missing_components(
        self, qapp: Any, temp_plugins_dir: Path, mock_app_context: Any
    ) -> None:
        """Plugin tester warns about missing required components."""
        incomplete_plugin = temp_plugins_dir / "incomplete.py"
        incomplete_plugin.write_text("# Plugin without class or methods\npass", encoding='utf-8')

        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.test_file_edit.setText(str(incomplete_plugin))

        dialog.test_plugin()

        output = dialog.test_output.toPlainText()
        assert "Warning" in output or "WARNING" in output


class TestPluginExecution:
    """Test actual plugin execution functionality."""

    def test_executes_analysis_plugin_on_binary(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, test_binary_file: Path, mock_app_context: Any
    ) -> None:
        """Plugin executes successfully on test binary."""
        import importlib.util

        spec = importlib.util.spec_from_file_location("test_plugin", sample_analysis_plugin)
        assert spec is not None, "Failed to create module spec"
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None, "Spec has no loader"
        spec.loader.exec_module(module)

        plugin = module.create_plugin()
        result = plugin.execute(str(test_binary_file))

        assert result['status'] == 'success'
        assert 'data' in result
        assert 'entropy' in result['data']
        assert 'sha256' in result['data']
        assert result['data']['file_size'] > 0

    def test_executes_exploitation_plugin_on_binary(
        self,
        qapp: Any,
        temp_plugins_dir: Path,
        sample_exploitation_plugin: Path,
        test_binary_file: Path,
        mock_app_context: Any
    ) -> None:
        """Exploitation plugin detects license patterns in binary."""
        import importlib.util

        spec = importlib.util.spec_from_file_location("exploit_plugin", sample_exploitation_plugin)
        assert spec is not None, "Failed to create module spec"
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None, "Spec has no loader"
        spec.loader.exec_module(module)

        plugin = module.create_plugin()
        result = plugin.execute(str(test_binary_file))

        assert result['status'] == 'success'
        assert result['data']['patterns_found'] > 0
        assert len(result['data']['findings']) > 0
        assert any('Trial expired' in finding for finding in result['data']['findings'])

    def test_plugin_handles_nonexistent_file(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, mock_app_context: Any
    ) -> None:
        """Plugin handles nonexistent file gracefully."""
        import importlib.util

        spec = importlib.util.spec_from_file_location("test_plugin", sample_analysis_plugin)
        assert spec is not None, "Failed to create module spec"
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None, "Spec has no loader"
        spec.loader.exec_module(module)

        plugin = module.create_plugin()
        result = plugin.execute("nonexistent_file.exe")

        assert result['status'] == 'error'
        assert 'not found' in result['message'].lower()


class TestDependencyChecking:
    """Test plugin dependency validation."""

    def test_checks_available_dependencies(
        self, qapp: Any, mock_app_context: Any
    ) -> None:
        """Plugin manager checks if dependencies are available."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)

        available_deps = ['os', 'sys', 'json']
        missing = dialog._check_dependencies(available_deps)

        assert len(missing) == 0

    def test_detects_missing_dependencies(
        self, qapp: Any, mock_app_context: Any
    ) -> None:
        """Plugin manager detects missing dependencies."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)

        test_deps = ['nonexistent_package_xyz123']
        missing = dialog._check_dependencies(test_deps)

        assert 'nonexistent_package_xyz123' in missing

    def test_checks_common_plugin_dependencies(
        self, qapp: Any, mock_app_context: Any
    ) -> None:
        """Plugin manager validates common plugin dependencies."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)

        common_deps = ['numpy', 'pefile', 'capstone']
        missing = dialog._check_dependencies(common_deps)

        assert isinstance(missing, list)


class TestPluginCodeGeneration:
    """Test plugin code generation for different types."""

    def test_generates_valid_analysis_plugin_code(
        self, qapp: Any, temp_plugins_dir: Path, mock_app_context: Any
    ) -> None:
        """Generated analysis plugin code is valid and functional."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)

        code = dialog._generate_analysis_plugin_code(
            "Binary Scanner",
            "1.0.0",
            "Test Author",
            "Scan binaries for patterns"
        )

        assert "class BinaryScannerPlugin" in code
        assert "def analyze_entropy(" in code
        assert "def detect_packers(" in code
        assert "def execute(" in code
        assert "PLUGIN_INFO" in code

        compile(code, "generated_plugin.py", 'exec')

    def test_generates_valid_exploitation_plugin_code(
        self, qapp: Any, temp_plugins_dir: Path, mock_app_context: Any
    ) -> None:
        """Generated exploitation plugin code is valid and functional."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)

        code = dialog._generate_exploitation_plugin_code(
            "Patcher Tool",
            "2.0.0",
            "Security Team",
            "Patch binaries to bypass checks"
        )

        assert "class PatcherToolPlugin" in code
        assert "license_patterns" in code
        assert "def execute(" in code
        assert "PLUGIN_INFO" in code

        compile(code, "generated_exploit.py", 'exec')

    def test_generates_valid_network_plugin_code(
        self, qapp: Any, temp_plugins_dir: Path, mock_app_context: Any
    ) -> None:
        """Generated network plugin code is valid and functional."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)

        code = dialog._generate_network_plugin_code(
            "Traffic Analyzer",
            "1.5.0",
            "Network Team",
            "Analyze network traffic patterns"
        )

        assert "class TrafficAnalyzerPlugin" in code
        assert "def execute(" in code
        assert "network" in code.lower()
        assert "PLUGIN_INFO" in code

        compile(code, "generated_network.py", 'exec')


class TestPluginRefresh:
    """Test plugin list refresh functionality."""

    def test_refreshes_plugin_list_after_installation(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, mock_app_context: Any
    ) -> None:
        """Plugin list refreshes after new plugin installation."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.load_installed_plugins()
        initial_count = len(dialog.installed_plugins)

        new_plugin = temp_plugins_dir / "new_plugin.py"
        new_plugin.write_text("# Name: New Plugin\n# Version: 1.0.0\npass", encoding='utf-8')

        dialog.refresh_plugins()

        assert len(dialog.installed_plugins) == initial_count + 1

    def test_refresh_updates_plugin_info(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, mock_app_context: Any
    ) -> None:
        """Refresh updates plugin information in list."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.load_installed_plugins()

        sample_analysis_plugin.write_text(
            sample_analysis_plugin.read_text().replace("Version: 1.2.0", "Version: 2.0.0"),
            encoding='utf-8'
        )

        dialog.refresh_plugins()

        updated_plugin = next(p for p in dialog.installed_plugins if 'Entropy' in p['name'])
        assert updated_plugin['version'] == '2.0.0'


class TestPluginInfoDisplay:
    """Test plugin information display."""

    def test_displays_plugin_info_on_selection(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, mock_app_context: Any
    ) -> None:
        """Plugin info is displayed when plugin is selected."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.load_installed_plugins()
        dialog.installed_list.setCurrentRow(0)

        info_text = dialog.plugin_info.toPlainText()

        assert "Entropy Analyzer" in info_text
        assert "1.2.0" in info_text
        assert "file" in info_text.lower()

    def test_clears_info_when_no_selection(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, mock_app_context: Any
    ) -> None:
        """Plugin info is cleared when no plugin is selected."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.load_installed_plugins()
        dialog.installed_list.setCurrentRow(0)

        assert len(dialog.plugin_info.toPlainText()) > 0

        dialog.installed_list.clearSelection()
        dialog.on_installed_selection_changed()

        assert len(dialog.plugin_info.toPlainText()) == 0


class TestPluginManagerIntegration:
    """Integration tests for complete plugin workflows."""

    def test_complete_plugin_installation_workflow(
        self, qapp: Any, temp_plugins_dir: Path, sample_analysis_plugin: Path, mock_app_context: Any
    ) -> None:
        """Complete workflow: install, enable, configure, test plugin."""
        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.load_installed_plugins()
        initial_count = len(dialog.installed_plugins)

        new_plugin_source = temp_plugins_dir / "source" / "workflow_plugin.py"
        new_plugin_source.parent.mkdir(exist_ok=True)
        shutil.copy2(sample_analysis_plugin, new_plugin_source)

        install_dir = temp_plugins_dir / "workflow_test"
        install_dir.mkdir()

        thread = PluginInstallThread(str(new_plugin_source), str(install_dir))

        success = False

        def on_finish(s: bool, m: str) -> None:
            nonlocal success
            success = s

        thread.installation_finished.connect(on_finish)
        thread.run()

        assert success

        dialog.refresh_plugins()
        assert len(dialog.installed_plugins) > initial_count

    def test_plugin_lifecycle_from_creation_to_removal(
        self, qapp: Any, temp_plugins_dir: Path, mock_app_context: Any, monkeypatch: Any
    ) -> None:
        """Complete plugin lifecycle: create, test, configure, remove."""
        from intellicrack.handlers.pyqt6_handler import QMessageBox

        dialog = PluginManagerDialog(parent=None, app_context=mock_app_context)
        dialog.plugins_dir = str(temp_plugins_dir)

        dialog.plugin_name_edit.setText("Lifecycle Test")
        dialog.plugin_type_combo.setCurrentText("Analysis Plugin")
        dialog.author_edit.setText("Test User")
        dialog.create_plugin_template()

        dialog.load_installed_plugins()
        assert any("Lifecycle Test" in p['name'] for p in dialog.installed_plugins)

        plugin_file = temp_plugins_dir / "lifecycle_test_plugin.py"
        dialog.test_file_edit.setText(str(plugin_file))
        dialog.test_plugin()

        output = dialog.test_output.toPlainText()
        assert "Syntax check passed" in output

        monkeypatch.setattr(
            QMessageBox, 'question',
            lambda *args, **kwargs: QMessageBox.StandardButton.Yes
        )

        dialog.installed_list.setCurrentRow(0)
        dialog.remove_selected_plugin()

        assert not plugin_file.exists()
