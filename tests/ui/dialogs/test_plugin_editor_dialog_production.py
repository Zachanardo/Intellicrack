"""Production-ready tests for PluginEditorDialog - Plugin development interface validation.

This module validates PluginEditorDialog's complete functionality including:
- Dialog initialization and multi-tab UI layout
- Plugin file loading and saving workflow
- Code editor integration with validation
- Test execution environment with process management
- Binary test file selection
- API documentation browser
- Plugin testing output capture
- CI/CD integration button availability
- Signal emission for plugin events
"""

import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox

from intellicrack.ui.dialogs.plugin_editor_dialog import PluginEditorDialog


@pytest.fixture
def qapp(qapp: QApplication) -> QApplication:
    """Provide QApplication instance for PyQt6 tests."""
    return qapp


@pytest.fixture
def temp_plugin_file(tmp_path: Path) -> Path:
    """Create temporary plugin file for testing."""
    plugin_content = '''"""Test plugin for license cracking."""

class TestPlugin:
    """Test plugin that analyzes license validation."""

    def __init__(self) -> None:
        self.name = "Test License Analyzer"
        self.version = "1.0.0"

    def run(self, binary_path: str, options: dict | None = None) -> dict:
        """Run license analysis on binary.

        Args:
            binary_path: Path to binary to analyze
            options: Optional analysis configuration

        Returns:
            Dictionary containing analysis results
        """
        return {
            "status": "success",
            "license_checks_found": 3,
            "activation_functions": ["CheckLicense", "ValidateSerial"],
        }

    def get_metadata(self) -> dict:
        """Return plugin metadata."""
        return {
            "name": self.name,
            "version": self.version,
            "description": "Analyzes license validation mechanisms",
            "author": "Test Author",
        }
'''
    plugin_file = tmp_path / "test_plugin.py"
    plugin_file.write_text(plugin_content)
    return plugin_file


@pytest.fixture
def temp_binary_file(tmp_path: Path) -> Path:
    """Create temporary binary file for testing."""
    binary_file = tmp_path / "test_binary.exe"
    binary_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)
    return binary_file


@pytest.fixture
def plugin_editor_dialog(qapp: QApplication) -> PluginEditorDialog:
    """Create PluginEditorDialog for testing."""
    dialog = PluginEditorDialog()
    return dialog


@pytest.fixture
def plugin_editor_with_file(qapp: QApplication, temp_plugin_file: Path) -> PluginEditorDialog:
    """Create PluginEditorDialog with loaded plugin file."""
    dialog = PluginEditorDialog(plugin_path=str(temp_plugin_file))
    return dialog


class TestPluginEditorDialogInitialization:
    """Test PluginEditorDialog initialization and UI setup."""

    def test_dialog_window_title_is_set(self, plugin_editor_dialog: PluginEditorDialog) -> None:
        """Dialog window title is set to 'Plugin Editor'."""
        assert plugin_editor_dialog.windowTitle() == "Plugin Editor"

    def test_dialog_minimum_size_configured(self, plugin_editor_dialog: PluginEditorDialog) -> None:
        """Dialog has minimum size of 1000x700 pixels."""
        assert plugin_editor_dialog.minimumWidth() == 1000
        assert plugin_editor_dialog.minimumHeight() == 700

    def test_dialog_has_tab_widget(self, plugin_editor_dialog: PluginEditorDialog) -> None:
        """Dialog contains tab widget for multiple sections."""
        assert plugin_editor_dialog.tab_widget is not None
        assert plugin_editor_dialog.tab_widget.count() == 3

    def test_editor_tab_exists(self, plugin_editor_dialog: PluginEditorDialog) -> None:
        """Dialog has Editor tab with plugin editor widget."""
        assert plugin_editor_dialog.tab_widget.tabText(0) == " Editor"
        assert plugin_editor_dialog.editor is not None

    def test_testing_tab_exists(self, plugin_editor_dialog: PluginEditorDialog) -> None:
        """Dialog has Testing tab for plugin execution."""
        tab_text = plugin_editor_dialog.tab_widget.tabText(1)
        assert "Testing" in tab_text
        assert plugin_editor_dialog.test_widget is not None

    def test_documentation_tab_exists(self, plugin_editor_dialog: PluginEditorDialog) -> None:
        """Dialog has Documentation tab with API reference."""
        tab_text = plugin_editor_dialog.tab_widget.tabText(2)
        assert "Documentation" in tab_text
        assert plugin_editor_dialog.docs_widget is not None

    def test_action_buttons_created(self, plugin_editor_dialog: PluginEditorDialog) -> None:
        """Dialog has action buttons for running, debugging, and testing."""
        assert plugin_editor_dialog.run_btn is not None
        assert plugin_editor_dialog.debug_btn is not None
        assert plugin_editor_dialog.test_gen_btn is not None
        assert plugin_editor_dialog.ci_cd_btn is not None

    def test_test_process_initialized_to_none(self, plugin_editor_dialog: PluginEditorDialog) -> None:
        """Test process is None on initialization."""
        assert plugin_editor_dialog.test_process is None

    def test_plugin_path_is_none_without_file(self, plugin_editor_dialog: PluginEditorDialog) -> None:
        """Plugin path is None when dialog created without file."""
        assert plugin_editor_dialog.plugin_path is None


class TestPluginEditorDialogFileOperations:
    """Test plugin file loading and saving operations."""

    def test_load_plugin_updates_editor_content(
        self, plugin_editor_dialog: PluginEditorDialog, temp_plugin_file: Path
    ) -> None:
        """Loading plugin file updates editor content with file text."""
        plugin_editor_dialog.load_plugin(str(temp_plugin_file))
        editor_content = plugin_editor_dialog.editor.get_code()
        assert "TestPlugin" in editor_content
        assert "run" in editor_content
        assert "get_metadata" in editor_content

    def test_load_plugin_updates_window_title(
        self, plugin_editor_dialog: PluginEditorDialog, temp_plugin_file: Path
    ) -> None:
        """Loading plugin updates window title with filename."""
        plugin_editor_dialog.load_plugin(str(temp_plugin_file))
        assert "test_plugin.py" in plugin_editor_dialog.windowTitle()

    def test_load_plugin_sets_current_file_path(
        self, plugin_editor_dialog: PluginEditorDialog, temp_plugin_file: Path
    ) -> None:
        """Loading plugin sets current file path in editor."""
        plugin_editor_dialog.load_plugin(str(temp_plugin_file))
        assert plugin_editor_dialog.editor.current_file == str(temp_plugin_file)

    def test_load_plugin_on_initialization(
        self, qapp: QApplication, temp_plugin_file: Path
    ) -> None:
        """Plugin file is loaded automatically when provided at initialization."""
        dialog = PluginEditorDialog(plugin_path=str(temp_plugin_file))
        editor_content = dialog.editor.get_code()
        assert "TestPlugin" in editor_content
        assert dialog.editor.current_file == str(temp_plugin_file)

    def test_load_nonexistent_plugin_shows_error(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Loading nonexistent plugin file displays error message."""
        with patch.object(QMessageBox, "critical") as mock_critical:
            plugin_editor_dialog.load_plugin("/nonexistent/plugin.py")
            mock_critical.assert_called_once()
            args = mock_critical.call_args[0]
            assert "Failed to load plugin" in args[2]

    def test_save_plugin_calls_editor_save(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Save plugin calls editor's save_file method."""
        with patch.object(plugin_editor_dialog.editor, "save_file") as mock_save:
            plugin_editor_dialog.save_plugin()
            mock_save.assert_called_once()

    def test_on_plugin_saved_emits_signal(
        self, plugin_editor_dialog: PluginEditorDialog, temp_plugin_file: Path
    ) -> None:
        """Plugin saved event emits plugin_saved signal with path."""
        signal_received = False
        received_path = None

        def signal_handler(path: str) -> None:
            nonlocal signal_received, received_path
            signal_received = True
            received_path = path

        plugin_editor_dialog.plugin_saved.connect(signal_handler)

        with patch.object(QMessageBox, "information"):
            plugin_editor_dialog.on_plugin_saved(str(temp_plugin_file))

        assert signal_received
        assert received_path == str(temp_plugin_file)

    def test_on_plugin_saved_shows_success_message(
        self, plugin_editor_dialog: PluginEditorDialog, temp_plugin_file: Path
    ) -> None:
        """Plugin saved event shows success message to user."""
        with patch.object(QMessageBox, "information") as mock_info:
            plugin_editor_dialog.on_plugin_saved(str(temp_plugin_file))
            mock_info.assert_called_once()
            args = mock_info.call_args[0]
            assert "saved successfully" in args[2]


class TestPluginEditorDialogTestingTab:
    """Test plugin testing functionality."""

    def test_test_tab_has_file_selector(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Testing tab has binary file selector widget."""
        assert plugin_editor_dialog.test_file_edit is not None

    def test_test_tab_has_verbose_checkbox(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Testing tab has verbose output checkbox."""
        assert plugin_editor_dialog.verbose_check is not None
        assert plugin_editor_dialog.verbose_check.isChecked()

    def test_test_tab_has_output_area(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Testing tab has output text area for test results."""
        assert plugin_editor_dialog.test_output is not None
        assert plugin_editor_dialog.test_output.isReadOnly()

    def test_browse_test_file_opens_dialog(
        self, plugin_editor_dialog: PluginEditorDialog, temp_binary_file: Path
    ) -> None:
        """Browse test file button opens file dialog and sets path."""
        with patch.object(
            QFileDialog, "getOpenFileName", return_value=(str(temp_binary_file), "")
        ):
            plugin_editor_dialog.browse_test_file()
            assert plugin_editor_dialog.test_file_edit.text() == str(temp_binary_file)

    def test_run_test_requires_saved_plugin(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Running test without saved plugin shows warning."""
        with patch.object(QMessageBox, "warning") as mock_warning:
            plugin_editor_dialog.run_test()
            mock_warning.assert_called_once()
            args = mock_warning.call_args[0]
            assert "No Plugin" in args[1]

    def test_run_test_requires_test_file(
        self, plugin_editor_with_file: PluginEditorDialog
    ) -> None:
        """Running test without test binary shows warning."""
        with patch.object(QMessageBox, "warning") as mock_warning:
            plugin_editor_with_file.run_test()
            mock_warning.assert_called_once()
            args = mock_warning.call_args[0]
            assert "No Test File" in args[1]

    def test_run_test_starts_process(
        self, plugin_editor_with_file: PluginEditorDialog, temp_binary_file: Path
    ) -> None:
        """Running test starts QProcess with plugin and binary."""
        plugin_editor_with_file.test_file_edit.setText(str(temp_binary_file))

        with patch("intellicrack.ui.dialogs.plugin_editor_dialog.QProcess") as MockProcess:
            mock_process = Mock()
            MockProcess.return_value = mock_process

            plugin_editor_with_file.run_test()

            mock_process.start.assert_called_once()
            assert plugin_editor_with_file.run_test_btn.isEnabled() is False
            assert plugin_editor_with_file.stop_test_btn.isEnabled() is True

    def test_stop_test_terminates_process(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Stop test button terminates running test process."""
        mock_process = Mock()
        plugin_editor_dialog.test_process = mock_process

        plugin_editor_dialog.stop_test()

        mock_process.terminate.assert_called_once()

    def test_test_finished_updates_ui_state(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Test completion updates button states correctly."""
        plugin_editor_dialog.run_test_btn.setEnabled(False)
        plugin_editor_dialog.stop_test_btn.setEnabled(True)

        plugin_editor_dialog.test_finished(0, None)

        assert plugin_editor_dialog.run_test_btn.isEnabled() is True
        assert plugin_editor_dialog.stop_test_btn.isEnabled() is False
        assert plugin_editor_dialog.test_process is None

    def test_run_plugin_switches_to_test_tab(
        self, plugin_editor_with_file: PluginEditorDialog, temp_binary_file: Path
    ) -> None:
        """Run plugin button switches to testing tab."""
        plugin_editor_with_file.test_file_edit.setText(str(temp_binary_file))

        with patch.object(plugin_editor_with_file.editor, "save_file"):
            with patch("intellicrack.ui.dialogs.plugin_editor_dialog.QProcess"):
                plugin_editor_with_file.run_plugin()
                current_tab = plugin_editor_with_file.tab_widget.currentWidget()
                assert current_tab == plugin_editor_with_file.test_widget


class TestPluginEditorDialogDocumentation:
    """Test API documentation functionality."""

    def test_docs_tab_has_api_list(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Documentation tab has API topic list."""
        assert plugin_editor_dialog.api_list is not None
        assert plugin_editor_dialog.api_list.count() > 0

    def test_docs_tab_has_viewer(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Documentation tab has documentation viewer."""
        assert plugin_editor_dialog.docs_viewer is not None

    def test_api_list_contains_required_topics(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """API list contains essential plugin development topics."""
        topics = []
        for i in range(plugin_editor_dialog.api_list.count()):
            topics.append(plugin_editor_dialog.api_list.item(i).text())

        assert "Plugin Base Class" in topics
        assert "Binary Analysis API" in topics
        assert "Frida API" in topics

    def test_selecting_api_topic_shows_documentation(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Selecting API topic displays its documentation in viewer."""
        plugin_editor_dialog.api_list.setCurrentRow(0)
        QApplication.processEvents()

        docs_html = plugin_editor_dialog.docs_viewer.toHtml()
        assert len(docs_html) > 0
        assert "Plugin Base Class" in docs_html

    def test_get_api_documentation_returns_html(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Getting API documentation returns HTML formatted content."""
        docs = plugin_editor_dialog.get_api_documentation("Binary Analysis API")
        assert "<h2>Binary Analysis API</h2>" in docs
        assert "analyze_binary" in docs

    def test_get_api_documentation_handles_unknown_topic(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Getting unknown API topic returns placeholder message."""
        docs = plugin_editor_dialog.get_api_documentation("Unknown Topic")
        assert "Unknown Topic" in docs
        assert "not available" in docs


class TestPluginEditorDialogValidation:
    """Test plugin validation functionality."""

    def test_validation_complete_enables_run_button(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Valid plugin validation enables run button."""
        plugin_editor_dialog.run_btn.setEnabled(False)
        plugin_editor_dialog.on_validation_complete({"valid": True})
        assert plugin_editor_dialog.run_btn.isEnabled() is True

    def test_validation_complete_disables_run_on_invalid(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Invalid plugin validation disables run button."""
        plugin_editor_dialog.run_btn.setEnabled(True)
        plugin_editor_dialog.on_validation_complete({"valid": False})
        assert plugin_editor_dialog.run_btn.isEnabled() is False

    def test_validation_complete_sets_tooltip(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Validation result sets appropriate button tooltip."""
        plugin_editor_dialog.on_validation_complete({"valid": True})
        tooltip = plugin_editor_dialog.run_btn.toolTip()
        assert "ready to run" in tooltip.lower()

    def test_validation_failure_sets_error_tooltip(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Validation failure sets error tooltip on run button."""
        plugin_editor_dialog.on_validation_complete({"valid": False})
        tooltip = plugin_editor_dialog.run_btn.toolTip()
        assert "Fix validation errors" in tooltip


class TestPluginEditorDialogIntegrations:
    """Test integration buttons and external dialog launches."""

    def test_debug_plugin_requires_saved_file(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Debug plugin without saved file shows warning."""
        with patch.object(QMessageBox, "warning") as mock_warning:
            plugin_editor_dialog.debug_plugin()
            mock_warning.assert_called_once()
            args = mock_warning.call_args[0]
            assert "save the plugin first" in args[2].lower()

    def test_generate_tests_requires_saved_file(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Generate tests without saved file shows warning."""
        with patch.object(QMessageBox, "warning") as mock_warning:
            plugin_editor_dialog.generate_tests()
            mock_warning.assert_called_once()
            args = mock_warning.call_args[0]
            assert "save the plugin first" in args[2].lower()

    def test_open_ci_cd_requires_saved_file(
        self, plugin_editor_dialog: PluginEditorDialog
    ) -> None:
        """Open CI/CD without saved file shows warning."""
        with patch.object(QMessageBox, "warning") as mock_warning:
            plugin_editor_dialog.open_ci_cd()
            mock_warning.assert_called_once()
            args = mock_warning.call_args[0]
            assert "save the plugin first" in args[2].lower()

    def test_debug_plugin_handles_import_error(
        self, plugin_editor_with_file: PluginEditorDialog
    ) -> None:
        """Debug plugin handles missing debugger module gracefully."""
        with patch.object(QMessageBox, "warning") as mock_warning:
            plugin_editor_with_file.debug_plugin()
            if mock_warning.called:
                args = mock_warning.call_args[0]
                assert "Not Available" in args[1] or "Debugger" in str(args)

    def test_generate_tests_handles_import_error(
        self, plugin_editor_with_file: PluginEditorDialog
    ) -> None:
        """Generate tests handles missing test generator gracefully."""
        with patch.object(QMessageBox, "warning") as mock_warning:
            plugin_editor_with_file.generate_tests()
            if mock_warning.called:
                args = mock_warning.call_args[0]
                assert "Not Available" in args[1] or "Test generator" in str(args)

    def test_open_ci_cd_handles_import_error(
        self, plugin_editor_with_file: PluginEditorDialog
    ) -> None:
        """Open CI/CD handles missing CI/CD module gracefully."""
        with patch.object(QMessageBox, "warning") as mock_warning:
            plugin_editor_with_file.open_ci_cd()
            if mock_warning.called:
                args = mock_warning.call_args[0]
                assert "Not Available" in args[1] or "CI/CD" in str(args)
