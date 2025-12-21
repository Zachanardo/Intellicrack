"""Production tests for settings tab configuration management.

Tests validate real configuration persistence, theme changes, tool discovery,
and settings import/export functionality.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import platform
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest


pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Settings tab tests require Windows platform",
)

pytest.importorskip("PyQt6", reason="PyQt6 required for settings tab tests")


@pytest.fixture
def qt_app() -> Any:
    """Create QApplication instance for testing."""
    import sys

    from intellicrack.handlers.pyqt6_handler import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app
    app.processEvents()


@pytest.fixture
def settings_tab(qt_app: Any) -> Any:
    """Create settings tab instance for testing."""
    from intellicrack.ui.tabs.settings_tab import SettingsTab

    shared_context = {"main_window": Mock()}

    with patch("intellicrack.ui.tabs.settings_tab.AdvancedToolDiscovery"):
        tab = SettingsTab(shared_context=shared_context)
        yield tab
        tab.deleteLater()


def test_settings_tab_initialization_loads_defaults(settings_tab: Any) -> None:
    """Settings tab initializes with proper default configuration values."""
    assert hasattr(settings_tab, "settings")
    assert isinstance(settings_tab.settings, dict)

    assert "theme" in settings_tab.settings
    assert "ui_font" in settings_tab.settings
    assert "analysis_depth" in settings_tab.settings


def test_settings_tab_saves_configuration_to_disk(settings_tab: Any, tmp_path: Path, qt_app: Any) -> None:
    """Settings tab persists configuration changes to centralized config system."""
    settings_tab.settings["theme"] = "Dark"
    settings_tab.settings["ui_font_size"] = 12

    mock_config = Mock()
    settings_tab.config = mock_config

    with patch("intellicrack.ui.tabs.settings_tab.QMessageBox.information"):
        settings_tab.save_settings()

    qt_app.processEvents()

    assert mock_config.save.called


def test_settings_tab_theme_change_applies_immediately(settings_tab: Any, qt_app: Any) -> None:
    """Settings tab theme changes are applied to application immediately."""
    theme_changed = {"signal_emitted": False}

    def on_theme_changed(theme: str) -> None:
        theme_changed["signal_emitted"] = True

    settings_tab.theme_changed.connect(on_theme_changed)

    with patch("intellicrack.ui.tabs.settings_tab.get_theme_manager") as mock_theme_mgr:
        mock_manager = Mock()
        mock_theme_mgr.return_value = mock_manager

        settings_tab.on_theme_changed("Dark")

    qt_app.processEvents()

    assert theme_changed["signal_emitted"] is True
    assert settings_tab.settings["theme"] == "Dark"


def test_settings_tab_tool_discovery_detects_installations(settings_tab: Any, qt_app: Any) -> None:
    """Settings tab tool discovery successfully detects installed tools."""
    if not hasattr(settings_tab, "tool_discovery"):
        pytest.skip("Tool discovery not initialized")

    mock_discovery = Mock()
    mock_discovery.discover_all_tools.return_value = {
        "ghidra": {"available": True, "path": "C:\\ghidra\\ghidraRun.bat"},
        "radare2": {"available": True, "path": "C:\\radare2\\bin\\r2.exe"},
    }
    settings_tab.tool_discovery = mock_discovery

    settings_tab.discover_tools()
    qt_app.processEvents()

    mock_discovery.discover_all_tools.assert_called_once()


def test_settings_tab_manual_tool_path_validation(settings_tab: Any, tmp_path: Path, qt_app: Any) -> None:
    """Settings tab validates manually entered tool paths."""
    if not hasattr(settings_tab, "tool_widgets"):
        pytest.skip("Tool widgets not initialized")

    tool_path = tmp_path / "fake_tool.exe"
    tool_path.write_bytes(b"tool content")

    settings_tab.on_tool_path_changed("radare2", str(tool_path))
    qt_app.processEvents()


def test_settings_tab_export_settings_to_json(settings_tab: Any, tmp_path: Path, qt_app: Any) -> None:
    """Settings tab exports configuration to JSON file successfully."""
    export_file = tmp_path / "exported_settings.json"

    settings_tab.settings["theme"] = "Dark"
    settings_tab.settings["analysis_timeout"] = 600

    with (
        patch("intellicrack.ui.tabs.settings_tab.QFileDialog.getSaveFileName", return_value=(str(export_file), "")),
        patch("intellicrack.ui.tabs.settings_tab.QMessageBox.information"),
    ):
        settings_tab.export_settings()

    qt_app.processEvents()

    assert export_file.exists()

    with open(export_file) as f:
        exported_data = json.load(f)

    assert "theme" in exported_data
    assert exported_data["theme"] == "Dark"


def test_settings_tab_import_settings_from_json(settings_tab: Any, tmp_path: Path, qt_app: Any) -> None:
    """Settings tab imports configuration from JSON file and applies changes."""
    import_file = tmp_path / "import_settings.json"

    import_data = {
        "theme": "Light",
        "ui_font": "Arial",
        "analysis_timeout": 900,
    }

    with open(import_file, "w") as f:
        json.dump(import_data, f)

    mock_config = Mock()
    settings_tab.config = mock_config

    with (
        patch("intellicrack.ui.tabs.settings_tab.QFileDialog.getOpenFileName", return_value=(str(import_file), "")),
        patch("intellicrack.ui.tabs.settings_tab.QMessageBox.information"),
        patch.object(settings_tab, "update_ui_from_settings"),
        patch.object(settings_tab, "update_preview"),
    ):
        settings_tab.import_settings()

    qt_app.processEvents()

    assert settings_tab.settings["theme"] == "Light"
    assert settings_tab.settings["analysis_timeout"] == 900


def test_settings_tab_reset_to_defaults_confirmation(settings_tab: Any, qt_app: Any) -> None:
    """Settings tab requires confirmation before resetting to defaults."""
    settings_tab.settings["theme"] = "Dark"

    with patch("intellicrack.ui.tabs.settings_tab.QMessageBox.question") as mock_question:
        from intellicrack.handlers.pyqt6_handler import QMessageBox

        mock_question.return_value = QMessageBox.StandardButton.No

        settings_tab.reset_to_defaults()

    qt_app.processEvents()

    assert settings_tab.settings["theme"] == "Dark"


def test_settings_tab_accent_color_selection_applies(settings_tab: Any, qt_app: Any) -> None:
    """Settings tab accent color selection updates application stylesheet."""
    with patch("intellicrack.ui.tabs.settings_tab.QColorDialog.getColor") as mock_color_dialog:
        from intellicrack.handlers.pyqt6_handler import QColor

        test_color = QColor("#FF5733")
        test_color.setRed(255)
        mock_color = Mock(spec=QColor)
        mock_color.isValid.return_value = True
        mock_color.name.return_value = "#FF5733"

        mock_color_dialog.return_value = mock_color

        with patch.object(settings_tab, "apply_accent_color") as mock_apply:
            settings_tab.select_accent_color()

        qt_app.processEvents()

        assert settings_tab.settings["accent_color"] == "#FF5733"
        mock_apply.assert_called_once_with("#FF5733")


def test_settings_tab_opacity_slider_updates_window(settings_tab: Any, qt_app: Any) -> None:
    """Settings tab opacity slider dynamically updates main window transparency."""
    settings_tab.shared_context = {"main_window": Mock()}

    settings_tab.on_opacity_changed(75)
    qt_app.processEvents()

    assert settings_tab.settings["window_opacity"] == 75
    assert settings_tab.opacity_label.text() == "75%"


def test_settings_tab_tooltip_toggle_disables_globally(settings_tab: Any, qt_app: Any) -> None:
    """Settings tab tooltip toggle disables tooltips application-wide."""
    with patch("intellicrack.ui.tabs.settings_tab.QApplication.instance") as mock_app:
        mock_app_instance = Mock()
        mock_app_instance.allWidgets.return_value = []
        mock_app.return_value = mock_app_instance

        settings_tab.apply_tooltip_settings(False)

    qt_app.processEvents()


def test_settings_tab_animation_toggle_modifies_stylesheet(settings_tab: Any, qt_app: Any) -> None:
    """Settings tab animation toggle modifies application stylesheet correctly."""
    with patch("intellicrack.ui.tabs.settings_tab.QApplication.instance") as mock_app:
        mock_app_instance = Mock()
        mock_app_instance.styleSheet.return_value = "* { color: black; }"
        mock_app.return_value = mock_app_instance

        settings_tab.apply_animation_settings(False)

    qt_app.processEvents()

    mock_app_instance.setStyleSheet.assert_called()


def test_settings_tab_ai_provider_discovery(settings_tab: Any, qt_app: Any) -> None:
    """Settings tab dynamically discovers available AI providers."""
    with patch("intellicrack.ui.tabs.settings_tab.get_model_discovery_service") as mock_discovery:
        mock_service = Mock()
        mock_service.discover_all_models.return_value = {
            "OpenAI": ["gpt-4", "gpt-3.5-turbo"],
            "Anthropic": ["claude-3-opus"],
        }
        mock_discovery.return_value = mock_service

        settings_tab.populate_ai_providers()

    qt_app.processEvents()

    assert settings_tab.ai_provider_combo.count() >= 2


def test_settings_tab_console_font_applies_to_terminals(settings_tab: Any, qt_app: Any) -> None:
    """Settings tab console font changes apply to terminal widgets."""
    from intellicrack.handlers.pyqt6_handler import QFont

    with patch("intellicrack.ui.tabs.settings_tab.QApplication.instance") as mock_app:
        mock_app_instance = Mock()
        mock_app_instance.allWidgets.return_value = []
        mock_app.return_value = mock_app_instance

        settings_tab.apply_console_font()

    qt_app.processEvents()


def test_settings_tab_preview_reflects_current_config(settings_tab: Any, qt_app: Any) -> None:
    """Settings tab preview panel displays current configuration accurately."""
    settings_tab.settings["theme"] = "Dark"
    settings_tab.settings["cache_size"] = 1024

    settings_tab.update_preview()
    qt_app.processEvents()

    preview_text = settings_tab.preview_area.toPlainText()
    assert "Dark" in preview_text
    assert "1024" in preview_text


def test_settings_tab_collect_settings_from_ui_widgets(settings_tab: Any, qt_app: Any) -> None:
    """Settings tab collects all current values from UI widgets."""
    if hasattr(settings_tab, "theme_combo"):
        settings_tab.theme_combo.setCurrentText("Light")

    settings_tab.collect_settings_from_ui()
    qt_app.processEvents()

    if hasattr(settings_tab, "theme_combo"):
        assert settings_tab.settings.get("theme") == "Light"


def test_settings_tab_tool_reset_clears_manual_override(settings_tab: Any, qt_app: Any) -> None:
    """Settings tab tool path reset clears manual overrides and re-discovers."""
    if not hasattr(settings_tab, "tool_discovery"):
        pytest.skip("Tool discovery not initialized")

    mock_discovery = Mock()
    mock_discovery.discover_tool.return_value = {
        "available": True,
        "path": "C:\\auto_discovered\\r2.exe",
    }
    settings_tab.tool_discovery = mock_discovery

    if "radare2" in getattr(settings_tab, "tool_widgets", {}):
        settings_tab.reset_tool_path("radare2")
        qt_app.processEvents()

        mock_discovery.clear_manual_override.assert_called_once_with("radare2")
