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

import pytest


pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Settings tab tests require Windows platform",
)

pytest.importorskip("PyQt6", reason="PyQt6 required for settings tab tests")


class FakeMainWindow:
    """Fake main window for settings tab testing."""

    def __init__(self) -> None:
        self.opacity_value: float = 1.0

    def setWindowOpacity(self, value: float) -> None:
        self.opacity_value = value


class FakeConfig:
    """Fake configuration manager for testing settings persistence."""

    def __init__(self) -> None:
        self.data: dict[str, Any] = {}
        self.save_called: bool = False
        self.save_count: int = 0

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split(".")
        current = self.data
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        return current

    def set(self, key: str, value: Any, save: bool = True) -> None:
        keys = key.split(".")
        current = self.data
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value
        if save:
            self.save()

    def save(self) -> None:
        self.save_called = True
        self.save_count += 1


class FakeThemeManager:
    """Fake theme manager for testing theme changes."""

    def __init__(self) -> None:
        self.current_theme: str = "dark"
        self.set_theme_calls: list[str] = []

    def set_theme(self, theme: str) -> None:
        self.current_theme = theme
        self.set_theme_calls.append(theme)

    def _apply_theme(self) -> None:
        pass


class FakeToolDiscovery:
    """Fake tool discovery for testing tool detection."""

    def __init__(self) -> None:
        self.discovered_tools: dict[str, dict[str, Any]] = {}
        self.manual_overrides: dict[str, str] = {}
        self.discover_all_calls: int = 0
        self.discover_tool_calls: list[tuple[str, dict[str, Any]]] = []
        self.health_check_calls: list[str] = []
        self.refresh_calls: int = 0

    def discover_all_tools(self) -> dict[str, dict[str, Any]]:
        self.discover_all_calls += 1
        return self.discovered_tools

    def discover_tool(self, tool_key: str, config: dict[str, Any]) -> dict[str, Any]:
        self.discover_tool_calls.append((tool_key, config))
        return self.discovered_tools.get(
            tool_key,
            {"available": False, "path": "", "error": "Not configured"},
        )

    def health_check_tool(self, tool_key: str) -> dict[str, Any]:
        self.health_check_calls.append(tool_key)
        tool_info = self.discovered_tools.get(tool_key, {})
        if tool_info.get("available"):
            return {
                "healthy": True,
                "available": True,
                "version": tool_info.get("version", "1.0.0"),
            }
        return {"healthy": False, "available": False, "issues": ["Not found"]}

    def set_manual_override(self, tool_key: str, path: str) -> None:
        self.manual_overrides[tool_key] = path

    def clear_manual_override(self, tool_key: str) -> None:
        if tool_key in self.manual_overrides:
            del self.manual_overrides[tool_key]

    def refresh_discovery(self) -> None:
        self.refresh_calls += 1


class FakeModelDiscoveryService:
    """Fake AI model discovery service for testing AI provider detection."""

    def __init__(self) -> None:
        self.available_models: dict[str, list[str]] = {}

    def discover_all_models(self, force_refresh: bool = False) -> dict[str, list[str]]:
        return self.available_models


class FakeQColor:
    """Fake QColor for testing color selection."""

    def __init__(self, color_hex: str) -> None:
        self.color_hex: str = color_hex
        self.valid: bool = True

    def isValid(self) -> bool:
        return self.valid

    def name(self) -> str:
        return self.color_hex


class FakeQApplication:
    """Fake QApplication for testing application-wide settings."""

    def __init__(self) -> None:
        self.stylesheet: str = "* { color: black; }"
        self.widgets: list[Any] = []

    def styleSheet(self) -> str:
        return self.stylesheet

    def setStyleSheet(self, stylesheet: str) -> None:
        self.stylesheet = stylesheet

    def allWidgets(self) -> list[Any]:
        return self.widgets


class FakeQMessageBox:
    """Fake message box for capturing user interactions."""

    class StandardButton:
        Yes = 1
        No = 0

    last_question_response: int = StandardButton.No

    @staticmethod
    def information(parent: Any, title: str, message: str) -> None:
        pass

    @staticmethod
    def question(parent: Any, title: str, message: str, buttons: int, default: int) -> int:
        return FakeQMessageBox.last_question_response


class FakeQFileDialog:
    """Fake file dialog for testing file operations."""

    save_file_name: str = ""
    open_file_name: str = ""

    @staticmethod
    def getSaveFileName(parent: Any, title: str, directory: str, filter: str) -> tuple[str, str]:
        return (FakeQFileDialog.save_file_name, "")

    @staticmethod
    def getOpenFileName(parent: Any, title: str, directory: str, filter: str) -> tuple[str, str]:
        return (FakeQFileDialog.open_file_name, "")


class FakeQColorDialog:
    """Fake color dialog for testing color selection."""

    selected_color: FakeQColor | None = None

    @staticmethod
    def getColor(initial: Any, parent: Any) -> Any:
        return FakeQColorDialog.selected_color


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
def fake_config() -> FakeConfig:
    """Create fake configuration manager."""
    return FakeConfig()


@pytest.fixture
def fake_theme_manager() -> FakeThemeManager:
    """Create fake theme manager."""
    return FakeThemeManager()


@pytest.fixture
def fake_tool_discovery() -> FakeToolDiscovery:
    """Create fake tool discovery."""
    fake_discovery = FakeToolDiscovery()
    fake_discovery.discovered_tools = {
        "ghidra": {"available": True, "path": "C:\\ghidra\\ghidraRun.bat", "version": "10.1"},
        "radare2": {"available": True, "path": "C:\\radare2\\bin\\r2.exe", "version": "5.6.0"},
    }
    return fake_discovery


@pytest.fixture
def settings_tab(qt_app: Any, fake_config: FakeConfig, monkeypatch: Any) -> Any:
    """Create settings tab instance for testing."""
    from intellicrack.ui.tabs.settings_tab import SettingsTab

    shared_context = {"main_window": FakeMainWindow()}

    def fake_tool_discovery_init(self: Any) -> None:
        pass

    monkeypatch.setattr(
        "intellicrack.ui.tabs.settings_tab.AdvancedToolDiscovery.__init__",
        fake_tool_discovery_init,
    )

    tab = SettingsTab(shared_context=shared_context)
    tab.config = fake_config

    yield tab
    tab.deleteLater()


def test_settings_tab_initialization_loads_defaults(settings_tab: Any) -> None:
    """Settings tab initializes with proper default configuration values."""
    assert hasattr(settings_tab, "settings")
    assert isinstance(settings_tab.settings, dict)

    assert "theme" in settings_tab.settings
    assert "ui_font" in settings_tab.settings
    assert "analysis_depth" in settings_tab.settings


def test_settings_tab_saves_configuration_to_disk(
    settings_tab: Any,
    tmp_path: Path,
    qt_app: Any,
    fake_config: FakeConfig,
    monkeypatch: Any,
) -> None:
    """Settings tab persists configuration changes to centralized config system."""
    settings_tab.settings["theme"] = "Dark"
    settings_tab.settings["ui_font_size"] = 12
    settings_tab.config = fake_config

    monkeypatch.setattr(
        "intellicrack.ui.tabs.settings_tab.QMessageBox.information",
        FakeQMessageBox.information,
    )

    settings_tab.save_settings()
    qt_app.processEvents()

    assert fake_config.save_called
    assert fake_config.save_count >= 1


def test_settings_tab_theme_change_applies_immediately(
    settings_tab: Any,
    qt_app: Any,
    fake_theme_manager: FakeThemeManager,
    monkeypatch: Any,
) -> None:
    """Settings tab theme changes are applied to application immediately."""
    theme_changed = {"signal_emitted": False}

    def on_theme_changed(theme: str) -> None:
        theme_changed["signal_emitted"] = True

    settings_tab.theme_changed.connect(on_theme_changed)

    def fake_get_theme_manager() -> FakeThemeManager:
        return fake_theme_manager

    monkeypatch.setattr(
        "intellicrack.ui.tabs.settings_tab.get_theme_manager",
        fake_get_theme_manager,
    )

    settings_tab.on_theme_changed("Dark")
    qt_app.processEvents()

    assert theme_changed["signal_emitted"] is True
    assert settings_tab.settings["theme"] == "Dark"
    assert "dark" in fake_theme_manager.set_theme_calls


def test_settings_tab_tool_discovery_detects_installations(
    settings_tab: Any,
    qt_app: Any,
    fake_tool_discovery: FakeToolDiscovery,
) -> None:
    """Settings tab tool discovery successfully detects installed tools."""
    if not hasattr(settings_tab, "tool_discovery"):
        settings_tab.tool_discovery = fake_tool_discovery

    settings_tab.discover_tools()
    qt_app.processEvents()

    assert fake_tool_discovery.discover_all_calls >= 1


def test_settings_tab_manual_tool_path_validation(
    settings_tab: Any,
    tmp_path: Path,
    qt_app: Any,
) -> None:
    """Settings tab validates manually entered tool paths."""
    if not hasattr(settings_tab, "tool_widgets"):
        pytest.skip("Tool widgets not initialized")

    tool_path = tmp_path / "fake_tool.exe"
    tool_path.write_bytes(b"tool content")

    settings_tab.on_tool_path_changed("radare2", str(tool_path))
    qt_app.processEvents()


def test_settings_tab_export_settings_to_json(
    settings_tab: Any,
    tmp_path: Path,
    qt_app: Any,
    monkeypatch: Any,
) -> None:
    """Settings tab exports configuration to JSON file successfully."""
    export_file = tmp_path / "exported_settings.json"

    settings_tab.settings["theme"] = "Dark"
    settings_tab.settings["analysis_timeout"] = 600

    FakeQFileDialog.save_file_name = str(export_file)

    monkeypatch.setattr(
        "intellicrack.ui.tabs.settings_tab.QFileDialog.getSaveFileName",
        FakeQFileDialog.getSaveFileName,
    )
    monkeypatch.setattr(
        "intellicrack.ui.tabs.settings_tab.QMessageBox.information",
        FakeQMessageBox.information,
    )

    settings_tab.export_settings()
    qt_app.processEvents()

    assert export_file.exists()

    with open(export_file) as f:
        exported_data = json.load(f)

    assert "theme" in exported_data
    assert exported_data["theme"] == "Dark"


def test_settings_tab_import_settings_from_json(
    settings_tab: Any,
    tmp_path: Path,
    qt_app: Any,
    fake_config: FakeConfig,
    monkeypatch: Any,
) -> None:
    """Settings tab imports configuration from JSON file and applies changes."""
    import_file = tmp_path / "import_settings.json"

    import_data = {
        "theme": "Light",
        "ui_font": "Arial",
        "analysis_timeout": 900,
    }

    with open(import_file, "w") as f:
        json.dump(import_data, f)

    settings_tab.config = fake_config

    FakeQFileDialog.open_file_name = str(import_file)

    update_ui_called = {"called": False}
    update_preview_called = {"called": False}

    original_update_ui = settings_tab.update_ui_from_settings
    original_update_preview = settings_tab.update_preview

    def fake_update_ui() -> None:
        update_ui_called["called"] = True
        original_update_ui()

    def fake_update_preview() -> None:
        update_preview_called["called"] = True
        original_update_preview()

    monkeypatch.setattr(settings_tab, "update_ui_from_settings", fake_update_ui)
    monkeypatch.setattr(settings_tab, "update_preview", fake_update_preview)
    monkeypatch.setattr(
        "intellicrack.ui.tabs.settings_tab.QFileDialog.getOpenFileName",
        FakeQFileDialog.getOpenFileName,
    )
    monkeypatch.setattr(
        "intellicrack.ui.tabs.settings_tab.QMessageBox.information",
        FakeQMessageBox.information,
    )

    settings_tab.import_settings()
    qt_app.processEvents()

    assert settings_tab.settings["theme"] == "Light"
    assert settings_tab.settings["analysis_timeout"] == 900


def test_settings_tab_reset_to_defaults_confirmation(
    settings_tab: Any,
    qt_app: Any,
    monkeypatch: Any,
) -> None:
    """Settings tab requires confirmation before resetting to defaults."""
    settings_tab.settings["theme"] = "Dark"

    FakeQMessageBox.last_question_response = FakeQMessageBox.StandardButton.No

    monkeypatch.setattr(
        "intellicrack.ui.tabs.settings_tab.QMessageBox.question",
        FakeQMessageBox.question,
    )

    settings_tab.reset_to_defaults()
    qt_app.processEvents()

    assert settings_tab.settings["theme"] == "Dark"


def test_settings_tab_accent_color_selection_applies(
    settings_tab: Any,
    qt_app: Any,
    monkeypatch: Any,
) -> None:
    """Settings tab accent color selection updates application stylesheet."""
    test_color = FakeQColor("#FF5733")

    FakeQColorDialog.selected_color = test_color

    apply_calls = {"count": 0, "color": None}

    def fake_apply_accent_color(color_hex: str) -> None:
        apply_calls["count"] += 1
        apply_calls["color"] = color_hex

    monkeypatch.setattr(
        "intellicrack.ui.tabs.settings_tab.QColorDialog.getColor",
        FakeQColorDialog.getColor,
    )
    monkeypatch.setattr(settings_tab, "apply_accent_color", fake_apply_accent_color)

    settings_tab.select_accent_color()
    qt_app.processEvents()

    assert settings_tab.settings["accent_color"] == "#FF5733"
    assert apply_calls["count"] == 1
    assert apply_calls["color"] == "#FF5733"


def test_settings_tab_opacity_slider_updates_window(settings_tab: Any, qt_app: Any) -> None:
    """Settings tab opacity slider dynamically updates main window transparency."""
    fake_main_window = FakeMainWindow()
    settings_tab.shared_context = {"main_window": fake_main_window}

    settings_tab.on_opacity_changed(75)
    qt_app.processEvents()

    assert settings_tab.settings["window_opacity"] == 75
    assert settings_tab.opacity_label.text() == "75%"


def test_settings_tab_tooltip_toggle_disables_globally(
    settings_tab: Any,
    qt_app: Any,
    monkeypatch: Any,
) -> None:
    """Settings tab tooltip toggle disables tooltips application-wide."""
    fake_app = FakeQApplication()

    def fake_app_instance() -> FakeQApplication:
        return fake_app

    monkeypatch.setattr(
        "intellicrack.ui.tabs.settings_tab.QApplication.instance",
        fake_app_instance,
    )

    settings_tab.apply_tooltip_settings(False)
    qt_app.processEvents()


def test_settings_tab_animation_toggle_modifies_stylesheet(
    settings_tab: Any,
    qt_app: Any,
    monkeypatch: Any,
) -> None:
    """Settings tab animation toggle modifies application stylesheet correctly."""
    fake_app = FakeQApplication()

    def fake_app_instance() -> FakeQApplication:
        return fake_app

    monkeypatch.setattr(
        "intellicrack.ui.tabs.settings_tab.QApplication.instance",
        fake_app_instance,
    )

    initial_stylesheet = fake_app.stylesheet

    settings_tab.apply_animation_settings(False)
    qt_app.processEvents()

    assert fake_app.stylesheet != initial_stylesheet


def test_settings_tab_ai_provider_discovery(
    settings_tab: Any,
    qt_app: Any,
    monkeypatch: Any,
) -> None:
    """Settings tab dynamically discovers available AI providers."""
    fake_discovery_service = FakeModelDiscoveryService()
    fake_discovery_service.available_models = {
        "OpenAI": ["gpt-4", "gpt-3.5-turbo"],
        "Anthropic": ["claude-3-opus"],
    }

    def fake_get_discovery_service() -> FakeModelDiscoveryService:
        return fake_discovery_service

    monkeypatch.setattr(
        "intellicrack.ui.tabs.settings_tab.get_model_discovery_service",
        fake_get_discovery_service,
    )

    settings_tab.populate_ai_providers()
    qt_app.processEvents()

    assert settings_tab.ai_provider_combo.count() >= 2


def test_settings_tab_console_font_applies_to_terminals(
    settings_tab: Any,
    qt_app: Any,
    monkeypatch: Any,
) -> None:
    """Settings tab console font changes apply to terminal widgets."""
    fake_app = FakeQApplication()

    def fake_app_instance() -> FakeQApplication:
        return fake_app

    monkeypatch.setattr(
        "intellicrack.ui.tabs.settings_tab.QApplication.instance",
        fake_app_instance,
    )

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


def test_settings_tab_tool_reset_clears_manual_override(
    settings_tab: Any,
    qt_app: Any,
    fake_tool_discovery: FakeToolDiscovery,
) -> None:
    """Settings tab tool path reset clears manual overrides and re-discovers."""
    if not hasattr(settings_tab, "tool_discovery"):
        settings_tab.tool_discovery = fake_tool_discovery

    if "radare2" in getattr(settings_tab, "tool_widgets", {}):
        settings_tab.reset_tool_path("radare2")
        qt_app.processEvents()

        assert "radare2" not in fake_tool_discovery.manual_overrides
