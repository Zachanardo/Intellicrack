"""
Comprehensive tests for UI manager components.

Tests StyleManager, ThemeManager, DashboardManager, and MenuUtils for
proper style application, theme switching, stats tracking, and menu operations.
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest
from PyQt6.QtWidgets import QApplication, QLabel, QMenu, QMenuBar, QProgressBar, QPushButton, QWidget

from intellicrack.ui.dashboard_manager import DashboardManager
from intellicrack.ui.menu_utils import find_or_create_menu
from intellicrack.ui.style_manager import StyleManager
from intellicrack.ui.theme_manager import ThemeManager
from tests.base_test import IntellicrackTestBase


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for testing."""
    if not QApplication.instance():
        yield QApplication(sys.argv)
    else:
        yield QApplication.instance()


class FakeApp:
    """Real test double for application instance with controlled state."""

    def __init__(self, binary_path: str | None = None) -> None:
        """Initialize fake app with optional binary path.

        Args:
            binary_path: Path to a binary file to simulate loaded state.
        """
        self.binary_path: str | None = binary_path
        self.state: dict[str, Any] = {}


class RealConfigManager:
    """Real configuration manager for testing theme persistence."""

    def __init__(self) -> None:
        """Initialize with in-memory config storage."""
        self.config_data: dict[str, Any] = {}

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with nested key support.

        Args:
            key: Configuration key (supports dot notation).
            default: Default value if key not found.

        Returns:
            Configuration value or default.
        """
        keys = key.split(".")
        current = self.config_data
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        return current

    def set(self, key: str, value: Any) -> None:
        """Set configuration value with nested key support.

        Args:
            key: Configuration key (supports dot notation).
            value: Value to set.
        """
        keys = key.split(".")
        current = self.config_data
        for k in keys[:-1]:
            if k not in current or not isinstance(current[k], dict):
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value


class TestStyleManager(IntellicrackTestBase):
    """Test StyleManager functionality with real widget styling."""

    def test_style_manager_initializes(self) -> None:
        """StyleManager initializes successfully with style mappings."""
        manager = StyleManager()
        assert manager is not None
        assert hasattr(manager, "STYLE_MAPPINGS")
        assert isinstance(manager.STYLE_MAPPINGS, dict)

    def test_style_mappings_populated(self) -> None:
        """Style mappings dictionary contains expected widget styles."""
        manager = StyleManager()
        assert len(manager.STYLE_MAPPINGS) > 0
        assert "status_success" in manager.STYLE_MAPPINGS
        assert "primary_button" in manager.STYLE_MAPPINGS
        assert "header_bold" in manager.STYLE_MAPPINGS

    def test_style_mappings_contain_all_expected_categories(self) -> None:
        """Style mappings contain all expected style categories."""
        manager = StyleManager()
        expected_categories = [
            "status_success",
            "status_error",
            "status_warning",
            "primary_button",
            "secondary_button",
            "danger_button",
            "header_bold",
            "title_large",
            "loading_progress",
            "console_output",
        ]

        for category in expected_categories:
            assert category in manager.STYLE_MAPPINGS, f"Missing style: {category}"

    def test_apply_style_sets_object_name(self, qapp: QApplication) -> None:
        """apply_style sets widget objectName for valid styles."""
        manager = StyleManager()
        widget = QWidget()

        manager.apply_style(widget, "content_panel")

        assert widget.objectName() == "contentPanel"

    def test_apply_style_with_invalid_name_logs_warning(self, qapp: QApplication) -> None:
        """apply_style handles invalid style names gracefully."""
        manager = StyleManager()
        widget = QWidget()
        original_name = widget.objectName()

        manager.apply_style(widget, "nonexistent_style_that_does_not_exist")

        assert widget.objectName() == original_name

    def test_style_label_applies_correct_object_name(self, qapp: QApplication) -> None:
        """style_label applies correct object name to QLabel."""
        manager = StyleManager()
        label = QLabel("Test Label")

        manager.style_label(label, "header_bold")

        assert label.objectName() == "headerBold"

    def test_style_label_with_multiple_styles(self, qapp: QApplication) -> None:
        """style_label correctly applies different label styles."""
        manager = StyleManager()
        styles = ["header_bold", "title_large", "subtitle", "description_text"]

        for style in styles:
            label = QLabel("Test")
            manager.style_label(label, style)
            expected_name = manager.STYLE_MAPPINGS[style]
            assert label.objectName() == expected_name

    def test_style_button_applies_correct_object_name(self, qapp: QApplication) -> None:
        """style_button applies correct object name to QPushButton."""
        manager = StyleManager()
        button = QPushButton("Test Button")

        manager.style_button(button, "primary_button")

        assert button.objectName() == "primaryButton"

    def test_style_button_with_multiple_styles(self, qapp: QApplication) -> None:
        """style_button correctly applies different button styles."""
        manager = StyleManager()
        button_styles = ["primary_button", "secondary_button", "danger_button", "accent_button"]

        for style in button_styles:
            button = QPushButton("Test")
            manager.style_button(button, style)
            expected_name = manager.STYLE_MAPPINGS[style]
            assert button.objectName() == expected_name

    def test_style_progress_applies_correct_object_name(self, qapp: QApplication) -> None:
        """style_progress applies correct object name to QProgressBar."""
        manager = StyleManager()
        progress = QProgressBar()

        manager.style_progress(progress, "loading_progress")

        assert progress.objectName() == "loadingProgress"

    def test_update_status_style_applies_correct_status(self, qapp: QApplication) -> None:
        """update_status_style applies correct status-based styling."""
        manager = StyleManager()
        label = QLabel("Status")

        manager.update_status_style(label, "success")
        assert label.objectName() == "statusSuccess"

        manager.update_status_style(label, "error")
        assert label.objectName() == "statusError"

        manager.update_status_style(label, "warning")
        assert label.objectName() == "statusWarning"

    def test_update_status_style_with_all_statuses(self, qapp: QApplication) -> None:
        """update_status_style handles all status types correctly."""
        manager = StyleManager()
        statuses = ["success", "error", "warning", "info", "neutral", "installed", "not_installed", "installing"]

        for status in statuses:
            label = QLabel("Test")
            manager.update_status_style(label, status)
            assert label.objectName() != ""

    def test_update_progress_style_applies_state_correctly(self, qapp: QApplication) -> None:
        """update_progress_style applies correct state-based styling."""
        manager = StyleManager()
        progress = QProgressBar()

        manager.update_progress_style(progress, "loading")
        assert progress.objectName() == "loadingProgress"

        manager.update_progress_style(progress, "completed")
        assert progress.objectName() == "completedProgress"

    def test_update_cpu_progress_style_based_on_usage(self, qapp: QApplication) -> None:
        """update_cpu_progress_style applies correct styling based on CPU usage."""
        manager = StyleManager()

        progress_low = QProgressBar()
        manager.update_cpu_progress_style(progress_low, 30.0)
        assert progress_low.objectName() == "cpuNormal"

        progress_medium = QProgressBar()
        manager.update_cpu_progress_style(progress_medium, 60.0)
        assert progress_medium.objectName() == "cpuMedium"

        progress_high = QProgressBar()
        manager.update_cpu_progress_style(progress_high, 85.0)
        assert progress_high.objectName() == "cpuHigh"

    def test_update_gpu_progress_style_based_on_usage(self, qapp: QApplication) -> None:
        """update_gpu_progress_style applies correct styling based on GPU usage."""
        manager = StyleManager()

        progress_low = QProgressBar()
        manager.update_gpu_progress_style(progress_low, 25.0)
        assert progress_low.objectName() == "gpuNormal"

        progress_medium = QProgressBar()
        manager.update_gpu_progress_style(progress_medium, 55.0)
        assert progress_medium.objectName() == "gpuMedium"

        progress_high = QProgressBar()
        manager.update_gpu_progress_style(progress_high, 90.0)
        assert progress_high.objectName() == "gpuHigh"

    def test_update_memory_progress_style_based_on_usage(self, qapp: QApplication) -> None:
        """update_memory_progress_style applies correct styling based on memory usage."""
        manager = StyleManager()

        progress_low = QProgressBar()
        manager.update_memory_progress_style(progress_low, 20.0)
        assert progress_low.objectName() == "cpuNormal"

        progress_high = QProgressBar()
        manager.update_memory_progress_style(progress_high, 85.0)
        assert progress_high.objectName() == "memoryHigh"

    def test_style_drop_zone_active_state(self, qapp: QApplication) -> None:
        """style_drop_zone applies correct styling for active state."""
        manager = StyleManager()
        widget = QWidget()

        manager.style_drop_zone(widget, True)
        assert widget.objectName() == "dropZoneActive"

        manager.style_drop_zone(widget, False)
        assert widget.objectName() == "dropZoneInactive"

    def test_remove_inline_styles_clears_stylesheet(self, qapp: QApplication) -> None:
        """remove_inline_styles clears widget inline stylesheet."""
        manager = StyleManager()
        widget = QWidget()
        widget.setStyleSheet("background-color: red;")

        manager.remove_inline_styles(widget)

        assert widget.styleSheet() == ""

    def test_batch_apply_styles_to_multiple_widgets(self, qapp: QApplication) -> None:
        """batch_apply_styles applies styles to multiple widgets correctly."""
        manager = StyleManager()
        label1 = QLabel("Label 1")
        label2 = QLabel("Label 2")
        button = QPushButton("Button")

        widgets_styles = {label1: "header_bold", label2: "subtitle", button: "primary_button"}

        manager.batch_apply_styles(widgets_styles)

        assert label1.objectName() == "headerBold"
        assert label2.objectName() == "subtitle"
        assert button.objectName() == "primaryButton"


class TestThemeManagerRealConfig(IntellicrackTestBase):
    """Test ThemeManager with real configuration manager."""

    def test_theme_manager_initializes_with_default_theme(self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """ThemeManager initializes with default dark theme."""
        config = RealConfigManager()
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: config)

        manager = ThemeManager()

        assert manager is not None
        assert hasattr(manager, "current_theme")
        assert manager.current_theme == "dark"

    def test_get_current_theme_returns_active_theme(self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_current_theme returns currently active theme."""
        config = RealConfigManager()
        config.set("ui_preferences.theme", "light")
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: config)

        manager = ThemeManager()
        current = manager.get_current_theme()

        assert current == "light"
        assert isinstance(current, str)

    def test_load_theme_preference_from_config(self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """load_theme_preference loads theme from config correctly."""
        config = RealConfigManager()
        config.set("ui_preferences.theme", "dark")
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: config)

        manager = ThemeManager()
        loaded_theme = manager.load_theme_preference()

        assert loaded_theme == "dark"

    def test_load_theme_preference_handles_invalid_theme_defaults_to_dark(
        self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """load_theme_preference defaults to dark for invalid theme names."""
        config = RealConfigManager()
        config.set("ui_preferences.theme", "invalid_nonexistent_theme")
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: config)

        manager = ThemeManager()
        loaded_theme = manager.load_theme_preference()

        assert loaded_theme == "dark"

    def test_load_theme_preference_normalizes_theme_variations(
        self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """load_theme_preference normalizes common theme variations."""
        config = RealConfigManager()
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: config)

        test_cases = [("black", "dark"), ("white", "light"), ("default", "dark"), ("DARK", "dark"), ("LIGHT", "light")]

        for input_theme, expected_output in test_cases:
            config.set("ui_preferences.theme", input_theme)
            manager = ThemeManager()
            loaded_theme = manager.load_theme_preference()
            assert loaded_theme == expected_output, f"Failed for input: {input_theme}"

    def test_set_theme_changes_current_theme(self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """set_theme changes current theme and persists to config."""
        config = RealConfigManager()
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: config)

        manager = ThemeManager()
        assert manager.current_theme == "dark"

        manager.set_theme("light")

        assert manager.current_theme == "light"
        assert config.get("ui_preferences.theme") == "light"

    def test_set_theme_toggles_between_themes(self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """set_theme can toggle between dark and light themes."""
        config = RealConfigManager()
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: config)

        manager = ThemeManager()
        manager.set_theme("light")
        assert manager.current_theme == "light"

        manager.set_theme("dark")
        assert manager.current_theme == "dark"

    def test_set_theme_with_invalid_theme_defaults_to_light(
        self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """set_theme handles invalid theme names by defaulting to light."""
        config = RealConfigManager()
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: config)

        manager = ThemeManager()
        manager.set_theme("nonexistent_invalid_theme")

        assert manager.current_theme == "light"

    def test_save_theme_preference_persists_to_config(self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """save_theme_preference saves current theme to config."""
        config = RealConfigManager()
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: config)

        manager = ThemeManager()
        manager.current_theme = "light"
        manager.save_theme_preference()

        assert config.get("ui_preferences.theme") == "light"

    def test_themes_dictionary_contains_theme_files(self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """themes dictionary contains theme file definitions."""
        config = RealConfigManager()
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: config)

        manager = ThemeManager()

        assert hasattr(manager, "themes")
        assert isinstance(manager.themes, dict)
        assert "dark" in manager.themes
        assert "light" in manager.themes
        assert manager.themes["dark"] == "dark_theme.qss"
        assert manager.themes["light"] == "light_theme.qss"

    def test_styles_dir_attribute_set_correctly(self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """styles_dir attribute points to correct directory."""
        config = RealConfigManager()
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: config)

        manager = ThemeManager()

        assert hasattr(manager, "styles_dir")
        assert isinstance(manager.styles_dir, str)
        assert manager.styles_dir.endswith("styles")

    def test_apply_theme_sets_application_stylesheet(self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """_apply_theme sets QApplication stylesheet with theme CSS."""
        config = RealConfigManager()
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: config)

        manager = ThemeManager()
        manager._apply_theme()

        app = QApplication.instance()
        if isinstance(app, QApplication):
            stylesheet = app.styleSheet()
            assert stylesheet != ""
            assert "QMainWindow" in stylesheet

    def test_get_builtin_dark_stylesheet_returns_valid_css(
        self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_get_builtin_dark_stylesheet returns valid CSS content."""
        config = RealConfigManager()
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: config)

        manager = ThemeManager()
        stylesheet = manager._get_builtin_dark_stylesheet()

        assert isinstance(stylesheet, str)
        assert len(stylesheet) > 0
        assert "QMainWindow" in stylesheet
        assert "background-color" in stylesheet
        assert "#1E1E1E" in stylesheet

    def test_get_builtin_light_stylesheet_returns_valid_css(
        self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_get_builtin_light_stylesheet returns valid CSS content."""
        config = RealConfigManager()
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: config)

        manager = ThemeManager()
        stylesheet = manager._get_builtin_light_stylesheet()

        assert isinstance(stylesheet, str)
        assert len(stylesheet) > 0
        assert "QMainWindow" in stylesheet
        assert "background-color" in stylesheet
        assert "#F8F8F8" in stylesheet


class TestMenuUtils(IntellicrackTestBase):
    """Test menu utility functions with real Qt menus."""

    def test_find_or_create_menu_creates_new_menu(self, qapp: QApplication) -> None:
        """find_or_create_menu creates new menu when not found."""
        menu_bar = QMenuBar()
        menu_name = "Test Menu"

        menu = find_or_create_menu(menu_bar, menu_name)

        assert menu is not None
        assert isinstance(menu, QMenu)
        assert menu.title() == menu_name

    def test_find_or_create_menu_finds_existing_menu(self, qapp: QApplication) -> None:
        """find_or_create_menu returns existing menu if found."""
        menu_bar = QMenuBar()
        menu_name = "Existing Menu"

        first_menu = menu_bar.addMenu(menu_name)
        found_menu = find_or_create_menu(menu_bar, menu_name)

        assert found_menu is not None
        assert found_menu.title() == menu_name
        assert first_menu == found_menu

    def test_find_or_create_menu_handles_multiple_menus(self, qapp: QApplication) -> None:
        """find_or_create_menu works correctly with multiple menus."""
        menu_bar = QMenuBar()

        menu1 = find_or_create_menu(menu_bar, "File")
        menu2 = find_or_create_menu(menu_bar, "Edit")
        menu3 = find_or_create_menu(menu_bar, "View")

        assert menu1.title() == "File"
        assert menu2.title() == "Edit"
        assert menu3.title() == "View"
        assert len(menu_bar.actions()) == 3

    def test_find_or_create_menu_idempotent_on_same_name(self, qapp: QApplication) -> None:
        """find_or_create_menu returns same menu when called multiple times."""
        menu_bar = QMenuBar()
        menu_name = "Tools"

        menu1 = find_or_create_menu(menu_bar, menu_name)
        menu2 = find_or_create_menu(menu_bar, menu_name)
        menu3 = find_or_create_menu(menu_bar, menu_name)

        assert menu1 == menu2 == menu3
        assert len(menu_bar.actions()) == 1


class TestDashboardManager(IntellicrackTestBase):
    """Test DashboardManager with real application state tracking."""

    def test_dashboard_manager_initializes_with_app(self) -> None:
        """DashboardManager initializes with application context."""
        app = FakeApp()
        manager = DashboardManager(app)

        assert manager is not None
        assert hasattr(manager, "app")
        assert manager.app == app
        assert hasattr(manager, "stats")
        assert hasattr(manager, "recent_activities")

    def test_get_stats_returns_dictionary(self) -> None:
        """get_stats returns statistics dictionary."""
        app = FakeApp()
        manager = DashboardManager(app)

        stats = manager.get_stats()

        assert isinstance(stats, dict)

    def test_update_stats_populates_stats_dictionary(self) -> None:
        """update_stats populates stats with all required categories."""
        app = FakeApp()
        manager = DashboardManager(app)

        manager.update_stats()
        stats = manager.get_stats()

        assert "binary" in stats
        assert "patches" in stats
        assert "analysis" in stats
        assert "licensing" in stats
        assert "advanced_analysis" in stats

    def test_update_binary_stats_with_valid_file(self, tmp_path: Path) -> None:
        """_update_binary_stats correctly processes valid binary file."""
        binary_file = tmp_path / "test.exe"
        binary_file.write_bytes(b"MZ" + b"\x00" * 1000)

        app = FakeApp(str(binary_file))
        manager = DashboardManager(app)
        manager._update_binary_stats()

        assert manager.stats["binary"] is not None
        assert manager.stats["binary"]["name"] == "test.exe"
        assert manager.stats["binary"]["size"] == 1002
        assert "KB" in manager.stats["binary"]["size_formatted"]

    def test_update_binary_stats_with_no_binary(self) -> None:
        """_update_binary_stats handles missing binary gracefully."""
        app = FakeApp()
        manager = DashboardManager(app)
        manager._update_binary_stats()

        assert manager.stats["binary"] is None

    def test_update_patch_stats_initializes_correctly(self) -> None:
        """_update_patch_stats initializes patch statistics."""
        app = FakeApp()
        manager = DashboardManager(app)
        manager._update_patch_stats()

        assert "patches" in manager.stats
        assert "applied_count" in manager.stats["patches"]
        assert "pending_count" in manager.stats["patches"]
        assert manager.stats["patches"]["applied_count"] == 0

    def test_update_analysis_stats_initializes_correctly(self) -> None:
        """_update_analysis_stats initializes analysis statistics."""
        app = FakeApp()
        manager = DashboardManager(app)
        manager._update_analysis_stats()

        assert "analysis" in manager.stats
        assert "total_analyses" in manager.stats["analysis"]
        assert "protection_detections" in manager.stats["analysis"]

    def test_update_license_stats_initializes_correctly(self) -> None:
        """_update_license_stats initializes licensing statistics."""
        app = FakeApp()
        manager = DashboardManager(app)
        manager._update_license_stats()

        assert "licensing" in manager.stats
        assert "validations_performed" in manager.stats["licensing"]
        assert "serials_generated" in manager.stats["licensing"]

    def test_update_advanced_analysis_stats_initializes_correctly(self) -> None:
        """_update_advanced_analysis_stats initializes advanced analysis statistics."""
        app = FakeApp()
        manager = DashboardManager(app)
        manager._update_advanced_analysis_stats()

        assert "advanced_analysis" in manager.stats
        assert "dynamic_analyses" in manager.stats["advanced_analysis"]
        assert "vulnerabilities_found" in manager.stats["advanced_analysis"]

    def test_get_recent_activities_returns_list(self) -> None:
        """get_recent_activities returns list of activities."""
        app = FakeApp()
        manager = DashboardManager(app)

        activities = manager.get_recent_activities()

        assert isinstance(activities, list)

    def test_add_activity_adds_to_activities_list(self) -> None:
        """add_activity adds new activity to recent activities."""
        app = FakeApp()
        manager = DashboardManager(app)

        initial_count = len(manager.get_recent_activities())
        manager.add_activity("analysis", "Completed static analysis of binary.exe")
        new_count = len(manager.get_recent_activities())

        assert new_count == initial_count + 1

    def test_add_activity_includes_timestamp(self) -> None:
        """add_activity includes timestamp in activity record."""
        app = FakeApp()
        manager = DashboardManager(app)

        manager.add_activity("patch", "Applied license bypass patch")
        activities = manager.get_recent_activities()

        assert len(activities) > 0
        latest = activities[0]
        assert "timestamp" in latest
        assert "type" in latest
        assert "description" in latest
        assert latest["type"] == "patch"

    def test_add_activity_with_different_types(self) -> None:
        """add_activity handles different activity types correctly."""
        app = FakeApp()
        manager = DashboardManager(app)

        activity_types = ["analysis", "patch", "exploit", "scan", "keygen"]
        for activity_type in activity_types:
            manager.add_activity(activity_type, f"Test {activity_type} activity")

        activities = manager.get_recent_activities()
        assert len(activities) == len(activity_types)

        activity_type_set = {act["type"] for act in activities}
        assert activity_type_set == set(activity_types)

    def test_add_activity_respects_max_activities_limit(self) -> None:
        """add_activity respects maximum activities limit."""
        app = FakeApp()
        manager = DashboardManager(app)
        manager.max_recent_activities = 5

        for i in range(10):
            manager.add_activity("test", f"Activity {i}")

        activities = manager.get_recent_activities()
        assert len(activities) == 5

    def test_add_activity_maintains_chronological_order(self) -> None:
        """add_activity maintains newest-first chronological order."""
        app = FakeApp()
        manager = DashboardManager(app)

        manager.add_activity("first", "First activity")
        manager.add_activity("second", "Second activity")
        manager.add_activity("third", "Third activity")

        activities = manager.get_recent_activities()
        assert activities[0]["description"] == "Third activity"
        assert activities[1]["description"] == "Second activity"
        assert activities[2]["description"] == "First activity"

    def test_format_size_formats_bytes_correctly(self) -> None:
        """_format_size formats byte sizes to human readable strings."""
        app = FakeApp()
        manager = DashboardManager(app)

        assert manager._format_size(100) == "100.00 B"
        assert "KB" in manager._format_size(2048)
        assert "MB" in manager._format_size(2 * 1024 * 1024)
        assert "GB" in manager._format_size(3 * 1024 * 1024 * 1024)

    def test_export_stats_creates_json_file(self, tmp_path: Path) -> None:
        """export_stats creates valid JSON file with statistics."""
        app = FakeApp()
        manager = DashboardManager(app)
        manager.update_stats()
        manager.add_activity("test", "Test activity")

        export_path = tmp_path / "stats.json"
        result = manager.export_stats(str(export_path))

        assert result is True
        assert export_path.exists()

        with open(export_path, encoding="utf-8") as f:
            data = json.load(f)

        assert "timestamp" in data
        assert "statistics" in data
        assert "recent_activities" in data

    def test_export_stats_contains_complete_data(self, tmp_path: Path) -> None:
        """export_stats includes all statistics and activities."""
        app = FakeApp()
        manager = DashboardManager(app)
        manager.update_stats()
        manager.add_activity("analysis", "Test analysis")
        manager.add_activity("patch", "Test patch")

        export_path = tmp_path / "complete_stats.json"
        manager.export_stats(str(export_path))

        with open(export_path, encoding="utf-8") as f:
            data = json.load(f)

        assert len(data["recent_activities"]) == 2
        assert "binary" in data["statistics"]
        assert "patches" in data["statistics"]

    def test_export_stats_handles_invalid_path(self) -> None:
        """export_stats returns False for invalid export paths."""
        app = FakeApp()
        manager = DashboardManager(app)

        result = manager.export_stats("/invalid/nonexistent/directory/stats.json")

        assert result is False


class TestStyleManagerEdgeCases(IntellicrackTestBase):
    """Test StyleManager edge cases and error handling."""

    def test_apply_style_with_none_widget_raises_error(self) -> None:
        """apply_style with None widget raises AttributeError."""
        manager = StyleManager()

        with pytest.raises(AttributeError):
            manager.apply_style(None, "header_bold")  # type: ignore

    def test_update_status_style_with_unknown_status_uses_neutral(self, qapp: QApplication) -> None:
        """update_status_style with unknown status defaults to neutral."""
        manager = StyleManager()
        label = QLabel("Status")

        manager.update_status_style(label, "unknown_status_type")

        assert label.objectName() == "statusNeutral"

    def test_update_progress_style_with_unknown_state_does_nothing(self, qapp: QApplication) -> None:
        """update_progress_style with unknown state doesn't crash."""
        manager = StyleManager()
        progress = QProgressBar()
        original_name = progress.objectName()

        manager.update_progress_style(progress, "unknown_state")

        assert progress.objectName() == original_name

    def test_batch_apply_styles_with_empty_dict(self, qapp: QApplication) -> None:
        """batch_apply_styles handles empty widget dictionary."""
        manager = StyleManager()

        manager.batch_apply_styles({})


class TestDashboardManagerEdgeCases(IntellicrackTestBase):
    """Test DashboardManager edge cases and error handling."""

    def test_add_activity_with_empty_description(self) -> None:
        """add_activity handles empty description correctly."""
        app = FakeApp()
        manager = DashboardManager(app)

        manager.add_activity("analysis", "")
        activities = manager.get_recent_activities()

        assert len(activities) == 1
        assert activities[0]["description"] == ""

    def test_add_activity_with_very_long_description(self) -> None:
        """add_activity handles very long descriptions."""
        app = FakeApp()
        manager = DashboardManager(app)

        long_desc = "A" * 10000
        manager.add_activity("analysis", long_desc)
        activities = manager.get_recent_activities()

        assert len(activities) == 1
        assert activities[0]["description"] == long_desc

    def test_update_stats_without_app_attributes(self) -> None:
        """update_stats handles app without expected attributes."""
        app = FakeApp()
        manager = DashboardManager(app)

        manager.update_stats()

        assert isinstance(manager.stats, dict)
        assert manager.stats["binary"] is None

    def test_format_size_with_zero_bytes(self) -> None:
        """_format_size handles zero bytes correctly."""
        app = FakeApp()
        manager = DashboardManager(app)

        result = manager._format_size(0)

        assert result == "0.00 B"

    def test_format_size_with_very_large_values(self) -> None:
        """_format_size handles very large byte values."""
        app = FakeApp()
        manager = DashboardManager(app)

        result = manager._format_size(10 * 1024**4)

        assert "TB" in result
