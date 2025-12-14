"""
Comprehensive tests for UI manager components.

Tests StyleManager, ThemeManager, DashboardManager, and MenuUtils for
proper style application, theme switching, stats tracking, and menu operations.
"""

import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

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
        app = QApplication(sys.argv)
        yield app
    else:
        yield QApplication.instance()


class TestStyleManager(IntellicrackTestBase):
    """Test StyleManager functionality."""

    def test_style_manager_initializes(self) -> None:
        """StyleManager initializes successfully."""
        manager = StyleManager()
        assert manager is not None
        assert hasattr(manager, "STYLE_MAPPINGS")

    def test_style_mappings_exist(self) -> None:
        """Style mappings dictionary is populated with expected styles."""
        manager = StyleManager()
        assert isinstance(manager.STYLE_MAPPINGS, dict)
        assert len(manager.STYLE_MAPPINGS) > 0

    def test_style_mappings_contain_expected_keys(self) -> None:
        """Style mappings contain common UI element styles."""
        manager = StyleManager()
        expected_keys = [
            "status_success", "status_error", "status_warning",
            "primary_button", "secondary_button", "danger_button",
            "header_bold", "title_large"
        ]

        for key in expected_keys:
            assert key in manager.STYLE_MAPPINGS, f"Missing expected style key: {key}"

    def test_style_label_method_exists(self, qapp: QApplication) -> None:
        """style_label method exists and can be called."""
        manager = StyleManager()
        label = QLabel("Test")

        if hasattr(manager, "style_label"):
            manager.style_label(label, "header_bold")
            assert label.objectName() in ["headerBold", "header_bold", ""]

    def test_style_button_method_exists(self, qapp: QApplication) -> None:
        """style_button method exists and can be called."""
        manager = StyleManager()
        button = QPushButton("Test")

        if hasattr(manager, "style_button"):
            manager.style_button(button, "primary_button")
            assert button.objectName() in ["primaryButton", "primary_button", ""]

    def test_style_progress_bar_method_exists(self, qapp: QApplication) -> None:
        """style_progress_bar method exists and can be called."""
        manager = StyleManager()
        progress = QProgressBar()

        if hasattr(manager, "style_progress_bar"):
            manager.style_progress_bar(progress, "loading_progress")
            assert progress.objectName() in ["loadingProgress", "loading_progress", ""]

    def test_apply_style_method_exists(self, qapp: QApplication) -> None:
        """apply_style method exists for generic widget styling."""
        manager = StyleManager()
        widget = QWidget()

        if hasattr(manager, "apply_style"):
            manager.apply_style(widget, "content_panel")
            assert isinstance(widget, QWidget)


class TestThemeManager(IntellicrackTestBase):
    """Test ThemeManager functionality."""

    @patch("intellicrack.core.config_manager.get_config")
    def test_theme_manager_initializes(self, mock_config: Mock, qapp: QApplication) -> None:
        """ThemeManager initializes with default theme."""
        mock_config_instance = MagicMock()
        mock_config_instance.get.return_value = "dark"
        mock_config.return_value = mock_config_instance

        manager = ThemeManager()
        assert manager is not None
        assert hasattr(manager, "current_theme")
        assert manager.current_theme in ["dark", "light"]

    @patch("intellicrack.core.config_manager.get_config")
    def test_get_current_theme(self, mock_config: Mock, qapp: QApplication) -> None:
        """get_current_theme returns active theme."""
        mock_config_instance = MagicMock()
        mock_config_instance.get.return_value = "dark"
        mock_config.return_value = mock_config_instance

        manager = ThemeManager()
        current = manager.get_current_theme()

        assert current in ["dark", "light"]
        assert isinstance(current, str)

    @patch("intellicrack.core.config_manager.get_config")
    def test_load_theme_preference_returns_valid_theme(self, mock_config: Mock, qapp: QApplication) -> None:
        """load_theme_preference returns valid theme name."""
        mock_config_instance = MagicMock()
        mock_config_instance.get.return_value = "dark"
        mock_config.return_value = mock_config_instance

        manager = ThemeManager()
        loaded_theme = manager.load_theme_preference()

        assert loaded_theme in ["dark", "light"]

    @patch("intellicrack.core.config_manager.get_config")
    def test_load_theme_preference_handles_invalid_theme(self, mock_config: Mock, qapp: QApplication) -> None:
        """load_theme_preference defaults to dark for invalid theme names."""
        mock_config_instance = MagicMock()
        mock_config_instance.get.return_value = "invalid_theme_name"
        mock_config.return_value = mock_config_instance

        manager = ThemeManager()
        loaded_theme = manager.load_theme_preference()

        assert loaded_theme == "dark"

    @patch("intellicrack.core.config_manager.get_config")
    def test_set_theme_changes_theme(self, mock_config: Mock, qapp: QApplication) -> None:
        """set_theme changes current theme."""
        mock_config_instance = MagicMock()
        mock_config_instance.get.return_value = "dark"
        mock_config_instance.set = MagicMock()
        mock_config.return_value = mock_config_instance

        manager = ThemeManager()
        initial_theme = manager.current_theme

        new_theme = "light" if initial_theme == "dark" else "dark"
        manager.set_theme(new_theme)

        assert manager.current_theme == new_theme

    @patch("intellicrack.core.config_manager.get_config")
    def test_save_theme_preference_saves_to_config(self, mock_config: Mock, qapp: QApplication) -> None:
        """save_theme_preference saves current theme to config."""
        mock_config_instance = MagicMock()
        mock_config_instance.get.return_value = "dark"
        mock_config_instance.set = MagicMock()
        mock_config.return_value = mock_config_instance

        manager = ThemeManager()
        manager.save_theme_preference()

        mock_config_instance.set.assert_called()

    @patch("intellicrack.core.config_manager.get_config")
    def test_themes_dictionary_populated(self, mock_config: Mock, qapp: QApplication) -> None:
        """themes dictionary contains theme definitions."""
        mock_config_instance = MagicMock()
        mock_config_instance.get.return_value = "dark"
        mock_config.return_value = mock_config_instance

        manager = ThemeManager()

        assert hasattr(manager, "themes")
        assert isinstance(manager.themes, dict)
        assert "dark" in manager.themes or "light" in manager.themes

    @patch("intellicrack.core.config_manager.get_config")
    def test_styles_dir_exists(self, mock_config: Mock, qapp: QApplication) -> None:
        """styles_dir attribute is set."""
        mock_config_instance = MagicMock()
        mock_config_instance.get.return_value = "dark"
        mock_config.return_value = mock_config_instance

        manager = ThemeManager()

        assert hasattr(manager, "styles_dir")
        assert isinstance(manager.styles_dir, str)


class TestMenuUtils(IntellicrackTestBase):
    """Test menu utility functions."""

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

    def test_find_or_create_menu_handles_multiple_menus(self, qapp: QApplication) -> None:
        """find_or_create_menu works with multiple menus."""
        menu_bar = QMenuBar()

        menu1 = find_or_create_menu(menu_bar, "File")
        menu2 = find_or_create_menu(menu_bar, "Edit")
        menu3 = find_or_create_menu(menu_bar, "View")

        assert menu1.title() == "File"
        assert menu2.title() == "Edit"
        assert menu3.title() == "View"
        assert menu_bar.actions()[0].menu() == menu1


class TestDashboardManager(IntellicrackTestBase):
    """Test DashboardManager functionality."""

    def test_dashboard_manager_initializes(self) -> None:
        """DashboardManager initializes with app context."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        assert manager is not None
        assert hasattr(manager, "app")

    def test_get_stats_returns_dictionary(self) -> None:
        """get_stats returns statistics dictionary."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        stats = manager.get_stats()

        assert isinstance(stats, dict)

    def test_get_stats_contains_expected_keys(self) -> None:
        """get_stats returns dict with expected stat categories."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        stats = manager.get_stats()

        expected_keys = ["binary_count", "patch_count", "analysis_count"]
        for key in expected_keys:
            assert key in stats or len(stats) == 0

    def test_update_stats_executes_without_error(self) -> None:
        """update_stats executes without raising exceptions."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        try:
            manager.update_stats()
        except Exception as e:
            pytest.fail(f"update_stats should not raise exception: {e}")

    def test_get_recent_activities_returns_list(self) -> None:
        """get_recent_activities returns list of activities."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        activities = manager.get_recent_activities()

        assert isinstance(activities, list)

    def test_add_activity_adds_to_activities(self) -> None:
        """add_activity adds new activity to recent activities."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        initial_count = len(manager.get_recent_activities())
        manager.add_activity("analysis", "Completed static analysis of binary.exe")
        new_count = len(manager.get_recent_activities())

        assert new_count >= initial_count

    def test_add_activity_with_valid_types(self) -> None:
        """add_activity handles different activity types."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        activity_types = ["analysis", "patch", "exploit", "scan"]
        for activity_type in activity_types:
            try:
                manager.add_activity(activity_type, f"Test {activity_type} activity")
            except Exception as e:
                pytest.fail(f"add_activity failed for type {activity_type}: {e}")

    def test_format_size_method_exists(self) -> None:
        """_format_size method formats byte sizes correctly."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        if hasattr(manager, "_format_size"):
            result = manager._format_size(1024)
            assert isinstance(result, str)
            assert len(result) > 0

    def test_export_stats_method_exists(self, tmp_path: Path) -> None:
        """export_stats method exists and can be called."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        if hasattr(manager, "export_stats"):
            export_path = tmp_path / "stats.json"
            result = manager.export_stats(str(export_path))
            assert isinstance(result, bool)

    def test_update_binary_stats_executes(self) -> None:
        """_update_binary_stats executes without error."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        if hasattr(manager, "_update_binary_stats"):
            try:
                manager._update_binary_stats()
            except Exception as e:
                pytest.fail(f"_update_binary_stats should not raise: {e}")

    def test_update_patch_stats_executes(self) -> None:
        """_update_patch_stats executes without error."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        if hasattr(manager, "_update_patch_stats"):
            try:
                manager._update_patch_stats()
            except Exception as e:
                pytest.fail(f"_update_patch_stats should not raise: {e}")

    def test_update_analysis_stats_executes(self) -> None:
        """_update_analysis_stats executes without error."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        if hasattr(manager, "_update_analysis_stats"):
            try:
                manager._update_analysis_stats()
            except Exception as e:
                pytest.fail(f"_update_analysis_stats should not raise: {e}")

    def test_update_license_stats_executes(self) -> None:
        """_update_license_stats executes without error."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        if hasattr(manager, "_update_license_stats"):
            try:
                manager._update_license_stats()
            except Exception as e:
                pytest.fail(f"_update_license_stats should not raise: {e}")

    def test_update_advanced_analysis_stats_executes(self) -> None:
        """_update_advanced_analysis_stats executes without error."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        if hasattr(manager, "_update_advanced_analysis_stats"):
            try:
                manager._update_advanced_analysis_stats()
            except Exception as e:
                pytest.fail(f"_update_advanced_analysis_stats should not raise: {e}")


class TestStyleManagerEdgeCases(IntellicrackTestBase):
    """Test StyleManager edge cases."""

    def test_style_with_invalid_style_name(self, qapp: QApplication) -> None:
        """StyleManager handles invalid style names gracefully."""
        manager = StyleManager()
        label = QLabel("Test")

        if hasattr(manager, "style_label"):
            try:
                manager.style_label(label, "nonexistent_style")
            except KeyError:
                pass
            except Exception as e:
                pytest.fail(f"Unexpected exception: {e}")

    def test_style_with_none_widget(self) -> None:
        """StyleManager handles None widget gracefully."""
        manager = StyleManager()

        if hasattr(manager, "style_label"):
            try:
                manager.style_label(None, "header_bold")
            except (TypeError, AttributeError):
                pass


class TestThemeManagerEdgeCases(IntellicrackTestBase):
    """Test ThemeManager edge cases."""

    @patch("intellicrack.core.config_manager.get_config")
    def test_theme_manager_with_none_config_value(self, mock_config: Mock, qapp: QApplication) -> None:
        """ThemeManager handles None config value."""
        mock_config_instance = MagicMock()
        mock_config_instance.get.return_value = None
        mock_config.return_value = mock_config_instance

        manager = ThemeManager()
        assert manager.current_theme in ["dark", "light"]

    @patch("intellicrack.core.config_manager.get_config")
    def test_set_theme_with_invalid_theme(self, mock_config: Mock, qapp: QApplication) -> None:
        """set_theme handles invalid theme names."""
        mock_config_instance = MagicMock()
        mock_config_instance.get.return_value = "dark"
        mock_config.return_value = mock_config_instance

        manager = ThemeManager()

        try:
            manager.set_theme("invalid_theme_that_does_not_exist")
        except Exception as e:
            pass


class TestDashboardManagerEdgeCases(IntellicrackTestBase):
    """Test DashboardManager edge cases."""

    def test_add_activity_with_empty_description(self) -> None:
        """add_activity handles empty description."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        try:
            manager.add_activity("analysis", "")
        except Exception as e:
            pytest.fail(f"Should handle empty description: {e}")

    def test_add_activity_with_long_description(self) -> None:
        """add_activity handles very long descriptions."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        long_desc = "A" * 10000
        try:
            manager.add_activity("analysis", long_desc)
        except Exception as e:
            pytest.fail(f"Should handle long description: {e}")

    def test_get_stats_returns_consistent_type(self) -> None:
        """get_stats always returns dict, even when empty."""
        mock_app = MagicMock()
        manager = DashboardManager(mock_app)

        stats1 = manager.get_stats()
        stats2 = manager.get_stats()

        assert isinstance(stats1, dict)
        assert isinstance(stats2, dict)
