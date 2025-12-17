"""Production tests for ThemeManager.

Tests theme switching, stylesheet application, persistence, and fallback
mechanisms with real QApplication instances.

Copyright (C) 2025 Zachary Flint
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
from typing import Any

from intellicrack.handlers.pyqt6_handler import QApplication
from intellicrack.ui.theme_manager import (
    ThemeManager,
    get_theme_manager,
    apply_theme,
    get_current_theme,
)


@pytest.fixture
def qapp() -> QApplication:
    """Provide QApplication instance for theme testing."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def mock_config() -> MagicMock:
    """Provide mock configuration manager."""
    config = MagicMock()
    config.get.return_value = "dark"
    return config


@pytest.fixture
def theme_manager(qapp: QApplication, mock_config: MagicMock) -> ThemeManager:
    """Create ThemeManager instance for testing."""
    with patch("intellicrack.ui.theme_manager.get_config", return_value=mock_config):
        manager = ThemeManager()
    return manager


class TestThemeManagerInitialization:
    """Test ThemeManager initialization and configuration loading."""

    def test_initialization_loads_default_dark_theme(
        self, qapp: QApplication, mock_config: MagicMock
    ) -> None:
        """ThemeManager initializes with dark theme by default."""
        mock_config.get.return_value = "dark"

        with patch("intellicrack.ui.theme_manager.get_config", return_value=mock_config):
            manager = ThemeManager()

            assert manager.current_theme == "dark"
            assert "dark" in manager.themes
            assert "light" in manager.themes

    def test_initialization_normalizes_stored_theme_preference(
        self, qapp: QApplication, mock_config: MagicMock
    ) -> None:
        """ThemeManager normalizes stored theme preference to lowercase."""
        mock_config.get.return_value = "DARK"

        with patch("intellicrack.ui.theme_manager.get_config", return_value=mock_config):
            manager = ThemeManager()

            assert manager.current_theme == "dark"

    def test_initialization_handles_theme_name_variations(
        self, qapp: QApplication, mock_config: MagicMock
    ) -> None:
        """ThemeManager handles common theme name variations correctly."""
        variations = {
            "black": "dark",
            "white": "light",
            "default": "dark",
            "LIGHT": "light",
        }

        for input_theme, expected_theme in variations.items():
            mock_config.get.return_value = input_theme

            with patch(
                "intellicrack.ui.theme_manager.get_config", return_value=mock_config
            ):
                manager = ThemeManager()

                assert manager.current_theme == expected_theme

    def test_initialization_applies_theme_to_qapplication(
        self, qapp: QApplication, mock_config: MagicMock
    ) -> None:
        """ThemeManager applies theme stylesheet to QApplication on initialization."""
        mock_config.get.return_value = "dark"

        with patch("intellicrack.ui.theme_manager.get_config", return_value=mock_config):
            manager = ThemeManager()

            stylesheet = qapp.styleSheet()
            assert len(stylesheet) > 0
            assert any(
                keyword in stylesheet.lower()
                for keyword in ["background", "color", "qmainwindow"]
            )


class TestThemeManagerThemeSwitching:
    """Test theme switching functionality."""

    def test_set_theme_to_light_changes_current_theme(
        self, theme_manager: ThemeManager, mock_config: MagicMock
    ) -> None:
        """Setting theme to light changes current theme and saves preference."""
        theme_manager.set_theme("light")

        assert theme_manager.current_theme == "light"
        mock_config.set.assert_called_with("ui_preferences.theme", "light")

    def test_set_theme_to_dark_changes_current_theme(
        self, theme_manager: ThemeManager, mock_config: MagicMock
    ) -> None:
        """Setting theme to dark changes current theme and saves preference."""
        theme_manager.set_theme("dark")

        assert theme_manager.current_theme == "dark"
        mock_config.set.assert_called_with("ui_preferences.theme", "dark")

    def test_set_theme_normalizes_theme_name(
        self, theme_manager: ThemeManager, mock_config: MagicMock
    ) -> None:
        """Setting theme normalizes theme name to lowercase."""
        theme_manager.set_theme("LIGHT")

        assert theme_manager.current_theme == "light"

    def test_set_theme_handles_common_variations(
        self, theme_manager: ThemeManager, mock_config: MagicMock
    ) -> None:
        """Setting theme handles common theme name variations."""
        variations = {
            "black": "dark",
            "white": "light",
            "default": "dark",
        }

        for input_theme, expected_theme in variations.items():
            theme_manager.set_theme(input_theme)

            assert theme_manager.current_theme == expected_theme

    def test_set_theme_with_invalid_name_falls_back_to_light(
        self, theme_manager: ThemeManager, mock_config: MagicMock
    ) -> None:
        """Setting invalid theme name falls back to light theme."""
        theme_manager.set_theme("invalid_theme_name")

        assert theme_manager.current_theme == "light"

    def test_set_theme_applies_stylesheet_to_qapplication(
        self, theme_manager: ThemeManager, qapp: QApplication
    ) -> None:
        """Setting theme applies corresponding stylesheet to QApplication."""
        theme_manager.set_theme("light")

        light_stylesheet = qapp.styleSheet()
        assert len(light_stylesheet) > 0

        theme_manager.set_theme("dark")

        dark_stylesheet = qapp.styleSheet()
        assert len(dark_stylesheet) > 0
        assert dark_stylesheet != light_stylesheet


class TestThemeManagerStylesheetLoading:
    """Test stylesheet loading from files and built-in fallbacks."""

    def test_get_theme_stylesheet_loads_from_file_when_exists(
        self, theme_manager: ThemeManager
    ) -> None:
        """Getting theme stylesheet loads from file when file exists."""
        test_stylesheet_content = "QMainWindow { background-color: #123456; }"

        with patch("os.path.exists", return_value=True), patch(
            "builtins.open", mock_open(read_data=test_stylesheet_content)
        ):
            stylesheet = theme_manager._get_theme_stylesheet()

            assert stylesheet == test_stylesheet_content

    def test_get_theme_stylesheet_falls_back_to_builtin_when_file_missing(
        self, theme_manager: ThemeManager
    ) -> None:
        """Getting theme stylesheet falls back to built-in when file missing."""
        with patch("os.path.exists", return_value=False):
            stylesheet = theme_manager._get_theme_stylesheet()

            assert len(stylesheet) > 0
            assert "QMainWindow" in stylesheet

    def test_get_builtin_dark_stylesheet_returns_valid_css(
        self, theme_manager: ThemeManager
    ) -> None:
        """Built-in dark stylesheet returns valid CSS with proper selectors."""
        theme_manager.current_theme = "dark"

        stylesheet = theme_manager._get_builtin_dark_stylesheet()

        assert len(stylesheet) > 0
        assert "QMainWindow" in stylesheet
        assert "background-color" in stylesheet.lower()
        assert "#1E1E1E" in stylesheet or "#1e1e1e" in stylesheet.lower()
        assert "QTabWidget" in stylesheet
        assert "QPushButton" in stylesheet

    def test_get_builtin_light_stylesheet_returns_valid_css(
        self, theme_manager: ThemeManager
    ) -> None:
        """Built-in light stylesheet returns valid CSS with proper selectors."""
        theme_manager.current_theme = "light"

        stylesheet = theme_manager._get_builtin_light_stylesheet()

        assert len(stylesheet) > 0
        assert "QMainWindow" in stylesheet
        assert "background-color" in stylesheet.lower()
        assert "#F8F8F8" in stylesheet or "#f8f8f8" in stylesheet.lower()
        assert "QTabWidget" in stylesheet
        assert "QPushButton" in stylesheet

    def test_builtin_dark_stylesheet_has_proper_contrast(
        self, theme_manager: ThemeManager
    ) -> None:
        """Built-in dark stylesheet has proper contrast for readability."""
        stylesheet = theme_manager._get_builtin_dark_stylesheet()

        assert "color: #FFFFFF" in stylesheet or "color: #ffffff" in stylesheet.lower()
        assert any(
            dark_color in stylesheet.lower()
            for dark_color in ["#1e1e1e", "#2b2b2b", "#3c3c3c"]
        )

    def test_builtin_light_stylesheet_has_proper_contrast(
        self, theme_manager: ThemeManager
    ) -> None:
        """Built-in light stylesheet has proper contrast for readability."""
        stylesheet = theme_manager._get_builtin_light_stylesheet()

        assert "color: #1A1A1A" in stylesheet or "color: #1a1a1a" in stylesheet.lower()
        assert any(
            light_color in stylesheet.lower()
            for light_color in ["#f8f8f8", "#ffffff", "#e0e0e0"]
        )

    def test_get_builtin_theme_stylesheet_selects_correct_theme(
        self, theme_manager: ThemeManager
    ) -> None:
        """Getting built-in theme stylesheet selects correct theme based on current."""
        theme_manager.current_theme = "dark"
        dark_stylesheet = theme_manager._get_builtin_theme_stylesheet()

        theme_manager.current_theme = "light"
        light_stylesheet = theme_manager._get_builtin_theme_stylesheet()

        assert dark_stylesheet != light_stylesheet
        assert "#1E1E1E" in dark_stylesheet or "#1e1e1e" in dark_stylesheet.lower()
        assert "#F8F8F8" in light_stylesheet or "#f8f8f8" in light_stylesheet.lower()


class TestThemeManagerPersistence:
    """Test theme preference persistence."""

    def test_save_theme_preference_saves_to_config(
        self, theme_manager: ThemeManager, mock_config: MagicMock
    ) -> None:
        """Saving theme preference writes to configuration manager."""
        theme_manager.current_theme = "light"
        theme_manager.save_theme_preference()

        mock_config.set.assert_called_with("ui_preferences.theme", "light")

    def test_load_theme_preference_loads_from_config(
        self, qapp: QApplication, mock_config: MagicMock
    ) -> None:
        """Loading theme preference reads from configuration manager."""
        mock_config.get.return_value = "light"

        with patch("intellicrack.ui.theme_manager.get_config", return_value=mock_config):
            manager = ThemeManager()

            loaded_theme = manager.load_theme_preference()

            assert loaded_theme == "light"
            mock_config.get.assert_called_with("ui_preferences.theme", "dark")

    def test_load_theme_preference_returns_dark_as_default(
        self, qapp: QApplication, mock_config: MagicMock
    ) -> None:
        """Loading theme preference returns dark as default when not set."""
        mock_config.get.return_value = None

        with patch("intellicrack.ui.theme_manager.get_config", return_value=mock_config):
            manager = ThemeManager()

            loaded_theme = manager.load_theme_preference()

            assert loaded_theme == "dark"


class TestThemeManagerGlobalFunctions:
    """Test global theme manager functions."""

    def test_get_theme_manager_returns_singleton_instance(
        self, qapp: QApplication, mock_config: MagicMock
    ) -> None:
        """Getting theme manager returns same singleton instance."""
        with patch("intellicrack.ui.theme_manager.get_config", return_value=mock_config):
            manager1 = get_theme_manager()
            manager2 = get_theme_manager()

            assert manager1 is manager2

    def test_apply_theme_sets_theme_via_manager(
        self, qapp: QApplication, mock_config: MagicMock
    ) -> None:
        """Applying theme sets theme via global theme manager."""
        with patch("intellicrack.ui.theme_manager.get_config", return_value=mock_config):
            apply_theme("light")

            manager = get_theme_manager()
            assert manager.current_theme == "light"

    def test_get_current_theme_returns_active_theme(
        self, qapp: QApplication, mock_config: MagicMock
    ) -> None:
        """Getting current theme returns active theme from manager."""
        with patch("intellicrack.ui.theme_manager.get_config", return_value=mock_config):
            apply_theme("dark")

            current = get_current_theme()
            assert current == "dark"


class TestThemeManagerErrorHandling:
    """Test theme manager error handling and fallbacks."""

    def test_apply_theme_handles_file_read_error_gracefully(
        self, theme_manager: ThemeManager
    ) -> None:
        """Applying theme handles file read errors gracefully with fallback."""
        with patch("os.path.exists", return_value=True), patch(
            "builtins.open", side_effect=IOError("File read error")
        ):
            theme_manager._apply_theme()

            stylesheet = QApplication.instance().styleSheet()
            assert len(stylesheet) > 0

    def test_apply_builtin_dark_theme_as_fallback_when_exception_occurs(
        self, theme_manager: ThemeManager, qapp: QApplication
    ) -> None:
        """Applying built-in dark theme as fallback when exception occurs."""
        theme_manager._apply_builtin_dark_theme()

        stylesheet = qapp.styleSheet()
        assert len(stylesheet) > 0
        assert "QMainWindow" in stylesheet

    def test_apply_theme_logs_error_when_no_qapplication_instance(
        self, theme_manager: ThemeManager
    ) -> None:
        """Applying theme logs error when no QApplication instance exists."""
        with patch(
            "intellicrack.handlers.pyqt6_handler.QApplication.instance",
            return_value=None,
        ), patch("intellicrack.ui.theme_manager.logger") as mock_logger:

            theme_manager._apply_theme()

            mock_logger.warning.assert_called()


class TestThemeManagerIntegration:
    """Integration tests for complete theme switching workflows."""

    def test_complete_theme_switch_workflow_dark_to_light(
        self, theme_manager: ThemeManager, qapp: QApplication, mock_config: MagicMock
    ) -> None:
        """Complete theme switch from dark to light updates all components."""
        theme_manager.set_theme("dark")
        dark_stylesheet = qapp.styleSheet()

        theme_manager.set_theme("light")
        light_stylesheet = qapp.styleSheet()

        assert theme_manager.current_theme == "light"
        assert dark_stylesheet != light_stylesheet
        mock_config.set.assert_called_with("ui_preferences.theme", "light")

    def test_multiple_theme_switches_maintain_consistency(
        self, theme_manager: ThemeManager, qapp: QApplication
    ) -> None:
        """Multiple theme switches maintain stylesheet consistency."""
        theme_manager.set_theme("dark")
        assert "QMainWindow" in qapp.styleSheet()

        theme_manager.set_theme("light")
        assert "QMainWindow" in qapp.styleSheet()

        theme_manager.set_theme("dark")
        assert "QMainWindow" in qapp.styleSheet()

        assert theme_manager.current_theme == "dark"

    def test_theme_persistence_across_manager_instances(
        self, qapp: QApplication, mock_config: MagicMock
    ) -> None:
        """Theme preference persists across different manager instances."""
        mock_config.get.return_value = "light"

        with patch("intellicrack.ui.theme_manager.get_config", return_value=mock_config):
            manager1 = ThemeManager()
            manager1.set_theme("dark")

            mock_config.get.return_value = "dark"

            manager2 = ThemeManager()
            assert manager2.current_theme == "dark"
