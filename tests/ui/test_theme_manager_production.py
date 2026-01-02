"""Production tests for ThemeManager.

Tests theme switching, stylesheet application, persistence, and fallback
mechanisms with real QApplication instances.

Copyright (C) 2025 Zachary Flint
"""

import pytest
from pathlib import Path
from typing import Any
import tempfile
import os

from intellicrack.handlers.pyqt6_handler import QApplication
from intellicrack.ui.theme_manager import (
    ThemeManager,
    get_theme_manager,
    apply_theme,
    get_current_theme,
)


class FakeConfigManager:
    """Real test double for configuration manager.

    Provides fully functional in-memory configuration storage
    without external dependencies.
    """

    def __init__(self) -> None:
        """Initialize fake config with empty storage."""
        self._storage: dict[str, Any] = {}
        self._default_theme: str = "dark"

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with default fallback.

        Args:
            key: Configuration key to retrieve
            default: Default value if key not found

        Returns:
            Stored value or default
        """
        return self._storage.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Store configuration value.

        Args:
            key: Configuration key to store
            value: Value to store
        """
        self._storage[key] = value

    def clear(self) -> None:
        """Clear all stored configuration."""
        self._storage.clear()

    def set_default_theme(self, theme: str) -> None:
        """Set default theme for get() calls.

        Args:
            theme: Theme name to use as default
        """
        self._default_theme = theme
        self._storage["ui_preferences.theme"] = theme


class FakeFileSystem:
    """Real test double for file system operations.

    Provides in-memory file storage for testing stylesheet loading
    without touching real filesystem.
    """

    def __init__(self) -> None:
        """Initialize fake filesystem with empty storage."""
        self._files: dict[str, str] = {}

    def write_file(self, path: str, content: str) -> None:
        """Write content to virtual file.

        Args:
            path: File path to write
            content: Content to store
        """
        self._files[path] = content

    def read_file(self, path: str) -> str:
        """Read content from virtual file.

        Args:
            path: File path to read

        Returns:
            File content

        Raises:
            FileNotFoundError: If file doesn't exist
            IOError: On read errors
        """
        if path not in self._files:
            raise FileNotFoundError(f"File not found: {path}")
        return self._files[path]

    def exists(self, path: str) -> bool:
        """Check if file exists in virtual filesystem.

        Args:
            path: File path to check

        Returns:
            True if file exists, False otherwise
        """
        return path in self._files

    def remove_file(self, path: str) -> None:
        """Remove file from virtual filesystem.

        Args:
            path: File path to remove
        """
        if path in self._files:
            del self._files[path]

    def clear(self) -> None:
        """Clear all virtual files."""
        self._files.clear()


class FakeLogger:
    """Real test double for logging operations.

    Captures log messages for verification in tests
    without writing to actual log files.
    """

    def __init__(self) -> None:
        """Initialize fake logger with empty message storage."""
        self.info_messages: list[str] = []
        self.warning_messages: list[str] = []
        self.error_messages: list[str] = []
        self.exception_messages: list[str] = []

    def info(self, message: str, *args: Any) -> None:
        """Log info message.

        Args:
            message: Message format string
            *args: Format arguments
        """
        formatted = message % args if args else message
        self.info_messages.append(formatted)

    def warning(self, message: str, *args: Any) -> None:
        """Log warning message.

        Args:
            message: Message format string
            *args: Format arguments
        """
        formatted = message % args if args else message
        self.warning_messages.append(formatted)

    def error(self, message: str, *args: Any) -> None:
        """Log error message.

        Args:
            message: Message format string
            *args: Format arguments
        """
        formatted = message % args if args else message
        self.error_messages.append(formatted)

    def exception(self, message: str, *args: Any) -> None:
        """Log exception message.

        Args:
            message: Message format string
            *args: Format arguments
        """
        formatted = message % args if args else message
        self.exception_messages.append(formatted)

    def clear(self) -> None:
        """Clear all logged messages."""
        self.info_messages.clear()
        self.warning_messages.clear()
        self.error_messages.clear()
        self.exception_messages.clear()

    def has_warning_containing(self, text: str) -> bool:
        """Check if any warning contains specified text.

        Args:
            text: Text to search for

        Returns:
            True if text found in warnings
        """
        return any(text in msg for msg in self.warning_messages)

    def get_last_info(self) -> str | None:
        """Get last info message.

        Returns:
            Last info message or None if empty
        """
        return self.info_messages[-1] if self.info_messages else None


@pytest.fixture
def qapp() -> QApplication:
    """Provide QApplication instance for theme testing."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def fake_config() -> FakeConfigManager:
    """Provide fake configuration manager."""
    config = FakeConfigManager()
    config.set_default_theme("dark")
    return config


@pytest.fixture
def fake_filesystem() -> FakeFileSystem:
    """Provide fake filesystem for stylesheet testing."""
    return FakeFileSystem()


@pytest.fixture
def fake_logger() -> FakeLogger:
    """Provide fake logger for testing log outputs."""
    return FakeLogger()


@pytest.fixture
def theme_manager(qapp: QApplication, fake_config: FakeConfigManager, monkeypatch: pytest.MonkeyPatch) -> ThemeManager:
    """Create ThemeManager instance for testing."""
    monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: fake_config)
    manager = ThemeManager()
    return manager


class TestThemeManagerInitialization:
    """Test ThemeManager initialization and configuration loading."""

    def test_initialization_loads_default_dark_theme(
        self, qapp: QApplication, fake_config: FakeConfigManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ThemeManager initializes with dark theme by default."""
        fake_config.set("ui_preferences.theme", "dark")

        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: fake_config)
        manager = ThemeManager()

        assert manager.current_theme == "dark"
        assert "dark" in manager.themes
        assert "light" in manager.themes

    def test_initialization_normalizes_stored_theme_preference(
        self, qapp: QApplication, fake_config: FakeConfigManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ThemeManager normalizes stored theme preference to lowercase."""
        fake_config.set("ui_preferences.theme", "DARK")

        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: fake_config)
        manager = ThemeManager()

        assert manager.current_theme == "dark"

    def test_initialization_handles_theme_name_variations(
        self, qapp: QApplication, fake_config: FakeConfigManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ThemeManager handles common theme name variations correctly."""
        variations = {
            "black": "dark",
            "white": "light",
            "default": "dark",
            "LIGHT": "light",
        }

        for input_theme, expected_theme in variations.items():
            fake_config.clear()
            fake_config.set("ui_preferences.theme", input_theme)

            monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: fake_config)
            manager = ThemeManager()

            assert manager.current_theme == expected_theme

    def test_initialization_applies_theme_to_qapplication(
        self, qapp: QApplication, fake_config: FakeConfigManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ThemeManager applies theme stylesheet to QApplication on initialization."""
        fake_config.set("ui_preferences.theme", "dark")

        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: fake_config)
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
        self, theme_manager: ThemeManager, fake_config: FakeConfigManager
    ) -> None:
        """Setting theme to light changes current theme and saves preference."""
        theme_manager.set_theme("light")

        assert theme_manager.current_theme == "light"
        assert fake_config.get("ui_preferences.theme") == "light"

    def test_set_theme_to_dark_changes_current_theme(
        self, theme_manager: ThemeManager, fake_config: FakeConfigManager
    ) -> None:
        """Setting theme to dark changes current theme and saves preference."""
        theme_manager.set_theme("dark")

        assert theme_manager.current_theme == "dark"
        assert fake_config.get("ui_preferences.theme") == "dark"

    def test_set_theme_normalizes_theme_name(
        self, theme_manager: ThemeManager, fake_config: FakeConfigManager
    ) -> None:
        """Setting theme normalizes theme name to lowercase."""
        theme_manager.set_theme("LIGHT")

        assert theme_manager.current_theme == "light"

    def test_set_theme_handles_common_variations(
        self, theme_manager: ThemeManager, fake_config: FakeConfigManager
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
        self, theme_manager: ThemeManager, fake_config: FakeConfigManager
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
        self, theme_manager: ThemeManager, fake_filesystem: FakeFileSystem, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Getting theme stylesheet loads from file when file exists."""
        test_stylesheet_content = "QMainWindow { background-color: #123456; }"
        test_path = os.path.join(theme_manager.styles_dir, "dark_theme.qss")

        fake_filesystem.write_file(test_path, test_stylesheet_content)

        monkeypatch.setattr("os.path.exists", lambda p: fake_filesystem.exists(p))
        monkeypatch.setattr("builtins.open",
                          lambda p, encoding=None: FakeFileHandle(fake_filesystem.read_file(p)))

        stylesheet = theme_manager._get_theme_stylesheet()

        assert stylesheet == test_stylesheet_content

    def test_get_theme_stylesheet_falls_back_to_builtin_when_file_missing(
        self, theme_manager: ThemeManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Getting theme stylesheet falls back to built-in when file missing."""
        monkeypatch.setattr("os.path.exists", lambda p: False)

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


class FakeFileHandle:
    """Real test double for file handle operations.

    Simulates file reading behavior for stylesheet loading tests.
    """

    def __init__(self, content: str) -> None:
        """Initialize fake file handle with content.

        Args:
            content: File content to return on read
        """
        self.content = content
        self.closed = False

    def read(self) -> str:
        """Read file content.

        Returns:
            File content
        """
        if self.closed:
            raise ValueError("I/O operation on closed file")
        return self.content

    def close(self) -> None:
        """Close file handle."""
        self.closed = True

    def __enter__(self) -> "FakeFileHandle":
        """Enter context manager."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context manager and close file."""
        self.close()


class TestThemeManagerPersistence:
    """Test theme preference persistence."""

    def test_save_theme_preference_saves_to_config(
        self, theme_manager: ThemeManager, fake_config: FakeConfigManager
    ) -> None:
        """Saving theme preference writes to configuration manager."""
        theme_manager.current_theme = "light"
        theme_manager.save_theme_preference()

        assert fake_config.get("ui_preferences.theme") == "light"

    def test_load_theme_preference_loads_from_config(
        self, qapp: QApplication, fake_config: FakeConfigManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Loading theme preference reads from configuration manager."""
        fake_config.set("ui_preferences.theme", "light")

        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: fake_config)
        manager = ThemeManager()

        loaded_theme = manager.load_theme_preference()

        assert loaded_theme == "light"
        assert fake_config.get("ui_preferences.theme") == "light"

    def test_load_theme_preference_returns_dark_as_default(
        self, qapp: QApplication, fake_config: FakeConfigManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Loading theme preference returns dark as default when not set."""
        fake_config.clear()

        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: fake_config)
        manager = ThemeManager()

        loaded_theme = manager.load_theme_preference()

        assert loaded_theme == "dark"


class TestThemeManagerGlobalFunctions:
    """Test global theme manager functions."""

    def test_get_theme_manager_returns_singleton_instance(
        self, qapp: QApplication, fake_config: FakeConfigManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Getting theme manager returns same singleton instance."""
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: fake_config)

        import intellicrack.ui.theme_manager
        intellicrack.ui.theme_manager._theme_manager = None

        manager1 = get_theme_manager()
        manager2 = get_theme_manager()

        assert manager1 is manager2

    def test_apply_theme_sets_theme_via_manager(
        self, qapp: QApplication, fake_config: FakeConfigManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Applying theme sets theme via global theme manager."""
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: fake_config)

        import intellicrack.ui.theme_manager
        intellicrack.ui.theme_manager._theme_manager = None

        apply_theme("light")

        manager = get_theme_manager()
        assert manager.current_theme == "light"

    def test_get_current_theme_returns_active_theme(
        self, qapp: QApplication, fake_config: FakeConfigManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Getting current theme returns active theme from manager."""
        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: fake_config)

        import intellicrack.ui.theme_manager
        intellicrack.ui.theme_manager._theme_manager = None

        apply_theme("dark")

        current = get_current_theme()
        assert current == "dark"


class TestThemeManagerErrorHandling:
    """Test theme manager error handling and fallbacks."""

    def test_apply_theme_handles_file_read_error_gracefully(
        self, theme_manager: ThemeManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Applying theme handles file read errors gracefully with fallback."""
        def raise_io_error(path: str, encoding: str = "utf-8") -> None:
            raise IOError("File read error")

        monkeypatch.setattr("os.path.exists", lambda p: True)
        monkeypatch.setattr("builtins.open", raise_io_error)

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
        self, theme_manager: ThemeManager, fake_logger: FakeLogger, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Applying theme logs error when no QApplication instance exists."""
        monkeypatch.setattr(
            "intellicrack.handlers.pyqt6_handler.QApplication.instance",
            lambda: None,
        )
        monkeypatch.setattr("intellicrack.ui.theme_manager.logger", fake_logger)

        theme_manager._apply_theme()

        assert fake_logger.has_warning_containing("No QApplication instance found")


class TestThemeManagerIntegration:
    """Integration tests for complete theme switching workflows."""

    def test_complete_theme_switch_workflow_dark_to_light(
        self, theme_manager: ThemeManager, qapp: QApplication, fake_config: FakeConfigManager
    ) -> None:
        """Complete theme switch from dark to light updates all components."""
        theme_manager.set_theme("dark")
        dark_stylesheet = qapp.styleSheet()

        theme_manager.set_theme("light")
        light_stylesheet = qapp.styleSheet()

        assert theme_manager.current_theme == "light"
        assert dark_stylesheet != light_stylesheet
        assert fake_config.get("ui_preferences.theme") == "light"

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
        self, qapp: QApplication, fake_config: FakeConfigManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Theme preference persists across different manager instances."""
        fake_config.set("ui_preferences.theme", "light")

        monkeypatch.setattr("intellicrack.ui.theme_manager.get_config", lambda: fake_config)
        manager1 = ThemeManager()
        manager1.set_theme("dark")

        assert fake_config.get("ui_preferences.theme") == "dark"

        manager2 = ThemeManager()
        assert manager2.current_theme == "dark"
