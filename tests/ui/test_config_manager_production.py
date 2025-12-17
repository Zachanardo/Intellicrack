"""Production tests for UI Configuration Manager.

Validates real configuration management, theme switching, persistence,
and integration with central config system.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ui.config_manager import (
    AccessibilityConfig,
    AnimationConfig,
    EditorConfig,
    FontConfig,
    LayoutConfig,
    ThemeConfig,
    UIConfigManager,
    get_ui_config_manager,
)


class TestThemeConfig:
    """Test theme configuration data class."""

    def test_theme_config_defaults(self) -> None:
        """Theme config has correct default values."""
        theme = ThemeConfig()
        assert theme.name == "dark"
        assert theme.primary_color == "#00ff00"
        assert theme.background_color == "#1e1e1e"
        assert theme.foreground_color == "#ffffff"
        assert theme.border_radius == 4

    def test_theme_config_custom_values(self) -> None:
        """Theme config accepts custom values."""
        theme = ThemeConfig(
            name="custom",
            primary_color="#ff0000",
            background_color="#000000",
            border_radius=8,
        )
        assert theme.name == "custom"
        assert theme.primary_color == "#ff0000"
        assert theme.background_color == "#000000"
        assert theme.border_radius == 8


class TestFontConfig:
    """Test font configuration data class."""

    def test_font_config_defaults(self) -> None:
        """Font config has correct default values."""
        font = FontConfig()
        assert font.family == "Segoe UI"
        assert font.base_size == 10
        assert font.header_size == 14
        assert font.code_family == "Consolas"
        assert font.code_size == 10
        assert font.bold_weight == 700
        assert font.use_antialiasing is True

    def test_font_config_custom_values(self) -> None:
        """Font config accepts custom values."""
        font = FontConfig(
            family="Arial",
            base_size=12,
            code_family="Courier New",
            use_antialiasing=False,
        )
        assert font.family == "Arial"
        assert font.base_size == 12
        assert font.code_family == "Courier New"
        assert font.use_antialiasing is False


class TestLayoutConfig:
    """Test layout configuration data class."""

    def test_layout_config_defaults(self) -> None:
        """Layout config has correct default values."""
        layout = LayoutConfig()
        assert layout.window_width == 1400
        assert layout.window_height == 900
        assert layout.sidebar_width == 250
        assert layout.sidebar_visible is True
        assert layout.toolbar_visible is True
        assert layout.statusbar_visible is True

    def test_layout_config_custom_values(self) -> None:
        """Layout config accepts custom dimensions."""
        layout = LayoutConfig(
            window_width=1920,
            window_height=1080,
            sidebar_visible=False,
        )
        assert layout.window_width == 1920
        assert layout.window_height == 1080
        assert layout.sidebar_visible is False


class TestUIConfigManager:
    """Production tests for UIConfigManager."""

    @pytest.fixture
    def temp_config_dir(self) -> Path:
        """Create temporary config directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir)
            os.environ["INTELLICRACK_CONFIG_DIR"] = str(config_dir)
            yield config_dir
            if "INTELLICRACK_CONFIG_DIR" in os.environ:
                del os.environ["INTELLICRACK_CONFIG_DIR"]

    @pytest.fixture
    def config_manager(self, temp_config_dir: Path) -> UIConfigManager:
        """Create config manager with isolated config."""
        return UIConfigManager()

    def test_initialization_creates_default_config(self, config_manager: UIConfigManager) -> None:
        """Config manager initializes with default theme and settings."""
        assert config_manager.theme is not None
        assert config_manager.font is not None
        assert config_manager.layout is not None
        assert config_manager.editor is not None
        assert config_manager.animation is not None
        assert config_manager.accessibility is not None

    def test_default_theme_is_dark(self, config_manager: UIConfigManager) -> None:
        """Default theme is dark theme."""
        theme = config_manager.get_theme_config()
        assert theme.name == "dark"
        assert theme.primary_color == "#00ff00"
        assert theme.background_color == "#1e1e1e"

    def test_set_theme_by_name_succeeds(self, config_manager: UIConfigManager) -> None:
        """Set theme by name switches to correct theme."""
        result = config_manager.set_theme("light")
        assert result is True

        theme = config_manager.get_theme_config()
        assert theme.name == "light"
        assert theme.background_color == "#ffffff"
        assert theme.foreground_color == "#000000"

    def test_set_theme_hacker_theme(self, config_manager: UIConfigManager) -> None:
        """Hacker theme has correct green-on-black styling."""
        result = config_manager.set_theme("hacker")
        assert result is True

        theme = config_manager.get_theme_config()
        assert theme.name == "hacker"
        assert theme.background_color == "#000000"
        assert theme.foreground_color == "#00ff00"
        assert theme.text_color == "#00ff00"

    def test_set_invalid_theme_returns_false(self, config_manager: UIConfigManager) -> None:
        """Setting invalid theme name returns False."""
        original_theme = config_manager.theme.name
        result = config_manager.set_theme("nonexistent_theme")
        assert result is False
        assert config_manager.theme.name == original_theme

    def test_create_custom_theme(self, config_manager: UIConfigManager) -> None:
        """Custom theme can be created and retrieved."""
        custom_theme = ThemeConfig(
            name="my_custom",
            primary_color="#ff00ff",
            background_color="#2a2a2a",
        )

        config_manager.create_custom_theme("my_custom", custom_theme)
        assert "my_custom" in config_manager.custom_themes

        result = config_manager.set_theme("my_custom")
        assert result is True
        assert config_manager.theme.primary_color == "#ff00ff"

    def test_get_available_themes_includes_all(self, config_manager: UIConfigManager) -> None:
        """Available themes includes default and custom themes."""
        custom_theme = ThemeConfig(name="test_theme")
        config_manager.create_custom_theme("test_theme", custom_theme)

        available = config_manager.get_available_themes()
        assert "dark" in available
        assert "light" in available
        assert "hacker" in available
        assert "test_theme" in available

    def test_font_config_persistence(self, config_manager: UIConfigManager) -> None:
        """Font configuration persists after save."""
        new_font = FontConfig(
            family="Arial",
            base_size=14,
            code_family="Monaco",
        )

        config_manager.set_font_config(new_font)

        new_manager = UIConfigManager()
        loaded_font = new_manager.get_font_config()
        assert loaded_font.family == "Arial"
        assert loaded_font.base_size == 14
        assert loaded_font.code_family == "Monaco"

    def test_layout_config_persistence(self, config_manager: UIConfigManager) -> None:
        """Layout configuration persists after save."""
        new_layout = LayoutConfig(
            window_width=1920,
            window_height=1080,
            sidebar_visible=False,
        )

        config_manager.set_layout_config(new_layout)

        new_manager = UIConfigManager()
        loaded_layout = new_manager.get_layout_config()
        assert loaded_layout.window_width == 1920
        assert loaded_layout.window_height == 1080
        assert loaded_layout.sidebar_visible is False

    def test_editor_config_persistence(self, config_manager: UIConfigManager) -> None:
        """Editor configuration persists after save."""
        new_editor = EditorConfig(
            indent_size=2,
            use_tabs=True,
            show_whitespace=True,
        )

        config_manager.set_editor_config(new_editor)

        new_manager = UIConfigManager()
        loaded_editor = new_manager.get_editor_config()
        assert loaded_editor.indent_size == 2
        assert loaded_editor.use_tabs is True
        assert loaded_editor.show_whitespace is True

    def test_animation_config_persistence(self, config_manager: UIConfigManager) -> None:
        """Animation configuration persists after save."""
        new_animation = AnimationConfig(
            enabled=False,
            duration=300,
            fade_effects=False,
        )

        config_manager.set_animation_config(new_animation)

        new_manager = UIConfigManager()
        loaded_animation = new_manager.get_animation_config()
        assert loaded_animation.enabled is False
        assert loaded_animation.duration == 300
        assert loaded_animation.fade_effects is False

    def test_accessibility_config_persistence(self, config_manager: UIConfigManager) -> None:
        """Accessibility configuration persists after save."""
        new_accessibility = AccessibilityConfig(
            high_contrast=True,
            large_icons=True,
            reduce_motion=True,
        )

        config_manager.set_accessibility_config(new_accessibility)

        new_manager = UIConfigManager()
        loaded_accessibility = new_manager.get_accessibility_config()
        assert loaded_accessibility.high_contrast is True
        assert loaded_accessibility.large_icons is True
        assert loaded_accessibility.reduce_motion is True

    def test_get_setting_retrieves_dashboard_config(self, config_manager: UIConfigManager) -> None:
        """Get setting retrieves dashboard configuration from main config."""
        value = config_manager.get_setting("dashboard.show_tabs", True)
        assert isinstance(value, bool)

    def test_set_setting_updates_dashboard_config(self, config_manager: UIConfigManager) -> None:
        """Set setting updates dashboard configuration in main config."""
        config_manager.set_setting("dashboard.custom_value", 42)
        retrieved = config_manager.get_setting("dashboard.custom_value")
        assert retrieved == 42

    def test_callback_registration_and_notification(self, config_manager: UIConfigManager) -> None:
        """Callback is invoked when configuration changes."""
        callback_invoked = False

        def test_callback() -> None:
            nonlocal callback_invoked
            callback_invoked = True

        config_manager.register_callback("theme", test_callback)
        config_manager.set_theme("light")

        assert callback_invoked is True

    def test_callback_unregistration(self, config_manager: UIConfigManager) -> None:
        """Callback unregistration prevents future invocations."""
        callback_count = 0

        def test_callback() -> None:
            nonlocal callback_count
            callback_count += 1

        config_manager.register_callback("theme", test_callback)
        config_manager.set_theme("light")
        assert callback_count == 1

        config_manager.unregister_callback("theme", test_callback)
        config_manager.set_theme("dark")
        assert callback_count == 1

    def test_reset_to_defaults(self, config_manager: UIConfigManager) -> None:
        """Reset to defaults restores all default configurations."""
        config_manager.set_theme("light")
        config_manager.set_font_config(FontConfig(family="Arial", base_size=14))
        config_manager.set_layout_config(LayoutConfig(window_width=1920))

        config_manager.reset_to_defaults()

        assert config_manager.theme.name == "dark"
        assert config_manager.font.family == "Segoe UI"
        assert config_manager.font.base_size == 10
        assert config_manager.layout.window_width == 1400

    def test_reset_invokes_all_callbacks(self, config_manager: UIConfigManager) -> None:
        """Reset to defaults invokes callbacks for all categories."""
        invoked_categories: set[str] = set()

        def make_callback(category: str) -> Any:
            def callback() -> None:
                invoked_categories.add(category)

            return callback

        for category in ["theme", "font", "layout", "editor", "animation", "accessibility"]:
            config_manager.register_callback(category, make_callback(category))

        config_manager.reset_to_defaults()

        assert "theme" in invoked_categories
        assert "font" in invoked_categories
        assert "layout" in invoked_categories

    def test_theme_string_migration(self, config_manager: UIConfigManager) -> None:
        """Config manager handles old string theme format."""
        config_manager.main_config.set("ui.theme", "light")

        new_manager = UIConfigManager()
        theme = new_manager.get_theme_config()
        assert theme.name == "light"
        assert isinstance(theme, ThemeConfig)

    def test_singleton_returns_same_instance(self) -> None:
        """get_ui_config_manager returns singleton instance."""
        instance1 = get_ui_config_manager()
        instance2 = get_ui_config_manager()
        assert instance1 is instance2

    def test_concurrent_theme_switches(self, config_manager: UIConfigManager) -> None:
        """Multiple rapid theme switches maintain consistency."""
        themes = ["dark", "light", "hacker", "dark", "light"]

        for theme_name in themes:
            result = config_manager.set_theme(theme_name)
            assert result is True
            assert config_manager.theme.name == theme_name

    def test_custom_theme_persists_across_instances(self, config_manager: UIConfigManager) -> None:
        """Custom theme persists and is available in new instances."""
        custom = ThemeConfig(
            name="persistent_custom",
            primary_color="#123456",
            background_color="#abcdef",
        )
        config_manager.create_custom_theme("persistent_custom", custom)

        new_manager = UIConfigManager()
        assert "persistent_custom" in new_manager.custom_themes
        assert new_manager.custom_themes["persistent_custom"].primary_color == "#123456"

    def test_invalid_theme_data_type_uses_default(self, config_manager: UIConfigManager) -> None:
        """Invalid theme data type falls back to default theme."""
        config_manager.main_config.set("ui.theme", 12345)

        new_manager = UIConfigManager()
        theme = new_manager.get_theme_config()
        assert theme.name == "dark"


class TestEdgesCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def config_manager(self) -> UIConfigManager:
        """Create isolated config manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["INTELLICRACK_CONFIG_DIR"] = str(tmpdir)
            manager = UIConfigManager()
            yield manager
            if "INTELLICRACK_CONFIG_DIR" in os.environ:
                del os.environ["INTELLICRACK_CONFIG_DIR"]

    def test_callback_error_does_not_crash(self, config_manager: UIConfigManager) -> None:
        """Exception in callback does not prevent other callbacks."""
        callback1_invoked = False
        callback2_invoked = False

        def failing_callback() -> None:
            raise ValueError("Test error")

        def working_callback() -> None:
            nonlocal callback2_invoked
            callback2_invoked = True

        config_manager.register_callback("theme", failing_callback)
        config_manager.register_callback("theme", working_callback)

        config_manager.set_theme("light")

        assert callback2_invoked is True

    def test_empty_custom_themes_handled(self, config_manager: UIConfigManager) -> None:
        """Empty custom themes dictionary is handled correctly."""
        config_manager.custom_themes = {}
        available = config_manager.get_available_themes()
        assert "dark" in available
        assert "light" in available
        assert "hacker" in available

    def test_unregister_nonexistent_callback(self, config_manager: UIConfigManager) -> None:
        """Unregistering nonexistent callback does not raise error."""

        def dummy_callback() -> None:
            pass

        config_manager.unregister_callback("theme", dummy_callback)
