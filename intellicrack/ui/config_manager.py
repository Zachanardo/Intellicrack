"""Centralized UI configuration manager for Intellicrack.

This module provides UI configuration management that integrates directly
with Intellicrack's unified configuration system. NO standalone configs.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import contextlib
import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any


logger = logging.getLogger(__name__)


@dataclass
class ThemeConfig:
    """Theme configuration settings."""

    name: str = "dark"
    primary_color: str = "#00ff00"
    background_color: str = "#1e1e1e"
    foreground_color: str = "#ffffff"
    accent_color: str = "#00ff00"
    error_color: str = "#ff4444"
    warning_color: str = "#ffaa00"
    success_color: str = "#44ff44"
    info_color: str = "#4488ff"

    # Extended theme colors
    text_color: str = "#ffffff"
    text_color_secondary: str = "#cccccc"
    panel_color: str = "#252525"
    border_color: str = "#3d3d3d"
    hover_color: str = "#3d3d3d"
    selection_color: str = "#00ff00"
    disabled_color: str = "#666666"
    button_color: str = "#2d2d2d"
    input_background: str = "#252525"
    border_radius: int = 4


@dataclass
class FontConfig:
    """Font configuration settings."""

    family: str = "Segoe UI"
    base_size: int = 10
    header_size: int = 14
    code_family: str = "Consolas"
    code_size: int = 10
    bold_weight: int = 700
    use_antialiasing: bool = True


@dataclass
class LayoutConfig:
    """Layout configuration settings."""

    window_width: int = 1400
    window_height: int = 900
    sidebar_width: int = 250
    sidebar_visible: bool = True
    toolbar_visible: bool = True
    statusbar_visible: bool = True
    tab_position: str = "top"
    panel_spacing: int = 8
    margin_size: int = 10


@dataclass
class EditorConfig:
    """Code editor configuration settings."""

    indent_size: int = 4
    use_tabs: bool = False
    show_whitespace: bool = False
    highlight_current_line: bool = True
    bracket_matching: bool = True
    auto_indent: bool = True
    auto_complete: bool = True
    show_line_numbers: bool = True


@dataclass
class AnimationConfig:
    """Animation and transition settings."""

    enabled: bool = True
    duration: int = 200
    fade_effects: bool = True
    slide_effects: bool = True
    smooth_scrolling: bool = True


@dataclass
class AccessibilityConfig:
    """Accessibility configuration settings."""

    high_contrast: bool = False
    large_icons: bool = False
    screen_reader_mode: bool = False
    keyboard_navigation: bool = True
    tooltip_delay: int = 500
    focus_indicators: bool = True
    reduce_motion: bool = False


class UIConfigManager:
    """UI configuration manager that uses Intellicrack's unified config system.

    ALL configuration is stored in the main config. No separate UI config files.
    """

    DEFAULT_THEMES = {
        "dark": ThemeConfig(
            name="dark",
            primary_color="#00ff00",
            background_color="#1e1e1e",
            text_color="#ffffff",
            text_color_secondary="#cccccc",
            panel_color="#252525",
            border_color="#3d3d3d",
            hover_color="#3d3d3d",
            selection_color="#00ff00",
            disabled_color="#666666",
            button_color="#2d2d2d",
            input_background="#252525",
        ),
        "light": ThemeConfig(
            name="light",
            primary_color="#0066cc",
            background_color="#ffffff",
            foreground_color="#000000",
            text_color="#000000",
            text_color_secondary="#666666",
            panel_color="#f5f5f5",
            border_color="#dddddd",
            hover_color="#e5e5e5",
            selection_color="#0066cc",
            disabled_color="#999999",
            button_color="#ffffff",
            input_background="#ffffff",
            accent_color="#0066cc",
            error_color="#cc0000",
            warning_color="#ff9900",
            success_color="#00cc00",
            info_color="#0099ff",
        ),
        "hacker": ThemeConfig(
            name="hacker",
            primary_color="#00ff00",
            background_color="#000000",
            foreground_color="#00ff00",
            text_color="#00ff00",
            text_color_secondary="#00cc00",
            panel_color="#001100",
            border_color="#00ff00",
            hover_color="#003300",
            selection_color="#00ffff",
            disabled_color="#005500",
            button_color="#001100",
            input_background="#000500",
            accent_color="#00ffff",
            error_color="#ff0000",
            warning_color="#ffff00",
            success_color="#00ff00",
            info_color="#00ffff",
        ),
    }

    def __init__(self) -> None:
        """Initialize the UI configuration manager using main config."""
        from intellicrack.core.config_manager import get_config

        # Get the unified config instance
        self.main_config = get_config()

        # Initialize with defaults if UI section doesn't exist
        if not self.main_config.get("ui"):
            self._initialize_ui_config()

        # Load current configurations from main config
        self._load_from_main_config()

        # Change callbacks
        self.change_callbacks: dict[str, list[Callable[[], None]]] = {
            "theme": [],
            "font": [],
            "layout": [],
            "editor": [],
            "animation": [],
            "accessibility": [],
        }

        logger.info("UIConfigManager initialized with unified config system")

    def _initialize_ui_config(self) -> None:
        """Initialize UI configuration in main config with defaults."""
        ui_config = {
            "theme": asdict(self.DEFAULT_THEMES["dark"]),
            "font": asdict(FontConfig()),
            "layout": asdict(LayoutConfig()),
            "editor": asdict(EditorConfig()),
            "animation": asdict(AnimationConfig()),
            "accessibility": asdict(AccessibilityConfig()),
            "custom_themes": {},
            "recent_files": [],
            "dashboard": {
                "show_tabs": True,
                "show_system_monitor": True,
                "show_gpu_status": True,
                "show_cpu_status": True,
                "monitor_refresh_interval": 5000,
                "gpu_refresh_interval": 3000,
                "cpu_refresh_interval": 2000,
                "auto_start_monitoring": True,
                "auto_start_gpu_monitoring": True,
                "auto_start_cpu_monitoring": True,
                "max_recent_files": 10,
                "show_file_icons": True,
            },
        }

        self.main_config.set("ui", ui_config)
        logger.info("Initialized UI configuration in main config")

    def _load_from_main_config(self) -> None:
        """Load UI configurations from main config."""
        ui_config_raw: object = self.main_config.get("ui", {})

        # Type guard for ui_config
        if not isinstance(ui_config_raw, dict):
            logger.warning("Invalid ui_config type: %s, using empty dict", type(ui_config_raw))
            ui_config_raw = {}

        ui_config: dict[str, Any] = ui_config_raw

        # Load theme
        theme_data_raw: object = ui_config.get("theme", asdict(self.DEFAULT_THEMES["dark"]))
        # Handle case where theme_data is a string instead of dict
        if isinstance(theme_data_raw, str):
            theme_name: str = theme_data_raw.lower()
            if theme_name in self.DEFAULT_THEMES:
                theme_data: dict[str, Any] = asdict(self.DEFAULT_THEMES[theme_name])
            else:
                logger.warning("Unknown theme '%s', using dark theme", theme_name)
                theme_data = asdict(self.DEFAULT_THEMES["dark"])
        elif isinstance(theme_data_raw, dict):
            theme_data = theme_data_raw
        else:
            logger.warning("Invalid theme data type: %s, using dark theme", type(theme_data_raw))
            theme_data = asdict(self.DEFAULT_THEMES["dark"])
        self.theme = ThemeConfig(**theme_data)

        # Load font
        font_data_raw: object = ui_config.get("font", asdict(FontConfig()))
        if isinstance(font_data_raw, dict):
            font_data: dict[str, Any] = font_data_raw
        else:
            font_data = asdict(FontConfig())
        self.font = FontConfig(**font_data)

        # Load layout
        layout_data_raw: object = ui_config.get("layout", asdict(LayoutConfig()))
        if isinstance(layout_data_raw, dict):
            layout_data: dict[str, Any] = layout_data_raw
        else:
            layout_data = asdict(LayoutConfig())
        self.layout = LayoutConfig(**layout_data)

        # Load editor
        editor_data_raw: object = ui_config.get("editor", asdict(EditorConfig()))
        if isinstance(editor_data_raw, dict):
            editor_data: dict[str, Any] = editor_data_raw
        else:
            editor_data = asdict(EditorConfig())
        self.editor = EditorConfig(**editor_data)

        # Load animation
        animation_data_raw: object = ui_config.get("animation", asdict(AnimationConfig()))
        if isinstance(animation_data_raw, dict):
            animation_data: dict[str, Any] = animation_data_raw
        else:
            animation_data = asdict(AnimationConfig())
        self.animation = AnimationConfig(**animation_data)

        # Load accessibility
        accessibility_data_raw: object = ui_config.get("accessibility", asdict(AccessibilityConfig()))
        if isinstance(accessibility_data_raw, dict):
            accessibility_data: dict[str, Any] = accessibility_data_raw
        else:
            accessibility_data = asdict(AccessibilityConfig())
        self.accessibility = AccessibilityConfig(**accessibility_data)

        # Load custom themes
        self.custom_themes = {}
        custom_themes_data_raw: object = ui_config.get("custom_themes", {})
        if isinstance(custom_themes_data_raw, dict):
            custom_themes_data: dict[str, Any] = custom_themes_data_raw
            for name, theme_data_item in custom_themes_data.items():
                if isinstance(theme_data_item, dict):
                    self.custom_themes[name] = ThemeConfig(**theme_data_item)

    def _save_to_main_config(self) -> None:
        """Save UI configurations to main config."""
        ui_config = {
            "theme": asdict(self.theme),
            "font": asdict(self.font),
            "layout": asdict(self.layout),
            "editor": asdict(self.editor),
            "animation": asdict(self.animation),
            "accessibility": asdict(self.accessibility),
            "custom_themes": {name: asdict(theme) for name, theme in self.custom_themes.items()},
            # Preserve existing settings
            "recent_files": self.main_config.get("ui.recent_files", []),
            "dashboard": self.main_config.get("ui.dashboard", {}),
        }

        self.main_config.set("ui", ui_config)
        logger.debug("Saved UI configuration to main config")

    # Theme Management
    def get_theme_config(self) -> ThemeConfig:
        """Get current theme configuration."""
        return self.theme

    def set_theme(self, theme_name: str) -> bool:
        """Set the theme by name.

        Args:
            theme_name: Name of theme to apply

        Returns:
            True if theme was applied, False if theme not found

        """
        # Check default themes
        if theme_name in self.DEFAULT_THEMES:
            self.theme = self.DEFAULT_THEMES[theme_name]
            self._save_to_main_config()
            self._notify_change("theme")
            return True

        # Check custom themes
        if theme_name in self.custom_themes:
            self.theme = self.custom_themes[theme_name]
            self._save_to_main_config()
            self._notify_change("theme")
            return True

        logger.warning("Theme not found: %s", theme_name)
        return False

    def create_custom_theme(self, name: str, theme: ThemeConfig) -> None:
        """Create a custom theme."""
        self.custom_themes[name] = theme
        self._save_to_main_config()
        logger.info("Custom theme created: %s", name)

    # Font Management
    def get_font_config(self) -> FontConfig:
        """Get current font configuration."""
        return self.font

    def set_font_config(self, font_config: FontConfig) -> None:
        """Set font configuration."""
        self.font = font_config
        self._save_to_main_config()
        self._notify_change("font")

    # Layout Management
    def get_layout_config(self) -> LayoutConfig:
        """Get current layout configuration."""
        return self.layout

    def set_layout_config(self, layout_config: LayoutConfig) -> None:
        """Set layout configuration."""
        self.layout = layout_config
        self._save_to_main_config()
        self._notify_change("layout")

    # Editor Configuration
    def get_editor_config(self) -> EditorConfig:
        """Get current editor configuration."""
        return self.editor

    def set_editor_config(self, editor_config: EditorConfig) -> None:
        """Set editor configuration."""
        self.editor = editor_config
        self._save_to_main_config()
        self._notify_change("editor")

    # Animation Configuration
    def get_animation_config(self) -> AnimationConfig:
        """Get current animation configuration."""
        return self.animation

    def set_animation_config(self, animation_config: AnimationConfig) -> None:
        """Set animation configuration."""
        self.animation = animation_config
        self._save_to_main_config()
        self._notify_change("animation")

    # Accessibility Configuration
    def get_accessibility_config(self) -> AccessibilityConfig:
        """Get current accessibility configuration."""
        return self.accessibility

    def set_accessibility_config(self, accessibility_config: AccessibilityConfig) -> None:
        """Set accessibility configuration."""
        self.accessibility = accessibility_config
        self._save_to_main_config()
        self._notify_change("accessibility")

    # Generic Settings Access (for dashboard, etc.)
    def get_setting(self, key: str, default: object = None) -> object:
        """Get a UI setting from main config.

        Args:
            key: Dot-notation key (e.g., 'dashboard.max_recent_files')
            default: Default value if key not found

        Returns:
            Setting value or default

        """
        full_key = f"ui.{key}"
        return self.main_config.get(full_key, default)

    def set_setting(self, key: str, value: object) -> None:
        """Set a UI setting in main config.

        Args:
            key: Dot-notation key (e.g., 'dashboard.max_recent_files')
            value: Value to set

        """
        full_key = f"ui.{key}"
        self.main_config.set(full_key, value)

    # Change Notification System
    def register_callback(self, category: str, callback: Callable[[], None]) -> None:
        """Register a callback for configuration changes."""
        if category in self.change_callbacks:
            self.change_callbacks[category].append(callback)

    def unregister_callback(self, category: str, callback: Callable[[], None]) -> None:
        """Unregister a change callback."""
        if category in self.change_callbacks:
            with contextlib.suppress(ValueError):
                self.change_callbacks[category].remove(callback)

    def _notify_change(self, category: str) -> None:
        """Notify all registered callbacks of a change."""
        if category in self.change_callbacks:
            for callback in self.change_callbacks[category]:
                try:
                    callback()
                except Exception as e:
                    logger.exception("Error in change callback: %s", e)

    # Utility Methods
    def get_available_themes(self) -> list[str]:
        """Get list of available theme names."""
        themes = list(self.DEFAULT_THEMES.keys())
        themes.extend(self.custom_themes.keys())
        return themes

    def reset_to_defaults(self) -> None:
        """Reset all UI settings to defaults."""
        self.theme = self.DEFAULT_THEMES["dark"]
        self.font = FontConfig()
        self.layout = LayoutConfig()
        self.editor = EditorConfig()
        self.animation = AnimationConfig()
        self.accessibility = AccessibilityConfig()
        self.custom_themes = {}

        self._save_to_main_config()

        # Notify all categories
        for category in self.change_callbacks:
            self._notify_change(category)

        logger.info("UI settings reset to defaults")


# Singleton instance
_ui_config_manager: UIConfigManager | None = None


def get_ui_config_manager() -> UIConfigManager:
    """Get the singleton UIConfigManager instance.

    Returns:
        The UIConfigManager instance

    """
    global _ui_config_manager
    if _ui_config_manager is None:
        _ui_config_manager = UIConfigManager()
    return _ui_config_manager
