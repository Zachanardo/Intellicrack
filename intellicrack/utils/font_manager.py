"""Font manager for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.

Font loader utility for Intellicrack
"""

import logging
import os
from typing import Any

from PyQt6.QtGui import QFont, QFontDatabase

from intellicrack.utils.resource_helper import get_resource_path


logger = logging.getLogger(__name__)


class FontManager:
    """Manages custom font loading and configuration for the application."""

    def __init__(self) -> None:
        """Initialize the font manager with configuration and setup font directories."""
        from intellicrack.core.config_manager import get_config

        self.fonts_dir: str = get_resource_path("assets/fonts")
        self.loaded_fonts: list[str] = []
        # Load configuration from central config system
        self.central_config = get_config()
        self.config: dict[str, Any] = self._load_config()

    def _load_config(self) -> dict[str, Any]:
        """Load font configuration from central config system.

        Returns:
            dict[str, Any]: Font configuration dictionary with
                monospace_fonts, ui_fonts, and font_sizes keys. Returns
                default font configuration if central config is unavailable.
        """
        try:
            # Get font configuration from central config
            font_config: Any = self.central_config.get("font_configuration", {})
            if not font_config:
                # If central config is empty, try to trigger migration
                self.central_config.upgrade_config()
                font_config = self.central_config.get("font_configuration", {})
            return font_config if isinstance(font_config, dict) else {}
        except Exception as e:
            logger.warning("Could not load font config from central config: %s", e, exc_info=True)
            # Return default configuration structure
            return {
                "monospace_fonts": {
                    "primary": ["JetBrains Mono", "JetBrainsMono-Regular"],
                    "fallback": ["Consolas", "Source Code Pro", "Courier New", "monospace"],
                },
                "ui_fonts": {
                    "primary": ["Segoe UI", "Roboto", "Arial"],
                    "fallback": ["Helvetica Neue", "Helvetica", "Ubuntu", "sans-serif"],
                },
                "font_sizes": {
                    "ui_default": 10,
                    "ui_small": 9,
                    "ui_large": 12,
                    "code_default": 10,
                    "code_small": 9,
                    "code_large": 11,
                    "hex_view": 11,
                },
                "available_fonts": [],
            }

    def load_application_fonts(self) -> None:
        """Load custom fonts into Qt application.

        Returns:
            None.
        """
        if not os.path.exists(self.fonts_dir):
            return

        for font_file in self.config.get("available_fonts", []):
            font_path = os.path.join(self.fonts_dir, font_file)
            if os.path.exists(font_path):
                try:
                    font_id = QFontDatabase.addApplicationFont(font_path)
                    if font_id >= 0:
                        self.loaded_fonts.append(font_file)
                        logger.info("Loaded font: %s", font_file)
                except Exception as e:
                    logger.warning("Failed to load font %s: %s", font_file, e, exc_info=True)

    def get_monospace_font(self, size: int | None = None) -> QFont:
        """Get the best available monospace font.

        Args:
            size: Font size in points. If None, uses code_default from
                configuration. Defaults to None.

        Returns:
            QFont: QFont object configured with the best available monospace
                font. Returns system monospace font as ultimate fallback.
        """
        if size is None:
            size = self.config.get("font_sizes", {}).get("code_default", 10)

        # Try primary fonts first
        for font_name in self.config.get("monospace_fonts", {}).get("primary", []):
            font = QFont(font_name, size)
            if font.exactMatch():
                font.setStyleHint(QFont.StyleHint.Monospace)
                return font

        # Try fallback fonts
        for font_name in self.config.get("monospace_fonts", {}).get("fallback", []):
            font = QFont(font_name, size)
            font.setStyleHint(QFont.StyleHint.Monospace)
            # Return first available fallback
            return font

        # Ultimate fallback
        font = QFont("monospace", size)
        font.setStyleHint(QFont.StyleHint.Monospace)
        return font

    def get_ui_font(self, size: int | None = None) -> QFont:
        """Get the best available UI font.

        Args:
            size: Font size in points. If None, uses ui_default from
                configuration. Defaults to None.

        Returns:
            QFont: QFont object configured with the best available UI font.
                Returns system sans-serif font as ultimate fallback.
        """
        if size is None:
            size = self.config.get("font_sizes", {}).get("ui_default", 10)

        # Try primary fonts first
        for font_name in self.config.get("ui_fonts", {}).get("primary", []):
            font = QFont(font_name, size)
            if font.exactMatch():
                return font

        # Try fallback fonts
        for font_name in self.config.get("ui_fonts", {}).get("fallback", []):
            font = QFont(font_name, size)
            # Return first available fallback
            return font

        # Ultimate fallback
        return QFont("sans-serif", size)


# Global font manager instance
_font_manager: FontManager | None = None


def get_font_manager() -> FontManager:
    """Get or create the global font manager.

    Returns:
        FontManager: Global singleton FontManager instance, loading
            application fonts on first access.
    """
    global _font_manager
    if _font_manager is None:
        _font_manager = FontManager()
        _font_manager.load_application_fonts()
    return _font_manager
