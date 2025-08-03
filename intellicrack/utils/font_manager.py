"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Font loader utility for Intellicrack
"""

import json
import logging
import os

from PyQt6.QtGui import QFont, QFontDatabase

logger = logging.getLogger(__name__)

class FontManager:
    """Manages custom font loading and configuration for the application."""
    def __init__(self):
        """Initialize the font manager with configuration and setup font directories."""
        self.fonts_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "fonts")
        self.config_file = os.path.join(self.fonts_dir, "font_config.json")
        self.loaded_fonts = []
        self.config = self._load_config()

    def _load_config(self):
        """Load font configuration"""
        try:
            with open(self.config_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load font config: {e}")
            return {}

    def load_application_fonts(self):
        """Load custom fonts into Qt application"""
        if not os.path.exists(self.fonts_dir):
            return

        for font_file in self.config.get("available_fonts", []):
            font_path = os.path.join(self.fonts_dir, font_file)
            if os.path.exists(font_path):
                try:
                    font_id = QFontDatabase.addApplicationFont(font_path)
                    if font_id >= 0:
                        self.loaded_fonts.append(font_file)
                        logger.info(f"Loaded font: {font_file}")
                except Exception as e:
                    logger.warning(f"Failed to load font {font_file}: {e}")

    def get_monospace_font(self, size=None):
        """Get the best available monospace font"""
        if size is None:
            size = self.config.get("font_sizes", {}).get("code_default", 10)

        # Try primary fonts first
        for font_name in self.config.get("monospace_fonts", {}).get("primary", []):
            font = QFont(font_name, size)
            if font.exactMatch():
                font.setStyleHint(QFont.Monospace)
                return font

        # Try fallback fonts
        for font_name in self.config.get("monospace_fonts", {}).get("fallback", []):
            font = QFont(font_name, size)
            font.setStyleHint(QFont.Monospace)
            # Return first available fallback
            return font

        # Ultimate fallback
        font = QFont("monospace", size)
        font.setStyleHint(QFont.Monospace)
        return font

    def get_ui_font(self, size=None):
        """Get the best available UI font"""
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
_font_manager = None

def get_font_manager():
    """Get or create the global font manager"""
    global _font_manager
    if _font_manager is None:
        _font_manager = FontManager()
        _font_manager.load_application_fonts()
    return _font_manager
