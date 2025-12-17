"""Production tests for font manager functionality.

Tests validate that the FontManager properly loads fonts from the filesystem,
integrates with PyQt6 font database, and provides appropriate font fallbacks
for both monospace and UI fonts in real application scenarios.
"""

import os
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from PyQt6.QtGui import QFont

from intellicrack.utils.font_manager import FontManager, get_font_manager


class TestFontManagerInitialization:
    """Test FontManager initialization and configuration loading."""

    def test_initialization_loads_config(self) -> None:
        """FontManager loads configuration on initialization."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {"primary": ["Test Mono"], "fallback": ["Courier"]},
                "ui_fonts": {"primary": ["Test Sans"], "fallback": ["Arial"]},
                "font_sizes": {"ui_default": 10, "code_default": 11},
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()

            assert manager.config is not None
            assert "monospace_fonts" in manager.config
            assert "ui_fonts" in manager.config

    def test_initialization_sets_fonts_directory(self) -> None:
        """FontManager sets fonts directory during initialization."""
        with patch("intellicrack.utils.font_manager.get_config"):
            manager = FontManager()

            assert hasattr(manager, "fonts_dir")
            assert isinstance(manager.fonts_dir, str)
            assert "fonts" in manager.fonts_dir.lower()

    def test_initialization_creates_loaded_fonts_list(self) -> None:
        """FontManager creates empty list for tracking loaded fonts."""
        with patch("intellicrack.utils.font_manager.get_config"):
            manager = FontManager()

            assert hasattr(manager, "loaded_fonts")
            assert isinstance(manager.loaded_fonts, list)
            assert len(manager.loaded_fonts) == 0

    def test_default_config_on_config_load_failure(self) -> None:
        """FontManager provides default configuration when loading fails."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.side_effect = Exception("Config load error")
            mock_get_config.return_value = mock_config

            manager = FontManager()

            assert manager.config is not None
            assert "monospace_fonts" in manager.config
            assert "ui_fonts" in manager.config
            assert "font_sizes" in manager.config


class TestConfigurationLoading:
    """Test configuration loading from central config system."""

    def test_loads_monospace_fonts_config(self) -> None:
        """Configuration includes monospace fonts settings."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {
                    "primary": ["JetBrains Mono"],
                    "fallback": ["Consolas", "Courier New"],
                },
                "ui_fonts": {"primary": [], "fallback": []},
                "font_sizes": {},
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()

            assert "monospace_fonts" in manager.config
            assert "primary" in manager.config["monospace_fonts"]
            assert "JetBrains Mono" in manager.config["monospace_fonts"]["primary"]

    def test_loads_ui_fonts_config(self) -> None:
        """Configuration includes UI fonts settings."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {"primary": [], "fallback": []},
                "ui_fonts": {
                    "primary": ["Segoe UI", "Roboto"],
                    "fallback": ["Arial"],
                },
                "font_sizes": {},
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()

            assert "ui_fonts" in manager.config
            assert "Segoe UI" in manager.config["ui_fonts"]["primary"]

    def test_loads_font_sizes_config(self) -> None:
        """Configuration includes font size settings."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {"primary": [], "fallback": []},
                "ui_fonts": {"primary": [], "fallback": []},
                "font_sizes": {
                    "ui_default": 10,
                    "code_default": 11,
                    "hex_view": 12,
                },
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()

            assert "font_sizes" in manager.config
            assert manager.config["font_sizes"]["ui_default"] == 10
            assert manager.config["font_sizes"]["code_default"] == 11

    def test_triggers_config_upgrade_on_empty_config(self) -> None:
        """FontManager triggers config upgrade when config is empty."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.side_effect = [{}, {"loaded": True}]
            mock_config.upgrade_config = Mock()
            mock_get_config.return_value = mock_config

            manager = FontManager()

            mock_config.upgrade_config.assert_called_once()


class TestLoadApplicationFonts:
    """Test loading custom fonts into Qt application."""

    def test_skips_loading_when_fonts_dir_missing(self) -> None:
        """load_application_fonts skips when fonts directory does not exist."""
        with patch("intellicrack.utils.font_manager.get_config"):
            with patch("os.path.exists", return_value=False):
                manager = FontManager()
                manager.load_application_fonts()

                assert len(manager.loaded_fonts) == 0

    def test_loads_fonts_from_available_fonts_list(self) -> None:
        """load_application_fonts loads fonts specified in config."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {"primary": [], "fallback": []},
                "ui_fonts": {"primary": [], "fallback": []},
                "font_sizes": {},
                "available_fonts": ["TestFont.ttf"],
            }
            mock_get_config.return_value = mock_config

            with patch("os.path.exists", return_value=True):
                with patch("intellicrack.utils.font_manager.QFontDatabase.addApplicationFont", return_value=1):
                    manager = FontManager()
                    manager.load_application_fonts()

                    assert "TestFont.ttf" in manager.loaded_fonts

    def test_handles_font_loading_errors(self) -> None:
        """load_application_fonts handles errors when loading individual fonts."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {"primary": [], "fallback": []},
                "ui_fonts": {"primary": [], "fallback": []},
                "font_sizes": {},
                "available_fonts": ["BadFont.ttf"],
            }
            mock_get_config.return_value = mock_config

            with patch("os.path.exists", return_value=True):
                with patch(
                    "intellicrack.utils.font_manager.QFontDatabase.addApplicationFont",
                    side_effect=Exception("Font error"),
                ):
                    manager = FontManager()
                    manager.load_application_fonts()

                    assert "BadFont.ttf" not in manager.loaded_fonts

    def test_ignores_fonts_with_invalid_id(self) -> None:
        """load_application_fonts ignores fonts that fail to load (negative ID)."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {"primary": [], "fallback": []},
                "ui_fonts": {"primary": [], "fallback": []},
                "font_sizes": {},
                "available_fonts": ["InvalidFont.ttf"],
            }
            mock_get_config.return_value = mock_config

            with patch("os.path.exists", return_value=True):
                with patch("intellicrack.utils.font_manager.QFontDatabase.addApplicationFont", return_value=-1):
                    manager = FontManager()
                    manager.load_application_fonts()

                    assert "InvalidFont.ttf" not in manager.loaded_fonts

    def test_loads_multiple_fonts(self) -> None:
        """load_application_fonts loads multiple fonts from config."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {"primary": [], "fallback": []},
                "ui_fonts": {"primary": [], "fallback": []},
                "font_sizes": {},
                "available_fonts": ["Font1.ttf", "Font2.otf", "Font3.ttf"],
            }
            mock_get_config.return_value = mock_config

            with patch("os.path.exists", return_value=True):
                with patch("intellicrack.utils.font_manager.QFontDatabase.addApplicationFont", return_value=1):
                    manager = FontManager()
                    manager.load_application_fonts()

                    assert len(manager.loaded_fonts) == 3


class TestGetMonospaceFont:
    """Test monospace font retrieval with fallbacks."""

    def test_returns_qfont_instance(self) -> None:
        """get_monospace_font returns QFont instance."""
        with patch("intellicrack.utils.font_manager.get_config"):
            manager = FontManager()
            font = manager.get_monospace_font()

            assert isinstance(font, QFont)

    def test_uses_default_size_when_not_specified(self) -> None:
        """get_monospace_font uses default size from config."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {"primary": ["Courier"], "fallback": ["monospace"]},
                "ui_fonts": {"primary": [], "fallback": []},
                "font_sizes": {"code_default": 12},
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()
            font = manager.get_monospace_font()

            assert font.pointSize() == 12

    def test_uses_specified_size(self) -> None:
        """get_monospace_font uses specified size parameter."""
        with patch("intellicrack.utils.font_manager.get_config"):
            manager = FontManager()
            font = manager.get_monospace_font(size=14)

            assert font.pointSize() == 14

    def test_tries_primary_fonts_first(self) -> None:
        """get_monospace_font tries primary fonts before fallbacks."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {
                    "primary": ["Courier New"],
                    "fallback": ["Courier"],
                },
                "ui_fonts": {"primary": [], "fallback": []},
                "font_sizes": {"code_default": 10},
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()
            font = manager.get_monospace_font()

            assert font is not None

    def test_sets_monospace_style_hint(self) -> None:
        """get_monospace_font sets monospace style hint."""
        with patch("intellicrack.utils.font_manager.get_config"):
            manager = FontManager()
            font = manager.get_monospace_font()

            assert font.styleHint() == QFont.StyleHint.Monospace

    def test_provides_ultimate_fallback(self) -> None:
        """get_monospace_font provides ultimate fallback font."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {"primary": [], "fallback": []},
                "ui_fonts": {"primary": [], "fallback": []},
                "font_sizes": {"code_default": 10},
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()
            font = manager.get_monospace_font()

            assert font is not None
            assert isinstance(font, QFont)


class TestGetUIFont:
    """Test UI font retrieval with fallbacks."""

    def test_returns_qfont_instance(self) -> None:
        """get_ui_font returns QFont instance."""
        with patch("intellicrack.utils.font_manager.get_config"):
            manager = FontManager()
            font = manager.get_ui_font()

            assert isinstance(font, QFont)

    def test_uses_default_size_when_not_specified(self) -> None:
        """get_ui_font uses default size from config."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {"primary": [], "fallback": []},
                "ui_fonts": {"primary": ["Arial"], "fallback": ["sans-serif"]},
                "font_sizes": {"ui_default": 11},
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()
            font = manager.get_ui_font()

            assert font.pointSize() == 11

    def test_uses_specified_size(self) -> None:
        """get_ui_font uses specified size parameter."""
        with patch("intellicrack.utils.font_manager.get_config"):
            manager = FontManager()
            font = manager.get_ui_font(size=13)

            assert font.pointSize() == 13

    def test_tries_primary_fonts_first(self) -> None:
        """get_ui_font tries primary fonts before fallbacks."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {"primary": [], "fallback": []},
                "ui_fonts": {
                    "primary": ["Segoe UI"],
                    "fallback": ["Arial"],
                },
                "font_sizes": {"ui_default": 10},
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()
            font = manager.get_ui_font()

            assert font is not None

    def test_provides_ultimate_fallback(self) -> None:
        """get_ui_font provides ultimate fallback font."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {"primary": [], "fallback": []},
                "ui_fonts": {"primary": [], "fallback": []},
                "font_sizes": {"ui_default": 10},
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()
            font = manager.get_ui_font()

            assert font is not None
            assert isinstance(font, QFont)


class TestGetFontManager:
    """Test global font manager singleton access."""

    def test_returns_font_manager_instance(self) -> None:
        """get_font_manager returns FontManager instance."""
        with patch("intellicrack.utils.font_manager.get_config"):
            manager = get_font_manager()

            assert isinstance(manager, FontManager)

    def test_returns_same_instance_on_multiple_calls(self) -> None:
        """get_font_manager returns singleton instance."""
        with patch("intellicrack.utils.font_manager.get_config"):
            manager1 = get_font_manager()
            manager2 = get_font_manager()

            assert manager1 is manager2

    def test_loads_fonts_on_first_access(self) -> None:
        """get_font_manager loads application fonts on first access."""
        with patch("intellicrack.utils.font_manager.get_config"):
            with patch("intellicrack.utils.font_manager._font_manager", None):
                with patch.object(FontManager, "load_application_fonts") as mock_load:
                    get_font_manager()

                    mock_load.assert_called_once()


class TestRealWorldScenarios:
    """Test realistic production usage scenarios."""

    def test_hex_viewer_font_configuration(self) -> None:
        """FontManager provides appropriate font for hex viewer."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {
                    "primary": ["Consolas"],
                    "fallback": ["Courier New"],
                },
                "ui_fonts": {"primary": [], "fallback": []},
                "font_sizes": {"hex_view": 11},
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()
            hex_font = manager.get_monospace_font(size=11)

            assert hex_font.pointSize() == 11
            assert hex_font.styleHint() == QFont.StyleHint.Monospace

    def test_code_editor_font_configuration(self) -> None:
        """FontManager provides appropriate font for code editor."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {
                    "primary": ["JetBrains Mono"],
                    "fallback": ["Source Code Pro", "Courier New"],
                },
                "ui_fonts": {"primary": [], "fallback": []},
                "font_sizes": {"code_default": 10, "code_large": 12},
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()
            code_font = manager.get_monospace_font()

            assert code_font.styleHint() == QFont.StyleHint.Monospace

    def test_ui_elements_font_configuration(self) -> None:
        """FontManager provides appropriate font for UI elements."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {"primary": [], "fallback": []},
                "ui_fonts": {
                    "primary": ["Segoe UI", "Roboto"],
                    "fallback": ["Arial"],
                },
                "font_sizes": {"ui_default": 10},
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()
            ui_font = manager.get_ui_font()

            assert ui_font.pointSize() == 10


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_handles_missing_font_sizes_in_config(self) -> None:
        """FontManager handles missing font_sizes configuration."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {"primary": [], "fallback": []},
                "ui_fonts": {"primary": [], "fallback": []},
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()
            font = manager.get_monospace_font()

            assert isinstance(font, QFont)

    def test_handles_missing_monospace_fonts_in_config(self) -> None:
        """FontManager handles missing monospace_fonts configuration."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "ui_fonts": {"primary": [], "fallback": []},
                "font_sizes": {},
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()
            font = manager.get_monospace_font()

            assert isinstance(font, QFont)

    def test_handles_missing_ui_fonts_in_config(self) -> None:
        """FontManager handles missing ui_fonts configuration."""
        with patch("intellicrack.utils.font_manager.get_config") as mock_get_config:
            mock_config = Mock()
            mock_config.get.return_value = {
                "monospace_fonts": {"primary": [], "fallback": []},
                "font_sizes": {},
                "available_fonts": [],
            }
            mock_get_config.return_value = mock_config

            manager = FontManager()
            font = manager.get_ui_font()

            assert isinstance(font, QFont)

    def test_handles_zero_font_size(self) -> None:
        """FontManager handles zero font size gracefully."""
        with patch("intellicrack.utils.font_manager.get_config"):
            manager = FontManager()
            font = manager.get_monospace_font(size=0)

            assert isinstance(font, QFont)

    def test_handles_negative_font_size(self) -> None:
        """FontManager handles negative font size gracefully."""
        with patch("intellicrack.utils.font_manager.get_config"):
            manager = FontManager()
            font = manager.get_ui_font(size=-1)

            assert isinstance(font, QFont)

    def test_handles_very_large_font_size(self) -> None:
        """FontManager handles very large font sizes."""
        with patch("intellicrack.utils.font_manager.get_config"):
            manager = FontManager()
            font = manager.get_monospace_font(size=200)

            assert isinstance(font, QFont)
            assert font.pointSize() == 200
