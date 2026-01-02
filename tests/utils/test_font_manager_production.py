"""Production tests for font manager functionality.

Tests validate that the FontManager properly loads fonts from the filesystem,
integrates with PyQt6 font database, and provides appropriate font fallbacks
for both monospace and UI fonts in real application scenarios.
"""

import os
from pathlib import Path
from typing import Any

import pytest
from PyQt6.QtGui import QFont

from intellicrack.utils.font_manager import FontManager, get_font_manager


class FakeConfig:
    """Real test double for config manager that stores and returns configuration."""

    def __init__(self, config_data: dict[str, Any] | None = None) -> None:
        self.config_data: dict[str, Any] = config_data if config_data is not None else {}
        self.upgrade_called: bool = False
        self.get_calls: list[tuple[str, Any]] = []

    def get(self, key: str, default: Any = None) -> Any:
        self.get_calls.append((key, default))
        if key in self.config_data:
            value = self.config_data[key]
            if isinstance(value, Exception):
                raise value
            return value
        return default

    def upgrade_config(self) -> None:
        self.upgrade_called = True


class FakeQFontDatabase:
    """Real test double for QFontDatabase that simulates font loading."""

    def __init__(self, font_id: int = 1, raise_exception: bool = False) -> None:
        self.font_id: int = font_id
        self.raise_exception: bool = raise_exception
        self.loaded_fonts: list[str] = []

    def addApplicationFont(self, font_path: str) -> int:
        if self.raise_exception:
            raise Exception("Font error")
        self.loaded_fonts.append(font_path)
        return self.font_id


class FakePathExists:
    """Real test double for os.path.exists that controls file existence checks."""

    def __init__(self, exists: bool = True, existing_paths: set[str] | None = None) -> None:
        self.exists: bool = exists
        self.existing_paths: set[str] = existing_paths if existing_paths is not None else set()
        self.checked_paths: list[str] = []

    def __call__(self, path: str) -> bool:
        self.checked_paths.append(path)
        if self.existing_paths:
            return path in self.existing_paths
        return self.exists


def create_test_font_config(
    monospace_primary: list[str] | None = None,
    monospace_fallback: list[str] | None = None,
    ui_primary: list[str] | None = None,
    ui_fallback: list[str] | None = None,
    font_sizes: dict[str, int] | None = None,
    available_fonts: list[str] | None = None,
) -> dict[str, Any]:
    """Create a test font configuration with sensible defaults."""
    return {
        "monospace_fonts": {
            "primary": monospace_primary if monospace_primary is not None else [],
            "fallback": monospace_fallback if monospace_fallback is not None else [],
        },
        "ui_fonts": {
            "primary": ui_primary if ui_primary is not None else [],
            "fallback": ui_fallback if ui_fallback is not None else [],
        },
        "font_sizes": font_sizes if font_sizes is not None else {},
        "available_fonts": available_fonts if available_fonts is not None else [],
    }


class TestFontManagerInitialization:
    """Test FontManager initialization and configuration loading."""

    def test_initialization_loads_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FontManager loads configuration on initialization."""
        config_data = {
            "font_configuration": create_test_font_config(
                monospace_primary=["Test Mono"],
                monospace_fallback=["Courier"],
                ui_primary=["Test Sans"],
                ui_fallback=["Arial"],
                font_sizes={"ui_default": 10, "code_default": 11},
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()

        assert manager.config is not None
        assert "monospace_fonts" in manager.config
        assert "ui_fonts" in manager.config

    def test_initialization_sets_fonts_directory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FontManager sets fonts directory during initialization."""
        fake_config = FakeConfig({"font_configuration": create_test_font_config()})

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()

        assert hasattr(manager, "fonts_dir")
        assert isinstance(manager.fonts_dir, str)
        assert "fonts" in manager.fonts_dir.lower()

    def test_initialization_creates_loaded_fonts_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FontManager creates empty list for tracking loaded fonts."""
        fake_config = FakeConfig({"font_configuration": create_test_font_config()})

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()

        assert hasattr(manager, "loaded_fonts")
        assert isinstance(manager.loaded_fonts, list)
        assert len(manager.loaded_fonts) == 0

    def test_default_config_on_config_load_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FontManager provides default configuration when loading fails."""
        fake_config = FakeConfig({"font_configuration": Exception("Config load error")})

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()

        assert manager.config is not None
        assert "monospace_fonts" in manager.config
        assert "ui_fonts" in manager.config
        assert "font_sizes" in manager.config


class TestConfigurationLoading:
    """Test configuration loading from central config system."""

    def test_loads_monospace_fonts_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Configuration includes monospace fonts settings."""
        config_data = {
            "font_configuration": create_test_font_config(
                monospace_primary=["JetBrains Mono"],
                monospace_fallback=["Consolas", "Courier New"],
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()

        assert "monospace_fonts" in manager.config
        assert "primary" in manager.config["monospace_fonts"]
        assert "JetBrains Mono" in manager.config["monospace_fonts"]["primary"]

    def test_loads_ui_fonts_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Configuration includes UI fonts settings."""
        config_data = {
            "font_configuration": create_test_font_config(
                ui_primary=["Segoe UI", "Roboto"],
                ui_fallback=["Arial"],
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()

        assert "ui_fonts" in manager.config
        assert "Segoe UI" in manager.config["ui_fonts"]["primary"]

    def test_loads_font_sizes_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Configuration includes font size settings."""
        config_data = {
            "font_configuration": create_test_font_config(
                font_sizes={
                    "ui_default": 10,
                    "code_default": 11,
                    "hex_view": 12,
                }
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()

        assert "font_sizes" in manager.config
        assert manager.config["font_sizes"]["ui_default"] == 10
        assert manager.config["font_sizes"]["code_default"] == 11

    def test_triggers_config_upgrade_on_empty_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FontManager triggers config upgrade when config is empty."""
        fake_config = FakeConfig({})

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()

        assert fake_config.upgrade_called


class TestLoadApplicationFonts:
    """Test loading custom fonts into Qt application."""

    def test_skips_loading_when_fonts_dir_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """load_application_fonts skips when fonts directory does not exist."""
        fake_config = FakeConfig({"font_configuration": create_test_font_config()})

        def fake_get_config() -> FakeConfig:
            return fake_config

        fake_exists = FakePathExists(exists=False)

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)
        monkeypatch.setattr("os.path.exists", fake_exists)

        manager = FontManager()
        manager.load_application_fonts()

        assert len(manager.loaded_fonts) == 0

    def test_loads_fonts_from_available_fonts_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """load_application_fonts loads fonts specified in config."""
        config_data = {
            "font_configuration": create_test_font_config(
                available_fonts=["TestFont.ttf"]
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        fake_exists = FakePathExists(exists=True)
        fake_font_db = FakeQFontDatabase(font_id=1)

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)
        monkeypatch.setattr("os.path.exists", fake_exists)
        monkeypatch.setattr("intellicrack.utils.font_manager.QFontDatabase.addApplicationFont", fake_font_db.addApplicationFont)

        manager = FontManager()
        manager.load_application_fonts()

        assert "TestFont.ttf" in manager.loaded_fonts

    def test_handles_font_loading_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """load_application_fonts handles errors when loading individual fonts."""
        config_data = {
            "font_configuration": create_test_font_config(
                available_fonts=["BadFont.ttf"]
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        fake_exists = FakePathExists(exists=True)
        fake_font_db = FakeQFontDatabase(raise_exception=True)

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)
        monkeypatch.setattr("os.path.exists", fake_exists)
        monkeypatch.setattr("intellicrack.utils.font_manager.QFontDatabase.addApplicationFont", fake_font_db.addApplicationFont)

        manager = FontManager()
        manager.load_application_fonts()

        assert "BadFont.ttf" not in manager.loaded_fonts

    def test_ignores_fonts_with_invalid_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """load_application_fonts ignores fonts that fail to load (negative ID)."""
        config_data = {
            "font_configuration": create_test_font_config(
                available_fonts=["InvalidFont.ttf"]
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        fake_exists = FakePathExists(exists=True)
        fake_font_db = FakeQFontDatabase(font_id=-1)

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)
        monkeypatch.setattr("os.path.exists", fake_exists)
        monkeypatch.setattr("intellicrack.utils.font_manager.QFontDatabase.addApplicationFont", fake_font_db.addApplicationFont)

        manager = FontManager()
        manager.load_application_fonts()

        assert "InvalidFont.ttf" not in manager.loaded_fonts

    def test_loads_multiple_fonts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """load_application_fonts loads multiple fonts from config."""
        config_data = {
            "font_configuration": create_test_font_config(
                available_fonts=["Font1.ttf", "Font2.otf", "Font3.ttf"]
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        fake_exists = FakePathExists(exists=True)
        fake_font_db = FakeQFontDatabase(font_id=1)

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)
        monkeypatch.setattr("os.path.exists", fake_exists)
        monkeypatch.setattr("intellicrack.utils.font_manager.QFontDatabase.addApplicationFont", fake_font_db.addApplicationFont)

        manager = FontManager()
        manager.load_application_fonts()

        assert len(manager.loaded_fonts) == 3


class TestGetMonospaceFont:
    """Test monospace font retrieval with fallbacks."""

    def test_returns_qfont_instance(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_monospace_font returns QFont instance."""
        fake_config = FakeConfig({"font_configuration": create_test_font_config()})

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_monospace_font()

        assert isinstance(font, QFont)

    def test_uses_default_size_when_not_specified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_monospace_font uses default size from config."""
        config_data = {
            "font_configuration": create_test_font_config(
                monospace_primary=["Courier"],
                monospace_fallback=["monospace"],
                font_sizes={"code_default": 12},
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_monospace_font()

        assert font.pointSize() == 12

    def test_uses_specified_size(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_monospace_font uses specified size parameter."""
        fake_config = FakeConfig({"font_configuration": create_test_font_config()})

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_monospace_font(size=14)

        assert font.pointSize() == 14

    def test_tries_primary_fonts_first(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_monospace_font tries primary fonts before fallbacks."""
        config_data = {
            "font_configuration": create_test_font_config(
                monospace_primary=["Courier New"],
                monospace_fallback=["Courier"],
                font_sizes={"code_default": 10},
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_monospace_font()

        assert font is not None

    def test_sets_monospace_style_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_monospace_font sets monospace style hint."""
        fake_config = FakeConfig({"font_configuration": create_test_font_config()})

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_monospace_font()

        assert font.styleHint() == QFont.StyleHint.Monospace

    def test_provides_ultimate_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_monospace_font provides ultimate fallback font."""
        config_data = {
            "font_configuration": create_test_font_config(
                font_sizes={"code_default": 10}
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_monospace_font()

        assert font is not None
        assert isinstance(font, QFont)


class TestGetUIFont:
    """Test UI font retrieval with fallbacks."""

    def test_returns_qfont_instance(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_ui_font returns QFont instance."""
        fake_config = FakeConfig({"font_configuration": create_test_font_config()})

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_ui_font()

        assert isinstance(font, QFont)

    def test_uses_default_size_when_not_specified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_ui_font uses default size from config."""
        config_data = {
            "font_configuration": create_test_font_config(
                ui_primary=["Arial"],
                ui_fallback=["sans-serif"],
                font_sizes={"ui_default": 11},
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_ui_font()

        assert font.pointSize() == 11

    def test_uses_specified_size(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_ui_font uses specified size parameter."""
        fake_config = FakeConfig({"font_configuration": create_test_font_config()})

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_ui_font(size=13)

        assert font.pointSize() == 13

    def test_tries_primary_fonts_first(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_ui_font tries primary fonts before fallbacks."""
        config_data = {
            "font_configuration": create_test_font_config(
                ui_primary=["Segoe UI"],
                ui_fallback=["Arial"],
                font_sizes={"ui_default": 10},
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_ui_font()

        assert font is not None

    def test_provides_ultimate_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_ui_font provides ultimate fallback font."""
        config_data = {
            "font_configuration": create_test_font_config(
                font_sizes={"ui_default": 10}
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_ui_font()

        assert font is not None
        assert isinstance(font, QFont)


class TestGetFontManager:
    """Test global font manager singleton access."""

    def test_returns_font_manager_instance(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_font_manager returns FontManager instance."""
        fake_config = FakeConfig({"font_configuration": create_test_font_config()})

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)
        monkeypatch.setattr("intellicrack.utils.font_manager._font_manager", None)

        manager = get_font_manager()

        assert isinstance(manager, FontManager)

    def test_returns_same_instance_on_multiple_calls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_font_manager returns singleton instance."""
        fake_config = FakeConfig({"font_configuration": create_test_font_config()})

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)
        monkeypatch.setattr("intellicrack.utils.font_manager._font_manager", None)

        manager1 = get_font_manager()
        manager2 = get_font_manager()

        assert manager1 is manager2

    def test_loads_fonts_on_first_access(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_font_manager loads application fonts on first access."""
        fake_config = FakeConfig({"font_configuration": create_test_font_config()})

        def fake_get_config() -> FakeConfig:
            return fake_config

        load_called: list[bool] = []

        original_load = FontManager.load_application_fonts

        def tracked_load(self: FontManager) -> None:
            load_called.append(True)
            original_load(self)

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)
        monkeypatch.setattr("intellicrack.utils.font_manager._font_manager", None)
        monkeypatch.setattr(FontManager, "load_application_fonts", tracked_load)

        get_font_manager()

        assert len(load_called) == 1


class TestRealWorldScenarios:
    """Test realistic production usage scenarios."""

    def test_hex_viewer_font_configuration(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FontManager provides appropriate font for hex viewer."""
        config_data = {
            "font_configuration": create_test_font_config(
                monospace_primary=["Consolas"],
                monospace_fallback=["Courier New"],
                font_sizes={"hex_view": 11},
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        hex_font = manager.get_monospace_font(size=11)

        assert hex_font.pointSize() == 11
        assert hex_font.styleHint() == QFont.StyleHint.Monospace

    def test_code_editor_font_configuration(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FontManager provides appropriate font for code editor."""
        config_data = {
            "font_configuration": create_test_font_config(
                monospace_primary=["JetBrains Mono"],
                monospace_fallback=["Source Code Pro", "Courier New"],
                font_sizes={"code_default": 10, "code_large": 12},
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        code_font = manager.get_monospace_font()

        assert code_font.styleHint() == QFont.StyleHint.Monospace

    def test_ui_elements_font_configuration(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FontManager provides appropriate font for UI elements."""
        config_data = {
            "font_configuration": create_test_font_config(
                ui_primary=["Segoe UI", "Roboto"],
                ui_fallback=["Arial"],
                font_sizes={"ui_default": 10},
            )
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        ui_font = manager.get_ui_font()

        assert ui_font.pointSize() == 10


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_handles_missing_font_sizes_in_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FontManager handles missing font_sizes configuration."""
        config_data = {
            "font_configuration": create_test_font_config()
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_monospace_font()

        assert isinstance(font, QFont)

    def test_handles_missing_monospace_fonts_in_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FontManager handles missing monospace_fonts configuration."""
        config_data = {
            "font_configuration": {
                "ui_fonts": {"primary": [], "fallback": []},
                "font_sizes": {},
                "available_fonts": [],
            }
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_monospace_font()

        assert isinstance(font, QFont)

    def test_handles_missing_ui_fonts_in_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FontManager handles missing ui_fonts configuration."""
        config_data = {
            "font_configuration": {
                "monospace_fonts": {"primary": [], "fallback": []},
                "font_sizes": {},
                "available_fonts": [],
            }
        }
        fake_config = FakeConfig(config_data)

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_ui_font()

        assert isinstance(font, QFont)

    def test_handles_zero_font_size(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FontManager handles zero font size gracefully."""
        fake_config = FakeConfig({"font_configuration": create_test_font_config()})

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_monospace_font(size=0)

        assert isinstance(font, QFont)

    def test_handles_negative_font_size(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FontManager handles negative font size gracefully."""
        fake_config = FakeConfig({"font_configuration": create_test_font_config()})

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_ui_font(size=-1)

        assert isinstance(font, QFont)

    def test_handles_very_large_font_size(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FontManager handles very large font sizes."""
        fake_config = FakeConfig({"font_configuration": create_test_font_config()})

        def fake_get_config() -> FakeConfig:
            return fake_config

        monkeypatch.setattr("intellicrack.utils.font_manager.get_config", fake_get_config)

        manager = FontManager()
        font = manager.get_monospace_font(size=200)

        assert isinstance(font, QFont)
        assert font.pointSize() == 200
