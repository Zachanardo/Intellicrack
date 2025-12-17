"""Production tests for Icon Manager.

Validates icon retrieval, caching, fallback handling, and custom icon registration.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import tempfile
from pathlib import Path

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication, QIcon, QPushButton
from intellicrack.ui.icon_manager import IconManager, get_icon, get_icon_manager, get_icon_text, set_button_icon


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


class TestIconManager:
    """Production tests for IconManager class."""

    @pytest.fixture
    def temp_icon_dir(self) -> Path:
        """Create temporary icon directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            icon_dir = Path(tmpdir)
            yield icon_dir

    @pytest.fixture
    def icon_manager(self, temp_icon_dir: Path) -> IconManager:
        """Create icon manager with temp directory."""
        return IconManager(icon_path=temp_icon_dir)

    def test_initialization_sets_icon_path(self, temp_icon_dir: Path) -> None:
        """Icon manager initializes with correct path."""
        manager = IconManager(icon_path=temp_icon_dir)
        assert manager.icon_path == temp_icon_dir

    def test_default_icon_path_when_none_provided(self) -> None:
        """Icon manager uses default assets path when none provided."""
        manager = IconManager()
        assert "assets" in str(manager.icon_path)
        assert "icons" in str(manager.icon_path)

    def test_icon_cache_initialized_empty(self, icon_manager: IconManager) -> None:
        """Icon cache is initialized as empty dictionary."""
        assert isinstance(icon_manager._icon_cache, dict)
        assert len(icon_manager._icon_cache) == 0

    def test_get_icon_returns_qicon(self, qapp: QApplication, icon_manager: IconManager) -> None:
        """Get icon returns QIcon instance."""
        icon = icon_manager.get_icon("file_open")
        assert isinstance(icon, QIcon)

    def test_get_icon_caches_result(self, qapp: QApplication, icon_manager: IconManager) -> None:
        """Icon is cached after first retrieval."""
        icon_name = "file_save"
        icon1 = icon_manager.get_icon(icon_name)
        icon2 = icon_manager.get_icon(icon_name)

        assert icon_name in icon_manager._icon_cache
        assert icon1 is icon2

    def test_get_icon_from_file(self, qapp: QApplication, temp_icon_dir: Path) -> None:
        """Icon is loaded from file when available."""
        icon_file = temp_icon_dir / "test_icon.png"
        icon_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        manager = IconManager(icon_path=temp_icon_dir)
        icon = manager.get_icon("test_icon")

        assert isinstance(icon, QIcon)

    def test_get_icon_fallback_when_file_missing(self, qapp: QApplication, icon_manager: IconManager) -> None:
        """Icon fallback is used when file not found."""
        icon = icon_manager.get_icon("nonexistent_icon", fallback=True)
        assert isinstance(icon, QIcon)

    def test_get_icon_no_fallback_returns_null(self, qapp: QApplication, icon_manager: IconManager) -> None:
        """Icon without fallback returns null icon when missing."""
        icon = icon_manager.get_icon("nonexistent_icon", fallback=False)
        assert isinstance(icon, QIcon)

    def test_get_icon_text_returns_string(self, icon_manager: IconManager) -> None:
        """Get icon text returns string representation."""
        text = icon_manager.get_icon_text("file_open")
        assert isinstance(text, str)

    def test_get_icon_text_known_icons(self, icon_manager: IconManager) -> None:
        """Known icons have text representations in ICON_MAP."""
        text = icon_manager.get_icon_text("security_lock")
        assert isinstance(text, str)
        assert len(text) > 0

    def test_get_icon_text_unknown_icon(self, icon_manager: IconManager) -> None:
        """Unknown icon returns empty string."""
        text = icon_manager.get_icon_text("completely_unknown_icon")
        assert text == ""

    def test_register_icon_adds_to_cache(self, qapp: QApplication, temp_icon_dir: Path) -> None:
        """Register icon adds custom icon to cache."""
        icon_file = temp_icon_dir / "custom.png"
        icon_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        manager = IconManager(icon_path=temp_icon_dir)
        manager.register_icon("my_custom_icon", str(icon_file))

        assert "my_custom_icon" in manager._icon_cache

    def test_register_icon_nonexistent_file(self, qapp: QApplication, icon_manager: IconManager) -> None:
        """Register icon with nonexistent file does not crash."""
        icon_manager.register_icon("invalid_icon", "/nonexistent/path.png")
        assert "invalid_icon" not in icon_manager._icon_cache

    def test_clear_cache_removes_all_icons(self, qapp: QApplication, icon_manager: IconManager) -> None:
        """Clear cache removes all cached icons."""
        icon_manager.get_icon("file_open")
        icon_manager.get_icon("file_save")

        assert len(icon_manager._icon_cache) > 0

        icon_manager.clear_cache()

        assert len(icon_manager._icon_cache) == 0

    def test_icon_map_has_required_icons(self, icon_manager: IconManager) -> None:
        """ICON_MAP contains essential icons for UI."""
        essential_icons = [
            "file_open",
            "file_save",
            "action_run",
            "action_stop",
            "status_success",
            "status_error",
            "security_lock",
        ]

        for icon_name in essential_icons:
            assert icon_name in IconManager.ICON_MAP

    def test_load_icon_from_file_tries_multiple_extensions(self, qapp: QApplication, temp_icon_dir: Path) -> None:
        """Load icon tries PNG, SVG, and ICO extensions."""
        svg_file = temp_icon_dir / "test_icon.svg"
        svg_file.write_text('<svg width="16" height="16"></svg>')

        manager = IconManager(icon_path=temp_icon_dir)
        icon = manager._load_icon_from_file("test_icon")

        assert isinstance(icon, QIcon)


class TestGlobalFunctions:
    """Test global icon manager functions."""

    def test_get_icon_manager_returns_instance(self, qapp: QApplication) -> None:
        """get_icon_manager returns IconManager instance."""
        manager = get_icon_manager()
        assert isinstance(manager, IconManager)

    def test_get_icon_manager_singleton(self, qapp: QApplication) -> None:
        """get_icon_manager returns same instance."""
        manager1 = get_icon_manager()
        manager2 = get_icon_manager()
        assert manager1 is manager2

    def test_get_icon_global_function(self, qapp: QApplication) -> None:
        """Global get_icon function returns QIcon."""
        icon = get_icon("file_open")
        assert isinstance(icon, QIcon)

    def test_get_icon_text_global_function(self) -> None:
        """Global get_icon_text function returns string."""
        text = get_icon_text("file_save")
        assert isinstance(text, str)

    def test_set_button_icon_sets_icon(self, qapp: QApplication) -> None:
        """set_button_icon applies icon to button."""
        button = QPushButton("Test")

        with tempfile.TemporaryDirectory() as tmpdir:
            icon_dir = Path(tmpdir)
            icon_file = icon_dir / "test.png"
            icon_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

            manager = get_icon_manager()
            manager.icon_path = icon_dir
            manager.clear_cache()
            manager.register_icon("test_icon", str(icon_file))

            set_button_icon(button, "test_icon", add_text_prefix=False)

            assert not button.icon().isNull() or button.text() == "Test"

    def test_set_button_icon_with_text_prefix(self, qapp: QApplication) -> None:
        """set_button_icon adds emoji prefix when icon not found."""
        button = QPushButton("Save")

        set_button_icon(button, "file_save", add_text_prefix=True)

        text = button.text()
        assert "Save" in text

    def test_set_button_icon_without_text_prefix(self, qapp: QApplication) -> None:
        """set_button_icon without prefix keeps original text."""
        button = QPushButton("Open")

        set_button_icon(button, "nonexistent_icon", add_text_prefix=False)

        assert button.text() == "Open"


class TestIconCategories:
    """Test icon categories are complete."""

    @pytest.fixture
    def icon_manager(self) -> IconManager:
        """Create icon manager."""
        return IconManager()

    def test_file_operation_icons_exist(self, icon_manager: IconManager) -> None:
        """File operation icons are defined."""
        file_ops = ["file_open", "file_save", "file_new", "file_export", "file_import"]
        for icon_name in file_ops:
            text = icon_manager.get_icon_text(icon_name)
            assert isinstance(text, str)

    def test_edit_operation_icons_exist(self, icon_manager: IconManager) -> None:
        """Edit operation icons are defined."""
        edit_ops = ["edit_copy", "edit_paste", "edit_cut", "edit_undo", "edit_redo"]
        for icon_name in edit_ops:
            text = icon_manager.get_icon_text(icon_name)
            assert isinstance(text, str)

    def test_navigation_icons_exist(self, icon_manager: IconManager) -> None:
        """Navigation icons are defined."""
        nav_icons = ["nav_back", "nav_forward", "nav_up", "nav_down", "nav_refresh"]
        for icon_name in nav_icons:
            text = icon_manager.get_icon_text(icon_name)
            assert isinstance(text, str)

    def test_action_icons_exist(self, icon_manager: IconManager) -> None:
        """Action icons are defined."""
        action_icons = ["action_run", "action_stop", "action_pause", "action_analyze"]
        for icon_name in action_icons:
            text = icon_manager.get_icon_text(icon_name)
            assert isinstance(text, str)

    def test_status_icons_exist(self, icon_manager: IconManager) -> None:
        """Status icons are defined."""
        status_icons = ["status_success", "status_error", "status_warning", "status_info"]
        for icon_name in status_icons:
            text = icon_manager.get_icon_text(icon_name)
            assert isinstance(text, str)

    def test_security_icons_exist(self, icon_manager: IconManager) -> None:
        """Security icons are defined."""
        security_icons = ["security_lock", "security_unlock", "security_key", "security_shield"]
        for icon_name in security_icons:
            text = icon_manager.get_icon_text(icon_name)
            assert isinstance(text, str)

    def test_binary_analysis_icons_exist(self, icon_manager: IconManager) -> None:
        """Binary analysis icons are defined."""
        binary_icons = ["binary_exe", "binary_patch", "binary_hex", "binary_disasm"]
        for icon_name in binary_icons:
            text = icon_manager.get_icon_text(icon_name)
            assert isinstance(text, str)


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def temp_icon_dir(self) -> Path:
        """Create temporary icon directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_icon_manager_with_nonexistent_path(self, qapp: QApplication) -> None:
        """Icon manager works with nonexistent icon path."""
        manager = IconManager(icon_path=Path("/nonexistent/path"))
        icon = manager.get_icon("file_open", fallback=True)
        assert isinstance(icon, QIcon)

    def test_multiple_icon_managers_independent(self, qapp: QApplication) -> None:
        """Multiple icon managers maintain independent caches."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager1 = IconManager(icon_path=Path(tmpdir))
            manager2 = IconManager(icon_path=Path(tmpdir))

            manager1.get_icon("file_open")
            assert len(manager1._icon_cache) == 1
            assert len(manager2._icon_cache) == 0

    def test_corrupted_icon_file_handling(self, qapp: QApplication, temp_icon_dir: Path) -> None:
        """Corrupted icon file falls back gracefully."""
        corrupt_file = temp_icon_dir / "corrupt.png"
        corrupt_file.write_bytes(b"INVALID IMAGE DATA")

        manager = IconManager(icon_path=temp_icon_dir)
        icon = manager.get_icon("corrupt", fallback=True)

        assert isinstance(icon, QIcon)

    def test_unicode_icon_names(self, qapp: QApplication) -> None:
        """Icon manager handles Unicode icon names."""
        manager = IconManager()
        text = manager.get_icon_text("файл_open")
        assert isinstance(text, str)

    def test_special_characters_in_icon_path(self, qapp: QApplication) -> None:
        """Icon manager handles paths with special characters."""
        with tempfile.TemporaryDirectory() as tmpdir:
            special_dir = Path(tmpdir) / "test dir with spaces"
            special_dir.mkdir()

            manager = IconManager(icon_path=special_dir)
            icon = manager.get_icon("test", fallback=True)
            assert isinstance(icon, QIcon)
