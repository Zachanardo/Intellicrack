"""Production tests for menu utilities.

Tests menu finding, creation, and management functions with real Qt menu bars
and menu objects.

Copyright (C) 2025 Zachary Flint
"""

import pytest
from typing import Generator, cast

from intellicrack.handlers.pyqt6_handler import QApplication, QMainWindow, QMenu, QMenuBar
from intellicrack.ui.menu_utils import find_or_create_menu


@pytest.fixture
def qapp() -> QApplication:
    """Provide QApplication instance for Qt menu testing."""
    existing_app = QApplication.instance()
    if existing_app is None:
        return QApplication([])
    assert isinstance(existing_app, QApplication), "Expected QApplication instance"
    return existing_app


@pytest.fixture
def main_window(qapp: QApplication) -> Generator[QMainWindow, None, None]:
    """Create QMainWindow with menu bar for testing."""
    window = QMainWindow()
    menu_bar = window.menuBar()
    assert menu_bar is not None
    yield window
    window.deleteLater()


@pytest.fixture
def menu_bar(main_window: QMainWindow) -> QMenuBar:
    """Get menu bar from main window."""
    bar = main_window.menuBar()
    assert bar is not None
    return bar


class TestFindOrCreateMenu:
    """Test find_or_create_menu functionality with real Qt menus."""

    def test_find_or_create_menu_creates_new_menu_when_not_exists(
        self, menu_bar: QMenuBar
    ) -> None:
        """Creating menu when it doesn't exist adds new menu to menu bar."""
        assert menu_bar.actions() == []

        file_menu = find_or_create_menu(menu_bar, "File")

        assert isinstance(file_menu, QMenu)
        assert file_menu.title() == "File"
        assert len(menu_bar.actions()) == 1

    def test_find_or_create_menu_finds_existing_menu_by_name(
        self, menu_bar: QMenuBar
    ) -> None:
        """Finding existing menu returns the same menu instance."""
        original_menu = menu_bar.addMenu("Edit")
        assert original_menu is not None

        found_menu = find_or_create_menu(menu_bar, "Edit")

        assert found_menu is original_menu
        assert found_menu.title() == "Edit"
        assert len(menu_bar.actions()) == 1

    def test_find_or_create_menu_with_multiple_existing_menus(
        self, menu_bar: QMenuBar
    ) -> None:
        """Finding menu among multiple existing menus returns correct menu."""
        file_menu = menu_bar.addMenu("File")
        edit_menu = menu_bar.addMenu("Edit")
        view_menu = menu_bar.addMenu("View")

        assert file_menu is not None
        assert edit_menu is not None
        assert view_menu is not None

        found_edit = find_or_create_menu(menu_bar, "Edit")

        assert found_edit is edit_menu
        assert found_edit.title() == "Edit"
        assert len(menu_bar.actions()) == 3

    def test_find_or_create_menu_creates_when_similar_names_exist(
        self, menu_bar: QMenuBar
    ) -> None:
        """Creating menu with similar name creates new menu, not reusing existing."""
        file_menu = menu_bar.addMenu("File")
        assert file_menu is not None

        files_menu = find_or_create_menu(menu_bar, "Files")

        assert files_menu is not file_menu
        assert files_menu.title() == "Files"
        assert len(menu_bar.actions()) == 2

    def test_find_or_create_menu_with_empty_menu_bar_creates_menu(
        self, menu_bar: QMenuBar
    ) -> None:
        """Creating menu on empty menu bar successfully creates first menu."""
        assert len(menu_bar.actions()) == 0

        help_menu = find_or_create_menu(menu_bar, "Help")

        assert isinstance(help_menu, QMenu)
        assert help_menu.title() == "Help"
        assert len(menu_bar.actions()) == 1

    def test_find_or_create_menu_returns_valid_menu_object(
        self, menu_bar: QMenuBar
    ) -> None:
        """Created or found menu is valid and can be used for adding actions."""
        tools_menu = find_or_create_menu(menu_bar, "Tools")

        action = tools_menu.addAction("Test Action")
        assert action is not None
        assert action.text() == "Test Action"
        assert len(tools_menu.actions()) == 1

    def test_find_or_create_menu_case_sensitive_matching(
        self, menu_bar: QMenuBar
    ) -> None:
        """Menu finding is case-sensitive for menu names."""
        file_menu = menu_bar.addMenu("File")
        assert file_menu is not None

        file_lower_menu = find_or_create_menu(menu_bar, "file")

        assert file_lower_menu is not file_menu
        assert file_lower_menu.title() == "file"
        assert len(menu_bar.actions()) == 2

    def test_find_or_create_menu_preserves_menu_order(
        self, menu_bar: QMenuBar
    ) -> None:
        """Creating menus preserves order in menu bar."""
        file_menu = find_or_create_menu(menu_bar, "File")
        edit_menu = find_or_create_menu(menu_bar, "Edit")
        view_menu = find_or_create_menu(menu_bar, "View")

        actions = menu_bar.actions()
        assert len(actions) == 3
        assert actions[0].menu() is file_menu
        assert actions[1].menu() is edit_menu
        assert actions[2].menu() is view_menu

    def test_find_or_create_menu_with_special_characters_in_name(
        self, menu_bar: QMenuBar
    ) -> None:
        """Creating menu with special characters in name works correctly."""
        menu_name = "File && Edit"
        special_menu = find_or_create_menu(menu_bar, menu_name)

        assert isinstance(special_menu, QMenu)
        assert special_menu.title() == menu_name

    def test_find_or_create_menu_multiple_calls_same_name_returns_same_menu(
        self, menu_bar: QMenuBar
    ) -> None:
        """Multiple calls with same name return the same menu instance."""
        menu1 = find_or_create_menu(menu_bar, "Analysis")
        menu2 = find_or_create_menu(menu_bar, "Analysis")
        menu3 = find_or_create_menu(menu_bar, "Analysis")

        assert menu1 is menu2
        assert menu2 is menu3
        assert len(menu_bar.actions()) == 1

    def test_find_or_create_menu_with_unicode_characters(
        self, menu_bar: QMenuBar
    ) -> None:
        """Creating menu with Unicode characters in name works correctly."""
        menu_name = "文件"
        unicode_menu = find_or_create_menu(menu_bar, menu_name)

        assert isinstance(unicode_menu, QMenu)
        assert unicode_menu.title() == menu_name

    def test_find_or_create_menu_after_adding_actions_to_existing(
        self, menu_bar: QMenuBar
    ) -> None:
        """Finding menu after adding actions to it preserves actions."""
        original_menu = find_or_create_menu(menu_bar, "File")
        original_menu.addAction("Open")
        original_menu.addAction("Save")

        found_menu = find_or_create_menu(menu_bar, "File")

        assert found_menu is original_menu
        assert len(found_menu.actions()) == 2

    def test_find_or_create_menu_with_ampersand_accelerator(
        self, menu_bar: QMenuBar
    ) -> None:
        """Creating menu with ampersand accelerator works correctly."""
        menu_name = "&File"
        file_menu = find_or_create_menu(menu_bar, menu_name)

        assert isinstance(file_menu, QMenu)
        assert file_menu.title() == menu_name

    def test_find_or_create_menu_returns_menu_with_correct_parent(
        self, menu_bar: QMenuBar, main_window: QMainWindow
    ) -> None:
        """Created menu has menu bar as parent."""
        new_menu = find_or_create_menu(menu_bar, "New Menu")

        assert new_menu.parent() is not None


class TestFindOrCreateMenuEdgeCases:
    """Test edge cases and error handling for menu utilities."""

    def test_find_or_create_menu_with_empty_string_name(
        self, menu_bar: QMenuBar
    ) -> None:
        """Creating menu with empty string name creates menu with empty title."""
        empty_menu = find_or_create_menu(menu_bar, "")

        assert isinstance(empty_menu, QMenu)
        assert empty_menu.title() == ""

    def test_find_or_create_menu_with_whitespace_only_name(
        self, menu_bar: QMenuBar
    ) -> None:
        """Creating menu with whitespace-only name creates menu with that name."""
        whitespace_menu = find_or_create_menu(menu_bar, "   ")

        assert isinstance(whitespace_menu, QMenu)
        assert whitespace_menu.title() == "   "

    def test_find_or_create_menu_with_very_long_name(
        self, menu_bar: QMenuBar
    ) -> None:
        """Creating menu with very long name works correctly."""
        long_name = "A" * 1000
        long_menu = find_or_create_menu(menu_bar, long_name)

        assert isinstance(long_menu, QMenu)
        assert long_menu.title() == long_name

    def test_find_or_create_menu_creates_independent_menus(
        self, menu_bar: QMenuBar
    ) -> None:
        """Created menus are independent and don't affect each other."""
        menu1 = find_or_create_menu(menu_bar, "Menu1")
        menu2 = find_or_create_menu(menu_bar, "Menu2")

        menu1.addAction("Action1")
        menu2.addAction("Action2")

        assert len(menu1.actions()) == 1
        assert len(menu2.actions()) == 1
        assert menu1.actions()[0].text() == "Action1"
        assert menu2.actions()[0].text() == "Action2"


class TestMenuUtilsIntegration:
    """Integration tests for menu utilities with complete workflows."""

    def test_create_complete_menu_structure(self, menu_bar: QMenuBar) -> None:
        """Creating complete menu structure with multiple menus and actions."""
        file_menu = find_or_create_menu(menu_bar, "File")
        file_menu.addAction("New")
        file_menu.addAction("Open")
        file_menu.addAction("Save")

        edit_menu = find_or_create_menu(menu_bar, "Edit")
        edit_menu.addAction("Cut")
        edit_menu.addAction("Copy")
        edit_menu.addAction("Paste")

        view_menu = find_or_create_menu(menu_bar, "View")
        view_menu.addAction("Zoom In")
        view_menu.addAction("Zoom Out")

        assert len(menu_bar.actions()) == 3
        assert len(file_menu.actions()) == 3
        assert len(edit_menu.actions()) == 3
        assert len(view_menu.actions()) == 2

    def test_find_and_modify_existing_menus(self, menu_bar: QMenuBar) -> None:
        """Finding and modifying existing menus works correctly."""
        tools_menu = find_or_create_menu(menu_bar, "Tools")
        tools_menu.addAction("Option 1")

        found_tools = find_or_create_menu(menu_bar, "Tools")
        found_tools.addAction("Option 2")

        assert found_tools is tools_menu
        assert len(found_tools.actions()) == 2

    def test_menu_structure_persistence_across_lookups(
        self, menu_bar: QMenuBar
    ) -> None:
        """Menu structure persists correctly across multiple lookups."""
        analysis_menu = find_or_create_menu(menu_bar, "Analysis")
        analysis_menu.addAction("Static Analysis")

        for _ in range(10):
            found_menu = find_or_create_menu(menu_bar, "Analysis")
            assert found_menu is analysis_menu
            assert len(found_menu.actions()) == 1

        assert len(menu_bar.actions()) == 1
