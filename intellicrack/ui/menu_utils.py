"""Menu utilities for Intellicrack UI.

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

Menu utilities for creating and managing UI menus.

Menu Utilities

Common functionality for menu operations to eliminate code duplication.
"""

from typing import Any, cast

from intellicrack.utils.logger import logger


try:
    from intellicrack.handlers.pyqt6_handler import QMenu, QMenuBar
except ImportError as e:
    logger.error("Import error in menu_utils: %s", e)
    from intellicrack.handlers.pyqt6_handler import QMenu, QMenuBar


def find_or_create_menu(menu_bar: QMenuBar, menu_name: str) -> QMenu:
    """Find an existing menu by name or create a new one if it doesn't exist.

    Args:
        menu_bar: The menu bar to search in
        menu_name: Name of the menu to find or create

    Returns:
        The found or newly created menu

    """
    # Search for existing menu
    for action in menu_bar.actions():
        if action.text() == menu_name:
            if menu := action.menu():
                return cast("QMenu", menu)

    # Create new menu if not found
    new_menu = menu_bar.addMenu(menu_name)
    if new_menu is None:
        raise RuntimeError(f"Failed to create menu '{menu_name}'")
    return new_menu
