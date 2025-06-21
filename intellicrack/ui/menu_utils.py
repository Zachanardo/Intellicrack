"""
Menu Utilities

Common functionality for menu operations to eliminate code duplication.
"""

try:
    from PyQt6.QtWidgets import QMenu, QMenuBar
except ImportError:
    from PyQt5.QtWidgets import QMenu, QMenuBar


def find_or_create_menu(menu_bar: QMenuBar, menu_name: str) -> QMenu:
    """
    Find an existing menu by name or create a new one if it doesn't exist.

    Args:
        menu_bar: The menu bar to search in
        menu_name: Name of the menu to find or create

    Returns:
        The found or newly created menu
    """
    # Search for existing menu
    for action in menu_bar.actions():
        if action.text() == menu_name:
            menu = action.menu()
            if menu:
                return menu

    # Create new menu if not found
    return menu_bar.addMenu(menu_name)
