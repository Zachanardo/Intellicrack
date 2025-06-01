"""
Integration between enhanced hex viewer/editor and Intellicrack.

This module provides functions for integrating the enhanced hex viewer with
the main Intellicrack application, including UI hooks and tool registration.
"""

import os
import logging
from typing import Dict, Any, Optional

from PyQt5.QtWidgets import (
    QDialog, QMessageBox, QMenu, QAction, QToolBar, QVBoxLayout
)

try:
    from .hex_dialog import HexViewerDialog
except ImportError:
    HexViewerDialog = None

try:
    from .ai_bridge import (
        wrapper_ai_binary_analyze,
        wrapper_ai_binary_pattern_search,
        wrapper_ai_binary_edit_suggest
    )
except ImportError:
    # Provide dummy functions if AI bridge is not available
    def wrapper_ai_binary_analyze(*args, **kwargs):
        return {"error": "AI bridge not available"}
    def wrapper_ai_binary_pattern_search(*args, **kwargs):
        return {"error": "AI bridge not available"}
    def wrapper_ai_binary_edit_suggest(*args, **kwargs):
        return {"error": "AI bridge not available"}

logger = logging.getLogger('Intellicrack.HexView')

# Tool registry for hex viewer AI tools
TOOL_REGISTRY = {}


def show_enhanced_hex_viewer(app_instance, file_path: Optional[str] = None, read_only: bool = True) -> QDialog:
    """
    Show the enhanced hex viewer/editor dialog.
    
    This function creates and shows the enhanced hex viewer dialog, optionally
    loading a file if provided.
    
    Args:
        app_instance: Intellicrack application instance
        file_path: Path to the file to load (optional)
        read_only: Whether to open the file in read-only mode
        
    Returns:
        The created dialog instance
    """
    try:
        # If no file path is provided, use the currently loaded binary
        if not file_path:
            if hasattr(app_instance, "binary_path") and app_instance.binary_path:
                file_path = app_instance.binary_path
                logger.debug(f"Using current binary path: {file_path}")
            else:
                # Show a message box if no file is loaded
                logger.warning("No file path provided and no binary loaded")
                QMessageBox.warning(
                    app_instance,
                    "No File Loaded",
                    "Please load a binary file first."
                )
                return None
        
        # Validate file before creating dialog
        if not os.path.exists(file_path):
            logger.error(f"File does not exist: {file_path}")
            QMessageBox.critical(
                app_instance,
                "Error Opening File",
                f"The file does not exist: {file_path}"
            )
            return None
            
        # Check for read permission
        if not os.access(file_path, os.R_OK):
            logger.error(f"No permission to read file: {file_path}")
            QMessageBox.critical(
                app_instance,
                "Error Opening File",
                f"No permission to read file: {file_path}"
            )
            return None
        
        # Check file size
        try:
            file_size = os.path.getsize(file_path)
            logger.debug(f"File size: {file_size} bytes")
            if file_size == 0:
                logger.warning(f"File is empty: {file_path}")
                QMessageBox.warning(
                    app_instance,
                    "Empty File",
                    f"The file is empty: {file_path}"
                )
                # Continue anyway - we'll show an empty hex view
        except Exception as e:
            logger.warning(f"Could not get file size: {e}")
        
        # Create the dialog
        logger.debug(f"Creating HexViewerDialog for {file_path}, read_only={read_only}")
        dialog = HexViewerDialog(app_instance, file_path, read_only)
        
        # Show the dialog (non-modal)
        dialog.show()
        dialog.raise_()  # Bring to front
        dialog.activateWindow()  # Make it the active window
        
        # Force update after showing
        dialog.hex_viewer.viewport().update()
        
        logger.info(f"Opened enhanced hex viewer for {file_path}")
        return dialog
    except Exception as e:
        logger.error(f"Error showing enhanced hex viewer: {e}", exc_info=True)
        QMessageBox.critical(
            app_instance,
            "Error Opening Hex Viewer",
            f"Failed to open hex viewer: {str(e)}"
        )
        return None


def initialize_hex_viewer(app_instance):
    """
    Initialize the hex viewer functionality.
    
    This function sets up the hex viewer methods on the application instance
    to enable both read-only viewing and editable modes.
    
    Args:
        app_instance: Intellicrack application instance
    """
    # Store the original method
    if not hasattr(app_instance, "_original_show_editable_hex_viewer"):
        app_instance._original_show_editable_hex_viewer = app_instance.show_editable_hex_viewer
        
    # Replace with enhanced version
    # Ensure the proper way to open hex viewer in edit mode is used
    app_instance.show_editable_hex_viewer = lambda: show_enhanced_hex_viewer(
        app_instance, app_instance.binary_path if hasattr(app_instance, "binary_path") else None, False
    )
    
    # Add function to show writable hex viewer explicitly (fixes the menu-only integration)
    if not hasattr(app_instance, "show_writable_hex_viewer"):
        app_instance.show_writable_hex_viewer = app_instance.show_editable_hex_viewer
    
    logger.info("Initialized hex viewer functionality")


def restore_standard_hex_viewer(app_instance):
    """
    Restore the standard hex viewer.
    
    This function restores the original hex viewer function if it was
    previously replaced.
    
    Args:
        app_instance: Intellicrack application instance
    """
    if hasattr(app_instance, "_original_show_editable_hex_viewer"):
        app_instance.show_editable_hex_viewer = app_instance._original_show_editable_hex_viewer
        logger.info("Restored standard hex viewer")


def add_hex_viewer_menu(app_instance, menu_name: str = None):
    """
    Add the enhanced hex viewer to a menu.
    
    This function adds a menu item for the enhanced hex viewer to the
    specified menu in the application.
    
    Args:
        app_instance: Intellicrack application instance
        menu_name: Name of the menu to add the item to
    """
    # Check if menu_name is None - skip menu creation if so
    if menu_name is None:
        # Skip adding hex viewer menu items - they're already available in the dedicated tab
        logger.info("Skipping hex viewer menu creation - using dedicated tab instead")
        return
        
    # Find the menu
    menu = None
    for action in app_instance.menuBar().actions():
        if action.text() == menu_name:
            menu = action.menu()
            break
            
    if not menu:
        # Create the menu if it doesn't exist
        menu = app_instance.menuBar().addMenu(menu_name)
        
    # Add view action (read-only)
    enhanced_hex_action = QAction("Hex Viewer (View)", app_instance)
    enhanced_hex_action.triggered.connect(lambda: show_enhanced_hex_viewer(app_instance, None, True))
    enhanced_hex_action.setStatusTip("Open binary in read-only hex viewer")
    menu.addAction(enhanced_hex_action)
    
    # Add edit action
    edit_hex_action = QAction("Hex Editor (Editable)", app_instance)
    edit_hex_action.triggered.connect(lambda: show_enhanced_hex_viewer(app_instance, None, False))
    edit_hex_action.setStatusTip("Open binary in editable hex editor")
    menu.addAction(edit_hex_action)
    
    logger.info(f"Added Enhanced Hex Viewer options to {menu_name} menu")


def add_hex_viewer_toolbar_button(app_instance, toolbar: Optional[QToolBar] = None):
    """
    Add the enhanced hex viewer to a toolbar.
    
    This function adds a toolbar button for the enhanced hex viewer to the
    specified toolbar in the application.
    
    Args:
        app_instance: Intellicrack application instance
        toolbar: Toolbar to add the button to, or None to use the main toolbar
    """
    # Find the toolbar if not provided
    if not toolbar:
        for child in app_instance.children():
            if isinstance(child, QToolBar):
                toolbar = child
                break
                
    if not toolbar:
        logger.warning("Could not find a toolbar to add the hex viewer button to")
        return
        
    # Add the action
    enhanced_hex_action = QAction("Enhanced Hex", app_instance)
    enhanced_hex_action.triggered.connect(lambda: show_enhanced_hex_viewer(app_instance))
    toolbar.addAction(enhanced_hex_action)
    
    logger.info("Added Enhanced Hex Viewer button to toolbar")


def register_hex_viewer_ai_tools(app_instance):
    """
    Register the AI tool wrappers for the hex viewer.
    
    This function registers the AI tool wrappers that provide integration
    between the hex viewer and the AI model.
    
    Args:
        app_instance: Intellicrack application instance
    """
    # Check if TOOL_REGISTRY exists
    if not hasattr(app_instance, "TOOL_REGISTRY"):
        logger.warning("TOOL_REGISTRY not found in app_instance")
        return
        
    # Register the tool wrappers
    tool_registry = {
        "tool_ai_binary_analyze": wrapper_ai_binary_analyze,
        "tool_ai_binary_pattern_search": wrapper_ai_binary_pattern_search,
        "tool_ai_binary_edit_suggest": wrapper_ai_binary_edit_suggest
    }
    
    # Update the registry
    app_instance.TOOL_REGISTRY.update(tool_registry)
    
    logger.info(f"Registered {len(tool_registry)} hex viewer AI tools")


def integrate_enhanced_hex_viewer(app_instance):
    """
    Fully integrate the enhanced hex viewer with Intellicrack.
    
    This function performs all necessary steps to integrate the enhanced hex
    viewer with the main Intellicrack application.
    
    Args:
        app_instance: Intellicrack application instance
    """
    try:
        # Check if already integrated to prevent duplicates
        if hasattr(app_instance, '_hex_viewer_integrated'):
            logger.info("Enhanced hex viewer already integrated - skipping")
            return True
        
        # Initialize hex viewer
        initialize_hex_viewer(app_instance)
        
        # Skip adding to menu since we have a dedicated tab
        # add_hex_viewer_menu(app_instance)
        logger.info("Skipping hex viewer menu integration - using dedicated tab instead")
        
        # Register AI tools
        register_hex_viewer_ai_tools(app_instance)
        
        # Mark as integrated
        app_instance._hex_viewer_integrated = True
        
        logger.info("Hex viewer integration completed successfully")
        return True
    except Exception as e:
        logger.error(f"Error integrating enhanced hex viewer: {e}")
        return False


# Decorator for hex viewer AI tool wrappers
def hex_viewer_ai_tool(func):
    """
    Decorator for hex viewer AI tool wrappers.
    
    This decorator adds common functionality to all hex viewer AI tool wrappers,
    such as error handling and logging.
    
    Args:
        func: The tool wrapper function
        
    Returns:
        Decorated function
    """
    def wrapper(app_instance, parameters):
        try:
            logger.debug(f"Calling hex viewer AI tool: {func.__name__}")
            result = func(app_instance, parameters)
            logger.debug(f"Hex viewer AI tool {func.__name__} completed successfully")
            return result
        except Exception as e:
            logger.error(f"Error in hex viewer AI tool {func.__name__}: {e}")
            return {"error": str(e)}
    
    return wrapper