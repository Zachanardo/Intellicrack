"""Perform Integration Script for Adding Radare2 UI to Existing Application.

This script provides a simple way to integrate all radare2 functionality
into the existing Intellicrack application without modifying core files.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import sys

from ..utils.logger import get_logger
from .comprehensive_integration import integrate_radare2_comprehensive

logger = get_logger(__name__)


def add_radare2_to_intellicrack_app(app_instance: object) -> bool:
    """Add comprehensive radare2 functionality to existing IntellicrackApp instance.

    This is the main entry point for users who want to add radare2 functionality
    to their existing Intellicrack application.

    Usage::

        from intellicrack.ui.integrate_radare2 import add_radare2_to_intellicrack_app

        # In your main application initialization:
        success = add_radare2_to_intellicrack_app(your_app_instance)
        if success:
            print("Radare2 integration successful!")
        else:
            print("Radare2 integration failed!")

    Args:
        app_instance: The main IntellicrackApp instance

    Returns:
        bool: True if integration successful, False otherwise

    """
    try:
        logger.info("Starting radare2 integration with IntellicrackApp")

        # Validate app instance
        if app_instance is None:
            logger.error("App instance is None")
            return False

        # Perform comprehensive integration
        success = integrate_radare2_comprehensive(app_instance)

        if success:
            logger.info("Radare2 integration completed successfully")

            # Add success notification to app if possible
            if hasattr(app_instance, "update_output"):
                app_instance.update_output.emit(
                    "[Radare2 Integration] Successfully integrated advanced radare2 analysis capabilities!",
                )
                app_instance.update_output.emit(
                    "[Radare2 Integration] New tabs and menu items have been added for comprehensive binary analysis.",
                )
                app_instance.update_output.emit(
                    "[Radare2 Integration] Features include: decompilation, vulnerability detection, AI analysis, and automated bypass generation.",
                )
        else:
            logger.error("Radare2 integration failed")

            # Add failure notification
            if hasattr(app_instance, "update_output"):
                app_instance.update_output.emit(
                    "[Radare2 Integration] Failed to integrate radare2 functionality. Check logs for details.",
                )

        return success

    except Exception as e:
        logger.error(f"Integration failed with exception: {e}")

        # Add error notification
        if hasattr(app_instance, "update_output"):
            app_instance.update_output.emit(
                f"[Radare2 Integration] Integration failed: {e}",
            )

        return False


def integrate_with_main_app() -> bool:
    """Automatic integration function that tries to find and integrate with.

    the main IntellicrackApp instance.

    This function can be called from the main application module to
    automatically add radare2 functionality.

    Returns:
        bool: True if integration successful, False otherwise

    """
    try:
        # Try to find the main app instance in various ways
        main_app = None

        # Method 1: Check if running in QApplication context
        from intellicrack.handlers.pyqt6_handler import QApplication

        app = QApplication.instance()
        if app:
            # Look for IntellicrackApp in top-level widgets
            for widget in app.topLevelWidgets():
                if hasattr(widget, "__class__") and "IntellicrackApp" in str(type(widget)):
                    main_app = widget
                    break

        # Method 2: Check global variables (if app stores itself globally)
        if not main_app:
            import __main__

            if hasattr(__main__, "app") and hasattr(__main__.app, "__class__"):
                if "IntellicrackApp" in str(type(__main__.app)):
                    main_app = __main__.app

        # Method 3: Check sys.modules for app instance
        if not main_app:
            for _, module in sys.modules.items():
                if hasattr(module, "app"):
                    app_candidate = module.app
                    if hasattr(app_candidate, "__class__") and "IntellicrackApp" in str(type(app_candidate)):
                        main_app = app_candidate
                        break

        if main_app:
            logger.info(f"Found main app instance: {type(main_app)}")
            return add_radare2_to_intellicrack_app(main_app)
        logger.warning("Could not find main IntellicrackApp instance for automatic integration")
        return False

    except Exception as e:
        logger.error(f"Automatic integration failed: {e}")
        return False


def create_standalone_radare2_app() -> tuple[object, object] | tuple[None, None]:
    """Create a standalone radare2 analysis application.

    This creates a new application window with only radare2 functionality,
    useful for users who want a dedicated radare2 analysis tool.

    Returns:
        tuple: (QApplication, main_window) or (None, None) if failed

    """
    try:
        from .enhanced_ui_integration import create_enhanced_application

        app, window = create_enhanced_application()

        if app and window:
            logger.info("Created standalone radare2 application")
            return app, window
        logger.error("Failed to create standalone application")
        return None, None

    except Exception as e:
        logger.error(f"Failed to create standalone application: {e}")
        return None, None


def show_integration_status(app_instance: object | None = None) -> dict:
    """Show the current integration status.

    Args:
        app_instance: Optional app instance to check

    Returns:
        dict: Integration status information

    """
    try:
        from .comprehensive_integration import get_integration_status

        status = get_integration_status()

        # Add app-specific status if provided
        if app_instance:
            status["app_type"] = str(type(app_instance))
            status["has_tab_widget"] = hasattr(app_instance, "tab_widget")
            status["has_menu_bar"] = hasattr(app_instance, "menuBar")
            status["has_r2_ui_manager"] = hasattr(app_instance, "r2_ui_manager")
            status["has_r2_widget"] = hasattr(app_instance, "r2_widget")

        return status

    except Exception as e:
        logger.error(f"Failed to get integration status: {e}")
        return {"error": str(e)}


# Example usage functions for documentation
def example_manual_integration() -> None:
    """Show example of manual integration with existing app.

    This shows how to manually integrate radare2 with an existing app instance.
    """
    # This is just documentation - not meant to be run

    # Assuming you have an existing IntellicrackApp instance called 'app'
    # from intellicrack.ui.integrate_radare2 import add_radare2_to_intellicrack_app
    #
    # success = add_radare2_to_intellicrack_app(app)
    # if success:
    #     print("Radare2 functionality added successfully!")
    #     print("Check the new 'Radare2 Analysis' and 'Enhanced Analysis' tabs")
    #     print("Also check the 'Radare2' menu for analysis options")
    # else:
    #     print("Integration failed - check logs for details")


def example_automatic_integration() -> None:
    """Show example of automatic integration.

    This shows how to automatically integrate radare2 without knowing the app instance.
    """
    # This is just documentation - not meant to be run

    # from intellicrack.ui.integrate_radare2 import integrate_with_main_app
    #
    # success = integrate_with_main_app()
    # if success:
    #     print("Automatic radare2 integration successful!")
    # else:
    #     print("Automatic integration failed - try manual integration")


def example_standalone_app() -> None:
    """Show example of creating a standalone radare2 application.

    This shows how to create a dedicated radare2 analysis application.
    """
    # This is just documentation - not meant to be run

    # from intellicrack.ui.integrate_radare2 import create_standalone_radare2_app
    #
    # app, window = create_standalone_radare2_app()
    # if app and window:
    #     window.show()
    #     app.exec()
    # else:
    #     print("Failed to create standalone application")


__all__ = [
    "add_radare2_to_intellicrack_app",
    "create_standalone_radare2_app",
    "integrate_with_main_app",
    "show_integration_status",
]
