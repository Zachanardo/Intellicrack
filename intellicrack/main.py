"""Main entry point for the Intellicrack binary analysis platform.

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

import logging
import os
import sys
import warnings

# Suppress pkg_resources deprecation warning from capstone
warnings.filterwarnings("ignore", message="pkg_resources is deprecated as an API.*", category=UserWarning)

# Initialize GIL safety measures at the very start
try:
    from intellicrack.utils.torch_gil_safety import initialize_gil_safety

    initialize_gil_safety()
except ImportError:
    # Fallback environment variables
    os.environ.setdefault("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF", "1")

# Initialize logger before it's used
logger = logging.getLogger(__name__)

# Import security enforcement early to apply patches
try:
    from intellicrack.core import security_enforcement
except ImportError as e:
    logger.warning(f"Security enforcement not available: {e}")

# Configure TensorFlow to prevent GPU initialization issues with Intel Arc B580
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"  # Suppress TensorFlow warnings
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"  # Disable GPU for TensorFlow
os.environ["MKL_THREADING_LAYER"] = "GNU"  # Fix PyTorch + TensorFlow import conflict


# Set Qt to offscreen mode for WSL/headless environments if no display
if "DISPLAY" not in os.environ and "QT_QPA_PLATFORM" not in os.environ:
    # Check if we're in WSL by examining /proc/version for Microsoft string
    if os.path.exists("/proc/version"):
        try:
            with open("/proc/version", encoding="utf-8") as f:
                if "microsoft" in f.read().lower():
                    os.environ["QT_QPA_PLATFORM"] = "offscreen"
        except (IOError, OSError) as e:
            print(f"Warning: Could not read /proc/version to detect WSL: {e}")
    # Don't set offscreen mode on Windows - use native rendering
    elif os.name != "nt":
        os.environ["QT_QPA_PLATFORM"] = "offscreen"

# Configure Qt font handling for Windows
if os.name == "nt":
    # Set Windows font directory for Qt to find system fonts
    if "QT_QPA_FONTDIR" not in os.environ:
        windir = os.environ.get("WINDIR", "C:\\Windows")
        os.environ["QT_QPA_FONTDIR"] = os.path.join(windir, "Fonts")

    # Suppress Qt font warnings to reduce console noise
    os.environ["QT_LOGGING_RULES"] = "*.debug=false;qt.qpa.fonts=false"

    # Force software rendering for Windows (especially Intel Arc compatibility)
    if "QT_OPENGL" not in os.environ:
        os.environ["QT_OPENGL"] = "software"

    # Additional Intel Arc compatibility settings
    gpu_vendor = os.environ.get("INTELLICRACK_GPU_VENDOR", "Unknown")
    if gpu_vendor == "Intel":
        os.environ["QT_OPENGL"] = "software"  # Always force software for Intel
        os.environ["QT_QUICK_BACKEND"] = "software"
        os.environ["QT_ANGLE_PLATFORM"] = "warp"

# Comprehensive logging disabled for Qt compatibility
# The comprehensive logging system interferes with Qt's window display mechanisms


def main() -> int:
    """Main entry point for the Intellicrack application.

    This function performs the following operations:

    1. Executes startup checks and auto-configuration
    2. Imports and launches the GUI application
    3. Handles import errors and other exceptions gracefully

    The function includes verbose logging for debugging startup issues
    and provides helpful error messages for missing dependencies.

    Returns:
        int: Application exit code - 0 for success, 1 for error.

    Note:
        No exceptions are raised - all errors are caught and logged.

    Example:
        .. code-block:: python

            import sys
            sys.exit(main())

    """
    try:
        # Initialize security enforcement if available
        try:
            security_enforcement.initialize_security()
            security_status = security_enforcement.get_security_status()
            if security_status.get("initialized"):
                logger.info(f"Security enforcement initialized: {security_status}")
                print("Security enforcement enabled.")
        except NameError:
            # security_enforcement was not imported successfully
            logger.debug("Security enforcement module not available")

        # Perform startup checks and auto-configuration
        from intellicrack.core.startup_checks import perform_startup_checks

        print("Initializing Intellicrack...")
        perform_startup_checks()
        print("Startup checks completed.")

        # Import and launch the GUI
        # Always use absolute import to avoid issues
        print("Importing launch function...")
        from intellicrack.ui.main_app import launch

        print("Launch function imported successfully.")

        print("Calling launch()...")
        sys.stdout.flush()  # Force output to display
        result = launch()
        print(f"Launch() returned: {result}")
        sys.stdout.flush()
        return result

    except ImportError as e:
        logger.error("Import error in main: %s", e)
        print(f"Error: Failed to import Intellicrack components: {e}")
        print("\nPlease ensure all dependencies are installed:")
        print("  pip install -r requirements.txt")
        import traceback

        traceback.print_exc()
        return 1

    except (OSError, ValueError, RuntimeError) as e:  # pylint: disable=broad-exception-caught
        logger.error("Error launching Intellicrack: %s", e)
        print(f"Error launching Intellicrack: {e}")
        import traceback

        traceback.print_exc()
        return 1


# Command line entry point
if __name__ == "__main__":
    sys.exit(main())
