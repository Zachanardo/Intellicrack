"""Run entry point for the Intellicrack binary analysis platform.

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

# Initialize logger before it's used
logger = logging.getLogger(__name__)

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
        except OSError as e:
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


from intellicrack.utils.logger import log_function_call


@log_function_call
def main() -> int:
    """Run the main entry point for the Intellicrack application.

    This function performs the following operations:

    1. Configures logging with file output
    2. Executes startup checks and auto-configuration
    3. Imports and launches the GUI application
    4. Handles import errors and other exceptions gracefully

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
        # Configure logging using the central configuration
        import os

        from intellicrack.config import get_config
        from intellicrack.utils.core.plugin_paths import get_logs_dir
        from intellicrack.utils.logger import setup_logging

        log_config = get_config().get("logging", {})
        log_level = log_config.get("level", "INFO")

        log_file = None
        if log_config.get("enable_file_logging", True):
            log_dir = get_logs_dir()
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(log_dir, "intellicrack.log")

        # Get console logging status from config, default to True if not specified
        enable_console = log_config.get("enable_console_logging", True)

        setup_logging(
            level=log_level,
            log_file=log_file,
            enable_rotation=log_config.get("log_rotation", 5) > 0,
            max_bytes=log_config.get("max_log_size", 10 * 1024 * 1024),
            backup_count=log_config.get("log_rotation", 5),
            enable_console=enable_console,
        )

        logger.info("=== Intellicrack Application Starting ===")
        if log_file:
            logger.info(f"Log file: {log_file}")

        # Initialize GIL safety measures
        logger.debug("Initializing GIL safety...")
        try:
            from intellicrack.utils.torch_gil_safety import initialize_gil_safety
            initialize_gil_safety()
            logger.info("GIL safety initialized")
            logger.debug("GIL safety initialized")
        except ImportError as e:
            logger.warning(f"GIL safety not available: {e}")
            os.environ.setdefault("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF", "1")
            logger.debug(f"GIL safety not available: {e}")

        # Initialize security enforcement if available
        logger.debug("Initializing security enforcement...")
        try:
            from intellicrack.core import security_enforcement
            security_enforcement.initialize_security()
            security_status = security_enforcement.get_security_status()
            if security_status.get("initialized"):
                logger.info(f"Security enforcement initialized: {security_status}")
                logger.info("Security enforcement enabled.")
            logger.debug("Security enforcement initialized")
        except ImportError as e:
            logger.warning(f"Security enforcement not available: {e}")
            logger.debug(f"Security enforcement not available: {e}")

        # Apply security mitigations
        logger.debug("Applying security mitigations...")
        try:
            from intellicrack.utils.security_mitigations import apply_all_mitigations
            apply_all_mitigations()
            logger.info("Security mitigations applied")
            logger.debug("Security mitigations applied")
        except ImportError as e:
            logger.warning(f"Security mitigations not available: {e}")
            logger.debug(f"Security mitigations not available: {e}")

        # Perform startup checks and auto-configuration
        logger.debug("Importing startup_checks...")
        from intellicrack.core.startup_checks import perform_startup_checks

        logger.info("Initializing Intellicrack...")
        logger.info("Performing startup checks...")
        logger.debug("Calling perform_startup_checks()...")
        perform_startup_checks()
        logger.info("Startup checks completed.")
        logger.info("Startup checks completed successfully")
        logger.debug("Startup checks completed")

        # Import and launch the GUI
        # Always use absolute import to avoid issues
        logger.info("Importing launch function...")
        logger.info("Importing GUI launch function...")
        logger.debug("Importing main_app.launch...")
        from intellicrack.ui.main_app import launch

        logger.info("Launch function imported successfully.")
        logger.info("GUI launch function imported successfully")
        logger.debug("Launch function imported")

        logger.info("Calling launch()...")
        logger.info("Launching GUI application...")
        logger.debug("Calling launch()...")
        result = launch()
        logger.info(f"Launch() returned: {result}")
        logger.info(f"GUI application exited with code: {result}")
        logger.debug(f"Launch returned: {result}")
        return result

    except ImportError as e:
        logger.exception("Import error in main: %s", e)
        logger.critical("Failed to import Intellicrack components: %s. Please ensure all dependencies are installed using 'pip install -r requirements.txt'", e)
        import traceback

        traceback.print_exc()
        return 1

    except (OSError, ValueError, RuntimeError) as e:  # pylint: disable=broad-exception-caught
        logger.exception("Error launching Intellicrack: %s", e)
        logger.critical("Error launching Intellicrack: %s", e)
        import traceback

        traceback.print_exc()
        return 1


# Command line entry point
if __name__ == "__main__":
    sys.exit(main())
