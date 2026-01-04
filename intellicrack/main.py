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

import intellicrack.utils.logger


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
    logger.debug("No DISPLAY environment variable found and QT_QPA_PLATFORM not set.")
    # Check if we're in WSL by examining /proc/version for Microsoft string
    if os.path.exists("/proc/version"):
        try:
            with open("/proc/version", encoding="utf-8") as f:
                if "microsoft" in f.read().lower():
                    os.environ["QT_QPA_PLATFORM"] = "offscreen"
                    logger.info("WSL detected, setting QT_QPA_PLATFORM to 'offscreen'.")
                else:
                    logger.debug("Not running in WSL.")
        except OSError as e:
            logger.warning("Could not read /proc/version to detect WSL: %s", e)
    # Don't set offscreen mode on Windows - use native rendering
    elif os.name != "nt":
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
        logger.info("Non-Windows OS detected without display, setting QT_QPA_PLATFORM to 'offscreen'.")
    else:
        logger.debug("Running on Windows, not setting QT_QPA_PLATFORM to 'offscreen'.")
else:
    logger.debug(
        "DISPLAY is '%s' or QT_QPA_PLATFORM is '%s', skipping offscreen mode configuration.",
        os.environ.get("DISPLAY"),
        os.environ.get("QT_QPA_PLATFORM"),
    )

# Configure Qt font handling for Windows
if os.name == "nt":
    logger.debug("Running on Windows, configuring Qt font handling and OpenGL settings.")
    # Set Windows font directory for Qt to find system fonts
    if "QT_QPA_FONTDIR" not in os.environ:
        windir = os.environ.get("WINDIR", "C:\\Windows")
        os.environ["QT_QPA_FONTDIR"] = os.path.join(windir, "Fonts")
        logger.debug("QT_QPA_FONTDIR not set, setting to '%s'.", os.environ["QT_QPA_FONTDIR"])
    else:
        logger.debug("QT_QPA_FONTDIR already set to '%s'.", os.environ["QT_QPA_FONTDIR"])

    # Suppress Qt font warnings to reduce console noise
    if "QT_LOGGING_RULES" not in os.environ:
        os.environ["QT_LOGGING_RULES"] = "*.debug=false;qt.qpa.fonts=false"
        logger.debug("QT_LOGGING_RULES not set, setting to suppress Qt font warnings.")
    else:
        logger.debug("QT_LOGGING_RULES already set to '%s'.", os.environ["QT_LOGGING_RULES"])

    # Force software rendering for Windows (especially Intel Arc compatibility)
    if "QT_OPENGL" not in os.environ:
        os.environ["QT_OPENGL"] = "software"
        logger.debug("QT_OPENGL not set, forcing 'software' rendering for Windows.")
    else:
        logger.debug("QT_OPENGL already set to '%s'.", os.environ["QT_OPENGL"])

    # Additional Intel Arc compatibility settings
    gpu_vendor = os.environ.get("INTELLICRACK_GPU_VENDOR", "Unknown")
    logger.debug("Detected INTELLICRACK_GPU_VENDOR: '%s'.", gpu_vendor)
    if gpu_vendor == "Intel":
        os.environ["QT_OPENGL"] = "software"  # Always force software for Intel
        os.environ["QT_QUICK_BACKEND"] = "software"
        os.environ["QT_ANGLE_PLATFORM"] = "warp"
        logger.info("Intel GPU detected, forcing software rendering and specific Qt backend/platform for compatibility.")
        logger.debug(
            "QT_OPENGL set to '%s', QT_QUICK_BACKEND set to '%s', QT_ANGLE_PLATFORM set to '%s'.",
            os.environ["QT_OPENGL"],
            os.environ["QT_QUICK_BACKEND"],
            os.environ["QT_ANGLE_PLATFORM"],
        )
    else:
        logger.debug("Intel GPU not detected or not specified as vendor.")
else:
    logger.debug("Not running on Windows, skipping Qt font handling and OpenGL settings.")

# Comprehensive logging disabled for Qt compatibility
# The comprehensive logging system interferes with Qt's window display mechanisms


def exception_hook(exctype, value, traceback_obj):
    """Global exception hook to log unhandled exceptions."""
    logger.critical("Unhandled exception:", exc_info=(exctype, value, traceback_obj))
    sys.__excepthook__(exctype, value, traceback_obj)


@intellicrack.utils.logger.log_function_call
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
    sys.excepthook = exception_hook

    try:
        # Configure logging using the central configuration
        import os
        from typing import Any

        from intellicrack.config import get_config
        from intellicrack.utils.core.plugin_paths import get_logs_dir
        from intellicrack.utils.logger import setup_logging

        config_data = get_config()
        logging_config_obj: Any = config_data.get("logging", {})
        log_config: dict[str, Any] = logging_config_obj if isinstance(logging_config_obj, dict) else {}

        # Force DEBUG level for troubleshooting
        level_obj: Any = log_config.get("level", "DEBUG")
        log_level: str = level_obj if isinstance(level_obj, str) else "DEBUG"

        log_file: str | None = None
        file_logging_obj: Any = log_config.get("enable_file_logging", True)
        enable_file_logging: bool = file_logging_obj if isinstance(file_logging_obj, bool) else True
        if enable_file_logging:
            log_dir = get_logs_dir()
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(log_dir, "intellicrack.log")

        # Get console logging status from config, default to True if not specified
        console_obj: Any = log_config.get("enable_console_logging", True)
        enable_console: bool = console_obj if isinstance(console_obj, bool) else True

        rotation_obj: Any = log_config.get("log_rotation", 5)
        log_rotation: int = rotation_obj if isinstance(rotation_obj, int) else 5

        size_obj: Any = log_config.get("max_log_size", 10 * 1024 * 1024)
        max_log_size: int = size_obj if isinstance(size_obj, int) else 10 * 1024 * 1024

        setup_logging(
            level=log_level,
            log_file=log_file,
            enable_rotation=log_rotation > 0,
            max_bytes=max_log_size,
            backup_count=log_rotation,
            enable_console=enable_console,
        )

        logger.info("=== Intellicrack Application Starting ===")
        if log_file:
            logger.info("Log file: %s", log_file)
        else:
            logger.info("File logging is disabled.")

        # Initialize comprehensive logging system
        try:
            from intellicrack.core.logging.audit_logger import setup_comprehensive_logging

            setup_comprehensive_logging()
            logger.info("Comprehensive logging system initialized successfully.")
        except Exception as e:
            logger.warning("Failed to initialize comprehensive logging: %s", e)

        # Initialize GIL safety measures
        logger.debug("Attempting to initialize GIL safety...")
        try:
            from intellicrack.utils.torch_gil_safety import initialize_gil_safety

            initialize_gil_safety()
            logger.info("GIL safety initialized successfully.")
        except ImportError as e:
            logger.warning("GIL safety not available: %s. Setting PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF environment variable.", e)
            os.environ.setdefault("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF", "1")
        except Exception as e:
            logger.exception("An unexpected error occurred during GIL safety initialization: %s", e)

        # Initialize security enforcement if available
        logger.debug("Attempting to initialize security enforcement...")
        try:
            from intellicrack.core import security_enforcement as se_module

            if se_module is not None:
                se_module.initialize_security()
                security_status = se_module.get_security_status()
                status_initialized: object = security_status.get("initialized") if isinstance(security_status, dict) else False
                if status_initialized:
                    logger.info("Security enforcement initialized successfully with status: %s.", security_status)
                else:
                    logger.warning("Security enforcement initialized but reported not enabled. Status: %s", security_status)
        except ImportError as e:
            logger.warning("Security enforcement not available: %s. Skipping security enforcement initialization.", e)
        except Exception as e:
            logger.exception("An unexpected error occurred during security enforcement initialization: %s", e)

        # Apply security mitigations
        logger.debug("Attempting to apply security mitigations...")
        try:
            from intellicrack.utils.security_mitigations import apply_all_mitigations

            apply_all_mitigations()
            logger.info("Security mitigations applied successfully.")
        except ImportError as e:
            logger.warning("Security mitigations not available: %s. Skipping security mitigation application.", e)
        except Exception as e:
            logger.exception("An unexpected error occurred during security mitigation application: %s", e)

        # Perform startup checks and auto-configuration
        logger.debug("Importing startup_checks module...")
        from intellicrack.core.startup_checks import perform_startup_checks

        logger.info("Performing startup checks...")
        try:
            perform_startup_checks()
            logger.info("Startup checks completed successfully.")
        except Exception as e:
            logger.exception("An error occurred during startup checks: %s", e)
            # Depending on severity, you might want to exit here or continue with a warning
            # For now, we'll just log and continue.

        # Import and launch the GUI
        logger.debug("Importing GUI launch function from intellicrack.ui.main_app...")
        from intellicrack.ui.main_app import launch

        logger.info("GUI launch function imported successfully.")

        logger.info("Launching GUI application...")
        result = launch()
        logger.info("GUI application exited with code: %s.", result)
        return result

    except ImportError as e:
        logger.exception("Import error in main: %s", e)
        logger.critical(
            "Failed to import Intellicrack components: %s. Please ensure all dependencies are installed using 'pip install -r requirements.txt'",
            e,
        )
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
