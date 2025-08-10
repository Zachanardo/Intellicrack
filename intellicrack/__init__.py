"""Intellicrack: A fully featured, AI-assisted software analysis and security research suite.

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
along with this program.  If not, see https://www.gnu.org/licenses/.

This package provides comprehensive tools for binary analysis, vulnerability detection,
automated patching, and advanced security research capabilities.

Key Features:
- Static and dynamic binary analysis
- Multi-format binary parsing (PE, ELF, Mach-O)
- AI-assisted vulnerability detection
- Automated patching and exploit generation
- Network protocol analysis
- Hardware protection bypass
- Advanced GUI with integrated tools

Usage:
    from intellicrack import IntellicrackApp
    from intellicrack.config import CONFIG

    # Initialize and run the application
    app = IntellicrackApp()
    app.run()
"""

# Initialize GIL safety measures FIRST - must be done before any imports
try:
    from .utils.torch_gil_safety import initialize_gil_safety
    initialize_gil_safety()
except ImportError:
    # If torch_gil_safety isn't available, set basic environment variables
    import os
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    os.environ.setdefault("MKL_NUM_THREADS", "1")
    os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")
    os.environ.setdefault("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF", "1")

# Standard library imports
import logging

# Local imports
from .config import CONFIG, get_config

__version__ = "1.0.0"
__author__ = "Intellicrack Team"
__license__ = "GPL-3.0"

# Initialize GPU acceleration automatically
try:
    # Additional environment variables for PyTorch threading safety
    import os
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    os.environ.setdefault("MKL_NUM_THREADS", "1")
    os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

    from .utils.gpu_autoloader import get_device, get_gpu_info, gpu_autoloader

    # Setup GPU on import (silent initialization for optimal performance)
    gpu_autoloader.setup()

    # Log GPU status only if logger is configured
    gpu_info = get_gpu_info()
    if gpu_info.get("available", False):
        import sys

        # Get the actual device for logging
        device = get_device()
        # Check if we're in interactive mode (REPL) vs script mode
        if not hasattr(sys, "ps1"):  # Not in interactive mode
            # Store device info for later use
            _default_device = device
        else:
            # In interactive mode, we might print device info
            _default_device = device
except Exception:
    # Silently continue without GPU - application will fall back to CPU
    _default_device = "cpu"

# Setup logging after imports
logger = logging.getLogger(__name__)

# Initialize and validate configuration
_config = get_config()
if _config:
    # Validate configuration on module load to ensure all required settings are present
    if not _config.validate_config():
        logger.warning("Configuration validation failed - using defaults")

    # Check if repositories are enabled for model management
    if _config.is_repository_enabled("model_repository"):
        logger.info("Model repository is enabled")

    # Get and validate Ghidra path for reverse engineering integration
    ghidra_path = _config.get_ghidra_path()
    if ghidra_path and ghidra_path != "ghidra":
        logger.info(f"Ghidra path configured: {ghidra_path}")

    # Update configuration with runtime defaults if needed
    runtime_config = {
        "initialized": True,  # Mark configuration as initialized
        "version": __version__,  # Store current version for compatibility checks
    }
    _config.update(runtime_config)

# Main application
try:
    from .main import main
    from .ui.main_app import IntellicrackApp
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    # Handle case where dependencies aren't available
    main = None
    IntellicrackApp = None

# Core analysis modules
try:
    from . import ai, core, utils
except ImportError as e:
    logger.warning("Core modules not available: %s", e)
    ai = core = utils = None

# UI modules (optional - requires PyQt6)
try:
    from . import ui
except ImportError as e:
    logger.warning("UI module not available: %s", e)
    ui = None

# Plugin system
try:
    from . import plugins
except ImportError as e:
    logger.warning("Plugins module not available: %s", e)
    plugins = None

# Hex viewer integration (optional - requires PyQt6)
try:
    from . import hexview
except ImportError as e:
    logger.warning("Hexview module not available: %s", e)
    hexview = None

# Version info


def get_version():
    """Return the current version of Intellicrack.

    This function provides a programmatic way to access the version string
    of the Intellicrack package, useful for version checking, logging,
    and compatibility verification.

    Returns:
        str: The version string in semantic versioning format (e.g., "1.0.0")

    Example:
        .. code-block:: python

            from intellicrack import get_version
            version = get_version()
            print(f"Running Intellicrack v{version}")
            # Output: Running Intellicrack v1.0.0

    """
    return __version__


# Package-level convenience functions


def create_app():
    """Create and return a new Intellicrack application instance.

    This factory function creates a fresh instance of the IntellicrackApp,
    which is the main GUI application class. It ensures that all required
    dependencies are available before attempting to create the instance.

    Returns:
        IntellicrackApp: A new instance of the main application

    Raises:
        ImportError: If IntellicrackApp is not available due to missing
                    dependencies (typically PyQt6 or other UI components)

    Example:
        .. code-block:: python

            from intellicrack import create_app
            app = create_app()
            app.show()

    Note:
        This function checks if the UI module was successfully imported
        before attempting to create the application instance.

    """
    if IntellicrackApp is None:
        raise ImportError("IntellicrackApp not available. Check dependencies.")
    return IntellicrackApp()


def run_app():
    """Run the Intellicrack application.

    This convenience function provides a simple way to launch the complete
    Intellicrack application, handling all initialization, GPU detection,
    and UI setup automatically.

    Returns:
        int: Exit code from the application (0 for success, non-zero for errors)

    Raises:
        ImportError: If the main function is not available due to missing
                    dependencies or import failures

    Example:
        .. code-block:: python

            from intellicrack import run_app
            exit_code = run_app()
            sys.exit(exit_code)

    Note:
        This function wraps the main() function from intellicrack.main,
        which handles all application initialization including GPU detection,
        configuration loading, and UI setup.

    """
    if main is None:
        raise ImportError("Main function not available. Check dependencies.")
    return main()


def get_default_device():
    """Get the default compute device detected at startup.

    This function returns the device that was detected during module
    initialization. It can be useful for ensuring consistent device usage
    across the application.

    Returns:
        str: The device string (e.g., 'cuda:0', 'cpu', 'mps')

    Example:
        .. code-block:: python

            from intellicrack import get_default_device
            device = get_default_device()
            print(f"Using device: {device}")
            # Output: Using device: cuda:0

    """
    return _default_device


__all__ = [
    "CONFIG",
    "IntellicrackApp",
    "__author__",
    "__license__",
    "__version__",
    "ai",
    "core",
    "create_app",
    "get_default_device",
    "get_version",
    "hexview",
    "plugins",
    "run_app",
    "ui",
    "utils",
]
