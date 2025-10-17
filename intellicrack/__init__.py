"""Intellicrack: A fully featured, AI-assisted software analysis and security research suite.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.

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

# Set basic threading safety environment variables immediately
import os

os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")
os.environ.setdefault("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF", "1")

# Standard library imports
import logging

# GIL safety will be initialized lazily if needed
_gil_safety_initialized = False


def _initialize_gil_safety():
    """Initialize GIL safety measures lazily."""
    global _gil_safety_initialized
    if not _gil_safety_initialized:
        try:
            from .utils.torch_gil_safety import initialize_gil_safety

            initialize_gil_safety()
        except ImportError:
            logger.debug("torch_gil_safety module not available, using environment variables")
        _gil_safety_initialized = True


__version__ = "1.0.0"
__author__ = "Intellicrack Team"
__license__ = "GPL-3.0"

# GPU will be initialized lazily on first use to prevent blocking during import
_default_device = "cpu"  # Default fallback
_gpu_initialized = False


def _initialize_gpu():
    """Initialize GPU lazily on first use."""
    global _default_device, _gpu_initialized
    if not _gpu_initialized:
        try:
            import os

            os.environ.setdefault("OMP_NUM_THREADS", "1")
            os.environ.setdefault("MKL_NUM_THREADS", "1")
            os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

            from .utils.gpu_autoloader import get_device, get_gpu_info, gpu_autoloader

            gpu_autoloader.setup()

            gpu_info = get_gpu_info()
            if gpu_info.get("available", False):
                _default_device = get_device()
        except Exception:
            _default_device = "cpu"
        _gpu_initialized = True
    return _default_device


# Setup logging after imports
logger = logging.getLogger(__name__)

# Configuration will be initialized lazily when first accessed
# This prevents blocking during module import
_config = None


def _initialize_config():
    """Initialize and validate configuration lazily."""
    global _config
    if _config is None:
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
    return _config


# Lazy imports to prevent blocking during module load
# These will be imported on first access
_main = None
_IntellicrackApp = None
_ai = None
_core = None
_utils = None
_ui = None
_plugins = None
_hexview = None
_CONFIG = None
_get_config_func = None


def _lazy_import_config():
    """Lazy import of CONFIG."""
    global _CONFIG
    if _CONFIG is None:
        from .config import CONFIG

        _CONFIG = CONFIG
    return _CONFIG


def _lazy_import_get_config():
    """Lazy import of get_config function."""
    global _get_config_func
    if _get_config_func is None:
        from .config import get_config as _imported_get_config

        _get_config_func = _imported_get_config
    return _get_config_func


# Export lazy references for backwards compatibility
CONFIG = None  # Will be replaced by _lazy_import_config() when accessed
get_config = None  # Will be replaced by _lazy_import_get_config() when accessed


def _lazy_import_main():
    """Lazy import of main function."""
    global _main
    if _main is None:
        try:
            from .main import main as _imported_main

            _main = _imported_main
        except ImportError as e:
            logger.error("Failed to import main function: %s", e)
            _main = False  # Mark as attempted
    return _main if _main is not False else None


def _lazy_import_app():
    """Lazy import of UI application."""
    global _IntellicrackApp
    if _IntellicrackApp is None:
        try:
            from .ui.main_app import IntellicrackApp

            _IntellicrackApp = IntellicrackApp
        except ImportError as e:
            logger.warning("UI application not available: %s", e)
            _IntellicrackApp = False
    return _IntellicrackApp if _IntellicrackApp is not False else None


# Export lazy-loaded references
main = property(lambda self: _lazy_import_main())
IntellicrackApp = property(lambda self: _lazy_import_app())

# Core modules will be imported when accessed
ai = core = utils = ui = plugins = hexview = None

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
    return _initialize_gpu()


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
