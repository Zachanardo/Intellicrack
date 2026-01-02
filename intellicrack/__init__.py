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
from collections.abc import Callable
from typing import Any, Optional, Union


# GIL safety will be initialized lazily if needed
_gil_safety_initialized: bool = False


def _initialize_gil_safety() -> None:
    """Initialize GIL safety measures lazily.

    Sets up thread safety measures for PyTorch operations by initializing
    the GIL safety module if available. If the module is not available,
    falls back to using pre-configured environment variables.

    """
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


def _initialize_gpu() -> str:
    """Initialize GPU lazily on first use.

    Detects and initializes GPU acceleration on first call. Falls back to CPU
    if GPU detection fails or dependencies are unavailable. Sets thread limits
    to prevent resource contention. Global state is updated to mark
    initialization as complete on first call.

    Returns:
        str: Device string ("cuda:0", "cpu", "xpu", or other valid device
            identifier) representing the detected or default compute device.

    """
    global _default_device, _gpu_initialized
    if not _gpu_initialized:
        try:
            import os

            os.environ.setdefault("OMP_NUM_THREADS", "1")
            os.environ.setdefault("MKL_NUM_THREADS", "1")
            os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

            from .utils.gpu_autoloader import get_gpu_info, gpu_autoloader

            gpu_autoloader.setup()

            gpu_info = get_gpu_info()
            if gpu_info.get("available", False):
                _default_device = gpu_autoloader.get_device_string()
        except (ImportError, OSError, RuntimeError):
            _default_device = "cpu"
        _gpu_initialized = True
    return _default_device


def _initialize_gpu_with_timeout(timeout_seconds: int = 5) -> str:
    """Initialize GPU with timeout protection to prevent hanging.

    Spawns a daemon thread to perform GPU initialization with a specified
    timeout. If initialization exceeds the timeout, defaults to CPU. Handles
    import errors and runtime exceptions gracefully, logging warnings for
    failed initialization attempts.

    Args:
        timeout_seconds: Maximum time to wait for GPU initialization in
            seconds. Defaults to 5 seconds.

    Returns:
        str: Device string ("xpu:0", "cuda:0", "cpu", or other valid device
            identifier) representing the detected or default compute device.

    """
    import threading

    global _default_device, _gpu_initialized
    if _gpu_initialized:
        return _default_device

    result: dict[str, Any] = {"device": "cpu", "error": None}

    def gpu_init_worker() -> None:
        """Initialize GPU in a separate thread with exception handling.

        Attempts to set up GPU acceleration and updates the result dictionary
        with the device string. Catches exceptions and logs them for fallback
        to CPU mode. Updates the shared result dict with device and error
        information.

        """
        try:
            import os

            os.environ.setdefault("OMP_NUM_THREADS", "1")
            os.environ.setdefault("MKL_NUM_THREADS", "1")
            os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

            from .utils.gpu_autoloader import get_gpu_info, gpu_autoloader

            gpu_autoloader.setup()

            gpu_info = get_gpu_info()
            result["device"] = gpu_autoloader.get_device_string() if gpu_info.get("available", False) else "cpu"
        except (ImportError, OSError, RuntimeError) as e:
            result["error"] = str(e)
            result["device"] = "cpu"

    # Run GPU initialization in a daemon thread with timeout
    init_thread = threading.Thread(target=gpu_init_worker, daemon=True)
    init_thread.start()
    init_thread.join(timeout=timeout_seconds)

    if init_thread.is_alive():
        logger.warning("GPU initialization timed out after %ds - using CPU fallback", timeout_seconds)
        _default_device = "cpu"
    else:
        if result["error"]:
            logger.warning("GPU initialization failed: %s - using CPU fallback", result["error"])
        _default_device = result["device"]

    _gpu_initialized = True
    return _default_device


# Setup logging after imports
logger = logging.getLogger(__name__)

# Configuration will be initialized lazily when first accessed
# This prevents blocking during module import
_config: Optional[Any] = None


def _load_config() -> Optional[Any]:
    """Load configuration from get_config function.

    Attempts to import and call the get_config function to retrieve the
    current configuration object. Returns None if the function is not
    available or callable. Provides lazy initialization of configuration
    without blocking on import.

    Returns:
        Optional[Any]: Configuration object (typically dict or Config instance)
            if loaded successfully, None otherwise.

    """
    get_config_func = _lazy_import_get_config()
    if get_config_func is not None and callable(get_config_func):
        return get_config_func()()
    return None


def _validate_config(config: Any) -> None:
    """Validate and log configuration settings.

    Checks if the configuration object has a validate_config method and
    invokes it. Logs a warning if validation fails, allowing the application
    to continue with default settings.

    Args:
        config: Configuration object to validate. Should have a
            validate_config method that returns bool.

    """
    if hasattr(config, "validate_config") and not config.validate_config():
        logger.warning("Configuration validation failed - using defaults")


def _log_repository_status(config: Any) -> None:
    """Log repository enablement status.

    Checks if the configuration has the is_repository_enabled method and
    logs an info message if the model repository is enabled.

    Args:
        config: Configuration object to check repository status. Should have
            an is_repository_enabled method that takes a string argument.

    """
    if hasattr(config, "is_repository_enabled") and config.is_repository_enabled("model_repository"):
        logger.info("Model repository is enabled")


def _log_ghidra_path(config: Any) -> None:
    """Log Ghidra path configuration.

    Retrieves the Ghidra path from the configuration object if available and
    logs it if it differs from the default 'ghidra' string.

    Args:
        config: Configuration object to retrieve Ghidra path. Should have a
            get_ghidra_path method that returns a string or None.

    """
    ghidra_path = getattr(config, "get_ghidra_path", lambda: None)()
    if ghidra_path and ghidra_path != "ghidra":
        logger.info("Ghidra path configured: %s", ghidra_path)


def _update_config_with_runtime_defaults(config: Any) -> None:
    """Update configuration with runtime defaults.

    Updates the configuration object with initialization and version
    information from the current runtime environment.

    Args:
        config: Configuration object to update with runtime values. Should have
            an update method that accepts a dictionary.

    """
    runtime_config = {
        "initialized": True,
        "version": __version__,
    }
    if hasattr(config, "update"):
        config.update(runtime_config)


def _initialize_config() -> Optional[Any]:
    """Initialize and validate configuration lazily.

    Loads and validates the configuration object on first call, then
    caches it for subsequent calls. Logs various configuration settings
    and updates with runtime defaults. Subsequent calls return the cached
    configuration without reloading.

    Returns:
        Optional[Any]: Configuration object (dict or Config instance) if
            loaded successfully, empty dict otherwise. On subsequent calls,
            returns the cached configuration.

    """
    global _config
    if _config is None:
        _config = _load_config() or {}

        if _config:
            _validate_config(_config)
            _log_repository_status(_config)
            _log_ghidra_path(_config)
            _update_config_with_runtime_defaults(_config)

    return _config


# Lazy imports to prevent blocking during module load
# These will be imported on first access
_main: Optional[Union[Callable[[], int], bool]] = None
_IntellicrackApp: Optional[Any] = None
_ai: Optional[Union[Any, bool]] = None
_core: Optional[Any] = None
_utils: Optional[Any] = None
_ui: Optional[Any] = None
_plugins: Optional[Any] = None
_hexview: Optional[Any] = None
_config_cached: Optional[Any] = None
_get_config_func: Optional[Callable[[], Any]] = None


def _lazy_import_config() -> Optional[Any]:
    """Lazy import of CONFIG.

    Imports the CONFIG object from the config module on first call and
    caches it for subsequent accesses. Prevents blocking during initial
    module import by deferring config module access.

    Returns:
        Optional[Any]: The CONFIG object from the config module, cached for
            subsequent calls.

    """
    global _config_cached
    if _config_cached is None:
        from .config import CONFIG

        _config_cached = CONFIG
    return _config_cached


def _lazy_import_get_config() -> Optional[Callable[[], Any]]:
    """Lazy import of get_config function.

    Imports the get_config function from the config module on first call
    and caches it for subsequent accesses. Prevents blocking during initial
    module import by deferring config module access.

    Returns:
        Optional[Callable[[], Any]]: The get_config function from config
            module, cached for subsequent calls.

    """
    global _get_config_func
    if _get_config_func is None:
        from .config import get_config as _imported_get_config

        _get_config_func = _imported_get_config
    return _get_config_func


# Export lazy references for backwards compatibility
# These will be handled by the __getattr__ function


def _lazy_import_main() -> Optional[Callable[[], int]]:
    """Lazy import of main function.

    Attempts to import the main function from the main module on first call.
    Caches the result and returns None if import fails. Logs exceptions for
    debugging purposes.

    Returns:
        Optional[Callable[[], int]]: The main function if available and
            callable, None otherwise.

    """
    global _main
    if _main is None:
        try:
            from .main import main as _imported_main

            _main = _imported_main
        except ImportError as e:
            logger.exception("Failed to import main function: %s", e)
            _main = False
    return _main if callable(_main) else None


def _lazy_import_app() -> Optional[Any]:
    """Lazy import of UI application.

    Attempts to import the IntellicrackApp class from the UI module on first
    call. Caches the result and returns None if import fails. Logs warnings
    for debugging purposes if import fails.

    Returns:
        Optional[Any]: The IntellicrackApp class if available, None otherwise.

    """
    global _IntellicrackApp
    if _IntellicrackApp is None:
        try:
            from .ui.main_app import IntellicrackApp

            _IntellicrackApp = IntellicrackApp
        except ImportError as e:
            logger.warning("UI application not available: %s", e)
            _IntellicrackApp = None
    return _IntellicrackApp


# Core modules will be imported when accessed via __getattr__
_dashboard: Optional[Any] = None


def _lazy_import_dashboard() -> Optional[Any]:
    """Lazy import of dashboard module.

    Attempts to import the dashboard module on first call. Caches the result
    and returns None if import fails. Logs warnings if the import fails for
    debugging purposes.

    Returns:
        Optional[Any]: The dashboard module if available, None otherwise.

    """
    global _dashboard
    if _dashboard is None:
        try:
            import intellicrack.dashboard as _imported_dashboard

            _dashboard = _imported_dashboard
        except ImportError as e:
            logger.warning("Dashboard module not available: %s", e)
            _dashboard = False
    return _dashboard if _dashboard is not False else None


def _lazy_import_ai() -> Optional[Any]:
    """Lazy import of ai module.

    Attempts to import the ai module on first call. Caches the result
    and returns None if import fails. Logs warnings if the import fails for
    debugging purposes.

    Returns:
        Optional[Any]: The ai module if available, None otherwise.

    """
    global _ai
    if _ai is None:
        try:
            import intellicrack.ai as _imported_ai

            _ai = _imported_ai
        except ImportError as e:
            logger.warning("AI module not available: %s", e)
            _ai = False
    return _ai if _ai is not False else None


def _lazy_import_core() -> Optional[Any]:
    """Lazy import of core module.

    Attempts to import the core module. Returns None if import fails.
    Logs warnings if the import fails for debugging purposes.

    Returns:
        Optional[Any]: The core module if available, None otherwise.

    """
    try:
        import intellicrack.core as _imported_core

        return _imported_core
    except ImportError as e:
        logger.warning("Core module not available: %s", e)
        return None


def _lazy_import_ui() -> Optional[Any]:
    """Lazy import of ui module.

    Attempts to import the ui module. Returns None if import fails.
    Logs warnings if the import fails for debugging purposes.

    Returns:
        Optional[Any]: The ui module if available, None otherwise.

    """
    try:
        import intellicrack.ui as _imported_ui

        return _imported_ui
    except ImportError as e:
        logger.warning("UI module not available: %s", e)
        return None


def _lazy_import_utils() -> Optional[Any]:
    """Lazy import of utils module.

    Attempts to import the utils module. Returns None if import fails.
    Logs warnings if the import fails for debugging purposes.

    Returns:
        Optional[Any]: The utils module if available, None otherwise.

    """
    try:
        import intellicrack.utils as _imported_utils

        return _imported_utils
    except ImportError as e:
        logger.warning("Utils module not available: %s", e)
        return None


def _lazy_import_plugins() -> Optional[Any]:
    """Lazy import of plugins module.

    Attempts to import the plugins module. Returns None if import fails.
    Logs warnings if the import fails for debugging purposes.

    Returns:
        Optional[Any]: The plugins module if available, None otherwise.

    """
    try:
        import intellicrack.plugins as _imported_plugins

        return _imported_plugins
    except ImportError as e:
        logger.warning("Plugins module not available: %s", e)
        return None


def _lazy_import_hexview() -> Optional[Any]:
    """Lazy import of hexview module.

    Attempts to import the hexview module. Returns None if import fails.
    Logs warnings if the import fails for debugging purposes.

    Returns:
        Optional[Any]: The hexview module if available, None otherwise.

    """
    try:
        import intellicrack.hexview as _imported_hexview

        return _imported_hexview
    except ImportError as e:
        logger.warning("Hexview module not available: %s", e)
        return None


# Lazy-loaded references are handled by __getattr__

# Version info


def get_version() -> str:
    """Return the current version of Intellicrack.

    This function provides a programmatic way to access the version string
    of the Intellicrack package, useful for version checking, logging,
    and compatibility verification.

    Returns:
        str: The version string in semantic versioning format (e.g., "1.0.0")

    Example:
        .. code-block:: python

            from intellicrack import (
                get_version,
            )

            version = get_version()
            print(
                f"Running Intellicrack v{version}"
            )
            # Output: Running Intellicrack v1.0.0

    """
    return __version__


# Package-level convenience functions


def create_app() -> Any:
    """Create and return a new Intellicrack application instance.

    This factory function creates a fresh instance of the IntellicrackApp,
    which is the main GUI application class. It ensures that all required
    dependencies are available before attempting to create the instance.
    Performs lazy import of the IntellicrackApp class if not already loaded.

    Returns:
        Any: A new instance of the IntellicrackApp main application class.

    Raises:
        ImportError: If IntellicrackApp is not available due to missing
            dependencies (typically PyQt6 or other UI components).
        RuntimeError: If IntellicrackApp failed to load properly during
            import attempt.

    Example:
        .. code-block:: python

            from intellicrack import (
                create_app,
            )

            app = create_app()
            app.show()

    Note:
        This function checks if the UI module was successfully imported
        before attempting to create the application instance. Caches the
        IntellicrackApp class for efficiency on subsequent calls.

    """
    if _IntellicrackApp is None:
        _lazy_import_app()
    if _IntellicrackApp is None:
        error_msg = "IntellicrackApp not available. Check dependencies."
        logger.error(error_msg)
        raise ImportError(error_msg)
    if _IntellicrackApp is True:
        error_msg = "IntellicrackApp failed to load."
        logger.error(error_msg)
        raise RuntimeError(error_msg)
    return _IntellicrackApp()


def run_app() -> int:
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

            from intellicrack import (
                run_app,
            )

            exit_code = run_app()
            sys.exit(exit_code)

    Note:
        This function wraps the main() function from intellicrack.main,
        which handles all application initialization including GPU detection,
        configuration loading, and UI setup.

    """
    main = _lazy_import_main()  # Ensure main is imported lazily
    if main is None:
        error_msg = "Main function not available. Check dependencies."
        logger.error(error_msg)
        raise ImportError(error_msg)
    return main()


def get_default_device() -> str:
    """Get the default compute device detected at startup.

    This function returns the device that was detected during module
    initialization. It can be useful for ensuring consistent device usage
    across the application.

    Returns:
        str: The device string (e.g., 'cuda:0', 'cpu', 'mps')

    Example:
        .. code-block:: python

            from intellicrack import (
                get_default_device,
            )

            device = get_default_device()
            print(
                f"Using device: {device}"
            )
            # Output: Using device: cuda:0

    """
    return _initialize_gpu()


def __getattr__(name: str) -> Optional[Any]:
    """Lazy loading for module attributes.

    Provides dynamic attribute loading for submodules and functions that are
    not directly imported. Supports lazy loading of ai, core, ui, utils,
    plugins, hexview, dashboard modules and CONFIG, get_config functions.

    Args:
        name: The name of the attribute to load. Supported values are 'ai',
            'core', 'ui', 'utils', 'plugins', 'hexview', 'dashboard',
            'CONFIG', and 'get_config'.

    Returns:
        Optional[Any]: The requested module or attribute if available, None
            if the module/attribute could not be imported.

    Raises:
        AttributeError: If the requested attribute does not exist or is not
            supported by the lazy loading mechanism.

    """
    if name == "ai":
        return _lazy_import_ai()
    if name == "core":
        return _lazy_import_core()
    if name == "ui":
        return _lazy_import_ui()
    if name == "utils":
        return _lazy_import_utils()
    if name == "plugins":
        return _lazy_import_plugins()
    if name == "hexview":
        return _lazy_import_hexview()
    if name == "dashboard":
        return _lazy_import_dashboard()
    if name == "CONFIG":
        return _lazy_import_config()
    if name == "get_config":
        return _lazy_import_get_config()
    error_msg = f"module '{__name__}' has no attribute '{name}'"
    logger.error(error_msg)
    raise AttributeError(error_msg)


__all__ = [
    "__author__",
    "__license__",
    "__version__",
    "create_app",
    "get_default_device",
    "get_version",
    "run_app",
]
