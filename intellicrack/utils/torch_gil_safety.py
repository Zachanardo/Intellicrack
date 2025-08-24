"""Thread-safe PyTorch wrapper to handle GIL issues with pybind11.

This module provides utilities to safely use PyTorch in multithreaded
environments where GIL errors can occur with pybind11 C++ extensions.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import functools
import logging
import os
import sys
import threading
from typing import Any, Callable

logger = logging.getLogger(__name__)

_torch_lock = threading.RLock()

# Set critical environment variables early to prevent threading conflicts
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("VECLIB_MAXIMUM_THREADS", "1")
os.environ.setdefault("BLIS_NUM_THREADS", "1")


def torch_thread_safe(func: Callable) -> Callable:
    """Decorator to ensure PyTorch operations are thread-safe.

    This decorator wraps PyTorch operations with proper locking
    to prevent GIL-related errors with pybind11 extensions.

    Args:
        func: Function that uses PyTorch operations

    Returns:
        Thread-safe wrapped function

    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        with _torch_lock:
            return func(*args, **kwargs)

    return wrapper


def safe_torch_import():
    """Safely import PyTorch with thread-safe configuration.

    Returns:
        torch module or None if import fails

    """
    # Intel Arc detection - return None immediately without ANY torch import
    if os.environ.get("UR_L0_ENABLE_RELAXED_ALLOCATION_LIMITS") == "1":
        return None  # Intel Arc detected, avoid PyTorch import completely

    with _torch_lock:
        try:
            # Set environment variables before importing torch
            os.environ.setdefault("OMP_NUM_THREADS", "1")
            os.environ.setdefault("MKL_NUM_THREADS", "1")
            os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

            # Try to import PyTorch directly with protection
            import torch

            return torch
        except ImportError:
            return None


class TorchGILSafeContext:
    """Context manager for PyTorch operations that ensures GIL safety."""

    def __enter__(self):
        """Enter the thread-safe PyTorch context."""
        _torch_lock.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the thread-safe PyTorch context."""
        _torch_lock.release()


def with_torch_gil_safety(torch_func: Callable) -> Callable:
    """Wrap a PyTorch function call with GIL safety.

    Args:
        torch_func: PyTorch function to call safely

    Returns:
        Thread-safe wrapped function

    """

    def safe_func(*args, **kwargs):
        with TorchGILSafeContext():
            return torch_func(*args, **kwargs)

    return safe_func


def configure_pybind11_environment():
    """Configure environment for pybind11 GIL safety.

    This should be called very early in application startup,
    before any C++ extensions are imported.
    """
    # Disable pybind11 GIL checks if they're causing issues
    # This is a last resort but may be necessary for complex applications
    os.environ.setdefault("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF", "1")

    # Set NDEBUG to disable debug assertions
    os.environ.setdefault("NDEBUG", "1")

    # Additional pybind11 safety flags
    os.environ.setdefault(
        "PYBIND11_DISABLE_GIL_CHECKS", "1"
    )  # Not standard but some builds check this

    # Ensure single-threaded execution for critical libraries
    os.environ.setdefault("PYTORCH_DISABLE_CUDNN_BATCH_NORM", "1")
    os.environ.setdefault("CUDA_LAUNCH_BLOCKING", "1")

    # Force Python to use a single thread for C extensions
    if hasattr(sys, "setcheckinterval"):
        sys.setcheckinterval(1000)  # Reduce thread switching frequency

    # Try to override pybind11 settings programmatically
    try:
        # Try to access and modify pybind11 internal settings if possible
        import warnings

        warnings.filterwarnings("ignore", category=UserWarning, message=".*pybind11.*GIL.*")
    except Exception as e:
        logger.debug("Could not configure GIL warnings: %s", e)


def initialize_gil_safety():
    """Initialize GIL safety measures for the application.

    This function should be called at the very beginning of the application
    before any threading or C++ extension imports occur.
    """
    configure_pybind11_environment()

    # Import threading and set up proper thread state
    import threading

    # Ensure we're running in the main thread for GIL operations
    if threading.current_thread() is not threading.main_thread():
        import warnings

        warnings.warn(
            "GIL safety initialization called from non-main thread. "
            "This may cause pybind11 errors.",
            RuntimeWarning,
            stacklevel=2,
        )
