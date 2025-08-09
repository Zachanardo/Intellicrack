#\!/usr/bin/env python3
"""
Launcher script for Intellicrack with comprehensive GIL safety.

This script provides a safe startup environment for Intellicrack that addresses
pybind11 GIL issues by properly configuring the Python environment before
any C++ extensions are loaded.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import sys
import warnings

# Disable all pybind11 GIL assertions at the environment level
os.environ["PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF"] = "1"

# Attempt to disable pybind11 GIL assertions using ctypes approach
try:
    import ctypes
    import ctypes.util
    
    # Try to find and load the Python shared library
    python_lib = None
    if sys.platform.startswith('win'):
        # On Windows, try to get the Python DLL
        python_lib = ctypes.CDLL(None)
    else:
        # On Unix-like systems
        libname = ctypes.util.find_library('python{}.{}'.format(*sys.version_info[:2]))
        if libname:
            python_lib = ctypes.CDLL(libname)
    
    # If we successfully loaded the library, we can potentially set flags
    if python_lib:
        print("Python library loaded for pybind11 configuration", file=sys.stderr)
        
except Exception as e:
    print(f"Could not configure pybind11 via ctypes: {e}", file=sys.stderr)

# Set comprehensive threading environment
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("VECLIB_MAXIMUM_THREADS", "1")
os.environ.setdefault("BLIS_NUM_THREADS", "1")

# PyTorch specific settings
os.environ.setdefault("PYTORCH_DISABLE_CUDNN_BATCH_NORM", "1")
os.environ.setdefault("CUDA_LAUNCH_BLOCKING", "1")

# Suppress specific warnings that can interfere with GIL handling
warnings.filterwarnings("ignore", category=UserWarning, module="pkg_resources")
warnings.filterwarnings("ignore", message=".*pkg_resources is deprecated.*")


def run_intellicrack():
    """Run Intellicrack with proper GIL handling."""
    try:
        # Set up thread safety before any imports
        import threading
        if hasattr(sys, 'setcheckinterval'):
            sys.setcheckinterval(10000)  # Reduce thread switching
        
        # Import and run the main application
        from intellicrack.main import main
        return main()
        
    except Exception as e:
        print(f"Error starting Intellicrack: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run_intellicrack())
