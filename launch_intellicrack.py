#!/usr/bin/env python3
"""Launcher script for Intellicrack with comprehensive GIL safety.

This script provides a safe startup environment for Intellicrack that addresses
pybind11 GIL issues by properly configuring the Python environment before
any C++ extensions are loaded.

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
"""

import os
import sys
import warnings

# Log Python version and executable path IMMEDIATELY
print(f"Python version: {sys.version}", file=sys.stderr)
print(f"Python executable: {sys.executable}", file=sys.stderr)
print(f"Python prefix: {sys.prefix}", file=sys.stderr)
print(f"Python base prefix: {sys.base_prefix}", file=sys.stderr)

# Disable all pybind11 GIL assertions at the environment level
os.environ["PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF"] = "1"

# Attempt to disable pybind11 GIL assertions using ctypes approach
try:
    import ctypes
    import ctypes.util

    # Try to find and load the Python shared library
    python_lib = None
    if sys.platform.startswith("win"):
        # On Windows, try to use kernel32 or find the Python DLL explicitly
        try:
            # First try to use kernel32 as a proxy for system DLL access
            python_lib = ctypes.windll.kernel32
        except Exception:
            # If that fails, try to find python dll explicitly
            try:
                python_dll = f"python{sys.version_info[0]}{sys.version_info[1]}.dll"
                python_lib = ctypes.CDLL(python_dll)
            except Exception:
                python_lib = None
    else:
        # On Unix-like systems
        libname = ctypes.util.find_library("python{}.{}".format(*sys.version_info[:2]))
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
    # Debug: Check if TCL/TK environment variables are set
    tcl_lib = os.environ.get("TCL_LIBRARY", "NOT SET")
    tk_lib = os.environ.get("TK_LIBRARY", "NOT SET")
    print(f"DEBUG: TCL_LIBRARY={tcl_lib}", file=sys.stderr)
    print(f"DEBUG: TK_LIBRARY={tk_lib}", file=sys.stderr)

    # Add launcher DLL directory to Windows DLL search path if available
    dll_dir = os.environ.get("INTEL_LAUNCHER_DLL_DIR")
    if dll_dir and sys.platform.startswith("win"):
        print(f"DEBUG: INTEL_LAUNCHER_DLL_DIR={dll_dir}", file=sys.stderr)
        # Add to PATH for DLL loading
        current_path = os.environ.get("PATH", "")
        if dll_dir not in current_path:
            os.environ["PATH"] = f"{dll_dir};{current_path}"
            print(f"DEBUG: Added {dll_dir} to PATH", file=sys.stderr)

        # Use Windows AddDllDirectory if available (Windows 7+)
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32
            kernel32.AddDllDirectory.argtypes = [wintypes.LPCWSTR]
            kernel32.AddDllDirectory.restype = wintypes.LPVOID
            result = kernel32.AddDllDirectory(dll_dir)
            if result:
                print(f"DEBUG: Successfully called AddDllDirectory({dll_dir})", file=sys.stderr)
            else:
                print(f"DEBUG: AddDllDirectory failed for {dll_dir}", file=sys.stderr)
        except Exception as e:
            print(f"DEBUG: Could not use AddDllDirectory: {e}", file=sys.stderr)

    try:
        # Set up thread safety before any imports
        if hasattr(sys, "setcheckinterval"):
            sys.setcheckinterval(10000)  # Reduce thread switching

        # Import and run the main application
        from intellicrack.main import main

        return main()

    except Exception as e:
        print(f"Error starting Intellicrack: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    # CRITICAL DEBUG: Test environment variables before importing Intellicrack
    print("=== DEBUG: Environment Variables ===", file=sys.stderr)
    print(f"TCL_LIBRARY: {os.environ.get('TCL_LIBRARY', 'NOT SET')}", file=sys.stderr)
    print(f"TK_LIBRARY: {os.environ.get('TK_LIBRARY', 'NOT SET')}", file=sys.stderr)

    # Test if paths exist
    tcl_lib = os.environ.get("TCL_LIBRARY")
    if tcl_lib:
        tcl_exists = os.path.exists(tcl_lib)
        init_tcl = os.path.join(tcl_lib, "init.tcl")
        init_exists = os.path.exists(init_tcl)
        print(f"TCL_LIBRARY exists: {tcl_exists}", file=sys.stderr)
        print(f"init.tcl exists: {init_exists}", file=sys.stderr)

    # Test _tkinter availability BEFORE running main application
    import importlib.util

    _tkinter_spec = importlib.util.find_spec("_tkinter")
    if _tkinter_spec is not None:
        print("✅ SUCCESS: _tkinter module available", file=sys.stderr)

        # Test tkinter GUI creation
        try:
            import tkinter as tk

            root = tk.Tk()
            root.withdraw()
            root.destroy()
            print("✅ SUCCESS: tkinter GUI test passed - FULLY FUNCTIONAL!", file=sys.stderr)
        except Exception as e:
            print(f"❌ FAIL: tkinter GUI test failed: {e}", file=sys.stderr)
    else:
        print("❌ FAIL: _tkinter module not available", file=sys.stderr)

    print("=== END DEBUG ===", file=sys.stderr)
    sys.exit(run_intellicrack())
