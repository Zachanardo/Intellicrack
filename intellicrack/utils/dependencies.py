"""Dependency checking utilities for Intellicrack.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import os
import sys
from typing import Any

logger = logging.getLogger(__name__)


def check_weasyprint_dependencies() -> list[str]:
    """Check WeasyPrint dependencies with detailed logging.

    Returns:
        List[str]: List of missing dependencies

    """
    missing_deps = []

    try:
        import cffi

        # Store CFFI version for debugging
        cffi_version = getattr(cffi, "__version__", "unknown")
        logger.info(f"✓ CFFI dependency found (version: {cffi_version})")
    except ImportError as e:
        logger.error("✗ CFFI import error: %s", e)
        missing_deps.append("cffi")

    try:
        import cairocffi

        # Store Cairo version for debugging
        cairo_version = getattr(cairocffi, "__version__", "unknown")
        logger.info(f"✓ Cairo dependency found (version: {cairo_version})")
    except ImportError as e:
        logger.error("✗ Cairo import error: %s", e)
        missing_deps.append("cairocffi")

    try:
        import tinycss2

        # Store TinyCSS2 version for debugging
        css_version = getattr(tinycss2, "__version__", "unknown")
        logger.info(f"✓ TinyCSS2 dependency found (version: {css_version})")
    except ImportError as e:
        logger.error("✗ TinyCSS2 import error: %s", e)
        missing_deps.append("tinycss2")

    if sys.platform == "win32":
        try:
            gtk_paths = [
                os.path.join(
                    os.environ.get("ProgramFiles", r"C:\Program Files"), "GTK3-Runtime Win64", "bin"
                ),
                r"C:\GTK\bin",
                os.environ.get("GTK_BASEPATH", "") + "\\bin",
            ]
            logger.info("Checking GTK paths: %s", gtk_paths)
            dll_found = False

            for gtk_path in gtk_paths:
                if os.path.exists(gtk_path):
                    for dll in ["libcairo-2.dll", "libgdk_pixbuf-2.0-0.dll", "libpango-1.0-0.dll"]:
                        dll_path = os.path.join(gtk_path, dll)
                        if os.path.exists(dll_path):
                            logger.info("✓ Found GTK DLL: %s", dll_path)
                            dll_found = True
                            break
                    if dll_found:
                        break

            if not dll_found:
                logger.warning("✗ GTK runtime libraries not found")
                missing_deps.append("gtk-runtime")

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error checking GTK dependencies: %s", e)
            missing_deps.append("gtk-runtime")

    return missing_deps


def check_and_install_dependencies() -> bool:
    """Check for required dependencies and attempt to install missing ones.

    Returns:
        bool: True if all dependencies are available, False otherwise

    """
    missing_deps = []

    # Core dependencies
    core_deps = [
        "psutil",
        "requests",
        "pefile",
        "capstone",
        "keystone",
        "unicorn",
        "lief",
        "yara",
        "cryptography",
    ]

    for dep in core_deps:
        try:
            __import__(dep)
            logger.info("✓ %s available", dep)
        except ImportError:
            logger.warning("✗ %s missing", dep)
            missing_deps.append(dep)

    # Optional dependencies with graceful fallbacks
    optional_deps = {
        "PyQt6": "GUI interface",
        "numpy": "Machine learning features",
        "scikit-learn": "ML model training",
        "matplotlib": "Visualization features",
        "networkx": "Graph analysis",
        "frida": "Dynamic analysis",
        "angr": "Symbolic execution",
        "manticore": "Concolic execution",
    }

    for dep, description in optional_deps.items():
        try:
            __import__(dep)
            logger.info("✓ %s available (%s)", dep, description)
        except ImportError:
            logger.info("ℹ %s not available - %s will be disabled", dep, description)

    return len(missing_deps) == 0


def install_dependencies(deps: list[str]) -> bool:
    """Attempt to install missing dependencies using pip.

    Args:
        deps: List of dependency names to install

    Returns:
        bool: True if installation succeeded, False otherwise

    """
    import subprocess

    try:
        for dep in deps:
            logger.info("Installing %s...", dep)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    dep,
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            if result.returncode == 0:
                logger.info("✓ Successfully installed %s", dep)
            else:
                logger.error("✗ Failed to install %s: %s", dep, result.stderr)
                return False

        return True

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error installing dependencies: %s", e)
        return False


def setup_required_environment() -> dict[str, Any]:
    """Set up the required environment for Intellicrack operation.

    Returns:
        Dict with environment setup status and available features

    """
    env_status = {
        "core_available": True,
        "gui_available": False,
        "ml_available": False,
        "dynamic_analysis_available": False,
        "symbolic_execution_available": False,
        "missing_dependencies": [],
    }

    # Check GUI availability
    try:
        import PyQt6.QtCore

        # Get PyQt6 version for logging
        pyqt_version = getattr(PyQt6.QtCore, "PYQT_VERSION_STR", "unknown")
        env_status["gui_available"] = True
        logger.info(f"✓ GUI interface available (PyQt6 {pyqt_version})")
    except ImportError:
        logger.warning("✗ GUI interface not available - running in CLI mode")
        env_status["missing_dependencies"].append("PyQt6")

    # Check ML availability
    try:
        import numpy
        import sklearn

        # Get versions for logging
        numpy_version = getattr(numpy, "__version__", "unknown")
        sklearn_version = getattr(sklearn, "__version__", "unknown")
        env_status["ml_available"] = True
        logger.info(
            f"✓ Machine learning features available (numpy {numpy_version}, sklearn {sklearn_version})"
        )
    except ImportError:
        logger.warning("✗ ML features not available")
        env_status["missing_dependencies"].extend(["numpy", "scikit-learn"])

    # Check dynamic analysis
    try:
        import frida

        # Get Frida version for logging
        frida_version = getattr(frida, "__version__", "unknown")
        env_status["dynamic_analysis_available"] = True
        logger.info(f"✓ Dynamic analysis (Frida {frida_version}) available")
    except ImportError:
        logger.warning("✗ Dynamic analysis not available")
        env_status["missing_dependencies"].append("frida")

    # Check symbolic execution
    try:
        import angr

        # Get angr version for logging
        angr_version = getattr(angr, "__version__", "unknown")
        env_status["symbolic_execution_available"] = True
        logger.info(f"✓ Symbolic execution (angr {angr_version}) available")
    except ImportError:
        logger.warning("✗ Symbolic execution not available")
        env_status["missing_dependencies"].append("angr")

    return env_status
