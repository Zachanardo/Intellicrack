"""
Dependency checking utilities for Intellicrack.

This module provides functions to check for optional dependencies
and provide graceful fallbacks when they are not available.
"""

import logging
import os
import sys
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def check_weasyprint_dependencies() -> List[str]:
    """
    Check WeasyPrint dependencies with detailed logging.

    Returns:
        List[str]: List of missing dependencies
    """
    missing_deps = []

    try:
        import cffi
        logger.info("✓ CFFI dependency found")
    except ImportError as e:
        logger.error("✗ CFFI import error: %s", e)
        missing_deps.append("cffi")

    try:
        import cairocffi
        logger.info("✓ Cairo dependency found")
    except ImportError as e:
        logger.error("✗ Cairo import error: %s", e)
        missing_deps.append("cairocffi")

    try:
        import tinycss2
        logger.info("✓ TinyCSS2 dependency found")
    except ImportError as e:
        logger.error("✗ TinyCSS2 import error: %s", e)
        missing_deps.append("tinycss2")

    if sys.platform == 'win32':
        try:
            gtk_paths = [
                os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), 'GTK3-Runtime Win64', 'bin'),
                r"C:\GTK\bin",
                os.environ.get("GTK_BASEPATH", "") + "\\bin"
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

        except Exception as e:
            logger.error("Error checking GTK dependencies: %s", e)
            missing_deps.append("gtk-runtime")

    return missing_deps


def check_and_install_dependencies() -> bool:
    """
    Check for required dependencies and attempt to install missing ones.

    Returns:
        bool: True if all dependencies are available, False otherwise
    """
    missing_deps = []

    # Core dependencies
    core_deps = [
        "psutil", "requests", "pefile", "capstone", "keystone",
        "unicorn", "lief", "yara", "cryptography"
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
        "PyQt5": "GUI interface",
        "numpy": "Machine learning features",
        "scikit-learn": "ML model training",
        "matplotlib": "Visualization features",
        "networkx": "Graph analysis",
        "frida": "Dynamic analysis",
        "angr": "Symbolic execution",
        "manticore": "Concolic execution"
    }

    for dep, description in optional_deps.items():
        try:
            __import__(dep)
            logger.info("✓ %s available (%s)", dep, description)
        except ImportError:
            logger.info("ℹ %s not available - %s will be disabled", dep, description)

    return len(missing_deps) == 0


def install_dependencies(deps: List[str]) -> bool:
    """
    Attempt to install missing dependencies using pip.

    Args:
        deps: List of dependency names to install

    Returns:
        bool: True if installation succeeded, False otherwise
    """
    import subprocess

    try:
        for dep in deps:
            logger.info("Installing %s...", dep)
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", dep
            ], capture_output=True, text=True)

            if result.returncode == 0:
                logger.info("✓ Successfully installed %s", dep)
            else:
                logger.error("✗ Failed to install %s: %s", dep, result.stderr)
                return False

        return True

    except Exception as e:
        logger.error("Error installing dependencies: %s", e)
        return False


def setup_required_environment() -> Dict[str, Any]:
    """
    Set up the required environment for Intellicrack operation.

    Returns:
        Dict with environment setup status and available features
    """
    env_status = {
        "core_available": True,
        "gui_available": False,
        "ml_available": False,
        "dynamic_analysis_available": False,
        "symbolic_execution_available": False,
        "missing_dependencies": []
    }

    # Check GUI availability
    try:
        import PyQt5
        env_status["gui_available"] = True
        logger.info("✓ GUI interface available")
    except ImportError:
        logger.warning("✗ GUI interface not available - running in CLI mode")
        env_status["missing_dependencies"].append("PyQt5")

    # Check ML availability
    try:
        import numpy
        import sklearn
        env_status["ml_available"] = True
        logger.info("✓ Machine learning features available")
    except ImportError:
        logger.warning("✗ ML features not available")
        env_status["missing_dependencies"].extend(["numpy", "scikit-learn"])

    # Check dynamic analysis
    try:
        import frida
        env_status["dynamic_analysis_available"] = True
        logger.info("✓ Dynamic analysis (Frida) available")
    except ImportError:
        logger.warning("✗ Dynamic analysis not available")
        env_status["missing_dependencies"].append("frida")

    # Check symbolic execution
    try:
        import angr
        env_status["symbolic_execution_available"] = True
        logger.info("✓ Symbolic execution (angr) available")
    except ImportError:
        logger.warning("✗ Symbolic execution not available")
        env_status["missing_dependencies"].append("angr")

    return env_status
