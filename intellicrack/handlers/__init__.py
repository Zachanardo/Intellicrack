"""Dependency handler modules for external libraries.

This package provides fallback implementations and handlers for optional
external dependencies, ensuring Intellicrack continues to function when
certain libraries are not available.
"""

import logging

logger = logging.getLogger(__name__)

# Attempt to import all available handlers
_handlers = {}

# Core handlers that are commonly needed
_handler_modules = [
    ("aiohttp_handler", "aiohttp support"),
    ("capstone_handler", "capstone disassembly engine"),
    ("cryptography_handler", "cryptographic operations"),
    ("frida_handler", "Frida dynamic analysis"),
    ("lief_handler", "LIEF binary parsing"),
    ("matplotlib_handler", "matplotlib plotting"),
    ("numpy_handler", "numpy numerical operations"),
    ("opencl_handler", "OpenCL GPU acceleration"),
    ("pdfkit_handler", "PDF generation"),
    ("pefile_handler", "PE file analysis"),
    ("psutil_handler", "system utilities"),
    ("pyelftools_handler", "ELF file analysis"),
    ("pyqt6_handler", "PyQt6 GUI framework"),
    ("requests_handler", "HTTP requests"),
    ("sqlite3_handler", "SQLite database"),
    ("tensorflow_handler", "TensorFlow machine learning"),
    ("tkinter_handler", "Tkinter GUI framework"),
    ("torch_handler", "PyTorch machine learning"),
]

# Load handlers with error tolerance
for module_name, description in _handler_modules:
    try:
        module = __import__(f"{__name__}.{module_name}", fromlist=[module_name])
        _handlers[module_name] = module
        logger.debug("Loaded handler: %s (%s)", module_name, description)
    except ImportError as e:
        logger.debug("Handler not available: %s (%s) - %s", module_name, description, e)
    except Exception as e:
        logger.warning("Error loading handler %s: %s", module_name, e)


def get_available_handlers():
    """Get list of successfully loaded handlers."""
    return list(_handlers.keys())


def is_handler_available(handler_name):
    """Check if a specific handler is available."""
    return handler_name in _handlers


__all__ = [
    "get_available_handlers",
    "is_handler_available",
] + list(_handlers.keys())
