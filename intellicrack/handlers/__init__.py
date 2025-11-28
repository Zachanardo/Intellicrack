"""Dependency handler modules for external libraries.

This package provides fallback implementations and handlers for optional
external dependencies, ensuring Intellicrack continues to function when
certain libraries are not available.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import logging


logger: logging.Logger = logging.getLogger(__name__)

# Attempt to import all available handlers
_handlers: dict[str, object] = {}

# Core handlers that are commonly needed
_handler_modules: list[tuple[str, str]] = [
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
    ("wmi_handler", "WMI Windows Management"),
    ("torch_xpu_handler", "PyTorch XPU support"),
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


def get_available_handlers() -> list[str]:
    """Get list of successfully loaded handlers.

    Returns the names of all dependency handlers that were successfully
    loaded during module initialization.

    Returns:
        List of successfully loaded handler module names.

    """
    return list(_handlers.keys())


def is_handler_available(handler_name: str) -> bool:
    """Check if a specific handler is available.

    Determines whether a dependency handler was successfully loaded and
    is available for use.

    Args:
        handler_name: The name of the handler module to check.

    Returns:
        True if the handler is available, False otherwise.

    """
    return handler_name in _handlers


_handlers_list: list[str] = [str(name) for name in _handlers]
__all__: list[str] = ["get_available_handlers", "is_handler_available", *_handlers_list]  # noqa: PLE0604
