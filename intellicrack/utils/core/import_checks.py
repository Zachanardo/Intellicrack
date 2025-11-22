"""Import checks for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

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

Import checking utilities for validating module availability.

This module consolidates repeated import checking patterns
to avoid code duplication across modules.
"""

import logging
import platform


logger = logging.getLogger(__name__)

# Binary analysis libraries
try:
    from intellicrack.handlers.pefile_handler import pefile

    PEFILE_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    PEFILE_AVAILABLE = False
    pefile = None

try:
    from intellicrack.handlers.lief_handler import HAS_LIEF, lief

    LIEF_AVAILABLE = HAS_LIEF
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    LIEF_AVAILABLE = False
    HAS_LIEF = False
    lief = None

try:
    from intellicrack.handlers.capstone_handler import capstone

    CAPSTONE_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    CAPSTONE_AVAILABLE = False
    capstone = None

try:
    from intellicrack.handlers.pyelftools_handler import HAS_PYELFTOOLS, ELFFile, elffile

    PYELFTOOLS_AVAILABLE = HAS_PYELFTOOLS
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    PYELFTOOLS_AVAILABLE = False
    HAS_PYELFTOOLS = False
    ELFFile = None
    elffile = None

# System monitoring
try:
    from intellicrack.handlers.psutil_handler import psutil

    PSUTIL_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    PSUTIL_AVAILABLE = False
    psutil = None

# Instrumentation
try:
    import frida

    HAS_FRIDA = True
    FRIDA_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    FRIDA_AVAILABLE = False
    HAS_FRIDA = False
    frida = None

# Visualization
try:
    from intellicrack.handlers.matplotlib_handler import HAS_MATPLOTLIB, plt

    MATPLOTLIB_AVAILABLE = HAS_MATPLOTLIB
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    MATPLOTLIB_AVAILABLE = False
    HAS_MATPLOTLIB = False
    plt = None

# PDF generation
try:
    from intellicrack.handlers.pdfkit_handler import pdfkit

    PDFKIT_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    PDFKIT_AVAILABLE = False
    pdfkit = None

# Machine learning
try:
    # Configure TensorFlow to prevent GPU initialization issues
    import os

    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"  # Suppress TensorFlow warnings
    os.environ["CUDA_VISIBLE_DEVICES"] = (
        "-1"  # Disable GPU for TensorFlow (Intel Arc B580 compatibility)
    )

    # Fix PyTorch + TensorFlow import conflict by using GNU threading layer
    os.environ["MKL_THREADING_LAYER"] = "GNU"

    from intellicrack.handlers.tensorflow_handler import tensorflow as tf

    # Disable GPU for TensorFlow to prevent Intel Arc B580 compatibility issues
    tf.config.set_visible_devices([], "GPU")
    TENSORFLOW_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    TENSORFLOW_AVAILABLE = False
    tf = None

# GUI framework availability check only - imports handled by common_imports
try:
    import PyQt6

    _ = PyQt6.__name__  # Verify PyQt6 is properly imported and available
    HAS_PYQT = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    HAS_PYQT = False

# Numerical computing
try:
    from intellicrack.handlers.numpy_handler import (
        HAS_NUMPY,
        numpy as np,
    )
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    HAS_NUMPY = False
    np = None

# Windows-specific modules
try:
    if platform.system() == "Windows":
        import winreg

        WINREG_AVAILABLE = True
    else:
        WINREG_AVAILABLE = False
        winreg = None
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    WINREG_AVAILABLE = False
    winreg = None

# Export all availability flags
__all__ = [
    "CAPSTONE_AVAILABLE",
    "ELFFile",
    "FRIDA_AVAILABLE",
    "HAS_NUMPY",
    "HAS_PYQT",
    "LIEF_AVAILABLE",
    "MATPLOTLIB_AVAILABLE",
    "PDFKIT_AVAILABLE",
    "PEFILE_AVAILABLE",
    "PSUTIL_AVAILABLE",
    "PYELFTOOLS_AVAILABLE",
    "TENSORFLOW_AVAILABLE",
    "WINREG_AVAILABLE",
    "capstone",
    "frida",
    "lief",
    "np",
    "pdfkit",
    "pefile",
    "plt",
    "psutil",
    "tf",
    "winreg",
]
