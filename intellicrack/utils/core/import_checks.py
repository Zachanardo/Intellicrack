"""This file is part of Intellicrack.
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
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Import checking utilities for validating module availability.

This module consolidates repeated import checking patterns
to avoid code duplication across modules.
"""

import platform

from intellicrack.logger import logger

# Binary analysis libraries
try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    PEFILE_AVAILABLE = False
    pefile = None

try:
    import lief

    LIEF_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    LIEF_AVAILABLE = False
    lief = None

try:
    import capstone

    CAPSTONE_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    CAPSTONE_AVAILABLE = False
    capstone = None

try:
    from elftools.elf.elffile import ELFFile

    PYELFTOOLS_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    PYELFTOOLS_AVAILABLE = False
    ELFFile = None

# System monitoring
try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    PSUTIL_AVAILABLE = False
    psutil = None

# Instrumentation
try:
    import frida

    FRIDA_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    FRIDA_AVAILABLE = False
    frida = None

# Visualization
try:
    import matplotlib.pyplot as plt

    MATPLOTLIB_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    MATPLOTLIB_AVAILABLE = False
    plt = None

# PDF generation
try:
    import pdfkit

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

    import tensorflow as tf

    # Disable GPU for TensorFlow to prevent Intel Arc B580 compatibility issues
    tf.config.set_visible_devices([], "GPU")
    TENSORFLOW_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    TENSORFLOW_AVAILABLE = False
    tf = None

# GUI framework
try:
    from PyQt6.QtCore import QThread, QTimer, pyqtSignal
    from PyQt6.QtWidgets import QApplication, QWidget

    HAS_PYQT = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    HAS_PYQT = False
    QThread = None
    QTimer = None
    pyqtSignal = None
    QApplication = None
    QWidget = None

# Numerical computing
try:
    import numpy as np

    HAS_NUMPY = True
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
    "ELFFile",
    "QApplication",
    "QThread",
    "QTimer",
    "QWidget",
    "capstone",
    "frida",
    "lief",
    "np",
    "pdfkit",
    "pefile",
    "plt",
    "psutil",
    "pyqtSignal",
    "tf",
    "winreg",
]
