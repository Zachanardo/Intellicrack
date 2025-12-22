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

from __future__ import annotations

import logging
import platform
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from types import ModuleType


logger: logging.Logger = logging.getLogger(__name__)

# Binary analysis libraries
try:
    from intellicrack.handlers.pefile_handler import pefile as _pefile_import

    pefile: ModuleType | None = _pefile_import
    PEFILE_AVAILABLE: bool = True
except ImportError as e:
    logger.exception("Import error in import_checks: %s", e)
    PEFILE_AVAILABLE = False
    pefile = None

try:
    from intellicrack.handlers.lief_handler import HAS_LIEF, lief as _lief_import

    lief: ModuleType | None = _lief_import
    LIEF_AVAILABLE: bool = HAS_LIEF
except ImportError as e:
    logger.exception("Import error in import_checks: %s", e)
    LIEF_AVAILABLE = False
    HAS_LIEF = False
    lief = None

try:
    from intellicrack.handlers.capstone_handler import capstone as _capstone_import

    capstone: ModuleType | None = _capstone_import
    CAPSTONE_AVAILABLE: bool = True
except ImportError as e:
    logger.exception("Import error in import_checks: %s", e)
    CAPSTONE_AVAILABLE = False
    capstone = None

try:
    from intellicrack.handlers.pyelftools_handler import ELFFile as _ELFFile_import
    from intellicrack.handlers.pyelftools_handler import HAS_PYELFTOOLS

    ELFFile: type[Any] | None = _ELFFile_import
    PYELFTOOLS_AVAILABLE: bool = HAS_PYELFTOOLS
except ImportError as e:
    logger.exception("Import error in import_checks: %s", e)
    PYELFTOOLS_AVAILABLE = False
    HAS_PYELFTOOLS = False
    ELFFile = None

# System monitoring
try:
    from intellicrack.handlers.psutil_handler import psutil as _psutil_import

    psutil: ModuleType | None = _psutil_import
    PSUTIL_AVAILABLE: bool = True
except ImportError as e:
    logger.exception("Import error in import_checks: %s", e)
    PSUTIL_AVAILABLE = False
    psutil = None

# Instrumentation
try:
    import frida as _frida_import

    frida: ModuleType | None = _frida_import
    HAS_FRIDA: bool = True
    FRIDA_AVAILABLE: bool = True
except ImportError as e:
    logger.exception("Import error in import_checks: %s", e)
    FRIDA_AVAILABLE = False
    HAS_FRIDA = False
    frida = None

# Visualization
try:
    from intellicrack.handlers.matplotlib_handler import HAS_MATPLOTLIB
    from intellicrack.handlers.matplotlib_handler import plt as _plt_import

    plt: ModuleType | None = _plt_import
    MATPLOTLIB_AVAILABLE: bool = HAS_MATPLOTLIB
except ImportError as e:
    logger.exception("Import error in import_checks: %s", e)
    MATPLOTLIB_AVAILABLE = False
    HAS_MATPLOTLIB = False
    plt = None

# PDF generation
try:
    from intellicrack.handlers.pdfkit_handler import pdfkit as _pdfkit_import

    pdfkit: ModuleType | None = _pdfkit_import
    PDFKIT_AVAILABLE: bool = True
except ImportError as e:
    logger.exception("Import error in import_checks: %s", e)
    PDFKIT_AVAILABLE = False
    pdfkit = None

# Machine learning
try:
    # Configure TensorFlow to prevent GPU initialization issues
    import os

    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"  # Suppress TensorFlow warnings
    os.environ["CUDA_VISIBLE_DEVICES"] = "-1"  # Disable GPU for TensorFlow (Intel Arc B580 compatibility)

    # Fix PyTorch + TensorFlow import conflict by using GNU threading layer
    os.environ["MKL_THREADING_LAYER"] = "GNU"

    from intellicrack.handlers.tensorflow_handler import tf as _tf_import

    tf: Any = _tf_import
    # Disable GPU for TensorFlow to prevent Intel Arc B580 compatibility issues
    if hasattr(tf, "config") and hasattr(tf.config, "set_visible_devices"):
        tf.config.set_visible_devices([], "GPU")
    TENSORFLOW_AVAILABLE: bool = True
except ImportError as e:
    logger.exception("Import error in import_checks: %s", e)
    TENSORFLOW_AVAILABLE = False
    tf = None

# GUI framework availability check only - imports handled by common_imports
try:
    import PyQt6

    _ = PyQt6.__name__  # Verify PyQt6 is properly imported and available
    HAS_PYQT: bool = True
except ImportError as e:
    logger.exception("Import error in import_checks: %s", e)
    HAS_PYQT = False

# Numerical computing
try:
    from intellicrack.handlers.numpy_handler import HAS_NUMPY as _HAS_NUMPY_import
    from intellicrack.handlers.numpy_handler import numpy as _np_import

    np: ModuleType | None = _np_import
    HAS_NUMPY: bool = _HAS_NUMPY_import
except ImportError as e:
    logger.exception("Import error in import_checks: %s", e)
    HAS_NUMPY = False
    np = None

# Windows-specific modules
try:
    if platform.system() == "Windows":
        import winreg as _winreg_import

        winreg: ModuleType | None = _winreg_import
        WINREG_AVAILABLE: bool = True
    else:
        WINREG_AVAILABLE = False
        winreg = None
except ImportError as e:
    logger.exception("Import error in import_checks: %s", e)
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
