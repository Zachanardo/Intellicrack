import platform

from intellicrack.logger import logger

"""
Common import availability checks for Intellicrack.

This module consolidates repeated import checking patterns
to avoid code duplication across modules.
"""


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
    import tensorflow as tf
    TENSORFLOW_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in import_checks: %s", e)
    TENSORFLOW_AVAILABLE = False
    tf = None

# GUI framework
try:
    from PyQt5.QtCore import QThread, QTimer, pyqtSignal
    from PyQt5.QtWidgets import QApplication, QWidget
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
    'PEFILE_AVAILABLE', 'pefile',
    'LIEF_AVAILABLE', 'lief',
    'CAPSTONE_AVAILABLE', 'capstone',
    'PYELFTOOLS_AVAILABLE', 'ELFFile',
    'PSUTIL_AVAILABLE', 'psutil',
    'FRIDA_AVAILABLE', 'frida',
    'MATPLOTLIB_AVAILABLE', 'plt',
    'PDFKIT_AVAILABLE', 'pdfkit',
    'TENSORFLOW_AVAILABLE', 'tf',
    'HAS_PYQT', 'QThread', 'QTimer', 'pyqtSignal', 'QApplication', 'QWidget',
    'HAS_NUMPY', 'np',
    'WINREG_AVAILABLE', 'winreg'
]
