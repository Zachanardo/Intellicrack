"""
Common import checks and availability flags.

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

logger = logging.getLogger(__name__)

# ML/AI Libraries
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

try:
    import tensorflow as tf
    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False

# Binary Analysis Libraries
try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import elftools
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    capstone = None
    CAPSTONE_AVAILABLE = False

# Visualization
try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    plt = None
    MATPLOTLIB_AVAILABLE = False

# PDF generation
try:
    import pdfkit
    PDFKIT_AVAILABLE = True
except ImportError:
    pdfkit = None
    PDFKIT_AVAILABLE = False

# OpenCL for GPU acceleration
try:
    import pyopencl as cl
    HAS_OPENCL = True
except ImportError:
    cl = None
    HAS_OPENCL = False

# UI Framework
try:
    from PyQt5.QtCore import Qt, QThread, QTimer, pyqtSignal
    from PyQt5.QtGui import QColor, QFont
    from PyQt5.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QDial,
        QFileDialog,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QPlainTextEdit,
        QProgressBar,
        QPushButton,
        QSlider,
        QSpinBox,
        QSplitter,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QTextEdit,
        QTreeWidget,
        QTreeWidgetItem,
        QVBoxLayout,
        QWidget,
    )
    HAS_PYQT = True
except ImportError:
    HAS_PYQT = False
    # Create dummy classes to prevent import errors
    class _DummyWidget:
        def __init__(self, *args, **kwargs):
            pass
        def __call__(self, *args, **kwargs):
            return self
        def addWidget(self, *args, **kwargs):
            """Stub method for adding widgets."""
            pass
        def addLayout(self, *args, **kwargs):
            """Stub method for adding layouts."""
            pass
        def addItems(self, *args, **kwargs):
            """Stub method for adding items."""
            pass
        def addStretch(self, *args, **kwargs):
            """Stub method for adding stretch."""
            pass
        def setObjectName(self, *args, **kwargs):
            """Stub method for setting object name."""
            pass
        def setMinimum(self, *args, **kwargs):
            """Stub method for setting minimum value."""
            pass
        def setMaximum(self, *args, **kwargs):
            """Stub method for setting maximum value."""
            pass
        def setValue(self, *args, **kwargs):
            """Stub method for setting value."""
            pass
        def setText(self, *args, **kwargs):
            """Stub method for setting text."""
            pass
        def addTab(self, *args, **kwargs):
            """Stub method for adding tabs."""
            pass
        def timeout(self):
            """Stub timeout method."""
            return self
        def connect(self, *args, **kwargs):
            """Stub method for connecting signals."""
            pass
        def start(self, *args, **kwargs):
            """Stub method for starting operations."""
            pass
        def __getattr__(self, name):
            logger.debug(f"Dummy widget fallback for attribute: {name}")
            return _DummyWidget()

    Qt = QThread = QTimer = pyqtSignal = _DummyWidget()
    QColor = QFont = _DummyWidget()
    QApplication = QWidget = QCheckBox = QComboBox = QDial = QFileDialog = _DummyWidget()
    QGroupBox = QHBoxLayout = QHeaderView = QLabel = QLineEdit = QListWidget = _DummyWidget()
    QListWidgetItem = QPlainTextEdit = QProgressBar = QPushButton = QSlider = _DummyWidget()
    QSpinBox = QSplitter = QTableWidget = QTableWidgetItem = QTabWidget = _DummyWidget()
    QTextEdit = QTreeWidget = QTreeWidgetItem = QVBoxLayout = _DummyWidget()
