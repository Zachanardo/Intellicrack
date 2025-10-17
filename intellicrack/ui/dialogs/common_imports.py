"""Common imports for Intellicrack UI dialogs.

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
"""

import os

from ...utils.logger import get_logger

logger = get_logger(__name__)

"""
Common imports for dialog modules.

This module centralizes common PyQt6 imports to avoid duplication.
"""

# Common PyQt6 imports
try:
    from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
    from PyQt6.QtGui import QFont, QIcon, QPixmap, QTextCursor
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QDialog,
        QFileDialog,
        QFormLayout,
        QGraphicsView,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QInputDialog,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMessageBox,
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

    # Utility functions for unused imports
    def create_icon(path_or_pixmap):
        """Create a QIcon from a path or pixmap."""
        if isinstance(path_or_pixmap, str) or isinstance(path_or_pixmap, QPixmap):
            return QIcon(path_or_pixmap)
        return QIcon()

    def create_pixmap_from_file(path, size=None):
        """Create a QPixmap from a file."""
        pixmap = QPixmap(path)
        if size and not pixmap.isNull():
            pixmap = pixmap.scaled(size[0], size[1], Qt.KeepAspectRatio, Qt.SmoothTransformation)
        return pixmap

    def get_user_input(parent, title, label, default="", password=False):
        """Get user input using QInputDialog."""
        if password:
            text, ok = QInputDialog.getText(parent, title, label, QLineEdit.EchoMode.Password, default)
        else:
            text, ok = QInputDialog.getText(parent, title, label, QLineEdit.EchoMode.Normal, default)
        return text, ok

    def create_horizontal_slider(min_val=0, max_val=100, value=50, tick_interval=10):
        """Create a configured horizontal slider."""
        slider = QSlider(Qt.Orientation.Horizontal)
        slider.setMinimum(min_val)
        slider.setMaximum(max_val)
        slider.setValue(value)
        slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        slider.setTickInterval(tick_interval)
        return slider

except ImportError as e:
    logger.error("Import error in common_imports: %s", e)
    HAS_PYQT = False

    # Skip GUI imports during testing to avoid dependency issues
    if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
        logger.info("Skipping PyQt6 imports during testing mode")

    # Define missing imports as None when PyQt is not available
    Qt = None
    QThread = None
    QTimer = None
    QTest = None
    QTextCursor = None

    def pyqtSignal(*args, **kwargs):
        """Fallback pyqtSignal implementation when PyQt6 is not available."""
        return lambda: None

    QFont = None
    QIcon = None
    QPixmap = None
    QApplication = None
    QCheckBox = None
    QComboBox = None
    QDialog = None
    QFileDialog = None
    QFormLayout = None
    QGraphicsView = None
    QGroupBox = None
    QHBoxLayout = None
    QHeaderView = None
    QInputDialog = None
    QLabel = None
    QLineEdit = None
    QListWidget = None
    QListWidgetItem = None
    QMessageBox = None
    QProgressBar = None
    QPushButton = None
    QSlider = None
    QSpinBox = None
    QSplitter = None
    QTableWidget = None
    QTableWidgetItem = None
    QTabWidget = None
    QTextEdit = None
    QTreeWidget = None
    QTreeWidgetItem = None
    QVBoxLayout = None
    QWidget = None

    # Fallback functions for non-PyQt environments
    def create_icon(path_or_pixmap):
        """Create icon fallback."""
        return None

    def create_pixmap_from_file(path, size=None):
        """Create pixmap fallback."""
        return None

    def get_user_input(parent, title, label, default="", password=False):
        """Get user input fallback."""
        return default, True

    def create_horizontal_slider(min_val=0, max_val=100, value=50, tick_interval=10):
        """Create slider fallback."""

        class MockSlider:
            def __init__(self):
                self._value = value
                self._min = min_val
                self._max = max_val

            def setValue(self, val):
                self._value = val

            def value(self):
                return self._value

            def setMinimum(self, val):
                self._min = val

            def setMaximum(self, val):
                self._max = val

        return MockSlider()


# Export all imports and utilities
__all__ = [
    # Availability flag
    "HAS_PYQT",
    # Core imports
    "Qt",
    "QThread",
    "QTimer",
    "pyqtSignal",
    # GUI imports
    "QFont",
    "QIcon",
    "QPixmap",
    "QTextCursor",
    # Test imports
    "QTest",
    # Widget imports
    "QApplication",
    "QCheckBox",
    "QComboBox",
    "QDialog",
    "QFileDialog",
    "QFormLayout",
    "QGraphicsView",
    "QGroupBox",
    "QHBoxLayout",
    "QHeaderView",
    "QInputDialog",
    "QLabel",
    "QLineEdit",
    "QListWidget",
    "QListWidgetItem",
    "QMessageBox",
    "QProgressBar",
    "QPushButton",
    "QSlider",
    "QSpinBox",
    "QSplitter",
    "QTableWidget",
    "QTableWidgetItem",
    "QTabWidget",
    "QTextEdit",
    "QTreeWidget",
    "QTreeWidgetItem",
    "QVBoxLayout",
    "QWidget",
    # Utility functions
    "create_icon",
    "create_pixmap_from_file",
    "get_user_input",
    "create_horizontal_slider",
]
