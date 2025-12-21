"""Provide imports for Intellicrack UI dialogs.

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

Common imports for dialog modules.

This module centralizes common PyQt6 imports to avoid duplication.
"""

import os
from collections.abc import Callable
from typing import Any

from ...utils.logger import get_logger


logger = get_logger(__name__)

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
    def create_icon(path_or_pixmap: str | QPixmap) -> QIcon:
        """Create a QIcon from a path or pixmap.

        Args:
            path_or_pixmap: File path string or QPixmap instance.

        Returns:
            A QIcon instance created from the given input.

        """
        if isinstance(path_or_pixmap, QPixmap):
            return QIcon(path_or_pixmap)
        return QIcon(str(path_or_pixmap))

    def create_pixmap_from_file(path: str, size: tuple[int, int] | None = None) -> QPixmap:
        """Create a QPixmap from a file.

        Args:
            path: File path to the pixmap file.
            size: Optional tuple of (width, height) to scale the pixmap.

        Returns:
            A QPixmap instance, scaled if size is specified and file is valid.

        """
        pixmap = QPixmap(path)
        if size and not pixmap.isNull():
            pixmap = pixmap.scaled(size[0], size[1], Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        return pixmap

    def get_user_input(parent: QWidget, title: str, label: str, default: str = "", password: bool = False) -> tuple[str, bool]:
        """Get user input using QInputDialog.

        Args:
            parent: Parent widget for the dialog.
            title: Dialog window title.
            label: Prompt label text.
            default: Default text value.
            password: Whether to mask input as password.

        Returns:
            Tuple of (input_text, ok_pressed) where ok_pressed is True if user clicked OK.

        """
        if password:
            text, ok = QInputDialog.getText(parent, title, label, QLineEdit.EchoMode.Password, default)
        else:
            text, ok = QInputDialog.getText(parent, title, label, QLineEdit.EchoMode.Normal, default)
        return text, bool(ok)

    def create_horizontal_slider(min_val: int = 0, max_val: int = 100, value: int = 50, tick_interval: int = 10) -> QSlider:
        """Create a configured horizontal slider.

        Args:
            min_val: Minimum slider value.
            max_val: Maximum slider value.
            value: Initial slider value.
            tick_interval: Interval between tick marks.

        Returns:
            A configured QSlider instance with horizontal orientation.

        """
        slider = QSlider(Qt.Orientation.Horizontal)
        slider.setMinimum(min_val)
        slider.setMaximum(max_val)
        slider.setValue(value)
        slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        slider.setTickInterval(tick_interval)
        return slider

except ImportError as e:
    logger.exception("Import error in common_imports: %s", e)
    HAS_PYQT = False

    if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
        logger.info("Skipping PyQt6 imports during testing mode")

    Qt = None  # type: ignore[misc,assignment]
    QThread = None  # type: ignore[misc,assignment]
    QTimer = None  # type: ignore[misc,assignment]
    QTest = None  # type: ignore[misc,assignment]
    QTextCursor = None  # type: ignore[misc,assignment]

    def pyqtSignal(*args: Any, **kwargs: Any) -> Callable[..., None]:  # type: ignore[no-redef]
        """Fallback pyqtSignal implementation when PyQt6 is not available."""

        def _noop_signal(*signal_args: Any) -> None:
            logger.debug("No-op signal called with args: %s", signal_args)

        return _noop_signal

    QFont = None  # type: ignore[misc,assignment]
    QIcon = None  # type: ignore[misc,assignment]
    QPixmap = None  # type: ignore[misc,assignment]
    QApplication = None  # type: ignore[misc,assignment]
    QCheckBox = None  # type: ignore[misc,assignment]
    QComboBox = None  # type: ignore[misc,assignment]
    QDialog = None  # type: ignore[misc,assignment]
    QFileDialog = None  # type: ignore[misc,assignment]
    QFormLayout = None  # type: ignore[misc,assignment]
    QGraphicsView = None  # type: ignore[misc,assignment]
    QGroupBox = None  # type: ignore[misc,assignment]
    QHBoxLayout = None  # type: ignore[misc,assignment]
    QHeaderView = None  # type: ignore[misc,assignment]
    QInputDialog = None  # type: ignore[misc,assignment]
    QLabel = None  # type: ignore[misc,assignment]
    QLineEdit = None  # type: ignore[misc,assignment]
    QListWidget = None  # type: ignore[misc,assignment]
    QListWidgetItem = None  # type: ignore[misc,assignment]
    QMessageBox = None  # type: ignore[misc,assignment]
    QProgressBar = None  # type: ignore[misc,assignment]
    QPushButton = None  # type: ignore[misc,assignment]
    QSlider = None  # type: ignore[misc,assignment]
    QSpinBox = None  # type: ignore[misc,assignment]
    QSplitter = None  # type: ignore[misc,assignment]
    QTableWidget = None  # type: ignore[misc,assignment]
    QTableWidgetItem = None  # type: ignore[misc,assignment]
    QTabWidget = None  # type: ignore[misc,assignment]
    QTextEdit = None  # type: ignore[misc,assignment]
    QTreeWidget = None  # type: ignore[misc,assignment]
    QTreeWidgetItem = None  # type: ignore[misc,assignment]
    QVBoxLayout = None  # type: ignore[misc,assignment]
    QWidget = None  # type: ignore[misc,assignment]

    def create_icon(path_or_pixmap: str | object) -> None:  # type: ignore[misc]
        """Create icon fallback when PyQt6 is unavailable."""
        return

    def create_pixmap_from_file(path: str, size: tuple[int, int] | None = None) -> None:  # type: ignore[misc]
        """Create pixmap fallback when PyQt6 is unavailable."""
        return

    def get_user_input(parent: object, title: str, label: str, default: str = "", password: bool = False) -> tuple[str, bool]:  # type: ignore[misc]
        """Get user input fallback when PyQt6 is unavailable."""
        return default, True

    def create_horizontal_slider(min_val: int = 0, max_val: int = 100, value: int = 50, tick_interval: int = 10) -> "FallbackSlider":  # type: ignore[misc]
        """Create slider fallback when PyQt6 is unavailable."""
        return FallbackSlider(min_val, max_val, value, tick_interval)


class FallbackSlider:
    """Production fallback slider implementation for non-PyQt environments.

    This class provides a functional slider interface when PyQt6 is unavailable,
    maintaining state and interface compatibility with QSlider.

    Attributes:
        _value: Current slider value.
        _min: Minimum allowed value.
        _max: Maximum allowed value.
        _tick_interval: Interval between tick marks.

    """

    def __init__(self, min_val: int, max_val: int, value: int, tick_interval: int) -> None:
        """Initialize the fallback slider.

        Args:
            min_val: Minimum slider value.
            max_val: Maximum slider value.
            value: Initial slider value.
            tick_interval: Interval between tick marks.

        """
        self._min: int = min_val
        self._max: int = max_val
        self._value: int = min(max(value, min_val), max_val)
        self._tick_interval: int = tick_interval

    def setValue(self, val: int) -> None:
        """Set the slider value.

        Args:
            val: New slider value, clamped to [min, max] range.

        """
        self._value = min(max(val, self._min), self._max)

    def value(self) -> int:
        """Get the current slider value.

        Returns:
            Current value within [min, max] range.

        """
        return self._value

    def setMinimum(self, val: int) -> None:
        """Set the minimum slider value.

        Args:
            val: New minimum value.

        """
        self._min = val
        self._value = max(self._value, self._min)

    def setMaximum(self, val: int) -> None:
        """Set the maximum slider value.

        Args:
            val: New maximum value.

        """
        self._max = val
        self._value = min(self._value, self._max)

    def setTickPosition(self, position: object) -> None:
        """Set tick mark position (no-op in fallback).

        Args:
            position: Tick position value (ignored).

        """
        pass

    def setTickInterval(self, interval: int) -> None:
        """Set the interval between tick marks.

        Args:
            interval: Tick interval value.

        """
        self._tick_interval = interval


# Export all imports and utilities
__all__ = [
    "FallbackSlider",
    "HAS_PYQT",
    "QApplication",
    "QCheckBox",
    "QComboBox",
    "QDialog",
    "QFileDialog",
    "QFont",
    "QFormLayout",
    "QGraphicsView",
    "QGroupBox",
    "QHBoxLayout",
    "QHeaderView",
    "QIcon",
    "QInputDialog",
    "QLabel",
    "QLineEdit",
    "QListWidget",
    "QListWidgetItem",
    "QMessageBox",
    "QPixmap",
    "QProgressBar",
    "QPushButton",
    "QSlider",
    "QSpinBox",
    "QSplitter",
    "QTabWidget",
    "QTableWidget",
    "QTableWidgetItem",
    "QTest",
    "QTextCursor",
    "QTextEdit",
    "QThread",
    "QTimer",
    "QTreeWidget",
    "QTreeWidgetItem",
    "QVBoxLayout",
    "QWidget",
    "Qt",
    "create_horizontal_slider",
    "create_icon",
    "create_pixmap_from_file",
    "get_user_input",
    "pyqtSignal",
]
