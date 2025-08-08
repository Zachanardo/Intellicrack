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
"""

from intellicrack.logger import logger

"""
Common imports for dialog modules.

This module centralizes common PyQt6 imports to avoid duplication.
"""

# Common PyQt6 imports
try:
    from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
    from PyQt6.QtGui import QFont, QIcon, QPixmap
    from PyQt6.QtWidgets import (
        QCheckBox,
        QComboBox,
        QDialog,
        QFileDialog,
        QFormLayout,
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
        """Create a QIcon from a path or pixmap"""
        if isinstance(path_or_pixmap, str) or isinstance(path_or_pixmap, QPixmap):
            return QIcon(path_or_pixmap)
        return QIcon()

    def create_pixmap_from_file(path, size=None):
        """Create a QPixmap from a file"""
        pixmap = QPixmap(path)
        if size and not pixmap.isNull():
            pixmap = pixmap.scaled(size[0], size[1], Qt.KeepAspectRatio, Qt.SmoothTransformation)
        return pixmap

    def get_user_input(parent, title, label, default="", password=False):
        """Get user input using QInputDialog"""
        if password:
            text, ok = QInputDialog.getText(parent, title, label, QLineEdit.Password, default)
        else:
            text, ok = QInputDialog.getText(parent, title, label, QLineEdit.Normal, default)
        return text, ok

    def create_horizontal_slider(min_val=0, max_val=100, value=50, tick_interval=10):
        """Create a configured horizontal slider"""
        slider = QSlider(Qt.Horizontal)
        slider.setMinimum(min_val)
        slider.setMaximum(max_val)
        slider.setValue(value)
        slider.setTickPosition(QSlider.TicksBelow)
        slider.setTickInterval(tick_interval)
        return slider

except ImportError as e:
    logger.error("Import error in common_imports: %s", e)
    HAS_PYQT = False

    # Stub classes for when PyQt is not available
    class QDialog:
        """Stub QDialog class for non-PyQt environments."""

    class QThread:
        """Stub QThread class for non-PyQt environments."""

    def pyqtSignal(*args, **kwargs):
        """Stub pyqtSignal function for non-PyQt environments."""
        _ = args, kwargs
        return lambda: None

    # Dummy utility functions for non-PyQt environments
    def create_icon(path_or_pixmap):
        """Create icon for exploit dialog UI elements."""

        class Icon:
            def __init__(self, source):
                self.source = source
                self.is_pixmap = hasattr(source, "width") and hasattr(source, "height")
                self.is_path = isinstance(source, str)
                self._size = (32, 32)  # Default size

            def pixmap(self, size=None):
                if self.is_pixmap:
                    return self.source
                if self.is_path:
                    # Create pixmap from path
                    pixmap = type(
                        "Pixmap",
                        (),
                        {
                            "width": self._size[0],
                            "height": self._size[1],
                            "path": self.source,
                        },
                    )()
                    return pixmap
                return None

            def isNull(self):
                if self.is_path:
                    import os

                    return not os.path.exists(self.source)
                return False

            def actualSize(self, size=None):
                return type(
                    "Size",
                    (),
                    {
                        "width": lambda: self._size[0],
                        "height": lambda: self._size[1],
                    },
                )()

        return Icon(path_or_pixmap)

    def create_pixmap_from_file(path, size=None):
        """Create pixmap from file for exploit visualization."""
        import os

        class Pixmap:
            def __init__(self, path, size=None):
                self.path = path
                self.valid = os.path.exists(path) if path else False

                if size:
                    self.width = size[0] if isinstance(size, (list, tuple)) else size
                    self.height = size[1] if isinstance(size, (list, tuple)) else size
                else:
                    self.width = 256
                    self.height = 256

                # Simulate image data
                self.data = bytearray(self.width * self.height * 4)  # RGBA

            def scaled(self, width, height, aspect_ratio_mode="keep", transform_mode="smooth"):
                """Scale pixmap for display."""
                new_pixmap = Pixmap(self.path, (width, height))
                new_pixmap.valid = self.valid
                return new_pixmap

            def size(self):
                return type(
                    "Size",
                    (),
                    {
                        "width": lambda: self.width,
                        "height": lambda: self.height,
                    },
                )()

            def isNull(self):
                return not self.valid

            def save(self, path, format="PNG", quality=100):
                """Save pixmap to file."""
                return True  # Simulate successful save

        return Pixmap(path, size)

    def get_user_input(parent, title, label, default="", password=False):
        """Get user input through dialog."""
        return ("", False)

    def create_horizontal_slider(min_val=0, max_val=100, value=50, tick_interval=10):
        """Create horizontal slider for exploit parameter control."""

        class HorizontalSlider:
            def __init__(self):
                self.orientation = "horizontal"
                self.minimum = 0
                self.maximum = 100
                self.value = 50
                self.tick_interval = 10
                self.tick_position = "both"
                self.single_step = 1
                self.page_step = 10
                self.tracking = True
                self.inverted_appearance = False
                self.value_changed_callbacks = []
                self.slider_pressed_callbacks = []
                self.slider_released_callbacks = []

            def setMinimum(self, val):
                self.minimum = int(val)
                if self.value < self.minimum:
                    self.setValue(self.minimum)

            def setMaximum(self, val):
                self.maximum = int(val)
                if self.value > self.maximum:
                    self.setValue(self.maximum)

            def setRange(self, min_val, max_val):
                self.setMinimum(min_val)
                self.setMaximum(max_val)

            def setValue(self, val):
                old_value = self.value
                self.value = max(self.minimum, min(self.maximum, int(val)))
                if self.value != old_value:
                    self._emit_value_changed()

            def value(self):
                return self.value

            def setTickInterval(self, interval):
                self.tick_interval = int(interval)

            def setTickPosition(self, position):
                self.tick_position = position

            def setSingleStep(self, step):
                self.single_step = int(step)

            def setPageStep(self, step):
                self.page_step = int(step)

            def setTracking(self, enable):
                self.tracking = bool(enable)

            def setInvertedAppearance(self, inverted):
                self.inverted_appearance = bool(inverted)

            def _emit_value_changed(self):
                for callback in self.value_changed_callbacks:
                    try:
                        callback(self.value)
                    except:
                        pass

            def valueChanged(self):
                class Signal:
                    def __init__(self, slider):
                        self.slider = slider

                    def connect(self, callback):
                        self.slider.value_changed_callbacks.append(callback)

                return Signal(self)

            def sliderPressed(self):
                class Signal:
                    def __init__(self, slider):
                        self.slider = slider

                    def connect(self, callback):
                        self.slider.slider_pressed_callbacks.append(callback)

                return Signal(self)

            def sliderReleased(self):
                class Signal:
                    def __init__(self, slider):
                        self.slider = slider

                    def connect(self, callback):
                        self.slider.slider_released_callbacks.append(callback)

                return Signal(self)

        slider = HorizontalSlider()
        slider.setMinimum(min_val)
        slider.setMaximum(max_val)
        slider.setValue(value)
        slider.setTickInterval(tick_interval)
        return slider


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
    # Widget imports
    "QCheckBox",
    "QComboBox",
    "QDialog",
    "QFileDialog",
    "QFormLayout",
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
