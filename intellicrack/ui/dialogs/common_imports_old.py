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
along with this program.  If not, see https://www.gnu.org/licenses/.
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

    # Define missing imports as None when PyQt is not available
    Qt = None
    QThread = None
    QTimer = None
    pyqtSignal = lambda *args, **kwargs: lambda: None
    QFont = None
    QIcon = None
    QPixmap = None
    QCheckBox = None
    QComboBox = None
    QDialog = None
    QFileDialog = None
    QFormLayout = None
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
        """Create icon for exploit dialog UI elements."""
        import os

        from PIL import Image

        class Icon:
            def __init__(self, source):
                self.source = source
                self._image = None
                self._size = (32, 32)

                if isinstance(source, str) and os.path.exists(source):
                    try:
                        self._image = Image.open(source)
                        self._size = self._image.size
                    except Exception:
                        self._image = None
                elif hasattr(source, 'size') and hasattr(source, 'mode'):
                    # Already a PIL Image
                    self._image = source
                    self._size = source.size

            def pixmap(self, size=None):
                if self._image:
                    if size:
                        resized = self._image.resize((size[0], size[1]), Image.Resampling.LANCZOS)
                        return resized
                    return self._image
                return None

            def isNull(self):
                return self._image is None

            def actualSize(self, size=None):
                class Size:
                    def __init__(self, w, h):
                        self._width = w
                        self._height = h

                    def width(self):
                        return self._width

                    def height(self):
                        return self._height

                return Size(self._size[0], self._size[1])

        return Icon(path_or_pixmap)

    def create_pixmap_from_file(path, size=None):
        """Create pixmap from file for exploit visualization."""
        import os

        from PIL import Image

        class Pixmap:
            def __init__(self, path, size=None):
                self.path = path
                self._image = None
                self.valid = False

                if path and os.path.exists(path):
                    try:
                        self._image = Image.open(path)
                        self.valid = True

                        if size:
                            target_width = size[0] if isinstance(size, (list, tuple)) else size
                            target_height = size[1] if isinstance(size, (list, tuple)) else size
                            self._image = self._image.resize((target_width, target_height), Image.Resampling.LANCZOS)
                    except Exception:
                        self._image = None
                        self.valid = False

                if self._image:
                    self.width, self.height = self._image.size
                else:
                    self.width = size[0] if size and isinstance(size, (list, tuple)) else 256
                    self.height = size[1] if size and isinstance(size, (list, tuple)) else 256

            def scaled(self, width, height, aspect_ratio_mode="keep", transform_mode="smooth"):
                """Scale pixmap for display."""
                if not self._image:
                    return Pixmap(None, (width, height))

                if aspect_ratio_mode == "keep":
                    # Calculate aspect ratio
                    aspect = self._image.width / self._image.height
                    if width / height > aspect:
                        width = int(height * aspect)
                    else:
                        height = int(width / aspect)

                resample = Image.Resampling.LANCZOS if transform_mode == "smooth" else Image.Resampling.NEAREST
                scaled_image = self._image.resize((width, height), resample)

                # Create new Pixmap with scaled image
                new_pixmap = Pixmap(None)
                new_pixmap._image = scaled_image
                new_pixmap.valid = True
                new_pixmap.width, new_pixmap.height = scaled_image.size
                new_pixmap.path = self.path
                return new_pixmap

            def size(self):
                class Size:
                    def __init__(self, w, h):
                        self._width = w
                        self._height = h

                    def width(self):
                        return self._width

                    def height(self):
                        return self._height

                return Size(self.width, self.height)

            def isNull(self):
                return not self.valid or self._image is None

            def save(self, path, format="PNG", quality=100):
                """Save pixmap to file."""
                if not self._image:
                    return False

                try:
                    save_kwargs = {"format": format}
                    if format.upper() in ["JPEG", "JPG"]:
                        save_kwargs["quality"] = quality
                        save_kwargs["optimize"] = True

                    self._image.save(path, **save_kwargs)
                    return True
                except Exception:
                    return False

        return Pixmap(path, size)

    def get_user_input(parent, title, label, default="", password=False):
        """Get user input through dialog."""
        from intellicrack.handlers.tkinter_handler import simpledialog
        from intellicrack.handlers.tkinter_handler import tkinter as tk

        root = tk.Tk()
        root.withdraw()  # Hide the main window

        if password:
            # Create custom password dialog
            dialog = simpledialog.askstring(title, label, show='*', initialvalue=default, parent=root)
        else:
            dialog = simpledialog.askstring(title, label, initialvalue=default, parent=root)

        root.destroy()

        if dialog is not None:
            return (dialog, True)
        return ("", False)

    def create_horizontal_slider(min_val=0, max_val=100, value=50, tick_interval=10):
        """Create horizontal slider for exploit parameter control."""
        from intellicrack.handlers.tkinter_handler import tkinter as tk
        from intellicrack.handlers.tkinter_handler import ttk

        class HorizontalSlider:
            def __init__(self):
                self._root = None
                self._scale = None
                self.minimum = 0
                self.maximum = 100
                self._value = 50
                self.tick_interval = 10
                self.tick_position = "both"
                self.single_step = 1
                self.page_step = 10
                self.tracking = True
                self.inverted_appearance = False
                self.value_changed_callbacks = []
                self.slider_pressed_callbacks = []
                self.slider_released_callbacks = []
                self._initialized = False

            def _ensure_widget(self):
                """Create the actual Tkinter widget when needed."""
                if not self._initialized:
                    self._root = tk.Tk()
                    self._root.withdraw()
                    self._scale = ttk.Scale(
                        self._root,
                        from_=self.minimum,
                        to=self.maximum,
                        orient='horizontal',
                        command=self._on_value_changed
                    )
                    self._scale.set(self._value)
                    self._initialized = True

            def setMinimum(self, val):
                self.minimum = int(val)
                if self._value < self.minimum:
                    self.setValue(self.minimum)
                if self._scale:
                    self._scale.configure(from_=self.minimum)

            def setMaximum(self, val):
                self.maximum = int(val)
                if self._value > self.maximum:
                    self.setValue(self.maximum)
                if self._scale:
                    self._scale.configure(to=self.maximum)

            def setRange(self, min_val, max_val):
                self.setMinimum(min_val)
                self.setMaximum(max_val)

            def setValue(self, val):
                old_value = self._value
                self._value = max(self.minimum, min(self.maximum, int(val)))
                if self._scale:
                    self._scale.set(self._value)
                if self._value != old_value:
                    self._emit_value_changed()

            def value(self):
                return self._value

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

            def _on_value_changed(self, val):
                """Internal callback for Tkinter scale value changes."""
                try:
                    self._value = int(float(val))
                    self._emit_value_changed()
                except ValueError:
                    pass

            def _emit_value_changed(self):
                for callback in self.value_changed_callbacks:
                    try:
                        callback(self._value)
                    except Exception:
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

            def __del__(self):
                """Clean up Tkinter resources."""
                if self._root:
                    try:
                        self._root.destroy()
                    except (AttributeError, RuntimeError, Exception) as e:
                        logger.debug(f"Failed to destroy root window: {e}")

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
