"""
Common PyQt5 imports used across dialogs

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


try:
    from PyQt5.QtCore import QPoint, QRect, QSize, Qt, QThread, QTimer, pyqtSignal
    from PyQt5.QtGui import (
        QColor,
        QFont,
        QFontMetrics,
        QIcon,
        QKeyEvent,
        QKeySequence,
        QMouseEvent,
        QPainter,
        QPaintEvent,
        QPen,
        QPixmap,
        QResizeEvent,
    )
    from PyQt5.QtWidgets import (
        QAbstractItemView,
        QAbstractScrollArea,
        QAction,
        QApplication,
        QButtonGroup,
        QCheckBox,
        QComboBox,
        QDesktopWidget,
        QDialog,
        QDialogButtonBox,
        QFileDialog,
        QFormLayout,
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QInputDialog,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QMenu,
        QMessageBox,
        QPlainTextEdit,
        QProgressBar,
        QPushButton,
        QRadioButton,
        QScrollArea,
        QSizePolicy,
        QSlider,
        QSpacerItem,
        QSpinBox,
        QSplashScreen,
        QSplitter,
        QStatusBar,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QTextBrowser,
        QTextEdit,
        QToolBar,
        QTreeWidget,
        QTreeWidgetItem,
        QVBoxLayout,
        QWidget,
        QWizard,
        QWizardPage,
    )
    PYQT5_AVAILABLE = True
except ImportError:
    PYQT5_AVAILABLE = False
    # Create dummy classes for missing imports
    class MockQtClass:
        """
        Mock class to stand in for PyQt5 classes when PyQt5 is not available.

        Provides a no-op implementation that allows the code to run without
        PyQt5 installed, returning itself for any attribute access or calls.
        """
        def __init__(self, *args, **kwargs):
            pass
        def __call__(self, *args, **kwargs):
            return self
        def __getattr__(self, name):
            return MockQtClass()

    # Core classes
    Qt = MockQtClass()
    QThread = MockQtClass
    QTimer = MockQtClass
    QPoint = MockQtClass
    QRect = MockQtClass
    QSize = MockQtClass

    # GUI classes
    QColor = MockQtClass
    QFont = MockQtClass
    QFontMetrics = MockQtClass
    QIcon = MockQtClass
    QKeyEvent = MockQtClass
    QKeySequence = MockQtClass
    QMouseEvent = MockQtClass
    QPainter = MockQtClass
    QPaintEvent = MockQtClass
    QPen = MockQtClass
    QPixmap = MockQtClass
    QResizeEvent = MockQtClass

    # Widget classes
    QAbstractItemView = MockQtClass
    QAbstractScrollArea = MockQtClass
    QAction = MockQtClass
    QApplication = MockQtClass
    QButtonGroup = MockQtClass
    QCheckBox = MockQtClass
    QComboBox = MockQtClass
    QDesktopWidget = MockQtClass
    QDialog = MockQtClass
    QDialogButtonBox = MockQtClass
    QFileDialog = MockQtClass
    QFormLayout = MockQtClass
    QFrame = MockQtClass
    QGridLayout = MockQtClass
    QGroupBox = MockQtClass
    QHBoxLayout = MockQtClass
    QHeaderView = MockQtClass
    QInputDialog = MockQtClass
    QLabel = MockQtClass
    QLineEdit = MockQtClass
    QListWidget = MockQtClass
    QListWidgetItem = MockQtClass
    QMainWindow = MockQtClass
    QMenu = MockQtClass
    QMessageBox = MockQtClass
    QPlainTextEdit = MockQtClass
    QProgressBar = MockQtClass
    QPushButton = MockQtClass
    QRadioButton = MockQtClass
    QScrollArea = MockQtClass
    QSizePolicy = MockQtClass
    QSlider = MockQtClass
    QSpacerItem = MockQtClass
    QSpinBox = MockQtClass
    QSplashScreen = MockQtClass
    QSplitter = MockQtClass
    QStatusBar = MockQtClass
    QTableWidget = MockQtClass
    QTableWidgetItem = MockQtClass
    QTabWidget = MockQtClass
    QTextBrowser = MockQtClass
    QTextEdit = MockQtClass
    QToolBar = MockQtClass
    QTreeWidget = MockQtClass
    QTreeWidgetItem = MockQtClass
    QVBoxLayout = MockQtClass
    QWidget = MockQtClass
    QWizard = MockQtClass
    QWizardPage = MockQtClass

    def pyqtSignal(*args, **kwargs):  # pylint: disable=unused-argument
        """
        Mock implementation of PyQt5's pyqtSignal when PyQt5 is not available.

        Args:
            *args: Signal type arguments (ignored)
            **kwargs: Signal keyword arguments (ignored)

        Returns:
            lambda: A no-op function that can be used as a signal attribute
        """
        return lambda: None
