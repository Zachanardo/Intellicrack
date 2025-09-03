"""This file is part of Intellicrack.
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

from intellicrack.logger import logger

"""
PyQt6 Import Handler

This module provides a centralized abstraction layer for all PyQt6 imports.
It handles PyQt6 availability detection and provides fallback implementations
when PyQt6 is not available.
"""

# PyQt6 availability detection and import handling
try:
    # QtCore imports
    from PyQt6.QtCore import (
        PYQT_VERSION_STR,
        QT_VERSION_STR,
        QAbstractItemModel,
        QAbstractTableModel,
        QBuffer,
        QCoreApplication,
        QDateTime,
        QFileInfo,
        QFileSystemWatcher,
        QIODevice,
        QMetaObject,
        QModelIndex,
        QObject,
        QPoint,
        QProcess,
        QRect,
        QRegularExpression,
        QRunnable,
        QSize,
        Qt,
        QThread,
        QThreadPool,
        QTimer,
        QUrl,
        QVariant,
        pyqtSignal,
        pyqtSlot,
    )

    # QtGui imports
    from PyQt6.QtGui import (
        QAction,
        QBrush,
        QCloseEvent,
        QColor,
        QDesktopServices,
        QDragEnterEvent,
        QDropEvent,
        QFont,
        QFontDatabase,
        QFontMetrics,
        QIcon,
        QImage,
        QKeyEvent,
        QKeySequence,
        QMouseEvent,
        QOpenGLContext,
        QPainter,
        QPaintEvent,
        QPalette,
        QPen,
        QPixmap,
        QResizeEvent,
        QShortcut,
        QStandardItem,
        QStandardItemModel,
        QSurfaceFormat,
        QSyntaxHighlighter,
        QTextCharFormat,
        QTextCursor,
        QTextDocument,
        QTextFormat,
        qRgba,
    )

    # QtWidgets imports
    from PyQt6.QtWidgets import (
        QAbstractItemView,
        QAbstractScrollArea,
        QApplication,
        QButtonGroup,
        QCheckBox,
        QColorDialog,
        QComboBox,
        QDialog,
        QDialogButtonBox,
        QDoubleSpinBox,
        QFileDialog,
        QFileIconProvider,
        QFontComboBox,
        QFormLayout,
        QFrame,
        QGraphicsScene,
        QGraphicsView,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QInputDialog,
        QLabel,
        QLineEdit,
        QListView,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QMenu,
        QMenuBar,
        QMessageBox,
        QPlainTextEdit,
        QProgressBar,
        QProgressDialog,
        QPushButton,
        QRadioButton,
        QScrollArea,
        QScrollBar,
        QSizePolicy,
        QSlider,
        QSpacerItem,
        QSpinBox,
        QSplashScreen,
        QSplitter,
        QStackedWidget,
        QStatusBar,
        QStyle,
        QTableView,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QTextBrowser,
        QTextEdit,
        QToolBar,
        QTreeView,
        QTreeWidget,
        QTreeWidgetItem,
        QVBoxLayout,
        QWidget,
        QWizard,
        QWizardPage,
    )

    # Optional PyQt6 modules with fallback handling
    try:
        from PyQt6.QtPrintSupport import QPrintDialog, QPrinter
    except ImportError:
        QPrintDialog = None
        QPrinter = None

    try:
        from PyQt6.QtWebEngineWidgets import QWebEngineView
    except ImportError:
        QWebEngineView = None

    try:
        from PyQt6.QtPdf import QPdfDocument
    except ImportError:
        QPdfDocument = None

    try:
        from PyQt6.QtPdfWidgets import QPdfView
    except ImportError:
        QPdfView = None

    try:
        from PyQt6.QtTest import QTest
    except ImportError:
        QTest = None

    try:
        from PyQt6.QtOpenGLWidgets import QOpenGLWidget
    except ImportError:
        QOpenGLWidget = None

    # Verify critical Qt model classes are available
    _ = QAbstractTableModel.__name__  # Used for table model implementations
    _ = QProgressDialog.__name__  # Used for progress indication dialogs
    _ = QScrollArea.__name__  # Used for scrollable content areas
    _ = QTabWidget.__name__  # Used for tabbed interfaces
    _ = QToolBar.__name__  # Used for application toolbars

    # Verify QtGui action and event classes are available
    _ = QAction.__name__  # Used for menu and toolbar actions
    _ = QShortcut.__name__  # Used for keyboard shortcuts
    _ = QKeyEvent.__name__  # Used for keyboard event handling
    _ = QMouseEvent.__name__  # Used for mouse event handling
    _ = QDragEnterEvent.__name__  # Used for drag-and-drop events
    _ = QDropEvent.__name__  # Used for drop event handling

    # Verify QtGui rendering and text classes are available
    _ = QFont.__name__  # Used for font styling
    _ = QFontMetrics.__name__  # Used for font measurement
    _ = QIcon.__name__  # Used for application icons
    _ = QPixmap.__name__  # Used for image rendering
    _ = QPainter.__name__  # Used for custom drawing
    _ = QPen.__name__  # Used for drawing lines and borders
    _ = QSyntaxHighlighter.__name__  # Used for text syntax highlighting
    _ = QTextCharFormat.__name__  # Used for text formatting
    _ = QTextDocument.__name__  # Used for rich text documents

    # Verify QtWidgets container and item classes
    _ = QButtonGroup.__name__  # Used for button group management
    _ = QListWidgetItem.__name__  # Used for list widget items
    _ = QTreeWidgetItem.__name__  # Used for tree widget items
    _ = QFontComboBox.__name__  # Used for font selection widgets
    _ = QGraphicsScene.__name__  # Used for graphics scene management

    HAS_PYQT = True
    PYQT6_AVAILABLE = True

except ImportError as e:
    logger.error("PyQt6 not available: %s", e)
    HAS_PYQT = False
    PYQT6_AVAILABLE = False

    import os

    # Create mock classes instead of None to prevent inheritance errors
    class MockWidget:
        def __init__(self, *args, **kwargs):
            self._mock_name = "MockWidget"

        def __getattr__(self, name):
            # Return mock objects that can handle nested attribute access
            return MockWidget()

        def isVisible(self):
            return False

        def show(self):
            pass

        def hide(self):
            pass

        def __call__(self, *args, **kwargs):
            return None

        def __int__(self):
            return 0

        def __str__(self):
            return "MockWidget"

        def __bool__(self):
            return False

        @classmethod
        def instance(cls):
            # Mock QApplication.instance() method
            return None

        def exec(self):
            # Mock exec method for QApplication
            return 0

        def processEvents(self):
            # Mock processEvents for QApplication
            pass

        def quit(self):
            # Mock quit method
            pass

        def exit(self, code=0):
            # Mock exit method
            return code

        def connect(self, *args, **kwargs):
            # Mock connect method for pyqtSignal
            pass

        def disconnect(self, *args, **kwargs):
            # Mock disconnect method for pyqtSignal
            pass

        def emit(self, *args, **kwargs):
            # Mock emit method for pyqtSignal
            pass

        @classmethod
        def critical(cls, parent, title, message, buttons=None, default=None):
            # Mock QMessageBox.critical
            return 0

        @classmethod
        def warning(cls, parent, title, message, buttons=None, default=None):
            # Mock QMessageBox.warning
            return 0

        @classmethod
        def information(cls, parent, title, message, buttons=None, default=None):
            # Mock QMessageBox.information
            return 0

        @classmethod
        def question(cls, parent, title, message, buttons=None, default=None):
            # Mock QMessageBox.question
            return 0

    # Special mock class for Qt namespace with nested enumerations
    class MockQt:
        def __init__(self):
            self._mock_name = "MockQt"

        def __getattr__(self, name):
            # Create nested mock objects for Qt enumerations
            if name in (
                "ItemDataRole",
                "Orientation",
                "KeyboardModifier",
                "MouseButton",
                "WindowState",
                "WindowType",
                "FocusPolicy",
                "TextFormat",
                "SortOrder",
                "CheckState",
                "ToolButtonStyle",
                "LayoutDirection",
            ):
                return MockQtEnum()
            return MockWidget()

        def __call__(self, *args, **kwargs):
            return None

        def __int__(self):
            return 0

        def __bool__(self):
            return False

    # Mock class for Qt enumerations that provides common enum values
    class MockQtEnum:
        def __init__(self):
            self._mock_name = "MockQtEnum"

        def __getattr__(self, name):
            # Return integer values for common Qt enum values
            if name in ("DisplayRole", "EditRole", "UserRole", "DecorationRole"):
                return 0  # Qt.ItemDataRole.DisplayRole = 0
            elif name in ("Horizontal", "Vertical"):
                return 1 if name == "Horizontal" else 2
            elif name in ("Ascending", "Descending"):
                return 0 if name == "Ascending" else 1
            elif name in ("Unchecked", "PartiallyChecked", "Checked"):
                return {"Unchecked": 0, "PartiallyChecked": 1, "Checked": 2}[name]
            else:
                return 0  # Default enum value

        def __int__(self):
            return 0

        def __call__(self, *args, **kwargs):
            return 0

    # Mock classes for testing mode to prevent TypeError: NoneType takes no arguments
    if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
        PYQT_VERSION_STR = "Mock"
        QAbstractItemModel = MockWidget
        QAbstractItemView = MockWidget
        QAbstractScrollArea = MockWidget
        QAction = MockWidget
        QApplication = MockWidget
        QBrush = MockWidget
        QBuffer = MockWidget
        QButtonGroup = MockWidget
        QCheckBox = MockWidget
        QCloseEvent = MockWidget
        QColor = MockWidget
        QColorDialog = MockWidget
        QComboBox = MockWidget
        QCoreApplication = MockWidget
        QDateTime = MockWidget
        QDesktopServices = MockWidget
        QDialog = MockWidget
    else:
        # Null object pattern for all PyQt6 classes when not available (non-testing)
        PYQT_VERSION_STR = None
        QAbstractItemModel = None
        QAbstractItemView = None
        QAbstractScrollArea = None
        QAction = None
        QApplication = None
        QBrush = None
        QBuffer = None
        QButtonGroup = None
        QCheckBox = None
        QCloseEvent = None
        QColor = None
        QColorDialog = None
        QComboBox = None
        QCoreApplication = None
        QDateTime = None
        QDesktopServices = None
        QDialog = None
    # Continue testing mode assignment for remaining Qt classes
    if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
        QDialogButtonBox = MockWidget
        QDoubleSpinBox = MockWidget
        QDragEnterEvent = MockWidget
        QDropEvent = MockWidget
        QFileDialog = MockWidget
        QFileIconProvider = MockWidget
        QFileInfo = MockWidget
        QFileSystemWatcher = MockWidget
        QFont = MockWidget
        QFontDatabase = MockWidget
        QFontMetrics = MockWidget
        QFormLayout = MockWidget
        QFrame = MockWidget
        QGraphicsView = MockWidget
        QGridLayout = MockWidget
        QGroupBox = MockWidget
        QHBoxLayout = MockWidget
        QHeaderView = MockWidget
        QIODevice = MockWidget
        QIcon = MockWidget
        QImage = MockWidget
        QInputDialog = MockWidget
        QKeyEvent = MockWidget
        QKeySequence = MockWidget
        QLabel = MockWidget
        QLineEdit = MockWidget
        QListView = MockWidget
        QListWidget = MockWidget
        QListWidgetItem = MockWidget
        QMainWindow = MockWidget
        QMenu = MockWidget
        QMenuBar = MockWidget
        QMessageBox = MockWidget
        QMetaObject = MockWidget
        QModelIndex = MockWidget
        QMouseEvent = MockWidget
        QObject = MockWidget
        QOpenGLContext = MockWidget
        QOpenGLWidget = MockWidget
        QPaintEvent = MockWidget
        QPainter = MockWidget
        QPalette = MockWidget
        QPdfDocument = MockWidget
        QPdfView = MockWidget
        QPen = MockWidget
        QPixmap = MockWidget
        QPlainTextEdit = MockWidget
        QPoint = MockWidget
        QPrintDialog = MockWidget
        QPrinter = MockWidget
        QProcess = MockWidget
        QProgressBar = MockWidget
        QProgressDialog = MockWidget
        QPushButton = MockWidget
        QT_VERSION_STR = "Mock"
        QRadioButton = MockWidget
        QRect = MockWidget
        QRegularExpression = MockWidget
        QResizeEvent = MockWidget
        QRunnable = MockWidget
        QShortcut = MockWidget
        QScrollArea = MockWidget
        QScrollBar = MockWidget
        QSize = MockWidget
        QSizePolicy = MockWidget
        QSlider = MockWidget
        QSpacerItem = MockWidget
        QSpinBox = MockWidget
        QSplashScreen = MockWidget
        QSplitter = MockWidget
        QStackedWidget = MockWidget
        QStandardItem = MockWidget
        QStandardItemModel = MockWidget
        QStatusBar = MockWidget
        QStyle = MockWidget
        QSurfaceFormat = MockWidget
    else:
        QDialogButtonBox = None
        QDoubleSpinBox = None
        QDragEnterEvent = None
        QDropEvent = None
        QFileDialog = None
        QFileIconProvider = None
        QFileInfo = None
        QFileSystemWatcher = None
        QFont = None
        QFontDatabase = None
        QFontMetrics = None
        QFormLayout = None
        QFrame = None
        QGraphicsView = None
        QGridLayout = None
        QGroupBox = None
        QHBoxLayout = None
        QHeaderView = None
        QIODevice = None
        QIcon = None
        QImage = None
        QInputDialog = None
        QKeyEvent = None
        QKeySequence = None
        QLabel = None
        QLineEdit = None
        QListView = None
        QListWidget = None
        QListWidgetItem = None
        QMainWindow = None
        QMenu = None
        QMenuBar = None
        QMessageBox = None
        QMetaObject = None
        QModelIndex = None
        QMouseEvent = None
        QObject = None
        QOpenGLContext = None
        QOpenGLWidget = None
        QPaintEvent = None
        QPainter = None
        QPalette = None
        QPdfDocument = None
        QPdfView = None
        QPen = None
        QPixmap = None
        QPlainTextEdit = None
        QPoint = None
        QPrintDialog = None
        QPrinter = None
        QProcess = None
        QProgressBar = None
        QProgressDialog = None
        QPushButton = None
        QT_VERSION_STR = None
        QRadioButton = None
        QRect = None
        QRegularExpression = None
        QResizeEvent = None
        QRunnable = None
        QShortcut = None
        QScrollArea = None
        QScrollBar = None
        QSize = None
        QSizePolicy = None
        QSlider = None
        QSpacerItem = None
        QSpinBox = None
        QSplashScreen = None
        QSplitter = None
        QStackedWidget = None
        QStandardItem = None
        QStandardItemModel = None
        QStatusBar = None
        QStyle = None
        QSurfaceFormat = None
    # Finish testing mode assignment for final Qt classes
    if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
        QSyntaxHighlighter = MockWidget
        QTabWidget = MockWidget
        QTableView = MockWidget
        QTableWidget = MockWidget
        QTableWidgetItem = MockWidget
        QTest = MockWidget
        QTextBrowser = MockWidget
        QTextCharFormat = MockWidget
        QTextCursor = MockWidget
        QTextDocument = MockWidget
        QTextEdit = MockWidget
        QTextFormat = MockWidget
        QThread = MockWidget
        QThreadPool = MockWidget
        QTimer = MockWidget
        QToolBar = MockWidget
        QTreeView = MockWidget
        QTreeWidget = MockWidget
        QTreeWidgetItem = MockWidget
        QUrl = MockWidget
        QVariant = MockWidget
        QVBoxLayout = MockWidget
        QWebEngineView = MockWidget
        QWidget = MockWidget
        QWizard = MockWidget
        QWizardPage = MockWidget
        Qt = MockQt()

        def pyqtSignal(*args, **kwargs):
            """Fallback pyqtSignal implementation when PyQt6 is not available."""
            return lambda *a, **kw: None

        def pyqtSlot(*args, **kwargs):
            """Fallback pyqtSlot decorator implementation when PyQt6 is not available."""
            return lambda *a, **kw: None

        def qRgba(*args):
            """Fallback RGBA color function when PyQt6 is not available."""
            return None
    else:
        QSyntaxHighlighter = None
        QTabWidget = None
        QTableView = None
        QTableWidget = None
        QTableWidgetItem = None
        QTest = None
        QTextBrowser = None
        QTextCharFormat = None
        QTextCursor = None
        QTextDocument = None
        QTextEdit = None
        QTextFormat = None
        QThread = None
        QThreadPool = None
        QTimer = None
        QToolBar = None
        QTreeView = None
        QTreeWidget = None
        QTreeWidgetItem = None
        QUrl = None
        QVariant = None
        QVBoxLayout = None
        QWebEngineView = None
        QWidget = None
        QWizard = None
        QWizardPage = None
        Qt = None

        def pyqtSignal(*args, **kwargs):
            """Fallback pyqtSignal implementation for minimal PyQt6 compatibility."""
            return lambda: None

        def pyqtSlot(*args, **kwargs):
            """Fallback pyqtSlot decorator for minimal PyQt6 compatibility."""
            return lambda: None

        qRgba = None


# Export all PyQt6 classes and availability flag
__all__ = [
    # Availability flag
    "HAS_PYQT",
    "PYQT6_AVAILABLE",
    # QtCore imports
    "PYQT_VERSION_STR",
    "QAbstractItemModel",
    "QBuffer",
    "QCoreApplication",
    "QDateTime",
    "QFileInfo",
    "QFileSystemWatcher",
    "QIODevice",
    "QMetaObject",
    "QModelIndex",
    "QObject",
    "QPoint",
    "QProcess",
    "QRect",
    "QRegularExpression",
    "QRunnable",
    "QSize",
    "QT_VERSION_STR",
    "QThread",
    "QThreadPool",
    "QTimer",
    "QUrl",
    "QVariant",
    "Qt",
    "pyqtSignal",
    "pyqtSlot",
    # QtGui imports
    "QAction",
    "QBrush",
    "QCloseEvent",
    "QColor",
    "QDesktopServices",
    "QDragEnterEvent",
    "QDropEvent",
    "QFont",
    "QFontDatabase",
    "QFontMetrics",
    "QIcon",
    "QImage",
    "QKeyEvent",
    "QKeySequence",
    "QMouseEvent",
    "QOpenGLContext",
    "QPaintEvent",
    "QPainter",
    "QPalette",
    "QPen",
    "QPixmap",
    "QResizeEvent",
    "QShortcut",
    "QStandardItem",
    "QStandardItemModel",
    "QSurfaceFormat",
    "QSyntaxHighlighter",
    "QTextCharFormat",
    "QTextCursor",
    "QTextDocument",
    "QTextFormat",
    "qRgba",
    # QtWidgets imports
    "QAbstractItemView",
    "QAbstractScrollArea",
    "QApplication",
    "QButtonGroup",
    "QCheckBox",
    "QColorDialog",
    "QComboBox",
    "QDialog",
    "QDialogButtonBox",
    "QDoubleSpinBox",
    "QFileDialog",
    "QFileIconProvider",
    "QFormLayout",
    "QFrame",
    "QGraphicsView",
    "QGridLayout",
    "QGroupBox",
    "QHBoxLayout",
    "QHeaderView",
    "QInputDialog",
    "QLabel",
    "QLineEdit",
    "QListView",
    "QListWidget",
    "QListWidgetItem",
    "QMainWindow",
    "QMenu",
    "QMenuBar",
    "QMessageBox",
    "QPlainTextEdit",
    "QProgressBar",
    "QProgressDialog",
    "QPushButton",
    "QRadioButton",
    "QScrollArea",
    "QScrollBar",
    "QSizePolicy",
    "QSlider",
    "QSpacerItem",
    "QSpinBox",
    "QSplashScreen",
    "QSplitter",
    "QStackedWidget",
    "QStatusBar",
    "QStyle",
    "QTabWidget",
    "QTableView",
    "QTableWidget",
    "QTableWidgetItem",
    "QTextBrowser",
    "QTextEdit",
    "QToolBar",
    "QTreeView",
    "QTreeWidget",
    "QTreeWidgetItem",
    "QVBoxLayout",
    "QWidget",
    "QWizard",
    "QWizardPage",
    # Optional imports
    "QPrintDialog",
    "QPrinter",
    "QWebEngineView",
    "QPdfDocument",
    "QPdfView",
    "QTest",
    "QOpenGLWidget",
]
