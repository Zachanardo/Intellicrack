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
        QSettings,
        QSize,
        Qt,
        QThread,
        QThreadPool,
        QTimer,
        QUrl,
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

    HAS_PYQT = True
    PYQT6_AVAILABLE = True

except ImportError as e:
    logger.error("PyQt6 not available: %s", e)
    HAS_PYQT = False
    PYQT6_AVAILABLE = False

    # Null object pattern for all PyQt6 classes when not available
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
    QScrollArea = None
    QScrollBar = None
    QSettings = None
    QSize = None
    QSizePolicy = None
    QSlider = None
    QSpacerItem = None
    QSpinBox = None
    QSplashScreen = None
    QSplitter = None
    QStandardItem = None
    QStandardItemModel = None
    QStatusBar = None
    QStyle = None
    QSurfaceFormat = None
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
    QVBoxLayout = None
    QWebEngineView = None
    QWidget = None
    QWizard = None
    QWizardPage = None
    Qt = None
    pyqtSignal = lambda *args, **kwargs: lambda: None
    pyqtSlot = lambda *args, **kwargs: lambda: None
    qRgba = None


# Export all PyQt6 classes and availability flag
__all__ = [
    # Availability flag
    "HAS_PYQT",
    "PYQT6_AVAILABLE",
    # QtCore imports
    "PYQT_VERSION_STR", "QAbstractItemModel", "QBuffer", "QCoreApplication", "QDateTime",
    "QFileInfo", "QFileSystemWatcher", "QIODevice", "QMetaObject", "QModelIndex", "QObject", "QPoint",
    "QProcess", "QRect", "QRegularExpression", "QRunnable", "QSettings", "QSize",
    "QT_VERSION_STR", "QThread", "QThreadPool", "QTimer", "QUrl", "Qt", "pyqtSignal", "pyqtSlot",
    # QtGui imports
    "QAction", "QBrush", "QCloseEvent", "QColor", "QDesktopServices", "QDragEnterEvent",
    "QDropEvent", "QFont", "QFontDatabase", "QFontMetrics", "QIcon", "QImage", "QKeyEvent", "QKeySequence", "QMouseEvent", "QOpenGLContext",
    "QPaintEvent", "QPainter", "QPalette", "QPen", "QPixmap", "QResizeEvent", "QStandardItem", "QStandardItemModel", "QSurfaceFormat", "QSyntaxHighlighter",
    "QTextCharFormat", "QTextCursor", "QTextDocument", "QTextFormat", "qRgba",
    # QtWidgets imports
    "QAbstractItemView", "QAbstractScrollArea", "QApplication", "QButtonGroup", "QCheckBox", "QColorDialog", "QComboBox", "QDialog",
    "QDialogButtonBox", "QDoubleSpinBox", "QFileDialog", "QFileIconProvider", "QFormLayout",
    "QFrame", "QGraphicsView", "QGridLayout", "QGroupBox", "QHBoxLayout", "QHeaderView",
    "QInputDialog", "QLabel", "QLineEdit", "QListView", "QListWidget", "QListWidgetItem",
    "QMainWindow", "QMenu", "QMenuBar", "QMessageBox", "QPlainTextEdit", "QProgressBar",
    "QProgressDialog", "QPushButton", "QRadioButton", "QScrollArea", "QScrollBar", "QSizePolicy",
    "QSlider", "QSpacerItem", "QSpinBox", "QSplashScreen", "QSplitter", "QStatusBar",
    "QStyle", "QTabWidget", "QTableView", "QTableWidget", "QTableWidgetItem", "QTextBrowser",
    "QTextEdit", "QToolBar", "QTreeView", "QTreeWidget", "QTreeWidgetItem", "QVBoxLayout", "QWidget",
    "QWizard", "QWizardPage",
    # Optional imports
    "QPrintDialog", "QPrinter", "QWebEngineView", "QPdfDocument", "QPdfView", "QTest", "QOpenGLWidget",
]
