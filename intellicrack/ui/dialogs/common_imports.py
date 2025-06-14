"""
Common imports for dialog modules.

This module centralizes common PyQt5 imports to avoid duplication.
"""

import logging

# Common PyQt5 imports
try:
    from PyQt5.QtCore import Qt, QThread, QTimer, pyqtSignal
    from PyQt5.QtGui import QFont, QIcon, QPixmap
    from PyQt5.QtWidgets import (
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
except ImportError:
    HAS_PYQT = False
    
    # Stub classes for when PyQt is not available
    class QDialog:
        pass
    
    class QThread:
        pass
    
    def pyqtSignal(*args, **kwargs):
        return lambda: None

logger = logging.getLogger(__name__)