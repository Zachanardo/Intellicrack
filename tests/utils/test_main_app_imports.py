#!/usr/bin/env python
"""Test imports in main_app.py step by step"""

import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

print("Testing main_app.py imports step by step...")

try:
    print("1. Testing pyqt6_handler import...")
    from intellicrack.handlers.pyqt6_handler import HAS_PYQT, QMainWindow, QApplication
    print(f"   ✅ pyqt6_handler imported successfully, HAS_PYQT: {HAS_PYQT}")

    print("2. Testing individual PyQt6 components...")
    try:
        from intellicrack.handlers.pyqt6_handler import (
            QAbstractItemView,
            QAction,
            QApplication,
            QButtonGroup,
            QCheckBox,
            QColor,
            QComboBox,
            QCoreApplication,
            QDateTime,
            QDesktopServices,
            QDialog,
            QDialogButtonBox,
            QDoubleSpinBox,
            QFileDialog,
            QFileIconProvider,
            QFileInfo,
            QFont,
            QFormLayout,
            QFrame,
            QGridLayout,
            QGroupBox,
            QHBoxLayout,
            QHeaderView,
            QIcon,
            QInputDialog,
            QLabel,
            QLineEdit,
            QListWidget,
            QListWidgetItem,
            QMainWindow,
        )
        print("   ✅ First batch of PyQt6 components imported successfully")

        # Test more components
        from intellicrack.handlers.pyqt6_handler import (
            QMenu,
            QMessageBox,
            QMetaObject,
            QModelIndex,
            QPainter,
            QPalette,
            QPdfDocument,
            QPdfView,
            QPen,
            QPixmap,
            QPlainTextEdit,
            QPrintDialog,
            QPrinter,
            QProgressBar,
            QProgressDialog,
            QPushButton,
            QRadioButton,
            QScrollArea,
            QSettings,
            QSize,
            QSizePolicy,
            QSlider,
            QSpacerItem,
            QSpinBox,
            QSplitter,
            QStackedWidget,
            QStyle,
            Qt,
            QTableView,
            QTableWidget,
            QTableWidgetItem,
            QTabWidget,
            QTextBrowser,
            QTextCursor,
            QTextEdit,
            QThread,
            QTimer,
            QToolBar,
            QTreeWidget,
            QTreeWidgetItem,
            QUrl,
            QVBoxLayout,
            QWebEngineView,
            QWidget,
            QWizard,
            QWizardPage,
            pyqtSignal,
        )
        print("   ✅ All PyQt6 components imported successfully")
        print(f"   QMainWindow type: {type(QMainWindow)}")
        print(f"   QMainWindow has setGeometry: {hasattr(QMainWindow, 'setGeometry')}")

    except ImportError as e:
        print(f"   ❌ PyQt6 components import failed: {e}")
        import traceback
        traceback.print_exc()

except Exception as e:
    print(f"❌ Basic import failed: {e}")
    import traceback
    traceback.print_exc()
