"""
Smart Program Selector Dialog

Provides an intelligent interface for selecting programs for analysis
via desktop shortcuts, file resolution, and program discovery.
"""

import os
import sys
from typing import List, Optional

# Qt imports with fallback handling
try:
    from PyQt5.QtCore import QThread, QTimer, pyqtSignal
    from PyQt5.QtGui import QIcon, QPixmap
    from PyQt5.QtWidgets import (
        QApplication,
        QCheckBox,
        QDialog,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QListWidget,
        QListWidgetItem,
        QProgressBar,
        QPushButton,
        QTabWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
    HAS_QT = True
except ImportError:
    # Fallback definitions for when PyQt5 is not available
    QDialog = object
    QVBoxLayout = object
    QHBoxLayout = object
    QLabel = object
    QPushButton = object
    QListWidget = object
    QListWidgetItem = object
    QTextEdit = object
    QProgressBar = object
    QCheckBox = object
    QGroupBox = object
    QTabWidget = object
    QWidget = object
    QApplication = object
    QThread = object
    pyqtSignal = lambda *args: None
    QTimer = object
    QIcon = object
    QPixmap = object
    HAS_QT = False

# Import program discovery components
try:
    from ...utils.system.file_resolution import file_resolver
    from ...utils.system.program_discovery import ProgramInfo, program_discovery_engine
    HAS_PROGRAM_DISCOVERY = True
except ImportError:
    program_discovery_engine = None
    ProgramInfo = None
    file_resolver = None
    HAS_PROGRAM_DISCOVERY = False


class ProgramDiscoveryWorker(QThread):
    """Worker thread for program discovery operations."""

    programs_found = pyqtSignal(list)
    progress_updated = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, discovery_paths: List[str]):
        super().__init__()
        self.discovery_paths = discovery_paths
        self.running = True

    def run(self):
        """Run program discovery in background thread."""
        if not HAS_PROGRAM_DISCOVERY:
            self.progress_updated.emit("Program discovery not available")
            self.finished.emit()
            return

        all_programs = []

        for path in self.discovery_paths:
            if not self.running:
                break

            self.progress_updated.emit(f"Scanning {path}...")

            try:
                programs = program_discovery_engine.discover_programs_from_path(path)
                all_programs.extend(programs)
                self.progress_updated.emit(f"Found {len(programs)} programs in {path}")
            except Exception as e:
                self.progress_updated.emit(f"Error scanning {path}: {str(e)}")

        self.programs_found.emit(all_programs)
        self.finished.emit()

    def stop(self):
        """Stop the discovery process."""
        self.running = False


class SmartProgramSelectorDialog(QDialog):
    """Smart program selector dialog with intelligent discovery."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Smart Program Selector")
        self.setModal(True)
        self.resize(800, 600)

        # Initialize attributes
        self.selected_program: Optional[ProgramInfo] = None
        self.discovery_worker: Optional[ProgramDiscoveryWorker] = None
        self.discovery_timer = QTimer()

        if HAS_QT:
            self.setup_ui()
            self.connect_signals()

    def setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)

        # Title
        title_label = QLabel("Select a Program for Analysis")
        layout.addWidget(title_label)

        # Programs list
        self.programs_list = QListWidget()
        layout.addWidget(self.programs_list)

        # Progress area
        self.progress_text = QTextEdit()
        self.progress_text.setMaximumHeight(100)
        layout.addWidget(self.progress_text)

        # Buttons
        button_layout = QHBoxLayout()

        self.scan_button = QPushButton("Scan for Programs")
        self.analyze_button = QPushButton("Analyze Selected")
        self.cancel_button = QPushButton("Cancel")

        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.analyze_button)
        button_layout.addWidget(self.cancel_button)

        layout.addLayout(button_layout)

    def connect_signals(self):
        """Connect UI signals."""
        if HAS_QT:
            self.scan_button.clicked.connect(self.start_program_discovery)
            self.analyze_button.clicked.connect(self.analyze_selected_program)
            self.cancel_button.clicked.connect(self.reject)

    def start_program_discovery(self):
        """Start program discovery process."""
        if not HAS_PROGRAM_DISCOVERY:
            self.progress_text.append("Program discovery not available")
            return

        # Get common program locations
        discovery_paths = self.get_discovery_paths()

        # Start worker thread
        self.discovery_worker = ProgramDiscoveryWorker(discovery_paths)
        self.discovery_worker.programs_found.connect(self.handle_programs_found)
        self.discovery_worker.progress_updated.connect(self.update_progress)
        self.discovery_worker.finished.connect(self.discovery_finished)

        self.discovery_worker.start()
        self.scan_button.setEnabled(False)

    def get_discovery_paths(self) -> List[str]:
        """Get paths to scan for programs."""
        paths = []

        if sys.platform.startswith('win'):
            # Windows paths
            user_profile = os.environ.get('USERPROFILE', '')
            if user_profile:
                paths.extend([
                    os.path.join(user_profile, 'Desktop'),
                    os.path.join(user_profile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs')
                ])
            paths.extend([
                r'C:\Users\Public\Desktop',
                r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs'
            ])
        elif sys.platform.startswith('linux'):
            # Linux paths
            home = os.environ.get('HOME', '')
            if home:
                paths.extend([
                    os.path.join(home, 'Desktop'),
                    os.path.join(home, '.local', 'share', 'applications')
                ])
            paths.extend([
                '/usr/share/applications',
                '/usr/local/share/applications'
            ])
        elif sys.platform.startswith('darwin'):
            # macOS paths
            home = os.environ.get('HOME', '')
            if home:
                paths.extend([
                    os.path.join(home, 'Desktop'),
                    os.path.join(home, 'Applications')
                ])
            paths.extend([
                '/Applications',
                '/System/Applications'
            ])

        # Filter to existing paths
        return [path for path in paths if os.path.exists(path)]

    def handle_programs_found(self, programs: List[ProgramInfo]):
        """Handle discovered programs."""
        self.programs_list.clear()

        for program in programs:
            item = QListWidgetItem(f"{program.display_name} ({program.discovery_method})")
            item.setData(32, program)  # Store program object
            self.programs_list.addItem(item)

    def update_progress(self, message: str):
        """Update progress display."""
        self.progress_text.append(message)

    def discovery_finished(self):
        """Handle discovery completion."""
        self.scan_button.setEnabled(True)
        self.progress_text.append("Discovery completed.")

    def analyze_selected_program(self):
        """Analyze the selected program."""
        current_item = self.programs_list.currentItem()
        if current_item:
            self.selected_program = current_item.data(32)
            self.accept()

    def get_selected_program(self) -> Optional[ProgramInfo]:
        """Get the selected program."""
        return self.selected_program


def show_smart_program_selector(parent=None) -> Optional[ProgramInfo]:
    """Show the smart program selector dialog."""
    if not HAS_QT:
        return None

    dialog = SmartProgramSelectorDialog(parent)
    if dialog.exec_() == QDialog.Accepted:
        return dialog.get_selected_program()
    return None
