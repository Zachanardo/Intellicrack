"""
Smart Program Selector Dialog for Intellicrack.

Provides intelligent program discovery from desktop shortcuts, executables,
and installation folders with automatic licensing analysis integration.

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

import logging
import os
import subprocess
import sys
from pathlib import Path

from ...utils.system.file_resolution import file_resolver
from ...utils.system.program_discovery import ProgramDiscoveryEngine
from .common_imports import (
    HAS_PYQT,
    QCheckBox,
    QDialog,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    Qt,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

if HAS_PYQT:
    from PyQt5.QtCore import QThread, QTimer, pyqtSignal
    from PyQt5.QtGui import QFont
    from PyQt5.QtWidgets import QStyle
else:
    # Fallback definitions when PyQt is not available
    QThread = object
    QTimer = object
    pyqtSignal = lambda *args: lambda x: x


logger = logging.getLogger(__name__)


class ProgramDiscoveryThread(QThread):
    """Background thread for program discovery operations."""

    program_found = pyqtSignal(dict)
    discovery_progress = pyqtSignal(str, int)
    discovery_complete = pyqtSignal()

    def __init__(self, discovery_engine, search_paths=None):
        super().__init__()
        self.discovery_engine = discovery_engine
        self.search_paths = search_paths or []
        self.should_stop = False

    def stop_discovery(self):
        """Stop the discovery process."""
        self.should_stop = True

    def run(self):
        """Run program discovery in background."""
        try:
            if self.search_paths:
                # Discover from specific paths
                for i, path in enumerate(self.search_paths):
                    if self.should_stop:
                        break

                    self.discovery_progress.emit(f"Scanning {path}...",
                                               int((i / len(self.search_paths)) * 100))

                    programs = self.discovery_engine.discover_programs_from_path(path)
                    for program in programs:
                        if not self.should_stop:
                            self.program_found.emit(program.__dict__)
            else:
                # Full system discovery
                self.discovery_progress.emit("Scanning installed programs...", 10)
                installed_programs = self.discovery_engine.get_installed_programs()

                for i, program in enumerate(installed_programs):
                    if self.should_stop:
                        break

                    progress = 10 + int((i / len(installed_programs)) * 80)
                    self.discovery_progress.emit(f"Found {program.display_name}", progress)
                    self.program_found.emit(program.__dict__)

                # Scan common executable directories
                self.discovery_progress.emit("Scanning executable directories...", 90)
                executable_programs = self.discovery_engine.scan_executable_directories()

                for program in executable_programs:
                    if not self.should_stop:
                        self.program_found.emit(program.__dict__)

            self.discovery_progress.emit("Discovery complete", 100)
            self.discovery_complete.emit()

        except Exception as e:
            logger.error(f"Error in program discovery thread: {e}")
            self.discovery_complete.emit()


class ProgramSelectorDialog(QDialog):
    """
    Program Selector Dialog with intelligent shortcut resolution
    and installation folder discovery.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.discovery_engine = ProgramDiscoveryEngine()
        self.discovery_thread = None
        self.selected_program = None
        self.installation_folder = None
        self.licensing_files = []

        self.setWindowTitle("Program Selector - Intellicrack")
        self.setMinimumSize(1000, 700)
        self.resize(1200, 800)

        self.setup_ui()
        self.connect_signals()

        # Auto-scan desktop for shortcuts on startup
        QTimer.singleShot(100, self.scan_desktop_shortcuts)

    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)

        # Header
        header_layout = QHBoxLayout()

        title_label = QLabel("Program Selection")
        if HAS_PYQT:
            title_font = QFont()
            title_font.setPointSize(14)
            title_font.setBold(True)
            title_label.setFont(title_font)

        header_layout.addWidget(title_label)
        header_layout.addStretch()

        # Selection buttons
        self.select_file_btn = QPushButton("Select File/Shortcut")
        self.scan_desktop_btn = QPushButton("Scan Desktop")
        self.full_scan_btn = QPushButton("Full System Scan")

        if HAS_PYQT:
            self.select_file_btn.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
            self.scan_desktop_btn.setIcon(self.style().standardIcon(QStyle.SP_DesktopIcon))
            self.full_scan_btn.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))

        header_layout.addWidget(self.select_file_btn)
        header_layout.addWidget(self.scan_desktop_btn)
        header_layout.addWidget(self.full_scan_btn)

        layout.addLayout(header_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Main content splitter
        splitter = QSplitter(Qt.Horizontal if HAS_PYQT else 1)

        # Left panel - Program list
        left_panel = QGroupBox("Discovered Programs")
        left_layout = QVBoxLayout(left_panel)

        # Search filter
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Filter:"))
        self.search_filter = QLineEdit()
        self.search_filter.setPlaceholderText("Type to filter programs...")
        search_layout.addWidget(self.search_filter)
        left_layout.addLayout(search_layout)

        # Programs table
        self.programs_table = QTableWidget()
        self.programs_table.setColumnCount(4)
        self.programs_table.setHorizontalHeaderLabels(["Program Name", "Version", "Publisher", "Path"])

        if HAS_PYQT:
            header = self.programs_table.horizontalHeader()
            header.setStretchLastSection(True)
            header.setSectionResizeMode(0, QHeaderView.Stretch)
            header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeToContents)

        self.programs_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.programs_table.setAlternatingRowColors(True)
        left_layout.addWidget(self.programs_table)

        splitter.addWidget(left_panel)

        # Right panel - Program details and installation analysis
        right_panel = QGroupBox("Program Analysis")
        right_layout = QVBoxLayout(right_panel)

        # Program info
        self.program_info = QTextEdit()
        self.program_info.setMaximumHeight(200)
        self.program_info.setReadOnly(True)
        right_layout.addWidget(QLabel("Program Information:"))
        right_layout.addWidget(self.program_info)

        # Installation folder analysis
        folder_group = QGroupBox("Installation Folder Analysis")
        folder_layout = QVBoxLayout(folder_group)

        # Folder path display
        folder_path_layout = QHBoxLayout()
        folder_path_layout.addWidget(QLabel("Installation Folder:"))
        self.folder_path_label = QLabel("No program selected")
        self.folder_path_label.setWordWrap(True)
        if HAS_PYQT:
            self.folder_path_label.setStyleSheet("QLabel { background-color: #f0f0f0; padding: 5px; }")
        folder_path_layout.addWidget(self.folder_path_label)
        folder_layout.addLayout(folder_path_layout)

        # Licensing files tree
        folder_layout.addWidget(QLabel("Detected Licensing Files:"))
        self.licensing_tree = QTreeWidget()
        self.licensing_tree.setHeaderLabels(["File", "Type", "Size", "Priority"])
        folder_layout.addWidget(self.licensing_tree)

        # Analysis options
        options_layout = QHBoxLayout()
        self.auto_analyze_checkbox = QCheckBox("Auto-analyze licensing files")
        self.auto_analyze_checkbox.setChecked(True)

        self.include_subdirs_checkbox = QCheckBox("Include subdirectories")
        self.include_subdirs_checkbox.setChecked(True)

        options_layout.addWidget(self.auto_analyze_checkbox)
        options_layout.addWidget(self.include_subdirs_checkbox)
        folder_layout.addLayout(options_layout)

        right_layout.addWidget(folder_group)

        splitter.addWidget(right_panel)

        # Set splitter proportions
        splitter.setSizes([600, 600])
        layout.addWidget(splitter)

        # Bottom buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.analyze_btn = QPushButton("Analyze Selected Program")
        self.analyze_btn.setEnabled(False)
        if HAS_PYQT:
            self.analyze_btn.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))

        self.cancel_btn = QPushButton("Cancel")
        if HAS_PYQT:
            self.cancel_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogCancelButton))

        button_layout.addWidget(self.analyze_btn)
        button_layout.addWidget(self.cancel_btn)

        layout.addLayout(button_layout)

    def connect_signals(self):
        """Connect UI signals to handlers."""
        self.select_file_btn.clicked.connect(self.select_file_or_shortcut)
        self.scan_desktop_btn.clicked.connect(self.scan_desktop_shortcuts)
        self.full_scan_btn.clicked.connect(self.full_system_scan)

        self.programs_table.itemSelectionChanged.connect(self.on_program_selected)
        self.search_filter.textChanged.connect(self.filter_programs)

        self.analyze_btn.clicked.connect(self.analyze_selected_program)
        self.cancel_btn.clicked.connect(self.reject)

        self.licensing_tree.itemDoubleClicked.connect(self.open_licensing_file)

    def select_file_or_shortcut(self):
        """Open file dialog to select program file or shortcut."""
        file_filters = file_resolver.get_supported_file_filters()

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Program File or Shortcut",
            "",
            file_filters
        )

        if file_path:
            self.process_selected_file(file_path)

    def process_selected_file(self, file_path):
        """Process a selected file or shortcut."""
        try:
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(10)

            # Resolve file path (handles shortcuts)
            resolved_path, metadata = file_resolver.resolve_file_path(file_path)

            self.progress_bar.setValue(30)

            if "error" in metadata:
                QMessageBox.warning(self, "Error", f"Could not process file: {metadata['error']}")
                self.progress_bar.setVisible(False)
                return

            # Create program info from resolved file
            program_info = self.create_program_info_from_file(resolved_path, metadata)

            self.progress_bar.setValue(60)

            # Add to programs table
            self.add_program_to_table(program_info)

            # Auto-select the new program
            last_row = self.programs_table.rowCount() - 1
            self.programs_table.selectRow(last_row)

            self.progress_bar.setValue(100)

            logger.info(f"Successfully processed file: {file_path} -> {resolved_path}")

        except Exception as e:
            logger.error(f"Error processing selected file {file_path}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to process file: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)

    def create_program_info_from_file(self, file_path, metadata):
        """Create program info dictionary from a resolved file."""
        file_path = Path(file_path)

        # Determine installation folder
        if metadata.get("is_shortcut"):
            # For shortcuts, use the target's parent directory
            install_folder = file_path.parent
        else:
            # For direct executables, use parent directory
            install_folder = file_path.parent

        # Try to get more program info from the discovery engine
        discovered_program = self.discovery_engine.analyze_program_from_path(str(install_folder))

        if discovered_program:
            return discovered_program.__dict__
        else:
            # Create basic program info
            return {
                "name": file_path.stem,
                "display_name": file_path.name,
                "version": "Unknown",
                "publisher": "Unknown",
                "install_location": str(install_folder),
                "executable_paths": [str(file_path)],
                "icon_path": None,
                "uninstall_string": None,
                "install_date": None,
                "estimated_size": metadata.get("size", 0),
                "architecture": "Unknown",
                "file_types": [file_path.suffix],
                "description": f"Program discovered from {metadata.get('resolution_method', 'direct')} selection",
                "registry_key": None,
                "discovery_method": "manual_selection",
                "confidence_score": 0.8,
                "analysis_priority": 5
            }

    def scan_desktop_shortcuts(self):
        """Scan desktop for shortcuts and analyze them."""
        desktop_paths = self.get_desktop_paths()

        if not desktop_paths:
            QMessageBox.information(self, "No Desktop Found", "Could not locate desktop folders.")
            return

        self.start_discovery_thread(desktop_paths)

    def get_desktop_paths(self):
        """Get desktop folder paths for current user."""
        desktop_paths = []

        if sys.platform.startswith('win'):
            # Windows desktop paths
            user_profile = os.environ.get('USERPROFILE', '')
            if user_profile:
                desktop_paths.extend([
                    os.path.join(user_profile, 'Desktop'),
                    os.path.join(user_profile, 'OneDrive', 'Desktop'),
                    r'C:\Users\Public\Desktop'
                ])
        elif sys.platform.startswith('linux'):
            # Linux desktop paths
            home = os.environ.get('HOME', '')
            if home:
                desktop_paths.extend([
                    os.path.join(home, 'Desktop'),
                    os.path.join(home, '.local', 'share', 'applications')
                ])
        elif sys.platform.startswith('darwin'):
            # macOS desktop paths
            home = os.environ.get('HOME', '')
            if home:
                desktop_paths.extend([
                    os.path.join(home, 'Desktop'),
                    '/Applications'
                ])

        # Filter to existing paths
        return [path for path in desktop_paths if os.path.exists(path)]

    def full_system_scan(self):
        """Perform full system scan for installed programs."""
        self.start_discovery_thread()

    def start_discovery_thread(self, search_paths=None):
        """Start background program discovery."""
        if self.discovery_thread and self.discovery_thread.isRunning():
            self.discovery_thread.stop_discovery()
            self.discovery_thread.wait()

        # Clear existing programs
        self.programs_table.setRowCount(0)

        # Start discovery
        self.discovery_thread = ProgramDiscoveryThread(self.discovery_engine, search_paths)
        self.discovery_thread.program_found.connect(self.add_program_to_table)
        self.discovery_thread.discovery_progress.connect(self.update_discovery_progress)
        self.discovery_thread.discovery_complete.connect(self.discovery_finished)

        self.progress_bar.setVisible(True)
        self.discovery_thread.start()

        # Disable buttons during discovery
        self.select_file_btn.setEnabled(False)
        self.scan_desktop_btn.setEnabled(False)
        self.full_scan_btn.setEnabled(False)

    def add_program_to_table(self, program_dict):
        """Add a program to the programs table."""
        row = self.programs_table.rowCount()
        self.programs_table.insertRow(row)

        # Store program data in first column item
        name_item = QTableWidgetItem(program_dict.get("display_name", "Unknown"))
        name_item.setData(Qt.UserRole, program_dict)
        self.programs_table.setItem(row, 0, name_item)

        self.programs_table.setItem(row, 1, QTableWidgetItem(program_dict.get("version", "Unknown")))
        self.programs_table.setItem(row, 2, QTableWidgetItem(program_dict.get("publisher", "Unknown")))
        self.programs_table.setItem(row, 3, QTableWidgetItem(program_dict.get("install_location", "Unknown")))

    def update_discovery_progress(self, message, progress):
        """Update discovery progress."""
        self.logger.debug(f"Discovery progress: {message} ({progress}%)")
        self.progress_bar.setValue(progress)
        # Could add status label here if needed

    def discovery_finished(self):
        """Handle discovery completion."""
        self.progress_bar.setVisible(False)

        # Re-enable buttons
        self.select_file_btn.setEnabled(True)
        self.scan_desktop_btn.setEnabled(True)
        self.full_scan_btn.setEnabled(True)

        # Show results
        program_count = self.programs_table.rowCount()
        if program_count == 0:
            QMessageBox.information(self, "Discovery Complete", "No programs found.")
        else:
            QMessageBox.information(self, "Discovery Complete", f"Found {program_count} programs.")

    def on_program_selected(self):
        """Handle program selection in table."""
        selected_items = self.programs_table.selectedItems()
        if not selected_items:
            self.analyze_btn.setEnabled(False)
            self.selected_program = None
            return

        # Get program data from first column
        row = selected_items[0].row()
        name_item = self.programs_table.item(row, 0)
        program_data = name_item.data(Qt.UserRole)

        if program_data:
            self.selected_program = program_data
            self.update_program_details(program_data)
            self.analyze_btn.setEnabled(True)

    def update_program_details(self, program_data):
        """Update program details panel."""
        # Update program info text
        info_text = f"""Program Name: {program_data.get('display_name', 'Unknown')}
Version: {program_data.get('version', 'Unknown')}
Publisher: {program_data.get('publisher', 'Unknown')}
Install Location: {program_data.get('install_location', 'Unknown')}
Discovery Method: {program_data.get('discovery_method', 'Unknown')}
Confidence Score: {program_data.get('confidence_score', 0):.2f}
Analysis Priority: {program_data.get('analysis_priority', 0)}

Description: {program_data.get('description', 'No description available')}"""

        self.program_info.setPlainText(info_text)

        # Update installation folder
        install_location = program_data.get('install_location', '')
        self.installation_folder = install_location
        self.folder_path_label.setText(install_location or "No installation folder detected")

        # Analyze installation folder for licensing files
        if install_location and os.path.exists(install_location):
            self.analyze_installation_folder(install_location)

    def analyze_installation_folder(self, folder_path):
        """Analyze installation folder for licensing files."""
        self.licensing_tree.clear()
        self.licensing_files = []

        try:
            # Comprehensive licensing patterns - from obvious to highly obscure
            licensing_patterns = {
                # Obvious licensing files
                'license': 10, 'licence': 10, 'eula': 10, 'terms': 9, 'agreement': 9,
                'copyright': 8, 'legal': 8, 'rights': 8, 'disclaimer': 7,

                # Activation and protection
                'activation': 9, 'serial': 9, 'key': 8, 'keyfile': 8, 'keystore': 8,
                'authenticate': 7, 'auth': 7, 'register': 7, 'registration': 8,
                'unlock': 7, 'unlocker': 8, 'crack': 9, 'patch': 8, 'keygen': 9,

                # Commercial licensing terms
                'commercial': 7, 'proprietary': 7, 'subscription': 6, 'trial': 6,
                'demo': 5, 'evaluation': 6, 'eval': 6, 'beta': 4, 'alpha': 4,

                # Legal and compliance
                'compliance': 6, 'policy': 5, 'privacy': 5, 'gdpr': 6, 'dmca': 7,
                'takedown': 6, 'notice': 5, 'attribution': 6, 'credits': 5,

                # Software protection schemes
                'dongle': 8, 'hasp': 8, 'sentinel': 8, 'flexlm': 8, 'rlm': 8,
                'safenet': 8, 'wibu': 8, 'codemeter': 8, 'reprise': 8,
                'macrovision': 7, 'installshield': 6, 'nalpeiron': 7,

                # Obscure protection files
                'lic': 8, 'dat': 6, 'bin': 5, 'db': 5, 'cfg': 5, 'conf': 5,
                'ini': 5, 'reg': 6, 'xml': 5, 'json': 4, 'sig': 7, 'cert': 7,
                'crt': 7, 'pem': 6, 'p7b': 6, 'p12': 6, 'pfx': 6,

                # Company-specific patterns
                'adobe': 7, 'autodesk': 7, 'microsoft': 6, 'oracle': 6,
                'vmware': 7, 'citrix': 7, 'symantec': 7, 'mcafee': 7,
                'norton': 7, 'kaspersky': 7, 'eset': 7, 'avast': 6,

                # Hidden/encoded files
                'hidden': 6, 'encoded': 6, 'encrypted': 7, 'obfuscated': 7,
                'protected': 7, 'secured': 6, 'locked': 6, 'vault': 7,

                # License server related
                'server': 5, 'daemon': 6, 'service': 5, 'client': 4,
                'manager': 5, 'admin': 5, 'control': 5, 'monitor': 5,

                # File integrity and validation
                'checksum': 6, 'hash': 6, 'md5': 6, 'sha1': 6, 'sha256': 6,
                'crc': 6, 'verify': 6, 'validate': 6, 'integrity': 6,

                # Backup and recovery
                'backup': 5, 'recovery': 5, 'restore': 5, 'emergency': 6,
                'rescue': 6, 'safe': 5, 'secure': 6,

                # Version and update control
                'version': 4, 'update': 4, 'patch': 6, 'hotfix': 5,
                'upgrade': 5, 'migration': 5, 'transfer': 5,

                # Obscure extensions and patterns
                'token': 7, 'ticket': 6, 'voucher': 6, 'permit': 7,
                'grant': 6, 'allow': 5, 'deny': 6, 'block': 6,
                'whitelist': 6, 'blacklist': 6, 'filter': 5,

                # Network licensing
                'network': 5, 'floating': 6, 'concurrent': 6, 'node': 5,
                'seat': 6, 'user': 4, 'machine': 5, 'hardware': 5,

                # Cryptographic elements
                'rsa': 6, 'dsa': 6, 'ecc': 6, 'aes': 6, 'des': 6,
                'blowfish': 6, 'twofish': 6, 'serpent': 6,

                # File naming conventions
                'readme': 4, 'install': 4, 'setup': 4, 'config': 4,
                'settings': 4, 'options': 4, 'preferences': 4,

                # Suspicious/crack-related terms
                'nfo': 7, 'diz': 6, 'scene': 6, 'release': 5,
                'team': 4, 'group': 4, 'crew': 5, 'union': 5,
                'force': 5, 'revenge': 6, 'paradox': 6, 'prophet': 6,

                # Database and storage
                'sqlite': 5, 'mysql': 5, 'postgres': 5, 'oracle': 6,
                'access': 5, 'firebird': 5, 'derby': 5,

                # Virtualization and sandboxing
                'virtual': 5, 'sandbox': 6, 'container': 5, 'docker': 5,
                'vm': 5, 'hyperv': 5, 'xen': 5, 'kvm': 5,

                # Hardware fingerprinting
                'fingerprint': 7, 'hwid': 7, 'hardware': 6, 'bios': 6,
                'uefi': 6, 'tpm': 7, 'smartcard': 7, 'usb': 6,

                # Time-based licensing
                'expire': 7, 'expiry': 7, 'timeout': 6, 'timer': 6,
                'countdown': 6, 'deadline': 6, 'schedule': 5,

                # Custom extensions that might hide licensing
                'x': 4, 'z': 4, 'tmp': 5, 'temp': 5, 'bak': 5,
                'old': 4, 'new': 4, 'orig': 5, 'copy': 4,

                # Vendor-specific file patterns
                'flexera': 7, 'installaware': 6, 'wise': 6, 'inno': 6,
                'nsis': 6, 'wix': 6, 'msi': 6, 'msm': 6, 'msp': 6,
            }

            # Comprehensive file extensions
            extensions = [
                # Text formats
                '.txt', '.rtf', '.doc', '.docx', '.pdf', '.html', '.htm', '.xml',
                '.json', '.yaml', '.yml', '.ini', '.cfg', '.conf', '.properties',

                # Binary formats
                '.dll', '.exe', '.sys', '.ocx', '.ax', '.cpl', '.scr',
                '.bin', '.dat', '.db', '.sqlite', '.mdb', '.accdb',

                # Certificate and key files
                '.cer', '.crt', '.der', '.pem', '.p7b', '.p7c', '.p12', '.pfx',
                '.key', '.pub', '.sig', '.csr', '.jks', '.keystore',

                # Archive formats (might contain licensing)
                '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
                '.cab', '.msi', '.pkg', '.deb', '.rpm',

                # Image formats (sometimes contain embedded licensing)
                '.bmp', '.jpg', '.jpeg', '.png', '.gif', '.tiff', '.ico',

                # Script and code files
                '.bat', '.cmd', '.ps1', '.vbs', '.js', '.py', '.pl', '.sh',
                '.reg', '.inf', '.cat', '.manifest',

                # Data files
                '.csv', '.tsv', '.log', '.out', '.dump', '.trace',

                # Licensing-specific extensions
                '.lic', '.license', '.key', '.dat', '.bin', '.token',
                '.permit', '.grant', '.auth', '.unlock', '.crack',

                # Hidden or no extension
                '', '.', '.hidden', '.sys', '.tmp'
            ]

            # Search for licensing-related files with advanced detection
            for root, dirs, files in os.walk(folder_path):
                # Limit depth if not including subdirs
                if not self.include_subdirs_checkbox.isChecked():
                    if root != folder_path:
                        continue

                for file in files:
                    file_path = os.path.join(root, file)
                    file_lower = file.lower()
                    file_stem = os.path.splitext(file_lower)[0]
                    file_ext = os.path.splitext(file_lower)[1]

                    # Advanced pattern matching with scoring
                    max_priority = 0
                    best_file_type = "Other"
                    matched_patterns = []

                    # Check filename patterns (including stem and full name)
                    for pattern, pattern_priority in licensing_patterns.items():
                        if (pattern in file_lower or
                            pattern in file_stem or
                            file_lower.startswith(pattern) or
                            file_lower.endswith(pattern)):

                            matched_patterns.append((pattern, pattern_priority))
                            if pattern_priority > max_priority:
                                max_priority = pattern_priority

                                # Categorize based on pattern type
                                if pattern in ['license', 'licence', 'eula', 'terms', 'agreement']:
                                    best_file_type = "License"
                                elif pattern in ['activation', 'serial', 'key', 'keyfile', 'keystore', 'auth']:
                                    best_file_type = "Activation"
                                elif pattern in ['crack', 'patch', 'keygen', 'unlocker']:
                                    best_file_type = "Bypass"
                                elif pattern in ['dongle', 'hasp', 'sentinel', 'flexlm', 'safenet', 'wibu']:
                                    best_file_type = "Protection"
                                elif pattern in ['cert', 'crt', 'pem', 'sig', 'token']:
                                    best_file_type = "Certificate"
                                elif pattern in ['server', 'daemon', 'service', 'manager']:
                                    best_file_type = "Service"
                                elif pattern in ['backup', 'recovery', 'emergency']:
                                    best_file_type = "Backup"
                                elif pattern in ['encrypted', 'protected', 'secured', 'locked']:
                                    best_file_type = "Protected"
                                elif pattern in ['fingerprint', 'hwid', 'hardware', 'tpm']:
                                    best_file_type = "Hardware"
                                elif pattern in ['expire', 'timeout', 'timer', 'deadline']:
                                    best_file_type = "Temporal"
                                elif pattern in ['network', 'floating', 'concurrent']:
                                    best_file_type = "Network"
                                else:
                                    best_file_type = "Legal"

                    # Check suspicious file extensions (even without pattern matches)
                    if file_ext in extensions:
                        ext_priority = 0
                        if file_ext in ['.lic', '.license', '.key', '.token']:
                            ext_priority = 8
                        elif file_ext in ['.dll', '.exe', '.sys'] and max_priority == 0:
                            # Only consider executables if no other patterns matched
                            ext_priority = 4
                        elif file_ext in ['.dat', '.bin', '.db']:
                            ext_priority = 5
                        elif file_ext in ['.txt', '.rtf', '.pdf', '.doc']:
                            ext_priority = 3
                        elif file_ext in ['.cert', '.crt', '.pem', '.sig']:
                            ext_priority = 7
                        else:
                            ext_priority = 2

                        if ext_priority > max_priority:
                            max_priority = ext_priority
                            if best_file_type == "Other":
                                best_file_type = "Document"

                    # Special checks for hidden or suspicious files
                    if file.startswith('.') and max_priority == 0:
                        max_priority = 4
                        best_file_type = "Hidden"

                    # Check for files with no extension (often suspicious)
                    if not file_ext and len(file) > 0 and max_priority == 0:
                        # Common names that might be licensing related
                        no_ext_patterns = ['readme', 'license', 'eula', 'terms', 'key', 'serial']
                        for pattern in no_ext_patterns:
                            if pattern in file_lower:
                                max_priority = 6
                                best_file_type = "NoExt"
                                break

                    # Boost priority for files in certain directories
                    dir_boost = 0
                    root_lower = root.lower()
                    if any(term in root_lower for term in ['license', 'legal', 'key', 'crack', 'patch']):
                        dir_boost = 2
                    elif any(term in root_lower for term in ['bin', 'data', 'config']):
                        dir_boost = 1

                    final_priority = min(max_priority + dir_boost, 10)

                    # Only add files with some suspicion of being licensing-related
                    if final_priority > 2:
                        # Add matched patterns to file info for detailed analysis
                        pattern_info = ", ".join([f"{p}({pr})" for p, pr in matched_patterns[:3]])
                        if pattern_info:
                            best_file_type += f" [{pattern_info}]"

                        self.add_licensing_file_to_tree(file_path, best_file_type, final_priority)

            # Sort by priority
            self.licensing_files.sort(key=lambda x: x['priority'], reverse=True)

        except Exception as e:
            logger.error(f"Error analyzing installation folder {folder_path}: {e}")

    def add_licensing_file_to_tree(self, file_path, file_type, priority):
        """Add a licensing file to the tree widget."""
        try:
            file_info = {
                'path': file_path,
                'type': file_type,
                'priority': priority,
                'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
            }

            self.licensing_files.append(file_info)

            # Create tree item
            item = QTreeWidgetItem()
            item.setText(0, os.path.basename(file_path))
            item.setText(1, file_type)
            item.setText(2, self.format_file_size(file_info['size']))
            item.setText(3, str(priority))
            item.setData(0, Qt.UserRole, file_info)

            # Set priority-based styling
            if priority >= 9:
                if HAS_PYQT:
                    item.setBackground(0, Qt.red)
            elif priority >= 7:
                if HAS_PYQT:
                    item.setBackground(0, Qt.yellow)
            elif priority >= 5:
                if HAS_PYQT:
                    item.setBackground(0, Qt.cyan)

            self.licensing_tree.addTopLevelItem(item)

        except Exception as e:
            logger.error(f"Error adding licensing file {file_path}: {e}")

    def format_file_size(self, size):
        """Format file size in human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def filter_programs(self, text):
        """Filter programs table based on search text."""
        for row in range(self.programs_table.rowCount()):
            should_show = True

            if text:
                # Check all columns for match
                match_found = False
                for col in range(self.programs_table.columnCount()):
                    item = self.programs_table.item(row, col)
                    if item and text.lower() in item.text().lower():
                        match_found = True
                        break

                should_show = match_found

            self.programs_table.setRowHidden(row, not should_show)

    def open_licensing_file(self, item):
        """Open a licensing file for viewing."""
        file_info = item.data(0, Qt.UserRole)
        if file_info:
            file_path = file_info['path']
            try:
                # Use system default program to open file
                if sys.platform.startswith('win'):
                    if hasattr(os, 'startfile'):
                        os.startfile(file_path)
                elif sys.platform.startswith('linux'):
                    subprocess.run(['xdg-open', file_path])
                elif sys.platform.startswith('darwin'):
                    subprocess.run(['open', file_path])
            except Exception as e:
                logger.error(f"Error opening file {file_path}: {e}")
                QMessageBox.warning(self, "Error", f"Could not open file: {str(e)}")

    def analyze_selected_program(self):
        """Analyze the selected program."""
        if not self.selected_program:
            return

        # Return the selected program and analysis data
        self.accept()

    def get_selected_program_data(self):
        """Get data for the selected program."""
        return {
            'program_info': self.selected_program,
            'installation_folder': self.installation_folder,
            'licensing_files': self.licensing_files,
            'auto_analyze': self.auto_analyze_checkbox.isChecked()
        }


# Convenience function for creating and showing the dialog
def show_program_selector(parent=None):
    """Show the program selector dialog and return selected data."""
    dialog = ProgramSelectorDialog(parent)
    if dialog.exec_() == QDialog.Accepted:
        return dialog.get_selected_program_data()
    return None

# Backward compatibility alias
show_smart_program_selector = show_program_selector
