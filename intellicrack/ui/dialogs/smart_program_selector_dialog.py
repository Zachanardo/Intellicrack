"""Smart program selector dialog for Intellicrack UI.

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
"""

import os
import sys

from intellicrack.handlers.pyqt6_handler import (
    HAS_PYQT as HAS_QT,
    QCloseEvent,
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QTextEdit,
    QThread,
    QTimer,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)
from intellicrack.utils.logger import logger
from intellicrack.utils.type_safety import validate_type

from ...utils.system.file_resolution import FileResolver
from ...utils.system.program_discovery import ProgramDiscoveryEngine, ProgramInfo


"""Smart program selector dialog for choosing target applications."""

"""
Smart Program Selector Dialog

Provides an intelligent interface for selecting programs for analysis
via desktop shortcuts, file resolution, and program discovery.
"""

program_discovery_engine: ProgramDiscoveryEngine | None = None
file_resolver: FileResolver | None = None
ProgramInfo_actual: type[ProgramInfo] | None = None
HAS_PROGRAM_DISCOVERY: bool = False

try:
    from ...utils.system.file_resolution import file_resolver as _file_resolver
    from ...utils.system.program_discovery import (
        ProgramInfo as _ProgramInfo,
        program_discovery_engine as _program_discovery_engine,
    )

    program_discovery_engine = _program_discovery_engine
    file_resolver = _file_resolver
    ProgramInfo_actual = _ProgramInfo
    HAS_PROGRAM_DISCOVERY = True
except ImportError as e:
    logger.error("Import error in smart_program_selector_dialog: %s", e)


class ProgramDiscoveryWorker(QThread):
    """Worker thread for program discovery operations."""

    programs_found = pyqtSignal(list)
    progress_updated = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, discovery_paths: list[str]) -> None:
        """Initialize the program discovery worker with specified paths.

        Args:
            discovery_paths: Paths to scan for programs.
        """
        super().__init__()
        self.discovery_paths: list[str] = discovery_paths
        self.running: bool = True
        self.logger = logger

    def run(self) -> None:
        """Run program discovery in background thread.

        Scans configured discovery paths for executable programs and
        emits signals with progress updates and discovered programs.
        """
        if not HAS_PROGRAM_DISCOVERY:
            self.progress_updated.emit("Program discovery not available")
            self.finished.emit()
            return

        all_programs: list[object] = []

        for path in self.discovery_paths:
            if not self.running:
                break

            self.progress_updated.emit(f"Scanning {path}...")

            try:
                if program_discovery_engine is not None:
                    programs = validate_type(program_discovery_engine.discover_programs_from_path(path), list)
                    all_programs.extend(programs)
                    self.progress_updated.emit(f"Found {len(programs)} programs in {path}")
            except Exception as e:
                self.logger.exception("Exception in smart_program_selector_dialog: %s", e)
                self.progress_updated.emit(f"Error scanning {path}: {e!s}")

        self.programs_found.emit(all_programs)
        self.finished.emit()

    def stop(self) -> None:
        """Stop the discovery process.

        Sets the running flag to false to cleanly stop the worker thread.
        """
        self.running = False


class SmartProgramSelectorDialog(QDialog):
    """Smart program selector dialog with intelligent discovery."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the smart program selector dialog with UI components and discovery functionality.

        Args:
            parent: Parent widget for this dialog.
        """
        super().__init__(parent)
        self.setWindowTitle("Smart Program Selector")
        self.setModal(True)
        self.resize(800, 600)

        self.selected_program: ProgramInfo | None = None
        self.discovery_worker: ProgramDiscoveryWorker | None = None
        self.discovery_timer: QTimer = QTimer()
        self.programs_list: QListWidget | None = None
        self.progress_text: QTextEdit | None = None
        self.scan_button: QPushButton | None = None
        self.analyze_button: QPushButton | None = None
        self.cancel_button: QPushButton | None = None

        if HAS_QT:
            self.setup_ui()
            self.connect_signals()

    def setup_ui(self) -> None:
        """Set up the user interface.

        Creates and configures all UI components including labels, list widget,
        progress text display, and action buttons.

        Returns:
            None
        """
        layout: QVBoxLayout = QVBoxLayout(self)

        title_label: QLabel = QLabel("Select a Program for Analysis")
        layout.addWidget(title_label)

        self.programs_list = QListWidget()
        layout.addWidget(self.programs_list)

        self.progress_text = QTextEdit()
        self.progress_text.setMaximumHeight(100)
        layout.addWidget(self.progress_text)

        button_layout: QHBoxLayout = QHBoxLayout()

        self.scan_button = QPushButton("Scan for Programs")
        self.analyze_button = QPushButton("Analyze Selected")
        self.cancel_button = QPushButton("Cancel")

        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.analyze_button)
        button_layout.addWidget(self.cancel_button)

        layout.addLayout(button_layout)

    def connect_signals(self) -> None:
        """Connect UI signals.

        Establishes signal connections between UI buttons and their corresponding
        handler methods.

        Returns:
            None
        """
        if HAS_QT and self.scan_button is not None and self.analyze_button is not None and self.cancel_button is not None:
            self.scan_button.clicked.connect(self.start_program_discovery)
            self.analyze_button.clicked.connect(self.analyze_selected_program)
            self.cancel_button.clicked.connect(self.reject)

    def start_program_discovery(self) -> None:
        """Start program discovery process.

        Initiates background program discovery by creating and starting a
        ProgramDiscoveryWorker thread with configured discovery paths.
        Disables the scan button during discovery.

        Returns:
            None
        """
        if not HAS_PROGRAM_DISCOVERY:
            if self.progress_text is not None:
                self.progress_text.append("Program discovery not available")
            return

        discovery_paths: list[str] = self.get_discovery_paths()

        self.discovery_worker = ProgramDiscoveryWorker(discovery_paths)
        self.discovery_worker.programs_found.connect(self.handle_programs_found)
        self.discovery_worker.progress_updated.connect(self.update_progress)
        self.discovery_worker.finished.connect(self.discovery_finished)

        self.discovery_worker.start()
        if self.scan_button is not None:
            self.scan_button.setEnabled(False)

    def get_discovery_paths(self) -> list[str]:
        """Get paths to scan for programs.

        Returns:
            List of existing directory paths to scan for programs on the
            current platform (Windows, Linux, or macOS).
        """
        paths: list[str] = []

        if sys.platform.startswith("win"):
            if user_profile := os.environ.get("USERPROFILE", ""):
                paths.extend(
                    [
                        os.path.join(user_profile, "Desktop"),
                        os.path.join(
                            user_profile,
                            "AppData",
                            "Roaming",
                            "Microsoft",
                            "Windows",
                            "Start Menu",
                            "Programs",
                        ),
                    ],
                )
            paths.extend(
                [
                    r"C:\Users\Public\Desktop",
                    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs",
                ],
            )
        elif sys.platform.startswith("linux"):
            if home := os.environ.get("HOME", ""):
                paths.extend(
                    [
                        os.path.join(home, "Desktop"),
                        os.path.join(home, ".local", "share", "applications"),
                    ],
                )
            paths.extend(
                [
                    "/usr/share/applications",
                    "/usr/local/share/applications",
                ],
            )
        elif sys.platform.startswith("darwin"):
            if home := os.environ.get("HOME", ""):
                paths.extend(
                    [
                        os.path.join(home, "Desktop"),
                        os.path.join(home, "Applications"),
                    ],
                )
            paths.extend(
                [
                    "/Applications",
                    "/System/Applications",
                ],
            )

        # Filter to existing paths
        return [path for path in paths if os.path.exists(path)]

    def handle_programs_found(self, programs: list[object]) -> None:
        """Handle discovered programs.

        Populates the programs list widget with discovered ProgramInfo objects,
        displaying their names and discovery methods.

        Args:
            programs: List of discovered program objects from discovery worker.

        Returns:
            None
        """
        if self.programs_list is None:
            return

        self.programs_list.clear()

        for program in programs:
            if ProgramInfo_actual is not None and isinstance(program, ProgramInfo_actual):
                item: QListWidgetItem = QListWidgetItem(f"{program.display_name} ({program.discovery_method})")
                item.setData(32, program)
                self.programs_list.addItem(item)

    def update_progress(self, message: str) -> None:
        """Update progress display.

        Appends a message to the progress text area to provide feedback during
        program discovery operations.

        Args:
            message: Progress message to display.

        Returns:
            None
        """
        if self.progress_text is not None:
            self.progress_text.append(message)

    def discovery_finished(self) -> None:
        """Handle discovery completion.

        Re-enables the scan button and appends a completion message to the
        progress text area when program discovery finishes.

        Returns:
            None
        """
        if self.scan_button is not None:
            self.scan_button.setEnabled(True)
        if self.progress_text is not None:
            self.progress_text.append("Discovery completed.")

    def analyze_selected_program(self) -> None:
        """Analyze the selected program.

        Retrieves the currently selected program from the list widget and
        accepts the dialog if a selection is present.

        Returns:
            None
        """
        if self.programs_list is not None:
            current_item = self.programs_list.currentItem()
            if current_item is not None:
                self.selected_program = current_item.data(32)
                self.accept()

    def get_selected_program(self) -> ProgramInfo | None:
        """Get the selected program.

        Returns:
            The selected ProgramInfo object, or None if no program was selected.
        """
        return self.selected_program

    def closeEvent(self, event: QCloseEvent | None) -> None:  # noqa: N802
        """Handle dialog close with proper thread cleanup.

        Ensures any running discovery worker is properly terminated before
        closing the dialog to prevent resource leaks.

        Args:
            event: Close event from Qt framework.

        Returns:
            None
        """
        if self.discovery_worker is not None and self.discovery_worker.isRunning():
            self.discovery_worker.quit()
            if not self.discovery_worker.wait(2000):
                self.discovery_worker.terminate()
                self.discovery_worker.wait()
            self.discovery_worker = None
        super().closeEvent(event)


def show_smart_program_selector(parent: QWidget | None = None) -> object | None:
    """Show the smart program selector dialog.

    Creates and displays the smart program selector dialog, returning the
    selected program if accepted by the user.

    Args:
        parent: Parent widget for the dialog.

    Returns:
        The selected ProgramInfo object if accepted, or None if canceled.
    """
    if not HAS_QT:
        return None

    dialog: SmartProgramSelectorDialog = SmartProgramSelectorDialog(parent)
    if dialog.exec() == 1:
        return dialog.get_selected_program()
    return None
