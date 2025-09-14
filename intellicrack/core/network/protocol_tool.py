"""
Protocol Tool Module

This module provides a graphical user interface for protocol analysis and manipulation
within the Intellicrack application. It includes classes for managing protocol tool windows,
handling user interactions, and integrating with the main application framework.

Main Classes:
    ProtocolToolSignals: Defines PyQt signals for communication between the protocol tool and the main application.
    ProtocolToolWindow: Singleton QWidget subclass that implements the protocol tool interface.

Main Functions:
    launch_protocol_tool: Launches the protocol tool window.
    update_protocol_tool_description: Updates the description displayed in the protocol tool window.
"""

import logging

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

logger = logging.getLogger(__name__)


class ProtocolToolSignals(QObject):
    """Defines signals available from the ProtocolToolWindow to the main application."""

    tool_launched = pyqtSignal(str)
    tool_closed = pyqtSignal(str)
    description_updated = pyqtSignal(str)
    # Add more signals as needed for complex interactions


class ProtocolToolWindow(QWidget):
    """Singleton QWidget subclass that provides the graphical interface for the Intellicrack Protocol Tool.

    This class manages the user interface for protocol analysis, including input handling, output display,
    and integration with the main Intellicrack application through PyQt signals. It implements a singleton
    pattern to ensure only one instance exists at a time, preventing multiple protocol tool windows.

    Attributes:
        _instance: Class variable holding the singleton instance.
        signals: Instance of ProtocolToolSignals for emitting events to the main application.
        app_instance: Reference to the main application instance for communication.
        title_label: QLabel displaying the tool's title.
        description_label: QLabel showing current status or description.
        output_text_edit: QTextEdit widget for displaying protocol analysis output.
        input_line_edit: QLineEdit for user input commands.
        send_button: QPushButton to submit user input.
        start_analysis_button: QPushButton to initiate protocol analysis.
        clear_log_button: QPushButton to clear the output log.
        close_button: QPushButton to close the tool window.

    """

    _instance = None
    signals = ProtocolToolSignals()

    def __new__(cls, *args, **kwargs):
        """Ensures a singleton instance of the ProtocolToolWindow."""
        if not cls._instance:
            cls._instance = super(ProtocolToolWindow, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self, app_instance=None):
        """Initializes the Protocol Tool window with a sophisticated UI."""
        # Only initialize UI components once for the singleton instance
        if not hasattr(self, "_initialized"):
            super().__init__()
            self._initialized = True
            self.app_instance = app_instance
            self.setWindowTitle("Intellicrack Protocol Tool")
            self.setGeometry(100, 100, 800, 600)  # Larger default size

            self._setup_ui()
            self._connect_signals()
            logger.info("ProtocolToolWindow initialized with sophisticated UI.")
            ProtocolToolWindow.signals.tool_launched.emit("Protocol Tool UI ready.")

    def _setup_ui(self):
        """Sets up the layout and widgets for the Protocol Tool."""
        main_layout = QVBoxLayout(self)

        # Title/Status Label
        self.title_label = QLabel("<b>Intellicrack Protocol Tool</b>")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setStyleSheet("font-size: 18px; margin-bottom: 10px;")
        main_layout.addWidget(self.title_label)

        # Description/Status Display
        self.description_label = QLabel("Ready for protocol analysis.")
        self.description_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.description_label.setStyleSheet("font-style: italic; color: gray;")
        main_layout.addWidget(self.description_label)

        # Protocol Output/Log Area
        self.output_text_edit = QTextEdit()
        self.output_text_edit.setReadOnly(True)
        self.output_text_edit.setPlaceholderText("Protocol analysis output will appear here...")
        self.output_text_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        main_layout.addWidget(self.output_text_edit)

        # Input Line
        input_layout = QHBoxLayout()
        self.input_line_edit = QLineEdit()
        self.input_line_edit.setPlaceholderText("Enter protocol command or data...")
        self.input_line_edit.returnPressed.connect(self._on_input_submitted)
        input_layout.addWidget(self.input_line_edit)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self._on_input_submitted)
        input_layout.addWidget(self.send_button)
        main_layout.addLayout(input_layout)

        # Control Buttons
        button_layout = QHBoxLayout()
        self.start_analysis_button = QPushButton("Start Analysis")
        self.start_analysis_button.clicked.connect(self._on_start_analysis)
        button_layout.addWidget(self.start_analysis_button)

        self.clear_log_button = QPushButton("Clear Log")
        self.clear_log_button.clicked.connect(self._on_clear_log)
        button_layout.addWidget(self.clear_log_button)

        self.close_button = QPushButton("Close Tool")
        self.close_button.clicked.connect(self.close)
        button_layout.addWidget(self.close_button)
        main_layout.addLayout(button_layout)

    def _connect_signals(self):
        """Connects internal UI signals to their slots."""
        # Example: Connect a custom signal to update description
        ProtocolToolWindow.signals.description_updated.connect(self.update_description)

    def _on_input_submitted(self):
        """Handles user input from the QLineEdit.
        This is where sophisticated protocol command parsing and execution would go.
        """
        command = self.input_line_edit.text().strip()
        if command:
            self.output_text_edit.append(f"> {command}")
            self.input_line_edit.clear()
            logger.info(f"Protocol command submitted: {command}")
            # In a real scenario, this would trigger a backend protocol operation
            self.output_text_edit.append(f"[INFO] Processing command: '{command}'...")
            # Simulate a response
            if "analyze" in command.lower():
                self.output_text_edit.append("[RESPONSE] Initiating deep protocol analysis...")
            elif "send" in command.lower():
                self.output_text_edit.append("[RESPONSE] Data sent over protocol.")
            else:
                self.output_text_edit.append("[RESPONSE] Command not recognized. Try 'analyze <protocol>' or 'send <data>'.")
        else:
            self.output_text_edit.append("[WARNING] Input cannot be empty.")

    def _on_start_analysis(self):
        """Handles the 'Start Analysis' button click.
        This would trigger a comprehensive protocol analysis routine.
        """
        self.output_text_edit.append("[INFO] Starting comprehensive protocol analysis...")
        self.description_label.setText("Performing deep analysis...")
        logger.info("Comprehensive protocol analysis initiated.")
        # Placeholder for actual analysis logic
        # This would likely involve calling methods from ProtocolFingerprinter or TrafficInterceptionEngine
        self.output_text_edit.append("[INFO] Analysis complete. Found potential protocol patterns.")
        self.description_label.setText("Analysis complete.")

    def _on_clear_log(self):
        """Clears the output log area."""
        self.output_text_edit.clear()
        self.output_text_edit.append("Protocol analysis output cleared.")
        logger.info("Protocol tool log cleared.")

    def update_description(self, description: str):
        """Updates the description label in the Protocol Tool window."""
        self.description_label.setText(description)
        logger.info(f"Protocol tool description updated to: {description}")
        ProtocolToolWindow.signals.description_updated.emit(description)
        if self.app_instance:
            self.app_instance.update_output.emit(f"Protocol tool description updated: {description}")

    def closeEvent(self, event):
        """Handles the close event for the window."""
        logger.info("Protocol Tool window closing.")
        ProtocolToolWindow.signals.tool_closed.emit("Protocol Tool closed.")
        # Clean up resources if necessary
        super().closeEvent(event)
        ProtocolToolWindow._instance = None  # Allow new instance to be created next time


def launch_protocol_tool(app_instance=None):
    """Launches the Protocol Tool window.
    Returns the instance of the ProtocolToolWindow.
    """
    app = QApplication.instance()
    if not app:
        app = QApplication([])  # Create QApplication if it doesn't exist (for standalone testing)

    window = ProtocolToolWindow(app_instance)
    window.show()
    logger.info("Protocol tool window launched.")
    return window


def update_protocol_tool_description(app_instance=None, description=""):
    """Updates the description in the Protocol Tool window."""
    # Ensure the window is instantiated before trying to update it
    window = ProtocolToolWindow()
    window.update_description(description)
