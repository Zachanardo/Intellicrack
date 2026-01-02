"""Protocol Tool Module.

This module provides a graphical user interface for protocol analysis and manipulation
within the Intellicrack application. It includes classes for managing protocol tool windows,
handling user interactions, and integrating with the main application framework.

Main Classes:
    ProtocolToolSignals: Defines PyQt signals for communication between the protocol tool and the main application.
    ProtocolToolWindow: Singleton QWidget subclass that implements the protocol tool interface.

Main Functions:
    launch_protocol_tool: Launches the protocol tool window.
    update_protocol_tool_description: Updates the description displayed in the protocol tool window.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import logging

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import QApplication, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSizePolicy, QTextEdit, QVBoxLayout, QWidget

# Import protocol parsers for real functionality
from intellicrack.core.network import protocols
from intellicrack.core.network.protocol_fingerprinter import ProtocolFingerprinter
from intellicrack.core.network.traffic_interception_engine import TrafficInterceptionEngine


PYQT6_AVAILABLE = True

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

    def __new__(cls, *args: object, **kwargs: object) -> "ProtocolToolWindow":
        """Ensure a singleton instance of the ProtocolToolWindow.

        Args:
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            The singleton instance of the ProtocolToolWindow.

        """
        if not cls._instance:
            cls._instance = super().__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self, app_instance: object | None = None) -> None:
        """Initialize the Protocol Tool window with a sophisticated UI.

        Args:
            app_instance: Reference to the main application instance for communication.

        """
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

    def _setup_ui(self) -> None:
        """Set up the layout and widgets for the Protocol Tool.

        Initializes all UI components including labels, text editors, line edits, and buttons,
        and arranges them in appropriate layouts for the protocol tool window.

        """
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
        self.output_text_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        main_layout.addWidget(self.output_text_edit)

        # Input Line
        input_layout = QHBoxLayout()
        self.input_line_edit = QLineEdit()
        # Show real command syntax hints for available protocol operations
        self.input_line_edit.setToolTip("Commands: analyze <protocol> <file>, parse <hex_data>, send <protocol> <command>")
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

    def _connect_signals(self) -> None:
        """Connect internal UI signals to their slots.

        Establishes connections between protocol tool signals and their corresponding slot methods
        for updating the UI when protocol analysis state changes.

        """
        # Example: Connect a custom signal to update description
        ProtocolToolWindow.signals.description_updated.connect(self.update_description)

    def _on_input_submitted(self) -> None:
        """Handle user input from the QLineEdit with real protocol processing.

        Processes protocol commands entered by the user and executes appropriate actions
        such as analyzing protocols, parsing raw data, or sending protocol commands.

        Returns:
            None.

        """
        if command := self.input_line_edit.text().strip():
            self.output_text_edit.append(f"> {command}")
            self.input_line_edit.clear()
            logger.info("Protocol command submitted: %s", command)

            # Parse command and execute real protocol operations
            parts = command.split()
            if not parts:
                self.output_text_edit.append("[ERROR] Empty command")
                return

            cmd = parts[0].lower()

            if cmd == "analyze" and len(parts) >= 3:
                # Real protocol analysis: analyze <protocol> <hex_data>
                protocol_name = parts[1].lower()
                hex_data = "".join(parts[2:])
                self._execute_protocol_analysis(protocol_name, hex_data)

            elif cmd == "parse" and len(parts) >= 2:
                # Parse raw hex data to identify protocol
                hex_data = "".join(parts[1:])
                self._parse_raw_data(hex_data)

            elif cmd == "send" and len(parts) >= 3:
                # Send protocol command
                protocol_name = parts[1].lower()
                command_data = " ".join(parts[2:])
                self._send_protocol_command(protocol_name, command_data)

            elif cmd == "list":
                # List available protocol parsers
                self._list_available_protocols()

            else:
                self.output_text_edit.append(f"[ERROR] Unknown command: {cmd}")
                self.output_text_edit.append("[HELP] Available commands:")
                self.output_text_edit.append("  analyze <protocol> <hex_data> - Analyze protocol data")
                self.output_text_edit.append("  parse <hex_data> - Auto-detect and parse protocol")
                self.output_text_edit.append("  send <protocol> <command> - Send protocol command")
                self.output_text_edit.append("  list - List available protocols")
        else:
            self.output_text_edit.append("[WARNING] Input cannot be empty.")

    def _on_start_analysis(self) -> None:
        """Handle the 'Start Analysis' button click with real protocol analysis.

        Executes comprehensive protocol fingerprinting and traffic interception to detect
        active network protocols and license validation attempts.

        """
        self.output_text_edit.append("[INFO] Starting comprehensive protocol analysis...")
        self.description_label.setText("Performing deep analysis...")
        logger.info("Comprehensive protocol analysis initiated.")

        # Execute real protocol fingerprinting
        try:
            fingerprinter = ProtocolFingerprinter()
            interceptor = TrafficInterceptionEngine()

            # Analyze network traffic for protocol patterns
            self.output_text_edit.append("[SCAN] Detecting active network protocols...")
            detected_protocols = fingerprinter.detect_protocols()

            for protocol in detected_protocols:
                self.output_text_edit.append(f"[FOUND] {protocol['name']} - Port {protocol['port']}")
                self.output_text_edit.append(f"  Confidence: {protocol['confidence']}%")
                self.output_text_edit.append(f"  Pattern: {protocol['pattern'][:50]}...")

            if license_traffic := interceptor.capture_license_traffic():
                self.output_text_edit.append(f"[LICENSE] Detected {len(license_traffic)} license validation attempts")
                for traffic in license_traffic[:5]:  # Show first 5
                    self.output_text_edit.append(f"  {traffic['protocol']} -> {traffic['server']}")

            self.output_text_edit.append(f"[INFO] Analysis complete. Found {len(detected_protocols)} protocol patterns.")
            self.description_label.setText(f"Analysis complete - {len(detected_protocols)} protocols detected")

        except Exception as e:
            self.output_text_edit.append(f"[ERROR] Analysis failed: {e!s}")
            logger.exception("Protocol analysis error: %s", e)
            self.description_label.setText("Analysis failed")

    def _on_clear_log(self) -> None:
        """Clear the output log area.

        Clears all displayed text from the output log and displays a confirmation message.

        """
        self.output_text_edit.clear()
        self.output_text_edit.append("Protocol analysis output cleared.")
        logger.info("Protocol tool log cleared.")

    def update_description(self, description: str) -> None:
        """Update the description label in the Protocol Tool window.

        Args:
            description: The new description text to display.

        """
        self.description_label.setText(description)
        logger.info("Protocol tool description updated to: %s", description)
        ProtocolToolWindow.signals.description_updated.emit(description)
        if self.app_instance:
            update_signal = getattr(self.app_instance, "update_output", None)
            if update_signal is not None and hasattr(update_signal, "emit"):
                update_signal.emit(f"Protocol tool description updated: {description}")

    def _execute_protocol_analysis(self, protocol_name: str, hex_data: str) -> None:
        """Execute real protocol analysis on hex data.

        Args:
            protocol_name: The name of the protocol to analyze.
            hex_data: The hexadecimal data to analyze.

        Returns:
            None.

        """
        try:
            # Clean hex data
            hex_data = hex_data.replace(" ", "").replace("0x", "")
            if len(hex_data) % 2 != 0:
                self.output_text_edit.append("[ERROR] Invalid hex data length")
                return

            data_bytes = bytes.fromhex(hex_data)
            self.output_text_edit.append(f"[ANALYZE] Protocol: {protocol_name}, Data: {len(data_bytes)} bytes")

            # Map protocol names to parser modules
            parser_map = {
                "flexlm": "flexlm_parser",
                "hasp": "hasp_parser",
                "codemeter": "codemeter_parser",
                "adobe": "adobe_parser",
                "autodesk": "autodesk_parser",
            }

            if protocol_name in parser_map:
                if parser_module := protocols.get_parser(parser_map[protocol_name]):
                    # Use the specific parser
                    if hasattr(parser_module, f"{protocol_name.upper()}ProtocolParser"):
                        parser_class = getattr(parser_module, f"{protocol_name.upper()}ProtocolParser")
                    elif hasattr(parser_module, f"{protocol_name.capitalize()}ProtocolParser"):
                        parser_class = getattr(parser_module, f"{protocol_name.capitalize()}ProtocolParser")
                    else:
                        parser_class = next(
                            (
                                getattr(parser_module, attr_name)
                                for attr_name in dir(parser_module)
                                if "Parser" in attr_name and "Protocol" in attr_name
                            ),
                            None,
                        )
                    if parser_class:
                        parser = parser_class()
                        if result := parser.parse_request(data_bytes):
                            self.output_text_edit.append(f"[PARSED] Command: {result.command}")
                            self.output_text_edit.append(f"[PARSED] Version: {result.version}")
                            if hasattr(result, "feature"):
                                self.output_text_edit.append(f"[PARSED] Feature: {result.feature}")
                            if hasattr(result, "additional_data"):
                                for key, value in result.additional_data.items():
                                    self.output_text_edit.append(f"[PARSED] {key}: {value}")
                        else:
                            self.output_text_edit.append("[ERROR] Failed to parse protocol data")
                    else:
                        self.output_text_edit.append(f"[ERROR] Parser class not found for {protocol_name}")
                else:
                    self.output_text_edit.append(f"[ERROR] Parser module not available for {protocol_name}")
            else:
                self.output_text_edit.append(f"[ERROR] Unknown protocol: {protocol_name}")
                self.output_text_edit.append(f"[INFO] Available: {', '.join(parser_map.keys())}")

        except ValueError as e:
            self.output_text_edit.append(f"[ERROR] Invalid hex data: {e}")
        except Exception as e:
            self.output_text_edit.append(f"[ERROR] Analysis failed: {e}")
            logger.exception("Protocol analysis error: %s", e)

    def _parse_raw_data(self, hex_data: str) -> None:
        """Auto-detect and parse protocol from raw hex data.

        Args:
            hex_data: The hexadecimal data to parse.

        Returns:
            None.

        """
        try:
            # Clean hex data
            hex_data = hex_data.replace(" ", "").replace("0x", "")
            data_bytes = bytes.fromhex(hex_data)

            self.output_text_edit.append(f"[PARSE] Analyzing {len(data_bytes)} bytes...")

            # Try protocol fingerprinting
            fingerprinter = ProtocolFingerprinter()
            if detected_protocol := fingerprinter.identify_protocol(data_bytes):
                self.output_text_edit.append(f"[DETECTED] Protocol: {detected_protocol['name']}")
                self.output_text_edit.append(f"[CONFIDENCE] {detected_protocol['confidence']}%")

                # Parse with detected protocol
                self._execute_protocol_analysis(detected_protocol["name"].lower(), hex_data)
            else:
                # Try each parser until one succeeds
                self.output_text_edit.append("[SCAN] Trying known protocol parsers...")
                parsers_tried = []

                for parser_name in protocols.get_available_parsers():
                    parsers_tried.append(parser_name)
                    parser_module = protocols.get_parser(parser_name)

                    # Try to parse with this module
                    for attr_name in dir(parser_module):
                        if "Parser" in attr_name and "Protocol" in attr_name:
                            parser_class = getattr(parser_module, attr_name)
                            try:
                                parser = parser_class()
                                if result := parser.parse_request(data_bytes):
                                    self.output_text_edit.append(f"[SUCCESS] Parsed as {parser_name}")
                                    self.output_text_edit.append(f"[COMMAND] {result.command}")
                                    return
                            except (AttributeError, KeyError):
                                continue

                self.output_text_edit.append("[FAILED] No parser recognized the data")
                self.output_text_edit.append(f"[TRIED] {', '.join(parsers_tried)}")

        except ValueError as e:
            self.output_text_edit.append(f"[ERROR] Invalid hex data: {e}")
        except Exception as e:
            self.output_text_edit.append(f"[ERROR] Parse failed: {e}")
            logger.exception("Raw data parse error: %s", e)

    def _send_protocol_command(self, protocol_name: str, command_data: str) -> None:
        """Send a protocol command to a license server.

        Args:
            protocol_name: The name of the protocol to send.
            command_data: The command data including host and port information.

        """
        try:
            self.output_text_edit.append(f"[SEND] Protocol: {protocol_name}, Command: {command_data}")

            # Use traffic interception engine to send command
            interceptor = TrafficInterceptionEngine()

            # Parse command parameters
            if ":" in command_data:
                host, port_str = command_data.split(":", 1)
                port = int(port_str) if port_str.isdigit() else 27000  # Default FlexLM port
            else:
                host = command_data
                port = 27000

            self.output_text_edit.append(f"[CONNECT] {host}:{port}")

            if response := interceptor.send_protocol_command(protocol_name, host, port, b"STATUS"):
                self.output_text_edit.append(f"[RESPONSE] {len(response)} bytes received")
                # Display first 100 chars of response
                response_str = response[:100].hex()
                self.output_text_edit.append(f"[DATA] {response_str}...")
            else:
                self.output_text_edit.append("[ERROR] No response received")

        except Exception as e:
            self.output_text_edit.append(f"[ERROR] Send failed: {e}")
            logger.exception("Protocol send error: %s", e)

    def _list_available_protocols(self) -> None:
        """List all available protocol parsers.

        Displays all loaded protocol parser modules and their descriptions in the output log.

        """
        self.output_text_edit.append("[PROTOCOLS] Available protocol parsers:")

        available_parsers = protocols.get_available_parsers()
        if available_parsers:
            for parser_name in available_parsers:
                parser_module = protocols.get_parser(parser_name)
                # Get parser description
                desc = parser_module.__doc__.split("\n")[0] if parser_module.__doc__ else "No description"
                self.output_text_edit.append(f"   {parser_name}: {desc}")
        else:
            self.output_text_edit.append("  No protocol parsers loaded")

        self.output_text_edit.append(f"[TOTAL] {len(available_parsers)} parsers available")

    def closeEvent(self, event: QCloseEvent | None) -> None:
        """Handle the close event for the window.

        Args:
            event: The close event that triggered this handler.

        """
        logger.info("Protocol Tool window closing.")
        ProtocolToolWindow.signals.tool_closed.emit("Protocol Tool closed.")
        # Clean up resources if necessary
        super().closeEvent(event)
        ProtocolToolWindow._instance = None  # Allow new instance to be created next time


def launch_protocol_tool(app_instance: object | None = None) -> ProtocolToolWindow:
    """Launch the Protocol Tool window.

    Args:
        app_instance: Reference to the main application instance for communication.

    Returns:
        The instance of the ProtocolToolWindow.

    """
    QApplication.instance() or QApplication([])  # Create QApplication if it doesn't exist (for standalone testing)

    window = ProtocolToolWindow(app_instance)
    window.show()
    logger.info("Protocol tool window launched.")
    return window


def update_protocol_tool_description(app_instance: object | None = None, description: str = "") -> None:
    """Update the description in the Protocol Tool window.

    Args:
        app_instance: Reference to the main application instance for communication.
        description: The new description text to display in the protocol tool window.

    """
    # Ensure the window is instantiated before trying to update it
    window = ProtocolToolWindow()
    window.update_description(description)
