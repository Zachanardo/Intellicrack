"""
This file is part of Intellicrack.
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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
C2 Management Dialog

Advanced UI for managing Command and Control infrastructure,
sessions, and remote operations.
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import Any, Dict

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont
from PyQt6.QtWidgets import (
    QAction,
    QCheckBox,
    QComboBox,
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QVBoxLayout,
    QWidget,
)

from ...core.c2 import C2Server

logger = logging.getLogger(__name__)


class C2ServerThread(QThread):
    """Thread for running C2 server without blocking UI."""

    status_update = pyqtSignal(str)
    session_update = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, server_config):
        super().__init__()
        self.server_config = server_config
        self.server = None
        self.running = False

    def run(self):
        """Run the C2 server thread."""
        try:
            # Create and start C2 server
            self.server = C2Server(self.server_config)

            # Set up event handlers
            self.server.add_event_handler('session_connected', self.on_session_connected)
            self.server.add_event_handler('session_disconnected', self.on_session_disconnected)
            self.server.add_event_handler('beacon_received', self.on_beacon_received)

            # Run server
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            self.running = True
            self.status_update.emit("C2 server starting...")

            loop.run_until_complete(self.server.start())

        except Exception as e:
            self.logger.error("Exception in c2_management_dialog: %s", e)
            self.error.emit(str(e))

    def stop_server(self):
        """Stop the C2 server."""
        self.running = False
        if self.server:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.server.stop())

    def on_session_connected(self, session):
        """Handle new session connection."""
        self.session_update.emit({
            'event': 'connected',
            'session': session.to_dict() if hasattr(session, 'to_dict') else session
        })

    def on_session_disconnected(self, session):
        """Handle session disconnection."""
        self.session_update.emit({
            'event': 'disconnected',
            'session': session.to_dict() if hasattr(session, 'to_dict') else session
        })

    def on_beacon_received(self, data):
        """Handle beacon from session."""
        self.session_update.emit({
            'event': 'beacon',
            'data': data
        })


class C2ManagementDialog(QDialog):
    """
    Comprehensive C2 management interface for controlling
    remote sessions and infrastructure.
    """

    session_selected = pyqtSignal(str)
    command_executed = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger("IntellicrackLogger.C2ManagementDialog")

        self.server_thread = None
        self.active_sessions = {}
        self.selected_session = None

        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_statistics)
        self.update_timer.start(5000)  # Update every 5 seconds

        self.setup_ui()

    @staticmethod
    def finalize_widget_layout(widget, layout):
        """Common widget finalization pattern."""
        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def setup_ui(self):
        """Setup the user interface."""
        self.setWindowTitle("C2 Infrastructure Management")
        self.setMinimumSize(1200, 800)

        layout = QVBoxLayout()

        # Create main tabs
        self.tab_widget = QTabWidget()

        # Server control tab
        self.server_tab = self.create_server_tab()
        self.tab_widget.addTab(self.server_tab, "Server Control")

        # Sessions tab
        self.sessions_tab = self.create_sessions_tab()
        self.tab_widget.addTab(self.sessions_tab, "Active Sessions")

        # Command tab
        self.command_tab = self.create_command_tab()
        self.tab_widget.addTab(self.command_tab, "Command & Control")

        # File manager tab
        self.file_tab = self.create_file_manager_tab()
        self.tab_widget.addTab(self.file_tab, "File Manager")

        # Logs tab
        self.logs_tab = self.create_logs_tab()
        self.tab_widget.addTab(self.logs_tab, "Activity Logs")

        layout.addWidget(self.tab_widget)

        # Status bar
        self.status_label = QLabel("C2 Server: Stopped")
        self.status_label.setStyleSheet("QLabel { padding: 5px; }")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def create_server_tab(self):
        """Create server control tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Server configuration
        config_group = QGroupBox("Server Configuration")
        config_layout = QVBoxLayout()

        # Protocol settings
        protocol_layout = QHBoxLayout()
        protocol_layout.addWidget(QLabel("Protocol:"))

        self.https_check = QCheckBox("HTTPS")
        self.https_check.setChecked(True)
        self.dns_check = QCheckBox("DNS")
        self.tcp_check = QCheckBox("TCP")

        protocol_layout.addWidget(self.https_check)
        protocol_layout.addWidget(self.dns_check)
        protocol_layout.addWidget(self.tcp_check)
        protocol_layout.addStretch()

        config_layout.addLayout(protocol_layout)

        # Server settings
        settings_layout = QHBoxLayout()

        settings_layout.addWidget(QLabel("Listen Address:"))
        self.listen_addr_edit = QLineEdit("0.0.0.0")
        settings_layout.addWidget(self.listen_addr_edit)

        settings_layout.addWidget(QLabel("HTTPS Port:"))
        self.https_port_spin = QSpinBox()
        self.https_port_spin.setRange(1, 65535)
        self.https_port_spin.setValue(443)
        settings_layout.addWidget(self.https_port_spin)

        settings_layout.addWidget(QLabel("DNS Port:"))
        self.dns_port_spin = QSpinBox()
        self.dns_port_spin.setRange(1, 65535)
        self.dns_port_spin.setValue(53)
        settings_layout.addWidget(self.dns_port_spin)

        settings_layout.addWidget(QLabel("TCP Port:"))
        self.tcp_port_spin = QSpinBox()
        self.tcp_port_spin.setRange(1, 65535)
        self.tcp_port_spin.setValue(4444)
        settings_layout.addWidget(self.tcp_port_spin)

        settings_layout.addStretch()
        config_layout.addLayout(settings_layout)

        # Beacon settings
        beacon_layout = QHBoxLayout()
        beacon_layout.addWidget(QLabel("Default Beacon Interval:"))
        self.beacon_interval_spin = QSpinBox()
        self.beacon_interval_spin.setRange(1, 3600)
        self.beacon_interval_spin.setValue(60)
        self.beacon_interval_spin.setSuffix(" seconds")
        beacon_layout.addWidget(self.beacon_interval_spin)

        beacon_layout.addWidget(QLabel("Jitter:"))
        self.jitter_spin = QSpinBox()
        self.jitter_spin.setRange(0, 50)
        self.jitter_spin.setValue(20)
        self.jitter_spin.setSuffix("%")
        beacon_layout.addWidget(self.jitter_spin)

        beacon_layout.addStretch()
        config_layout.addLayout(beacon_layout)

        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

        # Server control buttons
        control_layout = QHBoxLayout()

        self.start_server_btn = QPushButton("Start Server")
        self.start_server_btn.clicked.connect(self.start_server)
        control_layout.addWidget(self.start_server_btn)

        self.stop_server_btn = QPushButton("Stop Server")
        self.stop_server_btn.clicked.connect(self.stop_server)
        self.stop_server_btn.setEnabled(False)
        control_layout.addWidget(self.stop_server_btn)

        control_layout.addStretch()
        layout.addLayout(control_layout)

        # Server statistics
        stats_group = QGroupBox("Server Statistics")
        self.stats_layout = QVBoxLayout()

        self.uptime_label = QLabel("Uptime: N/A")
        self.sessions_count_label = QLabel("Active Sessions: 0")
        self.total_connections_label = QLabel("Total Connections: 0")
        self.data_transferred_label = QLabel("Data Transferred: 0 KB")

        self.stats_layout.addWidget(self.uptime_label)
        self.stats_layout.addWidget(self.sessions_count_label)
        self.stats_layout.addWidget(self.total_connections_label)
        self.stats_layout.addWidget(self.data_transferred_label)

        stats_group.setLayout(self.stats_layout)
        layout.addWidget(stats_group)

        return self.finalize_widget_layout(widget, layout)

    def create_sessions_tab(self):
        """Create sessions management tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Session controls
        control_layout = QHBoxLayout()

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_sessions)
        control_layout.addWidget(self.refresh_btn)

        self.interact_btn = QPushButton("Interact")
        self.interact_btn.clicked.connect(self.interact_with_session)
        self.interact_btn.setEnabled(False)
        control_layout.addWidget(self.interact_btn)

        self.kill_session_btn = QPushButton("Kill Session")
        self.kill_session_btn.clicked.connect(self.kill_session)
        self.kill_session_btn.setEnabled(False)
        control_layout.addWidget(self.kill_session_btn)

        control_layout.addStretch()
        layout.addLayout(control_layout)

        # Sessions table
        self.sessions_table = QTableWidget()
        self.sessions_table.setColumnCount(8)
        self.sessions_table.setHorizontalHeaderLabels([
            "Session ID", "Remote Address", "Username", "OS",
            "Architecture", "Status", "Last Beacon", "Uptime"
        ])

        # Configure table
        self.sessions_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.sessions_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.sessions_table.customContextMenuRequested.connect(self.show_session_context_menu)
        self.sessions_table.itemSelectionChanged.connect(self.on_session_selected)

        header = self.sessions_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setStretchLastSection(True)

        layout.addWidget(self.sessions_table)

        # Session details
        details_group = QGroupBox("Session Details")
        self.details_layout = QVBoxLayout()

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(150)
        self.details_layout.addWidget(self.details_text)

        details_group.setLayout(self.details_layout)
        layout.addWidget(details_group)

        widget.setLayout(layout)
        return widget

    def create_command_tab(self):
        """Create command and control tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Session selector
        session_layout = QHBoxLayout()
        session_layout.addWidget(QLabel("Target Session:"))

        self.session_combo = QComboBox()
        self.session_combo.addItem("Select a session...")
        session_layout.addWidget(self.session_combo)

        session_layout.addStretch()
        layout.addLayout(session_layout)

        # Command interface
        command_group = QGroupBox("Command Interface")
        command_layout = QVBoxLayout()

        # Quick commands
        quick_layout = QHBoxLayout()
        quick_layout.addWidget(QLabel("Quick Commands:"))

        self.sysinfo_btn = QPushButton("System Info")
        self.sysinfo_btn.clicked.connect(lambda: self.execute_command("sysinfo"))
        quick_layout.addWidget(self.sysinfo_btn)

        self.screenshot_btn = QPushButton("Screenshot")
        self.screenshot_btn.clicked.connect(lambda: self.execute_command("screenshot"))
        quick_layout.addWidget(self.screenshot_btn)

        self.processes_btn = QPushButton("Process List")
        self.processes_btn.clicked.connect(lambda: self.execute_command("ps"))
        quick_layout.addWidget(self.processes_btn)

        self.keylog_btn = QPushButton("Start Keylogger")
        self.keylog_btn.clicked.connect(lambda: self.execute_command("keylog start"))
        quick_layout.addWidget(self.keylog_btn)

        quick_layout.addStretch()
        command_layout.addLayout(quick_layout)

        # Command input
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter command...")
        self.command_input.returnPressed.connect(self.execute_custom_command)
        command_layout.addWidget(self.command_input)

        # Command output
        self.command_output = QTextEdit()
        self.command_output.setFont(QFont("Courier", 10))
        self.command_output.setReadOnly(True)
        command_layout.addWidget(self.command_output)

        command_group.setLayout(command_layout)
        layout.addWidget(command_group)

        # Task queue
        task_group = QGroupBox("Task Queue")
        task_layout = QVBoxLayout()

        self.task_table = QTableWidget()
        self.task_table.setColumnCount(4)
        self.task_table.setHorizontalHeaderLabels([
            "Task ID", "Type", "Status", "Created"
        ])
        self.task_table.setMaximumHeight(150)

        task_layout.addWidget(self.task_table)
        task_group.setLayout(task_layout)
        layout.addWidget(task_group)

        widget.setLayout(layout)
        return widget

    def create_file_manager_tab(self):
        """Create file manager tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # File browser
        browser_layout = QHBoxLayout()

        # Remote file tree
        remote_group = QGroupBox("Remote Files")
        remote_layout = QVBoxLayout()

        self.remote_tree = QTreeWidget()
        self.remote_tree.setHeaderLabel("Remote File System")
        remote_layout.addWidget(self.remote_tree)

        # Remote file controls
        remote_control_layout = QHBoxLayout()

        self.download_btn = QPushButton("Download")
        self.download_btn.clicked.connect(self.download_file)
        remote_control_layout.addWidget(self.download_btn)

        self.delete_remote_btn = QPushButton("Delete")
        self.delete_remote_btn.clicked.connect(self.delete_remote_file)
        remote_control_layout.addWidget(self.delete_remote_btn)

        remote_control_layout.addStretch()
        remote_layout.addLayout(remote_control_layout)

        remote_group.setLayout(remote_layout)
        browser_layout.addWidget(remote_group)

        # Upload area
        upload_group = QGroupBox("File Upload")
        upload_layout = QVBoxLayout()

        self.upload_list = QTreeWidget()
        self.upload_list.setHeaderLabel("Files to Upload")
        upload_layout.addWidget(self.upload_list)

        # Upload controls
        upload_control_layout = QHBoxLayout()

        self.add_file_btn = QPushButton("Add File")
        self.add_file_btn.clicked.connect(self.add_file_to_upload)
        upload_control_layout.addWidget(self.add_file_btn)

        self.upload_btn = QPushButton("Upload")
        self.upload_btn.clicked.connect(self.upload_files)
        upload_control_layout.addWidget(self.upload_btn)

        self.clear_upload_btn = QPushButton("Clear")
        self.clear_upload_btn.clicked.connect(self.clear_upload_list)
        upload_control_layout.addWidget(self.clear_upload_btn)

        upload_control_layout.addStretch()
        upload_layout.addLayout(upload_control_layout)

        upload_group.setLayout(upload_layout)
        browser_layout.addWidget(upload_group)

        layout.addLayout(browser_layout)

        # Transfer progress
        progress_group = QGroupBox("Transfer Progress")
        progress_layout = QVBoxLayout()

        self.transfer_table = QTableWidget()
        self.transfer_table.setColumnCount(5)
        self.transfer_table.setHorizontalHeaderLabels([
            "File", "Direction", "Size", "Progress", "Status"
        ])
        self.transfer_table.setMaximumHeight(150)

        progress_layout.addWidget(self.transfer_table)
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)

        widget.setLayout(layout)
        return widget

    def create_logs_tab(self):
        """Create activity logs tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Log filters
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))

        self.log_filter_combo = QComboBox()
        self.log_filter_combo.addItems([
            "All", "Connections", "Commands", "Transfers", "Errors"
        ])
        self.log_filter_combo.currentTextChanged.connect(self.filter_logs)
        filter_layout.addWidget(self.log_filter_combo)

        self.clear_logs_btn = QPushButton("Clear Logs")
        self.clear_logs_btn.clicked.connect(self.clear_logs)
        filter_layout.addWidget(self.clear_logs_btn)

        self.export_logs_btn = QPushButton("Export Logs")
        self.export_logs_btn.clicked.connect(self.export_logs)
        filter_layout.addWidget(self.export_logs_btn)

        filter_layout.addStretch()
        layout.addLayout(filter_layout)

        # Log display
        self.log_display = QTextEdit()
        self.log_display.setFont(QFont("Courier", 9))
        self.log_display.setReadOnly(True)
        layout.addWidget(self.log_display)

        widget.setLayout(layout)
        return widget

    def start_server(self):
        """Start the C2 server."""
        try:
            # Build server configuration
            config = {
                'https_enabled': self.https_check.isChecked(),
                'dns_enabled': self.dns_check.isChecked(),
                'tcp_enabled': self.tcp_check.isChecked(),
                'https': {
                    'host': self.listen_addr_edit.text(),
                    'port': self.https_port_spin.value()
                },
                'dns': {
                    'host': self.listen_addr_edit.text(),
                    'port': self.dns_port_spin.value(),
                    'domain': 'example.com'
                },
                'tcp': {
                    'host': self.listen_addr_edit.text(),
                    'port': self.tcp_port_spin.value()
                },
                'beacon_interval': self.beacon_interval_spin.value(),
                'jitter_percent': self.jitter_spin.value()
            }

            # Start server thread
            self.server_thread = C2ServerThread(config)
            self.server_thread.status_update.connect(self.on_server_status_update)
            self.server_thread.session_update.connect(self.on_session_update)
            self.server_thread.error.connect(self.on_server_error)
            self.server_thread.start()

            # Update UI
            self.start_server_btn.setEnabled(False)
            self.stop_server_btn.setEnabled(True)
            self.status_label.setText("C2 Server: Starting...")

            self.log_message("C2 server starting...", "info")

        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
            QMessageBox.critical(self, "Error", f"Failed to start server: {e}")

    def stop_server(self):
        """Stop the C2 server."""
        try:
            if self.server_thread:
                self.server_thread.stop_server()
                self.server_thread.wait()
                self.server_thread = None

            # Update UI
            self.start_server_btn.setEnabled(True)
            self.stop_server_btn.setEnabled(False)
            self.status_label.setText("C2 Server: Stopped")

            self.log_message("C2 server stopped", "info")

        except Exception as e:
            self.logger.error(f"Failed to stop server: {e}")
            QMessageBox.critical(self, "Error", f"Failed to stop server: {e}")

    def on_server_status_update(self, status: str):
        """Handle server status updates."""
        self.status_label.setText(f"C2 Server: {status}")
        self.log_message(f"Server: {status}", "info")

        if "started successfully" in status.lower():
            self.status_label.setStyleSheet("QLabel { padding: 5px; background-color: #90EE90; }")
        elif "stopped" in status.lower():
            self.status_label.setStyleSheet("QLabel { padding: 5px; background-color: #FFB6C1; }")

    def on_session_update(self, update: Dict[str, Any]):
        """Handle session updates from server."""
        event = update.get('event')

        if event == 'connected':
            session = update.get('session', {})
            self.add_session(session)
            self.log_message(f"New session connected: {session.get('session_id', 'unknown')}", "success")

        elif event == 'disconnected':
            session = update.get('session', {})
            self.remove_session(session.get('session_id'))
            self.log_message(f"Session disconnected: {session.get('session_id', 'unknown')}", "warning")

        elif event == 'beacon':
            data = update.get('data', {})
            session_id = data.get('session', {}).get('session_id')
            if session_id:
                self.update_session_beacon(session_id)

    def on_server_error(self, error: str):
        """Handle server errors."""
        self.status_label.setText("C2 Server: Error")
        self.status_label.setStyleSheet("QLabel { padding: 5px; background-color: #FF6B6B; }")
        self.log_message(f"Server error: {error}", "error")
        QMessageBox.critical(self, "Server Error", f"C2 server error: {error}")

    def add_session(self, session: Dict[str, Any]):
        """Add new session to table."""
        try:
            session_id = session.get('session_id', 'unknown')

            # Store session
            self.active_sessions[session_id] = session

            # Add to table
            row = self.sessions_table.rowCount()
            self.sessions_table.insertRow(row)

            # Populate row
            self.sessions_table.setItem(row, 0, QTableWidgetItem(session_id[:8]))

            conn_info = session.get('connection_info', {})
            self.sessions_table.setItem(row, 1, QTableWidgetItem(
                str(conn_info.get('remote_addr', 'unknown'))
            ))

            client_info = session.get('client_info', {})
            self.sessions_table.setItem(row, 2, QTableWidgetItem(
                client_info.get('username', 'unknown')
            ))
            self.sessions_table.setItem(row, 3, QTableWidgetItem(
                client_info.get('platform', 'unknown')
            ))
            self.sessions_table.setItem(row, 4, QTableWidgetItem(
                client_info.get('architecture', 'unknown')
            ))

            # Status
            status_item = QTableWidgetItem("Active")
            status_item.setForeground(QBrush(QColor(0, 255, 0)))
            self.sessions_table.setItem(row, 5, status_item)

            # Last beacon
            self.sessions_table.setItem(row, 6, QTableWidgetItem("Just now"))

            # Uptime
            self.sessions_table.setItem(row, 7, QTableWidgetItem("0:00:00"))

            # Update session combo
            self.session_combo.addItem(session_id, session_id)

        except Exception as e:
            self.logger.error(f"Failed to add session: {e}")

    def remove_session(self, session_id: str):
        """Remove session from table."""
        try:
            # Remove from storage
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]

            # Remove from table
            for row in range(self.sessions_table.rowCount()):
                item = self.sessions_table.item(row, 0)
                if item and session_id.startswith(item.text()):
                    self.sessions_table.removeRow(row)
                    break

            # Remove from combo
            for i in range(self.session_combo.count()):
                if self.session_combo.itemData(i) == session_id:
                    self.session_combo.removeItem(i)
                    break

        except Exception as e:
            self.logger.error(f"Failed to remove session: {e}")

    def update_session_beacon(self, session_id: str):
        """Update session beacon time."""
        try:
            # Find session row
            for row in range(self.sessions_table.rowCount()):
                item = self.sessions_table.item(row, 0)
                if item and session_id.startswith(item.text()):
                    # Update last beacon
                    self.sessions_table.setItem(row, 6, QTableWidgetItem("Just now"))
                    break

        except Exception as e:
            self.logger.error(f"Failed to update session beacon: {e}")

    def on_session_selected(self):
        """Handle session selection in table."""
        selected = self.sessions_table.selectedItems()
        if selected:
            session_id_item = self.sessions_table.item(selected[0].row(), 0)
            if session_id_item:
                # Find full session ID
                partial_id = session_id_item.text()
                for sid in self.active_sessions:
                    if sid.startswith(partial_id):
                        self.selected_session = sid
                        self.interact_btn.setEnabled(True)
                        self.kill_session_btn.setEnabled(True)
                        self.display_session_details(self.active_sessions[sid])
                        break
        else:
            self.selected_session = None
            self.interact_btn.setEnabled(False)
            self.kill_session_btn.setEnabled(False)
            self.details_text.clear()

    def display_session_details(self, session: Dict[str, Any]):
        """Display detailed session information."""
        try:
            details = []
            details.append(f"Session ID: {session.get('session_id', 'unknown')}")

            conn_info = session.get('connection_info', {})
            details.append(f"Remote Address: {conn_info.get('remote_addr', 'unknown')}")
            details.append(f"Protocol: {conn_info.get('protocol', 'unknown')}")

            client_info = session.get('client_info', {})
            details.append(f"Username: {client_info.get('username', 'unknown')}")
            details.append(f"Hostname: {client_info.get('hostname', 'unknown')}")
            details.append(f"OS: {client_info.get('platform', 'unknown')}")
            details.append(f"Architecture: {client_info.get('architecture', 'unknown')}")

            caps = session.get('capabilities', [])
            details.append(f"Capabilities: {', '.join(caps)}")

            self.details_text.setText('\n'.join(details))

        except Exception as e:
            self.logger.error(f"Failed to display session details: {e}")

    def show_session_context_menu(self, position):
        """Show context menu for session table."""
        if not self.selected_session:
            return

        menu = QMenu()

        interact_action = QAction("Interact", self)
        interact_action.triggered.connect(self.interact_with_session)
        menu.addAction(interact_action)

        menu.addSeparator()

        sysinfo_action = QAction("Get System Info", self)
        sysinfo_action.triggered.connect(lambda: self.execute_command("sysinfo"))
        menu.addAction(sysinfo_action)

        screenshot_action = QAction("Take Screenshot", self)
        screenshot_action.triggered.connect(lambda: self.execute_command("screenshot"))
        menu.addAction(screenshot_action)

        menu.addSeparator()

        kill_action = QAction("Kill Session", self)
        kill_action.triggered.connect(self.kill_session)
        menu.addAction(kill_action)

        menu.exec_(self.sessions_table.mapToGlobal(position))

    def interact_with_session(self):
        """Start interaction with selected session."""
        if self.selected_session:
            self.tab_widget.setCurrentIndex(2)  # Switch to command tab

            # Set session in combo
            for i in range(self.session_combo.count()):
                if self.session_combo.itemData(i) == self.selected_session:
                    self.session_combo.setCurrentIndex(i)
                    break

            self.command_input.setFocus()
            self.log_message(f"Interacting with session {self.selected_session}", "info")

    def kill_session(self):
        """Kill selected session."""
        if not self.selected_session:
            return

        reply = QMessageBox.question(
            self, "Kill Session",
            f"Are you sure you want to kill session {self.selected_session[:8]}?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            # Send kill command
            self.execute_command("exit", self.selected_session)
            self.remove_session(self.selected_session)
            self.log_message(f"Killed session {self.selected_session}", "warning")

    def execute_command(self, command: str, session_id: str = None):
        """Execute command on target session."""
        try:
            if not session_id:
                session_id = self.session_combo.currentData()

            if not session_id or session_id not in self.active_sessions:
                QMessageBox.warning(self, "Warning", "Please select a valid session")
                return

            # Send command to server
            if self.server_thread and self.server_thread.server:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                loop.run_until_complete(
                    self.server_thread.server.send_command(
                        session_id, "shell_command", {"command": command}
                    )
                )

                # Display in output
                timestamp = datetime.now().strftime("%H:%M:%S")
                self.command_output.append(f"[{timestamp}] > {command}")
                self.command_output.append("Command sent, awaiting response...\n")

                # Log command
                self.log_message(f"Command sent to {session_id[:8]}: {command}", "info")

                # Emit signal
                self.command_executed.emit(session_id, command)

        except Exception as e:
            self.logger.error(f"Failed to execute command: {e}")
            QMessageBox.critical(self, "Error", f"Failed to execute command: {e}")

    def execute_custom_command(self):
        """Execute custom command from input."""
        command = self.command_input.text().strip()
        if command:
            self.execute_command(command)
            self.command_input.clear()

    def refresh_sessions(self):
        """Refresh session list."""
        if self.server_thread and self.server_thread.server:
            sessions = self.server_thread.server.get_active_sessions()

            # Clear and repopulate table
            self.sessions_table.setRowCount(0)
            self.active_sessions.clear()

            for session in sessions:
                self.add_session(session)

            self.log_message("Session list refreshed", "info")

    def update_statistics(self):
        """Update server statistics."""
        try:
            if self.server_thread and self.server_thread.server:
                stats = self.server_thread.server.get_server_statistics()

                # Update labels
                if stats.get('start_time'):
                    uptime = time.time() - stats['start_time']
                    hours = int(uptime // 3600)
                    minutes = int((uptime % 3600) // 60)
                    seconds = int(uptime % 60)
                    self.uptime_label.setText(f"Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}")

                self.sessions_count_label.setText(f"Active Sessions: {stats.get('active_sessions', 0)}")
                self.total_connections_label.setText(f"Total Connections: {stats.get('total_connections', 0)}")

                data_kb = stats.get('total_data_transfer', 0) / 1024
                self.data_transferred_label.setText(f"Data Transferred: {data_kb:.2f} KB")

                # Update session uptime in table
                for row in range(self.sessions_table.rowCount()):
                    session_id_item = self.sessions_table.item(row, 0)
                    if session_id_item:
                        partial_id = session_id_item.text()
                        for sid, session in self.active_sessions.items():
                            if sid.startswith(partial_id):
                                created_at = session.get('created_at', time.time())
                                session_uptime = time.time() - created_at
                                uptime_str = f"{int(session_uptime//3600):02d}:{int((session_uptime%3600)//60):02d}:{int(session_uptime%60):02d}"
                                self.sessions_table.setItem(row, 7, QTableWidgetItem(uptime_str))
                                break

        except Exception as e:
            self.logger.error(f"Failed to update statistics: {e}")

    def download_file(self):
        """Download file from remote session."""
        try:
            # Get current selection
            current_item = self.file_browser.currentItem()
            if not current_item:
                QMessageBox.warning(self, "Download", "Please select a file to download")
                return

            file_path = current_item.text()
            session_id = self.session_combo.currentData()

            if not session_id:
                QMessageBox.warning(self, "Download", "No active session selected")
                return

            # Get remote file path
            if hasattr(current_item, 'full_path'):
                remote_path = current_item.full_path
            else:
                remote_path = file_path

            # Show file dialog for local save location
            from PyQt6.QtWidgets import QFileDialog
            local_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Downloaded File",
                file_path,
                "All Files (*.*)"
            )

            if not local_path:
                return

            # Send download command to session
            command = {
                'type': 'download_file',
                'remote_path': remote_path,
                'local_path': local_path
            }

            success = self.send_command_to_session(session_id, command)
            if success:
                self.log_message(f"Downloading file: {remote_path}", "info")
                QMessageBox.information(self, "Download", f"File download initiated: {remote_path}")
            else:
                QMessageBox.critical(self, "Download", "Failed to initiate file download")

        except Exception as e:
            self.logger.error(f"File download error: {e}")
            QMessageBox.critical(self, "Download", f"Download failed: {str(e)}")

    def delete_remote_file(self):
        """Delete file on remote session."""
        try:
            # Get current selection
            current_item = self.file_browser.currentItem()
            if not current_item:
                QMessageBox.warning(self, "Delete", "Please select a file to delete")
                return

            file_path = current_item.text()
            session_id = self.session_combo.currentData()

            if not session_id:
                QMessageBox.warning(self, "Delete", "No active session selected")
                return

            # Get remote file path
            if hasattr(current_item, 'full_path'):
                remote_path = current_item.full_path
            else:
                remote_path = file_path

            # Confirm deletion
            reply = QMessageBox.question(
                self,
                "Confirm Delete",
                f"Are you sure you want to delete the remote file:\n{remote_path}?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply != QMessageBox.Yes:
                return

            # Send delete command to session
            command = {
                'type': 'delete_file',
                'remote_path': remote_path
            }

            success = self.send_command_to_session(session_id, command)
            if success:
                self.log_message(f"Deleting file: {remote_path}", "info")
                # Remove item from browser
                parent = current_item.parent()
                if parent:
                    parent.removeChild(current_item)
                else:
                    index = self.file_browser.indexOfTopLevelItem(current_item)
                    if index >= 0:
                        self.file_browser.takeTopLevelItem(index)
                QMessageBox.information(self, "Delete", f"File deletion initiated: {remote_path}")
            else:
                QMessageBox.critical(self, "Delete", "Failed to initiate file deletion")

        except Exception as e:
            self.logger.error(f"File deletion error: {e}")
            QMessageBox.critical(self, "Delete", f"Deletion failed: {str(e)}")

    def add_file_to_upload(self):
        """Add file to upload list."""
        try:
            from PyQt6.QtWidgets import QFileDialog

            # Open file dialog to select files
            file_paths, _ = QFileDialog.getOpenFileNames(
                self,
                "Select Files to Upload",
                "",
                "All Files (*.*)"
            )

            if not file_paths:
                return

            # Add files to upload list
            for file_path in file_paths:
                import os
                file_name = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)

                # Check if file already exists in list
                for row in range(self.upload_list.rowCount()):
                    existing_item = self.upload_list.item(row, 0)
                    if existing_item and existing_item.text() == file_name:
                        continue  # Skip duplicates

                # Add to upload list table
                row = self.upload_list.rowCount()
                self.upload_list.insertRow(row)

                # File name
                name_item = QTableWidgetItem(file_name)
                name_item.setData(Qt.UserRole, file_path)  # Store full path
                self.upload_list.setItem(row, 0, name_item)

                # File size
                size_str = self.format_file_size(file_size)
                self.upload_list.setItem(row, 1, QTableWidgetItem(size_str))

                # Status
                self.upload_list.setItem(row, 2, QTableWidgetItem("Ready"))

            self.log_message(f"Added {len(file_paths)} file(s) to upload queue", "info")

        except Exception as e:
            self.logger.error(f"Add file to upload error: {e}")
            QMessageBox.critical(self, "Upload", f"Failed to add files: {str(e)}")

    def upload_files(self):
        """Upload files to remote session."""
        try:
            session_id = self.session_combo.currentData()
            if not session_id:
                QMessageBox.warning(self, "Upload", "No active session selected")
                return

            # Check if there are files to upload
            if self.upload_list.rowCount() == 0:
                QMessageBox.warning(self, "Upload", "No files in upload queue")
                return

            # Get remote directory from path input (if available)
            remote_dir = getattr(self, 'remote_path_input', None)
            if remote_dir and hasattr(remote_dir, 'text'):
                remote_base_path = remote_dir.text() or "/"
            else:
                remote_base_path = "/"

            uploaded_count = 0
            failed_count = 0

            # Process each file in upload list
            for row in range(self.upload_list.rowCount()):
                name_item = self.upload_list.item(row, 0)
                status_item = self.upload_list.item(row, 2)

                if not name_item or status_item.text() != "Ready":
                    continue

                local_path = name_item.data(Qt.UserRole)
                file_name = name_item.text()

                # Update status to uploading
                status_item.setText("Uploading...")

                try:
                    # Read file data
                    with open(local_path, 'rb') as f:
                        file_data = f.read()

                    import base64

                    # Construct remote path
                    remote_path = f"{remote_base_path.rstrip('/')}/{file_name}"

                    # Send upload command to session
                    command = {
                        'type': 'upload_file',
                        'remote_path': remote_path,
                        'file_data': base64.b64encode(file_data).decode('utf-8'),
                        'file_size': len(file_data)
                    }

                    success = self.send_command_to_session(session_id, command)
                    if success:
                        status_item.setText("Completed")
                        status_item.setForeground(QBrush(QColor(0, 255, 0)))
                        uploaded_count += 1
                        self.log_message(f"Uploaded file: {file_name}", "success")
                    else:
                        status_item.setText("Failed")
                        status_item.setForeground(QBrush(QColor(255, 0, 0)))
                        failed_count += 1

                except Exception as file_error:
                    self.logger.error(f"Failed to upload {file_name}: {file_error}")
                    status_item.setText("Error")
                    status_item.setForeground(QBrush(QColor(255, 0, 0)))
                    failed_count += 1

            # Show completion message
            if uploaded_count > 0:
                message = f"Upload completed: {uploaded_count} file(s) uploaded"
                if failed_count > 0:
                    message += f", {failed_count} failed"
                QMessageBox.information(self, "Upload Complete", message)
            elif failed_count > 0:
                QMessageBox.critical(self, "Upload Failed", f"All {failed_count} file(s) failed to upload")

        except Exception as e:
            self.logger.error(f"File upload error: {e}")
            QMessageBox.critical(self, "Upload", f"Upload failed: {str(e)}")

    def clear_upload_list(self):
        """Clear upload file list."""
        self.upload_list.clear()

    def filter_logs(self, filter_type: str):
        """Filter activity logs."""
        # Placeholder for log filtering
        pass

    def clear_logs(self):
        """Clear activity logs."""
        self.log_display.clear()

    def export_logs(self):
        """Export activity logs."""
        # Placeholder for log export functionality
        QMessageBox.information(self, "Export", "Log export functionality to be implemented")

    def log_message(self, message: str, level: str = "info"):
        """Add message to activity log."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Format message based on level
        if level == "error":
            formatted = f"[{timestamp}] [ERROR] {message}"
            color = "red"
        elif level == "warning":
            formatted = f"[{timestamp}] [WARN] {message}"
            color = "orange"
        elif level == "success":
            formatted = f"[{timestamp}] [OK] {message}"
            color = "green"
        else:
            formatted = f"[{timestamp}] [INFO] {message}"
            color = "black"

        # Add to log display
        cursor = self.log_display.textCursor()
        cursor.movePosition(cursor.End)

        format = cursor.charFormat()
        format.setForeground(QColor(color))
        cursor.setCharFormat(format)

        cursor.insertText(formatted + "\n")
        self.log_display.setTextCursor(cursor)
        self.log_display.ensureCursorVisible()

    def format_file_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format."""
        try:
            if size_bytes < 1024:
                return f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                return f"{size_bytes / 1024:.1f} KB"
            elif size_bytes < 1024 * 1024 * 1024:
                return f"{size_bytes / (1024 * 1024):.1f} MB"
            else:
                return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
        except:
            return f"{size_bytes} B"

    def send_command_to_session(self, session_id: str, command: Dict[str, Any]) -> bool:
        """Send command to specific session."""
        try:
            if not self.server_thread or not self.server_thread.server:
                self.log_message("No active C2 server to send command", "error")
                return False

            if session_id not in self.active_sessions:
                self.log_message(f"Session {session_id} not found", "error")
                return False

            # Add command to server's command queue for the session
            # This would typically go through the server's session manager
            success = self.server_thread.server.send_command_to_session(session_id, command)

            if success:
                self.log_message(f"Command sent to session {session_id}: {command.get('type', 'unknown')}", "info")
            else:
                self.log_message(f"Failed to send command to session {session_id}", "error")

            return success

        except Exception as e:
            self.logger.error(f"Failed to send command to session: {e}")
            self.log_message(f"Command send error: {str(e)}", "error")
            return False

    def closeEvent(self, event):
        """Handle dialog close event."""
        if self.server_thread and self.server_thread.isRunning():
            reply = QMessageBox.question(
                self, "Close C2 Manager",
                "C2 server is still running. Stop server and close?",
                QMessageBox.Yes | QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                self.stop_server()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()
