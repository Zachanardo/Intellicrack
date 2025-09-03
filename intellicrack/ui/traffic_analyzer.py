"""Network Traffic Analysis UI Module.

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

import logging
import platform
import threading
import time

from intellicrack.handlers.pyqt6_handler import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTextEdit,
    QTimer,
    QVBoxLayout,
    QWidget,
)
from intellicrack.utils.log_message import log_error, log_info, log_warning


class TrafficAnalyzer:
    """Visual Network Traffic Analysis UI wrapper.

    This class provides a comprehensive UI interface for network traffic
    analysis, integrating with Intellicrack's existing NetworkTrafficAnalyzer
    for real-time packet capture, analysis, and visualization.
    """

    def __init__(self):
        """Initialize traffic analyzer with existing infrastructure integration."""
        self.logger = logging.getLogger(__name__)
        self.analyzer = None
        self.analysis_thread = None
        self.capture_active = False

    def run_visual_network_traffic_analyzer(self, main_window):
        """Launch visual network traffic analyzer dialog.

        Args:
            main_window: Main application window for context and logging
        """
        try:
            log_info("Launching Visual Network Traffic Analyzer...")

            # Import the core analyzer
            from intellicrack.core.network.traffic_analyzer import NetworkTrafficAnalyzer

            # Create and show the traffic analysis dialog
            dialog = NetworkTrafficAnalysisDialog(main_window)
            dialog.exec()

        except ImportError as e:
            error_msg = f"Failed to import NetworkTrafficAnalyzer: {e}"
            log_error(error_msg)
            main_window.log_message(error_msg)
        except Exception as e:
            error_msg = f"Error launching traffic analyzer: {e}"
            log_error(error_msg)
            main_window.log_message(error_msg)


class NetworkTrafficAnalysisDialog(QDialog):
    """Comprehensive network traffic analysis dialog with real-time capture and visualization."""

    def __init__(self, parent=None):
        """Initialize the network traffic analysis dialog.

        Args:
            parent: Parent widget, typically main application window
        """
        super().__init__(parent)
        self.parent = parent
        self.analyzer = None
        self.capture_thread = None
        self.analysis_results = {}
        self.captured_packets = []

        self.setWindowTitle("Visual Network Traffic Analyzer")
        self.setMinimumSize(900, 700)
        self.setModal(True)

        self._initialize_analyzer()
        self._setup_ui()
        self._connect_signals()

    def _initialize_analyzer(self):
        """Initialize the core NetworkTrafficAnalyzer."""
        try:
            from intellicrack.core.network.traffic_analyzer import NetworkTrafficAnalyzer

            self.analyzer = NetworkTrafficAnalyzer()
            log_info("NetworkTrafficAnalyzer initialized successfully")
        except Exception as e:
            error_msg = f"Failed to initialize NetworkTrafficAnalyzer: {e}"
            log_error(error_msg)
            self.analyzer = None

    def _setup_ui(self):
        """Set up the comprehensive UI layout."""
        layout = QVBoxLayout(self)

        # Create tab widget for organized interface
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Capture Configuration Tab
        self._create_capture_config_tab()

        # Real-time Monitoring Tab
        self._create_monitoring_tab()

        # Analysis Results Tab
        self._create_results_tab()

        # Visualization Tab
        self._create_visualization_tab()

        # Control buttons
        self._create_control_buttons(layout)

    def _create_capture_config_tab(self):
        """Create the capture configuration tab."""
        config_widget = QWidget()
        layout = QVBoxLayout(config_widget)

        # Interface Selection Group
        interface_group = QGroupBox("Network Interface Configuration")
        interface_layout = QGridLayout(interface_group)

        interface_layout.addWidget(QLabel("Interface:"), 0, 0)
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(["auto", "eth0", "wlan0", "lo"])
        interface_layout.addWidget(self.interface_combo, 0, 1)

        interface_layout.addWidget(QLabel("Capture Filter:"), 1, 0)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("tcp port 443 or udp port 53")
        interface_layout.addWidget(self.filter_edit, 1, 1)

        interface_layout.addWidget(QLabel("Timeout (seconds):"), 2, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(10, 3600)
        self.timeout_spin.setValue(60)
        interface_layout.addWidget(self.timeout_spin, 2, 1)

        layout.addWidget(interface_group)

        # License Detection Group
        license_group = QGroupBox("License Traffic Detection")
        license_layout = QGridLayout(license_group)

        self.enable_license_detection = QCheckBox("Enable License Server Detection")
        self.enable_license_detection.setChecked(True)
        license_layout.addWidget(self.enable_license_detection, 0, 0, 1, 2)

        license_layout.addWidget(QLabel("License Patterns:"), 1, 0)
        self.license_patterns_edit = QTextEdit()
        self.license_patterns_edit.setMaximumHeight(100)
        self.license_patterns_edit.setPlainText("license\nactivation\nkey\ntoken\ncredentials")
        license_layout.addWidget(self.license_patterns_edit, 1, 1)

        license_layout.addWidget(QLabel("Common License Ports:"), 2, 0)
        self.license_ports_edit = QLineEdit("443,8080,27000,27001,7788,5093")
        license_layout.addWidget(self.license_ports_edit, 2, 1)

        layout.addWidget(license_group)

        # Analysis Options Group
        analysis_group = QGroupBox("Analysis Options")
        analysis_layout = QGridLayout(analysis_group)

        self.deep_packet_inspection = QCheckBox("Deep Packet Inspection")
        self.deep_packet_inspection.setChecked(True)
        analysis_layout.addWidget(self.deep_packet_inspection, 0, 0)

        self.protocol_analysis = QCheckBox("Protocol Analysis")
        self.protocol_analysis.setChecked(True)
        analysis_layout.addWidget(self.protocol_analysis, 0, 1)

        self.traffic_classification = QCheckBox("Traffic Classification")
        self.traffic_classification.setChecked(True)
        analysis_layout.addWidget(self.traffic_classification, 1, 0)

        self.anomaly_detection = QCheckBox("Anomaly Detection")
        self.anomaly_detection.setChecked(False)
        analysis_layout.addWidget(self.anomaly_detection, 1, 1)

        layout.addWidget(analysis_group)

        self.tab_widget.addTab(config_widget, "Configuration")

    def _create_monitoring_tab(self):
        """Create the real-time monitoring tab."""
        monitor_widget = QWidget()
        layout = QVBoxLayout(monitor_widget)

        # Status Group
        status_group = QGroupBox("Capture Status")
        status_layout = QGridLayout(status_group)

        status_layout.addWidget(QLabel("Status:"), 0, 0)
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: green; font-weight: bold;")
        status_layout.addWidget(self.status_label, 0, 1)

        status_layout.addWidget(QLabel("Packets Captured:"), 1, 0)
        self.packet_count_label = QLabel("0")
        status_layout.addWidget(self.packet_count_label, 1, 1)

        status_layout.addWidget(QLabel("License Traffic:"), 2, 0)
        self.license_traffic_label = QLabel("0")
        status_layout.addWidget(self.license_traffic_label, 2, 1)

        layout.addWidget(status_group)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Real-time Packet List
        packet_group = QGroupBox("Live Packet Feed")
        packet_layout = QVBoxLayout(packet_group)

        self.packet_list = QListWidget()
        self.packet_list.setMaximumHeight(300)
        packet_layout.addWidget(self.packet_list)

        layout.addWidget(packet_group)

        # Real-time Statistics
        stats_group = QGroupBox("Real-time Statistics")
        stats_layout = QGridLayout(stats_group)

        stats_layout.addWidget(QLabel("Packet Rate (pps):"), 0, 0)
        self.packet_rate_label = QLabel("0")
        stats_layout.addWidget(self.packet_rate_label, 0, 1)

        stats_layout.addWidget(QLabel("Data Rate (Mbps):"), 1, 0)
        self.data_rate_label = QLabel("0.0")
        stats_layout.addWidget(self.data_rate_label, 1, 1)

        stats_layout.addWidget(QLabel("Top Protocol:"), 2, 0)
        self.top_protocol_label = QLabel("N/A")
        stats_layout.addWidget(self.top_protocol_label, 2, 1)

        layout.addWidget(stats_group)

        self.tab_widget.addTab(monitor_widget, "Live Monitoring")

    def _create_results_tab(self):
        """Create the analysis results tab."""
        results_widget = QWidget()
        layout = QVBoxLayout(results_widget)

        # Analysis Summary
        summary_group = QGroupBox("Analysis Summary")
        summary_layout = QVBoxLayout(summary_group)

        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setMaximumHeight(200)
        summary_layout.addWidget(self.summary_text)

        layout.addWidget(summary_group)

        # Detailed Results
        details_group = QGroupBox("Detailed Analysis Results")
        details_layout = QVBoxLayout(details_group)

        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        details_layout.addWidget(self.results_text)

        layout.addWidget(details_group)

        # Export Options
        export_group = QGroupBox("Export Options")
        export_layout = QHBoxLayout(export_group)

        self.export_json_btn = QPushButton("Export JSON")
        self.export_csv_btn = QPushButton("Export CSV")
        self.export_pcap_btn = QPushButton("Export PCAP")
        self.export_report_btn = QPushButton("Generate Report")

        export_layout.addWidget(self.export_json_btn)
        export_layout.addWidget(self.export_csv_btn)
        export_layout.addWidget(self.export_pcap_btn)
        export_layout.addWidget(self.export_report_btn)

        layout.addWidget(export_group)

        self.tab_widget.addTab(results_widget, "Results")

    def _create_visualization_tab(self):
        """Create the visualization tab."""
        viz_widget = QWidget()
        layout = QVBoxLayout(viz_widget)

        # Visualization Controls
        controls_group = QGroupBox("Visualization Controls")
        controls_layout = QGridLayout(controls_group)

        controls_layout.addWidget(QLabel("Chart Type:"), 0, 0)
        self.chart_type_combo = QComboBox()
        self.chart_type_combo.addItems(
            ["Protocol Distribution", "Traffic Over Time", "Port Distribution", "License Traffic Analysis", "Connection Flow Diagram"]
        )
        controls_layout.addWidget(self.chart_type_combo, 0, 1)

        controls_layout.addWidget(QLabel("Time Window (minutes):"), 1, 0)
        self.time_window_spin = QSpinBox()
        self.time_window_spin.setRange(1, 60)
        self.time_window_spin.setValue(5)
        controls_layout.addWidget(self.time_window_spin, 1, 1)

        self.generate_viz_btn = QPushButton("Generate Visualization")
        controls_layout.addWidget(self.generate_viz_btn, 2, 0, 1, 2)

        layout.addWidget(controls_group)

        # Visualization Display Area
        viz_display_group = QGroupBox("Visualization Display")
        viz_display_layout = QVBoxLayout(viz_display_group)

        self.viz_display = QTextEdit()
        self.viz_display.setReadOnly(True)
        self.viz_display.setPlainText("Visualization will be displayed here after analysis...")
        viz_display_layout.addWidget(self.viz_display)

        layout.addWidget(viz_display_group)

        self.tab_widget.addTab(viz_widget, "Visualization")

    def _create_control_buttons(self, layout):
        """Create main control buttons."""
        button_layout = QHBoxLayout()

        self.start_capture_btn = QPushButton("Start Capture")
        self.stop_capture_btn = QPushButton("Stop Capture")
        self.analyze_btn = QPushButton("Analyze Traffic")
        self.clear_btn = QPushButton("Clear Data")
        self.close_btn = QPushButton("Close")

        self.stop_capture_btn.setEnabled(False)
        self.analyze_btn.setEnabled(False)

        button_layout.addWidget(self.start_capture_btn)
        button_layout.addWidget(self.stop_capture_btn)
        button_layout.addWidget(self.analyze_btn)
        button_layout.addWidget(self.clear_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.close_btn)

        layout.addLayout(button_layout)

    def _connect_signals(self):
        """Connect UI signals to handlers."""
        self.start_capture_btn.clicked.connect(self._start_capture)
        self.stop_capture_btn.clicked.connect(self._stop_capture)
        self.analyze_btn.clicked.connect(self._analyze_traffic)
        self.clear_btn.clicked.connect(self._clear_data)
        self.close_btn.clicked.connect(self.close)

        # Export buttons
        self.export_json_btn.clicked.connect(self._export_json)
        self.export_csv_btn.clicked.connect(self._export_csv)
        self.export_pcap_btn.clicked.connect(self._export_pcap)
        self.export_report_btn.clicked.connect(self._export_report)

        # Visualization button
        self.generate_viz_btn.clicked.connect(self._generate_visualization)

        # Update timer for real-time stats
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self._update_realtime_stats)

    def _start_capture(self):
        """Start network traffic capture."""
        if not self.analyzer:
            QMessageBox.warning(self, "Error", "Network traffic analyzer not available")
            return

        try:
            # Get configuration from UI
            interface = self.interface_combo.currentText()
            timeout = self.timeout_spin.value()
            packet_filter = self.filter_edit.text()

            # Configure analyzer
            config = {
                "interface": interface,
                "timeout": timeout,
                "filter": packet_filter,
                "enable_license_detection": self.enable_license_detection.isChecked(),
                "deep_inspection": self.deep_packet_inspection.isChecked(),
            }

            # Start capture in separate thread
            self.capture_thread = threading.Thread(target=self._capture_worker, args=(config,), daemon=True)

            self.capture_thread.start()

            # Update UI state
            self.start_capture_btn.setEnabled(False)
            self.stop_capture_btn.setEnabled(True)
            self.status_label.setText("Capturing...")
            self.status_label.setStyleSheet("color: orange; font-weight: bold;")

            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, timeout)

            # Start update timer
            self.update_timer.start(1000)  # Update every second

            log_info(f"Started network traffic capture on interface: {interface}")

        except Exception as e:
            error_msg = f"Failed to start capture: {e}"
            log_error(error_msg)
            QMessageBox.critical(self, "Capture Error", error_msg)

    def _capture_worker(self, config):
        """Worker method for packet capture."""
        try:
            # Set license patterns if enabled
            if config.get("enable_license_detection"):
                patterns = self.license_patterns_edit.toPlainText().split("\n")
                patterns = [p.strip() for p in patterns if p.strip()]
                self.analyzer.license_patterns = patterns

                # Set license ports
                ports_text = self.license_ports_edit.text()
                if ports_text:
                    ports = [int(p.strip()) for p in ports_text.split(",") if p.strip().isdigit()]
                    self.analyzer.license_ports = ports

            # Start capture
            self.analyzer.start_capture(
                interface=config.get("interface", "auto"), timeout=config.get("timeout", 60), packet_filter=config.get("filter")
            )

        except Exception as e:
            log_error(f"Capture worker error: {e}")

    def _stop_capture(self):
        """Stop network traffic capture."""
        try:
            if self.analyzer:
                self.analyzer.stop_capture()

            # Update UI state
            self.start_capture_btn.setEnabled(True)
            self.stop_capture_btn.setEnabled(False)
            self.analyze_btn.setEnabled(True)
            self.status_label.setText("Capture Complete")
            self.status_label.setStyleSheet("color: blue; font-weight: bold;")

            self.progress_bar.setVisible(False)
            self.update_timer.stop()

            log_info("Network traffic capture stopped")

        except Exception as e:
            error_msg = f"Error stopping capture: {e}"
            log_error(error_msg)
            QMessageBox.critical(self, "Stop Error", error_msg)

    def _analyze_traffic(self):
        """Analyze captured traffic."""
        if not self.analyzer:
            QMessageBox.warning(self, "Error", "Network traffic analyzer not available")
            return

        try:
            self.status_label.setText("Analyzing...")
            self.status_label.setStyleSheet("color: orange; font-weight: bold;")

            # Run analysis
            self.analyzer.analyze_traffic()
            self.analysis_results = self.analyzer.get_results()

            # Update results display
            self._update_results_display()

            self.status_label.setText("Analysis Complete")
            self.status_label.setStyleSheet("color: green; font-weight: bold;")

            log_info("Traffic analysis completed successfully")

        except Exception as e:
            error_msg = f"Analysis failed: {e}"
            log_error(error_msg)
            QMessageBox.critical(self, "Analysis Error", error_msg)
            self.status_label.setText("Analysis Failed")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")

    def _update_results_display(self):
        """Update the results display with analysis data."""
        if not self.analysis_results:
            return

        # Update summary
        summary = f"""
Analysis Summary:
================
Total Packets: {self.analysis_results.get("packet_count", 0)}
License Traffic: {self.analysis_results.get("license_traffic_count", 0)}
Analysis Duration: {self.analysis_results.get("capture_duration", 0):.2f} seconds
Threat Level: {self.analysis_results.get("threat_level", "Unknown")}
        """
        self.summary_text.setPlainText(summary.strip())

        # Update detailed results
        details = "Detailed Analysis Results:\n"
        details += "=" * 50 + "\n\n"

        # Protocol distribution
        if "protocol_distribution" in self.analysis_results:
            details += "Protocol Distribution:\n"
            for protocol, count in self.analysis_results["protocol_distribution"].items():
                details += f"  {protocol}: {count} packets\n"
            details += "\n"

        # Top connections
        if "top_connections" in self.analysis_results:
            details += "Top Connections:\n"
            for conn in self.analysis_results["top_connections"][:10]:
                details += f"  {conn['src']} -> {conn['dst']} ({conn['count']} packets)\n"
            details += "\n"

        # License analysis
        if "license_analysis" in self.analysis_results:
            details += "License Traffic Analysis:\n"
            license_data = self.analysis_results["license_analysis"]
            details += f"  Suspected License Servers: {len(license_data.get('servers', []))}\n"
            details += f"  License-related Packets: {license_data.get('packet_count', 0)}\n"
            details += f"  License Traffic Percentage: {license_data.get('traffic_percentage', 0):.2f}%\n"

        self.results_text.setPlainText(details)

    def _update_realtime_stats(self):
        """Update real-time statistics during capture."""
        if not self.analyzer:
            return

        try:
            packet_count = len(getattr(self.analyzer, "packets", []))
            license_count = len(getattr(self.analyzer, "license_connections", []))

            self.packet_count_label.setText(str(packet_count))
            self.license_traffic_label.setText(str(license_count))

            # Update progress bar
            if self.progress_bar.isVisible():
                elapsed = getattr(self.analyzer, "_capture_start_time", 0)
                if elapsed:
                    import time

                    elapsed_seconds = time.time() - elapsed
                    self.progress_bar.setValue(min(int(elapsed_seconds), self.progress_bar.maximum()))

        except Exception as e:
            log_warning(f"Error updating real-time stats: {e}")

    def _clear_data(self):
        """Clear all captured data and reset the interface."""
        try:
            if self.analyzer:
                self.analyzer.packets = []
                self.analyzer.connections = {}
                self.analyzer.license_connections = []

            self.analysis_results = {}
            self.packet_count_label.setText("0")
            self.license_traffic_label.setText("0")
            self.packet_list.clear()
            self.summary_text.clear()
            self.results_text.clear()
            self.viz_display.setPlainText("Visualization will be displayed here after analysis...")

            self.status_label.setText("Ready")
            self.status_label.setStyleSheet("color: green; font-weight: bold;")

            log_info("Traffic analysis data cleared")

        except Exception as e:
            log_error(f"Error clearing data: {e}")

    def _export_json(self):
        """Export analysis results to JSON."""
        if not self.analysis_results:
            QMessageBox.warning(self, "Warning", "No analysis results to export")
            return

        try:
            filename, _ = QFileDialog.getSaveFileName(self, "Export JSON", "traffic_analysis.json", "JSON files (*.json)")

            if filename:
                import json

                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(self.analysis_results, f, indent=2, default=str)

                QMessageBox.information(self, "Success", f"Results exported to {filename}")
                log_info(f"Analysis results exported to JSON: {filename}")

        except Exception as e:
            error_msg = f"Failed to export JSON: {e}"
            log_error(error_msg)
            QMessageBox.critical(self, "Export Error", error_msg)

    def _export_csv(self):
        """Export packet data to CSV."""
        if not self.analyzer or not hasattr(self.analyzer, "packets"):
            QMessageBox.warning(self, "Warning", "No packet data to export")
            return

        try:
            filename, _ = QFileDialog.getSaveFileName(self, "Export CSV", "packet_data.csv", "CSV files (*.csv)")

            if filename:
                import csv

                with open(filename, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Timestamp", "Source", "Destination", "Protocol", "Length"])

                    for packet in self.analyzer.packets[:1000]:  # Limit to first 1000 packets
                        writer.writerow(
                            [
                                packet.get("timestamp", ""),
                                packet.get("src", ""),
                                packet.get("dst", ""),
                                packet.get("protocol", ""),
                                packet.get("length", 0),
                            ]
                        )

                QMessageBox.information(self, "Success", f"Packet data exported to {filename}")
                log_info(f"Packet data exported to CSV: {filename}")

        except Exception as e:
            error_msg = f"Failed to export CSV: {e}"
            log_error(error_msg)
            QMessageBox.critical(self, "Export Error", error_msg)

    def _export_pcap(self):
        """Export captured packets to PCAP file."""
        QMessageBox.information(
            self,
            "PCAP Export",
            "PCAP export functionality requires additional packet capture libraries.\n"
            "Use the built-in packet capture features or external tools for PCAP generation.",
        )

    def _export_report(self):
        """Generate and export comprehensive analysis report."""
        if not self.analysis_results:
            QMessageBox.warning(self, "Warning", "No analysis results to export")
            return

        try:
            filename, _ = QFileDialog.getSaveFileName(self, "Export Report", "traffic_analysis_report.txt", "Text files (*.txt)")

            if filename:
                if self.analyzer:
                    report_content = self.analyzer.generate_report()

                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(report_content)

                    QMessageBox.information(self, "Success", f"Report exported to {filename}")
                    log_info(f"Analysis report exported: {filename}")
                else:
                    QMessageBox.warning(self, "Warning", "Analyzer not available for report generation")

        except Exception as e:
            error_msg = f"Failed to export report: {e}"
            log_error(error_msg)
            QMessageBox.critical(self, "Export Error", error_msg)

    def _generate_visualization(self):
        """Generate traffic visualization based on selected type."""
        if not self.analysis_results:
            QMessageBox.warning(self, "Warning", "No analysis results available for visualization")
            return

        try:
            chart_type = self.chart_type_combo.currentText()

            viz_text = f"Visualization: {chart_type}\n"
            viz_text += "=" * 50 + "\n\n"

            if chart_type == "Protocol Distribution":
                if "protocol_distribution" in self.analysis_results:
                    viz_text += "Protocol Distribution Chart:\n"
                    total = sum(self.analysis_results["protocol_distribution"].values())

                    for protocol, count in self.analysis_results["protocol_distribution"].items():
                        percentage = (count / total * 100) if total > 0 else 0
                        bar = "█" * int(percentage / 2)  # Visual bar representation
                        viz_text += f"{protocol:10s} {bar} {percentage:.1f}% ({count} packets)\n"

            elif chart_type == "Traffic Over Time":
                viz_text += "Traffic over time analysis would require time-series data.\n"
                viz_text += "This feature requires additional data collection during capture.\n"

            elif chart_type == "Port Distribution":
                if "port_distribution" in self.analysis_results:
                    viz_text += "Port Distribution Chart:\n"
                    for port, count in list(self.analysis_results["port_distribution"].items())[:20]:
                        bar = "█" * min(int(count / 10), 50)
                        viz_text += f"Port {port:5d} {bar} {count} connections\n"

            elif chart_type == "License Traffic Analysis":
                if "license_analysis" in self.analysis_results:
                    license_data = self.analysis_results["license_analysis"]
                    viz_text += "License Traffic Analysis:\n"
                    viz_text += f"Total License Packets: {license_data.get('packet_count', 0)}\n"
                    viz_text += f"License Traffic %: {license_data.get('traffic_percentage', 0):.2f}%\n"
                    viz_text += f"Detected Servers: {len(license_data.get('servers', []))}\n"

            else:
                viz_text += "Advanced visualizations require matplotlib integration.\n"
                viz_text += "Consider exporting data for external visualization tools.\n"

            self.viz_display.setPlainText(viz_text)

        except Exception as e:
            error_msg = f"Visualization generation failed: {e}"
            log_error(error_msg)
            QMessageBox.critical(self, "Visualization Error", error_msg)


# Network capture management functions for main_app binding
def start_network_capture(self, interface=None, filter_str=None):
    """Start network packet capture on specified interface.

    Args:
        interface: Network interface to capture on (None for default)
        filter_str: BPF filter string for capture filtering
    """
    try:
        # Initialize traffic analyzer if not already done
        if not hasattr(self, "_traffic_analyzer"):
            self._traffic_analyzer = TrafficAnalyzer()

        # Determine interface if not specified
        if interface is None:
            # Try to get default interface
            try:
                import netifaces

                gateways = netifaces.gateways()
                if "default" in gateways and netifaces.AF_INET in gateways["default"]:
                    interface = gateways["default"][netifaces.AF_INET][1]
            except ImportError:
                # Fall back to common interface names
                import platform

                if platform.system() == "Windows":
                    interface = "Ethernet"
                else:
                    interface = "eth0"

        # Store capture settings
        self._capture_interface = interface
        self._capture_filter = filter_str
        self._capture_active = True
        self._captured_packets = []

        # Start capture in background thread
        import threading

        self._capture_thread = threading.Thread(target=self._perform_network_capture, args=(interface, filter_str), daemon=True)
        self._capture_thread.start()

        if hasattr(self, "log_message"):
            self.log_message(f"Started network capture on {interface}")

        return True

    except Exception as e:
        error_msg = f"Failed to start network capture: {e}"
        log_error(error_msg)
        if hasattr(self, "log_message"):
            self.log_message(error_msg)
        return False


def stop_network_capture(self):
    """Stop active network packet capture."""
    try:
        if hasattr(self, "_capture_active"):
            self._capture_active = False

        if hasattr(self, "_capture_thread"):
            # Wait for capture thread to finish
            self._capture_thread.join(timeout=2.0)

        captured_count = len(self._captured_packets) if hasattr(self, "_captured_packets") else 0

        if hasattr(self, "log_message"):
            self.log_message(f"Stopped network capture. Captured {captured_count} packets")

        return True

    except Exception as e:
        error_msg = f"Failed to stop network capture: {e}"
        log_error(error_msg)
        if hasattr(self, "log_message"):
            self.log_message(error_msg)
        return False


def clear_network_capture(self):
    """Clear captured network packets from memory."""
    try:
        if hasattr(self, "_captured_packets"):
            packet_count = len(self._captured_packets)
            self._captured_packets.clear()

            if hasattr(self, "log_message"):
                self.log_message(f"Cleared {packet_count} captured packets")

        return True

    except Exception as e:
        error_msg = f"Failed to clear network capture: {e}"
        log_error(error_msg)
        if hasattr(self, "log_message"):
            self.log_message(error_msg)
        return False


def _perform_network_capture(self, interface, filter_str):
    """Background thread function to perform packet capture.

    Args:
        interface: Network interface to capture on
        filter_str: BPF filter string
    """
    try:
        # Try to use scapy for packet capture
        try:
            from scapy.all import sniff, wrpcap

            def packet_handler(packet):
                """Handle captured packets."""
                if hasattr(self, "_captured_packets"):
                    self._captured_packets.append(packet)

                    # Optionally update UI with packet info
                    if hasattr(self, "update_output"):
                        packet_summary = f"Captured: {packet.summary()}"
                        self.update_output.emit(packet_summary)

            # Start packet sniffing
            sniff(
                iface=interface,
                filter=filter_str,
                prn=packet_handler,
                stop_filter=lambda x: not getattr(self, "_capture_active", False),
                store=False,
            )

        except ImportError:
            # Fall back to socket-based capture if scapy not available
            import socket

            # Create raw socket for packet capture
            if platform.system() == "Windows":
                # Windows raw socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # Linux/Unix raw socket
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

            sock.settimeout(1.0)  # 1 second timeout for checking capture_active

            while getattr(self, "_capture_active", False):
                try:
                    # Receive packet data
                    packet_data, addr = sock.recvfrom(65535)

                    # Store packet data
                    if hasattr(self, "_captured_packets"):
                        self._captured_packets.append({"data": packet_data, "address": addr, "timestamp": time.time()})

                    # Update UI if possible
                    if hasattr(self, "update_output"):
                        self.update_output.emit(f"Captured packet: {len(packet_data)} bytes")

                except socket.timeout:
                    continue
                except Exception as e:
                    if self._capture_active:
                        log_error(f"Packet capture error: {e}")
                    break

            # Clean up socket
            if platform.system() == "Windows":
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()

    except Exception as e:
        error_msg = f"Network capture thread error: {e}"
        log_error(error_msg)
        if hasattr(self, "log_message"):
            self.log_message(error_msg)
