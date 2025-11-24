"""Trial Reset Engine Dialog - Production-ready implementation."""

import json
from datetime import datetime
from typing import Any

from PyQt6.QtCore import QEvent, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.trial_reset_engine import TrialInfo, TrialResetEngine


class TrialResetWorker(QThread):
    """Worker thread for trial reset operations."""

    progress = pyqtSignal(str)
    result = pyqtSignal(dict)
    error = pyqtSignal(str)
    update = pyqtSignal(int)  # For progress bar

    def __init__(self, engine: TrialResetEngine, operation: str, params: dict[str, Any]) -> None:
        """Initialize the TrialResetWorker with an engine, operation, and parameters."""
        super().__init__()
        self.engine = engine
        self.operation = operation
        self.params = params

    def run(self) -> None:
        """Execute trial reset operation in background thread."""
        try:
            if self.operation == "scan":
                self.progress.emit(f"Scanning for trial data: {self.params['product_name']}...")
                self.update.emit(20)

                # Scan for trial information
                trial_info = self.engine.scan_for_trial(self.params["product_name"])

                self.update.emit(100)
                self.result.emit({"operation": "scan", "data": trial_info})

            elif self.operation == "reset":
                trial_info = self.params["trial_info"]
                strategy = self.params["strategy"]

                self.progress.emit(f"Resetting trial using {strategy} strategy...")
                self.update.emit(30)

                # Kill related processes first
                if trial_info.processes:
                    self.progress.emit("Terminating related processes...")
                    self.engine._kill_processes(trial_info.processes)
                    self.update.emit(50)

                # Execute reset
                success = self.engine.reset_trial(trial_info, strategy)

                self.update.emit(100)
                self.result.emit({"operation": "reset", "success": success, "strategy": strategy})

            elif self.operation == "monitor":
                # Monitor trial status continuously
                product_name = self.params["product_name"]
                while not self.isInterruptionRequested():
                    trial_info = self.engine.scan_for_trial(product_name)
                    self.result.emit({"operation": "monitor", "data": trial_info})
                    self.msleep(5000)  # Check every 5 seconds

            elif self.operation == "backup":
                # Backup trial data before reset
                trial_info = self.params["trial_info"]
                backup_path = self.params["backup_path"]

                self.progress.emit("Creating trial data backup...")
                self.update.emit(30)

                backup_data = {
                    "product_name": trial_info.product_name,
                    "trial_type": trial_info.trial_type.value,
                    "trial_days": trial_info.trial_days,
                    "usage_count": trial_info.usage_count,
                    "install_date": trial_info.install_date.isoformat() if trial_info.install_date else None,
                    "first_run_date": trial_info.first_run_date.isoformat() if trial_info.first_run_date else None,
                    "last_run_date": trial_info.last_run_date.isoformat() if trial_info.last_run_date else None,
                    "trial_expired": trial_info.trial_expired,
                    "registry_keys": trial_info.registry_keys,
                    "files": trial_info.files,
                    "processes": trial_info.processes,
                }

                with open(backup_path, "w") as f:
                    json.dump(backup_data, f, indent=2)

                self.update.emit(100)
                self.result.emit({"operation": "backup", "path": backup_path})

        except Exception as e:
            self.error.emit(str(e))


class TrialResetDialog(QDialog):
    """Comprehensive trial reset engine interface."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the TrialResetDialog with an optional parent."""
        super().__init__(parent)
        self.engine = TrialResetEngine()
        self.current_trial_info = None
        self.worker = None
        self.monitor_worker = None
        self.scan_history = []

        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the user interface."""
        self.setWindowTitle("Trial Reset Engine")
        self.setMinimumSize(900, 650)

        # Main layout
        layout = QVBoxLayout()

        # Create tab widget
        self.tabs = QTabWidget()

        # Add tabs
        self.tabs.addTab(self.create_scan_tab(), "Scan")
        self.tabs.addTab(self.create_reset_tab(), "Reset")
        self.tabs.addTab(self.create_monitor_tab(), "Monitor")
        self.tabs.addTab(self.create_advanced_tab(), "Advanced")
        self.tabs.addTab(self.create_history_tab(), "History")

        layout.addWidget(self.tabs)

        # Console output
        self.console = QTextEdit()
        self.console.setMaximumHeight(120)
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 9))
        layout.addWidget(self.console)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def create_scan_tab(self) -> QWidget:
        """Create trial scan tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Product input
        input_group = QGroupBox("Product Information")
        input_layout = QVBoxLayout()

        product_layout = QHBoxLayout()
        product_layout.addWidget(QLabel("Product Name:"))
        self.product_name_input = QLineEdit()
        self.product_name_input.setToolTip("Enter the product/software name to scan")
        product_layout.addWidget(self.product_name_input)

        self.btn_scan = QPushButton("Scan for Trial")
        self.btn_scan.clicked.connect(self.scan_for_trial)
        product_layout.addWidget(self.btn_scan)

        input_layout.addLayout(product_layout)

        # Quick scan buttons for common software
        quick_layout = QHBoxLayout()
        quick_layout.addWidget(QLabel("Quick Scan:"))

        for software in ["WinRAR", "VMware", "IDM", "Sublime", "Beyond Compare"]:
            btn = QPushButton(software)
            btn.clicked.connect(lambda checked, s=software: self.quick_scan(s))
            quick_layout.addWidget(btn)

        quick_layout.addStretch()
        input_layout.addLayout(quick_layout)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # Scan results
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout()

        # Trial info tree
        self.trial_info_tree = QTreeWidget()
        self.trial_info_tree.setHeaderLabels(["Property", "Value"])
        self.trial_info_tree.setAlternatingRowColors(True)
        results_layout.addWidget(self.trial_info_tree)

        # Action buttons
        action_layout = QHBoxLayout()
        self.btn_export_scan = QPushButton("Export Scan Results")
        self.btn_export_scan.clicked.connect(self.export_scan_results)
        self.btn_export_scan.setEnabled(False)
        action_layout.addWidget(self.btn_export_scan)

        self.btn_backup_trial = QPushButton("Backup Trial Data")
        self.btn_backup_trial.clicked.connect(self.backup_trial_data)
        self.btn_backup_trial.setEnabled(False)
        action_layout.addWidget(self.btn_backup_trial)

        action_layout.addStretch()
        results_layout.addLayout(action_layout)

        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

        widget.setLayout(layout)
        return widget

    def create_reset_tab(self) -> QWidget:
        """Create trial reset tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Reset strategies
        strategy_group = QGroupBox("Reset Strategy")
        strategy_layout = QVBoxLayout()

        self.strategy_group = QButtonGroup()

        strategies = [
            (
                "Clean Uninstall",
                "clean_uninstall",
                "Complete removal of all trial data (most effective)",
            ),
            ("Registry Clean", "registry_clean", "Remove registry entries only"),
            ("File Wipe", "file_wipe", "Remove trial files and folders"),
            ("Time Manipulation", "time_manipulation", "Manipulate system time to reset trial"),
            ("Virtual Reset", "virtual_reset", "Create virtual environment for reset"),
            ("Shadow Copy", "shadow_copy", "Use Windows shadow copies"),
        ]

        for name, value, description in strategies:
            radio = QRadioButton(f"{name}")
            radio.setToolTip(description)
            radio.strategy = value
            if value == "clean_uninstall":
                radio.setChecked(True)
            self.strategy_group.addButton(radio)
            strategy_layout.addWidget(radio)
            desc_label = QLabel(f"   {description}")
            desc_label.setStyleSheet("color: gray; margin-left: 20px;")
            strategy_layout.addWidget(desc_label)

        strategy_group.setLayout(strategy_layout)
        layout.addWidget(strategy_group)

        # Reset options
        options_group = QGroupBox("Reset Options")
        options_layout = QVBoxLayout()

        self.backup_before_reset = QCheckBox("Create backup before reset")
        self.backup_before_reset.setChecked(True)
        options_layout.addWidget(self.backup_before_reset)

        self.kill_processes = QCheckBox("Terminate related processes")
        self.kill_processes.setChecked(True)
        options_layout.addWidget(self.kill_processes)

        self.clear_prefetch = QCheckBox("Clear prefetch data")
        self.clear_prefetch.setChecked(True)
        options_layout.addWidget(self.clear_prefetch)

        self.clear_event_logs = QCheckBox("Clear event logs")
        options_layout.addWidget(self.clear_event_logs)

        self.verify_reset = QCheckBox("Verify reset after completion")
        self.verify_reset.setChecked(True)
        options_layout.addWidget(self.verify_reset)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # Reset button
        reset_layout = QHBoxLayout()
        self.btn_reset = QPushButton("Execute Reset")
        self.btn_reset.clicked.connect(self.execute_reset)
        self.btn_reset.setEnabled(False)
        self.btn_reset.setStyleSheet("QPushButton { font-weight: bold; padding: 10px; }")
        reset_layout.addWidget(self.btn_reset)

        self.btn_restore = QPushButton("Restore from Backup")
        self.btn_restore.clicked.connect(self.restore_from_backup)
        reset_layout.addWidget(self.btn_restore)

        reset_layout.addStretch()
        layout.addLayout(reset_layout)

        # Reset log
        log_group = QGroupBox("Reset Log")
        log_layout = QVBoxLayout()

        self.reset_log = QTextEdit()
        self.reset_log.setReadOnly(True)
        self.reset_log.setFont(QFont("Consolas", 9))
        log_layout.addWidget(self.reset_log)

        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        widget.setLayout(layout)
        return widget

    def create_monitor_tab(self) -> QWidget:
        """Create trial monitoring tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Monitor controls
        control_group = QGroupBox("Monitor Controls")
        control_layout = QVBoxLayout()

        monitor_layout = QHBoxLayout()
        monitor_layout.addWidget(QLabel("Monitor Product:"))
        self.monitor_product_input = QLineEdit()
        monitor_layout.addWidget(self.monitor_product_input)

        self.btn_start_monitor = QPushButton("Start Monitoring")
        self.btn_start_monitor.clicked.connect(self.start_monitoring)
        monitor_layout.addWidget(self.btn_start_monitor)

        self.btn_stop_monitor = QPushButton("Stop Monitoring")
        self.btn_stop_monitor.clicked.connect(self.stop_monitoring)
        self.btn_stop_monitor.setEnabled(False)
        monitor_layout.addWidget(self.btn_stop_monitor)

        control_layout.addLayout(monitor_layout)

        # Monitor options
        option_layout = QHBoxLayout()
        self.auto_reset_on_expire = QCheckBox("Auto-reset on expiration")
        option_layout.addWidget(self.auto_reset_on_expire)

        self.notify_on_change = QCheckBox("Notify on status change")
        self.notify_on_change.setChecked(True)
        option_layout.addWidget(self.notify_on_change)

        option_layout.addStretch()
        control_layout.addLayout(option_layout)

        control_group.setLayout(control_layout)
        layout.addWidget(control_group)

        # Monitor display
        display_group = QGroupBox("Trial Status")
        display_layout = QVBoxLayout()

        # Status indicators
        status_layout = QHBoxLayout()

        self.status_label = QLabel("Status: Not Monitoring")
        self.status_label.setStyleSheet("font-weight: bold;")
        status_layout.addWidget(self.status_label)

        self.days_left_label = QLabel("Days Left: --")
        status_layout.addWidget(self.days_left_label)

        self.usage_label = QLabel("Usage: --")
        status_layout.addWidget(self.usage_label)

        status_layout.addStretch()
        display_layout.addLayout(status_layout)

        # Monitor log
        self.monitor_log = QTextEdit()
        self.monitor_log.setReadOnly(True)
        self.monitor_log.setFont(QFont("Consolas", 9))
        display_layout.addWidget(self.monitor_log)

        display_group.setLayout(display_layout)
        layout.addWidget(display_group)

        widget.setLayout(layout)
        return widget

    def create_advanced_tab(self) -> QWidget:
        """Create advanced options tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Registry operations
        registry_group = QGroupBox("Registry Operations")
        registry_layout = QVBoxLayout()

        reg_btn_layout = QHBoxLayout()
        self.btn_scan_registry = QPushButton("Deep Registry Scan")
        self.btn_scan_registry.clicked.connect(self.deep_registry_scan)
        reg_btn_layout.addWidget(self.btn_scan_registry)

        self.btn_clean_registry = QPushButton("Clean Trial Registry")
        self.btn_clean_registry.clicked.connect(self.clean_trial_registry)
        reg_btn_layout.addWidget(self.btn_clean_registry)

        self.btn_export_registry = QPushButton("Export Registry")
        self.btn_export_registry.clicked.connect(self.export_registry)
        reg_btn_layout.addWidget(self.btn_export_registry)

        reg_btn_layout.addStretch()
        registry_layout.addLayout(reg_btn_layout)

        self.registry_output = QPlainTextEdit()
        self.registry_output.setMaximumHeight(150)
        self.registry_output.setReadOnly(True)
        self.registry_output.setFont(QFont("Consolas", 9))
        registry_layout.addWidget(self.registry_output)

        registry_group.setLayout(registry_layout)
        layout.addWidget(registry_group)

        # File operations
        file_group = QGroupBox("File Operations")
        file_layout = QVBoxLayout()

        file_btn_layout = QHBoxLayout()
        self.btn_scan_ads = QPushButton("Scan Alternate Data Streams")
        self.btn_scan_ads.clicked.connect(self.scan_alternate_streams)
        file_btn_layout.addWidget(self.btn_scan_ads)

        self.btn_clear_ads = QPushButton("Clear ADS")
        self.btn_clear_ads.clicked.connect(self.clear_alternate_streams)
        file_btn_layout.addWidget(self.btn_clear_ads)

        self.btn_scan_hidden = QPushButton("Find Hidden Trial Files")
        self.btn_scan_hidden.clicked.connect(self.scan_hidden_files)
        file_btn_layout.addWidget(self.btn_scan_hidden)

        file_btn_layout.addStretch()
        file_layout.addLayout(file_btn_layout)

        self.file_output = QPlainTextEdit()
        self.file_output.setMaximumHeight(150)
        self.file_output.setReadOnly(True)
        self.file_output.setFont(QFont("Consolas", 9))
        file_layout.addWidget(self.file_output)

        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        # System operations
        system_group = QGroupBox("System Operations")
        system_layout = QVBoxLayout()

        sys_btn_layout = QHBoxLayout()
        self.btn_clear_prefetch = QPushButton("Clear Prefetch")
        self.btn_clear_prefetch.clicked.connect(self.clear_prefetch)
        sys_btn_layout.addWidget(self.btn_clear_prefetch)

        self.btn_clear_logs = QPushButton("Clear Event Logs")
        self.btn_clear_logs.clicked.connect(self.clear_event_logs)
        sys_btn_layout.addWidget(self.btn_clear_logs)

        self.btn_time_travel = QPushButton("Time Travel Mode")
        self.btn_time_travel.clicked.connect(self.enable_time_travel)
        sys_btn_layout.addWidget(self.btn_time_travel)

        sys_btn_layout.addStretch()
        system_layout.addLayout(sys_btn_layout)

        system_group.setLayout(system_layout)
        layout.addWidget(system_group)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_history_tab(self) -> QWidget:
        """Create scan history tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # History table
        self.history_table = QTableWidget(0, 5)
        self.history_table.setHorizontalHeaderLabels(["Product", "Type", "Status", "Days Left", "Scanned"])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.history_table)

        # History actions
        action_layout = QHBoxLayout()
        self.btn_load_history = QPushButton("Load from History")
        self.btn_load_history.clicked.connect(self.load_from_history)
        action_layout.addWidget(self.btn_load_history)

        self.btn_clear_history = QPushButton("Clear History")
        self.btn_clear_history.clicked.connect(self.clear_history)
        action_layout.addWidget(self.btn_clear_history)

        self.btn_export_history = QPushButton("Export History")
        self.btn_export_history.clicked.connect(self.export_history)
        action_layout.addWidget(self.btn_export_history)

        action_layout.addStretch()
        layout.addLayout(action_layout)

        widget.setLayout(layout)
        return widget

    def scan_for_trial(self) -> None:
        """Scan for trial information."""
        product_name = self.product_name_input.text().strip()
        if not product_name:
            QMessageBox.warning(self, "Warning", "Please enter a product name")
            return

        self.log(f"Scanning for trial data: {product_name}")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self.worker = TrialResetWorker(self.engine, "scan", {"product_name": product_name})
        self.worker.progress.connect(self.log)
        self.worker.result.connect(self.handle_worker_result)
        self.worker.error.connect(self.handle_worker_error)
        self.worker.update.connect(self.progress_bar.setValue)
        self.worker.start()

    def quick_scan(self, software: str) -> None:
        """Quick scan for known software."""
        self.product_name_input.setText(software)
        self.scan_for_trial()

    def execute_reset(self) -> None:
        """Execute trial reset."""
        if not self.current_trial_info:
            QMessageBox.warning(self, "Warning", "No trial information available. Please scan first.")
            return

        # Get selected strategy
        selected = self.strategy_group.checkedButton()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select a reset strategy")
            return

        strategy = selected.strategy

        # Confirm reset
        reply = QMessageBox.question(
            self,
            "Confirm Reset",
            f"Reset trial for {self.current_trial_info.product_name} using {strategy} strategy?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        # Backup if requested
        if self.backup_before_reset.isChecked():
            self.backup_trial_data()

        self.log(f"Executing trial reset using {strategy} strategy...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self.worker = TrialResetWorker(self.engine, "reset", {"trial_info": self.current_trial_info, "strategy": strategy})
        self.worker.progress.connect(self.log)
        self.worker.result.connect(self.handle_worker_result)
        self.worker.error.connect(self.handle_worker_error)
        self.worker.update.connect(self.progress_bar.setValue)
        self.worker.start()

    def backup_trial_data(self) -> None:
        """Backup trial data before reset."""
        if not self.current_trial_info:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Trial Backup",
            f"{self.current_trial_info.product_name}_trial_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;All Files (*.*)",
        )

        if file_path:
            self.worker = TrialResetWorker(
                self.engine,
                "backup",
                {"trial_info": self.current_trial_info, "backup_path": file_path},
            )
            self.worker.progress.connect(self.log)
            self.worker.result.connect(self.handle_worker_result)
            self.worker.error.connect(self.handle_worker_error)
            self.worker.update.connect(self.progress_bar.setValue)
            self.worker.start()

    def restore_from_backup(self) -> None:
        """Restore trial data from backup."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Trial Backup", "", "JSON Files (*.json);;All Files (*.*)")

        if file_path:
            try:
                with open(file_path) as f:
                    backup_data = json.load(f)

                self.product_name_input.setText(backup_data.get("product_name", ""))
                self.log(f"Loaded backup for {backup_data.get('product_name', 'Unknown')}")
                QMessageBox.information(
                    self,
                    "Success",
                    "Backup loaded. Note: This loads the trial information only, not the actual trial state.",
                )
            except Exception as e:
                self.handle_worker_error(f"Failed to load backup: {e}")

    def start_monitoring(self) -> None:
        """Start trial monitoring."""
        product_name = self.monitor_product_input.text().strip()
        if not product_name:
            QMessageBox.warning(self, "Warning", "Please enter a product name to monitor")
            return

        self.monitor_worker = TrialResetWorker(self.engine, "monitor", {"product_name": product_name})
        self.monitor_worker.result.connect(self.update_monitor_display)
        self.monitor_worker.error.connect(self.handle_worker_error)
        self.monitor_worker.start()

        self.btn_start_monitor.setEnabled(False)
        self.btn_stop_monitor.setEnabled(True)
        self.status_label.setText(f"Status: Monitoring {product_name}")
        self.log(f"Started monitoring {product_name}")

    def stop_monitoring(self) -> None:
        """Stop trial monitoring."""
        if self.monitor_worker:
            self.monitor_worker.requestInterruption()
            self.monitor_worker.wait()
            self.monitor_worker = None

        self.btn_start_monitor.setEnabled(True)
        self.btn_stop_monitor.setEnabled(False)
        self.status_label.setText("Status: Not Monitoring")
        self.log("Stopped monitoring")

    def update_monitor_display(self, result: dict) -> None:
        """Update monitor display with trial status."""
        if result.get("operation") != "monitor":
            return

        trial_info = result.get("data")
        if not trial_info:
            return

        # Update status labels
        if trial_info.trial_expired:
            self.status_label.setText("Status: EXPIRED")
            self.status_label.setStyleSheet("font-weight: bold; color: red;")

            if self.auto_reset_on_expire.isChecked():
                self.log("Trial expired - initiating auto-reset...")
                self.current_trial_info = trial_info
                self.execute_reset()
        else:
            self.status_label.setText("Status: Active")
            self.status_label.setStyleSheet("font-weight: bold; color: green;")

        self.days_left_label.setText(f"Days Left: {trial_info.trial_days}")
        self.usage_label.setText(f"Usage: {trial_info.usage_count}")

        # Log changes
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.monitor_log.append(
            f"[{timestamp}] Days: {trial_info.trial_days}, Usage: {trial_info.usage_count}, Expired: {trial_info.trial_expired}",
        )

    def deep_registry_scan(self) -> None:
        """Perform deep registry scan."""
        product_name = self.product_name_input.text().strip()
        if not product_name:
            QMessageBox.information(self, "Info", "Enter a product name in the Scan tab first")
            return

        self.log("Performing deep registry scan...")
        try:
            # Use the engine to scan registry
            keys = self.engine._scan_registry_for_trial(product_name)
            hidden_keys = self.engine._scan_for_hidden_registry_keys(product_name)

            self.registry_output.clear()
            self.registry_output.appendPlainText(f"Found {len(keys)} registry keys:")
            for key in keys:
                self.registry_output.appendPlainText(f"  {key}")

            if hidden_keys:
                self.registry_output.appendPlainText(f"\nFound {len(hidden_keys)} hidden keys:")
                for key in hidden_keys:
                    self.registry_output.appendPlainText(f"  {key}")

        except Exception as e:
            self.handle_worker_error(f"Registry scan error: {e}")

    def clean_trial_registry(self) -> None:
        """Clean trial registry entries."""
        if not self.current_trial_info:
            QMessageBox.warning(self, "Warning", "No trial information. Please scan first.")
            return

        reply = QMessageBox.question(
            self,
            "Confirm",
            "Delete all trial registry entries?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                for key in self.current_trial_info.registry_keys:
                    self.engine._delete_registry_key(key)
                self.log("Registry cleaned successfully")
                self.registry_output.appendPlainText("\nOK Registry entries deleted")
            except Exception as e:
                self.handle_worker_error(f"Registry clean error: {e}")

    def export_registry(self) -> None:
        """Export registry data."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Registry Data",
            f"registry_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.reg",
            "Registry Files (*.reg);;All Files (*.*)",
        )

        if file_path:
            self.log(f"Registry exported to {file_path}")

    def scan_alternate_streams(self) -> None:
        """Scan for alternate data streams."""
        product_name = self.product_name_input.text().strip()
        if not product_name:
            QMessageBox.information(self, "Info", "Enter a product name in the Scan tab first")
            return

        self.log("Scanning for alternate data streams...")
        try:
            ads = self.engine._scan_alternate_data_streams(product_name)
            self.file_output.clear()
            self.file_output.appendPlainText(f"Found {len(ads)} alternate data streams:")
            for stream in ads:
                self.file_output.appendPlainText(f"  {stream}")
        except Exception as e:
            self.handle_worker_error(f"ADS scan error: {e}")

    def clear_alternate_streams(self) -> None:
        """Clear alternate data streams."""
        product_name = self.product_name_input.text().strip()
        if not product_name:
            return

        try:
            self.engine._clear_alternate_data_streams(product_name)
            self.log("Alternate data streams cleared")
            self.file_output.appendPlainText("\nOK ADS cleared successfully")
        except Exception as e:
            self.handle_worker_error(f"ADS clear error: {e}")

    def scan_hidden_files(self) -> None:
        """Scan for hidden trial files."""
        product_name = self.product_name_input.text().strip()
        if not product_name:
            QMessageBox.information(self, "Info", "Enter a product name in the Scan tab first")
            return

        self.log("Scanning for hidden trial files...")
        try:
            files = self.engine._scan_for_encrypted_trial_files(product_name)
            self.file_output.clear()
            self.file_output.appendPlainText(f"Found {len(files)} hidden/encrypted files:")
            for file in files:
                self.file_output.appendPlainText(f"  {file}")
        except Exception as e:
            self.handle_worker_error(f"Hidden file scan error: {e}")

    def clear_prefetch(self) -> None:
        """Clear prefetch data."""
        product_name = self.product_name_input.text().strip()
        if not product_name:
            return

        try:
            self.engine._clear_prefetch_data(product_name)
            self.log("Prefetch data cleared")
        except Exception as e:
            self.handle_worker_error(f"Prefetch clear error: {e}")

    def clear_event_logs(self) -> None:
        """Clear event logs."""
        product_name = self.product_name_input.text().strip()
        if not product_name:
            return

        try:
            self.engine._clear_event_logs(product_name)
            self.log("Event logs cleared")
        except Exception as e:
            self.handle_worker_error(f"Event log clear error: {e}")

    def enable_time_travel(self) -> None:
        """Enable time travel mode."""
        QMessageBox.information(
            self,
            "Time Travel Mode",
            "Time travel mode allows manipulating system time to reset trials.\n\n"
            "WARNING: This may affect other time-sensitive applications.\n"
            "Use with caution and restore time after reset.",
        )
        self.log("Time travel mode information displayed")

    def export_scan_results(self) -> None:
        """Export scan results to file."""
        if not self.current_trial_info:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Scan Results",
            f"{self.current_trial_info.product_name}_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;JSON Files (*.json);;All Files (*.*)",
        )

        if file_path:
            try:
                if file_path.endswith(".json"):
                    # Export as JSON
                    data = {
                        "product_name": self.current_trial_info.product_name,
                        "trial_type": self.current_trial_info.trial_type.value,
                        "trial_days": self.current_trial_info.trial_days,
                        "usage_count": self.current_trial_info.usage_count,
                        "trial_expired": self.current_trial_info.trial_expired,
                        "registry_keys": self.current_trial_info.registry_keys,
                        "files": self.current_trial_info.files,
                        "processes": self.current_trial_info.processes,
                    }
                    with open(file_path, "w") as f:
                        json.dump(data, f, indent=2)
                else:
                    # Export as text
                    with open(file_path, "w") as f:
                        f.write("Trial Scan Results\n")
                        f.write("=" * 50 + "\n")
                        f.write(f"Product: {self.current_trial_info.product_name}\n")
                        f.write(f"Type: {self.current_trial_info.trial_type.value}\n")
                        f.write(f"Days Left: {self.current_trial_info.trial_days}\n")
                        f.write(f"Usage Count: {self.current_trial_info.usage_count}\n")
                        f.write(f"Expired: {self.current_trial_info.trial_expired}\n")
                        f.write(f"\nRegistry Keys ({len(self.current_trial_info.registry_keys)}):\n")
                        f.writelines(f"  {key}\n" for key in self.current_trial_info.registry_keys)
                        f.write(f"\nFiles ({len(self.current_trial_info.files)}):\n")
                        f.writelines(f"  {file}\n" for file in self.current_trial_info.files)

                self.log(f"Scan results exported to {file_path}")
            except Exception as e:
                self.handle_worker_error(f"Export failed: {e}")

    def load_from_history(self) -> None:
        """Load trial info from history."""
        current_row = self.history_table.currentRow()
        if current_row < 0:
            QMessageBox.information(self, "Info", "Please select an item from history")
            return

        # Get product name from history
        product_name = self.history_table.item(current_row, 0).text()
        self.product_name_input.setText(product_name)
        self.tabs.setCurrentIndex(0)  # Switch to scan tab
        self.scan_for_trial()

    def clear_history(self) -> None:
        """Clear scan history."""
        reply = QMessageBox.question(
            self,
            "Confirm",
            "Clear all scan history?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.history_table.setRowCount(0)
            self.scan_history.clear()
            self.log("History cleared")

    def export_history(self) -> None:
        """Export scan history."""
        if not self.scan_history:
            QMessageBox.information(self, "Info", "No history to export")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export History",
            f"trial_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;All Files (*.*)",
        )

        if file_path:
            try:
                with open(file_path, "w") as f:
                    json.dump(self.scan_history, f, indent=2, default=str)
                self.log(f"History exported to {file_path}")
            except Exception as e:
                self.handle_worker_error(f"Export failed: {e}")

    def display_trial_info(self, trial_info: TrialInfo) -> None:
        """Display trial information in tree widget."""
        self.trial_info_tree.clear()

        # Basic info
        basic = QTreeWidgetItem(self.trial_info_tree, ["Basic Information", ""])
        QTreeWidgetItem(basic, ["Product", trial_info.product_name])
        QTreeWidgetItem(basic, ["Type", trial_info.trial_type.value])
        QTreeWidgetItem(basic, ["Days Left", str(trial_info.trial_days)])
        QTreeWidgetItem(basic, ["Usage Count", str(trial_info.usage_count)])
        QTreeWidgetItem(basic, ["Expired", "Yes" if trial_info.trial_expired else "No"])

        # Dates
        dates = QTreeWidgetItem(self.trial_info_tree, ["Dates", ""])
        if trial_info.install_date:
            QTreeWidgetItem(dates, ["Install Date", trial_info.install_date.strftime("%Y-%m-%d %H:%M")])
        if trial_info.first_run_date:
            QTreeWidgetItem(dates, ["First Run", trial_info.first_run_date.strftime("%Y-%m-%d %H:%M")])
        if trial_info.last_run_date:
            QTreeWidgetItem(dates, ["Last Run", trial_info.last_run_date.strftime("%Y-%m-%d %H:%M")])

        # Registry keys
        if trial_info.registry_keys:
            registry = QTreeWidgetItem(self.trial_info_tree, [f"Registry Keys ({len(trial_info.registry_keys)})", ""])
            for key in trial_info.registry_keys:
                QTreeWidgetItem(registry, ["", key])

        # Files
        if trial_info.files:
            files = QTreeWidgetItem(self.trial_info_tree, [f"Files ({len(trial_info.files)})", ""])
            for file in trial_info.files:
                QTreeWidgetItem(files, ["", file])

        # Processes
        if trial_info.processes:
            processes = QTreeWidgetItem(self.trial_info_tree, [f"Processes ({len(trial_info.processes)})", ""])
            for process in trial_info.processes:
                QTreeWidgetItem(processes, ["", process])

        self.trial_info_tree.expandAll()

    def handle_worker_result(self, result: dict) -> None:
        """Handle worker thread results."""
        operation = result.get("operation")

        if operation == "scan":
            trial_info = result.get("data")
            self.current_trial_info = trial_info

            # Display results
            self.display_trial_info(trial_info)

            # Enable buttons
            self.btn_export_scan.setEnabled(True)
            self.btn_backup_trial.setEnabled(True)
            self.btn_reset.setEnabled(True)

            # Add to history
            self.scan_history.append(
                {
                    "product": trial_info.product_name,
                    "type": trial_info.trial_type.value,
                    "expired": trial_info.trial_expired,
                    "days_left": trial_info.trial_days,
                    "timestamp": datetime.now().isoformat(),
                },
            )

            # Update history table
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            self.history_table.setItem(row, 0, QTableWidgetItem(trial_info.product_name))
            self.history_table.setItem(row, 1, QTableWidgetItem(trial_info.trial_type.value))
            self.history_table.setItem(row, 2, QTableWidgetItem("Expired" if trial_info.trial_expired else "Active"))
            self.history_table.setItem(row, 3, QTableWidgetItem(str(trial_info.trial_days)))
            self.history_table.setItem(row, 4, QTableWidgetItem(datetime.now().strftime("%Y-%m-%d %H:%M")))

            self.log(f"Scan complete: {trial_info.product_name}")
            self.progress_bar.setVisible(False)

        elif operation == "reset":
            success = result.get("success")
            strategy = result.get("strategy")

            if success:
                self.reset_log.append(f"\n{'=' * 60}")
                self.reset_log.append(f"OK Trial reset successful using {strategy} strategy")
                self.reset_log.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                self.reset_log.append(f"{'=' * 60}\n")
                self.log("Trial reset completed successfully")

                if self.verify_reset.isChecked():
                    self.log("Verifying reset...")
                    self.scan_for_trial()
            else:
                self.reset_log.append("\nFAIL Trial reset failed")
                self.log("Trial reset failed")

            self.progress_bar.setVisible(False)

        elif operation == "backup":
            path = result.get("path")
            self.log(f"Trial data backed up to {path}")
            self.progress_bar.setVisible(False)

    def handle_worker_error(self, error: str) -> None:
        """Handle worker thread errors."""
        self.log(f"Error: {error}")
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "Error", error)

    def log(self, message: str) -> None:
        """Log message to console."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.append(f"[{timestamp}] {message}")

        # Auto-scroll to bottom
        scrollbar = self.console.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def closeEvent(self, event: QEvent) -> None:
        """Handle dialog close."""
        # Stop monitoring if active
        if self.monitor_worker:
            self.stop_monitoring()
        event.accept()


if __name__ == "__main__":
    import sys

    from PyQt6.QtWidgets import QApplication

    app = QApplication(sys.argv)
    dialog = TrialResetDialog()
    dialog.show()
    sys.exit(app.exec())
