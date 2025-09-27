"""
Frida Bypass Wizard Dialog - Advanced UI for automated protection bypass
Provides comprehensive interface for the Frida Bypass Wizard with real-time monitoring
"""

import json
import os
from datetime import datetime
from typing import Optional

import psutil
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.frida_bypass_wizard import FridaBypassWizard


class FridaWorkerThread(QThread):
    """Worker thread for running Frida operations without blocking UI"""

    progress_update = pyqtSignal(str)
    status_update = pyqtSignal(str, str)  # status, color
    bypass_complete = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, wizard: FridaBypassWizard, target_process: str, mode: str, options: dict):
        super().__init__()
        self.wizard = wizard
        self.target_process = target_process
        self.mode = mode
        self.options = options
        self._stop_requested = False

    def run(self):
        """Execute the bypass operation"""
        try:
            self.status_update.emit("Starting bypass operation...", "blue")

            # Attach to target process
            self.progress_update.emit(f"Attaching to process: {self.target_process}")

            if self.target_process.isdigit():
                pid = int(self.target_process)
                success = self.wizard.attach_to_process(pid=pid)
            else:
                success = self.wizard.attach_to_process(process_name=self.target_process)

            if not success:
                raise Exception("Failed to attach to target process")

            self.progress_update.emit("Successfully attached to process")

            # Run bypass based on mode
            if self.mode == "Auto-detect & Bypass":
                self.run_auto_bypass()
            elif self.mode == "Manual Script Injection":
                self.run_manual_bypass()
            elif self.mode == "Protection Analysis":
                self.run_analysis()
            elif self.mode == "Hook Monitoring":
                self.run_hook_monitoring()

            self.status_update.emit("Bypass operation completed successfully", "green")

        except Exception as e:
            self.error_occurred.emit(str(e))
            self.status_update.emit(f"Error: {str(e)}", "red")

    def run_auto_bypass(self):
        """Run automatic protection detection and bypass"""
        self.progress_update.emit("Detecting protection mechanisms...")

        detections = self.wizard.detect_protections()

        for protection, confidence in detections.items():
            if self._stop_requested:
                break

            self.progress_update.emit(f"Found: {protection} (confidence: {confidence:.1%})")

            if confidence > 0.7:  # High confidence
                self.progress_update.emit(f"Applying bypass for {protection}...")

                # Generate and inject bypass script
                script = self.wizard.generate_bypass_script(protection)
                if script:
                    self.wizard.inject_script(script, f"{protection}_bypass")
                    self.progress_update.emit(f"Bypass injected for {protection}")

        self.progress_update.emit("Auto-bypass complete")
        self.bypass_complete.emit({"detections": detections, "mode": "auto"})

    def run_manual_bypass(self):
        """Run manual script injection"""
        script_path = self.options.get('script_path')
        if not script_path:
            raise Exception("No script path provided")

        self.progress_update.emit(f"Loading script: {script_path}")

        with open(script_path, 'r') as f:
            script_content = f.read()

        self.progress_update.emit("Injecting custom script...")
        self.wizard.inject_script(script_content, "custom_bypass")

        self.progress_update.emit("Custom script injected successfully")
        self.bypass_complete.emit({"script": script_path, "mode": "manual"})

    def run_analysis(self):
        """Run protection analysis only"""
        self.progress_update.emit("Analyzing protection mechanisms...")

        analysis = self.wizard.analyze_protections()

        for category, items in analysis.items():
            self.progress_update.emit(f"\n{category}:")
            for item in items:
                self.progress_update.emit(f"  - {item}")

        self.bypass_complete.emit({"analysis": analysis, "mode": "analysis"})

    def run_hook_monitoring(self):
        """Monitor API hooks in real-time"""
        self.progress_update.emit("Starting hook monitoring...")

        # Generate comprehensive API monitoring script
        monitor_script = """
var monitored_apis = {
    'kernel32.dll': [
        'CreateFileW', 'ReadFile', 'WriteFile', 'RegOpenKeyExW',
        'RegQueryValueExW', 'GetSystemTime', 'GetTickCount'
    ],
    'advapi32.dll': [
        'RegCreateKeyExW', 'RegSetValueExW', 'CryptAcquireContextW'
    ],
    'user32.dll': [
        'MessageBoxW', 'GetWindowTextW', 'FindWindowW'
    ],
    'ntdll.dll': [
        'NtQuerySystemInformation', 'NtCreateFile', 'NtOpenProcess'
    ]
};

var hook_count = 0;
var call_count = 0;

// Hook all monitored APIs
Object.keys(monitored_apis).forEach(function(dll) {
    monitored_apis[dll].forEach(function(api) {
        try {
            var addr = Module.findExportByName(dll, api);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        call_count++;
                        send({
                            type: 'api_call',
                            dll: dll,
                            api: api,
                            args: args.length > 0 ? args[0].toString() : 'none',
                            count: call_count,
                            timestamp: Date.now()
                        });
                    },
                    onLeave: function(retval) {
                        send({
                            type: 'api_return',
                            dll: dll,
                            api: api,
                            retval: retval.toString(),
                            timestamp: Date.now()
                        });
                    }
                });
                hook_count++;
                console.log('[+] Hooked: ' + dll + '!' + api);
            }
        } catch(e) {
            console.log('[-] Failed to hook: ' + dll + '!' + api);
        }
    });
});

// Hook license-specific patterns
var license_patterns = [
    {pattern: '*License*', module: null},
    {pattern: '*Registration*', module: null},
    {pattern: '*Activation*', module: null},
    {pattern: '*Serial*', module: null},
    {pattern: '*Trial*', module: null}
];

Process.enumerateModules().forEach(function(module) {
    module.enumerateExports().forEach(function(exp) {
        license_patterns.forEach(function(p) {
            if (exp.name.toLowerCase().includes(p.pattern.toLowerCase().replace('*', ''))) {
                try {
                    Interceptor.attach(exp.address, {
                        onEnter: function(args) {
                            send({
                                type: 'license_api',
                                module: module.name,
                                api: exp.name,
                                timestamp: Date.now()
                            });
                        }
                    });
                    hook_count++;
                } catch(e) {}
            }
        });
    });
});

send({
    type: 'monitor_started',
    hooks: hook_count,
    timestamp: Date.now()
});

// Set up periodic stats update
setInterval(function() {
    send({
        type: 'stats_update',
        hooks: hook_count,
        calls: call_count,
        timestamp: Date.now()
    });
}, 1000);
"""

        # Inject the monitoring script
        self.wizard.inject_script(monitor_script, "api_monitor")

        # Set up message handler for receiving data from script
        def on_message(message, data):
            if message['type'] == 'send':
                payload = message['payload']
                if payload['type'] == 'api_call':
                    self.progress_update.emit(f"[API] {payload['dll']}!{payload['api']} called")
                elif payload['type'] == 'api_return':
                    self.progress_update.emit(f"[RET] {payload['api']} returned: {payload['retval']}")
                elif payload['type'] == 'license_api':
                    self.progress_update.emit(f"[LICENSE] {payload['module']}!{payload['api']} detected")
                elif payload['type'] == 'stats_update':
                    self.status_update.emit(f"Hooks: {payload['hooks']} | Calls: {payload['calls']}", "blue")
                elif payload['type'] == 'monitor_started':
                    self.progress_update.emit(f"Hook monitoring active with {payload['hooks']} hooks")

        # Register message handler with Frida session
        if self.wizard.session:
            self.wizard.session.on('message', on_message)

        self.progress_update.emit("Hook monitoring active")

        # Monitor until stop is requested
        while not self._stop_requested:
            # Process Frida events and check for messages
            if self.wizard.session:
                try:
                    # Keep session alive and process callbacks
                    self.wizard.session.is_detached
                except Exception:
                    break
            self.msleep(100)

        self.progress_update.emit("Hook monitoring stopped")

    def stop(self):
        """Request the thread to stop"""
        self._stop_requested = True


class FridaBypassWizardDialog(QDialog):
    """Advanced dialog for Frida Bypass Wizard with full functionality"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.wizard = FridaBypassWizard()
        self.worker_thread = None
        self.init_ui()
        self.load_settings()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Frida Bypass Wizard - Advanced Protection Bypass")
        self.setMinimumSize(1000, 700)

        layout = QVBoxLayout(self)

        # Create main tabs
        self.tab_widget = QTabWidget()

        # Tab 1: Process Selection and Control
        self.process_tab = self.create_process_tab()
        self.tab_widget.addTab(self.process_tab, "Process Control")

        # Tab 2: Bypass Configuration
        self.config_tab = self.create_config_tab()
        self.tab_widget.addTab(self.config_tab, "Bypass Configuration")

        # Tab 3: Scripts and Templates
        self.scripts_tab = self.create_scripts_tab()
        self.tab_widget.addTab(self.scripts_tab, "Scripts & Templates")

        # Tab 4: Real-time Monitor
        self.monitor_tab = self.create_monitor_tab()
        self.tab_widget.addTab(self.monitor_tab, "Real-time Monitor")

        # Tab 5: Results and Logs
        self.results_tab = self.create_results_tab()
        self.tab_widget.addTab(self.results_tab, "Results & Logs")

        layout.addWidget(self.tab_widget)

        # Status bar at bottom
        self.create_status_bar(layout)

        # Control buttons
        self.create_control_buttons(layout)

    def create_process_tab(self) -> QWidget:
        """Create process selection and control tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Process selection group
        process_group = QGroupBox("Target Process Selection")
        process_layout = QVBoxLayout()

        # Process list
        list_layout = QHBoxLayout()
        list_layout.addWidget(QLabel("Running Processes:"))
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_process_list)
        list_layout.addStretch()
        list_layout.addWidget(self.refresh_btn)
        process_layout.addLayout(list_layout)

        # Process table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(4)
        self.process_table.setHorizontalHeaderLabels(["PID", "Name", "Path", "Status"])
        self.process_table.horizontalHeader().setStretchLastSection(True)
        self.process_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        process_layout.addWidget(self.process_table)

        # Manual input
        manual_layout = QHBoxLayout()
        manual_layout.addWidget(QLabel("Or enter manually:"))
        self.manual_process_input = QLineEdit()
        self.manual_process_input.setToolTip("Enter process name (e.g., notepad.exe) or PID (e.g., 1234)")
        self.manual_process_input.textChanged.connect(self.validate_process_input)

        # Add validation indicator
        self.input_valid_label = QLabel("✓")
        self.input_valid_label.setStyleSheet("QLabel { color: green; font-weight: bold; }")
        self.input_valid_label.setVisible(False)

        manual_layout.addWidget(self.manual_process_input)
        manual_layout.addWidget(self.input_valid_label)
        process_layout.addLayout(manual_layout)

        process_group.setLayout(process_layout)
        layout.addWidget(process_group)

        # Frida settings group
        frida_group = QGroupBox("Frida Settings")
        frida_layout = QVBoxLayout()

        # Device selection
        device_layout = QHBoxLayout()
        device_layout.addWidget(QLabel("Device:"))
        self.device_combo = QComboBox()
        self.device_combo.addItems(["Local", "USB", "Remote"])
        device_layout.addWidget(self.device_combo)
        device_layout.addStretch()
        frida_layout.addLayout(device_layout)

        # Runtime options
        self.spawn_process_check = QCheckBox("Spawn process (don't attach)")
        self.pause_on_attach_check = QCheckBox("Pause on attach")
        self.persistent_check = QCheckBox("Keep script persistent")

        frida_layout.addWidget(self.spawn_process_check)
        frida_layout.addWidget(self.pause_on_attach_check)
        frida_layout.addWidget(self.persistent_check)

        frida_group.setLayout(frida_layout)
        layout.addWidget(frida_group)

        layout.addStretch()

        # Refresh process list on init
        self.refresh_process_list()

        return tab

    def create_config_tab(self) -> QWidget:
        """Create bypass configuration tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Bypass mode selection
        mode_group = QGroupBox("Bypass Mode")
        mode_layout = QVBoxLayout()

        self.mode_combo = QComboBox()
        self.mode_combo.addItems([
            "Auto-detect & Bypass",
            "Manual Script Injection",
            "Protection Analysis",
            "Hook Monitoring",
            "Custom Workflow"
        ])
        self.mode_combo.currentTextChanged.connect(self.on_mode_changed)
        mode_layout.addWidget(self.mode_combo)

        # Mode description
        self.mode_description = QTextEdit()
        self.mode_description.setMaximumHeight(60)
        self.mode_description.setReadOnly(True)
        mode_layout.addWidget(self.mode_description)

        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)

        # Protection targets
        targets_group = QGroupBox("Protection Targets")
        targets_layout = QVBoxLayout()

        # Checkboxes for different protections
        self.protection_checks = {}
        protections = [
            "License Validation", "Hardware ID", "Trial Expiration",
            "Online Activation", "Anti-Debug", "Integrity Checks",
            "DRM Systems", "Network License", "Dongles"
        ]

        for protection in protections:
            check = QCheckBox(protection)
            check.setChecked(True)  # Default all enabled
            self.protection_checks[protection] = check
            targets_layout.addWidget(check)

        targets_group.setLayout(targets_layout)
        layout.addWidget(targets_group)

        # Advanced options
        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QVBoxLayout()

        # Timing options
        timing_layout = QHBoxLayout()
        timing_layout.addWidget(QLabel("Hook delay (ms):"))
        self.hook_delay_spin = QSpinBox()
        self.hook_delay_spin.setRange(0, 5000)
        self.hook_delay_spin.setValue(100)
        timing_layout.addWidget(self.hook_delay_spin)
        timing_layout.addStretch()
        advanced_layout.addLayout(timing_layout)

        # Bypass options
        self.aggressive_check = QCheckBox("Aggressive bypass (may cause instability)")
        self.stealth_check = QCheckBox("Stealth mode (avoid detection)")
        self.log_api_check = QCheckBox("Log all API calls")

        advanced_layout.addWidget(self.aggressive_check)
        advanced_layout.addWidget(self.stealth_check)
        advanced_layout.addWidget(self.log_api_check)

        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)

        layout.addStretch()

        # Set initial mode description
        self.on_mode_changed(self.mode_combo.currentText())

        return tab

    def create_scripts_tab(self) -> QWidget:
        """Create scripts and templates tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Split view
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Script templates
        templates_widget = QWidget()
        templates_layout = QVBoxLayout(templates_widget)

        templates_layout.addWidget(QLabel("Script Templates:"))

        self.template_list = QListWidget()
        self.load_script_templates()
        self.template_list.itemClicked.connect(self.on_template_selected)
        templates_layout.addWidget(self.template_list)

        # Template buttons
        template_btn_layout = QHBoxLayout()
        self.load_template_btn = QPushButton("Load")
        self.save_template_btn = QPushButton("Save As")
        template_btn_layout.addWidget(self.load_template_btn)
        template_btn_layout.addWidget(self.save_template_btn)
        templates_layout.addLayout(template_btn_layout)

        splitter.addWidget(templates_widget)

        # Right: Script editor
        editor_widget = QWidget()
        editor_layout = QVBoxLayout(editor_widget)

        editor_layout.addWidget(QLabel("Script Editor:"))

        self.script_editor = QTextEdit()
        self.script_editor.setFont(QFont("Consolas", 10))
        editor_layout.addWidget(self.script_editor)

        # Editor buttons
        editor_btn_layout = QHBoxLayout()
        self.validate_btn = QPushButton("Validate")
        self.test_btn = QPushButton("Test")
        self.inject_btn = QPushButton("Inject")

        self.validate_btn.clicked.connect(self.validate_script)
        self.test_btn.clicked.connect(self.test_script)
        self.inject_btn.clicked.connect(self.inject_script)

        editor_btn_layout.addWidget(self.validate_btn)
        editor_btn_layout.addWidget(self.test_btn)
        editor_btn_layout.addWidget(self.inject_btn)
        editor_layout.addLayout(editor_btn_layout)

        splitter.addWidget(editor_widget)

        layout.addWidget(splitter)

        return tab

    def create_monitor_tab(self) -> QWidget:
        """Create real-time monitoring tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Monitor controls
        control_layout = QHBoxLayout()
        self.monitor_start_btn = QPushButton("Start Monitoring")
        self.monitor_stop_btn = QPushButton("Stop Monitoring")
        self.monitor_clear_btn = QPushButton("Clear")

        self.monitor_start_btn.clicked.connect(self.start_monitoring)
        self.monitor_stop_btn.clicked.connect(self.stop_monitoring)
        self.monitor_clear_btn.clicked.connect(self.clear_monitor)

        self.monitor_stop_btn.setEnabled(False)

        control_layout.addWidget(self.monitor_start_btn)
        control_layout.addWidget(self.monitor_stop_btn)
        control_layout.addWidget(self.monitor_clear_btn)
        control_layout.addStretch()

        # Filter controls
        control_layout.addWidget(QLabel("Filter:"))
        self.monitor_filter = QLineEdit()
        self.monitor_filter.setToolTip("Filter by API name, module, or keyword")
        self.monitor_filter_label = QLabel("e.g., CreateFile, kernel32, license")
        self.monitor_filter_label.setStyleSheet("QLabel { color: gray; font-size: 9pt; }")
        self.monitor_filter.textChanged.connect(self.apply_monitor_filter)
        control_layout.addWidget(self.monitor_filter)
        control_layout.addWidget(self.monitor_filter_label)

        layout.addLayout(control_layout)

        # Monitor output
        self.monitor_output = QTextEdit()
        self.monitor_output.setReadOnly(True)
        self.monitor_output.setFont(QFont("Consolas", 9))
        layout.addWidget(self.monitor_output)

        # Statistics
        stats_group = QGroupBox("Statistics")
        stats_layout = QHBoxLayout()

        self.api_calls_label = QLabel("API Calls: 0")
        self.hooks_active_label = QLabel("Active Hooks: 0")
        self.bypasses_applied_label = QLabel("Bypasses Applied: 0")

        stats_layout.addWidget(self.api_calls_label)
        stats_layout.addWidget(self.hooks_active_label)
        stats_layout.addWidget(self.bypasses_applied_label)
        stats_layout.addStretch()

        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)

        return tab

    def create_results_tab(self) -> QWidget:
        """Create results and logs tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Results summary
        summary_group = QGroupBox("Bypass Summary")
        summary_layout = QVBoxLayout()

        self.summary_text = QTextEdit()
        self.summary_text.setMaximumHeight(150)
        self.summary_text.setReadOnly(True)
        summary_layout.addWidget(self.summary_text)

        summary_group.setLayout(summary_layout)
        layout.addWidget(summary_group)

        # Detailed logs
        logs_group = QGroupBox("Detailed Logs")
        logs_layout = QVBoxLayout()

        # Log controls
        log_control_layout = QHBoxLayout()
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["All", "Info", "Warning", "Error"])
        log_control_layout.addWidget(QLabel("Log Level:"))
        log_control_layout.addWidget(self.log_level_combo)

        self.export_logs_btn = QPushButton("Export Logs")
        self.export_logs_btn.clicked.connect(self.export_logs)
        log_control_layout.addStretch()
        log_control_layout.addWidget(self.export_logs_btn)

        logs_layout.addLayout(log_control_layout)

        # Log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFont(QFont("Consolas", 9))
        logs_layout.addWidget(self.log_output)

        logs_group.setLayout(logs_layout)
        layout.addWidget(logs_group)

        return tab

    def create_status_bar(self, parent_layout):
        """Create status bar"""
        status_layout = QHBoxLayout()

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("QLabel { padding: 5px; }")
        status_layout.addWidget(self.status_label)

        status_layout.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        status_layout.addWidget(self.progress_bar)

        parent_layout.addLayout(status_layout)

    def create_control_buttons(self, parent_layout):
        """Create main control buttons"""
        button_layout = QHBoxLayout()

        self.start_btn = QPushButton("Start Bypass")
        self.start_btn.clicked.connect(self.start_bypass)
        self.start_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 8px; }")

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_bypass)
        self.stop_btn.setEnabled(False)

        self.save_config_btn = QPushButton("Save Configuration")
        self.save_config_btn.clicked.connect(self.save_configuration)

        self.load_config_btn = QPushButton("Load Configuration")
        self.load_config_btn.clicked.connect(self.load_configuration)

        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.save_config_btn)
        button_layout.addWidget(self.load_config_btn)

        parent_layout.addLayout(button_layout)

    def refresh_process_list(self):
        """Refresh the list of running processes"""
        self.process_table.setRowCount(0)

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                row = self.process_table.rowCount()
                self.process_table.insertRow(row)

                self.process_table.setItem(row, 0, QTableWidgetItem(str(proc.info['pid'])))
                self.process_table.setItem(row, 1, QTableWidgetItem(proc.info['name']))
                self.process_table.setItem(row, 2, QTableWidgetItem(proc.info['exe'] or ""))
                self.process_table.setItem(row, 3, QTableWidgetItem("Running"))

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def on_mode_changed(self, mode):
        """Update description when mode changes"""
        descriptions = {
            "Auto-detect & Bypass": "Automatically detects protection mechanisms and applies appropriate bypasses",
            "Manual Script Injection": "Inject custom Frida scripts for specific bypass requirements",
            "Protection Analysis": "Analyze the target for protection mechanisms without applying bypasses",
            "Hook Monitoring": "Monitor API calls and hooks in real-time",
            "Custom Workflow": "Create custom bypass workflow with multiple steps"
        }

        self.mode_description.setText(descriptions.get(mode, ""))

    def load_script_templates(self):
        """Load available script templates"""
        templates = [
            "Generic License Bypass",
            "Hardware ID Spoofer",
            "Trial Reset",
            "Anti-Debug Bypass",
            "Network License Emulator",
            "Steam API Hooks",
            "Denuvo Triggers",
            "VMProtect Analyzer",
            "Custom Template"
        ]

        self.template_list.addItems(templates)

    def on_template_selected(self, item):
        """Load selected template into editor"""
        template_name = item.text()

        # Load template content based on selection
        templates = {
            "Generic License Bypass": self.get_generic_bypass_template(),
            "Hardware ID Spoofer": self.get_hwid_template(),
            "Trial Reset": self.get_trial_reset_template(),
            "Anti-Debug Bypass": self.get_antidebug_template(),
            "Network License Emulator": self.get_network_license_template(),
            "Steam API Hooks": self.get_steam_api_template(),
            "Denuvo Triggers": self.get_denuvo_template(),
            "VMProtect Analyzer": self.get_vmprotect_template(),
            "Custom Template": self.get_custom_template()
        }

        content = templates.get(template_name, "// Custom template\n")
        self.script_editor.setText(content)

    def get_generic_bypass_template(self):
        """Get generic license bypass template"""
        return """// Generic License Bypass Template
// Hooks common license validation functions

// Hook license check function
Interceptor.attach(Module.findExportByName(null, "CheckLicense"), {
    onLeave: function(retval) {
        console.log("[*] License check intercepted");
        retval.replace(1); // Return success
    }
});

// Hook registration validation
Interceptor.attach(Module.findExportByName(null, "IsRegistered"), {
    onLeave: function(retval) {
        console.log("[*] Registration check bypassed");
        retval.replace(1);
    }
});

console.log("[+] Generic license bypass active");
"""

    def get_hwid_template(self):
        """Get hardware ID spoofing template"""
        return """// Hardware ID Spoofing Template
// Spoofs various hardware identifiers

// Spoof volume serial
Interceptor.attach(Module.findExportByName("kernel32.dll", "GetVolumeInformationW"), {
    onEnter: function(args) {
        this.serialPtr = args[4];
    },
    onLeave: function(retval) {
        if (this.serialPtr) {
            Memory.writeU32(this.serialPtr, 0x12345678);
            console.log("[*] Volume serial spoofed");
        }
    }
});

// Spoof MAC address
Interceptor.attach(Module.findExportByName("iphlpapi.dll", "GetAdaptersInfo"), {
    onLeave: function(retval) {
        console.log("[*] MAC address spoofed");
        // Modify adapter info in memory
    }
});

console.log("[+] Hardware ID spoofing active");
"""

    def get_trial_reset_template(self):
        """Get trial reset template"""
        return """// Trial Reset Template
// Resets trial period and removes time restrictions

// Hook time functions
var GetSystemTime = Module.findExportByName("kernel32.dll", "GetSystemTime");
Interceptor.attach(GetSystemTime, {
    onEnter: function(args) {
        this.timePtr = args[0];
    },
    onLeave: function(retval) {
        if (this.timePtr) {
            // Set to specific date
            Memory.writeU16(this.timePtr, 2024);      // Year
            Memory.writeU16(this.timePtr.add(2), 1);  // Month
            Memory.writeU16(this.timePtr.add(6), 1);  // Day
            console.log("[*] System time spoofed");
        }
    }
});

// Clear trial data from registry
// Add registry manipulation code here

console.log("[+] Trial reset active");
"""

    def get_antidebug_template(self):
        """Get anti-debugging bypass template"""
        return """// Anti-Debug Bypass Template
// Bypasses common anti-debugging techniques

// Hook IsDebuggerPresent
Interceptor.attach(Module.findExportByName("kernel32.dll", "IsDebuggerPresent"), {
    onLeave: function(retval) {
        console.log("[*] IsDebuggerPresent hooked");
        retval.replace(0); // Not being debugged
    }
});

// Hook CheckRemoteDebuggerPresent
Interceptor.attach(Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent"), {
    onEnter: function(args) {
        this.pbDebuggerPresent = args[1];
    },
    onLeave: function(retval) {
        console.log("[*] CheckRemoteDebuggerPresent hooked");
        if (this.pbDebuggerPresent) {
            Memory.writeU8(this.pbDebuggerPresent, 0);
        }
        retval.replace(1); // Success
    }
});

// Hook NtQueryInformationProcess
var ntdll = Process.getModuleByName("ntdll.dll");
var NtQueryInformationProcess = Module.findExportByName("ntdll.dll", "NtQueryInformationProcess");
Interceptor.attach(NtQueryInformationProcess, {
    onEnter: function(args) {
        this.ProcessInformationClass = args[1].toInt32();
        this.ProcessInformation = args[2];
    },
    onLeave: function(retval) {
        if (this.ProcessInformationClass === 7) { // ProcessDebugPort
            console.log("[*] ProcessDebugPort query intercepted");
            Memory.writeU32(this.ProcessInformation, 0);
        } else if (this.ProcessInformationClass === 0x1E) { // ProcessDebugObjectHandle
            console.log("[*] ProcessDebugObjectHandle query intercepted");
            Memory.writePointer(this.ProcessInformation, ptr(0));
        }
    }
});

console.log("[+] Anti-debug bypass active");
"""

    def get_network_license_template(self):
        """Get network license emulator template"""
        return """// Network License Emulator Template
// Emulates network license server responses

// Hook connect to intercept license server connections
Interceptor.attach(Module.findExportByName("ws2_32.dll", "connect"), {
    onEnter: function(args) {
        var sockfd = args[0].toInt32();
        var addr = args[1];

        // Read port from sockaddr
        var port = Memory.readU16(addr.add(2));
        port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);

        console.log("[*] Connect to port: " + port);

        // Common license server ports
        if (port === 27000 || port === 27001 || port === 1947) {
            console.log("[*] License server connection detected");
            this.isLicenseServer = true;
        }
    },
    onLeave: function(retval) {
        if (this.isLicenseServer) {
            console.log("[*] Simulating successful connection");
            retval.replace(0); // Success
        }
    }
});

// Hook recv to inject license responses
Interceptor.attach(Module.findExportByName("ws2_32.dll", "recv"), {
    onEnter: function(args) {
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave: function(retval) {
        if (this.buf && retval.toInt32() <= 0) {
            // Inject fake license response
            var licenseResponse = [
                0x01, 0x00, 0x00, 0x00,  // Valid license
                0xFF, 0xFF, 0xFF, 0x7F,  // Expiration (far future)
            ];

            for (var i = 0; i < Math.min(licenseResponse.length, this.len); i++) {
                Memory.writeU8(this.buf.add(i), licenseResponse[i]);
            }

            retval.replace(licenseResponse.length);
            console.log("[*] Injected license response");
        }
    }
});

console.log("[+] Network license emulator active");
"""

    def get_steam_api_template(self):
        """Get Steam API hooks template"""
        return """// Steam API Hooks Template
// Hooks Steam DRM and ownership checks

// Hook SteamAPI_Init
var steamapi = Process.getModuleByName("steam_api.dll") || Process.getModuleByName("steam_api64.dll");
if (steamapi) {
    var SteamAPI_Init = Module.findExportByName(steamapi.name, "SteamAPI_Init");
    if (SteamAPI_Init) {
        Interceptor.attach(SteamAPI_Init, {
            onLeave: function(retval) {
                console.log("[*] SteamAPI_Init hooked - returning success");
                retval.replace(1); // Initialized successfully
            }
        });
    }

    // Hook SteamAPI_RestartAppIfNecessary
    var RestartApp = Module.findExportByName(steamapi.name, "SteamAPI_RestartAppIfNecessary");
    if (RestartApp) {
        Interceptor.attach(RestartApp, {
            onEnter: function(args) {
                this.appId = args[0].toInt32();
                console.log("[*] App ID: " + this.appId);
            },
            onLeave: function(retval) {
                console.log("[*] Preventing Steam restart check");
                retval.replace(0); // Don't need to restart
            }
        });
    }

    // Hook SteamAPI_IsSteamRunning
    var IsSteamRunning = Module.findExportByName(steamapi.name, "SteamAPI_IsSteamRunning");
    if (IsSteamRunning) {
        Interceptor.attach(IsSteamRunning, {
            onLeave: function(retval) {
                console.log("[*] Simulating Steam is running");
                retval.replace(1); // Steam is running
            }
        });
    }
}

console.log("[+] Steam API hooks active");
"""

    def get_denuvo_template(self):
        """Get Denuvo trigger bypass template"""
        return """// Denuvo Trigger Bypass Template
// Attempts to identify and bypass Denuvo triggers

console.warn("[!] Denuvo detected - This is an advanced protection!");

// Monitor CPUID usage (common in Denuvo)
Process.setExceptionHandler(function(details) {
    if (details.type === 'illegal-instruction') {
        var bytes = Memory.readByteArray(details.address, 2);
        var view = new Uint8Array(bytes);

        // Check for CPUID instruction (0F A2)
        if (view[0] === 0x0F && view[1] === 0xA2) {
            console.log("[*] CPUID intercepted at: " + details.address);

            // Set fake CPUID results
            details.context.rax = ptr(0x12345678);
            details.context.rbx = ptr(0x87654321);
            details.context.rcx = ptr(0xABCDEF00);
            details.context.rdx = ptr(0xFEDCBA00);

            // Skip the CPUID instruction
            details.context.rip = details.address.add(2);

            return true; // Handled
        }
    }
    return false;
});

// Hook GetTickCount for timing checks
Interceptor.attach(Module.findExportByName("kernel32.dll", "GetTickCount"), {
    onLeave: function(retval) {
        // Return consistent tick count
        retval.replace(0x10000000);
    }
});

// Hook GetSystemTimeAsFileTime for date checks
Interceptor.attach(Module.findExportByName("kernel32.dll", "GetSystemTimeAsFileTime"), {
    onEnter: function(args) {
        this.timePtr = args[0];
    },
    onLeave: function(retval) {
        if (this.timePtr) {
            // Set to fixed date (Jan 1, 2024)
            Memory.writeU64(this.timePtr, ptr("0x01DA5E3C96C30000"));
        }
    }
});

console.log("[+] Denuvo bypass hooks active");
console.log("[!] Note: Full Denuvo bypass requires extensive analysis");
"""

    def get_vmprotect_template(self):
        """Get VMProtect analysis template"""
        return """// VMProtect Analysis Template
// Helps analyze VMProtect protected binaries

console.warn("[!] VMProtect detected - Extreme protection!");

// Look for VMProtect SDK functions
var vmprotect_apis = [
    "VMProtectBegin",
    "VMProtectEnd",
    "VMProtectIsDebuggerPresent",
    "VMProtectIsVirtualMachinePresent",
    "VMProtectGetSerialNumberState",
    "VMProtectSetSerialNumber"
];

vmprotect_apis.forEach(function(api) {
    var addr = Module.findExportByName(null, api);
    if (addr) {
        console.log("[*] Found VMProtect API: " + api + " at " + addr);

        Interceptor.attach(addr, {
            onEnter: function(args) {
                console.log("[VMProtect] " + api + " called");
            },
            onLeave: function(retval) {
                if (api.includes("Present")) {
                    console.log("[VMProtect] Returning false for: " + api);
                    retval.replace(0); // Not present
                } else if (api === "VMProtectGetSerialNumberState") {
                    console.log("[VMProtect] Returning valid serial state");
                    retval.replace(0); // Serial is valid
                }
            }
        });
    }
});

// Detect VMProtect sections
Process.enumerateModules().forEach(function(module) {
    if (module === Process.enumerateModules()[0]) {
        console.log("[VMProtect] Analyzing main module: " + module.name);

        // Look for .vmp sections
        Process.enumerateRanges({
            protection: 'r-x',
            coalesce: false
        }).forEach(function(range) {
            if (range.base.compare(module.base) >= 0 &&
                range.base.compare(module.base.add(module.size)) < 0) {

                // Check for VM handler patterns
                var sample = Memory.readByteArray(range.base, Math.min(range.size, 256));
                var view = new Uint8Array(sample);

                // Look for high entropy (sign of virtualization)
                var entropy = 0;
                var freq = {};
                for (var i = 0; i < view.length; i++) {
                    freq[view[i]] = (freq[view[i]] || 0) + 1;
                }

                for (var byte in freq) {
                    var p = freq[byte] / view.length;
                    entropy -= p * Math.log2(p);
                }

                if (entropy > 7.0) {
                    console.log("[VMProtect] High entropy section at: " + range.base + " (likely virtualized)");
                }
            }
        });
    }
});

console.log("[+] VMProtect analyzer active");
"""

    def get_custom_template(self):
        """Get custom template"""
        return """// Custom Frida Script Template
// Add your custom bypass code here

// Example: Hook a specific function by pattern
var targetModule = Process.enumerateModules()[0]; // Main module

// Search for patterns in memory
Memory.scan(targetModule.base, targetModule.size, "48 89 5C 24 ?? 48 89 74 24", {
    onMatch: function(address, size) {
        console.log("[*] Found pattern at: " + address);

        // Hook the found address
        Interceptor.attach(address, {
            onEnter: function(args) {
                console.log("[*] Function called with args:");
                for (var i = 0; i < 4; i++) {
                    if (args[i]) {
                        console.log("  arg[" + i + "]: " + args[i]);
                    }
                }
            },
            onLeave: function(retval) {
                console.log("[*] Function returned: " + retval);
                // Modify return value if needed
                // retval.replace(1);
            }
        });
    },
    onError: function(reason) {
        console.error("[!] Scan failed: " + reason);
    }
});

// Hook by export name
var exports = Module.enumerateExports(targetModule.name);
exports.forEach(function(exp) {
    if (exp.name.toLowerCase().includes("license") ||
        exp.name.toLowerCase().includes("check") ||
        exp.name.toLowerCase().includes("valid")) {

        console.log("[*] Hooking suspicious export: " + exp.name);

        Interceptor.attach(exp.address, {
            onEnter: function(args) {
                console.log("[*] " + exp.name + " called");
            },
            onLeave: function(retval) {
                // Analyze and potentially modify return value
            }
        });
    }
});

console.log("[+] Custom script loaded");
"""

    def validate_process_input(self, text):
        """Validate the manually entered process input"""
        if not text:
            self.input_valid_label.setVisible(False)
            return

        # Check if it's a valid PID
        if text.isdigit():
            pid = int(text)
            # Check if process exists
            if psutil.pid_exists(pid):
                self.input_valid_label.setText("✓")
                self.input_valid_label.setStyleSheet("QLabel { color: green; font-weight: bold; }")
                self.input_valid_label.setVisible(True)
            else:
                self.input_valid_label.setText("✗")
                self.input_valid_label.setStyleSheet("QLabel { color: red; font-weight: bold; }")
                self.input_valid_label.setVisible(True)
        else:
            # Check if it's a valid process name
            found = False
            for proc in psutil.process_iter(['name']):
                try:
                    if text.lower() in proc.info['name'].lower():
                        found = True
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if found:
                self.input_valid_label.setText("✓")
                self.input_valid_label.setStyleSheet("QLabel { color: green; font-weight: bold; }")
                self.input_valid_label.setVisible(True)
            else:
                self.input_valid_label.setText("✗")
                self.input_valid_label.setStyleSheet("QLabel { color: red; font-weight: bold; }")
                self.input_valid_label.setVisible(True)

    def validate_script(self):
        """Validate the current script"""
        script = self.script_editor.toPlainText()

        if not script:
            QMessageBox.warning(self, "Warning", "No script to validate")
            return

        # Basic validation
        if "Interceptor" not in script and "Java.perform" not in script:
            QMessageBox.warning(self, "Warning", "Script doesn't appear to contain Frida code")
            return

        QMessageBox.information(self, "Validation", "Script appears valid")

    def test_script(self):
        """Test the current script"""
        script = self.script_editor.toPlainText()
        if not script:
            QMessageBox.warning(self, "Warning", "No script to test")
            return

        target = self.get_selected_process()
        if not target:
            QMessageBox.warning(self, "Warning", "No target process selected")
            return

        # Create test wrapper for the script
        test_wrapper = f"""
// Test wrapper - will auto-detach after 5 seconds
var test_start = Date.now();
console.log("[TEST] Starting script test...");

{script}

setTimeout(function() {{
    console.log("[TEST] Test completed - detaching");
    send({{type: 'test_complete', duration: Date.now() - test_start}});
}}, 5000);
"""

        try:
            # Attach and inject test script
            if target.isdigit():
                self.wizard.attach_to_process(pid=int(target))
            else:
                self.wizard.attach_to_process(process_name=target)

            self.wizard.inject_script(test_wrapper, "test_script")

            def on_test_message(message, data):
                if message['type'] == 'send' and message['payload'].get('type') == 'test_complete':
                    duration = message['payload']['duration']
                    QMessageBox.information(self, "Test Complete",
                        f"Script executed successfully\nDuration: {duration}ms\n\nCheck monitor output for details")
                    self.wizard.detach()

            if self.wizard.session:
                self.wizard.session.on('message', on_test_message)

            self.log_message("Test script injected - will auto-detach in 5 seconds", "blue")

        except Exception as e:
            QMessageBox.critical(self, "Test Failed", f"Script test failed: {str(e)}")
            self.log_message(f"Test failed: {str(e)}", "red")

    def inject_script(self):
        """Inject the current script"""
        script = self.script_editor.toPlainText()

        if not script:
            QMessageBox.warning(self, "Warning", "No script to inject")
            return

        # Get selected process
        target = self.get_selected_process()
        if not target:
            QMessageBox.warning(self, "Warning", "No target process selected")
            return

        # Inject script
        try:
            if target.isdigit():
                self.wizard.attach_to_process(pid=int(target))
            else:
                self.wizard.attach_to_process(process_name=target)

            self.wizard.inject_script(script, "manual_injection")

            self.log_message("Script injected successfully", "green")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to inject script: {str(e)}")

    def start_monitoring(self):
        """Start real-time monitoring"""
        target = self.get_selected_process()
        if not target:
            QMessageBox.warning(self, "Warning", "No target process selected")
            return

        self.monitor_start_btn.setEnabled(False)
        self.monitor_stop_btn.setEnabled(True)

        # Start monitoring in worker thread
        self.log_message("Starting API monitoring...", "blue")

    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitor_start_btn.setEnabled(True)
        self.monitor_stop_btn.setEnabled(False)

        self.log_message("Monitoring stopped", "orange")

    def clear_monitor(self):
        """Clear monitor output"""
        self.monitor_output.clear()

    def apply_monitor_filter(self, filter_text):
        """Apply filter to monitor output"""
        if not filter_text:
            # Show all content
            self.monitor_output.setPlainText(self.monitor_output.toPlainText())
            return

        # Filter the monitor output
        all_text = self.monitor_output.toPlainText()
        lines = all_text.split('\n')
        filtered_lines = []

        filter_lower = filter_text.lower()
        for line in lines:
            if filter_lower in line.lower():
                filtered_lines.append(line)

        # Update display with filtered content
        self.monitor_output.clear()
        for line in filtered_lines:
            self.monitor_output.append(line)

    def start_bypass(self):
        """Start the bypass operation"""
        target = self.get_selected_process()
        if not target:
            QMessageBox.warning(self, "Warning", "No target process selected")
            return

        # Disable start button, enable stop
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)

        # Get selected options
        mode = self.mode_combo.currentText()
        options = self.get_bypass_options()

        # Create and start worker thread
        self.worker_thread = FridaWorkerThread(self.wizard, target, mode, options)
        self.worker_thread.progress_update.connect(self.on_progress_update)
        self.worker_thread.status_update.connect(self.on_status_update)
        self.worker_thread.bypass_complete.connect(self.on_bypass_complete)
        self.worker_thread.error_occurred.connect(self.on_error)

        self.worker_thread.start()

        self.log_message(f"Starting bypass operation in {mode} mode", "blue")

    def stop_bypass(self):
        """Stop the bypass operation"""
        if self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.stop()
            self.worker_thread.wait()

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)

        self.log_message("Bypass operation stopped", "orange")

    def get_selected_process(self) -> Optional[str]:
        """Get the selected target process"""
        # Check manual input first
        if self.manual_process_input.text():
            return self.manual_process_input.text()

        # Check table selection
        selected = self.process_table.selectedItems()
        if selected:
            row = selected[0].row()
            return self.process_table.item(row, 0).text()  # Return PID

        return None

    def get_bypass_options(self) -> dict:
        """Get current bypass options"""
        return {
            'protections': [name for name, check in self.protection_checks.items() if check.isChecked()],
            'aggressive': self.aggressive_check.isChecked(),
            'stealth': self.stealth_check.isChecked(),
            'log_api': self.log_api_check.isChecked(),
            'hook_delay': self.hook_delay_spin.value(),
            'spawn': self.spawn_process_check.isChecked(),
            'pause': self.pause_on_attach_check.isChecked(),
            'persistent': self.persistent_check.isChecked()
        }

    def on_progress_update(self, message):
        """Handle progress updates from worker thread"""
        self.log_message(message)
        self.monitor_output.append(message)

    def on_status_update(self, status, color):
        """Handle status updates from worker thread"""
        self.status_label.setText(status)
        self.status_label.setStyleSheet(f"QLabel {{ padding: 5px; color: {color}; }}")

    def on_bypass_complete(self, results):
        """Handle bypass completion"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)

        # Update summary
        summary = "Bypass completed successfully\n"
        summary += f"Mode: {results.get('mode', 'Unknown')}\n"

        if 'detections' in results:
            summary += f"Protections found: {len(results['detections'])}\n"
            for protection, confidence in results['detections'].items():
                summary += f"  - {protection}: {confidence:.1%} confidence\n"

        self.summary_text.setText(summary)

        self.log_message("Bypass operation completed successfully", "green")

    def on_error(self, error_msg):
        """Handle errors from worker thread"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)

        QMessageBox.critical(self, "Bypass Error", error_msg)
        self.log_message(f"Error: {error_msg}", "red")

    def log_message(self, message, color="black"):
        """Add message to log output"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}"

        cursor = self.log_output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        format = cursor.charFormat()
        format.setForeground(QColor(color))
        cursor.setCharFormat(format)

        cursor.insertText(formatted_msg + "\n")
        self.log_output.setTextCursor(cursor)

    def save_configuration(self):
        """Save current configuration to file"""
        config = {
            'mode': self.mode_combo.currentText(),
            'protections': [name for name, check in self.protection_checks.items() if check.isChecked()],
            'options': self.get_bypass_options(),
            'script': self.script_editor.toPlainText()
        }

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Configuration", "", "JSON Files (*.json)"
        )

        if file_path:
            with open(file_path, 'w') as f:
                json.dump(config, f, indent=2)

            QMessageBox.information(self, "Success", "Configuration saved successfully")

    def load_configuration(self):
        """Load configuration from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Configuration", "", "JSON Files (*.json)"
        )

        if file_path:
            with open(file_path, 'r') as f:
                config = json.load(f)

            # Apply configuration
            self.mode_combo.setCurrentText(config.get('mode', ''))

            for name, check in self.protection_checks.items():
                check.setChecked(name in config.get('protections', []))

            if 'script' in config:
                self.script_editor.setText(config['script'])

            QMessageBox.information(self, "Success", "Configuration loaded successfully")

    def export_logs(self):
        """Export logs to file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Logs", f"frida_bypass_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            "Log Files (*.log);;Text Files (*.txt)"
        )

        if file_path:
            with open(file_path, 'w') as f:
                f.write(self.log_output.toPlainText())

            QMessageBox.information(self, "Success", "Logs exported successfully")

    def load_settings(self):
        """Load saved settings"""
        import json
        settings_file = os.path.join(os.path.expanduser("~"), ".intellicrack", "frida_wizard_settings.json")

        if os.path.exists(settings_file):
            try:
                with open(settings_file, 'r') as f:
                    settings = json.load(f)

                # Apply loaded settings
                if 'device' in settings:
                    index = self.device_combo.findText(settings['device'])
                    if index >= 0:
                        self.device_combo.setCurrentIndex(index)

                if 'mode' in settings:
                    index = self.mode_combo.findText(settings['mode'])
                    if index >= 0:
                        self.mode_combo.setCurrentIndex(index)

                if 'spawn_process' in settings:
                    self.spawn_process_check.setChecked(settings['spawn_process'])

                if 'pause_on_attach' in settings:
                    self.pause_on_attach_check.setChecked(settings['pause_on_attach'])

                if 'persistent' in settings:
                    self.persistent_check.setChecked(settings['persistent'])

                if 'aggressive' in settings:
                    self.aggressive_check.setChecked(settings['aggressive'])

                if 'stealth' in settings:
                    self.stealth_check.setChecked(settings['stealth'])

                if 'log_api' in settings:
                    self.log_api_check.setChecked(settings['log_api'])

                if 'hook_delay' in settings:
                    self.hook_delay_spin.setValue(settings['hook_delay'])

            except Exception as e:
                self.log_message(f"Failed to load settings: {str(e)}", "orange")

    def closeEvent(self, event):
        """Handle dialog close"""
        if self.worker_thread and self.worker_thread.isRunning():
            reply = QMessageBox.question(
                self, "Confirm Exit",
                "Bypass operation is still running. Stop and exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.worker_thread.stop()
                self.worker_thread.wait()
            else:
                event.ignore()
                return

        # Detach from process if attached
        if self.wizard.session:
            self.wizard.detach()

        event.accept()
