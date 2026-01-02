"""Offline Activation Emulator Dialog - Production-ready implementation."""

import json
import logging
import os
from datetime import datetime
from typing import Any

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QCloseEvent, QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.offline_activation_emulator import (
    ActivationRequest,
    ActivationResponse,
    ActivationType,
    HardwareProfile,
    OfflineActivationEmulator,
)


logger = logging.getLogger(__name__)


class ActivationWorker(QThread):
    """Worker thread for activation operations."""

    progress = pyqtSignal(str)
    result = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, emulator: OfflineActivationEmulator, operation: str, params: dict[str, Any]) -> None:
        """Initialize the OfflineActivationWorker with emulator and operation parameters.

        Args:
            emulator: OfflineActivationEmulator instance to use for activation.
            operation: Operation to perform during activation.
            params: Parameters for the activation operation.

        """
        super().__init__()
        self.emulator = emulator
        self.operation = operation
        self.params = params

    def run(self) -> None:
        """Execute offline activation operation in background thread.

        Performs the specified operation using the emulator and emits progress
        updates, results, or errors via Qt signals.
        """
        try:
            if self.operation == "get_hardware_profile":
                self.progress.emit("Gathering hardware information...")
                profile = self.emulator.get_hardware_profile()
                self.result.emit({"operation": "hardware_profile", "data": profile})

            elif self.operation == "generate_hardware_id":
                self.progress.emit("Generating hardware ID...")
                hw_id = self.emulator.generate_hardware_id(
                    profile=self.params.get("profile"),
                    algorithm=self.params.get("algorithm", "standard"),
                )
                self.result.emit({"operation": "hardware_id", "data": hw_id})

            elif self.operation == "generate_installation_id":
                self.progress.emit("Generating installation ID...")
                install_id = self.emulator.generate_installation_id(self.params["product_id"], self.params["hardware_id"])
                self.result.emit({"operation": "installation_id", "data": install_id})

            elif self.operation == "generate_request_code":
                self.progress.emit("Generating request code...")
                request_code = self.emulator.generate_request_code(self.params["installation_id"])
                self.result.emit({"operation": "request_code", "data": request_code})

            elif self.operation == "generate_activation":
                self.progress.emit("Generating activation response...")
                request = ActivationRequest(
                    product_id=self.params["product_id"],
                    product_version=self.params["product_version"],
                    hardware_id=self.params["hardware_id"],
                    installation_id=self.params["installation_id"],
                    request_code=self.params["request_code"],
                    timestamp=datetime.now(),
                    additional_data=self.params.get("additional_data", {}),
                )
                response = self.emulator.generate_activation_response(request, product_key=self.params.get("product_key"))
                self.result.emit({"operation": "activation_response", "data": response})

            elif self.operation == "validate_license":
                self.progress.emit("Validating license file...")
                result = self.emulator.validate_license_file(self.params["file_path"], self.params.get("hardware_id"))
                self.result.emit({"operation": "validation", "data": result})

            elif self.operation == "export_license":
                self.progress.emit("Exporting license file...")
                self.emulator.export_license_file(
                    self.params["response"],
                    self.params["file_path"],
                    self.params.get("format", "xml"),
                )
                self.result.emit({
                    "operation": "export",
                    "data": {"success": True, "path": self.params["file_path"]},
                })

        except Exception as e:
            logger.exception("Activation worker operation failed: %s", self.operation, exc_info=True)
            self.error.emit(str(e))


class OfflineActivationDialog(QDialog):
    """Comprehensive offline activation emulator interface."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the OfflineActivationDialog with an optional parent.

        Args:
            parent: Parent widget for the dialog, if any.
        """
        super().__init__(parent)
        self.emulator = OfflineActivationEmulator()
        self.current_profile: HardwareProfile | None = None
        self.current_hardware_id: str | None = None
        self.current_installation_id: str | None = None
        self.current_request_code: str | None = None
        self.current_response: ActivationResponse | None = None
        self.saved_profiles: dict[str, dict[str, Any]] = {}
        self.worker: ActivationWorker | None = None

        self.init_ui()
        self.load_saved_profiles()

    def init_ui(self) -> None:
        """Initialize the user interface.

        Creates the main dialog layout with tabs for hardware profile, ID generation,
        activation, algorithms, saved profiles, and testing. Adds a console output
        area and dialog control buttons.

        Sets the dialog title, minimum size, and configures all UI components
        and their layout.
        """
        self.setWindowTitle("Offline Activation Emulator")
        self.setMinimumSize(1000, 700)

        # Main layout
        layout = QVBoxLayout()

        # Create tab widget
        self.tabs = QTabWidget()

        # Add tabs
        self.tabs.addTab(self.create_hardware_tab(), "Hardware Profile")
        self.tabs.addTab(self.create_generation_tab(), "ID Generation")
        self.tabs.addTab(self.create_activation_tab(), "Activation")
        self.tabs.addTab(self.create_algorithms_tab(), "Algorithms")
        self.tabs.addTab(self.create_profiles_tab(), "Saved Profiles")
        self.tabs.addTab(self.create_testing_tab(), "Testing")

        layout.addWidget(self.tabs)

        # Console output
        self.console = QTextEdit()
        self.console.setMaximumHeight(150)
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 9))
        layout.addWidget(self.console)

        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def create_hardware_tab(self) -> QWidget:
        """Create hardware profile tab.

        Constructs a widget with hardware capture and ID generation controls,
        including buttons for capturing, importing, and exporting hardware profiles,
        along with a table displaying hardware components and an ID generation group.

        Returns:
            Widget containing hardware profile capture, display, and ID generation controls.
        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Hardware capture group
        capture_group = QGroupBox("Hardware Capture")
        capture_layout = QVBoxLayout()

        # Capture buttons
        btn_layout = QHBoxLayout()
        self.btn_capture_hardware = QPushButton("Capture Current Hardware")
        self.btn_capture_hardware.clicked.connect(self.capture_hardware)
        btn_layout.addWidget(self.btn_capture_hardware)

        self.btn_import_hardware = QPushButton("Import Hardware Profile")
        self.btn_import_hardware.clicked.connect(self.import_hardware_profile)
        btn_layout.addWidget(self.btn_import_hardware)

        self.btn_export_hardware = QPushButton("Export Hardware Profile")
        self.btn_export_hardware.clicked.connect(self.export_hardware_profile)
        self.btn_export_hardware.setEnabled(False)
        btn_layout.addWidget(self.btn_export_hardware)

        btn_layout.addStretch()
        capture_layout.addLayout(btn_layout)

        # Hardware details table
        self.hardware_table = QTableWidget(0, 2)
        self.hardware_table.setHorizontalHeaderLabels(["Component", "Value"])
        header = self.hardware_table.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(True)
        self.hardware_table.setAlternatingRowColors(True)
        capture_layout.addWidget(self.hardware_table)

        capture_group.setLayout(capture_layout)
        layout.addWidget(capture_group)

        # Hardware ID generation group
        hwid_group = QGroupBox("Hardware ID Generation")
        hwid_layout = QVBoxLayout()

        # Algorithm selection
        algo_layout = QHBoxLayout()
        algo_layout.addWidget(QLabel("Algorithm:"))
        self.hwid_algorithm = QComboBox()
        self.hwid_algorithm.addItems(["standard", "microsoft", "adobe", "autodesk", "vmware", "custom_md5", "custom_sha256"])
        algo_layout.addWidget(self.hwid_algorithm)

        self.btn_generate_hwid = QPushButton("Generate Hardware ID")
        self.btn_generate_hwid.clicked.connect(self.generate_hardware_id)
        self.btn_generate_hwid.setEnabled(False)
        algo_layout.addWidget(self.btn_generate_hwid)

        algo_layout.addStretch()
        hwid_layout.addLayout(algo_layout)

        # Hardware ID output
        self.hwid_output = QLineEdit()
        self.hwid_output.setReadOnly(True)
        self.hwid_output.setFont(QFont("Consolas", 10))
        hwid_layout.addWidget(self.hwid_output)

        hwid_group.setLayout(hwid_layout)
        layout.addWidget(hwid_group)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_generation_tab(self) -> QWidget:
        """Create ID generation tab.

        Constructs a widget with product information inputs (ID, version, key) and
        ID generation controls for installation ID and request code generation,
        with formatted output display.

        Returns:
            Widget containing product information input and ID generation controls.
        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Product information
        product_group = QGroupBox("Product Information")
        product_layout = QVBoxLayout()

        # Product ID
        pid_layout = QHBoxLayout()
        pid_layout.addWidget(QLabel("Product ID:"))
        self.product_id_input = QLineEdit()
        self.product_id_input.setText("")
        self.product_id_input.setToolTip("Enter product identifier (OFFICE-2021-PRO, ADOBE-CC-2023, etc.)")
        pid_layout.addWidget(self.product_id_input)
        product_layout.addLayout(pid_layout)

        # Product Version
        version_layout = QHBoxLayout()
        version_layout.addWidget(QLabel("Version:"))
        self.product_version_input = QLineEdit()
        self.product_version_input.setText("")
        self.product_version_input.setToolTip("Enter product version number")
        version_layout.addWidget(self.product_version_input)
        product_layout.addLayout(version_layout)

        # Product Key (optional)
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("Product Key (optional):"))
        self.product_key_input = QLineEdit()
        self.product_key_input.setText("")
        self.product_key_input.setToolTip("Enter 25-character product key if available")
        key_layout.addWidget(self.product_key_input)
        product_layout.addLayout(key_layout)

        product_group.setLayout(product_layout)
        layout.addWidget(product_group)

        # Installation ID generation
        install_group = QGroupBox("Installation ID")
        install_layout = QVBoxLayout()

        btn_layout = QHBoxLayout()
        self.btn_generate_install_id = QPushButton("Generate Installation ID")
        self.btn_generate_install_id.clicked.connect(self.generate_installation_id)
        btn_layout.addWidget(self.btn_generate_install_id)

        self.btn_format_install_id = QPushButton("Format for Phone Activation")
        self.btn_format_install_id.clicked.connect(self.format_installation_id)
        self.btn_format_install_id.setEnabled(False)
        btn_layout.addWidget(self.btn_format_install_id)

        btn_layout.addStretch()
        install_layout.addLayout(btn_layout)

        self.install_id_output = QTextEdit()
        self.install_id_output.setMaximumHeight(100)
        self.install_id_output.setFont(QFont("Consolas", 10))
        self.install_id_output.setReadOnly(True)
        install_layout.addWidget(self.install_id_output)

        install_group.setLayout(install_layout)
        layout.addWidget(install_group)

        # Request code generation
        request_group = QGroupBox("Request Code")
        request_layout = QVBoxLayout()

        btn_layout = QHBoxLayout()
        self.btn_generate_request = QPushButton("Generate Request Code")
        self.btn_generate_request.clicked.connect(self.generate_request_code)
        self.btn_generate_request.setEnabled(False)
        btn_layout.addWidget(self.btn_generate_request)

        btn_layout.addStretch()
        request_layout.addLayout(btn_layout)

        self.request_code_output = QLineEdit()
        self.request_code_output.setFont(QFont("Consolas", 10))
        self.request_code_output.setReadOnly(True)
        request_layout.addWidget(self.request_code_output)

        request_group.setLayout(request_layout)
        layout.addWidget(request_group)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_activation_tab(self) -> QWidget:
        """Create activation response tab.

        Constructs a widget with activation settings (type, features, expiry, hardware lock),
        generation buttons, and response output display for viewing generated activation data.

        Returns:
            Widget containing activation settings and response generation controls.
        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Activation settings
        settings_group = QGroupBox("Activation Settings")
        settings_layout = QVBoxLayout()

        # Activation type
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Activation Type:"))
        self.activation_type = QComboBox()
        for act_type in ActivationType:
            self.activation_type.addItem(act_type.value)
        type_layout.addWidget(self.activation_type)
        type_layout.addStretch()
        settings_layout.addLayout(type_layout)

        # Features
        features_layout = QHBoxLayout()
        features_layout.addWidget(QLabel("Features:"))
        self.features_input = QLineEdit()
        self.features_input.setText("")
        self.features_input.setToolTip("Enter comma-separated list of features to enable")
        features_layout.addWidget(self.features_input)
        settings_layout.addLayout(features_layout)

        # Expiry
        expiry_layout = QHBoxLayout()
        self.enable_expiry = QCheckBox("Set Expiry Date")
        expiry_layout.addWidget(self.enable_expiry)
        self.expiry_date = QDateEdit()
        self.expiry_date.setCalendarPopup(True)
        self.expiry_date.setDate(datetime.now().date())
        self.expiry_date.setEnabled(False)
        self.enable_expiry.toggled.connect(self.expiry_date.setEnabled)
        expiry_layout.addWidget(self.expiry_date)

        self.hardware_lock = QCheckBox("Hardware Locked")
        self.hardware_lock.setChecked(True)
        expiry_layout.addWidget(self.hardware_lock)

        expiry_layout.addStretch()
        settings_layout.addLayout(expiry_layout)

        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)

        # Generation buttons
        gen_layout = QHBoxLayout()
        self.btn_generate_activation = QPushButton("Generate Activation Response")
        self.btn_generate_activation.clicked.connect(self.generate_activation_response)
        gen_layout.addWidget(self.btn_generate_activation)

        self.btn_export_license = QPushButton("Export License File")
        self.btn_export_license.clicked.connect(self.export_license_file)
        self.btn_export_license.setEnabled(False)
        gen_layout.addWidget(self.btn_export_license)

        self.btn_validate_license = QPushButton("Validate License File")
        self.btn_validate_license.clicked.connect(self.validate_license_file)
        gen_layout.addWidget(self.btn_validate_license)

        gen_layout.addStretch()
        layout.addLayout(gen_layout)

        # Response output
        response_group = QGroupBox("Activation Response")
        response_layout = QVBoxLayout()

        self.response_output = QTextEdit()
        self.response_output.setFont(QFont("Consolas", 9))
        self.response_output.setReadOnly(True)
        response_layout.addWidget(self.response_output)

        response_group.setLayout(response_layout)
        layout.addWidget(response_group)

        widget.setLayout(layout)
        return widget

    def create_algorithms_tab(self) -> QWidget:
        """Create algorithms configuration tab.

        Constructs a widget displaying known activation schemes in a table and
        providing custom algorithm configuration controls (key length, hash algorithm, encoding).

        Returns:
            Widget displaying known activation schemes and custom algorithm configuration.
        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Known schemes
        schemes_group = QGroupBox("Known Activation Schemes")
        schemes_layout = QVBoxLayout()

        self.schemes_table = QTableWidget(0, 4)
        self.schemes_table.setHorizontalHeaderLabels(["Product", "Type", "Algorithm", "Hardware Locked"])
        header = self.schemes_table.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(True)
        self.schemes_table.setAlternatingRowColors(True)

        # Load known schemes
        for name, scheme in self.emulator.known_schemes.items():
            row = self.schemes_table.rowCount()
            self.schemes_table.insertRow(row)
            self.schemes_table.setItem(row, 0, QTableWidgetItem(name))
            self.schemes_table.setItem(row, 1, QTableWidgetItem(scheme["type"].value))
            self.schemes_table.setItem(row, 2, QTableWidgetItem(scheme["algorithm"]))
            self.schemes_table.setItem(row, 3, QTableWidgetItem("Yes" if scheme.get("hardware_locked") else "No"))

        schemes_layout.addWidget(self.schemes_table)
        schemes_group.setLayout(schemes_layout)
        layout.addWidget(schemes_group)

        # Custom algorithm configuration
        custom_group = QGroupBox("Custom Algorithm Configuration")
        custom_layout = QVBoxLayout()

        # Algorithm parameters
        params_layout = QHBoxLayout()
        params_layout.addWidget(QLabel("Key Length:"))
        self.key_length = QSpinBox()
        self.key_length.setRange(16, 256)
        self.key_length.setValue(128)
        params_layout.addWidget(self.key_length)

        params_layout.addWidget(QLabel("Hash Algorithm:"))
        self.hash_algorithm = QComboBox()
        self.hash_algorithm.addItems(["SHA256", "SHA512", "MD5", "BLAKE2"])
        params_layout.addWidget(self.hash_algorithm)

        params_layout.addWidget(QLabel("Encoding:"))
        self.encoding_type = QComboBox()
        self.encoding_type.addItems(["Base64", "Hex", "Base32", "Custom"])
        params_layout.addWidget(self.encoding_type)

        params_layout.addStretch()
        custom_layout.addLayout(params_layout)

        # Save custom scheme
        save_layout = QHBoxLayout()
        save_layout.addWidget(QLabel("Scheme Name:"))
        self.scheme_name_input = QLineEdit()
        save_layout.addWidget(self.scheme_name_input)

        self.btn_save_scheme = QPushButton("Save Custom Scheme")
        self.btn_save_scheme.clicked.connect(self.save_custom_scheme)
        save_layout.addWidget(self.btn_save_scheme)

        save_layout.addStretch()
        custom_layout.addLayout(save_layout)

        custom_group.setLayout(custom_layout)
        layout.addWidget(custom_group)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_profiles_tab(self) -> QWidget:
        """Create saved profiles tab.

        Constructs a widget for managing and viewing saved activation profiles,
        including buttons to load, save, and delete profiles, with a table showing
        profile details and a JSON details viewer.

        Returns:
            Widget for managing and viewing saved activation profiles.
        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Profile management
        mgmt_layout = QHBoxLayout()
        self.btn_load_profile = QPushButton("Load Profile")
        self.btn_load_profile.clicked.connect(self.load_profile)
        mgmt_layout.addWidget(self.btn_load_profile)

        self.btn_save_profile = QPushButton("Save Current Profile")
        self.btn_save_profile.clicked.connect(self.save_current_profile)
        mgmt_layout.addWidget(self.btn_save_profile)

        self.btn_delete_profile = QPushButton("Delete Profile")
        self.btn_delete_profile.clicked.connect(self.delete_profile)
        mgmt_layout.addWidget(self.btn_delete_profile)

        mgmt_layout.addStretch()
        layout.addLayout(mgmt_layout)

        # Profiles table
        self.profiles_table = QTableWidget(0, 5)
        self.profiles_table.setHorizontalHeaderLabels(["Name", "Product ID", "Hardware ID", "Created", "Notes"])
        header = self.profiles_table.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(True)
        self.profiles_table.setAlternatingRowColors(True)
        self.profiles_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.profiles_table)

        # Profile details
        details_group = QGroupBox("Profile Details")
        details_layout = QVBoxLayout()

        self.profile_details = QTextEdit()
        self.profile_details.setReadOnly(True)
        self.profile_details.setFont(QFont("Consolas", 9))
        details_layout.addWidget(self.profile_details)

        details_group.setLayout(details_layout)
        layout.addWidget(details_group)

        widget.setLayout(layout)
        return widget

    def create_testing_tab(self) -> QWidget:
        """Create testing and validation tab.

        Constructs a widget for selecting and running predefined test scenarios
        (Microsoft, Adobe, Autodesk, VMware, etc.) and displaying test results.

        Returns:
            Widget for running test scenarios and viewing results.
        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Test scenarios
        scenarios_group = QGroupBox("Test Scenarios")
        scenarios_layout = QVBoxLayout()

        scenario_layout = QHBoxLayout()
        scenario_layout.addWidget(QLabel("Scenario:"))
        self.test_scenario = QComboBox()
        self.test_scenario.addItems(
            [
                "Microsoft Office Activation",
                "Adobe CC License",
                "Autodesk Product",
                "VMware License",
                "Custom RSA Activation",
                "Hardware-Locked License",
                "Time-Limited Trial",
            ],
        )
        scenario_layout.addWidget(self.test_scenario)

        self.btn_run_test = QPushButton("Run Test Scenario")
        self.btn_run_test.clicked.connect(self.run_test_scenario)
        scenario_layout.addWidget(self.btn_run_test)

        scenario_layout.addStretch()
        scenarios_layout.addLayout(scenario_layout)

        scenarios_group.setLayout(scenarios_layout)
        layout.addWidget(scenarios_group)

        # Test results
        results_group = QGroupBox("Test Results")
        results_layout = QVBoxLayout()

        self.test_results = QTextEdit()
        self.test_results.setFont(QFont("Consolas", 9))
        self.test_results.setReadOnly(True)
        results_layout.addWidget(self.test_results)

        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

        widget.setLayout(layout)
        return widget

    def capture_hardware(self) -> None:
        """Capture current hardware profile.

        Launches a background worker thread to gather hardware information from
        the system and display it in the hardware table. Connects worker signals
        to display progress, results, and errors.
        """
        self.log("Capturing hardware profile...")
        worker = ActivationWorker(self.emulator, "get_hardware_profile", {})
        self.worker = worker
        worker.progress.connect(self.log)
        worker.result.connect(self.handle_worker_result)
        worker.error.connect(self.handle_worker_error)
        worker.start()

    def generate_hardware_id(self) -> None:
        """Generate hardware ID from current profile.

        Uses the algorithm selected in the hardware ID generation group to create
        a hardware ID from the current hardware profile. Launches a background worker
        thread and displays the generated ID. Shows warning if no profile has been captured.
        """
        if not self.current_profile:
            QMessageBox.warning(self, "Warning", "Please capture hardware profile first")
            return

        algorithm = self.hwid_algorithm.currentText()
        self.log("Generating hardware ID using %s algorithm...", algorithm)

        worker = ActivationWorker(
            self.emulator,
            "generate_hardware_id",
            {"profile": self.current_profile, "algorithm": algorithm},
        )
        self.worker = worker
        worker.progress.connect(self.log)
        worker.result.connect(self.handle_worker_result)
        worker.error.connect(self.handle_worker_error)
        worker.start()

    def generate_installation_id(self) -> None:
        """Generate installation ID.

        Creates an installation ID from the current product ID and hardware ID.
        Launches a background worker thread and displays the result. Validates that
        both a product ID is entered and a hardware ID has been generated.
        """
        product_id = self.product_id_input.text().strip()
        if not product_id:
            QMessageBox.warning(self, "Warning", "Please enter a product ID")
            return

        if not self.current_hardware_id:
            QMessageBox.warning(self, "Warning", "Please generate hardware ID first")
            return

        self.log("Generating installation ID...")
        worker = ActivationWorker(
            self.emulator,
            "generate_installation_id",
            {"product_id": product_id, "hardware_id": self.current_hardware_id},
        )
        self.worker = worker
        worker.progress.connect(self.log)
        worker.result.connect(self.handle_worker_result)
        worker.error.connect(self.handle_worker_error)
        worker.start()

    def generate_request_code(self) -> None:
        """Generate request code.

        Generates a request code from the current installation ID using a background
        worker thread. Displays the generated code. Validates that an installation ID
        has been generated first.
        """
        if not self.current_installation_id:
            QMessageBox.warning(self, "Warning", "Please generate installation ID first")
            return

        self.log("Generating request code...")
        worker = ActivationWorker(
            self.emulator,
            "generate_request_code",
            {"installation_id": self.current_installation_id},
        )
        self.worker = worker
        worker.progress.connect(self.log)
        worker.result.connect(self.handle_worker_result)
        worker.error.connect(self.handle_worker_error)
        worker.start()

    def generate_activation_response(self) -> None:
        """Generate complete activation response.

        Creates a full activation response with settings from the activation tab,
        including features, hardware lock status, expiry date, and activation type.
        Launches a background worker thread to generate the response. Validates that
        all required fields (product ID, version, hardware ID) are set.
        """
        product_id = self.product_id_input.text().strip()
        product_version = self.product_version_input.text().strip()

        if not all([product_id, product_version, self.current_hardware_id]):
            QMessageBox.warning(self, "Warning", "Please ensure product ID, version, and hardware ID are set")
            return

        features = [f.strip() for f in self.features_input.text().split(",") if f.strip()]

        additional_data: dict[str, Any] = {
            "features": features,
            "hardware_locked": self.hardware_lock.isChecked(),
            "activation_type": self.activation_type.currentText(),
        }

        if self.enable_expiry.isChecked():
            additional_data["expiry_date"] = self.expiry_date.date().toString("yyyy-MM-dd")

        params: dict[str, Any] = {
            "product_id": product_id,
            "product_version": product_version,
            "hardware_id": self.current_hardware_id,
            "installation_id": self.current_installation_id or "",
            "request_code": self.current_request_code or "",
            "product_key": self.product_key_input.text().strip() or None,
            "additional_data": additional_data,
        }

        self.log("Generating activation response...")
        worker = ActivationWorker(self.emulator, "generate_activation", params)
        self.worker = worker
        worker.progress.connect(self.log)
        worker.result.connect(self.handle_worker_result)
        worker.error.connect(self.handle_worker_error)
        worker.start()

    def format_installation_id(self) -> None:
        """Format installation ID for phone activation.

        Formats the current installation ID into groups of 6 digits separated by hyphens
        for easier phone-based activation entry. Displays formatted ID in the output field.
        """
        if not self.current_installation_id:
            return

        # Format as groups of 6 digits for phone reading
        id_str = self.current_installation_id
        formatted = "-".join([id_str[i : i + 6] for i in range(0, len(id_str), 6)])
        self.install_id_output.setText(formatted)
        self.log("Installation ID formatted for phone activation")

    def export_license_file(self) -> None:
        """Export activation response as license file.

        Exports the current activation response to a file selected by the user via
        file dialog. Supports XML, JSON, and binary license file formats. Launches a
        background worker thread for export. Shows error if no activation response exists.
        """
        if not self.current_response:
            QMessageBox.warning(self, "Warning", "No activation response to export")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export License File",
            "",
            "XML Files (*.xml);;JSON Files (*.json);;License Files (*.lic);;All Files (*.*)",
        )

        if file_path:
            try:
                # Determine format from extension
                ext = os.path.splitext(file_path)[1].lower()
                format_map = {".xml": "xml", ".json": "json", ".lic": "binary"}
                file_format = format_map.get(ext, "xml")

                worker = ActivationWorker(
                    self.emulator,
                    "export_license",
                    {
                        "response": self.current_response,
                        "file_path": file_path,
                        "format": file_format,
                    },
                )
                self.worker = worker
                worker.progress.connect(self.log)
                worker.result.connect(self.handle_worker_result)
                worker.error.connect(self.handle_worker_error)
                worker.start()
            except Exception as e:
                logger.exception("Failed to export license file to %s", file_path, exc_info=True)
                self.handle_worker_error(str(e))

    def validate_license_file(self) -> None:
        """Validate an existing license file.

        Allows the user to select a license file via file dialog and validates it
        against the current hardware ID using a background worker thread. Displays
        validation results in the response output.
        """
        file_path, _ = QFileDialog.getOpenFileName(self, "Select License File", "", "License Files (*.xml *.json *.lic);;All Files (*.*)")

        if file_path:
            worker = ActivationWorker(
                self.emulator,
                "validate_license",
                {"file_path": file_path, "hardware_id": self.current_hardware_id},
            )
            self.worker = worker
            worker.progress.connect(self.log)
            worker.result.connect(self.handle_worker_result)
            worker.error.connect(self.handle_worker_error)
            worker.start()

    def import_hardware_profile(self) -> None:
        """Import hardware profile from file.

        Allows the user to select a JSON file containing a hardware profile via
        file dialog and loads it into the current session. Updates display and enables
        related buttons on successful import. Logs errors if import fails.
        """
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Hardware Profile", "", "JSON Files (*.json);;All Files (*.*)")

        if file_path:
            try:
                with open(file_path) as f:
                    data = json.load(f)

                self.current_profile = HardwareProfile(**data)
                self.display_hardware_profile(self.current_profile)
                self.btn_generate_hwid.setEnabled(True)
                self.btn_export_hardware.setEnabled(True)
                self.log("Hardware profile imported from %s", file_path)
            except Exception as e:
                logger.exception("Failed to import hardware profile from %s", file_path, exc_info=True)
                self.handle_worker_error(f"Failed to import profile: {e}")

    def export_hardware_profile(self) -> None:
        """Export current hardware profile to file.

        Exports the current hardware profile as a JSON file via file dialog that
        can be imported in a different session. Logs errors if export fails.
        """
        if not self.current_profile:
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Export Hardware Profile", "", "JSON Files (*.json);;All Files (*.*)")

        if file_path:
            try:
                profile_dict = {
                    "cpu_id": self.current_profile.cpu_id,
                    "motherboard_serial": self.current_profile.motherboard_serial,
                    "disk_serial": self.current_profile.disk_serial,
                    "mac_addresses": self.current_profile.mac_addresses,
                    "bios_serial": self.current_profile.bios_serial,
                    "system_uuid": self.current_profile.system_uuid,
                    "volume_serial": self.current_profile.volume_serial,
                    "machine_guid": self.current_profile.machine_guid,
                }

                with open(file_path, "w") as f:
                    json.dump(profile_dict, f, indent=2)

                self.log("Hardware profile exported to %s", file_path)
            except Exception as e:
                logger.exception("Failed to export hardware profile to %s", file_path, exc_info=True)
                self.handle_worker_error(f"Failed to export profile: {e}")

    def save_custom_scheme(self) -> None:
        """Save custom activation scheme.

        Creates and saves a new custom activation scheme with user-specified parameters
        including key length, hash algorithm, and encoding type. Updates the schemes
        table and logs the action. Shows warning if scheme name is empty.
        """
        name = self.scheme_name_input.text().strip()
        if not name:
            QMessageBox.warning(self, "Warning", "Please enter a scheme name")
            return

        # Add to emulator's known schemes
        self.emulator.known_schemes[name] = {
            "type": ActivationType[self.activation_type.currentText().upper()],
            "algorithm": "custom",
            "hardware_locked": self.hardware_lock.isChecked(),
            "key_length": self.key_length.value(),
            "hash_algorithm": self.hash_algorithm.currentText(),
            "encoding": self.encoding_type.currentText(),
        }

        # Update schemes table
        row = self.schemes_table.rowCount()
        self.schemes_table.insertRow(row)
        self.schemes_table.setItem(row, 0, QTableWidgetItem(name))
        self.schemes_table.setItem(row, 1, QTableWidgetItem(self.activation_type.currentText()))
        self.schemes_table.setItem(row, 2, QTableWidgetItem("custom"))
        self.schemes_table.setItem(row, 3, QTableWidgetItem("Yes" if self.hardware_lock.isChecked() else "No"))

        self.log("Custom scheme '%s' saved", name)
        self.scheme_name_input.clear()

    def save_current_profile(self) -> None:
        """Save current activation profile.

        Saves the current activation settings, hardware profile, and generated IDs
        to the saved profiles dictionary. Prompts user for a profile name via input dialog.
        Updates profiles table and persists to disk. Shows warning if no profile exists.
        """
        if not self.current_profile:
            QMessageBox.warning(self, "Warning", "No profile to save")
            return

        name, ok = QInputDialog.getText(self, "Save Profile", "Profile Name:")
        if ok and name:
            profile = {
                "name": name,
                "product_id": self.product_id_input.text(),
                "product_version": self.product_version_input.text(),
                "hardware_profile": self.current_profile.__dict__ if self.current_profile else None,
                "hardware_id": self.current_hardware_id,
                "installation_id": self.current_installation_id,
                "request_code": self.current_request_code,
                "created": datetime.now().isoformat(),
                "notes": "",
            }

            self.saved_profiles[name] = profile
            self.update_profiles_table()
            self.save_profiles_to_disk()
            self.log("Profile '%s' saved", name)

    def load_profile(self) -> None:
        """Load selected profile.

        Loads a previously saved profile from the profiles table into the current
        session, restoring all settings, generated IDs, and UI state. Shows warning
        if no profile is selected.
        """
        current_row = self.profiles_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "Please select a profile to load")
            return

        item = self.profiles_table.item(current_row, 0)
        if item is None:
            return

        name = item.text()
        if profile := self.saved_profiles.get(name):
            self.product_id_input.setText(profile.get("product_id", ""))
            self.product_version_input.setText(profile.get("product_version", ""))

            hw_profile_data = profile.get("hardware_profile")
            if hw_profile_data and isinstance(hw_profile_data, dict):
                self.current_profile = HardwareProfile(**hw_profile_data)
                self.display_hardware_profile(self.current_profile)
                self.btn_generate_hwid.setEnabled(True)
                self.btn_export_hardware.setEnabled(True)

            hw_id = profile.get("hardware_id")
            if hw_id and isinstance(hw_id, str):
                self.current_hardware_id = hw_id
                self.hwid_output.setText(hw_id)

            install_id = profile.get("installation_id")
            if install_id and isinstance(install_id, str):
                self.current_installation_id = install_id
                self.install_id_output.setText(install_id)
                self.btn_format_install_id.setEnabled(True)
                self.btn_generate_request.setEnabled(True)

            req_code = profile.get("request_code")
            if req_code and isinstance(req_code, str):
                self.current_request_code = req_code
                self.request_code_output.setText(req_code)

            self.log("Profile '%s' loaded", name)

    def delete_profile(self) -> None:
        """Delete selected profile.

        Removes a saved profile from the profiles dictionary and updates the
        profiles table with confirmation. Persists changes to disk. Shows warning
        if no profile is selected.
        """
        current_row = self.profiles_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "Please select a profile to delete")
            return

        item = self.profiles_table.item(current_row, 0)
        if item is None:
            return

        name = item.text()

        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Delete profile '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            del self.saved_profiles[name]
            self.update_profiles_table()
            self.save_profiles_to_disk()
            self.log("Profile '%s' deleted", name)

    def run_test_scenario(self) -> None:
        """Run selected test scenario.

        Executes one of the predefined activation test scenarios (Microsoft,
        Adobe, Autodesk, VMware, Custom RSA, Hardware-Locked, or Time-Limited).
        Generates test data, performs activation operations, and displays detailed
        results with status indicators.
        """
        scenario = self.test_scenario.currentText()
        self.test_results.clear()
        self.test_results.append(f"Running test scenario: {scenario}\n")
        self.test_results.append("=" * 50 + "\n")

        try:
            # Create test profile
            test_profile = self.emulator.get_hardware_profile()

            if "Microsoft" in scenario:
                # Test Microsoft activation
                hw_id = self.emulator.generate_hardware_id(test_profile, "microsoft")
                install_id = self.emulator.generate_installation_id("OFFICE-2021-PRO", hw_id)
                request_code = self.emulator.generate_request_code(install_id)

                request = ActivationRequest(
                    product_id="OFFICE-2021-PRO",
                    product_version="16.0.14332.20204",
                    hardware_id=hw_id,
                    installation_id=install_id,
                    request_code=request_code,
                    timestamp=datetime.now(),
                    additional_data={},
                )

                response = self.emulator.generate_activation_response(request)

                self.test_results.append(f"Hardware ID: {hw_id}\n")
                self.test_results.append(f"Installation ID: {install_id[:50]}...\n")
                self.test_results.append(f"Request Code: {request_code}\n")
                self.test_results.append(f"Activation Code: {response.activation_code}\n")
                self.test_results.append(f"License Key: {response.license_key}\n")

            elif "Adobe" in scenario:
                # Test Adobe activation
                hw_id = self.emulator.generate_hardware_id(test_profile, "adobe")
                request = ActivationRequest(
                    product_id="ADOBE-CC-2023",
                    product_version="24.0.0",
                    hardware_id=hw_id,
                    installation_id="",
                    request_code="",
                    timestamp=datetime.now(),
                    additional_data={"suite": "creative_cloud"},
                )

                response = self.emulator.generate_activation_response(request)
                self.test_results.append(f"Hardware ID: {hw_id}\n")
                self.test_results.append(f"License Key: {response.license_key}\n")
                self.test_results.append(f"Features: {', '.join(response.features)}\n")

            elif "Custom RSA" in scenario:
                # Test custom RSA activation
                hw_id = self.emulator.generate_hardware_id(test_profile, "custom_sha256")
                request = ActivationRequest(
                    product_id="CUSTOM-APP",
                    product_version="1.0.0",
                    hardware_id=hw_id,
                    installation_id="",
                    request_code="",
                    timestamp=datetime.now(),
                    additional_data={},
                )

                response = self.emulator._rsa_based_activation(request)
                self.test_results.append(f"Hardware ID: {hw_id}\n")
                self.test_results.append(f"Activation Code: {response.activation_code[:50]}...\n")
                self.test_results.append(f"Signature present: {response.signature is not None}\n")

            self.test_results.append("\nOK Test scenario completed successfully")

        except Exception as e:
            logger.exception("Test scenario failed for %s", scenario, exc_info=True)
            self.test_results.append(f"\nFAIL Test failed: {e!s}")

    def display_hardware_profile(self, profile: HardwareProfile) -> None:
        """Display hardware profile in table.

        Args:
            profile: The hardware profile to display.
        """
        self.hardware_table.setRowCount(0)

        fields = [
            ("CPU ID", profile.cpu_id),
            ("Motherboard Serial", profile.motherboard_serial),
            ("Disk Serial", profile.disk_serial),
            ("MAC Addresses", ", ".join(profile.mac_addresses)),
            ("BIOS Serial", profile.bios_serial),
            ("System UUID", profile.system_uuid),
            ("Volume Serial", profile.volume_serial),
            ("Machine GUID", profile.machine_guid),
        ]

        for name, value in fields:
            row = self.hardware_table.rowCount()
            self.hardware_table.insertRow(row)
            self.hardware_table.setItem(row, 0, QTableWidgetItem(name))
            self.hardware_table.setItem(row, 1, QTableWidgetItem(value))

    def update_profiles_table(self) -> None:
        """Update saved profiles table.

        Refreshes the profiles table with all saved profiles from the
        saved_profiles dictionary. Populates table rows with profile details and
        connects the selection change handler for profile detail display.
        """
        self.profiles_table.setRowCount(0)

        for name, profile in self.saved_profiles.items():
            row = self.profiles_table.rowCount()
            self.profiles_table.insertRow(row)
            self.profiles_table.setItem(row, 0, QTableWidgetItem(name))
            self.profiles_table.setItem(row, 1, QTableWidgetItem(profile.get("product_id", "")))
            self.profiles_table.setItem(
                row,
                2,
                QTableWidgetItem(profile.get("hardware_id", "")[:20] + "..." if profile.get("hardware_id") else ""),
            )
            self.profiles_table.setItem(row, 3, QTableWidgetItem(profile.get("created", "")[:10]))
            self.profiles_table.setItem(row, 4, QTableWidgetItem(profile.get("notes", "")))

        # Connect selection change
        self.profiles_table.itemSelectionChanged.connect(self.on_profile_selected)

    def on_profile_selected(self) -> None:
        """Handle profile selection.

        Updates the profile details text widget to show a formatted JSON representation
        of the selected profile from the profiles table, including all settings and IDs.
        """
        current_row = self.profiles_table.currentRow()
        if current_row >= 0:
            item = self.profiles_table.item(current_row, 0)
            if item is None:
                return
            name = item.text()
            if profile := self.saved_profiles.get(name):
                details = json.dumps(profile, indent=2, default=str)
                self.profile_details.setText(details)

    def load_saved_profiles(self) -> None:
        """Load saved profiles from disk.

        Loads the activation_profiles.json file from disk if it exists and
        populates the saved_profiles dictionary. Updates the profiles table and
        logs errors if loading fails.
        """
        profiles_file = "activation_profiles.json"
        if os.path.exists(profiles_file):
            try:
                with open(profiles_file) as f:
                    self.saved_profiles = json.load(f)
                self.update_profiles_table()
            except Exception as e:
                logger.exception("Failed to load profiles from %s", profiles_file, exc_info=True)
                self.log("Failed to load profiles: %s", str(e))

    def save_profiles_to_disk(self) -> None:
        """Save profiles to disk.

        Writes the saved_profiles dictionary to activation_profiles.json file with
        indentation for readability. Logs errors if saving fails.
        """
        profiles_file = "activation_profiles.json"
        try:
            with open(profiles_file, "w") as f:
                json.dump(self.saved_profiles, f, indent=2, default=str)
        except Exception as e:
            logger.exception("Failed to save profiles to %s", profiles_file, exc_info=True)
            self.log("Failed to save profiles: %s", str(e))

    def handle_worker_result(self, result: dict[str, Any]) -> None:
        """Handle worker thread results.

        Args:
            result: Dictionary containing operation type and data from worker thread.
        """
        operation = result.get("operation")
        data = result.get("data")

        if operation == "hardware_profile" and isinstance(data, HardwareProfile):
            self.current_profile = data
            self.display_hardware_profile(data)
            self.btn_generate_hwid.setEnabled(True)
            self.btn_export_hardware.setEnabled(True)
            self.log("Hardware profile captured successfully")

        elif operation == "hardware_id" and isinstance(data, str):
            self.current_hardware_id = data
            self.hwid_output.setText(data)
            self.log("Hardware ID generated: %s", data)

        elif operation == "installation_id" and isinstance(data, str):
            self.current_installation_id = data
            self.install_id_output.setText(data)
            self.btn_format_install_id.setEnabled(True)
            self.btn_generate_request.setEnabled(True)
            self.log("Installation ID generated")

        elif operation == "request_code" and isinstance(data, str):
            self.current_request_code = data
            self.request_code_output.setText(data)
            self.log("Request code generated: %s", data)

        elif operation == "activation_response" and isinstance(data, ActivationResponse):
            self.current_response = data
            response_text = f"""Activation Response Generated:
=====================================
Activation Code: {data.activation_code}
License Key: {data.license_key}
Hardware Locked: {data.hardware_locked}
Features: {", ".join(data.features) if data.features else "None"}
Expiry: {data.expiry_date.strftime("%Y-%m-%d") if data.expiry_date else "Never"}
Signature: {"Present" if data.signature else "None"}
"""
            self.response_output.setText(response_text)
            self.btn_export_license.setEnabled(True)
            self.log("Activation response generated successfully")

        elif operation == "validation" and isinstance(data, dict):
            valid = data.get("valid", False)
            message = data.get("message", "")
            details = data.get("details", {})

            validation_text = f"""License Validation Result:
=====================================
Valid: {valid}
Message: {message}

Details:
{json.dumps(details, indent=2)}
"""
            self.response_output.setText(validation_text)
            self.log("License validation: %s", valid)

        elif operation == "export" and isinstance(data, dict):
            if data.get("success"):
                self.log("License file exported to %s", data.get("path"))
                QMessageBox.information(self, "Success", f"License file exported successfully to:\n{data.get('path')}")

    def handle_worker_error(self, error: str) -> None:
        """Handle worker thread errors.

        Args:
            error: Error message from worker thread.
        """
        self.log("Error: %s", error)
        QMessageBox.critical(self, "Error", error)

    def log(self, message: str, *args: Any) -> None:
        """Log message to console.

        Formats a message with provided arguments and appends it to the console
        output with a timestamp prefix. Supports printf-style string formatting.

        Args:
            message: Format string for the log message.
            *args: Variable positional arguments for the log message.
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = message % args if args else message
        self.console.append(f"[{timestamp}] {formatted_message}")

        scrollbar = self.console.verticalScrollBar()
        if scrollbar is not None:
            scrollbar.setValue(scrollbar.maximum())

    def closeEvent(self, event: QCloseEvent | None) -> None:  # noqa: N802
        """Handle dialog close with proper thread cleanup.

        Ensures any running worker thread is properly terminated before
        closing the dialog to prevent resource leaks.

        Args:
            event: Close event from Qt framework.

        """
        if self.worker is not None and self.worker.isRunning():
            self.worker.quit()
            if not self.worker.wait(2000):
                self.worker.terminate()
                self.worker.wait()
            self.worker = None
        super().closeEvent(event)


if __name__ == "__main__":
    import sys

    from PyQt6.QtWidgets import QApplication

    app = QApplication(sys.argv)
    dialog = OfflineActivationDialog()
    dialog.show()
    sys.exit(app.exec())
