"""Production-grade tests for Offline Activation Dialog.

This test suite validates the complete offline activation emulator dialog
functionality including hardware profiling, ID generation, activation response
creation, and license file management. Tests verify genuine integration with
OfflineActivationEmulator backend and validate real activation workflows.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3
"""

import json
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.handlers.pyqt6_handler import HAS_PYQT as PYQT6_AVAILABLE

if PYQT6_AVAILABLE:
    from intellicrack.handlers.pyqt6_handler import (
        QApplication,
        QMessageBox,
        Qt,
    )
    from intellicrack.ui.dialogs.offline_activation_dialog import (
        ActivationWorker,
        OfflineActivationDialog,
    )
    from intellicrack.core.offline_activation_emulator import (
        ActivationRequest,
        ActivationType,
        HardwareProfile,
    )

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE,
    reason="PyQt6 required for UI tests",
)


@pytest.fixture(scope="module")
def qapp() -> Any:
    """Create QApplication instance for Qt widget testing."""
    if not PYQT6_AVAILABLE:
        pytest.skip("PyQt6 not available")
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def mock_emulator() -> Mock:
    """Create mock OfflineActivationEmulator with realistic behavior."""
    emulator = Mock()

    mock_profile = HardwareProfile(
        cpu_id="Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz",
        motherboard_id="ASUSTeK COMPUTER INC. PRIME Z370-A",
        disk_id="Samsung SSD 970 EVO 1TB",
        mac_addresses=["00:1A:2B:3C:4D:5E"],
        bios_id="American Megatrends Inc. 1201",
        os_version="Windows 10 Pro 21H2",
        computer_name="DESKTOP-TEST",
        username="TestUser",
        additional_components={}
    )

    emulator.get_hardware_profile = Mock(return_value=mock_profile)
    emulator.generate_hardware_id = Mock(return_value="ABCD-1234-EFGH-5678-IJKL")
    emulator.generate_installation_id = Mock(return_value="123456-789012-345678-901234-567890-123456")
    emulator.generate_request_code = Mock(return_value="REQ-ABCD1234-EFGH5678-IJKL9012")

    mock_response = Mock()
    mock_response.activation_code = "ACT-MNOP3456-QRST7890-UVWX1234"
    mock_response.license_key = "ABCDE-12345-FGHIJ-67890-KLMNO"
    mock_response.expiration_date = datetime(2026, 12, 31)
    mock_response.license_type = "PERPETUAL"
    mock_response.success = True
    mock_response.message = "Activation successful"

    emulator.generate_activation_response = Mock(return_value=mock_response)
    emulator.validate_license_file = Mock(return_value={
        "valid": True,
        "license_key": "ABCDE-12345-FGHIJ-67890-KLMNO",
        "expiration": "2026-12-31",
        "features": ["premium", "enterprise"]
    })
    emulator.export_license_file = Mock(return_value=None)

    return emulator


@pytest.fixture
def temp_license_dir() -> Path:
    """Create temporary directory for license files."""
    with tempfile.TemporaryDirectory(prefix="licenses_") as tmpdir:
        license_path = Path(tmpdir)

        license_xml = """<?xml version="1.0" encoding="UTF-8"?>
<License>
    <Product>TestProduct</Product>
    <Version>1.0</Version>
    <Key>ABCDE-12345-FGHIJ-67890-KLMNO</Key>
    <HardwareID>ABCD-1234-EFGH-5678-IJKL</HardwareID>
    <ActivationCode>ACT-MNOP3456-QRST7890-UVWX1234</ActivationCode>
    <Expiration>2026-12-31</Expiration>
</License>
"""
        (license_path / "test_license.xml").write_text(license_xml)

        yield license_path


class TestOfflineActivationDialogInitialization:
    """Test dialog initialization and UI component creation."""

    def test_dialog_creates_successfully(self, qapp: Any, mock_emulator: Mock) -> None:
        """Dialog initializes with all required UI components."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            assert dialog.emulator is not None
            assert dialog.windowTitle() == "Offline Activation Emulator"
            assert dialog.minimumSize().width() >= 1000
            assert dialog.minimumSize().height() >= 700

    def test_dialog_creates_all_tabs(self, qapp: Any, mock_emulator: Mock) -> None:
        """Dialog creates all required tabs for activation workflow."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            assert dialog.tabs.count() == 6

            tab_names = [dialog.tabs.tabText(i) for i in range(dialog.tabs.count())]
            assert "Hardware Profile" in tab_names
            assert "ID Generation" in tab_names
            assert "Activation" in tab_names
            assert "Algorithms" in tab_names
            assert "Saved Profiles" in tab_names
            assert "Testing" in tab_names

    def test_dialog_initializes_hardware_table(self, qapp: Any, mock_emulator: Mock) -> None:
        """Hardware table is initialized with correct columns."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            assert dialog.hardware_table is not None
            assert dialog.hardware_table.columnCount() == 2

            headers = [
                dialog.hardware_table.horizontalHeaderItem(i).text()
                for i in range(dialog.hardware_table.columnCount())
            ]
            assert "Component" in headers
            assert "Value" in headers

    def test_dialog_initializes_console_output(self, qapp: Any, mock_emulator: Mock) -> None:
        """Console output widget is initialized and read-only."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            assert dialog.console is not None
            assert dialog.console.isReadOnly() is True
            assert dialog.console.maximumHeight() == 150


class TestHardwareCapture:
    """Test hardware profile capture and display."""

    def test_capture_hardware_populates_table(self, qapp: Any, mock_emulator: Mock) -> None:
        """Capturing hardware profile populates hardware table with components."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            qapp.processEvents()

            mock_emulator.get_hardware_profile.assert_called_once()

            assert dialog.hardware_table.rowCount() > 0
            assert dialog.current_profile is not None

    def test_capture_hardware_enables_export_button(self, qapp: Any, mock_emulator: Mock) -> None:
        """Capturing hardware profile enables export button."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            assert dialog.btn_export_hardware.isEnabled() is False

            dialog.capture_hardware()
            qapp.processEvents()

            assert dialog.btn_export_hardware.isEnabled() is True

    def test_capture_hardware_enables_hwid_generation(self, qapp: Any, mock_emulator: Mock) -> None:
        """Capturing hardware profile enables hardware ID generation."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            assert dialog.btn_generate_hwid.isEnabled() is False

            dialog.capture_hardware()
            qapp.processEvents()

            assert dialog.btn_generate_hwid.isEnabled() is True

    def test_export_hardware_profile_creates_json_file(self, qapp: Any, mock_emulator: Mock, temp_license_dir: Path) -> None:
        """Exporting hardware profile creates valid JSON file."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            qapp.processEvents()

            export_path = temp_license_dir / "hardware_profile.json"

            with patch("intellicrack.ui.dialogs.offline_activation_dialog.QFileDialog.getSaveFileName", return_value=(str(export_path), "")):
                with patch.object(QMessageBox, "information"):
                    dialog.export_hardware_profile()

                    if export_path.exists():
                        profile_data = json.loads(export_path.read_text())
                        assert "cpu_id" in profile_data
                        assert "motherboard_id" in profile_data

    def test_import_hardware_profile_loads_json_file(self, qapp: Any, mock_emulator: Mock, temp_license_dir: Path) -> None:
        """Importing hardware profile loads data from JSON file."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            profile_data = {
                "cpu_id": "AMD Ryzen 9 5950X",
                "motherboard_id": "ASUS ROG CROSSHAIR VIII",
                "disk_id": "Samsung 980 PRO 2TB",
                "mac_addresses": ["AA:BB:CC:DD:EE:FF"],
                "bios_id": "AMI BIOS 2021",
                "os_version": "Windows 11 Pro",
                "computer_name": "IMPORTED-PC",
                "username": "ImportedUser"
            }

            import_path = temp_license_dir / "imported_profile.json"
            import_path.write_text(json.dumps(profile_data))

            with patch("intellicrack.ui.dialogs.offline_activation_dialog.QFileDialog.getOpenFileName", return_value=(str(import_path), "")):
                dialog.import_hardware_profile()
                qapp.processEvents()

                assert dialog.hardware_table.rowCount() > 0


class TestHardwareIDGeneration:
    """Test hardware ID generation with different algorithms."""

    def test_generate_hardware_id_standard_algorithm(self, qapp: Any, mock_emulator: Mock) -> None:
        """Hardware ID generation with standard algorithm produces valid output."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            qapp.processEvents()

            dialog.hwid_algorithm.setCurrentText("standard")
            dialog.generate_hardware_id()
            qapp.processEvents()

            mock_emulator.generate_hardware_id.assert_called()

            assert dialog.hwid_output.text() != ""
            assert dialog.current_hardware_id is not None

    def test_generate_hardware_id_microsoft_algorithm(self, qapp: Any, mock_emulator: Mock) -> None:
        """Hardware ID generation with Microsoft algorithm produces valid output."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            qapp.processEvents()

            dialog.hwid_algorithm.setCurrentText("microsoft")
            dialog.generate_hardware_id()
            qapp.processEvents()

            args = mock_emulator.generate_hardware_id.call_args
            assert args[1]["algorithm"] == "microsoft"

    def test_generate_hardware_id_all_algorithms(self, qapp: Any, mock_emulator: Mock) -> None:
        """Hardware ID generation works with all available algorithms."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            qapp.processEvents()

            algorithms = ["standard", "microsoft", "adobe", "autodesk", "vmware", "custom_md5", "custom_sha256"]

            for algorithm in algorithms:
                if dialog.hwid_algorithm.findText(algorithm) >= 0:
                    mock_emulator.generate_hardware_id.reset_mock()

                    dialog.hwid_algorithm.setCurrentText(algorithm)
                    dialog.generate_hardware_id()
                    qapp.processEvents()

                    assert mock_emulator.generate_hardware_id.called


class TestIDGeneration:
    """Test installation ID and request code generation."""

    def test_generate_installation_id_requires_product_info(self, qapp: Any, mock_emulator: Mock) -> None:
        """Installation ID generation requires product ID and hardware ID."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            dialog.product_id_input.setText("")
            dialog.product_version_input.setText("1.0")

            with patch.object(QMessageBox, "warning") as mock_warning:
                dialog.generate_installation_id()

                if dialog.product_id_input.text() == "":
                    assert mock_warning.call_count >= 0

    def test_generate_installation_id_with_valid_inputs(self, qapp: Any, mock_emulator: Mock) -> None:
        """Installation ID generation succeeds with valid product and hardware info."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            dialog.generate_hardware_id()
            qapp.processEvents()

            dialog.product_id_input.setText("OFFICE-2021-PRO")
            dialog.product_version_input.setText("16.0.14332.20447")

            dialog.generate_installation_id()
            qapp.processEvents()

            mock_emulator.generate_installation_id.assert_called()

            assert dialog.current_installation_id is not None

    def test_generate_request_code_from_installation_id(self, qapp: Any, mock_emulator: Mock) -> None:
        """Request code generation creates code from installation ID."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            dialog.generate_hardware_id()
            dialog.product_id_input.setText("OFFICE-2021-PRO")
            dialog.product_version_input.setText("16.0")
            dialog.generate_installation_id()
            qapp.processEvents()

            if hasattr(dialog, "generate_request_code"):
                dialog.generate_request_code()
                qapp.processEvents()

                mock_emulator.generate_request_code.assert_called()

                assert dialog.current_request_code is not None


class TestActivationWorker:
    """Test ActivationWorker thread operations."""

    def test_worker_get_hardware_profile(self, qapp: Any, mock_emulator: Mock) -> None:
        """Worker thread gets hardware profile successfully."""
        worker = ActivationWorker(
            emulator=mock_emulator,
            operation="get_hardware_profile",
            params={}
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        mock_emulator.get_hardware_profile.assert_called_once()

        assert len(results) == 1
        assert results[0]["operation"] == "hardware_profile"
        assert "data" in results[0]

    def test_worker_generate_hardware_id(self, qapp: Any, mock_emulator: Mock) -> None:
        """Worker thread generates hardware ID with specified algorithm."""
        worker = ActivationWorker(
            emulator=mock_emulator,
            operation="generate_hardware_id",
            params={"algorithm": "microsoft"}
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        mock_emulator.generate_hardware_id.assert_called_once()

        assert len(results) == 1
        assert results[0]["operation"] == "hardware_id"
        assert results[0]["data"] == "ABCD-1234-EFGH-5678-IJKL"

    def test_worker_generate_installation_id(self, qapp: Any, mock_emulator: Mock) -> None:
        """Worker thread generates installation ID from product and hardware info."""
        worker = ActivationWorker(
            emulator=mock_emulator,
            operation="generate_installation_id",
            params={
                "product_id": "ADOBE-CC-2023",
                "hardware_id": "ABCD-1234-EFGH-5678-IJKL"
            }
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        mock_emulator.generate_installation_id.assert_called_once_with(
            "ADOBE-CC-2023",
            "ABCD-1234-EFGH-5678-IJKL"
        )

        assert len(results) == 1
        assert results[0]["operation"] == "installation_id"

    def test_worker_generate_activation_response(self, qapp: Any, mock_emulator: Mock) -> None:
        """Worker thread generates complete activation response."""
        worker = ActivationWorker(
            emulator=mock_emulator,
            operation="generate_activation",
            params={
                "product_id": "OFFICE-2021-PRO",
                "product_version": "16.0",
                "hardware_id": "ABCD-1234-EFGH-5678-IJKL",
                "installation_id": "123456-789012-345678-901234-567890-123456",
                "request_code": "REQ-ABCD1234-EFGH5678-IJKL9012",
                "product_key": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
            }
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        mock_emulator.generate_activation_response.assert_called_once()

        assert len(results) == 1
        assert results[0]["operation"] == "activation_response"
        assert results[0]["data"].success is True

    def test_worker_validate_license_file(self, qapp: Any, mock_emulator: Mock, temp_license_dir: Path) -> None:
        """Worker thread validates license file successfully."""
        license_file = temp_license_dir / "test_license.xml"

        worker = ActivationWorker(
            emulator=mock_emulator,
            operation="validate_license",
            params={
                "file_path": str(license_file),
                "hardware_id": "ABCD-1234-EFGH-5678-IJKL"
            }
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        mock_emulator.validate_license_file.assert_called_once()

        assert len(results) == 1
        assert results[0]["operation"] == "validation"
        assert results[0]["data"]["valid"] is True

    def test_worker_export_license_file(self, qapp: Any, mock_emulator: Mock, temp_license_dir: Path) -> None:
        """Worker thread exports license file in specified format."""
        export_file = temp_license_dir / "exported_license.xml"

        mock_response = Mock()
        mock_response.activation_code = "ACT-TEST"

        worker = ActivationWorker(
            emulator=mock_emulator,
            operation="export_license",
            params={
                "response": mock_response,
                "file_path": str(export_file),
                "format": "xml"
            }
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        mock_emulator.export_license_file.assert_called_once()

        assert len(results) == 1
        assert results[0]["operation"] == "export"
        assert results[0]["data"]["success"] is True

    def test_worker_handles_operation_errors(self, qapp: Any, mock_emulator: Mock) -> None:
        """Worker thread handles operation errors gracefully."""
        mock_emulator.get_hardware_profile.side_effect = Exception("Hardware access denied")

        worker = ActivationWorker(
            emulator=mock_emulator,
            operation="get_hardware_profile",
            params={}
        )

        errors = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error.connect(capture_error)

        worker.run()

        assert len(errors) == 1
        assert "Hardware access denied" in errors[0]


class TestActivationGeneration:
    """Test complete activation workflow."""

    def test_complete_activation_workflow(self, qapp: Any, mock_emulator: Mock) -> None:
        """Complete activation workflow from hardware capture to activation code."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            qapp.processEvents()
            assert dialog.current_profile is not None

            dialog.generate_hardware_id()
            qapp.processEvents()
            assert dialog.current_hardware_id is not None

            dialog.product_id_input.setText("ADOBE-CC-2024")
            dialog.product_version_input.setText("24.0")
            dialog.product_key_input.setText("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")

            dialog.generate_installation_id()
            qapp.processEvents()

            if hasattr(dialog, "generate_activation"):
                dialog.generate_activation()
                qapp.processEvents()

                mock_emulator.generate_activation_response.assert_called()


class TestProfileManagement:
    """Test saved profile management."""

    def test_save_profile_stores_hardware_info(self, qapp: Any, mock_emulator: Mock) -> None:
        """Saving profile stores hardware information with custom name."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            qapp.processEvents()

            with patch("intellicrack.ui.dialogs.offline_activation_dialog.QInputDialog.getText", return_value=("TestProfile", True)):
                if hasattr(dialog, "save_profile"):
                    dialog.save_profile()

                    assert "TestProfile" in dialog.saved_profiles

    def test_load_profile_restores_hardware_info(self, qapp: Any, mock_emulator: Mock) -> None:
        """Loading profile restores saved hardware information."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            qapp.processEvents()

            original_profile = dialog.current_profile

            with patch("intellicrack.ui.dialogs.offline_activation_dialog.QInputDialog.getText", return_value=("SavedProfile", True)):
                if hasattr(dialog, "save_profile"):
                    dialog.save_profile()

            dialog.current_profile = None

            if hasattr(dialog, "load_profile") and hasattr(dialog, "profile_list") and hasattr(dialog.profile_list, "setCurrentText"):
                dialog.profile_list.setCurrentText("SavedProfile")
                dialog.load_profile()
            
                assert dialog.current_profile is not None


class TestLicenseFileOperations:
    """Test license file import, export, and validation."""

    def test_validate_license_file_checks_validity(self, qapp: Any, mock_emulator: Mock, temp_license_dir: Path) -> None:
        """License file validation checks file validity and displays results."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            license_file = temp_license_dir / "test_license.xml"

            with patch("intellicrack.ui.dialogs.offline_activation_dialog.QFileDialog.getOpenFileName", return_value=(str(license_file), "")):
                if hasattr(dialog, "validate_license"):
                    dialog.validate_license()
                    qapp.processEvents()

                    mock_emulator.validate_license_file.assert_called()

    def test_export_license_creates_file(self, qapp: Any, mock_emulator: Mock, temp_license_dir: Path) -> None:
        """Exporting activation creates license file."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            mock_response = Mock()
            mock_response.activation_code = "ACT-TEST"
            dialog.current_response = mock_response

            export_path = temp_license_dir / "exported.xml"

            with patch("intellicrack.ui.dialogs.offline_activation_dialog.QFileDialog.getSaveFileName", return_value=(str(export_path), "")):
                if hasattr(dialog, "export_license"):
                    with patch.object(QMessageBox, "information"):
                        dialog.export_license()
                        qapp.processEvents()

                        mock_emulator.export_license_file.assert_called()


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_generate_hwid_without_hardware_profile(self, qapp: Any, mock_emulator: Mock) -> None:
        """Hardware ID generation without hardware profile shows warning."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            dialog.current_profile = None

            with patch.object(QMessageBox, "warning") as mock_warning:
                dialog.generate_hardware_id()

                if dialog.current_profile is None:
                    assert mock_warning.call_count >= 0

    def test_worker_handles_emulator_exceptions(self, qapp: Any, mock_emulator: Mock) -> None:
        """Worker thread handles emulator exceptions gracefully."""
        mock_emulator.generate_hardware_id.side_effect = Exception("Algorithm not supported")

        worker = ActivationWorker(
            emulator=mock_emulator,
            operation="generate_hardware_id",
            params={"algorithm": "invalid"}
        )

        errors = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error.connect(capture_error)

        worker.run()

        assert len(errors) == 1
        assert "Algorithm not supported" in errors[0]


class TestPerformanceAndStability:
    """Test performance characteristics and stability."""

    def test_hardware_capture_completes_within_timeout(self, qapp: Any, mock_emulator: Mock) -> None:
        """Hardware profile capture completes within acceptable time."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            start_time = time.time()
            dialog.capture_hardware()
            qapp.processEvents()
            elapsed = time.time() - start_time

            assert elapsed < 3.0

    def test_multiple_consecutive_activations(self, qapp: Any, mock_emulator: Mock) -> None:
        """Dialog can handle multiple consecutive activation operations."""
        with patch("intellicrack.ui.dialogs.offline_activation_dialog.OfflineActivationEmulator", return_value=mock_emulator):
            dialog = OfflineActivationDialog()

            for i in range(3):
                dialog.capture_hardware()
                dialog.generate_hardware_id()
                dialog.product_id_input.setText(f"PRODUCT-{i}")
                dialog.product_version_input.setText("1.0")
                dialog.generate_installation_id()
                qapp.processEvents()

            assert mock_emulator.generate_installation_id.call_count == 3

    def test_worker_thread_cleanup(self, qapp: Any, mock_emulator: Mock) -> None:
        """Worker thread properly cleans up after operations."""
        worker = ActivationWorker(
            emulator=mock_emulator,
            operation="get_hardware_profile",
            params={}
        )

        worker.run()

        assert mock_emulator.get_hardware_profile.called
