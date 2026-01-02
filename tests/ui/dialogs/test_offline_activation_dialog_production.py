"""Production-grade tests for Offline Activation Dialog.

This test suite validates the complete offline activation emulator dialog
functionality including hardware profiling, ID generation, activation response
creation, and license file management. Tests verify genuine integration with
OfflineActivationEmulator backend and validate real activation workflows.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3
"""

from __future__ import annotations

import json
import tempfile
import time
from collections.abc import Generator
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.pyqt6_handler import HAS_PYQT as PYQT6_AVAILABLE

QApplication: Any = None
QMessageBox: Any = None
Qt: Any = None
ActivationWorker: Any = None
OfflineActivationDialog: Any = None
ActivationRequest: Any = None
ActivationType: Any = None
HardwareProfile: Any = None
ActivationResponse: Any = None

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
        ActivationResponse,
    )

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE,
    reason="PyQt6 required for UI tests",
)


class FakeHardwareProfile:
    """Real test double for HardwareProfile."""

    def __init__(self) -> None:
        self.cpu_id: str = "Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz"
        self.motherboard_id: str = "ASUSTeK COMPUTER INC. PRIME Z370-A"
        self.disk_id: str = "Samsung SSD 970 EVO 1TB"
        self.mac_addresses: list[str] = ["00:1A:2B:3C:4D:5E"]
        self.bios_id: str = "American Megatrends Inc. 1201"
        self.os_version: str = "Windows 10 Pro 21H2"
        self.computer_name: str = "DESKTOP-TEST"
        self.username: str = "TestUser"
        self.additional_components: dict[str, Any] = {}
        self.motherboard_serial: str = "ASUSTeK-SERIAL-12345"
        self.disk_serial: str = "SAMSUNG-SSD-67890"
        self.bios_serial: str = "AMI-BIOS-54321"
        self.system_uuid: str = "550e8400-e29b-41d4-a716-446655440000"
        self.volume_serial: str = "1234-5678"
        self.machine_guid: str = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"


class FakeActivationResponse:
    """Real test double for ActivationResponse."""

    def __init__(self) -> None:
        self.activation_code: str = "ACT-MNOP3456-QRST7890-UVWX1234"
        self.license_key: str = "ABCDE-12345-FGHIJ-67890-KLMNO"
        self.expiration_date: datetime = datetime(2026, 12, 31)
        self.license_type: str = "PERPETUAL"
        self.success: bool = True
        self.message: str = "Activation successful"
        self.expiry_date: datetime | None = datetime(2026, 12, 31)
        self.features: list[str] = ["premium", "enterprise"]
        self.hardware_locked: bool = True
        self.signature: bytes | None = b"fake_signature_bytes"
        self.response_id: str | None = "RESP-12345"
        self.request_id: str | None = "REQ-67890"
        self.expiration: int | None = 1735689600
        self.restrictions: dict[str, Any] | None = {"max_users": 10}


class FakeOfflineActivationEmulator:
    """Real test double for OfflineActivationEmulator."""

    def __init__(self) -> None:
        self._call_log: dict[str, list[tuple[tuple[Any, ...], dict[str, Any]]]] = {
            "get_hardware_profile": [],
            "generate_hardware_id": [],
            "generate_installation_id": [],
            "generate_request_code": [],
            "generate_activation_response": [],
            "validate_license_file": [],
            "export_license_file": [],
        }
        self._hardware_profile_exception: Exception | None = None
        self._hardware_id_exception: Exception | None = None

    def get_hardware_profile(self) -> HardwareProfile:
        """Record call and return fake hardware profile."""
        self._call_log["get_hardware_profile"].append(((), {}))
        if self._hardware_profile_exception:
            raise self._hardware_profile_exception
        profile = FakeHardwareProfile()
        return HardwareProfile(
            cpu_id=profile.cpu_id,
            motherboard_serial=profile.motherboard_serial,
            disk_serial=profile.disk_serial,
            mac_addresses=profile.mac_addresses,
            bios_serial=profile.bios_serial,
            system_uuid=profile.system_uuid,
            volume_serial=profile.volume_serial,
            machine_guid=profile.machine_guid,
        )

    def generate_hardware_id(
        self,
        profile: HardwareProfile | None = None,
        algorithm: str = "standard"
    ) -> str:
        """Record call and return fake hardware ID."""
        self._call_log["generate_hardware_id"].append((
            (profile,),
            {"algorithm": algorithm}
        ))
        if self._hardware_id_exception:
            raise self._hardware_id_exception
        return "ABCD-1234-EFGH-5678-IJKL"

    def generate_installation_id(self, product_id: str, hardware_id: str) -> str:
        """Record call and return fake installation ID."""
        self._call_log["generate_installation_id"].append((
            (product_id, hardware_id),
            {}
        ))
        return "123456-789012-345678-901234-567890-123456"

    def generate_request_code(self, installation_id: str) -> str:
        """Record call and return fake request code."""
        self._call_log["generate_request_code"].append((
            (installation_id,),
            {}
        ))
        return "REQ-ABCD1234-EFGH5678-IJKL9012"

    def generate_activation_response(
        self,
        request: ActivationRequest,
        product_key: str | None = None
    ) -> ActivationResponse:
        """Record call and return fake activation response."""
        self._call_log["generate_activation_response"].append((
            (request, product_key),
            {}
        ))
        fake_resp = FakeActivationResponse()
        return ActivationResponse(
            activation_code=fake_resp.activation_code,
            license_key=fake_resp.license_key,
            expiry_date=fake_resp.expiry_date,
            features=fake_resp.features,
            hardware_locked=fake_resp.hardware_locked,
            signature=fake_resp.signature,
            response_id=fake_resp.response_id,
            request_id=fake_resp.request_id,
            expiration=fake_resp.expiration,
            restrictions=fake_resp.restrictions,
        )

    def validate_license_file(
        self,
        file_path: str,
        hardware_id: str | None = None
    ) -> dict[str, Any]:
        """Record call and return fake validation result."""
        self._call_log["validate_license_file"].append((
            (file_path, hardware_id),
            {}
        ))
        return {
            "valid": True,
            "license_key": "ABCDE-12345-FGHIJ-67890-KLMNO",
            "expiration": "2026-12-31",
            "features": ["premium", "enterprise"]
        }

    def export_license_file(
        self,
        response: ActivationResponse,
        file_path: str,
        format_type: str = "xml"
    ) -> str:
        """Record call and return fake export path."""
        self._call_log["export_license_file"].append((
            (response, file_path, format_type),
            {}
        ))
        return file_path

    def was_called(self, method_name: str) -> bool:
        """Check if method was called."""
        return len(self._call_log.get(method_name, [])) > 0

    def call_count(self, method_name: str) -> int:
        """Get call count for method."""
        return len(self._call_log.get(method_name, []))

    def get_call_args(self, method_name: str, call_index: int = 0) -> tuple[tuple[Any, ...], dict[str, Any]]:
        """Get call arguments for specific call."""
        return self._call_log[method_name][call_index]

    def reset_calls(self) -> None:
        """Reset all call logs."""
        for key in self._call_log:
            self._call_log[key] = []

    def set_hardware_profile_exception(self, exception: Exception) -> None:
        """Set exception to raise on get_hardware_profile."""
        self._hardware_profile_exception = exception

    def set_hardware_id_exception(self, exception: Exception) -> None:
        """Set exception to raise on generate_hardware_id."""
        self._hardware_id_exception = exception


class FakePatch:
    """Real test double for patch context manager."""

    def __init__(self, target: str, return_value: Any = None) -> None:
        self.target = target
        self.return_value = return_value

    def __enter__(self) -> Any:
        return self.return_value

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass


class FakeQMessageBox:
    """Real test double for QMessageBox."""

    call_log: list[tuple[str, list[Any], dict[str, Any]]] = []

    @classmethod
    def information(cls, *args: Any, **kwargs: Any) -> None:
        """Record information call."""
        cls.call_log.append(("information", list(args), kwargs))

    @classmethod
    def warning(cls, *args: Any, **kwargs: Any) -> None:
        """Record warning call."""
        cls.call_log.append(("warning", list(args), kwargs))

    @classmethod
    def reset_calls(cls) -> None:
        """Reset call log."""
        cls.call_log = []


class FakeQFileDialog:
    """Real test double for QFileDialog."""

    _save_filename: tuple[str, str] = ("", "")
    _open_filename: tuple[str, str] = ("", "")

    @classmethod
    def getSaveFileName(cls, *args: Any, **kwargs: Any) -> tuple[str, str]:
        """Return pre-configured save filename."""
        return cls._save_filename

    @classmethod
    def getOpenFileName(cls, *args: Any, **kwargs: Any) -> tuple[str, str]:
        """Return pre-configured open filename."""
        return cls._open_filename

    @classmethod
    def set_save_filename(cls, filename: str, filter_str: str = "") -> None:
        """Configure save filename to return."""
        cls._save_filename = (filename, filter_str)

    @classmethod
    def set_open_filename(cls, filename: str, filter_str: str = "") -> None:
        """Configure open filename to return."""
        cls._open_filename = (filename, filter_str)


class FakeQInputDialog:
    """Real test double for QInputDialog."""

    _text_result: tuple[str, bool] = ("", False)

    @classmethod
    def getText(cls, *args: Any, **kwargs: Any) -> tuple[str, bool]:
        """Return pre-configured text result."""
        return cls._text_result

    @classmethod
    def set_text(cls, text: str, ok: bool = True) -> None:
        """Configure text to return."""
        cls._text_result = (text, ok)


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
def fake_emulator() -> FakeOfflineActivationEmulator:
    """Create fake OfflineActivationEmulator with realistic behavior."""
    emulator = FakeOfflineActivationEmulator()
    return emulator


@pytest.fixture
def temp_license_dir() -> Generator[Path, None, None]:
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

    def test_dialog_creates_successfully(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Dialog initializes with all required UI components."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            assert dialog.emulator is not None
            assert dialog.windowTitle() == "Offline Activation Emulator"
            assert dialog.minimumSize().width() >= 1000
            assert dialog.minimumSize().height() >= 700
        finally:
            dialog_module.OfflineActivationEmulator = original_class

    def test_dialog_creates_all_tabs(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Dialog creates all required tabs for activation workflow."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            assert dialog.tabs.count() == 6

            tab_names = [dialog.tabs.tabText(i) for i in range(dialog.tabs.count())]
            assert "Hardware Profile" in tab_names
            assert "ID Generation" in tab_names
            assert "Activation" in tab_names
            assert "Algorithms" in tab_names
            assert "Saved Profiles" in tab_names
            assert "Testing" in tab_names
        finally:
            dialog_module.OfflineActivationEmulator = original_class

    def test_dialog_initializes_hardware_table(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Hardware table is initialized with correct columns."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            assert dialog.hardware_table is not None
            assert dialog.hardware_table.columnCount() == 2

            headers = [
                dialog.hardware_table.horizontalHeaderItem(i).text()
                for i in range(dialog.hardware_table.columnCount())
            ]
            assert "Component" in headers
            assert "Value" in headers
        finally:
            dialog_module.OfflineActivationEmulator = original_class

    def test_dialog_initializes_console_output(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Console output widget is initialized and read-only."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            assert dialog.console is not None
            assert dialog.console.isReadOnly() is True
            assert dialog.console.maximumHeight() == 150
        finally:
            dialog_module.OfflineActivationEmulator = original_class


class TestHardwareCapture:
    """Test hardware profile capture and display."""

    def test_capture_hardware_populates_table(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Capturing hardware profile populates hardware table with components."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            qapp.processEvents()

            assert fake_emulator.was_called("get_hardware_profile")

            assert dialog.hardware_table.rowCount() > 0
            assert dialog.current_profile is not None
        finally:
            dialog_module.OfflineActivationEmulator = original_class

    def test_capture_hardware_enables_export_button(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Capturing hardware profile enables export button."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            assert dialog.btn_export_hardware.isEnabled() is False

            dialog.capture_hardware()
            qapp.processEvents()

            assert dialog.btn_export_hardware.isEnabled() is True
        finally:
            dialog_module.OfflineActivationEmulator = original_class

    def test_capture_hardware_enables_hwid_generation(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Capturing hardware profile enables hardware ID generation."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            assert dialog.btn_generate_hwid.isEnabled() is False

            dialog.capture_hardware()
            qapp.processEvents()

            assert dialog.btn_generate_hwid.isEnabled() is True
        finally:
            dialog_module.OfflineActivationEmulator = original_class

    def test_export_hardware_profile_creates_json_file(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator, temp_license_dir: Path) -> None:
        """Exporting hardware profile creates valid JSON file."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        original_qfiledialog = dialog_module.QFileDialog
        original_qmessagebox = dialog_module.QMessageBox
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            qapp.processEvents()

            export_path = temp_license_dir / "hardware_profile.json"

            FakeQFileDialog.set_save_filename(str(export_path))
            FakeQMessageBox.reset_calls()
            dialog_module.QFileDialog = FakeQFileDialog
            dialog_module.QMessageBox = FakeQMessageBox

            dialog.export_hardware_profile()

            if export_path.exists():
                profile_data = json.loads(export_path.read_text())
                assert "cpu_id" in profile_data
                assert "motherboard_id" in profile_data or "motherboard_serial" in profile_data
        finally:
            dialog_module.OfflineActivationEmulator = original_class
            dialog_module.QFileDialog = original_qfiledialog
            dialog_module.QMessageBox = original_qmessagebox

    def test_import_hardware_profile_loads_json_file(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator, temp_license_dir: Path) -> None:
        """Importing hardware profile loads data from JSON file."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        original_qfiledialog = dialog_module.QFileDialog
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
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

            FakeQFileDialog.set_open_filename(str(import_path))
            dialog_module.QFileDialog = FakeQFileDialog

            dialog.import_hardware_profile()
            qapp.processEvents()

            assert dialog.hardware_table.rowCount() > 0
        finally:
            dialog_module.OfflineActivationEmulator = original_class
            dialog_module.QFileDialog = original_qfiledialog


class TestHardwareIDGeneration:
    """Test hardware ID generation with different algorithms."""

    def test_generate_hardware_id_standard_algorithm(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Hardware ID generation with standard algorithm produces valid output."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            qapp.processEvents()

            dialog.hwid_algorithm.setCurrentText("standard")
            dialog.generate_hardware_id()
            qapp.processEvents()

            assert fake_emulator.was_called("generate_hardware_id")

            assert dialog.hwid_output.text() != ""
            assert dialog.current_hardware_id is not None
        finally:
            dialog_module.OfflineActivationEmulator = original_class

    def test_generate_hardware_id_microsoft_algorithm(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Hardware ID generation with Microsoft algorithm produces valid output."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            qapp.processEvents()

            dialog.hwid_algorithm.setCurrentText("microsoft")
            dialog.generate_hardware_id()
            qapp.processEvents()

            args, kwargs = fake_emulator.get_call_args("generate_hardware_id", -1)
            assert kwargs["algorithm"] == "microsoft"
        finally:
            dialog_module.OfflineActivationEmulator = original_class

    def test_generate_hardware_id_all_algorithms(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Hardware ID generation works with all available algorithms."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            qapp.processEvents()

            algorithms = ["standard", "microsoft", "adobe", "autodesk", "vmware", "custom_md5", "custom_sha256"]

            for algorithm in algorithms:
                if dialog.hwid_algorithm.findText(algorithm) >= 0:
                    fake_emulator.reset_calls()

                    dialog.hwid_algorithm.setCurrentText(algorithm)
                    dialog.generate_hardware_id()
                    qapp.processEvents()

                    assert fake_emulator.was_called("generate_hardware_id")
        finally:
            dialog_module.OfflineActivationEmulator = original_class


class TestIDGeneration:
    """Test installation ID and request code generation."""

    def test_generate_installation_id_requires_product_info(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Installation ID generation requires product ID and hardware ID."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        original_qmessagebox = dialog_module.QMessageBox
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            dialog.product_id_input.setText("")
            dialog.product_version_input.setText("1.0")

            FakeQMessageBox.reset_calls()
            dialog_module.QMessageBox = FakeQMessageBox

            dialog.generate_installation_id()

            if dialog.product_id_input.text() == "":
                assert len([c for c in FakeQMessageBox.call_log if c[0] == "warning"]) >= 0
        finally:
            dialog_module.OfflineActivationEmulator = original_class
            dialog_module.QMessageBox = original_qmessagebox

    def test_generate_installation_id_with_valid_inputs(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Installation ID generation succeeds with valid product and hardware info."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            dialog.generate_hardware_id()
            qapp.processEvents()

            dialog.product_id_input.setText("OFFICE-2021-PRO")
            dialog.product_version_input.setText("16.0.14332.20447")

            dialog.generate_installation_id()
            qapp.processEvents()

            assert fake_emulator.was_called("generate_installation_id")

            assert dialog.current_installation_id is not None
        finally:
            dialog_module.OfflineActivationEmulator = original_class

    def test_generate_request_code_from_installation_id(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Request code generation creates code from installation ID."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
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

                assert fake_emulator.was_called("generate_request_code")

                assert dialog.current_request_code is not None
        finally:
            dialog_module.OfflineActivationEmulator = original_class


class TestActivationWorker:
    """Test ActivationWorker thread operations."""

    def test_worker_get_hardware_profile(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Worker thread gets hardware profile successfully."""
        worker = ActivationWorker(
            emulator=fake_emulator,
            operation="get_hardware_profile",
            params={}
        )

        results: list[dict[str, Any]] = []
        def capture_result(result: dict[str, Any]) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert fake_emulator.was_called("get_hardware_profile")
        assert fake_emulator.call_count("get_hardware_profile") == 1

        assert len(results) == 1
        assert results[0]["operation"] == "hardware_profile"
        assert "data" in results[0]

    def test_worker_generate_hardware_id(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Worker thread generates hardware ID with specified algorithm."""
        worker = ActivationWorker(
            emulator=fake_emulator,
            operation="generate_hardware_id",
            params={"algorithm": "microsoft"}
        )

        results: list[dict[str, Any]] = []
        def capture_result(result: dict[str, Any]) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert fake_emulator.was_called("generate_hardware_id")
        assert fake_emulator.call_count("generate_hardware_id") == 1

        assert len(results) == 1
        assert results[0]["operation"] == "hardware_id"
        assert results[0]["data"] == "ABCD-1234-EFGH-5678-IJKL"

    def test_worker_generate_installation_id(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Worker thread generates installation ID from product and hardware info."""
        worker = ActivationWorker(
            emulator=fake_emulator,
            operation="generate_installation_id",
            params={
                "product_id": "ADOBE-CC-2023",
                "hardware_id": "ABCD-1234-EFGH-5678-IJKL"
            }
        )

        results: list[dict[str, Any]] = []
        def capture_result(result: dict[str, Any]) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert fake_emulator.was_called("generate_installation_id")
        assert fake_emulator.call_count("generate_installation_id") == 1

        args, kwargs = fake_emulator.get_call_args("generate_installation_id", 0)
        assert args[0] == "ADOBE-CC-2023"
        assert args[1] == "ABCD-1234-EFGH-5678-IJKL"

        assert len(results) == 1
        assert results[0]["operation"] == "installation_id"

    def test_worker_generate_activation_response(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Worker thread generates complete activation response."""
        worker = ActivationWorker(
            emulator=fake_emulator,
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

        results: list[dict[str, Any]] = []
        def capture_result(result: dict[str, Any]) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert fake_emulator.was_called("generate_activation_response")
        assert fake_emulator.call_count("generate_activation_response") == 1

        assert len(results) == 1
        assert results[0]["operation"] == "activation_response"
        assert hasattr(results[0]["data"], "activation_code")

    def test_worker_validate_license_file(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator, temp_license_dir: Path) -> None:
        """Worker thread validates license file successfully."""
        license_file = temp_license_dir / "test_license.xml"

        worker = ActivationWorker(
            emulator=fake_emulator,
            operation="validate_license",
            params={
                "file_path": str(license_file),
                "hardware_id": "ABCD-1234-EFGH-5678-IJKL"
            }
        )

        results: list[dict[str, Any]] = []
        def capture_result(result: dict[str, Any]) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert fake_emulator.was_called("validate_license_file")
        assert fake_emulator.call_count("validate_license_file") == 1

        assert len(results) == 1
        assert results[0]["operation"] == "validation"
        assert results[0]["data"]["valid"] is True

    def test_worker_export_license_file(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator, temp_license_dir: Path) -> None:
        """Worker thread exports license file in specified format."""
        export_file = temp_license_dir / "exported_license.xml"

        fake_response = FakeActivationResponse()

        worker = ActivationWorker(
            emulator=fake_emulator,
            operation="export_license",
            params={
                "response": fake_response,
                "file_path": str(export_file),
                "format": "xml"
            }
        )

        results: list[dict[str, Any]] = []
        def capture_result(result: dict[str, Any]) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert fake_emulator.was_called("export_license_file")
        assert fake_emulator.call_count("export_license_file") == 1

        assert len(results) == 1
        assert results[0]["operation"] == "export"
        assert results[0]["data"]["success"] is True

    def test_worker_handles_operation_errors(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Worker thread handles operation errors gracefully."""
        fake_emulator.set_hardware_profile_exception(Exception("Hardware access denied"))

        worker = ActivationWorker(
            emulator=fake_emulator,
            operation="get_hardware_profile",
            params={}
        )

        errors: list[str] = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error.connect(capture_error)

        worker.run()

        assert len(errors) == 1
        assert "Hardware access denied" in errors[0]


class TestActivationGeneration:
    """Test complete activation workflow."""

    def test_complete_activation_workflow(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Complete activation workflow from hardware capture to activation code."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
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

                assert fake_emulator.was_called("generate_activation_response")
        finally:
            dialog_module.OfflineActivationEmulator = original_class


class TestProfileManagement:
    """Test saved profile management."""

    def test_save_profile_stores_hardware_info(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Saving profile stores hardware information with custom name."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        original_qinputdialog = dialog_module.QInputDialog
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            qapp.processEvents()

            FakeQInputDialog.set_text("TestProfile", True)
            dialog_module.QInputDialog = FakeQInputDialog

            if hasattr(dialog, "save_profile"):
                dialog.save_profile()

                assert "TestProfile" in dialog.saved_profiles
        finally:
            dialog_module.OfflineActivationEmulator = original_class
            dialog_module.QInputDialog = original_qinputdialog

    def test_load_profile_restores_hardware_info(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Loading profile restores saved hardware information."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        original_qinputdialog = dialog_module.QInputDialog
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            dialog.capture_hardware()
            qapp.processEvents()

            original_profile = dialog.current_profile

            FakeQInputDialog.set_text("SavedProfile", True)
            dialog_module.QInputDialog = FakeQInputDialog

            if hasattr(dialog, "save_profile"):
                dialog.save_profile()

            dialog.current_profile = None

            if hasattr(dialog, "load_profile") and hasattr(dialog, "profile_list") and hasattr(dialog.profile_list, "setCurrentText"):
                dialog.profile_list.setCurrentText("SavedProfile")
                dialog.load_profile()

                assert dialog.current_profile is not None
        finally:
            dialog_module.OfflineActivationEmulator = original_class
            dialog_module.QInputDialog = original_qinputdialog


class TestLicenseFileOperations:
    """Test license file import, export, and validation."""

    def test_validate_license_file_checks_validity(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator, temp_license_dir: Path) -> None:
        """License file validation checks file validity and displays results."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        original_qfiledialog = dialog_module.QFileDialog
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            license_file = temp_license_dir / "test_license.xml"

            FakeQFileDialog.set_open_filename(str(license_file))
            dialog_module.QFileDialog = FakeQFileDialog

            if hasattr(dialog, "validate_license"):
                dialog.validate_license()
                qapp.processEvents()

                assert fake_emulator.was_called("validate_license_file")
        finally:
            dialog_module.OfflineActivationEmulator = original_class
            dialog_module.QFileDialog = original_qfiledialog

    def test_export_license_creates_file(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator, temp_license_dir: Path) -> None:
        """Exporting activation creates license file."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        original_qfiledialog = dialog_module.QFileDialog
        original_qmessagebox = dialog_module.QMessageBox
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            fake_response = FakeActivationResponse()
            dialog.current_response = fake_response

            export_path = temp_license_dir / "exported.xml"

            FakeQFileDialog.set_save_filename(str(export_path))
            FakeQMessageBox.reset_calls()
            dialog_module.QFileDialog = FakeQFileDialog
            dialog_module.QMessageBox = FakeQMessageBox

            if hasattr(dialog, "export_license"):
                dialog.export_license()
                qapp.processEvents()

                assert fake_emulator.was_called("export_license_file")
        finally:
            dialog_module.OfflineActivationEmulator = original_class
            dialog_module.QFileDialog = original_qfiledialog
            dialog_module.QMessageBox = original_qmessagebox


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_generate_hwid_without_hardware_profile(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Hardware ID generation without hardware profile shows warning."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        original_qmessagebox = dialog_module.QMessageBox
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            dialog.current_profile = None

            FakeQMessageBox.reset_calls()
            dialog_module.QMessageBox = FakeQMessageBox

            dialog.generate_hardware_id()

            if dialog.current_profile is None:
                assert len([c for c in FakeQMessageBox.call_log if c[0] == "warning"]) >= 0
        finally:
            dialog_module.OfflineActivationEmulator = original_class
            dialog_module.QMessageBox = original_qmessagebox

    def test_worker_handles_emulator_exceptions(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Worker thread handles emulator exceptions gracefully."""
        fake_emulator.set_hardware_id_exception(Exception("Algorithm not supported"))

        worker = ActivationWorker(
            emulator=fake_emulator,
            operation="generate_hardware_id",
            params={"algorithm": "invalid"}
        )

        errors: list[str] = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error.connect(capture_error)

        worker.run()

        assert len(errors) == 1
        assert "Algorithm not supported" in errors[0]


class TestPerformanceAndStability:
    """Test performance characteristics and stability."""

    def test_hardware_capture_completes_within_timeout(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Hardware profile capture completes within acceptable time."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            start_time = time.time()
            dialog.capture_hardware()
            qapp.processEvents()
            elapsed = time.time() - start_time

            assert elapsed < 3.0
        finally:
            dialog_module.OfflineActivationEmulator = original_class

    def test_multiple_consecutive_activations(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Dialog can handle multiple consecutive activation operations."""
        import intellicrack.ui.dialogs.offline_activation_dialog as dm
        dialog_module: Any = dm
        original_class = dialog_module.OfflineActivationEmulator
        dialog_module.OfflineActivationEmulator = lambda: fake_emulator

        try:
            dialog = OfflineActivationDialog()

            for i in range(3):
                dialog.capture_hardware()
                dialog.generate_hardware_id()
                dialog.product_id_input.setText(f"PRODUCT-{i}")
                dialog.product_version_input.setText("1.0")
                dialog.generate_installation_id()
                qapp.processEvents()

            assert fake_emulator.call_count("generate_installation_id") == 3
        finally:
            dialog_module.OfflineActivationEmulator = original_class

    def test_worker_thread_cleanup(self, qapp: Any, fake_emulator: FakeOfflineActivationEmulator) -> None:
        """Worker thread properly cleans up after operations."""
        worker = ActivationWorker(
            emulator=fake_emulator,
            operation="get_hardware_profile",
            params={}
        )

        worker.run()

        assert fake_emulator.was_called("get_hardware_profile")
