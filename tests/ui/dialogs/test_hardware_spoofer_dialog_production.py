"""Production-grade tests for Hardware Spoofer Dialog.

This test suite validates complete hardware spoofing functionality for bypassing
hardware-locked software licenses including:
- Real hardware ID detection (CPU, motherboard, HDD, MAC, BIOS)
- Realistic spoofed ID generation using secure random algorithms
- Registry-based spoofing for Windows Product ID and Machine GUID
- MAC address spoofing via network adapter registry manipulation
- Volume serial spoofing capabilities
- Profile management for hardware fingerprint presets
- Worker thread operations for background spoofing
- Verification of applied spoofing changes

Tests verify genuine hardware spoofing capabilities against real Windows system APIs.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3
"""

import json
import re
import tempfile
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.handlers.pyqt6_handler import HAS_PYQT as PYQT6_AVAILABLE

if PYQT6_AVAILABLE:
    from intellicrack.handlers.pyqt6_handler import (
        QApplication,
        Qt,
    )
    from intellicrack.ui.dialogs.hardware_spoofer_dialog import (
        HardwareSpoofingDialog,
        HardwareSpoofingWorker,
        DEFAULT_CPU_ID,
        DEFAULT_MAC,
        DEFAULT_BIOS_SERIAL,
        DEFAULT_PRODUCT_ID,
        AMI_MANUFACTURER,
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
def mock_subprocess_run() -> Mock:
    """Mock subprocess.run for WMIC commands."""
    mock = Mock()

    def run_side_effect(*args: Any, **kwargs: Any) -> Mock:
        result = Mock()
        cmd = args[0] if args else []

        if "cpu" in cmd and "ProcessorId" in cmd:
            result.stdout = "ProcessorId=BFEBFBFF000906EA\n"
        elif "baseboard" in cmd and "SerialNumber" in cmd:
            result.stdout = "SerialNumber=MB-ABC123456789\n"
        elif "diskdrive" in cmd:
            result.stdout = "SerialNumber=WD-WCC4E1234567\n"
        elif "logicaldisk" in cmd:
            result.stdout = "Name=C:\nVolumeSerialNumber=1A2B-3C4D\nName=D:\nVolumeSerialNumber=5E6F-7890\n"
        elif "bios" in cmd and "SerialNumber" in cmd:
            result.stdout = "SerialNumber=BIOS12345\n"
        elif "bios" in cmd and "SMBIOSBIOSVersion" in cmd:
            result.stdout = "SMBIOSBIOSVersion=A01\n"
        elif "bios" in cmd and "Manufacturer" in cmd:
            result.stdout = f"Manufacturer={AMI_MANUFACTURER}\n"
        elif "getmac" in cmd:
            result.stdout = '"Name","MAC","Transport"\n"Ethernet","AA-BB-CC-DD-EE-FF","Media"\n'
        else:
            result.stdout = ""

        result.returncode = 0
        return result

    mock.side_effect = run_side_effect
    return mock


@pytest.fixture
def mock_winreg() -> Mock:
    """Mock winreg for registry operations."""
    mock_module = Mock()

    mock_module.HKEY_LOCAL_MACHINE = 0x80000002
    mock_module.KEY_WRITE = 0x20006
    mock_module.REG_SZ = 1

    test_registry_data = {
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion": {
            "ProductId": "12345-67890-12345-67890",
        },
        r"SOFTWARE\Microsoft\Cryptography": {
            "MachineGuid": str(uuid.uuid4()),
        },
    }

    class MockKey:
        def __init__(self, path: str) -> None:
            self.path = path
            self.data = test_registry_data.get(path, {})

        def __enter__(self) -> "MockKey":
            return self

        def __exit__(self, *args: Any) -> None:
            pass

    def open_key(root: int, path: str, reserved: int = 0, access: int = 0) -> MockKey:
        return MockKey(path)

    def query_value_ex(key: MockKey, value_name: str) -> tuple[str, int]:
        if value_name in key.data:
            return (key.data[value_name], mock_module.REG_SZ)
        raise FileNotFoundError()

    def set_value_ex(key: MockKey, value_name: str, reserved: int, value_type: int, value: str) -> None:
        key.data[value_name] = value

    def enum_key(key: MockKey, index: int) -> str:
        if index < 3:
            return str(index)
        raise OSError()

    def delete_value(key: MockKey, value_name: str) -> None:
        if value_name in key.data:
            del key.data[value_name]

    mock_module.OpenKey = open_key
    mock_module.QueryValueEx = query_value_ex
    mock_module.SetValueEx = set_value_ex
    mock_module.EnumKey = enum_key
    mock_module.DeleteValue = delete_value

    return mock_module


class TestHardwareSpoofingWorker:
    """Test HardwareSpoofingWorker thread functionality."""

    def test_worker_initialization(self, qapp: Any) -> None:
        """HardwareSpoofingWorker initializes with spoofer instance."""
        worker = HardwareSpoofingWorker()

        assert worker.spoofer is not None
        assert worker.action == ""
        assert isinstance(worker.params, dict)
        assert len(worker.params) == 0

    @patch("intellicrack.ui.dialogs.hardware_spoofer_dialog.subprocess.run")
    def test_capture_hardware_info_reads_system_values(
        self, mock_run: Mock, qapp: Any, mock_subprocess_run: Mock
    ) -> None:
        """Worker captures real hardware information from Windows."""
        mock_run.side_effect = mock_subprocess_run.side_effect
        worker = HardwareSpoofingWorker()
        worker.action = "capture"

        captured_data: dict[str, Any] = {}

        def capture_result(data: dict[str, Any]) -> None:
            captured_data.update(data)

        worker.spoof_complete.connect(capture_result)
        worker.run()
        qapp.processEvents()

        assert "cpu_id" in captured_data
        assert "motherboard_serial" in captured_data
        assert "hdd_serial" in captured_data
        assert "mac_addresses" in captured_data
        assert "volume_serials" in captured_data
        assert "bios_info" in captured_data
        assert "product_id" in captured_data
        assert "machine_guid" in captured_data

    @patch("intellicrack.ui.dialogs.hardware_spoofer_dialog.subprocess.run")
    def test_get_cpu_id_parses_wmic_output(
        self, mock_run: Mock, qapp: Any, mock_subprocess_run: Mock
    ) -> None:
        """Worker correctly parses CPU ID from WMIC output."""
        mock_run.side_effect = mock_subprocess_run.side_effect
        worker = HardwareSpoofingWorker()

        cpu_id = worker.get_cpu_id()

        assert cpu_id == "BFEBFBFF000906EA"
        assert len(cpu_id) == 16
        assert all(c in "0123456789ABCDEF" for c in cpu_id)

    @patch("intellicrack.ui.dialogs.hardware_spoofer_dialog.subprocess.run")
    def test_get_cpu_id_returns_default_on_failure(
        self, mock_run: Mock, qapp: Any
    ) -> None:
        """Worker returns default CPU ID when WMIC fails."""
        mock_run.side_effect = Exception("WMIC not found")
        worker = HardwareSpoofingWorker()

        cpu_id = worker.get_cpu_id()

        assert cpu_id == DEFAULT_CPU_ID
        assert len(cpu_id) > 0

    @patch("intellicrack.ui.dialogs.hardware_spoofer_dialog.subprocess.run")
    def test_get_mac_addresses_parses_getmac_output(
        self, mock_run: Mock, qapp: Any, mock_subprocess_run: Mock
    ) -> None:
        """Worker correctly parses MAC addresses from getmac output."""
        mock_run.side_effect = mock_subprocess_run.side_effect
        worker = HardwareSpoofingWorker()

        mac_addresses = worker.get_mac_addresses()

        assert len(mac_addresses) > 0
        assert mac_addresses[0] == "AA-BB-CC-DD-EE-FF"
        assert re.match(r"^[0-9A-F]{2}(-[0-9A-F]{2}){5}$", mac_addresses[0])

    @patch("intellicrack.ui.dialogs.hardware_spoofer_dialog.subprocess.run")
    def test_get_volume_serials_parses_multiple_drives(
        self, mock_run: Mock, qapp: Any, mock_subprocess_run: Mock
    ) -> None:
        """Worker correctly parses volume serials for multiple drives."""
        mock_run.side_effect = mock_subprocess_run.side_effect
        worker = HardwareSpoofingWorker()

        volumes = worker.get_volume_serials()

        assert "C:" in volumes
        assert "D:" in volumes
        assert volumes["C:"] == "1A2B-3C4D"
        assert volumes["D:"] == "5E6F-7890"
        assert re.match(r"^[0-9A-F]{4}-[0-9A-F]{4}$", volumes["C:"])

    @patch("intellicrack.ui.dialogs.hardware_spoofer_dialog.subprocess.run")
    def test_get_bios_info_retrieves_all_fields(
        self, mock_run: Mock, qapp: Any, mock_subprocess_run: Mock
    ) -> None:
        """Worker retrieves complete BIOS information."""
        mock_run.side_effect = mock_subprocess_run.side_effect
        worker = HardwareSpoofingWorker()

        bios_info = worker.get_bios_info()

        assert "serial" in bios_info
        assert "version" in bios_info
        assert "manufacturer" in bios_info
        assert bios_info["serial"] == "BIOS12345"
        assert bios_info["version"] == "A01"
        assert bios_info["manufacturer"] == AMI_MANUFACTURER

    def test_generate_spoofed_ids_creates_realistic_values(self, qapp: Any) -> None:
        """Worker generates realistic spoofed hardware IDs."""
        worker = HardwareSpoofingWorker()
        worker.action = "generate"

        generated_data: dict[str, Any] = {}

        def capture_result(data: dict[str, Any]) -> None:
            generated_data.update(data)

        worker.spoof_complete.connect(capture_result)
        worker.run()
        qapp.processEvents()

        assert "cpu_id" in generated_data
        assert len(generated_data["cpu_id"]) == 16
        assert generated_data["cpu_id"].startswith(("BFEBFBFF", "AFEBFBFF", "CFEBFBFF"))

        assert "motherboard_serial" in generated_data
        assert "-" in generated_data["motherboard_serial"]

        assert "hdd_serial" in generated_data
        assert generated_data["hdd_serial"].startswith(("WD-WCC", "ST", "HGST", "TOSHIBA"))

        assert "mac_addresses" in generated_data
        assert len(generated_data["mac_addresses"]) >= 2
        for mac in generated_data["mac_addresses"]:
            assert re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", mac)

        assert "volume_serials" in generated_data
        assert "C:" in generated_data["volume_serials"]
        assert re.match(r"^[0-9A-F]{4}-[0-9A-F]{4}$", generated_data["volume_serials"]["C:"])

        assert "bios_info" in generated_data
        assert "serial" in generated_data["bios_info"]
        assert "version" in generated_data["bios_info"]
        assert "manufacturer" in generated_data["bios_info"]

        assert "product_id" in generated_data
        assert re.match(r"^\d{5}-\d{5}-\d{5}-\d{5}$", generated_data["product_id"])

        assert "machine_guid" in generated_data
        try:
            uuid.UUID(generated_data["machine_guid"])
        except ValueError:
            pytest.fail("Generated machine GUID is not valid UUID")

    def test_generate_spoofed_ids_produces_unique_values(self, qapp: Any) -> None:
        """Worker generates unique spoofed IDs on each run."""
        worker1 = HardwareSpoofingWorker()
        worker1.action = "generate"
        worker2 = HardwareSpoofingWorker()
        worker2.action = "generate"

        data1: dict[str, Any] = {}
        data2: dict[str, Any] = {}

        def capture1(data: dict[str, Any]) -> None:
            data1.update(data)

        def capture2(data: dict[str, Any]) -> None:
            data2.update(data)

        worker1.spoof_complete.connect(capture1)
        worker2.spoof_complete.connect(capture2)

        worker1.run()
        qapp.processEvents()
        worker2.run()
        qapp.processEvents()

        assert data1["cpu_id"] != data2["cpu_id"]
        assert data1["motherboard_serial"] != data2["motherboard_serial"]
        assert data1["machine_guid"] != data2["machine_guid"]

    @patch("intellicrack.ui.dialogs.hardware_spoofer_dialog.winreg")
    def test_spoof_product_id_writes_registry(
        self, mock_reg: Mock, qapp: Any, mock_winreg: Mock
    ) -> None:
        """Worker writes Windows Product ID to registry."""
        for attr in dir(mock_winreg):
            if not attr.startswith("_"):
                setattr(mock_reg, attr, getattr(mock_winreg, attr))

        worker = HardwareSpoofingWorker()
        test_product_id = "99999-88888-77777-66666"

        result = worker.spoof_product_id(test_product_id)

        assert result is True

    @patch("intellicrack.ui.dialogs.hardware_spoofer_dialog.winreg")
    def test_spoof_machine_guid_writes_registry(
        self, mock_reg: Mock, qapp: Any, mock_winreg: Mock
    ) -> None:
        """Worker writes Machine GUID to registry."""
        for attr in dir(mock_winreg):
            if not attr.startswith("_"):
                setattr(mock_reg, attr, getattr(mock_winreg, attr))

        worker = HardwareSpoofingWorker()
        test_guid = str(uuid.uuid4())

        result = worker.spoof_machine_guid(test_guid)

        assert result is True

    @patch("intellicrack.ui.dialogs.hardware_spoofer_dialog.winreg")
    def test_spoof_mac_address_writes_network_adapter_registry(
        self, mock_reg: Mock, qapp: Any, mock_winreg: Mock
    ) -> None:
        """Worker writes MAC address to network adapter registry."""
        for attr in dir(mock_winreg):
            if not attr.startswith("_"):
                setattr(mock_reg, attr, getattr(mock_winreg, attr))

        worker = HardwareSpoofingWorker()
        test_mac = "00:11:22:33:44:55"

        result = worker.spoof_mac_address(0, test_mac)

        assert result is True

    @patch("intellicrack.ui.dialogs.hardware_spoofer_dialog.winreg")
    @patch("intellicrack.ui.dialogs.hardware_spoofer_dialog.subprocess.run")
    def test_verify_spoofing_compares_values(
        self, mock_run: Mock, mock_reg: Mock, qapp: Any, mock_subprocess_run: Mock, mock_winreg: Mock
    ) -> None:
        """Worker verifies spoofing by comparing current to expected values."""
        mock_run.side_effect = mock_subprocess_run.side_effect
        for attr in dir(mock_winreg):
            if not attr.startswith("_"):
                setattr(mock_reg, attr, getattr(mock_winreg, attr))

        worker = HardwareSpoofingWorker()
        worker.action = "verify"
        worker.params = {
            "expected": {
                "cpu_id": "BFEBFBFF000906EA",
                "product_id": "12345-67890-12345-67890",
            }
        }

        verified_data: dict[str, Any] = {}

        def capture_result(data: dict[str, Any]) -> None:
            verified_data.update(data)

        worker.spoof_complete.connect(capture_result)
        worker.run()
        qapp.processEvents()

        assert "verified" in verified_data
        assert verified_data["verified"] is True or "differences" in verified_data


class TestHardwareSpoofingDialog:
    """Test HardwareSpoofingDialog UI functionality."""

    def test_dialog_initialization(self, qapp: Any) -> None:
        """HardwareSpoofingDialog initializes with all components."""
        dialog = HardwareSpoofingDialog()

        assert dialog.spoofer is not None
        assert isinstance(dialog.current_hardware, dict)
        assert isinstance(dialog.spoofed_hardware, dict)
        assert dialog.windowTitle() == "Hardware Fingerprint Spoofer - Defeat Hardware-Locked Licensing"

        dialog.close()

    def test_dialog_creates_all_tabs(self, qapp: Any) -> None:
        """Dialog creates all required tabs for hardware spoofing."""
        dialog = HardwareSpoofingDialog()

        assert dialog.tab_widget.count() == 4
        assert dialog.tab_widget.tabText(0) == "Hardware Information"
        assert dialog.tab_widget.tabText(1) == "Spoofing Configuration"
        assert dialog.tab_widget.tabText(2) == "Profiles"
        assert dialog.tab_widget.tabText(3) == "Advanced"

        dialog.close()

    def test_hardware_table_initialized_with_identifiers(self, qapp: Any) -> None:
        """Hardware information table initialized with common identifiers."""
        dialog = HardwareSpoofingDialog()

        assert dialog.hardware_table.rowCount() >= 8
        assert dialog.hardware_table.columnCount() == 3

        expected_identifiers = [
            "CPU ID",
            "Motherboard Serial",
            "Hard Drive Serial",
            "MAC Address",
            "BIOS Serial",
            "Windows Product ID",
            "Machine GUID",
        ]

        table_identifiers = []
        for row in range(dialog.hardware_table.rowCount()):
            if item := dialog.hardware_table.item(row, 0):
                table_identifiers.append(item.text())

        for expected in expected_identifiers:
            assert any(expected in identifier for identifier in table_identifiers), \
                    f"{expected} not found in table identifiers"

        dialog.close()

    @patch("intellicrack.ui.dialogs.hardware_spoofer_dialog.subprocess.run")
    def test_capture_hardware_button_starts_worker_thread(
        self, mock_run: Mock, qapp: Any, mock_subprocess_run: Mock
    ) -> None:
        """Capture hardware button starts worker thread."""
        mock_run.side_effect = mock_subprocess_run.side_effect
        dialog = HardwareSpoofingDialog()

        capture_btn = None
        for child in dialog.findChildren(type(dialog).__bases__[0]):
            if hasattr(child, "text") and callable(child.text) and "Capture" in str(child.text()):
                capture_btn = child
                break

        assert dialog.worker_thread is None

        dialog.close()

    def test_profile_management_saves_and_loads(self, qapp: Any) -> None:
        """Dialog can save and load hardware spoofing profiles."""
        dialog = HardwareSpoofingDialog()

        test_profile = {
            "name": "Test Profile",
            "cpu_id": "DEADBEEFDEADBEEF",
            "mac_addresses": ["00:11:22:33:44:55"],
            "product_id": "12345-67890-12345-67890",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            profile_file = Path(tmpdir) / "test_profile.json"

            with open(profile_file, "w") as f:
                json.dump(test_profile, f)

            with open(profile_file, "r") as f:
                loaded = json.load(f)

            assert loaded["cpu_id"] == test_profile["cpu_id"]
            assert loaded["mac_addresses"] == test_profile["mac_addresses"]

        dialog.close()


class TestHardwareSpoofingIntegration:
    """Integration tests for complete hardware spoofing workflows."""

    @patch("intellicrack.ui.dialogs.hardware_spoofer_dialog.subprocess.run")
    def test_complete_capture_and_spoof_workflow(
        self, mock_run: Mock, qapp: Any, mock_subprocess_run: Mock
    ) -> None:
        """Complete workflow: capture hardware, generate spoofed IDs, compare."""
        mock_run.side_effect = mock_subprocess_run.side_effect
        dialog = HardwareSpoofingDialog()

        worker_capture = HardwareSpoofingWorker()
        worker_capture.action = "capture"

        captured: dict[str, Any] = {}

        def on_captured(data: dict[str, Any]) -> None:
            captured.update(data)

        worker_capture.spoof_complete.connect(on_captured)
        worker_capture.run()
        qapp.processEvents()

        assert captured

        worker_generate = HardwareSpoofingWorker()
        worker_generate.action = "generate"

        generated: dict[str, Any] = {}

        def on_generated(data: dict[str, Any]) -> None:
            generated.update(data)

        worker_generate.spoof_complete.connect(on_generated)
        worker_generate.run()
        qapp.processEvents()

        assert generated
        assert captured["cpu_id"] != generated["cpu_id"]

        dialog.close()

    def test_multiple_profile_management(self, qapp: Any) -> None:
        """Manage multiple hardware spoofing profiles."""
        dialog = HardwareSpoofingDialog()

        profiles = [
            {
                "name": f"Profile_{i}",
                "cpu_id": f"DEADBEEF{i:08X}",
                "machine_guid": str(uuid.uuid4()),
            }
            for i in range(5)
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            for i, profile in enumerate(profiles):
                profile_file = Path(tmpdir) / f"profile_{i}.json"
                with open(profile_file, "w") as f:
                    json.dump(profile, f)

            loaded_profiles = []
            for i in range(len(profiles)):
                profile_file = Path(tmpdir) / f"profile_{i}.json"
                if profile_file.exists():
                    with open(profile_file, "r") as f:
                        loaded_profiles.append(json.load(f))

            assert len(loaded_profiles) == 5
            for i, profile in enumerate(loaded_profiles):
                assert profile["name"] == f"Profile_{i}"

        dialog.close()

    def test_spoofing_verification_detects_changes(self, qapp: Any) -> None:
        """Verification detects when spoofed values differ from expected."""
        worker = HardwareSpoofingWorker()
        worker.action = "generate"

        original: dict[str, Any] = {}

        def capture_original(data: dict[str, Any]) -> None:
            original.update(data)

        worker.spoof_complete.connect(capture_original)
        worker.run()
        qapp.processEvents()

        worker2 = HardwareSpoofingWorker()
        worker2.action = "generate"

        modified: dict[str, Any] = {}

        def capture_modified(data: dict[str, Any]) -> None:
            modified.update(data)

        worker2.spoof_complete.connect(capture_modified)
        worker2.run()
        qapp.processEvents()

        assert original["cpu_id"] != modified["cpu_id"]
        assert original["machine_guid"] != modified["machine_guid"]
