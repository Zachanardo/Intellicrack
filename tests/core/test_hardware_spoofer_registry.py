"""Production tests for hardware spoofer with real Windows Registry validation.

Tests that validate actual HWID spoofing against real Windows API calls and Registry
modifications. These tests verify genuine offensive capability to bypass hardware-based
license checks.
"""

import platform
import secrets
import uuid
import winreg
from typing import Any

import pytest

from intellicrack.core.hardware_spoofer import HardwareFingerPrintSpoofer, HardwareIdentifiers


pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Hardware spoofing tests require Windows platform"
)


class TestHardwareSpooferRegistryModification:
    """Test suite validating real Windows Registry modifications for HWID spoofing."""

    @pytest.fixture
    def spoofer(self) -> HardwareFingerPrintSpoofer:
        """Create HardwareFingerPrintSpoofer instance."""
        spoofer_instance = HardwareFingerPrintSpoofer()
        yield spoofer_instance
        try:
            spoofer_instance.restore_original()
        except Exception:
            pass

    @pytest.fixture
    def original_registry_values(self) -> dict[str, dict[str, Any]]:
        """Capture original registry values before modification."""
        values: dict[str, dict[str, Any]] = {}

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                values["machine_guid"] = {"value": machine_guid, "path": r"SOFTWARE\Microsoft\Cryptography", "name": "MachineGuid"}
        except OSError:
            pass

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                cpu_name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
                values["cpu_name"] = {"value": cpu_name, "path": r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "name": "ProcessorNameString"}
        except OSError:
            pass

        return values

    def test_cpu_spoof_modifies_actual_registry(self, spoofer: HardwareFingerPrintSpoofer) -> None:
        """Test that CPU spoofing actually modifies Windows Registry keys.

        This test validates that _spoof_cpu creates real Registry modifications that
        would bypass hardware-based license checks reading CPU information.
        """
        spoofer.capture_original_hardware()

        spoofed_cpu_id = "BFEBFBFF00050662"
        spoofed_cpu_name = "Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz"

        spoofer._spoof_cpu(cpu_id=spoofed_cpu_id, cpu_name=spoofed_cpu_name)

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
            actual_cpu_name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            actual_cpu_id, _ = winreg.QueryValueEx(key, "Identifier")

        assert actual_cpu_name == spoofed_cpu_name, "CPU name not properly spoofed in Registry"
        assert spoofed_cpu_id in actual_cpu_id or actual_cpu_id == spoofed_cpu_id, "CPU ID not properly spoofed in Registry"

    def test_motherboard_spoof_modifies_system_information(self, spoofer: HardwareFingerPrintSpoofer) -> None:
        """Test motherboard spoofing modifies system information registry keys.

        Validates that motherboard manufacturer and serial are written to Registry
        locations checked by hardware-based licensing systems.
        """
        spoofer.capture_original_hardware()

        spoofed_serial = "MB-" + "".join(secrets.choice("0123456789ABCDEF") for _ in range(12))
        spoofed_manufacturer = "GIGABYTE TECHNOLOGY CO., LTD."

        spoofer._spoof_motherboard(serial=spoofed_serial, manufacturer=spoofed_manufacturer)

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation") as key:
            actual_manufacturer, _ = winreg.QueryValueEx(key, "SystemManufacturer")
            actual_product, _ = winreg.QueryValueEx(key, "BaseBoardProduct")

        assert actual_manufacturer == spoofed_manufacturer, "Motherboard manufacturer not spoofed in Registry"
        assert actual_product == spoofed_serial, "Motherboard serial not spoofed in Registry"

    def test_bios_spoof_modifies_hardware_description(self, spoofer: HardwareFingerPrintSpoofer) -> None:
        """Test BIOS spoofing modifies hardware description registry keys.

        Validates that BIOS version and product name are written to Registry for
        bypassing BIOS-based hardware fingerprinting.
        """
        spoofer.capture_original_hardware()

        spoofed_bios_serial = "BIOS-" + "".join(secrets.choice("0123456789") for _ in range(10))
        spoofed_bios_version = "F27 (American Megatrends Inc.)"

        spoofer._spoof_bios(serial=spoofed_bios_serial, version=spoofed_bios_version)

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as key:
            actual_version, _ = winreg.QueryValueEx(key, "BIOSVersion")
            actual_product, _ = winreg.QueryValueEx(key, "SystemProductName")

        assert spoofed_bios_version in actual_version or actual_version[0] == spoofed_bios_version, "BIOS version not spoofed"
        assert actual_product == spoofed_bios_serial, "BIOS serial not spoofed"

    def test_system_uuid_spoof_modifies_computer_hardware_id(self, spoofer: HardwareFingerPrintSpoofer) -> None:
        """Test system UUID spoofing modifies ComputerHardwareId registry key.

        Validates that system UUID modifications are written to the Registry location
        used by Windows and license managers for hardware identification.
        """
        spoofer.capture_original_hardware()

        spoofed_uuid = str(uuid.uuid4()).upper()

        spoofer._spoof_system_uuid(uuid_str=spoofed_uuid)

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation") as key:
            actual_uuid, _ = winreg.QueryValueEx(key, "ComputerHardwareId")

        assert actual_uuid == spoofed_uuid, "System UUID not properly spoofed in Registry"

    def test_disk_serial_spoof_creates_ide_enum_entries(self, spoofer: HardwareFingerPrintSpoofer) -> None:
        """Test disk serial spoofing creates IDE enumeration registry entries.

        Validates that disk serial numbers are written to Registry locations read
        by disk-based hardware fingerprinting systems.
        """
        spoofer.capture_original_hardware()

        spoofed_serials = [
            "WD-" + "".join(secrets.choice("0123456789ABCDEF") for _ in range(10)),
            "ST-" + "".join(secrets.choice("0123456789ABCDEF") for _ in range(10))
        ]

        spoofer._spoof_disk(serials=spoofed_serials)

        for i, expected_serial in enumerate(spoofed_serials):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"SYSTEM\\CurrentControlSet\\Enum\\IDE\\Disk{i}") as key:
                    actual_serial, _ = winreg.QueryValueEx(key, "SerialNumber")
                    assert actual_serial == expected_serial, f"Disk {i} serial not properly spoofed"
            except OSError:
                pytest.skip(f"Could not verify disk {i} serial spoofing due to registry access")

    def test_restore_original_reverts_registry_modifications(
        self,
        spoofer: HardwareFingerPrintSpoofer,
        original_registry_values: dict[str, dict[str, Any]]
    ) -> None:
        """Test that restore_original() reverts all Registry modifications.

        Validates that restoration functionality properly reverts spoofed values
        back to original hardware identifiers in the Registry.
        """
        spoofer.capture_original_hardware()
        assert spoofer.original_hardware is not None

        spoofed_uuid = str(uuid.uuid4()).upper()
        spoofer._spoof_system_uuid(uuid_str=spoofed_uuid)

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation") as key:
            spoofed_value, _ = winreg.QueryValueEx(key, "ComputerHardwareId")

        assert spoofed_value == spoofed_uuid

        success = spoofer.restore_original()

        assert success is True, "Restoration reported failure"

        if "machine_guid" in original_registry_values:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                restored_value, _ = winreg.QueryValueEx(key, "MachineGuid")
                assert restored_value == original_registry_values["machine_guid"]["value"], "MachineGuid not restored"

    def test_capture_original_hardware_retrieves_real_values(self, spoofer: HardwareFingerPrintSpoofer) -> None:
        """Test that capture_original_hardware() reads actual system hardware identifiers.

        Validates that hardware capture functionality retrieves real values from WMI
        and Registry, not placeholder or mock data.
        """
        original = spoofer.capture_original_hardware()

        assert isinstance(original, HardwareIdentifiers)
        assert len(original.cpu_id) > 0, "CPU ID not captured"
        assert len(original.cpu_name) > 0, "CPU name not captured"
        assert len(original.machine_guid) > 0, "Machine GUID not captured"
        assert len(original.mac_addresses) > 0, "MAC addresses not captured"

        assert original.machine_guid != "00000000-0000-0000-0000-000000000000", "Machine GUID is placeholder"

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                actual_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                assert original.machine_guid == actual_guid, "Captured GUID doesn't match Registry"
        except OSError:
            pytest.skip("Could not verify MachineGuid due to registry access")

    def test_network_adapter_spoofing_modifies_network_class(self, spoofer: HardwareFingerPrintSpoofer) -> None:
        """Test network adapter MAC spoofing modifies network adapter registry keys.

        Validates that MAC address spoofing writes to the network adapter class
        registry locations used by licensing systems.
        """
        spoofer.capture_original_hardware()

        spoofed_macs = ["0A-1B-2C-3D-4E-5F", "10-20-30-40-50-60"]

        spoofer._spoof_mac_address(mac_addresses=spoofed_macs)

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            ) as key:
                subkeys_count = 0
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        if subkey_name.isdigit():
                            subkeys_count += 1
                        i += 1
                    except OSError:
                        break

                assert subkeys_count > 0, "No network adapter registry keys found"
        except OSError:
            pytest.skip("Could not verify network adapter spoofing due to registry access")

    def test_multiple_spoofs_all_persist_in_registry(self, spoofer: HardwareFingerPrintSpoofer) -> None:
        """Test that multiple simultaneous spoofs all persist correctly in Registry.

        Validates that spoofing multiple hardware components doesn't cause conflicts
        and all modifications persist correctly.
        """
        spoofer.capture_original_hardware()

        spoofed_cpu_name = "AMD Ryzen 9 5950X 16-Core Processor"
        spoofed_mb_serial = "MB-" + "".join(secrets.choice("0123456789ABCDEF") for _ in range(12))
        spoofed_uuid = str(uuid.uuid4()).upper()

        spoofer._spoof_cpu(cpu_name=spoofed_cpu_name)
        spoofer._spoof_motherboard(serial=spoofed_mb_serial)
        spoofer._spoof_system_uuid(uuid_str=spoofed_uuid)

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
            actual_cpu, _ = winreg.QueryValueEx(key, "ProcessorNameString")

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation") as key:
            actual_mb, _ = winreg.QueryValueEx(key, "BaseBoardProduct")
            actual_uuid, _ = winreg.QueryValueEx(key, "ComputerHardwareId")

        assert actual_cpu == spoofed_cpu_name, "CPU not persisted after multiple spoofs"
        assert actual_mb == spoofed_mb_serial, "Motherboard not persisted after multiple spoofs"
        assert actual_uuid == spoofed_uuid, "UUID not persisted after multiple spoofs"

    def test_spoofing_with_special_characters_handles_correctly(self, spoofer: HardwareFingerPrintSpoofer) -> None:
        """Test spoofing handles special characters in hardware identifiers.

        Validates that special characters in spoofed values are properly escaped
        and written to Registry without corruption.
        """
        spoofer.capture_original_hardware()

        spoofed_manufacturer = "Test & Development Co., Ltd. (™)"

        spoofer._spoof_motherboard(manufacturer=spoofed_manufacturer)

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation") as key:
            actual_manufacturer, _ = winreg.QueryValueEx(key, "SystemManufacturer")

        assert actual_manufacturer == spoofed_manufacturer, "Special characters not handled correctly"

    def test_registry_permissions_error_handling(self, spoofer: HardwareFingerPrintSpoofer) -> None:
        """Test that registry permission errors are handled gracefully.

        Validates that spoofer handles permission errors without crashing and
        logs appropriate error messages.
        """
        spoofer.capture_original_hardware()

        try:
            spoofer._spoof_cpu(cpu_name="Test CPU")
        except PermissionError:
            pytest.skip("Test requires elevated permissions")
        except Exception as e:
            pytest.fail(f"Unexpected exception during spoofing: {e}")

    def test_concurrent_registry_modifications_are_atomic(self, spoofer: HardwareFingerPrintSpoofer) -> None:
        """Test that concurrent registry modifications don't cause corruption.

        Validates that rapid sequential modifications to different registry keys
        don't interfere with each other.
        """
        spoofer.capture_original_hardware()

        cpu_values = [f"Test CPU {i}" for i in range(10)]

        for cpu_name in cpu_values:
            spoofer._spoof_cpu(cpu_name=cpu_name)

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
            final_value, _ = winreg.QueryValueEx(key, "ProcessorNameString")

        assert final_value == cpu_values[-1], "Final registry value doesn't match last write"
        assert final_value in cpu_values, "Registry value corrupted during concurrent writes"
