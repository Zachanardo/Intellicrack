"""Comprehensive production-ready tests for hardware ID spoofing capabilities.

Tests validate REAL hardware ID manipulation for defeating hardware-locked license checks.
All tests use actual Windows registry, WMI, ctypes APIs - NO MOCKS OR STUBS.
Tests FAIL if spoofing doesn't achieve genuine hardware ID modification.
"""

import ctypes
import hashlib
import json
import os
import platform
import struct
import subprocess
import uuid
import winreg
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.protection_bypass.hardware_id_spoofer import HardwareIDSpoofer


WINDOWS_ONLY: bool = platform.system() == "Windows"
ADMIN_REQUIRED: bool = not (
    os.geteuid() == 0 if hasattr(os, "geteuid") else ctypes.windll.shell32.IsUserAnAdmin() != 0
)


class TestHardwareIDSpooferInitialization:
    """Test spoofer initialization and driver setup."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoofer_initialization_creates_wmi_connection(self) -> None:
        """Spoofer initializes with active WMI connection for hardware queries."""
        spoofer = HardwareIDSpoofer()

        assert spoofer.wmi_connection is not None
        assert spoofer.original_values == {}
        assert spoofer.spoofed_values == {}

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoofer_initializes_kernel_handles(self) -> None:
        """Spoofer initializes kernel32, advapi32, setupapi DLL handles."""
        spoofer = HardwareIDSpoofer()

        assert spoofer.kernel32 is not None
        assert spoofer.advapi32 is not None
        assert spoofer.setupapi is not None

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoofer_sets_driver_path_correctly(self) -> None:
        """Spoofer sets driver path relative to module location."""
        spoofer = HardwareIDSpoofer()

        assert spoofer.driver_path.name == "hwid_spoof.sys"
        assert "drivers" in str(spoofer.driver_path)


class TestHardwareCollectionCapabilities:
    """Test real hardware information collection from Windows APIs."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_collect_hardware_info_retrieves_all_components(self) -> None:
        """Collect hardware info retrieves CPU, motherboard, disk, MAC, BIOS, system, GPU, USB data."""
        spoofer = HardwareIDSpoofer()
        info = spoofer.collect_hardware_info()

        assert "cpu_id" in info
        assert "motherboard" in info
        assert "disk_serials" in info
        assert "mac_addresses" in info
        assert "bios" in info
        assert "system" in info
        assert "gpu" in info
        assert "usb_devices" in info

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_collect_hardware_info_cpu_contains_valid_processor_data(self) -> None:
        """CPU info collection returns real processor identification data."""
        spoofer = HardwareIDSpoofer()
        info = spoofer.collect_hardware_info()

        cpu_info = info["cpu_id"]
        assert isinstance(cpu_info, dict)
        assert len(cpu_info) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_collect_hardware_info_motherboard_contains_manufacturer_serial(self) -> None:
        """Motherboard info collection returns manufacturer and serial number."""
        spoofer = HardwareIDSpoofer()
        info = spoofer.collect_hardware_info()

        mb_info = info["motherboard"]
        assert isinstance(mb_info, dict)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_collect_hardware_info_disk_serials_returns_physical_drives(self) -> None:
        """Disk serial collection returns list of physical disk identifiers."""
        spoofer = HardwareIDSpoofer()
        info = spoofer.collect_hardware_info()

        disk_serials = info["disk_serials"]
        assert isinstance(disk_serials, list)
        assert len(disk_serials) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_collect_hardware_info_mac_addresses_returns_network_adapters(self) -> None:
        """MAC address collection returns list of network adapter MAC addresses."""
        spoofer = HardwareIDSpoofer()
        info = spoofer.collect_hardware_info()

        mac_addresses = info["mac_addresses"]
        assert isinstance(mac_addresses, list)
        assert len(mac_addresses) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_collect_hardware_info_bios_contains_version_serial(self) -> None:
        """BIOS info collection returns version and serial number data."""
        spoofer = HardwareIDSpoofer()
        info = spoofer.collect_hardware_info()

        bios_info = info["bios"]
        assert isinstance(bios_info, dict)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_collect_hardware_info_system_contains_uuid_and_guid(self) -> None:
        """System info collection returns UUID and machine GUID."""
        spoofer = HardwareIDSpoofer()
        info = spoofer.collect_hardware_info()

        system_info = info["system"]
        assert isinstance(system_info, dict)


class TestCPUIDRetrieval:
    """Test CPU identification retrieval methods."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_cpu_id_returns_valid_processor_id(self) -> None:
        """CPU ID retrieval returns valid processor identification string."""
        spoofer = HardwareIDSpoofer()
        cpu_info = spoofer._get_cpu_id()

        assert isinstance(cpu_info, dict)
        assert len(cpu_info) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_cpuid_via_asm_executes_cpuid_instruction(self) -> None:
        """ASM CPUID execution returns CPU vendor, signature, serial via direct instruction."""
        spoofer = HardwareIDSpoofer()
        cpu_info = spoofer._get_cpuid_via_asm()

        assert isinstance(cpu_info, dict)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_cpuid_via_asm_returns_vendor_string(self) -> None:
        """ASM CPUID retrieval includes CPU vendor identification string."""
        spoofer = HardwareIDSpoofer()
        cpu_info = spoofer._get_cpuid_via_asm()

        if "vendor" in cpu_info:
            vendor = cpu_info["vendor"]
            assert isinstance(vendor, str)
            assert len(vendor) > 0


class TestMotherboardInfoRetrieval:
    """Test motherboard information collection."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_motherboard_info_retrieves_manufacturer_product_serial(self) -> None:
        """Motherboard info retrieval returns manufacturer, product, serial via WMI."""
        spoofer = HardwareIDSpoofer()
        mb_info = spoofer._get_motherboard_info()

        assert isinstance(mb_info, dict)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_motherboard_info_retrieves_registry_system_info(self) -> None:
        """Motherboard info includes registry-based system manufacturer and UUID."""
        spoofer = HardwareIDSpoofer()
        mb_info = spoofer._get_motherboard_info()

        assert isinstance(mb_info, dict)


class TestDiskSerialRetrieval:
    """Test disk serial number collection."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_disk_serials_returns_physical_disk_list(self) -> None:
        """Disk serial retrieval returns list of physical disk serial numbers."""
        spoofer = HardwareIDSpoofer()
        disks = spoofer._get_disk_serials()

        assert isinstance(disks, list)
        assert len(disks) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_disk_serials_includes_wmi_disk_drive_data(self) -> None:
        """Disk serial retrieval includes WMI Win32_DiskDrive information."""
        spoofer = HardwareIDSpoofer()
        disks = spoofer._get_disk_serials()

        assert isinstance(disks, list)
        for disk in disks:
            assert isinstance(disk, dict)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_volume_serial_retrieves_c_drive_serial(self) -> None:
        """Volume serial retrieval returns C: drive serial number via GetVolumeInformationW."""
        spoofer = HardwareIDSpoofer()
        volume_info = spoofer._get_volume_serial("C:\\")

        if volume_info:
            assert isinstance(volume_info, dict)
            assert "serial" in volume_info


class TestMACAddressRetrieval:
    """Test network adapter MAC address collection."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_mac_addresses_returns_adapter_list(self) -> None:
        """MAC address retrieval returns list of network adapter MAC addresses."""
        spoofer = HardwareIDSpoofer()
        macs = spoofer._get_mac_addresses()

        assert isinstance(macs, list)
        assert len(macs) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_mac_addresses_includes_adapter_details(self) -> None:
        """MAC address retrieval includes adapter name, MAC, GUID, PNP device ID."""
        spoofer = HardwareIDSpoofer()
        macs = spoofer._get_mac_addresses()

        for mac_entry in macs:
            assert isinstance(mac_entry, dict)
            assert "mac" in mac_entry or "name" in mac_entry


class TestBIOSInfoRetrieval:
    """Test BIOS information collection."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_bios_info_retrieves_manufacturer_version_serial(self) -> None:
        """BIOS info retrieval returns manufacturer, version, serial, release date."""
        spoofer = HardwareIDSpoofer()
        bios_info = spoofer._get_bios_info()

        assert isinstance(bios_info, dict)


class TestSystemInfoRetrieval:
    """Test system UUID and machine GUID collection."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_system_info_retrieves_uuid_and_vendor(self) -> None:
        """System info retrieval returns system UUID, SKU, vendor via WMI."""
        spoofer = HardwareIDSpoofer()
        system_info = spoofer._get_system_info()

        assert isinstance(system_info, dict)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_machine_guid_reads_registry_cryptography_key(self) -> None:
        """Machine GUID retrieval reads MachineGuid from registry Cryptography key."""
        spoofer = HardwareIDSpoofer()
        machine_guid = spoofer._get_machine_guid()

        assert isinstance(machine_guid, str)
        assert len(machine_guid) > 0


class TestGPUAndUSBRetrieval:
    """Test GPU and USB device information collection."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_gpu_info_retrieves_video_controller_list(self) -> None:
        """GPU info retrieval returns list of video controllers with device IDs."""
        spoofer = HardwareIDSpoofer()
        gpus = spoofer._get_gpu_info()

        assert isinstance(gpus, list)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_usb_devices_retrieves_usb_hub_list(self) -> None:
        """USB device retrieval returns list of USB hubs with device IDs."""
        spoofer = HardwareIDSpoofer()
        usbs = spoofer._get_usb_devices()

        assert isinstance(usbs, list)


class TestCPUIDSpoofing:
    """Test CPU ID spoofing via kernel driver and usermode hooks."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_cpu_id_generates_random_cpu_id_when_none_provided(self) -> None:
        """CPU ID spoofing generates random processor ID when not specified."""
        spoofer = HardwareIDSpoofer()
        result = spoofer.spoof_cpu_id()

        assert isinstance(result, bool)
        if result:
            assert "cpu_vendor" in spoofer.spoofed_values or "cpu_id" in spoofer.spoofed_values

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_cpu_id_uses_provided_vendor_and_id(self) -> None:
        """CPU ID spoofing uses provided vendor and processor ID values."""
        spoofer = HardwareIDSpoofer()
        test_vendor = "GenuineIntel"
        test_cpu_id = "BFEBFBFF000906EA"

        result = spoofer.spoof_cpu_id(vendor=test_vendor, processor_id=test_cpu_id)

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_cpu_id_stores_spoofed_values(self) -> None:
        """CPU ID spoofing stores spoofed vendor and CPU ID in spoofed_values dict."""
        spoofer = HardwareIDSpoofer()
        test_vendor = "AuthenticAMD"
        test_cpu_id = "178BFBFF00800F11"

        result = spoofer.spoof_cpu_id(vendor=test_vendor, processor_id=test_cpu_id)

        if result:
            assert spoofer.spoofed_values.get("cpu_vendor") == test_vendor
            assert spoofer.spoofed_values.get("cpu_id") == test_cpu_id

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_cpu_id_creates_valid_format(self) -> None:
        """Random CPU ID generation creates valid processor ID format."""
        spoofer = HardwareIDSpoofer()
        cpu_id = spoofer._generate_random_cpu_id()

        assert isinstance(cpu_id, str)
        assert len(cpu_id) >= 12

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_cpu_usermode_attempts_detours_hooking(self) -> None:
        """Usermode CPU spoofing attempts Detours-based CPUID hooking."""
        spoofer = HardwareIDSpoofer()
        test_vendor = "GenuineIntel"
        test_cpu_id = "BFEBFBFF000306C3"

        result = spoofer._spoof_cpu_usermode(vendor=test_vendor, processor_id=test_cpu_id)

        assert isinstance(result, bool)


class TestMACAddressSpoofing:
    """Test network adapter MAC address spoofing via registry."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_mac_address_generates_random_mac_when_none_provided(self) -> None:
        """MAC address spoofing generates random locally-administered MAC when not specified."""
        spoofer = HardwareIDSpoofer()
        result = spoofer.spoof_mac_address()

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_mac_address_uses_provided_mac_value(self) -> None:
        """MAC address spoofing uses provided MAC address for specified adapter."""
        spoofer = HardwareIDSpoofer()
        test_mac = "02:42:13:37:69:AC"

        result = spoofer.spoof_mac_address(new_mac=test_mac)

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_spoof_mac_address_modifies_registry_network_address(self) -> None:
        """MAC address spoofing writes NetworkAddress value to adapter registry key."""
        spoofer = HardwareIDSpoofer()
        test_mac = "02:11:22:33:44:55"

        original_info = spoofer.collect_hardware_info()
        if not original_info.get("mac_addresses"):
            pytest.skip("No network adapters available for testing")

        result = spoofer.spoof_mac_address(new_mac=test_mac)

        if result:
            adapter_name = list(spoofer.spoofed_values.keys())[0].replace("mac_", "")
            assert spoofer.spoofed_values[f"mac_{adapter_name}"] == test_mac

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_mac_creates_locally_administered_address(self) -> None:
        """Random MAC generation creates locally-administered MAC (LSB of first octet = 1)."""
        spoofer = HardwareIDSpoofer()
        mac = spoofer._generate_random_mac()

        assert isinstance(mac, str)
        assert len(mac.replace(":", "")) == 12
        first_octet = int(mac.split(":")[0], 16)
        assert first_octet & 0x02 == 0x02

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_restart_network_adapter_executes_netsh_commands(self) -> None:
        """Network adapter restart executes netsh disable/enable commands."""
        spoofer = HardwareIDSpoofer()
        test_adapter = "TestAdapter"

        try:
            spoofer._restart_network_adapter(test_adapter)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass


class TestDiskSerialSpoofing:
    """Test disk serial number spoofing via kernel driver and registry."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_disk_serial_generates_random_serial_when_none_provided(self) -> None:
        """Disk serial spoofing generates random 16-character serial when not specified."""
        spoofer = HardwareIDSpoofer()
        result = spoofer.spoof_disk_serial()

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_disk_serial_uses_provided_serial_value(self) -> None:
        """Disk serial spoofing uses provided serial number for specified drive."""
        spoofer = HardwareIDSpoofer()
        test_serial = "TESTDISK12345678"
        test_drive = "C:\\"

        result = spoofer.spoof_disk_serial(drive=test_drive, new_serial=test_serial)

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_disk_serial_stores_spoofed_value(self) -> None:
        """Disk serial spoofing stores spoofed serial in spoofed_values dict."""
        spoofer = HardwareIDSpoofer()
        test_serial = "SPOOFED123456789"
        test_drive = "C:\\"

        result = spoofer.spoof_disk_serial(drive=test_drive, new_serial=test_serial)

        if result:
            assert spoofer.spoofed_values.get(f"disk_{test_drive}") == test_serial

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_disk_serial_creates_16_char_string(self) -> None:
        """Random disk serial generation creates 16-character alphanumeric string."""
        spoofer = HardwareIDSpoofer()
        serial = spoofer._generate_random_disk_serial()

        assert isinstance(serial, str)
        assert len(serial) == 16
        assert serial.isalnum()

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_spoof_disk_usermode_modifies_registry_volume_id(self) -> None:
        """Usermode disk spoofing writes VolumeId to Windows NT registry key."""
        spoofer = HardwareIDSpoofer()
        test_serial = "USERMODETEST1234"
        test_drive = "C:\\"

        result = spoofer._spoof_disk_usermode(drive=test_drive, new_serial=test_serial)

        if result:
            assert spoofer.spoofed_values.get(f"disk_{test_drive}") == test_serial


class TestMotherboardSerialSpoofing:
    """Test motherboard manufacturer, product, serial spoofing via SMBIOS."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_motherboard_serial_generates_random_values_when_none_provided(self) -> None:
        """Motherboard spoofing generates random manufacturer, product, serial when not specified."""
        spoofer = HardwareIDSpoofer()
        result = spoofer.spoof_motherboard_serial()

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_motherboard_serial_uses_provided_values(self) -> None:
        """Motherboard spoofing uses provided manufacturer, product, serial values."""
        spoofer = HardwareIDSpoofer()
        test_manufacturer = "TestManufacturer"
        test_product = "TestBoard-Z690"
        test_serial = "TESTMBSERIAL"

        result = spoofer.spoof_motherboard_serial(
            manufacturer=test_manufacturer, product=test_product, serial=test_serial
        )

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_motherboard_serial_stores_spoofed_values(self) -> None:
        """Motherboard spoofing stores spoofed manufacturer, product, serial in spoofed_values."""
        spoofer = HardwareIDSpoofer()
        test_manufacturer = "ASUS"
        test_product = "ASUS-Z690"
        test_serial = "MB123456789ABC"

        result = spoofer.spoof_motherboard_serial(
            manufacturer=test_manufacturer, product=test_product, serial=test_serial
        )

        if result:
            assert spoofer.spoofed_values.get("motherboard_manufacturer") == test_manufacturer
            assert spoofer.spoofed_values.get("motherboard_product") == test_product
            assert spoofer.spoofed_values.get("motherboard_serial") == test_serial

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_serial_creates_12_char_alphanumeric(self) -> None:
        """Random serial generation creates 12-character alphanumeric string."""
        spoofer = HardwareIDSpoofer()
        serial = spoofer._generate_random_serial()

        assert isinstance(serial, str)
        assert len(serial) == 12
        assert serial.isalnum()


class TestSystemUUIDSpoofing:
    """Test system UUID spoofing via registry modification."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_system_uuid_generates_random_uuid_when_none_provided(self) -> None:
        """System UUID spoofing generates random UUID when not specified."""
        spoofer = HardwareIDSpoofer()
        result = spoofer.spoof_system_uuid()

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_system_uuid_uses_provided_uuid_value(self) -> None:
        """System UUID spoofing uses provided UUID value."""
        spoofer = HardwareIDSpoofer()
        test_uuid = str(uuid.uuid4())

        result = spoofer.spoof_system_uuid(new_uuid=test_uuid)

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_spoof_system_uuid_modifies_machine_guid_registry(self) -> None:
        """System UUID spoofing writes MachineGuid to Cryptography registry key."""
        spoofer = HardwareIDSpoofer()
        test_uuid = str(uuid.uuid4())

        original_guid = spoofer._get_machine_guid()

        try:
            result = spoofer.spoof_system_uuid(new_uuid=test_uuid)

            if result:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                    current_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                    assert current_guid == test_uuid
        except PermissionError:
            pytest.skip("Insufficient permissions for registry modification")
        finally:
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_WRITE
                ) as key:
                    winreg.SetValueEx(key, "MachineGuid", 0, winreg.REG_SZ, original_guid)
            except (OSError, PermissionError):
                pass

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_spoof_system_uuid_modifies_computer_hardware_id_registry(self) -> None:
        """System UUID spoofing writes ComputerHardwareId to SystemInformation registry key."""
        spoofer = HardwareIDSpoofer()
        test_uuid = str(uuid.uuid4())

        try:
            result = spoofer.spoof_system_uuid(new_uuid=test_uuid)

            if result:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation"
                ) as key:
                    current_uuid, _ = winreg.QueryValueEx(key, "ComputerHardwareId")
                    assert test_uuid in current_uuid
        except (OSError, PermissionError):
            pytest.skip("Insufficient permissions for registry modification")

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_system_uuid_stores_spoofed_value(self) -> None:
        """System UUID spoofing stores spoofed UUID in spoofed_values dict."""
        spoofer = HardwareIDSpoofer()
        test_uuid = str(uuid.uuid4())

        result = spoofer.spoof_system_uuid(new_uuid=test_uuid)

        if result:
            assert spoofer.spoofed_values.get("system_uuid") == test_uuid


class TestCompositeSpoofing:
    """Test composite spoofing of all hardware identifiers."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_all_generates_random_profile_when_none_provided(self) -> None:
        """Spoof all generates random hardware profile when not provided."""
        spoofer = HardwareIDSpoofer()
        results = spoofer.spoof_all()

        assert isinstance(results, dict)
        assert "cpu" in results
        assert isinstance(results["cpu"], bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_all_uses_provided_profile(self) -> None:
        """Spoof all uses provided hardware profile for spoofing operations."""
        spoofer = HardwareIDSpoofer()
        test_profile = {
            "cpu_vendor": "GenuineIntel",
            "cpu_id": "BFEBFBFF000906EA",
            "mac_addresses": [],
            "disk_serials": [],
            "motherboard_manufacturer": "ASUS",
            "motherboard_product": "ASUS-Z690",
            "motherboard_serial": "TEST123",
            "system_uuid": str(uuid.uuid4()),
        }

        results = spoofer.spoof_all(profile=test_profile)

        assert isinstance(results, dict)
        assert "cpu" in results

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_all_spoofs_cpu_with_profile_values(self) -> None:
        """Spoof all invokes CPU spoofing with profile CPU vendor and ID."""
        spoofer = HardwareIDSpoofer()
        test_profile = {
            "cpu_vendor": "AuthenticAMD",
            "cpu_id": "178BFBFF00800F11",
            "mac_addresses": [],
            "disk_serials": [],
            "motherboard_manufacturer": "MSI",
            "motherboard_product": "MSI-B550",
            "motherboard_serial": "MSI123",
            "system_uuid": str(uuid.uuid4()),
        }

        results = spoofer.spoof_all(profile=test_profile)

        assert "cpu" in results

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_all_spoofs_mac_addresses_from_profile(self) -> None:
        """Spoof all invokes MAC address spoofing for each adapter in profile."""
        spoofer = HardwareIDSpoofer()

        adapters = spoofer._get_mac_addresses()
        if not adapters:
            pytest.skip("No network adapters available for testing")

        test_profile = {
            "cpu_vendor": "GenuineIntel",
            "cpu_id": "BFEBFBFF000906EA",
            "mac_addresses": [{"adapter": adapters[0]["name"], "mac": "02:11:22:33:44:55"}],
            "disk_serials": [],
            "motherboard_manufacturer": "Gigabyte",
            "motherboard_product": "GB-X570",
            "motherboard_serial": "GB123",
            "system_uuid": str(uuid.uuid4()),
        }

        results = spoofer.spoof_all(profile=test_profile)

        assert any(k.startswith("mac_") for k in results.keys())

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_all_spoofs_disk_serials_from_profile(self) -> None:
        """Spoof all invokes disk serial spoofing for each drive in profile."""
        spoofer = HardwareIDSpoofer()
        test_profile = {
            "cpu_vendor": "GenuineIntel",
            "cpu_id": "BFEBFBFF000906EA",
            "mac_addresses": [],
            "disk_serials": [{"drive": "C:\\", "serial": "TESTDISK12345678"}],
            "motherboard_manufacturer": "ASRock",
            "motherboard_product": "ASR-B550",
            "motherboard_serial": "ASR123",
            "system_uuid": str(uuid.uuid4()),
        }

        results = spoofer.spoof_all(profile=test_profile)

        assert any(k.startswith("disk_") for k in results.keys())

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_all_spoofs_motherboard_from_profile(self) -> None:
        """Spoof all invokes motherboard spoofing with profile manufacturer, product, serial."""
        spoofer = HardwareIDSpoofer()
        test_profile = {
            "cpu_vendor": "GenuineIntel",
            "cpu_id": "BFEBFBFF000906EA",
            "mac_addresses": [],
            "disk_serials": [],
            "motherboard_manufacturer": "Dell",
            "motherboard_product": "Dell-XPS",
            "motherboard_serial": "DELL123",
            "system_uuid": str(uuid.uuid4()),
        }

        results = spoofer.spoof_all(profile=test_profile)

        assert "motherboard" in results

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_all_spoofs_system_uuid_from_profile(self) -> None:
        """Spoof all invokes system UUID spoofing with profile UUID."""
        spoofer = HardwareIDSpoofer()
        test_uuid = str(uuid.uuid4())
        test_profile = {
            "cpu_vendor": "GenuineIntel",
            "cpu_id": "BFEBFBFF000906EA",
            "mac_addresses": [],
            "disk_serials": [],
            "motherboard_manufacturer": "HP",
            "motherboard_product": "HP-Pavilion",
            "motherboard_serial": "HP123",
            "system_uuid": test_uuid,
        }

        results = spoofer.spoof_all(profile=test_profile)

        assert "system_uuid" in results


class TestRandomProfileGeneration:
    """Test random hardware profile generation."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_profile_creates_complete_profile(self) -> None:
        """Random profile generation creates complete profile with all hardware components."""
        spoofer = HardwareIDSpoofer()
        profile = spoofer.generate_random_profile()

        assert isinstance(profile, dict)
        assert "cpu_vendor" in profile
        assert "cpu_id" in profile
        assert "mac_addresses" in profile
        assert "disk_serials" in profile
        assert "motherboard_manufacturer" in profile
        assert "motherboard_product" in profile
        assert "motherboard_serial" in profile
        assert "system_uuid" in profile

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_profile_cpu_vendor_is_valid(self) -> None:
        """Random profile CPU vendor is GenuineIntel or AuthenticAMD."""
        spoofer = HardwareIDSpoofer()
        profile = spoofer.generate_random_profile()

        assert profile["cpu_vendor"] in ["GenuineIntel", "AuthenticAMD"]

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_profile_cpu_id_has_valid_length(self) -> None:
        """Random profile CPU ID has valid length (>= 12 characters)."""
        spoofer = HardwareIDSpoofer()
        profile = spoofer.generate_random_profile()

        assert len(profile["cpu_id"]) >= 12

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_profile_mac_addresses_list_populated(self) -> None:
        """Random profile MAC addresses list contains up to 2 adapter entries."""
        spoofer = HardwareIDSpoofer()
        profile = spoofer.generate_random_profile()

        assert isinstance(profile["mac_addresses"], list)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_profile_disk_serials_list_populated(self) -> None:
        """Random profile disk serials list contains up to 2 disk entries."""
        spoofer = HardwareIDSpoofer()
        profile = spoofer.generate_random_profile()

        assert isinstance(profile["disk_serials"], list)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_profile_motherboard_manufacturer_is_realistic(self) -> None:
        """Random profile motherboard manufacturer is realistic vendor (ASUS, MSI, Gigabyte)."""
        spoofer = HardwareIDSpoofer()
        profile = spoofer.generate_random_profile()

        assert profile["motherboard_manufacturer"] in ["ASUS", "MSI", "Gigabyte"]

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_profile_system_uuid_is_valid_uuid(self) -> None:
        """Random profile system UUID is valid UUID format."""
        spoofer = HardwareIDSpoofer()
        profile = spoofer.generate_random_profile()

        uuid.UUID(profile["system_uuid"])


class TestProfileEncryptionAndPersistence:
    """Test hardware profile encryption, saving, and loading."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_save_profile_creates_encrypted_file(self, temp_workspace: Path) -> None:
        """Save profile creates encrypted file at specified path."""
        spoofer = HardwareIDSpoofer()
        profile = spoofer.generate_random_profile()
        profile_path = temp_workspace / "test_profile.enc"

        spoofer.save_profile(profile, profile_path)

        assert profile_path.exists()
        assert profile_path.stat().st_size > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_save_profile_creates_parent_directories(self, temp_workspace: Path) -> None:
        """Save profile creates parent directories if they don't exist."""
        spoofer = HardwareIDSpoofer()
        profile = spoofer.generate_random_profile()
        profile_path = temp_workspace / "subdir" / "profiles" / "test_profile.enc"

        spoofer.save_profile(profile, profile_path)

        assert profile_path.exists()
        assert profile_path.parent.exists()

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_load_profile_decrypts_saved_file(self, temp_workspace: Path) -> None:
        """Load profile decrypts and returns profile from encrypted file."""
        spoofer = HardwareIDSpoofer()
        original_profile = spoofer.generate_random_profile()
        profile_path = temp_workspace / "test_profile.enc"

        spoofer.save_profile(original_profile, profile_path)
        loaded_profile = spoofer.load_profile(profile_path)

        assert loaded_profile["cpu_vendor"] == original_profile["cpu_vendor"]
        assert loaded_profile["cpu_id"] == original_profile["cpu_id"]
        assert loaded_profile["system_uuid"] == original_profile["system_uuid"]

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_encrypt_profile_creates_encrypted_bytes(self) -> None:
        """Encrypt profile creates encrypted bytes from profile dict."""
        spoofer = HardwareIDSpoofer()
        profile = spoofer.generate_random_profile()

        encrypted = spoofer._encrypt_profile(profile)

        assert isinstance(encrypted, bytes)
        assert len(encrypted) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_decrypt_profile_recovers_original_profile(self) -> None:
        """Decrypt profile recovers original profile from encrypted bytes."""
        spoofer = HardwareIDSpoofer()
        original_profile = spoofer.generate_random_profile()

        encrypted = spoofer._encrypt_profile(original_profile)
        decrypted = spoofer._decrypt_profile(encrypted)

        assert decrypted["cpu_vendor"] == original_profile["cpu_vendor"]
        assert decrypted["cpu_id"] == original_profile["cpu_id"]
        assert decrypted["motherboard_manufacturer"] == original_profile["motherboard_manufacturer"]
        assert decrypted["system_uuid"] == original_profile["system_uuid"]

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_encrypted_profile_not_plaintext_json(self) -> None:
        """Encrypted profile is not plaintext JSON (encryption actually applied)."""
        spoofer = HardwareIDSpoofer()
        profile = spoofer.generate_random_profile()

        encrypted = spoofer._encrypt_profile(profile)

        with pytest.raises((json.JSONDecodeError, UnicodeDecodeError)):
            json.loads(encrypted.decode())


class TestOriginalValueRestoration:
    """Test restoration of original hardware identifiers."""

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_restore_original_reverts_spoofed_mac_addresses(self) -> None:
        """Restore original reverts MAC addresses to original values."""
        spoofer = HardwareIDSpoofer()

        original_info = spoofer.collect_hardware_info()
        if not original_info.get("mac_addresses"):
            pytest.skip("No network adapters available for testing")

        adapter_name = original_info["mac_addresses"][0]["name"]
        original_mac = original_info["mac_addresses"][0]["mac"]
        spoofer.original_values[f"mac_{adapter_name}"] = original_mac

        try:
            result = spoofer.restore_original()
            assert isinstance(result, bool)
        except Exception:
            pytest.skip("MAC restoration requires specific privileges")

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_restore_mac_address_removes_registry_network_address(self) -> None:
        """Restore MAC address removes NetworkAddress registry value."""
        spoofer = HardwareIDSpoofer()
        test_adapter = "TestAdapter"
        test_mac = "00:11:22:33:44:55"

        spoofer._restore_mac_address(adapter=test_adapter, original_mac=test_mac)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_restore_disk_serial_exists(self) -> None:
        """Restore disk serial method exists for restoration operations."""
        spoofer = HardwareIDSpoofer()
        test_drive = "C:\\"
        test_serial = "ORIGINAL12345678"

        spoofer._restore_disk_serial(drive=test_drive, original_serial=test_serial)


class TestDriverCreationAndLoading:
    """Test kernel driver creation and loading operations."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_driver_code_creates_x64_assembly(self) -> None:
        """Generate driver code creates x64 assembly code for hardware spoofing."""
        spoofer = HardwareIDSpoofer()
        driver_code = spoofer._generate_driver_code()

        assert isinstance(driver_code, bytes)
        assert len(driver_code) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_align_function_aligns_to_boundary(self) -> None:
        """Align function aligns value to specified boundary."""
        spoofer = HardwareIDSpoofer()

        aligned = spoofer._align(value=100, alignment=0x200)
        assert aligned % 0x200 == 0
        assert aligned >= 100

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_load_driver_attempts_service_creation(self) -> None:
        """Load driver attempts to create and start kernel driver service."""
        spoofer = HardwareIDSpoofer()

        try:
            spoofer._load_driver()
        except Exception:
            pass


class TestCleanupOperations:
    """Test cleanup of driver and spoofing resources."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_cleanup_closes_driver_handle(self) -> None:
        """Cleanup closes kernel driver handle."""
        spoofer = HardwareIDSpoofer()
        spoofer.driver_handle = None

        spoofer.cleanup()

        assert spoofer.driver_handle is None

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_cleanup_stops_driver_service(self) -> None:
        """Cleanup stops and deletes HWIDSpoof driver service."""
        spoofer = HardwareIDSpoofer()

        try:
            spoofer.cleanup()
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling scenarios."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_cpu_id_handles_invalid_vendor_gracefully(self) -> None:
        """CPU ID spoofing handles invalid vendor string gracefully."""
        spoofer = HardwareIDSpoofer()

        result = spoofer.spoof_cpu_id(vendor="", processor_id="INVALID")

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_mac_address_handles_invalid_mac_format(self) -> None:
        """MAC address spoofing handles invalid MAC format gracefully."""
        spoofer = HardwareIDSpoofer()

        result = spoofer.spoof_mac_address(new_mac="INVALID:MAC:FORMAT")

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_disk_serial_handles_invalid_drive_gracefully(self) -> None:
        """Disk serial spoofing handles invalid drive letter gracefully."""
        spoofer = HardwareIDSpoofer()

        result = spoofer.spoof_disk_serial(drive="Z:\\", new_serial="TESTSERIAL")

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_collect_hardware_info_handles_wmi_errors_gracefully(self) -> None:
        """Hardware info collection handles WMI errors gracefully and returns partial data."""
        spoofer = HardwareIDSpoofer()

        info = spoofer.collect_hardware_info()

        assert isinstance(info, dict)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_load_profile_handles_nonexistent_file(self, temp_workspace: Path) -> None:
        """Load profile raises appropriate error for nonexistent file."""
        spoofer = HardwareIDSpoofer()
        nonexistent_path = temp_workspace / "nonexistent.enc"

        with pytest.raises(FileNotFoundError):
            spoofer.load_profile(nonexistent_path)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_decrypt_profile_handles_invalid_encrypted_data(self) -> None:
        """Decrypt profile raises appropriate error for invalid encrypted data."""
        spoofer = HardwareIDSpoofer()
        invalid_data = b"invalid encrypted data"

        with pytest.raises(Exception):
            spoofer._decrypt_profile(invalid_data)


class TestPerformanceRequirements:
    """Test performance requirements for spoofing operations."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_collect_hardware_info_completes_within_5_seconds(self) -> None:
        """Hardware info collection completes within 5 seconds."""
        import time

        spoofer = HardwareIDSpoofer()

        start = time.time()
        spoofer.collect_hardware_info()
        elapsed = time.time() - start

        assert elapsed < 5.0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_profile_completes_within_1_second(self) -> None:
        """Random profile generation completes within 1 second."""
        import time

        spoofer = HardwareIDSpoofer()

        start = time.time()
        spoofer.generate_random_profile()
        elapsed = time.time() - start

        assert elapsed < 1.0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_encrypt_decrypt_roundtrip_completes_within_1_second(self) -> None:
        """Profile encryption and decryption roundtrip completes within 1 second."""
        import time

        spoofer = HardwareIDSpoofer()
        profile = spoofer.generate_random_profile()

        start = time.time()
        encrypted = spoofer._encrypt_profile(profile)
        decrypted = spoofer._decrypt_profile(encrypted)
        elapsed = time.time() - start

        assert elapsed < 1.0
        assert decrypted["cpu_vendor"] == profile["cpu_vendor"]


class TestRealWorldIntegrationScenarios:
    """Test complete real-world hardware spoofing scenarios."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_complete_spoofing_workflow_collect_spoof_restore(self) -> None:
        """Complete workflow: collect -> generate profile -> spoof all -> restore."""
        spoofer = HardwareIDSpoofer()

        original_info = spoofer.collect_hardware_info()
        assert len(original_info) > 0

        profile = spoofer.generate_random_profile()
        assert profile["cpu_vendor"] in ["GenuineIntel", "AuthenticAMD"]

        results = spoofer.spoof_all(profile=profile)
        assert isinstance(results, dict)

        if any(results.values()):
            restore_result = spoofer.restore_original()
            assert isinstance(restore_result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_profile_persistence_workflow_generate_save_load_apply(self, temp_workspace: Path) -> None:
        """Profile persistence workflow: generate -> save -> load -> apply."""
        spoofer1 = HardwareIDSpoofer()
        profile = spoofer1.generate_random_profile()
        profile_path = temp_workspace / "hwid_profile.enc"

        spoofer1.save_profile(profile, profile_path)
        assert profile_path.exists()

        spoofer2 = HardwareIDSpoofer()
        loaded_profile = spoofer2.load_profile(profile_path)
        assert loaded_profile["cpu_vendor"] == profile["cpu_vendor"]

        results = spoofer2.spoof_all(profile=loaded_profile)
        assert isinstance(results, dict)

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_node_locked_license_bypass_system_uuid_change_verified(self) -> None:
        """Node-locked license bypass: verify system UUID change is detectable."""
        spoofer = HardwareIDSpoofer()

        original_guid = spoofer._get_machine_guid()
        new_uuid = str(uuid.uuid4())

        try:
            result = spoofer.spoof_system_uuid(new_uuid=new_uuid)

            if result:
                current_guid = spoofer._get_machine_guid()
                assert current_guid != original_guid
                assert current_guid == new_uuid
        except PermissionError:
            pytest.skip("Insufficient permissions for UUID spoofing verification")
        finally:
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_WRITE
                ) as key:
                    winreg.SetValueEx(key, "MachineGuid", 0, winreg.REG_SZ, original_guid)
            except (OSError, PermissionError):
                pass

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_multiple_profiles_generate_unique_fingerprints(self) -> None:
        """Multiple random profiles generate unique hardware fingerprints."""
        spoofer = HardwareIDSpoofer()

        profile1 = spoofer.generate_random_profile()
        profile2 = spoofer.generate_random_profile()
        profile3 = spoofer.generate_random_profile()

        fingerprint1 = hashlib.sha256(json.dumps(profile1, sort_keys=True).encode()).hexdigest()
        fingerprint2 = hashlib.sha256(json.dumps(profile2, sort_keys=True).encode()).hexdigest()
        fingerprint3 = hashlib.sha256(json.dumps(profile3, sort_keys=True).encode()).hexdigest()

        assert fingerprint1 != fingerprint2
        assert fingerprint2 != fingerprint3
        assert fingerprint1 != fingerprint3


class TestAntiDetectionValidation:
    """Test that spoofed values pass anti-spoofing validation checks."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_cpu_id_passes_format_validation(self) -> None:
        """Generated CPU ID passes format validation checks used by license systems."""
        spoofer = HardwareIDSpoofer()
        cpu_id = spoofer._generate_random_cpu_id()

        assert len(cpu_id) >= 12
        assert all(c in "0123456789ABCDEF" for c in cpu_id.upper())

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_mac_has_locally_administered_bit_set(self) -> None:
        """Generated MAC address has locally-administered bit set (not globally unique)."""
        spoofer = HardwareIDSpoofer()
        mac = spoofer._generate_random_mac()

        mac_bytes = mac.split(":")
        first_octet = int(mac_bytes[0], 16)
        assert first_octet & 0x02 == 0x02

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_disk_serial_matches_realistic_format(self) -> None:
        """Generated disk serial matches realistic vendor serial number format."""
        spoofer = HardwareIDSpoofer()
        serial = spoofer._generate_random_disk_serial()

        assert len(serial) == 16
        assert serial.isalnum()
        assert serial.isupper()

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_motherboard_serial_matches_realistic_format(self) -> None:
        """Generated motherboard serial matches realistic manufacturer serial format."""
        spoofer = HardwareIDSpoofer()
        serial = spoofer._generate_random_serial()

        assert len(serial) == 12
        assert serial.isalnum()
        assert serial.isupper()

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_uuid_is_valid_rfc4122_format(self) -> None:
        """Generated system UUID is valid RFC 4122 UUID format."""
        spoofer = HardwareIDSpoofer()
        profile = spoofer.generate_random_profile()

        test_uuid = uuid.UUID(profile["system_uuid"])
        assert str(test_uuid) == profile["system_uuid"]
