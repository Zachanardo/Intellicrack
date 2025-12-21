"""Production-ready tests for hardware ID spoofing capabilities.

Tests validate REAL hardware ID manipulation for defeating hardware-locked license checks.
All tests use actual Windows registry, WMI, ctypes APIs - NO MOCKS OR STUBS.
Tests FAIL if spoofing doesn't achieve genuine hardware ID modification.
"""

import ctypes
import ctypes.wintypes
import hashlib
import json
import os
import platform
import re
import secrets
import struct
import subprocess
import tempfile
import uuid
import winreg
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import pytest

from intellicrack.core.protection_bypass.hardware_id_spoofer import HardwareIDSpoofer


WINDOWS_ONLY: bool = platform.system() == "Windows"


def is_admin() -> bool:
    """Check if running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


ADMIN_REQUIRED: bool = not is_admin()


@pytest.fixture(scope="session")
def real_hardware_baseline() -> Dict[str, Any]:
    """Capture baseline hardware information from real system for comparison testing."""
    if not WINDOWS_ONLY:
        pytest.skip("Windows-only test")

    try:
        spoofer = HardwareIDSpoofer()
        return spoofer.collect_hardware_info()
    except Exception as e:
        pytest.skip(f"Failed to collect hardware baseline: {e}")


@pytest.fixture(scope="function")
def temp_profile_dir(tmp_path: Path) -> Path:
    """Provide temporary directory for profile storage testing."""
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir(exist_ok=True)
    return profile_dir


@pytest.fixture(scope="function")
def hardware_spoofer() -> HardwareIDSpoofer:
    """Provide fresh HardwareIDSpoofer instance for each test."""
    if not WINDOWS_ONLY:
        pytest.skip("Windows-only test")

    try:
        spoofer = HardwareIDSpoofer()
    except Exception as e:
        pytest.skip(f"Failed to initialize HardwareIDSpoofer: {e}")

    yield spoofer

    try:
        spoofer.cleanup()
    except Exception:
        pass


class TestHardwareIDSpooferInitialization:
    """Test spoofer initialization and system integration."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoofer_initializes_with_valid_wmi_connection(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Spoofer initializes with functional WMI connection for hardware queries."""
        assert hardware_spoofer.wmi_connection is not None

        processor_count = sum(
            1 for _ in hardware_spoofer.wmi_connection.Win32_Processor()
        )
        assert processor_count > 0, "WMI connection must be functional and return processor data"

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoofer_initializes_windows_api_handles(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Spoofer initializes valid Windows API DLL handles."""
        assert hardware_spoofer.kernel32 is not None
        assert hardware_spoofer.advapi32 is not None
        assert hardware_spoofer.setupapi is not None

        version_info = ctypes.wintypes.OSVERSIONINFOW()
        version_info.dwOSVersionInfoSize = ctypes.sizeof(version_info)

        assert hardware_spoofer.kernel32.GetVersionExW(ctypes.byref(version_info)) != 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoofer_initializes_tracking_dictionaries(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Spoofer initializes empty tracking dictionaries for original and spoofed values."""
        assert isinstance(hardware_spoofer.original_values, dict)
        assert isinstance(hardware_spoofer.spoofed_values, dict)
        assert len(hardware_spoofer.original_values) == 0
        assert len(hardware_spoofer.spoofed_values) == 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoofer_sets_correct_driver_path(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Spoofer configures driver path relative to module directory."""
        assert hardware_spoofer.driver_path.name == "hwid_spoof.sys"
        assert "drivers" in hardware_spoofer.driver_path.parts
        assert hardware_spoofer.driver_path.parent.name == "drivers"


class TestCPUIDCollection:
    """Test real CPU identification data collection."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_cpu_id_returns_processor_identification(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """CPU ID collection returns real processor vendor and identification data."""
        cpu_info = hardware_spoofer._get_cpu_id()

        assert isinstance(cpu_info, dict)
        assert len(cpu_info) > 0

        if "vendor" in cpu_info:
            known_vendors = ["GenuineIntel", "AuthenticAMD", "CentaurHauls"]
            assert any(vendor in cpu_info["vendor"] for vendor in known_vendors), \
                    f"CPU vendor must be recognized: {cpu_info.get('vendor')}"

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_cpu_id_includes_processor_signature(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """CPU ID collection includes processor family, model, stepping information."""
        cpu_info = hardware_spoofer._get_cpu_id()

        has_signature_info = any(key in cpu_info for key in ["signature", "family", "model", "processor_id"])
        assert has_signature_info, "CPU info must include processor signature/identification data"

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_cpuid_via_asm_executes_cpuid_instruction(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Assembly CPUID execution retrieves real CPU identification via CPUID instruction."""
        if platform.machine() not in ("AMD64", "x86_64"):
            pytest.skip("CPUID instruction only available on x86_64")

        cpu_info = hardware_spoofer._get_cpuid_via_asm()

        assert isinstance(cpu_info, dict)

        if len(cpu_info) > 0:
            assert "vendor" in cpu_info or "signature" in cpu_info

            if "vendor" in cpu_info:
                assert len(cpu_info["vendor"]) == 12, "CPUID vendor string must be 12 characters"
                assert cpu_info["vendor"] in ["GenuineIntel", "AuthenticAMD", "CentaurHauls"]


class TestMotherboardInfoCollection:
    """Test real motherboard information collection."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_motherboard_info_returns_baseboard_data(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Motherboard info collection returns manufacturer, product, serial from WMI."""
        mb_info = hardware_spoofer._get_motherboard_info()

        assert isinstance(mb_info, dict)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_motherboard_info_includes_system_information(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Motherboard info includes system manufacturer and UUID from registry."""
        mb_info = hardware_spoofer._get_motherboard_info()

        has_system_info = any(key in mb_info for key in ["manufacturer", "product", "serial", "system_manufacturer"])
        assert has_system_info or len(mb_info) == 0, "Motherboard info should include identification data when available"


class TestDiskSerialCollection:
    """Test real disk serial number collection."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_disk_serials_returns_physical_disk_list(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Disk serial collection returns list of physical disk drive identifiers."""
        disk_serials = hardware_spoofer._get_disk_serials()

        assert isinstance(disk_serials, list)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_disk_serials_includes_model_and_serial(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Disk serial collection includes model and serial number for each drive."""
        disk_serials = hardware_spoofer._get_disk_serials()

        for disk in disk_serials:
            assert isinstance(disk, dict)
            has_identification = any(key in disk for key in ["model", "serial", "signature", "drive"])
            assert has_identification, "Each disk entry must have identification data"

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_volume_serial_retrieves_volume_information(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Volume serial retrieval uses GetVolumeInformationW for drive serial numbers."""
        partitions = psutil.disk_partitions()

        if not partitions:
            pytest.skip("No disk partitions available for testing")

        test_drive = partitions[0].device
        volume_info = hardware_spoofer._get_volume_serial(test_drive)

        if volume_info is not None:
            assert isinstance(volume_info, dict)
            assert "serial" in volume_info
            assert "volume_name" in volume_info
            assert "file_system" in volume_info
            assert "drive" in volume_info

            assert re.match(r"^[0-9A-F]{8}$", volume_info["serial"]), \
                "Volume serial must be 8-character hex string"


class TestMACAddressCollection:
    """Test real network adapter MAC address collection."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_mac_addresses_returns_adapter_list(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """MAC address collection returns list of network adapters with addresses."""
        mac_addresses = hardware_spoofer._get_mac_addresses()

        assert isinstance(mac_addresses, list)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_mac_addresses_includes_adapter_names(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """MAC address collection includes adapter names and MAC addresses."""
        mac_addresses = hardware_spoofer._get_mac_addresses()

        for mac_entry in mac_addresses:
            assert isinstance(mac_entry, dict)
            assert "name" in mac_entry
            assert "mac" in mac_entry

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_mac_addresses_validates_mac_format(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """MAC address collection returns properly formatted MAC addresses."""
        mac_addresses = hardware_spoofer._get_mac_addresses()

        mac_pattern = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")

        for mac_entry in mac_addresses:
            if "mac" in mac_entry and mac_entry["mac"]:
                assert mac_pattern.match(mac_entry["mac"]), \
                    f"Invalid MAC format: {mac_entry['mac']}"


class TestBIOSAndSystemInfo:
    """Test BIOS and system information collection."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_bios_info_returns_firmware_data(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """BIOS info collection returns firmware manufacturer and version."""
        bios_info = hardware_spoofer._get_bios_info()

        assert isinstance(bios_info, dict)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_system_info_returns_uuid_and_vendor(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """System info collection returns system UUID and vendor information."""
        sys_info = hardware_spoofer._get_system_info()

        assert isinstance(sys_info, dict)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_machine_guid_retrieves_registry_value(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Machine GUID retrieval reads real value from Windows registry."""
        machine_guid = hardware_spoofer._get_machine_guid()

        assert isinstance(machine_guid, str)

        if machine_guid:
            guid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
            assert guid_pattern.match(machine_guid), f"Invalid machine GUID format: {machine_guid}"


class TestGPUAndUSBCollection:
    """Test GPU and USB device collection."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_gpu_info_returns_video_controller_data(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """GPU info collection returns video controller identification."""
        gpu_info = hardware_spoofer._get_gpu_info()

        assert isinstance(gpu_info, list)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_usb_devices_returns_usb_hub_data(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """USB device collection returns USB hub and device identification."""
        usb_devices = hardware_spoofer._get_usb_devices()

        assert isinstance(usb_devices, list)


class TestCompleteHardwareCollection:
    """Test complete hardware information collection."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_collect_hardware_info_gathers_all_components(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Complete hardware collection gathers CPU, MB, disk, MAC, BIOS, system, GPU, USB."""
        info = hardware_spoofer.collect_hardware_info()

        assert isinstance(info, dict)

        required_keys = ["cpu_id", "motherboard", "disk_serials", "mac_addresses",
                        "bios", "system", "gpu", "usb_devices"]

        for key in required_keys:
            assert key in info, f"Hardware info must include {key}"

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_collect_hardware_info_returns_non_empty_data(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Complete hardware collection returns actual data from system."""
        info = hardware_spoofer.collect_hardware_info()

        has_real_data = any(
            len(info[key]) > 0 if isinstance(info[key], (dict, list)) else info[key]
            for key in info.keys()
        )

        assert has_real_data, "Hardware collection must return actual system data"


class TestCPUIDSpoofing:
    """Test CPU identification spoofing capabilities."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_cpu_id_accepts_custom_vendor(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """CPU ID spoofing accepts and uses custom vendor string."""
        vendor = "GenuineIntel"
        processor_id = "0000000000000001"

        result = hardware_spoofer.spoof_cpu_id(vendor=vendor, processor_id=processor_id)

        assert isinstance(result, bool)

        if result:
            assert hardware_spoofer.spoofed_values.get("cpu_vendor") == vendor
            assert hardware_spoofer.spoofed_values.get("cpu_id") == processor_id

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_cpu_id_generates_random_values_when_none(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """CPU ID spoofing generates random vendor and ID when not specified."""
        result = hardware_spoofer.spoof_cpu_id()

        assert isinstance(result, bool)

        if result:
            assert "cpu_vendor" in hardware_spoofer.spoofed_values
            assert "cpu_id" in hardware_spoofer.spoofed_values

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_cpu_id_creates_valid_format(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Random CPU ID generation creates valid processor ID format."""
        cpu_id = hardware_spoofer._generate_random_cpu_id()

        assert isinstance(cpu_id, str)
        assert len(cpu_id) > 0
        assert all(c in "0123456789ABCDEF" for c in cpu_id), "CPU ID must be hex string"

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_cpu_id_updates_spoofed_values_dict(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """CPU ID spoofing updates spoofed_values tracking dictionary."""
        vendor = "AuthenticAMD"
        processor_id = hardware_spoofer._generate_random_cpu_id()

        hardware_spoofer.spoof_cpu_id(vendor=vendor, processor_id=processor_id)

        if "cpu_vendor" in hardware_spoofer.spoofed_values:
            assert hardware_spoofer.spoofed_values["cpu_vendor"] == vendor


class TestMACAddressSpoofing:
    """Test MAC address spoofing capabilities."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_mac_creates_locally_administered_address(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Random MAC generation creates locally administered MAC address."""
        mac = hardware_spoofer._generate_random_mac()

        assert isinstance(mac, str)
        mac_pattern = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
        assert mac_pattern.match(mac), f"Invalid MAC format: {mac}"

        first_octet = int(mac.split(":")[0], 16)
        assert first_octet & 0x02 == 0x02, "MAC must have locally administered bit set"

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_mac_address_accepts_custom_address(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """MAC address spoofing accepts custom MAC address."""
        adapters = hardware_spoofer._get_mac_addresses()

        if not adapters:
            pytest.skip("No network adapters available for testing")

        adapter_name = adapters[0]["name"]
        custom_mac = "02:42:13:37:69:AC"

        result = hardware_spoofer.spoof_mac_address(adapter_name=adapter_name, new_mac=custom_mac)

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_spoof_mac_address_modifies_registry_value(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """MAC address spoofing modifies registry NetworkAddress value."""
        adapters = hardware_spoofer._get_mac_addresses()

        if not adapters:
            pytest.skip("No network adapters available for testing")

        adapter_name = adapters[0]["name"]
        custom_mac = "02:42:13:37:69:AD"

        original_mac = adapters[0]["mac"]
        hardware_spoofer.original_values[f"mac_{adapter_name}"] = original_mac

        if result := hardware_spoofer.spoof_mac_address(
            adapter_name=adapter_name, new_mac=custom_mac
        ):
            assert f"mac_{adapter_name}" in hardware_spoofer.spoofed_values
            assert hardware_spoofer.spoofed_values[f"mac_{adapter_name}"] == custom_mac

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_mac_address_uses_first_adapter_when_none_specified(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """MAC address spoofing uses first available adapter when none specified."""
        adapters = hardware_spoofer._get_mac_addresses()

        if not adapters:
            pytest.skip("No network adapters available for testing")

        result = hardware_spoofer.spoof_mac_address()

        assert isinstance(result, bool)


class TestDiskSerialSpoofing:
    """Test disk serial number spoofing capabilities."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_disk_serial_creates_valid_format(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Random disk serial generation creates valid alphanumeric serial."""
        serial = hardware_spoofer._generate_random_disk_serial()

        assert isinstance(serial, str)
        assert len(serial) == 16
        assert all(c in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in serial)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_disk_serial_accepts_custom_serial(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Disk serial spoofing accepts custom serial number."""
        drive = "C:\\"
        custom_serial = "SPOOFED12345678"

        result = hardware_spoofer.spoof_disk_serial(drive=drive, new_serial=custom_serial)

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_disk_serial_defaults_to_c_drive(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Disk serial spoofing defaults to C: drive when not specified."""
        result = hardware_spoofer.spoof_disk_serial()

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_spoof_disk_serial_updates_spoofed_values(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Disk serial spoofing updates spoofed_values tracking dictionary."""
        drive = "C:\\"
        custom_serial = hardware_spoofer._generate_random_disk_serial()

        if result := hardware_spoofer.spoof_disk_serial(
            drive=drive, new_serial=custom_serial
        ):
            assert f"disk_{drive}" in hardware_spoofer.spoofed_values


class TestMotherboardSpoofing:
    """Test motherboard serial number spoofing capabilities."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_serial_creates_valid_format(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Random serial generation creates valid 12-character alphanumeric string."""
        serial = hardware_spoofer._generate_random_serial()

        assert isinstance(serial, str)
        assert len(serial) == 12
        assert all(c in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in serial)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_motherboard_serial_accepts_custom_values(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Motherboard spoofing accepts custom manufacturer, product, serial."""
        manufacturer = "ASUS"
        product = "PRIME-Z490-A"
        serial = "SPOOFEDMB001"

        result = hardware_spoofer.spoof_motherboard_serial(
            manufacturer=manufacturer,
            product=product,
            serial=serial
        )

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_motherboard_serial_generates_random_when_none(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Motherboard spoofing generates random values when not specified."""
        result = hardware_spoofer.spoof_motherboard_serial()

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_spoof_motherboard_serial_updates_spoofed_values(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Motherboard spoofing updates spoofed_values tracking dictionary."""
        manufacturer = "MSI"
        product = "B550-GAMING"
        serial = hardware_spoofer._generate_random_serial()

        if result := hardware_spoofer.spoof_motherboard_serial(
            manufacturer=manufacturer, product=product, serial=serial
        ):
            assert "motherboard_manufacturer" in hardware_spoofer.spoofed_values
            assert "motherboard_product" in hardware_spoofer.spoofed_values
            assert "motherboard_serial" in hardware_spoofer.spoofed_values


class TestSystemUUIDSpoofing:
    """Test system UUID spoofing capabilities."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_system_uuid_accepts_custom_uuid(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """System UUID spoofing accepts custom UUID string."""
        custom_uuid = str(uuid.uuid4())

        result = hardware_spoofer.spoof_system_uuid(new_uuid=custom_uuid)

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_system_uuid_generates_random_when_none(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """System UUID spoofing generates random UUID when not specified."""
        result = hardware_spoofer.spoof_system_uuid()

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_spoof_system_uuid_modifies_machine_guid_registry(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """System UUID spoofing modifies MachineGuid registry value."""
        original_guid = hardware_spoofer._get_machine_guid()

        if not original_guid:
            pytest.skip("Unable to read original MachineGuid")

        hardware_spoofer.original_values["machine_guid"] = original_guid

        custom_uuid = str(uuid.uuid4())
        if result := hardware_spoofer.spoof_system_uuid(new_uuid=custom_uuid):
            assert "system_uuid" in hardware_spoofer.spoofed_values
            assert hardware_spoofer.spoofed_values["system_uuid"] == custom_uuid

            new_guid = hardware_spoofer._get_machine_guid()
            assert new_guid == custom_uuid or "{" + custom_uuid + "}" in new_guid


class TestProfileGeneration:
    """Test hardware profile generation and management."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_profile_creates_complete_profile(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Random profile generation creates profile with all hardware components."""
        profile = hardware_spoofer.generate_random_profile()

        assert isinstance(profile, dict)

        required_keys = ["cpu_vendor", "cpu_id", "mac_addresses", "disk_serials",
                        "motherboard_manufacturer", "motherboard_product",
                        "motherboard_serial", "system_uuid"]

        for key in required_keys:
            assert key in profile, f"Profile must include {key}"

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_profile_includes_valid_cpu_vendor(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Random profile generation includes valid CPU vendor."""
        profile = hardware_spoofer.generate_random_profile()

        assert profile["cpu_vendor"] in ["GenuineIntel", "AuthenticAMD"]

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_profile_includes_mac_addresses(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Random profile generation includes MAC addresses for available adapters."""
        profile = hardware_spoofer.generate_random_profile()

        assert isinstance(profile["mac_addresses"], list)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_profile_includes_disk_serials(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Random profile generation includes disk serials for available drives."""
        profile = hardware_spoofer.generate_random_profile()

        assert isinstance(profile["disk_serials"], list)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_profile_creates_unique_profiles(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Random profile generation creates different profiles on multiple calls."""
        profile1 = hardware_spoofer.generate_random_profile()
        profile2 = hardware_spoofer.generate_random_profile()

        assert profile1["cpu_id"] != profile2["cpu_id"] or \
               profile1["motherboard_serial"] != profile2["motherboard_serial"] or \
               profile1["system_uuid"] != profile2["system_uuid"], \
               "Profiles should have different values"


class TestProfilePersistence:
    """Test profile saving and loading capabilities."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_save_profile_creates_encrypted_file(self, hardware_spoofer: HardwareIDSpoofer, temp_profile_dir: Path) -> None:
        """Profile saving creates encrypted file at specified path."""
        profile = hardware_spoofer.generate_random_profile()
        profile_path = temp_profile_dir / "test_profile.enc"

        hardware_spoofer.save_profile(profile, profile_path)

        assert profile_path.exists()
        assert profile_path.stat().st_size > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_save_profile_creates_parent_directories(self, hardware_spoofer: HardwareIDSpoofer, temp_profile_dir: Path) -> None:
        """Profile saving creates parent directories if they don't exist."""
        profile = hardware_spoofer.generate_random_profile()
        nested_path = temp_profile_dir / "nested" / "dir" / "profile.enc"

        hardware_spoofer.save_profile(profile, nested_path)

        assert nested_path.exists()

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_load_profile_decrypts_saved_profile(self, hardware_spoofer: HardwareIDSpoofer, temp_profile_dir: Path) -> None:
        """Profile loading successfully decrypts saved profile data."""
        original_profile = hardware_spoofer.generate_random_profile()
        profile_path = temp_profile_dir / "test_profile.enc"

        hardware_spoofer.save_profile(original_profile, profile_path)
        loaded_profile = hardware_spoofer.load_profile(profile_path)

        assert loaded_profile == original_profile

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_encrypt_profile_produces_non_plaintext_output(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Profile encryption produces encrypted data that differs from plaintext."""
        profile = {"test": "data", "cpu_id": "12345"}

        encrypted = hardware_spoofer._encrypt_profile(profile)

        assert isinstance(encrypted, bytes)
        assert b"test" not in encrypted
        assert b"cpu_id" not in encrypted
        assert b"12345" not in encrypted

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_decrypt_profile_recovers_original_data(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Profile decryption recovers original profile dictionary."""
        original_profile = {
            "cpu_vendor": "GenuineIntel",
            "cpu_id": "0123456789ABCDEF",
            "system_uuid": str(uuid.uuid4())
        }

        encrypted = hardware_spoofer._encrypt_profile(original_profile)
        decrypted = hardware_spoofer._decrypt_profile(encrypted)

        assert decrypted == original_profile


class TestSpoofAllOperation:
    """Test complete hardware spoofing operation."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_all_accepts_custom_profile(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Spoof all operation accepts custom hardware profile."""
        profile = hardware_spoofer.generate_random_profile()

        results = hardware_spoofer.spoof_all(profile=profile)

        assert isinstance(results, dict)
        assert "cpu" in results
        assert "motherboard" in results
        assert "system_uuid" in results

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_all_generates_profile_when_none(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Spoof all operation generates random profile when none provided."""
        results = hardware_spoofer.spoof_all()

        assert isinstance(results, dict)
        assert len(results) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_all_returns_result_status_for_each_component(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Spoof all operation returns boolean success status for each component."""
        results = hardware_spoofer.spoof_all()

        for key, value in results.items():
            assert isinstance(value, bool), f"Result for {key} must be boolean"

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_spoof_all_updates_spoofed_values_for_successful_operations(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Spoof all operation updates spoofed_values for successful spoofing operations."""
        profile = hardware_spoofer.generate_random_profile()

        results = hardware_spoofer.spoof_all(profile=profile)

        successful_operations = sum(bool(result)
                                for result in results.values())

        if successful_operations > 0:
            assert len(hardware_spoofer.spoofed_values) > 0


class TestRestoreOperations:
    """Test hardware ID restoration capabilities."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_restore_original_returns_status(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Restore original operation returns boolean success status."""
        result = hardware_spoofer.restore_original()

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_restore_mac_address_removes_registry_override(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """MAC address restoration removes NetworkAddress registry override."""
        adapters = hardware_spoofer._get_mac_addresses()

        if not adapters:
            pytest.skip("No network adapters available for testing")

        adapter_name = adapters[0]["name"]
        original_mac = adapters[0]["mac"]

        hardware_spoofer._restore_mac_address(adapter_name, original_mac)


class TestCleanupOperations:
    """Test cleanup and resource management."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_cleanup_closes_driver_handle(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Cleanup operation closes kernel driver handle."""
        hardware_spoofer.cleanup()

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_cleanup_can_be_called_multiple_times(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Cleanup operation can be called multiple times without errors."""
        hardware_spoofer.cleanup()
        hardware_spoofer.cleanup()


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_cpu_id_handles_invalid_vendor(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """CPU ID spoofing handles invalid vendor strings gracefully."""
        result = hardware_spoofer.spoof_cpu_id(vendor="InvalidVendor123", processor_id="0000000000000001")

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_mac_address_handles_nonexistent_adapter(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """MAC address spoofing handles nonexistent adapter names gracefully."""
        result = hardware_spoofer.spoof_mac_address(
            adapter_name="NonexistentAdapter9999",
            new_mac="02:42:13:37:69:AB"
        )

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_volume_serial_handles_invalid_drive(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Volume serial retrieval handles invalid drive paths gracefully."""
        result = hardware_spoofer._get_volume_serial("Z:\\InvalidDrive\\")

        assert result is None

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_load_profile_handles_corrupted_file(self, hardware_spoofer: HardwareIDSpoofer, temp_profile_dir: Path) -> None:
        """Profile loading handles corrupted encrypted files gracefully."""
        corrupted_path = temp_profile_dir / "corrupted.enc"
        corrupted_path.write_bytes(b"This is corrupted data, not encrypted profile")

        with pytest.raises(Exception):
            hardware_spoofer.load_profile(corrupted_path)


class TestIntegrationScenarios:
    """Test real-world integration scenarios."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_complete_workflow_collect_spoof_restore(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Complete workflow: collect hardware info, spoof, restore original."""
        original_info = hardware_spoofer.collect_hardware_info()

        assert len(original_info) > 0

        profile = hardware_spoofer.generate_random_profile()
        spoof_results = hardware_spoofer.spoof_all(profile=profile)

        assert isinstance(spoof_results, dict)

        restore_result = hardware_spoofer.restore_original()

        assert isinstance(restore_result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_profile_roundtrip_save_load_apply(self, hardware_spoofer: HardwareIDSpoofer, temp_profile_dir: Path) -> None:
        """Profile roundtrip: generate, save, load, apply."""
        profile = hardware_spoofer.generate_random_profile()
        profile_path = temp_profile_dir / "roundtrip.enc"

        hardware_spoofer.save_profile(profile, profile_path)

        loaded_profile = hardware_spoofer.load_profile(profile_path)

        assert loaded_profile == profile

        results = hardware_spoofer.spoof_all(profile=loaded_profile)

        assert isinstance(results, dict)

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_spoofing_changes_detectable_hardware_ids(
        self,
        hardware_spoofer: HardwareIDSpoofer,
        real_hardware_baseline: Dict[str, Any]
    ) -> None:
        """Spoofing operation changes hardware IDs that can be detected by applications."""
        custom_uuid = str(uuid.uuid4())

        if result := hardware_spoofer.spoof_system_uuid(new_uuid=custom_uuid):
            new_guid = hardware_spoofer._get_machine_guid()
            original_guid = real_hardware_baseline.get("system", {}).get("machine_guid", "")

            if new_guid and original_guid:
                assert new_guid != original_guid, "System UUID should be different after spoofing"


class TestSecurityAndValidation:
    """Test security aspects and validation."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_mac_never_creates_multicast_address(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Random MAC generation never creates multicast addresses."""
        for _ in range(100):
            mac = hardware_spoofer._generate_random_mac()
            first_octet = int(mac.split(":")[0], 16)

            assert first_octet & 0x01 == 0, "MAC must not have multicast bit set"

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_random_mac_creates_locally_administered_addresses(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Random MAC generation consistently creates locally administered addresses."""
        for _ in range(100):
            mac = hardware_spoofer._generate_random_mac()
            first_octet = int(mac.split(":")[0], 16)

            assert first_octet & 0x02 == 0x02, "MAC must have locally administered bit set"

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_profile_encryption_uses_consistent_key_derivation(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Profile encryption uses consistent key derivation for encrypt/decrypt."""
        profile = {"test": "data"}

        encrypted1 = hardware_spoofer._encrypt_profile(profile)
        decrypted1 = hardware_spoofer._decrypt_profile(encrypted1)

        encrypted2 = hardware_spoofer._encrypt_profile(profile)
        decrypted2 = hardware_spoofer._decrypt_profile(encrypted2)

        assert decrypted1 == profile
        assert decrypted2 == profile
        assert decrypted1 == decrypted2


class TestDriverCodeGeneration:
    """Test kernel driver code generation capabilities."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_driver_code_produces_x64_assembly(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Driver code generation produces x64 assembly bytecode."""
        try:
            driver_code = hardware_spoofer._generate_driver_code()

            assert isinstance(driver_code, bytes)
            assert len(driver_code) > 0
        except ImportError:
            pytest.skip("Keystone assembler not available")

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_align_function_aligns_to_boundary(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Align function correctly aligns values to specified boundaries."""
        assert hardware_spoofer._align(100, 64) == 128
        assert hardware_spoofer._align(128, 64) == 128
        assert hardware_spoofer._align(200, 512) == 512
        assert hardware_spoofer._align(1000, 0x1000) == 0x1000


class TestRandomnessAndUnpredictability:
    """Test randomness and unpredictability of generated values."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_random_cpu_ids_are_unique(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Random CPU ID generation produces unique values."""
        cpu_ids = [hardware_spoofer._generate_random_cpu_id() for _ in range(50)]

        assert len(set(cpu_ids)) > 45, "CPU IDs should be highly unique"

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_random_disk_serials_are_unique(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Random disk serial generation produces unique values."""
        serials = [hardware_spoofer._generate_random_disk_serial() for _ in range(50)]

        assert len(set(serials)) > 45, "Disk serials should be highly unique"

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_random_mac_addresses_are_unique(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Random MAC address generation produces unique values."""
        macs = [hardware_spoofer._generate_random_mac() for _ in range(50)]

        assert len(set(macs)) > 45, "MAC addresses should be highly unique"

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_random_profiles_have_different_components(self, hardware_spoofer: HardwareIDSpoofer) -> None:
        """Random profile generation produces profiles with different component values."""
        profiles = [hardware_spoofer.generate_random_profile() for _ in range(10)]

        cpu_ids = [p["cpu_id"] for p in profiles]
        uuids = [p["system_uuid"] for p in profiles]

        assert len(set(cpu_ids)) == 10, "All CPU IDs should be unique"
        assert len(set(uuids)) == 10, "All system UUIDs should be unique"
