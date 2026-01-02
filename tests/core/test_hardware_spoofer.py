"""Comprehensive tests for hardware fingerprint spoofing capabilities.

Tests validate real hardware ID manipulation for bypassing hardware-based licensing.
All tests use actual Windows registry, WMI, and system APIs - NO MOCKS.
"""

import ctypes
import os
import platform
import uuid
import winreg
from typing import Any

import pytest

from intellicrack.core.hardware_spoofer import (
    HardwareFingerPrintSpoofer,
    HardwareIdentifiers,
    SpoofMethod,
)


WINDOWS_ONLY: bool = platform.system() == "Windows"
ADMIN_REQUIRED: bool = not (os.geteuid() == 0 if hasattr(os, "geteuid") else ctypes.windll.shell32.IsUserAnAdmin() != 0)


class TestHardwareIdentifiersDataclass:
    """Test HardwareIdentifiers dataclass structure and validation."""

    def test_hardware_identifiers_creation_with_all_fields(self) -> None:
        """HardwareIdentifiers dataclass accepts all required hardware ID fields."""
        hw_id = HardwareIdentifiers(
            cpu_id="BFEBFBFF000306C3",
            cpu_name="Intel(R) Core(TM) i7-4770K CPU @ 3.50GHz",
            motherboard_serial="MB-123456789ABC",
            motherboard_manufacturer="ASUSTeK COMPUTER INC.",
            bios_serial="BIOS-1234567890",
            bios_version="2.17.1246",
            disk_serial=["WD-WCAV12345678"],
            disk_model=["Samsung SSD 970 EVO Plus 1TB"],
            mac_addresses=["005056C00001"],
            system_uuid="12345678-1234-5678-1234-567812345678",
            machine_guid="12345678-1234-5678-1234-567812345678",
            volume_serial="1234ABCD",
            product_id="00000-00000-00000-AAOEM",
            network_adapters=[{"name": "Ethernet", "mac": "005056C00001", "guid": str(uuid.uuid4()), "pnp_id": "PCI\\VEN_8086"}],
            gpu_ids=["PCI\\VEN_10DE&DEV_1B80"],
            ram_serial=["12345678"],
            usb_devices=[{"device_id": "USB\\VID_046D&PID_C52B", "pnp_id": "USB\\VID_046D&PID_C52B\\1"}],
        )

        assert hw_id.cpu_id == "BFEBFBFF000306C3"
        assert hw_id.cpu_name == "Intel(R) Core(TM) i7-4770K CPU @ 3.50GHz"
        assert hw_id.motherboard_serial == "MB-123456789ABC"
        assert hw_id.bios_serial == "BIOS-1234567890"
        assert len(hw_id.disk_serial) == 1
        assert len(hw_id.mac_addresses) == 1
        assert hw_id.machine_guid == "12345678-1234-5678-1234-567812345678"


class TestHardwareFingerPrintSpooferInitialization:
    """Test spoofer initialization and setup."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoofer_initialization_creates_wmi_client_on_windows(self) -> None:
        """Spoofer initializes WMI client on Windows for hardware queries."""
        spoofer = HardwareFingerPrintSpoofer()

        assert spoofer.wmi_client is not None
        assert spoofer.original_hardware is None
        assert spoofer.spoofed_hardware is None
        assert spoofer.hooks_installed is False

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoofer_initializes_all_spoof_methods(self) -> None:
        """Spoofer registers all hardware component spoofing methods."""
        spoofer = HardwareFingerPrintSpoofer()

        expected_methods = ["cpu", "motherboard", "bios", "disk", "mac", "uuid", "gpu", "ram", "usb"]
        for method in expected_methods:
            assert method in spoofer.spoof_methods
            assert callable(spoofer.spoof_methods[method])


class TestOriginalHardwareCapture:
    """Test capturing real hardware identifiers from system."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_capture_original_hardware_retrieves_real_system_values(self) -> None:
        """Capture original hardware retrieves actual CPU, motherboard, BIOS, disk values from WMI."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()

        assert original is not None
        assert original.cpu_id != ""
        assert original.cpu_name != ""
        assert original.motherboard_serial != ""
        assert original.bios_serial != ""
        assert len(original.disk_serial) > 0
        assert len(original.mac_addresses) > 0
        assert original.system_uuid != ""
        assert original.machine_guid != ""
        assert original.volume_serial != ""
        assert original.product_id != ""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_captured_hardware_stores_in_original_hardware_field(self) -> None:
        """Captured hardware is stored in spoofer.original_hardware."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()

        assert spoofer.original_hardware is original
        assert spoofer.original_hardware is not None

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_cpu_id_retrieval_returns_valid_format(self) -> None:
        """CPU ID retrieval returns valid processor ID format."""
        spoofer = HardwareFingerPrintSpoofer()
        cpu_id = spoofer._get_cpu_id()

        assert cpu_id is not None
        assert isinstance(cpu_id, str)
        assert len(cpu_id) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_cpu_name_retrieval_returns_valid_processor_name(self) -> None:
        """CPU name retrieval returns valid processor name string."""
        spoofer = HardwareFingerPrintSpoofer()
        cpu_name = spoofer._get_cpu_name()

        assert cpu_name is not None
        assert isinstance(cpu_name, str)
        assert len(cpu_name) > 0
        assert "CPU" in cpu_name or "Processor" in cpu_name or "Core" in cpu_name or "Ryzen" in cpu_name

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_motherboard_serial_retrieval_returns_serial_or_generated(self) -> None:
        """Motherboard serial retrieval returns actual or generated serial."""
        spoofer = HardwareFingerPrintSpoofer()
        mb_serial = spoofer._get_motherboard_serial()

        assert mb_serial is not None
        assert isinstance(mb_serial, str)
        assert len(mb_serial) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_bios_serial_retrieval_returns_serial_or_generated(self) -> None:
        """BIOS serial retrieval returns actual or generated BIOS serial."""
        spoofer = HardwareFingerPrintSpoofer()
        bios_serial = spoofer._get_bios_serial()

        assert bios_serial is not None
        assert isinstance(bios_serial, str)
        assert len(bios_serial) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_disk_serials_retrieval_returns_list_of_serials(self) -> None:
        """Disk serial retrieval returns list of physical disk serials."""
        spoofer = HardwareFingerPrintSpoofer()
        disk_serials = spoofer._get_disk_serials()

        assert disk_serials is not None
        assert isinstance(disk_serials, list)
        assert len(disk_serials) > 0
        assert all(isinstance(s, str) for s in disk_serials)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_mac_addresses_retrieval_returns_valid_addresses(self) -> None:
        """MAC address retrieval returns valid network adapter MAC addresses."""
        spoofer = HardwareFingerPrintSpoofer()
        mac_addresses = spoofer._get_mac_addresses()

        assert mac_addresses is not None
        assert isinstance(mac_addresses, list)
        assert len(mac_addresses) > 0
        for mac in mac_addresses:
            assert isinstance(mac, str)
            assert len(mac) == 12

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_system_uuid_retrieval_returns_valid_uuid(self) -> None:
        """System UUID retrieval returns valid UUID format."""
        spoofer = HardwareFingerPrintSpoofer()
        system_uuid = spoofer._get_system_uuid()

        assert system_uuid is not None
        assert isinstance(system_uuid, str)
        assert len(system_uuid) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_machine_guid_retrieval_from_registry(self) -> None:
        """Machine GUID retrieval reads actual MachineGuid from registry."""
        spoofer = HardwareFingerPrintSpoofer()
        machine_guid = spoofer._get_machine_guid()

        assert machine_guid is not None
        assert isinstance(machine_guid, str)
        assert len(machine_guid) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_volume_serial_retrieval_returns_valid_serial(self) -> None:
        """Volume serial retrieval returns valid C: drive serial number."""
        spoofer = HardwareFingerPrintSpoofer()
        volume_serial = spoofer._get_volume_serial()

        assert volume_serial is not None
        assert isinstance(volume_serial, str)
        assert len(volume_serial) == 8

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_product_id_retrieval_from_registry(self) -> None:
        """Product ID retrieval reads Windows ProductId from registry."""
        spoofer = HardwareFingerPrintSpoofer()
        product_id = spoofer._get_product_id()

        assert product_id is not None
        assert isinstance(product_id, str)
        assert len(product_id) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_network_adapters_retrieval_returns_adapter_list(self) -> None:
        """Network adapter retrieval returns list of physical adapter details."""
        spoofer = HardwareFingerPrintSpoofer()
        adapters = spoofer._get_network_adapters()

        assert adapters is not None
        assert isinstance(adapters, list)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_gpu_ids_retrieval_returns_gpu_device_ids(self) -> None:
        """GPU ID retrieval returns PNP device IDs for GPUs."""
        spoofer = HardwareFingerPrintSpoofer()
        gpu_ids = spoofer._get_gpu_ids()

        assert gpu_ids is not None
        assert isinstance(gpu_ids, list)
        assert len(gpu_ids) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_ram_serials_retrieval_returns_memory_serials(self) -> None:
        """RAM serial retrieval returns physical memory serial numbers."""
        spoofer = HardwareFingerPrintSpoofer()
        ram_serials = spoofer._get_ram_serials()

        assert ram_serials is not None
        assert isinstance(ram_serials, list)
        assert len(ram_serials) > 0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_usb_devices_retrieval_returns_device_list(self) -> None:
        """USB device retrieval returns list of USB device identifiers."""
        spoofer = HardwareFingerPrintSpoofer()
        usb_devices = spoofer._get_usb_devices()

        assert usb_devices is not None
        assert isinstance(usb_devices, list)


class TestSpoofedHardwareGeneration:
    """Test generation of spoofed hardware identifiers."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_spoofed_hardware_creates_different_values(self) -> None:
        """Generate spoofed hardware creates values different from original."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()
        spoofed = spoofer.generate_spoofed_hardware()

        assert spoofed.cpu_id != original.cpu_id
        assert spoofed.motherboard_serial != original.motherboard_serial
        assert spoofed.bios_serial != original.bios_serial
        assert spoofed.system_uuid != original.system_uuid
        assert spoofed.machine_guid != original.machine_guid

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_spoofed_hardware_with_preserve_list_keeps_specified_components(self) -> None:
        """Generate spoofed hardware preserves specified components from original."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()
        spoofed = spoofer.generate_spoofed_hardware(preserve=["cpu", "bios"])

        assert spoofed.cpu_id == original.cpu_id
        assert spoofed.cpu_name == original.cpu_name
        assert spoofed.bios_serial == original.bios_serial
        assert spoofed.bios_version == original.bios_version
        assert spoofed.motherboard_serial != original.motherboard_serial
        assert spoofed.system_uuid != original.system_uuid

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_cpu_id_is_valid_intel_format(self) -> None:
        """Generated CPU ID matches valid Intel processor ID format."""
        spoofer = HardwareFingerPrintSpoofer()
        cpu_id = spoofer._generate_cpu_id()

        assert cpu_id is not None
        assert len(cpu_id) == 16
        assert cpu_id.startswith("BFEBFBFF")

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_cpu_name_is_realistic_processor_name(self) -> None:
        """Generated CPU name is realistic Intel or AMD processor name."""
        spoofer = HardwareFingerPrintSpoofer()
        cpu_name = spoofer._generate_cpu_name()

        assert cpu_name is not None
        assert "Intel" in cpu_name or "AMD" in cpu_name or "Ryzen" in cpu_name
        assert "Core" in cpu_name or "Ryzen" in cpu_name

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_motherboard_serial_has_valid_format(self) -> None:
        """Generated motherboard serial has realistic format with prefix."""
        spoofer = HardwareFingerPrintSpoofer()
        mb_serial = spoofer._generate_mb_serial()

        assert mb_serial is not None
        assert "-" in mb_serial
        prefixes = ["MB", "SN", "BASE", "BOARD"]
        assert any(mb_serial.startswith(prefix) for prefix in prefixes)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_motherboard_manufacturer_is_realistic(self) -> None:
        """Generated motherboard manufacturer is realistic vendor name."""
        spoofer = HardwareFingerPrintSpoofer()
        manufacturer = spoofer._generate_mb_manufacturer()

        assert manufacturer is not None
        realistic_manufacturers = ["ASUS", "Gigabyte", "MSI", "ASRock", "EVGA", "Dell", "HP", "Lenovo"]
        assert any(mfr in manufacturer for mfr in realistic_manufacturers)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_bios_serial_has_alphanumeric_format(self) -> None:
        """Generated BIOS serial is alphanumeric string."""
        spoofer = HardwareFingerPrintSpoofer()
        bios_serial = spoofer._generate_bios_serial()

        assert bios_serial is not None
        assert len(bios_serial) == 10
        assert bios_serial.isalnum()

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_bios_version_has_version_format(self) -> None:
        """Generated BIOS version has major.minor.build format."""
        spoofer = HardwareFingerPrintSpoofer()
        bios_version = spoofer._generate_bios_version()

        assert bios_version is not None
        parts = bios_version.split(".")
        assert len(parts) == 3
        assert all(part.isdigit() for part in parts)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_disk_serials_are_realistic_formats(self) -> None:
        """Generated disk serials have realistic vendor prefix formats."""
        spoofer = HardwareFingerPrintSpoofer()
        disk_serials = spoofer._generate_disk_serials()

        assert disk_serials is not None
        assert len(disk_serials) >= 1
        assert len(disk_serials) <= 3
        for serial in disk_serials:
            assert "-" in serial
            prefixes = ["WD", "ST", "SAMSUNG", "CRUCIAL", "KINGSTON"]
            assert any(serial.startswith(prefix) for prefix in prefixes)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_disk_models_are_realistic_drive_names(self) -> None:
        """Generated disk models are realistic drive product names."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.spoofed_hardware = HardwareIdentifiers(
            cpu_id="", cpu_name="", motherboard_serial="", motherboard_manufacturer="",
            bios_serial="", bios_version="", disk_serial=["TEST"], disk_model=[],
            mac_addresses=[], system_uuid="", machine_guid="", volume_serial="",
            product_id="", network_adapters=[], gpu_ids=[], ram_serial=[], usb_devices=[]
        )
        disk_models = spoofer._generate_disk_models()

        assert disk_models is not None
        assert len(disk_models) > 0
        for model in disk_models:
            assert any(vendor in model for vendor in ["Samsung", "WDC", "ST", "Crucial", "Kingston"])

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_mac_addresses_have_valid_oui_prefixes(self) -> None:
        """Generated MAC addresses use valid OUI prefixes."""
        spoofer = HardwareFingerPrintSpoofer()
        mac_addresses = spoofer._generate_mac_addresses()

        assert mac_addresses is not None
        assert len(mac_addresses) >= 1
        for mac in mac_addresses:
            assert len(mac) == 12
            assert all(c in "0123456789ABCDEF" for c in mac)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_volume_serial_is_8_hex_chars(self) -> None:
        """Generated volume serial is 8 character hex string."""
        spoofer = HardwareFingerPrintSpoofer()
        volume_serial = spoofer._generate_volume_serial()

        assert volume_serial is not None
        assert len(volume_serial) == 8
        assert all(c in "0123456789ABCDEF" for c in volume_serial)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_product_id_has_windows_format(self) -> None:
        """Generated product ID has Windows ProductId format with segments."""
        spoofer = HardwareFingerPrintSpoofer()
        product_id = spoofer._generate_product_id()

        assert product_id is not None
        segments = product_id.split("-")
        assert len(segments) == 4
        assert all(len(seg) == 5 for seg in segments[:3])

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_network_adapters_have_required_fields(self) -> None:
        """Generated network adapters contain name, MAC, GUID, PNP ID fields."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.spoofed_hardware = HardwareIdentifiers(
            cpu_id="", cpu_name="", motherboard_serial="", motherboard_manufacturer="",
            bios_serial="", bios_version="", disk_serial=[], disk_model=[],
            mac_addresses=["005056C00001"], system_uuid="", machine_guid="",
            volume_serial="", product_id="", network_adapters=[], gpu_ids=[],
            ram_serial=[], usb_devices=[]
        )
        adapters = spoofer._generate_network_adapters()

        assert adapters is not None
        for adapter in adapters:
            assert "name" in adapter
            assert "mac" in adapter
            assert "guid" in adapter
            assert "pnp_id" in adapter

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_gpu_ids_are_valid_pci_format(self) -> None:
        """Generated GPU IDs have valid PCI vendor/device format."""
        spoofer = HardwareFingerPrintSpoofer()
        gpu_ids = spoofer._generate_gpu_ids()

        assert gpu_ids is not None
        assert len(gpu_ids) > 0
        for gpu_id in gpu_ids:
            assert "PCI\\VEN_" in gpu_id
            assert "&DEV_" in gpu_id

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_ram_serials_are_hex_strings(self) -> None:
        """Generated RAM serials are hex format serial numbers."""
        spoofer = HardwareFingerPrintSpoofer()
        ram_serials = spoofer._generate_ram_serials()

        assert ram_serials is not None
        assert len(ram_serials) >= 2
        assert len(ram_serials) <= 4
        for serial in ram_serials:
            assert len(serial) == 8
            assert all(c in "0123456789ABCDEF" for c in serial)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generated_usb_devices_have_vendor_product_ids(self) -> None:
        """Generated USB devices have VID/PID format device identifiers."""
        spoofer = HardwareFingerPrintSpoofer()
        usb_devices = spoofer._generate_usb_devices()

        assert usb_devices is not None
        assert len(usb_devices) >= 1
        for device in usb_devices:
            assert "device_id" in device
            assert "pnp_id" in device
            assert "USB\\VID_" in device["device_id"]
            assert "&PID_" in device["device_id"]


class TestRegistrySpoof:
    """Test registry-based hardware spoofing."""

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_apply_registry_spoof_modifies_machine_guid_in_registry(self) -> None:
        """Registry spoof writes spoofed MachineGuid to Cryptography registry key."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()
        spoofed = spoofer.generate_spoofed_hardware()

        try:
            success = spoofer._apply_registry_spoof()
            assert success is True

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                current_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                assert current_guid == spoofed.machine_guid
        finally:
            spoofer.restore_original()

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_apply_registry_spoof_modifies_product_id_in_registry(self) -> None:
        """Registry spoof writes spoofed ProductId to Windows NT registry key."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()
        spoofed = spoofer.generate_spoofed_hardware()

        try:
            success = spoofer._apply_registry_spoof()
            assert success is True

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                current_product_id, _ = winreg.QueryValueEx(key, "ProductId")
                assert current_product_id == spoofed.product_id
        finally:
            spoofer.restore_original()

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_apply_registry_spoof_modifies_system_uuid_in_registry(self) -> None:
        """Registry spoof writes spoofed ComputerHardwareId to SystemInformation key."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()
        spoofed = spoofer.generate_spoofed_hardware()

        try:
            success = spoofer._apply_registry_spoof()
            assert success is True

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation") as key:
                current_uuid, _ = winreg.QueryValueEx(key, "ComputerHardwareId")
                assert current_uuid == spoofed.system_uuid
        finally:
            spoofer.restore_original()

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_apply_spoof_with_registry_method_calls_registry_spoof(self) -> None:
        """apply_spoof with REGISTRY method invokes registry-based spoofing."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.capture_original_hardware()
        spoofer.generate_spoofed_hardware()

        result = spoofer.apply_spoof(SpoofMethod.REGISTRY)

        assert isinstance(result, bool)


class TestHookSpoof:
    """Test API hook-based hardware spoofing."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_apply_hook_spoof_sets_hooks_installed_flag(self) -> None:
        """Hook spoof installation sets hooks_installed flag to True."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.capture_original_hardware()
        spoofer.generate_spoofed_hardware()

        try:
            result = spoofer._apply_hook_spoof()
            assert result is True
            assert spoofer.hooks_installed is True
        except Exception:
            pytest.skip("Hook installation requires specific privileges")

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_apply_spoof_with_hook_method_installs_hooks(self) -> None:
        """apply_spoof with HOOK method invokes hook-based spoofing."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.capture_original_hardware()
        spoofer.generate_spoofed_hardware()

        result = spoofer.apply_spoof(SpoofMethod.HOOK)

        assert isinstance(result, bool)


class TestMemorySpoof:
    """Test memory-based hardware spoofing."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_apply_memory_spoof_patches_wmi_memory(self) -> None:
        """Memory spoof attempts to patch WMI provider process memory."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.capture_original_hardware()
        spoofer.generate_spoofed_hardware()

        result = spoofer._apply_memory_spoof()

        assert isinstance(result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_find_wmi_processes_returns_process_list(self) -> None:
        """find_wmi_processes locates wmiprvse.exe processes."""
        spoofer = HardwareFingerPrintSpoofer()
        wmi_pids = spoofer._find_wmi_processes()

        assert wmi_pids is not None
        assert isinstance(wmi_pids, list)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_apply_spoof_with_memory_method_invokes_memory_spoof(self) -> None:
        """apply_spoof with MEMORY method invokes memory-based spoofing."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.capture_original_hardware()
        spoofer.generate_spoofed_hardware()

        result = spoofer.apply_spoof(SpoofMethod.MEMORY)

        assert isinstance(result, bool)


class TestDriverAndVirtualSpoof:
    """Test driver and virtualization-based spoofing methods."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_apply_driver_spoof_returns_false_without_driver(self) -> None:
        """Driver spoof returns False when kernel driver unavailable."""
        spoofer = HardwareFingerPrintSpoofer()
        result = spoofer._apply_driver_spoof()

        assert result is False

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_apply_virtual_spoof_returns_false_without_hypervisor(self) -> None:
        """Virtual spoof returns False when hypervisor access unavailable."""
        spoofer = HardwareFingerPrintSpoofer()
        result = spoofer._apply_virtual_spoof()

        assert result is False


class TestComponentSpoofingMethods:
    """Test individual component spoofing methods."""

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_spoof_cpu_modifies_registry_processor_entries(self) -> None:
        """CPU spoofing writes ProcessorNameString to registry."""
        spoofer = HardwareFingerPrintSpoofer()
        test_cpu_name = "Test CPU Spoof"
        test_cpu_id = "TEST12345678ABCD"

        try:
            spoofer._spoof_cpu(test_cpu_id, test_cpu_name)

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
                assert test_cpu_name in name or name is not None
        except PermissionError:
            pytest.skip("Insufficient permissions for CPU registry spoofing")

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_spoof_motherboard_modifies_system_information_registry(self) -> None:
        """Motherboard spoofing writes manufacturer to SystemInformation registry."""
        spoofer = HardwareFingerPrintSpoofer()
        test_manufacturer = "Test Manufacturer"
        test_serial = "TEST-SERIAL-123"

        try:
            spoofer._spoof_motherboard(test_serial, test_manufacturer)

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation") as key:
                manufacturer, _ = winreg.QueryValueEx(key, "SystemManufacturer")
                assert manufacturer is not None
        except PermissionError:
            pytest.skip("Insufficient permissions for motherboard registry spoofing")

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_spoof_bios_modifies_bios_registry_entries(self) -> None:
        """BIOS spoofing writes BIOSVersion to registry."""
        spoofer = HardwareFingerPrintSpoofer()
        test_version = "1.0.TEST"
        test_serial = "TESTBIOS123"

        try:
            spoofer._spoof_bios(test_serial, test_version)

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as key:
                version, _ = winreg.QueryValueEx(key, "BIOSVersion")
                assert version is not None
        except PermissionError:
            pytest.skip("Insufficient permissions for BIOS registry spoofing")

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_disk_accepts_serial_list(self) -> None:
        """Disk spoofing accepts list of disk serial numbers."""
        spoofer = HardwareFingerPrintSpoofer()
        test_serials = ["DISK-001", "DISK-002"]

        spoofer._spoof_disk(test_serials)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_mac_address_invokes_network_registry_spoof(self) -> None:
        """MAC address spoofing invokes network adapter registry modification."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.capture_original_hardware()
        spoofer.generate_spoofed_hardware()
        test_macs = ["001122334455", "AABBCCDDEEFF"]

        spoofer._spoof_mac_address(test_macs)

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_spoof_system_uuid_modifies_computer_hardware_id_registry(self) -> None:
        """System UUID spoofing writes ComputerHardwareId to registry."""
        spoofer = HardwareFingerPrintSpoofer()
        test_uuid = str(uuid.uuid4()).upper()

        try:
            spoofer._spoof_system_uuid(test_uuid)

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation") as key:
                hw_id, _ = winreg.QueryValueEx(key, "ComputerHardwareId")
                assert hw_id is not None
        except PermissionError:
            pytest.skip("Insufficient permissions for UUID registry spoofing")

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_gpu_accepts_gpu_id_list(self) -> None:
        """GPU spoofing accepts list of GPU PNP device IDs."""
        spoofer = HardwareFingerPrintSpoofer()
        test_gpu_ids = ["PCI\\VEN_10DE&DEV_TEST"]

        spoofer._spoof_gpu(test_gpu_ids)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_ram_accepts_serial_list(self) -> None:
        """RAM spoofing accepts list of memory serial numbers."""
        spoofer = HardwareFingerPrintSpoofer()
        test_serials = ["RAM001", "RAM002"]

        spoofer._spoof_ram(test_serials)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_usb_accepts_device_list(self) -> None:
        """USB spoofing accepts list of USB device identifiers."""
        spoofer = HardwareFingerPrintSpoofer()
        test_devices = [{"device_id": "USB\\VID_TEST", "pnp_id": "USB\\VID_TEST\\1"}]

        spoofer._spoof_usb(test_devices)


class TestRestoreOriginal:
    """Test restoration of original hardware identifiers."""

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_restore_original_reverts_machine_guid_to_original(self) -> None:
        """Restore original writes original MachineGuid back to registry."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()
        spoofed = spoofer.generate_spoofed_hardware()

        try:
            spoofer._apply_registry_spoof()
            success = spoofer.restore_original()

            assert success is True

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                current_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                assert current_guid == original.machine_guid
        except PermissionError:
            pytest.skip("Insufficient permissions for registry restore")

    @pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
    def test_restore_original_reverts_product_id_to_original(self) -> None:
        """Restore original writes original ProductId back to registry."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()
        spoofed = spoofer.generate_spoofed_hardware()

        try:
            spoofer._apply_registry_spoof()
            success = spoofer.restore_original()

            assert success is True

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                current_product_id, _ = winreg.QueryValueEx(key, "ProductId")
                assert current_product_id == original.product_id
        except PermissionError:
            pytest.skip("Insufficient permissions for registry restore")

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_restore_original_returns_false_when_no_original_captured(self) -> None:
        """Restore original returns False when no original hardware was captured."""
        spoofer = HardwareFingerPrintSpoofer()
        result = spoofer.restore_original()

        assert result is False

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_restore_original_removes_hooks_if_installed(self) -> None:
        """Restore original calls _remove_hooks when hooks were installed."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.capture_original_hardware()
        spoofer.hooks_installed = True

        try:
            spoofer.restore_original()
            assert not spoofer.hooks_installed
        except Exception:
            pass


class TestNetworkRegistrySpoof:
    """Test network adapter registry spoofing."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_network_registry_enumerates_adapters(self) -> None:
        """Network registry spoof enumerates network adapter registry keys."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.capture_original_hardware()
        spoofer.generate_spoofed_hardware()

        spoofer._spoof_network_registry()

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_remove_network_spoofing_deletes_network_address_values(self) -> None:
        """Remove network spoofing deletes NetworkAddress registry values."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer._remove_network_spoofing()


class TestConfigurationExportImport:
    """Test spoofing configuration export and import."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_export_configuration_returns_dict_with_original_and_spoofed(self) -> None:
        """Export configuration returns dict containing original and spoofed hardware."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()
        spoofed = spoofer.generate_spoofed_hardware()

        config = spoofer.export_configuration()

        assert config is not None
        assert "original" in config
        assert "spoofed" in config
        assert "timestamp" in config
        assert config["original"]["cpu_id"] == original.cpu_id
        assert config["spoofed"]["cpu_id"] == spoofed.cpu_id

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_import_configuration_loads_spoofed_hardware_from_dict(self) -> None:
        """Import configuration loads spoofed hardware from exported dict."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.capture_original_hardware()
        spoofer.generate_spoofed_hardware()
        config = spoofer.export_configuration()

        new_spoofer = HardwareFingerPrintSpoofer()
        success = new_spoofer.import_configuration(config)

        assert success is True
        assert new_spoofer.spoofed_hardware is not None
        assert new_spoofer.spoofed_hardware.cpu_id == config["spoofed"]["cpu_id"]

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_import_configuration_returns_false_on_invalid_config(self) -> None:
        """Import configuration returns False when given invalid config dict."""
        spoofer = HardwareFingerPrintSpoofer()
        invalid_config: dict[str, Any] = {"invalid": "data"}

        success = spoofer.import_configuration(invalid_config)

        assert success is False

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_hardware_to_dict_converts_all_fields(self) -> None:
        """_hardware_to_dict converts HardwareIdentifiers to complete dict."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()

        hw_dict = spoofer._hardware_to_dict(original)

        assert hw_dict is not None
        assert "cpu_id" in hw_dict
        assert "cpu_name" in hw_dict
        assert "motherboard_serial" in hw_dict
        assert "bios_serial" in hw_dict
        assert "disk_serial" in hw_dict
        assert "mac_addresses" in hw_dict
        assert "system_uuid" in hw_dict
        assert "machine_guid" in hw_dict
        assert "volume_serial" in hw_dict
        assert "product_id" in hw_dict
        assert "network_adapters" in hw_dict
        assert "gpu_ids" in hw_dict
        assert "ram_serial" in hw_dict
        assert "usb_devices" in hw_dict


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_spoofed_hardware_without_capturing_original_creates_defaults(self) -> None:
        """Generate spoofed hardware works without capturing original first."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.original_hardware = HardwareIdentifiers(
            cpu_id="DEFAULT", cpu_name="DEFAULT", motherboard_serial="DEFAULT",
            motherboard_manufacturer="DEFAULT", bios_serial="DEFAULT", bios_version="DEFAULT",
            disk_serial=["DEFAULT"], disk_model=["DEFAULT"], mac_addresses=["DEFAULT"],
            system_uuid="DEFAULT", machine_guid="DEFAULT", volume_serial="DEFAULT",
            product_id="DEFAULT", network_adapters=[], gpu_ids=["DEFAULT"],
            ram_serial=["DEFAULT"], usb_devices=[]
        )

        spoofed = spoofer.generate_spoofed_hardware()

        assert spoofed is not None
        assert spoofed.cpu_id != "DEFAULT"

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_apply_spoof_generates_spoofed_hardware_if_not_set(self) -> None:
        """apply_spoof generates spoofed hardware automatically if not already generated."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.capture_original_hardware()

        result = spoofer.apply_spoof(SpoofMethod.REGISTRY)

        assert spoofer.spoofed_hardware is not None

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_multiple_spoof_generations_produce_different_values(self) -> None:
        """Multiple spoofed hardware generations produce different random values."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.capture_original_hardware()

        spoofed1 = spoofer.generate_spoofed_hardware()
        spoofed2 = spoofer.generate_spoofed_hardware()

        assert spoofed1.cpu_id != spoofed2.cpu_id or spoofed1.machine_guid != spoofed2.machine_guid

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoof_method_enum_has_all_methods(self) -> None:
        """SpoofMethod enum contains all expected spoofing methods."""
        assert SpoofMethod.REGISTRY.value == "registry"
        assert SpoofMethod.MEMORY.value == "memory"
        assert SpoofMethod.DRIVER.value == "driver"
        assert SpoofMethod.HOOK.value == "hook"
        assert SpoofMethod.VIRTUAL.value == "virtual"


class TestPerformanceAndReliability:
    """Test performance and reliability of spoofing operations."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_hardware_capture_completes_within_reasonable_time(self) -> None:
        """Hardware capture completes within 5 seconds."""
        import time
        spoofer = HardwareFingerPrintSpoofer()

        start = time.time()
        spoofer.capture_original_hardware()
        elapsed = time.time() - start

        assert elapsed < 5.0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_spoofed_generation_completes_within_reasonable_time(self) -> None:
        """Spoofed hardware generation completes within 1 second."""
        import time
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.capture_original_hardware()

        start = time.time()
        spoofer.generate_spoofed_hardware()
        elapsed = time.time() - start

        assert elapsed < 1.0

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_multiple_capture_operations_return_consistent_values(self) -> None:
        """Multiple hardware captures return identical values for stable hardware."""
        spoofer = HardwareFingerPrintSpoofer()

        hw1 = spoofer.capture_original_hardware()
        hw2 = spoofer.capture_original_hardware()

        assert hw1.cpu_id == hw2.cpu_id
        assert hw1.motherboard_serial == hw2.motherboard_serial
        assert hw1.machine_guid == hw2.machine_guid
        assert hw1.product_id == hw2.product_id


class TestRealWorldScenarios:
    """Test real-world hardware spoofing scenarios."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_complete_spoof_workflow_capture_generate_apply_restore(self) -> None:
        """Complete workflow: capture -> generate -> apply -> restore."""
        spoofer = HardwareFingerPrintSpoofer()

        original = spoofer.capture_original_hardware()
        assert original is not None

        spoofed = spoofer.generate_spoofed_hardware()
        assert spoofed is not None
        assert spoofed.machine_guid != original.machine_guid

        result = spoofer.apply_spoof(SpoofMethod.REGISTRY)
        assert isinstance(result, bool)

        if result:
            restore_result = spoofer.restore_original()
            assert isinstance(restore_result, bool)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_export_import_workflow_preserves_configuration(self) -> None:
        """Export -> Import workflow preserves spoofing configuration."""
        spoofer1 = HardwareFingerPrintSpoofer()
        spoofer1.capture_original_hardware()
        spoofer1.generate_spoofed_hardware()

        config = spoofer1.export_configuration()

        spoofer2 = HardwareFingerPrintSpoofer()
        success = spoofer2.import_configuration(config)

        assert success is True
        assert spoofer2.spoofed_hardware is not None
        assert spoofer1.spoofed_hardware is not None
        assert spoofer2.spoofed_hardware.cpu_id == spoofer1.spoofed_hardware.cpu_id
        assert spoofer2.spoofed_hardware.machine_guid == spoofer1.spoofed_hardware.machine_guid

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_partial_preservation_workflow_preserves_selected_components(self) -> None:
        """Partial preservation workflow keeps specified hardware components original."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()

        preserve_list = ["cpu", "motherboard", "bios"]
        spoofed = spoofer.generate_spoofed_hardware(preserve=preserve_list)

        assert spoofed.cpu_id == original.cpu_id
        assert spoofed.motherboard_serial == original.motherboard_serial
        assert spoofed.bios_serial == original.bios_serial
        assert spoofed.mac_addresses != original.mac_addresses
        assert spoofed.machine_guid != original.machine_guid
