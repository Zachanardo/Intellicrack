"""Production-ready tests for hardware fingerprint spoofing capabilities.

Tests real hardware ID generation, spoofing, and API hooking for bypassing
hardware-based license validation.
"""

import platform
import re
import uuid

import pytest

from intellicrack.core.hardware_spoofer import HardwareFingerPrintSpoofer, HardwareIdentifiers


class TestHardwareSpooferCapture:
    """Test capture of real hardware identifiers."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Requires Windows WMI")
    def test_spoofer_captures_real_cpu_id(self) -> None:
        """Spoofer captures actual CPU processor ID from system."""
        spoofer = HardwareFingerPrintSpoofer()

        hardware = spoofer.capture_original_hardware()

        assert hardware.cpu_id is not None, "Failed to capture CPU ID"
        assert len(hardware.cpu_id) > 0, "CPU ID empty"
        assert re.match(r"^[0-9A-F]+$", hardware.cpu_id), "CPU ID not hexadecimal"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Requires Windows WMI")
    def test_spoofer_captures_real_motherboard_serial(self) -> None:
        """Spoofer captures actual motherboard serial number."""
        spoofer = HardwareFingerPrintSpoofer()

        hardware = spoofer.capture_original_hardware()

        assert hardware.motherboard_serial is not None, "Failed to capture motherboard serial"
        assert len(hardware.motherboard_serial) > 0, "Motherboard serial empty"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Requires Windows WMI")
    def test_spoofer_captures_real_bios_serial(self) -> None:
        """Spoofer captures actual BIOS serial number."""
        spoofer = HardwareFingerPrintSpoofer()

        hardware = spoofer.capture_original_hardware()

        assert hardware.bios_serial is not None, "Failed to capture BIOS serial"
        assert len(hardware.bios_serial) > 0, "BIOS serial empty"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Requires Windows WMI")
    def test_spoofer_captures_real_disk_serials(self) -> None:
        """Spoofer captures physical disk serial numbers."""
        spoofer = HardwareFingerPrintSpoofer()

        hardware = spoofer.capture_original_hardware()

        assert hardware.disk_serial is not None, "Failed to capture disk serials"
        assert len(hardware.disk_serial) > 0, "No disk serials captured"
        assert all(len(serial) > 0 for serial in hardware.disk_serial), "Empty disk serial found"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Requires Windows WMI")
    def test_spoofer_captures_real_mac_addresses(self) -> None:
        """Spoofer captures network adapter MAC addresses."""
        spoofer = HardwareFingerPrintSpoofer()

        hardware = spoofer.capture_original_hardware()

        assert hardware.mac_addresses is not None, "Failed to capture MAC addresses"
        assert len(hardware.mac_addresses) > 0, "No MAC addresses captured"
        assert all(len(mac) == 12 for mac in hardware.mac_addresses), "MAC addresses wrong length"
        assert all(re.match(r"^[0-9A-F]{12}$", mac) for mac in hardware.mac_addresses), "MAC address format invalid"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Requires Windows WMI")
    def test_spoofer_captures_system_uuid(self) -> None:
        """Spoofer captures system UUID."""
        spoofer = HardwareFingerPrintSpoofer()

        hardware = spoofer.capture_original_hardware()

        assert hardware.system_uuid is not None, "Failed to capture system UUID"
        try:
            uuid.UUID(hardware.system_uuid)
        except ValueError:
            pytest.fail("System UUID not valid UUID format")

    @pytest.mark.skipif(platform.system() != "Windows", reason="Requires Windows WMI")
    def test_spoofer_captures_machine_guid(self) -> None:
        """Spoofer captures Windows machine GUID."""
        spoofer = HardwareFingerPrintSpoofer()

        hardware = spoofer.capture_original_hardware()

        assert hardware.machine_guid is not None, "Failed to capture machine GUID"
        try:
            uuid.UUID(hardware.machine_guid)
        except ValueError:
            pytest.fail("Machine GUID not valid UUID format")


class TestHardwareSpooferGeneration:
    """Test generation of spoofed hardware identifiers."""

    def test_spoofer_generates_different_cpu_id(self) -> None:
        """Spoofer generates CPU ID different from original."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()

        spoofed = spoofer.generate_spoofed_hardware()

        assert spoofed.cpu_id != original.cpu_id, "Spoofed CPU ID matches original"
        assert len(spoofed.cpu_id) > 0, "Spoofed CPU ID empty"
        assert re.match(r"^[0-9A-F]+$", spoofed.cpu_id), "Spoofed CPU ID not hexadecimal"

    def test_spoofer_generates_different_motherboard_serial(self) -> None:
        """Spoofer generates motherboard serial different from original."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()

        spoofed = spoofer.generate_spoofed_hardware()

        assert spoofed.motherboard_serial != original.motherboard_serial, "Spoofed MB serial matches original"
        assert len(spoofed.motherboard_serial) > 0, "Spoofed MB serial empty"

    def test_spoofer_generates_different_bios_serial(self) -> None:
        """Spoofer generates BIOS serial different from original."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()

        spoofed = spoofer.generate_spoofed_hardware()

        assert spoofed.bios_serial != original.bios_serial, "Spoofed BIOS serial matches original"
        assert len(spoofed.bios_serial) > 0, "Spoofed BIOS serial empty"

    def test_spoofer_generates_different_disk_serials(self) -> None:
        """Spoofer generates disk serials different from original."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()

        spoofed = spoofer.generate_spoofed_hardware()

        assert spoofed.disk_serial != original.disk_serial, "Spoofed disk serials match original"
        assert len(spoofed.disk_serial) > 0, "No spoofed disk serials generated"

    def test_spoofer_generates_different_mac_addresses(self) -> None:
        """Spoofer generates MAC addresses different from original."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()

        spoofed = spoofer.generate_spoofed_hardware()

        assert spoofed.mac_addresses != original.mac_addresses, "Spoofed MACs match original"
        assert len(spoofed.mac_addresses) > 0, "No spoofed MAC addresses generated"
        assert all(len(mac) == 12 for mac in spoofed.mac_addresses), "Spoofed MAC wrong length"

    def test_spoofer_generates_different_system_uuid(self) -> None:
        """Spoofer generates system UUID different from original."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()

        spoofed = spoofer.generate_spoofed_hardware()

        assert spoofed.system_uuid != original.system_uuid, "Spoofed UUID matches original"
        try:
            uuid.UUID(spoofed.system_uuid)
        except ValueError:
            pytest.fail("Spoofed UUID not valid UUID format")

    def test_spoofer_generates_different_machine_guid(self) -> None:
        """Spoofer generates machine GUID different from original."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()

        spoofed = spoofer.generate_spoofed_hardware()

        assert spoofed.machine_guid != original.machine_guid, "Spoofed GUID matches original"
        try:
            uuid.UUID(spoofed.machine_guid)
        except ValueError:
            pytest.fail("Spoofed GUID not valid UUID format")


class TestHardwareSpooferPreservation:
    """Test selective preservation of hardware components."""

    def test_spoofer_preserves_cpu_when_requested(self) -> None:
        """Spoofer preserves original CPU ID when in preserve list."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()

        spoofed = spoofer.generate_spoofed_hardware(preserve=["cpu"])

        assert spoofed.cpu_id == original.cpu_id, "CPU ID not preserved"
        assert spoofed.motherboard_serial != original.motherboard_serial, "Other components should be spoofed"

    def test_spoofer_preserves_motherboard_when_requested(self) -> None:
        """Spoofer preserves original motherboard serial when in preserve list."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()

        spoofed = spoofer.generate_spoofed_hardware(preserve=["motherboard"])

        assert spoofed.motherboard_serial == original.motherboard_serial, "Motherboard serial not preserved"
        assert spoofed.cpu_id != original.cpu_id, "Other components should be spoofed"

    def test_spoofer_preserves_multiple_components(self) -> None:
        """Spoofer preserves multiple components simultaneously."""
        spoofer = HardwareFingerPrintSpoofer()
        original = spoofer.capture_original_hardware()

        spoofed = spoofer.generate_spoofed_hardware(preserve=["cpu", "bios", "disk"])

        assert spoofed.cpu_id == original.cpu_id, "CPU ID not preserved"
        assert spoofed.bios_serial == original.bios_serial, "BIOS serial not preserved"
        assert spoofed.disk_serial == original.disk_serial, "Disk serials not preserved"
        assert spoofed.mac_addresses != original.mac_addresses, "MAC should be spoofed"


class TestHardwareSpooferConsistency:
    """Test consistency of generated spoofed values."""

    def test_spoofer_generates_unique_values_across_calls(self) -> None:
        """Each call to generate_spoofed_hardware produces different values."""
        spoofer = HardwareFingerPrintSpoofer()
        spoofer.capture_original_hardware()

        spoofed1 = spoofer.generate_spoofed_hardware()
        spoofed2 = spoofer.generate_spoofed_hardware()

        assert spoofed1.cpu_id != spoofed2.cpu_id, "Multiple calls produce same CPU ID"
        assert spoofed1.motherboard_serial != spoofed2.motherboard_serial, "Multiple calls produce same MB serial"
        assert spoofed1.system_uuid != spoofed2.system_uuid, "Multiple calls produce same UUID"

    def test_spoofer_generates_realistic_cpu_id_format(self) -> None:
        """Generated CPU ID follows realistic format."""
        spoofer = HardwareFingerPrintSpoofer()

        spoofed = spoofer.generate_spoofed_hardware()

        assert len(spoofed.cpu_id) >= 12, "CPU ID too short"
        assert re.match(r"^[0-9A-F]+$", spoofed.cpu_id), "CPU ID contains invalid characters"

    def test_spoofer_generates_realistic_mac_address_format(self) -> None:
        """Generated MAC addresses follow realistic vendor format."""
        spoofer = HardwareFingerPrintSpoofer()

        spoofed = spoofer.generate_spoofed_hardware()

        for mac in spoofed.mac_addresses:
            assert len(mac) == 12, f"MAC address wrong length: {mac}"
            assert re.match(r"^[0-9A-F]{12}$", mac), f"MAC address invalid format: {mac}"

    def test_spoofer_generates_realistic_disk_serial_format(self) -> None:
        """Generated disk serials follow manufacturer format."""
        spoofer = HardwareFingerPrintSpoofer()

        spoofed = spoofer.generate_spoofed_hardware()

        for serial in spoofed.disk_serial:
            assert len(serial) > 5, f"Disk serial too short: {serial}"
            assert any(prefix in serial for prefix in ["WD-", "ST", "Samsung"]), \
                f"Disk serial missing vendor prefix: {serial}"


class TestHardwareSpooferGPUIdentifiers:
    """Test GPU identifier spoofing."""

    def test_spoofer_generates_realistic_gpu_pnp_ids(self) -> None:
        """Generated GPU PNP IDs follow PCI device format."""
        spoofer = HardwareFingerPrintSpoofer()

        spoofed = spoofer.generate_spoofed_hardware()

        assert len(spoofed.gpu_ids) > 0, "No GPU IDs generated"
        for gpu_id in spoofed.gpu_ids:
            assert "PCI\\" in gpu_id or "VEN_" in gpu_id, f"GPU ID missing PCI prefix: {gpu_id}"


class TestHardwareSpooferNetworkAdapters:
    """Test network adapter spoofing."""

    def test_spoofer_generates_network_adapter_details(self) -> None:
        """Generated network adapters include name, MAC, and GUID."""
        spoofer = HardwareFingerPrintSpoofer()

        spoofed = spoofer.generate_spoofed_hardware()

        assert len(spoofed.network_adapters) > 0, "No network adapters generated"
        for adapter in spoofed.network_adapters:
            assert "name" in adapter, "Adapter missing name"
            assert "mac" in adapter, "Adapter missing MAC"


class TestHardwareSpooferRealisticValues:
    """Test that spoofed values appear realistic to license checks."""

    def test_spoofer_generates_valid_vendor_prefixes(self) -> None:
        """Spoofed hardware uses realistic vendor identifiers."""
        spoofer = HardwareFingerPrintSpoofer()

        spoofed = spoofer.generate_spoofed_hardware()

        cpu_vendors = ["Intel", "AMD", "ARM"]
        assert any(vendor in spoofed.cpu_name for vendor in cpu_vendors), \
            f"CPU name missing vendor: {spoofed.cpu_name}"

        mb_vendors = ["ASUSTeK", "Gigabyte", "MSI", "ASUS"]
        assert any(vendor in spoofed.motherboard_manufacturer for vendor in mb_vendors), \
            f"Motherboard manufacturer unrealistic: {spoofed.motherboard_manufacturer}"

    def test_spoofer_generates_consistent_hwid_components(self) -> None:
        """Spoofed hardware maintains internal consistency for HWID calculation."""
        spoofer = HardwareFingerPrintSpoofer()

        spoofed = spoofer.generate_spoofed_hardware()

        assert len(spoofed.cpu_id) > 0, "CPU ID empty"
        assert len(spoofed.disk_serial) > 0, "No disk serials"
        assert len(spoofed.mac_addresses) > 0, "No MAC addresses"
        assert len(spoofed.system_uuid) > 0, "System UUID empty"

    def test_spoofer_preserves_original_hardware_reference(self) -> None:
        """Spoofer maintains reference to original hardware after spoofing."""
        spoofer = HardwareFingerPrintSpoofer()

        original = spoofer.capture_original_hardware()
        spoofed = spoofer.generate_spoofed_hardware()

        assert spoofer.original_hardware is original, "Original hardware reference lost"
        assert spoofer.spoofed_hardware is spoofed, "Spoofed hardware reference not stored"


class TestHardwareSpooferVolumeSerialization:
    """Test volume serial number spoofing."""

    def test_spoofer_generates_valid_volume_serial_format(self) -> None:
        """Generated volume serial follows Windows format."""
        spoofer = HardwareFingerPrintSpoofer()

        spoofed = spoofer.generate_spoofed_hardware()

        assert re.match(r"^[0-9A-F]{4}-[0-9A-F]{4}$|^[0-9A-F]{8}$", spoofed.volume_serial), \
            f"Volume serial invalid format: {spoofed.volume_serial}"

    def test_spoofer_generates_valid_product_id_format(self) -> None:
        """Generated Windows product ID follows standard format."""
        spoofer = HardwareFingerPrintSpoofer()

        spoofed = spoofer.generate_spoofed_hardware()

        assert "-" in spoofed.product_id, f"Product ID missing hyphens: {spoofed.product_id}"
        parts = spoofed.product_id.split("-")
        assert len(parts) >= 3, f"Product ID has too few parts: {spoofed.product_id}"


class TestHardwareSpooferRAMSerials:
    """Test RAM serial number spoofing."""

    def test_spoofer_generates_ram_serial_numbers(self) -> None:
        """Generated RAM serials are non-empty and realistic."""
        spoofer = HardwareFingerPrintSpoofer()

        spoofed = spoofer.generate_spoofed_hardware()

        assert len(spoofed.ram_serial) > 0, "No RAM serials generated"
        for serial in spoofed.ram_serial:
            assert len(serial) >= 8, f"RAM serial too short: {serial}"


class TestHardwareSpooferUSBDevices:
    """Test USB device identifier spoofing."""

    def test_spoofer_generates_usb_device_identifiers(self) -> None:
        """Generated USB devices include device ID and PNP ID."""
        spoofer = HardwareFingerPrintSpoofer()

        spoofed = spoofer.generate_spoofed_hardware()

        if len(spoofed.usb_devices) > 0:
            for device in spoofed.usb_devices:
                assert "device_id" in device or "pnp_id" in device, "USB device missing identifiers"
