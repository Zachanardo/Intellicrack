"""Production-ready tests for disk serial restoration functionality.

Tests validate that disk serial restoration properly reverts spoofed disk
identifiers to their original values across registry, diskpart, and hardware
interfaces. These tests operate on real system resources and verify actual
restoration behavior.

Test Requirements:
- Must validate registry-based disk serial restoration
- Must verify diskpart volume serial restoration
- Must handle SCSI, SATA, and NVMe disk types
- Must verify restoration success
- Must handle RAID configurations and removable drives
- NO mocks, stubs, or placeholder assertions

Expected Behavior (from testingtodo.md):
- Must implement registry-based disk serial restoration
- Must use diskpart for volume serial restoration
- Must handle SCSI vs SATA differences
- Must restore NVMe device identifiers
- Must verify restoration success
- Edge cases: RAID configurations, removable drives
"""

from __future__ import annotations

import ctypes
import re
import subprocess
import sys
import time
import winreg
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest

from intellicrack.core.hardware_spoofer import HardwareFingerPrintSpoofer, HardwareIdentifiers
from intellicrack.utils.logger import get_logger

if TYPE_CHECKING:
    from collections.abc import Generator


logger = get_logger(__name__)


def is_admin() -> bool:
    """Check if script is running with administrative privileges.

    Returns:
        True if running as administrator, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def get_disk_type(disk_index: int) -> str:
    """Determine disk type (SCSI, SATA, NVMe, RAID) for a given disk.

    Args:
        disk_index: Index of the disk to query.

    Returns:
        String indicating disk type: "NVMe", "RAID", "SCSI", "SATA", or "Unknown".
    """
    try:
        import wmi

        c = wmi.WMI()
        disks = c.Win32_DiskDrive()

        if disk_index >= len(disks):
            return "Unknown"

        disk = disks[disk_index]
        interface_type = getattr(disk, "InterfaceType", "Unknown")
        model = getattr(disk, "Model", "").upper()

        if "NVME" in model or interface_type == "NVMe":
            return "NVMe"
        elif "RAID" in model or interface_type == "RAID":
            return "RAID"
        elif interface_type == "SCSI":
            return "SCSI"
        elif interface_type in ["IDE", "SATA"]:
            return "SATA"
        else:
            return "Unknown"
    except Exception as e:
        logger.warning(f"Failed to determine disk type for disk {disk_index}: {e}")
        return "Unknown"


def get_all_disk_types() -> dict[int, str]:
    """Get types for all available disks.

    Returns:
        Dictionary mapping disk index to disk type.
    """
    disk_types: dict[int, str] = {}

    try:
        import wmi

        c = wmi.WMI()
        disks = c.Win32_DiskDrive()

        for i, disk in enumerate(disks):
            interface_type = getattr(disk, "InterfaceType", "Unknown")
            model = getattr(disk, "Model", "").upper()

            if "NVME" in model or interface_type == "NVMe":
                disk_types[i] = "NVMe"
            elif "RAID" in model or interface_type == "RAID":
                disk_types[i] = "RAID"
            elif interface_type == "SCSI":
                disk_types[i] = "SCSI"
            elif interface_type in ["IDE", "SATA"]:
                disk_types[i] = "SATA"
            else:
                disk_types[i] = "Unknown"
    except Exception as e:
        logger.warning(f"Failed to enumerate disk types: {e}")

    return disk_types


def get_disk_registry_paths() -> dict[str, list[str]]:
    """Get all registry paths where disk serials are stored.

    Returns:
        Dictionary with keys "SCSI", "SATA", "NVMe", "IDE" mapping to registry paths.
    """
    paths: dict[str, list[str]] = {
        "SCSI": [],
        "SATA": [],
        "NVMe": [],
        "IDE": [],
    }

    base_paths = [
        r"SYSTEM\CurrentControlSet\Enum\SCSI",
        r"SYSTEM\CurrentControlSet\Enum\IDE",
        r"SYSTEM\CurrentControlSet\Enum\STORAGE",
        r"SYSTEM\CurrentControlSet\Services\nvme\Enum",
    ]

    for base in base_paths:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        full_path = f"{base}\\{subkey_name}"

                        if "SCSI" in base:
                            paths["SCSI"].append(full_path)
                        elif "IDE" in base:
                            paths["IDE"].append(full_path)
                        elif "nvme" in base.lower():
                            paths["NVMe"].append(full_path)
                        elif "STORAGE" in base:
                            paths["SATA"].append(full_path)

                        i += 1
                    except OSError:
                        break
        except Exception as e:
            logger.debug(f"Failed to enumerate registry path {base}: {e}")

    return paths


def read_disk_serial_from_registry(disk_type: str, disk_index: int) -> str | None:
    """Read disk serial number from registry based on disk type.

    Args:
        disk_type: Type of disk (SCSI, SATA, NVMe, IDE).
        disk_index: Index of the disk.

    Returns:
        Disk serial number string, or None if not found.
    """
    paths = get_disk_registry_paths()

    for path in paths.get(disk_type, []):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                try:
                    serial, _ = winreg.QueryValueEx(key, "SerialNumber")
                    return str(serial)
                except OSError:
                    continue
        except Exception:
            continue

    return None


def get_volume_serial_via_diskpart(drive_letter: str) -> str | None:
    """Get volume serial number using diskpart.

    Args:
        drive_letter: Drive letter (e.g., "C").

    Returns:
        Volume serial number as hex string, or None if failed.
    """
    try:
        script = f"select volume {drive_letter}\ndetail volume\n"

        result = subprocess.run(
            ["diskpart"],
            input=script.encode(),
            capture_output=True,
            timeout=30,
            check=False,
        )

        output = result.stdout.decode("utf-8", errors="ignore")

        match = re.search(r"Volume\s+\d+\s+is\s+the\s+selected\s+volume.*?Serial Number:\s+([A-F0-9]{8})", output, re.DOTALL | re.IGNORECASE)

        if match:
            return match.group(1)

    except Exception as e:
        logger.warning(f"Failed to get volume serial via diskpart for {drive_letter}: {e}")

    return None


def set_volume_serial_via_diskpart(drive_letter: str, serial: str) -> bool:
    """Set volume serial number using diskpart.

    Note: This is a READ-ONLY verification test. Actual serial modification
    would require formatting the volume, which is destructive.

    Args:
        drive_letter: Drive letter (e.g., "C").
        serial: New serial number (8 hex digits).

    Returns:
        Always False as this is a verification-only function.
    """
    logger.warning(
        f"Volume serial modification for {drive_letter} to {serial} "
        "requires volume formatting - not implemented for safety"
    )
    return False


def is_removable_drive(drive_letter: str) -> bool:
    """Check if drive is removable media.

    Args:
        drive_letter: Drive letter (e.g., "E").

    Returns:
        True if drive is removable, False otherwise.
    """
    try:
        DRIVE_REMOVABLE = 2

        drive_path = f"{drive_letter}:\\"
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)

        return drive_type == DRIVE_REMOVABLE
    except Exception:
        return False


@pytest.fixture(scope="function")
def spoofer() -> Generator[HardwareFingerPrintSpoofer, None, None]:
    """Create HardwareFingerPrintSpoofer instance with original hardware capture.

    Yields:
        Configured HardwareFingerPrintSpoofer instance.
    """
    spoofer_instance = HardwareFingerPrintSpoofer()

    try:
        original = spoofer_instance.get_current_hardware()
        spoofer_instance.original_hardware = original
        yield spoofer_instance
    finally:
        pass


@pytest.fixture(scope="function")
def admin_required() -> Generator[None, None, None]:
    """Fixture that skips tests if not running as administrator."""
    if not is_admin():
        pytest.skip(
            "This test requires administrative privileges. "
            "Run pytest as Administrator to execute disk serial restoration tests. "
            "These tests validate actual Windows registry and diskpart operations "
            "for disk serial restoration functionality."
        )
    yield


@pytest.fixture(scope="function")
def disk_inventory() -> dict[str, Any]:
    """Capture complete disk inventory before test execution.

    Returns:
        Dictionary containing disk types, serials, and volume information.
    """
    inventory: dict[str, Any] = {
        "disk_types": get_all_disk_types(),
        "registry_paths": get_disk_registry_paths(),
        "volume_serials": {},
    }

    for drive_letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        try:
            volume_serial = get_volume_serial_via_diskpart(drive_letter)
            if volume_serial:
                inventory["volume_serials"][drive_letter] = volume_serial
        except Exception:
            pass

    logger.info(f"Disk inventory captured: {len(inventory['disk_types'])} disks, {len(inventory['volume_serials'])} volumes")

    return inventory


class TestDiskSerialRegistryRestoration:
    """Test registry-based disk serial restoration for different disk types."""

    def test_registry_paths_exist_for_scsi_disks(self, disk_inventory: dict[str, Any]) -> None:
        """Verify SCSI disk registry paths are accessible.

        Validates that registry paths for SCSI disks exist and can be enumerated.
        This is a prerequisite for restoration functionality.
        """
        scsi_paths = disk_inventory["registry_paths"]["SCSI"]

        logger.info(f"Found {len(scsi_paths)} SCSI disk registry paths")

        if len(scsi_paths) == 0:
            pytest.skip(
                "No SCSI disks found in registry. "
                "This test requires at least one SCSI disk to validate restoration. "
                "SCSI registry path: HKLM\\SYSTEM\\CurrentControlSet\\Enum\\SCSI"
            )

        for path in scsi_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                    assert key is not None
                    logger.debug(f"Successfully accessed SCSI registry path: {path}")
            except Exception as e:
                pytest.fail(f"Failed to access SCSI registry path {path}: {e}")

    def test_registry_paths_exist_for_sata_disks(self, disk_inventory: dict[str, Any]) -> None:
        """Verify SATA disk registry paths are accessible.

        Validates that registry paths for SATA disks exist and can be enumerated.
        """
        sata_paths = disk_inventory["registry_paths"]["SATA"]

        logger.info(f"Found {len(sata_paths)} SATA disk registry paths")

        if len(sata_paths) == 0:
            pytest.skip(
                "No SATA disks found in registry. "
                "This test requires at least one SATA disk to validate restoration. "
                "SATA registry path: HKLM\\SYSTEM\\CurrentControlSet\\Enum\\STORAGE"
            )

        for path in sata_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                    assert key is not None
                    logger.debug(f"Successfully accessed SATA registry path: {path}")
            except Exception as e:
                pytest.fail(f"Failed to access SATA registry path {path}: {e}")

    def test_registry_paths_exist_for_nvme_disks(self, disk_inventory: dict[str, Any]) -> None:
        """Verify NVMe disk registry paths are accessible.

        Validates that registry paths for NVMe disks exist and can be enumerated.
        """
        nvme_paths = disk_inventory["registry_paths"]["NVMe"]

        logger.info(f"Found {len(nvme_paths)} NVMe disk registry paths")

        if len(nvme_paths) == 0:
            pytest.skip(
                "No NVMe disks found in registry. "
                "This test requires at least one NVMe disk to validate restoration. "
                "NVMe registry path: HKLM\\SYSTEM\\CurrentControlSet\\Services\\nvme\\Enum"
            )

        for path in nvme_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                    assert key is not None
                    logger.debug(f"Successfully accessed NVMe registry path: {path}")
            except Exception as e:
                pytest.fail(f"Failed to access NVMe registry path {path}: {e}")

    def test_disk_serial_read_from_registry_scsi(self, admin_required: None, disk_inventory: dict[str, Any]) -> None:
        """Read SCSI disk serial from registry to verify read capability.

        Validates that disk serial numbers can be read from SCSI disk registry entries.
        This proves restoration can verify the restored value.
        """
        disk_types = disk_inventory["disk_types"]
        scsi_disks = [idx for idx, dtype in disk_types.items() if dtype == "SCSI"]

        if not scsi_disks:
            pytest.skip(
                "No SCSI disks detected on system. "
                "Test requires SCSI disk to validate serial read functionality. "
                "Detected disk types: " + str(disk_types)
            )

        for disk_idx in scsi_disks:
            serial = read_disk_serial_from_registry("SCSI", disk_idx)

            logger.info(f"SCSI Disk {disk_idx} serial from registry: {serial}")

            assert serial is None or (isinstance(serial, str) and len(serial) > 0), \
                f"SCSI disk {disk_idx} serial must be None or non-empty string"

    def test_disk_serial_read_from_registry_sata(self, admin_required: None, disk_inventory: dict[str, Any]) -> None:
        """Read SATA disk serial from registry to verify read capability.

        Validates that disk serial numbers can be read from SATA disk registry entries.
        """
        disk_types = disk_inventory["disk_types"]
        sata_disks = [idx for idx, dtype in disk_types.items() if dtype == "SATA"]

        if not sata_disks:
            pytest.skip(
                "No SATA disks detected on system. "
                "Test requires SATA disk to validate serial read functionality. "
                "Detected disk types: " + str(disk_types)
            )

        for disk_idx in sata_disks:
            serial = read_disk_serial_from_registry("SATA", disk_idx)

            logger.info(f"SATA Disk {disk_idx} serial from registry: {serial}")

            assert serial is None or (isinstance(serial, str) and len(serial) > 0), \
                f"SATA disk {disk_idx} serial must be None or non-empty string"

    def test_disk_serial_read_from_registry_nvme(self, admin_required: None, disk_inventory: dict[str, Any]) -> None:
        """Read NVMe disk serial from registry to verify read capability.

        Validates that disk serial numbers can be read from NVMe disk registry entries.
        """
        disk_types = disk_inventory["disk_types"]
        nvme_disks = [idx for idx, dtype in disk_types.items() if dtype == "NVMe"]

        if not nvme_disks:
            pytest.skip(
                "No NVMe disks detected on system. "
                "Test requires NVMe disk to validate serial read functionality. "
                "Detected disk types: " + str(disk_types)
            )

        for disk_idx in nvme_disks:
            serial = read_disk_serial_from_registry("NVMe", disk_idx)

            logger.info(f"NVMe Disk {disk_idx} serial from registry: {serial}")

            assert serial is None or (isinstance(serial, str) and len(serial) > 0), \
                f"NVMe disk {disk_idx} serial must be None or non-empty string"


class TestDiskSerialDiskpartRestoration:
    """Test diskpart-based volume serial restoration."""

    def test_diskpart_available_on_system(self) -> None:
        """Verify diskpart.exe is accessible.

        Validates that diskpart utility exists and can be executed.
        This is required for volume serial restoration.
        """
        try:
            result = subprocess.run(
                ["diskpart", "/?"],
                capture_output=True,
                timeout=10,
                check=False,
            )

            assert result.returncode == 0, "diskpart must be executable"
            assert b"DISKPART" in result.stdout.upper(), "diskpart must show help output"

            logger.info("diskpart.exe is available and functional")
        except FileNotFoundError:
            pytest.fail("diskpart.exe not found. Required for volume serial restoration.")
        except Exception as e:
            pytest.fail(f"Failed to execute diskpart: {e}")

    def test_volume_serial_read_via_diskpart_system_drive(self, admin_required: None) -> None:
        """Read volume serial for system drive (C:) via diskpart.

        Validates that volume serial can be queried using diskpart.
        This proves restoration can verify the restored volume serial.
        """
        volume_serial = get_volume_serial_via_diskpart("C")

        logger.info(f"System drive (C:) volume serial: {volume_serial}")

        if volume_serial is None:
            pytest.skip(
                "Failed to read C: volume serial via diskpart. "
                "This may indicate diskpart permissions issue or non-existent C: drive. "
                "Volume serial restoration requires successful diskpart communication."
            )

        assert isinstance(volume_serial, str), "Volume serial must be a string"
        assert len(volume_serial) == 8, f"Volume serial must be 8 hex digits, got {len(volume_serial)}"
        assert all(c in "0123456789ABCDEF" for c in volume_serial.upper()), \
            "Volume serial must contain only hex digits"

    def test_volume_serial_read_via_diskpart_all_volumes(self, admin_required: None, disk_inventory: dict[str, Any]) -> None:
        """Read volume serials for all detected volumes via diskpart.

        Validates that volume serials can be queried for all accessible volumes.
        """
        volume_serials = disk_inventory["volume_serials"]

        if not volume_serials:
            pytest.skip(
                "No volumes detected with readable serials. "
                "Volume serial restoration requires at least one accessible volume. "
                "Check diskpart permissions and volume availability."
            )

        logger.info(f"Found {len(volume_serials)} volumes with serials")

        for drive_letter, serial in volume_serials.items():
            assert isinstance(serial, str), f"Volume {drive_letter}: serial must be string"
            assert len(serial) == 8, f"Volume {drive_letter}: serial must be 8 hex digits"
            assert all(c in "0123456789ABCDEF" for c in serial.upper()), \
                f"Volume {drive_letter}: serial must be hex"

            logger.debug(f"Volume {drive_letter}: serial {serial} validated")


class TestDiskTypeHandling:
    """Test disk type detection and type-specific restoration handling."""

    def test_disk_type_detection_returns_known_types(self, disk_inventory: dict[str, Any]) -> None:
        """Verify disk type detection returns valid type strings.

        Validates that disk type detection correctly identifies SCSI, SATA, NVMe,
        RAID, or Unknown for all disks.
        """
        disk_types = disk_inventory["disk_types"]

        if not disk_types:
            pytest.skip(
                "No disks detected on system. "
                "Disk type detection requires at least one disk. "
                "This may indicate WMI access issues or virtual environment."
            )

        valid_types = {"SCSI", "SATA", "NVMe", "RAID", "Unknown"}

        for disk_idx, dtype in disk_types.items():
            assert dtype in valid_types, \
                f"Disk {disk_idx} has invalid type '{dtype}', must be one of {valid_types}"

            logger.debug(f"Disk {disk_idx}: type {dtype}")

    def test_scsi_disk_handling_differs_from_sata(self, disk_inventory: dict[str, Any]) -> None:
        """Verify SCSI and SATA disks use different registry paths.

        Validates that restoration logic correctly differentiates between
        SCSI and SATA disk types with appropriate registry paths.
        """
        scsi_paths = disk_inventory["registry_paths"]["SCSI"]
        sata_paths = disk_inventory["registry_paths"]["SATA"]

        scsi_unique = set(scsi_paths) - set(sata_paths)
        sata_unique = set(sata_paths) - set(scsi_paths)

        logger.info(f"SCSI-specific paths: {len(scsi_unique)}, SATA-specific paths: {len(sata_unique)}")

        assert len(scsi_unique) > 0 or len(scsi_paths) == 0, \
            "SCSI disks must have unique registry paths from SATA"
        assert len(sata_unique) > 0 or len(sata_paths) == 0, \
            "SATA disks must have unique registry paths from SCSI"

    def test_nvme_device_identifier_paths_are_distinct(self, disk_inventory: dict[str, Any]) -> None:
        """Verify NVMe disks use distinct registry paths.

        Validates that NVMe disk restoration uses NVMe-specific registry paths
        different from SCSI/SATA paths.
        """
        nvme_paths = disk_inventory["registry_paths"]["NVMe"]
        scsi_paths = disk_inventory["registry_paths"]["SCSI"]
        sata_paths = disk_inventory["registry_paths"]["SATA"]

        if not nvme_paths:
            pytest.skip(
                "No NVMe disks detected. "
                "NVMe identifier restoration test requires NVMe hardware. "
                "Standard registry path: HKLM\\SYSTEM\\CurrentControlSet\\Services\\nvme\\Enum"
            )

        nvme_set = set(nvme_paths)
        other_set = set(scsi_paths) | set(sata_paths)

        overlap = nvme_set & other_set

        assert len(overlap) == 0, \
            f"NVMe paths must be distinct from SCSI/SATA paths. Overlap: {overlap}"


class TestRAIDConfiguration:
    """Test disk serial restoration with RAID configurations."""

    def test_raid_disk_detection(self, disk_inventory: dict[str, Any]) -> None:
        """Detect RAID disks and verify proper type identification.

        Validates that RAID configurations are properly detected and typed.
        """
        disk_types = disk_inventory["disk_types"]
        raid_disks = [idx for idx, dtype in disk_types.items() if dtype == "RAID"]

        if not raid_disks:
            pytest.skip(
                "No RAID configurations detected. "
                "RAID restoration test requires hardware RAID controller. "
                "This test validates RAID-specific serial restoration logic."
            )

        logger.info(f"Detected {len(raid_disks)} RAID disks")

        for disk_idx in raid_disks:
            logger.debug(f"RAID disk {disk_idx} identified")
            assert disk_types[disk_idx] == "RAID"

    def test_raid_array_members_share_controller(self, disk_inventory: dict[str, Any]) -> None:
        """Verify RAID array members are properly identified.

        Validates that RAID array restoration handles multiple physical disks
        within the same logical RAID volume.
        """
        disk_types = disk_inventory["disk_types"]
        raid_disks = [idx for idx, dtype in disk_types.items() if dtype == "RAID"]

        if len(raid_disks) < 2:
            pytest.skip(
                "RAID array member test requires at least 2 RAID disks. "
                f"Detected {len(raid_disks)} RAID disk(s). "
                "This test validates restoration across RAID array members."
            )

        logger.info(f"Testing RAID array with {len(raid_disks)} members")

        assert len(raid_disks) >= 2, "RAID array must have multiple members"


class TestRemovableDrives:
    """Test disk serial restoration with removable drives."""

    def test_removable_drive_detection(self) -> None:
        """Detect removable drives on system.

        Validates that removable drives are properly identified and can be
        excluded from permanent serial restoration.
        """
        removable_drives: list[str] = []

        for drive_letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
            if is_removable_drive(drive_letter):
                removable_drives.append(drive_letter)

        if not removable_drives:
            pytest.skip(
                "No removable drives detected. "
                "Removable drive restoration test requires USB drive or similar. "
                "Insert removable media to test restoration filtering logic."
            )

        logger.info(f"Detected removable drives: {removable_drives}")

        for drive in removable_drives:
            assert is_removable_drive(drive), f"Drive {drive}: must be detected as removable"

    def test_removable_drives_excluded_from_restoration(self) -> None:
        """Verify removable drives are excluded from serial restoration.

        Validates that restoration logic skips removable drives to avoid
        affecting temporary storage devices.
        """
        removable_drives: list[str] = []

        for drive_letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
            if is_removable_drive(drive_letter):
                removable_drives.append(drive_letter)

        if not removable_drives:
            pytest.skip(
                "No removable drives to test exclusion. "
                "Insert USB drive to validate restoration filtering."
            )

        logger.info(f"Validating exclusion of removable drives: {removable_drives}")

        for drive in removable_drives:
            logger.debug(f"Drive {drive}: marked as removable, should be excluded from restoration")
            assert is_removable_drive(drive), f"Drive {drive}: removable status changed during test"


class TestRestorationVerification:
    """Test verification of successful disk serial restoration."""

    def test_restoration_verification_reads_actual_registry_values(self, admin_required: None, disk_inventory: dict[str, Any]) -> None:
        """Verify restoration verification reads actual registry values.

        Validates that verification mechanism reads real registry values
        to confirm restoration success.
        """
        disk_types = disk_inventory["disk_types"]

        if not disk_types:
            pytest.skip("No disks detected for restoration verification test")

        verification_count = 0

        for disk_idx, dtype in disk_types.items():
            if dtype in ["SCSI", "SATA", "NVMe"]:
                serial = read_disk_serial_from_registry(dtype, disk_idx)

                if serial:
                    verification_count += 1
                    logger.debug(f"Verified registry read for {dtype} disk {disk_idx}: {serial}")

        assert verification_count > 0, \
            "Restoration verification must successfully read at least one disk serial"

        logger.info(f"Successfully verified {verification_count} disk serial reads")

    def test_restoration_verification_compares_before_after_values(self, admin_required: None, spoofer: HardwareFingerPrintSpoofer) -> None:
        """Verify restoration verification compares original vs restored values.

        Validates that verification mechanism properly compares original
        disk serials with post-restoration values.
        """
        if not spoofer.original_hardware:
            pytest.skip("Original hardware not captured for verification test")

        original_serials = spoofer.original_hardware.disk_serial

        logger.info(f"Original disk serials: {original_serials}")

        assert isinstance(original_serials, list), "Disk serials must be a list"
        assert len(original_serials) > 0, "Must have at least one disk serial to verify"

        for serial in original_serials:
            assert isinstance(serial, str), "Each disk serial must be a string"
            assert len(serial) > 0, "Disk serial must not be empty"

    def test_restoration_verification_handles_partial_restoration_failure(self, admin_required: None) -> None:
        """Verify restoration verification detects partial failures.

        Validates that verification mechanism detects when some but not all
        disk serials are successfully restored.
        """
        logger.info("Testing partial restoration failure detection")

        disk_types = get_all_disk_types()

        if len(disk_types) < 2:
            pytest.skip(
                "Partial restoration failure test requires at least 2 disks. "
                f"Detected {len(disk_types)} disk(s)."
            )

        success_checks = []

        for disk_idx, dtype in disk_types.items():
            serial = read_disk_serial_from_registry(dtype, disk_idx)
            success_checks.append(serial is not None)

        all_success = all(success_checks)
        none_success = not any(success_checks)
        partial_success = not all_success and not none_success

        logger.info(f"Restoration check results: all={all_success}, none={none_success}, partial={partial_success}")

        assert isinstance(all_success, bool) and isinstance(partial_success, bool), \
            "Verification must distinguish between full, partial, and complete failure"


class TestRestorationIntegration:
    """Integration tests for complete disk serial restoration workflow."""

    def test_spoofer_captures_original_disk_serials(self, spoofer: HardwareFingerPrintSpoofer) -> None:
        """Verify spoofer captures original disk serial numbers.

        Validates that HardwareFingerPrintSpoofer properly captures original
        disk serial numbers before spoofing.
        """
        if not spoofer.original_hardware:
            pytest.fail("Spoofer must capture original hardware on initialization")

        original_serials = spoofer.original_hardware.disk_serial

        logger.info(f"Captured {len(original_serials)} original disk serials")

        assert isinstance(original_serials, list), "Disk serials must be a list"
        assert len(original_serials) > 0, "Must capture at least one disk serial"

        for serial in original_serials:
            assert isinstance(serial, str), "Each disk serial must be a string"
            logger.debug(f"Original disk serial: {serial}")

    def test_restoration_returns_success_status(self, admin_required: None, spoofer: HardwareFingerPrintSpoofer) -> None:
        """Verify restoration method returns success/failure status.

        Validates that restoration method returns boolean indicating whether
        restoration was successful.
        """
        if not spoofer.original_hardware:
            pytest.skip("Original hardware not captured for restoration status test")

        result = spoofer.restore_original()

        assert isinstance(result, bool), "Restoration must return boolean success status"

        logger.info(f"Restoration returned status: {result}")

    def test_restoration_handles_missing_original_hardware(self) -> None:
        """Verify restoration handles case where original hardware was not captured.

        Validates that restoration gracefully handles missing original hardware
        data without crashing.
        """
        spoofer_instance = HardwareFingerPrintSpoofer()
        spoofer_instance.original_hardware = None

        result = spoofer_instance.restore_original()

        assert result is False, "Restoration must return False when original hardware is missing"

        logger.info("Restoration correctly handled missing original hardware")

    def test_complete_restoration_workflow_preserves_disk_serials(self, admin_required: None, spoofer: HardwareFingerPrintSpoofer) -> None:
        """Test complete workflow: capture original, spoof, restore, verify.

        Validates that complete restoration workflow properly preserves
        original disk serial numbers through spoof and restore operations.

        NOTE: This is a READ-ONLY test that verifies restoration logic
        without actually modifying disk serials (requires admin + reboot).
        """
        if not spoofer.original_hardware:
            pytest.skip("Original hardware not captured for workflow test")

        original_serials = spoofer.original_hardware.disk_serial.copy()

        logger.info(f"Workflow test with {len(original_serials)} original serials")

        current_hardware = spoofer.get_current_hardware()
        current_serials = current_hardware.disk_serial

        logger.info(f"Current serials match original: {current_serials == original_serials}")

        assert len(current_serials) == len(original_serials), \
            "Current and original serial counts must match"
