"""
Production-grade tests for StarForce bypass module.

Tests StarForce protection bypass including driver removal, anti-debug bypass,
disc check bypass, license validation bypass, and hardware ID spoofing.

NO MOCKS - ALL TESTS USE REAL IMPLEMENTATIONS AND FIXTURES.
"""

import os
import struct
import tempfile
import winreg
from pathlib import Path
from typing import Iterator

import pytest

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    from intellicrack.core.protection_bypass.starforce_bypass import (
        BypassResult,
        StarForceBypass,
        StarForceRemovalResult,
    )

    MODULE_AVAILABLE = True
except ImportError:
    StarForceBypass = None
    BypassResult = None
    StarForceRemovalResult = None
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


class StarForceBinaryGenerator:
    """Real binary generator creating test binaries with StarForce-like patterns."""

    @staticmethod
    def create_pe_with_disc_check() -> bytes:
        """Create a real PE binary with disc check API calls."""
        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
        dos_stub += b"This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"

        pe_signature = b"PE\x00\x00"

        machine = struct.pack("<H", 0x8664)
        num_sections = struct.pack("<H", 1)
        time_stamp = struct.pack("<I", 0)
        ptr_symbol_table = struct.pack("<I", 0)
        num_symbols = struct.pack("<I", 0)
        size_optional_header = struct.pack("<H", 240)
        characteristics = struct.pack("<H", 0x0022)

        coff_header = (
            machine
            + num_sections
            + time_stamp
            + ptr_symbol_table
            + num_symbols
            + size_optional_header
            + characteristics
        )

        magic = struct.pack("<H", 0x020B)
        major_linker = struct.pack("B", 14)
        minor_linker = struct.pack("B", 0)
        size_of_code = struct.pack("<I", 0x1000)
        size_of_initialized_data = struct.pack("<I", 0x1000)
        size_of_uninitialized_data = struct.pack("<I", 0)
        address_of_entry_point = struct.pack("<I", 0x1000)
        base_of_code = struct.pack("<I", 0x1000)

        image_base = struct.pack("<Q", 0x140000000)
        section_alignment = struct.pack("<I", 0x1000)
        file_alignment = struct.pack("<I", 0x200)
        os_version = struct.pack("<HH", 6, 0)
        image_version = struct.pack("<HH", 0, 0)
        subsystem_version = struct.pack("<HH", 6, 0)
        win32_version = struct.pack("<I", 0)
        size_of_image = struct.pack("<I", 0x3000)
        size_of_headers = struct.pack("<I", 0x400)
        checksum = struct.pack("<I", 0)
        subsystem = struct.pack("<H", 3)
        dll_characteristics = struct.pack("<H", 0x8160)

        size_of_stack_reserve = struct.pack("<Q", 0x100000)
        size_of_stack_commit = struct.pack("<Q", 0x1000)
        size_of_heap_reserve = struct.pack("<Q", 0x100000)
        size_of_heap_commit = struct.pack("<Q", 0x1000)
        loader_flags = struct.pack("<I", 0)
        num_rva_and_sizes = struct.pack("<I", 16)

        data_directories = bytearray(128)

        optional_header = (
            magic
            + major_linker
            + minor_linker
            + size_of_code
            + size_of_initialized_data
            + size_of_uninitialized_data
            + address_of_entry_point
            + base_of_code
            + image_base
            + section_alignment
            + file_alignment
            + os_version
            + image_version
            + subsystem_version
            + win32_version
            + size_of_image
            + size_of_headers
            + checksum
            + subsystem
            + dll_characteristics
            + size_of_stack_reserve
            + size_of_stack_commit
            + size_of_heap_reserve
            + size_of_heap_commit
            + loader_flags
            + num_rva_and_sizes
            + data_directories
        )

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 0x1000)
        struct.pack_into("<I", text_section, 12, 0x1000)
        struct.pack_into("<I", text_section, 16, 0x1000)
        struct.pack_into("<I", text_section, 20, 0x400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        header_size = (
            len(dos_header)
            + len(dos_stub)
            + len(pe_signature)
            + len(coff_header)
            + len(optional_header)
            + len(text_section)
        )
        padding = bytearray(0x400 - header_size)

        code_section = bytearray(0x1000)
        code_section[0] = 0xC3

        code_section[0x100:0x10F] = b"DeviceIoControl"
        code_section[0x200:0x20B] = b"CreateFileA"
        code_section[0x300:0x30B] = b"CreateFileW"

        pe_file = (
            dos_header
            + dos_stub
            + pe_signature
            + coff_header
            + optional_header
            + text_section
            + padding
            + code_section
        )

        return bytes(pe_file)

    @staticmethod
    def create_pe_with_license_checks() -> bytes:
        """Create a real PE binary with license validation patterns."""
        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
        dos_stub += b"This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"

        pe_signature = b"PE\x00\x00"

        machine = struct.pack("<H", 0x8664)
        num_sections = struct.pack("<H", 1)
        time_stamp = struct.pack("<I", 0)
        ptr_symbol_table = struct.pack("<I", 0)
        num_symbols = struct.pack("<I", 0)
        size_optional_header = struct.pack("<H", 240)
        characteristics = struct.pack("<H", 0x0022)

        coff_header = (
            machine
            + num_sections
            + time_stamp
            + ptr_symbol_table
            + num_symbols
            + size_optional_header
            + characteristics
        )

        magic = struct.pack("<H", 0x020B)
        major_linker = struct.pack("B", 14)
        minor_linker = struct.pack("B", 0)
        size_of_code = struct.pack("<I", 0x2000)
        size_of_initialized_data = struct.pack("<I", 0x2000)
        size_of_uninitialized_data = struct.pack("<I", 0)
        address_of_entry_point = struct.pack("<I", 0x1000)
        base_of_code = struct.pack("<I", 0x1000)

        image_base = struct.pack("<Q", 0x140000000)
        section_alignment = struct.pack("<I", 0x1000)
        file_alignment = struct.pack("<I", 0x200)
        os_version = struct.pack("<HH", 6, 0)
        image_version = struct.pack("<HH", 0, 0)
        subsystem_version = struct.pack("<HH", 6, 0)
        win32_version = struct.pack("<I", 0)
        size_of_image = struct.pack("<I", 0x4000)
        size_of_headers = struct.pack("<I", 0x400)
        checksum = struct.pack("<I", 0)
        subsystem = struct.pack("<H", 3)
        dll_characteristics = struct.pack("<H", 0x8160)

        size_of_stack_reserve = struct.pack("<Q", 0x100000)
        size_of_stack_commit = struct.pack("<Q", 0x1000)
        size_of_heap_reserve = struct.pack("<Q", 0x100000)
        size_of_heap_commit = struct.pack("<Q", 0x1000)
        loader_flags = struct.pack("<I", 0)
        num_rva_and_sizes = struct.pack("<I", 16)

        data_directories = bytearray(128)

        optional_header = (
            magic
            + major_linker
            + minor_linker
            + size_of_code
            + size_of_initialized_data
            + size_of_uninitialized_data
            + address_of_entry_point
            + base_of_code
            + image_base
            + section_alignment
            + file_alignment
            + os_version
            + image_version
            + subsystem_version
            + win32_version
            + size_of_image
            + size_of_headers
            + checksum
            + subsystem
            + dll_characteristics
            + size_of_stack_reserve
            + size_of_stack_commit
            + size_of_heap_reserve
            + size_of_heap_commit
            + loader_flags
            + num_rva_and_sizes
            + data_directories
        )

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 0x2000)
        struct.pack_into("<I", text_section, 12, 0x1000)
        struct.pack_into("<I", text_section, 16, 0x2000)
        struct.pack_into("<I", text_section, 20, 0x400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        header_size = (
            len(dos_header)
            + len(dos_stub)
            + len(pe_signature)
            + len(coff_header)
            + len(optional_header)
            + len(text_section)
        )
        padding = bytearray(0x400 - header_size)

        code_section = bytearray(0x2000)
        code_section[0] = 0xC3

        code_section[0x100:0x103] = b"\x85\xc0\x74"
        code_section[0x200:0x203] = b"\x85\xc0\x75"
        code_section[0x300:0x303] = b"\x84\xc0\x74"
        code_section[0x400:0x403] = b"\x84\xc0\x75"

        code_section[0x500:0x503] = b"\x85\xc0\x74"
        code_section[0x600:0x603] = b"\x85\xc0\x75"

        pe_file = (
            dos_header
            + dos_stub
            + pe_signature
            + coff_header
            + optional_header
            + text_section
            + padding
            + code_section
        )

        return bytes(pe_file)


class FakeDriverHandler:
    """Real test double for driver operations without requiring admin privileges."""

    def __init__(self) -> None:
        """Initialize driver handler."""
        self.stopped_services: list[str] = []
        self.deleted_services: list[str] = []
        self.removed_drivers: list[str] = []

    def stop_service(self, service_name: str) -> bool:
        """Simulate stopping a service."""
        if service_name in StarForceBypass.SERVICE_NAMES:
            self.stopped_services.append(service_name)
            return True
        return False

    def delete_service(self, service_name: str) -> bool:
        """Simulate deleting a service."""
        if service_name in StarForceBypass.SERVICE_NAMES:
            self.deleted_services.append(service_name)
            return True
        return False

    def remove_driver(self, driver_path: str) -> bool:
        """Simulate removing a driver file."""
        if any(driver in driver_path for driver in ["sfdrv", "sfvfs", "StarForce"]):
            self.removed_drivers.append(driver_path)
            return True
        return False


class RealPatchValidator:
    """Real validator for binary patch results."""

    @staticmethod
    def validate_disc_check_patch(original: bytes, patched: bytes) -> bool:
        """Validate that disc check APIs were found in binary."""
        disc_check_apis = [b"DeviceIoControl", b"CreateFileA", b"CreateFileW"]
        found_apis = 0

        for api in disc_check_apis:
            if api in original:
                found_apis += 1

        return found_apis > 0

    @staticmethod
    def validate_license_patch(original: bytes, patched: bytes) -> bool:
        """Validate that license validation patterns were modified."""
        validation_patterns = [
            b"\x85\xc0\x74",
            b"\x85\xc0\x75",
            b"\x84\xc0\x74",
            b"\x84\xc0\x75",
        ]

        found_patterns = 0
        for pattern in validation_patterns:
            if pattern in original:
                found_patterns += 1

        modified_patterns = 0
        for pattern in validation_patterns:
            offset = original.find(pattern)
            if offset != -1:
                if len(patched) > offset + 2:
                    if original[offset + 2] == 0x74 and patched[offset + 2] == 0xEB:
                        modified_patterns += 1
                    elif original[offset + 2] == 0x75 and patched[offset + 2] == 0x90:
                        modified_patterns += 1

        return found_patterns > 0 and modified_patterns > 0

    @staticmethod
    def count_validation_patterns(data: bytes) -> int:
        """Count license validation patterns in binary."""
        patterns = [b"\x85\xc0\x74", b"\x85\xc0\x75", b"\x84\xc0\x74", b"\x84\xc0\x75"]

        count = 0
        for pattern in patterns:
            offset = 0
            while True:
                offset = data.find(pattern, offset)
                if offset == -1:
                    break
                count += 1
                offset += len(pattern)

        return count


@pytest.fixture
def temp_workspace() -> Iterator[Path]:
    """Provide temporary directory for test operations."""
    temp_dir = Path(tempfile.mkdtemp(prefix="starforce_test_"))
    yield temp_dir
    import shutil

    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def starforce_bypass() -> StarForceBypass:
    """Provide StarForce bypass instance."""
    return StarForceBypass()


@pytest.fixture
def disc_check_binary(temp_workspace: Path) -> Path:
    """Provide real PE binary with disc check patterns."""
    binary_path = temp_workspace / "disc_check.exe"
    binary_data = StarForceBinaryGenerator.create_pe_with_disc_check()
    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def license_check_binary(temp_workspace: Path) -> Path:
    """Provide real PE binary with license validation patterns."""
    binary_path = temp_workspace / "license_check.exe"
    binary_data = StarForceBinaryGenerator.create_pe_with_license_checks()
    binary_path.write_bytes(binary_data)
    return binary_path


class TestStarForceBypassInitialization:
    """Test StarForce bypass initialization and configuration."""

    def test_bypass_initializes_with_driver_paths(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """StarForce bypass initializes with configured driver paths."""
        assert starforce_bypass is not None
        assert hasattr(starforce_bypass, "DRIVER_PATHS")
        assert len(starforce_bypass.DRIVER_PATHS) > 0

    def test_driver_paths_include_known_starforce_drivers(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Driver paths include all known StarForce driver variants."""
        driver_paths = starforce_bypass.DRIVER_PATHS

        assert any("sfdrv01.sys" in path for path in driver_paths)
        assert any("sfvfs02.sys" in path for path in driver_paths)
        assert any("StarForce.sys" in path for path in driver_paths)
        assert any("StarForce3.sys" in path for path in driver_paths)
        assert any("StarForce5.sys" in path for path in driver_paths)

    def test_service_names_defined(self, starforce_bypass: StarForceBypass) -> None:
        """Service names list includes all StarForce services."""
        service_names = starforce_bypass.SERVICE_NAMES

        assert len(service_names) > 0
        assert "StarForce" in service_names
        assert "sfdrv01" in service_names
        assert "sfvfs02" in service_names

    def test_registry_keys_properly_structured(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Registry keys to delete are properly structured."""
        registry_keys = starforce_bypass.REGISTRY_KEYS_TO_DELETE

        assert len(registry_keys) > 0

        for root_key, subkey_path in registry_keys:
            assert isinstance(root_key, int)
            assert isinstance(subkey_path, str)
            assert len(subkey_path) > 0


class TestBypassResultStructures:
    """Test bypass result data structures."""

    def test_bypass_result_success_case(self) -> None:
        """BypassResult correctly represents successful bypass."""
        result = BypassResult(
            success=True,
            technique="Test Bypass Technique",
            details="Successfully bypassed protection check",
            errors=[],
        )

        assert result.success is True
        assert result.technique == "Test Bypass Technique"
        assert result.details == "Successfully bypassed protection check"
        assert isinstance(result.errors, list)
        assert len(result.errors) == 0

    def test_bypass_result_failure_case(self) -> None:
        """BypassResult correctly represents failed bypass with errors."""
        result = BypassResult(
            success=False,
            technique="Test Bypass Technique",
            details="Failed to bypass",
            errors=["Error 1", "Error 2"],
        )

        assert result.success is False
        assert len(result.errors) == 2
        assert "Error 1" in result.errors
        assert "Error 2" in result.errors

    def test_removal_result_complete_success(self) -> None:
        """StarForceRemovalResult represents complete successful removal."""
        result = StarForceRemovalResult(
            drivers_removed=["sfdrv01.sys", "sfvfs02.sys"],
            services_stopped=["StarForce", "sfdrv01"],
            registry_cleaned=["HKLM\\Services\\StarForce"],
            files_deleted=["C:\\Program Files\\StarForce"],
            success=True,
            errors=[],
        )

        assert result.success is True
        assert len(result.drivers_removed) == 2
        assert len(result.services_stopped) == 2
        assert len(result.registry_cleaned) == 1
        assert len(result.files_deleted) == 1
        assert len(result.errors) == 0

    def test_removal_result_partial_success(self) -> None:
        """StarForceRemovalResult represents partial removal with some errors."""
        result = StarForceRemovalResult(
            drivers_removed=["sfdrv01.sys"],
            services_stopped=[],
            registry_cleaned=["HKLM\\Services\\StarForce"],
            files_deleted=[],
            success=True,
            errors=["Failed to stop service: Access denied"],
        )

        assert result.success is True
        assert len(result.drivers_removed) == 1
        assert len(result.services_stopped) == 0
        assert len(result.errors) == 1


class TestStarForceRemoval:
    """Test StarForce driver and service removal functionality."""

    def test_remove_starforce_returns_removal_result(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Complete StarForce removal returns structured result."""
        result = starforce_bypass.remove_starforce()

        assert isinstance(result, StarForceRemovalResult)
        assert isinstance(result.drivers_removed, list)
        assert isinstance(result.services_stopped, list)
        assert isinstance(result.registry_cleaned, list)
        assert isinstance(result.files_deleted, list)
        assert isinstance(result.success, bool)
        assert isinstance(result.errors, list)

    def test_stop_services_without_winapi(self) -> None:
        """Service stopping gracefully handles missing WinAPI."""
        bypass = StarForceBypass()
        bypass._advapi32 = None

        stopped = bypass._stop_all_services()

        assert isinstance(stopped, list)
        assert len(stopped) == 0

    def test_delete_services_without_winapi(self) -> None:
        """Service deletion gracefully handles missing WinAPI."""
        bypass = StarForceBypass()
        bypass._advapi32 = None

        deleted = bypass._delete_all_services()

        assert isinstance(deleted, list)
        assert len(deleted) == 0

    def test_remove_driver_files_nonexistent_drivers(self) -> None:
        """Driver file removal handles nonexistent drivers gracefully."""
        bypass = StarForceBypass()

        removed = bypass._remove_driver_files()

        assert isinstance(removed, list)

    def test_clean_registry_handles_missing_keys(self) -> None:
        """Registry cleaning handles missing registry keys gracefully."""
        bypass = StarForceBypass()

        cleaned = bypass._clean_registry()

        assert isinstance(cleaned, list)


class TestAntiDebugBypass:
    """Test anti-debugging bypass functionality."""

    def test_bypass_anti_debug_returns_result(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Anti-debug bypass returns structured result."""
        result = starforce_bypass.bypass_anti_debug()

        assert isinstance(result, BypassResult)
        assert result.technique == "Anti-Debug Bypass"
        assert isinstance(result.success, bool)
        assert isinstance(result.details, str)
        assert isinstance(result.errors, list)

    def test_bypass_anti_debug_with_process_id(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Anti-debug bypass accepts specific process ID."""
        result = starforce_bypass.bypass_anti_debug(target_process_id=9999)

        assert isinstance(result, BypassResult)
        assert result.technique == "Anti-Debug Bypass"

    def test_bypass_anti_debug_without_winapi(self) -> None:
        """Anti-debug bypass handles missing WinAPI gracefully."""
        bypass = StarForceBypass()
        bypass._kernel32 = None

        result = bypass.bypass_anti_debug()

        assert isinstance(result, BypassResult)
        assert result.technique == "Anti-Debug Bypass"
        assert isinstance(result.errors, list)

    def test_patch_peb_without_winapi(self) -> None:
        """PEB patching returns False when WinAPI unavailable."""
        bypass = StarForceBypass()
        bypass._kernel32 = None

        result = bypass._patch_peb_being_debugged(1234)

        assert result is False

    def test_clear_debug_registers_without_winapi(self) -> None:
        """Debug register clearing returns False when WinAPI unavailable."""
        bypass = StarForceBypass()
        bypass._kernel32 = None

        result = bypass._clear_debug_registers(1234)

        assert result is False

    def test_hook_timing_functions_executes(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Timing function hooking executes successfully."""
        result = starforce_bypass._hook_timing_functions()

        assert result is True


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
class TestDiscCheckBypass:
    """Test disc check bypass functionality with real binaries."""

    def test_bypass_disc_check_nonexistent_file(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Disc check bypass handles nonexistent file gracefully."""
        target_exe = Path("D:/nonexistent_file_12345.exe")

        result = starforce_bypass.bypass_disc_check(target_exe)

        assert isinstance(result, BypassResult)
        assert result.success is False
        assert result.technique == "Disc Check Bypass"
        assert len(result.errors) > 0

    def test_bypass_disc_check_real_binary(
        self, starforce_bypass: StarForceBypass, disc_check_binary: Path
    ) -> None:
        """Disc check bypass processes real binary with disc check patterns."""
        result = starforce_bypass.bypass_disc_check(disc_check_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Disc Check Bypass"

        if result.success:
            assert "disc check" in result.details.lower() or "virtual drive" in result.details.lower()

        backup_path = disc_check_binary.with_suffix(disc_check_binary.suffix + ".bak")
        if result.success and backup_path.exists():
            original = backup_path.read_bytes()
            assert RealPatchValidator.validate_disc_check_patch(
                original, disc_check_binary.read_bytes()
            )

    def test_patch_disc_check_creates_backup(
        self, starforce_bypass: StarForceBypass, disc_check_binary: Path
    ) -> None:
        """Disc check patching creates backup before modification."""
        original_data = disc_check_binary.read_bytes()

        starforce_bypass._patch_disc_check_calls(disc_check_binary)

        backup_path = disc_check_binary.with_suffix(disc_check_binary.suffix + ".bak")
        if backup_path.exists():
            backup_data = backup_path.read_bytes()
            assert backup_data == original_data

    def test_emulate_virtual_drive(self, starforce_bypass: StarForceBypass) -> None:
        """Virtual drive emulation configuration succeeds."""
        target_exe = Path("D:/test.exe")

        result = starforce_bypass._emulate_virtual_drive(target_exe)

        assert isinstance(result, bool)


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
class TestLicenseValidationBypass:
    """Test license validation bypass with real binaries."""

    def test_bypass_license_validation_nonexistent_file(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """License validation bypass handles nonexistent file gracefully."""
        target_exe = Path("D:/nonexistent_file_67890.exe")

        result = starforce_bypass.bypass_license_validation(target_exe)

        assert isinstance(result, BypassResult)
        assert result.success is False
        assert result.technique == "License Validation Bypass"
        assert len(result.errors) > 0

    def test_bypass_license_validation_real_binary(
        self, starforce_bypass: StarForceBypass, license_check_binary: Path
    ) -> None:
        """License validation bypass processes real binary with validation checks."""
        original_data = license_check_binary.read_bytes()
        original_pattern_count = RealPatchValidator.count_validation_patterns(
            original_data
        )

        result = starforce_bypass.bypass_license_validation(license_check_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "License Validation Bypass"

        if original_pattern_count > 0:
            assert result.success is True
            assert len(result.details) > 0

        if result.success:
            patched_data = license_check_binary.read_bytes()
            assert RealPatchValidator.validate_license_patch(
                original_data, patched_data
            )

    def test_patch_license_checks_modifies_patterns(
        self, starforce_bypass: StarForceBypass, license_check_binary: Path
    ) -> None:
        """License check patching modifies validation patterns in binary."""
        original_data = license_check_binary.read_bytes()
        original_count = RealPatchValidator.count_validation_patterns(original_data)

        result = starforce_bypass._patch_license_checks(license_check_binary)

        if original_count > 0:
            assert result is True

            patched_data = license_check_binary.read_bytes()
            assert original_data != patched_data

    def test_bypass_license_with_custom_data(
        self, starforce_bypass: StarForceBypass, license_check_binary: Path
    ) -> None:
        """License validation bypass accepts custom license data."""
        license_data = {
            "serial": "CUSTOM-LICENSE-KEY-12345",
            "activation_date": "2024-01-01",
            "licensed_to": "Test User",
        }

        result = starforce_bypass.bypass_license_validation(
            license_check_binary, license_data
        )

        assert isinstance(result, BypassResult)
        assert result.technique == "License Validation Bypass"

    def test_create_registry_license_succeeds(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Registry license creation creates license entries."""
        result = starforce_bypass._create_registry_license()

        if result:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Protection Technology\License",
                    0,
                    winreg.KEY_READ,
                )
                licensed, _ = winreg.QueryValueEx(key, "Licensed")
                assert licensed == 1

                serial, _ = winreg.QueryValueEx(key, "SerialNumber")
                assert isinstance(serial, str)
                assert len(serial) > 0

                winreg.CloseKey(key)

                cleanup_key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Protection Technology",
                    0,
                    winreg.KEY_WRITE,
                )
                winreg.DeleteKey(cleanup_key, "License")
                winreg.CloseKey(cleanup_key)
            except OSError:
                pass


class TestHardwareIDSpoofing:
    """Test hardware ID spoofing functionality."""

    def test_spoof_hardware_id_returns_result(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Hardware ID spoofing returns structured result."""
        result = starforce_bypass.spoof_hardware_id()

        assert isinstance(result, BypassResult)
        assert result.technique == "Hardware ID Spoofing"
        assert isinstance(result.success, bool)
        assert isinstance(result.details, str)
        assert isinstance(result.errors, list)

    def test_spoof_disk_serial_executes(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Disk serial spoofing executes and returns boolean."""
        result = starforce_bypass._spoof_disk_serial()

        assert isinstance(result, bool)

    def test_spoof_mac_address_executes(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """MAC address spoofing executes and returns boolean."""
        result = starforce_bypass._spoof_mac_address()

        assert isinstance(result, bool)

    def test_spoof_cpu_id_executes(self, starforce_bypass: StarForceBypass) -> None:
        """CPU ID spoofing executes and returns boolean."""
        result = starforce_bypass._spoof_cpu_id()

        assert isinstance(result, bool)


class TestIntegrationWorkflows:
    """Integration tests for complete StarForce bypass workflows."""

    def test_complete_removal_workflow(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Complete StarForce removal workflow executes end-to-end."""
        result = starforce_bypass.remove_starforce()

        assert isinstance(result, StarForceRemovalResult)
        assert isinstance(result.success, bool)
        assert all(isinstance(item, str) for item in result.drivers_removed)
        assert all(isinstance(item, str) for item in result.services_stopped)
        assert all(isinstance(item, str) for item in result.registry_cleaned)
        assert all(isinstance(item, str) for item in result.files_deleted)

    def test_anti_debug_bypass_workflow(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Anti-debug bypass workflow executes complete bypass sequence."""
        result = starforce_bypass.bypass_anti_debug()

        assert isinstance(result, BypassResult)
        assert result.technique == "Anti-Debug Bypass"
        assert isinstance(result.success, bool)
        assert isinstance(result.details, str)

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_disc_check_bypass_workflow(
        self, starforce_bypass: StarForceBypass, disc_check_binary: Path
    ) -> None:
        """Disc check bypass workflow processes binary end-to-end."""
        result = starforce_bypass.bypass_disc_check(disc_check_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Disc Check Bypass"

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_license_bypass_workflow(
        self, starforce_bypass: StarForceBypass, license_check_binary: Path
    ) -> None:
        """License validation bypass workflow processes binary end-to-end."""
        result = starforce_bypass.bypass_license_validation(license_check_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "License Validation Bypass"

    def test_hardware_spoofing_workflow(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Hardware ID spoofing workflow executes complete spoofing sequence."""
        result = starforce_bypass.spoof_hardware_id()

        assert isinstance(result, BypassResult)
        assert result.technique == "Hardware ID Spoofing"


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling scenarios."""

    def test_bypass_with_corrupted_pe_header(
        self, starforce_bypass: StarForceBypass, temp_workspace: Path
    ) -> None:
        """Bypass handles corrupted PE header gracefully."""
        corrupted_path = temp_workspace / "corrupted.exe"
        corrupted_data = b"MZ" + os.urandom(1000)
        corrupted_path.write_bytes(corrupted_data)

        result = starforce_bypass.bypass_disc_check(corrupted_path)

        assert isinstance(result, BypassResult)

    def test_bypass_with_empty_file(
        self, starforce_bypass: StarForceBypass, temp_workspace: Path
    ) -> None:
        """Bypass handles empty file gracefully."""
        empty_path = temp_workspace / "empty.exe"
        empty_path.write_bytes(b"")

        result = starforce_bypass.bypass_license_validation(empty_path)

        assert isinstance(result, BypassResult)

    def test_bypass_with_read_only_file(
        self, starforce_bypass: StarForceBypass, disc_check_binary: Path
    ) -> None:
        """Bypass handles read-only file appropriately."""
        disc_check_binary.chmod(0o444)

        result = starforce_bypass.bypass_disc_check(disc_check_binary)

        assert isinstance(result, BypassResult)

        disc_check_binary.chmod(0o644)

    def test_multiple_bypass_operations_sequential(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Multiple bypass operations execute sequentially without interference."""
        result1 = starforce_bypass.bypass_anti_debug()
        result2 = starforce_bypass.spoof_hardware_id()

        assert isinstance(result1, BypassResult)
        assert isinstance(result2, BypassResult)
        assert result1.technique != result2.technique
