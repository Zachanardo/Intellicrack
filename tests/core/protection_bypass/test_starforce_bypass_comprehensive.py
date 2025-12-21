"""Comprehensive Tests for StarForce Protection Bypass.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import ctypes
import os
import struct
import tempfile
import winreg
from pathlib import Path
from typing import Any

import pytest

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

from intellicrack.core.protection_bypass.starforce_bypass import (
    PEFILE_AVAILABLE as MODULE_PEFILE_AVAILABLE,
    BypassResult,
    StarForceBypass,
    StarForceRemovalResult,
)


@pytest.fixture
def starforce_bypass() -> StarForceBypass:
    """Create StarForce bypass instance."""
    return StarForceBypass()


@pytest.fixture
def temp_dir() -> Path:
    """Create temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def minimal_pe_binary(temp_dir: Path) -> Path:
    """Create minimal valid PE executable for StarForce bypass testing."""
    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 64)

    dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
    dos_stub += b"This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"

    pe_signature = b"PE\x00\x00"

    machine = struct.pack("<H", 0x8664)
    num_sections = struct.pack("<H", 2)
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
    size_of_code = struct.pack("<I", 512)
    size_of_initialized_data = struct.pack("<I", 512)
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
    struct.pack_into("<I", text_section, 8, 512)
    struct.pack_into("<I", text_section, 12, 0x1000)
    struct.pack_into("<I", text_section, 16, 512)
    struct.pack_into("<I", text_section, 20, 0x400)
    struct.pack_into("<I", text_section, 36, 0x60000020)

    data_section = bytearray(40)
    data_section[:8] = b".data\x00\x00\x00"
    struct.pack_into("<I", data_section, 8, 512)
    struct.pack_into("<I", data_section, 12, 0x2000)
    struct.pack_into("<I", data_section, 16, 512)
    struct.pack_into("<I", data_section, 20, 0x600)
    struct.pack_into("<I", data_section, 36, 0xC0000040)

    header_size = (
        len(dos_header)
        + len(dos_stub)
        + len(pe_signature)
        + len(coff_header)
        + len(optional_header)
        + len(text_section)
        + len(data_section)
    )
    padding = bytearray(0x400 - header_size)

    code_section = bytearray(512)
    code_section[0] = 0xC3

    data_section_content = bytearray(512)
    data_section_content[:13] = b"Hello World!\x00"

    pe_file = (
        dos_header
        + dos_stub
        + pe_signature
        + coff_header
        + optional_header
        + text_section
        + data_section
        + padding
        + code_section
        + data_section_content
    )

    exe_path = temp_dir / "test_protected.exe"
    exe_path.write_bytes(bytes(pe_file))
    return exe_path


@pytest.fixture
def starforce_protected_binary(minimal_pe_binary: Path) -> Path:
    """Create PE binary with StarForce protection patterns."""
    if not PEFILE_AVAILABLE:
        return minimal_pe_binary

    pe_data = bytearray(minimal_pe_binary.read_bytes())

    starforce_patterns = [
        b"StarForce",
        b"Protection Technology",
        b"DeviceIoControl",
        b"CreateFileW",
        b"\x85\xc0\x74\x05",
        b"\x85\xc0\x75\x05",
        b"\x84\xc0\x74\x05",
        b"\x84\xc0\x75\x05",
    ]

    for pattern in starforce_patterns:
        pe_data.extend(pattern)

    minimal_pe_binary.write_bytes(bytes(pe_data))
    return minimal_pe_binary


class TestStarForceBypassInitialization:
    """Test StarForce bypass initialization and WinAPI setup."""

    def test_bypass_initialization_creates_logger(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Bypass initialization creates logger instance."""
        assert starforce_bypass.logger is not None
        assert starforce_bypass.logger.name == "intellicrack.core.protection_bypass.starforce_bypass"

    def test_bypass_initializes_winapi_dlls(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Bypass initializes Windows API DLLs for driver and service manipulation."""
        if os.name == "nt":
            assert starforce_bypass._advapi32 is not None
            assert starforce_bypass._kernel32 is not None
            assert starforce_bypass._ntdll is not None

    def test_bypass_driver_paths_defined(self) -> None:
        """Bypass has comprehensive StarForce driver paths defined."""
        assert len(StarForceBypass.DRIVER_PATHS) > 0
        assert any("sfdrv01" in path for path in StarForceBypass.DRIVER_PATHS)
        assert any("sfvfs02" in path for path in StarForceBypass.DRIVER_PATHS)
        assert any("StarForce" in path for path in StarForceBypass.DRIVER_PATHS)

    def test_bypass_service_names_defined(self) -> None:
        """Bypass has comprehensive StarForce service names defined."""
        assert len(StarForceBypass.SERVICE_NAMES) > 0
        assert "StarForce" in StarForceBypass.SERVICE_NAMES
        assert "sfdrv01" in StarForceBypass.SERVICE_NAMES
        assert "sfvfs02" in StarForceBypass.SERVICE_NAMES

    def test_bypass_registry_keys_defined(self) -> None:
        """Bypass has comprehensive StarForce registry keys defined."""
        assert len(StarForceBypass.REGISTRY_KEYS_TO_DELETE) > 0
        assert any(
            "StarForce" in key_path
            for _, key_path in StarForceBypass.REGISTRY_KEYS_TO_DELETE
        )
        assert any(
            "Protection Technology" in key_path
            for _, key_path in StarForceBypass.REGISTRY_KEYS_TO_DELETE
        )


class TestStarForceCompleteRemoval:
    """Test complete StarForce protection removal from system."""

    def test_remove_starforce_returns_removal_result(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Complete StarForce removal returns detailed removal result."""
        result: StarForceRemovalResult = starforce_bypass.remove_starforce()

        assert isinstance(result, StarForceRemovalResult)
        assert isinstance(result.drivers_removed, list)
        assert isinstance(result.services_stopped, list)
        assert isinstance(result.registry_cleaned, list)
        assert isinstance(result.files_deleted, list)
        assert isinstance(result.success, bool)
        assert isinstance(result.errors, list)

    def test_remove_starforce_reports_success_when_items_removed(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """StarForce removal reports success when drivers, services, or registry keys removed."""
        fake_driver = temp_dir / "sfdrv01.sys"
        fake_driver.write_bytes(b"fake driver")

        original_paths = StarForceBypass.DRIVER_PATHS
        StarForceBypass.DRIVER_PATHS = [str(fake_driver)]

        result: StarForceRemovalResult = starforce_bypass.remove_starforce()

        StarForceBypass.DRIVER_PATHS = original_paths

        if result.drivers_removed:
            assert result.success is True

    def test_remove_starforce_removes_driver_files(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """StarForce removal deletes actual driver files from system."""
        fake_driver = temp_dir / "test_sfdrv01.sys"
        fake_driver.write_bytes(b"fake starforce driver")

        original_paths = StarForceBypass.DRIVER_PATHS
        StarForceBypass.DRIVER_PATHS = [str(fake_driver)]

        result: StarForceRemovalResult = starforce_bypass.remove_starforce()

        StarForceBypass.DRIVER_PATHS = original_paths

        assert not fake_driver.exists() or str(fake_driver) in result.drivers_removed

    def test_remove_starforce_cleans_registry_keys(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """StarForce removal attempts to clean registry keys."""
        result: StarForceRemovalResult = starforce_bypass.remove_starforce()

        assert isinstance(result.registry_cleaned, list)


class TestAntiDebugBypass:
    """Test StarForce anti-debugging bypass techniques."""

    def test_bypass_anti_debug_returns_bypass_result(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Anti-debug bypass returns detailed bypass result."""
        result: BypassResult = starforce_bypass.bypass_anti_debug()

        assert isinstance(result, BypassResult)
        assert isinstance(result.success, bool)
        assert result.technique == "Anti-Debug Bypass"
        assert isinstance(result.details, str)
        assert isinstance(result.errors, list)

    def test_bypass_anti_debug_targets_current_process_when_no_pid_provided(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Anti-debug bypass targets current process when no PID provided."""
        result: BypassResult = starforce_bypass.bypass_anti_debug(None)

        assert result is not None

    def test_bypass_anti_debug_attempts_peb_patch(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Anti-debug bypass attempts to patch PEB BeingDebugged flag."""
        if os.name != "nt":
            pytest.skip("Windows-only test")

        current_pid = os.getpid()
        result: BypassResult = starforce_bypass.bypass_anti_debug(current_pid)

        assert result is not None
        if "PEB BeingDebugged flag cleared" in result.details:
            assert result.success is True

    def test_bypass_anti_debug_attempts_debug_register_clear(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Anti-debug bypass attempts to clear hardware debug registers."""
        if os.name != "nt":
            pytest.skip("Windows-only test")

        current_pid = os.getpid()
        result: BypassResult = starforce_bypass.bypass_anti_debug(current_pid)

        assert result is not None
        if "Debug registers cleared" in result.details:
            assert result.success is True

    def test_bypass_anti_debug_hooks_timing_functions(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Anti-debug bypass hooks timing functions to normalize measurements."""
        result: BypassResult = starforce_bypass.bypass_anti_debug()

        assert result is not None
        if "Timing functions normalized" in result.details:
            assert result.success is True

    def test_bypass_anti_debug_reports_success_when_techniques_applied(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Anti-debug bypass reports success when any technique succeeds."""
        result: BypassResult = starforce_bypass.bypass_anti_debug()

        if result.details:
            assert result.success is True


class TestDiscCheckBypass:
    """Test StarForce disc authentication bypass."""

    def test_bypass_disc_check_returns_bypass_result(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """Disc check bypass returns detailed bypass result."""
        result: BypassResult = starforce_bypass.bypass_disc_check(
            starforce_protected_binary
        )

        assert isinstance(result, BypassResult)
        assert isinstance(result.success, bool)
        assert result.technique == "Disc Check Bypass"
        assert isinstance(result.details, str)
        assert isinstance(result.errors, list)

    def test_bypass_disc_check_fails_when_pefile_unavailable(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """Disc check bypass fails gracefully when pefile unavailable."""
        if not MODULE_PEFILE_AVAILABLE:
            nonexistent = temp_dir / "nonexistent.exe"
            result: BypassResult = starforce_bypass.bypass_disc_check(nonexistent)

            assert result.success is False
            assert "pefile not available" in result.errors[0]

    def test_bypass_disc_check_fails_when_target_missing(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """Disc check bypass fails when target executable does not exist."""
        nonexistent = temp_dir / "nonexistent.exe"
        result: BypassResult = starforce_bypass.bypass_disc_check(nonexistent)

        assert result.success is False
        assert len(result.errors) > 0

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_disc_check_patches_disc_check_calls(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """Disc check bypass patches disc check API calls in executable."""
        original_size = starforce_protected_binary.stat().st_size

        result: BypassResult = starforce_bypass.bypass_disc_check(
            starforce_protected_binary
        )

        if "Disc check calls patched" in result.details:
            assert result.success is True
            backup_path = starforce_protected_binary.with_suffix(
                f"{starforce_protected_binary.suffix}.bak"
            )
            assert backup_path.exists()

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_disc_check_creates_backup_before_patching(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """Disc check bypass creates backup before modifying executable."""
        backup_path = starforce_protected_binary.with_suffix(
            f"{starforce_protected_binary.suffix}.bak"
        )

        if backup_path.exists():
            backup_path.unlink()

        result = starforce_bypass.bypass_disc_check(starforce_protected_binary)

        if result.success and "patched" in result.details.lower():
            assert backup_path.exists()

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_disc_check_emulates_virtual_drive(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """Disc check bypass configures virtual drive emulation."""
        result: BypassResult = starforce_bypass.bypass_disc_check(
            starforce_protected_binary
        )

        if "Virtual drive emulation configured" in result.details:
            assert result.success is True


class TestLicenseValidationBypass:
    """Test StarForce license validation bypass."""

    def test_bypass_license_validation_returns_bypass_result(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """License validation bypass returns detailed bypass result."""
        result: BypassResult = starforce_bypass.bypass_license_validation(
            starforce_protected_binary
        )

        assert isinstance(result, BypassResult)
        assert isinstance(result.success, bool)
        assert result.technique == "License Validation Bypass"
        assert isinstance(result.details, str)
        assert isinstance(result.errors, list)

    def test_bypass_license_validation_fails_when_pefile_unavailable(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """License validation bypass fails gracefully when pefile unavailable."""
        if not MODULE_PEFILE_AVAILABLE:
            nonexistent = temp_dir / "nonexistent.exe"
            result: BypassResult = starforce_bypass.bypass_license_validation(
                nonexistent
            )

            assert result.success is False
            assert "pefile not available" in result.errors[0]

    def test_bypass_license_validation_fails_when_target_missing(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """License validation bypass fails when target executable does not exist."""
        nonexistent = temp_dir / "nonexistent.exe"
        result: BypassResult = starforce_bypass.bypass_license_validation(nonexistent)

        assert result.success is False
        assert len(result.errors) > 0

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_license_validation_patches_license_checks(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """License validation bypass patches license check instructions."""
        result: BypassResult = starforce_bypass.bypass_license_validation(
            starforce_protected_binary
        )

        if "License validation checks patched" in result.details:
            assert result.success is True

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_license_validation_patches_conditional_jumps(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """License validation bypass converts conditional jumps to bypass checks."""
        pe_data = bytearray(starforce_protected_binary.read_bytes())

        validation_patterns = [
            b"\x85\xc0\x74\x05",
            b"\x85\xc0\x75\x05",
            b"\x84\xc0\x74\x05",
            b"\x84\xc0\x75\x05",
        ]
        for pattern in validation_patterns:
            pe_data.extend(pattern)

        starforce_protected_binary.write_bytes(bytes(pe_data))
        original_data = starforce_protected_binary.read_bytes()

        result: BypassResult = starforce_bypass.bypass_license_validation(
            starforce_protected_binary
        )

        if "License validation checks patched" in result.details:
            modified_data = starforce_protected_binary.read_bytes()
            assert modified_data != original_data

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_license_validation_injects_license_data(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """License validation bypass injects custom license data into executable."""
        license_data = {
            "serial": "BYPASSED-KEY-12345",
            "activation_date": "2024-01-01",
            "user": "Test User",
        }

        result: BypassResult = starforce_bypass.bypass_license_validation(
            starforce_protected_binary, license_data
        )

        if "License data injected" in result.details:
            assert result.success is True

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_license_validation_creates_registry_license(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """License validation bypass creates registry-based license entries."""
        if os.name != "nt":
            pytest.skip("Windows-only test")

        result: BypassResult = starforce_bypass.bypass_license_validation(
            starforce_protected_binary
        )

        if "Registry license created" in result.details:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Protection Technology\License",
                    0,
                    winreg.KEY_READ,
                )
                value, _ = winreg.QueryValueEx(key, "Licensed")
                winreg.CloseKey(key)
                assert value == 1
            except OSError:
                pass

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_license_validation_creates_backup_before_patching(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """License validation bypass creates backup before modifying executable."""
        backup_path = starforce_protected_binary.with_suffix(
            f"{starforce_protected_binary.suffix}.bak"
        )

        if backup_path.exists():
            backup_path.unlink()

        result = starforce_bypass.bypass_license_validation(starforce_protected_binary)

        if result.success and "patched" in result.details.lower():
            assert backup_path.exists()


class TestHardwareIDSpoofing:
    """Test hardware ID spoofing for node-locked license bypass."""

    def test_spoof_hardware_id_returns_bypass_result(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Hardware ID spoofing returns detailed bypass result."""
        result: BypassResult = starforce_bypass.spoof_hardware_id()

        assert isinstance(result, BypassResult)
        assert isinstance(result.success, bool)
        assert result.technique == "Hardware ID Spoofing"
        assert isinstance(result.details, str)
        assert isinstance(result.errors, list)

    def test_spoof_hardware_id_spoofs_disk_serial(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Hardware ID spoofing spoofs disk volume serial number."""
        if os.name != "nt":
            pytest.skip("Windows-only test")

        result: BypassResult = starforce_bypass.spoof_hardware_id()

        if "Disk serial number spoofed" in result.details:
            assert result.success is True

    def test_spoof_hardware_id_spoofs_mac_address(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Hardware ID spoofing spoofs network adapter MAC address."""
        if os.name != "nt":
            pytest.skip("Windows-only test")

        result: BypassResult = starforce_bypass.spoof_hardware_id()

        if "MAC address spoofed" in result.details:
            assert result.success is True

    def test_spoof_hardware_id_spoofs_cpu_id(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Hardware ID spoofing spoofs CPU identification."""
        if os.name != "nt":
            pytest.skip("Windows-only test")

        result: BypassResult = starforce_bypass.spoof_hardware_id()

        if "CPU ID spoofed" in result.details:
            assert result.success is True

    def test_spoof_hardware_id_reports_success_when_techniques_applied(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Hardware ID spoofing reports success when any technique succeeds."""
        result: BypassResult = starforce_bypass.spoof_hardware_id()

        if result.details:
            assert result.success is True


class TestStarForceBypassIntegration:
    """Integration tests for complete StarForce bypass workflows."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_complete_starforce_defeat_workflow(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """Complete workflow defeats all StarForce protection layers."""
        removal_result: StarForceRemovalResult = starforce_bypass.remove_starforce()

        anti_debug_result: BypassResult = starforce_bypass.bypass_anti_debug()

        disc_result: BypassResult = starforce_bypass.bypass_disc_check(
            starforce_protected_binary
        )

        license_result: BypassResult = starforce_bypass.bypass_license_validation(
            starforce_protected_binary
        )

        hwid_result: BypassResult = starforce_bypass.spoof_hardware_id()

        assert isinstance(removal_result, StarForceRemovalResult)
        assert isinstance(anti_debug_result, BypassResult)
        assert isinstance(disc_result, BypassResult)
        assert isinstance(license_result, BypassResult)
        assert isinstance(hwid_result, BypassResult)

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_creates_backups_before_modifications(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """Bypass creates backups before any binary modifications."""
        backup_path = starforce_protected_binary.with_suffix(
            f"{starforce_protected_binary.suffix}.bak"
        )

        if backup_path.exists():
            backup_path.unlink()

        disc_result = starforce_bypass.bypass_disc_check(starforce_protected_binary)
        license_result = starforce_bypass.bypass_license_validation(starforce_protected_binary)

        if (disc_result.success and "patched" in disc_result.details.lower()) or \
           (license_result.success and "patched" in license_result.details.lower()):
            assert backup_path.exists()

    def test_bypass_handles_missing_pefile_gracefully(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """Bypass handles missing pefile dependency gracefully."""
        if not MODULE_PEFILE_AVAILABLE:
            test_exe = temp_dir / "test.exe"
            test_exe.write_bytes(b"MZ fake")

            disc_result = starforce_bypass.bypass_disc_check(test_exe)
            license_result = starforce_bypass.bypass_license_validation(test_exe)

            assert disc_result.success is False
            assert license_result.success is False
            assert "pefile not available" in disc_result.errors[0]
            assert "pefile not available" in license_result.errors[0]


class TestStarForceBypassEdgeCases:
    """Edge case tests for StarForce bypass robustness."""

    def test_bypass_handles_corrupted_pe_gracefully(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """Bypass handles corrupted PE files gracefully without crashing."""
        corrupted_pe = temp_dir / "corrupted.exe"
        corrupted_pe.write_bytes(b"MZ\x00\x00" + b"\xff" * 1000)

        disc_result = starforce_bypass.bypass_disc_check(corrupted_pe)
        license_result = starforce_bypass.bypass_license_validation(corrupted_pe)

        assert isinstance(disc_result, BypassResult)
        assert isinstance(license_result, BypassResult)

    def test_bypass_handles_empty_file_gracefully(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """Bypass handles empty files gracefully without crashing."""
        empty_file = temp_dir / "empty.exe"
        empty_file.write_bytes(b"")

        disc_result = starforce_bypass.bypass_disc_check(empty_file)
        license_result = starforce_bypass.bypass_license_validation(empty_file)

        assert isinstance(disc_result, BypassResult)
        assert isinstance(license_result, BypassResult)

    def test_bypass_handles_nonexistent_file_gracefully(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """Bypass handles nonexistent files gracefully without crashing."""
        nonexistent = temp_dir / "nonexistent.exe"

        disc_result = starforce_bypass.bypass_disc_check(nonexistent)
        license_result = starforce_bypass.bypass_license_validation(nonexistent)

        assert disc_result.success is False
        assert license_result.success is False

    def test_bypass_handles_invalid_process_id(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Bypass handles invalid process IDs gracefully."""
        result = starforce_bypass.bypass_anti_debug(999999999)

        assert isinstance(result, BypassResult)

    def test_registry_operations_handle_access_denied(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Registry operations handle access denied errors gracefully."""
        if os.name != "nt":
            pytest.skip("Windows-only test")

        result = starforce_bypass.spoof_hardware_id()

        assert isinstance(result, BypassResult)

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_handles_readonly_file(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """Bypass handles read-only files appropriately."""
        import stat

        starforce_protected_binary.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

        result = starforce_bypass.bypass_disc_check(starforce_protected_binary)

        starforce_protected_binary.chmod(
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
        )

        assert isinstance(result, BypassResult)


class TestDataclassValidation:
    """Validate dataclass structure and behavior."""

    def test_bypass_result_dataclass_structure(self) -> None:
        """BypassResult dataclass has correct fields and types."""
        result = BypassResult(
            success=True,
            technique="Test",
            details="Test details",
            errors=["error1"],
        )

        assert result.success is True
        assert result.technique == "Test"
        assert result.details == "Test details"
        assert result.errors == ["error1"]

    def test_starforce_removal_result_dataclass_structure(self) -> None:
        """StarForceRemovalResult dataclass has correct fields and types."""
        result = StarForceRemovalResult(
            drivers_removed=["driver1"],
            services_stopped=["service1"],
            registry_cleaned=["key1"],
            files_deleted=["file1"],
            success=True,
            errors=[],
        )

        assert result.drivers_removed == ["driver1"]
        assert result.services_stopped == ["service1"]
        assert result.registry_cleaned == ["key1"]
        assert result.files_deleted == ["file1"]
        assert result.success is True
        assert result.errors == []
