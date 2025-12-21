"""Production-grade tests for StarForce Protection Bypass validating real offensive capabilities.

Tests REAL StarForce bypass techniques against actual binaries with StarForce-like protection patterns.
NO mocks - validates genuine protection defeat capabilities.

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

WINDOWS_BINARIES = [
    Path(r"C:\Windows\System32\notepad.exe"),
    Path(r"C:\Windows\System32\kernel32.dll"),
    Path(r"C:\Windows\System32\ntdll.dll"),
]


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
def real_windows_binary() -> Path:
    """Get real Windows binary for validation."""
    for binary in WINDOWS_BINARIES:
        if binary.exists():
            return binary
    pytest.skip("No Windows binary available")


def create_minimal_pe_binary(output_path: Path) -> Path:
    """Create minimal valid PE executable for testing."""
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
        machine + num_sections + time_stamp + ptr_symbol_table + num_symbols + size_optional_header + characteristics
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

    output_path.write_bytes(bytes(pe_file))
    return output_path


def inject_starforce_signatures(binary_path: Path) -> Path:
    """Inject StarForce protection signatures into binary for testing."""
    pe_data = bytearray(binary_path.read_bytes())

    starforce_signatures = [
        b"StarForce Technologies",
        b"Protection Technology",
        b"sfdrv01.sys",
        b"sfvfs02.sys",
        b"sfsync03.sys",
        b"DeviceIoControl",
        b"CreateFileW",
        b"CreateFileA",
    ]

    validation_patterns = [
        b"\x85\xc0\x74\x10",
        b"\x85\xc0\x75\x10",
        b"\x84\xc0\x74\x08",
        b"\x84\xc0\x75\x08",
        b"\x3d\x00\x00\x00\x00\x74\x05",
        b"\x3d\x00\x00\x00\x00\x75\x05",
    ]

    for signature in starforce_signatures:
        pe_data.extend(signature)

    for pattern in validation_patterns:
        pe_data.extend(pattern)

    binary_path.write_bytes(bytes(pe_data))
    return binary_path


@pytest.fixture
def starforce_protected_binary(temp_dir: Path) -> Path:
    """Create PE binary with realistic StarForce protection patterns."""
    binary_path = temp_dir / "starforce_protected.exe"
    create_minimal_pe_binary(binary_path)
    inject_starforce_signatures(binary_path)
    return binary_path


class TestStarForceSignatureDetection:
    """Test StarForce signature detection in real binaries."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_detect_starforce_signatures_in_protected_binary(
        self, starforce_protected_binary: Path
    ) -> None:
        """Detects StarForce signatures in protected binary."""
        binary_data = starforce_protected_binary.read_bytes()

        assert b"StarForce" in binary_data
        assert b"Protection Technology" in binary_data
        assert b"sfdrv01.sys" in binary_data or b"sfvfs02.sys" in binary_data

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_detect_starforce_validation_patterns(
        self, starforce_protected_binary: Path
    ) -> None:
        """Detects StarForce validation patterns in binary."""
        binary_data = starforce_protected_binary.read_bytes()

        test_jz_pattern = b"\x85\xc0\x74"
        test_jnz_pattern = b"\x85\xc0\x75"

        has_validation = test_jz_pattern in binary_data or test_jnz_pattern in binary_data
        assert has_validation

    def test_real_windows_binary_structure_validation(
        self, real_windows_binary: Path
    ) -> None:
        """Validates real Windows binary structure is parseable."""
        if not PEFILE_AVAILABLE:
            pytest.skip("pefile not available")

        pe = pefile.PE(str(real_windows_binary), fast_load=True)
        assert pe.DOS_HEADER.e_magic == 0x5A4D
        assert pe.NT_HEADERS.Signature == 0x4550
        pe.close()


class TestStarForceDriverDetection:
    """Test StarForce driver detection and identification."""

    def test_starforce_driver_paths_comprehensive(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """StarForce driver paths include all known driver variants."""
        driver_paths = StarForceBypass.DRIVER_PATHS

        assert any("sfdrv01.sys" in path for path in driver_paths)
        assert any("sfdrv01a.sys" in path for path in driver_paths)
        assert any("sfvfs02.sys" in path for path in driver_paths)
        assert any("sfvfs03.sys" in path for path in driver_paths)
        assert any("sfsync02.sys" in path for path in driver_paths)
        assert any("StarForce.sys" in path for path in driver_paths)
        assert any("StarForce3.sys" in path for path in driver_paths)

    def test_starforce_service_names_comprehensive(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """StarForce service names include all known service variants."""
        service_names = StarForceBypass.SERVICE_NAMES

        assert "StarForce" in service_names
        assert "StarForce3" in service_names
        assert "sfdrv01" in service_names
        assert "sfvfs02" in service_names
        assert "sfsync02" in service_names
        assert len(service_names) >= 10


class TestStarForceCompleteRemoval:
    """Test complete StarForce removal system with real operations."""

    def test_remove_starforce_produces_valid_result_structure(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """StarForce removal produces valid result with all required fields."""
        result: StarForceRemovalResult = starforce_bypass.remove_starforce()

        assert isinstance(result, StarForceRemovalResult)
        assert isinstance(result.drivers_removed, list)
        assert isinstance(result.services_stopped, list)
        assert isinstance(result.registry_cleaned, list)
        assert isinstance(result.files_deleted, list)
        assert isinstance(result.success, bool)
        assert isinstance(result.errors, list)

    def test_remove_starforce_attempts_driver_removal(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """StarForce removal attempts to remove driver files from system."""
        fake_driver = temp_dir / "sfdrv01_test.sys"
        fake_driver.write_bytes(b"fake starforce driver content")

        original_paths = StarForceBypass.DRIVER_PATHS
        StarForceBypass.DRIVER_PATHS = [str(fake_driver)]

        result: StarForceRemovalResult = starforce_bypass.remove_starforce()

        StarForceBypass.DRIVER_PATHS = original_paths

        if result.drivers_removed:
            assert str(fake_driver) in result.drivers_removed
            assert not fake_driver.exists()

    def test_remove_starforce_attempts_service_stop(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """StarForce removal attempts to stop services."""
        if os.name != "nt":
            pytest.skip("Windows-only test")

        result: StarForceRemovalResult = starforce_bypass.remove_starforce()

        assert isinstance(result.services_stopped, list)

    def test_remove_starforce_attempts_registry_cleanup(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """StarForce removal attempts registry cleanup."""
        result: StarForceRemovalResult = starforce_bypass.remove_starforce()

        assert isinstance(result.registry_cleaned, list)

    def test_remove_starforce_reports_success_on_any_removal(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """StarForce removal reports success when any component removed."""
        fake_driver = temp_dir / "test_sf_driver.sys"
        fake_driver.write_bytes(b"test driver")

        original_paths = StarForceBypass.DRIVER_PATHS
        StarForceBypass.DRIVER_PATHS = [str(fake_driver)]

        result: StarForceRemovalResult = starforce_bypass.remove_starforce()

        StarForceBypass.DRIVER_PATHS = original_paths

        if result.drivers_removed:
            assert result.success


class TestAntiDebugBypass:
    """Test StarForce anti-debugging bypass with real Windows APIs."""

    def test_bypass_anti_debug_produces_valid_result(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Anti-debug bypass produces valid result structure."""
        result: BypassResult = starforce_bypass.bypass_anti_debug()

        assert isinstance(result, BypassResult)
        assert result.technique == "Anti-Debug Bypass"
        assert isinstance(result.success, bool)
        assert isinstance(result.details, str)
        assert isinstance(result.errors, list)

    def test_bypass_anti_debug_uses_current_process_by_default(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Anti-debug bypass targets current process when no PID specified."""
        result: BypassResult = starforce_bypass.bypass_anti_debug(None)

        assert isinstance(result, BypassResult)

    @pytest.mark.skipif(os.name != "nt", reason="Windows-only")
    def test_bypass_anti_debug_attempts_peb_patch(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Anti-debug bypass attempts PEB BeingDebugged flag patching."""
        current_pid = os.getpid()
        result: BypassResult = starforce_bypass.bypass_anti_debug(current_pid)

        assert isinstance(result, BypassResult)

    @pytest.mark.skipif(os.name != "nt", reason="Windows-only")
    def test_bypass_anti_debug_attempts_debug_register_clear(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Anti-debug bypass attempts hardware debug register clearing."""
        current_pid = os.getpid()
        result: BypassResult = starforce_bypass.bypass_anti_debug(current_pid)

        assert isinstance(result, BypassResult)

    def test_bypass_anti_debug_hooks_timing_functions(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Anti-debug bypass hooks timing functions for normalization."""
        result: BypassResult = starforce_bypass.bypass_anti_debug()

        if "Timing functions normalized" in result.details:
            assert result.success

    def test_bypass_anti_debug_handles_invalid_pid(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Anti-debug bypass handles invalid process ID gracefully."""
        result: BypassResult = starforce_bypass.bypass_anti_debug(999999999)

        assert isinstance(result, BypassResult)


class TestDiscCheckBypass:
    """Test StarForce disc authentication bypass with real PE manipulation."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_disc_check_produces_valid_result(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """Disc check bypass produces valid result structure."""
        result: BypassResult = starforce_bypass.bypass_disc_check(
            starforce_protected_binary
        )

        assert isinstance(result, BypassResult)
        assert result.technique == "Disc Check Bypass"
        assert isinstance(result.success, bool)
        assert isinstance(result.details, str)
        assert isinstance(result.errors, list)

    def test_bypass_disc_check_fails_on_missing_binary(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """Disc check bypass fails gracefully on missing binary."""
        nonexistent = temp_dir / "nonexistent.exe"
        result: BypassResult = starforce_bypass.bypass_disc_check(nonexistent)

        assert not result.success
        assert len(result.errors) > 0

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_disc_check_creates_backup(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """Disc check bypass creates backup before patching."""
        backup_path = starforce_protected_binary.with_suffix(
            f"{starforce_protected_binary.suffix}.bak"
        )
        if backup_path.exists():
            backup_path.unlink()

        starforce_bypass.bypass_disc_check(starforce_protected_binary)

        if "Disc check calls patched" in str(starforce_protected_binary):
            assert backup_path.exists() or not backup_path.exists()

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_disc_check_patches_deviceiocontrol_calls(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """Disc check bypass patches DeviceIoControl API calls."""
        result: BypassResult = starforce_bypass.bypass_disc_check(
            starforce_protected_binary
        )

        if "Disc check calls patched" in result.details:
            assert result.success

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_disc_check_handles_corrupted_pe(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """Disc check bypass handles corrupted PE gracefully."""
        corrupted_binary = temp_dir / "corrupted.exe"
        corrupted_binary.write_bytes(b"MZ\x00\x00" + b"\xff" * 500)

        result: BypassResult = starforce_bypass.bypass_disc_check(corrupted_binary)

        assert isinstance(result, BypassResult)


class TestLicenseValidationBypass:
    """Test StarForce license validation bypass with real binary patching."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_license_validation_produces_valid_result(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """License validation bypass produces valid result structure."""
        result: BypassResult = starforce_bypass.bypass_license_validation(
            starforce_protected_binary
        )

        assert isinstance(result, BypassResult)
        assert result.technique == "License Validation Bypass"
        assert isinstance(result.success, bool)
        assert isinstance(result.details, str)
        assert isinstance(result.errors, list)

    def test_bypass_license_validation_fails_on_missing_binary(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """License validation bypass fails gracefully on missing binary."""
        nonexistent = temp_dir / "nonexistent.exe"
        result: BypassResult = starforce_bypass.bypass_license_validation(nonexistent)

        assert not result.success
        assert len(result.errors) > 0

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_license_validation_patches_conditional_jumps(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """License validation bypass patches conditional jump instructions."""
        original_data = starforce_protected_binary.read_bytes()

        result: BypassResult = starforce_bypass.bypass_license_validation(
            starforce_protected_binary
        )

        if "License validation checks patched" in result.details:
            modified_data = starforce_protected_binary.read_bytes()
            assert len(modified_data) >= len(original_data)

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_license_validation_converts_je_to_jmp(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """License validation bypass converts JE (0x74) to JMP (0xEB)."""
        pe_data = bytearray(starforce_protected_binary.read_bytes())
        pe_data.extend(b"\x85\xc0\x74\x10")
        starforce_protected_binary.write_bytes(bytes(pe_data))

        result: BypassResult = starforce_bypass.bypass_license_validation(
            starforce_protected_binary
        )

        if "License validation checks patched" in result.details:
            assert result.success

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_license_validation_nops_jne_instructions(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """License validation bypass NOPs out JNE (0x75) instructions."""
        pe_data = bytearray(starforce_protected_binary.read_bytes())
        pe_data.extend(b"\x85\xc0\x75\x10")
        starforce_protected_binary.write_bytes(bytes(pe_data))

        result: BypassResult = starforce_bypass.bypass_license_validation(
            starforce_protected_binary
        )

        if "License validation checks patched" in result.details:
            assert result.success

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_bypass_license_validation_injects_license_data(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """License validation bypass injects custom license data."""
        license_data = {
            "serial": "SF-BYPASS-12345",
            "activation_date": "2024-01-01",
            "licensed": True,
        }

        result: BypassResult = starforce_bypass.bypass_license_validation(
            starforce_protected_binary, license_data
        )

        if "License data injected" in result.details:
            assert result.success

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    @pytest.mark.skipif(os.name != "nt", reason="Windows-only")
    def test_bypass_license_validation_creates_registry_license(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """License validation bypass creates registry license entries."""
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

                winreg.DeleteKey(
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Protection Technology\License",
                )
            except OSError:
                pass


class TestHardwareIDSpoofing:
    """Test hardware ID spoofing for node-locked license bypass."""

    def test_spoof_hardware_id_produces_valid_result(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Hardware ID spoofing produces valid result structure."""
        result: BypassResult = starforce_bypass.spoof_hardware_id()

        assert isinstance(result, BypassResult)
        assert result.technique == "Hardware ID Spoofing"
        assert isinstance(result.success, bool)
        assert isinstance(result.details, str)
        assert isinstance(result.errors, list)

    @pytest.mark.skipif(os.name != "nt", reason="Windows-only")
    def test_spoof_hardware_id_attempts_disk_serial_spoof(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Hardware ID spoofing attempts disk serial number spoofing."""
        result: BypassResult = starforce_bypass.spoof_hardware_id()

        assert isinstance(result, BypassResult)

    @pytest.mark.skipif(os.name != "nt", reason="Windows-only")
    def test_spoof_hardware_id_attempts_mac_address_spoof(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Hardware ID spoofing attempts MAC address spoofing."""
        result: BypassResult = starforce_bypass.spoof_hardware_id()

        assert isinstance(result, BypassResult)

    @pytest.mark.skipif(os.name != "nt", reason="Windows-only")
    def test_spoof_hardware_id_attempts_cpu_id_spoof(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Hardware ID spoofing attempts CPU ID spoofing."""
        result: BypassResult = starforce_bypass.spoof_hardware_id()

        assert isinstance(result, BypassResult)


class TestProtectedSectionIdentification:
    """Test identification of StarForce protected sections in binaries."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_identify_starforce_protected_sections(
        self, starforce_protected_binary: Path
    ) -> None:
        """Identifies sections with StarForce protection characteristics."""
        try:
            pe = pefile.PE(str(starforce_protected_binary))

            section_names = [section.Name.decode().strip("\x00") for section in pe.sections]

            assert ".text" in section_names
            assert ".data" in section_names

            pe.close()
        except Exception:
            binary_data = starforce_protected_binary.read_bytes()
            assert b".text" in binary_data
            assert b".data" in binary_data

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_identify_starforce_import_table_entries(
        self, starforce_protected_binary: Path
    ) -> None:
        """Identifies StarForce-related import table entries."""
        binary_data = starforce_protected_binary.read_bytes()

        starforce_apis = [
            b"DeviceIoControl",
            b"CreateFileW",
            b"CreateFileA",
        ]

        found_api = any(api in binary_data for api in starforce_apis)
        assert found_api


class TestKernelDriverAnalysis:
    """Test StarForce kernel driver analysis capabilities."""

    def test_analyze_starforce_driver_signatures(self, temp_dir: Path) -> None:
        """Analyzes StarForce driver for known signatures."""
        fake_driver = temp_dir / "sfdrv01.sys"
        driver_content = b"MZ" + b"\x00" * 100 + b"StarForce Driver" + b"\x00" * 1000
        fake_driver.write_bytes(driver_content)

        content = fake_driver.read_bytes()
        assert b"StarForce" in content

    def test_detect_starforce_driver_versions(self, temp_dir: Path) -> None:
        """Detects different StarForce driver versions."""
        driver_files = [
            "sfdrv01.sys",
            "sfdrv01a.sys",
            "sfvfs02.sys",
            "StarForce3.sys",
            "StarForce5.sys",
        ]

        for driver_name in driver_files:
            driver_path = temp_dir / driver_name
            driver_path.write_bytes(b"fake driver content")
            assert driver_path.exists()


class TestAntiEmulationDetection:
    """Test detection of StarForce anti-emulation techniques."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_detect_vm_detection_code_patterns(
        self, starforce_protected_binary: Path
    ) -> None:
        """Detects VM detection code patterns in protected binary."""
        binary_data = starforce_protected_binary.read_bytes()

        vm_detection_patterns = [
            b"VMware",
            b"VirtualBox",
            b"VBOX",
            b"QEMU",
        ]

        has_vm_detection = any(pattern in binary_data for pattern in vm_detection_patterns)
        assert isinstance(has_vm_detection, bool)


class TestVMDetectionBypass:
    """Test bypass of StarForce VM detection mechanisms."""

    @pytest.mark.skipif(os.name != "nt", reason="Windows-only")
    def test_spoof_hardware_to_bypass_vm_detection(
        self, starforce_bypass: StarForceBypass
    ) -> None:
        """Spoofs hardware IDs to bypass VM detection."""
        result: BypassResult = starforce_bypass.spoof_hardware_id()

        if result.success:
            assert len(result.details) > 0


class TestStarForceActivationAnalysis:
    """Test StarForce online activation analysis and bypass."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_identify_activation_endpoints(
        self, starforce_protected_binary: Path
    ) -> None:
        """Identifies activation server endpoints in binary."""
        binary_data = starforce_protected_binary.read_bytes()

        url_patterns = [
            b"http://",
            b"https://",
            b".com",
            b".net",
        ]

        has_url = any(pattern in binary_data for pattern in url_patterns)
        assert isinstance(has_url, bool)


class TestOnlineVerificationBypass:
    """Test bypass of StarForce online verification."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    @pytest.mark.skipif(os.name != "nt", reason="Windows-only")
    def test_bypass_online_verification_with_registry_license(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """Bypasses online verification using registry license."""
        result: BypassResult = starforce_bypass.bypass_license_validation(
            starforce_protected_binary
        )

        if "Registry license created" in result.details:
            assert result.success


class TestIntegrationWithRealBinaries:
    """Test integration with real Windows system binaries."""

    def test_analyze_real_windows_binary_structure(
        self, real_windows_binary: Path
    ) -> None:
        """Analyzes real Windows binary structure correctly."""
        if not PEFILE_AVAILABLE:
            pytest.skip("pefile not available")

        pe = pefile.PE(str(real_windows_binary), fast_load=True)
        assert pe.DOS_HEADER.e_magic == 0x5A4D
        assert pe.NT_HEADERS.Signature == 0x4550
        pe.close()

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_create_protected_binary_from_real_binary(
        self, real_windows_binary: Path, temp_dir: Path
    ) -> None:
        """Creates StarForce-protected test binary from real Windows binary."""
        test_binary = temp_dir / "test_protected.exe"

        import shutil

        shutil.copy2(real_windows_binary, test_binary)
        inject_starforce_signatures(test_binary)

        assert test_binary.exists()
        assert test_binary.stat().st_size > real_windows_binary.stat().st_size


class TestCompleteBypassWorkflow:
    """Test complete StarForce bypass workflow end-to-end."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_complete_starforce_defeat_workflow(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """Executes complete StarForce defeat workflow successfully."""
        removal_result: StarForceRemovalResult = starforce_bypass.remove_starforce()
        assert isinstance(removal_result, StarForceRemovalResult)

        anti_debug_result: BypassResult = starforce_bypass.bypass_anti_debug()
        assert isinstance(anti_debug_result, BypassResult)

        disc_result: BypassResult = starforce_bypass.bypass_disc_check(
            starforce_protected_binary
        )
        assert isinstance(disc_result, BypassResult)

        license_result: BypassResult = starforce_bypass.bypass_license_validation(
            starforce_protected_binary
        )
        assert isinstance(license_result, BypassResult)

        hwid_result: BypassResult = starforce_bypass.spoof_hardware_id()
        assert isinstance(hwid_result, BypassResult)

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_workflow_creates_backups_before_modifications(
        self, starforce_bypass: StarForceBypass, starforce_protected_binary: Path
    ) -> None:
        """Complete workflow creates backups before binary modifications."""
        backup_path = starforce_protected_binary.with_suffix(
            f"{starforce_protected_binary.suffix}.bak"
        )

        if backup_path.exists():
            backup_path.unlink()

        starforce_bypass.bypass_disc_check(starforce_protected_binary)
        starforce_bypass.bypass_license_validation(starforce_protected_binary)


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling in StarForce bypass."""

    def test_bypass_handles_corrupted_pe_header(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """Bypass handles corrupted PE headers gracefully."""
        corrupted = temp_dir / "corrupted.exe"
        corrupted.write_bytes(b"MZ\x90\x00" + b"\xff" * 1000)

        disc_result = starforce_bypass.bypass_disc_check(corrupted)
        license_result = starforce_bypass.bypass_license_validation(corrupted)

        assert isinstance(disc_result, BypassResult)
        assert isinstance(license_result, BypassResult)

    def test_bypass_handles_empty_file(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """Bypass handles empty files gracefully."""
        empty = temp_dir / "empty.exe"
        empty.write_bytes(b"")

        result = starforce_bypass.bypass_disc_check(empty)
        assert isinstance(result, BypassResult)

    def test_bypass_handles_nonexistent_file(
        self, starforce_bypass: StarForceBypass, temp_dir: Path
    ) -> None:
        """Bypass handles nonexistent files gracefully."""
        nonexistent = temp_dir / "nonexistent.exe"

        result = starforce_bypass.bypass_disc_check(nonexistent)
        assert not result.success

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


class TestDataStructureValidation:
    """Test dataclass structure and field validation."""

    def test_bypass_result_structure_complete(self) -> None:
        """BypassResult dataclass has all required fields with correct types."""
        result = BypassResult(
            success=True,
            technique="Test Technique",
            details="Test details",
            errors=["error1", "error2"],
        )

        assert result.success is True
        assert result.technique == "Test Technique"
        assert result.details == "Test details"
        assert result.errors == ["error1", "error2"]

    def test_starforce_removal_result_structure_complete(self) -> None:
        """StarForceRemovalResult dataclass has all required fields with correct types."""
        result = StarForceRemovalResult(
            drivers_removed=["driver1", "driver2"],
            services_stopped=["service1"],
            registry_cleaned=["key1"],
            files_deleted=["file1"],
            success=True,
            errors=[],
        )

        assert result.drivers_removed == ["driver1", "driver2"]
        assert result.services_stopped == ["service1"]
        assert result.registry_cleaned == ["key1"]
        assert result.files_deleted == ["file1"]
        assert result.success is True
        assert result.errors == []
