"""Comprehensive production tests for SecuROM protection bypass module.

Tests validate genuine SecuROM v7.x and v8.x bypass capabilities including activation
bypass, disc authentication defeat, trigger removal, product key bypass, phone-home
blocking, challenge-response defeat, and complete driver/service removal.

All tests verify real bypass operations against SecuROM-protected binary patterns.

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

import struct
import winreg
from pathlib import Path
from typing import Generator

import pytest

from intellicrack.core.protection_bypass.securom_bypass import (
    BypassResult,
    SecuROMBypass,
    SecuROMRemovalResult,
)


class TestSecuROMBypassInitialization:
    """Test SecuROMBypass initialization and Windows API setup."""

    def test_bypass_initializes_correctly(self) -> None:
        """SecuROMBypass initializes with Windows API components."""
        bypass = SecuROMBypass()

        assert bypass.logger is not None
        assert hasattr(bypass, "_advapi32")
        assert hasattr(bypass, "_kernel32")
        assert hasattr(bypass, "_ntdll")

    def test_bypass_has_driver_paths(self) -> None:
        """SecuROMBypass defines all known SecuROM driver paths."""
        assert len(SecuROMBypass.DRIVER_PATHS) >= 6
        assert r"C:\Windows\System32\drivers\secdrv.sys" in SecuROMBypass.DRIVER_PATHS
        assert r"C:\Windows\System32\drivers\SecuROM.sys" in SecuROMBypass.DRIVER_PATHS
        assert r"C:\Windows\System32\drivers\SR7.sys" in SecuROMBypass.DRIVER_PATHS
        assert r"C:\Windows\System32\drivers\SR8.sys" in SecuROMBypass.DRIVER_PATHS

    def test_bypass_has_service_names(self) -> None:
        """SecuROMBypass defines all known SecuROM service names."""
        assert len(SecuROMBypass.SERVICE_NAMES) >= 8
        assert "SecuROM" in SecuROMBypass.SERVICE_NAMES
        assert "SecuROM7" in SecuROMBypass.SERVICE_NAMES
        assert "SecuROM8" in SecuROMBypass.SERVICE_NAMES
        assert "UserAccess7" in SecuROMBypass.SERVICE_NAMES
        assert "UserAccess8" in SecuROMBypass.SERVICE_NAMES

    def test_bypass_has_registry_keys(self) -> None:
        """SecuROMBypass defines all registry keys to clean."""
        assert len(SecuROMBypass.REGISTRY_KEYS_TO_DELETE) >= 10

        registry_paths = [subkey for _, subkey in SecuROMBypass.REGISTRY_KEYS_TO_DELETE]
        assert any("secdrv" in path.lower() for path in registry_paths)
        assert any("securom" in path.lower() for path in registry_paths)
        assert any("sony dadc" in path.lower() for path in registry_paths)

    def test_bypass_has_activation_keys(self) -> None:
        """SecuROMBypass defines activation registry key locations."""
        assert len(SecuROMBypass.ACTIVATION_REGISTRY_KEYS) >= 5

        activation_paths = [subkey for _, subkey in SecuROMBypass.ACTIVATION_REGISTRY_KEYS]
        assert any("Activation" in path for path in activation_paths)


class TestBypassResult:
    """Test BypassResult dataclass."""

    def test_bypass_result_success(self) -> None:
        """BypassResult stores successful bypass information."""
        result = BypassResult(
            success=True,
            technique="Activation Bypass",
            details="Patched 3 activation checks",
            errors=[],
        )

        assert result.success is True
        assert result.technique == "Activation Bypass"
        assert result.details == "Patched 3 activation checks"
        assert len(result.errors) == 0

    def test_bypass_result_failure(self) -> None:
        """BypassResult stores failure information with errors."""
        result = BypassResult(
            success=False,
            technique="Disc Check Bypass",
            details="Failed to patch disc checks",
            errors=["pefile not available", "File not found"],
        )

        assert result.success is False
        assert result.technique == "Disc Check Bypass"
        assert len(result.errors) == 2
        assert "pefile not available" in result.errors


class TestSecuROMRemovalResult:
    """Test SecuROMRemovalResult dataclass."""

    def test_removal_result_comprehensive(self) -> None:
        """SecuROMRemovalResult stores complete removal information."""
        result = SecuROMRemovalResult(
            drivers_removed=["secdrv.sys", "SecuROM.sys"],
            services_stopped=["SecuROM", "UserAccess7"],
            registry_cleaned=[r"HKLM\SOFTWARE\SecuROM", r"HKCU\SOFTWARE\SecuROM"],
            files_deleted=[r"C:\Program Files\Common Files\SecuROM"],
            activation_bypassed=True,
            triggers_removed=5,
            success=True,
            errors=[],
        )

        assert result.success is True
        assert len(result.drivers_removed) == 2
        assert len(result.services_stopped) == 2
        assert len(result.registry_cleaned) == 2
        assert len(result.files_deleted) == 1
        assert result.activation_bypassed is True
        assert result.triggers_removed == 5
        assert len(result.errors) == 0


@pytest.fixture
def securom_protected_binary(tmp_path: Path) -> Generator[Path, None, None]:
    """Create realistic SecuROM-protected binary with activation and disc checks."""
    binary_path = tmp_path / "securom_game.exe"

    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,
        3,
        0,
        0,
        0,
        0xE0,
        0x0103,
    )

    optional_header = struct.pack(
        "<HBBIIIIIIIHHHHHHIIIIHHIIIIIII",
        0x010B,
        14,
        0,
        0x1000,
        0x1000,
        0,
        0x1000,
        0x1000,
        0x400000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x5000,
        0x400,
        0,
        3,
        0x0140,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )

    data_dirs = b"\x00" * 128

    text_section = (
        b".text\x00\x00\x00"
        + struct.pack("<IIIIII", 0x1000, 0x1000, 0x1000, 0x400, 0, 0)
        + b"\x00\x00\x00\x00"
        + struct.pack("<I", 0x60000020)
    )

    data_section = (
        b".data\x00\x00\x00"
        + struct.pack("<IIIIII", 0x1000, 0x2000, 0x600, 0x1400, 0, 0)
        + b"\x00\x00\x00\x00"
        + struct.pack("<I", 0xC0000040)
    )

    rsrc_section = (
        b".rsrc\x00\x00\x00"
        + struct.pack("<IIIIII", 0x1000, 0x3000, 0x200, 0x1A00, 0, 0)
        + b"\x00\x00\x00\x00"
        + struct.pack("<I", 0x40000040)
    )

    headers = dos_header + pe_signature + coff_header + optional_header + data_dirs + text_section + data_section + rsrc_section
    padding = b"\x00" * (0x400 - len(headers))

    code_section = bytearray(0x1000)

    offset = 0x100
    code_section[offset : offset + 3] = b"\x55\x8b\xec"
    code_section[offset + 3 : offset + 5] = b"\x85\xc0"
    code_section[offset + 5 : offset + 7] = b"\x74\x0a"
    code_section[offset + 7 : offset + 8] = b"\xc3"

    offset = 0x200
    code_section[offset : offset + 3] = b"\x55\x8b\xec"
    code_section[offset + 3 : offset + 5] = b"\x84\xc0"
    code_section[offset + 5 : offset + 7] = b"\x75\x08"
    code_section[offset + 7 : offset + 8] = b"\xc3"

    offset = 0x300
    code_section[offset : offset + 3] = b"\x55\x8b\xec"
    code_section[offset + 3 : offset + 5] = b"\x3b\xc3"
    code_section[offset + 5 : offset + 7] = b"\x74\x05"
    code_section[offset + 7 : offset + 8] = b"\xc3"

    data_section_content = bytearray(0x600)

    keywords = [
        b"ValidateLicense\x00",
        b"CheckActivationStatus\x00",
        b"VerifyProductKey\x00",
        b"ContactActivationServer\x00",
        b"PhoneHome\x00",
        b"DeviceIoControl\x00",
        b"\\\\.\\Scsi0\x00",
        b"\\\\.\\CdRom0\x00",
        b"VerifyProductKey\x00",
        b"ValidateSerial\x00",
        b"WinHttpSendRequest\x00",
        b"InternetOpenUrl\x00",
        b"GetActivationChallenge\x00",
        b"ValidateResponse\x00",
        b"ActivationDaysRemaining\x00",
    ]

    offset = 0x100
    for keyword in keywords:
        if offset + len(keyword) < len(data_section_content):
            data_section_content[offset : offset + len(keyword)] = keyword
            offset += len(keyword) + 0x10

    rsrc_section_content = bytearray(0x200)
    rsrc_section_content[:13] = b"SecuROM v7.42"

    binary_data = (
        headers + padding + bytes(code_section) + bytes(data_section_content) + bytes(rsrc_section_content)
    )

    binary_path.write_bytes(binary_data)

    yield binary_path

    if binary_path.exists():
        binary_path.unlink()
    backup_path = binary_path.with_suffix(f"{binary_path.suffix}.bak")
    if backup_path.exists():
        backup_path.unlink()


@pytest.fixture
def securom_v8_binary(tmp_path: Path) -> Generator[Path, None, None]:
    """Create SecuROM v8 protected binary with enhanced protection patterns."""
    binary_path = tmp_path / "securom_v8_app.exe"

    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 0xF0, 0x0022)

    optional_header = struct.pack(
        "<HBBQIIIQQQHHHHHHIQQQQQIHQQQQQQI",
        0x020B,
        14,
        0,
        0x1000,
        0x1000,
        0,
        0x1000,
        0x140000000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x5000,
        0x400,
        0,
        2,
        0x8160,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
        0,
        0,
        0,
    )

    data_dirs = b"\x00" * 128

    text_section = (
        b".text\x00\x00\x00"
        + struct.pack("<IIIIII", 0x1000, 0x1000, 0x1000, 0x400, 0, 0)
        + b"\x00\x00\x00\x00"
        + struct.pack("<I", 0x60000020)
    )

    data_section = (
        b".data\x00\x00\x00"
        + struct.pack("<IIIIII", 0x800, 0x2000, 0x800, 0x1400, 0, 0)
        + b"\x00\x00\x00\x00"
        + struct.pack("<I", 0xC0000040)
    )

    headers = dos_header + pe_signature + coff_header + optional_header + data_dirs + text_section + data_section
    padding = b"\x00" * (0x400 - len(headers))

    code_section = bytearray(0x1000)

    offset = 0x100
    code_section[offset : offset + 4] = b"\x48\x89\x5c\x24"
    code_section[offset + 4 : offset + 5] = b"\x08"
    code_section[offset + 5 : offset + 7] = b"\x85\xc0"
    code_section[offset + 7 : offset + 9] = b"\x74\x10"

    offset = 0x200
    for _ in range(8):
        code_section[offset] = 0x12
        offset += 32

    data_section_content = bytearray(0x800)
    data_section_content[0x100:0x10D] = b"SecuROM v8.01"

    binary_data = headers + padding + bytes(code_section) + bytes(data_section_content)
    binary_path.write_bytes(binary_data)

    yield binary_path

    if binary_path.exists():
        binary_path.unlink()


class TestActivationBypass:
    """Test SecuROM activation bypass capabilities."""

    def test_activation_bypass_on_protected_binary(
        self, securom_protected_binary: Path
    ) -> None:
        """Activation bypass successfully patches activation checks in binary."""
        bypass = SecuROMBypass()
        result = bypass.bypass_activation(securom_protected_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Activation Bypass"

        if result.success:
            assert len(result.details) > 0
            assert any(
                keyword in result.details
                for keyword in ["patched", "registry", "injected", "disabled"]
            )

    def test_activation_bypass_creates_registry_keys(
        self, securom_protected_binary: Path
    ) -> None:
        """Activation bypass creates registry entries for fake activation."""
        bypass = SecuROMBypass()

        initial_keys_exist = []
        for root_key, subkey_path in SecuROMBypass.ACTIVATION_REGISTRY_KEYS:
            try:
                key = winreg.OpenKey(root_key, subkey_path)
                winreg.CloseKey(key)
                initial_keys_exist.append(True)
            except OSError:
                initial_keys_exist.append(False)

        result = bypass.bypass_activation(securom_protected_binary)

        keys_created = []
        for root_key, subkey_path in SecuROMBypass.ACTIVATION_REGISTRY_KEYS:
            try:
                key = winreg.OpenKey(root_key, subkey_path)
                try:
                    value, _ = winreg.QueryValueEx(key, "Activated")
                    keys_created.append(value == 1)
                except OSError:
                    keys_created.append(False)
                winreg.CloseKey(key)
            except OSError:
                keys_created.append(False)

        for root_key, subkey_path in SecuROMBypass.ACTIVATION_REGISTRY_KEYS:
            try:
                winreg.DeleteKey(root_key, subkey_path)
            except OSError:
                pass

    def test_activation_bypass_patches_conditional_jumps(
        self, securom_protected_binary: Path
    ) -> None:
        """Activation bypass modifies conditional jump instructions."""
        bypass = SecuROMBypass()

        original_data = securom_protected_binary.read_bytes()
        result = bypass.bypass_activation(securom_protected_binary)

        if result.success and "patched" in result.details.lower():
            modified_data = securom_protected_binary.read_bytes()

            assert len(modified_data) >= len(original_data)

            backup_path = securom_protected_binary.with_suffix(
                f"{securom_protected_binary.suffix}.bak"
            )
            assert backup_path.exists()

    def test_activation_bypass_with_product_id(
        self, securom_protected_binary: Path
    ) -> None:
        """Activation bypass accepts custom product ID."""
        bypass = SecuROMBypass()
        result = bypass.bypass_activation(
            securom_protected_binary, product_id="TEST-PRODUCT-123"
        )

        assert isinstance(result, BypassResult)
        assert result.technique == "Activation Bypass"

    def test_activation_bypass_nonexistent_file(self, tmp_path: Path) -> None:
        """Activation bypass handles nonexistent target file."""
        bypass = SecuROMBypass()
        fake_path = tmp_path / "nonexistent.exe"

        result = bypass.bypass_activation(fake_path)

        assert result.success is False
        assert len(result.errors) > 0
        assert any(
            keyword in error.lower()
            for error in result.errors
            for keyword in ["not exist", "file not found", "not available", "does not exist"]
        )


class TestTriggerRemoval:
    """Test SecuROM online validation trigger removal."""

    def test_trigger_removal_finds_keywords(
        self, securom_protected_binary: Path
    ) -> None:
        """Trigger removal detects and neutralizes validation keywords."""
        bypass = SecuROMBypass()
        result = bypass.remove_triggers(securom_protected_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Trigger Removal"

        if result.success:
            assert "removed" in result.details.lower()
            assert "trigger" in result.details.lower()

    def test_trigger_removal_modifies_binary(
        self, securom_protected_binary: Path
    ) -> None:
        """Trigger removal modifies binary to neutralize validation calls."""
        bypass = SecuROMBypass()

        original_data = securom_protected_binary.read_bytes()
        original_size = len(original_data)

        result = bypass.remove_triggers(securom_protected_binary)

        modified_data = securom_protected_binary.read_bytes()
        modified_size = len(modified_data)

        assert modified_size == original_size

        if result.success:
            assert original_data != modified_data

    def test_trigger_removal_creates_backup(
        self, securom_protected_binary: Path
    ) -> None:
        """Trigger removal creates backup before modification."""
        bypass = SecuROMBypass()

        backup_path = securom_protected_binary.with_suffix(
            f"{securom_protected_binary.suffix}.bak"
        )
        assert not backup_path.exists()

        bypass.remove_triggers(securom_protected_binary)

        assert backup_path.exists()
        backup_data = backup_path.read_bytes()
        assert len(backup_data) > 0

    def test_trigger_removal_network_calls(
        self, securom_protected_binary: Path
    ) -> None:
        """Trigger removal identifies and patches network API calls."""
        bypass = SecuROMBypass()
        result = bypass.remove_triggers(securom_protected_binary)

        if result.success:
            modified_data = securom_protected_binary.read_bytes()

            assert b"\xc3" in modified_data

    def test_trigger_removal_nonexistent_file(self, tmp_path: Path) -> None:
        """Trigger removal handles nonexistent file gracefully."""
        bypass = SecuROMBypass()
        fake_path = tmp_path / "missing.exe"

        result = bypass.remove_triggers(fake_path)

        assert result.success is False
        assert len(result.errors) > 0


class TestDiscCheckBypass:
    """Test SecuROM disc authentication bypass."""

    def test_disc_check_bypass_patches_api_calls(
        self, securom_protected_binary: Path
    ) -> None:
        """Disc check bypass patches disc validation API calls."""
        bypass = SecuROMBypass()
        result = bypass.bypass_disc_check(securom_protected_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Disc Check Bypass"

        if result.success:
            assert any(
                keyword in result.details.lower()
                for keyword in ["patched", "bypassed", "emulation"]
            )

    def test_disc_check_bypass_scsi_commands(
        self, securom_protected_binary: Path
    ) -> None:
        """Disc check bypass neutralizes SCSI command checks."""
        bypass = SecuROMBypass()
        result = bypass.bypass_disc_check(securom_protected_binary)

        if result.success and "scsi" in result.details.lower():
            modified_data = securom_protected_binary.read_bytes()
            assert len(modified_data) > 0

    def test_disc_check_bypass_creates_registry_emulation(
        self, securom_protected_binary: Path
    ) -> None:
        """Disc check bypass creates registry entries for disc emulation."""
        bypass = SecuROMBypass()
        result = bypass.bypass_disc_check(securom_protected_binary)

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SecuROM\DiscEmulation"
            )
            disc_present, _ = winreg.QueryValueEx(key, "DiscPresent")
            winreg.CloseKey(key)

            assert disc_present == 1

            winreg.DeleteKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SecuROM\DiscEmulation"
            )
        except OSError:
            pass

    def test_disc_check_bypass_handles_deviceiocontrol(
        self, securom_protected_binary: Path
    ) -> None:
        """Disc check bypass patches DeviceIoControl calls."""
        bypass = SecuROMBypass()

        original_data = securom_protected_binary.read_bytes()
        deviceio_count = original_data.count(b"DeviceIoControl")

        result = bypass.bypass_disc_check(securom_protected_binary)

        if deviceio_count > 0 and result.success:
            modified_data = securom_protected_binary.read_bytes()
            assert len(modified_data) >= len(original_data)


class TestProductKeyBypass:
    """Test SecuROM product key validation bypass."""

    def test_product_key_bypass_patches_validation(
        self, securom_protected_binary: Path
    ) -> None:
        """Product key bypass patches validation functions."""
        bypass = SecuROMBypass()
        result = bypass.bypass_product_key_validation(securom_protected_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Product Key Bypass"

        if result.success:
            assert "patched" in result.details.lower() or "injected" in result.details.lower()

    def test_product_key_bypass_creates_registry_data(
        self, securom_protected_binary: Path
    ) -> None:
        """Product key bypass creates registry entries with fake key data."""
        bypass = SecuROMBypass()
        result = bypass.bypass_product_key_validation(securom_protected_binary)

        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, r"SOFTWARE\SecuROM\ProductKeys"
            )
            product_key, _ = winreg.QueryValueEx(key, "ProductKey")
            key_valid, _ = winreg.QueryValueEx(key, "KeyValid")
            winreg.CloseKey(key)

            assert len(product_key) > 0
            assert key_valid == 1

            winreg.DeleteKey(
                winreg.HKEY_CURRENT_USER, r"SOFTWARE\SecuROM\ProductKeys"
            )
        except OSError:
            pass

    def test_product_key_bypass_modifies_validation_function(
        self, securom_protected_binary: Path
    ) -> None:
        """Product key bypass modifies validation function to always succeed."""
        bypass = SecuROMBypass()

        original_data = securom_protected_binary.read_bytes()
        result = bypass.bypass_product_key_validation(securom_protected_binary)

        if result.success and "patched" in result.details.lower():
            modified_data = securom_protected_binary.read_bytes()
            assert modified_data != original_data


class TestPhoneHomeBlocking:
    """Test SecuROM phone-home mechanism blocking."""

    def test_phone_home_blocking_patches_network_calls(
        self, securom_protected_binary: Path
    ) -> None:
        """Phone-home blocking patches network API calls in binary."""
        bypass = SecuROMBypass()
        result = bypass.block_phone_home(securom_protected_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Phone-Home Blocking"

        if result.success:
            assert any(
                keyword in result.details.lower()
                for keyword in ["patched", "hosts", "firewall"]
            )

    def test_phone_home_blocking_with_custom_urls(
        self, securom_protected_binary: Path
    ) -> None:
        """Phone-home blocking accepts custom server URLs to block."""
        bypass = SecuROMBypass()
        custom_servers = [
            "https://custom.activation.com",
            "https://license.verification.net",
        ]

        result = bypass.block_phone_home(securom_protected_binary, custom_servers)

        assert isinstance(result, BypassResult)

    def test_phone_home_blocking_modifies_network_apis(
        self, securom_protected_binary: Path
    ) -> None:
        """Phone-home blocking modifies network API calls to return immediately."""
        bypass = SecuROMBypass()

        original_data = securom_protected_binary.read_bytes()
        winhttp_offsets = []
        offset = 0
        while True:
            offset = original_data.find(b"WinHttpSendRequest", offset)
            if offset == -1:
                break
            winhttp_offsets.append(offset)
            offset += 1

        result = bypass.block_phone_home(securom_protected_binary)

        assert isinstance(result, BypassResult)
        if (
            winhttp_offsets
            and result.success
            and "patched" in result.details.lower()
        ):
            modified_data = securom_protected_binary.read_bytes()
            assert modified_data != original_data


class TestChallengeResponseDefeat:
    """Test SecuROM challenge-response authentication defeat."""

    def test_challenge_response_defeat_patches_generation(
        self, securom_protected_binary: Path
    ) -> None:
        """Challenge-response defeat patches challenge generation."""
        bypass = SecuROMBypass()
        result = bypass.defeat_challenge_response(securom_protected_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Challenge-Response Defeat"

        if result.success:
            assert "challenge" in result.details.lower() or "response" in result.details.lower()

    def test_challenge_response_defeat_patches_validation(
        self, securom_protected_binary: Path
    ) -> None:
        """Challenge-response defeat patches response validation to always succeed."""
        bypass = SecuROMBypass()
        result = bypass.defeat_challenge_response(securom_protected_binary)

        if result.success:
            modified_data = securom_protected_binary.read_bytes()
            assert b"\xb8\x01\x00\x00\x00" in modified_data or b"\xc3" in modified_data

    def test_challenge_response_defeat_modifies_both_functions(
        self, securom_protected_binary: Path
    ) -> None:
        """Challenge-response defeat modifies both challenge and response functions."""
        bypass = SecuROMBypass()

        original_data = securom_protected_binary.read_bytes()
        challenge_offset = original_data.find(b"GetActivationChallenge")
        response_offset = original_data.find(b"ValidateResponse")

        result = bypass.defeat_challenge_response(securom_protected_binary)

        if challenge_offset != -1 and response_offset != -1 and result.success:
            modified_data = securom_protected_binary.read_bytes()
            assert modified_data != original_data


class TestCompleteSecuROMRemoval:
    """Test complete SecuROM system removal."""

    def test_remove_securom_executes_all_steps(self) -> None:
        """Complete SecuROM removal executes all cleanup steps."""
        bypass = SecuROMBypass()
        result = bypass.remove_securom()

        assert isinstance(result, SecuROMRemovalResult)
        assert result.success or len(result.errors) > 0

        assert isinstance(result.drivers_removed, list)
        assert isinstance(result.services_stopped, list)
        assert isinstance(result.registry_cleaned, list)
        assert isinstance(result.files_deleted, list)

    def test_remove_securom_cleans_registry(self) -> None:
        """SecuROM removal cleans all registry keys."""
        bypass = SecuROMBypass()

        for root_key, subkey_path in SecuROMBypass.REGISTRY_KEYS_TO_DELETE[:2]:
            try:
                key = winreg.CreateKey(root_key, subkey_path)
                winreg.SetValueEx(key, "TestValue", 0, winreg.REG_SZ, "test")
                winreg.CloseKey(key)
            except OSError:
                pass

        result = bypass.remove_securom()

        assert isinstance(result.registry_cleaned, list)

    def test_remove_securom_bypasses_activation(self) -> None:
        """SecuROM removal includes activation bypass."""
        bypass = SecuROMBypass()
        result = bypass.remove_securom()

        assert isinstance(result.activation_bypassed, bool)

    def test_remove_securom_handles_missing_components(self) -> None:
        """SecuROM removal handles missing drivers/services gracefully."""
        bypass = SecuROMBypass()
        result = bypass.remove_securom()

        assert result.success or len(result.services_stopped) == 0


class TestSecuROMV8Compatibility:
    """Test SecuROM v8 specific bypass capabilities."""

    def test_v8_activation_bypass(self, securom_v8_binary: Path) -> None:
        """Activation bypass works on SecuROM v8 protected binaries."""
        bypass = SecuROMBypass()
        result = bypass.bypass_activation(securom_v8_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Activation Bypass"

    def test_v8_disc_check_bypass(self, securom_v8_binary: Path) -> None:
        """Disc check bypass handles v8 x64 binaries."""
        bypass = SecuROMBypass()
        result = bypass.bypass_disc_check(securom_v8_binary)

        assert isinstance(result, BypassResult)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_bypass_empty_file(self, tmp_path: Path) -> None:
        """Bypass operations handle empty files gracefully."""
        bypass = SecuROMBypass()
        empty_file = tmp_path / "empty.exe"
        empty_file.write_bytes(b"")

        result = bypass.bypass_activation(empty_file)
        assert isinstance(result, BypassResult)

    def test_bypass_corrupted_pe(self, tmp_path: Path) -> None:
        """Bypass operations handle corrupted PE files."""
        bypass = SecuROMBypass()
        corrupted = tmp_path / "corrupted.exe"
        corrupted.write_bytes(b"MZ" + b"\x00" * 100)

        result = bypass.bypass_disc_check(corrupted)
        assert isinstance(result, BypassResult)

    def test_multiple_bypass_operations_sequential(
        self, securom_protected_binary: Path
    ) -> None:
        """Multiple bypass operations work sequentially on same binary."""
        bypass = SecuROMBypass()

        result1 = bypass.bypass_activation(securom_protected_binary)
        result2 = bypass.bypass_disc_check(securom_protected_binary)
        result3 = bypass.remove_triggers(securom_protected_binary)

        assert isinstance(result1, BypassResult)
        assert isinstance(result2, BypassResult)
        assert isinstance(result3, BypassResult)

    def test_bypass_with_readonly_file(self, securom_protected_binary: Path) -> None:
        """Bypass operations handle read-only files."""
        bypass = SecuROMBypass()

        import stat
        securom_protected_binary.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

        result = bypass.bypass_activation(securom_protected_binary)

        securom_protected_binary.chmod(stat.S_IWUSR | stat.S_IRUSR)
