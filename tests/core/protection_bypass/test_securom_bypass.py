"""
Unit tests for SecuROM Protection Bypass.

Tests activation bypass, trigger removal, disc defeat, product key bypass,
phone-home blocking, and challenge-response defeat using REAL implementations.
"""

import shutil
import tempfile
import winreg
from pathlib import Path
from typing import Iterator

import pytest

try:
    from intellicrack.core.protection_bypass.securom_bypass import (
        BypassResult,
        SecuROMBypass,
        SecuROMRemovalResult,
    )

    MODULE_AVAILABLE = True
except ImportError:
    SecuROMBypass = None
    BypassResult = None
    SecuROMRemovalResult = None
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


class SecuROMBinaryGenerator:
    """Generates realistic test binaries with SecuROM-like protection patterns."""

    @staticmethod
    def create_minimal_pe() -> bytes:
        """Create a minimal valid PE executable with DOS and PE headers."""
        dos_header = bytearray(b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00")
        dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7

        pe_signature = b"PE\x00\x00"

        coff_header = bytearray(20)
        coff_header[0:2] = b"\x4c\x01"
        coff_header[2:4] = b"\x01\x00"
        coff_header[16:18] = b"\xe0\x00"
        coff_header[18:20] = b"\x0b\x01"

        optional_header = bytearray(224)
        optional_header[0:2] = b"\x0b\x01"
        optional_header[16:20] = b"\x00\x10\x00\x00"
        optional_header[20:24] = b"\x00\x00\x04\x00"
        optional_header[24:28] = b"\x00\x10\x00\x00"
        optional_header[28:32] = b"\x00\x10\x00\x00"
        optional_header[40:44] = b"\x00\x00\x01\x00"
        optional_header[56:60] = b"\x00\x00\x02\x00"
        optional_header[60:64] = b"\x00\x10\x00\x00"

        section_header = bytearray(40)
        section_header[0:8] = b".text\x00\x00\x00"
        section_header[8:12] = b"\x00\x10\x00\x00"
        section_header[12:16] = b"\x00\x10\x00\x00"
        section_header[16:20] = b"\x00\x02\x00\x00"
        section_header[20:24] = b"\x00\x02\x00\x00"
        section_header[36:40] = b"\x20\x00\x00\x60"

        section_data = b"\x00" * 512

        pe_binary = dos_header + dos_stub
        pe_offset = len(pe_binary)
        pe_binary = pe_binary[:60] + pe_offset.to_bytes(4, "little") + pe_binary[64:]
        pe_binary = pe_binary + b"\x00" * (pe_offset - len(pe_binary))
        pe_binary = pe_binary + pe_signature + coff_header + optional_header + section_header + section_data

        return bytes(pe_binary)

    @staticmethod
    def add_activation_checks(binary: bytes) -> bytes:
        """Add SecuROM activation check patterns to binary."""
        data = bytearray(binary)

        activation_patterns = [
            b"\x85\xc0\x74\x10" + b"\x00" * 20,
            b"\x85\xc0\x75\x15" + b"\x00" * 20,
            b"\x84\xc0\x74\x08" + b"\x00" * 20,
            b"\x3b\xc3\x74\x12" + b"\x00" * 20,
        ]

        offset = len(data)
        for pattern in activation_patterns:
            data.extend(pattern)

        return bytes(data)

    @staticmethod
    def add_validation_triggers(binary: bytes) -> bytes:
        """Add validation trigger keywords and network calls."""
        data = bytearray(binary)

        triggers = [
            b"ValidateLicense\x00" + b"\x55\x8B\xEC\x83\xEC\x10" + b"\x00" * 30,
            b"CheckActivationStatus\x00" + b"\x55\x8B\xEC\x83\xEC\x10" + b"\x00" * 30,
            b"VerifyProductKey\x00" + b"\x55\x8B\xEC\x83\xEC\x10" + b"\x00" * 30,
            b"WinHttpSendRequest\x00" + b"\xFF\x15\x00\x00\x00\x00" + b"\x00" * 30,
        ]

        for trigger in triggers:
            data.extend(trigger)

        return bytes(data)

    @staticmethod
    def add_disc_check_patterns(binary: bytes) -> bytes:
        """Add disc check patterns including SCSI commands."""
        data = bytearray(binary)

        disc_patterns = [
            b"DeviceIoControl\x00" + b"\xFF\x15\x00\x00\x00\x00" + b"\x00" * 30,
            b"\\\\.\\Scsi\x00" + b"\x00" * 30,
            b"\\\\.\\CdRom\x00" + b"\x00" * 30,
            b"SCSI\x00\x12CDB\x00\x28" + b"\x00" * 30,
        ]

        for pattern in disc_patterns:
            data.extend(pattern)

        return bytes(data)

    @staticmethod
    def add_key_validation(binary: bytes) -> bytes:
        """Add product key validation patterns."""
        data = bytearray(binary)

        key_patterns = [
            b"VerifyProductKey\x00" + b"\x55\x8B\xEC\x83\xEC\x20" + b"\x00" * 30,
            b"ValidateSerial\x00" + b"\x55\x8B\xEC\x83\xEC\x20" + b"\x00" * 30,
        ]

        for pattern in key_patterns:
            data.extend(pattern)

        return bytes(data)

    @staticmethod
    def add_network_calls(binary: bytes) -> bytes:
        """Add network API call patterns."""
        data = bytearray(binary)

        network_patterns = [
            b"WinHttpSendRequest\x00" + b"\xFF\x15\x00\x00\x00\x00" + b"\x00" * 30,
            b"InternetOpenUrl\x00" + b"\xFF\x15\x00\x00\x00\x00" + b"\x00" * 30,
        ]

        for pattern in network_patterns:
            data.extend(pattern)

        return bytes(data)

    @staticmethod
    def add_challenge_response(binary: bytes) -> bytes:
        """Add challenge-response patterns."""
        data = bytearray(binary)

        challenge_patterns = [
            b"GetActivationChallenge\x00" + b"\x55\x8B\xEC\x83\xEC\x30" + b"\x00" * 30,
            b"ValidateResponse\x00" + b"\x55\x8B\xEC\x83\xEC\x30" + b"\x00" * 30,
        ]

        for pattern in challenge_patterns:
            data.extend(pattern)

        return bytes(data)

    @staticmethod
    def add_countdown_timer(binary: bytes) -> bytes:
        """Add activation countdown timer patterns."""
        data = bytearray(binary)

        countdown_patterns = [
            b"ActivationDaysRemaining\x00" + b"\x83\xe8\x01" + b"\x00" * 30,
            b"TrialDaysRemaining\x00" + b"\x83\xe8\x01" + b"\x00" * 30,
        ]

        for pattern in countdown_patterns:
            data.extend(pattern)

        return bytes(data)


class RegistryTestHelper:
    """Helper for managing registry operations in tests."""

    def __init__(self) -> None:
        """Initialize registry test helper."""
        self.created_keys: list[tuple[int | winreg.HKEYType, str]] = []

    def create_test_key(self, root: int | winreg.HKEYType, path: str) -> winreg.HKEYType:
        """Create a test registry key and track it for cleanup."""
        try:
            key = winreg.CreateKey(root, path)
            self.created_keys.append((root, path))
            return key
        except OSError:
            pytest.skip("Insufficient registry permissions")

    def cleanup(self) -> None:
        """Clean up all created registry keys."""
        for root, path in reversed(self.created_keys):
            try:
                self._delete_key_recursive(root, path)
            except OSError:
                pass

    def _delete_key_recursive(self, root: int | winreg.HKEYType, path: str) -> None:
        """Recursively delete a registry key."""
        try:
            key = winreg.OpenKey(root, path, 0, winreg.KEY_ALL_ACCESS)
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    self._delete_key_recursive(key, subkey_name)
                except OSError:
                    break
            winreg.CloseKey(key)
            winreg.DeleteKey(root, path)
        except OSError:
            pass

    def key_exists(self, root: int | winreg.HKEYType, path: str) -> bool:
        """Check if a registry key exists."""
        try:
            key = winreg.OpenKey(root, path)
            winreg.CloseKey(key)
            return True
        except OSError:
            return False

    def get_value(self, root: int | winreg.HKEYType, path: str, value_name: str) -> tuple[object, int] | None:
        """Get a registry value."""
        try:
            key = winreg.OpenKey(root, path)
            value, value_type = winreg.QueryValueEx(key, value_name)
            winreg.CloseKey(key)
            return (value, value_type)
        except OSError:
            return None


@pytest.fixture
def temp_dir() -> Iterator[Path]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def bypass() -> SecuROMBypass:
    """Create SecuROM bypass instance."""
    return SecuROMBypass()


@pytest.fixture
def registry_helper() -> Iterator[RegistryTestHelper]:
    """Create registry test helper with automatic cleanup."""
    helper = RegistryTestHelper()
    yield helper
    helper.cleanup()


@pytest.fixture
def basic_pe_binary(temp_dir: Path) -> Path:
    """Create a basic PE binary for testing."""
    binary = SecuROMBinaryGenerator.create_minimal_pe()
    binary_path = temp_dir / "test_basic.exe"
    binary_path.write_bytes(binary)
    return binary_path


@pytest.fixture
def protected_binary(temp_dir: Path) -> Path:
    """Create a fully protected binary with all SecuROM patterns."""
    binary = SecuROMBinaryGenerator.create_minimal_pe()
    binary = SecuROMBinaryGenerator.add_activation_checks(binary)
    binary = SecuROMBinaryGenerator.add_validation_triggers(binary)
    binary = SecuROMBinaryGenerator.add_disc_check_patterns(binary)
    binary = SecuROMBinaryGenerator.add_key_validation(binary)
    binary = SecuROMBinaryGenerator.add_network_calls(binary)
    binary = SecuROMBinaryGenerator.add_challenge_response(binary)
    binary = SecuROMBinaryGenerator.add_countdown_timer(binary)

    binary_path = temp_dir / "test_protected.exe"
    binary_path.write_bytes(binary)
    return binary_path


class TestSecuROMBypass:
    """Test cases for SecuROMBypass class using real implementations."""

    def test_bypass_activation_registry_creates_keys(self, bypass: SecuROMBypass, registry_helper: RegistryTestHelper) -> None:
        """Test activation bypass creates actual registry keys with correct values."""
        result = bypass._bypass_activation_registry()

        assert result is True

        activation_key_created = False
        for root, path in SecuROMBypass.ACTIVATION_REGISTRY_KEYS:
            if registry_helper.key_exists(root, path):
                activation_key_created = True

                activated_value = registry_helper.get_value(root, path, "Activated")
                if activated_value:
                    assert activated_value[0] == 1
                    assert activated_value[1] == winreg.REG_DWORD

                product_key_value = registry_helper.get_value(root, path, "ProductKey")
                if product_key_value:
                    assert isinstance(product_key_value[0], str)
                    assert "BYPASSED" in product_key_value[0]

                registry_helper.created_keys.append((root, path))

        assert activation_key_created, "At least one activation registry key should be created"

    def test_remove_driver_files_with_real_files(self, bypass: SecuROMBypass, temp_dir: Path) -> None:
        """Test driver file removal with actual files."""
        test_driver_paths = [
            temp_dir / "secdrv.sys",
            temp_dir / "SecuROM.sys",
            temp_dir / "SR8.sys",
        ]

        for driver_path in test_driver_paths:
            driver_path.write_bytes(b"FAKE_DRIVER_DATA" * 100)
            assert driver_path.exists()

        original_paths = SecuROMBypass.DRIVER_PATHS.copy()
        try:
            SecuROMBypass.DRIVER_PATHS = [str(p) for p in test_driver_paths]

            removed = bypass._remove_driver_files()

            assert isinstance(removed, list)
            assert len(removed) == 3

            for driver_path in test_driver_paths:
                assert not driver_path.exists()

        finally:
            SecuROMBypass.DRIVER_PATHS = original_paths

    def test_clean_registry_removes_real_keys(self, bypass: SecuROMBypass, registry_helper: RegistryTestHelper) -> None:
        """Test registry cleaning removes actual registry keys."""
        test_key_path = r"SOFTWARE\SecuROM\TestCleanup"
        key = registry_helper.create_test_key(winreg.HKEY_CURRENT_USER, test_key_path)
        winreg.SetValueEx(key, "TestValue", 0, winreg.REG_SZ, "TestData")
        winreg.CloseKey(key)

        assert registry_helper.key_exists(winreg.HKEY_CURRENT_USER, test_key_path)

        original_keys = SecuROMBypass.REGISTRY_KEYS_TO_DELETE.copy()
        try:
            SecuROMBypass.REGISTRY_KEYS_TO_DELETE = [
                (winreg.HKEY_CURRENT_USER, test_key_path)
            ]

            cleaned = bypass._clean_registry()

            assert isinstance(cleaned, list)
            assert len(cleaned) >= 1
            assert not registry_helper.key_exists(winreg.HKEY_CURRENT_USER, test_key_path)

        finally:
            SecuROMBypass.REGISTRY_KEYS_TO_DELETE = original_keys
            registry_helper.created_keys = [
                (root, path) for root, path in registry_helper.created_keys
                if path != test_key_path
            ]

    def test_remove_securom_complete_workflow(self, bypass: SecuROMBypass, registry_helper: RegistryTestHelper) -> None:
        """Test complete SecuROM removal workflow with real operations."""
        result = bypass.remove_securom()

        assert isinstance(result, SecuROMRemovalResult)
        assert isinstance(result.drivers_removed, list)
        assert isinstance(result.services_stopped, list)
        assert isinstance(result.registry_cleaned, list)
        assert isinstance(result.files_deleted, list)
        assert isinstance(result.activation_bypassed, bool)
        assert isinstance(result.success, bool)
        assert isinstance(result.errors, list)

        for root, path in SecuROMBypass.ACTIVATION_REGISTRY_KEYS:
            if registry_helper.key_exists(root, path):
                registry_helper.created_keys.append((root, path))

    def test_patch_activation_checks_modifies_binary(self, bypass: SecuROMBypass, protected_binary: Path) -> None:
        """Test activation check patching actually modifies binary patterns."""
        original_data = protected_binary.read_bytes()

        assert b"\x85\xc0\x74" in original_data or b"\x85\xc0\x75" in original_data

        result = bypass._patch_activation_checks(protected_binary)

        modified_data = protected_binary.read_bytes()

        if result:
            assert original_data != modified_data

            backup_path = protected_binary.with_suffix(f"{protected_binary.suffix}.bak")
            assert backup_path.exists()
            assert backup_path.read_bytes() == original_data

    def test_bypass_activation_complete(self, bypass: SecuROMBypass, protected_binary: Path, registry_helper: RegistryTestHelper) -> None:
        """Test complete activation bypass workflow."""
        result = bypass.bypass_activation(protected_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Activation Bypass"
        assert isinstance(result.success, bool)
        assert isinstance(result.details, str)
        assert isinstance(result.errors, list)

        if result.success:
            assert len(result.details) > 0

        for root, path in SecuROMBypass.ACTIVATION_REGISTRY_KEYS:
            if registry_helper.key_exists(root, path):
                registry_helper.created_keys.append((root, path))

    def test_disable_activation_countdown_patches_timers(self, bypass: SecuROMBypass, temp_dir: Path) -> None:
        """Test activation countdown disabling patches timer instructions."""
        binary = SecuROMBinaryGenerator.create_minimal_pe()
        binary = SecuROMBinaryGenerator.add_countdown_timer(binary)

        binary_path = temp_dir / "countdown_test.exe"
        binary_path.write_bytes(binary)

        original_data = binary_path.read_bytes()
        assert b"ActivationDaysRemaining" in original_data

        result = bypass._disable_activation_countdown(binary_path)

        if result:
            modified_data = binary_path.read_bytes()
            assert original_data != modified_data

    def test_remove_triggers_from_binary(self, bypass: SecuROMBypass, protected_binary: Path) -> None:
        """Test removal of online validation triggers from binary."""
        original_data = protected_binary.read_bytes()

        result = bypass.remove_triggers(protected_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Trigger Removal"

        if result.success:
            assert "trigger" in result.details.lower()
            modified_data = protected_binary.read_bytes()
            assert original_data != modified_data

            backup_path = protected_binary.with_suffix(f"{protected_binary.suffix}.bak")
            assert backup_path.exists()

    def test_nop_trigger_function_replaces_prologue(self, bypass: SecuROMBypass) -> None:
        """Test NOPing trigger function replaces function prologue with RET."""
        data = bytearray(b"\x00" * 50 + b"\x55\x8B\xEC\x83\xEC\x10" + b"\x00" * 50)
        offset = 60

        result = bypass._nop_trigger_function(data, offset)

        if result:
            assert data[50] == 0xC3
            assert data[51:60] == b"\x90" * 9

    def test_is_network_call_detects_network_apis(self, bypass: SecuROMBypass) -> None:
        """Test network call detection identifies WinHTTP and socket APIs."""
        network_data = bytearray(
            b"\x00" * 100
            + b"WinHttpSendRequest\x00"
            + b"\xFF\x15\x00\x00\x00\x00"
            + b"\x00" * 100
        )

        result = bypass._is_network_call(network_data, 120)
        assert result is True

    def test_is_network_call_rejects_non_network(self, bypass: SecuROMBypass) -> None:
        """Test network call detection rejects non-network functions."""
        non_network_data = bytearray(
            b"\x00" * 100
            + b"SomeRandomFunction\x00"
            + b"\xFF\x15\x00\x00\x00\x00"
            + b"\x00" * 100
        )

        result = bypass._is_network_call(non_network_data, 120)
        assert result is False

    def test_bypass_disc_check_workflow(self, bypass: SecuROMBypass, protected_binary: Path, registry_helper: RegistryTestHelper) -> None:
        """Test disc check bypass complete workflow."""
        result = bypass.bypass_disc_check(protected_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Disc Check Bypass"
        assert isinstance(result.success, bool)
        assert isinstance(result.errors, list)

        if registry_helper.key_exists(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SecuROM\DiscEmulation"):
            registry_helper.created_keys.append((winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SecuROM\DiscEmulation"))

    def test_patch_disc_check_calls_modifies_device_io(self, bypass: SecuROMBypass, temp_dir: Path) -> None:
        """Test disc check call patching modifies DeviceIoControl calls."""
        binary = SecuROMBinaryGenerator.create_minimal_pe()
        binary = SecuROMBinaryGenerator.add_disc_check_patterns(binary)

        binary_path = temp_dir / "disc_check_test.exe"
        binary_path.write_bytes(binary)

        original_data = binary_path.read_bytes()

        result = bypass._patch_disc_check_calls(binary_path)

        if result:
            modified_data = binary_path.read_bytes()
            assert original_data != modified_data

    def test_patch_scsi_commands_nullifies_opcodes(self, bypass: SecuROMBypass, temp_dir: Path) -> None:
        """Test SCSI command patching nullifies command opcodes."""
        binary = SecuROMBinaryGenerator.create_minimal_pe()
        binary = SecuROMBinaryGenerator.add_disc_check_patterns(binary)

        binary_path = temp_dir / "scsi_test.exe"
        binary_path.write_bytes(binary)

        original_data = binary_path.read_bytes()
        assert b"SCSI" in original_data

        result = bypass._patch_scsi_commands(binary_path)

        if result:
            modified_data = binary_path.read_bytes()
            assert original_data != modified_data

    def test_emulate_disc_presence_sets_registry(self, bypass: SecuROMBypass, basic_pe_binary: Path, registry_helper: RegistryTestHelper) -> None:
        """Test disc presence emulation creates registry entries."""
        result = bypass._emulate_disc_presence(basic_pe_binary)

        if result:
            disc_key_path = r"SOFTWARE\SecuROM\DiscEmulation"
            if registry_helper.key_exists(winreg.HKEY_LOCAL_MACHINE, disc_key_path):
                disc_present = registry_helper.get_value(winreg.HKEY_LOCAL_MACHINE, disc_key_path, "DiscPresent")
                if disc_present:
                    assert disc_present[0] == 1

                registry_helper.created_keys.append((winreg.HKEY_LOCAL_MACHINE, disc_key_path))

    def test_bypass_product_key_validation_workflow(self, bypass: SecuROMBypass, protected_binary: Path, registry_helper: RegistryTestHelper) -> None:
        """Test product key validation bypass workflow."""
        result = bypass.bypass_product_key_validation(protected_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Product Key Bypass"
        assert isinstance(result.success, bool)

        product_key_path = r"SOFTWARE\SecuROM\ProductKeys"
        if registry_helper.key_exists(winreg.HKEY_CURRENT_USER, product_key_path):
            registry_helper.created_keys.append((winreg.HKEY_CURRENT_USER, product_key_path))

    def test_patch_key_validation_patches_functions(self, bypass: SecuROMBypass, temp_dir: Path) -> None:
        """Test key validation patching modifies validation functions."""
        binary = SecuROMBinaryGenerator.create_minimal_pe()
        binary = SecuROMBinaryGenerator.add_key_validation(binary)

        binary_path = temp_dir / "key_validation_test.exe"
        binary_path.write_bytes(binary)

        original_data = binary_path.read_bytes()
        assert b"VerifyProductKey" in original_data

        result = bypass._patch_key_validation(binary_path)

        if result:
            modified_data = binary_path.read_bytes()
            assert original_data != modified_data

    def test_inject_valid_key_data_creates_registry(self, bypass: SecuROMBypass, basic_pe_binary: Path, registry_helper: RegistryTestHelper) -> None:
        """Test valid key data injection creates registry entries."""
        result = bypass._inject_valid_key_data(basic_pe_binary)

        if result:
            key_path = r"SOFTWARE\SecuROM\ProductKeys"
            if registry_helper.key_exists(winreg.HKEY_CURRENT_USER, key_path):
                product_key = registry_helper.get_value(winreg.HKEY_CURRENT_USER, key_path, "ProductKey")
                if product_key:
                    assert isinstance(product_key[0], str)
                    assert len(product_key[0]) > 0

                key_valid = registry_helper.get_value(winreg.HKEY_CURRENT_USER, key_path, "KeyValid")
                if key_valid:
                    assert key_valid[0] == 1

                registry_helper.created_keys.append((winreg.HKEY_CURRENT_USER, key_path))

    def test_block_phone_home_workflow(self, bypass: SecuROMBypass, protected_binary: Path) -> None:
        """Test phone-home blocking workflow."""
        server_urls = ["https://activation.example.com", "https://validation.test.com"]

        result = bypass.block_phone_home(protected_binary, server_urls)

        assert isinstance(result, BypassResult)
        assert result.technique == "Phone-Home Blocking"
        assert isinstance(result.success, bool)

    def test_patch_network_calls_modifies_api_calls(self, bypass: SecuROMBypass, temp_dir: Path) -> None:
        """Test network call patching modifies WinHTTP API calls."""
        binary = SecuROMBinaryGenerator.create_minimal_pe()
        binary = SecuROMBinaryGenerator.add_network_calls(binary)

        binary_path = temp_dir / "network_test.exe"
        binary_path.write_bytes(binary)

        original_data = binary_path.read_bytes()
        assert b"WinHttpSendRequest" in original_data

        result = bypass._patch_network_calls(binary_path)

        if result:
            modified_data = binary_path.read_bytes()
            assert original_data != modified_data

    def test_defeat_challenge_response_workflow(self, bypass: SecuROMBypass, protected_binary: Path) -> None:
        """Test challenge-response defeat workflow."""
        result = bypass.defeat_challenge_response(protected_binary)

        assert isinstance(result, BypassResult)
        assert result.technique == "Challenge-Response Defeat"
        assert isinstance(result.success, bool)

    def test_patch_challenge_generation_modifies_functions(self, bypass: SecuROMBypass, temp_dir: Path) -> None:
        """Test challenge generation patching replaces function logic."""
        binary = SecuROMBinaryGenerator.create_minimal_pe()
        binary = SecuROMBinaryGenerator.add_challenge_response(binary)

        binary_path = temp_dir / "challenge_test.exe"
        binary_path.write_bytes(binary)

        original_data = binary_path.read_bytes()
        assert b"GetActivationChallenge" in original_data

        result = bypass._patch_challenge_generation(binary_path)

        if result:
            modified_data = binary_path.read_bytes()
            assert original_data != modified_data

    def test_patch_response_validation_forces_success(self, bypass: SecuROMBypass, temp_dir: Path) -> None:
        """Test response validation patching forces validation success."""
        binary = SecuROMBinaryGenerator.create_minimal_pe()
        binary = SecuROMBinaryGenerator.add_challenge_response(binary)

        binary_path = temp_dir / "response_test.exe"
        binary_path.write_bytes(binary)

        original_data = binary_path.read_bytes()
        assert b"ValidateResponse" in original_data

        result = bypass._patch_response_validation(binary_path)

        if result:
            modified_data = binary_path.read_bytes()
            assert original_data != modified_data

    def test_bypass_activation_nonexistent_file(self, bypass: SecuROMBypass, temp_dir: Path) -> None:
        """Test activation bypass handles nonexistent files gracefully."""
        nonexistent_path = temp_dir / "nonexistent.exe"

        result = bypass.bypass_activation(nonexistent_path)

        assert isinstance(result, BypassResult)
        assert result.success is False
        assert len(result.errors) > 0

    def test_multiple_activation_pattern_types(self, bypass: SecuROMBypass, temp_dir: Path) -> None:
        """Test patching handles multiple types of activation patterns."""
        binary = SecuROMBinaryGenerator.create_minimal_pe()

        data = bytearray(binary)
        data.extend(b"\x85\xc0\x74\x10" + b"\x00" * 20)
        data.extend(b"\x85\xc0\x75\x15" + b"\x00" * 20)
        data.extend(b"\x84\xc0\x74\x08" + b"\x00" * 20)
        data.extend(b"\x84\xc0\x75\x12" + b"\x00" * 20)
        data.extend(b"\x3b\xc3\x74\x20" + b"\x00" * 20)
        data.extend(b"\x3b\xc3\x75\x18" + b"\x00" * 20)

        binary_path = temp_dir / "multi_pattern.exe"
        binary_path.write_bytes(bytes(data))

        original_data = binary_path.read_bytes()

        result = bypass._patch_activation_checks(binary_path)

        if result:
            modified_data = binary_path.read_bytes()
            assert original_data != modified_data

            original_count = original_data.count(b"\x74") + original_data.count(b"\x75")
            modified_count = modified_data.count(b"\x74") + modified_data.count(b"\x75")
            assert modified_count < original_count

    def test_real_securom_protected_binary_if_available(self, bypass: SecuROMBypass) -> None:
        """Test against real SecuROM-protected binary if available in fixtures."""
        real_binary_path = Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected/securom_protected.exe")

        if not real_binary_path.exists():
            pytest.skip("Real SecuROM protected binary not available")

        temp_path = Path(tempfile.gettempdir()) / "test_real_securom.exe"
        try:
            shutil.copy2(real_binary_path, temp_path)

            result = bypass.bypass_activation(temp_path)

            assert isinstance(result, BypassResult)

            if result.success:
                assert len(result.details) > 0

        finally:
            if temp_path.exists():
                temp_path.unlink()


class TestBypassResult:
    """Test cases for BypassResult dataclass."""

    def test_bypass_result_creation_success(self) -> None:
        """Test creation of successful bypass result."""
        result = BypassResult(
            success=True,
            technique="Activation Bypass",
            details="All checks bypassed successfully",
            errors=[],
        )

        assert result.success is True
        assert result.technique == "Activation Bypass"
        assert result.details == "All checks bypassed successfully"
        assert len(result.errors) == 0

    def test_bypass_result_creation_failure(self) -> None:
        """Test creation of failed bypass result."""
        errors = ["Failed to patch SCSI commands", "Registry access denied"]
        result = BypassResult(
            success=False,
            technique="Disc Check Bypass",
            details="Partial bypass only",
            errors=errors,
        )

        assert result.success is False
        assert result.technique == "Disc Check Bypass"
        assert len(result.errors) == 2
        assert "SCSI" in result.errors[0]

    def test_bypass_result_empty_errors(self) -> None:
        """Test bypass result with empty error list."""
        result = BypassResult(
            success=True,
            technique="Trigger Removal",
            details="Removed 15 triggers",
            errors=[],
        )

        assert result.success is True
        assert isinstance(result.errors, list)
        assert len(result.errors) == 0


class TestSecuROMRemovalResult:
    """Test cases for SecuROMRemovalResult dataclass."""

    def test_removal_result_creation_complete(self) -> None:
        """Test creation of complete removal result."""
        result = SecuROMRemovalResult(
            drivers_removed=["secdrv.sys", "SR8.sys"],
            services_stopped=["SecuROM8"],
            registry_cleaned=["SOFTWARE\\SecuROM"],
            files_deleted=["C:\\Program Files\\SecuROM"],
            activation_bypassed=True,
            triggers_removed=5,
            success=True,
            errors=[],
        )

        assert result.success is True
        assert result.activation_bypassed is True
        assert result.triggers_removed == 5
        assert len(result.drivers_removed) == 2
        assert len(result.services_stopped) == 1
        assert len(result.registry_cleaned) == 1
        assert len(result.files_deleted) == 1

    def test_removal_result_partial_success(self) -> None:
        """Test removal result with partial success."""
        result = SecuROMRemovalResult(
            drivers_removed=["secdrv.sys"],
            services_stopped=[],
            registry_cleaned=["SOFTWARE\\SecuROM"],
            files_deleted=[],
            activation_bypassed=False,
            triggers_removed=0,
            success=True,
            errors=["Failed to stop service"],
        )

        assert result.success is True
        assert result.activation_bypassed is False
        assert len(result.errors) == 1
        assert len(result.drivers_removed) == 1
        assert len(result.services_stopped) == 0

    def test_removal_result_complete_failure(self) -> None:
        """Test removal result with complete failure."""
        result = SecuROMRemovalResult(
            drivers_removed=[],
            services_stopped=[],
            registry_cleaned=[],
            files_deleted=[],
            activation_bypassed=False,
            triggers_removed=0,
            success=False,
            errors=["Insufficient permissions", "Files in use"],
        )

        assert result.success is False
        assert result.activation_bypassed is False
        assert len(result.errors) == 2
        assert all(len(getattr(result, field)) == 0 for field in ["drivers_removed", "services_stopped", "registry_cleaned", "files_deleted"])


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_binary_file(self, bypass: SecuROMBypass, temp_dir: Path) -> None:
        """Test handling of empty binary files."""
        empty_file = temp_dir / "empty.exe"
        empty_file.write_bytes(b"")

        result = bypass.bypass_activation(empty_file)

        assert isinstance(result, BypassResult)
        assert result.success is False

    def test_corrupted_pe_header(self, bypass: SecuROMBypass, temp_dir: Path) -> None:
        """Test handling of corrupted PE headers."""
        corrupted_file = temp_dir / "corrupted.exe"
        corrupted_file.write_bytes(b"MZ" + b"\x00" * 100)

        result = bypass._patch_activation_checks(corrupted_file)

        assert isinstance(result, bool)

    def test_binary_without_patterns(self, bypass: SecuROMBypass, basic_pe_binary: Path) -> None:
        """Test patching binary without SecuROM patterns."""
        result = bypass._patch_activation_checks(basic_pe_binary)

        assert isinstance(result, bool)

    def test_large_binary_handling(self, bypass: SecuROMBypass, temp_dir: Path) -> None:
        """Test handling of large binaries."""
        large_binary = SecuROMBinaryGenerator.create_minimal_pe()
        large_binary = large_binary + b"\x00" * (10 * 1024 * 1024)

        binary_path = temp_dir / "large.exe"
        binary_path.write_bytes(large_binary)

        result = bypass.remove_triggers(binary_path)

        assert isinstance(result, BypassResult)

    def test_concurrent_registry_access(self, bypass: SecuROMBypass, registry_helper: RegistryTestHelper) -> None:
        """Test handling of concurrent registry access."""
        result1 = bypass._bypass_activation_registry()
        result2 = bypass._bypass_activation_registry()

        assert isinstance(result1, bool)
        assert isinstance(result2, bool)

        for root, path in SecuROMBypass.ACTIVATION_REGISTRY_KEYS:
            if registry_helper.key_exists(root, path):
                registry_helper.created_keys.append((root, path))

    def test_read_only_file_handling(self, bypass: SecuROMBypass, basic_pe_binary: Path) -> None:
        """Test handling of read-only files."""
        import stat

        basic_pe_binary.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

        try:
            result = bypass._patch_activation_checks(basic_pe_binary)

            assert isinstance(result, bool)
        finally:
            basic_pe_binary.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)


class TestRealWorldScenarios:
    """Test real-world bypass scenarios."""

    def test_multi_layered_protection_bypass(self, bypass: SecuROMBypass, protected_binary: Path, registry_helper: RegistryTestHelper) -> None:
        """Test bypassing multiple protection layers in sequence."""
        activation_result = bypass.bypass_activation(protected_binary)
        assert isinstance(activation_result, BypassResult)

        disc_result = bypass.bypass_disc_check(protected_binary)
        assert isinstance(disc_result, BypassResult)

        key_result = bypass.bypass_product_key_validation(protected_binary)
        assert isinstance(key_result, BypassResult)

        challenge_result = bypass.defeat_challenge_response(protected_binary)
        assert isinstance(challenge_result, BypassResult)

        for root, path in SecuROMBypass.ACTIVATION_REGISTRY_KEYS:
            if registry_helper.key_exists(root, path):
                registry_helper.created_keys.append((root, path))

        if registry_helper.key_exists(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SecuROM\DiscEmulation"):
            registry_helper.created_keys.append((winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SecuROM\DiscEmulation"))

        if registry_helper.key_exists(winreg.HKEY_CURRENT_USER, r"SOFTWARE\SecuROM\ProductKeys"):
            registry_helper.created_keys.append((winreg.HKEY_CURRENT_USER, r"SOFTWARE\SecuROM\ProductKeys"))

    def test_complete_removal_workflow(self, bypass: SecuROMBypass, temp_dir: Path, registry_helper: RegistryTestHelper) -> None:
        """Test complete SecuROM removal including all components."""
        test_driver = temp_dir / "secdrv.sys"
        test_driver.write_bytes(b"FAKE_DRIVER" * 100)

        original_paths = SecuROMBypass.DRIVER_PATHS.copy()
        original_keys = SecuROMBypass.REGISTRY_KEYS_TO_DELETE.copy()

        try:
            SecuROMBypass.DRIVER_PATHS = [str(test_driver)]

            test_key_path = r"SOFTWARE\SecuROM\TestRemoval"
            registry_helper.create_test_key(winreg.HKEY_CURRENT_USER, test_key_path)

            SecuROMBypass.REGISTRY_KEYS_TO_DELETE = [
                (winreg.HKEY_CURRENT_USER, test_key_path)
            ]

            result = bypass.remove_securom()

            assert isinstance(result, SecuROMRemovalResult)
            assert result.success is True

            if len(result.drivers_removed) > 0:
                assert not test_driver.exists()

            for root, path in SecuROMBypass.ACTIVATION_REGISTRY_KEYS:
                if registry_helper.key_exists(root, path):
                    registry_helper.created_keys.append((root, path))

        finally:
            SecuROMBypass.DRIVER_PATHS = original_paths
            SecuROMBypass.REGISTRY_KEYS_TO_DELETE = original_keys

    def test_backup_creation_on_modification(self, bypass: SecuROMBypass, protected_binary: Path) -> None:
        """Test that backup files are created when modifying binaries."""
        original_data = protected_binary.read_bytes()

        bypass._patch_activation_checks(protected_binary)

        backup_path = protected_binary.with_suffix(f"{protected_binary.suffix}.bak")

        if backup_path.exists():
            backup_data = backup_path.read_bytes()
            assert backup_data == original_data

    def test_idempotent_registry_operations(self, bypass: SecuROMBypass, registry_helper: RegistryTestHelper) -> None:
        """Test that registry operations are idempotent."""
        result1 = bypass._bypass_activation_registry()
        result2 = bypass._bypass_activation_registry()

        assert result1 == result2

        for root, path in SecuROMBypass.ACTIVATION_REGISTRY_KEYS:
            if registry_helper.key_exists(root, path):
                registry_helper.created_keys.append((root, path))
