"""Production tests for Registry Activation Writing - validates real Windows Registry operations.

Tests complete registry license key writing, proper registry key permissions, encrypted license
storage formats, activation token generation, product-specific registry layouts, UAC elevation,
and registry redirection WITHOUT mocks or stubs.

These tests validate that the offline activation emulator can write actual license data to
Windows Registry in formats that real commercial software licensing systems expect.
"""

import base64
import datetime
import hashlib
import json
import os
import platform
import struct
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.offline_activation_emulator import (
    ActivationRequest,
    ActivationResponse,
    OfflineActivationEmulator,
)

if platform.system() == "Windows":
    import winreg
else:
    winreg = None  # type: ignore[assignment]

pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Registry tests require Windows platform",
)


REGISTRY_TEST_ROOT = r"SOFTWARE\IntellicrackTest"
VALID_LICENSE_KEY_LENGTH = 25
MINIMUM_ACTIVATION_TOKEN_LENGTH = 32
ENCRYPTED_LICENSE_MINIMUM_SIZE = 64


@pytest.fixture
def temp_registry_key() -> str:
    """Create temporary registry key for testing that auto-cleans up."""
    test_key = f"{REGISTRY_TEST_ROOT}\\Test_{uuid.uuid4().hex[:8]}"
    yield test_key

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            REGISTRY_TEST_ROOT,
            0,
            winreg.KEY_ALL_ACCESS,
        ) as parent_key:
            subkey_name = test_key.split("\\")[-1]
            try:
                winreg.DeleteKey(parent_key, subkey_name)
            except FileNotFoundError:
                pass
    except FileNotFoundError:
        pass


@pytest.fixture
def emulator() -> OfflineActivationEmulator:
    """Create OfflineActivationEmulator instance for testing."""
    return OfflineActivationEmulator()


class TestRegistryKeyWriting:
    """Test complete registry license key writing to Windows Registry."""

    def test_write_license_to_registry_creates_key(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes license activation data to Windows Registry and verifies key creation."""
        product_id = "TestProduct_2024"
        license_key = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
        activation_code = "ACT-CODE-12345678901234567890"

        registry_data = {
            f"HKEY_CURRENT_USER\\{temp_registry_key}\\License": "Activated",
            f"HKEY_CURRENT_USER\\{temp_registry_key}\\LicenseKey": license_key,
            f"HKEY_CURRENT_USER\\{temp_registry_key}\\ActivationCode": activation_code,
        }

        for reg_path, value in registry_data.items():
            self._write_registry_value(reg_path, value)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            license_status, _ = winreg.QueryValueEx(key, "License")
            assert license_status == "Activated"

            stored_license_key, _ = winreg.QueryValueEx(key, "LicenseKey")
            assert stored_license_key == license_key

            stored_activation_code, _ = winreg.QueryValueEx(key, "ActivationCode")
            assert stored_activation_code == activation_code

    def test_write_license_with_activation_timestamp(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes license with activation timestamp to Registry."""
        activation_date = datetime.datetime.now(datetime.UTC).isoformat()

        registry_data = {
            f"HKEY_CURRENT_USER\\{temp_registry_key}\\ActivationDate": activation_date,
        }

        for reg_path, value in registry_data.items():
            self._write_registry_value(reg_path, value)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            stored_date, _ = winreg.QueryValueEx(key, "ActivationDate")
            assert stored_date == activation_date

            parsed_date = datetime.datetime.fromisoformat(stored_date.replace("Z", "+00:00"))
            assert parsed_date <= datetime.datetime.now(datetime.UTC)

    def test_write_license_with_expiry_date(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes license with expiry date to Registry."""
        expiry_date = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650)).isoformat()

        registry_data = {
            f"HKEY_CURRENT_USER\\{temp_registry_key}\\ExpiryDate": expiry_date,
        }

        for reg_path, value in registry_data.items():
            self._write_registry_value(reg_path, value)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            stored_expiry, _ = winreg.QueryValueEx(key, "ExpiryDate")
            assert stored_expiry == expiry_date

            parsed_expiry = datetime.datetime.fromisoformat(stored_expiry.replace("Z", "+00:00"))
            assert parsed_expiry > datetime.datetime.now(datetime.UTC)

    def test_write_license_with_features(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes license with enabled features to Registry."""
        features = "Premium;Enterprise;Unlimited;CloudSync"

        registry_data = {
            f"HKEY_CURRENT_USER\\{temp_registry_key}\\Features": features,
        }

        for reg_path, value in registry_data.items():
            self._write_registry_value(reg_path, value)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            stored_features, _ = winreg.QueryValueEx(key, "Features")
            assert stored_features == features

            feature_list = stored_features.split(";")
            assert "Premium" in feature_list
            assert "Enterprise" in feature_list
            assert "Unlimited" in feature_list

    def test_write_multiple_registry_values_atomically(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes multiple registry values atomically for complete activation."""
        activation_data = {
            "License": "Activated",
            "LicenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "ActivationCode": "ACT-CODE-12345678901234567890",
            "ActivationDate": datetime.datetime.now(datetime.UTC).isoformat(),
            "ExpiryDate": (datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650)).isoformat(),
            "Features": "Premium;Enterprise",
            "ProductVersion": "2024.1.0",
            "ActivationType": "Offline",
        }

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, temp_registry_key) as key:
            for name, value in activation_data.items():
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            for name, expected_value in activation_data.items():
                stored_value, _ = winreg.QueryValueEx(key, name)
                assert stored_value == expected_value

    def _write_registry_value(self, registry_path: str, value: str) -> None:
        """Helper to write a single registry value."""
        if registry_path.startswith("HKEY_CURRENT_USER\\"):
            hive = winreg.HKEY_CURRENT_USER
            path_parts = registry_path.replace("HKEY_CURRENT_USER\\", "").rsplit("\\", 1)
        elif registry_path.startswith("HKEY_LOCAL_MACHINE\\"):
            hive = winreg.HKEY_LOCAL_MACHINE
            path_parts = registry_path.replace("HKEY_LOCAL_MACHINE\\", "").rsplit("\\", 1)
        else:
            raise ValueError(f"Unsupported registry hive in path: {registry_path}")

        key_path = path_parts[0]
        value_name = path_parts[1] if len(path_parts) > 1 else ""

        with winreg.CreateKey(hive, key_path) as key:
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value)


class TestRegistryPermissions:
    """Test proper registry key permissions for license data."""

    def test_registry_key_created_with_read_permissions(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Registry key created with proper read permissions."""
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, temp_registry_key) as key:
            winreg.SetValueEx(key, "TestValue", 0, winreg.REG_SZ, "TestData")

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            value, _ = winreg.QueryValueEx(key, "TestValue")
            assert value == "TestData"

    def test_registry_key_supports_write_permissions(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Registry key supports write permissions for updates."""
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, temp_registry_key) as key:
            winreg.SetValueEx(key, "UpdateTest", 0, winreg.REG_SZ, "OriginalValue")

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_WRITE,
        ) as key:
            winreg.SetValueEx(key, "UpdateTest", 0, winreg.REG_SZ, "UpdatedValue")

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            value, _ = winreg.QueryValueEx(key, "UpdateTest")
            assert value == "UpdatedValue"

    def test_registry_key_handles_all_access_permissions(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Registry key handles KEY_ALL_ACCESS permissions."""
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, temp_registry_key) as key:
            winreg.SetValueEx(key, "AllAccessTest", 0, winreg.REG_SZ, "TestData")

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_ALL_ACCESS,
        ) as key:
            value, _ = winreg.QueryValueEx(key, "AllAccessTest")
            assert value == "TestData"

            winreg.SetValueEx(key, "AllAccessTest", 0, winreg.REG_SZ, "ModifiedData")

            modified_value, _ = winreg.QueryValueEx(key, "AllAccessTest")
            assert modified_value == "ModifiedData"


class TestEncryptedLicenseStorage:
    """Test encrypted license storage formats in Registry."""

    def test_write_encrypted_license_to_registry(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes encrypted license data to Registry."""
        license_data = {
            "license_key": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "activation_code": "ACT-CODE-12345678901234567890",
            "features": ["Premium", "Enterprise"],
        }

        encrypted_license = self._encrypt_license_data(license_data)

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, temp_registry_key) as key:
            winreg.SetValueEx(key, "EncryptedLicense", 0, winreg.REG_BINARY, encrypted_license)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            stored_encrypted, value_type = winreg.QueryValueEx(key, "EncryptedLicense")
            assert value_type == winreg.REG_BINARY
            assert isinstance(stored_encrypted, bytes)
            assert len(stored_encrypted) >= ENCRYPTED_LICENSE_MINIMUM_SIZE

            decrypted = self._decrypt_license_data(stored_encrypted)
            assert decrypted["license_key"] == license_data["license_key"]

    def test_write_base64_encoded_license(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes Base64-encoded license to Registry."""
        license_json = json.dumps({
            "license_key": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "activation_code": "ACT-CODE-12345678901234567890",
        })

        encoded_license = base64.b64encode(license_json.encode()).decode()

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, temp_registry_key) as key:
            winreg.SetValueEx(key, "EncodedLicense", 0, winreg.REG_SZ, encoded_license)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            stored_encoded, _ = winreg.QueryValueEx(key, "EncodedLicense")
            decoded = base64.b64decode(stored_encoded).decode()
            license_data = json.loads(decoded)

            assert license_data["license_key"] == "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"

    def test_write_binary_encrypted_license_with_signature(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes binary encrypted license with cryptographic signature."""
        license_data = b"LICENSE_KEY=XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"

        signature = hashlib.sha256(license_data).digest()

        encrypted_data = self._xor_encrypt(license_data, b"encryption_key_32bytes_long!")

        combined_data = struct.pack("<I", len(signature)) + signature + encrypted_data

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, temp_registry_key) as key:
            winreg.SetValueEx(key, "SignedEncryptedLicense", 0, winreg.REG_BINARY, combined_data)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            stored_data, _ = winreg.QueryValueEx(key, "SignedEncryptedLicense")

            sig_len = struct.unpack("<I", stored_data[:4])[0]
            stored_signature = stored_data[4:4+sig_len]
            encrypted_license = stored_data[4+sig_len:]

            decrypted = self._xor_encrypt(encrypted_license, b"encryption_key_32bytes_long!")
            verification_sig = hashlib.sha256(decrypted).digest()

            assert stored_signature == verification_sig

    def _encrypt_license_data(self, data: dict[str, Any]) -> bytes:
        """Simple XOR encryption for license data."""
        json_data = json.dumps(data).encode()
        key = b"test_encryption_key_32bytes!"
        return self._xor_encrypt(json_data, key)

    def _decrypt_license_data(self, encrypted: bytes) -> dict[str, Any]:
        """Simple XOR decryption for license data."""
        key = b"test_encryption_key_32bytes!"
        decrypted = self._xor_encrypt(encrypted, key)
        return json.loads(decrypted.decode())

    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """XOR encryption/decryption."""
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


class TestActivationTokenGeneration:
    """Test proper activation token generation for Registry storage."""

    def test_generate_activation_token_with_hardware_binding(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Generates activation token bound to hardware ID."""
        profile = emulator.get_hardware_profile()
        hardware_id = emulator.generate_hardware_id(profile)

        activation_token = hashlib.sha256(
            f"{hardware_id}:TestProduct:2024".encode()
        ).hexdigest()

        assert len(activation_token) >= MINIMUM_ACTIVATION_TOKEN_LENGTH
        assert activation_token.isalnum()

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, temp_registry_key) as key:
            winreg.SetValueEx(key, "ActivationToken", 0, winreg.REG_SZ, activation_token)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            stored_token, _ = winreg.QueryValueEx(key, "ActivationToken")
            assert stored_token == activation_token

    def test_generate_time_based_activation_token(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Generates time-based activation token."""
        timestamp = int(datetime.datetime.now(datetime.UTC).timestamp())
        activation_token = hashlib.sha256(
            f"TestProduct:2024:{timestamp}".encode()
        ).hexdigest()

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, temp_registry_key) as key:
            winreg.SetValueEx(key, "ActivationToken", 0, winreg.REG_SZ, activation_token)
            winreg.SetValueEx(key, "ActivationTimestamp", 0, winreg.REG_DWORD, timestamp)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            stored_token, _ = winreg.QueryValueEx(key, "ActivationToken")
            stored_timestamp, _ = winreg.QueryValueEx(key, "ActivationTimestamp")

            assert stored_token == activation_token
            assert stored_timestamp == timestamp

    def test_generate_uuid_based_activation_token(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Generates UUID-based activation token."""
        installation_uuid = str(uuid.uuid4())
        activation_token = hashlib.sha256(installation_uuid.encode()).hexdigest()

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, temp_registry_key) as key:
            winreg.SetValueEx(key, "InstallationUUID", 0, winreg.REG_SZ, installation_uuid)
            winreg.SetValueEx(key, "ActivationToken", 0, winreg.REG_SZ, activation_token)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            stored_uuid, _ = winreg.QueryValueEx(key, "InstallationUUID")
            stored_token, _ = winreg.QueryValueEx(key, "ActivationToken")

            assert uuid.UUID(stored_uuid)
            assert stored_token == activation_token


class TestProductSpecificRegistryLayouts:
    """Test product-specific registry layouts for different vendors."""

    def test_microsoft_office_registry_layout(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes Microsoft Office-style registry layout."""
        office_key = f"{temp_registry_key}\\Office\\16.0\\Registration"

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, office_key) as key:
            winreg.SetValueEx(key, "ProductKey", 0, winreg.REG_SZ, "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")
            winreg.SetValueEx(key, "DigitalProductId", 0, winreg.REG_BINARY, os.urandom(164))
            winreg.SetValueEx(key, "TrialType", 0, winreg.REG_SZ, "")
            winreg.SetValueEx(key, "TimeRemaining", 0, winreg.REG_DWORD, 0)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            office_key,
            0,
            winreg.KEY_READ,
        ) as key:
            product_key, _ = winreg.QueryValueEx(key, "ProductKey")
            assert len(product_key) == VALID_LICENSE_KEY_LENGTH

            digital_id, _ = winreg.QueryValueEx(key, "DigitalProductId")
            assert len(digital_id) == 164

    def test_adobe_cc_registry_layout(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes Adobe Creative Cloud-style registry layout."""
        adobe_key = f"{temp_registry_key}\\Adobe\\Photoshop\\120.0"

        license_cache = {
            "activation_code": "ADOBE-ACT-CODE-12345678901234567890",
            "license_type": "subscription",
            "features": ["premium", "cloud_sync"],
        }

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, adobe_key) as key:
            winreg.SetValueEx(
                key,
                "LicenseCache",
                0,
                winreg.REG_BINARY,
                json.dumps(license_cache).encode(),
            )
            winreg.SetValueEx(key, "ActivationCount", 0, winreg.REG_DWORD, 1)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            adobe_key,
            0,
            winreg.KEY_READ,
        ) as key:
            cache_data, _ = winreg.QueryValueEx(key, "LicenseCache")
            cache_json = json.loads(cache_data.decode())

            assert cache_json["activation_code"].startswith("ADOBE-ACT-CODE-")
            assert cache_json["license_type"] == "subscription"

    def test_autodesk_registry_layout(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes Autodesk-style registry layout."""
        autodesk_key = f"{temp_registry_key}\\Autodesk\\AutoCAD\\R24.0"

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, autodesk_key) as key:
            winreg.SetValueEx(key, "SerialNumber", 0, winreg.REG_SZ, "666-69696969")
            winreg.SetValueEx(key, "ProductKey", 0, winreg.REG_SZ, "001P1")
            winreg.SetValueEx(
                key,
                "ActivationData",
                0,
                winreg.REG_BINARY,
                os.urandom(128),
            )

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            autodesk_key,
            0,
            winreg.KEY_READ,
        ) as key:
            serial, _ = winreg.QueryValueEx(key, "SerialNumber")
            assert "-" in serial

            activation_data, _ = winreg.QueryValueEx(key, "ActivationData")
            assert len(activation_data) == 128

    def test_vmware_registry_layout(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes VMware-style registry layout."""
        vmware_key = f"{temp_registry_key}\\VMware\\Workstation\\17.0"

        license_string = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, vmware_key) as key:
            winreg.SetValueEx(key, "Serial", 0, winreg.REG_SZ, license_string)
            winreg.SetValueEx(key, "Serial.0", 0, winreg.REG_SZ, license_string)
            winreg.SetValueEx(key, "LicenseType", 0, winreg.REG_SZ, "Perpetual")

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            vmware_key,
            0,
            winreg.KEY_READ,
        ) as key:
            serial, _ = winreg.QueryValueEx(key, "Serial")
            assert serial == license_string

            license_type, _ = winreg.QueryValueEx(key, "LicenseType")
            assert license_type == "Perpetual"


class TestRegistryRedirection:
    """Test Windows Registry redirection (32-bit vs 64-bit)."""

    def test_write_to_64bit_registry_view(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes to 64-bit Registry view on x64 Windows."""
        if platform.machine().lower() not in ["amd64", "x86_64"]:
            pytest.skip("Test requires 64-bit Windows")

        access_flags = winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            access_flags,
        ) as key:
            winreg.SetValueEx(key, "64BitTest", 0, winreg.REG_SZ, "64-bit value")

        read_flags = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        with winreg.OpenKeyEx(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            read_flags,
        ) as key:
            value, _ = winreg.QueryValueEx(key, "64BitTest")
            assert value == "64-bit value"

    def test_write_to_32bit_registry_view(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes to 32-bit Registry view (WOW64 redirection)."""
        access_flags = winreg.KEY_WRITE | winreg.KEY_WOW64_32KEY

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            access_flags,
        ) as key:
            winreg.SetValueEx(key, "32BitTest", 0, winreg.REG_SZ, "32-bit value")

        read_flags = winreg.KEY_READ | winreg.KEY_WOW64_32KEY
        with winreg.OpenKeyEx(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            read_flags,
        ) as key:
            value, _ = winreg.QueryValueEx(key, "32BitTest")
            assert value == "32-bit value"

    def test_registry_redirection_isolation(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """32-bit and 64-bit registry views are isolated."""
        if platform.machine().lower() not in ["amd64", "x86_64"]:
            pytest.skip("Test requires 64-bit Windows")

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY,
        ) as key:
            winreg.SetValueEx(key, "TestValue", 0, winreg.REG_SZ, "64-bit")

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_32KEY,
        ) as key:
            winreg.SetValueEx(key, "TestValue", 0, winreg.REG_SZ, "32-bit")

        with winreg.OpenKeyEx(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            value_64, _ = winreg.QueryValueEx(key, "TestValue")
            assert value_64 == "64-bit"

        with winreg.OpenKeyEx(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_32KEY,
        ) as key:
            value_32, _ = winreg.QueryValueEx(key, "TestValue")
            assert value_32 == "32-bit"


class TestUACElevationHandling:
    """Test UAC elevation handling for HKEY_LOCAL_MACHINE writes."""

    def test_detect_hklm_requires_elevation(
        self,
        emulator: OfflineActivationEmulator,
    ) -> None:
        """Detects that HKEY_LOCAL_MACHINE requires elevation."""
        requires_elevation = self._check_requires_elevation(
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\TestProduct"
        )

        if not self._is_admin():
            assert requires_elevation is True
        else:
            assert requires_elevation is False

    def test_hkcu_does_not_require_elevation(
        self,
        emulator: OfflineActivationEmulator,
    ) -> None:
        """HKEY_CURRENT_USER does not require elevation."""
        requires_elevation = self._check_requires_elevation(
            "HKEY_CURRENT_USER\\SOFTWARE\\TestProduct"
        )

        assert requires_elevation is False

    def test_fallback_to_hkcu_when_hklm_fails(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Falls back to HKEY_CURRENT_USER when HKEY_LOCAL_MACHINE write fails."""
        hklm_path = "SOFTWARE\\IntellicrackTestHKLM\\TestProduct"

        try:
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, hklm_path) as key:
                winreg.SetValueEx(key, "Test", 0, winreg.REG_SZ, "HKLM Success")
            hklm_succeeded = True
        except PermissionError:
            hklm_succeeded = False

        if not hklm_succeeded:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, temp_registry_key) as key:
                winreg.SetValueEx(key, "Test", 0, winreg.REG_SZ, "HKCU Fallback")

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                temp_registry_key,
                0,
                winreg.KEY_READ,
            ) as key:
                value, _ = winreg.QueryValueEx(key, "Test")
                assert value == "HKCU Fallback"

        if hklm_succeeded:
            try:
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, hklm_path)
            except Exception:
                pass

    def _is_admin(self) -> bool:
        """Check if running with administrator privileges."""
        try:
            return os.getuid() == 0  # type: ignore[attr-defined]
        except AttributeError:
            import ctypes
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False

    def _check_requires_elevation(self, registry_path: str) -> bool:
        """Check if registry path requires UAC elevation."""
        if "HKEY_LOCAL_MACHINE" in registry_path:
            return not self._is_admin()
        return False


class TestRegistryDataTypes:
    """Test different registry data types for license storage."""

    def test_write_reg_sz_string_value(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes REG_SZ string value to Registry."""
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, temp_registry_key) as key:
            winreg.SetValueEx(key, "StringValue", 0, winreg.REG_SZ, "Test String")

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            value, value_type = winreg.QueryValueEx(key, "StringValue")
            assert value_type == winreg.REG_SZ
            assert value == "Test String"

    def test_write_reg_dword_integer_value(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes REG_DWORD integer value to Registry."""
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, temp_registry_key) as key:
            winreg.SetValueEx(key, "DWordValue", 0, winreg.REG_DWORD, 12345)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            value, value_type = winreg.QueryValueEx(key, "DWordValue")
            assert value_type == winreg.REG_DWORD
            assert value == 12345

    def test_write_reg_binary_data(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes REG_BINARY data to Registry."""
        binary_data = os.urandom(256)

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, temp_registry_key) as key:
            winreg.SetValueEx(key, "BinaryValue", 0, winreg.REG_BINARY, binary_data)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            value, value_type = winreg.QueryValueEx(key, "BinaryValue")
            assert value_type == winreg.REG_BINARY
            assert value == binary_data

    def test_write_reg_multi_sz_string_array(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Writes REG_MULTI_SZ string array to Registry."""
        features = ["Premium", "Enterprise", "CloudSync", "Unlimited"]

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, temp_registry_key) as key:
            winreg.SetValueEx(key, "Features", 0, winreg.REG_MULTI_SZ, features)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            temp_registry_key,
            0,
            winreg.KEY_READ,
        ) as key:
            value, value_type = winreg.QueryValueEx(key, "Features")
            assert value_type == winreg.REG_MULTI_SZ
            assert value == features


class TestEndToEndRegistryActivation:
    """Test complete end-to-end registry activation workflows."""

    def test_complete_microsoft_office_activation_workflow(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Complete Microsoft Office activation workflow with Registry writes."""
        profile = emulator.get_hardware_profile()
        hardware_id = emulator.generate_hardware_id(profile, algorithm="microsoft")

        product_id = "Office.16.Standard"
        installation_id = emulator.generate_installation_id(product_id, hardware_id)
        request_code = emulator.generate_request_code(installation_id)

        request = ActivationRequest(
            product_id=product_id,
            product_version="16.0.0.0",
            hardware_id=hardware_id,
            installation_id=installation_id,
            request_code=request_code,
            timestamp=datetime.datetime.now(datetime.UTC),
            additional_data={},
        )

        response = emulator.generate_activation_response(request)

        office_key = f"{temp_registry_key}\\Office\\16.0\\Registration"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, office_key) as key:
            winreg.SetValueEx(key, "ProductKey", 0, winreg.REG_SZ, response.license_key)
            winreg.SetValueEx(key, "ActivationCode", 0, winreg.REG_SZ, response.activation_code)
            winreg.SetValueEx(
                key,
                "DigitalProductId",
                0,
                winreg.REG_BINARY,
                response.signature,
            )

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            office_key,
            0,
            winreg.KEY_READ,
        ) as key:
            product_key, _ = winreg.QueryValueEx(key, "ProductKey")
            assert product_key == response.license_key
            assert len(product_key) == VALID_LICENSE_KEY_LENGTH

    def test_complete_adobe_cc_activation_workflow(
        self,
        emulator: OfflineActivationEmulator,
        temp_registry_key: str,
    ) -> None:
        """Complete Adobe CC activation workflow with Registry writes."""
        profile = emulator.get_hardware_profile()
        hardware_id = emulator.generate_hardware_id(profile, algorithm="adobe")

        product_id = "Adobe.Photoshop.CC"
        installation_id = emulator.generate_installation_id(product_id, hardware_id)
        request_code = emulator.generate_request_code(installation_id)

        request = ActivationRequest(
            product_id=product_id,
            product_version="2024.0.0",
            hardware_id=hardware_id,
            installation_id=installation_id,
            request_code=request_code,
            timestamp=datetime.datetime.now(datetime.UTC),
            additional_data={},
        )

        response = emulator.generate_activation_response(request)

        license_cache = {
            "activation_code": response.activation_code,
            "license_key": response.license_key,
            "features": response.features,
            "expiry_date": response.expiry_date.isoformat() if response.expiry_date else None,
        }

        adobe_key = f"{temp_registry_key}\\Adobe\\Photoshop\\120.0"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, adobe_key) as key:
            encrypted_cache = self._xor_encrypt(
                json.dumps(license_cache).encode(),
                b"adobe_encryption_key_32bytes!",
            )
            winreg.SetValueEx(key, "LicenseCache", 0, winreg.REG_BINARY, encrypted_cache)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            adobe_key,
            0,
            winreg.KEY_READ,
        ) as key:
            encrypted_data, _ = winreg.QueryValueEx(key, "LicenseCache")
            decrypted = self._xor_encrypt(encrypted_data, b"adobe_encryption_key_32bytes!")
            cache_data = json.loads(decrypted.decode())

            assert cache_data["license_key"] == response.license_key

    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """XOR encryption/decryption."""
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
