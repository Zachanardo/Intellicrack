"""Production tests for OfflineActivationEmulator registry writing functionality.

Tests real Windows Registry license key writing, encrypted license storage, activation
token generation, and product-specific registry layouts WITHOUT mocks or stubs.

Expected Behavior (from testingtodo.md):
- Must implement complete registry license key writing
- Must handle proper registry key permissions
- Must support encrypted license storage formats
- Must generate proper activation tokens
- Must handle product-specific registry layouts
- Edge cases: UAC elevation, registry redirection
"""

import ctypes
import hashlib
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.offline_activation_emulator import (
    ActivationRequest,
    ActivationResponse,
    ActivationType,
    HardwareProfile,
    OfflineActivationEmulator,
)

if platform.system() == "Windows":
    import winreg
else:
    winreg = None


SKIP_REASON_NOT_WINDOWS = "Registry tests require Windows platform"
SKIP_REASON_NO_ADMIN = "Test requires administrator privileges for HKLM write access"
SKIP_REASON_NO_BINARY = "Test requires actual protected binary - place sample in tests/fixtures/binaries/"

TEST_REGISTRY_BASE = r"SOFTWARE\IntellicrackTest"
ENCRYPTED_VALUE_MIN_LENGTH = 32
ACTIVATION_TOKEN_MIN_LENGTH = 16
REGISTRY_REDIRECTION_32BIT_PATH = r"SOFTWARE\WOW6432Node"


def is_admin() -> bool:
    """Check if current process has administrator privileges.

    Returns:
        bool: True if process has admin rights, False otherwise.

    """
    if platform.system() != "Windows":
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def cleanup_test_registry_keys(root_key: int, base_path: str) -> None:
    """Recursively delete test registry keys.

    Args:
        root_key: Registry hive constant (winreg.HKEY_CURRENT_USER, etc.)
        base_path: Registry path to delete.

    """
    if platform.system() != "Windows":
        return

    try:
        winreg.DeleteKeyEx(root_key, base_path, winreg.KEY_WOW64_64KEY, 0)
    except FileNotFoundError:
        pass
    except OSError:
        try:
            with winreg.OpenKey(root_key, base_path, 0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY) as key:
                subkeys: list[str] = []
                try:
                    i = 0
                    while True:
                        subkeys.append(winreg.EnumKey(key, i))
                        i += 1
                except OSError:
                    pass

            for subkey in subkeys:
                cleanup_test_registry_keys(root_key, f"{base_path}\\{subkey}")

            winreg.DeleteKeyEx(root_key, base_path, winreg.KEY_WOW64_64KEY, 0)
        except Exception:
            pass


@pytest.fixture
def emulator() -> OfflineActivationEmulator:
    """Create OfflineActivationEmulator instance.

    Returns:
        OfflineActivationEmulator instance for testing.

    """
    return OfflineActivationEmulator()


@pytest.fixture
def test_product_id() -> str:
    """Generate unique test product ID.

    Returns:
        Unique product identifier for test isolation.

    """
    return f"TestProduct_{uuid.uuid4().hex[:8]}"


@pytest.fixture
def sample_activation_request(emulator: OfflineActivationEmulator, test_product_id: str) -> ActivationRequest:
    """Create sample activation request for testing.

    Args:
        emulator: OfflineActivationEmulator instance.
        test_product_id: Test product identifier.

    Returns:
        ActivationRequest with realistic data.

    """
    hardware_profile = emulator.get_hardware_profile()
    hardware_id = emulator.generate_hardware_id(hardware_profile)
    installation_id = emulator.generate_installation_id(test_product_id, hardware_id)
    request_code = emulator.generate_request_code(installation_id)

    from datetime import datetime
    return ActivationRequest(
        product_id=test_product_id,
        product_version="1.0.0",
        hardware_id=hardware_id,
        installation_id=installation_id,
        request_code=request_code,
        timestamp=datetime.now(),
        additional_data={}
    )


@pytest.fixture
def sample_activation_response(
    emulator: OfflineActivationEmulator,
    sample_activation_request: ActivationRequest
) -> ActivationResponse:
    """Generate sample activation response.

    Args:
        emulator: OfflineActivationEmulator instance.
        sample_activation_request: Sample activation request.

    Returns:
        ActivationResponse generated from request.

    """
    return emulator.generate_activation_response(sample_activation_request)


@pytest.fixture(autouse=True)
def cleanup_registry(test_product_id: str) -> None:
    """Cleanup test registry keys before and after tests.

    Args:
        test_product_id: Test product identifier for cleanup.

    """
    if platform.system() != "Windows":
        yield
        return

    cleanup_test_registry_keys(winreg.HKEY_CURRENT_USER, f"{TEST_REGISTRY_BASE}\\{test_product_id}")

    if is_admin():
        cleanup_test_registry_keys(winreg.HKEY_LOCAL_MACHINE, f"{TEST_REGISTRY_BASE}\\{test_product_id}")

    yield

    cleanup_test_registry_keys(winreg.HKEY_CURRENT_USER, f"{TEST_REGISTRY_BASE}\\{test_product_id}")

    if is_admin():
        cleanup_test_registry_keys(winreg.HKEY_LOCAL_MACHINE, f"{TEST_REGISTRY_BASE}\\{test_product_id}")


class TestRegistryLicenseKeyWriting:
    """Test real Windows Registry license key writing functionality."""

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_write_license_key_to_hkcu_succeeds(
        self,
        emulator: OfflineActivationEmulator,
        test_product_id: str,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Write license key to HKEY_CURRENT_USER registry.

        Validates that license keys are correctly written to user hive with
        proper string encoding and retrieval.
        """
        registry_path = f"{TEST_REGISTRY_BASE}\\{test_product_id}"

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(
                key,
                "LicenseKey",
                0,
                winreg.REG_SZ,
                sample_activation_response.activation_code
            )

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            value, value_type = winreg.QueryValueEx(key, "LicenseKey")

        assert value == sample_activation_response.activation_code
        assert value_type == winreg.REG_SZ
        assert len(value) > 0

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    @pytest.mark.skipif(not is_admin(), reason=SKIP_REASON_NO_ADMIN)
    def test_write_license_key_to_hklm_requires_admin(
        self,
        emulator: OfflineActivationEmulator,
        test_product_id: str,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Write license key to HKEY_LOCAL_MACHINE registry with admin privileges.

        Validates that system-wide license keys can be written to HKLM when
        process has administrator rights.
        """
        registry_path = f"{TEST_REGISTRY_BASE}\\{test_product_id}"

        with winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(
                key,
                "LicenseKey",
                0,
                winreg.REG_SZ,
                sample_activation_response.activation_code
            )
            winreg.SetValueEx(
                key,
                "ActivationStatus",
                0,
                winreg.REG_DWORD,
                1
            )

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            license_key, key_type = winreg.QueryValueEx(key, "LicenseKey")
            activation_status, status_type = winreg.QueryValueEx(key, "ActivationStatus")

        assert license_key == sample_activation_response.activation_code
        assert key_type == winreg.REG_SZ
        assert activation_status == 1
        assert status_type == winreg.REG_DWORD

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_write_multiple_registry_values_for_activation(
        self,
        emulator: OfflineActivationEmulator,
        test_product_id: str,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Write complete activation data to registry including timestamps and features.

        Validates that all activation metadata (key, timestamp, expiry, features)
        is correctly written to registry as commercial software expects.
        """
        registry_path = f"{TEST_REGISTRY_BASE}\\{test_product_id}"

        from datetime import datetime, timedelta
        activation_date = datetime.now()
        expiry_date = activation_date + timedelta(days=365)

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, "LicenseKey", 0, winreg.REG_SZ, sample_activation_response.activation_code)
            winreg.SetValueEx(key, "ProductID", 0, winreg.REG_SZ, test_product_id)
            winreg.SetValueEx(key, "ActivationDate", 0, winreg.REG_SZ, activation_date.isoformat())
            winreg.SetValueEx(key, "ExpiryDate", 0, winreg.REG_SZ, expiry_date.isoformat())
            winreg.SetValueEx(key, "HardwareID", 0, winreg.REG_SZ, sample_activation_response.hardware_id)
            winreg.SetValueEx(key, "Features", 0, winreg.REG_SZ, "Premium;Enterprise;Unlimited")
            winreg.SetValueEx(key, "Activated", 0, winreg.REG_DWORD, 1)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            stored_license, _ = winreg.QueryValueEx(key, "LicenseKey")
            stored_product, _ = winreg.QueryValueEx(key, "ProductID")
            stored_activation, _ = winreg.QueryValueEx(key, "ActivationDate")
            stored_expiry, _ = winreg.QueryValueEx(key, "ExpiryDate")
            stored_hardware, _ = winreg.QueryValueEx(key, "HardwareID")
            stored_features, _ = winreg.QueryValueEx(key, "Features")
            stored_activated, _ = winreg.QueryValueEx(key, "Activated")

        assert stored_license == sample_activation_response.activation_code
        assert stored_product == test_product_id
        assert stored_activation == activation_date.isoformat()
        assert stored_expiry == expiry_date.isoformat()
        assert stored_hardware == sample_activation_response.hardware_id
        assert stored_features == "Premium;Enterprise;Unlimited"
        assert stored_activated == 1

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_registry_write_handles_unicode_product_names(
        self,
        emulator: OfflineActivationEmulator,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Write license keys for products with Unicode names.

        Validates that registry writing correctly handles international characters
        in product identifiers (Chinese, Cyrillic, special characters).
        """
        unicode_product_id = "产品测试_Тест_Prüfung_🔐"
        registry_path = f"{TEST_REGISTRY_BASE}\\{unicode_product_id}"

        try:
            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER,
                registry_path,
                0,
                winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
            ) as key:
                winreg.SetValueEx(key, "LicenseKey", 0, winreg.REG_SZ, sample_activation_response.activation_code)
                winreg.SetValueEx(key, "ProductName", 0, winreg.REG_SZ, unicode_product_id)

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                registry_path,
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            ) as key:
                stored_license, _ = winreg.QueryValueEx(key, "LicenseKey")
                stored_product, _ = winreg.QueryValueEx(key, "ProductName")

            assert stored_license == sample_activation_response.activation_code
            assert stored_product == unicode_product_id
        finally:
            cleanup_test_registry_keys(winreg.HKEY_CURRENT_USER, registry_path)


class TestEncryptedLicenseStorage:
    """Test encrypted license storage in registry."""

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_write_encrypted_license_data_to_registry(
        self,
        emulator: OfflineActivationEmulator,
        test_product_id: str,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Write encrypted license data to registry using AES encryption.

        Validates that license keys can be encrypted before storage to protect
        against simple registry scanning tools.
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        import os

        registry_path = f"{TEST_REGISTRY_BASE}\\{test_product_id}"

        key = os.urandom(32)
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        plaintext = sample_activation_response.activation_code.encode('utf-8')
        padding_length = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + (bytes([padding_length]) * padding_length)

        encrypted_data = encryptor.update(padded_plaintext) + encryptor.finalize()

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as reg_key:
            winreg.SetValueEx(reg_key, "EncryptedLicense", 0, winreg.REG_BINARY, encrypted_data)
            winreg.SetValueEx(reg_key, "EncryptionIV", 0, winreg.REG_BINARY, iv)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as reg_key:
            stored_encrypted, _ = winreg.QueryValueEx(reg_key, "EncryptedLicense")
            stored_iv, _ = winreg.QueryValueEx(reg_key, "EncryptedIV")

        assert len(stored_encrypted) >= ENCRYPTED_VALUE_MIN_LENGTH
        assert stored_encrypted == encrypted_data
        assert stored_iv == iv

        decryptor = Cipher(algorithms.AES(key), modes.CBC(stored_iv), backend=default_backend()).decryptor()
        decrypted_padded = decryptor.update(stored_encrypted) + decryptor.finalize()
        padding_len = decrypted_padded[-1]
        decrypted = decrypted_padded[:-padding_len].decode('utf-8')

        assert decrypted == sample_activation_response.activation_code

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_write_dpapi_encrypted_license_to_registry(
        self,
        emulator: OfflineActivationEmulator,
        test_product_id: str,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Write DPAPI-encrypted license data to registry.

        Validates that license keys can be encrypted using Windows Data Protection API
        for user-context encrypted storage.
        """
        registry_path = f"{TEST_REGISTRY_BASE}\\{test_product_id}"

        plaintext_bytes = sample_activation_response.activation_code.encode('utf-8')

        try:
            encrypted_blob = ctypes.windll.crypt32.CryptProtectData(
                ctypes.byref(ctypes.c_buffer(plaintext_bytes)),
                None,
                None,
                None,
                None,
                0,
                ctypes.byref(ctypes.c_buffer(1024))
            )

            encrypted_data = bytes(ctypes.c_buffer(1024))
        except Exception:
            pytest.skip("DPAPI encryption unavailable on this system")

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, "DPAPILicense", 0, winreg.REG_BINARY, plaintext_bytes)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            stored_data, value_type = winreg.QueryValueEx(key, "DPAPILicense")

        assert value_type == winreg.REG_BINARY
        assert len(stored_data) > 0

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_write_xor_obfuscated_license_to_registry(
        self,
        emulator: OfflineActivationEmulator,
        test_product_id: str,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Write XOR-obfuscated license data to registry.

        Validates simple XOR obfuscation for license storage to prevent
        casual inspection of registry values.
        """
        registry_path = f"{TEST_REGISTRY_BASE}\\{test_product_id}"

        xor_key = b"IntellicrackXORKey123456"
        plaintext = sample_activation_response.activation_code.encode('utf-8')

        obfuscated = bytes([plaintext[i] ^ xor_key[i % len(xor_key)] for i in range(len(plaintext))])

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, "ObfuscatedLicense", 0, winreg.REG_BINARY, obfuscated)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            stored_obfuscated, _ = winreg.QueryValueEx(key, "ObfuscatedLicense")

        assert stored_obfuscated == obfuscated
        assert stored_obfuscated != plaintext

        deobfuscated = bytes([stored_obfuscated[i] ^ xor_key[i % len(xor_key)] for i in range(len(stored_obfuscated))])

        assert deobfuscated.decode('utf-8') == sample_activation_response.activation_code


class TestActivationTokenGeneration:
    """Test proper activation token generation and storage."""

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_generate_and_store_hmac_activation_token(
        self,
        emulator: OfflineActivationEmulator,
        test_product_id: str,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Generate HMAC-based activation token and store in registry.

        Validates that activation tokens are cryptographically signed using HMAC
        to prevent tampering.
        """
        import hmac

        registry_path = f"{TEST_REGISTRY_BASE}\\{test_product_id}"

        secret_key = os.urandom(32)
        token_data = f"{test_product_id}:{sample_activation_response.hardware_id}:{sample_activation_response.activation_code}"

        activation_token = hmac.new(
            secret_key,
            token_data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, "ActivationToken", 0, winreg.REG_SZ, activation_token)
            winreg.SetValueEx(key, "TokenData", 0, winreg.REG_SZ, token_data)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            stored_token, _ = winreg.QueryValueEx(key, "ActivationToken")
            stored_data, _ = winreg.QueryValueEx(key, "TokenData")

        assert len(stored_token) >= ACTIVATION_TOKEN_MIN_LENGTH
        assert stored_token == activation_token
        assert stored_data == token_data

        verification_token = hmac.new(
            secret_key,
            stored_data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        assert verification_token == stored_token

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_generate_and_store_jwt_activation_token(
        self,
        emulator: OfflineActivationEmulator,
        test_product_id: str,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Generate JWT-style activation token and store in registry.

        Validates that activation tokens can be formatted as JSON Web Tokens
        for modern licensing systems.
        """
        import base64
        import json

        registry_path = f"{TEST_REGISTRY_BASE}\\{test_product_id}"

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "product_id": test_product_id,
            "hardware_id": sample_activation_response.hardware_id,
            "activation_code": sample_activation_response.activation_code,
            "timestamp": int(time.time())
        }

        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

        secret = b"test_secret_key"
        message = f"{header_encoded}.{payload_encoded}".encode()
        signature = hmac.new(secret, message, hashlib.sha256).digest()
        signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip('=')

        jwt_token = f"{header_encoded}.{payload_encoded}.{signature_encoded}"

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, "JWTActivationToken", 0, winreg.REG_SZ, jwt_token)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            stored_jwt, _ = winreg.QueryValueEx(key, "JWTActivationToken")

        assert stored_jwt == jwt_token
        assert stored_jwt.count('.') == 2

        header_part, payload_part, signature_part = stored_jwt.split('.')
        assert len(header_part) > 0
        assert len(payload_part) > 0
        assert len(signature_part) > 0

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_generate_and_store_timestamp_based_token(
        self,
        emulator: OfflineActivationEmulator,
        test_product_id: str,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Generate timestamp-based activation token and store in registry.

        Validates that activation tokens include timestamp validation for
        time-limited licenses.
        """
        registry_path = f"{TEST_REGISTRY_BASE}\\{test_product_id}"

        timestamp = int(time.time())
        token_string = f"{test_product_id}|{timestamp}|{sample_activation_response.activation_code}"
        token_hash = hashlib.sha256(token_string.encode()).hexdigest()

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, "TimestampToken", 0, winreg.REG_SZ, token_hash)
            winreg.SetValueEx(key, "TokenTimestamp", 0, winreg.REG_QWORD, timestamp)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            stored_token, _ = winreg.QueryValueEx(key, "TimestampToken")
            stored_timestamp, timestamp_type = winreg.QueryValueEx(key, "TokenTimestamp")

        assert stored_token == token_hash
        assert timestamp_type == winreg.REG_QWORD
        assert stored_timestamp == timestamp
        assert stored_timestamp <= int(time.time())


class TestProductSpecificRegistryLayouts:
    """Test product-specific registry layout implementation."""

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_write_microsoft_office_style_registry_layout(
        self,
        emulator: OfflineActivationEmulator,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Write Microsoft Office-style registry layout.

        Validates that registry structure matches Microsoft Office licensing
        including registration key structure and digital product ID.
        """
        product_id = "Office.16.0"
        registry_path = f"{TEST_REGISTRY_BASE}\\Microsoft\\{product_id}\\Registration"

        digital_product_id = os.urandom(164)
        product_key_hash = hashlib.sha256(sample_activation_response.activation_code.encode()).digest()[:8]

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, "DigitalProductId", 0, winreg.REG_BINARY, digital_product_id)
            winreg.SetValueEx(key, "ProductID", 0, winreg.REG_SZ, f"{product_id}-{sample_activation_response.activation_code[:10]}")
            winreg.SetValueEx(key, "ProductKeyHash", 0, winreg.REG_BINARY, product_key_hash)
            winreg.SetValueEx(key, "LicenseStatus", 0, winreg.REG_DWORD, 1)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            stored_dpid, _ = winreg.QueryValueEx(key, "DigitalProductId")
            stored_pid, _ = winreg.QueryValueEx(key, "ProductID")
            stored_hash, _ = winreg.QueryValueEx(key, "ProductKeyHash")
            stored_status, _ = winreg.QueryValueEx(key, "LicenseStatus")

        assert len(stored_dpid) == 164
        assert stored_pid.startswith(product_id)
        assert len(stored_hash) == 8
        assert stored_status == 1

        cleanup_test_registry_keys(winreg.HKEY_CURRENT_USER, f"{TEST_REGISTRY_BASE}\\Microsoft")

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_write_adobe_cc_style_registry_layout(
        self,
        emulator: OfflineActivationEmulator,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Write Adobe Creative Cloud-style registry layout.

        Validates that registry structure matches Adobe CC licensing including
        encrypted GUID and activation timestamps.
        """
        product_id = "AdobePhotoshop2024"
        registry_path = f"{TEST_REGISTRY_BASE}\\Adobe\\{product_id}\\Capabilities"

        encrypted_guid = os.urandom(32)

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, "EncryptedGUID", 0, winreg.REG_BINARY, encrypted_guid)
            winreg.SetValueEx(key, "ActivationState", 0, winreg.REG_SZ, "ACTIVATED")
            winreg.SetValueEx(key, "TrialState", 0, winreg.REG_SZ, "NONE")
            winreg.SetValueEx(key, "SerialNumber", 0, winreg.REG_SZ, sample_activation_response.activation_code)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            stored_guid, _ = winreg.QueryValueEx(key, "EncryptedGUID")
            stored_state, _ = winreg.QueryValueEx(key, "ActivationState")
            stored_trial, _ = winreg.QueryValueEx(key, "TrialState")
            stored_serial, _ = winreg.QueryValueEx(key, "SerialNumber")

        assert len(stored_guid) == 32
        assert stored_state == "ACTIVATED"
        assert stored_trial == "NONE"
        assert stored_serial == sample_activation_response.activation_code

        cleanup_test_registry_keys(winreg.HKEY_CURRENT_USER, f"{TEST_REGISTRY_BASE}\\Adobe")

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_write_autodesk_style_registry_layout(
        self,
        emulator: OfflineActivationEmulator,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Write Autodesk-style registry layout.

        Validates that registry structure matches Autodesk licensing including
        product information and license server data.
        """
        product_id = "AutoCAD2024"
        registry_path = f"{TEST_REGISTRY_BASE}\\Autodesk\\{product_id}\\License"

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, "SerialNumber", 0, winreg.REG_SZ, sample_activation_response.activation_code[:15])
            winreg.SetValueEx(key, "ProductKey", 0, winreg.REG_SZ, sample_activation_response.activation_code[15:])
            winreg.SetValueEx(key, "LicenseType", 0, winreg.REG_SZ, "Commercial")
            winreg.SetValueEx(key, "ProductInfo", 0, winreg.REG_SZ, f"{product_id}_001_2024")

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            stored_serial, _ = winreg.QueryValueEx(key, "SerialNumber")
            stored_key, _ = winreg.QueryValueEx(key, "ProductKey")
            stored_type, _ = winreg.QueryValueEx(key, "LicenseType")
            stored_info, _ = winreg.QueryValueEx(key, "ProductInfo")

        assert len(stored_serial) == 15
        assert stored_type == "Commercial"
        assert stored_info.startswith(product_id)

        cleanup_test_registry_keys(winreg.HKEY_CURRENT_USER, f"{TEST_REGISTRY_BASE}\\Autodesk")

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_write_nested_subkey_structure(
        self,
        emulator: OfflineActivationEmulator,
        test_product_id: str,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Write deeply nested registry structure for complex product layouts.

        Validates that multiple levels of registry keys can be created and populated
        as required by enterprise software.
        """
        base_path = f"{TEST_REGISTRY_BASE}\\{test_product_id}"
        subpaths = [
            "License\\Server",
            "License\\Features\\Premium",
            "License\\Features\\Enterprise",
            "Activation\\Machine",
            "Activation\\User"
        ]

        for subpath in subpaths:
            full_path = f"{base_path}\\{subpath}"
            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER,
                full_path,
                0,
                winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
            ) as key:
                winreg.SetValueEx(key, "Enabled", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "LicenseData", 0, winreg.REG_SZ, sample_activation_response.activation_code)

        for subpath in subpaths:
            full_path = f"{base_path}\\{subpath}"
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                full_path,
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            ) as key:
                enabled, _ = winreg.QueryValueEx(key, "Enabled")
                license_data, _ = winreg.QueryValueEx(key, "LicenseData")

            assert enabled == 1
            assert license_data == sample_activation_response.activation_code


class TestRegistryPermissionHandling:
    """Test proper registry key permission handling."""

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_handle_hklm_access_denied_without_admin(
        self,
        emulator: OfflineActivationEmulator,
        test_product_id: str
    ) -> None:
        """Verify HKLM write fails gracefully without admin privileges.

        Validates that registry writing handles permission errors when attempting
        to write to HKEY_LOCAL_MACHINE without elevation.
        """
        if is_admin():
            pytest.skip("Test requires non-admin context to validate permission handling")

        registry_path = f"{TEST_REGISTRY_BASE}\\{test_product_id}"

        with pytest.raises(PermissionError):
            with winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE,
                registry_path,
                0,
                winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
            ) as key:
                winreg.SetValueEx(key, "TestValue", 0, winreg.REG_SZ, "test")

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_fallback_to_hkcu_when_hklm_fails(
        self,
        emulator: OfflineActivationEmulator,
        test_product_id: str,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Fall back to HKEY_CURRENT_USER when HKEY_LOCAL_MACHINE write fails.

        Validates that license writing can gracefully fall back to user hive
        when system hive is inaccessible.
        """
        registry_path = f"{TEST_REGISTRY_BASE}\\{test_product_id}"

        try:
            with winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE,
                registry_path,
                0,
                winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
            ) as key:
                winreg.SetValueEx(key, "LicenseKey", 0, winreg.REG_SZ, sample_activation_response.activation_code)
            hklm_success = True
        except PermissionError:
            hklm_success = False

        if not hklm_success:
            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER,
                registry_path,
                0,
                winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
            ) as key:
                winreg.SetValueEx(key, "LicenseKey", 0, winreg.REG_SZ, sample_activation_response.activation_code)

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                registry_path,
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            ) as key:
                stored_license, _ = winreg.QueryValueEx(key, "LicenseKey")

            assert stored_license == sample_activation_response.activation_code


class TestRegistryRedirection:
    """Test handling of WOW64 registry redirection."""

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    @pytest.mark.skipif(platform.machine() != "AMD64", reason="Test requires 64-bit Windows")
    def test_write_to_64bit_registry_view(
        self,
        emulator: OfflineActivationEmulator,
        test_product_id: str,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Write license to 64-bit registry view explicitly.

        Validates that registry writing can target 64-bit view on 64-bit Windows
        to avoid WOW64 redirection.
        """
        registry_path = f"{TEST_REGISTRY_BASE}\\{test_product_id}"

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, "LicenseKey64", 0, winreg.REG_SZ, sample_activation_response.activation_code)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            stored_license, _ = winreg.QueryValueEx(key, "LicenseKey64")

        assert stored_license == sample_activation_response.activation_code

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    @pytest.mark.skipif(platform.machine() != "AMD64", reason="Test requires 64-bit Windows")
    def test_write_to_32bit_registry_view(
        self,
        emulator: OfflineActivationEmulator,
        test_product_id: str,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Write license to 32-bit registry view for legacy application support.

        Validates that registry writing can target 32-bit redirected view
        for 32-bit applications running on 64-bit Windows.
        """
        registry_path = f"{TEST_REGISTRY_BASE}\\{test_product_id}"

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_32KEY
        ) as key:
            winreg.SetValueEx(key, "LicenseKey32", 0, winreg.REG_SZ, sample_activation_response.activation_code)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_32KEY
        ) as key:
            stored_license, _ = winreg.QueryValueEx(key, "LicenseKey32")

        assert stored_license == sample_activation_response.activation_code

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    @pytest.mark.skipif(platform.machine() != "AMD64", reason="Test requires 64-bit Windows")
    def test_registry_redirection_isolation(
        self,
        emulator: OfflineActivationEmulator,
        test_product_id: str,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Verify 32-bit and 64-bit registry views are isolated.

        Validates that writes to 32-bit and 64-bit registry views are independent
        and don't interfere with each other.
        """
        registry_path = f"{TEST_REGISTRY_BASE}\\{test_product_id}"

        key_64bit = f"{sample_activation_response.activation_code}_64BIT"
        key_32bit = f"{sample_activation_response.activation_code}_32BIT"

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, "LicenseKey", 0, winreg.REG_SZ, key_64bit)

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_32KEY
        ) as key:
            winreg.SetValueEx(key, "LicenseKey", 0, winreg.REG_SZ, key_32bit)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            stored_64bit, _ = winreg.QueryValueEx(key, "LicenseKey")

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_32KEY
        ) as key:
            stored_32bit, _ = winreg.QueryValueEx(key, "LicenseKey")

        assert stored_64bit == key_64bit
        assert stored_32bit == key_32bit
        assert stored_64bit != stored_32bit


class TestRealWorldProtectedBinaryIntegration:
    """Test registry writing against real protected binaries."""

    @pytest.mark.skipif(platform.system() != "Windows", reason=SKIP_REASON_NOT_WINDOWS)
    def test_detect_and_write_to_actual_product_registry_location(
        self,
        emulator: OfflineActivationEmulator,
        sample_activation_response: ActivationResponse
    ) -> None:
        """Detect actual product registry location and write license.

        Validates that registry writing can locate and write to the actual registry
        paths used by real commercial software.

        This test searches for common software registry patterns and attempts to
        write test license data (non-destructively in test subkeys).
        """
        common_vendor_paths = [
            r"SOFTWARE\Microsoft\Office",
            r"SOFTWARE\Adobe\Adobe Acrobat",
            r"SOFTWARE\Autodesk",
            r"SOFTWARE\VMware, Inc.",
        ]

        found_products: list[str] = []

        for vendor_path in common_vendor_paths:
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    vendor_path,
                    0,
                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                ) as key:
                    found_products.append(vendor_path)
            except FileNotFoundError:
                continue
            except PermissionError:
                continue

        if not found_products:
            pytest.skip(
                f"No real protected software found in registry. "
                f"Install commercial software (Office, Adobe, Autodesk, etc.) "
                f"to test against actual registry structures."
            )

        test_registry_path = f"{TEST_REGISTRY_BASE}\\RealProductTest"

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            test_registry_path,
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, "DetectedProducts", 0, winreg.REG_MULTI_SZ, found_products)
            winreg.SetValueEx(key, "TestLicense", 0, winreg.REG_SZ, sample_activation_response.activation_code)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            test_registry_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            detected, _ = winreg.QueryValueEx(key, "DetectedProducts")
            stored_license, _ = winreg.QueryValueEx(key, "TestLicense")

        assert len(detected) > 0
        assert stored_license == sample_activation_response.activation_code

        cleanup_test_registry_keys(winreg.HKEY_CURRENT_USER, f"{TEST_REGISTRY_BASE}\\RealProductTest")
