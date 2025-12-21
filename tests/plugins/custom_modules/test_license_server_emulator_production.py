"""Production tests for license_server_emulator module.

Tests real license server emulation capabilities including FlexLM protocol
implementation, cryptographic operations, and license validation used for
bypassing commercial software protection.
"""

from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
import uuid
from datetime import datetime, timedelta
from typing import Any

import pytest


try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.asymmetric import rsa

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    from fastapi.testclient import TestClient

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from intellicrack.plugins.custom_modules.license_server_emulator import (
    CryptoManager,
    FlexLMEmulator,
    HardwareFingerprint,
    LicenseEntry,
    LicenseRequest,
    LicenseResponse,
    LicenseStatus,
    LicenseType,
)


pytestmark = pytest.mark.skipif(not HAS_CRYPTOGRAPHY, reason="cryptography library required")


class TestCryptoManager:
    """Test cryptographic operations for license generation."""

    def test_crypto_manager_generates_rsa_key_pair(self) -> None:
        """CryptoManager initializes with valid RSA 2048-bit key pair."""
        crypto = CryptoManager()

        assert crypto.private_key is not None
        assert crypto.public_key is not None
        assert crypto.private_key.key_size == 2048
        assert crypto.public_key.key_size == 2048

    def test_generate_license_key_creates_unique_keys(self) -> None:
        """License key generation produces unique keys for each call."""
        crypto = CryptoManager()

        key1 = crypto.generate_license_key("TestProduct", "perpetual")
        key2 = crypto.generate_license_key("TestProduct", "perpetual")

        assert key1 != key2
        assert isinstance(key1, str)
        assert isinstance(key2, str)
        assert len(key1) > 0
        assert len(key2) > 0

    def test_generate_license_key_format_is_consistent(self) -> None:
        """License keys follow consistent format with hyphens."""
        crypto = CryptoManager()

        license_key = crypto.generate_license_key("Product", "trial")

        parts = license_key.split("-")
        assert len(parts) == 4
        for part in parts:
            assert len(part) == 4
            assert part.isupper()

    def test_sign_license_data_creates_valid_signature(self) -> None:
        """License data signing produces verifiable RSA signature."""
        crypto = CryptoManager()

        data = {
            "product": "TestApp",
            "license_type": "perpetual",
            "expiry": "2099-12-31",
        }

        signature = crypto.sign_license_data(data)

        assert isinstance(signature, str)
        assert len(signature) > 0
        assert all(c in "0123456789abcdef" for c in signature.lower())

    def test_verify_license_signature_validates_correct_signature(self) -> None:
        """License signature verification accepts valid signatures."""
        crypto = CryptoManager()

        data = {
            "product": "TestApp",
            "version": "1.0",
            "user": "test@example.com",
        }

        signature = crypto.sign_license_data(data)
        is_valid = crypto.verify_license_signature(data, signature)

        assert is_valid is True

    def test_verify_license_signature_rejects_tampered_data(self) -> None:
        """License signature verification rejects tampered license data."""
        crypto = CryptoManager()

        original_data = {
            "product": "TestApp",
            "license_type": "trial",
        }

        signature = crypto.sign_license_data(original_data)

        tampered_data = {
            "product": "TestApp",
            "license_type": "perpetual",
        }

        is_valid = crypto.verify_license_signature(tampered_data, signature)
        assert is_valid is False

    def test_verify_license_signature_rejects_invalid_signature(self) -> None:
        """License signature verification rejects completely invalid signatures."""
        crypto = CryptoManager()

        data = {"product": "TestApp"}
        fake_signature = "0" * 512

        is_valid = crypto.verify_license_signature(data, fake_signature)
        assert is_valid is False

    def test_encrypt_decrypt_license_data_roundtrip(self) -> None:
        """License data encryption and decryption roundtrip preserves data."""
        crypto = CryptoManager()

        original_data = "TestLicenseKey-1234-5678-ABCD-EFGH"

        encrypted = crypto.encrypt_license_data(original_data)
        assert encrypted != original_data
        assert len(encrypted) > 0

        decrypted = crypto.decrypt_license_data(encrypted)
        assert decrypted == original_data

    def test_encrypt_license_data_produces_different_ciphertext(self) -> None:
        """Encrypting same data twice produces different ciphertext (IV randomization)."""
        crypto = CryptoManager()

        data = "SensitiveLicenseData"

        encrypted1 = crypto.encrypt_license_data(data)
        encrypted2 = crypto.encrypt_license_data(data)

        assert encrypted1 != encrypted2

    def test_decrypt_license_data_handles_invalid_ciphertext(self) -> None:
        """Decryption handles invalid ciphertext gracefully."""
        crypto = CryptoManager()

        invalid_encrypted = "notvalidhexdata"
        result = crypto.decrypt_license_data(invalid_encrypted)

        assert result == ""

    def test_sign_and_verify_complex_license_structure(self) -> None:
        """Signing and verification work with complex nested license structures."""
        crypto = CryptoManager()

        complex_data = {
            "product": "EnterpriseApp",
            "version": "2.5.0",
            "license_type": "subscription",
            "features": {
                "advanced_analytics": True,
                "cloud_sync": True,
                "api_access": False,
            },
            "limits": {
                "max_users": 100,
                "max_projects": 1000,
            },
            "metadata": {
                "issued_by": "LicenseServer",
                "issued_at": datetime.utcnow().isoformat(),
            },
        }

        signature = crypto.sign_license_data(complex_data)
        is_valid = crypto.verify_license_signature(complex_data, signature)

        assert is_valid is True


class TestHardwareFingerprint:
    """Test hardware fingerprinting for license binding."""

    def test_hardware_fingerprint_generates_consistent_hash(self) -> None:
        """Hardware fingerprint hash is consistent for same components."""
        fp1 = HardwareFingerprint(
            cpu_id="GenuineIntel-12345",
            motherboard_id="ASUS-Z690",
            disk_serial="SN123456",
            mac_address="00:11:22:33:44:55",
        )

        fp2 = HardwareFingerprint(
            cpu_id="GenuineIntel-12345",
            motherboard_id="ASUS-Z690",
            disk_serial="SN123456",
            mac_address="00:11:22:33:44:55",
        )

        hash1 = fp1.generate_hash()
        hash2 = fp2.generate_hash()

        assert hash1 == hash2
        assert len(hash1) == 16

    def test_hardware_fingerprint_different_for_different_hardware(self) -> None:
        """Hardware fingerprint differs when hardware components differ."""
        fp1 = HardwareFingerprint(
            cpu_id="Intel-123",
            motherboard_id="MB-1",
            disk_serial="DISK-1",
            mac_address="00:11:22:33:44:55",
        )

        fp2 = HardwareFingerprint(
            cpu_id="AMD-456",
            motherboard_id="MB-2",
            disk_serial="DISK-2",
            mac_address="AA:BB:CC:DD:EE:FF",
        )

        hash1 = fp1.generate_hash()
        hash2 = fp2.generate_hash()

        assert hash1 != hash2

    def test_hardware_fingerprint_sensitive_to_single_component_change(self) -> None:
        """Changing single hardware component changes fingerprint hash."""
        base_fp = HardwareFingerprint(
            cpu_id="CPU-123",
            motherboard_id="MB-456",
            disk_serial="DISK-789",
            mac_address="00:11:22:33:44:55",
        )

        modified_fp = HardwareFingerprint(
            cpu_id="CPU-123",
            motherboard_id="MB-456",
            disk_serial="DISK-999",
            mac_address="00:11:22:33:44:55",
        )

        assert base_fp.generate_hash() != modified_fp.generate_hash()


class TestFlexLMEmulator:
    """Test FlexLM license server protocol emulation."""

    @pytest.fixture
    def crypto_manager(self) -> CryptoManager:
        """Create crypto manager for tests."""
        return CryptoManager()

    @pytest.fixture
    def flexlm_emulator(self, crypto_manager: CryptoManager) -> FlexLMEmulator:
        """Create FlexLM emulator for tests."""
        return FlexLMEmulator(crypto_manager)

    def test_flexlm_emulator_initializes_with_vendor_keys(self, flexlm_emulator: FlexLMEmulator) -> None:
        """FlexLM emulator initializes with vendor-specific encryption keys."""
        assert flexlm_emulator.vendor_keys is not None
        assert "encryption_key" in flexlm_emulator.vendor_keys
        assert "seed1" in flexlm_emulator.vendor_keys
        assert len(flexlm_emulator.vendor_keys["encryption_key"]) == 16

    def test_flexlm_parse_request_extracts_feature_name(self, flexlm_emulator: FlexLMEmulator) -> None:
        """FlexLM request parsing extracts feature name from protocol data."""
        request_data = b"CHECKOUT FEATURE advanced_module VERSION 5.0"

        parsed = flexlm_emulator._parse_flexlm_request(request_data)

        assert parsed["feature"] == "advanced_module"

    def test_flexlm_process_request_grants_license(self, flexlm_emulator: FlexLMEmulator) -> None:
        """FlexLM request processing grants license for valid checkout."""
        request = {
            "type": "checkout",
            "feature": "analytics_engine",
            "version": "3.0",
        }

        response = flexlm_emulator._process_flexlm_request(request, "127.0.0.1")

        assert b"GRANTED" in response
        assert b"analytics_engine" in response

    def test_flexlm_vendor_encrypt_decrypt_roundtrip(self, flexlm_emulator: FlexLMEmulator) -> None:
        """Vendor-specific encryption and decryption preserves data."""
        original_data = b"LICENSE_REQUEST_DATA_12345"

        encrypted = flexlm_emulator._vendor_encrypt(original_data)
        assert encrypted != original_data

        decrypted = flexlm_emulator._vendor_decrypt(encrypted)
        assert decrypted == original_data

    def test_flexlm_vendor_validate_accepts_valid_request(self, flexlm_emulator: FlexLMEmulator) -> None:
        """Vendor validation accepts properly formatted requests."""
        valid_data = b"VEND_LICENSE_REQUEST"

        is_valid = flexlm_emulator._vendor_validate(valid_data)
        assert is_valid is True

    def test_flexlm_vendor_validate_rejects_short_data(self, flexlm_emulator: FlexLMEmulator) -> None:
        """Vendor validation rejects data shorter than minimum length."""
        short_data = b"ABC"

        is_valid = flexlm_emulator._vendor_validate(short_data)
        assert is_valid is False

    def test_flexlm_add_feature_registers_licensed_feature(self, flexlm_emulator: FlexLMEmulator) -> None:
        """Adding feature registers it in available features list."""
        feature = {
            "name": "premium_analytics",
            "version": "2.0",
            "count": 100,
            "expiry": "2099-12-31",
        }

        flexlm_emulator.add_feature(feature)

        assert "premium_analytics" in flexlm_emulator.features
        assert flexlm_emulator.features["premium_analytics"]["version"] == "2.0"

    def test_flexlm_create_feature_list_formats_correctly(self, flexlm_emulator: FlexLMEmulator) -> None:
        """Feature list creation formats features in FlexLM protocol format."""
        flexlm_emulator.add_feature(
            {
                "name": "module_a",
                "version": "1.5",
                "count": "uncounted",
                "expiry": "permanent",
            }
        )

        flexlm_emulator.add_feature(
            {
                "name": "module_b",
                "version": "2.0",
                "count": 50,
                "expiry": "2025-12-31",
            }
        )

        feature_list = flexlm_emulator._create_feature_list()

        assert b"FEATURE module_a" in feature_list
        assert b"VERSION 1.5" in feature_list
        assert b"FEATURE module_b" in feature_list

    def test_flexlm_create_status_response_includes_server_info(self, flexlm_emulator: FlexLMEmulator) -> None:
        """Status response includes server version and active license count."""
        status = flexlm_emulator._create_status_response()

        assert b"server_version" in status
        assert b"vendor_daemon" in status
        assert b"active_licenses" in status

    def test_flexlm_vendor_encryption_includes_checksum(self, flexlm_emulator: FlexLMEmulator) -> None:
        """Vendor encryption appends checksum for data integrity."""
        data = b"TEST_DATA"

        encrypted = flexlm_emulator._vendor_encrypt(data)

        assert len(encrypted) > len(data)

    def test_flexlm_vendor_decryption_validates_checksum(self, flexlm_emulator: FlexLMEmulator) -> None:
        """Vendor decryption validates checksum before decryption."""
        data = b"VALID_LICENSE_DATA"

        encrypted = flexlm_emulator._vendor_encrypt(data)
        decrypted = flexlm_emulator._vendor_decrypt(encrypted)

        assert decrypted == data


class TestLicenseServerIntegration:
    """Test complete license server workflows."""

    @pytest.fixture
    def crypto_manager(self) -> CryptoManager:
        """Create crypto manager for integration tests."""
        return CryptoManager()

    def test_complete_license_generation_and_validation_workflow(self, crypto_manager: CryptoManager) -> None:
        """End-to-end license generation, signing, and validation works."""
        license_key = crypto_manager.generate_license_key("EnterpriseApp", "subscription")

        license_data = {
            "license_key": license_key,
            "product": "EnterpriseApp",
            "license_type": "subscription",
            "expiry": (datetime.utcnow() + timedelta(days=365)).isoformat(),
            "max_users": 100,
        }

        signature = crypto_manager.sign_license_data(license_data)
        assert len(signature) > 0

        is_valid = crypto_manager.verify_license_signature(license_data, signature)
        assert is_valid is True

    def test_encrypted_license_transmission_workflow(self, crypto_manager: CryptoManager) -> None:
        """License data encryption for secure transmission works."""
        license_key = crypto_manager.generate_license_key("SecureApp", "perpetual")

        encrypted = crypto_manager.encrypt_license_data(license_key)
        assert encrypted != license_key

        decrypted = crypto_manager.decrypt_license_data(encrypted)
        assert decrypted == license_key

    def test_hardware_bound_license_validation(self) -> None:
        """Hardware-bound license validation checks fingerprint match."""
        fp = HardwareFingerprint(
            cpu_id="Intel-Core-i7",
            motherboard_id="ASUS-Z690",
            disk_serial="WD-1234567890",
            mac_address="00:11:22:33:44:55",
        )

        hardware_hash = fp.generate_hash()

        assert len(hardware_hash) == 16
        assert hardware_hash == fp.generate_hash()

        different_fp = HardwareFingerprint(
            cpu_id="AMD-Ryzen",
            motherboard_id="MSI-B550",
            disk_serial="Samsung-9876543210",
            mac_address="AA:BB:CC:DD:EE:FF",
        )

        assert hardware_hash != different_fp.generate_hash()


class TestLicenseProtocolEdgeCases:
    """Test edge cases and error handling."""

    def test_crypto_manager_handles_empty_data_signing(self) -> None:
        """Signing empty or minimal data structures works."""
        crypto = CryptoManager()

        empty_data: dict[str, Any] = {}
        signature = crypto.sign_license_data(empty_data)

        assert isinstance(signature, str)
        assert len(signature) > 0

    def test_crypto_manager_handles_large_data_encryption(self) -> None:
        """Encryption handles large license data payloads."""
        crypto = CryptoManager()

        large_data = "X" * 10000
        encrypted = crypto.encrypt_license_data(large_data)
        decrypted = crypto.decrypt_license_data(encrypted)

        assert decrypted == large_data

    def test_flexlm_emulator_handles_malformed_requests(self) -> None:
        """FlexLM emulator handles malformed protocol requests gracefully."""
        crypto = CryptoManager()
        emulator = FlexLMEmulator(crypto)

        malformed_data = b"\x00\xFF\xAB\xCD\xEF"
        parsed = emulator._parse_flexlm_request(malformed_data)

        assert "type" in parsed

    def test_hardware_fingerprint_handles_empty_components(self) -> None:
        """Hardware fingerprint generation handles missing components."""
        fp = HardwareFingerprint()

        hardware_hash = fp.generate_hash()
        assert isinstance(hardware_hash, str)
        assert len(hardware_hash) == 16

    def test_license_key_uniqueness_across_products(self) -> None:
        """License keys are unique across different products."""
        crypto = CryptoManager()

        keys = set()
        products = ["ProductA", "ProductB", "ProductC"]
        license_types = ["trial", "perpetual", "subscription"]

        for product in products:
            for license_type in license_types:
                key = crypto.generate_license_key(product, license_type)
                assert key not in keys
                keys.add(key)

        assert len(keys) == len(products) * len(license_types)


class TestCryptoManagerPerformance:
    """Test cryptographic operations performance."""

    def test_license_key_generation_performance(self) -> None:
        """License key generation completes within acceptable time."""
        crypto = CryptoManager()

        start_time = time.time()
        for _ in range(100):
            crypto.generate_license_key("TestProduct", "trial")
        elapsed = time.time() - start_time

        assert elapsed < 1.0

    def test_signature_generation_performance(self) -> None:
        """License signing completes within acceptable time."""
        crypto = CryptoManager()

        data = {
            "product": "TestApp",
            "version": "1.0",
            "features": ["feature1", "feature2", "feature3"],
        }

        start_time = time.time()
        for _ in range(50):
            crypto.sign_license_data(data)
        elapsed = time.time() - start_time

        assert elapsed < 2.0

    def test_encryption_decryption_performance(self) -> None:
        """License encryption/decryption completes within acceptable time."""
        crypto = CryptoManager()

        test_data = "LICENSE-KEY-" + "A" * 1000

        start_time = time.time()
        for _ in range(100):
            encrypted = crypto.encrypt_license_data(test_data)
            crypto.decrypt_license_data(encrypted)
        elapsed = time.time() - start_time

        assert elapsed < 1.0


class TestFlexLMProtocolCompliance:
    """Test FlexLM protocol compliance."""

    def test_flexlm_response_format_compliance(self) -> None:
        """FlexLM responses match expected protocol format."""
        crypto = CryptoManager()
        emulator = FlexLMEmulator(crypto)

        request = {
            "type": "checkout",
            "feature": "cad_module",
            "version": "5.2",
        }

        response = emulator._process_flexlm_request(request, "192.168.1.100")

        assert b"GRANTED" in response or b"DENIED" in response
        assert b"\n" in response

    def test_flexlm_vendor_key_entropy(self) -> None:
        """Vendor encryption keys have sufficient entropy."""
        crypto = CryptoManager()
        emulator = FlexLMEmulator(crypto)

        keys = [emulator._generate_vendor_keys() for _ in range(10)]

        unique_encryption_keys = {k["encryption_key"] for k in keys}
        assert len(unique_encryption_keys) == 10

        for key_set in keys:
            assert key_set["seed1"] != key_set["seed2"]
            assert key_set["seed2"] != key_set["seed3"]
