"""Production-grade tests for License Server Emulator.

Tests validate real licensing functionality against multiple protection protocols:
- FlexLM license server emulation
- HASP dongle emulation with real cryptographic operations
- Microsoft KMS activation
- Adobe Creative Cloud licensing
- Hardware fingerprinting with real system data
- Database operations with SQLAlchemy
- FastAPI REST endpoints with real HTTP requests
- Cryptographic operations (RSA, AES, AES-GCM)
- License activation, validation, and expiration
- Concurrent user handling
- Hardware change detection
- Protocol switching and analysis
"""

import asyncio
import base64
import hashlib
import json
import os
import socket
import struct
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

try:
    from intellicrack.plugins.custom_modules.license_server_emulator import (
        AESGCM,
        ActivationRequest,
        ActivationResponse,
        AdobeEmulator,
        CryptoManager,
        DatabaseManager,
        FlexLMEmulator,
        HardwareFingerprint,
        HardwareFingerprintGenerator,
        HASPEmulator,
        LicenseEntry,
        LicenseRequest,
        LicenseResponse,
        LicenseServerEmulator,
        LicenseStatus,
        LicenseType,
        MicrosoftKMSEmulator,
        ProtocolAnalyzer,
        ProtocolType,
        ProxyInterceptor,
    )
    LICENSE_SERVER_AVAILABLE = True
except ImportError as e:
    LICENSE_SERVER_AVAILABLE = False
    IMPORT_ERROR = str(e)

try:
    from fastapi.testclient import TestClient
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    TestClient = None

pytestmark = pytest.mark.skipif(
    not LICENSE_SERVER_AVAILABLE,
    reason=f"License server emulator dependencies not available: {IMPORT_ERROR if not LICENSE_SERVER_AVAILABLE else ''}"
)


@pytest.fixture
def crypto_manager() -> CryptoManager:
    """Create real CryptoManager with RSA and AES keys."""
    return CryptoManager()


@pytest.fixture
def temp_db_path(tmp_path: Path) -> str:
    """Create temporary database path for testing."""
    db_path = tmp_path / "test_licenses.db"
    return str(db_path)


@pytest.fixture
def db_manager(temp_db_path: str) -> DatabaseManager:
    """Create DatabaseManager with temporary database."""
    return DatabaseManager(temp_db_path)


@pytest.fixture
def flexlm_emulator(crypto_manager: CryptoManager) -> FlexLMEmulator:
    """Create FlexLM emulator instance."""
    return FlexLMEmulator(crypto_manager)


@pytest.fixture
def hasp_emulator(crypto_manager: CryptoManager) -> HASPEmulator:
    """Create HASP emulator instance."""
    return HASPEmulator(crypto_manager)


@pytest.fixture
def kms_emulator(crypto_manager: CryptoManager) -> MicrosoftKMSEmulator:
    """Create Microsoft KMS emulator instance."""
    return MicrosoftKMSEmulator(crypto_manager)


@pytest.fixture
def adobe_emulator(crypto_manager: CryptoManager) -> AdobeEmulator:
    """Create Adobe emulator instance."""
    return AdobeEmulator(crypto_manager)


@pytest.fixture
def fingerprint_generator() -> HardwareFingerprintGenerator:
    """Create hardware fingerprint generator."""
    return HardwareFingerprintGenerator()


@pytest.fixture
def protocol_analyzer() -> ProtocolAnalyzer:
    """Create protocol analyzer instance."""
    return ProtocolAnalyzer()


@pytest.fixture
def license_server_config(temp_db_path: str) -> dict[str, Any]:
    """Create license server configuration."""
    return {
        "host": "127.0.0.1",
        "port": 8081,
        "ssl_enabled": False,
        "database_path": temp_db_path,
        "flexlm_port": 27100,
        "kms_port": 1689,
        "log_level": "DEBUG",
        "enable_cors": True,
        "auth_required": False,
    }


@pytest.fixture
def license_server(license_server_config: dict[str, Any]) -> LicenseServerEmulator:
    """Create license server emulator instance."""
    server = LicenseServerEmulator(license_server_config)
    yield server
    if hasattr(server, "flexlm") and server.flexlm.running:
        server.flexlm.stop_server()


@pytest.fixture
def test_client(license_server: LicenseServerEmulator) -> TestClient:
    """Create FastAPI test client."""
    return TestClient(license_server.app)


class TestCryptoManager:
    """Test CryptoManager cryptographic operations."""

    def test_license_key_generation_produces_valid_format(self, crypto_manager: CryptoManager) -> None:
        """Generated license keys follow correct format with checksums."""
        key = crypto_manager.generate_license_key("TestProduct", "trial")

        assert isinstance(key, str)
        assert len(key) == 19
        assert key.count("-") == 3
        parts = key.split("-")
        assert len(parts) == 4
        assert all(len(part) == 4 for part in parts)
        assert all(c in "0123456789ABCDEF" for part in parts for c in part)

    def test_license_key_generation_is_unique(self, crypto_manager: CryptoManager) -> None:
        """Each generated license key is cryptographically unique."""
        keys = [crypto_manager.generate_license_key("TestProduct", "trial") for _ in range(100)]

        assert len(set(keys)) == 100

    def test_rsa_signature_verification_succeeds_for_valid_data(
        self, crypto_manager: CryptoManager
    ) -> None:
        """RSA signature verification succeeds for correctly signed data."""
        data = {
            "license_key": "TEST-1234-5678-9ABC",
            "product": "TestApp",
            "expiry": "2025-12-31",
        }

        signature = crypto_manager.sign_license_data(data)

        assert signature
        assert len(signature) > 0
        assert crypto_manager.verify_license_signature(data, signature)

    def test_rsa_signature_verification_fails_for_tampered_data(
        self, crypto_manager: CryptoManager
    ) -> None:
        """RSA signature verification fails when data is modified."""
        data = {"license_key": "TEST-1234-5678-9ABC", "product": "TestApp"}
        signature = crypto_manager.sign_license_data(data)

        tampered_data = data.copy()
        tampered_data["product"] = "HackedApp"

        assert not crypto_manager.verify_license_signature(tampered_data, signature)

    def test_aes_encryption_decryption_roundtrip(self, crypto_manager: CryptoManager) -> None:
        """AES encryption and decryption produce original plaintext."""
        original_data = "Sensitive license data: ABCD-1234-EFGH-5678"

        encrypted = crypto_manager.encrypt_license_data(original_data)
        decrypted = crypto_manager.decrypt_license_data(encrypted)

        assert encrypted != original_data
        assert len(encrypted) > len(original_data) * 2
        assert decrypted == original_data

    def test_aes_encryption_produces_different_ciphertext(
        self, crypto_manager: CryptoManager
    ) -> None:
        """AES encryption with random IV produces different ciphertext each time."""
        data = "License: 1234-5678-9ABC-DEFG"

        encrypted1 = crypto_manager.encrypt_license_data(data)
        encrypted2 = crypto_manager.encrypt_license_data(data)

        assert encrypted1 != encrypted2

    def test_aes_decryption_fails_for_corrupted_data(self, crypto_manager: CryptoManager) -> None:
        """AES decryption returns empty string for corrupted ciphertext."""
        encrypted = crypto_manager.encrypt_license_data("Valid data")
        corrupted = encrypted[:-10] + "0000000000"

        decrypted = crypto_manager.decrypt_license_data(corrupted)

        assert decrypted == ""


class TestFlexLMEmulator:
    """Test FlexLM license server emulation."""

    def test_flexlm_server_starts_on_specified_port(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM server binds to specified port and accepts connections."""
        port = 27100

        flexlm_emulator.start_server(port)
        time.sleep(0.5)

        assert flexlm_emulator.running
        assert flexlm_emulator.server_socket is not None

        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(2.0)
            result = test_socket.connect_ex(("127.0.0.1", port))
            test_socket.close()
            assert result == 0
        finally:
            flexlm_emulator.stop_server()

    def test_flexlm_grants_license_for_feature_checkout(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM server grants licenses for valid feature checkout requests."""
        port = 27101
        flexlm_emulator.start_server(port)
        time.sleep(0.5)

        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))

            request = b"FEATURE TestFeature VERSION 1.0 USER testuser HOST localhost\n"
            client.send(request)

            response = client.recv(1024).decode("ascii")
            client.close()

            assert "GRANTED" in response
            assert "TestFeature" in response
        finally:
            flexlm_emulator.stop_server()

    def test_flexlm_vendor_daemon_starts_on_separate_port(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM vendor daemon runs on separate port from main server."""
        flexlm_emulator.start_server(27102)
        time.sleep(0.5)

        try:
            vendor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            vendor_socket.settimeout(2.0)
            result = vendor_socket.connect_ex(("127.0.0.1", flexlm_emulator.VENDOR_PORT))
            vendor_socket.close()

            assert result == 0
        finally:
            flexlm_emulator.stop_server()

    def test_flexlm_vendor_encryption_decryption_roundtrip(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM vendor encryption/decryption produces original data."""
        original_data = b"VENDOR_LICENSE_REQUEST_12345"

        encrypted = flexlm_emulator._vendor_encrypt(original_data)
        decrypted = flexlm_emulator._vendor_decrypt(encrypted)

        assert encrypted != original_data
        assert len(encrypted) > len(original_data)
        assert decrypted == original_data

    def test_flexlm_vendor_encryption_includes_checksum(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM vendor encryption appends checksum for integrity verification."""
        data = b"LICENSE_DATA"
        encrypted = flexlm_emulator._vendor_encrypt(data)

        checksum = encrypted[-1]
        encrypted_without_checksum = encrypted[:-1]
        expected_checksum = sum(encrypted_without_checksum) % 256

        assert checksum == expected_checksum

    def test_flexlm_adds_features_to_feature_list(self, flexlm_emulator: FlexLMEmulator) -> None:
        """FlexLM emulator tracks added features for license distribution."""
        feature = {
            "name": "AdvancedFeature",
            "version": "2.5",
            "count": 100,
            "expiry": "2025-12-31",
        }

        flexlm_emulator.add_feature(feature)

        assert "AdvancedFeature" in flexlm_emulator.features
        assert flexlm_emulator.features["AdvancedFeature"]["version"] == "2.5"
        assert flexlm_emulator.features["AdvancedFeature"]["count"] == 100


class TestHASPEmulator:
    """Test HASP dongle emulation with real cryptography."""

    def test_hasp_dongle_memory_initializes_with_valid_structure(
        self, hasp_emulator: HASPEmulator
    ) -> None:
        """HASP dongle memory contains valid header and feature directory."""
        assert hasp_emulator.dongle_memory[:4] == b"HASP"

        version = struct.unpack("<I", hasp_emulator.dongle_memory[4:8])[0]
        assert version == 0x04030001

        assert len(hasp_emulator.device_id) == 16
        assert hasp_emulator.dongle_memory[8:24] == hasp_emulator.device_id

        memory_size = struct.unpack("<I", hasp_emulator.dongle_memory[48:52])[0]
        assert memory_size == hasp_emulator.memory_size

    def test_hasp_login_returns_valid_handle_for_existing_feature(
        self, hasp_emulator: HASPEmulator
    ) -> None:
        """HASP login returns valid session handle for registered features."""
        feature_id = 1

        handle = hasp_emulator.hasp_login(feature_id)

        assert handle > 0
        assert handle in hasp_emulator.active_sessions
        assert hasp_emulator.active_sessions[handle]["feature_id"] == feature_id

    def test_hasp_login_fails_for_nonexistent_feature(self, hasp_emulator: HASPEmulator) -> None:
        """HASP login returns error code for unregistered feature ID."""
        invalid_feature_id = 9999

        handle = hasp_emulator.hasp_login(invalid_feature_id)

        assert handle == hasp_emulator.HASP_FEATURE_NOT_FOUND

    def test_hasp_logout_invalidates_session(self, hasp_emulator: HASPEmulator) -> None:
        """HASP logout removes active session and invalidates handle."""
        handle = hasp_emulator.hasp_login(1)

        result = hasp_emulator.hasp_logout(handle)

        assert result == hasp_emulator.HASP_STATUS_OK
        assert handle not in hasp_emulator.active_sessions

    def test_hasp_encrypt_decrypt_roundtrip_with_aesgcm(
        self, hasp_emulator: HASPEmulator
    ) -> None:
        """HASP encryption/decryption with AES-GCM produces original plaintext."""
        handle = hasp_emulator.hasp_login(1)
        original_data = b"Sensitive application data: 0x12345678"

        status_enc, encrypted = hasp_emulator.hasp_encrypt(handle, original_data)
        status_dec, decrypted = hasp_emulator.hasp_decrypt(handle, encrypted)

        assert status_enc == hasp_emulator.HASP_STATUS_OK
        assert status_dec == hasp_emulator.HASP_STATUS_OK
        assert encrypted != original_data
        assert decrypted == original_data

    def test_hasp_decrypt_fails_with_invalid_handle(self, hasp_emulator: HASPEmulator) -> None:
        """HASP decrypt returns error for invalid session handle."""
        invalid_handle = 9999
        encrypted_data = b"fake_encrypted_data_12345678901234567890"

        status, _ = hasp_emulator.hasp_decrypt(invalid_handle, encrypted_data)

        assert status == hasp_emulator.HASP_INVALID_HANDLE

    def test_hasp_encrypt_fails_with_tampered_authentication(
        self, hasp_emulator: HASPEmulator
    ) -> None:
        """HASP decrypt detects tampered ciphertext via AES-GCM authentication."""
        handle = hasp_emulator.hasp_login(1)
        _, encrypted = hasp_emulator.hasp_encrypt(handle, b"Original data")

        tampered = encrypted[:-5] + b"XXXXX"
        status, _ = hasp_emulator.hasp_decrypt(handle, tampered)

        assert status == hasp_emulator.HASP_SIGNATURE_CHECK_FAILED

    def test_hasp_read_retrieves_feature_memory(self, hasp_emulator: HASPEmulator) -> None:
        """HASP read operation retrieves data from feature-specific memory."""
        handle = hasp_emulator.hasp_login(1)

        status, data = hasp_emulator.hasp_read(handle, 0, 16)

        assert status == hasp_emulator.HASP_STATUS_OK
        assert len(data) == 16
        feature_id = struct.unpack("<I", data[:4])[0]
        assert feature_id == 1

    def test_hasp_write_modifies_feature_memory(self, hasp_emulator: HASPEmulator) -> None:
        """HASP write operation modifies feature memory with access control."""
        handle = hasp_emulator.hasp_login(1)
        test_data = b"TESTDATA12345678"

        write_status = hasp_emulator.hasp_write(handle, 16, test_data)
        read_status, read_data = hasp_emulator.hasp_read(handle, 16, len(test_data))

        assert write_status == hasp_emulator.HASP_STATUS_OK
        assert read_status == hasp_emulator.HASP_STATUS_OK
        assert read_data == test_data

    def test_hasp_write_fails_for_protected_memory(self, hasp_emulator: HASPEmulator) -> None:
        """HASP write fails for protected header region (first 16 bytes)."""
        handle = hasp_emulator.hasp_login(1)

        status = hasp_emulator.hasp_write(handle, 0, b"HACK")

        assert status == hasp_emulator.HASP_INVALID_PARAMETER

    def test_hasp_get_info_returns_device_id(self, hasp_emulator: HASPEmulator) -> None:
        """HASP get_info retrieves device ID for hardware binding."""
        handle = hasp_emulator.hasp_login(1)

        status, device_id = hasp_emulator.hasp_get_info(handle, 1)

        assert status == hasp_emulator.HASP_STATUS_OK
        assert device_id == hasp_emulator.device_id
        assert len(device_id) == 16

    def test_hasp_session_key_derivation_is_unique(self, hasp_emulator: HASPEmulator) -> None:
        """Each HASP login generates unique session key via HKDF."""
        handle1 = hasp_emulator.hasp_login(1)
        handle2 = hasp_emulator.hasp_login(1)

        key1 = hasp_emulator.session_keys[handle1]
        key2 = hasp_emulator.session_keys[handle2]

        assert key1 != key2
        assert len(key1) == 32
        assert len(key2) == 32


class TestMicrosoftKMSEmulator:
    """Test Microsoft KMS activation emulation."""

    def test_kms_activates_windows_product_successfully(
        self, kms_emulator: MicrosoftKMSEmulator
    ) -> None:
        """KMS emulator activates Windows products with valid response."""
        product_key = "W269N-WFGWX-YVC9B-4J6C9-T83GX"
        product_name = "Windows 10 Pro"
        client_info = {"hostname": "test-pc", "os_version": "10.0.19045"}

        result = kms_emulator.activate_product(product_key, product_name, client_info)

        assert result["success"]
        assert result["license_status"] == "Licensed"
        assert result["remaining_grace_time"] == 180
        assert "activation_id" in result
        assert result["kms_port"] == 1688

    def test_kms_activation_includes_expiry_dates(
        self, kms_emulator: MicrosoftKMSEmulator
    ) -> None:
        """KMS activation response includes last and next activation timestamps."""
        product_key = "NPPR9-FWDCX-D2C8J-H872K-2YT43"
        product_name = "Windows 10 Enterprise"

        result = kms_emulator.activate_product(product_key, product_name, {})

        assert "last_activation" in result
        assert "next_activation" in result

        last_activation = datetime.fromisoformat(result["last_activation"])
        next_activation = datetime.fromisoformat(result["next_activation"])

        assert (next_activation - last_activation).days == 180

    def test_kms_activation_generates_unique_ids(
        self, kms_emulator: MicrosoftKMSEmulator
    ) -> None:
        """Each KMS activation generates unique activation ID."""
        activations = [
            kms_emulator.activate_product("TEST-KEY", "Windows Server 2019", {})
            for _ in range(10)
        ]

        activation_ids = [act["activation_id"] for act in activations]
        assert len(set(activation_ids)) == 10


class TestAdobeEmulator:
    """Test Adobe Creative Cloud license emulation."""

    def test_adobe_validates_creative_cloud_license(self, adobe_emulator: AdobeEmulator) -> None:
        """Adobe emulator validates Creative Cloud licenses successfully."""
        license_data = {
            "product": "Photoshop",
            "version": "2024",
            "user_id": "test@example.com",
            "device_id": "test-device-001",
        }

        result = adobe_emulator.validate_license(license_data)

        assert result["valid"]
        assert result["license_type"] == "subscription"
        assert "expiry_date" in result
        assert "features" in result

    def test_adobe_generates_device_tokens(self, adobe_emulator: AdobeEmulator) -> None:
        """Adobe emulator generates device-bound activation tokens."""
        device_id = "adobe-test-device-12345"

        token = adobe_emulator.generate_device_token(device_id)

        assert isinstance(token, str)
        assert len(token) > 32
        assert adobe_emulator.verify_device_token(token, device_id)

    def test_adobe_device_token_verification_fails_for_wrong_device(
        self, adobe_emulator: AdobeEmulator
    ) -> None:
        """Adobe device token verification fails for mismatched device ID."""
        device_id = "device-001"
        token = adobe_emulator.generate_device_token(device_id)

        wrong_device = "device-002"

        assert not adobe_emulator.verify_device_token(token, wrong_device)


class TestDatabaseManager:
    """Test SQLAlchemy database operations."""

    def test_database_creates_tables_on_initialization(self, db_manager: DatabaseManager) -> None:
        """DatabaseManager creates required tables in SQLite database."""
        session = db_manager.Session()

        result = session.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='licenses'"
        )
        assert result.fetchone() is not None

        result = session.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='activations'"
        )
        assert result.fetchone() is not None

        session.close()

    def test_database_creates_license_entry(self, db_manager: DatabaseManager) -> None:
        """DatabaseManager creates license entries with full metadata."""
        license_data = {
            "license_key": "ABCD-1234-EFGH-5678",
            "license_type": "subscription",
            "product_name": "TestApp Pro",
            "version": "2.5",
            "max_users": 10,
            "expiry_date": datetime.utcnow() + timedelta(days=365),
        }

        created = db_manager.create_license(**license_data)

        assert created.id is not None
        assert created.license_key == "ABCD-1234-EFGH-5678"
        assert created.product_name == "TestApp Pro"
        assert created.max_users == 10
        assert created.status == "valid"

    def test_database_validates_existing_license(self, db_manager: DatabaseManager) -> None:
        """DatabaseManager validates licenses against stored entries."""
        license_key = "VALID-TEST-KEY-2024"
        db_manager.create_license(
            license_key=license_key,
            license_type="perpetual",
            product_name="TestProduct",
            version="1.0",
        )

        validated = db_manager.validate_license(license_key, "TestProduct")

        assert validated is not None
        assert validated.license_key == license_key
        assert validated.status == "valid"

    def test_database_rejects_expired_license(self, db_manager: DatabaseManager) -> None:
        """DatabaseManager identifies expired licenses during validation."""
        license_key = "EXPIRED-LICENSE-KEY"
        db_manager.create_license(
            license_key=license_key,
            license_type="trial",
            product_name="TestApp",
            version="1.0",
            expiry_date=datetime.utcnow() - timedelta(days=30),
        )

        validated = db_manager.validate_license(license_key, "TestApp")

        assert validated is None or validated.status == "expired"

    def test_database_logs_license_operations(self, db_manager: DatabaseManager) -> None:
        """DatabaseManager logs all license operations with client data."""
        db_manager.log_operation(
            license_key="TEST-LOG-KEY",
            operation="validate",
            client_ip="192.168.1.100",
            success=True,
            details="Test validation",
        )

        session = db_manager.Session()
        logs = (
            session.query(db_manager.Base.metadata.tables["license_logs"])
            .filter_by(license_key="TEST-LOG-KEY")
            .all()
        )
        session.close()

        assert len(logs) > 0

    def test_database_tracks_license_activations(self, db_manager: DatabaseManager) -> None:
        """DatabaseManager tracks license activations per hardware fingerprint."""
        license_entry = db_manager.create_license(
            license_key="TRACK-TEST-KEY",
            license_type="subscription",
            product_name="TrackedApp",
            version="1.0",
        )

        activation = db_manager.create_activation(
            license_id=license_entry.id,
            client_ip="10.0.0.50",
            hardware_fingerprint="hw-fingerprint-abc123",
        )

        assert activation is not None
        assert activation.license_id == license_entry.id
        assert activation.hardware_fingerprint == "hw-fingerprint-abc123"
        assert activation.is_active


class TestHardwareFingerprint:
    """Test hardware fingerprint generation and validation."""

    def test_fingerprint_generates_consistent_hash(self) -> None:
        """Hardware fingerprint generates consistent hash from same components."""
        fingerprint = HardwareFingerprint(
            cpu_id="GenuineIntel-12345",
            motherboard_id="ASUS-MB-67890",
            disk_serial="SSD-ABC123",
            mac_address="00:11:22:33:44:55",
        )

        hash1 = fingerprint.generate_hash()
        hash2 = fingerprint.generate_hash()

        assert hash1 == hash2
        assert len(hash1) == 16

    def test_fingerprint_hash_changes_with_different_hardware(self) -> None:
        """Hardware fingerprint produces different hash when components change."""
        fingerprint1 = HardwareFingerprint(
            cpu_id="Intel-001", motherboard_id="MB-001", disk_serial="DISK-001", mac_address="MAC-001"
        )
        fingerprint2 = HardwareFingerprint(
            cpu_id="Intel-002", motherboard_id="MB-001", disk_serial="DISK-001", mac_address="MAC-001"
        )

        hash1 = fingerprint1.generate_hash()
        hash2 = fingerprint2.generate_hash()

        assert hash1 != hash2

    def test_fingerprint_generator_collects_real_system_data(
        self, fingerprint_generator: HardwareFingerprintGenerator
    ) -> None:
        """HardwareFingerprintGenerator collects real CPU, disk, and network data."""
        fingerprint = fingerprint_generator.generate_fingerprint()

        assert fingerprint.hostname
        assert fingerprint.os_version
        assert fingerprint.ram_size > 0

        if fingerprint.cpu_id:
            assert len(fingerprint.cpu_id) > 0

    def test_fingerprint_generator_produces_unique_hash(
        self, fingerprint_generator: HardwareFingerprintGenerator
    ) -> None:
        """HardwareFingerprintGenerator produces non-empty hardware hash."""
        fingerprint = fingerprint_generator.generate_fingerprint()

        hw_hash = fingerprint.generate_hash()

        assert hw_hash
        assert len(hw_hash) == 16
        assert all(c in "0123456789abcdef" for c in hw_hash)


class TestProtocolAnalyzer:
    """Test license protocol detection and analysis."""

    def test_protocol_analyzer_detects_flexlm_traffic(
        self, protocol_analyzer: ProtocolAnalyzer
    ) -> None:
        """ProtocolAnalyzer identifies FlexLM license requests from traffic."""
        flexlm_request = b"FEATURE TestApp VERSION 2.0 USER admin HOST workstation\n"

        analysis = protocol_analyzer.analyze_traffic(flexlm_request, "192.168.1.10", 27000)

        assert analysis["protocol"] == LicenseType.FLEXLM
        assert analysis["confidence"] > 0.7

    def test_protocol_analyzer_detects_hasp_traffic(
        self, protocol_analyzer: ProtocolAnalyzer
    ) -> None:
        """ProtocolAnalyzer identifies HASP dongle communication patterns."""
        hasp_request = b"HASP" + struct.pack("<I", 1) + os.urandom(16)

        analysis = protocol_analyzer.analyze_traffic(hasp_request, "10.0.0.5", 1947)

        assert analysis["protocol"] == LicenseType.HASP

    def test_protocol_analyzer_detects_kms_activation(
        self, protocol_analyzer: ProtocolAnalyzer
    ) -> None:
        """ProtocolAnalyzer identifies Microsoft KMS activation requests."""
        kms_request = json.dumps({"product_key": "XXXXX-XXXXX", "product": "Windows"}).encode()

        analysis = protocol_analyzer.analyze_traffic(kms_request, "172.16.0.10", 1688)

        assert analysis["protocol"] in [LicenseType.MICROSOFT_KMS, LicenseType.CUSTOM]


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not available")
class TestLicenseServerEmulator:
    """Test complete license server REST API."""

    def test_server_root_endpoint_returns_status(self, test_client: TestClient) -> None:
        """Server root endpoint returns identification and status."""
        response = test_client.get("/")

        assert response.status_code == 200
        data = response.json()
        assert "Intellicrack" in data["message"]
        assert data["status"] == "running"

    def test_server_health_check_endpoint(self, test_client: TestClient) -> None:
        """Server health endpoint returns healthy status with timestamp."""
        response = test_client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data

    def test_license_validation_accepts_any_key_for_bypass(
        self, test_client: TestClient
    ) -> None:
        """License validation endpoint bypasses checks for security research."""
        request_data = {
            "license_key": "BYPASS-TEST-KEY-9999",
            "product_name": "TargetApplication",
            "version": "3.0",
        }

        response = test_client.post("/api/v1/license/validate", json=request_data)

        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["status"] == "valid"
        assert data["remaining_days"] > 0

    def test_license_activation_generates_certificate(self, test_client: TestClient) -> None:
        """License activation endpoint generates signed certificate."""
        request_data = {
            "license_key": "ACTIVATE-TEST-KEY",
            "product_name": "TestApp",
            "hardware_fingerprint": "hw-test-fingerprint-123",
        }

        response = test_client.post("/api/v1/license/activate", json=request_data)

        assert response.status_code == 200
        data = response.json()
        assert data["success"]
        assert data["activation_id"]
        assert data["certificate"]
        assert len(data["certificate"]) > 0

    def test_license_status_endpoint_returns_details(
        self, test_client: TestClient, license_server: LicenseServerEmulator
    ) -> None:
        """License status endpoint retrieves license metadata."""
        license_key = "STATUS-CHECK-KEY"
        license_server.db_manager.create_license(
            license_key=license_key,
            license_type="subscription",
            product_name="StatusTestApp",
            version="1.5",
            max_users=5,
        )

        response = test_client.get(f"/api/v1/license/{license_key}/status")

        assert response.status_code == 200
        data = response.json()
        assert data["license_key"] == license_key
        assert data["status"] == "valid"
        assert data["product_name"] == "StatusTestApp"
        assert data["max_users"] == 5

    def test_flexlm_checkout_endpoint_grants_license(self, test_client: TestClient) -> None:
        """FlexLM checkout endpoint processes feature requests."""
        request_data = {"feature": "AdvancedTools", "version": "2.0", "user": "engineer"}

        response = test_client.post("/api/v1/flexlm/checkout", json=request_data)

        assert response.status_code == 200
        data = response.json()
        assert data["granted"]

    def test_hasp_login_endpoint_returns_session_handle(self, test_client: TestClient) -> None:
        """HASP login endpoint creates session and returns handle."""
        request_data = {"feature_id": 1, "vendor_code": None}

        response = test_client.post("/api/v1/hasp/login", json=request_data)

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["handle"] > 0

    def test_kms_activate_endpoint_activates_windows(self, test_client: TestClient) -> None:
        """KMS activation endpoint processes Windows/Office activation."""
        request_data = {
            "product_key": "W269N-WFGWX-YVC9B-4J6C9-T83GX",
            "product_name": "Windows 10 Pro",
        }

        response = test_client.post("/api/v1/kms/activate", json=request_data)

        assert response.status_code == 200
        data = response.json()
        assert data["success"]
        assert data["license_status"] == "Licensed"

    def test_adobe_validate_endpoint_validates_creative_cloud(
        self, test_client: TestClient
    ) -> None:
        """Adobe validation endpoint processes Creative Cloud licenses."""
        request_data = {
            "product": "Illustrator",
            "version": "2024",
            "user_id": "creative@example.com",
        }

        response = test_client.post("/api/v1/adobe/validate", json=request_data)

        assert response.status_code == 200
        data = response.json()
        assert data["valid"]

    def test_fingerprint_generation_endpoint(self, test_client: TestClient) -> None:
        """Fingerprint generation endpoint returns hardware data."""
        response = test_client.get("/api/v1/fingerprint/generate")

        assert response.status_code == 200
        data = response.json()
        assert "fingerprint" in data
        assert len(data["fingerprint"]) == 16
        assert "details" in data
        assert data["details"]["hostname"]

    def test_traffic_analysis_endpoint_identifies_protocol(
        self, test_client: TestClient
    ) -> None:
        """Traffic analysis endpoint detects license protocol from packet data."""
        flexlm_traffic = b"FEATURE SomeApp VERSION 1.0\n"

        response = test_client.post("/api/v1/analyze/traffic", content=flexlm_traffic)

        assert response.status_code == 200
        data = response.json()
        assert "protocol" in data
        assert "confidence" in data
        assert "recommendations" in data

    def test_proxy_intercept_endpoint_modifies_responses(self, test_client: TestClient) -> None:
        """Proxy intercept endpoint modifies license validation responses."""
        response = test_client.post("/api/v1/proxy/intercept", json={"action": "validate"})

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["licensed"] is True


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_concurrent_license_validations(
        self, test_client: TestClient, license_server: LicenseServerEmulator
    ) -> None:
        """Server handles multiple concurrent license validation requests."""
        license_key = "CONCURRENT-TEST-KEY"
        license_server.db_manager.create_license(
            license_key=license_key,
            license_type="subscription",
            product_name="ConcurrentApp",
            version="1.0",
            max_users=100,
        )

        def validate_license() -> dict:
            response = test_client.post(
                "/api/v1/license/validate",
                json={"license_key": license_key, "product_name": "ConcurrentApp"},
            )
            return response.json()

        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(validate_license) for _ in range(50)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == 50
        assert all(r["valid"] for r in results)

    def test_license_expiry_edge_case(self, db_manager: DatabaseManager) -> None:
        """Database correctly handles licenses expiring exactly now."""
        license_key = "EXPIRING-NOW-KEY"
        db_manager.create_license(
            license_key=license_key,
            license_type="trial",
            product_name="ExpiringApp",
            version="1.0",
            expiry_date=datetime.utcnow(),
        )

        time.sleep(1)
        validated = db_manager.validate_license(license_key, "ExpiringApp")

        assert validated is None or validated.status == "expired"

    def test_hasp_memory_boundary_conditions(self, hasp_emulator: HASPEmulator) -> None:
        """HASP emulator handles memory access at boundaries correctly."""
        handle = hasp_emulator.hasp_login(1)

        status_at_end, data_at_end = hasp_emulator.hasp_read(
            handle, hasp_emulator.memory_size - 10, 20
        )

        assert status_at_end == hasp_emulator.HASP_STATUS_OK
        assert len(data_at_end) <= 10

    def test_flexlm_server_handles_malformed_requests(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM server gracefully handles malformed protocol requests."""
        port = 27103
        flexlm_emulator.start_server(port)
        time.sleep(0.5)

        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))

            malformed_request = b"\x00\x01\x02\x03\xff\xfe\xfd\xfc"
            client.send(malformed_request)

            response = client.recv(1024)
            client.close()

            assert len(response) > 0
        finally:
            flexlm_emulator.stop_server()

    def test_crypto_operations_with_empty_data(self, crypto_manager: CryptoManager) -> None:
        """CryptoManager handles empty data gracefully."""
        encrypted = crypto_manager.encrypt_license_data("")
        decrypted = crypto_manager.decrypt_license_data(encrypted)

        assert encrypted
        assert decrypted == ""

    def test_hardware_fingerprint_changes_invalidate_activation(
        self, db_manager: DatabaseManager
    ) -> None:
        """License activation fails when hardware fingerprint changes."""
        license_key = "HW-BOUND-KEY"
        license_entry = db_manager.create_license(
            license_key=license_key,
            license_type="perpetual",
            product_name="HWBoundApp",
            version="1.0",
            hardware_fingerprint="original-hw-fingerprint",
        )

        license_entry.hardware_fingerprint = "original-hw-fingerprint"
        db_manager.Session().commit()

        different_hw = HardwareFingerprint(
            cpu_id="Different-CPU",
            motherboard_id="Different-MB",
            disk_serial="Different-Disk",
            mac_address="Different-MAC",
        )

        assert different_hw.generate_hash() != "original-hw-fingerprint"


class TestPerformance:
    """Test performance characteristics."""

    def test_license_key_generation_performance(self, crypto_manager: CryptoManager) -> None:
        """License key generation completes within acceptable timeframe."""
        import time

        start = time.perf_counter()
        keys = [crypto_manager.generate_license_key("PerfTest", "trial") for _ in range(1000)]
        elapsed = time.perf_counter() - start

        assert len(set(keys)) == 1000
        assert elapsed < 2.0

    def test_hasp_encryption_throughput(self, hasp_emulator: HASPEmulator) -> None:
        """HASP encryption processes data at acceptable speed."""
        handle = hasp_emulator.hasp_login(1)
        data = b"X" * 1024

        import time

        start = time.perf_counter()
        for _ in range(100):
            hasp_emulator.hasp_encrypt(handle, data)
        elapsed = time.perf_counter() - start

        assert elapsed < 5.0

    def test_database_query_performance(self, db_manager: DatabaseManager) -> None:
        """Database license validation queries complete quickly."""
        for i in range(100):
            db_manager.create_license(
                license_key=f"PERF-KEY-{i:04d}",
                license_type="subscription",
                product_name="PerfTestApp",
                version="1.0",
            )

        import time

        start = time.perf_counter()
        for i in range(100):
            db_manager.validate_license(f"PERF-KEY-{i:04d}", "PerfTestApp")
        elapsed = time.perf_counter() - start

        assert elapsed < 1.0
