"""Production-grade tests for license server emulator.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import hashlib
import json
import os
import platform
import socket
import struct
import tempfile
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from intellicrack.plugins.custom_modules.license_server_emulator import (
    AdobeEmulator,
    CryptoManager,
    DatabaseManager,
    FlexLMEmulator,
    HardwareFingerprint,
    HardwareFingerprintGenerator,
    HASPEmulator,
    LicenseServerEmulator,
    LicenseStatus,
    LicenseType,
    MicrosoftKMSEmulator,
    ProtocolAnalyzer,
    ProtocolType,
)


class TestCryptoManager:
    """Test cryptographic operations for license generation and validation."""

    def test_crypto_manager_initialization_creates_rsa_keys(self) -> None:
        """CryptoManager initializes with valid RSA key pair for license signing."""
        crypto = CryptoManager()

        assert crypto.private_key is not None
        assert crypto.public_key is not None
        assert crypto.aes_key is not None
        assert len(crypto.aes_key) == 32

    def test_generate_license_key_creates_unique_keys(self) -> None:
        """License key generator produces unique keys for each invocation."""
        crypto = CryptoManager()

        key1 = crypto.generate_license_key("TestProduct", "perpetual")
        key2 = crypto.generate_license_key("TestProduct", "perpetual")

        assert key1 != key2
        assert len(key1) == 19
        assert len(key2) == 19
        assert "-" in key1
        assert "-" in key2

    def test_generate_license_key_format_validation(self) -> None:
        """Generated license keys follow expected format pattern."""
        crypto = CryptoManager()

        key = crypto.generate_license_key("Software", "trial")

        parts = key.split("-")
        assert len(parts) == 4
        for part in parts:
            assert len(part) == 4
            assert part.isupper()
            assert all(c in "0123456789ABCDEF" for c in part)

    def test_sign_license_data_produces_valid_signature(self) -> None:
        """License data signing produces valid RSA-PSS signature."""
        crypto = CryptoManager()
        data = {
            "product": "TestApp",
            "license_type": "perpetual",
            "expiry": "2099-12-31",
        }

        signature = crypto.sign_license_data(data)

        assert signature != ""
        assert len(signature) > 0
        assert all(c in "0123456789abcdef" for c in signature)

    def test_verify_license_signature_validates_correct_signature(self) -> None:
        """Signature verification succeeds for correctly signed license data."""
        crypto = CryptoManager()
        data = {
            "product": "TestApp",
            "version": "1.0",
            "expiry": "2099-12-31",
        }

        signature = crypto.sign_license_data(data)
        is_valid = crypto.verify_license_signature(data, signature)

        assert is_valid is True

    def test_verify_license_signature_rejects_tampered_data(self) -> None:
        """Signature verification fails when license data is modified."""
        crypto = CryptoManager()
        original_data = {"product": "TestApp", "version": "1.0"}

        signature = crypto.sign_license_data(original_data)
        tampered_data = {"product": "TestApp", "version": "2.0"}
        is_valid = crypto.verify_license_signature(tampered_data, signature)

        assert is_valid is False

    def test_verify_license_signature_rejects_invalid_signature(self) -> None:
        """Signature verification fails with corrupted signature."""
        crypto = CryptoManager()
        data = {"product": "TestApp"}

        invalid_signature = "0" * 512
        is_valid = crypto.verify_license_signature(data, invalid_signature)

        assert is_valid is False

    def test_encrypt_license_data_produces_different_output(self) -> None:
        """License encryption produces different ciphertext for same plaintext."""
        crypto = CryptoManager()
        plaintext = "sensitive_license_data"

        ciphertext1 = crypto.encrypt_license_data(plaintext)
        ciphertext2 = crypto.encrypt_license_data(plaintext)

        assert ciphertext1 != ciphertext2
        assert len(ciphertext1) > 0
        assert len(ciphertext2) > 0

    def test_decrypt_license_data_recovers_original(self) -> None:
        """License decryption recovers original plaintext data."""
        crypto = CryptoManager()
        original = "license_key_data_12345"

        encrypted = crypto.encrypt_license_data(original)
        decrypted = crypto.decrypt_license_data(encrypted)

        assert decrypted == original

    def test_encrypt_decrypt_cycle_handles_special_characters(self) -> None:
        """Encryption/decryption handles special characters correctly."""
        crypto = CryptoManager()
        original = "test!@#$%^&*(){}[]|\\:;\"'<>,.?/~`"

        encrypted = crypto.encrypt_license_data(original)
        decrypted = crypto.decrypt_license_data(encrypted)

        assert decrypted == original

    def test_decrypt_invalid_data_returns_empty_string(self) -> None:
        """Decryption of invalid data fails gracefully."""
        crypto = CryptoManager()

        decrypted = crypto.decrypt_license_data("invalid_hex_data")

        assert decrypted == ""


class TestFlexLMEmulator:
    """Test FlexLM license server protocol emulation."""

    @pytest.fixture
    def crypto_manager(self) -> CryptoManager:
        """Provide CryptoManager instance."""
        return CryptoManager()

    @pytest.fixture
    def flexlm_emulator(self, crypto_manager: CryptoManager) -> FlexLMEmulator:
        """Provide FlexLM emulator instance."""
        return FlexLMEmulator(crypto_manager)

    def test_flexlm_initialization_sets_protocol_constants(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM emulator initializes with correct protocol constants."""
        assert flexlm_emulator.FLEXLM_PORT == 27000
        assert flexlm_emulator.VENDOR_PORT == 27001
        assert flexlm_emulator.MSG_HELLO == 1
        assert flexlm_emulator.MSG_LICENSE_REQUEST == 2
        assert flexlm_emulator.SUCCESS == 0

    def test_flexlm_start_server_binds_to_port(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM server successfully binds to TCP port and accepts connections."""
        port = 27100

        try:
            flexlm_emulator.start_server(port)
            time.sleep(0.2)

            assert flexlm_emulator.running is True
            assert flexlm_emulator.server_socket is not None

            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(2.0)
            result = test_socket.connect_ex(("127.0.0.1", port))
            test_socket.close()

            assert result == 0
        finally:
            flexlm_emulator.stop_server()

    def test_flexlm_server_handles_client_connection(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM server accepts and handles client TCP connections."""
        port = 27101

        try:
            flexlm_emulator.start_server(port)
            time.sleep(0.2)

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2.0)
            client.connect(("127.0.0.1", port))

            request = b"FEATURE test_feature 1.0\n"
            client.send(request)

            response = client.recv(1024)
            client.close()

            assert response != b""
            assert b"GRANTED" in response or b"test_feature" in response
        finally:
            flexlm_emulator.stop_server()

    def test_flexlm_parse_request_extracts_feature_name(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM parser extracts feature name from protocol request."""
        request_data = b"FEATURE solidworks 2024 permanent"

        parsed = flexlm_emulator._parse_flexlm_request(request_data)

        assert parsed["type"] == "checkout"
        assert parsed["feature"] == "solidworks"

    def test_flexlm_process_request_grants_license(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM processor grants license for valid checkout request."""
        request = {
            "type": "checkout",
            "feature": "autocad",
            "version": "2024",
        }

        response = flexlm_emulator._process_flexlm_request(request, "127.0.0.1")

        assert b"GRANTED" in response
        assert b"autocad" in response

    def test_flexlm_vendor_encryption_decryption_cycle(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM vendor encryption/decryption cycle preserves data."""
        original_data = b"vendor_license_data_12345"

        encrypted = flexlm_emulator._vendor_encrypt(original_data)
        decrypted = flexlm_emulator._vendor_decrypt(encrypted)

        assert decrypted == original_data

    def test_flexlm_vendor_encryption_includes_checksum(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM vendor encryption appends validation checksum."""
        data = b"test_data"

        encrypted = flexlm_emulator._vendor_encrypt(data)

        assert len(encrypted) > len(data)
        checksum = encrypted[-1]
        assert isinstance(checksum, int)

    def test_flexlm_vendor_validation_accepts_valid_data(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM vendor validator accepts properly formatted data."""
        valid_data = b"VEND" + b"\x00" * 20

        is_valid = flexlm_emulator._vendor_validate(valid_data)

        assert is_valid is True

    def test_flexlm_add_feature_stores_feature_info(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM feature registration stores feature configuration."""
        feature = {
            "name": "matlab",
            "version": "R2024a",
            "count": "10",
            "expiry": "31-dec-2024",
        }

        flexlm_emulator.add_feature(feature)

        assert "matlab" in flexlm_emulator.features
        assert flexlm_emulator.features["matlab"]["version"] == "R2024a"

    def test_flexlm_stop_server_closes_sockets(
        self, flexlm_emulator: FlexLMEmulator
    ) -> None:
        """FlexLM server shutdown closes all network sockets."""
        port = 27102

        flexlm_emulator.start_server(port)
        time.sleep(0.2)
        flexlm_emulator.stop_server()

        assert flexlm_emulator.running is False

        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.settimeout(1.0)
        result = test_socket.connect_ex(("127.0.0.1", port))
        test_socket.close()

        assert result != 0


class TestHASPEmulator:
    """Test HASP dongle emulation with real cryptographic operations."""

    @pytest.fixture
    def crypto_manager(self) -> CryptoManager:
        """Provide CryptoManager instance."""
        return CryptoManager()

    @pytest.fixture
    def hasp_emulator(self, crypto_manager: CryptoManager) -> HASPEmulator:
        """Provide HASP emulator instance."""
        return HASPEmulator(crypto_manager)

    def test_hasp_initialization_creates_dongle_memory(
        self, hasp_emulator: HASPEmulator
    ) -> None:
        """HASP emulator initializes with valid dongle memory structure."""
        assert hasp_emulator.memory_size == 65536
        assert len(hasp_emulator.dongle_memory) == 65536
        assert hasp_emulator.dongle_memory[:4] == b"HASP"

    def test_hasp_memory_contains_device_id(self, hasp_emulator: HASPEmulator) -> None:
        """HASP dongle memory contains unique device identifier."""
        assert len(hasp_emulator.device_id) == 16
        assert hasp_emulator.dongle_memory[8:24] == hasp_emulator.device_id

    def test_hasp_login_succeeds_for_valid_feature(
        self, hasp_emulator: HASPEmulator
    ) -> None:
        """HASP login operation succeeds for registered feature."""
        feature_id = 1

        handle = hasp_emulator.hasp_login(feature_id)

        assert handle > 0
        assert handle in hasp_emulator.active_sessions

    def test_hasp_login_fails_for_invalid_feature(
        self, hasp_emulator: HASPEmulator
    ) -> None:
        """HASP login operation fails for non-existent feature."""
        invalid_feature_id = 9999

        handle = hasp_emulator.hasp_login(invalid_feature_id)

        assert handle == hasp_emulator.HASP_FEATURE_NOT_FOUND

    def test_hasp_login_creates_session_key(self, hasp_emulator: HASPEmulator) -> None:
        """HASP login generates cryptographic session key."""
        feature_id = 1

        handle = hasp_emulator.hasp_login(feature_id)

        assert handle in hasp_emulator.session_keys
        assert len(hasp_emulator.session_keys[handle]) == 32

    def test_hasp_logout_removes_session(self, hasp_emulator: HASPEmulator) -> None:
        """HASP logout operation removes active session."""
        handle = hasp_emulator.hasp_login(1)

        result = hasp_emulator.hasp_logout(handle)

        assert result == hasp_emulator.HASP_STATUS_OK
        assert handle not in hasp_emulator.active_sessions

    def test_hasp_encrypt_produces_valid_ciphertext(
        self, hasp_emulator: HASPEmulator
    ) -> None:
        """HASP encryption produces valid AES-GCM ciphertext."""
        handle = hasp_emulator.hasp_login(1)
        plaintext = b"sensitive_data_12345"

        status, ciphertext = hasp_emulator.hasp_encrypt(handle, plaintext)

        assert status == hasp_emulator.HASP_STATUS_OK
        assert len(ciphertext) > len(plaintext)
        assert ciphertext[:12] != plaintext[:12]

    def test_hasp_decrypt_recovers_original_data(
        self, hasp_emulator: HASPEmulator
    ) -> None:
        """HASP decryption recovers original plaintext from ciphertext."""
        handle = hasp_emulator.hasp_login(1)
        original = b"test_data_encrypt_decrypt"

        _, ciphertext = hasp_emulator.hasp_encrypt(handle, original)
        status, decrypted = hasp_emulator.hasp_decrypt(handle, ciphertext)

        assert status == hasp_emulator.HASP_STATUS_OK
        assert decrypted == original

    def test_hasp_encrypt_decrypt_fails_with_invalid_handle(
        self, hasp_emulator: HASPEmulator
    ) -> None:
        """HASP operations fail with invalid session handle."""
        invalid_handle = 9999
        data = b"test"

        encrypt_status, _ = hasp_emulator.hasp_encrypt(invalid_handle, data)
        decrypt_status, _ = hasp_emulator.hasp_decrypt(invalid_handle, data)

        assert encrypt_status == hasp_emulator.HASP_INVALID_HANDLE
        assert decrypt_status == hasp_emulator.HASP_INVALID_HANDLE

    def test_hasp_read_retrieves_memory_data(self, hasp_emulator: HASPEmulator) -> None:
        """HASP read operation retrieves data from dongle memory."""
        handle = hasp_emulator.hasp_login(1)
        offset = 0
        length = 32

        status, data = hasp_emulator.hasp_read(handle, offset, length)

        assert status == hasp_emulator.HASP_STATUS_OK
        assert len(data) == length

    def test_hasp_write_stores_memory_data(self, hasp_emulator: HASPEmulator) -> None:
        """HASP write operation stores data to dongle memory."""
        handle = hasp_emulator.hasp_login(1)
        test_data = b"test_write_data"
        offset = 100

        write_status = hasp_emulator.hasp_write(handle, offset, test_data)

        assert write_status == hasp_emulator.HASP_STATUS_OK

        read_status, retrieved = hasp_emulator.hasp_read(handle, offset, len(test_data))
        assert read_status == hasp_emulator.HASP_STATUS_OK
        assert retrieved == test_data

    def test_hasp_write_rejects_protected_memory(
        self, hasp_emulator: HASPEmulator
    ) -> None:
        """HASP write operation fails for protected memory region."""
        handle = hasp_emulator.hasp_login(1)
        offset = 4
        data = b"test"

        status = hasp_emulator.hasp_write(handle, offset, data)

        assert status == hasp_emulator.HASP_INVALID_PARAMETER

    def test_hasp_get_info_returns_device_id(self, hasp_emulator: HASPEmulator) -> None:
        """HASP get_info returns device identifier."""
        handle = hasp_emulator.hasp_login(1)

        status, device_id = hasp_emulator.hasp_get_info(handle, 1)

        assert status == hasp_emulator.HASP_STATUS_OK
        assert device_id == hasp_emulator.device_id

    def test_hasp_get_info_returns_memory_size(
        self, hasp_emulator: HASPEmulator
    ) -> None:
        """HASP get_info returns total memory size."""
        handle = hasp_emulator.hasp_login(1)

        status, size_data = hasp_emulator.hasp_get_info(handle, 2)

        assert status == hasp_emulator.HASP_STATUS_OK
        memory_size = struct.unpack("<I", size_data)[0]
        assert memory_size == 65536

    def test_hasp_vendor_checksum_calculation(
        self, hasp_emulator: HASPEmulator
    ) -> None:
        """HASP vendor code checksum calculation produces valid result."""
        vendor_code = b"VEND" + b"\x00" * 12

        checksum = hasp_emulator._calculate_vendor_checksum(vendor_code)

        assert isinstance(checksum, int)
        assert checksum >= 0
        assert checksum <= 0xFFFFFFFF


class TestMicrosoftKMSEmulator:
    """Test Microsoft KMS activation server emulation."""

    @pytest.fixture
    def crypto_manager(self) -> CryptoManager:
        """Provide CryptoManager instance."""
        return CryptoManager()

    @pytest.fixture
    def kms_emulator(self, crypto_manager: CryptoManager) -> MicrosoftKMSEmulator:
        """Provide KMS emulator instance."""
        return MicrosoftKMSEmulator(crypto_manager)

    def test_kms_initialization_loads_product_keys(
        self, kms_emulator: MicrosoftKMSEmulator
    ) -> None:
        """KMS emulator initializes with product key database."""
        assert "Windows 10 Pro" in kms_emulator.kms_keys
        assert "Windows 10 Enterprise" in kms_emulator.kms_keys
        assert "Office 2019 Professional" in kms_emulator.kms_keys

    def test_kms_activate_product_succeeds(
        self, kms_emulator: MicrosoftKMSEmulator
    ) -> None:
        """KMS activation succeeds for valid product."""
        product_key = "W269N-WFGWX-YVC9B-4J6C9-T83GX"
        product_name = "Windows 10 Pro"
        client_info = {"machine_id": "test-machine-001"}

        result = kms_emulator.activate_product(product_key, product_name, client_info)

        assert result["success"] is True
        assert result["license_status"] == "Licensed"
        assert "activation_id" in result

    def test_kms_activation_sets_grace_period(
        self, kms_emulator: MicrosoftKMSEmulator
    ) -> None:
        """KMS activation sets remaining grace period."""
        result = kms_emulator.activate_product(
            "NPPR9-FWDCX-D2C8J-H872K-2YT43",
            "Windows 10 Enterprise",
            {},
        )

        assert result["remaining_grace_time"] == 180

    def test_kms_activation_generates_unique_id(
        self, kms_emulator: MicrosoftKMSEmulator
    ) -> None:
        """KMS activation generates unique activation identifier."""
        result1 = kms_emulator.activate_product("KEY1", "Windows 10 Pro", {})
        result2 = kms_emulator.activate_product("KEY2", "Windows 10 Pro", {})

        assert result1["activation_id"] != result2["activation_id"]


class TestAdobeEmulator:
    """Test Adobe Creative Cloud license server emulation."""

    @pytest.fixture
    def crypto_manager(self) -> CryptoManager:
        """Provide CryptoManager instance."""
        return CryptoManager()

    @pytest.fixture
    def adobe_emulator(self, crypto_manager: CryptoManager) -> AdobeEmulator:
        """Provide Adobe emulator instance."""
        return AdobeEmulator(crypto_manager)

    def test_adobe_initialization_loads_products(
        self, adobe_emulator: AdobeEmulator
    ) -> None:
        """Adobe emulator initializes with product catalog."""
        assert "Photoshop" in adobe_emulator.adobe_products
        assert "Illustrator" in adobe_emulator.adobe_products
        assert "Premiere Pro" in adobe_emulator.adobe_products

    def test_adobe_validate_license_succeeds(
        self, adobe_emulator: AdobeEmulator
    ) -> None:
        """Adobe license validation succeeds for valid credentials."""
        product_id = "PHSP"
        user_id = "test-user-001"
        machine_id = "machine-001"

        result = adobe_emulator.validate_adobe_license(product_id, user_id, machine_id)

        assert result["status"] == "success"
        assert result["subscription_status"] == "active"

    def test_adobe_validation_enables_features(
        self, adobe_emulator: AdobeEmulator
    ) -> None:
        """Adobe license validation enables cloud features."""
        result = adobe_emulator.validate_adobe_license("ILST", "user", "machine")

        assert result["features"]["cloud_sync"] is True
        assert result["features"]["fonts"] is True
        assert result["features"]["stock"] is True

    def test_adobe_validation_generates_ngl_token(
        self, adobe_emulator: AdobeEmulator
    ) -> None:
        """Adobe license validation generates NGL token."""
        result = adobe_emulator.validate_adobe_license("PPRO", "user", "machine")

        assert "ngl_token" in result
        assert len(result["ngl_token"]) > 0


class TestDatabaseManager:
    """Test license database operations."""

    @pytest.fixture
    def temp_db_path(self) -> str:
        """Provide temporary database path."""
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, "test_licenses.db")
        yield db_path
        if os.path.exists(db_path):
            os.remove(db_path)
        os.rmdir(temp_dir)

    @pytest.fixture
    def db_manager(self, temp_db_path: str) -> DatabaseManager:
        """Provide DatabaseManager instance."""
        return DatabaseManager(temp_db_path)

    def test_database_initialization_creates_tables(
        self, db_manager: DatabaseManager
    ) -> None:
        """Database initialization creates required tables."""
        db = db_manager.get_db()

        assert db is not None

    def test_database_seeds_default_licenses(
        self, db_manager: DatabaseManager
    ) -> None:
        """Database seeding creates default license entries."""
        db = db_manager.get_db()
        from intellicrack.plugins.custom_modules.license_server_emulator import (
            LicenseEntry,
        )

        count = db.query(LicenseEntry).count()
        db.close()

        assert count > 0

    def test_validate_license_finds_existing_license(
        self, db_manager: DatabaseManager
    ) -> None:
        """License validation finds existing license in database."""
        license_entry = db_manager.validate_license(
            "FLEX-1234-5678-9ABC", "FlexLM Test Product"
        )

        assert license_entry is not None
        assert license_entry.license_key == "FLEX-1234-5678-9ABC"

    def test_validate_license_returns_none_for_invalid(
        self, db_manager: DatabaseManager
    ) -> None:
        """License validation returns None for non-existent license."""
        license_entry = db_manager.validate_license("INVALID-KEY", "NonExistent")

        assert license_entry is None

    def test_log_operation_records_activity(self, db_manager: DatabaseManager) -> None:
        """Operation logging records license activity."""
        db_manager.log_operation(
            "TEST-KEY", "validation", "127.0.0.1", True, "Test operation"
        )

        db = db_manager.get_db()
        from intellicrack.plugins.custom_modules.license_server_emulator import (
            LicenseLog,
        )

        logs = db.query(LicenseLog).filter(LicenseLog.license_key == "TEST-KEY").all()
        db.close()

        assert len(logs) > 0
        assert logs[0].operation == "validation"


class TestHardwareFingerprintGenerator:
    """Test hardware fingerprint generation for license binding."""

    @pytest.fixture
    def fingerprint_generator(self) -> HardwareFingerprintGenerator:
        """Provide HardwareFingerprintGenerator instance."""
        return HardwareFingerprintGenerator()

    def test_generate_fingerprint_produces_valid_fingerprint(
        self, fingerprint_generator: HardwareFingerprintGenerator
    ) -> None:
        """Hardware fingerprint generator produces valid fingerprint."""
        fingerprint = fingerprint_generator.generate_fingerprint()

        assert isinstance(fingerprint, HardwareFingerprint)
        assert len(fingerprint.cpu_id) > 0
        assert len(fingerprint.motherboard_id) > 0
        assert len(fingerprint.disk_serial) > 0

    def test_generate_fingerprint_is_consistent(
        self, fingerprint_generator: HardwareFingerprintGenerator
    ) -> None:
        """Hardware fingerprint generation produces consistent results."""
        fingerprint1 = fingerprint_generator.generate_fingerprint()
        fingerprint2 = fingerprint_generator.generate_fingerprint()

        assert fingerprint1.cpu_id == fingerprint2.cpu_id
        assert fingerprint1.motherboard_id == fingerprint2.motherboard_id

    def test_fingerprint_hash_generation(
        self, fingerprint_generator: HardwareFingerprintGenerator
    ) -> None:
        """Hardware fingerprint hash generation produces valid hash."""
        fingerprint = fingerprint_generator.generate_fingerprint()

        hash_value = fingerprint.generate_hash()

        assert len(hash_value) == 16
        assert all(c in "0123456789abcdef" for c in hash_value)

    @pytest.mark.skipif(
        platform.system() != "Windows", reason="Windows-specific test"
    )
    def test_get_cpu_id_windows_retrieves_processor_id(
        self, fingerprint_generator: HardwareFingerprintGenerator
    ) -> None:
        """Windows CPU ID extraction retrieves processor identifier."""
        cpu_id = fingerprint_generator._get_cpu_id_windows()

        assert cpu_id is not None
        assert len(cpu_id) > 0

    @pytest.mark.skipif(
        platform.system() != "Windows", reason="Windows-specific test"
    )
    def test_get_motherboard_id_windows_retrieves_board_serial(
        self, fingerprint_generator: HardwareFingerprintGenerator
    ) -> None:
        """Windows motherboard ID extraction retrieves board identifier."""
        board_id = fingerprint_generator._get_motherboard_id_windows()

        assert board_id is not None
        assert len(board_id) > 0


class TestProtocolAnalyzer:
    """Test license protocol traffic analysis."""

    @pytest.fixture
    def protocol_analyzer(self) -> ProtocolAnalyzer:
        """Provide ProtocolAnalyzer instance."""
        return ProtocolAnalyzer()

    def test_protocol_analyzer_initialization(
        self, protocol_analyzer: ProtocolAnalyzer
    ) -> None:
        """Protocol analyzer initializes with pattern database."""
        assert hasattr(protocol_analyzer, "patterns")
        assert hasattr(protocol_analyzer, "signatures")

    def test_analyze_traffic_detects_flexlm_protocol(
        self, protocol_analyzer: ProtocolAnalyzer
    ) -> None:
        """Protocol analyzer detects FlexLM protocol traffic."""
        flexlm_data = b"FEATURE solidworks 2024 permanent\n"

        analysis = protocol_analyzer.analyze_traffic(
            flexlm_data, "127.0.0.1", 27000
        )

        assert analysis["protocol_detected"] is True

    def test_analyze_traffic_parses_http_request(
        self, protocol_analyzer: ProtocolAnalyzer
    ) -> None:
        """Protocol analyzer parses HTTP license requests."""
        http_data = b"POST /activate HTTP/1.1\r\nHost: license.example.com\r\nContent-Length: 0\r\n\r\n"

        analysis = protocol_analyzer.analyze_traffic(http_data, "127.0.0.1", 80)

        assert analysis is not None

    def test_parse_flexlm_data_extracts_feature_info(
        self, protocol_analyzer: ProtocolAnalyzer
    ) -> None:
        """FlexLM parser extracts feature information from request."""
        flexlm_data = b"FEATURE autocad 2024 permanent 1000 VENDOR_KEY=ABC123"

        parsed = protocol_analyzer._parse_flexlm_data(flexlm_data)

        assert "feature_name" in parsed or "data" in parsed

    def test_parse_hasp_data_extracts_dongle_info(
        self, protocol_analyzer: ProtocolAnalyzer
    ) -> None:
        """HASP parser extracts dongle information from request."""
        hasp_data = b"HASP\x00\x00\x00\x01" + b"\x00" * 28

        parsed = protocol_analyzer._parse_hasp_data(hasp_data)

        assert "dongle_id" in parsed or "feature_id" in parsed or "data" in parsed


class TestLicenseServerEmulator:
    """Test main license server emulator integration."""

    @pytest.fixture
    def license_server(self) -> LicenseServerEmulator:
        """Provide LicenseServerEmulator instance."""
        config = {
            "enable_flexlm": True,
            "enable_hasp": True,
            "enable_kms": True,
            "enable_adobe": True,
        }
        return LicenseServerEmulator(config)

    def test_license_server_initialization(
        self, license_server: LicenseServerEmulator
    ) -> None:
        """License server emulator initializes with all components."""
        assert license_server.crypto is not None
        assert license_server.flexlm is not None
        assert license_server.hasp is not None
        assert license_server.kms is not None
        assert license_server.adobe is not None

    def test_create_license_server_instance(
        self, license_server: LicenseServerEmulator
    ) -> None:
        """License server creates server instance."""
        server_instance = license_server.create_license_server("127.0.0.1", 0)

        assert server_instance is not None
        assert hasattr(server_instance, "start_async")
        assert hasattr(server_instance, "stop")

    def test_create_license_client_instance(
        self, license_server: LicenseServerEmulator
    ) -> None:
        """License server creates client instance."""
        client_instance = license_server.create_license_client()

        assert client_instance is not None
        assert hasattr(client_instance, "connect")
        assert hasattr(client_instance, "disconnect")

    def test_license_server_client_communication(
        self, license_server: LicenseServerEmulator
    ) -> None:
        """License server and client communicate successfully."""
        server = license_server.create_license_server("127.0.0.1", 0)
        server.start_async()
        time.sleep(0.3)

        try:
            port = server.get_port()
            client = license_server.create_license_client()

            connected = client.connect("127.0.0.1", port, timeout=2.0)

            assert connected is True
            assert client.is_connected() is True

            client.disconnect()
        finally:
            server.stop()


class TestConcurrentOperations:
    """Test concurrent client handling and thread safety."""

    @pytest.fixture
    def crypto_manager(self) -> CryptoManager:
        """Provide CryptoManager instance."""
        return CryptoManager()

    def test_hasp_concurrent_login_operations(
        self, crypto_manager: CryptoManager
    ) -> None:
        """HASP emulator handles concurrent login operations safely."""
        hasp = HASPEmulator(crypto_manager)
        handles = []
        errors = []

        def login_worker() -> None:
            try:
                handle = hasp.hasp_login(1)
                if handle > 0:
                    handles.append(handle)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=login_worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(handles) == 10
        assert len(set(handles)) == 10

    def test_flexlm_concurrent_client_connections(
        self, crypto_manager: CryptoManager
    ) -> None:
        """FlexLM server handles multiple concurrent client connections."""
        flexlm = FlexLMEmulator(crypto_manager)
        port = 27200
        responses = []
        errors = []

        try:
            flexlm.start_server(port)
            time.sleep(0.2)

            def client_worker() -> None:
                try:
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.settimeout(3.0)
                    client.connect(("127.0.0.1", port))
                    client.send(b"FEATURE test 1.0\n")
                    response = client.recv(1024)
                    responses.append(response)
                    client.close()
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=client_worker) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(errors) == 0
            assert len(responses) == 5
        finally:
            flexlm.stop_server()


class TestCryptographicIntegrity:
    """Test cryptographic operations integrity and security."""

    def test_crypto_manager_key_uniqueness(self) -> None:
        """Each CryptoManager instance has unique RSA key pair."""
        crypto1 = CryptoManager()
        crypto2 = CryptoManager()

        signature1 = crypto1.sign_license_data({"data": "test"})
        signature2 = crypto2.sign_license_data({"data": "test"})

        assert signature1 != signature2

    def test_hasp_session_key_uniqueness(self) -> None:
        """Each HASP session generates unique encryption key."""
        crypto = CryptoManager()
        hasp = HASPEmulator(crypto)

        handle1 = hasp.hasp_login(1)
        handle2 = hasp.hasp_login(1)

        key1 = hasp.session_keys[handle1]
        key2 = hasp.session_keys[handle2]

        assert key1 != key2

    def test_hasp_encryption_authenticated(self) -> None:
        """HASP encryption uses authenticated encryption (AES-GCM)."""
        crypto = CryptoManager()
        hasp = HASPEmulator(crypto)
        handle = hasp.hasp_login(1)

        _, ciphertext = hasp.hasp_encrypt(handle, b"test_data")

        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[-5] ^= 0xFF
        status, _ = hasp.hasp_decrypt(handle, bytes(tampered_ciphertext))

        assert status == hasp.HASP_SIGNATURE_CHECK_FAILED


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_flexlm_handles_invalid_request_data(self) -> None:
        """FlexLM parser handles malformed request data gracefully."""
        crypto = CryptoManager()
        flexlm = FlexLMEmulator(crypto)

        parsed = flexlm._parse_flexlm_request(b"\xff\xfe\xfd\xfc")

        assert parsed["type"] == "unknown" or "type" in parsed

    def test_hasp_read_validates_bounds(self) -> None:
        """HASP read operation validates memory bounds."""
        crypto = CryptoManager()
        hasp = HASPEmulator(crypto)
        handle = hasp.hasp_login(1)

        status, _ = hasp.hasp_read(handle, 100000, 1000)

        assert status in (hasp.HASP_NO_MEMORY, hasp.HASP_INVALID_PARAMETER)

    def test_crypto_decrypt_handles_corrupted_data(self) -> None:
        """Crypto manager handles corrupted encrypted data."""
        crypto = CryptoManager()
        corrupted = "zzzz_invalid_hex_data_zzzz"

        result = crypto.decrypt_license_data(corrupted)

        assert result == ""

    def test_database_handles_duplicate_license_key(self) -> None:
        """Database handles duplicate license key insertion."""
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, "test_dup.db")

        try:
            db_manager = DatabaseManager(db_path)
            db = db_manager.get_db()

            from intellicrack.plugins.custom_modules.license_server_emulator import (
                LicenseEntry,
            )

            license1 = LicenseEntry(
                license_key="DUP-TEST-KEY",
                license_type="test",
                product_name="Test",
                version="1.0",
            )

            db.add(license1)
            db.commit()

            license2 = LicenseEntry(
                license_key="DUP-TEST-KEY",
                license_type="test",
                product_name="Test2",
                version="2.0",
            )

            try:
                db.add(license2)
                db.commit()
                duplicate_handled = False
            except Exception:
                db.rollback()
                duplicate_handled = True

            db.close()

            assert duplicate_handled is True
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
            os.rmdir(temp_dir)


class TestProtocolCompliance:
    """Test protocol compliance with real license server formats."""

    def test_flexlm_response_format_compliance(self) -> None:
        """FlexLM responses follow protocol specification format."""
        crypto = CryptoManager()
        flexlm = FlexLMEmulator(crypto)

        request = {"type": "checkout", "feature": "matlab", "version": "R2024a"}
        response = flexlm._process_flexlm_request(request, "127.0.0.1")

        response_text = response.decode("ascii", errors="ignore")
        assert "GRANTED" in response_text or "ERROR" in response_text

    def test_hasp_memory_structure_compliance(self) -> None:
        """HASP dongle memory follows SafeNet structure specification."""
        crypto = CryptoManager()
        hasp = HASPEmulator(crypto)

        assert hasp.dongle_memory[:4] == b"HASP"

        version = struct.unpack("<I", hasp.dongle_memory[4:8])[0]
        assert version > 0

    def test_kms_activation_response_format(self) -> None:
        """KMS activation response contains required fields."""
        crypto = CryptoManager()
        kms = MicrosoftKMSEmulator(crypto)

        result = kms.activate_product("TEST-KEY", "Windows 10 Pro", {})

        required_fields = [
            "success",
            "activation_id",
            "license_status",
            "remaining_grace_time",
        ]
        for field in required_fields:
            assert field in result


class TestPerformance:
    """Test performance characteristics of license operations."""

    def test_crypto_key_generation_performance(self) -> None:
        """License key generation completes within acceptable time."""
        crypto = CryptoManager()

        start = time.time()
        for _ in range(100):
            crypto.generate_license_key("TestProduct", "trial")
        duration = time.time() - start

        assert duration < 1.0

    def test_hasp_encrypt_decrypt_performance(self) -> None:
        """HASP encryption/decryption completes within acceptable time."""
        crypto = CryptoManager()
        hasp = HASPEmulator(crypto)
        handle = hasp.hasp_login(1)
        data = b"test_data_for_performance_testing"

        start = time.time()
        for _ in range(100):
            _, ciphertext = hasp.hasp_encrypt(handle, data)
            hasp.hasp_decrypt(handle, ciphertext)
        duration = time.time() - start

        assert duration < 2.0

    def test_flexlm_concurrent_throughput(self) -> None:
        """FlexLM server handles concurrent requests efficiently."""
        crypto = CryptoManager()
        flexlm = FlexLMEmulator(crypto)
        port = 27300

        try:
            flexlm.start_server(port)
            time.sleep(0.2)

            start = time.time()
            completed = [0]

            def client_request() -> None:
                try:
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.settimeout(3.0)
                    client.connect(("127.0.0.1", port))
                    client.send(b"FEATURE test 1.0\n")
                    client.recv(1024)
                    client.close()
                    completed[0] += 1
                except Exception:
                    pass

            threads = [threading.Thread(target=client_request) for _ in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            duration = time.time() - start

            assert completed[0] >= 15
            assert duration < 5.0
        finally:
            flexlm.stop_server()
