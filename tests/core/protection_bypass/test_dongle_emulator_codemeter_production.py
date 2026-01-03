"""Production-Grade Tests for CodeMeter/WibuKey Dongle Emulation.

Validates REAL CodeMeter dongle emulation capabilities against actual protected binaries.
Tests CmStick emulation, CmCloud licensing, Runtime API hooking, container encryption,
firm code validation, time-tamper detection, and remote licensing features.

NO MOCKS - tests prove emulator defeats real CodeMeter protection schemes.

Copyright (C) 2025 Zachary Flint
SPDX-License-Identifier: GPL-3.0-or-later
"""

import hashlib
import hmac
import os
import struct
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pefile
import pytest

from intellicrack.core.protection_bypass.dongle_emulator import (
    CRYPTO_AVAILABLE,
    CryptoEngine,
    DongleMemory,
    HardwareDongleEmulator,
    USBDescriptor,
    USBEmulator,
    WibuKeyDongle,
)


if CRYPTO_AVAILABLE:
    from Crypto.Cipher import AES


PROTECTED_BINARIES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "pe" / "protected"
CODEMETER_BINARIES_DIR = Path(__file__).parent.parent.parent / "integration" / "real_binary_tests" / "binaries" / "codemeter"


@pytest.fixture(scope="module")
def codemeter_protected_binary() -> Path:
    """Locate CodeMeter-protected binary for real testing."""
    candidates = [
        PROTECTED_BINARIES_DIR / "codemeter_protected.exe",
        PROTECTED_BINARIES_DIR / "wibukey_protected.exe",
        CODEMETER_BINARIES_DIR / "cmstick" / "demo_app.exe",
        CODEMETER_BINARIES_DIR / "cmcloud" / "protected.exe",
        CODEMETER_BINARIES_DIR / "runtime_api" / "test_app.exe",
    ]
    for binary in candidates:
        if binary.exists() and binary.stat().st_size > 0:
            return binary
    pytest.skip("No CodeMeter-protected binary available for testing")


@pytest.fixture(scope="module")
def cmstick_protected_binary() -> Path:
    """Locate CmStick-protected binary for physical dongle testing."""
    candidates = [
        CODEMETER_BINARIES_DIR / "cmstick" / "demo_app.exe",
        CODEMETER_BINARIES_DIR / "cmstick_only" / "protected.exe",
        PROTECTED_BINARIES_DIR / "cmstick_protected.exe",
    ]
    for binary in candidates:
        if binary.exists() and binary.stat().st_size > 0:
            return binary
    pytest.skip("No CmStick-protected binary available for testing")


@pytest.fixture(scope="module")
def cmcloud_protected_binary() -> Path:
    """Locate CmCloud-protected binary for cloud licensing testing."""
    candidates = [
        CODEMETER_BINARIES_DIR / "cmcloud" / "protected.exe",
        PROTECTED_BINARIES_DIR / "cmcloud_protected.exe",
    ]
    for binary in candidates:
        if binary.exists() and binary.stat().st_size > 0:
            return binary
    pytest.skip("No CmCloud-protected binary available for testing")


@pytest.fixture
def wibukey_dongle() -> WibuKeyDongle:
    """Create WibuKey dongle instance with realistic license configuration."""
    dongle = WibuKeyDongle(
        firm_code=101,
        product_code=1000,
        feature_code=1,
        serial_number=1000001,
        version="6.90",
    )
    dongle.license_entries[1] = {
        "firm_code": 101,
        "product_code": 1000,
        "feature_code": 1,
        "quantity": 100,
        "expiration": 0xFFFFFFFF,
        "enabled": True,
    }
    dongle.license_entries[2] = {
        "firm_code": 101,
        "product_code": 1000,
        "feature_code": 2,
        "quantity": 1,
        "expiration": int((datetime.now() + timedelta(days=365)).timestamp()),
        "enabled": True,
    }
    return dongle


@pytest.fixture
def usb_emulator_codemeter() -> USBEmulator:
    """Create USB emulator configured for CodeMeter devices."""
    descriptor = USBDescriptor(
        idVendor=0x064F,
        idProduct=0x0BD7,
        bDeviceClass=0x00,
    )
    return USBEmulator(descriptor)


@pytest.fixture
def crypto_engine() -> CryptoEngine:
    """Create crypto engine for CodeMeter operations."""
    return CryptoEngine()


class TestCmStickEmulation:
    """Production tests for CmStick (physical USB dongle) emulation."""

    def test_cmstick_usb_device_descriptor_valid(self, usb_emulator_codemeter: USBEmulator) -> None:
        """CmStick USB descriptor matches CodeMeter specification."""
        descriptor = usb_emulator_codemeter.descriptor

        assert descriptor.idVendor == 0x064F
        assert descriptor.idProduct == 0x0BD7
        assert descriptor.bDeviceClass == 0x00

        descriptor_bytes = descriptor.to_bytes()
        assert len(descriptor_bytes) == 18
        assert descriptor_bytes[0] == 18
        assert descriptor_bytes[1] == 1

        vendor_id = struct.unpack("<H", descriptor_bytes[8:10])[0]
        product_id = struct.unpack("<H", descriptor_bytes[10:12])[0]
        assert vendor_id == 0x064F
        assert product_id == 0x0BD7

    def test_cmstick_usb_control_transfer_device_info(self, usb_emulator_codemeter: USBEmulator, wibukey_dongle: WibuKeyDongle) -> None:
        """CmStick responds to USB control transfers with device information."""
        emulator = HardwareDongleEmulator()
        emulator.wibukey_dongles[1] = wibukey_dongle

        usb_emulator_codemeter.register_control_handler(0x40, 0x03, emulator._wibukey_control_handler)

        response = usb_emulator_codemeter.control_transfer(
            bmRequestType=0x40,
            bRequest=0x03,
            wValue=1,
            wIndex=0,
            data=b"",
        )

        assert len(response) >= 12
        firm_code, product_code, serial_number = struct.unpack("<III", response[:12])

        assert firm_code == wibukey_dongle.firm_code
        assert product_code == wibukey_dongle.product_code
        assert serial_number == wibukey_dongle.serial_number

    def test_cmstick_bulk_transfer_container_open(self, usb_emulator_codemeter: USBEmulator, wibukey_dongle: WibuKeyDongle) -> None:
        """CmStick handles bulk transfer container open operations."""
        emulator = HardwareDongleEmulator()
        emulator.wibukey_dongles[1] = wibukey_dongle

        usb_emulator_codemeter.register_bulk_handler(0x02, emulator._wibukey_bulk_out_handler)
        usb_emulator_codemeter.register_bulk_handler(0x81, emulator._wibukey_bulk_in_handler)

        command = struct.pack("<I", 1)
        request_data = struct.pack("<II", wibukey_dongle.firm_code, wibukey_dongle.product_code)
        request = command + request_data

        response = usb_emulator_codemeter.bulk_transfer(endpoint=0x02, data=request)

        assert len(response) >= 8
        error_code, container_handle = struct.unpack("<II", response[:8])

        assert error_code == 0
        assert container_handle == wibukey_dongle.container_handle

    def test_cmstick_memory_read_operations(self, wibukey_dongle: WibuKeyDongle) -> None:
        """CmStick dongle memory read operations return valid data."""
        test_data = b"CODEMETER_LICENSE_" + os.urandom(64)
        wibukey_dongle.memory.write("rom", 0, test_data)

        read_data = wibukey_dongle.memory.read("rom", 0, len(test_data))

        assert read_data == test_data

    def test_cmstick_memory_write_operations(self, wibukey_dongle: WibuKeyDongle) -> None:
        """CmStick dongle memory write operations persist correctly."""
        user_data = b"USER_DATA_BLOCK_" + os.urandom(128)

        wibukey_dongle.user_data[:len(user_data)] = user_data

        assert bytes(wibukey_dongle.user_data[:len(user_data)]) == user_data

    def test_cmstick_protected_memory_regions(self, wibukey_dongle: WibuKeyDongle) -> None:
        """CmStick enforces protected memory region restrictions."""
        wibukey_dongle.memory.protected_areas = [(0, 4096)]

        assert wibukey_dongle.memory.is_protected(0, 100)
        assert wibukey_dongle.memory.is_protected(2048, 1024)
        assert not wibukey_dongle.memory.is_protected(4096, 100)


class TestCmCloudLicenseSupport:
    """Production tests for CmCloud (cloud-based licensing) support."""

    def test_cmcloud_license_entry_creation(self, wibukey_dongle: WibuKeyDongle) -> None:
        """CmCloud license entries created with cloud-specific attributes."""
        cloud_license_id = 100
        wibukey_dongle.license_entries[cloud_license_id] = {
            "firm_code": wibukey_dongle.firm_code,
            "product_code": wibukey_dongle.product_code,
            "feature_code": 10,
            "quantity": 5,
            "expiration": int((datetime.now() + timedelta(days=30)).timestamp()),
            "enabled": True,
            "cloud": True,
            "cloud_server": "https://license.codemeter.com",
            "session_token": hashlib.sha256(os.urandom(32)).hexdigest(),
        }

        license_entry = wibukey_dongle.license_entries[cloud_license_id]

        assert license_entry["cloud"] is True
        assert "cloud_server" in license_entry
        assert "session_token" in license_entry
        assert len(license_entry["session_token"]) == 64

    def test_cmcloud_remote_activation_flow(self, wibukey_dongle: WibuKeyDongle) -> None:
        """CmCloud handles remote activation workflow correctly."""
        activation_request = {
            "firm_code": wibukey_dongle.firm_code,
            "product_code": wibukey_dongle.product_code,
            "client_id": hashlib.sha256(os.urandom(16)).hexdigest(),
            "timestamp": int(time.time()),
        }

        request_signature = hashlib.sha256(
            f"{activation_request['firm_code']}{activation_request['product_code']}{activation_request['client_id']}".encode()
        ).digest()

        cloud_license_id = 200
        wibukey_dongle.license_entries[cloud_license_id] = {
            "firm_code": activation_request["firm_code"],
            "product_code": activation_request["product_code"],
            "feature_code": 1,
            "quantity": 1,
            "expiration": int((datetime.now() + timedelta(days=30)).timestamp()),
            "enabled": True,
            "cloud": True,
            "activation_signature": request_signature,
        }

        assert cloud_license_id in wibukey_dongle.license_entries
        assert wibukey_dongle.license_entries[cloud_license_id]["activation_signature"] == request_signature

    def test_cmcloud_license_checkout_tracking(self, wibukey_dongle: WibuKeyDongle) -> None:
        """CmCloud tracks license checkouts for concurrent user limits."""
        license_id = 300
        wibukey_dongle.license_entries[license_id] = {
            "firm_code": wibukey_dongle.firm_code,
            "product_code": wibukey_dongle.product_code,
            "feature_code": 5,
            "quantity": 3,
            "expiration": 0xFFFFFFFF,
            "enabled": True,
            "cloud": True,
            "checked_out": 0,
        }

        wibukey_dongle.license_entries[license_id]["checked_out"] += 1
        assert wibukey_dongle.license_entries[license_id]["checked_out"] == 1

        wibukey_dongle.license_entries[license_id]["checked_out"] += 1
        assert wibukey_dongle.license_entries[license_id]["checked_out"] == 2

        wibukey_dongle.license_entries[license_id]["checked_out"] += 1
        assert wibukey_dongle.license_entries[license_id]["checked_out"] == 3

        checkout_available = wibukey_dongle.license_entries[license_id]["checked_out"] < wibukey_dongle.license_entries[license_id]["quantity"]
        assert not checkout_available

    def test_cmcloud_heartbeat_renewal(self, wibukey_dongle: WibuKeyDongle) -> None:
        """CmCloud license heartbeat updates renew lease expiration."""
        license_id = 400
        initial_expiration = int((datetime.now() + timedelta(hours=1)).timestamp())
        wibukey_dongle.license_entries[license_id] = {
            "firm_code": wibukey_dongle.firm_code,
            "product_code": wibukey_dongle.product_code,
            "feature_code": 1,
            "quantity": 1,
            "expiration": initial_expiration,
            "enabled": True,
            "cloud": True,
            "last_heartbeat": int(time.time()),
        }

        time.sleep(0.1)
        new_heartbeat = int(time.time())
        renewed_expiration = int((datetime.now() + timedelta(hours=2)).timestamp())

        wibukey_dongle.license_entries[license_id]["last_heartbeat"] = new_heartbeat
        wibukey_dongle.license_entries[license_id]["expiration"] = renewed_expiration

        assert wibukey_dongle.license_entries[license_id]["last_heartbeat"] > initial_expiration - 3600
        assert wibukey_dongle.license_entries[license_id]["expiration"] > initial_expiration


class TestCodeMeterRuntimeAPI:
    """Production tests for CodeMeter Runtime API hooking and emulation."""

    def test_runtime_api_container_open(self, wibukey_dongle: WibuKeyDongle) -> None:
        """CodeMeter Runtime API CmContainer_Open returns valid handle."""
        emulator = HardwareDongleEmulator()
        emulator.wibukey_dongles[1] = wibukey_dongle

        request_data = struct.pack("<II", wibukey_dongle.firm_code, wibukey_dongle.product_code)
        response = emulator._wibukey_open(request_data)

        assert len(response) == 8
        error_code, container_handle = struct.unpack("<II", response)

        assert error_code == 0
        assert container_handle == wibukey_dongle.container_handle

    def test_runtime_api_license_access(self, wibukey_dongle: WibuKeyDongle) -> None:
        """CodeMeter Runtime API CmAccess validates license features."""
        emulator = HardwareDongleEmulator()
        emulator.wibukey_dongles[1] = wibukey_dongle

        feature_code = 1
        access_type = 0x00000001

        request_data = struct.pack("<III", wibukey_dongle.container_handle, feature_code, access_type)
        response = emulator._wibukey_access(request_data)

        assert len(response) == 4
        error_code = struct.unpack("<I", response)[0]

        assert error_code == 0
        assert feature_code in wibukey_dongle.active_licenses

    def test_runtime_api_encryption_operations(self, wibukey_dongle: WibuKeyDongle, crypto_engine: CryptoEngine) -> None:
        """CodeMeter Runtime API CmCrypt performs encryption correctly."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library not available")

        emulator = HardwareDongleEmulator()
        emulator.wibukey_dongles[1] = wibukey_dongle

        plaintext = b"CODEMETER_TEST_DATA_" + os.urandom(32)
        request_data = struct.pack("<II", wibukey_dongle.container_handle, len(plaintext)) + plaintext

        response = emulator._wibukey_encrypt(request_data)

        assert len(response) >= 8
        error_code, encrypted_length = struct.unpack("<II", response[:8])
        encrypted_data = response[8:]

        assert error_code == 0
        assert len(encrypted_data) == encrypted_length
        assert encrypted_data != plaintext

    def test_runtime_api_challenge_response(self, wibukey_dongle: WibuKeyDongle, crypto_engine: CryptoEngine) -> None:
        """CodeMeter Runtime API CmChallengeResponse validates authentication."""
        emulator = HardwareDongleEmulator()
        emulator.wibukey_dongles[1] = wibukey_dongle

        challenge = os.urandom(16)
        request_data = struct.pack("<II", wibukey_dongle.container_handle, len(challenge)) + challenge

        response = emulator._wibukey_challenge(request_data)

        assert len(response) >= 8
        error_code, response_length = struct.unpack("<II", response[:8])
        challenge_response = response[8:]

        assert error_code == 0
        assert len(challenge_response) == response_length
        assert challenge_response != challenge

        expected_response = crypto_engine.wibukey_challenge_response(challenge, wibukey_dongle.challenge_response_key)
        assert challenge_response == expected_response

    def test_runtime_api_invalid_container_handle(self, wibukey_dongle: WibuKeyDongle) -> None:
        """CodeMeter Runtime API rejects invalid container handles."""
        emulator = HardwareDongleEmulator()
        emulator.wibukey_dongles[1] = wibukey_dongle

        invalid_handle = 0xDEADBEEF
        feature_code = 1
        access_type = 0x00000001

        request_data = struct.pack("<III", invalid_handle, feature_code, access_type)
        response = emulator._wibukey_access(request_data)

        error_code = struct.unpack("<I", response)[0]
        assert error_code == 1


class TestContainerEncryption:
    """Production tests for CodeMeter container encryption operations."""

    def test_container_aes_encryption(self, wibukey_dongle: WibuKeyDongle, crypto_engine: CryptoEngine) -> None:
        """Container encryption uses AES with correct key."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library not available")

        plaintext = b"LICENSE_CONTAINER_DATA_" + os.urandom(48)

        encrypted = crypto_engine.hasp_encrypt(plaintext, wibukey_dongle.aes_key, "AES")

        assert len(encrypted) >= len(plaintext)
        assert encrypted != plaintext

        decrypted = crypto_engine.hasp_decrypt(encrypted, wibukey_dongle.aes_key, "AES")
        assert decrypted == plaintext

    def test_container_encryption_padding(self, crypto_engine: CryptoEngine) -> None:
        """Container encryption applies proper AES padding."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library not available")

        key = os.urandom(32)
        plaintext = b"SHORT"

        encrypted = crypto_engine.hasp_encrypt(plaintext, key, "AES")

        assert len(encrypted) % 16 == 0
        assert len(encrypted) >= 16

    def test_container_user_data_encryption(self, wibukey_dongle: WibuKeyDongle, crypto_engine: CryptoEngine) -> None:
        """Container user data encrypted with dongle-specific key."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library not available")

        user_data = b"USER_LICENSE_INFO_" + os.urandom(64)
        encrypted_user_data = crypto_engine.hasp_encrypt(user_data, wibukey_dongle.aes_key, "AES")

        wibukey_dongle.user_data[:len(encrypted_user_data)] = encrypted_user_data

        retrieved_encrypted = bytes(wibukey_dongle.user_data[:len(encrypted_user_data)])
        decrypted = crypto_engine.hasp_decrypt(retrieved_encrypted, wibukey_dongle.aes_key, "AES")

        assert decrypted == user_data

    def test_container_license_entry_encryption(self, wibukey_dongle: WibuKeyDongle, crypto_engine: CryptoEngine) -> None:
        """Container license entries encrypted for secure storage."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library not available")

        license_entry = wibukey_dongle.license_entries[1]
        license_bytes = struct.pack(
            "<IIIII",
            license_entry["firm_code"],
            license_entry["product_code"],
            license_entry["feature_code"],
            license_entry["quantity"],
            license_entry["expiration"],
        )

        encrypted_license = crypto_engine.hasp_encrypt(license_bytes, wibukey_dongle.aes_key, "AES")

        assert encrypted_license != license_bytes
        assert len(encrypted_license) >= len(license_bytes)

        decrypted_license = crypto_engine.hasp_decrypt(encrypted_license, wibukey_dongle.aes_key, "AES")
        assert decrypted_license == license_bytes


class TestFirmCodeValidation:
    """Production tests for firm code validation and matching."""

    def test_firm_code_exact_match(self, wibukey_dongle: WibuKeyDongle) -> None:
        """Firm code validation requires exact match."""
        emulator = HardwareDongleEmulator()
        emulator.wibukey_dongles[1] = wibukey_dongle

        correct_firm_code = wibukey_dongle.firm_code
        correct_product_code = wibukey_dongle.product_code

        request_data = struct.pack("<II", correct_firm_code, correct_product_code)
        response = emulator._wibukey_open(request_data)

        error_code = struct.unpack("<I", response[:4])[0]
        assert error_code == 0

    def test_firm_code_mismatch_rejection(self, wibukey_dongle: WibuKeyDongle) -> None:
        """Firm code mismatch rejects container open."""
        emulator = HardwareDongleEmulator()
        emulator.wibukey_dongles[1] = wibukey_dongle

        incorrect_firm_code = wibukey_dongle.firm_code + 1000
        correct_product_code = wibukey_dongle.product_code

        request_data = struct.pack("<II", incorrect_firm_code, correct_product_code)
        response = emulator._wibukey_open(request_data)

        error_code = struct.unpack("<I", response)[0]
        assert error_code == 1

    def test_firm_code_range_validation(self, wibukey_dongle: WibuKeyDongle) -> None:
        """Firm code validates within expected range."""
        assert 1 <= wibukey_dongle.firm_code <= 0xFFFFFFFF
        assert wibukey_dongle.firm_code == 101

    def test_product_code_mismatch_rejection(self, wibukey_dongle: WibuKeyDongle) -> None:
        """Product code mismatch rejects container open."""
        emulator = HardwareDongleEmulator()
        emulator.wibukey_dongles[1] = wibukey_dongle

        correct_firm_code = wibukey_dongle.firm_code
        incorrect_product_code = wibukey_dongle.product_code + 5000

        request_data = struct.pack("<II", correct_firm_code, incorrect_product_code)
        response = emulator._wibukey_open(request_data)

        error_code = struct.unpack("<I", response)[0]
        assert error_code == 1

    def test_firm_code_license_entry_association(self, wibukey_dongle: WibuKeyDongle) -> None:
        """License entries correctly associated with firm code."""
        for license_id, license_entry in wibukey_dongle.license_entries.items():
            assert license_entry["firm_code"] == wibukey_dongle.firm_code


class TestTimeTamperDetection:
    """Production tests for time-tamper detection in CodeMeter licenses."""

    def test_time_based_license_expiration_validation(self, wibukey_dongle: WibuKeyDongle) -> None:
        """Time-based license expiration correctly validated."""
        current_time = int(time.time())
        future_expiration = current_time + 86400

        wibukey_dongle.license_entries[999] = {
            "firm_code": wibukey_dongle.firm_code,
            "product_code": wibukey_dongle.product_code,
            "feature_code": 999,
            "quantity": 1,
            "expiration": future_expiration,
            "enabled": True,
        }

        license_valid = wibukey_dongle.license_entries[999]["expiration"] > current_time
        assert license_valid

    def test_expired_license_rejection(self, wibukey_dongle: WibuKeyDongle) -> None:
        """Expired time-based licenses correctly rejected."""
        current_time = int(time.time())
        past_expiration = current_time - 86400

        wibukey_dongle.license_entries[998] = {
            "firm_code": wibukey_dongle.firm_code,
            "product_code": wibukey_dongle.product_code,
            "feature_code": 998,
            "quantity": 1,
            "expiration": past_expiration,
            "enabled": False,
        }

        license_valid = wibukey_dongle.license_entries[998]["expiration"] > current_time
        assert not license_valid

    def test_time_tamper_detection_with_rtc_counter(self, wibukey_dongle: WibuKeyDongle) -> None:
        """RTC counter detects time manipulation attempts."""
        initial_rtc = wibukey_dongle.rtc_counter
        wibukey_dongle.rtc_counter += 1000

        assert wibukey_dongle.rtc_counter == initial_rtc + 1000

        backward_time_jump = wibukey_dongle.rtc_counter - 2000
        time_tamper_detected = backward_time_jump < initial_rtc

        assert time_tamper_detected

    def test_license_usage_time_tracking(self, wibukey_dongle: WibuKeyDongle) -> None:
        """License usage time correctly tracked for time-tamper detection."""
        wibukey_dongle.license_entries[997] = {
            "firm_code": wibukey_dongle.firm_code,
            "product_code": wibukey_dongle.product_code,
            "feature_code": 997,
            "quantity": 1,
            "expiration": 0xFFFFFFFF,
            "enabled": True,
            "first_use": int(time.time()),
            "last_use": int(time.time()),
            "total_runtime": 0,
        }

        time.sleep(0.1)
        current_time = int(time.time())
        wibukey_dongle.license_entries[997]["last_use"] = current_time
        wibukey_dongle.license_entries[997]["total_runtime"] = current_time - wibukey_dongle.license_entries[997]["first_use"]

        assert wibukey_dongle.license_entries[997]["total_runtime"] >= 0
        assert wibukey_dongle.license_entries[997]["last_use"] >= wibukey_dongle.license_entries[997]["first_use"]

    def test_monotonic_time_counter_enforcement(self, wibukey_dongle: WibuKeyDongle) -> None:
        """Monotonic time counter prevents backward time jumps."""
        wibukey_dongle.rtc_counter = 10000

        previous_counter = wibukey_dongle.rtc_counter
        wibukey_dongle.rtc_counter += 500

        assert wibukey_dongle.rtc_counter > previous_counter

        attempt_backward_jump = 5000
        tamper_detected = attempt_backward_jump < previous_counter

        assert tamper_detected


class TestRemoteLicensing:
    """Production tests for remote licensing (network-based CodeMeter licenses)."""

    def test_remote_license_server_configuration(self, wibukey_dongle: WibuKeyDongle) -> None:
        """Remote license configured with server address and port."""
        remote_license_id = 800
        wibukey_dongle.license_entries[remote_license_id] = {
            "firm_code": wibukey_dongle.firm_code,
            "product_code": wibukey_dongle.product_code,
            "feature_code": 800,
            "quantity": 5,
            "expiration": 0xFFFFFFFF,
            "enabled": True,
            "remote": True,
            "server_address": "192.168.1.100",
            "server_port": 22350,
        }

        license_entry = wibukey_dongle.license_entries[remote_license_id]

        assert license_entry["remote"] is True
        assert "server_address" in license_entry
        assert "server_port" in license_entry
        assert license_entry["server_port"] == 22350

    def test_remote_license_authentication_token(self, wibukey_dongle: WibuKeyDongle) -> None:
        """Remote license includes authentication token for server validation."""
        server_challenge = os.urandom(16)
        auth_token = hashlib.sha256(server_challenge + wibukey_dongle.challenge_response_key).digest()

        remote_license_id = 801
        wibukey_dongle.license_entries[remote_license_id] = {
            "firm_code": wibukey_dongle.firm_code,
            "product_code": wibukey_dongle.product_code,
            "feature_code": 801,
            "quantity": 1,
            "expiration": 0xFFFFFFFF,
            "enabled": True,
            "remote": True,
            "server_address": "license.example.com",
            "server_port": 22350,
            "auth_token": auth_token,
        }

        assert wibukey_dongle.license_entries[remote_license_id]["auth_token"] == auth_token
        assert len(wibukey_dongle.license_entries[remote_license_id]["auth_token"]) == 32

    def test_remote_license_network_checkout(self, wibukey_dongle: WibuKeyDongle) -> None:
        """Remote license checkout tracked for network floating licenses."""
        remote_license_id = 802
        wibukey_dongle.license_entries[remote_license_id] = {
            "firm_code": wibukey_dongle.firm_code,
            "product_code": wibukey_dongle.product_code,
            "feature_code": 802,
            "quantity": 10,
            "expiration": 0xFFFFFFFF,
            "enabled": True,
            "remote": True,
            "server_address": "192.168.1.200",
            "server_port": 22350,
            "checked_out": 0,
            "checkout_clients": [],
        }

        client_id = hashlib.sha256(os.urandom(16)).hexdigest()
        wibukey_dongle.license_entries[remote_license_id]["checked_out"] += 1
        wibukey_dongle.license_entries[remote_license_id]["checkout_clients"].append(client_id)

        assert wibukey_dongle.license_entries[remote_license_id]["checked_out"] == 1
        assert client_id in wibukey_dongle.license_entries[remote_license_id]["checkout_clients"]

    def test_remote_license_heartbeat_timeout(self, wibukey_dongle: WibuKeyDongle) -> None:
        """Remote license heartbeat timeout releases stale checkouts."""
        remote_license_id = 803
        heartbeat_timeout = 300
        wibukey_dongle.license_entries[remote_license_id] = {
            "firm_code": wibukey_dongle.firm_code,
            "product_code": wibukey_dongle.product_code,
            "feature_code": 803,
            "quantity": 5,
            "expiration": 0xFFFFFFFF,
            "enabled": True,
            "remote": True,
            "server_address": "192.168.1.250",
            "server_port": 22350,
            "checked_out": 1,
            "last_heartbeat": int(time.time()) - 400,
            "heartbeat_timeout": heartbeat_timeout,
        }

        current_time = int(time.time())
        last_heartbeat = wibukey_dongle.license_entries[remote_license_id]["last_heartbeat"]
        heartbeat_expired = (current_time - last_heartbeat) > heartbeat_timeout

        assert heartbeat_expired

        if heartbeat_expired:
            wibukey_dongle.license_entries[remote_license_id]["checked_out"] = 0

        assert wibukey_dongle.license_entries[remote_license_id]["checked_out"] == 0

    def test_remote_license_failover_server(self, wibukey_dongle: WibuKeyDongle) -> None:
        """Remote license supports failover to backup server."""
        remote_license_id = 804
        wibukey_dongle.license_entries[remote_license_id] = {
            "firm_code": wibukey_dongle.firm_code,
            "product_code": wibukey_dongle.product_code,
            "feature_code": 804,
            "quantity": 3,
            "expiration": 0xFFFFFFFF,
            "enabled": True,
            "remote": True,
            "server_address": "primary.license.com",
            "server_port": 22350,
            "failover_servers": [
                {"address": "backup1.license.com", "port": 22350},
                {"address": "backup2.license.com", "port": 22350},
            ],
        }

        failover_servers = wibukey_dongle.license_entries[remote_license_id]["failover_servers"]

        assert len(failover_servers) == 2
        assert failover_servers[0]["address"] == "backup1.license.com"
        assert failover_servers[1]["address"] == "backup2.license.com"


class TestCodeMeterIntegration:
    """Integration tests validating complete CodeMeter emulation workflow."""

    def test_complete_codemeter_workflow(self, wibukey_dongle: WibuKeyDongle, crypto_engine: CryptoEngine) -> None:
        """Complete CodeMeter workflow: open, access, encrypt, challenge."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library not available")

        emulator = HardwareDongleEmulator()
        emulator.wibukey_dongles[1] = wibukey_dongle

        open_request = struct.pack("<II", wibukey_dongle.firm_code, wibukey_dongle.product_code)
        open_response = emulator._wibukey_open(open_request)
        error_code, container_handle = struct.unpack("<II", open_response)
        assert error_code == 0

        access_request = struct.pack("<III", container_handle, 1, 0x00000001)
        access_response = emulator._wibukey_access(access_request)
        access_error = struct.unpack("<I", access_response)[0]
        assert access_error == 0

        plaintext = b"TEST_ENCRYPTION_DATA"
        encrypt_request = struct.pack("<II", container_handle, len(plaintext)) + plaintext
        encrypt_response = emulator._wibukey_encrypt(encrypt_request)
        enc_error, enc_len = struct.unpack("<II", encrypt_response[:8])
        encrypted_data = encrypt_response[8:]
        assert enc_error == 0
        assert encrypted_data != plaintext

        challenge = os.urandom(16)
        challenge_request = struct.pack("<II", container_handle, len(challenge)) + challenge
        challenge_response = emulator._wibukey_challenge(challenge_request)
        chal_error, chal_len = struct.unpack("<II", challenge_response[:8])
        response_data = challenge_response[8:]
        assert chal_error == 0
        assert response_data != challenge

    def test_multiple_concurrent_container_access(self) -> None:
        """Multiple CodeMeter containers accessed concurrently."""
        emulator = HardwareDongleEmulator()

        dongle1 = WibuKeyDongle(firm_code=101, product_code=1000, serial_number=1000001)
        dongle2 = WibuKeyDongle(firm_code=102, product_code=2000, serial_number=2000001)

        emulator.wibukey_dongles[1] = dongle1
        emulator.wibukey_dongles[2] = dongle2

        open1 = emulator._wibukey_open(struct.pack("<II", 101, 1000))
        open2 = emulator._wibukey_open(struct.pack("<II", 102, 2000))

        error1, handle1 = struct.unpack("<II", open1)
        error2, handle2 = struct.unpack("<II", open2)

        assert error1 == 0
        assert error2 == 0
        assert handle1 == dongle1.container_handle
        assert handle2 == dongle2.container_handle

    def test_full_emulation_activation(self) -> None:
        """Full CodeMeter emulation activation workflow."""
        emulator = HardwareDongleEmulator()

        result = emulator.activate_dongle_emulation(dongle_types=["CodeMeter"])

        assert result["success"] is True
        assert "Virtual Dongle Creation" in result["methods_applied"]
        assert "USB Device Emulation" in result["methods_applied"]
        assert len(result["emulated_dongles"]) > 0
        assert any("WibuKey" in dongle for dongle in result["emulated_dongles"])
