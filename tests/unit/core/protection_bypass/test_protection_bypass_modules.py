"""Real-world protection bypass module tests.

Tests bypass capabilities with real system calls and operations.
NO MOCKS - Uses real system interaction where possible.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.protection_bypass.dongle_emulator import (
    DongleType,
    HardwareDongleEmulator,
    HASPDongle,
    SentinelDongle,
    WibuKeyDongle,
    activate_hardware_dongle_emulation,
)
from intellicrack.core.protection_bypass.hardware_id_spoofer import (
    HardwareIDSpoofer,
)
from intellicrack.core.protection_bypass.cloud_license_analyzer import (
    CloudLicenseAnalyzer,
    CloudEndpoint,
    LicenseToken,
)


@pytest.fixture
def temp_dir() -> Path:
    """Create temporary directory for test artifacts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestHardwareDongleEmulator:
    """Test hardware dongle emulation capabilities."""

    def test_emulator_initialization(self) -> None:
        """Test hardware dongle emulator initializes."""
        emulator = HardwareDongleEmulator()

        assert emulator is not None
        assert hasattr(emulator, "activate_dongle_emulation")
        assert hasattr(emulator, "process_hasp_challenge")
        assert hasattr(emulator, "read_dongle_memory")
        assert hasattr(emulator, "write_dongle_memory")

    def test_hasp_dongle_creation(self) -> None:
        """Test HASP dongle object creation."""
        hasp = HASPDongle(
            feature_id=1,
            vendor_code=0x01234567,
            memory_size=4096,
        )

        assert hasp is not None
        assert hasp.feature_id == 1
        assert hasp.vendor_code == 0x01234567
        assert hasp.memory_size == 4096

    def test_sentinel_dongle_creation(self) -> None:
        """Test Sentinel dongle object creation."""
        sentinel = SentinelDongle(
            product_id=12345,
            feature_count=5,
            memory_size=2048,
        )

        assert sentinel is not None
        assert sentinel.product_id == 12345
        assert sentinel.feature_count == 5

    def test_wibukey_dongle_creation(self) -> None:
        """Test WibuKey dongle object creation."""
        wibukey = WibuKeyDongle(
            firm_code=1000,
            user_code=2000,
            memory_size=8192,
        )

        assert wibukey is not None
        assert wibukey.firm_code == 1000
        assert wibukey.user_code == 2000

    def test_activate_dongle_emulation(self) -> None:
        """Test activating dongle emulation."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        emulator = HardwareDongleEmulator()

        result = emulator.activate_dongle_emulation(
            dongle_type=DongleType.HASP,
            target_process=None,
        )

        assert result is not None
        assert isinstance(result, (dict, bool))

    def test_hasp_challenge_processing(self) -> None:
        """Test HASP challenge-response processing."""
        emulator = HardwareDongleEmulator()

        challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08"

        response = emulator.process_hasp_challenge(challenge=challenge)

        assert response is not None
        assert isinstance(response, bytes)
        assert len(response) > 0

    def test_read_dongle_memory(self) -> None:
        """Test reading from emulated dongle memory."""
        emulator = HardwareDongleEmulator()

        data = emulator.read_dongle_memory(
            dongle_type=DongleType.HASP,
            address=0,
            size=16,
        )

        assert data is not None
        assert isinstance(data, bytes)

    def test_write_dongle_memory(self) -> None:
        """Test writing to emulated dongle memory."""
        emulator = HardwareDongleEmulator()

        test_data = b"TEST_DATA_HERE!!"

        result = emulator.write_dongle_memory(
            dongle_type=DongleType.HASP,
            address=0,
            data=test_data,
        )

        assert result is not None

        read_back = emulator.read_dongle_memory(
            dongle_type=DongleType.HASP,
            address=0,
            size=len(test_data),
        )

    def test_generate_emulation_script(self) -> None:
        """Test generating Frida emulation script."""
        emulator = HardwareDongleEmulator()

        script = emulator.generate_emulation_script(dongle_type=DongleType.HASP)

        assert script is not None
        assert isinstance(script, str)
        assert len(script) > 0

    def test_get_emulation_status(self) -> None:
        """Test retrieving emulation status."""
        emulator = HardwareDongleEmulator()

        status = emulator.get_emulation_status()

        assert status is not None
        assert isinstance(status, dict)

    def test_clear_emulation(self) -> None:
        """Test clearing dongle emulation."""
        emulator = HardwareDongleEmulator()

        emulator.clear_emulation()

    def test_factory_function_activate_emulation(self) -> None:
        """Test factory function for dongle emulation activation."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        result = activate_hardware_dongle_emulation(
            dongle_type="hasp",
            target_process=None,
        )

        assert result is not None


class TestHardwareIDSpoofer:
    """Test hardware ID spoofing capabilities."""

    def test_spoofer_initialization(self) -> None:
        """Test hardware ID spoofer initializes."""
        spoofer = HardwareIDSpoofer()

        assert spoofer is not None
        assert hasattr(spoofer, "collect_hardware_info")
        assert hasattr(spoofer, "spoof_cpu_id")
        assert hasattr(spoofer, "spoof_mac_address")
        assert hasattr(spoofer, "spoof_disk_serial")

    def test_collect_hardware_info(self) -> None:
        """Test collecting real hardware information."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        spoofer = HardwareIDSpoofer()

        hardware_info = spoofer.collect_hardware_info()

        assert hardware_info is not None
        assert isinstance(hardware_info, dict)

        expected_keys = ["cpu_id", "mac_addresses", "disk_serials"]
        for key in expected_keys:
            if key in hardware_info:
                assert hardware_info[key] is not None

    def test_spoof_cpu_id_generation(self) -> None:
        """Test CPU ID spoofing preparation."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        spoofer = HardwareIDSpoofer()

        result = spoofer._generate_random_cpu_id()

        assert result is not None
        assert isinstance(result, (str, int))

    def test_spoof_mac_address_generation(self) -> None:
        """Test MAC address generation."""
        spoofer = HardwareIDSpoofer()

        mac = spoofer._generate_random_mac()

        assert mac is not None
        assert isinstance(mac, str)
        assert len(mac) > 0

    def test_spoof_disk_serial_generation(self) -> None:
        """Test disk serial generation."""
        spoofer = HardwareIDSpoofer()

        serial = spoofer._generate_random_disk_serial()

        assert serial is not None
        assert isinstance(serial, str)

    def test_generate_random_profile(self) -> None:
        """Test generating complete random hardware profile."""
        spoofer = HardwareIDSpoofer()

        profile = spoofer.generate_random_profile()

        assert profile is not None
        assert isinstance(profile, dict)
        assert len(profile) > 0

        expected_keys = ["cpu_id", "mac_address", "disk_serial"]
        for key in expected_keys:
            if key in profile:
                assert profile[key] is not None

    def test_save_and_load_profile(self, temp_dir: Path) -> None:
        """Test saving and loading hardware spoof profiles."""
        spoofer = HardwareIDSpoofer()

        profile = spoofer.generate_random_profile()

        profile_file = temp_dir / "hwid_profile.json"

        spoofer.save_profile(profile, str(profile_file))

        assert profile_file.exists()

        loaded_profile = spoofer.load_profile(str(profile_file))

        assert loaded_profile is not None
        assert isinstance(loaded_profile, dict)

    def test_cleanup(self) -> None:
        """Test spoofer cleanup."""
        spoofer = HardwareIDSpoofer()

        spoofer.cleanup()


class TestCloudLicenseAnalyzer:
    """Test cloud license analysis capabilities."""

    def test_analyzer_initialization(self) -> None:
        """Test cloud license analyzer initializes."""
        analyzer = CloudLicenseAnalyzer()

        assert analyzer is not None
        assert hasattr(analyzer, "start_interception")
        assert hasattr(analyzer, "analyze_endpoint")
        assert hasattr(analyzer, "extract_license_tokens")
        assert hasattr(analyzer, "generate_token")

    def test_cloud_endpoint_creation(self) -> None:
        """Test CloudEndpoint dataclass creation."""
        endpoint = CloudEndpoint(
            url="https://api.example.com/license/validate",
            method="POST",
            headers={"Authorization": "Bearer token123"},
            payload={"user_id": "12345"},
        )

        assert endpoint is not None
        assert endpoint.url == "https://api.example.com/license/validate"
        assert endpoint.method == "POST"

    def test_license_token_creation(self) -> None:
        """Test LicenseToken dataclass creation."""
        token = LicenseToken(
            token_type="jwt",
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            expires_at=1234567890,
            scope=["read", "write"],
        )

        assert token is not None
        assert token.token_type == "jwt"
        assert token.expires_at == 1234567890

    def test_analyze_endpoint(self) -> None:
        """Test endpoint analysis."""
        analyzer = CloudLicenseAnalyzer()

        endpoint_data = {
            "url": "https://api.example.com/license",
            "method": "GET",
            "response": '{"license": "valid", "expiration": 1234567890}',
        }

        result = analyzer.analyze_endpoint(endpoint_data)

        assert result is not None
        assert isinstance(result, (dict, CloudEndpoint))

    def test_extract_license_tokens(self) -> None:
        """Test license token extraction from traffic."""
        analyzer = CloudLicenseAnalyzer()

        traffic_data = {
            "headers": {"Authorization": "Bearer test_token_12345"},
            "body": '{"access_token": "jwt_token_here", "refresh_token": "refresh_token_here"}',
        }

        tokens = analyzer.extract_license_tokens(traffic_data)

        assert tokens is not None
        assert isinstance(tokens, (list, dict))

    def test_generate_jwt_token(self) -> None:
        """Test JWT token generation."""
        analyzer = CloudLicenseAnalyzer()

        payload = {
            "user_id": "12345",
            "email": "test@example.com",
            "license_type": "professional",
            "expires": 1234567890,
        }

        token = analyzer.generate_token(
            token_type="jwt",
            payload=payload,
        )

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

    def test_generate_api_key_token(self) -> None:
        """Test API key generation."""
        analyzer = CloudLicenseAnalyzer()

        token = analyzer.generate_token(
            token_type="api_key",
            payload={},
        )

        assert token is not None
        assert isinstance(token, str)

    def test_generate_license_key_token(self) -> None:
        """Test license key generation."""
        analyzer = CloudLicenseAnalyzer()

        token = analyzer.generate_token(
            token_type="license_key",
            payload={"product_id": "ABC123"},
        )

        assert token is not None
        assert isinstance(token, str)

    def test_export_analysis(self, temp_dir: Path) -> None:
        """Test exporting analysis results."""
        analyzer = CloudLicenseAnalyzer()

        analyzer.discovered_endpoints.append(
            CloudEndpoint(
                url="https://api.example.com/license",
                method="GET",
                headers={},
                payload={},
            )
        )

        export_file = temp_dir / "cloud_analysis.json"

        analyzer.export_analysis(str(export_file))

        assert export_file.exists()

    def test_cleanup(self) -> None:
        """Test analyzer cleanup."""
        analyzer = CloudLicenseAnalyzer()

        analyzer.cleanup()


class TestIntegration:
    """Test integration between protection bypass modules."""

    def test_dongle_emulator_with_hwid_spoofer(self) -> None:
        """Test integration of dongle emulation with HWID spoofing."""
        emulator = HardwareDongleEmulator()
        spoofer = HardwareIDSpoofer()

        assert emulator is not None
        assert spoofer is not None

        profile = spoofer.generate_random_profile()
        assert profile is not None

        status = emulator.get_emulation_status()
        assert status is not None

    def test_cloud_analyzer_with_dongle_emulator(self) -> None:
        """Test cloud license analysis with dongle emulation."""
        analyzer = CloudLicenseAnalyzer()
        emulator = HardwareDongleEmulator()

        assert analyzer is not None
        assert emulator is not None

        token = analyzer.generate_token(
            token_type="jwt",
            payload={"license": "pro"},
        )

        assert token is not None

    def test_complete_bypass_stack(self) -> None:
        """Test complete protection bypass stack."""
        spoofer = HardwareIDSpoofer()

        profile = spoofer.generate_random_profile()
        assert profile is not None

        emulator = HardwareDongleEmulator()
        emulator_status = emulator.get_emulation_status()
        assert emulator_status is not None

        analyzer = CloudLicenseAnalyzer()
        token = analyzer.generate_token(
            token_type="license_key",
            payload={"product": "test"},
        )
        assert token is not None
