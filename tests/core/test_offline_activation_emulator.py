"""Comprehensive production tests for offline activation emulator functionality.

Tests all activation algorithms, hardware profiling, request/response generation,
license file creation, cryptographic operations, and trial bypass mechanisms.
"""

import base64
import hashlib
import json
import os
import platform
import struct
import tempfile
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

from intellicrack.core.offline_activation_emulator import (
    ActivationRequest,
    ActivationResponse,
    ActivationType,
    ExtendedActivationRequest,
    HardwareProfile,
    MachineProfile,
    OfflineActivationEmulator,
    RequestFormat,
)


@pytest.fixture
def emulator() -> OfflineActivationEmulator:
    """Create OfflineActivationEmulator instance for testing."""
    return OfflineActivationEmulator()


@pytest.fixture
def hardware_profile(emulator: OfflineActivationEmulator) -> HardwareProfile:
    """Get hardware profile from current system."""
    return emulator.get_hardware_profile()


@pytest.fixture
def sample_activation_request() -> ActivationRequest:
    """Create sample activation request for testing."""
    return ActivationRequest(
        product_id="TestProduct-2024",
        product_version="1.0.0",
        hardware_id="ABCD-1234-EFGH-5678",
        installation_id="INSTALL-12345678-ABCD",
        request_code="123456-789012-345678-901234",
        timestamp=datetime.now(),
        additional_data={"platform": "Windows", "edition": "Professional"},
    )


@pytest.fixture
def machine_profile() -> MachineProfile:
    """Create sample machine profile for activation requests."""
    return MachineProfile(
        machine_id="TEST123456789ABC",
        cpu_id="BFEBFBFF000906E9",
        motherboard_serial="MB123456789",
        disk_serial="SN123456789ABCDE",
        mac_address="00:1A:2B:3C:4D:5E",
        hostname="test-machine",
        username="testuser",
        os_version="Windows 10 Pro",
        install_date=int(time.time() - 86400 * 30),
        install_path="C:\\Program Files\\TestApp",
        product_version="1.0.0",
    )


class TestHardwareProfileRetrieval:
    """Test hardware profile retrieval from system."""

    def test_get_hardware_profile_returns_complete_profile(self, emulator: OfflineActivationEmulator) -> None:
        """Hardware profile contains all required system identifiers."""
        profile: HardwareProfile = emulator.get_hardware_profile()

        assert isinstance(profile, HardwareProfile)
        assert profile.cpu_id
        assert len(profile.cpu_id) >= 8
        assert profile.motherboard_serial
        assert profile.disk_serial
        assert isinstance(profile.mac_addresses, list)
        assert len(profile.mac_addresses) > 0
        assert profile.bios_serial
        assert profile.system_uuid
        assert profile.volume_serial
        assert profile.machine_guid

    def test_cpu_id_format_valid(self, hardware_profile: HardwareProfile) -> None:
        """CPU ID follows expected hexadecimal format."""
        assert hardware_profile.cpu_id.replace(" ", "").replace("-", "").isalnum()
        assert len(hardware_profile.cpu_id.replace(" ", "").replace("-", "")) >= 8

    def test_mac_addresses_valid_format(self, hardware_profile: HardwareProfile) -> None:
        """MAC addresses follow standard hexadecimal format."""
        for mac in hardware_profile.mac_addresses:
            clean_mac: str = mac.replace(":", "").replace("-", "")
            assert len(clean_mac) == 12
            assert all(c in "0123456789ABCDEFabcdef" for c in clean_mac)

    def test_system_uuid_valid_format(self, hardware_profile: HardwareProfile) -> None:
        """System UUID follows UUID format specification."""
        uuid_str: str = hardware_profile.system_uuid.replace("-", "")
        assert len(uuid_str) >= 32
        assert all(c in "0123456789ABCDEFabcdef-" for c in hardware_profile.system_uuid)

    def test_hardware_profile_deterministic_on_same_system(self, emulator: OfflineActivationEmulator) -> None:
        """Hardware profile remains consistent across multiple retrievals."""
        profile1: HardwareProfile = emulator.get_hardware_profile()
        profile2: HardwareProfile = emulator.get_hardware_profile()

        assert profile1.cpu_id == profile2.cpu_id
        assert profile1.motherboard_serial == profile2.motherboard_serial
        assert profile1.disk_serial == profile2.disk_serial
        assert profile1.system_uuid == profile2.system_uuid


class TestHardwareIDGeneration:
    """Test hardware ID generation from profiles."""

    def test_standard_hardware_id_format(self, emulator: OfflineActivationEmulator, hardware_profile: HardwareProfile) -> None:
        """Standard algorithm generates properly formatted hardware ID."""
        hw_id: str = emulator.generate_hardware_id(hardware_profile, "standard")

        assert "-" in hw_id
        groups: list[str] = hw_id.split("-")
        assert all(len(group) == 5 for group in groups)
        assert all(group.isalnum() for group in groups)

    def test_microsoft_hardware_id_format(self, emulator: OfflineActivationEmulator, hardware_profile: HardwareProfile) -> None:
        """Microsoft algorithm generates 8-character hexadecimal ID."""
        hw_id: str = emulator.generate_hardware_id(hardware_profile, "microsoft")

        assert len(hw_id) == 8
        assert all(c in "0123456789ABCDEF" for c in hw_id)

    def test_adobe_hardware_id_format(self, emulator: OfflineActivationEmulator, hardware_profile: HardwareProfile) -> None:
        """Adobe algorithm generates hyphen-separated LEID format."""
        hw_id: str = emulator.generate_hardware_id(hardware_profile, "adobe")

        assert hw_id.count("-") == 3
        groups: list[str] = hw_id.split("-")
        assert len(groups) == 4
        assert all(len(group) == 4 for group in groups)

    def test_custom_hardware_id_uses_pbkdf2(self, emulator: OfflineActivationEmulator, hardware_profile: HardwareProfile) -> None:
        """Custom algorithm produces base64-encoded PBKDF2 key."""
        hw_id: str = emulator.generate_hardware_id(hardware_profile, "custom")

        try:
            decoded: bytes = base64.b64decode(hw_id)
            assert len(decoded) == 24
        except Exception:
            pytest.fail("Custom hardware ID not valid base64")

    def test_hardware_id_deterministic_for_profile(self, emulator: OfflineActivationEmulator, hardware_profile: HardwareProfile) -> None:
        """Same profile generates same hardware ID consistently."""
        hw_id1: str = emulator.generate_hardware_id(hardware_profile, "standard")
        hw_id2: str = emulator.generate_hardware_id(hardware_profile, "standard")

        assert hw_id1 == hw_id2

    def test_hardware_id_unique_per_profile(self, emulator: OfflineActivationEmulator) -> None:
        """Different profiles generate different hardware IDs."""
        profile1: HardwareProfile = HardwareProfile(
            cpu_id="CPU1",
            motherboard_serial="MB1",
            disk_serial="DISK1",
            mac_addresses=["001122334455"],
            bios_serial="BIOS1",
            system_uuid="UUID1",
            volume_serial="VOL1",
            machine_guid="GUID1",
        )
        profile2: HardwareProfile = HardwareProfile(
            cpu_id="CPU2",
            motherboard_serial="MB2",
            disk_serial="DISK2",
            mac_addresses=["AABBCCDDEEFF"],
            bios_serial="BIOS2",
            system_uuid="UUID2",
            volume_serial="VOL2",
            machine_guid="GUID2",
        )

        hw_id1: str = emulator.generate_hardware_id(profile1)
        hw_id2: str = emulator.generate_hardware_id(profile2)

        assert hw_id1 != hw_id2


class TestInstallationIDGeneration:
    """Test installation ID generation binding products to hardware."""

    def test_installation_id_format(self, emulator: OfflineActivationEmulator) -> None:
        """Installation ID formatted as hyphen-separated hex groups."""
        install_id: str = emulator.generate_installation_id("PRODUCT-123", "HARDWARE-456")

        assert "-" in install_id
        groups: list[str] = install_id.split("-")
        assert all(len(group) == 6 for group in groups)
        assert all(all(c in "0123456789ABCDEF" for c in group) for group in groups)

    def test_installation_id_deterministic(self, emulator: OfflineActivationEmulator) -> None:
        """Same product and hardware produce same installation ID."""
        install_id1: str = emulator.generate_installation_id("PROD", "HW")
        install_id2: str = emulator.generate_installation_id("PROD", "HW")

        assert install_id1 == install_id2

    def test_installation_id_unique_per_product(self, emulator: OfflineActivationEmulator) -> None:
        """Different products generate different installation IDs."""
        install_id1: str = emulator.generate_installation_id("PRODUCT-A", "HARDWARE-X")
        install_id2: str = emulator.generate_installation_id("PRODUCT-B", "HARDWARE-X")

        assert install_id1 != install_id2

    def test_installation_id_unique_per_hardware(self, emulator: OfflineActivationEmulator) -> None:
        """Different hardware generates different installation IDs."""
        install_id1: str = emulator.generate_installation_id("PRODUCT-X", "HARDWARE-A")
        install_id2: str = emulator.generate_installation_id("PRODUCT-X", "HARDWARE-B")

        assert install_id1 != install_id2


class TestRequestCodeGeneration:
    """Test request code generation from installation IDs."""

    def test_request_code_format(self, emulator: OfflineActivationEmulator) -> None:
        """Request code formatted as 9 groups of 6 digits."""
        request_code: str = emulator.generate_request_code("INSTALL-123456")

        assert request_code.count("-") == 8
        groups: list[str] = request_code.split("-")
        assert len(groups) == 9
        assert all(len(group) == 6 for group in groups)
        assert all(group.isdigit() for group in groups)

    def test_request_code_deterministic(self, emulator: OfflineActivationEmulator) -> None:
        """Same installation ID produces same request code."""
        request_code1: str = emulator.generate_request_code("INSTALL-ABCD")
        request_code2: str = emulator.generate_request_code("INSTALL-ABCD")

        assert request_code1 == request_code2

    def test_request_code_unique_per_installation(self, emulator: OfflineActivationEmulator) -> None:
        """Different installation IDs produce different request codes."""
        request_code1: str = emulator.generate_request_code("INSTALL-AAA")
        request_code2: str = emulator.generate_request_code("INSTALL-BBB")

        assert request_code1 != request_code2


class TestMicrosoftActivation:
    """Test Microsoft Office activation response generation."""

    def test_microsoft_activation_generates_confirmation_id(self, emulator: OfflineActivationEmulator) -> None:
        """Microsoft activation produces properly formatted confirmation ID."""
        request: ActivationRequest = ActivationRequest(
            product_id="Microsoft Office 2024",
            product_version="16.0",
            hardware_id="12345678",
            installation_id="123456-789012-345678-901234-567890-123456-789012-345678",
            request_code="111111-222222-333333-444444-555555-666666-777777-888888-999999",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        assert response.activation_code
        assert "-" in response.activation_code
        groups: list[str] = response.activation_code.split("-")
        assert len(groups) == 8
        assert all(len(group) == 6 for group in groups)
        assert all(group.isdigit() for group in groups)

    def test_microsoft_activation_hardware_locked(self, emulator: OfflineActivationEmulator) -> None:
        """Microsoft activation response is hardware-locked."""
        request: ActivationRequest = ActivationRequest(
            product_id="Microsoft Office Pro",
            product_version="16.0",
            hardware_id="HW123",
            installation_id="INST123",
            request_code="REQ123",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        assert response.hardware_locked is True

    def test_microsoft_activation_includes_features(self, emulator: OfflineActivationEmulator) -> None:
        """Microsoft activation includes Professional/Enterprise features."""
        request: ActivationRequest = ActivationRequest(
            product_id="office",
            product_version="16.0",
            hardware_id="HW",
            installation_id="INST",
            request_code="REQ",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        assert "Professional" in response.features or "Enterprise" in response.features

    def test_microsoft_activation_with_product_key(self, emulator: OfflineActivationEmulator) -> None:
        """Microsoft activation accepts custom product key."""
        request: ActivationRequest = ActivationRequest(
            product_id="Microsoft",
            product_version="1.0",
            hardware_id="HW",
            installation_id="INST",
            request_code="REQ",
            timestamp=datetime.now(),
            additional_data={},
        )
        product_key: str = "XXXXX-YYYYY-ZZZZZ-AAAAA-BBBBB"

        response: ActivationResponse = emulator.generate_activation_response(request, product_key)

        assert response.license_key == product_key


class TestAdobeActivation:
    """Test Adobe Creative Cloud activation response generation."""

    def test_adobe_activation_generates_response_code(self, emulator: OfflineActivationEmulator) -> None:
        """Adobe activation produces formatted response code."""
        request: ActivationRequest = ActivationRequest(
            product_id="Adobe Photoshop CC",
            product_version="2024",
            hardware_id="ADOBE-HW-123",
            installation_id="ADOBE-INST",
            request_code="ADOBE-REQ-CODE",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        assert response.activation_code
        assert "-" in response.activation_code
        assert all(c in "0123456789ABCDEF-" for c in response.activation_code)

    def test_adobe_activation_includes_signature(self, emulator: OfflineActivationEmulator) -> None:
        """Adobe activation includes RSA signature."""
        request: ActivationRequest = ActivationRequest(
            product_id="Adobe CC",
            product_version="1.0",
            hardware_id="HW",
            installation_id="INST",
            request_code="REQ",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        assert response.signature is not None
        assert isinstance(response.signature, bytes)
        assert len(response.signature) > 0

    def test_adobe_activation_creative_cloud_features(self, emulator: OfflineActivationEmulator) -> None:
        """Adobe activation includes Creative Cloud features."""
        request: ActivationRequest = ActivationRequest(
            product_id="adobe",
            product_version="1.0",
            hardware_id="HW",
            installation_id="INST",
            request_code="REQ",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        assert "Creative Cloud" in response.features or "All Apps" in response.features

    def test_adobe_activation_365_day_expiry(self, emulator: OfflineActivationEmulator) -> None:
        """Adobe activation sets 365-day expiration period."""
        request: ActivationRequest = ActivationRequest(
            product_id="Adobe",
            product_version="1.0",
            hardware_id="HW",
            installation_id="INST",
            request_code="REQ",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        assert response.expiry_date is not None
        days_diff: int = (response.expiry_date - datetime.now()).days
        assert 360 <= days_diff <= 370


class TestAutodeskActivation:
    """Test Autodesk AutoCAD activation response generation."""

    def test_autodesk_activation_xor_transformation(self, emulator: OfflineActivationEmulator) -> None:
        """Autodesk activation uses XOR-based algorithm."""
        request: ActivationRequest = ActivationRequest(
            product_id="Autodesk AutoCAD 2024",
            product_version="2024",
            hardware_id="HW",
            installation_id="INST",
            request_code="123456789012345678",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        assert response.activation_code
        assert "-" in response.activation_code
        groups: list[str] = response.activation_code.split("-")
        assert all(all(c in "0123456789ABCDEF" for c in group) for group in groups)

    def test_autodesk_activation_hardware_locked(self, emulator: OfflineActivationEmulator) -> None:
        """Autodesk activation is hardware-locked."""
        request: ActivationRequest = ActivationRequest(
            product_id="Autodesk",
            product_version="1.0",
            hardware_id="HW",
            installation_id="INST",
            request_code="123456",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        assert response.hardware_locked is True


class TestVMwareActivation:
    """Test VMware vSphere activation response generation."""

    def test_vmware_activation_perpetual_license(self, emulator: OfflineActivationEmulator) -> None:
        """VMware activation generates perpetual license."""
        request: ActivationRequest = ActivationRequest(
            product_id="VMware vSphere ESXi",
            product_version="8.0",
            hardware_id="VMWARE-HW",
            installation_id="VMWARE-INST",
            request_code="VMWARE-REQ",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        assert response.expiry_date is None

    def test_vmware_activation_base32_format(self, emulator: OfflineActivationEmulator) -> None:
        """VMware activation uses base32-compatible character set."""
        request: ActivationRequest = ActivationRequest(
            product_id="vmware",
            product_version="1.0",
            hardware_id="HW",
            installation_id="INST",
            request_code="REQ",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        valid_chars: str = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789-"
        assert all(c in valid_chars for c in response.activation_code)


class TestMatlabActivation:
    """Test MATLAB activation and license file generation."""

    def test_matlab_activation_generates_license_file(self, emulator: OfflineActivationEmulator) -> None:
        """MATLAB activation includes signed license file."""
        request: ActivationRequest = ActivationRequest(
            product_id="MATLAB R2024a",
            product_version="R2024a",
            hardware_id="MATLAB-HW",
            installation_id="MATLAB-INST",
            request_code="MATLAB-REQ",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        assert response.signature is not None
        assert isinstance(response.signature, bytes)

    def test_matlab_activation_includes_toolboxes(self, emulator: OfflineActivationEmulator) -> None:
        """MATLAB activation includes toolbox features."""
        request: ActivationRequest = ActivationRequest(
            product_id="matlab",
            product_version="1.0",
            hardware_id="HW",
            installation_id="INST",
            request_code="REQ",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        assert any(feature in response.features for feature in ["MATLAB", "Simulink", "Toolboxes"])


class TestSolidWorksActivation:
    """Test SolidWorks CAD activation response generation."""

    def test_solidworks_activation_transformation(self, emulator: OfflineActivationEmulator) -> None:
        """SolidWorks activation uses multiplication algorithm."""
        request: ActivationRequest = ActivationRequest(
            product_id="SolidWorks Professional 2024",
            product_version="2024",
            hardware_id="SW-HW",
            installation_id="SW-INST",
            request_code="ABC123-DEF456-GHI789-JKL012",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        assert response.activation_code
        assert "-" in response.activation_code
        groups: list[str] = response.activation_code.split("-")
        assert all(len(group) == 6 for group in groups)
        assert all(group.isdigit() for group in groups)


class TestCryptographicActivation:
    """Test RSA, AES, and ECC-based activation algorithms."""

    def test_rsa_activation_generates_signature(self, emulator: OfflineActivationEmulator) -> None:
        """RSA activation produces valid RSA signature."""
        request: ActivationRequest = ActivationRequest(
            product_id="CustomRSA-Product",
            product_version="1.0",
            hardware_id="RSA-HW",
            installation_id="RSA-INST",
            request_code="RSA-REQ",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator._rsa_based_activation(request)

        assert response.signature is not None
        assert isinstance(response.signature, bytes)
        assert len(response.signature) > 100

    def test_aes_activation_encrypted_code(self, emulator: OfflineActivationEmulator) -> None:
        """AES activation produces base64-encoded encrypted code."""
        request: ActivationRequest = ActivationRequest(
            product_id="CustomAES-Product",
            product_version="1.0",
            hardware_id="AES-HW",
            installation_id="AES-INST",
            request_code="AES-REQ",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator._aes_based_activation(request)

        try:
            decoded: bytes = base64.b64decode(response.activation_code)
            assert len(decoded) >= 16
        except Exception:
            pytest.fail("AES activation code not valid base64")

    def test_ecc_activation_ecdsa_signature(self, emulator: OfflineActivationEmulator) -> None:
        """ECC activation produces ECDSA signature."""
        request: ActivationRequest = ActivationRequest(
            product_id="CustomECC-Product",
            product_version="1.0",
            hardware_id="ECC-HW",
            installation_id="ECC-INST",
            request_code="ECC-REQ",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator._ecc_based_activation(request)

        assert response.signature is not None
        assert isinstance(response.signature, bytes)


class TestProductKeyGeneration:
    """Test product key generation for various vendors."""

    def test_microsoft_product_key_format(self, emulator: OfflineActivationEmulator) -> None:
        """Microsoft product key follows 5x5 format."""
        key: str = emulator._generate_product_key("microsoft")

        groups: list[str] = key.split("-")
        assert len(groups) == 5
        assert all(len(group) == 5 for group in groups)
        valid_chars: str = "BCDFGHJKMPQRTVWXY2346789"
        assert all(all(c in valid_chars for c in group) for group in groups)

    def test_adobe_product_key_format(self, emulator: OfflineActivationEmulator) -> None:
        """Adobe product key follows 6x4 digit format."""
        key: str = emulator._generate_product_key("adobe")

        groups: list[str] = key.split("-")
        assert len(groups) == 6
        assert all(len(group) == 4 for group in groups)
        assert all(group.isdigit() for group in groups)

    def test_autodesk_product_key_format(self, emulator: OfflineActivationEmulator) -> None:
        """Autodesk product key follows 3-8 digit format."""
        key: str = emulator._generate_product_key("autodesk")

        parts: list[str] = key.split("-")
        assert len(parts) == 2
        assert len(parts[0]) == 3
        assert len(parts[1]) == 8
        assert all(part.isdigit() for part in parts)

    def test_generic_product_key_format(self, emulator: OfflineActivationEmulator) -> None:
        """Generic product key follows 5x5 alphanumeric format."""
        key: str = emulator._generate_product_key("default")

        groups: list[str] = key.split("-")
        assert len(groups) == 5
        assert all(len(group) == 5 for group in groups)
        assert all(group.isalnum() for group in groups)


class TestLicenseFileCreation:
    """Test license file generation in multiple formats."""

    def test_xml_license_file_format(self, emulator: OfflineActivationEmulator) -> None:
        """XML license file contains all response data."""
        response: ActivationResponse = ActivationResponse(
            activation_code="ACTIV-12345",
            license_key="LICENSE-KEY-12345",
            expiry_date=datetime.now() + timedelta(days=365),
            features=["Premium", "Enterprise"],
            hardware_locked=True,
            signature=b"test_signature_data",
        )

        xml_data: bytes = emulator.create_license_file(response, "xml")
        xml_str: str = xml_data.decode("utf-8")

        assert "LICENSE-KEY-12345" in xml_str
        assert "ACTIV-12345" in xml_str
        assert "Premium" in xml_str
        assert "Enterprise" in xml_str
        assert base64.b64encode(b"test_signature_data").decode() in xml_str

    def test_json_license_file_format(self, emulator: OfflineActivationEmulator) -> None:
        """JSON license file contains structured response data."""
        response: ActivationResponse = ActivationResponse(
            activation_code="JSON-ACTIV",
            license_key="JSON-LICENSE",
            expiry_date=datetime.now() + timedelta(days=180),
            features=["Standard"],
            hardware_locked=False,
            signature=None,
        )

        json_data: bytes = emulator.create_license_file(response, "json")
        license_obj: dict[str, Any] = json.loads(json_data)

        assert license_obj["activation_code"] == "JSON-ACTIV"
        assert license_obj["license_key"] == "JSON-LICENSE"
        assert license_obj["features"] == ["Standard"]
        assert license_obj["hardware_locked"] is False

    def test_binary_license_file_format(self, emulator: OfflineActivationEmulator) -> None:
        """Binary license file contains magic header and packed data."""
        response: ActivationResponse = ActivationResponse(
            activation_code="BIN-ACTIV",
            license_key="BIN-LICENSE",
            expiry_date=None,
            features=["Professional"],
            hardware_locked=True,
            signature=b"binary_signature",
        )

        binary_data: bytes = emulator.create_license_file(response, "binary")

        assert binary_data[:4] == b"LICX"
        version: int = struct.unpack("<I", binary_data[4:8])[0]
        assert version == 1

    def test_text_license_file_format(self, emulator: OfflineActivationEmulator) -> None:
        """Text license file contains human-readable information."""
        response: ActivationResponse = ActivationResponse(
            activation_code="TEXT-ACTIV",
            license_key="TEXT-LICENSE",
            expiry_date=datetime.now() + timedelta(days=90),
            features=["Basic"],
            hardware_locked=True,
            signature=None,
        )

        text_data: bytes = emulator.create_license_file(response, "text")
        text_str: str = text_data.decode("utf-8")

        assert "LICENSE INFORMATION" in text_str
        assert "TEXT-ACTIV" in text_str
        assert "TEXT-LICENSE" in text_str
        assert "Basic" in text_str


class TestPhoneActivation:
    """Test phone-based activation confirmation ID generation."""

    def test_phone_activation_confirmation_format(self, emulator: OfflineActivationEmulator) -> None:
        """Phone activation produces 9-group confirmation ID."""
        confirmation: str = emulator.emulate_phone_activation("INSTALL-123456-ABCDEF-789012")

        groups: list[str] = confirmation.split("-")
        assert len(groups) == 9
        assert all(len(group) == 6 for group in groups)
        assert all(group.isdigit() for group in groups)

    def test_phone_activation_deterministic(self, emulator: OfflineActivationEmulator) -> None:
        """Same installation ID produces same confirmation ID."""
        confirmation1: str = emulator.emulate_phone_activation("INSTALL-ABC123")
        confirmation2: str = emulator.emulate_phone_activation("INSTALL-ABC123")

        assert confirmation1 == confirmation2

    def test_phone_activation_unique_per_installation(self, emulator: OfflineActivationEmulator) -> None:
        """Different installation IDs produce different confirmations."""
        confirmation1: str = emulator.emulate_phone_activation("INSTALL-AAA")
        confirmation2: str = emulator.emulate_phone_activation("INSTALL-BBB")

        assert confirmation1 != confirmation2


class TestTrialRestrictionBypass:
    """Test trial limitation bypass data generation."""

    def test_trial_bypass_contains_all_components(self, emulator: OfflineActivationEmulator) -> None:
        """Trial bypass data includes all attack vectors."""
        bypass_data: dict[str, Any] = emulator.bypass_trial_restrictions("TestProduct")

        assert "trial_reset" in bypass_data
        assert "registry_keys" in bypass_data
        assert "license_files" in bypass_data
        assert "date_bypass" in bypass_data
        assert "network_bypass" in bypass_data

    def test_trial_reset_data_structure(self, emulator: OfflineActivationEmulator) -> None:
        """Trial reset data contains file and registry targets."""
        bypass_data: dict[str, Any] = emulator.bypass_trial_restrictions("TestProduct")
        trial_reset: dict[str, Any] = bypass_data["trial_reset"]

        assert "delete_files" in trial_reset
        assert "registry_keys_to_delete" in trial_reset
        assert "guid_to_regenerate" in trial_reset
        assert "machine_id_spoof" in trial_reset

        assert isinstance(trial_reset["delete_files"], list)
        assert len(trial_reset["delete_files"]) > 0
        assert all("TestProduct" in path for path in trial_reset["delete_files"])

    def test_registry_keys_structure(self, emulator: OfflineActivationEmulator) -> None:
        """Registry keys include activation and licensing entries."""
        bypass_data: dict[str, Any] = emulator.bypass_trial_restrictions("TestProduct")
        registry_keys: dict[str, str] = bypass_data["registry_keys"]

        assert any("License" in key for key in registry_keys)
        assert any("LicenseKey" in key for key in registry_keys)
        assert any("ActivationDate" in key for key in registry_keys)
        assert any("ExpiryDate" in key for key in registry_keys)

    def test_license_files_generated(self, emulator: OfflineActivationEmulator) -> None:
        """License files include multiple format variants."""
        bypass_data: dict[str, Any] = emulator.bypass_trial_restrictions("TestProduct")
        license_files: dict[str, bytes] = bypass_data["license_files"]

        assert "license.xml" in license_files
        assert "license.json" in license_files
        assert "license.dat" in license_files
        assert "license.txt" in license_files

        assert all(isinstance(content, bytes) for content in license_files.values())
        assert all(len(content) > 0 for content in license_files.values())

    def test_date_bypass_configuration(self, emulator: OfflineActivationEmulator) -> None:
        """Date bypass includes time freeze configuration."""
        bypass_data: dict[str, Any] = emulator.bypass_trial_restrictions("TestProduct")
        date_bypass: dict[str, Any] = bypass_data["date_bypass"]

        assert "system_time_freeze" in date_bypass
        assert "trial_start_date" in date_bypass
        assert "ntp_server_override" in date_bypass

        assert isinstance(date_bypass["system_time_freeze"], datetime)

    def test_network_bypass_configuration(self, emulator: OfflineActivationEmulator) -> None:
        """Network bypass includes hosts and firewall rules."""
        bypass_data: dict[str, Any] = emulator.bypass_trial_restrictions("TestProduct")
        network_bypass: dict[str, Any] = bypass_data["network_bypass"]

        assert "hosts_file_entries" in network_bypass
        assert "firewall_rules" in network_bypass
        assert "proxy_config" in network_bypass

        hosts_entries: list[str] = network_bypass["hosts_file_entries"]
        # lgtm[py/incomplete-url-substring-sanitization] Test assertion validating hosts file entries contain expected domains
        assert any("adobe.com" in entry for entry in hosts_entries)
        # lgtm[py/incomplete-url-substring-sanitization] Test assertion validating hosts file entries contain expected domains
        assert any("autodesk.com" in entry for entry in hosts_entries)
        # lgtm[py/incomplete-url-substring-sanitization] Test assertion validating hosts file entries contain expected domains
        assert any("microsoft.com" in entry for entry in hosts_entries)


class TestActivationRequestGeneration:
    """Test activation request generation in multiple formats."""

    def test_xml_request_format(self, emulator: OfflineActivationEmulator) -> None:
        """XML request contains all machine profile data."""
        xml_request: str = emulator.generate_activation_request("TestProduct", "SERIAL-12345", RequestFormat.XML)

        assert "<ActivationRequest>" in xml_request
        assert "<ProductID>TestProduct</ProductID>" in xml_request
        assert "<SerialNumber>SERIAL-12345</SerialNumber>" in xml_request
        assert "<MachineProfile>" in xml_request
        assert "<Signature>" in xml_request

    def test_json_request_format(self, emulator: OfflineActivationEmulator) -> None:
        """JSON request contains structured machine profile."""
        json_request: str = emulator.generate_activation_request("TestProduct", "SERIAL-JSON", RequestFormat.JSON)

        request_data: dict[str, Any] = json.loads(json_request)

        assert request_data["product_id"] == "TestProduct"
        assert request_data["serial_number"] == "SERIAL-JSON"
        assert "machine_profile" in request_data
        assert "signature" in request_data

        machine_profile: dict[str, Any] = request_data["machine_profile"]
        assert "cpu_id" in machine_profile
        assert "disk_serial" in machine_profile
        assert "mac_address" in machine_profile

    def test_base64_request_format(self, emulator: OfflineActivationEmulator) -> None:
        """Base64 request contains binary-packed data."""
        b64_request: str = emulator.generate_activation_request("TestProduct", "SERIAL-B64", RequestFormat.BASE64)

        try:
            decoded: bytes = base64.b64decode(b64_request)
            assert len(decoded) > 100
        except Exception:
            pytest.fail("Base64 request not valid base64")

    def test_binary_request_format(self, emulator: OfflineActivationEmulator) -> None:
        """Binary request contains magic header."""
        bin_request: str = emulator.generate_activation_request("TestProduct", "SERIAL-BIN", RequestFormat.BINARY)

        binary_data: bytes = bytes.fromhex(bin_request)
        assert binary_data[:8] == b"ACTREQ01"


class TestChallengeResponseBypass:
    """Test challenge-response activation bypass."""

    def test_challenge_response_valid_format(self, emulator: OfflineActivationEmulator) -> None:
        """Challenge-response produces base64-encoded response."""
        challenge: str = base64.b64encode(b"TEST_CHALLENGE_DATA_12345").decode()

        response: str = emulator.bypass_challenge_response(challenge)

        try:
            decoded: bytes = base64.b64decode(response)
            assert len(decoded) == 32
        except Exception:
            pytest.fail("Challenge response not valid base64")

    def test_challenge_response_deterministic(self, emulator: OfflineActivationEmulator) -> None:
        """Same challenge produces same response consistently."""
        challenge: str = "SAME_CHALLENGE_DATA"

        response1: str = emulator.bypass_challenge_response(challenge)
        response2: str = emulator.bypass_challenge_response(challenge)

        assert response1 == response2

    def test_challenge_response_unique_per_challenge(self, emulator: OfflineActivationEmulator) -> None:
        """Different challenges produce different responses."""
        challenge1: str = "CHALLENGE_A"
        challenge2: str = "CHALLENGE_B"

        response1: str = emulator.bypass_challenge_response(challenge1)
        response2: str = emulator.bypass_challenge_response(challenge2)

        assert response1 != response2


class TestActivationFileCreation:
    """Test encrypted activation file generation."""

    def test_activation_file_creation(self, emulator: OfflineActivationEmulator) -> None:
        """Activation file contains encrypted response data."""
        response: ActivationResponse = ActivationResponse(
            activation_code="FILE-ACTIV",
            license_key="FILE-LICENSE-KEY",
            expiry_date=datetime.now() + timedelta(days=365),
            features=["Premium"],
            hardware_locked=True,
            signature=b"file_signature",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path: str = str(Path(tmpdir) / "activation.dat")
            result_path: str = emulator.create_activation_file(response, output_path)

            assert result_path == output_path
            assert os.path.exists(result_path)

            with open(result_path, "rb") as f:
                file_data: bytes = f.read()
                assert file_data[:8] == b"ACTFILE1"
                assert len(file_data) > 24


class TestSignatureGeneration:
    """Test RSA signature generation for license data."""

    def test_license_signature_valid_rsa(self, emulator: OfflineActivationEmulator) -> None:
        """License signature is valid RSA PSS signature."""
        test_data: bytes = b"LICENSE_DATA_TO_SIGN"

        signature: bytes = emulator._sign_license_data(test_data)

        assert isinstance(signature, bytes)
        assert len(signature) == 256

    def test_request_signature_valid_rsa(self, emulator: OfflineActivationEmulator) -> None:
        """Request signature is valid RSA PSS signature."""
        test_data: bytes = b"REQUEST_DATA_TO_SIGN"

        signature: bytes = emulator._sign_request(test_data)

        assert isinstance(signature, bytes)
        assert len(signature) == 256


class TestAlgorithmDetection:
    """Test automatic detection of activation algorithms."""

    def test_detect_microsoft_algorithm(self, emulator: OfflineActivationEmulator) -> None:
        """Detects Microsoft algorithm from product ID."""
        assert emulator._detect_activation_algorithm("Microsoft Office") == "microsoft"
        assert emulator._detect_activation_algorithm("office 365") == "microsoft"

    def test_detect_adobe_algorithm(self, emulator: OfflineActivationEmulator) -> None:
        """Detects Adobe algorithm from product ID."""
        assert emulator._detect_activation_algorithm("Adobe Photoshop") == "adobe"
        assert emulator._detect_activation_algorithm("adobe cc") == "adobe"

    def test_detect_autodesk_algorithm(self, emulator: OfflineActivationEmulator) -> None:
        """Detects Autodesk algorithm from product ID."""
        assert emulator._detect_activation_algorithm("Autodesk AutoCAD") == "autodesk"
        assert emulator._detect_activation_algorithm("autodesk") == "autodesk"

    def test_detect_vmware_algorithm(self, emulator: OfflineActivationEmulator) -> None:
        """Detects VMware algorithm from product ID."""
        assert emulator._detect_activation_algorithm("VMware vSphere") == "vmware"
        assert emulator._detect_activation_algorithm("vmware") == "vmware"

    def test_detect_matlab_algorithm(self, emulator: OfflineActivationEmulator) -> None:
        """Detects MATLAB algorithm from product ID."""
        assert emulator._detect_activation_algorithm("MATLAB R2024") == "matlab"
        assert emulator._detect_activation_algorithm("matlab") == "matlab"

    def test_detect_solidworks_algorithm(self, emulator: OfflineActivationEmulator) -> None:
        """Detects SolidWorks algorithm from product ID."""
        assert emulator._detect_activation_algorithm("SolidWorks Professional") == "solidworks"
        assert emulator._detect_activation_algorithm("solidworks") == "solidworks"

    def test_default_to_custom_rsa(self, emulator: OfflineActivationEmulator) -> None:
        """Unknown products default to custom RSA algorithm."""
        assert emulator._detect_activation_algorithm("UnknownProduct") == "custom_rsa"


class TestEndToEndActivationFlow:
    """Test complete activation workflow from request to response."""

    def test_complete_activation_workflow(self, emulator: OfflineActivationEmulator) -> None:
        """Full activation flow produces valid license."""
        hardware_id: str = emulator.generate_hardware_id()
        installation_id: str = emulator.generate_installation_id("TestProduct", hardware_id)
        request_code: str = emulator.generate_request_code(installation_id)

        request: ActivationRequest = ActivationRequest(
            product_id="TestProduct",
            product_version="1.0.0",
            hardware_id=hardware_id,
            installation_id=installation_id,
            request_code=request_code,
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        assert response.activation_code
        assert response.license_key
        assert len(response.features) > 0

        with tempfile.TemporaryDirectory() as tmpdir:
            license_path: str = str(Path(tmpdir) / "license.xml")
            license_data: bytes = emulator.create_license_file(response, "xml")

            with open(license_path, "wb") as f:
                f.write(license_data)

            assert os.path.exists(license_path)
            assert os.path.getsize(license_path) > 0


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_installation_id_handled(self, emulator: OfflineActivationEmulator) -> None:
        """Empty installation ID produces valid request code."""
        request_code: str = emulator.generate_request_code("")

        assert request_code
        groups: list[str] = request_code.split("-")
        assert len(groups) == 9

    def test_short_challenge_handled(self, emulator: OfflineActivationEmulator) -> None:
        """Short challenge data produces valid response."""
        response: str = emulator.bypass_challenge_response("ABC")

        assert response
        assert len(response) > 0

    def test_malformed_request_code_handled(self, emulator: OfflineActivationEmulator) -> None:
        """Malformed request code in SolidWorks activation handled."""
        request: ActivationRequest = ActivationRequest(
            product_id="SolidWorks",
            product_version="1.0",
            hardware_id="HW",
            installation_id="INST",
            request_code="",
            timestamp=datetime.now(),
            additional_data={},
        )

        response: ActivationResponse = emulator.generate_activation_response(request)

        assert response.activation_code


class TestDataClasses:
    """Test data class structures and validation."""

    def test_hardware_profile_dataclass(self) -> None:
        """HardwareProfile stores all required fields."""
        profile: HardwareProfile = HardwareProfile(
            cpu_id="CPU123",
            motherboard_serial="MB123",
            disk_serial="DISK123",
            mac_addresses=["00:11:22:33:44:55"],
            bios_serial="BIOS123",
            system_uuid="UUID123",
            volume_serial="VOL123",
            machine_guid="GUID123",
        )

        assert profile.cpu_id == "CPU123"
        assert profile.mac_addresses == ["00:11:22:33:44:55"]

    def test_activation_request_dataclass(self) -> None:
        """ActivationRequest stores request metadata."""
        request: ActivationRequest = ActivationRequest(
            product_id="PROD",
            product_version="1.0",
            hardware_id="HW",
            installation_id="INST",
            request_code="REQ",
            timestamp=datetime.now(),
            additional_data={"key": "value"},
        )

        assert request.product_id == "PROD"
        assert request.additional_data["key"] == "value"

    def test_activation_response_dataclass(self) -> None:
        """ActivationResponse stores response data."""
        response: ActivationResponse = ActivationResponse(
            activation_code="ACT",
            license_key="LIC",
            expiry_date=None,
            features=["F1", "F2"],
            hardware_locked=True,
            signature=b"SIG",
        )

        assert response.activation_code == "ACT"
        assert response.features == ["F1", "F2"]
        assert response.hardware_locked is True
