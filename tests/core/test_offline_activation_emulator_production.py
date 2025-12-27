"""Production tests for OfflineActivationEmulator - validates real offline activation bypass.

Tests real hardware ID generation, activation request/response emulation, license file generation,
and trial restriction bypass WITHOUT mocks or stubs.
"""

import datetime
import json
import platform
import re
import struct
import uuid
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from defusedxml import ElementTree

from intellicrack.core.offline_activation_emulator import (
    ActivationRequest,
    ActivationResponse,
    ActivationType,
    HardwareProfile,
    OfflineActivationEmulator,
    RequestFormat,
)


VALID_HARDWARE_ID_LENGTH = 32
VALID_INSTALLATION_ID_LENGTH = 20
MINIMUM_REQUEST_CODE_LENGTH = 10
PRODUCT_KEY_LENGTH = 25
ACTIVATION_CODE_LENGTH = 25
MINIMUM_LICENSE_SIZE = 100
HARDWARE_ID_HEX_PATTERN = re.compile(r"^[A-F0-9]{32,}$")
INSTALLATION_ID_PATTERN = re.compile(r"^[0-9]{5}-[0-9]{5}-[0-9]{5}-[0-9]{5}$")


class TestHardwareProfileRetrieval:
    """Test real hardware profile retrieval from system."""

    def test_get_hardware_profile_retrieves_real_system_data(self) -> None:
        """Retrieves actual hardware profile from Windows system."""
        emulator = OfflineActivationEmulator()

        profile = emulator.get_hardware_profile()

        assert isinstance(profile, HardwareProfile)
        assert profile.cpu_id
        assert len(profile.cpu_id) > 0
        assert profile.motherboard_serial
        assert len(profile.motherboard_serial) > 0
        assert profile.disk_serial
        assert len(profile.disk_serial) > 0
        assert profile.mac_addresses
        assert len(profile.mac_addresses) > 0
        assert profile.bios_serial
        assert len(profile.bios_serial) > 0
        assert profile.system_uuid
        assert len(profile.system_uuid) > 0

    def test_cpu_id_retrieval_returns_valid_identifier(self) -> None:
        """Retrieves valid CPU ID from system."""
        emulator = OfflineActivationEmulator()

        cpu_id = emulator._get_cpu_id()

        assert cpu_id
        assert len(cpu_id) >= 8
        assert isinstance(cpu_id, str)

    def test_motherboard_serial_retrieval_returns_valid_serial(self) -> None:
        """Retrieves valid motherboard serial from system."""
        emulator = OfflineActivationEmulator()

        motherboard_serial = emulator._get_motherboard_serial()

        assert motherboard_serial
        assert len(motherboard_serial) >= 8
        assert isinstance(motherboard_serial, str)

    def test_mac_addresses_retrieval_returns_valid_addresses(self) -> None:
        """Retrieves valid MAC addresses from network interfaces."""
        emulator = OfflineActivationEmulator()

        mac_addresses = emulator._get_mac_addresses()

        assert mac_addresses
        assert len(mac_addresses) > 0
        for mac in mac_addresses:
            assert ":" in mac or "-" in mac
            assert len(mac) >= 12

    def test_system_uuid_retrieval_returns_valid_uuid(self) -> None:
        """Retrieves valid system UUID."""
        emulator = OfflineActivationEmulator()

        system_uuid = emulator._get_system_uuid()

        assert system_uuid
        assert len(system_uuid) >= 32


class TestHardwareIDGeneration:
    """Test hardware ID generation for activation."""

    def test_generate_hardware_id_produces_consistent_output(self) -> None:
        """Generates consistent hardware ID from same profile."""
        emulator = OfflineActivationEmulator()
        profile = emulator.get_hardware_profile()

        hwid1 = emulator.generate_hardware_id(profile)
        hwid2 = emulator.generate_hardware_id(profile)

        assert hwid1 == hwid2
        assert len(hwid1) >= VALID_HARDWARE_ID_LENGTH
        assert HARDWARE_ID_HEX_PATTERN.match(hwid1)

    def test_generate_hardware_id_microsoft_algorithm(self) -> None:
        """Generates hardware ID using Microsoft algorithm."""
        emulator = OfflineActivationEmulator()
        profile = emulator.get_hardware_profile()

        hwid = emulator.generate_hardware_id(profile, algorithm="microsoft")

        assert hwid
        assert len(hwid) >= VALID_HARDWARE_ID_LENGTH
        assert all(c in "0123456789ABCDEF" for c in hwid)

    def test_generate_hardware_id_adobe_algorithm(self) -> None:
        """Generates hardware ID using Adobe algorithm."""
        emulator = OfflineActivationEmulator()
        profile = emulator.get_hardware_profile()

        hwid = emulator.generate_hardware_id(profile, algorithm="adobe")

        assert hwid
        assert len(hwid) > 0

    def test_generate_hardware_id_autodesk_algorithm(self) -> None:
        """Generates hardware ID using Autodesk algorithm."""
        emulator = OfflineActivationEmulator()
        profile = emulator.get_hardware_profile()

        hwid = emulator.generate_hardware_id(profile, algorithm="autodesk")

        assert hwid
        assert len(hwid) > 0

    def test_different_profiles_generate_different_hardware_ids(self) -> None:
        """Different hardware profiles generate different hardware IDs."""
        emulator = OfflineActivationEmulator()

        profile1 = HardwareProfile(
            cpu_id="CPU001",
            motherboard_serial="MB001",
            disk_serial="DISK001",
            mac_addresses=["00:11:22:33:44:55"],
            bios_serial="BIOS001",
            system_uuid="UUID001",
            volume_serial="VOL001",
            machine_guid="GUID001",
        )

        profile2 = HardwareProfile(
            cpu_id="CPU002",
            motherboard_serial="MB002",
            disk_serial="DISK002",
            mac_addresses=["AA:BB:CC:DD:EE:FF"],
            bios_serial="BIOS002",
            system_uuid="UUID002",
            volume_serial="VOL002",
            machine_guid="GUID002",
        )

        hwid1 = emulator.generate_hardware_id(profile1)
        hwid2 = emulator.generate_hardware_id(profile2)

        assert hwid1 != hwid2


class TestInstallationIDGeneration:
    """Test installation ID generation."""

    def test_generate_installation_id_produces_valid_format(self) -> None:
        """Generates installation ID in valid format."""
        emulator = OfflineActivationEmulator()

        product_id = "TESTPRODUCT123"
        hardware_id = "A" * 32

        installation_id = emulator.generate_installation_id(product_id, hardware_id)

        assert installation_id
        assert len(installation_id) >= VALID_INSTALLATION_ID_LENGTH

    def test_installation_id_is_deterministic(self) -> None:
        """Same inputs produce same installation ID."""
        emulator = OfflineActivationEmulator()

        product_id = "TESTPRODUCT123"
        hardware_id = "A" * 32

        id1 = emulator.generate_installation_id(product_id, hardware_id)
        id2 = emulator.generate_installation_id(product_id, hardware_id)

        assert id1 == id2

    def test_different_product_ids_generate_different_installation_ids(self) -> None:
        """Different product IDs generate different installation IDs."""
        emulator = OfflineActivationEmulator()

        hardware_id = "A" * 32

        id1 = emulator.generate_installation_id("PRODUCT1", hardware_id)
        id2 = emulator.generate_installation_id("PRODUCT2", hardware_id)

        assert id1 != id2


class TestRequestCodeGeneration:
    """Test activation request code generation."""

    def test_generate_request_code_produces_valid_code(self) -> None:
        """Generates valid activation request code."""
        emulator = OfflineActivationEmulator()

        installation_id = "12345-67890-12345-67890"

        request_code = emulator.generate_request_code(installation_id)

        assert request_code
        assert len(request_code) >= MINIMUM_REQUEST_CODE_LENGTH

    def test_request_code_is_reproducible(self) -> None:
        """Same installation ID produces same request code."""
        emulator = OfflineActivationEmulator()

        installation_id = "12345-67890-12345-67890"

        code1 = emulator.generate_request_code(installation_id)
        code2 = emulator.generate_request_code(installation_id)

        assert code1 == code2


class TestActivationResponseGeneration:
    """Test activation response generation for bypassing activation."""

    def test_generate_activation_response_microsoft_scheme(self) -> None:
        """Generates valid Microsoft-style activation response."""
        emulator = OfflineActivationEmulator()

        request = ActivationRequest(
            product_id="Office.16.Standard",
            product_version="16.0.0.0",
            hardware_id="A" * 32,
            installation_id="12345-67890-12345-67890",
            request_code="ABCDEFGH12345678",
            timestamp=datetime.datetime.now(datetime.UTC),
            additional_data={},
        )

        response = emulator.generate_activation_response(request)

        assert response
        assert isinstance(response, ActivationResponse)
        assert response.activation_code
        assert len(response.activation_code) >= ACTIVATION_CODE_LENGTH
        assert response.license_key
        assert len(response.license_key) == PRODUCT_KEY_LENGTH

    def test_generate_activation_response_adobe_scheme(self) -> None:
        """Generates valid Adobe-style activation response."""
        emulator = OfflineActivationEmulator()

        request = ActivationRequest(
            product_id="Adobe.Photoshop.CC",
            product_version="2024.0.0",
            hardware_id="B" * 32,
            installation_id="ADOBE-INSTALL-ID-001",
            request_code="ADOBE-REQUEST-001",
            timestamp=datetime.datetime.now(datetime.UTC),
            additional_data={},
        )

        response = emulator.generate_activation_response(request)

        assert response
        assert response.activation_code
        assert response.license_key

    def test_generate_activation_response_autodesk_scheme(self) -> None:
        """Generates valid Autodesk-style activation response."""
        emulator = OfflineActivationEmulator()

        request = ActivationRequest(
            product_id="Autodesk.AutoCAD.2024",
            product_version="2024.0.0.0",
            hardware_id="C" * 32,
            installation_id="AUTODESK-INSTALL-ID",
            request_code="AUTODESK-REQUEST",
            timestamp=datetime.datetime.now(datetime.UTC),
            additional_data={},
        )

        response = emulator.generate_activation_response(request)

        assert response
        assert response.activation_code
        assert response.license_key

    def test_activation_response_includes_features(self) -> None:
        """Activation response includes enabled features."""
        emulator = OfflineActivationEmulator()

        request = ActivationRequest(
            product_id="TestProduct",
            product_version="1.0.0",
            hardware_id="D" * 32,
            installation_id="TEST-INSTALL-ID",
            request_code="TEST-REQUEST",
            timestamp=datetime.datetime.now(datetime.UTC),
            additional_data={},
        )

        response = emulator.generate_activation_response(request)

        assert response.features
        assert isinstance(response.features, list)
        assert len(response.features) > 0

    def test_activation_response_includes_expiry_date(self) -> None:
        """Activation response includes expiry date."""
        emulator = OfflineActivationEmulator()

        request = ActivationRequest(
            product_id="TestProduct",
            product_version="1.0.0",
            hardware_id="E" * 32,
            installation_id="TEST-INSTALL-ID",
            request_code="TEST-REQUEST",
            timestamp=datetime.datetime.now(datetime.UTC),
            additional_data={},
        )

        response = emulator.generate_activation_response(request)

        assert response.expiry_date
        assert response.expiry_date > datetime.datetime.now(datetime.UTC)

    def test_activation_response_signature_is_generated(self) -> None:
        """Activation response includes cryptographic signature."""
        emulator = OfflineActivationEmulator()

        request = ActivationRequest(
            product_id="TestProduct",
            product_version="1.0.0",
            hardware_id="F" * 32,
            installation_id="TEST-INSTALL-ID",
            request_code="TEST-REQUEST",
            timestamp=datetime.datetime.now(datetime.UTC),
            additional_data={},
        )

        response = emulator.generate_activation_response(request)

        assert response.signature
        assert isinstance(response.signature, bytes)
        assert len(response.signature) > 0


class TestLicenseFileGeneration:
    """Test license file generation for offline activation."""

    def test_create_xml_license_file(self) -> None:
        """Creates valid XML license file."""
        emulator = OfflineActivationEmulator()

        response = ActivationResponse(
            activation_code="ACT-CODE-12345678901234567890",
            license_key="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            expiry_date=datetime.datetime(2025, 12, 31, tzinfo=datetime.UTC),
            features=["feature1", "feature2"],
            hardware_locked=True,
            signature=b"signature_data",
        )

        license_file = emulator.create_license_file(response, format="xml")

        assert license_file
        assert isinstance(license_file, bytes)
        assert len(license_file) >= MINIMUM_LICENSE_SIZE
        assert b"<license>" in license_file or b"<?xml" in license_file

        root = ElementTree.fromstring(license_file)
        assert root is not None

    def test_create_json_license_file(self) -> None:
        """Creates valid JSON license file."""
        emulator = OfflineActivationEmulator()

        response = ActivationResponse(
            activation_code="ACT-CODE-12345678901234567890",
            license_key="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            expiry_date=datetime.datetime(2025, 12, 31, tzinfo=datetime.UTC),
            features=["feature1", "feature2"],
            hardware_locked=False,
            signature=b"signature_data",
        )

        license_file = emulator.create_license_file(response, format="json")

        assert license_file
        assert isinstance(license_file, bytes)
        assert len(license_file) >= MINIMUM_LICENSE_SIZE

        license_data = json.loads(license_file)
        assert "activation_code" in license_data
        assert "license_key" in license_data

    def test_create_binary_license_file(self) -> None:
        """Creates valid binary license file."""
        emulator = OfflineActivationEmulator()

        response = ActivationResponse(
            activation_code="ACT-CODE-12345678901234567890",
            license_key="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            expiry_date=datetime.datetime(2025, 12, 31, tzinfo=datetime.UTC),
            features=["feature1", "feature2"],
            hardware_locked=True,
            signature=b"signature_data",
        )

        license_file = emulator.create_license_file(response, format="binary")

        assert license_file
        assert isinstance(license_file, bytes)
        assert len(license_file) >= MINIMUM_LICENSE_SIZE

    def test_create_text_license_file(self) -> None:
        """Creates valid text license file."""
        emulator = OfflineActivationEmulator()

        response = ActivationResponse(
            activation_code="ACT-CODE-12345678901234567890",
            license_key="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            expiry_date=datetime.datetime(2025, 12, 31, tzinfo=datetime.UTC),
            features=["feature1", "feature2"],
            hardware_locked=False,
            signature=b"signature_data",
        )

        license_file = emulator.create_license_file(response, format="text")

        assert license_file
        assert isinstance(license_file, bytes)
        assert len(license_file) >= MINIMUM_LICENSE_SIZE
        assert b"License Key:" in license_file or b"Activation Code:" in license_file


class TestPhoneActivationEmulation:
    """Test phone activation bypass."""

    def test_emulate_phone_activation_generates_valid_code(self) -> None:
        """Emulates phone activation and generates valid activation code."""
        emulator = OfflineActivationEmulator()

        installation_id = "12345-67890-12345-67890"

        activation_code = emulator.emulate_phone_activation(installation_id)

        assert activation_code
        assert len(activation_code) >= 20
        assert isinstance(activation_code, str)

    def test_phone_activation_produces_deterministic_output(self) -> None:
        """Same installation ID produces same phone activation code."""
        emulator = OfflineActivationEmulator()

        installation_id = "12345-67890-12345-67890"

        code1 = emulator.emulate_phone_activation(installation_id)
        code2 = emulator.emulate_phone_activation(installation_id)

        assert code1 == code2


class TestTrialRestrictionBypass:
    """Test trial restriction bypass capabilities."""

    def test_bypass_trial_restrictions_generates_bypass_data(self) -> None:
        """Generates trial restriction bypass data."""
        emulator = OfflineActivationEmulator()

        product_id = "TestProduct.Trial.2024"

        bypass_data = emulator.bypass_trial_restrictions(product_id)

        assert bypass_data
        assert isinstance(bypass_data, dict)
        assert "registry_keys" in bypass_data
        assert "license_files" in bypass_data
        assert "date_bypass" in bypass_data

    def test_bypass_trial_includes_registry_keys(self) -> None:
        """Trial bypass includes registry key modifications."""
        emulator = OfflineActivationEmulator()

        product_id = "TestProduct.Trial.2024"

        bypass_data = emulator.bypass_trial_restrictions(product_id)

        registry_keys = bypass_data["registry_keys"]
        assert registry_keys
        assert isinstance(registry_keys, dict)
        assert len(registry_keys) > 0

    def test_bypass_trial_includes_license_files(self) -> None:
        """Trial bypass includes license file generation."""
        emulator = OfflineActivationEmulator()

        product_id = "TestProduct.Trial.2024"

        bypass_data = emulator.bypass_trial_restrictions(product_id)

        license_files = bypass_data["license_files"]
        assert license_files
        assert isinstance(license_files, dict)

        for filename, content in license_files.items():
            assert isinstance(filename, str)
            assert isinstance(content, bytes)
            assert len(content) > 0

    def test_bypass_trial_includes_date_bypass(self) -> None:
        """Trial bypass includes date/time manipulation data."""
        emulator = OfflineActivationEmulator()

        product_id = "TestProduct.Trial.2024"

        bypass_data = emulator.bypass_trial_restrictions(product_id)

        date_bypass = bypass_data["date_bypass"]
        assert date_bypass
        assert isinstance(date_bypass, dict)

    def test_bypass_trial_includes_network_bypass(self) -> None:
        """Trial bypass includes network validation bypass."""
        emulator = OfflineActivationEmulator()

        product_id = "TestProduct.Trial.2024"

        bypass_data = emulator.bypass_trial_restrictions(product_id)

        assert "network_bypass" in bypass_data
        network_bypass = bypass_data["network_bypass"]
        assert network_bypass
        assert isinstance(network_bypass, dict)


class TestProductKeyGeneration:
    """Test product key generation."""

    def test_generate_microsoft_product_key(self) -> None:
        """Generates valid Microsoft-format product key."""
        emulator = OfflineActivationEmulator()

        product_key = emulator._generate_product_key("microsoft")

        assert product_key
        assert len(product_key) == PRODUCT_KEY_LENGTH
        assert product_key.count("-") == 4

        parts = product_key.split("-")
        assert len(parts) == 5
        for part in parts:
            assert len(part) == 5
            assert part.isalnum()

    def test_generate_adobe_product_key(self) -> None:
        """Generates valid Adobe-format product key."""
        emulator = OfflineActivationEmulator()

        product_key = emulator._generate_product_key("adobe")

        assert product_key
        assert len(product_key) > 0

    def test_generate_autodesk_product_key(self) -> None:
        """Generates valid Autodesk-format product key."""
        emulator = OfflineActivationEmulator()

        product_key = emulator._generate_product_key("autodesk")

        assert product_key
        assert len(product_key) > 0


class TestCryptographicSignatures:
    """Test cryptographic signature generation for license validation."""

    def test_sign_license_data_generates_valid_signature(self) -> None:
        """Generates valid RSA signature for license data."""
        emulator = OfflineActivationEmulator()

        test_data = b"License data to be signed"

        signature = emulator._sign_license_data(test_data)

        assert signature
        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_signature_is_deterministic(self) -> None:
        """Same data produces same signature with same key."""
        emulator = OfflineActivationEmulator()

        test_data = b"License data to be signed"

        sig1 = emulator._sign_license_data(test_data)
        sig2 = emulator._sign_license_data(test_data)

        assert sig1 == sig2


class TestAlgorithmDetection:
    """Test activation algorithm detection."""

    def test_detect_microsoft_office_algorithm(self) -> None:
        """Detects Microsoft Office activation algorithm."""
        emulator = OfflineActivationEmulator()

        algorithm = emulator._detect_activation_algorithm("Office.16.Standard")

        assert algorithm == "microsoft"

    def test_detect_adobe_algorithm(self) -> None:
        """Detects Adobe activation algorithm."""
        emulator = OfflineActivationEmulator()

        algorithm = emulator._detect_activation_algorithm("Adobe.Photoshop.CC")

        assert algorithm == "adobe"

    def test_detect_autodesk_algorithm(self) -> None:
        """Detects Autodesk activation algorithm."""
        emulator = OfflineActivationEmulator()

        algorithm = emulator._detect_activation_algorithm("Autodesk.AutoCAD.2024")

        assert algorithm == "autodesk"

    def test_detect_unknown_defaults_to_custom_rsa(self) -> None:
        """Unknown product defaults to custom RSA algorithm."""
        emulator = OfflineActivationEmulator()

        algorithm = emulator._detect_activation_algorithm("UnknownProduct.2024")

        assert algorithm in ["custom_rsa", "custom_aes", "custom_ecc"]


class TestEndToEndActivationWorkflow:
    """Test complete activation bypass workflow."""

    def test_complete_offline_activation_workflow(self) -> None:
        """Completes full offline activation bypass workflow."""
        emulator = OfflineActivationEmulator()

        profile = emulator.get_hardware_profile()
        assert profile

        hardware_id = emulator.generate_hardware_id(profile)
        assert hardware_id

        installation_id = emulator.generate_installation_id("TestProduct.2024", hardware_id)
        assert installation_id

        request_code = emulator.generate_request_code(installation_id)
        assert request_code

        request = ActivationRequest(
            product_id="TestProduct.2024",
            product_version="1.0.0.0",
            hardware_id=hardware_id,
            installation_id=installation_id,
            request_code=request_code,
            timestamp=datetime.datetime.now(datetime.UTC),
            additional_data={},
        )

        response = emulator.generate_activation_response(request)
        assert response
        assert response.activation_code
        assert response.license_key

        license_file = emulator.create_license_file(response, format="xml")
        assert license_file
        assert len(license_file) > 0

    def test_complete_trial_bypass_workflow(self) -> None:
        """Completes full trial bypass workflow."""
        emulator = OfflineActivationEmulator()

        product_id = "TestProduct.Trial.2024"

        bypass_data = emulator.bypass_trial_restrictions(product_id)
        assert bypass_data
        assert "registry_keys" in bypass_data
        assert "license_files" in bypass_data
        assert "date_bypass" in bypass_data
        assert "network_bypass" in bypass_data

        assert len(bypass_data["registry_keys"]) > 0
        assert len(bypass_data["license_files"]) > 0
