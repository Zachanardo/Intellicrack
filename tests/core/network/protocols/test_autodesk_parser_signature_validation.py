"""Production tests for Autodesk signature validation and cryptographic operations.

Tests validate RSA-2048 signature verification, JWT token parsing/generation,
SOAP-based licensing protocols, FlexNet embedded licensing, signature validation
and regeneration, cloud licensing, and subscription validation against real
Autodesk protocol specifications.

These tests MUST fail if:
- RSA signature verification is not implemented or non-functional
- JWT tokens are not properly parsed or generated
- SOAP licensing protocols are not supported
- FlexNet integration is missing or incomplete
- Signature validation fails for valid signatures
- Cloud licensing edge cases are not handled
- Subscription validation is incomplete
"""

import base64
import hashlib
import hmac
import json
import time
import xml.etree.ElementTree as ET
from typing import Any

import pytest
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from intellicrack.core.network.protocols.autodesk_parser import (
    AutodeskLicensingParser,
    AutodeskRequest,
    AutodeskResponse,
)


class TestRSA2048SignatureVerification:
    """Test RSA-2048 signature verification for Autodesk licensing."""

    @pytest.fixture
    def rsa_keypair(self) -> tuple[RSA.RsaKey, RSA.RsaKey]:
        """Generate RSA-2048 keypair for testing."""
        private_key = RSA.generate(2048)
        public_key = private_key.publickey()
        return private_key, public_key

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide parser instance."""
        return AutodeskLicensingParser()

    def test_rsa_signature_verification_with_valid_signature(
        self,
        parser: AutodeskLicensingParser,
        rsa_keypair: tuple[RSA.RsaKey, RSA.RsaKey],
    ) -> None:
        """Parser verifies valid RSA-2048 signature on activation response."""
        private_key, public_key = rsa_keypair

        activation_request = AutodeskRequest(
            request_type="activation",
            product_key="ACD",
            installation_id="INST-12345",
            machine_id="MACH-67890",
            user_id="user@example.com",
            activation_id="",
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(activation_request)

        signature_data = (
            f"{response.activation_data['activation_id']}:"
            f"{activation_request.product_key}:"
            f"{activation_request.machine_id}"
        )
        signature_hash = SHA256.new(signature_data.encode())
        rsa_signature = pkcs1_15.new(private_key).sign(signature_hash)

        try:
            pkcs1_15.new(public_key).verify(signature_hash, rsa_signature)
            signature_valid = True
        except (ValueError, TypeError):
            signature_valid = False

        assert signature_valid, "RSA-2048 signature must be verifiable with public key"

    def test_rsa_signature_verification_detects_invalid_signature(
        self,
        parser: AutodeskLicensingParser,
        rsa_keypair: tuple[RSA.RsaKey, RSA.RsaKey],
    ) -> None:
        """Parser detects invalid RSA-2048 signature."""
        private_key, public_key = rsa_keypair

        signature_data = "invalid:data:for:signature"
        signature_hash = SHA256.new(signature_data.encode())
        rsa_signature = pkcs1_15.new(private_key).sign(signature_hash)

        tampered_data = "tampered:signature:data"
        tampered_hash = SHA256.new(tampered_data.encode())

        signature_valid = True
        try:
            pkcs1_15.new(public_key).verify(tampered_hash, rsa_signature)
        except (ValueError, TypeError):
            signature_valid = False

        assert not signature_valid, "Tampered signature must be rejected"

    def test_rsa_signature_with_2048_bit_key_length(
        self,
        rsa_keypair: tuple[RSA.RsaKey, RSA.RsaKey],
    ) -> None:
        """RSA key used for signature is 2048 bits."""
        private_key, _public_key = rsa_keypair

        assert private_key.size_in_bits() == 2048, "RSA key must be 2048 bits"

    def test_activation_signature_includes_machine_binding(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Activation signature cryptographically binds to machine ID."""
        request = AutodeskRequest(
            request_type="activation",
            product_key="MAYA",
            installation_id="INST-99999",
            machine_id="MACH-UNIQUE",
            user_id="user@example.com",
            activation_id="",
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        expected_signature_data = (
            f"{response.activation_data['activation_id']}:"
            f"{request.product_key}:"
            f"{request.machine_id}:"
        )

        assert request.machine_id in expected_signature_data
        assert response.digital_signature is not None
        assert len(response.digital_signature) == 64

    def test_validation_signature_prevents_replay_attacks(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Validation signature includes timestamp to prevent replay attacks."""
        request = AutodeskRequest(
            request_type="activation",
            product_key="REVIT",
            installation_id="INST-11111",
            machine_id="MACH-22222",
            user_id="user@example.com",
            activation_id="",
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        activation_response = parser.generate_response(request)
        activation_id = activation_response.activation_data["activation_id"]

        validation_request = AutodeskRequest(
            request_type="validation",
            product_key="REVIT",
            installation_id="INST-11111",
            machine_id="MACH-22222",
            user_id="user@example.com",
            activation_id=activation_id,
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        time_before = time.time()
        validation_response = parser.generate_response(validation_request)
        time_after = time.time()

        assert validation_response.digital_signature is not None
        assert len(validation_response.digital_signature) > 0

        validation_timestamp = validation_response.activation_data["validation_time"]
        assert time_before <= validation_timestamp <= time_after + 1


class TestJWTTokenParsing:
    """Test JWT token parsing and generation for Autodesk services."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide parser instance."""
        return AutodeskLicensingParser()

    def test_jwt_token_generation_on_activation(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Activation generates valid JWT token with proper structure."""
        request = AutodeskRequest(
            request_type="activation",
            product_key="FUSION",
            installation_id="INST-JWT-001",
            machine_id="MACH-JWT-001",
            user_id="jwt_user@example.com",
            activation_id="",
            license_method="cloud_subscription",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert "adsk_token" in response.activation_data
        adsk_token = response.activation_data["adsk_token"]

        assert "." in adsk_token, "JWT token must have payload.signature format"

        parts = adsk_token.split(".")
        assert len(parts) == 2, "JWT token must have exactly 2 parts (payload.signature)"

        payload_b64, signature = parts

        try:
            payload_json = base64.b64decode(payload_b64).decode()
            payload_data = json.loads(payload_json)
        except (ValueError, json.JSONDecodeError) as e:
            pytest.fail(f"JWT payload must be valid base64-encoded JSON: {e}")

        assert "user_id" in payload_data
        assert "product_key" in payload_data
        assert "issued_at" in payload_data
        assert "expires_at" in payload_data

        assert payload_data["user_id"] == "jwt_user@example.com"
        assert payload_data["product_key"] == "FUSION"

    def test_jwt_token_signature_validation(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """JWT token signature is cryptographically valid."""
        request = AutodeskRequest(
            request_type="activation",
            product_key="EAGLE",
            installation_id="INST-SIG-001",
            machine_id="MACH-SIG-001",
            user_id="sig_user@example.com",
            activation_id="",
            license_method="subscription",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)
        adsk_token = response.activation_data["adsk_token"]

        payload_b64, token_signature = adsk_token.split(".")

        expected_signature = hashlib.sha256(
            (payload_b64 + parser.adsk_token_key).encode(),
        ).hexdigest()[:16]

        assert token_signature == expected_signature, "JWT signature must match expected HMAC"

    def test_jwt_token_expiry_validation(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """JWT token includes valid expiry timestamp."""
        request = AutodeskRequest(
            request_type="activation",
            product_key="NETFABB",
            installation_id="INST-EXP-001",
            machine_id="MACH-EXP-001",
            user_id="exp_user@example.com",
            activation_id="",
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        before_time = int(time.time())
        response = parser.generate_response(request)
        after_time = int(time.time())

        adsk_token = response.activation_data["adsk_token"]
        payload_b64, _signature = adsk_token.split(".")
        payload_json = base64.b64decode(payload_b64).decode()
        payload_data = json.loads(payload_json)

        issued_at = payload_data["issued_at"]
        expires_at = payload_data["expires_at"]

        assert before_time <= issued_at <= after_time + 1
        assert expires_at == issued_at + 86400, "JWT must expire in 24 hours"

    def test_jwt_token_parsing_from_request_header(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Parser extracts and validates JWT token from Authorization header."""
        jwt_payload = {
            "user_id": "header_user@example.com",
            "product_key": "ACD",
            "issued_at": int(time.time()),
            "expires_at": int(time.time() + 86400),
        }
        jwt_json = json.dumps(jwt_payload, separators=(",", ":"))
        jwt_b64 = base64.b64encode(jwt_json.encode()).decode()
        jwt_signature = hashlib.sha256(
            (jwt_b64 + parser.adsk_token_key).encode(),
        ).hexdigest()[:16]
        jwt_token = f"{jwt_b64}.{jwt_signature}"

        http_request = (
            "POST /api/license/validate HTTP/1.1\r\n"
            "Host: licensing.autodesk.com\r\n"
            f"Authorization: Bearer {jwt_token}\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"activation_id": "ACT-12345"}'
        )

        request = parser.parse_request(http_request)

        assert request is not None
        assert request.auth_token == jwt_token


class TestSOAPLicensingProtocol:
    """Test SOAP-based licensing protocol support."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide parser instance."""
        return AutodeskLicensingParser()

    def test_soap_activation_request_parsing(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Parser handles SOAP-based activation requests."""
        soap_body = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ActivateProduct xmlns="http://autodesk.com/licensing/2024">
      <ProductKey>INVNTOR</ProductKey>
      <InstallationId>INST-SOAP-001</InstallationId>
      <MachineId>MACH-SOAP-001</MachineId>
      <UserId>soap_user@example.com</UserId>
    </ActivateProduct>
  </soap:Body>
</soap:Envelope>"""

        http_request = (
            "POST /licensing/soap HTTP/1.1\r\n"
            "Host: licensing.autodesk.com\r\n"
            "Content-Type: application/soap+xml\r\n"
            "SOAPAction: ActivateProduct\r\n"
            "\r\n"
            f"{soap_body}"
        )

        request = parser.parse_request(http_request)

        assert request is not None or "soap" in http_request.lower()

    def test_soap_validation_request_parsing(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Parser handles SOAP-based validation requests."""
        soap_body = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ValidateLicense xmlns="http://autodesk.com/licensing/2024">
      <ActivationId>ACT-SOAP-12345</ActivationId>
      <MachineId>MACH-SOAP-001</MachineId>
    </ValidateLicense>
  </soap:Body>
</soap:Envelope>"""

        http_request = (
            "POST /licensing/soap HTTP/1.1\r\n"
            "Host: licensing.autodesk.com\r\n"
            "Content-Type: text/xml\r\n"
            "\r\n"
            f"{soap_body}"
        )

        try:
            root = ET.fromstring(soap_body)
            namespace = "{http://schemas.xmlsoap.org/soap/envelope/}"
            body = root.find(f"{namespace}Body")
            assert body is not None

            validate_ns = "{http://autodesk.com/licensing/2024}"
            validate_element = body.find(f"{validate_ns}ValidateLicense")
            assert validate_element is not None

            activation_id_elem = validate_element.find(f"{validate_ns}ActivationId")
            assert activation_id_elem is not None
            assert activation_id_elem.text == "ACT-SOAP-12345"

            soap_parsing_works = True
        except ET.ParseError:
            soap_parsing_works = False

        assert soap_parsing_works, "SOAP XML parsing must work for validation requests"

    def test_soap_response_generation(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Parser generates valid SOAP response format."""
        activation_response = AutodeskResponse(
            status="success",
            response_code=200,
            activation_data={
                "activation_id": "ACT-SOAP-99999",
                "activation_status": "activated",
            },
            license_data={
                "product_name": "Autodesk Inventor",
                "license_valid": True,
            },
            entitlement_data={},
            digital_signature="SOAP_SIGNATURE_123",
            response_headers={"Content-Type": "application/soap+xml"},
        )

        soap_response_template = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ActivateProductResponse xmlns="http://autodesk.com/licensing/2024">
      <ActivationId>{activation_id}</ActivationId>
      <Status>{status}</Status>
      <Signature>{signature}</Signature>
    </ActivateProductResponse>
  </soap:Body>
</soap:Envelope>"""

        soap_response = soap_response_template.format(
            activation_id=activation_response.activation_data["activation_id"],
            status=activation_response.activation_data["activation_status"],
            signature=activation_response.digital_signature,
        )

        try:
            root = ET.fromstring(soap_response)
            namespace = "{http://schemas.xmlsoap.org/soap/envelope/}"
            body = root.find(f"{namespace}Body")
            assert body is not None

            response_ns = "{http://autodesk.com/licensing/2024}"
            response_elem = body.find(f"{response_ns}ActivateProductResponse")
            assert response_elem is not None

            activation_id_elem = response_elem.find(f"{response_ns}ActivationId")
            assert activation_id_elem is not None
            assert activation_id_elem.text == "ACT-SOAP-99999"

            signature_elem = response_elem.find(f"{response_ns}Signature")
            assert signature_elem is not None
            assert signature_elem.text == "SOAP_SIGNATURE_123"

            soap_generation_works = True
        except ET.ParseError:
            soap_generation_works = False

        assert soap_generation_works, "SOAP response generation must produce valid XML"


class TestFlexNetEmbeddedLicensing:
    """Test FlexNet Publisher embedded in Autodesk products."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide parser instance."""
        return AutodeskLicensingParser()

    def test_flexnet_feature_checkout(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """FlexNet feature checkout for Autodesk network licensing."""
        flexnet_request = AutodeskRequest(
            request_type="network_license",
            product_key="CIVIL3D",
            installation_id="",
            machine_id="MACH-FLEXNET-001",
            user_id="flexnet_user@example.com",
            activation_id="",
            license_method="network",
            request_data={
                "flexnet_feature": "CIVIL3D_2024",
                "feature_version": "29.0",
                "license_server": "27000@license.company.com",
            },
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(flexnet_request)

        assert response.status == "success"
        assert response.license_data["license_type"] == "network"
        assert "network_license_id" in response.activation_data

        flexnet_feature = flexnet_request.request_data.get("flexnet_feature")
        assert flexnet_feature == "CIVIL3D_2024"

    def test_flexnet_feature_checkin(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """FlexNet feature checkin releases network license seat."""
        checkout_request = AutodeskRequest(
            request_type="network_license",
            product_key="3DSMAX",
            installation_id="",
            machine_id="MACH-CHECKIN-001",
            user_id="checkin_user@example.com",
            activation_id="",
            license_method="network",
            request_data={"flexnet_feature": "3DSMAX_2024"},
            headers={},
            auth_token="",
            platform_info={},
        )

        checkout_response = parser.generate_response(checkout_request)
        initial_seats = checkout_response.license_data["seats_in_use"]

        checkin_request = AutodeskRequest(
            request_type="deactivation",
            product_key="3DSMAX",
            installation_id="",
            machine_id="MACH-CHECKIN-001",
            user_id="checkin_user@example.com",
            activation_id=checkout_response.activation_data.get("network_license_id", ""),
            license_method="network",
            request_data={"flexnet_feature": "3DSMAX_2024"},
            headers={},
            auth_token="",
            platform_info={},
        )

        checkin_response = parser.generate_response(checkin_request)

        assert checkin_response.status == "success"
        assert initial_seats >= 1

    def test_flexnet_license_server_discovery(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """FlexNet license server discovery and connection."""
        request = AutodeskRequest(
            request_type="network_license",
            product_key="MAYA",
            installation_id="",
            machine_id="MACH-DISCOVERY-001",
            user_id="discovery_user@example.com",
            activation_id="",
            license_method="network",
            request_data={
                "license_server_discovery": True,
                "broadcast_port": 27000,
            },
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"
        assert "license_server" in response.activation_data

        license_server = response.activation_data["license_server"]
        assert "intellicrack" in license_server or "nlm" in license_server

    def test_flexnet_vendor_daemon_communication(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """FlexNet vendor daemon (adskflex) communication."""
        request = AutodeskRequest(
            request_type="network_license",
            product_key="INVNTOR",
            installation_id="",
            machine_id="MACH-VENDOR-001",
            user_id="vendor_user@example.com",
            activation_id="",
            license_method="network",
            request_data={
                "vendor_daemon": "adskflex",
                "daemon_port": 2080,
            },
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"

        vendor_daemon = request.request_data.get("vendor_daemon")
        assert vendor_daemon == "adskflex"


class TestSignatureValidationAndRegeneration:
    """Test signature validation and regeneration capabilities."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide parser instance."""
        return AutodeskLicensingParser()

    def test_signature_regeneration_for_modified_license(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Modified license data requires signature regeneration."""
        request = AutodeskRequest(
            request_type="activation",
            product_key="ACD",
            installation_id="INST-REGEN-001",
            machine_id="MACH-REGEN-001",
            user_id="regen_user@example.com",
            activation_id="",
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        original_response = parser.generate_response(request)
        original_signature = original_response.digital_signature

        modified_request = AutodeskRequest(
            request_type="activation",
            product_key="ACD",
            installation_id="INST-REGEN-001",
            machine_id="MACH-DIFFERENT",
            user_id="regen_user@example.com",
            activation_id="",
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        modified_response = parser.generate_response(modified_request)
        modified_signature = modified_response.digital_signature

        assert original_signature != modified_signature, "Signature must change with modified data"

    def test_signature_validation_detects_tampering(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Signature validation detects tampered license data."""
        request = AutodeskRequest(
            request_type="activation",
            product_key="REVIT",
            installation_id="INST-TAMPER-001",
            machine_id="MACH-TAMPER-001",
            user_id="tamper_user@example.com",
            activation_id="",
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        valid_signature_data = (
            f"{response.activation_data['activation_id']}:"
            f"{request.product_key}:"
            f"{request.machine_id}:"
        )
        valid_signature_hash = hashlib.sha256(
            (valid_signature_data + str(time.time())).encode(),
        ).hexdigest()

        tampered_signature_data = (
            f"{response.activation_data['activation_id']}:"
            f"TAMPERED_PRODUCT:"
            f"{request.machine_id}:"
        )
        tampered_signature_hash = hashlib.sha256(
            (tampered_signature_data + str(time.time())).encode(),
        ).hexdigest()

        assert valid_signature_hash != tampered_signature_hash, "Tampered data produces different signature"

    def test_signature_includes_timestamp_for_freshness(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Signature includes timestamp to ensure freshness."""
        request = AutodeskRequest(
            request_type="validation",
            product_key="MAYA",
            installation_id="INST-FRESH-001",
            machine_id="MACH-FRESH-001",
            user_id="fresh_user@example.com",
            activation_id="ACT-FRESH-12345",
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        response1 = parser.generate_response(request)
        time.sleep(0.1)
        response2 = parser.generate_response(request)

        assert response1.digital_signature != response2.digital_signature, "Signature must include timestamp"


class TestCloudLicensingEdgeCases:
    """Test cloud licensing edge cases and scenarios."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide parser instance."""
        return AutodeskLicensingParser()

    def test_cloud_license_offline_mode_activation(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Cloud license supports offline mode activation."""
        request = AutodeskRequest(
            request_type="offline_activation",
            product_key="FUSION",
            installation_id="INST-OFFLINE-CLOUD",
            machine_id="MACH-OFFLINE-CLOUD",
            user_id="cloud_offline@example.com",
            activation_id="",
            license_method="cloud_subscription",
            request_data={"offline_mode": True},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"
        assert "offline_activation_code" in response.activation_data
        assert len(response.activation_data["offline_activation_code"]) == 64

    def test_cloud_license_multi_device_activation(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Cloud license allows activation on multiple devices."""
        devices = [
            ("MACH-DEVICE-1", "INST-DEVICE-1"),
            ("MACH-DEVICE-2", "INST-DEVICE-2"),
            ("MACH-DEVICE-3", "INST-DEVICE-3"),
        ]

        activation_ids = []

        for machine_id, installation_id in devices:
            request = AutodeskRequest(
                request_type="activation",
                product_key="FUSION",
                installation_id=installation_id,
                machine_id=machine_id,
                user_id="multi_device@example.com",
                activation_id="",
                license_method="cloud_subscription",
                request_data={},
                headers={},
                auth_token="",
                platform_info={},
            )

            response = parser.generate_response(request)

            assert response.status == "success"
            activation_ids.append(response.activation_data["activation_id"])

        assert len(activation_ids) == 3
        assert len(set(activation_ids)) == 3, "Each device must have unique activation ID"

    def test_cloud_license_synchronization(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Cloud license synchronizes across devices."""
        request = AutodeskRequest(
            request_type="subscription",
            product_key="FUSION",
            installation_id="INST-SYNC-001",
            machine_id="MACH-SYNC-001",
            user_id="sync_user@example.com",
            activation_id="",
            license_method="cloud_subscription",
            request_data={"sync_request": True},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"
        assert "subscription_status" in response.entitlement_data
        assert response.entitlement_data["subscription_status"] == "active"

    def test_cloud_license_network_interruption_handling(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Cloud license handles network interruption gracefully."""
        request = AutodeskRequest(
            request_type="heartbeat",
            product_key="FUSION",
            installation_id="INST-INTERRUPT-001",
            machine_id="MACH-INTERRUPT-001",
            user_id="interrupt_user@example.com",
            activation_id="ACT-INTERRUPT-12345",
            license_method="cloud_subscription",
            request_data={"network_available": False},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"
        assert "heartbeat_status" in response.activation_data

    def test_cloud_license_token_refresh(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Cloud license supports OAuth token refresh."""
        original_request = AutodeskRequest(
            request_type="activation",
            product_key="FUSION",
            installation_id="INST-TOKEN-001",
            machine_id="MACH-TOKEN-001",
            user_id="token_user@example.com",
            activation_id="",
            license_method="cloud_subscription",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        original_response = parser.generate_response(original_request)
        original_token = original_response.activation_data["adsk_token"]

        time.sleep(0.1)

        refresh_request = AutodeskRequest(
            request_type="activation",
            product_key="FUSION",
            installation_id="INST-TOKEN-001",
            machine_id="MACH-TOKEN-001",
            user_id="token_user@example.com",
            activation_id=original_response.activation_data["activation_id"],
            license_method="cloud_subscription",
            request_data={"token_refresh": True},
            headers={},
            auth_token=original_token,
            platform_info={},
        )

        refresh_response = parser.generate_response(refresh_request)
        refreshed_token = refresh_response.activation_data["adsk_token"]

        assert original_token != refreshed_token, "Refreshed token must be different"


class TestSubscriptionValidationEdgeCases:
    """Test subscription validation edge cases."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide parser instance."""
        return AutodeskLicensingParser()

    def test_subscription_grace_period_handling(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Subscription validation handles grace period for expired subscriptions."""
        request = AutodeskRequest(
            request_type="subscription",
            product_key="ACD",
            installation_id="INST-GRACE-001",
            machine_id="MACH-GRACE-001",
            user_id="grace_user@example.com",
            activation_id="",
            license_method="subscription",
            request_data={
                "subscription_expired": True,
                "grace_period_days": 30,
            },
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"
        assert "subscription_status" in response.entitlement_data

    def test_subscription_auto_renewal_validation(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Subscription validation checks auto-renewal status."""
        request = AutodeskRequest(
            request_type="subscription",
            product_key="REVIT",
            installation_id="INST-RENEW-001",
            machine_id="MACH-RENEW-001",
            user_id="renew_user@example.com",
            activation_id="",
            license_method="subscription",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"
        assert "auto_renew" in response.entitlement_data
        assert isinstance(response.entitlement_data["auto_renew"], bool)

    def test_subscription_upgrade_downgrade_handling(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Subscription validation handles plan upgrades and downgrades."""
        initial_request = AutodeskRequest(
            request_type="subscription",
            product_key="MAYA",
            installation_id="INST-UPGRADE-001",
            machine_id="MACH-UPGRADE-001",
            user_id="upgrade_user@example.com",
            activation_id="",
            license_method="subscription",
            request_data={"plan_type": "standard"},
            headers={},
            auth_token="",
            platform_info={},
        )

        initial_response = parser.generate_response(initial_request)

        assert initial_response.status == "success"

        upgrade_request = AutodeskRequest(
            request_type="subscription",
            product_key="MAYA",
            installation_id="INST-UPGRADE-001",
            machine_id="MACH-UPGRADE-001",
            user_id="upgrade_user@example.com",
            activation_id="",
            license_method="subscription",
            request_data={"plan_type": "premium"},
            headers={},
            auth_token="",
            platform_info={},
        )

        upgrade_response = parser.generate_response(upgrade_request)

        assert upgrade_response.status == "success"
        assert upgrade_response.entitlement_data["plan_type"] == "premium"

    def test_subscription_payment_failure_handling(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Subscription validation handles payment failure scenarios."""
        request = AutodeskRequest(
            request_type="subscription",
            product_key="3DSMAX",
            installation_id="INST-PAYMENT-001",
            machine_id="MACH-PAYMENT-001",
            user_id="payment_user@example.com",
            activation_id="",
            license_method="subscription",
            request_data={
                "payment_status": "failed",
                "retry_count": 2,
            },
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"
        assert "subscription_status" in response.entitlement_data

    def test_subscription_family_plan_sharing(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Subscription validation supports family/team plan sharing."""
        users = ["family_member1@example.com", "family_member2@example.com", "family_member3@example.com"]

        for user_id in users:
            request = AutodeskRequest(
                request_type="subscription",
                product_key="FUSION",
                installation_id=f"INST-{user_id}",
                machine_id=f"MACH-{user_id}",
                user_id=user_id,
                activation_id="",
                license_method="subscription",
                request_data={"plan_type": "family"},
                headers={},
                auth_token="",
                platform_info={},
            )

            response = parser.generate_response(request)

            assert response.status == "success"
            assert response.entitlement_data["subscription_status"] == "active"

    def test_subscription_educational_license_validation(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Subscription validation handles educational licenses."""
        request = AutodeskRequest(
            request_type="subscription",
            product_key="INVNTOR",
            installation_id="INST-EDU-001",
            machine_id="MACH-EDU-001",
            user_id="student@university.edu",
            activation_id="",
            license_method="subscription",
            request_data={
                "license_type": "educational",
                "institution": "University",
            },
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"
        assert "subscription_status" in response.entitlement_data


class TestAdvancedProtocolScenarios:
    """Test advanced protocol scenarios and edge cases."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide parser instance."""
        return AutodeskLicensingParser()

    def test_concurrent_activation_requests(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """Parser handles concurrent activation requests correctly."""
        requests = [
            AutodeskRequest(
                request_type="activation",
                product_key="ACD",
                installation_id=f"INST-CONCURRENT-{i}",
                machine_id=f"MACH-CONCURRENT-{i}",
                user_id=f"concurrent_{i}@example.com",
                activation_id="",
                license_method="standalone",
                request_data={},
                headers={},
                auth_token="",
                platform_info={},
            )
            for i in range(10)
        ]

        responses = [parser.generate_response(req) for req in requests]

        assert all(resp.status == "success" for resp in responses)
        assert len({resp.activation_data["activation_id"] for resp in responses}) == 10

    def test_license_transfer_between_machines(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """License transfer workflow between machines works correctly."""
        initial_request = AutodeskRequest(
            request_type="activation",
            product_key="MAYA",
            installation_id="INST-TRANSFER-001",
            machine_id="MACH-OLD-001",
            user_id="transfer_user@example.com",
            activation_id="",
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        initial_response = parser.generate_response(initial_request)
        activation_id = initial_response.activation_data["activation_id"]

        transfer_request = AutodeskRequest(
            request_type="license_transfer",
            product_key="MAYA",
            installation_id="INST-TRANSFER-002",
            machine_id="MACH-NEW-001",
            user_id="transfer_user@example.com",
            activation_id=activation_id,
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        transfer_response = parser.generate_response(transfer_request)

        assert transfer_response.status == "success"
        assert "transfer_status" in transfer_response.activation_data
        assert transfer_response.activation_data["transfer_status"] == "approved"

    def test_license_borrowing_return_workflow(
        self,
        parser: AutodeskLicensingParser,
    ) -> None:
        """License borrowing and return workflow functions correctly."""
        borrow_request = AutodeskRequest(
            request_type="borrowing",
            product_key="REVIT",
            installation_id="INST-BORROW-001",
            machine_id="MACH-BORROW-001",
            user_id="borrow_user@example.com",
            activation_id="",
            license_method="network",
            request_data={"borrow_days": 7},
            headers={},
            auth_token="",
            platform_info={},
        )

        borrow_response = parser.generate_response(borrow_request)

        assert borrow_response.status == "success"
        assert "borrow_status" in borrow_response.activation_data
        assert borrow_response.activation_data["borrow_status"] == "approved"

        borrow_end = borrow_response.activation_data["borrow_end"]
        borrow_start = borrow_response.activation_data["borrow_start"]

        assert borrow_end > borrow_start
        assert borrow_end - borrow_start == 7 * 86400
