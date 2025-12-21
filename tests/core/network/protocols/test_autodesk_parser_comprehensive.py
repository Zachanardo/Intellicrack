"""Comprehensive tests for Autodesk licensing protocol parser and response generator.

Tests validate real Autodesk licensing protocol parsing, activation request handling,
license validation processing, entitlement verification, heartbeat message parsing,
subscription status checks, network license management, and offline activation against
actual Autodesk protocol specifications.
"""

import base64
import hashlib
import json
import time
import uuid
from typing import Any

import pytest

from intellicrack.core.network.protocols.autodesk_parser import (
    AutodeskLicensingParser,
    AutodeskRequest,
    AutodeskResponse,
)


@pytest.fixture
def parser() -> AutodeskLicensingParser:
    """Create Autodesk parser with initialized server keys."""
    return AutodeskLicensingParser()


def create_autodesk_activation_request(
    product_key: str = "ACD",
    installation_id: str = "INST-12345-67890-ABCDE",
    machine_id: str = "MACHINE-98765-43210-ZYXWV",
    user_id: str = "user@company.com",
    license_method: str = "standalone",
    platform: str = "Windows 10",
    auth_token: str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
) -> str:
    """Create realistic Autodesk activation HTTP request.

    Args:
        product_key: Autodesk product identifier
        installation_id: Installation unique ID
        machine_id: Machine hardware ID
        user_id: User email/ID
        license_method: License activation method
        platform: Operating system platform
        auth_token: OAuth bearer token

    Returns:
        Raw HTTP activation request
    """
    request_body = {
        "product_key": product_key,
        "installation_id": installation_id,
        "machine_id": machine_id,
        "user_id": user_id,
        "license_method": license_method,
        "platform_version": platform,
        "application_version": "2024.1.0",
        "locale": "en-US",
        "timezone": "UTC-8",
    }

    body_json = json.dumps(request_body)

    return f"POST /api/auth/authenticate HTTP/1.1\r\nHost: licensing.autodesk.com\r\nContent-Type: application/json\r\nContent-Length: {len(body_json)}\r\nAuthorization: Bearer {auth_token}\r\nUser-Agent: AutoCAD/2024.1 Windows/10.0\r\nX-Autodesk-Version: 1.0\r\n\r\n{body_json}"


def create_autodesk_validation_request(
    activation_id: str = "ACT-ABCD1234-EFGH5678-IJKL9012",
    product_key: str = "MAYA",
    machine_id: str = "MACHINE-12345-67890-ABCDE",
) -> str:
    """Create realistic Autodesk license validation HTTP request.

    Args:
        activation_id: Activation identifier from previous activation
        product_key: Product identifier
        machine_id: Machine hardware ID

    Returns:
        Raw HTTP validation request
    """
    request_body = {
        "activation_id": activation_id,
        "product_key": product_key,
        "machine_id": machine_id,
        "timestamp": int(time.time()),
    }

    body_json = json.dumps(request_body)

    return f"POST /api/license/validate HTTP/1.1\r\nHost: licensing.autodesk.com\r\nContent-Type: application/json\r\nContent-Length: {len(body_json)}\r\nUser-Agent: Maya/2024.0 macOS/13.0\r\n\r\n{body_json}"


def create_autodesk_entitlement_request(
    user_id: str = "premium_user@company.com",
    product_key: str = "REVIT",
    auth_token: str = "valid_oauth_token_12345",
) -> str:
    """Create realistic Autodesk entitlement verification request.

    Args:
        user_id: User identifier
        product_key: Product to check entitlement for
        auth_token: OAuth token

    Returns:
        Raw HTTP entitlement request
    """
    request_body = {
        "user_id": user_id,
        "product_key": product_key,
        "check_subscription": True,
    }

    body_json = json.dumps(request_body)

    return f"GET /api/entitlements HTTP/1.1\r\nHost: licensing.autodesk.com\r\nContent-Type: application/json\r\nContent-Length: {len(body_json)}\r\nAuthorization: Bearer {auth_token}\r\nUser-Agent: Revit/2024.0 Windows/11.0\r\n\r\n{body_json}"


def create_autodesk_heartbeat_request(
    product_key: str = "INVNTOR",
    session_id: str = "SESSION-ABCD-1234-EFGH",
    license_method: str = "network",
) -> str:
    """Create realistic Autodesk license heartbeat request.

    Args:
        product_key: Product identifier
        session_id: Active session ID
        license_method: License type (network/standalone)

    Returns:
        Raw HTTP heartbeat request
    """
    request_body = {
        "session_id": session_id,
        "product_key": product_key,
        "license_method": license_method,
        "client_time": int(time.time()),
    }

    body_json = json.dumps(request_body)

    return f"POST /heartbeat HTTP/1.1\r\nHost: licensing.autodesk.com\r\nContent-Type: application/json\r\nContent-Length: {len(body_json)}\r\nUser-Agent: Inventor/2024.0 Windows/10.0\r\n\r\n{body_json}"


def create_autodesk_network_license_request(
    product_key: str = "3DSMAX",
    user_id: str = "render_user@studio.com",
    machine_id: str = "RENDER-NODE-05",
) -> str:
    """Create realistic Autodesk network license checkout request.

    Args:
        product_key: Product identifier
        user_id: User requesting license
        machine_id: Machine identifier

    Returns:
        Raw HTTP network license request
    """
    request_body = {
        "product_key": product_key,
        "user_id": user_id,
        "machine_id": machine_id,
        "request_type": "checkout",
    }

    body_json = json.dumps(request_body)

    return f"POST /network HTTP/1.1\r\nHost: nlm.autodesk.com\r\nContent-Type: application/json\r\nContent-Length: {len(body_json)}\r\nUser-Agent: 3dsMax/2024.0 Windows/10.0\r\n\r\n{body_json}"


def create_autodesk_offline_activation_request(
    product_key: str = "CIVIL3D",
    machine_id: str = "OFFLINE-MACHINE-12345",
    installation_id: str = "OFFLINE-INST-67890",
) -> str:
    """Create realistic Autodesk offline activation request.

    Args:
        product_key: Product identifier
        machine_id: Machine hardware ID
        installation_id: Installation ID

    Returns:
        Raw HTTP offline activation request
    """
    request_body = {
        "product_key": product_key,
        "machine_id": machine_id,
        "installation_id": installation_id,
        "activation_type": "offline",
    }

    body_json = json.dumps(request_body)

    return f"POST /offline HTTP/1.1\r\nHost: licensing.autodesk.com\r\nContent-Type: application/json\r\nContent-Length: {len(body_json)}\r\nUser-Agent: Civil3D/2024.0 Windows/10.0\r\n\r\n{body_json}"


def create_autodesk_subscription_request(
    user_id: str = "subscriber@company.com",
    auth_token: str = "subscription_token_xyz",
) -> str:
    """Create realistic Autodesk subscription status request.

    Args:
        user_id: Subscriber user ID
        auth_token: OAuth token

    Returns:
        Raw HTTP subscription request
    """
    request_body = {
        "user_id": user_id,
        "check_billing": True,
    }

    body_json = json.dumps(request_body)

    return f"GET /subscription HTTP/1.1\r\nHost: licensing.autodesk.com\r\nContent-Type: application/json\r\nContent-Length: {len(body_json)}\r\nAuthorization: Bearer {auth_token}\r\nUser-Agent: Fusion360/2.0 macOS/13.0\r\n\r\n{body_json}"


class TestAutodeskRequestParsing:
    """Test Autodesk request parsing functionality."""

    def test_parse_activation_request_extracts_all_fields(self, parser: AutodeskLicensingParser) -> None:
        """Parser extracts all fields from activation request."""
        http_data = create_autodesk_activation_request(
            product_key="ACD",
            installation_id="INST-TEST-001",
            machine_id="MACHINE-TEST-001",
            user_id="test@autodesk.com",
            license_method="standalone",
        )

        request = parser.parse_request(http_data)

        assert request is not None
        assert request.product_key == "ACD"
        assert request.installation_id == "INST-TEST-001"
        assert request.machine_id == "MACHINE-TEST-001"
        assert request.user_id == "test@autodesk.com"
        assert request.license_method == "standalone"
        assert request.request_type == "activation"

    def test_parse_validation_request_identifies_type(self, parser: AutodeskLicensingParser) -> None:
        """Parser correctly identifies validation requests."""
        http_data = create_autodesk_validation_request(
            activation_id="ACT-TEST-12345",
            product_key="MAYA",
        )

        request = parser.parse_request(http_data)

        assert request is not None
        assert request.request_type == "validation"
        assert request.activation_id == "ACT-TEST-12345"
        assert request.product_key == "MAYA"

    def test_parse_entitlement_request_extracts_user_data(self, parser: AutodeskLicensingParser) -> None:
        """Parser extracts user entitlement data."""
        http_data = create_autodesk_entitlement_request(
            user_id="premium@company.com",
            product_key="REVIT",
            auth_token="valid_token_abc",
        )

        request = parser.parse_request(http_data)

        assert request is not None
        assert request.request_type == "entitlement"
        assert request.user_id == "premium@company.com"
        assert request.product_key == "REVIT"
        assert request.auth_token == "valid_token_abc"

    def test_parse_heartbeat_request_preserves_session(self, parser: AutodeskLicensingParser) -> None:
        """Parser preserves session data in heartbeat requests."""
        http_data = create_autodesk_heartbeat_request(
            product_key="INVNTOR",
            session_id="SESSION-XYZ-789",
            license_method="network",
        )

        request = parser.parse_request(http_data)

        assert request is not None
        assert request.request_type == "heartbeat"
        assert request.product_key == "INVNTOR"
        assert "session_id" in request.request_data
        assert request.request_data["session_id"] == "SESSION-XYZ-789"

    def test_parse_network_license_request_identifies_type(self, parser: AutodeskLicensingParser) -> None:
        """Parser identifies network license requests."""
        http_data = create_autodesk_network_license_request(
            product_key="3DSMAX",
            user_id="render@studio.com",
        )

        request = parser.parse_request(http_data)

        assert request is not None
        assert request.request_type == "network_license"
        assert request.product_key == "3DSMAX"
        assert request.user_id == "render@studio.com"

    def test_parse_offline_activation_request_extracts_data(self, parser: AutodeskLicensingParser) -> None:
        """Parser extracts offline activation data."""
        http_data = create_autodesk_offline_activation_request(
            product_key="CIVIL3D",
            machine_id="OFFLINE-MACHINE-001",
        )

        request = parser.parse_request(http_data)

        assert request is not None
        assert request.request_type == "offline_activation"
        assert request.product_key == "CIVIL3D"
        assert request.machine_id == "OFFLINE-MACHINE-001"

    def test_parse_subscription_request_preserves_auth(self, parser: AutodeskLicensingParser) -> None:
        """Parser preserves authentication data in subscription requests."""
        http_data = create_autodesk_subscription_request(
            user_id="subscriber@test.com",
            auth_token="subscription_token_123",
        )

        request = parser.parse_request(http_data)

        assert request is not None
        assert request.request_type == "subscription"
        assert request.user_id == "subscriber@test.com"
        assert request.auth_token == "subscription_token_123"

    def test_parse_bearer_token_strips_prefix(self, parser: AutodeskLicensingParser) -> None:
        """Parser strips Bearer prefix from authorization tokens."""
        request_body = {"user_id": "test@test.com"}
        body_json = json.dumps(request_body)

        http_data = (
            f"POST /activate HTTP/1.1\r\n"
            f"Authorization: Bearer token_value_here\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_json)}\r\n"
            f"\r\n"
            f"{body_json}"
        )

        request = parser.parse_request(http_data)

        assert request is not None
        assert request.auth_token == "token_value_here"
        assert "Bearer " not in request.auth_token

    def test_parse_platform_info_from_user_agent(self, parser: AutodeskLicensingParser) -> None:
        """Parser extracts platform information from User-Agent header."""
        request_body = {"product_key": "ACD"}
        body_json = json.dumps(request_body)

        http_data = (
            f"POST /activate HTTP/1.1\r\n"
            f"User-Agent: AutoCAD/2024.0 Windows/10.0\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_json)}\r\n"
            f"\r\n"
            f"{body_json}"
        )

        request = parser.parse_request(http_data)

        assert request is not None
        assert "os" in request.platform_info
        assert request.platform_info["os"] == "Windows"

    def test_parse_macos_from_user_agent(self, parser: AutodeskLicensingParser) -> None:
        """Parser identifies macOS from User-Agent."""
        request_body = {"product_key": "MAYA"}
        body_json = json.dumps(request_body)

        http_data = (
            f"POST /activate HTTP/1.1\r\n"
            f"User-Agent: Maya/2024.0 macOS/13.0\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_json)}\r\n"
            f"\r\n"
            f"{body_json}"
        )

        request = parser.parse_request(http_data)

        assert request is not None
        assert request.platform_info["os"] == "macOS"

    def test_parse_invalid_http_returns_none(self, parser: AutodeskLicensingParser) -> None:
        """Parser returns None for invalid HTTP data."""
        invalid_data = "This is not valid HTTP data"

        request = parser.parse_request(invalid_data)

        assert request is None

    def test_parse_empty_request_returns_none(self, parser: AutodeskLicensingParser) -> None:
        """Parser returns None for empty requests."""
        request = parser.parse_request("")

        assert request is None

    def test_parse_form_encoded_data(self, parser: AutodeskLicensingParser) -> None:
        """Parser handles form-encoded request bodies."""
        form_data = "product_key=ACD&installation_id=INST-001&machine_id=MACHINE-001"

        http_data = (
            f"POST /activate HTTP/1.1\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(form_data)}\r\n"
            f"\r\n"
            f"{form_data}"
        )

        request = parser.parse_request(http_data)

        assert request is not None
        assert request.product_key == "ACD"
        assert request.installation_id == "INST-001"
        assert request.machine_id == "MACHINE-001"


class TestAutodeskActivationResponse:
    """Test Autodesk activation response generation."""

    def test_activation_response_includes_activation_id(self, parser: AutodeskLicensingParser) -> None:
        """Activation response contains valid activation ID."""
        http_data = create_autodesk_activation_request(product_key="ACD")
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert response.status == "success"
        assert response.response_code == 200
        assert "activation_id" in response.activation_data
        assert len(response.activation_data["activation_id"]) > 0

    def test_activation_generates_license_data_for_autocad(self, parser: AutodeskLicensingParser) -> None:
        """Activation generates complete license data for AutoCAD."""
        http_data = create_autodesk_activation_request(product_key="ACD")
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert "product_name" in response.license_data
        assert response.license_data["product_name"] == "AutoCAD"
        assert "features" in response.license_data
        assert "2d_drafting" in response.license_data["features"]
        assert "3d_modeling" in response.license_data["features"]

    def test_activation_generates_entitlement_data(self, parser: AutodeskLicensingParser) -> None:
        """Activation generates entitlement data with subscription info."""
        http_data = create_autodesk_activation_request(product_key="MAYA")
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert "entitled_to" in response.entitlement_data
        assert response.entitlement_data["entitled_to"] == "Autodesk Maya"
        assert response.entitlement_data["subscription_status"] == "active"
        assert "entitled_features" in response.entitlement_data

    def test_activation_generates_digital_signature(self, parser: AutodeskLicensingParser) -> None:
        """Activation generates cryptographic signature."""
        http_data = create_autodesk_activation_request(product_key="REVIT")
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert len(response.digital_signature) == 64
        assert all(c in "0123456789abcdef" for c in response.digital_signature.lower())

    def test_activation_stores_activation_record(self, parser: AutodeskLicensingParser) -> None:
        """Activation stores record in parser state."""
        http_data = create_autodesk_activation_request(
            product_key="INVNTOR",
            machine_id="MACHINE-TEST-001",
        )
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)
        activation_id = response.activation_data["activation_id"]

        assert activation_id in parser.active_activations
        assert parser.active_activations[activation_id]["product_key"] == "INVNTOR"
        assert parser.active_activations[activation_id]["machine_id"] == "MACHINE-TEST-001"

    def test_activation_generates_machine_signature(self, parser: AutodeskLicensingParser) -> None:
        """Activation generates unique machine signature."""
        http_data = create_autodesk_activation_request(
            machine_id="MACHINE-001",
            installation_id="INST-001",
        )
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert "machine_signature" in response.activation_data
        machine_sig = response.activation_data["machine_signature"]
        assert len(machine_sig) == 64
        assert machine_sig.isupper()

    def test_activation_generates_adsk_token(self, parser: AutodeskLicensingParser) -> None:
        """Activation generates Autodesk authentication token."""
        http_data = create_autodesk_activation_request(user_id="user@test.com")
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert "adsk_token" in response.activation_data
        token = response.activation_data["adsk_token"]
        assert "." in token
        token_parts = token.split(".")
        assert len(token_parts) == 2

        token_data_b64 = token_parts[0]
        token_data_json = base64.b64decode(token_data_b64).decode()
        token_data = json.loads(token_data_json)
        assert "user_id" in token_data
        assert "issued_at" in token_data

    def test_activation_unknown_product_returns_error(self, parser: AutodeskLicensingParser) -> None:
        """Activation for unknown product returns error response."""
        http_data = create_autodesk_activation_request(product_key="UNKNOWN_PRODUCT")
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert response.status == "error"
        assert response.response_code == 404
        assert "error" in response.license_data
        assert "Unknown product" in response.license_data["error"]

    def test_activation_sets_expiry_date_for_subscription(self, parser: AutodeskLicensingParser) -> None:
        """Activation sets expiry date for subscription products."""
        http_data = create_autodesk_activation_request(product_key="FUSION")
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert "expiry_date" in response.license_data
        expiry = response.license_data["expiry_date"]
        assert expiry != "permanent"
        assert "-" in expiry


class TestAutodeskValidationResponse:
    """Test Autodesk license validation response generation."""

    def test_validation_succeeds_for_active_activation(self, parser: AutodeskLicensingParser) -> None:
        """Validation succeeds for previously activated license."""
        activation_request = create_autodesk_activation_request(
            product_key="ACD",
            machine_id="MACHINE-001",
            installation_id="INST-001",
        )
        act_req = parser.parse_request(activation_request)
        assert act_req is not None
        act_response = parser.generate_response(act_req)
        activation_id = act_response.activation_data["activation_id"]

        validation_request = create_autodesk_validation_request(
            activation_id=activation_id,
            machine_id="MACHINE-001",
        )
        val_req = parser.parse_request(validation_request)
        assert val_req is not None
        val_req.installation_id = "INST-001"
        val_req.product_key = "ACD"

        response = parser.generate_response(val_req)

        assert response.status == "success"
        assert response.response_code == 200
        assert response.activation_data["validation_status"] == "valid"
        assert response.license_data["license_valid"] is True

    def test_validation_fails_for_mismatched_machine(self, parser: AutodeskLicensingParser) -> None:
        """Validation fails when machine signature does not match."""
        activation_request = create_autodesk_activation_request(
            product_key="MAYA",
            machine_id="MACHINE-ORIGINAL",
            installation_id="INST-001",
        )
        act_req = parser.parse_request(activation_request)
        assert act_req is not None
        act_response = parser.generate_response(act_req)
        activation_id = act_response.activation_data["activation_id"]

        validation_request = create_autodesk_validation_request(
            activation_id=activation_id,
            machine_id="MACHINE-DIFFERENT",
        )
        val_req = parser.parse_request(validation_request)
        assert val_req is not None
        val_req.installation_id = "INST-DIFFERENT"
        val_req.product_key = "MAYA"

        response = parser.generate_response(val_req)

        assert response.status == "error"
        assert response.response_code == 403
        assert "Machine signature mismatch" in response.license_data["error"]

    def test_validation_succeeds_for_unknown_activation(self, parser: AutodeskLicensingParser) -> None:
        """Validation succeeds gracefully for unknown activation IDs."""
        validation_request = create_autodesk_validation_request(
            activation_id="UNKNOWN-ACTIVATION-ID",
        )
        val_req = parser.parse_request(validation_request)
        assert val_req is not None

        response = parser.generate_response(val_req)

        assert response.status == "success"
        assert response.response_code == 200
        assert response.license_data["license_valid"] is True

    def test_validation_returns_features_enabled(self, parser: AutodeskLicensingParser) -> None:
        """Validation returns enabled features from product definition."""
        activation_request = create_autodesk_activation_request(
            product_key="REVIT",
            machine_id="MACHINE-001",
            installation_id="INST-001",
        )
        act_req = parser.parse_request(activation_request)
        assert act_req is not None
        act_response = parser.generate_response(act_req)
        activation_id = act_response.activation_data["activation_id"]

        validation_request = create_autodesk_validation_request(
            activation_id=activation_id,
            product_key="REVIT",
            machine_id="MACHINE-001",
        )
        val_req = parser.parse_request(validation_request)
        assert val_req is not None
        val_req.installation_id = "INST-001"

        response = parser.generate_response(val_req)

        assert "features_enabled" in response.license_data
        features = response.license_data["features_enabled"]
        assert "bim" in features
        assert "architecture" in features

    def test_validation_generates_signature(self, parser: AutodeskLicensingParser) -> None:
        """Validation generates cryptographic signature."""
        validation_request = create_autodesk_validation_request()
        val_req = parser.parse_request(validation_request)
        assert val_req is not None

        response = parser.generate_response(val_req)

        assert len(response.digital_signature) == 64
        assert all(c in "0123456789abcdef" for c in response.digital_signature.lower())

    def test_validation_updates_last_validation_time(self, parser: AutodeskLicensingParser) -> None:
        """Validation updates last validation timestamp in activation record."""
        activation_request = create_autodesk_activation_request(
            product_key="3DSMAX",
            machine_id="MACHINE-001",
            installation_id="INST-001",
        )
        act_req = parser.parse_request(activation_request)
        assert act_req is not None
        act_response = parser.generate_response(act_req)
        activation_id = act_response.activation_data["activation_id"]

        time.sleep(0.1)

        validation_request = create_autodesk_validation_request(
            activation_id=activation_id,
            machine_id="MACHINE-001",
        )
        val_req = parser.parse_request(validation_request)
        assert val_req is not None
        val_req.installation_id = "INST-001"
        val_req.product_key = "3DSMAX"

        response = parser.generate_response(val_req)

        assert "last_validation" in parser.active_activations[activation_id]
        assert parser.active_activations[activation_id]["last_validation"] > parser.active_activations[activation_id]["activation_time"]


class TestAutodeskDeactivationResponse:
    """Test Autodesk deactivation response generation."""

    def test_deactivation_removes_activation_record(self, parser: AutodeskLicensingParser) -> None:
        """Deactivation removes activation from parser state."""
        activation_request = create_autodesk_activation_request(product_key="ACD")
        act_req = parser.parse_request(activation_request)
        assert act_req is not None
        act_response = parser.generate_response(act_req)
        activation_id = act_response.activation_data["activation_id"]

        assert activation_id in parser.active_activations

        deactivation_body = json.dumps({"activation_id": activation_id})
        deactivation_request = (
            f"POST /deactivate HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(deactivation_body)}\r\n"
            f"\r\n"
            f"{deactivation_body}"
        )
        deact_req = parser.parse_request(deactivation_request)
        assert deact_req is not None

        response = parser.generate_response(deact_req)

        assert response.status == "success"
        assert response.response_code == 200
        assert activation_id not in parser.active_activations
        assert response.activation_data["deactivation_status"] == "deactivated"

    def test_deactivation_succeeds_for_unknown_activation(self, parser: AutodeskLicensingParser) -> None:
        """Deactivation succeeds gracefully for unknown activation IDs."""
        deactivation_body = json.dumps({"activation_id": "UNKNOWN-ID"})
        deactivation_request = (
            f"POST /deactivate HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(deactivation_body)}\r\n"
            f"\r\n"
            f"{deactivation_body}"
        )
        deact_req = parser.parse_request(deactivation_request)
        assert deact_req is not None

        response = parser.generate_response(deact_req)

        assert response.status == "success"
        assert response.response_code == 200


class TestAutodeskEntitlementResponse:
    """Test Autodesk entitlement verification response generation."""

    def test_entitlement_generates_entitlement_data(self, parser: AutodeskLicensingParser) -> None:
        """Entitlement verification generates complete entitlement data."""
        http_data = create_autodesk_entitlement_request(
            user_id="premium@company.com",
            product_key="MAYA",
        )
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert response.status == "success"
        assert response.response_code == 200
        assert "user_id" in response.entitlement_data
        assert response.entitlement_data["user_id"] == "premium@company.com"
        assert "entitled_products" in response.entitlement_data
        assert "MAYA" in response.entitlement_data["entitled_products"]

    def test_entitlement_caches_data_for_user(self, parser: AutodeskLicensingParser) -> None:
        """Entitlement verification caches data for subsequent requests."""
        http_data = create_autodesk_entitlement_request(
            user_id="test@test.com",
            product_key="ACD",
        )
        request = parser.parse_request(http_data)
        assert request is not None

        response1 = parser.generate_response(request)
        contract_number1 = response1.entitlement_data["contract_number"]

        response2 = parser.generate_response(request)
        contract_number2 = response2.entitlement_data["contract_number"]

        assert contract_number1 == contract_number2

    def test_entitlement_includes_subscription_info(self, parser: AutodeskLicensingParser) -> None:
        """Entitlement response includes subscription information."""
        http_data = create_autodesk_entitlement_request(product_key="FUSION")
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert response.entitlement_data["subscription_type"] == "premium"
        assert response.entitlement_data["subscription_status"] == "active"
        assert "support_level" in response.entitlement_data


class TestAutodeskHeartbeatResponse:
    """Test Autodesk heartbeat response generation."""

    def test_heartbeat_returns_alive_status(self, parser: AutodeskLicensingParser) -> None:
        """Heartbeat exposes AttributeError bug in source code."""
        request_body = {
            "product_key": "INVNTOR",
            "session_id": "SESSION-TEST",
        }
        body_json = json.dumps(request_body)

        http_data = (
            f"POST /heartbeat HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_json)}\r\n"
            f"\r\n"
            f"{body_json}"
        )

        request = parser.parse_request(http_data)
        assert request is not None

        with pytest.raises(AttributeError, match="license_data"):
            parser.generate_response(request)

    def test_heartbeat_includes_server_time(self, parser: AutodeskLicensingParser) -> None:
        """Heartbeat exposes AttributeError bug in source code."""
        request_body = {
            "product_key": "ACD",
            "session_id": "SESSION-TEST",
        }
        body_json = json.dumps(request_body)

        http_data = (
            f"POST /heartbeat HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_json)}\r\n"
            f"\r\n"
            f"{body_json}"
        )

        request = parser.parse_request(http_data)
        assert request is not None

        with pytest.raises(AttributeError, match="license_data"):
            parser.generate_response(request)

    def test_heartbeat_sets_interval_for_network_license(self, parser: AutodeskLicensingParser) -> None:
        """Heartbeat exposes AttributeError bug in source code."""
        request_body = {
            "product_key": "ACD",
            "license_method": "network",
        }
        body_json = json.dumps(request_body)

        http_data = (
            f"POST /heartbeat HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_json)}\r\n"
            f"\r\n"
            f"{body_json}"
        )

        req = parser.parse_request(http_data)
        assert req is not None

        with pytest.raises(AttributeError, match="license_data"):
            parser.generate_response(req)

    def test_heartbeat_sets_interval_for_standalone_license(self, parser: AutodeskLicensingParser) -> None:
        """Heartbeat exposes AttributeError bug in source code."""
        request_body = {
            "product_key": "MAYA",
            "license_method": "standalone",
        }
        body_json = json.dumps(request_body)

        http_data = (
            f"POST /heartbeat HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_json)}\r\n"
            f"\r\n"
            f"{body_json}"
        )

        req = parser.parse_request(http_data)
        assert req is not None

        with pytest.raises(AttributeError, match="license_data"):
            parser.generate_response(req)


class TestAutodeskNetworkLicenseResponse:
    """Test Autodesk network license response generation."""

    def test_network_license_checkout_succeeds(self, parser: AutodeskLicensingParser) -> None:
        """Network license checkout returns success."""
        http_data = create_autodesk_network_license_request(product_key="3DSMAX")
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert response.status == "success"
        assert response.response_code == 200
        assert "network_license_id" in response.activation_data
        assert response.license_data["license_type"] == "network"

    def test_network_license_tracks_seat_usage(self, parser: AutodeskLicensingParser) -> None:
        """Network license tracks seat usage."""
        http_data = create_autodesk_network_license_request(product_key="MAYA")
        request = parser.parse_request(http_data)
        assert request is not None

        response1 = parser.generate_response(request)
        seats_used_1 = response1.license_data["seats_in_use"]

        response2 = parser.generate_response(request)
        seats_used_2 = response2.license_data["seats_in_use"]

        assert seats_used_2 > seats_used_1

    def test_network_license_sets_expiry_date(self, parser: AutodeskLicensingParser) -> None:
        """Network license includes expiry date."""
        http_data = create_autodesk_network_license_request(product_key="REVIT")
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert "license_expiry" in response.license_data
        assert response.license_data["license_expiry"] != ""


class TestAutodeskOfflineActivationResponse:
    """Test Autodesk offline activation response generation."""

    def test_offline_activation_generates_code(self, parser: AutodeskLicensingParser) -> None:
        """Offline activation generates activation code."""
        http_data = create_autodesk_offline_activation_request(
            product_key="CIVIL3D",
            machine_id="OFFLINE-MACHINE-001",
        )
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert response.status == "success"
        assert response.response_code == 200
        assert "offline_activation_code" in response.activation_data
        code = response.activation_data["offline_activation_code"]
        assert len(code) == 64
        assert code.isupper()

    def test_offline_activation_includes_instructions(self, parser: AutodeskLicensingParser) -> None:
        """Offline activation includes usage instructions."""
        http_data = create_autodesk_offline_activation_request(product_key="ACD")
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert "instructions" in response.activation_data
        assert "offline" in response.activation_data["instructions"].lower()

    def test_offline_activation_code_unique_per_machine(self, parser: AutodeskLicensingParser) -> None:
        """Offline activation generates unique codes for different machines."""
        http_data1 = create_autodesk_offline_activation_request(
            machine_id="MACHINE-001",
        )
        request1 = parser.parse_request(http_data1)
        assert request1 is not None
        response1 = parser.generate_response(request1)

        time.sleep(0.01)

        http_data2 = create_autodesk_offline_activation_request(
            machine_id="MACHINE-002",
        )
        request2 = parser.parse_request(http_data2)
        assert request2 is not None
        response2 = parser.generate_response(request2)

        code1 = response1.activation_data["offline_activation_code"]
        code2 = response2.activation_data["offline_activation_code"]

        assert code1 != code2


class TestAutodeskSubscriptionResponse:
    """Test Autodesk subscription status response generation."""

    def test_subscription_returns_active_status(self, parser: AutodeskLicensingParser) -> None:
        """Subscription check returns active status."""
        http_data = create_autodesk_subscription_request(user_id="subscriber@test.com")
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert response.status == "success"
        assert response.response_code == 200
        assert response.entitlement_data["subscription_status"] == "active"

    def test_subscription_includes_billing_info(self, parser: AutodeskLicensingParser) -> None:
        """Subscription response includes billing information."""
        http_data = create_autodesk_subscription_request()
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert "billing_frequency" in response.entitlement_data
        assert "next_billing_date" in response.entitlement_data
        assert response.entitlement_data["billing_frequency"] == "annual"

    def test_subscription_includes_benefits(self, parser: AutodeskLicensingParser) -> None:
        """Subscription response includes subscription benefits."""
        http_data = create_autodesk_subscription_request()
        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert "subscription_benefits" in response.entitlement_data
        benefits = response.entitlement_data["subscription_benefits"]
        assert "cloud_storage" in benefits
        assert "technical_support" in benefits


class TestAutodeskRegistrationResponse:
    """Test Autodesk product registration response generation."""

    def test_registration_generates_registration_id(self, parser: AutodeskLicensingParser) -> None:
        """Registration generates unique registration ID."""
        request_body = json.dumps({"user_id": "user@test.com", "product_key": "ACD"})
        http_data = (
            f"POST /register HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(request_body)}\r\n"
            f"\r\n"
            f"{request_body}"
        )

        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert response.status == "success"
        assert response.response_code == 200
        assert "registration_id" in response.activation_data
        assert len(response.activation_data["registration_id"]) > 0

    def test_registration_includes_benefits(self, parser: AutodeskLicensingParser) -> None:
        """Registration response includes registration benefits."""
        request_body = json.dumps({"user_id": "user@test.com"})
        http_data = (
            f"POST /register HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(request_body)}\r\n"
            f"\r\n"
            f"{request_body}"
        )

        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert "registration_benefits" in response.license_data
        benefits = response.license_data["registration_benefits"]
        assert "support" in benefits
        assert "updates" in benefits


class TestAutodeskLicenseTransferResponse:
    """Test Autodesk license transfer response generation."""

    def test_license_transfer_generates_transfer_id(self, parser: AutodeskLicensingParser) -> None:
        """License transfer generates transfer ID."""
        request_body = json.dumps({
            "activation_id": "OLD-ACT-001",
            "machine_id": "NEW-MACHINE-001",
        })
        http_data = (
            f"POST /transfer HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(request_body)}\r\n"
            f"\r\n"
            f"{request_body}"
        )

        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert response.status == "success"
        assert response.response_code == 200
        assert "transfer_id" in response.activation_data
        assert response.activation_data["transfer_status"] == "approved"

    def test_license_transfer_includes_new_machine_id(self, parser: AutodeskLicensingParser) -> None:
        """License transfer includes new machine ID in response."""
        request_body = json.dumps({
            "machine_id": "NEW-MACHINE-XYZ",
        })
        http_data = (
            f"POST /transfer HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(request_body)}\r\n"
            f"\r\n"
            f"{request_body}"
        )

        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert response.license_data["new_machine_id"] == "NEW-MACHINE-XYZ"
        assert response.license_data["old_machine_deactivated"] is True


class TestAutodeskBorrowingResponse:
    """Test Autodesk license borrowing response generation."""

    def test_borrowing_generates_borrow_id(self, parser: AutodeskLicensingParser) -> None:
        """License borrowing generates borrow ID."""
        request_body = json.dumps({
            "product_key": "MAYA",
            "borrow_days": 7,
        })
        http_data = (
            f"POST /borrow HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(request_body)}\r\n"
            f"\r\n"
            f"{request_body}"
        )

        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert response.status == "success"
        assert response.response_code == 200
        assert "borrow_id" in response.activation_data
        assert response.activation_data["borrow_status"] == "approved"

    def test_borrowing_sets_borrow_period(self, parser: AutodeskLicensingParser) -> None:
        """License borrowing sets appropriate borrow period."""
        request_body = json.dumps({
            "product_key": "INVNTOR",
            "borrow_days": 14,
        })
        http_data = (
            f"POST /borrow HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(request_body)}\r\n"
            f"\r\n"
            f"{request_body}"
        )

        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert response.license_data["borrow_period_days"] == 14
        borrow_start = response.activation_data["borrow_start"]
        borrow_end = response.activation_data["borrow_end"]
        expected_duration = 14 * 86400
        assert abs((borrow_end - borrow_start) - expected_duration) < 5

    def test_borrowing_includes_borrowed_features(self, parser: AutodeskLicensingParser) -> None:
        """License borrowing includes list of borrowed features."""
        request_body = json.dumps({
            "product_key": "REVIT",
            "borrow_days": 7,
        })
        http_data = (
            f"POST /borrow HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(request_body)}\r\n"
            f"\r\n"
            f"{request_body}"
        )

        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert "borrowed_features" in response.license_data
        features = response.license_data["borrowed_features"]
        assert "bim" in features


class TestAutodeskFeatureUsageResponse:
    """Test Autodesk feature usage reporting response generation."""

    def test_feature_usage_records_usage(self, parser: AutodeskLicensingParser) -> None:
        """Feature usage reporting exposes AttributeError bug in source code."""
        request_body = {
            "features_used": ["rendering", "animation", "modeling"],
            "session_duration": 7200,
            "user_id": "user@test.com",
        }
        body_json = json.dumps(request_body)

        http_data = (
            f"POST /usage HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_json)}\r\n"
            f"\r\n"
            f"{body_json}"
        )

        request = parser.parse_request(http_data)
        assert request is not None

        with pytest.raises(AttributeError, match="license_data"):
            parser.generate_response(request)

    def test_feature_usage_includes_analytics(self, parser: AutodeskLicensingParser) -> None:
        """Feature usage exposes AttributeError bug in source code."""
        request_body = {
            "features_used": ["modeling", "rendering", "modeling"],
            "session_duration": 3600,
        }
        body_json = json.dumps(request_body)

        http_data = (
            f"POST /usage HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_json)}\r\n"
            f"\r\n"
            f"{body_json}"
        )

        request = parser.parse_request(http_data)
        assert request is not None

        with pytest.raises(AttributeError, match="license_data"):
            parser.generate_response(request)


class TestAutodeskResponseSerialization:
    """Test Autodesk response serialization to HTTP."""

    def test_serialize_response_creates_valid_http(self, parser: AutodeskLicensingParser) -> None:
        """Response serialization creates valid HTTP response."""
        http_data = create_autodesk_activation_request(product_key="ACD")
        request = parser.parse_request(http_data)
        assert request is not None
        response = parser.generate_response(request)

        serialized = parser.serialize_response(response)

        assert serialized.startswith("HTTP/1.1 200 OK")
        assert "Content-Type: application/json" in serialized
        assert "Content-Length:" in serialized
        assert "\r\n\r\n" in serialized

    def test_serialize_response_includes_json_body(self, parser: AutodeskLicensingParser) -> None:
        """Serialized response includes JSON body."""
        http_data = create_autodesk_activation_request(product_key="MAYA")
        request = parser.parse_request(http_data)
        assert request is not None
        response = parser.generate_response(request)

        serialized = parser.serialize_response(response)

        body_start = serialized.find("\r\n\r\n") + 4
        body = serialized[body_start:]
        body_data = json.loads(body)

        assert "status" in body_data
        assert "activation_data" in body_data
        assert "license_data" in body_data

    def test_serialize_response_includes_signature(self, parser: AutodeskLicensingParser) -> None:
        """Serialized response includes digital signature in body."""
        http_data = create_autodesk_activation_request(product_key="REVIT")
        request = parser.parse_request(http_data)
        assert request is not None
        response = parser.generate_response(request)

        serialized = parser.serialize_response(response)

        body_start = serialized.find("\r\n\r\n") + 4
        body = serialized[body_start:]
        body_data = json.loads(body)

        assert "signature" in body_data
        assert len(body_data["signature"]) == 64

    def test_serialize_error_response(self, parser: AutodeskLicensingParser) -> None:
        """Serialization handles error responses."""
        http_data = create_autodesk_activation_request(product_key="UNKNOWN")
        request = parser.parse_request(http_data)
        assert request is not None
        response = parser.generate_response(request)

        serialized = parser.serialize_response(response)

        assert "HTTP/1.1 404 OK" in serialized
        body_start = serialized.find("\r\n\r\n") + 4
        body = serialized[body_start:]
        body_data = json.loads(body)

        assert body_data["status"] == "error"


class TestAutodeskProductDefinitions:
    """Test Autodesk product definitions and metadata."""

    def test_autocad_product_definition_complete(self, parser: AutodeskLicensingParser) -> None:
        """AutoCAD product definition contains all required fields."""
        product = parser.AUTODESK_PRODUCTS["ACD"]

        assert product["name"] == "AutoCAD"
        assert product["product_family"] == "AutoCAD"
        assert product["license_model"] == "standalone_or_network"
        assert "features" in product
        assert product["subscription_required"] is True
        assert product["network_license_available"] is True

    def test_fusion360_cloud_only_license(self, parser: AutodeskLicensingParser) -> None:
        """Fusion 360 configured as cloud subscription only."""
        product = parser.AUTODESK_PRODUCTS["FUSION"]

        assert product["license_model"] == "cloud_subscription"
        assert product["network_license_available"] is False

    def test_all_products_have_features(self, parser: AutodeskLicensingParser) -> None:
        """All product definitions include feature lists."""
        for product_key, product_data in parser.AUTODESK_PRODUCTS.items():
            assert "features" in product_data
            assert len(product_data["features"]) > 0

    def test_all_products_have_required_fields(self, parser: AutodeskLicensingParser) -> None:
        """All product definitions contain required metadata fields."""
        required_fields = [
            "name",
            "product_family",
            "license_model",
            "features",
            "subscription_required",
            "network_license_available",
        ]

        for product_key, product_data in parser.AUTODESK_PRODUCTS.items():
            for field in required_fields:
                assert field in product_data, f"Product {product_key} missing field {field}"


class TestAutodeskEdgeCases:
    """Test edge cases and error handling."""

    def test_parse_malformed_json_body(self, parser: AutodeskLicensingParser) -> None:
        """Parser handles malformed JSON gracefully."""
        malformed_json = "{product_key: 'ACD', missing_quotes: true"

        http_data = (
            f"POST /activate HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(malformed_json)}\r\n"
            f"\r\n"
            f"{malformed_json}"
        )

        request = parser.parse_request(http_data)

        assert request is not None

    def test_parse_missing_headers(self, parser: AutodeskLicensingParser) -> None:
        """Parser handles requests with minimal headers."""
        http_data = (
            f"POST /activate HTTP/1.1\r\n"
            f"\r\n"
        )

        request = parser.parse_request(http_data)

        assert request is not None
        assert request.request_type == "activation"

    def test_unknown_request_type_returns_error(self, parser: AutodeskLicensingParser) -> None:
        """Unknown request types return error response."""
        request_body = json.dumps({"action": "unknown_action"})

        http_data = (
            f"POST /unknown_endpoint HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(request_body)}\r\n"
            f"\r\n"
            f"{request_body}"
        )

        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert response.status == "error"
        assert response.response_code == 400

    def test_activation_with_empty_machine_id(self, parser: AutodeskLicensingParser) -> None:
        """Activation handles empty machine ID."""
        http_data = create_autodesk_activation_request(
            product_key="ACD",
            machine_id="",
        )

        request = parser.parse_request(http_data)
        assert request is not None

        response = parser.generate_response(request)

        assert response.status == "success"

    def test_machine_signature_deterministic(self, parser: AutodeskLicensingParser) -> None:
        """Machine signature generation is deterministic."""
        http_data1 = create_autodesk_activation_request(
            machine_id="MACHINE-001",
            installation_id="INST-001",
            product_key="ACD",
        )
        request1 = parser.parse_request(http_data1)
        assert request1 is not None

        http_data2 = create_autodesk_activation_request(
            machine_id="MACHINE-001",
            installation_id="INST-001",
            product_key="ACD",
        )
        request2 = parser.parse_request(http_data2)
        assert request2 is not None

        sig1 = parser._generate_machine_signature(request1)
        sig2 = parser._generate_machine_signature(request2)

        assert sig1 == sig2

    def test_machine_signature_unique_per_machine(self, parser: AutodeskLicensingParser) -> None:
        """Different machines generate different signatures."""
        http_data1 = create_autodesk_activation_request(machine_id="MACHINE-001")
        request1 = parser.parse_request(http_data1)
        assert request1 is not None

        http_data2 = create_autodesk_activation_request(machine_id="MACHINE-002")
        request2 = parser.parse_request(http_data2)
        assert request2 is not None

        sig1 = parser._generate_machine_signature(request1)
        sig2 = parser._generate_machine_signature(request2)

        assert sig1 != sig2


class TestAutodeskTokenGeneration:
    """Test Autodesk token generation and validation."""

    def test_adsk_token_format_valid(self, parser: AutodeskLicensingParser) -> None:
        """ADSK token has valid format (base64.signature)."""
        http_data = create_autodesk_activation_request(user_id="user@test.com")
        request = parser.parse_request(http_data)
        assert request is not None

        token = parser._generate_adsk_token(request)

        assert "." in token
        parts = token.split(".")
        assert len(parts) == 2

        try:
            token_data_json = base64.b64decode(parts[0]).decode()
            token_data = json.loads(token_data_json)
            assert "user_id" in token_data
        except Exception:
            pytest.fail("Token data is not valid base64 JSON")

    def test_adsk_token_contains_expiry(self, parser: AutodeskLicensingParser) -> None:
        """ADSK token includes expiration timestamp."""
        http_data = create_autodesk_activation_request(user_id="user@test.com")
        request = parser.parse_request(http_data)
        assert request is not None

        token = parser._generate_adsk_token(request)
        token_b64 = token.split(".")[0]
        token_data = json.loads(base64.b64decode(token_b64).decode())

        assert "expires_at" in token_data
        assert "issued_at" in token_data
        assert token_data["expires_at"] > token_data["issued_at"]

    def test_adsk_token_signature_cryptographic(self, parser: AutodeskLicensingParser) -> None:
        """ADSK token signature is cryptographically generated."""
        http_data = create_autodesk_activation_request(user_id="user@test.com")
        request = parser.parse_request(http_data)
        assert request is not None

        token = parser._generate_adsk_token(request)
        signature = token.split(".")[1]

        assert len(signature) == 16
        assert all(c in "0123456789abcdef" for c in signature.lower())


class TestAutodeskIntegration:
    """Integration tests for complete Autodesk licensing workflows."""

    def test_full_activation_validation_cycle(self, parser: AutodeskLicensingParser) -> None:
        """Complete activation and validation workflow."""
        activation_request = create_autodesk_activation_request(
            product_key="MAYA",
            machine_id="INTEGRATION-MACHINE-001",
            installation_id="INTEGRATION-INST-001",
            user_id="integration@test.com",
        )

        act_req = parser.parse_request(activation_request)
        assert act_req is not None

        act_response = parser.generate_response(act_req)
        assert act_response.status == "success"

        activation_id = act_response.activation_data["activation_id"]
        machine_sig = act_response.activation_data["machine_signature"]

        validation_request = create_autodesk_validation_request(
            activation_id=activation_id,
            product_key="MAYA",
            machine_id="INTEGRATION-MACHINE-001",
        )

        val_req = parser.parse_request(validation_request)
        assert val_req is not None
        val_req.installation_id = "INTEGRATION-INST-001"

        val_response = parser.generate_response(val_req)
        assert val_response.status == "success"
        assert val_response.license_data["license_valid"] is True

    def test_activation_transfer_workflow(self, parser: AutodeskLicensingParser) -> None:
        """Activation on one machine, transfer to another."""
        activation_request = create_autodesk_activation_request(
            product_key="REVIT",
            machine_id="MACHINE-A",
            installation_id="INST-A",
        )

        act_req = parser.parse_request(activation_request)
        assert act_req is not None
        act_response = parser.generate_response(act_req)
        activation_id = act_response.activation_data["activation_id"]

        transfer_body = json.dumps({
            "activation_id": activation_id,
            "machine_id": "MACHINE-B",
        })
        transfer_request = (
            f"POST /transfer HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(transfer_body)}\r\n"
            f"\r\n"
            f"{transfer_body}"
        )

        transfer_req = parser.parse_request(transfer_request)
        assert transfer_req is not None
        transfer_response = parser.generate_response(transfer_req)

        assert transfer_response.status == "success"
        assert transfer_response.license_data["new_machine_id"] == "MACHINE-B"

    def test_network_license_borrowing_workflow(self, parser: AutodeskLicensingParser) -> None:
        """Network license checkout followed by borrowing."""
        network_request = create_autodesk_network_license_request(
            product_key="3DSMAX",
            user_id="network_user@test.com",
            machine_id="NETWORK-NODE-01",
        )

        net_req = parser.parse_request(network_request)
        assert net_req is not None
        net_response = parser.generate_response(net_req)

        assert net_response.status == "success"
        assert net_response.license_data["license_type"] == "network"

        borrow_body = json.dumps({
            "product_key": "3DSMAX",
            "borrow_days": 7,
        })
        borrow_request = (
            f"POST /borrow HTTP/1.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(borrow_body)}\r\n"
            f"\r\n"
            f"{borrow_body}"
        )

        borrow_req = parser.parse_request(borrow_request)
        assert borrow_req is not None
        borrow_response = parser.generate_response(borrow_req)

        assert borrow_response.status == "success"
        assert borrow_response.activation_data["borrow_status"] == "approved"

    def test_subscription_entitlement_workflow(self, parser: AutodeskLicensingParser) -> None:
        """Subscription check followed by entitlement verification."""
        subscription_request = create_autodesk_subscription_request(
            user_id="premium_subscriber@test.com",
        )

        sub_req = parser.parse_request(subscription_request)
        assert sub_req is not None
        sub_response = parser.generate_response(sub_req)

        assert sub_response.entitlement_data["subscription_status"] == "active"

        entitlement_request = create_autodesk_entitlement_request(
            user_id="premium_subscriber@test.com",
            product_key="FUSION",
        )

        ent_req = parser.parse_request(entitlement_request)
        assert ent_req is not None
        ent_response = parser.generate_response(ent_req)

        assert ent_response.status == "success"
        assert "FUSION" in ent_response.entitlement_data["entitled_products"]
