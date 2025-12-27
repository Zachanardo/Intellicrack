"""Production tests for Autodesk Licensing Protocol Parser.

Tests validate parsing of real Autodesk licensing requests, response generation,
activation, validation, network licensing, and subscription handling against
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


class TestAutodeskRequestParsing:
    """Test parsing of Autodesk licensing requests."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide fresh parser instance."""
        return AutodeskLicensingParser()

    def test_parse_activation_request(self, parser: AutodeskLicensingParser) -> None:
        """Parser correctly parses Autodesk activation request."""
        http_request = (
            "POST /api/auth/activate HTTP/1.1\r\n"
            "Host: licensing.autodesk.com\r\n"
            "Content-Type: application/json\r\n"
            "Authorization: Bearer test_token\r\n"
            "\r\n"
            '{"product_key": "ACD", "installation_id": "INST-12345", '
            '"machine_id": "MACH-67890", "user_id": "user@example.com"}'
        )

        request = parser.parse_request(http_request)

        assert request is not None
        assert request.request_type == "activation"
        assert request.product_key == "ACD"
        assert request.installation_id == "INST-12345"
        assert request.machine_id == "MACH-67890"
        assert request.user_id == "user@example.com"
        assert request.auth_token == "test_token"

    def test_parse_validation_request(self, parser: AutodeskLicensingParser) -> None:
        """Parser correctly parses license validation request."""
        http_request = (
            "GET /api/license/validate HTTP/1.1\r\n"
            "Host: licensing.autodesk.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"activation_id": "ACT-12345", "machine_id": "MACH-67890"}'
        )

        request = parser.parse_request(http_request)

        assert request is not None
        assert request.request_type == "validation"
        assert request.activation_id == "ACT-12345"
        assert request.machine_id == "MACH-67890"

    def test_parse_request_with_form_data(self, parser: AutodeskLicensingParser) -> None:
        """Parser handles form-encoded data in requests."""
        http_request = (
            "POST /activate HTTP/1.1\r\n"
            "Host: licensing.autodesk.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "\r\n"
            "product_key=MAYA&installation_id=INST-54321&machine_id=MACH-98765"
        )

        request = parser.parse_request(http_request)

        assert request is not None
        assert request.product_key == "MAYA"
        assert request.installation_id == "INST-54321"
        assert request.machine_id == "MACH-98765"

    def test_parse_request_invalid_returns_none(self, parser: AutodeskLicensingParser) -> None:
        """Parser returns None for invalid request data."""
        invalid_request = "INVALID HTTP DATA"

        result = parser.parse_request(invalid_request)

        assert result is None

    def test_parse_request_extracts_platform_info(self, parser: AutodeskLicensingParser) -> None:
        """Parser extracts platform information from request."""
        http_request = (
            "POST /activate HTTP/1.1\r\n"
            "Host: licensing.autodesk.com\r\n"
            "User-Agent: AutoCAD/2024 Windows NT 10.0\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"product_key": "ACD", "language": "en-US", "timezone": "America/New_York"}'
        )

        request = parser.parse_request(http_request)

        assert request is not None
        assert "user_agent" in request.platform_info
        assert request.platform_info["os"] == "Windows"
        assert request.platform_info["language"] == "en-US"
        assert request.platform_info["timezone"] == "America/New_York"

    def test_parse_request_case_insensitive_headers(self, parser: AutodeskLicensingParser) -> None:
        """Parser handles case-insensitive header names."""
        http_request = (
            "POST /activate HTTP/1.1\r\n"
            "CONTENT-TYPE: application/json\r\n"
            "AUTHORIZATION: Bearer test_token\r\n"
            "\r\n"
            '{"product_key": "REVIT"}'
        )

        request = parser.parse_request(http_request)

        assert request is not None
        assert "content-type" in request.headers
        assert request.auth_token == "test_token"


class TestAutodeskActivation:
    """Test activation response generation."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide fresh parser instance."""
        return AutodeskLicensingParser()

    @pytest.fixture
    def activation_request(self) -> AutodeskRequest:
        """Provide sample activation request."""
        return AutodeskRequest(
            request_type="activation",
            product_key="ACD",
            installation_id="INST-12345",
            machine_id="MACH-67890",
            user_id="user@example.com",
            activation_id="",
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="test_token",
            platform_info={"os": "Windows"},
        )

    def test_activation_generates_activation_id(self, parser: AutodeskLicensingParser, activation_request: AutodeskRequest) -> None:
        """Activation response includes generated activation ID."""
        response = parser.generate_response(activation_request)

        assert response.status == "success"
        assert response.response_code == 200
        assert "activation_id" in response.activation_data
        assert len(response.activation_data["activation_id"]) > 0

    def test_activation_stores_activation_data(self, parser: AutodeskLicensingParser, activation_request: AutodeskRequest) -> None:
        """Activation stores activation data internally."""
        response = parser.generate_response(activation_request)

        activation_id = response.activation_data["activation_id"]

        assert activation_id in parser.active_activations
        assert parser.active_activations[activation_id]["product_key"] == "ACD"
        assert parser.active_activations[activation_id]["machine_id"] == "MACH-67890"

    def test_activation_includes_license_data(self, parser: AutodeskLicensingParser, activation_request: AutodeskRequest) -> None:
        """Activation response includes comprehensive license data."""
        response = parser.generate_response(activation_request)

        assert "product_name" in response.license_data
        assert response.license_data["product_name"] == "AutoCAD"
        assert "features" in response.license_data
        assert isinstance(response.license_data["features"], list)
        assert "expiry_date" in response.license_data

    def test_activation_includes_entitlement_data(self, parser: AutodeskLicensingParser, activation_request: AutodeskRequest) -> None:
        """Activation response includes entitlement information."""
        response = parser.generate_response(activation_request)

        assert "entitled_to" in response.entitlement_data
        assert "subscription_status" in response.entitlement_data
        assert response.entitlement_data["subscription_status"] == "active"

    def test_activation_generates_digital_signature(self, parser: AutodeskLicensingParser, activation_request: AutodeskRequest) -> None:
        """Activation response includes digital signature."""
        response = parser.generate_response(activation_request)

        assert response.digital_signature is not None
        assert len(response.digital_signature) == 64

    def test_activation_unknown_product_returns_error(self, parser: AutodeskLicensingParser) -> None:
        """Activation for unknown product returns error response."""
        request = AutodeskRequest(
            request_type="activation",
            product_key="UNKNOWN_PRODUCT",
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

        response = parser.generate_response(request)

        assert response.status == "error"
        assert response.response_code == 404
        assert "Unknown product" in response.license_data.get("error", "")


class TestAutodeskValidation:
    """Test license validation."""

    @pytest.fixture
    def parser_with_activation(self) -> tuple[AutodeskLicensingParser, str]:
        """Provide parser with pre-existing activation."""
        parser = AutodeskLicensingParser()

        activation_request = AutodeskRequest(
            request_type="activation",
            product_key="MAYA",
            installation_id="INST-99999",
            machine_id="MACH-11111",
            user_id="test@example.com",
            activation_id="",
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        activation_response = parser.generate_response(activation_request)
        activation_id = activation_response.activation_data["activation_id"]

        return parser, activation_id

    def test_validation_succeeds_for_valid_activation(self, parser_with_activation: tuple[AutodeskLicensingParser, str]) -> None:
        """Validation succeeds for existing valid activation."""
        parser, activation_id = parser_with_activation

        validation_request = AutodeskRequest(
            request_type="validation",
            product_key="MAYA",
            installation_id="INST-99999",
            machine_id="MACH-11111",
            user_id="test@example.com",
            activation_id=activation_id,
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(validation_request)

        assert response.status == "success"
        assert response.response_code == 200
        assert response.activation_data["validation_status"] == "valid"
        assert response.license_data["license_valid"] is True

    def test_validation_succeeds_for_unknown_activation(self, parser_with_activation: tuple[AutodeskLicensingParser, str]) -> None:
        """Validation succeeds gracefully even for unknown activations."""
        parser, _activation_id = parser_with_activation

        validation_request = AutodeskRequest(
            request_type="validation",
            product_key="ACD",
            installation_id="INST-77777",
            machine_id="MACH-88888",
            user_id="unknown@example.com",
            activation_id="UNKNOWN-ACTIVATION",
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(validation_request)

        assert response.status == "success"
        assert response.response_code == 200
        assert response.license_data["license_valid"] is True

    def test_validation_detects_machine_mismatch(self, parser_with_activation: tuple[AutodeskLicensingParser, str]) -> None:
        """Validation detects machine signature mismatch."""
        parser, activation_id = parser_with_activation

        validation_request = AutodeskRequest(
            request_type="validation",
            product_key="MAYA",
            installation_id="INST-99999",
            machine_id="DIFFERENT-MACHINE",
            user_id="test@example.com",
            activation_id=activation_id,
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(validation_request)

        assert response.status == "error"
        assert response.response_code == 403
        assert "signature mismatch" in response.license_data.get("error", "")


class TestAutodeskNetworkLicensing:
    """Test network license management."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide fresh parser instance."""
        return AutodeskLicensingParser()

    def test_network_license_checkout(self, parser: AutodeskLicensingParser) -> None:
        """Network license checkout succeeds and tracks seat usage."""
        request = AutodeskRequest(
            request_type="network_license",
            product_key="INVNTOR",
            installation_id="",
            machine_id="MACH-11111",
            user_id="user@example.com",
            activation_id="",
            license_method="network",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"
        assert response.response_code == 200
        assert "network_license_id" in response.activation_data
        assert response.license_data["license_type"] == "network"
        assert response.license_data["seats_in_use"] == 1
        assert response.license_data["seats_total"] == 100

    def test_network_license_tracks_multiple_checkouts(self, parser: AutodeskLicensingParser) -> None:
        """Multiple network license checkouts increment seat count."""
        request = AutodeskRequest(
            request_type="network_license",
            product_key="REVIT",
            installation_id="",
            machine_id="",
            user_id="",
            activation_id="",
            license_method="network",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        parser.generate_response(request)
        parser.generate_response(request)
        response = parser.generate_response(request)

        assert response.license_data["seats_in_use"] == 3


class TestAutodeskSubscriptionHandling:
    """Test subscription status checks."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide fresh parser instance."""
        return AutodeskLicensingParser()

    def test_subscription_check_returns_active_status(self, parser: AutodeskLicensingParser) -> None:
        """Subscription check returns active subscription data."""
        request = AutodeskRequest(
            request_type="subscription",
            product_key="FUSION",
            installation_id="",
            machine_id="",
            user_id="subscriber@example.com",
            activation_id="",
            license_method="cloud_subscription",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"
        assert response.response_code == 200
        assert "subscription_status" in response.entitlement_data
        assert response.entitlement_data["subscription_status"] == "active"
        assert "subscription_benefits" in response.entitlement_data


class TestAutodeskDeactivation:
    """Test product deactivation."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide fresh parser instance."""
        return AutodeskLicensingParser()

    def test_deactivation_removes_activation(self, parser: AutodeskLicensingParser) -> None:
        """Deactivation removes activation from active list."""
        activation_request = AutodeskRequest(
            request_type="activation",
            product_key="3DSMAX",
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

        activation_response = parser.generate_response(activation_request)
        activation_id = activation_response.activation_data["activation_id"]

        assert activation_id in parser.active_activations

        deactivation_request = AutodeskRequest(
            request_type="deactivation",
            product_key="3DSMAX",
            installation_id="INST-12345",
            machine_id="MACH-67890",
            user_id="user@example.com",
            activation_id=activation_id,
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        deactivation_response = parser.generate_response(deactivation_request)

        assert deactivation_response.status == "success"
        assert deactivation_response.response_code == 200
        assert activation_id not in parser.active_activations


class TestAutodeskResponseSerialization:
    """Test response serialization to HTTP format."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide fresh parser instance."""
        return AutodeskLicensingParser()

    def test_serialize_response_valid_http(self, parser: AutodeskLicensingParser) -> None:
        """Response serialization produces valid HTTP response."""
        response = AutodeskResponse(
            status="success",
            response_code=200,
            activation_data={"test": "data"},
            license_data={"license": "valid"},
            entitlement_data={},
            digital_signature="abc123",
            response_headers={"Content-Type": "application/json"},
        )

        http_response = parser.serialize_response(response)

        assert "HTTP/1.1 200 OK" in http_response
        assert "Content-Type: application/json" in http_response
        assert "Content-Length:" in http_response
        assert '"status": "success"' in http_response
        assert '"signature": "abc123"' in http_response

    def test_serialize_response_includes_body(self, parser: AutodeskLicensingParser) -> None:
        """Serialized response includes JSON body with all data."""
        response = AutodeskResponse(
            status="success",
            response_code=200,
            activation_data={"activation_id": "ACT-12345"},
            license_data={"license_valid": True},
            entitlement_data={"subscription": "active"},
            digital_signature="",
            response_headers={},
        )

        http_response = parser.serialize_response(response)

        assert '"activation_data"' in http_response
        assert '"license_data"' in http_response
        assert '"entitlement_data"' in http_response
        assert '"activation_id": "ACT-12345"' in http_response


class TestAutodeskEntitlementVerification:
    """Test entitlement verification."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide fresh parser instance."""
        return AutodeskLicensingParser()

    def test_entitlement_verification_caches_data(self, parser: AutodeskLicensingParser) -> None:
        """Entitlement verification caches entitlement data."""
        request = AutodeskRequest(
            request_type="entitlement",
            product_key="EAGLE",
            installation_id="",
            machine_id="",
            user_id="user@example.com",
            activation_id="",
            license_method="subscription",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"
        assert "user@example.com:EAGLE" in parser.entitlement_cache
        assert response.entitlement_data["subscription_status"] == "active"


class TestAutodeskHeartbeat:
    """Test license heartbeat mechanism."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide fresh parser instance."""
        return AutodeskLicensingParser()

    def test_heartbeat_network_license_shorter_interval(self, parser: AutodeskLicensingParser) -> None:
        """Network license heartbeat uses shorter interval."""
        request = AutodeskRequest(
            request_type="heartbeat",
            product_key="CIVIL3D",
            installation_id="",
            machine_id="",
            user_id="",
            activation_id="",
            license_method="network",
            request_data={"license_method": "network"},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"
        assert response.license_data["heartbeat_interval"] == 1800

    def test_heartbeat_standalone_license_longer_interval(self, parser: AutodeskLicensingParser) -> None:
        """Standalone license heartbeat uses longer interval."""
        request = AutodeskRequest(
            request_type="heartbeat",
            product_key="MAYA",
            installation_id="",
            machine_id="",
            user_id="",
            activation_id="",
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.license_data["heartbeat_interval"] == 3600


class TestAutodeskOfflineActivation:
    """Test offline activation flow."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide fresh parser instance."""
        return AutodeskLicensingParser()

    def test_offline_activation_generates_code(self, parser: AutodeskLicensingParser) -> None:
        """Offline activation generates unique activation code."""
        request = AutodeskRequest(
            request_type="offline_activation",
            product_key="NETFABB",
            installation_id="",
            machine_id="MACH-OFFLINE",
            user_id="",
            activation_id="",
            license_method="standalone",
            request_data={},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"
        assert "offline_activation_code" in response.activation_data
        assert len(response.activation_data["offline_activation_code"]) == 64


class TestAutodeskLicenseBorrowing:
    """Test license borrowing functionality."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide fresh parser instance."""
        return AutodeskLicensingParser()

    def test_license_borrowing_with_custom_period(self, parser: AutodeskLicensingParser) -> None:
        """License borrowing respects custom borrow period."""
        request = AutodeskRequest(
            request_type="borrowing",
            product_key="INVNTOR",
            installation_id="",
            machine_id="",
            user_id="",
            activation_id="",
            license_method="network",
            request_data={"borrow_days": 14},
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"
        assert response.license_data["borrow_period_days"] == 14


class TestAutodeskFeatureUsageReporting:
    """Test feature usage analytics."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide fresh parser instance."""
        return AutodeskLicensingParser()

    def test_feature_usage_analytics(self, parser: AutodeskLicensingParser) -> None:
        """Feature usage reporting processes analytics correctly."""
        request = AutodeskRequest(
            request_type="feature_usage",
            product_key="ACD",
            installation_id="",
            machine_id="",
            user_id="",
            activation_id="",
            license_method="standalone",
            request_data={
                "features_used": ["2d_drafting", "dwg_files", "2d_drafting", "pdf_import"],
                "session_duration": 7200,
                "product_version": "2024",
            },
            headers={},
            auth_token="",
            platform_info={},
        )

        response = parser.generate_response(request)

        assert response.status == "success"
        assert "usage_analytics" in response.license_data
        assert response.license_data["usage_analytics"]["total_features"] == 3
        assert response.license_data["usage_analytics"]["most_used_feature"] == "2d_drafting"


class TestAutodeskProductIdentifiers:
    """Test Autodesk product identification."""

    @pytest.fixture
    def parser(self) -> AutodeskLicensingParser:
        """Provide fresh parser instance."""
        return AutodeskLicensingParser()

    def test_all_product_identifiers_valid(self, parser: AutodeskLicensingParser) -> None:
        """All defined Autodesk products have valid metadata."""
        for product_key, product_data in parser.AUTODESK_PRODUCTS.items():
            assert "name" in product_data
            assert "product_family" in product_data
            assert "license_model" in product_data
            assert "features" in product_data
            assert isinstance(product_data["features"], list)
            assert "subscription_required" in product_data
            assert "network_license_available" in product_data
