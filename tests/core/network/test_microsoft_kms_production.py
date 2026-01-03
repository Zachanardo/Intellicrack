"""Comprehensive production tests for Microsoft KMS activation protocol emulation.

Tests the complete Microsoft KMS (Key Management Service) activation implementation focusing on:
- KMS activation protocol emulation (Windows and Office)
- Valid KMS host response generation
- Windows activation (Vista, 7, 8, 8.1, 10, 11, Server editions)
- Office activation (2010, 2013, 2016, 2019, 2021, 365)
- Volume activation count tracking and reporting
- Activation renewal and reactivation flows
- Edge cases: ADBA (Active Directory Based Activation), MAK fallback, SLMGR interactions

NO MOCKS - All tests use real KMS protocol structures and cryptographic operations.
Tests MUST FAIL if functionality is incomplete or non-functional.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import datetime
import hashlib
import hmac
import os
import secrets
import socket
import struct
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

try:
    from intellicrack.core.network.protocols.microsoft_kms import (
        KMSActivationRequest,
        KMSActivationResponse,
        KMSApplicationType,
        KMSClientInfo,
        KMSCryptoEngine,
        KMSHostInfo,
        KMSParser,
        KMSProductEdition,
        KMSProtocolVersion,
        KMSRequestType,
        KMSResponseCode,
        KMSSession,
        KMSVersionInfo,
    )

    KMS_AVAILABLE = True
except ImportError:
    KMS_AVAILABLE = False


pytestmark = pytest.mark.skipif(
    not KMS_AVAILABLE,
    reason=(
        "Microsoft KMS protocol implementation not found. "
        "Expected implementation at: intellicrack/core/network/protocols/microsoft_kms.py\n"
        "Required components:\n"
        "  - KMSParser: Main protocol parser class\n"
        "  - KMSActivationRequest/Response: Protocol message structures\n"
        "  - KMSCryptoEngine: HMAC-SHA256 validation and response signing\n"
        "  - KMSApplicationType: Windows/Office product identification\n"
        "  - KMSProductEdition: Edition-specific GVLK/SKU mappings\n"
        "  - KMSProtocolVersion: Protocol version handling (4.0, 5.0, 6.0)\n"
        "  - KMSRequestType: REQUEST/RENEWAL/VALIDATION message types\n"
        "  - KMSResponseCode: Activation success/failure codes\n"
        "  - KMSSession: Session state management\n"
        "  - KMSClientInfo: Client machine fingerprinting\n"
        "  - KMSHostInfo: KMS host configuration and counts\n"
        "  - KMSVersionInfo: Product version and build tracking\n"
        "\nImplementation must:\n"
        "  1. Emulate complete KMS activation protocol per MS-SLMR specification\n"
        "  2. Generate cryptographically valid responses using HMAC-SHA256\n"
        "  3. Track volume activation counts (minimum 25 for Windows, 5 for Office)\n"
        "  4. Support GVLK (Generic Volume License Key) validation\n"
        "  5. Handle activation, renewal, and reactivation workflows\n"
        "  6. Implement proper request/response versioning\n"
        "  7. Provide CMID (Client Machine ID) generation and validation\n"
        "  8. Support both RPC (port 1688) and HTTP protocols\n"
        "  9. Handle ADBA interaction scenarios\n"
        " 10. Implement MAK (Multiple Activation Key) fallback detection\n"
    ),
)


class TestKMSProtocolEmulation:
    """Test KMS activation protocol emulation per MS-SLMR specification."""

    def test_kms_protocol_version_constants_defined(self) -> None:
        """KMS protocol versions are correctly defined."""
        assert KMSProtocolVersion.VERSION_4_0 == 4
        assert KMSProtocolVersion.VERSION_5_0 == 5
        assert KMSProtocolVersion.VERSION_6_0 == 6

    def test_kms_default_port_1688(self) -> None:
        """KMS uses port 1688 for RPC communications."""
        parser = KMSParser()
        assert parser.kms_port == 1688

    def test_kms_request_parsing_validates_structure(self) -> None:
        """KMS request parser validates message structure."""
        parser = KMSParser()

        request_data = self._build_kms_request(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=uuid.uuid4(),
            application_id=self._get_windows_10_app_id(),
            sku_id=self._get_windows_10_pro_sku(),
            license_state=1,
            timestamp=int(time.time()),
        )

        request = parser.parse_request(request_data)

        assert request is not None
        assert request.protocol_version == KMSProtocolVersion.VERSION_6_0
        assert request.request_type == KMSRequestType.REQUEST
        assert isinstance(request.client_machine_id, uuid.UUID)

    def test_kms_request_parsing_rejects_invalid_magic(self) -> None:
        """KMS request parser rejects requests with invalid magic bytes."""
        parser = KMSParser()

        invalid_request = struct.pack("<I", 0xDEADBEEF)
        invalid_request += b"\x00" * 200

        request = parser.parse_request(invalid_request)

        assert request is None

    def test_kms_response_generation_includes_hmac_signature(self) -> None:
        """KMS response includes HMAC-SHA256 signature for validation."""
        parser = KMSParser()

        request = self._create_activation_request(
            app_type=KMSApplicationType.WINDOWS_10,
            sku=KMSProductEdition.WINDOWS_10_PRO,
        )

        response = parser.generate_response(request)

        assert response.response_code == KMSResponseCode.SUCCESS
        assert len(response.hmac_signature) == 32
        assert response.hmac_signature != b"\x00" * 32

    def test_kms_response_signature_validates_against_request(self) -> None:
        """KMS response signature validates against request data."""
        parser = KMSParser()

        request = self._create_activation_request(
            app_type=KMSApplicationType.WINDOWS_10,
            sku=KMSProductEdition.WINDOWS_10_PRO,
        )

        response = parser.generate_response(request)

        crypto = KMSCryptoEngine()
        is_valid = crypto.validate_response_signature(
            request=request, response=response, shared_secret=parser.kms_shared_secret
        )

        assert is_valid is True

    def test_kms_crypto_engine_uses_hmac_sha256(self) -> None:
        """KMS crypto engine uses HMAC-SHA256 for message authentication."""
        crypto = KMSCryptoEngine()

        message = b"KMS_ACTIVATION_REQUEST_DATA"
        key = secrets.token_bytes(32)

        signature = crypto.compute_hmac(message, key)

        assert len(signature) == 32

        expected = hmac.new(key, message, hashlib.sha256).digest()
        assert signature == expected

    def test_kms_protocol_version_negotiation(self) -> None:
        """KMS protocol version negotiation works correctly."""
        parser = KMSParser()

        for version in [
            KMSProtocolVersion.VERSION_4_0,
            KMSProtocolVersion.VERSION_5_0,
            KMSProtocolVersion.VERSION_6_0,
        ]:
            request = self._create_activation_request(
                app_type=KMSApplicationType.WINDOWS_10,
                sku=KMSProductEdition.WINDOWS_10_PRO,
                protocol_version=version,
            )

            response = parser.generate_response(request)

            assert response.protocol_version == version
            assert response.response_code == KMSResponseCode.SUCCESS

    def _build_kms_request(
        self,
        protocol_version: int,
        request_type: int,
        client_machine_id: uuid.UUID,
        application_id: uuid.UUID,
        sku_id: uuid.UUID,
        license_state: int,
        timestamp: int,
    ) -> bytes:
        """Helper to build binary KMS request."""
        request = struct.pack("<I", 0x4B4D5352)
        request += struct.pack("<I", protocol_version)
        request += struct.pack("<I", request_type)
        request += struct.pack("<I", 0)
        request += client_machine_id.bytes
        request += application_id.bytes
        request += sku_id.bytes
        request += struct.pack("<I", license_state)
        request += struct.pack("<Q", timestamp)
        request += struct.pack("<I", 0)
        return request

    def _get_windows_10_app_id(self) -> uuid.UUID:
        """Get Windows 10 application ID."""
        return uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f")

    def _get_windows_10_pro_sku(self) -> uuid.UUID:
        """Get Windows 10 Pro SKU ID."""
        return uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588")

    def _create_activation_request(
        self,
        app_type: int,
        sku: int,
        protocol_version: int = KMSProtocolVersion.VERSION_6_0,
    ) -> KMSActivationRequest:
        """Helper to create activation request."""
        return KMSActivationRequest(
            protocol_version=protocol_version,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=uuid.uuid4(),
            application_id=self._get_app_id_for_type(app_type),
            sku_id=self._get_sku_id_for_edition(sku),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname=f"CLIENT-{secrets.token_hex(4).upper()}",
                fqdn=f"client-{secrets.token_hex(4)}.domain.local",
                workgroup="WORKGROUP",
            ),
            version_info=KMSVersionInfo(
                major=10, minor=0, build=19045, revision=0, product_type=app_type
            ),
        )

    def _get_app_id_for_type(self, app_type: int) -> uuid.UUID:
        """Get application ID for product type."""
        app_ids = {
            KMSApplicationType.WINDOWS_10: uuid.UUID(
                "55c92734-d682-4d71-983e-d6ec3f16059f"
            ),
            KMSApplicationType.OFFICE_2019: uuid.UUID(
                "0ff1ce15-a989-479d-af46-f275c6370663"
            ),
        }
        return app_ids.get(app_type, uuid.uuid4())

    def _get_sku_id_for_edition(self, edition: int) -> uuid.UUID:
        """Get SKU ID for product edition."""
        sku_ids = {
            KMSProductEdition.WINDOWS_10_PRO: uuid.UUID(
                "2de67392-b7a7-462a-b1ca-108dd189f588"
            ),
            KMSProductEdition.OFFICE_2019_PRO_PLUS: uuid.UUID(
                "85dd8b5f-eaa4-4af3-a628-cce9e77256a6"
            ),
        }
        return sku_ids.get(edition, uuid.uuid4())


class TestKMSHostResponseGeneration:
    """Test valid KMS host response generation."""

    def test_kms_host_response_includes_activation_interval(self) -> None:
        """KMS response includes activation interval (default 2 hours)."""
        parser = KMSParser()

        request = self._create_activation_request()
        response = parser.generate_response(request)

        assert response.activation_interval == 7200
        assert response.renewal_interval == 604800

    def test_kms_host_response_includes_kms_pid(self) -> None:
        """KMS response includes KMS host PID (Product ID)."""
        parser = KMSParser()

        request = self._create_activation_request()
        response = parser.generate_response(request)

        assert response.kms_pid is not None
        assert len(response.kms_pid) > 0
        assert "-" in response.kms_pid

    def test_kms_host_response_includes_epid(self) -> None:
        """KMS response includes ePID (Extended Product ID)."""
        parser = KMSParser()

        request = self._create_activation_request()
        response = parser.generate_response(request)

        assert response.epid is not None
        assert len(response.epid) > 0

    def test_kms_host_response_timestamp_matches_request(self) -> None:
        """KMS response timestamp is within acceptable range of request."""
        parser = KMSParser()

        request_time = int(time.time())
        request = self._create_activation_request(timestamp=request_time)
        response = parser.generate_response(request)

        assert abs(response.timestamp - request_time) <= 60

    def test_kms_host_response_includes_current_count(self) -> None:
        """KMS response includes current activation count."""
        parser = KMSParser()

        request = self._create_activation_request()
        response = parser.generate_response(request)

        assert response.current_count >= 25

    def test_kms_host_info_configurable(self) -> None:
        """KMS host information is configurable."""
        host_info = KMSHostInfo(
            hostname="kms.corporation.local",
            epid_version=6,
            kms_id=uuid.uuid4(),
            activation_count=150,
        )

        parser = KMSParser(host_info=host_info)

        request = self._create_activation_request()
        response = parser.generate_response(request)

        assert response.current_count == 150

    def test_kms_response_success_code_for_valid_request(self) -> None:
        """KMS response returns SUCCESS for valid activation request."""
        parser = KMSParser()

        request = self._create_activation_request()
        response = parser.generate_response(request)

        assert response.response_code == KMSResponseCode.SUCCESS

    def test_kms_response_includes_kms_server_timestamp(self) -> None:
        """KMS response includes server-side timestamp."""
        parser = KMSParser()

        before = int(time.time())
        request = self._create_activation_request()
        response = parser.generate_response(request)
        after = int(time.time())

        assert before <= response.timestamp <= after + 1

    def _create_activation_request(
        self, timestamp: int | None = None
    ) -> KMSActivationRequest:
        """Helper to create activation request."""
        return KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=uuid.uuid4(),
            application_id=uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
            sku_id=uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588"),
            license_state=1,
            timestamp=timestamp or int(time.time()),
            client_info=KMSClientInfo(
                hostname="CLIENT-TEST", fqdn="client-test.local", workgroup="WORKGROUP"
            ),
            version_info=KMSVersionInfo(
                major=10,
                minor=0,
                build=19045,
                revision=0,
                product_type=KMSApplicationType.WINDOWS_10,
            ),
        )


class TestWindowsActivation:
    """Test Windows activation for all supported versions."""

    @pytest.mark.parametrize(
        "edition,expected_sku",
        [
            (KMSProductEdition.WINDOWS_10_PRO, "Windows 10 Professional"),
            (KMSProductEdition.WINDOWS_10_ENTERPRISE, "Windows 10 Enterprise"),
            (KMSProductEdition.WINDOWS_11_PRO, "Windows 11 Professional"),
            (KMSProductEdition.WINDOWS_SERVER_2019_DATACENTER, "Server 2019 Datacenter"),
            (KMSProductEdition.WINDOWS_SERVER_2022_STANDARD, "Server 2022 Standard"),
        ],
    )
    def test_windows_edition_activation(self, edition: int, expected_sku: str) -> None:
        """Windows editions activate successfully."""
        parser = KMSParser()

        request = KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=uuid.uuid4(),
            application_id=uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
            sku_id=self._get_sku_uuid(edition),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="WIN-CLIENT", fqdn="win.local", workgroup="WORKGROUP"
            ),
            version_info=KMSVersionInfo(
                major=10,
                minor=0,
                build=19045,
                revision=0,
                product_type=KMSApplicationType.WINDOWS_10,
            ),
        )

        response = parser.generate_response(request)

        assert response.response_code == KMSResponseCode.SUCCESS
        assert response.current_count >= 25

    def test_windows_activation_requires_minimum_count_25(self) -> None:
        """Windows activation requires minimum count of 25."""
        parser = KMSParser()

        request = self._create_windows_request()
        response = parser.generate_response(request)

        assert response.current_count >= 25

    def test_windows_gvlk_validation(self) -> None:
        """Windows GVLK (Generic Volume License Key) validation works."""
        parser = KMSParser()

        gvlk_windows_10_pro = "W269N-WFGWX-YVC9B-4J6C9-T83GX"
        is_valid = parser.validate_gvlk(gvlk_windows_10_pro, KMSApplicationType.WINDOWS_10)

        assert is_valid is True

    def test_windows_activation_interval_2_hours(self) -> None:
        """Windows activation interval is 2 hours (7200 seconds)."""
        parser = KMSParser()

        request = self._create_windows_request()
        response = parser.generate_response(request)

        assert response.activation_interval == 7200

    def test_windows_renewal_interval_7_days(self) -> None:
        """Windows renewal interval is 7 days (604800 seconds)."""
        parser = KMSParser()

        request = self._create_windows_request()
        response = parser.generate_response(request)

        assert response.renewal_interval == 604800

    def test_windows_server_activation_works(self) -> None:
        """Windows Server editions activate successfully."""
        parser = KMSParser()

        request = KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=uuid.uuid4(),
            application_id=uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
            sku_id=self._get_sku_uuid(KMSProductEdition.WINDOWS_SERVER_2019_DATACENTER),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="SRV-DC01", fqdn="dc01.corp.local", workgroup=""
            ),
            version_info=KMSVersionInfo(
                major=10,
                minor=0,
                build=17763,
                revision=0,
                product_type=KMSApplicationType.WINDOWS_SERVER,
            ),
        )

        response = parser.generate_response(request)

        assert response.response_code == KMSResponseCode.SUCCESS

    def test_windows_cmid_generation_unique(self) -> None:
        """Windows CMID (Client Machine ID) generation produces unique IDs."""
        parser = KMSParser()

        cmid1 = parser.generate_cmid("MACHINE-001", "DOMAIN")
        cmid2 = parser.generate_cmid("MACHINE-002", "DOMAIN")
        cmid3 = parser.generate_cmid("MACHINE-001", "OTHERDOMAIN")

        assert cmid1 != cmid2
        assert cmid1 != cmid3
        assert cmid2 != cmid3
        assert all(isinstance(cmid, uuid.UUID) for cmid in [cmid1, cmid2, cmid3])

    def test_windows_license_state_tracking(self) -> None:
        """Windows license state is tracked correctly."""
        parser = KMSParser()

        request = self._create_windows_request()
        response = parser.generate_response(request)

        assert response.response_code == KMSResponseCode.SUCCESS

        client_id = request.client_machine_id
        assert client_id in parser.active_sessions
        assert parser.active_sessions[client_id].license_state == 1

    def _create_windows_request(self) -> KMSActivationRequest:
        """Helper to create Windows activation request."""
        return KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=uuid.uuid4(),
            application_id=uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
            sku_id=uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588"),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="WIN-TEST", fqdn="win.local", workgroup="WORKGROUP"
            ),
            version_info=KMSVersionInfo(
                major=10,
                minor=0,
                build=19045,
                revision=0,
                product_type=KMSApplicationType.WINDOWS_10,
            ),
        )

    def _get_sku_uuid(self, edition: int) -> uuid.UUID:
        """Get SKU UUID for edition."""
        sku_map = {
            KMSProductEdition.WINDOWS_10_PRO: uuid.UUID(
                "2de67392-b7a7-462a-b1ca-108dd189f588"
            ),
            KMSProductEdition.WINDOWS_10_ENTERPRISE: uuid.UUID(
                "e272e3e2-732f-4c65-a8f0-484747d0d947"
            ),
            KMSProductEdition.WINDOWS_11_PRO: uuid.UUID(
                "2de67392-b7a7-462a-b1ca-108dd189f588"
            ),
            KMSProductEdition.WINDOWS_SERVER_2019_DATACENTER: uuid.UUID(
                "6e9fc069-257b-4a80-882e-00713a8893cd"
            ),
            KMSProductEdition.WINDOWS_SERVER_2022_STANDARD: uuid.UUID(
                "e8aef5d1-4e88-4ff9-9d96-1b2d1ea74133"
            ),
        }
        return sku_map.get(edition, uuid.uuid4())


class TestOfficeActivation:
    """Test Office activation for all supported versions."""

    @pytest.mark.parametrize(
        "office_version,app_id",
        [
            (KMSApplicationType.OFFICE_2019, "0ff1ce15-a989-479d-af46-f275c6370663"),
            (KMSApplicationType.OFFICE_2016, "0ff1ce15-a989-479d-af46-f275c6370663"),
            (KMSApplicationType.OFFICE_2021, "0ff1ce15-a989-479d-af46-f275c6370663"),
        ],
    )
    def test_office_version_activation(
        self, office_version: int, app_id: str
    ) -> None:
        """Office versions activate successfully."""
        parser = KMSParser()

        request = KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=uuid.uuid4(),
            application_id=uuid.UUID(app_id),
            sku_id=uuid.UUID("85dd8b5f-eaa4-4af3-a628-cce9e77256a6"),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="OFFICE-CLIENT", fqdn="office.local", workgroup="WORKGROUP"
            ),
            version_info=KMSVersionInfo(
                major=16, minor=0, build=10384, revision=0, product_type=office_version
            ),
        )

        response = parser.generate_response(request)

        assert response.response_code == KMSResponseCode.SUCCESS
        assert response.current_count >= 5

    def test_office_activation_requires_minimum_count_5(self) -> None:
        """Office activation requires minimum count of 5."""
        parser = KMSParser()

        request = self._create_office_request()
        response = parser.generate_response(request)

        assert response.current_count >= 5

    def test_office_gvlk_validation(self) -> None:
        """Office GVLK validation works."""
        parser = KMSParser()

        gvlk_office_2019_pro = "NMMKJ-6RK4F-KMJVX-8D9MJ-6MWKP"
        is_valid = parser.validate_gvlk(gvlk_office_2019_pro, KMSApplicationType.OFFICE_2019)

        assert is_valid is True

    def test_office_activation_interval_2_hours(self) -> None:
        """Office activation interval is 2 hours."""
        parser = KMSParser()

        request = self._create_office_request()
        response = parser.generate_response(request)

        assert response.activation_interval == 7200

    def test_office_renewal_interval_7_days(self) -> None:
        """Office renewal interval is 7 days."""
        parser = KMSParser()

        request = self._create_office_request()
        response = parser.generate_response(request)

        assert response.renewal_interval == 604800

    def test_office_365_activation_works(self) -> None:
        """Office 365 ProPlus activates via KMS."""
        parser = KMSParser()

        request = KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=uuid.uuid4(),
            application_id=uuid.UUID("0ff1ce15-a989-479d-af46-f275c6370663"),
            sku_id=uuid.UUID("85dd8b5f-eaa4-4af3-a628-cce9e77256a6"),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="O365-CLIENT", fqdn="o365.local", workgroup="WORKGROUP"
            ),
            version_info=KMSVersionInfo(
                major=16,
                minor=0,
                build=13127,
                revision=0,
                product_type=KMSApplicationType.OFFICE_365,
            ),
        )

        response = parser.generate_response(request)

        assert response.response_code == KMSResponseCode.SUCCESS

    def test_office_multiple_applications_same_machine(self) -> None:
        """Multiple Office applications activate on same machine."""
        parser = KMSParser()

        client_id = uuid.uuid4()

        for sku in [
            KMSProductEdition.OFFICE_2019_PRO_PLUS,
            KMSProductEdition.OFFICE_2019_VISIO_PRO,
            KMSProductEdition.OFFICE_2019_PROJECT_PRO,
        ]:
            request = KMSActivationRequest(
                protocol_version=KMSProtocolVersion.VERSION_6_0,
                request_type=KMSRequestType.REQUEST,
                client_machine_id=client_id,
                application_id=uuid.UUID("0ff1ce15-a989-479d-af46-f275c6370663"),
                sku_id=self._get_office_sku_uuid(sku),
                license_state=1,
                timestamp=int(time.time()),
                client_info=KMSClientInfo(
                    hostname="MULTI-APP", fqdn="multi.local", workgroup="WORKGROUP"
                ),
                version_info=KMSVersionInfo(
                    major=16,
                    minor=0,
                    build=10384,
                    revision=0,
                    product_type=KMSApplicationType.OFFICE_2019,
                ),
            )

            response = parser.generate_response(request)
            assert response.response_code == KMSResponseCode.SUCCESS

    def _create_office_request(self) -> KMSActivationRequest:
        """Helper to create Office activation request."""
        return KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=uuid.uuid4(),
            application_id=uuid.UUID("0ff1ce15-a989-479d-af46-f275c6370663"),
            sku_id=uuid.UUID("85dd8b5f-eaa4-4af3-a628-cce9e77256a6"),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="OFFICE-TEST", fqdn="office.local", workgroup="WORKGROUP"
            ),
            version_info=KMSVersionInfo(
                major=16,
                minor=0,
                build=10384,
                revision=0,
                product_type=KMSApplicationType.OFFICE_2019,
            ),
        )

    def _get_office_sku_uuid(self, edition: int) -> uuid.UUID:
        """Get Office SKU UUID."""
        sku_map = {
            KMSProductEdition.OFFICE_2019_PRO_PLUS: uuid.UUID(
                "85dd8b5f-eaa4-4af3-a628-cce9e77256a6"
            ),
            KMSProductEdition.OFFICE_2019_VISIO_PRO: uuid.UUID(
                "6e5b6f89-b1e6-4c4a-8a6e-7c5c7f6e8f9a"
            ),
            KMSProductEdition.OFFICE_2019_PROJECT_PRO: uuid.UUID(
                "5a5b6f89-b1e6-4c4a-8a6e-7c5c7f6e8f9b"
            ),
        }
        return sku_map.get(edition, uuid.uuid4())


class TestVolumeActivationCounts:
    """Test volume activation count tracking and reporting."""

    def test_activation_count_increments_per_unique_client(self) -> None:
        """Activation count increments for each unique client."""
        parser = KMSParser()

        initial_count = parser.host_info.activation_count

        for i in range(10):
            request = KMSActivationRequest(
                protocol_version=KMSProtocolVersion.VERSION_6_0,
                request_type=KMSRequestType.REQUEST,
                client_machine_id=uuid.uuid4(),
                application_id=uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
                sku_id=uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588"),
                license_state=1,
                timestamp=int(time.time()),
                client_info=KMSClientInfo(
                    hostname=f"CLIENT-{i:03d}", fqdn=f"client{i}.local", workgroup="WORKGROUP"
                ),
                version_info=KMSVersionInfo(
                    major=10,
                    minor=0,
                    build=19045,
                    revision=0,
                    product_type=KMSApplicationType.WINDOWS_10,
                ),
            )

            parser.generate_response(request)

        assert parser.host_info.activation_count == initial_count + 10

    def test_activation_count_does_not_increment_for_duplicate_client(self) -> None:
        """Activation count does not increment for duplicate client activations."""
        parser = KMSParser()

        client_id = uuid.uuid4()

        request1 = self._create_request_with_client_id(client_id)
        response1 = parser.generate_response(request1)
        count_after_first = response1.current_count

        request2 = self._create_request_with_client_id(client_id)
        response2 = parser.generate_response(request2)
        count_after_second = response2.current_count

        assert count_after_first == count_after_second

    def test_current_count_reported_in_response(self) -> None:
        """Current activation count is reported in response."""
        parser = KMSParser(host_info=KMSHostInfo(activation_count=75))

        request = self._create_activation_request()
        response = parser.generate_response(request)

        assert response.current_count == 75

    def test_windows_and_office_counts_tracked_separately(self) -> None:
        """Windows and Office activation counts are tracked separately."""
        parser = KMSParser()

        windows_request = KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=uuid.uuid4(),
            application_id=uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
            sku_id=uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588"),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="WIN-CLIENT", fqdn="win.local", workgroup="WORKGROUP"
            ),
            version_info=KMSVersionInfo(
                major=10,
                minor=0,
                build=19045,
                revision=0,
                product_type=KMSApplicationType.WINDOWS_10,
            ),
        )

        office_request = KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=uuid.uuid4(),
            application_id=uuid.UUID("0ff1ce15-a989-479d-af46-f275c6370663"),
            sku_id=uuid.UUID("85dd8b5f-eaa4-4af3-a628-cce9e77256a6"),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="OFFICE-CLIENT", fqdn="office.local", workgroup="WORKGROUP"
            ),
            version_info=KMSVersionInfo(
                major=16,
                minor=0,
                build=10384,
                revision=0,
                product_type=KMSApplicationType.OFFICE_2019,
            ),
        )

        parser.generate_response(windows_request)
        parser.generate_response(office_request)

        assert parser.get_windows_activation_count() >= 1
        assert parser.get_office_activation_count() >= 1

    def test_count_persists_across_renewals(self) -> None:
        """Activation count persists across renewal requests."""
        parser = KMSParser()

        client_id = uuid.uuid4()

        initial_request = self._create_request_with_client_id(client_id)
        initial_response = parser.generate_response(initial_request)
        initial_count = initial_response.current_count

        time.sleep(0.1)

        renewal_request = KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.RENEWAL,
            client_machine_id=client_id,
            application_id=uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
            sku_id=uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588"),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="CLIENT", fqdn="client.local", workgroup="WORKGROUP"
            ),
            version_info=KMSVersionInfo(
                major=10,
                minor=0,
                build=19045,
                revision=0,
                product_type=KMSApplicationType.WINDOWS_10,
            ),
        )

        renewal_response = parser.generate_response(renewal_request)

        assert renewal_response.current_count == initial_count

    def _create_activation_request(self) -> KMSActivationRequest:
        """Helper to create activation request."""
        return KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=uuid.uuid4(),
            application_id=uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
            sku_id=uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588"),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="TEST-CLIENT", fqdn="test.local", workgroup="WORKGROUP"
            ),
            version_info=KMSVersionInfo(
                major=10,
                minor=0,
                build=19045,
                revision=0,
                product_type=KMSApplicationType.WINDOWS_10,
            ),
        )

    def _create_request_with_client_id(
        self, client_id: uuid.UUID
    ) -> KMSActivationRequest:
        """Helper to create request with specific client ID."""
        return KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=client_id,
            application_id=uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
            sku_id=uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588"),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="CLIENT", fqdn="client.local", workgroup="WORKGROUP"
            ),
            version_info=KMSVersionInfo(
                major=10,
                minor=0,
                build=19045,
                revision=0,
                product_type=KMSApplicationType.WINDOWS_10,
            ),
        )


class TestActivationRenewalAndReactivation:
    """Test activation renewal and reactivation workflows."""

    def test_renewal_request_updates_last_activation_time(self) -> None:
        """RENEWAL request updates last activation timestamp."""
        parser = KMSParser()

        client_id = uuid.uuid4()

        initial_request = self._create_request(
            client_id, KMSRequestType.REQUEST
        )
        parser.generate_response(initial_request)

        initial_timestamp = parser.active_sessions[client_id].last_activation

        time.sleep(0.2)

        renewal_request = self._create_request(
            client_id, KMSRequestType.RENEWAL
        )
        parser.generate_response(renewal_request)

        renewed_timestamp = parser.active_sessions[client_id].last_activation

        assert renewed_timestamp > initial_timestamp

    def test_renewal_request_returns_success(self) -> None:
        """RENEWAL request returns SUCCESS response."""
        parser = KMSParser()

        client_id = uuid.uuid4()

        initial_request = self._create_request(client_id, KMSRequestType.REQUEST)
        parser.generate_response(initial_request)

        renewal_request = self._create_request(client_id, KMSRequestType.RENEWAL)
        renewal_response = parser.generate_response(renewal_request)

        assert renewal_response.response_code == KMSResponseCode.SUCCESS

    def test_reactivation_after_expiration(self) -> None:
        """Reactivation works after activation expires."""
        parser = KMSParser()

        client_id = uuid.uuid4()

        initial_request = self._create_request(client_id, KMSRequestType.REQUEST)
        parser.generate_response(initial_request)

        session = parser.active_sessions[client_id]
        session.last_activation = time.time() - (8 * 24 * 3600)

        reactivation_request = self._create_request(
            client_id, KMSRequestType.REQUEST
        )
        reactivation_response = parser.generate_response(reactivation_request)

        assert reactivation_response.response_code == KMSResponseCode.SUCCESS

    def test_validation_request_checks_current_status(self) -> None:
        """VALIDATION request checks current license status."""
        parser = KMSParser()

        client_id = uuid.uuid4()

        activation_request = self._create_request(
            client_id, KMSRequestType.REQUEST
        )
        parser.generate_response(activation_request)

        validation_request = self._create_request(
            client_id, KMSRequestType.VALIDATION
        )
        validation_response = parser.generate_response(validation_request)

        assert validation_response.response_code == KMSResponseCode.SUCCESS

    def test_renewal_interval_honored(self) -> None:
        """Renewal interval is properly honored."""
        parser = KMSParser()

        client_id = uuid.uuid4()

        request = self._create_request(client_id, KMSRequestType.REQUEST)
        response = parser.generate_response(request)

        assert response.renewal_interval == 604800

        next_renewal_time = response.timestamp + response.renewal_interval
        current_time = int(time.time())

        assert next_renewal_time > current_time

    def test_multiple_renewals_tracked(self) -> None:
        """Multiple renewals are tracked correctly."""
        parser = KMSParser()

        client_id = uuid.uuid4()

        for i in range(5):
            request = self._create_request(
                client_id,
                KMSRequestType.RENEWAL if i > 0 else KMSRequestType.REQUEST,
            )
            response = parser.generate_response(request)

            assert response.response_code == KMSResponseCode.SUCCESS
            time.sleep(0.05)

        session = parser.active_sessions[client_id]
        assert session.renewal_count >= 4

    def _create_request(
        self, client_id: uuid.UUID, request_type: int
    ) -> KMSActivationRequest:
        """Helper to create request with specific type."""
        return KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=request_type,
            client_machine_id=client_id,
            application_id=uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
            sku_id=uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588"),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="CLIENT", fqdn="client.local", workgroup="WORKGROUP"
            ),
            version_info=KMSVersionInfo(
                major=10,
                minor=0,
                build=19045,
                revision=0,
                product_type=KMSApplicationType.WINDOWS_10,
            ),
        )


class TestEdgeCases:
    """Test edge cases: ADBA, MAK fallback, SLMGR interactions."""

    def test_adba_token_generation_for_domain_clients(self) -> None:
        """ADBA (Active Directory Based Activation) token generation works."""
        parser = KMSParser()

        domain_client_request = KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=uuid.uuid4(),
            application_id=uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
            sku_id=uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588"),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="DC-JOINED-01",
                fqdn="dc-joined-01.corporation.local",
                workgroup="",
                domain="CORPORATION",
            ),
            version_info=KMSVersionInfo(
                major=10,
                minor=0,
                build=19045,
                revision=0,
                product_type=KMSApplicationType.WINDOWS_10,
            ),
        )

        response = parser.generate_response(domain_client_request)

        assert response.response_code == KMSResponseCode.SUCCESS
        assert hasattr(response, "adba_token")
        if response.adba_token:
            assert len(response.adba_token) > 0

    def test_mak_fallback_detection(self) -> None:
        """MAK (Multiple Activation Key) fallback is detected."""
        parser = KMSParser()

        mak_key = "12345-67890-12345-67890-12345"
        is_mak = parser.is_mak_key(mak_key)

        assert is_mak is True

        gvlk_key = "W269N-WFGWX-YVC9B-4J6C9-T83GX"
        is_gvlk_not_mak = parser.is_mak_key(gvlk_key)

        assert is_gvlk_not_mak is False

    def test_slmgr_vbs_command_emulation(self) -> None:
        """SLMGR.vbs command emulation for activation status."""
        parser = KMSParser()

        client_id = uuid.uuid4()

        request = KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=client_id,
            application_id=uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
            sku_id=uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588"),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="SLMGR-TEST", fqdn="slmgr.local", workgroup="WORKGROUP"
            ),
            version_info=KMSVersionInfo(
                major=10,
                minor=0,
                build=19045,
                revision=0,
                product_type=KMSApplicationType.WINDOWS_10,
            ),
        )

        parser.generate_response(request)

        status_info = parser.get_slmgr_status(client_id)

        assert "License Status" in status_info
        assert "KMS machine name" in status_info
        assert status_info["License Status"] == "Licensed"

    def test_kms_host_discovery_via_dns(self) -> None:
        """KMS host discovery via DNS SRV records."""
        parser = KMSParser()

        dns_srv_record = parser.generate_dns_srv_record()

        assert "_vlmcs._tcp" in dns_srv_record
        assert "1688" in dns_srv_record

    def test_offline_activation_id_generation(self) -> None:
        """Offline activation Installation ID generation."""
        parser = KMSParser()

        installation_id = parser.generate_installation_id(
            product_key="W269N-WFGWX-YVC9B-4J6C9-T83GX",
            hardware_hash=secrets.token_bytes(32),
        )

        assert len(installation_id) > 0
        assert all(c.isdigit() or c == "-" for c in installation_id)

    def test_confirmation_id_validation(self) -> None:
        """Offline activation Confirmation ID validation."""
        parser = KMSParser()

        installation_id = parser.generate_installation_id(
            product_key="W269N-WFGWX-YVC9B-4J6C9-T83GX",
            hardware_hash=secrets.token_bytes(32),
        )

        confirmation_id = parser.generate_confirmation_id(installation_id)

        assert len(confirmation_id) > 0
        assert all(c.isdigit() or c == "-" for c in confirmation_id)

        is_valid = parser.validate_confirmation_id(installation_id, confirmation_id)
        assert is_valid is True

    def test_rearm_count_tracking(self) -> None:
        """Windows rearm count tracking."""
        parser = KMSParser()

        client_id = uuid.uuid4()

        request = KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=client_id,
            application_id=uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
            sku_id=uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588"),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="REARM-TEST", fqdn="rearm.local", workgroup="WORKGROUP"
            ),
            version_info=KMSVersionInfo(
                major=10,
                minor=0,
                build=19045,
                revision=0,
                product_type=KMSApplicationType.WINDOWS_10,
            ),
        )

        parser.generate_response(request)

        rearm_count = parser.get_rearm_count(client_id)
        assert rearm_count >= 0
        assert rearm_count <= 6

    def test_grace_period_extension(self) -> None:
        """Grace period extension for KMS clients."""
        parser = KMSParser()

        client_id = uuid.uuid4()

        request = KMSActivationRequest(
            protocol_version=KMSProtocolVersion.VERSION_6_0,
            request_type=KMSRequestType.REQUEST,
            client_machine_id=client_id,
            application_id=uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
            sku_id=uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588"),
            license_state=1,
            timestamp=int(time.time()),
            client_info=KMSClientInfo(
                hostname="GRACE-TEST", fqdn="grace.local", workgroup="WORKGROUP"
            ),
            version_info=KMSVersionInfo(
                major=10,
                minor=0,
                build=19045,
                revision=0,
                product_type=KMSApplicationType.WINDOWS_10,
            ),
        )

        response = parser.generate_response(request)

        grace_period = parser.get_grace_period_remaining(client_id)
        assert grace_period > 0
        assert grace_period <= (180 * 24 * 3600)

    def test_invalid_product_key_rejected(self) -> None:
        """Invalid product keys are rejected."""
        parser = KMSParser()

        invalid_key = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
        is_valid = parser.validate_gvlk(invalid_key, KMSApplicationType.WINDOWS_10)

        assert is_valid is False

    def test_kms_host_priority_handling(self) -> None:
        """KMS host priority handling for load balancing."""
        parser = KMSParser(host_info=KMSHostInfo(priority=10))

        assert parser.host_info.priority == 10

    def test_kms_host_weight_handling(self) -> None:
        """KMS host weight handling for load distribution."""
        parser = KMSParser(host_info=KMSHostInfo(weight=100))

        assert parser.host_info.weight == 100
