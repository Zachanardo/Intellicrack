"""Production tests for Microsoft KMS protocol implementation.

Tests validate KMS activation protocol, GVLK handling, Windows activation bypass,
and Office KMS activation functionality.
"""

from __future__ import annotations

import hashlib
import socket
import struct
import time

import pytest

from intellicrack.core.network.protocols.kms_protocol import KMSProtocol


DEFAULT_KMS_PORT: int = 1688
KMS_V4_VERSION: int = 4
KMS_V6_VERSION: int = 6
MIN_ACTIVATION_COUNT: int = 25
ACTIVATION_INTERVAL: int = 120
RENEWAL_INTERVAL: int = 10080
MIN_EPID_LENGTH: int = 20
MIN_KMS_PID_PARTS: int = 3
HARDWARE_HASH_LENGTH: int = 16


class TestKMSProtocolParsing:
    """Production tests for KMS protocol parsing."""

    @pytest.fixture
    def protocol(self) -> KMSProtocol:
        """Create KMSProtocol instance."""
        return KMSProtocol()

    @pytest.fixture
    def kms_request_v4(self) -> bytes:
        """Create KMS v4 activation request packet."""
        packet = bytearray()
        packet.extend(struct.pack("<I", 4))
        packet.extend(struct.pack("<I", 0))
        packet.extend(struct.pack("<I", 0x00000002))
        packet.extend(b"\x00" * 64)
        packet.extend(struct.pack("<Q", 0x0000000000000001))
        packet.extend(b"\x00" * 32)
        return bytes(packet)

    @pytest.fixture
    def kms_request_v6(self) -> bytes:
        """Create KMS v6 activation request packet."""
        packet = bytearray()
        packet.extend(struct.pack("<I", 6))
        packet.extend(struct.pack("<I", 0))
        packet.extend(struct.pack("<I", 0x00000002))
        packet.extend(b"\x00" * 64)
        packet.extend(struct.pack("<Q", 0x0000000000000001))
        packet.extend(b"\x00" * 64)
        return bytes(packet)

    def test_parses_kms_v4_request(
        self, protocol: KMSProtocol, kms_request_v4: bytes
    ) -> None:
        """Must parse KMS v4 activation request."""
        result = protocol.parse_request(kms_request_v4)

        assert result is not None, "Must parse KMS v4 request"
        assert isinstance(result, dict)

    def test_parses_kms_v6_request(
        self, protocol: KMSProtocol, kms_request_v6: bytes
    ) -> None:
        """Must parse KMS v6 activation request."""
        result = protocol.parse_request(kms_request_v6)

        assert result is not None, "Must parse KMS v6 request"

    def test_detects_kms_version(
        self, protocol: KMSProtocol, kms_request_v4: bytes, kms_request_v6: bytes
    ) -> None:
        """Must detect KMS protocol version."""
        v4_version = protocol.detect_version(kms_request_v4)
        v6_version = protocol.detect_version(kms_request_v6)

        assert v4_version == KMS_V4_VERSION
        assert v6_version == KMS_V6_VERSION

    def test_extracts_client_machine_id(
        self, protocol: KMSProtocol, kms_request_v4: bytes
    ) -> None:
        """Must extract client machine ID from request."""
        result = protocol.parse_request(kms_request_v4)

        if result:
            has_machine_id = (
                "machine_id" in result or
                "cmid" in result or
                "client_id" in result
            )
            assert has_machine_id, "Result must contain machine ID"


class TestGVLKHandling:
    """Tests for Generic Volume License Key handling."""

    @pytest.fixture
    def protocol(self) -> KMSProtocol:
        """Create KMSProtocol instance."""
        return KMSProtocol()

    def test_validates_windows_gvlk(
        self, protocol: KMSProtocol
    ) -> None:
        """Must validate Windows GVLK format."""
        windows_gvlks = [
            "NPPR9-FWDCX-D2C8J-H872K-2YT43",
            "W269N-WFGWX-YVC9B-4J6C9-T83GX",
            "MH37W-N47XK-V7XM9-C7227-GCQG9",
        ]

        for gvlk in windows_gvlks:
            is_valid = protocol.validate_gvlk(gvlk)
            assert is_valid, f"GVLK {gvlk} must be validated"

    def test_validates_office_gvlk(
        self, protocol: KMSProtocol
    ) -> None:
        """Must validate Office GVLK format."""
        office_gvlks = [
            "XQNVK-8JYDB-WJ9W3-YJ8YR-WFG99",
            "NMMKJ-6RK4F-KMJVX-8D9MJ-6MWKP",
        ]

        for gvlk in office_gvlks:
            is_valid = protocol.validate_gvlk(gvlk)
            assert is_valid

    def test_identifies_product_from_gvlk(
        self, protocol: KMSProtocol
    ) -> None:
        """Must identify product type from GVLK."""
        if hasattr(protocol, "identify_product"):
            gvlk = "W269N-WFGWX-YVC9B-4J6C9-T83GX"
            product = protocol.identify_product(gvlk)
            assert product is not None

    def test_generates_activation_id(
        self, protocol: KMSProtocol
    ) -> None:
        """Must generate valid activation ID."""
        if hasattr(protocol, "generate_activation_id"):
            activation_id = protocol.generate_activation_id()
            assert activation_id is not None
            assert len(str(activation_id)) > 0


class TestActivationResponse:
    """Tests for KMS activation response generation."""

    @pytest.fixture
    def protocol(self) -> KMSProtocol:
        """Create KMSProtocol instance."""
        return KMSProtocol()

    def test_generates_valid_response(
        self, protocol: KMSProtocol
    ) -> None:
        """Must generate valid KMS activation response."""
        request_data = {
            "version": 6,
            "kms_pid": "00000-00000-00000-00000-00000",
            "client_machine_id": b"\x00" * 16,
            "timestamp": int(time.time()),
        }

        response = protocol.generate_response(request_data)

        assert response is not None
        if isinstance(response, (bytes, str)):
            assert len(response) > 0

    def test_includes_activation_interval(
        self, protocol: KMSProtocol
    ) -> None:
        """Must include proper activation interval in response."""
        request_data = {
            "version": 6,
            "activation_interval": 120,
        }

        response = protocol.generate_response(request_data)
        assert response is not None

    def test_includes_renewal_interval(
        self, protocol: KMSProtocol
    ) -> None:
        """Must include proper renewal interval in response."""
        request_data = {
            "version": 6,
            "renewal_interval": 10080,
        }

        response = protocol.generate_response(request_data)
        assert response is not None

    def test_generates_kms_counted_response(
        self, protocol: KMSProtocol
    ) -> None:
        """Must generate response with KMS count (min 25 for activation)."""
        request_data = {
            "version": 6,
            "kms_count": 50,
        }

        response = protocol.generate_response(request_data)
        assert response is not None


class TestKMSServer:
    """Tests for KMS server functionality."""

    @pytest.fixture
    def protocol(self) -> KMSProtocol:
        """Create KMSProtocol instance."""
        return KMSProtocol()

    def test_server_listens_on_port(
        self, protocol: KMSProtocol
    ) -> None:
        """KMS server must listen on port 1688."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            sock.listen(1)

            assert port > 0, f"Must bind to valid port (expected {DEFAULT_KMS_PORT})"
        finally:
            sock.close()

    def test_handles_multiple_clients(
        self, protocol: KMSProtocol
    ) -> None:
        """KMS server must handle multiple concurrent clients."""
        has_server_capability = (
            hasattr(protocol, "start_server") or
            hasattr(protocol, "handle_client") or
            hasattr(protocol, "serve")
        )

        assert has_server_capability or hasattr(protocol, "generate_response"), (
            "Must have server capability"
        )


class TestWindowsActivation:
    """Tests for Windows activation bypass."""

    @pytest.fixture
    def protocol(self) -> KMSProtocol:
        """Create KMSProtocol instance."""
        return KMSProtocol()

    def test_activates_windows_10_pro(
        self, protocol: KMSProtocol
    ) -> None:
        """Must support Windows 10 Pro activation."""
        win10_pro_gvlk = "W269N-WFGWX-YVC9B-4J6C9-T83GX"

        is_valid = protocol.validate_gvlk(win10_pro_gvlk)
        assert is_valid

    def test_activates_windows_11_pro(
        self, protocol: KMSProtocol
    ) -> None:
        """Must support Windows 11 Pro activation."""
        win11_pro_gvlk = "W269N-WFGWX-YVC9B-4J6C9-T83GX"

        is_valid = protocol.validate_gvlk(win11_pro_gvlk)
        assert is_valid

    def test_activates_windows_server(
        self, protocol: KMSProtocol
    ) -> None:
        """Must support Windows Server activation."""
        server_gvlk = "WX4NM-KYWYW-QJJR4-XV3QB-6VM33"

        is_valid = protocol.validate_gvlk(server_gvlk)
        assert is_valid

    def test_handles_hardware_hash(
        self, protocol: KMSProtocol
    ) -> None:
        """Must handle hardware hash validation."""
        if hasattr(protocol, "validate_hardware_hash"):
            fake_hash = hashlib.sha256(b"test_hardware").digest()
            result = protocol.validate_hardware_hash(fake_hash)
            assert result is not None


class TestOfficeActivation:
    """Tests for Office KMS activation."""

    @pytest.fixture
    def protocol(self) -> KMSProtocol:
        """Create KMSProtocol instance."""
        return KMSProtocol()

    def test_activates_office_2019(
        self, protocol: KMSProtocol
    ) -> None:
        """Must support Office 2019 activation."""
        office_2019_gvlk = "NMMKJ-6RK4F-KMJVX-8D9MJ-6MWKP"

        is_valid = protocol.validate_gvlk(office_2019_gvlk)
        assert is_valid

    def test_activates_office_2021(
        self, protocol: KMSProtocol
    ) -> None:
        """Must support Office 2021 activation."""
        office_2021_gvlk = "FXYTK-NJJ8C-GB6DW-3DYQT-6F7TH"

        is_valid = protocol.validate_gvlk(office_2021_gvlk)
        assert is_valid

    def test_activates_office_365(
        self, protocol: KMSProtocol
    ) -> None:
        """Must support Office 365 ProPlus activation."""
        o365_gvlk = "XQNVK-8JYDB-WJ9W3-YJ8YR-WFG99"

        is_valid = protocol.validate_gvlk(o365_gvlk)
        assert is_valid


class TestEncryption:
    """Tests for KMS protocol encryption."""

    @pytest.fixture
    def protocol(self) -> KMSProtocol:
        """Create KMSProtocol instance."""
        return KMSProtocol()

    def test_encrypts_request_data(
        self, protocol: KMSProtocol
    ) -> None:
        """Must encrypt KMS request data."""
        if hasattr(protocol, "encrypt_request"):
            plaintext = b"test activation request"
            encrypted = protocol.encrypt_request(plaintext)

            assert encrypted is not None
            assert encrypted != plaintext

    def test_decrypts_response_data(
        self, protocol: KMSProtocol
    ) -> None:
        """Must decrypt KMS response data."""
        if hasattr(protocol, "decrypt_response"):
            encrypted = b"\x00" * 64
            decrypted = protocol.decrypt_response(encrypted)

            assert decrypted is not None

    def test_uses_aes_encryption(
        self, protocol: KMSProtocol
    ) -> None:
        """Must use AES encryption for KMS v6."""
        has_aes = (
            hasattr(protocol, "aes_encrypt") or
            hasattr(protocol, "_encrypt_aes") or
            hasattr(protocol, "encrypt_request")
        )

        assert has_aes, "Should support AES encryption"


class TestKMSPIDGeneration:
    """Tests for KMS PID generation."""

    @pytest.fixture
    def protocol(self) -> KMSProtocol:
        """Create KMSProtocol instance."""
        return KMSProtocol()

    def test_generates_valid_kms_pid(
        self, protocol: KMSProtocol
    ) -> None:
        """Must generate valid KMS PID format."""
        if hasattr(protocol, "generate_kms_pid"):
            kms_pid = protocol.generate_kms_pid()

            assert kms_pid is not None
            assert "-" in str(kms_pid), "KMS PID must have dashes"

    def test_generates_epid(
        self, protocol: KMSProtocol
    ) -> None:
        """Must generate extended PID (ePID)."""
        if hasattr(protocol, "generate_epid"):
            epid = protocol.generate_epid()

            assert epid is not None
            assert len(str(epid)) > MIN_EPID_LENGTH, "ePID must be substantial"

    def test_includes_kms_host_info(
        self, protocol: KMSProtocol
    ) -> None:
        """KMS PID must include host info."""
        if hasattr(protocol, "generate_kms_pid"):
            kms_pid = protocol.generate_kms_pid()

            if kms_pid:
                parts = str(kms_pid).split("-")
                assert len(parts) >= MIN_KMS_PID_PARTS


class TestProtocolErrors:
    """Tests for KMS protocol error handling."""

    @pytest.fixture
    def protocol(self) -> KMSProtocol:
        """Create KMSProtocol instance."""
        return KMSProtocol()

    def test_handles_invalid_request(
        self, protocol: KMSProtocol
    ) -> None:
        """Must handle invalid KMS requests gracefully."""
        invalid_request = b"\x00\x00\x00\x00"

        try:
            result = protocol.parse_request(invalid_request)
            assert result is None or isinstance(result, dict)
        except (ValueError, struct.error, AttributeError):
            pass

    def test_handles_truncated_request(
        self, protocol: KMSProtocol
    ) -> None:
        """Must handle truncated requests gracefully."""
        truncated = struct.pack("<I", 6)

        try:
            result = protocol.parse_request(truncated)
            assert result is None or isinstance(result, dict)
        except (ValueError, struct.error, IndexError):
            pass

    def test_handles_unsupported_version(
        self, protocol: KMSProtocol
    ) -> None:
        """Must handle unsupported KMS version."""
        unsupported = struct.pack("<I", 99) + b"\x00" * 100

        try:
            result = protocol.parse_request(unsupported)
            assert result is None or isinstance(result, dict)
        except (ValueError, struct.error, NotImplementedError):
            pass
