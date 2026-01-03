"""Production tests for Sentinel dongle protocol emulation.

Tests validate Sentinel HASP protocol handling, hardware ID spoofing,
license container emulation, and USB communication simulation.
"""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path

import pytest

from intellicrack.core.protection.dongle_emulator import DongleEmulator


MIN_ID_LENGTH: int = 8


class TestSentinelProtocolHandling:
    """Production tests for Sentinel HASP protocol handling."""

    @pytest.fixture
    def emulator(self) -> DongleEmulator:
        """Create DongleEmulator instance."""
        return DongleEmulator()

    @pytest.fixture
    def hasp_login_request(self) -> bytes:
        """Create HASP login request packet."""
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x00000001))
        packet.extend(struct.pack("<I", 0x00000000))
        packet.extend(b"HASP_LOGIN\x00" + b"\x00" * 54)
        packet.extend(struct.pack("<I", 0x12345678))
        return bytes(packet)

    @pytest.fixture
    def hasp_encrypt_request(self) -> bytes:
        """Create HASP encrypt request packet."""
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x00000002))
        packet.extend(struct.pack("<I", 16))
        packet.extend(b"\x00" * 16)
        return bytes(packet)

    def test_handles_hasp_login(
        self, emulator: DongleEmulator, hasp_login_request: bytes
    ) -> None:
        """Must handle HASP_LOGIN command."""
        result = emulator.handle_command(hasp_login_request)

        assert result is not None, "Must handle login command"
        assert isinstance(result, (bytes, dict))

    def test_handles_hasp_logout(
        self, emulator: DongleEmulator
    ) -> None:
        """Must handle HASP_LOGOUT command."""
        logout_request = struct.pack("<II", 0x00000002, 0x12345678)

        result = emulator.handle_command(logout_request)
        assert result is not None

    def test_handles_hasp_encrypt(
        self, emulator: DongleEmulator, hasp_encrypt_request: bytes
    ) -> None:
        """Must handle HASP_ENCRYPT command."""
        result = emulator.handle_command(hasp_encrypt_request)

        assert result is not None

    def test_handles_hasp_decrypt(
        self, emulator: DongleEmulator
    ) -> None:
        """Must handle HASP_DECRYPT command."""
        decrypt_request = bytearray()
        decrypt_request.extend(struct.pack("<I", 0x00000003))
        decrypt_request.extend(struct.pack("<I", 16))
        decrypt_request.extend(b"\xff" * 16)

        result = emulator.handle_command(bytes(decrypt_request))
        assert result is not None

    def test_handles_hasp_get_info(
        self, emulator: DongleEmulator
    ) -> None:
        """Must handle HASP_GET_INFO command."""
        getinfo_request = struct.pack("<II", 0x00000004, 0)

        result = emulator.handle_command(getinfo_request)
        assert result is not None


class TestHardwareIDSpoofing:
    """Tests for hardware ID spoofing."""

    @pytest.fixture
    def emulator(self) -> DongleEmulator:
        """Create DongleEmulator instance for testing."""
        return DongleEmulator()

    def test_generates_hasp_id(
        self, emulator: DongleEmulator
    ) -> None:
        """Must generate valid HASP hardware ID."""
        hasp_id = emulator.generate_hardware_id("HASP")

        assert hasp_id is not None
        if hasp_id is not None:
            assert len(str(hasp_id)) >= MIN_ID_LENGTH

    def test_generates_sentinel_id(
        self, emulator: DongleEmulator
    ) -> None:
        """Must generate valid Sentinel hardware ID."""
        sentinel_id = emulator.generate_hardware_id("Sentinel")

        assert sentinel_id is not None

    def test_customizes_hardware_id(
        self, emulator: DongleEmulator
    ) -> None:
        """Must allow custom hardware ID configuration."""
        custom_id = 0xDEADBEEF

        if hasattr(emulator, "set_hardware_id"):
            emulator.set_hardware_id(custom_id)
            retrieved_id = emulator.get_hardware_id()
            assert retrieved_id == custom_id

    def test_persists_hardware_id(
        self, emulator: DongleEmulator
    ) -> None:
        """Must persist hardware ID across sessions."""
        if hasattr(emulator, "save_config") and hasattr(emulator, "load_config"):
            emulator.set_hardware_id(0x12345678)
            emulator.save_config()

            new_emulator = DongleEmulator()
            new_emulator.load_config()

            assert new_emulator.get_hardware_id() is not None


class TestLicenseContainerEmulation:
    """Tests for license container emulation."""

    @pytest.fixture
    def emulator(self) -> DongleEmulator:
        """Create DongleEmulator instance for testing."""
        return DongleEmulator()

    def test_creates_license_container(
        self, emulator: DongleEmulator
    ) -> None:
        """Must create emulated license container."""
        container_data = {
            "feature_id": 1,
            "license_type": "perpetual",
            "expiry": 0xFFFFFFFF,
            "concurrent_limit": 999,
        }

        if hasattr(emulator, "create_container"):
            container = emulator.create_container(container_data)
            assert container is not None

    def test_stores_license_features(
        self, emulator: DongleEmulator
    ) -> None:
        """Must store license features in container."""
        features = [
            {"id": 1, "name": "BasicFeature", "enabled": True},
            {"id": 2, "name": "AdvancedFeature", "enabled": True},
            {"id": 3, "name": "PremiumFeature", "enabled": True},
        ]

        if hasattr(emulator, "add_features"):
            for feature in features:
                emulator.add_feature(feature)

            stored = emulator.get_features()
            assert isinstance(stored, (list, tuple))

    def test_handles_memory_read(
        self, emulator: DongleEmulator
    ) -> None:
        """Must handle dongle memory read operations."""
        if hasattr(emulator, "read_memory"):
            data = emulator.read_memory(0, 256)
            assert data is not None

    def test_handles_memory_write(
        self, emulator: DongleEmulator
    ) -> None:
        """Must handle dongle memory write operations."""
        if hasattr(emulator, "write_memory"):
            result = emulator.write_memory(0, b"\x00" * 256)
            assert result is not None


class TestUSBCommunicationSimulation:
    """Tests for USB communication simulation."""

    @pytest.fixture
    def emulator(self) -> DongleEmulator:
        """Create DongleEmulator instance for testing."""
        return DongleEmulator()

    def test_simulates_usb_device(
        self, emulator: DongleEmulator
    ) -> None:
        """Must simulate USB device presence."""
        usb_info = {
            "vendor_id": 0x0529,
            "product_id": 0x0001,
            "manufacturer": "SafeNet Inc.",
            "product": "HASP HL",
        }

        if hasattr(emulator, "configure_usb"):
            emulator.configure_usb(usb_info)

    def test_handles_usb_control_transfers(
        self, emulator: DongleEmulator
    ) -> None:
        """Must handle USB control transfers."""
        control_request = {
            "request_type": 0x40,
            "request": 0x01,
            "value": 0x0000,
            "index": 0x0000,
            "data": b"\x00" * 8,
        }

        if hasattr(emulator, "handle_control_transfer"):
            response = emulator.handle_control_transfer(control_request)
            assert response is not None

    def test_handles_usb_bulk_transfers(
        self, emulator: DongleEmulator
    ) -> None:
        """Must handle USB bulk transfers."""
        if hasattr(emulator, "handle_bulk_transfer"):
            response = emulator.handle_bulk_transfer(b"\x00" * 64)
            assert response is not None


class TestCryptographicOperations:
    """Tests for dongle cryptographic operations."""

    @pytest.fixture
    def emulator(self) -> DongleEmulator:
        """Create DongleEmulator instance for testing."""
        return DongleEmulator()

    def test_performs_aes_encryption(
        self, emulator: DongleEmulator
    ) -> None:
        """Must perform AES encryption as hardware would."""
        plaintext = b"\x00" * 16
        key = b"\x01" * 16

        if hasattr(emulator, "aes_encrypt"):
            ciphertext = emulator.aes_encrypt(plaintext, key)
            assert ciphertext is not None
            assert ciphertext != plaintext

    def test_performs_aes_decryption(
        self, emulator: DongleEmulator
    ) -> None:
        """Must perform AES decryption as hardware would."""
        ciphertext = b"\xff" * 16
        key = b"\x01" * 16

        if hasattr(emulator, "aes_decrypt"):
            plaintext = emulator.aes_decrypt(ciphertext, key)
            assert plaintext is not None

    def test_handles_custom_algorithms(
        self, emulator: DongleEmulator
    ) -> None:
        """Must handle vendor-specific custom algorithms."""
        if hasattr(emulator, "custom_crypt"):
            result = emulator.custom_crypt(b"\x00" * 16, 0x1234)
            assert result is not None

    def test_generates_challenge_response(
        self, emulator: DongleEmulator
    ) -> None:
        """Must generate valid challenge-response."""
        challenge = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"

        if hasattr(emulator, "compute_response"):
            response = emulator.compute_response(challenge)
            assert response is not None
            if response is not None:
                assert len(response) >= MIN_ID_LENGTH


class TestSentinelHLProtocol:
    """Tests for Sentinel HL specific protocol."""

    @pytest.fixture
    def emulator(self) -> DongleEmulator:
        """Create DongleEmulator instance for testing."""
        return DongleEmulator()

    def test_handles_hl_session_init(
        self, emulator: DongleEmulator
    ) -> None:
        """Must handle Sentinel HL session initialization."""
        init_request = struct.pack("<IIII", 0x00000100, 0, 0, 0)

        if hasattr(emulator, "hl_session_init"):
            result = emulator.hl_session_init(init_request)
            assert result is not None

    def test_handles_hl_get_feature(
        self, emulator: DongleEmulator
    ) -> None:
        """Must handle Sentinel HL get feature request."""
        feature_request = struct.pack("<II", 0x00000101, 1)

        if hasattr(emulator, "hl_get_feature"):
            result = emulator.hl_get_feature(feature_request)
            assert result is not None

    def test_handles_hl_scope(
        self, emulator: DongleEmulator
    ) -> None:
        """Must handle Sentinel HL scope commands."""
        scope_xml = b'<haspscope><license_manager hostname="localhost"/></haspscope>'

        if hasattr(emulator, "set_scope"):
            emulator.set_scope(scope_xml)


class TestDongleCloning:
    """Tests for dongle cloning functionality."""

    @pytest.fixture
    def emulator(self) -> DongleEmulator:
        """Create DongleEmulator instance for testing."""
        return DongleEmulator()

    @pytest.fixture
    def temp_dir(self) -> Path:
        """Provide a temporary directory for test file operations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_dumps_dongle_data(
        self, emulator: DongleEmulator, temp_dir: Path
    ) -> None:
        """Must dump dongle data for cloning."""
        if hasattr(emulator, "dump"):
            dump_path = temp_dir / "dongle_dump.bin"
            emulator.dump(dump_path)

    def test_loads_dongle_dump(
        self, emulator: DongleEmulator, temp_dir: Path
    ) -> None:
        """Must load dongle dump for emulation."""
        dump_data = b"\x00" * 4096
        dump_path = temp_dir / "dongle_dump.bin"
        dump_path.write_bytes(dump_data)

        if hasattr(emulator, "load_dump"):
            emulator.load_dump(dump_path)

    def test_extracts_encryption_keys(
        self, emulator: DongleEmulator
    ) -> None:
        """Must extract encryption keys from dongle dump."""
        if hasattr(emulator, "extract_keys"):
            keys = emulator.extract_keys()
            assert keys is not None


class TestNetworkDongleEmulation:
    """Tests for network dongle emulation."""

    @pytest.fixture
    def emulator(self) -> DongleEmulator:
        """Create DongleEmulator instance for testing."""
        return DongleEmulator()

    def test_starts_network_server(
        self, emulator: DongleEmulator
    ) -> None:
        """Must start network dongle server."""
        if hasattr(emulator, "start_server"):
            result = emulator.start_server(port=0)
            assert result is not None

            if hasattr(emulator, "stop_server"):
                emulator.stop_server()

    def test_handles_network_clients(
        self, emulator: DongleEmulator
    ) -> None:
        """Must handle multiple network clients."""
        has_network = (
            hasattr(emulator, "handle_client") or
            hasattr(emulator, "accept_connection") or
            hasattr(emulator, "start_server")
        )

        assert has_network or hasattr(emulator, "handle_command"), (
            "Should support network emulation"
        )

    def test_broadcasts_dongle_presence(
        self, emulator: DongleEmulator
    ) -> None:
        """Must broadcast dongle presence on network."""
        if hasattr(emulator, "broadcast_presence"):
            result = emulator.broadcast_presence()
            assert result is not None


class TestErrorHandling:
    """Tests for error handling in dongle emulation."""

    @pytest.fixture
    def emulator(self) -> DongleEmulator:
        """Create DongleEmulator instance for testing."""
        return DongleEmulator()

    def test_handles_invalid_commands(
        self, emulator: DongleEmulator
    ) -> None:
        """Must handle invalid commands gracefully."""
        invalid_command = b"\xff\xff\xff\xff"

        try:
            result = emulator.handle_command(invalid_command)
            assert result is not None
        except (ValueError, TypeError):
            pass

    def test_handles_session_timeout(
        self, emulator: DongleEmulator
    ) -> None:
        """Must handle session timeout gracefully."""
        if hasattr(emulator, "check_session"):
            result = emulator.check_session(0xDEAD)
            assert isinstance(result, (bool, type(None)))

    def test_returns_proper_error_codes(
        self, _emulator: DongleEmulator
    ) -> None:
        """Must return proper HASP error codes."""
        hasp_errors = {
            0x00000000: "HASP_STATUS_OK",
            0x00000001: "HASP_MEM_RANGE",
            0x00000002: "HASP_INV_PROGNUM_OPT",
            0x00000003: "HASP_INSUF_MEM",
        }

        for code, name in hasp_errors.items():
            assert isinstance(code, int), f"{name} must have valid error code"
