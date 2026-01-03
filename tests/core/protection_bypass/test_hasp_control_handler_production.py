"""Production tests for HASP control handler zero buffer issue (lines 926-953).

Tests validate that HASP USB control transfer handler properly implements:
- Command parsing and response generation
- Realistic memory contents from emulated dongle
- Encryption/decryption with actual cryptography
- Session state management with proper handles
- Support for HASP4/HL/SL command variants
- Multi-feature and network dongle scenarios

NO mocks or stubs - tests MUST validate real functionality against actual HASP protocol.
"""

import struct
from typing import Any

import pytest

from intellicrack.core.protection_bypass.dongle_emulator import (
    CryptoEngine,
    HardwareDongleEmulator,
    HASPDongle,
    HASPStatus,
    USBDescriptor,
    USBEmulator,
)

try:
    from Crypto.Cipher import AES

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class TestHASPControlHandlerProduction:
    """Production tests for HASP control handler functionality."""

    @pytest.fixture
    def emulator(self) -> HardwareDongleEmulator:
        """Create hardware dongle emulator with HASP support."""
        emu = HardwareDongleEmulator()
        emu.activate_dongle_emulation(["HASP"])
        return emu

    @pytest.fixture
    def hasp_dongle(self, emulator: HardwareDongleEmulator) -> HASPDongle:
        """Get first HASP dongle from emulator."""
        assert len(emulator.hasp_dongles) > 0
        return next(iter(emulator.hasp_dongles.values()))

    def test_control_handler_returns_valid_hasp_id(self, emulator: HardwareDongleEmulator, hasp_dongle: HASPDongle) -> None:
        """Control handler returns actual HASP ID, not zero buffer."""
        response = emulator._hasp_control_handler(wValue=1, wIndex=0, data=b"")

        assert len(response) >= 4
        hasp_id = struct.unpack("<I", response[:4])[0]
        assert hasp_id == hasp_dongle.hasp_id
        assert hasp_id != 0
        assert response != b"\x00" * 64

    def test_control_handler_returns_vendor_and_feature_codes(self, emulator: HardwareDongleEmulator, hasp_dongle: HASPDongle) -> None:
        """Control handler returns valid vendor and feature codes, not zeros."""
        response = emulator._hasp_control_handler(wValue=2, wIndex=0, data=b"")

        assert len(response) >= 4
        vendor_code, feature_id = struct.unpack("<HH", response[:4])
        assert vendor_code == hasp_dongle.vendor_code
        assert feature_id == hasp_dongle.feature_id
        assert vendor_code != 0
        assert feature_id != 0
        assert response != b"\x00" * 64

    def test_control_handler_returns_seed_code(self, emulator: HardwareDongleEmulator, hasp_dongle: HASPDongle) -> None:
        """Control handler returns actual seed code, not zero buffer."""
        response = emulator._hasp_control_handler(wValue=3, wIndex=0, data=b"")

        assert len(response) == len(hasp_dongle.seed_code)
        assert response == hasp_dongle.seed_code
        assert response != b"\x00" * len(hasp_dongle.seed_code)
        assert len(set(response)) > 1

    def test_control_handler_with_no_dongles_returns_zeros(self) -> None:
        """Control handler returns zeros only when no dongles exist."""
        emulator = HardwareDongleEmulator()

        response = emulator._hasp_control_handler(wValue=1, wIndex=0, data=b"")

        assert response == b"\x00" * 64

    def test_control_handler_unknown_wvalue_returns_zeros(self, emulator: HardwareDongleEmulator) -> None:
        """Control handler returns zeros for unknown wValue commands."""
        response = emulator._hasp_control_handler(wValue=99, wIndex=0, data=b"")

        assert response == b"\x00" * 64

    def test_bulk_out_handler_parses_login_command(self, emulator: HardwareDongleEmulator, hasp_dongle: HASPDongle) -> None:
        """Bulk OUT handler properly parses and processes login command."""
        login_cmd = struct.pack("<I", 1)
        login_data = struct.pack("<HH", hasp_dongle.vendor_code, hasp_dongle.feature_id)
        request = login_cmd + login_data

        response = emulator._hasp_bulk_out_handler(request)

        assert len(response) >= 8
        status, session_handle = struct.unpack("<II", response[:8])
        assert status == HASPStatus.HASP_STATUS_OK
        assert session_handle != 0
        assert hasp_dongle.logged_in is True

    def test_bulk_out_handler_parses_logout_command(self, emulator: HardwareDongleEmulator, hasp_dongle: HASPDongle) -> None:
        """Bulk OUT handler properly parses and processes logout command."""
        login_cmd = struct.pack("<I", 1)
        login_data = struct.pack("<HH", hasp_dongle.vendor_code, hasp_dongle.feature_id)
        login_response = emulator._hasp_bulk_out_handler(login_cmd + login_data)
        _, session_handle = struct.unpack("<II", login_response[:8])

        logout_cmd = struct.pack("<I", 2)
        logout_data = struct.pack("<I", session_handle)
        logout_response = emulator._hasp_bulk_out_handler(logout_cmd + logout_data)

        status = struct.unpack("<I", logout_response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK
        assert hasp_dongle.logged_in is False

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Requires PyCryptodome")
    def test_bulk_out_handler_encrypts_with_real_crypto(self, emulator: HardwareDongleEmulator, hasp_dongle: HASPDongle) -> None:
        """Bulk OUT handler performs real AES encryption, not placeholders."""
        login_cmd = struct.pack("<I", 1)
        login_data = struct.pack("<HH", hasp_dongle.vendor_code, hasp_dongle.feature_id)
        login_response = emulator._hasp_bulk_out_handler(login_cmd + login_data)
        _, session_handle = struct.unpack("<II", login_response[:8])

        plaintext = b"TestData1234567890ABCDEF123456"
        encrypt_cmd = struct.pack("<I", 3)
        encrypt_data = struct.pack("<II", session_handle, len(plaintext)) + plaintext
        encrypt_response = emulator._hasp_bulk_out_handler(encrypt_cmd + encrypt_data)

        status, encrypted_len = struct.unpack("<II", encrypt_response[:8])
        assert status == HASPStatus.HASP_STATUS_OK
        encrypted = encrypt_response[8 : 8 + encrypted_len]

        assert encrypted != plaintext
        assert encrypted != b"\x00" * len(encrypted)
        assert len(encrypted) >= len(plaintext)
        assert len(encrypted) % 16 == 0

        cipher = AES.new(hasp_dongle.aes_key, AES.MODE_ECB)
        padded_plaintext = plaintext + b"\x00" * (16 - len(plaintext) % 16)
        expected_encrypted = cipher.encrypt(padded_plaintext)
        assert encrypted == expected_encrypted

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Requires PyCryptodome")
    def test_bulk_out_handler_decrypts_with_real_crypto(self, emulator: HardwareDongleEmulator, hasp_dongle: HASPDongle) -> None:
        """Bulk OUT handler performs real AES decryption, not placeholders."""
        login_cmd = struct.pack("<I", 1)
        login_data = struct.pack("<HH", hasp_dongle.vendor_code, hasp_dongle.feature_id)
        login_response = emulator._hasp_bulk_out_handler(login_cmd + login_data)
        _, session_handle = struct.unpack("<II", login_response[:8])

        plaintext = b"DecryptTest12345"
        cipher = AES.new(hasp_dongle.aes_key, AES.MODE_ECB)
        padded_plaintext = plaintext + b"\x00" * (16 - len(plaintext) % 16)
        ciphertext = cipher.encrypt(padded_plaintext)

        decrypt_cmd = struct.pack("<I", 4)
        decrypt_data = struct.pack("<II", session_handle, len(ciphertext)) + ciphertext
        decrypt_response = emulator._hasp_bulk_out_handler(decrypt_cmd + decrypt_data)

        status, decrypted_len = struct.unpack("<II", decrypt_response[:8])
        assert status == HASPStatus.HASP_STATUS_OK
        decrypted = decrypt_response[8 : 8 + decrypted_len]

        assert decrypted.rstrip(b"\x00") == plaintext
        assert decrypted != ciphertext
        assert decrypted != b"\x00" * len(decrypted)

    def test_bulk_out_handler_reads_realistic_memory(self, emulator: HardwareDongleEmulator, hasp_dongle: HASPDongle) -> None:
        """Bulk OUT handler reads actual memory contents, not zero buffers."""
        test_data = b"LicenseData123XYZ"
        hasp_dongle.memory.write("eeprom", 0, test_data)

        login_cmd = struct.pack("<I", 1)
        login_data = struct.pack("<HH", hasp_dongle.vendor_code, hasp_dongle.feature_id)
        login_response = emulator._hasp_bulk_out_handler(login_cmd + login_data)
        _, session_handle = struct.unpack("<II", login_response[:8])

        read_cmd = struct.pack("<I", 5)
        read_data = struct.pack("<III", session_handle, 0, len(test_data))
        read_response = emulator._hasp_bulk_out_handler(read_cmd + read_data)

        status, mem_len = struct.unpack("<II", read_response[:8])
        assert status == HASPStatus.HASP_STATUS_OK
        memory_data = read_response[8 : 8 + mem_len]

        assert memory_data == test_data
        assert memory_data != b"\x00" * len(test_data)

    def test_bulk_out_handler_writes_memory_successfully(self, emulator: HardwareDongleEmulator, hasp_dongle: HASPDongle) -> None:
        """Bulk OUT handler writes data to memory correctly."""
        login_cmd = struct.pack("<I", 1)
        login_data = struct.pack("<HH", hasp_dongle.vendor_code, hasp_dongle.feature_id)
        login_response = emulator._hasp_bulk_out_handler(login_cmd + login_data)
        _, session_handle = struct.unpack("<II", login_response[:8])

        write_data_bytes = b"WriteTest987654321"
        write_cmd = struct.pack("<I", 6)
        write_data = struct.pack("<III", session_handle, 100, len(write_data_bytes)) + write_data_bytes
        write_response = emulator._hasp_bulk_out_handler(write_cmd + write_data)

        status = struct.unpack("<I", write_response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK

        actual_memory = hasp_dongle.memory.read("eeprom", 100, len(write_data_bytes))
        assert actual_memory == write_data_bytes

    def test_bulk_out_handler_maintains_session_state(self, emulator: HardwareDongleEmulator, hasp_dongle: HASPDongle) -> None:
        """Bulk OUT handler maintains session handle across operations."""
        login_cmd = struct.pack("<I", 1)
        login_data = struct.pack("<HH", hasp_dongle.vendor_code, hasp_dongle.feature_id)
        login_response = emulator._hasp_bulk_out_handler(login_cmd + login_data)
        _, session_handle = struct.unpack("<II", login_response[:8])

        read_cmd = struct.pack("<I", 5)
        read_data = struct.pack("<III", session_handle, 0, 16)
        read_response1 = emulator._hasp_bulk_out_handler(read_cmd + read_data)
        status1 = struct.unpack("<I", read_response1[:4])[0]

        read_response2 = emulator._hasp_bulk_out_handler(read_cmd + read_data)
        status2 = struct.unpack("<I", read_response2[:4])[0]

        assert status1 == HASPStatus.HASP_STATUS_OK
        assert status2 == HASPStatus.HASP_STATUS_OK
        assert hasp_dongle.session_handle == session_handle

    def test_bulk_out_handler_rejects_invalid_session(self, emulator: HardwareDongleEmulator) -> None:
        """Bulk OUT handler rejects operations with invalid session handle."""
        invalid_session = 0xDEADBEEF
        read_cmd = struct.pack("<I", 5)
        read_data = struct.pack("<III", invalid_session, 0, 16)
        read_response = emulator._hasp_bulk_out_handler(read_cmd + read_data)

        status = struct.unpack("<I", read_response[:4])[0]
        assert status == HASPStatus.HASP_INV_HND

    def test_bulk_out_handler_short_data_returns_error(self, emulator: HardwareDongleEmulator) -> None:
        """Bulk OUT handler returns error for malformed short requests."""
        short_request = b"\x01"
        response = emulator._hasp_bulk_out_handler(short_request)

        assert response == b""

    def test_bulk_out_handler_unknown_command_returns_ok(self, emulator: HardwareDongleEmulator) -> None:
        """Bulk OUT handler returns OK for unknown commands (protocol tolerance)."""
        unknown_cmd = struct.pack("<I", 999)
        response = emulator._hasp_bulk_out_handler(unknown_cmd)

        status = struct.unpack("<I", response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK

    def test_bulk_in_handler_returns_dongle_info(self, emulator: HardwareDongleEmulator, hasp_dongle: HASPDongle) -> None:
        """Bulk IN handler returns structured dongle information, not zeros."""
        response = emulator._hasp_bulk_in_handler(b"")

        assert len(response) == 512
        assert response != b"\x00" * 512

        hasp_id, vendor_code, feature_id, rtc_counter = struct.unpack("<IHHQ", response[:16])
        assert hasp_id == hasp_dongle.hasp_id
        assert vendor_code == hasp_dongle.vendor_code
        assert feature_id == hasp_dongle.feature_id
        assert rtc_counter == hasp_dongle.rtc_counter


class TestHASPMultiFeatureDongles:
    """Test HASP dongles with multiple features (edge case)."""

    @pytest.fixture
    def multi_feature_dongle(self) -> HASPDongle:
        """Create HASP dongle with multiple features."""
        dongle = HASPDongle(hasp_id=0x11223344, vendor_code=0xABCD, feature_id=1)
        dongle.feature_map[2] = {
            "id": 2,
            "type": "professional",
            "expiration": 0xFFFFFFFF,
            "max_users": 50,
            "current_users": 0,
        }
        dongle.feature_map[3] = {
            "id": 3,
            "type": "enterprise",
            "expiration": 0xFFFFFFFF,
            "max_users": 100,
            "current_users": 0,
        }
        return dongle

    def test_multi_feature_dongle_has_multiple_features(self, multi_feature_dongle: HASPDongle) -> None:
        """Multi-feature dongle maintains multiple feature definitions."""
        assert len(multi_feature_dongle.feature_map) == 3
        assert 1 in multi_feature_dongle.feature_map
        assert 2 in multi_feature_dongle.feature_map
        assert 3 in multi_feature_dongle.feature_map

    def test_multi_feature_login_with_different_features(self, multi_feature_dongle: HASPDongle) -> None:
        """Multi-feature dongle can login with different feature IDs."""
        emulator = HardwareDongleEmulator()
        emulator.hasp_dongles[1] = multi_feature_dongle

        login_data_feature1 = struct.pack("<HH", multi_feature_dongle.vendor_code, 1)
        response1 = emulator._hasp_login(login_data_feature1)
        status1, session1 = struct.unpack("<II", response1[:8])

        multi_feature_dongle.logged_in = False
        multi_feature_dongle.session_handle = 0

        login_data_feature2 = struct.pack("<HH", multi_feature_dongle.vendor_code, 2)
        response2 = emulator._hasp_login(login_data_feature2)
        status2, session2 = struct.unpack("<II", response2[:8])

        assert status1 == HASPStatus.HASP_STATUS_OK
        assert status2 == HASPStatus.HASP_STATUS_OK
        assert session1 != 0
        assert session2 != 0

    def test_multi_feature_control_handler_returns_correct_feature(self, multi_feature_dongle: HASPDongle) -> None:
        """Control handler returns correct feature ID for multi-feature dongle."""
        emulator = HardwareDongleEmulator()
        emulator.hasp_dongles[1] = multi_feature_dongle

        response = emulator._hasp_control_handler(wValue=2, wIndex=0, data=b"")

        vendor_code, feature_id = struct.unpack("<HH", response[:4])
        assert vendor_code == multi_feature_dongle.vendor_code
        assert feature_id == multi_feature_dongle.feature_id


class TestHASPCommandVariants:
    """Test support for HASP4/HL/SL command variants."""

    @pytest.fixture
    def emulator(self) -> HardwareDongleEmulator:
        """Create emulator for command variant testing."""
        emu = HardwareDongleEmulator()
        emu.activate_dongle_emulation(["HASP"])
        return emu

    @pytest.fixture
    def session_handle(self, emulator: HardwareDongleEmulator) -> int:
        """Create logged-in session and return handle."""
        dongle = next(iter(emulator.hasp_dongles.values()))
        login_cmd = struct.pack("<I", 1)
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        response = emulator._hasp_bulk_out_handler(login_cmd + login_data)
        _, handle = struct.unpack("<II", response[:8])
        return handle

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Requires PyCryptodome")
    def test_hasp_hl_aes_encryption_command(self, emulator: HardwareDongleEmulator, session_handle: int) -> None:
        """HASP HL AES encryption command processes correctly."""
        plaintext = b"HASPHLTestData12"
        encrypt_cmd = struct.pack("<I", 3)
        encrypt_data = struct.pack("<II", session_handle, len(plaintext)) + plaintext

        response = emulator._hasp_bulk_out_handler(encrypt_cmd + encrypt_data)

        status, encrypted_len = struct.unpack("<II", response[:8])
        assert status == HASPStatus.HASP_STATUS_OK
        assert encrypted_len >= 16
        encrypted = response[8 : 8 + encrypted_len]
        assert encrypted != plaintext

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Requires PyCryptodome")
    def test_hasp_sl_aes_decryption_command(self, emulator: HardwareDongleEmulator, session_handle: int) -> None:
        """HASP SL AES decryption command processes correctly."""
        dongle = next(iter(emulator.hasp_dongles.values()))
        plaintext = b"HASPSLTestData12"
        cipher = AES.new(dongle.aes_key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(plaintext)

        decrypt_cmd = struct.pack("<I", 4)
        decrypt_data = struct.pack("<II", session_handle, len(ciphertext)) + ciphertext

        response = emulator._hasp_bulk_out_handler(decrypt_cmd + decrypt_data)

        status, decrypted_len = struct.unpack("<II", response[:8])
        assert status == HASPStatus.HASP_STATUS_OK
        decrypted = response[8 : 8 + decrypted_len]
        assert decrypted.rstrip(b"\x00") == plaintext

    def test_hasp4_legacy_memory_read_command(self, emulator: HardwareDongleEmulator, session_handle: int) -> None:
        """HASP4 legacy memory read command works correctly."""
        dongle = next(iter(emulator.hasp_dongles.values()))
        test_data = b"HASP4LegacyData"
        dongle.memory.write("eeprom", 50, test_data)

        read_cmd = struct.pack("<I", 5)
        read_data = struct.pack("<III", session_handle, 50, len(test_data))

        response = emulator._hasp_bulk_out_handler(read_cmd + read_data)

        status, mem_len = struct.unpack("<II", response[:8])
        assert status == HASPStatus.HASP_STATUS_OK
        memory_data = response[8 : 8 + mem_len]
        assert memory_data == test_data

    def test_hasp4_legacy_memory_write_command(self, emulator: HardwareDongleEmulator, session_handle: int) -> None:
        """HASP4 legacy memory write command works correctly."""
        write_data_bytes = b"HASP4WriteTest"
        write_cmd = struct.pack("<I", 6)
        write_data = struct.pack("<III", session_handle, 200, len(write_data_bytes)) + write_data_bytes

        response = emulator._hasp_bulk_out_handler(write_cmd + write_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK

        dongle = next(iter(emulator.hasp_dongles.values()))
        actual = dongle.memory.read("eeprom", 200, len(write_data_bytes))
        assert actual == write_data_bytes


class TestHASPNetworkDongle:
    """Test HASP network dongle scenarios (edge case)."""

    @pytest.fixture
    def network_dongles(self) -> list[HASPDongle]:
        """Create multiple HASP dongles simulating network environment."""
        dongles = []
        for i in range(3):
            dongle = HASPDongle(
                hasp_id=0x10000000 + i,
                vendor_code=0x5000 + i,
                feature_id=i + 1
            )
            dongles.append(dongle)
        return dongles

    def test_network_environment_multiple_dongles(self, network_dongles: list[HASPDongle]) -> None:
        """Network environment can have multiple HASP dongles."""
        emulator = HardwareDongleEmulator()
        for idx, dongle in enumerate(network_dongles):
            emulator.hasp_dongles[idx + 1] = dongle

        assert len(emulator.hasp_dongles) == 3

    def test_network_dongle_concurrent_sessions(self, network_dongles: list[HASPDongle]) -> None:
        """Multiple concurrent sessions can exist on network dongles."""
        emulator = HardwareDongleEmulator()
        for idx, dongle in enumerate(network_dongles):
            emulator.hasp_dongles[idx + 1] = dongle

        sessions = []
        for dongle in network_dongles:
            login_cmd = struct.pack("<I", 1)
            login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
            response = emulator._hasp_bulk_out_handler(login_cmd + login_data)
            _, session_handle = struct.unpack("<II", response[:8])
            sessions.append(session_handle)

        assert len(sessions) == 3
        assert len(set(sessions)) == 3
        assert all(s != 0 for s in sessions)

    def test_network_dongle_independent_memory_spaces(self, network_dongles: list[HASPDongle]) -> None:
        """Network dongles maintain independent memory spaces."""
        for idx, dongle in enumerate(network_dongles):
            test_data = f"Dongle{idx}Data".encode()
            dongle.memory.write("eeprom", 0, test_data)

        for idx, dongle in enumerate(network_dongles):
            memory_data = dongle.memory.read("eeprom", 0, 20)
            expected = f"Dongle{idx}Data".encode()
            assert memory_data.startswith(expected)

    def test_network_dongle_control_handler_selects_first(self, network_dongles: list[HASPDongle]) -> None:
        """Control handler selects first dongle in network environment."""
        emulator = HardwareDongleEmulator()
        for idx, dongle in enumerate(network_dongles):
            emulator.hasp_dongles[idx + 1] = dongle

        response = emulator._hasp_control_handler(wValue=1, wIndex=0, data=b"")

        hasp_id = struct.unpack("<I", response[:4])[0]
        assert hasp_id == network_dongles[0].hasp_id


class TestHASPCryptoEngineIntegration:
    """Test CryptoEngine integration with HASP commands."""

    @pytest.fixture
    def crypto_engine(self) -> CryptoEngine:
        """Create crypto engine instance."""
        return CryptoEngine()

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Requires PyCryptodome")
    def test_crypto_engine_aes_encryption_is_real(self, crypto_engine: CryptoEngine) -> None:
        """CryptoEngine performs real AES encryption, not simulation."""
        key = b"\x01\x02\x03\x04" * 8
        plaintext = b"TestPlaintext123"

        encrypted = crypto_engine.hasp_encrypt(plaintext, key, "AES")

        assert encrypted != plaintext
        assert encrypted != b"\x00" * len(encrypted)
        assert len(encrypted) % 16 == 0

        cipher = AES.new(key, AES.MODE_ECB)
        padded = plaintext + b"\x00" * (16 - len(plaintext) % 16)
        expected = cipher.encrypt(padded)
        assert encrypted == expected

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Requires PyCryptodome")
    def test_crypto_engine_aes_decryption_is_real(self, crypto_engine: CryptoEngine) -> None:
        """CryptoEngine performs real AES decryption, not simulation."""
        key = b"\x05\x06\x07\x08" * 8
        plaintext = b"TestDecryption12"
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(plaintext)

        decrypted = crypto_engine.hasp_decrypt(ciphertext, key, "AES")

        assert decrypted.rstrip(b"\x00") == plaintext
        assert decrypted != ciphertext

    def test_crypto_engine_xor_fallback_when_crypto_unavailable(self, crypto_engine: CryptoEngine, monkeypatch: pytest.MonkeyPatch) -> None:
        """CryptoEngine falls back to XOR when crypto unavailable."""
        monkeypatch.setattr("intellicrack.core.protection_bypass.dongle_emulator.CRYPTO_AVAILABLE", False)

        key = b"\xAA\xBB\xCC\xDD"
        plaintext = b"TestXORFallback"

        encrypted = crypto_engine.hasp_encrypt(plaintext, key, "AES")

        assert encrypted != plaintext
        assert len(encrypted) == len(plaintext)

        expected = bytearray(len(plaintext))
        for i in range(len(plaintext)):
            expected[i] = plaintext[i] ^ key[i % len(key)]
        assert encrypted == bytes(expected)


class TestHASPMemoryBoundaryConditions:
    """Test HASP memory operations at boundary conditions."""

    @pytest.fixture
    def emulator_with_session(self) -> tuple[HardwareDongleEmulator, int]:
        """Create emulator with active session."""
        emu = HardwareDongleEmulator()
        emu.activate_dongle_emulation(["HASP"])
        dongle = next(iter(emu.hasp_dongles.values()))

        login_cmd = struct.pack("<I", 1)
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        response = emu._hasp_bulk_out_handler(login_cmd + login_data)
        _, session_handle = struct.unpack("<II", response[:8])

        return emu, session_handle

    def test_memory_read_at_boundary(self, emulator_with_session: tuple[HardwareDongleEmulator, int]) -> None:
        """Memory read at EEPROM boundary succeeds."""
        emulator, session_handle = emulator_with_session
        dongle = next(iter(emulator.hasp_dongles.values()))
        eeprom_size = len(dongle.memory.eeprom)

        test_data = b"BoundaryTest"
        offset = eeprom_size - len(test_data)
        dongle.memory.write("eeprom", offset, test_data)

        read_cmd = struct.pack("<I", 5)
        read_data = struct.pack("<III", session_handle, offset, len(test_data))
        response = emulator._hasp_bulk_out_handler(read_cmd + read_data)

        status, mem_len = struct.unpack("<II", response[:8])
        assert status == HASPStatus.HASP_STATUS_OK
        memory_data = response[8 : 8 + mem_len]
        assert memory_data == test_data

    def test_memory_read_beyond_boundary_fails(self, emulator_with_session: tuple[HardwareDongleEmulator, int]) -> None:
        """Memory read beyond EEPROM boundary returns error."""
        emulator, session_handle = emulator_with_session
        dongle = next(iter(emulator.hasp_dongles.values()))
        eeprom_size = len(dongle.memory.eeprom)

        read_cmd = struct.pack("<I", 5)
        read_data = struct.pack("<III", session_handle, eeprom_size - 10, 20)
        response = emulator._hasp_bulk_out_handler(read_cmd + read_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == HASPStatus.HASP_MEM_RANGE

    def test_memory_write_beyond_boundary_fails(self, emulator_with_session: tuple[HardwareDongleEmulator, int]) -> None:
        """Memory write beyond EEPROM boundary returns error."""
        emulator, session_handle = emulator_with_session
        dongle = next(iter(emulator.hasp_dongles.values()))
        eeprom_size = len(dongle.memory.eeprom)

        write_data_bytes = b"ExceedBoundary"
        write_cmd = struct.pack("<I", 6)
        write_data = struct.pack("<III", session_handle, eeprom_size - 5, len(write_data_bytes)) + write_data_bytes
        response = emulator._hasp_bulk_out_handler(write_cmd + write_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == HASPStatus.HASP_MEM_RANGE

    def test_memory_zero_length_read(self, emulator_with_session: tuple[HardwareDongleEmulator, int]) -> None:
        """Memory read with zero length returns empty data."""
        emulator, session_handle = emulator_with_session

        read_cmd = struct.pack("<I", 5)
        read_data = struct.pack("<III", session_handle, 0, 0)
        response = emulator._hasp_bulk_out_handler(read_cmd + read_data)

        status, mem_len = struct.unpack("<II", response[:8])
        assert status == HASPStatus.HASP_STATUS_OK
        assert mem_len == 0

    def test_memory_large_read_succeeds(self, emulator_with_session: tuple[HardwareDongleEmulator, int]) -> None:
        """Memory read of entire EEPROM succeeds."""
        emulator, session_handle = emulator_with_session
        dongle = next(iter(emulator.hasp_dongles.values()))
        eeprom_size = len(dongle.memory.eeprom)

        read_cmd = struct.pack("<I", 5)
        read_data = struct.pack("<III", session_handle, 0, eeprom_size)
        response = emulator._hasp_bulk_out_handler(read_cmd + read_data)

        status, mem_len = struct.unpack("<II", response[:8])
        assert status == HASPStatus.HASP_STATUS_OK
        assert mem_len == eeprom_size
