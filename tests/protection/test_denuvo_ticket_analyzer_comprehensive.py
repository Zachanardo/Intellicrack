"""Comprehensive production tests for Denuvo Ticket Analyzer.

Tests validate real offensive capabilities including ticket parsing, token forging,
license manipulation, machine ID spoofing, and activation response generation.
All tests use real binary structures and cryptographic operations.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import hmac
import os
import struct
import time
from typing import Any

import pytest

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Util.Padding import pad, unpad

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from intellicrack.protection.denuvo_ticket_analyzer import (
    ActivationResponse,
    ActivationToken,
    DenuvoTicket,
    DenuvoTicketAnalyzer,
    MachineIdentifier,
    TicketHeader,
    TicketPayload,
)


@pytest.fixture
def analyzer() -> DenuvoTicketAnalyzer:
    """Create analyzer instance."""
    return DenuvoTicketAnalyzer()


@pytest.fixture
def game_id() -> bytes:
    """Test game identifier."""
    return hashlib.sha256(b"test_game_2025").digest()[:16]


@pytest.fixture
def machine_id() -> bytes:
    """Test machine identifier."""
    return hashlib.sha256(b"test_machine_id").digest()


@pytest.fixture
def encryption_key() -> bytes:
    """Test encryption key."""
    return hashlib.sha256(b"denuvo_aes_key_v7_extended_master").digest()


@pytest.fixture
def iv() -> bytes:
    """Test initialization vector."""
    return hashlib.md5(b"denuvo_iv_v7").digest()


@pytest.fixture
def hmac_key() -> bytes:
    """Test HMAC key."""
    return hashlib.sha256(b"denuvo_master_key_v7").digest()


@pytest.fixture
def real_ticket_v7(
    game_id: bytes,
    machine_id: bytes,
    encryption_key: bytes,
    iv: bytes,
    hmac_key: bytes,
) -> bytes:
    """Create real Denuvo v7 ticket with proper encryption and signature."""
    if not CRYPTO_AVAILABLE:
        pytest.skip("Crypto library required for ticket creation")

    machine_identifier = MachineIdentifier(
        hwid_hash=hashlib.sha256(machine_id + b"hwid").digest(),
        cpu_hash=hashlib.sha256(machine_id + b"cpu").digest(),
        disk_hash=hashlib.sha256(machine_id + b"disk").digest(),
        mac_hash=hashlib.sha256(machine_id + b"mac").digest(),
        bios_hash=hashlib.sha256(machine_id + b"bios").digest(),
        combined_hash=machine_id,
        salt=b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10",
    )

    payload_data = bytearray()
    payload_data.extend(game_id)
    payload_data.extend(b"1.0.0.0" + (b"\x00" * 9))
    payload_data.extend(machine_identifier.hwid_hash)
    payload_data.extend(machine_identifier.cpu_hash)
    payload_data.extend(machine_identifier.disk_hash)
    payload_data.extend(machine_identifier.mac_hash)
    payload_data.extend(machine_identifier.bios_hash)
    payload_data.extend(machine_identifier.combined_hash)
    payload_data.extend(machine_identifier.salt)

    token_id = b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
    activation_time = int(time.time())
    expiration_time = activation_time + (365 * 86400)
    ticket_hash = hashlib.sha256(b"ticket_placeholder").digest()

    token_data = bytearray()
    token_data.extend(b"DNVT")
    token_data.extend(token_id)
    token_data.extend(game_id)
    token_data.extend(ticket_hash)
    token_data.extend(machine_id)
    token_data.extend(struct.pack("<QQII", activation_time, expiration_time, 0x02, 0xFFFFFFFF))
    token_signature = hmac.new(hmac_key, bytes(token_data), hashlib.sha256).digest()
    token_data.extend(token_signature + (b"\x00" * (256 - len(token_signature))))

    payload_data.extend(bytes(token_data)[:128])

    license_type = 0x02
    expiration = int(time.time()) + (365 * 86400)
    payload_data.extend(struct.pack("<I", license_type))
    payload_data.extend(struct.pack("<Q", expiration))
    payload_data.extend(b"\x21" * 32)
    payload_data.extend(b"\x22" * 32)

    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    encrypted_payload = cipher.encrypt(pad(bytes(payload_data), AES.block_size))

    header_size_v7 = 136
    payload_offset = header_size_v7
    signature_offset = payload_offset + len(encrypted_payload)
    ticket_size = signature_offset + 256

    timestamp = int(time.time())
    header_packed = struct.pack(
        "<4sIIQIIIBB102s",
        b"DNV7",
        7,
        0x01,
        timestamp,
        ticket_size,
        payload_offset,
        signature_offset,
        0x02,
        0x00,
        b"\x00" * 102,
    )

    data_to_sign = header_packed[:20] + encrypted_payload
    signature = hmac.new(hmac_key, data_to_sign, hashlib.sha256).digest()
    signature_padded = signature + (b"\x00" * (256 - len(signature)))

    ticket_data = header_packed + encrypted_payload + signature_padded

    return ticket_data


@pytest.fixture
def real_token_v7(game_id: bytes, machine_id: bytes, hmac_key: bytes) -> bytes:
    """Create real Denuvo v7 activation token."""
    token_id = os.urandom(16)
    activation_time = int(time.time())
    expiration_time = activation_time + (365 * 86400)
    ticket_hash = hashlib.sha256(b"ticket_placeholder").digest()

    token_data = bytearray()
    token_data.extend(b"DNVT")
    token_data.extend(token_id)
    token_data.extend(game_id)
    token_data.extend(ticket_hash)
    token_data.extend(machine_id)
    token_data.extend(struct.pack("<QQII", activation_time, expiration_time, 0x04, 0xFFFFFFFF))

    signature = hmac.new(hmac_key, bytes(token_data), hashlib.sha256).digest()
    token_data.extend(signature + (b"\x00" * (256 - len(signature))))

    return bytes(token_data)


class TestTicketParsing:
    """Tests for ticket parsing functionality."""

    def test_parse_valid_v7_ticket(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
    ) -> None:
        """Parser extracts valid v7 ticket structure with correct header fields."""
        ticket = analyzer.parse_ticket(real_ticket_v7)

        assert ticket is not None
        assert isinstance(ticket, DenuvoTicket)
        assert ticket.header.magic == b"DNV7"
        assert ticket.header.version == 7
        assert ticket.header.encryption_type == 0x02
        assert ticket.header.compression_type == 0x00
        assert len(ticket.encrypted_payload) > 0
        assert len(ticket.signature) == 256

    def test_parse_ticket_validates_signature(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
    ) -> None:
        """Parser verifies HMAC signature and sets valid flag correctly."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        ticket = analyzer.parse_ticket(real_ticket_v7)

        assert ticket is not None
        assert ticket.is_valid is True

    def test_parse_ticket_decrypts_payload(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
    ) -> None:
        """Parser decrypts payload and extracts machine ID and license data."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        ticket = analyzer.parse_ticket(real_ticket_v7)

        assert ticket is not None
        assert ticket.payload is not None
        assert isinstance(ticket.payload, TicketPayload)
        assert len(ticket.payload.game_id) == 16
        assert isinstance(ticket.payload.machine_id, MachineIdentifier)
        assert len(ticket.payload.machine_id.combined_hash) == 32
        assert "type" in ticket.payload.license_data
        assert "expiration" in ticket.payload.license_data

    def test_parse_ticket_rejects_invalid_magic(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Parser rejects tickets with invalid magic bytes."""
        invalid_ticket = b"FAKE" + (b"\x00" * 200)

        ticket = analyzer.parse_ticket(invalid_ticket)

        assert ticket is None

    def test_parse_ticket_rejects_truncated_data(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Parser rejects tickets smaller than minimum header size."""
        truncated = b"DNV7" + (b"\x00" * 30)

        ticket = analyzer.parse_ticket(truncated)

        assert ticket is None

    def test_parse_ticket_handles_corrupted_signature(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
    ) -> None:
        """Parser parses ticket but marks as invalid with corrupted signature."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        corrupted = bytearray(real_ticket_v7)
        corrupted[-10:] = b"\xFF" * 10
        corrupted_ticket = bytes(corrupted)

        ticket = analyzer.parse_ticket(corrupted_ticket)

        assert ticket is not None
        assert ticket.is_valid is False

    @pytest.mark.parametrize(
        "magic,version,header_size",
        [
            (b"DNV4", 4, 72),
            (b"DNV5", 5, 88),
            (b"DNV6", 6, 104),
            (b"DNV7", 7, 136),
        ],
    )
    def test_parse_ticket_supports_all_versions(
        self,
        analyzer: DenuvoTicketAnalyzer,
        magic: bytes,
        version: int,
        header_size: int,
        encryption_key: bytes,
        iv: bytes,
        hmac_key: bytes,
    ) -> None:
        """Parser correctly identifies and processes all Denuvo versions."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        header_formats = {
            72: "<4sIIQIIIBB38s",
            88: "<4sIIQIIIBB54s",
            104: "<4sIIQIIIBB70s",
            136: "<4sIIQIIIBB102s",
        }

        timestamp = int(time.time())
        payload_offset = header_size
        dummy_payload = b"\x00" * 256
        signature_offset = payload_offset + len(dummy_payload)

        reserved_size = header_size - 38
        header_values = (
            magic,
            version,
            0x01,
            timestamp,
            signature_offset + 256,
            payload_offset,
            signature_offset,
            0x00,
            0x00,
            b"\x00" * reserved_size,
        )

        header_data = struct.pack(header_formats[header_size], *header_values)
        signature = hmac.new(hmac_key, header_data + dummy_payload, hashlib.sha256).digest()
        ticket_data = header_data + dummy_payload + signature + (b"\x00" * (256 - len(signature)))

        ticket = analyzer.parse_ticket(ticket_data)

        assert ticket is not None
        assert ticket.header.magic == magic
        assert ticket.header.version == version


class TestTokenParsing:
    """Tests for activation token parsing."""

    def test_parse_valid_token(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_token_v7: bytes,
    ) -> None:
        """Parser extracts token structure with all fields correctly."""
        token = analyzer.parse_token(real_token_v7)

        assert token is not None
        assert isinstance(token, ActivationToken)
        assert len(token.token_id) == 16
        assert len(token.game_id) == 16
        assert len(token.ticket_hash) == 32
        assert len(token.machine_id) == 32
        assert token.activation_time > 0
        assert token.expiration_time > token.activation_time
        assert token.license_type in [0x01, 0x02, 0x03, 0x04]
        assert len(token.signature) == 256

    def test_parse_token_rejects_invalid_magic(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Parser rejects tokens with incorrect magic bytes."""
        invalid_token = b"FAKE" + (b"\x00" * 200)

        token = analyzer.parse_token(invalid_token)

        assert token is None

    def test_parse_token_rejects_truncated_data(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Parser rejects tokens smaller than minimum size."""
        truncated = b"DNVT" + (b"\x00" * 50)

        token = analyzer.parse_token(truncated)

        assert token is None

    def test_parse_token_extracts_license_type(
        self,
        analyzer: DenuvoTicketAnalyzer,
        game_id: bytes,
        machine_id: bytes,
        hmac_key: bytes,
    ) -> None:
        """Parser correctly identifies trial vs full license types."""
        for license_type in [
            analyzer.LICENSE_TRIAL,
            analyzer.LICENSE_FULL,
            analyzer.LICENSE_PERPETUAL,
        ]:
            token_data = bytearray()
            token_data.extend(b"DNVT")
            token_data.extend(os.urandom(16))
            token_data.extend(game_id)
            token_data.extend(os.urandom(32))
            token_data.extend(machine_id)
            token_data.extend(
                struct.pack("<QQII", int(time.time()), int(time.time()) + 86400, license_type, 0xFFFFFFFF),
            )
            signature = hmac.new(hmac_key, bytes(token_data), hashlib.sha256).digest()
            token_data.extend(signature + (b"\x00" * (256 - len(signature))))

            token = analyzer.parse_token(bytes(token_data))

            assert token is not None
            assert token.license_type == license_type


class TestActivationResponseGeneration:
    """Tests for activation response generation (offline bypass)."""

    def test_generate_activation_response_creates_valid_structure(
        self,
        analyzer: DenuvoTicketAnalyzer,
        game_id: bytes,
        machine_id: bytes,
    ) -> None:
        """Generator produces complete activation response with all components."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        request_data = b"\x00" * 16 + game_id + machine_id
        response = analyzer.generate_activation_response(request_data)

        assert response is not None
        assert isinstance(response, ActivationResponse)
        assert response.status_code == 200
        assert len(response.response_id) == 16
        assert len(response.ticket) > 0
        assert len(response.token) > 0
        assert len(response.server_signature) == 256
        assert response.timestamp > 0
        assert response.expiration > response.timestamp

    def test_generate_activation_response_creates_perpetual_license(
        self,
        analyzer: DenuvoTicketAnalyzer,
        game_id: bytes,
        machine_id: bytes,
    ) -> None:
        """Generator creates perpetual license by default with 100 year duration."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        request_data = b"\x00" * 16 + game_id + machine_id
        response = analyzer.generate_activation_response(request_data, license_type=analyzer.LICENSE_PERPETUAL)

        assert response is not None
        assert response.metadata["license_type"] == analyzer.LICENSE_PERPETUAL
        assert response.expiration > response.timestamp + (365 * 86400 * 90)

    def test_generate_activation_response_accepts_custom_duration(
        self,
        analyzer: DenuvoTicketAnalyzer,
        game_id: bytes,
        machine_id: bytes,
    ) -> None:
        """Generator respects custom license duration parameter."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        request_data = b"\x00" * 16 + game_id + machine_id
        duration_days = 30
        response = analyzer.generate_activation_response(request_data, duration_days=duration_days)

        assert response is not None
        expected_expiration = response.timestamp + (duration_days * 86400)
        assert abs(response.expiration - expected_expiration) < 5

    def test_generate_activation_response_signs_components(
        self,
        analyzer: DenuvoTicketAnalyzer,
        game_id: bytes,
        machine_id: bytes,
    ) -> None:
        """Generator creates valid HMAC signature over response components."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        request_data = b"\x00" * 16 + game_id + machine_id
        response = analyzer.generate_activation_response(request_data)

        assert response is not None
        assert len(response.server_signature) == 256
        assert response.server_signature != b"\x00" * 256


class TestTokenForging:
    """Tests for activation token forging."""

    def test_forge_token_creates_valid_structure(
        self,
        analyzer: DenuvoTicketAnalyzer,
        game_id: bytes,
        machine_id: bytes,
    ) -> None:
        """Forger creates token with correct magic and all required fields."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        forged = analyzer.forge_token(game_id, machine_id)

        assert forged is not None
        assert forged.startswith(b"DNVT")
        assert len(forged) >= 152

        parsed = analyzer.parse_token(forged)
        assert parsed is not None
        assert parsed.game_id == game_id
        assert parsed.machine_id == machine_id

    def test_forge_token_enables_all_features(
        self,
        analyzer: DenuvoTicketAnalyzer,
        game_id: bytes,
        machine_id: bytes,
    ) -> None:
        """Forger sets features_enabled to 0xFFFFFFFF to unlock everything."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        forged = analyzer.forge_token(game_id, machine_id)
        assert forged is not None

        parsed = analyzer.parse_token(forged)
        assert parsed is not None
        assert parsed.features_enabled == 0xFFFFFFFF

    def test_forge_token_creates_perpetual_license(
        self,
        analyzer: DenuvoTicketAnalyzer,
        game_id: bytes,
        machine_id: bytes,
    ) -> None:
        """Forger creates perpetual license with 100 year expiration."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        forged = analyzer.forge_token(game_id, machine_id, license_type=analyzer.LICENSE_PERPETUAL, duration_days=36500)
        assert forged is not None

        parsed = analyzer.parse_token(forged)
        assert parsed is not None
        assert parsed.license_type == analyzer.LICENSE_PERPETUAL
        assert parsed.expiration_time > parsed.activation_time + (365 * 86400 * 90)

    def test_forge_token_includes_valid_signature(
        self,
        analyzer: DenuvoTicketAnalyzer,
        game_id: bytes,
        machine_id: bytes,
    ) -> None:
        """Forger creates HMAC signature over token data."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        forged = analyzer.forge_token(game_id, machine_id)
        assert forged is not None

        parsed = analyzer.parse_token(forged)
        assert parsed is not None
        assert len(parsed.signature) == 256
        assert parsed.signature != b"\x00" * 256

    @pytest.mark.parametrize(
        "license_type",
        [
            DenuvoTicketAnalyzer.LICENSE_TRIAL,
            DenuvoTicketAnalyzer.LICENSE_FULL,
            DenuvoTicketAnalyzer.LICENSE_SUBSCRIPTION,
            DenuvoTicketAnalyzer.LICENSE_PERPETUAL,
        ],
    )
    def test_forge_token_supports_all_license_types(
        self,
        analyzer: DenuvoTicketAnalyzer,
        game_id: bytes,
        machine_id: bytes,
        license_type: int,
    ) -> None:
        """Forger creates valid tokens for all license types."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        forged = analyzer.forge_token(game_id, machine_id, license_type=license_type)
        assert forged is not None

        parsed = analyzer.parse_token(forged)
        assert parsed is not None
        assert parsed.license_type == license_type


class TestTrialConversion:
    """Tests for trial to full license conversion."""

    def test_convert_trial_to_full_upgrades_license_type(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
    ) -> None:
        """Converter changes license type from trial to perpetual."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        converted = analyzer.convert_trial_to_full(real_ticket_v7)
        assert converted is not None

        ticket = analyzer.parse_ticket(converted)
        assert ticket is not None
        assert ticket.payload is not None
        assert ticket.payload.license_data["type"] == analyzer.LICENSE_PERPETUAL

    def test_convert_trial_to_full_extends_expiration(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
    ) -> None:
        """Converter sets expiration to 100 years in future."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        converted = analyzer.convert_trial_to_full(real_ticket_v7)
        assert converted is not None

        ticket = analyzer.parse_ticket(converted)
        assert ticket is not None
        assert ticket.payload is not None

        current_time = int(time.time())
        expiration = ticket.payload.license_data["expiration"]
        assert expiration > current_time + (365 * 86400 * 90)

    def test_convert_trial_to_full_enables_all_features(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
    ) -> None:
        """Converter sets features_enabled to 0xFFFFFFFF."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        converted = analyzer.convert_trial_to_full(real_ticket_v7)
        assert converted is not None

        ticket = analyzer.parse_ticket(converted)
        assert ticket is not None
        assert ticket.payload is not None
        assert ticket.payload.activation_token.features_enabled == 0xFFFFFFFF

    def test_convert_trial_to_full_maintains_ticket_structure(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
    ) -> None:
        """Converter preserves ticket magic, version, and encryption."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        converted = analyzer.convert_trial_to_full(real_ticket_v7)
        assert converted is not None

        original = analyzer.parse_ticket(real_ticket_v7)
        modified = analyzer.parse_ticket(converted)

        assert original is not None
        assert modified is not None
        assert modified.header.magic == original.header.magic
        assert modified.header.version == original.header.version
        assert modified.header.encryption_type == original.header.encryption_type

    def test_convert_trial_to_full_rejects_undecryptable_ticket(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Converter fails gracefully on encrypted ticket without keys."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        header = struct.pack("<4sIIQIIIBB102s", b"DNV7", 7, 0x01, int(time.time()), 2048, 128, 1792, 0x04, 0x00, b"\x00" * 102)
        unknown_encrypted = os.urandom(1664)
        signature = os.urandom(256)
        bad_ticket = header + unknown_encrypted + signature

        converted = analyzer.convert_trial_to_full(bad_ticket)

        assert converted is None


class TestMachineIDOperations:
    """Tests for machine ID extraction and spoofing."""

    def test_extract_machine_id_from_ticket(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
        machine_id: bytes,
    ) -> None:
        """Extractor retrieves machine ID from decrypted payload."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        extracted = analyzer.extract_machine_id(real_ticket_v7)

        assert extracted is not None
        assert len(extracted) == 32
        assert extracted == machine_id

    def test_extract_machine_id_fails_without_payload(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Extractor returns None for encrypted ticket without decryption."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        header = struct.pack("<4sIIQIIIBB102s", b"DNV7", 7, 0x01, int(time.time()), 2048, 128, 1792, 0x04, 0x00, b"\x00" * 102)
        unknown_encrypted = os.urandom(1664)
        signature = os.urandom(256)
        bad_ticket = header + unknown_encrypted + signature

        extracted = analyzer.extract_machine_id(bad_ticket)

        assert extracted is None

    def test_spoof_machine_id_replaces_identifier(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
    ) -> None:
        """Spoofer replaces machine ID with target value."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        target_id = hashlib.sha256(b"spoofed_machine").digest()
        spoofed = analyzer.spoof_machine_id(real_ticket_v7, target_id)

        assert spoofed is not None

        extracted = analyzer.extract_machine_id(spoofed)
        assert extracted == target_id

    def test_spoof_machine_id_updates_token_machine_id(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
    ) -> None:
        """Spoofer updates both payload and token machine ID fields."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        target_id = hashlib.sha256(b"spoofed_machine_2").digest()
        spoofed = analyzer.spoof_machine_id(real_ticket_v7, target_id)

        assert spoofed is not None

        ticket = analyzer.parse_ticket(spoofed)
        assert ticket is not None
        assert ticket.payload is not None
        assert ticket.payload.machine_id.combined_hash == target_id
        assert ticket.payload.activation_token.machine_id == target_id

    def test_spoof_machine_id_maintains_ticket_validity(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
    ) -> None:
        """Spoofer preserves ticket structure and parsability."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        target_id = hashlib.sha256(b"spoofed_machine_3").digest()
        spoofed = analyzer.spoof_machine_id(real_ticket_v7, target_id)

        assert spoofed is not None

        ticket = analyzer.parse_ticket(spoofed)
        assert ticket is not None
        assert ticket.header.magic == b"DNV7"
        assert ticket.payload is not None


class TestActivationTrafficAnalysis:
    """Tests for PCAP traffic analysis."""

    def test_analyze_activation_traffic_requires_dpkt(
        self,
        analyzer: DenuvoTicketAnalyzer,
        tmp_path: Any,
    ) -> None:
        """Analyzer returns empty list without dpkt library."""
        try:
            import dpkt  # noqa: F401

            pytest.skip("dpkt is available")
        except ImportError:
            pass

        fake_pcap = tmp_path / "test.pcap"
        fake_pcap.write_bytes(b"\x00" * 100)

        sessions = analyzer.analyze_activation_traffic(str(fake_pcap))

        assert sessions == []

    def test_analyze_activation_traffic_handles_missing_file(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Analyzer returns empty list for nonexistent PCAP file."""
        sessions = analyzer.analyze_activation_traffic("/nonexistent/file.pcap")

        assert sessions == []

    def test_analyze_activation_traffic_detects_ticket_traffic(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
        tmp_path: Any,
    ) -> None:
        """Analyzer identifies and parses Denuvo tickets in network traffic."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required")

        pcap_file = tmp_path / "activation.pcap"

        with open(pcap_file, "wb") as f:
            pcap_writer = dpkt.pcap.Writer(f)

            eth = dpkt.ethernet.Ethernet()
            ip_packet = dpkt.ip.IP()
            tcp_packet = dpkt.tcp.TCP()
            tcp_packet.data = real_ticket_v7

            ip_packet.data = tcp_packet
            ip_packet.p = dpkt.ip.IP_PROTO_TCP
            eth.data = ip_packet
            eth.type = dpkt.ethernet.ETH_TYPE_IP

            pcap_writer.writepkt(eth.pack(), ts=time.time())

        sessions = analyzer.analyze_activation_traffic(str(pcap_file))

        assert len(sessions) > 0
        assert any(s.get("type") == "ticket" for s in sessions)

    def test_analyze_activation_traffic_detects_token_traffic(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_token_v7: bytes,
        tmp_path: Any,
    ) -> None:
        """Analyzer identifies and parses activation tokens in traffic."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required")

        pcap_file = tmp_path / "token.pcap"

        with open(pcap_file, "wb") as f:
            pcap_writer = dpkt.pcap.Writer(f)

            eth = dpkt.ethernet.Ethernet()
            ip_packet = dpkt.ip.IP()
            tcp_packet = dpkt.tcp.TCP()
            tcp_packet.data = real_token_v7

            ip_packet.data = tcp_packet
            ip_packet.p = dpkt.ip.IP_PROTO_TCP
            eth.data = ip_packet
            eth.type = dpkt.ethernet.ETH_TYPE_IP

            pcap_writer.writepkt(eth.pack(), ts=time.time())

        sessions = analyzer.analyze_activation_traffic(str(pcap_file))

        assert len(sessions) > 0
        assert any(s.get("type") == "token" for s in sessions)


class TestEncryptionDecryption:
    """Tests for cryptographic operations."""

    def test_decrypt_aes256_cbc_with_valid_key(
        self,
        analyzer: DenuvoTicketAnalyzer,
        encryption_key: bytes,
        iv: bytes,
    ) -> None:
        """Decryption succeeds with correct AES-256-CBC key."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        plaintext = b"Test payload data for Denuvo ticket"
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        decrypted = analyzer._decrypt_aes256_cbc(ciphertext, encryption_key, iv)

        assert decrypted == plaintext

    def test_decrypt_aes128_cbc_with_valid_key(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Decryption succeeds with correct AES-128-CBC key."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        key = os.urandom(16)
        iv = os.urandom(16)
        plaintext = b"AES-128 test payload"
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        decrypted = analyzer._decrypt_aes128_cbc(ciphertext, key, iv)

        assert decrypted == plaintext

    def test_decrypt_aes256_gcm_with_valid_key(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Decryption succeeds with correct AES-256-GCM key and tag."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        key = os.urandom(32)
        nonce = os.urandom(12)
        plaintext = b"GCM authenticated encryption test"

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        ciphertext_with_tag = ciphertext + tag

        decrypted = analyzer._decrypt_aes256_gcm(ciphertext_with_tag, key, nonce)

        assert decrypted == plaintext

    def test_decrypt_with_wrong_key_returns_none(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Decryption fails gracefully with incorrect key."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        correct_key = os.urandom(32)
        wrong_key = os.urandom(32)
        iv = os.urandom(16)
        plaintext = b"Secret data"

        cipher = AES.new(correct_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        decrypted = analyzer._decrypt_aes256_cbc(ciphertext, wrong_key, iv)

        assert decrypted is None


class TestSignatureOperations:
    """Tests for signature generation and verification."""

    def test_sign_data_creates_hmac_signature(
        self,
        analyzer: DenuvoTicketAnalyzer,
    ) -> None:
        """Signer creates HMAC signature over data."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        test_data = b"Data to sign for Denuvo"
        signature = analyzer._sign_data(test_data)

        assert len(signature) == 256
        assert signature != b"\x00" * 256

    def test_sign_token_creates_signature(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_token_v7: bytes,
    ) -> None:
        """Token signer creates signature over token data."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        token_data = real_token_v7[:-256]
        signature = analyzer._sign_token(token_data)

        assert len(signature) == 256

    def test_verify_signature_with_hmac_key(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
    ) -> None:
        """Verifier validates HMAC signatures correctly."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        ticket = analyzer.parse_ticket(real_ticket_v7)
        assert ticket is not None

        is_valid = analyzer._verify_signature(ticket)

        assert is_valid is True


class TestDataStructures:
    """Tests for data structure creation and validation."""

    def test_ticket_header_structure(self) -> None:
        """TicketHeader dataclass contains all required fields."""
        header = TicketHeader(
            magic=b"DNV7",
            version=7,
            flags=0x01,
            timestamp=int(time.time()),
            ticket_size=2048,
            payload_offset=128,
            signature_offset=1792,
            encryption_type=0x02,
            compression_type=0x00,
            reserved=b"\x00" * 102,
        )

        assert header.magic == b"DNV7"
        assert header.version == 7
        assert header.encryption_type == 0x02

    def test_machine_identifier_structure(self, machine_id: bytes) -> None:
        """MachineIdentifier dataclass contains all hash fields."""
        identifier = MachineIdentifier(
            hwid_hash=hashlib.sha256(machine_id + b"hwid").digest(),
            cpu_hash=hashlib.sha256(machine_id + b"cpu").digest(),
            disk_hash=hashlib.sha256(machine_id + b"disk").digest(),
            mac_hash=hashlib.sha256(machine_id + b"mac").digest(),
            bios_hash=hashlib.sha256(machine_id + b"bios").digest(),
            combined_hash=machine_id,
            salt=os.urandom(16),
        )

        assert len(identifier.hwid_hash) == 32
        assert len(identifier.cpu_hash) == 32
        assert len(identifier.combined_hash) == 32

    def test_activation_token_structure(self, game_id: bytes, machine_id: bytes) -> None:
        """ActivationToken dataclass contains all token fields."""
        token = ActivationToken(
            token_id=os.urandom(16),
            game_id=game_id,
            ticket_hash=hashlib.sha256(b"ticket").digest(),
            machine_id=machine_id,
            activation_time=int(time.time()),
            expiration_time=int(time.time()) + 86400,
            license_type=0x04,
            features_enabled=0xFFFFFFFF,
            signature=os.urandom(256),
        )

        assert len(token.token_id) == 16
        assert token.license_type == 0x04
        assert token.features_enabled == 0xFFFFFFFF


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_parse_empty_data(self, analyzer: DenuvoTicketAnalyzer) -> None:
        """Parser rejects empty input."""
        result = analyzer.parse_ticket(b"")

        assert result is None

    def test_parse_null_bytes(self, analyzer: DenuvoTicketAnalyzer) -> None:
        """Parser rejects all-null data."""
        result = analyzer.parse_ticket(b"\x00" * 200)

        assert result is None

    def test_forge_token_without_crypto(self, analyzer: DenuvoTicketAnalyzer, game_id: bytes, machine_id: bytes) -> None:
        """Forger returns None when crypto unavailable."""
        original_crypto = analyzer.crypto_available
        analyzer.crypto_available = False

        result = analyzer.forge_token(game_id, machine_id)

        analyzer.crypto_available = original_crypto
        assert result is None

    def test_convert_trial_with_invalid_ticket(self, analyzer: DenuvoTicketAnalyzer) -> None:
        """Converter returns None for unparseable ticket."""
        invalid_ticket = b"INVALID" + (b"\x00" * 200)

        result = analyzer.convert_trial_to_full(invalid_ticket)

        assert result is None

    def test_extract_game_id_from_short_request(self, analyzer: DenuvoTicketAnalyzer) -> None:
        """Game ID extractor handles truncated requests."""
        short_request = b"\x00" * 10

        game_id = analyzer._extract_game_id(short_request)

        assert game_id is not None
        assert len(game_id) == 16

    def test_extract_machine_id_from_short_request(self, analyzer: DenuvoTicketAnalyzer) -> None:
        """Machine ID extractor handles truncated requests."""
        short_request = b"\x00" * 20

        machine_id = analyzer._extract_machine_id(short_request)

        assert machine_id is not None
        assert len(machine_id) == 32


class TestConstants:
    """Tests for analyzer constants."""

    def test_ticket_magic_constants(self, analyzer: DenuvoTicketAnalyzer) -> None:
        """Analyzer defines all ticket version magic bytes."""
        assert analyzer.TICKET_MAGIC_V4 == b"DNV4"
        assert analyzer.TICKET_MAGIC_V5 == b"DNV5"
        assert analyzer.TICKET_MAGIC_V6 == b"DNV6"
        assert analyzer.TICKET_MAGIC_V7 == b"DNV7"

    def test_encryption_type_constants(self, analyzer: DenuvoTicketAnalyzer) -> None:
        """Analyzer defines all encryption types."""
        assert analyzer.ENCRYPTION_NONE == 0x00
        assert analyzer.ENCRYPTION_AES128_CBC == 0x01
        assert analyzer.ENCRYPTION_AES256_CBC == 0x02
        assert analyzer.ENCRYPTION_AES256_GCM == 0x03
        assert analyzer.ENCRYPTION_CHACHA20 == 0x04

    def test_license_type_constants(self, analyzer: DenuvoTicketAnalyzer) -> None:
        """Analyzer defines all license types."""
        assert analyzer.LICENSE_TRIAL == 0x01
        assert analyzer.LICENSE_FULL == 0x02
        assert analyzer.LICENSE_SUBSCRIPTION == 0x03
        assert analyzer.LICENSE_PERPETUAL == 0x04

    def test_header_size_constants(self, analyzer: DenuvoTicketAnalyzer) -> None:
        """Analyzer defines correct header sizes for each version."""
        assert analyzer.HEADER_SIZE_V4 == 64
        assert analyzer.HEADER_SIZE_V5 == 80
        assert analyzer.HEADER_SIZE_V6 == 96
        assert analyzer.HEADER_SIZE_V7 == 128


class TestIntegration:
    """Integration tests for complete workflows."""

    def test_full_offline_activation_workflow(
        self,
        analyzer: DenuvoTicketAnalyzer,
        game_id: bytes,
        machine_id: bytes,
    ) -> None:
        """Complete workflow: request -> response -> token forging -> validation."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        request = b"\x00" * 16 + game_id + machine_id
        response = analyzer.generate_activation_response(request, license_type=analyzer.LICENSE_PERPETUAL)

        assert response is not None

        ticket = analyzer.parse_ticket(response.ticket)
        assert ticket is not None
        assert ticket.payload is not None

        token = analyzer.parse_token(response.token)
        assert token is not None
        assert token.license_type == analyzer.LICENSE_PERPETUAL
        assert token.features_enabled == 0xFFFFFFFF

    def test_trial_to_full_conversion_workflow(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
    ) -> None:
        """Complete workflow: parse trial -> convert -> verify full license."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        original = analyzer.parse_ticket(real_ticket_v7)
        assert original is not None

        converted = analyzer.convert_trial_to_full(real_ticket_v7)
        assert converted is not None

        full_ticket = analyzer.parse_ticket(converted)
        assert full_ticket is not None
        assert full_ticket.payload is not None
        assert full_ticket.payload.license_data["type"] == analyzer.LICENSE_PERPETUAL

    def test_machine_id_spoofing_workflow(
        self,
        analyzer: DenuvoTicketAnalyzer,
        real_ticket_v7: bytes,
    ) -> None:
        """Complete workflow: extract ID -> spoof -> verify change."""
        if not CRYPTO_AVAILABLE:
            pytest.skip("Crypto library required")

        original_id = analyzer.extract_machine_id(real_ticket_v7)
        assert original_id is not None

        new_id = hashlib.sha256(b"target_machine").digest()
        spoofed_ticket = analyzer.spoof_machine_id(real_ticket_v7, new_id)
        assert spoofed_ticket is not None

        extracted_id = analyzer.extract_machine_id(spoofed_ticket)
        assert extracted_id == new_id
        assert extracted_id != original_id
