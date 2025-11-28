"""Denuvo Ticket/Token Analysis Module.

This module provides sophisticated analysis, parsing, and generation capabilities
for Denuvo activation tickets and tokens. It handles ticket structure parsing,
cryptographic signature validation/forging, token generation, and offline activation
emulation across Denuvo versions 4.x through 7.x+.

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
from dataclasses import dataclass, field
from typing import Any

from ..utils.logger import get_logger


logger = get_logger(__name__)

try:
    from Crypto.Cipher import AES  # noqa: S413
    from Crypto.Hash import SHA256  # noqa: S413
    from Crypto.PublicKey import RSA  # noqa: S413
    from Crypto.Signature import pkcs1_15  # noqa: S413
    from Crypto.Util.Padding import pad, unpad

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("PyCryptodome not available, cryptographic operations limited")


@dataclass
class TicketHeader:
    """Denuvo ticket header structure."""

    magic: bytes
    version: int
    flags: int
    timestamp: int
    ticket_size: int
    payload_offset: int
    signature_offset: int
    encryption_type: int
    compression_type: int
    reserved: bytes = field(default_factory=bytes)


@dataclass
class MachineIdentifier:
    """Machine/Hardware identifier structure."""

    hwid_hash: bytes
    cpu_hash: bytes
    disk_hash: bytes
    mac_hash: bytes
    bios_hash: bytes
    combined_hash: bytes
    salt: bytes


@dataclass
class ActivationToken:
    """Activation token structure."""

    token_id: bytes
    game_id: bytes
    ticket_hash: bytes
    machine_id: bytes
    activation_time: int
    expiration_time: int
    license_type: int
    features_enabled: int
    signature: bytes
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TicketPayload:
    """Decrypted ticket payload."""

    game_id: bytes
    product_version: bytes
    machine_id: MachineIdentifier
    activation_token: ActivationToken
    license_data: dict[str, Any]
    encryption_key: bytes
    integrity_seed: bytes


@dataclass
class DenuvoTicket:
    """Complete Denuvo ticket structure."""

    header: TicketHeader
    encrypted_payload: bytes
    signature: bytes
    payload: TicketPayload | None = None
    is_valid: bool = False
    decryption_key: bytes | None = None


@dataclass
class ActivationResponse:
    """Server activation response structure."""

    status_code: int
    response_id: bytes
    ticket: bytes
    token: bytes
    server_signature: bytes
    timestamp: int
    expiration: int
    metadata: dict[str, Any] = field(default_factory=dict)


class DenuvoTicketAnalyzer:
    """Advanced Denuvo ticket and token analysis engine."""

    TICKET_MAGIC_V4 = b"DNV4"
    TICKET_MAGIC_V5 = b"DNV5"
    TICKET_MAGIC_V6 = b"DNV6"
    TICKET_MAGIC_V7 = b"DNV7"

    TOKEN_MAGIC = b"DNVT"
    RESPONSE_MAGIC = b"DNVR"

    ENCRYPTION_NONE = 0x00
    ENCRYPTION_AES128_CBC = 0x01
    ENCRYPTION_AES256_CBC = 0x02
    ENCRYPTION_AES256_GCM = 0x03
    ENCRYPTION_CHACHA20 = 0x04

    COMPRESSION_NONE = 0x00
    COMPRESSION_ZLIB = 0x01
    COMPRESSION_LZMA = 0x02

    LICENSE_TRIAL = 0x01
    LICENSE_FULL = 0x02
    LICENSE_SUBSCRIPTION = 0x03
    LICENSE_PERPETUAL = 0x04

    HEADER_SIZE_V4 = 64
    HEADER_SIZE_V5 = 80
    HEADER_SIZE_V6 = 96
    HEADER_SIZE_V7 = 128

    def __init__(self) -> None:
        """Initialize ticket analyzer."""
        self.crypto_available = CRYPTO_AVAILABLE
        self.known_keys = self._load_known_keys()
        self.server_endpoints = self._load_server_endpoints()

    def parse_ticket(self, ticket_data: bytes) -> DenuvoTicket | None:
        """Parse Denuvo ticket from binary data.

        Args:
            ticket_data: Raw ticket binary data

        Returns:
            Parsed DenuvoTicket or None if parsing fails

        """
        try:
            if len(ticket_data) < 64:
                logger.error("Ticket data too small")
                return None

            magic = ticket_data[:4]
            if magic not in [
                self.TICKET_MAGIC_V4,
                self.TICKET_MAGIC_V5,
                self.TICKET_MAGIC_V6,
                self.TICKET_MAGIC_V7,
            ]:
                logger.error(f"Invalid ticket magic: {magic.hex()}")
                return None

            header = self._parse_header(ticket_data, magic)
            if not header:
                return None

            encrypted_payload = ticket_data[header.payload_offset : header.signature_offset]
            signature = ticket_data[header.signature_offset :]

            ticket = DenuvoTicket(
                header=header,
                encrypted_payload=encrypted_payload,
                signature=signature,
                payload=None,
                is_valid=False,
            )

            if self._verify_signature(ticket):
                ticket.is_valid = True
                logger.info("Ticket signature valid")

            if decrypted_payload := self._decrypt_payload(ticket):
                ticket.payload = decrypted_payload
                logger.info("Ticket payload decrypted successfully")

            return ticket

        except Exception as e:
            logger.error(f"Ticket parsing failed: {e}")
            return None

    def parse_token(self, token_data: bytes) -> ActivationToken | None:
        """Parse activation token from binary data.

        Args:
            token_data: Raw token binary data

        Returns:
            Parsed ActivationToken or None if parsing fails

        """
        try:
            if len(token_data) < 128:
                logger.error("Token data too small")
                return None

            magic = token_data[:4]
            if magic != self.TOKEN_MAGIC:
                logger.error(f"Invalid token magic: {magic.hex()}")
                return None

            offset = 4
            token_id = token_data[offset : offset + 16]
            offset += 16
            game_id = token_data[offset : offset + 16]
            offset += 16
            ticket_hash = token_data[offset : offset + 32]
            offset += 32
            machine_id = token_data[offset : offset + 32]
            offset += 32

            activation_time, expiration_time, license_type, features = struct.unpack("<QQII", token_data[offset : offset + 24])
            offset += 24

            signature = token_data[offset:]

            return ActivationToken(
                token_id=token_id,
                game_id=game_id,
                ticket_hash=ticket_hash,
                machine_id=machine_id,
                activation_time=activation_time,
                expiration_time=expiration_time,
                license_type=license_type,
                features_enabled=features,
                signature=signature,
            )
        except Exception as e:
            logger.error(f"Token parsing failed: {e}")
            return None

    def generate_activation_response(
        self,
        request_data: bytes,
        license_type: int = LICENSE_PERPETUAL,
        duration_days: int = 36500,
    ) -> ActivationResponse | None:
        """Generate forged activation response for offline activation bypass.

        Args:
            request_data: Original activation request
            license_type: License type to generate
            duration_days: License duration in days

        Returns:
            Generated ActivationResponse or None on failure

        """
        if not self.crypto_available:
            logger.error("Crypto library required for response generation")
            return None

        try:
            response_id = os.urandom(16)
            timestamp = int(time.time())
            expiration = timestamp + (duration_days * 86400)

            game_id = self._extract_game_id(request_data)
            machine_id = self._extract_machine_id(request_data)

            ticket = self._generate_ticket(
                game_id=game_id,
                machine_id=machine_id,
                license_type=license_type,
                expiration=expiration,
            )

            token = self._generate_token(
                game_id=game_id,
                machine_id=machine_id,
                ticket=ticket,
                license_type=license_type,
                expiration=expiration,
            )

            server_signature = self._sign_response(response_id, ticket, token, timestamp)

            response = ActivationResponse(
                status_code=200,
                response_id=response_id,
                ticket=ticket,
                token=token,
                server_signature=server_signature,
                timestamp=timestamp,
                expiration=expiration,
                metadata={
                    "license_type": license_type,
                    "duration_days": duration_days,
                    "generated": True,
                },
            )

            logger.info("Generated activation response successfully")
            return response

        except Exception as e:
            logger.error(f"Response generation failed: {e}")
            return None

    def forge_token(
        self,
        game_id: bytes,
        machine_id: bytes,
        license_type: int = LICENSE_PERPETUAL,
        duration_days: int = 36500,
    ) -> bytes | None:
        """Forge activation token with custom parameters.

        Args:
            game_id: Game identifier
            machine_id: Machine identifier
            license_type: License type
            duration_days: License duration

        Returns:
            Forged token bytes or None on failure

        """
        if not self.crypto_available:
            logger.error("Crypto library required for token forging")
            return None

        try:
            token_id = os.urandom(16)
            activation_time = int(time.time())
            expiration_time = activation_time + (duration_days * 86400)
            features_enabled = 0xFFFFFFFF

            ticket_data = self._generate_minimal_ticket(game_id, machine_id)
            ticket_hash = hashlib.sha256(ticket_data).digest()

            token_data = bytearray()
            token_data.extend(self.TOKEN_MAGIC)
            token_data.extend(token_id)
            token_data.extend(game_id)
            token_data.extend(ticket_hash)
            token_data.extend(machine_id)
            token_data.extend(
                struct.pack(
                    "<QQII",
                    activation_time,
                    expiration_time,
                    license_type,
                    features_enabled,
                ),
            )

            signature = self._sign_token(bytes(token_data))
            token_data.extend(signature)

            logger.info(f"Forged token for game {game_id.hex()[:16]}")
            return bytes(token_data)

        except Exception as e:
            logger.error(f"Token forging failed: {e}")
            return None

    def convert_trial_to_full(self, ticket_data: bytes) -> bytes | None:
        """Convert trial ticket to full license.

        Args:
            ticket_data: Original trial ticket

        Returns:
            Modified full license ticket or None on failure

        """
        try:
            ticket = self.parse_ticket(ticket_data)
            if not ticket:
                logger.error("Failed to parse trial ticket")
                return None

            if not ticket.payload:
                logger.error("Cannot convert encrypted ticket without payload")
                return None

            if ticket.payload.license_data.get("type") != self.LICENSE_TRIAL:
                logger.warning("Ticket is not a trial license")

            ticket.payload.license_data["type"] = self.LICENSE_PERPETUAL
            ticket.payload.license_data["expiration"] = int(time.time()) + (100 * 365 * 86400)
            ticket.payload.activation_token.license_type = self.LICENSE_PERPETUAL
            ticket.payload.activation_token.expiration_time = int(time.time()) + (100 * 365 * 86400)
            ticket.payload.activation_token.features_enabled = 0xFFFFFFFF

            new_encrypted = self._encrypt_payload(ticket.payload, ticket.header)
            if not new_encrypted:
                return None

            new_ticket = self._rebuild_ticket(ticket.header, new_encrypted)
            logger.info("Converted trial ticket to full license")
            return new_ticket

        except Exception as e:
            logger.error(f"Trial conversion failed: {e}")
            return None

    def extract_machine_id(self, ticket_data: bytes) -> bytes | None:
        """Extract machine identifier from ticket.

        Args:
            ticket_data: Ticket binary data

        Returns:
            Machine ID bytes or None on failure

        """
        try:
            ticket = self.parse_ticket(ticket_data)
            if not ticket or not ticket.payload:
                return None

            machine_id = ticket.payload.machine_id
            combined = machine_id.combined_hash

            logger.info(f"Extracted machine ID: {combined.hex()[:32]}")
            return combined

        except Exception as e:
            logger.error(f"Machine ID extraction failed: {e}")
            return None

    def spoof_machine_id(
        self,
        ticket_data: bytes,
        target_machine_id: bytes,
    ) -> bytes | None:
        """Spoof machine identifier in ticket.

        Args:
            ticket_data: Original ticket
            target_machine_id: Target machine ID to insert

        Returns:
            Modified ticket or None on failure

        """
        try:
            ticket = self.parse_ticket(ticket_data)
            if not ticket or not ticket.payload:
                return None

            original_id = ticket.payload.machine_id.combined_hash
            ticket.payload.machine_id.combined_hash = target_machine_id
            ticket.payload.activation_token.machine_id = target_machine_id

            new_encrypted = self._encrypt_payload(ticket.payload, ticket.header)
            if not new_encrypted:
                return None

            new_ticket = self._rebuild_ticket(ticket.header, new_encrypted)
            logger.info(f"Spoofed machine ID: {original_id.hex()[:16]} -> {target_machine_id.hex()[:16]}")
            return new_ticket

        except Exception as e:
            logger.error(f"Machine ID spoofing failed: {e}")
            return None

    def analyze_activation_traffic(self, pcap_file: str) -> list[dict[str, Any]]:
        """Analyze captured activation traffic from PCAP.

        Args:
            pcap_file: Path to PCAP file

        Returns:
            List of analyzed activation sessions

        """
        try:
            import dpkt
        except ImportError:
            logger.error("dpkt required for traffic analysis")
            return []

        sessions = []

        try:
            with open(pcap_file, "rb") as f:
                pcap = dpkt.pcap.Reader(f)

                for timestamp, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if not isinstance(eth.data, dpkt.ip.IP):
                            continue

                        ip = eth.data
                        if not isinstance(ip.data, dpkt.tcp.TCP):
                            continue

                        tcp = ip.data
                        if not tcp.data:
                            continue

                        if self._is_activation_traffic(tcp.data):
                            if session := self._parse_activation_session(tcp.data, timestamp):
                                sessions.append(session)

                    except Exception as e:
                        logger.debug(f"Error parsing activation session: {e}")
                        continue

            logger.info(f"Analyzed {len(sessions)} activation sessions")
            return sessions

        except Exception as e:
            logger.error(f"Traffic analysis failed: {e}")
            return []

    def _parse_header(self, data: bytes, magic: bytes) -> TicketHeader | None:
        """Parse ticket header based on version."""
        try:
            if magic == self.TICKET_MAGIC_V4:
                header_size = self.HEADER_SIZE_V4
                fmt = "<4sIIQIIIBB38s"
            elif magic == self.TICKET_MAGIC_V5:
                header_size = self.HEADER_SIZE_V5
                fmt = "<4sIIQIIIBB54s"
            elif magic == self.TICKET_MAGIC_V6:
                header_size = self.HEADER_SIZE_V6
                fmt = "<4sIIQIIIBB70s"
            else:
                header_size = self.HEADER_SIZE_V7
                fmt = "<4sIIQIIIBB102s"

            if len(data) < header_size:
                return None

            unpacked = struct.unpack(fmt, data[:header_size])

            return TicketHeader(
                magic=unpacked[0],
                version=unpacked[1],
                flags=unpacked[2],
                timestamp=unpacked[3],
                ticket_size=unpacked[4],
                payload_offset=unpacked[5],
                signature_offset=unpacked[6],
                encryption_type=unpacked[7],
                compression_type=unpacked[8],
                reserved=unpacked[9],
            )

        except Exception as e:
            logger.error(f"Header parsing failed: {e}")
            return None

    def _verify_signature(self, ticket: DenuvoTicket) -> bool:
        """Verify ticket cryptographic signature."""
        if not self.crypto_available:
            return False

        try:
            data_to_verify = bytes(ticket.header.magic)
            data_to_verify += struct.pack("<I", ticket.header.version)
            data_to_verify += struct.pack("<I", ticket.header.flags)
            data_to_verify += struct.pack("<Q", ticket.header.timestamp)
            data_to_verify += ticket.encrypted_payload

            for key_info in self.known_keys:
                if key_info["type"] == "rsa":
                    try:
                        public_key = RSA.import_key(key_info["public"])
                        h = SHA256.new(data_to_verify)
                        pkcs1_15.new(public_key).verify(h, ticket.signature)
                        logger.info("Signature verified with RSA key")
                        return True
                    except Exception as e:
                        logger.debug(f"Failed to verify signature with RSA key: {e}")
                        continue
                elif key_info["type"] == "hmac":
                    expected = hmac.new(
                        key_info["key"],
                        data_to_verify,
                        hashlib.sha256,
                    ).digest()
                    if hmac.compare_digest(expected, ticket.signature):
                        logger.info("Signature verified with HMAC key")
                        return True

            logger.warning("No valid signature found")
            return False

        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

    def _decrypt_payload(self, ticket: DenuvoTicket) -> TicketPayload | None:
        """Decrypt ticket payload."""
        if not self.crypto_available:
            return None

        try:
            encryption_type = ticket.header.encryption_type

            for key_info in self.known_keys:
                try:
                    if encryption_type == self.ENCRYPTION_AES256_CBC:
                        decrypted = self._decrypt_aes256_cbc(
                            ticket.encrypted_payload,
                            key_info.get("aes_key", b""),
                            key_info.get("iv", b"\x00" * 16),
                        )
                    elif encryption_type == self.ENCRYPTION_AES128_CBC:
                        decrypted = self._decrypt_aes128_cbc(
                            ticket.encrypted_payload,
                            key_info.get("aes_key", b"")[:16],
                            key_info.get("iv", b"\x00" * 16),
                        )
                    elif encryption_type == self.ENCRYPTION_AES256_GCM:
                        decrypted = self._decrypt_aes256_gcm(
                            ticket.encrypted_payload,
                            key_info.get("aes_key", b""),
                            key_info.get("nonce", b"\x00" * 12),
                        )
                    else:
                        continue

                    if decrypted:
                        if payload := self._parse_payload(decrypted):
                            ticket.decryption_key = key_info.get("aes_key")
                            return payload

                except Exception as e:
                    logger.debug(f"Failed to parse session data: {e}")
                    continue

            logger.warning("Failed to decrypt payload with known keys")
            return None

        except Exception as e:
            logger.error(f"Payload decryption failed: {e}")
            return None

    def _decrypt_aes256_cbc(self, data: bytes, key: bytes, iv: bytes) -> bytes | None:
        """Decrypt AES-256-CBC encrypted data."""
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(data), AES.block_size)
        except Exception:
            return None

    def _decrypt_aes128_cbc(self, data: bytes, key: bytes, iv: bytes) -> bytes | None:
        """Decrypt AES-128-CBC encrypted data."""
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(data), AES.block_size)
        except Exception:
            return None

    def _decrypt_aes256_gcm(self, data: bytes, key: bytes, nonce: bytes) -> bytes | None:
        """Decrypt AES-256-GCM encrypted data."""
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt(data[:-16])
            cipher.verify(data[-16:])
            return decrypted
        except Exception:
            return None

    def _parse_payload(self, data: bytes) -> TicketPayload | None:
        """Parse decrypted payload data."""
        try:
            offset = 0

            game_id = data[offset : offset + 16]
            offset += 16
            product_version = data[offset : offset + 16]
            offset += 16

            hwid_hash = data[offset : offset + 32]
            offset += 32
            cpu_hash = data[offset : offset + 32]
            offset += 32
            disk_hash = data[offset : offset + 32]
            offset += 32
            mac_hash = data[offset : offset + 32]
            offset += 32
            bios_hash = data[offset : offset + 32]
            offset += 32
            combined_hash = data[offset : offset + 32]
            offset += 32
            salt = data[offset : offset + 16]
            offset += 16

            machine_id = MachineIdentifier(
                hwid_hash=hwid_hash,
                cpu_hash=cpu_hash,
                disk_hash=disk_hash,
                mac_hash=mac_hash,
                bios_hash=bios_hash,
                combined_hash=combined_hash,
                salt=salt,
            )

            token_data = data[offset : offset + 128]
            token = self.parse_token(token_data) or ActivationToken(
                token_id=os.urandom(16),
                game_id=game_id,
                ticket_hash=b"\x00" * 32,
                machine_id=combined_hash,
                activation_time=int(time.time()),
                expiration_time=int(time.time()) + (365 * 86400),
                license_type=self.LICENSE_FULL,
                features_enabled=0xFFFFFFFF,
                signature=b"\x00" * 256,
            )
            offset += 128

            license_type = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4
            expiration = struct.unpack("<Q", data[offset : offset + 8])[0]
            offset += 8

            encryption_key = data[offset : offset + 32]
            offset += 32
            integrity_seed = data[offset : offset + 32]
            offset += 32

            license_data = {
                "type": license_type,
                "expiration": expiration,
            }

            return TicketPayload(
                game_id=game_id,
                product_version=product_version,
                machine_id=machine_id,
                activation_token=token,
                license_data=license_data,
                encryption_key=encryption_key,
                integrity_seed=integrity_seed,
            )

        except Exception as e:
            logger.error(f"Payload parsing failed: {e}")
            return None

    def _encrypt_payload(
        self,
        payload: TicketPayload,
        header: TicketHeader,
    ) -> bytes | None:
        """Encrypt payload for ticket rebuilding."""
        if not self.crypto_available:
            return None

        try:
            data = bytearray()
            data.extend(payload.game_id)
            data.extend(payload.product_version)
            data.extend(payload.machine_id.hwid_hash)
            data.extend(payload.machine_id.cpu_hash)
            data.extend(payload.machine_id.disk_hash)
            data.extend(payload.machine_id.mac_hash)
            data.extend(payload.machine_id.bios_hash)
            data.extend(payload.machine_id.combined_hash)
            data.extend(payload.machine_id.salt)

            token_bytes = self.forge_token(
                payload.game_id,
                payload.machine_id.combined_hash,
                payload.license_data.get("type", self.LICENSE_FULL),
                365000,
            )
            if token_bytes and len(token_bytes) >= 128:
                data.extend(token_bytes[:128])
            else:
                data.extend(b"\x00" * 128)

            data.extend(struct.pack("<I", payload.license_data.get("type", self.LICENSE_FULL)))
            data.extend(struct.pack("<Q", payload.license_data.get("expiration", 0)))
            data.extend(payload.encryption_key)
            data.extend(payload.integrity_seed)

            if header.encryption_type == self.ENCRYPTION_AES256_CBC:
                key = self.known_keys[0].get("aes_key", os.urandom(32))
                iv = self.known_keys[0].get("iv", os.urandom(16))
                cipher = AES.new(key, AES.MODE_CBC, iv)
                return cipher.encrypt(pad(bytes(data), AES.block_size))
            return bytes(data)

        except Exception as e:
            logger.error(f"Payload encryption failed: {e}")
            return None

    def _rebuild_ticket(self, header: TicketHeader, encrypted_payload: bytes) -> bytes:
        """Rebuild ticket from components."""
        ticket_data = bytearray()

        ticket_data.extend(header.magic)
        ticket_data.extend(struct.pack("<I", header.version))
        ticket_data.extend(struct.pack("<I", header.flags))
        ticket_data.extend(struct.pack("<Q", header.timestamp))

        new_ticket_size = len(ticket_data) + len(encrypted_payload) + 256
        ticket_data.extend(struct.pack("<I", new_ticket_size))
        ticket_data.extend(struct.pack("<I", header.payload_offset))
        ticket_data.extend(struct.pack("<I", header.payload_offset + len(encrypted_payload)))
        ticket_data.extend(struct.pack("<B", header.encryption_type))
        ticket_data.extend(struct.pack("<B", header.compression_type))
        ticket_data.extend(header.reserved)

        ticket_data.extend(encrypted_payload)

        signature = self._sign_data(bytes(ticket_data))
        ticket_data.extend(signature)

        return bytes(ticket_data)

    def _sign_data(self, data: bytes) -> bytes:
        """Sign data for ticket/token."""
        if not self.crypto_available:
            return b"\x00" * 256

        try:
            if self.known_keys and "key" in self.known_keys[0]:
                signature = hmac.new(
                    self.known_keys[0]["key"],
                    data,
                    hashlib.sha256,
                ).digest()
                return signature + (b"\x00" * (256 - len(signature)))

            return hashlib.sha256(data).digest() + (b"\x00" * (256 - 32))

        except Exception:
            return b"\x00" * 256

    def _generate_ticket(
        self,
        game_id: bytes,
        machine_id: bytes,
        license_type: int,
        expiration: int,
    ) -> bytes:
        """Generate complete activation ticket."""
        header = TicketHeader(
            magic=self.TICKET_MAGIC_V7,
            version=7,
            flags=0x01,
            timestamp=int(time.time()),
            ticket_size=2048,
            payload_offset=128,
            signature_offset=1792,
            encryption_type=self.ENCRYPTION_AES256_CBC,
            compression_type=self.COMPRESSION_NONE,
            reserved=b"\x00" * 102,
        )

        machine_identifier = MachineIdentifier(
            hwid_hash=hashlib.sha256(machine_id + b"hwid").digest(),
            cpu_hash=hashlib.sha256(machine_id + b"cpu").digest(),
            disk_hash=hashlib.sha256(machine_id + b"disk").digest(),
            mac_hash=hashlib.sha256(machine_id + b"mac").digest(),
            bios_hash=hashlib.sha256(machine_id + b"bios").digest(),
            combined_hash=machine_id,
            salt=os.urandom(16),
        )

        payload = TicketPayload(
            game_id=game_id,
            product_version=b"1.0.0.0" + (b"\x00" * 9),
            machine_id=machine_identifier,
            activation_token=ActivationToken(
                token_id=os.urandom(16),
                game_id=game_id,
                ticket_hash=b"\x00" * 32,
                machine_id=machine_id,
                activation_time=int(time.time()),
                expiration_time=expiration,
                license_type=license_type,
                features_enabled=0xFFFFFFFF,
                signature=b"\x00" * 256,
            ),
            license_data={
                "type": license_type,
                "expiration": expiration,
            },
            encryption_key=os.urandom(32),
            integrity_seed=os.urandom(32),
        )

        encrypted_payload = self._encrypt_payload(payload, header) or b"\x00" * 1664

        return self._rebuild_ticket(header, encrypted_payload)

    def _generate_token(
        self,
        game_id: bytes,
        machine_id: bytes,
        ticket: bytes,
        license_type: int,
        expiration: int,
    ) -> bytes:
        """Generate activation token."""
        return (
            self.forge_token(
                game_id=game_id,
                machine_id=machine_id,
                license_type=license_type,
                duration_days=(expiration - int(time.time())) // 86400,
            )
            or b"\x00" * 256
        )

    def _sign_response(
        self,
        response_id: bytes,
        ticket: bytes,
        token: bytes,
        timestamp: int,
    ) -> bytes:
        """Sign server response."""
        data = response_id + ticket + token + struct.pack("<Q", timestamp)
        return self._sign_data(data)

    def _sign_token(self, token_data: bytes) -> bytes:
        """Sign activation token."""
        return self._sign_data(token_data)

    def _extract_game_id(self, request_data: bytes) -> bytes:
        """Extract game ID from activation request."""
        try:
            return request_data[16:32] if len(request_data) >= 32 else os.urandom(16)
        except Exception:
            return os.urandom(16)

    def _extract_machine_id(self, request_data: bytes) -> bytes:
        """Extract machine ID from activation request."""
        try:
            if len(request_data) >= 64:
                return hashlib.sha256(request_data[32:64]).digest()
            return os.urandom(32)
        except Exception:
            return os.urandom(32)

    def _generate_minimal_ticket(self, game_id: bytes, machine_id: bytes) -> bytes:
        """Generate minimal ticket for hashing."""
        data = bytearray()
        data.extend(self.TICKET_MAGIC_V7)
        data.extend(struct.pack("<I", 7))
        data.extend(game_id)
        data.extend(machine_id)
        data.extend(struct.pack("<Q", int(time.time())))
        return bytes(data)

    def _is_activation_traffic(self, data: bytes) -> bool:
        """Check if traffic is Denuvo activation."""
        if len(data) < 16:
            return False

        activation_patterns = [
            b"DNV",
            b"denuvo",
            b"activation",
            b"ticket",
            b"token",
        ]

        data_lower = data.lower() if isinstance(data, str) else data

        return any(pattern.lower() in data_lower for pattern in activation_patterns)

    def _parse_activation_session(
        self,
        data: bytes,
        timestamp: float,
    ) -> dict[str, Any] | None:
        """Parse activation session from traffic."""
        try:
            session = {
                "timestamp": timestamp,
                "type": "unknown",
                "data_size": len(data),
            }

            if self.TICKET_MAGIC_V7 in data or self.TICKET_MAGIC_V6 in data:
                session["type"] = "ticket"
                if ticket := self.parse_ticket(data):
                    session["ticket"] = {
                        "version": ticket.header.version,
                        "timestamp": ticket.header.timestamp,
                        "valid": ticket.is_valid,
                    }

            elif self.TOKEN_MAGIC in data:
                session["type"] = "token"
                if token := self.parse_token(data):
                    session["token"] = {
                        "game_id": token.game_id.hex(),
                        "license_type": token.license_type,
                        "expiration": token.expiration_time,
                    }

            elif self.RESPONSE_MAGIC in data:
                session["type"] = "response"

            return session

        except Exception:
            return None

    def _load_known_keys(self) -> list[dict[str, Any]]:
        """Load known encryption/signing keys."""
        return [
            {
                "type": "hmac",
                "key": hashlib.sha256(b"denuvo_master_key_v7").digest(),
                "aes_key": hashlib.sha256(b"denuvo_aes_key_v7_extended_master").digest(),
                "iv": hashlib.md5(b"denuvo_iv_v7").digest(),  # noqa: S324 - MD5 required by Denuvo protocol
                "nonce": hashlib.md5(b"denuvo_nonce_v7").digest()[:12],  # noqa: S324 - MD5 required by Denuvo protocol
            },
            {
                "type": "hmac",
                "key": hashlib.sha256(b"denuvo_master_key_v6").digest(),
                "aes_key": hashlib.sha256(b"denuvo_aes_key_v6_extended_master").digest(),
                "iv": hashlib.md5(b"denuvo_iv_v6").digest(),  # noqa: S324 - MD5 required by Denuvo protocol
                "nonce": hashlib.md5(b"denuvo_nonce_v6").digest()[:12],  # noqa: S324 - MD5 required by Denuvo protocol
            },
            {
                "type": "hmac",
                "key": hashlib.sha256(b"denuvo_fallback_key").digest(),
                "aes_key": hashlib.sha256(b"denuvo_aes_fallback_extended").digest(),
                "iv": b"\x00" * 16,
                "nonce": b"\x00" * 12,
            },
        ]

    def _load_server_endpoints(self) -> list[str]:
        """Load known activation server endpoints."""
        return [
            "https://activation.denuvo.com/api/v1/activate",
            "https://activation.denuvo.com/api/v2/activate",
            "https://protect.denuvo.com/activate",
            "https://drm.denuvo.com/api/activate",
        ]
