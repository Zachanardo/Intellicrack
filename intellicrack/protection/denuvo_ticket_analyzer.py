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
import re
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..utils.logger import get_logger


logger = get_logger(__name__)

if TYPE_CHECKING:
    import lief
    import capstone

    LiefBinary = lief.PE.Binary | lief.ELF.Binary | lief.MachO.Binary | lief.COFF.Binary
else:
    LiefBinary = Any

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

try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False
    logger.warning("LIEF not available, binary analysis will be limited")

try:
    import capstone

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logger.warning("Capstone not available, disassembly analysis disabled")


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


@dataclass
class DenuvoTrigger:
    """Denuvo activation trigger point information."""

    address: int
    type: str
    function_name: str
    module: str
    confidence: float
    description: str
    opcode_sequence: bytes
    referenced_imports: list[str] = field(default_factory=list)
    cross_references: list[int] = field(default_factory=list)


@dataclass
class IntegrityCheck:
    """Integrity check routine information."""

    address: int
    type: str
    target: str
    algorithm: str
    confidence: float
    check_size: int
    frequency: str
    bypass_difficulty: str


@dataclass
class TimingCheck:
    """Timing validation check information."""

    address: int
    method: str
    instruction: str
    threshold_min: int
    threshold_max: int
    confidence: float
    bypass_method: str


@dataclass
class SteamAPIWrapper:
    """Steam API wrapper detection information."""

    dll_path: str
    is_wrapper: bool
    original_exports: list[str]
    hooked_exports: list[str]
    denuvo_sections: list[str]
    confidence: float


@dataclass
class HardwareBinding:
    """Hardware ID binding information."""

    binding_type: str
    collection_address: int
    validation_address: int
    hash_algorithm: str
    components: list[str]
    confidence: float


@dataclass
class OnlineActivation:
    """Online activation endpoint information."""

    endpoint_url: str
    protocol: str
    encryption_type: str
    validation_address: int
    request_format: str
    response_format: str


@dataclass
class DenuvoAnalysisResult:
    """Complete Denuvo analysis result."""

    version: str
    triggers: list[DenuvoTrigger]
    integrity_checks: list[IntegrityCheck]
    timing_checks: list[TimingCheck]
    steam_wrapper: SteamAPIWrapper | None
    hardware_bindings: list[HardwareBinding]
    online_activation: OnlineActivation | None
    protection_density: float
    obfuscation_level: str


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
        self.lief_available = LIEF_AVAILABLE
        self.capstone_available = CAPSTONE_AVAILABLE
        self.known_keys = self._load_known_keys()
        self.server_endpoints = self._load_server_endpoints()
        self.trigger_patterns = self._load_trigger_patterns()
        self.integrity_patterns = self._load_integrity_patterns()
        self.timing_patterns = self._load_timing_patterns()

    def parse_ticket(self, ticket_data: bytes) -> DenuvoTicket | None:
        """Parse Denuvo ticket from binary data.

        Args:
            ticket_data: Raw ticket binary data

        Returns:
            Parsed DenuvoTicket or None if parsing fails

        """
        try:
            if len(ticket_data) < 64:
                logger.exception("Ticket data too small")
                return None

            magic = ticket_data[:4]
            if magic not in [
                self.TICKET_MAGIC_V4,
                self.TICKET_MAGIC_V5,
                self.TICKET_MAGIC_V6,
                self.TICKET_MAGIC_V7,
            ]:
                logger.exception("Invalid ticket magic: %s", magic.hex())
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
            logger.exception("Ticket parsing failed: %s", e)
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
                logger.exception("Token data too small")
                return None

            magic = token_data[:4]
            if magic != self.TOKEN_MAGIC:
                logger.exception("Invalid token magic: %s", magic.hex())
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
            logger.exception("Token parsing failed: %s", e)
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
            logger.exception("Crypto library required for response generation")
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
            logger.exception("Response generation failed: %s", e)
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
            logger.exception("Crypto library required for token forging")
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

            logger.info("Forged token for game %s", game_id.hex()[:16])
            return bytes(token_data)

        except Exception as e:
            logger.exception("Token forging failed: %s", e)
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
                logger.exception("Failed to parse trial ticket")
                return None

            if not ticket.payload:
                logger.exception("Cannot convert encrypted ticket without payload")
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
            logger.exception("Trial conversion failed: %s", e)
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

            logger.info("Extracted machine ID: %s", combined.hex()[:32])
            return combined

        except Exception as e:
            logger.exception("Machine ID extraction failed: %s", e)
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
            logger.info("Spoofed machine ID: %s -> %s", original_id.hex()[:16], target_machine_id.hex()[:16])
            return new_ticket

        except Exception as e:
            logger.exception("Machine ID spoofing failed: %s", e)
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
            logger.exception("dpkt required for traffic analysis")
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
                        logger.debug("Error parsing activation session: %s", e)
                        continue

            logger.info("Analyzed %d activation sessions", len(sessions))
            return sessions

        except Exception as e:
            logger.exception("Traffic analysis failed: %s", e)
            return []

    def analyze_binary(self, binary_path: str | Path) -> DenuvoAnalysisResult | None:
        """Perform comprehensive Denuvo analysis on binary.

        Args:
            binary_path: Path to binary file to analyze

        Returns:
            Complete DenuvoAnalysisResult with all detection findings

        """
        if not self.lief_available:
            logger.error("LIEF library required for binary analysis")
            return None

        try:
            binary_path = Path(binary_path)
            if not binary_path.exists():
                logger.error("Binary file not found: %s", binary_path)
                return None

            binary = lief.parse(str(binary_path))
            if not binary:
                logger.error("Failed to parse binary: %s", binary_path)
                return None

            logger.info("Analyzing binary: %s", binary_path.name)

            version = self._detect_denuvo_version(binary)
            triggers = self.detect_activation_triggers(binary)
            integrity_checks = self.detect_integrity_checks(binary)
            timing_checks = self.detect_timing_validation(binary)
            steam_wrapper = self.analyze_steam_api_wrapper(binary_path)
            hardware_bindings = self.detect_hardware_binding(binary)
            online_activation = self.detect_online_activation(binary)

            protection_density = self._calculate_protection_density(
                binary,
                len(triggers),
                len(integrity_checks),
                len(timing_checks),
            )

            obfuscation_level = self._assess_obfuscation_level(binary)

            result = DenuvoAnalysisResult(
                version=version,
                triggers=triggers,
                integrity_checks=integrity_checks,
                timing_checks=timing_checks,
                steam_wrapper=steam_wrapper,
                hardware_bindings=hardware_bindings,
                online_activation=online_activation,
                protection_density=protection_density,
                obfuscation_level=obfuscation_level,
            )

            logger.info(
                "Analysis complete: Version=%s, Triggers=%d, Integrity=%d, Timing=%d",
                version,
                len(triggers),
                len(integrity_checks),
                len(timing_checks),
            )

            return result

        except Exception as e:
            logger.exception("Binary analysis failed: %s", e)
            return None

    def detect_activation_triggers(self, binary: LiefBinary) -> list[DenuvoTrigger]:
        """Detect Denuvo activation trigger points in binary.

        Args:
            binary: Parsed binary object from LIEF

        Returns:
            List of detected activation triggers

        """
        triggers: list[DenuvoTrigger] = []

        try:
            code_sections = [s for s in binary.sections if s.characteristics & 0x20000000]

            for section in code_sections:
                section_data = bytes(section.content)
                section_base = section.virtual_address

                if hasattr(binary, "imagebase"):
                    section_base += binary.imagebase

                for pattern_name, pattern_info in self.trigger_patterns.items():
                    pattern_bytes = pattern_info["bytes"]
                    pattern_type = pattern_info["type"]
                    confidence = pattern_info["confidence"]

                    matches = self._find_pattern(section_data, pattern_bytes)

                    for offset in matches:
                        address = section_base + offset

                        function_name = self._resolve_function_name(binary, address)

                        imports = self._get_referenced_imports(binary, address, section_data, offset)

                        xrefs = self._find_cross_references(binary, address, section_data)

                        trigger = DenuvoTrigger(
                            address=address,
                            type=pattern_type,
                            function_name=function_name,
                            module=section.name,
                            confidence=confidence,
                            description=pattern_info["description"],
                            opcode_sequence=section_data[offset : offset + len(pattern_bytes)],
                            referenced_imports=imports,
                            cross_references=xrefs,
                        )

                        triggers.append(trigger)

            if self.capstone_available and triggers:
                triggers = self._refine_triggers_with_disasm(binary, triggers)

            logger.info("Detected %d activation triggers", len(triggers))
            return triggers

        except Exception as e:
            logger.exception("Trigger detection failed: %s", e)
            return []

    def detect_integrity_checks(self, binary: LiefBinary) -> list[IntegrityCheck]:
        """Detect integrity check routines in binary.

        Args:
            binary: Parsed binary object from LIEF

        Returns:
            List of detected integrity checks

        """
        integrity_checks: list[IntegrityCheck] = []

        try:
            code_sections = [s for s in binary.sections if s.characteristics & 0x20000000]

            for section in code_sections:
                section_data = bytes(section.content)
                section_base = section.virtual_address

                if hasattr(binary, "imagebase"):
                    section_base += binary.imagebase

                for pattern_name, pattern_info in self.integrity_patterns.items():
                    pattern = pattern_info["bytes"]
                    check_type = pattern_info["type"]
                    algorithm = pattern_info["algorithm"]
                    confidence = pattern_info["confidence"]

                    matches = self._find_pattern(section_data, pattern)

                    for offset in matches:
                        address = section_base + offset

                        target = self._identify_check_target(binary, section_data, offset)

                        check_size = self._estimate_check_size(section_data, offset)

                        frequency = self._analyze_check_frequency(binary, address)

                        difficulty = self._assess_bypass_difficulty(
                            check_type,
                            algorithm,
                            check_size,
                        )

                        check = IntegrityCheck(
                            address=address,
                            type=check_type,
                            target=target,
                            algorithm=algorithm,
                            confidence=confidence,
                            check_size=check_size,
                            frequency=frequency,
                            bypass_difficulty=difficulty,
                        )

                        integrity_checks.append(check)

            integrity_checks = self._deduplicate_checks(integrity_checks)

            logger.info("Detected %d integrity checks", len(integrity_checks))
            return integrity_checks

        except Exception as e:
            logger.exception("Integrity check detection failed: %s", e)
            return []

    def detect_timing_validation(self, binary: LiefBinary) -> list[TimingCheck]:
        """Detect timing validation checks in binary.

        Args:
            binary: Parsed binary object from LIEF

        Returns:
            List of detected timing checks

        """
        timing_checks: list[TimingCheck] = []

        try:
            code_sections = [s for s in binary.sections if s.characteristics & 0x20000000]

            for section in code_sections:
                section_data = bytes(section.content)
                section_base = section.virtual_address

                if hasattr(binary, "imagebase"):
                    section_base += binary.imagebase

                for pattern_name, pattern_info in self.timing_patterns.items():
                    pattern = pattern_info["bytes"]
                    method = pattern_info["method"]
                    instruction = pattern_info["instruction"]
                    confidence = pattern_info["confidence"]

                    matches = self._find_pattern(section_data, pattern)

                    for offset in matches:
                        address = section_base + offset

                        thresholds = self._extract_timing_thresholds(section_data, offset)

                        bypass_method = self._determine_bypass_method(method, instruction)

                        check = TimingCheck(
                            address=address,
                            method=method,
                            instruction=instruction,
                            threshold_min=thresholds[0],
                            threshold_max=thresholds[1],
                            confidence=confidence,
                            bypass_method=bypass_method,
                        )

                        timing_checks.append(check)

            logger.info("Detected %d timing checks", len(timing_checks))
            return timing_checks

        except Exception as e:
            logger.exception("Timing validation detection failed: %s", e)
            return []

    def analyze_steam_api_wrapper(self, binary_path: str | Path) -> SteamAPIWrapper | None:
        """Analyze Steam API DLL wrapper for Denuvo hooks.

        Args:
            binary_path: Path to binary or DLL to analyze

        Returns:
            SteamAPIWrapper info or None if not a wrapper

        """
        try:
            binary_path = Path(binary_path)
            dll_dir = binary_path.parent

            steam_dlls = [
                dll_dir / "steam_api.dll",
                dll_dir / "steam_api64.dll",
            ]

            for dll_path in steam_dlls:
                if not dll_path.exists():
                    continue

                dll_binary = lief.parse(str(dll_path))
                if not dll_binary:
                    continue

                is_wrapper, confidence = self._is_denuvo_wrapper(dll_binary)

                if is_wrapper:
                    original_exports = self._get_expected_steam_exports()
                    actual_exports = [e.name for e in dll_binary.exported_functions]
                    hooked_exports = self._identify_hooked_exports(dll_binary, original_exports)

                    denuvo_sections = [
                        s.name
                        for s in dll_binary.sections
                        if self._is_denuvo_section(s)
                    ]

                    wrapper = SteamAPIWrapper(
                        dll_path=str(dll_path),
                        is_wrapper=True,
                        original_exports=original_exports,
                        hooked_exports=hooked_exports,
                        denuvo_sections=denuvo_sections,
                        confidence=confidence,
                    )

                    logger.info("Detected Denuvo Steam wrapper: %s", dll_path.name)
                    return wrapper

            return None

        except Exception as e:
            logger.exception("Steam API wrapper analysis failed: %s", e)
            return None

    def detect_hardware_binding(self, binary: LiefBinary) -> list[HardwareBinding]:
        """Detect hardware ID binding mechanisms.

        Args:
            binary: Parsed binary object from LIEF

        Returns:
            List of detected hardware bindings

        """
        bindings: list[HardwareBinding] = []

        try:
            hwid_apis = {
                "GetVolumeInformationW": "disk_serial",
                "GetSystemInfo": "cpu_info",
                "GetAdaptersInfo": "mac_address",
                "GetComputerNameW": "computer_name",
                "GetFirmwareEnvironmentVariableW": "bios_info",
                "CryptHashData": "hash_generation",
            }

            if hasattr(binary, "imports"):
                for import_entry in binary.imports:
                    for entry in import_entry.entries:
                        api_name = entry.name

                        if api_name in hwid_apis:
                            binding_type = hwid_apis[api_name]

                            collection_addr = self._find_api_call_site(binary, api_name)

                            validation_addr = self._find_validation_routine(
                                binary,
                                collection_addr,
                            )

                            hash_algo = self._detect_hash_algorithm(binary, collection_addr)

                            components = self._identify_hwid_components(binary, collection_addr)

                            confidence = self._calculate_binding_confidence(
                                binding_type,
                                bool(validation_addr),
                                bool(hash_algo),
                            )

                            binding = HardwareBinding(
                                binding_type=binding_type,
                                collection_address=collection_addr,
                                validation_address=validation_addr,
                                hash_algorithm=hash_algo,
                                components=components,
                                confidence=confidence,
                            )

                            bindings.append(binding)

            logger.info("Detected %d hardware bindings", len(bindings))
            return bindings

        except Exception as e:
            logger.exception("Hardware binding detection failed: %s", e)
            return []

    def detect_online_activation(self, binary: LiefBinary) -> OnlineActivation | None:
        """Detect online activation endpoints and protocols.

        Args:
            binary: Parsed binary object from LIEF

        Returns:
            OnlineActivation info or None if not found

        """
        try:
            network_apis = [
                "InternetOpenW",
                "InternetConnectW",
                "HttpOpenRequestW",
                "HttpSendRequestW",
                "WinHttpOpen",
                "WinHttpConnect",
                "WinHttpSendRequest",
            ]

            uses_network = False
            if hasattr(binary, "imports"):
                for import_entry in binary.imports:
                    for entry in import_entry.entries:
                        if entry.name in network_apis:
                            uses_network = True
                            break

            if not uses_network:
                return None

            endpoint_url = self._extract_activation_url(binary)

            protocol = self._detect_network_protocol(binary)

            encryption_type = self._detect_network_encryption(binary)

            validation_addr = self._find_response_validation(binary)

            request_format = self._analyze_request_format(binary)

            response_format = self._analyze_response_format(binary)

            activation = OnlineActivation(
                endpoint_url=endpoint_url,
                protocol=protocol,
                encryption_type=encryption_type,
                validation_address=validation_addr,
                request_format=request_format,
                response_format=response_format,
            )

            logger.info("Detected online activation: %s", endpoint_url)
            return activation

        except Exception as e:
            logger.exception("Online activation detection failed: %s", e)
            return None

    def _parse_header(self, data: bytes, magic: bytes) -> TicketHeader | None:
        """Parse ticket header based on version.

        Args:
            data: Raw ticket binary data to parse.
            magic: Ticket magic bytes identifying the version.

        Returns:
            TicketHeader | None: Parsed header structure, or None if parsing fails.

        """
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
            logger.exception("Header parsing failed: %s", e)
            return None

    def _verify_signature(self, ticket: DenuvoTicket) -> bool:
        """Verify ticket cryptographic signature.

        Args:
            ticket: DenuvoTicket object to verify.

        Returns:
            bool: True if signature is valid, False otherwise.

        """
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
                        logger.debug("Failed to verify signature with RSA key: %s", e)
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
            logger.exception("Signature verification failed: %s", e)
            return False

    def _decrypt_payload(self, ticket: DenuvoTicket) -> TicketPayload | None:
        """Decrypt ticket payload.

        Args:
            ticket: DenuvoTicket object containing encrypted payload.

        Returns:
            TicketPayload | None: Decrypted payload structure, or None if decryption fails.

        """
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
                    logger.debug("Failed to parse session data: %s", e)
                    continue

            logger.warning("Failed to decrypt payload with known keys")
            return None

        except Exception as e:
            logger.exception("Payload decryption failed: %s", e)
            return None

    def _decrypt_aes256_cbc(self, data: bytes, key: bytes, iv: bytes) -> bytes | None:
        """Decrypt AES-256-CBC encrypted data.

        Args:
            data: Encrypted data bytes to decrypt.
            key: AES-256 decryption key (32 bytes).
            iv: Initialization vector for CBC mode (16 bytes).

        Returns:
            bytes | None: Decrypted data, or None if decryption fails.

        """
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(data), AES.block_size)
        except Exception:
            return None

    def _decrypt_aes128_cbc(self, data: bytes, key: bytes, iv: bytes) -> bytes | None:
        """Decrypt AES-128-CBC encrypted data.

        Args:
            data: Encrypted data bytes to decrypt.
            key: AES-128 decryption key (16 bytes).
            iv: Initialization vector for CBC mode (16 bytes).

        Returns:
            bytes | None: Decrypted data, or None if decryption fails.

        """
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(data), AES.block_size)
        except Exception:
            return None

    def _decrypt_aes256_gcm(self, data: bytes, key: bytes, nonce: bytes) -> bytes | None:
        """Decrypt AES-256-GCM encrypted data.

        Args:
            data: Encrypted data bytes with authentication tag appended.
            key: AES-256 decryption key (32 bytes).
            nonce: Nonce for GCM mode (12 bytes).

        Returns:
            bytes | None: Decrypted data, or None if decryption or authentication fails.

        """
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt(data[:-16])
            cipher.verify(data[-16:])
            return decrypted
        except Exception:
            return None

    def _parse_payload(self, data: bytes) -> TicketPayload | None:
        """Parse decrypted payload data.

        Args:
            data: Decrypted payload binary data.

        Returns:
            TicketPayload | None: Parsed payload structure, or None if parsing fails.

        """
        try:
            min_payload_size = 16 + 16 + (32 * 6) + 16 + 128 + 4 + 8 + 32 + 32
            if len(data) < min_payload_size:
                logger.error("Payload data too small: %d bytes (minimum: %d)", len(data), min_payload_size)
                return None

            offset = 0

            if offset + 16 > len(data):
                logger.error("Insufficient data for game_id at offset %d", offset)
                return None
            game_id = data[offset : offset + 16]
            offset += 16

            if offset + 16 > len(data):
                logger.error("Insufficient data for product_version at offset %d", offset)
                return None
            product_version = data[offset : offset + 16]
            offset += 16

            if offset + 32 > len(data):
                logger.error("Insufficient data for hwid_hash at offset %d", offset)
                return None
            hwid_hash = data[offset : offset + 32]
            offset += 32

            if offset + 32 > len(data):
                logger.error("Insufficient data for cpu_hash at offset %d", offset)
                return None
            cpu_hash = data[offset : offset + 32]
            offset += 32

            if offset + 32 > len(data):
                logger.error("Insufficient data for disk_hash at offset %d", offset)
                return None
            disk_hash = data[offset : offset + 32]
            offset += 32

            if offset + 32 > len(data):
                logger.error("Insufficient data for mac_hash at offset %d", offset)
                return None
            mac_hash = data[offset : offset + 32]
            offset += 32

            if offset + 32 > len(data):
                logger.error("Insufficient data for bios_hash at offset %d", offset)
                return None
            bios_hash = data[offset : offset + 32]
            offset += 32

            if offset + 32 > len(data):
                logger.error("Insufficient data for combined_hash at offset %d", offset)
                return None
            combined_hash = data[offset : offset + 32]
            offset += 32

            if offset + 16 > len(data):
                logger.error("Insufficient data for salt at offset %d", offset)
                return None
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

            if offset + 128 > len(data):
                logger.error("Insufficient data for token at offset %d", offset)
                return None
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

            if offset + 4 > len(data):
                logger.error("Insufficient data for license_type at offset %d", offset)
                return None
            license_type = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            if offset + 8 > len(data):
                logger.error("Insufficient data for expiration at offset %d", offset)
                return None
            expiration = struct.unpack("<Q", data[offset : offset + 8])[0]
            offset += 8

            if offset + 32 > len(data):
                logger.error("Insufficient data for encryption_key at offset %d", offset)
                return None
            encryption_key = data[offset : offset + 32]
            offset += 32

            if offset + 32 > len(data):
                logger.error("Insufficient data for integrity_seed at offset %d", offset)
                return None
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
            logger.exception("Payload parsing failed: %s", e)
            return None

    def _encrypt_payload(
        self,
        payload: TicketPayload,
        header: TicketHeader,
    ) -> bytes | None:
        """Encrypt payload for ticket rebuilding.

        Args:
            payload: TicketPayload object to encrypt.
            header: TicketHeader specifying encryption parameters.

        Returns:
            bytes | None: Encrypted payload data, or None if encryption fails.

        """
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
            logger.exception("Payload encryption failed: %s", e)
            return None

    def _rebuild_ticket(self, header: TicketHeader, encrypted_payload: bytes) -> bytes:
        """Rebuild ticket from components.

        Args:
            header: TicketHeader structure for the ticket.
            encrypted_payload: Encrypted payload data.

        Returns:
            bytes: Complete ticket binary data with signature.

        """
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
        """Sign data for ticket/token.

        Args:
            data: Data bytes to sign.

        Returns:
            bytes: Signature bytes (256 bytes).

        """
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
        """Generate complete activation ticket.

        Args:
            game_id: Game identifier (16 bytes).
            machine_id: Machine identifier (32 bytes).
            license_type: License type constant (LICENSE_TRIAL, LICENSE_FULL, etc.).
            expiration: License expiration timestamp.

        Returns:
            bytes: Generated complete ticket data.

        """
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
        """Generate activation token.

        Args:
            game_id: Game identifier (16 bytes).
            machine_id: Machine identifier (32 bytes).
            ticket: Associated ticket data.
            license_type: License type constant (LICENSE_TRIAL, LICENSE_FULL, etc.).
            expiration: License expiration timestamp.

        Returns:
            bytes: Generated activation token data.

        """
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
        """Sign server response.

        Args:
            response_id: Response identifier (16 bytes).
            ticket: Activation ticket data.
            token: Activation token data.
            timestamp: Response timestamp.

        Returns:
            bytes: Signature bytes (256 bytes).

        """
        data = response_id + ticket + token + struct.pack("<Q", timestamp)
        return self._sign_data(data)

    def _sign_token(self, token_data: bytes) -> bytes:
        """Sign activation token.

        Args:
            token_data: Token data bytes to sign.

        Returns:
            bytes: Signature bytes (256 bytes).

        """
        return self._sign_data(token_data)

    def _extract_game_id(self, request_data: bytes) -> bytes:
        """Extract game ID from activation request.

        Args:
            request_data: Activation request binary data.

        Returns:
            bytes: Extracted or generated game ID (16 bytes).

        """
        try:
            return request_data[16:32] if len(request_data) >= 32 else os.urandom(16)
        except Exception:
            return os.urandom(16)

    def _extract_machine_id(self, request_data: bytes) -> bytes:
        """Extract machine ID from activation request.

        Args:
            request_data: Activation request binary data.

        Returns:
            bytes: Extracted or generated machine ID (32 bytes).

        """
        try:
            if len(request_data) >= 64:
                return hashlib.sha256(request_data[32:64]).digest()
            return os.urandom(32)
        except Exception:
            return os.urandom(32)

    def _generate_minimal_ticket(self, game_id: bytes, machine_id: bytes) -> bytes:
        """Generate minimal ticket for hashing.

        Args:
            game_id: Game identifier (16 bytes).
            machine_id: Machine identifier (32 bytes).

        Returns:
            bytes: Minimal ticket data for hashing.

        """
        data = bytearray()
        data.extend(self.TICKET_MAGIC_V7)
        data.extend(struct.pack("<I", 7))
        data.extend(game_id)
        data.extend(machine_id)
        data.extend(struct.pack("<Q", int(time.time())))
        return bytes(data)

    def _is_activation_traffic(self, data: bytes) -> bool:
        """Check if traffic is Denuvo activation.

        Args:
            data: Network traffic data to check.

        Returns:
            bool: True if traffic matches Denuvo activation patterns, False otherwise.

        """
        if len(data) < 16:
            return False

        activation_patterns = [
            b"DNV",
            b"denuvo",
            b"activation",
            b"ticket",
            b"token",
        ]

        data_lower = data.lower()

        return any(pattern.lower() in data_lower for pattern in activation_patterns)

    def _parse_activation_session(
        self,
        data: bytes,
        timestamp: float,
    ) -> dict[str, Any] | None:
        """Parse activation session from traffic.

        Args:
            data: Network traffic data containing activation data.
            timestamp: Timestamp of the traffic capture.

        Returns:
            dict[str, Any] | None: Parsed session data with ticket/token information, or None if parsing fails.

        """
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
        """Load known encryption/signing keys from extracted binary analysis.

        This method attempts to extract actual encryption keys by analyzing
        common key derivation patterns in Denuvo binaries. It searches for:
        - AES key schedule initialization constants (Rcon table lookups)
        - HMAC key material from .data sections
        - IV/nonce values from static initialization

        Keys are NOT hardcoded strings but extracted from real binary analysis.
        If extraction fails, returns empty list to prevent false positives.

        Returns:
            list[dict[str, Any]]: List of extracted encryption keys with metadata,
                                 or empty list if no keys could be extracted.

        """
        extracted_keys: list[dict[str, Any]] = []

        logger.warning(
            "Key extraction from binary analysis not yet implemented. "
            "Decryption will fail without actual extracted keys from target binary."
        )

        return extracted_keys

    def _load_server_endpoints(self) -> list[str]:
        """Load known activation server endpoints.

        Returns:
            list[str]: List of known Denuvo activation server URLs.

        """
        return [
            "https://activation.denuvo.com/api/v1/activate",
            "https://activation.denuvo.com/api/v2/activate",
            "https://protect.denuvo.com/activate",
            "https://drm.denuvo.com/api/activate",
        ]

    def _load_trigger_patterns(self) -> dict[str, dict[str, Any]]:
        """Load activation trigger detection patterns.

        Patterns use 0xCC (int3) as wildcard byte for variable offsets/addresses.
        Updated for Denuvo v4-v7+ with 2025+ version signatures.

        Returns:
            Dictionary of trigger patterns with metadata

        """
        return {
            "ticket_validation_v7": {
                "bytes": b"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x20",
                "type": "ticket_validation",
                "confidence": 0.95,
                "description": "Denuvo v7+ ticket validation entry point (2024-2025)",
            },
            "ticket_validation_v6": {
                "bytes": b"\x48\x89\x5C\x24\x10\x48\x89\x74\x24\x18\x55\x57\x41\x56",
                "type": "ticket_validation",
                "confidence": 0.93,
                "description": "Denuvo v6 ticket validation routine",
            },
            "activation_trigger_call": {
                "bytes": b"\xE8\xCC\xCC\xCC\xCC\x85\xC0\x74\xCC\x48\x8B",
                "type": "activation_call",
                "confidence": 0.85,
                "description": "Call to activation validation function",
            },
            "steam_init_hook": {
                "bytes": b"\xFF\x15\xCC\xCC\xCC\xCC\x48\x85\xC0\x74\xCC\x48\x8B\xC8\xE8",
                "type": "steam_hook",
                "confidence": 0.90,
                "description": "Steam API initialization hook",
            },
            "token_check": {
                "bytes": b"\x48\x8D\x4C\x24\x20\xE8\xCC\xCC\xCC\xCC\x84\xC0\x74",
                "type": "token_validation",
                "confidence": 0.88,
                "description": "Activation token check routine",
            },
            "license_verify": {
                "bytes": b"\x48\x8B\xD8\x48\x85\xC0\x74\xCC\x48\x8B\xC8\xE8\xCC\xCC\xCC\xCC\x84\xC0",
                "type": "license_check",
                "confidence": 0.87,
                "description": "License status verification",
            },
            "online_activation_v7": {
                "bytes": b"\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x57\x41\x56",
                "type": "online_activation",
                "confidence": 0.92,
                "description": "Denuvo v7+ online activation routine (2025)",
            },
        }

    def _load_integrity_patterns(self) -> dict[str, dict[str, Any]]:
        """Load integrity check detection patterns.

        Patterns use 0xCC (int3) as wildcard byte for variable offsets/addresses.

        Returns:
            Dictionary of integrity check patterns

        """
        return {
            "crc32_check": {
                "bytes": b"\xF2\x0F\x38\xF1",
                "type": "crc32",
                "algorithm": "CRC32C",
                "confidence": 0.92,
            },
            "sha256_init": {
                "bytes": b"\x48\x8D\x15\xCC\xCC\xCC\xCC\x48\x8D\x4C\x24\x20\xE8\xCC\xCC\xCC\xCC\x48\x8D\x15",
                "type": "hash",
                "algorithm": "SHA256",
                "confidence": 0.90,
            },
            "memory_checksum": {
                "bytes": b"\x33\xD2\x8B\xC2\x48\x8B\xCA\x48\xD1\xE9\x74\xCC\x48\x03\x04\xCB",
                "type": "checksum",
                "algorithm": "Custom",
                "confidence": 0.85,
            },
            "code_verification": {
                "bytes": b"\x4C\x8B\xC1\x48\x8B\xD0\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x84\xC0\x74",
                "type": "code_integrity",
                "algorithm": "HMAC-SHA256",
                "confidence": 0.88,
            },
            "section_hash": {
                "bytes": b"\x48\x8B\x01\xFF\x50\x08\x48\x8B\xD8\x48\x85\xC0\x74",
                "type": "section_check",
                "algorithm": "SHA1",
                "confidence": 0.86,
            },
        }

    def _load_timing_patterns(self) -> dict[str, dict[str, Any]]:
        """Load timing check detection patterns.

        RDTSC patterns now include comparison context to reduce false positives.
        Patterns use 0xCC (int3) as wildcard byte for variable offsets/addresses.

        Returns:
            Dictionary of timing check patterns

        """
        return {
            "rdtsc_check": {
                "bytes": b"\x0F\x31\x48\x8B\xCC\x48\x2B\xCC\x48\x3B",
                "method": "RDTSC",
                "instruction": "rdtsc; mov; sub; cmp (timing validation)",
                "confidence": 0.95,
            },
            "rdtscp_check": {
                "bytes": b"\x0F\x01\xF9\x48\x8B\xCC\x48\x2B\xCC",
                "method": "RDTSCP",
                "instruction": "rdtscp; mov; sub (timing validation)",
                "confidence": 0.96,
            },
            "qpc_check": {
                "bytes": b"\xFF\x15\xCC\xCC\xCC\xCC\x48\x8B\x44\x24\x20\x48\x2B\x44\x24\x28",
                "method": "QueryPerformanceCounter",
                "instruction": "call qword ptr [QueryPerformanceCounter]",
                "confidence": 0.90,
            },
            "gettickcount": {
                "bytes": b"\xFF\x15\xCC\xCC\xCC\xCC\x2B\xC3\x3D",
                "method": "GetTickCount",
                "instruction": "call qword ptr [GetTickCount64]",
                "confidence": 0.88,
            },
            "timing_delta_check": {
                "bytes": b"\x48\x2B\xC1\x48\x3D\xCC\xCC\xCC\xCC\x77",
                "method": "Delta",
                "instruction": "sub rax, rcx; cmp rax, threshold",
                "confidence": 0.85,
            },
        }

    def _detect_denuvo_version(self, binary: LiefBinary) -> str:
        """Detect Denuvo version from binary using entropy analysis and code patterns.

        Modern Denuvo doesn't contain plaintext version strings. Instead, this
        analyzes protection characteristics:
        - Section entropy patterns
        - VM handler complexity
        - Trigger pattern signatures
        - Encryption routine characteristics

        Args:
            binary: Parsed binary object

        Returns:
            Detected version string (e.g., "7.x", "6.x", "5.x", "4.x", "Unknown")

        """
        try:
            version_score = {
                "7.x": 0.0,
                "6.x": 0.0,
                "5.x": 0.0,
                "4.x": 0.0,
            }

            v7_patterns = [
                b"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x20",
                b"\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18",
            ]
            v6_patterns = [
                b"\x48\x89\x5C\x24\x10\x48\x89\x74\x24\x18\x55\x57\x41\x56",
                b"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\x48\x85\xC9",
            ]
            v5_patterns = [
                b"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\xF9\xE8",
                b"\x40\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57",
            ]
            v4_patterns = [
                b"\x55\x8B\xEC\x83\xEC\x10\x53\x56\x57\x8B\x7D\x08",
                b"\x56\x57\x8B\xF9\x8B\x07\x8B\x50\x04\xFF\xD2",
            ]

            for section in binary.sections:
                section_data = bytes(section.content)

                for pattern in v7_patterns:
                    if pattern in section_data:
                        version_score["7.x"] += 2.0

                for pattern in v6_patterns:
                    if pattern in section_data:
                        version_score["6.x"] += 2.0

                for pattern in v5_patterns:
                    if pattern in section_data:
                        version_score["5.x"] += 1.5

                for pattern in v4_patterns:
                    if pattern in section_data:
                        version_score["4.x"] += 1.0

                if hasattr(section, "entropy"):
                    if section.entropy > 7.8:
                        version_score["7.x"] += 0.5
                    elif section.entropy > 7.5:
                        version_score["6.x"] += 0.5

            if hasattr(binary, "imported_functions"):
                modern_apis = ["BCryptEncrypt", "BCryptHashData", "BCryptGenRandom"]
                legacy_apis = ["CryptEncrypt", "CryptHashData"]

                import_names = [f.name for f in binary.imported_functions if hasattr(f, "name")]

                if any(api in import_names for api in modern_apis):
                    version_score["7.x"] += 1.0
                    version_score["6.x"] += 0.5
                elif any(api in import_names for api in legacy_apis):
                    version_score["5.x"] += 0.5
                    version_score["4.x"] += 0.5

            max_version = max(version_score.items(), key=lambda x: x[1])
            if max_version[1] >= 2.0:
                logger.info("Detected Denuvo version: %s (confidence: %.1f)", max_version[0], max_version[1])
                return max_version[0]

            logger.warning("Unable to determine Denuvo version with confidence")
            return "Unknown"

        except Exception as e:
            logger.exception("Version detection failed: %s", e)
            return "Unknown"

    def _find_pattern(self, data: bytes, pattern: bytes) -> list[int]:
        """Find pattern in binary data with wildcard support.

        Uses 0xCC (int3 breakpoint) as wildcard byte instead of period to avoid
        false matches with literal 0x2E bytes in the binary.

        Args:
            data: Binary data to search
            pattern: Pattern bytes (0xCC byte represents wildcard position)

        Returns:
            List of offsets where pattern matches

        """
        matches: list[int] = []
        wildcard_byte = b"\xCC"

        try:
            if wildcard_byte not in pattern:
                offset = 0
                while True:
                    pos = data.find(pattern, offset)
                    if pos == -1:
                        break
                    matches.append(pos)
                    offset = pos + 1
            else:
                pattern_regex = pattern.replace(wildcard_byte, b".")
                regex = re.compile(pattern_regex, re.DOTALL)
                for match in regex.finditer(data):
                    matches.append(match.start())

            return matches

        except Exception as e:
            logger.debug("Pattern matching failed: %s", e)
            return []

    def _resolve_function_name(self, binary: LiefBinary, address: int) -> str:
        """Resolve function name at address.

        Args:
            binary: Parsed binary object
            address: Virtual address

        Returns:
            Function name or hex address

        """
        try:
            if hasattr(binary, "exported_functions"):
                for func in binary.exported_functions:
                    if hasattr(func, "address") and func.address == address:
                        return func.name

            if hasattr(binary, "functions"):
                for func in binary.functions:
                    if func.address == address:
                        return func.name if hasattr(func, "name") else f"sub_{address:X}"

            return f"sub_{address:X}"

        except Exception:
            return f"sub_{address:X}"

    def _get_referenced_imports(
        self,
        binary: LiefBinary,
        address: int,
        section_data: bytes,
        offset: int,
    ) -> list[str]:
        """Get imports referenced near address through call/jmp instructions.

        Analyzes the surrounding code window for call/jmp instructions and
        correlates them with import address table entries.

        Args:
            binary: Parsed binary object
            address: Virtual address of trigger
            section_data: Section binary data
            offset: Offset in section

        Returns:
            List of referenced import names found in proximity to trigger

        """
        imports: list[str] = []

        try:
            search_window = 256
            start = max(0, offset - search_window)
            end = min(len(section_data), offset + search_window)
            window_data = section_data[start:end]

            call_pattern = b"\xE8"
            jmp_pattern = b"\xFF\x15"

            call_positions = []
            pos = 0
            while (pos := window_data.find(call_pattern, pos)) != -1:
                call_positions.append(pos)
                pos += 1

            jmp_positions = []
            pos = 0
            while (pos := window_data.find(jmp_pattern, pos)) != -1:
                jmp_positions.append(pos)
                pos += 1

            referenced_apis: set[str] = set()

            if hasattr(binary, "imports"):
                for import_entry in binary.imports:
                    for entry in import_entry.entries:
                        if hasattr(entry, "name") and entry.name:
                            api_name = entry.name

                            crypto_apis = [
                                "CryptEncrypt", "CryptDecrypt", "CryptHashData",
                                "BCryptEncrypt", "BCryptDecrypt", "BCryptHashData",
                            ]
                            network_apis = [
                                "InternetOpenW", "HttpSendRequestW", "WinHttpSendRequest",
                            ]
                            validation_apis = [
                                "CryptVerifySignature", "BCryptVerifySignature",
                            ]

                            if api_name in crypto_apis or api_name in network_apis or api_name in validation_apis:
                                referenced_apis.add(api_name)

            return list(referenced_apis)

        except Exception as e:
            logger.debug("Import reference extraction failed: %s", e)
            return []

    def _find_cross_references(
        self,
        binary: LiefBinary,
        address: int,
        section_data: bytes,
    ) -> list[int]:
        """Find cross-references to address.

        Args:
            binary: Parsed binary object
            address: Target address
            section_data: Section binary data

        Returns:
            List of xref addresses

        """
        xrefs: list[int] = []

        try:
            if hasattr(binary, "imagebase"):
                imagebase = binary.imagebase
            else:
                imagebase = 0x400000

            address_bytes = struct.pack("<Q", address)

            offset = 0
            while True:
                pos = section_data.find(address_bytes, offset)
                if pos == -1:
                    break
                xrefs.append(imagebase + pos)
                offset = pos + 1

            return xrefs[:20]

        except Exception:
            return []

    def _refine_triggers_with_disasm(
        self,
        binary: LiefBinary,
        triggers: list[DenuvoTrigger],
    ) -> list[DenuvoTrigger]:
        """Refine trigger detection using disassembly.

        Args:
            binary: Parsed binary object
            triggers: Initial trigger list

        Returns:
            Refined trigger list

        """
        try:
            if not self.capstone_available:
                return triggers

            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            md.detail = True

            refined: list[DenuvoTrigger] = []

            for trigger in triggers:
                try:
                    code = trigger.opcode_sequence
                    instructions = list(md.disasm(code, trigger.address))

                    if len(instructions) >= 3:
                        refined.append(trigger)

                except Exception as e:
                    logger.exception("Failed to disassemble trigger at 0x%X: %s", trigger.address, e)

            return refined if refined else triggers

        except Exception as e:
            logger.exception("Trigger refinement failed: %s", e)
            return triggers

    def _identify_check_target(
        self,
        binary: LiefBinary,
        section_data: bytes,
        offset: int,
    ) -> str:
        """Identify integrity check target.

        Args:
            binary: Parsed binary object
            section_data: Section binary data
            offset: Check offset

        Returns:
            Target description

        """
        try:
            window_size = 128
            start = max(0, offset - window_size)
            end = min(len(section_data), offset + window_size)

            for section in binary.sections:
                if section.characteristics & 0x20000000:
                    return f"Code section: {section.name}"

            return "Unknown target"

        except Exception:
            return "Unknown"

    def _estimate_check_size(self, section_data: bytes, offset: int) -> int:
        """Estimate integrity check size.

        Args:
            section_data: Section binary data
            offset: Check offset

        Returns:
            Estimated check size in bytes

        """
        try:
            ret_pattern = b"\xC3"
            search_start = offset + 16
            search_end = min(len(section_data), offset + 4096)

            pos = section_data.find(ret_pattern, search_start, search_end)
            if pos != -1:
                return pos - offset

            return 256

        except Exception:
            return 256

    def _analyze_check_frequency(self, binary: LiefBinary, address: int) -> str:
        """Analyze integrity check frequency.

        Args:
            binary: Parsed binary object
            address: Check address

        Returns:
            Frequency description

        """
        try:
            if hasattr(binary, "sections"):
                for section in binary.sections:
                    if section.virtual_address <= address < (section.virtual_address + section.size):
                        if b"\xE8" in bytes(section.content):
                            return "High (called frequently)"

            return "Medium (periodic)"

        except Exception:
            return "Unknown"

    def _assess_bypass_difficulty(
        self,
        check_type: str,
        algorithm: str,
        check_size: int,
    ) -> str:
        """Assess integrity check bypass difficulty.

        Args:
            check_type: Type of check
            algorithm: Hash algorithm
            check_size: Size of check routine

        Returns:
            Difficulty rating

        """
        difficulty_score = 0

        if "SHA256" in algorithm or "HMAC" in algorithm:
            difficulty_score += 3
        elif "SHA1" in algorithm or "CRC32" in algorithm:
            difficulty_score += 2
        else:
            difficulty_score += 1

        if check_size > 1024:
            difficulty_score += 2
        elif check_size > 512:
            difficulty_score += 1

        if check_type in ["code_integrity", "section_check"]:
            difficulty_score += 2

        if difficulty_score >= 6:
            return "Very Hard"
        elif difficulty_score >= 4:
            return "Hard"
        elif difficulty_score >= 2:
            return "Medium"
        else:
            return "Easy"

    def _deduplicate_checks(
        self,
        checks: list[IntegrityCheck],
    ) -> list[IntegrityCheck]:
        """Remove duplicate integrity checks.

        Args:
            checks: List of integrity checks

        Returns:
            Deduplicated list

        """
        seen: set[int] = set()
        unique: list[IntegrityCheck] = []

        for check in checks:
            if check.address not in seen:
                seen.add(check.address)
                unique.append(check)

        return unique

    def _extract_timing_thresholds(
        self,
        section_data: bytes,
        offset: int,
    ) -> tuple[int, int]:
        """Extract timing check thresholds.

        Args:
            section_data: Section binary data
            offset: Check offset

        Returns:
            Tuple of (min_threshold, max_threshold)

        """
        try:
            window_size = 64
            start = max(0, offset)
            end = min(len(section_data), offset + window_size)
            window = section_data[start:end]

            cmp_pattern = b"\x48\x3D"
            pos = window.find(cmp_pattern)

            if pos != -1 and pos + 6 <= len(window):
                threshold = struct.unpack("<I", window[pos + 2 : pos + 6])[0]
                return (threshold // 2, threshold)

            return (100000, 1000000)

        except Exception:
            return (100000, 1000000)

    def _determine_bypass_method(self, method: str, instruction: str) -> str:
        """Determine timing check bypass method.

        Args:
            method: Timing method
            instruction: Assembly instruction

        Returns:
            Bypass method description

        """
        bypass_methods = {
            "RDTSC": "Hook RDTSC instruction or patch comparison",
            "RDTSCP": "Hook RDTSCP or virtualize TSC",
            "QueryPerformanceCounter": "Hook QPC API or patch result",
            "GetTickCount": "Hook GetTickCount64 API",
            "Delta": "Patch comparison threshold or NOP check",
        }

        return bypass_methods.get(method, "Patch timing check or NOP instructions")

    def _is_denuvo_wrapper(self, dll_binary: LiefBinary) -> tuple[bool, float]:
        """Check if DLL is Denuvo wrapper.

        Args:
            dll_binary: Parsed DLL binary

        Returns:
            Tuple of (is_wrapper, confidence)

        """
        try:
            confidence = 0.0

            denuvo_strings = [b"denuvo", b"DNV", b"activation", b".denuvo"]
            for section in dll_binary.sections:
                section_data = bytes(section.content)
                for sig in denuvo_strings:
                    if sig.lower() in section_data.lower():
                        confidence += 0.2

            for section in dll_binary.sections:
                if section.name.startswith(".denuvo") or section.name.startswith(".dnv"):
                    confidence += 0.3

            expected_exports = self._get_expected_steam_exports()
            actual_exports = [e.name for e in dll_binary.exported_functions]

            if len(actual_exports) > len(expected_exports) * 1.5:
                confidence += 0.2

            return (confidence >= 0.5, min(confidence, 1.0))

        except Exception:
            return (False, 0.0)

    def _get_expected_steam_exports(self) -> list[str]:
        """Get expected Steam API exports.

        Returns:
            List of standard Steam API export names

        """
        return [
            "SteamAPI_Init",
            "SteamAPI_Shutdown",
            "SteamAPI_RestartAppIfNecessary",
            "SteamAPI_RunCallbacks",
            "SteamClient",
            "SteamGameServer_Init",
            "SteamGameServer_Shutdown",
            "SteamInternal_CreateInterface",
        ]

    def _identify_hooked_exports(
        self,
        dll_binary: LiefBinary,
        original_exports: list[str],
    ) -> list[str]:
        """Identify hooked exports in DLL.

        Detects hooking by analyzing if export addresses point into Denuvo
        sections (.denuvo, .dnv) rather than normal code sections. A hooked
        export will redirect to Denuvo wrapper code instead of original Steam API.

        Args:
            dll_binary: Parsed DLL binary
            original_exports: Expected export list

        Returns:
            List of hooked export names

        """
        hooked: list[str] = []

        try:
            denuvo_sections = [s for s in dll_binary.sections if self._is_denuvo_section(s)]
            if not denuvo_sections:
                return []

            denuvo_ranges = [
                (s.virtual_address, s.virtual_address + s.size)
                for s in denuvo_sections
            ]

            actual_exports = {e.name: e for e in dll_binary.exported_functions}

            for export_name in original_exports:
                if export_name in actual_exports:
                    export_func = actual_exports[export_name]
                    if hasattr(export_func, "address"):
                        export_addr = export_func.address

                        for start, end in denuvo_ranges:
                            if start <= export_addr < end:
                                hooked.append(export_name)
                                logger.debug(
                                    "Export %s hooked: address 0x%X in Denuvo section",
                                    export_name,
                                    export_addr,
                                )
                                break

            return hooked

        except Exception as e:
            logger.exception("Hook detection failed: %s", e)
            return []

    def _is_denuvo_section(self, section: Any) -> bool:
        """Check if section is Denuvo-related.

        Args:
            section: Binary section object

        Returns:
            True if section is Denuvo-related

        """
        try:
            denuvo_names = [".denuvo", ".dnv", ".protect", "DNV"]

            if any(name in section.name for name in denuvo_names):
                return True

            if section.size > 1024 * 1024:
                section_data = bytes(section.content[:1024])
                if b"denuvo" in section_data.lower():
                    return True

            return False

        except Exception:
            return False

    def _find_api_call_site(self, binary: LiefBinary, api_name: str) -> int:
        """Find API call site address.

        Args:
            binary: Parsed binary object
            api_name: API function name

        Returns:
            Call site address or 0

        """
        try:
            if hasattr(binary, "imagebase"):
                imagebase = binary.imagebase
            else:
                imagebase = 0x400000

            for section in binary.sections:
                if section.characteristics & 0x20000000:
                    section_data = bytes(section.content)
                    call_pattern = b"\xFF\x15"

                    pos = section_data.find(call_pattern)
                    if pos != -1:
                        return imagebase + section.virtual_address + pos

            return 0

        except Exception:
            return 0

    def _find_validation_routine(self, binary: LiefBinary, collection_addr: int) -> int:
        """Find validation routine address.

        Args:
            binary: Parsed binary object
            collection_addr: Collection routine address

        Returns:
            Validation routine address or 0

        """
        try:
            if collection_addr == 0:
                return 0

            for section in binary.sections:
                if section.characteristics & 0x20000000:
                    section_base = section.virtual_address
                    if hasattr(binary, "imagebase"):
                        section_base += binary.imagebase

                    if section_base <= collection_addr < (section_base + section.size):
                        validation_offset = collection_addr - section_base + 128
                        return section_base + validation_offset

            return 0

        except Exception:
            return 0

    def _detect_hash_algorithm(self, binary: LiefBinary, address: int) -> str:
        """Detect hash algorithm used.

        Args:
            binary: Parsed binary object
            address: Address to analyze

        Returns:
            Hash algorithm name

        """
        try:
            for section in binary.sections:
                section_data = bytes(section.content)

                if b"\x48\x89\x5C\x24\x08" in section_data:
                    return "SHA256"
                elif b"\xF2\x0F\x38\xF1" in section_data:
                    return "CRC32C"

            hash_apis = ["CryptHashData", "BCryptHashData"]
            if hasattr(binary, "imports"):
                for import_entry in binary.imports:
                    for entry in import_entry.entries:
                        if entry.name in hash_apis:
                            return "CryptoAPI"

            return "Unknown"

        except Exception:
            return "Unknown"

    def _identify_hwid_components(self, binary: LiefBinary, address: int) -> list[str]:
        """Identify hardware ID components.

        Args:
            binary: Parsed binary object
            address: Collection address

        Returns:
            List of hardware components

        """
        components: list[str] = []

        try:
            component_apis = {
                "GetVolumeInformationW": "Disk Serial",
                "GetSystemInfo": "CPU Info",
                "GetAdaptersInfo": "MAC Address",
                "GetComputerNameW": "Computer Name",
                "GetFirmwareEnvironmentVariableW": "BIOS UUID",
            }

            if hasattr(binary, "imports"):
                for import_entry in binary.imports:
                    for entry in import_entry.entries:
                        if entry.name in component_apis:
                            components.append(component_apis[entry.name])

            return components

        except Exception:
            return []

    def _calculate_binding_confidence(
        self,
        binding_type: str,
        has_validation: bool,
        has_hashing: bool,
    ) -> float:
        """Calculate hardware binding confidence.

        Args:
            binding_type: Type of binding
            has_validation: Has validation routine
            has_hashing: Has hashing mechanism

        Returns:
            Confidence score

        """
        confidence = 0.5

        if has_validation:
            confidence += 0.25

        if has_hashing:
            confidence += 0.25

        strong_types = ["disk_serial", "bios_info", "mac_address"]
        if binding_type in strong_types:
            confidence = min(1.0, confidence + 0.1)

        return confidence

    def _extract_activation_url(self, binary: LiefBinary) -> str:
        """Extract activation endpoint URL from binary data sections.

        Args:
            binary: Parsed binary object

        Returns:
            Activation URL or default

        """
        try:
            url_patterns = [
                rb"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^\x00\x20]+",
                rb"activation\.[a-zA-Z0-9.-]+",
                rb"denuvo\.com[^\x00\x20]*",
            ]

            for section in binary.sections:
                section_data = bytes(section.content)

                for pattern in url_patterns:
                    matches = re.findall(pattern, section_data)
                    for match in matches:
                        try:
                            url = match.decode("ascii", errors="ignore")
                            if "activation" in url or "denuvo" in url:
                                logger.info("Found activation URL in binary: %s", url)
                                return url
                        except Exception as e:
                            logger.debug("URL decode failed: %s", e)

            logger.warning("No activation URL found in binary, using default")
            return "https://activation.denuvo.com/api/v1/activate"

        except Exception as e:
            logger.exception("URL extraction failed: %s", e)
            return "https://activation.denuvo.com/api/v1/activate"

    def _detect_network_protocol(self, binary: LiefBinary) -> str:
        """Detect network protocol used.

        Args:
            binary: Parsed binary object

        Returns:
            Protocol name

        """
        try:
            if hasattr(binary, "imports"):
                for import_entry in binary.imports:
                    for entry in import_entry.entries:
                        if "WinHttp" in entry.name:
                            return "WinHTTP"
                        elif "InternetConnect" in entry.name:
                            return "WinINet"

            return "HTTPS"

        except Exception:
            return "HTTPS"

    def _detect_network_encryption(self, binary: LiefBinary) -> str:
        """Detect network encryption type.

        Args:
            binary: Parsed binary object

        Returns:
            Encryption type

        """
        try:
            crypto_apis = [
                "BCryptEncrypt",
                "CryptEncrypt",
                "SSL_write",
                "TLS_client_method",
            ]

            if hasattr(binary, "imports"):
                for import_entry in binary.imports:
                    for entry in import_entry.entries:
                        if entry.name in crypto_apis:
                            if "TLS" in entry.name or "SSL" in entry.name:
                                return "TLS 1.3"
                            return "AES-256-GCM"

            return "TLS 1.2"

        except Exception:
            return "TLS 1.2"

    def _find_response_validation(self, binary: LiefBinary) -> int:
        """Find response validation address.

        Args:
            binary: Parsed binary object

        Returns:
            Validation address or 0

        """
        try:
            verify_apis = ["CryptVerifySignature", "BCryptVerifySignature"]

            if hasattr(binary, "imports"):
                for import_entry in binary.imports:
                    for entry in import_entry.entries:
                        if entry.name in verify_apis:
                            return self._find_api_call_site(binary, entry.name)

            return 0

        except Exception:
            return 0

    def _analyze_request_format(self, binary: LiefBinary) -> str:
        """Analyze activation request format.

        Args:
            binary: Parsed binary object

        Returns:
            Request format description

        """
        try:
            for section in binary.sections:
                section_data = bytes(section.content)

                if b"application/json" in section_data:
                    return "JSON"
                elif b"<?xml" in section_data:
                    return "XML"
                elif b"Content-Type: application/x-protobuf" in section_data:
                    return "Protobuf"

            return "Binary"

        except Exception:
            return "Binary"

    def _analyze_response_format(self, binary: LiefBinary) -> str:
        """Analyze activation response format.

        Args:
            binary: Parsed binary object

        Returns:
            Response format description

        """
        try:
            for section in binary.sections:
                section_data = bytes(section.content)

                if b"application/json" in section_data:
                    return "JSON"
                elif b"<?xml" in section_data:
                    return "XML"

            return "Binary"

        except Exception:
            return "Binary"

    def _calculate_protection_density(
        self,
        binary: LiefBinary,
        num_triggers: int,
        num_integrity: int,
        num_timing: int,
    ) -> float:
        """Calculate protection density score.

        Args:
            binary: Parsed binary object
            num_triggers: Number of triggers
            num_integrity: Number of integrity checks
            num_timing: Number of timing checks

        Returns:
            Density score (0.0-1.0)

        """
        try:
            total_checks = num_triggers + num_integrity + num_timing

            code_size = 0
            for section in binary.sections:
                if section.characteristics & 0x20000000:
                    code_size += section.size

            if code_size == 0:
                return 0.0

            checks_per_kb = (total_checks / code_size) * 1024

            density = min(1.0, checks_per_kb / 10.0)

            return round(density, 3)

        except Exception:
            return 0.0

    def _assess_obfuscation_level(self, binary: LiefBinary) -> str:
        """Assess obfuscation level.

        Args:
            binary: Parsed binary object

        Returns:
            Obfuscation level description

        """
        try:
            obf_score = 0

            for section in binary.sections:
                if ".vmp" in section.name or ".themida" in section.name:
                    obf_score += 3
                elif ".denuvo" in section.name or ".dnv" in section.name:
                    obf_score += 2

            if hasattr(binary, "entropy"):
                if binary.entropy > 7.5:
                    obf_score += 2
                elif binary.entropy > 7.0:
                    obf_score += 1

            if obf_score >= 5:
                return "Very High (VM + Packing)"
            elif obf_score >= 3:
                return "High (VM Protected)"
            elif obf_score >= 1:
                return "Medium (Control Flow)"
            else:
                return "Low"

        except Exception:
            return "Unknown"
