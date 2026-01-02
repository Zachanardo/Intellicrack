"""Protocol Fingerprinting for Proprietary License Protocols.

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

import json
import logging
import math
import os
import re
import socket
import time
from collections import Counter
from typing import Any

from intellicrack.data import PROTOCOL_SIGNATURES
from intellicrack.utils.protection_utils import calculate_entropy


logger = logging.getLogger(__name__)


logger.debug("Module loading started")

logger.debug("About to import calculate_entropy from protection_utils...")

logger.debug("calculate_entropy imported OK")


class ProtocolFingerprinter:
    """Protocol fingerprinting for proprietary license protocols.

    This system analyzes network traffic to identify and fingerprint proprietary
    license verification protocols, enabling more effective bypasses.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize the protocol fingerprinter.

        Args:
            config: Configuration dictionary (optional)

        """
        logger.debug("Entering ProtocolFingerprinter.__init__ with config=%s", config is not None)
        self.logger = logging.getLogger(__name__)

        self.config = {
            "min_confidence": 0.7,
            "max_fingerprints": 100,
            "learning_mode": True,
            "analysis_depth": 3,
            "signature_db_path": str(PROTOCOL_SIGNATURES),
        }

        # Update with provided configuration
        if config:
            self.config |= config

        # Initialize components
        self.signatures: dict[str, dict[str, Any]] = {}
        self.learned_signatures: dict[str, dict[str, Any]] = {}
        self.traffic_samples: list[dict[str, Any]] = []

        # License server ports to monitor
        self.license_ports = [
            27000,
            27001,  # FlexLM
            1947,
            6001,  # HASP/Sentinel
            22350,  # CodeMeter
            2080,  # Autodesk
            8080,
            443,  # HTTPS (various licensing)
            1688,  # Microsoft KMS
            5093,  # Sentinel RMS
            8224,  # Generic license server
        ]

        self._load_signatures()
        logger.debug("Exiting ProtocolFingerprinter.__init__: signatures=%d", len(self.signatures))

    def _load_signatures(self) -> None:
        """Load known protocol signatures from database.

        Reads protocol signatures from the configured database file.
        If the file does not exist, initializes with built-in signatures.
        """
        logger.debug("Entering _load_signatures: path=%s", self.config["signature_db_path"])
        sig_path: str = str(self.config["signature_db_path"])
        try:
            if os.path.exists(sig_path):
                with open(sig_path, encoding="utf-8") as f:
                    self.signatures = json.load(f)

                self.logger.info("Loaded %d protocol signatures", len(self.signatures))
            else:
                self.logger.info("Signature database not found, initializing with built-in signatures")
                self._initialize_signatures()
                self._save_signatures()

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error loading signatures: %s", e, exc_info=True)
            self._initialize_signatures()

    def _save_signatures(self) -> None:
        """Save protocol signatures to database.

        Persists all known signatures to the configured database file.
        Creates the database directory if it does not exist.
        """
        sig_path: str = str(self.config["signature_db_path"])
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(sig_path)), exist_ok=True)

            # Save signatures
            with open(sig_path, "w", encoding="utf-8") as f:
                json.dump(self.signatures, f, indent=2)

            self.logger.info("Saved %d protocol signatures", len(self.signatures))

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error saving signatures: %s", e, exc_info=True)

    def _initialize_signatures(self) -> None:
        """Initialize with built-in protocol signatures.

        Populates the signatures dictionary with known protocol fingerprints for
        FlexLM, HASP/Sentinel, Autodesk, and Microsoft KMS. All byte patterns are
        stored as hex strings for JSON serialization and converted back to bytes
        during pattern matching.

        Note: All byte patterns are stored as hex strings for JSON serialization.
        Use bytes.fromhex() to convert back to bytes when matching.
        """
        self.signatures["flexlm"] = {
            "name": "FlexLM",
            "description": "FlexLM/FlexNet License Manager by Flexera",
            "ports": [27000, 27001, 1101],
            "patterns": [
                {"type": "binary", "offset": 0, "bytes": "56454e444f525f", "weight": 0.5, "description": "VENDOR_"},
                {"type": "binary", "offset": 0, "bytes": "5345525645525f", "weight": 0.5, "description": "SERVER_"},
                {"type": "binary", "offset": 0, "bytes": "46454154555245", "weight": 0.5, "description": "FEATURE"},
                {"type": "binary", "offset": 0, "bytes": "494e4352454d454e54", "weight": 0.5, "description": "INCREMENT"},
                {"type": "regex", "pattern": "(FEATURE|VENDOR|SERVER|INCREMENT)", "weight": 0.4, "description": "FlexLM keywords in payload"},
                {"type": "regex", "pattern": "SIGN=[A-F0-9]+", "weight": 0.4, "description": "License signature pattern"},
                {"type": "regex", "pattern": "(lmgrd|adskflex|flexlm)", "weight": 0.35, "description": "FlexLM daemon references"},
            ],
            "header_format": [
                {"name": "command", "type": "string", "length": 8},
                {"name": "version", "type": "uint16", "length": 2},
                {"name": "payload_length", "type": "uint16", "length": 2},
            ],
            "response_templates": {
                "heartbeat": "5345525645525f4845415254424541540001000000",
                "license_ok": "464541545552455f524553504f4e5345000100010001",
            },
        }

        self.signatures["hasp"] = {
            "name": "HASP/Sentinel",
            "description": "Hardware key protection by Thales",
            "ports": [1947],
            "patterns": [
                {"type": "binary", "offset": 0, "bytes": "484153505f", "weight": 0.5, "description": "HASP_"},
                {"type": "binary", "offset": 0, "bytes": "53454e54494e454c5f", "weight": 0.5, "description": "SENTINEL_"},
                {"type": "binary", "offset": 0, "bytes": "04030201", "weight": 0.4, "description": "HASP binary header little-endian"},
                {"type": "regex", "pattern": "HASP_QUERY", "weight": 0.5, "description": "HASP query command"},
            ],
            "header_format": [
                {"name": "signature", "type": "bytes", "length": 4},
                {"name": "command", "type": "uint8", "length": 1},
                {"name": "payload_length", "type": "uint16", "length": 2},
            ],
            "response_templates": {
                "heartbeat": "00010203000000",
                "license_ok": "0001020301000101",
            },
        }

        self.signatures["autodesk"] = {
            "name": "Autodesk Licensing",
            "description": "Autodesk product licensing protocol",
            "ports": [2080, 443],
            "patterns": [
                {"type": "binary", "offset": 0, "bytes": "4144534b", "weight": 0.5, "description": "ADSK"},
                {"type": "regex", "pattern": '\\{"license":', "weight": 0.3, "description": "JSON license payload"},
            ],
            "header_format": [
                {"name": "signature", "type": "string", "length": 4},
                {"name": "version", "type": "uint8", "length": 1},
                {"name": "command", "type": "uint8", "length": 1},
                {"name": "payload_length", "type": "uint16", "length": 2},
            ],
            "response_templates": {
                "heartbeat": "4144534b01000000",
                "license_ok": "4144534b0101000101",
            },
        }

        self.signatures["microsoft_kms"] = {
            "name": "Microsoft KMS",
            "description": "Microsoft Key Management Service protocol",
            "ports": [1688],
            "patterns": [
                {"type": "binary", "offset": 0, "bytes": "05000000", "weight": 0.3, "description": "KMS version 5 header"},
                {"type": "binary", "offset": 56, "bytes": "4b4d5356", "weight": 0.5, "description": "KMSV at offset 56"},
                {"type": "regex", "pattern": "KMSV", "weight": 0.5, "description": "KMSV signature string"},
            ],
            "header_format": [
                {"name": "signature", "type": "bytes", "length": 8},
                {"name": "protocol", "type": "uint16", "length": 2},
                {"name": "payload_length", "type": "uint16", "length": 2},
            ],
            "response_templates": {
                "license_ok": "00000000000000000200000000000000000000000000000000000000000000000000000000000000000000004b4d5356000000000000000000000000",
            },
        }

    def _calculate_byte_frequency(self, data: bytes | bytearray) -> dict[int, float]:
        """Calculate the frequency distribution of bytes in the given data.

        Args:
            data: Binary data to analyze

        Returns:
            dict[int, float]: Mapping of byte values to their frequency (0.0 to 1.0)

        """
        length = len(data)  # pylint: disable=redefined-outer-name
        if length == 0:
            return {}

        counts = Counter(data)
        return {byte: count / length for byte, count in counts.items()}

    def analyze_traffic(self, packet_data: bytes | bytearray, port: int | None = None) -> dict[str, Any] | None:
        """Analyze network traffic to identify license protocols.

        Args:
            packet_data: Raw packet data
            port: Port number (optional)

        Returns:
            dict[str, Any] | None: Identified protocol information, or None if not identified
        """
        try:
            self._store_traffic_sample(packet_data, port)
            results = self._analyze_protocol_signatures(packet_data, port)
            return self._process_analysis_results(results, packet_data, port)

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error analyzing traffic: %s", e, exc_info=True)
            return None

    def _store_traffic_sample(self, packet_data: bytes | bytearray, port: int | None) -> None:
        """Store traffic sample for learning if learning mode is enabled.

        Appends the packet data to the traffic samples buffer for later analysis
        and signature learning. Maintains a maximum size limit.

        Args:
            packet_data: Raw packet data to store.
            port: Port number associated with the packet (optional).
        """
        if not self.config["learning_mode"]:
            return

        self.traffic_samples.append(
            {
                "data": packet_data,
                "port": port,
                "timestamp": time.time(),
            },
        )

        max_samples = int(self.config.get("max_fingerprints", 1000))
        if len(self.traffic_samples) > max_samples:
            self.traffic_samples = self.traffic_samples[-max_samples:]

    def _analyze_protocol_signatures(self, packet_data: bytes | bytearray, port: int | None) -> list[dict[str, Any]]:
        """Analyze packet data against all protocol signatures.

        Args:
            packet_data: Raw packet data to analyze.
            port: Optional port number for signature context.

        Returns:
            list[dict[str, Any]]: List of matching protocol signatures with confidence scores.
        """
        results = []

        for protocol_id, signature in self.signatures.items():
            confidence = self._calculate_protocol_confidence(packet_data, port, signature)
            min_conf_val = self.config.get("min_confidence", 0.7)
            if isinstance(min_conf_val, (int, float)):
                min_conf: float = float(min_conf_val)
            else:
                min_conf = 0.7

            if confidence >= min_conf:
                results.append(
                    {
                        "protocol_id": protocol_id,
                        "name": signature["name"],
                        "description": signature["description"],
                        "confidence": confidence,
                        "header_format": signature["header_format"],
                        "response_templates": signature["response_templates"],
                    },
                )

        return results

    def _calculate_protocol_confidence(self, packet_data: bytes | bytearray, port: int | None, signature: dict[str, Any]) -> float:
        """Calculate confidence score for a protocol signature.

        Args:
            packet_data: Raw packet data to analyze.
            port: Optional port number for signature matching.
            signature: Protocol signature dictionary to match against.

        Returns:
            float: Confidence score capped at 1.0 (100%).
        """
        confidence = 0.0

        confidence += self._check_port_match(port, signature)
        confidence += self._check_statistical_features(packet_data, signature)
        confidence += self._check_binary_patterns(packet_data, signature)
        confidence += self._check_regex_patterns(packet_data, signature)

        return min(confidence, 1.0)

    def _check_port_match(self, port: int | None, signature: dict[str, Any]) -> float:
        """Check if port matches signature ports.

        Args:
            port: Port number to check, or None.
            signature: Protocol signature dictionary.

        Returns:
            float: Confidence bonus (0.2) if port matches, 0.0 otherwise.
        """
        return 0.2 if port is not None and port in signature["ports"] else 0.0

    def _check_statistical_features(self, packet_data: bytes | bytearray, signature: dict[str, Any]) -> float:
        """Check statistical features like entropy and byte frequency.

        Args:
            packet_data: Raw packet data to analyze.
            signature: Protocol signature dictionary.

        Returns:
            float: Combined confidence score from entropy and frequency checks.
        """
        if "statistical_features" not in signature:
            return 0.0

        confidence = 0.0
        confidence += self._check_entropy_match(packet_data, signature["statistical_features"])
        confidence += self._check_byte_frequency_match(packet_data, signature["statistical_features"])

        return confidence

    def _check_entropy_match(self, packet_data: bytes | bytearray, stats_features: dict[str, Any]) -> float:
        """Check if packet entropy matches signature requirements.

        Args:
            packet_data: Raw packet data to analyze.
            stats_features: Statistical features dictionary with entropy bounds.

        Returns:
            float: Confidence bonus (0.3) if entropy is in range, 0.0 otherwise.
        """
        entropy = calculate_entropy(bytes(packet_data))
        min_entropy = stats_features.get("min_entropy", 0)
        max_entropy = stats_features.get("max_entropy", 8)

        return 0.3 if min_entropy < entropy < max_entropy else 0.0

    def _check_byte_frequency_match(self, packet_data: bytes | bytearray, stats_features: dict[str, Any]) -> float:
        """Check if byte frequency distribution matches signature requirements.

        Args:
            packet_data: Raw packet data to analyze.
            stats_features: Statistical features dictionary with frequency thresholds.

        Returns:
            float: Proportional confidence score based on matching frequency thresholds.
        """
        if "byte_freq_thresholds" not in stats_features:
            return 0.0

        byte_freq = self._calculate_byte_frequency(packet_data)
        freq_matches = 0
        total_checks = 0

        for byte_val, (min_freq, max_freq) in stats_features["byte_freq_thresholds"].items():
            byte_val = int(byte_val) if isinstance(byte_val, str) else byte_val
            total_checks += 1

            if byte_val in byte_freq and min_freq <= byte_freq[byte_val] <= max_freq:
                freq_matches += 1

        return 0.3 * (freq_matches / total_checks) if total_checks > 0 else 0.0

    def _check_binary_patterns(self, packet_data: bytes | bytearray, signature: dict[str, Any]) -> float:
        """Check binary pattern matching for signature.

        Args:
            packet_data: Raw packet data to analyze.
            signature: Protocol signature dictionary.

        Returns:
            float: Cumulative confidence score from all binary pattern matches.
        """
        if "patterns" not in signature:
            return 0.0

        confidence = 0.0

        for pattern in signature["patterns"]:
            if not isinstance(pattern, dict):
                continue
            pattern_type = pattern.get("type", "binary")
            if pattern_type == "binary" and "bytes" in pattern:
                confidence += self._match_binary_pattern(packet_data, pattern)

        return confidence

    def _match_binary_pattern(self, packet_data: bytes | bytearray, pattern: dict[str, Any]) -> float:
        """Match a single binary pattern against packet data.

        Args:
            packet_data: Raw packet data to match against.
            pattern: Pattern dictionary with offset, bytes, weight, and optional mask.

        Returns:
            float: Weight value if pattern matches, 0.0 otherwise.
        """
        offset: int = int(pattern.get("offset", 0))
        raw_bytes = pattern["bytes"]
        if isinstance(raw_bytes, str):
            pattern_bytes = bytes.fromhex(raw_bytes)
        elif isinstance(raw_bytes, bytes):
            pattern_bytes = raw_bytes
        else:
            pattern_bytes = bytes(raw_bytes)
        weight: float = float(pattern.get("weight", 0.2))

        if offset + len(pattern_bytes) > len(packet_data):
            return 0.0

        if pattern.get("mask") is None:
            if packet_data[offset : offset + len(pattern_bytes)] == pattern_bytes:
                return weight
        elif self._match_masked_pattern(packet_data, pattern, offset):
            return weight

        return 0.0

    def _match_masked_pattern(self, packet_data: bytes | bytearray, pattern: dict[str, Any], offset: int) -> bool:
        """Check masked pattern match.

        Args:
            packet_data: Raw packet data to match against.
            pattern: Pattern dictionary containing bytes and mask fields.
            offset: Byte offset in packet data to start matching.

        Returns:
            bool: True if masked pattern matches, False otherwise.
        """
        raw_bytes = pattern["bytes"]
        raw_mask = pattern["mask"]
        if isinstance(raw_bytes, str):
            pattern_bytes = bytes.fromhex(raw_bytes)
        elif isinstance(raw_bytes, bytes):
            pattern_bytes = raw_bytes
        else:
            pattern_bytes = bytes(raw_bytes)
        if isinstance(raw_mask, str):
            mask_bytes = bytes.fromhex(raw_mask)
        elif isinstance(raw_mask, bytes):
            mask_bytes = raw_mask
        else:
            mask_bytes = bytes(raw_mask)

        for i in range(len(pattern_bytes)):
            masked_packet = mask_bytes[i] & packet_data[offset + i]
            masked_pattern = mask_bytes[i] & pattern_bytes[i]
            if masked_packet != masked_pattern:
                return False
        return True

    def _check_regex_patterns(self, packet_data: bytes | bytearray, signature: dict[str, Any]) -> float:
        """Check regex pattern matching for signature.

        Args:
            packet_data: Raw packet data to analyze.
            signature: Protocol signature dictionary.

        Returns:
            float: Cumulative confidence score from all regex pattern matches.
        """
        if "patterns" not in signature:
            return 0.0

        regex_patterns: list[dict[str, Any]] = []
        for p in signature["patterns"]:
            if isinstance(p, dict) and p.get("type") == "regex" and "pattern" in p:
                regex_patterns.append(p)
            elif isinstance(p, str):
                regex_patterns.append({"pattern": p, "weight": 0.3})

        if not regex_patterns:
            return 0.0

        total_confidence = 0.0
        packet_bytes = bytes(packet_data)
        packet_str = packet_bytes.decode("utf-8", errors="ignore")

        for regex_entry in regex_patterns:
            pattern_str = regex_entry["pattern"]
            weight = float(regex_entry.get("weight", 0.3))
            try:
                if re.search(pattern_str, packet_str, re.IGNORECASE):
                    total_confidence += weight
                elif re.search(pattern_str.encode("utf-8"), packet_bytes):
                    total_confidence += weight
            except re.error:
                continue

        return total_confidence

    def _process_analysis_results(
        self,
        results: list[dict[str, Any]],
        packet_data: bytes | bytearray,
        port: int | None,
    ) -> dict[str, Any] | None:
        """Process analysis results and return best match or learn new signature.

        Args:
            results: List of matched protocol signatures.
            packet_data: Raw packet data analyzed.
            port: Optional port number for learning context.

        Returns:
            dict[str, Any] | None: Best matching protocol result or None if no match.
        """
        results.sort(key=lambda x: x["confidence"], reverse=True)

        if results:
            self.logger.info(
                "Identified protocol: %s (confidence: %.2f)",
                results[0]["name"],
                results[0]["confidence"],
            )
            return results[0]

        if self.config["learning_mode"]:
            self._learn_new_signature(packet_data, port)

        return None

    def identify_protocol(self, data_bytes: bytes | bytearray, port: int | None = None) -> dict[str, Any] | None:
        """Identify the protocol from raw packet data.

        This is a convenience method that wraps analyze_traffic to provide
        a simpler interface for protocol identification.

        Args:
            data_bytes: Raw packet data to analyze.
            port: Optional port number for context.

        Returns:
            Dictionary containing protocol identification results:
            - name: Protocol name (e.g., "FlexLM", "HASP")
            - protocol_id: Internal protocol identifier
            - confidence: Confidence percentage (0-100)
            - description: Protocol description
            Returns None if no protocol could be identified.

        """
        if not data_bytes:
            return None

        if result := self.analyze_traffic(data_bytes, port):
            confidence_pct = int(result.get("confidence", 0) * 100)

            return {
                "name": result.get("name", "Unknown"),
                "protocol_id": result.get("protocol_id", "unknown"),
                "confidence": confidence_pct,
                "description": result.get("description", ""),
                "header_format": result.get("header_format", []),
                "response_templates": result.get("response_templates", {}),
            }

        return next(
            (
                {
                    "name": signature["name"],
                    "protocol_id": protocol_id,
                    "confidence": 50,
                    "description": signature.get("description", ""),
                    "header_format": signature.get("header_format", []),
                    "response_templates": signature.get("response_templates", {}),
                }
                for protocol_id, signature in self.signatures.items()
                if self._quick_pattern_match(data_bytes, signature)
            ),
            None,
        )

    def _quick_pattern_match(self, data_bytes: bytes | bytearray, signature: dict[str, Any]) -> bool:
        """Perform quick pattern matching without full analysis.

        Args:
            data_bytes: Data to check.
            signature: Protocol signature to match against.

        Returns:
            True if any pattern matches, False otherwise.

        """
        patterns = signature.get("patterns", [])

        for pattern in patterns:
            if not isinstance(pattern, dict):
                continue

            offset = pattern.get("offset", 0)
            pattern_bytes = pattern.get("bytes")

            if pattern_bytes is None:
                continue

            if isinstance(pattern_bytes, str):
                pattern_bytes = pattern_bytes.encode("utf-8")

            if offset + len(pattern_bytes) <= len(data_bytes) and data_bytes[offset : offset + len(pattern_bytes)] == pattern_bytes:
                return True

        return False

    def detect_protocols(self) -> list[dict[str, Any]]:
        """Detect active license protocols by scanning known license server ports.

        This method probes common license server ports on localhost and nearby network
        addresses to identify running license servers and their protocols.

        Returns:
            list[dict[str, Any]]: List of detected protocol dictionaries containing:
            - name: Protocol name
            - port: Port number where protocol was detected
            - confidence: Detection confidence percentage (0-100)
            - pattern: Sample pattern matched
            - host: Host address where detected
        """
        detected = []

        license_server_hosts = ["127.0.0.1", "localhost"]

        for host in license_server_hosts:
            for port in self.license_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((host, port))

                    if result == 0:
                        probe_data = self._send_protocol_probe(sock, port)
                        sock.close()

                        if probe_data:
                            if protocol_info := self._identify_protocol_from_response(probe_data, port):
                                protocol_info["host"] = host
                                detected.append(protocol_info)
                        else:
                            for protocol_id, signature in self.signatures.items():
                                if port in signature.get("ports", []):
                                    detected.append({
                                        "name": signature["name"],
                                        "port": port,
                                        "confidence": 60,
                                        "pattern": f"Port match for {signature['name']}",
                                        "host": host,
                                        "protocol_id": protocol_id,
                                    })
                                    break
                    else:
                        sock.close()

                except (TimeoutError, OSError) as e:
                    self.logger.debug("Port scan error on %s:%d: %s", host, port, e, exc_info=True)
                    continue

        self.logger.info("Protocol detection complete: found %d active protocols", len(detected))
        return detected

    def _send_protocol_probe(self, sock: socket.socket, port: int) -> bytes | None:
        """Send appropriate probe packet based on port and capture response.

        Args:
            sock: Connected socket to license server.
            port: Port number for protocol-specific probing.

        Returns:
            bytes | None: Response bytes from server, or None if no response.
        """
        probe_packets = {
            27000: b"FEATURE\x00\x01\x00\x00",
            27001: b"VENDOR_STRING\x00",
            1947: b"\x00\x01\x02\x03HASP_QUERY\x00",
            22350: b"CMACT\x00\x01",
            2080: b"ADSK\x01\x00",
            1688: b"\x00\x00\x00\x00\x00\x00\x00\x00",
            5093: b"RMS_QUERY\x00",
        }

        generic_probe = b"\x00\x01\x00\x00LICENSE_PROBE\x00"
        probe = probe_packets.get(port, generic_probe)

        try:
            sock.settimeout(2.0)
            sock.send(probe)
            response = sock.recv(4096)
            return response or None
        except (TimeoutError, OSError) as e:
            self.logger.debug("Protocol probe timeout/error on port %d: %s", port, e, exc_info=True)
            return None

    def _identify_protocol_from_response(self, response: bytes, port: int) -> dict[str, Any] | None:
        """Identify protocol from server response data.

        Args:
            response: Raw response bytes from license server.
            port: Port number where response was received.

        Returns:
            dict[str, Any] | None: Protocol identification dictionary or None if unidentified.
        """
        best_match = None
        best_confidence = 0.0

        for protocol_id, signature in self.signatures.items():
            confidence = self._calculate_protocol_confidence(response, port, signature)

            if confidence > best_confidence and confidence >= 0.5:
                best_confidence = confidence
                best_match = {
                    "name": signature["name"],
                    "port": port,
                    "confidence": int(confidence * 100),
                    "pattern": response[:50].hex() if response else "",
                    "protocol_id": protocol_id,
                    "description": signature.get("description", ""),
                }

        return best_match

    def fingerprint_packet(self, packet_data: bytes | bytearray, port: int | None = None) -> dict[str, Any] | None:
        """Fingerprint a single packet for protocol identification.

        Args:
            packet_data: Raw packet data.
            port: Port number (optional).

        Returns:
            dict[str, Any] | None: Protocol fingerprint information, or None if not identified.
        """
        try:
            self.logger.debug("Fingerprinting packet of %d bytes on port %s", len(packet_data), port)

            if result := self.analyze_traffic(packet_data, port):
                # Add fingerprinting specific metadata
                result["fingerprint_timestamp"] = time.time()
                result["packet_size"] = len(packet_data)
                result["source_port"] = port

                # Enhance with packet-specific analysis
                packet_analysis = self._analyze_packet_structure(packet_data)
                result.update(packet_analysis)

                return result

            return None

        except Exception as e:
            self.logger.exception("Packet fingerprinting failed: %s", e, exc_info=True)
            return None

    def _analyze_packet_structure(self, packet_data: bytes | bytearray) -> dict[str, Any]:
        """Analyze packet structure for additional fingerprint information.

        Args:
            packet_data: Raw packet data to analyze.

        Returns:
            dict[str, Any]: Analysis results containing entropy, ASCII ratio, and protocol hints.
        """
        analysis: dict[str, Any] = {
            "packet_entropy": 0.0,
            "ascii_ratio": 0.0,
            "common_patterns": [],
            "protocol_hints": [],
        }

        try:
            # Calculate entropy
            if len(packet_data) > 0:
                byte_counts = [packet_data.count(i) for i in range(256)]
                analysis["packet_entropy"] = -sum(
                    (count / len(packet_data)) * math.log2(count / len(packet_data)) for count in byte_counts if count > 0
                )

            # Calculate ASCII ratio
            ascii_bytes = sum(32 <= b <= 126 for b in packet_data)
            analysis["ascii_ratio"] = ascii_bytes / len(packet_data) if packet_data else 0.0

            # Look for common patterns
            protocol_hints: list[str] = []
            if b"HTTP" in packet_data:
                protocol_hints.append("HTTP")
            if b"FTP" in packet_data:
                protocol_hints.append("FTP")
            if packet_data.startswith(b"\x16\x03"):  # TLS handshake
                protocol_hints.append("TLS")
            if b"SSH" in packet_data:
                protocol_hints.append("SSH")

            # License-specific patterns
            if any(pattern in packet_data for pattern in [b"license", b"activation", b"key"]):
                protocol_hints.append("License_Protocol")

            analysis["protocol_hints"] = protocol_hints

        except Exception as e:
            self.logger.debug("Packet structure analysis failed: %s", e, exc_info=True)

        return analysis

    def parse_packet(self, protocol_id: str, packet_data: bytes | bytearray) -> dict[str, Any] | None:
        """Parse a packet according to the protocol's header format.

        Args:
            protocol_id: Protocol identifier.
            packet_data: Raw packet data.

        Returns:
            dict[str, Any] | None: Parsed packet fields, or None if parsing failed.
        """
        try:
            if protocol_id not in self.signatures:
                return None

            signature = self.signatures[protocol_id]
            header_format = signature["header_format"]

            result: dict[str, Any] = {}
            offset = 0

            for field in header_format:
                field_name: str = str(field["name"])
                field_type: str = str(field["type"])
                field_length: int = int(field["length"])

                if offset + field_length > len(packet_data):
                    return None

                if field_type == "uint8":
                    result[field_name] = packet_data[offset]
                elif field_type in {"uint16", "uint32"}:
                    result[field_name] = int.from_bytes(packet_data[offset : offset + field_length], byteorder="big")
                elif field_type == "string":
                    result[field_name] = packet_data[offset : offset + field_length].decode("utf-8", errors="ignore").rstrip("\x00")
                elif field_type == "bytes":
                    result[field_name] = bytes(packet_data[offset : offset + field_length])

                offset += field_length

            # Add payload
            if offset < len(packet_data):
                result["payload"] = packet_data[offset:]

            return result

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error parsing packet: %s", e, exc_info=True)
            return None

    def generate_response(self, protocol_id: str, request_packet: bytes | bytearray, response_type: str = "license_ok") -> bytes | None:
        """Generate a response packet for a license check request.

        Args:
            protocol_id: Protocol identifier.
            request_packet: Request packet data.
            response_type: Type of response to generate.

        Returns:
            bytes | None: Response packet data, or None if generation failed.
        """
        try:
            if protocol_id not in self.signatures:
                return None

            signature = self.signatures[protocol_id]

            if response_type not in signature["response_templates"]:
                response_type = next(iter(signature["response_templates"]))

            raw_template = signature["response_templates"][response_type]
            if isinstance(raw_template, str):
                response_template = bytes.fromhex(raw_template)
            elif isinstance(raw_template, bytes):
                response_template = raw_template
            else:
                response_template = bytes(raw_template)

            # Parse request packet
            parsed_request = self.parse_packet(protocol_id, request_packet)

            if not parsed_request:
                return response_template

            # Customize response based on request
            response = bytearray(response_template)

            # Copy request fields that should be echoed back
            if protocol_id == "flexlm" and len(response) >= 4 and len(request_packet) >= 4:
                # Copy version field
                response[2:4] = request_packet[2:4]

            elif protocol_id == "hasp" and len(response) >= 7 and len(request_packet) >= 7:
                # Copy signature field
                response[:4] = request_packet[:4]

            elif protocol_id == "autodesk" and len(response) >= 6 and len(request_packet) >= 6:
                # Copy signature and version fields
                response[:5] = request_packet[:5]

            elif protocol_id == "microsoft_kms" and len(response) >= 12 and len(request_packet) >= 12:
                # Copy signature and protocol fields
                response[:10] = request_packet[:10]

            return bytes(response)

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error generating response: %s", e, exc_info=True)
            return None

    def _learn_new_signature(self, packet_data: bytes | bytearray, port: int | None = None) -> bool:
        """Attempt to learn a new protocol signature from traffic.

        Args:
            packet_data: Raw packet data.
            port: Port number (optional).

        Returns:
            bool: True if a new signature was learned, False otherwise.
        """
        try:
            # Need at least 10 samples to learn
            if len(self.traffic_samples) < 10:
                return False

            # Find similar packets
            similar_packets = []

            for sample in self.traffic_samples:
                if sample["data"] != packet_data:  # Skip self
                    similarity = self._calculate_similarity(packet_data, sample["data"])
                    if similarity > 0.7:
                        similar_packets.append(sample)

            if len(similar_packets) < 3:
                return False

            # Extract common patterns
            patterns = self._extract_common_patterns(similar_packets)

            if not patterns:
                return False

            # Create new signature
            signature_id = f"learned_{len(self.learned_signatures) + 1}"

            signature = {
                "name": f"Learned Protocol {len(self.learned_signatures) + 1}",
                "description": "Automatically learned protocol signature",
                "ports": [port] if port else [],
                "patterns": patterns,
                "header_format": [
                    {"name": "signature", "type": "bytes", "length": len(patterns[0]["bytes"])},
                    {"name": "payload", "type": "bytes", "length": 0},  # Variable length
                ],
                "response_templates": {
                    "license_ok": b"\x01" * 8,  # Generic positive response
                },
            }

            # Add to learned signatures
            self.learned_signatures[signature_id] = signature

            # Add to active signatures
            self.signatures[signature_id] = signature

            # Save signatures
            self._save_signatures()

            self.logger.info("Learned new protocol signature: %s", signature_id)
            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error learning new signature: %s", e, exc_info=True)
            return False

    def _calculate_similarity(self, data1: bytes | bytearray, data2: bytes | bytearray) -> float:
        """Calculate similarity between two data samples.

        Args:
            data1: First data sample.
            data2: Second data sample.

        Returns:
            float: Similarity score (0.0 to 1.0).
        """
        # Simple similarity based on common bytes
        min_len = min(len(data1), len(data2))
        max_len = max(len(data1), len(data2))

        if min_len == 0:
            return 0.0

        common_bytes = sum(data1[i] == data2[i] for i in range(min_len))
        return common_bytes / max_len

    def _extract_common_patterns(self, samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Extract common patterns from similar packets.

        Args:
            samples: List of similar packet samples.

        Returns:
            list[dict[str, Any]]: List of pattern dictionaries.
        """
        # Extract common prefix
        min_len = min(len(sample["data"]) for sample in samples)

        if min_len < 4:
            return []

        # Find longest common prefix
        prefix_len = 0
        for i in range(min_len):
            byte_values = {sample["data"][i] for sample in samples}
            if len(byte_values) == 1:
                prefix_len += 1
            else:
                break

        if prefix_len < 2:
            return []

        # Create pattern from prefix
        prefix_bytes = samples[0]["data"][:prefix_len]

        return [
            {"offset": 0, "bytes": prefix_bytes, "mask": None, "weight": 0.5},
        ]

    def analyze_pcap(self, pcap_path: str) -> dict[str, Any]:
        """Analyze PCAP file for protocol fingerprints.

        This method processes a PCAP capture file to identify and fingerprint
        network protocols, particularly focusing on license-related communications.

        Args:
            pcap_path: Path to PCAP file.

        Returns:
            dict[str, Any]: Dictionary containing:
            - file: Path to analyzed file
            - protocols: List of identified protocols
            - fingerprints: Detailed protocol fingerprints
        """
        self.logger.info("Analyzing PCAP file: %s", pcap_path)

        results = {
            "file": pcap_path,
            "protocols": [],
            "fingerprints": {},
            "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_packets": 0,
                "license_packets": 0,
                "identified_protocols": 0,
                "new_signatures_learned": 0,
            },
        }

        try:
            # Check if file exists
            if not os.path.exists(pcap_path):
                self.logger.exception("PCAP file not found: %s", pcap_path)
                results["error"] = "File not found"
                return results

            # Try to use pyshark if available
            try:
                import pyshark

                # Open PCAP file
                capture = pyshark.FileCapture(pcap_path, keep_packets=False)

                packets_analyzed = 0
                license_packets = 0
                protocol_counts: Counter[str] = Counter()

                # Process packets
                for packet in capture:
                    packets_analyzed += 1

                    # Check for TCP packets
                    if hasattr(packet, "tcp") and hasattr(packet, "ip"):
                        src_port = int(packet.tcp.srcport)
                        dst_port = int(packet.tcp.dstport)

                        # Check if it's a license port
                        if dst_port in self.license_ports or src_port in self.license_ports:
                            license_packets += 1

                            # Extract payload if available
                            if hasattr(packet.tcp, "payload"):
                                try:
                                    payload = bytes.fromhex(packet.tcp.payload.replace(":", ""))

                                    if fingerprint_result := self.fingerprint_packet(payload, dst_port):
                                        protocol_id_str = str(fingerprint_result["protocol_id"])
                                        protocol_counts[protocol_id_str] += 1

                                        # Store detailed fingerprint
                                        fingerprints_obj = results["fingerprints"]
                                        if not isinstance(fingerprints_obj, dict):
                                            fingerprints_obj = {}
                                            results["fingerprints"] = fingerprints_obj
                                        fingerprints_dict: dict[str, Any] = fingerprints_obj
                                        if protocol_id_str not in fingerprints_dict:
                                            fingerprints_dict[protocol_id_str] = {
                                                "name": fingerprint_result.get("name", protocol_id_str),
                                                "confidence": fingerprint_result.get("confidence", 0),
                                                "packets": 0,
                                                "ports": set(),
                                                "sample_data": [],
                                            }
                                            results["fingerprints"] = fingerprints_dict

                                        fp = fingerprints_dict[protocol_id_str]
                                        fp["packets"] += 1
                                        fp["ports"].add(dst_port)

                                        # Store sample data (limit to 5 samples)
                                        if len(fp["sample_data"]) < 5:
                                            fp["sample_data"].append(
                                                {
                                                    "timestamp": float(packet.sniff_timestamp),
                                                    "src": f"{packet.ip.src}:{src_port}",
                                                    "dst": f"{packet.ip.dst}:{dst_port}",
                                                    "size": len(payload),
                                                    "entropy": calculate_entropy(payload),
                                                },
                                            )

                                except Exception as e:
                                    self.logger.debug("Error processing packet payload: %s", e, exc_info=True)

                capture.close()

                # Convert sets to lists for JSON serialization
                fingerprints_obj_final = results["fingerprints"]
                if isinstance(fingerprints_obj_final, dict):
                    fingerprints_final: dict[str, Any] = fingerprints_obj_final
                    for fp in fingerprints_final.values():
                        fp["ports"] = list(fp["ports"])
                    results["fingerprints"] = fingerprints_final

                # Update results
                protocols_list: list[str] = list(protocol_counts.keys())
                results["protocols"] = protocols_list
                summary_obj = results["summary"]
                if isinstance(summary_obj, dict):
                    summary_dict: dict[str, Any] = summary_obj
                    summary_dict["total_packets"] = packets_analyzed
                    summary_dict["license_packets"] = license_packets
                    summary_dict["identified_protocols"] = len(protocols_list)
                    results["summary"] = summary_dict

                self.logger.info("PCAP analysis complete: %d packets, %d protocols identified", packets_analyzed, len(results["protocols"]))

            except ImportError as e:
                self.logger.warning("pyshark not available, using basic PCAP parsing: %s", e, exc_info=True)
                results["error"] = "Limited analysis - pyshark not available"

                # Basic PCAP file structure parsing
                with open(pcap_path, "rb") as f:
                    # Read PCAP header
                    pcap_header = f.read(24)
                    if len(pcap_header) < 24:
                        results["error"] = "Invalid PCAP file"
                        return results

                    # Simple packet counting
                    packet_count = 0
                    while True:
                        # Read packet header
                        packet_header = f.read(16)
                        if len(packet_header) < 16:
                            break

                        # Get packet length
                        packet_len = int.from_bytes(packet_header[8:12], byteorder="little")

                        # Skip packet data
                        f.seek(packet_len, 1)
                        packet_count += 1

                    summary_obj_alt = results["summary"]
                    if isinstance(summary_obj_alt, dict):
                        summary_dict_alt: dict[str, Any] = summary_obj_alt
                        summary_dict_alt["total_packets"] = packet_count
                        results["summary"] = summary_dict_alt

        except Exception as e:
            self.logger.exception("Error analyzing PCAP file: %s", e, exc_info=True)
            results["error"] = str(e)

        return results

    def analyze_binary(self, binary_path: str) -> dict[str, Any]:
        """Analyze binary for network protocols.

        This method analyzes a binary file to identify hardcoded network protocols,
        license server addresses, and protocol-related strings that indicate
        network-based license verification.

        Args:
            binary_path: Path to binary file.

        Returns:
            dict[str, Any]: Dictionary containing:
            - binary: Path to analyzed file
            - network_functions: List of identified network functions
            - protocols: List of likely protocols used
        """
        self.logger.info("Analyzing binary for network protocols: %s", binary_path)

        results: dict[str, Any] = {
            "binary": binary_path,
            "network_functions": [],
            "protocols": [],
            "license_indicators": [],
            "network_strings": [],
            "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "has_network_code": False,
                "likely_license_client": False,
                "protocol_confidence": 0.0,
            },
        }

        try:
            # Check if file exists
            if not os.path.exists(binary_path):
                self.logger.exception("Binary file not found: %s", binary_path)
                results["error"] = "File not found"
                return results

            # Read binary file
            with open(binary_path, "rb") as f:
                binary_data = f.read()

            # 1. Search for network-related function imports
            network_functions = [
                b"socket",
                b"connect",
                b"send",
                b"recv",
                b"WSAStartup",
                b"getaddrinfo",
                b"gethostbyname",
                b"inet_addr",
                b"WinHttpOpen",
                b"InternetOpen",
                b"URLDownload",
                b"curl_easy_init",
                b"SSL_connect",
                b"TLS_",
            ]

            network_funcs_list: list[str] = [func.decode("utf-8", errors="ignore") for func in network_functions if func in binary_data]
            results["network_functions"] = network_funcs_list

            # 2. Search for protocol-specific strings
            protocol_indicators = {
                "FlexLM": [
                    b"lmgrd",
                    b"flexlm",
                    b"license.dat",
                    b"@",
                    b"SERVER",
                    b"VENDOR",
                    b"FEATURE",
                ],
                "HASP": [b"hasp", b"aksusbd", b"hasplms", b"sentinel", b"1947"],
                "CodeMeter": [b"codemeter", b"cmact", b"wibu", b"22350", b"CmDongle"],
                "Sentinel": [b"sentinel", b"sntlkeyssrvr", b"RMS License Manager", b"5093"],
                "Autodesk": [b"adskflex", b"autodesk", b"flexnet", b"2080"],
                "Microsoft KMS": [b"KMSClient", b"SLMgr", b"1688", b"kms."],
                "Generic": [b"LICENSE", b"ACTIVATION", b"serial", b"product_key", b"registration"],
            }

            license_indicators_list: list[dict[str, str]] = []
            protocols_list_bin: list[str] = []
            for protocol, indicators in protocol_indicators.items():
                matches = 0
                for indicator in indicators:
                    if indicator in binary_data:
                        matches += 1

                        # Extract context around the match
                        index = binary_data.find(indicator)
                        start = max(0, index - 20)
                        end = min(len(binary_data), index + len(indicator) + 20)
                        context = binary_data[start:end]

                        license_indicators_list.append(
                            {
                                "protocol": protocol,
                                "indicator": indicator.decode("utf-8", errors="ignore"),
                                "context": context.hex(),
                            },
                        )

                if matches >= 2:  # At least 2 indicators for confidence
                    protocols_list_bin.append(protocol)

            results["license_indicators"] = license_indicators_list
            results["protocols"] = protocols_list_bin

            # 3. Search for network-related strings
            # Extract ASCII strings
            ascii_strings = re.findall(rb"[\x20-\x7e]{4,}", binary_data)

            network_patterns = [
                re.compile(rb"(?:https?://|ftp://|tcp://|udp://)[^\s]+"),
                re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),  # IP addresses
                re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}\b"),  # IP:port
                re.compile(rb"(?:port|PORT)\s*[=:]\s*[0-9]{1,5}"),
                re.compile(rb"(?:server|SERVER)\s*[=:]\s*[^\s]+"),
                re.compile(rb"license[_\-]?server", re.IGNORECASE),
                re.compile(rb"activation[_\-]?server", re.IGNORECASE),
            ]

            network_strings_list: list[str] = []
            for string in ascii_strings[:1000]:  # Limit to first 1000 strings
                for pattern in network_patterns:
                    if pattern.search(string):
                        decoded = string.decode("utf-8", errors="ignore")
                        if decoded not in network_strings_list:
                            network_strings_list.append(decoded)
                        break
            results["network_strings"] = network_strings_list

            # 4. Check for specific port numbers
            license_ports_bytes = [
                b"\x69\x68",  # 27000 (FlexLM)
                b"\x69\x69",  # 27001 (FlexLM)
                b"\x07\x9b",  # 1947 (HASP)
                b"\x17\x71",  # 6001 (HASP)
                b"\x57\x36",  # 22350 (CodeMeter)
                b"\x08\x20",  # 2080 (License Manager)
                b"\x20\x28",  # 8224 (License Server)
                b"\x13\xd5",  # 5093 (Sentinel)
                b"\x06\x90",  # 1688 (KMS)
            ]

            for port_bytes in license_ports_bytes:
                if port_bytes in binary_data:
                    port_num = int.from_bytes(port_bytes, byteorder="big")
                    self.logger.debug("Found license port number: %d", port_num)

            # 5. Calculate summary
            summary_final: dict[str, Any] = dict(results["summary"])
            summary_final["has_network_code"] = len(results["network_functions"]) > 0
            summary_final["likely_license_client"] = len(results["protocols"]) > 0 or len(results["license_indicators"]) > 0

            # Calculate confidence
            confidence = 0.0
            if results["network_functions"]:
                confidence += 0.3
            if results["protocols"]:
                confidence += 0.4
            if results["license_indicators"]:
                confidence += 0.3

            summary_final["protocol_confidence"] = min(confidence, 1.0)
            results["summary"] = summary_final

            self.logger.info(
                "Binary analysis complete: %d network functions, %d protocols identified",
                len(results["network_functions"]),
                len(results["protocols"]),
            )

        except Exception as e:
            self.logger.exception("Error analyzing binary: %s", e, exc_info=True)
            results["error"] = str(e)

        return results


__all__ = ["ProtocolFingerprinter", "calculate_entropy"]

logger.debug("Module load complete (end of file)")
