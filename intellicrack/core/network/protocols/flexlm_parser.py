"""FlexLM License Protocol Parser and Response Generator.

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
import struct
import time
from dataclasses import dataclass
from typing import Any

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FlexLMRequest:
    """FlexLM request structure."""

    command: int
    version: int
    sequence: int
    client_id: str
    feature: str
    version_requested: str
    platform: str
    hostname: str
    username: str
    pid: int
    checkout_time: int
    additional_data: dict[str, Any]


@dataclass
class FlexLMResponse:
    """FlexLM response structure."""

    status: int
    sequence: int
    server_version: str
    feature: str
    expiry_date: str
    license_key: str
    server_id: str
    additional_data: dict[str, Any]


class FlexLMProtocolParser:
    """Real FlexLM protocol parser and response generator."""

    # FlexLM protocol constants
    FLEXLM_COMMANDS = {
        0x01: "CHECKOUT",
        0x02: "CHECKIN",
        0x03: "STATUS",
        0x04: "HEARTBEAT",
        0x05: "FEATURE_INFO",
        0x06: "SERVER_INFO",
        0x07: "USER_INFO",
        0x08: "VENDOR_INFO",
        0x09: "LICENSE_INFO",
        0x0A: "SHUTDOWN",
        0x0B: "RESTART",
        0x0C: "REREAD",
        0x0D: "REMOVE_USER",
        0x0E: "REMOVE_FEATURE",
        0x10: "HOSTID_REQUEST",
        0x11: "ENCRYPTION_SEED",
        0x12: "BORROW_REQUEST",
        0x13: "RETURN_REQUEST",
    }

    FLEXLM_STATUS_CODES = {
        0x00: "SUCCESS",
        0x01: "FEATURE_NOT_FOUND",
        0x02: "NO_LICENSE_AVAILABLE",
        0x03: "SERVER_UNAVAILABLE",
        0x04: "INVALID_LICENSE",
        0x05: "CHECKOUT_FAILED",
        0x06: "HEARTBEAT_FAILED",
        0x07: "INVALID_HOSTID",
        0x08: "FEATURE_EXPIRED",
        0x09: "VENDOR_DOWN",
        0x0A: "LICENSE_EXPIRED",
        0x0B: "INVALID_SIGNATURE",
        0x0C: "ENCRYPTION_FAILED",
    }

    def __init__(self):
        """Initialize the FlexLM protocol parser with license tracking and server features."""
        self.logger = get_logger(__name__)
        self.active_checkouts = {}  # Track active license checkouts
        self.server_features = {}  # Available features on server
        self.encryption_seed = self._generate_encryption_seed()
        self._load_default_features()

    def _load_default_features(self):
        """Load default feature set for common applications."""
        self.server_features = {
            # Autodesk Products
            "AUTOCAD": {
                "version": "2024.0",
                "expiry": "31-dec-2025",
                "count": 100,
                "vendor": "ADSKFLEX",
                "signature": "A1B2C3D4E5F6789012345678901234567890ABCD",
            },
            "INVENTOR": {
                "version": "2024.0",
                "expiry": "31-dec-2025",
                "count": 50,
                "vendor": "ADSKFLEX",
                "signature": "B2C3D4E5F6789012345678901234567890ABCDEF",
            },
            "MAYA": {
                "version": "2024.0",
                "expiry": "31-dec-2025",
                "count": 25,
                "vendor": "ADSKFLEX",
                "signature": "C3D4E5F6789012345678901234567890ABCDEF12",
            },
            # MATLAB Products
            "MATLAB": {
                "version": "R2024a",
                "expiry": "31-dec-2025",
                "count": 100,
                "vendor": "MLM",
                "signature": "D4E5F6789012345678901234567890ABCDEF1234",
            },
            "SIMULINK": {
                "version": "R2024a",
                "expiry": "31-dec-2025",
                "count": 50,
                "vendor": "MLM",
                "signature": "E5F6789012345678901234567890ABCDEF123456",
            },
            # SolidWorks
            "SOLIDWORKS": {
                "version": "2024",
                "expiry": "31-dec-2025",
                "count": 100,
                "vendor": "SW_D",
                "signature": "F6789012345678901234567890ABCDEF12345678",
            },
            # ANSYS Products
            "ANSYS": {
                "version": "2024.1",
                "expiry": "31-dec-2025",
                "count": 50,
                "vendor": "ANSYS",
                "signature": "6789012345678901234567890ABCDEF1234567890",
            },
            # Generic features for testing
            "GENERIC_CAD": {
                "version": "1.0",
                "expiry": "31-dec-2025",
                "count": 999,
                "vendor": "FLEX",
                "signature": "789012345678901234567890ABCDEF123456789A",
            },
        }

    def _generate_encryption_seed(self) -> bytes:
        """Generate encryption seed for FlexLM communication."""
        return hashlib.sha256(str(time.time()).encode()).digest()

    def parse_request(self, data: bytes) -> FlexLMRequest | None:
        """Parse incoming FlexLM request.

        Args:
            data: Raw FlexLM request data

        Returns:
            Parsed FlexLMRequest object or None if invalid

        """
        try:
            if len(data) < 16:  # Minimum FlexLM header size
                self.logger.warning("FlexLM request too short")
                return None

            # Parse FlexLM header
            offset = 0

            # Check for FlexLM magic number (varies by version)
            magic = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4

            if magic not in [0x464C4558, 0x4C4D5F56, 0x46584C4D]:  # "FLEX", "LM_V", "FXLM"
                self.logger.debug(f"Invalid FlexLM magic: 0x{magic:X}")
                return None

            # Parse header fields
            command = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2

            version = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2

            sequence = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4

            length = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4

            if len(data) < length:
                self.logger.warning("FlexLM request length mismatch")
                return None

            # Parse variable-length fields
            client_id = self._parse_string_field(data, offset)
            offset += len(client_id) + 1

            feature = self._parse_string_field(data, offset)
            offset += len(feature) + 1

            version_requested = self._parse_string_field(data, offset)
            offset += len(version_requested) + 1

            platform = self._parse_string_field(data, offset)
            offset += len(platform) + 1

            hostname = self._parse_string_field(data, offset)
            offset += len(hostname) + 1

            username = self._parse_string_field(data, offset)
            offset += len(username) + 1

            # Parse remaining numeric fields
            if offset + 8 <= len(data):
                pid = struct.unpack(">I", data[offset : offset + 4])[0]
                offset += 4

                checkout_time = struct.unpack(">I", data[offset : offset + 4])[0]
                offset += 4
            else:
                pid = 0
                checkout_time = int(time.time())

            # Parse additional data if present
            additional_data = {}
            if offset < len(data):
                additional_data = self._parse_additional_data(data[offset:])

            request = FlexLMRequest(
                command=command,
                version=version,
                sequence=sequence,
                client_id=client_id,
                feature=feature,
                version_requested=version_requested,
                platform=platform,
                hostname=hostname,
                username=username,
                pid=pid,
                checkout_time=checkout_time,
                additional_data=additional_data,
            )

            self.logger.info(f"Parsed FlexLM {self.FLEXLM_COMMANDS.get(command, 'UNKNOWN')} request for feature '{feature}'")
            return request

        except Exception as e:
            self.logger.error(f"Failed to parse FlexLM request: {e}")
            return None

    def _parse_string_field(self, data: bytes, offset: int) -> str:
        """Parse null-terminated string from data."""
        try:
            end = data.find(b"\x00", offset)
            if end == -1:
                end = len(data)
            return data[offset:end].decode("utf-8", errors="ignore")
        except (UnicodeDecodeError, IndexError, Exception) as e:
            self.logger.error("Error in flexlm_parser: %s", e)
            return ""

    def _parse_additional_data(self, data: bytes) -> dict[str, Any]:
        """Parse additional FlexLM data fields."""
        additional = {}
        try:
            offset = 0
            while offset < len(data) - 4:
                field_type = struct.unpack(">H", data[offset : offset + 2])[0]
                field_length = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
                offset += 4

                if offset + field_length > len(data):
                    break

                field_data = data[offset : offset + field_length]
                offset += field_length

                # Parse common field types
                if field_type == 0x0001:  # Host ID
                    additional["hostid"] = field_data.hex()
                elif field_type == 0x0002:  # Encryption info
                    additional["encryption"] = field_data
                elif field_type == 0x0003:  # Vendor data
                    additional["vendor_data"] = field_data
                elif field_type == 0x0004:  # License path
                    additional["license_path"] = field_data.decode("utf-8", errors="ignore")
                else:
                    additional[f"field_{field_type:04X}"] = field_data

        except Exception as e:
            self.logger.debug(f"Error parsing additional data: {e}")

        return additional

    def generate_response(self, request: FlexLMRequest) -> FlexLMResponse:
        """Generate appropriate FlexLM response based on request.

        Args:
            request: Parsed FlexLM request

        Returns:
            FlexLM response object

        """
        command_name = self.FLEXLM_COMMANDS.get(request.command, "UNKNOWN")
        self.logger.info(f"Generating response for {command_name} command")

        if request.command == 0x01:  # CHECKOUT
            return self._handle_checkout(request)
        if request.command == 0x02:  # CHECKIN
            return self._handle_checkin(request)
        if request.command == 0x03:  # STATUS
            return self._handle_status(request)
        if request.command == 0x04:  # HEARTBEAT
            return self._handle_heartbeat(request)
        if request.command == 0x05:  # FEATURE_INFO
            return self._handle_feature_info(request)
        if request.command == 0x06:  # SERVER_INFO
            return self._handle_server_info(request)
        if request.command == 0x10:  # HOSTID_REQUEST
            return self._handle_hostid_request(request)
        if request.command == 0x11:  # ENCRYPTION_SEED
            return self._handle_encryption_seed(request)
        return self._handle_unknown_command(request)

    def _handle_checkout(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle license checkout request."""
        feature = request.feature.upper()

        # Check if feature exists
        if feature not in self.server_features:
            # Try to find partial match
            matches = [f for f in self.server_features.keys() if feature in f or f in feature]
            if matches:
                feature = matches[0]
            else:
                return FlexLMResponse(
                    status=0x01,  # FEATURE_NOT_FOUND
                    sequence=request.sequence,
                    server_version="11.18.0",
                    feature=request.feature,
                    expiry_date="",
                    license_key="",
                    server_id="intellicrack-flexlm",
                    additional_data={"error": f"Feature {request.feature} not found"},
                )

        feature_info = self.server_features[feature]

        # Generate checkout key
        checkout_key = self._generate_checkout_key(request, feature_info)

        # Track checkout
        checkout_id = f"{request.hostname}:{request.username}:{request.feature}"
        self.active_checkouts[checkout_id] = {
            "request": request,
            "checkout_time": time.time(),
            "key": checkout_key,
        }

        return FlexLMResponse(
            status=0x00,  # SUCCESS
            sequence=request.sequence,
            server_version="11.18.0",
            feature=feature,
            expiry_date=feature_info["expiry"],
            license_key=checkout_key,
            server_id="intellicrack-flexlm",
            additional_data={
                "vendor": feature_info["vendor"],
                "version": feature_info["version"],
                "count_remaining": feature_info["count"] - 1,
                "signature": feature_info["signature"],
            },
        )

    def _handle_checkin(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle license checkin request."""
        checkout_id = f"{request.hostname}:{request.username}:{request.feature}"

        if checkout_id in self.active_checkouts:
            del self.active_checkouts[checkout_id]
            status = 0x00  # SUCCESS
        else:
            status = 0x00  # SUCCESS (allow checkin even if not tracked)

        return FlexLMResponse(
            status=status,
            sequence=request.sequence,
            server_version="11.18.0",
            feature=request.feature,
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={"checkin_time": int(time.time())},
        )

    def _handle_status(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle server status request."""
        return FlexLMResponse(
            status=0x00,  # SUCCESS
            sequence=request.sequence,
            server_version="11.18.0",
            feature="",
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={
                "server_status": "UP",
                "active_checkouts": len(self.active_checkouts),
                "features_available": len(self.server_features),
                "uptime": int(time.time()),
            },
        )

    def _handle_heartbeat(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle heartbeat request."""
        checkout_id = f"{request.hostname}:{request.username}:{request.feature}"

        if checkout_id in self.active_checkouts:
            # Update heartbeat time
            self.active_checkouts[checkout_id]["last_heartbeat"] = time.time()
            status = 0x00  # SUCCESS
        else:
            status = 0x06  # HEARTBEAT_FAILED

        return FlexLMResponse(
            status=status,
            sequence=request.sequence,
            server_version="11.18.0",
            feature=request.feature,
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={"heartbeat_time": int(time.time())},
        )

    def _handle_feature_info(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle feature information request."""
        feature = request.feature.upper()

        if feature in self.server_features:
            feature_info = self.server_features[feature]
            return FlexLMResponse(
                status=0x00,  # SUCCESS
                sequence=request.sequence,
                server_version="11.18.0",
                feature=feature,
                expiry_date=feature_info["expiry"],
                license_key="",
                server_id="intellicrack-flexlm",
                additional_data=feature_info,
            )
        return FlexLMResponse(
            status=0x01,  # FEATURE_NOT_FOUND
            sequence=request.sequence,
            server_version="11.18.0",
            feature=request.feature,
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={},
        )

    def _handle_server_info(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle server information request."""
        return FlexLMResponse(
            status=0x00,  # SUCCESS
            sequence=request.sequence,
            server_version="11.18.0",
            feature="",
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={
                "server_name": "intellicrack-flexlm",
                "server_version": "11.18.0",
                "features": list(self.server_features.keys()),
                "max_connections": 1000,
                "current_connections": len(self.active_checkouts),
            },
        )

    def _handle_hostid_request(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle host ID request."""
        # Generate deterministic host ID
        hostid = hashlib.sha256(request.hostname.encode()).hexdigest()[:12].upper()

        return FlexLMResponse(
            status=0x00,  # SUCCESS
            sequence=request.sequence,
            server_version="11.18.0",
            feature="",
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={"hostid": hostid},
        )

    def _handle_encryption_seed(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle encryption seed request."""
        return FlexLMResponse(
            status=0x00,  # SUCCESS
            sequence=request.sequence,
            server_version="11.18.0",
            feature="",
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={"encryption_seed": self.encryption_seed.hex()},
        )

    def _handle_unknown_command(self, request: FlexLMRequest) -> FlexLMResponse:
        """Handle unknown command."""
        self.logger.warning(f"Unknown FlexLM command: 0x{request.command:02X}")
        return FlexLMResponse(
            status=0x0C,  # ENCRYPTION_FAILED (generic error)
            sequence=request.sequence,
            server_version="11.18.0",
            feature="",
            expiry_date="",
            license_key="",
            server_id="intellicrack-flexlm",
            additional_data={"error": f"Unknown command: 0x{request.command:02X}"},
        )

    def _generate_checkout_key(self, request: FlexLMRequest, feature_info: dict[str, Any]) -> str:
        """Generate checkout key for license."""
        # Incorporate feature information into key generation
        feature_version = feature_info.get("version", "1.0")
        feature_type = feature_info.get("type", "standard")
        feature_limit = feature_info.get("user_limit", 1)
        vendor_string = feature_info.get("vendor_string", "INTELLICRACK")

        # Create comprehensive key data incorporating feature details
        data = (
            f"{request.hostname}:{request.username}:{request.feature}:"
            f"{feature_version}:{feature_type}:{feature_limit}:"
            f"{vendor_string}:{time.time()}"
        )

        # Generate feature-specific key with enhanced entropy
        key = hashlib.sha256(data.encode()).hexdigest()[:32].upper()

        # Add feature-specific prefix for debugging
        if feature_type == "premium":
            key = "P" + key[1:]
        elif feature_type == "trial":
            key = "T" + key[1:]
        else:
            key = "S" + key[1:]  # Standard

        return key

    def serialize_response(self, response: FlexLMResponse) -> bytes:
        """Serialize FlexLM response to bytes.

        Args:
            response: FlexLM response object

        Returns:
            Serialized response bytes

        """
        try:
            # Build response packet
            packet = bytearray()

            # Magic number
            packet.extend(struct.pack(">I", 0x464C4558))  # "FLEX"

            # Status code
            packet.extend(struct.pack(">H", response.status))

            # Sequence number
            packet.extend(struct.pack(">I", response.sequence))

            # Server version
            server_version_bytes = response.server_version.encode("utf-8") + b"\x00"
            packet.extend(server_version_bytes)

            # Feature name
            feature_bytes = response.feature.encode("utf-8") + b"\x00"
            packet.extend(feature_bytes)

            # Expiry date
            expiry_bytes = response.expiry_date.encode("utf-8") + b"\x00"
            packet.extend(expiry_bytes)

            # License key
            key_bytes = response.license_key.encode("utf-8") + b"\x00"
            packet.extend(key_bytes)

            # Server ID
            server_id_bytes = response.server_id.encode("utf-8") + b"\x00"
            packet.extend(server_id_bytes)

            # Additional data
            if response.additional_data:
                additional_bytes = self._serialize_additional_data(response.additional_data)
                packet.extend(additional_bytes)

            # Update length field (insert at position 6)
            length = len(packet)
            packet[6:6] = struct.pack(">I", length)

            return bytes(packet)

        except Exception as e:
            self.logger.error(f"Failed to serialize FlexLM response: {e}")
            # Return minimal error response
            return struct.pack(">IHI", 0x464C4558, 0x03, response.sequence) + b"\x00"

    def _serialize_additional_data(self, data: dict[str, Any]) -> bytes:
        """Serialize additional data fields."""
        serialized = bytearray()

        for key, value in data.items():
            try:
                if isinstance(value, str):
                    value_bytes = value.encode("utf-8")
                elif isinstance(value, int):
                    value_bytes = struct.pack(">I", value)
                elif isinstance(value, bytes):
                    value_bytes = value
                else:
                    value_bytes = str(value).encode("utf-8")

                # Field header: type (2 bytes) + length (2 bytes)
                field_type = hash(key) & 0xFFFF  # Simple hash for field type
                serialized.extend(struct.pack(">HH", field_type, len(value_bytes)))
                serialized.extend(value_bytes)

            except Exception as e:
                self.logger.debug(f"Error serializing field {key}: {e}")

        return bytes(serialized)

    def add_custom_feature(
        self,
        name: str,
        version: str,
        vendor: str,
        count: int = 100,
        expiry: str = "31-dec-2025",
        signature: str | None = None,
    ) -> None:
        """Add custom FlexLM feature to server.

        Args:
            name: Feature name
            version: Feature version
            vendor: Vendor daemon name
            count: License count
            expiry: Expiry date
            signature: License signature (generated if None)

        """
        if signature is None:
            signature = hashlib.sha256(f"{name}:{version}:{vendor}".encode()).hexdigest()[:40].upper()

        self.server_features[name.upper()] = {
            "version": version,
            "expiry": expiry,
            "count": count,
            "vendor": vendor,
            "signature": signature,
        }
        self.logger.info(f"Added custom FlexLM feature: {name}")

    def remove_feature(self, name: str) -> None:
        """Remove feature from server.

        Args:
            name: Feature name to remove

        """
        feature_key = name.upper()
        if feature_key in self.server_features:
            del self.server_features[feature_key]
            self.logger.info(f"Removed FlexLM feature: {name}")

    def get_active_checkouts(self) -> dict[str, dict[str, Any]]:
        """Get all active license checkouts.

        Returns:
            Dictionary of active checkouts

        """
        return self.active_checkouts.copy()

    def clear_checkouts(self) -> None:
        """Clear all active checkouts."""
        count = len(self.active_checkouts)
        self.active_checkouts.clear()
        self.logger.info(f"Cleared {count} active checkouts")

    def get_server_statistics(self) -> dict[str, Any]:
        """Get server statistics.

        Returns:
            Dictionary containing server statistics

        """
        return {
            "total_features": len(self.server_features),
            "active_checkouts": len(self.active_checkouts),
            "features": list(self.server_features.keys()),
            "server_version": "11.18.0",
            "uptime": int(time.time()),
        }


class FlexLMTrafficCapture:
    """FlexLM traffic capture and analysis engine."""

    def __init__(self, parser: FlexLMProtocolParser):
        """Initialize traffic capture engine.

        Args:
            parser: FlexLM protocol parser instance

        """
        self.logger = get_logger(__name__)
        self.parser = parser
        self.captured_requests: list[tuple[float, FlexLMRequest, bytes]] = []
        self.captured_responses: list[tuple[float, FlexLMResponse, bytes]] = []
        self.server_endpoints: set[tuple[str, int]] = set()
        self.client_endpoints: set[tuple[str, int]] = set()

    def capture_packet(self, data: bytes, source: tuple[str, int], dest: tuple[str, int], timestamp: float | None = None) -> bool:
        """Capture FlexLM network packet.

        Args:
            data: Raw packet data
            source: Source (IP, port) tuple
            dest: Destination (IP, port) tuple
            timestamp: Capture timestamp (current time if None)

        Returns:
            True if packet was successfully parsed and captured

        """
        if timestamp is None:
            timestamp = time.time()

        request = self.parser.parse_request(data)
        if request:
            self.captured_requests.append((timestamp, request, data))
            self.client_endpoints.add(source)
            self.server_endpoints.add(dest)
            self.logger.debug(f"Captured FlexLM request from {source} to {dest}")
            return True

        return False

    def analyze_traffic_patterns(self) -> dict[str, Any]:
        """Analyze captured traffic patterns.

        Returns:
            Dictionary containing traffic analysis results

        """
        if not self.captured_requests:
            return {"error": "No captured traffic to analyze"}

        command_counts: dict[int, int] = {}
        feature_requests: dict[str, int] = {}
        hourly_distribution: dict[int, int] = {}

        for timestamp, request, _ in self.captured_requests:
            command_counts[request.command] = command_counts.get(request.command, 0) + 1

            if request.feature:
                feature_requests[request.feature] = feature_requests.get(request.feature, 0) + 1

            hour = int(timestamp % 86400 / 3600)
            hourly_distribution[hour] = hourly_distribution.get(hour, 0) + 1

        top_commands = sorted(
            [
                (self.parser.FLEXLM_COMMANDS.get(cmd, f"UNKNOWN_{cmd:02X}"), count)
                for cmd, count in command_counts.items()
            ],
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        top_features = sorted(feature_requests.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_packets": len(self.captured_requests),
            "unique_clients": len(self.client_endpoints),
            "unique_servers": len(self.server_endpoints),
            "command_distribution": dict(command_counts),
            "top_commands": top_commands,
            "top_features": top_features,
            "hourly_distribution": hourly_distribution,
            "capture_duration": max(ts for ts, _, _ in self.captured_requests) - min(ts for ts, _, _ in self.captured_requests) if len(self.captured_requests) > 1 else 0,
        }

    def extract_license_info(self) -> list[dict[str, Any]]:
        """Extract license information from captured traffic.

        Returns:
            List of extracted license information dictionaries

        """
        licenses = []

        for timestamp, request, _ in self.captured_requests:
            if request.command == 0x01:
                license_info = {
                    "timestamp": timestamp,
                    "feature": request.feature,
                    "version": request.version_requested,
                    "client": request.hostname,
                    "username": request.username,
                    "platform": request.platform,
                    "client_id": request.client_id,
                }
                licenses.append(license_info)

        return licenses

    def detect_server_endpoints(self) -> list[dict[str, Any]]:
        """Detect FlexLM server endpoints from captured traffic.

        Returns:
            List of detected server endpoint information

        """
        servers = []
        for ip, port in self.server_endpoints:
            server_info = {
                "ip": ip,
                "port": port,
                "endpoint": f"{ip}:{port}",
                "protocol": "FlexLM",
            }
            servers.append(server_info)

        return servers

    def export_capture(self, filepath: str) -> None:
        """Export captured traffic to file.

        Args:
            filepath: Output file path

        """
        import json

        capture_data = {
            "capture_time": time.time(),
            "total_packets": len(self.captured_requests),
            "packets": [
                {
                    "timestamp": ts,
                    "command": req.command,
                    "command_name": self.parser.FLEXLM_COMMANDS.get(req.command, "UNKNOWN"),
                    "feature": req.feature,
                    "version": req.version_requested,
                    "hostname": req.hostname,
                    "username": req.username,
                    "platform": req.platform,
                    "sequence": req.sequence,
                }
                for ts, req, _ in self.captured_requests
            ],
            "analysis": self.analyze_traffic_patterns(),
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(capture_data, f, indent=2)

        self.logger.info(f"Exported {len(self.captured_requests)} captured packets to {filepath}")


class FlexLMLicenseGenerator:
    """FlexLM license file generator."""

    def __init__(self):
        """Initialize license generator."""
        self.logger = get_logger(__name__)

    def generate_license_file(
        self,
        features: list[dict[str, Any]],
        server_host: str,
        server_port: int = 27000,
        vendor_daemon: str = "vendor",
        vendor_port: int = 27001,
    ) -> str:
        """Generate FlexLM license file content.

        Args:
            features: List of feature dictionaries
            server_host: License server hostname
            server_port: License server port
            vendor_daemon: Vendor daemon name
            vendor_port: Vendor daemon port

        Returns:
            License file content as string

        """
        lines = []

        lines.append(f"SERVER {server_host} ANY {server_port}")
        lines.append(f"VENDOR {vendor_daemon} PORT={vendor_port}")
        lines.append("")

        for feature in features:
            name = feature.get("name", "FEATURE")
            version = feature.get("version", "1.0")
            vendor = feature.get("vendor", vendor_daemon)
            expiry = feature.get("expiry", "31-dec-2025")
            count = feature.get("count", 1)
            signature = feature.get("signature", self._generate_signature(name, version))

            license_line = (
                f'FEATURE {name} {vendor} {version} {expiry} {count} '
                f'HOSTID=ANY SIGN="{signature}"'
            )
            lines.append(license_line)

        return "\n".join(lines)

    def _generate_signature(self, feature: str, version: str) -> str:
        """Generate license signature.

        Args:
            feature: Feature name
            version: Version string

        Returns:
            Generated signature string

        """
        data = f"{feature}:{version}:{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()[:40].upper()

    def parse_license_file(self, content: str) -> dict[str, Any]:
        """Parse FlexLM license file.

        Args:
            content: License file content

        Returns:
            Parsed license data dictionary

        """
        license_data: dict[str, Any] = {
            "servers": [],
            "vendors": [],
            "features": [],
        }

        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if not parts:
                continue

            keyword = parts[0].upper()

            if keyword == "SERVER":
                if len(parts) >= 3:
                    license_data["servers"].append({
                        "hostname": parts[1],
                        "hostid": parts[2],
                        "port": int(parts[3]) if len(parts) > 3 else 27000,
                    })

            elif keyword == "VENDOR":
                vendor_info = {"name": parts[1] if len(parts) > 1 else ""}
                for part in parts[2:]:
                    if "=" in part:
                        key, value = part.split("=", 1)
                        if key.upper() == "PORT":
                            vendor_info["port"] = int(value)
                license_data["vendors"].append(vendor_info)

            elif keyword == "FEATURE" or keyword == "INCREMENT":
                if len(parts) >= 5:
                    feature_info = {
                        "name": parts[1],
                        "vendor": parts[2],
                        "version": parts[3],
                        "expiry": parts[4],
                        "count": int(parts[5]) if len(parts) > 5 else 1,
                    }

                    for part in parts[6:]:
                        if "=" in part:
                            key, value = part.split("=", 1)
                            feature_info[key.lower()] = value.strip('"')

                    license_data["features"].append(feature_info)

        return license_data
