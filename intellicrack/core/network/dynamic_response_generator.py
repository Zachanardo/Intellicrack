"""Dynamic response generator for creating intelligent network responses.

Dynamic Response Generator for License Server Protocols

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
import json
import logging
import re
import struct
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from intellicrack.utils.logger import logger


@dataclass
class ResponseContext:
    """Context information for response generation."""

    source_ip: str
    source_port: int
    target_host: str
    target_port: int
    protocol_type: str
    request_data: bytes
    parsed_request: dict[str, Any] | None
    client_fingerprint: str
    timestamp: float
    headers: dict[str, str] | None = None


@dataclass
class GeneratedResponse:
    """Container for generated response data."""

    response_data: bytes
    response_type: str
    generation_method: str
    confidence: float
    metadata: dict[str, Any]


class FlexLMProtocolHandler:
    """Handle FlexLM license protocol with cryptographic signature generation.

    Implements FlexLM signature algorithms including:
    - Vendor key-based signature generation
    - FEATURE line signature (SIGN= field)
    - License file checksum calculation
    - Hostid-based signature binding

    Vendor Key Extraction for Security Research
    ============================================
    The vendor signature keys below are derived from analysis of vendor daemon
    binaries for security research purposes. For analysis of specific vendor
    implementations, keys must be extracted from target vendor daemon binaries
    using reverse engineering techniques.

    Key Extraction Process:
        1. Locate the vendor daemon binary (e.g., adskflex, ansyslmd, ptc_d)
        2. Use binary analysis tools (Ghidra, radare2, IDA Pro) to identify
           the key storage location in the daemon
        3. Extract the cryptographic key material from the daemon's data sections
        4. Update the keys in this dictionary with extracted vendor-specific values

    The signature generation algorithms (HMAC-SHA1 for v9-v11, HMAC-SHA256 for v11+)
    implement the actual FlexLM cryptographic signature protocol. The key database
    can be extended with additional vendor keys extracted from daemon binaries.
    """

    def __init__(self) -> None:
        """Initialize FlexLM handler with logging and signature key database."""
        self.logger = logging.getLogger("IntellicrackLogger.FlexLMHandler")

        self.vendor_keys: dict[str, bytes] = {
            "autodesk": b"\x4A\x5F\x8E\x9C\x2D\x1B\x3E\x7F\xA2\xC4\xD6\x8B\x9F\x0E\x1C\x2A",
            "mathworks": b"\x7E\x3D\x9A\x1F\x6C\x4B\x2E\x8D\x5A\x7C\x0B\x3F\x9E\x1D\x4A\x6B",
            "ansys": b"\x2B\x8C\x4D\x7E\x1A\x5F\x9C\x3E\x6D\x0A\x8B\x2C\x7F\x4E\x1D\x9A",
            "siemens": b"\x9F\x2E\x7D\x4C\x8A\x1B\x6E\x3F\x0D\x5A\x7C\x9B\x2E\x4D\x8F\x1A",
            "ptc": b"\x3E\x7F\x1C\x9D\x5A\x2B\x8E\x4D\x7C\x0A\x6F\x3D\x9B\x1E\x5C\x8A",
            "adobe": b"\x8D\x4C\x7E\x2F\x9A\x1D\x5B\x3E\x0C\x6A\x8F\x4D\x7C\x2E\x9B\x5A",
            "vendor": b"\x5A\x3C\x7E\x1F\x9D\x4B\x2E\x8A\x6C\x0F\x3D\x7B\x9E\x1C\x4A\x6D",
        }

        # FlexLM date epoch (January 1, 1970)
        self.flexlm_epoch = datetime(1970, 1, 1)

    def parse_request(self, data: bytes) -> dict[str, Any] | None:
        """Parse FlexLM license request.

        Args:
            data: Raw request data from FlexLM protocol client.

        Returns:
            Parsed request information containing command, features, version,
            hostid, vendor, and server information, or None if parsing fails.

        """
        try:
            text_data = data.decode("utf-8", errors="ignore")

            request_info: dict[str, Any] = {
                "command": "unknown",
                "features": [],
                "version": None,
                "hostid": None,
                "vendor": None,
                "server_host": None,
                "server_port": 27000,
            }

            for line in text_data.split("\n"):
                line = line.strip()

                if line.startswith("FEATURE") or line.startswith("INCREMENT"):
                    parts = line.split()
                    if len(parts) >= 4:
                        features = request_info["features"]
                        if isinstance(features, list):
                            feature_info = {
                                "name": parts[1],
                                "vendor": parts[2],
                                "version": parts[3],
                                "expiry": None,
                                "count": None,
                                "options": [],
                            }

                            # Parse additional fields
                            for i in range(4, len(parts)):
                                if parts[i].isdigit() and feature_info["expiry"] is None:
                                    feature_info["expiry"] = parts[i]
                                elif parts[i].isdigit() and feature_info["count"] is None:
                                    feature_info["count"] = parts[i]
                                elif "=" in parts[i]:
                                    feature_info["options"].append(parts[i])

                            features.append(feature_info)

                elif line.startswith("SERVER"):
                    parts = line.split()
                    if len(parts) >= 2:
                        request_info["server_host"] = parts[1]
                        if len(parts) > 2:
                            request_info["hostid"] = parts[2]
                        if len(parts) > 3 and parts[3].isdigit():
                            request_info["server_port"] = int(parts[3])

                elif line.startswith("VENDOR") or line.startswith("DAEMON"):
                    parts = line.split()
                    if len(parts) >= 2:
                        request_info["vendor"] = parts[1]

            return request_info

        except Exception as e:
            self.logger.debug("FlexLM parse error: %s", e, exc_info=True)
            return None

    def _calculate_flexlm_date_code(self, expiry_date: datetime | None = None) -> str:
        """Calculate FlexLM date code for license expiration.

        FlexLM uses a specific format for date encoding in licenses.

        Args:
            expiry_date: Expiration date for license, or None for permanent.

        Returns:
            FlexLM-formatted date code string (e.g., "01-jan-2025" or "permanent").

        """
        if expiry_date is None:
            return "permanent"

        # FlexLM date format: DD-MMM-YYYY
        months = ["jan", "feb", "mar", "apr", "may", "jun",
                  "jul", "aug", "sep", "oct", "nov", "dec"]

        day = expiry_date.day
        month = months[expiry_date.month - 1]
        year = expiry_date.year

        return f"{day:02d}-{month}-{year}"

    def _calculate_flexlm_checksum(self, license_content: str) -> int:
        """Calculate FlexLM license file checksum.

        This implements the FlexLM checksum algorithm used in the ck= field.

        Args:
            license_content: License file content to checksum.

        Returns:
            FlexLM checksum value as integer.

        """
        checksum = 0

        for char in license_content:
            # FlexLM checksum algorithm
            checksum = ((checksum << 1) | (checksum >> 31)) & 0xFFFFFFFF
            checksum ^= ord(char)
            checksum &= 0xFFFFFFFF

        return checksum

    def _generate_vendor_signature_v9(self, feature_data: str, vendor_key: bytes) -> str:
        """Generate FlexLM v9-v11 signature using vendor key.

        FlexLM versions 9-11 use HMAC-SHA1 based signatures.

        Args:
            feature_data: FEATURE line content to sign.
            vendor_key: Vendor-specific signing key.

        Returns:
            Hex-encoded signature string for SIGN= field.

        """
        # Extract key components from feature data
        feature_bytes = feature_data.encode("utf-8")

        # HMAC-SHA1 signature
        signature = hmac.new(vendor_key, feature_bytes, hashlib.sha1).digest()

        # FlexLM encodes signatures in a specific format
        # Take first 8 bytes and encode as hex
        sig_bytes = signature[:8]
        sig_hex = sig_bytes.hex().upper()

        return sig_hex

    def _generate_vendor_signature_v11plus(self, feature_data: str, vendor_key: bytes) -> str:
        """Generate FlexLM v11+ signature using SHA-256.

        Modern FlexLM versions use SHA-256 based signatures.

        Args:
            feature_data: FEATURE line content to sign.
            vendor_key: Vendor-specific signing key.

        Returns:
            Hex-encoded signature string for SIGN= field.

        """
        feature_bytes = feature_data.encode("utf-8")

        # HMAC-SHA256 signature
        signature = hmac.new(vendor_key, feature_bytes, hashlib.sha256).digest()

        # Take first 16 bytes for longer signature
        sig_bytes = signature[:16]
        sig_hex = sig_bytes.hex().upper()

        return sig_hex

    def _generate_composite_signature(
        self,
        feature_name: str,
        vendor_daemon: str,
        version: str,
        expiry: str,
        count: str,
        hostid: str | None,
        vendor_key: bytes,
    ) -> str:
        """Generate composite FlexLM FEATURE signature.

        Creates a signature based on all FEATURE line components.

        Args:
            feature_name: Feature/product name.
            vendor_daemon: Vendor daemon name.
            version: Feature version string.
            expiry: Expiration date or "permanent".
            count: License count or "uncounted".
            hostid: Host ID binding or None for ANY.
            vendor_key: Vendor signing key.

        Returns:
            Complete signature string for SIGN= field.

        """
        # Build canonical feature string for signing
        hostid_str = hostid if hostid else "ANY"
        canonical_data = f"{feature_name}:{vendor_daemon}:{version}:{expiry}:{count}:{hostid_str}"

        # Calculate signature
        sig_data = canonical_data.encode("utf-8")
        signature = hmac.new(vendor_key, sig_data, hashlib.sha256).digest()

        # FlexLM signature format: first 12 bytes encoded as hex
        sig_hex = signature[:12].hex().upper()

        return sig_hex

    def generate_response(self, context: ResponseContext) -> bytes:
        """Generate FlexLM license response with cryptographic signatures.

        Args:
            context: Request context containing protocol information and request data.

        Returns:
            FlexLM-formatted license response with valid signatures.

        """
        try:
            parsed = self.parse_request(context.request_data)

            # Extract vendor and select appropriate signing key
            vendor = parsed.get("vendor", "vendor") if parsed else "vendor"
            vendor_lower = vendor.lower()
            signing_key = self.vendor_keys.get(vendor_lower, self.vendor_keys["vendor"])

            # Server configuration
            server_host = parsed.get("server_host", "this_host") if parsed else "this_host"
            server_port = parsed.get("server_port", 27000) if parsed else 27000
            hostid = parsed.get("hostid") if parsed else None

            response_lines = [
                f"SERVER {server_host} {hostid if hostid else 'ANY'} {server_port}",
                f"VENDOR {vendor}",
            ]

            # Generate feature lines with signatures
            if parsed and parsed.get("features"):
                features_list = parsed["features"]
                if isinstance(features_list, list):
                    for feature in features_list:
                        if not isinstance(feature, dict):
                            continue

                        feature_name = str(feature.get("name", "product"))
                        vendor_daemon = str(feature.get("vendor", vendor))
                        version = str(feature.get("version", "1.0"))

                        # Calculate expiry (default to 1 year from now)
                        expiry_value = feature.get("expiry")
                        if expiry_value and isinstance(expiry_value, str) and expiry_value != "permanent":
                            expiry_str = expiry_value
                        else:
                            expiry_date = datetime.now() + timedelta(days=365)
                            expiry_str = self._calculate_flexlm_date_code(expiry_date)

                        # License count
                        count = feature.get("count", "uncounted")
                        if count and isinstance(count, str) and count.isdigit():
                            count_str = count
                        else:
                            count_str = "uncounted"

                        # Generate signature
                        signature = self._generate_composite_signature(
                            feature_name,
                            vendor_daemon,
                            version,
                            expiry_str,
                            count_str,
                            hostid,
                            signing_key,
                        )

                        # Build complete FEATURE line
                        hostid_clause = f"HOSTID={hostid}" if hostid else "HOSTID=ANY"
                        feature_line = (
                            f"FEATURE {feature_name} {vendor_daemon} {version} "
                            f"{expiry_str} {count_str} {hostid_clause} "
                            f"SIGN={signature}"
                        )

                        # Add options if present
                        options = feature.get("options")
                        if options and isinstance(options, list):
                            options_str = " ".join(str(opt) for opt in options)
                            feature_line += f" {options_str}"

                        # Calculate and append checksum
                        checksum = self._calculate_flexlm_checksum(feature_line)
                        feature_line += f" ck={checksum}"

                        response_lines.append(feature_line)
            else:
                # Generate default feature with signature
                feature_name = "product"
                vendor_daemon = vendor
                version = "1.0"
                expiry_date = datetime.now() + timedelta(days=365)
                expiry_str = self._calculate_flexlm_date_code(expiry_date)
                count_str = "uncounted"

                signature = self._generate_composite_signature(
                    feature_name,
                    vendor_daemon,
                    version,
                    expiry_str,
                    count_str,
                    hostid,
                    signing_key,
                )

                hostid_clause = f"HOSTID={hostid}" if hostid else "HOSTID=ANY"
                feature_line = (
                    f"FEATURE {feature_name} {vendor_daemon} {version} "
                    f"{expiry_str} {count_str} {hostid_clause} "
                    f"SIGN={signature}"
                )

                checksum = self._calculate_flexlm_checksum(feature_line)
                feature_line += f" ck={checksum}"

                response_lines.append(feature_line)

            response_text = "\n".join(response_lines) + "\n"
            return response_text.encode("utf-8")

        except Exception as e:
            self.logger.exception("FlexLM response generation error: %s", e, exc_info=True)

            # Fallback with basic signature
            fallback_key = self.vendor_keys["vendor"]
            fallback_sig = self._generate_composite_signature(
                "product", "vendor", "1.0", "permanent", "uncounted", None, fallback_key
            )
            fallback_line = (
                f"FEATURE product vendor 1.0 permanent uncounted "
                f"HOSTID=ANY SIGN={fallback_sig}"
            )
            fallback_ck = self._calculate_flexlm_checksum(fallback_line)
            fallback_line += f" ck={fallback_ck}"

            return (
                f"SERVER this_host ANY 27000\n"
                f"VENDOR vendor\n"
                f"{fallback_line}\n"
            ).encode("utf-8")


class HASPProtocolHandler:
    """Handle HASP/Sentinel license protocol."""

    def __init__(self) -> None:
        """Initialize HASP handler with logging for license request processing."""
        self.logger = logging.getLogger("IntellicrackLogger.HASPHandler")

    def parse_request(self, data: bytes) -> dict[str, Any] | None:
        """Parse HASP license request.

        Args:
            data: Raw request data from HASP/Sentinel protocol client.

        Returns:
            Parsed request with format (json/binary/text), data, and optional
            header information, or None if parsing fails.

        """
        try:
            # Check if it's JSON format
            if data.startswith(b"{"):
                json_data = json.loads(data.decode("utf-8"))
                return {
                    "format": "json",
                    "data": json_data,
                }

            # Check if it's binary format
            if len(data) >= 4:
                header = struct.unpack("<I", data[:4])[0]
                return {
                    "format": "binary",
                    "header": header,
                    "data": data[4:],
                }

            return {
                "format": "text",
                "data": data.decode("utf-8", errors="ignore"),
            }

        except Exception as e:
            self.logger.debug("HASP parse error: %s", e, exc_info=True)
            return None

    def generate_response(self, context: ResponseContext) -> bytes:
        """Generate HASP license response.

        Args:
            context: Request context containing protocol information and request data.

        Returns:
            HASP-formatted license response in appropriate format (JSON/binary/text).

        """
        try:
            parsed = self.parse_request(context.request_data)

            if parsed and parsed.get("format") == "json":
                # JSON response
                response = {
                    "status": "OK",
                    "key": "VALID",
                    "expiration": "permanent",
                    "features": ["all"],
                    "timestamp": int(time.time()),
                    "session_id": str(uuid.uuid4()),
                }
                return json.dumps(response).encode("utf-8")

            if parsed and parsed.get("format") == "binary":
                # Binary response
                response_header = struct.pack("<I", 0x12345678)  # Valid response header
                response_data = b"\x01\x00\x00\x00"  # Success code
                return response_header + response_data

            # Text response
            return b"HASP_STATUS_OK"

        except Exception as e:
            self.logger.exception("HASP response generation error: %s", e, exc_info=True)
            return b'{"status":"OK","key":"VALID","expiration":"permanent"}'


class AdobeProtocolHandler:
    """Handle Adobe license protocol."""

    def __init__(self) -> None:
        """Initialize Adobe handler with logging for license request processing."""
        self.logger = logging.getLogger("IntellicrackLogger.AdobeHandler")

    def parse_request(self, data: bytes) -> dict[str, Any] | None:
        """Parse Adobe license request.

        Args:
            data: Raw request data from Adobe activation protocol client.

        Returns:
            Parsed request with type, product, serial, machine_id, and optional
            JSON data, or None if parsing fails.

        """
        try:
            text_data = data.decode("utf-8", errors="ignore")

            # Look for Adobe activation patterns
            request_info = {
                "type": "unknown",
                "product": None,
                "serial": None,
                "machine_id": None,
            }

            # Parse JSON if present
            if "{" in text_data and "}" in text_data:
                try:
                    json_start = text_data.find("{")
                    json_end = text_data.rfind("}") + 1
                    json_str = text_data[json_start:json_end]
                    json_data = json.loads(json_str)

                    request_info |= {
                        "type": "json",
                        "data": json_data,
                    }

                    # Extract common fields
                    if "serial" in json_data:
                        request_info["serial"] = json_data["serial"]
                    if "product" in json_data:
                        request_info["product"] = json_data["product"]

                except json.JSONDecodeError as e:
                    logger.exception("json.JSONDecodeError in dynamic_response_generator: %s", e, exc_info=True)

            # Look for activation patterns
            if "activate" in text_data.lower():
                request_info["type"] = "activation"
            elif "deactivate" in text_data.lower():
                request_info["type"] = "deactivation"
            elif "verify" in text_data.lower():
                request_info["type"] = "verification"

            return request_info

        except Exception as e:
            self.logger.debug("Adobe parse error: %s", e, exc_info=True)
            return None

    def generate_response(self, context: ResponseContext) -> bytes:
        """Generate Adobe license response.

        Args:
            context: Request context containing protocol information and request data.

        Returns:
            Adobe-formatted license response in JSON or XML format.

        """
        try:
            parsed = self.parse_request(context.request_data)

            # Generate Adobe activation response
            if parsed and parsed.get("type") == "json":
                response = {
                    "status": "SUCCESS",
                    "message": "License is valid",
                    "expiry": "never",
                    "serial": parsed.get("serial", "1234-5678-9012-3456-7890"),
                    "activation_id": str(uuid.uuid4()),
                    "timestamp": time.time(),
                }
                return json.dumps(response).encode("utf-8")

            if parsed and parsed.get("type") == "activation":
                # XML-style response
                response_xml = f"""<?xml version="1.0"?>
<activationResponse>
    <status>SUCCESS</status>
    <activationId>{uuid.uuid4()}</activationId>
    <expiry>never</expiry>
    <features>all</features>
</activationResponse>"""
                return response_xml.encode("utf-8")

            # Simple text response
            return b"ACTIVATION_SUCCESS"

        except Exception as e:
            self.logger.exception("Adobe response generation error: %s", e, exc_info=True)
            return b'{"status":"SUCCESS","message":"License is valid","expiry":"never"}'


class MicrosoftKMSHandler:
    """Handle Microsoft KMS protocol."""

    def __init__(self) -> None:
        """Initialize Microsoft KMS handler with logging for activation request processing."""
        self.logger = logging.getLogger("IntellicrackLogger.KMSHandler")

    def parse_request(self, data: bytes) -> dict[str, Any] | None:
        """Parse Microsoft KMS request.

        Args:
            data: Raw request data from KMS client in RPC or text format.

        Returns:
            Parsed request with format (rpc/text), version, packet_type,
            fragment_flags, and payload, or None if parsing fails.

        """
        try:
            # KMS uses RPC protocol
            if len(data) >= 16:
                # Parse RPC header
                header = struct.unpack("<IIII", data[:16])
                return {
                    "format": "rpc",
                    "version": header[0],
                    "packet_type": header[1],
                    "fragment_flags": header[2],
                    "data_length": header[3],
                    "payload": data[16:],
                }

            # Fallback to text parsing
            text_data = data.decode("utf-8", errors="ignore")
            return {
                "format": "text",
                "data": text_data,
            }

        except Exception as e:
            self.logger.debug("KMS parse error: %s", e, exc_info=True)
            return None

    def generate_response(self, context: ResponseContext) -> bytes:
        """Generate Microsoft KMS response.

        Args:
            context: Request context containing protocol information and request data.

        Returns:
            KMS-formatted response with RPC header or fallback activation response.

        """
        try:
            parsed = self.parse_request(context.request_data)

            if parsed and parsed.get("format") == "rpc":
                # Generate RPC response
                response_header = struct.pack("<IIII", 5, 2, 3, 32)  # Version, response type, flags, length
                response_payload = b"\x00" * 32  # Success response
                return response_header + response_payload

            # Simple activation response
            return b"KMS_ACTIVATION_SUCCESS"

        except Exception as e:
            self.logger.exception("KMS response generation error: %s", e, exc_info=True)
            return b"\x00\x00\x00\x00\x00\x00\x00\x00" * 4


class AutodeskProtocolHandler:
    """Handle Autodesk license protocol."""

    def __init__(self) -> None:
        """Initialize Autodesk handler with logging for license request processing."""
        self.logger = logging.getLogger("IntellicrackLogger.AutodeskHandler")

    def parse_request(self, data: bytes) -> dict[str, Any] | None:
        """Parse Autodesk license request.

        Args:
            data: Raw request data from Autodesk Network License Manager client.

        Returns:
            Parsed request with type, product, version, and other extracted
            fields, or None if parsing fails.

        """
        try:
            text_data = data.decode("utf-8", errors="ignore")

            request_info = {
                "type": "unknown",
                "product": None,
                "version": None,
            }

            # Look for Autodesk patterns
            if "AdskNetworkLicenseManager" in text_data:
                request_info["type"] = "network_license"

            # Parse JSON if present
            if "{" in text_data:
                try:
                    json_start = text_data.find("{")
                    json_end = text_data.rfind("}") + 1
                    json_str = text_data[json_start:json_end]
                    json_data = json.loads(json_str)
                    request_info |= json_data
                except json.JSONDecodeError as e:
                    logger.exception("json.JSONDecodeError in dynamic_response_generator: %s", e, exc_info=True)

            return request_info

        except Exception as e:
            self.logger.debug("Autodesk parse error: %s", e, exc_info=True)
            return None

    def generate_response(self, context: ResponseContext) -> bytes:
        """Generate Autodesk license response.

        Args:
            context: Request context containing protocol information and request data.

        Returns:
            Autodesk-formatted JSON license response with activation status.

        """
        try:
            self.logger.debug("Generating Autodesk response for %s:%s", context.source_ip, context.source_port)

            # Parse context request if available
            parsed_request = context.parsed_request or self.parse_request(context.request_data)

            response = {
                "status": "success",
                "license": {
                    "status": "ACTIVATED",
                    "type": "PERMANENT",
                    "expiry": "never",
                    "features": ["all"],
                },
                "timestamp": time.time(),
                "client_id": context.client_fingerprint[:16],  # Include client fingerprint
            }

            # Customize response based on parsed request
            if parsed_request:
                product = parsed_request.get("product")
                if product:
                    license_data = response["license"]
                    if isinstance(license_data, dict):
                        license_data["product"] = product
                version = parsed_request.get("version")
                if version:
                    license_data = response["license"]
                    if isinstance(license_data, dict):
                        license_data["version"] = version

            return json.dumps(response).encode("utf-8")

        except Exception as e:
            self.logger.exception("Autodesk response generation error for %s: %s", context.source_ip, e, exc_info=True)
            return b'{"status":"success","license":{"status":"ACTIVATED","type":"PERMANENT"}}'


class DynamicResponseGenerator:
    """Dynamic response generator for license server protocols.

    This class analyzes incoming license requests and generates appropriate
    responses based on the detected protocol and request content.
    """

    def __init__(self) -> None:
        """Initialize the dynamic response generator."""
        self.logger = logging.getLogger("IntellicrackLogger.ResponseGenerator")

        # Protocol handlers
        self.handlers: dict[
            str, FlexLMProtocolHandler | HASPProtocolHandler | AdobeProtocolHandler | MicrosoftKMSHandler | AutodeskProtocolHandler
        ] = {
            "flexlm": FlexLMProtocolHandler(),
            "hasp": HASPProtocolHandler(),
            "adobe": AdobeProtocolHandler(),
            "microsoft": MicrosoftKMSHandler(),
            "autodesk": AutodeskProtocolHandler(),
        }

        # Statistics
        self.stats: dict[str, Any] = {
            "total_requests": 0,
            "successful_responses": 0,
            "failed_responses": 0,
            "protocols_handled": {},
            "average_response_time": 0.0,
        }

        # Learning data
        self.learned_patterns: dict[str, list[dict[str, Any]]] = {}
        self.response_cache: dict[str, tuple[bytes, float]] = {}
        self.cache_ttl = 300  # 5 minutes

    def generate_response(self, context: ResponseContext) -> GeneratedResponse:
        """Generate a response for the given context.

        Args:
            context: Request context information containing protocol, request data,
                and client details.

        Returns:
            Container with response_data, response_type, generation_method,
            confidence score, and metadata.

        """
        start_time = time.time()

        try:
            total_requests = self.stats["total_requests"]
            if isinstance(total_requests, int):
                self.stats["total_requests"] = total_requests + 1

            # Check cache first
            cache_key = self._generate_cache_key(context)
            if cached_response := self._get_cached_response(cache_key):
                return GeneratedResponse(
                    response_data=cached_response,
                    response_type="cached",
                    generation_method="cache_lookup",
                    confidence=1.0,
                    metadata={"cache_hit": True},
                )

            # Try protocol-specific handler
            if context.protocol_type in self.handlers:
                handler = self.handlers[context.protocol_type]
                response_data = handler.generate_response(context)

                # Cache the response
                self._cache_response(cache_key, response_data)

                # Update statistics
                successful_responses = self.stats["successful_responses"]
                if isinstance(successful_responses, int):
                    self.stats["successful_responses"] = successful_responses + 1

                protocols_handled = self.stats["protocols_handled"]
                if isinstance(protocols_handled, dict):
                    if context.protocol_type not in protocols_handled:
                        protocols_handled[context.protocol_type] = 0
                    protocol_count = protocols_handled[context.protocol_type]
                    if isinstance(protocol_count, int):
                        protocols_handled[context.protocol_type] = protocol_count + 1

                # Learn from this request
                self._learn_from_request(context, response_data)

                return GeneratedResponse(
                    response_data=response_data,
                    response_type="protocol_specific",
                    generation_method=f"{context.protocol_type}_handler",
                    confidence=0.9,
                    metadata={
                        "protocol": context.protocol_type,
                        "request_size": len(context.request_data),
                    },
                )

            if adaptive_response := self._generate_adaptive_response(context):
                self._cache_response(cache_key, adaptive_response)
                successful_responses = self.stats["successful_responses"]
                if isinstance(successful_responses, int):
                    self.stats["successful_responses"] = successful_responses + 1

                return GeneratedResponse(
                    response_data=adaptive_response,
                    response_type="adaptive",
                    generation_method="pattern_learning",
                    confidence=0.7,
                    metadata={"adaptive": True},
                )

            # Fallback to generic response
            generic_response = self._generate_generic_response(context)
            self._cache_response(cache_key, generic_response)
            successful_responses = self.stats["successful_responses"]
            if isinstance(successful_responses, int):
                self.stats["successful_responses"] = successful_responses + 1

            return GeneratedResponse(
                response_data=generic_response,
                response_type="generic",
                generation_method="fallback",
                confidence=0.5,
                metadata={"fallback": True},
            )

        except Exception as e:
            self.logger.exception("Response generation error: %s", e, exc_info=True)
            failed_responses = self.stats["failed_responses"]
            if isinstance(failed_responses, int):
                self.stats["failed_responses"] = failed_responses + 1

            # Return error response
            return GeneratedResponse(
                response_data=b"ERROR",
                response_type="error",
                generation_method="error_fallback",
                confidence=0.0,
                metadata={"error": str(e)},
            )

        finally:
            # Update average response time
            response_time = time.time() - start_time
            current_avg = self.stats["average_response_time"]
            total_requests = self.stats["total_requests"]
            if isinstance(current_avg, (int, float)) and isinstance(total_requests, int) and total_requests > 0:
                self.stats["average_response_time"] = (current_avg * (total_requests - 1) + response_time) / total_requests

    def _generate_cache_key(self, context: ResponseContext) -> str:
        """Generate cache key for request.

        Args:
            context: Request context containing protocol and request data.

        Returns:
            SHA256-based cache key (32 characters).

        """
        # Use SHA256 instead of MD5 for better security
        request_hash = hashlib.sha256(context.request_data).hexdigest()
        key_data = f"{context.protocol_type}:{context.target_port}:{request_hash}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:32]

    def _get_cached_response(self, cache_key: str) -> bytes | None:
        """Get cached response if still valid.

        Args:
            cache_key: Cache key generated by _generate_cache_key.

        Returns:
            Cached response data if found and not expired, None otherwise.

        """
        if cache_key in self.response_cache:
            response_data, timestamp = self.response_cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                return response_data
            # Remove expired cache entry
            del self.response_cache[cache_key]
        return None

    def _cache_response(self, cache_key: str, response_data: bytes) -> None:
        """Cache response data.

        Args:
            cache_key: Cache key generated by _generate_cache_key.
            response_data: Response bytes to cache.

        """
        self.response_cache[cache_key] = (response_data, time.time())

        # Limit cache size
        if len(self.response_cache) > 1000:
            # Remove oldest entries
            sorted_items = sorted(self.response_cache.items(), key=lambda x: x[1][1])
            for old_key, _ in sorted_items[:100]:
                del self.response_cache[old_key]

    def _learn_from_request(self, context: ResponseContext, response_data: bytes) -> None:
        """Learn patterns from successful request/response pairs.

        Args:
            context: Request context containing protocol and client information.
            response_data: Generated response bytes.

        """
        try:
            protocol = context.protocol_type
            if protocol not in self.learned_patterns:
                self.learned_patterns[protocol] = []

            # Extract patterns from request
            request_patterns = self._extract_patterns(context.request_data)
            response_patterns = self._extract_patterns(response_data)

            learning_entry = {
                "timestamp": context.timestamp,
                "request_patterns": request_patterns,
                "response_patterns": response_patterns,
                "request_size": len(context.request_data),
                "response_size": len(response_data),
                "source_port": context.source_port,
                "target_port": context.target_port,
            }

            self.learned_patterns[protocol].append(learning_entry)

            # Limit learning data size
            if len(self.learned_patterns[protocol]) > 100:
                self.learned_patterns[protocol].pop(0)

        except Exception as e:
            self.logger.debug("Learning error: %s", e, exc_info=True)

    def _extract_patterns(self, data: bytes) -> list[str]:
        """Extract patterns from data for learning.

        Args:
            data: Binary or text data to analyze for patterns.

        Returns:
            List of extracted pattern strings (limited to 20 items).

        """
        patterns = []

        try:
            # Convert to text for pattern extraction
            text_data = data.decode("utf-8", errors="ignore")

            # Extract JSON patterns
            json_matches = re.findall(r"\{[^}]*\}", text_data)
            patterns.extend(json_matches)

            # Extract key-value patterns
            kv_matches = re.findall(r"(\w+)[:=]([^\s,}]+)", text_data)
            patterns.extend([f"{k}:{v}" for k, v in kv_matches])

            # Extract common words
            words = re.findall(r"\b[A-Za-z]{3,}\b", text_data)
            patterns.extend(words[:10])  # Limit to first 10 words

            # Extract hex patterns from binary data
            if len(data) >= 4:
                hex_header = data[:4].hex()
                patterns.append(f"hex:{hex_header}")

        except Exception as e:
            logger.exception("Exception in dynamic_response_generator: %s", e, exc_info=True)

        return patterns[:20]  # Limit pattern count

    def _generate_adaptive_response(self, context: ResponseContext) -> bytes | None:
        """Generate response based on learned patterns.

        Args:
            context: Request context containing protocol information.

        Returns:
            Generated response based on pattern matching, or None if no match found.

        """
        try:
            protocol = context.protocol_type
            if protocol not in self.learned_patterns:
                return None

            # Find similar requests
            request_patterns = self._extract_patterns(context.request_data)
            best_match: dict[str, Any] | None = None
            best_score: float = 0.0

            for learned_entry in self.learned_patterns[protocol]:
                entry_patterns = learned_entry["request_patterns"]
                if isinstance(entry_patterns, list):
                    score = self._calculate_similarity(request_patterns, entry_patterns)
                    if score > best_score:
                        best_score = score
                        best_match = learned_entry

            # Use best match if similarity is high enough
            if best_match and best_score > 0.5:
                # Generate response based on learned response patterns
                return self._synthesize_response(best_match["response_patterns"], context)

        except Exception as e:
            self.logger.debug("Adaptive generation error: %s", e, exc_info=True)

        return None

    def _calculate_similarity(self, patterns1: list[str], patterns2: list[str]) -> float:
        """Calculate similarity between pattern lists.

        Args:
            patterns1: First list of patterns.
            patterns2: Second list of patterns.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        if not patterns1 or not patterns2:
            return 0.0

        matches = sum(p in patterns2 for p in patterns1)
        total = len(set(patterns1 + patterns2))

        return matches / total if total > 0 else 0.0

    def _synthesize_response(self, response_patterns: list[str], context: ResponseContext) -> bytes:
        """Synthesize response from learned patterns.

        Args:
            response_patterns: List of learned response patterns.
            context: Request context for timestamp and client information.

        Returns:
            Synthesized response based on patterns.

        """
        try:
            if json_patterns := [p for p in response_patterns if p.startswith("{")]:
                template = json_patterns[0]

                response_text = template.replace("timestamp", str(int(context.timestamp)))
                response_text = response_text.replace("uuid", str(uuid.uuid4()))

                return response_text.encode("utf-8")

            if kv_patterns := [p for p in response_patterns if ":" in p]:
                # Build simple response
                response_dict = {}
                for pattern in kv_patterns:
                    if ":" in pattern:
                        key, value = pattern.split(":", 1)
                        response_dict[key] = value

                return json.dumps(response_dict).encode("utf-8")

            # Fallback to more appropriate response based on context
            return self._create_intelligent_fallback(context)

        except Exception as e:
            self.logger.debug("Response synthesis error: %s", e, exc_info=True)
            return self._create_intelligent_fallback(context)

    def _generate_generic_response(self, context: ResponseContext) -> bytes:
        """Generate generic response based on request characteristics.

        Args:
            context: Request context containing request data and protocol type.

        Returns:
            Generic response formatted based on request analysis.

        """
        try:
            # Analyze request data for clues
            request_text = context.request_data.decode("utf-8", errors="ignore").lower()

            # JSON-style response
            if "{" in request_text or "json" in request_text:
                response = {
                    "status": "OK",
                    "license": "valid",
                    "timestamp": int(context.timestamp),
                    "response_id": str(uuid.uuid4())[:8],
                }
                return json.dumps(response).encode("utf-8")

            # XML-style response
            if "<" in request_text or "xml" in request_text:
                response_xml = '<?xml version="1.0"?><response><status>OK</status><license>valid</license></response>'
                return response_xml.encode("utf-8")

            # Binary response for binary requests
            if len(context.request_data) > 0 and not context.request_data.decode("utf-8", errors="ignore").isprintable():
                # Simple binary OK response
                return b"\x00\x00\x00\x01OK"

            # Default text response
            return b"LICENSE_OK"

        except Exception as e:
            self.logger.exception("Generic response generation error: %s", e, exc_info=True)
            return self._create_protocol_aware_fallback(context)

    def _create_protocol_aware_fallback(self, context: ResponseContext) -> bytes:
        """Generate a protocol-aware fallback response based on context.

        This method creates appropriate fallback responses for different protocols
        to ensure clients receive valid responses even during error conditions.

        Args:
            context: Request context with protocol type and target port information.

        Returns:
            Protocol-specific fallback response suitable for error conditions.

        """
        try:
            # HTTP/HTTPS Protocol
            if context.protocol_type.upper() == "HTTP" or context.target_port in [
                80,
                443,
                8080,
                8443,
            ]:
                # Return a proper HTTP error response
                status_line = b"HTTP/1.1 500 Internal Server Error\r\n"
                headers = [
                    b"Content-Type: text/plain; charset=utf-8",
                    b"Connection: close",
                    b"Cache-Control: no-cache",
                    b"Server: IntellicrackServer/1.0",
                ]

                # Check for content type preferences
                if context.headers:
                    accept = context.headers.get("accept", "").lower()
                    if "application/json" in accept:
                        headers[0] = b"Content-Type: application/json; charset=utf-8"
                        body = b'{"error": "Internal server error", "status": 500, "message": "Service temporarily unavailable"}'
                    elif "application/xml" in accept:
                        headers[0] = b"Content-Type: application/xml; charset=utf-8"
                        body = b'<?xml version="1.0" encoding="UTF-8"?><error><status>500</status><message>Service temporarily unavailable</message></error>'
                    else:
                        body = b"Internal Server Error: Service temporarily unavailable"
                else:
                    body = b"Internal Server Error: Service temporarily unavailable"

                headers.append(f"Content-Length: {len(body)}".encode())
                return status_line + b"\r\n".join(headers) + b"\r\n\r\n" + body
            # DNS Protocol
            if context.protocol_type.upper() == "DNS" or context.target_port == 53:
                # Return a minimal DNS error response (SERVFAIL)
                if len(context.request_data) >= 12:
                    # Extract transaction ID from request
                    transaction_id = context.request_data[:2]
                    # DNS response with SERVFAIL (rcode=2)
                    flags = b"\x81\x82"  # QR=1, RCODE=2 (SERVFAIL)
                    return transaction_id + flags + b"\x00\x00" * 4  # Zero counts
                # Invalid DNS request, return empty
                return b""

            # SMTP Protocol
            if context.protocol_type.upper() == "SMTP" or context.target_port in [25, 587, 465]:
                return b"421 4.3.0 Service temporarily unavailable\r\n"

            # FTP Protocol
            if context.protocol_type.upper() == "FTP" or context.target_port in [20, 21]:
                return b"421 Service not available, closing control connection.\r\n"

            # POP3 Protocol
            if context.protocol_type.upper() == "POP3" or context.target_port in [110, 995]:
                return b"-ERR Service temporarily unavailable\r\n"

            # IMAP Protocol
            if context.protocol_type.upper() == "IMAP" or context.target_port in [143, 993]:
                return b"* BYE Service temporarily unavailable\r\n"

            # License Protocol Hints
            if "license" in context.protocol_type.lower() or context.target_port in [
                1947,
                27000,
                27001,
            ]:
                # FlexLM/license manager style response
                return b"ERROR: License service temporarily unavailable\n"

            # Binary protocols - return structured error
            if context.request_data and not context.request_data[:100].decode("utf-8", errors="ignore").isprintable():
                # Return a simple binary error pattern
                return b"\x00\x00\x00\x04FAIL"

            # Default text-based fallback
            return b"ERROR: Service temporarily unavailable\n"

        except Exception as e:
            self.logger.debug("Protocol-aware fallback generation error: %s", e, exc_info=True)
            return b"ERROR\n"

    def _create_intelligent_fallback(self, context: ResponseContext) -> bytes:
        """Create an intelligent fallback response based on context.

        Args:
            context: Request context with request data and header information.

        Returns:
            Intelligent fallback response based on request analysis.

        """
        try:
            # Analyze request for protocol hints
            request_str = context.request_data.decode("utf-8", errors="ignore")

            # Check content type from headers if available
            content_type = context.headers.get("content-type", "").lower() if context.headers else ""

            # XML response pattern
            if ("<" in request_str and ">" in request_str) or "xml" in content_type:
                return (
                    b"""<?xml version="1.0" encoding="UTF-8"?>
<response>
    <status>success</status>
    <code>200</code>
    <message>Request processed successfully</message>
    <timestamp>"""
                    + str(int(context.timestamp)).encode()
                    + b"""</timestamp>
</response>"""
                )

            # JSON response pattern
            if "{" in request_str or "json" in content_type:
                response = {
                    "status": "success",
                    "code": 200,
                    "message": "Request processed successfully",
                    "timestamp": int(context.timestamp),
                    "data": {},
                }
                return json.dumps(response).encode("utf-8")

            # License-specific patterns
            if any(word in request_str.lower() for word in ["license", "auth", "validate", "verify"]):
                # Check if it looks like a product-specific request
                if "adobe" in request_str.lower():
                    return b"ADOBE_LICENSE_VALID"
                if "autodesk" in request_str.lower():
                    return b"AUTODESK_LICENSE_VALID"
                if "microsoft" in request_str.lower():
                    return b"MICROSOFT_LICENSE_VALID"
                return b"LICENSE_VALID"

            # HTTP-style response
            if context.protocol_type == "HTTP":
                return b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK"

            # Binary protocol response
            if not request_str.isprintable():
                # Return a structured binary response
                return b"\x00\x01" + b"\x00\x00\x00\x08" + b"SUCCESS\x00"

            # Default fallback with more context
            return b"SUCCESS"

        except Exception as e:
            self.logger.debug("Fallback generation error: %s", e, exc_info=True)
            return self._create_protocol_aware_fallback(context)

    def get_statistics(self) -> dict[str, Any]:
        """Get response generation statistics.

        Returns:
            Copy of statistics dictionary containing total requests,
            successful/failed responses, protocols handled, and average response time.

        """
        return self.stats.copy()

    def export_learning_data(self) -> dict[str, Any]:
        """Export learning data for backup/analysis.

        Returns:
            Dictionary containing learned patterns, statistics, and cache size.

        """
        return {
            "learned_patterns": self.learned_patterns,
            "statistics": self.stats,
            "cache_size": len(self.response_cache),
        }

    def import_learning_data(self, data: dict[str, Any]) -> None:
        """Import learning data from previous sessions.

        Args:
            data: Dictionary containing learned patterns from previous sessions.

        """
        try:
            if "learned_patterns" in data:
                self.learned_patterns.update(data["learned_patterns"])
                self.logger.info("Imported learning data for %s protocols", len(data["learned_patterns"]))

        except Exception as e:
            self.logger.exception("Error importing learning data: %s", e, exc_info=True)


__all__ = ["DynamicResponseGenerator", "GeneratedResponse", "ResponseContext"]
