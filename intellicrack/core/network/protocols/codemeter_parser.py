"""CodeMeter License Protocol Parser and Response Generator.

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
import random
import secrets
import struct
import time
import uuid
from dataclasses import dataclass
from typing import Any

from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)


@dataclass
class CodeMeterRequest:
    """CodeMeter request structure."""

    command: int
    request_id: int
    firm_code: int
    product_code: int
    feature_map: int
    version: str
    client_id: str
    session_context: dict[str, Any]
    challenge_data: bytes
    additional_data: dict[str, Any]


@dataclass
class CodeMeterResponse:
    """CodeMeter response structure."""

    status: int
    request_id: int
    firm_code: int
    product_code: int
    license_info: dict[str, Any]
    response_data: bytes
    container_info: dict[str, Any]
    expiry_data: dict[str, Any]


class CodeMeterProtocolParser:
    """Real CodeMeter protocol parser and response generator."""

    # CodeMeter command constants
    CODEMETER_COMMANDS = {
        0x1000: "CM_LOGIN",
        0x1001: "CM_LOGOUT",
        0x1002: "CM_CHALLENGE",
        0x1003: "CM_RESPONSE",
        0x1004: "CM_GET_INFO",
        0x1005: "CM_SET_ACCESS",
        0x1006: "CM_ENCRYPT",
        0x1007: "CM_DECRYPT",
        0x1008: "CM_SIGN",
        0x1009: "CM_VERIFY",
        0x100A: "CM_GET_LICENSE",
        0x100B: "CM_RELEASE_LICENSE",
        0x100C: "CM_HEARTBEAT",
        0x100D: "CM_GET_CONTAINER_INFO",
        0x100E: "CM_ENUM_PRODUCTS",
        0x100F: "CM_TRANSFER_RECEIPT",
        0x1010: "CM_CHECK_RECEIPT",
        0x1011: "CM_UPDATE_CONTAINER",
        0x1012: "CM_BACKUP_CONTAINER",
        0x1013: "CM_RESTORE_CONTAINER",
    }

    # CodeMeter status codes
    CODEMETER_STATUS_CODES = {
        0x00000000: "CM_GCM_OK",
        0x00000001: "CM_GCM_NO_CODEMETER",
        0x00000002: "CM_GCM_NO_LICENSE",
        0x00000003: "CM_GCM_NO_SECURE_REPOSITORY",
        0x00000004: "CM_GCM_SERVER_NOT_FOUND",
        0x00000005: "CM_GCM_UNKNOWN_FIRM_CODE",
        0x00000006: "CM_GCM_UNKNOWN_PRODUCT_CODE",
        0x00000007: "CM_GCM_INVALID_PRODUCT_CODE",
        0x00000008: "CM_GCM_INVALID_PASSWORD",
        0x00000009: "CM_GCM_INVALID_ACCESS_MODE",
        0x0000000A: "CM_GCM_PORT_IN_USE",
        0x0000000B: "CM_GCM_NO_DONGLE_MEMORY",
        0x0000000C: "CM_GCM_MEMORY_READ_WRITE_ERROR",
        0x0000000D: "CM_GCM_FEATURE_NOT_AVAILABLE",
        0x0000000E: "CM_GCM_TRIAL_LICENSE_EXPIRED",
        0x0000000F: "CM_GCM_CONTAINER_LOCKED",
        0x00000010: "CM_GCM_INVALID_CONTAINER",
        0x00000011: "CM_GCM_NETWORK_ERROR",
        0x00000012: "CM_GCM_ENCRYPTION_ERROR",
    }

    def __init__(self) -> None:
        """Initialize the CodeMeter protocol parser with session tracking and container info."""
        self.logger = get_logger(__name__)
        self.active_sessions: dict[str, dict[str, Any]] = {}
        self.container_info = self._generate_container_info()
        self.license_receipts: dict[str, dict[str, Any]] = {}
        self._load_default_products()

    def _load_default_products(self) -> None:
        """Load default CodeMeter products."""
        self.products: dict[tuple[int, int], dict[str, Any]] = {
            # Common firm codes and products
            (500001, 1): {  # Sample CAD software
                "name": "CAD_PROFESSIONAL",
                "features": 0xFFFFFFFF,  # All features enabled
                "max_users": 100,
                "expiry": "31-dec-2025",
                "license_type": "permanent",
                "encryption_supported": True,
                "signing_supported": True,
            },
            (500001, 2): {
                "name": "CAD_STANDARD",
                "features": 0x0000FFFF,  # Limited features
                "max_users": 50,
                "expiry": "31-dec-2025",
                "license_type": "permanent",
                "encryption_supported": True,
                "signing_supported": False,
            },
            (500002, 1): {  # Sample Engineering software
                "name": "ENGINEERING_SUITE",
                "features": 0xFFFFFFFF,
                "max_users": 25,
                "expiry": "31-dec-2025",
                "license_type": "permanent",
                "encryption_supported": True,
                "signing_supported": True,
            },
            (500003, 1): {  # Sample Media software
                "name": "MEDIA_EDITOR_PRO",
                "features": 0x7FFFFFFF,
                "max_users": 10,
                "expiry": "31-dec-2025",
                "license_type": "subscription",
                "encryption_supported": True,
                "signing_supported": True,
            },
            (500004, 1): {  # Sample Development tools
                "name": "DEVELOPMENT_TOOLS",
                "features": 0xFFFFFFFF,
                "max_users": 200,
                "expiry": "permanent",
                "license_type": "permanent",
                "encryption_supported": True,
                "signing_supported": True,
            },
            (999999, 1): {  # Generic product for testing
                "name": "GENERIC_PRODUCT",
                "features": 0xFFFFFFFF,
                "max_users": 999,
                "expiry": "permanent",
                "license_type": "permanent",
                "encryption_supported": True,
                "signing_supported": True,
            },
        }

    def _generate_container_info(self) -> dict[str, Any]:
        """Generate realistic CodeMeter container information."""
        return {
            "serial_number": secrets.randbelow(9000000) + 1000000,
            "firm_code": 500001,
            "container_type": "CmStick/T",
            "memory_total": 65536,
            "memory_free": 32768,
            "creation_time": int(time.time() - random.randint(86400, 864000)),  # noqa: S311 - Randomized creation time offset
            "activation_count": random.randint(1, 100),  # noqa: S311 - Randomized activation statistics
            "firm_update_count": random.randint(0, 10),  # noqa: S311 - Randomized update statistics
            "product_update_count": random.randint(0, 50),  # noqa: S311 - Randomized update statistics
            "device_id": str(uuid.uuid4()).upper(),
            "firmware_version": "6.90.5317.500",
        }

    def parse_request(self, data: bytes) -> CodeMeterRequest | None:
        """Parse incoming CodeMeter request.

        Args:
            data: Raw CodeMeter request data

        Returns:
            Parsed CodeMeterRequest object or None if invalid

        """
        try:
            if len(data) < 24:  # Minimum CodeMeter header
                self.logger.warning("CodeMeter request too short")
                return None

            offset = 0

            # Check CodeMeter magic signature
            magic = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            if magic not in [0x434D4554, 0x57495553, 0x434D5354]:  # "CMET", "WIUS", "CMST"
                self.logger.debug("Invalid CodeMeter magic: 0x%X", magic)
                return None

            # Parse header
            command = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            request_id = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            firm_code = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            product_code = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            feature_map = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            # Parse version string
            version_length = struct.unpack("<H", data[offset : offset + 2])[0]
            offset += 2

            if offset + version_length > len(data):
                return None

            version = data[offset : offset + version_length].decode("utf-8", errors="ignore")
            offset += version_length

            # Parse client ID
            client_id_length = struct.unpack("<H", data[offset : offset + 2])[0]
            offset += 2

            if offset + client_id_length > len(data):
                return None

            client_id = data[offset : offset + client_id_length].decode("utf-8", errors="ignore")
            offset += client_id_length

            # Parse session context (JSON-like structure)
            context_length = struct.unpack("<H", data[offset : offset + 2])[0]
            offset += 2

            session_context = {}
            if context_length > 0 and offset + context_length <= len(data):
                context_data = data[offset : offset + context_length]
                session_context = self._parse_session_context(context_data)
                offset += context_length

            # Parse challenge data
            challenge_length = struct.unpack("<H", data[offset : offset + 2])[0]
            offset += 2

            challenge_data = b""
            if challenge_length > 0 and offset + challenge_length <= len(data):
                challenge_data = data[offset : offset + challenge_length]
                offset += challenge_length

            # Parse additional data
            additional_data = {}
            if offset < len(data):
                additional_data = self._parse_additional_data(data[offset:])

            request = CodeMeterRequest(
                command=command,
                request_id=request_id,
                firm_code=firm_code,
                product_code=product_code,
                feature_map=feature_map,
                version=version,
                client_id=client_id,
                session_context=session_context,
                challenge_data=challenge_data,
                additional_data=additional_data,
            )

            command_name = self.CODEMETER_COMMANDS.get(command, f"UNKNOWN_{command:04X}")
            self.logger.info("Parsed CodeMeter %s request for product %s:%s", command_name, firm_code, product_code)
            return request

        except Exception as e:
            self.logger.exception("Failed to parse CodeMeter request: %s", e)
            return None

    def _parse_session_context(self, data: bytes) -> dict[str, Any]:
        """Parse CodeMeter session context data."""
        context = {}
        try:
            offset = 0
            while offset < len(data) - 4:
                key_length = struct.unpack("<H", data[offset : offset + 2])[0]
                offset += 2

                if offset + key_length > len(data):
                    break

                key = data[offset : offset + key_length].decode("utf-8", errors="ignore")
                offset += key_length

                value_length = struct.unpack("<H", data[offset : offset + 2])[0]
                offset += 2

                if offset + value_length > len(data):
                    break

                value = data[offset : offset + value_length].decode("utf-8", errors="ignore")
                offset += value_length

                context[key] = value

        except Exception as e:
            self.logger.debug("Error parsing session context: %s", e)

        return context

    def _parse_additional_data(self, data: bytes) -> dict[str, Any]:
        """Parse additional CodeMeter data fields."""
        additional: dict[str, Any] = {}
        try:
            offset = 0
            while offset < len(data) - 4:
                field_type = struct.unpack("<H", data[offset : offset + 2])[0]
                field_length = struct.unpack("<H", data[offset + 2 : offset + 4])[0]
                offset += 4

                if offset + field_length > len(data):
                    break

                field_data = data[offset : offset + field_length]
                offset += field_length

                if field_type == 0x0001:  # Hostname
                    additional["hostname"] = field_data.decode("utf-8", errors="ignore")
                elif field_type == 0x0002:  # Process name
                    additional["process_name"] = field_data.decode("utf-8", errors="ignore")
                elif field_type == 0x0003:  # Process ID
                    if len(field_data) >= 4:
                        additional["process_id"] = struct.unpack("<I", field_data[:4])[0]
                elif field_type == 0x0004:  # User context
                    additional["user_context"] = field_data.decode("utf-8", errors="ignore")
                else:
                    additional[f"field_{field_type:04X}"] = field_data

        except Exception as e:
            self.logger.debug("Error parsing additional data: %s", e)

        return additional

    def generate_response(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Generate appropriate CodeMeter response based on request.

        Args:
            request: Parsed CodeMeter request

        Returns:
            CodeMeter response object

        """
        command_name = self.CODEMETER_COMMANDS.get(request.command, "UNKNOWN")
        self.logger.info("Generating response for %s command", command_name)

        if request.command == 0x1000:  # CM_LOGIN
            return self._handle_login(request)
        if request.command == 0x1001:  # CM_LOGOUT
            return self._handle_logout(request)
        if request.command == 0x1002:  # CM_CHALLENGE
            return self._handle_challenge(request)
        if request.command == 0x1003:  # CM_RESPONSE
            return self._handle_response(request)
        if request.command == 0x1004:  # CM_GET_INFO
            return self._handle_get_info(request)
        if request.command == 0x1006:  # CM_ENCRYPT
            return self._handle_encrypt(request)
        if request.command == 0x1007:  # CM_DECRYPT
            return self._handle_decrypt(request)
        if request.command == 0x1008:  # CM_SIGN
            return self._handle_sign(request)
        if request.command == 0x1009:  # CM_VERIFY
            return self._handle_verify(request)
        if request.command == 0x100A:  # CM_GET_LICENSE
            return self._handle_get_license(request)
        if request.command == 0x100B:  # CM_RELEASE_LICENSE
            return self._handle_release_license(request)
        if request.command == 0x100C:  # CM_HEARTBEAT
            return self._handle_heartbeat(request)
        if request.command == 0x100D:  # CM_GET_CONTAINER_INFO
            return self._handle_get_container_info(request)
        if request.command == 0x100E:  # CM_ENUM_PRODUCTS
            return self._handle_enum_products(request)
        if request.command == 0x100F:  # CM_TRANSFER_RECEIPT
            return self._handle_transfer_receipt(request)
        if request.command == 0x1010:  # CM_CHECK_RECEIPT
            return self._handle_check_receipt(request)
        return self._handle_unknown_command(request)

    def _handle_login(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle CodeMeter login request."""
        product_key = (request.firm_code, request.product_code)

        if product_key not in self.products:
            return CodeMeterResponse(
                status=0x00000006,  # CM_GCM_UNKNOWN_PRODUCT_CODE
                request_id=request.request_id,
                firm_code=request.firm_code,
                product_code=request.product_code,
                license_info={},
                response_data=b"",
                container_info={},
                expiry_data={},
            )

        product = self.products[product_key]

        # Generate session
        session_id = f"{request.client_id}:{request.firm_code}:{request.product_code}:{time.time()}"
        session_hash = hashlib.sha256(session_id.encode()).hexdigest()

        self.active_sessions[session_hash] = {
            "request": request,
            "product": product,
            "login_time": time.time(),
            "access_count": 0,
        }

        features: int = product["features"]
        max_users: int = product["max_users"]

        return CodeMeterResponse(
            status=0x00000000,  # CM_GCM_OK
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={
                "session_id": session_hash,
                "features_granted": features & request.feature_map,
                "access_mode": "exclusive" if max_users == 1 else "shared",
            },
            response_data=hashlib.sha256(session_id.encode()).digest()[:16],
            container_info=self.container_info,
            expiry_data={
                "expiry_date": product["expiry"],
                "license_type": product["license_type"],
            },
        )

    def _handle_logout(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle CodeMeter logout request."""
        session_id = request.session_context.get("session_id", "")

        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
        status = 0x00000000  # CM_GCM_OK
        return CodeMeterResponse(
            status=status,
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={"logout_time": int(time.time())},
            response_data=b"",
            container_info={},
            expiry_data={},
        )

    def _handle_challenge(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle challenge-response authentication."""
        # Generate response to challenge
        challenge_response = hashlib.sha256(
            request.challenge_data + str(request.firm_code).encode() + str(request.product_code).encode(),
        ).digest()

        return CodeMeterResponse(
            status=0x00000000,  # CM_GCM_OK
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={},
            response_data=challenge_response,
            container_info={},
            expiry_data={},
        )

    def _handle_response(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle response verification."""
        # Verify the response (simplified - always accept)
        return CodeMeterResponse(
            status=0x00000000,  # CM_GCM_OK
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={"authentication": "verified"},
            response_data=b"\x01",  # Success
            container_info={},
            expiry_data={},
        )

    def _handle_get_info(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle get info request."""
        return CodeMeterResponse(
            status=0x00000000,  # CM_GCM_OK
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={
                "runtime_version": "7.60.6089.500",
                "api_version": "7.60",
                "containers_found": 1,
                "server_running": True,
            },
            response_data=b"",
            container_info=self.container_info,
            expiry_data={},
        )

    def _handle_encrypt(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle encryption request."""
        # Perform XOR encryption using firm/product code as key
        key = struct.pack("<II", request.firm_code, request.product_code)
        encrypted_data = bytearray()

        for i, byte in enumerate(request.challenge_data):
            encrypted_data.append(byte ^ key[i % len(key)])

        return CodeMeterResponse(
            status=0x00000000,  # CM_GCM_OK
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={},
            response_data=bytes(encrypted_data),
            container_info={},
            expiry_data={},
        )

    def _handle_decrypt(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle decryption request."""
        # Same as encrypt for XOR cipher
        return self._handle_encrypt(request)

    def _handle_sign(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle digital signature request."""
        # Generate signature hash
        signature = hashlib.sha256(
            request.challenge_data + struct.pack("<II", request.firm_code, request.product_code),
        ).digest()

        return CodeMeterResponse(
            status=0x00000000,  # CM_GCM_OK
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={"signature_algorithm": "SHA256"},
            response_data=signature,
            container_info={},
            expiry_data={},
        )

    def _handle_verify(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle signature verification request."""
        # Simplified verification - always succeed
        return CodeMeterResponse(
            status=0x00000000,  # CM_GCM_OK
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={"verification": "valid"},
            response_data=b"\x01",  # Valid
            container_info={},
            expiry_data={},
        )

    def _handle_get_license(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle get license request."""
        product_key = (request.firm_code, request.product_code)

        if product_key in self.products:
            product = self.products[product_key]
            return CodeMeterResponse(
                status=0x00000000,  # CM_GCM_OK
                request_id=request.request_id,
                firm_code=request.firm_code,
                product_code=request.product_code,
                license_info=product,
                response_data=b"",
                container_info=self.container_info,
                expiry_data={
                    "expiry_date": product["expiry"],
                    "license_type": product["license_type"],
                },
            )
        return CodeMeterResponse(
            status=0x00000002,  # CM_GCM_NO_LICENSE
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={},
            response_data=b"",
            container_info={},
            expiry_data={},
        )

    def _handle_release_license(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle release license request."""
        return CodeMeterResponse(
            status=0x00000000,  # CM_GCM_OK
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={"release_time": int(time.time())},
            response_data=b"",
            container_info={},
            expiry_data={},
        )

    def _handle_heartbeat(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle heartbeat request."""
        session_id = request.session_context.get("session_id", "")

        if session_id in self.active_sessions:
            self.active_sessions[session_id]["last_heartbeat"] = time.time()

        return CodeMeterResponse(
            status=0x00000000,  # CM_GCM_OK
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={"heartbeat_time": int(time.time())},
            response_data=b"",
            container_info={},
            expiry_data={},
        )

    def _handle_get_container_info(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle get container info request."""
        return CodeMeterResponse(
            status=0x00000000,  # CM_GCM_OK
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={},
            response_data=b"",
            container_info=self.container_info,
            expiry_data={},
        )

    def _handle_enum_products(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle enumerate products request."""
        products_list = []
        for (firm_code, product_code), product in self.products.items():
            if request.firm_code in (firm_code, 0):
                products_list.append(
                    {
                        "firm_code": firm_code,
                        "product_code": product_code,
                        "name": product["name"],
                        "features": product["features"],
                        "max_users": product["max_users"],
                    },
                )

        return CodeMeterResponse(
            status=0x00000000,  # CM_GCM_OK
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={"products": products_list},
            response_data=b"",
            container_info=self.container_info,
            expiry_data={},
        )

    def _handle_transfer_receipt(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle transfer receipt request."""
        receipt_id = hashlib.sha256(
            f"{request.firm_code}:{request.product_code}:{time.time()}".encode(),
        ).hexdigest()

        self.license_receipts[receipt_id] = {
            "firm_code": request.firm_code,
            "product_code": request.product_code,
            "transfer_time": time.time(),
            "client_id": request.client_id,
        }

        return CodeMeterResponse(
            status=0x00000000,  # CM_GCM_OK
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={"receipt_id": receipt_id},
            response_data=receipt_id.encode(),
            container_info={},
            expiry_data={},
        )

    def _handle_check_receipt(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle check receipt request."""
        receipt_id = request.session_context.get("receipt_id", "")

        if receipt_id in self.license_receipts:
            receipt = self.license_receipts[receipt_id]
            return CodeMeterResponse(
                status=0x00000000,  # CM_GCM_OK
                request_id=request.request_id,
                firm_code=request.firm_code,
                product_code=request.product_code,
                license_info=receipt,
                response_data=b"",
                container_info={},
                expiry_data={},
            )
        return CodeMeterResponse(
            status=0x00000002,  # CM_GCM_NO_LICENSE
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={},
            response_data=b"",
            container_info={},
            expiry_data={},
        )

    def _handle_unknown_command(self, request: CodeMeterRequest) -> CodeMeterResponse:
        """Handle unknown command."""
        self.logger.warning("Unknown CodeMeter command: 0x%04X", request.command)
        return CodeMeterResponse(
            status=0x00000012,  # CM_GCM_ENCRYPTION_ERROR (generic error)
            request_id=request.request_id,
            firm_code=request.firm_code,
            product_code=request.product_code,
            license_info={},
            response_data=b"",
            container_info={},
            expiry_data={},
        )

    def serialize_response(self, response: CodeMeterResponse) -> bytes:
        """Serialize CodeMeter response to bytes.

        Args:
            response: CodeMeter response object

        Returns:
            Serialized response bytes

        """
        try:
            packet = bytearray()

            # Magic signature
            packet.extend(struct.pack("<I", 0x434D4554))  # "CMET"

            # Status code
            packet.extend(struct.pack("<I", response.status))

            # Request ID
            packet.extend(struct.pack("<I", response.request_id))

            # Firm code
            packet.extend(struct.pack("<I", response.firm_code))

            # Product code
            packet.extend(struct.pack("<I", response.product_code))

            # License info (serialized as key-value pairs)
            license_data = self._serialize_dict(response.license_info)
            packet.extend(struct.pack("<H", len(license_data)))
            packet.extend(license_data)

            # Response data
            packet.extend(struct.pack("<H", len(response.response_data)))
            packet.extend(response.response_data)

            # Container info
            container_data = self._serialize_dict(response.container_info)
            packet.extend(struct.pack("<H", len(container_data)))
            packet.extend(container_data)

            # Expiry data
            expiry_data = self._serialize_dict(response.expiry_data)
            packet.extend(struct.pack("<H", len(expiry_data)))
            packet.extend(expiry_data)

            return bytes(packet)

        except Exception as e:
            self.logger.exception("Failed to serialize CodeMeter response: %s", e)
            # Return minimal error response
            return struct.pack("<III", 0x434D4554, response.status, response.request_id)

    def _serialize_dict(self, data: dict[str, Any]) -> bytes:
        """Serialize dictionary to bytes."""
        serialized = bytearray()

        for key, value in data.items():
            try:
                key_bytes = key.encode("utf-8")

                if isinstance(value, str):
                    value_bytes = value.encode("utf-8")
                elif isinstance(value, int):
                    value_bytes = struct.pack("<I", value)
                else:
                    value_bytes = str(value).encode("utf-8")
                serialized.extend(struct.pack("<H", len(key_bytes)))
                serialized.extend(key_bytes)
                serialized.extend(struct.pack("<H", len(value_bytes)))
                serialized.extend(value_bytes)

            except Exception as e:
                self.logger.debug("Error serializing %s: %s", key, e)

        return bytes(serialized)
