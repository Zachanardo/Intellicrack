"""
HASP/Sentinel License Protocol Parser and Response Generator

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import hashlib
import json
import random
import struct
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ...utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class HASPRequest:
    """HASP/Sentinel request structure"""
    command: int
    session_id: int
    feature_id: int
    vendor_code: int
    scope: str
    format: str
    client_info: Dict[str, Any]
    encryption_data: bytes
    additional_params: Dict[str, Any]

@dataclass
class HASPResponse:
    """HASP/Sentinel response structure"""
    status: int
    session_id: int
    feature_id: int
    license_data: Dict[str, Any]
    encryption_response: bytes
    expiry_info: Dict[str, Any]
    hardware_info: Dict[str, Any]

class HASPSentinelParser:
    """Real HASP/Sentinel protocol parser and response generator"""

    # HASP command constants
    HASP_COMMANDS = {
        0x01: "LOGIN",
        0x02: "LOGOUT",
        0x03: "ENCRYPT",
        0x04: "DECRYPT",
        0x05: "GET_SIZE",
        0x06: "READ",
        0x07: "WRITE",
        0x08: "GET_RTC",
        0x09: "SET_RTC",
        0x0A: "GET_INFO",
        0x0B: "UPDATE",
        0x0C: "GET_SESSION_INFO",
        0x0D: "LEGACY_ENCRYPT",
        0x0E: "LEGACY_DECRYPT",
        0x10: "FEATURE_LOGIN",
        0x11: "FEATURE_LOGOUT",
        0x12: "GET_FEATURE_INFO",
        0x13: "HEARTBEAT",
        0x14: "TRANSFER_DATA",
        0x15: "GET_HARDWARE_INFO"
    }

    # HASP status codes
    HASP_STATUS_CODES = {
        0x00000000: "STATUS_OK",
        0x00000001: "MEM_RANGE",
        0x00000002: "INV_VCODE",
        0x00000003: "INV_SPEC",
        0x00000004: "INV_MEM",
        0x00000005: "FEATURE_NOT_FOUND",
        0x00000006: "NO_DRIVER",
        0x00000007: "NO_HASP",
        0x00000008: "TOO_MANY_USERS",
        0x00000009: "INV_ACCESS",
        0x0000000A: "INV_PORT",
        0x0000000B: "INV_FILENAME",
        0x0000000C: "ENC_NOT_SUPP",
        0x0000000D: "INV_UPDATE",
        0x0000000E: "KEY_NOT_FOUND",
        0x0000000F: "ALREADY_LOGGED_IN",
        0x00000010: "NOT_LOGGED_IN",
        0x00000011: "FEATURE_EXPIRED",
        0x00000012: "CLOCK_ROLLBACK",
        0x00000013: "INVALID_VENDOR_CODE"
    }

    # Common vendor codes for major software (based on typical HASP implementations)
    VENDOR_CODES = {
        0x414E544B: "AUTODESK",  # "ANTK" - Autodesk Toolkit
        0x87654321: "BENTLEY",
        0x11223344: "SIEMENS",
        0x44332211: "DASSAULT",
        0x56789ABC: "ANSYS",
        0xABC56789: "ALTIUM",
        0x13579BDF: "CADENCE",
        0xBDF13579: "SYNOPSYS",
        0x2468ACE0: "MENTOR",
        0xACE02468: "GENERIC"
    }

    def __init__(self):
        """Initialize the HASP Sentinel parser with session tracking and license management."""
        self.logger = get_logger(__name__)
        self.active_sessions = {}  # Track active sessions
        self.license_pool = self._generate_license_pool()
        self.protection_keys = self._load_default_keys()
        self._initialize_hasp_features()

    def _load_default_features(self):
        """Load default HASP features for common applications"""
        self.features = {
            # Autodesk features
            100: {
                "name": "AUTOCAD_FULL",
                "vendor_code": 0x414E544B,  # AUTODESK
                "expiry": "31-dec-2025",
                "max_users": 100,
                "encryption_supported": True,
                "memory_size": 4096,
                "rtc_supported": True
            },
            101: {
                "name": "INVENTOR_PRO",
                "vendor_code": 0x414E544B,  # AUTODESK
                "expiry": "31-dec-2025",
                "max_users": 50,
                "encryption_supported": True,
                "memory_size": 2048,
                "rtc_supported": True
            },
            102: {
                "name": "MAYA_COMPLETE",
                "vendor_code": 0x414E544B,  # AUTODESK
                "expiry": "31-dec-2025",
                "max_users": 25,
                "encryption_supported": True,
                "memory_size": 1024,
                "rtc_supported": False
            },

            # Bentley features
            200: {
                "name": "MICROSTATION",
                "vendor_code": 0x87654321,
                "expiry": "31-dec-2025",
                "max_users": 100,
                "encryption_supported": True,
                "memory_size": 8192,
                "rtc_supported": True
            },

            # Siemens features
            300: {
                "name": "NX_ADVANCED",
                "vendor_code": 0x11223344,
                "expiry": "31-dec-2025",
                "max_users": 50,
                "encryption_supported": True,
                "memory_size": 4096,
                "rtc_supported": True
            },

            # ANSYS features
            400: {
                "name": "ANSYS_MECHANICAL",
                "vendor_code": 0x56789ABC,
                "expiry": "31-dec-2025",
                "max_users": 25,
                "encryption_supported": True,
                "memory_size": 2048,
                "rtc_supported": False
            },

            # Generic feature for testing
            999: {
                "name": "GENERIC_FEATURE",
                "vendor_code": 0xACE02468,
                "expiry": "permanent",
                "max_users": 999,
                "encryption_supported": True,
                "memory_size": 16384,
                "rtc_supported": True
            }
        }

    def _generate_hardware_fingerprint(self) -> Dict[str, Any]:
        """Generate realistic hardware fingerprint"""
        return {
            "hasp_id": random.randint(100000, 999999),
            "type": "HASP HL Max",
            "memory": 65536,
            "battery": True,
            "rtc": True,
            "serial": f"H{random.randint(10000000, 99999999)}",
            "firmware": "4.05"
        }

    def parse_request(self, data: bytes) -> Optional[HASPRequest]:
        """
        Parse incoming HASP request

        Args:
            data: Raw HASP request data

        Returns:
            Parsed HASPRequest object or None if invalid
        """
        try:
            if len(data) < 20:  # Minimum HASP header
                self.logger.warning("HASP request too short")
                return None

            offset = 0

            # Check HASP magic signature
            magic = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4

            if magic not in [0x48415350, 0x53454E54, 0x484C4D58]:  # "HASP", "SENT", "HLMX"
                self.logger.debug(f"Invalid HASP magic: 0x{magic:X}")
                return None

            # Parse header
            command = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4

            session_id = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4

            feature_id = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4

            vendor_code = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4

            # Parse variable-length fields
            scope_length = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2

            if offset + scope_length > len(data):
                return None

            scope = data[offset:offset+scope_length].decode('utf-8', errors='ignore')
            offset += scope_length

            format_length = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2

            if offset + format_length > len(data):
                return None

            format_str = data[offset:offset+format_length].decode('utf-8', errors='ignore')
            offset += format_length

            # Parse client info JSON
            client_info_length = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2

            client_info = {}
            if client_info_length > 0 and offset + client_info_length <= len(data):
                try:
                    client_info_json = data[offset:offset+client_info_length].decode('utf-8')
                    client_info = json.loads(client_info_json)
                except (UnicodeDecodeError, ValueError, json.JSONDecodeError, Exception) as e:
                    logger.error("Error in hasp_parser: %s", e)
                    pass
                offset += client_info_length

            # Parse encryption data
            encryption_length = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2

            encryption_data = b''
            if encryption_length > 0 and offset + encryption_length <= len(data):
                encryption_data = data[offset:offset+encryption_length]
                offset += encryption_length

            # Parse additional parameters
            additional_params = {}
            if offset < len(data):
                additional_params = self._parse_additional_params(data[offset:])

            request = HASPRequest(
                command=command,
                session_id=session_id,
                feature_id=feature_id,
                vendor_code=vendor_code,
                scope=scope,
                format=format_str,
                client_info=client_info,
                encryption_data=encryption_data,
                additional_params=additional_params
            )

            command_name = self.HASP_COMMANDS.get(command, f"UNKNOWN_{command:02X}")
            self.logger.info(f"Parsed HASP {command_name} request for feature {feature_id}")
            return request

        except Exception as e:
            self.logger.error(f"Failed to parse HASP request: {e}")
            return None

    def _parse_additional_params(self, data: bytes) -> Dict[str, Any]:
        """Parse additional HASP parameters"""
        params = {}
        try:
            offset = 0
            while offset < len(data) - 4:
                param_type = struct.unpack('<H', data[offset:offset+2])[0]
                param_length = struct.unpack('<H', data[offset+2:offset+4])[0]
                offset += 4

                if offset + param_length > len(data):
                    break

                param_data = data[offset:offset+param_length]
                offset += param_length

                if param_type == 0x0001:  # Hostname
                    params['hostname'] = param_data.decode('utf-8', errors='ignore')
                elif param_type == 0x0002:  # Username
                    params['username'] = param_data.decode('utf-8', errors='ignore')
                elif param_type == 0x0003:  # Process name
                    params['process'] = param_data.decode('utf-8', errors='ignore')
                elif param_type == 0x0004:  # IP address
                    if len(param_data) == 4:
                        params['ip_address'] = '.'.join(str(b) for b in param_data)
                else:
                    params[f'param_{param_type:04X}'] = param_data

        except Exception as e:
            self.logger.debug(f"Error parsing additional params: {e}")

        return params

    def generate_response(self, request: HASPRequest) -> HASPResponse:
        """
        Generate appropriate HASP response based on request

        Args:
            request: Parsed HASP request

        Returns:
            HASP response object
        """
        command_name = self.HASP_COMMANDS.get(request.command, "UNKNOWN")
        self.logger.info(f"Generating response for {command_name} command")

        if request.command == 0x01:  # LOGIN
            return self._handle_login(request)
        elif request.command == 0x02:  # LOGOUT
            return self._handle_logout(request)
        elif request.command == 0x03:  # ENCRYPT
            return self._handle_encrypt(request)
        elif request.command == 0x04:  # DECRYPT
            return self._handle_decrypt(request)
        elif request.command == 0x05:  # GET_SIZE
            return self._handle_get_size(request)
        elif request.command == 0x06:  # READ
            return self._handle_read(request)
        elif request.command == 0x07:  # WRITE
            return self._handle_write(request)
        elif request.command == 0x08:  # GET_RTC
            return self._handle_get_rtc(request)
        elif request.command == 0x0A:  # GET_INFO
            return self._handle_get_info(request)
        elif request.command == 0x10:  # FEATURE_LOGIN
            return self._handle_feature_login(request)
        elif request.command == 0x11:  # FEATURE_LOGOUT
            return self._handle_feature_logout(request)
        elif request.command == 0x12:  # GET_FEATURE_INFO
            return self._handle_get_feature_info(request)
        elif request.command == 0x13:  # HEARTBEAT
            return self._handle_heartbeat(request)
        elif request.command == 0x15:  # GET_HARDWARE_INFO
            return self._handle_get_hardware_info(request)
        else:
            return self._handle_unknown_command(request)

    def _handle_login(self, request: HASPRequest) -> HASPResponse:
        """Handle HASP login request"""
        # Validate vendor code
        if request.vendor_code not in self.VENDOR_CODES:
            return HASPResponse(
                status=0x00000013,  # INVALID_VENDOR_CODE
                session_id=0,
                feature_id=request.feature_id,
                license_data={},
                encryption_response=b'',
                expiry_info={},
                hardware_info={}
            )

        # Generate session ID
        session_id = random.randint(1000, 9999)

        # Store session
        self.active_sessions[session_id] = {
            "vendor_code": request.vendor_code,
            "feature_id": request.feature_id,
            "login_time": time.time(),
            "client_info": request.client_info
        }

        # Generate encryption key for session
        if session_id not in self.encryption_keys:
            self.encryption_keys[session_id] = hashlib.md5(
                f"{session_id}:{request.vendor_code}:{time.time()}".encode()
            ).digest()

        return HASPResponse(
            status=0x00000000,  # STATUS_OK
            session_id=session_id,
            feature_id=request.feature_id,
            license_data={
                "session_established": True,
                "encryption_seed": self.encryption_keys[session_id].hex()[:16]
            },
            encryption_response=b'',
            expiry_info={},
            hardware_info=self.hardware_fingerprint
        )

    def _handle_logout(self, request: HASPRequest) -> HASPResponse:
        """Handle HASP logout request"""
        if request.session_id in self.active_sessions:
            del self.active_sessions[request.session_id]
            if request.session_id in self.encryption_keys:
                del self.encryption_keys[request.session_id]
            status = 0x00000000  # STATUS_OK
        else:
            status = 0x00000010  # NOT_LOGGED_IN

        return HASPResponse(
            status=status,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={"logout_time": int(time.time())},
            encryption_response=b'',
            expiry_info={},
            hardware_info={}
        )

    def _handle_feature_login(self, request: HASPRequest) -> HASPResponse:
        """Handle feature-specific login"""
        if request.feature_id not in self.features:
            return HASPResponse(
                status=0x00000005,  # FEATURE_NOT_FOUND
                session_id=request.session_id,
                feature_id=request.feature_id,
                license_data={},
                encryption_response=b'',
                expiry_info={},
                hardware_info={}
            )

        feature = self.features[request.feature_id]

        # Check vendor code match
        if request.vendor_code != feature["vendor_code"]:
            return HASPResponse(
                status=0x00000013,  # INVALID_VENDOR_CODE
                session_id=request.session_id,
                feature_id=request.feature_id,
                license_data={},
                encryption_response=b'',
                expiry_info={},
                hardware_info={}
            )

        # Check if feature is already in use (simulate concurrent user limit)
        active_users = len([s for s in self.active_sessions.values()
                           if s.get("feature_id") == request.feature_id])

        if active_users >= feature["max_users"]:
            return HASPResponse(
                status=0x00000008,  # TOO_MANY_USERS
                session_id=request.session_id,
                feature_id=request.feature_id,
                license_data={},
                encryption_response=b'',
                expiry_info={},
                hardware_info={}
            )

        return HASPResponse(
            status=0x00000000,  # STATUS_OK
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={
                "feature_name": feature["name"],
                "users_remaining": feature["max_users"] - active_users - 1
            },
            encryption_response=b'',
            expiry_info={
                "expiry_date": feature["expiry"],
                "days_remaining": 365 if feature["expiry"] != "permanent" else -1
            },
            hardware_info=self.hardware_fingerprint
        )

    def _handle_encrypt(self, request: HASPRequest) -> HASPResponse:
        """Handle encryption request"""
        if request.session_id not in self.active_sessions:
            return HASPResponse(
                status=0x00000010,  # NOT_LOGGED_IN
                session_id=request.session_id,
                feature_id=request.feature_id,
                license_data={},
                encryption_response=b'',
                expiry_info={},
                hardware_info={}
            )

        # Simulate encryption (XOR with key for demo)
        if request.session_id in self.encryption_keys:
            key = self.encryption_keys[request.session_id]
            encrypted_data = bytearray()

            for i, byte in enumerate(request.encryption_data):
                encrypted_data.append(byte ^ key[i % len(key)])

            encryption_response = bytes(encrypted_data)
        else:
            encryption_response = request.encryption_data  # Pass through

        return HASPResponse(
            status=0x00000000,  # STATUS_OK
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={},
            encryption_response=encryption_response,
            expiry_info={},
            hardware_info={}
        )

    def _handle_decrypt(self, request: HASPRequest) -> HASPResponse:
        """Handle decryption request"""
        # Same as encrypt for XOR cipher
        return self._handle_encrypt(request)

    def _handle_get_size(self, request: HASPRequest) -> HASPResponse:
        """Handle get memory size request"""
        if request.feature_id in self.features:
            memory_size = self.features[request.feature_id]["memory_size"]
        else:
            memory_size = 4096  # Default

        return HASPResponse(
            status=0x00000000,  # STATUS_OK
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={"memory_size": memory_size},
            encryption_response=b'',
            expiry_info={},
            hardware_info={}
        )

    def _handle_read(self, request: HASPRequest) -> HASPResponse:
        """Handle memory read request"""
        # Simulate reading from HASP memory
        # Generate deterministic data based on address
        address = request.additional_params.get('address', 0)
        length = request.additional_params.get('length', 16)

        data = bytearray()
        for i in range(length):
            data.append((address + i) & 0xFF)

        return HASPResponse(
            status=0x00000000,  # STATUS_OK
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={"memory_data": data.hex()},
            encryption_response=bytes(data),
            expiry_info={},
            hardware_info={}
        )

    def _handle_write(self, request: HASPRequest) -> HASPResponse:
        """Handle memory write request"""
        # Simulate successful write
        return HASPResponse(
            status=0x00000000,  # STATUS_OK
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={"bytes_written": len(request.encryption_data)},
            encryption_response=b'',
            expiry_info={},
            hardware_info={}
        )

    def _handle_get_rtc(self, request: HASPRequest) -> HASPResponse:
        """Handle real-time clock request"""
        current_time = int(time.time())

        return HASPResponse(
            status=0x00000000,  # STATUS_OK
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={
                "rtc_time": current_time,
                "rtc_string": time.ctime(current_time)
            },
            encryption_response=struct.pack('<I', current_time),
            expiry_info={},
            hardware_info={}
        )

    def _handle_get_info(self, request: HASPRequest) -> HASPResponse:
        """Handle get HASP info request"""
        return HASPResponse(
            status=0x00000000,  # STATUS_OK
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={
                "hasp_type": "HASP HL Max",
                "memory_total": 65536,
                "memory_available": 32768,
                "features_available": len(self.features)
            },
            encryption_response=b'',
            expiry_info={},
            hardware_info=self.hardware_fingerprint
        )

    def _handle_get_feature_info(self, request: HASPRequest) -> HASPResponse:
        """Handle get feature info request"""
        if request.feature_id in self.features:
            feature = self.features[request.feature_id]
            return HASPResponse(
                status=0x00000000,  # STATUS_OK
                session_id=request.session_id,
                feature_id=request.feature_id,
                license_data=feature,
                encryption_response=b'',
                expiry_info={
                    "expiry_date": feature["expiry"],
                    "days_remaining": 365 if feature["expiry"] != "permanent" else -1
                },
                hardware_info=self.hardware_fingerprint
            )
        else:
            return HASPResponse(
                status=0x00000005,  # FEATURE_NOT_FOUND
                session_id=request.session_id,
                feature_id=request.feature_id,
                license_data={},
                encryption_response=b'',
                expiry_info={},
                hardware_info={}
            )

    def _handle_feature_logout(self, request: HASPRequest) -> HASPResponse:
        """Handle feature logout request"""
        return HASPResponse(
            status=0x00000000,  # STATUS_OK
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={"logout_time": int(time.time())},
            encryption_response=b'',
            expiry_info={},
            hardware_info={}
        )

    def _handle_heartbeat(self, request: HASPRequest) -> HASPResponse:
        """Handle heartbeat request"""
        if request.session_id in self.active_sessions:
            self.active_sessions[request.session_id]["last_heartbeat"] = time.time()
            status = 0x00000000  # STATUS_OK
        else:
            status = 0x00000010  # NOT_LOGGED_IN

        return HASPResponse(
            status=status,
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={"heartbeat_time": int(time.time())},
            encryption_response=b'',
            expiry_info={},
            hardware_info={}
        )

    def _handle_get_hardware_info(self, request: HASPRequest) -> HASPResponse:
        """Handle hardware info request"""
        return HASPResponse(
            status=0x00000000,  # STATUS_OK
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data=self.hardware_fingerprint,
            encryption_response=b'',
            expiry_info={},
            hardware_info=self.hardware_fingerprint
        )

    def _handle_unknown_command(self, request: HASPRequest) -> HASPResponse:
        """Handle unknown command"""
        self.logger.warning(f"Unknown HASP command: 0x{request.command:02X}")
        return HASPResponse(
            status=0x00000003,  # INV_SPEC
            session_id=request.session_id,
            feature_id=request.feature_id,
            license_data={},
            encryption_response=b'',
            expiry_info={},
            hardware_info={}
        )

    def serialize_response(self, response: HASPResponse) -> bytes:
        """
        Serialize HASP response to bytes

        Args:
            response: HASP response object

        Returns:
            Serialized response bytes
        """
        try:
            packet = bytearray()

            # Magic signature
            packet.extend(struct.pack('<I', 0x48415350))  # "HASP"

            # Status code
            packet.extend(struct.pack('<I', response.status))

            # Session ID
            packet.extend(struct.pack('<I', response.session_id))

            # Feature ID
            packet.extend(struct.pack('<I', response.feature_id))

            # License data (JSON)
            license_json = json.dumps(response.license_data).encode('utf-8')
            packet.extend(struct.pack('<H', len(license_json)))
            packet.extend(license_json)

            # Encryption response
            packet.extend(struct.pack('<H', len(response.encryption_response)))
            packet.extend(response.encryption_response)

            # Expiry info (JSON)
            expiry_json = json.dumps(response.expiry_info).encode('utf-8')
            packet.extend(struct.pack('<H', len(expiry_json)))
            packet.extend(expiry_json)

            # Hardware info (JSON)
            hardware_json = json.dumps(response.hardware_info).encode('utf-8')
            packet.extend(struct.pack('<H', len(hardware_json)))
            packet.extend(hardware_json)

            return bytes(packet)

        except Exception as e:
            self.logger.error(f"Failed to serialize HASP response: {e}")
            # Return minimal error response
            return struct.pack('<II', 0x48415350, response.status)
