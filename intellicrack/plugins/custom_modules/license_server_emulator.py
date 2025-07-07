#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
License Server Emulator

Comprehensive local license server emulator supporting multiple licensing
protocols including FlexLM, HASP, Microsoft KMS, Adobe, and custom vendor
systems. Provides offline license validation and fallback capabilities.

Author: Intellicrack Framework
Version: 2.0.0
License: GPL v3
"""

import hashlib
import json
import logging
import socket
import struct
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Optional, Tuple

import jwt
import uvicorn
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship, sessionmaker
from sqlalchemy.pool import StaticPool


class LicenseType(Enum):
    """License types supported"""
    FLEXLM = "flexlm"
    HASP = "hasp"
    MICROSOFT_KMS = "kms"
    ADOBE = "adobe"
    CUSTOM = "custom"
    TRIAL = "trial"
    PERPETUAL = "perpetual"
    SUBSCRIPTION = "subscription"


class LicenseStatus(Enum):
    """License status values"""
    VALID = "valid"
    EXPIRED = "expired"
    INVALID = "invalid"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    PENDING = "pending"


class ProtocolType(Enum):
    """Communication protocols supported"""
    HTTP_REST = "http_rest"
    HTTPS_REST = "https_rest"
    SOAP = "soap"
    TCP_SOCKET = "tcp_socket"
    UDP_DATAGRAM = "udp_datagram"
    NAMED_PIPE = "named_pipe"


@dataclass
class HardwareFingerprint:
    """Hardware fingerprint for license binding"""
    cpu_id: str = ""
    motherboard_id: str = ""
    disk_serial: str = ""
    mac_address: str = ""
    gpu_id: str = ""
    ram_size: int = 0
    os_version: str = ""
    hostname: str = ""

    def generate_hash(self) -> str:
        """Generate unique hash from hardware components"""
        data = f"{self.cpu_id}{self.motherboard_id}{self.disk_serial}{self.mac_address}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]


# Database Models
Base = declarative_base()


class LicenseEntry(Base):
    """License database entry"""
    __tablename__ = 'licenses'

    id = Column(Integer, primary_key=True)
    license_key = Column(String(255), unique=True, nullable=False)
    license_type = Column(String(50), nullable=False)
    product_name = Column(String(255), nullable=False)
    version = Column(String(50), nullable=False)
    status = Column(String(50), default="valid")
    created_date = Column(DateTime, default=datetime.utcnow)
    expiry_date = Column(DateTime, nullable=True)
    max_users = Column(Integer, default=1)
    current_users = Column(Integer, default=0)
    hardware_fingerprint = Column(String(255), nullable=True)
    custom_data = Column(Text, nullable=True)

    # Relationships
    activations = relationship("LicenseActivation", back_populates="license")


class LicenseActivation(Base):
    """License activation tracking"""
    __tablename__ = 'activations'

    id = Column(Integer, primary_key=True)
    license_id = Column(Integer, ForeignKey('licenses.id'), nullable=False)
    client_ip = Column(String(45), nullable=False)
    hardware_fingerprint = Column(String(255), nullable=False)
    activation_time = Column(DateTime, default=datetime.utcnow)
    last_checkin = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    user_agent = Column(String(255), nullable=True)

    # Relationships
    license = relationship("LicenseEntry", back_populates="activations")


class LicenseLog(Base):
    """License operation logging"""
    __tablename__ = 'license_logs'

    id = Column(Integer, primary_key=True)
    license_key = Column(String(255), nullable=False)
    operation = Column(String(100), nullable=False)
    client_ip = Column(String(45), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean, nullable=False)
    details = Column(Text, nullable=True)


# Pydantic Models for API
class LicenseRequest(BaseModel):
    """License validation request"""
    license_key: str = Field(..., description="License key to validate")
    product_name: str = Field(..., description="Product name")
    version: str = Field("1.0", description="Product version")
    hardware_fingerprint: Optional[str] = Field(None, description="Hardware fingerprint")
    client_info: Optional[Dict[str, Any]] = Field(default_factory=dict)


class LicenseResponse(BaseModel):
    """License validation response"""
    valid: bool = Field(..., description="License validity")
    status: str = Field(..., description="License status")
    expiry_date: Optional[datetime] = Field(None, description="License expiry")
    remaining_days: Optional[int] = Field(None, description="Days until expiry")
    max_users: int = Field(1, description="Maximum concurrent users")
    current_users: int = Field(0, description="Current active users")
    features: Dict[str, bool] = Field(default_factory=dict)
    message: str = Field("", description="Response message")


class ActivationRequest(BaseModel):
    """License activation request"""
    license_key: str = Field(..., description="License key")
    product_name: str = Field(..., description="Product name")
    hardware_fingerprint: str = Field(..., description="Hardware fingerprint")
    client_info: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ActivationResponse(BaseModel):
    """License activation response"""
    success: bool = Field(..., description="Activation success")
    activation_id: Optional[str] = Field(None, description="Activation ID")
    certificate: Optional[str] = Field(None, description="License certificate")
    message: str = Field("", description="Response message")


class CryptoManager:
    """Cryptographic operations for license generation and validation"""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.CryptoManager")

        # Generate RSA key pair for signing
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

        # AES encryption key for license data
        self.aes_key = hashlib.sha256(b"intellicrack_license_key_2024").digest()

    def generate_license_key(self, product: str, license_type: str) -> str:
        """Generate cryptographically secure license key"""
        # Create base data
        timestamp = int(time.time())
        random_data = uuid.uuid4().hex

        # Combine and hash
        data = f"{product}:{license_type}:{timestamp}:{random_data}"
        key_hash = hashlib.sha256(data.encode()).hexdigest()

        # Format as license key (XXXX-XXXX-XXXX-XXXX)
        formatted_key = "-".join([
            key_hash[i:i+4].upper()
            for i in range(0, 16, 4)
        ])

        return formatted_key

    def sign_license_data(self, data: Dict[str, Any]) -> str:
        """Sign license data with RSA private key"""
        try:
            json_data = json.dumps(data, sort_keys=True).encode()

            signature = self.private_key.sign(
                json_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return signature.hex()
        except Exception as e:
            self.logger.error(f"License signing failed: {e}")
            return ""

    def verify_license_signature(self, data: Dict[str, Any], signature: str) -> bool:
        """Verify license signature with RSA public key"""
        try:
            json_data = json.dumps(data, sort_keys=True).encode()
            signature_bytes = bytes.fromhex(signature)

            self.public_key.verify(
                signature_bytes,
                json_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return True
        except Exception:
            return False

    def encrypt_license_data(self, data: str) -> str:
        """Encrypt license data with AES"""
        try:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
            encryptor = cipher.encryptor()

            # Pad data to AES block size
            padded_data = data.encode()
            padding_length = 16 - (len(padded_data) % 16)
            padded_data += bytes([padding_length]) * padding_length

            encrypted = encryptor.update(padded_data) + encryptor.finalize()

            return (iv + encrypted).hex()
        except Exception as e:
            self.logger.error(f"License encryption failed: {e}")
            return ""

    def decrypt_license_data(self, encrypted_data: str) -> str:
        """Decrypt license data with AES"""
        try:
            data_bytes = bytes.fromhex(encrypted_data)
            iv = data_bytes[:16]
            encrypted = data_bytes[16:]

            cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()

            decrypted = decryptor.update(encrypted) + decryptor.finalize()

            # Remove padding
            padding_length = decrypted[-1]
            return decrypted[:-padding_length].decode()
        except Exception as e:
            self.logger.error(f"License decryption failed: {e}")
            return ""


class FlexLMEmulator:
    """FlexLM license server emulation"""

    def __init__(self, crypto_manager: CryptoManager):
        self.logger = logging.getLogger(f"{__name__}.FlexLM")
        self.crypto = crypto_manager
        self.server_socket = None
        self.running = False

        # FlexLM response codes
        self.SUCCESS = 0
        self.LICENSE_NOT_FOUND = 1
        self.LICENSE_EXPIRED = 2
        self.TOO_MANY_USERS = 3

    def start_server(self, port: int = 27000):
        """Start FlexLM TCP server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(5)

            self.running = True
            self.logger.info(f"FlexLM server started on port {port}")

            # Start accepting connections
            threading.Thread(target=self._accept_connections, daemon=True).start()

        except Exception as e:
            self.logger.error(f"FlexLM server start failed: {e}")

    def _accept_connections(self):
        """Accept FlexLM client connections"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                self.logger.info(f"FlexLM client connected: {address}")

                # Handle client in thread
                threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address),
                    daemon=True
                ).start()

            except Exception as e:
                if self.running:
                    self.logger.error(f"FlexLM connection error: {e}")

    def _handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle FlexLM client requests"""
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break

                # Parse FlexLM request (simplified)
                request = self._parse_flexlm_request(data)
                response = self._process_flexlm_request(request, address[0])

                client_socket.send(response)

        except Exception as e:
            self.logger.error(f"FlexLM client error: {e}")
        finally:
            client_socket.close()

    def _parse_flexlm_request(self, data: bytes) -> Dict[str, Any]:
        """Parse FlexLM protocol request"""
        try:
            # Simplified FlexLM parsing
            text = data.decode('ascii', errors='ignore')

            request = {
                'type': 'checkout',
                'feature': 'unknown',
                'version': '1.0',
                'user': 'anonymous',
                'host': 'localhost'
            }

            # Look for feature name
            if 'FEATURE' in text:
                parts = text.split()
                for i, part in enumerate(parts):
                    if part == 'FEATURE' and i + 1 < len(parts):
                        request['feature'] = parts[i + 1]
                        break

            return request

        except Exception:
            return {'type': 'unknown'}

    def _process_flexlm_request(self, request: Dict[str, Any], client_ip: str) -> bytes:
        """Process FlexLM request and generate response"""
        try:
            if request['type'] == 'checkout':
                # Always grant license (bypass)
                response_data = {
                    'status': self.SUCCESS,
                    'feature': request.get('feature', 'unknown'),
                    'expiry': '31-dec-2099',
                    'user_count': 1,
                    'max_users': 1000
                }

                # Format FlexLM response
                response = f"GRANTED: {response_data['feature']} {response_data['expiry']}\n"

                self.logger.info(f"FlexLM: Granted {request.get('feature')} to {client_ip}")

                return response.encode('ascii')

            else:
                # Unknown request
                return b"ERROR: Unknown request type\n"

        except Exception as e:
            self.logger.error(f"FlexLM request processing error: {e}")
            return b"ERROR: Internal server error\n"


class HASPEmulator:
    """HASP dongle emulation"""

    def __init__(self, crypto_manager: CryptoManager):
        self.logger = logging.getLogger(f"{__name__}.HASP")
        self.crypto = crypto_manager

        # HASP response codes
        self.HASP_STATUS_OK = 0
        self.HASP_FEATURE_NOT_FOUND = 7
        self.HASP_FEATURE_EXPIRED = 16

        # Simulated dongle memory
        self.dongle_memory = bytearray(4096)  # 4KB
        self._initialize_dongle_memory()

    def _initialize_dongle_memory(self):
        """Initialize dongle memory with default data"""
        # Write magic signature
        self.dongle_memory[0:4] = b'HASP'

        # Write version
        self.dongle_memory[4:8] = struct.pack('<I', 0x01000000)

        # Write features (simplified)
        for i in range(10):
            offset = 16 + (i * 16)
            # Feature ID
            self.dongle_memory[offset:offset+4] = struct.pack('<I', i + 1)
            # Expiry date (far future)
            self.dongle_memory[offset+4:offset+8] = struct.pack('<I', 0x7FFFFFFF)
            # Usage count
            self.dongle_memory[offset+8:offset+12] = struct.pack('<I', 0)

    def hasp_login(self, feature_id: int, vendor_code: bytes = b'\\x00' * 16) -> int:
        """HASP login operation"""
        try:
            self.logger.info(f"HASP login: feature {feature_id}")

            # Always succeed (bypass)
            return self.HASP_STATUS_OK

        except Exception as e:
            self.logger.error(f"HASP login error: {e}")
            return self.HASP_FEATURE_NOT_FOUND

    def hasp_logout(self, handle: int) -> int:
        """HASP logout operation"""
        self.logger.info(f"HASP logout: handle {handle}")
        return self.HASP_STATUS_OK

    def hasp_encrypt(self, handle: int, data: bytes) -> Tuple[int, bytes]:
        """HASP encrypt operation"""
        try:
            # Fake encryption (just XOR with 0xAA)
            encrypted = bytes(b ^ 0xAA for b in data)

            self.logger.info(f"HASP encrypt: {len(data)} bytes")

            return self.HASP_STATUS_OK, encrypted

        except Exception as e:
            self.logger.error(f"HASP encrypt error: {e}")
            return self.HASP_FEATURE_NOT_FOUND, b''

    def hasp_decrypt(self, handle: int, data: bytes) -> Tuple[int, bytes]:
        """HASP decrypt operation"""
        try:
            # Fake decryption (reverse XOR)
            decrypted = bytes(b ^ 0xAA for b in data)

            self.logger.info(f"HASP decrypt: {len(data)} bytes")

            return self.HASP_STATUS_OK, decrypted

        except Exception as e:
            self.logger.error(f"HASP decrypt error: {e}")
            return self.HASP_FEATURE_NOT_FOUND, b''

    def hasp_read(self, handle: int, offset: int, length: int) -> Tuple[int, bytes]:
        """HASP memory read operation"""
        try:
            if offset + length > len(self.dongle_memory):
                return self.HASP_FEATURE_NOT_FOUND, b''

            data = bytes(self.dongle_memory[offset:offset + length])

            self.logger.info(f"HASP read: offset {offset}, length {length}")

            return self.HASP_STATUS_OK, data

        except Exception as e:
            self.logger.error(f"HASP read error: {e}")
            return self.HASP_FEATURE_NOT_FOUND, b''

    def hasp_write(self, handle: int, offset: int, data: bytes) -> int:
        """HASP memory write operation"""
        try:
            if offset + len(data) > len(self.dongle_memory):
                return self.HASP_FEATURE_NOT_FOUND

            self.dongle_memory[offset:offset + len(data)] = data

            self.logger.info(f"HASP write: offset {offset}, length {len(data)}")

            return self.HASP_STATUS_OK

        except Exception as e:
            self.logger.error(f"HASP write error: {e}")
            return self.HASP_FEATURE_NOT_FOUND


class MicrosoftKMSEmulator:
    """Microsoft KMS server emulation"""

    def __init__(self, crypto_manager: CryptoManager):
        self.logger = logging.getLogger(f"{__name__}.KMS")
        self.crypto = crypto_manager

        # KMS product keys (simplified)
        self.kms_keys = {
            'Windows 10 Pro': 'W269N-WFGWX-YVC9B-4J6C9-T83GX',
            'Windows 10 Enterprise': 'NPPR9-FWDCX-D2C8J-H872K-2YT43',
            'Windows Server 2019': 'N69G4-B89J2-4G8F4-WWYCC-J464C',
            'Office 2019 Professional': 'NMMKJ-6RK4F-KMJVX-8D9MJ-6MWKP'
        }

    def activate_product(self, product_key: str, product_name: str, client_info: Dict[str, Any]) -> Dict[str, Any]:
        """Activate Microsoft product"""
        try:
            self.logger.info(f"KMS activation: {product_name}")

            # Generate activation response
            response = {
                'success': True,
                'activation_id': uuid.uuid4().hex,
                'product_key': product_key,
                'product_name': product_name,
                'license_status': 'Licensed',
                'remaining_grace_time': 180,  # Days
                'kms_server': 'intellicrack-kms.local',
                'kms_port': 1688,
                'last_activation': datetime.utcnow().isoformat(),
                'next_activation': (datetime.utcnow() + timedelta(days=180)).isoformat()
            }

            return response

        except Exception as e:
            self.logger.error(f"KMS activation error: {e}")
            return {'success': False, 'error': str(e)}


import os


class AdobeEmulator:
    """Adobe license server emulation"""

    def __init__(self, crypto_manager: CryptoManager):
        self.logger = logging.getLogger(f"{__name__}.Adobe")
        self.crypto = crypto_manager

        # Adobe product configurations
        self.adobe_products = {
            'Photoshop': {'id': 'PHSP', 'version': '2024'},
            'Illustrator': {'id': 'ILST', 'version': '2024'},
            'Premiere Pro': {'id': 'PPRO', 'version': '2024'},
            'After Effects': {'id': 'AEFT', 'version': '2024'},
            'InDesign': {'id': 'IDSN', 'version': '2024'},
            'Acrobat Pro': {'id': 'ACRO', 'version': '2024'}
        }

    def validate_adobe_license(self, product_id: str, user_id: str, machine_id: str) -> Dict[str, Any]:
        """Validate Adobe Creative Cloud license"""
        try:
            self.logger.info(f"Adobe validation: {product_id} for user {user_id}")

            # Generate Adobe-style response
            response = {
                'status': 'success',
                'license_type': 'subscription',
                'product_id': product_id,
                'user_id': user_id,
                'machine_id': machine_id,
                'subscription_status': 'active',
                'expiry_date': (datetime.utcnow() + timedelta(days=365)).isoformat(),
                'features': {
                    'cloud_sync': True,
                    'fonts': True,
                    'stock': True,
                    'behance': True
                },
                'server_time': datetime.utcnow().isoformat(),
                'ngl_token': self._generate_ngl_token(product_id, user_id)
            }

            return response

        except Exception as e:
            self.logger.error(f"Adobe validation error: {e}")
            return {'status': 'error', 'message': str(e)}

    def _generate_ngl_token(self, product_id: str, user_id: str) -> str:
        """Generate Adobe NGL (licensing) token"""
        token_data = {
            'pid': product_id,
            'uid': user_id,
            'exp': int((datetime.utcnow() + timedelta(days=30)).timestamp()),
            'iat': int(datetime.utcnow().timestamp()),
            'iss': 'intellicrack-adobe-emulator'
        }

        # Sign with secret key
        secret = "adobe_ngl_secret_2024"
        token = jwt.encode(token_data, secret, algorithm='HS256')

        return token


class DatabaseManager:
    """Database operations for license management"""

    def __init__(self, db_path: str = "license_server.db"):
        self.logger = logging.getLogger(f"{__name__}.Database")
        self.db_path = db_path

        # Create SQLite engine
        self.engine = create_engine(
            f"sqlite:///{db_path}",
            poolclass=StaticPool,
            connect_args={'check_same_thread': False}
        )

        # Create session factory
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

        # Create tables
        self._create_tables()
        self._seed_default_licenses()

    def _create_tables(self):
        """Create database tables"""
        try:
            Base.metadata.create_all(bind=self.engine)
            self.logger.info("Database tables created successfully")
        except Exception as e:
            self.logger.error(f"Database table creation failed: {e}")

    def _seed_default_licenses(self):
        """Seed database with default licenses"""
        try:
            db = self.SessionLocal()

            # Check if licenses already exist
            if db.query(LicenseEntry).count() > 0:
                db.close()
                return

            # Create default licenses
            default_licenses = [
                {
                    'license_key': 'FLEX-1234-5678-9ABC',
                    'license_type': 'flexlm',
                    'product_name': 'FlexLM Test Product',
                    'version': '1.0',
                    'expiry_date': datetime.utcnow() + timedelta(days=365),
                    'max_users': 100
                },
                {
                    'license_key': 'HASP-ABCD-EFGH-IJKL',
                    'license_type': 'hasp',
                    'product_name': 'HASP Protected Software',
                    'version': '2.0',
                    'expiry_date': datetime.utcnow() + timedelta(days=365),
                    'max_users': 50
                },
                {
                    'license_key': 'KMS-2024-WXYZ-1234',
                    'license_type': 'kms',
                    'product_name': 'Windows 10 Pro',
                    'version': '2004',
                    'expiry_date': datetime.utcnow() + timedelta(days=180),
                    'max_users': 1000
                },
                {
                    'license_key': 'ADOBE-CC-2024-5678',
                    'license_type': 'adobe',
                    'product_name': 'Adobe Creative Cloud',
                    'version': '2024',
                    'expiry_date': datetime.utcnow() + timedelta(days=365),
                    'max_users': 10
                }
            ]

            for license_data in default_licenses:
                license_entry = LicenseEntry(**license_data)
                db.add(license_entry)

            db.commit()
            db.close()

            self.logger.info("Default licenses seeded successfully")

        except Exception as e:
            self.logger.error(f"License seeding failed: {e}")

    def get_db(self) -> Session:
        """Get database session"""
        db = self.SessionLocal()
        try:
            return db
        finally:
            pass  # Session will be closed by caller

    def validate_license(self, license_key: str, product_name: str) -> Optional[LicenseEntry]:
        """Validate license in database"""
        try:
            db = self.SessionLocal()

            license_entry = db.query(LicenseEntry).filter(
                LicenseEntry.license_key == license_key,
                LicenseEntry.product_name == product_name
            ).first()

            db.close()
            return license_entry

        except Exception as e:
            self.logger.error(f"License validation error: {e}")
            return None

    def log_operation(self, license_key: str, operation: str, client_ip: str, success: bool, details: str = ""):
        """Log license operation"""
        try:
            db = self.SessionLocal()

            log_entry = LicenseLog(
                license_key=license_key,
                operation=operation,
                client_ip=client_ip,
                success=success,
                details=details
            )

            db.add(log_entry)
            db.commit()
            db.close()

        except Exception as e:
            self.logger.error(f"Operation logging failed: {e}")


class HardwareFingerprintGenerator:
    """Generate hardware fingerprints for license binding"""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.Fingerprint")

    def generate_fingerprint(self) -> HardwareFingerprint:
        """Generate hardware fingerprint from system"""
        try:
            import platform

            import psutil
            import wmi

            fingerprint = HardwareFingerprint()

            # Get CPU info
            try:
                c = wmi.WMI()
                for cpu in c.Win32_Processor():
                    fingerprint.cpu_id = cpu.ProcessorId or ""
                    break
            except Exception:
                fingerprint.cpu_id = "unknown_cpu"

            # Get motherboard info
            try:
                for board in c.Win32_BaseBoard():
                    fingerprint.motherboard_id = board.SerialNumber or ""
                    break
            except Exception:
                fingerprint.motherboard_id = "unknown_board"

            # Get disk serial
            try:
                for disk in c.Win32_LogicalDisk():
                    if disk.DriveType == 3:  # Fixed disk
                        fingerprint.disk_serial = disk.VolumeSerialNumber or ""
                        break
            except Exception:
                fingerprint.disk_serial = "unknown_disk"

            # Get MAC address
            try:
                import uuid
                fingerprint.mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                                                   for ele in range(0,8*6,8)][::-1])
            except Exception:
                fingerprint.mac_address = "unknown_mac"

            # Get RAM size
            try:
                fingerprint.ram_size = int(psutil.virtual_memory().total / (1024**3))  # GB
            except Exception:
                fingerprint.ram_size = 0

            # Get OS version
            try:
                fingerprint.os_version = platform.platform()
            except Exception:
                fingerprint.os_version = "unknown_os"

            # Get hostname
            try:
                fingerprint.hostname = socket.gethostname()
            except Exception:
                fingerprint.hostname = "unknown_host"

            return fingerprint

        except Exception as e:
            self.logger.error(f"Fingerprint generation failed: {e}")
            # Return dummy fingerprint
            return HardwareFingerprint(
                cpu_id="dummy_cpu",
                motherboard_id="dummy_board",
                disk_serial="dummy_disk",
                mac_address="00:00:00:00:00:00",
                ram_size=8,
                os_version="Windows 10",
                hostname="test-machine"
            )


class LicenseServerEmulator:
    """Main license server emulator class"""

    def __init__(self, config: Dict[str, Any] = None):
        self.logger = logging.getLogger(f"{__name__}.Server")

        # Default configuration
        self.config = {
            'host': '0.0.0.0',
            'port': 8080,
            'ssl_enabled': False,
            'ssl_cert': None,
            'ssl_key': None,
            'database_path': 'license_server.db',
            'flexlm_port': 27000,
            'kms_port': 1688,
            'log_level': 'INFO',
            'enable_cors': True,
            'auth_required': False
        }

        if config:
            self.config.update(config)

        # Initialize components
        self.crypto = CryptoManager()
        self.db_manager = DatabaseManager(self.config['database_path'])
        self.flexlm = FlexLMEmulator(self.crypto)
        self.hasp = HASPEmulator(self.crypto)
        self.kms = MicrosoftKMSEmulator(self.crypto)
        self.adobe = AdobeEmulator(self.crypto)
        self.fingerprint_gen = HardwareFingerprintGenerator()

        # FastAPI app
        self.app = FastAPI(
            title="Intellicrack License Server Emulator",
            description="Comprehensive license server emulation for multiple protection systems",
            version="2.0.0"
        )

        # Setup FastAPI
        self._setup_middleware()
        self._setup_routes()

        # Security
        self.security = HTTPBearer() if self.config['auth_required'] else None

        self.logger.info("License server emulator initialized")

    def _setup_middleware(self):
        """Setup FastAPI middleware"""
        if self.config['enable_cors']:
            self.app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )

    def _setup_routes(self):
        """Setup FastAPI routes"""

        @self.app.get("/")
        async def root():
            return {"message": "Intellicrack License Server Emulator v2.0.0", "status": "running"}

        @self.app.get("/health")
        async def health_check():
            return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

        @self.app.post("/api/v1/license/validate", response_model=LicenseResponse)
        async def validate_license(request: LicenseRequest, client_request: Request):
            return await self._handle_license_validation(request, client_request)

        @self.app.post("/api/v1/license/activate", response_model=ActivationResponse)
        async def activate_license(request: ActivationRequest, client_request: Request):
            return await self._handle_license_activation(request, client_request)

        @self.app.get("/api/v1/license/{license_key}/status")
        async def get_license_status(license_key: str):
            return await self._handle_license_status(license_key)

        @self.app.post("/api/v1/flexlm/checkout")
        async def flexlm_checkout(request: Dict[str, Any], client_request: Request):
            return await self._handle_flexlm_request(request, client_request)

        @self.app.post("/api/v1/hasp/login")
        async def hasp_login(request: Dict[str, Any]):
            return await self._handle_hasp_request(request)

        @self.app.post("/api/v1/kms/activate")
        async def kms_activate(request: Dict[str, Any], client_request: Request):
            return await self._handle_kms_request(request, client_request)

        @self.app.post("/api/v1/adobe/validate")
        async def adobe_validate(request: Dict[str, Any], client_request: Request):
            return await self._handle_adobe_request(request, client_request)

        @self.app.get("/api/v1/fingerprint/generate")
        async def generate_fingerprint():
            fingerprint = self.fingerprint_gen.generate_fingerprint()
            return {
                "fingerprint": fingerprint.generate_hash(),
                "details": {
                    "cpu_id": fingerprint.cpu_id[:8] + "...",  # Truncate for privacy
                    "hostname": fingerprint.hostname,
                    "ram_size": fingerprint.ram_size,
                    "os_version": fingerprint.os_version
                }
            }

    async def _handle_license_validation(self, request: LicenseRequest, client_request: Request) -> LicenseResponse:
        """Handle license validation request"""
        try:
            client_ip = client_request.client.host

            # Log the request
            self.db_manager.log_operation(
                request.license_key,
                "validate",
                client_ip,
                True,
                f"Product: {request.product_name}"
            )

            # Check database first
            license_entry = self.db_manager.validate_license(request.license_key, request.product_name)

            if license_entry:
                # Calculate remaining days
                remaining_days = None
                if license_entry.expiry_date:
                    remaining_days = (license_entry.expiry_date - datetime.utcnow()).days

                response = LicenseResponse(
                    valid=license_entry.status == "valid",
                    status=license_entry.status,
                    expiry_date=license_entry.expiry_date,
                    remaining_days=remaining_days,
                    max_users=license_entry.max_users,
                    current_users=license_entry.current_users,
                    features={"all": True},
                    message="License validated successfully"
                )
            else:
                # Create bypass license (always valid)
                response = LicenseResponse(
                    valid=True,
                    status="valid",
                    expiry_date=datetime.utcnow() + timedelta(days=365),
                    remaining_days=365,
                    max_users=1000,
                    current_users=1,
                    features={"all": True},
                    message="License bypassed - validation successful"
                )

            self.logger.info(f"License validation: {request.license_key} -> {response.status}")

            return response

        except Exception as e:
            self.logger.error(f"License validation error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    async def _handle_license_activation(self, request: ActivationRequest, client_request: Request) -> ActivationResponse:
        """Handle license activation request"""
        try:
            client_ip = client_request.client.host

            # Always succeed activation (bypass)
            activation_id = uuid.uuid4().hex

            # Generate certificate
            cert_data = {
                'license_key': request.license_key,
                'product_name': request.product_name,
                'hardware_fingerprint': request.hardware_fingerprint,
                'activation_id': activation_id,
                'timestamp': datetime.utcnow().isoformat()
            }

            certificate = self.crypto.sign_license_data(cert_data)

            # Log activation
            self.db_manager.log_operation(
                request.license_key,
                "activate",
                client_ip,
                True,
                f"Activation ID: {activation_id}"
            )

            response = ActivationResponse(
                success=True,
                activation_id=activation_id,
                certificate=certificate,
                message="License activated successfully"
            )

            self.logger.info(f"License activation: {request.license_key} -> {activation_id}")

            return response

        except Exception as e:
            self.logger.error(f"License activation error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    async def _handle_license_status(self, license_key: str) -> Dict[str, Any]:
        """Handle license status request"""
        try:
            license_entry = self.db_manager.validate_license(license_key, "")

            if license_entry:
                return {
                    "license_key": license_key,
                    "status": license_entry.status,
                    "product_name": license_entry.product_name,
                    "version": license_entry.version,
                    "expiry_date": license_entry.expiry_date.isoformat() if license_entry.expiry_date else None,
                    "max_users": license_entry.max_users,
                    "current_users": license_entry.current_users
                }
            else:
                # Return bypass status
                return {
                    "license_key": license_key,
                    "status": "valid",
                    "product_name": "Unknown Product",
                    "version": "1.0",
                    "expiry_date": (datetime.utcnow() + timedelta(days=365)).isoformat(),
                    "max_users": 1000,
                    "current_users": 1
                }

        except Exception as e:
            self.logger.error(f"License status error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    async def _handle_flexlm_request(self, request: Dict[str, Any], client_request: Request) -> Dict[str, Any]:
        """Handle FlexLM license request"""
        try:
            feature = request.get('feature', 'unknown')
            version = request.get('version', '1.0')

            # Always grant license
            response = {
                'status': 'granted',
                'feature': feature,
                'version': version,
                'expiry': '31-dec-2099',
                'server': 'intellicrack-flexlm',
                'port': self.config['flexlm_port']
            }

            self.logger.info(f"FlexLM request: {feature} -> granted")

            return response

        except Exception as e:
            self.logger.error(f"FlexLM request error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    async def _handle_hasp_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle HASP dongle request"""
        try:
            operation = request.get('operation', 'login')
            feature_id = request.get('feature_id', 1)

            if operation == 'login':
                status = self.hasp.hasp_login(feature_id)
                return {'status': status, 'handle': 12345 if status == 0 else 0}
            elif operation == 'encrypt':
                data = request.get('data', b'')
                status, encrypted = self.hasp.hasp_encrypt(12345, data.encode())
                return {'status': status, 'data': encrypted.hex()}
            elif operation == 'decrypt':
                data = request.get('data', '')
                status, decrypted = self.hasp.hasp_decrypt(12345, bytes.fromhex(data))
                return {'status': status, 'data': decrypted.decode()}
            else:
                return {'status': 0, 'message': 'Operation successful'}

        except Exception as e:
            self.logger.error(f"HASP request error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    async def _handle_kms_request(self, request: Dict[str, Any], client_request: Request) -> Dict[str, Any]:
        """Handle Microsoft KMS activation request"""
        try:
            product_key = request.get('product_key', '')
            product_name = request.get('product_name', 'Windows')
            client_info = request.get('client_info', {})

            response = self.kms.activate_product(product_key, product_name, client_info)

            self.logger.info(f"KMS activation: {product_name} -> success")

            return response

        except Exception as e:
            self.logger.error(f"KMS request error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    async def _handle_adobe_request(self, request: Dict[str, Any], client_request: Request) -> Dict[str, Any]:
        """Handle Adobe license validation request"""
        try:
            product_id = request.get('product_id', 'PHSP')
            user_id = request.get('user_id', 'user@example.com')
            machine_id = request.get('machine_id', 'machine-123')

            response = self.adobe.validate_adobe_license(product_id, user_id, machine_id)

            self.logger.info(f"Adobe validation: {product_id} -> success")

            return response

        except Exception as e:
            self.logger.error(f"Adobe request error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    def start_servers(self):
        """Start all license servers"""
        try:
            # Start FlexLM server
            self.flexlm.start_server(self.config['flexlm_port'])

            # Start main HTTP server
            if self.config['ssl_enabled'] and self.config['ssl_cert'] and self.config['ssl_key']:
                uvicorn.run(
                    self.app,
                    host=self.config['host'],
                    port=self.config['port'],
                    ssl_certfile=self.config['ssl_cert'],
                    ssl_keyfile=self.config['ssl_key'],
                    log_level=self.config['log_level'].lower()
                )
            else:
                uvicorn.run(
                    self.app,
                    host=self.config['host'],
                    port=self.config['port'],
                    log_level=self.config['log_level'].lower()
                )

        except Exception as e:
            self.logger.error(f"Server startup failed: {e}")
            raise


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Intellicrack License Server Emulator")
    parser.add_argument("--host", default="0.0.0.0", help="Server host")
    parser.add_argument("--port", type=int, default=8080, help="Server port")
    parser.add_argument("--flexlm-port", type=int, default=27000, help="FlexLM port")
    parser.add_argument("--ssl-cert", help="SSL certificate file")
    parser.add_argument("--ssl-key", help="SSL private key file")
    parser.add_argument("--db-path", default="license_server.db", help="Database path")
    parser.add_argument("--log-level", default="INFO", help="Log level")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Server configuration
    config = {
        'host': args.host,
        'port': args.port,
        'flexlm_port': args.flexlm_port,
        'database_path': args.db_path,
        'log_level': args.log_level,
        'ssl_enabled': bool(args.ssl_cert and args.ssl_key),
        'ssl_cert': args.ssl_cert,
        'ssl_key': args.ssl_key
    }

    # Create and start server
    server = LicenseServerEmulator(config)

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║              Intellicrack License Server Emulator           ║
║                         Version 2.0.0                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTP Server:    http://{args.host}:{args.port}                           ║
║ FlexLM Server:  TCP port {args.flexlm_port}                           ║
║ Database:       {args.db_path}                               ║
║ Log Level:      {args.log_level}                            ║
╚══════════════════════════════════════════════════════════════╝

Starting license server emulator...
""")

    try:
        server.start_servers()
    except KeyboardInterrupt:
        print("\nShutting down license server emulator...")
    except Exception as e:
        print(f"Server error: {e}")


if __name__ == "__main__":
    main()
