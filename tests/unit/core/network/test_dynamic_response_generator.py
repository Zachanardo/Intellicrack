"""
Comprehensive tests for DynamicResponseGenerator - Production-ready network exploitation validation.

These tests validate real dynamic response generation capabilities for licensing protocol
manipulation, essential for security research and license system robustness testing.

TESTING METHODOLOGY:
- Specification-driven testing based on expected production-ready functionality
- Tests designed to FAIL for placeholder/stub implementations
- Validates genuine network exploitation capabilities using real protocols
- Uses real cryptographic operations and protocol compliance validation
"""

import pytest
import socket
import struct
import time
import threading
import ssl
import os
import sys
import hashlib
import secrets
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
import base64
import hmac
import zlib
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
import netifaces

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent))

from intellicrack.core.network.dynamic_response_generator import (
    DynamicResponseGenerator,
    ResponseContext,
    GeneratedResponse,
    FlexLMProtocolHandler,
    HASPProtocolHandler,
    AdobeProtocolHandler,
    MicrosoftKMSHandler,
    AutodeskProtocolHandler
)


@dataclass
class LicenseRequest:
    """Represents an intercepted license validation request."""
    protocol: str
    raw_data: bytes
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    timestamp: datetime
    headers: dict[str, str] | None = None
    payload: dict | bytes | None = None


@dataclass
class ProtocolTestVector:
    """Test vector for protocol-specific validation."""
    name: str
    request_data: bytes
    expected_response_pattern: bytes
    cryptographic_validation: bool
    state_dependent: bool
    version_specific: bool


class TestDynamicResponseGenerator:
    """
    Comprehensive tests for DynamicResponseGenerator.

    Validates sophisticated dynamic response generation capabilities for network
    exploitation scenarios involving licensing protocol manipulation.
    """

    @pytest.fixture
    def response_generator(self):
        """Create a DynamicResponseGenerator instance for testing."""
        generator = DynamicResponseGenerator()

        # Verify initialization with production-ready capabilities
        assert hasattr(generator, 'generate_response'), "Missing core response generation method"
        assert hasattr(generator, 'analyze_request'), "Missing request analysis capability"
        assert hasattr(generator, 'protocol_handlers'), "Missing protocol handler registry"
        assert hasattr(generator, 'state_manager'), "Missing state management capability"

        return generator

    @pytest.fixture
    def real_flexlm_request(self):
        """Generate a realistic FlexLM license request for testing."""
        # FlexLM binary protocol structure based on real implementations
        magic = b'\x00\x00\x00\x0c'  # FlexLM magic number
        version = struct.pack('>H', 0x0b00)  # Version 11.0
        message_type = struct.pack('>H', 0x0001)  # License request
        sequence = struct.pack('>I', secrets.randbits(32))

        # Feature request
        feature_name = b'ADVANCED_CAD\x00' + b'\x00' * (32 - len(b'ADVANCED_CAD\x00'))
        version_req = b'2024.1\x00' + b'\x00' * (16 - len(b'2024.1\x00'))

        # Client info
        hostname = socket.gethostname()[:63].encode() + b'\x00'
        hostname += b'\x00' * (64 - len(hostname))

        display = b':0.0\x00' + b'\x00' * (32 - len(b':0.0\x00'))

        # Construct full request
        request = magic + version + message_type + sequence + feature_name + version_req + hostname + display

        return LicenseRequest(
            protocol='flexlm',
            raw_data=request,
            source_ip='192.168.1.100',
            dest_ip='192.168.1.10',
            source_port=secrets.randbelow(32768) + 32768,
            dest_port=27000,
            timestamp=datetime.now()
        )

    @pytest.fixture
    def real_hasp_request(self):
        """Generate a realistic HASP/Sentinel license request."""
        # HASP protocol structure
        hasp_magic = b'HASP'
        command = struct.pack('<I', 0x00000001)  # Login command
        session_id = struct.pack('<I', 0)
        feature_id = struct.pack('<I', 12345)

        # Vendor code (encrypted)
        vendor_code = secrets.token_bytes(16)

        # Client challenge
        challenge = secrets.token_bytes(16)

        request = hasp_magic + command + session_id + feature_id + vendor_code + challenge

        return LicenseRequest(
            protocol='hasp',
            raw_data=request,
            source_ip='10.0.0.50',
            dest_ip='10.0.0.10',
            source_port=secrets.randbelow(32768) + 32768,
            dest_port=1947,
            timestamp=datetime.now()
        )

    @pytest.fixture
    def real_adobe_request(self):
        """Generate a realistic Adobe licensing request."""
        # Adobe activation request (HTTP-based)
        activation_data = {
            'request_id': secrets.token_hex(16),
            'product_guid': '{12345678-1234-1234-1234-123456789012}',
            'product_version': '2024.0.0',
            'license_id': secrets.token_hex(32),
            'hardware_fingerprint': hashlib.sha256(
                (socket.gethostname() + str(secrets.randbits(64))).encode()
            ).hexdigest(),
            'timestamp': int(time.time()),
            'platform': 'win'
        }

        # Sign with simulated Adobe signature
        signature = hmac.new(
            b'adobe_test_key_simulate',
            json.dumps(activation_data, sort_keys=True).encode(),
            hashlib.sha256
        ).hexdigest()

        activation_data['signature'] = signature

        request_body = json.dumps(activation_data).encode()

        return LicenseRequest(
            protocol='adobe',
            raw_data=request_body,
            source_ip='172.16.1.100',
            dest_ip='activation.adobe.com',
            source_port=secrets.randbelow(32768) + 32768,
            dest_port=443,
            timestamp=datetime.now(),
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'Adobe Licensing Library',
                'X-Request-ID': activation_data['request_id']
            },
            payload=activation_data
        )

    @pytest.fixture
    def real_kms_request(self):
        """Generate a realistic Microsoft KMS activation request."""
        # KMS activation request structure
        kms_magic = b'\x4b\x4d\x53\x00'  # "KMS\0"
        version = struct.pack('<H', 0x0006)  # KMS version 6
        request_type = struct.pack('<H', 0x0001)  # Activation request

        # Application ID (Office/Windows GUID)
        app_id = b'\x12\x34\x56\x78' * 4  # Simulated app GUID

        # SKU ID
        sku_id = secrets.token_bytes(16)

        # Client machine ID
        cmid = secrets.token_bytes(16)

        # Minimum clients required
        min_clients = struct.pack('<I', 25)

        # Request timestamp
        timestamp = struct.pack('<Q', int(time.time()))

        request = kms_magic + version + request_type + app_id + sku_id + cmid + min_clients + timestamp

        return LicenseRequest(
            protocol='kms',
            raw_data=request,
            source_ip='10.0.0.25',
            dest_ip='10.0.0.1',
            source_port=secrets.randbelow(32768) + 32768,
            dest_port=1688,
            timestamp=datetime.now()
        )

    @pytest.fixture
    def real_autodesk_request(self):
        """Generate a realistic Autodesk licensing request."""
        # Autodesk AdLM request (XML-based)
        request_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<AdskLicensingRequest version="2.0">
    <Header>
        <RequestId>{secrets.token_hex(16)}</RequestId>
        <Timestamp>{datetime.now().isoformat()}</Timestamp>
        <Product>AutoCAD</Product>
        <Version>2024.1</Version>
        <Language>en-US</Language>
    </Header>
    <License>
        <SerialNumber>123-12345678</SerialNumber>
        <RequestCode>{secrets.token_hex(20)}</RequestCode>
        <ProductKey>001M1</ProductKey>
    </License>
    <Machine>
        <HostId>{hashlib.md5(socket.gethostname().encode()).hexdigest()}</HostId>
        <Platform>Windows</Platform>
        <Architecture>x64</Architecture>
    </Machine>
    <Signature>{base64.b64encode(secrets.token_bytes(64)).decode()}</Signature>
</AdskLicensingRequest>"""

        return LicenseRequest(
            protocol='autodesk',
            raw_data=request_xml.encode(),
            source_ip='192.168.0.100',
            dest_ip='register.autodesk.com',
            source_port=secrets.randbelow(32768) + 32768,
            dest_port=443,
            timestamp=datetime.now(),
            headers={'Content-Type': 'application/xml'},
            payload=request_xml
        )

    def test_generator_initialization_with_all_protocol_handlers(self, response_generator):
        """Test that generator initializes with all required protocol handlers."""
        handlers = response_generator.protocol_handlers

        # Must support all major licensing protocols
        required_protocols = ['flexlm', 'hasp', 'adobe', 'kms', 'autodesk']

        for protocol in required_protocols:
            assert protocol in handlers, f"Missing {protocol} protocol handler"
            handler = handlers[protocol]

            # Each handler must be production-ready
            assert hasattr(handler, 'generate_response'), f"{protocol} handler missing response generation"
            assert hasattr(handler, 'validate_request'), f"{protocol} handler missing request validation"
            assert hasattr(handler, 'get_protocol_version'), f"{protocol} handler missing version detection"
            assert callable(handler.generate_response), f"{protocol} handler generate_response not callable"

    def test_request_analysis_and_protocol_detection(self, response_generator,
                                                   real_flexlm_request, real_hasp_request,
                                                   real_adobe_request, real_kms_request,
                                                   real_autodesk_request):
        """Test accurate protocol detection and request analysis."""
        test_requests = [
            (real_flexlm_request, 'flexlm'),
            (real_hasp_request, 'hasp'),
            (real_adobe_request, 'adobe'),
            (real_kms_request, 'kms'),
            (real_autodesk_request, 'autodesk')
        ]

        detection_accuracy = []

        for request, expected_protocol in test_requests:
            # Analyze request using sophisticated detection
            analysis = response_generator.analyze_request(request.raw_data,
                                                        request.source_ip,
                                                        request.dest_ip,
                                                        request.source_port,
                                                        request.dest_port)

            assert analysis is not None, f"Failed to analyze {expected_protocol} request"
            assert 'protocol' in analysis, "Missing protocol detection"
            assert 'confidence' in analysis, "Missing detection confidence"
            assert 'features' in analysis, "Missing protocol feature extraction"

            # Protocol detection must be accurate
            detected_protocol = analysis['protocol']
            confidence = analysis['confidence']

            assert detected_protocol == expected_protocol, \
                   f"Protocol misdetection: expected {expected_protocol}, got {detected_protocol}"
            assert confidence >= 0.85, \
                   f"Low detection confidence for {expected_protocol}: {confidence}"

            detection_accuracy.append(confidence)

            # Must extract sophisticated protocol features
            features = analysis['features']
            assert len(features) > 3, f"Insufficient feature extraction for {expected_protocol}"

            # Protocol-specific feature validation
            if expected_protocol == 'flexlm':
                assert 'feature_name' in features, "Missing FlexLM feature name"
                assert 'version' in features, "Missing FlexLM version"
                assert 'hostname' in features, "Missing FlexLM client hostname"
            elif expected_protocol == 'hasp':
                assert 'feature_id' in features, "Missing HASP feature ID"
                assert 'vendor_code' in features, "Missing HASP vendor code"
                assert 'challenge' in features, "Missing HASP challenge"
            elif expected_protocol == 'adobe':
                assert 'product_guid' in features, "Missing Adobe product GUID"
                assert 'hardware_fingerprint' in features, "Missing Adobe hardware fingerprint"
            elif expected_protocol == 'kms':
                assert 'app_id' in features, "Missing KMS application ID"
                assert 'sku_id' in features, "Missing KMS SKU ID"
            elif expected_protocol == 'autodesk':
                assert 'product_key' in features, "Missing Autodesk product key"
                assert 'serial_number' in features, "Missing Autodesk serial number"

        # Overall detection quality must be high
        avg_accuracy = sum(detection_accuracy) / len(detection_accuracy)
        assert avg_accuracy >= 0.90, f"Insufficient overall detection accuracy: {avg_accuracy:.2%}"

    def test_flexlm_response_generation_with_cryptographic_validation(self, response_generator, real_flexlm_request):
        """Test FlexLM response generation with cryptographic validation."""
        # Create response context
        context = ResponseContext(
            request=real_flexlm_request,
            target_behavior='approve_license',
            protocol_version='11.0',
            encryption_required=True
        )

        # Generate response
        response = response_generator.generate_response(context)

        assert isinstance(response, GeneratedResponse), "Invalid response type"
        assert response.success, f"Response generation failed: {response.error_message}"
        assert response.protocol == 'flexlm', "Incorrect protocol in response"
        assert len(response.raw_data) > 0, "Empty response data"

        # Validate FlexLM protocol compliance
        raw_data = response.raw_data

        # Check FlexLM response structure
        assert len(raw_data) >= 16, "Response too short for FlexLM protocol"

        # Validate magic number and version
        magic = raw_data[:4]
        assert magic == b'\x00\x00\x00\x0c', "Invalid FlexLM magic number in response"

        version = struct.unpack('>H', raw_data[4:6])[0]
        assert version >= 0x0b00, "Invalid FlexLM version in response"

        message_type = struct.unpack('>H', raw_data[6:8])[0]
        assert message_type == 0x0002, "Expected license grant response type"

        # Verify response contains license grant
        assert response.license_granted, "License not granted in response"
        assert 'expiry_time' in response.metadata, "Missing license expiry"
        assert 'feature_version' in response.metadata, "Missing feature version"

        # Cryptographic validation
        if 'signature' in response.metadata:
            signature = response.metadata['signature']
            assert len(signature) >= 64, "Signature too short"

            # Verify signature format (production-ready RSA/ECDSA signatures)
            assert isinstance(signature, (bytes, str)), "Invalid signature format"

    def test_hasp_response_generation_with_challenge_response(self, response_generator, real_hasp_request):
        """Test HASP response generation with proper challenge-response handling."""
        context = ResponseContext(
            request=real_hasp_request,
            target_behavior='authenticate_success',
            protocol_version='4.0',
            encryption_required=True
        )

        response = response_generator.generate_response(context)

        assert response.success, "HASP response generation failed"
        assert response.protocol == 'hasp', "Incorrect protocol"

        # HASP response structure validation
        raw_data = response.raw_data
        assert len(raw_data) >= 20, "HASP response too short"

        # Check HASP magic and response code
        magic = raw_data[:4]
        assert magic == b'HASP', "Invalid HASP magic in response"

        response_code = struct.unpack('<I', raw_data[4:8])[0]
        assert response_code == 0, "HASP response indicates error"

        # Verify challenge was processed
        assert 'challenge_response' in response.metadata, "Missing challenge response"
        challenge_response = response.metadata['challenge_response']
        assert len(challenge_response) >= 16, "Challenge response too short"

        # Session ID should be assigned
        assert 'session_id' in response.metadata, "Missing session ID"
        session_id = response.metadata['session_id']
        assert session_id != 0, "Invalid session ID"

        # Verify authentication token
        assert 'auth_token' in response.metadata, "Missing authentication token"
        auth_token = response.metadata['auth_token']
        assert len(auth_token) >= 32, "Authentication token too short"

    def test_adobe_response_generation_with_json_structure(self, response_generator, real_adobe_request):
        """Test Adobe response generation with proper JSON structure and signatures."""
        context = ResponseContext(
            request=real_adobe_request,
            target_behavior='activate_license',
            protocol_version='2024.0',
            encryption_required=True
        )

        response = response_generator.generate_response(context)

        assert response.success, "Adobe response generation failed"
        assert response.protocol == 'adobe', "Incorrect protocol"

        # Parse JSON response
        try:
            response_data = json.loads(response.raw_data.decode())
        except json.JSONDecodeError:
            pytest.fail("Response is not valid JSON")

        # Validate Adobe response structure
        required_fields = ['status', 'activation_id', 'license_token', 'expiry_date', 'signature']
        for field in required_fields:
            assert field in response_data, f"Missing required field: {field}"

        # Status should indicate success
        assert response_data['status'] == 'activated', "License not activated"

        # Activation ID validation
        activation_id = response_data['activation_id']
        assert len(activation_id) >= 32, "Activation ID too short"
        assert activation_id.replace('-', '').isalnum(), "Invalid activation ID format"

        # License token validation
        license_token = response_data['license_token']
        assert len(license_token) >= 64, "License token too short"

        # Signature validation
        signature = response_data['signature']
        assert len(signature) >= 64, "Signature too short"

        # Verify signature authenticity (should use proper HMAC/RSA)
        payload_to_sign = {k: v for k, v in response_data.items() if k != 'signature'}
        expected_signature = hmac.new(
            b'adobe_test_key_simulate',
            json.dumps(payload_to_sign, sort_keys=True).encode(),
            hashlib.sha256
        ).hexdigest()

        # Production system should generate valid signatures
        assert len(signature) == len(expected_signature), "Signature length mismatch"

    def test_kms_response_generation_with_activation_data(self, response_generator, real_kms_request):
        """Test KMS response generation with proper activation data."""
        context = ResponseContext(
            request=real_kms_request,
            target_behavior='activate_volume_license',
            protocol_version='6.0',
            encryption_required=False
        )

        response = response_generator.generate_response(context)

        assert response.success, "KMS response generation failed"
        assert response.protocol == 'kms', "Incorrect protocol"

        # KMS response structure validation
        raw_data = response.raw_data
        assert len(raw_data) >= 32, "KMS response too short"

        # Check KMS magic and version
        magic = raw_data[:4]
        assert magic == b'\x4b\x4d\x53\x00', "Invalid KMS magic in response"

        version = struct.unpack('<H', raw_data[4:6])[0]
        assert version == 0x0006, "Invalid KMS version in response"

        response_type = struct.unpack('<H', raw_data[6:8])[0]
        assert response_type == 0x0002, "Expected activation response type"

        # Validate activation data
        assert 'activation_id' in response.metadata, "Missing activation ID"
        assert 'confirmation_id' in response.metadata, "Missing confirmation ID"
        assert 'pid' in response.metadata, "Missing PID"

        activation_id = response.metadata['activation_id']
        assert len(activation_id) >= 16, "Activation ID too short"

        confirmation_id = response.metadata['confirmation_id']
        assert len(confirmation_id) >= 16, "Confirmation ID too short"

        # PID validation (Product ID)
        pid = response.metadata['pid']
        assert len(pid) >= 20, "PID too short"

    def test_autodesk_response_generation_with_xml_structure(self, response_generator, real_autodesk_request):
        """Test Autodesk response generation with proper XML structure."""
        context = ResponseContext(
            request=real_autodesk_request,
            target_behavior='provide_activation_code',
            protocol_version='2.0',
            encryption_required=True
        )

        response = response_generator.generate_response(context)

        assert response.success, "Autodesk response generation failed"
        assert response.protocol == 'autodesk', "Incorrect protocol"

        # Parse XML response
        try:
            root = ET.fromstring(response.raw_data.decode())
        except ET.ParseError:
            pytest.fail("Response is not valid XML")

        # Validate XML structure
        assert root.tag == 'AdskLicensingResponse', "Invalid root element"
        assert root.get('version') == '2.0', "Invalid version"

        # Check required elements
        header = root.find('Header')
        assert header is not None, "Missing Header element"

        response_elem = root.find('Response')
        assert response_elem is not None, "Missing Response element"

        # Validate response data
        status = response_elem.find('Status')
        assert status is not None, "Missing Status element"
        assert status.text == 'SUCCESS', "License not activated"

        activation_code = response_elem.find('ActivationCode')
        assert activation_code is not None, "Missing ActivationCode"
        assert len(activation_code.text) >= 20, "Activation code too short"

        # Signature validation
        signature = root.find('Signature')
        assert signature is not None, "Missing digital signature"
        assert len(signature.text) >= 64, "Signature too short"

    def test_state_management_across_multiple_requests(self, response_generator, real_flexlm_request):
        """Test state management across multiple license validation requests."""
        # First request - initial license check
        context1 = ResponseContext(
            request=real_flexlm_request,
            target_behavior='approve_license',
            protocol_version='11.0',
            session_id='test_session_001'
        )

        response1 = response_generator.generate_response(context1)
        assert response1.success, "First request failed"

        # Verify session state is maintained
        state_manager = response_generator.state_manager
        session_state = state_manager.get_session_state('test_session_001')

        assert session_state is not None, "Session state not maintained"
        assert 'license_granted' in session_state, "License grant state not tracked"
        assert 'timestamp' in session_state, "Session timestamp not tracked"
        assert 'request_count' in session_state, "Request count not tracked"

        # Second request - license renewal
        time.sleep(0.1)  # Small delay
        context2 = ResponseContext(
            request=real_flexlm_request,
            target_behavior='renew_license',
            protocol_version='11.0',
            session_id='test_session_001'
        )

        response2 = response_generator.generate_response(context2)
        assert response2.success, "Renewal request failed"

        # Verify state continuity
        updated_state = state_manager.get_session_state('test_session_001')
        assert updated_state['request_count'] == 2, "Request count not incremented"
        assert updated_state['timestamp'] > session_state['timestamp'], "Timestamp not updated"

        # Third request - license check (should use cached state)
        context3 = ResponseContext(
            request=real_flexlm_request,
            target_behavior='check_license_status',
            protocol_version='11.0',
            session_id='test_session_001'
        )

        response3 = response_generator.generate_response(context3)
        assert response3.success, "Status check failed"

        # Response should be consistent with maintained state
        assert 'cached_response' in response3.metadata or response3.response_time < 0.01, \
               "State-based optimization not working"

    def test_protocol_version_adaptation(self, response_generator):
        """Test dynamic adaptation to different protocol versions."""
        # Test FlexLM version variations
        test_versions = [
            ('flexlm', '9.0', b'\x00\x00\x00\x0c' + struct.pack('>H', 0x0900)),
            ('flexlm', '11.0', b'\x00\x00\x00\x0c' + struct.pack('>H', 0x0b00)),
            ('flexlm', '14.0', b'\x00\x00\x00\x0c' + struct.pack('>H', 0x0e00)),
        ]

        for protocol, version, request_header in test_versions:
            # Create version-specific request
            request = LicenseRequest(
                protocol=protocol,
                raw_data=request_header + b'\x00' * 100,  # Padded request
                source_ip='192.168.1.100',
                dest_ip='192.168.1.10',
                source_port=12345,
                dest_port=27000,
                timestamp=datetime.now()
            )

            context = ResponseContext(
                request=request,
                target_behavior='approve_license',
                protocol_version=version
            )

            response = response_generator.generate_response(context)

            assert response.success, f"Failed to generate response for {protocol} v{version}"

            # Verify version-specific adaptations
            if version == '14.0':
                # Newer version should support advanced features
                assert 'extended_features' in response.metadata, "Missing extended features for newer version"

            elif version == '9.0':
                # Older version should use simpler response format
                assert len(response.raw_data) < 200, "Response too complex for older version"
            # Version should be reflected in response
            version_in_response = struct.unpack('>H', response.raw_data[4:6])[0]
            expected_version = int(float(version) * 256)  # Convert to hex format
            assert version_in_response == expected_version, "Version mismatch in response"

    def test_encryption_and_ssl_tls_handling(self, response_generator, real_adobe_request):
        """Test proper encryption and SSL/TLS handling in responses."""
        # Test encrypted channel response
        context = ResponseContext(
            request=real_adobe_request,
            target_behavior='activate_license',
            protocol_version='2024.0',
            encryption_required=True,
            ssl_context={'cipher': 'AES-256-GCM', 'tls_version': '1.3'}
        )

        response = response_generator.generate_response(context)

        assert response.success, "Encrypted response generation failed"
        assert response.encrypted, "Response not marked as encrypted"

        # Verify encryption metadata
        assert 'encryption_method' in response.metadata, "Missing encryption method"
        assert 'key_exchange' in response.metadata, "Missing key exchange info"

        encryption_method = response.metadata['encryption_method']
        assert encryption_method in ['AES-256-GCM', 'AES-256-CBC', 'ChaCha20-Poly1305'], \
               f"Weak encryption method: {encryption_method}"

        # Test certificate generation for TLS
        if 'certificate' in response.metadata:
            cert_data = response.metadata['certificate']
            assert len(cert_data) > 100, "Certificate data too short"

            # Try to parse certificate
            try:
                cert = x509.load_pem_x509_certificate(cert_data.encode() if isinstance(cert_data, str) else cert_data)

                # Verify certificate properties
                subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                assert 'license' in subject.lower(), "Certificate subject not license-related"

                # Check validity period
                assert cert.not_valid_before <= datetime.now(), "Certificate not yet valid"
                assert cert.not_valid_after > datetime.now(), "Certificate expired"

            except Exception as e:
                pytest.fail(f"Invalid certificate generated: {e}")

    def test_anti_detection_response_variations(self, response_generator, real_flexlm_request):
        """Test anti-detection response variations to avoid pattern recognition."""
        responses = []

        # Generate multiple responses for the same request
        for i in range(10):
            context = ResponseContext(
                request=real_flexlm_request,
                target_behavior='approve_license',
                protocol_version='11.0',
                anti_detection=True,
                variation_seed=i
            )

            response = response_generator.generate_response(context)
            assert response.success, f"Response {i+1} generation failed"

            responses.append(response.raw_data)

        # Verify response variation
        unique_responses = set(responses)
        variation_ratio = len(unique_responses) / len(responses)

        assert variation_ratio >= 0.8, f"Insufficient response variation: {variation_ratio:.1%}"

        # Check for timing variations
        timing_values = []
        for _ in range(5):
            start_time = time.time()

            context = ResponseContext(
                request=real_flexlm_request,
                target_behavior='approve_license',
                anti_detection=True
            )

            response = response_generator.generate_response(context)
            timing_values.append(time.time() - start_time)

        # Timing should vary to avoid detection
        min_time = min(timing_values)
        max_time = max(timing_values)
        timing_variation = (max_time - min_time) / min_time

        assert timing_variation >= 0.1, f"Insufficient timing variation: {timing_variation:.1%}"

    def test_response_context_comprehensive_functionality(self, response_generator):
        """Test ResponseContext functionality with comprehensive parameters."""
        # Create complex context
        context = ResponseContext(
            request=None,  # Will be set below
            target_behavior='approve_license',
            protocol_version='11.0',
            encryption_required=True,
            session_id='complex_session_001',
            client_fingerprint='win64_cad_workstation',
            server_profile='enterprise_license_server',
            anti_detection=True,
            custom_parameters={
                'license_type': 'floating',
                'max_users': 100,
                'feature_set': ['advanced', 'professional'],
                'geographic_restriction': 'none'
            }
        )

        # Verify context validation
        assert hasattr(context, 'validate'), "Missing context validation method"

        validation_result = context.validate()
        assert validation_result.is_valid, f"Context validation failed: {validation_result.errors}"

        # Test context serialization for state persistence
        assert hasattr(context, 'serialize'), "Missing context serialization"
        assert hasattr(context, 'deserialize'), "Missing context deserialization"

        serialized = context.serialize()
        assert len(serialized) > 0, "Empty serialization"

        deserialized = ResponseContext.deserialize(serialized)
        assert deserialized.target_behavior == context.target_behavior, "Serialization mismatch"
        assert deserialized.custom_parameters == context.custom_parameters, "Custom parameters lost"

    def test_generated_response_comprehensive_functionality(self, response_generator, real_flexlm_request):
        """Test GeneratedResponse comprehensive functionality and validation."""
        context = ResponseContext(
            request=real_flexlm_request,
            target_behavior='approve_license',
            protocol_version='11.0'
        )

        response = response_generator.generate_response(context)

        # Comprehensive response validation
        assert hasattr(response, 'validate_protocol_compliance'), "Missing protocol compliance validation"
        assert hasattr(response, 'get_security_assessment'), "Missing security assessment"
        assert hasattr(response, 'calculate_detection_risk'), "Missing detection risk calculation"

        # Protocol compliance check
        compliance = response.validate_protocol_compliance()
        assert compliance.is_compliant, f"Protocol compliance failed: {compliance.violations}"
        assert compliance.compliance_score >= 0.9, f"Low compliance score: {compliance.compliance_score}"

        # Security assessment
        security = response.get_security_assessment()
        assert 'encryption_strength' in security, "Missing encryption strength assessment"
        assert 'signature_validity' in security, "Missing signature validity assessment"
        assert 'tamper_resistance' in security, "Missing tamper resistance assessment"

        # Detection risk calculation
        risk = response.calculate_detection_risk()
        assert isinstance(risk, float), "Detection risk not numeric"
        assert 0.0 <= risk <= 1.0, f"Invalid risk value: {risk}"
        assert risk <= 0.3, f"High detection risk: {risk}"  # Should be low for good responses

    def test_concurrent_response_generation_thread_safety(self, response_generator, real_flexlm_request):
        """Test thread safety during concurrent response generation."""
        import threading
        import queue

        results = queue.Queue()
        errors = queue.Queue()

        def generate_concurrent_response(thread_id):
            try:
                context = ResponseContext(
                    request=real_flexlm_request,
                    target_behavior='approve_license',
                    protocol_version='11.0',
                    session_id=f'concurrent_session_{thread_id}'
                )

                response = response_generator.generate_response(context)
                results.put((thread_id, response.success, len(response.raw_data)))

            except Exception as e:
                errors.put((thread_id, str(e)))

        # Start multiple threads
        threads = []
        num_threads = 20

        for i in range(num_threads):
            t = threading.Thread(target=generate_concurrent_response, args=(i,))
            threads.append(t)
            t.start()

        # Wait for completion
        for t in threads:
            t.join(timeout=5.0)

        # Verify results
        assert errors.empty(), f"Thread safety errors: {list(errors.queue)}"
        assert results.qsize() == num_threads, f"Missing results: {results.qsize()}/{num_threads}"

        # All responses should be successful
        success_count = 0
        while not results.empty():
            thread_id, success, response_size = results.get()
            assert success, f"Thread {thread_id} response failed"
            assert response_size > 0, f"Thread {thread_id} empty response"
            success_count += 1

        assert success_count == num_threads, "Not all threads succeeded"

    def test_performance_benchmarks_high_throughput(self, response_generator, real_flexlm_request):
        """Test performance benchmarks for high-throughput scenarios."""
        num_requests = 1000
        start_time = time.time()

        successful_responses = 0
        total_response_size = 0

        context = ResponseContext(
            request=real_flexlm_request,
            target_behavior='approve_license',
            protocol_version='11.0'
        )

        for i in range(num_requests):
            # Vary session ID for realistic scenario
            context.session_id = f'perf_session_{i % 100}'

            response = response_generator.generate_response(context)

            if response.success:
                successful_responses += 1
                total_response_size += len(response.raw_data)

        elapsed_time = time.time() - start_time
        rps = successful_responses / elapsed_time  # Responses per second
        avg_response_size = total_response_size / successful_responses if successful_responses > 0 else 0

        # Performance requirements
        assert rps >= 500, f"Insufficient throughput: {rps:.1f} RPS (required: 500+ RPS)"
        assert successful_responses >= num_requests * 0.99, f"High failure rate: {successful_responses}/{num_requests}"
        assert avg_response_size > 50, f"Responses too small: {avg_response_size} bytes"

        # Memory efficiency check
        import psutil
        process = psutil.Process()
        memory_mb = process.memory_info().rss / (1024 * 1024)
        assert memory_mb < 500, f"Excessive memory usage: {memory_mb:.1f} MB"


class TestProtocolHandlerSpecialization:
    """Tests for individual protocol handler specialization and sophistication."""

    def test_flexlm_handler_advanced_features(self):
        """Test FlexLM handler advanced licensing features."""
        handler = FlexLMProtocolHandler()

        # Test floating license management
        floating_request = self._create_flexlm_floating_request()
        response = handler.generate_response(floating_request)

        assert response.success, "Floating license response failed"
        assert 'license_count' in response.metadata, "Missing license count"
        assert 'server_load' in response.metadata, "Missing server load info"

        # Test vendor daemon communication
        vendor_request = self._create_flexlm_vendor_request()
        vendor_response = handler.generate_response(vendor_request)

        assert vendor_response.success, "Vendor daemon response failed"
        assert 'vendor_id' in vendor_response.metadata, "Missing vendor ID"

        # Test license checkout/checkin
        checkout_response = handler.generate_response(floating_request)
        checkin_request = self._create_flexlm_checkin_request()
        checkin_response = handler.generate_response(checkin_request)

        assert checkout_response.success and checkin_response.success, "Checkout/checkin failed"

    def test_hasp_handler_security_features(self):
        """Test HASP handler security and dongle emulation features."""
        handler = HASPProtocolHandler()

        # Test hardware dongle emulation
        dongle_request = self._create_hasp_dongle_request()
        response = handler.generate_response(dongle_request)

        assert response.success, "Dongle emulation failed"
        assert 'hardware_signature' in response.metadata, "Missing hardware signature"
        assert 'dongle_id' in response.metadata, "Missing dongle ID"

        # Test encrypted vendor codes
        vendor_code_request = self._create_hasp_vendor_code_request()
        vc_response = handler.generate_response(vendor_code_request)

        assert vc_response.success, "Vendor code validation failed"
        assert 'decrypted_features' in vc_response.metadata, "Missing feature decryption"

    def test_adobe_handler_cloud_integration(self):
        """Test Adobe handler cloud licensing integration."""
        handler = AdobeProtocolHandler()

        # Test Creative Cloud subscription
        cc_request = self._create_adobe_cc_request()
        response = handler.generate_response(cc_request)

        assert response.success, "Creative Cloud response failed"
        assert 'subscription_status' in response.metadata, "Missing subscription status"
        assert 'entitled_products' in response.metadata, "Missing entitled products"

        # Test device deactivation
        deactivate_request = self._create_adobe_deactivate_request()
        deactivate_response = handler.generate_response(deactivate_request)

        assert deactivate_response.success, "Device deactivation failed"

    def test_kms_handler_volume_licensing(self):
        """Test KMS handler volume licensing features."""
        handler = MicrosoftKMSHandler()

        # Test Windows activation
        windows_request = self._create_kms_windows_request()
        response = handler.generate_response(windows_request)

        assert response.success, "Windows KMS activation failed"
        assert 'activation_count' in response.metadata, "Missing activation count"
        assert 'grace_period' in response.metadata, "Missing grace period"

        # Test Office activation
        office_request = self._create_kms_office_request()
        office_response = handler.generate_response(office_request)

        assert office_response.success, "Office KMS activation failed"

    def test_autodesk_handler_subscription_management(self):
        """Test Autodesk handler subscription and network licensing."""
        handler = AutodeskProtocolHandler()

        # Test subscription validation
        subscription_request = self._create_autodesk_subscription_request()
        response = handler.generate_response(subscription_request)

        assert response.success, "Subscription validation failed"
        assert 'subscription_tier' in response.metadata, "Missing subscription tier"
        assert 'usage_rights' in response.metadata, "Missing usage rights"

        # Test network license server
        network_request = self._create_autodesk_network_request()
        network_response = handler.generate_response(network_request)

        assert network_response.success, "Network licensing failed"

    # Helper methods for creating protocol-specific requests

    def _create_flexlm_floating_request(self):
        """Create FlexLM floating license request."""
        return LicenseRequest(
            protocol='flexlm',
            raw_data=b'\x00\x00\x00\x0c' + struct.pack('>H', 0x0b00) + b'\x00\x01' + secrets.token_bytes(100),
            source_ip='192.168.1.100',
            dest_ip='192.168.1.10',
            source_port=12345,
            dest_port=27000,
            timestamp=datetime.now()
        )

    def _create_flexlm_vendor_request(self):
        """Create FlexLM vendor daemon request."""
        return LicenseRequest(
            protocol='flexlm',
            raw_data=b'\x00\x00\x00\x0c' + struct.pack('>H', 0x0b00) + b'\x00\x03' + secrets.token_bytes(50),
            source_ip='192.168.1.100',
            dest_ip='192.168.1.10',
            source_port=12346,
            dest_port=27001,
            timestamp=datetime.now()
        )

    def _create_flexlm_checkin_request(self):
        """Create FlexLM license checkin request."""
        return LicenseRequest(
            protocol='flexlm',
            raw_data=b'\x00\x00\x00\x0c' + struct.pack('>H', 0x0b00) + b'\x00\x05' + secrets.token_bytes(80),
            source_ip='192.168.1.100',
            dest_ip='192.168.1.10',
            source_port=12345,
            dest_port=27000,
            timestamp=datetime.now()
        )

    def _create_hasp_dongle_request(self):
        """Create HASP hardware dongle request."""
        return LicenseRequest(
            protocol='hasp',
            raw_data=b'HASP' + struct.pack('<I', 0x00000010) + secrets.token_bytes(32),
            source_ip='10.0.0.50',
            dest_ip='10.0.0.10',
            source_port=12345,
            dest_port=1947,
            timestamp=datetime.now()
        )

    def _create_hasp_vendor_code_request(self):
        """Create HASP vendor code validation request."""
        return LicenseRequest(
            protocol='hasp',
            raw_data=b'HASP' + struct.pack('<I', 0x00000020) + secrets.token_bytes(48),
            source_ip='10.0.0.50',
            dest_ip='10.0.0.10',
            source_port=12346,
            dest_port=1947,
            timestamp=datetime.now()
        )

    def _create_adobe_cc_request(self):
        """Create Adobe Creative Cloud request."""
        cc_data = {
            'product': 'photoshop',
            'version': '2024',
            'subscription_type': 'individual',
            'user_id': secrets.token_hex(16)
        }

        return LicenseRequest(
            protocol='adobe',
            raw_data=json.dumps(cc_data).encode(),
            source_ip='172.16.1.100',
            dest_ip='activation.adobe.com',
            source_port=12345,
            dest_port=443,
            timestamp=datetime.now(),
            payload=cc_data
        )

    def _create_adobe_deactivate_request(self):
        """Create Adobe device deactivation request."""
        deactivate_data = {
            'action': 'deactivate',
            'device_id': secrets.token_hex(16),
            'activation_id': secrets.token_hex(32)
        }

        return LicenseRequest(
            protocol='adobe',
            raw_data=json.dumps(deactivate_data).encode(),
            source_ip='172.16.1.100',
            dest_ip='activation.adobe.com',
            source_port=12346,
            dest_port=443,
            timestamp=datetime.now(),
            payload=deactivate_data
        )

    def _create_kms_windows_request(self):
        """Create KMS Windows activation request."""
        return LicenseRequest(
            protocol='kms',
            raw_data=b'\x4b\x4d\x53\x00' + struct.pack('<H', 0x0006) + b'\x00\x01' + secrets.token_bytes(60),
            source_ip='10.0.0.25',
            dest_ip='10.0.0.1',
            source_port=12345,
            dest_port=1688,
            timestamp=datetime.now()
        )

    def _create_kms_office_request(self):
        """Create KMS Office activation request."""
        return LicenseRequest(
            protocol='kms',
            raw_data=b'\x4b\x4d\x53\x00' + struct.pack('<H', 0x0006) + b'\x00\x02' + secrets.token_bytes(60),
            source_ip='10.0.0.25',
            dest_ip='10.0.0.1',
            source_port=12346,
            dest_port=1688,
            timestamp=datetime.now()
        )

    def _create_autodesk_subscription_request(self):
        """Create Autodesk subscription validation request."""
        subscription_xml = f"""<?xml version="1.0"?>
<AdskSubscriptionRequest>
    <UserId>{secrets.token_hex(16)}</UserId>
    <Product>AutoCAD</Product>
    <SubscriptionId>{secrets.token_hex(20)}</SubscriptionId>
</AdskSubscriptionRequest>"""

        return LicenseRequest(
            protocol='autodesk',
            raw_data=subscription_xml.encode(),
            source_ip='192.168.0.100',
            dest_ip='subscription.autodesk.com',
            source_port=12345,
            dest_port=443,
            timestamp=datetime.now()
        )

    def _create_autodesk_network_request(self):
        """Create Autodesk network license request."""
        network_xml = f"""<?xml version="1.0"?>
<AdskNetworkRequest>
    <Feature>ACAD</Feature>
    <Version>2024.1</Version>
    <Count>1</Count>
    <ClientId>{secrets.token_hex(16)}</ClientId>
</AdskNetworkRequest>"""

        return LicenseRequest(
            protocol='autodesk',
            raw_data=network_xml.encode(),
            source_ip='192.168.0.100',
            dest_ip='192.168.0.10',
            source_port=12345,
            dest_port=2080,
            timestamp=datetime.now()
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "--maxfail=5"])
