"""
Functional tests for Intellicrack's network protocol parsing capabilities.

This module contains comprehensive tests for network protocol parsing operations in Intellicrack,
including FlexLM protocol packet parsing, HASP protocol packet parsing, Adobe Creative Cloud
protocol parsing, KMS (Key Management Service) protocol packet parsing, multi-protocol
detection and routing, protocol state tracking across multiple packets, protocol error
handling and malformed packet processing, protocol parsing performance with large
packet volumes, protocol fragmentation handling, protocol encryption and obfuscation
detection, and protocol signature validation and integrity checking. These tests
ensure the network protocol parsers work correctly with real protocol packets.
"""

import pytest
import struct
import socket
import time
import json
import base64
import zlib
from datetime import datetime, timedelta
from typing import Dict, List, Any

from intellicrack.core.network.protocol_parsers import ProtocolParsers
from intellicrack.core.network.flexlm_parser import FlexLMParser
from intellicrack.core.network.hasp_parser import HASPParser
from intellicrack.core.network.adobe_parser import AdobeParser
from intellicrack.core.network.kms_parser import KMSParser
from intellicrack.core.network.rpc_parser import RPCParser
from intellicrack.core.network.http_parser import HTTPParser
from intellicrack.core.app_context import AppContext


class TestRealProtocolParsers:
    """Functional tests for REAL network protocol parsing operations."""

    @pytest.fixture
    def app_context(self) -> Any:
        """Create REAL application context."""
        context = AppContext()
        context.initialize()  # type: ignore[attr-defined]
        return context

    @pytest.fixture
    def flexlm_packets(self) -> Dict[str, bytes]:
        """Create REAL FlexLM protocol packets."""
        # License request packet
        request = b''
        request += struct.pack('>I', 0x464C584D)  # Magic 'FLXM'
        request += struct.pack('>H', 0x0301)  # Version 3.1
        request += struct.pack('>H', 0x0001)  # Request type: LICENSE_REQUEST
        request += struct.pack('>I', 0x12345678)  # Transaction ID
        request += struct.pack('>I', 0x00000040)  # Packet length

        # Request data
        request += b'autocad\x00'  # Feature name (8 bytes)
        request += b'2024.1\x00\x00'  # Version (8 bytes)
        request += struct.pack('>I', 1)  # License count
        request += b'user@workstation\x00\x00\x00'  # User@host (16 bytes)
        request += b'DISPLAY=:0.0\x00\x00\x00\x00'  # Display (16 bytes)
        request += struct.pack('>I', int(time.time()))  # Timestamp
        request += struct.pack('>I', 0x12345678)  # Host ID 1
        request += struct.pack('>I', 0x87654321)  # Host ID 2
        packets = {'license_request': request}
        # License response packet
        response = b''
        response += struct.pack('>I', 0x464C584D)  # Magic 'FLXM'
        response += struct.pack('>H', 0x0301)  # Version 3.1
        response += struct.pack('>H', 0x0002)  # Response type: LICENSE_GRANTED
        response += struct.pack('>I', 0x12345678)  # Transaction ID
        response += struct.pack('>I', 0x00000080)  # Packet length

        # Response data
        response += struct.pack('>I', 0)  # Status: SUCCESS
        response += b'ABCD-EFGH-IJKL-MNOP-QRST-UVWX'  # License key (30 bytes)
        response += b'\x00\x00'  # Padding
        response += struct.pack('>I', int(time.time()) + 86400)  # Expiry (24h)
        response += struct.pack('>I', 1)  # Max users
        response += b'autocad\x00'  # Feature confirmed
        response += b'2024.1\x00\x00'  # Version confirmed
        response += struct.pack('>Q', 0x0123456789ABCDEF)  # Server signature
        response += b'\x00' * 32  # Reserved
        packets['license_response'] = response

        # Heartbeat packet
        heartbeat = b''
        heartbeat += struct.pack('>I', 0x464C584D)  # Magic
        heartbeat += struct.pack('>H', 0x0301)  # Version
        heartbeat += struct.pack('>H', 0x0003)  # Type: HEARTBEAT
        heartbeat += struct.pack('>I', 0x87654321)  # Transaction ID
        heartbeat += struct.pack('>I', 0x00000020)  # Length
        heartbeat += struct.pack('>I', int(time.time()))  # Timestamp
        heartbeat += struct.pack('>I', 0x12345678)  # Host ID
        heartbeat += b'\x00' * 16  # Reserved
        packets['heartbeat'] = heartbeat

        return packets

    @pytest.fixture
    def hasp_packets(self) -> Dict[str, bytes]:
        """Create REAL HASP protocol packets."""
        # Login packet
        login = b''
        login += b'HASP'  # Signature
        login += struct.pack('<I', 0x00010004)  # Version 1.4
        login += struct.pack('<I', 0x00000001)  # Command: LOGIN
        login += struct.pack('<I', 0x00000060)  # Packet size
        login += struct.pack('<I', 0x12345678)  # Feature ID
        login += struct.pack('<Q', 0x0123456789ABCDEF)  # Vendor code
        login += struct.pack('<I', 0x00000001)  # Login type: EXCLUSIVE
        login += b'MyApplication\x00\x00\x00\x00'  # Application name (16 bytes)
        login += struct.pack('<I', 0x20240101)  # Build date
        login += b'\x00' * 32  # Reserved
        # Login response
        login_response = b''
        login_response += b'HASP'  # Signature
        login_response += struct.pack('<I', 0x00010004)  # Version
        login_response += struct.pack('<I', 0x00008001)  # Response: LOGIN_OK
        login_response += struct.pack('<I', 0x00000040)  # Size
        login_response += struct.pack('<I', 0)  # Status: SUCCESS
        login_response += struct.pack('<I', 0xABCD1234)  # Session handle
        login_response += struct.pack('<Q', int(time.time()) + 3600)  # Session expiry
        login_response += struct.pack('<I', 0x00000001)  # Max concurrent
        login_response += b'\x00' * 28  # Reserved
        packets = {'login': login, 'login_response': login_response}
        # Read memory packet
        read_mem = b''
        read_mem += b'HASP'  # Signature
        read_mem += struct.pack('<I', 0x00010004)  # Version
        read_mem += struct.pack('<I', 0x00000010)  # Command: READ_MEMORY
        read_mem += struct.pack('<I', 0x00000030)  # Size
        read_mem += struct.pack('<I', 0xABCD1234)  # Session handle
        read_mem += struct.pack('<I', 0x0000)  # Memory address
        read_mem += struct.pack('<I', 256)  # Read length
        read_mem += b'\x00' * 20  # Reserved
        packets['read_memory'] = read_mem

        return packets

    @pytest.fixture
    def adobe_packets(self) -> Dict[str, bytes]:
        """Create REAL Adobe Creative Cloud packets."""
        # Activation request
        activation_request = {
            "header": {
                "version": "2.1",
                "timestamp": datetime.utcnow().isoformat(),
                "request_id": "REQ-12345678-ABCD-EFGH",
                "client_version": "CC2024.1.0"
            },
            "activation": {
                "product_id": "PHSP",
                "product_version": "25.0.0",
                "serial_number": "1234-5678-9012-3456-7890-1234",
                "machine_info": {
                    "machine_id": "MAC-ABCDEF123456",
                    "os_version": "Windows 10 Pro 64-bit",
                    "cpu_info": "Intel Core i7-9700K",
                    "ram_size": "32 GB",
                    "graphics": "NVIDIA RTX 3080"
                },
                "user_info": {
                    "adobe_id": "user@example.com",
                    "country": "US",
                    "language": "en_US"
                },
                "activation_type": "initial"
            }
        }

        # Convert to HTTP POST packet
        json_data = json.dumps(activation_request)
        http_request = f"POST /activation/v2/activate HTTP/1.1\r\n"
        http_request += f"Host: activation.adobe.com\r\n"
        http_request += f"Content-Type: application/json\r\n"
        http_request += f"Content-Length: {len(json_data)}\r\n"
        http_request += f"User-Agent: Adobe-Activation-Client/2.1\r\n"
        http_request += f"Authorization: Bearer TOKEN_PLACEHOLDER\r\n"
        http_request += f"\r\n{json_data}"
        packets = {'activation_request': http_request.encode()}
        # Activation response
        activation_response = {
            "header": {
                "version": "2.1",
                "timestamp": datetime.utcnow().isoformat(),
                "request_id": "REQ-12345678-ABCD-EFGH",
                "status": "success"
            },
            "activation": {
                "activation_id": "ACT-87654321-ZYXW-VUTSRQ",
                "license_key": "ADOBE-LICENSE-KEY-12345678901234567890",
                "license_type": "subscription",
                "expiry_date": (datetime.utcnow() + timedelta(days=30)).isoformat(),
                "features": [
                    "photoshop_core",
                    "camera_raw",
                    "bridge_integration",
                    "cloud_sync"
                ],
                "restrictions": {
                    "max_devices": 2,
                    "offline_grace_period": 7
                }
            }
        }

        response_json = json.dumps(activation_response)
        http_response = f"HTTP/1.1 200 OK\r\n"
        http_response += f"Content-Type: application/json\r\n"
        http_response += f"Content-Length: {len(response_json)}\r\n"
        http_response += f"Server: Adobe-Activation-Server/2.1\r\n"
        http_response += f"\r\n{response_json}"
        packets['activation_response'] = http_response.encode()

        return packets

    @pytest.fixture
    def kms_packets(self) -> Dict[str, bytes]:
        """Create REAL KMS (Key Management Service) packets."""
        # KMS activation request
        kms_request = b''
        kms_request += struct.pack('<I', 0x4B4D5320)  # Magic 'KMS '
        kms_request += struct.pack('<H', 0x0006)  # Version 6
        kms_request += struct.pack('<H', 0x0001)  # Request type: ACTIVATION
        kms_request += struct.pack('<I', 0xDEADBEEF)  # Transaction ID
        kms_request += struct.pack('<I', 0x00000100)  # Packet length

        # Product info
        kms_request += b'Windows 10 Pro\x00\x00\x00'  # Product name (16 bytes)
        kms_request += b'VK7JG-NPHTM-C97JM-9MPGT-3V66T'  # Product key (29 bytes)
        kms_request += b'\x00\x00\x00'  # Padding
        kms_request += struct.pack('<Q', 0x0123456789ABCDEF)  # Client ID
        kms_request += struct.pack('<I', 0x20240101)  # Build version
        kms_request += struct.pack('<I', int(time.time()))  # Request time

        # Machine info
        kms_request += b'WORKSTATION-PC\x00\x00'  # Machine name (16 bytes)
        kms_request += struct.pack('<Q', 0xFEDCBA9876543210)  # Hardware hash
        kms_request += b'\x00' * 128  # Reserved/padding
        # KMS activation response
        kms_response = b''
        kms_response += struct.pack('<I', 0x4B4D5320)  # Magic 'KMS '
        kms_response += struct.pack('<H', 0x0006)  # Version 6
        kms_response += struct.pack('<H', 0x8001)  # Response: ACTIVATION_SUCCESS
        kms_response += struct.pack('<I', 0xDEADBEEF)  # Transaction ID
        kms_response += struct.pack('<I', 0x00000080)  # Packet length

        # Response data
        kms_response += struct.pack('<I', 0)  # Status: SUCCESS
        kms_response += struct.pack('<Q', int(time.time()) + (180 * 24 * 3600))  # Expiry (180 days)
        kms_response += struct.pack('<I', 25)  # Minimum clients
        kms_response += struct.pack('<I', 50)  # Current count
        kms_response += b'KMS-SERVER-2024\x00'  # Server name (16 bytes)
        kms_response += struct.pack('<Q', 0x1122334455667788)  # Server signature
        kms_response += b'\x00' * 64  # Reserved
        return {'activation_request': kms_request, 'activation_response': kms_response}

    def test_real_flexlm_protocol_parsing(self, flexlm_packets: Dict[str, bytes], app_context: Any) -> None:
        """Test REAL FlexLM protocol packet parsing."""
        parser = FlexLMParser()

        # Parse license request
        request_result = parser.parse_packet(flexlm_packets['license_request'])
        assert request_result is not None, "FlexLM request parsing must succeed"
        assert request_result['valid'], "Parsed packet must be valid"
        assert request_result['packet_type'] == 'license_request', "Must identify packet type"
        assert request_result['version'] == '3.1', "Must extract version"
        assert request_result['transaction_id'] == 0x12345678, "Must extract transaction ID"

        # Verify request fields
        request_data = request_result['data']
        assert request_data['feature'] == 'autocad', "Must extract feature name"
        assert request_data['version'] == '2024.1', "Must extract version"
        assert request_data['count'] == 1, "Must extract license count"
        assert 'user@workstation' in request_data['user_host'], "Must extract user@host"
        assert 'DISPLAY=' in request_data['display'], "Must extract display"

        # Parse license response
        response_result = parser.parse_packet(flexlm_packets['license_response'])
        assert response_result is not None, "FlexLM response parsing must succeed"
        assert response_result['valid'], "Response packet must be valid"
        assert response_result['packet_type'] == 'license_granted', "Must identify response type"

        # Verify response fields
        response_data = response_result['data']
        assert response_data['status'] == 'success', "Must extract status"
        assert 'ABCD-EFGH' in response_data['license_key'], "Must extract license key"
        assert response_data['feature'] == 'autocad', "Must confirm feature"
        assert response_data['max_users'] == 1, "Must extract user limit"

        # Parse heartbeat
        heartbeat_result = parser.parse_packet(flexlm_packets['heartbeat'])
        assert heartbeat_result is not None, "Heartbeat parsing must succeed"
        assert heartbeat_result['packet_type'] == 'heartbeat', "Must identify heartbeat"
        assert heartbeat_result['data']['host_id'] == 0x12345678, "Must extract host ID"

    def test_real_hasp_protocol_parsing(self, hasp_packets: Dict[str, bytes], app_context: Any) -> None:
        """Test REAL HASP protocol packet parsing."""
        parser = HASPParser()

        # Parse login request
        login_result = parser.parse_packet(hasp_packets['login'])
        assert login_result is not None, "HASP login parsing must succeed"
        assert login_result['valid'], "Login packet must be valid"
        assert login_result['command'] == 'login', "Must identify login command"
        assert login_result['version'] == '1.4', "Must extract version"

        # Verify login fields
        login_data = login_result['data']
        assert login_data['feature_id'] == 0x12345678, "Must extract feature ID"
        assert login_data['vendor_code'] == 0x0123456789ABCDEF, "Must extract vendor code"
        assert login_data['login_type'] == 'exclusive', "Must identify login type"
        assert 'MyApplication' in login_data['application'], "Must extract app name"

        # Parse login response
        response_result = parser.parse_packet(hasp_packets['login_response'])
        assert response_result is not None, "Login response parsing must succeed"
        assert response_result['valid'], "Response must be valid"
        assert response_result['command'] == 'login_response', "Must identify response"

        # Verify response fields
        response_data = response_result['data']
        assert response_data['status'] == 'success', "Must extract status"
        assert response_data['session_handle'] == 0xABCD1234, "Must extract session"
        assert response_data['max_concurrent'] == 1, "Must extract concurrency limit"

        # Parse memory read
        read_result = parser.parse_packet(hasp_packets['read_memory'])
        assert read_result is not None, "Memory read parsing must succeed"
        assert read_result['command'] == 'read_memory', "Must identify memory read"

        read_data = read_result['data']
        assert read_data['session_handle'] == 0xABCD1234, "Must extract session"
        assert read_data['address'] == 0x0000, "Must extract address"
        assert read_data['length'] == 256, "Must extract read length"

    def test_real_adobe_protocol_parsing(self, adobe_packets: Dict[str, bytes], app_context: Any) -> None:
        """Test REAL Adobe Creative Cloud protocol parsing."""
        parser = AdobeParser()

        # Parse activation request
        request_result = parser.parse_http_packet(adobe_packets['activation_request'])
        assert request_result is not None, "Adobe request parsing must succeed"
        assert request_result['valid'], "Request must be valid"
        assert request_result['method'] == 'POST', "Must extract HTTP method"
        assert '/activation/v2/activate' in request_result['path'], "Must extract path"

        # Verify request headers
        headers = request_result['headers']
        assert headers['Content-Type'] == 'application/json', "Must extract content type"
        assert 'Adobe-Activation-Client' in headers['User-Agent'], "Must extract user agent"
        host_value = headers['Host'].split(':')[0]
        assert host_value == 'activation.adobe.com' or host_value.endswith('.activation.adobe.com'), "Must extract host"

        # Verify request body
        body_data = request_result['body_json']
        assert body_data['activation']['product_id'] == 'PHSP', "Must extract product ID"
        assert 'serial_number' in body_data['activation'], "Must have serial number"
        assert 'machine_info' in body_data['activation'], "Must have machine info"

        machine_info = body_data['activation']['machine_info']
        assert 'MAC-ABCDEF123456' in machine_info['machine_id'], "Must extract machine ID"
        assert 'Windows 10' in machine_info['os_version'], "Must extract OS"

        # Parse activation response
        response_result = parser.parse_http_packet(adobe_packets['activation_response'])
        assert response_result is not None, "Response parsing must succeed"
        assert response_result['status_code'] == 200, "Must extract status code"
        assert response_result['valid'], "Response must be valid"

        # Verify response body
        response_body = response_result['body_json']
        assert response_body['header']['status'] == 'success', "Must extract status"
        assert 'ACT-' in response_body['activation']['activation_id'], "Must extract activation ID"
        assert 'ADOBE-LICENSE-KEY' in response_body['activation']['license_key'], "Must extract license"

        features = response_body['activation']['features']
        assert 'photoshop_core' in features, "Must extract features"
        assert len(features) >= 3, "Must have multiple features"

    def test_real_kms_protocol_parsing(self, kms_packets: Dict[str, bytes], app_context: Any) -> None:
        """Test REAL KMS protocol packet parsing."""
        parser = KMSParser()

        # Parse activation request
        request_result = parser.parse_packet(kms_packets['activation_request'])
        assert request_result is not None, "KMS request parsing must succeed"
        assert request_result['valid'], "Request must be valid"
        assert request_result['packet_type'] == 'activation_request', "Must identify packet type"
        assert request_result['version'] == 6, "Must extract version"
        assert request_result['transaction_id'] == 0xDEADBEEF, "Must extract transaction ID"

        # Verify request fields
        request_data = request_result['data']
        assert 'Windows 10 Pro' in request_data['product_name'], "Must extract product"
        assert 'VK7JG-NPHTM' in request_data['product_key'], "Must extract product key"
        assert request_data['client_id'] == 0x0123456789ABCDEF, "Must extract client ID"
        assert 'WORKSTATION-PC' in request_data['machine_name'], "Must extract machine name"

        # Parse activation response
        response_result = parser.parse_packet(kms_packets['activation_response'])
        assert response_result is not None, "KMS response parsing must succeed"
        assert response_result['valid'], "Response must be valid"
        assert response_result['packet_type'] == 'activation_success', "Must identify success"

        # Verify response fields
        response_data = response_result['data']
        assert response_data['status'] == 'success', "Must extract status"
        assert response_data['minimum_clients'] == 25, "Must extract minimum clients"
        assert response_data['current_count'] == 50, "Must extract current count"
        assert 'KMS-SERVER-2024' in response_data['server_name'], "Must extract server name"

    def test_real_multi_protocol_detection(self, flexlm_packets: Dict[str, bytes], hasp_packets: Dict[str, bytes], adobe_packets: Dict[str, bytes], kms_packets: Dict[str, bytes], app_context: Any) -> None:
        """Test REAL multi-protocol detection and routing."""
        protocol_parsers = ProtocolParsers()

        test_packets = [
            ('flexlm', flexlm_packets['license_request']),
            ('hasp', hasp_packets['login']),
            ('adobe', adobe_packets['activation_request']),
            ('kms', kms_packets['activation_request'])
        ]

        for expected_protocol, packet_data in test_packets:
            # Auto-detect protocol
            detection_result = protocol_parsers.detect_protocol(packet_data)
            assert detection_result is not None, f"Protocol detection must succeed for {expected_protocol}"
            assert detection_result['detected'], "Must detect a protocol"
            assert detection_result['protocol'] == expected_protocol, f"Must detect {expected_protocol}"
            assert detection_result['confidence'] > 0.8, "Detection confidence must be high"

            # Parse with detected protocol
            parse_result = protocol_parsers.parse_with_protocol(
                packet_data,
                detection_result['protocol']
            )
            assert parse_result is not None, f"Parsing must succeed for {expected_protocol}"
            assert parse_result['valid'], f"Parsed packet must be valid for {expected_protocol}"
            assert parse_result['protocol'] == expected_protocol, "Protocol must match detection"

    def test_real_protocol_state_tracking(self, flexlm_packets: Dict[str, bytes], app_context: Any) -> None:
        """Test REAL protocol state tracking across multiple packets."""
        parser = FlexLMParser()
        state_tracker = parser.create_session_tracker()

        # Process request
        request_result = parser.parse_packet_with_state(
            flexlm_packets['license_request'],
            state_tracker
        )
        assert request_result is not None, "Request with state must succeed"
        assert 'session_id' in request_result, "Must create session"

        session_id = request_result['session_id']
        session_state = state_tracker.get_session(session_id)
        assert session_state is not None, "Session must exist"
        assert session_state['state'] == 'awaiting_response', "Must track request state"

        # Process response
        response_result = parser.parse_packet_with_state(
            flexlm_packets['license_response'],
            state_tracker
        )
        assert response_result is not None, "Response with state must succeed"
        assert response_result['session_id'] == session_id, "Must match session"

        # Verify state transition
        updated_state = state_tracker.get_session(session_id)
        assert updated_state['state'] == 'license_granted', "Must update to granted state"
        assert 'license_key' in updated_state, "Must store license key"

        # Process heartbeat
        heartbeat_result = parser.parse_packet_with_state(
            flexlm_packets['heartbeat'],
            state_tracker
        )
        assert heartbeat_result is not None, "Heartbeat with state must succeed"

        # Verify heartbeat tracking
        final_state = state_tracker.get_session(session_id)
        assert 'last_heartbeat' in final_state, "Must track heartbeat time"
        assert final_state['state'] == 'active', "Must show active state"

    def test_real_protocol_error_handling(self, app_context: Any) -> None:
        """Test REAL protocol error handling and malformed packets."""
        parser = FlexLMParser()

        # Test malformed packets
        malformed_packets = [
            b'',  # Empty packet
            b'INVALID',  # Wrong magic
            struct.pack('>I', 0x464C584D) + b'\x00\x00',  # Truncated header
            struct.pack('>I', 0x464C584D) + struct.pack('>H', 0x9999),  # Invalid version
            b'FLXM' + b'\x00' * 100 + b'\xFF' * 50  # Oversized invalid data
        ]

        for i, packet in enumerate(malformed_packets):
            result = parser.parse_packet(packet)
            assert result is not None, f"Parser must handle malformed packet {i}"
            assert not result['valid'], f"Malformed packet {i} must be marked invalid"
            assert 'error' in result, f"Must provide error for malformed packet {i}"
            assert 'error_code' in result, f"Must provide error code for packet {i}"

        # Test packet size limits
        oversized_packet = b'FLXM' + b'\x00' * 65536  # 64KB packet
        oversized_result = parser.parse_packet(oversized_packet)
        assert oversized_result is not None, "Must handle oversized packet"
        assert not oversized_result['valid'], "Oversized packet must be invalid"
        assert 'size_limit' in oversized_result['error'], "Must identify size limit error"

    def test_real_protocol_performance_parsing(self, flexlm_packets: Dict[str, bytes], hasp_packets: Dict[str, bytes], app_context: Any) -> None:
        """Test REAL protocol parsing performance with large packet volumes."""
        protocol_parsers = ProtocolParsers()

        # Create packet batch
        packet_batch = []
        for _ in range(100):
            packet_batch.extend([
                flexlm_packets['license_request'],
                flexlm_packets['license_response'],
                hasp_packets['login'],
                hasp_packets['login_response']
            ])

        # Time batch processing
        start_time = time.time()

        results = []
        for packet in packet_batch:
            result = protocol_parsers.parse_packet_fast(packet)
            results.append(result)

        end_time = time.time()
        processing_time = end_time - start_time

        # Verify performance
        assert len(results) == len(packet_batch), "All packets must be processed"
        assert processing_time < 5.0, "Batch processing should complete under 5 seconds"

        # Verify accuracy
        valid_results = [r for r in results if r and r.get('valid', False)]
        assert len(valid_results) >= len(packet_batch) * 0.9, "At least 90% should parse successfully"

        # Calculate throughput
        throughput = len(packet_batch) / processing_time
        assert throughput > 50, "Should process at least 50 packets per second"

    def test_real_protocol_fragmentation_handling(self, flexlm_packets: Dict[str, bytes], app_context: Any) -> None:
        """Test REAL protocol handling of fragmented packets."""
        parser = FlexLMParser()

        original_packet = flexlm_packets['license_request']

        # Fragment into multiple pieces
        fragment_size = 16
        fragments = []
        for i in range(0, len(original_packet), fragment_size):
            fragment = original_packet[i:i + fragment_size]
            fragments.append(fragment)

        assert len(fragments) > 3, "Packet should fragment into multiple pieces"

        # Test reassembly
        reassembler = parser.create_reassembler()

        for i, fragment in enumerate(fragments):
            fragment_result = reassembler.process_fragment(fragment, fragment_id=i)

            if i < len(fragments) - 1:
                assert not fragment_result['complete'], f"Fragment {i} should not be complete"
                assert 'bytes_received' in fragment_result, "Must track received bytes"
            else:
                assert fragment_result['complete'], "Final fragment should complete packet"
                assert 'reassembled_packet' in fragment_result, "Must provide reassembled packet"

        # Verify reassembled packet
        reassembled = fragment_result['reassembled_packet']
        assert reassembled == original_packet, "Reassembled packet must match original"

        # Parse reassembled packet
        parse_result = parser.parse_packet(reassembled)
        assert parse_result['valid'], "Reassembled packet must parse correctly"

    def test_real_protocol_encryption_detection(self, app_context: Any) -> None:
        """Test REAL protocol encryption and obfuscation detection."""
        protocol_parsers = ProtocolParsers()

        # Create encrypted/obfuscated test data
        test_data = b"SENSITIVE_LICENSE_DATA_12345"

        # XOR encryption
        xor_key = 0xAA
        xor_encrypted = bytes(b ^ xor_key for b in test_data)

        # Base64 encoding
        b64_encoded = base64.b64encode(test_data)

        # Zlib compression
        compressed = zlib.compress(test_data)

        # Test detection
        encryption_tests = [
            ('xor', xor_encrypted),
            ('base64', b64_encoded),
            ('compressed', compressed),
            ('plaintext', test_data)
        ]

        for encryption_type, data in encryption_tests:
            detection_result = protocol_parsers.detect_encryption(data)
            assert detection_result is not None, f"Encryption detection must work for {encryption_type}"
            assert 'encryption_detected' in detection_result, "Must indicate if encryption detected"
            assert 'encryption_type' in detection_result, "Must identify encryption type"
            assert 'confidence' in detection_result, "Must provide confidence score"

            if encryption_type != 'plaintext':
                assert detection_result['encryption_detected'], f"Must detect {encryption_type}"
            else:
                assert not detection_result['encryption_detected'], "Must not detect encryption in plaintext"

    def test_real_protocol_signature_validation(self, flexlm_packets: Dict[str, bytes], hasp_packets: Dict[str, bytes], app_context: Any) -> None:
        """Test REAL protocol signature validation and integrity checking."""
        protocol_parsers = ProtocolParsers()

        signature_tests = [
            ('flexlm', flexlm_packets['license_response']),
            ('hasp', hasp_packets['login_response'])
        ]

        for protocol_name, packet in signature_tests:
            # Validate original signature
            validation_result = protocol_parsers.validate_packet_signature(packet, protocol_name)
            assert validation_result is not None, f"Signature validation must work for {protocol_name}"
            assert 'signature_valid' in validation_result, "Must check signature validity"
            assert 'integrity_check' in validation_result, "Must perform integrity check"

            # Test with corrupted packet
            corrupted_packet = bytearray(packet)
            corrupted_packet[-10] ^= 0xFF  # Corrupt signature area

            corruption_result = protocol_parsers.validate_packet_signature(
                bytes(corrupted_packet),
                protocol_name
            )
            assert corruption_result is not None, "Must handle corrupted signatures"
            assert not corruption_result['signature_valid'], "Corrupted signature must be invalid"
            assert not corruption_result['integrity_check'], "Integrity check must fail"
