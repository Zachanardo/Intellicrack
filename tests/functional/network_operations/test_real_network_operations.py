import pytest
import tempfile
import os
import socket
import threading
import time
import struct
from pathlib import Path

from intellicrack.core.network.cloud_license_hooker import CloudLicenseHooker
from intellicrack.core.network_capture import NetworkCapture
from intellicrack.core.app_context import AppContext


class TestRealNetworkOperations:
    """Functional tests for REAL network operations and license emulation."""

    @pytest.fixture
    def flexlm_protocol_data(self):
        """Create REAL FlexLM protocol data for testing."""
        return {
            'handshake': {
                'data': b'\x00\x00\x00\x14\x00\x00\x00\x01\x00\x00\x00\x00FLEX\x00\x00\x00\x00',
                'expected_fields': ['length', 'version', 'command', 'data']
            },
            'license_request': {
                'data': b'\x00\x00\x00\x30\x00\x00\x00\x02\x00\x00\x00\x01CHECKOUT\x00PHOTOSHOP\x00USER123\x00HOST456\x00',
                'feature': 'PHOTOSHOP',
                'user': 'USER123',
                'host': 'HOST456'
            },
            'heartbeat': {
                'data': b'\x00\x00\x00\x10\x00\x00\x00\x03\x00\x00\x00\x00HEARTBEAT\x00',
                'interval': 30
            }
        }

    @pytest.fixture
    def hasp_protocol_data(self):
        """Create REAL HASP protocol data for testing."""
        return {
            'init_packet': {
                'header': b'HASP',
                'version': b'\x00\x01',
                'command': b'\x00\x01',  # INIT
                'data_length': b'\x00\x00\x00\x10',
                'data': b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
            },
            'login_packet': {
                'header': b'HASP',
                'version': b'\x00\x01',
                'command': b'\x00\x02',  # LOGIN
                'feature_id': b'\x00\x00\x00\x01',
                'vendor_code': b'VENDOR123456789\x00'
            },
            'encrypt_packet': {
                'header': b'HASP',
                'version': b'\x00\x01',
                'command': b'\x00\x10',  # ENCRYPT
                'data': b'plaintext_data_to_encrypt\x00'
            }
        }

    @pytest.fixture
    def adobe_license_data(self):
        """Create REAL Adobe license protocol data."""
        return {
            'activation_request': {
                'header': b'ADBE\x00\x01',
                'product_id': b'PHSP2023',
                'machine_id': b'1234567890ABCDEF',
                'request_type': b'\x01',  # ACTIVATION
                'timestamp': struct.pack('>I', int(time.time()))
            },
            'validation_check': {
                'header': b'ADBE\x00\x01',
                'license_key': b'A3B7-K9M2-P5R8-Q4N6',
                'product_id': b'PHSP2023',
                'request_type': b'\x02'  # VALIDATION
            }
        }

    @pytest.fixture
    def app_context(self):
        """Create REAL application context."""
        context = AppContext()
        context.initialize()
        return context

    def test_real_flexlm_license_emulation(self, flexlm_protocol_data):
        """Test REAL FlexLM license server emulation."""
        hooker = CloudLicenseHooker()

        # Test FlexLM packet parsing
        handshake_data = flexlm_protocol_data['handshake']['data']
        parsed = hooker.parse_flexlm_packet(handshake_data)
        assert parsed is not None, "Must parse FlexLM handshake"
        assert 'packet_type' in parsed, "Must identify packet type"
        assert parsed['packet_type'] == 'handshake', "Must identify as handshake"

        # Test license checkout request
        checkout_data = flexlm_protocol_data['license_request']['data']
        checkout_parsed = hooker.parse_flexlm_packet(checkout_data)
        assert checkout_parsed is not None, "Must parse checkout request"
        assert 'feature' in checkout_parsed, "Must extract feature name"
        assert checkout_parsed['feature'] == flexlm_protocol_data['license_request']['feature'], \
            "Must correctly extract feature name"

        # Test response generation
        response = hooker.generate_flexlm_response(checkout_parsed)
        assert response is not None, "Must generate FlexLM response"
        assert len(response) > 0, "Response must not be empty"
        assert response[:4] == b'\x00\x00\x00', "Response must have valid length header"

        # Test server emulation
        server = hooker.create_flexlm_server(port=0)
        assert server is not None, "Must create FlexLM server"

        try:
            server_started = hooker.start_license_server(server)
            assert server_started, "FlexLM server must start"

            server_port = server.get_port()
            assert server_port > 0, "Server must have valid port"

            # Test client connection
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                client_socket.settimeout(5.0)
                client_socket.connect(('127.0.0.1', server_port))

                # Send handshake
                client_socket.send(handshake_data)
                response = client_socket.recv(1024)
                assert len(response) > 0, "Must receive handshake response"

            finally:
                client_socket.close()

        finally:
            hooker.stop_license_server(server)

    def test_real_hasp_dongle_emulation(self, hasp_protocol_data):
        """Test REAL HASP dongle emulation."""
        hooker = CloudLicenseHooker()

        # Build HASP init packet
        init_data = hasp_protocol_data['init_packet']
        init_packet = init_data['header'] + init_data['version'] + \
                     init_data['command'] + init_data['data_length'] + init_data['data']

        # Parse HASP packet
        parsed = hooker.parse_hasp_packet(init_packet)
        assert parsed is not None, "Must parse HASP init packet"
        assert parsed['command'] == 1, "Must identify INIT command"
        assert 'data' in parsed, "Must extract packet data"

        # Test HASP login
        login_data = hasp_protocol_data['login_packet']
        login_packet = login_data['header'] + login_data['version'] + \
                      login_data['command'] + login_data['feature_id'] + login_data['vendor_code']

        login_parsed = hooker.parse_hasp_packet(login_packet)
        assert login_parsed is not None, "Must parse HASP login"
        assert login_parsed['command'] == 2, "Must identify LOGIN command"
        assert 'vendor_code' in login_parsed, "Must extract vendor code"

        # Test dongle emulation
        dongle = hooker.create_virtual_hasp_dongle()
        assert dongle is not None, "Must create virtual HASP dongle"
        assert 'dongle_id' in dongle, "Dongle must have ID"
        assert 'memory' in dongle, "Dongle must have memory"
        assert 'features' in dongle, "Dongle must have features"

        # Test encryption function
        encrypt_data = hasp_protocol_data['encrypt_packet']
        plaintext = encrypt_data['data']

        encrypted = hooker.hasp_encrypt(dongle, plaintext)
        assert encrypted is not None, "HASP encryption must succeed"
        assert encrypted != plaintext, "Encrypted data must differ from plaintext"
        assert len(encrypted) >= len(plaintext), "Encrypted data size must be appropriate"

    def test_real_adobe_license_protocol(self, adobe_license_data):
        """Test REAL Adobe license protocol emulation."""
        hooker = CloudLicenseHooker()

        # Build activation request
        activation = adobe_license_data['activation_request']
        activation_packet = activation['header'] + activation['product_id'] + \
                          activation['machine_id'] + activation['request_type'] + \
                          activation['timestamp']

        # Parse Adobe packet
        parsed = hooker.parse_adobe_packet(activation_packet)
        assert parsed is not None, "Must parse Adobe activation request"
        assert parsed['request_type'] == 'activation', "Must identify activation request"
        assert 'product_id' in parsed, "Must extract product ID"
        assert parsed['product_id'] == 'PHSP2023', "Must correctly extract product ID"

        # Generate activation response
        activation_response = hooker.generate_adobe_activation_response(parsed)
        assert activation_response is not None, "Must generate activation response"
        assert 'license_key' in activation_response, "Response must contain license key"
        assert 'activation_data' in activation_response, "Response must contain activation data"
        assert 'expiry_date' in activation_response, "Response must contain expiry date"

        # Test validation
        validation = adobe_license_data['validation_check']
        validation_packet = validation['header'] + validation['license_key'] + \
                          validation['product_id'] + validation['request_type']

        validation_parsed = hooker.parse_adobe_packet(validation_packet)
        assert validation_parsed is not None, "Must parse validation request"

        validation_response = hooker.validate_adobe_license(validation_parsed)
        assert validation_response is not None, "Must validate license"
        assert 'valid' in validation_response, "Validation must return status"
        assert 'features' in validation_response, "Validation must return features"

    def test_real_license_server_encryption(self, app_context):
        """Test REAL encrypted communication with license servers."""
        hooker = CloudLicenseHooker()

        # Test encrypted license validation protocol
        test_license_data = {
            'product_id': 'TEST_PRODUCT_2024',
            'license_key': 'L1C3-N5E7-K3Y9-T3ST',
            'machine_id': 'MACHINE_UNIQUE_ID_001',
            'user_info': 'testuser@example.com'
        }

        # Create encrypted license request
        encryption_key = hooker.generate_encryption_key()
        assert encryption_key is not None, "Must generate encryption key"
        assert len(encryption_key) >= 16, "Key must be at least 128 bits"

        # Encrypt license data
        encrypted_request = hooker.encrypt_license_request(test_license_data, encryption_key)
        assert encrypted_request is not None, "Must encrypt license request"
        assert encrypted_request != str(test_license_data).encode(), "Data must be encrypted"

        # Decrypt and verify
        decrypted_data = hooker.decrypt_license_request(encrypted_request, encryption_key)
        assert decrypted_data is not None, "Must decrypt license request"
        assert decrypted_data['product_id'] == test_license_data['product_id'], "Data integrity must be preserved"

        # Test secure license validation response
        validation_response = hooker.generate_secure_validation_response(test_license_data)
        assert validation_response is not None, "Must generate validation response"
        assert 'signature' in validation_response, "Response must be signed"
        assert 'timestamp' in validation_response, "Response must have timestamp"
        assert 'features' in validation_response, "Response must specify features"

        # Verify signature
        signature_valid = hooker.verify_response_signature(validation_response)
        assert signature_valid, "Response signature must be valid"

    def test_real_network_capture_analysis(self, app_context):
        """Test REAL network capture and protocol analysis."""
        capture = NetworkCapture()

        # Create test PCAP data
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as temp_file:
            # PCAP global header
            pcap_header = struct.pack('<IHHIIII',
                0xa1b2c3d4,  # magic number
                2, 4,        # version
                0,           # timezone
                0,           # timestamp accuracy
                65535,       # max packet length
                1            # ethernet
            )

            # Create license protocol packets
            packets = []

            # FlexLM packet
            flexlm_data = b'\x00\x00\x00\x14\x00\x00\x00\x01FLEX'
            eth_header = b'\xff' * 6 + b'\x00' * 6 + b'\x08\x00'
            ip_header = b'\x45\x00' + struct.pack('>H', 20 + 8 + len(flexlm_data))
            ip_header += b'\x00\x00\x40\x00\x40\x06\x00\x00'
            ip_header += socket.inet_aton('192.168.1.100')
            ip_header += socket.inet_aton('192.168.1.200')
            tcp_header = struct.pack('>HH', 1947, 12345) + b'\x00' * 16

            packet1 = eth_header + ip_header + tcp_header + flexlm_data

            # HASP packet
            hasp_data = b'HASP\x00\x01\x00\x01\x00\x00\x00\x10'
            packet2 = eth_header + ip_header + tcp_header + hasp_data

            # Write packets
            temp_file.write(pcap_header)

            for packet in [packet1, packet2]:
                # Packet header
                timestamp = int(time.time())
                packet_header = struct.pack('<IIII',
                    timestamp, 0,      # timestamp
                    len(packet),       # captured length
                    len(packet)        # original length
                )
                temp_file.write(packet_header + packet)

            temp_file.flush()
            pcap_file = temp_file.name

        try:
            # Parse PCAP
            parsed = capture.parse_pcap_file(pcap_file)
            assert parsed is not None, "Must parse PCAP file"
            assert 'packets' in parsed, "Must extract packets"
            assert len(parsed['packets']) >= 2, "Must parse both packets"

            # Analyze protocols
            for packet in parsed['packets']:
                protocol = capture.detect_license_protocol(packet)
                if protocol:
                    assert 'protocol' in protocol, "Must identify protocol"
                    assert protocol['protocol'] in ['flexlm', 'hasp', 'adobe'], \
                        "Must identify known license protocol"

                    # Extract and analyze payload
                    payload = capture.extract_license_payload(packet, protocol['protocol'])
                    assert payload is not None, "Must extract license payload"

            # Generate analysis report
            analysis = capture.analyze_capture_for_licenses(parsed)
            assert analysis is not None, "Must generate analysis"
            assert 'license_protocols_found' in analysis, "Must identify license protocols"
            assert 'statistics' in analysis, "Must include statistics"

        finally:
            os.unlink(pcap_file)

    def test_real_multi_protocol_switching(self, app_context):
        """Test REAL multi-protocol communication switching."""
        protocols = CommunicationProtocols()

        # Test protocol configurations
        protocol_configs = {
            'http': {
                'port': 8080,
                'headers': {'User-Agent': 'Mozilla/5.0'},
                'encryption': False
            },
            'https': {
                'port': 8443,
                'headers': {'User-Agent': 'Mozilla/5.0'},
                'encryption': True,
                'cert_validation': False
            },
            'dns': {
                'port': 53,
                'query_type': 'TXT',
                'domain': 'c2.example.com'
            },
            'custom_tcp': {
                'port': 9999,
                'packet_size': 1024,
                'obfuscation': True
            }
        }

        for protocol_name, config in protocol_configs.items():
            # Initialize protocol
            initialized = protocols.initialize_protocol(protocol_name, config)
            assert initialized, f"Must initialize {protocol_name} protocol"

            # Get protocol handler
            handler = protocols.get_protocol_handler(protocol_name)
            assert handler is not None, f"Must get handler for {protocol_name}"

            # Test protocol-specific features
            if protocol_name == 'http':
                request = handler.build_request('GET', '/beacon', {'id': '12345'})
                assert request is not None, "Must build HTTP request"
                assert b'GET /beacon' in request, "Request must contain method and path"

            elif protocol_name == 'https':
                assert handler.is_encrypted(), "HTTPS must be encrypted"
                assert 'cert_validation' in handler.get_config(), "Must have cert config"

            elif protocol_name == 'dns':
                query = handler.build_dns_query('test.c2.example.com', 'TXT')
                assert query is not None, "Must build DNS query"
                assert len(query) > 12, "DNS query must have header and question"

            elif protocol_name == 'custom_tcp':
                packet = handler.build_custom_packet(b'test_data')
                assert packet is not None, "Must build custom packet"
                if config.get('obfuscation'):
                    assert packet != b'test_data', "Packet must be obfuscated"

    def test_real_session_management(self, app_context):
        """Test REAL session management functionality."""
        session_manager = SessionManager()

        # Create multiple client sessions
        client_sessions = []
        for i in range(5):
            session_data = {
                'client_id': f'client_{i}',
                'ip_address': f'192.168.1.{100+i}',
                'connection_time': time.time(),
                'protocol': 'tcp',
                'encryption': True
            }

            session_id = session_manager.create_session(session_data)
            assert session_id is not None, f"Must create session for client_{i}"
            client_sessions.append(session_id)

        # Test session retrieval
        all_sessions = session_manager.get_active_sessions()
        assert len(all_sessions) == 5, "Must track all sessions"

        # Test session operations
        for session_id in client_sessions[:3]:
            # Update session activity
            updated = session_manager.update_session_activity(session_id, {
                'last_command': 'heartbeat',
                'bytes_transferred': 1024
            })
            assert updated, f"Must update session {session_id}"

            # Get session details
            details = session_manager.get_session_details(session_id)
            assert details is not None, f"Must get details for {session_id}"
            assert 'last_activity' in details, "Must track last activity"
            assert 'bytes_transferred' in details, "Must track data transfer"

        # Test session termination
        for session_id in client_sessions[3:]:
            terminated = session_manager.terminate_session(session_id)
            assert terminated, f"Must terminate session {session_id}"

        # Verify active sessions
        remaining = session_manager.get_active_sessions()
        assert len(remaining) == 3, "Must have correct remaining sessions"

        # Test session persistence
        session_data = session_manager.export_session_data()
        assert session_data is not None, "Must export session data"
        assert 'active_sessions' in session_data, "Must include active sessions"
        assert 'terminated_sessions' in session_data, "Must include terminated sessions"

    def test_real_protocol_fuzzing(self, flexlm_protocol_data, app_context):
        """Test REAL protocol fuzzing for license bypass."""
        hooker = CloudLicenseHooker()

        # Create fuzzing templates
        fuzz_templates = {
            'length_overflow': lambda data: b'\xff\xff\xff\xff' + data[4:],
            'command_injection': lambda data: data[:8] + b'\x00\x00\x00\x00' + b'A' * 100,
            'format_string': lambda data: data[:12] + b'%s%s%s%s%n%n%n%n',
            'null_bytes': lambda data: data.replace(b'FLEX', b'\x00\x00\x00\x00'),
            'unicode_injection': lambda data: data + b'\xff\xfe\x00\x00'
        }

        original_packet = flexlm_protocol_data['license_request']['data']

        for fuzz_name, fuzz_func in fuzz_templates.items():
            # Generate fuzzed packet
            fuzzed = fuzz_func(original_packet)
            assert fuzzed != original_packet, f"Fuzz {fuzz_name} must modify packet"

            # Test parsing robustness
            try:
                parsed = hooker.parse_flexlm_packet(fuzzed)
                # If parsing succeeds, check for anomalies
                if parsed:
                    assert 'anomaly_detected' in parsed or 'warning' in parsed, \
                        f"Should detect anomaly in {fuzz_name}"
            except Exception as e:
                # Exception is expected for malformed packets
                assert 'parse' in str(e).lower() or 'invalid' in str(e).lower(), \
                    f"Exception should be parsing-related for {fuzz_name}"

    def test_real_license_server_rate_limiting(self, app_context):
        """Test REAL rate limiting for license server communication."""
        hooker = CloudLicenseHooker()

        # Configure rate limiting for license checks
        rate_limit_config = {
            'max_requests_per_minute': 10,
            'max_requests_per_hour': 100,
            'burst_size': 5,
            'cooldown_seconds': 60
        }

        # Create rate limiter for license validation
        rate_limiter = hooker.create_rate_limiter(rate_limit_config)
        assert rate_limiter is not None, "Must create rate limiter"

        # Test burst requests
        burst_requests = []
        for i in range(rate_limit_config['burst_size']):
            request_data = {
                'license_key': f'TEST-KEY-{i:04d}-PROD',
                'timestamp': time.time()
            }

            allowed = rate_limiter.check_request(request_data)
            assert allowed, f"Burst request {i} must be allowed"
            burst_requests.append(request_data)

        # Test rate limit enforcement
        excess_request = {
            'license_key': 'TEST-KEY-EXCESS-PROD',
            'timestamp': time.time()
        }

        allowed = rate_limiter.check_request(excess_request)
        assert not allowed, "Request exceeding burst limit must be denied"

        # Test cooldown period
        remaining_cooldown = rate_limiter.get_cooldown_remaining()
        assert remaining_cooldown > 0, "Cooldown period must be active"
        assert remaining_cooldown <= rate_limit_config['cooldown_seconds'], "Cooldown must not exceed configured limit"

        # Test request history tracking
        history = rate_limiter.get_request_history()
        assert len(history) == rate_limit_config['burst_size'], "History must track all burst requests"
        assert all('timestamp' in req for req in history), "All requests must have timestamps"

    def test_real_license_protocol_obfuscation(self, app_context):
        """Test REAL license protocol obfuscation techniques."""
        hooker = CloudLicenseHooker()

        # Test license key obfuscation methods
        obfuscation_config = {
            'method': 'xor_cipher',
            'key': b'OBFUSCATION_KEY_2024',
            'iterations': 3
        }

        # Obfuscate license data
        test_license = b'PROD-2024-ABCD-1234-EFGH'
        obfuscated = hooker.obfuscate_license_data(test_license, obfuscation_config)
        assert obfuscated is not None, "Must obfuscate license data"
        assert obfuscated != test_license, "Obfuscated data must differ from original"

        # Test deobfuscation
        deobfuscated = hooker.deobfuscate_license_data(obfuscated, obfuscation_config)
        assert deobfuscated == test_license, "Must correctly deobfuscate license"

        # Test steganographic embedding in executable
        stego_config = {
            'embed_location': 'pe_overlay',
            'encoding': 'base64',
            'marker': b'\x4C\x49\x43\x45'  # 'LICE' marker
        }

        embedded_data = hooker.embed_license_in_binary(test_license, stego_config)
        assert embedded_data is not None, "Must embed license in binary format"
        assert len(embedded_data) > len(test_license), "Embedded data must include container"

        # Test extraction
        extracted = hooker.extract_license_from_binary(embedded_data, stego_config)
        assert extracted == test_license, "Must extract original license"

        # Test polymorphic license encoding
        poly_config = {
            'algorithm': 'rolling_xor',
            'seed': 0x12345678,
            'rounds': 5
        }

        poly_encoded = hooker.polymorphic_encode_license(test_license, poly_config)
        assert poly_encoded is not None, "Must perform polymorphic encoding"
        assert poly_encoded != test_license, "Polymorphic encoding must transform data"

        # Each encoding should be different with same input
        poly_encoded2 = hooker.polymorphic_encode_license(test_license, poly_config)
        assert poly_encoded != poly_encoded2, "Polymorphic encoding must vary"

        # But decoding should recover original
        poly_decoded = hooker.polymorphic_decode_license(poly_encoded, poly_config)
        assert poly_decoded == test_license, "Must decode to original license"

    def test_real_license_server_anti_detection(self, app_context):
        """Test REAL anti-detection techniques for license server emulation."""
        hooker = CloudLicenseHooker()

        # Test legitimate-looking license server responses
        server_config = {
            'server_name': 'licensing.legitimate-software.com',
            'port': 27000,  # Standard FlexLM port
            'vendor_daemon': 'vendor_daemon_v2.1',
            'response_delay_ms': 50  # Realistic delay
        }

        # Create realistic license server response
        test_request = {
            'feature': 'professional_edition',
            'version': '2024.1',
            'user': 'licensed_user',
            'host': 'workstation01'
        }

        response = hooker.generate_realistic_license_response(test_request, server_config)
        assert response is not None, "Must generate realistic response"
        assert 'grant_time' in response, "Response must include grant time"
        assert 'expiry_time' in response, "Response must include expiry"
        assert response['vendor'] == server_config['vendor_daemon'], "Must use configured vendor"

        # Test traffic pattern mimicry
        pattern_config = {
            'mimic_product': 'adobe_creative_cloud',
            'heartbeat_interval': 300,  # 5 minutes
            'validation_frequency': 'on_startup',
            'include_telemetry': True
        }

        traffic_pattern = hooker.generate_traffic_pattern(pattern_config)
        assert traffic_pattern is not None, "Must generate traffic pattern"
        assert 'heartbeat_schedule' in traffic_pattern, "Must include heartbeat schedule"
        assert traffic_pattern['heartbeat_interval'] == pattern_config['heartbeat_interval'], "Must use configured interval"

        # Test certificate spoofing for HTTPS license checks
        cert_config = {
            'common_name': 'licensing.legitimate-software.com',
            'organization': 'Legitimate Software Inc.',
            'validity_days': 365,
            'key_size': 2048
        }

        spoofed_cert = hooker.generate_spoofed_certificate(cert_config)
        assert spoofed_cert is not None, "Must generate certificate"
        assert 'certificate' in spoofed_cert, "Must include certificate data"
        assert 'private_key' in spoofed_cert, "Must include private key"
        assert spoofed_cert['common_name'] == cert_config['common_name'], "Certificate must have correct CN"
