"""
Unit tests for Protocol Parsers with REAL protocol parsing.
Tests REAL license protocol parsing including FlexLM, HASP, Adobe, and KMS.
NO MOCKS - ALL TESTS USE REAL NETWORK CAPTURES AND PRODUCE REAL RESULTS.
"""

import pytest
from pathlib import Path
import struct

from intellicrack.core.network.protocol_parsers import ProtocolParser
from tests.base_test import IntellicrackTestBase


class TestProtocolParsers(IntellicrackTestBase):
    """Test protocol parsing with REAL network captures."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with real protocol parser."""
        self.parser = ProtocolParser()
        self.test_dir = Path(__file__).parent.parent.parent / 'fixtures' / 'network'
        
        # Real protocol captures
        self.flexlm_capture = self.test_dir / 'flexlm_handshake.pcap'
        self.hasp_capture = self.test_dir / 'hasp_activation.pcap'
        self.adobe_capture = self.test_dir / 'adobe_licensing.pcap'
        self.kms_capture = self.test_dir / 'kms_activation.pcap'
        
    def test_flexlm_protocol_parsing(self):
        """Test FlexLM protocol parsing from real capture."""
        if not self.flexlm_capture.exists():
            pytest.skip("FlexLM capture not found")
            
        packets = self.parser.parse_pcap(self.flexlm_capture)
        flexlm_packets = self.parser.filter_flexlm_packets(packets)
        
        self.assert_real_output(flexlm_packets)
        assert len(flexlm_packets) > 0
        
        # Parse FlexLM handshake
        for packet in flexlm_packets:
            parsed = self.parser.parse_flexlm_packet(packet)
            
            assert 'version' in parsed
            assert 'message_type' in parsed
            assert 'transaction_id' in parsed
            
            # Validate FlexLM structure
            if parsed['message_type'] == 'LICENSE_REQUEST':
                assert 'feature' in parsed
                assert 'version_requested' in parsed
                assert 'client_id' in parsed
                
            elif parsed['message_type'] == 'LICENSE_GRANT':
                assert 'license_key' in parsed
                assert 'expiry' in parsed
                assert 'features' in parsed
                
    def test_hasp_protocol_parsing(self):
        """Test HASP protocol parsing from real capture."""
        if not self.hasp_capture.exists():
            pytest.skip("HASP capture not found")
            
        packets = self.parser.parse_pcap(self.hasp_capture)
        hasp_packets = self.parser.filter_hasp_packets(packets)
        
        self.assert_real_output(hasp_packets)
        assert len(hasp_packets) > 0
        
        # Parse HASP communication
        for packet in hasp_packets:
            parsed = self.parser.parse_hasp_packet(packet)
            
            assert 'command' in parsed
            assert 'status' in parsed
            
            # HASP specific fields
            if parsed['command'] == 'AUTH':
                assert 'vendor_code' in parsed
                assert 'challenge' in parsed
                
            elif parsed['command'] == 'RESPONSE':
                assert 'auth_response' in parsed
                assert 'session_id' in parsed
                
    def test_adobe_licensing_parsing(self):
        """Test Adobe licensing protocol parsing."""
        if not self.adobe_capture.exists():
            pytest.skip("Adobe capture not found")
            
        packets = self.parser.parse_pcap(self.adobe_capture)
        adobe_packets = self.parser.filter_adobe_packets(packets)
        
        self.assert_real_output(adobe_packets)
        
        for packet in adobe_packets:
            parsed = self.parser.parse_adobe_packet(packet)
            
            assert 'protocol_version' in parsed
            assert 'request_type' in parsed
            
            # Adobe specific validation
            if parsed['request_type'] == 'ACTIVATION':
                assert 'serial_number' in parsed
                assert 'machine_id' in parsed
                assert 'product_id' in parsed
                
            elif parsed['request_type'] == 'VALIDATION':
                assert 'license_token' in parsed
                assert 'timestamp' in parsed
                
    def test_kms_protocol_parsing(self):
        """Test KMS (Key Management Service) protocol parsing."""
        if not self.kms_capture.exists():
            pytest.skip("KMS capture not found")
            
        packets = self.parser.parse_pcap(self.kms_capture)
        kms_packets = self.parser.filter_kms_packets(packets)
        
        self.assert_real_output(kms_packets)
        assert len(kms_packets) > 0
        
        for packet in kms_packets:
            parsed = self.parser.parse_kms_packet(packet)
            
            assert 'message_type' in parsed
            assert 'version' in parsed
            
            # KMS specific fields
            if parsed['message_type'] == 'ACTIVATION_REQUEST':
                assert 'client_machine_id' in parsed
                assert 'application_id' in parsed
                assert 'kms_count' in parsed
                
            elif parsed['message_type'] == 'ACTIVATION_RESPONSE':
                assert 'response_timestamp' in parsed
                assert 'activation_interval' in parsed
                assert 'renewal_interval' in parsed
                
    def test_protocol_identification(self):
        """Test automatic protocol identification."""
        # Test with unknown packet data
        test_data = b'\x01\x47\x00\x01\x12\x34\x56\x78'  # FlexLM-like
        
        protocol = self.parser.identify_protocol(test_data)
        
        self.assert_real_output(protocol)
        assert protocol in ['flexlm', 'hasp', 'adobe', 'kms', 'unknown']
        
    def test_license_key_extraction(self):
        """Test license key extraction from protocols."""
        if not self.flexlm_capture.exists():
            pytest.skip("Capture files not found")
            
        packets = self.parser.parse_pcap(self.flexlm_capture)
        
        # Extract license keys
        keys = self.parser.extract_license_keys(packets)
        
        self.assert_real_output(keys)
        assert isinstance(keys, list)
        
        for key_info in keys:
            assert 'protocol' in key_info
            assert 'key' in key_info
            assert 'metadata' in key_info
            
            # Validate key format
            key = key_info['key']
            assert len(key) > 0
            assert not key.startswith('MOCK_')
            
    def test_handshake_sequence_analysis(self):
        """Test protocol handshake sequence analysis."""
        if not self.flexlm_capture.exists():
            pytest.skip("Capture files not found")
            
        packets = self.parser.parse_pcap(self.flexlm_capture)
        
        # Analyze handshake
        handshake = self.parser.analyze_handshake_sequence(packets)
        
        self.assert_real_output(handshake)
        assert 'steps' in handshake
        assert 'complete' in handshake
        assert 'protocol' in handshake
        
        # Validate handshake steps
        for step in handshake['steps']:
            assert 'timestamp' in step
            assert 'direction' in step  # client->server or server->client
            assert 'message_type' in step
            assert 'data' in step
            
    def test_protocol_state_machine(self):
        """Test protocol state machine reconstruction."""
        if not self.hasp_capture.exists():
            pytest.skip("HASP capture not found")
            
        packets = self.parser.parse_pcap(self.hasp_capture)
        
        # Build state machine
        state_machine = self.parser.build_protocol_state_machine(packets)
        
        self.assert_real_output(state_machine)
        assert 'states' in state_machine
        assert 'transitions' in state_machine
        assert 'initial_state' in state_machine
        
        # Validate states
        assert len(state_machine['states']) > 2
        assert 'INIT' in state_machine['states']
        assert 'AUTHENTICATED' in state_machine['states']
        
    def test_custom_protocol_parsing(self):
        """Test parsing custom/proprietary protocols."""
        # Custom protocol data
        custom_data = struct.pack('>HHI8s', 
            0xDEAD,  # Magic
            0x0001,  # Version
            0x12345678,  # Session ID
            b'TESTAPP\x00'  # App name
        )
        
        # Define custom protocol structure
        custom_format = {
            'magic': '>H',
            'version': '>H',
            'session_id': '>I',
            'app_name': '8s'
        }
        
        parsed = self.parser.parse_custom_protocol(custom_data, custom_format)
        
        self.assert_real_output(parsed)
        assert parsed['magic'] == 0xDEAD
        assert parsed['version'] == 1
        assert parsed['session_id'] == 0x12345678
        assert b'TESTAPP' in parsed['app_name']
        
    def test_protocol_fuzzing_detection(self):
        """Test detection of protocol fuzzing attempts."""
        if not self.flexlm_capture.exists():
            pytest.skip("Capture files not found")
            
        packets = self.parser.parse_pcap(self.flexlm_capture)
        
        # Detect anomalies
        anomalies = self.parser.detect_protocol_anomalies(packets)
        
        self.assert_real_output(anomalies)
        assert isinstance(anomalies, list)
        
        for anomaly in anomalies:
            assert 'type' in anomaly
            assert 'severity' in anomaly
            assert 'description' in anomaly
            assert 'packet_index' in anomaly
            
    def test_protocol_encryption_detection(self):
        """Test detection of encrypted protocol data."""
        # Test various packet types
        test_packets = [
            b'\x00\x01\x02\x03\x04\x05',  # Sequential - not encrypted
            b'\x8f\xa2\x3e\x91\xcc\x45',  # Random - possibly encrypted
            b'LICENSE:TEST123',  # Plaintext
        ]
        
        for packet in test_packets:
            result = self.parser.detect_encryption(packet)
            
            self.assert_real_output(result)
            assert 'encrypted' in result
            assert 'confidence' in result
            assert 'entropy' in result
            
            # Validate entropy calculation
            assert 0.0 <= result['entropy'] <= 8.0
            
    def test_protocol_timing_analysis(self):
        """Test protocol timing analysis."""
        if not self.flexlm_capture.exists():
            pytest.skip("Capture files not found")
            
        packets = self.parser.parse_pcap(self.flexlm_capture)
        
        # Analyze timing
        timing = self.parser.analyze_protocol_timing(packets)
        
        self.assert_real_output(timing)
        assert 'avg_response_time' in timing
        assert 'min_response_time' in timing
        assert 'max_response_time' in timing
        assert 'packet_intervals' in timing
        
        # Validate timing values
        assert timing['avg_response_time'] >= 0
        assert timing['min_response_time'] <= timing['avg_response_time']
        assert timing['max_response_time'] >= timing['avg_response_time']
        
    def test_protocol_replay_generation(self):
        """Test generation of protocol replay attacks."""
        if not self.hasp_capture.exists():
            pytest.skip("HASP capture not found")
            
        packets = self.parser.parse_pcap(self.hasp_capture)
        
        # Generate replay sequence
        replay = self.parser.generate_replay_sequence(packets)
        
        self.assert_real_output(replay)
        assert 'original_session' in replay
        assert 'replay_packets' in replay
        assert 'modifications' in replay
        
        # Replay should have modified timestamps
        assert len(replay['replay_packets']) > 0
        assert replay['modifications']['timestamp_shift'] != 0
        
    def test_protocol_field_extraction(self):
        """Test extraction of specific protocol fields."""
        if not self.adobe_capture.exists():
            pytest.skip("Adobe capture not found")
            
        packets = self.parser.parse_pcap(self.adobe_capture)
        
        # Extract specific fields
        fields = ['serial_number', 'machine_id', 'product_id']
        extracted = self.parser.extract_protocol_fields(packets, fields)
        
        self.assert_real_output(extracted)
        
        for field in fields:
            if field in extracted:
                assert len(extracted[field]) > 0
                # Values should be unique-ish
                assert len(set(extracted[field])) > 0
                
    def test_protocol_session_tracking(self):
        """Test protocol session tracking."""
        if not self.kms_capture.exists():
            pytest.skip("KMS capture not found")
            
        packets = self.parser.parse_pcap(self.kms_capture)
        
        # Track sessions
        sessions = self.parser.track_protocol_sessions(packets)
        
        self.assert_real_output(sessions)
        assert isinstance(sessions, list)
        
        for session in sessions:
            assert 'session_id' in session
            assert 'start_time' in session
            assert 'end_time' in session
            assert 'packet_count' in session
            assert 'client_addr' in session
            assert 'server_addr' in session
            
    def test_protocol_validation_rules(self):
        """Test protocol validation rule extraction."""
        if not self.flexlm_capture.exists():
            pytest.skip("Capture files not found")
            
        packets = self.parser.parse_pcap(self.flexlm_capture)
        
        # Extract validation rules
        rules = self.parser.extract_validation_rules(packets)
        
        self.assert_real_output(rules)
        assert 'field_constraints' in rules
        assert 'sequence_rules' in rules
        assert 'timing_constraints' in rules
        
        # Should identify some constraints
        assert len(rules['field_constraints']) > 0
        
    def test_protocol_error_handling(self):
        """Test protocol error message parsing."""
        # Simulate error packets
        error_packets = [
            b'ERROR:LICENSE_EXPIRED',
            b'ERROR:INVALID_KEY',
            b'ERROR:MAX_USERS_REACHED'
        ]
        
        for packet in error_packets:
            result = self.parser.parse_error_response(packet)
            
            self.assert_real_output(result)
            assert 'error_code' in result
            assert 'error_message' in result
            assert 'recoverable' in result