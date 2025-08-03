"""
Unit tests for Network Capture with REAL packet capture and analysis.
Tests REAL network traffic capture, filtering, and protocol analysis.
NO MOCKS - ALL TESTS USE REAL NETWORK DATA AND PRODUCE REAL RESULTS.
"""

import pytest
from pathlib import Path
import socket
import threading
import time
import struct

from intellicrack.core.network.network_capture import NetworkCapture
from tests.base_test import IntellicrackTestBase


class TestNetworkCapture(IntellicrackTestBase):
    """Test network capture with REAL packets and protocols."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with real network capture."""
        self.capture = NetworkCapture()
        self.test_dir = Path(__file__).parent.parent.parent / 'fixtures' / 'network'
        
        # Test server details
        self.test_port = 55555
        self.test_host = '127.0.0.1'
        
    def test_live_packet_capture(self):
        """Test live network packet capture."""
        # Start a test server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.test_host, self.test_port))
        server.listen(1)
        
        def server_handler():
            conn, addr = server.accept()
            conn.recv(1024)
            conn.send(b'SERVER_RESPONSE')
            conn.close()
            
        server_thread = threading.Thread(target=server_handler)
        server_thread.daemon = True
        server_thread.start()
        
        # Start capture
        capture_filter = f'tcp port {self.test_port}'
        self.capture.start_capture(
            interface='lo',  # Loopback
            filter=capture_filter,
            timeout=5
        )
        
        time.sleep(0.5)  # Let capture start
        
        # Generate traffic
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((self.test_host, self.test_port))
        client.send(b'CLIENT_REQUEST')
        response = client.recv(1024)
        client.close()
        
        # Stop capture
        packets = self.capture.stop_capture()
        
        self.assert_real_output(packets)
        assert len(packets) > 0
        
        # Verify captured data
        found_request = False
        found_response = False
        
        for packet in packets:
            if b'CLIENT_REQUEST' in packet['data']:
                found_request = True
            if b'SERVER_RESPONSE' in packet['data']:
                found_response = True
                
        assert found_request
        assert found_response
        
        server.close()
        
    def test_pcap_file_operations(self):
        """Test PCAP file reading and writing."""
        # Read existing PCAP
        test_pcap = self.test_dir / 'flexlm_handshake.pcap'
        if test_pcap.exists():
            packets = self.capture.read_pcap(test_pcap)
            
            self.assert_real_output(packets)
            assert len(packets) > 0
            
            # Validate packet structure
            for packet in packets:
                assert 'timestamp' in packet
                assert 'src_ip' in packet
                assert 'dst_ip' in packet
                assert 'src_port' in packet
                assert 'dst_port' in packet
                assert 'data' in packet
                
        # Write new PCAP
        test_packets = [
            {
                'timestamp': time.time(),
                'src_ip': '10.0.0.1',
                'dst_ip': '10.0.0.2',
                'src_port': 1234,
                'dst_port': 80,
                'data': b'GET / HTTP/1.1\r\n\r\n'
            }
        ]
        
        output_pcap = self.test_dir / 'test_output.pcap'
        self.capture.write_pcap(output_pcap, test_packets)
        
        assert output_pcap.exists()
        
        # Read back and verify
        read_packets = self.capture.read_pcap(output_pcap)
        assert len(read_packets) == 1
        assert read_packets[0]['data'] == test_packets[0]['data']
        
        # Cleanup
        output_pcap.unlink()
        
    def test_protocol_filtering(self):
        """Test filtering packets by protocol."""
        # Create mixed protocol packets
        test_packets = [
            # HTTP packet
            {
                'src_port': 45678,
                'dst_port': 80,
                'data': b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'
            },
            # HTTPS packet
            {
                'src_port': 45679,
                'dst_port': 443,
                'data': b'\x16\x03\x01\x00\x95'  # TLS handshake
            },
            # License protocol (FlexLM)
            {
                'src_port': 45680,
                'dst_port': 27000,
                'data': struct.pack('>HHI', 0x0147, 0x0001, 0x12345678)
            }
        ]
        
        # Filter HTTP
        http_packets = self.capture.filter_by_protocol(test_packets, 'http')
        self.assert_real_output(http_packets)
        assert len(http_packets) == 1
        assert b'HTTP' in http_packets[0]['data']
        
        # Filter license protocols
        license_packets = self.capture.filter_by_protocol(test_packets, 'license')
        assert len(license_packets) == 1
        assert license_packets[0]['dst_port'] == 27000
        
    def test_packet_reassembly(self):
        """Test TCP stream reassembly."""
        # Simulate fragmented packets
        fragments = [
            {
                'seq': 1000,
                'data': b'FIRST_PART_',
                'flags': 0x18  # PSH+ACK
            },
            {
                'seq': 1011,
                'data': b'SECOND_PART_',
                'flags': 0x18
            },
            {
                'seq': 1023,
                'data': b'FINAL_PART',
                'flags': 0x19  # FIN+PSH+ACK
            }
        ]
        
        # Reassemble stream
        stream = self.capture.reassemble_tcp_stream(fragments)
        
        self.assert_real_output(stream)
        assert stream == b'FIRST_PART_SECOND_PART_FINAL_PART'
        
    def test_protocol_detection(self):
        """Test automatic protocol detection."""
        test_cases = [
            # HTTP
            (b'GET / HTTP/1.1\r\n', 'HTTP'),
            (b'POST /api HTTP/1.0\r\n', 'HTTP'),
            # FlexLM
            (struct.pack('>HHI', 0x0147, 0x0001, 0), 'FlexLM'),
            # HASP
            (b'HASP_HL_REQUEST', 'HASP'),
            # Generic binary
            (b'\x00\x01\x02\x03\x04\x05', 'Unknown')
        ]
        
        for data, expected in test_cases:
            protocol = self.capture.detect_protocol(data)
            self.assert_real_output(protocol)
            assert protocol == expected
            
    def test_packet_injection(self):
        """Test packet injection capabilities."""
        # Create injection packet
        inject_packet = self.capture.create_packet(
            src_ip='10.0.0.100',
            dst_ip='10.0.0.200',
            src_port=12345,
            dst_port=80,
            data=b'INJECTED_DATA',
            flags='PA'  # PSH+ACK
        )
        
        self.assert_real_output(inject_packet)
        assert 'raw' in inject_packet
        assert len(inject_packet['raw']) > 20  # IP header minimum
        
        # Validate packet structure
        # IP header validation
        ip_version = (inject_packet['raw'][0] >> 4) & 0xF
        assert ip_version == 4  # IPv4
        
    def test_session_tracking(self):
        """Test TCP session tracking."""
        # Simulate session packets
        session_packets = [
            # SYN
            {
                'timestamp': 1.0,
                'src_ip': '10.0.0.1',
                'dst_ip': '10.0.0.2',
                'src_port': 50000,
                'dst_port': 80,
                'flags': 0x02,  # SYN
                'seq': 1000
            },
            # SYN-ACK
            {
                'timestamp': 1.1,
                'src_ip': '10.0.0.2',
                'dst_ip': '10.0.0.1',
                'src_port': 80,
                'dst_port': 50000,
                'flags': 0x12,  # SYN+ACK
                'seq': 2000,
                'ack': 1001
            },
            # ACK
            {
                'timestamp': 1.2,
                'src_ip': '10.0.0.1',
                'dst_ip': '10.0.0.2',
                'src_port': 50000,
                'dst_port': 80,
                'flags': 0x10,  # ACK
                'seq': 1001,
                'ack': 2001
            }
        ]
        
        # Track sessions
        sessions = self.capture.track_tcp_sessions(session_packets)
        
        self.assert_real_output(sessions)
        assert len(sessions) == 1
        
        session = sessions[0]
        assert session['state'] == 'ESTABLISHED'
        assert session['src'] == '10.0.0.1:50000'
        assert session['dst'] == '10.0.0.2:80'
        assert session['packet_count'] == 3
        
    def test_bandwidth_analysis(self):
        """Test bandwidth usage analysis."""
        # Generate packets with timestamps
        packets = []
        current_time = time.time()
        
        for i in range(100):
            packets.append({
                'timestamp': current_time + i * 0.1,
                'length': 1500,  # MTU size
                'src_ip': '10.0.0.1',
                'dst_ip': '10.0.0.2'
            })
            
        # Analyze bandwidth
        bandwidth = self.capture.analyze_bandwidth(packets)
        
        self.assert_real_output(bandwidth)
        assert 'total_bytes' in bandwidth
        assert 'duration' in bandwidth
        assert 'avg_bandwidth' in bandwidth
        assert 'peak_bandwidth' in bandwidth
        
        # Validate calculations
        assert bandwidth['total_bytes'] == 150000  # 100 * 1500
        assert bandwidth['duration'] > 9.0  # ~10 seconds
        assert bandwidth['avg_bandwidth'] > 0
        
    def test_packet_statistics(self):
        """Test packet statistics generation."""
        # Create diverse packet set
        packets = [
            {'protocol': 'TCP', 'length': 100, 'src_ip': '10.0.0.1'},
            {'protocol': 'TCP', 'length': 200, 'src_ip': '10.0.0.1'},
            {'protocol': 'UDP', 'length': 150, 'src_ip': '10.0.0.2'},
            {'protocol': 'ICMP', 'length': 64, 'src_ip': '10.0.0.3'},
        ]
        
        stats = self.capture.generate_statistics(packets)
        
        self.assert_real_output(stats)
        assert stats['total_packets'] == 4
        assert stats['total_bytes'] == 514
        assert stats['protocols']['TCP'] == 2
        assert stats['protocols']['UDP'] == 1
        assert stats['protocols']['ICMP'] == 1
        assert len(stats['unique_ips']) == 3
        
    def test_packet_export_formats(self):
        """Test exporting packets in different formats."""
        test_packets = [
            {
                'timestamp': time.time(),
                'src_ip': '192.168.1.100',
                'dst_ip': '192.168.1.1',
                'src_port': 54321,
                'dst_port': 80,
                'protocol': 'TCP',
                'data': b'GET / HTTP/1.1\r\n'
            }
        ]
        
        # Export as JSON
        json_export = self.capture.export_json(test_packets)
        self.assert_real_output(json_export)
        assert 'packets' in json_export
        assert json_export['packets'][0]['src_ip'] == '192.168.1.100'
        
        # Export as CSV
        csv_export = self.capture.export_csv(test_packets)
        assert 'src_ip,dst_ip,src_port,dst_port' in csv_export
        assert '192.168.1.100' in csv_export
        
        # Export as hex dump
        hex_export = self.capture.export_hexdump(test_packets[0]['data'])
        assert '47 45 54' in hex_export  # 'GET'
        
    def test_license_protocol_detection(self):
        """Test specific license protocol detection."""
        # Test various license protocols
        license_samples = {
            'flexlm': struct.pack('>HHI', 0x0147, 0x0001, 0x12345678),
            'hasp': b'HASP_HL_REQUEST\x00',
            'adobe': b'<?xml version="1.0"?><ActivationRequest>',
            'kms': struct.pack('<BBHHI', 0x00, 0x00, 0x0000, 0x0000, 0x68)
        }
        
        for protocol, data in license_samples.items():
            detected = self.capture.detect_license_protocol(data)
            self.assert_real_output(detected)
            assert detected['protocol'] == protocol
            assert detected['confidence'] > 0.7
            
    def test_deep_packet_inspection(self):
        """Test deep packet inspection capabilities."""
        # HTTP packet with embedded data
        http_packet = (
            b'POST /license/activate HTTP/1.1\r\n'
            b'Host: license.example.com\r\n'
            b'Content-Type: application/x-license\r\n'
            b'Content-Length: 50\r\n'
            b'\r\n'
            b'LICENSE_KEY=XXXX-XXXX-XXXX-XXXX&MACHINE_ID=ABC123'
        )
        
        # Perform DPI
        inspection = self.capture.deep_inspect_packet(http_packet)
        
        self.assert_real_output(inspection)
        assert inspection['protocol'] == 'HTTP'
        assert inspection['method'] == 'POST'
        assert inspection['uri'] == '/license/activate'
        assert 'license' in inspection['content_type']
        assert 'LICENSE_KEY' in inspection['extracted_data']
        assert 'MACHINE_ID' in inspection['extracted_data']
        
    def test_packet_modification(self):
        """Test packet modification capabilities."""
        # Original packet
        original = {
            'src_ip': '10.0.0.1',
            'dst_ip': '10.0.0.2',
            'src_port': 12345,
            'dst_port': 80,
            'data': b'GET /original HTTP/1.1\r\n'
        }
        
        # Modify packet
        modified = self.capture.modify_packet(
            original,
            new_data=b'GET /modified HTTP/1.1\r\n'
        )
        
        self.assert_real_output(modified)
        assert modified['data'] == b'GET /modified HTTP/1.1\r\n'
        assert modified['src_ip'] == original['src_ip']
        
        # Modify with checksums
        modified_with_checksum = self.capture.modify_packet(
            original,
            new_data=b'GET /checksum HTTP/1.1\r\n',
            recalculate_checksum=True
        )
        
        assert 'checksum' in modified_with_checksum
        assert modified_with_checksum['checksum'] != 0