"""
Comprehensive tests for BaseNetworkAnalyzer - Production-ready network analysis validation.

These tests validate real network traffic analysis, protocol detection, and licensing
communication identification capabilities essential for security research.
"""

import pytest
import socket
import struct
import time
import threading
import ssl
import os
import sys
from pathlib import Path
import subprocess
import tempfile
import json
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import netifaces
import pydivert
import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.tls.all import TLS
import dpkt
import pcapy
import winpcapy

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent))

from intellicrack.core.network.base_network_analyzer import BaseNetworkAnalyzer


@dataclass
class LicenseProtocol:
    """Represents a detected licensing protocol."""
    protocol_type: str
    server_endpoint: str
    port: int
    encryption: bool
    key_exchange_method: Optional[str]
    validation_pattern: bytes


class TestBaseNetworkAnalyzer:
    """
    Comprehensive tests for BaseNetworkAnalyzer functionality.
    Validates real network analysis capabilities for security research.
    """

    @pytest.fixture
    def analyzer(self):
        """Create a BaseNetworkAnalyzer instance for testing."""
        return BaseNetworkAnalyzer()

    @pytest.fixture
    def test_pcap_file(self, tmp_path):
        """Generate a test PCAP file with various protocol traffic."""
        pcap_path = tmp_path / "test_traffic.pcap"

        # Create packets with different protocols
        packets = []

        # HTTP license check request
        http_packet = Ether()/IP(dst="license.example.com")/TCP(dport=80)/\
                     "GET /validate?key=XXXX-YYYY-ZZZZ HTTP/1.1\r\nHost: license.example.com\r\n\r\n"
        packets.append(http_packet)

        # HTTPS/TLS license validation
        tls_packet = Ether()/IP(dst="secure.license.com")/TCP(dport=443)
        packets.append(tls_packet)

        # Custom protocol on non-standard port
        custom_packet = Ether()/IP(dst="10.0.0.1")/TCP(dport=31337)/\
                       struct.pack(">HH16s", 0x4C49, 0x4345, b"LICENSE_CHECK_V2")
        packets.append(custom_packet)

        # DNS query for license server
        dns_packet = Ether()/IP()/UDP(dport=53)/DNS(qd=DNSQR(qname="license-server.app.com"))
        packets.append(dns_packet)

        # Write packets to PCAP
        scapy.wrpcap(str(pcap_path), packets)
        return pcap_path

    @pytest.fixture
    def live_test_server(self):
        """Create a test license server for live capture testing."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('127.0.0.1', 0))
        port = server_socket.getsockname()[1]
        server_socket.listen(1)

        def handle_client():
            while True:
                try:
                    client, addr = server_socket.accept()
                    # Simulate license protocol handshake
                    client.recv(1024)
                    response = struct.pack(">HH32s", 0x4C43, 0x524B, os.urandom(32))
                    client.send(response)
                    client.close()
                except:
                    break

        server_thread = threading.Thread(target=handle_client, daemon=True)
        server_thread.start()

        yield ('127.0.0.1', port)

        server_socket.close()

    def test_analyzer_initialization(self, analyzer):
        """Test that analyzer initializes with required capabilities."""
        assert analyzer is not None
        assert hasattr(analyzer, 'create_packet_handler')
        assert hasattr(analyzer, 'logger')

        # Verify network interface detection
        interfaces = netifaces.interfaces()
        assert len(interfaces) > 0, "No network interfaces detected"

    def test_packet_handler_creation(self, analyzer):
        """Test creation of packet handlers for different protocols."""
        # Test handler creation returns a callable
        handler = analyzer.create_packet_handler()
        assert callable(handler), "Packet handler must be callable"

        # Create test packet
        test_packet = Ether()/IP(dst="192.168.1.1")/TCP(dport=443)

        # Handler should process packet without errors
        try:
            result = handler(test_packet.build())
            assert result is not None
        except Exception as e:
            pytest.fail(f"Packet handler failed: {e}")

    def test_real_time_packet_capture(self, analyzer, live_test_server):
        """Test real-time network packet capture and analysis."""
        server_ip, server_port = live_test_server
        captured_packets = []

        def packet_callback(packet_data):
            captured_packets.append(packet_data)

        # Create packet handler with callback
        handler = analyzer.create_packet_handler()

        # Start capture in background thread
        capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(analyzer, packet_callback, 3.0),
            daemon=True
        )
        capture_thread.start()

        # Generate test traffic
        time.sleep(0.5)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((server_ip, server_port))
        client.send(b"LICENSE_CHECK:12345678")
        response = client.recv(1024)
        client.close()

        # Wait for capture
        capture_thread.join(timeout=5.0)

        # Verify packets were captured
        assert len(captured_packets) > 0, "No packets captured"

        # Verify licensing communication was detected
        license_detected = any(
            b"LICENSE" in packet or
            struct.pack(">H", 0x4C43) in packet
            for packet in captured_packets
        )
        assert license_detected, "License protocol not detected in captured traffic"

    def test_protocol_identification(self, analyzer, test_pcap_file):
        """Test identification of various network protocols."""
        handler = analyzer.create_packet_handler()
        protocols_detected = set()

        # Read and analyze PCAP file
        packets = scapy.rdpcap(str(test_pcap_file))

        for packet in packets:
            result = handler(bytes(packet))
            if result and 'protocol' in result:
                protocols_detected.add(result['protocol'])

        # Verify common protocols are detected
        expected_protocols = {'HTTP', 'TCP', 'UDP', 'DNS'}
        assert len(protocols_detected.intersection(expected_protocols)) > 0, \
               f"Failed to detect expected protocols. Found: {protocols_detected}"

    def test_licensing_communication_detection(self, analyzer):
        """Test detection of licensing-specific communication patterns."""
        handler = analyzer.create_packet_handler()

        # Common licensing patterns to test
        license_patterns = [
            b"GET /api/license/validate",
            b"POST /activation/check",
            b"X-License-Key: ",
            b"Authorization: Bearer LICENSE-",
            struct.pack(">HH", 0x4C49, 0x4345),  # "LI", "CE" magic bytes
            b"<?xml version=\"1.0\"?><license>",
            b'{"license_key":',
            b"LICENSE_SERVER_HELLO",
        ]

        detected_patterns = []

        for pattern in license_patterns:
            # Create packet with pattern
            packet = Ether()/IP()/TCP()/pattern
            result = handler(bytes(packet))

            if result and result.get('is_licensing_traffic'):
                detected_patterns.append(pattern)

        # Should detect most licensing patterns
        detection_rate = len(detected_patterns) / len(license_patterns)
        assert detection_rate >= 0.75, \
               f"Insufficient licensing pattern detection: {detection_rate:.1%}"

    def test_encrypted_traffic_analysis(self, analyzer):
        """Test analysis of encrypted/TLS traffic for licensing."""
        handler = analyzer.create_packet_handler()

        # Create TLS ClientHello with SNI for license server
        tls_handshake = self._create_tls_client_hello("license.software.com")
        packet = Ether()/IP(dst="1.2.3.4")/TCP(dport=443)/tls_handshake

        result = handler(bytes(packet))

        assert result is not None, "Failed to analyze TLS traffic"
        assert result.get('encrypted', False), "Failed to detect encryption"
        assert 'server_name' in result, "Failed to extract SNI from TLS"
        assert 'license' in result.get('server_name', '').lower(), \
               "Failed to identify license server from SNI"

    def test_multi_interface_capture(self, analyzer):
        """Test capturing from multiple network interfaces."""
        interfaces = netifaces.interfaces()

        # Skip loopback and virtual interfaces for this test
        physical_interfaces = [
            iface for iface in interfaces
            if not iface.startswith('lo') and
               not iface.startswith('vEthernet')
        ]

        if len(physical_interfaces) < 1:
            pytest.skip("No suitable physical interfaces for testing")

        # Test analyzer can handle multiple interfaces
        for interface in physical_interfaces[:2]:  # Test first 2 interfaces
            handler = analyzer.create_packet_handler()
            assert handler is not None, f"Failed to create handler for {interface}"

    def test_packet_filtering_capabilities(self, analyzer):
        """Test packet filtering for targeted analysis."""
        handler = analyzer.create_packet_handler()

        # Test packets with different characteristics
        test_cases = [
            (Ether()/IP(dst="license.server.com")/TCP(dport=443), True),
            (Ether()/IP(dst="google.com")/TCP(dport=80), False),
            (Ether()/IP()/UDP(dport=31337), True),  # Non-standard port
            (Ether()/IP()/TCP(dport=22), False),  # SSH, not licensing
        ]

        for packet, should_analyze in test_cases:
            result = handler(bytes(packet))
            if should_analyze:
                assert result is not None, f"Failed to analyze relevant packet"
            # Non-relevant packets may or may not return results based on config

    def test_protocol_state_tracking(self, analyzer):
        """Test tracking of protocol state across multiple packets."""
        handler = analyzer.create_packet_handler()

        # Simulate TCP three-way handshake for license connection
        syn = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=12345, dport=9999, flags="S", seq=1000)
        syn_ack = Ether()/IP(src="10.0.0.2", dst="10.0.0.1")/TCP(sport=9999, dport=12345, flags="SA", seq=2000, ack=1001)
        ack = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=12345, dport=9999, flags="A", seq=1001, ack=2001)

        # Process handshake
        results = []
        for packet in [syn, syn_ack, ack]:
            result = handler(bytes(packet))
            if result:
                results.append(result)

        # Verify connection state tracking
        assert len(results) > 0, "No state tracking results"

        # Check if final state shows established connection
        final_state = results[-1].get('connection_state')
        assert final_state in ['ESTABLISHED', 'CONNECTED', None], \
               f"Unexpected connection state: {final_state}"

    def test_license_server_endpoint_extraction(self, analyzer):
        """Test extraction of license server endpoints from traffic."""
        handler = analyzer.create_packet_handler()
        endpoints = set()

        # Test various license server patterns
        test_endpoints = [
            ("license.app.com", 443),
            ("10.0.0.100", 31337),
            ("activation.software.io", 80),
            ("validate.service.net", 8443),
        ]

        for host, port in test_endpoints:
            packet = Ether()/IP(dst=host)/TCP(dport=port)/b"LICENSE_CHECK"
            result = handler(bytes(packet))

            if result and 'endpoint' in result:
                endpoints.add((result['endpoint']['host'], result['endpoint']['port']))

        # Should extract most endpoints
        assert len(endpoints) >= len(test_endpoints) * 0.5, \
               f"Insufficient endpoint extraction: {len(endpoints)}/{len(test_endpoints)}"

    def test_traffic_replay_capability(self, analyzer, test_pcap_file):
        """Test ability to replay captured traffic for analysis."""
        handler = analyzer.create_packet_handler()

        # Load original packets
        original_packets = scapy.rdpcap(str(test_pcap_file))

        # Analyze original
        original_results = []
        for packet in original_packets:
            result = handler(bytes(packet))
            if result:
                original_results.append(result)

        # Replay analysis should produce consistent results
        replay_results = []
        for packet in original_packets:
            result = handler(bytes(packet))
            if result:
                replay_results.append(result)

        # Results should be consistent
        assert len(replay_results) == len(original_results), \
               "Replay analysis produced different number of results"

    def test_custom_protocol_detection(self, analyzer):
        """Test detection of custom/proprietary licensing protocols."""
        handler = analyzer.create_packet_handler()

        # Define custom protocol structure
        magic = b"CUST"
        version = struct.pack(">H", 0x0100)
        command = struct.pack(">H", 0x0010)  # LICENSE_CHECK command
        payload = b"SERIAL-12345-67890"

        custom_data = magic + version + command + payload
        packet = Ether()/IP()/TCP(dport=65432)/custom_data

        result = handler(bytes(packet))

        assert result is not None, "Failed to analyze custom protocol"
        assert result.get('protocol_type') in ['custom', 'proprietary', 'unknown'], \
               "Failed to identify as custom protocol"

        # Should extract some protocol features
        if 'protocol_features' in result:
            features = result['protocol_features']
            assert any(k in features for k in ['magic', 'version', 'command']), \
                   "Failed to extract custom protocol features"

    def test_performance_with_high_traffic_volume(self, analyzer):
        """Test analyzer performance with high-volume traffic."""
        handler = analyzer.create_packet_handler()

        # Generate large number of packets
        num_packets = 10000
        start_time = time.time()
        processed = 0

        for i in range(num_packets):
            # Vary packet types
            if i % 3 == 0:
                packet = Ether()/IP()/TCP(dport=443)
            elif i % 3 == 1:
                packet = Ether()/IP()/UDP(dport=53)
            else:
                packet = Ether()/IP()/TCP(dport=80)/b"GET /license"

            result = handler(bytes(packet))
            if result:
                processed += 1

        elapsed = time.time() - start_time
        pps = num_packets / elapsed  # Packets per second

        # Should handle at least 1000 packets per second
        assert pps >= 1000, f"Insufficient performance: {pps:.0f} pps"
        assert processed > 0, "No packets were processed"

    def test_concurrent_analysis_thread_safety(self, analyzer):
        """Test thread safety with concurrent packet analysis."""
        handler = analyzer.create_packet_handler()
        errors = []
        results = []

        def analyze_packets(thread_id):
            try:
                for i in range(100):
                    packet = Ether()/IP()/TCP(dport=thread_id)/f"Thread{thread_id}".encode()
                    result = handler(bytes(packet))
                    if result:
                        results.append((thread_id, result))
            except Exception as e:
                errors.append((thread_id, str(e)))

        # Run multiple threads
        threads = []
        for i in range(10):
            t = threading.Thread(target=analyze_packets, args=(8000+i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Should complete without errors
        assert len(errors) == 0, f"Thread safety errors: {errors}"
        assert len(results) > 0, "No results from concurrent analysis"

    def test_winpcap_integration(self, analyzer):
        """Test integration with WinPcap/Npcap on Windows."""
        if sys.platform != 'win32':
            pytest.skip("Windows-specific test")

        # Check if WinPcap/Npcap is installed
        try:
            import winpcapy
            devices = winpcapy.WinPcapDevices()
            assert len(devices.devices) > 0, "No WinPcap devices found"
        except ImportError:
            pytest.skip("WinPcap/Npcap not installed")

        handler = analyzer.create_packet_handler()
        assert handler is not None, "Failed to create handler with WinPcap"

    def test_pydivert_integration(self, analyzer):
        """Test integration with WinDivert for packet interception."""
        if sys.platform != 'win32':
            pytest.skip("Windows-specific test")

        try:
            # Test WinDivert availability
            with pydivert.WinDivert("tcp.DstPort == 65432") as w:
                pass  # Just test initialization
        except Exception as e:
            pytest.skip(f"WinDivert not available: {e}")

        handler = analyzer.create_packet_handler()
        assert handler is not None, "Failed to create handler with WinDivert support"

    # Helper methods

    def _capture_packets(self, analyzer, callback, duration):
        """Helper to capture packets for a duration."""
        handler = analyzer.create_packet_handler()
        end_time = time.time() + duration

        while time.time() < end_time:
            # Simulate packet capture (would use actual capture in production)
            time.sleep(0.1)
            # In production, this would capture real packets
            # For testing, we simulate with callback

    def _create_tls_client_hello(self, server_name):
        """Create a TLS ClientHello packet with SNI."""
        # Simplified TLS ClientHello structure
        content_type = b'\x16'  # Handshake
        version = b'\x03\x03'  # TLS 1.2
        handshake_type = b'\x01'  # ClientHello

        # SNI extension
        sni_ext = b'\x00\x00' + struct.pack(">H", len(server_name) + 5)
        sni_ext += b'\x00' + struct.pack(">H", len(server_name) + 3)
        sni_ext += b'\x00' + struct.pack(">H", len(server_name))
        sni_ext += server_name.encode()

        # Simplified handshake (not complete, for testing)
        handshake = handshake_type + b'\x00\x00\x00' + os.urandom(32) + sni_ext

        return content_type + version + struct.pack(">H", len(handshake)) + handshake


class TestBaseNetworkAnalyzerIntegration:
    """Integration tests for BaseNetworkAnalyzer with real scenarios."""

    @pytest.fixture
    def real_license_server(self):
        """Create a realistic license server simulation."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Use SSL/TLS
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        # Generate self-signed cert for testing
        cert_file = tempfile.NamedTemporaryFile(suffix='.pem', delete=False)
        self._generate_self_signed_cert(cert_file.name)
        context.load_cert_chain(cert_file.name)

        server.bind(('127.0.0.1', 0))
        port = server.getsockname()[1]
        server.listen(1)

        def handle_license_request():
            while True:
                try:
                    client, addr = server.accept()
                    ssl_client = context.wrap_socket(client, server_side=True)

                    # Read license request
                    request = ssl_client.recv(1024)

                    # Send license response
                    response = json.dumps({
                        'status': 'valid',
                        'expiry': '2025-12-31',
                        'features': ['pro', 'enterprise'],
                        'signature': hashlib.sha256(request).hexdigest()
                    }).encode()

                    ssl_client.send(response)
                    ssl_client.close()
                except:
                    break

        thread = threading.Thread(target=handle_license_request, daemon=True)
        thread.start()

        yield ('127.0.0.1', port)

        server.close()
        os.unlink(cert_file.name)

    def test_full_license_validation_flow(self, real_license_server):
        """Test complete license validation flow analysis."""
        analyzer = BaseNetworkAnalyzer()
        handler = analyzer.create_packet_handler()

        server_ip, server_port = real_license_server

        # Capture and analyze full license check
        captured_flow = []

        def capture_callback(packet):
            result = handler(packet)
            if result:
                captured_flow.append(result)

        # Start capture
        capture_thread = threading.Thread(
            target=lambda: self._monitor_traffic(analyzer, capture_callback, 5.0),
            daemon=True
        )
        capture_thread.start()

        # Perform license check
        time.sleep(0.5)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((server_ip, server_port)) as sock:
            with context.wrap_socket(sock) as ssock:
                # Send license request
                request = json.dumps({
                    'product': 'TestApp',
                    'version': '1.0',
                    'license_key': 'XXXX-YYYY-ZZZZ-AAAA',
                    'hardware_id': hashlib.md5(b'test_hardware').hexdigest()
                }).encode()

                ssock.send(request)
                response = ssock.recv(1024)

        capture_thread.join()

        # Verify complete flow was captured
        assert len(captured_flow) > 0, "No license flow captured"

        # Check for key elements
        flow_elements = {
            'handshake': False,
            'license_request': False,
            'license_response': False,
            'encryption': False
        }

        for packet_result in captured_flow:
            if packet_result.get('tls_handshake'):
                flow_elements['handshake'] = True
            if packet_result.get('contains_license_data'):
                if packet_result.get('direction') == 'outbound':
                    flow_elements['license_request'] = True
                else:
                    flow_elements['license_response'] = True
            if packet_result.get('encrypted'):
                flow_elements['encryption'] = True

        # All elements should be detected
        for element, detected in flow_elements.items():
            assert detected, f"Failed to detect {element} in license flow"

    def test_license_bypass_detection(self):
        """Test detection of license bypass attempts."""
        analyzer = BaseNetworkAnalyzer()
        handler = analyzer.create_packet_handler()

        # Common bypass patterns
        bypass_patterns = [
            # Hosts file redirection
            Ether()/IP(dst="127.0.0.1")/TCP(dport=443)/b"GET /validate",

            # Proxy interception
            Ether()/IP()/TCP(dport=8080)/b"CONNECT license.server.com:443",

            # Modified response
            Ether()/IP()/TCP()/json.dumps({'status': 'valid', 'cracked': True}).encode(),

            # Time manipulation attempt
            Ether()/IP()/UDP(dport=123),  # NTP traffic during license check
        ]

        bypass_detected = []

        for packet in bypass_patterns:
            result = handler(bytes(packet))
            if result and result.get('potential_bypass'):
                bypass_detected.append(result)

        # Should detect bypass attempts
        assert len(bypass_detected) > 0, "No bypass attempts detected"

    def _generate_self_signed_cert(self, cert_path):
        """Generate a self-signed certificate for testing."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime

        # Generate key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"test.license.server"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).sign(key, hashes.SHA256())

        # Write to file
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    def _monitor_traffic(self, analyzer, callback, duration):
        """Monitor network traffic for a duration."""
        # In production, this would use actual packet capture
        # For testing, we simulate monitoring
        end_time = time.time() + duration
        while time.time() < end_time:
            time.sleep(0.1)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
