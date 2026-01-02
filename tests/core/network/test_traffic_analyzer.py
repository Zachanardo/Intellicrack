"""Comprehensive tests for NetworkTrafficAnalyzer - Production-ready network traffic analysis validation.

These tests validate real network traffic capture, protocol detection, license communication
analysis, and statistical processing capabilities essential for security research.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import datetime
import glob
import hashlib
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import netifaces
import pytest


# Network analysis imports
try:
    import scapy.all as scapy
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

# Add parent directory to path for imports

from intellicrack.core.network.traffic_analyzer import NetworkTrafficAnalyzer


@dataclass
class LicenseTrafficPattern:
    """Represents a detected license traffic pattern."""
    protocol_type: str
    server_ip: str
    server_port: int
    client_ip: str
    client_port: int
    payload_pattern: bytes
    encryption_detected: bool
    license_server_type: str | None = None


@dataclass
class NetworkAnalysisResult:
    """Expected results from network traffic analysis."""
    total_packets: int
    license_connections: int
    protocols_detected: list[str]
    suspicious_indicators: list[str]
    server_endpoints: list[tuple[str, int]]
    statistical_metrics: dict[str, float]


class TestNetworkTrafficAnalyzer:
    """Comprehensive tests for NetworkTrafficAnalyzer functionality.
    Validates real network analysis capabilities for production security research.
    """

    @pytest.fixture
    def analyzer(self) -> Any:
        """Create a NetworkTrafficAnalyzer instance for testing."""
        config = {
            "capture_file": "test_license_traffic.pcap",
            "max_packets": 1000,
            "filter": "tcp",
            "visualization_dir": "test_visualizations",
            "auto_analyze": False  # Manual control for testing
        }
        return NetworkTrafficAnalyzer(config=config)

    @pytest.fixture
    def test_pcap_files(self) -> None:
        """Locate real PCAP files from test fixtures."""
        pcap_dir = Path(__file__).parent.parent.parent.parent / "fixtures" / "network_captures"
        pcap_files = list(pcap_dir.glob("*.pcap"))

        if not pcap_files:
            pytest.skip("No PCAP test files found in fixtures")

        return pcap_files

    @pytest.fixture
    def license_server_simulator(self) -> Any:
        """Create a realistic license server for testing."""
        class LicenseServerSimulator:
            def __init__(self) -> None:
                self.server_socket = None
                self.port = None
                self.thread = None
                self.running = False

            def start_flexlm_server(self) -> Tuple[str, int]:
                """Start FlexLM license server simulation."""
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind(('127.0.0.1', 27000))
                self.port = self.server_socket.getsockname()[1]
                self.server_socket.listen(5)
                self.running = True

                def handle_connections():
                    while self.running:
                        try:
                            self.server_socket.settimeout(1.0)
                            client, _addr = self.server_socket.accept()

                            # Simulate FlexLM protocol handshake
                            client.recv(1024)

                            # FlexLM response pattern
                            response = b"FLEXLM_SERVER_HELLO\x00"
                            response += b"FEATURE TestApp vendor_daemon 1.0 01-jan-2026"
                            response += b"\x00INCREMENT TestApp vendor_daemon 1.0 01-jan-2026 1 ABCD1234 \\"

                            client.send(response)
                            client.close()
                        except TimeoutError:
                            continue
                        except Exception:
                            break

                self.thread = threading.Thread(target=handle_connections, daemon=True)
                self.thread.start()

                return ('127.0.0.1', self.port)

            def start_hasp_server(self) -> Tuple[str, int]:
                """Start HASP/Sentinel license server simulation."""
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind(('127.0.0.1', 1947))
                self.port = self.server_socket.getsockname()[1]
                self.server_socket.listen(5)
                self.running = True

                def handle_connections():
                    while self.running:
                        try:
                            self.server_socket.settimeout(1.0)
                            client, _addr = self.server_socket.accept()

                            client.recv(1024)

                            # HASP protocol simulation
                            hasp_header = struct.pack(">HH", 0x4841, 0x5350)  # "HA", "SP"
                            hasp_response = hasp_header + b"Sentinel\x00" + os.urandom(16)

                            client.send(hasp_response)
                            client.close()
                        except TimeoutError:
                            continue
                        except Exception:
                            break

                self.thread = threading.Thread(target=handle_connections, daemon=True)
                self.thread.start()

                return ('127.0.0.1', self.port)

            def stop(self):
                """Stop the license server."""
                self.running = False
                if self.server_socket:
                    self.server_socket.close()
                if self.thread:
                    self.thread.join(timeout=2.0)

        simulator = LicenseServerSimulator()
        yield simulator
        simulator.stop()

    @pytest.fixture
    def ssl_license_server(self) -> Any:
        """Create an SSL-enabled license server for testing encrypted communications."""
        # Generate temporary self-signed certificate
        cert_file = tempfile.NamedTemporaryFile(suffix='.pem', delete=False)
        key_file = tempfile.NamedTemporaryFile(suffix='.key', delete=False)

        # Generate certificate using OpenSSL
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', key_file.name, '-out', cert_file.name,
            '-days', '1', '-nodes',
            '-subj', '/CN=license.test.server'
        ], capture_output=True)

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('127.0.0.1', 0))
        port = server_socket.getsockname()[1]
        server_socket.listen(5)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(cert_file.name, key_file.name)

        running = threading.Event()
        running.set()

        def handle_ssl_connections():
            while running.is_set():
                try:
                    server_socket.settimeout(1.0)
                    client, _addr = server_socket.accept()
                    ssl_client = context.wrap_socket(client, server_side=True)

                    # Read encrypted license request
                    request = ssl_client.recv(1024)

                    # Send encrypted license response
                    response = json.dumps({
                        'license_status': 'valid',
                        'features': ['pro_features', 'enterprise_tools'],
                        'expiry': '2026-01-01T00:00:00Z',
                        'server_id': 'license-srv-001',
                        'validation_token': hashlib.sha256(request).hexdigest()
                    }).encode()

                    ssl_client.send(response)
                    ssl_client.close()
                except TimeoutError:
                    continue
                except Exception:
                    break

        server_thread = threading.Thread(target=handle_ssl_connections, daemon=True)
        server_thread.start()

        yield ('127.0.0.1', port)

        running.clear()
        server_socket.close()
        server_thread.join(timeout=2.0)

        # Cleanup
        os.unlink(cert_file.name)
        os.unlink(key_file.name)

    def test_analyzer_initialization(self, analyzer: NetworkTrafficAnalyzer) -> None:
        """Test NetworkTrafficAnalyzer initialization with required capabilities."""
        assert analyzer is not None
        assert hasattr(analyzer, 'start_capture')
        assert hasattr(analyzer, 'stop_capture')
        assert hasattr(analyzer, 'analyze_traffic')
        assert hasattr(analyzer, 'get_results')
        assert hasattr(analyzer, 'generate_report')

        # Verify configuration
        assert analyzer.config['capture_file'] == 'test_license_traffic.pcap'
        assert analyzer.config['max_packets'] == 1000

        # Verify license detection patterns
        assert len(analyzer.license_patterns) > 0
        assert b"license" in analyzer.license_patterns
        assert b"FLEXLM" in analyzer.license_patterns
        assert b"HASP" in analyzer.license_patterns

        # Verify license server ports
        assert 27000 in analyzer.license_ports  # FlexLM
        assert 1947 in analyzer.license_ports   # HASP/Sentinel
        assert 22350 in analyzer.license_ports  # CodeMeter

    def test_real_pcap_analysis(self, analyzer: NetworkTrafficAnalyzer, test_pcap_files: List[Path]) -> None:
        """Test analysis of real PCAP files from test fixtures."""
        for pcap_file in test_pcap_files[:3]:  # Test first 3 files

            if not PYSHARK_AVAILABLE and not SCAPY_AVAILABLE:
                pytest.skip("No packet analysis library available")

            # Load and analyze the PCAP file
            if SCAPY_AVAILABLE:
                packets = scapy.rdpcap(str(pcap_file))

                # Process packets through analyzer
                for packet in packets[:100]:  # Limit for testing
                    if hasattr(packet, 'payload'):
                        analyzer._process_captured_packet(bytes(packet))

            # Perform traffic analysis
            results = analyzer.analyze_traffic()

            assert results is not None, f"Failed to analyze {pcap_file.name}"
            assert 'total_packets' in results
            assert 'total_connections' in results
            assert 'license_connections' in results
            assert 'license_servers' in results

            # Verify meaningful analysis results
            if results['total_packets'] > 0:
                assert results['total_connections'] >= 0
                assert isinstance(results['license_servers'], list)

    def test_live_traffic_capture_socket_backend(self, analyzer: NetworkTrafficAnalyzer) -> None:
        """Test live traffic capture using socket backend."""
        if os.name != 'nt':
            pytest.skip("Socket-based capture testing requires Windows")

        # Test socket capture initialization
        capture_stats = None

        def test_capture() -> None:
            nonlocal capture_stats
            try:
                capture_stats = analyzer._capture_with_socket(
                    interface=None,
                    capture_filter=None,
                    output_file=None,
                    packet_count=10,
                    timeout=5.0
                )
            except PermissionError:
                pytest.skip("Administrator privileges required for raw socket capture")
            except Exception as e:
                pytest.fail(f"Socket capture failed: {e}")

        # Start capture in thread
        analyzer.capturing = True
        capture_thread = threading.Thread(target=test_capture, daemon=True)
        capture_thread.start()

        # Generate some test traffic
        time.sleep(1.0)

        # Create test connections
        for port in [80, 443, 27000]:
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_sock.settimeout(1.0)
                test_sock.connect(('127.0.0.1', port))
                test_sock.close()
            except Exception:
                pass  # Expected for non-listening ports

        # Stop capture
        analyzer.capturing = False
        capture_thread.join(timeout=10.0)

        # Verify capture results
        if capture_stats:
            assert 'start_time' in capture_stats
            assert 'packets_total' in capture_stats
            assert capture_stats['packets_total'] >= 0

    @pytest.mark.skipif(not PYSHARK_AVAILABLE, reason="pyshark not available")
    def test_pyshark_capture_backend(self, analyzer: Any, license_server_simulator: Any) -> None:
        """Test live traffic capture using pyshark backend."""
        # Start license server
        server_addr = license_server_simulator.start_flexlm_server()
        time.sleep(0.5)  # Allow server to start

        # Configure analyzer for pyshark capture
        analyzer.capturing = True

        # Start capture in background
        capture_thread = threading.Thread(
            target=lambda: analyzer._capture_with_pyshark(
                interface=None,
                capture_filter="tcp port 27000",
                output_file=None,
                packet_count=20,
                timeout=10.0
            ),
            daemon=True
        )
        capture_thread.start()

        time.sleep(1.0)  # Allow capture to start

        # Generate license server traffic
        for i in range(5):
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(2.0)
                client.connect(server_addr)

                # Send FlexLM-style request
                request = b"FLEXLM_CLIENT_HELLO\x00"
                request += b"CHECKOUT TestApp 1.0\x00"
                client.send(request)

                client.recv(1024)
                client.close()

                time.sleep(0.2)
            except Exception as e:
                print(f"Connection {i} failed: {e}")

        # Wait for capture to complete
        time.sleep(2.0)
        analyzer.capturing = False
        capture_thread.join(timeout=15.0)

        # Analyze captured traffic
        results = analyzer.analyze_traffic()

        assert results is not None
        assert results['total_packets'] > 0, "No packets captured"
        assert results['total_connections'] > 0, "No connections detected"

        # Verify FlexLM traffic detection
        if results['license_connections'] > 0:
            assert len(results['license_servers']) > 0, "License servers not detected"
            assert '127.0.0.1' in results['license_servers'], "Local license server not detected"

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not available")
    def test_scapy_capture_backend(self, analyzer: Any, license_server_simulator: Any) -> None:
        """Test live traffic capture using scapy backend."""
        # Start HASP server
        server_addr = license_server_simulator.start_hasp_server()
        time.sleep(0.5)

        # Configure analyzer for scapy capture
        analyzer.capturing = True

        # Start capture
        capture_thread = threading.Thread(
            target=lambda: analyzer._capture_with_scapy(interface=None),
            daemon=True
        )
        capture_thread.start()

        time.sleep(1.0)

        # Generate HASP traffic
        for i in range(3):
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(2.0)
                client.connect(server_addr)

                # Send HASP-style request
                hasp_header = struct.pack(">HH", 0x4841, 0x5350)
                request = hasp_header + b"Sentinel_Check" + os.urandom(8)
                client.send(request)

                client.recv(1024)
                client.close()

                time.sleep(0.3)
            except Exception as e:
                print(f"HASP connection {i} failed: {e}")

        # Stop capture
        time.sleep(2.0)
        analyzer.capturing = False
        capture_thread.join(timeout=10.0)

        # Verify results
        results = analyzer.analyze_traffic()

        assert results is not None
        assert results['total_packets'] >= 0

        if results['total_connections'] > 0:
            assert results['license_connections'] >= 0

    def test_license_protocol_detection(self, analyzer: NetworkTrafficAnalyzer) -> None:
        """Test detection of various license protocols and patterns."""
        test_patterns = [
            # FlexLM protocol patterns
            (b"FLEXLM", "FlexLM"),
            (b"FEATURE TestApp", "FlexLM"),
            (b"INCREMENT", "FlexLM"),
            (b"VENDOR_DAEMON", "FlexLM"),

            # HASP/Sentinel patterns
            (b"HASP", "HASP"),
            (b"Sentinel", "HASP"),
            (struct.pack(">HH", 0x4841, 0x5350), "HASP"),

            # CodeMeter patterns
            (b"WIBU", "CodeMeter"),
            (b"CodeMeter", "CodeMeter"),

            # Generic license patterns
            (b"license", "Generic"),
            (b"activation", "Generic"),
            (b"validation", "Generic"),
            (b"license_key", "Generic"),

            # JSON license responses
            (b'{"license_status": "valid"}', "JSON"),
            (b'{"activation": true}', "JSON"),

            # XML license data
            (b'<license><key>', "XML"),
            (b'<?xml version="1.0"?><activation>', "XML"),
        ]

        for pattern, _protocol_type in test_patterns:
            # Simulate packet with pattern
            packet_data = b"\x00" * 20 + pattern + b"\x00" * 10  # Basic IP header + payload

            # Process through analyzer
            analyzer._process_captured_packet(packet_data)

        # Analyze accumulated traffic
        results = analyzer.analyze_traffic()

        # Verify protocol detection capabilities
        assert results is not None

        # Check for detected patterns in connections
        pattern_detections = 0
        if results['license_conn_details']:
            for conn in results['license_conn_details']:
                if conn.get('patterns'):
                    pattern_detections += len(conn['patterns'])

        # Should detect a reasonable number of license patterns
        assert pattern_detections >= len(test_patterns) * 0.3, \
               f"Insufficient pattern detection: {pattern_detections}/{len(test_patterns)}"

    def test_encrypted_traffic_analysis(self, analyzer: NetworkTrafficAnalyzer, ssl_license_server: Tuple[str, int]) -> None:
        """Test analysis of encrypted license traffic."""
        server_ip, server_port = ssl_license_server
        time.sleep(0.5)  # Allow server to start

        # Start traffic capture
        analyzer.capturing = True

        capture_thread = threading.Thread(
            target=lambda: self._simulate_traffic_capture(analyzer, duration=5.0),
            daemon=True
        )
        capture_thread.start()

        time.sleep(1.0)

        # Generate encrypted license traffic
        # lgtm[py/insecure-protocol] Intentionally insecure SSL context for testing license traffic interception
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # nosec B504 - Required for test SSL interception

        for i in range(3):
            try:
                with socket.create_connection((server_ip, server_port), timeout=3.0) as sock:
                    with context.wrap_socket(sock, server_hostname='license.test.server') as ssock:
                        # Send encrypted license request
                        request = json.dumps({
                            'product_id': f'TestApp{i}',
                            'license_key': f'XXXX-YYYY-ZZZZ-{i:04d}',
                            'hardware_fingerprint': hashlib.md5(f'hw{i}'.encode()).hexdigest(),
                            'version': '1.0.0'
                        }).encode()

                        ssock.send(request)
                        response = ssock.recv(1024)

                        # Verify encrypted response received
                        assert len(response) > 0, f"No response from SSL server (attempt {i})"

                time.sleep(0.5)

            except Exception as e:
                print(f"SSL connection {i} failed: {e}")

        # Stop capture and analyze
        analyzer.capturing = False
        capture_thread.join(timeout=10.0)

        results = analyzer.analyze_traffic()

        assert results is not None

        # Verify SSL/TLS traffic handling
        if results['total_connections'] > 0:
            # Check for encrypted traffic indicators
            ssl_indicators = ['https', 'tls', 'ssl', '443']

            protocols_detected = results.get('protocols_detected', [])
            any(
                any(indicator in str(protocol).lower() for indicator in ssl_indicators)
                for protocol in protocols_detected
            )

    def test_statistical_analysis_capabilities(self, analyzer: NetworkTrafficAnalyzer) -> None:
        """Test comprehensive statistical analysis of network traffic."""
        # Generate test traffic data
        test_connections = self._create_test_connection_data()

        # Populate analyzer with test data
        for conn_key, conn_data in test_connections.items():
            analyzer.connections[conn_key] = conn_data

            # Add packets for each connection
            for i in range(conn_data['packet_count']):
                packet_info = {
                    'timestamp': time.time() + i,
                    'src_ip': conn_data['src_ip'],
                    'dst_ip': conn_data['dst_ip'],
                    'src_port': conn_data['src_port'],
                    'dst_port': conn_data['dst_port'],
                    'size': conn_data['packet_size'],
                    'connection_id': conn_key,
                    'payload': None
                }
                analyzer.packets.append(packet_info)

        # Get comprehensive results
        results = analyzer.get_results()

        assert results is not None
        assert 'statistics' in results
        assert 'protocols_detected' in results
        assert 'suspicious_traffic' in results

        stats = results['statistics']

        # Verify statistical metrics
        required_metrics = [
            'capture_duration',
            'packets_per_second',
            'total_bytes',
            'unique_ips',
            'protocol_distribution',
            'port_distribution',
            'license_traffic_percentage',
            'connection_durations'
        ]

        for metric in required_metrics:
            assert metric in stats, f"Missing statistical metric: {metric}"

        # Verify metric calculations
        assert stats['total_bytes'] > 0, "Total bytes calculation failed"
        assert stats['unique_ips'] >= 2, "Unique IP count incorrect"
        assert isinstance(stats['protocol_distribution'], dict), "Protocol distribution not computed"
        assert isinstance(stats['port_distribution'], dict), "Port distribution not computed"

        # Verify connection duration analysis
        durations = stats['connection_durations']
        assert 'min' in durations and 'max' in durations and 'avg' in durations

    def test_suspicious_traffic_detection(self, analyzer: NetworkTrafficAnalyzer) -> None:
        """Test detection of suspicious traffic patterns and bypass attempts."""
        # Create suspicious traffic patterns
        suspicious_patterns = [
            # High port license traffic (suspicious)
            {
                'src_ip': '10.0.0.1',
                'dst_ip': '10.0.0.2',
                'src_port': 12345,
                'dst_port': 55555,  # High port
                'bytes_sent': 50000,
                'bytes_received': 1000,
                'is_license': True,
                'duration': 3600,  # Long duration
            },

            # Excessive data transfer
            {
                'src_ip': '192.168.1.10',
                'dst_ip': '8.8.8.8',
                'src_port': 12346,
                'dst_port': 443,
                'bytes_sent': 2000000,  # 2MB sent
                'bytes_received': 100000,
                'is_license': False,
                'duration': 60,
            },

            # Asymmetric data flow (potential exfiltration)
            {
                'src_ip': '192.168.1.20',
                'dst_ip': '203.0.113.1',
                'src_port': 12347,
                'dst_port': 80,
                'bytes_sent': 500000,  # 10x more sent than received
                'bytes_received': 50000,
                'is_license': False,
                'duration': 300,
            },

            # Non-standard license port
            {
                'src_ip': '10.0.0.5',
                'dst_ip': '10.0.0.6',
                'src_port': 12348,
                'dst_port': 9999,  # Non-standard
                'bytes_sent': 10000,
                'bytes_received': 10000,
                'is_license': True,  # Claims to be license traffic
                'duration': 120,
            }
        ]

        # Populate analyzer with suspicious connections
        for pattern in suspicious_patterns:
            conn_key = f"{pattern['src_ip']}:{pattern['src_port']}-{pattern['dst_ip']}:{pattern['dst_port']}"

            conn_data = {
                'src_ip': pattern['src_ip'],
                'dst_ip': pattern['dst_ip'],
                'src_port': pattern['src_port'],
                'dst_port': pattern['dst_port'],
                'bytes_sent': pattern['bytes_sent'],
                'bytes_received': pattern['bytes_received'],
                'start_time': time.time(),
                'last_time': time.time() + pattern['duration'],
                'is_license': pattern['is_license'],
                'packets': []
            }

            analyzer.connections[conn_key] = conn_data

        # Analyze for suspicious patterns
        results = analyzer.get_results()

        assert results is not None
        assert 'suspicious_traffic' in results

        suspicious_traffic = results['suspicious_traffic']

        # Should detect multiple suspicious indicators
        assert len(suspicious_traffic) > 0, "No suspicious traffic detected"

        # Verify threat level assessment
        threat_levels = [item.get('severity') for item in suspicious_traffic]
        valid_levels = ['low', 'medium', 'high']

        for level in threat_levels:
            assert level in valid_levels, f"Invalid threat level: {level}"

        # Should detect high threat patterns
        high_threat_count = sum(bool(level == 'high')
                            for level in threat_levels)
        assert high_threat_count > 0, "Failed to detect high-threat patterns"

    def test_license_server_identification(self, analyzer: NetworkTrafficAnalyzer) -> None:
        """Test identification of different license server types and endpoints."""
        # Define known license server patterns
        license_servers = [
            # FlexLM servers
            ('license-flexlm.company.com', 27000, 'FlexLM'),
            ('10.0.0.100', 27001, 'FlexLM'),
            ('flexlm-backup.local', 27002, 'FlexLM'),

            # HASP/Sentinel servers
            ('hasp-server.domain.net', 1947, 'HASP'),
            ('10.0.0.200', 1947, 'HASP'),
            ('sentinel-license.local', 6001, 'HASP'),

            # CodeMeter servers
            ('codemeter.license.org', 22350, 'CodeMeter'),
            ('10.0.0.300', 22351, 'CodeMeter'),

            # Custom license servers
            ('custom-lic.app.com', 31337, 'Custom'),
            ('validate.software.io', 8443, 'Custom'),
        ]

        # Simulate traffic to license servers
        for server_ip, server_port, server_type in license_servers:
            conn_key = f"10.0.0.1:12345-{server_ip}:{server_port}"

            # Create license connection
            conn_data = {
                'src_ip': '10.0.0.1',
                'dst_ip': server_ip,
                'src_port': 12345,
                'dst_port': server_port,
                'bytes_sent': 1024,
                'bytes_received': 2048,
                'start_time': time.time(),
                'last_time': time.time() + 30,
                'is_license': True,
                'packets': []
            }

            # Add license patterns based on server type
            if server_type == 'FlexLM':
                conn_data['license_patterns'] = ['FLEXLM', 'FEATURE', 'INCREMENT']
            elif server_type == 'HASP':
                conn_data['license_patterns'] = ['HASP', 'Sentinel']
            elif server_type == 'CodeMeter':
                conn_data['license_patterns'] = ['WIBU', 'CodeMeter']
            else:
                conn_data['license_patterns'] = ['license', 'validation']

            analyzer.connections[conn_key] = conn_data
            analyzer.license_servers.add(server_ip)

        # Analyze license server landscape
        results = analyzer.analyze_traffic()

        assert results is not None
        assert 'license_servers' in results
        assert 'license_connections' in results
        assert 'license_conn_details' in results

        # Verify server identification
        detected_servers = results['license_servers']
        assert len(detected_servers) > 0, "No license servers detected"

        # Should identify different server types
        server_details = results['license_conn_details']
        detected_patterns = set()

        for conn in server_details:
            patterns = conn.get('patterns', [])
            detected_patterns.update(patterns)

        # Verify pattern diversity
        expected_patterns = {'FLEXLM', 'HASP', 'Sentinel', 'CodeMeter', 'license'}
        found_patterns = detected_patterns.intersection(expected_patterns)

        assert len(found_patterns) >= 3, f"Insufficient license pattern diversity: {found_patterns}"

    def test_visualization_generation(self, analyzer: NetworkTrafficAnalyzer) -> None:
        """Test generation of network visualizations."""
        if not hasattr(analyzer, '_generate_visualizations'):
            pytest.skip("Visualization functionality not available")

        # Create test data for visualization
        test_data = {
            'total_packets': 1000,
            'total_connections': 50,
            'license_connections': 5,
            'license_servers': ['10.0.0.100', '10.0.0.200', 'license.server.com'],
            'license_conn_details': [
                {
                    'src_ip': '10.0.0.1',
                    'dst_ip': '10.0.0.100',
                    'src_port': 12345,
                    'dst_port': 27000,
                    'bytes_sent': 5000,
                    'bytes_received': 10000,
                    'patterns': ['FLEXLM', 'FEATURE']
                },
                {
                    'src_ip': '10.0.0.2',
                    'dst_ip': '10.0.0.200',
                    'src_port': 12346,
                    'dst_port': 1947,
                    'bytes_sent': 3000,
                    'bytes_received': 7000,
                    'patterns': ['HASP', 'Sentinel']
                }
            ]
        }

        # Test visualization generation
        try:
            analyzer._generate_visualizations(test_data)

            # Check if visualization files were created
            viz_dir = Path(analyzer.config['visualization_dir'])
            if viz_dir.exists():
                if viz_files := list(viz_dir.glob("*.png")):
                    assert viz_files, "No visualization files generated"

                    # Verify file sizes (should be non-empty)
                    for viz_file in viz_files:
                        assert viz_file.stat().st_size > 1000, f"Visualization file too small: {viz_file}"

        except ImportError:
            pytest.skip("matplotlib not available for visualization")
        except Exception as e:
            pytest.fail(f"Visualization generation failed: {e}")

    def test_html_report_generation(self, analyzer: NetworkTrafficAnalyzer) -> None:
        """Test generation of comprehensive HTML analysis reports."""
        # Populate analyzer with test data
        test_connections = self._create_test_connection_data()

        for conn_key, conn_data in test_connections.items():
            analyzer.connections[conn_key] = conn_data

        # Generate report
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"test_license_report_{timestamp}.html"

        success = analyzer.generate_report(report_file)

        assert success, "Failed to generate HTML report"

        # Verify report file was created
        assert os.path.exists(report_file), "Report file not created"

        # Verify report content
        with open(report_file, encoding='utf-8') as f:
            report_content = f.read()

        # Check for required report elements
        required_elements = [
            'License Traffic Analysis Report',
            'Total Packets:',
            'Total Connections:',
            'License-related Connections:',
            'License Servers:',
            'License Connections'
        ]

        for element in required_elements:
            assert element in report_content, f"Missing report element: {element}"

        # Check for HTML structure
        html_elements = ['<html>', '<head>', '<body>', '</html>']
        for element in html_elements:
            assert element in report_content, f"Invalid HTML structure: missing {element}"

        # Cleanup
        os.unlink(report_file)

    def test_performance_with_high_volume_traffic(self, analyzer: NetworkTrafficAnalyzer) -> None:
        """Test analyzer performance with high-volume network traffic."""
        # Generate large volume of test packets
        start_time = time.time()
        num_packets = 5000

        for i in range(num_packets):
            # Vary packet characteristics
            if i % 4 == 0:
                # License server traffic
                packet_data = struct.pack(">HH", 0x4C43, 0x524B) + b"LICENSE_CHECK" + os.urandom(100)
            elif i % 4 == 1:
                # HTTP traffic
                packet_data = b"GET /api/validate HTTP/1.1\r\nHost: license.com\r\n\r\n"
            elif i % 4 == 2:
                # FlexLM traffic
                packet_data = b"FLEXLM_SERVER\x00FEATURE TestApp 1.0\x00" + os.urandom(50)
            else:
                # Generic TCP traffic
                packet_data = os.urandom(200)

            # Process packet
            analyzer._process_captured_packet(packet_data)

        processing_time = time.time() - start_time

        # Verify performance
        packets_per_second = num_packets / processing_time
        assert packets_per_second >= 1000, f"Insufficient processing performance: {packets_per_second:.0f} pps"

        # Analyze accumulated traffic
        analysis_start = time.time()
        results = analyzer.analyze_traffic()
        analysis_time = time.time() - analysis_start

        assert results is not None, "Analysis failed with high volume traffic"
        assert analysis_time < 10.0, f"Analysis too slow: {analysis_time:.2f} seconds"

    def test_concurrent_analysis_thread_safety(self, analyzer: NetworkTrafficAnalyzer) -> None:
        """Test thread safety during concurrent traffic analysis."""
        errors = []
        results = []

        def analyze_traffic_batch(thread_id: int) -> None:
            try:
                for i in range(100):
                    # Generate unique packet data per thread
                    packet_data = f"Thread{thread_id}_Packet{i}_LICENSE_CHECK".encode() + os.urandom(50)
                    analyzer._process_captured_packet(packet_data)

                # Perform analysis
                thread_results = analyzer.analyze_traffic()
                if thread_results:
                    results.append((thread_id, thread_results))

            except Exception as e:
                errors.append((thread_id, str(e)))

        # Run concurrent analysis threads
        threads = []
        for thread_id in range(5):
            t = threading.Thread(target=analyze_traffic_batch, args=(thread_id,))
            threads.append(t)
            t.start()

        # Wait for completion
        for t in threads:
            t.join(timeout=30.0)

        # Verify thread safety
        assert not errors, f"Thread safety violations: {errors}"
        assert results, "No results from concurrent analysis"

        # Verify data integrity
        for thread_id, thread_result in results:
            assert thread_result is not None, f"Invalid result from thread {thread_id}"
            assert 'total_packets' in thread_result, f"Corrupted result from thread {thread_id}"

    # Helper methods for test data generation

    def _create_test_connection_data(self) -> dict[str, Any]:
        """Create realistic test connection data."""
        connections = {
            '10.0.0.1:12345-10.0.0.100:27000': {
                'src_ip': '10.0.0.1',
                'dst_ip': '10.0.0.100',
                'src_port': 12345,
                'dst_port': 27000,
                'bytes_sent': 5000,
                'bytes_received': 15000,
                'start_time': time.time() - 300,
                'last_time': time.time(),
                'is_license': True,
                'packets': [],
                'packet_count': 50,
                'packet_size': 400,
            }
        }

        # HASP connection
        connections['10.0.0.2:12346-10.0.0.200:1947'] = {
            'src_ip': '10.0.0.2',
            'dst_ip': '10.0.0.200',
            'src_port': 12346,
            'dst_port': 1947,
            'bytes_sent': 3000,
            'bytes_received': 8000,
            'start_time': time.time() - 180,
            'last_time': time.time(),
            'is_license': True,
            'packets': [],
            'packet_count': 30,
            'packet_size': 350
        }

        # HTTP connection
        connections['10.0.0.3:12347-10.0.0.300:443'] = {
            'src_ip': '10.0.0.3',
            'dst_ip': '10.0.0.300',
            'src_port': 12347,
            'dst_port': 443,
            'bytes_sent': 2000,
            'bytes_received': 12000,
            'start_time': time.time() - 120,
            'last_time': time.time(),
            'is_license': False,
            'packets': [],
            'packet_count': 40,
            'packet_size': 350
        }

        return connections

    def _simulate_traffic_capture(self, analyzer, duration: float):
        """Simulate traffic capture for testing."""
        end_time = time.time() + duration
        packet_count = 0

        while time.time() < end_time and analyzer.capturing:
            # Generate simulated packets
            if packet_count % 10 == 0:
                # License traffic packet
                packet_data = b"LICENSE_PACKET" + struct.pack(">I", packet_count) + os.urandom(100)
            else:
                # Regular traffic packet
                packet_data = b"REGULAR_PACKET" + struct.pack(">I", packet_count) + os.urandom(150)

            analyzer._process_captured_packet(packet_data)
            packet_count += 1

            time.sleep(0.01)  # 10ms between packets


class TestTrafficAnalyzerIntegration:
    """Integration tests for NetworkTrafficAnalyzer with real-world scenarios."""

    def test_complete_license_validation_workflow(self) -> None:
        """Test complete license validation workflow analysis."""
        analyzer = NetworkTrafficAnalyzer()

        # Simulate complete license check workflow
        workflow_steps = [
            # 1. DNS lookup for license server
            ('DNS', '8.8.8.8', 53, b'license.server.com'),

            # 2. TCP connection establishment
            ('TCP_SYN', '10.0.0.100', 27000, b''),
            ('TCP_SYN_ACK', '10.0.0.1', 12345, b''),
            ('TCP_ACK', '10.0.0.100', 27000, b''),

            # 3. License protocol handshake
            ('LICENSE_HELLO', '10.0.0.100', 27000, b'FLEXLM_CLIENT_HELLO\x00'),
            ('LICENSE_WELCOME', '10.0.0.1', 12345, b'FLEXLM_SERVER_HELLO\x00'),

            # 4. License request
            ('LICENSE_REQUEST', '10.0.0.100', 27000, b'CHECKOUT TestApp 1.0 user@host'),

            # 5. License response
            ('LICENSE_RESPONSE', '10.0.0.1', 12345, b'LICENSE_GRANTED\x00expires=2025-12-31'),

            # 6. Connection cleanup
            ('TCP_FIN', '10.0.0.100', 27000, b''),
            ('TCP_FIN_ACK', '10.0.0.1', 12345, b''),
        ]

        # Process workflow packets
        for _step_type, _dst_ip, _dst_port, payload in workflow_steps:
            packet_data = payload + b"\x00" * (100 - len(payload))  # Pad packet
            analyzer._process_captured_packet(packet_data)
            time.sleep(0.01)  # Small delay between steps

        # Analyze complete workflow
        results = analyzer.analyze_traffic()

        assert results is not None
        assert results['total_packets'] >= len(workflow_steps)

        # Verify workflow elements detected
        if results['license_connections'] > 0:
            license_details = results['license_conn_details']

            # Should detect FlexLM patterns
            patterns_found = []
            for conn in license_details:
                patterns_found.extend(conn.get('patterns', []))

            flexlm_patterns = [p for p in patterns_found if 'FLEXLM' in p or 'CHECKOUT' in p]
            assert flexlm_patterns, "FlexLM workflow patterns not detected"

    def test_multi_protocol_license_environment(self) -> None:
        """Test analysis of environment with multiple license protocols."""
        analyzer = NetworkTrafficAnalyzer()

        # Simulate multi-protocol environment
        protocols = [
            # FlexLM server
            ('FlexLM', '10.0.0.100', 27000, [
                b'FLEXLM_SERVER_HELLO',
                b'FEATURE AutoCAD autodesk 2024.1',
                b'INCREMENT AutoCAD autodesk 2024.1 permanent 5',
                b'VENDOR_DAEMON autodesk'
            ]),

            # HASP/Sentinel server
            ('HASP', '10.0.0.200', 1947, [
                struct.pack(">HH", 0x4841, 0x5350),  # "HA" "SP"
                b'Sentinel Runtime API',
                b'HASP_LOGIN',
                b'HASP_LOGOUT'
            ]),

            # CodeMeter server
            ('CodeMeter', '10.0.0.300', 22350, [
                b'WIBU-SYSTEMS',
                b'CodeMeter Runtime',
                b'CmContainer',
                b'CmAccess'
            ]),

            # Custom protocol
            ('Custom', '10.0.0.400', 31337, [
                b'CUSTOM_LICENSE_V2',
                b'AUTH_TOKEN_REQUEST',
                b'VALIDATION_RESPONSE',
                b'SESSION_ESTABLISHED'
            ])
        ]

        # Generate traffic for each protocol
        for _protocol_name, server_ip, port, patterns in protocols:
            for pattern in patterns:
                packet_data = pattern + b"\x00" * (150 - len(pattern))
                analyzer._process_captured_packet(packet_data)

            # Add connection metadata
            conn_key = f"10.0.0.1:12345-{server_ip}:{port}"
            analyzer.connections[conn_key] = {
                'src_ip': '10.0.0.1',
                'dst_ip': server_ip,
                'src_port': 12345,
                'dst_port': port,
                'bytes_sent': 2000,
                'bytes_received': 5000,
                'start_time': time.time() - 120,
                'last_time': time.time(),
                'is_license': True,
                'packets': []
            }

            analyzer.license_servers.add(server_ip)

        # Analyze multi-protocol environment
        results = analyzer.analyze_traffic()

        assert results is not None
        assert len(results['license_servers']) >= 3, "Multiple license servers not detected"
        assert results['license_connections'] >= 3, "Multiple license protocols not detected"

        # Verify protocol diversity
        license_details = results['license_conn_details']
        detected_protocols = set()

        for conn in license_details:
            patterns = conn.get('patterns', [])
            for pattern in patterns:
                if 'FLEXLM' in pattern or 'FEATURE' in pattern:
                    detected_protocols.add('FlexLM')
                elif 'HASP' in pattern or 'Sentinel' in pattern:
                    detected_protocols.add('HASP')
                elif 'WIBU' in pattern or 'CodeMeter' in pattern:
                    detected_protocols.add('CodeMeter')
                elif 'CUSTOM' in pattern:
                    detected_protocols.add('Custom')

        assert len(detected_protocols) >= 2, f"Insufficient protocol diversity detected: {detected_protocols}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "--maxfail=5"])
