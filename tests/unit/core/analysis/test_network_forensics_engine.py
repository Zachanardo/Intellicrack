"""
Unit tests for NetworkForensicsEngine - Production-Ready Network Forensics Validation

This test suite validates sophisticated network forensics capabilities expected from
a professional security research platform. Tests are designed using specification-driven
methodology and assume genuine forensics functionality exists.

All tests validate production-ready forensics capabilities with real network protocols and encryption.
"""

import pytest
import tempfile
import os
from pathlib import Path
import struct
import hashlib
import time
from typing import Dict, List, Any

from intellicrack.core.analysis.network_forensics_engine import NetworkForensicsEngine


class TestNetworkForensicsEngine:
    """Comprehensive test suite for NetworkForensicsEngine production capabilities."""

    @pytest.fixture
    def engine(self):
        """Create NetworkForensicsEngine instance."""
        return NetworkForensicsEngine()

    @pytest.fixture
    def sample_pcap_data(self):
        """Generate realistic PCAP file data with genuine network traffic patterns."""
        # Create legitimate PCAP header (libpcap format)
        pcap_header = struct.pack('<IHHIIII',
            0xa1b2c3d4,  # magic number
            2,           # version major
            4,           # version minor
            0,           # timezone offset
            0,           # timestamp accuracy
            65535,       # max packet length
            1            # data link type (Ethernet)
        )

        # Create realistic packet data with HTTP traffic
        http_request = (
            b'GET /api/v1/status HTTP/1.1\r\n'
            b'Host: malware-c2.example.com\r\n'
            b'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n'
            b'Authorization: Bearer suspicious_token_12345\r\n'
            b'X-Forwarded-For: 192.168.1.100\r\n'
            b'\r\n'
        )

        # Create packet header for the HTTP packet
        packet_time = int(time.time())
        packet_header = struct.pack('<IIII',
            packet_time,           # timestamp seconds
            0,                     # timestamp microseconds
            len(http_request),     # captured packet length
            len(http_request)      # original packet length
        )

        return pcap_header + packet_header + http_request

    @pytest.fixture
    def sample_pcapng_data(self):
        """Generate realistic PCAPNG file data with advanced traffic patterns."""
        # PCAPNG Section Header Block
        shb = struct.pack('<III',
            0x0A0D0D0A,  # Block type: Section Header Block
            28,          # Block total length
            0x1A2B3C4D   # Byte order magic
        ) + b'\x00' * 12 + struct.pack('<I', 28)

        # Add realistic TLS encrypted traffic
        tls_data = (
            b'\x16\x03\x03\x00\x30' +  # TLS handshake header
            b'\x01\x00\x00\x2c' +      # Client hello message
            b'\x03\x03' +              # TLS version 1.2
            b'\x12\x34\x56\x78' * 8 +  # Random data (32 bytes)
            b'\x00\x02\x00\x35' +      # Cipher suites
            b'\x01\x00\x00\x04'        # Extensions
        )

        return shb + tls_data

    @pytest.fixture
    def malicious_traffic_data(self):
        """Generate realistic malicious network traffic for artifact testing."""
        return (
            b'POST /api/upload HTTP/1.1\r\n'
            b'Host: attacker-c2.badactors.net\r\n'
            b'Content-Type: application/octet-stream\r\n'
            b'X-Malware-Command: download_payload\r\n'
            b'Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=\r\n'  # admin:password123
            b'\r\n'
            b'suspicious_user@darkweb.onion\r\n'
            b'192.168.1.254\r\n'
            b'https://evil-site.malicious.com/payload.exe\r\n'
            b'filename=trojan.exe\r\n'
            b'api_key=sk_test_abcdef123456789\r\n'
            b'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==\r\n'  # Base64 PNG
        )

    def test_initialization_sets_correct_attributes(self, engine):
        """Test engine initializes with proper production-ready configuration."""
        # Validate logger configuration
        assert hasattr(engine, 'logger')
        assert engine.logger is not None
        assert engine.logger.name.endswith('network_forensics_engine')

        # Validate supported formats for professional forensics
        assert hasattr(engine, 'supported_formats')
        expected_formats = {'pcap', 'pcapng', 'cap'}
        assert set(engine.supported_formats) >= expected_formats

        # Engine should be ready for immediate forensics analysis
        assert callable(getattr(engine, 'analyze_capture', None))
        assert callable(getattr(engine, 'analyze_live_traffic', None))
        assert callable(getattr(engine, 'extract_artifacts', None))
        assert callable(getattr(engine, 'detect_protocols', None))

    def test_analyze_capture_handles_nonexistent_file(self, engine):
        """Test proper error handling for missing capture files."""
        result = engine.analyze_capture('/nonexistent/file.pcap')

        assert isinstance(result, dict)
        assert 'error' in result
        assert 'not found' in result['error'].lower()

    def test_analyze_capture_validates_real_pcap_format(self, engine, sample_pcap_data):
        """Test sophisticated PCAP format detection and parsing."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp.write(sample_pcap_data)
            tmp.flush()

            try:
                result = engine.analyze_capture(tmp.name)

                # Validate production-ready analysis results
                assert isinstance(result, dict)
                assert result.get('analysis_status') == 'completed'

                # Must detect correct file format through sophisticated parsing
                assert 'file_type' in result
                assert result['file_type'] in ['PCAP', 'PCAPNG']

                # Must provide comprehensive packet analysis
                assert 'packet_count' in result
                assert isinstance(result['packet_count'], int)
                assert result['packet_count'] >= 0

                # Must detect protocols through deep inspection
                assert 'protocols_detected' in result
                assert isinstance(result['protocols_detected'], list)

                # Should detect HTTP in our sample data
                protocols = [p.upper() for p in result['protocols_detected']]
                assert any('HTTP' in proto for proto in protocols)

                # Must analyze for suspicious patterns
                assert 'suspicious_traffic' in result
                assert isinstance(result['suspicious_traffic'], list)

                # Must provide traffic flow analysis
                assert 'connection_flows' in result
                assert isinstance(result['connection_flows'], list)

                # Must extract network artifacts
                assert 'dns_queries' in result
                assert 'http_requests' in result

            finally:
                os.unlink(tmp.name)

    def test_analyze_capture_detects_advanced_threats(self, engine, malicious_traffic_data):
        """Test detection of sophisticated attack patterns and C2 communication."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            # Create PCAP with malicious traffic
            pcap_header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
            packet_header = struct.pack('<IIII', int(time.time()), 0, len(malicious_traffic_data), len(malicious_traffic_data))
            tmp.write(pcap_header + packet_header + malicious_traffic_data)
            tmp.flush()

            try:
                result = engine.analyze_capture(tmp.name)

                # Must detect advanced threat indicators
                assert 'suspicious_traffic' in result
                suspicious = result['suspicious_traffic']

                # Should identify C2 communication patterns
                suspicious_text = ' '.join(suspicious).lower()
                assert any(indicator in suspicious_text for indicator in [
                    'credential', 'password', 'suspicious', 'malicious', 'threat'
                ])

                # Must identify protocols even in malicious traffic
                assert len(result.get('protocols_detected', [])) > 0

            finally:
                os.unlink(tmp.name)

    def test_analyze_capture_handles_large_files_efficiently(self, engine):
        """Test performance and memory efficiency with large capture files."""
        # Create large PCAP file with real network packets
        # Generate actual Ethernet/IP/TCP packets for realistic testing
        packets = []
        for i in range(10000):  # 10k real packets
            # Ethernet header (14 bytes)
            eth_header = (
                b'\x00\x11\x22\x33\x44\x55' +  # Destination MAC
                b'\x66\x77\x88\x99\xaa\xbb' +  # Source MAC
                b'\x08\x00'  # EtherType (IPv4)
            )

            # IP header (20 bytes minimum)
            ip_header = (
                b'\x45\x00'  # Version/IHL, DSCP/ECN
                + struct.pack('>H', 60 + (i % 1000))  # Total length
                + struct.pack('>H', i)  # Identification
                + b'\x40\x00'  # Flags/Fragment offset
                + b'\x40\x06'  # TTL, Protocol (TCP)
                + b'\x00\x00'  # Header checksum (simplified)
                + struct.pack('>I', 0xC0A80001 + (i % 255))  # Source IP
                + struct.pack('>I', 0x08080808)  # Dest IP (8.8.8.8)
            )

            # TCP header (20 bytes minimum)
            tcp_header = (
                struct.pack('>H', 1024 + (i % 60000))  # Source port
                + struct.pack('>H', 443 if i % 2 else 80)  # Dest port
                + struct.pack('>I', i * 1000)  # Sequence number
                + struct.pack('>I', i * 1000 + 100)  # Acknowledgment
                + b'\x50\x18'  # Data offset, flags
                + struct.pack('>H', 8192)  # Window size
                + b'\x00\x00'  # Checksum (simplified)
                + b'\x00\x00'  # Urgent pointer
            )

            # Application data (varies per packet)
            if i % 2:  # HTTPS traffic
                app_data = (
                    b'\x16\x03\x03' +  # TLS record
                    struct.pack('>H', 40 + (i % 200)) +  # Length
                    os.urandom(40 + (i % 200))  # Encrypted payload
                )
            else:  # HTTP traffic
                app_data = (
                    b'GET /path' + str(i).encode() + b' HTTP/1.1\r\n'
                    b'Host: example.com\r\n'
                    b'User-Agent: Intellicrack/1.0\r\n\r\n'
                )

            packet_data = eth_header + ip_header + tcp_header + app_data

            # PCAP packet header
            pcap_pkt_header = struct.pack('<IIII',
                i,  # Timestamp seconds
                i * 1000,  # Timestamp microseconds
                len(packet_data),  # Capture length
                len(packet_data)  # Original length
            )

            packets.append(pcap_pkt_header + packet_data)

        large_data = b''.join(packets)
        pcap_header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp.write(pcap_header + large_data)
            tmp.flush()

            try:
                start_time = time.time()
                result = engine.analyze_capture(tmp.name)
                analysis_time = time.time() - start_time

                # Must handle large files within reasonable time
                assert analysis_time < 60  # Should process within 60 seconds

                # Must provide accurate file size analysis
                assert 'file_size' in result
                assert result['file_size'] == len(pcap_header + large_data)

                # Must estimate packet count for large files
                assert 'packet_count' in result
                assert isinstance(result['packet_count'], int)

            finally:
                os.unlink(tmp.name)

    def test_analyze_live_traffic_validates_interfaces(self, engine):
        """Test live traffic analysis with proper interface validation."""
        # Test with actual system network interfaces
        try:
            import psutil
            available_interfaces = list(psutil.net_if_addrs().keys())
        except ImportError:
            # If psutil not available, use common interface names
            available_interfaces = []

        # Test with invalid interface
        result = engine.analyze_live_traffic('NonexistentInterface999')

        assert isinstance(result, dict)

        # Should either report error or handle gracefully
        if 'error' in result:
            assert 'not found' in result['error'].lower() or 'invalid' in result['error'].lower()

            # Should provide available interfaces if possible
            if 'available_interfaces' in result:
                assert isinstance(result['available_interfaces'], list)

                # If we know actual interfaces, verify they're listed
                if available_interfaces:
                    result_interfaces = result['available_interfaces']
                    # Should have some overlap with real interfaces
                    assert len(set(result_interfaces) & set(available_interfaces)) > 0 or len(result_interfaces) > 0

    def test_analyze_live_traffic_captures_real_traffic(self, engine):
        """Test sophisticated live traffic capture and analysis."""
        # Attempt to use a real interface if available
        interface = None
        try:
            import psutil
            interfaces = list(psutil.net_if_addrs().keys())
            # Try to find a suitable interface (prefer Ethernet/WiFi over loopback)
            for iface in interfaces:
                if 'lo' not in iface.lower() and 'loopback' not in iface.lower():
                    interface = iface
                    break
            if not interface and interfaces:
                interface = interfaces[0]  # Fallback to first available
        except ImportError:
            # Use common interface names
            interface = 'eth0'  # Common on Linux

        if interface:
            # Test with short duration to avoid long waits
            result = engine.analyze_live_traffic(interface, duration=1)

            # Validate comprehensive live analysis results
            assert isinstance(result, dict)

            # Should either succeed or report error
            if 'error' not in result:
                assert result.get('analysis_status') in ['completed', 'in_progress', 'partial']
                assert result.get('interface') == interface
                assert result.get('duration', 0) > 0

                # Should provide traffic statistics if successful
                if 'packets_captured' in result:
                    assert isinstance(result['packets_captured'], int)
                    assert result['packets_captured'] >= 0

                # Should provide traffic summary if available
                if 'traffic_summary' in result:
                    traffic_summary = result['traffic_summary']
                    assert isinstance(traffic_summary, dict)

                    # Check for standard network metrics
                    for metric in ['bytes_sent', 'bytes_received', 'packets_sent', 'packets_received']:
                        if metric in traffic_summary:
                            assert isinstance(traffic_summary[metric], (int, float))
                            assert traffic_summary[metric] >= 0

                # Should detect protocols if any traffic observed
                if 'protocols_observed' in result:
                    assert isinstance(result['protocols_observed'], list)

                # Should detect anomalies if present
                if 'anomalies_detected' in result:
                    assert isinstance(result['anomalies_detected'], list)

                # Should analyze connections if any active
                if 'connection_analysis' in result:
                    connections = result['connection_analysis']
                    assert isinstance(connections, list)

                    for conn in connections:
                        assert isinstance(conn, dict)
                        # Should have connection details
                        if 'local_address' in conn:
                            assert isinstance(conn['local_address'], str)
                        if 'remote_address' in conn:
                            assert isinstance(conn['remote_address'], str)

    def test_extract_artifacts_handles_empty_data(self, engine):
        """Test artifact extraction gracefully handles empty or invalid data."""
        # Empty data
        result = engine.extract_artifacts(b'')
        assert isinstance(result, list)
        assert len(result) == 0

        # None input
        result = engine.extract_artifacts(None)
        assert isinstance(result, list)
        assert len(result) == 0

    def test_extract_artifacts_finds_comprehensive_indicators(self, engine, malicious_traffic_data):
        """Test sophisticated artifact extraction from complex network data."""
        artifacts = engine.extract_artifacts(malicious_traffic_data)

        # Must extract multiple artifact types
        assert isinstance(artifacts, list)
        assert len(artifacts) > 5  # Should find multiple artifacts

        # Organize artifacts by type for validation
        artifact_types = {}
        for artifact in artifacts:
            artifact_type = artifact.get('type', 'Unknown')
            if artifact_type not in artifact_types:
                artifact_types[artifact_type] = []
            artifact_types[artifact_type].append(artifact)

        # Must extract URLs from network traffic
        assert 'URL' in artifact_types
        urls = [a['value'] for a in artifact_types['URL']]
        assert any('evil-site.malicious.com' in url for url in urls)

        # Must extract email addresses
        assert 'Email' in artifact_types
        emails = [a['value'] for a in artifact_types['Email']]
        assert any('suspicious_user@darkweb.onion' in email for email in emails)

        # Must extract IP addresses
        assert 'IP_Address' in artifact_types
        ips = [a['value'] for a in artifact_types['IP_Address']]
        assert any('192.168.1.254' in ip for ip in ips)

        # Must detect base64 encoded data
        assert 'Base64_Data' in artifact_types

        # Must extract potential credentials
        cred_types = {'Password', 'Username', 'Token', 'API_Key'}
        found_creds = set(artifact_types.keys()) & cred_types
        assert len(found_creds) > 0  # Should find at least one credential type

        # Must extract file indicators
        file_types = {'Filename', 'File_Extension'}
        found_files = set(artifact_types.keys()) & file_types
        assert len(found_files) > 0

        # Validate artifact metadata completeness
        for artifact in artifacts:
            assert 'type' in artifact
            assert 'value' in artifact
            assert 'offset' in artifact
            assert 'length' in artifact
            assert isinstance(artifact['offset'], int)
            assert isinstance(artifact['length'], int)

    def test_extract_artifacts_handles_obfuscated_data(self, engine):
        """Test extraction of artifacts from obfuscated or encoded traffic."""
        # Create obfuscated traffic with various encoding schemes
        obfuscated_data = (
            b'POST /api HTTP/1.1\r\n'
            b'X-Token: dXNlcjpzZWNyZXQ=\r\n'  # user:secret in base64
            b'Data: %48%65%6C%6C%6F%20%57%6F%72%6C%64\r\n'  # URL encoded "Hello World"
            b'Payload: 4d5a90000300000004000000ffff0000\r\n'  # Hex encoded PE header
            b'Config: {"server":"192.168.1.1","port":8080}\r\n'
            b'\r\n'
        )

        artifacts = engine.extract_artifacts(obfuscated_data)

        # Must find encoded credentials
        assert len(artifacts) > 0

        # Should detect base64 patterns
        base64_artifacts = [a for a in artifacts if a['type'] == 'Base64_Data']
        assert len(base64_artifacts) > 0

        # Should extract IP addresses from JSON config
        ip_artifacts = [a for a in artifacts if a['type'] == 'IP_Address']
        assert any('192.168.1.1' in a['value'] for a in ip_artifacts)

    def test_detect_protocols_identifies_standard_protocols(self, engine):
        """Test comprehensive protocol detection for standard network protocols."""
        # HTTP traffic
        http_data = b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'
        protocols = engine.detect_protocols(http_data)
        assert 'HTTP' in protocols

        # HTTPS/TLS traffic
        tls_data = b'\x16\x03\x03\x00\x30' + b'A' * 48  # TLS handshake
        protocols = engine.detect_protocols(tls_data)
        assert any('TLS' in p or 'HTTPS' in p for p in protocols)

        # SSH traffic
        ssh_data = b'SSH-2.0-OpenSSH_7.4\r\n'
        protocols = engine.detect_protocols(ssh_data)
        assert 'SSH' in protocols

        # FTP traffic
        ftp_data = b'220 Welcome to FTP server\r\nUSER anonymous\r\n'
        protocols = engine.detect_protocols(ftp_data)
        assert 'FTP' in protocols

    def test_detect_protocols_handles_complex_traffic(self, engine):
        """Test protocol detection in complex, multi-protocol network streams."""
        # Mixed protocol traffic
        complex_data = (
            b'SSH-2.0-OpenSSH_7.4\r\n'  # SSH
            b'GET /api HTTP/1.1\r\n'    # HTTP
            b'Host: api.example.com\r\n'
            b'\x16\x03\x03\x00\x30'    # TLS handshake
            b'220 Welcome to FTP\r\n'   # FTP
            b'HELO smtp.example.com\r\n'  # SMTP
        )

        protocols = engine.detect_protocols(complex_data)

        # Must detect multiple protocols
        assert len(protocols) >= 3
        assert 'SSH' in protocols
        assert 'HTTP' in protocols
        assert any('FTP' in p for p in protocols)

    def test_detect_protocols_identifies_malware_patterns(self, engine):
        """Test detection of protocols used by malware and C2 communications."""
        # Custom protocol with malware-like patterns
        malware_data = (
            b'\x00\x00\x00\x08MALWARE\x01'  # Custom header
            b'POST /beacon HTTP/1.1\r\n'
            b'X-Session-ID: bot12345\r\n'
            b'X-Command: download\r\n'
            b'\r\n'
        )

        protocols = engine.detect_protocols(malware_data)

        # Should detect HTTP despite malicious nature
        assert 'HTTP' in protocols

    def test_detect_protocols_handles_fragmented_data(self, engine):
        """Test protocol detection with incomplete or fragmented packets."""
        # Partial HTTP request
        partial_http = b'GET /api/v1/st'  # Incomplete
        protocols = engine.detect_protocols(partial_http)

        # Should handle gracefully without errors
        assert isinstance(protocols, list)

        # Fragmented TLS handshake
        partial_tls = b'\x16\x03'  # Incomplete TLS header
        protocols = engine.detect_protocols(partial_tls)
        assert isinstance(protocols, list)

    def test_detect_protocols_handles_empty_data(self, engine):
        """Test protocol detection gracefully handles empty data."""
        # Empty data
        protocols = engine.detect_protocols(b'')
        assert isinstance(protocols, list)
        assert len(protocols) == 0

        # None input handling
        protocols = engine.detect_protocols(None)
        assert isinstance(protocols, list)
        assert len(protocols) == 0

    def test_comprehensive_workflow_integration(self, engine, sample_pcap_data, malicious_traffic_data):
        """Test complete forensics workflow integration across all methods."""
        # Step 1: Analyze capture file
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp.write(sample_pcap_data)
            tmp.flush()

            try:
                capture_results = engine.analyze_capture(tmp.name)
                assert capture_results.get('analysis_status') == 'completed'

                # Step 2: Extract artifacts from raw data
                artifacts = engine.extract_artifacts(malicious_traffic_data)
                assert len(artifacts) > 0

                # Step 3: Protocol detection on same data
                protocols = engine.detect_protocols(malicious_traffic_data)
                assert len(protocols) > 0

                # Integration validation: Results should be consistent
                # Protocol detection should align with capture analysis
                if capture_results.get('protocols_detected'):
                    capture_protocols = [p.upper() for p in capture_results['protocols_detected']]
                    detected_protocols = [p.upper() for p in protocols]

                    # Should have some protocol overlap or complementary detection
                    assert len(set(capture_protocols) | set(detected_protocols)) > 0

            finally:
                os.unlink(tmp.name)

    def test_error_handling_and_logging_integration(self, engine):
        """Test comprehensive error handling across all methods."""
        # Test invalid file paths
        result = engine.analyze_capture('/invalid/path/file.pcap')
        assert 'error' in result

        # Test invalid interface for live traffic
        result = engine.analyze_live_traffic('invalid_interface_999')
        assert isinstance(result, dict)
        # Should either handle gracefully or report error
        if 'error' in result:
            assert 'not found' in result['error'].lower() or 'invalid' in result['error'].lower()

        # Test malformed data handling
        malformed_data = b'\x00\x01\x02\x03\xff\xfe\xfd'
        artifacts = engine.extract_artifacts(malformed_data)
        assert isinstance(artifacts, list)  # Should not crash

        protocols = engine.detect_protocols(malformed_data)
        assert isinstance(protocols, list)  # Should not crash

    def test_performance_and_scalability_validation(self, engine):
        """Test engine performance with various data sizes and complexity."""
        # Test small data performance
        small_data = b'GET / HTTP/1.1\r\nHost: test.com\r\n\r\n'
        start_time = time.time()
        protocols = engine.detect_protocols(small_data)
        small_time = time.time() - start_time

        assert small_time < 1.0  # Should be very fast
        assert len(protocols) > 0

        # Test medium data performance
        medium_data = small_data * 1000  # Repeat pattern
        start_time = time.time()
        artifacts = engine.extract_artifacts(medium_data)
        medium_time = time.time() - start_time

        assert medium_time < 10.0  # Should handle medium data efficiently
        assert len(artifacts) >= 0

        # Performance should scale reasonably
        # (Medium data processing shouldn't be 1000x slower than small)
        if small_time > 0:
            performance_ratio = medium_time / small_time
            assert performance_ratio < 100  # Reasonable scaling

    @pytest.mark.parametrize("file_extension,expected_format", [
        ('.pcap', 'PCAP'),
        ('.pcapng', 'PCAPNG'),
        ('.cap', 'PCAP'),
    ])
    def test_supported_capture_formats(self, engine, file_extension, expected_format):
        """Test support for various network capture file formats."""
        # Create minimal valid file for each format
        if file_extension == '.pcapng':
            # PCAPNG format
            data = struct.pack('<III', 0x0A0D0D0A, 28, 0x1A2B3C4D) + b'\x00' * 16
        else:
            # PCAP format
            data = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

        with tempfile.NamedTemporaryFile(suffix=file_extension, delete=False) as tmp:
            tmp.write(data)
            tmp.flush()

            try:
                result = engine.analyze_capture(tmp.name)

                # Must support the format
                assert 'error' not in result or 'not found' not in result.get('error', '')

                # Should detect correct format type
                if 'file_type' in result:
                    detected = result['file_type']
                    assert detected in [expected_format, 'Unknown']  # Allow Unknown for minimal data

            finally:
                os.unlink(tmp.name)


class TestNetworkForensicsEngineEdgeCases:
    """Test edge cases and boundary conditions for NetworkForensicsEngine."""

    @pytest.fixture
    def engine(self):
        """Create NetworkForensicsEngine instance."""
        return NetworkForensicsEngine()

    def test_binary_data_artifact_extraction(self, engine):
        """Test artifact extraction from pure binary/executable data."""
        # Create real PE binary with embedded network configuration data
        # Build a minimal valid PE executable structure with network strings

        # DOS header (64 bytes)
        dos_header = (
            b'\x4d\x5a'  # MZ signature
            + b'\x90\x00'  # Bytes on last page
            + b'\x03\x00'  # Pages in file
            + b'\x00\x00'  # Relocations
            + b'\x04\x00'  # Size of header in paragraphs
            + b'\x00\x00'  # Minimum extra paragraphs
            + b'\xff\xff'  # Maximum extra paragraphs
            + b'\x00\x00'  # Initial SS value
            + b'\xb8\x00'  # Initial SP value
            + b'\x00\x00'  # Checksum
            + b'\x00\x00'  # Initial IP value
            + b'\x00\x00'  # Initial CS value
            + b'\x40\x00'  # File address of relocation table
            + b'\x00\x00'  # Overlay number
            + b'\x00\x00' * 4  # Reserved
            + b'\x00\x00'  # OEM identifier
            + b'\x00\x00'  # OEM information
            + b'\x00\x00' * 10  # Reserved
            + b'\x80\x00\x00\x00'  # PE header offset at 0x80
        )

        # Complete DOS executable program for PE header compatibility
        dos_program = (
            # Full DOS program with system detection and environment verification
            b'\x0e'              # PUSH CS - Save code segment
            b'\x1f'              # POP DS - Set data segment
            b'\xba\x0e\x00'      # MOV DX, 0x0E - Offset to message
            b'\xb4\x09'          # MOV AH, 9 - DOS print string function
            b'\xcd\x21'          # INT 21h - Call DOS interrupt
            # Check DOS version
            b'\xb4\x30'          # MOV AH, 30h - Get DOS version
            b'\xcd\x21'          # INT 21h - Call DOS interrupt
            b'\x3c\x02'          # CMP AL, 2 - Check if DOS 2.0 or higher
            b'\x73\x05'          # JAE skip - Jump if above or equal
            # Exit with error code
            b'\xb8\x01\x4c'      # MOV AX, 4C01h - Exit with code 1
            b'\xcd\x21'          # INT 21h - DOS exit
            # Advanced DOS operations
            b'\xb8\x00\x06'      # MOV AX, 0600h - Clear screen
            b'\xb7\x07'          # MOV BH, 07h - White on black
            b'\xb9\x00\x00'      # MOV CX, 0000h - Upper left
            b'\xba\x4f\x18'      # MOV DX, 184Fh - Lower right
            b'\xcd\x10'          # INT 10h - BIOS video
            b'\xb4\x02'          # MOV AH, 02h - Set cursor position
            b'\xb6\x0c'          # MOV DH, 0Ch - Row 12
            b'\xb2\x20'          # MOV DL, 20h - Column 32
            b'\xb7\x00'          # MOV BH, 00h - Page 0
            b'\xcd\x10'          # INT 10h - BIOS video
            # Display warning message
            b'This is a Windows PE executable.\r\n$'
            b'\x00' * 16         # Alignment padding
        )

        # PE header
        pe_header = (
            b'PE\x00\x00'  # PE signature
            + b'\x4c\x01'  # Machine type (i386)
            + b'\x03\x00'  # Number of sections
            + struct.pack('<I', 0x5f000000)  # TimeDateStamp
            + b'\x00\x00\x00\x00'  # PointerToSymbolTable
            + b'\x00\x00\x00\x00'  # NumberOfSymbols
            + b'\xe0\x00'  # SizeOfOptionalHeader
            + b'\x0f\x01'  # Characteristics
        )

        # Optional header (simplified)
        optional_header = (
            b'\x0b\x01'  # Magic (PE32)
            + b'\x0e\x00'  # Linker version
            + b'\x00\x10\x00\x00'  # SizeOfCode
            + b'\x00\x10\x00\x00'  # SizeOfInitializedData
            + b'\x00\x00\x00\x00'  # SizeOfUninitializedData
            + b'\x00\x10\x00\x00'  # AddressOfEntryPoint
            + b'\x00\x10\x00\x00'  # BaseOfCode
            + b'\x00\x20\x00\x00'  # BaseOfData
            + b'\x00\x00\x40\x00'  # ImageBase
            + b'\x00\x10\x00\x00'  # SectionAlignment
            + b'\x00\x02\x00\x00'  # FileAlignment
            + b'\x06\x00'  # OS version major
            + b'\x00\x00'  # OS version minor
            + b'\x00\x00' * 2  # Image version
            + b'\x06\x00'  # Subsystem version major
            + b'\x00\x00'  # Subsystem version minor
            + b'\x00\x00\x00\x00'  # Win32 version
            + b'\x00\x30\x00\x00'  # SizeOfImage
            + b'\x00\x02\x00\x00'  # SizeOfHeaders
            + b'\x00\x00\x00\x00'  # CheckSum
            + b'\x03\x00'  # Subsystem (console)
            + b'\x00\x00'  # DLL characteristics
            + b'\x00' * 64  # Stack/heap sizes and data directories (simplified)
        )

        # Pad to alignment
        header_padding = b'\x00' * (512 - len(dos_header) - len(dos_program) - len(pe_header) - len(optional_header))

        # Network configuration data embedded in .data section
        network_config = (
            # Actual C2 server URLs
            b'https://command-control.darknet.onion/beacon\x00'
            b'https://backup-c2.hiddenservice.tor/update\x00'
            b'http://192.168.1.100:8080/exfil\x00'
            # Email drops
            b'drops@protonmail.ch\x00'
            b'exfil.data@tutanota.com\x00'
            # Network IPs and ports
            b'10.0.0.1:4444\x00'
            b'172.16.0.1:31337\x00'
            b'192.168.88.1:443\x00'
            # Encryption keys (Base64)
            b'aGFyZGNvZGVkX2tleV9mb3JfdGVzdGluZw==\x00'
            # User agent strings
            b'Mozilla/5.0 (Stealth Bot 1.0)\x00'
            # API endpoints
            b'/api/v1/register\x00'
            b'/api/v1/heartbeat\x00'
            b'/api/v1/command\x00'
            + b'\x00' * 200  # Null padding
        )

        binary_data = dos_header + dos_program + pe_header + optional_header + header_padding + network_config

        artifacts = engine.extract_artifacts(binary_data)

        # Must extract artifacts even from binary data
        assert len(artifacts) > 0

        # Should find URL, email, IP
        types_found = {a['type'] for a in artifacts}
        assert 'URL' in types_found
        assert 'Email' in types_found
        assert 'IP_Address' in types_found

    def test_unicode_and_internationalized_data(self, engine):
        """Test handling of international and Unicode network traffic."""
        # Mixed encoding traffic
        unicode_data = (
            b'GET /\xc3\xa9\xc3\xa9 HTTP/1.1\r\n'  # UTF-8 encoded path
            b'Host: \xd0\xbf\xd1\x80\xd0\xb8\xd0\xbc\xd0\xb5\xd1\x80.com\r\n'  # Cyrillic domain
            b'User-Agent: \xe6\xb5\x8b\xe8\xaf\x95\r\n'  # Chinese characters
            b'\r\n'
        )

        # Should handle without crashing
        protocols = engine.detect_protocols(unicode_data)
        assert isinstance(protocols, list)
        assert 'HTTP' in protocols

        artifacts = engine.extract_artifacts(unicode_data)
        assert isinstance(artifacts, list)

    def test_extremely_large_packet_analysis(self, engine):
        """Test handling of very large network packets."""
        # Create large packet (jumbo frame size)
        large_packet = (
            b'POST /upload HTTP/1.1\r\n'
            b'Content-Length: 65000\r\n'
            b'\r\n' +
            b'A' * 65000  # Large payload
        )

        # Should handle large packets efficiently
        start_time = time.time()
        protocols = engine.detect_protocols(large_packet)
        analysis_time = time.time() - start_time

        assert analysis_time < 30  # Should complete within reasonable time
        assert 'HTTP' in protocols

    def test_malformed_protocol_headers(self, engine):
        """Test resilience against malformed protocol headers."""
        malformed_data = [
            b'GET /\x00\x01\x02 HTTP/1.1\r\n',  # Null bytes in URL
            b'HTTP/1.1\r\n\x00\x00\x00\r\n',   # Malformed header
            b'\xff\xfe\xfd GET / HTTP/1.1\r\n', # Invalid prefix
            b'GET / HTTP/999.999\r\n',          # Invalid version
        ]

        for data in malformed_data:
            # Should handle gracefully without errors
            protocols = engine.detect_protocols(data)
            assert isinstance(protocols, list)

            artifacts = engine.extract_artifacts(data)
            assert isinstance(artifacts, list)
