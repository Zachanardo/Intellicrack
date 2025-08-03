import pytest
import time
import threading
import socket
import tempfile
import os
import psutil

from intellicrack.core.network.packet_parser import PacketParser
from intellicrack.core.network.protocol_analyzer import ProtocolAnalyzer
from intellicrack.core.network.license_server_emulator import LicenseServerEmulator
from intellicrack.core.network.network_monitor import NetworkMonitor
from intellicrack.core.network.packet_filter import PacketFilter
from intellicrack.core.network.session_reassembly import SessionReassembly
from tests.base_test import IntellicrackTestBase


class TestNetworkPerformance(IntellicrackTestBase):
    """Performance benchmarks for network operations and protocol analysis."""

    @pytest.fixture
    def sample_packet_data(self):
        """Generate REAL network packet data for testing."""
        # Ethernet header (14 bytes)
        ethernet = b'\x00\x11\x22\x33\x44\x55\xaa\xbb\xcc\xdd\xee\xff\x08\x00'
        
        # IP header (20 bytes)
        ip_header = b'\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06'
        ip_header += b'\xb1\xe6\xc0\xa8\x00\x68\xc0\xa8\x00\x01'
        
        # TCP header (20 bytes)
        tcp_header = b'\x00\x50\x08\xae\x00\x00\x00\x00\x00\x00\x00\x00'
        tcp_header += b'\x50\x02\x20\x00\x91\x7c\x00\x00'
        
        # Payload
        payload = b'LICENSE_REQUEST\x00\x01\x02\x03\x04\x05'
        
        return ethernet + ip_header + tcp_header + payload

    @pytest.fixture
    def sample_pcap_file(self):
        """Create REAL PCAP file for testing."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as temp_file:
            # PCAP global header
            pcap_header = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00'
            pcap_header += b'\x00\x00\x00\x00\x00\x00\x00\x00'
            pcap_header += b'\xff\xff\x00\x00\x01\x00\x00\x00'
            
            temp_file.write(pcap_header)
            
            # Add some packet records
            for i in range(10):
                # Packet header
                packet_header = b'\x00\x00\x00\x00\x00\x00\x00\x00'
                packet_header += b'\x4a\x00\x00\x00\x4a\x00\x00\x00'
                
                # Packet data
                packet_data = b'\x00' * 74
                
                temp_file.write(packet_header + packet_data)
            
            temp_file.flush()
            yield temp_file.name
        
        try:
            os.unlink(temp_file.name)
        except:
            pass

    @pytest.fixture
    def process_memory(self):
        """Monitor process memory usage."""
        process = psutil.Process()
        return process.memory_info()

    @pytest.mark.benchmark
    def test_packet_parsing_performance(self, benchmark, sample_packet_data):
        """Benchmark REAL packet parsing speed."""
        def parse_packet():
            parser = PacketParser()
            return parser.parse_packet(sample_packet_data)
        
        result = benchmark(parse_packet)
        
        self.assert_real_output(result)
        assert 'ethernet' in result, "Result must contain ethernet layer"
        assert 'ip' in result, "Result must contain IP layer"
        assert 'tcp' in result, "Result must contain TCP layer"
        assert benchmark.stats.mean < 0.001, "Packet parsing should be under 1ms"

    @pytest.mark.benchmark  
    def test_protocol_analysis_performance(self, benchmark, sample_packet_data):
        """Benchmark REAL protocol analysis speed."""
        def analyze_protocol():
            analyzer = ProtocolAnalyzer()
            return analyzer.analyze_packet(sample_packet_data)
        
        result = benchmark(analyze_protocol)
        
        self.assert_real_output(result)
        assert 'protocol' in result, "Result must identify protocol"
        assert 'layers' in result, "Result must contain layer analysis"
        assert benchmark.stats.mean < 0.005, "Protocol analysis should be under 5ms"

    @pytest.mark.benchmark
    def test_license_server_startup_performance(self, benchmark):
        """Benchmark REAL license server startup speed."""
        def start_license_server():
            server = LicenseServerEmulator()
            server.start_server(port=0)  # Random port
            time.sleep(0.1)  # Allow server to start
            server.stop_server()
            return True
        
        result = benchmark(start_license_server)
        
        assert result is True, "Server must start and stop successfully"
        assert benchmark.stats.mean < 0.5, "Server startup should be under 500ms"

    @pytest.mark.benchmark
    def test_pcap_file_loading_performance(self, benchmark, sample_pcap_file):
        """Benchmark REAL PCAP file loading speed."""
        def load_pcap():
            parser = PacketParser()
            return parser.load_pcap_file(sample_pcap_file)
        
        result = benchmark(load_pcap)
        
        self.assert_real_output(result)
        assert 'packets' in result, "Result must contain packets"
        assert len(result['packets']) == 10, "Must load all 10 packets"
        assert benchmark.stats.mean < 0.1, "PCAP loading should be under 100ms"

    @pytest.mark.benchmark
    def test_packet_filter_performance(self, benchmark, sample_packet_data):
        """Benchmark REAL packet filtering speed."""
        def filter_packets():
            filter_engine = PacketFilter()
            filter_engine.add_filter("tcp.port == 80")
            
            results = []
            for i in range(1000):
                result = filter_engine.match_packet(sample_packet_data)
                results.append(result)
            
            return results
        
        results = benchmark(filter_packets)
        
        assert len(results) == 1000, "Must process all 1000 packets"
        assert benchmark.stats.mean < 0.1, "Filtering 1000 packets should be under 100ms"

    @pytest.mark.benchmark
    def test_session_reassembly_performance(self, benchmark):
        """Benchmark REAL TCP session reassembly speed."""
        def reassemble_session():
            reassembler = SessionReassembly()
            
            # Simulate TCP stream
            for seq_num in range(0, 10000, 1000):
                packet = {
                    'tcp': {
                        'seq': seq_num,
                        'ack': 0,
                        'flags': {'PSH': True}
                    },
                    'payload': b'DATA' * 250  # 1KB chunks
                }
                reassembler.add_packet(packet)
            
            return reassembler.get_reassembled_stream()
        
        result = benchmark(reassemble_session)
        
        self.assert_real_output(result)
        assert len(result) == 10000, "Reassembled stream must be 10KB"
        assert benchmark.stats.mean < 0.05, "Session reassembly should be under 50ms"

    def test_concurrent_packet_processing(self, sample_packet_data):
        """Test REAL concurrent packet processing performance."""
        parser = PacketParser()
        results = []
        errors = []
        
        def process_packets(thread_id):
            try:
                thread_results = []
                for i in range(100):
                    result = parser.parse_packet(sample_packet_data)
                    thread_results.append(result)
                results.append((thread_id, len(thread_results)))
            except Exception as e:
                errors.append((thread_id, str(e)))
        
        threads = []
        start_time = time.time()
        
        for i in range(5):
            thread = threading.Thread(target=process_packets, args=(i,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join(timeout=5.0)
        
        end_time = time.time()
        
        assert len(errors) == 0, f"Concurrent processing errors: {errors}"
        assert len(results) == 5, f"Expected 5 results, got {len(results)}"
        assert end_time - start_time < 1.0, "Concurrent processing should complete under 1 second"

    def test_network_monitor_performance(self):
        """Test REAL network monitoring performance."""
        monitor = NetworkMonitor()
        
        # Start monitoring
        monitor.start_monitoring()
        
        # Simulate network activity
        start_time = time.time()
        
        for i in range(100):
            event = {
                'timestamp': time.time(),
                'type': 'packet',
                'size': 1024 + i,
                'protocol': 'TCP'
            }
            monitor.record_event(event)
            time.sleep(0.001)  # 1ms between packets
        
        # Get statistics
        stats = monitor.get_statistics()
        monitor.stop_monitoring()
        
        end_time = time.time()
        
        self.assert_real_output(stats)
        assert 'packet_count' in stats, "Stats must include packet count"
        assert stats['packet_count'] == 100, "Must record all 100 packets"
        assert end_time - start_time < 0.5, "Monitoring 100 packets should be under 500ms"

    def test_license_protocol_emulation_performance(self):
        """Test REAL license protocol emulation performance."""
        server = LicenseServerEmulator()
        
        # Test various license protocols
        protocols = ['flexlm', 'hasp', 'adobe', 'microsoft']
        
        start_time = time.time()
        
        for protocol in protocols:
            request = {
                'protocol': protocol,
                'action': 'check_license',
                'product': 'test_product',
                'version': '1.0'
            }
            
            response = server.handle_license_request(request)
            self.assert_real_output(response)
            assert 'status' in response, f"Response for {protocol} must contain status"
        
        end_time = time.time()
        
        assert end_time - start_time < 0.1, "Protocol emulation should be fast"

    @pytest.mark.benchmark
    def test_packet_capture_performance(self, benchmark):
        """Benchmark REAL packet capture performance."""
        def capture_packets():
            monitor = NetworkMonitor()
            captured = []
            
            # Simulate packet capture
            for i in range(1000):
                packet = {
                    'id': i,
                    'timestamp': time.time(),
                    'size': 64 + (i % 1436),  # Varying sizes
                    'data': b'\x00' * 64
                }
                captured.append(monitor.capture_packet(packet))
            
            return captured
        
        result = benchmark(capture_packets)
        
        assert len(result) == 1000, "Must capture all 1000 packets"
        assert benchmark.stats.mean < 0.1, "Capturing 1000 packets should be under 100ms"

    def test_protocol_decoder_performance(self, sample_packet_data):
        """Test REAL protocol decoder performance."""
        analyzer = ProtocolAnalyzer()
        
        # Test different protocol decoders
        protocols = {
            'http': b'GET /license HTTP/1.1\r\nHost: server\r\n\r\n',
            'https': b'\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03',
            'flexlm': b'FLEXLM\x00\x01\x00\x00\x00\x10LICENSE_REQUEST',
            'custom': b'CUSTOM_PROTOCOL\x00\x01\x02\x03'
        }
        
        start_time = time.time()
        
        for proto_name, proto_data in protocols.items():
            result = analyzer.decode_protocol(proto_data)
            self.assert_real_output(result)
            assert 'protocol_type' in result, f"Must identify {proto_name}"
        
        end_time = time.time()
        
        assert end_time - start_time < 0.05, "Protocol decoding should be fast"

    def test_network_buffer_performance(self, process_memory):
        """Test REAL network buffer management performance."""
        initial_memory = process_memory.rss
        
        monitor = NetworkMonitor()
        
        # Fill network buffers
        for i in range(10000):
            packet = b'\x00' * (100 + i % 900)  # 100-1000 byte packets
            monitor.buffer_packet(packet)
        
        # Process buffered packets
        processed = monitor.process_buffered_packets()
        
        current_process = psutil.Process()
        final_memory = current_process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        assert processed == 10000, "Must process all buffered packets"
        assert memory_increase < 50 * 1024 * 1024, "Memory usage should be under 50MB"

    @pytest.mark.benchmark
    def test_connection_tracking_performance(self, benchmark):
        """Benchmark REAL connection tracking performance."""
        def track_connections():
            tracker = NetworkMonitor()
            
            # Simulate many connections
            for i in range(100):
                conn = {
                    'src_ip': f'192.168.1.{i % 256}',
                    'dst_ip': f'10.0.0.{i % 256}',
                    'src_port': 1024 + i,
                    'dst_port': 80,
                    'protocol': 'TCP',
                    'state': 'ESTABLISHED'
                }
                tracker.track_connection(conn)
            
            # Query connections
            active = tracker.get_active_connections()
            return len(active)
        
        result = benchmark(track_connections)
        
        assert result == 100, "Must track all 100 connections"
        assert benchmark.stats.mean < 0.01, "Connection tracking should be under 10ms"

    def test_packet_injection_performance(self):
        """Test REAL packet injection performance."""
        injector = PacketParser()  # Assuming it has injection capability
        
        start_time = time.time()
        
        # Create various packet types
        packet_types = [
            b'\x00' * 64,   # Minimal packet
            b'\xff' * 1500, # Maximum MTU
            b'\xaa' * 576,  # Standard size
        ]
        
        injected_count = 0
        for packet_type in packet_types:
            for i in range(100):
                result = injector.validate_packet_format(packet_type)
                if result:
                    injected_count += 1
        
        end_time = time.time()
        
        assert injected_count == 300, "Must validate all 300 packets"
        assert end_time - start_time < 0.1, "Packet validation should be fast"

    def test_network_statistics_aggregation(self):
        """Test REAL network statistics aggregation performance."""
        monitor = NetworkMonitor()
        
        # Generate lots of statistics
        start_time = time.time()
        
        for i in range(1000):
            monitor.update_statistics({
                'bytes_sent': 1000 + i,
                'bytes_received': 2000 + i,
                'packets_sent': 10 + i % 10,
                'packets_received': 20 + i % 20,
                'errors': i % 100 == 0
            })
        
        # Aggregate statistics
        aggregated = monitor.aggregate_statistics()
        
        end_time = time.time()
        
        self.assert_real_output(aggregated)
        assert 'total_bytes' in aggregated, "Must include total bytes"
        assert 'total_packets' in aggregated, "Must include total packets"
        assert 'error_rate' in aggregated, "Must include error rate"
        assert end_time - start_time < 0.1, "Statistics aggregation should be under 100ms"