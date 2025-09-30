import pytest
import time
import threading
import tempfile
import os
import psutil
import socket
from intellicrack.core.network.cloud_license_hooker import CloudLicenseHooker
from intellicrack.core.network_capture import NetworkCapture
from intellicrack.plugins.custom_modules.license_server_emulator import LicenseServerEmulator
from intellicrack.core.network.license_protocol_analyzer import LicenseProtocolAnalyzer


class TestNetworkPerformance:
    """Performance benchmarks for network operations and license emulation functionality."""

    @pytest.fixture
    def sample_license_packet(self):
        """Generate REAL license packet data for testing."""
        flexlm_packet = b'\x00\x00\x00\x14'
        flexlm_packet += b'\x00\x00\x00\x01'
        flexlm_packet += b'\x00\x00\x00\x00'
        flexlm_packet += b'\x46\x4c\x45\x58'
        flexlm_packet += b'\x00\x00\x00\x00'
        return flexlm_packet

    @pytest.fixture
    def hasp_packet(self):
        """Generate REAL HASP packet data for testing."""
        hasp_packet = b'\x48\x41\x53\x50'
        hasp_packet += b'\x00\x01\x00\x00'
        hasp_packet += b'\x00\x00\x00\x10'
        hasp_packet += b'\x01\x02\x03\x04'
        hasp_packet += b'\x05\x06\x07\x08'
        hasp_packet += b'\x09\x0a\x0b\x0c'
        return hasp_packet

    @pytest.fixture
    def adobe_activation_packet(self):
        """Generate REAL Adobe activation packet for testing."""
        adobe_packet = b'\x41\x44\x4f\x42'
        adobe_packet += b'\x45\x00\x00\x00'
        adobe_packet += b'\x00\x00\x00\x20'
        adobe_packet += b'\x01\x00\x00\x00'
        adobe_packet += b'PHOTOSHOP2023\x00\x00\x00'
        adobe_packet += b'\xff\xff\xff\xff'
        return adobe_packet

    @pytest.fixture
    def network_capture_file(self):
        """Create REAL network capture file for testing."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as temp_file:
            pcap_header = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00'
            pcap_header += b'\x00\x00\x00\x00\x00\x00\x00\x00'
            pcap_header += b'\xff\xff\x00\x00\x01\x00\x00\x00'

            packet_header = b'\x00\x00\x00\x00\x00\x00\x00\x00'
            packet_header += b'\x2a\x00\x00\x00\x2a\x00\x00\x00'

            ethernet_frame = b'\xff\xff\xff\xff\xff\xff'
            ethernet_frame += b'\x00\x11\x22\x33\x44\x55'
            ethernet_frame += b'\x08\x00'

            ip_packet = b'\x45\x00\x00\x1c\x00\x01\x00\x00'
            ip_packet += b'\x40\x11\x00\x00\x7f\x00\x00\x01'
            ip_packet += b'\x7f\x00\x00\x01'

            udp_packet = b'\x04\xd2\x04\xd2\x00\x08\x00\x00'

            temp_file.write(pcap_header + packet_header + ethernet_frame + ip_packet + udp_packet)
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
    def test_license_packet_parsing_performance(self, benchmark, sample_license_packet):
        """Benchmark REAL license packet parsing speed."""
        def parse_license_packet():
            hooker = CloudLicenseHooker()
            return hooker.parse_flexlm_packet(sample_license_packet)

        result = benchmark(parse_license_packet)

        assert result is not None, "License packet parsing must return result"
        assert 'packet_type' in result or 'data' in result, "Result must contain packet information"
        assert benchmark.stats.mean < 0.01, "License packet parsing should be under 10ms"

    @pytest.mark.benchmark
    def test_hasp_protocol_handling_performance(self, benchmark, hasp_packet):
        """Benchmark REAL HASP protocol handling speed."""
        def handle_hasp_protocol():
            hooker = CloudLicenseHooker()
            return hooker.handle_hasp_request(hasp_packet)

        result = benchmark(handle_hasp_protocol)

        assert result is not None, "HASP handling must return result"
        assert len(result) > 0, "HASP response must not be empty"
        assert benchmark.stats.mean < 0.02, "HASP handling should be under 20ms"

    @pytest.mark.benchmark
    def test_adobe_activation_performance(self, benchmark, adobe_activation_packet):
        """Benchmark REAL Adobe activation processing speed."""
        def process_adobe_activation():
            hooker = CloudLicenseHooker()
            return hooker.process_adobe_activation(adobe_activation_packet)

        result = benchmark(process_adobe_activation)

        assert result is not None, "Adobe activation must return result"
        assert 'status' in result or 'response' in result, "Result must contain status information"
        assert benchmark.stats.mean < 0.05, "Adobe activation should be under 50ms"

    @pytest.mark.benchmark
    def test_license_server_startup_performance(self, benchmark):
        """Benchmark REAL license server startup speed."""
        def start_license_server():
            emulator = LicenseServerEmulator()
            server = emulator.create_license_server(host='127.0.0.1', port=0)
            server.start_async()
            time.sleep(0.1)
            server.stop()
            return server.is_running

        result = benchmark(start_license_server)

        assert result is not None, "License server startup must return status"
        assert benchmark.stats.mean < 0.5, "License server startup should be under 500ms"

    @pytest.mark.benchmark
    def test_license_client_connection_performance(self, benchmark):
        """Benchmark REAL license client connection speed."""
        emulator = LicenseServerEmulator()
        server = emulator.create_license_server(host='127.0.0.1', port=0)
        server.start_async()
        server_port = server.get_port()

        def connect_license_client():
            client = emulator.create_license_client()
            result = client.connect('127.0.0.1', server_port, timeout=1.0)
            if client.is_connected():
                client.disconnect()
            return result

        try:
            result = benchmark(connect_license_client)

            assert result is not None, "License client connection must return result"
            assert benchmark.stats.mean < 0.2, "License client connection should be under 200ms"
        finally:
            server.stop()

    @pytest.mark.benchmark
    def test_encryption_performance(self, benchmark):
        """Benchmark REAL encryption/decryption operations."""
        def encrypt_decrypt_data():
            hooker = CloudLicenseHooker()
            key = hooker.generate_encryption_key()

            test_data = b"This is test data for encryption performance testing" * 10

            encrypted = hooker.encrypt_license_data(test_data, key)
            decrypted = hooker.decrypt_license_data(encrypted, key)

            return decrypted == test_data

        result = benchmark(encrypt_decrypt_data)

        assert result is True, "Encryption/decryption must be successful"
        assert benchmark.stats.mean < 0.01, "Encryption/decryption should be under 10ms"

    @pytest.mark.benchmark
    def test_network_capture_parsing_performance(self, benchmark, network_capture_file):
        """Benchmark REAL network capture parsing speed."""
        def parse_network_capture():
            capture = NetworkCapture()
            return capture.parse_pcap_file(network_capture_file)

        result = benchmark(parse_network_capture)

        assert result is not None, "Network capture parsing must return result"
        assert 'packets' in result, "Result must contain packets"
        assert len(result['packets']) > 0, "Must parse at least one packet"
        assert benchmark.stats.mean < 0.1, "Network capture parsing should be under 100ms"

    @pytest.mark.benchmark
    def test_session_management_performance(self, benchmark):
        """Benchmark REAL session management operations."""
        def manage_sessions():
            manager = SessionManager()

            session_ids = []
            for i in range(10):
                session_id = manager.create_session(f"client_{i}", f"127.0.0.{i+1}")
                session_ids.append(session_id)

            for session_id in session_ids:
                manager.update_session_activity(session_id)

            active_sessions = manager.get_active_sessions()

            for session_id in session_ids:
                manager.close_session(session_id)

            return len(active_sessions)

        result = benchmark(manage_sessions)

        assert result == 10, "Must manage exactly 10 sessions"
        assert benchmark.stats.mean < 0.05, "Session management should be under 50ms"

    def test_concurrent_license_connections(self):
        """Test REAL concurrent license connection performance."""
        emulator = LicenseServerEmulator()
        server = emulator.create_license_server(host='127.0.0.1', port=0)
        server.start_async()
        server_port = server.get_port()

        results = []
        errors = []

        def connect_license_client(client_id):
            try:
                client = emulator.create_license_client()
                result = client.connect('127.0.0.1', server_port, timeout=2.0)
                if client.is_connected():
                    time.sleep(0.1)
                    client.disconnect()
                results.append((client_id, result))
            except Exception as e:
                errors.append((client_id, str(e)))

        try:
            threads = []
            start_time = time.time()

            for i in range(5):
                thread = threading.Thread(target=connect_license_client, args=(i,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join(timeout=5.0)

            end_time = time.time()

            assert len(errors) == 0, f"Concurrent connection errors: {errors}"
            assert len(results) == 5, f"Expected 5 connections, got {len(results)}"
            assert end_time - start_time < 3.0, "Concurrent connections should complete under 3 seconds"

        finally:
            server.stop()

    def test_license_protocol_memory_usage(self, sample_license_packet, process_memory):
        """Test REAL license protocol memory efficiency."""
        initial_memory = process_memory.rss

        hooker = CloudLicenseHooker()

        for i in range(100):
            result = hooker.parse_flexlm_packet(sample_license_packet)
            assert result is not None, f"License parsing {i} failed"

        current_process = psutil.Process()
        final_memory = current_process.memory_info().rss
        memory_increase = final_memory - initial_memory

        assert memory_increase < 20 * 1024 * 1024, "Memory increase should be under 20MB for 100 parsings"

    @pytest.mark.benchmark
    def test_communication_protocol_switching_performance(self, benchmark):
        """Benchmark REAL communication protocol switching speed."""
        def switch_protocols():
            protocols = CommunicationProtocols()

            protocols.switch_to_http()
            http_status = protocols.get_current_protocol()

            protocols.switch_to_dns()
            dns_status = protocols.get_current_protocol()

            protocols.switch_to_tcp()
            tcp_status = protocols.get_current_protocol()

            return [http_status, dns_status, tcp_status]

        result = benchmark(switch_protocols)

        assert result is not None, "Protocol switching must return results"
        assert len(result) == 3, "Must return status for all protocols"
        assert benchmark.stats.mean < 0.01, "Protocol switching should be under 10ms"

    def test_network_stress_test(self, sample_license_packet, hasp_packet):
        """Stress test REAL network operations under heavy load."""
        hooker = CloudLicenseHooker()

        start_time = time.time()

        packets = [sample_license_packet, hasp_packet] * 50

        for i, packet in enumerate(packets):
            if i % 2 == 0:
                result = hooker.parse_flexlm_packet(packet)
            else:
                result = hooker.handle_hasp_request(packet)

            assert result is not None, f"Stress test packet {i} failed"

        end_time = time.time()

        assert end_time - start_time < 5.0, "Network stress test should complete under 5 seconds"

    def test_license_message_throughput(self):
        """Test REAL license message throughput performance."""
        emulator = LicenseServerEmulator()
        server = emulator.create_license_server(host='127.0.0.1', port=0)
        server.start_async()
        server_port = server.get_port()

        client = emulator.create_license_client()

        try:
            connection_result = client.connect('127.0.0.1', server_port, timeout=2.0)
            assert connection_result, "License client must connect successfully"

            start_time = time.time()
            message_count = 100

            for i in range(message_count):
                license_request = f"LICENSE_CHECK:PRODUCT_{i}".encode()
                sent = client.send_license_request(license_request)
                assert sent, f"License request {i} failed to send"

            end_time = time.time()
            throughput = message_count / (end_time - start_time)

            assert throughput > 50, f"Throughput too low: {throughput} requests/second"

        finally:
            if client.is_connected():
                client.disconnect()
            server.stop()

    @pytest.mark.benchmark
    def test_license_emulation_performance(self, benchmark, sample_license_packet):
        """Benchmark REAL license server emulation performance."""
        def emulate_license_server():
            hooker = CloudLicenseHooker()

            parsed = hooker.parse_flexlm_packet(sample_license_packet)
            response = hooker.generate_license_response(parsed)

            return response

        result = benchmark(emulate_license_server)

        assert result is not None, "License emulation must return response"
        assert len(result) > 0, "License response must not be empty"
        assert benchmark.stats.mean < 0.02, "License emulation should be under 20ms"

    def test_network_error_handling_performance(self):
        """Test REAL network error handling performance."""
        hooker = CloudLicenseHooker()

        start_time = time.time()

        invalid_packets = [
            b"",
            b"\x00\x00\x00\x00",
            b"INVALID_PACKET_DATA",
            None,
            b"\xff" * 1000
        ]

        for packet in invalid_packets:
            try:
                result = hooker.parse_flexlm_packet(packet)
                if result is not None:
                    pass
            except Exception:
                pass

        end_time = time.time()

        assert end_time - start_time < 0.1, "Network error handling should be fast (under 100ms)"

    def test_license_session_persistence(self):
        """Test REAL license session persistence performance."""
        analyzer = LicenseProtocolAnalyzer()

        start_time = time.time()

        session_ids = []
        for i in range(20):
            session_id = analyzer.create_license_session(f"license_client_{i}", f"10.0.0.{i+1}")
            session_ids.append(session_id)

        for _ in range(10):
            for session_id in session_ids:
                analyzer.update_session_activity(session_id)

        active_count = len(analyzer.get_active_sessions())

        for session_id in session_ids:
            analyzer.close_session(session_id)

        end_time = time.time()

        assert active_count == 20, f"Expected 20 active sessions, got {active_count}"
        assert end_time - start_time < 2.0, "License session persistence test should complete under 2 seconds"

    @pytest.mark.benchmark
    def test_network_protocol_detection_performance(self, benchmark, network_capture_file):
        """Benchmark REAL network protocol detection speed."""
        def detect_protocols():
            capture = NetworkCapture()
            parsed = capture.parse_pcap_file(network_capture_file)
            return capture.detect_protocols(parsed['packets'])

        result = benchmark(detect_protocols)

        assert result is not None, "Protocol detection must return results"
        assert 'protocols' in result, "Result must contain detected protocols"
        assert len(result['protocols']) > 0, "Must detect at least one protocol"
        assert benchmark.stats.mean < 0.05, "Protocol detection should be under 50ms"

    def test_license_key_generation_performance(self):
        """Test REAL license key generation performance."""
        hooker = CloudLicenseHooker()

        start_time = time.time()

        keys = []
        for i in range(50):
            key = hooker.generate_license_key()
            keys.append(key)

            assert key is not None, f"License key generation {i} failed"
            assert len(key) > 0, f"License key {i} is empty"

        end_time = time.time()

        unique_keys = set(keys)
        assert len(unique_keys) == len(keys), "All generated license keys must be unique"
        assert end_time - start_time < 1.0, "License key generation should complete under 1 second"

    def test_network_capture_real_time_performance(self):
        """Test REAL real-time network capture performance."""
        capture = NetworkCapture()

        packets_captured = []

        def packet_handler(packet):
            packets_captured.append(packet)

        start_time = time.time()

        capture.start_real_time_capture('lo', packet_handler, duration=1.0)

        end_time = time.time()

        assert end_time - start_time >= 1.0, "Capture should run for at least 1 second"
        assert end_time - start_time < 1.5, "Capture should not significantly exceed 1 second"
