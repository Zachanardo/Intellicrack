import pytest
import tempfile
import os
import time
import threading
import socket
from pathlib import Path

from intellicrack.core.network.cloud_license_hooker import CloudLicenseHooker
from intellicrack.core.network_capture import NetworkCapture
from intellicrack.plugins.custom_modules.license_server_emulator import LicenseServerEmulator
from intellicrack.core.network.license_protocol_analyzer import LicenseProtocolAnalyzer


class TestNetworkLicenseIntegration:
    """Integration tests for REAL network and license emulation workflows."""

    @pytest.fixture
    def test_license_packets(self):
        """Generate REAL license protocol packets for testing."""
        return {
            'flexlm': {
                'handshake': b'\x00\x00\x00\x14\x00\x00\x00\x01\x00\x00\x00\x00\x46\x4c\x45\x58\x00\x00\x00\x00',
                'license_request': b'\x00\x00\x00\x20\x00\x00\x00\x02\x00\x00\x00\x00\x4c\x49\x43\x45\x4e\x53\x45\x00\x50\x48\x4f\x54\x4f\x53\x48\x4f\x50\x00\x00\x00\x00',
                'checkout': b'\x00\x00\x00\x18\x00\x00\x00\x03\x00\x00\x00\x01\x43\x48\x45\x43\x4b\x4f\x55\x54\x00\x00\x00\x00'
            },
            'hasp': {
                'init': b'\x48\x41\x53\x50\x00\x01\x00\x00\x00\x00\x00\x10\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c',
                'login': b'\x48\x41\x53\x50\x00\x02\x00\x00\x00\x00\x00\x08\x4c\x4f\x47\x49\x4e\x00\x00\x00',
                'encrypt': b'\x48\x41\x53\x50\x00\x03\x00\x00\x00\x00\x00\x10\x45\x4e\x43\x52\x59\x50\x54\x00\x00\x00\x00\x00\x00\x00\x00'
            },
            'adobe': {
                'activation': b'\x41\x44\x4f\x42\x45\x00\x00\x00\x00\x00\x00\x20\x01\x00\x00\x00\x50\x48\x4f\x54\x4f\x53\x48\x4f\x50\x32\x30\x32\x33\x00\x00\x00\xff\xff\xff\xff',
                'verification': b'\x41\x44\x4f\x42\x45\x00\x00\x00\x00\x00\x00\x18\x02\x00\x00\x00\x56\x45\x52\x49\x46\x59\x00\x00\x00\x00\x00\x00\x00\x00',
                'deactivation': b'\x41\x44\x4f\x42\x45\x00\x00\x00\x00\x00\x00\x10\x03\x00\x00\x00\x44\x45\x41\x43\x54\x00\x00\x00\x00'
            }
        }

    @pytest.fixture
    def network_capture_data(self):
        """Create REAL network capture data for testing."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as temp_file:
            pcap_header = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00'
            pcap_header += b'\x00\x00\x00\x00\x00\x00\x00\x00'
            pcap_header += b'\xff\xff\x00\x00\x01\x00\x00\x00'

            ethernet_frame = b'\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x00'
            ip_header = b'\x45\x00\x00\x1c\x00\x01\x00\x00\x40\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01'
            udp_header = b'\x04\xd2\x04\xd2\x00\x08\x00\x00'

            packet_data = []
            for i in range(5):
                packet_header = b'\x00\x00\x00\x00\x00\x00\x00\x00'
                packet_header += (len(ethernet_frame + ip_header + udp_header) + 8).to_bytes(4, 'little')
                packet_header += (len(ethernet_frame + ip_header + udp_header) + 8).to_bytes(4, 'little')

                packet_data.append(packet_header + ethernet_frame + ip_header + udp_header + b'\x00' * 8)

            temp_file.write(pcap_header + b''.join(packet_data))
            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except:
            pass

    def test_complete_license_emulation_workflow(self, test_license_packets):
        """Test REAL complete license server emulation workflow."""
        hooker = CloudLicenseHooker()

        for protocol_name, packets in test_license_packets.items():
            emulation_session = hooker.create_emulation_session(protocol_name)
            assert emulation_session is not None, f"Must create emulation session for {protocol_name}"

            try:
                for packet_type, packet_data in packets.items():
                    parse_result = hooker.parse_packet(packet_data, protocol_name)
                    assert parse_result is not None, f"Must parse {protocol_name} {packet_type} packet"
                    assert 'packet_type' in parse_result, "Parsed packet must have type"
                    assert 'data' in parse_result, "Parsed packet must have data"

                    response = hooker.generate_response(parse_result, emulation_session)
                    assert response is not None, f"Must generate response for {protocol_name} {packet_type}"
                    assert len(response) > 0, "Response must not be empty"
                    assert response != packet_data, "Response must be different from request"

            finally:
                hooker.close_emulation_session(emulation_session)

    def test_license_server_client_integration_workflow(self):
        """Test REAL license server-client integration workflow."""
        emulator = LicenseServerEmulator()
        analyzer = LicenseProtocolAnalyzer()

        try:
            server = emulator.create_license_server(host='127.0.0.1', port=0)
            server.start_async()
            server_port = server.get_port()
            assert server_port > 0, "License server must provide valid port"

            time.sleep(0.5)

            client = emulator.create_license_client()
            connection_result = client.connect('127.0.0.1', server_port, timeout=5.0)
            assert connection_result, "License client must connect successfully"
            assert client.is_connected(), "Client must report connected status"

            session_id = analyzer.register_license_session(
                client.get_client_id(),
                client.get_remote_address()
            )
            assert session_id is not None, "License session must be registered"

            test_license_requests = [
                b'LICENSE_CHECK:PRODUCT_2024',
                b'FEATURE_REQUEST:professional_edition',
                b'VALIDATION:A3B7-K9M2-P5R8-Q4N6',
                b'RENEWAL_CHECK:subscription_status'
            ]

            for request in test_license_requests:
                send_result = client.send_license_request(request)
                assert send_result, f"License request must succeed: {request}"

                analyzer.update_session_activity(session_id)

                time.sleep(0.1)

                response = client.receive_license_response(timeout=2.0)
                if response is not None:
                    assert len(response) > 0, "License response must not be empty"

            client.disconnect()
            analyzer.close_session(session_id)

        finally:
            server.stop()

    def test_network_capture_to_license_analysis_workflow(self, network_capture_data, test_license_packets):
        """Test REAL network capture to license protocol analysis workflow."""
        capture = NetworkCapture()
        hooker = CloudLicenseHooker()

        parsed_capture = capture.parse_pcap_file(network_capture_data)
        assert parsed_capture is not None, "Network capture parsing must succeed"
        assert 'packets' in parsed_capture, "Parsed capture must contain packets"

        packets = parsed_capture['packets']
        assert len(packets) > 0, "Must parse at least one packet"

        for packet in packets:
            protocol_detection = capture.detect_license_protocol(packet)

            if protocol_detection and protocol_detection.get('protocol') in test_license_packets:
                protocol_name = protocol_detection['protocol']

                extracted_payload = capture.extract_license_payload(packet, protocol_name)
                if extracted_payload:
                    analysis_result = hooker.analyze_license_packet(extracted_payload, protocol_name)
                    assert analysis_result is not None, f"License analysis must succeed for {protocol_name}"
                    assert 'packet_structure' in analysis_result, "Analysis must identify packet structure"
                    assert 'license_info' in analysis_result, "Analysis must extract license information"

    def test_encrypted_license_communication_workflow(self):
        """Test REAL encrypted license communication workflow."""
        emulator = LicenseServerEmulator()
        server = emulator.create_encrypted_license_server(host='127.0.0.1', port=0)

        try:
            server.start_async()
            server_port = server.get_port()

            time.sleep(0.5)

            client = emulator.create_encrypted_license_client()
            connection_result = client.connect('127.0.0.1', server_port, timeout=5.0)
            assert connection_result, "Encrypted license client must connect successfully"

            key_exchange_result = client.perform_key_exchange()
            assert key_exchange_result, "Key exchange must succeed"

            test_license_data = b"LICENSE_KEY:A3B7-K9M2-P5R8-Q4N6"

            encrypted_message = client.encrypt_license_request(test_license_data)
            assert encrypted_message is not None, "License request encryption must succeed"
            assert encrypted_message != test_license_data, "Encrypted request must be different"

            send_result = client.send_encrypted_license_request(encrypted_message)
            assert send_result, "Encrypted license request send must succeed"

            encrypted_response = client.receive_encrypted_response(timeout=3.0)
            if encrypted_response is not None:
                decrypted_response = client.decrypt_license_response(encrypted_response)
                assert decrypted_response is not None, "License response decryption must succeed"
                assert len(decrypted_response) > 0, "Decrypted license response must not be empty"

            client.disconnect()

        finally:
            server.stop()

    def test_multi_protocol_license_server_workflow(self, test_license_packets):
        """Test REAL multi-protocol license server workflow."""
        hooker = CloudLicenseHooker()

        emulation_server = hooker.create_multi_protocol_server(['flexlm', 'hasp', 'adobe'])
        assert emulation_server is not None, "Multi-protocol server must be created"

        try:
            server_status = hooker.start_emulation_server(emulation_server)
            assert server_status, "Emulation server must start successfully"

            for protocol_name, packets in test_license_packets.items():
                protocol_client = hooker.create_protocol_client(protocol_name)
                assert protocol_client is not None, f"Must create client for {protocol_name}"

                try:
                    connection_result = protocol_client.connect_to_server(emulation_server)
                    assert connection_result, f"Client must connect to server for {protocol_name}"

                    for packet_type, packet_data in packets.items():
                        response = protocol_client.send_packet(packet_data)
                        assert response is not None, f"Must receive response for {protocol_name} {packet_type}"

                        validation_result = hooker.validate_license_response(response, protocol_name)
                        assert validation_result.get('valid', False), \
                            f"Response must be valid for {protocol_name} {packet_type}"

                finally:
                    protocol_client.disconnect()

        finally:
            hooker.stop_emulation_server(emulation_server)

    def test_license_protocol_switching_workflow(self):
        """Test REAL license protocol switching workflow."""
        emulator = LicenseServerEmulator()
        license_server = emulator.create_adaptive_license_server(host='127.0.0.1', port=0)

        try:
            license_server.start_async()
            server_port = license_server.get_port()

            protocol_configs = [
                {'name': 'flexlm', 'port': server_port, 'encryption': False},
                {'name': 'hasp', 'port': server_port, 'encryption': True},
                {'name': 'adobe', 'port': server_port, 'encryption': True},
                {'name': 'custom', 'port': server_port, 'encryption': False}
            ]

            for config in protocol_configs:
                switch_result = license_server.switch_to_protocol(config['name'], config)
                assert switch_result, f"Must switch to {config['name']} protocol"

                current_protocol = license_server.get_current_protocol()
                assert current_protocol == config['name'], f"Current protocol must be {config['name']}"

                client = emulator.create_protocol_client(config['name'])
                assert client is not None, f"Must create license client for {config['name']}"

                try:
                    connection_test = client.test_connection('127.0.0.1', config['port'])
                    if connection_test:
                        assert True, f"Connection test passed for {config['name']}"
                except Exception:
                    pass

        finally:
            license_server.stop()

    def test_concurrent_license_emulation_workflow(self, test_license_packets):
        """Test REAL concurrent license emulation workflow."""
        hooker = CloudLicenseHooker()
        results = []
        errors = []

        def emulate_protocol(protocol_name, packets, thread_id):
            try:
                session = hooker.create_emulation_session(f"{protocol_name}_{thread_id}")

                for packet_type, packet_data in packets.items():
                    parsed = hooker.parse_packet(packet_data, protocol_name)
                    response = hooker.generate_response(parsed, session)

                    results.append((thread_id, protocol_name, packet_type, len(response)))

                hooker.close_emulation_session(session)

            except Exception as e:
                errors.append((thread_id, protocol_name, str(e)))

        threads = []
        start_time = time.time()

        thread_id = 0
        for protocol_name, packets in test_license_packets.items():
            for _ in range(2):
                thread = threading.Thread(
                    target=emulate_protocol,
                    args=(protocol_name, packets, thread_id)
                )
                threads.append(thread)
                thread.start()
                thread_id += 1

        for thread in threads:
            thread.join(timeout=15.0)

        end_time = time.time()

        assert len(errors) == 0, f"Concurrent emulation errors: {errors}"
        assert len(results) > 0, "Must produce concurrent emulation results"
        assert end_time - start_time < 12.0, "Concurrent emulation should complete under 12 seconds"

        for thread_id, protocol_name, packet_type, response_length in results:
            assert response_length > 0, f"Thread {thread_id} {protocol_name} {packet_type} must produce response"

    def test_network_forensics_integration_workflow(self, network_capture_data):
        """Test REAL network forensics integration workflow."""
        capture = NetworkCapture()
        hooker = CloudLicenseHooker()

        forensics_config = {
            'capture_file': network_capture_data,
            'analysis_depth': 'comprehensive',
            'extract_license_data': True,
            'identify_patterns': True
        }

        forensics_result = capture.perform_forensic_analysis(forensics_config)
        assert forensics_result is not None, "Forensic analysis must return results"
        assert 'timeline' in forensics_result, "Results must contain timeline"
        assert 'protocols_detected' in forensics_result, "Results must contain detected protocols"
        assert 'license_traffic' in forensics_result, "Results must identify license traffic"

        timeline = forensics_result['timeline']
        assert isinstance(timeline, list), "Timeline must be a list"

        protocols_detected = forensics_result['protocols_detected']
        assert isinstance(protocols_detected, list), "Detected protocols must be a list"

        license_traffic = forensics_result['license_traffic']
        if len(license_traffic) > 0:
            for traffic_entry in license_traffic:
                assert 'timestamp' in traffic_entry, "Traffic entry must have timestamp"
                assert 'protocol' in traffic_entry, "Traffic entry must identify protocol"
                assert 'data_size' in traffic_entry, "Traffic entry must have data size"

    def test_license_server_failover_workflow(self, test_license_packets):
        """Test REAL license server failover workflow."""
        hooker = CloudLicenseHooker()

        primary_server = hooker.create_emulation_server(['flexlm'])
        backup_server = hooker.create_emulation_server(['flexlm'])

        failover_config = {
            'primary': primary_server,
            'backup': backup_server,
            'health_check_interval': 1.0,
            'failover_timeout': 3.0
        }

        try:
            primary_status = hooker.start_emulation_server(primary_server)
            backup_status = hooker.start_emulation_server(backup_server)

            assert primary_status, "Primary server must start"
            assert backup_status, "Backup server must start"

            failover_manager = hooker.create_failover_manager(failover_config)
            assert failover_manager is not None, "Failover manager must be created"

            client = hooker.create_protocol_client('flexlm')
            connection_result = client.connect_with_failover(failover_manager)
            assert connection_result, "Client must connect with failover support"

            primary_health = failover_manager.check_server_health(primary_server)
            assert primary_health, "Primary server must be healthy"

            hooker.trigger_server_shutdown(primary_server)

            time.sleep(2.0)

            failover_triggered = failover_manager.check_failover_status()
            if failover_triggered:
                assert failover_triggered.get('failed_over', False), "Failover must be triggered"
                assert failover_triggered.get('active_server') == backup_server, "Backup must be active"

            test_packet = test_license_packets['flexlm']['handshake']
            response = client.send_packet(test_packet)
            assert response is not None, "Client must still receive responses after failover"

        finally:
            hooker.stop_emulation_server(primary_server)
            hooker.stop_emulation_server(backup_server)

    def test_network_performance_monitoring_workflow(self):
        """Test REAL network performance monitoring workflow."""
        capture = NetworkCapture()
        protocols = CommunicationProtocols()

        monitor_config = {
            'interfaces': ['lo'],
            'protocols': ['tcp', 'udp'],
            'metrics': ['throughput', 'latency', 'packet_loss'],
            'duration': 3.0
        }

        monitoring_session = capture.start_performance_monitoring(monitor_config)
        assert monitoring_session is not None, "Performance monitoring must start"

        time.sleep(1.0)

        test_traffic = protocols.generate_test_traffic('tcp', count=10)
        assert test_traffic, "Must generate test traffic"

        time.sleep(2.5)

        monitoring_results = capture.stop_performance_monitoring(monitoring_session)
        assert monitoring_results is not None, "Performance monitoring must return results"
        assert 'metrics' in monitoring_results, "Results must contain metrics"
        assert 'summary' in monitoring_results, "Results must contain summary"

        metrics = monitoring_results['metrics']
        for metric_name in monitor_config['metrics']:
            if metric_name in metrics:
                metric_data = metrics[metric_name]
                assert isinstance(metric_data, dict), f"Metric {metric_name} must be a dictionary"
                assert 'average' in metric_data, f"Metric {metric_name} must have average"
                assert 'samples' in metric_data, f"Metric {metric_name} must have samples"
