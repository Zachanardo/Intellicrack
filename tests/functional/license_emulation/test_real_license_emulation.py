import pytest
import tempfile
import os
import struct
import socket
import threading
import time
import json
import base64
from datetime import datetime, timedelta
from pathlib import Path

from intellicrack.core.network_capture import NetworkCapture
from intellicrack.core.network.cloud_license_hooker import CloudLicenseHooker
from intellicrack.plugins.custom_modules.cloud_license_interceptor import CloudLicenseInterceptor
from intellicrack.plugins.custom_modules.hardware_dongle_emulator import HardwareDongleEmulator
from intellicrack.utils.templates.license_response_templates import LicenseResponseTemplates
from intellicrack.core.app_context import AppContext


class TestRealLicenseEmulation:
    """Functional tests for REAL license emulation and server operations."""

    @pytest.fixture
    def flexlm_license_request(self):
        """Create REAL FlexLM license request packet."""
        # FlexLM protocol structure
        request = b''

        # Header
        request += struct.pack('>I', 0x464C584D)  # Magic 'FLXM'
        request += struct.pack('>H', 0x0201)  # Version 2.1
        request += struct.pack('>H', 0x0001)  # Request type: LICENSE_REQUEST
        request += struct.pack('>I', 0x00001234)  # Transaction ID

        # License request data
        request += b'autocad\x00'  # Feature name
        request += b'2024.0\x00'   # Version
        request += struct.pack('>I', 1)  # Count
        request += b'user@host\x00'  # User@host
        request += b'DISPLAY=:0\x00'  # Display
        request += struct.pack('>I', int(time.time()))  # Timestamp

        # Host ID
        request += struct.pack('>I', 0x12345678)  # Primary host ID
        request += struct.pack('>I', 0x87654321)  # Secondary host ID

        return request

    @pytest.fixture
    def hasp_license_packet(self):
        """Create REAL HASP license check packet."""
        # HASP HL protocol
        packet = b''

        # Header
        packet += b'HASP'  # Signature
        packet += struct.pack('<I', 0x00010003)  # Version
        packet += struct.pack('<I', 0x00000100)  # Command: CHECK_LICENSE
        packet += struct.pack('<I', 0x00000040)  # Packet size

        # License data
        packet += struct.pack('<I', 0x12345678)  # Feature ID
        packet += struct.pack('<I', 0x00000001)  # License type
        packet += struct.pack('<Q', 0x0123456789ABCDEF)  # Vendor code
        packet += b'\x00' * 16  # Reserved

        return packet

    @pytest.fixture
    def adobe_activation_request(self):
        """Create REAL Adobe activation request."""
        request = {
            "activation_request": {
                "app_id": "Photoshop",
                "app_version": "2024.0.0",
                "serial_number": "1234-5678-9012-3456-7890-1234",
                "machine_id": "A1B2C3D4E5F6",
                "os_version": "Windows 10",
                "request_type": "initial_activation",
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        return json.dumps(request).encode()

    @pytest.fixture
    def app_context(self):
        """Create REAL application context."""
        context = AppContext()
        context.initialize()
        return context

    @pytest.fixture
    def license_server_config(self):
        """REAL license server configuration."""
        return {
            'flexlm': {
                'port': 27000,
                'vendor': 'autodesk',
                'features': ['autocad', '3dsmax', 'maya'],
                'timeout': 30
            },
            'hasp': {
                'port': 1947,
                'vendor_code': 0x0123456789ABCDEF,
                'features': {
                    0x12345678: 'professional',
                    0x87654321: 'enterprise'
                }
            },
            'adobe': {
                'port': 443,
                'endpoint': '/activation/v2',
                'products': ['photoshop', 'illustrator', 'premiere']
            },
            'custom': {
                'port': 8080,
                'protocol': 'http',
                'auth_method': 'token'
            }
        }

    def test_real_flexlm_license_server_emulation(self, flexlm_license_request, license_server_config, app_context):
        """Test REAL FlexLM license server emulation."""
        license_hooker = CloudLicenseHooker(app_context)

        # Start FlexLM emulation server
        server_config = license_server_config['flexlm']
        server_result = license_hooker.start_flexlm_server(server_config)
        assert server_result is not None, "FlexLM server must start"
        assert server_result['status'] == 'running', "Server must be running"
        assert 'server_thread' in server_result, "Must have server thread"

        try:
            # Connect as client
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5.0)
            client_socket.connect(('localhost', server_config['port']))

            # Send license request
            client_socket.send(flexlm_license_request)

            # Receive response
            response = client_socket.recv(4096)
            assert len(response) > 0, "Must receive response"

            # Parse response
            parsed_response = license_hooker.parse_flexlm_response(response)
            assert parsed_response is not None, "Response must be parseable"
            assert parsed_response['status'] == 'granted', "License must be granted"
            assert 'license_key' in parsed_response, "Must contain license key"
            assert 'expiry' in parsed_response, "Must contain expiry"

            # Verify license details
            assert parsed_response['feature'] == 'autocad', "Feature must match"
            assert parsed_response['version'] == '2024.0', "Version must match"

            client_socket.close()

        finally:
            # Stop server
            license_hooker.stop_flexlm_server()

    def test_real_hasp_dongle_emulation(self, hasp_license_packet, license_server_config, app_context):
        """Test REAL HASP hardware dongle emulation."""
        dongle_emulator = HardwareDongleEmulator()

        # Configure HASP emulation
        hasp_config = license_server_config['hasp']
        emulation_result = dongle_emulator.emulate_hasp_dongle(hasp_config)
        assert emulation_result is not None, "HASP emulation must succeed"
        assert emulation_result['status'] == 'active', "Emulation must be active"

        # Start HASP service
        service_result = dongle_emulator.start_hasp_service(hasp_config['port'])
        assert service_result['running'], "HASP service must start"

        try:
            # Test license check
            check_result = dongle_emulator.process_hasp_request(hasp_license_packet)
            assert check_result is not None, "Must process HASP request"
            assert 'response_packet' in check_result, "Must generate response"
            assert 'license_status' in check_result, "Must have license status"

            # Verify response
            response_packet = check_result['response_packet']
            assert len(response_packet) >= 64, "Response must be complete"
            assert response_packet[:4] == b'HASP', "Response must have HASP header"

            # Check license status
            license_status = check_result['license_status']
            assert license_status['valid'], "License must be valid"
            assert license_status['feature_id'] == 0x12345678, "Feature ID must match"
            assert license_status['feature_name'] == 'professional', "Feature name must match"

            # Test memory operations
            memory_result = dongle_emulator.emulate_hasp_memory_read(0x0000, 256)
            assert memory_result is not None, "Memory read must succeed"
            assert len(memory_result['data']) == 256, "Must read requested size"

        finally:
            # Stop service
            dongle_emulator.stop_hasp_service()

    def test_real_adobe_cloud_activation_emulation(self, adobe_activation_request, license_server_config, app_context):
        """Test REAL Adobe Creative Cloud activation emulation."""
        cloud_interceptor = CloudLicenseInterceptor()

        # Configure Adobe emulation
        adobe_config = license_server_config['adobe']

        # Start HTTPS server for Adobe
        server_result = cloud_interceptor.start_adobe_server(adobe_config)
        assert server_result is not None, "Adobe server must start"
        assert server_result['status'] == 'running', "Server must be running"

        try:
            # Process activation request
            activation_result = cloud_interceptor.process_adobe_activation(adobe_activation_request)
            assert activation_result is not None, "Activation must be processed"
            assert 'response' in activation_result, "Must have response"
            assert 'license_file' in activation_result, "Must generate license file"

            # Parse response
            response = json.loads(activation_result['response'])
            assert response['status'] == 'success', "Activation must succeed"
            assert 'license_key' in response, "Must have license key"
            assert 'activation_id' in response, "Must have activation ID"
            assert 'features' in response, "Must list features"

            # Verify license file
            license_file = activation_result['license_file']
            assert 'ADOBE_LICENSE' in license_file, "Must be Adobe license format"
            assert 'Photoshop' in license_file, "Must contain product name"
            assert '2024.0.0' in license_file, "Must contain version"

            # Test license validation
            validation_result = cloud_interceptor.validate_adobe_license(license_file)
            assert validation_result['valid'], "Generated license must be valid"
            assert validation_result['product'] == 'Photoshop', "Product must match"

        finally:
            # Stop server
            cloud_interceptor.stop_adobe_server()

    def test_real_network_license_interception(self, app_context):
        """Test REAL network license traffic interception."""
        network_capture = NetworkCapture()
        license_hooker = CloudLicenseHooker(app_context)

        # Start packet capture
        capture_config = {
            'interface': 'loopback',
            'filter': 'tcp port 27000 or tcp port 1947 or tcp port 443',
            'timeout': 10
        }

        capture_result = network_capture.start_capture(capture_config)
        assert capture_result is not None, "Capture must start"

        # Simulate license traffic
        test_ports = [27000, 1947, 8080]
        for port in test_ports:
            try:
                # Create test connection
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(1.0)
                test_socket.connect(('localhost', port))
                test_socket.send(b'TEST_LICENSE_REQUEST')
                test_socket.close()
            except:
                pass  # Expected if no server on port

        # Stop capture and analyze
        time.sleep(2)  # Allow capture to process
        packets = network_capture.stop_capture()

        # Analyze captured packets
        analysis_result = license_hooker.analyze_license_traffic(packets)
        assert analysis_result is not None, "Traffic analysis must succeed"
        assert 'protocols_detected' in analysis_result, "Must detect protocols"
        assert 'license_requests' in analysis_result, "Must identify license requests"

        # Check for automatic protocol detection
        if len(analysis_result['license_requests']) > 0:
            for request in analysis_result['license_requests']:
                assert 'protocol' in request, "Must identify protocol"
                assert 'port' in request, "Must identify port"
                assert 'direction' in request, "Must identify direction"

    def test_real_multi_protocol_license_emulation(self, license_server_config, app_context):
        """Test REAL multi-protocol license server emulation."""
        license_hooker = CloudLicenseHooker(app_context)

        # Start multi-protocol server
        multi_config = {
            'protocols': ['flexlm', 'hasp', 'custom'],
            'ports': {
                'flexlm': 27000,
                'hasp': 1947,
                'custom': 8080
            },
            'unified_management': True
        }

        multi_result = license_hooker.start_multi_protocol_server(multi_config)
        assert multi_result is not None, "Multi-protocol server must start"
        assert multi_result['status'] == 'running', "Server must be running"
        assert 'active_protocols' in multi_result, "Must list active protocols"

        active_protocols = multi_result['active_protocols']
        assert len(active_protocols) == 3, "All protocols must be active"

        try:
            # Test each protocol
            test_results = {}

            # Test FlexLM
            flexlm_test = license_hooker.test_protocol_endpoint('flexlm', 27000)
            test_results['flexlm'] = flexlm_test
            assert flexlm_test['responsive'], "FlexLM must respond"

            # Test HASP
            hasp_test = license_hooker.test_protocol_endpoint('hasp', 1947)
            test_results['hasp'] = hasp_test
            assert hasp_test['responsive'], "HASP must respond"

            # Test custom
            custom_test = license_hooker.test_protocol_endpoint('custom', 8080)
            test_results['custom'] = custom_test
            assert custom_test['responsive'], "Custom protocol must respond"

            # Verify unified management
            management_status = license_hooker.get_server_status()
            assert management_status['total_requests'] >= 3, "Must track all requests"
            assert management_status['active_licenses'] >= 0, "Must track licenses"

        finally:
            # Stop all servers
            license_hooker.stop_all_servers()

    def test_real_license_persistence_and_caching(self, app_context):
        """Test REAL license persistence and caching mechanisms."""
        license_hooker = CloudLicenseHooker(app_context)

        # Generate test license
        test_license = {
            'license_id': 'TEST-1234-5678-9012',
            'product': 'TestProduct',
            'features': ['feature1', 'feature2', 'feature3'],
            'expiry': (datetime.utcnow() + timedelta(days=30)).isoformat(),
            'hardware_id': 'HW-12345678',
            'max_activations': 3
        }

        # Store license
        store_result = license_hooker.store_license(test_license)
        assert store_result['success'], "License storage must succeed"
        assert 'storage_path' in store_result, "Must have storage path"

        # Test caching
        cache_result = license_hooker.cache_license(test_license['license_id'], test_license)
        assert cache_result['cached'], "License must be cached"

        # Retrieve from cache
        cached_license = license_hooker.get_cached_license(test_license['license_id'])
        assert cached_license is not None, "Must retrieve from cache"
        assert cached_license['product'] == test_license['product'], "Cached data must match"

        # Test persistence across restart
        license_hooker.clear_cache()

        # Load from persistent storage
        loaded_license = license_hooker.load_license(test_license['license_id'])
        assert loaded_license is not None, "Must load from storage"
        assert loaded_license['features'] == test_license['features'], "Loaded data must match"

        # Test expiry handling
        expired_license = test_license.copy()
        expired_license['license_id'] = 'EXPIRED-TEST'
        expired_license['expiry'] = (datetime.utcnow() - timedelta(days=1)).isoformat()

        expiry_check = license_hooker.validate_license_expiry(expired_license)
        assert not expiry_check['valid'], "Expired license must be invalid"
        assert expiry_check['reason'] == 'expired', "Must identify expiry"

    def test_real_license_feature_control(self, app_context):
        """Test REAL license feature control and restrictions."""
        license_hooker = CloudLicenseHooker(app_context)
        templates = LicenseResponseTemplates()

        # Create tiered licenses
        license_tiers = {
            'basic': {
                'features': ['core', 'export'],
                'limits': {'users': 1, 'projects': 5}
            },
            'professional': {
                'features': ['core', 'export', 'advanced', 'automation'],
                'limits': {'users': 5, 'projects': 50}
            },
            'enterprise': {
                'features': ['core', 'export', 'advanced', 'automation', 'api', 'custom'],
                'limits': {'users': -1, 'projects': -1}  # Unlimited
            }
        }

        # Test feature checking for each tier
        for tier_name, tier_config in license_tiers.items():
            # Generate license
            license_data = templates.generate_license_response(
                product='TestProduct',
                tier=tier_name,
                features=tier_config['features'],
                limits=tier_config['limits']
            )

            # Test feature access
            for feature in ['core', 'export', 'advanced', 'automation', 'api', 'custom']:
                access_result = license_hooker.check_feature_access(license_data, feature)

                if feature in tier_config['features']:
                    assert access_result['allowed'], f"{tier_name} should have {feature}"
                else:
                    assert not access_result['allowed'], f"{tier_name} should not have {feature}"

                assert 'reason' in access_result, "Must provide access reason"

            # Test limits
            limit_check = license_hooker.check_license_limits(license_data, {
                'current_users': 3,
                'current_projects': 10
            })

            if tier_name == 'basic':
                assert not limit_check['users_ok'], "Basic should exceed user limit"
                assert not limit_check['projects_ok'], "Basic should exceed project limit"
            elif tier_name == 'professional':
                assert limit_check['users_ok'], "Professional should allow 3 users"
                assert limit_check['projects_ok'], "Professional should allow 10 projects"
            else:  # enterprise
                assert limit_check['users_ok'], "Enterprise has unlimited users"
                assert limit_check['projects_ok'], "Enterprise has unlimited projects"

    def test_real_license_heartbeat_mechanism(self, app_context):
        """Test REAL license heartbeat and keep-alive mechanisms."""
        license_hooker = CloudLicenseHooker(app_context)

        # Configure heartbeat
        heartbeat_config = {
            'interval': 30,  # seconds
            'timeout': 90,   # seconds
            'retry_count': 3,
            'license_id': 'HB-TEST-LICENSE'
        }

        # Start heartbeat monitoring
        heartbeat_result = license_hooker.start_heartbeat_monitor(heartbeat_config)
        assert heartbeat_result['started'], "Heartbeat monitor must start"
        assert 'monitor_thread' in heartbeat_result, "Must have monitor thread"

        try:
            # Simulate heartbeats
            for i in range(3):
                beat_result = license_hooker.send_heartbeat(heartbeat_config['license_id'])
                assert beat_result['acknowledged'], f"Heartbeat {i} must be acknowledged"
                assert 'timestamp' in beat_result, "Must have timestamp"
                time.sleep(1)

            # Check license status
            status = license_hooker.get_heartbeat_status(heartbeat_config['license_id'])
            assert status['active'], "License must be active"
            assert status['last_heartbeat'] is not None, "Must have last heartbeat time"
            assert status['consecutive_beats'] >= 3, "Must count heartbeats"

            # Test timeout handling
            time.sleep(2)  # Simulate delay
            timeout_check = license_hooker.check_heartbeat_timeout(
                heartbeat_config['license_id'],
                heartbeat_config['timeout']
            )
            assert not timeout_check['timed_out'], "Should not timeout yet"

        finally:
            # Stop monitor
            license_hooker.stop_heartbeat_monitor(heartbeat_config['license_id'])

    def test_real_license_migration_and_transfer(self, app_context):
        """Test REAL license migration and transfer operations."""
        license_hooker = CloudLicenseHooker(app_context)

        # Create source license
        source_license = {
            'license_id': 'MIGRATE-SOURCE-001',
            'product': 'TestProduct',
            'hardware_id': 'OLD-HW-12345',
            'features': ['all'],
            'activations': 1
        }

        # Create transfer request
        transfer_request = {
            'source_license': source_license['license_id'],
            'source_hardware': source_license['hardware_id'],
            'target_hardware': 'NEW-HW-67890',
            'reason': 'hardware_upgrade',
            'timestamp': datetime.utcnow().isoformat()
        }

        # Process transfer
        transfer_result = license_hooker.transfer_license(transfer_request)
        assert transfer_result is not None, "Transfer must be processed"
        assert transfer_result['status'] == 'success', "Transfer must succeed"
        assert 'new_license_id' in transfer_result, "Must generate new license ID"
        assert 'deactivation_proof' in transfer_result, "Must provide deactivation proof"

        # Verify old license is deactivated
        old_status = license_hooker.check_license_status(source_license['license_id'])
        assert old_status['status'] == 'deactivated', "Old license must be deactivated"
        assert old_status['reason'] == 'transferred', "Must show transfer reason"

        # Verify new license is active
        new_status = license_hooker.check_license_status(transfer_result['new_license_id'])
        assert new_status['status'] == 'active', "New license must be active"
        assert new_status['hardware_id'] == 'NEW-HW-67890', "Hardware ID must be updated"
        assert new_status['features'] == source_license['features'], "Features must be preserved"

    def test_real_offline_license_activation(self, app_context):
        """Test REAL offline license activation workflow."""
        license_hooker = CloudLicenseHooker(app_context)

        # Generate offline request
        offline_request = {
            'product': 'TestProduct',
            'version': '2024.0',
            'hardware_fingerprint': license_hooker.generate_hardware_fingerprint(),
            'request_code': license_hooker.generate_request_code(),
            'timestamp': datetime.utcnow().isoformat()
        }

        # Encode request for user
        encoded_request = base64.b64encode(
            json.dumps(offline_request).encode()
        ).decode()

        assert len(encoded_request) > 0, "Request must be encoded"

        # Simulate server-side processing
        server_response = license_hooker.process_offline_request(encoded_request)
        assert server_response is not None, "Server must process request"
        assert 'activation_code' in server_response, "Must generate activation code"
        assert 'license_file' in server_response, "Must generate license file"

        # Decode and apply activation
        activation_code = server_response['activation_code']
        activation_result = license_hooker.apply_offline_activation(activation_code)

        assert activation_result['success'], "Offline activation must succeed"
        assert activation_result['product'] == 'TestProduct', "Product must match"
        assert 'features_enabled' in activation_result, "Must enable features"

        # Verify offline license works
        offline_check = license_hooker.validate_offline_license()
        assert offline_check['valid'], "Offline license must be valid"
        assert offline_check['mode'] == 'offline', "Must identify as offline"

    def test_real_license_audit_trail(self, app_context):
        """Test REAL license audit trail and compliance logging."""
        license_hooker = CloudLicenseHooker(app_context)

        # Enable audit logging
        audit_config = {
            'log_level': 'detailed',
            'include_timestamps': True,
            'include_hardware': True,
            'retention_days': 90
        }

        audit_result = license_hooker.enable_audit_trail(audit_config)
        assert audit_result['enabled'], "Audit trail must be enabled"

        # Perform various license operations
        operations = [
            {'type': 'activation', 'license_id': 'AUDIT-001', 'result': 'success'},
            {'type': 'validation', 'license_id': 'AUDIT-001', 'result': 'valid'},
            {'type': 'feature_check', 'feature': 'advanced', 'result': 'granted'},
            {'type': 'deactivation', 'license_id': 'AUDIT-001', 'result': 'success'}
        ]

        for op in operations:
            license_hooker.log_license_operation(op)

        # Retrieve audit log
        audit_log = license_hooker.get_audit_log(
            start_time=datetime.utcnow() - timedelta(hours=1),
            end_time=datetime.utcnow()
        )

        assert len(audit_log) >= len(operations), "All operations must be logged"

        # Verify audit entries
        for entry in audit_log:
            assert 'timestamp' in entry, "Must have timestamp"
            assert 'operation_type' in entry, "Must have operation type"
            assert 'result' in entry, "Must have result"
            assert 'session_id' in entry, "Must have session tracking"

        # Generate compliance report
        compliance_report = license_hooker.generate_compliance_report({
            'period': 'last_30_days',
            'include_violations': True,
            'format': 'detailed'
        })

        assert compliance_report is not None, "Must generate compliance report"
        assert 'total_activations' in compliance_report, "Must count activations"
        assert 'unique_users' in compliance_report, "Must count users"
        assert 'feature_usage' in compliance_report, "Must track feature usage"
        assert 'violations' in compliance_report, "Must identify violations"
