"""
Unit tests for License Emulator with REAL license server emulation.
Tests REAL license protocol emulation and response generation.
NO MOCKS - ALL TESTS USE REAL PROTOCOLS AND PRODUCE REAL RESULTS.
"""

import pytest
from pathlib import Path
import socket
import threading
import time
import struct

from intellicrack.core.network.license_emulator import LicenseEmulator
from tests.base_test import IntellicrackTestBase


class TestLicenseEmulator(IntellicrackTestBase):
    """Test license server emulation with REAL protocols."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with real license emulator."""
        self.emulator = LicenseEmulator()
        self.test_port = 27000  # FlexLM default
        
    def test_flexlm_server_emulation(self):
        """Test FlexLM license server emulation."""
        # Configure FlexLM emulation
        config = {
            'protocol': 'flexlm',
            'port': self.test_port,
            'features': [
                {'name': 'MATLAB', 'version': '2023', 'count': 10},
                {'name': 'Simulink', 'version': '2023', 'count': 5}
            ]
        }
        
        # Start emulator in thread
        server_thread = threading.Thread(
            target=self.emulator.start_server,
            args=(config,)
        )
        server_thread.daemon = True
        server_thread.start()
        
        time.sleep(0.5)  # Let server start
        
        # Test client connection
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect(('localhost', self.test_port))
            
            # Send FlexLM hello
            hello = struct.pack('>HHI', 
                0x0147,  # FlexLM version
                0x0001,  # Message type
                0x12345678  # Transaction ID
            )
            client.send(hello)
            
            # Receive response
            response = client.recv(1024)
            
            self.assert_real_output(response)
            assert len(response) > 0
            
            # Parse response
            version, msg_type, trans_id = struct.unpack('>HHI', response[:8])
            assert version == 0x0147
            assert msg_type == 0x0002  # Hello response
            assert trans_id == 0x12345678
            
        finally:
            client.close()
            self.emulator.stop_server()
            
    def test_hasp_server_emulation(self):
        """Test HASP license server emulation."""
        config = {
            'protocol': 'hasp',
            'port': 1947,  # HASP default
            'vendor_code': 0xDEADBEEF,
            'features': [
                {'id': 1, 'name': 'Feature1'},
                {'id': 2, 'name': 'Feature2'}
            ]
        }
        
        # Start HASP emulator
        self.emulator.configure_hasp(config)
        
        # Test HASP authentication
        auth_request = self.emulator.generate_hasp_auth_request(
            vendor_code=config['vendor_code']
        )
        
        self.assert_real_output(auth_request)
        assert len(auth_request) > 0
        
        # Process auth request
        auth_response = self.emulator.process_hasp_request(auth_request)
        
        assert 'status' in auth_response
        assert 'session_id' in auth_response
        assert auth_response['status'] == 'SUCCESS'
        
    def test_adobe_licensing_emulation(self):
        """Test Adobe licensing server emulation."""
        config = {
            'protocol': 'adobe',
            'activation_server': 'activate.adobe.com',
            'products': [
                {
                    'id': 'PHSP',
                    'name': 'Photoshop',
                    'version': '2023'
                }
            ]
        }
        
        # Configure Adobe emulation
        self.emulator.configure_adobe(config)
        
        # Test activation request
        activation = self.emulator.process_adobe_activation(
            serial='1234-5678-9012-3456',
            machine_id='ABCD1234',
            product_id='PHSP'
        )
        
        self.assert_real_output(activation)
        assert 'license_key' in activation
        assert 'activation_code' in activation
        assert 'expiry_date' in activation
        
        # License should be valid
        assert len(activation['license_key']) > 20
        assert activation['activation_code'] != ''
        
    def test_kms_server_emulation(self):
        """Test KMS (Key Management Service) emulation."""
        config = {
            'protocol': 'kms',
            'port': 1688,  # KMS default
            'kms_host': 'kms.example.com',
            'activation_interval': 180,  # days
            'renewal_interval': 7  # days
        }
        
        # Start KMS emulator
        self.emulator.configure_kms(config)
        
        # Test KMS activation
        activation_request = {
            'client_machine_id': 'CLIENT123',
            'application_id': 'Windows-10-Pro',
            'kms_count_required': 25,
            'current_count': 30
        }
        
        response = self.emulator.process_kms_activation(activation_request)
        
        self.assert_real_output(response)
        assert response['activated'] == True
        assert 'response_timestamp' in response
        assert response['activation_interval'] == 180
        assert response['renewal_interval'] == 7
        
    def test_multi_client_handling(self):
        """Test handling multiple concurrent clients."""
        config = {
            'protocol': 'flexlm',
            'port': self.test_port + 1,
            'max_clients': 5
        }
        
        # Start server
        server_thread = threading.Thread(
            target=self.emulator.start_concurrent_server,
            args=(config,)
        )
        server_thread.daemon = True
        server_thread.start()
        
        time.sleep(0.5)
        
        # Connect multiple clients
        clients = []
        for i in range(3):
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(('localhost', config['port']))
            clients.append(client)
            
        # Each client should get unique session
        sessions = []
        for client in clients:
            # Send request
            client.send(b'HELLO')
            response = client.recv(1024)
            
            self.assert_real_output(response)
            assert len(response) > 0
            sessions.append(response)
            
        # Sessions should be unique
        assert len(set(sessions)) == len(sessions)
        
        # Cleanup
        for client in clients:
            client.close()
        self.emulator.stop_server()
        
    def test_license_checkout_logic(self):
        """Test license checkout/checkin logic."""
        # Initialize license pool
        self.emulator.initialize_license_pool({
            'feature_A': {'total': 10, 'available': 10},
            'feature_B': {'total': 5, 'available': 5}
        })
        
        # Checkout license
        checkout = self.emulator.checkout_license(
            feature='feature_A',
            user='user1',
            host='host1'
        )
        
        self.assert_real_output(checkout)
        assert checkout['success'] == True
        assert checkout['license_id'] is not None
        assert checkout['remaining'] == 9
        
        # Try to checkout more than available
        for i in range(9):
            self.emulator.checkout_license('feature_A', f'user{i+2}', 'host1')
            
        # This should fail
        failed = self.emulator.checkout_license('feature_A', 'user12', 'host1')
        assert failed['success'] == False
        assert 'error' in failed
        
        # Checkin license
        checkin = self.emulator.checkin_license(checkout['license_id'])
        assert checkin['success'] == True
        assert checkin['remaining'] == 1
        
    def test_heartbeat_mechanism(self):
        """Test license heartbeat/keepalive mechanism."""
        # Setup heartbeat config
        config = {
            'heartbeat_interval': 1,  # seconds
            'timeout': 3  # seconds
        }
        
        self.emulator.configure_heartbeat(config)
        
        # Checkout license
        checkout = self.emulator.checkout_license('test_feature', 'user1', 'host1')
        license_id = checkout['license_id']
        
        # Send heartbeats
        for _ in range(3):
            heartbeat = self.emulator.send_heartbeat(license_id)
            self.assert_real_output(heartbeat)
            assert heartbeat['status'] == 'alive'
            time.sleep(0.5)
            
        # Stop heartbeat and wait for timeout
        time.sleep(4)
        
        # License should be expired
        status = self.emulator.check_license_status(license_id)
        assert status['expired'] == True
        
    def test_license_encryption(self):
        """Test license response encryption."""
        # Enable encryption
        self.emulator.enable_encryption({
            'algorithm': 'aes256',
            'key': b'0123456789ABCDEF0123456789ABCDEF'
        })
        
        # Generate encrypted license
        license_data = {
            'feature': 'PRO_FEATURE',
            'expiry': '2025-12-31',
            'user': 'testuser'
        }
        
        encrypted = self.emulator.generate_encrypted_license(license_data)
        
        self.assert_real_output(encrypted)
        assert 'encrypted_data' in encrypted
        assert 'signature' in encrypted
        assert len(encrypted['encrypted_data']) > len(str(license_data))
        
        # Verify decryption works
        decrypted = self.emulator.decrypt_license(encrypted)
        assert decrypted['feature'] == license_data['feature']
        
    def test_feature_dependency_handling(self):
        """Test feature dependency validation."""
        # Define feature dependencies
        dependencies = {
            'ADVANCED': ['BASIC'],
            'PREMIUM': ['BASIC', 'ADVANCED'],
            'ADDON': ['PREMIUM']
        }
        
        self.emulator.set_feature_dependencies(dependencies)
        
        # Test valid checkout (has dependencies)
        self.emulator.checkout_license('BASIC', 'user1', 'host1')
        self.emulator.checkout_license('ADVANCED', 'user1', 'host1')
        
        premium = self.emulator.checkout_license('PREMIUM', 'user1', 'host1')
        self.assert_real_output(premium)
        assert premium['success'] == True
        
        # Test invalid checkout (missing dependency)
        self.emulator.clear_checkouts()
        addon = self.emulator.checkout_license('ADDON', 'user2', 'host2')
        assert addon['success'] == False
        assert 'dependency' in addon['error'].lower()
        
    def test_geographic_restrictions(self):
        """Test geographic license restrictions."""
        # Configure geo restrictions
        self.emulator.set_geo_restrictions({
            'allowed_countries': ['US', 'CA', 'UK'],
            'blocked_countries': ['CN', 'RU']
        })
        
        # Test allowed country
        us_license = self.emulator.checkout_license(
            'feature1',
            'user1',
            'host1',
            client_ip='8.8.8.8'  # US IP
        )
        
        self.assert_real_output(us_license)
        assert us_license['success'] == True
        
        # Test blocked country (simulated)
        blocked_license = self.emulator.checkout_license(
            'feature1',
            'user2',
            'host2',
            client_ip='1.2.3.4',  # Simulated blocked
            country_override='CN'
        )
        
        assert blocked_license['success'] == False
        assert 'geographic' in blocked_license['error'].lower()
        
    def test_floating_license_management(self):
        """Test floating license pool management."""
        # Configure floating licenses
        self.emulator.configure_floating_licenses({
            'total_seats': 10,
            'overdraft_allowed': 2,
            'overdraft_grace_period': 3600  # 1 hour
        })
        
        # Checkout up to limit
        checkouts = []
        for i in range(10):
            checkout = self.emulator.checkout_floating_license(f'user{i}')
            checkouts.append(checkout)
            assert checkout['success'] == True
            
        # Overdraft checkout
        overdraft = self.emulator.checkout_floating_license('user11')
        self.assert_real_output(overdraft)
        assert overdraft['success'] == True
        assert overdraft['overdraft'] == True
        assert 'grace_period_end' in overdraft
        
        # Beyond overdraft limit
        exceeded = self.emulator.checkout_floating_license('user13')
        assert exceeded['success'] == False
        
    def test_license_usage_tracking(self):
        """Test license usage statistics tracking."""
        # Enable usage tracking
        self.emulator.enable_usage_tracking()
        
        # Simulate usage
        for i in range(5):
            checkout = self.emulator.checkout_license(
                'feature1',
                f'user{i}',
                f'host{i}'
            )
            time.sleep(0.1)
            self.emulator.checkin_license(checkout['license_id'])
            
        # Get usage statistics
        stats = self.emulator.get_usage_statistics('feature1')
        
        self.assert_real_output(stats)
        assert stats['total_checkouts'] == 5
        assert stats['unique_users'] == 5
        assert stats['avg_usage_time'] > 0
        assert 'peak_usage' in stats
        assert 'usage_by_hour' in stats
        
    def test_custom_validation_hooks(self):
        """Test custom license validation hooks."""
        # Define custom validator
        def custom_validator(request):
            # Check custom hardware ID
            if 'hardware_id' not in request:
                return False, "Missing hardware ID"
            if len(request['hardware_id']) != 32:
                return False, "Invalid hardware ID"
            return True, None
            
        self.emulator.add_validation_hook(custom_validator)
        
        # Test valid request
        valid_request = {
            'feature': 'test',
            'user': 'user1',
            'hardware_id': 'A' * 32
        }
        
        result = self.emulator.validate_license_request(valid_request)
        self.assert_real_output(result)
        assert result['valid'] == True
        
        # Test invalid request
        invalid_request = {
            'feature': 'test',
            'user': 'user1',
            'hardware_id': 'SHORT'
        }
        
        result = self.emulator.validate_license_request(invalid_request)
        assert result['valid'] == False
        assert 'hardware ID' in result['error']
        
    def test_license_server_discovery(self):
        """Test license server discovery protocol."""
        # Enable discovery
        self.emulator.enable_discovery({
            'broadcast_port': 27001,
            'service_name': 'TestLicenseServer',
            'version': '1.0'
        })
        
        # Test discovery response
        discovery_packet = b'DISCOVER_LICENSE_SERVER'
        response = self.emulator.handle_discovery_request(discovery_packet)
        
        self.assert_real_output(response)
        assert 'server_info' in response
        assert response['server_info']['service_name'] == 'TestLicenseServer'
        assert 'port' in response['server_info']
        assert 'features' in response['server_info']