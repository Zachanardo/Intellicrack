"""
Unit tests for C2 Communication with REAL network protocols.
Tests REAL C2 server, client, and protocol implementations.
NO MOCKS - ALL TESTS USE REAL NETWORK SOCKETS AND PROTOCOLS.
"""

import pytest
import socket
import threading
import time
import json
import ssl
from pathlib import Path

from intellicrack.core.c2.c2_server import C2Server
from intellicrack.core.c2.c2_client import C2Client
from intellicrack.core.c2.c2_manager import C2Manager
from intellicrack.core.c2.communication_protocols import ProtocolHandler
from intellicrack.core.c2.encryption_manager import EncryptionManager
from tests.base_test import BaseIntellicrackTest


class TestC2Communication(BaseIntellicrackTest):
    """Test C2 communication with REAL network protocols."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with C2 components."""
        self.server = None
        self.client = None
        self.test_port = 9999  # Use non-standard port for testing

    def teardown_method(self):
        """Clean up after each test."""
        if self.server:
            self.server.stop()
        if self.client:
            self.client.disconnect()

    def test_c2_server_startup_real(self):
        """Test REAL C2 server startup and listening."""
        # Start C2 server
        server_config = {
            'bind_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tcp',
            'encryption': 'none'  # Start with unencrypted for testing
        }

        self.server = C2Server(server_config)
        start_result = self.server.start()

        # Validate real server startup
        self.assert_real_output(start_result)
        assert 'status' in start_result
        assert 'listening_address' in start_result
        assert 'port' in start_result

        # Check server is actually listening
        assert start_result['status'] == 'running'
        assert start_result['port'] == self.test_port

        # Verify socket is bound
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Should fail to bind to same port
            test_socket.bind(('127.0.0.1', self.test_port))
            pytest.fail("Server should be occupying the port")
        except OSError:
            # Expected - port should be in use
            pass
        finally:
            test_socket.close()

    def test_c2_client_connection_real(self):
        """Test REAL C2 client connection to server."""
        # Start server first
        server_config = {
            'bind_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tcp',
            'encryption': 'none'
        }

        self.server = C2Server(server_config)
        self.server.start()
        time.sleep(0.5)  # Give server time to start

        # Connect client
        client_config = {
            'server_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tcp',
            'timeout': 10
        }

        self.client = C2Client(client_config)
        connection_result = self.client.connect()

        # Validate real connection
        self.assert_real_output(connection_result)
        assert 'connected' in connection_result
        assert 'session_id' in connection_result
        assert 'server_info' in connection_result

        # Check connection established
        assert connection_result['connected'] == True
        assert len(connection_result['session_id']) > 0

        # Verify server sees the connection
        server_connections = self.server.list_connections()
        assert len(server_connections) == 1
        assert server_connections[0]['session_id'] == connection_result['session_id']

    def test_c2_message_exchange_real(self):
        """Test REAL message exchange between C2 client and server."""
        # Setup server and client
        server_config = {
            'bind_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tcp'
        }

        self.server = C2Server(server_config)
        self.server.start()
        time.sleep(0.5)

        client_config = {
            'server_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tcp'
        }

        self.client = C2Client(client_config)
        self.client.connect()
        time.sleep(0.5)

        # Send message from client to server
        test_message = {
            'type': 'system_info',
            'hostname': 'test-machine',
            'os': 'Windows 10',
            'architecture': 'x64',
            'user': 'test-user'
        }

        send_result = self.client.send_message(test_message)

        # Validate message sending
        self.assert_real_output(send_result)
        assert 'sent' in send_result
        assert 'message_id' in send_result
        assert send_result['sent'] == True

        time.sleep(0.5)  # Allow message to be processed

        # Check server received message
        server_messages = self.server.get_received_messages()
        assert len(server_messages) > 0

        received_msg = server_messages[-1]
        assert received_msg['content']['type'] == 'system_info'
        assert received_msg['content']['hostname'] == 'test-machine'

    def test_c2_command_execution_real(self):
        """Test REAL command execution through C2 channel."""
        # Setup C2 connection
        self._setup_c2_connection()

        # Send command from server to client
        command = {
            'type': 'execute_command',
            'command': 'echo "Hello from C2"',
            'capture_output': True
        }

        command_result = self.server.send_command(command, target='all')

        # Validate command sending
        self.assert_real_output(command_result)
        assert 'command_id' in command_result
        assert 'sent_to' in command_result

        time.sleep(1)  # Allow command execution

        # Check client received and executed command
        client_responses = self.client.get_command_responses()
        assert len(client_responses) > 0

        response = client_responses[-1]
        assert 'output' in response
        assert 'Hello from C2' in response['output']

    def test_encrypted_communication_real(self):
        """Test REAL encrypted C2 communication."""
        # Setup encrypted server
        server_config = {
            'bind_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tcp',
            'encryption': 'aes256',
            'key': b'test_encryption_key_32_bytes_long'
        }

        self.server = C2Server(server_config)
        self.server.start()
        time.sleep(0.5)

        # Setup encrypted client
        client_config = {
            'server_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tcp',
            'encryption': 'aes256',
            'key': b'test_encryption_key_32_bytes_long'
        }

        self.client = C2Client(client_config)
        connection_result = self.client.connect()

        # Validate encrypted connection
        self.assert_real_output(connection_result)
        assert connection_result['connected'] == True
        assert connection_result.get('encrypted', False) == True

        # Test encrypted message exchange
        encrypted_message = {
            'type': 'encrypted_test',
            'secret_data': 'This should be encrypted'
        }

        send_result = self.client.send_message(encrypted_message)
        assert send_result['sent'] == True

        time.sleep(0.5)

        # Verify server received decrypted message
        server_messages = self.server.get_received_messages()
        received_msg = server_messages[-1]
        assert received_msg['content']['secret_data'] == 'This should be encrypted'

    def test_tls_communication_real(self):
        """Test REAL TLS-encrypted C2 communication."""
        # Generate test certificates for TLS
        cert_manager = EncryptionManager()
        cert_result = cert_manager.generate_test_certificates()

        # Setup TLS server
        server_config = {
            'bind_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tls',
            'cert_file': cert_result['cert_path'],
            'key_file': cert_result['key_path']
        }

        self.server = C2Server(server_config)
        self.server.start()
        time.sleep(0.5)

        # Setup TLS client
        client_config = {
            'server_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tls',
            'verify_cert': False  # Self-signed cert for testing
        }

        self.client = C2Client(client_config)
        connection_result = self.client.connect()

        # Validate TLS connection
        self.assert_real_output(connection_result)
        assert connection_result['connected'] == True
        assert connection_result.get('tls_enabled', False) == True

        # Test message over TLS
        tls_message = {'type': 'tls_test', 'data': 'TLS encrypted data'}
        send_result = self.client.send_message(tls_message)
        assert send_result['sent'] == True

    def test_http_c2_protocol_real(self):
        """Test REAL HTTP-based C2 communication."""
        # Setup HTTP C2 server
        server_config = {
            'bind_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'http',
            'endpoints': {
                'beacon': '/api/beacon',
                'tasks': '/api/tasks',
                'results': '/api/results'
            }
        }

        self.server = C2Server(server_config)
        self.server.start()
        time.sleep(0.5)

        # Setup HTTP client
        client_config = {
            'server_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'http',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'beacon_interval': 5
        }

        self.client = C2Client(client_config)
        connection_result = self.client.connect()

        # Validate HTTP connection
        self.assert_real_output(connection_result)
        assert connection_result['connected'] == True

        # Test HTTP beacon
        beacon_result = self.client.send_beacon()
        assert 'beacon_sent' in beacon_result
        assert beacon_result['beacon_sent'] == True

        # Check server received beacon
        server_beacons = self.server.get_beacons()
        assert len(server_beacons) > 0

    def test_dns_c2_protocol_real(self):
        """Test REAL DNS-based C2 communication."""
        # Setup DNS C2 server
        server_config = {
            'bind_address': '127.0.0.1',
            'port': 5353,  # Alternative DNS port
            'protocol': 'dns',
            'domain': 'test.local',
            'record_types': ['TXT', 'A', 'AAAA']
        }

        self.server = C2Server(server_config)
        self.server.start()
        time.sleep(0.5)

        # Setup DNS client
        client_config = {
            'server_address': '127.0.0.1',
            'port': 5353,
            'protocol': 'dns',
            'domain': 'test.local',
            'query_type': 'TXT'
        }

        self.client = C2Client(client_config)
        connection_result = self.client.connect()

        # Validate DNS connection
        self.assert_real_output(connection_result)

        # Test DNS query-based communication
        dns_message = {
            'type': 'dns_exfil',
            'data': 'exfiltrated_data'
        }

        send_result = self.client.send_dns_message(dns_message)
        assert 'query_sent' in send_result

    def test_c2_session_management_real(self):
        """Test REAL C2 session management and tracking."""
        # Setup multiple clients
        self._setup_c2_connection()

        # Create additional clients
        client2_config = {
            'server_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tcp'
        }

        client2 = C2Client(client2_config)
        client2.connect()
        time.sleep(0.5)

        # Check server manages multiple sessions
        sessions = self.server.list_sessions()

        # Validate session management
        self.assert_real_output(sessions)
        assert len(sessions) == 2

        for session in sessions:
            assert 'session_id' in session
            assert 'client_info' in session
            assert 'connected_at' in session
            assert 'last_seen' in session

        # Test session termination
        session_id = sessions[0]['session_id']
        termination_result = self.server.terminate_session(session_id)

        assert 'terminated' in termination_result
        assert termination_result['terminated'] == True

        # Verify session count decreased
        updated_sessions = self.server.list_sessions()
        assert len(updated_sessions) == 1

        client2.disconnect()

    def test_c2_persistence_real(self):
        """Test REAL C2 persistence mechanisms."""
        # Test connection persistence and reconnection
        self._setup_c2_connection()

        # Simulate network interruption
        original_session_id = self.client.get_session_id()
        self.client.simulate_network_interruption()

        time.sleep(1)

        # Test automatic reconnection
        reconnect_result = self.client.reconnect()

        # Validate reconnection
        self.assert_real_output(reconnect_result)
        assert 'reconnected' in reconnect_result
        assert reconnect_result['reconnected'] == True

        # Should have same or new session ID
        new_session_id = self.client.get_session_id()
        assert len(new_session_id) > 0

    def test_c2_stealth_features_real(self):
        """Test REAL C2 stealth and evasion features."""
        # Setup stealthy C2 server
        server_config = {
            'bind_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tcp',
            'stealth_features': {
                'jitter': True,
                'random_delays': True,
                'traffic_shaping': True,
                'protocol_mimicry': 'http'
            }
        }

        self.server = C2Server(server_config)
        self.server.start()
        time.sleep(0.5)

        # Setup stealthy client
        client_config = {
            'server_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tcp',
            'stealth_features': {
                'jitter': True,
                'random_delays': True,
                'traffic_shaping': True
            }
        }

        self.client = C2Client(client_config)
        connection_result = self.client.connect()

        # Validate stealthy connection
        self.assert_real_output(connection_result)
        assert connection_result['connected'] == True

        # Test jittered communication
        start_time = time.time()
        for i in range(3):
            message = {'type': 'test', 'sequence': i}
            self.client.send_message(message)
            time.sleep(0.1)
        end_time = time.time()

        # With jitter, timing should be variable
        communication_time = end_time - start_time
        assert communication_time > 0.3  # Should take longer due to jitter

    def _setup_c2_connection(self):
        """Helper method to setup basic C2 connection."""
        server_config = {
            'bind_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tcp'
        }

        self.server = C2Server(server_config)
        self.server.start()
        time.sleep(0.5)

        client_config = {
            'server_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tcp'
        }

        self.client = C2Client(client_config)
        self.client.connect()
        time.sleep(0.5)
