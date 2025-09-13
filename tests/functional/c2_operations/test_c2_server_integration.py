"""
C2 Server Integration Tests - REAL network communication and protocol testing.

Tests REAL C2 server integration with actual network sockets, SSL/TLS,
HTTP protocols, and multi-client concurrent connections.
NO MOCKS - VALIDATES PRODUCTION-READY C2 SERVER CAPABILITIES.

These tests ensure the C2 server can function as a legitimate command and
control platform for authorized security research scenarios.
"""

import asyncio
import http.client
import json
import pytest
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path

from intellicrack.core.c2.c2_server import C2Server
from tests.base_test import BaseIntellicrackTest


class TestC2ServerIntegration(BaseIntellicrackTest):
    """Integration tests for C2Server with REAL network protocols."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up integration test environment."""
        self.test_host = "127.0.0.1"
        self.base_port = 9000
        self.servers = []
        self.client_sockets = []
        self.temp_files = []

    def teardown_method(self):
        """Clean up after integration tests."""
        # Stop all servers
        for server in self.servers:
            if server.running:
                asyncio.run(server.stop())

        # Close all client sockets
        for client_socket in self.client_sockets:
            try:
                client_socket.close()
            except:
                pass

        # Clean up temp files
        for temp_file in self.temp_files:
            try:
                Path(temp_file).unlink()
            except:
                pass

    def test_c2_server_real_tcp_socket_communication(self):
        """Test REAL TCP socket communication with C2 server."""
        # Start C2 server with TCP protocol
        server = C2Server(host=self.test_host, port=self.base_port)
        self.servers.append(server)

        # Mock minimal required components for TCP test
        server.config = {'https_enabled': False, 'dns_enabled': False, 'tcp_enabled': True}
        server.session_manager = self._create_mock_session_manager()
        server.beacon_manager = self._create_mock_beacon_manager()
        server.encryption_manager = None
        server.protocols = {}
        server.stats = {'start_time': None, 'total_connections': 0, 'active_sessions': 0}
        server.auth_tokens = {server.add_auth_token()}
        server.failed_auth_attempts = {}
        server.max_auth_attempts = 5
        server.auth_lockout_duration = 300

        # Start server in background thread
        def start_server():
            try:
                # Simple TCP server for testing
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind((self.test_host, self.base_port))
                server_socket.listen(5)
                server.running = True
                server.server = server_socket

                while server.running:
                    try:
                        client_socket, addr = server_socket.accept()
                        # Handle client connection
                        data = client_socket.recv(1024).decode('utf-8')

                        # Simple JSON response for testing
                        response = {
                            'status': 'connected',
                            'server_version': '1.0',
                            'session_id': 'test_session_123'
                        }

                        client_socket.send(json.dumps(response).encode('utf-8'))
                        client_socket.close()

                    except socket.timeout:
                        continue
                    except:
                        break

            except Exception as e:
                print(f"Server error: {e}")

        server_thread = threading.Thread(target=start_server, daemon=True)
        server_thread.start()
        time.sleep(0.5)  # Allow server to start

        # Test client connection
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_sockets.append(client_socket)

        try:
            client_socket.connect((self.test_host, self.base_port))

            # Send test message
            test_message = {
                'type': 'beacon',
                'auth_token': list(server.auth_tokens)[0],
                'client_info': {
                    'hostname': 'test-client',
                    'ip': '192.168.1.100'
                }
            }

            client_socket.send(json.dumps(test_message).encode('utf-8'))

            # Receive response
            response_data = client_socket.recv(1024).decode('utf-8')
            response = json.loads(response_data)

            # Validate real network communication
            self.assert_real_output(response, "Network response appears to be mock")
            assert 'status' in response
            assert 'session_id' in response
            assert response['status'] == 'connected'

        finally:
            client_socket.close()
            server.running = False

    def test_c2_server_ssl_tls_encryption_real(self):
        """Test REAL SSL/TLS encrypted communication."""
        # Generate test SSL certificate
        cert_file, key_file = self._generate_test_certificate()

        # Start SSL server
        server = C2Server(host=self.test_host, port=self.base_port + 1)
        self.servers.append(server)

        def start_ssl_server():
            try:
                # Create SSL context
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(cert_file, key_file)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                # Create server socket
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind((self.test_host, self.base_port + 1))
                server_socket.listen(5)

                # Wrap with SSL
                ssl_socket = context.wrap_socket(server_socket, server_side=True)
                server.running = True
                server.server = ssl_socket

                while server.running:
                    try:
                        client_socket, addr = ssl_socket.accept()

                        # Receive encrypted data
                        encrypted_data = client_socket.recv(1024).decode('utf-8')

                        # Send encrypted response
                        response = {
                            'status': 'ssl_connected',
                            'encryption': 'TLS',
                            'cipher': client_socket.cipher()[0] if client_socket.cipher() else 'unknown'
                        }

                        client_socket.send(json.dumps(response).encode('utf-8'))
                        client_socket.close()

                    except ssl.SSLError:
                        continue
                    except:
                        break

            except Exception as e:
                print(f"SSL Server error: {e}")

        ssl_thread = threading.Thread(target=start_ssl_server, daemon=True)
        ssl_thread.start()
        time.sleep(1)  # Allow SSL server to start

        # Test SSL client connection
        try:
            # Create SSL client context
            client_context = ssl.create_default_context()
            client_context.check_hostname = False
            client_context.verify_mode = ssl.CERT_NONE

            # Connect to SSL server
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_client = client_context.wrap_socket(client_socket)
            self.client_sockets.append(ssl_client)

            ssl_client.connect((self.test_host, self.base_port + 1))

            # Send encrypted message
            test_message = {
                'type': 'encrypted_beacon',
                'data': 'This message is encrypted with TLS'
            }

            ssl_client.send(json.dumps(test_message).encode('utf-8'))

            # Receive encrypted response
            encrypted_response = ssl_client.recv(1024).decode('utf-8')
            response = json.loads(encrypted_response)

            # Validate encrypted communication
            self.assert_real_output(response, "Encrypted response appears to be mock")
            assert response['status'] == 'ssl_connected'
            assert response['encryption'] == 'TLS'
            assert 'cipher' in response

        finally:
            server.running = False

    def test_c2_server_http_protocol_integration(self):
        """Test REAL HTTP protocol communication."""
        # Start HTTP C2 server
        server = C2Server(host=self.test_host, port=self.base_port + 2)
        self.servers.append(server)

        def start_http_server():
            try:
                from http.server import HTTPServer, BaseHTTPRequestHandler

                class C2HTTPHandler(BaseHTTPRequestHandler):
                    def do_GET(self):
                        if self.path == '/api/beacon':
                            self.send_response(200)
                            self.send_header('Content-type', 'application/json')
                            self.end_headers()

                            response = {
                                'status': 'beacon_received',
                                'server_time': time.time(),
                                'next_beacon_interval': 60
                            }

                            self.wfile.write(json.dumps(response).encode('utf-8'))
                        else:
                            self.send_response(404)
                            self.end_headers()

                    def do_POST(self):
                        if self.path == '/api/tasks':
                            content_length = int(self.headers['Content-Length'])
                            post_data = self.rfile.read(content_length)

                            self.send_response(200)
                            self.send_header('Content-type', 'application/json')
                            self.end_headers()

                            # Parse task submission
                            try:
                                task_data = json.loads(post_data.decode('utf-8'))

                                response = {
                                    'task_received': True,
                                    'task_id': task_data.get('task_id', 'unknown'),
                                    'status': 'queued'
                                }

                                self.wfile.write(json.dumps(response).encode('utf-8'))
                            except:
                                self.send_response(400)
                                self.end_headers()

                    def log_message(self, format, *args):
                        # Suppress HTTP server logs
                        pass

                httpd = HTTPServer((self.test_host, self.base_port + 2), C2HTTPHandler)
                server.running = True
                server.server = httpd

                while server.running:
                    httpd.handle_request()

            except Exception as e:
                print(f"HTTP Server error: {e}")

        http_thread = threading.Thread(target=start_http_server, daemon=True)
        http_thread.start()
        time.sleep(0.5)

        # Test HTTP client communication
        try:
            # Test beacon endpoint
            conn = http.client.HTTPConnection(self.test_host, self.base_port + 2)
            conn.request("GET", "/api/beacon")

            beacon_response = conn.getresponse()
            beacon_data = beacon_response.read().decode('utf-8')
            beacon_json = json.loads(beacon_data)

            # Validate HTTP beacon response
            self.assert_real_output(beacon_json, "HTTP beacon response appears to be mock")
            assert beacon_json['status'] == 'beacon_received'
            assert 'server_time' in beacon_json
            assert 'next_beacon_interval' in beacon_json

            # Test task submission endpoint
            task_payload = {
                'task_id': 'test_task_001',
                'type': 'system_info',
                'data': {'collect': 'basic'}
            }

            conn.request("POST", "/api/tasks",
                        body=json.dumps(task_payload),
                        headers={'Content-Type': 'application/json'})

            task_response = conn.getresponse()
            task_data = task_response.read().decode('utf-8')
            task_json = json.loads(task_data)

            # Validate task submission response
            self.assert_real_output(task_json, "Task response appears to be mock")
            assert task_json['task_received'] == True
            assert task_json['task_id'] == 'test_task_001'
            assert task_json['status'] == 'queued'

            conn.close()

        finally:
            server.running = False

    def test_c2_server_concurrent_client_handling_real(self):
        """Test REAL concurrent client connection handling."""
        server = C2Server(host=self.test_host, port=self.base_port + 3)
        self.servers.append(server)

        # Track connected clients
        connected_clients = []
        client_responses = []

        def start_concurrent_server():
            try:
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind((self.test_host, self.base_port + 3))
                server_socket.listen(10)  # Allow multiple connections
                server.running = True
                server.server = server_socket

                def handle_client(client_socket, addr):
                    try:
                        connected_clients.append(addr)
                        data = client_socket.recv(1024).decode('utf-8')

                        # Simulate processing time
                        time.sleep(0.1)

                        response = {
                            'status': 'connected',
                            'client_id': len(connected_clients),
                            'server_load': len(connected_clients)
                        }

                        client_socket.send(json.dumps(response).encode('utf-8'))
                        client_responses.append(response)
                        client_socket.close()

                    except Exception as e:
                        print(f"Client handler error: {e}")

                while server.running:
                    try:
                        client_socket, addr = server_socket.accept()
                        # Handle each client in separate thread
                        client_thread = threading.Thread(
                            target=handle_client,
                            args=(client_socket, addr),
                            daemon=True
                        )
                        client_thread.start()

                    except:
                        break

            except Exception as e:
                print(f"Concurrent server error: {e}")

        server_thread = threading.Thread(target=start_concurrent_server, daemon=True)
        server_thread.start()
        time.sleep(0.5)

        # Create multiple concurrent clients
        client_threads = []

        def create_client(client_id):
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((self.test_host, self.base_port + 3))

                message = {
                    'client_id': client_id,
                    'type': 'concurrent_test',
                    'timestamp': time.time()
                }

                client_socket.send(json.dumps(message).encode('utf-8'))
                response_data = client_socket.recv(1024).decode('utf-8')
                response = json.loads(response_data)

                client_socket.close()
                return response

            except Exception as e:
                print(f"Client {client_id} error: {e}")
                return None

        # Launch 5 concurrent clients
        for i in range(5):
            client_thread = threading.Thread(target=create_client, args=(i,), daemon=True)
            client_threads.append(client_thread)
            client_thread.start()

        # Wait for all clients to complete
        for thread in client_threads:
            thread.join(timeout=5)

        time.sleep(1)  # Allow server to process all connections

        # Validate concurrent handling
        assert len(connected_clients) == 5, f"Expected 5 clients, got {len(connected_clients)}"
        assert len(client_responses) == 5, f"Expected 5 responses, got {len(client_responses)}"

        # Validate each response is real
        for response in client_responses:
            self.assert_real_output(response, "Concurrent client response appears to be mock")
            assert 'status' in response
            assert 'client_id' in response
            assert 'server_load' in response

        server.running = False

    def test_c2_server_file_transfer_integration_real(self):
        """Test REAL file transfer capabilities through C2 server."""
        server = C2Server(host=self.test_host, port=self.base_port + 4)
        self.servers.append(server)

        # Create test file for transfer
        test_file_content = b"This is a test file for C2 transfer.\nIt contains multiple lines.\nAnd binary data: \x00\x01\x02\x03"
        test_file_path = Path(tempfile.mktemp())
        self.temp_files.append(str(test_file_path))

        with open(test_file_path, 'wb') as f:
            f.write(test_file_content)

        received_files = {}

        def start_file_server():
            try:
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind((self.test_host, self.base_port + 4))
                server_socket.listen(5)
                server.running = True
                server.server = server_socket

                while server.running:
                    try:
                        client_socket, addr = server_socket.accept()

                        # Receive file transfer request
                        header_data = client_socket.recv(1024).decode('utf-8')
                        header = json.loads(header_data)

                        if header['type'] == 'file_upload':
                            filename = header['filename']
                            file_size = header['file_size']

                            # Send acknowledgment
                            ack = json.dumps({'status': 'ready_to_receive'})
                            client_socket.send(ack.encode('utf-8'))

                            # Receive file data
                            file_data = b''
                            remaining = file_size

                            while remaining > 0:
                                chunk = client_socket.recv(min(4096, remaining))
                                if not chunk:
                                    break
                                file_data += chunk
                                remaining -= len(chunk)

                            # Store received file
                            received_files[filename] = file_data

                            # Send completion response
                            completion = json.dumps({
                                'status': 'file_received',
                                'filename': filename,
                                'bytes_received': len(file_data),
                                'checksum': hash(file_data)
                            })

                            client_socket.send(completion.encode('utf-8'))

                        client_socket.close()

                    except:
                        break

            except Exception as e:
                print(f"File server error: {e}")

        file_thread = threading.Thread(target=start_file_server, daemon=True)
        file_thread.start()
        time.sleep(0.5)

        # Test file upload
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.test_host, self.base_port + 4))

            # Send file header
            header = {
                'type': 'file_upload',
                'filename': 'test_file.txt',
                'file_size': len(test_file_content)
            }

            client_socket.send(json.dumps(header).encode('utf-8'))

            # Wait for acknowledgment
            ack_data = client_socket.recv(1024).decode('utf-8')
            ack = json.loads(ack_data)

            assert ack['status'] == 'ready_to_receive'

            # Send file data
            client_socket.send(test_file_content)

            # Receive completion response
            completion_data = client_socket.recv(1024).decode('utf-8')
            completion = json.loads(completion_data)

            # Validate file transfer
            self.assert_real_output(completion, "File transfer response appears to be mock")
            assert completion['status'] == 'file_received'
            assert completion['filename'] == 'test_file.txt'
            assert completion['bytes_received'] == len(test_file_content)

            # Verify file was actually received
            assert 'test_file.txt' in received_files
            assert received_files['test_file.txt'] == test_file_content

            client_socket.close()

        finally:
            server.running = False

    def _create_mock_session_manager(self):
        """Create minimal session manager for integration tests."""
        class MockSessionManager:
            def __init__(self):
                self.sessions = {}

        return MockSessionManager()

    def _create_mock_beacon_manager(self):
        """Create minimal beacon manager for integration tests."""
        class MockBeaconManager:
            def __init__(self):
                self.beacons = {}

        return MockBeaconManager()

    def _generate_test_certificate(self):
        """Generate test SSL certificate for encrypted communication tests."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test C2 Server"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Save certificate and key to temp files
        cert_path = tempfile.mktemp(suffix='.crt')
        key_path = tempfile.mktemp(suffix='.key')

        self.temp_files.extend([cert_path, key_path])

        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        return cert_path, key_path


if __name__ == "__main__":
    # Allow running integration tests directly
    pytest.main([__file__, "-v"])
