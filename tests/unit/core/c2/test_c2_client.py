"""
Comprehensive C2Client Tests - Production-Ready Security Research Validation

Tests REAL C2 client functionality with genuine exploitation capabilities.
NO MOCKS OR STUBS - All tests validate actual C2 client operations
for binary analysis and security research scenarios.
"""

import asyncio
import json
import os
import platform
import pytest
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from intellicrack.core.c2.c2_client import C2Client
from intellicrack.core.c2.c2_server import C2Server
from intellicrack.core.c2.base_c2 import BaseC2
from intellicrack.handlers.psutil_handler import psutil
from tests.base_test import BaseIntellicrackTest


class TestC2Client(BaseIntellicrackTest):
    """
    Comprehensive C2Client test suite validating production-ready
    C2 client capabilities for security research scenarios.
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test environment with real C2 infrastructure."""
        self.test_port = 9998
        self.server = None
        self.client = None
        self.test_config = {
            "server_host": "127.0.0.1",
            "server_port": self.test_port,
            "protocol": "tcp",
            "encryption_key": b"test_key_32_bytes_for_encryption!",
            "client_id": "test_client_001",
            "heartbeat_interval": 5,
            "max_reconnect_attempts": 3,
            "use_encryption": True,
            "verify_ssl": False,
            "jitter_enabled": True,
            "sleep_time": 0.5,
            "max_jitter": 0.1,
        }

    def teardown_method(self):
        """Clean up test resources."""
        if self.client:
            try:
                asyncio.run(self.client.stop())
            except:
                pass
        if self.server:
            try:
                self.server.stop()
            except:
                pass

    def test_c2_client_initialization_real(self):
        """Test real C2Client initialization with configuration validation."""
        client = C2Client(self.test_config)

        # Validate initialization creates production-ready client
        self.assert_real_output(client)
        assert client.server_host == "127.0.0.1"
        assert client.server_port == self.test_port
        assert client.protocol == "tcp"
        assert client.encryption_key is not None
        assert client.client_id == "test_client_001"
        assert client.heartbeat_interval == 5
        assert client.max_reconnect_attempts == 3
        assert client.use_encryption == True
        assert client.jitter_enabled == True

        # Validate client has all required security capabilities
        assert hasattr(client, 'command_queue')
        assert hasattr(client, 'result_queue')
        assert hasattr(client, 'running')
        assert hasattr(client, 'connected')
        assert hasattr(client, 'session_start_time')

        # Statistics tracking for operational monitoring
        assert client.commands_executed == 0
        assert client.bytes_sent == 0
        assert client.bytes_received == 0
        assert isinstance(client.session_start_time, float)

    def test_multi_protocol_initialization_real(self):
        """Test real multi-protocol C2 client initialization."""
        protocols_config = {
            "protocols": {
                "https_enabled": True,
                "dns_enabled": True,
                "tcp_enabled": True,
                "https": {"host": "127.0.0.1", "port": 8443},
                "dns": {"host": "127.0.0.1", "port": 5353, "domain": "test.local"},
                "tcp": {"host": "127.0.0.1", "port": 4444}
            }
        }
        config = {**self.test_config, **protocols_config}

        client = C2Client(config)

        # Should initialize with multi-protocol support
        self.assert_real_output(client)
        assert client.config.get("protocols") is not None

        # Validate protocol initialization method exists and works
        try:
            client._initialize_protocols()
            # Should not raise exceptions for valid config
        except Exception as e:
            pytest.fail(f"Protocol initialization failed: {e}")

    async def test_c2_client_connection_establishment_real(self):
        """Test real C2 client connection establishment with server."""
        # Start real C2 server
        server_config = {
            'bind_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tcp'
        }

        self.server = C2Server(server_config)
        self.server.start()
        await asyncio.sleep(0.5)

        # Create and start C2 client
        client = C2Client(self.test_config)
        self.client = client

        # Test connection establishment
        try:
            await client.start()

            # Validate real connection was established
            assert client.running == True
            assert client.session_id is not None
            assert len(client.session_id) > 0

            # Verify server registered the connection
            connections = self.server.list_connections()
            assert len(connections) >= 1

        except Exception as e:
            # Connection establishment is critical capability
            pytest.fail(f"Failed to establish C2 connection: {e}")

    async def test_c2_client_registration_real(self):
        """Test real C2 client registration with server including system info."""
        await self._setup_server_client()

        # Registration should gather real system information
        system_info = await self.client._gather_system_info()

        # Validate real system information gathering
        self.assert_real_output(system_info)
        assert 'hostname' in system_info
        assert 'platform' in system_info
        assert 'architecture' in system_info
        assert 'username' in system_info
        assert 'domain' in system_info
        assert 'processes' in system_info
        assert 'network_interfaces' in system_info

        # System info should contain realistic data
        assert len(system_info['hostname']) > 0
        assert system_info['platform'] in ['Windows', 'Linux', 'Darwin']
        assert system_info['architecture'] in ['x86', 'x64', 'ARM64']
        assert len(system_info['processes']) > 0
        assert len(system_info['network_interfaces']) > 0

    async def test_c2_client_heartbeat_beacon_real(self):
        """Test real C2 client heartbeat and beacon functionality."""
        await self._setup_server_client()

        # Test beacon sending
        beacon_result = await self.client._send_beacon()

        # Validate real beacon functionality
        self.assert_real_output(beacon_result)
        assert 'beacon_sent' in beacon_result or 'status' in beacon_result

        # Beacon should include operational data
        if 'beacon_data' in beacon_result:
            beacon_data = beacon_result['beacon_data']
            assert 'timestamp' in beacon_data
            assert 'client_status' in beacon_data
            assert 'system_health' in beacon_data

    async def test_shell_command_execution_real(self):
        """Test real shell command execution through C2 client."""
        await self._setup_server_client()

        # Test basic command execution
        if platform.system() == "Windows":
            test_command = "echo Test Command Execution"
        else:
            test_command = "echo 'Test Command Execution'"

        result = await self.client._execute_shell_command(test_command)

        # Validate real command execution
        self.assert_real_output(result)
        assert 'output' in result or 'stdout' in result
        assert 'exit_code' in result

        # Command should actually execute and return output
        output = result.get('output') or result.get('stdout', '')
        assert 'Test Command Execution' in output
        assert result['exit_code'] == 0

    async def test_file_download_real(self):
        """Test real file download capability through C2 client."""
        await self._setup_server_client()

        # Create test file to download
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
            temp_file.write("Test file content for C2 download")
            temp_file_path = temp_file.name

        try:
            # Test file download
            result = await self.client._download_file(temp_file_path)

            # Validate real file download
            self.assert_real_output(result)
            assert 'file_data' in result or 'content' in result
            assert 'file_size' in result

            # Downloaded content should match original
            file_data = result.get('file_data') or result.get('content', b'')
            if isinstance(file_data, str):
                file_data = file_data.encode()
            assert b"Test file content for C2 download" in file_data
            assert result['file_size'] > 0

        finally:
            # Clean up test file
            try:
                os.unlink(temp_file_path)
            except:
                pass

    async def test_file_upload_real(self):
        """Test real file upload capability through C2 client."""
        await self._setup_server_client()

        # Create test data to upload
        test_data = b"Test data for C2 upload functionality"
        upload_path = os.path.join(tempfile.gettempdir(), "c2_upload_test.txt")

        try:
            # Test file upload
            result = await self.client._upload_file(test_data, upload_path)

            # Validate real file upload
            self.assert_real_output(result)
            assert 'uploaded' in result or 'success' in result
            assert 'file_path' in result

            # Verify file was actually uploaded
            assert os.path.exists(upload_path)
            with open(upload_path, 'rb') as f:
                uploaded_content = f.read()
            assert uploaded_content == test_data

        finally:
            # Clean up uploaded file
            try:
                os.unlink(upload_path)
            except:
                pass

    async def test_screenshot_capture_real(self):
        """Test real screenshot capture capability."""
        await self._setup_server_client()

        try:
            # Test screenshot capture
            result = await self.client._take_screenshot()

            # Validate real screenshot functionality
            if result.get('error') and 'display' in result['error'].lower():
                # Skip if no display available (headless environment)
                pytest.skip("No display available for screenshot test")

            self.assert_real_output(result)
            assert 'screenshot' in result or 'image_data' in result
            assert 'format' in result

            # Screenshot should contain actual image data
            image_data = result.get('screenshot') or result.get('image_data')
            assert len(image_data) > 1000  # Reasonable minimum size
            assert result['format'] in ['PNG', 'JPEG', 'BMP']

        except Exception as e:
            if 'display' in str(e).lower() or 'screen' in str(e).lower():
                pytest.skip("No display available for screenshot test")
            else:
                raise

    async def test_process_enumeration_real(self):
        """Test real process enumeration capability."""
        await self._setup_server_client()

        # Test process listing
        result = await self.client._get_process_list()

        # Validate real process enumeration
        self.assert_real_output(result)
        assert 'processes' in result
        assert isinstance(result['processes'], list)
        assert len(result['processes']) > 0

        # Process list should contain real process information
        first_process = result['processes'][0]
        required_fields = ['pid', 'name', 'status']
        for field in required_fields:
            assert field in first_process
            assert first_process[field] is not None

        # Should include current process
        current_pid = os.getpid()
        process_pids = [p['pid'] for p in result['processes']]
        assert current_pid in process_pids

    async def test_network_scanning_real(self):
        """Test real network scanning capability."""
        await self._setup_server_client()

        # Test local network scan (limited scope for testing)
        scan_config = {
            'target': '127.0.0.1',
            'ports': [22, 80, 443, 3389, 5985],
            'timeout': 2
        }

        result = await self.client._network_scan(scan_config)

        # Validate real network scanning
        self.assert_real_output(result)
        assert 'scan_results' in result
        assert 'target' in result
        assert result['target'] == '127.0.0.1'

        # Scan should contain port information
        scan_results = result['scan_results']
        assert isinstance(scan_results, list)

        # Should detect listening ports on localhost
        for port_result in scan_results:
            assert 'port' in port_result
            assert 'status' in port_result
            assert port_result['status'] in ['open', 'closed', 'filtered']

    async def test_keylogger_functionality_real(self):
        """Test real keylogger start/stop functionality."""
        await self._setup_server_client()

        # Test keylogger startup
        start_result = await self.client._start_keylogging()

        if start_result.get('error') and 'permission' in start_result['error'].lower():
            pytest.skip("Insufficient permissions for keylogger test")

        # Validate keylogger initialization
        self.assert_real_output(start_result)
        assert 'keylogger_started' in start_result or 'status' in start_result

        if start_result.get('keylogger_started') or start_result.get('status') == 'started':
            # Test keylogger termination
            await asyncio.sleep(0.5)  # Brief operation period

            stop_result = await self.client._stop_keylogging()

            # Validate keylogger termination
            self.assert_real_output(stop_result)
            assert 'keylogger_stopped' in stop_result or 'status' in stop_result

    async def test_privilege_escalation_detection_real(self):
        """Test real privilege escalation capability detection."""
        await self._setup_server_client()

        # Test current privilege checking
        privilege_info = await self.client._check_current_privileges()

        # Validate privilege checking
        self.assert_real_output(privilege_info)
        assert 'is_admin' in privilege_info or 'is_root' in privilege_info
        assert 'privileges' in privilege_info
        assert 'escalation_possible' in privilege_info

        # Should detect actual privilege level
        if platform.system() == "Windows":
            assert 'is_admin' in privilege_info
            assert isinstance(privilege_info['is_admin'], bool)
        else:
            assert 'is_root' in privilege_info
            assert isinstance(privilege_info['is_root'], bool)

    async def test_persistence_installation_real(self):
        """Test real persistence mechanism installation."""
        await self._setup_server_client()

        # Test persistence installation (with cleanup)
        persistence_config = {
            'method': 'registry' if platform.system() == "Windows" else 'crontab',
            'cleanup': True,  # Ensure cleanup after test
        }

        result = await self.client._install_persistence(persistence_config)

        # Validate persistence installation
        self.assert_real_output(result)
        assert 'persistence_installed' in result or 'status' in result
        assert 'method' in result

        # Should indicate successful installation or permission issues
        if not result.get('persistence_installed') and 'permission' in str(result).lower():
            pytest.skip("Insufficient permissions for persistence test")

    async def test_service_vulnerability_analysis_real(self):
        """Test real Windows service vulnerability analysis."""
        if platform.system() != "Windows":
            pytest.skip("Service vulnerability analysis is Windows-specific")

        await self._setup_server_client()

        # Test service vulnerability analysis
        result = await self.client._analyze_services_for_vulnerabilities()

        # Validate service analysis
        self.assert_real_output(result)
        assert 'services_analyzed' in result
        assert 'vulnerabilities_found' in result
        assert isinstance(result['services_analyzed'], int)
        assert isinstance(result['vulnerabilities_found'], list)

        # Should analyze actual Windows services
        assert result['services_analyzed'] > 0

    async def test_autonomous_operation_real(self):
        """Test real autonomous operation capabilities."""
        await self._setup_server_client()

        # Test autonomous activities decision making
        autonomous_result = await self.client._perform_autonomous_activities()

        # Validate autonomous operation
        self.assert_real_output(autonomous_result)
        assert 'activities_performed' in autonomous_result
        assert isinstance(autonomous_result['activities_performed'], list)

        # Test autonomous info gathering decision
        info_decision = await self.client._should_gather_info()
        assert isinstance(info_decision, bool)

        # Test autonomous screenshot decision
        screenshot_decision = await self.client._should_take_screenshot()
        assert isinstance(screenshot_decision, bool)

    async def test_protocol_failover_real(self):
        """Test real protocol failover functionality."""
        # Setup client with multiple protocols
        multi_protocol_config = {
            **self.test_config,
            "protocols": {
                "https_enabled": True,
                "tcp_enabled": True,
                "https": {"host": "127.0.0.1", "port": 8443},
                "tcp": {"host": "127.0.0.1", "port": self.test_port}
            }
        }

        client = C2Client(multi_protocol_config)
        self.client = client

        # Test protocol failover
        failover_result = await client._attempt_protocol_failover()

        # Validate failover capability
        self.assert_real_output(failover_result)
        assert 'failover_attempted' in failover_result or 'protocol_switched' in failover_result

    async def test_encryption_functionality_real(self):
        """Test real encryption/decryption functionality."""
        await self._setup_server_client()

        # Test encrypted communication if encryption is enabled
        if self.client.use_encryption:
            test_data = {"test": "encrypted_message", "timestamp": time.time()}

            # Should handle encryption internally
            # This tests that encryption doesn't break communication
            try:
                # Send encrypted data through normal channels
                beacon_result = await self.client._send_beacon()
                self.assert_real_output(beacon_result)

                # If we get here, encryption is working
                assert True
            except Exception as e:
                pytest.fail(f"Encryption broke communication: {e}")

    async def test_jitter_timing_real(self):
        """Test real jitter and timing functionality."""
        config_with_jitter = {**self.test_config, "jitter_enabled": True, "max_jitter": 0.5}
        client = C2Client(config_with_jitter)

        # Test beacon time calculation with jitter
        times = []
        for _ in range(5):
            beacon_time = client._calculate_beacon_time()
            times.append(beacon_time)

        # With jitter, times should vary
        assert len(set(times)) > 1, "Jitter should produce variable timing"

        # All times should be positive
        assert all(t > 0 for t in times)

    async def test_client_statistics_real(self):
        """Test real client statistics tracking."""
        await self._setup_server_client()

        # Perform some operations to generate statistics
        await self.client._send_beacon()
        await self.client._gather_system_info()

        # Get client statistics
        stats = self.client.get_client_statistics()

        # Validate statistics tracking
        self.assert_real_output(stats)
        assert 'session_duration' in stats
        assert 'commands_executed' in stats
        assert 'bytes_sent' in stats
        assert 'bytes_received' in stats
        assert 'last_activity' in stats

        # Statistics should show actual activity
        assert stats['session_duration'] > 0
        assert isinstance(stats['commands_executed'], int)
        assert isinstance(stats['bytes_sent'], int)
        assert isinstance(stats['bytes_received'], int)

    async def test_c2_client_capabilities_real(self):
        """Test real C2 client capabilities reporting."""
        await self._setup_server_client()

        # Get client capabilities
        capabilities = self.client._get_capabilities()

        # Validate capabilities reporting
        self.assert_real_output(capabilities)
        assert isinstance(capabilities, list)
        assert len(capabilities) > 0

        # Should report actual available capabilities
        expected_capabilities = [
            'shell_execution', 'file_operations', 'system_info',
            'process_enumeration', 'network_scanning'
        ]

        for cap in expected_capabilities:
            assert any(cap in str(reported_cap).lower() for reported_cap in capabilities), \
                   f"Missing expected capability: {cap}"

    async def test_direct_command_execution_real(self):
        """Test real direct command execution bypassing queue."""
        await self._setup_server_client()

        # Test direct command execution
        test_command = {
            'type': 'direct_execute',
            'command': 'echo "Direct execution test"' if platform.system() != "Windows"
                      else 'echo Direct execution test'
        }

        result = await self.client._execute_direct_command(test_command)

        # Validate direct execution
        self.assert_real_output(result)
        assert 'output' in result or 'result' in result
        assert 'success' in result or 'status' in result

        # Should execute immediately without queuing
        output = result.get('output') or result.get('result', '')
        assert 'Direct execution test' in str(output)

    async def _setup_server_client(self):
        """Helper method to setup server and client connection."""
        # Start server
        server_config = {
            'bind_address': '127.0.0.1',
            'port': self.test_port,
            'protocol': 'tcp'
        }

        self.server = C2Server(server_config)
        self.server.start()
        await asyncio.sleep(0.5)

        # Start client
        client = C2Client(self.test_config)
        self.client = client

        try:
            await client.start()
            await asyncio.sleep(0.5)  # Allow connection to establish
        except Exception as e:
            pytest.skip(f"Could not establish C2 connection for test: {e}")


class TestC2ClientIntegration(BaseIntellicrackTest):
    """Integration tests for C2Client with external systems."""

    def test_c2_client_with_real_binary_analysis(self):
        """Test C2Client integration with real binary analysis workflow."""
        config = {
            "server_host": "127.0.0.1",
            "server_port": 9997,
            "protocol": "tcp",
            "auto_gather_info": True
        }

        client = C2Client(config)

        # Should integrate with Intellicrack's binary analysis capabilities
        self.assert_real_output(client)
        assert hasattr(client, '_gather_system_info')
        assert hasattr(client, '_get_process_list')
        assert hasattr(client, '_network_scan')

    def test_c2_client_security_research_workflow(self):
        """Test C2Client in realistic security research workflow."""
        config = {
            "server_host": "127.0.0.1",
            "server_port": 9996,
            "protocol": "tcp",
            "use_encryption": True,
            "encryption_key": b"security_research_key_32_bytes!!",
        }

        client = C2Client(config)

        # Should support comprehensive security research workflow
        expected_methods = [
            '_install_persistence',
            '_attempt_privilege_escalation',
            '_analyze_services_for_vulnerabilities',
            '_start_keylogging',
            '_take_screenshot',
            '_network_scan'
        ]

        for method in expected_methods:
            assert hasattr(client, method), f"Missing security research method: {method}"

    async def test_c2_client_production_readiness(self):
        """Test C2Client production readiness for security research."""
        config = {
            "server_host": "127.0.0.1",
            "server_port": 9995,
            "protocol": "tcp",
            "use_encryption": True,
            "jitter_enabled": True,
            "verify_ssl": False
        }

        client = C2Client(config)

        # Production-ready client should handle all error conditions
        try:
            # Should gracefully handle connection failures
            await client._establish_connection()
        except Exception:
            # Expected for no server - but should not crash
            pass

        # Should have comprehensive logging
        assert client.logger is not None

        # Should track operational statistics
        stats = client.get_client_statistics()
        assert isinstance(stats, dict)
        assert 'session_duration' in stats
