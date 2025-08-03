"""
Unit tests for System Utils with REAL system operations.
Tests REAL system information, process management, and platform detection.
NO MOCKS - ALL TESTS USE REAL SYSTEM CALLS AND PRODUCE REAL RESULTS.
"""

import pytest
import platform
import os
import sys
import time
import subprocess

from intellicrack.utils.system_utils import SystemUtils
from tests.base_test import IntellicrackTestBase


class TestSystemUtils(IntellicrackTestBase):
    """Test system utilities with REAL system operations."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with real system utils."""
        self.utils = SystemUtils()
        
    def test_system_info_collection(self):
        """Test system information collection."""
        info = self.utils.get_system_info()
        
        self.assert_real_output(info)
        
        # Validate required fields
        assert 'platform' in info
        assert 'architecture' in info
        assert 'processor' in info
        assert 'memory' in info
        assert 'python_version' in info
        
        # Validate values
        assert info['platform'] in ['Windows', 'Linux', 'Darwin']
        assert info['architecture'][0] in ['32bit', '64bit']
        assert info['memory']['total'] > 0
        assert info['memory']['available'] > 0
        
    def test_process_enumeration(self):
        """Test process enumeration."""
        processes = self.utils.list_processes()
        
        self.assert_real_output(processes)
        assert len(processes) > 10  # Should have many processes
        
        # Check process structure
        for proc in processes[:10]:  # Check first 10
            assert 'pid' in proc
            assert 'name' in proc
            assert 'memory' in proc
            assert proc['pid'] > 0
            assert proc['name'] != ''
            
        # Current process should be in list
        current_pid = os.getpid()
        pids = [p['pid'] for p in processes]
        assert current_pid in pids
        
    def test_cpu_information(self):
        """Test CPU information retrieval."""
        cpu_info = self.utils.get_cpu_info()
        
        self.assert_real_output(cpu_info)
        
        assert 'count' in cpu_info
        assert 'brand' in cpu_info
        assert 'frequency' in cpu_info
        assert 'usage' in cpu_info
        
        assert cpu_info['count'] > 0
        assert 0.0 <= cpu_info['usage'] <= 100.0
        
    def test_memory_information(self):
        """Test memory information retrieval."""
        mem_info = self.utils.get_memory_info()
        
        self.assert_real_output(mem_info)
        
        assert 'total' in mem_info
        assert 'available' in mem_info
        assert 'used' in mem_info
        assert 'percent' in mem_info
        
        assert mem_info['total'] > 0
        assert mem_info['used'] > 0
        assert 0.0 <= mem_info['percent'] <= 100.0
        
    def test_disk_information(self):
        """Test disk information retrieval."""
        disk_info = self.utils.get_disk_info()
        
        self.assert_real_output(disk_info)
        assert len(disk_info) > 0
        
        for disk in disk_info:
            assert 'device' in disk
            assert 'mountpoint' in disk
            assert 'total' in disk
            assert 'used' in disk
            assert 'free' in disk
            assert 'percent' in disk
            
            assert disk['total'] > 0
            assert 0.0 <= disk['percent'] <= 100.0
            
    def test_network_interfaces(self):
        """Test network interface enumeration."""
        interfaces = self.utils.get_network_interfaces()
        
        self.assert_real_output(interfaces)
        assert len(interfaces) > 0
        
        # Should have at least loopback
        interface_names = [iface['name'] for iface in interfaces]
        assert any('lo' in name or 'Loopback' in name for name in interface_names)
        
        for iface in interfaces:
            assert 'name' in iface
            assert 'addresses' in iface
            assert 'status' in iface
            
    def test_environment_variables(self):
        """Test environment variable operations."""
        # Get existing variable
        path_var = self.utils.get_env_variable('PATH')
        
        self.assert_real_output(path_var)
        assert path_var is not None
        assert len(path_var) > 0
        
        # Set new variable
        test_var = 'INTELLICRACK_TEST_VAR'
        test_value = 'test_value_123'
        
        self.utils.set_env_variable(test_var, test_value)
        retrieved = self.utils.get_env_variable(test_var)
        assert retrieved == test_value
        
        # Delete variable
        self.utils.delete_env_variable(test_var)
        assert self.utils.get_env_variable(test_var) is None
        
    def test_process_creation(self):
        """Test process creation and management."""
        # Create a simple process
        if platform.system() == 'Windows':
            cmd = ['cmd', '/c', 'echo', 'test']
        else:
            cmd = ['echo', 'test']
            
        proc = self.utils.create_process(cmd)
        
        self.assert_real_output(proc)
        assert proc is not None
        assert proc.pid > 0
        
        # Wait for completion
        result = self.utils.wait_for_process(proc, timeout=5)
        assert result['completed'] == True
        assert result['return_code'] == 0
        
    def test_process_termination(self):
        """Test process termination."""
        # Create a long-running process
        if platform.system() == 'Windows':
            cmd = ['cmd', '/c', 'timeout', '/t', '10']
        else:
            cmd = ['sleep', '10']
            
        proc = self.utils.create_process(cmd)
        time.sleep(0.5)  # Let it start
        
        # Terminate process
        result = self.utils.terminate_process(proc.pid)
        
        self.assert_real_output(result)
        assert result == True
        
        # Process should be terminated
        time.sleep(0.5)
        is_running = self.utils.is_process_running(proc.pid)
        assert is_running == False
        
    def test_registry_operations_windows(self):
        """Test Windows registry operations."""
        if platform.system() != 'Windows':
            pytest.skip("Windows only test")
            
        # Read registry value
        value = self.utils.read_registry(
            'HKEY_LOCAL_MACHINE',
            'SOFTWARE\\Microsoft\\Windows\\CurrentVersion',
            'ProgramFilesDir'
        )
        
        self.assert_real_output(value)
        assert value is not None
        assert 'Program Files' in value
        
    def test_service_enumeration(self):
        """Test service enumeration."""
        services = self.utils.list_services()
        
        self.assert_real_output(services)
        
        if platform.system() == 'Windows':
            # Should have many Windows services
            assert len(services) > 50
            
            # Check for common services
            service_names = [s['name'] for s in services]
            assert any('Windows' in name for name in service_names)
        else:
            # Unix services/daemons
            assert len(services) > 0
            
    def test_user_information(self):
        """Test user information retrieval."""
        user_info = self.utils.get_current_user()
        
        self.assert_real_output(user_info)
        assert 'username' in user_info
        assert 'uid' in user_info
        assert 'groups' in user_info
        assert 'home' in user_info
        
        assert user_info['username'] != ''
        assert user_info['home'] != ''
        
    def test_system_uptime(self):
        """Test system uptime calculation."""
        uptime = self.utils.get_system_uptime()
        
        self.assert_real_output(uptime)
        assert uptime > 0  # System has been up
        
        # Convert to human readable
        uptime_str = self.utils.format_uptime(uptime)
        assert 'day' in uptime_str or 'hour' in uptime_str or 'minute' in uptime_str
        
    def test_installed_software(self):
        """Test installed software enumeration."""
        software = self.utils.list_installed_software()
        
        self.assert_real_output(software)
        assert isinstance(software, list)
        
        # Should find Python at least
        software_names = [s.get('name', '').lower() for s in software]
        assert any('python' in name for name in software_names)
        
    def test_system_resources_monitoring(self):
        """Test system resource monitoring."""
        # Start monitoring
        self.utils.start_resource_monitoring()
        
        # Do some work
        data = [i ** 2 for i in range(1000000)]
        time.sleep(1)
        
        # Get resource usage
        usage = self.utils.get_resource_usage()
        
        self.assert_real_output(usage)
        assert 'cpu_percent' in usage
        assert 'memory_mb' in usage
        assert 'duration' in usage
        
        assert usage['cpu_percent'] >= 0.0
        assert usage['memory_mb'] > 0
        assert usage['duration'] > 0
        
    def test_firewall_status(self):
        """Test firewall status check."""
        status = self.utils.get_firewall_status()
        
        self.assert_real_output(status)
        assert 'enabled' in status
        assert isinstance(status['enabled'], bool)
        
        if platform.system() == 'Windows':
            assert 'profiles' in status
            
    def test_antivirus_detection(self):
        """Test antivirus software detection."""
        av_list = self.utils.detect_antivirus()
        
        self.assert_real_output(av_list)
        assert isinstance(av_list, list)
        
        # May or may not have AV installed
        if av_list:
            for av in av_list:
                assert 'name' in av
                assert 'active' in av
                
    def test_hardware_info(self):
        """Test hardware information collection."""
        hw_info = self.utils.get_hardware_info()
        
        self.assert_real_output(hw_info)
        
        assert 'motherboard' in hw_info
        assert 'bios' in hw_info
        assert 'cpu' in hw_info
        assert 'gpu' in hw_info
        
        # CPU info should be populated
        assert hw_info['cpu']['name'] != ''
        assert hw_info['cpu']['cores'] > 0
        
    def test_temperature_sensors(self):
        """Test temperature sensor reading."""
        temps = self.utils.get_temperatures()
        
        self.assert_real_output(temps)
        
        # May not have sensor access
        if temps:
            for sensor, temp in temps.items():
                assert isinstance(temp, (int, float))
                assert -50 < temp < 150  # Reasonable temperature range
                
    def test_system_events(self):
        """Test system event log reading."""
        if platform.system() == 'Windows':
            events = self.utils.get_system_events(
                log_name='System',
                max_events=10
            )
            
            self.assert_real_output(events)
            assert isinstance(events, list)
            
            if events:
                for event in events:
                    assert 'time' in event
                    assert 'source' in event
                    assert 'message' in event
                    
    def test_driver_enumeration(self):
        """Test driver enumeration."""
        drivers = self.utils.list_drivers()
        
        self.assert_real_output(drivers)
        assert isinstance(drivers, list)
        
        if platform.system() == 'Windows' and drivers:
            # Should have many drivers on Windows
            assert len(drivers) > 10
            
            for driver in drivers[:5]:
                assert 'name' in driver
                assert 'path' in driver
                assert 'status' in driver