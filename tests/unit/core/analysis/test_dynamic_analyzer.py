"""
Unit tests for DynamicAnalyzer with REAL runtime analysis.
Tests REAL process monitoring and behavior analysis.
NO MOCKS - ALL TESTS USE REAL PROCESSES AND PRODUCE REAL RESULTS.
"""

import pytest
import subprocess
import time
import psutil
from pathlib import Path

from intellicrack.core.analysis.dynamic_analyzer import DynamicAnalyzer
from tests.base_test import BaseIntellicrackTest


class TestDynamicAnalyzer(BaseIntellicrackTest):
    """Test dynamic analyzer with REAL process monitoring."""
    
    @pytest.fixture(autouse=True)
    def setup(self, real_pe_binary):
        """Set up test with real binaries."""
        self.analyzer = DynamicAnalyzer()
        self.test_binary = real_pe_binary
        
    def test_process_monitoring_real(self):
        """Test REAL process monitoring and behavior capture."""
        # Start monitoring before launching process
        self.analyzer.start_monitoring()
        
        # Launch a real process (notepad as safe example)
        process = subprocess.Popen(['notepad.exe'])
        time.sleep(2)  # Let it initialize
        
        # Capture real behavior
        behavior = self.analyzer.capture_behavior(process.pid)
        
        # Validate real monitoring data
        self.assert_real_output(behavior)
        assert 'process_info' in behavior
        assert 'api_calls' in behavior
        assert 'file_operations' in behavior
        assert 'registry_operations' in behavior
        assert 'network_activity' in behavior
        
        # Check process info is real
        proc_info = behavior['process_info']
        assert proc_info['pid'] == process.pid
        assert proc_info['name'] == 'notepad.exe'
        assert proc_info['start_time'] > 0
        assert 'command_line' in proc_info
        
        # Cleanup
        process.terminate()
        self.analyzer.stop_monitoring()
        
    def test_api_call_tracing_real(self):
        """Test REAL Windows API call tracing."""
        # Monitor API calls for a real process
        api_trace = self.analyzer.trace_api_calls(self.test_binary, duration=5)
        
        # Validate real API traces
        self.assert_real_output(api_trace)
        assert isinstance(api_trace, list)
        
        # Check API call structure
        for api_call in api_trace:
            assert 'timestamp' in api_call
            assert 'module' in api_call
            assert 'function' in api_call
            assert 'parameters' in api_call
            assert 'return_value' in api_call
            
            # Real API calls have real module names
            assert api_call['module'].endswith('.dll')
            # Real functions don't have mock prefixes
            assert not api_call['function'].startswith('mock_')
            
    def test_memory_snapshot_real(self):
        """Test REAL memory snapshot analysis."""
        # Take memory snapshot of current process (safe)
        import os
        current_pid = os.getpid()
        
        snapshot = self.analyzer.take_memory_snapshot(current_pid)
        
        # Validate real memory data
        self.assert_real_output(snapshot)
        assert 'modules' in snapshot
        assert 'heap_info' in snapshot
        assert 'threads' in snapshot
        assert 'handles' in snapshot
        
        # Check modules are real
        assert len(snapshot['modules']) > 0
        for module in snapshot['modules']:
            assert 'name' in module
            assert 'base_address' in module
            assert 'size' in module
            assert module['size'] > 0
            # Real modules have real paths
            assert not module['name'].startswith('fake_')
            
    def test_network_monitoring_real(self):
        """Test REAL network activity monitoring."""
        # Monitor network for a short duration
        self.analyzer.start_network_monitoring()
        time.sleep(3)  # Capture some traffic
        network_data = self.analyzer.get_network_activity()
        self.analyzer.stop_network_monitoring()
        
        # Validate real network data
        self.assert_real_output(network_data)
        assert 'connections' in network_data
        assert 'dns_queries' in network_data
        assert 'packets_captured' in network_data
        
        # If connections exist, validate they're real
        if network_data['connections']:
            for conn in network_data['connections']:
                assert 'src_ip' in conn
                assert 'dst_ip' in conn
                assert 'src_port' in conn
                assert 'dst_port' in conn
                assert 'protocol' in conn
                # Real ports are in valid range
                assert 0 < conn['src_port'] <= 65535
                assert 0 < conn['dst_port'] <= 65535
                
    def test_file_operation_monitoring_real(self):
        """Test REAL file system operation monitoring."""
        # Monitor file operations
        self.analyzer.start_file_monitoring()
        
        # Perform real file operations
        test_file = Path('test_file_ops.tmp')
        test_file.write_text('test data')
        test_file.read_text()
        test_file.unlink()
        
        # Get captured operations
        file_ops = self.analyzer.get_file_operations()
        self.analyzer.stop_file_monitoring()
        
        # Validate real file operations
        self.assert_real_output(file_ops)
        assert isinstance(file_ops, list)
        
        # Should have captured our operations
        assert len(file_ops) > 0
        for op in file_ops:
            assert 'type' in op  # create, read, write, delete
            assert 'path' in op
            assert 'timestamp' in op
            assert 'process_id' in op
            
    def test_registry_monitoring_real(self):
        """Test REAL registry operation monitoring (Windows)."""
        import platform
        if platform.system() != 'Windows':
            pytest.skip("Registry monitoring is Windows-only")
            
        # Monitor registry operations
        self.analyzer.start_registry_monitoring()
        time.sleep(2)  # Capture some activity
        
        reg_ops = self.analyzer.get_registry_operations()
        self.analyzer.stop_registry_monitoring()
        
        # Validate real registry data
        self.assert_real_output(reg_ops)
        assert isinstance(reg_ops, list)
        
        # Check operation structure
        for op in reg_ops:
            assert 'type' in op  # create, read, write, delete
            assert 'key' in op
            assert 'value' in op
            assert 'timestamp' in op
            # Real registry keys have proper format
            assert op['key'].startswith('HKEY_') or '\\' in op['key']
            
    def test_behavior_scoring_real(self):
        """Test REAL behavior analysis and scoring."""
        # Analyze a real binary's behavior
        behavior_score = self.analyzer.analyze_behavior(self.test_binary)
        
        # Validate real scoring
        self.assert_real_output(behavior_score)
        assert 'risk_score' in behavior_score
        assert 'suspicious_behaviors' in behavior_score
        assert 'behavior_categories' in behavior_score
        
        # Check score is realistic
        assert 0 <= behavior_score['risk_score'] <= 100
        assert isinstance(behavior_score['suspicious_behaviors'], list)
        
        # Check behavior categories
        categories = behavior_score['behavior_categories']
        possible_categories = ['file_system', 'registry', 'network', 'process', 'cryptography']
        for cat in categories:
            assert cat in possible_categories
            
    def test_injection_detection_real(self):
        """Test REAL process injection detection."""
        # Monitor for injection attempts
        injections = self.analyzer.detect_injections(duration=5)
        
        # Validate output format
        assert isinstance(injections, list)
        
        # If injections detected, validate they're real
        for injection in injections:
            assert 'source_pid' in injection
            assert 'target_pid' in injection
            assert 'technique' in injection
            assert 'timestamp' in injection
            # Real PIDs are positive
            assert injection['source_pid'] > 0
            assert injection['target_pid'] > 0
            
    def test_sandbox_detection_real(self):
        """Test REAL sandbox/VM detection capabilities."""
        # Check if running in sandbox/VM
        sandbox_indicators = self.analyzer.detect_sandbox_environment()
        
        # Validate real detection results
        self.assert_real_output(sandbox_indicators)
        assert 'is_sandbox' in sandbox_indicators
        assert 'indicators' in sandbox_indicators
        assert 'confidence' in sandbox_indicators
        
        # Check indicator types
        assert isinstance(sandbox_indicators['indicators'], list)
        for indicator in sandbox_indicators['indicators']:
            assert 'type' in indicator
            assert 'description' in indicator
            assert 'severity' in indicator
            
    def test_persistence_mechanism_detection_real(self):
        """Test REAL persistence mechanism detection."""
        # Scan for persistence mechanisms
        persistence = self.analyzer.detect_persistence_mechanisms()
        
        # Validate real persistence data
        self.assert_real_output(persistence)
        assert isinstance(persistence, list)
        
        # Check persistence entries
        for entry in persistence:
            assert 'type' in entry
            assert 'location' in entry
            assert 'value' in entry
            assert 'risk_level' in entry
            
            # Real persistence types
            valid_types = ['registry_run', 'startup_folder', 'scheduled_task', 
                          'service', 'wmi', 'dll_hijack']
            assert entry['type'] in valid_types
            
    def test_cpu_usage_monitoring_real(self):
        """Test REAL CPU usage monitoring."""
        # Monitor CPU usage of current process
        import os
        current_pid = os.getpid()
        
        cpu_data = self.analyzer.monitor_cpu_usage(current_pid, duration=3)
        
        # Validate real CPU data
        self.assert_real_output(cpu_data)
        assert 'average_usage' in cpu_data
        assert 'peak_usage' in cpu_data
        assert 'samples' in cpu_data
        
        # Check realistic values
        assert 0 <= cpu_data['average_usage'] <= 100
        assert 0 <= cpu_data['peak_usage'] <= 100
        assert len(cpu_data['samples']) > 0
        
    def test_handle_enumeration_real(self):
        """Test REAL handle enumeration."""
        # Enumerate handles for current process
        import os
        current_pid = os.getpid()
        
        handles = self.analyzer.enumerate_handles(current_pid)
        
        # Validate real handle data
        self.assert_real_output(handles)
        assert isinstance(handles, list)
        assert len(handles) > 0  # Process always has handles
        
        # Check handle structure
        for handle in handles:
            assert 'type' in handle
            assert 'name' in handle
            assert 'access' in handle
            # Real handle types
            valid_types = ['File', 'Process', 'Thread', 'Key', 'Event', 'Mutex']
            assert any(t in handle['type'] for t in valid_types)