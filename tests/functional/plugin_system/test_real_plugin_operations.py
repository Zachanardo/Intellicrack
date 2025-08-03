import pytest
import tempfile
import os
import json
import importlib.util
import time
from pathlib import Path

from intellicrack.plugins.plugin_system import PluginSystem
from intellicrack.tools.plugin_debugger import PluginDebugger
from intellicrack.tools.plugin_test_generator import PluginTestGenerator
from intellicrack.plugins.ghidra_scripts.user.AntiAnalysisDetector import AntiAnalysisDetector
from intellicrack.plugins.radare2_modules.radare2_keygen_assistant import Radare2KeygenAssistant
from intellicrack.plugins.radare2_modules.radare2_license_analyzer import Radare2LicenseAnalyzer
from intellicrack.core.app_context import AppContext


class TestRealPluginOperations:
    """Functional tests for REAL plugin system operations."""

    @pytest.fixture
    def test_plugin_code(self):
        """Create REAL plugin code for testing."""
        return '''
from intellicrack.plugins.base_plugin import BasePlugin

class TestAnalysisPlugin(BasePlugin):
    """Test plugin for binary analysis."""

    def __init__(self):
        super().__init__()
        self.name = "TestAnalysisPlugin"
        self.version = "1.0.0"
        self.description = "Plugin for testing binary analysis"
        self.author = "Test Author"
        self.capabilities = ["analysis", "reporting"]

    def initialize(self, context):
        """Initialize plugin with context."""
        self.context = context
        self.initialized = True
        return True

    def analyze_binary(self, binary_path):
        """Analyze binary file."""
        results = {
            "file_path": binary_path,
            "analysis_type": "test_analysis",
            "findings": []
        }

        # Simulate analysis
        if os.path.exists(binary_path):
            file_size = os.path.getsize(binary_path)
            results["findings"].append({
                "type": "file_info",
                "size": file_size,
                "readable": True
            })

            # Check for patterns
            with open(binary_path, 'rb') as f:
                header = f.read(4)
                if header == b'MZ\\x90\\x00':
                    results["findings"].append({
                        "type": "pe_file",
                        "confidence": 0.9
                    })
                elif header[:4] == b'\\x7fELF':
                    results["findings"].append({
                        "type": "elf_file",
                        "confidence": 0.9
                    })

        return results

    def generate_report(self, analysis_results):
        """Generate report from analysis."""
        report = {
            "plugin": self.name,
            "version": self.version,
            "timestamp": time.time(),
            "summary": f"Found {len(analysis_results.get('findings', []))} items"
        }
        return report

    def cleanup(self):
        """Cleanup plugin resources."""
        self.initialized = False
        return True
'''

    @pytest.fixture
    def test_ghidra_script(self):
        """Create REAL Ghidra script for testing."""
        return '''
# Ghidra Script - License Check Finder
# @category Analysis
# @toolbar_icon

from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import RefType

def find_license_checks():
    """Find potential license check functions."""
    license_functions = []
    function_manager = currentProgram.getFunctionManager()

    # Common license check patterns
    patterns = ["license", "check", "validate", "serial", "key", "activation"]

    for function in function_manager.getFunctions(True):
        name = function.getName().lower()
        for pattern in patterns:
            if pattern in name:
                license_functions.append({
                    "name": function.getName(),
                    "address": function.getEntryPoint().toString(),
                    "size": function.getBody().getNumAddresses()
                })
                break

    return license_functions

def analyze_strings():
    """Analyze strings for license-related content."""
    license_strings = []
    listing = currentProgram.getListing()

    # Get all defined strings
    for data in listing.getDefinedData(True):
        if data.hasStringValue():
            value = data.getDefaultValueRepresentation()
            if any(keyword in value.lower() for keyword in ["license", "trial", "expire", "activate"]):
                license_strings.append({
                    "value": value,
                    "address": data.getAddress().toString()
                })

    return license_strings

# Main execution
print("Starting License Analysis...")
functions = find_license_checks()
strings = analyze_strings()

print(f"Found {len(functions)} potential license functions")
print(f"Found {len(strings)} license-related strings")

# Create bookmarks for findings
for func in functions:
    createBookmark(toAddr(func["address"]), "License", func["name"])

for string in strings:
    createBookmark(toAddr(string["address"]), "License String", string["value"])
'''

    @pytest.fixture
    def app_context(self):
        """Create REAL application context."""
        context = AppContext()
        context.initialize()
        return context

    @pytest.fixture
    def plugin_directory(self):
        """Create temporary plugin directory."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        # Cleanup
        import shutil
        try:
            shutil.rmtree(temp_dir)
        except:
            pass

    def test_real_plugin_loading_and_initialization(self, test_plugin_code, plugin_directory, app_context):
        """Test REAL plugin loading and initialization."""
        plugin_system = PluginSystem(app_context)

        # Write test plugin
        plugin_file = os.path.join(plugin_directory, 'test_analysis_plugin.py')
        with open(plugin_file, 'w') as f:
            f.write(test_plugin_code)

        # Add plugin directory
        added = plugin_system.add_plugin_directory(plugin_directory)
        assert added, "Must add plugin directory"

        # Discover plugins
        discovered = plugin_system.discover_plugins()
        assert discovered is not None, "Must discover plugins"
        assert len(discovered) > 0, "Must find at least one plugin"

        # Load plugin
        plugin_name = 'TestAnalysisPlugin'
        loaded = plugin_system.load_plugin(plugin_name)
        assert loaded, f"Must load plugin {plugin_name}"

        # Get plugin instance
        plugin = plugin_system.get_plugin(plugin_name)
        assert plugin is not None, "Must get plugin instance"
        assert plugin.name == plugin_name, "Plugin name must match"
        assert plugin.version == "1.0.0", "Plugin version must match"

        # Test plugin capabilities
        capabilities = plugin_system.get_plugin_capabilities(plugin_name)
        assert capabilities is not None, "Must return capabilities"
        assert 'analysis' in capabilities, "Must have analysis capability"
        assert 'reporting' in capabilities, "Must have reporting capability"

    def test_real_plugin_execution(self, test_plugin_code, plugin_directory, app_context):
        """Test REAL plugin execution functionality."""
        plugin_system = PluginSystem(app_context)

        # Setup plugin
        plugin_file = os.path.join(plugin_directory, 'test_plugin.py')
        with open(plugin_file, 'w') as f:
            f.write(test_plugin_code)

        plugin_system.add_plugin_directory(plugin_directory)
        plugin_system.discover_plugins()
        plugin_system.load_plugin('TestAnalysisPlugin')

        # Create test binary
        test_binary = os.path.join(plugin_directory, 'test.exe')
        with open(test_binary, 'wb') as f:
            # Write PE header
            f.write(b'MZ\x90\x00' + b'\x00' * 60)

        # Execute plugin method
        result = plugin_system.execute_plugin_method(
            'TestAnalysisPlugin',
            'analyze_binary',
            test_binary
        )

        assert result is not None, "Plugin execution must return result"
        assert 'findings' in result, "Result must contain findings"
        assert len(result['findings']) >= 2, "Must find file info and PE detection"

        # Verify findings
        findings_types = [f['type'] for f in result['findings']]
        assert 'file_info' in findings_types, "Must detect file info"
        assert 'pe_file' in findings_types, "Must detect PE file"

        # Test report generation
        report = plugin_system.execute_plugin_method(
            'TestAnalysisPlugin',
            'generate_report',
            result
        )

        assert report is not None, "Report generation must succeed"
        assert report['plugin'] == 'TestAnalysisPlugin', "Report must identify plugin"
        assert 'timestamp' in report, "Report must have timestamp"

    def test_real_plugin_debugging(self, test_plugin_code, plugin_directory, app_context):
        """Test REAL plugin debugging functionality."""
        debugger = PluginDebugger()

        # Write plugin with intentional issue
        buggy_plugin = test_plugin_code.replace(
            'file_size = os.path.getsize(binary_path)',
            'file_size = os.path.getsize(binary_path)\nraise ValueError("Test error")'
        )

        plugin_file = os.path.join(plugin_directory, 'buggy_plugin.py')
        with open(plugin_file, 'w') as f:
            f.write(buggy_plugin)

        # Debug plugin loading
        load_result = debugger.debug_plugin_load(plugin_file)
        assert load_result is not None, "Debug load must return result"
        assert 'loaded' in load_result, "Must indicate load status"
        assert 'module' in load_result or 'error' in load_result, "Must return module or error"

        if load_result['loaded']:
            # Test method debugging
            plugin_instance = load_result['module'].TestAnalysisPlugin()

            # Debug method execution
            debug_result = debugger.debug_method_execution(
                plugin_instance,
                'analyze_binary',
                os.path.join(plugin_directory, 'test.exe')
            )

            assert debug_result is not None, "Debug execution must return result"
            assert 'error' in debug_result, "Must catch the intentional error"
            assert 'traceback' in debug_result, "Must provide traceback"
            assert 'Test error' in str(debug_result['error']), "Must capture error message"

    def test_real_ghidra_script_operations(self, test_ghidra_script, plugin_directory, app_context):
        """Test REAL Ghidra script operations."""
        # Write Ghidra script
        script_file = os.path.join(plugin_directory, 'LicenseCheckFinder.py')
        with open(script_file, 'w') as f:
            f.write(test_ghidra_script)

        # Test script validation
        plugin_system = PluginSystem(app_context)

        validation = plugin_system.validate_ghidra_script(script_file)
        assert validation is not None, "Script validation must return result"
        assert validation.get('valid', False), "Script should be valid"
        assert 'category' in validation, "Should extract category"

        # Test script metadata extraction
        metadata = plugin_system.extract_ghidra_metadata(script_file)
        assert metadata is not None, "Must extract metadata"
        assert metadata.get('category') == 'Analysis', "Should extract category correctly"

        # Simulate script execution context
        ghidra_context = {
            'currentProgram': {
                'name': 'test.exe',
                'functions': [
                    {'name': 'check_license', 'address': '0x401000'},
                    {'name': 'validate_key', 'address': '0x401100'},
                    {'name': 'main', 'address': '0x401200'}
                ],
                'strings': [
                    {'value': 'Enter license key:', 'address': '0x402000'},
                    {'value': 'Trial expired!', 'address': '0x402020'}
                ]
            }
        }

        # Test pattern matching
        functions_found = []
        for func in ghidra_context['currentProgram']['functions']:
            if any(pattern in func['name'].lower() for pattern in ['license', 'check', 'validate']):
                functions_found.append(func)

        assert len(functions_found) >= 2, "Should find license-related functions"

    def test_real_radare2_plugin_operations(self, app_context):
        """Test REAL radare2 plugin operations."""
        # Test Keygen Assistant
        keygen_assistant = Radare2KeygenAssistant()

        # Analyze algorithm pattern
        algorithm_code = """
        mov eax, [ebp+8]      ; input
        xor eax, 0xDEADBEEF   ; XOR with constant
        rol eax, 5            ; rotate left
        add eax, 0x1337       ; add constant
        """

        pattern_analysis = keygen_assistant.analyze_algorithm_pattern(algorithm_code)
        assert pattern_analysis is not None, "Must analyze algorithm pattern"
        assert 'operations' in pattern_analysis, "Must identify operations"
        assert 'constants' in pattern_analysis, "Must extract constants"

        operations = pattern_analysis['operations']
        assert 'xor' in operations, "Must identify XOR operation"
        assert 'rotate' in operations, "Must identify rotation"
        assert 'add' in operations, "Must identify addition"

        # Generate keygen template
        keygen_template = keygen_assistant.generate_keygen_template(pattern_analysis)
        assert keygen_template is not None, "Must generate keygen template"
        assert 'algorithm' in keygen_template, "Template must contain algorithm"
        assert 'implementation' in keygen_template, "Template must contain implementation"

        # Test License Analyzer
        license_analyzer = Radare2LicenseAnalyzer()

        # Analyze license check
        license_check_asm = """
        push ebp
        mov ebp, esp
        mov eax, [ebp+8]      ; license key
        call validate_checksum
        test eax, eax
        jz invalid_license
        mov eax, 1            ; valid
        jmp done
        invalid_license:
        xor eax, eax          ; invalid
        done:
        pop ebp
        ret
        """

        check_analysis = license_analyzer.analyze_license_check(license_check_asm)
        assert check_analysis is not None, "Must analyze license check"
        assert 'check_type' in check_analysis, "Must identify check type"
        assert 'validation_method' in check_analysis, "Must identify validation method"
        assert 'return_values' in check_analysis, "Must identify return values"

    def test_real_plugin_test_generation(self, test_plugin_code, plugin_directory, app_context):
        """Test REAL plugin test generation."""
        test_generator = PluginTestGenerator()

        # Write plugin
        plugin_file = os.path.join(plugin_directory, 'plugin_to_test.py')
        with open(plugin_file, 'w') as f:
            f.write(test_plugin_code)

        # Generate tests
        generated_tests = test_generator.generate_plugin_tests(plugin_file)
        assert generated_tests is not None, "Must generate tests"
        assert 'test_code' in generated_tests, "Must contain test code"
        assert 'test_cases' in generated_tests, "Must contain test cases"

        test_code = generated_tests['test_code']
        assert 'import pytest' in test_code, "Tests must use pytest"
        assert 'TestAnalysisPlugin' in test_code, "Tests must reference plugin"
        assert 'def test_' in test_code, "Must contain test functions"

        # Verify test cases
        test_cases = generated_tests['test_cases']
        assert len(test_cases) > 0, "Must generate test cases"

        for test_case in test_cases:
            assert 'name' in test_case, "Test case must have name"
            assert 'method' in test_case, "Test case must target method"
            assert 'assertions' in test_case, "Test case must have assertions"

    def test_real_plugin_dependency_management(self, plugin_directory, app_context):
        """Test REAL plugin dependency management."""
        plugin_system = PluginSystem(app_context)

        # Create plugins with dependencies
        plugin1_code = '''
from intellicrack.plugins.base_plugin import BasePlugin

class Plugin1(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "Plugin1"
        self.version = "1.0.0"
        self.dependencies = []

    def provide_service(self):
        return {"service": "data_analysis", "version": "1.0"}
'''

        plugin2_code = '''
from intellicrack.plugins.base_plugin import BasePlugin

class Plugin2(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "Plugin2"
        self.version = "1.0.0"
        self.dependencies = ["Plugin1"]

    def use_dependency(self, plugin1_instance):
        service = plugin1_instance.provide_service()
        return {"using": service, "enhanced": True}
'''

        # Write plugins
        with open(os.path.join(plugin_directory, 'plugin1.py'), 'w') as f:
            f.write(plugin1_code)
        with open(os.path.join(plugin_directory, 'plugin2.py'), 'w') as f:
            f.write(plugin2_code)

        # Test dependency resolution
        plugin_system.add_plugin_directory(plugin_directory)
        plugin_system.discover_plugins()

        # Load with dependencies
        load_order = plugin_system.resolve_dependencies(['Plugin2'])
        assert load_order is not None, "Must resolve dependencies"
        assert len(load_order) == 2, "Must include dependency"
        assert load_order[0] == 'Plugin1', "Dependency must load first"
        assert load_order[1] == 'Plugin2', "Dependent must load second"

        # Load plugins in order
        for plugin_name in load_order:
            loaded = plugin_system.load_plugin(plugin_name)
            assert loaded, f"Must load {plugin_name}"

    def test_real_plugin_hot_reload(self, test_plugin_code, plugin_directory, app_context):
        """Test REAL plugin hot reload functionality."""
        plugin_system = PluginSystem(app_context)

        # Initial plugin
        plugin_file = os.path.join(plugin_directory, 'hot_reload_plugin.py')
        with open(plugin_file, 'w') as f:
            f.write(test_plugin_code)

        # Load plugin
        plugin_system.add_plugin_directory(plugin_directory)
        plugin_system.discover_plugins()
        plugin_system.load_plugin('TestAnalysisPlugin')

        # Get initial version
        plugin_v1 = plugin_system.get_plugin('TestAnalysisPlugin')
        assert plugin_v1.version == "1.0.0", "Initial version must be 1.0.0"

        # Modify plugin
        updated_code = test_plugin_code.replace('version = "1.0.0"', 'version = "2.0.0"')
        updated_code = updated_code.replace(
            'return True',
            'self.hot_reloaded = True\n        return True'
        )

        # Wait a moment to ensure file modification time changes
        time.sleep(0.1)

        with open(plugin_file, 'w') as f:
            f.write(updated_code)

        # Hot reload
        reloaded = plugin_system.reload_plugin('TestAnalysisPlugin')
        assert reloaded, "Hot reload must succeed"

        # Verify new version
        plugin_v2 = plugin_system.get_plugin('TestAnalysisPlugin')
        assert plugin_v2.version == "2.0.0", "Version must be updated"
        assert hasattr(plugin_v2, 'hot_reloaded'), "Must have new attribute"

    def test_real_plugin_sandboxing(self, plugin_directory, app_context):
        """Test REAL plugin sandboxing and security."""
        plugin_system = PluginSystem(app_context)

        # Create potentially dangerous plugin
        dangerous_plugin = '''
from intellicrack.plugins.base_plugin import BasePlugin
import os
import subprocess

class DangerousPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "DangerousPlugin"
        self.version = "1.0.0"

    def try_file_access(self):
        """Try to access restricted files."""
        try:
            with open('/etc/passwd', 'r') as f:
                return f.read()
        except:
            return "Access denied"

    def try_subprocess(self):
        """Try to execute system command."""
        try:
            result = subprocess.run(['whoami'], capture_output=True)
            return result.stdout.decode()
        except:
            return "Execution denied"

    def try_network(self):
        """Try network access."""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('google.com', 80))
            s.close()
            return "Network allowed"
        except:
            return "Network denied"
'''

        plugin_file = os.path.join(plugin_directory, 'dangerous_plugin.py')
        with open(plugin_file, 'w') as f:
            f.write(dangerous_plugin)

        # Enable sandboxing
        sandbox_config = {
            'restrict_file_access': True,
            'restrict_network': True,
            'restrict_subprocess': True,
            'allowed_paths': [plugin_directory],
            'max_memory': 100 * 1024 * 1024,  # 100MB
            'max_execution_time': 5.0  # 5 seconds
        }

        plugin_system.enable_sandboxing(sandbox_config)

        # Load and test plugin
        plugin_system.add_plugin_directory(plugin_directory)
        plugin_system.discover_plugins()

        # Test loading with sandbox
        loaded = plugin_system.load_plugin('DangerousPlugin', sandboxed=True)
        if loaded:
            # Test restricted operations
            file_result = plugin_system.execute_plugin_method(
                'DangerousPlugin',
                'try_file_access'
            )
            assert file_result == "Access denied", "File access should be denied"

            subprocess_result = plugin_system.execute_plugin_method(
                'DangerousPlugin',
                'try_subprocess'
            )
            assert subprocess_result == "Execution denied", "Subprocess should be denied"

    def test_real_plugin_performance_monitoring(self, test_plugin_code, plugin_directory, app_context):
        """Test REAL plugin performance monitoring."""
        plugin_system = PluginSystem(app_context)

        # Add performance tracking
        performance_plugin = test_plugin_code.replace(
            'def analyze_binary(self, binary_path):',
            '''def analyze_binary(self, binary_path):
        import time
        start_time = time.time()

        # Simulate some work
        total = 0
        for i in range(100000):
            total += i'''
        ).replace(
            'return results',
            '''
        end_time = time.time()
        results["execution_time"] = end_time - start_time
        results["operations_count"] = 100000
        return results'''
        )

        plugin_file = os.path.join(plugin_directory, 'perf_plugin.py')
        with open(plugin_file, 'w') as f:
            f.write(performance_plugin)

        # Enable performance monitoring
        plugin_system.enable_performance_monitoring()

        # Load and execute
        plugin_system.add_plugin_directory(plugin_directory)
        plugin_system.discover_plugins()
        plugin_system.load_plugin('TestAnalysisPlugin')

        # Execute with monitoring
        test_file = os.path.join(plugin_directory, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'TEST' * 100)

        result = plugin_system.execute_plugin_method(
            'TestAnalysisPlugin',
            'analyze_binary',
            test_file
        )

        # Get performance metrics
        metrics = plugin_system.get_plugin_metrics('TestAnalysisPlugin')
        assert metrics is not None, "Must return metrics"
        assert 'execution_count' in metrics, "Must track execution count"
        assert 'total_time' in metrics, "Must track total time"
        assert 'average_time' in metrics, "Must calculate average time"

        # Verify execution was tracked
        assert metrics['execution_count'] >= 1, "Must track at least one execution"
        assert metrics['total_time'] > 0, "Must record execution time"
