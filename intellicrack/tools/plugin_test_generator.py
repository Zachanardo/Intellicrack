"""
Plugin Unit Test Generator for Intellicrack.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import ast
import os
import sys
import re
import textwrap
from typing import List, Dict, Tuple, Any
from datetime import datetime


class PluginTestGenerator:
    """Generates unit tests for Intellicrack plugins"""
    
    def __init__(self):
        self.test_template = """\"\"\"
Unit tests for {plugin_name}.
Generated by Intellicrack Test Generator on {date}.
\"\"\"

import unittest
import os
import sys
import tempfile
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

{imports}

class Test{class_name}(unittest.TestCase):
    \"\"\"Test cases for {class_name}\"\"\"
    
    def setUp(self):
        \"\"\"Set up test fixtures\"\"\"
        self.plugin = {class_name}()
        self.test_binary = self._create_test_binary()
        self.test_options = {{
            'verbose': True,
            'timeout': 30
        }}
    
    def tearDown(self):
        \"\"\"Clean up after tests\"\"\"
        if hasattr(self, 'test_binary') and os.path.exists(self.test_binary):
            os.remove(self.test_binary)
    
    def _create_test_binary(self):
        \"\"\"Create a test binary file\"\"\"
        # Create a minimal PE file for testing
        pe_header = b'MZ' + b'\\x00' * 58 + b'\\x00\\x00\\x00\\x00'  # DOS header
        pe_data = pe_header + b'PE\\x00\\x00' + b'\\x00' * 1000  # Minimal PE
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as f:
            f.write(pe_data)
            return f.name
    
{test_methods}
    
    # Helper assertion methods
    def assertPluginResult(self, result):
        \"\"\"Assert that plugin result has expected structure\"\"\"
        self.assertIsInstance(result, dict)
        self.assertIn('status', result)
        self.assertIn(result['status'], ['success', 'error', 'warning'])
    
    def assertNoErrors(self, result):
        \"\"\"Assert that plugin executed without errors\"\"\"
        self.assertEqual(result.get('status'), 'success')
        self.assertNotIn('error', result)


if __name__ == '__main__':
    unittest.main()
"""
        
        self.method_test_template = """
    def test_{method_name}_basic(self):
        \"\"\"Test {method_name} with basic input\"\"\"
        {test_body}
    
    def test_{method_name}_invalid_input(self):
        \"\"\"Test {method_name} with invalid input\"\"\"
        {invalid_test_body}
    
    def test_{method_name}_edge_cases(self):
        \"\"\"Test {method_name} edge cases\"\"\"
        {edge_test_body}"""
    
    def generate_tests_for_file(self, plugin_path: str) -> str:
        """Generate unit tests for a plugin file"""
        with open(plugin_path, 'r') as f:
            code = f.read()
        
        # Parse the plugin code
        tree = ast.parse(code)
        
        # Extract plugin information
        plugin_info = self._analyze_plugin(tree)
        
        # Generate test code
        test_code = self._generate_test_code(plugin_info, os.path.basename(plugin_path))
        
        return test_code
    
    def _analyze_plugin(self, tree: ast.AST) -> Dict[str, Any]:
        """Analyze plugin AST to extract structure"""
        info = {
            'imports': [],
            'classes': [],
            'functions': [],
            'has_run_method': False,
            'has_metadata': False
        }
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    info['imports'].append(alias.name)
                    
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    info['imports'].append(f"{node.module}")
                    
            elif isinstance(node, ast.ClassDef):
                class_info = {
                    'name': node.name,
                    'methods': [],
                    'init_params': []
                }
                
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        method_info = {
                            'name': item.name,
                            'params': [arg.arg for arg in item.args.args if arg.arg != 'self'],
                            'has_return': self._has_return(item),
                            'docstring': ast.get_docstring(item)
                        }
                        class_info['methods'].append(method_info)
                        
                        if item.name == 'run':
                            info['has_run_method'] = True
                        elif item.name == 'get_metadata':
                            info['has_metadata'] = True
                        elif item.name == '__init__':
                            class_info['init_params'] = method_info['params']
                
                info['classes'].append(class_info)
                
            elif isinstance(node, ast.FunctionDef) and node.col_offset == 0:
                func_info = {
                    'name': node.name,
                    'params': [arg.arg for arg in node.args.args],
                    'has_return': self._has_return(node),
                    'docstring': ast.get_docstring(node)
                }
                info['functions'].append(func_info)
                
                if node.name == 'run':
                    info['has_run_method'] = True
        
        return info
    
    def _has_return(self, func_node: ast.FunctionDef) -> bool:
        """Check if function has return statement"""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Return) and node.value is not None:
                return True
        return False
    
    def _generate_test_code(self, plugin_info: Dict[str, Any], filename: str) -> str:
        """Generate test code based on plugin analysis"""
        plugin_name = filename.replace('.py', '').replace('.js', '')
        
        # Generate imports
        imports = self._generate_imports(plugin_info, plugin_name)
        
        # Generate test methods
        test_methods = []
        
        # If there's a main class, test it
        if plugin_info['classes']:
            for class_info in plugin_info['classes']:
                test_methods.extend(self._generate_class_tests(class_info))
        
        # Test standalone functions
        for func_info in plugin_info['functions']:
            test_methods.append(self._generate_function_test(func_info, plugin_name))
        
        # Add standard plugin tests if applicable
        if plugin_info['has_run_method']:
            test_methods.append(self._generate_run_method_test())
        
        if plugin_info['has_metadata']:
            test_methods.append(self._generate_metadata_test())
        
        # Format the test code
        test_code = self.test_template.format(
            plugin_name=plugin_name,
            date=datetime.now().strftime('%Y-%m-%d'),
            imports=imports,
            class_name=plugin_info['classes'][0]['name'] if plugin_info['classes'] else plugin_name.replace('_', '').title(),
            test_methods='\n'.join(test_methods)
        )
        
        return test_code
    
    def _generate_imports(self, plugin_info: Dict[str, Any], plugin_name: str) -> str:
        """Generate import statements for tests"""
        imports = []
        
        # Import the plugin
        if plugin_info['classes']:
            class_name = plugin_info['classes'][0]['name']
            imports.append(f"from {plugin_name} import {class_name}")
        else:
            imports.append(f"import {plugin_name}")
        
        # Add common test imports based on plugin imports
        if 'requests' in plugin_info['imports']:
            imports.append("import requests_mock")
        
        if 'subprocess' in plugin_info['imports']:
            imports.append("from subprocess import CompletedProcess")
        
        if any('frida' in imp for imp in plugin_info['imports']):
            imports.append("# Mock Frida imports")
            imports.append("frida = MagicMock()")
        
        return '\n'.join(imports)
    
    def _generate_class_tests(self, class_info: Dict[str, Any]) -> List[str]:
        """Generate tests for a class"""
        tests = []
        
        # Test initialization
        if class_info['init_params']:
            tests.append(self._generate_init_test(class_info))
        
        # Test each method
        for method in class_info['methods']:
            if method['name'] not in ['__init__', '__str__', '__repr__']:
                tests.append(self._generate_method_test(method, class_info['name']))
        
        return tests
    
    def _generate_init_test(self, class_info: Dict[str, Any]) -> str:
        """Generate initialization test"""
        return f"""
    def test_initialization(self):
        \"\"\"Test {class_info['name']} initialization\"\"\"
        # Test default initialization
        instance = {class_info['name']}()
        self.assertIsNotNone(instance)
        
        # Test with parameters
        {self._generate_init_params_test(class_info['init_params'])}"""
    
    def _generate_init_params_test(self, params: List[str]) -> str:
        """Generate parameter test code"""
        if not params:
            return "# No parameters to test"
        
        param_values = []
        for param in params:
            if 'path' in param.lower() or 'file' in param.lower():
                param_values.append("'test_file.bin'")
            elif 'name' in param.lower():
                param_values.append("'test_name'")
            elif 'config' in param.lower() or 'options' in param.lower():
                param_values.append("{}")
            else:
                param_values.append("None")
        
        return f"instance = {class_info['name']}({', '.join(param_values)})"
    
    def _generate_method_test(self, method: Dict[str, Any], class_name: str) -> str:
        """Generate test for a method"""
        method_name = method['name']
        
        # Generate test body based on method signature
        test_body = self._generate_test_body(method)
        invalid_test_body = self._generate_invalid_test_body(method)
        edge_test_body = self._generate_edge_test_body(method)
        
        return self.method_test_template.format(
            method_name=method_name,
            test_body=test_body,
            invalid_test_body=invalid_test_body,
            edge_test_body=edge_test_body
        )
    
    def _generate_test_body(self, method: Dict[str, Any]) -> str:
        """Generate basic test body for method"""
        lines = []
        
        # Prepare arguments
        args = []
        for param in method['params']:
            if 'path' in param.lower() or 'binary' in param.lower():
                args.append("self.test_binary")
            elif 'options' in param.lower():
                args.append("self.test_options")
            else:
                args.append("'test_value'")
        
        # Call method
        if args:
            lines.append(f"result = self.plugin.{method['name']}({', '.join(args)})")
        else:
            lines.append(f"result = self.plugin.{method['name']}()")
        
        # Add assertions based on method characteristics
        if method['has_return']:
            lines.append("self.assertIsNotNone(result)")
            
            # Add type-specific assertions based on method name
            if 'find' in method['name'] or 'search' in method['name']:
                lines.append("self.assertIsInstance(result, (list, tuple))")
            elif 'analyze' in method['name'] or 'scan' in method['name']:
                lines.append("self.assertIsInstance(result, dict)")
            elif 'is_' in method['name'] or 'has_' in method['name']:
                lines.append("self.assertIsInstance(result, bool)")
        
        return '\n        '.join(lines) if lines else "pass"
    
    def _generate_invalid_test_body(self, method: Dict[str, Any]) -> str:
        """Generate invalid input test body"""
        lines = []
        
        if method['params']:
            # Test with None
            none_args = ['None' for _ in method['params']]
            lines.append(f"with self.assertRaises((TypeError, ValueError, AttributeError)):")
            lines.append(f"    self.plugin.{method['name']}({', '.join(none_args)})")
            
            # Test with wrong types
            lines.append("")
            lines.append("# Test with wrong types")
            wrong_args = ['123' if 'str' in str(p).lower() else "'string'" for p in method['params']]
            lines.append(f"with self.assertRaises((TypeError, ValueError)):")
            lines.append(f"    self.plugin.{method['name']}({', '.join(wrong_args)})")
        else:
            lines.append("# No parameters to test")
            lines.append("pass")
        
        return '\n        '.join(lines)
    
    def _generate_edge_test_body(self, method: Dict[str, Any]) -> str:
        """Generate edge case test body"""
        lines = []
        
        # Edge cases based on parameter names
        for param in method['params']:
            if 'path' in param.lower():
                lines.append("# Test with non-existent file")
                lines.append("result = self.plugin.{}('nonexistent.exe')".format(method['name']))
                lines.append("# Should handle gracefully")
                lines.append("")
            elif 'size' in param.lower():
                lines.append("# Test with zero size")
                lines.append("result = self.plugin.{}(0)".format(method['name']))
                lines.append("# Test with very large size")
                lines.append("result = self.plugin.{}(sys.maxsize)".format(method['name']))
        
        if not lines:
            lines.append("# Test edge cases specific to this method")
            lines.append("pass")
        
        return '\n        '.join(lines)
    
    def _generate_function_test(self, func_info: Dict[str, Any], plugin_name: str) -> str:
        """Generate test for standalone function"""
        return f"""
    def test_{func_info['name']}_function(self):
        \"\"\"Test {func_info['name']} function\"\"\"
        # Import function
        from {plugin_name} import {func_info['name']}
        
        {self._generate_test_body(func_info)}"""
    
    def _generate_run_method_test(self) -> str:
        """Generate standard run method test"""
        return """
    def test_run_method_success(self):
        \"\"\"Test successful plugin execution\"\"\"
        result = self.plugin.run(self.test_binary, self.test_options)
        self.assertPluginResult(result)
        self.assertNoErrors(result)
    
    def test_run_method_missing_binary(self):
        \"\"\"Test run with missing binary\"\"\"
        result = self.plugin.run('nonexistent.exe', self.test_options)
        self.assertPluginResult(result)
        self.assertIn(result['status'], ['error', 'warning'])
    
    @patch('os.path.exists')
    def test_run_method_permission_error(self, mock_exists):
        \"\"\"Test run with permission error\"\"\"
        mock_exists.return_value = True
        
        with patch('builtins.open', side_effect=PermissionError):
            result = self.plugin.run(self.test_binary, self.test_options)
            self.assertPluginResult(result)
            self.assertEqual(result['status'], 'error')"""
    
    def _generate_metadata_test(self) -> str:
        """Generate metadata test"""
        return """
    def test_get_metadata(self):
        \"\"\"Test plugin metadata\"\"\"
        metadata = self.plugin.get_metadata()
        
        # Check required fields
        self.assertIsInstance(metadata, dict)
        self.assertIn('name', metadata)
        self.assertIn('version', metadata)
        self.assertIn('description', metadata)
        
        # Check field types
        self.assertIsInstance(metadata['name'], str)
        self.assertIsInstance(metadata['version'], str)
        self.assertIsInstance(metadata['description'], str)
        
        # Check optional fields
        if 'author' in metadata:
            self.assertIsInstance(metadata['author'], str)
        if 'capabilities' in metadata:
            self.assertIsInstance(metadata['capabilities'], list)"""


class TestCoverageAnalyzer:
    """Analyzes test coverage for plugins"""
    
    def analyze_coverage(self, plugin_path: str, test_path: str) -> Dict[str, Any]:
        """Analyze test coverage for a plugin"""
        import coverage
        
        # Create coverage instance
        cov = coverage.Coverage()
        
        # Start coverage
        cov.start()
        
        # Run the tests
        import subprocess
        result = subprocess.run(
            [sys.executable, '-m', 'pytest', test_path, '-v'],
            capture_output=True,
            text=True
        )
        
        # Stop coverage
        cov.stop()
        
        # Generate report
        report = {
            'total_coverage': 0,
            'missing_lines': [],
            'uncovered_functions': [],
            'test_results': {
                'passed': 0,
                'failed': 0,
                'errors': 0
            }
        }
        
        # Parse test results
        if result.returncode == 0:
            # Parse pytest output
            lines = result.stdout.split('\n')
            for line in lines:
                if 'passed' in line:
                    report['test_results']['passed'] = int(re.search(r'(\d+) passed', line).group(1))
                if 'failed' in line:
                    report['test_results']['failed'] = int(re.search(r'(\d+) failed', line).group(1))
        
        return report


class MockDataGenerator:
    """Generates mock data for plugin testing"""
    
    @staticmethod
    def create_mock_binary(binary_type: str = 'pe') -> bytes:
        """Create mock binary data"""
        if binary_type == 'pe':
            # Minimal PE structure
            dos_header = b'MZ' + b'\x90' * 58 + b'\x3c\x00\x00\x00'  # e_lfanew at offset 60
            dos_stub = b'\x00' * 64
            
            # PE header
            pe_header = b'PE\x00\x00'  # PE signature
            
            # COFF header
            machine = b'\x64\x86'  # x64
            num_sections = b'\x03\x00'
            timestamp = b'\x00\x00\x00\x00'
            ptr_symbol_table = b'\x00\x00\x00\x00'
            num_symbols = b'\x00\x00\x00\x00'
            size_optional = b'\xf0\x00'
            characteristics = b'\x22\x00'
            
            coff_header = machine + num_sections + timestamp + ptr_symbol_table + num_symbols + size_optional + characteristics
            
            # Optional header
            magic = b'\x0b\x02'  # PE32+
            optional_header = magic + b'\x00' * 238
            
            # Section headers
            text_section = b'.text\x00\x00\x00' + b'\x00' * 32
            data_section = b'.data\x00\x00\x00' + b'\x00' * 32
            rsrc_section = b'.rsrc\x00\x00\x00' + b'\x00' * 32
            
            # Combine all parts
            pe_data = dos_header + dos_stub + pe_header + coff_header + optional_header
            pe_data += text_section + data_section + rsrc_section
            
            # Add some fake code
            pe_data += b'\x55\x48\x89\xe5'  # push rbp; mov rbp, rsp
            pe_data += b'\x48\x83\xec\x20'  # sub rsp, 0x20
            pe_data += b'\xe8\x00\x00\x00\x00'  # call
            pe_data += b'\x48\x83\xc4\x20'  # add rsp, 0x20
            pe_data += b'\x5d'  # pop rbp
            pe_data += b'\xc3'  # ret
            
            # Pad to reasonable size
            pe_data += b'\x00' * (4096 - len(pe_data))
            
            return pe_data
            
        elif binary_type == 'elf':
            # ELF header
            elf_header = b'\x7fELF'  # Magic
            elf_header += b'\x02'  # 64-bit
            elf_header += b'\x01'  # Little endian
            elf_header += b'\x01'  # Current version
            elf_header += b'\x00' * 9  # Padding
            elf_header += b'\x02\x00'  # Executable
            elf_header += b'\x3e\x00'  # x86-64
            elf_header += b'\x01\x00\x00\x00'  # Current version
            elf_header += b'\x00' * 48  # Rest of header
            
            return elf_header + b'\x00' * 4000
        
        else:
            # Generic binary
            return b'BINARY' + b'\x00' * 1000
    
    @staticmethod
    def create_mock_network_data() -> Dict[str, Any]:
        """Create mock network data"""
        return {
            'packets': [
                {
                    'timestamp': 1234567890.123,
                    'src_ip': '192.168.1.100',
                    'dst_ip': '10.0.0.1',
                    'protocol': 'TCP',
                    'data': b'LICENSE_CHECK'
                },
                {
                    'timestamp': 1234567891.456,
                    'src_ip': '10.0.0.1',
                    'dst_ip': '192.168.1.100',
                    'protocol': 'TCP',
                    'data': b'LICENSE_VALID'
                }
            ],
            'connections': [
                {
                    'local': ('192.168.1.100', 12345),
                    'remote': ('10.0.0.1', 443),
                    'state': 'ESTABLISHED'
                }
            ]
        }
    
    @staticmethod
    def create_mock_registry_data() -> Dict[str, str]:
        """Create mock registry data"""
        return {
            'HKLM\\SOFTWARE\\Company\\Product': {
                'LicenseKey': 'XXXX-XXXX-XXXX-XXXX',
                'InstallDate': '2023-01-01',
                'Version': '1.0.0'
            },
            'HKCU\\SOFTWARE\\Company\\Product': {
                'TrialDaysLeft': '30',
                'LastRun': '2023-06-01'
            }
        }


# Test runner integration
class PluginTestRunner:
    """Runs tests for plugins with coverage reporting"""
    
    def __init__(self):
        self.generator = PluginTestGenerator()
        self.analyzer = TestCoverageAnalyzer()
    
    def generate_and_run_tests(self, plugin_path: str) -> Dict[str, Any]:
        """Generate tests and run them with coverage"""
        # Generate test file
        test_code = self.generator.generate_tests_for_file(plugin_path)
        
        # Save test file
        test_dir = os.path.join(os.path.dirname(plugin_path), 'tests')
        os.makedirs(test_dir, exist_ok=True)
        
        test_filename = f"test_{os.path.basename(plugin_path)}"
        test_path = os.path.join(test_dir, test_filename)
        
        with open(test_path, 'w') as f:
            f.write(test_code)
        
        # Run tests with coverage
        coverage_report = self.analyzer.analyze_coverage(plugin_path, test_path)
        
        return {
            'test_file': test_path,
            'coverage': coverage_report,
            'test_code': test_code
        }


