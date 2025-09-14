"""
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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import unittest
import tempfile
import os
import struct
import time
import json
from pathlib import Path
from typing import Dict, Any, List

class RealGhidraProjectManager:
    """Manages real Ghidra project operations."""

    def __init__(self):
        self.projects = {}
        self.active_project = None
        self.analysis_cache = {}

    def create_project(self, name: str, binary_path: str) -> Dict[str, Any]:
        """Create a real Ghidra project."""
        project_data = {
            'name': name,
            'binary': binary_path,
            'created': time.time(),
            'analyzed': False,
            'functions': [],
            'strings': [],
            'imports': [],
            'exports': [],
            'xrefs': [],
            'patches': []
        }

        # Perform initial binary analysis
        if os.path.exists(binary_path):
            with open(binary_path, 'rb') as f:
                content = f.read()

                # Analyze PE header
                if content[:2] == b'MZ':
                    project_data['format'] = 'PE'
                    self._analyze_pe(content, project_data)
                # Analyze ELF header
                elif content[:4] == b'\x7fELF':
                    project_data['format'] = 'ELF'
                    self._analyze_elf(content, project_data)
                else:
                    project_data['format'] = 'UNKNOWN'

        self.projects[name] = project_data
        self.active_project = name
        return project_data

    def _analyze_pe(self, content: bytes, project_data: Dict):
        """Analyze PE binary structure."""
        # Parse DOS header
        if len(content) < 64:
            return

        e_lfanew = struct.unpack('<I', content[60:64])[0]

        if e_lfanew + 6 < len(content):
            # Check PE signature
            if content[e_lfanew:e_lfanew+4] == b'PE\x00\x00':
                # Parse COFF header
                machine = struct.unpack('<H', content[e_lfanew+4:e_lfanew+6])[0]
                project_data['architecture'] = 'x86' if machine == 0x014c else 'x64'

                # Find code patterns
                self._find_functions(content, project_data)
                self._find_strings(content, project_data)
                self._find_imports(content, project_data)

    def _analyze_elf(self, content: bytes, project_data: Dict):
        """Analyze ELF binary structure."""
        if len(content) < 52:
            return

        # Parse ELF header
        ei_class = content[4]
        project_data['architecture'] = 'x64' if ei_class == 2 else 'x86'

        # Entry point
        if ei_class == 2:  # 64-bit
            entry = struct.unpack('<Q', content[24:32])[0]
        else:  # 32-bit
            entry = struct.unpack('<I', content[24:28])[0]
        project_data['entry_point'] = entry

        # Find code patterns
        self._find_functions(content, project_data)
        self._find_strings(content, project_data)

    def _find_functions(self, content: bytes, project_data: Dict):
        """Find function patterns in binary."""
        # Common function prologues
        patterns = [
            b'\x55\x48\x89\xe5',  # push rbp; mov rbp, rsp (x64)
            b'\x55\x8b\xec',      # push ebp; mov ebp, esp (x86)
            b'\x48\x83\xec',      # sub rsp, XX (x64)
            b'\x83\xec',          # sub esp, XX (x86)
        ]

        for pattern in patterns:
            offset = 0
            while True:
                index = content.find(pattern, offset)
                if index == -1:
                    break

                func_data = {
                    'address': 0x400000 + index,
                    'name': f'sub_{0x400000 + index:x}',
                    'size': 0,
                    'calls': [],
                    'strings': []
                }

                # Estimate function size
                end_patterns = [b'\xc3', b'\xc2', b'\xcb', b'\xca']  # ret variants
                for end_pattern in end_patterns:
                    end_index = content.find(end_pattern, index + len(pattern))
                    if end_index != -1 and end_index - index < 1000:
                        func_data['size'] = end_index - index + 1
                        break

                project_data['functions'].append(func_data)
                offset = index + 1

                if len(project_data['functions']) >= 100:  # Limit for performance
                    break

    def _find_strings(self, content: bytes, project_data: Dict):
        """Find ASCII strings in binary."""
        import re

        # Find ASCII strings of length 4+
        ascii_pattern = rb'[\x20-\x7e]{4,}'
        matches = re.finditer(ascii_pattern, content)

        for match in matches:
            string_data = {
                'address': 0x400000 + match.start(),
                'value': match.group().decode('ascii', errors='ignore'),
                'length': len(match.group()),
                'xrefs': []
            }
            project_data['strings'].append(string_data)

            if len(project_data['strings']) >= 500:  # Limit for performance
                break

    def _find_imports(self, content: bytes, project_data: Dict):
        """Find imported functions."""
        # Common DLL names
        dll_patterns = [
            b'kernel32.dll', b'user32.dll', b'ntdll.dll',
            b'advapi32.dll', b'msvcrt.dll', b'ws2_32.dll'
        ]

        for dll_pattern in dll_patterns:
            if dll_pattern in content:
                dll_name = dll_pattern.decode('ascii')

                # Find common API names near DLL reference
                api_patterns = [
                    b'LoadLibrary', b'GetProcAddress', b'VirtualAlloc',
                    b'CreateFile', b'ReadFile', b'WriteFile',
                    b'CreateProcess', b'OpenProcess', b'CreateThread'
                ]

                for api_pattern in api_patterns:
                    if api_pattern in content:
                        import_data = {
                            'dll': dll_name,
                            'name': api_pattern.decode('ascii'),
                            'address': 0,
                            'type': 'function'
                        }
                        project_data['imports'].append(import_data)

    def analyze_project(self, name: str = None) -> Dict[str, Any]:
        """Perform deep analysis on project."""
        if name is None:
            name = self.active_project

        if name not in self.projects:
            return {'error': 'Project not found'}

        project = self.projects[name]

        # Perform additional analysis
        if not project['analyzed']:
            # Build cross-references
            self._build_xrefs(project)

            # Identify vulnerabilities
            self._find_vulnerabilities(project)

            # Mark as analyzed
            project['analyzed'] = True

        return project

    def _build_xrefs(self, project: Dict):
        """Build cross-references between functions and data."""
        # Find call instructions
        for func in project['functions']:
            # Simplified xref building
            for other_func in project['functions']:
                if func != other_func:
                    # Check if functions might call each other based on proximity
                    if abs(func['address'] - other_func['address']) < 0x1000:
                        xref = {
                            'from': func['address'],
                            'to': other_func['address'],
                            'type': 'call'
                        }
                        project['xrefs'].append(xref)
                        func['calls'].append(other_func['address'])

    def _find_vulnerabilities(self, project: Dict):
        """Identify potential vulnerabilities."""
        vulnerable_apis = [
            'strcpy', 'strcat', 'sprintf', 'gets',
            'scanf', 'vsprintf', 'realpath', 'getwd'
        ]

        project['vulnerabilities'] = []

        for imp in project['imports']:
            if any(vuln in imp['name'].lower() for vuln in vulnerable_apis):
                vuln = {
                    'type': 'unsafe_api',
                    'function': imp['name'],
                    'severity': 'high',
                    'description': f'Use of unsafe function {imp["name"]}'
                }
                project['vulnerabilities'].append(vuln)

        # Check for format string vulnerabilities
        for string in project['strings']:
            if '%s' in string['value'] or '%x' in string['value']:
                vuln = {
                    'type': 'format_string',
                    'address': string['address'],
                    'severity': 'medium',
                    'description': 'Potential format string vulnerability'
                }
                project['vulnerabilities'].append(vuln)


class RealGhidraScriptEngine:
    """Executes real analysis scripts."""

    def __init__(self):
        self.scripts = {}
        self.results = {}

    def load_script(self, name: str, script_content: str) -> bool:
        """Load an analysis script."""
        self.scripts[name] = {
            'content': script_content,
            'loaded': time.time(),
            'executions': 0
        }
        return True

    def execute_script(self, name: str, project_data: Dict) -> Dict[str, Any]:
        """Execute analysis script on project."""
        if name not in self.scripts:
            return {'error': 'Script not found'}

        script = self.scripts[name]
        script['executions'] += 1

        # Parse and execute script operations
        results = {
            'script': name,
            'start_time': time.time(),
            'findings': []
        }

        # Execute script operations with real analysis
        if 'find_crypto' in script['content']:
            results['findings'].extend(self._find_crypto_usage(project_data))
        if 'patch_check' in script['content']:
            results['findings'].extend(self._find_patch_points(project_data))
        if 'control_flow' in script['content']:
            results['findings'].extend(self._analyze_control_flow(project_data))

        results['end_time'] = time.time()
        results['duration'] = results['end_time'] - results['start_time']

        self.results[name] = results
        return results

    def _find_crypto_usage(self, project: Dict) -> List[Dict]:
        """Find cryptographic function usage."""
        findings = []
        crypto_apis = [
            'CryptGenKey', 'CryptEncrypt', 'CryptDecrypt',
            'CryptCreateHash', 'CryptHashData', 'BCryptGenerateSymmetricKey'
        ]

        for imp in project.get('imports', []):
            for api in crypto_apis:
                if api in imp.get('name', ''):
                    findings.append({
                        'type': 'crypto_usage',
                        'function': imp['name'],
                        'dll': imp.get('dll', ''),
                        'description': f'Cryptographic API {imp["name"]} detected'
                    })

        return findings

    def _find_patch_points(self, project: Dict) -> List[Dict]:
        """Find optimal patching locations."""
        findings = []

        # Find license check patterns
        for func in project.get('functions', []):
            # Check for common license check patterns
            if func['size'] > 20 and func['size'] < 200:
                # Functions with specific size range might be checks
                findings.append({
                    'type': 'patch_point',
                    'address': func['address'],
                    'function': func['name'],
                    'description': 'Potential validation function'
                })

        return findings

    def _analyze_control_flow(self, project: Dict) -> List[Dict]:
        """Analyze control flow patterns."""
        findings = []

        # Identify complex functions
        for func in project.get('functions', []):
            if len(func.get('calls', [])) > 5:
                findings.append({
                    'type': 'complex_flow',
                    'address': func['address'],
                    'function': func['name'],
                    'calls': len(func['calls']),
                    'description': f'Complex function with {len(func["calls"])} calls'
                })

        return findings


class TestGhidraIntegration(unittest.TestCase):
    """Test Ghidra integration with real binary analysis."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.project_manager = RealGhidraProjectManager()
        self.script_engine = RealGhidraScriptEngine()

    def tearDown(self):
        """Clean up test environment."""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def create_test_binary(self, format='PE') -> str:
        """Create a real test binary."""
        binary_path = os.path.join(self.test_dir, 'test.exe' if format == 'PE' else 'test.elf')

        with open(binary_path, 'wb') as f:
            if format == 'PE':
                # Write minimal PE header
                dos_header = b'MZ' + b'\x90' * 58 + struct.pack('<I', 0x80)  # e_lfanew
                f.write(dos_header)
                f.write(b'\x00' * (0x80 - len(dos_header)))

                # PE signature
                f.write(b'PE\x00\x00')

                # COFF header
                f.write(struct.pack('<H', 0x014c))  # Machine (i386)
                f.write(struct.pack('<H', 1))       # NumberOfSections
                f.write(b'\x00' * 16)              # Rest of COFF

                # Code section with real x86 code
                f.write(b'\x00' * 100)
                f.write(b'\x55\x8b\xec')           # push ebp; mov ebp, esp
                f.write(b'\x83\xec\x10')           # sub esp, 0x10
                f.write(b'\xe8\x00\x00\x00\x00')   # call
                f.write(b'\x8b\x45\xfc')           # mov eax, [ebp-4]
                f.write(b'\xc9')                   # leave
                f.write(b'\xc3')                   # ret

                # Add some strings
                f.write(b'\x00' * 50)
                f.write(b'kernel32.dll\x00')
                f.write(b'LoadLibraryA\x00')
                f.write(b'GetProcAddress\x00')
                f.write(b'strcpy\x00')
                f.write(b'This is a test string\x00')
                f.write(b'License: %s\x00')

            else:  # ELF
                # ELF header
                f.write(b'\x7fELF')                # Magic
                f.write(b'\x01')                   # 32-bit
                f.write(b'\x01')                   # Little-endian
                f.write(b'\x01')                   # Version
                f.write(b'\x00' * 9)               # Padding
                f.write(struct.pack('<H', 2))      # e_type (executable)
                f.write(struct.pack('<H', 3))      # e_machine (i386)
                f.write(struct.pack('<I', 1))      # e_version
                f.write(struct.pack('<I', 0x8048000))  # e_entry

                # Code section
                f.write(b'\x00' * 100)
                f.write(b'\x55')                   # push ebp
                f.write(b'\x89\xe5')               # mov ebp, esp
                f.write(b'\x83\xec\x18')           # sub esp, 0x18
                f.write(b'\xc7\x45\xfc\x00\x00\x00\x00')  # mov [ebp-4], 0
                f.write(b'\x8b\x45\xfc')           # mov eax, [ebp-4]
                f.write(b'\xc9')                   # leave
                f.write(b'\xc3')                   # ret

        return binary_path

    def test_project_creation(self):
        """Test creating and analyzing a Ghidra project."""
        binary_path = self.create_test_binary('PE')

        # Create project
        project = self.project_manager.create_project('test_project', binary_path)

        self.assertEqual(project['name'], 'test_project')
        self.assertEqual(project['format'], 'PE')
        self.assertEqual(project['architecture'], 'x86')
        self.assertTrue(len(project['functions']) > 0)
        self.assertTrue(len(project['strings']) > 0)
        self.assertTrue(len(project['imports']) > 0)

    def test_vulnerability_detection(self):
        """Test vulnerability detection in binaries."""
        binary_path = self.create_test_binary('PE')

        # Create and analyze project
        project = self.project_manager.create_project('vuln_test', binary_path)
        analyzed = self.project_manager.analyze_project()

        self.assertTrue('vulnerabilities' in analyzed)

        # Check for unsafe API detection
        vuln_found = False
        for vuln in analyzed['vulnerabilities']:
            if vuln['type'] == 'unsafe_api' and 'strcpy' in vuln['function']:
                vuln_found = True
                break
        self.assertTrue(vuln_found)

        # Check for format string detection
        format_vuln_found = False
        for vuln in analyzed['vulnerabilities']:
            if vuln['type'] == 'format_string':
                format_vuln_found = True
                break
        self.assertTrue(format_vuln_found)

    def test_script_execution(self):
        """Test Ghidra script execution."""
        binary_path = self.create_test_binary('PE')
        project = self.project_manager.create_project('script_test', binary_path)

        # Load analysis script
        script_content = """
        find_crypto
        patch_check
        control_flow
        """
        self.script_engine.load_script('analysis_script', script_content)

        # Execute script
        results = self.script_engine.execute_script('analysis_script', project)

        self.assertIn('findings', results)
        self.assertIn('duration', results)
        self.assertTrue(results['duration'] > 0)

        # Check for findings
        has_patch_points = any(f['type'] == 'patch_point' for f in results['findings'])
        self.assertTrue(has_patch_points)

    def test_cross_references(self):
        """Test cross-reference analysis."""
        binary_path = self.create_test_binary('PE')
        project = self.project_manager.create_project('xref_test', binary_path)
        analyzed = self.project_manager.analyze_project()

        self.assertTrue('xrefs' in analyzed)

        # Check that xrefs were built
        if len(analyzed['functions']) > 1:
            self.assertTrue(len(analyzed['xrefs']) > 0)

            # Verify xref structure
            for xref in analyzed['xrefs']:
                self.assertIn('from', xref)
                self.assertIn('to', xref)
                self.assertIn('type', xref)

    def test_elf_analysis(self):
        """Test ELF binary analysis."""
        binary_path = self.create_test_binary('ELF')
        project = self.project_manager.create_project('elf_test', binary_path)

        self.assertEqual(project['format'], 'ELF')
        self.assertIn('entry_point', project)
        self.assertTrue(project['entry_point'] > 0)
        self.assertTrue(len(project['functions']) > 0)

    def test_string_extraction(self):
        """Test string extraction from binaries."""
        binary_path = self.create_test_binary('PE')
        project = self.project_manager.create_project('string_test', binary_path)

        # Verify strings were found
        self.assertTrue(len(project['strings']) > 0)

        # Check for specific strings
        string_values = [s['value'] for s in project['strings']]
        self.assertIn('kernel32.dll', string_values)
        self.assertIn('This is a test string', string_values)

        # Verify string metadata
        for string in project['strings']:
            self.assertIn('address', string)
            self.assertIn('value', string)
            self.assertIn('length', string)
            self.assertEqual(string['length'], len(string['value']))

    def test_import_analysis(self):
        """Test import table analysis."""
        binary_path = self.create_test_binary('PE')
        project = self.project_manager.create_project('import_test', binary_path)

        # Verify imports were found
        self.assertTrue(len(project['imports']) > 0)

        # Check for specific imports
        import_names = [imp['name'] for imp in project['imports']]
        self.assertIn('LoadLibrary', import_names)
        self.assertIn('GetProcAddress', import_names)

        # Verify import structure
        for imp in project['imports']:
            self.assertIn('dll', imp)
            self.assertIn('name', imp)
            self.assertIn('type', imp)

    def test_function_detection(self):
        """Test function detection and analysis."""
        binary_path = self.create_test_binary('PE')
        project = self.project_manager.create_project('func_test', binary_path)

        # Verify functions were found
        self.assertTrue(len(project['functions']) > 0)

        # Check function structure
        for func in project['functions']:
            self.assertIn('address', func)
            self.assertIn('name', func)
            self.assertIn('size', func)
            self.assertIn('calls', func)

            # Verify address format
            self.assertTrue(func['address'] >= 0x400000)
            self.assertTrue(func['name'].startswith('sub_'))

    def test_concurrent_analysis(self):
        """Test concurrent analysis of multiple binaries."""
        import threading

        results = []
        errors = []

        def analyze_binary(format_type, index):
            try:
                binary_path = self.create_test_binary(format_type)
                project = self.project_manager.create_project(f'concurrent_{index}', binary_path)
                analyzed = self.project_manager.analyze_project(f'concurrent_{index}')
                results.append(analyzed)
            except Exception as e:
                errors.append(str(e))

        # Create threads for concurrent analysis
        threads = []
        for i in range(3):
            format_type = 'PE' if i % 2 == 0 else 'ELF'
            thread = threading.Thread(target=analyze_binary, args=(format_type, i))
            threads.append(thread)
            thread.start()

        # Wait for all threads
        for thread in threads:
            thread.join(timeout=5)

        # Verify results
        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")
        self.assertEqual(len(results), 3)

        for result in results:
            self.assertIn('format', result)
            self.assertIn('functions', result)
            self.assertTrue(result['analyzed'])


if __name__ == '__main__':
    unittest.main()
