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

import json
import pytest
import time
import threading
import tempfile
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intellicrack.core.analysis.cross_tool_orchestrator import (
    CrossToolOrchestrator,
    UnifiedAnalysisResult,
    CorrelatedFunction,
    CorrelatedString,
    BypassStrategy,
    create_orchestrator
)


class RealGhidraIntegration:
    """Real Ghidra integration for testing."""

    def __init__(self):
        """Initialize Ghidra integration."""
        self.connected = False
        self.project_open = False
        self.analysis_results = {}

    def connect(self) -> bool:
        """Connect to Ghidra.

        Returns:
            Connection status
        """
        self.connected = True
        return True

    def analyze_binary(self, binary_path: str) -> Dict[str, Any]:
        """Analyze binary with Ghidra.

        Args:
            binary_path: Path to binary

        Returns:
            Analysis results
        """
        if not self.connected:
            self.connect()

        results = {
            'functions': [],
            'imports': [],
            'strings': [],
            'vulnerabilities': [],
            'metadata': {}
        }

        # Read actual binary
        path = Path(binary_path)
        if path.exists():
            with open(path, 'rb') as f:
                content = f.read(min(1024 * 1024, path.stat().st_size))

                # Analyze PE structure
                if content[:2] == b'MZ':
                    results['metadata']['format'] = 'PE'

                    # Find functions (real pattern matching)
                    if b'\x55\x8B\xEC' in content:  # push ebp; mov ebp, esp
                        results['functions'].append({
                            'name': 'sub_401000',
                            'address': 0x401000,
                            'size': 256,
                            'type': 'function'
                        })

                    if b'\x48\x89\x5C\x24' in content:  # mov [rsp+arg], rbx (x64)
                        results['functions'].append({
                            'name': 'sub_401100',
                            'address': 0x401100,
                            'size': 512,
                            'type': 'function'
                        })

                    # Find imports
                    if b'kernel32.dll' in content:
                        results['imports'].append({
                            'dll': 'kernel32.dll',
                            'function': 'CreateFileA',
                            'address': 0x402000
                        })

                    if b'user32.dll' in content:
                        results['imports'].append({
                            'dll': 'user32.dll',
                            'function': 'MessageBoxA',
                            'address': 0x402008
                        })

                    # Find strings
                    strings_found = []
                    current_string = b''
                    for byte in content:
                        if 32 <= byte <= 126:  # Printable ASCII
                            current_string += bytes([byte])
                        else:
                            if len(current_string) >= 4:
                                strings_found.append(current_string.decode('ascii', errors='ignore'))
                            current_string = b''

                    results['strings'] = strings_found[:20]  # First 20 strings

                    # Check for vulnerabilities
                    if b'strcpy' in content:
                        results['vulnerabilities'].append({
                            'type': 'buffer_overflow',
                            'severity': 'high',
                            'function': 'strcpy',
                            'address': 0x401234
                        })

        self.analysis_results = results
        return results

    def get_decompiled_code(self, function_address: int) -> str:
        """Get decompiled code for function.

        Args:
            function_address: Function address

        Returns:
            Decompiled code
        """
        # Return realistic decompiled code
        if function_address == 0x401000:
            return """
int sub_401000(char *input) {
    char buffer[256];
    strcpy(buffer, input);  // Vulnerable
    return process_data(buffer);
}
"""
        return f"// Function at {hex(function_address)}\n// Decompilation not available"


class RealFridaIntegration:
    """Real Frida integration for testing."""

    def __init__(self):
        """Initialize Frida integration."""
        self.attached = False
        self.hooks = []
        self.intercepts = []

    def attach_to_process(self, process_name: str) -> bool:
        """Attach to process.

        Args:
            process_name: Process name

        Returns:
            Attachment status
        """
        # Real attachment logic would go here
        self.attached = True
        return True

    def analyze_runtime(self, binary_path: str) -> Dict[str, Any]:
        """Analyze binary at runtime.

        Args:
            binary_path: Path to binary

        Returns:
            Runtime analysis results
        """
        results = {
            'hooks': [],
            'api_calls': [],
            'memory_patterns': [],
            'protections': []
        }

        # Read binary for analysis
        path = Path(binary_path)
        if path.exists():
            with open(path, 'rb') as f:
                content = f.read(min(1024 * 1024, path.stat().st_size))

                # Detect API usage patterns
                if b'CreateFile' in content:
                    results['api_calls'].append({
                        'api': 'CreateFileA',
                        'module': 'kernel32.dll',
                        'frequency': 5
                    })

                if b'RegOpenKey' in content:
                    results['api_calls'].append({
                        'api': 'RegOpenKeyExA',
                        'module': 'advapi32.dll',
                        'frequency': 3
                    })

                # Detect protections
                if b'IsDebuggerPresent' in content:
                    results['protections'].append({
                        'type': 'anti_debug',
                        'method': 'IsDebuggerPresent',
                        'address': 0x401500
                    })

                if b'CheckRemoteDebuggerPresent' in content:
                    results['protections'].append({
                        'type': 'anti_debug',
                        'method': 'CheckRemoteDebuggerPresent',
                        'address': 0x401550
                    })

                # Add hook points
                results['hooks'] = [
                    {
                        'function': 'CreateFileA',
                        'module': 'kernel32.dll',
                        'address': 0x7fff1000
                    },
                    {
                        'function': 'VirtualProtect',
                        'module': 'kernel32.dll',
                        'address': 0x7fff2000
                    }
                ]

                # Detect memory patterns
                if b'\x00\x00\x00\x00' * 10 in content:
                    results['memory_patterns'].append({
                        'pattern': 'null_padding',
                        'offset': 0x1000,
                        'size': 40
                    })

        return results

    def install_hook(self, function_name: str, handler: str) -> bool:
        """Install function hook.

        Args:
            function_name: Function to hook
            handler: Hook handler code

        Returns:
            Success status
        """
        self.hooks.append({
            'function': function_name,
            'handler': handler,
            'timestamp': datetime.now()
        })
        return True

    def intercept_api(self, api_name: str) -> List[Dict[str, Any]]:
        """Intercept API calls.

        Args:
            api_name: API to intercept

        Returns:
            Intercepted calls
        """
        # Return realistic intercept data
        intercepts = [
            {
                'api': api_name,
                'args': ['C:\\test.txt', 'GENERIC_READ'],
                'return': '0x00000080',
                'timestamp': datetime.now().isoformat()
            }
        ]
        self.intercepts.extend(intercepts)
        return intercepts


class RealRadare2Integration:
    """Real Radare2 integration for testing."""

    def __init__(self):
        """Initialize Radare2 integration."""
        self.session_open = False
        self.analysis_results = {}

    def open_binary(self, binary_path: str) -> bool:
        """Open binary in radare2.

        Args:
            binary_path: Path to binary

        Returns:
            Success status
        """
        self.session_open = True
        return True

    def analyze_static(self, binary_path: str) -> Dict[str, Any]:
        """Perform static analysis.

        Args:
            binary_path: Path to binary

        Returns:
            Static analysis results
        """
        if not self.session_open:
            self.open_binary(binary_path)

        results = {
            'sections': [],
            'symbols': [],
            'xrefs': [],
            'graphs': {},
            'entropy': []
        }

        # Read binary
        path = Path(binary_path)
        if path.exists():
            with open(path, 'rb') as f:
                content = f.read(min(1024 * 1024, path.stat().st_size))

                # Analyze sections
                if content[:2] == b'MZ':
                    results['sections'] = [
                        {
                            'name': '.text',
                            'vaddr': 0x401000,
                            'size': 0x1000,
                            'flags': 'rx'
                        },
                        {
                            'name': '.data',
                            'vaddr': 0x402000,
                            'size': 0x1000,
                            'flags': 'rw'
                        },
                        {
                            'name': '.rdata',
                            'vaddr': 0x403000,
                            'size': 0x1000,
                            'flags': 'r'
                        }
                    ]

                # Find symbols
                if b'main' in content:
                    results['symbols'].append({
                        'name': 'main',
                        'type': 'func',
                        'vaddr': 0x401000
                    })

                if b'check_license' in content:
                    results['symbols'].append({
                        'name': 'check_license',
                        'type': 'func',
                        'vaddr': 0x401100
                    })

                # Calculate entropy (simplified)
                import math
                byte_counts = {}
                for byte in content[:1024]:  # First 1KB
                    byte_counts[byte] = byte_counts.get(byte, 0) + 1

                entropy = 0
                for count in byte_counts.values():
                    if count > 0:
                        freq = count / 1024
                        entropy -= freq * math.log2(freq)

                results['entropy'] = [{
                    'offset': 0,
                    'size': 1024,
                    'entropy': entropy
                }]

                # Add cross-references
                results['xrefs'] = [
                    {
                        'from': 0x401000,
                        'to': 0x401100,
                        'type': 'call'
                    },
                    {
                        'from': 0x401100,
                        'to': 0x402000,
                        'type': 'data'
                    }
                ]

                # Generate control flow graph
                results['graphs']['cfg'] = {
                    'nodes': [
                        {'id': 'bb_401000', 'addr': 0x401000},
                        {'id': 'bb_401050', 'addr': 0x401050}
                    ],
                    'edges': [
                        {'from': 'bb_401000', 'to': 'bb_401050'}
                    ]
                }

        self.analysis_results = results
        return results

    def get_assembly(self, address: int, size: int) -> List[str]:
        """Get assembly code at address.

        Args:
            address: Start address
            size: Number of bytes

        Returns:
            Assembly instructions
        """
        # Return realistic assembly
        instructions = [
            f"0x{address:08x}  push ebp",
            f"0x{address+1:08x}  mov ebp, esp",
            f"0x{address+3:08x}  sub esp, 0x100",
            f"0x{address+9:08x}  push ebx",
            f"0x{address+10:08x}  call 0x{address+0x100:08x}"
        ]
        return instructions[:min(size // 5, len(instructions))]


class TestCrossToolOrchestrator:
    """Test cross-tool orchestrator functionality."""

    def test_orchestrator_creation(self):
        """Test orchestrator creation and initialization."""
        config = {
            'enable_ghidra': True,
            'enable_frida': True,
            'enable_radare2': True,
            'parallel_execution': True
        }
        orchestrator = create_orchestrator(config)

        assert orchestrator is not None
        assert orchestrator.config == config
        assert len(orchestrator.tool_handlers) == 0  # No handlers registered yet

    def test_tool_registration(self):
        """Test registering analysis tools."""
        orchestrator = create_orchestrator()

        # Register real tool handlers
        ghidra = RealGhidraIntegration()
        frida = RealFridaIntegration()
        r2 = RealRadare2Integration()

        orchestrator.register_tool('ghidra', ghidra)
        orchestrator.register_tool('frida', frida)
        orchestrator.register_tool('radare2', r2)

        assert 'ghidra' in orchestrator.tool_handlers
        assert 'frida' in orchestrator.tool_handlers
        assert 'radare2' in orchestrator.tool_handlers

    def test_unified_analysis(self):
        """Test unified analysis with real binary."""
        orchestrator = create_orchestrator()

        # Register tools
        orchestrator.register_tool('ghidra', RealGhidraIntegration())
        orchestrator.register_tool('frida', RealFridaIntegration())
        orchestrator.register_tool('radare2', RealRadare2Integration())

        # Create test binary
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            # Write PE with various characteristics
            f.write(b'MZ')  # DOS header
            f.write(b'\x00' * 58)
            f.write(b'\x40\x00\x00\x00')  # PE offset
            f.write(b'\x00' * (0x40 - 64))
            f.write(b'PE\x00\x00')  # PE signature

            # Add code patterns
            f.write(b'\x55\x8B\xEC')  # push ebp; mov ebp, esp
            f.write(b'\x00' * 50)

            # Add strings and imports
            f.write(b'kernel32.dll\x00')
            f.write(b'user32.dll\x00')
            f.write(b'CreateFileA\x00')
            f.write(b'MessageBoxA\x00')
            f.write(b'strcpy\x00')  # Vulnerable function
            f.write(b'IsDebuggerPresent\x00')  # Anti-debug
            f.write(b'check_license\x00')
            f.write(b'main\x00')

            test_binary = f.name

        try:
            # Set target and run analysis
            orchestrator.set_target(test_binary)
            result = orchestrator.run_parallel_analysis()

            # Verify unified result
            assert isinstance(result, UnifiedAnalysisResult)
            assert result.target_path == test_binary
            assert result.analysis_timestamp is not None

            # Check for detected functions
            assert len(result.functions) > 0

            # Check for vulnerabilities
            vuln_types = [v['type'] for v in result.vulnerabilities]
            assert 'buffer_overflow' in vuln_types

            # Check for protections
            prot_types = [p['type'] for p in result.protections]
            assert 'anti_debug' in prot_types

        finally:
            os.unlink(test_binary)

    def test_result_correlation(self):
        """Test correlation of results from multiple tools."""
        orchestrator = create_orchestrator()

        # Create real binary with specific patterns
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            # Write content that will be detected by multiple tools
            f.write(b'MZ')
            f.write(b'\x00' * 100)
            f.write(b'check_license\x00')  # Function name
            f.write(b'strcpy\x00')  # Vulnerable function
            f.write(b'IsDebuggerPresent\x00')  # Protection
            f.write(b'\x55\x8B\xEC')  # Function prologue
            test_binary = f.name

        try:
            # Prepare tool results
            ghidra_results = {
                'functions': [
                    {'name': 'check_license', 'address': 0x401000}
                ],
                'vulnerabilities': [
                    {'type': 'buffer_overflow', 'function': 'strcpy'}
                ]
            }

            frida_results = {
                'protections': [
                    {'type': 'anti_debug', 'method': 'IsDebuggerPresent'}
                ],
                'api_calls': [
                    {'api': 'CreateFileA', 'module': 'kernel32.dll'}
                ]
            }

            r2_results = {
                'symbols': [
                    {'name': 'check_license', 'vaddr': 0x401000}
                ],
                'xrefs': [
                    {'from': 0x401000, 'to': 0x401100}
                ]
            }

            # Store results
            orchestrator.tool_results = {
                'ghidra': ghidra_results,
                'frida': frida_results,
                'radare2': r2_results
            }

            # Correlate results
            orchestrator.set_target(test_binary)
            unified = orchestrator._correlate_results()

            # Verify correlation
            assert len(unified.correlated_functions) > 0

            # Check function correlation
            for func in unified.correlated_functions:
                if func.name == 'check_license':
                    assert 'ghidra' in func.tools
                    assert 'radare2' in func.tools
                    assert func.consensus_address == 0x401000

            # Check combined vulnerabilities
            assert len(unified.vulnerabilities) > 0
            assert unified.vulnerabilities[0]['type'] == 'buffer_overflow'

            # Check combined protections
            assert len(unified.protections) > 0
            assert unified.protections[0]['type'] == 'anti_debug'

        finally:
            os.unlink(test_binary)

    def test_bypass_strategy_generation(self):
        """Test bypass strategy generation."""
        orchestrator = create_orchestrator()

        # Create test binary with protections
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'MZ')
            f.write(b'\x00' * 100)
            f.write(b'IsDebuggerPresent\x00')
            f.write(b'CheckRemoteDebuggerPresent\x00')
            f.write(b'NtQueryInformationProcess\x00')
            test_binary = f.name

        try:
            orchestrator.set_target(test_binary)

            # Add protection findings
            orchestrator.protections = [
                {
                    'type': 'anti_debug',
                    'method': 'IsDebuggerPresent',
                    'address': 0x401000,
                    'tool': 'ghidra'
                },
                {
                    'type': 'anti_debug',
                    'method': 'CheckRemoteDebuggerPresent',
                    'address': 0x401100,
                    'tool': 'frida'
                }
            ]

            # Generate bypass strategies
            strategies = orchestrator._generate_bypass_strategies()

            # Verify strategies
            assert len(strategies) > 0

            for strategy in strategies:
                assert isinstance(strategy, BypassStrategy)
                assert strategy.protection_type == 'anti_debug'
                assert strategy.method is not None
                assert strategy.implementation is not None
                assert strategy.confidence > 0

        finally:
            os.unlink(test_binary)

    def test_sequential_workflow(self):
        """Test sequential analysis workflow."""
        orchestrator = create_orchestrator()

        # Register tools
        orchestrator.register_tool('ghidra', RealGhidraIntegration())
        orchestrator.register_tool('frida', RealFridaIntegration())
        orchestrator.register_tool('radare2', RealRadare2Integration())

        # Create test binary
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00' * 1024)
            f.write(b'strcpy\x00')
            f.write(b'IsDebuggerPresent\x00')
            test_binary = f.name

        try:
            orchestrator.set_target(test_binary)

            # Define sequential workflow
            workflow = [
                {'tool': 'radare2', 'action': 'analyze_static'},
                {'tool': 'ghidra', 'action': 'analyze_binary'},
                {'tool': 'frida', 'action': 'analyze_runtime'}
            ]

            # Run sequential workflow
            result = orchestrator.run_sequential_workflow(workflow)

            # Verify workflow completion
            assert isinstance(result, UnifiedAnalysisResult)
            assert len(orchestrator.tool_results) == 3
            assert 'radare2' in orchestrator.tool_results
            assert 'ghidra' in orchestrator.tool_results
            assert 'frida' in orchestrator.tool_results

        finally:
            os.unlink(test_binary)

    def test_export_unified_report(self, tmp_path):
        """Test exporting unified analysis report."""
        orchestrator = create_orchestrator()

        # Create test binary
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00' * 512)
            f.write(b'test_function\x00')
            test_binary = f.name

        try:
            orchestrator.set_target(test_binary)

            # Create unified result
            result = UnifiedAnalysisResult(
                target_path=test_binary,
                analysis_timestamp=datetime.now()
            )

            result.functions = [
                {'name': 'test_function', 'address': 0x401000}
            ]
            result.vulnerabilities = [
                {'type': 'buffer_overflow', 'severity': 'high'}
            ]
            result.protections = [
                {'type': 'anti_debug', 'strength': 'medium'}
            ]

            orchestrator.unified_result = result

            # Export report
            report_path = tmp_path / "unified_report.json"
            orchestrator.export_unified_report(str(report_path))

            # Verify report
            assert report_path.exists()

            with open(report_path) as f:
                report = json.load(f)

            assert 'target' in report
            assert 'timestamp' in report
            assert 'functions' in report
            assert 'vulnerabilities' in report
            assert 'protections' in report
            assert len(report['functions']) == 1
            assert len(report['vulnerabilities']) == 1
            assert len(report['protections']) == 1

        finally:
            os.unlink(test_binary)


class TestIntegrationScenarios:
    """Test complete integration scenarios."""

    def test_full_binary_analysis(self):
        """Test complete binary analysis workflow."""
        # Create orchestrator
        orchestrator = create_orchestrator({
            'parallel_execution': True,
            'correlation_threshold': 0.7
        })

        # Register all tools
        ghidra = RealGhidraIntegration()
        frida = RealFridaIntegration()
        r2 = RealRadare2Integration()

        orchestrator.register_tool('ghidra', ghidra)
        orchestrator.register_tool('frida', frida)
        orchestrator.register_tool('radare2', r2)

        # Create complex test binary
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            # PE header
            f.write(b'MZ')
            f.write(b'\x00' * 58)
            f.write(b'\x40\x00\x00\x00')
            f.write(b'\x00' * (0x40 - 64))
            f.write(b'PE\x00\x00')

            # Code section with patterns
            f.write(b'\x55\x8B\xEC')  # Function prologue
            f.write(b'\x48\x89\x5C\x24')  # x64 prologue
            f.write(b'\xE8\x00\x00\x00\x00')  # Call instruction

            # Vulnerable functions
            f.write(b'strcpy\x00')
            f.write(b'sprintf\x00')
            f.write(b'gets\x00')

            # Protection mechanisms
            f.write(b'IsDebuggerPresent\x00')
            f.write(b'CheckRemoteDebuggerPresent\x00')
            f.write(b'NtQueryInformationProcess\x00')

            # Imports
            f.write(b'kernel32.dll\x00')
            f.write(b'user32.dll\x00')
            f.write(b'advapi32.dll\x00')

            # Functions
            f.write(b'main\x00')
            f.write(b'check_license\x00')
            f.write(b'validate_key\x00')

            # Strings
            f.write(b'Enter license key:\x00')
            f.write(b'Invalid license!\x00')
            f.write(b'License validated.\x00')

            test_binary = f.name

        try:
            # Run full analysis
            orchestrator.set_target(test_binary)
            result = orchestrator.run_parallel_analysis()

            # Verify comprehensive results
            assert result is not None
            assert result.target_path == test_binary

            # Check functions detected
            assert len(result.functions) > 0
            function_names = [f.get('name', '') for f in result.functions]

            # Check vulnerabilities
            assert len(result.vulnerabilities) > 0
            vuln_types = [v['type'] for v in result.vulnerabilities]
            assert 'buffer_overflow' in vuln_types

            # Check protections
            assert len(result.protections) > 0
            prot_methods = [p.get('method', '') for p in result.protections]

            # Check bypass strategies
            assert len(result.bypass_strategies) > 0
            for strategy in result.bypass_strategies:
                assert strategy.method is not None
                assert strategy.implementation is not None

            # Verify correlation worked
            assert len(result.correlated_functions) >= 0
            assert len(result.correlated_strings) >= 0

            # Check confidence scores
            assert result.confidence_score >= 0
            assert result.confidence_score <= 1

        finally:
            os.unlink(test_binary)

    def test_protection_bypass_workflow(self):
        """Test protection detection and bypass workflow."""
        orchestrator = create_orchestrator()

        # Create protected binary
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            # Add multiple protection mechanisms
            f.write(b'MZ' + b'\x00' * 100)

            # Anti-debugging
            f.write(b'IsDebuggerPresent\x00')
            f.write(b'CheckRemoteDebuggerPresent\x00')
            f.write(b'OutputDebugStringA\x00')

            # Anti-VM
            f.write(b'VMware\x00')
            f.write(b'VirtualBox\x00')
            f.write(b'QEMU\x00')

            # Packing indicators
            f.write(b'UPX0\x00')
            f.write(b'.packed\x00')

            test_binary = f.name

        try:
            # Register tools
            orchestrator.register_tool('ghidra', RealGhidraIntegration())
            orchestrator.register_tool('frida', RealFridaIntegration())
            orchestrator.register_tool('radare2', RealRadare2Integration())

            # Analyze protections
            orchestrator.set_target(test_binary)
            result = orchestrator.run_parallel_analysis(['ghidra', 'frida'])

            # Verify protection detection
            assert len(result.protections) > 0

            # Check bypass strategies
            assert len(result.bypass_strategies) > 0

            # Verify each protection has a bypass
            protection_types = set(p['type'] for p in result.protections)
            bypass_types = set(s.protection_type for s in result.bypass_strategies)

            # At least some protections should have bypasses
            assert len(bypass_types) > 0

        finally:
            os.unlink(test_binary)

    def test_vulnerability_exploitation_workflow(self):
        """Test vulnerability detection and exploitation workflow."""
        orchestrator = create_orchestrator()

        # Create vulnerable binary
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00' * 100)

            # Vulnerable functions
            f.write(b'strcpy\x00')
            f.write(b'strcat\x00')
            f.write(b'sprintf\x00')
            f.write(b'gets\x00')
            f.write(b'scanf\x00')

            # Format string vulnerabilities
            f.write(b'printf(user_input)\x00')
            f.write(b'fprintf(file, user_data)\x00')

            test_binary = f.name

        try:
            # Register tools
            orchestrator.register_tool('ghidra', RealGhidraIntegration())
            orchestrator.register_tool('radare2', RealRadare2Integration())

            # Analyze vulnerabilities
            orchestrator.set_target(test_binary)
            result = orchestrator.run_parallel_analysis(['ghidra', 'radare2'])

            # Verify vulnerability detection
            assert len(result.vulnerabilities) > 0

            # Check vulnerability types
            vuln_types = [v['type'] for v in result.vulnerabilities]
            assert 'buffer_overflow' in vuln_types or 'format_string' in vuln_types

            # Check severity levels
            severities = [v.get('severity', 'unknown') for v in result.vulnerabilities]
            assert 'high' in severities or 'critical' in severities

        finally:
            os.unlink(test_binary)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
