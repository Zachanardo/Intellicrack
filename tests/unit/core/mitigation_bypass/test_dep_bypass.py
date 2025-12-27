"""
Comprehensive black-box tests for DEP (Data Execution Prevention) bypass functionality.

This test suite validates REAL exploitation capabilities expected from a production-ready
DEP bypass module. Tests are designed to fail for placeholder/stub implementations.

Expected DEP Bypass Capabilities:
- Return-Oriented Programming (ROP) chain generation and validation
- Jump-Oriented Programming (JOP) technique implementation
- VirtualProtect/mprotect memory permission manipulation
- WriteProcessMemory/ReadProcessMemory exploitation techniques
- Code reuse gadget discovery and chaining
- Structured Exception Handler (SEH) exploitation
- NX bit manipulation and circumvention
- Import Address Table (IAT) analysis for dangerous functions
- Architecture-specific bypass techniques (x86, x64, ARM)
"""

import pytest
import struct
import os
import tempfile
from pathlib import Path

try:
    from intellicrack.core.mitigation_bypass.dep_bypass import DEPBypass
    MODULE_AVAILABLE = True
except ImportError:
    DEPBypass = None
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


class TestDEPBypassSpecificationDriven:
    """
    Specification-driven tests for DEP bypass functionality.
    These tests validate expected behavior without examining implementation.
    """

    @pytest.fixture
    def dep_bypass(self):
        """Initialize DEP bypass module."""
        return DEPBypass()

    @pytest.fixture
    def x86_binary_with_dep(self):
        """dict x86 binary with DEP enabled."""
        return {
            'path': 'C:\\test\\protected.exe',
            'architecture': 'x86',
            'dep_enabled': True,
            'aslr_enabled': False,
            'imports': ['kernel32.dll', 'ntdll.dll', 'user32.dll'],
            'sections': [
                {'name': '.text', 'flags': 'rx', 'size': 0x10000},
                {'name': '.data', 'flags': 'rw', 'size': 0x5000},
                {'name': '.rdata', 'flags': 'r', 'size': 0x3000}
            ],
            'entry_point': 0x401000,
            'image_base': 0x400000,
            'file_size': 0x20000
        }

    @pytest.fixture
    def x64_binary_with_dep_and_aslr(self):
        """dict x64 binary with DEP and ASLR enabled."""
        return {
            'path': 'C:\\test\\secure_app.exe',
            'architecture': 'x64',
            'dep_enabled': True,
            'aslr_enabled': True,
            'imports': ['kernel32.dll', 'ntdll.dll', 'msvcrt.dll', 'advapi32.dll'],
            'sections': [
                {'name': '.text', 'flags': 'rx', 'size': 0x20000},
                {'name': '.data', 'flags': 'rw', 'size': 0x8000},
                {'name': '.rdata', 'flags': 'r', 'size': 0x6000},
                {'name': '.pdata', 'flags': 'r', 'size': 0x2000}
            ],
            'entry_point': 0x140001000,
            'image_base': 0x140000000,
            'file_size': 0x40000,
            'has_seh': True,
            'has_cfi': True
        }

    @pytest.fixture
    def arm_binary_with_nx(self):
        """dict ARM binary with NX bit set."""
        return {
            'path': '/data/app/libprotected.so',
            'architecture': 'arm64',
            'dep_enabled': True,
            'nx_bit': True,
            'pie_enabled': True,
            'imports': ['libc.so', 'libm.so', 'libdl.so'],
            'sections': [
                {'name': '.text', 'flags': 'rx', 'size': 0x15000},
                {'name': '.rodata', 'flags': 'r', 'size': 0x4000},
                {'name': '.data', 'flags': 'rw', 'size': 0x6000},
                {'name': '.bss', 'flags': 'rw', 'size': 0x2000}
            ],
            'entry_point': 0x1000,
            'load_address': 0x0,
            'file_size': 0x25000
        }

    def test_initialization(self, dep_bypass):
        """Test DEP bypass module initialization."""
        assert dep_bypass is not None
        assert hasattr(dep_bypass, 'techniques')
        assert isinstance(dep_bypass.techniques, dict)

        # Verify essential DEP bypass techniques are registered
        expected_techniques = [
            'rop_chain',
            'jop_chain',
            'virtualprotect',
            'writeprocessmemory',
            'seh_exploitation',
            'ret2libc',
            'gadget_chaining',
            'code_reuse',
            'memory_permission_change'
        ]

        for technique in expected_techniques:
            assert technique in dep_bypass.techniques, \
                f"Essential DEP bypass technique '{technique}' not found"

    def test_analyze_x86_dep_bypass(self, dep_bypass, x86_binary_with_dep):
        """Test DEP bypass analysis for x86 binaries."""
        result = dep_bypass.analyze_dep_bypass(x86_binary_with_dep)

        # Validate result structure
        assert isinstance(result, dict)
        assert 'success' in result
        assert 'technique' in result
        assert 'confidence' in result
        assert 'gadgets' in result
        assert 'chain' in result
        assert 'exploit_code' in result

        # Validate analysis was successful
        assert result['success'] == True, "DEP bypass analysis should succeed for valid binary"

        # Validate recommended technique is appropriate for x86 DEP
        valid_x86_techniques = ['rop_chain', 'seh_exploitation', 'virtualprotect']
        assert result['technique'] in valid_x86_techniques, \
            f"Technique should be one of {valid_x86_techniques} for x86 DEP bypass"

        # Validate confidence score
        assert 0.0 <= result['confidence'] <= 1.0, "Confidence should be between 0 and 1"
        assert result['confidence'] >= 0.7, "Should have high confidence for straightforward x86 DEP"

        # Validate gadget discovery
        assert isinstance(result['gadgets'], list)
        assert len(result['gadgets']) > 0, "Should discover ROP gadgets in binary"

        # Validate each gadget has required properties
        for gadget in result['gadgets']:
            assert 'address' in gadget
            assert 'instructions' in gadget
            assert 'type' in gadget  # pop/ret, jmp, call, etc.
            assert isinstance(gadget['address'], int)
            assert gadget['address'] >= x86_binary_with_dep['image_base']

        # Validate ROP chain generation
        assert isinstance(result['chain'], list)
        assert len(result['chain']) > 0, "Should generate ROP chain"

        # Validate exploit code generation
        assert isinstance(result['exploit_code'], (bytes, str))
        assert len(result['exploit_code']) > 0, "Should generate exploit code"

    def test_analyze_x64_dep_with_aslr(self, dep_bypass, x64_binary_with_dep_and_aslr):
        """Test DEP bypass analysis for x64 binaries with ASLR."""
        result = dep_bypass.analyze_dep_bypass(x64_binary_with_dep_and_aslr)

        assert result['success'] == True

        # x64 with ASLR requires more sophisticated techniques
        valid_x64_techniques = ['rop_chain', 'jop_chain', 'virtualprotect', 'memory_permission_change']
        assert result['technique'] in valid_x64_techniques

        # Should handle ASLR consideration
        assert 'aslr_bypass_required' in result
        assert result['aslr_bypass_required'] == True

        # Should identify information leaks needed
        assert 'info_leak_required' in result
        assert result['info_leak_required'] == True

        # Validate x64-specific gadgets
        for gadget in result['gadgets']:
            # x64 gadgets should use 64-bit registers
            if 'instructions' in gadget:
                instructions = gadget['instructions']
                x64_regs = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
                # At least one x64 register should be present
                assert any(reg in str(instructions).lower() for reg in x64_regs), \
                    "x64 gadgets should use 64-bit registers"

    def test_analyze_arm_nx_bypass(self, dep_bypass, arm_binary_with_nx):
        """Test NX bypass analysis for ARM binaries."""
        result = dep_bypass.analyze_dep_bypass(arm_binary_with_nx)

        assert result['success'] == True

        # ARM-specific bypass techniques
        valid_arm_techniques = ['rop_chain', 'ret2libc', 'code_reuse', 'jop_chain']
        assert result['technique'] in valid_arm_techniques

        # ARM gadgets should be validated
        for gadget in result['gadgets']:
            assert 'thumb_mode' in gadget or 'arm_mode' in gadget
            # ARM addresses should be aligned
            if gadget.get('thumb_mode'):
                assert gadget['address'] % 2 == 0, "Thumb mode addresses should be 2-byte aligned"
            else:
                assert gadget['address'] % 4 == 0, "ARM mode addresses should be 4-byte aligned"

    def test_virtualprotect_technique(self, dep_bypass):
        """Test VirtualProtect memory permission change technique."""
        binary_info = {
            'path': 'C:\\test\\target.exe',
            'architecture': 'x86',
            'dep_enabled': True,
            'imports': ['kernel32.dll'],
            'imported_functions': {
                'kernel32.dll': ['VirtualProtect', 'VirtualAlloc', 'GetModuleHandleA']
            }
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should recognize VirtualProtect availability
        assert result['technique'] == 'virtualprotect'

        # Should generate chain to call VirtualProtect
        assert 'virtualprotect_chain' in result
        chain = result['virtualprotect_chain']

        # Chain should set up VirtualProtect parameters
        assert 'setup_lpAddress' in chain
        assert 'setup_dwSize' in chain
        assert 'setup_flNewProtect' in chain  # Should be PAGE_EXECUTE_READWRITE (0x40)
        assert 'setup_lpflOldProtect' in chain
        assert 'call_virtualprotect' in chain

    def test_writeprocessmemory_technique(self, dep_bypass):
        """Test WriteProcessMemory technique for DEP bypass."""
        binary_info = {
            'path': 'C:\\test\\vulnerable.exe',
            'architecture': 'x64',
            'dep_enabled': True,
            'imports': ['kernel32.dll', 'ntdll.dll'],
            'imported_functions': {
                'kernel32.dll': ['WriteProcessMemory', 'GetCurrentProcess', 'VirtualAllocEx'],
                'ntdll.dll': ['NtWriteVirtualMemory', 'NtProtectVirtualMemory']
            }
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should identify WriteProcessMemory capability
        assert 'writeprocessmemory_available' in result
        assert result['writeprocessmemory_available'] == True

        # Should generate appropriate exploitation strategy
        assert 'memory_write_chain' in result
        assert 'target_address' in result
        assert 'shellcode_size' in result

    def test_seh_exploitation_technique(self, dep_bypass):
        """Test SEH (Structured Exception Handler) exploitation for DEP bypass."""
        binary_info = {
            'path': 'C:\\test\\seh_vuln.exe',
            'architecture': 'x86',
            'dep_enabled': True,
            'seh_enabled': True,
            'safeseh_enabled': False,  # No SafeSEH makes it exploitable
            'imports': ['kernel32.dll', 'msvcrt.dll'],
            'seh_handlers': [
                {'address': 0x401500, 'module': 'main'},
                {'address': 0x7c901000, 'module': 'ntdll.dll'}
            ]
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should identify SEH exploitation opportunity
        assert result['technique'] == 'seh_exploitation'

        # Should generate SEH overwrite chain
        assert 'seh_chain' in result
        assert 'seh_overwrite_address' in result
        assert 'pop_pop_ret_gadget' in result

        # Validate pop-pop-ret gadget
        gadget = result['pop_pop_ret_gadget']
        assert gadget is not None
        assert 'address' in gadget
        assert 'instructions' in gadget
        # Should be pop-pop-ret sequence
        instructions = gadget['instructions'].lower()
        assert 'pop' in instructions and 'ret' in instructions

    def test_ret2libc_technique(self, dep_bypass):
        """Test return-to-libc technique for DEP bypass."""
        binary_info = {
            'path': '/usr/bin/vulnerable',
            'architecture': 'x86',
            'dep_enabled': True,
            'nx_bit': True,
            'imports': ['libc.so.6'],
            'imported_functions': {
                'libc.so.6': ['system', 'execve', 'mprotect', 'mmap']
            },
            'plt_entries': {
                'system': 0x8048430,
                'execve': 0x8048450,
                'mprotect': 0x8048470
            }
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should identify ret2libc opportunity
        assert 'ret2libc_possible' in result
        assert result['ret2libc_possible'] == True

        # Should generate ret2libc chain
        assert 'libc_chain' in result
        chain = result['libc_chain']

        # Chain should include libc function calls
        assert 'function_calls' in chain
        for call in chain['function_calls']:
            assert 'function' in call
            assert 'address' in call
            assert 'arguments' in call

    def test_gadget_quality_assessment(self, dep_bypass, x86_binary_with_dep):
        """Test gadget quality and usability assessment."""
        result = dep_bypass.analyze_dep_bypass(x86_binary_with_dep)

        # Should assess gadget quality
        assert 'gadget_quality' in result
        quality = result['gadget_quality']

        assert 'total_gadgets' in quality
        assert 'usable_gadgets' in quality
        assert 'quality_score' in quality

        # Should categorize gadgets by type
        assert 'gadget_types' in quality
        types = quality['gadget_types']

        expected_types = ['stack_pivot', 'register_control', 'memory_write', 'memory_read', 'arithmetic', 'control_flow']
        for gadget_type in expected_types:
            assert gadget_type in types, f"Should categorize {gadget_type} gadgets"

    def test_exploit_code_generation(self, dep_bypass, x86_binary_with_dep):
        """Test actual exploit code generation."""
        result = dep_bypass.analyze_dep_bypass(x86_binary_with_dep)

        exploit_code = result['exploit_code']

        # Should be valid binary exploit code or Python exploit script
        if isinstance(exploit_code, bytes):
            # Binary exploit
            assert len(exploit_code) > 100, "Exploit code should be substantial"
            # Should contain ROP chain addresses
            assert struct.pack('<I', x86_binary_with_dep['image_base']) in exploit_code or \
                   struct.pack('<I', x86_binary_with_dep['entry_point']) in exploit_code
        else:
            # Python exploit script
            assert 'struct.pack' in exploit_code, "Should use struct.pack for addresses"
            assert 'payload' in exploit_code.lower() or 'exploit' in exploit_code.lower()
            assert 'rop_chain' in exploit_code.lower() or 'gadget' in exploit_code.lower()

    def test_multi_technique_combination(self, dep_bypass):
        """Test combining multiple DEP bypass techniques."""
        binary_info = {
            'path': 'C:\\test\\complex.exe',
            'architecture': 'x64',
            'dep_enabled': True,
            'aslr_enabled': True,
            'cfi_enabled': True,
            'imports': ['kernel32.dll', 'ntdll.dll', 'msvcrt.dll'],
            'imported_functions': {
                'kernel32.dll': ['VirtualProtect', 'WriteProcessMemory'],
                'ntdll.dll': ['NtProtectVirtualMemory']
            }
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should identify need for technique combination
        assert 'combined_techniques' in result
        assert len(result['combined_techniques']) > 1

        # Should provide technique chaining order
        assert 'technique_order' in result
        order = result['technique_order']
        assert isinstance(order, list)
        assert len(order) >= 2, "Should chain multiple techniques"

    def test_failure_handling(self, dep_bypass):
        """Test handling of binaries where DEP bypass is not feasible."""
        binary_info = {
            'path': 'C:\\test\\hardened.exe',
            'architecture': 'x64',
            'dep_enabled': True,
            'aslr_enabled': True,
            'cfi_enabled': True,
            'cet_enabled': True,  # Intel CET makes ROP extremely difficult
            'acg_enabled': True,  # Arbitrary Code Guard
            'imports': [],  # No useful imports
            'sections': [
                {'name': '.text', 'flags': 'rx', 'size': 0x1000}  # Tiny binary
            ]
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should handle failure gracefully
        assert 'success' in result
        if not result['success']:
            assert 'failure_reason' in result
            assert 'mitigation_barriers' in result
            assert 'recommended_alternative' in result

    def test_performance_constraints(self, dep_bypass, x86_binary_with_dep):
        """Test that analysis completes within reasonable time."""
        import time

        start_time = time.time()
        result = dep_bypass.analyze_dep_bypass(x86_binary_with_dep)
        elapsed_time = time.time() - start_time

        # Analysis should complete within reasonable time (5 seconds for standard binary)
        assert elapsed_time < 5.0, f"Analysis took {elapsed_time}s, should complete within 5s"

        # Should still produce valid results
        assert result['success'] == True
        assert len(result['gadgets']) > 0

    def test_memory_safety(self, dep_bypass):
        """Test memory safety and resource management."""
        # Test with large binary
        large_binary = {
            'path': 'C:\\test\\large.exe',
            'architecture': 'x64',
            'dep_enabled': True,
            'file_size': 100 * 1024 * 1024,  # 100MB binary
            'sections': [
                {'name': '.text', 'flags': 'rx', 'size': 50 * 1024 * 1024},
                {'name': '.data', 'flags': 'rw', 'size': 30 * 1024 * 1024}
            ],
            'imports': ['kernel32.dll'] * 100  # Many imports
        }

        # Should handle large binaries without memory issues
        result = dep_bypass.analyze_dep_bypass(large_binary)
        assert 'memory_efficient' in result or result['success'] in [True, False]

    def test_cross_platform_compatibility(self, dep_bypass):
        """Test cross-platform DEP/NX bypass support."""
        platforms = [
            {'os': 'windows', 'arch': 'x86', 'dep_name': 'DEP'},
            {'os': 'windows', 'arch': 'x64', 'dep_name': 'DEP'},
            {'os': 'linux', 'arch': 'x86', 'dep_name': 'NX'},
            {'os': 'linux', 'arch': 'x64', 'dep_name': 'NX'},
            {'os': 'linux', 'arch': 'arm', 'dep_name': 'XN'},
            {'os': 'macos', 'arch': 'x64', 'dep_name': 'NX'},
            {'os': 'android', 'arch': 'arm64', 'dep_name': 'XN'}
        ]

        for platform in platforms:
            binary_info = {
                'path': f'/test/binary_{platform["os"]}_{platform["arch"]}',
                'os': platform['os'],
                'architecture': platform['arch'],
                'dep_enabled': True,
                'protection_name': platform['dep_name']
            }

            result = dep_bypass.analyze_dep_bypass(binary_info)
            assert 'platform_specific' in result or 'technique' in result, \
                f"Should handle {platform['os']} {platform['arch']} platform"


class TestDEPBypassIntegration:
    """Integration tests for DEP bypass with other components."""

    @pytest.fixture
    def dep_bypass(self):
        """Initialize DEP bypass module."""
        return DEPBypass()

    def test_integration_with_binary_analysis(self, dep_bypass):
        """Test integration with binary analysis components."""
        # This would integrate with actual binary analysis module

        analyzer = {
            "analyze": {
                'architecture': 'x86',
                'dep_enabled': True,
                'gadgets': [
                    {'address': 0x401000, 'instructions': 'pop eax; ret'},
                    {'address': 0x401005, 'instructions': 'pop ebx; pop ecx; ret'},
                ],
            }
        }
        binary_info = analyzer.analyze('test.exe')
        result = dep_bypass.analyze_dep_bypass(binary_info)

        assert result['success'] == True
        assert len(result['gadgets']) >= 2

    def test_integration_with_exploit_generation(self, dep_bypass):
        """Test integration with exploit generation framework."""
        binary_info = {
            'path': 'C:\\vulnerable.exe',
            'architecture': 'x86',
            'dep_enabled': True,
            'vulnerability': {
                'type': 'buffer_overflow',
                'offset': 256,
                'controllable_registers': ['eip', 'ebp']
            }
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should generate exploit tailored to vulnerability
        assert 'exploit_code' in result
        assert 'payload_offset' in result
        assert result['payload_offset'] == 256

    def test_integration_with_shellcode_encoder(self, dep_bypass):
        """Test integration with shellcode encoding for DEP bypass."""
        binary_info = {
            'path': 'C:\\target.exe',
            'architecture': 'x64',
            'dep_enabled': True,
            'bad_chars': [0x00, 0x0a, 0x0d],
            'available_space': 1024
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should consider bad characters and space constraints
        if 'encoded_payload' in result:
            payload = result['encoded_payload']
            assert isinstance(payload, bytes)
            # Should not contain bad characters
            for bad_char in [0x00, 0x0a, 0x0d]:
                assert bad_char not in payload
            # Should fit in available space
            assert len(payload) <= 1024


class TestDEPBypassEdgeCases:
    """Edge case and error handling tests."""

    @pytest.fixture
    def dep_bypass(self):
        """Initialize DEP bypass module."""
        return DEPBypass()

    def test_empty_binary_info(self, dep_bypass):
        """Test handling of empty binary info."""
        result = dep_bypass.analyze_dep_bypass({})
        assert 'success' in result
        assert 'error' in result or result['success'] == False

    def test_missing_architecture(self, dep_bypass):
        """Test handling of missing architecture info."""
        binary_info = {
            'path': 'C:\\test.exe',
            'dep_enabled': True
        }
        result = dep_bypass.analyze_dep_bypass(binary_info)
        assert 'success' in result
        # Should attempt to detect architecture or fail gracefully

    def test_unknown_architecture(self, dep_bypass):
        """Test handling of unknown architecture."""
        binary_info = {
            'path': 'C:\\test.exe',
            'architecture': 'mips',  # Less common architecture
            'dep_enabled': True
        }
        result = dep_bypass.analyze_dep_bypass(binary_info)
        assert 'success' in result
        # Should handle gracefully or provide basic support

    def test_corrupted_binary_info(self, dep_bypass):
        """Test handling of corrupted binary information."""
        binary_info = {
            'path': None,
            'architecture': 'x86',
            'dep_enabled': 'yes',  # Wrong type
            'sections': 'invalid'  # Wrong type
        }
        result = dep_bypass.analyze_dep_bypass(binary_info)
        assert 'success' in result
        # Should handle type errors gracefully

    def test_dep_disabled_binary(self, dep_bypass):
        """Test handling of binary with DEP disabled."""
        binary_info = {
            'path': 'C:\\test.exe',
            'architecture': 'x86',
            'dep_enabled': False
        }
        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should recognize DEP is disabled
        assert 'dep_bypass_needed' in result
        assert result['dep_bypass_needed'] == False
        # Should suggest direct code execution
        assert 'alternative_technique' in result
        assert result['alternative_technique'] == 'direct_execution'


class TestDEPBypassAdvancedTechniques:
    """Tests for advanced DEP bypass techniques."""

    @pytest.fixture
    def dep_bypass(self):
        """Initialize DEP bypass module."""
        return DEPBypass()

    def test_rop_chain_validation(self, dep_bypass):
        """Test ROP chain validation and optimization."""
        binary_info = {
            'path': 'C:\\test.exe',
            'architecture': 'x86',
            'dep_enabled': True,
            'gadgets': [
                {'address': 0x401000, 'instructions': 'pop eax; ret', 'bytes': b'\x58\xc3'},
                {'address': 0x401002, 'instructions': 'pop ebx; ret', 'bytes': b'\x5b\xc3'},
                {'address': 0x401004, 'instructions': 'xor eax, eax; ret', 'bytes': b'\x31\xc0\xc3'},
                {'address': 0x401007, 'instructions': 'add esp, 8; ret', 'bytes': b'\x83\xc4\x08\xc3'}
            ]
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should validate ROP chain
        assert 'chain_valid' in result
        assert result['chain_valid'] == True

        # Should optimize chain for size
        assert 'optimized_chain' in result
        assert len(result['optimized_chain']) <= len(result['chain'])

    def test_jop_chain_generation(self, dep_bypass):
        """Test JOP (Jump-Oriented Programming) chain generation."""
        binary_info = {
            'path': 'C:\\test.exe',
            'architecture': 'x64',
            'dep_enabled': True,
            'jop_gadgets': [
                {'address': 0x401000, 'instructions': 'jmp rax', 'register': 'rax'},
                {'address': 0x401010, 'instructions': 'jmp [rbx]', 'register': 'rbx'},
                {'address': 0x401020, 'instructions': 'call qword ptr [rcx]', 'register': 'rcx'}
            ]
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should generate JOP chain when ROP is difficult
        if 'jop_chain' in result:
            chain = result['jop_chain']
            assert isinstance(chain, list)
            assert len(chain) > 0
            # JOP chains use indirect jumps
            for gadget in chain:
                assert 'jmp' in str(gadget).lower() or 'call' in str(gadget).lower()

    def test_blind_rop_generation(self, dep_bypass):
        """Test BROP (Blind ROP) technique for remote exploitation."""
        binary_info = {
            'path': 'remote://192.168.1.100:8080/service',
            'architecture': 'x64',
            'dep_enabled': True,
            'remote_target': True,
            'crash_behavior': {
                'stop_gadget': 0x401234,
                'crash_gadget': 0x401000,
                'useful_gadget': 0x401100
            }
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should support blind ROP for remote targets
        assert result['success'] == True  # Demand success
        assert 'blind_rop' in result
        assert 'probe_gadgets' in result
        assert 'stop_gadget' in result

    def test_sigreturn_rop(self, dep_bypass):
        """Test SROP (Sigreturn-Oriented Programming) technique."""
        binary_info = {
            'path': '/usr/bin/vulnerable',
            'architecture': 'x64',
            'os': 'linux',
            'dep_enabled': True,
            'syscalls_available': ['rt_sigreturn', 'sigreturn'],
            'control_registers': ['rip', 'rsp', 'rax']
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should identify SROP opportunity on Linux
        if 'srop_possible' in result:
            assert result['srop_possible'] == True
            assert 'sigframe' in result
            frame = result['sigframe']
            # Sigframe should set up all registers
            assert 'rax' in frame
            assert 'rip' in frame
            assert 'rsp' in frame


class TestDEPBypassRealWorldScenarios:
    """Tests based on real-world DEP bypass scenarios."""

    @pytest.fixture
    def dep_bypass(self):
        """Initialize DEP bypass module."""
        return DEPBypass()

    def test_internet_explorer_dep_bypass(self, dep_bypass):
        """Test DEP bypass for browser exploitation scenario."""
        binary_info = {
            'path': 'C:\\Program Files\\Internet Explorer\\iexplore.exe',
            'architecture': 'x64',
            'dep_enabled': True,
            'aslr_enabled': True,
            'heap_spray_possible': True,
            'plugins': ['Flash.ocx', 'Java.dll'],
            'scripting_engine': 'jscript9.dll'
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should identify browser-specific techniques
        assert result['success'] == True  # Demand success
        assert 'heap_spray' in result or 'jit_spray' in result
        assert 'info_leak' in result  # Need info leak for ASLR

    def test_adobe_reader_dep_bypass(self, dep_bypass):
        """Test DEP bypass for PDF reader exploitation."""
        binary_info = {
            'path': 'C:\\Program Files\\Adobe\\Reader\\AcroRd32.exe',
            'architecture': 'x86',
            'dep_enabled': True,
            'javascript_enabled': True,
            'embedded_flash': True,
            'sandbox_enabled': False
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should leverage JavaScript for ROP chain construction
        assert result['success'] == True  # Demand success
        assert 'javascript_rop' in result or 'technique' in result

    def test_microsoft_office_dep_bypass(self, dep_bypass):
        """Test DEP bypass for Office application exploitation."""
        binary_info = {
            'path': 'C:\\Program Files\\Microsoft Office\\WINWORD.EXE',
            'architecture': 'x64',
            'dep_enabled': True,
            'vba_enabled': True,
            'activex_controls': True,
            'protected_view': False
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should identify Office-specific bypass techniques
        assert result['success'] == True  # Demand success
        assert result['technique'] in ['rop_chain', 'virtualprotect', 'vba_bypass']

    def test_service_dep_bypass(self, dep_bypass):
        """Test DEP bypass for Windows service exploitation."""
        binary_info = {
            'path': 'C:\\Windows\\System32\\spoolsv.exe',
            'architecture': 'x64',
            'dep_enabled': True,
            'service': True,
            'privilege_level': 'SYSTEM',
            'imports': ['kernel32.dll', 'ntdll.dll', 'advapi32.dll']
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        # Should handle high-privilege service context
        assert result['success'] == True  # Demand success
        assert 'privilege_considerations' in result
        assert result['technique'] in ['rop_chain', 'virtualprotect']


class TestDEPBypassMetrics:
    """Tests for DEP bypass metrics and reporting."""

    @pytest.fixture
    def dep_bypass(self):
        """Initialize DEP bypass module."""
        return DEPBypass()

    def test_bypass_success_rate(self, dep_bypass):
        """Test bypass success rate calculation."""
        test_binaries = [
            {'path': f'test{i}.exe', 'architecture': 'x86', 'dep_enabled': True}
            for i in range(10)
        ]

        results = []
        for binary in test_binaries:
            result = dep_bypass.analyze_dep_bypass(binary)
            results.append(result)

        # Calculate success rate
        successful = sum(bool(r.get('success', False))
                     for r in results)
        success_rate = successful / len(results)

        # Should have reasonable success rate for standard binaries
        assert success_rate >= 0.5, f"Success rate {success_rate} is too low"

    def test_gadget_discovery_metrics(self, dep_bypass):
        """Test gadget discovery and quality metrics."""
        binary_info = {
            'path': 'C:\\test.exe',
            'architecture': 'x86',
            'dep_enabled': True,
            'file_size': 1024 * 1024  # 1MB
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        if 'gadget_metrics' in result:
            metrics = result['gadget_metrics']
            assert 'total_gadgets' in metrics
            assert 'unique_gadgets' in metrics
            assert 'gadget_density' in metrics  # gadgets per KB
            assert 'quality_distribution' in metrics

    def test_performance_metrics(self, dep_bypass):
        """Test performance metrics collection."""
        binary_info = {
            'path': 'C:\\test.exe',
            'architecture': 'x64',
            'dep_enabled': True
        }

        result = dep_bypass.analyze_dep_bypass(binary_info)

        if 'performance_metrics' in result:
            metrics = result['performance_metrics']
            assert 'analysis_time' in metrics
            assert 'memory_usage' in metrics
            assert 'gadget_search_time' in metrics
            assert 'chain_generation_time' in metrics
