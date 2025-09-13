"""
Comprehensive test suite for CFI (Control Flow Integrity) bypass module.
Tests validate real-world exploitation capabilities against modern CFI protections.
"""

import pytest
import os
import struct
import tempfile
from pathlib import Path

from intellicrack.core.mitigation_bypass.cfi_bypass import CFIBypass


class TestCFIBypassCore:
    """Test core CFI bypass functionality and production readiness."""

    @pytest.fixture
    def cfi_bypass(self):
        """Create CFIBypass instance for testing."""
        return CFIBypass()

    @pytest.fixture
    def sample_pe_with_cfg(self):
        """Create a sample PE binary with CFG (Control Flow Guard) markers."""
        # PE header with CFG directory entry
        pe_header = bytearray(b'MZ' + b'\x00' * 58)  # DOS header
        pe_header += struct.pack('<I', 128)  # e_lfanew
        pe_header += b'\x00' * (128 - len(pe_header))

        # PE signature and headers
        pe_header += b'PE\x00\x00'
        pe_header += struct.pack('<H', 0x8664)  # Machine (x64)
        pe_header += struct.pack('<H', 5)  # NumberOfSections
        pe_header += b'\x00' * 12  # TimeDateStamp, PointerToSymbolTable, NumberOfSymbols
        pe_header += struct.pack('<H', 240)  # SizeOfOptionalHeader
        pe_header += struct.pack('<H', 0x2022)  # Characteristics (DLL, executable)

        # Optional header with CFG
        pe_header += struct.pack('<H', 0x20B)  # Magic (PE32+)
        pe_header += b'\x00' * 106  # Various fields
        pe_header += struct.pack('<I', 0x4000)  # DllCharacteristics with CFG

        # Add guard CF function table
        pe_header += b'\x00' * 512  # Padding for realistic structure
        pe_header += b'\xF4\xF4\xF4\xF4' * 16  # CFG check markers

        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(pe_header)
            return f.name

    @pytest.fixture
    def sample_elf_with_cet(self):
        """Create a sample ELF binary with Intel CET markers."""
        # ELF header
        elf_header = bytearray(b'\x7fELF')
        elf_header += b'\x02\x01\x01\x00'  # 64-bit, little endian, current version
        elf_header += b'\x00' * 8  # Padding
        elf_header += struct.pack('<H', 2)  # ET_EXEC
        elf_header += struct.pack('<H', 0x3E)  # EM_X86_64
        elf_header += struct.pack('<I', 1)  # Version

        # Program headers with CET properties
        elf_header += b'\x00' * 128
        # GNU_PROPERTY note for CET
        elf_header += b'GNU\x00'  # Note name
        elf_header += struct.pack('<I', 0xC0000002)  # CET IBT property
        elf_header += struct.pack('<I', 0xC0000003)  # CET SHSTK property

        # Add ENDBR64 instructions at function entries
        elf_header += b'\xF3\x0F\x1E\xFA' * 32  # ENDBR64 markers

        with tempfile.NamedTemporaryFile(suffix='.elf', delete=False) as f:
            f.write(elf_header)
            return f.name

    def test_analyze_cfi_protection_with_cfg(self, cfi_bypass, sample_pe_with_cfg):
        """Test detection of Windows Control Flow Guard protection."""
        result = cfi_bypass.analyze_cfi_protection(sample_pe_with_cfg)

        # Should detect CFG protection
        assert result is not None
        assert "success" in result or "technique" in result
        assert 'cfi_type' in result
        assert 'protected' in result
        assert result['protected'] is True

        # Should identify specific CFG features
        assert 'cfg_enabled' in result or 'control_flow_guard' in result
        assert 'indirect_calls_protected' in result
        assert 'bypass_difficulty' in result
        assert isinstance(result['bypass_difficulty'], (int, float))
        assert result['bypass_difficulty'] > 0

        # Should provide bypass recommendations
        assert 'bypass_techniques' in result
        assert isinstance(result['bypass_techniques'], list)
        assert len(result['bypass_techniques']) > 0

    def test_analyze_cfi_protection_with_cet(self, cfi_bypass, sample_elf_with_cet):
        """Test detection of Intel CET (Control-flow Enforcement Technology)."""
        result = cfi_bypass.analyze_cfi_protection(sample_elf_with_cet)

        assert result is not None
        assert "success" in result or "technique" in result
        assert result['protected'] is True

        # Should identify CET features
        assert 'cet_enabled' in result or 'intel_cet' in result
        assert 'shadow_stack' in result
        assert 'indirect_branch_tracking' in result

        # Should assess bypass difficulty
        assert result['bypass_difficulty'] >= 7  # CET is harder to bypass

    def test_analyze_unprotected_binary(self, cfi_bypass):
        """Test analysis of binary without CFI protection."""
        # Create minimal unprotected binary
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00' * 1024)
            unprotected_file = f.name

        result = cfi_bypass.analyze_cfi_protection(unprotected_file)

        assert result is not None
        assert "success" in result or "technique" in result
        assert result['protected'] is False
        assert result['bypass_difficulty'] == 0
        assert 'bypass_techniques' not in result or len(result['bypass_techniques']) == 0

    def test_generate_bypass_payload_for_cfg(self, cfi_bypass, sample_pe_with_cfg):
        """Test generation of CFG bypass payload."""
        # First analyze the protection
        analysis = cfi_bypass.analyze_cfi_protection(sample_pe_with_cfg)

        # Generate bypass payload
        payload = cfi_bypass.generate_bypass_payload(
            sample_pe_with_cfg,
            technique='vtable_hijack',
            target_address=0x140001000
        )

        assert payload is not None
        assert isinstance(payload, (bytes, bytearray))
        assert len(payload) > 0

        # Payload should contain valid x64 instructions
        # Check for common bypass patterns
        assert any([
            b'\x48\x89' in payload,  # MOV instructions
            b'\x48\x8B' in payload,  # MOV with memory operand
            b'\xFF\x25' in payload,  # JMP indirect
            b'\xFF\x15' in payload,  # CALL indirect
        ])

    def test_generate_bypass_payload_with_rop(self, cfi_bypass, sample_pe_with_cfg):
        """Test ROP-based CFI bypass payload generation."""
        payload = cfi_bypass.generate_bypass_payload(
            sample_pe_with_cfg,
            technique='rop_chain',
            target_address=0x140001000
        )

        assert payload is not None
        assert len(payload) >= 8  # At least one gadget address

        # Should be aligned properly for stack operations
        assert len(payload) % 8 == 0  # 64-bit alignment

    def test_find_rop_gadgets(self, cfi_bypass, sample_pe_with_cfg):
        """Test ROP gadget discovery for CFI bypass."""
        gadgets = cfi_bypass.find_rop_gadgets(sample_pe_with_cfg)

        assert isinstance(gadgets, list)
        assert len(gadgets) > 0

        for gadget in gadgets:
            assert 'address' in gadget
            assert 'instructions' in gadget
            assert 'bytes' in gadget
            assert isinstance(gadget['address'], int)
            assert isinstance(gadget['instructions'], str)
            assert isinstance(gadget['bytes'], (bytes, bytearray))

            # Gadgets should end with RET
            assert gadget['bytes'][-1] == 0xC3 or gadget['bytes'][-2:] == b'\xC2'

    def test_find_jop_gadgets(self, cfi_bypass, sample_pe_with_cfg):
        """Test JOP gadget discovery for indirect branch exploitation."""
        gadgets = cfi_bypass.find_jop_gadgets(sample_pe_with_cfg)

        assert isinstance(gadgets, list)

        for gadget in gadgets:
            assert 'address' in gadget
            assert 'instructions' in gadget
            assert 'type' in gadget
            assert gadget['type'] in ['jmp', 'call', 'indirect']

            # JOP gadgets should contain indirect jumps/calls
            assert any([
                b'\xFF\x25' in gadget.get('bytes', b''),  # JMP [mem]
                b'\xFF\xE0' in gadget.get('bytes', b''),  # JMP RAX
                b'\xFF\x15' in gadget.get('bytes', b''),  # CALL [mem]
                b'\xFF\xD0' in gadget.get('bytes', b''),  # CALL RAX
            ])

    def test_get_available_bypass_methods(self, cfi_bypass, sample_pe_with_cfg):
        """Test enumeration of available bypass methods."""
        # Analyze first
        cfi_bypass.analyze_cfi_protection(sample_pe_with_cfg)

        methods = cfi_bypass.get_available_bypass_methods()

        assert isinstance(methods, list)
        assert len(methods) > 0

        for method in methods:
            assert 'name' in method
            assert 'description' in method
            assert 'success_rate' in method
            assert 'complexity' in method
            assert method['success_rate'] >= 0 and method['success_rate'] <= 100
            assert method['complexity'] in ['low', 'medium', 'high', 'extreme']

    def test_vtable_hijacking_bypass(self, cfi_bypass):
        """Test VTable hijacking for C++ CFI bypass."""
        # Create a mock C++ binary with vtables
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            # Simulate vtable structure
            vtable_data = b'\x00' * 0x1000
            vtable_data += struct.pack('<Q', 0x140001000) * 16  # Function pointers
            f.write(b'MZ' + b'\x00' * 512 + vtable_data)
            cpp_binary = f.name

        result = cfi_bypass._vtable_hijacking(cpp_binary, 0x1000)

        assert result is not None
        assert "success" in result or "technique" in result
        assert 'fake_vtable' in result
        assert 'hijack_location' in result
        assert isinstance(result['fake_vtable'], (bytes, bytearray))

    def test_shadow_stack_bypass(self, cfi_bypass, sample_elf_with_cet):
        """Test shadow stack bypass techniques."""
        # Shadow stack bypass is complex and requires sophisticated techniques
        result = cfi_bypass._return_oriented_bypass(sample_elf_with_cet)

        assert result is not None
        assert "success" in result or "technique" in result
        assert 'bypass_chain' in result
        assert 'shadow_stack_pivot' in result

    def test_indirect_call_analysis(self, cfi_bypass, sample_pe_with_cfg):
        """Test analysis of indirect calls for bypass opportunities."""
        result = cfi_bypass._analyze_indirect_calls(sample_pe_with_cfg)

        assert isinstance(result, dict)
        assert 'total_indirect_calls' in result
        assert 'unprotected_calls' in result
        assert 'bypass_candidates' in result
        assert isinstance(result['bypass_candidates'], list)

    def test_indirect_branch_analysis(self, cfi_bypass, sample_pe_with_cfg):
        """Test analysis of indirect branches."""
        result = cfi_bypass._analyze_indirect_branches(sample_pe_with_cfg)

        assert isinstance(result, dict)
        assert 'indirect_jumps' in result
        assert 'indirect_calls' in result
        assert 'exploitable_branches' in result

    def test_cfi_marker_detection(self, cfi_bypass, sample_pe_with_cfg):
        """Test detection of CFI protection markers."""
        result = cfi_bypass._check_cfi_markers(sample_pe_with_cfg)

        assert isinstance(result, dict)
        assert 'has_cfi_markers' in result
        assert 'marker_types' in result
        assert isinstance(result['marker_types'], list)

    def test_bypass_target_discovery(self, cfi_bypass, sample_pe_with_cfg):
        """Test discovery of bypass targets."""
        targets = cfi_bypass._find_bypass_targets(sample_pe_with_cfg)

        assert isinstance(targets, list)
        for target in targets:
            assert 'address' in target
            assert 'type' in target
            assert 'confidence' in target
            assert target['confidence'] >= 0 and target['confidence'] <= 100

    def test_legitimate_target_finding(self, cfi_bypass, sample_pe_with_cfg):
        """Test finding legitimate CFI targets for bypass."""
        targets = cfi_bypass._find_legitimate_targets(sample_pe_with_cfg)

        assert isinstance(targets, list)
        for target in targets:
            assert 'address' in target
            assert 'function_name' in target or 'type' in target
            assert 'can_redirect' in target

    def test_function_start_detection(self, cfi_bypass, sample_pe_with_cfg):
        """Test detection of function entry points."""
        functions = cfi_bypass._find_function_starts(sample_pe_with_cfg)

        assert isinstance(functions, list)
        for func in functions:
            assert isinstance(func, int)  # Address
            assert func > 0

    def test_vtable_entry_detection(self, cfi_bypass):
        """Test detection of VTable entries in C++ binaries."""
        # Create mock C++ binary
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00' * 1024)
            cpp_file = f.name

        entries = cfi_bypass._find_vtable_entries(cpp_file)

        assert isinstance(entries, list)

    def test_function_pointer_detection(self, cfi_bypass, sample_pe_with_cfg):
        """Test detection of function pointers."""
        pointers = cfi_bypass._find_function_pointers(sample_pe_with_cfg)

        assert isinstance(pointers, list)
        for ptr in pointers:
            assert 'address' in ptr
            assert 'target' in ptr

    def test_exported_function_detection(self, cfi_bypass, sample_pe_with_cfg):
        """Test detection of exported functions."""
        exports = cfi_bypass._find_exported_functions(sample_pe_with_cfg)

        assert isinstance(exports, list)

    def test_gadget_usefulness_evaluation(self, cfi_bypass):
        """Test evaluation of gadget usefulness."""
        mock_gadget = {
            'address': 0x140001000,
            'instructions': 'pop rax; ret',
            'bytes': b'\x58\xC3'
        }

        score = cfi_bypass._evaluate_gadget_usefulness(mock_gadget)

        assert isinstance(score, (int, float))
        assert score >= 0 and score <= 100

    def test_jop_chain_building(self, cfi_bypass):
        """Test JOP chain construction."""
        gadgets = [
            {'address': 0x140001000, 'type': 'jmp', 'register': 'rax'},
            {'address': 0x140002000, 'type': 'jmp', 'register': 'rbx'},
        ]

        chain = cfi_bypass._build_jop_chain(gadgets, target=0x140003000)

        assert chain is not None
        assert isinstance(chain, (bytes, bytearray))

    def test_addressing_mode_decoding(self, cfi_bypass):
        """Test x86/x64 addressing mode decoding."""
        # ModRM byte for [RAX+8]
        mode = cfi_bypass._decode_addressing_mode(b'\x40\x08')

        assert mode is not None
        assert 'base' in mode
        assert 'displacement' in mode

    def test_branch_protection_checking(self, cfi_bypass):
        """Test checking of branch protection."""
        is_protected = cfi_bypass._check_branch_protection(0x140001000, sample_data=b'\xFF\x25\x00\x00\x00\x00')

        assert isinstance(is_protected, bool)

    def test_branch_payload_generation(self, cfi_bypass):
        """Test generation of branch exploitation payload."""
        payload = cfi_bypass._generate_branch_payload(
            source=0x140001000,
            target=0x140002000,
            method='indirect_jmp'
        )

        assert payload is not None
        assert isinstance(payload, (bytes, bytearray))

    def test_fake_vtable_generation(self, cfi_bypass):
        """Test generation of fake VTable for hijacking."""
        fake_vtable = cfi_bypass._generate_fake_vtable(
            original_vtable=struct.pack('<Q', 0x140001000) * 8,
            target_function=0x140002000,
            slot=3
        )

        assert fake_vtable is not None
        assert len(fake_vtable) >= 64  # At least 8 pointers
        # Check that target is at correct slot
        assert struct.unpack('<Q', fake_vtable[24:32])[0] == 0x140002000

    def test_rop_chain_building(self, cfi_bypass):
        """Test ROP chain construction."""
        gadgets = [
            {'address': 0x140001000, 'instructions': 'pop rax; ret'},
            {'address': 0x140002000, 'instructions': 'pop rdx; ret'},
        ]

        chain = cfi_bypass._build_rop_chain(gadgets, target=0x140003000)

        assert chain is not None
        assert isinstance(chain, (bytes, bytearray))
        assert len(chain) >= 16  # At least two addresses

    def test_bypass_difficulty_calculation(self, cfi_bypass):
        """Test calculation of bypass difficulty."""
        protection_info = {
            'cfg_enabled': True,
            'shadow_stack': False,
            'indirect_branch_tracking': True
        }

        difficulty = cfi_bypass._calculate_bypass_difficulty(protection_info)

        assert isinstance(difficulty, (int, float))
        assert difficulty >= 0 and difficulty <= 10

    def test_gadget_description(self, cfi_bypass):
        """Test gadget description generation."""
        gadget = {
            'address': 0x140001000,
            'bytes': b'\x58\x5B\xC3',
            'instructions': 'pop rax; pop rbx; ret'
        }

        description = cfi_bypass._describe_gadget(gadget)

        assert isinstance(description, str)
        assert '0x140001000' in description or '140001000' in description
        assert 'pop' in description.lower()

    def test_error_handling_invalid_file(self, cfi_bypass):
        """Test error handling for invalid files."""
        result = cfi_bypass.analyze_cfi_protection("nonexistent_file.exe")

        # Should handle gracefully
        assert result is not None
        assert "success" in result or "technique" in result
        assert 'error' in result or result['protected'] is False

    def test_error_handling_corrupt_binary(self, cfi_bypass):
        """Test error handling for corrupt binaries."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'\xFF' * 100)  # Invalid binary data
            corrupt_file = f.name

        result = cfi_bypass.analyze_cfi_protection(corrupt_file)

        # Should handle without crashing
        assert result is not None
        assert "success" in result or "technique" in result

    def test_payload_generation_without_analysis(self, cfi_bypass):
        """Test payload generation without prior analysis."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00' * 1024)
            test_file = f.name

        # Should either work or handle gracefully
        payload = cfi_bypass.generate_bypass_payload(
            test_file,
            technique='generic',
            target_address=0x140001000
        )

        # Should return something (even if empty for unprotected)
        assert payload is not None or payload == b''

    def test_multi_technique_bypass(self, cfi_bypass, sample_pe_with_cfg):
        """Test combining multiple bypass techniques."""
        # Analyze protection
        cfi_bypass.analyze_cfi_protection(sample_pe_with_cfg)

        # Try multiple techniques
        techniques = ['rop_chain', 'vtable_hijack', 'jop_chain']
        payloads = []

        for technique in techniques:
            payload = cfi_bypass.generate_bypass_payload(
                sample_pe_with_cfg,
                technique=technique,
                target_address=0x140001000
            )
            if payload:
                payloads.append(payload)

        # At least one technique should work
        assert len(payloads) > 0

    def test_cfi_bypass_with_aslr(self, cfi_bypass):
        """Test CFI bypass with ASLR consideration."""
        # Create binary with ASLR flags
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            pe_header = b'MZ' + b'\x00' * 58
            pe_header += struct.pack('<I', 128)
            pe_header += b'\x00' * (128 - len(pe_header))
            pe_header += b'PE\x00\x00'
            pe_header += struct.pack('<H', 0x8664)
            pe_header += b'\x00' * 18
            pe_header += struct.pack('<H', 0x20B)
            pe_header += b'\x00' * 106
            pe_header += struct.pack('<I', 0x4140)  # CFG + ASLR
            pe_header += b'\x00' * 512
            f.write(pe_header)
            aslr_file = f.name

        result = cfi_bypass.analyze_cfi_protection(aslr_file)

        assert result is not None
        assert "success" in result or "technique" in result
        # Should detect both CFG and ASLR
        assert result['protected'] is True
        assert result['bypass_difficulty'] >= 5  # Harder with ASLR

    def test_performance_large_binary(self, cfi_bypass):
        """Test performance with large binary files."""
        # Create a large binary (10MB)
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00' * (10 * 1024 * 1024))
            large_file = f.name

        import time
        start = time.time()
        result = cfi_bypass.analyze_cfi_protection(large_file)
        elapsed = time.time() - start

        assert result is not None
        assert "success" in result or "technique" in result
        assert elapsed < 10  # Should complete within 10 seconds

    def test_concurrent_analysis(self, cfi_bypass):
        """Test thread safety of CFI bypass operations."""
        import threading
        results = []

        def analyze_file():
            with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
                f.write(b'MZ' + b'\x00' * 1024)
                result = cfi_bypass.analyze_cfi_protection(f.name)
                results.append(result)

        threads = [threading.Thread(target=analyze_file) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 5
        assert all(r is not None for r in results)


class TestCFIBypassIntegration:
    """Integration tests for CFI bypass with other modules."""

    @pytest.fixture
    def cfi_bypass(self):
        """Create CFIBypass instance."""
        return CFIBypass()

    def test_integration_with_binary_analyzer(self, cfi_bypass):
        """Test integration with binary analysis module."""
        # This would test how CFI bypass works with binary analyzer
        # In production, this would use actual binary analyzer
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00' * 2048)
            test_file = f.name

        # Analyze and get gadgets
        cfi_bypass.analyze_cfi_protection(test_file)
        rop_gadgets = cfi_bypass.find_rop_gadgets(test_file)
        jop_gadgets = cfi_bypass.find_jop_gadgets(test_file)

        # Should provide data for other modules
        assert isinstance(rop_gadgets, list)
        assert isinstance(jop_gadgets, list)

    def test_real_world_cfg_bypass(self, cfi_bypass):
        """Test against realistic CFG-protected binary structure."""
        # Create more realistic PE with CFG
        pe_data = bytearray(b'MZ' + b'\x90' * 58)
        pe_data += struct.pack('<I', 128)
        pe_data += b'\x00' * (128 - len(pe_data))

        # PE header
        pe_data += b'PE\x00\x00'
        pe_data += struct.pack('<H', 0x8664)  # x64
        pe_data += struct.pack('<H', 5)  # sections
        pe_data += b'\x00' * 12
        pe_data += struct.pack('<H', 240)
        pe_data += struct.pack('<H', 0x2022)

        # Optional header
        pe_data += struct.pack('<H', 0x20B)
        pe_data += b'\x00' * 106
        pe_data += struct.pack('<I', 0x4000)  # CFG enabled

        # Add code section with indirect calls
        pe_data += b'\x00' * 512
        # Add indirect call patterns
        pe_data += b'\xFF\x15\x00\x00\x00\x00' * 10  # CALL [rip+0]
        pe_data += b'\xFF\x25\x00\x00\x00\x00' * 10  # JMP [rip+0]
        # Add potential gadgets
        pe_data += b'\x58\xC3' * 20  # pop rax; ret
        pe_data += b'\x5B\xC3' * 20  # pop rbx; ret

        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(pe_data)
            cfg_file = f.name

        # Full bypass workflow
        analysis = cfi_bypass.analyze_cfi_protection(cfg_file)
        assert analysis['protected'] is True

        methods = cfi_bypass.get_available_bypass_methods()
        assert len(methods) > 0

        # Generate bypass for each method
        for method in methods[:3]:  # Test first 3 methods
            payload = cfi_bypass.generate_bypass_payload(
                cfg_file,
                technique=method['name'],
                target_address=0x140001000
            )
            assert payload is not None or method.get('requires_analysis')

    def test_cet_shadow_stack_bypass(self, cfi_bypass):
        """Test Intel CET shadow stack bypass capabilities."""
        # Create ELF with CET markers
        elf_data = bytearray(b'\x7fELF')
        elf_data += b'\x02\x01\x01\x00' + b'\x00' * 8
        elf_data += struct.pack('<H', 2)
        elf_data += struct.pack('<H', 0x3E)
        elf_data += struct.pack('<I', 1)
        elf_data += b'\x00' * 128

        # Add CET note section
        elf_data += b'GNU\x00'
        elf_data += struct.pack('<I', 0xC0000002)  # IBT
        elf_data += struct.pack('<I', 0xC0000003)  # SHSTK

        # Add ENDBR64 instructions
        elf_data += b'\xF3\x0F\x1E\xFA' * 50

        # Add some ROP gadgets that would work with shadow stack
        elf_data += b'\x48\x89\xE0\xC3'  # mov rax, rsp; ret
        elf_data += b'\x48\x83\xC4\x08\xC3'  # add rsp, 8; ret

        with tempfile.NamedTemporaryFile(suffix='.elf', delete=False) as f:
            f.write(elf_data)
            cet_file = f.name

        analysis = cfi_bypass.analyze_cfi_protection(cet_file)
        assert analysis['protected'] is True
        assert 'shadow_stack' in analysis

        # Shadow stack bypass is complex
        payload = cfi_bypass.generate_bypass_payload(
            cet_file,
            technique='shadow_stack_pivot',
            target_address=0x400000
        )

        # May return None if bypass is too complex
        assert payload is None or isinstance(payload, (bytes, bytearray))


class TestCFIBypassEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.fixture
    def cfi_bypass(self):
        """Create CFIBypass instance."""
        return CFIBypass()

    def test_empty_file_handling(self, cfi_bypass):
        """Test handling of empty files."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            empty_file = f.name

        result = cfi_bypass.analyze_cfi_protection(empty_file)
        assert result is not None
        assert "success" in result or "technique" in result
        assert result['protected'] is False

    def test_text_file_handling(self, cfi_bypass):
        """Test handling of non-binary files."""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='w') as f:
            f.write("This is not a binary file\n")
            text_file = f.name

        result = cfi_bypass.analyze_cfi_protection(text_file)
        assert result is not None
        assert "success" in result or "technique" in result

    def test_permission_denied_handling(self, cfi_bypass):
        """Test handling of permission errors."""
        # Try to analyze a protected system file (may not have permission)
        result = cfi_bypass.analyze_cfi_protection("C:\\Windows\\System32\\kernel32.dll")
        # Should handle gracefully even if access denied
        assert result is not None
        assert "success" in result or "technique" in result

    def test_invalid_technique_handling(self, cfi_bypass):
        """Test handling of invalid bypass technique."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00' * 1024)
            test_file = f.name

        payload = cfi_bypass.generate_bypass_payload(
            test_file,
            technique='invalid_technique_xyz',
            target_address=0x140001000
        )

        # Should handle gracefully
        assert payload is None or payload == b''

    def test_null_bytes_in_payload(self, cfi_bypass):
        """Test handling of null bytes in generated payloads."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00' * 1024)
            test_file = f.name

        payload = cfi_bypass.generate_bypass_payload(
            test_file,
            technique='rop_chain',
            target_address=0x140001000,
            avoid_nulls=True
        )

        if payload and len(payload) > 0:
            # Should avoid null bytes if requested
            assert b'\x00' not in payload or payload == b''

    def test_extremely_small_binary(self, cfi_bypass):
        """Test with minimal valid PE."""
        # Smallest possible PE header
        mini_pe = b'MZ' + struct.pack('<I', 4) + b'PE\x00\x00'

        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(mini_pe)
            mini_file = f.name

        result = cfi_bypass.analyze_cfi_protection(mini_file)
        assert result is not None
        assert "success" in result or "technique" in result

    def test_mixed_architecture_handling(self, cfi_bypass):
        """Test handling of mixed 32/64-bit code."""
        # PE with mixed architecture indicators
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            pe = b'MZ' + b'\x00' * 58
            pe += struct.pack('<I', 64)
            pe += b'\x00' * (64 - len(pe))
            pe += b'PE\x00\x00'
            pe += struct.pack('<H', 0x014C)  # 32-bit machine type
            pe += b'\x00' * 18
            pe += struct.pack('<H', 0x20B)  # 64-bit optional header
            pe += b'\x00' * 512
            f.write(pe)
            mixed_file = f.name

        result = cfi_bypass.analyze_cfi_protection(mixed_file)
        assert result is not None
        assert "success" in result or "technique" in result

    def test_unicode_path_handling(self, cfi_bypass):
        """Test handling of Unicode paths."""
        unicode_dir = tempfile.mkdtemp(suffix='_测试_тест')
        unicode_file = os.path.join(unicode_dir, 'binary_文件.exe')

        with open(unicode_file, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 1024)

        result = cfi_bypass.analyze_cfi_protection(unicode_file)
        assert result is not None
        assert "success" in result or "technique" in result

    def test_network_path_handling(self, cfi_bypass):
        """Test handling of UNC paths."""
        # This would fail in most cases but should handle gracefully
        result = cfi_bypass.analyze_cfi_protection("\\\\server\\share\\file.exe")
        assert result is not None
        assert "success" in result or "technique" in result

    def test_symbolic_link_handling(self, cfi_bypass):
        """Test handling of symbolic links."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00' * 1024)
            real_file = f.name

        # Create symlink (if supported)
        link_file = real_file + '.link'
        try:
            os.symlink(real_file, link_file)
            result = cfi_bypass.analyze_cfi_protection(link_file)
            assert result is not None
            assert "success" in result or "technique" in result
        except (OSError, NotImplementedError):
            # Symlinks may not be supported
            pass
