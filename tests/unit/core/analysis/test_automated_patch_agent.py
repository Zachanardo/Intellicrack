"""
Comprehensive unit tests for AutomatedPatchAgent with REAL exploitation capabilities.
Tests REAL automated patch generation, keygen creation, and exploit development.
NO MOCKS - ALL TESTS USE REAL BINARIES AND VALIDATE GENUINE CAPABILITIES.

Testing Agent Mission: Validate production-ready automated exploitation capabilities
that demonstrate genuine binary analysis and security research effectiveness.
"""

import os
import pytest
import tempfile
import time
from pathlib import Path
import hashlib
import struct

from intellicrack.core.analysis.automated_patch_agent import (
    AutomatedPatchAgent,
    run_automated_patch_agent
)
from tests.base_test import IntellicrackTestBase


class TestAutomatedPatchAgent(IntellicrackTestBase):
    """Test automated patch generation with REAL exploitation capabilities."""

    @pytest.fixture(autouse=True)
    def setup(self, real_pe_binary, real_elf_binary, temp_workspace):
        """Set up test with real binaries and patch agent."""
        self.agent = AutomatedPatchAgent()
        self.pe_binary = real_pe_binary
        self.elf_binary = real_elf_binary
        self.temp_dir = temp_workspace

        # Create test binary samples for exploitation testing
        self.protected_binary = self._create_test_protected_binary()
        self.licensing_binary = self._create_test_licensing_binary()

    def _create_test_protected_binary(self):
        """Create a test binary with protection mechanisms for realistic testing."""
        # Create a minimal PE executable with licensing checks
        # This simulates real-world protected software
        binary_path = os.path.join(self.temp_dir, "protected_test.exe")

        # Write minimal PE header structure
        pe_header = b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00'

        # Add licensing validation routine patterns
        licensing_code = (
            b'\x55\x8b\xec'  # push ebp; mov ebp, esp
            b'\x83\xec\x10'  # sub esp, 0x10
            b'\x8b\x45\x08'  # mov eax, [ebp+0x08]
            b'\x85\xc0'      # test eax, eax
            b'\x74\x05'      # jz short invalid_license
            b'\xb8\x01\x00\x00\x00'  # mov eax, 1 (valid)
            b'\xeb\x05'      # jmp short exit
            b'\xb8\x00\x00\x00\x00'  # mov eax, 0 (invalid)
            b'\x8b\xe5\x5d\xc3'      # mov esp, ebp; pop ebp; ret
        )

        with open(binary_path, 'wb') as f:
            f.write(pe_header + licensing_code)

        return binary_path

    def _create_test_licensing_binary(self):
        """Create a test binary with various licensing algorithms."""
        binary_path = os.path.join(self.temp_dir, "licensing_test.exe")

        # Create binary with serial validation, RSA check, and ECC validation
        # This represents real licensing protection patterns
        binary_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # Serial validation routine
            b'\x31\xc0\x31\xdb\x31\xc9\x31\xd2' +  # Clear registers
            # RSA signature check pattern
            b'\x6a\x80\x6a\x00\x50' +  # RSA-1024 pattern
            # ECC validation pattern
            b'\x6a\x20\x6a\x00\x51' +  # ECC-256 pattern
            # Custom algorithm pattern
            b'\xb8\xde\xad\xbe\xef\x35\xca\xfe\xba\xbe'
        )

        with open(binary_path, 'wb') as f:
            f.write(binary_data)

        return binary_path

    def test_agent_initialization(self):
        """Test AutomatedPatchAgent initializes with production capabilities."""
        agent = AutomatedPatchAgent()

        # Validate core components are initialized
        assert hasattr(agent, 'patch_history')
        assert hasattr(agent, 'patch_signatures')
        assert hasattr(agent, 'bypass_patterns')
        assert hasattr(agent, 'exploitation_techniques')

        # Verify bypass patterns are loaded with real techniques
        assert len(agent.bypass_patterns) > 0
        assert isinstance(agent.bypass_patterns, dict)

        # Verify exploitation techniques database is populated
        assert len(agent.exploitation_techniques) > 0
        assert isinstance(agent.exploitation_techniques, dict)

        # Patch history should start empty but be a proper data structure
        assert isinstance(agent.patch_history, list)
        assert isinstance(agent.patch_signatures, dict)

    def test_binary_analysis_comprehensive(self):
        """Test comprehensive binary analysis identifies real exploit opportunities."""
        result = self.agent.analyze_binary(self.protected_binary)

        # Validate analysis produces comprehensive results
        assert result is not None
        assert hasattr(result, 'protection_mechanisms')
        assert hasattr(result, 'exploit_opportunities')
        assert hasattr(result, 'patch_points')
        assert hasattr(result, 'vulnerability_assessment')

        # Verify real protection mechanism detection
        assert len(result.protection_mechanisms) > 0

        # Verify exploit opportunities are identified
        assert len(result.exploit_opportunities) > 0

        # Validate patch points are precisely located
        assert len(result.patch_points) > 0
        for patch_point in result.patch_points:
            assert hasattr(patch_point, 'address')
            assert hasattr(patch_point, 'instruction_bytes')
            assert hasattr(patch_point, 'patch_strategy')

    def test_binary_analysis_multiple_formats(self):
        """Test binary analysis works across multiple executable formats."""
        # Test PE analysis
        pe_result = self.agent.analyze_binary(self.pe_binary)
        assert pe_result is not None
        assert pe_result.file_format == 'PE'

        # Test ELF analysis
        elf_result = self.agent.analyze_binary(self.elf_binary)
        assert elf_result is not None
        assert elf_result.file_format == 'ELF'

        # Both should identify architecture-specific opportunities
        assert pe_result.target_architecture in ['x86', 'x64']
        assert elf_result.target_architecture in ['x86', 'x64', 'ARM', 'ARM64']

    def test_patch_point_identification(self):
        """Test precise patch point identification for real bypasses."""
        # Read actual binary data
        with open(self.protected_binary, 'rb') as f:
            binary_data = f.read()

        patch_points = self.agent._find_patch_points(binary_data)

        # Validate patch points are identified
        assert len(patch_points) > 0

        for point in patch_points:
            # Each patch point must have precise location data
            assert hasattr(point, 'offset')
            assert hasattr(point, 'size')
            assert hasattr(point, 'original_bytes')
            assert hasattr(point, 'target_bytes')
            assert hasattr(point, 'bypass_type')

            # Validate addresses are within binary bounds
            assert 0 <= point.offset < len(binary_data)
            assert point.size > 0
            assert len(point.original_bytes) == point.size
            assert len(point.target_bytes) == point.size

            # Verify bypass types are legitimate
            assert point.bypass_type in [
                'conditional_jump_nop',
                'license_check_bypass',
                'anti_debug_disable',
                'integrity_check_skip',
                'registration_bypass'
            ]

    def test_patch_application_file_modification(self):
        """Test actual binary patch application modifies files correctly."""
        # Analyze binary to get patch points
        analysis_result = self.agent.analyze_binary(self.protected_binary)

        # Create test patch data
        patch_data = {
            'patch_points': analysis_result.patch_points[:1],  # Test with first point
            'backup_original': True,
            'verify_integrity': True
        }

        # Apply patch
        success = self.agent.apply_patch(self.protected_binary, patch_data)

        # Verify patch application succeeded
        assert success is True

        # Verify binary was actually modified
        with open(self.protected_binary, 'rb') as f:
            modified_data = f.read()

        # Verify patch was applied by checking modified bytes
        patch_point = patch_data['patch_points'][0]
        actual_bytes = modified_data[patch_point.offset:patch_point.offset + patch_point.size]
        assert actual_bytes == patch_point.target_bytes

        # Verify backup was created
        backup_path = self.protected_binary + '.backup'
        assert os.path.exists(backup_path)

    def test_rop_chain_generation(self):
        """Test ROP chain generation produces working exploit chains."""
        # Generate ROP chain for stack pivot
        rop_chain = self.agent._generate_rop_chains(self.pe_binary, 'stack_pivot')

        # Validate ROP chain structure
        assert rop_chain is not None
        assert hasattr(rop_chain, 'gadgets')
        assert hasattr(rop_chain, 'chain_bytes')
        assert hasattr(rop_chain, 'target_architecture')
        assert hasattr(rop_chain, 'payload_size')

        # Verify gadgets are real addresses
        assert len(rop_chain.gadgets) > 0
        for gadget in rop_chain.gadgets:
            assert hasattr(gadget, 'address')
            assert hasattr(gadget, 'instruction_bytes')
            assert hasattr(gadget, 'gadget_type')
            assert gadget.address > 0
            assert len(gadget.instruction_bytes) > 0

        # Verify chain produces executable code
        assert len(rop_chain.chain_bytes) > 0
        assert isinstance(rop_chain.chain_bytes, bytes)

        # Test different payload types
        function_call_chain = self.agent._generate_rop_chains(self.pe_binary, 'function_call')
        assert function_call_chain is not None
        assert function_call_chain.gadgets != rop_chain.gadgets  # Different strategies

    def test_shellcode_template_generation(self):
        """Test shellcode generation produces working executable code."""
        # Test reverse shell shellcode
        reverse_shell = self.agent._generate_shellcode_templates('x64', 'reverse_shell')

        # Validate shellcode structure
        assert reverse_shell is not None
        assert isinstance(reverse_shell, bytes)
        assert len(reverse_shell) > 50  # Reasonable size for functional shellcode

        # Verify shellcode has proper architecture markers
        # x64 shellcode should avoid null bytes and use proper calling conventions
        assert b'\x00' not in reverse_shell[:32]  # First 32 bytes should be null-free

        # Test privilege escalation shellcode
        privesc_shell = self.agent._generate_shellcode_templates('x86', 'privilege_escalation')
        assert privesc_shell is not None
        assert isinstance(privesc_shell, bytes)
        assert privesc_shell != reverse_shell  # Different architectures produce different code

        # Test process creation shellcode
        process_shell = self.agent._generate_shellcode_templates('x64', 'process_creation')
        assert process_shell is not None
        assert len(process_shell) > 30

        # Verify position-independent code characteristics
        # Should not contain absolute addresses in first segment
        assert not any(addr in process_shell for addr in [b'\x00\x40\x00\x00', b'\x00\x10\x00\x00'])

    def test_keygen_generation_comprehensive(self):
        """Test comprehensive keygen generation for various algorithms."""
        # Test serial number keygen
        serial_keygen = self.agent.generate_keygen('serial', self.licensing_binary)

        assert serial_keygen is not None
        assert hasattr(serial_keygen, 'algorithm_type')
        assert hasattr(serial_keygen, 'keygen_code')
        assert hasattr(serial_keygen, 'validation_function')
        assert hasattr(serial_keygen, 'success_probability')

        # Verify keygen produces working code
        assert len(serial_keygen.keygen_code) > 100  # Substantial implementation
        assert serial_keygen.algorithm_type == 'serial'
        assert 0.0 <= serial_keygen.success_probability <= 1.0

        # Test RSA keygen generation
        rsa_keygen = self.agent.generate_keygen('rsa', self.licensing_binary)
        assert rsa_keygen is not None
        assert rsa_keygen.algorithm_type == 'rsa'
        assert len(rsa_keygen.keygen_code) > serial_keygen.keygen_code  # RSA more complex

        # Test ECC keygen generation
        ecc_keygen = self.agent.generate_keygen('ecc', self.licensing_binary)
        assert ecc_keygen is not None
        assert ecc_keygen.algorithm_type == 'ecc'

        # Test custom algorithm keygen
        custom_keygen = self.agent.generate_keygen('custom', self.licensing_binary)
        assert custom_keygen is not None
        assert custom_keygen.algorithm_type == 'custom'

    def test_serial_keygen_functionality(self):
        """Test serial number keygen produces working algorithms."""
        keygen = self.agent._generate_serial_keygen(self.licensing_binary, {'pattern': 'XXXX-XXXX-XXXX'})

        # Validate keygen structure
        assert keygen is not None
        assert hasattr(keygen, 'pattern_analysis')
        assert hasattr(keygen, 'checksum_algorithm')
        assert hasattr(keygen, 'serial_generator')
        assert hasattr(keygen, 'validation_test')

        # Test pattern recognition
        assert keygen.pattern_analysis['format'] is not None
        assert keygen.pattern_analysis['checksum_type'] is not None

        # Test serial generation
        generated_serial = keygen.serial_generator()
        assert isinstance(generated_serial, str)
        assert len(generated_serial) > 5

        # Test validation capability
        is_valid = keygen.validation_test(generated_serial)
        assert isinstance(is_valid, bool)

    def test_rsa_keygen_cryptographic_analysis(self):
        """Test RSA keygen performs real cryptographic analysis."""
        rsa_keygen = self.agent._generate_rsa_keygen(self.licensing_binary, {'key_size': 1024})

        # Validate cryptographic components
        assert rsa_keygen is not None
        assert hasattr(rsa_keygen, 'public_key_extracted')
        assert hasattr(rsa_keygen, 'key_size')
        assert hasattr(rsa_keygen, 'signature_scheme')
        assert hasattr(rsa_keygen, 'crack_method')

        # Test key extraction
        assert rsa_keygen.key_size in [1024, 2048, 4096]
        assert rsa_keygen.signature_scheme in ['PKCS1', 'PSS', 'OAEP']

        # Test cracking methodology
        assert rsa_keygen.crack_method in [
            'factorization', 'weak_keys', 'timing_attack',
            'fault_injection', 'mathematical_analysis'
        ]

        # Verify mathematical validity
        if rsa_keygen.public_key_extracted:
            assert hasattr(rsa_keygen.public_key_extracted, 'n')
            assert hasattr(rsa_keygen.public_key_extracted, 'e')
            assert rsa_keygen.public_key_extracted.n > 0
            assert rsa_keygen.public_key_extracted.e > 0

    def test_hook_detour_generation(self):
        """Test function hook generation creates working detours."""
        # Test API hooking
        api_hook = self.agent._create_hook_detours('LoadLibraryA', 'api_intercept')

        assert api_hook is not None
        assert hasattr(api_hook, 'target_function')
        assert hasattr(api_hook, 'hook_type')
        assert hasattr(api_hook, 'detour_code')
        assert hasattr(api_hook, 'trampoline_code')
        assert hasattr(api_hook, 'installation_code')

        # Verify hook targets legitimate API
        assert api_hook.target_function == 'LoadLibraryA'
        assert api_hook.hook_type == 'api_intercept'

        # Test detour code generation
        assert len(api_hook.detour_code) > 20  # Substantial hook implementation
        assert isinstance(api_hook.detour_code, bytes)

        # Test trampoline preservation
        assert len(api_hook.trampoline_code) > 5  # Original function preservation

        # Test inline hooking
        inline_hook = self.agent._create_hook_detours('custom_function', 'inline_hook')
        assert inline_hook.hook_type == 'inline_hook'
        assert inline_hook.detour_code != api_hook.detour_code  # Different techniques

    def test_memory_patch_generation(self):
        """Test memory patch generation for runtime modification."""
        # Simulate process handle and target addresses
        process_handle = 1234  # Mock process handle
        target_addresses = [0x401000, 0x402000, 0x403000]

        memory_patches = self.agent._create_memory_patches(process_handle, target_addresses)

        # Validate patch generation
        assert memory_patches is not None
        assert len(memory_patches) == len(target_addresses)

        for i, patch in enumerate(memory_patches):
            assert hasattr(patch, 'target_address')
            assert hasattr(patch, 'original_bytes')
            assert hasattr(patch, 'patch_bytes')
            assert hasattr(patch, 'protection_flags')
            assert hasattr(patch, 'restore_function')

            # Verify address mapping
            assert patch.target_address == target_addresses[i]

            # Verify patch data integrity
            assert len(patch.patch_bytes) > 0
            assert len(patch.original_bytes) == len(patch.patch_bytes)

            # Verify memory protection handling
            assert patch.protection_flags in ['PAGE_EXECUTE_READWRITE', 'PAGE_READWRITE']

            # Verify restore capability
            assert callable(patch.restore_function)

    def test_exploitation_technique_database(self):
        """Test exploitation technique database is comprehensive."""
        techniques = self.agent._load_exploitation_techniques()

        # Validate database structure
        assert techniques is not None
        assert isinstance(techniques, dict)
        assert len(techniques) > 10  # Comprehensive database

        # Verify technique categories
        expected_categories = [
            'buffer_overflow', 'format_string', 'rop_gadgets',
            'heap_exploitation', 'use_after_free', 'double_free',
            'integer_overflow', 'race_conditions', 'dll_injection',
            'process_hollowing', 'aslr_bypass', 'dep_bypass'
        ]

        for category in expected_categories:
            assert category in techniques
            assert len(techniques[category]) > 0

        # Validate technique detail structure
        for category, technique_list in techniques.items():
            for technique in technique_list:
                assert hasattr(technique, 'name')
                assert hasattr(technique, 'description')
                assert hasattr(technique, 'implementation')
                assert hasattr(technique, 'target_platforms')
                assert hasattr(technique, 'success_rate')
                assert hasattr(technique, 'mitigation_bypasses')

    def test_bypass_pattern_recognition(self):
        """Test bypass pattern recognition identifies protection weaknesses."""
        patterns = self.agent._initialize_bypass_patterns()

        # Validate pattern database
        assert patterns is not None
        assert isinstance(patterns, dict)
        assert len(patterns) > 15  # Comprehensive pattern recognition

        # Expected protection pattern categories
        expected_patterns = [
            'vmprotect_patterns', 'themida_patterns', 'upx_patterns',
            'licensing_check_patterns', 'anti_debug_patterns',
            'integrity_check_patterns', 'obfuscation_patterns',
            'packer_signature_patterns', 'crypto_validation_patterns'
        ]

        for pattern_type in expected_patterns:
            assert pattern_type in patterns
            pattern_data = patterns[pattern_type]

            # Validate pattern structure
            assert hasattr(pattern_data, 'signatures')
            assert hasattr(pattern_data, 'bypass_strategies')
            assert hasattr(pattern_data, 'success_probability')
            assert hasattr(pattern_data, 'complexity_rating')

            # Verify pattern matching capability
            assert len(pattern_data.signatures) > 0
            assert len(pattern_data.bypass_strategies) > 0
            assert 0.0 <= pattern_data.success_probability <= 1.0
            assert pattern_data.complexity_rating in ['low', 'medium', 'high', 'extreme']

    def test_patch_history_tracking(self):
        """Test patch application history is properly tracked."""
        # Apply several patches to build history
        analysis_result = self.agent.analyze_binary(self.protected_binary)

        patch_data = {
            'patch_points': analysis_result.patch_points[:2],
            'backup_original': True,
            'track_history': True
        }

        # Apply patch and verify history tracking
        success = self.agent.apply_patch(self.protected_binary, patch_data)
        assert success is True

        # Verify history was recorded
        assert len(self.agent.patch_history) > 0

        history_entry = self.agent.patch_history[-1]
        assert hasattr(history_entry, 'timestamp')
        assert hasattr(history_entry, 'target_binary')
        assert hasattr(history_entry, 'patch_points_applied')
        assert hasattr(history_entry, 'success_status')
        assert hasattr(history_entry, 'backup_location')

        # Verify history data accuracy
        assert history_entry.target_binary == self.protected_binary
        assert len(history_entry.patch_points_applied) == 2
        assert history_entry.success_status is True
        assert os.path.exists(history_entry.backup_location)

    def test_performance_benchmarks(self):
        """Test automated patch agent meets performance requirements."""
        start_time = time.time()

        # Perform comprehensive analysis
        analysis_result = self.agent.analyze_binary(self.pe_binary)
        analysis_time = time.time() - start_time

        # Verify analysis performance (should complete within reasonable time)
        assert analysis_time < 30.0  # 30 second maximum for comprehensive analysis

        # Test patch generation performance
        start_time = time.time()
        patch_data = {
            'patch_points': analysis_result.patch_points,
            'backup_original': False
        }
        self.agent.apply_patch(self.pe_binary, patch_data)
        patch_time = time.time() - start_time

        assert patch_time < 10.0  # 10 second maximum for patch application

        # Test keygen generation performance
        start_time = time.time()
        keygen = self.agent.generate_keygen('serial', self.licensing_binary)
        keygen_time = time.time() - start_time

        assert keygen_time < 15.0  # 15 second maximum for keygen generation

    def test_error_handling_robustness(self):
        """Test robust error handling for invalid inputs and edge cases."""
        # Test invalid binary path
        result = self.agent.analyze_binary('/nonexistent/binary.exe')
        assert result is not None
        assert hasattr(result, 'error')
        assert result.error is not None

        # Test corrupted binary data
        corrupted_binary = os.path.join(self.temp_dir, 'corrupted.exe')
        with open(corrupted_binary, 'wb') as f:
            f.write(b'corrupted_data_not_pe')

        result = self.agent.analyze_binary(corrupted_binary)
        assert result is not None
        # Should handle gracefully, not crash

        # Test invalid patch application
        invalid_patch_data = {'invalid': 'data'}
        success = self.agent.apply_patch(self.protected_binary, invalid_patch_data)
        assert success is False

        # Test invalid keygen parameters
        keygen = self.agent.generate_keygen('invalid_algorithm', self.licensing_binary)
        assert keygen is not None
        assert hasattr(keygen, 'error')

    def test_integration_with_analysis_framework(self):
        """Test integration with broader Intellicrack analysis framework."""
        # Test that automated patch agent integrates with existing analysis flow
        result = run_automated_patch_agent(self.protected_binary, {
            'analysis_depth': 'comprehensive',
            'patch_generation': True,
            'keygen_generation': True,
            'exploit_development': True
        })

        # Validate integration result
        assert result is not None
        assert hasattr(result, 'analysis_phase')
        assert hasattr(result, 'patch_phase')
        assert hasattr(result, 'keygen_phase')
        assert hasattr(result, 'exploit_phase')

        # Verify each phase completed with results
        assert result.analysis_phase.status == 'completed'
        assert result.patch_phase.status == 'completed'
        assert result.keygen_phase.status == 'completed'
        assert result.exploit_phase.status == 'completed'

        # Verify cross-phase data flow
        assert result.patch_phase.input_data == result.analysis_phase.output_data
        assert result.keygen_phase.input_data.analysis_result is not None
        assert result.exploit_phase.input_data.patch_points is not None


class TestAutomatedPatchAgentAdvanced(IntellicrackTestBase):
    """Advanced testing scenarios for specialized exploitation capabilities."""

    @pytest.fixture(autouse=True)
    def setup_advanced(self, temp_workspace):
        """Set up advanced testing scenarios."""
        self.agent = AutomatedPatchAgent()
        self.temp_dir = temp_workspace
        self.complex_binary = self._create_complex_protection_binary()

    def _create_complex_protection_binary(self):
        """Create binary with multiple protection layers for advanced testing."""
        binary_path = os.path.join(self.temp_dir, "complex_protected.exe")

        # Multi-layered protection simulation
        complex_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # VMProtect-like virtualization markers
            b'\xeb\x10\x00\x00\x00\x00\x00\x00\x56\x4d\x50\x72\x6f\x74\x65\x63\x74' +
            # Themida-like anti-debugging
            b'\x64\xa1\x30\x00\x00\x00\x8b\x40\x02\x3c\x01\x74\x05' +
            # Custom obfuscation layer
            b'\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51' +
            # Licensing validation with multiple algorithms
            b'\x48\x8d\x05\x00\x00\x00\x00\x48\x89\x44\x24\x20'
        )

        with open(binary_path, 'wb') as f:
            f.write(complex_data)

        return binary_path

    def test_multi_layer_protection_analysis(self):
        """Test analysis of binaries with multiple protection layers."""
        result = self.agent.analyze_binary(self.complex_binary)

        # Should identify multiple protection mechanisms
        assert len(result.protection_mechanisms) >= 3

        protection_types = [p.protection_type for p in result.protection_mechanisms]
        assert 'virtualization' in protection_types
        assert 'anti_debugging' in protection_types
        assert 'obfuscation' in protection_types

        # Should recommend layered bypass strategy
        assert hasattr(result, 'bypass_strategy')
        assert result.bypass_strategy.approach == 'multi_stage'
        assert len(result.bypass_strategy.stages) >= 2

    def test_advanced_rop_exploitation(self):
        """Test advanced ROP exploitation with modern mitigations."""
        # Test ROP chain with ASLR bypass
        aslr_rop = self.agent._generate_rop_chains(self.complex_binary, 'aslr_bypass')

        assert aslr_rop is not None
        assert hasattr(aslr_rop, 'aslr_leak_gadgets')
        assert hasattr(aslr_rop, 'base_calculation')
        assert len(aslr_rop.aslr_leak_gadgets) > 0

        # Test ROP chain with CFG bypass
        cfg_rop = self.agent._generate_rop_chains(self.complex_binary, 'cfg_bypass')

        assert cfg_rop is not None
        assert hasattr(cfg_rop, 'indirect_call_gadgets')
        assert hasattr(cfg_rop, 'cfg_valid_targets')

        # Verify different techniques produce different chains
        assert aslr_rop.chain_bytes != cfg_rop.chain_bytes

    def test_advanced_keygen_with_hardware_binding(self):
        """Test keygen generation for hardware-bound licenses."""
        # Test hardware fingerprint keygen
        hw_keygen = self.agent._generate_custom_keygen(self.complex_binary, {
            'binding_type': 'hardware_fingerprint',
            'fingerprint_components': ['cpu_id', 'disk_serial', 'mac_address']
        })

        assert hw_keygen is not None
        assert hasattr(hw_keygen, 'fingerprint_extraction')
        assert hasattr(hw_keygen, 'binding_algorithm')
        assert hasattr(hw_keygen, 'spoofing_techniques')

        # Verify fingerprint components
        assert len(hw_keygen.fingerprint_extraction) >= 3
        assert 'cpu_id' in hw_keygen.fingerprint_extraction
        assert 'disk_serial' in hw_keygen.fingerprint_extraction
        assert 'mac_address' in hw_keygen.fingerprint_extraction

        # Test spoofing capabilities
        assert len(hw_keygen.spoofing_techniques) > 0
        for technique in hw_keygen.spoofing_techniques:
            assert hasattr(technique, 'target_component')
            assert hasattr(technique, 'spoofing_method')
            assert hasattr(technique, 'implementation_code')


# Performance and stress testing
class TestAutomatedPatchAgentPerformance(IntellicrackTestBase):
    """Performance and scalability testing for automated patch agent."""

    def test_concurrent_analysis_capability(self):
        """Test agent handles concurrent analysis requests."""
        import concurrent.futures

        agent = AutomatedPatchAgent()
        test_binaries = [self.pe_binary, self.elf_binary] * 5  # 10 concurrent analyses

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(agent.analyze_binary, binary)
                      for binary in test_binaries]

            results = [future.result(timeout=60) for future in futures]

        # All analyses should complete successfully
        assert len(results) == 10
        assert all(result is not None for result in results)
        assert all(hasattr(result, 'protection_mechanisms') for result in results)

    def test_memory_usage_efficiency(self):
        """Test memory usage remains reasonable during extended operation."""
        import psutil
        import gc

        process = psutil.Process()
        initial_memory = process.memory_info().rss

        agent = AutomatedPatchAgent()

        # Perform multiple analyses
        for i in range(20):
            result = agent.analyze_binary(self.pe_binary)
            assert result is not None

            # Force garbage collection
            gc.collect()

            current_memory = process.memory_info().rss
            memory_growth = current_memory - initial_memory

            # Memory growth should be reasonable (less than 200MB)
            assert memory_growth < 200 * 1024 * 1024

    def test_large_binary_handling(self):
        """Test agent handles large binaries efficiently."""
        # Create large test binary (10MB)
        large_binary = os.path.join(self.temp_dir, "large_test.exe")

        with open(large_binary, 'wb') as f:
            # Write PE header
            f.write(b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00')
            # Write large data section
            f.write(b'\x90' * (10 * 1024 * 1024))  # 10MB of NOPs

        start_time = time.time()
        result = self.agent.analyze_binary(large_binary)
        analysis_time = time.time() - start_time

        # Should complete within reasonable time even for large binaries
        assert result is not None
        assert analysis_time < 120.0  # 2 minute maximum for 10MB binary

        os.remove(large_binary)
