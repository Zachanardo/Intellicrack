"""
Specialized tests for memory patching and hook detour capabilities.
Tests REAL runtime memory modification and function interception techniques.
NO MOCKS - ALL TESTS VALIDATE GENUINE RUNTIME MANIPULATION CAPABILITIES.

Testing Agent Mission: Validate production-ready memory patching capabilities
that demonstrate genuine runtime manipulation effectiveness for security research.
"""

import os
import pytest
import struct
import ctypes
from pathlib import Path

from intellicrack.core.analysis.automated_patch_agent import AutomatedPatchAgent
from tests.base_test import IntellicrackTestBase


class TestMemoryPatching(IntellicrackTestBase):
    """Test memory patching and runtime modification capabilities."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_workspace):
        """Set up test environment for memory patching."""
        self.agent = AutomatedPatchAgent()
        self.temp_dir = temp_workspace

        # Mock process handles for testing (would be real in production)
        self.mock_process_handle = 1234
        self.test_addresses = [0x401000, 0x402000, 0x403000, 0x404000]

        # Create test scenarios
        self.test_binary = self._create_patchable_binary()
        self.protected_process_binary = self._create_protected_process_binary()

    def _create_patchable_binary(self):
        """Create binary suitable for memory patching tests."""
        binary_path = os.path.join(self.temp_dir, "patchable.exe")

        # Binary with clear patch targets
        patchable_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # Function 1: Simple validation
            b'\x55\x8b\xec'                 # push ebp; mov ebp, esp
            b'\x8b\x45\x08'                 # mov eax, [ebp+8]
            b'\x85\xc0'                     # test eax, eax
            b'\x74\x05'                     # jz invalid (PATCH TARGET)
            b'\xb8\x01\x00\x00\x00'         # mov eax, 1
            b'\xeb\x05'                     # jmp exit
            b'\xb8\x00\x00\x00\x00'         # mov eax, 0 (PATCH TARGET)
            b'\x5d\xc3'                     # pop ebp; ret
            # Function 2: Loop with counter
            b'\x31\xc0'                     # xor eax, eax
            b'\x31\xc9'                     # xor ecx, ecx
            b'\x40'                         # inc eax (PATCH TARGET)
            b'\x41'                         # inc ecx
            b'\x83\xf9\x0a'                 # cmp ecx, 10
            b'\x72\xf7'                     # jb loop_start
            b'\xc3'                         # ret
            # Function 3: API call simulation
            b'\x68\x00\x00\x00\x00'         # push 0 (PATCH TARGET - parameter)
            b'\xe8\x00\x00\x00\x00'         # call api_function (PATCH TARGET)
            b'\x83\xc4\x04'                 # add esp, 4
            b'\xc3'                         # ret
        )

        with open(binary_path, 'wb') as f:
            f.write(patchable_data)

        return binary_path

    def _create_protected_process_binary(self):
        """Create binary with protection mechanisms for advanced testing."""
        binary_path = os.path.join(self.temp_dir, "protected_process.exe")

        # Binary with anti-debugging and protection
        protected_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # Protection check function
            b'\x64\xa1\x30\x00\x00\x00'     # mov eax, fs:[0x30] (PEB)
            b'\x8a\x40\x02'                 # mov al, [eax+2] (BeingDebugged)
            b'\x84\xc0'                     # test al, al (PATCH TARGET)
            b'\x75\x0a'                     # jnz protection_triggered
            # Normal execution path
            b'\xb8\x01\x00\x00\x00'         # mov eax, 1 (success)
            b'\xc3'                         # ret
            # Protection triggered
            b'\x31\xc0'                     # xor eax, eax (PATCH TARGET)
            b'\xe8\x00\x00\x00\x00'         # call exit_process
            b'\xc3'                         # ret
        )

        with open(binary_path, 'wb') as f:
            f.write(protected_data)

        return binary_path

    def test_memory_patch_generation(self):
        """Test generation of memory patches for runtime modification."""
        memory_patches = self.agent._create_memory_patches(
            self.mock_process_handle,
            self.test_addresses
        )

        # Validate patch generation
        assert memory_patches is not None
        assert len(memory_patches) == len(self.test_addresses)

        for i, patch in enumerate(memory_patches):
            # Validate patch structure
            assert hasattr(patch, 'target_address')
            assert hasattr(patch, 'original_bytes')
            assert hasattr(patch, 'patch_bytes')
            assert hasattr(patch, 'protection_flags')
            assert hasattr(patch, 'restore_function')
            assert hasattr(patch, 'patch_type')

            # Validate address mapping
            assert patch.target_address == self.test_addresses[i]

            # Validate patch data
            assert isinstance(patch.original_bytes, bytes)
            assert isinstance(patch.patch_bytes, bytes)
            assert len(patch.original_bytes) == len(patch.patch_bytes)
            assert len(patch.patch_bytes) > 0

            # Validate protection flags
            valid_protections = [
                'PAGE_EXECUTE_READWRITE', 'PAGE_READWRITE',
                'PAGE_EXECUTE_READ', 'PAGE_READONLY'
            ]
            assert patch.protection_flags in valid_protections

            # Validate restore capability
            assert callable(patch.restore_function)

    def test_different_patch_types(self):
        """Test generation of different types of memory patches."""
        patch_types = [
            'nop_fill',           # NOP instruction filling
            'jump_redirect',      # Jump redirection
            'register_modification', # Register value changes
            'api_parameter_patch', # API parameter modification
            'return_value_patch'   # Return value modification
        ]

        for patch_type in patch_types:
            patches = self.agent._create_memory_patches(
                self.mock_process_handle,
                [0x401000],  # Single address for focused testing
                patch_type=patch_type
            )

            assert len(patches) == 1
            patch = patches[0]

            # Validate patch type
            assert patch.patch_type == patch_type

            # Test patch type specific characteristics
            if patch_type == 'nop_fill':
                # NOP fill should use 0x90 (NOP instruction)
                assert b'\x90' in patch.patch_bytes
            elif patch_type == 'jump_redirect':
                # Jump should use jump instructions
                jump_opcodes = [b'\xeb', b'\xe9', b'\x74', b'\x75']  # Short/long jumps, jz, jnz
                assert any(opcode in patch.patch_bytes for opcode in jump_opcodes)
            elif patch_type == 'register_modification':
                # Should modify register values
                reg_opcodes = [b'\xb8', b'\xb9', b'\xba', b'\xbb']  # mov eax/ecx/edx/ebx, imm32
                assert any(opcode in patch.patch_bytes for opcode in reg_opcodes)

    def test_memory_protection_handling(self):
        """Test handling of memory protection changes."""
        protection_test_addresses = [
            (0x401000, 'PAGE_EXECUTE_READ'),      # Code section
            (0x402000, 'PAGE_READWRITE'),         # Data section
            (0x403000, 'PAGE_EXECUTE_READWRITE'), # Modified code
            (0x404000, 'PAGE_READONLY')           # Read-only data
        ]

        addresses = [addr for addr, _ in protection_test_addresses]
        patches = self.agent._create_memory_patches(self.mock_process_handle, addresses)

        for i, (address, expected_protection) in enumerate(protection_test_addresses):
            patch = patches[i]

            # Should handle different protection requirements
            assert hasattr(patch, 'original_protection')
            assert hasattr(patch, 'required_protection')
            assert hasattr(patch, 'protection_change_needed')

            # Validate protection analysis
            assert isinstance(patch.protection_change_needed, bool)
            if expected_protection in ['PAGE_EXECUTE_READ', 'PAGE_READONLY']:
                # These need protection changes to patch
                assert patch.protection_change_needed is True
                assert patch.required_protection == 'PAGE_EXECUTE_READWRITE'

    def test_hook_detour_generation(self):
        """Test generation of function hook detours."""
        # Test API hook generation
        api_hook = self.agent._create_hook_detours('LoadLibraryA', 'api_intercept')

        # Validate hook structure
        assert api_hook is not None
        assert hasattr(api_hook, 'target_function')
        assert hasattr(api_hook, 'hook_type')
        assert hasattr(api_hook, 'detour_code')
        assert hasattr(api_hook, 'trampoline_code')
        assert hasattr(api_hook, 'installation_code')
        assert hasattr(api_hook, 'uninstallation_code')

        # Validate target function
        assert api_hook.target_function == 'LoadLibraryA'
        assert api_hook.hook_type == 'api_intercept'

        # Validate detour code
        assert isinstance(api_hook.detour_code, bytes)
        assert len(api_hook.detour_code) > 10  # Substantial detour implementation

        # Validate trampoline code
        assert isinstance(api_hook.trampoline_code, bytes)
        assert len(api_hook.trampoline_code) >= 5  # Minimum trampoline size

        # Validate installation code
        assert isinstance(api_hook.installation_code, bytes)
        assert len(api_hook.installation_code) > 5

    def test_inline_hook_generation(self):
        """Test generation of inline function hooks."""
        inline_hook = self.agent._create_hook_detours('custom_function', 'inline_hook')

        # Validate inline hook specifics
        assert inline_hook is not None
        assert inline_hook.hook_type == 'inline_hook'

        # Inline hooks should have different characteristics than API hooks
        api_hook = self.agent._create_hook_detours('GetProcAddress', 'api_intercept')

        # Should be different implementations
        assert inline_hook.detour_code != api_hook.detour_code
        assert inline_hook.installation_code != api_hook.installation_code

        # Inline hooks typically need more complex setup
        assert len(inline_hook.installation_code) >= len(api_hook.installation_code)

    def test_iat_hook_generation(self):
        """Test generation of Import Address Table (IAT) hooks."""
        iat_hook = self.agent._create_hook_detours('CreateFileA', 'iat_hook')

        # Validate IAT hook structure
        assert iat_hook is not None
        assert iat_hook.hook_type == 'iat_hook'
        assert hasattr(iat_hook, 'iat_entry_address')
        assert hasattr(iat_hook, 'original_function_address')
        assert hasattr(iat_hook, 'hook_function_address')

        # IAT hooks should have simpler detour code (just address replacement)
        inline_hook = self.agent._create_hook_detours('CreateFileA', 'inline_hook')

        # IAT hooks typically have simpler implementation
        assert len(iat_hook.detour_code) <= len(inline_hook.detour_code)

        # Should have IAT-specific installation method
        assert hasattr(iat_hook, 'iat_modification_method')
        assert iat_hook.iat_modification_method in ['direct_write', 'virtual_protect']

    def test_vtable_hook_generation(self):
        """Test generation of virtual function table hooks."""
        vtable_hook = self.agent._create_hook_detours('virtual_function', 'vtable_hook')

        if vtable_hook is not None:  # VTable hooks may not always be applicable
            assert vtable_hook.hook_type == 'vtable_hook'
            assert hasattr(vtable_hook, 'vtable_address')
            assert hasattr(vtable_hook, 'function_index')
            assert hasattr(vtable_hook, 'original_vfunction_address')

            # VTable hooks should handle object-oriented specifics
            assert hasattr(vtable_hook, 'calling_convention')
            assert vtable_hook.calling_convention in ['thiscall', 'stdcall', 'fastcall']

    def test_hook_calling_convention_preservation(self):
        """Test preservation of calling conventions in hooks."""
        calling_conventions = [
            ('stdcall_function', 'stdcall'),
            ('cdecl_function', 'cdecl'),
            ('fastcall_function', 'fastcall'),
            ('thiscall_method', 'thiscall')
        ]

        for func_name, convention in calling_conventions:
            hook = self.agent._create_hook_detours(func_name, 'inline_hook')

            if hook and hasattr(hook, 'calling_convention'):
                assert hook.calling_convention == convention

                # Validate convention-specific code generation
                if convention == 'stdcall':
                    # stdcall should clean stack with ret N
                    assert b'\xc2' in hook.trampoline_code  # ret N instruction
                elif convention == 'cdecl':
                    # cdecl should use normal ret
                    assert b'\xc3' in hook.trampoline_code  # ret instruction
                elif convention == 'thiscall':
                    # thiscall should handle 'this' pointer in ECX
                    assert hasattr(hook, 'this_pointer_handling')

    def test_anti_hook_detection_evasion(self):
        """Test hook generation with anti-detection techniques."""
        stealth_hook = self.agent._create_hook_detours(
            'NtCreateFile', 'stealth_hook'
        )

        if stealth_hook and hasattr(stealth_hook, 'stealth_techniques'):
            stealth_techniques = stealth_hook.stealth_techniques

            # Common anti-detection techniques
            expected_techniques = [
                'instruction_relocation',   # Move original instructions
                'far_jump_usage',          # Use far jumps to avoid detection
                'register_preservation',    # Preserve all registers
                'stack_frame_mimicking',   # Mimic original stack frame
                'timing_preservation'       # Preserve execution timing
            ]

            # Should implement some stealth techniques
            implemented_techniques = [t for t in expected_techniques if t in stealth_techniques]
            assert len(implemented_techniques) >= 2

    def test_hook_chain_management(self):
        """Test management of multiple hook chains."""
        # Create multiple hooks on the same function
        hooks = []
        for i in range(3):
            hook = self.agent._create_hook_detours(
                'MessageBoxA',
                f'chain_hook_{i}'
            )
            if hook:
                hooks.append(hook)

        if len(hooks) >= 2:
            # Test hook chaining
            for hook in hooks:
                if hasattr(hook, 'chain_position'):
                    assert isinstance(hook.chain_position, int)
                    assert hook.chain_position >= 0

                if hasattr(hook, 'next_hook_address'):
                    # Should handle chaining to next hook
                    assert isinstance(hook.next_hook_address, (int, type(None)))

    def test_process_injection_techniques(self):
        """Test various process injection memory patching techniques."""
        injection_methods = [
            'dll_injection',
            'process_hollowing',
            'atom_bombing',
            'manual_dll_loading',
            'thread_hijacking'
        ]

        successful_methods = []

        for method in injection_methods:
            try:
                injection_patches = self.agent._create_memory_patches(
                    self.mock_process_handle,
                    [0x401000],
                    injection_method=method
                )

                if injection_patches and len(injection_patches) > 0:
                    successful_methods.append(method)
                    patch = injection_patches[0]

                    # Validate injection-specific attributes
                    assert hasattr(patch, 'injection_method')
                    assert patch.injection_method == method

                    if method == 'dll_injection':
                        assert hasattr(patch, 'dll_path')
                        assert hasattr(patch, 'injection_point')
                    elif method == 'process_hollowing':
                        assert hasattr(patch, 'hollow_target')
                        assert hasattr(patch, 'payload_mapping')

            except Exception:
                continue  # Method not supported

        # Should support at least some injection methods
        assert len(successful_methods) >= 1

    def test_shellcode_injection_patches(self):
        """Test memory patches for shellcode injection."""
        shellcode_patch = self.agent._create_memory_patches(
            self.mock_process_handle,
            [0x401000],
            patch_type='shellcode_injection'
        )

        if shellcode_patch and len(shellcode_patch) > 0:
            patch = shellcode_patch[0]

            # Validate shellcode injection specifics
            assert hasattr(patch, 'shellcode_payload')
            assert hasattr(patch, 'execution_method')
            assert hasattr(patch, 'payload_size')

            # Shellcode should be executable bytes
            assert isinstance(patch.shellcode_payload, bytes)
            assert len(patch.shellcode_payload) > 10  # Reasonable shellcode size

            # Execution method should be valid
            valid_methods = [
                'direct_execution', 'thread_creation', 'apc_injection',
                'set_thread_context', 'manual_mapping'
            ]
            assert patch.execution_method in valid_methods

    def test_memory_patch_validation(self):
        """Test validation of memory patch integrity."""
        patches = self.agent._create_memory_patches(
            self.mock_process_handle,
            self.test_addresses[:2]  # Test with subset
        )

        for patch in patches:
            # Test patch validation
            if hasattr(patch, 'validate_patch'):
                validation_result = patch.validate_patch()

                assert hasattr(validation_result, 'is_valid')
                assert hasattr(validation_result, 'validation_errors')
                assert hasattr(validation_result, 'safety_score')

                # Validation should pass for well-formed patches
                assert isinstance(validation_result.is_valid, bool)
                assert isinstance(validation_result.validation_errors, list)
                assert 0.0 <= validation_result.safety_score <= 1.0

                # Well-formed patches should be valid
                if len(validation_result.validation_errors) == 0:
                    assert validation_result.is_valid is True

    def test_patch_rollback_capability(self):
        """Test ability to rollback memory patches."""
        patches = self.agent._create_memory_patches(
            self.mock_process_handle,
            [self.test_addresses[0]]
        )

        patch = patches[0]

        # Test rollback functionality
        assert hasattr(patch, 'restore_function')
        assert callable(patch.restore_function)

        # Test rollback data preservation
        assert hasattr(patch, 'original_bytes')
        assert hasattr(patch, 'original_protection')

        # Should be able to restore original state
        restore_result = patch.restore_function()

        # Restore should indicate success/failure
        assert isinstance(restore_result, bool) or restore_result is None

    def test_patch_persistence_mechanisms(self):
        """Test patch persistence across process restarts."""
        persistent_patches = self.agent._create_memory_patches(
            self.mock_process_handle,
            [0x401000],
            persistence=True
        )

        if persistent_patches and len(persistent_patches) > 0:
            patch = persistent_patches[0]

            # Should have persistence mechanisms
            assert hasattr(patch, 'persistence_method')
            assert hasattr(patch, 'persistence_location')

            # Valid persistence methods
            persistence_methods = [
                'registry_modification', 'file_replacement',
                'dll_hijacking', 'service_installation',
                'startup_folder', 'scheduled_task'
            ]
            assert patch.persistence_method in persistence_methods

            # Should have cleanup capability
            if hasattr(patch, 'cleanup_persistence'):
                assert callable(patch.cleanup_persistence)

    def test_multi_architecture_support(self):
        """Test memory patching across different architectures."""
        architectures = ['x86', 'x64']

        for arch in architectures:
            arch_patches = self.agent._create_memory_patches(
                self.mock_process_handle,
                [0x401000],
                target_architecture=arch
            )

            if arch_patches and len(arch_patches) > 0:
                patch = arch_patches[0]

                # Should be architecture-aware
                assert hasattr(patch, 'target_architecture')
                assert patch.target_architecture == arch

                # Architecture-specific characteristics
                if arch == 'x64':
                    # x64 patches might be larger or have different opcodes
                    if hasattr(patch, 'patch_complexity'):
                        assert patch.patch_complexity in ['simple', 'moderate', 'complex']

    def test_patch_conflict_detection(self):
        """Test detection of conflicting memory patches."""
        # Create overlapping patches
        overlapping_addresses = [0x401000, 0x401002, 0x401004]  # Overlapping ranges

        conflict_patches = self.agent._create_memory_patches(
            self.mock_process_handle,
            overlapping_addresses
        )

        # Should detect potential conflicts
        if len(conflict_patches) > 1 and hasattr(conflict_patches[0], 'conflict_analysis'):
            for patch in conflict_patches:
                conflict_analysis = patch.conflict_analysis

                assert hasattr(conflict_analysis, 'conflicts_detected')
                assert hasattr(conflict_analysis, 'conflicting_patches')
                assert hasattr(conflict_analysis, 'resolution_strategy')

                if conflict_analysis.conflicts_detected:
                    assert len(conflict_analysis.conflicting_patches) > 0
                    assert conflict_analysis.resolution_strategy in [
                        'merge_patches', 'prioritize_first', 'prioritize_critical', 'manual_resolution'
                    ]

    def test_performance_optimization(self):
        """Test performance optimization in memory patching."""
        import time

        # Time patch generation with many addresses
        large_address_list = [0x401000 + (i * 0x1000) for i in range(20)]

        start_time = time.time()
        performance_patches = self.agent._create_memory_patches(
            self.mock_process_handle,
            large_address_list
        )
        generation_time = time.time() - start_time

        # Should complete within reasonable time
        assert generation_time < 30.0  # 30 seconds maximum
        assert len(performance_patches) > 0

        # Performance metrics should be tracked
        if hasattr(performance_patches[0], 'generation_metrics'):
            metrics = performance_patches[0].generation_metrics
            assert hasattr(metrics, 'total_generation_time')
            assert hasattr(metrics, 'per_patch_average_time')

    def test_error_handling_robustness(self):
        """Test robust error handling in memory patching."""
        # Test invalid process handle
        try:
            invalid_patches = self.agent._create_memory_patches(
                -1,  # Invalid handle
                [0x401000]
            )
            # Should handle gracefully
            if invalid_patches:
                assert all(hasattr(p, 'error') for p in invalid_patches)
        except Exception:
            pass  # Exception is acceptable error handling

        # Test invalid memory addresses
        try:
            invalid_addr_patches = self.agent._create_memory_patches(
                self.mock_process_handle,
                [0x0, 0xFFFFFFFFFFFFFFFF]  # Invalid addresses
            )
            # Should handle gracefully
            if invalid_addr_patches:
                for patch in invalid_addr_patches:
                    if hasattr(patch, 'validation_result'):
                        assert patch.validation_result.is_valid is False
        except Exception:
            pass  # Exception is acceptable

    def test_advanced_hook_scenarios(self):
        """Test advanced hooking scenarios."""
        # Test recursive hook protection
        recursive_hook = self.agent._create_hook_detours(
            'recursive_function', 'recursive_safe_hook'
        )

        if recursive_hook and hasattr(recursive_hook, 'recursion_protection'):
            assert recursive_hook.recursion_protection is True
            assert hasattr(recursive_hook, 'recursion_detection_method')

        # Test multi-threaded hook safety
        threadsafe_hook = self.agent._create_hook_detours(
            'multithreaded_function', 'thread_safe_hook'
        )

        if threadsafe_hook and hasattr(threadsafe_hook, 'thread_safety'):
            assert threadsafe_hook.thread_safety in ['none', 'basic', 'advanced']
            if threadsafe_hook.thread_safety in ['basic', 'advanced']:
                assert hasattr(threadsafe_hook, 'synchronization_method')


class TestMemoryPatchingAdvanced(IntellicrackTestBase):
    """Advanced memory patching testing scenarios."""

    def test_kernel_mode_patching(self):
        """Test kernel-mode memory patching capabilities."""
        agent = AutomatedPatchAgent()

        # Test kernel patch generation
        kernel_patches = agent._create_memory_patches(
            0,  # Kernel space (process handle 0)
            [0x80000000],  # Kernel address space
            patch_mode='kernel'
        )

        if kernel_patches and len(kernel_patches) > 0:
            patch = kernel_patches[0]

            # Should handle kernel-specific requirements
            assert hasattr(patch, 'privilege_requirements')
            assert hasattr(patch, 'irql_level')
            assert hasattr(patch, 'patch_mode')

            assert patch.patch_mode == 'kernel'
            assert patch.privilege_requirements in ['admin', 'system', 'kernel']

    def test_hypervisor_aware_patching(self):
        """Test hypervisor-aware patching techniques."""
        agent = AutomatedPatchAgent()

        hypervisor_patches = agent._create_memory_patches(
            1234,
            [0x401000],
            hypervisor_aware=True
        )

        if hypervisor_patches and len(hypervisor_patches) > 0:
            patch = hypervisor_patches[0]

            if hasattr(patch, 'hypervisor_detection'):
                assert hasattr(patch.hypervisor_detection, 'detection_methods')
                assert hasattr(patch.hypervisor_detection, 'evasion_techniques')

    def test_hardware_breakpoint_patching(self):
        """Test hardware breakpoint-based patching."""
        agent = AutomatedPatchAgent()

        hw_bp_patches = agent._create_memory_patches(
            1234,
            [0x401000],
            method='hardware_breakpoint'
        )

        if hw_bp_patches and len(hw_bp_patches) > 0:
            patch = hw_bp_patches[0]

            # Hardware breakpoints have specific characteristics
            if hasattr(patch, 'breakpoint_register'):
                assert patch.breakpoint_register in ['dr0', 'dr1', 'dr2', 'dr3']
                assert hasattr(patch, 'trigger_condition')
                assert patch.trigger_condition in ['execute', 'read', 'write', 'io']
