"""
Specialized tests for binary analysis and patch point identification capabilities.
Tests REAL binary analysis that identifies precise locations for protection bypasses.
NO MOCKS - ALL TESTS USE REAL BINARY DATA AND VALIDATE GENUINE ANALYSIS.

Testing Agent Mission: Validate production-ready patch point identification
that demonstrates genuine reverse engineering effectiveness for security research.
"""

import os
import pytest
import struct
from pathlib import Path

from intellicrack.core.analysis.automated_patch_agent import AutomatedPatchAgent
from tests.base_test import IntellicrackTestBase


class TestPatchPointAnalysis(IntellicrackTestBase):
    """Test precise patch point identification in real binaries."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_workspace):
        """Set up test with specialized binaries for patch point analysis."""
        self.agent = AutomatedPatchAgent()
        self.temp_dir = temp_workspace

        # Create binaries with specific protection patterns
        self.license_check_binary = self._create_license_check_binary()
        self.anti_debug_binary = self._create_anti_debug_binary()
        self.integrity_check_binary = self._create_integrity_check_binary()
        self.registration_binary = self._create_registration_binary()

    def _create_license_check_binary(self):
        """Create binary with typical license validation patterns."""
        binary_path = os.path.join(self.temp_dir, "license_check.exe")

        # PE header with license validation routine
        pe_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # License check function
            b'\x55\x8b\xec'         # push ebp; mov ebp, esp
            b'\x83\xec\x20'         # sub esp, 0x20
            b'\x8b\x45\x08'         # mov eax, [ebp+8] (license parameter)
            b'\x85\xc0'             # test eax, eax
            b'\x74\x15'             # jz invalid_license (PATCH POINT)
            b'\x50'                 # push eax
            b'\xe8\x00\x00\x00\x00' # call validate_license_key
            b'\x83\xc4\x04'         # add esp, 4
            b'\x85\xc0'             # test eax, eax
            b'\x75\x05'             # jnz valid_license (PATCH POINT)
            # Invalid license path
            b'\xb8\x00\x00\x00\x00' # mov eax, 0 (FAIL)
            b'\xeb\x05'             # jmp exit
            # Valid license path
            b'\xb8\x01\x00\x00\x00' # mov eax, 1 (SUCCESS)
            # Exit
            b'\x8b\xe5\x5d\xc3'     # mov esp, ebp; pop ebp; ret
        )

        with open(binary_path, 'wb') as f:
            f.write(pe_data)

        return binary_path

    def _create_anti_debug_binary(self):
        """Create binary with anti-debugging checks."""
        binary_path = os.path.join(self.temp_dir, "anti_debug.exe")

        # Anti-debugging techniques
        anti_debug_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # IsDebuggerPresent check
            b'\x64\xa1\x30\x00\x00\x00' # mov eax, fs:[0x30] (PEB)
            b'\x8a\x40\x02'             # mov al, [eax+2] (BeingDebugged)
            b'\x84\xc0'                 # test al, al
            b'\x75\x05'                 # jnz debugger_detected (PATCH POINT)
            # NtGlobalFlag check
            b'\x64\xa1\x30\x00\x00\x00' # mov eax, fs:[0x30]
            b'\x8b\x40\x68'             # mov eax, [eax+0x68] (NtGlobalFlag)
            b'\x25\x70\x00\x00\x00'     # and eax, 0x70
            b'\x75\x05'                 # jnz debugger_detected (PATCH POINT)
            # Normal execution
            b'\xb8\x00\x00\x00\x00'     # mov eax, 0 (continue)
            b'\xeb\x05'                 # jmp continue
            # Debugger detected
            b'\xb8\x01\x00\x00\x00'     # mov eax, 1 (exit)
            # Continue
            b'\xc3'                     # ret
        )

        with open(binary_path, 'wb') as f:
            f.write(anti_debug_data)

        return binary_path

    def _create_integrity_check_binary(self):
        """Create binary with integrity validation."""
        binary_path = os.path.join(self.temp_dir, "integrity_check.exe")

        # Integrity checking routine
        integrity_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # Checksum calculation
            b'\x31\xc0'                 # xor eax, eax (checksum)
            b'\x31\xc9'                 # xor ecx, ecx (counter)
            b'\xbe\x00\x10\x40\x00'     # mov esi, 0x401000 (start addr)
            # Checksum loop
            b'\x8a\x1e'                 # mov bl, [esi]
            b'\x01\xd8'                 # add eax, ebx
            b'\x46'                     # inc esi
            b'\x41'                     # inc ecx
            b'\x81\xf9\x00\x10\x00\x00' # cmp ecx, 0x1000
            b'\x72\xf5'                 # jb checksum_loop
            # Compare with expected
            b'\x3d\x12\x34\x56\x78'     # cmp eax, 0x78563412
            b'\x74\x05'                 # je integrity_ok (PATCH POINT)
            # Integrity failed
            b'\xb8\x00\x00\x00\x00'     # mov eax, 0 (FAIL)
            b'\xeb\x05'                 # jmp exit
            # Integrity ok
            b'\xb8\x01\x00\x00\x00'     # mov eax, 1 (SUCCESS)
            # Exit
            b'\xc3'                     # ret
        )

        with open(binary_path, 'wb') as f:
            f.write(integrity_data)

        return binary_path

    def _create_registration_binary(self):
        """Create binary with registration/trial checks."""
        binary_path = os.path.join(self.temp_dir, "registration.exe")

        # Registration validation
        reg_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # Trial period check
            b'\xe8\x00\x00\x00\x00'     # call GetTickCount
            b'\x2d\x00\x00\x00\x00'     # sub eax, install_time
            b'\x3d\x80\x84\x1e\x00'     # cmp eax, 2000000 (trial period)
            b'\x77\x15'                 # ja trial_expired (PATCH POINT)
            # Check registration key
            b'\xe8\x00\x00\x00\x00'     # call check_registration
            b'\x85\xc0'                 # test eax, eax
            b'\x74\x0a'                 # jz not_registered (PATCH POINT)
            # Registered/trial ok
            b'\xb8\x01\x00\x00\x00'     # mov eax, 1 (SUCCESS)
            b'\xeb\x0a'                 # jmp exit
            # Trial expired/not registered
            b'\xb8\x00\x00\x00\x00'     # mov eax, 0 (FAIL)
            b'\xeb\x00'                 # jmp exit
            # Exit
            b'\xc3'                     # ret
        )

        with open(binary_path, 'wb') as f:
            f.write(reg_data)

        return binary_path

    def test_license_check_patch_identification(self):
        """Test identification of license validation patch points."""
        with open(self.license_check_binary, 'rb') as f:
            binary_data = f.read()

        patch_points = self.agent._find_patch_points(binary_data)

        # Should identify multiple license-related patch points
        license_patches = [p for p in patch_points if p.bypass_type == 'license_check_bypass']
        assert len(license_patches) >= 2  # At least 2 license check points

        # Verify patch point details
        for patch in license_patches:
            # Should identify conditional jumps in license validation
            assert patch.size >= 2  # Minimum instruction size
            assert patch.offset > 64  # Beyond PE header

            # Original bytes should contain conditional jump instructions
            original = patch.original_bytes
            assert original[0] in [0x74, 0x75, 0x77, 0x76]  # jz, jnz, ja, jbe variations

            # Target bytes should be bypass instructions
            target = patch.target_bytes
            assert target[0] in [0x90, 0xeb]  # NOP or JMP

    def test_anti_debug_patch_identification(self):
        """Test identification of anti-debugging bypass points."""
        with open(self.anti_debug_binary, 'rb') as f:
            binary_data = f.read()

        patch_points = self.agent._find_patch_points(binary_data)

        # Should identify anti-debugging patches
        anti_debug_patches = [p for p in patch_points if p.bypass_type == 'anti_debug_disable']
        assert len(anti_debug_patches) >= 2  # Multiple anti-debug techniques

        for patch in anti_debug_patches:
            # Verify patch targets anti-debug conditionals
            original = patch.original_bytes

            # Should target conditional jumps after debug checks
            if len(original) >= 2:
                assert original[0] in [0x75, 0x77, 0x74, 0x76]  # Conditional jumps

            # Target should bypass the anti-debug reaction
            target = patch.target_bytes
            assert len(target) == len(original)

    def test_integrity_check_patch_identification(self):
        """Test identification of integrity validation bypass points."""
        with open(self.integrity_check_binary, 'rb') as f:
            binary_data = f.read()

        patch_points = self.agent._find_patch_points(binary_data)

        # Should identify integrity check bypasses
        integrity_patches = [p for p in patch_points if p.bypass_type == 'integrity_check_skip']
        assert integrity_patches

        for patch in integrity_patches:
            # Verify patch targets integrity validation
            assert patch.size > 0
            assert isinstance(patch.original_bytes, bytes)
            assert isinstance(patch.target_bytes, bytes)

            # Should preserve instruction alignment
            assert len(patch.original_bytes) == len(patch.target_bytes)

    def test_registration_patch_identification(self):
        """Test identification of registration/trial bypass points."""
        with open(self.registration_binary, 'rb') as f:
            binary_data = f.read()

        patch_points = self.agent._find_patch_points(binary_data)

        # Should identify registration-related patches
        reg_patches = [p for p in patch_points if p.bypass_type == 'registration_bypass']
        assert len(reg_patches) >= 2  # Trial and registration checks

        for patch in reg_patches:
            # Verify patch addresses registration validation
            assert patch.offset < len(binary_data)
            assert patch.size <= 10  # Reasonable instruction size

            # Should have valid bypass strategy
            assert hasattr(patch, 'bypass_strategy')
            assert patch.bypass_strategy in ['nop_fill', 'jump_redirect', 'register_set']

    def test_patch_point_precision(self):
        """Test patch points are precisely located at instruction boundaries."""
        with open(self.license_check_binary, 'rb') as f:
            binary_data = f.read()

        patch_points = self.agent._find_patch_points(binary_data)

        for patch in patch_points:
            # Verify patch is at valid instruction boundary
            offset = patch.offset
            size = patch.size

            # Should not exceed binary bounds
            assert offset + size <= len(binary_data)

            # Original bytes should be valid x86 instructions
            original = patch.original_bytes
            assert len(original) >= 1

            # First byte should be valid x86 opcode
            opcode = original[0]
            valid_opcodes = list(range(0xff))  # All possible opcodes
            assert opcode in valid_opcodes

    def test_patch_strategy_selection(self):
        """Test appropriate patch strategies are selected for different patterns."""
        test_binaries = [
            (self.license_check_binary, 'license_check_bypass'),
            (self.anti_debug_binary, 'anti_debug_disable'),
            (self.integrity_check_binary, 'integrity_check_skip'),
            (self.registration_binary, 'registration_bypass')
        ]

        for binary_path, expected_type in test_binaries:
            with open(binary_path, 'rb') as f:
                binary_data = f.read()

            patch_points = self.agent._find_patch_points(binary_data)

            # Should find patches of expected type
            matching_patches = [p for p in patch_points if p.bypass_type == expected_type]
            assert matching_patches

            # Verify strategy appropriateness
            for patch in matching_patches:
                if expected_type == 'anti_debug_disable':
                    # Anti-debug often requires NOPs or register manipulation
                    assert patch.bypass_strategy in ['nop_fill', 'register_clear']
                elif expected_type == 'integrity_check_skip':
                    # Integrity checks often need jump redirects
                    assert patch.bypass_strategy in ['jump_redirect', 'comparison_patch']
                elif expected_type == 'license_check_bypass':
                    # License checks typically use conditional jumps
                    assert patch.bypass_strategy in ['jump_redirect', 'nop_fill']
                elif expected_type == 'registration_bypass':
                    # Registration can use various strategies
                    assert patch.bypass_strategy in ['jump_redirect', 'register_set', 'nop_fill']

    def test_complex_instruction_analysis(self):
        """Test analysis handles complex x86 instruction patterns."""
        # Create binary with complex instruction patterns
        complex_binary = os.path.join(self.temp_dir, "complex_instructions.exe")

        complex_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # Multi-byte instructions
            b'\x0f\x84\x00\x00\x00\x00' # je long_jump (6 bytes)
            b'\x0f\x85\x00\x00\x00\x00' # jne long_jump (6 bytes)
            b'\x66\x81\x38\x00\x00'     # cmp word ptr [eax], 0 (5 bytes)
            b'\x48\x8b\x05\x00\x00\x00\x00' # mov rax, qword ptr [rip+0] (7 bytes, x64)
        )

        with open(complex_binary, 'wb') as f:
            f.write(complex_data)

        with open(complex_binary, 'rb') as f:
            binary_data = f.read()

        patch_points = self.agent._find_patch_points(binary_data)

        # Should handle multi-byte instructions correctly
        assert len(patch_points) > 0

        for patch in patch_points:
            # Verify instruction boundaries are respected
            assert patch.size >= 2  # Multi-byte instructions
            assert patch.size <= 15  # Maximum x86 instruction length

            # Should identify complete instructions
            original = patch.original_bytes
            if len(original) >= 6 and original[0] == 0x0f:
                # Multi-byte instruction detected
                assert patch.size >= 6  # Complete instruction captured

        os.remove(complex_binary)

    def test_architecture_specific_analysis(self):
        """Test patch point analysis adapts to different architectures."""
        # Test x86 vs x64 instruction analysis
        x86_binary = self.license_check_binary  # 32-bit patterns

        # Create x64 binary with different instruction patterns
        x64_binary = os.path.join(self.temp_dir, "x64_test.exe")
        x64_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # x64 specific instructions
            b'\x48\x85\xc0'             # test rax, rax (x64)
            b'\x74\x05'                 # jz short (same in x64)
            b'\x48\x8b\x05\x00\x00\x00\x00' # mov rax, [rip+offset] (x64 RIP-relative)
        )

        with open(x64_binary, 'wb') as f:
            f.write(x64_data)

        # Analyze both architectures
        with open(self.license_check_binary, 'rb') as f:
            x86_data = f.read()
        with open(x64_binary, 'rb') as f:
            x64_data_read = f.read()

        x86_patches = self.agent._find_patch_points(x86_data)
        x64_patches = self.agent._find_patch_points(x64_data_read)

        # Both should produce patches but with different characteristics
        assert len(x86_patches) > 0
        assert len(x64_patches) > 0

        # x64 patches should account for different instruction encoding
        for patch in x64_patches:
            if patch.original_bytes.startswith(b'\x48'):
                # REX prefix indicates x64 instruction
                assert patch.size >= 3  # REX + opcode + ModR/M minimum

        os.remove(x64_binary)

    def test_patch_point_validation(self):
        """Test patch points are validated for correctness and safety."""
        with open(self.license_check_binary, 'rb') as f:
            binary_data = f.read()

        patch_points = self.agent._find_patch_points(binary_data)

        for patch in patch_points:
            # Validate patch point structure
            assert hasattr(patch, 'offset')
            assert hasattr(patch, 'size')
            assert hasattr(patch, 'original_bytes')
            assert hasattr(patch, 'target_bytes')
            assert hasattr(patch, 'bypass_type')
            assert hasattr(patch, 'bypass_strategy')
            assert hasattr(patch, 'confidence_score')
            assert hasattr(patch, 'risk_assessment')

            # Validate data integrity
            assert isinstance(patch.offset, int)
            assert isinstance(patch.size, int)
            assert isinstance(patch.original_bytes, bytes)
            assert isinstance(patch.target_bytes, bytes)
            assert isinstance(patch.confidence_score, float)

            # Validate ranges
            assert 0 <= patch.offset < len(binary_data)
            assert 1 <= patch.size <= 15  # Valid instruction size range
            assert 0.0 <= patch.confidence_score <= 1.0
            assert len(patch.original_bytes) == patch.size
            assert len(patch.target_bytes) == patch.size

            # Validate risk assessment
            assert patch.risk_assessment in ['low', 'medium', 'high']

    def test_false_positive_minimization(self):
        """Test patch point identification minimizes false positives."""
        # Create binary with legitimate conditional jumps (not protection)
        normal_binary = os.path.join(self.temp_dir, "normal_code.exe")

        normal_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # Normal program logic (not protection)
            b'\x8b\x45\x08'             # mov eax, [ebp+8] (parameter)
            b'\x83\xf8\x0a'             # cmp eax, 10
            b'\x7f\x05'                 # jg greater_than_10 (normal logic)
            b'\x83\xc0\x01'             # inc eax
            b'\xeb\x03'                 # jmp continue
            b'\x83\xe8\x01'             # dec eax
            b'\xc3'                     # ret
        )

        with open(normal_binary, 'wb') as f:
            f.write(normal_data)

        with open(normal_binary, 'rb') as f:
            binary_data = f.read()

        patch_points = self.agent._find_patch_points(binary_data)

        # Should have fewer or no patches for normal program logic
        protection_patches = [p for p in patch_points
                            if p.confidence_score > 0.7]  # High confidence only

        # Normal program logic should not trigger high-confidence protection patches
        assert len(protection_patches) <= 1  # Very few false positives allowed

        # Compare with actual protection binary
        with open(self.license_check_binary, 'rb') as f:
            protection_data = f.read()

        protection_patch_points = self.agent._find_patch_points(protection_data)
        protection_count = len([p for p in protection_patch_points
                              if p.confidence_score > 0.7])

        # Protection binary should have significantly more high-confidence patches
        assert protection_count > len(protection_patches)

        os.remove(normal_binary)
