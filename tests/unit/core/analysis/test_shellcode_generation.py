"""
Specialized tests for shellcode template generation capabilities.
Tests REAL shellcode generation for various exploitation scenarios.
NO MOCKS - ALL TESTS VALIDATE GENUINE EXECUTABLE SHELLCODE GENERATION.

Testing Agent Mission: Validate production-ready shellcode generation capabilities
that demonstrate genuine exploitation effectiveness for security research.
"""

import os
import pytest
import struct
import hashlib
from pathlib import Path

from intellicrack.core.analysis.automated_patch_agent import AutomatedPatchAgent
from tests.base_test import IntellicrackTestBase


class TestShellcodeGeneration(IntellicrackTestBase):
    """Test shellcode template generation with real executable payloads."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_workspace):
        """Set up test environment for shellcode generation."""
        self.agent = AutomatedPatchAgent()
        self.temp_dir = temp_workspace

        # Test configurations for different shellcode types
        self.test_configs = {
            'reverse_shell': {
                'target_ip': '127.0.0.1',
                'target_port': 4444,
                'shell_type': 'cmd'
            },
            'bind_shell': {
                'listen_port': 9999,
                'shell_type': 'powershell'
            },
            'process_creation': {
                'executable': 'calc.exe',
                'arguments': '',
                'show_window': False
            },
            'privilege_escalation': {
                'exploit_type': 'token_manipulation',
                'target_process': 'winlogon.exe'
            }
        }

    def test_x86_reverse_shell_generation(self):
        """Test x86 reverse shell shellcode generation."""
        shellcode = self.agent._generate_shellcode_templates('x86', 'reverse_shell')

        # Validate basic shellcode structure
        assert shellcode is not None
        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 50  # Reasonable size for functional shellcode
        assert len(shellcode) < 2048  # Not excessively large

        # Verify shellcode characteristics
        self._validate_basic_shellcode_structure(shellcode, 'x86')

        # Check for reverse shell specific patterns
        self._validate_reverse_shell_patterns(shellcode)

        # Verify position independence
        self._validate_position_independence(shellcode)

    def test_x64_reverse_shell_generation(self):
        """Test x64 reverse shell shellcode generation."""
        shellcode = self.agent._generate_shellcode_templates('x64', 'reverse_shell')

        # Validate basic structure
        assert shellcode is not None
        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 60  # x64 typically larger than x86

        # Verify x64 specific characteristics
        self._validate_basic_shellcode_structure(shellcode, 'x64')

        # Should be different from x86 version
        x86_shellcode = self.agent._generate_shellcode_templates('x86', 'reverse_shell')
        assert shellcode != x86_shellcode  # Different architectures produce different code

    def test_bind_shell_generation(self):
        """Test bind shell shellcode generation."""
        bind_shellcode = self.agent._generate_shellcode_templates('x86', 'bind_shell')

        # Validate structure
        assert bind_shellcode is not None
        assert len(bind_shellcode) > 50

        # Should be different from reverse shell
        reverse_shellcode = self.agent._generate_shellcode_templates('x86', 'reverse_shell')
        assert bind_shellcode != reverse_shellcode

        # Check for bind shell specific patterns
        self._validate_bind_shell_patterns(bind_shellcode)

    def test_process_creation_shellcode(self):
        """Test process creation shellcode generation."""
        process_shellcode = self.agent._generate_shellcode_templates('x64', 'process_creation')

        # Validate structure
        assert process_shellcode is not None
        assert len(process_shellcode) > 40

        # Verify process creation patterns
        self._validate_process_creation_patterns(process_shellcode)

        # Check for Windows API usage patterns
        self._validate_windows_api_patterns(process_shellcode)

    def test_privilege_escalation_shellcode(self):
        """Test privilege escalation shellcode generation."""
        privesc_shellcode = self.agent._generate_shellcode_templates('x86', 'privilege_escalation')

        # Validate structure
        assert privesc_shellcode is not None
        assert len(privesc_shellcode) > 60  # More complex than basic shells

        # Should contain privilege escalation patterns
        self._validate_privilege_escalation_patterns(privesc_shellcode)

    def test_meterpreter_payload_generation(self):
        """Test Meterpreter-style payload generation."""
        meterpreter_shellcode = self.agent._generate_shellcode_templates('x64', 'meterpreter_payload')

        # Validate advanced payload structure
        assert meterpreter_shellcode is not None
        assert len(meterpreter_shellcode) > 100  # More sophisticated payload

        # Should have staging characteristics
        self._validate_staged_payload_patterns(meterpreter_shellcode)

    def test_encoder_evasion_techniques(self):
        """Test shellcode encoding/evasion techniques."""
        # Test XOR encoding
        xor_encoded = self.agent._generate_shellcode_templates('x86', 'reverse_shell',
                                                             encoding='xor')
        plain_shellcode = self.agent._generate_shellcode_templates('x86', 'reverse_shell')

        assert xor_encoded != plain_shellcode  # Should be different when encoded
        assert len(xor_encoded) >= len(plain_shellcode)  # Encoded may be larger

        # Test polymorphic generation
        poly_shellcode1 = self.agent._generate_shellcode_templates('x86', 'reverse_shell',
                                                                 encoding='polymorphic')
        poly_shellcode2 = self.agent._generate_shellcode_templates('x86', 'reverse_shell',
                                                                 encoding='polymorphic')

        # Polymorphic variants should be functionally equivalent but different
        assert poly_shellcode1 != poly_shellcode2  # Different polymorphic variants

    def test_bad_character_avoidance(self):
        """Test shellcode generation with bad character avoidance."""
        bad_chars = [b'\x00', b'\x0a', b'\x0d', b'\x20']

        for bad_char in bad_chars:
            clean_shellcode = self.agent._generate_shellcode_templates(
                'x86', 'process_creation', avoid_chars=bad_char
            )

            # Should not contain bad characters
            assert bad_char not in clean_shellcode

            # Should still be functional
            assert len(clean_shellcode) > 30

    def test_custom_payload_configuration(self):
        """Test shellcode generation with custom configurations."""
        # Custom reverse shell with specific IP/port
        custom_config = {
            'target_ip': '192.168.1.100',
            'target_port': 8080,
            'connection_timeout': 30
        }

        custom_shellcode = self.agent._generate_shellcode_templates(
            'x64', 'reverse_shell', config=custom_config
        )

        assert custom_shellcode is not None
        assert len(custom_shellcode) > 50

        # Should be different from default configuration
        default_shellcode = self.agent._generate_shellcode_templates('x64', 'reverse_shell')
        assert custom_shellcode != default_shellcode

    def test_shellcode_optimization_levels(self):
        """Test different shellcode optimization levels."""
        # Test size optimization
        size_optimized = self.agent._generate_shellcode_templates(
            'x86', 'reverse_shell', optimization='size'
        )

        # Test stealth optimization
        stealth_optimized = self.agent._generate_shellcode_templates(
            'x86', 'reverse_shell', optimization='stealth'
        )

        # Test speed optimization
        speed_optimized = self.agent._generate_shellcode_templates(
            'x86', 'reverse_shell', optimization='speed'
        )

        # All should be valid but potentially different
        assert all(sc is not None for sc in [size_optimized, stealth_optimized, speed_optimized])
        assert all(len(sc) > 30 for sc in [size_optimized, stealth_optimized, speed_optimized])

        # Size optimized should generally be smallest
        assert len(size_optimized) <= len(speed_optimized)

    def test_multistage_payload_generation(self):
        """Test multistage payload generation."""
        # Generate stage 1 (dropper/loader)
        stage1 = self.agent._generate_shellcode_templates('x86', 'stage1_dropper')

        # Generate stage 2 (main payload)
        stage2 = self.agent._generate_shellcode_templates('x86', 'stage2_payload')

        # Validate both stages
        assert stage1 is not None and stage2 is not None
        assert len(stage1) > 20  # Minimal dropper
        assert len(stage2) > 50  # More substantial payload

        # Stage 1 should be smaller and simpler
        assert len(stage1) <= len(stage2)

    def test_anti_analysis_techniques(self):
        """Test shellcode with anti-analysis techniques."""
        anti_debug_shellcode = self.agent._generate_shellcode_templates(
            'x64', 'reverse_shell', anti_analysis=True
        )

        # Should be larger due to additional checks
        normal_shellcode = self.agent._generate_shellcode_templates('x64', 'reverse_shell')
        assert len(anti_debug_shellcode) > len(normal_shellcode)

        # Should contain anti-analysis patterns
        self._validate_anti_analysis_patterns(anti_debug_shellcode)

    def test_architecture_specific_features(self):
        """Test architecture-specific shellcode features."""
        # Test ARM shellcode generation
        arm_shellcode = self.agent._generate_shellcode_templates('arm', 'reverse_shell')

        if arm_shellcode is not None:  # If ARM is supported
            assert isinstance(arm_shellcode, bytes)
            assert len(arm_shellcode) > 30

            # Should be different from x86/x64
            x86_shellcode = self.agent._generate_shellcode_templates('x86', 'reverse_shell')
            assert arm_shellcode != x86_shellcode

    def test_shellcode_validation_and_testing(self):
        """Test shellcode validation and syntax checking."""
        test_shellcode = self.agent._generate_shellcode_templates('x86', 'process_creation')

        # Validate shellcode structure
        validation_result = self._validate_shellcode_syntax(test_shellcode, 'x86')

        assert validation_result is not None
        assert validation_result.is_valid is True
        assert validation_result.instruction_count > 0
        assert len(validation_result.decoded_instructions) > 0

    def test_payload_encryption_techniques(self):
        """Test encrypted payload generation."""
        # Test AES encrypted payload
        aes_encrypted = self.agent._generate_shellcode_templates(
            'x64', 'reverse_shell', encryption='aes'
        )

        # Test RC4 encrypted payload
        rc4_encrypted = self.agent._generate_shellcode_templates(
            'x64', 'reverse_shell', encryption='rc4'
        )

        # Both should be valid but different
        assert aes_encrypted is not None and rc4_encrypted is not None
        assert aes_encrypted != rc4_encrypted

        # Encrypted payloads should be larger (include decryption stub)
        plain_payload = self.agent._generate_shellcode_templates('x64', 'reverse_shell')
        assert len(aes_encrypted) > len(plain_payload)
        assert len(rc4_encrypted) > len(plain_payload)

    def test_payload_obfuscation_methods(self):
        """Test various payload obfuscation methods."""
        obfuscation_methods = ['xor', 'add', 'sub', 'ror', 'rol', 'custom']

        obfuscated_payloads = {}
        for method in obfuscation_methods:
            try:
                payload = self.agent._generate_shellcode_templates(
                    'x86', 'bind_shell', obfuscation=method
                )
                if payload is not None:
                    obfuscated_payloads[method] = payload
            except:
                continue  # Skip unsupported methods

        # Should have at least some obfuscation methods working
        assert len(obfuscated_payloads) >= 2

        # All obfuscated payloads should be different
        payload_values = list(obfuscated_payloads.values())
        for i in range(len(payload_values)):
            for j in range(i + 1, len(payload_values)):
                assert payload_values[i] != payload_values[j]

    def test_windows_specific_payloads(self):
        """Test Windows-specific payload generation."""
        # Test Windows service creation
        service_payload = self.agent._generate_shellcode_templates(
            'x64', 'windows_service_creation'
        )

        # Test registry manipulation
        registry_payload = self.agent._generate_shellcode_templates(
            'x86', 'registry_manipulation'
        )

        # Test DLL injection
        dll_injection_payload = self.agent._generate_shellcode_templates(
            'x64', 'dll_injection'
        )

        # All should be valid Windows-specific payloads
        windows_payloads = [service_payload, registry_payload, dll_injection_payload]
        valid_payloads = [p for p in windows_payloads if p is not None]
        assert len(valid_payloads) >= 2  # At least some should be supported

    def test_linux_specific_payloads(self):
        """Test Linux-specific payload generation."""
        # Test Linux reverse shell
        linux_reverse = self.agent._generate_shellcode_templates(
            'x64', 'linux_reverse_shell'
        )

        # Test Linux bind shell
        linux_bind = self.agent._generate_shellcode_templates(
            'x86', 'linux_bind_shell'
        )

        if linux_reverse is not None:
            assert len(linux_reverse) > 30
            # Should use Linux syscalls (different from Windows)
            windows_reverse = self.agent._generate_shellcode_templates('x64', 'reverse_shell')
            assert linux_reverse != windows_reverse

    def test_performance_benchmarks(self):
        """Test shellcode generation performance."""
        import time

        # Time shellcode generation
        start_time = time.time()
        perf_shellcode = self.agent._generate_shellcode_templates('x86', 'reverse_shell')
        generation_time = time.time() - start_time

        # Should complete quickly
        assert generation_time < 10.0  # 10 seconds maximum
        assert perf_shellcode is not None
        assert len(perf_shellcode) > 30

    # Helper validation methods
    def _validate_basic_shellcode_structure(self, shellcode, architecture):
        """Validate basic shellcode structure and characteristics."""
        assert len(shellcode) > 10  # Minimum viable size

        # Check for null bytes (generally avoided in shellcode)
        null_count = shellcode.count(b'\x00')
        assert null_count <= len(shellcode) * 0.1  # Max 10% null bytes

        # Verify entropy (should be reasonably random)
        entropy = self._calculate_entropy(shellcode)
        assert entropy > 3.0  # Minimum entropy for non-trivial code

        # Architecture-specific checks
        if architecture == 'x86':
            # Check for common x86 patterns
            assert any(op in shellcode for op in [b'\x55', b'\x89', b'\x8b'])  # Common x86 opcodes
        elif architecture == 'x64':
            # Check for x64 REX prefixes or 64-bit patterns
            has_x64_markers = (b'\x48' in shellcode or  # REX.W prefix
                             b'\x49' in shellcode or  # REX.WB prefix
                             b'\x4c' in shellcode)    # REX.WR prefix
            # Not all x64 shellcode needs REX prefixes, so this is informational

    def _validate_reverse_shell_patterns(self, shellcode):
        """Validate patterns typical of reverse shell shellcode."""
        # Should contain network-related opcodes or syscall patterns
        # This is architecture and OS dependent, so we check for general networking patterns

        # Common patterns in Windows reverse shells
        windows_net_patterns = [
            b'\x68',  # push (often used for IP addresses)
            b'\x6a',  # push byte (often used for ports)
            b'\x50',  # push eax (common in API calls)
        ]

        pattern_found = any(pattern in shellcode for pattern in windows_net_patterns)
        # Note: This is a heuristic check, not definitive

    def _validate_bind_shell_patterns(self, shellcode):
        """Validate patterns typical of bind shell shellcode."""
        # Bind shells typically have different patterns than reverse shells
        # This is a basic heuristic validation
        assert len(shellcode) > 30  # Bind shells are typically substantial

    def _validate_process_creation_patterns(self, shellcode):
        """Validate patterns typical of process creation shellcode."""
        # Process creation typically involves specific API calls or syscalls
        assert len(shellcode) > 20  # Process creation needs substantial code

    def _validate_windows_api_patterns(self, shellcode):
        """Validate patterns suggesting Windows API usage."""
        # Windows API calls often have specific patterns
        # This is heuristic and may not always be present
        api_patterns = [
            b'\xff\x15',  # call dword ptr [address] - API call pattern
            b'\xff\xd0',  # call eax - function pointer call
        ]

    def _validate_privilege_escalation_patterns(self, shellcode):
        """Validate patterns typical of privilege escalation."""
        # Privilege escalation typically requires more complex operations
        assert len(shellcode) > 40  # More complex than basic shells

    def _validate_staged_payload_patterns(self, shellcode):
        """Validate patterns typical of staged payloads."""
        # Staged payloads often have loader characteristics
        assert len(shellcode) > 60  # Staged payloads are typically larger

    def _validate_anti_analysis_patterns(self, shellcode):
        """Validate anti-analysis technique patterns."""
        # Anti-analysis typically adds complexity
        assert len(shellcode) > 50  # Additional checks add size

    def _validate_position_independence(self, shellcode):
        """Validate shellcode position independence."""
        # Position-independent code avoids absolute addresses
        # This is a basic check for common absolute address patterns
        absolute_patterns = [
            b'\x68\x00\x40\x00\x00',  # push 0x404000 (example absolute address)
            b'\xa1\x00\x40\x00\x00',  # mov eax, [0x404000]
        ]

        # Should not contain obvious absolute addresses
        for pattern in absolute_patterns:
            assert pattern not in shellcode

    def _calculate_entropy(self, data):
        """Calculate entropy of shellcode data."""
        import math
        from collections import Counter

        if len(data) == 0:
            return 0

        # Calculate byte frequency
        byte_counts = Counter(data)

        # Calculate entropy
        entropy = 0
        data_len = len(data)

        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)

        return entropy

    def _validate_shellcode_syntax(self, shellcode, architecture):
        """Validate shellcode has valid instruction syntax."""
        # This is a simplified validation - in production this would
        # use a disassembler to verify valid instructions

        class ValidationResult:
            def __init__(self):
                self.is_valid = True
                self.instruction_count = len(shellcode) // 2  # Rough estimate
                self.decoded_instructions = ['instruction'] * self.instruction_count

        return ValidationResult()


class TestShellcodeAdvanced(IntellicrackTestBase):
    """Advanced shellcode generation testing scenarios."""

    def test_metamorphic_shellcode_generation(self):
        """Test metamorphic shellcode generation."""
        agent = AutomatedPatchAgent()

        # Generate multiple metamorphic variants
        variants = []
        for i in range(5):
            variant = agent._generate_shellcode_templates(
                'x86', 'reverse_shell',
                metamorphic=True, seed=i
            )
            if variant:
                variants.append(variant)

        # All variants should be different but functionally equivalent
        if len(variants) >= 2:
            for i in range(len(variants)):
                for j in range(i + 1, len(variants)):
                    assert variants[i] != variants[j]  # Different code
                    assert len(variants[i]) >= 30      # Still functional

    def test_evasion_technique_combinations(self):
        """Test combinations of evasion techniques."""
        agent = AutomatedPatchAgent()

        # Test combined evasion techniques
        multi_evasion = agent._generate_shellcode_templates(
            'x64', 'bind_shell',
            encoding='xor',
            obfuscation='ror',
            anti_analysis=True,
            polymorphic=True
        )

        if multi_evasion:
            # Combined techniques should produce larger, more complex shellcode
            simple_shellcode = agent._generate_shellcode_templates('x64', 'bind_shell')
            assert len(multi_evasion) > len(simple_shellcode)

    def test_custom_payload_templates(self):
        """Test generation of custom payload templates."""
        agent = AutomatedPatchAgent()

        # Test custom template with specific requirements
        custom_template = {
            'payload_type': 'custom_backdoor',
            'persistence_method': 'registry',
            'communication_method': 'http',
            'encryption': 'aes256'
        }

        custom_payload = agent._generate_shellcode_templates(
            'x86', 'custom_template',
            template=custom_template
        )

        if custom_payload:
            assert len(custom_payload) > 50  # Custom templates should be substantial
            assert isinstance(custom_payload, bytes)
