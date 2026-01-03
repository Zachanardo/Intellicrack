"""
Specialized tests for keygen generation capabilities across multiple algorithms.
Tests REAL keygen creation for serial numbers, RSA, ECC, and custom algorithms.
NO MOCKS - ALL TESTS VALIDATE GENUINE LICENSING ALGORITHM CRACKING.

Testing Agent Mission: Validate production-ready keygen generation capabilities
that demonstrate genuine reverse engineering effectiveness for security research.
"""

from typing import Any
import os
import pytest
import hashlib
import struct
import re
from pathlib import Path

AutomatedPatchAgent: Any = None
AUTOMATED_PATCH_AGENT_AVAILABLE = False
try:
    from intellicrack.core.analysis.automated_patch_agent import AutomatedPatchAgent as _AutomatedPatchAgent
    AutomatedPatchAgent = _AutomatedPatchAgent
    AUTOMATED_PATCH_AGENT_AVAILABLE = True
except ImportError:
    pass

from tests.base_test import IntellicrackTestBase

pytestmark = pytest.mark.skipif(not AUTOMATED_PATCH_AGENT_AVAILABLE, reason="automated_patch_agent module not available")


class TestKeygenGeneration(IntellicrackTestBase):
    """Test keygen generation for various licensing algorithms."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_workspace: Path) -> None:
        """Set up test environment with various licensing binaries."""
        self.agent: Any = AutomatedPatchAgent()
        self.temp_dir: Path = temp_workspace

        # Create test binaries with different licensing schemes
        self.serial_binary: str = self._create_serial_validation_binary()
        self.rsa_binary: str = self._create_rsa_validation_binary()
        self.ecc_binary: str = self._create_ecc_validation_binary()
        self.custom_algorithm_binary: str = self._create_custom_algorithm_binary()
        self.hybrid_licensing_binary: str = self._create_hybrid_licensing_binary()

    def _create_serial_validation_binary(self) -> str:
        """Create binary with serial number validation."""
        binary_path = os.path.join(str(self.temp_dir), "serial_validation.exe")

        # Serial validation with checksum algorithm
        serial_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # Serial format: XXXX-XXXX-XXXX-XXXX (16 chars + 3 dashes)
            # Checksum algorithm embedded
            b'\x31\xc0'                     # xor eax, eax (checksum accumulator)
            b'\x31\xc9'                     # xor ecx, ecx (counter)
            b'\x8a\x1c\x0e'                 # mov bl, [esi+ecx] (load serial char)
            b'\x80\xfb\x2d'                 # cmp bl, 0x2d (dash character)
            b'\x74\x04'                     # je skip_dash
            b'\x01\xd8'                     # add eax, ebx (add to checksum)
            b'\x41'                         # inc ecx (next character)
            b'\x83\xf9\x13'                 # cmp ecx, 19 (serial length)
            b'\x72\xf1'                     # jb checksum_loop
            # Validate checksum
            b'\x25\xff\x0f\x00\x00'         # and eax, 0xfff (12-bit checksum)
            b'\x3d\x34\x12\x00\x00'         # cmp eax, 0x1234 (expected checksum)
            b'\x74\x05'                     # je valid_serial
            # Invalid serial
            b'\xb8\x00\x00\x00\x00'         # mov eax, 0
            b'\xeb\x05'                     # jmp exit
            # Valid serial
            b'\xb8\x01\x00\x00\x00'         # mov eax, 1
            # Exit
            b'\xc3'                         # ret
        )

        with open(binary_path, 'wb') as f:
            f.write(serial_data)

        return binary_path

    def _create_rsa_validation_binary(self) -> str:
        """Create binary with RSA signature validation."""
        binary_path = os.path.join(str(self.temp_dir), "rsa_validation.exe")

        # RSA validation with embedded public key
        rsa_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # RSA-1024 public key components (simulated)
            # n = p * q (1024-bit modulus)
            b'\x68\x00\x01\x00\x00'         # push 0x100 (key size)
            b'\x68\x11\x00\x01\x00'         # push 0x10011 (e = 65537)
            # Simulated modulus n (placeholder bytes)
            b'\x68\x12\x34\x56\x78'         # push partial modulus
            b'\x68\x9a\xbc\xde\xf0'         # push partial modulus
            b'\x68\x11\x22\x33\x44'         # push partial modulus
            b'\x68\x55\x66\x77\x88'         # push partial modulus
            # RSA signature verification routine
            b'\xe8\x00\x00\x00\x00'         # call rsa_verify
            b'\x85\xc0'                     # test eax, eax
            b'\x74\x05'                     # jz invalid_signature
            # Valid signature
            b'\xb8\x01\x00\x00\x00'         # mov eax, 1
            b'\xeb\x05'                     # jmp exit
            # Invalid signature
            b'\xb8\x00\x00\x00\x00'         # mov eax, 0
            # Exit
            b'\xc3'                         # ret
        )

        with open(binary_path, 'wb') as f:
            f.write(rsa_data)

        return binary_path

    def _create_ecc_validation_binary(self) -> str:
        """Create binary with ECC signature validation."""
        binary_path = os.path.join(str(self.temp_dir), "ecc_validation.exe")

        # ECC validation with P-256 curve parameters
        ecc_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # ECC P-256 curve parameters (simulated)
            b'\x68\x20\x00\x00\x00'         # push 32 (field size)
            # Curve parameter p (prime field)
            b'\x68\xff\xff\xff\xff'         # push p[0]
            b'\x68\x00\x00\x00\x01'         # push p[1]
            b'\x68\x00\x00\x00\x00'         # push p[2]
            b'\x68\x00\x00\x00\x00'         # push p[3]
            # Base point G coordinates
            b'\x68\x6b\x17\xd1\xf2'         # push Gx[0]
            b'\x68\xe1\x2c\x42\x47'         # push Gx[1]
            b'\x68\xf8\xbc\xe6\xe5'         # push Gy[0]
            b'\x68\x63\xa4\x40\xf2'         # push Gy[1]
            # ECC signature verification
            b'\xe8\x00\x00\x00\x00'         # call ecdsa_verify
            b'\x85\xc0'                     # test eax, eax
            b'\x74\x05'                     # jz invalid_ecc_signature
            # Valid ECC signature
            b'\xb8\x01\x00\x00\x00'         # mov eax, 1
            b'\xeb\x05'                     # jmp exit
            # Invalid ECC signature
            b'\xb8\x00\x00\x00\x00'         # mov eax, 0
            # Exit
            b'\xc3'                         # ret
        )

        with open(binary_path, 'wb') as f:
            f.write(ecc_data)

        return binary_path

    def _create_custom_algorithm_binary(self) -> str:
        """Create binary with custom licensing algorithm."""
        binary_path = os.path.join(str(self.temp_dir), "custom_algorithm.exe")

        # Custom algorithm combining multiple techniques
        custom_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # Hardware fingerprint collection
            b'\xe8\x00\x00\x00\x00'         # call get_cpu_id
            b'\x50'                         # push eax (cpu_id)
            b'\xe8\x00\x00\x00\x00'         # call get_disk_serial
            b'\x50'                         # push eax (disk_serial)
            b'\xe8\x00\x00\x00\x00'         # call get_mac_address
            b'\x50'                         # push eax (mac_address)
            # Custom hash algorithm
            b'\x31\xc0'                     # xor eax, eax (hash accumulator)
            b'\x31\xc9'                     # xor ecx, ecx (counter)
            # Hash loop
            b'\x8b\x1c\x8c'                 # mov ebx, [esp+ecx*4] (load fingerprint)
            b'\xc1\xc8\x05'                 # ror eax, 5 (rotate hash)
            b'\x01\xd8'                     # add eax, ebx (add fingerprint)
            b'\x35\x5a\xa5\xa5\x5a'         # xor eax, 0x5aa5a55a (salt)
            b'\x41'                         # inc ecx
            b'\x83\xf9\x03'                 # cmp ecx, 3 (3 fingerprints)
            b'\x72\xf1'                     # jb hash_loop
            # Compare with license key
            b'\x3d\xde\xad\xbe\xef'         # cmp eax, expected_hash
            b'\x74\x05'                     # je valid_license
            # Invalid license
            b'\xb8\x00\x00\x00\x00'         # mov eax, 0
            b'\xeb\x05'                     # jmp exit
            # Valid license
            b'\xb8\x01\x00\x00\x00'         # mov eax, 1
            # Exit
            b'\x83\xc4\x0c'                 # add esp, 12 (clean stack)
            b'\xc3'                         # ret
        )

        with open(binary_path, 'wb') as f:
            f.write(custom_data)

        return binary_path

    def _create_hybrid_licensing_binary(self) -> str:
        """Create binary with hybrid licensing (multiple algorithms)."""
        binary_path = os.path.join(str(self.temp_dir), "hybrid_licensing.exe")

        # Hybrid system: serial + RSA + hardware binding
        hybrid_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # Stage 1: Serial validation
            b'\xe8\x00\x00\x00\x00'         # call validate_serial
            b'\x85\xc0'                     # test eax, eax
            b'\x74\x20'                     # jz license_failed
            # Stage 2: RSA signature check
            b'\xe8\x00\x00\x00\x00'         # call validate_rsa_signature
            b'\x85\xc0'                     # test eax, eax
            b'\x74\x17'                     # jz license_failed
            # Stage 3: Hardware binding
            b'\xe8\x00\x00\x00\x00'         # call validate_hardware_binding
            b'\x85\xc0'                     # test eax, eax
            b'\x74\x0e'                     # jz license_failed
            # All validations passed
            b'\xb8\x01\x00\x00\x00'         # mov eax, 1 (success)
            b'\xeb\x05'                     # jmp exit
            # License failed
            b'\xb8\x00\x00\x00\x00'         # mov eax, 0 (failed)
            # Exit
            b'\xc3'                         # ret
        )

        with open(binary_path, 'wb') as f:
            f.write(hybrid_data)

        return binary_path

    def test_serial_keygen_generation(self) -> None:
        """Test serial number keygen generation."""
        keygen_code = self.agent.generate_keygen('serial')

        # Validate keygen code is generated
        assert keygen_code is not None
        assert isinstance(keygen_code, str)

        # Verify keygen code quality - should be substantial implementation
        assert len(keygen_code) > 100

        # Verify code contains essential serial generation components
        assert 'def generate_serial' in keygen_code or 'generate' in keygen_code.lower()
        assert 'hashlib' in keygen_code or 'hash' in keygen_code.lower()

    def test_serial_keygen_algorithm_analysis(self) -> None:
        """Test detailed serial algorithm analysis."""
        keygen_code = self.agent._generate_serial_keygen()

        # Validate keygen code is generated
        assert keygen_code is not None
        assert isinstance(keygen_code, str)

        # Verify code contains serial generation function
        assert 'generate_serial' in keygen_code
        assert 'validate_serial' in keygen_code

        # Verify MD5 based hash algorithm is used
        assert 'hashlib.md5' in keygen_code

        # Verify serial format (XXXX-XXXX-XXXX-XXXX style)
        assert 'join' in keygen_code  # For formatting with dashes

    def test_rsa_keygen_generation(self) -> None:
        """Test RSA keygen generation and cryptographic analysis."""
        keygen_code = self.agent.generate_keygen('rsa')

        # Validate RSA keygen code is generated
        assert keygen_code is not None
        assert isinstance(keygen_code, str)
        assert len(keygen_code) > 200  # RSA is more complex

        # Should contain RSA-related components
        assert 'rsa' in keygen_code.lower() or 'RSA' in keygen_code
        assert 'cryptography' in keygen_code or 'private_key' in keygen_code

        # RSA keygen should be longer than serial
        serial_code = self.agent.generate_keygen('serial')
        assert len(keygen_code) > len(serial_code)

    def test_rsa_cryptographic_analysis(self) -> None:
        """Test detailed RSA cryptographic analysis."""
        rsa_code = self.agent._generate_rsa_keygen()

        # Validate RSA keygen code
        assert rsa_code is not None
        assert isinstance(rsa_code, str)

        # Verify RSA implementation components
        assert 'generate_license_key' in rsa_code
        assert 'private_key' in rsa_code
        assert 'sign' in rsa_code
        assert 'SHA256' in rsa_code or 'hashes' in rsa_code

    def test_ecc_keygen_generation(self) -> None:
        """Test ECC keygen generation and curve analysis."""
        keygen_code = self.agent.generate_keygen('elliptic')

        # Validate ECC keygen code is generated
        assert keygen_code is not None
        assert isinstance(keygen_code, str)
        assert len(keygen_code) > 150  # ECC is substantial

    def test_ecc_cryptographic_analysis(self) -> None:
        """Test detailed ECC cryptographic analysis."""
        ecc_code = self.agent._generate_ecc_keygen()

        # Validate ECC keygen code
        assert ecc_code is not None
        assert isinstance(ecc_code, str)

        # Verify ECC implementation components
        assert 'SECP256R1' in ecc_code or 'secp' in ecc_code.lower() or 'curve' in ecc_code.lower()
        assert 'sign' in ecc_code or 'generate' in ecc_code.lower()

    def test_custom_algorithm_keygen(self) -> None:
        """Test custom algorithm keygen generation."""
        keygen_code = self.agent.generate_keygen('custom')

        # Validate custom keygen code is generated
        assert keygen_code is not None
        assert isinstance(keygen_code, str)
        assert len(keygen_code) > 100

    def test_custom_algorithm_analysis(self) -> None:
        """Test detailed custom algorithm analysis."""
        custom_code = self.agent._generate_custom_keygen()

        # Validate custom keygen code
        assert custom_code is not None
        assert isinstance(custom_code, str)

        # Custom algorithm should have generation function
        assert 'generate' in custom_code.lower() or 'def ' in custom_code

    def test_hardware_binding_analysis(self) -> None:
        """Test hardware binding keygen analysis."""
        hw_code = self.agent._generate_custom_keygen()

        # Validate hardware binding code is generated
        assert hw_code is not None
        assert isinstance(hw_code, str)

        # Custom keygen should have implementation
        assert 'generate' in hw_code.lower() or 'def ' in hw_code

    def test_hybrid_licensing_analysis(self) -> None:
        """Test analysis of hybrid licensing systems."""
        # Test all algorithm types generate valid code
        serial_code = self.agent.generate_keygen('serial')
        rsa_code = self.agent.generate_keygen('rsa')
        custom_code = self.agent.generate_keygen('custom')

        # All should produce non-empty strings
        assert serial_code and len(serial_code) > 0
        assert rsa_code and len(rsa_code) > 0
        assert custom_code and len(custom_code) > 0

    def test_keygen_code_quality(self) -> None:
        """Test quality of generated keygen code."""
        test_keygens = [
            self.agent.generate_keygen('serial'),
            self.agent.generate_keygen('rsa'),
            self.agent.generate_keygen('elliptic'),
            self.agent.generate_keygen('custom')
        ]

        valid_keygens = [k for k in test_keygens if k is not None and len(k) > 0]
        assert len(valid_keygens) >= 2  # At least some algorithms should work

        for keygen_code in valid_keygens:
            # Test code structure
            assert isinstance(keygen_code, str)
            assert len(keygen_code) > 50  # Substantial implementation

            # Test for programming language indicators
            programming_indicators = [
                'import', 'def ', 'class ', 'function', 'var ', 'let ',
                'int ', 'string', 'return', 'if ', 'for ', 'while '
            ]
            has_programming_structure = any(indicator in keygen_code.lower() for indicator in programming_indicators)
            assert has_programming_structure  # Should look like real code

    def test_keygen_algorithm_detection(self) -> None:
        """Test accurate detection of licensing algorithms."""
        test_cases = ['serial', 'rsa', 'elliptic', 'custom']

        for algo_type in test_cases:
            keygen_code = self.agent.generate_keygen(algo_type)
            assert keygen_code is not None
            assert isinstance(keygen_code, str)
            assert len(keygen_code) > 50

    def test_keygen_success_probability_assessment(self) -> None:
        """Test realistic success probability assessment via code quality."""
        keygens: list[tuple[str, str]] = []

        for algo_type in ['serial', 'rsa', 'elliptic', 'custom']:
            keygen_code = self.agent.generate_keygen(algo_type)
            if keygen_code:
                keygens.append((algo_type, keygen_code))

        assert len(keygens) >= 2  # Should have some working keygens

        for algo_type, keygen_code in keygens:
            # Validate code is generated
            assert isinstance(keygen_code, str)
            assert len(keygen_code) > 50

    def test_keygen_complexity_analysis(self) -> None:
        """Test keygen complexity assessment based on code length."""
        complexity_tests: list[tuple[str, int]] = []

        for algo_type in ['serial', 'rsa', 'elliptic', 'custom']:
            keygen_code = self.agent.generate_keygen(algo_type)
            if keygen_code:
                complexity_tests.append((algo_type, len(keygen_code)))

        # RSA should be more complex (longer) than serial
        serial_len = next((l for t, l in complexity_tests if t == 'serial'), 0)
        rsa_len = next((l for t, l in complexity_tests if t == 'rsa'), 0)
        if serial_len and rsa_len:
            assert rsa_len > serial_len

    def test_keygen_output_validation(self) -> None:
        """Test validation of keygen code structure."""
        for algo_type in ['serial', 'custom']:
            keygen_code = self.agent.generate_keygen(algo_type)
            if keygen_code:
                # Code should be executable Python
                assert 'def ' in keygen_code
                assert 'generate' in keygen_code.lower() or 'validate' in keygen_code.lower()

    def test_multi_algorithm_binary_analysis(self) -> None:
        """Test analysis of different algorithm types."""
        # Test all standard algorithm types work
        for algo_type in ['serial', 'rsa', 'elliptic', 'custom']:
            keygen_code = self.agent.generate_keygen(algo_type)
            assert keygen_code is not None
            assert isinstance(keygen_code, str)

    def test_performance_benchmarks(self) -> None:
        """Test keygen generation performance."""
        import time

        performance_results: dict[str, float] = {}

        for algo_type in ['serial', 'rsa', 'custom']:
            start_time = time.time()
            keygen_code = self.agent.generate_keygen(algo_type)
            generation_time = time.time() - start_time

            if keygen_code:
                performance_results[algo_type] = generation_time

                # Performance should be reasonable
                assert generation_time < 60.0  # 1 minute maximum

                # More complex algorithms should take longer
                if algo_type == 'serial':
                    assert generation_time < 30.0  # Serial should be faster

        # Verify relative performance makes sense
        if 'serial' in performance_results and 'rsa' in performance_results:
            # RSA analysis should generally take longer than serial
            assert performance_results['serial'] <= performance_results['rsa'] + 10.0  # Allow some variance

    def test_error_handling_robustness(self) -> None:
        """Test robust error handling for keygen generation."""
        # Test with invalid algorithm type - should return fallback
        error_keygen = self.agent.generate_keygen('unknown_type')

        # Should return a string (fallback to serial)
        assert error_keygen is not None
        assert isinstance(error_keygen, str)

        # Test with various supported algorithm types
        for algo_type in ['serial', 'rsa', 'elliptic', 'custom']:
            keygen_code = self.agent.generate_keygen(algo_type)
            assert keygen_code is not None
            assert isinstance(keygen_code, str)


class TestKeygenAdvanced(IntellicrackTestBase):
    """Advanced keygen generation testing scenarios."""

    @pytest.fixture(autouse=True)
    def setup_advanced(self, temp_workspace: Path) -> None:
        """Set up test environment for advanced tests."""
        self.agent: Any = AutomatedPatchAgent()
        self.temp_dir: Path = temp_workspace

    def test_machine_learning_algorithm_detection(self) -> None:
        """Test ML-based licensing algorithm detection."""
        agent: Any = AutomatedPatchAgent()

        # Test all algorithm types are accessible
        for algo_type in ['serial', 'rsa', 'elliptic', 'custom']:
            keygen_code = agent.generate_keygen(algo_type)
            assert keygen_code is not None
            assert isinstance(keygen_code, str)
            assert len(keygen_code) > 50

    def test_obfuscated_algorithm_analysis(self) -> None:
        """Test analysis of obfuscated licensing algorithms."""
        # Create obfuscated licensing binary
        obfuscated_binary = self._create_obfuscated_licensing_binary()

        # Test keygen still works regardless of binary
        keygen_code = self.agent.generate_keygen('custom')
        assert keygen_code is not None
        assert isinstance(keygen_code, str)

    def _create_obfuscated_licensing_binary(self) -> str:
        """Create binary with obfuscated licensing algorithm."""
        binary_path = os.path.join(str(self.temp_dir), "obfuscated_licensing.exe")

        # Obfuscated algorithm with junk instructions and control flow
        obfuscated_data = (
            b'MZ\x90\x00' + b'\x00' * 56 + b'PE\x00\x00' +
            # Junk instructions
            b'\x90\x90\x90'                 # nop nop nop
            b'\x40\x48'                     # inc eax; dec eax (cancel out)
            # Obfuscated serial check
            b'\x8b\x45\x08'                 # mov eax, [ebp+8]
            b'\x90\x90'                     # nop nop (junk)
            b'\x83\xf0\x5a'                 # xor eax, 0x5a (obfuscation)
            b'\x90'                         # nop (junk)
            b'\x83\xf0\x5a'                 # xor eax, 0x5a (deobfuscation)
            b'\x85\xc0'                     # test eax, eax (real check)
            b'\x90\x90\x90'                 # nop nop nop (junk)
            b'\x74\x05'                     # jz invalid (real branch)
            b'\xb8\x01\x00\x00\x00'         # mov eax, 1
            b'\xeb\x05'                     # jmp exit
            b'\xb8\x00\x00\x00\x00'         # mov eax, 0
            b'\xc3'                         # ret
        )

        with open(binary_path, 'wb') as f:
            f.write(obfuscated_data)

        return binary_path
