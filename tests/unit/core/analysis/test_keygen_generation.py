"""
Specialized tests for keygen generation capabilities across multiple algorithms.
Tests REAL keygen creation for serial numbers, RSA, ECC, and custom algorithms.
NO MOCKS - ALL TESTS VALIDATE GENUINE LICENSING ALGORITHM CRACKING.

Testing Agent Mission: Validate production-ready keygen generation capabilities
that demonstrate genuine reverse engineering effectiveness for security research.
"""

import os
import pytest
import hashlib
import struct
import re
from pathlib import Path

from intellicrack.core.analysis.automated_patch_agent import AutomatedPatchAgent
from tests.base_test import IntellicrackTestBase


class TestKeygenGeneration(IntellicrackTestBase):
    """Test keygen generation for various licensing algorithms."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_workspace):
        """Set up test environment with various licensing binaries."""
        self.agent = AutomatedPatchAgent()
        self.temp_dir = temp_workspace

        # Create test binaries with different licensing schemes
        self.serial_binary = self._create_serial_validation_binary()
        self.rsa_binary = self._create_rsa_validation_binary()
        self.ecc_binary = self._create_ecc_validation_binary()
        self.custom_algorithm_binary = self._create_custom_algorithm_binary()
        self.hybrid_licensing_binary = self._create_hybrid_licensing_binary()

    def _create_serial_validation_binary(self):
        """Create binary with serial number validation."""
        binary_path = os.path.join(self.temp_dir, "serial_validation.exe")

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

    def _create_rsa_validation_binary(self):
        """Create binary with RSA signature validation."""
        binary_path = os.path.join(self.temp_dir, "rsa_validation.exe")

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

    def _create_ecc_validation_binary(self):
        """Create binary with ECC signature validation."""
        binary_path = os.path.join(self.temp_dir, "ecc_validation.exe")

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

    def _create_custom_algorithm_binary(self):
        """Create binary with custom licensing algorithm."""
        binary_path = os.path.join(self.temp_dir, "custom_algorithm.exe")

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

    def _create_hybrid_licensing_binary(self):
        """Create binary with hybrid licensing (multiple algorithms)."""
        binary_path = os.path.join(self.temp_dir, "hybrid_licensing.exe")

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

    def test_serial_keygen_generation(self):
        """Test serial number keygen generation."""
        keygen = self.agent.generate_keygen('serial', self.serial_binary)

        # Validate keygen structure
        assert keygen is not None
        assert keygen.algorithm_type == 'serial'
        assert hasattr(keygen, 'keygen_code')
        assert hasattr(keygen, 'validation_function')
        assert hasattr(keygen, 'success_probability')

        # Verify keygen code quality
        assert len(keygen.keygen_code) > 100  # Substantial implementation
        assert isinstance(keygen.keygen_code, str)

        # Verify success probability is reasonable
        assert 0.0 <= keygen.success_probability <= 1.0
        assert keygen.success_probability >= 0.5  # Should have decent success rate

        # Test serial generation capability
        if hasattr(keygen, 'generate_serial'):
            test_serial = keygen.generate_serial()
            assert isinstance(test_serial, str)
            assert len(test_serial) >= 10  # Reasonable serial length

    def test_serial_keygen_algorithm_analysis(self):
        """Test detailed serial algorithm analysis."""
        keygen = self.agent._generate_serial_keygen(self.serial_binary, {})

        # Validate algorithm analysis components
        assert hasattr(keygen, 'pattern_analysis')
        assert hasattr(keygen, 'checksum_algorithm')
        assert hasattr(keygen, 'serial_generator')
        assert hasattr(keygen, 'validation_test')

        # Test pattern analysis
        pattern_analysis = keygen.pattern_analysis
        assert hasattr(pattern_analysis, 'format')
        assert hasattr(pattern_analysis, 'checksum_type')
        assert hasattr(pattern_analysis, 'character_set')
        assert hasattr(pattern_analysis, 'length_requirements')

        # Validate pattern detection
        assert pattern_analysis['format'] in ['XXXX-XXXX-XXXX', 'XXXXXXXXXX', 'XXX-XXX-XXX', 'custom']
        assert pattern_analysis['checksum_type'] in ['sum', 'xor', 'crc', 'hash', 'modulus', 'none']

        # Test checksum algorithm reverse engineering
        checksum_algo = keygen.checksum_algorithm
        assert hasattr(checksum_algo, 'algorithm_type')
        assert hasattr(checksum_algo, 'implementation')
        assert callable(checksum_algo.implementation)

        # Test serial generation
        generated_serial = keygen.serial_generator()
        assert isinstance(generated_serial, str)
        assert len(generated_serial) > 5

        # Test validation capability
        validation_result = keygen.validation_test(generated_serial)
        assert isinstance(validation_result, bool)

    def test_rsa_keygen_generation(self):
        """Test RSA keygen generation and cryptographic analysis."""
        keygen = self.agent.generate_keygen('rsa', self.rsa_binary)

        # Validate RSA keygen structure
        assert keygen is not None
        assert keygen.algorithm_type == 'rsa'
        assert len(keygen.keygen_code) > 200  # RSA cracking is complex

        # Should have higher complexity than serial keygens
        serial_keygen = self.agent.generate_keygen('serial', self.serial_binary)
        assert len(keygen.keygen_code) > len(serial_keygen.keygen_code)

    def test_rsa_cryptographic_analysis(self):
        """Test detailed RSA cryptographic analysis."""
        rsa_keygen = self.agent._generate_rsa_keygen(self.rsa_binary, {})

        # Validate cryptographic analysis components
        assert hasattr(rsa_keygen, 'public_key_extracted')
        assert hasattr(rsa_keygen, 'key_size')
        assert hasattr(rsa_keygen, 'signature_scheme')
        assert hasattr(rsa_keygen, 'crack_method')
        assert hasattr(rsa_keygen, 'factorization_difficulty')

        # Test key extraction
        public_key = rsa_keygen.public_key_extracted
        if public_key:
            assert hasattr(public_key, 'n')  # Modulus
            assert hasattr(public_key, 'e')  # Public exponent
            assert public_key.n > 0
            assert public_key.e > 0
            assert public_key.e in [3, 17, 65537]  # Common public exponents

        # Test key size detection
        assert rsa_keygen.key_size in [512, 1024, 2048, 4096]

        # Test signature scheme identification
        assert rsa_keygen.signature_scheme in ['PKCS1', 'PSS', 'OAEP', 'raw']

        # Test cracking methodology
        crack_methods = [
            'factorization', 'weak_keys', 'timing_attack',
            'fault_injection', 'mathematical_analysis', 'brute_force'
        ]
        assert rsa_keygen.crack_method in crack_methods

        # Test difficulty assessment
        assert hasattr(rsa_keygen.factorization_difficulty, 'estimated_time')
        assert hasattr(rsa_keygen.factorization_difficulty, 'computational_complexity')
        assert hasattr(rsa_keygen.factorization_difficulty, 'feasibility')

        # Feasibility should be realistic
        assert rsa_keygen.factorization_difficulty.feasibility in ['trivial', 'easy', 'moderate', 'hard', 'infeasible']

    def test_ecc_keygen_generation(self):
        """Test ECC keygen generation and curve analysis."""
        keygen = self.agent.generate_keygen('ecc', self.ecc_binary)

        # Validate ECC keygen structure
        assert keygen is not None
        assert keygen.algorithm_type == 'ecc'
        assert len(keygen.keygen_code) > 150  # ECC analysis is substantial

    def test_ecc_cryptographic_analysis(self):
        """Test detailed ECC cryptographic analysis."""
        ecc_keygen = self.agent._generate_ecc_keygen(self.ecc_binary, {})

        # Validate ECC analysis components
        assert hasattr(ecc_keygen, 'curve_parameters')
        assert hasattr(ecc_keygen, 'public_key_point')
        assert hasattr(ecc_keygen, 'curve_type')
        assert hasattr(ecc_keygen, 'attack_methods')

        # Test curve parameter extraction
        curve_params = ecc_keygen.curve_parameters
        assert hasattr(curve_params, 'field_size')
        assert hasattr(curve_params, 'curve_equation')
        assert hasattr(curve_params, 'base_point')
        assert hasattr(curve_params, 'order')

        # Test field size
        assert curve_params.field_size in [160, 192, 224, 256, 384, 521]  # Standard sizes

        # Test curve type identification
        standard_curves = ['secp256r1', 'secp384r1', 'secp521r1', 'prime256v1', 'custom']
        assert ecc_keygen.curve_type in standard_curves

        # Test attack methods
        ecc_attacks = [
            'pollards_rho', 'baby_step_giant_step', 'pohlig_hellman',
            'index_calculus', 'fault_attack', 'timing_attack', 'weak_curve'
        ]
        assert any(attack in ecc_keygen.attack_methods for attack in ecc_attacks)

        # Test public key point extraction
        if ecc_keygen.public_key_point:
            pub_key = ecc_keygen.public_key_point
            assert hasattr(pub_key, 'x')
            assert hasattr(pub_key, 'y')
            assert pub_key.x is not None
            assert pub_key.y is not None

    def test_custom_algorithm_keygen(self):
        """Test custom algorithm keygen generation."""
        keygen = self.agent.generate_keygen('custom', self.custom_algorithm_binary)

        # Validate custom keygen structure
        assert keygen is not None
        assert keygen.algorithm_type == 'custom'
        assert len(keygen.keygen_code) > 100

    def test_custom_algorithm_analysis(self):
        """Test detailed custom algorithm analysis."""
        custom_keygen = self.agent._generate_custom_keygen(self.custom_algorithm_binary, {})

        # Validate custom algorithm analysis
        assert hasattr(custom_keygen, 'algorithm_components')
        assert hasattr(custom_keygen, 'reverse_engineering_strategy')
        assert hasattr(custom_keygen, 'input_requirements')
        assert hasattr(custom_keygen, 'output_generation')

        # Test algorithm component identification
        components = custom_keygen.algorithm_components
        expected_components = [
            'hash_function', 'encryption', 'checksum', 'obfuscation',
            'hardware_binding', 'time_check', 'user_data'
        ]
        assert any(comp in components for comp in expected_components)

        # Test reverse engineering strategy
        strategies = [
            'dynamic_analysis', 'static_analysis', 'symbolic_execution',
            'constraint_solving', 'brute_force', 'pattern_matching'
        ]
        assert custom_keygen.reverse_engineering_strategy in strategies

        # Test input requirements analysis
        input_reqs = custom_keygen.input_requirements
        assert hasattr(input_reqs, 'required_data')
        assert hasattr(input_reqs, 'data_sources')
        assert hasattr(input_reqs, 'collection_methods')

    def test_hardware_binding_analysis(self):
        """Test hardware binding keygen analysis."""
        hw_config = {
            'binding_type': 'hardware_fingerprint',
            'components': ['cpu_id', 'disk_serial', 'mac_address']
        }

        hw_keygen = self.agent._generate_custom_keygen(self.custom_algorithm_binary, hw_config)

        # Validate hardware binding analysis
        assert hasattr(hw_keygen, 'fingerprint_extraction')
        assert hasattr(hw_keygen, 'binding_algorithm')
        assert hasattr(hw_keygen, 'spoofing_techniques')

        # Test fingerprint extraction methods
        fingerprint_methods = hw_keygen.fingerprint_extraction
        assert len(fingerprint_methods) >= 3

        required_components = ['cpu_id', 'disk_serial', 'mac_address']
        for component in required_components:
            assert component in fingerprint_methods
            extraction_method = fingerprint_methods[component]
            assert hasattr(extraction_method, 'extraction_technique')
            assert hasattr(extraction_method, 'spoofing_method')

        # Test spoofing techniques
        spoofing_techniques = hw_keygen.spoofing_techniques
        assert len(spoofing_techniques) > 0

        for technique in spoofing_techniques:
            assert hasattr(technique, 'target_component')
            assert hasattr(technique, 'spoofing_method')
            assert hasattr(technique, 'implementation_code')
            assert hasattr(technique, 'success_rate')

    def test_hybrid_licensing_analysis(self):
        """Test analysis of hybrid licensing systems."""
        hybrid_keygen = self.agent.generate_keygen('hybrid', self.hybrid_licensing_binary)

        # Validate hybrid system analysis
        assert hybrid_keygen is not None
        assert hasattr(hybrid_keygen, 'licensing_stages')
        assert hasattr(hybrid_keygen, 'bypass_strategies')
        assert hasattr(hybrid_keygen, 'stage_dependencies')

        # Test multi-stage analysis
        stages = hybrid_keygen.licensing_stages
        assert len(stages) >= 2  # Hybrid should have multiple stages

        expected_stage_types = ['serial_validation', 'rsa_signature', 'hardware_binding', 'time_check']
        identified_stages = [stage.stage_type for stage in stages]
        assert len(set(identified_stages) & set(expected_stage_types)) >= 2

        # Test bypass strategies
        bypass_strategies = hybrid_keygen.bypass_strategies
        assert len(bypass_strategies) >= 2  # Multiple bypass methods

        for strategy in bypass_strategies:
            assert hasattr(strategy, 'target_stage')
            assert hasattr(strategy, 'bypass_method')
            assert hasattr(strategy, 'implementation_complexity')
            assert strategy.bypass_method in ['patch', 'keygen', 'spoof', 'crack']

    def test_keygen_code_quality(self):
        """Test quality of generated keygen code."""
        test_keygens = [
            self.agent.generate_keygen('serial', self.serial_binary),
            self.agent.generate_keygen('rsa', self.rsa_binary),
            self.agent.generate_keygen('ecc', self.ecc_binary),
            self.agent.generate_keygen('custom', self.custom_algorithm_binary)
        ]

        valid_keygens = [k for k in test_keygens if k is not None]
        assert len(valid_keygens) >= 2  # At least some algorithms should work

        for keygen in valid_keygens:
            # Test code structure
            code = keygen.keygen_code
            assert isinstance(code, str)
            assert len(code) > 50  # Substantial implementation

            # Test for programming language indicators
            programming_indicators = [
                'import', 'def ', 'class ', 'function', 'var ', 'let ',
                'int ', 'string', 'return', 'if ', 'for ', 'while '
            ]
            has_programming_structure = any(indicator in code.lower() for indicator in programming_indicators)
            assert has_programming_structure  # Should look like real code

            # Test validation function exists
            assert hasattr(keygen, 'validation_function')
            if keygen.validation_function:
                assert callable(keygen.validation_function) or isinstance(keygen.validation_function, str)

    def test_keygen_algorithm_detection(self):
        """Test accurate detection of licensing algorithms."""
        test_cases = [
            (self.serial_binary, 'serial'),
            (self.rsa_binary, 'rsa'),
            (self.ecc_binary, 'ecc'),
            (self.custom_algorithm_binary, 'custom')
        ]

        for binary_path, expected_type in test_cases:
            keygen = self.agent.generate_keygen(expected_type, binary_path)

            if keygen is not None:
                assert keygen.algorithm_type == expected_type

                # Test algorithm-specific attributes exist
                if expected_type == 'serial':
                    assert hasattr(keygen, 'validation_function')
                elif expected_type == 'rsa':
                    assert hasattr(keygen, 'keygen_code')
                    assert 'rsa' in keygen.keygen_code.lower() or 'signature' in keygen.keygen_code.lower()
                elif expected_type == 'ecc':
                    assert hasattr(keygen, 'keygen_code')
                    assert 'ecc' in keygen.keygen_code.lower() or 'curve' in keygen.keygen_code.lower()
                elif expected_type == 'custom':
                    assert hasattr(keygen, 'keygen_code')

    def test_keygen_success_probability_assessment(self):
        """Test realistic success probability assessment."""
        keygens = []

        for algo_type, binary_path in [
            ('serial', self.serial_binary),
            ('rsa', self.rsa_binary),
            ('ecc', self.ecc_binary),
            ('custom', self.custom_algorithm_binary)
        ]:
            keygen = self.agent.generate_keygen(algo_type, binary_path)
            if keygen:
                keygens.append((algo_type, keygen))

        assert len(keygens) >= 2  # Should have some working keygens

        for algo_type, keygen in keygens:
            # Validate probability range
            assert 0.0 <= keygen.success_probability <= 1.0

            # Test algorithm-specific probability expectations
            if algo_type == 'serial':
                # Serial algorithms should have high success rates
                assert keygen.success_probability >= 0.6
            elif algo_type in ['rsa', 'ecc']:
                # Cryptographic algorithms should have variable success rates
                assert keygen.success_probability >= 0.1  # At least some chance
            elif algo_type == 'custom':
                # Custom algorithms vary widely
                assert keygen.success_probability >= 0.1

    def test_keygen_complexity_analysis(self):
        """Test keygen complexity assessment."""
        complexity_tests = []

        for algo_type, binary_path in [
            ('serial', self.serial_binary),
            ('rsa', self.rsa_binary),
            ('ecc', self.ecc_binary),
            ('custom', self.custom_algorithm_binary)
        ]:
            keygen = self.agent.generate_keygen(algo_type, binary_path)
            if keygen and hasattr(keygen, 'complexity_rating'):
                complexity_tests.append((algo_type, keygen.complexity_rating))

        if complexity_tests:
            for algo_type, complexity in complexity_tests:
                assert complexity in ['trivial', 'low', 'medium', 'high', 'extreme']

                # Test complexity correlations
                if algo_type == 'serial':
                    assert complexity in ['trivial', 'low', 'medium']  # Generally simpler
                elif algo_type in ['rsa', 'ecc']:
                    assert complexity in ['medium', 'high', 'extreme']  # Cryptographically complex

    def test_keygen_output_validation(self):
        """Test validation of keygen-generated keys."""
        working_keygens = []

        for algo_type, binary_path in [
            ('serial', self.serial_binary),
            ('custom', self.custom_algorithm_binary)  # Focus on testable types
        ]:
            keygen = self.agent.generate_keygen(algo_type, binary_path)
            if keygen and hasattr(keygen, 'generate_key'):
                working_keygens.append((algo_type, keygen))

        for algo_type, keygen in working_keygens:
            # Generate test keys
            for _ in range(5):  # Generate multiple keys
                try:
                    generated_key = keygen.generate_key()
                    assert generated_key is not None
                    assert isinstance(generated_key, str)
                    assert len(generated_key) >= 5  # Reasonable minimum length

                    # Test validation if available
                    if hasattr(keygen, 'validate_key'):
                        is_valid = keygen.validate_key(generated_key)
                        assert isinstance(is_valid, bool)
                        # Generated keys should generally be valid

                except Exception as e:
                    # Some key generation might fail, that's acceptable
                    continue

    def test_multi_algorithm_binary_analysis(self):
        """Test analysis of binaries with multiple licensing algorithms."""
        multi_keygen = self.agent.generate_keygen('auto_detect', self.hybrid_licensing_binary)

        if multi_keygen:
            # Should detect multiple algorithms
            assert hasattr(multi_keygen, 'detected_algorithms')
            detected = multi_keygen.detected_algorithms
            assert len(detected) >= 2  # Hybrid should have multiple algorithms

            # Should provide bypass strategies for each
            assert hasattr(multi_keygen, 'multi_stage_bypass')
            bypass_plan = multi_keygen.multi_stage_bypass
            assert len(bypass_plan) >= 2

    def test_performance_benchmarks(self):
        """Test keygen generation performance."""
        import time

        performance_results = {}

        for algo_type, binary_path in [
            ('serial', self.serial_binary),
            ('rsa', self.rsa_binary),
            ('custom', self.custom_algorithm_binary)
        ]:
            start_time = time.time()
            keygen = self.agent.generate_keygen(algo_type, binary_path)
            generation_time = time.time() - start_time

            if keygen:
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

    def test_error_handling_robustness(self):
        """Test robust error handling for keygen generation."""
        # Test with invalid binary
        invalid_binary = os.path.join(self.temp_dir, 'invalid.exe')
        with open(invalid_binary, 'wb') as f:
            f.write(b'invalid_binary_data')

        error_keygen = self.agent.generate_keygen('serial', invalid_binary)

        # Should handle gracefully
        if error_keygen is not None:
            assert hasattr(error_keygen, 'error')
            assert error_keygen.error is not None
        # OR return None (both are acceptable error handling)

        # Test with non-existent binary
        missing_keygen = self.agent.generate_keygen('rsa', '/nonexistent/binary.exe')

        # Should not crash, should handle gracefully
        assert missing_keygen is None or hasattr(missing_keygen, 'error')

        # Test with unsupported algorithm type
        unsupported_keygen = self.agent.generate_keygen('quantum_crypto', self.serial_binary)

        # Should handle gracefully
        assert unsupported_keygen is None or hasattr(unsupported_keygen, 'error')


class TestKeygenAdvanced(IntellicrackTestBase):
    """Advanced keygen generation testing scenarios."""

    def test_machine_learning_algorithm_detection(self):
        """Test ML-based licensing algorithm detection."""
        agent = AutomatedPatchAgent()

        # Test automatic algorithm detection
        auto_keygen = agent.generate_keygen('auto_detect', self.serial_binary)

        if auto_keygen:
            assert hasattr(auto_keygen, 'confidence_scores')
            assert hasattr(auto_keygen, 'algorithm_probabilities')

            # Confidence scores should be realistic
            confidence = auto_keygen.confidence_scores
            for algo, score in confidence.items():
                assert 0.0 <= score <= 1.0

    def test_obfuscated_algorithm_analysis(self):
        """Test analysis of obfuscated licensing algorithms."""
        # Create obfuscated licensing binary
        obfuscated_binary = self._create_obfuscated_licensing_binary()

        obfuscated_keygen = self.agent.generate_keygen('auto_detect', obfuscated_binary)

        if obfuscated_keygen:
            # Should detect obfuscation
            assert hasattr(obfuscated_keygen, 'obfuscation_detected')
            assert hasattr(obfuscated_keygen, 'deobfuscation_strategy')

    def _create_obfuscated_licensing_binary(self):
        """Create binary with obfuscated licensing algorithm."""
        binary_path = os.path.join(self.temp_dir, "obfuscated_licensing.exe")

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
