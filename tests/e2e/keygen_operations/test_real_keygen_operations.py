"""
Functional tests for Intellicrack's keygen operations.

This module contains comprehensive tests for keygen generation and validation functionality
in Intellicrack, including serial algorithm analysis, keygen template generation,
multi-algorithm keygen support, hardware-locked keygens, RSA-style implementations,
brute force resistance, pattern obfuscation, online activation systems, validation bypasses,
elliptic curve cryptography, anti-debugging integration, and ML-based pattern detection.
These tests ensure that keygen generation works effectively for various protection schemes.
"""

import os
import tempfile

import pytest

from intellicrack.ai.ai_script_generator import AIScriptGenerator
from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.core.app_context import AppContext
from intellicrack.core.exploitation.license_bypass_code_generator import LicenseBypassCodeGenerator
from intellicrack.plugins.radare2_modules.radare2_keygen_assistant import Radare2KeygenAssistant


class TestRealKeygenOperations:
    """Functional tests for REAL keygen generation and validation operations."""

    @pytest.fixture
    def protected_binary_with_serial_check(self):
        """Create REAL protected binary with serial number validation."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            # DOS Header
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 40
            dos_header += b'\x80\x00\x00\x00'
            dos_header += b'\x00' * 60

            # PE Signature
            pe_signature = b'PE\x00\x00'

            # COFF Header
            coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16

            # Optional Header
            optional_header = b'\x0b\x01\x0e\x00' + b'\x00' * 220

            # Section Headers
            text_section = b'.text\x00\x00\x00'
            text_section += b'\x00\x20\x00\x00'  # VirtualSize
            text_section += b'\x00\x10\x00\x00'  # VirtualAddress
            text_section += b'\x00\x20\x00\x00'  # SizeOfRawData
            text_section += b'\x00\x04\x00\x00'  # PointerToRawData
            text_section += b'\x00' * 12
            text_section += b'\x20\x00\x00\x60'  # Characteristics

            data_section = b'.data\x00\x00\x00'
            data_section += b'\x00\x10\x00\x00'
            data_section += b'\x00\x30\x00\x00'
            data_section += b'\x00\x10\x00\x00'
            data_section += b'\x00\x24\x00\x00'
            data_section += b'\x00' * 12
            data_section += b'\x40\x00\x00\xc0'

            # Serial validation code
            serial_code = b''

            # Function: validate_serial(char* serial)
            # Prologue
            serial_code += b'\x55'  # push ebp
            serial_code += b'\x8b\xec'  # mov ebp, esp
            serial_code += b'\x83\xec\x20'  # sub esp, 32

            # Get serial parameter
            serial_code += b'\x8b\x45\x08'  # mov eax, [ebp+8]
            serial_code += b'\x89\x45\xf0'  # mov [ebp-16], eax

            # Length check (must be 16 chars)
            serial_code += b'\x50'  # push eax
            serial_code += b'\xe8\x50\x00\x00\x00'  # call strlen
            serial_code += b'\x83\xc4\x04'  # add esp, 4
            serial_code += b'\x83\xf8\x10'  # cmp eax, 16
            serial_code += b'\x75\x40'  # jne invalid

            # Algorithm: sum = 0
            serial_code += b'\x33\xc0'  # xor eax, eax
            serial_code += b'\x89\x45\xfc'  # mov [ebp-4], eax

            # Loop through characters
            serial_code += b'\x33\xc9'  # xor ecx, ecx (i = 0)
            # loop_start:
            serial_code += b'\x83\xf9\x10'  # cmp ecx, 16
            serial_code += b'\x7d\x20'  # jge check_sum

            # Get char at position i
            serial_code += b'\x8b\x55\xf0'  # mov edx, [ebp-16]
            serial_code += b'\x0f\xb6\x04\x0a'  # movzx eax, byte [edx+ecx]

            # Complex algorithm
            serial_code += b'\x6b\xc0\x0d'  # imul eax, 13
            serial_code += b'\x03\xc1'  # add eax, ecx
            serial_code += b'\x35\xef\xbe\xad\xde'  # xor eax, 0xDEADBEEF
            serial_code += b'\xc1\xc0\x05'  # rol eax, 5

            # Add to sum
            serial_code += b'\x03\x45\xfc'  # add eax, [ebp-4]
            serial_code += b'\x89\x45\xfc'  # mov [ebp-4], eax

            # Increment counter
            serial_code += b'\x41'  # inc ecx
            serial_code += b'\xeb\xde'  # jmp loop_start

            # check_sum:
            serial_code += b'\x8b\x45\xfc'  # mov eax, [ebp-4]
            serial_code += b'\x3d\x37\x13\x00\x00'  # cmp eax, 0x1337
            serial_code += b'\x75\x07'  # jne invalid

            # Valid serial
            serial_code += b'\xb8\x01\x00\x00\x00'  # mov eax, 1
            serial_code += b'\xeb\x05'  # jmp done

            # invalid:
            serial_code += b'\xb8\x00\x00\x00\x00'  # mov eax, 0

            # done:
            serial_code += b'\x8b\xe5'  # mov esp, ebp
            serial_code += b'\x5d'  # pop ebp
            serial_code += b'\xc3'  # ret

            # Generate hardware ID function
            serial_code += b'\x90' * 16  # padding

            # Function: get_hardware_id()
            serial_code += b'\x55'  # push ebp
            serial_code += b'\x8b\xec'  # mov ebp, esp

            # Simulate hardware ID generation
            serial_code += b'\xe8\x00\x00\x00\x00'  # call GetVolumeInformation
            serial_code += b'\x35\x12\x34\x56\x78'  # xor eax, 0x78563412
            serial_code += b'\xc1\xc8\x08'  # ror eax, 8

            serial_code += b'\x8b\xe5'  # mov esp, ebp
            serial_code += b'\x5d'  # pop ebp
            serial_code += b'\xc3'  # ret

            # Production RSA signature verification system
            serial_code += b'\x90' * 16  # padding

            # Function: rsa_verify(serial, signature, public_key, key_size)
            # Returns: 1 if valid, 0 if invalid
            serial_code += b'\x55'  # push ebp
            serial_code += b'\x8b\xec'  # mov ebp, esp
            serial_code += b'\x83\xec\x20'  # sub esp, 32 (local variables)

            # Save registers
            serial_code += b'\x53'  # push ebx
            serial_code += b'\x56'  # push esi
            serial_code += b'\x57'  # push edi

            # Load parameters: serial=[ebp+8], signature=[ebp+12], pubkey=[ebp+16], keysize=[ebp+20]
            serial_code += b'\x8b\x45\x08'  # mov eax, [ebp+8] (serial data)
            serial_code += b'\x8b\x5d\x0c'  # mov ebx, [ebp+12] (signature)
            serial_code += b'\x8b\x4d\x10'  # mov ecx, [ebp+16] (public key)
            serial_code += b'\x8b\x55\x14'  # mov edx, [ebp+20] (key size in bits)

            # RSA public key components (realistic 1024-bit example)
            # n = modulus (stored at [ecx])
            # e = public exponent (typically 65537 = 0x10001)
            serial_code += b'\xb8\x01\x00\x01\x00'  # mov eax, 0x10001 (standard RSA exponent)
            serial_code += b'\x89\x45\xf0'  # mov [ebp-16], eax (store exponent)

            # Perform modular exponentiation: signature^e mod n
            # This implements binary exponentiation algorithm

            # Initialize result = 1
            serial_code += b'\xb8\x01\x00\x00\x00'  # mov eax, 1
            serial_code += b'\x89\x45\xf4'  # mov [ebp-12], eax (result)

            # Initialize base = signature
            serial_code += b'\x89\x5d\xf8'  # mov [ebp-8], ebx (base)

            # Initialize exponent = e
            serial_code += b'\x8b\x45\xf0'  # mov eax, [ebp-16] (exponent)
            serial_code += b'\x89\x45\xfc'  # mov [ebp-4], eax (current exponent)

            # Binary exponentiation loop
            # modexp_loop:
            serial_code += b'\x83\x7d\xfc\x00'  # cmp dword [ebp-4], 0 (exponent == 0?)
            serial_code += b'\x74\x2a'  # je modexp_done (jump if exponent is 0)

            # Check if exponent is odd
            serial_code += b'\x8b\x45\xfc'  # mov eax, [ebp-4] (exponent)
            serial_code += b'\xa8\x01'  # test al, 1 (check LSB)
            serial_code += b'\x74\x0f'  # jz skip_multiply (jump if even)

            # result = (result * base) mod n
            serial_code += b'\x8b\x45\xf4'  # mov eax, [ebp-12] (result)
            serial_code += b'\xf7\x65\xf8'  # mul dword [ebp-8] (result * base)
            serial_code += b'\x31\xd2'  # xor edx, edx (clear high bits for division)
            serial_code += b'\xf7\x31'  # div dword [ecx] (mod n)
            serial_code += b'\x89\x55\xf4'  # mov [ebp-12], edx (store result)

            # skip_multiply:
            # base = (base * base) mod n
            serial_code += b'\x8b\x45\xf8'  # mov eax, [ebp-8] (base)
            serial_code += b'\xf7\x65\xf8'  # mul dword [ebp-8] (base * base)
            serial_code += b'\x31\xd2'  # xor edx, edx
            serial_code += b'\xf7\x31'  # div dword [ecx] (mod n)
            serial_code += b'\x89\x55\xf8'  # mov [ebp-8], edx (store new base)

            # exponent >>= 1
            serial_code += b'\xd1\x6d\xfc'  # shr dword [ebp-4], 1 (exponent /= 2)
            serial_code += b'\xeb\xd1'  # jmp modexp_loop

            # modexp_done:
            # Now [ebp-12] contains signature^e mod n (decrypted signature)

            # PKCS#1 v1.5 padding verification
            # Expected format: 0x00 0x01 0xFF...0xFF 0x00 ASN.1 DigestInfo Hash
            serial_code += b'\x8b\x45\xf4'  # mov eax, [ebp-12] (decrypted signature)

            # Check first byte = 0x00
            serial_code += b'\x8a\x10'  # mov dl, [eax] (first byte)
            serial_code += b'\x80\xfa\x00'  # cmp dl, 0x00
            serial_code += b'\x75\x3a'  # jne invalid_signature

            # Check second byte = 0x01
            serial_code += b'\x8a\x50\x01'  # mov dl, [eax+1] (second byte)
            serial_code += b'\x80\xfa\x01'  # cmp dl, 0x01
            serial_code += b'\x75\x33'  # jne invalid_signature

            # Verify padding bytes (0xFF sequence)
            serial_code += b'\xbe\x02\x00\x00\x00'  # mov esi, 2 (start index)
            serial_code += b'\xb9\x00\x00\x00\x00'  # mov ecx, 0 (padding counter)

            # padding_loop:
            serial_code += b'\x8a\x14\x30'  # mov dl, [eax+esi] (current byte)
            serial_code += b'\x80\xfa\xff'  # cmp dl, 0xFF
            serial_code += b'\x75\x06'  # jne check_separator
            serial_code += b'\x46'  # inc esi
            serial_code += b'\x41'  # inc ecx
            serial_code += b'\xeb\xf5'  # jmp padding_loop

            # check_separator:
            serial_code += b'\x80\xfa\x00'  # cmp dl, 0x00 (separator)
            serial_code += b'\x75\x1c'  # jne invalid_signature

            # Verify minimum padding length (at least 8 bytes of 0xFF)
            serial_code += b'\x83\xf9\x08'  # cmp ecx, 8
            serial_code += b'\x7c\x16'  # jl invalid_signature

            # Hash comparison (simplified - compare remaining bytes with expected hash)
            serial_code += b'\x46'  # inc esi (point to hash)
            serial_code += b'\x8b\x7d\x08'  # mov edi, [ebp+8] (original serial)

            # Compare hash bytes (simplified 20-byte SHA-1 hash comparison)
            serial_code += b'\xb9\x14\x00\x00\x00'  # mov ecx, 20 (hash length)
            serial_code += b'\xf3\xa6'  # repe cmpsb (compare strings)
            serial_code += b'\x75\x07'  # jne invalid_signature

            # valid_signature:
            serial_code += b'\xb8\x01\x00\x00\x00'  # mov eax, 1 (valid)
            serial_code += b'\xeb\x05'  # jmp cleanup

            # invalid_signature:
            serial_code += b'\xb8\x00\x00\x00\x00'  # mov eax, 0 (invalid)

            # cleanup:
            # Restore registers
            serial_code += b'\x5f'  # pop edi
            serial_code += b'\x5e'  # pop esi
            serial_code += b'\x5b'  # pop ebx

            serial_code += b'\x8b\xe5'  # mov esp, ebp
            serial_code += b'\x5d'  # pop ebp
            serial_code += b'\xc3'  # ret

            # Pad to section size
            serial_code += b'\x90' * (8192 - len(serial_code))

            # Data section with strings
            data_content = b'strlen\x00GetVolumeInformation\x00'
            data_content += b'Enter Serial Number: \x00'
            data_content += b'Invalid Serial!\x00'
            data_content += b'Serial Accepted!\x00'
            data_content += b'XXXX-XXXX-XXXX-XXXX\x00'
            data_content += b'\x00' * (4096 - len(data_content))

            temp_file.write(dos_header + pe_signature + coff_header + optional_header +
                          text_section + data_section + serial_code + data_content)
            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except OSError:
            # File already deleted or permission error
            pass

    @pytest.fixture
    def app_context(self):
        """Create REAL application context."""
        context = AppContext()
        context.initialize()
        return context

    @pytest.fixture
    def keygen_patterns(self):
        """REAL keygen algorithm patterns."""
        return {
            'simple_xor': {
                'operations': ['xor'],
                'constants': [0xDEADBEEF],
                'example': lambda name: f"{name}-{hex(sum(ord(c) for c in name) ^ 0xDEADBEEF)[2:].upper()}"
            },
            'checksum_based': {
                'operations': ['add', 'mul', 'mod'],
                'constants': [13, 256, 0x1337],
                'example': lambda name: f"{name[:4].upper()}-{str(sum(ord(c)*13 for c in name) % 0x1337).zfill(4)}"
            },
            'rsa_style': {
                'operations': ['pow', 'mod'],
                'constants': [65, 273],  # e=65, n=273
                'example': lambda name: f"RSA-{str(pow(sum(ord(c) for c in name), 65, 273)).zfill(3)}"
            },
            'hardware_locked': {
                'operations': ['xor', 'ror', 'add'],
                'constants': [0x78563412],
                'example': lambda name, hwid=0x12345678: f"HW{hwid:08X}-{name[:4].upper()}"
            }
        }

    def test_real_serial_algorithm_analysis(self, protected_binary_with_serial_check, app_context):
        """Test REAL serial validation algorithm analysis."""
        analyzer = BinaryAnalyzer()
        keygen_assistant = Radare2KeygenAssistant()

        # Analyze binary
        analysis_results = analyzer.analyze_file(protected_binary_with_serial_check)
        assert analysis_results is not None, "Binary analysis must succeed"

        # Find serial validation functions
        functions = analysis_results.get('functions', [])
        serial_functions = []

        for func in functions:
            func_name = func.get('name', '').lower()
            if any(keyword in func_name for keyword in ['serial', 'validate', 'check', 'verify']):
                serial_functions.append(func)

        # Analyze serial validation logic
        serial_analysis = keygen_assistant.analyze_serial_validation(
            protected_binary_with_serial_check,
            serial_functions
        )

        assert serial_analysis is not None, "Serial analysis must return results"
        assert 'algorithm_type' in serial_analysis, "Must identify algorithm type"
        assert 'operations' in serial_analysis, "Must identify operations"
        assert 'constants' in serial_analysis, "Must extract constants"
        assert 'constraints' in serial_analysis, "Must identify constraints"

        # Verify algorithm detection
        operations = serial_analysis['operations']
        assert len(operations) > 0, "Must detect at least one operation"

        constants = serial_analysis['constants']
        assert len(constants) > 0, "Must extract at least one constant"

        # Check for common patterns
        algorithm_type = serial_analysis['algorithm_type']
        assert algorithm_type in ['checksum', 'xor_based', 'mathematical', 'rsa_style', 'custom'], \
            "Must classify algorithm type"

    def test_real_keygen_template_generation(self, protected_binary_with_serial_check, keygen_patterns, app_context):
        """Test REAL keygen template generation from analysis."""
        ai_generator = AIScriptGenerator(app_context)

        # Analyze the binary first
        algorithm_info = {
            'binary': protected_binary_with_serial_check,
            'algorithm_type': 'checksum_based',
            'operations': ['mul', 'add', 'xor', 'rol'],
            'constants': [13, 0xDEADBEEF, 5, 0x1337],
            'constraints': {
                'length': 16,
                'charset': 'alphanumeric',
                'format': 'XXXX-XXXX-XXXX-XXXX'
            }
        }

        # Generate keygen template
        keygen_result = ai_generator.generate_keygen_from_analysis(algorithm_info)
        assert keygen_result is not None, "Keygen generation must succeed"
        assert 'keygen_code' in keygen_result, "Must generate keygen code"
        assert 'algorithm_notes' in keygen_result, "Must include algorithm notes"
        assert 'test_serials' in keygen_result, "Must generate test serials"

        keygen_code = keygen_result['keygen_code']
        assert len(keygen_code) > 0, "Keygen code must not be empty"
        assert 'def generate_serial' in keygen_code, "Must have serial generation function"
        assert 'def validate_serial' in keygen_code, "Must have validation function"

        # Verify test serials
        test_serials = keygen_result['test_serials']
        assert isinstance(test_serials, list), "Test serials must be a list"
        assert len(test_serials) >= 3, "Must generate at least 3 test serials"

        for serial in test_serials:
            assert len(serial) == 19, "Serial must match format (16 chars + 3 dashes)"
            assert serial.count('-') == 3, "Serial must have correct format"

    def test_real_multi_algorithm_keygen(self, keygen_patterns, app_context):
        """Test REAL keygen for multiple algorithm types."""
        keygen_assistant = Radare2KeygenAssistant()

        test_cases = []

        # Test each algorithm pattern
        for algo_name, pattern in keygen_patterns.items():
            # Generate keygen for pattern
            keygen_config = {
                'algorithm_name': algo_name,
                'operations': pattern['operations'],
                'constants': pattern['constants'],
                'target_platform': 'windows',
                'output_format': 'python'
            }

            keygen_result = keygen_assistant.generate_multi_algorithm_keygen(keygen_config)
            assert keygen_result is not None, f"Keygen generation failed for {algo_name}"
            assert 'implementation' in keygen_result, f"Must have implementation for {algo_name}"
            assert 'complexity' in keygen_result, f"Must assess complexity for {algo_name}"

            implementation = keygen_result['implementation']
            assert len(implementation) > 0, f"Implementation must not be empty for {algo_name}"

            # Test the example function
            if 'example' in pattern:
                test_name = "TestUser"
                expected = pattern['example'](test_name)
                test_cases.append({
                    'algorithm': algo_name,
                    'input': test_name,
                    'expected_format': expected,
                    'implementation': implementation
                })

        # Verify all algorithms generated
        assert len(test_cases) == len(keygen_patterns), "Must generate keygen for all patterns"

    def test_real_hardware_locked_keygen(self, app_context):
        """Test REAL hardware-locked keygen generation."""
        keygen_assistant = Radare2KeygenAssistant()

        # Hardware ID sources
        hardware_sources = {
            'cpu_id': {'method': 'cpuid', 'registers': ['eax', 'ebx', 'ecx', 'edx']},
            'disk_serial': {'method': 'GetVolumeInformation', 'api': 'windows'},
            'mac_address': {'method': 'GetAdaptersInfo', 'api': 'windows'},
            'motherboard': {'method': 'WMI', 'query': 'Win32_BaseBoard'}
        }

        # Generate hardware-locked keygen
        hw_keygen_config = {
            'hardware_sources': hardware_sources,
            'mixing_algorithm': 'xor_rotate',
            'user_input_required': True,
            'reversible': False
        }

        hw_keygen_result = keygen_assistant.generate_hardware_locked_keygen(hw_keygen_config)
        assert hw_keygen_result is not None, "Hardware keygen generation must succeed"
        assert 'collector_code' in hw_keygen_result, "Must generate hardware collector"
        assert 'generator_code' in hw_keygen_result, "Must generate key generator"
        assert 'validator_code' in hw_keygen_result, "Must generate validator"

        collector_code = hw_keygen_result['collector_code']
        assert 'GetVolumeInformation' in collector_code or 'cpuid' in collector_code, \
            "Collector must use hardware APIs"

        generator_code = hw_keygen_result['generator_code']
        assert 'hardware_id' in generator_code, "Generator must use hardware ID"
        assert 'user_name' in generator_code or 'user_input' in generator_code, \
            "Generator must combine user input"

    def test_real_rsa_style_keygen(self, app_context):
        """Test REAL RSA-style keygen implementation."""
        keygen_assistant = Radare2KeygenAssistant()

        # RSA parameters (small for testing)
        rsa_params = {
            'p': 17,
            'q': 19,
            'e': 5,  # Public exponent
            'n': 323,  # p * q
            'd': 173  # Private exponent
        }

        # Generate RSA-style keygen
        rsa_config = {
            'key_size': 'small',  # For testing
            'parameters': rsa_params,
            'encoding': 'base32',
            'add_checksum': True
        }

        rsa_keygen_result = keygen_assistant.generate_rsa_keygen(rsa_config)
        assert rsa_keygen_result is not None, "RSA keygen generation must succeed"
        assert 'signing_function' in rsa_keygen_result, "Must have signing function"
        assert 'verification_function' in rsa_keygen_result, "Must have verification function"
        assert 'example_keys' in rsa_keygen_result, "Must generate example keys"

        # Test example key generation
        example_keys = rsa_keygen_result['example_keys']
        assert len(example_keys) >= 3, "Must generate multiple example keys"

        for key_info in example_keys:
            assert 'name' in key_info, "Key must have associated name"
            assert 'serial' in key_info, "Key must have serial"
            assert 'signature' in key_info, "Key must have signature"

            # Verify format
            serial = key_info['serial']
            assert len(serial) > 0, "Serial must not be empty"

    def test_real_keygen_brute_force_resistance(self, keygen_patterns, app_context):
        """Test REAL keygen resistance to brute force attacks."""
        keygen_assistant = Radare2KeygenAssistant()

        # Analyze brute force resistance
        for algo_name, _pattern in keygen_patterns.items():
            resistance_analysis = keygen_assistant.analyze_brute_force_resistance({
                'algorithm': algo_name,
                'key_space': 2**64 if 'rsa' in algo_name else 2**32,
                'constraints': {
                    'length': 16,
                    'charset_size': 36  # alphanumeric
                }
            })

            assert resistance_analysis is not None, f"Resistance analysis failed for {algo_name}"
            assert 'entropy_bits' in resistance_analysis, "Must calculate entropy"
            assert 'brute_force_time' in resistance_analysis, "Must estimate brute force time"
            assert 'recommendations' in resistance_analysis, "Must provide recommendations"

            entropy = resistance_analysis['entropy_bits']
            assert entropy > 0, f"Entropy must be positive for {algo_name}"

            # Check recommendations
            recommendations = resistance_analysis['recommendations']
            assert isinstance(recommendations, list), "Recommendations must be a list"

    def test_real_keygen_pattern_obfuscation(self, protected_binary_with_serial_check, app_context):
        """Test REAL keygen pattern obfuscation techniques."""
        shellcode_gen = LicenseBypassCodeGenerator()
        keygen_assistant = Radare2KeygenAssistant()

        # Original keygen algorithm
        original_keygen = """
def generate_key(name):
    sum_val = 0
    for i, char in enumerate(name):
        sum_val += ord(char) * 13
        sum_val ^= 0xDEADBEEF
        sum_val = ((sum_val << 5) | (sum_val >> 27)) & 0xFFFFFFFF
    return f"{name[:4]}-{sum_val:08X}"
"""

        # Obfuscate the keygen
        obfuscation_config = {
            'techniques': ['opaque_predicates', 'control_flow_flattening', 'constant_hiding'],
            'level': 'high',
            'preserve_functionality': True
        }

        obfuscated_result = keygen_assistant.obfuscate_keygen(original_keygen, obfuscation_config)
        assert obfuscated_result is not None, "Obfuscation must succeed"
        assert 'obfuscated_code' in obfuscated_result, "Must return obfuscated code"
        assert 'techniques_applied' in obfuscated_result, "Must list applied techniques"
        assert 'complexity_increase' in obfuscated_result, "Must measure complexity increase"

        obfuscated_code = obfuscated_result['obfuscated_code']
        assert len(obfuscated_code) > len(original_keygen), "Obfuscated code should be larger"
        assert '0xDEADBEEF' not in obfuscated_code, "Constants should be hidden"

        # Generate native code version
        native_result = shellcode_gen.generate_keygen_shellcode({
            'algorithm': original_keygen,
            'architecture': 'x86',
            'obfuscate': True
        })

        assert native_result is not None, "Native code generation must succeed"
        assert 'shellcode' in native_result, "Must generate shellcode"
        assert len(native_result['shellcode']) > 0, "Shellcode must not be empty"

    def test_real_online_activation_keygen(self, app_context):
        """Test REAL online activation system keygen."""
        keygen_assistant = Radare2KeygenAssistant()

        # Online activation configuration
        activation_config = {
            'server_url': 'https://license.example.com/activate',
            'protocol': 'https',
            'auth_method': 'challenge_response',
            'hardware_binding': True,
            'time_limited': True,
            'features': ['pro', 'enterprise', 'unlimited']
        }

        # Generate activation keygen system
        activation_result = keygen_assistant.generate_online_activation_system(activation_config)
        assert activation_result is not None, "Activation system generation must succeed"
        assert 'client_code' in activation_result, "Must generate client code"
        assert 'server_code' in activation_result, "Must generate server code"
        assert 'protocol_spec' in activation_result, "Must define protocol"

        client_code = activation_result['client_code']
        assert 'generate_request' in client_code, "Client must generate requests"
        assert 'validate_response' in client_code, "Client must validate responses"
        assert 'hardware_fingerprint' in client_code, "Client must collect hardware info"

        server_code = activation_result['server_code']
        assert 'process_activation' in server_code, "Server must process activations"
        assert 'generate_license' in server_code, "Server must generate licenses"
        assert 'verify_hardware' in server_code, "Server must verify hardware"

        # Test protocol specification
        protocol = activation_result['protocol_spec']
        assert 'request_format' in protocol, "Protocol must define request format"
        assert 'response_format' in protocol, "Protocol must define response format"
        assert 'error_codes' in protocol, "Protocol must define error codes"

    def test_real_keygen_validation_bypass(self, protected_binary_with_serial_check, app_context):
        """Test REAL keygen validation bypass generation."""
        analyzer = BinaryAnalyzer()
        keygen_assistant = Radare2KeygenAssistant()

        # Analyze serial check locations
        check_locations = analyzer.find_serial_checks(protected_binary_with_serial_check)
        assert check_locations is not None, "Must find serial check locations"

        # Generate bypass instead of keygen
        bypass_config = {
            'binary': protected_binary_with_serial_check,
            'check_locations': check_locations,
            'bypass_method': 'patch',
            'preserve_functionality': True
        }

        bypass_result = keygen_assistant.generate_validation_bypass(bypass_config)
        assert bypass_result is not None, "Bypass generation must succeed"
        assert 'patch_locations' in bypass_result, "Must identify patch locations"
        assert 'patch_bytes' in bypass_result, "Must provide patch bytes"
        assert 'bypass_script' in bypass_result, "Must generate bypass script"

        # Verify patch locations
        patch_locations = bypass_result['patch_locations']
        assert len(patch_locations) > 0, "Must identify at least one patch location"

        for location in patch_locations:
            assert 'offset' in location, "Patch must have offset"
            assert 'original' in location, "Patch must show original bytes"
            assert 'patched' in location, "Patch must show new bytes"
            assert 'description' in location, "Patch must have description"

    def test_real_elliptic_curve_keygen(self, app_context):
        """Test REAL elliptic curve based keygen."""
        keygen_assistant = Radare2KeygenAssistant()

        # ECC parameters
        ecc_config = {
            'curve': 'secp256k1',  # Bitcoin curve
            'hash_function': 'sha256',
            'encoding': 'base58',
            'add_checksum': True
        }

        # Generate ECC keygen
        ecc_result = keygen_assistant.generate_ecc_keygen(ecc_config)
        assert ecc_result is not None, "ECC keygen generation must succeed"
        assert 'key_generation' in ecc_result, "Must have key generation code"
        assert 'signature_generation' in ecc_result, "Must have signature code"
        assert 'verification' in ecc_result, "Must have verification code"
        assert 'example_keys' in ecc_result, "Must generate examples"

        # Test example generation
        examples = ecc_result['example_keys']
        assert len(examples) >= 2, "Must generate multiple examples"

        for example in examples:
            assert 'private_key' in example, "Must have private key"
            assert 'public_key' in example, "Must have public key"
            assert 'license_key' in example, "Must have license key"

            # Verify format
            license_key = example['license_key']
            assert len(license_key) > 20, "ECC keys should be reasonably long"
            assert all(c in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in license_key), \
                "Should use base58 encoding"

    def test_real_keygen_anti_debugging_integration(self, app_context):
        """Test REAL keygen with anti-debugging protection."""
        keygen_assistant = Radare2KeygenAssistant()
        shellcode_gen = LicenseBypassCodeGenerator()

        # Generate protected keygen
        protected_config = {
            'base_algorithm': 'checksum_xor',
            'protections': [
                'anti_debug_checks',
                'timing_checks',
                'integrity_checks',
                'anti_hook'
            ],
            'false_paths': 3,
            'obfuscation_level': 'high'
        }

        protected_result = keygen_assistant.generate_protected_keygen(protected_config)
        assert protected_result is not None, "Protected keygen generation must succeed"
        assert 'protected_code' in protected_result, "Must generate protected code"
        assert 'protection_layers' in protected_result, "Must document protections"
        assert 'bypass_difficulty' in protected_result, "Must assess bypass difficulty"

        # Generate native protected version
        native_protected = shellcode_gen.generate_protected_keygen_stub({
            'keygen_logic': protected_result['protected_code'],
            'anti_debug': True,
            'anti_vm': True,
            'polymorphic': True
        })

        assert native_protected is not None, "Native protection must succeed"
        assert 'stub_code' in native_protected, "Must generate stub code"
        assert len(native_protected['stub_code']) > 100, "Protected stub should be substantial"

        # Verify protection features
        protection_layers = protected_result['protection_layers']
        assert len(protection_layers) >= len(protected_config['protections']), \
            "All protections should be applied"

        for protection in protection_layers:
            assert 'type' in protection, "Protection must have type"
            assert 'implementation' in protection, "Protection must be implemented"
            assert 'bypass_resistance' in protection, "Must assess bypass resistance"

    def test_real_keygen_machine_learning_detection(self, keygen_patterns, app_context):
        """Test REAL ML-based keygen pattern detection."""
        keygen_assistant = Radare2KeygenAssistant()

        # Prepare training data from patterns
        training_samples = []
        for algo_name, pattern in keygen_patterns.items():
            # Generate sample serials
            test_names = ['Alice', 'Bob', 'Charlie', 'David', 'Eve']
            for name in test_names:
                if 'example' in pattern:
                    serial = pattern['example'](name)
                    training_samples.append({
                        'input': name,
                        'output': serial,
                        'algorithm': algo_name
                    })

        # Train ML model to detect patterns
        ml_config = {
            'model_type': 'pattern_classifier',
            'features': ['length', 'charset', 'entropy', 'structure'],
            'training_samples': training_samples
        }

        ml_result = keygen_assistant.train_keygen_detector(ml_config)
        assert ml_result is not None, "ML training must succeed"
        assert 'model_accuracy' in ml_result, "Must report model accuracy"
        assert 'feature_importance' in ml_result, "Must show feature importance"
        assert 'detection_rules' in ml_result, "Must generate detection rules"

        # Test pattern detection
        test_serial = "TEST-1234ABCD"
        detection = keygen_assistant.detect_keygen_pattern(test_serial, ml_result['model'])
        assert detection is not None, "Pattern detection must work"
        assert 'algorithm_type' in detection, "Must predict algorithm type"
        assert 'confidence' in detection, "Must provide confidence score"
        assert 'features_detected' in detection, "Must show detected features"
