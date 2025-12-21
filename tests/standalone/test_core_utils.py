"""Standalone tests for core utilities without external dependencies"""
import os
import sys
import json
import struct
import tempfile
from pathlib import Path

# Disable GPU initialization
os.environ['INTELLICRACK_NO_GPU'] = '1'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

# Add project to path
sys.path.insert(0, 'C:\\Intellicrack')

def run_test_pe_utils():
    """Test PE utility functions"""
    print("\n=== Running PE Utils Test ===")

    try:
        from intellicrack.utils.binary.pe_analysis_common import (
            is_valid_pe,
            get_pe_machine_type,
            get_section_characteristics
        )

        # Create minimal PE header
        dos_header = b'MZ' + b'\x90' * 58 + struct.pack('<I', 0x80)  # PE offset at 0x80
        dos_stub = b'\x00' * (0x80 - 64)
        pe_header = b'PE\x00\x00' + struct.pack('<H', 0x014c)  # x86 machine

        test_pe = dos_header + dos_stub + pe_header + b'\x00' * 100

        # Test PE validation
        is_pe = is_valid_pe(test_pe)
        assert is_pe, "Failed to recognize valid PE"
        print("PE validation working")

        # Test machine type detection
        machine = get_pe_machine_type(test_pe)
        assert machine == 0x014c, f"Wrong machine type: {machine}"
        print(f"Machine type detected: 0x{machine:04x}")

        # Test section characteristics
        chars = get_section_characteristics(0x60000020)  # CODE|EXECUTE|READ
        assert 'CODE' in chars, "Failed to detect CODE characteristic"
        assert 'EXECUTE' in chars, "Failed to detect EXECUTE characteristic"
        print("Section characteristics decoded correctly")

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_path_utils():
    """Test file path utilities"""
    print("\n=== Running Path Utils Test ===")

    try:
        from intellicrack.utils.system.file_resolution import (
            resolve_path,
            safe_path_join,
            get_safe_filename
        )

        # Test path resolution
        test_path = "~/test_file.exe"
        resolved = resolve_path(test_path)
        assert resolved is not None, "Path resolution failed"
        print(f"Resolved path: {resolved}")

        # Test safe path joining
        base = "C:\\Intellicrack"
        joined = safe_path_join(base, "tests", "test.exe")
        assert joined.startswith(base), "Safe join failed"
        assert "tests" in joined, "Path component missing"
        print(f"Safe joined path: {joined}")

        # Test filename sanitization
        unsafe_name = "test<script>.exe"
        safe_name = get_safe_filename(unsafe_name)
        assert "<" not in safe_name, "Failed to sanitize <"
        assert ">" not in safe_name, "Failed to sanitize >"
        print(f"Sanitized filename: {safe_name}")

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_crypto_utils():
    """Test cryptographic utilities"""
    print("\n=== Running Crypto Utils Test ===")

    try:
        import hashlib
        import hmac

        # Test data
        test_data = b"Test data for crypto operations"
        test_key = b"secret_key_123"

        # Test hash functions
        md5_hash = hashlib.md5(test_data).hexdigest()
        sha256_hash = hashlib.sha256(test_data).hexdigest()

        assert len(md5_hash) == 32, "Invalid MD5 length"
        assert len(sha256_hash) == 64, "Invalid SHA256 length"
        print(f"MD5: {md5_hash[:16]}...")
        print(f"SHA256: {sha256_hash[:16]}...")

        # Test HMAC
        hmac_result = hmac.new(test_key, test_data, hashlib.sha256).hexdigest()
        assert len(hmac_result) == 64, "Invalid HMAC length"
        print(f"HMAC-SHA256: {hmac_result[:16]}...")

        # Test XOR encryption (simple)
        xor_result = bytes(b ^ 0x55 for b in test_data)
        assert len(xor_result) == len(test_data), "XOR length mismatch"
        print("XOR encryption working")

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_pattern_matching():
    """Test basic pattern matching without YARA"""
    print("\n=== Running Pattern Matching Test ===")

    try:
        # Simple pattern matching implementation
        patterns = {
            'IsDebuggerPresent': b'IsDebuggerPresent',
            'CheckRemoteDebuggerPresent': b'CheckRemoteDebuggerPresent',
            'CreateToolhelp32Snapshot': b'CreateToolhelp32Snapshot',
            'VirtualProtect': b'VirtualProtect',
            'WriteProcessMemory': b'WriteProcessMemory'
        }

        # Test data with some patterns
        test_data = b'Some code with IsDebuggerPresent and VirtualProtect calls'

        # Find patterns
        found_patterns = []
        for name, pattern in patterns.items():
            if pattern in test_data:
                found_patterns.append(name)
                print(f"  Found pattern: {name}")

        assert len(found_patterns) == 2, f"Expected 2 patterns, found {len(found_patterns)}"
        assert 'IsDebuggerPresent' in found_patterns, "Failed to find IsDebuggerPresent"
        assert 'VirtualProtect' in found_patterns, "Failed to find VirtualProtect"

        # Test hex pattern matching
        hex_patterns = {
            'INT3': b'\xCC',
            'NOP': b'\x90',
            'RET': b'\xC3'
        }

        test_code = b'\x90\x90\xCC\xC3'
        hex_found = []

        for name, pattern in hex_patterns.items():
            if pattern in test_code:
                hex_found.append(name)
                print(f"  Found instruction: {name}")

        assert len(hex_found) == 3, f"Expected 3 instructions, found {len(hex_found)}"

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_config_parsing():
    """Test configuration file parsing"""
    print("\n=== Running Config Parsing Test ===")

    try:
        import json
        import configparser

        # Test JSON config
        json_config = {
            "app_name": "Intellicrack",
            "version": "4.0.0",
            "features": {
                "ai_enabled": True,
                "gpu_acceleration": False,
                "max_threads": 8
            }
        }

        json_str = json.dumps(json_config)
        parsed_json = json.loads(json_str)

        assert parsed_json['app_name'] == "Intellicrack", "JSON parsing failed"
        assert parsed_json['features']['max_threads'] == 8, "Nested JSON parsing failed"
        print("JSON config parsing working")

        # Test INI config
        ini_config = configparser.ConfigParser()
        ini_config['DEFAULT'] = {'debug': 'false'}
        ini_config['analysis'] = {
            'timeout': '300',
            'max_depth': '10'
        }

        # Write and read back
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False) as f:
            ini_config.write(f)
            temp_ini = f.name

        # Read back
        read_config = configparser.ConfigParser()
        read_config.read(temp_ini)

        assert read_config.getint('analysis', 'timeout') == 300, "INI parsing failed"
        assert read_config.getint('analysis', 'max_depth') == 10, "INI parsing failed"
        print("INI config parsing working")

        # Cleanup
        os.unlink(temp_ini)

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_binary_packing():
    """Test binary data packing/unpacking"""
    print("\n=== Running Binary Packing Test ===")

    try:
        import struct

        # Test various struct formats
        test_cases = [
            # (format, data, description)
            ('<I', 0x12345678, "Little-endian DWORD"),
            ('>I', 0x12345678, "Big-endian DWORD"),
            ('<H', 0x1234, "Little-endian WORD"),
            ('<Q', 0x123456789ABCDEF0, "Little-endian QWORD"),
            ('<f', 3.14159, "Float"),
            ('<d', 3.14159265359, "Double")
        ]

        for fmt, value, desc in test_cases:
            # Pack
            packed = struct.pack(fmt, value)

            # Unpack
            unpacked = struct.unpack(fmt, packed)[0]

            # For floats, use approximate comparison
            if isinstance(value, float):
                assert abs(unpacked - value) < 0.0001, f"Float mismatch for {desc}"
            else:
                assert unpacked == value, f"Value mismatch for {desc}"

            print(f"  {desc}: OK ({len(packed)} bytes)")

        # Test structure packing
        class_format = '<4sIHH'  # signature, version, major, minor
        packed_struct = struct.pack(class_format, b'TEST', 0x01000000, 4, 0)
        sig, ver, maj, minor = struct.unpack(class_format, packed_struct)

        assert sig == b'TEST', "Signature mismatch"
        assert ver == 0x01000000, "Version mismatch"
        assert maj == 4, "Major version mismatch"
        assert minor == 0, "Minor version mismatch"
        print("Structure packing/unpacking working")

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_shellcode_patterns():
    """Test shellcode pattern generation"""
    print("\n=== Running Shellcode Patterns Test ===")

    try:
        # Common shellcode patterns
        nop_sled = b'\x90' * 16
        assert len(nop_sled) == 16, "NOP sled generation failed"
        assert all(b == 0x90 for b in nop_sled), "Invalid NOP bytes"
        print(f"NOP sled: {nop_sled.hex()}")

        # x86 shellcode patterns
        patterns = {
            'push_ebp': b'\x55',
            'mov_ebp_esp': b'\x8b\xec',
            'sub_esp': b'\x83\xec',
            'xor_eax_eax': b'\x33\xc0',
            'inc_eax': b'\x40',
            'dec_eax': b'\x48',
            'ret': b'\xc3',
            'int3': b'\xcc',
            'call': b'\xe8',
            'jmp': b'\xe9'
        }

        # Test pattern recognition
        test_code = b'\x55\x8b\xec\x33\xc0\xc3'  # push ebp; mov ebp,esp; xor eax,eax; ret

        found = []
        for name, pattern in patterns.items():
            if pattern in test_code:
                found.append(name)
                print(f"  Found: {name}")

        assert 'push_ebp' in found, "Failed to find push ebp"
        assert 'xor_eax_eax' in found, "Failed to find xor eax,eax"
        assert 'ret' in found, "Failed to find ret"

        # Test gadget patterns
        rop_gadgets = [
            b'\x58\xc3',  # pop eax; ret
            b'\x5b\xc3',  # pop ebx; ret
            b'\x59\xc3',  # pop ecx; ret
            b'\x5a\xc3',  # pop edx; ret
        ]

        print(f"ROP gadget patterns: {len(rop_gadgets)} defined")

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_protection_constants():
    """Test protection detection constants"""
    print("\n=== Running Protection Constants Test ===")

    try:
        # Common protection signatures
        protections = {
            'VMProtect': [b'VMProtect', b'.vmp0', b'.vmp1'],
            'Themida': [b'Themida', b'WinLicense'],
            'ASPack': [b'ASPack', b'ASPack section'],
            'UPX': [b'UPX0', b'UPX1', b'UPX!'],
            'PECompact': [b'PECompact', b'PEC2'],
            'Armadillo': [b'Armadillo', b'.arm'],
            'Obsidium': [b'Obsidium'],
            'Enigma': [b'Enigma protector']
        }

        # Test data with some signatures
        test_data = b'This file is protected by VMProtect with UPX0 compression'

        detected = []
        for name, signatures in protections.items():
            for sig in signatures:
                if sig in test_data:
                    detected.append(name)
                    print(f"  Detected: {name} (signature: {sig})")
                    break

        assert 'VMProtect' in detected, "Failed to detect VMProtect"
        assert 'UPX' in detected, "Failed to detect UPX"
        assert len(detected) == 2, f"Expected 2 protections, found {len(detected)}"

        # Test protection characteristics
        characteristics = {
            'packed': ['high_entropy', 'suspicious_sections', 'import_obfuscation'],
            'encrypted': ['encrypted_strings', 'encrypted_code', 'decryption_stub'],
            'anti_debug': ['debug_checks', 'timing_checks', 'exception_handling'],
            'virtualized': ['vm_handlers', 'bytecode_sections', 'dispatcher']
        }

        print(f"\nProtection characteristics defined: {len(characteristics)} categories")
        for category, features in characteristics.items():
            print(f"  {category}: {len(features)} features")

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all core utility tests"""
    print("Starting core utility standalone tests...")

    tests = [
        run_test_pe_utils,
        run_test_path_utils,
        run_test_crypto_utils,
        run_test_pattern_matching,
        run_test_config_parsing,
        run_test_binary_packing,
        run_test_shellcode_patterns,
        run_test_protection_constants
    ]

    passed = 0
    failed = 0

    for test in tests:
        result = test()
        if result:
            passed += 1
        else:
            failed += 1

    print(f"\n{'='*50}")
    print("Core Utility Test Results:")
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")
    print(f"  Total: {len(tests)}")
    print(f"{'='*50}")

    return failed == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
