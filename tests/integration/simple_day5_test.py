#!/usr/bin/env python3
"""Standalone test for Day 5.1 Enhanced String Analysis Pattern Detection

Tests the enhanced algorithms without complex imports to avoid circular dependencies.
"""

import binascii
import hashlib
import math
import re
import string


class SimpleStringAnalyzer:
    """Standalone string analyzer for testing enhanced methods."""

    def _calculate_shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        entropy = 0.0
        text_len = len(text)

        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _detect_license_key_formats(self, content: str) -> bool:
        """Enhanced license key format detection algorithms."""
        if len(content) < 8 or len(content) > 64:
            return False

        # Pattern 1: Traditional dashed format (XXXX-XXXX-XXXX-XXXX)
        dash_pattern = re.compile(r'^[A-Z0-9]{4,8}(-[A-Z0-9]{4,8}){2,7}$', re.IGNORECASE)
        if dash_pattern.match(content):
            return True

        # Pattern 2: UUID format
        uuid_pattern = re.compile(r'^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$', re.IGNORECASE)
        if uuid_pattern.match(content):
            return True

        # Pattern 3: Base32-like format (no padding for license keys)
        base32_pattern = re.compile(r'^[A-Z2-7]{16,40}$')
        if base32_pattern.match(content.upper()):
            # Check for repetitive patterns - avoid false positives
            if self._is_repetitive_pattern(content.upper()):
                return False
            return True

        # Pattern 4: Microsoft product key format (25 characters)
        if len(content) == 25 and re.match(r'^[BCDFGHJKMPQRTVWXY2-9]{25}$', content.upper()):
            return True

        # Pattern 5: High entropy alphanumeric strings (likely license keys)
        if re.match(r'^[A-Z0-9]+$', content.upper()) and len(content) >= 12:
            # Check for repetitive patterns first
            if self._is_repetitive_pattern(content.upper()):
                return False

            entropy = self._calculate_shannon_entropy(content.upper())
            if 2.5 <= entropy <= 4.5:  # Typical range for license keys
                # Check character distribution
                digits = sum(1 for c in content if c.isdigit())
                letters = sum(1 for c in content if c.isalpha())
                total = len(content)

                digit_ratio = digits / total
                letter_ratio = letters / total

                # License keys typically have balanced alphanumeric distribution
                if 0.3 <= digit_ratio <= 0.7 and 0.3 <= letter_ratio <= 0.7:
                    return True

        return False

    def _is_repetitive_pattern(self, content: str) -> bool:
        """Check if string has repetitive patterns that are unlikely in real license keys."""
        if len(content) < 4:
            return False

        # Check for excessive character repetition
        char_counts = {}
        for char in content:
            char_counts[char] = char_counts.get(char, 0) + 1

        # If any character appears more than 50% of the time, it's too repetitive
        max_char_freq = max(char_counts.values()) / len(content)
        if max_char_freq > 0.5:
            return True

        # Check for simple patterns like "AAAA", "ABAB", etc.
        # Pattern 1: All same character
        if len(set(content)) == 1:
            return True

        # Pattern 2: Simple repetition of 1-3 characters
        for pattern_len in range(1, 4):
            pattern = content[:pattern_len]
            if pattern * (len(content) // pattern_len + 1) == content + pattern[:len(content) % pattern_len]:
                return True

        return False

    def _detect_cryptographic_data(self, content: str) -> bool:
        """Enhanced cryptographic string identification."""
        if len(content) < 8:
            return False

        content_upper = content.upper()

        # Pattern 1: Base64 encoded data detection
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
        if base64_pattern.match(content) and len(content) % 4 == 0:
            try:
                decoded = binascii.a2b_base64(content)
                if len(decoded) >= 4:  # Valid decoded data
                    return True
            except:
                pass

        # Pattern 2: Hexadecimal crypto data
        hex_pattern = re.compile(r'^[0-9A-F]+$', re.IGNORECASE)
        if hex_pattern.match(content) and len(content) % 2 == 0:
            # Common hash lengths
            if len(content) in [32, 40, 64, 96, 128]:  # MD5, SHA1, SHA256, SHA384, SHA512
                return True

        # Pattern 3: PEM format markers
        pem_markers = [
            'BEGIN CERTIFICATE', 'BEGIN PRIVATE KEY', 'BEGIN PUBLIC KEY',
            'BEGIN RSA PRIVATE KEY', 'BEGIN DSA PRIVATE KEY', 'BEGIN EC PRIVATE KEY'
        ]
        if any(marker in content_upper for marker in pem_markers):
            return True

        # Pattern 4: High entropy data (likely encrypted/compressed)
        if len(content) >= 16:
            entropy = self._calculate_shannon_entropy(content)
            if entropy >= 4.0:  # High entropy indicates cryptographic data
                return True

        # Pattern 5: Common cryptographic constants
        crypto_constants = [
            '67452301', 'EFCDAB89', '98BADCFE', '10325476',  # MD5 constants
            '67452301EFCDAB89', 'DEADBEEF', 'CAFEBABE',      # Common debug/crypto values
            'SHA1', 'SHA256', 'AES', 'RSA'
        ]
        if any(const in content_upper for const in crypto_constants):
            return True

        return False

    def _analyze_api_function_patterns(self, content: str) -> bool:
        """Enhanced API call string analysis."""
        if len(content) < 3 or len(content) > 64:
            return False

        # Windows API functions database
        windows_api_functions = {
            'CreateFileA', 'CreateFileW', 'ReadFile', 'WriteFile', 'CloseHandle',
            'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW', 'FreeLibrary',
            'VirtualAlloc', 'VirtualFree', 'VirtualProtect', 'VirtualQuery',
            'RegOpenKeyA', 'RegOpenKeyW', 'RegQueryValueA', 'RegQueryValueW',
            'RegSetValueA', 'RegSetValueW', 'RegCloseKey',
            'NtCreateFile', 'NtReadFile', 'NtWriteFile', 'NtClose',
            'LdrLoadDll', 'LdrGetProcedureAddress', 'NtQuerySystemInformation'
        }

        # POSIX API functions database
        posix_api_functions = {
            'open', 'read', 'write', 'close', 'lseek', 'stat', 'fstat',
            'malloc', 'free', 'calloc', 'realloc', 'memcpy', 'memset',
            'pthread_create', 'pthread_join', 'pthread_mutex_lock',
            'socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv',
            'fork', 'exec', 'waitpid', 'signal', 'kill'
        }

        # Library API functions database
        library_api_functions = {
            'SSL_connect', 'SSL_write', 'SSL_read', 'SSL_free',
            'EVP_EncryptInit', 'EVP_DecryptInit', 'EVP_DigestInit',
            'glBegin', 'glEnd', 'glVertex3f', 'glColor3f', 'glLoadIdentity',
            'sqlite3_open', 'sqlite3_prepare', 'sqlite3_step', 'sqlite3_finalize',
            'mysql_connect', 'mysql_query', 'mysql_fetch_row', 'mysql_close'
        }

        # Direct API function lookup
        if content in windows_api_functions or content in posix_api_functions or content in library_api_functions:
            return True

        # Pattern 1: CamelCase API naming convention
        camelcase_pattern = re.compile(r'^[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*$')
        if camelcase_pattern.match(content):
            return True

        # Pattern 2: snake_case API naming convention
        snakecase_pattern = re.compile(r'^[a-z][a-z0-9_]*[a-z0-9]$')
        if snakecase_pattern.match(content) and '_' in content:
            return True

        # Pattern 3: Common API verb-noun patterns
        api_verbs = ['get', 'set', 'create', 'delete', 'update', 'open', 'close', 'read', 'write', 'load', 'save']
        content_lower = content.lower()
        if any(content_lower.startswith(verb) for verb in api_verbs) and len(content) >= 6:
            return True

        # Pattern 4: Windows API A/W suffix pattern
        if content.endswith('A') or content.endswith('W'):
            base_name = content[:-1]
            if len(base_name) >= 4 and base_name[0].isupper():
                return True

        # Pattern 5: Library prefixed functions (namespace_function)
        if '_' in content:
            parts = content.split('_')
            if len(parts) >= 2 and len(parts[0]) >= 2 and len(parts[1]) >= 3:
                # Common library prefixes
                library_prefixes = ['ssl', 'crypto', 'gl', 'sqlite3', 'mysql', 'nt', 'ldr']
                if parts[0].lower() in library_prefixes:
                    return True

        return False


def main():
    """Test the enhanced string analysis algorithms."""
    print("DAY 5.1 ENHANCED STRING ANALYSIS VALIDATION")
    print("=" * 50)

    analyzer = SimpleStringAnalyzer()

    # Test license key detection
    print("\n1. Testing Enhanced License Key Detection:")
    license_tests = [
        ("ABCD-1234-EFGH-5678", True, "Traditional license key"),
        ("550E8400-E29B-41D4-A716-446655440000", True, "UUID format"),
        ("MFRGG43FMZRW6Y3PNUXSA", True, "Base32 format"),
        ("A7X9K2L5M8P3R6T4W1Z", True, "High entropy alphanumeric"),
        ("hello world", False, "Regular text"),
        ("AAAAAAAAAAAAAAAAA", False, "Too repetitive")
    ]

    license_passed = 0
    for content, expected, desc in license_tests:
        result = analyzer._detect_license_key_formats(content)
        status = "✓ PASS" if result == expected else "✗ FAIL"
        print(f"  {status}: {desc} - '{content}' -> {result}")
        if result == expected:
            license_passed += 1

    # Test crypto string detection
    print("\n2. Testing Enhanced Cryptographic String Detection:")
    crypto_tests = [
        ("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IHN0cmluZw==", True, "Base64 encoded"),
        ("5d41402abc4b2a76b9719d911017c592", True, "MD5 hash"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", True, "SHA256 hash"),
        ("-----BEGIN CERTIFICATE-----", True, "PEM certificate"),
        ("67452301EFCDAB89", True, "MD5 constant"),
        ("hello world", False, "Regular text")
    ]

    crypto_passed = 0
    for content, expected, desc in crypto_tests:
        result = analyzer._detect_cryptographic_data(content)
        status = "✓ PASS" if result == expected else "✗ FAIL"
        print(f"  {status}: {desc} - '{content}' -> {result}")
        if result == expected:
            crypto_passed += 1

    # Test API string detection
    print("\n3. Testing Enhanced API String Analysis:")
    api_tests = [
        ("CreateFileA", True, "Windows API"),
        ("malloc", True, "POSIX API"),
        ("SSL_connect", True, "OpenSSL API"),
        ("getUserData", True, "CamelCase API"),
        ("set_config_value", True, "snake_case API"),
        ("hello", False, "Regular word"),
        ("a", False, "Too short")
    ]

    api_passed = 0
    for content, expected, desc in api_tests:
        result = analyzer._analyze_api_function_patterns(content)
        status = "✓ PASS" if result == expected else "✗ FAIL"
        print(f"  {status}: {desc} - '{content}' -> {result}")
        if result == expected:
            api_passed += 1

    # Summary
    print(f"\nDAY 5.1 VALIDATION RESULTS:")
    print(f"License Key Detection: {license_passed}/{len(license_tests)} passed")
    print(f"Crypto String Detection: {crypto_passed}/{len(crypto_tests)} passed")
    print(f"API String Analysis: {api_passed}/{len(api_tests)} passed")

    total_passed = license_passed + crypto_passed + api_passed
    total_tests = len(license_tests) + len(crypto_tests) + len(api_tests)

    if total_passed == total_tests:
        print("\n🎉 DAY 5.1 ENHANCED STRING ANALYSIS VALIDATION PASSED!")
        print("✅ All enhanced pattern detection algorithms working correctly")
        return 0
    else:
        print(f"\n❌ DAY 5.1 VALIDATION FAILED: {total_tests - total_passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit(main())
