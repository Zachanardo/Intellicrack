#!/usr/bin/env python3
"""Test script for Day 5.1 Enhanced String Analysis Pattern Detection

Tests the enhanced algorithms for:
1. License key format detection
2. Cryptographic string identification
3. API call string analysis
"""

import sys
from typing import Any

try:
    from intellicrack.core.analysis.radare2_strings import R2StringAnalyzer
except ImportError as e:
    print(f"Import error: {e}")
    print("Testing enhanced methods directly...")


class TestStringAnalyzer:
    """Test class for enhanced string analysis methods."""

    def __init__(self) -> None:
        """Initialize with dummy binary path for testing."""
        self.analyzer = R2StringAnalyzer("dummy.bin")

    def test_license_key_detection(self) -> bool:
        """Test enhanced license key format detection."""
        print("Testing Enhanced License Key Detection:")
        print("=" * 50)

        # Test cases for license key patterns
        test_cases = [
            # Traditional license keys
            ("ABCD-1234-EFGH-5678", True, "Traditional license key format"),
            ("12345-67890-ABCDE-FGHIJ", True, "5-group license key"),

            # Microsoft product keys
            ("BCDFG-HJKMP-QRTVW-XY234-6789X", False, "Microsoft product key format (too long for pattern)"),
            ("BCDFGHJKMPQRTVWXY2346789X", True, "Microsoft product key (25 chars)"),

            # UUID format license keys
            ("550E8400-E29B-41D4-A716-446655440000", True, "UUID format license key"),

            # Base32 encoded keys
            ("MFRGG43FMZRW6Y3PNUXSA", True, "Base32 encoded key"),

            # High entropy alphanumeric strings
            ("A7X9K2L5M8P3R6T4W1Z", True, "High entropy alphanumeric"),

            # Non-license strings
            ("hello world", False, "Regular text"),
            ("12345", False, "Too short"),
            ("AAAAAAAAAAAAAAAAA", False, "Too repetitive"),
        ]

        passed = 0
        failed = 0

        for content, expected, description in test_cases:
            try:
                result = self.analyzer._detect_license_key_formats(content)
                if result == expected:
                    print(f"OK PASS: {description} - '{content}' -> {result}")
                    passed += 1
                else:
                    print(f"FAIL FAIL: {description} - '{content}' -> {result} (expected {expected})")
                    failed += 1
            except Exception as e:
                print(f"FAIL ERROR: {description} - '{content}' -> {e}")
                failed += 1

        print(f"\nLicense Key Detection: {passed} passed, {failed} failed")
        return failed == 0

    def test_crypto_string_detection(self) -> bool:
        """Test enhanced cryptographic string identification."""
        print("\nTesting Enhanced Cryptographic String Detection:")
        print("=" * 55)

        test_cases = [
            # Base64 encoded data
            ("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IHN0cmluZw==", True, "Base64 encoded data"),

            # Hex crypto data
            ("5d41402abc4b2a76b9719d911017c592", True, "MD5 hash (32 hex chars)"),
            ("adc83b19e793491b1c6ea0fd8b46cd9f32e592fc", True, "SHA1 hash (40 hex chars)"),
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", True, "SHA256 hash (64 hex chars)"),

            # PEM format
            ("-----BEGIN CERTIFICATE-----", True, "PEM certificate header"),
            ("-----BEGIN PRIVATE KEY-----", True, "PEM private key header"),

            # High entropy data
            ("x9k2L5M8P3R6T4W1Z7A3N9Q8Y2", True, "High entropy string"),

            # Crypto constants
            ("67452301EFCDAB89", True, "Contains MD5 initial value"),
            ("DEADBEEF", True, "Common debug constant"),

            # Non-crypto strings
            ("hello world", False, "Regular text"),
            ("12345", False, "Simple number"),
            ("ABC", False, "Too short"),
        ]

        passed = 0
        failed = 0

        for content, expected, description in test_cases:
            try:
                result = self.analyzer._detect_cryptographic_data(content)
                if result == expected:
                    print(f"OK PASS: {description} - '{content}' -> {result}")
                    passed += 1
                else:
                    print(f"FAIL FAIL: {description} - '{content}' -> {result} (expected {expected})")
                    failed += 1
            except Exception as e:
                print(f"FAIL ERROR: {description} - '{content}' -> {e}")
                failed += 1

        print(f"\nCrypto String Detection: {passed} passed, {failed} failed")
        return failed == 0

    def test_api_string_detection(self) -> bool:
        """Test enhanced API call string analysis."""
        print("\nTesting Enhanced API String Analysis:")
        print("=" * 45)

        test_cases = [
            # Windows API functions
            ("CreateFileA", True, "Windows API function"),
            ("GetProcAddress", True, "Windows API function"),
            ("VirtualAlloc", True, "Windows memory API"),
            ("RegOpenKey", True, "Registry API"),
            ("NtCreateFile", True, "Native API function"),

            # POSIX API functions
            ("malloc", True, "POSIX memory function"),
            ("pthread_create", True, "POSIX threading function"),
            ("socket", True, "POSIX networking function"),
            ("open", True, "POSIX file function"),

            # Library API functions
            ("SSL_connect", True, "OpenSSL API function"),
            ("glBegin", True, "OpenGL API function"),
            ("sqlite3_open", True, "SQLite API function"),

            # API naming conventions
            ("getUserData", True, "CamelCase API pattern"),
            ("set_config_value", True, "snake_case API pattern"),
            ("createWindow", True, "Verb-noun API pattern"),

            # Non-API strings
            ("hello", False, "Regular word"),
            ("12345", False, "Number"),
            ("a", False, "Too short"),
            ("this_is_a_very_long_function_name_that_exceeds_normal_api_length", False, "Too long"),
        ]

        passed = 0
        failed = 0

        for content, expected, description in test_cases:
            try:
                result = self.analyzer._analyze_api_function_patterns(content)
                if result == expected:
                    print(f"OK PASS: {description} - '{content}' -> {result}")
                    passed += 1
                else:
                    print(f"FAIL FAIL: {description} - '{content}' -> {result} (expected {expected})")
                    failed += 1
            except Exception as e:
                print(f"FAIL ERROR: {description} - '{content}' -> {e}")
                failed += 1

        print(f"\nAPI String Detection: {passed} passed, {failed} failed")
        return failed == 0


def main() -> int:
    """Main test function."""
    print("DAY 5.1 ENHANCED STRING ANALYSIS PATTERN DETECTION TESTING")
    print("=" * 65)
    print("Testing enhanced algorithms for license keys, crypto data, and API calls")
    print()

    try:
        tester = TestStringAnalyzer()

        # Run all tests
        tests = [
            tester.test_license_key_detection,
            tester.test_crypto_string_detection,
            tester.test_api_string_detection,
        ]

        passed_tests = 0
        failed_tests = 0

        for test_func in tests:
            try:
                if test_func():
                    passed_tests += 1
                else:
                    failed_tests += 1
            except Exception as e:
                print(f"Test failed with exception: {e}")
                failed_tests += 1

        print(f"\n DAY 5.1 ENHANCEMENT TEST RESULTS:")
        print(f"OK Test Categories Passed: {passed_tests}")
        print(f"FAIL Test Categories Failed: {failed_tests}")

        if failed_tests == 0:
            print("\n🎉 DAY 5.1 ENHANCEMENTS COMPLETED SUCCESSFULLY!")
            print("OK Enhanced license key format detection algorithms implemented")
            print("OK Advanced cryptographic string identification working")
            print("OK Comprehensive API call string analysis functional")
            print("OK All enhanced pattern detection algorithms operational")
            return 0
        else:
            print(f"\nFAIL DAY 5.1 ENHANCEMENTS FAILED: {failed_tests} test category(s) failed")
            return 1

    except Exception as e:
        print(f"FAIL Testing failed with error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
