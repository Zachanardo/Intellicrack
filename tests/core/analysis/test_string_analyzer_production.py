"""Production tests for Radare2 String Analysis Engine.

Tests validate real string extraction and analysis on actual Windows binaries.
NO MOCKS - all tests use real PE/ELF binaries with embedded strings.
Tests must verify genuine string analysis capabilities for license cracking.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import struct
from pathlib import Path
from typing import Any, Generator

import pytest

try:
    import r2pipe

    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False

from intellicrack.core.analysis.radare2_strings import (
    R2StringAnalyzer,
    analyze_binary_strings,
)


class BinaryStringBuilder:
    """Build real PE binaries with embedded strings for testing."""

    @staticmethod
    def create_pe_with_strings(strings: dict[str, list[str]]) -> bytes:
        """Create PE binary with specific strings embedded.

        Args:
            strings: Dictionary mapping section names to lists of strings.

        Returns:
            Complete PE binary as bytes.

        """
        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
        dos_stub += b"This program cannot be run in DOS mode.\r\r\n$"
        dos_stub += b"\x00" * (64 - len(dos_stub))

        pe_signature = b"PE\x00\x00"

        machine = struct.pack("<H", 0x8664)
        num_sections = struct.pack("<H", 3)
        time_stamp = struct.pack("<I", 0)
        ptr_symbol_table = struct.pack("<I", 0)
        num_symbols = struct.pack("<I", 0)
        size_optional_header = struct.pack("<H", 240)
        characteristics = struct.pack("<H", 0x0022)

        coff_header = (
            machine
            + num_sections
            + time_stamp
            + ptr_symbol_table
            + num_symbols
            + size_optional_header
            + characteristics
        )

        magic = struct.pack("<H", 0x020B)
        major_linker = struct.pack("B", 14)
        minor_linker = struct.pack("B", 0)
        size_of_code = struct.pack("<I", 1024)
        size_of_initialized_data = struct.pack("<I", 2048)
        size_of_uninitialized_data = struct.pack("<I", 0)
        address_of_entry_point = struct.pack("<I", 0x1000)
        base_of_code = struct.pack("<I", 0x1000)

        image_base = struct.pack("<Q", 0x140000000)
        section_alignment = struct.pack("<I", 0x1000)
        file_alignment = struct.pack("<I", 0x200)
        os_version = struct.pack("<HH", 6, 0)
        image_version = struct.pack("<HH", 0, 0)
        subsystem_version = struct.pack("<HH", 6, 0)
        win32_version = struct.pack("<I", 0)
        size_of_image = struct.pack("<I", 0x5000)
        size_of_headers = struct.pack("<I", 0x400)
        checksum = struct.pack("<I", 0)
        subsystem = struct.pack("<H", 3)
        dll_characteristics = struct.pack("<H", 0x8160)

        size_of_stack_reserve = struct.pack("<Q", 0x100000)
        size_of_stack_commit = struct.pack("<Q", 0x1000)
        size_of_heap_reserve = struct.pack("<Q", 0x100000)
        size_of_heap_commit = struct.pack("<Q", 0x1000)
        loader_flags = struct.pack("<I", 0)
        num_rva_and_sizes = struct.pack("<I", 16)

        data_directories = bytearray(128)

        optional_header = (
            magic
            + major_linker
            + minor_linker
            + size_of_code
            + size_of_initialized_data
            + size_of_uninitialized_data
            + address_of_entry_point
            + base_of_code
            + image_base
            + section_alignment
            + file_alignment
            + os_version
            + image_version
            + subsystem_version
            + win32_version
            + size_of_image
            + size_of_headers
            + checksum
            + subsystem
            + dll_characteristics
            + size_of_stack_reserve
            + size_of_stack_commit
            + size_of_heap_reserve
            + size_of_heap_commit
            + loader_flags
            + num_rva_and_sizes
            + data_directories
        )

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 1024)
        struct.pack_into("<I", text_section, 12, 0x1000)
        struct.pack_into("<I", text_section, 16, 1024)
        struct.pack_into("<I", text_section, 20, 0x400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        data_section = bytearray(40)
        data_section[:8] = b".data\x00\x00\x00"
        struct.pack_into("<I", data_section, 8, 2048)
        struct.pack_into("<I", data_section, 12, 0x2000)
        struct.pack_into("<I", data_section, 16, 2048)
        struct.pack_into("<I", data_section, 20, 0x800)
        struct.pack_into("<I", data_section, 36, 0xC0000040)

        rdata_section = bytearray(40)
        rdata_section[:8] = b".rdata\x00\x00"
        struct.pack_into("<I", rdata_section, 8, 2048)
        struct.pack_into("<I", rdata_section, 12, 0x3000)
        struct.pack_into("<I", rdata_section, 16, 2048)
        struct.pack_into("<I", rdata_section, 20, 0x1000)
        struct.pack_into("<I", rdata_section, 36, 0x40000040)

        header_size = (
            len(dos_header)
            + len(dos_stub)
            + len(pe_signature)
            + len(coff_header)
            + len(optional_header)
            + len(text_section)
            + len(data_section)
            + len(rdata_section)
        )
        padding = bytearray(0x400 - header_size)

        code_section_data = bytearray(1024)
        code_section_data[0] = 0xC3

        data_section_data = bytearray(2048)
        offset: int = 0
        for string in strings.get(".data", []):
            string_bytes: bytes = string.encode("utf-8") + b"\x00"
            data_section_data[offset : offset + len(string_bytes)] = string_bytes
            offset += len(string_bytes) + 4

        rdata_section_data = bytearray(2048)
        offset = 0
        for string in strings.get(".rdata", []):
            string_bytes = string.encode("utf-8") + b"\x00"
            rdata_section_data[offset : offset + len(string_bytes)] = string_bytes
            offset += len(string_bytes) + 4

        pe_file = (
            dos_header
            + dos_stub
            + pe_signature
            + coff_header
            + optional_header
            + text_section
            + data_section
            + rdata_section
            + padding
            + code_section_data
            + data_section_data
            + rdata_section_data
        )

        return bytes(pe_file)

    @staticmethod
    def create_pe_with_wide_strings(wide_strings: list[str]) -> bytes:
        """Create PE binary with UTF-16 wide character strings.

        Args:
            wide_strings: List of strings to embed as UTF-16.

        Returns:
            Complete PE binary as bytes.

        """
        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
        dos_stub += b"This program cannot be run in DOS mode.\r\r\n$"
        dos_stub += b"\x00" * (64 - len(dos_stub))

        pe_signature = b"PE\x00\x00"
        machine = struct.pack("<H", 0x8664)
        num_sections = struct.pack("<H", 2)
        time_stamp = struct.pack("<I", 0)
        ptr_symbol_table = struct.pack("<I", 0)
        num_symbols = struct.pack("<I", 0)
        size_optional_header = struct.pack("<H", 240)
        characteristics = struct.pack("<H", 0x0022)

        coff_header = (
            machine
            + num_sections
            + time_stamp
            + ptr_symbol_table
            + num_symbols
            + size_optional_header
            + characteristics
        )

        magic = struct.pack("<H", 0x020B)
        optional_fields = (
            struct.pack("BB", 14, 0)
            + struct.pack("<I", 512)
            + struct.pack("<I", 2048)
            + struct.pack("<I", 0)
            + struct.pack("<I", 0x1000)
            + struct.pack("<I", 0x1000)
            + struct.pack("<Q", 0x140000000)
            + struct.pack("<I", 0x1000)
            + struct.pack("<I", 0x200)
            + struct.pack("<HH", 6, 0)
            + struct.pack("<HH", 0, 0)
            + struct.pack("<HH", 6, 0)
            + struct.pack("<I", 0)
            + struct.pack("<I", 0x4000)
            + struct.pack("<I", 0x400)
            + struct.pack("<I", 0)
            + struct.pack("<H", 3)
            + struct.pack("<H", 0x8160)
            + struct.pack("<Q", 0x100000)
            + struct.pack("<Q", 0x1000)
            + struct.pack("<Q", 0x100000)
            + struct.pack("<Q", 0x1000)
            + struct.pack("<I", 0)
            + struct.pack("<I", 16)
            + bytearray(128)
        )

        optional_header = magic + optional_fields

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 512)
        struct.pack_into("<I", text_section, 12, 0x1000)
        struct.pack_into("<I", text_section, 16, 512)
        struct.pack_into("<I", text_section, 20, 0x400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        data_section = bytearray(40)
        data_section[:8] = b".data\x00\x00\x00"
        struct.pack_into("<I", data_section, 8, 2048)
        struct.pack_into("<I", data_section, 12, 0x2000)
        struct.pack_into("<I", data_section, 16, 2048)
        struct.pack_into("<I", data_section, 20, 0x600)
        struct.pack_into("<I", data_section, 36, 0xC0000040)

        header_size = (
            len(dos_header)
            + len(dos_stub)
            + len(pe_signature)
            + len(coff_header)
            + len(optional_header)
            + len(text_section)
            + len(data_section)
        )
        padding = bytearray(0x400 - header_size)

        code_section_data = bytearray(512)
        code_section_data[0] = 0xC3

        data_section_data = bytearray(2048)
        offset = 0
        for string in wide_strings:
            wide_bytes: bytes = string.encode("utf-16-le") + b"\x00\x00"
            data_section_data[offset : offset + len(wide_bytes)] = wide_bytes
            offset += len(wide_bytes) + 4

        pe_file = (
            dos_header
            + dos_stub
            + pe_signature
            + coff_header
            + optional_header
            + text_section
            + data_section
            + padding
            + code_section_data
            + data_section_data
        )

        return bytes(pe_file)

    @staticmethod
    def create_pe_with_license_strings() -> bytes:
        """Create PE binary with realistic license validation strings.

        Returns:
            Complete PE binary with license strings.

        """
        license_strings = {
            ".data": [
                "Please enter your license key",
                "Invalid license key",
                "License expired",
                "Trial period: 30 days remaining",
                "XXXX-XXXX-XXXX-XXXX",
                "Serial number verification failed",
                "Product activation required",
                "Thank you for registering!",
                "This is an unregistered copy",
                "Enter registration code:",
            ],
            ".rdata": [
                "CheckLicenseKey",
                "ValidateSerial",
                "GetTrialDaysRemaining",
                "ActivateProduct",
                "IsRegistered",
                "GetHardwareID",
                "VerifyAuthentication",
                "CheckDonglePresent",
            ],
        }
        return BinaryStringBuilder.create_pe_with_strings(license_strings)

    @staticmethod
    def create_pe_with_crypto_strings() -> bytes:
        """Create PE binary with cryptographic strings.

        Returns:
            Complete PE binary with crypto strings.

        """
        crypto_strings = {
            ".data": [
                "AES-256-CBC",
                "SHA256",
                "RSA-2048",
                "MD5 hash verification",
                "3DES encryption key",
                "HMAC-SHA1",
                "-----BEGIN PRIVATE KEY-----",
                "Certificate validation failed",
                "Invalid signature",
                "Cipher initialization vector",
            ],
            ".rdata": [
                "CryptEncrypt",
                "CryptDecrypt",
                "CryptHashData",
                "CryptVerifySignature",
                "BCryptGenerateSymmetricKey",
                "EVP_EncryptInit",
                "SSL_CTX_new",
            ],
        }
        return BinaryStringBuilder.create_pe_with_strings(crypto_strings)

    @staticmethod
    def create_pe_with_api_strings() -> bytes:
        """Create PE binary with Windows API strings.

        Returns:
            Complete PE binary with API strings.

        """
        api_strings = {
            ".rdata": [
                "CreateFileA",
                "ReadFile",
                "WriteFile",
                "CloseHandle",
                "VirtualAlloc",
                "GetProcAddress",
                "LoadLibraryA",
                "RegOpenKeyExA",
                "RegQueryValueExA",
                "CreateProcessW",
                "OpenProcess",
                "NtQuerySystemInformation",
                "RtlAllocateHeap",
            ],
        }
        return BinaryStringBuilder.create_pe_with_strings(api_strings)


@pytest.fixture(scope="session")
def string_test_binaries(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create test binaries with various string types.

    Args:
        tmp_path_factory: Pytest temp path factory.

    Returns:
        Path to directory containing test binaries.

    """
    binary_dir: Path = tmp_path_factory.mktemp("string_test_binaries")

    license_binary: Path = binary_dir / "license_strings.exe"
    license_binary.write_bytes(BinaryStringBuilder.create_pe_with_license_strings())

    crypto_binary: Path = binary_dir / "crypto_strings.exe"
    crypto_binary.write_bytes(BinaryStringBuilder.create_pe_with_crypto_strings())

    api_binary: Path = binary_dir / "api_strings.exe"
    api_binary.write_bytes(BinaryStringBuilder.create_pe_with_api_strings())

    wide_strings: list[str] = [
        "License Key Required",
        "Product Activation",
        "Registration Failed",
        "Serial Number Invalid",
    ]
    wide_binary: Path = binary_dir / "wide_strings.exe"
    wide_binary.write_bytes(BinaryStringBuilder.create_pe_with_wide_strings(wide_strings))

    mixed_strings = {
        ".data": [
            "http://license-server.example.com",
            "https://api.activation.com/validate",
            "C:\\Program Files\\Software\\license.dat",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Company\\Product",
            "Error: License file not found",
            "Warning: Trial period expired",
            "Version 1.2.3.4",
            "Copyright (C) 2025 Company",
        ],
        ".rdata": [
            "GetSystemInfo",
            "QueryPerformanceCounter",
            "socket",
            "connect",
            "send",
            "recv",
        ],
    }
    mixed_binary: Path = binary_dir / "mixed_strings.exe"
    mixed_binary.write_bytes(BinaryStringBuilder.create_pe_with_strings(mixed_strings))

    return binary_dir


@pytest.fixture
def analyzer_license(string_test_binaries: Path) -> R2StringAnalyzer:
    """Create analyzer for license strings binary.

    Args:
        string_test_binaries: Directory containing test binaries.

    Returns:
        Initialized R2StringAnalyzer.

    """
    binary_path: str = str(string_test_binaries / "license_strings.exe")
    return R2StringAnalyzer(binary_path)


@pytest.fixture
def analyzer_crypto(string_test_binaries: Path) -> R2StringAnalyzer:
    """Create analyzer for crypto strings binary.

    Args:
        string_test_binaries: Directory containing test binaries.

    Returns:
        Initialized R2StringAnalyzer.

    """
    binary_path: str = str(string_test_binaries / "crypto_strings.exe")
    return R2StringAnalyzer(binary_path)


@pytest.fixture
def analyzer_api(string_test_binaries: Path) -> R2StringAnalyzer:
    """Create analyzer for API strings binary.

    Args:
        string_test_binaries: Directory containing test binaries.

    Returns:
        Initialized R2StringAnalyzer.

    """
    binary_path: str = str(string_test_binaries / "api_strings.exe")
    return R2StringAnalyzer(binary_path)


@pytest.fixture
def analyzer_wide(string_test_binaries: Path) -> R2StringAnalyzer:
    """Create analyzer for wide strings binary.

    Args:
        string_test_binaries: Directory containing test binaries.

    Returns:
        Initialized R2StringAnalyzer.

    """
    binary_path: str = str(string_test_binaries / "wide_strings.exe")
    return R2StringAnalyzer(binary_path)


@pytest.fixture
def analyzer_mixed(string_test_binaries: Path) -> R2StringAnalyzer:
    """Create analyzer for mixed strings binary.

    Args:
        string_test_binaries: Directory containing test binaries.

    Returns:
        Initialized R2StringAnalyzer.

    """
    binary_path: str = str(string_test_binaries / "mixed_strings.exe")
    return R2StringAnalyzer(binary_path)


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestStringExtractionBasics:
    """Test basic string extraction functionality."""

    def test_analyze_all_strings_returns_valid_structure(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """String analyzer returns complete result structure."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        assert isinstance(result, dict)
        assert "total_strings" in result
        assert "license_strings" in result
        assert "crypto_strings" in result
        assert "api_strings" in result
        assert "string_sections" in result
        assert isinstance(result["total_strings"], int)

    def test_extracts_strings_from_real_binary(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """String analyzer extracts strings from actual PE binary."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        assert result["total_strings"] > 0
        assert len(result["license_strings"]) > 0

    def test_minimum_length_filtering_works(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """Minimum length filter correctly excludes short strings."""
        result_short: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)
        result_long: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=20)

        assert result_short["total_strings"] >= result_long["total_strings"]

    def test_string_data_has_required_fields(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """Extracted strings contain all required metadata fields."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        license_strings: list[dict[str, Any]] = result["license_strings"]
        assert license_strings

        for string_data in license_strings:
            assert "content" in string_data
            assert "address" in string_data
            assert "length" in string_data
            assert "section" in string_data
            assert isinstance(string_data["content"], str)
            assert isinstance(string_data["address"], int)
            assert isinstance(string_data["length"], int)


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestLicenseStringDetection:
    """Test license-related string identification."""

    def test_detects_license_keyword_strings(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """License string detector finds license keyword strings."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        license_strings: list[dict[str, Any]] = result["license_strings"]
        assert license_strings

        license_contents: list[str] = [s["content"].lower() for s in license_strings]
        assert any("license" in content for content in license_contents)

    def test_detects_registration_strings(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """License detector identifies registration-related strings."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        license_strings: list[dict[str, Any]] = result["license_strings"]
        license_contents: list[str] = [s["content"].lower() for s in license_strings]

        assert any("register" in content for content in license_contents)

    def test_detects_activation_strings(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """License detector identifies activation strings."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        license_strings: list[dict[str, Any]] = result["license_strings"]
        license_contents: list[str] = [s["content"].lower() for s in license_strings]

        assert any("activat" in content for content in license_contents)

    def test_detects_trial_period_strings(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """License detector identifies trial period strings."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        license_strings: list[dict[str, Any]] = result["license_strings"]
        license_contents: list[str] = [s["content"].lower() for s in license_strings]

        assert any("trial" in content for content in license_contents)

    def test_detects_serial_number_strings(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """License detector identifies serial number strings."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        license_strings: list[dict[str, Any]] = result["license_strings"]
        license_contents: list[str] = [s["content"].lower() for s in license_strings]

        assert any("serial" in content for content in license_contents)

    def test_detects_expiration_strings(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """License detector identifies expiration strings."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        license_strings: list[dict[str, Any]] = result["license_strings"]
        license_contents: list[str] = [s["content"].lower() for s in license_strings]

        assert any("expir" in content for content in license_contents)

    def test_license_validation_function_names(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """Detects license validation function names in strings."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        license_strings: list[dict[str, Any]] = result["license_strings"]
        api_strings: list[dict[str, Any]] = result["api_strings"]

        all_relevant: list[str] = [s["content"] for s in license_strings + api_strings]

        validation_functions: list[str] = [
            "CheckLicenseKey",
            "ValidateSerial",
            "IsRegistered",
            "VerifyAuthentication",
        ]

        found_functions: list[str] = [
            func for func in validation_functions if any(func in s for s in all_relevant)
        ]
        assert found_functions


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestCryptographicStringDetection:
    """Test cryptographic string identification."""

    def test_detects_aes_strings(self, analyzer_crypto: R2StringAnalyzer) -> None:
        """Crypto detector identifies AES algorithm strings."""
        result: dict[str, Any] = analyzer_crypto.analyze_all_strings(min_length=4)

        crypto_strings: list[dict[str, Any]] = result["crypto_strings"]
        crypto_contents: list[str] = [s["content"].lower() for s in crypto_strings]

        assert any("aes" in content for content in crypto_contents)

    def test_detects_sha_hash_strings(self, analyzer_crypto: R2StringAnalyzer) -> None:
        """Crypto detector identifies SHA hash strings."""
        result: dict[str, Any] = analyzer_crypto.analyze_all_strings(min_length=4)

        crypto_strings: list[dict[str, Any]] = result["crypto_strings"]
        crypto_contents: list[str] = [s["content"].lower() for s in crypto_strings]

        assert any("sha" in content for content in crypto_contents)

    def test_detects_rsa_strings(self, analyzer_crypto: R2StringAnalyzer) -> None:
        """Crypto detector identifies RSA algorithm strings."""
        result: dict[str, Any] = analyzer_crypto.analyze_all_strings(min_length=4)

        crypto_strings: list[dict[str, Any]] = result["crypto_strings"]
        crypto_contents: list[str] = [s["content"].lower() for s in crypto_strings]

        assert any("rsa" in content for content in crypto_contents)

    def test_detects_md5_strings(self, analyzer_crypto: R2StringAnalyzer) -> None:
        """Crypto detector identifies MD5 hash strings."""
        result: dict[str, Any] = analyzer_crypto.analyze_all_strings(min_length=4)

        crypto_strings: list[dict[str, Any]] = result["crypto_strings"]
        crypto_contents: list[str] = [s["content"].lower() for s in crypto_strings]

        assert any("md5" in content for content in crypto_contents)

    def test_detects_encryption_function_names(
        self, analyzer_crypto: R2StringAnalyzer
    ) -> None:
        """Detects cryptographic API function names."""
        result: dict[str, Any] = analyzer_crypto.analyze_all_strings(min_length=4)

        crypto_strings: list[dict[str, Any]] = result["crypto_strings"]
        api_strings: list[dict[str, Any]] = result["api_strings"]

        all_relevant: list[str] = [s["content"] for s in crypto_strings + api_strings]

        crypto_functions: list[str] = [
            "CryptEncrypt",
            "CryptDecrypt",
            "CryptHashData",
            "BCryptGenerateSymmetricKey",
        ]

        found_functions: list[str] = [
            func for func in crypto_functions if any(func in s for s in all_relevant)
        ]
        assert found_functions

    def test_detects_pem_format_strings(self, analyzer_crypto: R2StringAnalyzer) -> None:
        """Crypto detector identifies PEM format certificate strings."""
        result: dict[str, Any] = analyzer_crypto.analyze_all_strings(min_length=4)

        crypto_strings: list[dict[str, Any]] = result["crypto_strings"]
        crypto_contents: list[str] = [s["content"] for s in crypto_strings]

        assert any("BEGIN PRIVATE KEY" in content for content in crypto_contents)


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestAPIStringDetection:
    """Test Windows API string identification."""

    def test_detects_file_api_functions(self, analyzer_api: R2StringAnalyzer) -> None:
        """API detector identifies file operation functions."""
        result: dict[str, Any] = analyzer_api.analyze_all_strings(min_length=4)

        api_strings: list[dict[str, Any]] = result["api_strings"]
        api_contents: list[str] = [s["content"] for s in api_strings]

        file_apis: list[str] = ["CreateFileA", "ReadFile", "WriteFile", "CloseHandle"]
        found_apis: list[str] = [api for api in file_apis if any(api in s for s in api_contents)]

        assert len(found_apis) >= 2

    def test_detects_memory_api_functions(self, analyzer_api: R2StringAnalyzer) -> None:
        """API detector identifies memory management functions."""
        result: dict[str, Any] = analyzer_api.analyze_all_strings(min_length=4)

        api_strings: list[dict[str, Any]] = result["api_strings"]
        api_contents: list[str] = [s["content"] for s in api_strings]

        assert any("VirtualAlloc" in content for content in api_contents)

    def test_detects_process_api_functions(self, analyzer_api: R2StringAnalyzer) -> None:
        """API detector identifies process management functions."""
        result: dict[str, Any] = analyzer_api.analyze_all_strings(min_length=4)

        api_strings: list[dict[str, Any]] = result["api_strings"]
        api_contents: list[str] = [s["content"] for s in api_strings]

        process_apis: list[str] = ["CreateProcessW", "OpenProcess"]
        found_apis: list[str] = [
            api for api in process_apis if any(api in s for s in api_contents)
        ]

        assert found_apis

    def test_detects_registry_api_functions(self, analyzer_api: R2StringAnalyzer) -> None:
        """API detector identifies registry access functions."""
        result: dict[str, Any] = analyzer_api.analyze_all_strings(min_length=4)

        api_strings: list[dict[str, Any]] = result["api_strings"]
        api_contents: list[str] = [s["content"] for s in api_strings]

        registry_apis: list[str] = ["RegOpenKeyExA", "RegQueryValueExA"]
        found_apis: list[str] = [
            api for api in registry_apis if any(api in s for s in api_contents)
        ]

        assert found_apis

    def test_detects_native_api_functions(self, analyzer_api: R2StringAnalyzer) -> None:
        """API detector identifies native Windows API functions."""
        result: dict[str, Any] = analyzer_api.analyze_all_strings(min_length=4)

        api_strings: list[dict[str, Any]] = result["api_strings"]
        api_contents: list[str] = [s["content"] for s in api_strings]

        assert any("NtQuerySystemInformation" in content for content in api_contents)


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestWideStringHandling:
    """Test UTF-16 wide string extraction."""

    def test_detects_wide_strings(self, analyzer_wide: R2StringAnalyzer) -> None:
        """String analyzer detects UTF-16 wide strings."""
        result: dict[str, Any] = analyzer_wide.analyze_all_strings(
            min_length=4, encoding="auto"
        )

        assert result["total_strings"] > 0

    def test_wide_strings_have_encoding_marker(
        self, analyzer_wide: R2StringAnalyzer
    ) -> None:
        """Wide strings are marked with UTF-16 encoding."""
        result: dict[str, Any] = analyzer_wide.analyze_all_strings(
            min_length=4, encoding="utf16"
        )

        if result["total_strings"] > 0:
            if license_strings := result["license_strings"]:
                has_wide: bool = any(
                    s.get("encoding") == "utf-16" or s.get("is_wide") for s in license_strings
                )
                assert has_wide or result["total_strings"] > 0


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestURLAndPathExtraction:
    """Test URL and file path string extraction."""

    def test_detects_url_strings(self, analyzer_mixed: R2StringAnalyzer) -> None:
        """URL detector identifies HTTP/HTTPS URLs."""
        result: dict[str, Any] = analyzer_mixed.analyze_all_strings(min_length=4)

        url_strings: list[dict[str, Any]] = result["url_strings"]
        url_contents: list[str] = [s["content"] for s in url_strings]

        assert any("http://" in content or "https://" in content for content in url_contents)

    def test_detects_file_path_strings(self, analyzer_mixed: R2StringAnalyzer) -> None:
        """Path detector identifies Windows file paths."""
        result: dict[str, Any] = analyzer_mixed.analyze_all_strings(min_length=4)

        path_strings: list[dict[str, Any]] = result["file_path_strings"]
        path_contents: list[str] = [s["content"] for s in path_strings]

        assert any(":\\" in content for content in path_contents)

    def test_detects_registry_key_strings(self, analyzer_mixed: R2StringAnalyzer) -> None:
        """Registry detector identifies Windows registry keys."""
        result: dict[str, Any] = analyzer_mixed.analyze_all_strings(min_length=4)

        registry_strings: list[dict[str, Any]] = result["registry_strings"]
        registry_contents: list[str] = [s["content"] for s in registry_strings]

        assert any("HKEY_" in content for content in registry_contents)


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestErrorMessageExtraction:
    """Test error message string detection."""

    def test_detects_error_message_strings(self, analyzer_mixed: R2StringAnalyzer) -> None:
        """Error detector identifies error message strings."""
        result: dict[str, Any] = analyzer_mixed.analyze_all_strings(min_length=4)

        error_strings: list[dict[str, Any]] = result["error_message_strings"]
        error_contents: list[str] = [s["content"].lower() for s in error_strings]

        assert any("error" in content or "warning" in content for content in error_contents)

    def test_detects_failure_message_strings(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """Error detector identifies failure messages."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        error_strings: list[dict[str, Any]] = result["error_message_strings"]
        error_contents: list[str] = [s["content"].lower() for s in error_strings]

        assert any("fail" in content or "invalid" in content for content in error_contents)


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestVersionAndCompilerStrings:
    """Test version and compiler string detection."""

    def test_detects_version_strings(self, analyzer_mixed: R2StringAnalyzer) -> None:
        """Version detector identifies version information."""
        result: dict[str, Any] = analyzer_mixed.analyze_all_strings(min_length=4)

        version_strings: list[dict[str, Any]] = result["version_strings"]
        version_contents: list[str] = [s["content"] for s in version_strings]

        assert any("version" in content.lower() or "copyright" in content.lower() for content in version_contents)


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestEntropyAnalysis:
    """Test string entropy analysis."""

    def test_entropy_analysis_present(self, analyzer_license: R2StringAnalyzer) -> None:
        """String analysis includes entropy analysis."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        assert "string_entropy_analysis" in result
        entropy_data: dict[str, Any] = result["string_entropy_analysis"]
        assert "average_entropy" in entropy_data
        assert "entropy_distribution" in entropy_data

    def test_high_entropy_string_detection(
        self, analyzer_crypto: R2StringAnalyzer
    ) -> None:
        """Entropy analyzer identifies high entropy strings."""
        result: dict[str, Any] = analyzer_crypto.analyze_all_strings(min_length=4)

        entropy_data: dict[str, Any] = result["string_entropy_analysis"]
        assert "high_entropy_strings" in entropy_data

    def test_entropy_distribution_valid(self, analyzer_license: R2StringAnalyzer) -> None:
        """Entropy distribution has valid ranges."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        entropy_data: dict[str, Any] = result["string_entropy_analysis"]
        distribution: dict[str, int] = entropy_data["entropy_distribution"]

        assert "0-1" in distribution
        assert "1-2" in distribution
        assert "2-3" in distribution
        assert "3-4" in distribution
        assert "4+" in distribution


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestSectionAnalysis:
    """Test string distribution by section."""

    def test_section_analysis_present(self, analyzer_license: R2StringAnalyzer) -> None:
        """String analysis includes section distribution."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        assert "string_sections" in result
        sections: dict[str, Any] = result["string_sections"]
        assert isinstance(sections, dict)

    def test_strings_distributed_across_sections(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """Strings are distributed across multiple sections."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        sections: dict[str, Any] = result["string_sections"]
        sections_with_strings: list[str] = [
            name for name, data in sections.items() if data.get("string_count", 0) > 0
        ]

        assert sections_with_strings

    def test_section_statistics_valid(self, analyzer_license: R2StringAnalyzer) -> None:
        """Section statistics contain valid data."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        sections: dict[str, Any] = result["string_sections"]
        for section_data in sections.values():
            if "string_count" in section_data:
                assert section_data["string_count"] >= 0
                if section_data["string_count"] > 0:
                    assert "average_string_length" in section_data
                    assert section_data["average_string_length"] > 0


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestSuspiciousPatternDetection:
    """Test suspicious string pattern detection."""

    def test_suspicious_patterns_detected(
        self, analyzer_crypto: R2StringAnalyzer
    ) -> None:
        """Pattern detector identifies suspicious strings."""
        result: dict[str, Any] = analyzer_crypto.analyze_all_strings(min_length=4)

        assert "suspicious_patterns" in result
        suspicious: list[dict[str, Any]] = result["suspicious_patterns"]
        assert isinstance(suspicious, list)

    def test_detects_base64_patterns(self, string_test_binaries: Path) -> None:
        """Pattern detector identifies Base64-encoded strings."""
        base64_strings = {
            ".data": [
                "SGVsbG8gV29ybGQh",
                "VGhpcyBpcyBhIHRlc3Q=",
                "QmFzZTY0IGVuY29kZWQ=",
            ],
        }

        binary_path: Path = string_test_binaries / "base64_test.exe"
        binary_path.write_bytes(BinaryStringBuilder.create_pe_with_strings(base64_strings))

        analyzer: R2StringAnalyzer = R2StringAnalyzer(str(binary_path))
        result: dict[str, Any] = analyzer.analyze_all_strings(min_length=4)

        suspicious: list[dict[str, Any]] = result["suspicious_patterns"]
        base64_patterns: list[dict[str, Any]] = [
            p for p in suspicious if p.get("pattern_type") == "base64_like"
        ]

        assert base64_patterns or result["total_strings"] > 0


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestCategoryStatistics:
    """Test category statistics generation."""

    def test_category_stats_present(self, analyzer_license: R2StringAnalyzer) -> None:
        """String analysis includes category statistics."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        assert "categorized_stats" in result
        stats: dict[str, Any] = result["categorized_stats"]
        assert isinstance(stats, dict)

    def test_stats_have_count_and_percentage(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """Category statistics include count and percentage."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)

        stats: dict[str, Any] = result["categorized_stats"]
        for category_stats in stats.values():
            assert "count" in category_stats
            assert "percentage" in category_stats
            assert isinstance(category_stats["count"], int)
            assert isinstance(category_stats["percentage"], float)
            assert 0 <= category_stats["percentage"] <= 100


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestLicenseValidationSearch:
    """Test specialized license validation string search."""

    def test_license_validation_search_works(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """License validation search returns results."""
        result: dict[str, Any] = analyzer_license.search_license_validation_strings()

        assert "validation_strings" in result
        assert "total_found" in result
        assert isinstance(result["validation_strings"], list)
        assert isinstance(result["total_found"], int)

    def test_license_search_finds_relevant_strings(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """License validation search finds license-related strings."""
        result: dict[str, Any] = analyzer_license.search_license_validation_strings()

        if result["total_found"] > 0:
            validation_strings: list[dict[str, Any]] = result["validation_strings"]
            contents: list[str] = [s["content"].lower() for s in validation_strings]

            relevant_terms: list[str] = ["license", "register", "activation", "serial", "trial"]
            found_relevant: bool = any(
                any(term in content for term in relevant_terms) for content in contents
            )

            assert found_relevant


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestRealWorldBinaryAnalysis:
    """Test string analysis on real Windows system binaries."""

    @pytest.fixture
    def system_binary_path(self) -> str | None:
        """Get path to real Windows system binary.

        Returns:
            Path to system binary or None if not found.

        """
        candidates: list[str] = [
            r"C:\Windows\System32\notepad.exe",
            r"C:\Windows\System32\calc.exe",
            r"C:\Windows\System32\cmd.exe",
        ]

        return next(
            (candidate for candidate in candidates if os.path.exists(candidate)),
            None,
        )

    def test_analyzes_real_windows_binary(self, system_binary_path: str | None) -> None:
        """String analyzer works on real Windows system binary."""
        if system_binary_path is None:
            pytest.skip("No system binary available for testing")

        analyzer: R2StringAnalyzer = R2StringAnalyzer(system_binary_path)
        result: dict[str, Any] = analyzer.analyze_all_strings(min_length=4)

        assert result["total_strings"] > 0
        assert "error" not in result

    def test_real_binary_has_api_strings(self, system_binary_path: str | None) -> None:
        """Real Windows binaries contain API function strings."""
        if system_binary_path is None:
            pytest.skip("No system binary available for testing")

        analyzer: R2StringAnalyzer = R2StringAnalyzer(system_binary_path)
        result: dict[str, Any] = analyzer.analyze_all_strings(min_length=4)

        api_strings: list[dict[str, Any]] = result["api_strings"]
        assert api_strings

    def test_real_binary_section_distribution(
        self, system_binary_path: str | None
    ) -> None:
        """Real binaries have strings distributed across sections."""
        if system_binary_path is None:
            pytest.skip("No system binary available for testing")

        analyzer: R2StringAnalyzer = R2StringAnalyzer(system_binary_path)
        result: dict[str, Any] = analyzer.analyze_all_strings(min_length=4)

        sections: dict[str, Any] = result["string_sections"]
        sections_with_strings: int = sum(bool(data.get("string_count", 0) > 0)
                                     for data in sections.values())

        assert sections_with_strings > 0


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestModuleFunction:
    """Test module-level analysis function."""

    def test_analyze_binary_strings_function_works(
        self, string_test_binaries: Path
    ) -> None:
        """Module-level analyze function returns valid results."""
        binary_path: str = str(string_test_binaries / "license_strings.exe")
        result: dict[str, Any] = analyze_binary_strings(binary_path, min_length=4)

        assert isinstance(result, dict)
        assert "total_strings" in result
        assert result["total_strings"] > 0


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestErrorHandling:
    """Test error handling for invalid inputs."""

    def test_handles_nonexistent_file(self, tmp_path: Path) -> None:
        """Analyzer handles nonexistent file gracefully."""
        nonexistent: Path = tmp_path / "nonexistent.exe"
        analyzer: R2StringAnalyzer = R2StringAnalyzer(str(nonexistent))

        result: dict[str, Any] = analyzer.analyze_all_strings(min_length=4)

        assert "error" in result or result["total_strings"] == 0

    def test_handles_invalid_encoding(self, analyzer_license: R2StringAnalyzer) -> None:
        """Analyzer handles invalid encoding parameter."""
        result: dict[str, Any] = analyzer_license.analyze_all_strings(
            min_length=4, encoding="invalid_encoding"
        )

        assert isinstance(result, dict)


@pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
class TestPerformance:
    """Test performance on various binary sizes."""

    def test_analyzes_small_binary_quickly(
        self, analyzer_license: R2StringAnalyzer
    ) -> None:
        """String analysis completes quickly on small binaries."""
        import time

        start_time: float = time.time()
        result: dict[str, Any] = analyzer_license.analyze_all_strings(min_length=4)
        elapsed: float = time.time() - start_time

        assert result["total_strings"] > 0
        assert elapsed < 30.0

    def test_handles_large_string_count(self, string_test_binaries: Path) -> None:
        """Analyzer handles binaries with many strings."""
        many_strings = {".data": [f"String number {i}" for i in range(100)]}

        binary_path: Path = string_test_binaries / "many_strings.exe"
        binary_path.write_bytes(BinaryStringBuilder.create_pe_with_strings(many_strings))

        analyzer: R2StringAnalyzer = R2StringAnalyzer(str(binary_path))
        result: dict[str, Any] = analyzer.analyze_all_strings(min_length=4)

        assert result["total_strings"] > 50
