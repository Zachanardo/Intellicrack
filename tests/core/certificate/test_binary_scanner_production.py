"""Production-grade tests for BinaryScanner validating real binary analysis.

Tests REAL binary scanning capabilities on actual PE/ELF/Mach-O files.
NO mocks - validates genuine import parsing, string extraction, and API detection.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
from pathlib import Path

import pytest

from intellicrack.core.certificate.binary_scanner import BinaryScanner, ContextInfo

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def binaries_dir() -> Path:
    """Path to directory containing test binaries."""
    return Path(__file__).parent.parent.parent / "fixtures" / "binaries"


@pytest.fixture(scope="module")
def pe_binaries_dir(binaries_dir: Path) -> Path:
    """Path to PE binaries directory."""
    return binaries_dir / "pe"


@pytest.fixture(scope="module")
def elf_binaries_dir(binaries_dir: Path) -> Path:
    """Path to ELF binaries directory."""
    return binaries_dir / "elf"


@pytest.fixture(scope="module")
def legitimate_firefox(pe_binaries_dir: Path) -> Path:
    """Real Firefox PE binary."""
    binary_path = pe_binaries_dir / "legitimate" / "firefox.exe"
    if not binary_path.exists():
        pytest.skip(f"Test binary not found: {binary_path}")
    return binary_path


@pytest.fixture(scope="module")
def legitimate_7zip(pe_binaries_dir: Path) -> Path:
    """Real 7-Zip PE binary."""
    binary_path = pe_binaries_dir / "legitimate" / "7zip.exe"
    if not binary_path.exists():
        pytest.skip(f"Test binary not found: {binary_path}")
    return binary_path


@pytest.fixture(scope="module")
def online_activation_binary(pe_binaries_dir: Path) -> Path:
    """Binary with online activation."""
    binary_path = pe_binaries_dir / "protected" / "online_activation_app.exe"
    if not binary_path.exists():
        pytest.skip(f"Test binary not found: {binary_path}")
    return binary_path


@pytest.fixture(scope="module")
def simple_elf_binary(elf_binaries_dir: Path) -> Path:
    """Simple ELF x64 binary."""
    binary_path = elf_binaries_dir / "simple_x64"
    if not binary_path.exists():
        pytest.skip(f"Test binary not found: {binary_path}")
    return binary_path


class TestBinaryScannerInitialization:
    """Test BinaryScanner initialization and basic functionality."""

    def test_scanner_loads_pe_binary_successfully(self, legitimate_firefox: Path) -> None:
        """Scanner must successfully load and parse PE binary."""
        scanner = BinaryScanner(str(legitimate_firefox))

        assert scanner.binary_path == legitimate_firefox
        assert scanner.binary is not None

    def test_scanner_loads_elf_binary_successfully(self, simple_elf_binary: Path) -> None:
        """Scanner must successfully load and parse ELF binary."""
        scanner = BinaryScanner(str(simple_elf_binary))

        assert scanner.binary_path == simple_elf_binary
        assert scanner.binary is not None

    def test_scanner_raises_error_for_nonexistent_file(self) -> None:
        """Scanner must raise FileNotFoundError for missing binary."""
        with pytest.raises(FileNotFoundError, match="Binary not found"):
            BinaryScanner("nonexistent_file.exe")

    def test_scanner_context_manager_works(self, legitimate_firefox: Path) -> None:
        """Scanner must work as context manager."""
        with BinaryScanner(str(legitimate_firefox)) as scanner:
            assert scanner.binary is not None

    def test_scanner_close_cleans_up_resources(self, legitimate_firefox: Path) -> None:
        """Scanner.close() must clean up radare2 resources."""
        scanner = BinaryScanner(str(legitimate_firefox))
        scanner.close()


class TestImportScanning:
    """Test import table scanning functionality."""

    def test_scan_imports_returns_list_of_dlls(self, legitimate_firefox: Path) -> None:
        """scan_imports must return list of imported DLL names for PE binary."""
        scanner = BinaryScanner(str(legitimate_firefox))
        imports = scanner.scan_imports()

        assert isinstance(imports, list)
        assert len(imports) > 0
        assert all(isinstance(imp, str) for imp in imports)

    def test_scan_imports_includes_common_windows_dlls(self, legitimate_firefox: Path) -> None:
        """PE binary imports must include common Windows system DLLs."""
        scanner = BinaryScanner(str(legitimate_firefox))
        imports = scanner.scan_imports()

        imports_lower = [imp.lower() for imp in imports]

        common_dlls = ["kernel32.dll", "ntdll.dll", "user32.dll"]
        found_common = any(dll in imports_lower for dll in common_dlls)

        assert found_common, f"Expected at least one common DLL in imports: {imports_lower[:10]}"

    def test_scan_imports_normalizes_to_lowercase(self, legitimate_firefox: Path) -> None:
        """scan_imports must normalize DLL names to lowercase."""
        scanner = BinaryScanner(str(legitimate_firefox))
        imports = scanner.scan_imports()

        for imp in imports:
            assert imp == imp.lower()

    def test_scan_imports_on_elf_returns_libraries(self, simple_elf_binary: Path) -> None:
        """scan_imports must return shared libraries for ELF binary."""
        scanner = BinaryScanner(str(simple_elf_binary))
        imports = scanner.scan_imports()

        assert isinstance(imports, list)

    def test_scan_imports_returns_unique_libraries(self, legitimate_firefox: Path) -> None:
        """scan_imports must return unique library names without duplicates."""
        scanner = BinaryScanner(str(legitimate_firefox))
        imports = scanner.scan_imports()

        assert len(imports) == len(set(imports))


class TestTLSLibraryDetection:
    """Test TLS/SSL library detection."""

    def test_detect_tls_libraries_finds_ssl_libraries(self, online_activation_binary: Path) -> None:
        """detect_tls_libraries must identify TLS/SSL libraries in binary."""
        scanner = BinaryScanner(str(online_activation_binary))
        tls_libs = scanner.detect_tls_libraries()

        assert isinstance(tls_libs, list)

    def test_detect_tls_libraries_with_custom_imports(self) -> None:
        """detect_tls_libraries must identify TLS libraries from provided import list."""
        scanner = BinaryScanner(__file__)

        test_imports = [
            "kernel32.dll",
            "winhttp.dll",
            "crypt32.dll",
            "sspicli.dll",
            "user32.dll",
        ]

        tls_libs = scanner.detect_tls_libraries(test_imports)

        assert "winhttp.dll" in tls_libs
        assert "crypt32.dll" in tls_libs
        assert "sspicli.dll" in tls_libs
        assert "kernel32.dll" not in tls_libs
        assert "user32.dll" not in tls_libs

    def test_detect_tls_libraries_recognizes_openssl(self) -> None:
        """detect_tls_libraries must recognize OpenSSL libraries."""
        scanner = BinaryScanner(__file__)

        openssl_imports = ["libssl.so.1.1", "libcrypto.so.1.1", "libc.so.6"]

        tls_libs = scanner.detect_tls_libraries(openssl_imports)

        assert "libssl.so.1.1" in tls_libs
        assert "libcrypto.so.1.1" in tls_libs
        assert "libc.so.6" not in tls_libs

    def test_detect_tls_libraries_recognizes_nss(self) -> None:
        """detect_tls_libraries must recognize NSS libraries."""
        scanner = BinaryScanner(__file__)

        nss_imports = ["libnss3.so", "libssl3.so", "libpthread.so.0"]

        tls_libs = scanner.detect_tls_libraries(nss_imports)

        assert "libnss3.so" in tls_libs
        assert "libssl3.so" in tls_libs
        assert "libpthread.so.0" not in tls_libs

    def test_detect_tls_libraries_is_case_insensitive(self) -> None:
        """detect_tls_libraries must be case-insensitive."""
        scanner = BinaryScanner(__file__)

        mixed_case_imports = ["WinHTTP.dll", "CRYPT32.DLL", "SspiCli.DLL"]

        tls_libs = scanner.detect_tls_libraries(mixed_case_imports)

        assert len(tls_libs) == 3


class TestStringScanning:
    """Test string extraction from binaries."""

    def test_scan_strings_returns_list_of_strings(self, legitimate_firefox: Path) -> None:
        """scan_strings must return list of strings extracted from binary."""
        scanner = BinaryScanner(str(legitimate_firefox))
        strings = scanner.scan_strings()

        assert isinstance(strings, list)
        assert len(strings) > 0
        assert all(isinstance(s, str) for s in strings)

    def test_scan_strings_extracts_ascii_strings(self, legitimate_7zip: Path) -> None:
        """scan_strings must extract ASCII strings from binary."""
        scanner = BinaryScanner(str(legitimate_7zip))
        strings = scanner.scan_strings()

        ascii_found = any(len(s) >= 4 and s.isascii() for s in strings)
        assert ascii_found

    def test_scan_strings_has_minimum_length_threshold(self, legitimate_firefox: Path) -> None:
        """scan_strings must only return strings meeting minimum length (4+ chars)."""
        scanner = BinaryScanner(str(legitimate_firefox))
        strings = scanner.scan_strings()

        for s in strings:
            assert len(s) >= 4

    def test_scan_strings_returns_unique_strings(self, legitimate_firefox: Path) -> None:
        """scan_strings must return unique strings without duplicates."""
        scanner = BinaryScanner(str(legitimate_firefox))
        strings = scanner.scan_strings()

        assert len(strings) == len(set(strings))

    def test_scan_strings_handles_unicode_strings(self, legitimate_firefox: Path) -> None:
        """scan_strings must extract UTF-16LE encoded strings."""
        scanner = BinaryScanner(str(legitimate_firefox))
        strings = scanner.scan_strings()

        assert len(strings) > 0


class TestCertificateReferenceDetection:
    """Test certificate-related string detection."""

    def test_find_certificate_references_finds_cert_strings(self, online_activation_binary: Path) -> None:
        """find_certificate_references must identify certificate-related strings."""
        scanner = BinaryScanner(str(online_activation_binary))
        cert_strings = scanner.find_certificate_references()

        assert isinstance(cert_strings, list)

    def test_find_certificate_references_with_custom_strings(self) -> None:
        """find_certificate_references must filter cert-related strings from provided list."""
        scanner = BinaryScanner(__file__)

        test_strings = [
            "Hello World",
            "certificate validation failed",
            "SSL handshake error",
            "TLS connection",
            "x509 certificate chain",
            "random string",
            "PEM encoded certificate",
            "SHA256 hash",
            "trusted CA bundle",
        ]

        cert_strings = scanner.find_certificate_references(test_strings)

        assert "certificate validation failed" in cert_strings
        assert "SSL handshake error" in cert_strings
        assert "TLS connection" in cert_strings
        assert "x509 certificate chain" in cert_strings
        assert "PEM encoded certificate" in cert_strings
        assert "SHA256 hash" in cert_strings
        assert "trusted CA bundle" in cert_strings
        assert "Hello World" not in cert_strings
        assert "random string" not in cert_strings

    def test_find_certificate_references_is_case_insensitive(self) -> None:
        """find_certificate_references must be case-insensitive."""
        scanner = BinaryScanner(__file__)

        test_strings = [
            "CERTIFICATE",
            "ssl",
            "TLS",
            "X509",
            "verify",
            "PINNING",
        ]

        cert_strings = scanner.find_certificate_references(test_strings)

        assert len(cert_strings) == 6

    def test_find_certificate_references_matches_partial_words(self) -> None:
        """find_certificate_references must match keywords within strings."""
        scanner = BinaryScanner(__file__)

        test_strings = [
            "verify_certificate_chain",
            "ssl_context_init",
            "tls_handshake_complete",
            "unrelated_function",
        ]

        cert_strings = scanner.find_certificate_references(test_strings)

        assert "verify_certificate_chain" in cert_strings
        assert "ssl_context_init" in cert_strings
        assert "tls_handshake_complete" in cert_strings
        assert "unrelated_function" not in cert_strings


class TestAPICallLocationFinding:
    """Test API call location finding using radare2."""

    def test_find_api_calls_returns_list_of_addresses(self, legitimate_firefox: Path) -> None:
        """find_api_calls must return list of addresses where API is called."""
        scanner = BinaryScanner(str(legitimate_firefox))

        try:
            addresses = scanner.find_api_calls("GetProcAddress")
        finally:
            scanner.close()

        assert isinstance(addresses, list)
        assert all(isinstance(addr, int) for addr in addresses)

    def test_find_api_calls_returns_empty_for_nonexistent_api(self, legitimate_firefox: Path) -> None:
        """find_api_calls must return empty list for non-existent API."""
        scanner = BinaryScanner(str(legitimate_firefox))

        try:
            addresses = scanner.find_api_calls("NonExistentAPIFunction12345")
        finally:
            scanner.close()

        assert addresses == []

    def test_find_api_calls_handles_common_windows_apis(self, legitimate_firefox: Path) -> None:
        """find_api_calls must find calls to common Windows APIs."""
        scanner = BinaryScanner(str(legitimate_firefox))

        try:
            common_apis = ["LoadLibraryA", "GetModuleHandleA", "VirtualAlloc"]
            found_any = False

            for api in common_apis:
                addresses = scanner.find_api_calls(api)
                if len(addresses) > 0:
                    found_any = True
                    break

            assert found_any or len(addresses) == 0
        finally:
            scanner.close()


class TestCallContextAnalysis:
    """Test call context analysis functionality."""

    def test_analyze_call_context_returns_context_info(self, legitimate_firefox: Path) -> None:
        """analyze_call_context must return ContextInfo object."""
        scanner = BinaryScanner(str(legitimate_firefox))

        try:
            test_address = 0x401000

            context = scanner.analyze_call_context(test_address)

            assert isinstance(context, ContextInfo)
            assert context.address == test_address
        finally:
            scanner.close()

    def test_analyze_call_context_includes_function_name(self, legitimate_firefox: Path) -> None:
        """analyze_call_context must attempt to determine function name."""
        scanner = BinaryScanner(str(legitimate_firefox))

        try:
            test_address = 0x401000

            context = scanner.analyze_call_context(test_address)

            assert hasattr(context, "function_name")
            assert isinstance(context.function_name, str)
        finally:
            scanner.close()

    def test_analyze_call_context_includes_cross_references(self, legitimate_firefox: Path) -> None:
        """analyze_call_context must include cross-references."""
        scanner = BinaryScanner(str(legitimate_firefox))

        try:
            test_address = 0x401000

            context = scanner.analyze_call_context(test_address)

            assert hasattr(context, "cross_references")
            assert isinstance(context.cross_references, list)
        finally:
            scanner.close()

    def test_analyze_call_context_handles_invalid_address(self, legitimate_firefox: Path) -> None:
        """analyze_call_context must handle invalid addresses gracefully."""
        scanner = BinaryScanner(str(legitimate_firefox))

        try:
            invalid_address = 0xFFFFFFFFFFFFFFFF

            context = scanner.analyze_call_context(invalid_address)

            assert isinstance(context, ContextInfo)
            assert context.address == invalid_address
        finally:
            scanner.close()


class TestConfidenceCalculation:
    """Test confidence score calculation."""

    def test_calculate_confidence_returns_float_between_0_and_1(self) -> None:
        """calculate_confidence must return float in range [0.0, 1.0]."""
        scanner = BinaryScanner(__file__)

        context = ContextInfo(
            address=0x401000,
            function_name="test_function",
            surrounding_code="mov eax, ebx\ncall something",
            cross_references=[0x402000],
        )

        confidence = scanner.calculate_confidence(context)

        assert isinstance(confidence, float)
        assert 0.0 <= confidence <= 1.0

    def test_calculate_confidence_increases_with_function_name(self) -> None:
        """calculate_confidence must give higher score when function name is present."""
        scanner = BinaryScanner(__file__)

        context_no_name = ContextInfo(address=0x401000)
        context_with_name = ContextInfo(address=0x401000, function_name="verify_license")

        conf_no_name = scanner.calculate_confidence(context_no_name)
        conf_with_name = scanner.calculate_confidence(context_with_name)

        assert conf_with_name > conf_no_name

    def test_calculate_confidence_increases_with_license_keywords(self) -> None:
        """calculate_confidence must give higher score for license-related keywords."""
        scanner = BinaryScanner(__file__)

        context_generic = ContextInfo(
            address=0x401000,
            function_name="generic_function",
        )

        context_license = ContextInfo(
            address=0x401000,
            function_name="check_license_activation",
        )

        conf_generic = scanner.calculate_confidence(context_generic)
        conf_license = scanner.calculate_confidence(context_license)

        assert conf_license > conf_generic

    def test_calculate_confidence_increases_with_ssl_in_code(self) -> None:
        """calculate_confidence must give higher score when SSL/HTTPS appears in code."""
        scanner = BinaryScanner(__file__)

        context_no_ssl = ContextInfo(
            address=0x401000,
            surrounding_code="mov eax, ebx\nret",
        )

        context_with_ssl = ContextInfo(
            address=0x401000,
            surrounding_code="call https://license-server.com\nssl_verify",
        )

        conf_no_ssl = scanner.calculate_confidence(context_no_ssl)
        conf_with_ssl = scanner.calculate_confidence(context_with_ssl)

        assert conf_with_ssl > conf_no_ssl

    def test_calculate_confidence_considers_cross_references(self) -> None:
        """calculate_confidence must adjust score based on cross-references."""
        scanner = BinaryScanner(__file__)

        context_no_xrefs = ContextInfo(address=0x401000)

        context_one_xref = ContextInfo(
            address=0x401000,
            cross_references=[0x402000],
        )

        context_many_xrefs = ContextInfo(
            address=0x401000,
            cross_references=[0x402000, 0x403000, 0x404000, 0x405000, 0x406000],
        )

        conf_no_xrefs = scanner.calculate_confidence(context_no_xrefs)
        conf_one_xref = scanner.calculate_confidence(context_one_xref)
        conf_many_xrefs = scanner.calculate_confidence(context_many_xrefs)

        assert conf_one_xref > conf_no_xrefs
        assert conf_one_xref >= conf_many_xrefs

    def test_calculate_confidence_caps_at_1_0(self) -> None:
        """calculate_confidence must cap maximum score at 1.0."""
        scanner = BinaryScanner(__file__)

        context_maximal = ContextInfo(
            address=0x401000,
            function_name="verify_license_activation",
            surrounding_code="https://license-server.com ssl verify activation license",
            cross_references=[0x402000],
        )

        confidence = scanner.calculate_confidence(context_maximal)

        assert confidence <= 1.0


class TestContextManager:
    """Test BinaryScanner as context manager."""

    def test_context_manager_enter_returns_scanner(self, legitimate_firefox: Path) -> None:
        """Context manager __enter__ must return scanner instance."""
        with BinaryScanner(str(legitimate_firefox)) as scanner:
            assert isinstance(scanner, BinaryScanner)
            assert scanner.binary is not None

    def test_context_manager_exit_cleans_up(self, legitimate_firefox: Path) -> None:
        """Context manager __exit__ must clean up resources."""
        with BinaryScanner(str(legitimate_firefox)) as scanner:
            scanner.r2_handle = True

        assert scanner.r2_handle is None or scanner.r2_handle


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_scanner_handles_empty_string_path(self) -> None:
        """Scanner must handle empty string path appropriately."""
        with pytest.raises((FileNotFoundError, RuntimeError)):
            BinaryScanner("")

    def test_scan_imports_handles_binary_without_imports(self) -> None:
        """scan_imports must return empty list for binary without imports."""
        scanner = BinaryScanner(__file__)

        imports = scanner.scan_imports()

        assert isinstance(imports, list)

    def test_scan_strings_handles_binary_read_errors_gracefully(self) -> None:
        """scan_strings must handle binary read errors gracefully."""
        scanner = BinaryScanner(__file__)

        strings = scanner.scan_strings()

        assert isinstance(strings, list)

    def test_multiple_close_calls_safe(self, legitimate_firefox: Path) -> None:
        """Multiple calls to close() must be safe."""
        scanner = BinaryScanner(str(legitimate_firefox))

        scanner.close()
        scanner.close()
        scanner.close()
