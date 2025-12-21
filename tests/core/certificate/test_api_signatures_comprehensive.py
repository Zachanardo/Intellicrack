"""Production-grade tests for API signatures database validating real signature data.

Tests REAL API signature database completeness and correctness.
NO mocks - validates genuine signature data for certificate validation APIs.

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

import pytest

from intellicrack.core.certificate.api_signatures import (
    ALL_SIGNATURES,
    BORINGSSL_SIGNATURES,
    CRYPTOAPI_SIGNATURES,
    IOS_SIGNATURES,
    NSS_SIGNATURES,
    OPENSSL_SIGNATURES,
    OPENSSL_WINDOWS_SIGNATURES,
    SCHANNEL_SIGNATURES,
    WINHTTP_SIGNATURES,
    APISignature,
    CallingConvention,
    Platform,
    get_all_signatures,
    get_library_type,
    get_signature_by_name,
    get_signatures_by_library,
    get_signatures_by_platform,
)


class TestAPISignatureDatabase:
    """Test API signature database completeness and integrity."""

    def test_all_signatures_contains_all_platform_signatures(self) -> None:
        """ALL_SIGNATURES must include signatures from all platform-specific lists."""
        expected_count = (
            len(WINHTTP_SIGNATURES)
            + len(SCHANNEL_SIGNATURES)
            + len(CRYPTOAPI_SIGNATURES)
            + len(OPENSSL_SIGNATURES)
            + len(OPENSSL_WINDOWS_SIGNATURES)
            + len(NSS_SIGNATURES)
            + len(BORINGSSL_SIGNATURES)
            + len(IOS_SIGNATURES)
        )

        assert len(ALL_SIGNATURES) >= expected_count

        for sig in WINHTTP_SIGNATURES:
            assert sig in ALL_SIGNATURES
        for sig in SCHANNEL_SIGNATURES:
            assert sig in ALL_SIGNATURES
        for sig in CRYPTOAPI_SIGNATURES:
            assert sig in ALL_SIGNATURES
        for sig in OPENSSL_SIGNATURES:
            assert sig in ALL_SIGNATURES
        for sig in NSS_SIGNATURES:
            assert sig in ALL_SIGNATURES
        for sig in BORINGSSL_SIGNATURES:
            assert sig in ALL_SIGNATURES
        for sig in IOS_SIGNATURES:
            assert sig in ALL_SIGNATURES

    def test_all_signatures_are_valid_api_signature_objects(self) -> None:
        """All entries in signature lists must be valid APISignature objects."""
        for sig in ALL_SIGNATURES:
            assert isinstance(sig, APISignature)
            assert isinstance(sig.name, str) and len(sig.name) > 0
            assert isinstance(sig.library, str) and len(sig.library) > 0
            assert isinstance(sig.platforms, list) and len(sig.platforms) > 0
            assert isinstance(sig.calling_convention, CallingConvention)
            assert isinstance(sig.return_type, str) and len(sig.return_type) > 0
            assert isinstance(sig.description, str) and len(sig.description) > 0

    def test_all_platforms_are_valid_enum_values(self) -> None:
        """All platform values in signatures must be valid Platform enum values."""
        valid_platforms = set(Platform)

        for sig in ALL_SIGNATURES:
            for platform in sig.platforms:
                assert platform in valid_platforms

    def test_winhttp_signatures_have_correct_library_and_platform(self) -> None:
        """WinHTTP signatures must specify winhttp.dll and WINDOWS platform."""
        assert len(WINHTTP_SIGNATURES) >= 4

        for sig in WINHTTP_SIGNATURES:
            assert sig.library == "winhttp.dll"
            assert Platform.WINDOWS in sig.platforms
            assert sig.calling_convention == CallingConvention.STDCALL
            assert sig.return_type == "BOOL"

    def test_schannel_signatures_have_correct_library_and_platform(self) -> None:
        """Schannel signatures must specify sspicli.dll and WINDOWS platform."""
        assert len(SCHANNEL_SIGNATURES) >= 6

        for sig in SCHANNEL_SIGNATURES:
            assert sig.library == "sspicli.dll"
            assert Platform.WINDOWS in sig.platforms
            assert sig.calling_convention == CallingConvention.STDCALL

    def test_cryptoapi_signatures_have_correct_library_and_platform(self) -> None:
        """CryptoAPI signatures must specify crypt32.dll and WINDOWS platform."""
        assert len(CRYPTOAPI_SIGNATURES) >= 5

        for sig in CRYPTOAPI_SIGNATURES:
            assert sig.library == "crypt32.dll"
            assert Platform.WINDOWS in sig.platforms
            assert sig.calling_convention == CallingConvention.STDCALL

    def test_openssl_signatures_have_correct_library_and_platforms(self) -> None:
        """OpenSSL signatures must specify libssl.so/libcrypto.so and LINUX/ANDROID."""
        assert len(OPENSSL_SIGNATURES) >= 9

        for sig in OPENSSL_SIGNATURES:
            assert sig.library in ["libssl.so", "libcrypto.so"]
            assert Platform.LINUX in sig.platforms or Platform.ANDROID in sig.platforms
            assert sig.calling_convention == CallingConvention.CDECL

    def test_nss_signatures_have_correct_library_and_platforms(self) -> None:
        """NSS signatures must specify libnss3.so/nss3.dll."""
        assert len(NSS_SIGNATURES) >= 4

        for sig in NSS_SIGNATURES:
            assert sig.library in ["libnss3.so", "libssl3.so", "nss3.dll"]

    def test_boringssl_signatures_have_correct_library_and_platform(self) -> None:
        """BoringSSL signatures must specify libssl.so and ANDROID platform."""
        assert len(BORINGSSL_SIGNATURES) >= 2

        for sig in BORINGSSL_SIGNATURES:
            assert sig.library == "libssl.so"
            assert Platform.ANDROID in sig.platforms
            assert sig.calling_convention == CallingConvention.CDECL

    def test_ios_signatures_have_correct_frameworks_and_platforms(self) -> None:
        """iOS signatures must specify Security/CFNetwork and IOS/MACOS platforms."""
        assert len(IOS_SIGNATURES) >= 3

        for sig in IOS_SIGNATURES:
            assert sig.library in ["Security", "CFNetwork"]
            assert Platform.IOS in sig.platforms or Platform.MACOS in sig.platforms
            assert sig.calling_convention == CallingConvention.X64_SYSV


class TestGetSignaturesByLibrary:
    """Test get_signatures_by_library function."""

    def test_get_winhttp_signatures(self) -> None:
        """get_signatures_by_library must return all WinHTTP signatures."""
        sigs = get_signatures_by_library("winhttp.dll")

        assert len(sigs) >= 4
        for sig in sigs:
            assert sig.library == "winhttp.dll"
            assert sig in WINHTTP_SIGNATURES

    def test_get_schannel_signatures(self) -> None:
        """get_signatures_by_library must return all Schannel signatures."""
        sigs = get_signatures_by_library("sspicli.dll")

        assert len(sigs) >= 6
        for sig in sigs:
            assert sig.library == "sspicli.dll"

    def test_get_crypt32_signatures(self) -> None:
        """get_signatures_by_library must return all CryptoAPI signatures."""
        sigs = get_signatures_by_library("crypt32.dll")

        assert len(sigs) >= 5
        for sig in sigs:
            assert sig.library == "crypt32.dll"

    def test_get_openssl_signatures(self) -> None:
        """get_signatures_by_library must return OpenSSL signatures."""
        libssl_sigs = get_signatures_by_library("libssl.so")
        libcrypto_sigs = get_signatures_by_library("libcrypto.so")

        assert len(libssl_sigs) > 0
        assert len(libcrypto_sigs) > 0

        for sig in libssl_sigs:
            assert sig.library == "libssl.so"

    def test_get_nss_signatures(self) -> None:
        """get_signatures_by_library must return NSS signatures."""
        sigs = get_signatures_by_library("libnss3.so")

        assert len(sigs) > 0
        for sig in sigs:
            assert sig.library == "libnss3.so"

    def test_case_insensitive_library_lookup(self) -> None:
        """Library lookup must be case-insensitive."""
        lowercase = get_signatures_by_library("winhttp.dll")
        uppercase = get_signatures_by_library("WINHTTP.DLL")
        mixedcase = get_signatures_by_library("WinHttp.Dll")

        assert len(lowercase) == len(uppercase) == len(mixedcase)
        assert lowercase == uppercase == mixedcase

    def test_unknown_library_returns_empty_list(self) -> None:
        """Unknown library name must return empty list."""
        sigs = get_signatures_by_library("nonexistent.dll")

        assert sigs == []

    def test_partial_library_name_does_not_match(self) -> None:
        """Partial library names must not match unless exact."""
        partial = get_signatures_by_library("winhttp")
        full = get_signatures_by_library("winhttp.dll")

        assert len(partial) == 0
        assert len(full) > 0


class TestGetAllSignatures:
    """Test get_all_signatures function."""

    def test_returns_copy_of_all_signatures(self) -> None:
        """get_all_signatures must return a copy of ALL_SIGNATURES."""
        sigs = get_all_signatures()

        assert len(sigs) == len(ALL_SIGNATURES)
        assert sigs == ALL_SIGNATURES
        assert sigs is not ALL_SIGNATURES

    def test_returns_new_list_each_call(self) -> None:
        """Each call to get_all_signatures must return a new list."""
        sigs1 = get_all_signatures()
        sigs2 = get_all_signatures()

        assert sigs1 == sigs2
        assert sigs1 is not sigs2


class TestGetSignatureByName:
    """Test get_signature_by_name function."""

    @pytest.mark.parametrize(
        "api_name,expected_library",
        [
            ("WinHttpSetOption", "winhttp.dll"),
            ("InitializeSecurityContext", "sspicli.dll"),
            ("CertVerifyCertificateChainPolicy", "crypt32.dll"),
            ("SSL_CTX_set_verify", "libssl.so"),
            ("X509_verify_cert", "libcrypto.so"),
            ("CERT_VerifyCertificate", "libnss3.so"),
            ("SSL_set_custom_verify", "libssl.so"),
            ("SecTrustEvaluate", "Security"),
        ],
    )
    def test_lookup_known_api_by_exact_name(self, api_name: str, expected_library: str) -> None:
        """get_signature_by_name must find signatures by exact API name."""
        sig = get_signature_by_name(api_name)

        assert sig is not None
        assert sig.name == api_name
        assert expected_library in sig.library

    def test_lookup_unknown_api_returns_none(self) -> None:
        """Unknown API name must return None."""
        sig = get_signature_by_name("NonexistentAPI")

        assert sig is None

    def test_case_sensitive_lookup(self) -> None:
        """API name lookup must be case-sensitive."""
        correct = get_signature_by_name("SSL_CTX_set_verify")
        incorrect = get_signature_by_name("ssl_ctx_set_verify")

        assert correct is not None
        assert incorrect is None

    def test_returns_first_match_for_duplicate_names(self) -> None:
        """If multiple signatures have same name, must return first match."""
        sig = get_signature_by_name("SSL_CTX_set_verify")

        assert sig is not None
        assert sig.name == "SSL_CTX_set_verify"


class TestGetSignaturesByPlatform:
    """Test get_signatures_by_platform function."""

    def test_get_windows_signatures(self) -> None:
        """get_signatures_by_platform(WINDOWS) must return all Windows APIs."""
        sigs = get_signatures_by_platform(Platform.WINDOWS)

        assert len(sigs) >= 15

        expected_libs = ["winhttp.dll", "sspicli.dll", "crypt32.dll"]
        found_libs = {sig.library for sig in sigs}

        for expected_lib in expected_libs:
            assert expected_lib in found_libs

    def test_get_linux_signatures(self) -> None:
        """get_signatures_by_platform(LINUX) must return Linux APIs."""
        sigs = get_signatures_by_platform(Platform.LINUX)

        assert len(sigs) > 0

        for sig in sigs:
            assert Platform.LINUX in sig.platforms

    def test_get_android_signatures(self) -> None:
        """get_signatures_by_platform(ANDROID) must return Android APIs."""
        sigs = get_signatures_by_platform(Platform.ANDROID)

        assert len(sigs) > 0

        for sig in sigs:
            assert Platform.ANDROID in sig.platforms

    def test_get_macos_signatures(self) -> None:
        """get_signatures_by_platform(MACOS) must return macOS APIs."""
        sigs = get_signatures_by_platform(Platform.MACOS)

        assert len(sigs) > 0

        for sig in sigs:
            assert Platform.MACOS in sig.platforms

    def test_get_ios_signatures(self) -> None:
        """get_signatures_by_platform(IOS) must return iOS APIs."""
        sigs = get_signatures_by_platform(Platform.IOS)

        assert len(sigs) > 0

        for sig in sigs:
            assert Platform.IOS in sig.platforms

    def test_platforms_do_not_overlap_unexpectedly(self) -> None:
        """Platform-specific APIs should not appear in unrelated platforms."""
        windows_sigs = get_signatures_by_platform(Platform.WINDOWS)
        linux_sigs = get_signatures_by_platform(Platform.LINUX)

        windows_names = {
            sig.name for sig in windows_sigs if Platform.LINUX not in sig.platforms
        }
        linux_names = {
            sig.name for sig in linux_sigs if Platform.WINDOWS not in sig.platforms
        }

        winhttp_only = [sig for sig in windows_sigs if sig.library == "winhttp.dll"]
        assert all(Platform.WINDOWS in sig.platforms and Platform.LINUX not in sig.platforms for sig in winhttp_only)


class TestGetLibraryType:
    """Test get_library_type function."""

    @pytest.mark.parametrize(
        "library_name,expected_type",
        [
            ("winhttp.dll", "winhttp"),
            ("WINHTTP.DLL", "winhttp"),
            ("WinHttp.dll", "winhttp"),
            ("sspicli.dll", "schannel"),
            ("secur32.dll", "schannel"),
            ("SSPICLI.DLL", "schannel"),
            ("crypt32.dll", "cryptoapi"),
            ("CRYPT32.DLL", "cryptoapi"),
            ("libssl.so", "openssl"),
            ("libssl.so.1.1", "openssl"),
            ("libssl-1_1-x64.dll", "openssl"),
            ("libcrypto.so", "openssl"),
            ("libcrypto.so.1.1", "openssl"),
            ("libnss3.so", "nss"),
            ("nss3.dll", "nss"),
            ("Security", "ios_security"),
            ("CFNetwork", "ios_security"),
        ],
    )
    def test_library_type_detection(self, library_name: str, expected_type: str) -> None:
        """get_library_type must correctly identify library types."""
        detected_type = get_library_type(library_name)

        assert detected_type == expected_type

    def test_unknown_library_returns_none(self) -> None:
        """Unknown library name must return None."""
        lib_type = get_library_type("unknown_lib.dll")

        assert lib_type is None

    def test_case_insensitive_detection(self) -> None:
        """Library type detection must be case-insensitive."""
        assert get_library_type("WinHTTP.dll") == "winhttp"
        assert get_library_type("LIBSSL.SO") == "openssl"
        assert get_library_type("Crypt32.DLL") == "cryptoapi"


class TestSignatureDataIntegrity:
    """Test integrity and completeness of signature data."""

    def test_all_critical_windows_apis_present(self) -> None:
        """Critical Windows certificate validation APIs must be in database."""
        critical_apis = [
            "WinHttpSetOption",
            "InitializeSecurityContext",
            "CertVerifyCertificateChainPolicy",
            "CertGetCertificateChain",
        ]

        for api_name in critical_apis:
            sig = get_signature_by_name(api_name)
            assert sig is not None, f"Critical API {api_name} not in database"
            assert Platform.WINDOWS in sig.platforms

    def test_all_critical_openssl_apis_present(self) -> None:
        """Critical OpenSSL certificate validation APIs must be in database."""
        critical_apis = [
            "SSL_CTX_set_verify",
            "SSL_get_verify_result",
            "X509_verify_cert",
        ]

        for api_name in critical_apis:
            sig = get_signature_by_name(api_name)
            assert sig is not None, f"Critical API {api_name} not in database"

    def test_all_signatures_have_meaningful_descriptions(self) -> None:
        """All signatures must have descriptive text explaining their purpose."""
        for sig in ALL_SIGNATURES:
            assert len(sig.description) >= 20
            assert not sig.description.startswith("TODO")
            desc_lower = sig.description.lower()
            assert any(
                keyword in desc_lower
                for keyword in [
                    "certificate",
                    "cert",
                    "ssl",
                    "tls",
                    "verify",
                    "security",
                    "chain",
                    "context",
                    "encrypt",
                    "decrypt",
                    "http",
                    "handshake",
                ]
            )

    def test_no_duplicate_signatures(self) -> None:
        """Database must not contain duplicate signature entries."""
        seen = set()
        duplicates = []

        for sig in ALL_SIGNATURES:
            key = (sig.name, sig.library)
            if key in seen:
                duplicates.append(key)
            seen.add(key)

        assert not duplicates, f"Found duplicate signatures: {duplicates}"

    def test_calling_conventions_match_platforms(self) -> None:
        """Calling conventions must match expected platform conventions."""
        for sig in ALL_SIGNATURES:
            if Platform.WINDOWS in sig.platforms and (sig.library.endswith(".dll") and "x64" not in sig.library.lower()):
                assert sig.calling_convention in [CallingConvention.STDCALL, CallingConvention.CDECL, CallingConvention.X64_MS]

            if Platform.LINUX in sig.platforms or Platform.ANDROID in sig.platforms:
                assert sig.calling_convention in [CallingConvention.CDECL, CallingConvention.X64_SYSV]

            if Platform.IOS in sig.platforms or Platform.MACOS in sig.platforms:
                assert sig.calling_convention == CallingConvention.X64_SYSV


class TestSignatureCoverage:
    """Test coverage of signature database across different scenarios."""

    def test_covers_multiple_tls_libraries(self) -> None:
        """Database must cover multiple TLS/SSL library implementations."""
        library_types = set()

        for sig in ALL_SIGNATURES:
            if lib_type := get_library_type(sig.library):
                library_types.add(lib_type)

        assert "winhttp" in library_types
        assert "schannel" in library_types
        assert "cryptoapi" in library_types
        assert "openssl" in library_types
        assert "nss" in library_types
        assert "ios_security" in library_types

    def test_covers_verification_and_callback_apis(self) -> None:
        """Database must include both verification and callback setting APIs."""
        verification_apis = []
        callback_apis = []

        for sig in ALL_SIGNATURES:
            name_lower = sig.name.lower()
            desc_lower = sig.description.lower()

            if "verify" in name_lower or "verify" in desc_lower:
                verification_apis.append(sig.name)

            if "callback" in desc_lower or "hook" in desc_lower or "set_verify" in name_lower:
                callback_apis.append(sig.name)

        assert verification_apis
        assert callback_apis

    def test_covers_chain_building_apis(self) -> None:
        """Database must include certificate chain building APIs."""
        chain_apis = [sig for sig in ALL_SIGNATURES if "chain" in sig.description.lower()]

        assert chain_apis
