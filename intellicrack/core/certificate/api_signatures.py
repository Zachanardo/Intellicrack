"""API signatures for certificate validation functions across different TLS/SSL libraries.

CAPABILITIES:
- Comprehensive database of certificate validation API signatures
- Support for Windows (WinHTTP, Schannel, CryptoAPI)
- Support for Linux/Unix (OpenSSL, NSS)
- Support for Android (BoringSSL, OpenSSL)
- Support for iOS/macOS (Security framework)
- Platform-specific calling convention information
- Function return type specifications for proper hooking/patching
- Library type detection from DLL/SO names

LIMITATIONS:
- Does not detect custom certificate validation implementations
- Limited to known TLS/SSL library APIs
- May not include all API variants across different library versions
- Signature database requires manual updates for new APIs
- No automatic signature discovery from unknown libraries

USAGE EXAMPLES:
    # Get all signatures for a specific library
    from intellicrack.core.certificate.api_signatures import get_signatures_by_library

    winhttp_sigs = get_signatures_by_library("winhttp.dll")
    for sig in winhttp_sigs:
        print(f"{sig.name}: {sig.description}")

    # Get signature for a specific function
    from intellicrack.core.certificate.api_signatures import get_signature_by_name

    sig = get_signature_by_name("SSL_CTX_set_verify")
    if sig:
        print(f"Library: {sig.library}, Convention: {sig.calling_convention}")

    # Get all signatures for a platform
    from intellicrack.core.certificate.api_signatures import (
        get_signatures_by_platform,
        Platform
    )

    windows_sigs = get_signatures_by_platform(Platform.WINDOWS)
    print(f"Found {len(windows_sigs)} Windows certificate APIs")

    # Determine library type
    from intellicrack.core.certificate.api_signatures import get_library_type

    lib_type = get_library_type("libssl.so.1.1")
    print(f"Library type: {lib_type}")  # Output: openssl

RELATED MODULES:
- validation_detector.py: Uses these signatures to detect cert validation in binaries
- binary_scanner.py: Scans binaries for imports matching these signatures
- cert_patcher.py: Uses calling conventions to generate proper patches
- frida_cert_hooks.py: Uses signatures to hook these APIs at runtime
- patch_templates.py: References these APIs in pre-built patch templates

DATABASE COVERAGE:
- WinHTTP: 4 APIs (WinHttpSetOption, WinHttpSendRequest, etc.)
- Schannel: 6 APIs (InitializeSecurityContext, QueryContextAttributes, etc.)
- CryptoAPI: 5 APIs (CertVerifyCertificateChainPolicy, CertGetCertificateChain, etc.)
- OpenSSL: 9 APIs (SSL_CTX_set_verify, SSL_get_verify_result, etc.)
- NSS (Firefox): 4 APIs (CERT_VerifyCertificate, CERT_PKIXVerifyCert, etc.)
- BoringSSL (Chrome/Android): 2 APIs (SSL_set_custom_verify, etc.)
- iOS/macOS: 3 APIs (SecTrustEvaluate, SSLHandshake, etc.)
"""

from dataclasses import dataclass
from enum import Enum


class CallingConvention(Enum):
    """Calling conventions for API functions across platforms."""

    STDCALL = "stdcall"
    CDECL = "cdecl"
    FASTCALL = "fastcall"
    X64_MS = "x64_ms"
    X64_SYSV = "x64_sysv"


class Platform(Enum):
    """Target platforms for certificate validation APIs."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"
    ALL = "all"


@dataclass
class APISignature:
    """Signature information for a certificate validation API function."""

    name: str
    library: str
    platforms: list[Platform]
    calling_convention: CallingConvention
    return_type: str
    description: str


WINHTTP_SIGNATURES = [
    APISignature(
        name="WinHttpSetOption",
        library="winhttp.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="BOOL",
        description="Sets WinHTTP options including certificate validation flags",
    ),
    APISignature(
        name="WinHttpSendRequest",
        library="winhttp.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="BOOL",
        description="Sends HTTP request with certificate validation",
    ),
    APISignature(
        name="WinHttpQueryOption",
        library="winhttp.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="BOOL",
        description="Queries WinHTTP options including security flags",
    ),
    APISignature(
        name="WinHttpReceiveResponse",
        library="winhttp.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="BOOL",
        description="Receives HTTP response after certificate validation",
    ),
]

SCHANNEL_SIGNATURES = [
    APISignature(
        name="InitializeSecurityContext",
        library="sspicli.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="SECURITY_STATUS",
        description="Initiates TLS context with certificate validation",
    ),
    APISignature(
        name="InitializeSecurityContextW",
        library="sspicli.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="SECURITY_STATUS",
        description="Unicode version of InitializeSecurityContext",
    ),
    APISignature(
        name="QueryContextAttributes",
        library="sspicli.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="SECURITY_STATUS",
        description="Queries security context attributes including remote certificate",
    ),
    APISignature(
        name="QueryContextAttributesW",
        library="sspicli.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="SECURITY_STATUS",
        description="Unicode version of QueryContextAttributes",
    ),
    APISignature(
        name="EncryptMessage",
        library="sspicli.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="SECURITY_STATUS",
        description="Encrypts message after certificate validation",
    ),
    APISignature(
        name="DecryptMessage",
        library="sspicli.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="SECURITY_STATUS",
        description="Decrypts message in established TLS context",
    ),
]

CRYPTOAPI_SIGNATURES = [
    APISignature(
        name="CertVerifyCertificateChainPolicy",
        library="crypt32.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="BOOL",
        description="Verifies certificate chain against policy",
    ),
    APISignature(
        name="CertGetCertificateChain",
        library="crypt32.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="BOOL",
        description="Builds certificate chain for validation",
    ),
    APISignature(
        name="CertFreeCertificateChain",
        library="crypt32.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="void",
        description="Frees certificate chain context",
    ),
    APISignature(
        name="CertCreateCertificateChainEngine",
        library="crypt32.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="BOOL",
        description="Creates certificate chain engine for validation",
    ),
    APISignature(
        name="CertVerifyTimeValidity",
        library="crypt32.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="LONG",
        description="Verifies certificate time validity",
    ),
]

OPENSSL_SIGNATURES = [
    APISignature(
        name="SSL_CTX_set_verify",
        library="libssl.so",
        platforms=[Platform.LINUX, Platform.ANDROID],
        calling_convention=CallingConvention.CDECL,
        return_type="void",
        description="Sets certificate verification mode for SSL context",
    ),
    APISignature(
        name="SSL_get_verify_result",
        library="libssl.so",
        platforms=[Platform.LINUX, Platform.ANDROID],
        calling_convention=CallingConvention.CDECL,
        return_type="long",
        description="Gets certificate verification result",
    ),
    APISignature(
        name="SSL_set_verify",
        library="libssl.so",
        platforms=[Platform.LINUX, Platform.ANDROID],
        calling_convention=CallingConvention.CDECL,
        return_type="void",
        description="Sets certificate verification mode for SSL object",
    ),
    APISignature(
        name="SSL_CTX_set_cert_verify_callback",
        library="libssl.so",
        platforms=[Platform.LINUX, Platform.ANDROID],
        calling_convention=CallingConvention.CDECL,
        return_type="void",
        description="Sets custom certificate verification callback",
    ),
    APISignature(
        name="SSL_CTX_load_verify_locations",
        library="libssl.so",
        platforms=[Platform.LINUX, Platform.ANDROID],
        calling_convention=CallingConvention.CDECL,
        return_type="int",
        description="Loads CA certificates for verification",
    ),
    APISignature(
        name="X509_verify_cert",
        library="libcrypto.so",
        platforms=[Platform.LINUX, Platform.ANDROID],
        calling_convention=CallingConvention.CDECL,
        return_type="int",
        description="Verifies X509 certificate",
    ),
    APISignature(
        name="X509_STORE_CTX_get_error",
        library="libcrypto.so",
        platforms=[Platform.LINUX, Platform.ANDROID],
        calling_convention=CallingConvention.CDECL,
        return_type="int",
        description="Gets certificate verification error code",
    ),
    APISignature(
        name="SSL_CTX_set_verify_depth",
        library="libssl.so",
        platforms=[Platform.LINUX, Platform.ANDROID],
        calling_convention=CallingConvention.CDECL,
        return_type="void",
        description="Sets maximum certificate chain depth",
    ),
    APISignature(
        name="SSL_set_verify_depth",
        library="libssl.so",
        platforms=[Platform.LINUX, Platform.ANDROID],
        calling_convention=CallingConvention.CDECL,
        return_type="void",
        description="Sets maximum certificate chain depth for SSL object",
    ),
]

OPENSSL_WINDOWS_SIGNATURES = [
    APISignature(
        name="SSL_CTX_set_verify",
        library="libssl-1_1-x64.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.X64_MS,
        return_type="void",
        description="Sets certificate verification mode for SSL context (Windows)",
    ),
    APISignature(
        name="SSL_get_verify_result",
        library="libssl-1_1-x64.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.X64_MS,
        return_type="long",
        description="Gets certificate verification result (Windows)",
    ),
    APISignature(
        name="SSL_CTX_set_verify",
        library="libssl-1_1.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="void",
        description="Sets certificate verification mode for SSL context (Windows 32-bit)",
    ),
]

NSS_SIGNATURES = [
    APISignature(
        name="CERT_VerifyCertificate",
        library="libnss3.so",
        platforms=[Platform.LINUX],
        calling_convention=CallingConvention.CDECL,
        return_type="SECStatus",
        description="Verifies certificate using NSS (Firefox)",
    ),
    APISignature(
        name="CERT_PKIXVerifyCert",
        library="libnss3.so",
        platforms=[Platform.LINUX],
        calling_convention=CallingConvention.CDECL,
        return_type="SECStatus",
        description="PKIX certificate verification in NSS",
    ),
    APISignature(
        name="SSL_AuthCertificateHook",
        library="libssl3.so",
        platforms=[Platform.LINUX],
        calling_convention=CallingConvention.CDECL,
        return_type="SECStatus",
        description="Sets SSL certificate authentication hook",
    ),
    APISignature(
        name="CERT_VerifyCertificate",
        library="nss3.dll",
        platforms=[Platform.WINDOWS],
        calling_convention=CallingConvention.STDCALL,
        return_type="SECStatus",
        description="Verifies certificate using NSS on Windows",
    ),
]

BORINGSSL_SIGNATURES = [
    APISignature(
        name="SSL_set_custom_verify",
        library="libssl.so",
        platforms=[Platform.ANDROID],
        calling_convention=CallingConvention.CDECL,
        return_type="void",
        description="Sets custom certificate verification callback (BoringSSL)",
    ),
    APISignature(
        name="SSL_CTX_set_custom_verify",
        library="libssl.so",
        platforms=[Platform.ANDROID],
        calling_convention=CallingConvention.CDECL,
        return_type="void",
        description="Sets custom certificate verification for context (BoringSSL)",
    ),
]

IOS_SIGNATURES = [
    APISignature(
        name="SecTrustEvaluate",
        library="Security",
        platforms=[Platform.IOS, Platform.MACOS],
        calling_convention=CallingConvention.X64_SYSV,
        return_type="OSStatus",
        description="Evaluates certificate trust on iOS/macOS",
    ),
    APISignature(
        name="SSLHandshake",
        library="Security",
        platforms=[Platform.IOS, Platform.MACOS],
        calling_convention=CallingConvention.X64_SYSV,
        return_type="OSStatus",
        description="Performs SSL handshake with certificate validation",
    ),
    APISignature(
        name="SSLSetSessionOption",
        library="CFNetwork",
        platforms=[Platform.IOS, Platform.MACOS],
        calling_convention=CallingConvention.X64_SYSV,
        return_type="OSStatus",
        description="Sets SSL session options including certificate pinning",
    ),
]

ALL_SIGNATURES = (
    WINHTTP_SIGNATURES
    + SCHANNEL_SIGNATURES
    + CRYPTOAPI_SIGNATURES
    + OPENSSL_SIGNATURES
    + OPENSSL_WINDOWS_SIGNATURES
    + NSS_SIGNATURES
    + BORINGSSL_SIGNATURES
    + IOS_SIGNATURES
)


def get_signatures_by_library(library_name: str) -> list[APISignature]:
    """Get all API signatures for a specific library.

    Args:
        library_name: Name of the library (e.g., "winhttp.dll", "libssl.so")

    Returns:
        List of APISignature objects for the specified library

    """
    library_name_lower = library_name.lower()
    return [sig for sig in ALL_SIGNATURES if sig.library.lower() == library_name_lower]


def get_all_signatures() -> list[APISignature]:
    """Get all API signatures.

    Returns:
        List of all APISignature objects

    """
    return ALL_SIGNATURES.copy()


def get_signature_by_name(name: str) -> APISignature | None:
    """Get API signature by function name.

    Args:
        name: Function name (e.g., "SSL_CTX_set_verify")

    Returns:
        APISignature object if found, None otherwise

    """
    return next((sig for sig in ALL_SIGNATURES if sig.name == name), None)


def get_signatures_by_platform(platform: Platform) -> list[APISignature]:
    """Get all API signatures for a specific platform.

    Args:
        platform: Platform enum value

    Returns:
        List of APISignature objects for the specified platform

    """
    return [
        sig for sig in ALL_SIGNATURES if platform in sig.platforms or Platform.ALL in sig.platforms
    ]


def get_library_type(library_name: str) -> str | None:
    """Determine the type of TLS library from its name.

    Args:
        library_name: Name of the library

    Returns:
        Library type string ("winhttp", "schannel", "cryptoapi", "openssl", "nss", "boringssl")
        or None if unknown

    """
    library_name_lower = library_name.lower()

    if "winhttp" in library_name_lower:
        return "winhttp"
    if "sspicli" in library_name_lower or "secur32" in library_name_lower:
        return "schannel"
    if "crypt32" in library_name_lower:
        return "cryptoapi"
    if "libssl" in library_name_lower or "libcrypto" in library_name_lower:
        return "openssl"
    if "nss3" in library_name_lower or "ssl3" in library_name_lower:
        return "nss"
    if "security" in library_name_lower or "cfnetwork" in library_name_lower:
        return "ios_security"

    return None
