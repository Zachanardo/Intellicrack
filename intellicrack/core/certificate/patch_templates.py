"""Predefined patch templates for certificate validation APIs."""

from dataclasses import dataclass
from typing import Optional

from intellicrack.core.certificate.patch_generators import (
    Architecture,
    generate_always_succeed_x64,
    generate_always_succeed_x86,
)


@dataclass
class PatchTemplate:
    """Template for patching a specific API function."""

    name: str
    description: str
    target_api: str
    architecture: Architecture
    patch_bytes: bytes


WINHTTP_IGNORE_ALL_CERT_ERRORS_X86 = PatchTemplate(
    name="WINHTTP_IGNORE_ALL_CERT_ERRORS_X86",
    description="Patch WinHttpSetOption to ignore all certificate errors (x86)",
    target_api="WinHttpSetOption",
    architecture=Architecture.X86,
    patch_bytes=bytes([
        0x83, 0x7C, 0x24, 0x08, 0x1F,
        0x75, 0x10,
        0x8B, 0x44, 0x24, 0x0C,
        0x81, 0x08, 0x00, 0x33, 0x00, 0x00,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3
    ])
)

WINHTTP_IGNORE_ALL_CERT_ERRORS_X64 = PatchTemplate(
    name="WINHTTP_IGNORE_ALL_CERT_ERRORS_X64",
    description="Patch WinHttpSetOption to ignore all certificate errors (x64)",
    target_api="WinHttpSetOption",
    architecture=Architecture.X64,
    patch_bytes=bytes([
        0x83, 0xFA, 0x1F,
        0x75, 0x10,
        0x81, 0x08, 0x00, 0x33, 0x00, 0x00,
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
        0xC3
    ])
)

WINHTTP_FORCE_SUCCESS_X86 = PatchTemplate(
    name="WINHTTP_FORCE_SUCCESS_X86",
    description="Patch WinHttpSendRequest to always succeed (x86)",
    target_api="WinHttpSendRequest",
    architecture=Architecture.X86,
    patch_bytes=generate_always_succeed_x86()
)

WINHTTP_FORCE_SUCCESS_X64 = PatchTemplate(
    name="WINHTTP_FORCE_SUCCESS_X64",
    description="Patch WinHttpSendRequest to always succeed (x64)",
    target_api="WinHttpSendRequest",
    architecture=Architecture.X64,
    patch_bytes=generate_always_succeed_x64()
)

OPENSSL_DISABLE_VERIFY_X86 = PatchTemplate(
    name="OPENSSL_DISABLE_VERIFY_X86",
    description="Patch SSL_CTX_set_verify to set mode=SSL_VERIFY_NONE (x86)",
    target_api="SSL_CTX_set_verify",
    architecture=Architecture.X86,
    patch_bytes=bytes([
        0x8B, 0x44, 0x24, 0x04,
        0xC7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x00,
        0xC3
    ])
)

OPENSSL_DISABLE_VERIFY_X64 = PatchTemplate(
    name="OPENSSL_DISABLE_VERIFY_X64",
    description="Patch SSL_CTX_set_verify to set mode=SSL_VERIFY_NONE (x64)",
    target_api="SSL_CTX_set_verify",
    architecture=Architecture.X64,
    patch_bytes=bytes([
        0x48, 0x89, 0xC8,
        0x31, 0xD2,
        0xC3
    ])
)

OPENSSL_ALWAYS_VALID_X86 = PatchTemplate(
    name="OPENSSL_ALWAYS_VALID_X86",
    description="Patch SSL_get_verify_result to return X509_V_OK (x86)",
    target_api="SSL_get_verify_result",
    architecture=Architecture.X86,
    patch_bytes=bytes([
        0x31, 0xC0,
        0xC3
    ])
)

OPENSSL_ALWAYS_VALID_X64 = PatchTemplate(
    name="OPENSSL_ALWAYS_VALID_X64",
    description="Patch SSL_get_verify_result to return X509_V_OK (x64)",
    target_api="SSL_get_verify_result",
    architecture=Architecture.X64,
    patch_bytes=bytes([
        0x31, 0xC0,
        0xC3
    ])
)

SCHANNEL_SKIP_VALIDATION_X64 = PatchTemplate(
    name="SCHANNEL_SKIP_VALIDATION_X64",
    description="Patch InitializeSecurityContext to skip cert checks (x64)",
    target_api="InitializeSecurityContext",
    architecture=Architecture.X64,
    patch_bytes=bytes([
        0x81, 0x21, 0x00, 0x00, 0x10, 0x00,
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,
        0xC3
    ])
)

SCHANNEL_FORCE_TRUST_X64 = PatchTemplate(
    name="SCHANNEL_FORCE_TRUST_X64",
    description="Patch certificate policy to always trust (x64)",
    target_api="QueryContextAttributes",
    architecture=Architecture.X64,
    patch_bytes=bytes([
        0x48, 0x83, 0xFA, 0x53,
        0x75, 0x08,
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,
        0xC3
    ])
)

CRYPTOAPI_BYPASS_CHAIN_POLICY_X86 = PatchTemplate(
    name="CRYPTOAPI_BYPASS_CHAIN_POLICY_X86",
    description="Patch CertVerifyCertificateChainPolicy to return TRUE (x86)",
    target_api="CertVerifyCertificateChainPolicy",
    architecture=Architecture.X86,
    patch_bytes=bytes([
        0x8B, 0x44, 0x24, 0x10,
        0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC7, 0x40, 0x04, 0x00, 0x00, 0x00, 0x00,
        0xC7, 0x40, 0x08, 0x00, 0x00, 0x00, 0x00,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3
    ])
)

CRYPTOAPI_BYPASS_CHAIN_POLICY_X64 = PatchTemplate(
    name="CRYPTOAPI_BYPASS_CHAIN_POLICY_X64",
    description="Patch CertVerifyCertificateChainPolicy to return TRUE (x64)",
    target_api="CertVerifyCertificateChainPolicy",
    architecture=Architecture.X64,
    patch_bytes=bytes([
        0x49, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x49, 0xC7, 0x40, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x49, 0xC7, 0x40, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
        0xC3
    ])
)

ALL_TEMPLATES = [
    WINHTTP_IGNORE_ALL_CERT_ERRORS_X86,
    WINHTTP_IGNORE_ALL_CERT_ERRORS_X64,
    WINHTTP_FORCE_SUCCESS_X86,
    WINHTTP_FORCE_SUCCESS_X64,
    OPENSSL_DISABLE_VERIFY_X86,
    OPENSSL_DISABLE_VERIFY_X64,
    OPENSSL_ALWAYS_VALID_X86,
    OPENSSL_ALWAYS_VALID_X64,
    SCHANNEL_SKIP_VALIDATION_X64,
    SCHANNEL_FORCE_TRUST_X64,
    CRYPTOAPI_BYPASS_CHAIN_POLICY_X86,
    CRYPTOAPI_BYPASS_CHAIN_POLICY_X64,
]


def select_template(api_name: str, arch: Architecture) -> Optional[PatchTemplate]:
    """
    Select appropriate patch template for API and architecture.

    Args:
        api_name: Name of the API function to patch
        arch: Target architecture

    Returns:
        PatchTemplate if found, None otherwise
    """
    for template in ALL_TEMPLATES:
        if template.target_api == api_name and template.architecture == arch:
            return template
    return None


def get_all_templates() -> list[PatchTemplate]:
    """
    Get all available patch templates.

    Returns:
        List of all PatchTemplate objects
    """
    return ALL_TEMPLATES.copy()


def get_templates_by_api(api_name: str) -> list[PatchTemplate]:
    """
    Get all templates for a specific API.

    Args:
        api_name: Name of the API function

    Returns:
        List of templates targeting this API
    """
    return [t for t in ALL_TEMPLATES if t.target_api == api_name]


def get_templates_by_arch(arch: Architecture) -> list[PatchTemplate]:
    """
    Get all templates for a specific architecture.

    Args:
        arch: Target architecture

    Returns:
        List of templates for this architecture
    """
    return [t for t in ALL_TEMPLATES if t.architecture == arch]
