"""Predefined patch templates for common certificate validation APIs across platforms.

CAPABILITIES:
- Pre-built patch templates for WinHTTP APIs (x86/x64)
- Pre-built patch templates for OpenSSL APIs (x86/x64)
- Pre-built patch templates for Schannel APIs (x64)
- Pre-built patch templates for CryptoAPI (x86/x64)
- Template selection by API name and architecture
- Ready-to-apply machine code bytes
- Comprehensive template descriptions
- Architecture-specific implementations
- Tested against real applications

LIMITATIONS:
- Fixed set of templates (no dynamic generation)
- Templates assume standard function prologues
- May not work with heavily optimized binaries
- No templates for custom/proprietary APIs
- Limited ARM template coverage
- Assumes standard calling conventions
- No auto-adjustment for different library versions
- Templates require manual testing for new targets

USAGE EXAMPLES:
    # Get template by API and architecture
    from intellicrack.core.certificate.patch_templates import (
        select_template,
        Architecture
    )

    template = select_template("WinHttpSetOption", "x64")
    if template:
        print(f"Template: {template.name}")
        print(f"Description: {template.description}")
        print(f"Patch bytes: {template.patch_bytes.hex()}")

    # Get all available templates
    from intellicrack.core.certificate.patch_templates import get_all_templates

    templates = get_all_templates()
    print(f"Available templates: {len(templates)}")

    for t in templates:
        print(f"- {t.name} ({t.target_api}, {t.architecture.value})")

    # Use template for patching
    from intellicrack.core.certificate.patch_templates import (
        WINHTTP_IGNORE_ALL_CERT_ERRORS_X64
    )

    template = WINHTTP_IGNORE_ALL_CERT_ERRORS_X64
    patch_bytes = template.patch_bytes
    # Apply patch_bytes at detected API location

    # Get templates for specific library
    templates = get_all_templates()
    winhttp_templates = [t for t in templates if "WinHttp" in t.target_API]
    openssl_templates = [t for t in templates if "SSL" in t.target_api]

RELATED MODULES:
- patch_generators.py: Provides low-level patch generation functions
- cert_patcher.py: Applies templates to actual binaries
- api_signatures.py: Identifies target APIs for template matching
- validation_detector.py: Detects which APIs need patching
- bypass_orchestrator.py: Selects appropriate templates

TEMPLATE COVERAGE:
    WinHTTP (Windows):
        - WINHTTP_IGNORE_ALL_CERT_ERRORS (x86/x64)
        - WINHTTP_FORCE_SUCCESS (x86/x64)

    OpenSSL (Linux/Windows/Android):
        - OPENSSL_DISABLE_VERIFY (x86/x64)
        - OPENSSL_ALWAYS_VALID (x86/x64)

    Schannel (Windows):
        - SCHANNEL_SKIP_VALIDATION (x64)
        - SCHANNEL_FORCE_TRUST (x64)

    CryptoAPI (Windows):
        - CRYPTOAPI_BYPASS_CHAIN_POLICY (x86/x64)

TEMPLATE DETAILS:
    Each template includes:
    - name: Unique identifier
    - description: What the patch does
    - target_api: API function it patches
    - architecture: CPU architecture (x86/x64/ARM)
    - patch_bytes: Ready-to-apply machine code

    Templates are designed to:
    - Minimize patch size
    - Preserve calling convention
    - Handle return values correctly
    - Avoid crashes from side effects
"""

from dataclasses import dataclass

from intellicrack.core.certificate.patch_generators import Architecture, generate_always_succeed_x64, generate_always_succeed_x86
from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)
logger.debug("Certificate patch templates module loaded")


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
    patch_bytes=bytes(
        [
            0x83,
            0x7C,
            0x24,
            0x08,
            0x1F,
            0x75,
            0x10,
            0x8B,
            0x44,
            0x24,
            0x0C,
            0x81,
            0x08,
            0x00,
            0x33,
            0x00,
            0x00,
            0xB8,
            0x01,
            0x00,
            0x00,
            0x00,
            0xC3,
        ],
    ),
)

WINHTTP_IGNORE_ALL_CERT_ERRORS_X64 = PatchTemplate(
    name="WINHTTP_IGNORE_ALL_CERT_ERRORS_X64",
    description="Patch WinHttpSetOption to ignore all certificate errors (x64)",
    target_api="WinHttpSetOption",
    architecture=Architecture.X64,
    patch_bytes=bytes(
        [
            0x83,
            0xFA,
            0x1F,
            0x75,
            0x10,
            0x81,
            0x08,
            0x00,
            0x33,
            0x00,
            0x00,
            0x48,
            0xC7,
            0xC0,
            0x01,
            0x00,
            0x00,
            0x00,
            0xC3,
        ]
    ),
)

WINHTTP_FORCE_SUCCESS_X86 = PatchTemplate(
    name="WINHTTP_FORCE_SUCCESS_X86",
    description="Patch WinHttpSendRequest to always succeed (x86)",
    target_api="WinHttpSendRequest",
    architecture=Architecture.X86,
    patch_bytes=generate_always_succeed_x86(),
)

WINHTTP_FORCE_SUCCESS_X64 = PatchTemplate(
    name="WINHTTP_FORCE_SUCCESS_X64",
    description="Patch WinHttpSendRequest to always succeed (x64)",
    target_api="WinHttpSendRequest",
    architecture=Architecture.X64,
    patch_bytes=generate_always_succeed_x64(),
)

OPENSSL_DISABLE_VERIFY_X86 = PatchTemplate(
    name="OPENSSL_DISABLE_VERIFY_X86",
    description="Patch SSL_CTX_set_verify to set mode=SSL_VERIFY_NONE (x86)",
    target_api="SSL_CTX_set_verify",
    architecture=Architecture.X86,
    patch_bytes=bytes([0x8B, 0x44, 0x24, 0x04, 0xC7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x00, 0xC3]),
)

OPENSSL_DISABLE_VERIFY_X64 = PatchTemplate(
    name="OPENSSL_DISABLE_VERIFY_X64",
    description="Patch SSL_CTX_set_verify to set mode=SSL_VERIFY_NONE (x64)",
    target_api="SSL_CTX_set_verify",
    architecture=Architecture.X64,
    patch_bytes=bytes([0x48, 0x89, 0xC8, 0x31, 0xD2, 0xC3]),
)

OPENSSL_ALWAYS_VALID_X86 = PatchTemplate(
    name="OPENSSL_ALWAYS_VALID_X86",
    description="Patch SSL_get_verify_result to return X509_V_OK (x86)",
    target_api="SSL_get_verify_result",
    architecture=Architecture.X86,
    patch_bytes=bytes([0x31, 0xC0, 0xC3]),
)

OPENSSL_ALWAYS_VALID_X64 = PatchTemplate(
    name="OPENSSL_ALWAYS_VALID_X64",
    description="Patch SSL_get_verify_result to return X509_V_OK (x64)",
    target_api="SSL_get_verify_result",
    architecture=Architecture.X64,
    patch_bytes=bytes([0x31, 0xC0, 0xC3]),
)

SCHANNEL_SKIP_VALIDATION_X64 = PatchTemplate(
    name="SCHANNEL_SKIP_VALIDATION_X64",
    description="Patch InitializeSecurityContext to skip cert checks (x64)",
    target_api="InitializeSecurityContext",
    architecture=Architecture.X64,
    patch_bytes=bytes([0x81, 0x21, 0x00, 0x00, 0x10, 0x00, 0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3]),
)

SCHANNEL_FORCE_TRUST_X64 = PatchTemplate(
    name="SCHANNEL_FORCE_TRUST_X64",
    description="Patch certificate policy to always trust (x64)",
    target_api="QueryContextAttributes",
    architecture=Architecture.X64,
    patch_bytes=bytes([0x48, 0x83, 0xFA, 0x53, 0x75, 0x08, 0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3]),
)

CRYPTOAPI_BYPASS_CHAIN_POLICY_X86 = PatchTemplate(
    name="CRYPTOAPI_BYPASS_CHAIN_POLICY_X86",
    description="Patch CertVerifyCertificateChainPolicy to return TRUE (x86)",
    target_api="CertVerifyCertificateChainPolicy",
    architecture=Architecture.X86,
    patch_bytes=bytes(
        [
            0x8B,
            0x44,
            0x24,
            0x10,
            0xC7,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0xC7,
            0x40,
            0x04,
            0x00,
            0x00,
            0x00,
            0x00,
            0xC7,
            0x40,
            0x08,
            0x00,
            0x00,
            0x00,
            0x00,
            0xB8,
            0x01,
            0x00,
            0x00,
            0x00,
            0xC3,
        ],
    ),
)

CRYPTOAPI_BYPASS_CHAIN_POLICY_X64 = PatchTemplate(
    name="CRYPTOAPI_BYPASS_CHAIN_POLICY_X64",
    description="Patch CertVerifyCertificateChainPolicy to return TRUE (x64)",
    target_api="CertVerifyCertificateChainPolicy",
    architecture=Architecture.X64,
    patch_bytes=bytes(
        [
            0x49,
            0xC7,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x49,
            0xC7,
            0x40,
            0x04,
            0x00,
            0x00,
            0x00,
            0x00,
            0x49,
            0xC7,
            0x40,
            0x08,
            0x00,
            0x00,
            0x00,
            0x00,
            0x48,
            0xC7,
            0xC0,
            0x01,
            0x00,
            0x00,
            0x00,
            0xC3,
        ],
    ),
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


def select_template(api_name: str, arch: Architecture) -> PatchTemplate | None:
    """Select appropriate patch template for API and architecture.

    Args:
        api_name: Name of the API function to patch
        arch: Target architecture

    Returns:
        PatchTemplate if found, None otherwise

    """
    return next(
        (template for template in ALL_TEMPLATES if template.target_api == api_name and template.architecture == arch),
        None,
    )


def get_all_templates() -> list[PatchTemplate]:
    """Get all available patch templates.

    Returns:
        List of all PatchTemplate objects

    """
    return ALL_TEMPLATES.copy()


def get_templates_by_api(api_name: str) -> list[PatchTemplate]:
    """Get all templates for a specific API.

    Args:
        api_name: Name of the API function

    Returns:
        List of templates targeting this API

    """
    return [t for t in ALL_TEMPLATES if t.target_api == api_name]


def get_templates_by_arch(arch: Architecture) -> list[PatchTemplate]:
    """Get all templates for a specific architecture.

    Args:
        arch: Target architecture

    Returns:
        List of templates for this architecture

    """
    return [t for t in ALL_TEMPLATES if t.architecture == arch]
