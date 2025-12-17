"""Production tests for certificate validation patch templates.

Tests validate pre-built patch templates for bypassing certificate validation:
- WinHTTP API patches (ignore errors, force success)
- OpenSSL API patches (disable verify, always valid)
- Schannel API patches (skip validation, force trust)
- CryptoAPI patches (bypass chain policy)
- Template selection by API name and architecture
- Architecture-specific template availability
- Patch byte correctness and completeness

All tests validate actual patch templates that will be applied to
real binaries for certificate validation bypass.
"""

import pytest

from intellicrack.core.certificate.patch_generators import Architecture
from intellicrack.core.certificate.patch_templates import (
    CRYPTOAPI_BYPASS_CHAIN_POLICY_X64,
    CRYPTOAPI_BYPASS_CHAIN_POLICY_X86,
    OPENSSL_ALWAYS_VALID_X64,
    OPENSSL_ALWAYS_VALID_X86,
    OPENSSL_DISABLE_VERIFY_X64,
    OPENSSL_DISABLE_VERIFY_X86,
    SCHANNEL_FORCE_TRUST_X64,
    SCHANNEL_SKIP_VALIDATION_X64,
    WINHTTP_FORCE_SUCCESS_X64,
    WINHTTP_FORCE_SUCCESS_X86,
    WINHTTP_IGNORE_ALL_CERT_ERRORS_X64,
    WINHTTP_IGNORE_ALL_CERT_ERRORS_X86,
    PatchTemplate,
    get_all_templates,
    get_templates_by_api,
    get_templates_by_arch,
    select_template,
)


class TestPatchTemplateDataClass:
    """Test PatchTemplate data class structure."""

    def test_patch_template_structure(self) -> None:
        """PatchTemplate contains all required fields."""
        template = PatchTemplate(
            name="TEST_TEMPLATE",
            description="Test patch template",
            target_api="TestAPI",
            architecture=Architecture.X64,
            patch_bytes=b"\x90" * 10,
        )

        assert template.name == "TEST_TEMPLATE"
        assert template.description == "Test patch template"
        assert template.target_api == "TestAPI"
        assert template.architecture == Architecture.X64
        assert template.patch_bytes == b"\x90" * 10


class TestWinHttpTemplates:
    """Test WinHTTP API patch templates."""

    def test_winhttp_ignore_errors_x86_structure(self) -> None:
        """WinHTTP ignore errors x86 template has correct structure."""
        assert isinstance(WINHTTP_IGNORE_ALL_CERT_ERRORS_X86, PatchTemplate)
        assert WINHTTP_IGNORE_ALL_CERT_ERRORS_X86.name == "WINHTTP_IGNORE_ALL_CERT_ERRORS_X86"
        assert WINHTTP_IGNORE_ALL_CERT_ERRORS_X86.target_api == "WinHttpSetOption"
        assert WINHTTP_IGNORE_ALL_CERT_ERRORS_X86.architecture == Architecture.X86

    def test_winhttp_ignore_errors_x86_patch_bytes(self) -> None:
        """WinHTTP ignore errors x86 template has valid patch bytes."""
        assert isinstance(WINHTTP_IGNORE_ALL_CERT_ERRORS_X86.patch_bytes, bytes)
        assert len(WINHTTP_IGNORE_ALL_CERT_ERRORS_X86.patch_bytes) > 0

    def test_winhttp_ignore_errors_x64_structure(self) -> None:
        """WinHTTP ignore errors x64 template has correct structure."""
        assert isinstance(WINHTTP_IGNORE_ALL_CERT_ERRORS_X64, PatchTemplate)
        assert WINHTTP_IGNORE_ALL_CERT_ERRORS_X64.name == "WINHTTP_IGNORE_ALL_CERT_ERRORS_X64"
        assert WINHTTP_IGNORE_ALL_CERT_ERRORS_X64.target_api == "WinHttpSetOption"
        assert WINHTTP_IGNORE_ALL_CERT_ERRORS_X64.architecture == Architecture.X64

    def test_winhttp_ignore_errors_x64_patch_bytes(self) -> None:
        """WinHTTP ignore errors x64 template has valid patch bytes."""
        assert isinstance(WINHTTP_IGNORE_ALL_CERT_ERRORS_X64.patch_bytes, bytes)
        assert len(WINHTTP_IGNORE_ALL_CERT_ERRORS_X64.patch_bytes) > 0

    def test_winhttp_force_success_x86_structure(self) -> None:
        """WinHTTP force success x86 template has correct structure."""
        assert isinstance(WINHTTP_FORCE_SUCCESS_X86, PatchTemplate)
        assert WINHTTP_FORCE_SUCCESS_X86.name == "WINHTTP_FORCE_SUCCESS_X86"
        assert WINHTTP_FORCE_SUCCESS_X86.target_api == "WinHttpSendRequest"
        assert WINHTTP_FORCE_SUCCESS_X86.architecture == Architecture.X86

    def test_winhttp_force_success_x86_patch_bytes(self) -> None:
        """WinHTTP force success x86 template has valid patch bytes."""
        assert isinstance(WINHTTP_FORCE_SUCCESS_X86.patch_bytes, bytes)
        assert len(WINHTTP_FORCE_SUCCESS_X86.patch_bytes) > 0

    def test_winhttp_force_success_x64_structure(self) -> None:
        """WinHTTP force success x64 template has correct structure."""
        assert isinstance(WINHTTP_FORCE_SUCCESS_X64, PatchTemplate)
        assert WINHTTP_FORCE_SUCCESS_X64.name == "WINHTTP_FORCE_SUCCESS_X64"
        assert WINHTTP_FORCE_SUCCESS_X64.target_api == "WinHttpSendRequest"
        assert WINHTTP_FORCE_SUCCESS_X64.architecture == Architecture.X64

    def test_winhttp_force_success_x64_patch_bytes(self) -> None:
        """WinHTTP force success x64 template has valid patch bytes."""
        assert isinstance(WINHTTP_FORCE_SUCCESS_X64.patch_bytes, bytes)
        assert len(WINHTTP_FORCE_SUCCESS_X64.patch_bytes) > 0


class TestOpenSSLTemplates:
    """Test OpenSSL API patch templates."""

    def test_openssl_disable_verify_x86_structure(self) -> None:
        """OpenSSL disable verify x86 template has correct structure."""
        assert isinstance(OPENSSL_DISABLE_VERIFY_X86, PatchTemplate)
        assert OPENSSL_DISABLE_VERIFY_X86.name == "OPENSSL_DISABLE_VERIFY_X86"
        assert OPENSSL_DISABLE_VERIFY_X86.target_api == "SSL_CTX_set_verify"
        assert OPENSSL_DISABLE_VERIFY_X86.architecture == Architecture.X86

    def test_openssl_disable_verify_x86_patch_bytes(self) -> None:
        """OpenSSL disable verify x86 template has valid patch bytes."""
        assert isinstance(OPENSSL_DISABLE_VERIFY_X86.patch_bytes, bytes)
        assert len(OPENSSL_DISABLE_VERIFY_X86.patch_bytes) == 13

    def test_openssl_disable_verify_x64_structure(self) -> None:
        """OpenSSL disable verify x64 template has correct structure."""
        assert isinstance(OPENSSL_DISABLE_VERIFY_X64, PatchTemplate)
        assert OPENSSL_DISABLE_VERIFY_X64.name == "OPENSSL_DISABLE_VERIFY_X64"
        assert OPENSSL_DISABLE_VERIFY_X64.target_api == "SSL_CTX_set_verify"
        assert OPENSSL_DISABLE_VERIFY_X64.architecture == Architecture.X64

    def test_openssl_disable_verify_x64_patch_bytes(self) -> None:
        """OpenSSL disable verify x64 template has valid patch bytes."""
        assert isinstance(OPENSSL_DISABLE_VERIFY_X64.patch_bytes, bytes)
        assert len(OPENSSL_DISABLE_VERIFY_X64.patch_bytes) == 6

    def test_openssl_always_valid_x86_structure(self) -> None:
        """OpenSSL always valid x86 template has correct structure."""
        assert isinstance(OPENSSL_ALWAYS_VALID_X86, PatchTemplate)
        assert OPENSSL_ALWAYS_VALID_X86.name == "OPENSSL_ALWAYS_VALID_X86"
        assert OPENSSL_ALWAYS_VALID_X86.target_api == "SSL_get_verify_result"
        assert OPENSSL_ALWAYS_VALID_X86.architecture == Architecture.X86

    def test_openssl_always_valid_x86_patch_bytes(self) -> None:
        """OpenSSL always valid x86 template has valid patch bytes."""
        assert isinstance(OPENSSL_ALWAYS_VALID_X86.patch_bytes, bytes)
        assert len(OPENSSL_ALWAYS_VALID_X86.patch_bytes) == 3
        assert OPENSSL_ALWAYS_VALID_X86.patch_bytes == bytes([0x31, 0xC0, 0xC3])

    def test_openssl_always_valid_x64_structure(self) -> None:
        """OpenSSL always valid x64 template has correct structure."""
        assert isinstance(OPENSSL_ALWAYS_VALID_X64, PatchTemplate)
        assert OPENSSL_ALWAYS_VALID_X64.name == "OPENSSL_ALWAYS_VALID_X64"
        assert OPENSSL_ALWAYS_VALID_X64.target_api == "SSL_get_verify_result"
        assert OPENSSL_ALWAYS_VALID_X64.architecture == Architecture.X64

    def test_openssl_always_valid_x64_patch_bytes(self) -> None:
        """OpenSSL always valid x64 template has valid patch bytes."""
        assert isinstance(OPENSSL_ALWAYS_VALID_X64.patch_bytes, bytes)
        assert len(OPENSSL_ALWAYS_VALID_X64.patch_bytes) == 3
        assert OPENSSL_ALWAYS_VALID_X64.patch_bytes == bytes([0x31, 0xC0, 0xC3])


class TestSchannelTemplates:
    """Test Schannel API patch templates."""

    def test_schannel_skip_validation_x64_structure(self) -> None:
        """Schannel skip validation x64 template has correct structure."""
        assert isinstance(SCHANNEL_SKIP_VALIDATION_X64, PatchTemplate)
        assert SCHANNEL_SKIP_VALIDATION_X64.name == "SCHANNEL_SKIP_VALIDATION_X64"
        assert SCHANNEL_SKIP_VALIDATION_X64.target_api == "InitializeSecurityContext"
        assert SCHANNEL_SKIP_VALIDATION_X64.architecture == Architecture.X64

    def test_schannel_skip_validation_x64_patch_bytes(self) -> None:
        """Schannel skip validation x64 template has valid patch bytes."""
        assert isinstance(SCHANNEL_SKIP_VALIDATION_X64.patch_bytes, bytes)
        assert len(SCHANNEL_SKIP_VALIDATION_X64.patch_bytes) == 14

    def test_schannel_force_trust_x64_structure(self) -> None:
        """Schannel force trust x64 template has correct structure."""
        assert isinstance(SCHANNEL_FORCE_TRUST_X64, PatchTemplate)
        assert SCHANNEL_FORCE_TRUST_X64.name == "SCHANNEL_FORCE_TRUST_X64"
        assert SCHANNEL_FORCE_TRUST_X64.target_api == "QueryContextAttributes"
        assert SCHANNEL_FORCE_TRUST_X64.architecture == Architecture.X64

    def test_schannel_force_trust_x64_patch_bytes(self) -> None:
        """Schannel force trust x64 template has valid patch bytes."""
        assert isinstance(SCHANNEL_FORCE_TRUST_X64.patch_bytes, bytes)
        assert len(SCHANNEL_FORCE_TRUST_X64.patch_bytes) == 14


class TestCryptoAPITemplates:
    """Test CryptoAPI patch templates."""

    def test_cryptoapi_bypass_chain_policy_x86_structure(self) -> None:
        """CryptoAPI bypass chain policy x86 template has correct structure."""
        assert isinstance(CRYPTOAPI_BYPASS_CHAIN_POLICY_X86, PatchTemplate)
        assert CRYPTOAPI_BYPASS_CHAIN_POLICY_X86.name == "CRYPTOAPI_BYPASS_CHAIN_POLICY_X86"
        assert CRYPTOAPI_BYPASS_CHAIN_POLICY_X86.target_api == "CertVerifyCertificateChainPolicy"
        assert CRYPTOAPI_BYPASS_CHAIN_POLICY_X86.architecture == Architecture.X86

    def test_cryptoapi_bypass_chain_policy_x86_patch_bytes(self) -> None:
        """CryptoAPI bypass chain policy x86 template has valid patch bytes."""
        assert isinstance(CRYPTOAPI_BYPASS_CHAIN_POLICY_X86.patch_bytes, bytes)
        assert len(CRYPTOAPI_BYPASS_CHAIN_POLICY_X86.patch_bytes) > 0

    def test_cryptoapi_bypass_chain_policy_x64_structure(self) -> None:
        """CryptoAPI bypass chain policy x64 template has correct structure."""
        assert isinstance(CRYPTOAPI_BYPASS_CHAIN_POLICY_X64, PatchTemplate)
        assert CRYPTOAPI_BYPASS_CHAIN_POLICY_X64.name == "CRYPTOAPI_BYPASS_CHAIN_POLICY_X64"
        assert CRYPTOAPI_BYPASS_CHAIN_POLICY_X64.target_api == "CertVerifyCertificateChainPolicy"
        assert CRYPTOAPI_BYPASS_CHAIN_POLICY_X64.architecture == Architecture.X64

    def test_cryptoapi_bypass_chain_policy_x64_patch_bytes(self) -> None:
        """CryptoAPI bypass chain policy x64 template has valid patch bytes."""
        assert isinstance(CRYPTOAPI_BYPASS_CHAIN_POLICY_X64.patch_bytes, bytes)
        assert len(CRYPTOAPI_BYPASS_CHAIN_POLICY_X64.patch_bytes) > 0


class TestTemplateSelectionFunctions:
    """Test template selection and query functions."""

    def test_select_template_by_api_and_arch(self) -> None:
        """Select template returns correct template for API and architecture."""
        template = select_template("WinHttpSetOption", Architecture.X64)

        assert template is not None
        assert template.target_api == "WinHttpSetOption"
        assert template.architecture == Architecture.X64

    def test_select_template_nonexistent_api_returns_none(self) -> None:
        """Select template returns None for nonexistent API."""
        template = select_template("NonexistentAPI", Architecture.X64)

        assert template is None

    def test_select_template_wrong_architecture_returns_none(self) -> None:
        """Select template returns None for wrong architecture."""
        template = select_template("WinHttpSetOption", Architecture.ARM)

        assert template is None

    def test_get_all_templates_returns_all(self) -> None:
        """Get all templates returns complete template list."""
        templates = get_all_templates()

        assert isinstance(templates, list)
        assert len(templates) == 12
        assert all(isinstance(t, PatchTemplate) for t in templates)

    def test_get_all_templates_returns_copy(self) -> None:
        """Get all templates returns copy to prevent modification."""
        templates1 = get_all_templates()
        templates2 = get_all_templates()

        assert templates1 is not templates2
        assert len(templates1) == len(templates2)

    def test_get_templates_by_api_winhttp(self) -> None:
        """Get templates by API returns all WinHTTP templates."""
        templates = get_templates_by_api("WinHttpSetOption")

        assert isinstance(templates, list)
        assert len(templates) == 2
        assert all(t.target_api == "WinHttpSetOption" for t in templates)

    def test_get_templates_by_api_openssl(self) -> None:
        """Get templates by API returns all OpenSSL templates."""
        verify_templates = get_templates_by_api("SSL_CTX_set_verify")
        result_templates = get_templates_by_api("SSL_get_verify_result")

        assert len(verify_templates) == 2
        assert len(result_templates) == 2

    def test_get_templates_by_api_nonexistent_returns_empty(self) -> None:
        """Get templates by API returns empty list for nonexistent API."""
        templates = get_templates_by_api("NonexistentAPI")

        assert templates == []

    def test_get_templates_by_arch_x86(self) -> None:
        """Get templates by architecture returns all x86 templates."""
        templates = get_templates_by_arch(Architecture.X86)

        assert isinstance(templates, list)
        assert len(templates) == 6
        assert all(t.architecture == Architecture.X86 for t in templates)

    def test_get_templates_by_arch_x64(self) -> None:
        """Get templates by architecture returns all x64 templates."""
        templates = get_templates_by_arch(Architecture.X64)

        assert isinstance(templates, list)
        assert len(templates) == 6
        assert all(t.architecture == Architecture.X64 for t in templates)

    def test_get_templates_by_arch_arm_returns_empty(self) -> None:
        """Get templates by architecture returns empty for ARM."""
        templates = get_templates_by_arch(Architecture.ARM)

        assert templates == []


class TestTemplateCoverage:
    """Test template coverage across APIs and architectures."""

    def test_winhttp_has_both_architectures(self) -> None:
        """WinHTTP templates cover both x86 and x64."""
        x86_templates = [t for t in get_all_templates() if "WinHttp" in t.target_api and t.architecture == Architecture.X86]
        x64_templates = [t for t in get_all_templates() if "WinHttp" in t.target_api and t.architecture == Architecture.X64]

        assert len(x86_templates) > 0
        assert len(x64_templates) > 0

    def test_openssl_has_both_architectures(self) -> None:
        """OpenSSL templates cover both x86 and x64."""
        x86_templates = [t for t in get_all_templates() if "SSL" in t.target_api and t.architecture == Architecture.X86]
        x64_templates = [t for t in get_all_templates() if "SSL" in t.target_api and t.architecture == Architecture.X64]

        assert len(x86_templates) > 0
        assert len(x64_templates) > 0

    def test_cryptoapi_has_both_architectures(self) -> None:
        """CryptoAPI templates cover both x86 and x64."""
        x86_templates = [t for t in get_all_templates() if "CertVerify" in t.target_api and t.architecture == Architecture.X86]
        x64_templates = [t for t in get_all_templates() if "CertVerify" in t.target_api and t.architecture == Architecture.X64]

        assert len(x86_templates) == 1
        assert len(x64_templates) == 1

    def test_all_templates_have_patch_bytes(self) -> None:
        """All templates have non-empty patch bytes."""
        templates = get_all_templates()

        for template in templates:
            assert isinstance(template.patch_bytes, bytes)
            assert len(template.patch_bytes) > 0

    def test_all_templates_have_descriptions(self) -> None:
        """All templates have non-empty descriptions."""
        templates = get_all_templates()

        for template in templates:
            assert isinstance(template.description, str)
            assert len(template.description) > 0

    def test_all_templates_have_unique_names(self) -> None:
        """All templates have unique names."""
        templates = get_all_templates()
        names = [t.name for t in templates]

        assert len(names) == len(set(names))


class TestPatchByteValidity:
    """Test validity of patch byte sequences."""

    def test_x86_patches_end_with_ret(self) -> None:
        """x86 patches end with RET instruction (0xC3)."""
        x86_templates = get_templates_by_arch(Architecture.X86)

        for template in x86_templates:
            assert template.patch_bytes[-1] == 0xC3

    def test_x64_patches_end_with_ret(self) -> None:
        """x64 patches end with RET instruction (0xC3)."""
        x64_templates = get_templates_by_arch(Architecture.X64)

        for template in x64_templates:
            assert template.patch_bytes[-1] == 0xC3

    def test_openssl_always_valid_returns_zero(self) -> None:
        """OpenSSL always valid patches return 0 (XOR EAX, EAX; RET)."""
        assert OPENSSL_ALWAYS_VALID_X86.patch_bytes[0:2] == bytes([0x31, 0xC0])
        assert OPENSSL_ALWAYS_VALID_X64.patch_bytes[0:2] == bytes([0x31, 0xC0])

    def test_patch_bytes_are_readonly(self) -> None:
        """Patch bytes are immutable bytes objects."""
        templates = get_all_templates()

        for template in templates:
            assert isinstance(template.patch_bytes, bytes)
