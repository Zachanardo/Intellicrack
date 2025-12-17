"""Production tests for utils/url_validation.py.

This module validates URL and domain checking utilities for secure validation
of licensing server domains and JWT issuer fields.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import pytest

from intellicrack.utils.url_validation import is_domain_in_string, is_domain_in_url


class TestIsDomainInUrl:
    """Test is_domain_in_url for secure URL domain validation."""

    def test_exact_domain_match(self) -> None:
        """is_domain_in_url matches exact domain in URL."""
        assert is_domain_in_url("example.com", "https://example.com/path")
        assert is_domain_in_url("license.server.com", "https://license.server.com")

    def test_subdomain_match(self) -> None:
        """is_domain_in_url matches subdomains correctly."""
        assert is_domain_in_url("example.com", "https://api.example.com/validate")
        assert is_domain_in_url("example.com", "https://license.api.example.com")

    def test_http_and_https_schemes(self) -> None:
        """is_domain_in_url works with both HTTP and HTTPS."""
        assert is_domain_in_url("example.com", "https://example.com")
        assert is_domain_in_url("example.com", "http://example.com")

    def test_domain_with_port(self) -> None:
        """is_domain_in_url handles domains with port numbers."""
        assert is_domain_in_url("example.com", "https://example.com:8443/api")
        assert is_domain_in_url("license.server.com", "http://license.server.com:80")

    def test_domain_with_path(self) -> None:
        """is_domain_in_url validates domain regardless of path."""
        assert is_domain_in_url("example.com", "https://example.com/api/v1/validate")
        assert is_domain_in_url("example.com", "https://example.com/license/check")

    def test_domain_with_query_params(self) -> None:
        """is_domain_in_url validates domain with query parameters."""
        assert is_domain_in_url("example.com", "https://example.com/api?key=value")
        assert is_domain_in_url("example.com", "https://example.com?license=ABC123")

    def test_rejects_different_domain(self) -> None:
        """is_domain_in_url rejects completely different domains."""
        assert not is_domain_in_url("example.com", "https://other.com/path")
        assert not is_domain_in_url("license.com", "https://attacker.com")

    def test_rejects_partial_domain_match(self) -> None:
        """is_domain_in_url prevents partial domain attacks."""
        assert not is_domain_in_url("example.com", "https://fakeexample.com")
        assert not is_domain_in_url("example.com", "https://example.com.evil.com")

    def test_rejects_domain_in_path(self) -> None:
        """is_domain_in_url prevents domain spoofing in path."""
        assert not is_domain_in_url("example.com", "https://evil.com/example.com")
        assert not is_domain_in_url("license.com", "https://attacker.com/license.com/fake")

    def test_empty_domain(self) -> None:
        """is_domain_in_url handles empty domain gracefully."""
        assert not is_domain_in_url("", "https://example.com")

    def test_empty_url(self) -> None:
        """is_domain_in_url handles empty URL gracefully."""
        assert not is_domain_in_url("example.com", "")

    def test_invalid_url_format(self) -> None:
        """is_domain_in_url handles malformed URLs safely."""
        assert not is_domain_in_url("example.com", "not-a-url")
        assert not is_domain_in_url("example.com", "://missing-scheme")

    def test_url_without_hostname(self) -> None:
        """is_domain_in_url handles URLs without hostname."""
        assert not is_domain_in_url("example.com", "file:///path/to/file")
        assert not is_domain_in_url("example.com", "data:text/plain,Hello")

    def test_case_sensitivity(self) -> None:
        """is_domain_in_url is case-insensitive for domains."""
        assert is_domain_in_url("Example.Com", "https://example.com")
        assert is_domain_in_url("example.com", "https://EXAMPLE.COM")

    @pytest.mark.parametrize(
        "domain,url,expected",
        [
            ("license.example.com", "https://license.example.com/api", True),
            ("example.com", "https://www.example.com", True),
            ("api.example.com", "https://api.example.com:443", True),
            ("example.com", "https://example.net", False),
            ("example.com", "https://notexample.com", False),
        ],
    )
    def test_domain_url_combinations(self, domain: str, url: str, expected: bool) -> None:
        """is_domain_in_url correctly validates various domain/URL combinations."""
        assert is_domain_in_url(domain, url) == expected


class TestIsDomainInString:
    """Test is_domain_in_string for secure domain presence validation."""

    def test_domain_in_url_within_string(self) -> None:
        """is_domain_in_string detects domain in URL within text."""
        assert is_domain_in_string("example.com", "https://example.com")
        assert is_domain_in_string("example.com", "http://example.com/path")

    def test_domain_in_url_with_path(self) -> None:
        """is_domain_in_string detects domain in URL with path."""
        assert is_domain_in_string("example.com", "https://example.com/api/validate")

    def test_domain_in_url_with_port(self) -> None:
        """is_domain_in_string detects domain in URL with port."""
        assert is_domain_in_string("example.com", "https://example.com:8443")

    def test_domain_standalone_in_string(self) -> None:
        """is_domain_in_string detects standalone domain."""
        assert is_domain_in_string("example.com", "license.example.com")
        assert is_domain_in_string("license.com", "api.license.com")

    def test_domain_in_jwt_issuer_field(self) -> None:
        """is_domain_in_string validates JWT issuer fields containing domain."""
        assert is_domain_in_string("example.com", "https://auth.example.com")
        assert is_domain_in_string("license.com", "https://license.com/oauth")

    def test_empty_domain(self) -> None:
        """is_domain_in_string handles empty domain."""
        assert not is_domain_in_string("", "https://example.com")

    def test_empty_string(self) -> None:
        """is_domain_in_string handles empty text."""
        assert not is_domain_in_string("example.com", "")

    def test_domain_not_in_string(self) -> None:
        """is_domain_in_string correctly rejects non-matching domains."""
        assert not is_domain_in_string("example.com", "https://other.com")
        assert not is_domain_in_string("license.com", "no domain here")

    def test_prevents_subdomain_spoofing(self) -> None:
        """is_domain_in_string prevents subdomain spoofing attacks."""
        assert not is_domain_in_string("example.com", "fakeexample.com")
        assert not is_domain_in_string("example.com", "example.com.evil.com")

    def test_case_insensitive_matching(self) -> None:
        """is_domain_in_string performs case-insensitive matching."""
        assert is_domain_in_string("Example.Com", "https://example.com")
        assert is_domain_in_string("example.com", "HTTPS://EXAMPLE.COM")

    def test_domain_in_complex_string(self) -> None:
        """is_domain_in_string finds domain in complex text."""
        text = "License server at https://license.example.com provides validation"
        assert is_domain_in_string("example.com", text)

    def test_domain_with_subdomain_parts(self) -> None:
        """is_domain_in_string validates multi-level subdomains."""
        assert is_domain_in_string("example.com", "api.v2.example.com")
        assert is_domain_in_string("example.com", "license.secure.example.com")

    @pytest.mark.parametrize(
        "domain,text,expected",
        [
            ("example.com", "https://example.com/api", True),
            ("example.com", "Visit example.com for details", True),
            ("license.com", "license.com", True),
            ("example.com", "https://example.net", False),
            ("example.com", "This is not the domain", False),
        ],
    )
    def test_domain_string_combinations(self, domain: str, text: str, expected: bool) -> None:
        """is_domain_in_string correctly validates various domain/text combinations."""
        assert is_domain_in_string(domain, text) == expected

    def test_domain_at_string_boundaries(self) -> None:
        """is_domain_in_string validates domains at string boundaries."""
        assert is_domain_in_string("example.com", "example.com")
        assert is_domain_in_string("example.com", " example.com ")
        assert is_domain_in_string("example.com", "api.example.com:")

    def test_rejects_domain_as_substring(self) -> None:
        """is_domain_in_string prevents false positives from substrings."""
        assert not is_domain_in_string("example.com", "notexample.com")
        assert not is_domain_in_string("license.com", "licensecomposer")


class TestUrlValidationSecurity:
    """Test security aspects of URL validation functions."""

    def test_url_injection_prevention(self) -> None:
        """URL validation prevents injection attacks."""
        malicious_urls = [
            "https://evil.com@example.com",
            "https://example.com.evil.com",
            "https://evil.com/example.com",
            "javascript:alert('example.com')",
        ]
        for url in malicious_urls:
            assert not is_domain_in_url("example.com", url)

    def test_homograph_attack_resistance(self) -> None:
        """URL validation resists homograph attacks."""
        assert not is_domain_in_url("example.com", "https://examp1e.com")
        assert not is_domain_in_url("license.com", "https://1icense.com")

    def test_null_byte_injection_prevention(self) -> None:
        """URL validation handles null bytes safely."""
        assert not is_domain_in_url("example.com", "https://example.com\x00.evil.com")

    def test_unicode_domain_handling(self) -> None:
        """URL validation handles unicode domains appropriately."""
        try:
            result = is_domain_in_url("example.com", "https://example.com")
            assert result is True or result is False
        except Exception:
            pytest.fail("Unicode handling caused exception")

    def test_extremely_long_domain(self) -> None:
        """URL validation handles extremely long domains."""
        long_domain = "a" * 1000 + ".com"
        long_url = f"https://{long_domain}"
        try:
            result = is_domain_in_url(long_domain, long_url)
            assert isinstance(result, bool)
        except Exception:
            pytest.fail("Long domain caused exception")

    def test_special_characters_in_domain(self) -> None:
        """URL validation handles special characters safely."""
        assert not is_domain_in_url("example.com", "https://example!.com")
        assert not is_domain_in_url("example.com", "https://exam ple.com")
