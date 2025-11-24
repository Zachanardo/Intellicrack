from typing import Any
from urllib.parse import urlparse


def assert_domain_in_url(domain: str, url: str, msg: str | None = None) -> None:
    """
    Assert that a domain is present in a URL using secure parsing.

    Args:
        domain: Expected domain (e.g., "example.com")
        url: URL string to check
        msg: Optional assertion message
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            raise AssertionError(msg or f"No hostname found in URL: {url}")

        is_match = hostname == domain or hostname.endswith(f".{domain}")
        if not is_match:
            raise AssertionError(msg or f"Domain {domain} not found in URL {url} (hostname: {hostname})")
    except (ValueError, AttributeError) as e:
        raise AssertionError(msg or f"Invalid URL {url}: {e}") from e


def assert_domain_in_host_header(domain: str, host_header: str, msg: str | None = None) -> None:
    """
    Assert that a domain matches a Host header value.

    Args:
        domain: Expected domain
        host_header: Host header value (may include port)
        msg: Optional assertion message
    """
    host_parts = host_header.split(":")
    hostname = host_parts[0]

    is_match = hostname == domain or hostname.endswith(f".{domain}")
    if not is_match:
        raise AssertionError(msg or f"Domain {domain} not found in Host header: {host_header}")


def assert_domain_in_collection(domain: str, collection: list[str], msg: str | None = None) -> None:
    """
    Assert that a domain is present in a collection of hostnames/domains.

    Args:
        domain: Expected domain
        collection: Collection of domain names
        msg: Optional assertion message
    """
    if domain in collection:
        return

    for item in collection:
        if item == domain or item.endswith(f".{domain}"):
            return

    raise AssertionError(msg or f"Domain {domain} not found in collection")


def assert_text_contains_safely(needle: str, haystack: str, msg: str | None = None) -> None:
    """
    Assert that text contains a substring using boundary-aware matching.

    For use when checking that specific text appears in generated content,
    with protection against partial matches.

    Args:
        needle: Text to find
        haystack: Text to search in
        msg: Optional assertion message
    """
    if needle not in haystack:
        raise AssertionError(msg or f"Text '{needle}' not found in content")
