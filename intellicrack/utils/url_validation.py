"""URL validation utilities for secure domain and URL checking."""

from typing import cast
from urllib.parse import urlparse


def is_domain_in_url(domain: str, url: str) -> bool:
    """Securely check if a domain is in a URL.

    Args:
        domain: The domain to check for (e.g., "example.com")
        url: The URL string to check

    Returns:
        True if the domain matches the URL's hostname
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        hostname = cast("str", hostname)
        return hostname == domain or hostname.endswith(f".{domain}")
    except (ValueError, AttributeError):
        return False


def is_domain_in_string(domain: str, text: str) -> bool:
    """Securely check if a domain appears in a text string.

    For JWT issuer fields and other non-URL contexts where we expect
    the domain to appear as part of a URL or standalone.

    Args:
        domain: The domain to check for (e.g., "example.com")
        text: The text string to check

    Returns:
        True if the domain is found in a secure manner
    """
    if not domain or not text:
        return False

    domain_lower = domain.lower()
    text_lower = text.lower()

    if f"://{domain_lower}" in text_lower:
        return True

    if f"://{domain_lower}/" in text_lower:
        return True

    if f"://{domain_lower}:" in text_lower:
        return True

    parts = text_lower.split(".")
    domain_parts = domain_lower.split(".")

    if len(parts) >= len(domain_parts):
        for i in range(len(parts) - len(domain_parts) + 1):
            if parts[i : i + len(domain_parts)] == domain_parts and (i == 0 or parts[i - 1] in ("", " ", "\t", "\n")) and (i + len(domain_parts) == len(parts) or parts[i + len(domain_parts)] in ("", " ", "\t", "\n", ":")):
                return True

    return False
