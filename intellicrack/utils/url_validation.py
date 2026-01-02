"""URL validation utilities for secure domain and URL checking.

This module provides functions to validate and check if domains appear in URLs
and text strings, with security-focused implementations for use in contexts
such as JWT issuer validation and certificate pinning.

This module also provides SSRF protection through URL validation that blocks
access to private/internal IP ranges and restricts allowed schemes.
"""

import ipaddress
import logging
import socket
from urllib.parse import urlparse


logger = logging.getLogger(__name__)

ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

BLOCKED_IP_RANGES: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
)


class SSRFError(Exception):
    """Exception raised when SSRF attempt is detected."""

    pass


def is_safe_url(url: str, allow_local: bool = False) -> bool:
    """Check if a URL is safe to request (SSRF protection).

    Validates that:
    - URL scheme is http or https
    - Hostname is not a private/internal IP address
    - Hostname does not resolve to a private IP

    Args:
        url: The URL to validate.
        allow_local: If True, allows localhost and private IPs (for testing).

    Returns:
        True if the URL is safe to request, False otherwise.
    """
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ALLOWED_SCHEMES:
            logger.warning("Blocked URL with unsafe scheme: %s", parsed.scheme)
            return False

        hostname = parsed.hostname
        if not hostname:
            logger.warning("Blocked URL with no hostname")
            return False

        if allow_local:
            return True

        try:
            ip = ipaddress.ip_address(hostname)
            if _is_private_ip(ip):
                logger.warning("Blocked URL with private IP: %s", hostname)
                return False
        except ValueError:
            try:
                resolved_ips = socket.getaddrinfo(hostname, None)
                for _, _, _, _, sockaddr in resolved_ips:
                    ip = ipaddress.ip_address(sockaddr[0])
                    if _is_private_ip(ip):
                        logger.warning(
                            "Blocked URL: hostname %s resolves to private IP %s",
                            hostname, sockaddr[0]
                        )
                        return False
            except (socket.gaierror, OSError) as e:
                logger.debug("DNS resolution failed for %s: %s", hostname, e)

        return True

    except Exception as e:
        logger.exception("URL validation failed: %s", e)
        return False


def _is_private_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address is private/internal.

    Args:
        ip: The IP address to check.

    Returns:
        True if the IP is private/internal, False otherwise.
    """
    for network in BLOCKED_IP_RANGES:
        if ip in network:
            return True
    return ip.is_private or ip.is_loopback or ip.is_link_local


def validate_url_for_request(url: str, allow_local: bool = False) -> str:
    """Validate and return URL if safe, raise SSRFError otherwise.

    Args:
        url: The URL to validate.
        allow_local: If True, allows localhost and private IPs.

    Returns:
        The validated URL.

    Raises:
        SSRFError: If the URL is not safe to request.
    """
    if not is_safe_url(url, allow_local=allow_local):
        raise SSRFError(f"URL failed SSRF validation: {url}")
    return url


def is_domain_in_url(domain: str, url: str) -> bool:
    """Securely check if a domain is in a URL.

    Args:
        domain: The domain to check for (e.g., "example.com").
        url: The URL string to check.

    Returns:
        True if the domain matches the URL's hostname, False otherwise.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        return hostname == domain or hostname.endswith(f".{domain}")
    except (ValueError, AttributeError):
        return False


def is_domain_in_string(domain: str, text: str) -> bool:
    """Securely check if a domain appears in a text string.

    For JWT issuer fields and other non-URL contexts where we expect
    the domain to appear as part of a URL or standalone.

    Args:
        domain: The domain to check for (e.g., "example.com").
        text: The text string to check.

    Returns:
        True if the domain is found in a secure manner, False otherwise.
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
            if (
                parts[i : i + len(domain_parts)] == domain_parts
                and (i == 0 or parts[i - 1] in ("", " ", "\t", "\n"))
                and (i + len(domain_parts) == len(parts) or parts[i + len(domain_parts)] in ("", " ", "\t", "\n", ":"))
            ):
                return True

    return False
