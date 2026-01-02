"""Network API analysis utilities for binary analysis.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from collections import defaultdict
from collections.abc import Callable
from typing import Any

from intellicrack.utils.logger import logger


def analyze_network_apis(
    pe_binary: object,
    network_apis: dict[str, list[str]],
    logger_func: Callable[[str], None] | None = None,
) -> dict[str, list[str]]:
    """Analyze network APIs in a PE binary.

    Args:
        pe_binary: Parsed PE binary object.
        network_apis: Dictionary mapping API categories to API lists.
        logger_func: Optional function to log detected APIs.

    Returns:
        Dictionary of category -> list of detected APIs.

    """
    detected_apis = defaultdict(list)

    if hasattr(pe_binary, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe_binary.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if not imp.name:
                    continue
                func_name = imp.name.decode("utf-8", errors="ignore")

                for category, apis in network_apis.items():
                    if any(api.lower() in func_name.lower() for api in apis):
                        detected_apis[category].append(func_name)

                        if logger_func and len(detected_apis[category]) <= 3:
                            logger_func(f"[Network Analysis] Found {category} API: {func_name}")

    return dict(detected_apis)


def process_network_api_results(detected_apis: dict[str, list[str]]) -> dict[str, Any]:
    """Process detected network API results into analysis format.

    Args:
        detected_apis: Dictionary mapping categories to detected API lists.

    Returns:
        Dictionary with processed results including counts and security checks.

    """
    results = {"network_apis": {cat: len(apis) for cat, apis in detected_apis.items() if apis}}

    has_ssl = bool(detected_apis.get("ssl"))
    has_network = bool(detected_apis.get("basic")) or bool(detected_apis.get("http"))

    results["ssl_usage"] = {
        "has_ssl": has_ssl,
        "has_network": has_network,
        "ssl_without_network": has_ssl and not has_network,
        "network_without_ssl": has_network and not has_ssl,
    }

    return results


def get_scapy_layers(scapy_module: object) -> tuple[object, object] | None:
    """Get IP and TCP layers from scapy module with proper error handling.

    Args:
        scapy_module: The imported scapy module.

    Returns:
        Tuple of (IP, TCP) classes or None if import failed.

    """
    try:
        ip_layer = getattr(scapy_module, "IP", None)
        tcp_layer = getattr(scapy_module, "TCP", None)
        if ip_layer is None or tcp_layer is None:
            raise AttributeError("Missing IP or TCP layer")
        return ip_layer, tcp_layer
    except AttributeError as e:
        logger.error("Attribute error in network_api_analysis: %s", e)
        try:
            from scapy.layers.inet import IP, TCP

            return IP, TCP
        except ImportError as import_err:
            logger.error("Import error in network_api_analysis: %s", import_err)
            return None


def detect_network_apis(
    pe_binary: object,
    network_apis: dict[str, list[str]],
    logger_func: Callable[[str], None] | None = None,
) -> dict[str, list[str]]:
    """Alias for analyze_network_apis for backward compatibility.

    Args:
        pe_binary: Parsed PE binary object.
        network_apis: Dictionary mapping API categories to API lists.
        logger_func: Optional function to log detected APIs.

    Returns:
        Dictionary of category -> list of detected APIs.

    """
    return analyze_network_apis(pe_binary, network_apis, logger_func)


def get_network_api_categories() -> dict[str, list[str]]:
    """Get standard network API categories.

    Returns:
        Dictionary of category -> list of API names.

    """
    return {
        "basic": ["socket", "WSASocket", "bind", "listen", "accept", "connect", "send", "recv"],
        "http": ["HttpOpenRequest", "HttpSendRequest", "InternetConnect", "WinHttpOpen"],
        "ssl": ["SSL_connect", "SSL_write", "SSL_read", "CryptAcquireContext"],
        "dns": ["gethostbyname", "getaddrinfo", "DnsQuery"],
    }


def summarize_network_capabilities(detected_apis: dict[str, list[str]]) -> dict[str, object]:
    """Summarize network capabilities based on detected APIs.

    Args:
        detected_apis: Dictionary of category -> list of APIs.

    Returns:
        Summary statistics.

    """
    summary: dict[str, object] = {cat: len(apis) for cat, apis in detected_apis.items() if apis}

    summary["has_ssl"] = bool(detected_apis.get("ssl"))
    summary["has_network"] = bool(detected_apis.get("basic")) or bool(detected_apis.get("http"))
    summary["has_dns"] = bool(detected_apis.get("dns"))

    return summary
