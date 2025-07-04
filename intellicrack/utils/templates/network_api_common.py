"""
Common network API analysis utilities to avoid code duplication.
"""

from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from intellicrack.logger import logger


def analyze_network_apis(pe_binary, network_apis, logger_func=None):
    """
    Common function to analyze network APIs in a PE binary.

    Args:
        pe_binary: Parsed PE binary object
        network_apis: Dictionary mapping API categories to API lists
        logger_func: Optional function to log detected APIs

    Returns:
        dict: Dictionary of category -> list of detected APIs
    """
    detected_apis = defaultdict(list)

    if hasattr(pe_binary, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe_binary.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if not imp.name:
                    continue
                func_name = imp.name.decode('utf-8', errors='ignore')

                # Categorize APIs
                for category, apis in network_apis.items():
                    if any(api.lower() in func_name.lower() for api in apis):
                        detected_apis[category].append(func_name)

                        # Log detection if logger provided
                        if logger_func and len(detected_apis[category]) <= 3:
                            logger_func(f"[Network Analysis] Found {category} API: {func_name}")

    return dict(detected_apis)


def process_network_api_results(detected_apis: Dict[str, List[str]]) -> Dict[str, Any]:
    """
    Process detected network API results into analysis format.

    Args:
        detected_apis: Dictionary mapping categories to detected API lists

    Returns:
        Dictionary with processed results including counts and security checks
    """
    results = {}

    # Convert to counts for summary
    results["network_apis"] = {
        cat: len(apis) for cat, apis in detected_apis.items() if apis
    }

    # Check for SSL usage patterns
    has_ssl = bool(detected_apis.get('ssl', []))
    has_network = bool(detected_apis.get('basic', [])) or bool(detected_apis.get('http', []))

    results["ssl_usage"] = {
        "has_ssl": has_ssl,
        "has_network": has_network,
        "ssl_without_network": has_ssl and not has_network,
        "network_without_ssl": has_network and not has_ssl
    }

    return results


def get_scapy_layers(scapy_module) -> Optional[Tuple]:
    """
    Get IP and TCP layers from scapy module with proper error handling.

    This handles different scapy import scenarios across versions.

    Args:
        scapy_module: The imported scapy module

    Returns:
        Tuple of (IP, TCP) classes or None if import failed
    """
    try:
        # Try direct access first
        ip_layer = scapy_module.IP
        tcp_layer = scapy_module.TCP
        return ip_layer, tcp_layer
    except AttributeError as e:
        logger.error("Attribute error in network_api_common: %s", e)
        # Fall back to scapy.layers if needed
        try:
            from scapy.layers.inet import IP as ip_layer
            from scapy.layers.inet import TCP as tcp_layer
            return ip_layer, tcp_layer
        except ImportError as e:
            logger.error("Import error in network_api_common: %s", e)
            # Unable to access IP/TCP layers
            return None


def detect_network_apis(pe_binary, network_apis, logger_func=None):
    """
    Alias for analyze_network_apis for backward compatibility.

    Args:
        pe_binary: Parsed PE binary object
        network_apis: Dictionary mapping API categories to API lists
        logger_func: Optional function to log detected APIs

    Returns:
        dict: Dictionary of category -> list of detected APIs
    """
    return analyze_network_apis(pe_binary, network_apis, logger_func)


def get_network_api_categories():
    """
    Get standard network API categories.

    Returns:
        dict: Dictionary of category -> list of API names
    """
    return {
        'basic': ['socket', 'WSASocket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv'],
        'http': ['HttpOpenRequest', 'HttpSendRequest', 'InternetConnect', 'WinHttpOpen'],
        'ssl': ['SSL_connect', 'SSL_write', 'SSL_read', 'CryptAcquireContext'],
        'dns': ['gethostbyname', 'getaddrinfo', 'DnsQuery']
    }


def summarize_network_capabilities(detected_apis):
    """
    Summarize network capabilities based on detected APIs.

    Args:
        detected_apis: Dictionary of category -> list of APIs

    Returns:
        dict: Summary statistics
    """
    summary = {
        cat: len(apis) for cat, apis in detected_apis.items() if apis
    }

    # Add capability flags
    summary['has_ssl'] = bool(detected_apis.get('ssl', []))
    summary['has_network'] = bool(detected_apis.get('basic', [])) or bool(detected_apis.get('http', []))
    summary['has_dns'] = bool(detected_apis.get('dns', []))

    return summary
