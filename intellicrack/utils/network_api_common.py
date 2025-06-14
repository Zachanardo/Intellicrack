"""
Common network API analysis utilities to avoid code duplication.
"""

from collections import defaultdict


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
