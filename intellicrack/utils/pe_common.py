"""
Common PE file analysis utilities.

This module provides common functions for PE file import parsing.
"""

import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


def extract_pe_imports(pe_obj) -> List[str]:
    """
    Extract import function names from a PE object.
    
    Args:
        pe_obj: A pefile PE object
        
    Returns:
        List of import function names
    """
    imports = []
    
    try:
        if hasattr(pe_obj, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe_obj.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        imports.append(func_name)
    except (AttributeError, ValueError) as e:
        logger.debug("Error extracting PE imports: %s", e)
        
    return imports


def analyze_pe_import_security(pe_obj) -> dict:
    """
    Analyze PE imports for security-related functions.
    
    Args:
        pe_obj: A pefile PE object
        
    Returns:
        Dictionary with security analysis results
    """
    security_apis = {
        'crypto': ['CryptAcquireContext', 'CryptCreateHash', 'CryptDecrypt', 'CryptEncrypt'],
        'network': ['socket', 'connect', 'send', 'recv', 'WSAStartup', 'InternetOpen'],
        'process': ['CreateProcess', 'OpenProcess', 'TerminateProcess', 'ReadProcessMemory'],
        'registry': ['RegOpenKey', 'RegQueryValue', 'RegSetValue', 'RegCreateKey'],
        'file': ['CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile']
    }
    
    results = {category: [] for category in security_apis}
    imports = extract_pe_imports(pe_obj)
    
    for func_name in imports:
        for category, apis in security_apis.items():
            if any(api.lower() in func_name.lower() for api in apis):
                results[category].append(func_name)
                
    return results