"""
Pattern Search Utilities

Common pattern searching functionality to eliminate code duplication.
"""

from typing import Any, Dict, List


def find_all_pattern_occurrences(binary_data: bytes, pattern: bytes,
                                base_address: int = 0, max_results: int = None) -> List[Dict[str, Any]]:
    """
    Find all occurrences of a single pattern in binary data.
    Common pattern finding loop to eliminate code duplication.
    
    Args:
        binary_data: Binary data to search in
        pattern: Byte pattern to search for
        base_address: Base address to add to found offsets
        max_results: Maximum number of results to return (None for no limit)
        
    Returns:
        List of dictionaries containing found pattern information
    """
    results = []
    offset = 0

    while True:
        pos = binary_data.find(pattern, offset)
        if pos == -1:
            break

        results.append({
            'address': base_address + pos,
            'offset': pos,
            'pattern': pattern,
            'pattern_hex': pattern.hex()
        })

        if max_results and len(results) >= max_results:
            break

        offset = pos + 1

    return results


def search_patterns_in_binary(binary_data: bytes, patterns: List[bytes],
                            base_address: int = 0) -> List[Dict[str, Any]]:
    """
    Search for multiple patterns in binary data.
    
    Args:
        binary_data: Binary data to search in
        patterns: List of byte patterns to search for
        base_address: Base address to add to found offsets
        
    Returns:
        List of dictionaries containing found pattern information
    """
    results = []

    for i, pattern in enumerate(patterns):
        pattern_results = find_all_pattern_occurrences(binary_data, pattern, base_address)
        for result in pattern_results:
            result['pattern_index'] = i
            results.append(result)

    return results


def find_function_prologues(binary_data: bytes, base_address: int = 0) -> List[Dict[str, Any]]:
    """
    Find common function prologues in binary data.
    
    Args:
        binary_data: Binary data to search in
        base_address: Base address to add to found offsets
        
    Returns:
        List of found function prologues with their addresses
    """
    # Common function prologues
    prologues = [
        b'\\x55\\x8B\\xEC',  # push ebp; mov ebp, esp (32-bit)
        b'\\x55\\x89\\xE5',  # push ebp; mov ebp, esp (AT&T)
        b'\\x48\\x89\\x5C\\x24',  # mov [rsp+xx], rbx (64-bit)
        b'\\x40\\x53',  # push rbx (64-bit)
        b'\\x48\\x83\\xEC',  # sub rsp, xx (64-bit)
    ]

    results = search_patterns_in_binary(binary_data, prologues, base_address)

    # Add function-specific metadata
    for result in results:
        result['type'] = 'function_prologue'
        result['confidence'] = 0.7 + (result['pattern_index'] * 0.05)

    return results


def find_license_patterns(binary_data: bytes, base_address: int = 0x400000,
                         max_results: int = 20, context_size: int = 16) -> List[Dict[str, Any]]:
    """
    Find license and validation-related patterns in binary data.
    
    Args:
        binary_data: Binary data to search in
        base_address: Base address to add to found offsets (default: 0x400000)
        max_results: Maximum number of results to return
        context_size: Number of bytes of context to include around matches
        
    Returns:
        List of found license patterns with context and metadata
    """
    # Common license/validation function patterns
    license_patterns = [
        b'license', b'LICENSE', b'key', b'KEY', b'serial', b'SERIAL',
        b'valid', b'VALID', b'check', b'CHECK', b'verify', b'VERIFY',
        b'auth', b'AUTH', b'activate', b'ACTIVATE', b'trial', b'TRIAL'
    ]

    interesting_patterns = []

    for pattern in license_patterns:
        pattern_results = find_all_pattern_occurrences(binary_data, pattern, base_address, max_results - len(interesting_patterns))

        for result in pattern_results:
            interesting_patterns.append({
                'type': 'license_keyword',
                'pattern': pattern.decode('ascii', errors='ignore'),
                'address': hex(result['address']),
                'offset': result['offset'],
                'context': binary_data[max(0, result['offset']-context_size):result['offset']+len(pattern)+context_size].hex()
            })

        if len(interesting_patterns) >= max_results:
            break

    return interesting_patterns
