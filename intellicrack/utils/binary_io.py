"""
Common binary I/O utilities for Intellicrack.

This module provides shared utilities for reading and analyzing binary files.
"""

import os
from typing import Dict, Any, List, Optional


def find_all_pattern_offsets(data: bytes, pattern: bytes) -> List[int]:
    """
    Find all occurrences of a pattern in binary data.
    
    Args:
        data: Binary data to search
        pattern: Pattern to find
        
    Returns:
        List of offsets where pattern was found
    """
    offsets = []
    offset = 0
    while True:
        pos = data.find(pattern, offset)
        if pos == -1:
            break
        offsets.append(pos)
        offset = pos + 1
    return offsets


def analyze_binary_for_strings(binary_path: str, search_strings: list) -> Dict[str, Any]:
    """
    Analyze a binary file for specific strings.
    
    Args:
        binary_path: Path to the binary file
        search_strings: List of strings to search for
        
    Returns:
        Dictionary with analysis results
    """
    results = {
        "strings_found": [],
        "confidence": 0.0,
        "error": None
    }
    
    if not binary_path or not os.path.exists(binary_path):
        results["error"] = "Invalid binary path"
        return results
        
    try:
        with open(binary_path, 'rb') as f:
            data = f.read()
            
        # Search for strings
        found_count = 0
        for search_str in search_strings:
            if search_str.encode() in data:
                results["strings_found"].append(search_str)
                found_count += 1
                
        # Calculate confidence based on strings found
        if search_strings:
            results["confidence"] = (found_count / len(search_strings)) * 100.0
            
    except Exception as e:
        results["error"] = str(e)
        
    return results