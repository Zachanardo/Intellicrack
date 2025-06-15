"""
Entropy Calculation Utilities

Shared entropy calculation functions to eliminate code duplication.
"""

import math
from typing import Dict, Union


def calculate_entropy(data: Union[bytes, str]) -> float:
    """
    Calculate Shannon entropy of data.
    
    Args:
        data: Input data (bytes or string)
        
    Returns:
        Shannon entropy value
    """
    if not data:
        return 0.0

    # Count frequencies
    freq = {}
    for item in data:
        freq[item] = freq.get(item, 0) + 1

    # Calculate entropy
    entropy = 0.0
    data_len = len(data)

    for count in freq.values():
        p = count / data_len
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def calculate_byte_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy specifically for byte data.
    
    Args:
        data: Input byte data
        
    Returns:
        Shannon entropy value
    """
    return calculate_entropy(data)


def calculate_string_entropy(data: str) -> float:
    """
    Calculate Shannon entropy specifically for string data.
    
    Args:
        data: Input string data
        
    Returns:
        Shannon entropy value
    """
    return calculate_entropy(data)


def safe_entropy_calculation(data: bytes, max_entropy: float = None) -> float:
    """
    Safe entropy calculation with optional maximum cap.
    
    Args:
        data: Input byte data
        max_entropy: Optional maximum entropy value to cap result
        
    Returns:
        Shannon entropy value (optionally capped)
    """
    if not data:
        return 0.0
    
    entropy = calculate_byte_entropy(data)
    
    if max_entropy is not None:
        return min(entropy, max_entropy)
    
    return entropy


def calculate_frequency_distribution(data: Union[bytes, str]) -> Dict:
    """
    Calculate frequency distribution of data.
    
    Args:
        data: Input data (bytes or string)
        
    Returns:
        Dictionary with frequency distribution
    """
    if not data:
        return {}

    freq = {}
    for item in data:
        freq[item] = freq.get(item, 0) + 1

    data_len = len(data)

    # Convert to probabilities
    distribution = {}
    for item, count in freq.items():
        distribution[item] = {
            'count': count,
            'probability': count / data_len
        }

    return distribution


def is_high_entropy(data: Union[bytes, str], threshold: float = 7.0) -> bool:
    """
    Check if data has high entropy (likely encrypted/compressed).
    
    Args:
        data: Input data to analyze
        threshold: Entropy threshold (default 7.0 for binary data)
        
    Returns:
        True if entropy is above threshold
    """
    entropy = calculate_entropy(data)
    return entropy >= threshold


def analyze_entropy_sections(data: bytes, block_size: int = 256) -> Dict:
    """
    Analyze entropy across different sections of data.
    
    Args:
        data: Input byte data
        block_size: Size of each block to analyze
        
    Returns:
        Dictionary with entropy analysis
    """
    if not data:
        return {}

    sections = []
    overall_entropy = calculate_entropy(data)

    # Analyze blocks
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) > 0:
            block_entropy = calculate_entropy(block)
            sections.append({
                'offset': i,
                'size': len(block),
                'entropy': block_entropy,
                'is_high_entropy': is_high_entropy(block)
            })

    # Calculate statistics
    if sections:
        entropies = [s['entropy'] for s in sections]
        avg_entropy = sum(entropies) / len(entropies)
        min_entropy = min(entropies)
        max_entropy = max(entropies)
        variance = sum((e - avg_entropy) ** 2 for e in entropies) / len(entropies)
    else:
        avg_entropy = min_entropy = max_entropy = variance = 0.0

    return {
        'overall_entropy': overall_entropy,
        'sections': sections,
        'statistics': {
            'average_entropy': avg_entropy,
            'min_entropy': min_entropy,
            'max_entropy': max_entropy,
            'variance': variance,
            'section_count': len(sections)
        }
    }
