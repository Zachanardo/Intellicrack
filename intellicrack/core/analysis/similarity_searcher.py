"""
Binary Similarity Searcher

Provides compatibility wrapper for binary_similarity_search module.
"""

# Import the main implementation
from .binary_similarity_search import BinarySimilaritySearch

# Alias for backward compatibility
BinarySimilaritySearcher = BinarySimilaritySearch

__all__ = ['BinarySimilaritySearcher']