"""
Bypass Engine for Mitigation Bypass

This module provides a compatibility import from the main bypass engine.
"""

# Import the shared bypass engine to avoid code duplication
from ..exploitation.bypass_engine import BypassEngine

__all__ = ['BypassEngine']
