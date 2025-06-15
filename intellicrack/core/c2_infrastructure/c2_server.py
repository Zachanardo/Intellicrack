"""
C2 Server Module - Compatibility Alias

This module provides compatibility aliases for the C2 server components.
"""

# Import from the actual C2 module
from ..c2.c2_server import C2Server

# Re-export for compatibility
__all__ = ['C2Server']
