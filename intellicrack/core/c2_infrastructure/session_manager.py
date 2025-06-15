"""
Session Manager Module - Compatibility Alias

This module provides compatibility aliases for the session manager components.
"""

# Import from the actual C2 module
from ..c2.session_manager import SessionManager

# Re-export for compatibility
__all__ = ['SessionManager']
