"""
Encryption Handler Module - Compatibility Alias

This module provides compatibility aliases for the encryption components.
"""

# Import from the actual C2 module
from ..c2.encryption_manager import EncryptionManager

# Re-export for compatibility
EncryptionHandler = EncryptionManager

__all__ = ['EncryptionHandler']
