"""
C2 Infrastructure Module

This module provides compatibility aliases for the C2 infrastructure components.
The actual implementations are in the core.c2 module.
"""

# Import from the actual C2 module
from ..c2.c2_client import C2Client
from ..c2.c2_server import C2Server
from ..c2.encryption_manager import EncryptionManager
from ..c2.session_manager import SessionManager
from .c2_manager import C2Manager

# Export compatibility aliases
__all__ = ['C2Manager', 'C2Server', 'SessionManager', 'EncryptionHandler']

# Alias for encryption handler
EncryptionHandler = EncryptionManager
