"""
Unpacking Engine Module

Advanced unpacking capabilities for protected binaries including
VMProtect, Themida, Denuvo and other commercial protections.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from .universal_unpacker import UniversalUnpacker
from .oep_detection import OEPDetector

__all__ = ['UniversalUnpacker', 'OEPDetector']