"""
Common import patterns used across the Intellicrack codebase.

This module provides centralized import handling for commonly used libraries
with consistent error handling and availability flags.
"""

import logging

logger = logging.getLogger(__name__)

# Binary analysis tools
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    pefile = None
    PEFILE_AVAILABLE = False
    logger.debug("pefile not available")

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    CAPSTONE_AVAILABLE = True
except ImportError:
    CS_ARCH_X86 = None
    CS_MODE_32 = None
    CS_MODE_64 = None
    Cs = None
    CAPSTONE_AVAILABLE = False
    logger.debug("capstone not available")

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    lief = None
    LIEF_AVAILABLE = False
    logger.debug("lief not available")

try:
    from elftools.elf.elffile import ELFFile
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    ELFFile = None
    PYELFTOOLS_AVAILABLE = False
    logger.debug("pyelftools not available")

try:
    from macholib.MachO import MachO
    MACHOLIB_AVAILABLE = True
except ImportError:
    MachO = None
    MACHOLIB_AVAILABLE = False
    logger.debug("macholib not available")

# System tools
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False
    logger.debug("psutil not available")


def get_pefile():
    """Get pefile module if available."""
    return pefile


def get_capstone():
    """Get capstone module components if available."""
    return {
        'Cs': Cs,
        'CS_ARCH_X86': CS_ARCH_X86,
        'CS_MODE_32': CS_MODE_32,
        'CS_MODE_64': CS_MODE_64,
        'available': CAPSTONE_AVAILABLE
    }


def get_lief():
    """Get lief module if available."""
    return lief


def get_elftools():
    """Get elftools components if available."""
    return {
        'ELFFile': ELFFile,
        'available': PYELFTOOLS_AVAILABLE
    }


def get_macholib():
    """Get macholib components if available."""
    return {
        'MachO': MachO,
        'available': MACHOLIB_AVAILABLE
    }


def get_psutil():
    """Get psutil module if available."""
    return psutil


# Export all
__all__ = [
    'PEFILE_AVAILABLE', 'pefile', 'get_pefile',
    'CAPSTONE_AVAILABLE', 'CS_ARCH_X86', 'CS_MODE_32', 'CS_MODE_64', 'Cs', 'get_capstone',
    'LIEF_AVAILABLE', 'lief', 'get_lief',
    'PYELFTOOLS_AVAILABLE', 'ELFFile', 'get_elftools',
    'MACHOLIB_AVAILABLE', 'MachO', 'get_macholib',
    'PSUTIL_AVAILABLE', 'psutil', 'get_psutil',
]
