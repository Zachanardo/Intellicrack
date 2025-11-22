"""Import patterns for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.

Common import patterns used across the Intellicrack codebase.

This module provides centralized import handling for commonly used libraries
with consistent error handling and availability flags.
"""

import logging


logger = logging.getLogger(__name__)

# Binary analysis tools
try:
    from intellicrack.handlers.pefile_handler import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    pefile = None
    PEFILE_AVAILABLE = False
    logger.debug("pefile not available")

try:
    from intellicrack.handlers.capstone_handler import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    CAPSTONE_AVAILABLE = True
except ImportError:
    CS_ARCH_X86 = None
    CS_MODE_32 = None
    CS_MODE_64 = None
    Cs = None
    CAPSTONE_AVAILABLE = False
    logger.debug("capstone not available")

try:
    from intellicrack.handlers.lief_handler import HAS_LIEF, lief

    LIEF_AVAILABLE = HAS_LIEF
except ImportError:
    lief = None
    LIEF_AVAILABLE = False
    HAS_LIEF = False
    logger.debug("lief not available")

try:
    from intellicrack.handlers.pyelftools_handler import HAS_PYELFTOOLS, ELFFile, elffile

    PYELFTOOLS_AVAILABLE = HAS_PYELFTOOLS
except ImportError:
    ELFFile = None
    elffile = None
    PYELFTOOLS_AVAILABLE = False
    HAS_PYELFTOOLS = False
    logger.debug("pyelftools not available")

try:
    from macholib.MachO import MachO

    MACHOLIB_AVAILABLE = True
except ImportError:
    MachO = None
    MACHOLIB_AVAILABLE = False
    logger.debug("macholib not available")

# Android/Java analysis tools
try:
    import zipfile

    ZIPFILE_AVAILABLE = True
except ImportError:
    zipfile = None
    ZIPFILE_AVAILABLE = False
    logger.debug("zipfile not available")

try:
    import defusedxml.ElementTree as ET  # noqa: N817

    XML_AVAILABLE = True
except ImportError:
    try:
        import xml.etree.ElementTree as ET

        XML_AVAILABLE = True
    except ImportError:
        ET = None
        XML_AVAILABLE = False
        logger.debug("xml.etree.ElementTree not available")

# System tools
try:
    from intellicrack.handlers.psutil_handler import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False
    logger.debug("psutil not available")


def get_pefile() -> object | None:
    """Get pefile module if available.

    Returns:
        The pefile module if available, None otherwise.

    """
    return pefile


def get_capstone() -> dict[str, object]:
    """Get capstone module components if available.

    Returns:
        Dictionary containing Capstone disassembler components and availability flag.

    """
    return {
        "Cs": Cs,
        "CS_ARCH_X86": CS_ARCH_X86,
        "CS_MODE_32": CS_MODE_32,
        "CS_MODE_64": CS_MODE_64,
        "available": CAPSTONE_AVAILABLE,
    }


def get_lief() -> object | None:
    """Get lief module if available.

    Returns:
        The lief module if available, None otherwise.

    """
    return lief


def get_elftools() -> dict[str, object]:
    """Get elftools components if available.

    Returns:
        Dictionary containing ELF file reader and availability flag.

    """
    return {
        "ELFFile": ELFFile,
        "available": PYELFTOOLS_AVAILABLE,
    }


def get_macholib() -> dict[str, object]:
    """Get macholib components if available.

    Returns:
        Dictionary containing Mach-O binary reader and availability flag.

    """
    return {
        "MachO": MachO,
        "available": MACHOLIB_AVAILABLE,
    }


def get_zipfile() -> dict[str, object]:
    """Get zipfile module if available.

    Returns:
        Dictionary containing zipfile module and availability flag.

    """
    return {
        "zipfile": zipfile,
        "available": ZIPFILE_AVAILABLE,
    }


def get_xml() -> dict[str, object]:
    """Get XML parsing components if available.

    Returns:
        Dictionary containing ElementTree XML parser and availability flag.

    """
    return {
        "ET": ET,
        "available": XML_AVAILABLE,
    }


def get_psutil() -> object | None:
    """Get psutil module if available.

    Returns:
        The psutil module if available, None otherwise.

    """
    return psutil


# Export all
__all__ = [
    "CAPSTONE_AVAILABLE",
    "CS_ARCH_X86",
    "CS_MODE_32",
    "CS_MODE_64",
    "Cs",
    "ELFFile",
    "ET",
    "LIEF_AVAILABLE",
    "MACHOLIB_AVAILABLE",
    "MachO",
    "PEFILE_AVAILABLE",
    "PSUTIL_AVAILABLE",
    "PYELFTOOLS_AVAILABLE",
    "XML_AVAILABLE",
    "ZIPFILE_AVAILABLE",
    "get_capstone",
    "get_elftools",
    "get_lief",
    "get_macholib",
    "get_pefile",
    "get_psutil",
    "get_xml",
    "get_zipfile",
    "lief",
    "pefile",
    "psutil",
    "zipfile",
]
