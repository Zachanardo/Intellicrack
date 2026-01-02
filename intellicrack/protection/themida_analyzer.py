"""Themida/WinLicense Advanced Virtualization Analysis.

Production-ready analysis engine for Themida and WinLicense virtualization-based
protections including CISC, RISC, and FISH virtual machine architectures.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import math
import re
import struct
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Any


try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from ..utils.logger import get_logger


logger = get_logger(__name__)


class VMArchitecture(Enum):
    """Themida virtual machine architecture types."""

    CISC = "CISC"
    RISC = "RISC"
    FISH = "FISH"
    UNKNOWN = "Unknown"


class ThemidaVersion(Enum):
    """Themida/WinLicense version detection."""

    THEMIDA_1X = "Themida 1.x"
    THEMIDA_2X = "Themida 2.x"
    THEMIDA_3X = "Themida 3.x"
    WINLICENSE_1X = "WinLicense 1.x"
    WINLICENSE_2X = "WinLicense 2.x"
    WINLICENSE_3X = "WinLicense 3.x"
    UNKNOWN = "Unknown"


@dataclass
class VMHandler:
    """Virtual machine handler structure."""

    opcode: int
    address: int
    size: int
    instructions: list[tuple[int, str, str]]
    category: str
    complexity: int
    references: list[int]


@dataclass
class VMContext:
    """Virtual machine context structure."""

    vm_entry: int
    vm_exit: int
    context_size: int
    register_mapping: dict[str, int]
    stack_offset: int
    flags_offset: int


@dataclass
class DevirtualizedCode:
    """Devirtualized code structure."""

    original_rva: int
    original_size: int
    vm_handlers_used: list[int]
    native_code: bytes
    assembly: list[str]
    confidence: float


@dataclass
class ThemidaAnalysisResult:
    """Complete Themida analysis result."""

    is_protected: bool
    version: ThemidaVersion
    vm_architecture: VMArchitecture
    vm_sections: list[str]
    vm_entry_points: list[int]
    vm_contexts: list[VMContext]
    handlers: dict[int, VMHandler]
    handler_table_address: int
    devirtualized_sections: list[DevirtualizedCode]
    encryption_keys: list[bytes]
    anti_debug_locations: list[int]
    anti_dump_locations: list[int]
    integrity_check_locations: list[int]
    confidence: float


class ThemidaAnalyzer:
    """Advanced Themida/WinLicense virtualization analyzer."""

    THEMIDA_SIGNATURES = {
        b"\x8b\xc5\x8b\xd4\x60\xe8\x00\x00\x00\x00": "Themida 1.x Entry",
        b"\xb8\x00\x00\x00\x00\x60\x0b\xc0\x74": "Themida 2.x Entry",
        b"\x55\x8b\xec\x83\xc4\xf0\x53\x56\x57": "Themida 3.x Entry",
        b"\x68\x00\x00\x00\x00\x9c\x60\xe8": "WinLicense 1.x Entry",
        b"\xeb\x10\x66\x62\x3a\x43\x2b\x2b\x48\x4f\x4f\x4b": "WinLicense Marker",
    }

    VM_SECTION_NAMES = [
        b".themida",
        b".winlice",
        b".vmp0",
        b".vmp1",
        b".oreans",
        b"WinLice",
    ]

    CISC_HANDLER_PATTERNS: dict[int, bytes] = {
        0x00: b"\x8b\x45\x00\x89\x45\x04",
        0x01: b"\x8b\x45\x00\x03\x45\x04",
        0x02: b"\x8b\x45\x00\x2b\x45\x04",
        0x03: b"\x8b\x45\x00\x0f\xaf\x45\x04",
        0x04: b"\x8b\x45\x00\x33\x45\x04",
        0x05: b"\x8b\x45\x00\x0b\x45\x04",
        0x06: b"\x8b\x45\x00\x23\x45\x04",
        0x07: b"\xf7\x45\x00",
        0x08: b"\x8b\x45\x00\xd1\xe0",
        0x09: b"\x8b\x45\x00\xd1\xe8",
        0x0A: b"\x83\x7d\x00\x00\x74",
        0x0B: b"\x83\x7d\x00\x00\x75",
        0x0C: b"\xe9",
        0x0D: b"\xeb",
        0x0E: b"\x8b\x45\x00\xff\xe0",
        0x0F: b"\xc3",
        0x10: b"\x8b\x45\x00\xf7\xd0",
        0x11: b"\x8b\x45\x00\xd1\xf8",
        0x12: b"\x8b\x45\x00\xc1\xe0",
        0x13: b"\x8b\x45\x00\xc1\xe8",
        0x14: b"\x8b\x45\x00\xc1\xf8",
        0x15: b"\x8b\x45\x00\xd1\xc0",
        0x16: b"\x8b\x45\x00\xd1\xc8",
        0x17: b"\x8b\x45\x00\xd1\xd0",
        0x18: b"\x8b\x45\x00\xd1\xd8",
        0x19: b"\x8b\x45\x00\xf7\xe1",
        0x1A: b"\x8b\x45\x00\xf7\xf1",
        0x1B: b"\x8b\x45\x00\xf7\xe9",
        0x1C: b"\x8b\x45\x00\xf7\xf9",
        0x1D: b"\xff\x75\x00",
        0x1E: b"\x8f\x45\x00",
        0x1F: b"\x8d\x45\x00",
        0x20: b"\x8b\x00",
        0x21: b"\x8b\x40",
        0x22: b"\x89\x00",
        0x23: b"\x89\x40",
        0x24: b"\x0f\xb6\x00",
        0x25: b"\x0f\xb7\x00",
        0x26: b"\x0f\xbe\x00",
        0x27: b"\x0f\xbf\x00",
        0x28: b"\x88\x00",
        0x29: b"\x66\x89\x00",
        0x2A: b"\xe8",
        0x2B: b"\xff\x15",
        0x2C: b"\xff\xd0",
        0x2D: b"\x9c",
        0x2E: b"\x9d",
        0x2F: b"\x50",
        0x30: b"\x51",
        0x31: b"\x52",
        0x32: b"\x53",
        0x33: b"\x54",
        0x34: b"\x55",
        0x35: b"\x56",
        0x36: b"\x57",
        0x37: b"\x58",
        0x38: b"\x59",
        0x39: b"\x5a",
        0x3A: b"\x5b",
        0x3B: b"\x5c",
        0x3C: b"\x5d",
        0x3D: b"\x5e",
        0x3E: b"\x5f",
        0x3F: b"\x90",
        0x40: b"\xcc",
        0x41: b"\xf4",
        0x42: b"\xfa",
        0x43: b"\xfb",
        0x44: b"\x0f\x01",
        0x45: b"\x0f\xa0",
        0x46: b"\x0f\xa1",
        0x47: b"\x0f\xa8",
        0x48: b"\x0f\xa9",
        0x49: b"\x64\x8b\x00",
        0x4A: b"\x64\x8b\x40",
        0x4B: b"\x64\x89\x00",
        0x4C: b"\x64\x89\x40",
        0x4D: b"\x0f\x20",
        0x4E: b"\x0f\x22",
        0x4F: b"\x0f\xb2",
        0x50: b"\x0f\x30",
        0x51: b"\x0f\x32",
        0x52: b"\x0f\xae",
        0x53: b"\x0f\xba",
        0x54: b"\x0f\xa3",
        0x55: b"\x0f\xab",
        0x56: b"\x0f\xb3",
        0x57: b"\x0f\xbb",
        0x58: b"\x0f\xbc",
        0x59: b"\x0f\xbd",
        0x5A: b"\x0f\x40",
        0x5B: b"\x0f\x41",
        0x5C: b"\x0f\x42",
        0x5D: b"\x0f\x43",
        0x5E: b"\x0f\x44",
        0x5F: b"\x0f\x45",
        0x60: b"\x0f\x46",
        0x61: b"\x0f\x47",
        0x62: b"\x0f\x48",
        0x63: b"\x0f\x49",
        0x64: b"\x0f\x4a",
        0x65: b"\x0f\x4b",
        0x66: b"\x0f\x4c",
        0x67: b"\x0f\x4d",
        0x68: b"\x0f\x4e",
        0x69: b"\x0f\x4f",
        0x6A: b"\x83\xc0",
        0x6B: b"\x83\xe8",
        0x6C: b"\x83\xf0",
        0x6D: b"\x83\xc8",
        0x6E: b"\x83\xe0",
        0x6F: b"\x3b\x45\x00",
        0x70: b"\x85\xc0",
        0x71: b"\x0f\x84",
        0x72: b"\x0f\x85",
        0x73: b"\x0f\x86",
        0x74: b"\x0f\x87",
        0x75: b"\x0f\x82",
        0x76: b"\x0f\x83",
        0x77: b"\x0f\x88",
        0x78: b"\x0f\x89",
        0x79: b"\x0f\x8a",
        0x7A: b"\x0f\x8b",
        0x7B: b"\x0f\x8c",
        0x7C: b"\x0f\x8d",
        0x7D: b"\x0f\x8e",
        0x7E: b"\x0f\x8f",
        0x7F: b"\x0f\x80",
        0x80: b"\x0f\x81",
        0x81: b"\xf3\xa4",
        0x82: b"\xf3\xa5",
        0x83: b"\xf3\xa6",
        0x84: b"\xf3\xa7",
        0x85: b"\xf3\xaa",
        0x86: b"\xf3\xab",
        0x87: b"\xf2\xae",
        0x88: b"\xf2\xaf",
        0x89: b"\xa4",
        0x8A: b"\xa5",
        0x8B: b"\xaa",
        0x8C: b"\xab",
        0x8D: b"\xac",
        0x8E: b"\xad",
        0x8F: b"\xae",
        0x90: b"\xaf",
        0x91: b"\x0f\xc8",
        0x92: b"\x0f\xc9",
        0x93: b"\x0f\xca",
        0x94: b"\x0f\xcb",
        0x95: b"\x0f\xcc",
        0x96: b"\x0f\xcd",
        0x97: b"\x0f\xce",
        0x98: b"\x0f\xcf",
        0x99: b"\x64\xa1\x30\x00\x00\x00",
        0x9A: b"\x64\x8b\x15\x30\x00\x00\x00",
        0x9B: b"\x0f\x31",
        0x9C: b"\xf0\x0f\xb1",
        0x9D: b"\xf0\x0f\xc1",
        0x9E: b"\xf0\x0f\xc7",
        0x9F: b"\x0f\x05",
        0xA0: b"\x0f\x34",
        0xA1: b"\x0f\x35",
    }

    RISC_HANDLER_PATTERNS: dict[int, bytes] = {
        0x00: b"\xe2\x8f\x00\x00",
        0x01: b"\xe0\x80\x00\x00",
        0x02: b"\xe0\x40\x00\x00",
        0x03: b"\xe0\x00\x00\x00",
        0x04: b"\xe2\x00\x00\x00",
        0x05: b"\xe1\x80\x00\x00",
        0x06: b"\xe0\x00\x00\x01",
        0x07: b"\xe2\x61\x00\x00",
        0x08: b"\xe1\xa0\x00\x00",
        0x09: b"\xe1\xa0\x00\x20",
        0x0A: b"\xea\x00\x00\x00",
        0x0B: b"\xe3\x50\x00\x00",
        0x0C: b"\xe5\x9f\x00\x00",
        0x0D: b"\xe5\x8f\x00\x00",
        0x0E: b"\xe7\x9f\x00\x00",
        0x0F: b"\xe1\x2f\xff\x1e",
        0x10: b"\xe1\xe0\x00\x00",
        0x11: b"\xe1\xa0\x00\x40",
        0x12: b"\xe1\xa0\x00\x60",
        0x13: b"\xe0\x20\x00\x00",
        0x14: b"\xe0\xc0\x00\x00",
        0x15: b"\xe1\xc0\x00\x00",
        0x16: b"\xe0\x00\x00\x90",
        0x17: b"\xe0\x20\x00\x90",
        0x18: b"\xe0\xe0\x00\x90",
        0x19: b"\xe0\xc0\x00\x90",
        0x1A: b"\xe0\x80\x00\x90",
        0x1B: b"\xe0\x40\x00\x90",
        0x1C: b"\xe0\x00\x00\x91",
        0x1D: b"\xe0\x20\x00\x91",
        0x1E: b"\xe8\xbd\x00\x00",
        0x1F: b"\xe9\x2d\x00\x00",
        0x20: b"\xe4\x9d\x00\x04",
        0x21: b"\xe5\x2d\x00\x04",
        0x22: b"\xe5\x10\x00\x00",
        0x23: b"\xe5\x00\x00\x00",
        0x24: b"\xe5\xd1\x00\x00",
        0x25: b"\xe5\xc0\x00\x00",
        0x26: b"\xe1\x50\x00\x00",
        0x27: b"\xe3\x10\x00\x00",
        0x28: b"\xe3\xa0\x00\x00",
        0x29: b"\xe3\x80\x00\x00",
        0x2A: b"\xe3\x40\x00\x00",
        0x2B: b"\xe3\xc0\x00\x00",
        0x2C: b"\xe3\xe0\x00\x00",
        0x2D: b"\x0a\x00\x00\x00",
        0x2E: b"\x1a\x00\x00\x00",
        0x2F: b"\x2a\x00\x00\x00",
        0x30: b"\x3a\x00\x00\x00",
        0x31: b"\x4a\x00\x00\x00",
        0x32: b"\x5a\x00\x00\x00",
        0x33: b"\x6a\x00\x00\x00",
        0x34: b"\x7a\x00\x00\x00",
        0x35: b"\x8a\x00\x00\x00",
        0x36: b"\x9a\x00\x00\x00",
        0x37: b"\xaa\x00\x00\x00",
        0x38: b"\xba\x00\x00\x00",
        0x39: b"\xca\x00\x00\x00",
        0x3A: b"\xda\x00\x00\x00",
        0x3B: b"\xeb\x00\x00\x00",
        0x3C: b"\xe1\xa0\x00\x80",
        0x3D: b"\xe1\xa0\x00\xa0",
        0x3E: b"\xe1\xa0\x00\xc0",
        0x3F: b"\xe1\xa0\x00\xe0",
        0x40: b"\xe6\x00\x00\x10",
        0x41: b"\xe6\x20\x00\x10",
        0x42: b"\xe6\x00\x00\x30",
        0x43: b"\xe6\x20\x00\x30",
        0x44: b"\xe6\x00\x00\x50",
        0x45: b"\xe6\x20\x00\x50",
        0x46: b"\xe6\x00\x00\x70",
        0x47: b"\xe6\x20\x00\x70",
        0x48: b"\xe6\x00\x00\x90",
        0x49: b"\xe6\x20\x00\x90",
        0x4A: b"\xe1\xb0\x00\x00",
        0x4B: b"\xe3\x70\x00\x00",
        0x4C: b"\xef\x00\x00\x00",
        0x4D: b"\xe1\x60\x00\x00",
        0x4E: b"\xe1\x60\x00\x10",
        0x4F: b"\xe1\x20\x00\x00",
        0x50: b"\xe6\xef\x00\x70",
        0x51: b"\xe1\xa0\xf0\x0e",
        0x52: b"\xe3\x00\x00\x00",
        0x53: b"\xf1\x01\x00\x00",
        0x54: b"\xf5\x7f\x00\x00",
        0x55: b"\xe1\x0f\x00\x00",
        0x56: b"\xe1\x6f\x00\x00",
        0x57: b"\xe1\x29\xf0\x00",
        0x58: b"\xe1\x69\xf0\x00",
        0x59: b"\xe3\x20\x00\x00",
        0x5A: b"\xe0\x10\x00\x00",
        0x5B: b"\xe0\x30\x00\x00",
        0x5C: b"\xe0\x50\x00\x00",
        0x5D: b"\xe0\x70\x00\x00",
        0x5E: b"\xe0\x90\x00\x00",
        0x5F: b"\xe0\xb0\x00\x00",
        0x60: b"\xe0\xd0\x00\x00",
        0x61: b"\xe0\xf0\x00\x00",
    }

    FISH_HANDLER_PATTERNS: dict[int, bytes] = {
        0x00: b"\x48\x8b\x00",
        0x01: b"\x48\x01\x00",
        0x02: b"\x48\x29\x00",
        0x03: b"\x48\x0f\xaf\x00",
        0x04: b"\x48\x31\x00",
        0x05: b"\x48\x09\x00",
        0x06: b"\x48\x21\x00",
        0x07: b"\x48\xf7\x18",
        0x08: b"\x48\xd1\xe0",
        0x09: b"\x48\xd1\xe8",
        0x0A: b"\x48\x85\xc0\x74",
        0x0B: b"\x48\x85\xc0\x75",
        0x0C: b"\xe9",
        0x0D: b"\xeb",
        0x0E: b"\xff\xe0",
        0x0F: b"\xc3",
        0x10: b"\x48\xf7\xd0",
        0x11: b"\x48\xd1\xf8",
        0x12: b"\x48\xc1\xe0",
        0x13: b"\x48\xc1\xe8",
        0x14: b"\x48\xc1\xf8",
        0x15: b"\x48\xd1\xc0",
        0x16: b"\x48\xd1\xc8",
        0x17: b"\x48\xd1\xd0",
        0x18: b"\x48\xd1\xd8",
        0x19: b"\x48\xf7\xe1",
        0x1A: b"\x48\xf7\xf1",
        0x1B: b"\x48\xf7\xe9",
        0x1C: b"\x48\xf7\xf9",
        0x1D: b"\xff\x75\x00",
        0x1E: b"\x8f\x45\x00",
        0x1F: b"\x4c\x8d\x45\x00",
        0x20: b"\x4c\x8b\x00",
        0x21: b"\x4c\x8b\x40",
        0x22: b"\x4c\x89\x00",
        0x23: b"\x4c\x89\x40",
        0x24: b"\x4c\x0f\xb6\x00",
        0x25: b"\x4c\x0f\xb7\x00",
        0x26: b"\x4c\x0f\xbe\x00",
        0x27: b"\x4c\x0f\xbf\x00",
        0x28: b"\x44\x88\x00",
        0x29: b"\x66\x44\x89\x00",
        0x2A: b"\xe8",
        0x2B: b"\xff\x15",
        0x2C: b"\x41\xff\xd0",
        0x2D: b"\x9c",
        0x2E: b"\x9d",
        0x2F: b"\x41\x50",
        0x30: b"\x41\x51",
        0x31: b"\x41\x52",
        0x32: b"\x41\x53",
        0x33: b"\x41\x54",
        0x34: b"\x41\x55",
        0x35: b"\x41\x56",
        0x36: b"\x41\x57",
        0x37: b"\x41\x58",
        0x38: b"\x41\x59",
        0x39: b"\x41\x5a",
        0x3A: b"\x41\x5b",
        0x3B: b"\x41\x5c",
        0x3C: b"\x41\x5d",
        0x3D: b"\x41\x5e",
        0x3E: b"\x41\x5f",
        0x3F: b"\x90",
        0x40: b"\xcc",
        0x41: b"\xf4",
        0x42: b"\xfa",
        0x43: b"\xfb",
        0x44: b"\x0f\x01",
        0x45: b"\x0f\xa0",
        0x46: b"\x0f\xa1",
        0x47: b"\x0f\xa8",
        0x48: b"\x0f\xa9",
        0x49: b"\x65\x48\x8b\x00",
        0x4A: b"\x65\x48\x8b\x40",
        0x4B: b"\x65\x48\x89\x00",
        0x4C: b"\x65\x48\x89\x40",
        0x4D: b"\x0f\x20",
        0x4E: b"\x0f\x22",
        0x4F: b"\x0f\xb2",
        0x50: b"\x0f\x30",
        0x51: b"\x0f\x32",
        0x52: b"\x0f\xae",
        0x53: b"\x48\x0f\xba",
        0x54: b"\x48\x0f\xa3",
        0x55: b"\x48\x0f\xab",
        0x56: b"\x48\x0f\xb3",
        0x57: b"\x48\x0f\xbb",
        0x58: b"\x48\x0f\xbc",
        0x59: b"\x48\x0f\xbd",
        0x5A: b"\x4c\x0f\x40",
        0x5B: b"\x4c\x0f\x41",
        0x5C: b"\x4c\x0f\x42",
        0x5D: b"\x4c\x0f\x43",
        0x5E: b"\x4c\x0f\x44",
        0x5F: b"\x4c\x0f\x45",
        0x60: b"\x4c\x0f\x46",
        0x61: b"\x4c\x0f\x47",
        0x62: b"\x4c\x0f\x48",
        0x63: b"\x4c\x0f\x49",
        0x64: b"\x4c\x0f\x4a",
        0x65: b"\x4c\x0f\x4b",
        0x66: b"\x4c\x0f\x4c",
        0x67: b"\x4c\x0f\x4d",
        0x68: b"\x4c\x0f\x4e",
        0x69: b"\x4c\x0f\x4f",
        0x6A: b"\x49\x83\xc0",
        0x6B: b"\x49\x83\xe8",
        0x6C: b"\x49\x83\xf0",
        0x6D: b"\x49\x83\xc8",
        0x6E: b"\x49\x83\xe0",
        0x6F: b"\x4c\x3b\x45\x00",
        0x70: b"\x4d\x85\xc0",
        0x71: b"\x0f\x84",
        0x72: b"\x0f\x85",
        0x73: b"\x0f\x86",
        0x74: b"\x0f\x87",
        0x75: b"\x0f\x82",
        0x76: b"\x0f\x83",
        0x77: b"\x0f\x88",
        0x78: b"\x0f\x89",
        0x79: b"\x0f\x8a",
        0x7A: b"\x0f\x8b",
        0x7B: b"\x0f\x8c",
        0x7C: b"\x0f\x8d",
        0x7D: b"\x0f\x8e",
        0x7E: b"\x0f\x8f",
        0x7F: b"\x0f\x80",
        0x80: b"\x0f\x81",
        0x81: b"\xf3\x48\xa4",
        0x82: b"\xf3\x48\xa5",
        0x83: b"\xf3\x48\xa6",
        0x84: b"\xf3\x48\xa7",
        0x85: b"\xf3\x48\xaa",
        0x86: b"\xf3\x48\xab",
        0x87: b"\xf2\x48\xae",
        0x88: b"\xf2\x48\xaf",
        0x89: b"\x48\xa4",
        0x8A: b"\x48\xa5",
        0x8B: b"\x48\xaa",
        0x8C: b"\x48\xab",
        0x8D: b"\x48\xac",
        0x8E: b"\x48\xad",
        0x8F: b"\x48\xae",
        0x90: b"\x48\xaf",
        0x91: b"\x49\x0f\xc8",
        0x92: b"\x49\x0f\xc9",
        0x93: b"\x49\x0f\xca",
        0x94: b"\x49\x0f\xcb",
        0x95: b"\x49\x0f\xcc",
        0x96: b"\x49\x0f\xcd",
        0x97: b"\x49\x0f\xce",
        0x98: b"\x49\x0f\xcf",
        0x99: b"\x65\x48\xa1\x30\x00\x00\x00\x00\x00\x00\x00",
        0x9A: b"\x65\x48\x8b\x15\x30\x00\x00\x00",
        0x9B: b"\x0f\x31",
        0x9C: b"\xf0\x48\x0f\xb1",
        0x9D: b"\xf0\x48\x0f\xc1",
        0x9E: b"\xf0\x48\x0f\xc7",
        0x9F: b"\x0f\x05",
        0xA0: b"\x0f\x34",
        0xA1: b"\x0f\x35",
        0xA2: b"\x48\x0f\x38\xf0",
        0xA3: b"\x48\x0f\x38\xf1",
        0xA4: b"\x66\x0f\x3a\x44",
        0xA5: b"\x66\x0f\x3a\x60",
        0xA6: b"\x66\x0f\x3a\x61",
        0xA7: b"\x66\x0f\x3a\x62",
        0xA8: b"\x66\x0f\x3a\x63",
        0xA9: b"\xc4\xe2",
        0xAA: b"\xc4\xe3",
        0xAB: b"\x62\xf1",
        0xAC: b"\x62\xf2",
        0xAD: b"\x62\xf3",
        0xAE: b"\x62\xe1",
        0xAF: b"\x62\xe2",
    }

    def __init__(self) -> None:
        """Initialize Themida analyzer.

        Initializes instance variables for binary analysis.
        """
        self.binary: Any | None = None
        self.binary_data: bytes | None = None
        self.is_64bit = False

    def analyze(self, binary_path: str) -> ThemidaAnalysisResult:
        """Perform comprehensive Themida/WinLicense analysis.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Complete analysis result

        """
        logger.info("Starting Themida analysis on %s", binary_path)

        with open(binary_path, "rb") as f:
            self.binary_data = f.read()

        if LIEF_AVAILABLE:
            try:
                self.binary = lief.parse(binary_path)
                if self.binary and hasattr(self.binary, "header"):
                    header = self.binary.header
                    if hasattr(header, "machine") and hasattr(lief, "PE"):
                        pe_module = lief.PE
                        if hasattr(pe_module, "MACHINE_TYPES"):
                            self.is_64bit = header.machine == pe_module.MACHINE_TYPES.AMD64
            except Exception as e:
                logger.warning("LIEF parsing failed: %s", e)

        result = ThemidaAnalysisResult(
            is_protected=False,
            version=ThemidaVersion.UNKNOWN,
            vm_architecture=VMArchitecture.UNKNOWN,
            vm_sections=[],
            vm_entry_points=[],
            vm_contexts=[],
            handlers={},
            handler_table_address=0,
            devirtualized_sections=[],
            encryption_keys=[],
            anti_debug_locations=[],
            anti_dump_locations=[],
            integrity_check_locations=[],
            confidence=0.0,
        )

        if not self._detect_themida_presence():
            logger.info("Themida/WinLicense not detected")
            return result

        result.is_protected = True
        result.version = self._detect_version()
        result.vm_sections = self._find_vm_sections()
        result.vm_entry_points = self._find_vm_entry_points()
        result.vm_architecture = self._detect_vm_architecture()
        result.handler_table_address = self._find_handler_table()
        result.handlers = self._extract_handlers(result.handler_table_address, result.vm_architecture)
        result.vm_contexts = self._extract_vm_contexts(result.vm_entry_points)
        result.encryption_keys = self._extract_encryption_keys()
        result.anti_debug_locations = self._find_anti_debug_checks()
        result.anti_dump_locations = self._find_anti_dump_checks()
        result.integrity_check_locations = self._find_integrity_checks()
        result.devirtualized_sections = self._devirtualize_code(result.handlers, result.vm_contexts)
        result.confidence = self._calculate_confidence(result)

        logger.info(
            "Themida analysis complete: %s, VM: %s, Confidence: %.1f%%",
            result.version.value,
            result.vm_architecture.value,
            result.confidence,
        )
        return result

    def _detect_themida_presence(self) -> bool:
        """Detect if binary is protected by Themida/WinLicense.

        Returns:
            True if Themida/WinLicense protection signatures detected, False otherwise.
        """
        if self.binary_data is not None:
            for signature in self.THEMIDA_SIGNATURES:
                if signature in self.binary_data:
                    return True

        if self.binary:
            for section in self.binary.sections:
                section_name = section.name.encode() if isinstance(section.name, str) else section.name
                for vm_section in self.VM_SECTION_NAMES:
                    if vm_section in section_name:
                        return True

        return False

    def _detect_version(self) -> ThemidaVersion:
        """Detect Themida/WinLicense version.

        Returns:
            Detected ThemidaVersion enum value based on binary signatures.
        """
        if self.binary_data is not None:
            version_patterns = {
                b"\x8b\xc5\x8b\xd4\x60\xe8\x00\x00\x00\x00": ThemidaVersion.THEMIDA_1X,
                b"\xb8\x00\x00\x00\x00\x60\x0b\xc0\x74": ThemidaVersion.THEMIDA_2X,
                b"\x55\x8b\xec\x83\xc4\xf0\x53\x56\x57": ThemidaVersion.THEMIDA_3X,
                b"\x68\x00\x00\x00\x00\x9c\x60\xe8": ThemidaVersion.WINLICENSE_1X,
                b"\xeb\x10\x66\x62\x3a\x43\x2b\x2b\x48\x4f\x4f\x4b": ThemidaVersion.WINLICENSE_2X,
            }

            for pattern, version in version_patterns.items():
                if pattern in self.binary_data:
                    return version

            if b"WinLicense" in self.binary_data:
                return ThemidaVersion.WINLICENSE_3X
            if b"Themida" in self.binary_data:
                return ThemidaVersion.THEMIDA_3X

        return ThemidaVersion.UNKNOWN

    def _find_vm_sections(self) -> list[str]:
        """Find virtual machine sections.

        Returns:
            List of VM section names found in binary.
        """
        vm_sections: list[str] = []

        if not self.binary:
            return vm_sections

        for section in self.binary.sections:
            section_name = section.name
            for vm_name in [".themida", ".winlice", ".vmp", ".oreans", "WinLice"]:
                if vm_name in section_name:
                    vm_sections.append(section_name)
                    break

            if section.characteristics & 0x20000000 and section.entropy > 7.5:
                vm_sections.append(section_name)

        return vm_sections

    def _find_vm_entry_points(self) -> list[int]:
        """Find virtual machine entry points.

        Returns:
            Sorted list of unique VM entry point offsets.
        """
        entry_points = []

        entry_patterns = [
            b"\x9c\x60\xe8\x00\x00\x00\x00\x5d\x81\xed",
            b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed",
            b"\x55\x8b\xec\x83\xc4\xf0\xb8",
            b"\xe8\x00\x00\x00\x00\x58\x25\xff\xff\xff\x00",
        ]

        if self.binary_data is not None:
            for pattern in entry_patterns:
                offset = 0
                while True:
                    offset = self.binary_data.find(pattern, offset)
                    if offset == -1:
                        break
                    entry_points.append(offset)
                    offset += len(pattern)

        if self.binary:
            entry_points.append(self.binary.optional_header.addressof_entrypoint)

        return sorted(set(entry_points))

    def _detect_vm_architecture(self) -> VMArchitecture:
        """Detect virtual machine architecture type.

        Returns:
            Detected VMArchitecture enum (CISC, RISC, FISH, or UNKNOWN).
        """
        risc_score = 0
        fish_score = 0
        cisc_score = 0

        if self.binary_data is not None:
            cisc_score = sum(pattern in self.binary_data for pattern in self.CISC_HANDLER_PATTERNS.values())
            for pattern in self.RISC_HANDLER_PATTERNS.values():
                if pattern in self.binary_data:
                    risc_score += 1

            for pattern in self.FISH_HANDLER_PATTERNS.values():
                if pattern in self.binary_data:
                    fish_score += 1

            cisc_strings = [b"CISC", b"complex instruction", b"x86 emulation"]
            risc_strings = [b"RISC", b"reduced instruction", b"ARM emulation"]
            fish_strings = [b"FISH", b"flexible instruction", b"hybrid VM"]

            for s in cisc_strings:
                if s in self.binary_data:
                    cisc_score += 2

            for s in risc_strings:
                if s in self.binary_data:
                    risc_score += 2

            for s in fish_strings:
                if s in self.binary_data:
                    fish_score += 2

        max_score = max(cisc_score, risc_score, fish_score)
        if max_score == 0:
            return VMArchitecture.UNKNOWN
        if max_score == cisc_score:
            return VMArchitecture.CISC
        return VMArchitecture.RISC if max_score == risc_score else VMArchitecture.FISH

    def _find_handler_table(self) -> int:
        """Find virtual machine handler dispatch table.

        Returns:
            Address of handler dispatch table or 0 if not found.
        """
        handler_table_patterns = [
            b"\xff\x24\x85",
            b"\xff\x24\x8d",
            b"\xff\x14\x85",
            b"\xff\x14\x8d",
            b"\x41\xff\x24\xc5" if self.is_64bit else b"\xff\x24\x85",
        ]

        candidates = []

        image_base = 0x400000
        max_image_size = 0x10000000
        if self.binary and hasattr(self.binary, "optional_header"):
            opt_header = self.binary.optional_header
            if hasattr(opt_header, "imagebase"):
                image_base = opt_header.imagebase
            if hasattr(opt_header, "sizeof_image"):
                max_image_size = image_base + opt_header.sizeof_image

        if self.binary_data is not None:
            for pattern in handler_table_patterns:
                offset = 0
                while True:
                    offset = self.binary_data.find(pattern, offset)
                    if offset == -1:
                        break

                    if offset + 7 < len(self.binary_data):
                        table_addr = struct.unpack("<I", self.binary_data[offset + 3 : offset + 7])[0]

                        if image_base <= table_addr <= max_image_size:
                            candidates.append((table_addr, offset))

                    offset += len(pattern)

            pointer_array_pattern = re.compile(b"([\x00-\xff]{4})" * 16)
            for match in pointer_array_pattern.finditer(self.binary_data):
                pointers = [struct.unpack("<I", match.group(i))[0] for i in range(1, 17)]

                if all(image_base <= p <= max_image_size for p in pointers) and len(set(pointers)) > 8:
                    candidates.append((match.start(), match.start()))

        return max(candidates, key=lambda x: x[1])[0] if candidates else 0

    def _extract_handlers(self, handler_table_address: int, vm_arch: VMArchitecture) -> dict[int, VMHandler]:
        """Extract virtual machine handlers.

        Args:
            handler_table_address: Address of handler dispatch table
            vm_arch: Detected VM architecture

        Returns:
            Dictionary mapping opcode to handler information

        """
        handlers = {}

        if handler_table_address == 0:
            logger.warning("No handler table found, using pattern-based extraction")
            return self._extract_handlers_by_pattern(vm_arch)

        handler_patterns = {
            VMArchitecture.CISC: self.CISC_HANDLER_PATTERNS,
            VMArchitecture.RISC: self.RISC_HANDLER_PATTERNS,
            VMArchitecture.FISH: self.FISH_HANDLER_PATTERNS,
        }.get(vm_arch, {})

        if self.binary_data is not None:
            for opcode, pattern in handler_patterns.items():
                offset = self.binary_data.find(pattern)
                if offset != -1:
                    handler_size = self._estimate_handler_size(offset)
                    instructions = self._disassemble_handler(offset, handler_size)
                    category = self._categorize_handler(instructions)
                    complexity = self._calculate_handler_complexity(instructions)
                    references = self._find_handler_references(offset)

                    handlers[opcode] = VMHandler(
                        opcode=opcode,
                        address=offset,
                        size=handler_size,
                        instructions=instructions,
                        category=category,
                        complexity=complexity,
                        references=references,
                    )

        logger.info("Extracted %d VM handlers", len(handlers))
        return handlers

    def _extract_handlers_by_pattern(self, vm_arch: VMArchitecture) -> dict[int, VMHandler]:
        """Extract handlers using pattern matching when table is not found.

        Args:
            vm_arch: Detected VM architecture type.

        Returns:
            Dictionary mapping opcode to handler information.
        """
        handlers = {}

        handler_patterns = {
            VMArchitecture.CISC: self.CISC_HANDLER_PATTERNS,
            VMArchitecture.RISC: self.RISC_HANDLER_PATTERNS,
            VMArchitecture.FISH: self.FISH_HANDLER_PATTERNS,
        }.get(vm_arch, {})

        if self.binary_data is not None:
            for opcode, pattern in handler_patterns.items():
                offset = 0
                while True:
                    offset = self.binary_data.find(pattern, offset)
                    if offset == -1:
                        break

                    if opcode not in handlers:
                        handler_size = self._estimate_handler_size(offset)
                        instructions = self._disassemble_handler(offset, handler_size)
                        category = self._categorize_handler(instructions)
                        complexity = self._calculate_handler_complexity(instructions)
                        references = self._find_handler_references(offset)

                        handlers[opcode] = VMHandler(
                            opcode=opcode,
                            address=offset,
                            size=handler_size,
                            instructions=instructions,
                            category=category,
                            complexity=complexity,
                            references=references,
                        )
                        break

                    offset += len(pattern)

        return handlers

    def _estimate_handler_size(self, start_offset: int) -> int:
        """Estimate size of a handler by finding return instruction.

        Args:
            start_offset: Starting offset in binary data.

        Returns:
            Estimated handler size in bytes.
        """
        max_size = 256
        if self.binary_data is not None:
            ret_patterns = [b"\xc3", b"\xc2", b"\xcb", b"\xca"]

            for i in range(start_offset, min(start_offset + max_size, len(self.binary_data))):
                for ret_pattern in ret_patterns:
                    if self.binary_data[i : i + len(ret_pattern)] == ret_pattern:
                        return i - start_offset + len(ret_pattern)

        return max_size

    def _disassemble_handler(self, offset: int, size: int) -> list[tuple[int, str, str]]:
        """Disassemble handler code.

        Args:
            offset: Starting offset in binary data.
            size: Number of bytes to disassemble.

        Returns:
            List of (address, mnemonic, operands) tuples.
        """
        if not CAPSTONE_AVAILABLE:
            return [(offset, "unknown", "disassembler not available")]

        instructions: list[tuple[int, str, str]] = []
        mode = CS_MODE_64 if self.is_64bit else CS_MODE_32

        if self.binary_data is not None:
            try:
                md = Cs(CS_ARCH_X86, mode)
                code = self.binary_data[offset : offset + size]

                instructions.extend((insn.address, insn.mnemonic, insn.op_str) for insn in md.disasm(code, offset))
            except Exception as e:
                logger.warning("Disassembly failed at %x: %s", offset, e)

        return instructions

    def _categorize_handler(self, instructions: list[tuple[int, str, str]]) -> str:
        """Categorize handler based on instruction patterns.

        Args:
            instructions: List of (address, mnemonic, operands) tuples.

        Returns:
            Handler category string (arithmetic, logical, data_transfer, etc.).
        """
        if not instructions:
            return "unknown"

        mnemonics = [insn[1] for insn in instructions]
        operands = [insn[2] for insn in instructions]

        if any("fs:[0x30]" in op or "gs:[0x30]" in op for op in operands):
            return "anti_debug"
        if "rdtsc" in mnemonics:
            return "anti_debug"
        if any(m in ["cpuid"] for m in mnemonics):
            return "anti_debug"

        if any(m in ["add", "sub", "mul", "imul", "div", "idiv"] for m in mnemonics):
            return "arithmetic"
        if any(m in ["and", "or", "xor", "not", "shl", "shr", "rol", "ror"] for m in mnemonics):
            return "logical"
        if any(m in ["mov", "movzx", "movsx", "lea"] for m in mnemonics):
            return "data_transfer"
        if any(m in ["cmp", "test"] for m in mnemonics):
            return "comparison"
        if any(m in ["jmp", "je", "jne", "jg", "jl", "ja", "jb", "call"] for m in mnemonics):
            return "control_flow"
        if any(m in ["push", "pop"] for m in mnemonics):
            return "stack_operation"
        return "complex"

    def _calculate_handler_complexity(self, instructions: list[tuple[int, str, str]]) -> int:
        """Calculate handler complexity score (1-10).

        Args:
            instructions: List of (address, mnemonic, operands) tuples.

        Returns:
            Complexity score from 1 to 10.
        """
        if not instructions:
            return 1

        complexity = len(instructions) + len({insn[1] for insn in instructions})
        branch_count = sum(insn[1] in ["jmp", "je", "jne", "jg", "jl", "ja", "jb"] for insn in instructions)
        complexity += branch_count * 2

        return min(max(complexity // 5, 1), 10)

    def _find_handler_references(self, handler_offset: int) -> list[int]:
        """Find all references to this handler.

        Args:
            handler_offset: Offset of handler in binary data.

        Returns:
            List of offsets where handler is referenced.
        """
        references = []
        handler_bytes = struct.pack("<I", handler_offset)

        if self.binary_data is not None:
            offset = 0
            while True:
                offset = self.binary_data.find(handler_bytes, offset)
                if offset == -1:
                    break
                references.append(offset)
                offset += 4

        return references

    def _extract_vm_contexts(self, entry_points: list[int]) -> list[VMContext]:
        """Extract VM context structures from entry points.

        Args:
            entry_points: List of VM entry point offsets.

        Returns:
            List of extracted VM context structures.
        """
        contexts = []

        if self.binary_data is not None:
            for entry in entry_points:
                if entry >= len(self.binary_data) - 100:
                    continue

                context_size = self._detect_context_size(entry)
                register_mapping = self._extract_register_mapping(entry)
                stack_offset = self._find_stack_offset(entry)
                flags_offset = self._find_flags_offset(entry)
                vm_exit = self._find_vm_exit(entry)

                contexts.append(
                    VMContext(
                        vm_entry=entry,
                        vm_exit=vm_exit,
                        context_size=context_size,
                        register_mapping=register_mapping,
                        stack_offset=stack_offset,
                        flags_offset=flags_offset,
                    )
                )

        return contexts

    def _detect_context_size(self, entry: int) -> int:
        """Detect VM context structure size.

        Args:
            entry: Entry point offset.

        Returns:
            Detected context size in bytes.
        """
        if self.binary_data is not None:
            search_area = self.binary_data[entry : entry + 100]

            sub_esp_pattern = b"\x83\xec"
            offset = search_area.find(sub_esp_pattern)
            if offset != -1 and offset + 3 <= len(search_area):
                size_value = struct.unpack("B", search_area[offset + 2 : offset + 3])[0]
                return size_value

            add_esp_pattern = b"\x81\xec"

            offset = search_area.find(add_esp_pattern)
            if offset != -1 and offset + 6 <= len(search_area):
                return int(struct.unpack("<I", search_area[offset + 2 : offset + 6])[0])
        return 0x100

    def _extract_register_mapping(self, entry: int) -> dict[str, int]:
        """Extract VM register to native register mapping.

        Args:
            entry: Entry point offset.

        Returns:
            Dictionary mapping VM registers to offsets in context structure.
        """
        if not CAPSTONE_AVAILABLE or self.binary_data is None or entry >= len(self.binary_data) - 100:
            registers = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]
            return {reg: i * 4 for i, reg in enumerate(registers)}

        register_mapping: dict[str, int] = {}
        mode = CS_MODE_64 if self.is_64bit else CS_MODE_32

        try:
            md = Cs(CS_ARCH_X86, mode)
            code = self.binary_data[entry : entry + 100]

            reg_patterns = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]
            if self.is_64bit:
                reg_patterns = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

            for insn in md.disasm(code, entry):
                if insn.mnemonic == "mov" and "[ebp" in insn.op_str or "[rbp" in insn.op_str:
                    for reg in reg_patterns:
                        if f"{reg}," in insn.op_str or f", {reg}" in insn.op_str:
                            offset_match = re.search(r"\[.bp([+\-])0x([0-9a-fA-F]+)\]", insn.op_str)
                            if offset_match:
                                sign = offset_match.group(1)
                                offset = int(offset_match.group(2), 16)
                                if sign == "-":
                                    offset = -offset
                                register_mapping[reg] = offset
                                break

        except Exception as e:
            logger.debug("Failed to extract register mapping: %s", e)

        if not register_mapping:
            registers = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]
            return {reg: i * 4 for i, reg in enumerate(registers)}

        return register_mapping

    def _find_stack_offset(self, entry: int) -> int:
        """Find VM stack offset in context.

        Args:
            entry: Entry point offset.

        Returns:
            Stack offset in VM context structure.
        """
        if not CAPSTONE_AVAILABLE or self.binary_data is None or entry >= len(self.binary_data) - 100:
            return 0x80

        mode = CS_MODE_64 if self.is_64bit else CS_MODE_32

        try:
            md = Cs(CS_ARCH_X86, mode)
            code = self.binary_data[entry : entry + 100]

            for insn in md.disasm(code, entry):
                if insn.mnemonic == "mov" and "esp" in insn.op_str or "rsp" in insn.op_str:
                    if "[ebp" in insn.op_str or "[rbp" in insn.op_str:
                        offset_match = re.search(r"\[.bp([+\-])0x([0-9a-fA-F]+)\]", insn.op_str)
                        if offset_match:
                            sign = offset_match.group(1)
                            offset = int(offset_match.group(2), 16)
                            if sign == "-":
                                offset = -offset
                            return abs(offset)

        except Exception as e:
            logger.debug("Failed to find stack offset: %s", e)

        return 0x80

    def _find_flags_offset(self, entry: int) -> int:
        """Find VM flags offset in context.

        Args:
            entry: Entry point offset.

        Returns:
            Flags offset in VM context structure.
        """
        if not CAPSTONE_AVAILABLE or self.binary_data is None or entry >= len(self.binary_data) - 100:
            return 0xA0

        mode = CS_MODE_64 if self.is_64bit else CS_MODE_32

        try:
            md = Cs(CS_ARCH_X86, mode)
            code = self.binary_data[entry : entry + 100]

            for insn in md.disasm(code, entry):
                if insn.mnemonic == "pushf" or insn.mnemonic == "pushfd" or insn.mnemonic == "pushfq":
                    next_insn_offset = insn.address + insn.size
                    remaining_code = self.binary_data[next_insn_offset : next_insn_offset + 20]

                    md2 = Cs(CS_ARCH_X86, mode)
                    for next_insn in md2.disasm(remaining_code, next_insn_offset):
                        if next_insn.mnemonic == "mov" and "[ebp" in next_insn.op_str or "[rbp" in next_insn.op_str:
                            offset_match = re.search(r"\[.bp([+\-])0x([0-9a-fA-F]+)\]", next_insn.op_str)
                            if offset_match:
                                sign = offset_match.group(1)
                                offset = int(offset_match.group(2), 16)
                                if sign == "-":
                                    offset = -offset
                                return abs(offset)
                        break

        except Exception as e:
            logger.debug("Failed to find flags offset: %s", e)

        return 0xA0

    def _find_vm_exit(self, vm_entry: int) -> int:
        """Find VM exit point corresponding to entry.

        Args:
            vm_entry: VM entry point offset.

        Returns:
            VM exit point offset or 0 if not found.
        """
        if self.binary_data is not None:
            search_start = vm_entry
            search_end = min(vm_entry + 10000, len(self.binary_data))
            search_area = self.binary_data[search_start:search_end]

            exit_patterns = [
                b"\x61\x9d\xc3",
                b"\x61\xc3",
                b"\x5d\xc3",
                b"\x8b\xe5\x5d\xc3",
                b"\x48\x8b\xe5\x5d\xc3" if self.is_64bit else b"\x8b\xe5\x5d\xc3",
                b"\xff\x25",
                b"\xff\xe0",
                b"\xff\xe1",
                b"\xff\xe2",
            ]

            for pattern in exit_patterns:
                offset = search_area.find(pattern)
                if offset != -1:
                    return search_start + offset

            if CAPSTONE_AVAILABLE:
                mode = CS_MODE_64 if self.is_64bit else CS_MODE_32
                try:
                    md = Cs(CS_ARCH_X86, mode)

                    last_ret_offset = 0
                    for insn in md.disasm(search_area, search_start):
                        if insn.mnemonic == "ret" or insn.mnemonic == "retn":
                            context_cleanup = False
                            check_area_start = max(0, insn.address - search_start - 20)
                            check_area = search_area[check_area_start : insn.address - search_start]

                            md2 = Cs(CS_ARCH_X86, mode)
                            for prev_insn in md2.disasm(check_area, search_start + check_area_start):
                                if prev_insn.mnemonic in ["popa", "popad", "popf", "popfd", "mov"] and "esp" in prev_insn.op_str or "ebp" in prev_insn.op_str:
                                    context_cleanup = True
                                    break

                            if context_cleanup:
                                return insn.address

                            last_ret_offset = insn.address

                    if last_ret_offset > 0:
                        return last_ret_offset

                except Exception as e:
                    logger.debug("Failed to disassemble exit search: %s", e)

        return 0

    def _extract_encryption_keys(self) -> list[bytes]:
        """Extract encryption keys used by Themida.

        Returns:
            List of extracted encryption keys (up to 10).
        """
        keys = []

        if self.binary_data is None:
            return keys

        key_init_patterns = [
            b"\x68",
            b"\xb8",
            b"\xbb",
            b"\xc7\x05",
            b"\xc7\x45",
            b"\x48\xb8" if self.is_64bit else b"\xb8",
        ]

        high_entropy_threshold = 6.5
        executable_code_threshold = 3.0

        key_candidates: list[tuple[int, bytes]] = []

        for pattern in key_init_patterns:
            offset = 0
            while True:
                offset = self.binary_data.find(pattern, offset)
                if offset == -1:
                    break

                if offset + 36 <= len(self.binary_data):
                    nearby_region = self.binary_data[offset : offset + 36]

                    for key_size in [16, 32]:
                        if offset + key_size + 4 <= len(self.binary_data):
                            key_candidate = self.binary_data[offset + 4 : offset + 4 + key_size]

                            entropy = self._calculate_entropy_bytes(key_candidate)

                            if entropy > high_entropy_threshold and entropy < 8.0:
                                is_code = self._appears_to_be_code(key_candidate)

                                if not is_code:
                                    key_candidates.append((offset, key_candidate))

                offset += len(pattern)

        if self.binary and hasattr(self.binary, "sections"):
            for section in self.binary.sections:
                if hasattr(section, "content") and hasattr(section, "characteristics"):
                    if not (section.characteristics & 0x20):
                        section_data = bytes(section.content)

                        for i in range(0, len(section_data) - 32, 16):
                            chunk_16 = section_data[i : i + 16]
                            chunk_32 = section_data[i : i + 32]

                            entropy_16 = self._calculate_entropy_bytes(chunk_16)
                            entropy_32 = self._calculate_entropy_bytes(chunk_32)

                            if entropy_16 > high_entropy_threshold and entropy_16 < 8.0 and not self._appears_to_be_code(chunk_16):
                                key_candidates.append((i, chunk_16))

                            if entropy_32 > high_entropy_threshold and entropy_32 < 8.0 and not self._appears_to_be_code(chunk_32):
                                key_candidates.append((i, chunk_32))

        key_candidates.sort(key=lambda x: self._calculate_entropy_bytes(x[1]), reverse=True)

        seen_keys: set[bytes] = set()
        for offset, key in key_candidates:
            if key not in seen_keys and len(keys) < 10:
                keys.append(key)
                seen_keys.add(key)

        return keys

    def _appears_to_be_code(self, data: bytes) -> bool:
        """Determine if data appears to be executable code rather than a key.

        Args:
            data: Byte data to analyze.

        Returns:
            True if data appears to be code, False otherwise.
        """
        if not CAPSTONE_AVAILABLE or len(data) < 4:
            return False

        try:
            mode = CS_MODE_64 if self.is_64bit else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)

            instruction_count = 0
            valid_instructions = 0

            for insn in md.disasm(data, 0):
                instruction_count += 1
                if insn.mnemonic not in ["db", "invalid"]:
                    valid_instructions += 1

                if instruction_count >= 3:
                    break

            if instruction_count >= 2 and valid_instructions / instruction_count > 0.5:
                return True

        except Exception:
            pass

        return False

    def _calculate_entropy_bytes(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data.

        Args:
            data: Byte data to analyze.

        Returns:
            Shannon entropy value (0.0 to 8.0).
        """
        if not data:
            return 0.0

        frequency = Counter(data)
        entropy = 0.0
        data_len = len(data)

        for count in frequency.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    def _find_anti_debug_checks(self) -> list[int]:
        """Find anti-debugging check locations.

        Returns:
            List of offsets where anti-debug checks occur.
        """
        anti_debug_locations = []

        anti_debug_patterns = [
            b"\x64\xa1\x30\x00\x00\x00",
            b"\x64\x8b\x15\x30\x00\x00\x00",
            b"IsDebuggerPresent",
            b"CheckRemoteDebuggerPresent",
            b"NtQueryInformationProcess",
            b"\x0f\x31",
        ]

        if self.binary_data is not None:
            for pattern in anti_debug_patterns:
                offset = 0
                while True:
                    offset = self.binary_data.find(pattern, offset)
                    if offset == -1:
                        break
                    anti_debug_locations.append(offset)
                    offset += len(pattern)

        return sorted(set(anti_debug_locations))

    def _find_anti_dump_checks(self) -> list[int]:
        """Find anti-dumping check locations.

        Returns:
            List of offsets where anti-dump checks occur.
        """
        anti_dump_locations = []

        anti_dump_patterns = [
            b"VirtualProtect",
            b"VirtualAlloc",
            b"WriteProcessMemory",
            b"\x89\x45\x00\x8b\x45\x04\x89\x45\x08",
        ]

        if self.binary_data is not None:
            for pattern in anti_dump_patterns:
                offset = 0
                while True:
                    offset = self.binary_data.find(pattern, offset)
                    if offset == -1:
                        break
                    anti_dump_locations.append(offset)
                    offset += len(pattern)

        return sorted(set(anti_dump_locations))

    def _find_integrity_checks(self) -> list[int]:
        """Find integrity check locations.

        Returns:
            List of offsets where integrity checks occur.
        """
        integrity_locations = []

        if self.binary_data is None:
            return integrity_locations

        crc_patterns = [
            b"\xf7\x73",
            b"\xf7\x33",
            b"\xf2\x0f\x38\xf1",
            b"\x66\x0f\x38\xf0",
        ]

        hash_patterns = [
            b"\x81\xc1",
            b"\x81\xc9",
            b"\x33\xc0\x8b",
        ]

        loop_patterns = [
            b"\xe2",
            b"\x0f\x84",
            b"\x0f\x85",
            b"\x75",
            b"\x74",
        ]

        crc_references = [b"CRC32", b"checksum", b"integrity", b"hash", b"verify", b"validation"]

        for pattern in crc_patterns:
            offset = 0
            while True:
                offset = self.binary_data.find(pattern, offset)
                if offset == -1:
                    break

                nearby_area = self.binary_data[max(0, offset - 200) : offset + 200]

                has_loop = any(loop_pattern in nearby_area for loop_pattern in loop_patterns)
                has_reference = any(ref in nearby_area for ref in crc_references)

                if has_loop or has_reference:
                    integrity_locations.append(offset)

                offset += len(pattern)

        for pattern in hash_patterns:
            offset = 0
            while True:
                offset = self.binary_data.find(pattern, offset)
                if offset == -1:
                    break

                nearby_area = self.binary_data[max(0, offset - 200) : offset + 200]

                has_loop = any(loop_pattern in nearby_area for loop_pattern in loop_patterns)
                has_reference = any(ref in nearby_area for ref in crc_references)
                has_multiple_xor = nearby_area.count(b"\x33") > 2

                if (has_loop and has_multiple_xor) or has_reference:
                    integrity_locations.append(offset)

                offset += len(pattern)

        return sorted(set(integrity_locations))

    def _devirtualize_code(self, handlers: dict[int, VMHandler], contexts: list[VMContext]) -> list[DevirtualizedCode]:
        """Devirtualize VM-protected code sections.

        Args:
            handlers: Extracted VM handlers
            contexts: VM context structures

        Returns:
            List of devirtualized code sections

        """
        devirtualized: list[DevirtualizedCode] = []

        if not handlers or not contexts:
            logger.warning("Cannot devirtualize without handlers and contexts")
            return devirtualized

        if self.binary_data is not None:
            for context in contexts:
                vm_code_start = context.vm_entry
                vm_code_end = context.vm_exit if context.vm_exit > 0 else vm_code_start + 1000

                if vm_code_end > len(self.binary_data):
                    continue

                vm_bytecode = self.binary_data[vm_code_start:vm_code_end]

                native_code, assembly, handlers_used, confidence = self._translate_vm_to_native(
                    vm_bytecode,
                    handlers,
                    context,
                )

                devirtualized.append(
                    DevirtualizedCode(
                        original_rva=vm_code_start,
                        original_size=vm_code_end - vm_code_start,
                        vm_handlers_used=handlers_used,
                        native_code=native_code,
                        assembly=assembly,
                        confidence=confidence,
                    )
                )

        logger.info("Devirtualized %d code sections", len(devirtualized))
        return devirtualized

    def _translate_vm_to_native(
        self,
        vm_bytecode: bytes,
        handlers: dict[int, VMHandler],
        context: VMContext,
    ) -> tuple[bytes, list[str], list[int], float]:
        """Translate VM bytecode to native x86/x64 code with advanced handler lifting.

        Args:
            vm_bytecode: VM bytecode to translate.
            handlers: Dictionary of VM handlers indexed by opcode.
            context: VM context structure containing metadata.

        Returns:
            Tuple of (native_code, assembly_lines, handlers_used, confidence).
        """
        assembly = []
        native_code = bytearray()
        handlers_used = []
        confidence = 0.0

        opcode_translation = self._build_comprehensive_opcode_translation()

        i = 0
        valid_translations = 0
        total_opcodes = 0

        while i < len(vm_bytecode):
            opcode = vm_bytecode[i]
            total_opcodes += 1
            i += 1

            if opcode in handlers:
                handlers_used.append(opcode)
                handler = handlers[opcode]

                lifted_result = self._lift_handler_to_native(opcode, handler, vm_bytecode, i, context)

                if lifted_result:
                    native_bytes, asm_str, operand_size = lifted_result
                    native_code.extend(native_bytes)
                    assembly.append(asm_str)
                    valid_translations += 1
                    i += operand_size

                    if i > len(vm_bytecode):
                        logger.warning("Bytecode stream bounds exceeded at offset %d", i)
                        break

                elif opcode in opcode_translation:
                    native_bytes, asm_str = opcode_translation[opcode]
                    native_code.extend(native_bytes)
                    assembly.append(asm_str)
                    valid_translations += 1

                    if handler.category in ["data_transfer", "arithmetic", "logical"] and i + 4 <= len(vm_bytecode):
                        operand = struct.unpack("<I", vm_bytecode[i : i + 4])[0]
                        assembly[-1] += f"  ; operand: {operand:08x}"
                        i += 4

                        if i > len(vm_bytecode):
                            logger.warning("Bytecode stream bounds exceeded at offset %d", i)
                            break
                else:
                    assembly.append(f"vm_handler_{opcode:02x}")
            else:
                assembly.append(f"db {opcode:02x}h")
                native_code.append(opcode)

        if total_opcodes > 0:
            confidence = (valid_translations / total_opcodes) * 100.0
        else:
            confidence = 0.0

        return bytes(native_code), assembly, handlers_used, confidence

    def _build_comprehensive_opcode_translation(self) -> dict[int, tuple[bytes, str]]:
        """Build comprehensive opcode translation table for all VM architectures.

        Returns:
            Dictionary mapping opcodes to (native_bytes, assembly_string) tuples.
        """
        cisc_translations = {
            0x00: (b"\x8b\x45\x00", "mov eax, [ebp+0]"),
            0x01: (b"\x01\x45\x00", "add [ebp+0], eax"),
            0x02: (b"\x29\x45\x00", "sub [ebp+0], eax"),
            0x03: (b"\x0f\xaf\x45\x00", "imul eax, [ebp+0]"),
            0x04: (b"\x31\x45\x00", "xor [ebp+0], eax"),
            0x05: (b"\x09\x45\x00", "or [ebp+0], eax"),
            0x06: (b"\x21\x45\x00", "and [ebp+0], eax"),
            0x07: (b"\xf7\x5d\x00", "neg [ebp+0]"),
            0x08: (b"\xd1\x65\x00", "shl [ebp+0], 1"),
            0x09: (b"\xd1\x6d\x00", "shr [ebp+0], 1"),
            0x0A: (b"\x74\x00", "je short 0"),
            0x0B: (b"\x75\x00", "jne short 0"),
            0x0C: (b"\xe9\x00\x00\x00\x00", "jmp 0"),
            0x0D: (b"\xeb\x00", "jmp short 0"),
            0x0E: (b"\xff\xe0", "jmp eax"),
            0x0F: (b"\xc3", "ret"),
            0x10: (b"\xf7\xd0", "not eax"),
            0x11: (b"\xd1\xf8", "sar eax, 1"),
            0x12: (b"\xc1\xe0\x01", "shl eax, 1"),
            0x13: (b"\xc1\xe8\x01", "shr eax, 1"),
            0x14: (b"\xc1\xf8\x01", "sar eax, 1"),
            0x15: (b"\xd1\xc0", "rol eax, 1"),
            0x16: (b"\xd1\xc8", "ror eax, 1"),
            0x17: (b"\xd1\xd0", "rcl eax, 1"),
            0x18: (b"\xd1\xd8", "rcr eax, 1"),
            0x19: (b"\xf7\xe1", "mul ecx"),
            0x1A: (b"\xf7\xf1", "div ecx"),
            0x1B: (b"\xf7\xe9", "imul ecx"),
            0x1C: (b"\xf7\xf9", "idiv ecx"),
            0x1D: (b"\xff\x75\x00", "push [ebp+0]"),
            0x1E: (b"\x8f\x45\x00", "pop [ebp+0]"),
            0x1F: (b"\x8d\x45\x00", "lea eax, [ebp+0]"),
            0x20: (b"\x8b\x00", "mov eax, [eax]"),
            0x21: (b"\x8b\x40\x00", "mov eax, [eax+0]"),
            0x22: (b"\x89\x00", "mov [eax], eax"),
            0x23: (b"\x89\x40\x00", "mov [eax+0], eax"),
            0x24: (b"\x0f\xb6\x00", "movzx eax, byte [eax]"),
            0x25: (b"\x0f\xb7\x00", "movzx eax, word [eax]"),
            0x26: (b"\x0f\xbe\x00", "movsx eax, byte [eax]"),
            0x27: (b"\x0f\xbf\x00", "movsx eax, word [eax]"),
            0x28: (b"\x88\x00", "mov [eax], al"),
            0x29: (b"\x66\x89\x00", "mov [eax], ax"),
            0x2A: (b"\xe8\x00\x00\x00\x00", "call 0"),
            0x2B: (b"\xff\x15\x00\x00\x00\x00", "call [0]"),
            0x2C: (b"\xff\xd0", "call eax"),
            0x2D: (b"\x9c", "pushfd"),
            0x2E: (b"\x9d", "popfd"),
            0x2F: (b"\x50", "push eax"),
            0x30: (b"\x51", "push ecx"),
            0x31: (b"\x52", "push edx"),
            0x32: (b"\x53", "push ebx"),
            0x33: (b"\x54", "push esp"),
            0x34: (b"\x55", "push ebp"),
            0x35: (b"\x56", "push esi"),
            0x36: (b"\x57", "push edi"),
            0x37: (b"\x58", "pop eax"),
            0x38: (b"\x59", "pop ecx"),
            0x39: (b"\x5a", "pop edx"),
            0x3A: (b"\x5b", "pop ebx"),
            0x3B: (b"\x5c", "pop esp"),
            0x3C: (b"\x5d", "pop ebp"),
            0x3D: (b"\x5e", "pop esi"),
            0x3E: (b"\x5f", "pop edi"),
            0x3F: (b"\x90", "nop"),
            0x40: (b"\xcc", "int3"),
            0x41: (b"\xf4", "hlt"),
            0x42: (b"\xfa", "cli"),
            0x43: (b"\xfb", "sti"),
            0x44: (b"\x0f\x01", "vm_sgdt"),
            0x45: (b"\x0f\xa0", "push fs"),
            0x46: (b"\x0f\xa1", "pop fs"),
            0x47: (b"\x0f\xa8", "push gs"),
            0x48: (b"\x0f\xa9", "pop gs"),
            0x49: (b"\x64\x8b\x00", "mov eax, fs:[eax]"),
            0x4A: (b"\x64\x8b\x40\x00", "mov eax, fs:[eax+0]"),
            0x4B: (b"\x64\x89\x00", "mov fs:[eax], eax"),
            0x4C: (b"\x64\x89\x40\x00", "mov fs:[eax+0], eax"),
            0x4D: (b"\x0f\x20", "mov eax, cr0"),
            0x4E: (b"\x0f\x22", "mov cr0, eax"),
            0x4F: (b"\x0f\xb2", "lsl eax, eax"),
            0x50: (b"\x0f\x30", "wrmsr"),
            0x51: (b"\x0f\x32", "rdmsr"),
            0x52: (b"\x0f\xae", "vm_fxsave"),
            0x53: (b"\x0f\xba", "vm_bt"),
            0x54: (b"\x0f\xa3", "bt eax, eax"),
            0x55: (b"\x0f\xab", "bts eax, eax"),
            0x56: (b"\x0f\xb3", "btr eax, eax"),
            0x57: (b"\x0f\xbb", "btc eax, eax"),
            0x58: (b"\x0f\xbc", "bsf eax, eax"),
            0x59: (b"\x0f\xbd", "bsr eax, eax"),
            0x5A: (b"\x0f\x40", "cmovo eax, eax"),
            0x5B: (b"\x0f\x41", "cmovno eax, eax"),
            0x5C: (b"\x0f\x42", "cmovc eax, eax"),
            0x5D: (b"\x0f\x43", "cmovnc eax, eax"),
            0x5E: (b"\x0f\x44", "cmovz eax, eax"),
            0x5F: (b"\x0f\x45", "cmovnz eax, eax"),
            0x60: (b"\x0f\x46", "cmovbe eax, eax"),
            0x61: (b"\x0f\x47", "cmova eax, eax"),
            0x62: (b"\x0f\x48", "cmovs eax, eax"),
            0x63: (b"\x0f\x49", "cmovns eax, eax"),
            0x64: (b"\x0f\x4a", "cmovp eax, eax"),
            0x65: (b"\x0f\x4b", "cmovnp eax, eax"),
            0x66: (b"\x0f\x4c", "cmovl eax, eax"),
            0x67: (b"\x0f\x4d", "cmovge eax, eax"),
            0x68: (b"\x0f\x4e", "cmovle eax, eax"),
            0x69: (b"\x0f\x4f", "cmovg eax, eax"),
            0x6A: (b"\x83\xc0\x01", "add eax, 1"),
            0x6B: (b"\x83\xe8\x01", "sub eax, 1"),
            0x6C: (b"\x83\xf0\x01", "xor eax, 1"),
            0x6D: (b"\x83\xc8\x01", "or eax, 1"),
            0x6E: (b"\x83\xe0\x01", "and eax, 1"),
            0x6F: (b"\x3b\x45\x00", "cmp eax, [ebp+0]"),
            0x70: (b"\x85\xc0", "test eax, eax"),
            0x71: (b"\x0f\x84\x00\x00\x00\x00", "je 0"),
            0x72: (b"\x0f\x85\x00\x00\x00\x00", "jne 0"),
            0x73: (b"\x0f\x86\x00\x00\x00\x00", "jbe 0"),
            0x74: (b"\x0f\x87\x00\x00\x00\x00", "ja 0"),
            0x75: (b"\x0f\x82\x00\x00\x00\x00", "jb 0"),
            0x76: (b"\x0f\x83\x00\x00\x00\x00", "jae 0"),
            0x77: (b"\x0f\x88\x00\x00\x00\x00", "js 0"),
            0x78: (b"\x0f\x89\x00\x00\x00\x00", "jns 0"),
            0x79: (b"\x0f\x8a\x00\x00\x00\x00", "jp 0"),
            0x7A: (b"\x0f\x8b\x00\x00\x00\x00", "jnp 0"),
            0x7B: (b"\x0f\x8c\x00\x00\x00\x00", "jl 0"),
            0x7C: (b"\x0f\x8d\x00\x00\x00\x00", "jge 0"),
            0x7D: (b"\x0f\x8e\x00\x00\x00\x00", "jle 0"),
            0x7E: (b"\x0f\x8f\x00\x00\x00\x00", "jg 0"),
            0x7F: (b"\x0f\x80\x00\x00\x00\x00", "jo 0"),
            0x80: (b"\x0f\x81\x00\x00\x00\x00", "jno 0"),
            0x81: (b"\xf3\xa4", "rep movsb"),
            0x82: (b"\xf3\xa5", "rep movsd"),
            0x83: (b"\xf3\xa6", "repe cmpsb"),
            0x84: (b"\xf3\xa7", "repe cmpsd"),
            0x85: (b"\xf3\xaa", "rep stosb"),
            0x86: (b"\xf3\xab", "rep stosd"),
            0x87: (b"\xf2\xae", "repne scasb"),
            0x88: (b"\xf2\xaf", "repne scasd"),
            0x89: (b"\xa4", "movsb"),
            0x8A: (b"\xa5", "movsd"),
            0x8B: (b"\xaa", "stosb"),
            0x8C: (b"\xab", "stosd"),
            0x8D: (b"\xac", "lodsb"),
            0x8E: (b"\xad", "lodsd"),
            0x8F: (b"\xae", "scasb"),
            0x90: (b"\xaf", "scasd"),
            0x91: (b"\x0f\xc8", "bswap eax"),
            0x92: (b"\x0f\xc9", "bswap ecx"),
            0x93: (b"\x0f\xca", "bswap edx"),
            0x94: (b"\x0f\xcb", "bswap ebx"),
            0x95: (b"\x0f\xcc", "bswap esp"),
            0x96: (b"\x0f\xcd", "bswap ebp"),
            0x97: (b"\x0f\xce", "bswap esi"),
            0x98: (b"\x0f\xcf", "bswap edi"),
            0x99: (b"\x64\xa1\x30\x00\x00\x00", "mov eax, fs:[0x30]"),
            0x9A: (b"\x64\x8b\x15\x30\x00\x00\x00", "mov edx, fs:[0x30]"),
            0x9B: (b"\x0f\x31", "rdtsc"),
            0x9C: (b"\xf0\x0f\xb1\x00", "lock cmpxchg [eax], eax"),
            0x9D: (b"\xf0\x0f\xc1\x00", "lock xadd [eax], eax"),
            0x9E: (b"\xf0\x0f\xc7\x08", "lock cmpxchg8b [eax]"),
            0x9F: (b"\x0f\x05", "syscall"),
            0xA0: (b"\x0f\x34", "sysenter"),
            0xA1: (b"\x0f\x35", "sysexit"),
        }

        return cisc_translations

    def _lift_handler_to_native(
        self, opcode: int, handler: VMHandler, bytecode: bytes, offset: int, context: VMContext
    ) -> tuple[bytes, str, int] | None:
        """Lift VM handler to native x86/x64 instructions using semantic analysis.

        Args:
            opcode: VM opcode value.
            handler: VM handler structure.
            bytecode: Full VM bytecode.
            offset: Current offset in bytecode.
            context: VM context structure.

        Returns:
            Tuple of (native_bytes, assembly_string, operand_size) or None if lifting fails.
        """
        if handler.category == "anti_debug":
            return self._lift_anti_debug_handler(opcode, handler, bytecode, offset)

        if handler.category == "arithmetic":
            return self._lift_arithmetic_handler(opcode, handler, bytecode, offset)

        if handler.category == "logical":
            return self._lift_logical_handler(opcode, handler, bytecode, offset)

        if handler.category == "control_flow":
            return self._lift_control_flow_handler(opcode, handler, bytecode, offset)

        if handler.category == "data_transfer":
            return self._lift_data_transfer_handler(opcode, handler, bytecode, offset)

        return None

    def _lift_anti_debug_handler(
        self, opcode: int, handler: VMHandler, bytecode: bytes, offset: int
    ) -> tuple[bytes, str, int] | None:
        """Lift anti-debugging VM handlers to native code.

        Args:
            opcode: VM opcode value.
            handler: VM handler structure.
            bytecode: Full VM bytecode.
            offset: Current offset in bytecode.

        Returns:
            Tuple of (native_bytes, assembly_string, operand_size) or None.
        """
        anti_debug_mappings = {
            0x99: (b"\x64\xa1\x30\x00\x00\x00", "mov eax, fs:[0x30]  ; PEB access", 0),
            0x9A: (b"\x64\x8b\x15\x30\x00\x00\x00", "mov edx, fs:[0x30]  ; PEB access", 0),
            0x9B: (b"\x0f\x31", "rdtsc  ; timing check", 0),
        }

        return anti_debug_mappings.get(opcode)

    def _lift_arithmetic_handler(
        self, opcode: int, handler: VMHandler, bytecode: bytes, offset: int
    ) -> tuple[bytes, str, int] | None:
        """Lift arithmetic VM handlers with operand extraction.

        Args:
            opcode: VM opcode value.
            handler: VM handler structure.
            bytecode: Full VM bytecode.
            offset: Current offset in bytecode.

        Returns:
            Tuple of (native_bytes, assembly_string, operand_size) or None.
        """
        if offset + 4 > len(bytecode):
            return None

        operand = struct.unpack("<I", bytecode[offset : offset + 4])[0]

        arithmetic_templates = {
            0x01: (b"\x05" + struct.pack("<I", operand), f"add eax, 0x{operand:08x}", 4),
            0x02: (b"\x2d" + struct.pack("<I", operand), f"sub eax, 0x{operand:08x}", 4),
            0x03: (b"\x69\xc0" + struct.pack("<I", operand), f"imul eax, eax, 0x{operand:08x}", 4),
            0x6A: (b"\x83\xc0" + bytes([operand & 0xFF]), f"add eax, 0x{operand & 0xFF:02x}", 1),
            0x6B: (b"\x83\xe8" + bytes([operand & 0xFF]), f"sub eax, 0x{operand & 0xFF:02x}", 1),
        }

        return arithmetic_templates.get(opcode)

    def _lift_logical_handler(
        self, opcode: int, handler: VMHandler, bytecode: bytes, offset: int
    ) -> tuple[bytes, str, int] | None:
        """Lift logical operation VM handlers.

        Args:
            opcode: VM opcode value.
            handler: VM handler structure.
            bytecode: Full VM bytecode.
            offset: Current offset in bytecode.

        Returns:
            Tuple of (native_bytes, assembly_string, operand_size) or None.
        """
        if offset + 4 > len(bytecode):
            return None

        operand = struct.unpack("<I", bytecode[offset : offset + 4])[0]

        logical_templates = {
            0x04: (b"\x35" + struct.pack("<I", operand), f"xor eax, 0x{operand:08x}", 4),
            0x05: (b"\x0d" + struct.pack("<I", operand), f"or eax, 0x{operand:08x}", 4),
            0x06: (b"\x25" + struct.pack("<I", operand), f"and eax, 0x{operand:08x}", 4),
            0x6C: (b"\x83\xf0" + bytes([operand & 0xFF]), f"xor eax, 0x{operand & 0xFF:02x}", 1),
            0x6D: (b"\x83\xc8" + bytes([operand & 0xFF]), f"or eax, 0x{operand & 0xFF:02x}", 1),
            0x6E: (b"\x83\xe0" + bytes([operand & 0xFF]), f"and eax, 0x{operand & 0xFF:02x}", 1),
        }

        return logical_templates.get(opcode)

    def _lift_control_flow_handler(
        self, opcode: int, handler: VMHandler, bytecode: bytes, offset: int
    ) -> tuple[bytes, str, int] | None:
        """Lift control flow VM handlers.

        Args:
            opcode: VM opcode value.
            handler: VM handler structure.
            bytecode: Full VM bytecode.
            offset: Current offset in bytecode.

        Returns:
            Tuple of (native_bytes, assembly_string, operand_size) or None.
        """
        if opcode in [0x0C, 0x2A]:
            if offset + 4 > len(bytecode):
                return None
            target = struct.unpack("<I", bytecode[offset : offset + 4])[0]
            if opcode == 0x0C:
                return (b"\xe9" + struct.pack("<I", target), f"jmp 0x{target:08x}", 4)
            return (b"\xe8" + struct.pack("<I", target), f"call 0x{target:08x}", 4)

        if opcode in [0x0D]:
            if offset + 1 > len(bytecode):
                return None
            rel = bytecode[offset]
            return (b"\xeb" + bytes([rel]), f"jmp short 0x{rel:02x}", 1)

        conditional_jumps = {
            0x71: (b"\x0f\x84", "je"),
            0x72: (b"\x0f\x85", "jne"),
            0x73: (b"\x0f\x86", "jbe"),
            0x74: (b"\x0f\x87", "ja"),
            0x75: (b"\x0f\x82", "jb"),
            0x76: (b"\x0f\x83", "jae"),
            0x77: (b"\x0f\x88", "js"),
            0x78: (b"\x0f\x89", "jns"),
            0x79: (b"\x0f\x8a", "jp"),
            0x7A: (b"\x0f\x8b", "jnp"),
            0x7B: (b"\x0f\x8c", "jl"),
            0x7C: (b"\x0f\x8d", "jge"),
            0x7D: (b"\x0f\x8e", "jle"),
            0x7E: (b"\x0f\x8f", "jg"),
        }

        if opcode in conditional_jumps:
            if offset + 4 > len(bytecode):
                return None
            target = struct.unpack("<I", bytecode[offset : offset + 4])[0]
            opcode_bytes, mnemonic = conditional_jumps[opcode]
            return (opcode_bytes + struct.pack("<I", target), f"{mnemonic} 0x{target:08x}", 4)

        return None

    def _lift_data_transfer_handler(
        self, opcode: int, handler: VMHandler, bytecode: bytes, offset: int
    ) -> tuple[bytes, str, int] | None:
        """Lift data transfer VM handlers.

        Args:
            opcode: VM opcode value.
            handler: VM handler structure.
            bytecode: Full VM bytecode.
            offset: Current offset in bytecode.

        Returns:
            Tuple of (native_bytes, assembly_string, operand_size) or None.
        """
        if offset + 4 > len(bytecode):
            return None

        operand = struct.unpack("<I", bytecode[offset : offset + 4])[0]

        data_transfer_templates = {
            0x00: (b"\xa1" + struct.pack("<I", operand), f"mov eax, [0x{operand:08x}]", 4),
            0x20: (b"\x8b\x05" + struct.pack("<I", operand), f"mov eax, [0x{operand:08x}]", 4),
            0x22: (b"\xa3" + struct.pack("<I", operand), f"mov [0x{operand:08x}], eax", 4),
        }

        return data_transfer_templates.get(opcode)

    def detect_virtualized_regions(self) -> list[tuple[int, int, str]]:
        """Detect virtualized code regions in the binary.

        Returns:
            List of (start_offset, end_offset, vm_type) tuples for each virtualized region.
        """
        virtualized_regions: list[tuple[int, int, str]] = []

        if self.binary_data is None:
            return virtualized_regions

        vm_entry_signatures = [
            (b"\x9c\x60\xe8\x00\x00\x00\x00\x5d\x81\xed", "CISC"),
            (b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed", "CISC"),
            (b"\xe2\x8f\x00\x00", "RISC"),
            (b"\x48\x8b\x00", "FISH"),
            (b"\x55\x8b\xec\x83\xc4\xf0\xb8", "CISC"),
        ]

        for signature, vm_type in vm_entry_signatures:
            offset = 0
            while True:
                offset = self.binary_data.find(signature, offset)
                if offset == -1:
                    break

                region_end = self._find_virtualized_region_end(offset, vm_type)
                virtualized_regions.append((offset, region_end, vm_type))

                offset += len(signature)

        logger.info("Detected %d virtualized regions", len(virtualized_regions))
        return sorted(set(virtualized_regions))

    def _find_virtualized_region_end(self, start: int, vm_type: str) -> int:
        """Find the end of a virtualized code region.

        Args:
            start: Starting offset of virtualized region.
            vm_type: Type of VM architecture (CISC, RISC, FISH).

        Returns:
            Ending offset of virtualized region.
        """
        if self.binary_data is None:
            return start + 1000

        exit_patterns = {
            "CISC": [b"\x61\x9d\xc3", b"\x61\xc3", b"\xc3"],
            "RISC": [b"\xe1\x2f\xff\x1e", b"\xef\x00\x00\x00"],
            "FISH": [b"\xc3", b"\x48\xc3"],
        }

        patterns = exit_patterns.get(vm_type, [b"\xc3"])
        search_limit = min(start + 10000, len(self.binary_data))

        earliest_end = search_limit
        for pattern in patterns:
            offset = self.binary_data.find(pattern, start, search_limit)
            if offset != -1 and offset < earliest_end:
                earliest_end = offset + len(pattern)

        return earliest_end if earliest_end < search_limit else start + 1000

    def handle_mutation_variations(self, handlers: dict[int, VMHandler]) -> dict[int, list[VMHandler]]:
        """Detect and handle mutation engine variations of VM handlers.

        Args:
            handlers: Dictionary of base VM handlers.

        Returns:
            Dictionary mapping opcodes to lists of handler variations.
        """
        handler_variations: dict[int, list[VMHandler]] = {}

        for opcode, base_handler in handlers.items():
            variations = [base_handler]

            mutation_variants = self._find_handler_mutations(base_handler)
            variations.extend(mutation_variants)

            handler_variations[opcode] = variations

        total_variations = sum(len(v) for v in handler_variations.values())
        logger.info("Found %d handler variations across %d opcodes", total_variations, len(handler_variations))

        return handler_variations

    def _find_handler_mutations(self, base_handler: VMHandler) -> list[VMHandler]:
        """Find mutated versions of a handler using pattern similarity.

        Args:
            base_handler: Base handler to find mutations of.

        Returns:
            List of mutated handler variations.
        """
        mutations: list[VMHandler] = []

        if self.binary_data is None or not CAPSTONE_AVAILABLE:
            return mutations

        base_instructions = base_handler.instructions
        if not base_instructions or len(base_instructions) < 3:
            return mutations

        base_mnemonics = [insn[1] for insn in base_instructions]
        base_pattern_signature = "".join(base_mnemonics[:5])

        search_window = 10000
        start_search = max(0, base_handler.address - search_window)
        end_search = min(len(self.binary_data), base_handler.address + search_window)

        mode = CS_MODE_64 if self.is_64bit else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)

        search_data = self.binary_data[start_search:end_search]

        try:
            current_instructions: list[tuple[int, str, str]] = []
            last_address = start_search

            for insn in md.disasm(search_data, start_search):
                if insn.address == base_handler.address:
                    current_instructions = []
                    continue

                current_instructions.append((insn.address, insn.mnemonic, insn.op_str))

                if len(current_instructions) >= len(base_instructions):
                    candidate_mnemonics = [inst[1] for inst in current_instructions]

                    similarity = self._calculate_handler_similarity(base_mnemonics, candidate_mnemonics)

                    if similarity > 0.7:
                        candidate_offset = current_instructions[0][0]
                        candidate_size = insn.address + insn.size - candidate_offset

                        category = self._categorize_handler(current_instructions)
                        complexity = self._calculate_handler_complexity(current_instructions)
                        references = self._find_handler_references(candidate_offset)

                        mutation = VMHandler(
                            opcode=base_handler.opcode,
                            address=candidate_offset,
                            size=candidate_size,
                            instructions=list(current_instructions),
                            category=category,
                            complexity=complexity,
                            references=references,
                        )
                        mutations.append(mutation)

                        if len(mutations) >= 10:
                            break

                    current_instructions.pop(0)

        except Exception as e:
            logger.debug("Handler mutation search failed: %s", e)

        return mutations

    def _calculate_handler_similarity(self, mnemonics1: list[str], mnemonics2: list[str]) -> float:
        """Calculate similarity between two handler instruction sequences.

        Args:
            mnemonics1: First instruction mnemonic list.
            mnemonics2: Second instruction mnemonic list.

        Returns:
            Similarity score from 0.0 to 1.0.
        """
        if not mnemonics1 or not mnemonics2:
            return 0.0

        set1 = set(mnemonics1)
        set2 = set(mnemonics2)

        intersection = len(set1 & set2)
        union = len(set1 | set2)

        if union == 0:
            return 0.0

        jaccard_similarity = intersection / union

        len_diff = abs(len(mnemonics1) - len(mnemonics2))
        max_len = max(len(mnemonics1), len(mnemonics2))
        length_penalty = 1.0 - (len_diff / max_len) if max_len > 0 else 0.0

        return (jaccard_similarity + length_penalty) / 2.0

    def analyze_vm_bytecode_stream(self, bytecode: bytes, vm_arch: VMArchitecture) -> dict[str, Any]:
        """Analyze VM bytecode stream for patterns and characteristics.

        Args:
            bytecode: Raw VM bytecode to analyze.
            vm_arch: VM architecture type.

        Returns:
            Dictionary containing bytecode analysis results.
        """
        analysis: dict[str, Any] = {
            "total_bytes": len(bytecode),
            "opcode_distribution": {},
            "control_flow_instructions": 0,
            "data_instructions": 0,
            "anti_analysis_instructions": 0,
            "entropy": self._calculate_entropy_bytes(bytecode),
            "complexity_score": 0,
        }

        opcode_counts: dict[int, int] = {}
        control_flow_opcodes = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x2A}
        anti_analysis_opcodes = {0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E}

        for byte in bytecode:
            opcode_counts[byte] = opcode_counts.get(byte, 0) + 1

            if byte in control_flow_opcodes:
                analysis["control_flow_instructions"] += 1
            elif byte in anti_analysis_opcodes:
                analysis["anti_analysis_instructions"] += 1
            else:
                analysis["data_instructions"] += 1

        analysis["opcode_distribution"] = opcode_counts

        unique_opcodes = len(opcode_counts)
        branch_density = analysis["control_flow_instructions"] / len(bytecode) if len(bytecode) > 0 else 0
        anti_analysis_density = analysis["anti_analysis_instructions"] / len(bytecode) if len(bytecode) > 0 else 0

        analysis["complexity_score"] = int(unique_opcodes * 2 + branch_density * 100 + anti_analysis_density * 50)

        return analysis

    def _calculate_confidence(self, result: ThemidaAnalysisResult) -> float:
        """Calculate overall analysis confidence score.

        Args:
            result: Complete analysis result to score.

        Returns:
            Confidence score from 0.0 to 100.0.
        """
        confidence = 0.0

        if result.version != ThemidaVersion.UNKNOWN:
            confidence += 20.0

        if result.vm_architecture != VMArchitecture.UNKNOWN:
            confidence += 20.0

        if result.vm_sections:
            confidence += 15.0

        if result.vm_entry_points:
            confidence += 10.0

        if result.handler_table_address > 0:
            confidence += 15.0

        if result.handlers:
            confidence += min(len(result.handlers) * 0.5, 10.0)

        if result.devirtualized_sections:
            avg_dev_confidence = sum(d.confidence for d in result.devirtualized_sections) / len(result.devirtualized_sections)
            confidence += min(avg_dev_confidence * 0.1, 10.0)

        return min(confidence, 100.0)

    def get_analysis_report(self, result: ThemidaAnalysisResult) -> dict[str, Any]:
        """Generate human-readable analysis report.

        Args:
            result: Analysis result

        Returns:
            Dictionary containing formatted report

        """
        report: dict[str, Any] = {
            "protection_detected": result.is_protected,
            "version": result.version.value,
            "vm_architecture": result.vm_architecture.value,
            "confidence": f"{result.confidence:.1f}%",
            "vm_sections": result.vm_sections,
            "vm_entry_points": [f"0x{ep:08x}" for ep in result.vm_entry_points],
            "handler_table": f"0x{result.handler_table_address:08x}" if result.handler_table_address else "Not found",
            "handlers_extracted": len(result.handlers),
            "vm_contexts": len(result.vm_contexts),
            "devirtualized_sections": len(result.devirtualized_sections),
            "anti_debug_checks": len(result.anti_debug_locations),
            "anti_dump_checks": len(result.anti_dump_locations),
            "integrity_checks": len(result.integrity_check_locations),
        }

        if result.handlers:
            handler_categories: dict[str, int] = {}
            for handler in result.handlers.values():
                category = handler.category
                handler_categories[category] = handler_categories.get(category, 0) + 1
            report["handler_categories"] = handler_categories

        if result.devirtualized_sections:
            devirtualization_quality: dict[str, Any] = {
                "average_confidence": f"{sum(d.confidence for d in result.devirtualized_sections) / len(result.devirtualized_sections):.1f}%",
                "total_instructions": sum(len(d.assembly) for d in result.devirtualized_sections),
            }
            report["devirtualization_quality"] = devirtualization_quality

        return report
