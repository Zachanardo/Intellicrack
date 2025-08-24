"""ELF Binary Analysis Module for Intellicrack.

Provides comprehensive analysis capabilities for ELF (Executable and Linkable Format) binaries
commonly found on Linux, BSD, and other Unix-like systems.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import logging
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class ELFAnalyzer:
    """Comprehensive ELF binary analyzer for security research."""

    # ELF Constants
    EI_NIDENT = 16
    EI_MAG0 = 0
    EI_MAG1 = 1
    EI_MAG2 = 2
    EI_MAG3 = 3
    EI_CLASS = 4
    EI_DATA = 5
    EI_VERSION = 6
    EI_OSABI = 7
    EI_ABIVERSION = 8

    ELFMAG = b'\x7fELF'
    ELFCLASS32 = 1
    ELFCLASS64 = 2
    ELFDATA2LSB = 1
    ELFDATA2MSB = 2

    # ELF Types
    ET_NONE = 0
    ET_REL = 1
    ET_EXEC = 2
    ET_DYN = 3
    ET_CORE = 4

    # Machine Types
    EM_386 = 3
    EM_X86_64 = 62
    EM_ARM = 40
    EM_AARCH64 = 183

    def __init__(self, file_path: Union[str, Path]):
        """Initialize ELF analyzer with binary file.

        Args:
            file_path: Path to ELF binary file

        """
        self.file_path = Path(file_path)
        self.data: Optional[bytes] = None
        self.header: Optional[Dict[str, Any]] = None
        self.sections: List[Dict[str, Any]] = []
        self.segments: List[Dict[str, Any]] = []
        self.symbols: List[Dict[str, Any]] = []
        self.is_64bit: bool = False
        self.endian: str = 'little'

    def load_binary(self) -> bool:
        """Load and validate ELF binary.

        Returns:
            True if binary loaded successfully, False otherwise

        """
        try:
            with open(self.file_path, 'rb') as f:
                self.data = f.read()

            if not self._validate_elf():
                logger.error(f"Invalid ELF file: {self.file_path}")
                return False

            self._parse_header()
            return True

        except Exception as e:
            logger.error(f"Failed to load ELF binary {self.file_path}: {e}")
            return False

    def _validate_elf(self) -> bool:
        """Validate ELF magic bytes and basic structure.

        Returns:
            True if valid ELF file, False otherwise

        """
        if not self.data or len(self.data) < self.EI_NIDENT:
            return False

        return self.data[:4] == self.ELFMAG

    def _parse_header(self) -> None:
        """Parse ELF header information."""
        if not self.data:
            return

        # Parse ELF identification
        ei_class = self.data[self.EI_CLASS]
        ei_data = self.data[self.EI_DATA]
        ei_version = self.data[self.EI_VERSION]
        ei_osabi = self.data[self.EI_OSABI]
        ei_abiversion = self.data[self.EI_ABIVERSION]

        self.is_64bit = (ei_class == self.ELFCLASS64)
        self.endian = 'little' if ei_data == self.ELFDATA2LSB else 'big'

        # Parse main header based on architecture
        fmt_prefix = '<' if self.endian == 'little' else '>'

        if self.is_64bit:
            header_fmt = f'{fmt_prefix}HHIQQQIHHHHHH'
            header_size = 64
        else:
            header_fmt = f'{fmt_prefix}HHIIIIIHHHHHH'
            header_size = 52

        if len(self.data) < header_size:
            logger.error("ELF header truncated")
            return

        header_data = struct.unpack(header_fmt, self.data[16:header_size])

        self.header = {
            'ei_class': ei_class,
            'ei_data': ei_data,
            'ei_version': ei_version,
            'ei_osabi': ei_osabi,
            'ei_abiversion': ei_abiversion,
            'e_type': header_data[0],
            'e_machine': header_data[1],
            'e_version': header_data[2],
            'e_entry': header_data[3],
            'e_phoff': header_data[4],
            'e_shoff': header_data[5],
            'e_flags': header_data[6],
            'e_ehsize': header_data[7],
            'e_phentsize': header_data[8],
            'e_phnum': header_data[9],
            'e_shentsize': header_data[10],
            'e_shnum': header_data[11],
            'e_shstrndx': header_data[12]
        }

    def analyze_sections(self) -> List[Dict[str, Any]]:
        """Analyze ELF sections.

        Returns:
            List of section information dictionaries

        """
        if not self.header or not self.data:
            return []

        sections = []
        shoff = self.header['e_shoff']
        shentsize = self.header['e_shentsize']
        shnum = self.header['e_shnum']

        if shoff == 0 or shnum == 0:
            return sections

        fmt_prefix = '<' if self.endian == 'little' else '>'

        if self.is_64bit:
            section_fmt = f'{fmt_prefix}IIQQQQIIQQ'
        else:
            section_fmt = f'{fmt_prefix}IIIIIIIIII'

        for i in range(shnum):
            try:
                offset = shoff + i * shentsize
                if offset + shentsize > len(self.data):
                    break

                section_data = struct.unpack(section_fmt, self.data[offset:offset + shentsize])

                section = {
                    'index': i,
                    'sh_name': section_data[0],
                    'sh_type': section_data[1],
                    'sh_flags': section_data[2],
                    'sh_addr': section_data[3],
                    'sh_offset': section_data[4],
                    'sh_size': section_data[5],
                    'sh_link': section_data[6],
                    'sh_info': section_data[7],
                    'sh_addralign': section_data[8],
                    'sh_entsize': section_data[9] if len(section_data) > 9 else 0
                }

                sections.append(section)

            except struct.error as e:
                logger.debug(f"Error parsing section {i}: {e}")
                continue

        self.sections = sections
        return sections

    def analyze_segments(self) -> List[Dict[str, Any]]:
        """Analyze ELF program segments.

        Returns:
            List of segment information dictionaries

        """
        if not self.header or not self.data:
            return []

        segments = []
        phoff = self.header['e_phoff']
        phentsize = self.header['e_phentsize']
        phnum = self.header['e_phnum']

        if phoff == 0 or phnum == 0:
            return segments

        fmt_prefix = '<' if self.endian == 'little' else '>'

        if self.is_64bit:
            segment_fmt = f'{fmt_prefix}IIQQQQQQ'
        else:
            segment_fmt = f'{fmt_prefix}IIIIIIII'

        for i in range(phnum):
            try:
                offset = phoff + i * phentsize
                if offset + phentsize > len(self.data):
                    break

                segment_data = struct.unpack(segment_fmt, self.data[offset:offset + phentsize])

                segment = {
                    'index': i,
                    'p_type': segment_data[0],
                    'p_flags': segment_data[1] if self.is_64bit else segment_data[6],
                    'p_offset': segment_data[2] if self.is_64bit else segment_data[1],
                    'p_vaddr': segment_data[3] if self.is_64bit else segment_data[2],
                    'p_paddr': segment_data[4] if self.is_64bit else segment_data[3],
                    'p_filesz': segment_data[5] if self.is_64bit else segment_data[4],
                    'p_memsz': segment_data[6] if self.is_64bit else segment_data[5],
                    'p_align': segment_data[7] if self.is_64bit else segment_data[7]
                }

                segments.append(segment)

            except struct.error as e:
                logger.debug(f"Error parsing segment {i}: {e}")
                continue

        self.segments = segments
        return segments

    def find_symbols(self) -> List[Dict[str, Any]]:
        """Extract symbol table information.

        Returns:
            List of symbol information dictionaries

        """
        if not self.sections:
            self.analyze_sections()

        symbols = []

        for section in self.sections:
            # Symbol table sections (SHT_SYMTAB = 2, SHT_DYNSYM = 11)
            if section['sh_type'] not in (2, 11):
                continue

            try:
                self._parse_symbol_table(section, symbols)
            except Exception as e:
                logger.debug(f"Error parsing symbol table: {e}")
                continue

        self.symbols = symbols
        return symbols

    def _parse_symbol_table(self, section: Dict[str, Any], symbols: List[Dict[str, Any]]) -> None:
        """Parse a symbol table section.

        Args:
            section: Symbol table section information
            symbols: List to append symbol information to

        """
        if not self.data:
            return

        offset = section['sh_offset']
        size = section['sh_size']
        entsize = section['sh_entsize']

        if entsize == 0:
            entsize = 24 if self.is_64bit else 16

        num_symbols = size // entsize
        fmt_prefix = '<' if self.endian == 'little' else '>'

        if self.is_64bit:
            symbol_fmt = f'{fmt_prefix}IBBHQQ'
        else:
            symbol_fmt = f'{fmt_prefix}IIIBBH'

        for i in range(num_symbols):
            try:
                sym_offset = offset + i * entsize
                if sym_offset + entsize > len(self.data):
                    break

                symbol_data = struct.unpack(symbol_fmt, self.data[sym_offset:sym_offset + entsize])

                if self.is_64bit:
                    symbol = {
                        'st_name': symbol_data[0],
                        'st_info': symbol_data[1],
                        'st_other': symbol_data[2],
                        'st_shndx': symbol_data[3],
                        'st_value': symbol_data[4],
                        'st_size': symbol_data[5]
                    }
                else:
                    symbol = {
                        'st_name': symbol_data[0],
                        'st_value': symbol_data[1],
                        'st_size': symbol_data[2],
                        'st_info': symbol_data[3],
                        'st_other': symbol_data[4],
                        'st_shndx': symbol_data[5]
                    }

                symbols.append(symbol)

            except struct.error as e:
                logger.debug(f"Error parsing symbol {i}: {e}")
                continue

    def get_security_features(self) -> Dict[str, Any]:
        """Analyze security features and protections.

        Returns:
            Dictionary containing security feature analysis

        """
        features = {
            'nx_bit': False,
            'stack_canary': False,
            'pie': False,
            'relro': False,
            'fortify': False,
            'stripped': True
        }

        if not self.header:
            return features

        # Check for PIE (Position Independent Executable)
        features['pie'] = self.header['e_type'] == self.ET_DYN

        # Check for symbols (not stripped if symbol table exists)
        if self.symbols or any(s['sh_type'] == 2 for s in self.sections):
            features['stripped'] = False

        # Check for stack canary symbols
        symbol_names = self._get_symbol_names()
        canary_symbols = ['__stack_chk_fail', '__stack_chk_guard']
        features['stack_canary'] = any(name in symbol_names for name in canary_symbols)

        # Check for FORTIFY symbols
        fortify_symbols = ['__sprintf_chk', '__strcpy_chk', '__memcpy_chk']
        features['fortify'] = any(name in symbol_names for name in fortify_symbols)

        # Check program headers for NX bit and RELRO
        for segment in self.segments:
            # PT_GNU_STACK = 0x6474e551, PT_GNU_RELRO = 0x6474e552
            if segment['p_type'] == 0x6474e551:  # GNU_STACK
                features['nx_bit'] = (segment['p_flags'] & 1) == 0  # Not executable
            elif segment['p_type'] == 0x6474e552:  # GNU_RELRO
                features['relro'] = True

        return features

    def _get_symbol_names(self) -> List[str]:
        """Extract symbol names from string table.

        Returns:
            List of symbol names

        """
        names = []

        # Find string table sections
        string_tables = [s for s in self.sections if s['sh_type'] == 3]  # SHT_STRTAB = 3

        for strtab in string_tables:
            try:
                offset = strtab['sh_offset']
                size = strtab['sh_size']

                if offset + size > len(self.data):
                    continue

                strtab_data = self.data[offset:offset + size]

                # Extract null-terminated strings
                strings = strtab_data.split(b'\x00')
                names.extend([s.decode('utf-8', errors='ignore') for s in strings if s])

            except Exception as e:
                logger.debug(f"Error reading string table: {e}")
                continue

        return names

    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive ELF analysis.

        Returns:
            Complete analysis results

        """
        if not self.load_binary():
            return {'error': 'Failed to load binary'}

        analysis = {
            'file_path': str(self.file_path),
            'header': self.header,
            'architecture': self._get_architecture(),
            'sections': self.analyze_sections(),
            'segments': self.analyze_segments(),
            'symbols': self.find_symbols(),
            'security_features': self.get_security_features(),
            'file_size': len(self.data) if self.data else 0
        }

        return analysis

    def _get_architecture(self) -> str:
        """Get human-readable architecture string.

        Returns:
            Architecture description

        """
        if not self.header:
            return 'unknown'

        machine = self.header['e_machine']
        arch_map = {
            self.EM_386: 'x86',
            self.EM_X86_64: 'x86_64',
            self.EM_ARM: 'ARM',
            self.EM_AARCH64: 'AArch64'
        }

        arch = arch_map.get(machine, f'unknown_{machine}')
        bits = '64' if self.is_64bit else '32'
        endian = 'LE' if self.endian == 'little' else 'BE'

        return f'{arch}_{bits}_{endian}'


def analyze_elf_file(file_path: Union[str, Path]) -> Dict[str, Any]:
    """Convenience function to analyze an ELF file.

    Args:
        file_path: Path to ELF binary

    Returns:
        Analysis results dictionary

    """
    analyzer = ELFAnalyzer(file_path)
    return analyzer.analyze()


def is_elf_file(file_path: Union[str, Path]) -> bool:
    """Check if a file is an ELF binary.

    Args:
        file_path: Path to file to check

    Returns:
        True if file is ELF, False otherwise

    """
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            return magic == ELFAnalyzer.ELFMAG
    except Exception:
        return False


def extract_elf_strings(file_path: Union[str, Path], min_length: int = 4) -> List[str]:
    """Extract printable strings from ELF binary.

    Args:
        file_path: Path to ELF binary
        min_length: Minimum string length to extract

    Returns:
        List of extracted strings

    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        strings = []
        current_string = b''

        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += bytes([byte])
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string.decode('ascii'))
                current_string = b''

        # Don't forget the last string
        if len(current_string) >= min_length:
            strings.append(current_string.decode('ascii'))

        return strings

    except Exception as e:
        logger.error(f"Error extracting strings from {file_path}: {e}")
        return []
