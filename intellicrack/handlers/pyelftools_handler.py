"""PyElfTools handler for Intellicrack.

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
"""

from __future__ import annotations

import io
import struct
from typing import TYPE_CHECKING, Any, BinaryIO, Optional, Union

from intellicrack.utils.logger import logger


if TYPE_CHECKING:
    from collections.abc import Iterator

"""
PyElfTools Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for pyelftools imports.
When pyelftools is not available, it provides REAL, functional ELF parsing
implementations for essential operations used in Intellicrack.
"""

# PyElfTools availability detection and import handling
try:
    from elftools.common.exceptions import DWARFError, ELFError, ELFParseError

    # Try to import py3compat but handle if it doesn't exist
    try:
        from elftools.common.py3compat import bytes2str, str2bytes
    except ImportError:
        # Fallback for newer versions without py3compat
        def bytes2str(b: bytes | str) -> str:
            """Convert bytes to string.

            Args:
                b: Bytes or string to convert.

            Returns:
                String representation.

            """
            return b.decode("utf-8", errors="replace") if isinstance(b, bytes) else b

        def str2bytes(s: str | bytes) -> bytes:
            """Convert string to bytes.

            Args:
                s: String or bytes to convert.

            Returns:
                Bytes representation.

            """
            return s.encode("utf-8") if isinstance(s, str) else s

    from elftools.construct import Container, Struct

    # Try to import DWARF constants - they may have moved or changed
    try:
        from elftools.dwarf.constants import DW_TAG_compile_unit
    except ImportError:
        # Create fallback if not available
        DW_TAG_compile_unit = 0x11  # Standard DWARF value

    from elftools.dwarf.die import DIE
    from elftools.dwarf.dwarfinfo import DWARFInfo
    from elftools.elf.constants import E_FLAGS, P_FLAGS, SH_FLAGS, SHN_INDICES
    from elftools.elf.descriptions import describe_e_type, describe_p_type, describe_sh_type
    from elftools.elf.dynamic import Dynamic, DynamicSection, DynamicSegment
    from elftools.elf.elffile import ELFFile

    # Try to import enums - they may have changed structure
    try:
        from elftools.elf.enums import ENUM_D_TAG, ENUM_E_TYPE, ENUM_SH_TYPE
    except ImportError:
        # Create fallback enums if not available
        ENUM_D_TAG = None
        ENUM_E_TYPE = None
        ENUM_SH_TYPE = None

    from elftools.elf.relocation import Relocation, RelocationSection
    from elftools.elf.sections import NoteSection, Section, StringTableSection, Symbol, SymbolTableSection
    from elftools.elf.segments import InterpSegment, NoteSegment, Segment

    HAS_PYELFTOOLS: bool = True
    import elftools

    PYELFTOOLS_VERSION: str = getattr(elftools, "__version__", "unknown")

except ImportError as e:
    logger.error("PyElfTools not available, using fallback implementations: %s", e)
    HAS_PYELFTOOLS: bool = False
    PYELFTOOLS_VERSION: str | None = None

    # Production-ready fallback ELF parsing implementations

    # ELF constants
    class E_FLAGS:  # noqa: N801
        """ELF header flags."""

    class P_FLAGS:  # noqa: N801
        """Program header flags."""

        PF_X = 0x1  # Execute
        PF_W = 0x2  # Write
        PF_R = 0x4  # Read

    class SH_FLAGS:  # noqa: N801
        """Section header flags."""

        SHF_WRITE = 0x1
        SHF_ALLOC = 0x2
        SHF_EXECINSTR = 0x4
        SHF_MERGE = 0x10
        SHF_STRINGS = 0x20
        SHF_INFO_LINK = 0x40
        SHF_LINK_ORDER = 0x80
        SHF_OS_NONCONFORMING = 0x100
        SHF_GROUP = 0x200
        SHF_TLS = 0x400

    class SHN_INDICES:  # noqa: N801
        """Special section indices."""

        SHN_UNDEF = 0
        SHN_ABS = 0xFFF1
        SHN_COMMON = 0xFFF2
        SHN_XINDEX = 0xFFFF

    class ENUM_E_TYPE:  # noqa: N801
        """ELF file types."""

        ET_NONE = 0
        ET_REL = 1
        ET_EXEC = 2
        ET_DYN = 3
        ET_CORE = 4

    class ENUM_SH_TYPE:  # noqa: N801
        """Section types."""

        SHT_NULL = 0
        SHT_PROGBITS = 1
        SHT_SYMTAB = 2
        SHT_STRTAB = 3
        SHT_RELA = 4
        SHT_HASH = 5
        SHT_DYNAMIC = 6
        SHT_NOTE = 7
        SHT_NOBITS = 8
        SHT_REL = 9
        SHT_SHLIB = 10
        SHT_DYNSYM = 11

    class ENUM_D_TAG:  # noqa: N801
        """Dynamic section tags."""

        DT_NULL = 0
        DT_NEEDED = 1
        DT_PLTRELSZ = 2
        DT_PLTGOT = 3
        DT_HASH = 4
        DT_STRTAB = 5
        DT_SYMTAB = 6
        DT_RELA = 7
        DT_RELASZ = 8
        DT_RELAENT = 9
        DT_STRSZ = 10
        DT_SYMENT = 11
        DT_INIT = 12
        DT_FINI = 13
        DT_SONAME = 14
        DT_RPATH = 15
        DT_SYMBOLIC = 16
        DT_REL = 17
        DT_RELSZ = 18
        DT_RELENT = 19
        DT_PLTREL = 20
        DT_DEBUG = 21
        DT_TEXTREL = 22
        DT_JMPREL = 23

    # Exception classes
    class ELFError(Exception):
        """Base ELF error."""

    class ELFParseError(ELFError):
        """ELF parsing error."""

    class DWARFError(Exception):
        """DWARF error."""

    # Utility functions
    def bytes2str(data: bytes | str) -> str:
        """Convert bytes to string.

        Args:
            data: Bytes or string to convert.

        Returns:
            String representation.

        """
        return data.decode("latin-1") if isinstance(data, bytes) else data

    def str2bytes(data: str | bytes) -> bytes:
        """Convert string to bytes.

        Args:
            data: String or bytes to convert.

        Returns:
            Bytes representation.

        """
        return data.encode("latin-1") if isinstance(data, str) else data

    # Container class for construct compatibility
    class Container(dict):
        """Container for parsed structures."""

        def __init__(self, **kwargs: object) -> None:
            """Initialize container with keyword arguments as both dict entries and attributes.

            Args:
                **kwargs: Arbitrary keyword arguments to store as dict entries and object attributes.

            """
            super().__init__(**kwargs)
            self.__dict__.update(kwargs)

    class Struct:
        """Structure parser."""

        name: str
        fields: tuple[Any, ...]

        def __init__(self, name: str, *fields: tuple[Any, ...]) -> None:
            """Initialize structure parser with name and field definitions.

            Args:
                name: Name of the structure.
                *fields: Variable-length field definitions.

            """
            self.name = name
            self.fields = fields

    # ELF file parser
    class FallbackELFFile:
        """Functional ELF file parser implementation."""

        stream: BinaryIO
        little_endian: bool
        elfclass: int
        header: Container | None
        _section_headers: list[Container]
        _program_headers: list[Container]
        _sections: list[Any]
        _segments: list[Any]
        _string_table: bytes | None

        def __init__(self, stream: BinaryIO) -> None:
            """Initialize ELF file parser."""
            self.stream = stream
            self.little_endian = True
            self.elfclass = 64  # Default to 64-bit
            self.header = None
            self._section_headers = []
            self._program_headers = []
            self._sections = []
            self._segments = []
            self._string_table = None
            self._parse_elf_header()
            self._parse_program_headers()
            self._parse_section_headers()

        def _parse_elf_header(self) -> None:
            """Parse ELF header.

            Raises:
                ELFParseError: If the ELF file is invalid or malformed.

            """
            self.stream.seek(0)

            # Read ELF magic and class
            e_ident = self.stream.read(16)
            if len(e_ident) < 16:
                raise ELFParseError("Invalid ELF file: too short")

            if e_ident[:4] != b"\x7fELF":
                raise ELFParseError("Invalid ELF magic")

            # Parse EI_CLASS (32 or 64 bit)
            if e_ident[4] == 1:
                self.elfclass = 32
            elif e_ident[4] == 2:
                self.elfclass = 64
            else:
                raise ELFParseError(f"Invalid EI_CLASS: {e_ident[4]}")

            # Parse EI_DATA (endianness)
            if e_ident[5] == 1:
                self.little_endian = True
                endian = "<"
            elif e_ident[5] == 2:
                self.little_endian = False
                endian = ">"
            else:
                raise ELFParseError(f"Invalid EI_DATA: {e_ident[5]}")

            # Parse rest of header based on class
            if self.elfclass == 32:
                # 32-bit ELF header
                header_data = self.stream.read(36)  # e_ident already read
                if len(header_data) < 36:
                    raise ELFParseError("Incomplete ELF header")

                (
                    e_type,
                    e_machine,
                    e_version,
                    e_entry,
                    e_phoff,
                    e_shoff,
                    e_flags,
                    e_ehsize,
                    e_phentsize,
                    e_phnum,
                    e_shentsize,
                    e_shnum,
                    e_shstrndx,
                ) = struct.unpack(f"{endian}HHIIIIIHHHHHH", header_data)
            else:
                # 64-bit ELF header
                header_data = self.stream.read(48)  # e_ident already read
                if len(header_data) < 48:
                    raise ELFParseError("Incomplete ELF header")

                (
                    e_type,
                    e_machine,
                    e_version,
                    e_entry,
                    e_phoff,
                    e_shoff,
                    e_flags,
                    e_ehsize,
                    e_phentsize,
                    e_phnum,
                    e_shentsize,
                    e_shnum,
                    e_shstrndx,
                ) = struct.unpack(f"{endian}HHIQQQIHHHHHH", header_data)

            self.header = Container(
                e_ident=e_ident,
                e_type=e_type,
                e_machine=e_machine,
                e_version=e_version,
                e_entry=e_entry,
                e_phoff=e_phoff,
                e_shoff=e_shoff,
                e_flags=e_flags,
                e_ehsize=e_ehsize,
                e_phentsize=e_phentsize,
                e_phnum=e_phnum,
                e_shentsize=e_shentsize,
                e_shnum=e_shnum,
                e_shstrndx=e_shstrndx,
            )

        def _parse_program_headers(self) -> None:
            """Parse program headers.

            Raises:
                ELFParseError: If program headers cannot be parsed.

            """
            if not self.header or self.header.e_phoff == 0:
                return

            self.stream.seek(self.header.e_phoff)
            endian = "<" if self.little_endian else ">"

            for _i in range(self.header.e_phnum):
                if self.elfclass == 32:
                    # 32-bit program header
                    ph_data = self.stream.read(32)
                    if len(ph_data) < 32:
                        break

                    (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align) = struct.unpack(f"{endian}IIIIIIII", ph_data)
                else:
                    # 64-bit program header
                    ph_data = self.stream.read(56)
                    if len(ph_data) < 56:
                        break

                    (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align) = struct.unpack(f"{endian}IIQQQQQQ", ph_data)

                ph = Container(
                    p_type=p_type,
                    p_offset=p_offset,
                    p_vaddr=p_vaddr,
                    p_paddr=p_paddr,
                    p_filesz=p_filesz,
                    p_memsz=p_memsz,
                    p_flags=p_flags,
                    p_align=p_align,
                )
                self._program_headers.append(ph)

                # Create segment object
                segment = FallbackSegment(ph, self.stream)
                self._segments.append(segment)

        def _parse_section_headers(self) -> None:
            """Parse section headers.

            Raises:
                ELFParseError: If section headers cannot be parsed.

            """
            if not self.header or self.header.e_shoff == 0:
                return

            self.stream.seek(self.header.e_shoff)
            endian = "<" if self.little_endian else ">"

            for _i in range(self.header.e_shnum):
                if self.elfclass == 32:
                    # 32-bit section header
                    sh_data = self.stream.read(40)
                    if len(sh_data) < 40:
                        break

                    (
                        sh_name,
                        sh_type,
                        sh_flags,
                        sh_addr,
                        sh_offset,
                        sh_size,
                        sh_link,
                        sh_info,
                        sh_addralign,
                        sh_entsize,
                    ) = struct.unpack(
                        f"{endian}IIIIIIIIII",
                        sh_data,
                    )
                else:
                    # 64-bit section header
                    sh_data = self.stream.read(64)
                    if len(sh_data) < 64:
                        break

                    (
                        sh_name,
                        sh_type,
                        sh_flags,
                        sh_addr,
                        sh_offset,
                        sh_size,
                        sh_link,
                        sh_info,
                        sh_addralign,
                        sh_entsize,
                    ) = struct.unpack(
                        f"{endian}IIQQQQIIQQ",
                        sh_data,
                    )

                sh = Container(
                    sh_name=sh_name,
                    sh_type=sh_type,
                    sh_flags=sh_flags,
                    sh_addr=sh_addr,
                    sh_offset=sh_offset,
                    sh_size=sh_size,
                    sh_link=sh_link,
                    sh_info=sh_info,
                    sh_addralign=sh_addralign,
                    sh_entsize=sh_entsize,
                )
                self._section_headers.append(sh)

            # Load string table for section names
            if self.header.e_shstrndx < len(self._section_headers):
                strtab_sh = self._section_headers[self.header.e_shstrndx]
                self.stream.seek(strtab_sh.sh_offset)
                self._string_table = self.stream.read(strtab_sh.sh_size)

            # Create section objects
            for i, sh in enumerate(self._section_headers):
                name = self._get_string(sh.sh_name) if self._string_table else f".section{i}"

                if sh.sh_type == ENUM_SH_TYPE.SHT_STRTAB:
                    section = FallbackStringTableSection(sh, name, self.stream)
                elif sh.sh_type in (ENUM_SH_TYPE.SHT_SYMTAB, ENUM_SH_TYPE.SHT_DYNSYM):
                    section = FallbackSymbolTableSection(sh, name, self.stream, self)
                elif sh.sh_type in (ENUM_SH_TYPE.SHT_REL, ENUM_SH_TYPE.SHT_RELA):
                    section = FallbackRelocationSection(sh, name, self.stream, self)
                elif sh.sh_type == ENUM_SH_TYPE.SHT_DYNAMIC:
                    section = FallbackDynamicSection(sh, name, self.stream, self)
                elif sh.sh_type == ENUM_SH_TYPE.SHT_NOTE:
                    section = FallbackNoteSection(sh, name, self.stream)
                else:
                    section = FallbackSection(sh, name, self.stream)

                self._sections.append(section)

        def _get_string(self, offset: int) -> str:
            """Get string from string table.

            Args:
                offset: Byte offset in the string table.

            Returns:
                Null-terminated string at the specified offset.

            """
            if not self._string_table or offset >= len(self._string_table):
                return ""

            end = self._string_table.find(b"\x00", offset)
            if end == -1:
                end = len(self._string_table)

            return self._string_table[offset:end].decode("latin-1", errors="ignore")

        def num_sections(self) -> int:
            """Get number of sections.

            Returns:
                Total number of sections in the ELF file.

            """
            return len(self._sections)

        def num_segments(self) -> int:
            """Get number of segments.

            Returns:
                Total number of segments in the ELF file.

            """
            return len(self._segments)

        def get_section(self, n: int) -> FallbackSection | None:
            """Get section by index.

            Args:
                n: Section index.

            Returns:
                Section object at the specified index, or None if not found.

            """
            return self._sections[n] if 0 <= n < len(self._sections) else None

        def get_section_by_name(self, name: str) -> FallbackSection | None:
            """Get section by name.

            Args:
                name: Section name to search for.

            Returns:
                Section object with the specified name, or None if not found.

            """
            return next((section for section in self._sections if section.name == name), None)

        def get_segment(self, n: int) -> FallbackSegment | None:
            """Get segment by index.

            Args:
                n: Segment index.

            Returns:
                Segment object at the specified index, or None if not found.

            """
            return self._segments[n] if 0 <= n < len(self._segments) else None

        def iter_sections(self) -> Iterator[Any]:
            """Iterate over sections.

            Returns:
                Iterator yielding all sections in the file.

            """
            return iter(self._sections)

        def iter_segments(self) -> Iterator[Any]:
            """Iterate over segments.

            Returns:
                Iterator yielding all segments in the file.

            """
            return iter(self._segments)

        def has_dwarf_info(self) -> bool:
            """Check if file has DWARF debug info.

            Returns:
                True if the file contains DWARF debug sections, False otherwise.

            """
            return any(section.name.startswith(".debug_") for section in self._sections)

        def get_dwarf_info(self) -> FallbackDWARFInfo | None:
            """Get DWARF info (basic fallback).

            Returns:
                FallbackDWARFInfo object if debug info is present, None otherwise.

            """
            return FallbackDWARFInfo(self) if self.has_dwarf_info() else None

        def get_machine_arch(self) -> str:
            """Get machine architecture.

            Returns:
                Human-readable machine architecture string.

            """
            if not self.header:
                return "unknown"

            arch_map = {
                0x03: "x86",
                0x3E: "x64",
                0x28: "ARM",
                0xB7: "AArch64",
                0x08: "MIPS",
                0x14: "PowerPC",
                0x02: "SPARC",
            }
            return arch_map.get(self.header.e_machine, f"Unknown({self.header.e_machine})")

    class FallbackSection:
        """Functional ELF section implementation."""

        header: Container
        name: str
        stream: BinaryIO
        _data: bytes | None

        def __init__(self, header: Container, name: str, stream: BinaryIO) -> None:
            """Initialize section."""
            self.header = header
            self.name = name
            self.stream = stream
            self._data = None

        def data(self) -> bytes:
            """Get section data.

            Returns:
                Raw binary data from the section.

            """
            if self._data is None and self.header.sh_type != ENUM_SH_TYPE.SHT_NOBITS:
                self.stream.seek(self.header.sh_offset)
                self._data = self.stream.read(self.header.sh_size)
            return self._data or b""

        def is_null(self) -> bool:
            """Check if section is null.

            Returns:
                True if section type is SHT_NULL, False otherwise.

            """
            return self.header.sh_type == ENUM_SH_TYPE.SHT_NULL

        @property
        def data_size(self) -> int:
            """Get data size.

            Returns:
                Size of the section data in bytes.

            """
            return self.header.sh_size

        @property
        def data_alignment(self) -> int:
            """Get data alignment.

            Returns:
                Alignment requirement for the section in bytes.

            """
            return self.header.sh_addralign

    class FallbackStringTableSection(FallbackSection):
        """String table section."""

        def get_string(self, offset: int) -> str:
            """Get string at offset.

            Args:
                offset: Byte offset within the string table.

            Returns:
                String at the specified offset.

            """
            data = self.data()
            if offset >= len(data):
                return ""

            end = data.find(b"\x00", offset)
            if end == -1:
                end = len(data)

            return data[offset:end].decode("latin-1", errors="ignore")

    class FallbackSymbol:
        """Symbol representation."""

        st_name: int
        st_value: int
        st_size: int
        st_info: int
        st_other: int
        st_shndx: int
        name: str
        st_bind: int
        st_type: int

        def __init__(
            self,
            st_name: int,
            st_value: int,
            st_size: int,
            st_info: int,
            st_other: int,
            st_shndx: int,
            name: str = "",
        ) -> None:
            """Initialize symbol."""
            self.st_name = st_name
            self.st_value = st_value
            self.st_size = st_size
            self.st_info = st_info
            self.st_other = st_other
            self.st_shndx = st_shndx
            self.name = name

            # Parse symbol type and binding
            self.st_bind = (st_info >> 4) & 0x0F
            self.st_type = st_info & 0x0F

        @property
        def entry(self) -> Container:
            """Get symbol entry."""
            return Container(
                st_name=self.st_name,
                st_value=self.st_value,
                st_size=self.st_size,
                st_info=self.st_info,
                st_other=self.st_other,
                st_shndx=self.st_shndx,
            )

    class FallbackSymbolTableSection(FallbackSection):
        """Symbol table section."""

        elffile: FallbackELFFile
        _symbols: list[FallbackSymbol]

        def __init__(self, header: Container, name: str, stream: BinaryIO, elffile: FallbackELFFile) -> None:
            """Initialize symbol table."""
            super().__init__(header, name, stream)
            self.elffile = elffile
            self._symbols = []
            self._parse_symbols()

        def _parse_symbols(self) -> None:
            """Parse symbol table.

            Raises:
                struct.error: If symbol table cannot be parsed.

            """
            data = self.data()
            if not data:
                return

            # Get string table for symbol names
            strtab = None
            if self.header.sh_link < len(self.elffile._sections):
                strtab = self.elffile._sections[self.header.sh_link]

            endian = "<" if self.elffile.little_endian else ">"

            if self.elffile.elfclass == 32:
                # 32-bit symbol entry
                entry_size = 16
                entry_format = f"{endian}IIIBBH"
            else:
                # 64-bit symbol entry
                entry_size = 24
                entry_format = f"{endian}IBBHQQ"

            offset = 0
            while offset + entry_size <= len(data):
                if self.elffile.elfclass == 32:
                    (st_name, st_value, st_size, st_info, st_other, st_shndx) = struct.unpack(
                        entry_format,
                        data[offset : offset + entry_size],
                    )
                else:
                    (st_name, st_info, st_other, st_shndx, st_value, st_size) = struct.unpack(
                        entry_format,
                        data[offset : offset + entry_size],
                    )

                # Get symbol name
                name = ""
                if strtab and isinstance(strtab, FallbackStringTableSection):
                    name = strtab.get_string(st_name)

                symbol = FallbackSymbol(st_name, st_value, st_size, st_info, st_other, st_shndx, name)
                self._symbols.append(symbol)
                offset += entry_size

        def get_symbol(self, index: int) -> FallbackSymbol | None:
            """Get symbol by index.

            Args:
                index: Symbol index.

            Returns:
                Symbol object at the specified index, or None if not found.

            """
            return self._symbols[index] if 0 <= index < len(self._symbols) else None

        def num_symbols(self) -> int:
            """Get number of symbols.

            Returns:
                Total number of symbols in the symbol table.

            """
            return len(self._symbols)

        def iter_symbols(self) -> Iterator[FallbackSymbol]:
            """Iterate over symbols.

            Returns:
                Iterator yielding all symbols in the table.

            """
            return iter(self._symbols)

    class FallbackRelocation:
        """Relocation entry."""

        r_offset: int
        r_info: int
        r_addend: int
        r_sym: int
        r_type: int

        def __init__(self, r_offset: int, r_info: int, r_addend: int = 0) -> None:
            """Initialize relocation."""
            self.r_offset = r_offset
            self.r_info = r_info
            self.r_addend = r_addend

            # Parse symbol and type
            if self.r_info:
                self.r_sym = r_info >> 32 if r_info > 0xFFFFFFFF else r_info >> 8
                self.r_type = r_info & 0xFFFFFFFF if r_info > 0xFFFFFFFF else r_info & 0xFF
            else:
                self.r_sym = 0
                self.r_type = 0

        @property
        def entry(self) -> Container:
            """Get relocation entry."""
            return Container(r_offset=self.r_offset, r_info=self.r_info, r_addend=self.r_addend)

    class FallbackRelocationSection(FallbackSection):
        """Relocation section."""

        elffile: FallbackELFFile
        _relocations: list[FallbackRelocation]

        def __init__(self, header: Container, name: str, stream: BinaryIO, elffile: FallbackELFFile) -> None:
            """Initialize relocation section."""
            super().__init__(header, name, stream)
            self.elffile = elffile
            self._relocations = []
            self._parse_relocations()

        def _parse_relocations(self) -> None:
            """Parse relocations.

            Raises:
                struct.error: If relocations cannot be parsed.

            """
            data = self.data()
            if not data:
                return

            endian = "<" if self.elffile.little_endian else ">"
            is_rela = self.header.sh_type == ENUM_SH_TYPE.SHT_RELA

            if self.elffile.elfclass == 32:
                # 32-bit relocation entry
                entry_size = 12 if is_rela else 8
                entry_format = f"{endian}II" + ("i" if is_rela else "")
            else:
                # 64-bit relocation entry
                entry_size = 24 if is_rela else 16
                entry_format = f"{endian}QQ" + ("q" if is_rela else "")

            offset = 0
            while offset + entry_size <= len(data):
                if is_rela:
                    r_offset, r_info, r_addend = struct.unpack(entry_format, data[offset : offset + entry_size])
                else:
                    r_offset, r_info = struct.unpack(entry_format, data[offset : offset + entry_size])
                    r_addend = 0

                reloc = FallbackRelocation(r_offset, r_info, r_addend)
                self._relocations.append(reloc)
                offset += entry_size

        def num_relocations(self) -> int:
            """Get number of relocations.

            Returns:
                Total number of relocations in the section.

            """
            return len(self._relocations)

        def get_relocation(self, index: int) -> FallbackRelocation | None:
            """Get relocation by index.

            Args:
                index: Relocation index.

            Returns:
                Relocation object at the specified index, or None if not found.

            """
            if 0 <= index < len(self._relocations):
                return self._relocations[index]
            return None

        def iter_relocations(self) -> Iterator[FallbackRelocation]:
            """Iterate over relocations.

            Returns:
                Iterator yielding all relocations in the section.

            """
            return iter(self._relocations)

    class FallbackDynamic:
        """Dynamic entry."""

        d_tag: int
        d_val: int

        def __init__(self, d_tag: int, d_val: int) -> None:
            """Initialize dynamic entry."""
            self.d_tag = d_tag
            self.d_val = d_val

        @property
        def entry(self) -> Container:
            """Get dynamic entry."""
            return Container(d_tag=self.d_tag, d_val=self.d_val)

    class FallbackDynamicSection(FallbackSection):
        """Dynamic section."""

        elffile: FallbackELFFile
        _dynamics: list[FallbackDynamic]

        def __init__(self, header: Container, name: str, stream: BinaryIO, elffile: FallbackELFFile) -> None:
            """Initialize dynamic section."""
            super().__init__(header, name, stream)
            self.elffile = elffile
            self._dynamics = []
            self._parse_dynamics()

        def _parse_dynamics(self) -> None:
            """Parse dynamic entries.

            Raises:
                struct.error: If dynamic entries cannot be parsed.

            """
            data = self.data()
            if not data:
                return

            endian = "<" if self.elffile.little_endian else ">"

            if self.elffile.elfclass == 32:
                # 32-bit dynamic entry
                entry_size = 8
                entry_format = f"{endian}II"
            else:
                # 64-bit dynamic entry
                entry_size = 16
                entry_format = f"{endian}QQ"

            offset = 0
            while offset + entry_size <= len(data):
                d_tag, d_val = struct.unpack(entry_format, data[offset : offset + entry_size])

                if d_tag == ENUM_D_TAG.DT_NULL:
                    break

                dyn = FallbackDynamic(d_tag, d_val)
                self._dynamics.append(dyn)
                offset += entry_size

        def iter_tags(self) -> Iterator[FallbackDynamic]:
            """Iterate over dynamic tags.

            Returns:
                Iterator yielding all dynamic entries.

            """
            return iter(self._dynamics)

        def get_tag(self, tag: int) -> FallbackDynamic | None:
            """Get dynamic entry by tag.

            Args:
                tag: Dynamic tag value to search for.

            Returns:
                Dynamic entry matching the tag, or None if not found.

            """
            return next((dyn for dyn in self._dynamics if dyn.d_tag == tag), None)

    class FallbackNoteSection(FallbackSection):
        """Note section."""

        def iter_notes(self) -> Iterator[Container]:
            """Iterate over notes in the note section.

            Returns:
                Iterator yielding Container objects for each note.

            """
            data = self.data()
            offset = 0

            while offset < len(data) and not offset + 12 > len(data):
                n_namesz, n_descsz, n_type = struct.unpack("<III", data[offset : offset + 12])
                offset += 12

                # Read name
                if n_namesz:
                    name = data[offset : offset + n_namesz].rstrip(b"\x00")
                    offset += (n_namesz + 3) & ~3  # Align to 4 bytes
                else:
                    name = b""

                # Read descriptor
                if n_descsz:
                    desc = data[offset : offset + n_descsz]
                    offset += (n_descsz + 3) & ~3  # Align to 4 bytes
                else:
                    desc = b""

                yield Container(n_type=n_type, n_name=name, n_desc=desc)

    class FallbackSegment:
        """Functional ELF segment implementation."""

        header: Container
        stream: BinaryIO
        _data: bytes | None

        def __init__(self, header: Container, stream: BinaryIO) -> None:
            """Initialize segment."""
            self.header = header
            self.stream = stream
            self._data = None

        def data(self) -> bytes:
            """Get segment data.

            Returns:
                Raw binary data from the segment.

            """
            if self._data is None and self.header.p_filesz > 0:
                self.stream.seek(self.header.p_offset)
                self._data = self.stream.read(self.header.p_filesz)
            return self._data or b""

        @property
        def p_type(self) -> int:
            """Get segment type.

            Returns:
                Segment type value.

            """
            return self.header.p_type

        @property
        def p_flags(self) -> int:
            """Get segment flags.

            Returns:
                Segment flags value.

            """
            return self.header.p_flags

        @property
        def p_offset(self) -> int:
            """Get file offset.

            Returns:
                Offset in file where segment data begins.

            """
            return self.header.p_offset

        @property
        def p_vaddr(self) -> int:
            """Get virtual address.

            Returns:
                Virtual address where segment should be loaded.

            """
            return self.header.p_vaddr

        @property
        def p_paddr(self) -> int:
            """Get physical address.

            Returns:
                Physical address for segment loading.

            """
            return self.header.p_paddr

        @property
        def p_filesz(self) -> int:
            """Get file size.

            Returns:
                Size of segment data in file.

            """
            return self.header.p_filesz

        @property
        def p_memsz(self) -> int:
            """Get memory size.

            Returns:
                Size of segment in memory.

            """
            return self.header.p_memsz

        @property
        def p_align(self) -> int:
            """Get alignment.

            Returns:
                Alignment requirement for the segment.

            """
            return self.header.p_align

    class FallbackInterpSegment(FallbackSegment):
        """Interpreter segment."""

        def get_interp_name(self) -> str:
            """Get interpreter name.

            Returns:
                Path to the program interpreter (e.g., /lib64/ld-linux-x86-64.so.2).

            """
            if data := self.data():
                return data.rstrip(b"\x00").decode("latin-1", errors="ignore")
            return ""

    class FallbackNoteSegment(FallbackSegment):
        """Note segment."""

        def iter_notes(self) -> Iterator[Container]:
            """Iterate over notes in the note segment.

            Returns:
                Iterator yielding Container objects for each note.

            """
            data = self.data()
            offset = 0

            while offset < len(data) and not offset + 12 > len(data):
                n_namesz, n_descsz, n_type = struct.unpack("<III", data[offset : offset + 12])
                offset += 12

                # Read name
                if n_namesz:
                    name = data[offset : offset + n_namesz].rstrip(b"\x00")
                    offset += (n_namesz + 3) & ~3  # Align to 4 bytes
                else:
                    name = b""

                # Read descriptor
                if n_descsz:
                    desc = data[offset : offset + n_descsz]
                    offset += (n_descsz + 3) & ~3  # Align to 4 bytes
                else:
                    desc = b""

                yield Container(n_type=n_type, n_name=name, n_desc=desc)

    class FallbackDWARFInfo:
        """Basic DWARF info fallback."""

        elffile: FallbackELFFile

        def __init__(self, elffile: FallbackELFFile) -> None:
            """Initialize DWARF info.

            Args:
                elffile: ELF file object to associate with this DWARF info.

            """
            self.elffile = elffile

        def iter_CUs(self) -> Iterator[Any]:
            """Iterate over compilation units (empty for fallback).

            Returns:
                Empty iterator as fallback does not support DWARF parsing.

            """
            return iter([])

        def get_DIE_from_refaddr(self, refaddr: int) -> None:
            """Get DIE from reference address.

            Args:
                refaddr: Reference address (unused in fallback).

            Returns:
                None as fallback does not support DWARF parsing.

            """
            return

    class FallbackDIE:
        """Debug Information Entry."""

        tag: int
        attributes: dict[str, Any]

        def __init__(self, tag: int, attributes: dict[str, Any] | None = None) -> None:
            """Initialize DIE.

            Args:
                tag: DIE tag value.
                attributes: Optional dictionary of DIE attributes.

            """
            self.tag = tag
            self.attributes = attributes or {}

        def get_parent(self) -> None:
            """Get parent DIE.

            Returns:
                None as fallback does not support parent DIE traversal.

            """
            return

        def iter_children(self) -> Iterator[Any]:
            """Iterate over children.

            Returns:
                Empty iterator as fallback does not support child DIE traversal.

            """
            return iter([])

    def describe_e_type(e_type: int) -> str:
        """Describe ELF file type.

        Args:
            e_type: ELF file type value.

        Returns:
            Human-readable description of the ELF file type.

        """
        types = {
            ENUM_E_TYPE.ET_NONE: "NONE (No file type)",
            ENUM_E_TYPE.ET_REL: "REL (Relocatable file)",
            ENUM_E_TYPE.ET_EXEC: "EXEC (Executable file)",
            ENUM_E_TYPE.ET_DYN: "DYN (Shared object file)",
            ENUM_E_TYPE.ET_CORE: "CORE (Core file)",
        }
        return types.get(e_type, f"Unknown type {e_type}")

    def describe_p_type(p_type: int) -> str:
        """Describe program header type.

        Args:
            p_type: Program header type value.

        Returns:
            Human-readable description of the program header type.

        """
        types: dict[int, str] = {
            0: "PT_NULL",
            1: "PT_LOAD",
            2: "PT_DYNAMIC",
            3: "PT_INTERP",
            4: "PT_NOTE",
            5: "PT_SHLIB",
            6: "PT_PHDR",
            7: "PT_TLS",
        }
        return types.get(p_type, f"Unknown type {p_type}")

    def describe_sh_type(sh_type: int) -> str:
        """Describe section header type.

        Args:
            sh_type: Section header type value.

        Returns:
            Human-readable description of the section header type.

        """
        types = {
            ENUM_SH_TYPE.SHT_NULL: "NULL",
            ENUM_SH_TYPE.SHT_PROGBITS: "PROGBITS",
            ENUM_SH_TYPE.SHT_SYMTAB: "SYMTAB",
            ENUM_SH_TYPE.SHT_STRTAB: "STRTAB",
            ENUM_SH_TYPE.SHT_RELA: "RELA",
            ENUM_SH_TYPE.SHT_HASH: "HASH",
            ENUM_SH_TYPE.SHT_DYNAMIC: "DYNAMIC",
            ENUM_SH_TYPE.SHT_NOTE: "NOTE",
            ENUM_SH_TYPE.SHT_NOBITS: "NOBITS",
            ENUM_SH_TYPE.SHT_REL: "REL",
            ENUM_SH_TYPE.SHT_SHLIB: "SHLIB",
            ENUM_SH_TYPE.SHT_DYNSYM: "DYNSYM",
        }
        return types.get(sh_type, f"Unknown type {sh_type}")

    # DWARF constants
    DW_TAG_compile_unit = 0x11

    # Assign classes
    ELFFile = FallbackELFFile
    Section = FallbackSection
    StringTableSection = FallbackStringTableSection
    SymbolTableSection = FallbackSymbolTableSection
    Symbol = FallbackSymbol
    RelocationSection = FallbackRelocationSection
    Relocation = FallbackRelocation
    DynamicSection = FallbackDynamicSection
    Dynamic = FallbackDynamic
    NoteSection = FallbackNoteSection
    Segment = FallbackSegment
    InterpSegment = FallbackInterpSegment
    NoteSegment = FallbackNoteSegment
    DynamicSegment = FallbackSegment  # Alias
    DWARFInfo = FallbackDWARFInfo
    DIE = FallbackDIE

    # Create module references for compatibility
    class FallbackElftools:
        """Fallback elftools module."""

    elftools = FallbackElftools()
    elffile = ELFFile  # Alias for compatibility

# Ensure exports are available at module level
elftools: Any
elffile: type[ELFFile]

if not HAS_PYELFTOOLS:
    elftools = elftools if "elftools" in locals() else None
elffile = ELFFile
# Export all pyelftools objects and availability flag
__all__ = [
    "Container",
    "DIE",
    "DWARFError",
    "DWARFInfo",
    "DW_TAG_compile_unit",
    "Dynamic",
    "DynamicSection",
    "DynamicSegment",
    "ELFError",
    "ELFFile",
    "ELFParseError",
    "ENUM_D_TAG",
    "ENUM_E_TYPE",
    "ENUM_SH_TYPE",
    "E_FLAGS",
    "HAS_PYELFTOOLS",
    "InterpSegment",
    "NoteSection",
    "NoteSegment",
    "PYELFTOOLS_VERSION",
    "P_FLAGS",
    "Relocation",
    "RelocationSection",
    "SHN_INDICES",
    "SH_FLAGS",
    "Section",
    "Segment",
    "StringTableSection",
    "Struct",
    "Symbol",
    "SymbolTableSection",
    "bytes2str",
    "describe_e_type",
    "describe_p_type",
    "describe_sh_type",
    "elffile",
    "elftools",
    "str2bytes",
]
