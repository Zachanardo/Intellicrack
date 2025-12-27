"""Fallback implementations for pyelftools.

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

This module provides production-ready ELF parsing implementations
when pyelftools is not available. All classes implement the same
interface as the real pyelftools library.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Any, BinaryIO


if TYPE_CHECKING:
    from collections.abc import Iterator


EI_NIDENT: int = 16
ELF32_EHDR_SIZE: int = 36
ELF64_EHDR_SIZE: int = 48
ELF32_PHDR_SIZE: int = 32
ELF64_PHDR_SIZE: int = 56
ELF32_SHDR_SIZE: int = 40
ELF64_SHDR_SIZE: int = 64
ELF32_SYM_SIZE: int = 16
ELF64_SYM_SIZE: int = 24
ELF32_DYN_SIZE: int = 8
ELF64_DYN_SIZE: int = 16
ELF32_REL_SIZE: int = 8
ELF32_RELA_SIZE: int = 12
ELF64_REL_SIZE: int = 16
ELF64_RELA_SIZE: int = 24
NOTE_HDR_SIZE: int = 12
ELFCLASS32: int = 32
ELFCLASS64: int = 64
RINFO_32BIT_THRESHOLD: int = 0xFFFFFFFF
EI_CLASS_32: int = 1
EI_CLASS_64: int = 2
EI_DATA_LSB: int = 1
EI_DATA_MSB: int = 2


class E_FLAGS:  # noqa: N801
    """ELF header flags."""


class P_FLAGS:  # noqa: N801
    """Program header flags."""

    PF_X: int = 0x1
    PF_W: int = 0x2
    PF_R: int = 0x4


class SH_FLAGS:  # noqa: N801
    """Section header flags."""

    SHF_WRITE: int = 0x1
    SHF_ALLOC: int = 0x2
    SHF_EXECINSTR: int = 0x4
    SHF_MERGE: int = 0x10
    SHF_STRINGS: int = 0x20
    SHF_INFO_LINK: int = 0x40
    SHF_LINK_ORDER: int = 0x80
    SHF_OS_NONCONFORMING: int = 0x100
    SHF_GROUP: int = 0x200
    SHF_TLS: int = 0x400


class SHN_INDICES:  # noqa: N801
    """Special section indices."""

    SHN_UNDEF: int = 0
    SHN_ABS: int = 0xFFF1
    SHN_COMMON: int = 0xFFF2
    SHN_XINDEX: int = 0xFFFF


class ENUM_E_TYPE:  # noqa: N801
    """ELF file types."""

    ET_NONE: int = 0
    ET_REL: int = 1
    ET_EXEC: int = 2
    ET_DYN: int = 3
    ET_CORE: int = 4


class ENUM_SH_TYPE:  # noqa: N801
    """Section types."""

    SHT_NULL: int = 0
    SHT_PROGBITS: int = 1
    SHT_SYMTAB: int = 2
    SHT_STRTAB: int = 3
    SHT_RELA: int = 4
    SHT_HASH: int = 5
    SHT_DYNAMIC: int = 6
    SHT_NOTE: int = 7
    SHT_NOBITS: int = 8
    SHT_REL: int = 9
    SHT_SHLIB: int = 10
    SHT_DYNSYM: int = 11


class ENUM_D_TAG:  # noqa: N801
    """Dynamic section tags."""

    DT_NULL: int = 0
    DT_NEEDED: int = 1
    DT_PLTRELSZ: int = 2
    DT_PLTGOT: int = 3
    DT_HASH: int = 4
    DT_STRTAB: int = 5
    DT_SYMTAB: int = 6
    DT_RELA: int = 7
    DT_RELASZ: int = 8
    DT_RELAENT: int = 9
    DT_STRSZ: int = 10
    DT_SYMENT: int = 11
    DT_INIT: int = 12
    DT_FINI: int = 13
    DT_SONAME: int = 14
    DT_RPATH: int = 15
    DT_SYMBOLIC: int = 16
    DT_REL: int = 17
    DT_RELSZ: int = 18
    DT_RELENT: int = 19
    DT_PLTREL: int = 20
    DT_DEBUG: int = 21
    DT_TEXTREL: int = 22
    DT_JMPREL: int = 23


class ELFError(Exception):
    """Base ELF error."""


class ELFParseError(ELFError):
    """ELF parsing error."""


class DWARFError(Exception):
    """DWARF error."""


DW_TAG_compile_unit: int = 0x11


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


class Container(dict[str, Any]):
    """Container for parsed structures with dynamic attribute access."""

    def __init__(self, **kwargs: object) -> None:
        """Initialize container with keyword arguments as both dict entries and attributes.

        Args:
            **kwargs: Arbitrary keyword arguments to store as dict entries and object attributes.

        """
        super().__init__(**kwargs)
        for key, value in kwargs.items():
            super().__setattr__(key, value)

    def __getattr__(self, name: str) -> Any:
        """Get attribute from container, falling back to dict lookup.

        Args:
            name: Attribute name to retrieve.

        Returns:
            The value associated with the attribute name.

        Raises:
            AttributeError: If the attribute is not found.

        """
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name) from None

    def __setattr__(self, name: str, value: Any) -> None:
        """Set attribute on container, storing in both dict and object.

        Args:
            name: Attribute name to set.
            value: Value to associate with the attribute.

        """
        self[name] = value
        super().__setattr__(name, value)


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


class Section:
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
        return bool(self.header.sh_type == ENUM_SH_TYPE.SHT_NULL)

    @property
    def data_size(self) -> int:
        """Get data size.

        Returns:
            Size of the section data in bytes.

        """
        return int(self.header.sh_size)

    @property
    def data_alignment(self) -> int:
        """Get data alignment.

        Returns:
            Alignment requirement for the section in bytes.

        """
        return int(self.header.sh_addralign)


class StringTableSection(Section):
    """String table section."""

    def get_string(self, offset: int) -> str:
        """Get string at offset.

        Args:
            offset: Byte offset within the string table.

        Returns:
            String at the specified offset.

        """
        section_data = self.data()
        if offset >= len(section_data):
            return ""

        end = section_data.find(b"\x00", offset)
        if end == -1:
            end = len(section_data)

        return section_data[offset:end].decode("latin-1", errors="ignore")


class Symbol:
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


class SymbolTableSection(Section):
    """Symbol table section."""

    elffile: ELFFile
    _symbols: list[Symbol]

    def __init__(
        self, header: Container, name: str, stream: BinaryIO, elffile: ELFFile
    ) -> None:
        """Initialize symbol table."""
        super().__init__(header, name, stream)
        self.elffile = elffile
        self._symbols = []
        self._parse_symbols()

    def _parse_symbols(self) -> None:
        """Parse symbol table."""
        section_data = self.data()
        if not section_data:
            return

        strtab: StringTableSection | None = None
        if self.header.sh_link < len(self.elffile._sections):
            section = self.elffile._sections[self.header.sh_link]
            if isinstance(section, StringTableSection):
                strtab = section

        endian = "<" if self.elffile.little_endian else ">"

        if self.elffile.elfclass == ELFCLASS32:
            entry_size = ELF32_SYM_SIZE
            entry_format = f"{endian}IIIBBH"
        else:
            entry_size = ELF64_SYM_SIZE
            entry_format = f"{endian}IBBHQQ"

        offset = 0
        while offset + entry_size <= len(section_data):
            if self.elffile.elfclass == ELFCLASS32:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack(
                    entry_format,
                    section_data[offset : offset + entry_size],
                )
            else:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack(
                    entry_format,
                    section_data[offset : offset + entry_size],
                )

            symbol_name = ""
            if strtab is not None:
                symbol_name = strtab.get_string(st_name)

            symbol = Symbol(st_name, st_value, st_size, st_info, st_other, st_shndx, symbol_name)
            self._symbols.append(symbol)
            offset += entry_size

    def get_symbol(self, index: int) -> Symbol | None:
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

    def iter_symbols(self) -> Iterator[Symbol]:
        """Iterate over symbols.

        Returns:
            Iterator yielding all symbols in the table.

        """
        return iter(self._symbols)


class Relocation:
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

        if self.r_info:
            self.r_sym = r_info >> 32 if r_info > RINFO_32BIT_THRESHOLD else r_info >> 8
            self.r_type = r_info & RINFO_32BIT_THRESHOLD if r_info > RINFO_32BIT_THRESHOLD else r_info & 0xFF
        else:
            self.r_sym = 0
            self.r_type = 0

    @property
    def entry(self) -> Container:
        """Get relocation entry."""
        return Container(r_offset=self.r_offset, r_info=self.r_info, r_addend=self.r_addend)


class RelocationSection(Section):
    """Relocation section."""

    elffile: ELFFile
    _relocations: list[Relocation]

    def __init__(
        self, header: Container, name: str, stream: BinaryIO, elffile: ELFFile
    ) -> None:
        """Initialize relocation section."""
        super().__init__(header, name, stream)
        self.elffile = elffile
        self._relocations = []
        self._parse_relocations()

    def _parse_relocations(self) -> None:
        """Parse relocations."""
        section_data = self.data()
        if not section_data:
            return

        endian = "<" if self.elffile.little_endian else ">"
        is_rela = self.header.sh_type == ENUM_SH_TYPE.SHT_RELA

        if self.elffile.elfclass == ELFCLASS32:
            entry_size = ELF32_RELA_SIZE if is_rela else ELF32_REL_SIZE
            entry_format = f"{endian}II" + ("i" if is_rela else "")
        else:
            entry_size = ELF64_RELA_SIZE if is_rela else ELF64_REL_SIZE
            entry_format = f"{endian}QQ" + ("q" if is_rela else "")

        offset = 0
        while offset + entry_size <= len(section_data):
            if is_rela:
                r_offset, r_info, r_addend = struct.unpack(
                    entry_format, section_data[offset : offset + entry_size]
                )
            else:
                r_offset, r_info = struct.unpack(
                    entry_format, section_data[offset : offset + entry_size]
                )
                r_addend = 0

            reloc = Relocation(r_offset, r_info, r_addend)
            self._relocations.append(reloc)
            offset += entry_size

    def num_relocations(self) -> int:
        """Get number of relocations.

        Returns:
            Total number of relocations in the section.

        """
        return len(self._relocations)

    def get_relocation(self, index: int) -> Relocation | None:
        """Get relocation by index.

        Args:
            index: Relocation index.

        Returns:
            Relocation object at the specified index, or None if not found.

        """
        if 0 <= index < len(self._relocations):
            return self._relocations[index]
        return None

    def iter_relocations(self) -> Iterator[Relocation]:
        """Iterate over relocations.

        Returns:
            Iterator yielding all relocations in the section.

        """
        return iter(self._relocations)


class Dynamic:
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


class DynamicSection(Section):
    """Dynamic section."""

    elffile: ELFFile
    _dynamics: list[Dynamic]

    def __init__(
        self, header: Container, name: str, stream: BinaryIO, elffile: ELFFile
    ) -> None:
        """Initialize dynamic section."""
        super().__init__(header, name, stream)
        self.elffile = elffile
        self._dynamics = []
        self._parse_dynamics()

    def _parse_dynamics(self) -> None:
        """Parse dynamic entries."""
        section_data = self.data()
        if not section_data:
            return

        endian = "<" if self.elffile.little_endian else ">"

        if self.elffile.elfclass == ELFCLASS32:
            entry_size = ELF32_DYN_SIZE
            entry_format = f"{endian}II"
        else:
            entry_size = ELF64_DYN_SIZE
            entry_format = f"{endian}QQ"

        offset = 0
        while offset + entry_size <= len(section_data):
            d_tag, d_val = struct.unpack(
                entry_format, section_data[offset : offset + entry_size]
            )

            if d_tag == ENUM_D_TAG.DT_NULL:
                break

            dyn = Dynamic(d_tag, d_val)
            self._dynamics.append(dyn)
            offset += entry_size

    def iter_tags(self) -> Iterator[Dynamic]:
        """Iterate over dynamic tags.

        Returns:
            Iterator yielding all dynamic entries.

        """
        return iter(self._dynamics)

    def get_tag(self, tag: int) -> Dynamic | None:
        """Get dynamic entry by tag.

        Args:
            tag: Dynamic tag value to search for.

        Returns:
            Dynamic entry matching the tag, or None if not found.

        """
        return next((dyn for dyn in self._dynamics if dyn.d_tag == tag), None)


class NoteSection(Section):
    """Note section."""

    def iter_notes(self) -> Iterator[Container]:
        """Iterate over notes in the note section.

        Returns:
            Iterator yielding Container objects for each note.

        """
        section_data = self.data()
        offset = 0

        while offset < len(section_data) and offset + NOTE_HDR_SIZE <= len(section_data):
            n_namesz, n_descsz, n_type = struct.unpack(
                "<III", section_data[offset : offset + NOTE_HDR_SIZE]
            )
            offset += NOTE_HDR_SIZE

            if n_namesz:
                name = section_data[offset : offset + n_namesz].rstrip(b"\x00")
                offset += (n_namesz + 3) & ~3
            else:
                name = b""

            if n_descsz:
                desc = section_data[offset : offset + n_descsz]
                offset += (n_descsz + 3) & ~3
            else:
                desc = b""

            yield Container(n_type=n_type, n_name=name, n_desc=desc)


class Segment:
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
        """Get segment type."""
        return int(self.header.p_type)

    @property
    def p_flags(self) -> int:
        """Get segment flags."""
        return int(self.header.p_flags)

    @property
    def p_offset(self) -> int:
        """Get file offset."""
        return int(self.header.p_offset)

    @property
    def p_vaddr(self) -> int:
        """Get virtual address."""
        return int(self.header.p_vaddr)

    @property
    def p_paddr(self) -> int:
        """Get physical address."""
        return int(self.header.p_paddr)

    @property
    def p_filesz(self) -> int:
        """Get file size."""
        return int(self.header.p_filesz)

    @property
    def p_memsz(self) -> int:
        """Get memory size."""
        return int(self.header.p_memsz)

    @property
    def p_align(self) -> int:
        """Get alignment."""
        return int(self.header.p_align)


class InterpSegment(Segment):
    """Interpreter segment."""

    def get_interp_name(self) -> str:
        """Get interpreter name.

        Returns:
            Path to the program interpreter (e.g., /lib64/ld-linux-x86-64.so.2).

        """
        segment_data = self.data()
        if segment_data:
            return segment_data.rstrip(b"\x00").decode("latin-1", errors="ignore")
        return ""


class NoteSegment(Segment):
    """Note segment."""

    def iter_notes(self) -> Iterator[Container]:
        """Iterate over notes in the note segment.

        Returns:
            Iterator yielding Container objects for each note.

        """
        segment_data = self.data()
        offset = 0

        while offset < len(segment_data) and offset + NOTE_HDR_SIZE <= len(segment_data):
            n_namesz, n_descsz, n_type = struct.unpack(
                "<III", segment_data[offset : offset + NOTE_HDR_SIZE]
            )
            offset += NOTE_HDR_SIZE

            if n_namesz:
                name = segment_data[offset : offset + n_namesz].rstrip(b"\x00")
                offset += (n_namesz + 3) & ~3
            else:
                name = b""

            if n_descsz:
                desc = segment_data[offset : offset + n_descsz]
                offset += (n_descsz + 3) & ~3
            else:
                desc = b""

            yield Container(n_type=n_type, n_name=name, n_desc=desc)


DynamicSegment = Segment


class DWARFInfo:
    """Basic DWARF info fallback."""

    elffile: ELFFile

    def __init__(self, elffile: ELFFile) -> None:
        """Initialize DWARF info.

        Args:
            elffile: ELF file object to associate with this DWARF info.

        """
        self.elffile = elffile

    def iter_CUs(self) -> Iterator[Any]:  # noqa: N802
        """Iterate over compilation units (empty for fallback).

        Returns:
            Empty iterator as fallback does not support DWARF parsing.

        """
        return iter([])

    def get_DIE_from_refaddr(self, refaddr: int) -> None:  # noqa: ARG002, N802
        """Get DIE from reference address.

        Args:
            refaddr: Reference address (unused in fallback).

        Returns:
            None as fallback does not support DWARF parsing.

        """
        return


class DIE:
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

    def get_parent(self) -> DIE | None:
        """Get parent DIE.

        Returns:
            None as fallback does not support parent DIE traversal.

        """
        return None

    def iter_children(self) -> Iterator[DIE]:
        """Iterate over children.

        Returns:
            Empty iterator as fallback does not support child DIE traversal.

        """
        return iter([])


class ELFFile:
    """Functional ELF file parser implementation."""

    stream: BinaryIO
    little_endian: bool
    elfclass: int
    header: Container | None
    _section_headers: list[Container]
    _program_headers: list[Container]
    _sections: list[Section]
    _segments: list[Segment]
    _string_table: bytes | None

    def __init__(self, stream: BinaryIO) -> None:
        """Initialize ELF file parser."""
        self.stream = stream
        self.little_endian = True
        self.elfclass = 64
        self.header = None
        self._section_headers = []
        self._program_headers = []
        self._sections = []
        self._segments = []
        self._string_table = None
        self._parse_elf_header()
        self._parse_program_headers()
        self._parse_section_headers()

    def _parse_elf_header(self) -> None:  # noqa: PLR0914
        """Parse ELF header.

        Raises:
            ELFParseError: If the ELF file is invalid or malformed.

        """
        self.stream.seek(0)

        e_ident = self.stream.read(EI_NIDENT)
        if len(e_ident) < EI_NIDENT:
            raise ELFParseError("Invalid ELF file: too short")

        if e_ident[:4] != b"\x7fELF":
            raise ELFParseError("Invalid ELF magic")

        if e_ident[4] == EI_CLASS_32:
            self.elfclass = ELFCLASS32
        elif e_ident[4] == EI_CLASS_64:
            self.elfclass = ELFCLASS64
        else:
            raise ELFParseError(f"Invalid EI_CLASS: {e_ident[4]}")

        if e_ident[5] == EI_DATA_LSB:
            self.little_endian = True
            endian = "<"
        elif e_ident[5] == EI_DATA_MSB:
            self.little_endian = False
            endian = ">"
        else:
            raise ELFParseError(f"Invalid EI_DATA: {e_ident[5]}")

        if self.elfclass == ELFCLASS32:
            header_data = self.stream.read(ELF32_EHDR_SIZE)
            if len(header_data) < ELF32_EHDR_SIZE:
                raise ELFParseError("Incomplete ELF header")

            (
                e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
                e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
            ) = struct.unpack(f"{endian}HHIIIIIHHHHHH", header_data)
        else:
            header_data = self.stream.read(ELF64_EHDR_SIZE)
            if len(header_data) < ELF64_EHDR_SIZE:
                raise ELFParseError("Incomplete ELF header")

            (
                e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
                e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
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
        """Parse program headers."""
        if not self.header or self.header.e_phoff == 0:
            return

        self.stream.seek(self.header.e_phoff)
        endian = "<" if self.little_endian else ">"

        for _ in range(self.header.e_phnum):
            if self.elfclass == ELFCLASS32:
                ph_data = self.stream.read(ELF32_PHDR_SIZE)
                if len(ph_data) < ELF32_PHDR_SIZE:
                    break

                (
                    p_type, p_offset, p_vaddr, p_paddr,
                    p_filesz, p_memsz, p_flags, p_align,
                ) = struct.unpack(f"{endian}IIIIIIII", ph_data)
            else:
                ph_data = self.stream.read(ELF64_PHDR_SIZE)
                if len(ph_data) < ELF64_PHDR_SIZE:
                    break

                (
                    p_type, p_flags, p_offset, p_vaddr,
                    p_paddr, p_filesz, p_memsz, p_align,
                ) = struct.unpack(f"{endian}IIQQQQQQ", ph_data)

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

            segment = Segment(ph, self.stream)
            self._segments.append(segment)

    def _parse_section_headers(self) -> None:
        """Parse section headers."""
        if not self.header or self.header.e_shoff == 0:
            return

        self.stream.seek(self.header.e_shoff)
        endian = "<" if self.little_endian else ">"

        for _ in range(self.header.e_shnum):
            if self.elfclass == ELFCLASS32:
                sh_data = self.stream.read(ELF32_SHDR_SIZE)
                if len(sh_data) < ELF32_SHDR_SIZE:
                    break

                (
                    sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                    sh_size, sh_link, sh_info, sh_addralign, sh_entsize,
                ) = struct.unpack(f"{endian}IIIIIIIIII", sh_data)
            else:
                sh_data = self.stream.read(ELF64_SHDR_SIZE)
                if len(sh_data) < ELF64_SHDR_SIZE:
                    break

                (
                    sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                    sh_size, sh_link, sh_info, sh_addralign, sh_entsize,
                ) = struct.unpack(f"{endian}IIQQQQIIQQ", sh_data)

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

        if self.header.e_shstrndx < len(self._section_headers):
            strtab_sh = self._section_headers[self.header.e_shstrndx]
            self.stream.seek(strtab_sh.sh_offset)
            self._string_table = self.stream.read(strtab_sh.sh_size)

        for i, sh in enumerate(self._section_headers):
            name = self._get_string(sh.sh_name) if self._string_table else f".section{i}"

            section: Section
            if sh.sh_type == ENUM_SH_TYPE.SHT_STRTAB:
                section = StringTableSection(sh, name, self.stream)
            elif sh.sh_type in {ENUM_SH_TYPE.SHT_SYMTAB, ENUM_SH_TYPE.SHT_DYNSYM}:
                section = SymbolTableSection(sh, name, self.stream, self)
            elif sh.sh_type in {ENUM_SH_TYPE.SHT_REL, ENUM_SH_TYPE.SHT_RELA}:
                section = RelocationSection(sh, name, self.stream, self)
            elif sh.sh_type == ENUM_SH_TYPE.SHT_DYNAMIC:
                section = DynamicSection(sh, name, self.stream, self)
            elif sh.sh_type == ENUM_SH_TYPE.SHT_NOTE:
                section = NoteSection(sh, name, self.stream)
            else:
                section = Section(sh, name, self.stream)

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
        """Get number of sections."""
        return len(self._sections)

    def num_segments(self) -> int:
        """Get number of segments."""
        return len(self._segments)

    def get_section(self, n: int) -> Section | None:
        """Get section by index.

        Args:
            n: Section index.

        Returns:
            Section object at the specified index, or None if not found.

        """
        return self._sections[n] if 0 <= n < len(self._sections) else None

    def get_section_by_name(self, name: str) -> Section | None:
        """Get section by name.

        Args:
            name: Section name to search for.

        Returns:
            Section object with the specified name, or None if not found.

        """
        return next((section for section in self._sections if section.name == name), None)

    def get_segment(self, n: int) -> Segment | None:
        """Get segment by index.

        Args:
            n: Segment index.

        Returns:
            Segment object at the specified index, or None if not found.

        """
        return self._segments[n] if 0 <= n < len(self._segments) else None

    def iter_sections(self) -> Iterator[Section]:
        """Iterate over sections."""
        return iter(self._sections)

    def iter_segments(self) -> Iterator[Segment]:
        """Iterate over segments."""
        return iter(self._segments)

    def has_dwarf_info(self) -> bool:
        """Check if file has DWARF debug info."""
        return any(section.name.startswith(".debug_") for section in self._sections)

    def get_dwarf_info(self) -> DWARFInfo | None:
        """Get DWARF info (basic fallback)."""
        return DWARFInfo(self) if self.has_dwarf_info() else None

    def get_machine_arch(self) -> str:
        """Get machine architecture."""
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


def describe_e_type(e_type: int | str, elffile: Any = None) -> str:  # noqa: ARG001
    """Describe ELF file type.

    Args:
        e_type: ELF file type value.
        elffile: Optional ELF file object (for compatibility).

    Returns:
        Human-readable description of the ELF file type.

    """
    if isinstance(e_type, str):
        return e_type

    types = {
        ENUM_E_TYPE.ET_NONE: "NONE (No file type)",
        ENUM_E_TYPE.ET_REL: "REL (Relocatable file)",
        ENUM_E_TYPE.ET_EXEC: "EXEC (Executable file)",
        ENUM_E_TYPE.ET_DYN: "DYN (Shared object file)",
        ENUM_E_TYPE.ET_CORE: "CORE (Core file)",
    }
    return types.get(e_type, f"Unknown type {e_type}")


def describe_p_type(p_type: int | str) -> str:
    """Describe program header type.

    Args:
        p_type: Program header type value.

    Returns:
        Human-readable description of the program header type.

    """
    if isinstance(p_type, str):
        return p_type

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


def describe_sh_type(sh_type: int | str) -> str:
    """Describe section header type.

    Args:
        sh_type: Section header type value.

    Returns:
        Human-readable description of the section header type.

    """
    if isinstance(sh_type, str):
        return sh_type

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
    "InterpSegment",
    "NoteSection",
    "NoteSegment",
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
    "str2bytes",
]
