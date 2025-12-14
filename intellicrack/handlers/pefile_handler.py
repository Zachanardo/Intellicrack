"""PE file handler for Intellicrack.

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

import hashlib
import struct
from typing import Any

from intellicrack.utils.logger import log_all_methods, logger


logger.debug("PEfile handler module loaded")


class _FallbackDirectoryEntry:
    """PE directory entry indices."""

    EXPORT = 0
    IMPORT = 1
    RESOURCE = 2
    EXCEPTION = 3
    SECURITY = 4
    BASERELOC = 5
    DEBUG = 6
    COPYRIGHT = 7
    GLOBALPTR = 8
    TLS = 9
    LOAD_CONFIG = 10
    BOUND_IMPORT = 11
    IAT = 12
    DELAY_IMPORT = 13
    COM_DESCRIPTOR = 14
    RESERVED = 15


class _FallbackSectionCharacteristics:
    """Section characteristics flags."""

    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000
    IMAGE_SCN_MEM_SHARED = 0x10000000
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000


class _FallbackDllCharacteristics:
    """DLL characteristics flags."""

    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000


class _FallbackMachineType:
    """Machine types."""

    IMAGE_FILE_MACHINE_UNKNOWN = 0x0
    IMAGE_FILE_MACHINE_I386 = 0x14C
    IMAGE_FILE_MACHINE_R3000 = 0x162
    IMAGE_FILE_MACHINE_R4000 = 0x166
    IMAGE_FILE_MACHINE_R10000 = 0x168
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169
    IMAGE_FILE_MACHINE_ALPHA = 0x184
    IMAGE_FILE_MACHINE_SH3 = 0x1A2
    IMAGE_FILE_MACHINE_SH3DSP = 0x1A3
    IMAGE_FILE_MACHINE_SH3E = 0x1A4
    IMAGE_FILE_MACHINE_SH4 = 0x1A6
    IMAGE_FILE_MACHINE_SH5 = 0x1A8
    IMAGE_FILE_MACHINE_ARM = 0x1C0
    IMAGE_FILE_MACHINE_THUMB = 0x1C2
    IMAGE_FILE_MACHINE_ARMNT = 0x1C4
    IMAGE_FILE_MACHINE_AM33 = 0x1D3
    IMAGE_FILE_MACHINE_POWERPC = 0x1F0
    IMAGE_FILE_MACHINE_POWERPCFP = 0x1F1
    IMAGE_FILE_MACHINE_IA64 = 0x200
    IMAGE_FILE_MACHINE_MIPS16 = 0x266
    IMAGE_FILE_MACHINE_ALPHA64 = 0x284
    IMAGE_FILE_MACHINE_MIPSFPU = 0x366
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466
    IMAGE_FILE_MACHINE_TRICORE = 0x520
    IMAGE_FILE_MACHINE_CEF = 0xCEF
    IMAGE_FILE_MACHINE_EBC = 0xEBC
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_M32R = 0x9041
    IMAGE_FILE_MACHINE_ARM64 = 0xAA64
    IMAGE_FILE_MACHINE_CEE = 0xC0EE


class _FallbackSubsystemType:
    """Subsystem types."""

    IMAGE_SUBSYSTEM_UNKNOWN = 0
    IMAGE_SUBSYSTEM_NATIVE = 1
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
    IMAGE_SUBSYSTEM_OS2_CUI = 5
    IMAGE_SUBSYSTEM_POSIX_CUI = 7
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 10
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12
    IMAGE_SUBSYSTEM_EFI_ROM = 13
    IMAGE_SUBSYSTEM_XBOX = 14
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16


class _FallbackImageCharacteristics:
    """Image characteristics."""

    IMAGE_FILE_RELOCS_STRIPPED = 0x0001
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008
    IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x0010
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
    IMAGE_FILE_BYTES_REVERSED_LO = 0x0080
    IMAGE_FILE_32BIT_MACHINE = 0x0100
    IMAGE_FILE_DEBUG_STRIPPED = 0x0200
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800
    IMAGE_FILE_SYSTEM = 0x1000
    IMAGE_FILE_DLL = 0x2000
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000


class _FallbackDebugType:
    """Debug types."""

    IMAGE_DEBUG_TYPE_UNKNOWN = 0
    IMAGE_DEBUG_TYPE_COFF = 1
    IMAGE_DEBUG_TYPE_CODEVIEW = 2
    IMAGE_DEBUG_TYPE_FPO = 3
    IMAGE_DEBUG_TYPE_MISC = 4
    IMAGE_DEBUG_TYPE_EXCEPTION = 5
    IMAGE_DEBUG_TYPE_FIXUP = 6
    IMAGE_DEBUG_TYPE_OMAP_TO_SRC = 7
    IMAGE_DEBUG_TYPE_OMAP_FROM_SRC = 8
    IMAGE_DEBUG_TYPE_BORLAND = 9
    IMAGE_DEBUG_TYPE_RESERVED10 = 10
    IMAGE_DEBUG_TYPE_CLSID = 11


class _FallbackResourceType:
    """Resource types."""

    RT_CURSOR = 1
    RT_BITMAP = 2
    RT_ICON = 3
    RT_MENU = 4
    RT_DIALOG = 5
    RT_STRING = 6
    RT_FONTDIR = 7
    RT_FONT = 8
    RT_ACCELERATOR = 9
    RT_RCDATA = 10
    RT_MESSAGETABLE = 11
    RT_GROUP_CURSOR = 12
    RT_GROUP_ICON = 14
    RT_VERSION = 16
    RT_DLGINCLUDE = 17
    RT_PLUGPLAY = 19
    RT_VXD = 20
    RT_ANICURSOR = 21
    RT_ANIICON = 22
    RT_HTML = 23
    RT_MANIFEST = 24


class _FallbackPEFormatError(Exception):
    """PE format error exception."""


class _FallbackStructure:
    """Base structure for PE components."""

    def __init__(self, format_str: str | None = None, name: str | None = None) -> None:
        """Initialize structure.

        Args:
            format_str: Struct format string for binary unpacking, defaults to None.
            name: Human-readable name for the structure, defaults to "Structure".

        """
        self.format_str = format_str
        self.name = name or "Structure"
        self.sizeof = struct.calcsize(format_str) if format_str else 0
        self.fields: list[str] = []

    def unpack(self, data: bytes) -> tuple[Any, ...]:
        """Unpack binary data.

        Args:
            data: Raw binary data to unpack according to the format string.

        Returns:
            Tuple of unpacked values, or empty tuple if no format string defined.

        """
        if self.format_str:
            return struct.unpack(self.format_str, data[: self.sizeof])
        return ()


class _DataDirectory:
    """Data directory entry."""

    def __init__(self) -> None:
        """Initialize data directory entry."""
        self.VirtualAddress: int = 0
        self.Size: int = 0


class _FileHeaderImpl:
    """Internal representation of PE COFF file header."""

    def __init__(self) -> None:
        """Initialize file header."""
        self.Machine: int = 0
        self.NumberOfSections: int = 0
        self.TimeDateStamp: int = 0
        self.PointerToSymbolTable: int = 0
        self.NumberOfSymbols: int = 0
        self.SizeOfOptionalHeader: int = 0
        self.Characteristics: int = 0


class _OptionalHeaderImpl:
    """Internal representation of PE optional header."""

    def __init__(self) -> None:
        """Initialize optional header."""
        self.Magic: int = 0
        self.MajorLinkerVersion: int = 0
        self.MinorLinkerVersion: int = 0
        self.SizeOfCode: int = 0
        self.SizeOfInitializedData: int = 0
        self.SizeOfUninitializedData: int = 0
        self.AddressOfEntryPoint: int = 0
        self.BaseOfCode: int = 0
        self.BaseOfData: int = 0
        self.ImageBase: int = 0
        self.SectionAlignment: int = 0
        self.FileAlignment: int = 0
        self.MajorOperatingSystemVersion: int = 0
        self.MinorOperatingSystemVersion: int = 0
        self.MajorImageVersion: int = 0
        self.MinorImageVersion: int = 0
        self.MajorSubsystemVersion: int = 0
        self.MinorSubsystemVersion: int = 0
        self.Reserved1: int = 0
        self.SizeOfImage: int = 0
        self.SizeOfHeaders: int = 0
        self.CheckSum: int = 0
        self.Subsystem: int = 0
        self.DllCharacteristics: int = 0
        self.SizeOfStackReserve: int = 0
        self.SizeOfStackCommit: int = 0
        self.SizeOfHeapReserve: int = 0
        self.SizeOfHeapCommit: int = 0
        self.LoaderFlags: int = 0
        self.NumberOfRvaAndSizes: int = 0
        self.DATA_DIRECTORY: list[_DataDirectory] = []


class _SectionHeader:
    """Internal representation of PE section header."""

    def __init__(self) -> None:
        """Initialize section header."""
        self.Name: str = ""
        self.VirtualSize: int = 0
        self.VirtualAddress: int = 0
        self.SizeOfRawData: int = 0
        self.PointerToRawData: int = 0
        self.PointerToRelocations: int = 0
        self.PointerToLinenumbers: int = 0
        self.NumberOfRelocations: int = 0
        self.NumberOfLinenumbers: int = 0
        self.Characteristics: int = 0
        self.data: bytes = b""


class _ImportData:
    """Import function data."""

    def __init__(self) -> None:
        """Initialize import data."""
        self.ordinal: int | None = None
        self.name: str | None = None
        self.hint: int = 0


class _ImportDescriptorImpl:
    """Internal representation of import directory entry."""

    def __init__(self) -> None:
        """Initialize import descriptor."""
        self.OriginalFirstThunk: int = 0
        self.TimeDateStamp: int = 0
        self.ForwarderChain: int = 0
        self.Name: int = 0
        self.FirstThunk: int = 0
        self.dll: str = ""
        self.imports: list[_ImportData] = []


class _ExportSymbol:
    """Export symbol data."""

    def __init__(self) -> None:
        """Initialize export symbol."""
        self.ordinal: int = 0
        self.address: int = 0
        self.name: str | None = None
        self.forwarder: str | None = None


class _ExportDirectory:
    """Export directory data."""

    def __init__(self) -> None:
        """Initialize export directory."""
        self.Characteristics: int = 0
        self.TimeDateStamp: int = 0
        self.MajorVersion: int = 0
        self.MinorVersion: int = 0
        self.Name: int = 0
        self.Base: int = 0
        self.NumberOfFunctions: int = 0
        self.NumberOfNames: int = 0
        self.AddressOfFunctions: int = 0
        self.AddressOfNames: int = 0
        self.AddressOfNameOrdinals: int = 0
        self.name: str = ""
        self.symbols: list[_ExportSymbol] = []


@log_all_methods
class _FallbackPE:
    """Functional PE file parser implementation."""

    def __init__(self, name: str | None = None, data: bytes | None = None, fast_load: bool | None = None) -> None:
        """Initialize PE parser.

        Args:
            name: Path to PE file to load, defaults to None.
            data: Raw binary data of PE file, defaults to None.
            fast_load: Skip parsing imports, exports, and resources if True, defaults to None.

        """
        self.name = name
        self.fast_load = fast_load
        self._data: bytes = b""

        self.DOS_HEADER: object | None = None
        self.NT_HEADERS: object | None = None
        self.FILE_HEADER: _FileHeaderImpl | None = None
        self.OPTIONAL_HEADER: _OptionalHeaderImpl | None = None
        self.sections: list[_SectionHeader] = []
        self.DIRECTORY_ENTRY_IMPORT: list[_ImportDescriptorImpl] = []
        self.DIRECTORY_ENTRY_EXPORT: _ExportDirectory | None = None
        self.DIRECTORY_ENTRY_RESOURCE: object | None = None
        self.DIRECTORY_ENTRY_DEBUG: list[object] = []
        self.DIRECTORY_ENTRY_TLS: object | None = None
        self.DIRECTORY_ENTRY_BASERELOC: list[object] = []
        self.DIRECTORY_ENTRY_DELAY_IMPORT: list[object] = []
        self.DIRECTORY_ENTRY_BOUND_IMPORT: list[object] = []

        if name and not data:
            with open(name, "rb") as f:
                self._data = f.read()
        elif data:
            self._data = data

        if self._data:
            self._parse()

    def _parse(self) -> None:
        """Parse PE file structure.

        Raises:
            _FallbackPEFormatError: If PE file format is invalid.

        """
        if len(self._data) < 64:
            raise _FallbackPEFormatError("File too small to be PE")

        dos_magic = struct.unpack("<H", self._data[:2])[0]
        if dos_magic != 0x5A4D:
            raise _FallbackPEFormatError("Invalid DOS signature")

        pe_offset = struct.unpack("<I", self._data[60:64])[0]

        if len(self._data) < pe_offset + 24:
            raise _FallbackPEFormatError("Invalid PE header offset")

        pe_signature = struct.unpack("<I", self._data[pe_offset : pe_offset + 4])[0]
        if pe_signature != 0x00004550:
            raise _FallbackPEFormatError("Invalid PE signature")

        coff_offset = pe_offset + 4
        self.FILE_HEADER = self._parse_file_header(coff_offset)

        opt_offset = coff_offset + 20
        opt_magic = struct.unpack("<H", self._data[opt_offset : opt_offset + 2])[0]

        if opt_magic == 0x10B:
            self.OPTIONAL_HEADER = self._parse_optional_header32(opt_offset)
        elif opt_magic == 0x20B:
            self.OPTIONAL_HEADER = self._parse_optional_header64(opt_offset)
        else:
            raise _FallbackPEFormatError(f"Invalid optional header magic: 0x{opt_magic:04x}")

        section_offset = opt_offset + self.FILE_HEADER.SizeOfOptionalHeader
        self._parse_sections(section_offset, self.FILE_HEADER.NumberOfSections)

        if not self.fast_load:
            self._parse_imports()
            self._parse_exports()
            self._parse_resources()
            self._parse_debug()
            self._parse_relocations()

    def _parse_file_header(self, offset: int) -> _FileHeaderImpl:
        """Parse COFF file header.

        Args:
            offset: File offset where COFF header begins.

        Returns:
            _FileHeaderImpl object with parsed Machine, NumberOfSections, and other fields.

        """
        header = _FileHeaderImpl()
        data = self._data[offset : offset + 20]

        header.Machine = struct.unpack("<H", data[:2])[0]
        header.NumberOfSections = struct.unpack("<H", data[2:4])[0]
        header.TimeDateStamp = struct.unpack("<I", data[4:8])[0]
        header.PointerToSymbolTable = struct.unpack("<I", data[8:12])[0]
        header.NumberOfSymbols = struct.unpack("<I", data[12:16])[0]
        header.SizeOfOptionalHeader = struct.unpack("<H", data[16:18])[0]
        header.Characteristics = struct.unpack("<H", data[18:20])[0]

        return header

    def _parse_optional_header32(self, offset: int) -> _OptionalHeaderImpl:
        """Parse 32-bit optional header.

        Args:
            offset: File offset where optional header begins.

        Returns:
            _OptionalHeaderImpl object with parsed 32-bit optional header fields.

        """
        header = _OptionalHeaderImpl()
        data = self._data[offset:]

        header.Magic = struct.unpack("<H", data[:2])[0]
        header.MajorLinkerVersion = data[2]
        header.MinorLinkerVersion = data[3]
        header.SizeOfCode = struct.unpack("<I", data[4:8])[0]
        header.SizeOfInitializedData = struct.unpack("<I", data[8:12])[0]
        header.SizeOfUninitializedData = struct.unpack("<I", data[12:16])[0]
        header.AddressOfEntryPoint = struct.unpack("<I", data[16:20])[0]
        header.BaseOfCode = struct.unpack("<I", data[20:24])[0]
        header.BaseOfData = struct.unpack("<I", data[24:28])[0]
        header.ImageBase = struct.unpack("<I", data[28:32])[0]
        header.SectionAlignment = struct.unpack("<I", data[32:36])[0]
        header.FileAlignment = struct.unpack("<I", data[36:40])[0]
        header.MajorOperatingSystemVersion = struct.unpack("<H", data[40:42])[0]
        header.MinorOperatingSystemVersion = struct.unpack("<H", data[42:44])[0]
        header.MajorImageVersion = struct.unpack("<H", data[44:46])[0]
        header.MinorImageVersion = struct.unpack("<H", data[46:48])[0]
        header.MajorSubsystemVersion = struct.unpack("<H", data[48:50])[0]
        header.MinorSubsystemVersion = struct.unpack("<H", data[50:52])[0]
        header.Reserved1 = struct.unpack("<I", data[52:56])[0]
        header.SizeOfImage = struct.unpack("<I", data[56:60])[0]
        header.SizeOfHeaders = struct.unpack("<I", data[60:64])[0]
        header.CheckSum = struct.unpack("<I", data[64:68])[0]
        header.Subsystem = struct.unpack("<H", data[68:70])[0]
        header.DllCharacteristics = struct.unpack("<H", data[70:72])[0]
        header.SizeOfStackReserve = struct.unpack("<I", data[72:76])[0]
        header.SizeOfStackCommit = struct.unpack("<I", data[76:80])[0]
        header.SizeOfHeapReserve = struct.unpack("<I", data[80:84])[0]
        header.SizeOfHeapCommit = struct.unpack("<I", data[84:88])[0]
        header.LoaderFlags = struct.unpack("<I", data[88:92])[0]
        header.NumberOfRvaAndSizes = struct.unpack("<I", data[92:96])[0]

        header.DATA_DIRECTORY = []
        for i in range(min(header.NumberOfRvaAndSizes, 16)):
            dir_offset = 96 + i * 8
            vaddr = struct.unpack("<I", data[dir_offset : dir_offset + 4])[0]
            size = struct.unpack("<I", data[dir_offset + 4 : dir_offset + 8])[0]

            dir_entry = _DataDirectory()
            dir_entry.VirtualAddress = vaddr
            dir_entry.Size = size
            header.DATA_DIRECTORY.append(dir_entry)

        return header

    def _parse_optional_header64(self, offset: int) -> _OptionalHeaderImpl:
        """Parse 64-bit optional header.

        Args:
            offset: File offset where optional header begins.

        Returns:
            _OptionalHeaderImpl object with parsed 64-bit optional header fields.

        """
        header = _OptionalHeaderImpl()
        data = self._data[offset:]

        header.Magic = struct.unpack("<H", data[:2])[0]
        header.MajorLinkerVersion = data[2]
        header.MinorLinkerVersion = data[3]
        header.SizeOfCode = struct.unpack("<I", data[4:8])[0]
        header.SizeOfInitializedData = struct.unpack("<I", data[8:12])[0]
        header.SizeOfUninitializedData = struct.unpack("<I", data[12:16])[0]
        header.AddressOfEntryPoint = struct.unpack("<I", data[16:20])[0]
        header.BaseOfCode = struct.unpack("<I", data[20:24])[0]
        header.ImageBase = struct.unpack("<Q", data[24:32])[0]
        header.SectionAlignment = struct.unpack("<I", data[32:36])[0]
        header.FileAlignment = struct.unpack("<I", data[36:40])[0]
        header.MajorOperatingSystemVersion = struct.unpack("<H", data[40:42])[0]
        header.MinorOperatingSystemVersion = struct.unpack("<H", data[42:44])[0]
        header.MajorImageVersion = struct.unpack("<H", data[44:46])[0]
        header.MinorImageVersion = struct.unpack("<H", data[46:48])[0]
        header.MajorSubsystemVersion = struct.unpack("<H", data[48:50])[0]
        header.MinorSubsystemVersion = struct.unpack("<H", data[50:52])[0]
        header.Reserved1 = struct.unpack("<I", data[52:56])[0]
        header.SizeOfImage = struct.unpack("<I", data[56:60])[0]
        header.SizeOfHeaders = struct.unpack("<I", data[60:64])[0]
        header.CheckSum = struct.unpack("<I", data[64:68])[0]
        header.Subsystem = struct.unpack("<H", data[68:70])[0]
        header.DllCharacteristics = struct.unpack("<H", data[70:72])[0]
        header.SizeOfStackReserve = struct.unpack("<Q", data[72:80])[0]
        header.SizeOfStackCommit = struct.unpack("<Q", data[80:88])[0]
        header.SizeOfHeapReserve = struct.unpack("<Q", data[88:96])[0]
        header.SizeOfHeapCommit = struct.unpack("<Q", data[96:104])[0]
        header.LoaderFlags = struct.unpack("<I", data[104:108])[0]
        header.NumberOfRvaAndSizes = struct.unpack("<I", data[108:112])[0]

        header.DATA_DIRECTORY = []
        for i in range(min(header.NumberOfRvaAndSizes, 16)):
            dir_offset = 112 + i * 8
            vaddr = struct.unpack("<I", data[dir_offset : dir_offset + 4])[0]
            size = struct.unpack("<I", data[dir_offset + 4 : dir_offset + 8])[0]

            dir_entry = _DataDirectory()
            dir_entry.VirtualAddress = vaddr
            dir_entry.Size = size
            header.DATA_DIRECTORY.append(dir_entry)

        return header

    def _parse_sections(self, offset: int, count: int) -> None:
        """Parse section headers.

        Args:
            offset: File offset where first section header begins.
            count: Number of section headers to parse.

        """
        for i in range(count):
            section_offset = offset + i * 40
            if section_offset + 40 > len(self._data):
                break

            data = self._data[section_offset : section_offset + 40]

            section = _SectionHeader()
            section.Name = data[:8].rstrip(b"\x00").decode("ascii", errors="ignore")
            section.VirtualSize = struct.unpack("<I", data[8:12])[0]
            section.VirtualAddress = struct.unpack("<I", data[12:16])[0]
            section.SizeOfRawData = struct.unpack("<I", data[16:20])[0]
            section.PointerToRawData = struct.unpack("<I", data[20:24])[0]
            section.PointerToRelocations = struct.unpack("<I", data[24:28])[0]
            section.PointerToLinenumbers = struct.unpack("<I", data[28:32])[0]
            section.NumberOfRelocations = struct.unpack("<H", data[32:34])[0]
            section.NumberOfLinenumbers = struct.unpack("<H", data[34:36])[0]
            section.Characteristics = struct.unpack("<I", data[36:40])[0]

            if section.PointerToRawData > 0 and section.SizeOfRawData > 0:
                start = section.PointerToRawData
                end = start + section.SizeOfRawData
                section.data = self._data[start:end]
            else:
                section.data = b""

            self.sections.append(section)

    def _parse_imports(self) -> None:
        """Parse import directory."""
        if not self.OPTIONAL_HEADER or not self.OPTIONAL_HEADER.DATA_DIRECTORY:
            return

        if len(self.OPTIONAL_HEADER.DATA_DIRECTORY) <= _FallbackDirectoryEntry.IMPORT:
            return

        import_dir = self.OPTIONAL_HEADER.DATA_DIRECTORY[_FallbackDirectoryEntry.IMPORT]
        if import_dir.VirtualAddress == 0 or import_dir.Size == 0:
            return

        import_offset = self.get_offset_from_rva(import_dir.VirtualAddress)
        if not import_offset:
            return

        offset = import_offset
        while offset + 20 <= len(self._data):
            data = self._data[offset : offset + 20]

            if data == b"\x00" * 20:
                break

            import_desc = _ImportDescriptorImpl()
            import_desc.OriginalFirstThunk = struct.unpack("<I", data[:4])[0]
            import_desc.TimeDateStamp = struct.unpack("<I", data[4:8])[0]
            import_desc.ForwarderChain = struct.unpack("<I", data[8:12])[0]
            import_desc.Name = struct.unpack("<I", data[12:16])[0]
            import_desc.FirstThunk = struct.unpack("<I", data[16:20])[0]

            name_offset = self.get_offset_from_rva(import_desc.Name)
            if name_offset:
                dll_name = self._get_string(name_offset)
                import_desc.dll = dll_name
                import_desc.imports = []

                thunk_rva = import_desc.OriginalFirstThunk or import_desc.FirstThunk
                thunk_offset = self.get_offset_from_rva(thunk_rva)
                if thunk_offset:
                    self._parse_import_thunks(import_desc, thunk_offset)

                self.DIRECTORY_ENTRY_IMPORT.append(import_desc)

            offset += 20

    def _parse_import_thunks(self, import_desc: _ImportDescriptorImpl, offset: int) -> None:
        """Parse import thunks.

        Args:
            import_desc: _ImportDescriptorImpl object to populate with import thunk data.
            offset: File offset where import thunks begin.

        """
        if self.OPTIONAL_HEADER is None:
            return

        is_64bit = self.OPTIONAL_HEADER.Magic == 0x20B
        thunk_size = 8 if is_64bit else 4

        while offset + thunk_size <= len(self._data):
            if is_64bit:
                thunk = struct.unpack("<Q", self._data[offset : offset + 8])[0]
                ordinal_flag = 0x8000000000000000
            else:
                thunk = struct.unpack("<I", self._data[offset : offset + 4])[0]
                ordinal_flag = 0x80000000

            if thunk == 0:
                break

            import_data = _ImportData()

            if thunk & ordinal_flag:
                import_data.ordinal = thunk & 0xFFFF
                import_data.name = None
            else:
                name_rva = thunk & 0x7FFFFFFF
                name_offset = self.get_offset_from_rva(name_rva)
                if name_offset:
                    import_data.hint = struct.unpack("<H", self._data[name_offset : name_offset + 2])[0]
                    import_data.name = self._get_string(name_offset + 2)
                    import_data.ordinal = None

            import_desc.imports.append(import_data)
            offset += thunk_size

    def _parse_exports(self) -> None:
        """Parse export directory."""
        if not self.OPTIONAL_HEADER or not self.OPTIONAL_HEADER.DATA_DIRECTORY:
            return

        if len(self.OPTIONAL_HEADER.DATA_DIRECTORY) <= _FallbackDirectoryEntry.EXPORT:
            return

        export_dir = self.OPTIONAL_HEADER.DATA_DIRECTORY[_FallbackDirectoryEntry.EXPORT]
        if export_dir.VirtualAddress == 0 or export_dir.Size == 0:
            return

        export_offset = self.get_offset_from_rva(export_dir.VirtualAddress)
        if not export_offset:
            return

        if export_offset + 40 > len(self._data):
            return

        data = self._data[export_offset : export_offset + 40]

        export = _ExportDirectory()
        export.Characteristics = struct.unpack("<I", data[:4])[0]
        export.TimeDateStamp = struct.unpack("<I", data[4:8])[0]
        export.MajorVersion = struct.unpack("<H", data[8:10])[0]
        export.MinorVersion = struct.unpack("<H", data[10:12])[0]
        export.Name = struct.unpack("<I", data[12:16])[0]
        export.Base = struct.unpack("<I", data[16:20])[0]
        export.NumberOfFunctions = struct.unpack("<I", data[20:24])[0]
        export.NumberOfNames = struct.unpack("<I", data[24:28])[0]
        export.AddressOfFunctions = struct.unpack("<I", data[28:32])[0]
        export.AddressOfNames = struct.unpack("<I", data[32:36])[0]
        export.AddressOfNameOrdinals = struct.unpack("<I", data[36:40])[0]

        name_file_offset = self.get_offset_from_rva(export.Name)
        if name_file_offset:
            export.name = self._get_string(name_file_offset)

        export.symbols = []

        if 0 < export.NumberOfFunctions < 65536:
            func_offset = self.get_offset_from_rva(export.AddressOfFunctions)
            names_offset = self.get_offset_from_rva(export.AddressOfNames) if export.NumberOfNames > 0 else None
            ordinal_offset = self.get_offset_from_rva(export.AddressOfNameOrdinals) if export.NumberOfNames > 0 else None

            name_ordinals: dict[int, str] = {}
            if names_offset and ordinal_offset:
                for i in range(min(export.NumberOfNames, 65536)):
                    if names_offset + i * 4 + 4 > len(self._data):
                        break
                    if ordinal_offset + i * 2 + 2 > len(self._data):
                        break

                    name_rva = struct.unpack("<I", self._data[names_offset + i * 4 : names_offset + i * 4 + 4])[0]
                    ordinal = struct.unpack("<H", self._data[ordinal_offset + i * 2 : ordinal_offset + i * 2 + 2])[0]

                    name_str_offset = self.get_offset_from_rva(name_rva)
                    if name_str_offset:
                        func_name = self._get_string(name_str_offset)
                        name_ordinals[ordinal] = func_name

            if func_offset:
                for i in range(min(export.NumberOfFunctions, 65536)):
                    if func_offset + i * 4 + 4 > len(self._data):
                        break

                    func_rva = struct.unpack("<I", self._data[func_offset + i * 4 : func_offset + i * 4 + 4])[0]

                    if func_rva != 0:
                        symbol = _ExportSymbol()
                        symbol.ordinal = export.Base + i
                        symbol.address = func_rva
                        symbol.name = name_ordinals.get(i)
                        symbol.forwarder = None

                        if export_dir.VirtualAddress <= func_rva < export_dir.VirtualAddress + export_dir.Size:
                            forwarder_offset = self.get_offset_from_rva(func_rva)
                            if forwarder_offset:
                                symbol.forwarder = self._get_string(forwarder_offset)

                        export.symbols.append(symbol)

        self.DIRECTORY_ENTRY_EXPORT = export

    def _parse_resources(self) -> None:
        """Parse resource directory."""

    def _parse_debug(self) -> None:
        """Parse debug directory."""

    def _parse_relocations(self) -> None:
        """Parse base relocations."""

    def _get_string(self, offset: int) -> str:
        """Get null-terminated string from offset.

        Args:
            offset: File offset where string begins.

        Returns:
            Null-terminated ASCII string decoded from binary data.

        """
        end = self._data.find(b"\x00", offset)
        if end == -1:
            end = len(self._data)
        return self._data[offset:end].decode("ascii", errors="ignore")

    def get_offset_from_rva(self, rva: int) -> int | None:
        """Convert RVA to file offset.

        Args:
            rva: Relative Virtual Address to convert.

        Returns:
            File offset corresponding to RVA, or None if RVA is not in any section.

        """
        return next(
            (
                rva - section.VirtualAddress + section.PointerToRawData
                for section in self.sections
                if section.VirtualAddress <= rva < section.VirtualAddress + section.VirtualSize
            ),
            None,
        )

    def get_rva_from_offset(self, offset: int) -> int | None:
        """Convert file offset to RVA.

        Args:
            offset: File offset to convert.

        Returns:
            Relative Virtual Address corresponding to file offset, or None if not in any section.

        """
        return next(
            (
                offset - section.PointerToRawData + section.VirtualAddress
                for section in self.sections
                if section.PointerToRawData <= offset < section.PointerToRawData + section.SizeOfRawData
            ),
            None,
        )

    def get_data(self, rva: int, length: int) -> bytes | None:
        """Get data at RVA.

        Args:
            rva: Relative Virtual Address to read from.
            length: Number of bytes to read.

        Returns:
            Binary data from RVA, or None if RVA is invalid or insufficient data available.

        """
        offset = self.get_offset_from_rva(rva)
        if offset and offset + length <= len(self._data):
            return self._data[offset : offset + length]
        return None

    def get_memory_mapped_image(self) -> bytes | None:
        """Get memory-mapped image.

        Returns:
            Binary representation of PE as loaded in memory with sections mapped to virtual addresses,
            or None if unable to create.

        """
        if not self.OPTIONAL_HEADER:
            return None

        image_size = self.OPTIONAL_HEADER.SizeOfImage
        image = bytearray(image_size)

        header_size = self.OPTIONAL_HEADER.SizeOfHeaders
        image[:header_size] = self._data[:header_size]

        for section in self.sections:
            if section.PointerToRawData > 0:
                src_start = section.PointerToRawData
                src_end = src_start + min(section.SizeOfRawData, section.VirtualSize)
                dst_start = section.VirtualAddress
                dst_end = dst_start + (src_end - src_start)

                if src_end <= len(self._data) and dst_end <= image_size:
                    image[dst_start:dst_end] = self._data[src_start:src_end]

        return bytes(image)

    def get_imphash(self) -> str:
        """Calculate import hash.

        Returns:
            SHA256 hash of import function names and ordinals for static binary signature.

        """
        if not self.DIRECTORY_ENTRY_IMPORT:
            return ""

        imp_str = ""
        for entry in self.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.lower() if entry.dll else ""
            dll_name = dll_name.removesuffix(".dll")

            for imp in entry.imports:
                if imp.name:
                    imp_str += f"{dll_name}.{imp.name.lower()},"
                elif imp.ordinal:
                    imp_str += f"{dll_name}.ord{imp.ordinal},"

        imp_str = imp_str.rstrip(",")
        return hashlib.sha256(imp_str.encode()).hexdigest() if imp_str else ""

    def get_rich_header_hash(self) -> str | None:
        """Calculate Rich header hash.

        Returns:
            SHA256 hash of Rich header data between DanS marker and Rich signature, or None if not found.

        """
        rich_index = self._data.find(b"Rich")
        if rich_index == -1:
            return None

        dans_index = self._data.find(b"DanS")
        if dans_index == -1 or dans_index >= rich_index:
            return None

        rich_data = self._data[dans_index : rich_index + 8]
        return hashlib.sha256(rich_data).hexdigest()

    def generate_checksum(self) -> int:
        """Generate PE checksum.

        Returns:
            Calculated PE checksum value used for integrity verification.

        """
        checksum = 0
        top = 2**32

        for i in range(0, len(self._data), 2):
            if i + 1 < len(self._data):
                word = struct.unpack("<H", self._data[i : i + 2])[0]
            else:
                word = self._data[i]

            checksum = (checksum & 0xFFFFFFFF) + word + (checksum >> 32)
            if checksum > top:
                checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)

        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum += checksum >> 16
        checksum &= 0xFFFF

        return checksum + len(self._data)

    def is_exe(self) -> bool:
        """Check if file is EXE.

        Returns:
            True if PE file is executable, False otherwise.

        """
        if self.FILE_HEADER and self.FILE_HEADER.Characteristics:
            return bool(self.FILE_HEADER.Characteristics & _FallbackImageCharacteristics.IMAGE_FILE_EXECUTABLE_IMAGE)
        return False

    def is_dll(self) -> bool:
        """Check if file is DLL.

        Returns:
            True if PE file is a dynamic library, False otherwise.

        """
        if self.FILE_HEADER and self.FILE_HEADER.Characteristics:
            return bool(self.FILE_HEADER.Characteristics & _FallbackImageCharacteristics.IMAGE_FILE_DLL)
        return False

    def is_driver(self) -> bool:
        """Check if file is driver.

        Returns:
            True if PE file is a system driver, False otherwise.

        """
        if self.OPTIONAL_HEADER:
            return self.OPTIONAL_HEADER.Subsystem == _FallbackSubsystemType.IMAGE_SUBSYSTEM_NATIVE
        return False

    def write(self, filename: str | None = None) -> bytes:
        """Write PE to file.

        Args:
            filename: Output file path to write PE binary to, defaults to None.

        Returns:
            Binary PE data that was written.

        """
        if filename:
            with open(filename, "wb") as f:
                f.write(self._data)
        return self._data

    def close(self) -> None:
        """Close PE file."""
        self._data = b""

    def __str__(self) -> str:
        """Return string representation.

        Returns:
            str: String representation of the PE object.

        """
        return f"PE({self.name})"


class _FallbackPefileModule:
    """Fallback pefile module."""

    PE = _FallbackPE
    PEFormatError = _FallbackPEFormatError
    Structure = _FallbackStructure

    DIRECTORY_ENTRY = _FallbackDirectoryEntry
    SECTION_CHARACTERISTICS = _FallbackSectionCharacteristics
    DLL_CHARACTERISTICS = _FallbackDllCharacteristics
    MACHINE_TYPE = _FallbackMachineType
    SUBSYSTEM_TYPE = _FallbackSubsystemType
    IMAGE_CHARACTERISTICS = _FallbackImageCharacteristics
    DEBUG_TYPE = _FallbackDebugType
    RESOURCE_TYPE = _FallbackResourceType


def _load_pefile_or_fallback() -> tuple[
    bool,
    bool,
    str | None,
    type[Any],
    type[Any],
    type[Any],
    type[Any],
    type[Any],
    type[Any],
    type[Any],
    type[Any],
    type[Any],
    type[Exception],
    type[Any],
    Any,
]:
    """Load pefile module or use fallback implementations.

    Returns:
        Tuple containing availability flags, version, and all PE-related types and module.

    """
    try:
        import pefile as _pefile_module

        return (
            True,
            True,
            _pefile_module.__version__,
            _pefile_module.DEBUG_TYPE,
            _pefile_module.DIRECTORY_ENTRY,
            _pefile_module.DLL_CHARACTERISTICS,
            _pefile_module.IMAGE_CHARACTERISTICS,
            _pefile_module.MACHINE_TYPE,
            _pefile_module.PE,
            _pefile_module.RESOURCE_TYPE,
            _pefile_module.SECTION_CHARACTERISTICS,
            _pefile_module.SUBSYSTEM_TYPE,
            _pefile_module.PEFormatError,
            _pefile_module.Structure,
            _pefile_module,
        )
    except ImportError as e:
        logger.error("Pefile not available, using fallback implementations: %s", e)
        return (
            False,
            False,
            None,
            _FallbackDebugType,
            _FallbackDirectoryEntry,
            _FallbackDllCharacteristics,
            _FallbackImageCharacteristics,
            _FallbackMachineType,
            _FallbackPE,
            _FallbackResourceType,
            _FallbackSectionCharacteristics,
            _FallbackSubsystemType,
            _FallbackPEFormatError,
            _FallbackStructure,
            _FallbackPefileModule(),
        )


(
    HAS_PEFILE,
    PEFILE_AVAILABLE,
    PEFILE_VERSION,
    DEBUG_TYPE,
    DIRECTORY_ENTRY,
    DLL_CHARACTERISTICS,
    IMAGE_CHARACTERISTICS,
    MACHINE_TYPE,
    PE,
    RESOURCE_TYPE,
    SECTION_CHARACTERISTICS,
    SUBSYSTEM_TYPE,
    PEFormatError,
    Structure,
    pefile,
) = _load_pefile_or_fallback()


__all__ = [
    "DEBUG_TYPE",
    "DIRECTORY_ENTRY",
    "DLL_CHARACTERISTICS",
    "HAS_PEFILE",
    "IMAGE_CHARACTERISTICS",
    "MACHINE_TYPE",
    "PE",
    "PEFILE_AVAILABLE",
    "PEFILE_VERSION",
    "PEFormatError",
    "RESOURCE_TYPE",
    "SECTION_CHARACTERISTICS",
    "SUBSYSTEM_TYPE",
    "Structure",
    "pefile",
]
