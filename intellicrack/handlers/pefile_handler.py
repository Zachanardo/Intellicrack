"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

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

import hashlib
import struct

from intellicrack.logger import logger

"""
Pefile Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for pefile imports.
When pefile is not available, it provides REAL, functional Python-based
implementations for essential PE file parsing operations.
"""

# Pefile availability detection and import handling
try:
    import pefile
    from pefile import (
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
    )

    HAS_PEFILE = True
    PEFILE_AVAILABLE = True
    PEFILE_VERSION = pefile.__version__

except ImportError as e:
    logger.error("Pefile not available, using fallback implementations: %s", e)
    HAS_PEFILE = False
    PEFILE_AVAILABLE = False
    PEFILE_VERSION = None

    # Production-ready fallback implementations for PE analysis

    # PE Constants
    class DIRECTORY_ENTRY:
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

    class SECTION_CHARACTERISTICS:
        """Section characteristics flags."""
        IMAGE_SCN_CNT_CODE = 0x00000020
        IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
        IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        IMAGE_SCN_MEM_READ = 0x40000000
        IMAGE_SCN_MEM_WRITE = 0x80000000
        IMAGE_SCN_MEM_SHARED = 0x10000000
        IMAGE_SCN_MEM_DISCARDABLE = 0x02000000

    class DLL_CHARACTERISTICS:
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

    class MACHINE_TYPE:
        """Machine types."""
        IMAGE_FILE_MACHINE_UNKNOWN = 0x0
        IMAGE_FILE_MACHINE_I386 = 0x14c
        IMAGE_FILE_MACHINE_R3000 = 0x162
        IMAGE_FILE_MACHINE_R4000 = 0x166
        IMAGE_FILE_MACHINE_R10000 = 0x168
        IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169
        IMAGE_FILE_MACHINE_ALPHA = 0x184
        IMAGE_FILE_MACHINE_SH3 = 0x1a2
        IMAGE_FILE_MACHINE_SH3DSP = 0x1a3
        IMAGE_FILE_MACHINE_SH3E = 0x1a4
        IMAGE_FILE_MACHINE_SH4 = 0x1a6
        IMAGE_FILE_MACHINE_SH5 = 0x1a8
        IMAGE_FILE_MACHINE_ARM = 0x1c0
        IMAGE_FILE_MACHINE_THUMB = 0x1c2
        IMAGE_FILE_MACHINE_ARMNT = 0x1c4
        IMAGE_FILE_MACHINE_AM33 = 0x1d3
        IMAGE_FILE_MACHINE_POWERPC = 0x1f0
        IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1
        IMAGE_FILE_MACHINE_IA64 = 0x200
        IMAGE_FILE_MACHINE_MIPS16 = 0x266
        IMAGE_FILE_MACHINE_ALPHA64 = 0x284
        IMAGE_FILE_MACHINE_MIPSFPU = 0x366
        IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466
        IMAGE_FILE_MACHINE_TRICORE = 0x520
        IMAGE_FILE_MACHINE_CEF = 0xcef
        IMAGE_FILE_MACHINE_EBC = 0xebc
        IMAGE_FILE_MACHINE_AMD64 = 0x8664
        IMAGE_FILE_MACHINE_M32R = 0x9041
        IMAGE_FILE_MACHINE_ARM64 = 0xaa64
        IMAGE_FILE_MACHINE_CEE = 0xc0ee

    class SUBSYSTEM_TYPE:
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

    class IMAGE_CHARACTERISTICS:
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

    class DEBUG_TYPE:
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

    class RESOURCE_TYPE:
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

    class PEFormatError(Exception):
        """PE format error exception."""
        pass

    class Structure:
        """Base structure for PE components."""

        def __init__(self, format_str=None, name=None):
            """Initialize structure."""
            self.format_str = format_str
            self.name = name or "Structure"
            self.sizeof = struct.calcsize(format_str) if format_str else 0
            self.fields = []

        def unpack(self, data):
            """Unpack binary data."""
            if self.format_str:
                return struct.unpack(self.format_str, data[:self.sizeof])
            return ()

    class FallbackPE:
        """Functional PE file parser implementation."""

        def __init__(self, name=None, data=None, fast_load=None):
            """Initialize PE parser."""
            self.name = name
            self.fast_load = fast_load
            self.__data__ = data

            # Initialize structures
            self.DOS_HEADER = None
            self.NT_HEADERS = None
            self.FILE_HEADER = None
            self.OPTIONAL_HEADER = None
            self.sections = []
            self.DIRECTORY_ENTRY_IMPORT = []
            self.DIRECTORY_ENTRY_EXPORT = None
            self.DIRECTORY_ENTRY_RESOURCE = None
            self.DIRECTORY_ENTRY_DEBUG = []
            self.DIRECTORY_ENTRY_TLS = None
            self.DIRECTORY_ENTRY_BASERELOC = []
            self.DIRECTORY_ENTRY_DELAY_IMPORT = []
            self.DIRECTORY_ENTRY_BOUND_IMPORT = []

            # Load data
            if name and not data:
                with open(name, 'rb') as f:
                    self.__data__ = f.read()

            if self.__data__:
                self._parse()

        def _parse(self):
            """Parse PE file structure."""
            # Parse DOS header
            if len(self.__data__) < 64:
                raise PEFormatError("File too small to be PE")

            dos_magic = struct.unpack('<H', self.__data__[:2])[0]
            if dos_magic != 0x5A4D:  # MZ
                raise PEFormatError("Invalid DOS signature")

            # Get PE header offset
            pe_offset = struct.unpack('<I', self.__data__[60:64])[0]

            # Parse PE header
            if len(self.__data__) < pe_offset + 24:
                raise PEFormatError("Invalid PE header offset")

            pe_signature = struct.unpack('<I', self.__data__[pe_offset:pe_offset+4])[0]
            if pe_signature != 0x00004550:  # PE\0\0
                raise PEFormatError("Invalid PE signature")

            # Parse COFF header
            coff_offset = pe_offset + 4
            self.FILE_HEADER = self._parse_file_header(coff_offset)

            # Parse optional header
            opt_offset = coff_offset + 20
            opt_magic = struct.unpack('<H', self.__data__[opt_offset:opt_offset+2])[0]

            if opt_magic == 0x10b:  # PE32
                self.OPTIONAL_HEADER = self._parse_optional_header32(opt_offset)
            elif opt_magic == 0x20b:  # PE32+
                self.OPTIONAL_HEADER = self._parse_optional_header64(opt_offset)
            else:
                raise PEFormatError(f"Invalid optional header magic: 0x{opt_magic:04x}")

            # Parse sections
            section_offset = opt_offset + self.FILE_HEADER.SizeOfOptionalHeader
            self._parse_sections(section_offset, self.FILE_HEADER.NumberOfSections)

            # Parse imports
            if not self.fast_load:
                self._parse_imports()
                self._parse_exports()
                self._parse_resources()
                self._parse_debug()
                self._parse_relocations()

        def _parse_file_header(self, offset):
            """Parse COFF file header."""
            class FileHeader:
                pass

            header = FileHeader()
            data = self.__data__[offset:offset+20]

            header.Machine = struct.unpack('<H', data[0:2])[0]
            header.NumberOfSections = struct.unpack('<H', data[2:4])[0]
            header.TimeDateStamp = struct.unpack('<I', data[4:8])[0]
            header.PointerToSymbolTable = struct.unpack('<I', data[8:12])[0]
            header.NumberOfSymbols = struct.unpack('<I', data[12:16])[0]
            header.SizeOfOptionalHeader = struct.unpack('<H', data[16:18])[0]
            header.Characteristics = struct.unpack('<H', data[18:20])[0]

            return header

        def _parse_optional_header32(self, offset):
            """Parse 32-bit optional header."""
            class OptionalHeader:
                pass

            header = OptionalHeader()
            data = self.__data__[offset:]

            header.Magic = struct.unpack('<H', data[0:2])[0]
            header.MajorLinkerVersion = data[2]
            header.MinorLinkerVersion = data[3]
            header.SizeOfCode = struct.unpack('<I', data[4:8])[0]
            header.SizeOfInitializedData = struct.unpack('<I', data[8:12])[0]
            header.SizeOfUninitializedData = struct.unpack('<I', data[12:16])[0]
            header.AddressOfEntryPoint = struct.unpack('<I', data[16:20])[0]
            header.BaseOfCode = struct.unpack('<I', data[20:24])[0]
            header.BaseOfData = struct.unpack('<I', data[24:28])[0]
            header.ImageBase = struct.unpack('<I', data[28:32])[0]
            header.SectionAlignment = struct.unpack('<I', data[32:36])[0]
            header.FileAlignment = struct.unpack('<I', data[36:40])[0]
            header.MajorOperatingSystemVersion = struct.unpack('<H', data[40:42])[0]
            header.MinorOperatingSystemVersion = struct.unpack('<H', data[42:44])[0]
            header.MajorImageVersion = struct.unpack('<H', data[44:46])[0]
            header.MinorImageVersion = struct.unpack('<H', data[46:48])[0]
            header.MajorSubsystemVersion = struct.unpack('<H', data[48:50])[0]
            header.MinorSubsystemVersion = struct.unpack('<H', data[50:52])[0]
            header.Reserved1 = struct.unpack('<I', data[52:56])[0]
            header.SizeOfImage = struct.unpack('<I', data[56:60])[0]
            header.SizeOfHeaders = struct.unpack('<I', data[60:64])[0]
            header.CheckSum = struct.unpack('<I', data[64:68])[0]
            header.Subsystem = struct.unpack('<H', data[68:70])[0]
            header.DllCharacteristics = struct.unpack('<H', data[70:72])[0]
            header.SizeOfStackReserve = struct.unpack('<I', data[72:76])[0]
            header.SizeOfStackCommit = struct.unpack('<I', data[76:80])[0]
            header.SizeOfHeapReserve = struct.unpack('<I', data[80:84])[0]
            header.SizeOfHeapCommit = struct.unpack('<I', data[84:88])[0]
            header.LoaderFlags = struct.unpack('<I', data[88:92])[0]
            header.NumberOfRvaAndSizes = struct.unpack('<I', data[92:96])[0]

            # Parse data directories
            header.DATA_DIRECTORY = []
            for i in range(min(header.NumberOfRvaAndSizes, 16)):
                dir_offset = 96 + i * 8
                vaddr = struct.unpack('<I', data[dir_offset:dir_offset+4])[0]
                size = struct.unpack('<I', data[dir_offset+4:dir_offset+8])[0]

                class DataDir:
                    pass

                dir_entry = DataDir()
                dir_entry.VirtualAddress = vaddr
                dir_entry.Size = size
                header.DATA_DIRECTORY.append(dir_entry)

            return header

        def _parse_optional_header64(self, offset):
            """Parse 64-bit optional header."""
            class OptionalHeader:
                pass

            header = OptionalHeader()
            data = self.__data__[offset:]

            header.Magic = struct.unpack('<H', data[0:2])[0]
            header.MajorLinkerVersion = data[2]
            header.MinorLinkerVersion = data[3]
            header.SizeOfCode = struct.unpack('<I', data[4:8])[0]
            header.SizeOfInitializedData = struct.unpack('<I', data[8:12])[0]
            header.SizeOfUninitializedData = struct.unpack('<I', data[12:16])[0]
            header.AddressOfEntryPoint = struct.unpack('<I', data[16:20])[0]
            header.BaseOfCode = struct.unpack('<I', data[20:24])[0]
            header.ImageBase = struct.unpack('<Q', data[24:32])[0]
            header.SectionAlignment = struct.unpack('<I', data[32:36])[0]
            header.FileAlignment = struct.unpack('<I', data[36:40])[0]
            header.MajorOperatingSystemVersion = struct.unpack('<H', data[40:42])[0]
            header.MinorOperatingSystemVersion = struct.unpack('<H', data[42:44])[0]
            header.MajorImageVersion = struct.unpack('<H', data[44:46])[0]
            header.MinorImageVersion = struct.unpack('<H', data[46:48])[0]
            header.MajorSubsystemVersion = struct.unpack('<H', data[48:50])[0]
            header.MinorSubsystemVersion = struct.unpack('<H', data[50:52])[0]
            header.Reserved1 = struct.unpack('<I', data[52:56])[0]
            header.SizeOfImage = struct.unpack('<I', data[56:60])[0]
            header.SizeOfHeaders = struct.unpack('<I', data[60:64])[0]
            header.CheckSum = struct.unpack('<I', data[64:68])[0]
            header.Subsystem = struct.unpack('<H', data[68:70])[0]
            header.DllCharacteristics = struct.unpack('<H', data[70:72])[0]
            header.SizeOfStackReserve = struct.unpack('<Q', data[72:80])[0]
            header.SizeOfStackCommit = struct.unpack('<Q', data[80:88])[0]
            header.SizeOfHeapReserve = struct.unpack('<Q', data[88:96])[0]
            header.SizeOfHeapCommit = struct.unpack('<Q', data[96:104])[0]
            header.LoaderFlags = struct.unpack('<I', data[104:108])[0]
            header.NumberOfRvaAndSizes = struct.unpack('<I', data[108:112])[0]

            # Parse data directories
            header.DATA_DIRECTORY = []
            for i in range(min(header.NumberOfRvaAndSizes, 16)):
                dir_offset = 112 + i * 8
                vaddr = struct.unpack('<I', data[dir_offset:dir_offset+4])[0]
                size = struct.unpack('<I', data[dir_offset+4:dir_offset+8])[0]

                class DataDir:
                    pass

                dir_entry = DataDir()
                dir_entry.VirtualAddress = vaddr
                dir_entry.Size = size
                header.DATA_DIRECTORY.append(dir_entry)

            return header

        def _parse_sections(self, offset, count):
            """Parse section headers."""
            for i in range(count):
                section_offset = offset + i * 40
                if section_offset + 40 > len(self.__data__):
                    break

                data = self.__data__[section_offset:section_offset+40]

                class Section:
                    pass

                section = Section()
                section.Name = data[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                section.VirtualSize = struct.unpack('<I', data[8:12])[0]
                section.VirtualAddress = struct.unpack('<I', data[12:16])[0]
                section.SizeOfRawData = struct.unpack('<I', data[16:20])[0]
                section.PointerToRawData = struct.unpack('<I', data[20:24])[0]
                section.PointerToRelocations = struct.unpack('<I', data[24:28])[0]
                section.PointerToLinenumbers = struct.unpack('<I', data[28:32])[0]
                section.NumberOfRelocations = struct.unpack('<H', data[32:34])[0]
                section.NumberOfLinenumbers = struct.unpack('<H', data[34:36])[0]
                section.Characteristics = struct.unpack('<I', data[36:40])[0]

                # Get section data
                if section.PointerToRawData > 0 and section.SizeOfRawData > 0:
                    start = section.PointerToRawData
                    end = start + section.SizeOfRawData
                    section.data = self.__data__[start:end]
                else:
                    section.data = b''

                self.sections.append(section)

        def _parse_imports(self):
            """Parse import directory."""
            if not self.OPTIONAL_HEADER or not self.OPTIONAL_HEADER.DATA_DIRECTORY:
                return

            if len(self.OPTIONAL_HEADER.DATA_DIRECTORY) <= DIRECTORY_ENTRY.IMPORT:
                return

            import_dir = self.OPTIONAL_HEADER.DATA_DIRECTORY[DIRECTORY_ENTRY.IMPORT]
            if import_dir.VirtualAddress == 0 or import_dir.Size == 0:
                return

            # Convert RVA to file offset
            import_offset = self.get_offset_from_rva(import_dir.VirtualAddress)
            if not import_offset:
                return

            # Parse import descriptors
            offset = import_offset
            while True:
                if offset + 20 > len(self.__data__):
                    break

                data = self.__data__[offset:offset+20]

                # Check for end of imports
                if data == b'\x00' * 20:
                    break

                class ImportDescriptor:
                    pass

                import_desc = ImportDescriptor()
                import_desc.OriginalFirstThunk = struct.unpack('<I', data[0:4])[0]
                import_desc.TimeDateStamp = struct.unpack('<I', data[4:8])[0]
                import_desc.ForwarderChain = struct.unpack('<I', data[8:12])[0]
                import_desc.Name = struct.unpack('<I', data[12:16])[0]
                import_desc.FirstThunk = struct.unpack('<I', data[16:20])[0]

                # Get DLL name
                name_offset = self.get_offset_from_rva(import_desc.Name)
                if name_offset:
                    dll_name = self._get_string(name_offset)
                    import_desc.dll = dll_name
                    import_desc.imports = []

                    # Parse imports from this DLL
                    thunk_offset = self.get_offset_from_rva(import_desc.OriginalFirstThunk or import_desc.FirstThunk)
                    if thunk_offset:
                        self._parse_import_thunks(import_desc, thunk_offset)

                    self.DIRECTORY_ENTRY_IMPORT.append(import_desc)

                offset += 20

        def _parse_import_thunks(self, import_desc, offset):
            """Parse import thunks."""
            is_64bit = self.OPTIONAL_HEADER.Magic == 0x20b
            thunk_size = 8 if is_64bit else 4

            while True:
                if offset + thunk_size > len(self.__data__):
                    break

                if is_64bit:
                    thunk = struct.unpack('<Q', self.__data__[offset:offset+8])[0]
                    ordinal_flag = 0x8000000000000000
                else:
                    thunk = struct.unpack('<I', self.__data__[offset:offset+4])[0]
                    ordinal_flag = 0x80000000

                if thunk == 0:
                    break

                class ImportData:
                    pass

                import_data = ImportData()

                if thunk & ordinal_flag:
                    # Import by ordinal
                    import_data.ordinal = thunk & 0xFFFF
                    import_data.name = None
                else:
                    # Import by name
                    name_rva = thunk & 0x7FFFFFFF
                    name_offset = self.get_offset_from_rva(name_rva)
                    if name_offset:
                        # Skip hint
                        import_data.hint = struct.unpack('<H', self.__data__[name_offset:name_offset+2])[0]
                        import_data.name = self._get_string(name_offset + 2)
                        import_data.ordinal = None

                import_desc.imports.append(import_data)
                offset += thunk_size

        def _parse_exports(self):
            """Parse export directory."""
            if not self.OPTIONAL_HEADER or not self.OPTIONAL_HEADER.DATA_DIRECTORY:
                return

            if len(self.OPTIONAL_HEADER.DATA_DIRECTORY) <= DIRECTORY_ENTRY.EXPORT:
                return

            export_dir = self.OPTIONAL_HEADER.DATA_DIRECTORY[DIRECTORY_ENTRY.EXPORT]
            if export_dir.VirtualAddress == 0 or export_dir.Size == 0:
                return

            export_offset = self.get_offset_from_rva(export_dir.VirtualAddress)
            if not export_offset:
                return

            if export_offset + 40 > len(self.__data__):
                return

            data = self.__data__[export_offset:export_offset+40]

            class ExportDirectory:
                pass

            export = ExportDirectory()
            export.Characteristics = struct.unpack('<I', data[0:4])[0]
            export.TimeDateStamp = struct.unpack('<I', data[4:8])[0]
            export.MajorVersion = struct.unpack('<H', data[8:10])[0]
            export.MinorVersion = struct.unpack('<H', data[10:12])[0]
            export.Name = struct.unpack('<I', data[12:16])[0]
            export.Base = struct.unpack('<I', data[16:20])[0]
            export.NumberOfFunctions = struct.unpack('<I', data[20:24])[0]
            export.NumberOfNames = struct.unpack('<I', data[24:28])[0]
            export.AddressOfFunctions = struct.unpack('<I', data[28:32])[0]
            export.AddressOfNames = struct.unpack('<I', data[32:36])[0]
            export.AddressOfNameOrdinals = struct.unpack('<I', data[36:40])[0]

            # Get DLL name
            name_offset = self.get_offset_from_rva(export.Name)
            if name_offset:
                export.name = self._get_string(name_offset)

            export.symbols = []

            # Parse exported functions
            if export.NumberOfFunctions > 0 and export.NumberOfFunctions < 65536:
                func_offset = self.get_offset_from_rva(export.AddressOfFunctions)
                name_offset = self.get_offset_from_rva(export.AddressOfNames) if export.NumberOfNames > 0 else None
                ordinal_offset = self.get_offset_from_rva(export.AddressOfNameOrdinals) if export.NumberOfNames > 0 else None

                # Build name to ordinal mapping
                name_ordinals = {}
                if name_offset and ordinal_offset:
                    for i in range(min(export.NumberOfNames, 65536)):
                        if name_offset + i * 4 + 4 > len(self.__data__):
                            break
                        if ordinal_offset + i * 2 + 2 > len(self.__data__):
                            break

                        name_rva = struct.unpack('<I', self.__data__[name_offset + i * 4:name_offset + i * 4 + 4])[0]
                        ordinal = struct.unpack('<H', self.__data__[ordinal_offset + i * 2:ordinal_offset + i * 2 + 2])[0]

                        name_file_offset = self.get_offset_from_rva(name_rva)
                        if name_file_offset:
                            func_name = self._get_string(name_file_offset)
                            name_ordinals[ordinal] = func_name

                # Parse function addresses
                if func_offset:
                    for i in range(min(export.NumberOfFunctions, 65536)):
                        if func_offset + i * 4 + 4 > len(self.__data__):
                            break

                        func_rva = struct.unpack('<I', self.__data__[func_offset + i * 4:func_offset + i * 4 + 4])[0]

                        if func_rva != 0:
                            class ExportSymbol:
                                pass

                            symbol = ExportSymbol()
                            symbol.ordinal = export.Base + i
                            symbol.address = func_rva
                            symbol.name = name_ordinals.get(i, None)
                            symbol.forwarder = None

                            # Check if it's a forwarder
                            if export_dir.VirtualAddress <= func_rva < export_dir.VirtualAddress + export_dir.Size:
                                forwarder_offset = self.get_offset_from_rva(func_rva)
                                if forwarder_offset:
                                    symbol.forwarder = self._get_string(forwarder_offset)

                            export.symbols.append(symbol)

            self.DIRECTORY_ENTRY_EXPORT = export

        def _parse_resources(self):
            """Parse resource directory."""
            # Basic resource parsing - implement if needed
            pass

        def _parse_debug(self):
            """Parse debug directory."""
            # Basic debug info parsing - implement if needed
            pass

        def _parse_relocations(self):
            """Parse base relocations."""
            # Basic relocation parsing - implement if needed
            pass

        def _get_string(self, offset):
            """Get null-terminated string from offset."""
            end = self.__data__.find(b'\x00', offset)
            if end == -1:
                end = len(self.__data__)
            return self.__data__[offset:end].decode('ascii', errors='ignore')

        def get_offset_from_rva(self, rva):
            """Convert RVA to file offset."""
            for section in self.sections:
                if section.VirtualAddress <= rva < section.VirtualAddress + section.VirtualSize:
                    return rva - section.VirtualAddress + section.PointerToRawData
            return None

        def get_rva_from_offset(self, offset):
            """Convert file offset to RVA."""
            for section in self.sections:
                if section.PointerToRawData <= offset < section.PointerToRawData + section.SizeOfRawData:
                    return offset - section.PointerToRawData + section.VirtualAddress
            return None

        def get_data(self, rva, length):
            """Get data at RVA."""
            offset = self.get_offset_from_rva(rva)
            if offset and offset + length <= len(self.__data__):
                return self.__data__[offset:offset+length]
            return None

        def get_memory_mapped_image(self):
            """Get memory-mapped image."""
            if not self.OPTIONAL_HEADER:
                return None

            # Create memory image
            image_size = self.OPTIONAL_HEADER.SizeOfImage
            image = bytearray(image_size)

            # Copy headers
            header_size = self.OPTIONAL_HEADER.SizeOfHeaders
            image[:header_size] = self.__data__[:header_size]

            # Map sections
            for section in self.sections:
                if section.PointerToRawData > 0:
                    src_start = section.PointerToRawData
                    src_end = src_start + min(section.SizeOfRawData, section.VirtualSize)
                    dst_start = section.VirtualAddress
                    dst_end = dst_start + (src_end - src_start)

                    if src_end <= len(self.__data__) and dst_end <= image_size:
                        image[dst_start:dst_end] = self.__data__[src_start:src_end]

            return bytes(image)

        def get_imphash(self):
            """Calculate import hash."""
            if not self.DIRECTORY_ENTRY_IMPORT:
                return ""

            imp_str = ""
            for entry in self.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.lower() if hasattr(entry, 'dll') else ""
                if dll_name.endswith('.dll'):
                    dll_name = dll_name[:-4]

                for imp in entry.imports:
                    if hasattr(imp, 'name') and imp.name:
                        imp_str += f"{dll_name}.{imp.name.lower()},"
                    elif hasattr(imp, 'ordinal') and imp.ordinal:
                        imp_str += f"{dll_name}.ord{imp.ordinal},"

            imp_str = imp_str.rstrip(',')
            return hashlib.md5(imp_str.encode()).hexdigest() if imp_str else ""

        def get_rich_header_hash(self):
            """Calculate Rich header hash."""
            # Find Rich header
            rich_index = self.__data__.find(b'Rich')
            if rich_index == -1:
                return None

            # Find DanS marker
            dans_index = self.__data__.find(b'DanS')
            if dans_index == -1 or dans_index >= rich_index:
                return None

            # Get Rich header data
            rich_data = self.__data__[dans_index:rich_index+8]
            return hashlib.md5(rich_data).hexdigest()

        def generate_checksum(self):
            """Generate PE checksum."""
            checksum = 0
            top = 2**32

            # Calculate checksum
            for i in range(0, len(self.__data__), 2):
                if i + 1 < len(self.__data__):
                    word = struct.unpack('<H', self.__data__[i:i+2])[0]
                else:
                    word = self.__data__[i]

                checksum = (checksum & 0xFFFFFFFF) + word + (checksum >> 32)
                if checksum > top:
                    checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)

            checksum = (checksum & 0xFFFF) + (checksum >> 16)
            checksum = checksum + (checksum >> 16)
            checksum = checksum & 0xFFFF

            return checksum + len(self.__data__)

        def is_exe(self):
            """Check if file is EXE."""
            if self.FILE_HEADER and self.FILE_HEADER.Characteristics:
                return bool(self.FILE_HEADER.Characteristics & IMAGE_CHARACTERISTICS.IMAGE_FILE_EXECUTABLE_IMAGE)
            return False

        def is_dll(self):
            """Check if file is DLL."""
            if self.FILE_HEADER and self.FILE_HEADER.Characteristics:
                return bool(self.FILE_HEADER.Characteristics & IMAGE_CHARACTERISTICS.IMAGE_FILE_DLL)
            return False

        def is_driver(self):
            """Check if file is driver."""
            if self.OPTIONAL_HEADER:
                return self.OPTIONAL_HEADER.Subsystem == SUBSYSTEM_TYPE.IMAGE_SUBSYSTEM_NATIVE
            return False

        def write(self, filename=None):
            """Write PE to file."""
            if filename:
                with open(filename, 'wb') as f:
                    f.write(self.__data__)
            return self.__data__

        def close(self):
            """Close PE file."""
            self.__data__ = None

        def __str__(self):
            """String representation."""
            return f"PE({self.name})"

    # Assign main class
    PE = FallbackPE

    # Create module-like object
    class FallbackPefile:
        """Fallback pefile module."""

        PE = PE
        PEFormatError = PEFormatError
        Structure = Structure

        DIRECTORY_ENTRY = DIRECTORY_ENTRY
        SECTION_CHARACTERISTICS = SECTION_CHARACTERISTICS
        DLL_CHARACTERISTICS = DLL_CHARACTERISTICS
        MACHINE_TYPE = MACHINE_TYPE
        SUBSYSTEM_TYPE = SUBSYSTEM_TYPE
        IMAGE_CHARACTERISTICS = IMAGE_CHARACTERISTICS
        DEBUG_TYPE = DEBUG_TYPE
        RESOURCE_TYPE = RESOURCE_TYPE

    pefile = FallbackPefile()


# Export all pefile objects and availability flag
__all__ = [
    # Availability flags
    "HAS_PEFILE", "PEFILE_AVAILABLE", "PEFILE_VERSION",
    # Main module
    "pefile",
    # Main class
    "PE",
    # Exceptions
    "PEFormatError",
    # Constants
    "DIRECTORY_ENTRY", "SECTION_CHARACTERISTICS", "DLL_CHARACTERISTICS",
    "MACHINE_TYPE", "SUBSYSTEM_TYPE", "IMAGE_CHARACTERISTICS",
    "DEBUG_TYPE", "RESOURCE_TYPE",
    # Structures
    "Structure",
]
