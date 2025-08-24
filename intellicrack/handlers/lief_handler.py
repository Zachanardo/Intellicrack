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

import os
import struct

from intellicrack.logger import logger

"""
LIEF Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for LIEF imports.
When LIEF is not available, it provides REAL, functional Python-based
implementations for essential binary parsing operations.
"""

# LIEF availability detection and import handling
try:
    import lief

    # Import individual modules as LIEF structure has changed
    from lief import ELF, PE, MachO, is_elf, is_macho, is_pe, parse

    # Try to import architecture constants - these may have moved
    try:
        from lief import ARCHITECTURES, ENDIANNESS, MODES
    except ImportError:
        # Create fallback classes if not available
        ARCHITECTURES = None
        ENDIANNESS = None
        MODES = None

    # Import available classes
    try:
        from lief import Binary, Function, Section, Symbol
    except ImportError:
        Binary = None
        Function = None
        Section = None
        Symbol = None

    HAS_LIEF = True
    LIEF_VERSION = lief.__version__

except ImportError as e:
    logger.error("LIEF not available, using fallback implementations: %s", e)
    HAS_LIEF = False
    LIEF_VERSION = None

    # Production-ready fallback implementations for binary analysis

    # Architecture constants
    class ARCHITECTURES:
        """Binary architectures."""
        NONE = 0
        X86 = 1
        X64 = 2
        ARM = 3
        ARM64 = 4
        MIPS = 5
        PPC = 6

    class ENDIANNESS:
        """Byte order."""
        LITTLE = 0
        BIG = 1

    class MODES:
        """Execution modes."""
        MODE_32 = 0
        MODE_64 = 1
        THUMB = 2
        ARM = 3

    class FallbackSection:
        """Functional section implementation for binary sections."""

        def __init__(self, name="", offset=0, size=0, virtual_address=0, virtual_size=0, characteristics=0):
            """Initialize section."""
            self.name = name
            self.offset = offset
            self.size = size
            self.virtual_address = virtual_address
            self.virtual_size = virtual_size if virtual_size else size
            self.characteristics = characteristics
            self.content = b""
            self.entropy = 0.0

        def __str__(self):
            """String representation."""
            return f"Section({self.name}, VA=0x{self.virtual_address:08x}, Size={self.size})"

        def __repr__(self):
            """Representation."""
            return self.__str__()

    class FallbackSymbol:
        """Functional symbol implementation."""

        def __init__(self, name="", value=0, size=0, type="", binding=""):
            """Initialize symbol."""
            self.name = name
            self.value = value
            self.size = size
            self.type = type
            self.binding = binding
            self.section = None

        def __str__(self):
            """String representation."""
            return f"Symbol({self.name}, 0x{self.value:08x})"

        def __repr__(self):
            """Representation."""
            return self.__str__()

    class FallbackFunction:
        """Functional function implementation."""

        def __init__(self, name="", address=0, size=0):
            """Initialize function."""
            self.name = name
            self.address = address
            self.size = size

        def __str__(self):
            """String representation."""
            return f"Function({self.name}, 0x{self.address:08x})"

        def __repr__(self):
            """Representation."""
            return self.__str__()

    class FallbackBinary:
        """Base binary implementation with real parsing capabilities."""

        def __init__(self, path=""):
            """Initialize binary."""
            self.path = path
            self.name = os.path.basename(path) if path else ""
            self.size = 0
            self.entrypoint = 0
            self.imagebase = 0
            self.sections = []
            self.symbols = []
            self.functions = []
            self.imports = []
            self.exports = []
            self.libraries = []
            self.format = "UNKNOWN"
            self.architecture = ARCHITECTURES.NONE
            self.endianness = ENDIANNESS.LITTLE
            self.mode = MODES.MODE_32
            self.header = {}

            if path and os.path.exists(path):
                self.size = os.path.getsize(path)
                self._parse_file()

        def _parse_file(self):
            """Parse the binary file to detect format and extract basic info."""
            try:
                with open(self.path, 'rb') as f:
                    # Read first bytes for magic detection
                    magic = f.read(4)
                    f.seek(0)

                    if magic[:2] == b'MZ':
                        self._parse_pe(f)
                    elif magic == b'\x7fELF':
                        self._parse_elf(f)
                    elif magic in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                                  b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe'):
                        self._parse_macho(f)
                    else:
                        self.format = "UNKNOWN"

            except Exception as e:
                logger.error("Failed to parse binary %s: %s", self.path, e)

        def _parse_pe(self, f):
            """Parse PE format binary."""
            self.format = "PE"

            try:
                # Read DOS header
                dos_header = f.read(64)
                if len(dos_header) < 64:
                    return

                # Get PE header offset
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]
                f.seek(pe_offset)

                # Read PE signature
                signature = f.read(4)
                if signature != b'PE\x00\x00':
                    return

                # Read COFF header
                machine = struct.unpack('<H', f.read(2))[0]
                num_sections = struct.unpack('<H', f.read(2))[0]
                f.read(12)  # Skip timestamp, symbol table, num symbols
                opt_header_size = struct.unpack('<H', f.read(2))[0]
                characteristics = struct.unpack('<H', f.read(2))[0]

                # Determine architecture
                if machine == 0x14c:  # IMAGE_FILE_MACHINE_I386
                    self.architecture = ARCHITECTURES.X86
                    self.mode = MODES.MODE_32
                elif machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                    self.architecture = ARCHITECTURES.X64
                    self.mode = MODES.MODE_64
                elif machine == 0x1c0:  # IMAGE_FILE_MACHINE_ARM
                    self.architecture = ARCHITECTURES.ARM
                elif machine == 0xaa64:  # IMAGE_FILE_MACHINE_ARM64
                    self.architecture = ARCHITECTURES.ARM64

                # Read optional header
                if opt_header_size > 0:
                    opt_magic = struct.unpack('<H', f.read(2))[0]

                    if opt_magic == 0x10b:  # PE32
                        f.read(22)  # Skip to AddressOfEntryPoint
                        self.entrypoint = struct.unpack('<I', f.read(4))[0]
                        f.read(4)  # BaseOfCode
                        f.read(4)  # BaseOfData
                        self.imagebase = struct.unpack('<I', f.read(4))[0]
                    elif opt_magic == 0x20b:  # PE32+
                        f.read(22)  # Skip to AddressOfEntryPoint
                        self.entrypoint = struct.unpack('<I', f.read(4))[0]
                        f.read(4)  # BaseOfCode
                        self.imagebase = struct.unpack('<Q', f.read(8))[0]

                    # Skip rest of optional header
                    f.seek(pe_offset + 24 + opt_header_size)

                # Read section headers
                for _i in range(num_sections):
                    section_data = f.read(40)
                    if len(section_data) < 40:
                        break

                    name = section_data[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                    virtual_size = struct.unpack('<I', section_data[8:12])[0]
                    virtual_address = struct.unpack('<I', section_data[12:16])[0]
                    size_of_raw_data = struct.unpack('<I', section_data[16:20])[0]
                    pointer_to_raw_data = struct.unpack('<I', section_data[20:24])[0]
                    characteristics = struct.unpack('<I', section_data[36:40])[0]

                    section = FallbackSection(
                        name=name,
                        offset=pointer_to_raw_data,
                        size=size_of_raw_data,
                        virtual_address=virtual_address,
                        virtual_size=virtual_size,
                        characteristics=characteristics
                    )
                    self.sections.append(section)

            except Exception as e:
                logger.error("Failed to parse PE binary: %s", e)

        def _parse_elf(self, f):
            """Parse ELF format binary."""
            self.format = "ELF"

            try:
                # Read ELF header
                elf_header = f.read(64)
                if len(elf_header) < 52:
                    return

                # Parse ELF identification
                ei_class = elf_header[4]  # 32-bit or 64-bit
                ei_data = elf_header[5]   # Endianness

                if ei_class == 1:  # ELFCLASS32
                    self.mode = MODES.MODE_32
                elif ei_class == 2:  # ELFCLASS64
                    self.mode = MODES.MODE_64
                else:
                    return

                if ei_data == 1:  # ELFDATA2LSB
                    self.endianness = ENDIANNESS.LITTLE
                    endian = '<'
                elif ei_data == 2:  # ELFDATA2MSB
                    self.endianness = ENDIANNESS.BIG
                    endian = '>'
                else:
                    return

                # Parse rest of header based on architecture
                if self.mode == MODES.MODE_32:
                    struct.unpack(endian + 'H', elf_header[16:18])[0]
                    e_machine = struct.unpack(endian + 'H', elf_header[18:20])[0]
                    self.entrypoint = struct.unpack(endian + 'I', elf_header[24:28])[0]
                    struct.unpack(endian + 'I', elf_header[28:32])[0]
                    e_shoff = struct.unpack(endian + 'I', elf_header[32:36])[0]
                    struct.unpack(endian + 'H', elf_header[44:46])[0]
                    e_shnum = struct.unpack(endian + 'H', elf_header[48:50])[0]
                    e_shstrndx = struct.unpack(endian + 'H', elf_header[50:52])[0]
                else:  # 64-bit
                    struct.unpack(endian + 'H', elf_header[16:18])[0]
                    e_machine = struct.unpack(endian + 'H', elf_header[18:20])[0]
                    self.entrypoint = struct.unpack(endian + 'Q', elf_header[24:32])[0]
                    struct.unpack(endian + 'Q', elf_header[32:40])[0]
                    e_shoff = struct.unpack(endian + 'Q', elf_header[40:48])[0]
                    struct.unpack(endian + 'H', elf_header[56:58])[0]
                    e_shnum = struct.unpack(endian + 'H', elf_header[60:62])[0]
                    e_shstrndx = struct.unpack(endian + 'H', elf_header[62:64])[0]

                # Determine architecture from machine type
                if e_machine == 0x03:  # EM_386
                    self.architecture = ARCHITECTURES.X86
                elif e_machine == 0x3e:  # EM_X86_64
                    self.architecture = ARCHITECTURES.X64
                elif e_machine == 0x28:  # EM_ARM
                    self.architecture = ARCHITECTURES.ARM
                elif e_machine == 0xb7:  # EM_AARCH64
                    self.architecture = ARCHITECTURES.ARM64
                elif e_machine == 0x08:  # EM_MIPS
                    self.architecture = ARCHITECTURES.MIPS
                elif e_machine == 0x14:  # EM_PPC
                    self.architecture = ARCHITECTURES.PPC

                # Read section headers if present
                if e_shoff > 0 and e_shnum > 0:
                    # First read string table
                    if e_shstrndx < e_shnum:
                        if self.mode == MODES.MODE_32:
                            sh_size = 40
                        else:
                            sh_size = 64

                        # Get string table section header
                        f.seek(e_shoff + e_shstrndx * sh_size)
                        shstrtab_header = f.read(sh_size)

                        if self.mode == MODES.MODE_32:
                            shstrtab_offset = struct.unpack(endian + 'I', shstrtab_header[16:20])[0]
                            shstrtab_size = struct.unpack(endian + 'I', shstrtab_header[20:24])[0]
                        else:
                            shstrtab_offset = struct.unpack(endian + 'Q', shstrtab_header[24:32])[0]
                            shstrtab_size = struct.unpack(endian + 'Q', shstrtab_header[32:40])[0]

                        # Read string table
                        f.seek(shstrtab_offset)
                        string_table = f.read(shstrtab_size)
                    else:
                        string_table = b""

                    # Read all section headers
                    f.seek(e_shoff)
                    for i in range(min(e_shnum, 100)):  # Limit sections to prevent excessive memory
                        section_header = f.read(sh_size)
                        if len(section_header) < sh_size:
                            break

                        if self.mode == MODES.MODE_32:
                            sh_name = struct.unpack(endian + 'I', section_header[0:4])[0]
                            struct.unpack(endian + 'I', section_header[4:8])[0]
                            struct.unpack(endian + 'I', section_header[8:12])[0]
                            sh_addr = struct.unpack(endian + 'I', section_header[12:16])[0]
                            sh_offset = struct.unpack(endian + 'I', section_header[16:20])[0]
                            sh_size = struct.unpack(endian + 'I', section_header[20:24])[0]
                        else:
                            sh_name = struct.unpack(endian + 'I', section_header[0:4])[0]
                            struct.unpack(endian + 'I', section_header[4:8])[0]
                            struct.unpack(endian + 'Q', section_header[8:16])[0]
                            sh_addr = struct.unpack(endian + 'Q', section_header[16:24])[0]
                            sh_offset = struct.unpack(endian + 'Q', section_header[24:32])[0]
                            sh_size = struct.unpack(endian + 'Q', section_header[32:40])[0]

                        # Get section name from string table
                        if sh_name < len(string_table):
                            name_end = string_table.find(b'\x00', sh_name)
                            if name_end >= 0:
                                name = string_table[sh_name:name_end].decode('ascii', errors='ignore')
                            else:
                                name = string_table[sh_name:].decode('ascii', errors='ignore')
                        else:
                            name = f".section{i}"

                        section = FallbackSection(
                            name=name,
                            offset=sh_offset,
                            size=sh_size,
                            virtual_address=sh_addr,
                            virtual_size=sh_size
                        )
                        self.sections.append(section)

            except Exception as e:
                logger.error("Failed to parse ELF binary: %s", e)

        def _parse_macho(self, f):
            """Parse Mach-O format binary."""
            self.format = "MACHO"

            try:
                # Read magic
                magic = struct.unpack('<I', f.read(4))[0]

                # Determine architecture and endianness
                if magic == 0xfeedface:  # MH_MAGIC
                    self.mode = MODES.MODE_32
                    self.endianness = ENDIANNESS.LITTLE
                    endian = '<'
                elif magic == 0xcefaedfe:  # MH_CIGAM
                    self.mode = MODES.MODE_32
                    self.endianness = ENDIANNESS.BIG
                    endian = '>'
                elif magic == 0xfeedfacf:  # MH_MAGIC_64
                    self.mode = MODES.MODE_64
                    self.endianness = ENDIANNESS.LITTLE
                    endian = '<'
                elif magic == 0xcffaedfe:  # MH_CIGAM_64
                    self.mode = MODES.MODE_64
                    self.endianness = ENDIANNESS.BIG
                    endian = '>'
                else:
                    return

                # Read header
                cputype = struct.unpack(endian + 'I', f.read(4))[0]
                struct.unpack(endian + 'I', f.read(4))[0]
                struct.unpack(endian + 'I', f.read(4))[0]
                ncmds = struct.unpack(endian + 'I', f.read(4))[0]
                struct.unpack(endian + 'I', f.read(4))[0]
                struct.unpack(endian + 'I', f.read(4))[0]

                if self.mode == MODES.MODE_64:
                    struct.unpack(endian + 'I', f.read(4))[0]

                # Determine architecture
                if cputype == 0x7:  # CPU_TYPE_X86
                    self.architecture = ARCHITECTURES.X86
                elif cputype == 0x1000007:  # CPU_TYPE_X86_64
                    self.architecture = ARCHITECTURES.X64
                elif cputype == 0xc:  # CPU_TYPE_ARM
                    self.architecture = ARCHITECTURES.ARM
                elif cputype == 0x100000c:  # CPU_TYPE_ARM64
                    self.architecture = ARCHITECTURES.ARM64
                elif cputype == 0x12:  # CPU_TYPE_POWERPC
                    self.architecture = ARCHITECTURES.PPC

                # Read load commands to find segments
                for _i in range(min(ncmds, 100)):  # Limit commands
                    cmd_pos = f.tell()
                    cmd = struct.unpack(endian + 'I', f.read(4))[0]
                    cmdsize = struct.unpack(endian + 'I', f.read(4))[0]

                    if cmd == 0x1:  # LC_SEGMENT
                        segname = f.read(16).rstrip(b'\x00').decode('ascii', errors='ignore')
                        vmaddr = struct.unpack(endian + 'I', f.read(4))[0]
                        vmsize = struct.unpack(endian + 'I', f.read(4))[0]
                        fileoff = struct.unpack(endian + 'I', f.read(4))[0]
                        filesize = struct.unpack(endian + 'I', f.read(4))[0]

                        section = FallbackSection(
                            name=segname,
                            offset=fileoff,
                            size=filesize,
                            virtual_address=vmaddr,
                            virtual_size=vmsize
                        )
                        self.sections.append(section)

                    elif cmd == 0x19:  # LC_SEGMENT_64
                        segname = f.read(16).rstrip(b'\x00').decode('ascii', errors='ignore')
                        vmaddr = struct.unpack(endian + 'Q', f.read(8))[0]
                        vmsize = struct.unpack(endian + 'Q', f.read(8))[0]
                        fileoff = struct.unpack(endian + 'Q', f.read(8))[0]
                        filesize = struct.unpack(endian + 'Q', f.read(8))[0]

                        section = FallbackSection(
                            name=segname,
                            offset=fileoff,
                            size=filesize,
                            virtual_address=vmaddr,
                            virtual_size=vmsize
                        )
                        self.sections.append(section)

                    # Move to next command
                    f.seek(cmd_pos + cmdsize)

            except Exception as e:
                logger.error("Failed to parse Mach-O binary: %s", e)

        def __str__(self):
            """String representation."""
            return f"{self.format}({self.name})"

        def __repr__(self):
            """Representation."""
            return self.__str__()

    class FallbackPE(FallbackBinary):
        """PE specific binary implementation."""

        def __init__(self, path=""):
            """Initialize PE binary."""
            super().__init__(path)
            self.dos_header = {}
            self.header = {}
            self.optional_header = {}
            self.data_directories = []
            self.imports = []
            self.exports = []
            self.resources = []
            self.tls = None
            self.relocations = []
            self.signature = None

    class FallbackELF(FallbackBinary):
        """ELF specific binary implementation."""

        def __init__(self, path=""):
            """Initialize ELF binary."""
            super().__init__(path)
            self.segments = []
            self.dynamic_entries = []
            self.notes = []
            self.interpreter = ""
            self.gnu_hash = None
            self.sysv_hash = None

    class FallbackMachO(FallbackBinary):
        """Mach-O specific binary implementation."""

        def __init__(self, path=""):
            """Initialize Mach-O binary."""
            super().__init__(path)
            self.commands = []
            self.uuid = None
            self.main_command = None
            self.code_signature = None
            self.dylibs = []
            self.rpaths = []

    def parse(filepath):
        """Parse a binary file and return appropriate object."""
        if not os.path.exists(filepath):
            logger.error("File not found: %s", filepath)
            return None

        try:
            with open(filepath, 'rb') as f:
                magic = f.read(4)

                if magic[:2] == b'MZ':
                    return FallbackPE(filepath)
                elif magic == b'\x7fELF':
                    return FallbackELF(filepath)
                elif magic in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                              b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe'):
                    return FallbackMachO(filepath)
                else:
                    return FallbackBinary(filepath)

        except Exception as e:
            logger.error("Failed to parse binary %s: %s", filepath, e)
            return None

    def is_pe(filepath):
        """Check if file is PE format."""
        try:
            with open(filepath, 'rb') as f:
                magic = f.read(2)
                return magic == b'MZ'
        except Exception:
            return False

    def is_elf(filepath):
        """Check if file is ELF format."""
        try:
            with open(filepath, 'rb') as f:
                magic = f.read(4)
                return magic == b'\x7fELF'
        except Exception:
            return False

    def is_macho(filepath):
        """Check if file is Mach-O format."""
        try:
            with open(filepath, 'rb') as f:
                magic = f.read(4)
                return magic in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                                b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe')
        except Exception:
            return False

    # Assign classes
    Binary = FallbackBinary
    Section = FallbackSection
    Symbol = FallbackSymbol
    Function = FallbackFunction
    PE = FallbackPE
    ELF = FallbackELF
    MachO = FallbackMachO

    # Create module-like object
    class FallbackLIEF:
        """Fallback LIEF module."""

        # Classes
        Binary = Binary
        Section = Section
        Symbol = Symbol
        Function = Function
        PE = PE
        ELF = ELF
        MachO = MachO

        # Constants
        ARCHITECTURES = ARCHITECTURES
        ENDIANNESS = ENDIANNESS
        MODES = MODES

        # Functions
        parse = staticmethod(parse)
        is_pe = staticmethod(is_pe)
        is_elf = staticmethod(is_elf)
        is_macho = staticmethod(is_macho)

    lief = FallbackLIEF()

    # Export constants at module level
    Binary = FallbackBinary
    Section = FallbackSection
    Symbol = FallbackSymbol
    Function = FallbackFunction
    PE = PE
    ELF = ELF
    MachO = MachO
    ARCHITECTURES = ARCHITECTURES
    ENDIANNESS = ENDIANNESS
    MODES = MODES
    parse = parse
    is_pe = is_pe
    is_elf = is_elf
    is_macho = is_macho


# Export all LIEF objects and availability flag
__all__ = [
    # Availability flags
    "HAS_LIEF", "LIEF_VERSION",
    # Main module
    "lief",
    # Core classes
    "Binary", "Section", "Symbol", "Function",
    "PE", "ELF", "MachO",
    # Constants
    "ARCHITECTURES", "ENDIANNESS", "MODES",
    # Functions
    "parse", "is_pe", "is_elf", "is_macho",
]
