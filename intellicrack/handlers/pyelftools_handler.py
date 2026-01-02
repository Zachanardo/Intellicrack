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

Provide a centralized abstraction layer for pyelftools imports.

This module enables ELF binary analysis with graceful fallback support.
When pyelftools is available, it exports real implementations from the
installed package. When unavailable, it provides functional ELF parsing
implementations from the _pyelftools_fallback module.

Attributes:
    HAS_PYELFTOOLS: Flag indicating pyelftools availability.
    PYELFTOOLS_VERSION: Version string of pyelftools or None if unavailable.
"""

from __future__ import annotations

import types
from typing import Any

from intellicrack.utils.logger import logger


# Module-level type declarations for conditional imports
_elftools_module: types.ModuleType | None
Container: type[Any]
Struct: type[Any]
DW_TAG_compile_unit: Any
ENUM_D_TAG: Any
ENUM_E_TYPE: Any
ENUM_SH_TYPE: Any
elftools_instance: Any
elffile_instance: type[Any]

# Runtime availability check - must be done before conditional imports
HAS_PYELFTOOLS: bool = False
PYELFTOOLS_VERSION: str | None = None
_pyelftools_imported: bool = False

try:
    import elftools as _elftools_module

    _pyelftools_imported = True
    HAS_PYELFTOOLS = True
    PYELFTOOLS_VERSION = getattr(_elftools_module, "__version__", "unknown")
except ImportError as e:
    _elftools_module = None
    logger.info("PyElfTools not available, using fallback implementations: %s", e)

# Conditional imports based on pyelftools availability
# Using separate variable to help mypy understand the control flow
if _pyelftools_imported:
    from elftools.common.exceptions import DWARFError, ELFError, ELFParseError
    from elftools.dwarf.die import DIE
    from elftools.dwarf.dwarfinfo import DWARFInfo
    from elftools.elf.constants import E_FLAGS, P_FLAGS, SH_FLAGS, SHN_INDICES
    from elftools.elf.descriptions import describe_e_type, describe_p_type, describe_sh_type
    from elftools.elf.dynamic import Dynamic, DynamicSection, DynamicSegment
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import Relocation, RelocationSection
    from elftools.elf.sections import NoteSection, Section, StringTableSection, Symbol, SymbolTableSection
    from elftools.elf.segments import InterpSegment, NoteSegment, Segment

    # Handle optional pyelftools modules with individual fallbacks
    _py3compat_available = False
    try:
        from elftools.common.py3compat import bytes2str, str2bytes

        _py3compat_available = True
    except ImportError:
        pass

    if not _py3compat_available:
        from intellicrack.handlers._pyelftools_fallback import bytes2str, str2bytes

    # Handle construct module (may come from elftools or standalone)
    _construct_available = False
    try:
        from elftools.construct import Container, Struct

        _construct_available = True
    except (ImportError, AttributeError):
        try:
            from construct import Container, Struct

            _construct_available = True
        except ImportError:
            pass

    if not _construct_available:
        from intellicrack.handlers._pyelftools_fallback import Container, Struct

    # Handle DWARF constants
    _dwarf_constants_available = False
    try:
        from elftools.dwarf.constants import DW_TAG_compile_unit

        _dwarf_constants_available = True
    except (ImportError, AttributeError):
        pass

    if not _dwarf_constants_available:
        from intellicrack.handlers._pyelftools_fallback import DW_TAG_compile_unit

    # Handle ELF enums
    _elf_enums_available = False
    try:
        from elftools.elf.enums import ENUM_D_TAG, ENUM_E_TYPE, ENUM_SH_TYPE

        _elf_enums_available = True
    except (ImportError, AttributeError):
        pass

    if not _elf_enums_available:
        from intellicrack.handlers._pyelftools_fallback import ENUM_D_TAG, ENUM_E_TYPE, ENUM_SH_TYPE

    # Module references
    elftools_instance: Any = _elftools_module
    elffile_instance: type[Any] = ELFFile

else:
    # Fallback imports when pyelftools not available
    from intellicrack.handlers._pyelftools_fallback import (
        DIE,
        E_FLAGS,
        ENUM_D_TAG,
        ENUM_E_TYPE,
        ENUM_SH_TYPE,
        P_FLAGS,
        SH_FLAGS,
        SHN_INDICES,
        Container,
        DW_TAG_compile_unit,
        DWARFError,
        DWARFInfo,
        Dynamic,
        DynamicSection,
        DynamicSegment,
        ELFError,
        ELFFile,
        ELFParseError,
        InterpSegment,
        NoteSection,
        NoteSegment,
        Relocation,
        RelocationSection,
        Section,
        Segment,
        StringTableSection,
        Struct,
        Symbol,
        SymbolTableSection,
        bytes2str,
        describe_e_type,
        describe_p_type,
        describe_sh_type,
        str2bytes,
    )

    class _FallbackElftoolsModule:
        """Fallback elftools module reference when pyelftools is unavailable.

        Provides a minimal module interface to maintain compatibility with
        code that attempts to access elftools version information.

        Attributes:
            __version__: Version identifier for the fallback implementation.
        """

        __version__: str = "fallback"

    elftools_instance: Any = _FallbackElftoolsModule()
    elffile_instance: type[Any] = ELFFile


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
    "elffile_instance",
    "elftools_instance",
    "str2bytes",
]
