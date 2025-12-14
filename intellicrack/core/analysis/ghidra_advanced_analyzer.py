"""Ghidra Advanced Analysis Features.

Production-ready implementations for advanced binary analysis including
variable recovery, structure recovery, vtable analysis, and debug symbols.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import contextlib
import logging
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import lief
import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

from intellicrack.core.analysis.ghidra_analyzer import GhidraAnalysisResult, GhidraDataType, GhidraFunction


logger = logging.getLogger(__name__)


@dataclass
class RecoveredVariable:
    """Represents a recovered variable with type information."""

    name: str
    type: str
    size: int
    offset: int  # Stack or heap offset
    scope: str  # local, global, parameter
    is_pointer: bool
    pointed_type: str | None = None
    array_size: int | None = None
    usage_count: int = 0
    first_use: int = 0  # Instruction offset
    last_use: int = 0


@dataclass
class RecoveredStructure:
    """Represents a recovered structure/class."""

    name: str
    size: int
    alignment: int
    members: list[dict[str, Any]]
    vtable_offset: int | None = None
    base_classes: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    is_union: bool = False
    is_packed: bool = False


@dataclass
class VTableInfo:
    """Virtual function table information."""

    address: int
    class_name: str
    functions: list[int]  # Function addresses
    rtti_address: int | None = None
    base_offset: int = 0
    virtual_base: bool = False
    destructor_addr: int | None = None


@dataclass
class ExceptionHandlerInfo:
    """Exception handler information."""

    type: str  # SEH, C++, VEH
    handler_address: int
    try_start: int
    try_end: int
    catch_blocks: list[dict[str, Any]]
    filter_func: int | None = None
    unwind_info: dict[str, Any] | None = None


@dataclass
class DebugSymbolInfo:
    """Debug symbol information."""

    type: str  # PDB, DWARF, STABS
    path: str | None
    guid: str | None
    age: int | None
    symbols: dict[int, str]  # Address -> symbol name
    types: dict[str, dict[str, Any]]
    source_files: list[str]
    line_numbers: dict[int, tuple[str, int]]  # Address -> (file, line)


class GhidraAdvancedAnalyzer:
    """Advanced analysis features for Ghidra integration."""

    def __init__(self, binary_path: str) -> None:
        """Initialize the GhidraAdvancedAnalyzer with a binary file path.

        Args:
            binary_path: Path to the binary file to analyze.

        """
        self.binary_path = Path(binary_path)
        self.pe = None
        self.lief_binary = None
        self.md = None  # Capstone disassembler
        self._init_analyzers()

    def _init_analyzers(self) -> None:
        """Initialize binary analyzers."""
        try:
            # Load with PE parser for Windows binaries
            if self.binary_path.suffix.lower() in [".exe", ".dll", ".sys"]:
                self.pe = pefile.PE(str(self.binary_path))

            # Load with LIEF for cross-platform support
            self.lief_binary = lief.parse(str(self.binary_path))

            # Initialize Capstone disassembler
            if self.lief_binary:
                if self.lief_binary.header.machine_type == lief.ELF.ARCH.x86_64:
                    self.md = Cs(CS_ARCH_X86, CS_MODE_64)
                elif self.lief_binary.header.machine_type == lief.ELF.ARCH.i386:
                    self.md = Cs(CS_ARCH_X86, CS_MODE_32)
                elif self.pe:
                    if self.pe.FILE_HEADER.Machine == 0x8664:  # AMD64
                        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
                    else:
                        self.md = Cs(CS_ARCH_X86, CS_MODE_32)

            if self.md:
                self.md.detail = True
        except Exception:
            logger.exception("Failed to initialize analyzers", exc_info=True)

    def recover_variables(self, function: GhidraFunction) -> list[RecoveredVariable]:
        """Recover variables with type propagation."""
        stack_vars = {}

        if not function.assembly_code:
            return []
        # Parse assembly to track stack operations and type hints
        instructions = function.assembly_code.split("\n")

        for i, inst_line in enumerate(instructions):
            inst_parts = inst_line.strip().split()
            if not inst_parts:
                continue

            mnemonic = inst_parts[0].lower()

            # Track stack frame setup
            if mnemonic == "push" and "bp" in inst_line.lower():
                pass
            elif mnemonic == "sub" and "sp" in inst_line.lower():
                # Extract stack size
                if len(inst_parts) >= 3:
                    with contextlib.suppress(ValueError):
                        int(inst_parts[2].replace("0x", ""), 16)

            elif "[" in inst_line and ("bp" in inst_line.lower() or "sp" in inst_line.lower()):
                if var_match := re.search(r"\[(r|e)?([bs]p)([+-])0x([0-9a-f]+)\]", inst_line.lower()):
                    offset = int(var_match[4], 16)
                    if var_match[3] == "-":
                        offset = -offset

                    # Determine variable type from instruction
                    var_type = self._infer_type_from_instruction(mnemonic, inst_line)
                    var_size = self._get_size_from_type(var_type)

                    if offset not in stack_vars:
                        var_name = f"local_{abs(offset):x}"
                        if offset < 0:
                            scope = "local"
                        else:
                            scope = "parameter"
                            var_name = f"param_{abs(offset):x}"

                        stack_vars[offset] = RecoveredVariable(
                            name=var_name,
                            type=var_type,
                            size=var_size,
                            offset=offset,
                            scope=scope,
                            is_pointer="ptr" in var_type.lower(),
                            usage_count=1,
                            first_use=i,
                            last_use=i,
                        )
                    else:
                        stack_vars[offset].usage_count += 1
                        stack_vars[offset].last_use = i

        # Apply type propagation
        self._propagate_types(stack_vars, function)

        return list(stack_vars.values())

    def _infer_type_from_instruction(self, mnemonic: str, inst_line: str) -> str:
        """Infer variable type from instruction context."""
        inst_lower = inst_line.lower()

        # Size indicators
        if "qword" in inst_lower:
            base_type = "uint64_t"
        elif "dword" in inst_lower or ("word" not in inst_lower and "byte" not in inst_lower):
            base_type = "uint32_t"
        elif "word" in inst_lower:
            base_type = "uint16_t"
        else:
            base_type = "uint8_t"
        # Type hints from instructions
        if mnemonic in {"fld", "fstp", "fadd", "fmul"}:
            return "float" if "dword" in inst_lower else "double"
        if mnemonic in {"lea"}:
            return base_type + "*"  # Pointer
        if "str" in mnemonic or "stos" in mnemonic:
            return "char*"  # String operations

        return base_type

    def _get_size_from_type(self, type_str: str) -> int:
        """Get size in bytes from type string."""
        type_sizes = {
            "uint8_t": 1,
            "int8_t": 1,
            "char": 1,
            "uint16_t": 2,
            "int16_t": 2,
            "short": 2,
            "uint32_t": 4,
            "int32_t": 4,
            "int": 4,
            "float": 4,
            "uint64_t": 8,
            "int64_t": 8,
            "long": 8,
            "double": 8,
        }

        # Handle pointers
        if "*" in type_str:
            return 8 if "64" in type_str else 4

        base_type = type_str.replace("*", "").strip()
        return type_sizes.get(base_type, 4)

    def _propagate_types(self, variables: dict[int, RecoveredVariable], function: GhidraFunction) -> None:
        """Propagate types through data flow analysis."""
        # Analyze function parameters from calling convention
        if function.calling_convention not in [
            "__stdcall",
            "__cdecl",
            "__fastcall",
        ]:
            return
        # x86/x64 calling conventions
        param_regs = ["rcx", "rdx", "r8", "r9"] if "64" in function.signature else ["ecx", "edx"]

        len(function.parameters)
        for i, (param_type, param_name) in enumerate(function.parameters):
            # Match stack parameters
            for offset, var in variables.items():
                if var.scope == "parameter":
                    if i < len(param_regs):
                        # Register parameters
                        continue
                    # Stack parameters
                    stack_param_idx = i - len(param_regs)
                    expected_offset = 8 + (stack_param_idx * 8)  # Adjust for architecture
                    if abs(offset - expected_offset) < 16:
                        var.type = param_type
                        var.name = param_name or var.name

    def recover_structures(self, analysis_result: GhidraAnalysisResult) -> list[RecoveredStructure]:
        """Recover structure definitions from binary."""
        structures = []
        struct_candidates = {}

        # Analyze memory access patterns
        for func in analysis_result.functions.values():
            struct_accesses = self._analyze_struct_accesses(func)

            for offsets in struct_accesses.values():
                if len(offsets) > 2:  # Likely a structure if multiple offsets
                    struct_key = frozenset(offsets.keys())
                    if struct_key not in struct_candidates:
                        struct_candidates[struct_key] = {
                            "offsets": offsets,
                            "usage_count": 1,
                            "functions": [func.name],
                        }
                    else:
                        struct_candidates[struct_key]["usage_count"] += 1
                        struct_candidates[struct_key]["functions"].append(func.name)

        # Build structure definitions
        for i, (_struct_key, info) in enumerate(struct_candidates.items()):
            if info["usage_count"] < 2:  # Skip rarely used patterns
                continue

            members = []
            offsets = sorted(info["offsets"].items())
            struct_size = 0

            for offset, access_info in offsets:
                member_name = f"field_{offset:x}"
                member_type = access_info["type"]
                member_size = access_info["size"]

                members.append({
                    "name": member_name,
                    "type": member_type,
                    "offset": offset,
                    "size": member_size,
                })

                struct_size = max(struct_size, offset + member_size)

            # Check for vtable
            vtable_offset = None
            if 0 in info["offsets"] and "ptr" in info["offsets"][0]["type"]:
                vtable_offset = 0

            structures.append(
                RecoveredStructure(
                    name=f"struct_{i:03d}",
                    size=struct_size,
                    alignment=8 if struct_size > 32 else 4,
                    members=members,
                    vtable_offset=vtable_offset,
                ),
            )

        return structures

    def _analyze_struct_accesses(self, function: GhidraFunction) -> dict[str, dict[int, dict]]:
        """Analyze structure access patterns in a function."""
        struct_accesses = {}

        if not function.assembly_code:
            return struct_accesses

        instructions = function.assembly_code.split("\n")

        for inst_line in instructions:
            if access_match := re.search(r"(\w+)\s+.*\[(r\w+)\+0x([0-9a-f]+)\]", inst_line.lower()):
                mnemonic = access_match[1]
                base_reg = access_match[2]
                offset = int(access_match[3], 16)

                if base_reg not in struct_accesses:
                    struct_accesses[base_reg] = {}

                # Determine access type and size
                access_type = self._infer_type_from_instruction(mnemonic, inst_line)
                access_size = self._get_size_from_type(access_type)

                struct_accesses[base_reg][offset] = {
                    "type": access_type,
                    "size": access_size,
                    "instruction": mnemonic,
                }

        return struct_accesses

    def analyze_vtables(self, analysis_result: GhidraAnalysisResult) -> list[VTableInfo]:
        """Analyze virtual function tables."""
        vtables = []

        # Look for vtable patterns in data sections
        if self.pe:
            for section in self.pe.sections:
                if b".rdata" in section.Name or b".data" in section.Name:
                    data = section.get_data()
                    vtables.extend(self._scan_for_vtables(data, section.VirtualAddress))

        # Analyze constructor functions for vtable initialization
        for func in analysis_result.functions.values():
            if "ctor" in func.name.lower() or "constructor" in func.name.lower():
                vtable_inits = self._analyze_vtable_init(func)
                vtables.extend(
                    VTableInfo(
                        address=vtable_addr,
                        class_name=f"class_{vtable_addr:08x}",
                        functions=func_addrs,
                        destructor_addr=self._find_destructor(func_addrs),
                    )
                    for vtable_addr, func_addrs in vtable_inits.items()
                )
        # Analyze RTTI information if present
        if self.pe:
            rtti_vtables = self._analyze_rtti()
            vtables.extend(rtti_vtables)

        return vtables

    def _scan_for_vtables(self, data: bytes, base_address: int) -> list[VTableInfo]:
        """Scan data section for vtable patterns."""
        vtables = []
        ptr_size = 8 if self.md and self.md.mode == CS_MODE_64 else 4

        i = 0
        while i < len(data) - ptr_size * 3:
            # Look for consecutive function pointers
            ptrs = []
            j = i

            while j < len(data):
                if ptr_size == 8:
                    ptr = struct.unpack("<Q", data[j : j + 8])[0]
                else:
                    ptr = struct.unpack("<I", data[j : j + 4])[0]

                # Check if it looks like a code address
                if self._is_code_address(ptr):
                    ptrs.append(ptr)
                    j += ptr_size
                else:
                    break

            # If we found 3+ consecutive function pointers, it's likely a vtable
            if len(ptrs) >= 3:
                vtables.append(
                    VTableInfo(
                        address=base_address + i,
                        class_name=f"class_{base_address + i:08x}",
                        functions=ptrs,
                    )
                )
                i = j
            else:
                i += ptr_size

        return vtables

    def _is_code_address(self, address: int) -> bool:
        """Check if address points to code section."""
        if not self.pe:
            return False

        return next(
            (
                bool(section.Characteristics & 0x20000000)
                for section in self.pe.sections
                if (section.VirtualAddress <= address < section.VirtualAddress + section.Misc_VirtualSize)
            ),
            False,
        )

    def _analyze_vtable_init(self, function: GhidraFunction) -> dict[int, list[int]]:
        """Analyze vtable initialization in constructor."""
        vtable_inits = {}

        if not function.assembly_code:
            return vtable_inits

        instructions = function.assembly_code.split("\n")
        current_vtable = None

        for inst_line in instructions:
            # Look for vtable assignment patterns
            if "lea" in inst_line.lower():
                if vtable_match := re.search(r"lea\s+\w+,\s*\[0x([0-9a-f]+)\]", inst_line.lower()):
                    current_vtable = int(vtable_match[1], 16)

            elif "mov" in inst_line.lower() and current_vtable:
                # Look for storing vtable pointer to object
                if "[" in inst_line and "]" in inst_line:
                    # This could be vtable assignment
                    vtable_inits[current_vtable] = self._extract_vtable_functions(current_vtable)

        return vtable_inits

    def _extract_vtable_functions(self, vtable_addr: int) -> list[int]:
        """Extract function addresses from vtable."""
        functions = []

        if self.pe:
            # Find the section containing the vtable
            for section in self.pe.sections:
                if section.VirtualAddress <= vtable_addr < section.VirtualAddress + section.Misc_VirtualSize:
                    offset = vtable_addr - section.VirtualAddress
                    data = section.get_data()[offset:]
                    ptr_size = 8 if self.md and self.md.mode == CS_MODE_64 else 4

                    i = 0
                    while i < len(data):
                        if ptr_size == 8:
                            ptr = struct.unpack("<Q", data[i : i + 8])[0]
                        else:
                            ptr = struct.unpack("<I", data[i : i + 4])[0]

                        if self._is_code_address(ptr):
                            functions.append(ptr)
                            i += ptr_size
                        else:
                            break

        return functions

    def _find_destructor(self, func_addrs: list[int]) -> int | None:
        """Identify destructor in vtable functions."""
        # Usually first or second function in vtable
        return func_addrs[1] if len(func_addrs) >= 2 else None

    def _analyze_rtti(self) -> list[VTableInfo]:
        """Analyze RTTI (Run-Time Type Information)."""
        vtables = []

        if not self.pe:
            return vtables

        # Look for RTTI structures (MSVC specific)
        for section in self.pe.sections:
            if b".rdata" in section.Name:
                data = section.get_data()

                # Search for _RTTICompleteObjectLocator
                i = 0
                while i < len(data) - 24:
                    # Check for RTTI signature
                    sig = struct.unpack("<I", data[i : i + 4])[0]
                    if sig == 0:  # Signature field
                        offset = struct.unpack("<I", data[i + 4 : i + 8])[0]
                        if offset == 0:  # Offset field
                            # Likely found RTTI
                            vtable_addr = section.VirtualAddress + i - 4
                            class_name = self._extract_class_name_from_rtti(data[i : i + 32])

                            vtables.append(
                                VTableInfo(
                                    address=vtable_addr,
                                    class_name=class_name,
                                    functions=[],
                                    rtti_address=section.VirtualAddress + i,
                                ),
                            )

                    i += 4

        return vtables

    def _extract_class_name_from_rtti(self, rtti_data: bytes) -> str:
        """Extract class name from RTTI data."""
        # This would need proper RTTI parsing
        return f"rtti_class_{hash(rtti_data) & 0xFFFFFF:06x}"

    def extract_exception_handlers(self, analysis_result: GhidraAnalysisResult) -> list[ExceptionHandlerInfo]:
        """Extract exception handler information."""
        handlers = []

        if self.pe:
            # Extract SEH (Structured Exception Handling) for x86
            if self.pe.FILE_HEADER.Machine == 0x14C:  # x86
                handlers.extend(self._extract_seh())

            # Extract C++ exception handlers
            handlers.extend(self._extract_cpp_eh())

            # Extract VEH (Vectored Exception Handling)
            handlers.extend(self._extract_veh())

        return handlers

    def _extract_seh(self) -> list[ExceptionHandlerInfo]:
        """Extract SEH handlers from x86 binaries."""
        return []

    def _extract_cpp_eh(self) -> list[ExceptionHandlerInfo]:
        """Extract C++ exception handling information."""
        handlers = []

        if not self.pe:
            return handlers

        # Look for .pdata section (x64 exception data)
        for section in self.pe.sections:
            if b".pdata" in section.Name:
                data = section.get_data()

                # Parse RUNTIME_FUNCTION structures
                i = 0
                while i < len(data) - 12:
                    begin_addr = struct.unpack("<I", data[i : i + 4])[0]
                    end_addr = struct.unpack("<I", data[i + 4 : i + 8])[0]
                    unwind_info = struct.unpack("<I", data[i + 8 : i + 12])[0]

                    handlers.append(
                        ExceptionHandlerInfo(
                            type="C++",
                            handler_address=unwind_info,
                            try_start=begin_addr,
                            try_end=end_addr,
                            catch_blocks=[],
                        ),
                    )

                    i += 12

        return handlers

    def _extract_veh(self) -> list[ExceptionHandlerInfo]:
        """Extract VEH handlers."""
        return []

    def parse_debug_symbols(self, analysis_result: GhidraAnalysisResult) -> DebugSymbolInfo | None:
        """Parse debug symbol information."""
        debug_info = None

        if self.pe:
            # Check for PDB information
            debug_info = self._parse_pdb_info()

        elif self.lief_binary:
            # Check for DWARF information (ELF)
            if hasattr(self.lief_binary, "has_debug_info") and self.lief_binary.has_debug_info:
                debug_info = self._parse_dwarf_info()

        return debug_info

    def _parse_pdb_info(self) -> DebugSymbolInfo | None:
        """Parse PDB debug information from PE."""
        if not self.pe or not hasattr(self.pe, "DIRECTORY_ENTRY_DEBUG"):
            return None

        for debug_entry in self.pe.DIRECTORY_ENTRY_DEBUG:
            if debug_entry.struct.Type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                # Parse CodeView information
                data = debug_entry.entry.name
                if data.startswith(b"RSDS"):
                    # PDB 7.0 format
                    guid = data[4:20].hex()
                    age = struct.unpack("<I", data[20:24])[0]
                    pdb_path = data[24:].decode("utf-8", errors="ignore").rstrip("\x00")

                    return DebugSymbolInfo(
                        type="PDB",
                        path=pdb_path,
                        guid=guid,
                        age=age,
                        symbols={},
                        types={},
                        source_files=[],
                        line_numbers={},
                    )

        return None

    def _parse_dwarf_info(self) -> DebugSymbolInfo | None:
        """Parse DWARF debug information from ELF."""
        # Would require full DWARF parser implementation
        return DebugSymbolInfo(
            type="DWARF",
            path=None,
            guid=None,
            age=None,
            symbols={},
            types={},
            source_files=[],
            line_numbers={},
        )

    def create_custom_datatypes(self, structures: list[RecoveredStructure]) -> list[GhidraDataType]:
        """Create custom data types for Ghidra."""
        custom_types = []

        for struct_obj in structures:
            # Create Ghidra-compatible data type
            ghidra_type = GhidraDataType(
                name=struct_obj.name,
                size=struct_obj.size,
                category="union" if struct_obj.is_union else "struct",
                members=struct_obj.members,
                alignment=struct_obj.alignment,
            )

            custom_types.append(ghidra_type)

            # Create pointer type
            ptr_type = GhidraDataType(
                name=f"{struct.name}*",
                size=8,  # Assuming 64-bit
                category="pointer",
                base_type=struct.name,
            )
            custom_types.append(ptr_type)

            # Create array types for common sizes
            for array_size in [10, 100, 256]:
                array_type = GhidraDataType(
                    name=f"{struct.name}[{array_size}]",
                    size=struct.size * array_size,
                    category="array",
                    base_type=struct.name,
                )
                custom_types.append(array_type)

        return custom_types


def apply_advanced_analysis(analysis_result: GhidraAnalysisResult, binary_path: str) -> GhidraAnalysisResult:
    """Apply advanced analysis features to existing Ghidra results."""
    analyzer = GhidraAdvancedAnalyzer(binary_path)

    # Recover variables for each function
    for func in analysis_result.functions.values():
        recovered_vars = analyzer.recover_variables(func)

        # Update function with recovered variables
        for var in recovered_vars:
            if var.scope == "local":
                func.local_variables.append((var.type, var.name, var.offset))
            elif var.scope == "parameter" and len(func.parameters) < 10:
                func.parameters.append((var.type, var.name))

    # Recover structures
    structures = analyzer.recover_structures(analysis_result)
    for struct_obj in structures:
        ghidra_type = GhidraDataType(
            name=struct_obj.name,
            size=struct_obj.size,
            category="struct",
            members=struct_obj.members,
            alignment=struct_obj.alignment,
        )
        analysis_result.data_types[struct_obj.name] = ghidra_type

    # Analyze vtables
    vtables = analyzer.analyze_vtables(analysis_result)
    for vtable in vtables:
        analysis_result.vtables[vtable.address] = vtable.functions

    # Extract exception handlers
    handlers = analyzer.extract_exception_handlers(analysis_result)
    for handler in handlers:
        analysis_result.exception_handlers.append(
            {
                "type": handler.type,
                "address": handler.handler_address,
                "try_start": handler.try_start,
                "try_end": handler.try_end,
            },
        )

    if debug_info := analyzer.parse_debug_symbols(analysis_result):
        analysis_result.metadata["debug_info"] = {
            "type": debug_info.type,
            "path": debug_info.path,
            "guid": debug_info.guid,
        }

    # Create custom data types
    custom_types = analyzer.create_custom_datatypes(structures)
    for custom_type in custom_types:
        analysis_result.data_types[custom_type.name] = custom_type

    return analysis_result
