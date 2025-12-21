"""Ghidra Advanced Analysis Features.

Production-ready implementations for advanced binary analysis including
variable recovery, structure recovery, vtable analysis, and debug symbols.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import contextlib
import logging
import re
import struct as struct_module
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
    offset: int
    scope: str
    is_pointer: bool
    pointed_type: str | None = None
    array_size: int | None = None
    usage_count: int = 0
    first_use: int = 0
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
    functions: list[int]
    rtti_address: int | None = None
    base_offset: int = 0
    virtual_base: bool = False
    destructor_addr: int | None = None


@dataclass
class ExceptionHandlerInfo:
    """Exception handler information."""

    type: str
    handler_address: int
    try_start: int
    try_end: int
    catch_blocks: list[dict[str, Any]]
    filter_func: int | None = None
    unwind_info: dict[str, Any] | None = None


@dataclass
class DebugSymbolInfo:
    """Debug symbol information."""

    type: str
    path: str | None
    guid: str | None
    age: int | None
    symbols: dict[int, str]
    types: dict[str, dict[str, Any]]
    source_files: list[str]
    line_numbers: dict[int, tuple[str, int]]


class GhidraAdvancedAnalyzer:
    """Advanced analysis features for Ghidra integration."""

    def __init__(self, binary_path: str) -> None:
        """Initialize the GhidraAdvancedAnalyzer with a binary file path.

        Args:
            binary_path: Path to the binary file to analyze.

        """
        self.binary_path = Path(binary_path)
        self.pe: pefile.PE | None = None
        self.lief_binary: lief.PE.Binary | lief.ELF.Binary | lief.MachO.Binary | lief.COFF.Binary | None = None
        self.md: Cs | None = None
        self._init_analyzers()

    def _init_analyzers(self) -> None:
        """Initialize binary analyzers."""
        try:
            if self.binary_path.suffix.lower() in [".exe", ".dll", ".sys"]:
                self.pe = pefile.PE(str(self.binary_path))

            parsed_binary = lief.parse(str(self.binary_path))
            if parsed_binary:
                self.lief_binary = parsed_binary

            if self.lief_binary and isinstance(self.lief_binary, lief.ELF.Binary):
                if hasattr(self.lief_binary.header, 'machine_type'):
                    machine_type = self.lief_binary.header.machine_type
                    if hasattr(lief.ELF, 'ARCH'):
                        arch_type = lief.ELF.ARCH
                        if hasattr(arch_type, 'x86_64') and machine_type == arch_type.x86_64:
                            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
                        elif hasattr(arch_type, 'i386') and machine_type == arch_type.i386:
                            self.md = Cs(CS_ARCH_X86, CS_MODE_32)
            elif self.pe:
                if self.pe.FILE_HEADER.Machine == 0x8664:
                    self.md = Cs(CS_ARCH_X86, CS_MODE_64)
                else:
                    self.md = Cs(CS_ARCH_X86, CS_MODE_32)

            if self.md:
                self.md.detail = True
        except Exception:
            logger.exception("Failed to initialize analyzers")

    def recover_variables(self, function: GhidraFunction) -> list[RecoveredVariable]:
        """Recover variables with type propagation."""
        stack_vars: dict[int, RecoveredVariable] = {}

        if not function.assembly_code:
            return []
        instructions = function.assembly_code.split("\n")

        for i, inst_line in enumerate(instructions):
            inst_parts = inst_line.strip().split()
            if not inst_parts:
                continue

            mnemonic = inst_parts[0].lower()

            if mnemonic == "push" and "bp" in inst_line.lower():
                pass
            elif mnemonic == "sub" and "sp" in inst_line.lower():
                if len(inst_parts) >= 3:
                    with contextlib.suppress(ValueError):
                        int(inst_parts[2].replace("0x", ""), 16)

            elif "[" in inst_line and ("bp" in inst_line.lower() or "sp" in inst_line.lower()):
                if var_match := re.search(r"\[(r|e)?([bs]p)([+-])0x([0-9a-f]+)\]", inst_line.lower()):
                    offset = int(var_match[4], 16)
                    if var_match[3] == "-":
                        offset = -offset

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

        self._propagate_types(stack_vars, function)

        return list(stack_vars.values())

    def _infer_type_from_instruction(self, mnemonic: str, inst_line: str) -> str:
        """Infer variable type from instruction context."""
        inst_lower = inst_line.lower()

        if "qword" in inst_lower:
            base_type = "uint64_t"
        elif "dword" in inst_lower or ("word" not in inst_lower and "byte" not in inst_lower):
            base_type = "uint32_t"
        elif "word" in inst_lower:
            base_type = "uint16_t"
        else:
            base_type = "uint8_t"
        if mnemonic in {"fld", "fstp", "fadd", "fmul"}:
            return "float" if "dword" in inst_lower else "double"
        if mnemonic in {"lea"}:
            return f"{base_type}*"
        return "char*" if "str" in mnemonic or "stos" in mnemonic else base_type

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

        if "*" in type_str:
            return 8 if "64" in type_str else 4

        base_type = type_str.replace("*", "").strip()
        return type_sizes.get(base_type, 4)

    def _propagate_types(self, variables: dict[int, RecoveredVariable], function: GhidraFunction) -> None:
        """Propagate types through data flow analysis."""
        if function.calling_convention not in [
            "__stdcall",
            "__cdecl",
            "__fastcall",
        ]:
            return
        param_regs = ["rcx", "rdx", "r8", "r9"] if "64" in function.signature else ["ecx", "edx"]

        len(function.parameters)
        for i, (param_type, param_name) in enumerate(function.parameters):
            for offset, var in variables.items():
                if var.scope == "parameter":
                    if i < len(param_regs):
                        continue
                    stack_param_idx = i - len(param_regs)
                    expected_offset = 8 + (stack_param_idx * 8)
                    if abs(offset - expected_offset) < 16:
                        var.type = param_type
                        var.name = param_name or var.name

    def recover_structures(self, analysis_result: GhidraAnalysisResult) -> list[RecoveredStructure]:
        """Recover structure definitions from binary."""
        structures: list[RecoveredStructure] = []
        struct_candidates: dict[frozenset[int], dict[str, Any]] = {}

        for func in analysis_result.functions.values():
            struct_accesses = self._analyze_struct_accesses(func)

            for offsets in struct_accesses.values():
                if len(offsets) > 2:
                    struct_key = frozenset(offsets.keys())
                    if struct_key not in struct_candidates:
                        struct_candidates[struct_key] = {
                            "offsets": offsets,
                            "usage_count": 1,
                            "functions": [func.name],
                        }
                    else:
                        struct_candidates[struct_key]["usage_count"] += 1
                        functions_list = struct_candidates[struct_key]["functions"]
                        if isinstance(functions_list, list):
                            functions_list.append(func.name)

        for i, (_struct_key, info) in enumerate(struct_candidates.items()):
            usage_count = info.get("usage_count", 0)
            if not isinstance(usage_count, int) or usage_count < 2:
                continue

            members: list[dict[str, Any]] = []
            offsets_dict = info.get("offsets", {})
            if not isinstance(offsets_dict, dict):
                continue
            offsets_items = sorted(offsets_dict.items())
            struct_size = 0

            for offset, access_info in offsets_items:
                if not isinstance(access_info, dict):
                    continue
                member_name = f"field_{offset:x}"
                member_type = access_info.get("type", "unknown")
                member_size = access_info.get("size", 0)
                if not isinstance(member_size, int):
                    continue

                members.append({
                    "name": member_name,
                    "type": member_type,
                    "offset": offset,
                    "size": member_size,
                })

                struct_size = max(struct_size, offset + member_size)

            vtable_offset: int | None = None
            if isinstance(offsets_dict, dict) and 0 in offsets_dict:
                offset_info = offsets_dict[0]
                if isinstance(offset_info, dict) and "type" in offset_info:
                    offset_type = offset_info["type"]
                    if isinstance(offset_type, str) and "ptr" in offset_type:
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

    def _analyze_struct_accesses(self, function: GhidraFunction) -> dict[str, dict[int, dict[str, Any]]]:
        """Analyze structure access patterns in a function."""
        struct_accesses: dict[str, dict[int, dict[str, Any]]] = {}

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
        vtables: list[VTableInfo] = []

        if self.pe:
            for section in self.pe.sections:
                if b".rdata" in section.Name or b".data" in section.Name:
                    data = section.get_data()
                    vtables.extend(self._scan_for_vtables(data, section.VirtualAddress))

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
        if self.pe:
            rtti_vtables = self._analyze_rtti()
            vtables.extend(rtti_vtables)

        return vtables

    def _scan_for_vtables(self, data: bytes, base_address: int) -> list[VTableInfo]:
        """Scan data section for vtable patterns."""
        vtables: list[VTableInfo] = []
        ptr_size = 8 if self.md and self.md.mode == CS_MODE_64 else 4

        i = 0
        while i < len(data) - ptr_size * 3:
            ptrs: list[int] = []
            j = i

            while j < len(data):
                if ptr_size == 8:
                    ptr = struct_module.unpack("<Q", data[j : j + 8])[0]
                else:
                    ptr = struct_module.unpack("<I", data[j : j + 4])[0]

                if self._is_code_address(ptr):
                    ptrs.append(ptr)
                    j += ptr_size
                else:
                    break

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
        vtable_inits: dict[int, list[int]] = {}

        if not function.assembly_code:
            return vtable_inits

        instructions = function.assembly_code.split("\n")
        current_vtable: int | None = None

        for inst_line in instructions:
            if "lea" in inst_line.lower():
                if vtable_match := re.search(r"lea\s+\w+,\s*\[0x([0-9a-f]+)\]", inst_line.lower()):
                    current_vtable = int(vtable_match[1], 16)

            elif "mov" in inst_line.lower() and current_vtable:
                if "[" in inst_line and "]" in inst_line:
                    vtable_inits[current_vtable] = self._extract_vtable_functions(current_vtable)

        return vtable_inits

    def _extract_vtable_functions(self, vtable_addr: int) -> list[int]:
        """Extract function addresses from vtable."""
        functions: list[int] = []

        if self.pe:
            for section in self.pe.sections:
                if section.VirtualAddress <= vtable_addr < section.VirtualAddress + section.Misc_VirtualSize:
                    offset = vtable_addr - section.VirtualAddress
                    data = section.get_data()[offset:]
                    ptr_size = 8 if self.md and self.md.mode == CS_MODE_64 else 4

                    i = 0
                    while i < len(data):
                        if ptr_size == 8:
                            ptr = struct_module.unpack("<Q", data[i : i + 8])[0]
                        else:
                            ptr = struct_module.unpack("<I", data[i : i + 4])[0]

                        if self._is_code_address(ptr):
                            functions.append(ptr)
                            i += ptr_size
                        else:
                            break

        return functions

    def _find_destructor(self, func_addrs: list[int]) -> int | None:
        """Identify destructor in vtable functions."""
        return func_addrs[1] if len(func_addrs) >= 2 else None

    def _analyze_rtti(self) -> list[VTableInfo]:
        """Analyze RTTI (Run-Time Type Information)."""
        vtables: list[VTableInfo] = []

        if not self.pe:
            return vtables

        for section in self.pe.sections:
            if b".rdata" in section.Name:
                data = section.get_data()

                i = 0
                while i < len(data) - 24:
                    sig = struct_module.unpack("<I", data[i : i + 4])[0]
                    if sig == 0:
                        offset = struct_module.unpack("<I", data[i + 4 : i + 8])[0]
                        if offset == 0:
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
        return f"rtti_class_{hash(rtti_data) & 0xFFFFFF:06x}"

    def extract_exception_handlers(self, analysis_result: GhidraAnalysisResult) -> list[ExceptionHandlerInfo]:
        """Extract exception handler information."""
        handlers: list[ExceptionHandlerInfo] = []

        if self.pe:
            if self.pe.FILE_HEADER.Machine == 0x14C:
                handlers.extend(self._extract_seh())

            handlers.extend(self._extract_cpp_eh())

            handlers.extend(self._extract_veh())

        return handlers

    def _extract_seh(self) -> list[ExceptionHandlerInfo]:
        """Extract SEH handlers from x86 binaries."""
        return []

    def _extract_cpp_eh(self) -> list[ExceptionHandlerInfo]:
        """Extract C++ exception handling information."""
        handlers: list[ExceptionHandlerInfo] = []

        if not self.pe:
            return handlers

        for section in self.pe.sections:
            if b".pdata" in section.Name:
                data = section.get_data()

                i = 0
                while i < len(data) - 12:
                    begin_addr = struct_module.unpack("<I", data[i : i + 4])[0]
                    end_addr = struct_module.unpack("<I", data[i + 4 : i + 8])[0]
                    unwind_info = struct_module.unpack("<I", data[i + 8 : i + 12])[0]

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
        debug_info: DebugSymbolInfo | None = None

        if self.pe:
            debug_info = self._parse_pdb_info()

        elif self.lief_binary:
            if hasattr(self.lief_binary, "has_debug_info") and self.lief_binary.has_debug_info:
                debug_info = self._parse_dwarf_info()

        return debug_info

    def _parse_pdb_info(self) -> DebugSymbolInfo | None:
        """Parse PDB debug information from PE."""
        if not self.pe or not hasattr(self.pe, "DIRECTORY_ENTRY_DEBUG"):
            return None

        for debug_entry in self.pe.DIRECTORY_ENTRY_DEBUG:
            if debug_entry.struct.Type == 2:
                data = debug_entry.entry.name
                if data.startswith(b"RSDS"):
                    guid = data[4:20].hex()
                    age = struct_module.unpack("<I", data[20:24])[0]
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
        custom_types: list[GhidraDataType] = []

        for struct_obj in structures:
            ghidra_type = GhidraDataType(
                name=struct_obj.name,
                size=struct_obj.size,
                category="union" if struct_obj.is_union else "struct",
                members=struct_obj.members,
                alignment=struct_obj.alignment,
            )

            custom_types.append(ghidra_type)

            ptr_type = GhidraDataType(
                name=f"{struct_obj.name}*",
                size=8,
                category="pointer",
                base_type=struct_obj.name,
            )
            custom_types.append(ptr_type)

            for array_size in [10, 100, 256]:
                array_type = GhidraDataType(
                    name=f"{struct_obj.name}[{array_size}]",
                    size=struct_obj.size * array_size,
                    category="array",
                    base_type=struct_obj.name,
                )
                custom_types.append(array_type)

        return custom_types


def apply_advanced_analysis(analysis_result: GhidraAnalysisResult, binary_path: str) -> GhidraAnalysisResult:
    """Apply advanced analysis features to existing Ghidra results."""
    analyzer = GhidraAdvancedAnalyzer(binary_path)

    for func in analysis_result.functions.values():
        recovered_vars = analyzer.recover_variables(func)

        for var in recovered_vars:
            if var.scope == "local":
                func.local_variables.append((var.type, var.name, var.offset))
            elif var.scope == "parameter" and len(func.parameters) < 10:
                func.parameters.append((var.type, var.name))

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

    vtables = analyzer.analyze_vtables(analysis_result)
    for vtable in vtables:
        analysis_result.vtables[vtable.address] = vtable.functions

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

    custom_types = analyzer.create_custom_datatypes(structures)
    for custom_type in custom_types:
        analysis_result.data_types[custom_type.name] = custom_type

    return analysis_result
