"""Binary Ninja Analysis Engine.

This module provides advanced binary analysis capabilities using Binary Ninja,
focusing on license validation function identification, control flow analysis,
and decompilation for software protection cracking research.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import contextlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


try:
    import binaryninja as bn
    from binaryninja import BinaryView, Function, HighLevelILFunction, MediumLevelILFunction

    BINARYNINJA_AVAILABLE = True
except ImportError:
    BINARYNINJA_AVAILABLE = False
    bn = None
    BinaryView = Any
    Function = Any
    HighLevelILFunction = Any
    MediumLevelILFunction = Any

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    pefile = None


@dataclass
class BNFunction:
    """Represents a function analyzed by Binary Ninja."""

    name: str
    address: int
    size: int
    symbol_type: str
    can_return: bool
    has_variable_arguments: bool
    calling_convention: str
    parameter_count: int
    local_variable_count: int
    basic_block_count: int
    edge_count: int
    instruction_count: int
    cyclomatic_complexity: int
    xrefs_to: list[int]
    xrefs_from: list[int]
    calls: list[int]
    called_by: list[int]
    decompiled_code: str
    mlil_ssa_form: str
    hlil_code: str
    is_thunk: bool = False
    is_imported: bool = False
    is_exported: bool = False
    comments: dict[int, str] = field(default_factory=dict)
    strings_referenced: list[str] = field(default_factory=list)
    api_calls: list[str] = field(default_factory=list)


@dataclass
class BNBasicBlock:
    """Represents a basic block in control flow graph."""

    start: int
    end: int
    length: int
    instruction_count: int
    dominates: list[int]
    dominated_by: list[int]
    immediate_dominator: int | None
    outgoing_edges: list[int]
    incoming_edges: list[int]
    has_undetermined_outgoing_edges: bool


@dataclass
class BNAnalysisResult:
    """Complete analysis result from Binary Ninja."""

    binary_path: str
    architecture: str
    platform: str
    entry_point: int
    image_base: int
    functions: dict[int, BNFunction]
    strings: list[tuple[int, str]]
    imports: list[tuple[str, str, int]]
    exports: list[tuple[str, int]]
    sections: list[dict[str, Any]]
    symbols: dict[int, str]
    basic_blocks: dict[int, BNBasicBlock]
    license_validation_candidates: list[int]
    protection_indicators: dict[str, list[int]]
    metadata: dict[str, Any] = field(default_factory=dict)


class BinaryNinjaAnalyzer:
    """Advanced binary analysis using Binary Ninja for license cracking research."""

    LICENSE_VALIDATION_KEYWORDS = [
        "license",
        "serial",
        "key",
        "registration",
        "activation",
        "validate",
        "check",
        "verify",
        "authenticate",
        "trial",
        "expir",
        "demo",
        "unlock",
        "register",
        "authorized",
    ]

    PROTECTION_API_CALLS = {
        "anti_debug": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugString"],
        "anti_vm": ["GetSystemFirmwareTable", "SetupDiGetDeviceRegistryProperty", "EnumServicesStatus", "DeviceIoControl"],
        "crypto": [
            "CryptAcquireContext",
            "CryptCreateHash",
            "CryptHashData",
            "CryptDeriveKey",
            "BCryptOpenAlgorithmProvider",
            "BCryptEncrypt",
        ],
        "network": ["InternetOpen", "InternetConnect", "HttpSendRequest", "WSAStartup", "socket", "connect", "send", "recv"],
    }

    def __init__(self) -> None:
        """Initialize Binary Ninja analyzer."""
        self.logger = logging.getLogger(__name__)
        self.bv: BinaryView | None = None

        if not BINARYNINJA_AVAILABLE:
            self.logger.warning("Binary Ninja not available, will use fallback analysis")

    def analyze_binary(self, binary_path: str | Path) -> BNAnalysisResult:
        """Perform comprehensive binary analysis using Binary Ninja.

        Args:
            binary_path: Path to binary file to analyze

        Returns:
            Complete analysis result with functions, CFG, and license candidates

        Raises:
            FileNotFoundError: If binary file doesn't exist
            RuntimeError: If Binary Ninja analysis fails
        """
        binary_path = Path(binary_path)

        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        if not binary_path.is_file():
            raise ValueError(f"Not a file: {binary_path}")

        if not BINARYNINJA_AVAILABLE:
            self.logger.info("Falling back to pefile analysis")
            return self._fallback_analysis(binary_path)

        try:
            self.logger.info("Analyzing binary with Binary Ninja: %s", binary_path)
            self.bv = bn.open_view(str(binary_path))

            if self.bv is None:
                raise RuntimeError(f"Failed to open binary: {binary_path}")

            self.bv.update_analysis_and_wait()

            result = BNAnalysisResult(
                binary_path=str(binary_path),
                architecture=self.bv.arch.name if self.bv.arch else "unknown",
                platform=self.bv.platform.name if self.bv.platform else "unknown",
                entry_point=self.bv.entry_point,
                image_base=self.bv.start,
                functions={},
                strings=[],
                imports=[],
                exports=[],
                sections=[],
                symbols={},
                basic_blocks={},
                license_validation_candidates=[],
                protection_indicators={},
            )

            result.functions = self._analyze_functions()
            result.strings = self._extract_strings()
            result.imports = self._extract_imports()
            result.exports = self._extract_exports()
            result.sections = self._extract_sections()
            result.symbols = self._extract_symbols()
            result.basic_blocks = self._extract_basic_blocks()
            result.license_validation_candidates = self._identify_license_validators()
            result.protection_indicators = self._detect_protection_mechanisms()

            result.metadata = {
                "total_functions": len(result.functions),
                "total_basic_blocks": len(result.basic_blocks),
                "total_strings": len(result.strings),
                "total_imports": len(result.imports),
                "total_exports": len(result.exports),
                "license_candidates": len(result.license_validation_candidates),
            }

            return result

        except Exception as e:
            self.logger.exception("Binary Ninja analysis failed: %s", e)
            raise RuntimeError(f"Analysis failed: {e}") from e
        finally:
            if self.bv is not None:
                self.bv.file.close()

    def _analyze_functions(self) -> dict[int, BNFunction]:
        """Analyze all functions in the binary."""
        functions: dict[int, BNFunction] = {}

        if not self.bv or not BINARYNINJA_AVAILABLE:
            return functions

        for func in self.bv.functions:
            try:
                bn_func = self._analyze_single_function(func)
                functions[func.start] = bn_func
            except Exception as e:
                self.logger.warning("Failed to analyze function at 0x%x: %s", func.start, e)
                continue

        return functions

    def _analyze_single_function(self, func: Function) -> BNFunction:
        """Perform detailed analysis of a single function."""
        xrefs_to = [ref.address for ref in self.bv.get_code_refs(func.start)]
        xrefs_from = []
        calls = []
        called_by = [ref.address for ref in func.callers]

        for instr in func.instructions:
            for ref in func.get_callees(instr[1]):
                calls.append(ref.start)
                xrefs_from.append(instr[1])

        decompiled = ""
        hlil_code = ""
        mlil_ssa = ""

        try:
            if func.hlil:
                hlil_code = "\n".join(str(line) for line in func.hlil.instructions)
        except Exception:
            self.logger.exception("Failed to generate HLIL for function", exc_info=True)

        try:
            if func.mlil:
                mlil_ssa = "\n".join(str(line) for line in func.mlil.ssa_form.instructions)
        except Exception:
            self.logger.exception("Failed to generate MLIL SSA for function", exc_info=True)

        comments = {}
        for addr in func.address_ranges:
            for offset in range(addr.start, addr.end):
                if comment := func.get_comment_at(offset):
                    comments[offset] = comment

        strings_referenced = []
        api_calls = []

        for block in func.basic_blocks:
            for instr in block.disassembly_text:
                instr_text = str(instr)
                for string_ref in self.bv.strings:
                    if hex(string_ref.start)[2:] in instr_text:
                        strings_referenced.append(string_ref.value)

                for imp_name in [sym.short_name for sym in self.bv.symbols.values() if sym.type == bn.SymbolType.ImportedFunctionSymbol]:
                    if imp_name in instr_text:
                        api_calls.append(imp_name)

        return BNFunction(
            name=func.name,
            address=func.start,
            size=func.total_bytes,
            symbol_type=str(func.symbol.type) if func.symbol else "unknown",
            can_return=func.can_return.value if hasattr(func.can_return, "value") else True,
            has_variable_arguments=func.has_variable_arguments.value if hasattr(func.has_variable_arguments, "value") else False,
            calling_convention=func.calling_convention.name if func.calling_convention else "unknown",
            parameter_count=len(func.parameter_vars),
            local_variable_count=len(func.vars),
            basic_block_count=len(func.basic_blocks),
            edge_count=sum(len(bb.outgoing_edges) for bb in func.basic_blocks),
            instruction_count=sum(len(list(bb.disassembly_text)) for bb in func.basic_blocks),
            cyclomatic_complexity=self._calculate_cyclomatic_complexity(func),
            xrefs_to=xrefs_to,
            xrefs_from=xrefs_from,
            calls=calls,
            called_by=called_by,
            decompiled_code=decompiled,
            mlil_ssa_form=mlil_ssa,
            hlil_code=hlil_code,
            is_thunk=func.is_thunk,
            is_imported=func.symbol.type == bn.SymbolType.ImportedFunctionSymbol if func.symbol else False,
            is_exported=any(sym.address == func.start and sym.type == bn.SymbolType.FunctionSymbol for sym in self.bv.symbols.values()),
            comments=comments,
            strings_referenced=strings_referenced,
            api_calls=api_calls,
        )

    def _calculate_cyclomatic_complexity(self, func: Function) -> int:
        """Calculate cyclomatic complexity: M = E - N + 2P."""
        if not func.basic_blocks:
            return 1

        edges = sum(len(bb.outgoing_edges) for bb in func.basic_blocks)
        nodes = len(func.basic_blocks)

        return edges - nodes + 2

    def _extract_strings(self) -> list[tuple[int, str]]:
        """Extract all strings from binary."""
        strings: list[tuple[int, str]] = []

        if not self.bv or not BINARYNINJA_AVAILABLE:
            return strings

        strings.extend((string_ref.start, string_ref.value) for string_ref in self.bv.strings)
        return strings

    def _extract_imports(self) -> list[tuple[str, str, int]]:
        """Extract imported functions."""
        imports: list[tuple[str, str, int]] = []

        if not self.bv or not BINARYNINJA_AVAILABLE:
            return imports

        for sym in self.bv.symbols.values():
            if sym.type == bn.SymbolType.ImportedFunctionSymbol:
                lib = sym.namespace if hasattr(sym, "namespace") and sym.namespace else "unknown"
                imports.append((lib, sym.short_name, sym.address))

        return imports

    def _extract_exports(self) -> list[tuple[str, int]]:
        """Extract exported functions."""
        exports: list[tuple[str, int]] = []

        if not self.bv or not BINARYNINJA_AVAILABLE:
            return exports

        exports.extend(
            (sym.short_name, sym.address)
            for sym in self.bv.symbols.values()
            if any(seg.readable and seg.executable for seg in self.bv.segments)
            and sym.type in (bn.SymbolType.FunctionSymbol, bn.SymbolType.DataSymbol)
        )
        return exports

    def _extract_sections(self) -> list[dict[str, Any]]:
        """Extract section information."""
        sections: list[dict[str, Any]] = []

        if not self.bv or not BINARYNINJA_AVAILABLE:
            return sections

        sections.extend(
            {
                "name": section.name,
                "start": section.start,
                "end": section.end,
                "size": section.end - section.start,
                "type": section.type,
            }
            for section in self.bv.sections.values()
        )
        return sections

    def _extract_symbols(self) -> dict[int, str]:
        """Extract all symbols."""
        symbols: dict[int, str] = {}

        if not self.bv or not BINARYNINJA_AVAILABLE:
            return symbols

        for sym in self.bv.symbols.values():
            symbols[sym.address] = sym.full_name

        return symbols

    def _extract_basic_blocks(self) -> dict[int, BNBasicBlock]:
        """Extract all basic blocks with control flow information."""
        blocks: dict[int, BNBasicBlock] = {}

        if not self.bv or not BINARYNINJA_AVAILABLE:
            return blocks

        for func in self.bv.functions:
            for bb in func.basic_blocks:
                dominates = [dom.start for dom in bb.dominance_frontier]
                dominated_by = []

                immediate_dominator = None
                if bb.immediate_dominator:
                    immediate_dominator = bb.immediate_dominator.start

                outgoing = [edge.target.start for edge in bb.outgoing_edges]
                incoming = [edge.source.start for edge in bb.incoming_edges]

                blocks[bb.start] = BNBasicBlock(
                    start=bb.start,
                    end=bb.end,
                    length=bb.length,
                    instruction_count=bb.instruction_count,
                    dominates=dominates,
                    dominated_by=dominated_by,
                    immediate_dominator=immediate_dominator,
                    outgoing_edges=outgoing,
                    incoming_edges=incoming,
                    has_undetermined_outgoing_edges=bb.has_undetermined_outgoing_edges,
                )

        return blocks

    def _identify_license_validators(self) -> list[int]:
        """Identify potential license validation functions."""
        candidates: list[int] = []

        if not self.bv or not BINARYNINJA_AVAILABLE:
            return candidates

        for func in self.bv.functions:
            func_name_lower = func.name.lower()

            score = sum(10 for keyword in self.LICENSE_VALIDATION_KEYWORDS if keyword in func_name_lower)
            try:
                if func.hlil:
                    hlil_text = "\n".join(str(line) for line in func.hlil.instructions).lower()
                    for keyword in self.LICENSE_VALIDATION_KEYWORDS:
                        score += hlil_text.count(keyword) * 2
            except Exception:
                self.logger.exception("Failed to analyze HLIL for license validation keywords", exc_info=True)

            for string_addr, string_val in self._extract_strings():
                string_lower = string_val.lower()
                for keyword in self.LICENSE_VALIDATION_KEYWORDS:
                    if keyword in string_lower:
                        for ref in self.bv.get_code_refs(string_addr):
                            if func.start <= ref.address < func.start + func.total_bytes:
                                score += 5

            for _imp_lib, imp_name, imp_addr in self._extract_imports():
                imp_name_lower = imp_name.lower()
                if any(keyword in imp_name_lower for keyword in self.LICENSE_VALIDATION_KEYWORDS):
                    for caller in self.bv.get_code_refs(imp_addr):
                        if func.start <= caller.address < func.start + func.total_bytes:
                            score += 3

            if score >= 10:
                candidates.append(func.start)

        return sorted(candidates, key=lambda addr: addr)

    def _detect_protection_mechanisms(self) -> dict[str, list[int]]:
        """Detect anti-debug, anti-VM, and other protection mechanisms."""
        protections: dict[str, list[int]] = {"anti_debug": [], "anti_vm": [], "crypto": [], "network": []}

        if not self.bv or not BINARYNINJA_AVAILABLE:
            return protections

        for func in self.bv.functions:
            for category, api_list in self.PROTECTION_API_CALLS.items():
                for api_name in api_list:
                    for sym in self.bv.symbols.values():
                        if sym.short_name == api_name:
                            for ref in self.bv.get_code_refs(sym.address):
                                if func.start <= ref.address < func.start + func.total_bytes and func.start not in protections[category]:
                                    protections[category].append(func.start)

        return protections

    def _fallback_analysis(self, binary_path: Path) -> BNAnalysisResult:
        """Fallback to basic PE analysis when Binary Ninja unavailable."""
        if not PEFILE_AVAILABLE:
            raise RuntimeError("Neither Binary Ninja nor pefile available for analysis")

        self.logger.info("Using pefile fallback for: %s", binary_path)

        try:
            pe = pefile.PE(str(binary_path))

            imports = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode("utf-8", errors="ignore")
                            imports.append((dll_name, func_name, imp.address))

            exports = []
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        name = exp.name.decode("utf-8", errors="ignore")
                        exports.append((name, pe.OPTIONAL_HEADER.ImageBase + exp.address))

            sections = [
                {
                    "name": section.Name.decode("utf-8", errors="ignore").rstrip("\x00"),
                    "start": pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress,
                    "end": pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + section.Misc_VirtualSize,
                    "size": section.Misc_VirtualSize,
                    "type": "section",
                }
                for section in pe.sections
            ]
            strings = []
            for section in pe.sections:
                if section.IMAGE_SCN_MEM_EXECUTE or section.IMAGE_SCN_CNT_CODE:
                    continue
                data = section.get_data()
                current_string = b""
                current_addr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

                for i, byte in enumerate(data):
                    if 32 <= byte < 127:
                        current_string += bytes([byte])
                    else:
                        if len(current_string) >= 4:
                            with contextlib.suppress(Exception):
                                strings.append((current_addr + i - len(current_string), current_string.decode("ascii", errors="ignore")))
                        current_string = b""

            return BNAnalysisResult(
                binary_path=str(binary_path),
                architecture=pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine],
                platform="windows",
                entry_point=pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                image_base=pe.OPTIONAL_HEADER.ImageBase,
                functions={},
                strings=strings,
                imports=imports,
                exports=exports,
                sections=sections,
                symbols={},
                basic_blocks={},
                license_validation_candidates=[],
                protection_indicators={},
                metadata={"analysis_method": "pefile_fallback"},
            )
        except Exception as e:
            self.logger.exception("Fallback analysis failed: %s", e)
            raise RuntimeError(f"Fallback analysis failed: {e}") from e

    def get_function_cfg(self, function_address: int) -> dict[str, Any]:
        """Extract control flow graph for specific function.

        Args:
            function_address: Address of function to analyze

        Returns:
            Dictionary containing CFG nodes and edges

        Raises:
            ValueError: If function not found or Binary Ninja unavailable
        """
        if not self.bv or not BINARYNINJA_AVAILABLE:
            raise ValueError("Binary Ninja not available or binary not loaded")

        func = self.bv.get_function_at(function_address)
        if not func:
            raise ValueError(f"No function found at address 0x{function_address:x}")

        nodes = []
        edges = []

        for bb in func.basic_blocks:
            instructions = [str(instr) for instr in bb.disassembly_text]
            nodes.append({
                "address": bb.start,
                "end": bb.end,
                "instructions": instructions,
                "has_undetermined_outgoing_edges": bb.has_undetermined_outgoing_edges,
            })

            edges.extend(
                {
                    "source": bb.start,
                    "target": edge.target.start,
                    "type": str(edge.type),
                }
                for edge in bb.outgoing_edges
            )
        return {
            "function_name": func.name,
            "function_address": function_address,
            "nodes": nodes,
            "edges": edges,
            "entry_block": func.basic_blocks[0].start if func.basic_blocks else None,
        }

    def decompile_function(self, function_address: int) -> str:
        """Decompile function to high-level pseudocode.

        Args:
            function_address: Address of function to decompile

        Returns:
            Decompiled pseudocode as string

        Raises:
            ValueError: If function not found or decompilation fails
        """
        if not self.bv or not BINARYNINJA_AVAILABLE:
            raise ValueError("Binary Ninja not available or binary not loaded")

        func = self.bv.get_function_at(function_address)
        if not func:
            raise ValueError(f"No function found at address 0x{function_address:x}")

        try:
            if func.hlil:
                return "\n".join(str(line) for line in func.hlil.instructions)
            elif func.mlil:
                return "\n".join(str(line) for line in func.mlil.instructions)
            else:
                return "\n".join(str(line) for line in func.llil.instructions)
        except Exception as e:
            raise ValueError(f"Decompilation failed: {e}") from e

    def close(self) -> None:
        """Close Binary Ninja binary view."""
        if self.bv is not None and BINARYNINJA_AVAILABLE:
            self.bv.file.close()
            self.bv = None
