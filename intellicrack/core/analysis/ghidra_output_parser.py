"""Ghidra Output Parser - Production Implementation.

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

import json
import logging
import re


from dataclasses import dataclass, field

from defusedxml import ElementTree as ET
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


@dataclass
class FunctionSignature:
    """Represents a parsed function signature."""

    name: str
    address: int
    return_type: str
    parameters: list[tuple[str, str]]  # (type, name) pairs
    calling_convention: str
    is_thunk: bool = False
    is_exported: bool = False
    is_imported: bool = False
    stack_frame_size: int = 0
    local_variables: list[tuple[str, str, int]] = field(default_factory=list)  # (type, name, offset)


@dataclass
class DataStructure:
    """Represents a parsed data structure."""

    name: str
    size: int
    fields: list[tuple[str, str, int, int]]  # (type, name, offset, size)
    is_union: bool = False
    alignment: int = 1
    packed: bool = False


@dataclass
class CrossReference:
    """Represents a cross-reference."""

    from_address: int
    to_address: int
    ref_type: str  # CALL, JUMP, DATA_READ, DATA_WRITE
    from_function: str | None = None
    to_function: str | None = None
    instruction: str | None = None


@dataclass
class DecompiledFunction:
    """Represents decompiled C/C++ pseudocode."""

    name: str
    address: int
    pseudocode: str
    high_pcode: str | None = None  # High-level P-code representation
    complexity: int = 0
    basic_blocks: int = 0
    edges: int = 0


class GhidraOutputParser:
    """Parses Ghidra analysis output in various formats."""

    def __init__(self) -> None:
        """Initialize the GhidraOutputParser with empty data structures."""
        self.functions: dict[int, FunctionSignature] = {}
        self.structures: dict[str, DataStructure] = {}
        self.xrefs: list[CrossReference] = []
        self.decompiled: dict[int, DecompiledFunction] = {}
        self.imports: dict[str, int] = {}
        self.exports: dict[str, int] = {}
        self.strings: dict[int, str] = {}
        self.vtables: dict[int, list[int]] = {}

    def parse_xml_output(self, xml_path: Path) -> dict[str, Any]:
        """Parse Ghidra XML export format.

        Parses Ghidra's XML export format to extract program information,
        function definitions, data structures, cross-references, and strings
        for licensing protection analysis.

        Args:
            xml_path: Path to the Ghidra XML export file.

        Returns:
            dict[str, Any]: Dictionary containing parsed counts of functions,
                structures, cross-references, and strings with program metadata.

        Raises:
            Exception: If XML parsing fails or file cannot be read.
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            # Parse program information
            program_info = self._parse_program_info(root)

            # Parse functions
            for func_elem in root.findall(".//FUNCTIONS/FUNCTION"):
                function = self._parse_function_xml(func_elem)
                self.functions[function.address] = function

            # Parse data structures
            for struct_elem in root.findall(".//DATA_TYPES/STRUCTURE"):
                structure = self._parse_structure_xml(struct_elem)
                self.structures[structure.name] = structure

            # Parse cross-references
            for xref_elem in root.findall(".//PROGRAM_XREFS/XREF"):
                xref = self._parse_xref_xml(xref_elem)
                self.xrefs.append(xref)

            # Parse strings
            for string_elem in root.findall(".//DEFINED_DATA/STRING"):
                addr = int(string_elem.get("ADDRESS", "0"), 16)
                value = string_elem.get("VALUE", "")
                self.strings[addr] = value

            return {
                "program_info": program_info,
                "functions": len(self.functions),
                "structures": len(self.structures),
                "xrefs": len(self.xrefs),
                "strings": len(self.strings),
            }

        except Exception as e:
            logger.exception("Failed to parse XML output: %s", e)
            raise

    def parse_json_output(self, json_path: Path) -> dict[str, Any]:
        """Parse Ghidra JSON export format.

        Parses Ghidra's JSON export format to extract function signatures,
        decompiled pseudocode, imports, exports, and virtual tables for
        binary licensing protection analysis.

        Args:
            json_path: Path to the Ghidra JSON export file.

        Returns:
            dict[str, Any]: Dictionary containing counts of parsed functions,
                decompilation results, imports, exports, and virtual tables.

        Raises:
            Exception: If JSON parsing fails or file cannot be read.
        """
        try:
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)

            # Parse functions from JSON
            if "functions" in data:
                for func_data in data["functions"]:
                    function = FunctionSignature(
                        name=func_data["name"],
                        address=int(func_data["address"], 16),
                        return_type=func_data.get("returnType", "void"),
                        parameters=[(p["type"], p["name"]) for p in func_data.get("parameters", [])],
                        calling_convention=func_data.get("callingConvention", "default"),
                        is_thunk=func_data.get("isThunk", False),
                        is_exported=func_data.get("isExported", False),
                        is_imported=func_data.get("isImported", False),
                        stack_frame_size=func_data.get("stackFrameSize", 0),
                        local_variables=[(v["type"], v["name"], v["offset"]) for v in func_data.get("localVariables", [])],
                    )
                    self.functions[function.address] = function

            # Parse decompilation results
            if "decompilation" in data:
                for decomp_data in data["decompilation"]:
                    decompiled = DecompiledFunction(
                        name=decomp_data["name"],
                        address=int(decomp_data["address"], 16),
                        pseudocode=decomp_data["code"],
                        high_pcode=decomp_data.get("pcode"),
                        complexity=decomp_data.get("cyclomaticComplexity", 0),
                        basic_blocks=decomp_data.get("basicBlocks", 0),
                        edges=decomp_data.get("edges", 0),
                    )
                    self.decompiled[decompiled.address] = decompiled

            # Parse imports/exports
            if "imports" in data:
                for imp in data["imports"]:
                    self.imports[imp["name"]] = int(imp["address"], 16)

            if "exports" in data:
                for exp in data["exports"]:
                    self.exports[exp["name"]] = int(exp["address"], 16)

            # Parse virtual tables
            if "vtables" in data:
                for vtable in data["vtables"]:
                    addr = int(vtable["address"], 16)
                    entries = [int(e, 16) for e in vtable["entries"]]
                    self.vtables[addr] = entries

            return {
                "functions": len(self.functions),
                "decompiled": len(self.decompiled),
                "imports": len(self.imports),
                "exports": len(self.exports),
                "vtables": len(self.vtables),
            }

        except Exception as e:
            logger.exception("Failed to parse JSON output: %s", e)
            raise

    def parse_decompilation_output(self, decomp_path: Path) -> list[DecompiledFunction]:
        """Parse Ghidra decompiler output.

        Extracts decompiled pseudocode from Ghidra's decompilation output,
        including function boundaries, code structure, and complexity metrics
        for licensing protection analysis.

        Args:
            decomp_path: Path to the Ghidra decompilation output file.

        Returns:
            list[DecompiledFunction]: List of DecompiledFunction objects with
                pseudocode and complexity metrics.

        Raises:
            Exception: If parsing fails or file cannot be read.
        """
        decompiled_functions = []

        try:
            content = decomp_path.read_text(encoding="utf-8", errors="ignore")

            # Parse function boundaries
            function_pattern = r"/\*\s+\*\s+FUNCTION:\s+([^\s]+)\s+@\s+(0x[0-9a-fA-F]+)\s+\*/"
            code_blocks = re.split(function_pattern, content)

            # Process each function
            for i in range(1, len(code_blocks), 3):
                if i + 1 < len(code_blocks):
                    func_name = code_blocks[i]
                    func_addr = int(code_blocks[i + 1], 16)
                    func_code = code_blocks[i + 2] if i + 2 < len(code_blocks) else ""

                    # Clean up the pseudocode
                    func_code = self._clean_pseudocode(func_code)

                    # Calculate complexity metrics
                    complexity = self._calculate_complexity(func_code)
                    blocks = func_code.count("{")

                    decompiled = DecompiledFunction(
                        name=func_name,
                        address=func_addr,
                        pseudocode=func_code,
                        complexity=complexity,
                        basic_blocks=blocks,
                    )

                    decompiled_functions.append(decompiled)
                    self.decompiled[func_addr] = decompiled

            return decompiled_functions

        except Exception as e:
            logger.exception("Failed to parse decompilation output: %s", e)
            raise

    def parse_call_graph(self, graph_path: Path) -> dict[str, list[str]]:
        """Parse Ghidra call graph export.

        Parses call graph data to identify function call relationships
        and dependencies for tracing licensing validation routines.

        Args:
            graph_path: Path to the call graph file.

        Returns:
            dict[str, list[str]]: Dictionary mapping function names to lists
                of called functions.

        Raises:
            Exception: If parsing fails or file cannot be read.
        """
        call_graph: dict[str, list[str]] = {}

        try:
            with open(graph_path, encoding="utf-8") as f:
                for line in f:
                    if match := re.match(r"([^\s]+)\s+->\s+([^\s]+)", line.strip()):
                        caller = match[1]
                        callee = match[2]

                        if caller not in call_graph:
                            call_graph[caller] = []
                        call_graph[caller].append(callee)

            return call_graph

        except Exception as e:
            logger.exception("Failed to parse call graph: %s", e)
            raise

    def parse_data_types(self, types_path: Path) -> dict[str, DataStructure]:
        """Parse Ghidra data type definitions.

        Parses data type definitions to extract structure layouts and field
        information for analyzing binary protection data structures.

        Args:
            types_path: Path to the data type definitions file.

        Returns:
            dict[str, DataStructure]: Dictionary mapping structure names to
                DataStructure objects.

        Raises:
            Exception: If parsing fails or file cannot be read.
        """
        structures = {}

        try:
            content = types_path.read_text(encoding="utf-8", errors="ignore")

            # Parse structure definitions
            struct_pattern = r"struct\s+(\w+)\s*\{([^}]+)\}"

            for match in re.finditer(struct_pattern, content, re.DOTALL):
                struct_name = match.group(1)
                struct_body = match.group(2)

                # Parse fields
                fields = []
                field_pattern = r"([^;]+)\s+(\w+)(?:\[(\d+)\])?;"

                offset = 0
                for field_match in re.finditer(field_pattern, struct_body):
                    field_type = field_match.group(1).strip()
                    field_name = field_match.group(2)
                    array_size = field_match.group(3)

                    # Calculate field size
                    field_size = self._get_type_size(field_type)
                    if array_size:
                        field_size *= int(array_size)

                    fields.append((field_type, field_name, offset, field_size))
                    offset += field_size

                structure = DataStructure(name=struct_name, size=offset, fields=fields)

                structures[struct_name] = structure
                self.structures[struct_name] = structure

            return structures

        except Exception as e:
            logger.exception("Failed to parse data types: %s", e)
            raise

    def _parse_program_info(self, root: ET.Element) -> dict[str, Any]:
        """Parse program information from XML.

        Extracts program metadata including executable path, format, and
        base address from Ghidra's XML analysis output.

        Args:
            root: The root XML element of the Ghidra export.

        Returns:
            dict[str, Any]: Dictionary containing program name, executable
                path, format, and image base address.
        """
        info = {}

        prog_elem = root.find(".//PROGRAM")
        if prog_elem is not None:
            info["name"] = prog_elem.get("NAME", "")
            info["exe_path"] = prog_elem.get("EXE_PATH", "")
            info["exe_format"] = prog_elem.get("EXE_FORMAT", "")
            info["image_base"] = prog_elem.get("IMAGE_BASE", "")

        return info

    def _parse_function_xml(self, elem: ET.Element) -> FunctionSignature:
        """Parse function from XML element.

        Extracts function signature including name, address, parameters,
        return type, and local variables from Ghidra XML analysis.

        Args:
            elem: XML element containing function definition.

        Returns:
            FunctionSignature: Object with parsed function metadata including
                name, address, parameters, calling convention, and local
                variables.
        """
        name = elem.get("NAME", "")
        addr = int(elem.get("ENTRY_POINT", "0"), 16)

        # Parse return type
        return_elem = elem.find("RETURN_TYPE")
        return_type = return_elem.get("VALUE", "void") if return_elem is not None else "void"

        # Parse parameters
        params = []
        for param_elem in elem.findall(".//PARAMETER"):
            param_type = param_elem.get("DATATYPE", "")
            param_name = param_elem.get("NAME", "")
            params.append((param_type, param_name))

        # Parse local variables
        locals_list = []
        for var_elem in elem.findall(".//LOCAL_VAR"):
            var_type = var_elem.get("DATATYPE", "")
            var_name = var_elem.get("NAME", "")
            var_offset = int(var_elem.get("STACK_OFFSET", "0"))
            locals_list.append((var_type, var_name, var_offset))

        return FunctionSignature(
            name=name,
            address=addr,
            return_type=return_type,
            parameters=params,
            calling_convention=elem.get("CALLING_CONVENTION", "default"),
            is_thunk=elem.get("IS_THUNK", "false").lower() == "true",
            stack_frame_size=int(elem.get("STACK_FRAME_SIZE", "0")),
            local_variables=locals_list,
        )

    def _parse_structure_xml(self, elem: ET.Element) -> DataStructure:
        """Parse structure from XML element.

        Extracts data structure definition including fields, offsets, and
        size information from Ghidra's analysis output.

        Args:
            elem: XML element containing structure definition.

        Returns:
            DataStructure: Object with parsed field information including
                name, size, field list, and structure properties.
        """
        name = elem.get("NAME", "")
        size = int(elem.get("SIZE", "0"))

        fields = []
        for field_elem in elem.findall(".//MEMBER"):
            field_type = field_elem.get("DATATYPE", "")
            field_name = field_elem.get("NAME", "")
            field_offset = int(field_elem.get("OFFSET", "0"))
            field_size = int(field_elem.get("SIZE", "0"))
            fields.append((field_type, field_name, field_offset, field_size))

        return DataStructure(
            name=name,
            size=size,
            fields=fields,
            is_union=elem.get("IS_UNION", "false").lower() == "true",
        )

    def _parse_xref_xml(self, elem: ET.Element) -> CrossReference:
        """Parse cross-reference from XML element.

        Extracts cross-reference data including source, destination,
        reference type, and associated functions for call graph analysis.

        Args:
            elem: XML element containing cross-reference definition.

        Returns:
            CrossReference: Object with parsed reference metadata including
                source address, destination address, reference type, and
                associated function names.
        """
        return CrossReference(
            from_address=int(elem.get("FROM", "0"), 16),
            to_address=int(elem.get("TO", "0"), 16),
            ref_type=elem.get("TYPE", "UNKNOWN"),
            from_function=elem.get("FROM_FUNCTION"),
            to_function=elem.get("TO_FUNCTION"),
        )

    def _clean_pseudocode(self, code: str) -> str:
        """Clean up decompiled pseudocode.

        Removes Ghidra warnings, DWARF comments, and normalizes whitespace
        in decompiled pseudocode for cleaner analysis output.

        Args:
            code: Raw decompiled pseudocode from Ghidra.

        Returns:
            str: Cleaned pseudocode with normalized formatting.
        """
        # Remove excessive whitespace
        code = re.sub(r"\n\s*\n\s*\n", "\n\n", code)

        # Remove Ghidra comments that aren't useful
        code = re.sub(r"/\*\s+WARNING:.*?\*/", "", code, flags=re.DOTALL)
        code = re.sub(r"/\*\s+DWARF.*?\*/", "", code, flags=re.DOTALL)

        return code.strip()

    def _calculate_complexity(self, code: str) -> int:
        """Calculate cyclomatic complexity of pseudocode.

        Computes cyclomatic complexity by counting control flow statements
        including conditionals, loops, and logical operators to assess
        licensing routine code complexity.

        Args:
            code: Decompiled pseudocode.

        Returns:
            int: Cyclomatic complexity score.
        """
        complexity = 1 + code.count("if ")
        complexity += code.count("else if ")
        complexity += code.count("while ")
        complexity += code.count("for ")
        complexity += code.count("switch ")
        complexity += code.count("case ")
        complexity += code.count("&&")
        complexity += code.count("||")
        complexity += code.count("? ")  # Ternary operator

        return complexity

    def _get_type_size(self, type_name: str) -> int:
        """Get size of a data type in bytes.

        Determines the binary size of a data type assuming 64-bit
        architecture for licensing protection structure analysis.

        Args:
            type_name: C/C++ data type name.

        Returns:
            int: Size in bytes. Defaults to 4 bytes for unknown types.
        """
        # Basic type sizes (architecture-dependent, assuming 64-bit)
        type_sizes = {
            "char": 1,
            "unsigned char": 1,
            "byte": 1,
            "BYTE": 1,
            "short": 2,
            "unsigned short": 2,
            "WORD": 2,
            "int": 4,
            "unsigned int": 4,
            "DWORD": 4,
            "long": 4,
            "long long": 8,
            "unsigned long long": 8,
            "QWORD": 8,
            "float": 4,
            "double": 8,
            "void*": 8,
            "pointer": 8,
        }

        # Handle pointers
        if "*" in type_name or type_name.startswith("LP"):
            return 8  # 64-bit pointer

        # Check known types
        base_type = type_name.split(maxsplit=1)[0] if " " in type_name else type_name
        return type_sizes.get(base_type, 4)  # Default to 4 bytes

    def get_function_by_name(self, name: str) -> FunctionSignature | None:
        """Get function by name.

        Retrieves a function signature by its symbolic name for
        licensing analysis and validation routine identification.

        Args:
            name: Function name to search for.

        Returns:
            FunctionSignature | None: FunctionSignature object if found,
                None otherwise.
        """
        return next((func for func in self.functions.values() if func.name == name), None)

    def get_function_by_address(self, address: int) -> FunctionSignature | None:
        """Get function by address.

        Retrieves a function signature by its memory address for
        binary location-based analysis and protection mechanism tracing.

        Args:
            address: Memory address of the function.

        Returns:
            FunctionSignature | None: FunctionSignature object if found,
                None otherwise.
        """
        return self.functions.get(address)

    def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Get all cross-references to an address.

        Retrieves incoming cross-references to identify callers and
        code sections that interact with a target address for
        licensing validation analysis.

        Args:
            address: Target memory address.

        Returns:
            list[CrossReference]: List of CrossReference objects pointing to
                the address.
        """
        return [xref for xref in self.xrefs if xref.to_address == address]

    def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Get all cross-references from an address.

        Retrieves outgoing cross-references to identify code called by or
        data accessed from a source address for tracing licensing
        protection mechanisms.

        Args:
            address: Source memory address.

        Returns:
            list[CrossReference]: List of CrossReference objects originating
                from the address.
        """
        return [xref for xref in self.xrefs if xref.from_address == address]

    def get_call_targets(self, function_name: str) -> list[str]:
        """Get all functions called by a function.

        Retrieves the list of functions called by a specified function
        for call chain analysis of licensing validation routines.

        Args:
            function_name: Name of the function to analyze.

        Returns:
            list[str]: List of function names called by the specified function.
        """
        targets: list[str] = []
        if func := self.get_function_by_name(function_name):
            targets.extend(xref.to_function for xref in self.get_xrefs_from(func.address) if xref.ref_type == "CALL" and xref.to_function)
        return targets

    def export_to_json(self, output_path: Path) -> None:
        """Export parsed data to JSON format.

        Serializes all parsed Ghidra analysis data including functions,
        structures, cross-references, and decompiled code to JSON file
        for external processing and licensing protection analysis.

        Args:
            output_path: Path where JSON export will be written.
        """
        data = {
            "functions": [
                {
                    "name": f.name,
                    "address": hex(f.address),
                    "return_type": f.return_type,
                    "parameters": [{"type": t, "name": n} for t, n in f.parameters],
                    "calling_convention": f.calling_convention,
                    "stack_frame_size": f.stack_frame_size,
                    "local_variables": [{"type": t, "name": n, "offset": o} for t, n, o in f.local_variables],
                }
                for f in self.functions.values()
            ],
            "structures": [
                {
                    "name": s.name,
                    "size": s.size,
                    "fields": [{"type": t, "name": n, "offset": o, "size": sz} for t, n, o, sz in s.fields],
                }
                for s in self.structures.values()
            ],
            "cross_references": [
                {
                    "from": hex(x.from_address),
                    "to": hex(x.to_address),
                    "type": x.ref_type,
                    "from_function": x.from_function,
                    "to_function": x.to_function,
                }
                for x in self.xrefs
            ],
            "decompiled": [
                {
                    "name": d.name,
                    "address": hex(d.address),
                    "complexity": d.complexity,
                    "basic_blocks": d.basic_blocks,
                    "code": d.pseudocode[:1000],  # First 1000 chars for preview
                }
                for d in self.decompiled.values()
            ],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
