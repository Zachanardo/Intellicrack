"""Ghidra Analysis Engine.

This module provides the core functionality for running Ghidra headless analysis
and processing the results.

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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile

try:
    import defusedxml.ElementTree as ET  # noqa: N817
except ImportError:
    import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from threading import Thread
from typing import Any

from intellicrack.core.config_manager import get_config
from intellicrack.utils.subprocess_security import secure_popen


@dataclass
class GhidraFunction:
    """Represents a function analyzed by Ghidra."""

    name: str
    address: int
    size: int
    signature: str
    return_type: str
    parameters: list[tuple[str, str]]  # (type, name) pairs
    local_variables: list[tuple[str, str, int]]  # (type, name, offset) triples
    decompiled_code: str
    assembly_code: str
    xrefs_to: list[int]  # addresses that reference this function
    xrefs_from: list[int]  # addresses this function references
    comments: dict[int, str]  # offset -> comment mapping
    is_thunk: bool = False
    is_external: bool = False
    calling_convention: str = "__cdecl"


@dataclass
class GhidraDataType:
    """Represents a data type/structure analyzed by Ghidra."""

    name: str
    size: int
    category: str  # struct, enum, typedef, etc.
    members: list[dict[str, Any]] = field(default_factory=list)
    base_type: str | None = None
    alignment: int = 1


@dataclass
class GhidraAnalysisResult:
    """Complete analysis result from Ghidra."""

    binary_path: str
    architecture: str
    compiler: str
    functions: dict[int, GhidraFunction]  # address -> function mapping
    data_types: dict[str, GhidraDataType]  # name -> type mapping
    strings: list[tuple[int, str]]  # (address, string) pairs
    imports: list[tuple[str, str, int]]  # (library, function, address) triples
    exports: list[tuple[str, int]]  # (name, address) pairs
    sections: list[dict[str, Any]]
    entry_point: int
    image_base: int
    vtables: dict[int, list[int]]  # address -> vtable function pointers
    exception_handlers: list[dict[str, Any]]
    metadata: dict[str, Any] = field(default_factory=dict)


class GhidraOutputParser:
    """Parses various Ghidra output formats."""

    def __init__(self) -> None:
        """Initialize the GhidraOutputParser with an empty result."""
        self.result = None

    def parse_xml_output(self, xml_content: str) -> GhidraAnalysisResult:
        """Parse Ghidra XML output format."""
        try:
            root = ET.fromstring(xml_content)  # noqa: S314

            # Extract binary information
            binary_info = root.find(".//PROGRAM")
            binary_path = binary_info.get("NAME", "")
            image_base = int(binary_info.get("IMAGE_BASE", "0"), 16)

            # Extract architecture and compiler
            processor = root.find(".//PROCESSOR")
            architecture = processor.get("NAME", "unknown") if processor is not None else "unknown"
            compiler_elem = root.find(".//COMPILER")
            compiler = compiler_elem.get("NAME", "unknown") if compiler_elem is not None else "unknown"

            # Parse functions
            functions = {}
            for func_elem in root.findall(".//FUNCTION"):
                func = self._parse_xml_function(func_elem)
                functions[func.address] = func

            # Parse data types
            data_types = {}
            for dt_elem in root.findall(".//DATA_TYPE"):
                dt = self._parse_xml_datatype(dt_elem)
                data_types[dt.name] = dt

            # Parse strings
            strings = []
            for str_elem in root.findall('.//DEFINED_DATA[@DATATYPE="string"]'):
                addr = int(str_elem.get("ADDRESS", "0"), 16)
                value = str_elem.get("VALUE", "")
                strings.append((addr, value))

            # Parse imports
            imports = []
            for imp_elem in root.findall(".//IMPORT"):
                lib = imp_elem.get("LIBRARY", "")
                func = imp_elem.get("FUNCTION", "")
                addr = int(imp_elem.get("ADDRESS", "0"), 16)
                imports.append((lib, func, addr))

            # Parse exports
            exports = []
            for exp_elem in root.findall(".//EXPORT"):
                name = exp_elem.get("NAME", "")
                addr = int(exp_elem.get("ADDRESS", "0"), 16)
                exports.append((name, addr))

            # Parse sections
            sections = []
            for sec_elem in root.findall(".//MEMORY_SECTION"):
                sections.append(
                    {
                        "name": sec_elem.get("NAME", ""),
                        "start": int(sec_elem.get("START_ADDR", "0"), 16),
                        "size": int(sec_elem.get("LENGTH", "0"), 16),
                        "permissions": sec_elem.get("PERMISSIONS", ""),
                        "type": sec_elem.get("TYPE", ""),
                    },
                )

            # Parse entry point
            entry_elem = root.find(".//PROGRAM_ENTRY_POINT")
            entry_point = int(entry_elem.get("ADDRESS", "0"), 16) if entry_elem is not None else 0

            # Parse virtual tables
            vtables = {}
            for vt_elem in root.findall(".//VTABLE"):
                addr = int(vt_elem.get("ADDRESS", "0"), 16)
                funcs = [int(f.get("ADDRESS", "0"), 16) for f in vt_elem.findall(".//VFUNCTION")]
                vtables[addr] = funcs

            # Parse exception handlers
            exception_handlers = []
            for eh_elem in root.findall(".//EXCEPTION_HANDLER"):
                exception_handlers.append(
                    {
                        "address": int(eh_elem.get("ADDRESS", "0"), 16),
                        "type": eh_elem.get("TYPE", ""),
                        "handler": int(eh_elem.get("HANDLER", "0"), 16),
                    },
                )

            return GhidraAnalysisResult(
                binary_path=binary_path,
                architecture=architecture,
                compiler=compiler,
                functions=functions,
                data_types=data_types,
                strings=strings,
                imports=imports,
                exports=exports,
                sections=sections,
                entry_point=entry_point,
                image_base=image_base,
                vtables=vtables,
                exception_handlers=exception_handlers,
            )
        except Exception as e:
            raise ValueError(f"Failed to parse XML output: {e}") from e

    def _parse_xml_function(self, func_elem) -> GhidraFunction:
        """Parse a function element from XML."""
        name = func_elem.get("NAME", "unknown")
        address = int(func_elem.get("ENTRY_POINT", "0"), 16)
        size = int(func_elem.get("SIZE", "0"), 16)

        # Parse signature
        sig_elem = func_elem.find(".//SIGNATURE")
        if sig_elem is not None:
            signature = sig_elem.text or ""
            return_type = sig_elem.get("RETURN_TYPE", "void")
        else:
            signature = f"{name}()"
            return_type = "void"

        # Parse parameters
        parameters = []
        for param_elem in func_elem.findall(".//PARAMETER"):
            param_type = param_elem.get("DATATYPE", "unknown")
            param_name = param_elem.get("NAME", "")
            parameters.append((param_type, param_name))

        # Parse local variables
        local_variables = []
        for var_elem in func_elem.findall(".//LOCAL_VAR"):
            var_type = var_elem.get("DATATYPE", "unknown")
            var_name = var_elem.get("NAME", "")
            var_offset = int(var_elem.get("STACK_OFFSET", "0"), 16)
            local_variables.append((var_type, var_name, var_offset))

        # Parse decompiled code
        decomp_elem = func_elem.find(".//C_CODE")
        decompiled_code = decomp_elem.text if decomp_elem is not None else ""

        # Parse assembly code
        asm_elem = func_elem.find(".//ASSEMBLER")
        assembly_code = asm_elem.text if asm_elem is not None else ""

        # Parse cross-references
        xrefs_to = [int(xr.get("FROM_ADDRESS", "0"), 16) for xr in func_elem.findall('.//XREF[@TYPE="CALL"]')]
        xrefs_from = [int(xr.get("TO_ADDRESS", "0"), 16) for xr in func_elem.findall('.//XREF[@DIRECTION="FROM"]')]

        # Parse comments
        comments = {}
        for comm_elem in func_elem.findall(".//COMMENT"):
            offset = int(comm_elem.get("ADDRESS", "0"), 16) - address
            text = comm_elem.text or ""
            comments[offset] = text

        # Parse function attributes
        is_thunk = func_elem.get("IS_THUNK", "false").lower() == "true"
        is_external = func_elem.get("IS_EXTERNAL", "false").lower() == "true"
        calling_convention = func_elem.get("CALLING_CONVENTION", "__cdecl")

        return GhidraFunction(
            name=name,
            address=address,
            size=size,
            signature=signature,
            return_type=return_type,
            parameters=parameters,
            local_variables=local_variables,
            decompiled_code=decompiled_code,
            assembly_code=assembly_code,
            xrefs_to=xrefs_to,
            xrefs_from=xrefs_from,
            comments=comments,
            is_thunk=is_thunk,
            is_external=is_external,
            calling_convention=calling_convention,
        )

    def _parse_xml_datatype(self, dt_elem) -> GhidraDataType:
        """Parse a data type element from XML."""
        name = dt_elem.get("NAME", "unknown")
        size = int(dt_elem.get("SIZE", "0"), 10)
        category = dt_elem.get("CATEGORY", "unknown")

        members = []
        for member_elem in dt_elem.findall(".//MEMBER"):
            members.append(
                {
                    "name": member_elem.get("NAME", ""),
                    "type": member_elem.get("DATATYPE", ""),
                    "offset": int(member_elem.get("OFFSET", "0"), 10),
                    "size": int(member_elem.get("SIZE", "0"), 10),
                },
            )

        base_type = dt_elem.get("BASE_TYPE")
        alignment = int(dt_elem.get("ALIGNMENT", "1"), 10)

        return GhidraDataType(name=name, size=size, category=category, members=members, base_type=base_type, alignment=alignment)

    def parse_json_output(self, json_content: str) -> GhidraAnalysisResult:
        """Parse Ghidra JSON output format."""
        try:
            data = json.loads(json_content)

            # Extract basic information
            program_info = data.get("program", {})
            binary_path = program_info.get("name", "")
            architecture = program_info.get("processor", "unknown")
            compiler = program_info.get("compiler", "unknown")
            image_base = int(program_info.get("imageBase", "0"), 16)
            entry_point = int(program_info.get("entryPoint", "0"), 16)

            # Parse functions from JSON
            functions = {}
            for func_data in data.get("functions", []):
                func = self._parse_json_function(func_data)
                functions[func.address] = func

            # Parse data types from JSON
            data_types = {}
            for dt_data in data.get("dataTypes", []):
                dt = self._parse_json_datatype(dt_data)
                data_types[dt.name] = dt

            # Parse strings
            strings = [(int(s["address"], 16), s["value"]) for s in data.get("strings", [])]

            # Parse imports
            imports = [(i["library"], i["function"], int(i["address"], 16)) for i in data.get("imports", [])]

            # Parse exports
            exports = [(e["name"], int(e["address"], 16)) for e in data.get("exports", [])]

            # Parse sections
            sections = data.get("sections", [])

            # Parse vtables
            vtables = {}
            for vt in data.get("vtables", []):
                addr = int(vt["address"], 16)
                funcs = [int(f, 16) for f in vt.get("functions", [])]
                vtables[addr] = funcs

            # Parse exception handlers
            exception_handlers = data.get("exceptionHandlers", [])

            return GhidraAnalysisResult(
                binary_path=binary_path,
                architecture=architecture,
                compiler=compiler,
                functions=functions,
                data_types=data_types,
                strings=strings,
                imports=imports,
                exports=exports,
                sections=sections,
                entry_point=entry_point,
                image_base=image_base,
                vtables=vtables,
                exception_handlers=exception_handlers,
                metadata=data.get("metadata", {}),
            )
        except Exception as e:
            raise ValueError(f"Failed to parse JSON output: {e}") from e

    def _parse_json_function(self, func_data: dict) -> GhidraFunction:
        """Parse function data from JSON."""
        return GhidraFunction(
            name=func_data.get("name", "unknown"),
            address=int(func_data.get("address", "0"), 16),
            size=int(func_data.get("size", "0"), 10),
            signature=func_data.get("signature", ""),
            return_type=func_data.get("returnType", "void"),
            parameters=[(p["type"], p["name"]) for p in func_data.get("parameters", [])],
            local_variables=[(v["type"], v["name"], v["offset"]) for v in func_data.get("localVars", [])],
            decompiled_code=func_data.get("decompiledCode", ""),
            assembly_code=func_data.get("assembly", ""),
            xrefs_to=[int(x, 16) for x in func_data.get("xrefsTo", [])],
            xrefs_from=[int(x, 16) for x in func_data.get("xrefsFrom", [])],
            comments=func_data.get("comments", {}),
            is_thunk=func_data.get("isThunk", False),
            is_external=func_data.get("isExternal", False),
            calling_convention=func_data.get("callingConvention", "__cdecl"),
        )

    def _parse_json_datatype(self, dt_data: dict) -> GhidraDataType:
        """Parse data type from JSON."""
        return GhidraDataType(
            name=dt_data.get("name", "unknown"),
            size=dt_data.get("size", 0),
            category=dt_data.get("category", "unknown"),
            members=dt_data.get("members", []),
            base_type=dt_data.get("baseType"),
            alignment=dt_data.get("alignment", 1),
        )

    def parse_text_output(self, text_content: str) -> GhidraAnalysisResult:
        """Parse Ghidra text-based output (from scripts)."""
        functions = {}
        strings = []
        imports = []
        exports = []

        # Parse function listings
        func_pattern = r"Function:\s+([\w_]+)\s+at\s+0x([0-9a-fA-F]+)"
        for match in re.finditer(func_pattern, text_content):
            name = match.group(1)
            address = int(match.group(2), 16)

            # Extract function details from surrounding context
            func_context = self._extract_function_context(text_content, match.start())
            func = self._parse_text_function(name, address, func_context)
            functions[address] = func

        # Parse string references
        str_pattern = r'String\s+at\s+0x([0-9a-fA-F]+):\s+"([^"]+)"'
        for match in re.finditer(str_pattern, text_content):
            address = int(match.group(1), 16)
            value = match.group(2)
            strings.append((address, value))

        # Parse imports
        import_pattern = r"Import:\s+([\w\.]+)!([\w_]+)\s+at\s+0x([0-9a-fA-F]+)"
        for match in re.finditer(import_pattern, text_content):
            library = match.group(1)
            function = match.group(2)
            address = int(match.group(3), 16)
            imports.append((library, function, address))

        # Parse exports
        export_pattern = r"Export:\s+([\w_]+)\s+at\s+0x([0-9a-fA-F]+)"
        for match in re.finditer(export_pattern, text_content):
            name = match.group(1)
            address = int(match.group(2), 16)
            exports.append((name, address))

        # Extract basic program info
        arch_match = re.search(r"Processor:\s+(\S+)", text_content)
        architecture = arch_match.group(1) if arch_match else "unknown"

        compiler_match = re.search(r"Compiler:\s+(\S+)", text_content)
        compiler = compiler_match.group(1) if compiler_match else "unknown"

        entry_match = re.search(r"Entry\s+Point:\s+0x([0-9a-fA-F]+)", text_content)
        entry_point = int(entry_match.group(1), 16) if entry_match else 0

        base_match = re.search(r"Image\s+Base:\s+0x([0-9a-fA-F]+)", text_content)
        image_base = int(base_match.group(1), 16) if base_match else 0

        return GhidraAnalysisResult(
            binary_path="",
            architecture=architecture,
            compiler=compiler,
            functions=functions,
            data_types={},
            strings=strings,
            imports=imports,
            exports=exports,
            sections=[],
            entry_point=entry_point,
            image_base=image_base,
            vtables={},
            exception_handlers=[],
        )

    def _extract_function_context(self, text: str, position: int, context_lines: int = 50) -> str:
        """Extract context around a function definition."""
        lines = text.split("\n")
        current_line = text[:position].count("\n")

        start = max(0, current_line - context_lines // 2)
        end = min(len(lines), current_line + context_lines // 2)

        return "\n".join(lines[start:end])

    def _parse_text_function(self, name: str, address: int, context: str) -> GhidraFunction:
        """Parse function details from text context."""
        # Extract signature if available
        sig_pattern = rf"{re.escape(name)}\s*\(([^)]*)\)\s*->\s*(\S+)"
        sig_match = re.search(sig_pattern, context)

        if sig_match:
            params_str = sig_match.group(1)
            return_type = sig_match.group(2)

            # Parse parameters
            parameters = []
            if params_str:
                for param in params_str.split(","):
                    parts = param.strip().split()
                    if len(parts) >= 2:
                        param_type = " ".join(parts[:-1])
                        param_name = parts[-1]
                        parameters.append((param_type, param_name))

            signature = f"{return_type} {name}({params_str})"
        else:
            signature = f"{name}()"
            return_type = "void"
            parameters = []

        # Extract decompiled code if present
        decomp_start = context.find("{", context.find(name))
        decomp_code = ""
        if decomp_start != -1:
            brace_count = 0
            idx = decomp_start
            while idx < len(context):
                if context[idx] == "{":
                    brace_count += 1
                elif context[idx] == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        decomp_code = context[decomp_start : idx + 1]
                        break
                idx += 1

        # Extract cross-references
        xrefs_to = []
        xref_pattern = r"Called\s+from:\s+0x([0-9a-fA-F]+)"
        for match in re.finditer(xref_pattern, context):
            xrefs_to.append(int(match.group(1), 16))

        xrefs_from = []
        call_pattern = r"Calls:\s+0x([0-9a-fA-F]+)"
        for match in re.finditer(call_pattern, context):
            xrefs_from.append(int(match.group(1), 16))

        # Extract size if available
        size_match = re.search(r"Size:\s+(\d+)\s+bytes", context)
        size = int(size_match.group(1)) if size_match else 0

        return GhidraFunction(
            name=name,
            address=address,
            size=size,
            signature=signature,
            return_type=return_type,
            parameters=parameters,
            local_variables=[],
            decompiled_code=decomp_code,
            assembly_code="",
            xrefs_to=xrefs_to,
            xrefs_from=xrefs_from,
            comments={},
        )


def _run_ghidra_thread(main_app, command, temp_dir) -> None:
    """Run the Ghidra command in a background thread and clean up afterward."""
    try:
        main_app.update_output.emit(f"[Ghidra] Running command: {' '.join(command)}")
        # Use secure subprocess wrapper with validation
        # This prevents command injection while maintaining functionality
        process = secure_popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore", shell=False, cwd=temp_dir,
        )

        stdout, stderr = process.communicate()

        if process.returncode == 0:
            main_app.update_output.emit("[Ghidra] Analysis completed successfully.")

            # Parse Ghidra output
            parser = GhidraOutputParser()
            analysis_result = None

            # Check for output files in the temp directory
            output_files = list(Path(temp_dir).glob("*.xml")) + list(Path(temp_dir).glob("*.json"))

            if output_files:
                # Parse structured output files
                for output_file in output_files:
                    try:
                        with open(output_file, encoding="utf-8") as f:
                            content = f.read()

                        if output_file.suffix == ".xml":
                            analysis_result = parser.parse_xml_output(content)
                            main_app.update_output.emit(f"[Ghidra] Parsed XML output: {len(analysis_result.functions)} functions found")
                        elif output_file.suffix == ".json":
                            analysis_result = parser.parse_json_output(content)
                            main_app.update_output.emit(f"[Ghidra] Parsed JSON output: {len(analysis_result.functions)} functions found")
                        break
                    except Exception as e:
                        main_app.update_output.emit(f"[Ghidra] Warning: Failed to parse {output_file.name}: {e}")

            # Fallback to parsing stdout if no structured files found
            if not analysis_result and stdout:
                try:
                    # Try JSON first
                    if stdout.strip().startswith("{"):
                        analysis_result = parser.parse_json_output(stdout)
                        main_app.update_output.emit(f"[Ghidra] Parsed JSON from stdout: {len(analysis_result.functions)} functions")
                    # Try XML
                    elif stdout.strip().startswith("<?xml") or stdout.strip().startswith("<"):
                        analysis_result = parser.parse_xml_output(stdout)
                        main_app.update_output.emit(f"[Ghidra] Parsed XML from stdout: {len(analysis_result.functions)} functions")
                    # Fallback to text parsing
                    else:
                        analysis_result = parser.parse_text_output(stdout)
                        main_app.update_output.emit(f"[Ghidra] Parsed text output: {len(analysis_result.functions)} functions")
                except Exception as e:
                    main_app.update_output.emit(f"[Ghidra] Warning: Failed to parse stdout: {e}")

            # Store the analysis result
            if analysis_result:
                if hasattr(main_app, "ghidra_analysis_result"):
                    main_app.ghidra_analysis_result = analysis_result

                # Emit detailed analysis summary
                main_app.update_output.emit("[Ghidra] Analysis Summary:")
                main_app.update_output.emit(f"  - Architecture: {analysis_result.architecture}")
                main_app.update_output.emit(f"  - Compiler: {analysis_result.compiler}")
                main_app.update_output.emit(f"  - Entry Point: 0x{analysis_result.entry_point:08x}")
                main_app.update_output.emit(f"  - Functions: {len(analysis_result.functions)}")
                main_app.update_output.emit(f"  - Data Types: {len(analysis_result.data_types)}")
                main_app.update_output.emit(f"  - Strings: {len(analysis_result.strings)}")
                main_app.update_output.emit(f"  - Imports: {len(analysis_result.imports)}")
                main_app.update_output.emit(f"  - Exports: {len(analysis_result.exports)}")

                # Process critical functions for licensing analysis
                licensing_functions = _identify_licensing_functions(analysis_result)
                if licensing_functions:
                    main_app.update_output.emit(f"[Ghidra] Found {len(licensing_functions)} potential licensing functions")
                    for func_addr, func in licensing_functions:
                        main_app.update_output.emit(f"  - {func.name} at 0x{func_addr:08x}")
        else:
            main_app.update_output.emit(f"[Ghidra] Analysis failed with return code {process.returncode}.")
            if stdout:
                main_app.update_output.emit(f"[Ghidra STDOUT]:\n{stdout}")
            if stderr:
                main_app.update_output.emit(f"[Ghidra STDERR]:\n{stderr}")

    except FileNotFoundError:
        main_app.update_output.emit("[Ghidra] Error: Command not found. Ensure Ghidra is in your system's PATH.")
    except Exception as e:
        main_app.update_output.emit(f"[Ghidra] An unexpected error occurred: {e}")
    finally:
        try:
            shutil.rmtree(temp_dir)
            main_app.update_output.emit(f"[Ghidra] Cleaned up temporary project directory: {temp_dir}")
        except Exception as e:
            main_app.update_output.emit(f"[Ghidra] Warning: Failed to clean up temporary directory {temp_dir}: {e}")

        if hasattr(main_app, "analysis_completed"):
            main_app.analysis_completed.emit("Ghidra Analysis")


class GhidraScriptManager:
    """Manages Ghidra script execution and chaining."""

    # Production-ready script configurations for licensing analysis
    LICENSING_SCRIPTS = [
        {
            "name": "ExtractCryptoRoutines.py",
            "description": "Extract cryptographic routines used in licensing",
            "params": {"detect_rsa": True, "detect_aes": True, "detect_hashing": True},
            "output_format": "json",
        },
        {
            "name": "FindSerialValidation.py",
            "description": "Locate serial number validation routines",
            "params": {"pattern_depth": 5, "trace_calls": True},
            "output_format": "xml",
        },
        {
            "name": "IdentifyProtectionSchemes.py",
            "description": "Identify commercial protection systems",
            "params": {"check_vmprotect": True, "check_themida": True, "check_asprotect": True},
            "output_format": "json",
        },
        {
            "name": "ExtractStringReferences.py",
            "description": "Extract string references for licensing keywords",
            "params": {"keywords": ["license", "serial", "trial", "expire", "activation"]},
            "output_format": "text",
        },
        {
            "name": "AnalyzeAntiDebug.py",
            "description": "Analyze anti-debugging techniques",
            "params": {"detect_api": True, "detect_timing": True, "detect_exceptions": True},
            "output_format": "json",
        },
        {
            "name": "DumpImportReconstruction.py",
            "description": "Reconstruct import table for packed binaries",
            "params": {"resolve_iat": True, "fix_thunks": True},
            "output_format": "xml",
        },
    ]

    def __init__(self, ghidra_install_dir: str) -> None:
        """Initialize the GhidraAnalyzer with the Ghidra installation directory."""
        self.ghidra_install_dir = Path(ghidra_install_dir)
        self.scripts_dir = self.ghidra_install_dir / "Ghidra" / "Features" / "Base" / "ghidra_scripts"
        self.user_scripts_dir = Path.home() / "ghidra_scripts"
        self.custom_scripts = self._load_custom_scripts()

    def _load_custom_scripts(self) -> list[dict[str, Any]]:
        """Load custom Intellicrack Ghidra scripts."""
        custom_scripts = []
        script_dirs = [self.scripts_dir, self.user_scripts_dir]

        for script_dir in script_dirs:
            if script_dir.exists():
                for script_file in script_dir.glob("*.py"):
                    if self._is_intellicrack_script(script_file):
                        script_info = self._parse_script_metadata(script_file)
                        custom_scripts.append(script_info)

                for script_file in script_dir.glob("*.java"):
                    if self._is_intellicrack_script(script_file):
                        script_info = self._parse_script_metadata(script_file)
                        custom_scripts.append(script_info)

        return custom_scripts

    def _is_intellicrack_script(self, script_file: Path) -> bool:
        """Check if script is an Intellicrack-specific analysis script."""
        intellicrack_markers = ["@intellicrack", "INTELLICRACK", "License Analysis", "Protection Detection"]
        try:
            content = script_file.read_text(encoding="utf-8", errors="ignore")
            return any(marker in content for marker in intellicrack_markers)
        except (OSError, UnicodeDecodeError):
            return False

    def _parse_script_metadata(self, script_file: Path) -> dict[str, Any]:
        """Parse script metadata from comments."""
        metadata = {"name": script_file.name, "path": str(script_file), "params": {}, "output_format": "text", "description": ""}

        try:
            content = script_file.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")

            for line in lines[:50]:  # Check first 50 lines for metadata
                if "@description" in line:
                    metadata["description"] = line.split("@description")[-1].strip()
                elif "@param" in line:
                    param_match = re.match(r".*@param\s+(\w+)\s+(.+)", line)
                    if param_match:
                        metadata["params"][param_match.group(1)] = param_match.group(2)
                elif "@output" in line:
                    metadata["output_format"] = line.split("@output")[-1].strip()
        except (IndexError, ValueError):
            pass

        return metadata

    def get_script_for_analysis(self, analysis_type: str) -> list[dict[str, Any]]:
        """Select appropriate script based on analysis type."""
        analysis_map = {
            "licensing": ["FindSerialValidation.py", "ExtractCryptoRoutines.py"],
            "protection": ["IdentifyProtectionSchemes.py", "AnalyzeAntiDebug.py"],
            "unpacking": ["DumpImportReconstruction.py"],
            "strings": ["ExtractStringReferences.py"],
            "comprehensive": ["FindSerialValidation.py", "ExtractCryptoRoutines.py", "IdentifyProtectionSchemes.py"],
        }

        scripts_to_use = analysis_map.get(analysis_type, ["FindSerialValidation.py"])
        selected_scripts = []

        for script_name in scripts_to_use:
            for script in self.LICENSING_SCRIPTS:
                if script["name"] == script_name:
                    selected_scripts.append(script)
                    break
            else:
                # Check custom scripts
                for custom_script in self.custom_scripts:
                    if custom_script["name"] == script_name:
                        selected_scripts.append(custom_script)
                        break

        return selected_scripts if selected_scripts else [self.LICENSING_SCRIPTS[0]]

    def build_script_chain(self, scripts: list[dict[str, Any]]) -> list[str]:
        """Build command-line arguments for script chaining."""
        script_args = []

        for script in scripts:
            script_args.extend(["-postScript", script["name"]])

            # Add script parameters
            for param_name, param_value in script.get("params", {}).items():
                if isinstance(param_value, bool):
                    script_args.extend(["-scriptarg", f"{param_name}={str(param_value).lower()}"])
                elif isinstance(param_value, list):
                    script_args.extend(["-scriptarg", f"{param_name}={','.join(map(str, param_value))}"])
                else:
                    script_args.extend(["-scriptarg", f"{param_name}={param_value}"])

        return script_args


def run_advanced_ghidra_analysis(main_app, analysis_type: str = "comprehensive", scripts: list[str] | None = None) -> None:
    """Launch a Ghidra headless analysis session with intelligent script selection."""
    if not main_app.current_binary:
        main_app.update_output.emit("[Ghidra] Error: No binary loaded.")
        return

    binary_path = main_app.current_binary
    config = get_config()
    ghidra_install_dir = config.get_tool_path("ghidra")

    if not ghidra_install_dir or not os.path.isdir(ghidra_install_dir):
        main_app.update_output.emit(f"[Ghidra] Error: Ghidra installation directory not configured or invalid: {ghidra_install_dir}")
        return

    headless_script_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    headless_path = os.path.join(ghidra_install_dir, "support", headless_script_name)

    if not os.path.exists(headless_path):
        main_app.update_output.emit(f"[Ghidra] Error: Headless analyzer not found at {headless_path}")
        return

    temp_dir = tempfile.mkdtemp(prefix="intellicrack_ghidra_")
    project_name = "temp_project"

    # Initialize script manager for intelligent script selection
    script_manager = GhidraScriptManager(ghidra_install_dir)

    # Select scripts based on analysis type or use provided scripts
    if scripts:
        # Use explicitly provided scripts
        selected_scripts = []
        for script_name in scripts:
            for script in script_manager.LICENSING_SCRIPTS + script_manager.custom_scripts:
                if script["name"] == script_name:
                    selected_scripts.append(script)
                    break
    else:
        # Auto-select based on analysis type
        selected_scripts = script_manager.get_script_for_analysis(analysis_type)

    main_app.update_output.emit(f"[Ghidra] Selected {len(selected_scripts)} scripts for {analysis_type} analysis")
    for script in selected_scripts:
        main_app.update_output.emit(f"  - {script['name']}: {script.get('description', 'No description')}")

    # Build command with script chaining
    command = [
        headless_path,
        temp_dir,
        project_name,
        "-import",
        binary_path,
        "-overwrite",  # Overwrite existing project
        "-recursive",  # Process recursively
        "-readOnly",  # Read-only mode for safety
    ]

    # Add script chain
    script_args = script_manager.build_script_chain(selected_scripts)
    command.extend(script_args)

    # Add output formatting
    command.extend(
        [
            "-scriptPath",
            str(script_manager.scripts_dir),
            "-scriptPath",
            str(script_manager.user_scripts_dir),
            "-log",
            os.path.join(temp_dir, "ghidra_analysis.log"),
            "-scriptlog",
            os.path.join(temp_dir, "script_output.txt"),
            "-max-cpu",
            str(os.cpu_count() or 4),  # Use all available CPUs
            "-deleteProject",  # Clean up after analysis
        ],
    )

    # Store selected scripts info for result processing
    if hasattr(main_app, "ghidra_scripts_used"):
        main_app.ghidra_scripts_used = selected_scripts

    thread = Thread(target=_run_ghidra_thread, args=(main_app, command, temp_dir), daemon=True)
    thread.start()
    main_app.update_output.emit("[Ghidra] Headless analysis task submitted with production script chain.")


def _identify_licensing_functions(result: GhidraAnalysisResult) -> list[tuple[int, GhidraFunction]]:
    """Identify functions potentially related to licensing/protection."""
    licensing_keywords = [
        "license",
        "serial",
        "key",
        "activation",
        "registration",
        "validate",
        "check",
        "verify",
        "authenticate",
        "trial",
        "expire",
        "hwid",
        "machine",
        "fingerprint",
        "signature",
        "rsa",
        "aes",
        "decrypt",
        "encrypt",
        "hash",
        "protect",
        "security",
        "drm",
        "crack",
        "patch",
        "bypass",
    ]

    licensing_functions = []

    for addr, func in result.functions.items():
        # Check function name
        func_name_lower = func.name.lower()
        if any(keyword in func_name_lower for keyword in licensing_keywords):
            licensing_functions.append((addr, func))
            continue

        # Check for cryptographic operations in decompiled code
        if func.decompiled_code:
            code_lower = func.decompiled_code.lower()
            if any(keyword in code_lower for keyword in licensing_keywords):
                licensing_functions.append((addr, func))
                continue

        # Check for string references related to licensing
        for str_addr, string in result.strings:
            if str_addr in func.xrefs_from:
                string_lower = string.lower()
                if any(keyword in string_lower for keyword in licensing_keywords):
                    licensing_functions.append((addr, func))
                    break

        # Check imports that might be used for licensing
        licensing_imports = ["CryptGenRandom", "CryptHashData", "RegOpenKeyEx", "GetVolumeInformation", "GetComputerName", "GetUserName"]
        for _lib, imp_func, imp_addr in result.imports:
            if imp_func in licensing_imports and imp_addr in func.xrefs_from:
                licensing_functions.append((addr, func))
                break

    return licensing_functions


def export_ghidra_results(result: GhidraAnalysisResult, output_path: str, format: str = "json"):
    """Export Ghidra analysis results in various formats."""
    output_path = Path(output_path)

    if format == "json":
        export_data = {
            "binary_path": result.binary_path,
            "architecture": result.architecture,
            "compiler": result.compiler,
            "entry_point": hex(result.entry_point),
            "image_base": hex(result.image_base),
            "functions": [
                {
                    "address": hex(addr),
                    "name": func.name,
                    "size": func.size,
                    "signature": func.signature,
                    "return_type": func.return_type,
                    "parameters": func.parameters,
                    "decompiled_code": func.decompiled_code,
                    "xrefs_to": [hex(x) for x in func.xrefs_to],
                    "xrefs_from": [hex(x) for x in func.xrefs_from],
                }
                for addr, func in result.functions.items()
            ],
            "strings": [{"address": hex(addr), "value": val} for addr, val in result.strings],
            "imports": [{"library": lib, "function": func, "address": hex(addr)} for lib, func, addr in result.imports],
            "exports": [{"name": name, "address": hex(addr)} for name, addr in result.exports],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)

    elif format == "xml":
        root = ET.Element("GhidraAnalysis")
        program = ET.SubElement(root, "Program")
        program.set("path", result.binary_path)
        program.set("architecture", result.architecture)
        program.set("compiler", result.compiler)
        program.set("entryPoint", hex(result.entry_point))
        program.set("imageBase", hex(result.image_base))

        functions_elem = ET.SubElement(root, "Functions")
        for addr, func in result.functions.items():
            func_elem = ET.SubElement(functions_elem, "Function")
            func_elem.set("address", hex(addr))
            func_elem.set("name", func.name)
            func_elem.set("size", str(func.size))
            func_elem.set("signature", func.signature)

            if func.decompiled_code:
                decomp_elem = ET.SubElement(func_elem, "DecompiledCode")
                decomp_elem.text = func.decompiled_code

        tree = ET.ElementTree(root)
        tree.write(output_path, encoding="utf-8", xml_declaration=True)

    return output_path
