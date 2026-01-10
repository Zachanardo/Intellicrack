"""radare2 bridge for static and dynamic analysis.

This module provides integration with radare2 for disassembly,
analysis, and debugging capabilities using r2pipe.
"""

import asyncio
import json
import re
from pathlib import Path
from typing import Literal

import r2pipe

from ..core.logging import get_logger
from ..core.types import (
    BinaryInfo,
    CrossReference,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    ParameterInfo,
    SectionInfo,
    StringInfo,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
    VariableInfo,
)

XRefType = Literal["call", "jump", "data", "read", "write"]
StringEncoding = Literal["ascii", "utf-8", "utf-16le", "utf-16be"]
from .base import (
    BridgeCapabilities,
    BridgeState,
    DisassemblyLine,
    StaticAnalysisBridge,
)

_logger = get_logger("bridges.radare2")


class Radare2Bridge(StaticAnalysisBridge):
    """Bridge for radare2 reverse engineering framework.

    Provides static analysis, disassembly, and debugging capabilities
    using the r2pipe interface.

    Attributes:
        _r2: The r2pipe instance.
        _binary_path: Path to the loaded binary.
        _analyzed: Whether analysis has been run.
    """

    def __init__(self) -> None:
        """Initialize the radare2 bridge."""
        super().__init__()
        self._r2: r2pipe.open_sync | None = None
        self._binary_path: Path | None = None
        self._analyzed: bool = False
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_dynamic_analysis=True,
            supports_decompilation=True,
            supports_debugging=True,
            supports_patching=True,
            supports_scripting=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64", "mips", "ppc"],
            supported_formats=["pe", "elf", "macho", "raw"],
        )

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            ToolName.RADARE2
        """
        return ToolName.RADARE2

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition with all available functions.
        """
        return ToolDefinition(
            tool_name=ToolName.RADARE2,
            description="radare2 reverse engineering - disassembly, analysis, patching",
            functions=[
                ToolFunction(
                    name="r2.load_binary",
                    description="Load a binary file into radare2",
                    parameters=[
                        ToolParameter(
                            name="path",
                            type="string",
                            description="Path to the binary file",
                            required=True,
                        ),
                    ],
                    returns="BinaryInfo object with file details",
                ),
                ToolFunction(
                    name="r2.analyze",
                    description="Run full analysis on the loaded binary",
                    parameters=[
                        ToolParameter(
                            name="level",
                            type="string",
                            description="Analysis level: quick, normal, deep",
                            required=False,
                            default="normal",
                            enum=["quick", "normal", "deep"],
                        ),
                    ],
                    returns="Analysis completion status",
                ),
                ToolFunction(
                    name="r2.get_functions",
                    description="Get list of all functions",
                    parameters=[
                        ToolParameter(
                            name="filter_pattern",
                            type="string",
                            description="Optional regex to filter function names",
                            required=False,
                        ),
                    ],
                    returns="List of FunctionInfo objects",
                ),
                ToolFunction(
                    name="r2.decompile",
                    description="Decompile a function to pseudocode",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Function address to decompile",
                            required=True,
                        ),
                    ],
                    returns="Decompiled C-like pseudocode",
                ),
                ToolFunction(
                    name="r2.disassemble",
                    description="Disassemble instructions at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Start address",
                            required=True,
                        ),
                        ToolParameter(
                            name="count",
                            type="integer",
                            description="Number of instructions",
                            required=False,
                            default=20,
                        ),
                    ],
                    returns="Disassembly listing",
                ),
                ToolFunction(
                    name="r2.get_xrefs_to",
                    description="Get cross-references to an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Target address",
                            required=True,
                        ),
                    ],
                    returns="List of cross-references",
                ),
                ToolFunction(
                    name="r2.get_xrefs_from",
                    description="Get cross-references from an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Source address",
                            required=True,
                        ),
                    ],
                    returns="List of cross-references",
                ),
                ToolFunction(
                    name="r2.search_strings",
                    description="Search for strings in the binary",
                    parameters=[
                        ToolParameter(
                            name="pattern",
                            type="string",
                            description="String or regex pattern",
                            required=True,
                        ),
                    ],
                    returns="List of matching strings",
                ),
                ToolFunction(
                    name="r2.search_bytes",
                    description="Search for byte pattern",
                    parameters=[
                        ToolParameter(
                            name="hex_pattern",
                            type="string",
                            description="Hex pattern (e.g., '48 8B ?? ??')",
                            required=True,
                        ),
                    ],
                    returns="List of addresses",
                ),
                ToolFunction(
                    name="r2.get_imports",
                    description="Get imported functions",
                    parameters=[],
                    returns="List of imports",
                ),
                ToolFunction(
                    name="r2.get_exports",
                    description="Get exported functions",
                    parameters=[],
                    returns="List of exports",
                ),
                ToolFunction(
                    name="r2.get_sections",
                    description="Get binary sections",
                    parameters=[],
                    returns="List of sections",
                ),
                ToolFunction(
                    name="r2.rename_function",
                    description="Rename a function",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Function address",
                            required=True,
                        ),
                        ToolParameter(
                            name="new_name",
                            type="string",
                            description="New function name",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="r2.add_comment",
                    description="Add a comment at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address for comment",
                            required=True,
                        ),
                        ToolParameter(
                            name="comment",
                            type="string",
                            description="Comment text",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="r2.write_bytes",
                    description="Write bytes at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address to write at",
                            required=True,
                        ),
                        ToolParameter(
                            name="hex_data",
                            type="string",
                            description="Hex bytes to write",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="r2.assemble",
                    description="Assemble instruction at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Target address",
                            required=True,
                        ),
                        ToolParameter(
                            name="instruction",
                            type="string",
                            description="Assembly instruction",
                            required=True,
                        ),
                    ],
                    returns="Assembled bytes",
                ),
                ToolFunction(
                    name="r2.execute",
                    description="Execute raw radare2 command",
                    parameters=[
                        ToolParameter(
                            name="command",
                            type="string",
                            description="radare2 command to execute",
                            required=True,
                        ),
                    ],
                    returns="Command output",
                ),
            ],
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the radare2 bridge.

        Args:
            tool_path: Optional path to radare2 installation.
        """
        self._state = BridgeState(connected=True, tool_running=True)
        _logger.info("radare2 bridge initialized")

    async def shutdown(self) -> None:
        """Shutdown radare2 and cleanup resources."""
        if self._r2 is not None:
            try:
                await asyncio.to_thread(self._r2.quit)
            except Exception as e:
                _logger.warning("Error closing r2: %s", e)
            self._r2 = None

        self._binary_path = None
        self._analyzed = False
        await super().shutdown()
        _logger.info("radare2 bridge shutdown")

    async def is_available(self) -> bool:
        """Check if radare2 is available.

        Returns:
            True if radare2 can be used.
        """
        try:
            r2 = await asyncio.to_thread(r2pipe.open, "-")
            version = await asyncio.to_thread(r2.cmd, "?V")
            await asyncio.to_thread(r2.quit)
            return bool(version)
        except Exception:
            return False

    async def load_binary(self, path: Path) -> BinaryInfo:
        """Load a binary file into radare2.

        Args:
            path: Path to the binary file.

        Returns:
            BinaryInfo with file details.

        Raises:
            ToolError: If load fails.
        """
        if not path.exists():
            raise ToolError(f"File not found: {path}")

        try:
            if self._r2 is not None:
                await asyncio.to_thread(self._r2.quit)

            self._r2 = await asyncio.to_thread(r2pipe.open, str(path), ["-2"])
            self._binary_path = path.resolve()
            self._analyzed = False

            info = await self._cmd_json("ij")

            file_type = info.get("bin", {}).get("class", "unknown")
            arch = info.get("bin", {}).get("arch", "unknown")
            bits = info.get("bin", {}).get("bits", 32)
            entry = info.get("bin", {}).get("baddr", 0) + info.get("bin", {}).get("entry", 0)

            await asyncio.to_thread(self._r2.cmd, "e io.cache=true")

            hashes = await self._cmd_json("itj")
            md5 = ""
            sha256 = ""
            for h in hashes:
                if h.get("type") == "md5":
                    md5 = h.get("hash", "")
                elif h.get("type") == "sha256":
                    sha256 = h.get("hash", "")

            sections = await self._get_sections_internal()
            imports = await self._get_imports_internal()
            exports = await self._get_exports_internal()

            self._state = BridgeState(
                connected=True,
                tool_running=True,
                binary_loaded=True,
                target_path=self._binary_path,
            )

            _logger.info("Loaded binary: %s (%s, %s %d-bit)", path.name, file_type, arch, bits)

            return BinaryInfo(
                path=self._binary_path,
                name=path.name,
                size=path.stat().st_size,
                md5=md5,
                sha256=sha256,
                file_type=file_type.lower(),
                architecture=arch,
                is_64bit=bits == 64,
                entry_point=entry,
                sections=sections,
                imports=imports,
                exports=exports,
            )

        except Exception as e:
            _logger.exception("Failed to load binary")
            raise ToolError(f"Failed to load binary: {e}") from e

    async def analyze(self, level: str = "normal") -> None:
        """Run analysis on the loaded binary.

        Args:
            level: Analysis level (quick, normal, deep).

        Raises:
            ToolError: If analysis fails.
        """
        if self._r2 is None:
            raise ToolError("No binary loaded")

        cmd_map = {
            "quick": "aa",
            "normal": "aaa",
            "deep": "aaaa",
        }
        cmd = cmd_map.get(level, "aaa")

        _logger.info("Running %s analysis...", level)
        await asyncio.to_thread(self._r2.cmd, cmd)
        self._analyzed = True
        _logger.info("Analysis complete")

    async def get_functions(
        self,
        filter_pattern: str | None = None,
    ) -> list[FunctionInfo]:
        """Get all analyzed functions.

        Args:
            filter_pattern: Optional regex to filter names.

        Returns:
            List of function information.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            raise ToolError("No binary loaded")

        funcs = await self._cmd_json("aflj")

        result: list[FunctionInfo] = []
        pattern = re.compile(filter_pattern) if filter_pattern else None

        for f in funcs:
            name = f.get("name", "")
            if pattern and not pattern.search(name):
                continue

            result.append(
                FunctionInfo(
                    name=name,
                    address=f.get("offset", 0),
                    size=f.get("size", 0),
                    calling_convention=f.get("cc", "unknown"),
                    return_type="unknown",
                    parameters=[],
                    local_variables=[],
                    decompiled_code=None,
                    disassembly=None,
                )
            )

        return result

    async def get_function(self, address: int) -> FunctionInfo | None:
        """Get function at a specific address.

        Args:
            address: Function address.

        Returns:
            Function info or None if not found.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            raise ToolError("No binary loaded")

        await asyncio.to_thread(self._r2.cmd, f"s {address}")
        func_info = await self._cmd_json("afij")

        if not func_info:
            return None

        f = func_info[0]

        vars_data = await self._cmd_json("afvj")
        params: list[ParameterInfo] = []
        locals_list: list[VariableInfo] = []

        for var in vars_data.get("sp", []) + vars_data.get("bp", []) + vars_data.get("reg", []):
            var_name = var.get("name", "")
            var_type = var.get("type", "unknown")
            var_offset = var.get("ref", {}).get("offset", 0)

            if var.get("kind") == "arg":
                params.append(
                    ParameterInfo(
                        name=var_name,
                        type=var_type,
                        size=0,
                        location="stack",
                    )
                )
            else:
                locals_list.append(
                    VariableInfo(
                        name=var_name,
                        type=var_type,
                        offset=var_offset,
                        size=0,
                    )
                )

        return FunctionInfo(
            name=f.get("name", ""),
            address=f.get("offset", 0),
            size=f.get("size", 0),
            calling_convention=f.get("cc", "unknown"),
            return_type=f.get("type", "unknown"),
            parameters=params,
            local_variables=locals_list,
            decompiled_code=None,
            disassembly=None,
        )

    async def decompile(self, address: int) -> str:
        """Decompile function at address.

        Args:
            address: Function address.

        Returns:
            Decompiled C-like pseudocode.

        Raises:
            ToolError: If decompilation fails.
        """
        if self._r2 is None:
            raise ToolError("No binary loaded")

        await asyncio.to_thread(self._r2.cmd, f"s {address}")
        result = await asyncio.to_thread(self._r2.cmd, "pdc")

        if not result or "Cannot" in result:
            result = await asyncio.to_thread(self._r2.cmd, "pdg")

        if not result or "Cannot" in result:
            raise ToolError("Decompilation not available for this function")

        return result

    async def disassemble(
        self,
        address: int,
        count: int = 20,
    ) -> list[DisassemblyLine]:
        """Disassemble instructions at address.

        Args:
            address: Start address.
            count: Number of instructions.

        Returns:
            List of disassembly lines.

        Raises:
            ToolError: If disassembly fails.
        """
        if self._r2 is None:
            raise ToolError("No binary loaded")

        await asyncio.to_thread(self._r2.cmd, f"s {address}")
        insns = await self._cmd_json(f"pdj {count}")

        result: list[DisassemblyLine] = []
        for insn in insns:
            hex_bytes = insn.get("bytes", "")
            result.append(
                DisassemblyLine(
                    address=insn.get("offset", 0),
                    bytes=hex_bytes,
                    mnemonic=insn.get("opcode", "").split()[0] if insn.get("opcode") else "",
                    operands=" ".join(insn.get("opcode", "").split()[1:]) if insn.get("opcode") else "",
                    comment=insn.get("comment"),
                )
            )

        return result

    async def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Get cross-references to an address.

        Args:
            address: Target address.

        Returns:
            List of cross-references.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            raise ToolError("No binary loaded")

        xrefs = await self._cmd_json(f"axtj @ {address}")

        result: list[CrossReference] = []
        for x in xrefs:
            ref_type = x.get("type", "")
            xref_type: XRefType
            if ref_type == "CALL":
                xref_type = "call"
            elif ref_type in ("JMP", "CJMP"):
                xref_type = "jump"
            else:
                xref_type = "data"

            result.append(
                CrossReference(
                    from_address=x.get("from", 0),
                    to_address=address,
                    ref_type=xref_type,
                    from_function=x.get("fcn_name"),
                    to_function=None,
                )
            )

        return result

    async def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Get cross-references from an address.

        Args:
            address: Source address.

        Returns:
            List of cross-references.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            raise ToolError("No binary loaded")

        xrefs = await self._cmd_json(f"axfj @ {address}")

        result: list[CrossReference] = []
        for x in xrefs:
            ref_type = x.get("type", "")
            xref_type: XRefType
            if ref_type == "CALL":
                xref_type = "call"
            elif ref_type in ("JMP", "CJMP"):
                xref_type = "jump"
            else:
                xref_type = "data"

            result.append(
                CrossReference(
                    from_address=address,
                    to_address=x.get("ref", 0),
                    ref_type=xref_type,
                    from_function=None,
                    to_function=x.get("fcn_name"),
                )
            )

        return result

    async def search_strings(self, pattern: str) -> list[StringInfo]:
        """Search for strings matching pattern.

        Args:
            pattern: Regex pattern to match.

        Returns:
            List of matching strings.

        Raises:
            ToolError: If search fails.
        """
        if self._r2 is None:
            raise ToolError("No binary loaded")

        strings = await self._cmd_json("izj")

        regex = re.compile(pattern, re.IGNORECASE)
        result: list[StringInfo] = []

        for s in strings:
            string_val = s.get("string", "")
            if regex.search(string_val):
                raw_encoding = s.get("type", "ascii")
                encoding: StringEncoding
                if raw_encoding == "wide":
                    encoding = "utf-16le"
                elif raw_encoding == "utf-8":
                    encoding = "utf-8"
                elif raw_encoding == "utf-16be":
                    encoding = "utf-16be"
                elif raw_encoding == "utf-16le":
                    encoding = "utf-16le"
                else:
                    encoding = "ascii"

                result.append(
                    StringInfo(
                        address=s.get("vaddr", 0),
                        value=string_val,
                        encoding=encoding,
                        section=s.get("section", ""),
                    )
                )

        return result

    async def search_bytes(self, pattern: bytes) -> list[int]:
        """Search for byte pattern.

        Args:
            pattern: Byte sequence to find.

        Returns:
            List of addresses.

        Raises:
            ToolError: If search fails.
        """
        if self._r2 is None:
            raise ToolError("No binary loaded")

        hex_pattern = pattern.hex()
        results = await self._cmd_json(f"/xj {hex_pattern}")

        return [r.get("offset", 0) for r in results]

    async def search_bytes_wildcard(self, hex_pattern: str) -> list[int]:
        """Search for byte pattern with wildcards.

        Args:
            hex_pattern: Hex pattern like '48 8B ?? ??'.

        Returns:
            List of addresses.

        Raises:
            ToolError: If search fails.
        """
        if self._r2 is None:
            raise ToolError("No binary loaded")

        clean_pattern = hex_pattern.replace(" ", "").replace("??", "..")
        results = await self._cmd_json(f"/xj {clean_pattern}")

        return [r.get("offset", 0) for r in results]

    async def _get_sections_internal(self) -> list[SectionInfo]:
        """Get section information.

        Returns:
            List of section info.
        """
        if self._r2 is None:
            _logger.warning("radare2 session not available for _get_sections_internal")
            return []

        sections = await self._cmd_json("iSj")

        result: list[SectionInfo] = []
        for s in sections:
            result.append(
                SectionInfo(
                    name=s.get("name", ""),
                    virtual_address=s.get("vaddr", 0),
                    virtual_size=s.get("vsize", 0),
                    raw_size=s.get("size", 0),
                    characteristics=s.get("perm", 0),
                    entropy=s.get("entropy", 0.0),
                )
            )

        return result

    async def _get_imports_internal(self) -> list[ImportInfo]:
        """Get import information.

        Returns:
            List of import info.
        """
        if self._r2 is None:
            _logger.warning("radare2 session not available for _get_imports_internal")
            return []

        imports = await self._cmd_json("iij")

        result: list[ImportInfo] = []
        for i in imports:
            result.append(
                ImportInfo(
                    dll=i.get("lib", ""),
                    function=i.get("name", ""),
                    ordinal=i.get("ordinal"),
                    address=i.get("plt", 0),
                )
            )

        return result

    async def _get_exports_internal(self) -> list[ExportInfo]:
        """Get export information.

        Returns:
            List of export info.
        """
        if self._r2 is None:
            _logger.warning("radare2 session not available for _get_exports_internal")
            return []

        exports = await self._cmd_json("iEj")

        result: list[ExportInfo] = []
        for idx, e in enumerate(exports):
            result.append(
                ExportInfo(
                    name=e.get("name", ""),
                    ordinal=idx,
                    address=e.get("vaddr", 0),
                )
            )

        return result

    async def get_imports(self) -> list[ImportInfo]:
        """Get imported functions.

        Returns:
            List of import information.

        Raises:
            ToolError: If operation fails.
        """
        return await self._get_imports_internal()

    async def get_exports(self) -> list[ExportInfo]:
        """Get exported functions.

        Returns:
            List of export information.

        Raises:
            ToolError: If operation fails.
        """
        return await self._get_exports_internal()

    async def rename_function(self, address: int, new_name: str) -> bool:
        """Rename a function.

        Args:
            address: Function address.
            new_name: New function name.

        Returns:
            True if rename succeeded.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            raise ToolError("No binary loaded")

        await asyncio.to_thread(self._r2.cmd, f"afn {new_name} @ {address}")
        _logger.info("Renamed function at 0x%X to %s", address, new_name)
        return True

    async def add_comment(
        self,
        address: int,
        comment: str,
        comment_type: str = "EOL",
    ) -> bool:
        """Add a comment at an address.

        Args:
            address: Address for comment.
            comment: Comment text.
            comment_type: Type of comment.

        Returns:
            True if comment was added.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            raise ToolError("No binary loaded")

        escaped = comment.replace('"', '\\"')
        await asyncio.to_thread(self._r2.cmd, f'CC "{escaped}" @ {address}')
        _logger.info("Added comment at 0x%X", address)
        return True

    async def write_bytes(self, address: int, data: bytes) -> None:
        """Write bytes at an address.

        Args:
            address: Address to write at.
            data: Bytes to write.

        Raises:
            ToolError: If write fails.
        """
        if self._r2 is None:
            raise ToolError("No binary loaded")

        hex_data = data.hex()
        await asyncio.to_thread(self._r2.cmd, f"wx {hex_data} @ {address}")
        _logger.debug("Wrote %d bytes at 0x%X", len(data), address)

    async def assemble_at(self, address: int, instruction: str) -> bytes:
        """Assemble instruction at address.

        Args:
            address: Target address.
            instruction: Assembly instruction.

        Returns:
            Assembled bytes.

        Raises:
            ToolError: If assembly fails.
        """
        if self._r2 is None:
            raise ToolError("No binary loaded")

        result = await asyncio.to_thread(
            self._r2.cmd,
            f'rasm2 -a x86 -b 64 "{instruction}"',
        )

        if not result or "Cannot" in result:
            raise ToolError(f"Failed to assemble: {instruction}")

        return bytes.fromhex(result.strip())

    async def execute_command(self, command: str) -> str:
        """Execute raw radare2 command.

        Args:
            command: radare2 command to execute.

        Returns:
            Command output.

        Raises:
            ToolError: If execution fails.
        """
        if self._r2 is None:
            raise ToolError("No binary loaded")

        return await asyncio.to_thread(self._r2.cmd, command)

    async def _cmd_json(self, command: str) -> list[dict[str, object]]:
        """Execute command and parse JSON output.

        Args:
            command: Command to execute.

        Returns:
            Parsed JSON as list of dicts.
        """
        if self._r2 is None:
            _logger.warning("radare2 session not available for _cmd_json")
            return []

        result = await asyncio.to_thread(self._r2.cmd, command)

        if not result or not result.strip():
            return []

        try:
            parsed = json.loads(result)
            if isinstance(parsed, list):
                return parsed
            elif isinstance(parsed, dict):
                return [parsed]
            return []
        except json.JSONDecodeError:
            _logger.warning("Failed to parse JSON from command: %s", command)
            return []
