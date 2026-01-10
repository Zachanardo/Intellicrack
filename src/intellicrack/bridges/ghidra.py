"""Ghidra bridge for static analysis and decompilation.

This module provides integration with Ghidra for advanced static analysis,
decompilation, and reverse engineering capabilities using ghidra_bridge.
"""

import asyncio
import hashlib
import re
import subprocess
from pathlib import Path

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
from .base import (
    BridgeCapabilities,
    BridgeState,
    DisassemblyLine,
    StaticAnalysisBridge,
)

_logger = get_logger("bridges.ghidra")


class GhidraBridge(StaticAnalysisBridge):
    """Bridge for Ghidra reverse engineering suite.

    Provides advanced static analysis and decompilation capabilities
    using the ghidra_bridge Python interface.

    Attributes:
        _ghidra_path: Path to Ghidra installation.
        _bridge: The ghidra_bridge connection.
        _process: Ghidra headless process.
        _binary_path: Path to loaded binary.
    """

    DEFAULT_PORT = 4768

    def __init__(self) -> None:
        """Initialize the Ghidra bridge."""
        super().__init__()
        self._ghidra_path: Path | None = None
        self._bridge: object | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._binary_path: Path | None = None
        self._project_path: Path | None = None
        self._port: int = self.DEFAULT_PORT
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_decompilation=True,
            supports_scripting=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64", "mips", "ppc", "sparc"],
            supported_formats=["pe", "elf", "macho", "raw", "coff"],
        )

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            ToolName.GHIDRA
        """
        return ToolName.GHIDRA

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition with all available functions.
        """
        return ToolDefinition(
            tool_name=ToolName.GHIDRA,
            description="Ghidra static analysis - decompilation, disassembly, cross-references",
            functions=[
                ToolFunction(
                    name="ghidra.load_binary",
                    description="Load a binary file into Ghidra for analysis",
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
                    name="ghidra.analyze",
                    description="Run full Ghidra analysis on loaded binary",
                    parameters=[],
                    returns="Analysis completion status",
                ),
                ToolFunction(
                    name="ghidra.get_functions",
                    description="Get list of all functions in the binary",
                    parameters=[
                        ToolParameter(
                            name="filter_pattern",
                            type="string",
                            description="Optional regex pattern to filter function names",
                            required=False,
                        ),
                    ],
                    returns="List of FunctionInfo objects",
                ),
                ToolFunction(
                    name="ghidra.decompile",
                    description="Decompile a function to C pseudocode",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address of the function to decompile",
                            required=True,
                        ),
                    ],
                    returns="Decompiled C code as string",
                ),
                ToolFunction(
                    name="ghidra.disassemble",
                    description="Get disassembly at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Start address for disassembly",
                            required=True,
                        ),
                        ToolParameter(
                            name="count",
                            type="integer",
                            description="Number of instructions to disassemble",
                            required=False,
                            default=20,
                        ),
                    ],
                    returns="Disassembly text",
                ),
                ToolFunction(
                    name="ghidra.get_xrefs_to",
                    description="Get all cross-references pointing to an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Target address",
                            required=True,
                        ),
                    ],
                    returns="List of CrossReference objects",
                ),
                ToolFunction(
                    name="ghidra.get_xrefs_from",
                    description="Get all cross-references from an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Source address",
                            required=True,
                        ),
                    ],
                    returns="List of CrossReference objects",
                ),
                ToolFunction(
                    name="ghidra.search_strings",
                    description="Search for strings in the binary",
                    parameters=[
                        ToolParameter(
                            name="pattern",
                            type="string",
                            description="Regex pattern to match",
                            required=True,
                        ),
                    ],
                    returns="List of StringInfo objects",
                ),
                ToolFunction(
                    name="ghidra.search_bytes",
                    description="Search for a byte pattern in the binary",
                    parameters=[
                        ToolParameter(
                            name="hex_pattern",
                            type="string",
                            description="Hex string pattern (e.g., '48 8B 05 ?? ?? ?? ??')",
                            required=True,
                        ),
                    ],
                    returns="List of addresses where pattern found",
                ),
                ToolFunction(
                    name="ghidra.rename_function",
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
                    name="ghidra.add_comment",
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
                        ToolParameter(
                            name="comment_type",
                            type="string",
                            description="Type: EOL, PRE, POST, PLATE",
                            required=False,
                            default="EOL",
                            enum=["EOL", "PRE", "POST", "PLATE"],
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="ghidra.get_imports",
                    description="Get all imported functions",
                    parameters=[],
                    returns="List of ImportInfo objects",
                ),
                ToolFunction(
                    name="ghidra.get_exports",
                    description="Get all exported functions",
                    parameters=[],
                    returns="List of ExportInfo objects",
                ),
                ToolFunction(
                    name="ghidra.get_data_type",
                    description="Get data type at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address to check",
                            required=True,
                        ),
                    ],
                    returns="Data type information",
                ),
                ToolFunction(
                    name="ghidra.set_data_type",
                    description="Set data type at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address to set type",
                            required=True,
                        ),
                        ToolParameter(
                            name="data_type",
                            type="string",
                            description="Data type name",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
            ],
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the Ghidra bridge.

        Args:
            tool_path: Path to Ghidra installation.
        """
        self._ghidra_path = tool_path

        try:
            import ghidra_bridge

            self._bridge = await asyncio.to_thread(
                ghidra_bridge.GhidraBridge,
                namespace=None,
                connect_to_host="127.0.0.1",
                connect_to_port=self._port,
            )
            self._state = BridgeState(connected=True, tool_running=True)
            _logger.info("Connected to Ghidra bridge on port %d", self._port)

        except ImportError:
            _logger.warning(
                "ghidra_bridge not installed - install with 'pip install ghidra_bridge'"
            )
            self._bridge = None
            self._state = BridgeState(connected=False, tool_running=False)

        except Exception as e:
            _logger.warning("Failed to connect to Ghidra: %s", e)
            self._bridge = None
            self._state = BridgeState(connected=True, tool_running=False)

    async def shutdown(self) -> None:
        """Shutdown Ghidra and cleanup resources."""
        if self._process is not None:
            self._process.terminate()
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(self._process.wait),
                    timeout=10,
                )
            except asyncio.TimeoutError:
                self._process.kill()
            self._process = None

        self._bridge = None
        self._binary_path = None
        await super().shutdown()
        _logger.info("Ghidra bridge shutdown")

    async def is_available(self) -> bool:
        """Check if Ghidra is available.

        Returns:
            True if Ghidra can be used.
        """
        try:
            import ghidra_bridge
            return True
        except ImportError:
            return False

    async def start_headless(
        self,
        project_dir: Path,
        project_name: str = "intellicrack",
    ) -> None:
        """Start Ghidra in headless mode with bridge.

        Args:
            project_dir: Directory for Ghidra project.
            project_name: Name of the project.

        Raises:
            ToolError: If Ghidra cannot be started.
        """
        if self._ghidra_path is None:
            raise ToolError("Ghidra path not set")

        ghidra_run = self._ghidra_path / "support" / "analyzeHeadless.bat"
        if not ghidra_run.exists():
            ghidra_run = self._ghidra_path / "support" / "analyzeHeadless"

        if not ghidra_run.exists():
            raise ToolError(f"Ghidra headless script not found: {ghidra_run}")

        project_dir.mkdir(parents=True, exist_ok=True)
        self._project_path = project_dir / project_name

        bridge_script = self._create_bridge_script()

        cmd = [
            str(ghidra_run),
            str(project_dir),
            project_name,
            "-scriptPath",
            str(bridge_script.parent),
            "-postScript",
            bridge_script.name,
        ]

        _logger.info("Starting Ghidra headless: %s", " ".join(cmd))

        self._process = await asyncio.to_thread(
            subprocess.Popen,
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        await asyncio.sleep(10)

        try:
            import ghidra_bridge

            self._bridge = await asyncio.to_thread(
                ghidra_bridge.GhidraBridge,
                namespace=None,
                connect_to_host="127.0.0.1",
                connect_to_port=self._port,
            )
            self._state = BridgeState(connected=True, tool_running=True)
            _logger.info("Connected to Ghidra headless")
        except Exception as e:
            raise ToolError(f"Failed to connect to Ghidra: {e}") from e

    def _create_bridge_script(self) -> Path:
        """Create the Ghidra bridge startup script.

        Returns:
            Path to the created script.
        """
        import tempfile

        script_content = f"""
# @category: IntelliCrack
# Start ghidra_bridge server

import ghidra_bridge_server
ghidra_bridge_server.GhidraBridgeServer(
    server_host="127.0.0.1",
    server_port={self._port},
).start()
"""
        script_dir = Path(tempfile.gettempdir()) / "intellicrack_ghidra"
        script_dir.mkdir(exist_ok=True)

        script_path = script_dir / "start_bridge.py"
        script_path.write_text(script_content)

        return script_path

    async def load_binary(self, path: Path) -> BinaryInfo:
        """Load a binary file into Ghidra.

        Args:
            path: Path to the binary file.

        Returns:
            BinaryInfo with file details.

        Raises:
            ToolError: If load fails.
        """
        if not path.exists():
            raise ToolError(f"File not found: {path}")

        self._binary_path = path.resolve()

        if self._bridge is not None:
            try:
                await self._execute_remote(
                    f'importFile(java.io.File("{path.as_posix()}"))'
                )
            except Exception as e:
                _logger.warning("Remote import failed: %s", e)

        data = path.read_bytes()
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

        file_type = self._detect_format(data)
        arch, is_64 = self._detect_architecture(data)

        self._state = BridgeState(
            connected=True,
            tool_running=True,
            binary_loaded=True,
            target_path=self._binary_path,
        )

        _logger.info("Loaded binary: %s", path.name)

        return BinaryInfo(
            path=self._binary_path,
            name=path.name,
            size=len(data),
            md5=md5,
            sha256=sha256,
            file_type=file_type,
            architecture=arch,
            is_64bit=is_64,
            entry_point=0,
            sections=[],
            imports=[],
            exports=[],
        )

    def _detect_format(self, data: bytes) -> str:
        """Detect binary format.

        Args:
            data: Binary data.

        Returns:
            Format string.
        """
        if len(data) < 4:
            return "raw"

        if data[:2] == b"MZ":
            return "pe"
        if data[:4] == b"\x7fELF":
            return "elf"
        if data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                         b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
            return "macho"

        return "raw"

    def _detect_architecture(self, data: bytes) -> tuple[str, bool]:
        """Detect CPU architecture.

        Args:
            data: Binary data.

        Returns:
            Tuple of (architecture, is_64bit).
        """
        if len(data) < 64:
            return "unknown", False

        if data[:2] == b"MZ":
            if len(data) > 0x40:
                pe_offset = int.from_bytes(data[0x3C:0x40], "little")
                if len(data) > pe_offset + 6:
                    machine = int.from_bytes(data[pe_offset + 4:pe_offset + 6], "little")
                    if machine == 0x8664:
                        return "x86_64", True
                    if machine == 0x14c:
                        return "x86", False

        if data[:4] == b"\x7fELF":
            if data[4] == 2:
                return "x86_64", True
            return "x86", False

        return "unknown", False

    async def analyze(self) -> None:
        """Run full Ghidra analysis.

        Raises:
            ToolError: If analysis fails.
        """
        if self._bridge is None:
            _logger.warning("No Ghidra connection, skipping analysis")
            return

        try:
            await self._execute_remote("analyzeAll(currentProgram)")
            _logger.info("Ghidra analysis complete")
        except Exception as e:
            raise ToolError(f"Analysis failed: {e}") from e

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
        if self._bridge is None:
            return []

        try:
            result = await self._execute_remote("""
                functions = []
                fm = currentProgram.getFunctionManager()
                for func in fm.getFunctions(True):
                    functions.append({
                        'name': func.getName(),
                        'address': func.getEntryPoint().getOffset(),
                        'size': func.getBody().getNumAddresses(),
                    })
                functions
            """)

            pattern = re.compile(filter_pattern) if filter_pattern else None
            functions: list[FunctionInfo] = []

            for f in result:
                name = f.get("name", "")
                if pattern and not pattern.search(name):
                    continue

                functions.append(
                    FunctionInfo(
                        name=name,
                        address=f.get("address", 0),
                        size=f.get("size", 0),
                        calling_convention="unknown",
                        return_type="unknown",
                        parameters=[],
                        local_variables=[],
                        decompiled_code=None,
                        disassembly=None,
                    )
                )

            return functions

        except Exception as e:
            _logger.warning("Failed to get functions: %s", e)
            return []

    async def get_function(self, address: int) -> FunctionInfo | None:
        """Get function at a specific address.

        Args:
            address: Function address.

        Returns:
            Function info or None.

        Raises:
            ToolError: If operation fails.
        """
        if self._bridge is None:
            return None

        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is not None:
                    params = []
                    for param in func.getParameters():
                        params.append({{
                            'name': param.getName(),
                            'type': str(param.getDataType()),
                        }})
                    vars = []
                    for var in func.getLocalVariables():
                        vars.append({{
                            'name': var.getName(),
                            'type': str(var.getDataType()),
                            'offset': var.getStackOffset(),
                        }})
                    {{
                        'name': func.getName(),
                        'address': func.getEntryPoint().getOffset(),
                        'size': func.getBody().getNumAddresses(),
                        'signature': func.getSignature().getPrototypeString(),
                        'parameters': params,
                        'variables': vars,
                    }}
                else:
                    None
            """)

            if result is None:
                return None

            params = [
                ParameterInfo(
                    name=p.get("name", ""),
                    type=p.get("type", "unknown"),
                    size=0,
                    location="unknown",
                )
                for p in result.get("parameters", [])
            ]

            variables = [
                VariableInfo(
                    name=v.get("name", ""),
                    type=v.get("type", "unknown"),
                    offset=v.get("offset", 0),
                    size=0,
                )
                for v in result.get("variables", [])
            ]

            return FunctionInfo(
                name=result.get("name", ""),
                address=result.get("address", 0),
                size=result.get("size", 0),
                calling_convention="unknown",
                return_type="unknown",
                parameters=params,
                local_variables=variables,
                decompiled_code=None,
                disassembly=None,
            )

        except Exception as e:
            _logger.warning("Failed to get function: %s", e)
            return None

    async def decompile(self, address: int) -> str:
        """Decompile function at address.

        Args:
            address: Function address.

        Returns:
            Decompiled C pseudocode.

        Raises:
            ToolError: If decompilation fails.
        """
        if self._bridge is None:
            raise ToolError("Ghidra not connected")

        try:
            result = await self._execute_remote(f"""
                from ghidra.app.decompiler import DecompInterface

                ifc = DecompInterface()
                ifc.openProgram(currentProgram)

                addr = toAddr({address})
                func = getFunctionContaining(addr)

                if func is not None:
                    results = ifc.decompileFunction(func, 30, monitor)
                    if results.decompileCompleted():
                        results.getDecompiledFunction().getC()
                    else:
                        "Decompilation failed"
                else:
                    "Function not found"
            """)

            return str(result) if result else "Decompilation failed"

        except Exception as e:
            raise ToolError(f"Decompilation failed: {e}") from e

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
        if self._bridge is None:
            return []

        try:
            result = await self._execute_remote(f"""
                instructions = []
                addr = toAddr({address})
                listing = currentProgram.getListing()

                for i in range({count}):
                    instr = listing.getInstructionAt(addr)
                    if instr is None:
                        break
                    instructions.append({{
                        'address': addr.getOffset(),
                        'bytes': ' '.join('%02X' % b for b in instr.getBytes()),
                        'mnemonic': instr.getMnemonicString(),
                        'operands': instr.getDefaultOperandRepresentation(0),
                    }})
                    addr = instr.getNext().getAddress() if instr.getNext() else None
                    if addr is None:
                        break

                instructions
            """)

            return [
                DisassemblyLine(
                    address=i.get("address", 0),
                    bytes=i.get("bytes", ""),
                    mnemonic=i.get("mnemonic", ""),
                    operands=i.get("operands", ""),
                    comment=None,
                )
                for i in result
            ]

        except Exception as e:
            _logger.warning("Disassembly failed: %s", e)
            return []

    async def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Get cross-references to an address.

        Args:
            address: Target address.

        Returns:
            List of cross-references.

        Raises:
            ToolError: If operation fails.
        """
        if self._bridge is None:
            return []

        try:
            result = await self._execute_remote(f"""
                xrefs = []
                addr = toAddr({address})

                for ref in getReferencesTo(addr):
                    xrefs.append({{
                        'from': ref.getFromAddress().getOffset(),
                        'to': addr.getOffset(),
                        'type': str(ref.getReferenceType()),
                    }})

                xrefs
            """)

            return [
                CrossReference(
                    from_address=x.get("from", 0),
                    to_address=x.get("to", 0),
                    ref_type="call" if "CALL" in x.get("type", "") else "data",
                    from_function=None,
                    to_function=None,
                )
                for x in result
            ]

        except Exception as e:
            _logger.warning("Failed to get xrefs: %s", e)
            return []

    async def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Get cross-references from an address.

        Args:
            address: Source address.

        Returns:
            List of cross-references.

        Raises:
            ToolError: If operation fails.
        """
        if self._bridge is None:
            return []

        try:
            result = await self._execute_remote(f"""
                xrefs = []
                addr = toAddr({address})

                for ref in getReferencesFrom(addr):
                    xrefs.append({{
                        'from': addr.getOffset(),
                        'to': ref.getToAddress().getOffset(),
                        'type': str(ref.getReferenceType()),
                    }})

                xrefs
            """)

            return [
                CrossReference(
                    from_address=x.get("from", 0),
                    to_address=x.get("to", 0),
                    ref_type="call" if "CALL" in x.get("type", "") else "data",
                    from_function=None,
                    to_function=None,
                )
                for x in result
            ]

        except Exception as e:
            _logger.warning("Failed to get xrefs: %s", e)
            return []

    async def search_strings(self, pattern: str) -> list[StringInfo]:
        """Search for strings matching pattern.

        Args:
            pattern: Regex pattern.

        Returns:
            List of matching strings.

        Raises:
            ToolError: If search fails.
        """
        if self._bridge is None:
            return []

        try:
            result = await self._execute_remote(f"""
                import re
                strings = []
                pattern = re.compile(r'{pattern}', re.IGNORECASE)

                for string in currentProgram.getListing().getDefinedData(True):
                    if string.hasStringValue():
                        value = string.getValue()
                        if value and pattern.search(str(value)):
                            strings.append({{
                                'address': string.getAddress().getOffset(),
                                'value': str(value),
                            }})

                strings
            """)

            return [
                StringInfo(
                    address=s.get("address", 0),
                    value=s.get("value", ""),
                    encoding="ascii",
                    section="",
                )
                for s in result
            ]

        except Exception as e:
            _logger.warning("String search failed: %s", e)
            return []

    async def search_bytes(self, pattern: bytes) -> list[int]:
        """Search for byte pattern.

        Args:
            pattern: Bytes to find.

        Returns:
            List of addresses.

        Raises:
            ToolError: If search fails.
        """
        if self._bridge is None:
            return []

        hex_pattern = " ".join(f"{b:02x}" for b in pattern)

        try:
            result = await self._execute_remote(f"""
                from ghidra.app.plugin.core.searchmem import MemSearcherAlgorithm

                addresses = []
                memory = currentProgram.getMemory()

                start = memory.getMinAddress()
                end = memory.getMaxAddress()

                searcher = memory.findBytes(start, end, [{", ".join(str(b) for b in pattern)}], None, True, monitor)

                while searcher is not None:
                    addresses.append(searcher.getOffset())
                    searcher = memory.findBytes(searcher.add(1), end, [{", ".join(str(b) for b in pattern)}], None, True, monitor)

                addresses
            """)

            return result if isinstance(result, list) else []

        except Exception as e:
            _logger.warning("Byte search failed: %s", e)
            return []

    async def rename_function(self, address: int, new_name: str) -> bool:
        """Rename a function.

        Args:
            address: Function address.
            new_name: New name.

        Returns:
            True if renamed.

        Raises:
            ToolError: If operation fails.
        """
        if self._bridge is None:
            raise ToolError("Ghidra not connected")

        try:
            await self._execute_remote(f"""
                from ghidra.program.model.symbol import SourceType

                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is not None:
                    func.setName("{new_name}", SourceType.USER_DEFINED)
            """)
            _logger.info("Renamed function at 0x%X to %s", address, new_name)
            return True

        except Exception as e:
            raise ToolError(f"Rename failed: {e}") from e

    async def add_comment(
        self,
        address: int,
        comment: str,
        comment_type: str = "EOL",
    ) -> bool:
        """Add a comment at an address.

        Args:
            address: Address.
            comment: Comment text.
            comment_type: Type of comment.

        Returns:
            True if added.

        Raises:
            ToolError: If operation fails.
        """
        if self._bridge is None:
            raise ToolError("Ghidra not connected")

        comment_map = {
            "EOL": "CodeUnit.EOL_COMMENT",
            "PRE": "CodeUnit.PRE_COMMENT",
            "POST": "CodeUnit.POST_COMMENT",
            "PLATE": "CodeUnit.PLATE_COMMENT",
        }
        ghidra_type = comment_map.get(comment_type, "CodeUnit.EOL_COMMENT")

        try:
            await self._execute_remote(f"""
                from ghidra.program.model.listing import CodeUnit

                addr = toAddr({address})
                cu = currentProgram.getListing().getCodeUnitAt(addr)
                if cu is not None:
                    cu.setComment({ghidra_type}, "{comment}")
            """)
            _logger.info("Added comment at 0x%X", address)
            return True

        except Exception as e:
            raise ToolError(f"Add comment failed: {e}") from e

    async def get_imports(self) -> list[ImportInfo]:
        """Get imported functions.

        Returns:
            List of imports.

        Raises:
            ToolError: If operation fails.
        """
        if self._bridge is None:
            return []

        try:
            result = await self._execute_remote("""
                imports = []
                st = currentProgram.getSymbolTable()

                for sym in st.getExternalSymbols():
                    imports.append({
                        'dll': str(sym.getParentSymbol().getName()) if sym.getParentSymbol() else '',
                        'function': sym.getName(),
                        'address': sym.getAddress().getOffset(),
                    })

                imports
            """)

            return [
                ImportInfo(
                    dll=i.get("dll", ""),
                    function=i.get("function", ""),
                    ordinal=None,
                    address=i.get("address", 0),
                )
                for i in result
            ]

        except Exception as e:
            _logger.warning("Failed to get imports: %s", e)
            return []

    async def get_exports(self) -> list[ExportInfo]:
        """Get exported functions.

        Returns:
            List of exports.

        Raises:
            ToolError: If operation fails.
        """
        if self._bridge is None:
            return []

        try:
            result = await self._execute_remote("""
                exports = []
                st = currentProgram.getSymbolTable()

                for sym in st.getAllSymbols(True):
                    if sym.isExternalEntryPoint():
                        exports.append({
                            'name': sym.getName(),
                            'address': sym.getAddress().getOffset(),
                        })

                exports
            """)

            return [
                ExportInfo(
                    name=e.get("name", ""),
                    ordinal=idx,
                    address=e.get("address", 0),
                )
                for idx, e in enumerate(result)
            ]

        except Exception as e:
            _logger.warning("Failed to get exports: %s", e)
            return []

    async def _execute_remote(self, code: str) -> object:
        """Execute code on the Ghidra bridge.

        Args:
            code: Python code to execute.

        Returns:
            Result of execution.

        Raises:
            ToolError: If execution fails.
        """
        if self._bridge is None:
            raise ToolError("Ghidra bridge not connected")

        try:
            return await asyncio.to_thread(
                self._bridge.remote_exec,  # type: ignore[union-attr]
                code,
            )
        except Exception as e:
            raise ToolError(f"Remote execution failed: {e}") from e
