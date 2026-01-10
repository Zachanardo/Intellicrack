"""Base protocol for tool bridges.

This module defines the abstract interface that all tool bridge implementations
must follow, enabling consistent interaction across Ghidra, x64dbg, Frida,
radare2, and other reverse engineering tools.
"""

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypedDict

from ..core.types import (
    BinaryInfo,
    BreakpointInfo,
    CrossReference,
    ExportInfo,
    FunctionInfo,
    HookInfo,
    ImportInfo,
    MemoryRegion,
    ModuleInfo,
    PatchInfo,
    RegisterState,
    StringInfo,
    ToolDefinition,
    ToolError,
    ToolName,
    ToolState,
)


class DisassemblyLine(TypedDict):
    """Single line of disassembly output."""

    address: int
    bytes: str
    mnemonic: str
    operands: str
    comment: str | None


class MemorySearchResult(TypedDict):
    """Result from a memory pattern search."""

    address: int
    matched_bytes: str
    context_before: str
    context_after: str


class StackFrame(TypedDict):
    """Single stack frame in a call stack."""

    index: int
    address: int
    return_address: int
    function_name: str | None
    module_name: str | None


class WatchpointInfo(TypedDict):
    """Memory watchpoint information."""

    id: int
    address: int
    size: int
    watch_type: str
    enabled: bool
    hit_count: int


@dataclass
class BridgeCapabilities:
    """Describes the capabilities of a tool bridge.

    Attributes:
        supports_static_analysis: Whether the tool supports static analysis.
        supports_dynamic_analysis: Whether the tool supports dynamic analysis.
        supports_decompilation: Whether the tool can decompile to pseudocode.
        supports_debugging: Whether the tool can debug processes.
        supports_patching: Whether the tool can patch binaries.
        supports_scripting: Whether the tool supports custom scripts.
        supported_architectures: List of supported CPU architectures.
        supported_formats: List of supported binary formats.
    """

    supports_static_analysis: bool = False
    supports_dynamic_analysis: bool = False
    supports_decompilation: bool = False
    supports_debugging: bool = False
    supports_patching: bool = False
    supports_scripting: bool = False
    supported_architectures: list[str] = field(default_factory=list)
    supported_formats: list[str] = field(default_factory=list)


@dataclass
class BridgeState:
    """Current state of a tool bridge.

    Attributes:
        connected: Whether connected to the tool.
        tool_running: Whether the tool process is running.
        binary_loaded: Whether a binary is loaded.
        process_attached: Whether attached to a process.
        target_path: Path to the loaded binary.
        target_pid: PID of attached process.
        last_error: Last error message if any.
    """

    connected: bool = False
    tool_running: bool = False
    binary_loaded: bool = False
    process_attached: bool = False
    target_path: Path | None = None
    target_pid: int | None = None
    last_error: str | None = None


class ToolBridgeBase:
    """Base class for tool bridges.

    All bridge implementations must inherit from this class and override
    the methods defined here. This ensures a consistent interface for
    the orchestrator to interact with any reverse engineering tool.

    Attributes:
        _state: Current state of the bridge.
        _capabilities: Capabilities of the tool.
    """

    def __init__(self) -> None:
        """Initialize the base bridge."""
        self._state: BridgeState = BridgeState()
        self._capabilities: BridgeCapabilities = BridgeCapabilities()

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            The ToolName enum value for this bridge.

        Raises:
            ToolError: If not overridden by subclass.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override the 'name' property"
        )

    @property
    def state(self) -> BridgeState:
        """Get current bridge state.

        Returns:
            Current BridgeState instance.
        """
        return self._state

    @property
    def capabilities(self) -> BridgeCapabilities:
        """Get bridge capabilities.

        Returns:
            BridgeCapabilities describing what this tool can do.
        """
        return self._capabilities

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition with all available functions.

        Raises:
            ToolError: If not overridden by subclass.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override the 'tool_definition' property"
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the tool bridge.

        Args:
            tool_path: Optional path to tool installation.
                      If None, will auto-detect or download.

        Raises:
            ToolError: If tool cannot be found or initialized.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override the 'initialize' method"
        )

    async def shutdown(self) -> None:
        """Shutdown the tool and cleanup resources."""
        self._state = BridgeState()

    async def is_available(self) -> bool:
        """Check if the tool is installed and available.

        Returns:
            True if tool is ready to use.

        Raises:
            ToolError: If not overridden by subclass.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override the 'is_available' method"
        )


class StaticAnalysisBridge(ToolBridgeBase):
    """Base class for static analysis tools (Ghidra, radare2).

    Provides interface for binary loading, disassembly, decompilation,
    and cross-reference analysis without executing the target.
    """

    def __init__(self) -> None:
        """Initialize static analysis bridge."""
        super().__init__()
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_decompilation=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64"],
            supported_formats=["pe", "elf", "macho"],
        )

    async def load_binary(self, path: Path) -> BinaryInfo:
        """Load a binary for analysis.

        Args:
            path: Path to the binary file.

        Returns:
            BinaryInfo with file details.

        Raises:
            ToolError: If binary cannot be loaded.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'load_binary'"
        )

    async def analyze(self) -> None:
        """Run full analysis on loaded binary.

        Raises:
            ToolError: If analysis fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'analyze'"
        )

    async def get_functions(
        self,
        filter_pattern: str | None = None,
    ) -> list[FunctionInfo]:
        """Get all analyzed functions.

        Args:
            filter_pattern: Optional regex pattern to filter function names.

        Returns:
            List of function information.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'get_functions'"
        )

    async def get_function(self, address: int) -> FunctionInfo | None:
        """Get function at specific address.

        Args:
            address: Function address.

        Returns:
            Function info or None if not found.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'get_function'"
        )

    async def decompile(self, address: int) -> str:
        """Decompile function at address.

        Args:
            address: Function address.

        Returns:
            Decompiled C pseudocode.

        Raises:
            ToolError: If decompilation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'decompile'"
        )

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
        raise ToolError(
            f"{self.__class__.__name__} must override 'disassemble'"
        )

    async def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Get cross-references to an address.

        Args:
            address: Target address.

        Returns:
            List of cross-references.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'get_xrefs_to'"
        )

    async def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Get cross-references from an address.

        Args:
            address: Source address.

        Returns:
            List of cross-references.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'get_xrefs_from'"
        )

    async def search_strings(self, pattern: str) -> list[StringInfo]:
        """Search for strings matching pattern.

        Args:
            pattern: Regex pattern to match.

        Returns:
            Matching strings.

        Raises:
            ToolError: If search fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'search_strings'"
        )

    async def search_bytes(self, pattern: bytes) -> list[int]:
        """Search for byte pattern.

        Args:
            pattern: Byte sequence to find.

        Returns:
            List of addresses where pattern found.

        Raises:
            ToolError: If search fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'search_bytes'"
        )

    async def get_imports(self) -> list[ImportInfo]:
        """Get all imported functions.

        Returns:
            List of import information.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'get_imports'"
        )

    async def get_exports(self) -> list[ExportInfo]:
        """Get all exported functions.

        Returns:
            List of export information.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'get_exports'"
        )

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
        raise ToolError(
            f"{self.__class__.__name__} must override 'rename_function'"
        )

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
            comment_type: Type of comment (EOL, PRE, POST, PLATE).

        Returns:
            True if comment was added.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'add_comment'"
        )


class DynamicAnalysisBridge(ToolBridgeBase):
    """Base class for dynamic analysis tools (x64dbg, Frida).

    Provides interface for process attachment, memory manipulation,
    breakpoints, and runtime instrumentation.
    """

    def __init__(self) -> None:
        """Initialize dynamic analysis bridge."""
        super().__init__()
        self._capabilities = BridgeCapabilities(
            supports_dynamic_analysis=True,
            supports_debugging=True,
            supports_patching=True,
            supported_architectures=["x86", "x86_64"],
            supported_formats=["pe"],
        )

    async def attach(self, pid: int) -> None:
        """Attach to a running process.

        Args:
            pid: Process ID to attach to.

        Raises:
            ToolError: If attachment fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'attach'"
        )

    async def spawn(
        self,
        path: Path,
        args: list[str] | None = None,
    ) -> int:
        """Spawn a new process.

        Args:
            path: Path to executable.
            args: Command line arguments.

        Returns:
            PID of spawned process.

        Raises:
            ToolError: If spawn fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'spawn'"
        )

    async def detach(self) -> None:
        """Detach from current process.

        Raises:
            ToolError: If detachment fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'detach'"
        )

    async def read_memory(self, address: int, size: int) -> bytes:
        """Read process memory.

        Args:
            address: Memory address.
            size: Number of bytes to read.

        Returns:
            Memory contents.

        Raises:
            ToolError: If read fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'read_memory'"
        )

    async def write_memory(self, address: int, data: bytes) -> None:
        """Write to process memory.

        Args:
            address: Memory address.
            data: Bytes to write.

        Raises:
            ToolError: If write fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'write_memory'"
        )

    async def get_memory_regions(self) -> list[MemoryRegion]:
        """Get process memory map.

        Returns:
            List of memory regions.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'get_memory_regions'"
        )

    async def scan_memory(self, pattern: bytes) -> list[MemorySearchResult]:
        """Scan process memory for a pattern.

        Args:
            pattern: Byte pattern to search for.

        Returns:
            List of matches with context.

        Raises:
            ToolError: If scan fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'scan_memory'"
        )


class DebuggerBridge(DynamicAnalysisBridge):
    """Base class for full debuggers (x64dbg).

    Extends DynamicAnalysisBridge with breakpoints, stepping,
    and register manipulation.
    """

    def __init__(self) -> None:
        """Initialize debugger bridge."""
        super().__init__()
        self._capabilities.supports_debugging = True

    async def run(self) -> None:
        """Continue execution.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'run'"
        )

    async def pause(self) -> None:
        """Pause execution.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'pause'"
        )

    async def stop(self) -> None:
        """Stop debugging (terminate process).

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'stop'"
        )

    async def step_into(self) -> int:
        """Single step into.

        Returns:
            New instruction pointer.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'step_into'"
        )

    async def step_over(self) -> int:
        """Single step over.

        Returns:
            New instruction pointer.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'step_over'"
        )

    async def step_out(self) -> int:
        """Step out of current function.

        Returns:
            New instruction pointer.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'step_out'"
        )

    async def set_breakpoint(
        self,
        address: int,
        bp_type: str = "software",
        condition: str | None = None,
    ) -> BreakpointInfo:
        """Set a breakpoint.

        Args:
            address: Address for breakpoint.
            bp_type: Type (software, hardware, memory).
            condition: Optional condition expression.

        Returns:
            Breakpoint information.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'set_breakpoint'"
        )

    async def remove_breakpoint(self, address: int) -> bool:
        """Remove a breakpoint.

        Args:
            address: Breakpoint address.

        Returns:
            True if removed successfully.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'remove_breakpoint'"
        )

    async def get_breakpoints(self) -> list[BreakpointInfo]:
        """Get all breakpoints.

        Returns:
            List of breakpoint information.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'get_breakpoints'"
        )

    async def get_registers(self) -> RegisterState:
        """Get all register values.

        Returns:
            RegisterState with all registers.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'get_registers'"
        )

    async def set_register(self, register: str, value: int) -> bool:
        """Set a register value.

        Args:
            register: Register name (rax, rbx, etc.).
            value: New value.

        Returns:
            True if set successfully.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'set_register'"
        )

    async def get_stack_trace(self) -> list[StackFrame]:
        """Get current stack trace.

        Returns:
            List of stack frames.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'get_stack_trace'"
        )

    async def disassemble_at(
        self,
        address: int,
        count: int = 10,
    ) -> list[DisassemblyLine]:
        """Disassemble at runtime address.

        Args:
            address: Start address.
            count: Number of instructions.

        Returns:
            List of disassembly lines.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'disassemble_at'"
        )

    async def assemble_at(self, address: int, instruction: str) -> bytes:
        """Assemble instruction at address.

        Args:
            address: Target address.
            instruction: Assembly instruction.

        Returns:
            Assembled bytes.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'assemble_at'"
        )


class InstrumentationBridge(DynamicAnalysisBridge):
    """Base class for instrumentation tools (Frida).

    Extends DynamicAnalysisBridge with function hooking
    and script execution capabilities.
    """

    def __init__(self) -> None:
        """Initialize instrumentation bridge."""
        super().__init__()
        self._capabilities.supports_scripting = True

    async def enumerate_modules(self) -> list[ModuleInfo]:
        """List all loaded modules in the process.

        Returns:
            List of module information.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'enumerate_modules'"
        )

    async def enumerate_exports(self, module_name: str) -> list[ExportInfo]:
        """List exports of a module.

        Args:
            module_name: Name of the module.

        Returns:
            List of export information.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'enumerate_exports'"
        )

    async def hook_function(
        self,
        target: str,
        on_enter: str | None = None,
        on_leave: str | None = None,
    ) -> HookInfo:
        """Hook a function by name or address.

        Args:
            target: Function name (module!func) or hex address.
            on_enter: Script code to run on function entry.
            on_leave: Script code to run on function exit.

        Returns:
            Hook information.

        Raises:
            ToolError: If hooking fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'hook_function'"
        )

    async def remove_hook(self, hook_id: str) -> bool:
        """Remove a previously installed hook.

        Args:
            hook_id: ID of the hook to remove.

        Returns:
            True if removed successfully.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'remove_hook'"
        )

    async def get_hooks(self) -> list[HookInfo]:
        """Get all active hooks.

        Returns:
            List of hook information.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'get_hooks'"
        )

    async def execute_script(self, script: str) -> str:
        """Execute custom script code.

        Args:
            script: Script code to execute.

        Returns:
            Script execution result.

        Raises:
            ToolError: If execution fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'execute_script'"
        )

    async def intercept_return(self, target: str, return_value: int) -> HookInfo:
        """Hook a function and modify its return value.

        Args:
            target: Function to hook.
            return_value: Value to return instead.

        Returns:
            Hook information.

        Raises:
            ToolError: If operation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'intercept_return'"
        )

    async def call_function(
        self,
        address: int,
        args: list[int] | None = None,
    ) -> int:
        """Call a function in the target process.

        Args:
            address: Function address.
            args: Function arguments.

        Returns:
            Function return value.

        Raises:
            ToolError: If call fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'call_function'"
        )


class BinaryOperationsBridge(ToolBridgeBase):
    """Base class for direct binary file operations.

    Provides interface for reading, modifying, and patching
    binary files without running a full analysis tool.
    """

    def __init__(self) -> None:
        """Initialize binary operations bridge."""
        super().__init__()
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_patching=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64"],
            supported_formats=["pe", "elf", "macho", "raw"],
        )

    async def load_file(self, path: Path) -> BinaryInfo:
        """Load a binary file.

        Args:
            path: Path to the binary.

        Returns:
            BinaryInfo with file details.

        Raises:
            ToolError: If load fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'load_file'"
        )

    async def read_bytes(self, offset: int, size: int) -> bytes:
        """Read bytes from file.

        Args:
            offset: File offset.
            size: Number of bytes.

        Returns:
            Read bytes.

        Raises:
            ToolError: If read fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'read_bytes'"
        )

    async def write_bytes(self, offset: int, data: bytes) -> None:
        """Write bytes to file.

        Args:
            offset: File offset.
            data: Bytes to write.

        Raises:
            ToolError: If write fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'write_bytes'"
        )

    async def apply_patch(self, patch: PatchInfo) -> bool:
        """Apply a patch to the binary.

        Args:
            patch: Patch information.

        Returns:
            True if patch applied successfully.

        Raises:
            ToolError: If patching fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'apply_patch'"
        )

    async def revert_patch(self, patch: PatchInfo) -> bool:
        """Revert a previously applied patch.

        Args:
            patch: Patch to revert.

        Returns:
            True if reverted successfully.

        Raises:
            ToolError: If revert fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'revert_patch'"
        )

    async def save(self, path: Path | None = None) -> Path:
        """Save the binary to file.

        Args:
            path: Optional new path. Uses original if None.

        Returns:
            Path where file was saved.

        Raises:
            ToolError: If save fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'save'"
        )

    async def search_pattern(
        self,
        pattern: bytes,
        start_offset: int = 0,
        max_results: int = 100,
    ) -> list[int]:
        """Search for byte pattern in file.

        Args:
            pattern: Byte pattern to find.
            start_offset: Starting offset for search.
            max_results: Maximum results to return.

        Returns:
            List of offsets where pattern found.

        Raises:
            ToolError: If search fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'search_pattern'"
        )

    async def calculate_checksum(
        self,
        algorithm: str = "sha256",
    ) -> str:
        """Calculate file checksum.

        Args:
            algorithm: Hash algorithm (md5, sha1, sha256).

        Returns:
            Hex digest of hash.

        Raises:
            ToolError: If calculation fails.
        """
        raise ToolError(
            f"{self.__class__.__name__} must override 'calculate_checksum'"
        )
