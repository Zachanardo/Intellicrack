"""Core type definitions for Intellicrack.

This module contains all the fundamental dataclasses, enums, and type definitions
used throughout the Intellicrack application.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal


class ToolName(enum.Enum):
    """Enumeration of all supported reverse engineering tools."""

    GHIDRA = "ghidra"
    X64DBG = "x64dbg"
    FRIDA = "frida"
    RADARE2 = "radare2"
    PROCESS = "process"
    BINARY = "binary"


class ProviderName(enum.Enum):
    """Enumeration of all supported LLM providers."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GOOGLE = "google"
    OLLAMA = "ollama"
    OPENROUTER = "openrouter"


class ConfirmationLevel(enum.Enum):
    """User confirmation requirement levels for destructive operations."""

    NONE = "none"
    DESTRUCTIVE = "destructive"
    ALL = "all"


@dataclass
class ToolCall:
    """Represents a tool/function call request from the LLM.

    Attributes:
        id: Unique identifier for this tool call.
        tool_name: Name of the tool being called.
        function_name: Specific function within the tool.
        arguments: Dictionary of function arguments.
    """

    id: str
    tool_name: str
    function_name: str
    arguments: dict[str, Any]


@dataclass
class ToolResult:
    """Result of executing a tool call.

    Attributes:
        call_id: ID of the corresponding ToolCall.
        success: Whether the operation succeeded.
        result: The result data if successful.
        error: Error message if failed.
        duration_ms: Execution time in milliseconds.
    """

    call_id: str
    success: bool
    result: Any
    error: str | None
    duration_ms: float


@dataclass
class Message:
    """A single message in the conversation.

    Attributes:
        role: The message sender role.
        content: Text content of the message.
        tool_calls: Tool calls made by this message (if assistant).
        tool_results: Results of tool calls (if tool response).
        timestamp: When the message was created.
    """

    role: Literal["user", "assistant", "system", "tool"]
    content: str
    tool_calls: list[ToolCall] | None = None
    tool_results: list[ToolResult] | None = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class SectionInfo:
    """PE/ELF section information.

    Attributes:
        name: Section name (e.g., ".text", ".data").
        virtual_address: Address when loaded in memory.
        virtual_size: Size in memory.
        raw_size: Size on disk.
        characteristics: Section flags/permissions.
        entropy: Shannon entropy (0-8, higher = more random/encrypted).
    """

    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    characteristics: int
    entropy: float


@dataclass
class ImportInfo:
    """Import table entry.

    Attributes:
        dll: Name of the imported DLL/library.
        function: Name of the imported function.
        ordinal: Import ordinal if by ordinal.
        address: Address of the import thunk.
    """

    dll: str
    function: str
    ordinal: int | None
    address: int


@dataclass
class ExportInfo:
    """Export table entry.

    Attributes:
        name: Name of the exported symbol.
        ordinal: Export ordinal number.
        address: Virtual address of the export.
    """

    name: str
    ordinal: int
    address: int


@dataclass
class BinaryInfo:
    """Information about a loaded binary file.

    Attributes:
        path: Filesystem path to the binary.
        name: Filename without path.
        size: File size in bytes.
        md5: MD5 hash of the file.
        sha256: SHA-256 hash of the file.
        file_type: Detected file type (PE, ELF, Mach-O, etc.).
        architecture: Target architecture (x86, x64, ARM, etc.).
        is_64bit: Whether it's a 64-bit binary.
        entry_point: Entry point address.
        sections: List of sections in the binary.
        imports: List of imported functions.
        exports: List of exported functions.
    """

    path: Path
    name: str
    size: int
    md5: str
    sha256: str
    file_type: str
    architecture: str
    is_64bit: bool
    entry_point: int
    sections: list[SectionInfo]
    imports: list[ImportInfo]
    exports: list[ExportInfo]


@dataclass
class ParameterInfo:
    """Function parameter information.

    Attributes:
        name: Parameter name.
        type: Parameter type.
        size: Size in bytes.
        location: Where stored (register, stack, etc.).
    """

    name: str
    type: str
    size: int
    location: str


@dataclass
class VariableInfo:
    """Local variable information.

    Attributes:
        name: Variable name.
        type: Variable type.
        offset: Stack offset or register.
        size: Size in bytes.
    """

    name: str
    type: str
    offset: int
    size: int


@dataclass
class FunctionInfo:
    """Analyzed function information.

    Attributes:
        name: Function name (may be auto-generated).
        address: Function start address.
        size: Function size in bytes.
        calling_convention: Calling convention (cdecl, stdcall, etc.).
        return_type: Return type.
        parameters: List of parameters.
        local_variables: List of local variables.
        decompiled_code: Decompiled C pseudocode if available.
        disassembly: Disassembly listing if available.
    """

    name: str
    address: int
    size: int
    calling_convention: str
    return_type: str
    parameters: list[ParameterInfo]
    local_variables: list[VariableInfo]
    decompiled_code: str | None = None
    disassembly: str | None = None


@dataclass
class CrossReference:
    """Cross-reference information.

    Attributes:
        from_address: Source address of the reference.
        to_address: Target address being referenced.
        ref_type: Type of reference.
        from_function: Source function name if known.
        to_function: Target function name if known.
    """

    from_address: int
    to_address: int
    ref_type: Literal["call", "jump", "data", "read", "write"]
    from_function: str | None
    to_function: str | None


@dataclass
class StringInfo:
    """String found in binary.

    Attributes:
        address: Address where string is located.
        value: The string content.
        encoding: String encoding.
        section: Section containing the string.
    """

    address: int
    value: str
    encoding: Literal["ascii", "utf-8", "utf-16le", "utf-16be"]
    section: str


@dataclass
class BreakpointInfo:
    """Debugger breakpoint.

    Attributes:
        id: Breakpoint ID.
        address: Address of the breakpoint.
        bp_type: Type of breakpoint.
        enabled: Whether breakpoint is active.
        hit_count: Number of times breakpoint was hit.
        condition: Conditional expression if any.
    """

    id: int
    address: int
    bp_type: Literal["software", "hardware", "memory"]
    enabled: bool
    hit_count: int
    condition: str | None = None


@dataclass
class RegisterState:
    """CPU register state (x64).

    Attributes:
        rax-r15: General purpose registers.
        rflags: Flags register.
        cs-ss: Segment registers.
    """

    rax: int
    rbx: int
    rcx: int
    rdx: int
    rsi: int
    rdi: int
    rbp: int
    rsp: int
    rip: int
    r8: int
    r9: int
    r10: int
    r11: int
    r12: int
    r13: int
    r14: int
    r15: int
    rflags: int
    cs: int
    ds: int
    es: int
    fs: int
    gs: int
    ss: int


@dataclass
class MemoryRegion:
    """Process memory region.

    Attributes:
        base_address: Start address of the region.
        size: Size of the region in bytes.
        protection: Memory protection flags.
        state: Memory state (committed, reserved, free).
        type: Memory type (private, mapped, image).
        module_name: Module name if this is an image.
    """

    base_address: int
    size: int
    protection: str
    state: str
    type: str
    module_name: str | None


@dataclass
class ThreadInfo:
    """Thread information.

    Attributes:
        tid: Thread ID.
        start_address: Thread start address.
        state: Thread state.
        priority: Thread priority.
    """

    tid: int
    start_address: int
    state: str
    priority: int


@dataclass
class ModuleInfo:
    """Loaded module information.

    Attributes:
        name: Module filename.
        path: Full path to module.
        base_address: Base address in process.
        size: Module size in memory.
        entry_point: Module entry point.
    """

    name: str
    path: Path
    base_address: int
    size: int
    entry_point: int


@dataclass
class ProcessInfo:
    """Running process information.

    Attributes:
        pid: Process ID.
        name: Process name.
        path: Path to executable.
        command_line: Command line arguments.
        parent_pid: Parent process ID.
        threads: List of threads.
        modules: List of loaded modules.
    """

    pid: int
    name: str
    path: Path | None
    command_line: str | None
    parent_pid: int
    threads: list[ThreadInfo]
    modules: list[ModuleInfo]


@dataclass
class HookInfo:
    """Frida hook information.

    Attributes:
        id: Unique hook identifier.
        target: Target function or address.
        address: Resolved address if known.
        script_id: ID of the script containing the hook.
        active: Whether the hook is currently active.
    """

    id: str
    target: str
    address: int | None
    script_id: str
    active: bool


@dataclass
class PatchInfo:
    """Binary patch information.

    Attributes:
        address: Address where patch is applied.
        original_bytes: Original bytes before patching.
        new_bytes: New bytes after patching.
        description: Description of what the patch does.
        applied: Whether the patch has been applied.
    """

    address: int
    original_bytes: bytes
    new_bytes: bytes
    description: str
    applied: bool


@dataclass
class ToolState:
    """State of a tool bridge.

    Attributes:
        tool: Which tool this state is for.
        connected: Whether connected to the tool.
        process_attached: Whether attached to a process.
        target_path: Path to the loaded target.
        last_error: Last error message if any.
    """

    tool: ToolName
    connected: bool
    process_attached: bool
    target_path: Path | None
    last_error: str | None


@dataclass
class Session:
    """Complete session state.

    Attributes:
        id: Unique session identifier.
        created_at: When session was created.
        updated_at: When session was last updated.
        binaries: List of loaded binaries.
        active_binary_index: Index of currently active binary.
        provider: Active LLM provider.
        model: Active model ID.
        messages: Conversation history.
        tool_states: State of each tool bridge.
        patches: List of patches applied or pending.
    """

    id: str
    created_at: datetime
    updated_at: datetime
    binaries: list[BinaryInfo]
    active_binary_index: int
    provider: ProviderName
    model: str
    messages: list[Message]
    tool_states: dict[ToolName, ToolState]
    patches: list[PatchInfo]


@dataclass
class ModelInfo:
    """LLM model information.

    Attributes:
        id: Model identifier string.
        name: Human-readable model name.
        provider: Which provider offers this model.
        context_window: Maximum context length in tokens.
        supports_tools: Whether model supports function calling.
        supports_vision: Whether model supports image input.
        supports_streaming: Whether model supports streaming.
        input_cost_per_1m_tokens: Cost per 1M input tokens.
        output_cost_per_1m_tokens: Cost per 1M output tokens.
    """

    id: str
    name: str
    provider: ProviderName
    context_window: int
    supports_tools: bool
    supports_vision: bool
    supports_streaming: bool
    input_cost_per_1m_tokens: float | None
    output_cost_per_1m_tokens: float | None


@dataclass
class ProviderCredentials:
    """Credentials for an LLM provider.

    Attributes:
        api_key: API key for authentication.
        api_base: Custom API base URL if any.
        organization_id: Organization ID for providers that support it.
        project_id: Project ID for providers that support it.
    """

    api_key: str | None = None
    api_base: str | None = None
    organization_id: str | None = None
    project_id: str | None = None


@dataclass
class ToolParameter:
    """Tool function parameter definition for LLM schema.

    Attributes:
        name: Parameter name.
        type: JSON Schema type (string, integer, etc.).
        description: Description of the parameter.
        required: Whether the parameter is required.
        enum: List of allowed values if enumerated.
        default: Default value if optional.
    """

    name: str
    type: str
    description: str
    required: bool = True
    enum: list[str] | None = None
    default: Any = None


@dataclass
class ToolFunction:
    """Tool function definition for LLM.

    Attributes:
        name: Full function name (e.g., "ghidra.decompile").
        description: What the function does.
        parameters: List of parameters.
        returns: Description of return value.
    """

    name: str
    description: str
    parameters: list[ToolParameter]
    returns: str


@dataclass
class ToolDefinition:
    """Complete tool definition for LLM function calling.

    Attributes:
        tool_name: Which tool this definition is for.
        description: Overall tool description.
        functions: List of available functions.
    """

    tool_name: ToolName
    description: str
    functions: list[ToolFunction]


class IntellicrackError(Exception):
    """Base exception for all Intellicrack errors."""

    pass


class ProviderError(IntellicrackError):
    """Error related to LLM providers."""

    pass


class AuthenticationError(ProviderError):
    """Authentication failed with provider."""

    pass


class RateLimitError(ProviderError):
    """Rate limit exceeded."""

    pass


class ModelNotFoundError(ProviderError):
    """Requested model not found."""

    pass


class ToolError(IntellicrackError):
    """Error related to tool bridges."""

    pass


class ToolNotFoundError(ToolError):
    """Tool could not be found or installed."""

    pass


class InitializationError(ToolError):
    """Tool failed to initialize."""

    pass


class AttachError(ToolError):
    """Failed to attach to process."""

    pass


class SandboxError(IntellicrackError):
    """Error related to sandbox operations."""

    pass


class ConfigurationError(IntellicrackError):
    """Configuration error."""

    pass
