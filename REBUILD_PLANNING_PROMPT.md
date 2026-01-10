# Intellicrack Complete Rebuild Planning Prompt

You are tasked with creating a COMPREHENSIVE, DETAILED SPECIFICATION for rebuilding Intellicrack from the ground up. This specification must be complete enough that implementation can proceed without ambiguity.

---

## PROJECT OVERVIEW

**Intellicrack** is an AI-powered reverse engineering orchestration platform. The core concept is:

**The AI fully controls existing reverse engineering tools (Ghidra, x64dbg, Frida, radare2, etc.) based on natural language user requests.**

Intellicrack does NOT reimplement tool functionality. Instead, it provides:
1. A unified interface where users describe what they want in natural language
2. An AI agent that plans, executes, and iterates using real RE tools
3. Bridges that give the AI complete programmatic control over each tool
4. A sandbox environment for safe execution and testing

**Example workflow:**
```
User: "Find the license validation in notepad++.exe and patch it to always return true"

AI Agent:
1. Loads binary in Ghidra → runs analysis
2. Searches for license-related strings
3. Finds cross-references to those strings
4. Decompiles candidate functions
5. Identifies the validation function
6. Generates Frida hook or binary patch
7. Tests in sandbox environment
8. Reports results with option to apply
```

---

## CRITICAL REQUIREMENTS

### ABSOLUTE MANDATE: NO STUBS, MOCKS, OR PLACEHOLDERS

Every single component specified in this plan MUST be:
- **Fully functional** - performs real operations on real data
- **Production-ready** - handles errors, edge cases, and real-world complexity
- **Actually implemented** - no "TODO" markers, no placeholder code, no simulation modes
- **Tested against real targets** - works on actual binaries and tools

If a component cannot be fully implemented, it should NOT be in the specification. This is non-negotiable.

### Technical Requirements

- **Language:** Python 3.13 (latest stable)
- **Project Management:** pixi (NOT pip, NOT conda, NOT poetry)
- **Type Checking:** Full mypy strict mode compliance
- **Linting:** ruff with comprehensive rule set
- **Platform:** Windows-first with cross-platform compatibility where feasible
- **Directory:** D:/Intellicrack

---

## TOOLS REQUIRING FULL AGENTIC CONTROL

The AI must have COMPLETE programmatic control over each tool. This means:
- Start/stop the tool
- Load targets (binaries, processes)
- Execute ALL tool operations via API/bridge
- Receive ALL output and events
- Handle errors and state

### 1. Ghidra (Static Analysis)

**Control mechanism:** ghidra_bridge Python package OR Ghidra headless scripting

**Required capabilities:**
- Start Ghidra in headless/bridge mode
- Load and analyze binaries (PE, ELF, Mach-O)
- Get function list with addresses, names, signatures
- Decompile any function to C pseudocode
- Get cross-references (to and from any address)
- Search strings with regex support
- Search for byte patterns
- Get imports/exports
- Get section information
- Rename functions/variables
- Add comments/annotations
- Get control flow graphs
- Get call graphs
- Apply function signatures
- Define custom data types

### 2. x64dbg (Dynamic Debugging - Windows)

**Control mechanism:** x64dbg plugin with socket/pipe interface OR x64dbgpy

**Required capabilities:**
- Start x64dbg and load target
- Attach to running process
- Set breakpoints (software, hardware, conditional)
- Remove breakpoints
- Run/pause/stop execution
- Single step (into, over, out)
- Read/write registers (all registers including XMM, flags)
- Read/write memory at any address
- Search memory for patterns
- Get loaded modules list
- Get thread list
- Switch threads
- Get stack trace
- Assemble instructions at address
- Disassemble at address
- Set memory breakpoints (read/write/execute)
- Handle debug events (breakpoint hit, exception, etc.)
- Evaluate expressions
- Get/set TEB/PEB information
- Trace execution
- Dump memory regions
- Patch memory

### 3. Frida (Dynamic Instrumentation)

**Control mechanism:** frida-python native bindings

**Required capabilities:**
- Spawn process with instrumentation
- Attach to running process (local and remote)
- Inject JavaScript scripts
- Receive messages from scripts
- Send messages to scripts
- Enumerate modules and exports
- Hook any function by address or name
- Replace function implementations
- Read/write process memory
- Intercept and modify function arguments/return values
- Trace function calls with Stalker
- Scan memory for patterns
- Call arbitrary functions in target
- Allocate memory in target
- Create NativeFunction wrappers
- Handle script lifecycle (load, unload, reload)
- Multiple simultaneous script support
- iOS/Android device support (if applicable)

### 4. radare2 (Analysis & Scripting)

**Control mechanism:** r2pipe

**Required capabilities:**
- Open binary for analysis
- Full auto-analysis
- Disassemble at address/function
- Get function list
- Get string list
- Get imports/exports
- Search for bytes, strings, regex
- Get cross-references
- Print hexdump
- Write/patch bytes
- Assemble instructions
- Get section/segment info
- Get symbols
- Get relocations
- ESIL emulation
- Get control flow graph (JSON)
- Define functions
- Rename symbols
- Add comments
- Binary diffing
- ROP gadget finding
- Format string analysis

### 5. Process Control (Windows)

**Control mechanism:** Native Windows API via ctypes/pywin32

**Required capabilities:**
- Enumerate running processes
- Get process details (PID, name, path, command line)
- Spawn new processes (with various creation flags)
- Terminate processes
- Suspend/resume processes and threads
- Read/write process memory (ReadProcessMemory/WriteProcessMemory)
- Allocate memory in process (VirtualAllocEx)
- Change memory protection (VirtualProtectEx)
- Create remote threads (CreateRemoteThread)
- Inject DLLs
- Get module list in process
- Get thread list in process
- Handle process events

### 6. File/Binary Operations

**Control mechanism:** Native Python + pefile/lief

**Required capabilities:**
- Parse PE files (headers, sections, imports, exports, resources)
- Parse ELF files
- Parse Mach-O files
- Modify and write back PE/ELF files
- Extract resources from executables
- Calculate file hashes (MD5, SHA1, SHA256)
- Calculate entropy
- Identify file type (magic bytes)
- Extract strings (ASCII, Unicode)
- Identify packers/protections (signature-based)
- Unpack common packers (UPX, etc.)

---

## LLM PROVIDER SYSTEM

### Requirements

1. **Multi-provider support:** Anthropic (Claude), OpenAI (GPT-4), Google (Gemini), Mistral, Cohere, local models (Ollama, llama.cpp), OpenRouter, Together AI, Groq, and any provider with OpenAI-compatible API

2. **Dynamic model discovery:** NO hardcoded model names. All model lists fetched dynamically from provider APIs at runtime.

3. **Credential management:**
   - Secure storage using OS keyring (Windows Credential Manager)
   - API key input via GUI with validation
   - OAuth support for providers that require it (Google Cloud, enterprise providers)
   - Credentials encrypted at rest

4. **Tool/function calling:** All providers must support tool use (function calling). The AI must be able to call tool bridges as functions.

5. **Streaming support:** Responses should stream to UI in real-time where supported.

6. **Fallback chains:** If primary provider fails, automatically try secondary.

7. **Context management:** Conversation history, session persistence, context window management.

### Provider-Specific APIs

Each provider implementation must:
- Implement async methods for all operations
- Fetch available models dynamically: GET /v1/models or equivalent
- Handle rate limiting with exponential backoff
- Handle authentication errors gracefully
- Support cancellation of in-flight requests
- Report token usage

---

## SANDBOX ENVIRONMENT

### Requirements

1. **Automatic setup:** Sandbox should configure itself on first run without user intervention.

2. **Isolation:** Code executed in sandbox cannot affect host system.

3. **Windows Sandbox integration:**
   - Detect if Windows Sandbox feature is available
   - Generate .wsb configuration files
   - Map necessary files into sandbox
   - Execute commands inside sandbox
   - Retrieve results from sandbox

4. **QEMU/KVM fallback:**
   - If Windows Sandbox unavailable, use QEMU
   - Manage VM images (download, cache, snapshot)
   - Execute commands via SSH or agent
   - Snapshot before testing, restore after

5. **Docker option:**
   - Windows container support where applicable
   - Linux containers for cross-platform testing

6. **Sandbox capabilities:**
   - Execute arbitrary binaries
   - Monitor file system changes
   - Monitor registry changes (Windows)
   - Monitor network activity
   - Capture process behavior
   - Time-limited execution
   - Resource limits (CPU, memory)
   - Clean reset between tests

---

## GUI SPECIFICATION

### Framework: PyQt6

### Main Window Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│ Menu Bar: [File] [Tools] [Providers] [Sandbox] [Settings] [Help]    │
├─────────────────────────────────────────────────────────────────────┤
│ Toolbar: [Load Binary] [Provider: ▼] [Model: ▼] [Sandbox: ●]       │
├───────────────────────────────┬─────────────────────────────────────┤
│                               │                                     │
│   Chat Panel                  │   Tool Output Panel (Tabbed)        │
│   ─────────────────           │   ─────────────────────────         │
│   User: "Analyze this..."     │   [Ghidra] [x64dbg] [Frida] [r2]   │
│                               │                                     │
│   AI: "I'll start by..."      │   Function: main @ 0x401000         │
│   [Tool call: ghidra.load()]  │   int __cdecl main(int argc, ...)   │
│   [Tool call: ghidra.analyze] │   {                                 │
│                               │       if (check_license()) {        │
│   AI: "Found license check    │           ...                       │
│   at 0x401234..."             │       }                             │
│                               │   }                                 │
│   ┌───────────────────────┐   │                                     │
│   │ Type message...       │   │                                     │
│   └───────────────────────┘   │                                     │
│                               │                                     │
├───────────────────────────────┴─────────────────────────────────────┤
│ Status: Connected to Claude | Session: 45min | Tokens: 12,450       │
└─────────────────────────────────────────────────────────────────────┘
```

### Required Dialogs

1. **Provider Settings:**
   - List all supported providers
   - API key input fields with show/hide toggle
   - OAuth login buttons where applicable
   - "Test Connection" button for each
   - Dynamic model dropdown (populated after auth)
   - Default provider/model selection

2. **Sandbox Settings:**
   - Sandbox type selection (Windows Sandbox, QEMU, Docker)
   - Sandbox resource limits
   - Network isolation toggle
   - Shared folder configuration
   - Test sandbox button

3. **Tool Configuration:**
   - Path to Ghidra installation
   - Path to x64dbg installation
   - Frida server configuration (for remote)
   - radare2 path (usually in PATH)
   - Tool health check

4. **Session Management:**
   - Save/load sessions
   - Session history
   - Export conversation

---

## CONFIGURATION SYSTEM

### Storage

- **Location:** `%APPDATA%/Intellicrack/` on Windows
- **Format:** TOML for config, SQLite for session storage

### Configuration Structure

```toml
[general]
theme = "dark"
default_provider = "anthropic"
default_model = ""  # Empty = use provider's default

[providers.anthropic]
enabled = true
# API key stored in OS keyring, not config file

[providers.openai]
enabled = true
base_url = "https://api.openai.com/v1"

[providers.ollama]
enabled = true
base_url = "http://localhost:11434"

[tools.ghidra]
path = "C:/Tools/ghidra"
java_home = ""  # Auto-detect if empty

[tools.x64dbg]
path = "C:/Tools/x64dbg"

[sandbox]
type = "windows_sandbox"  # or "qemu" or "docker"
auto_setup = true
timeout_seconds = 300
memory_limit_mb = 2048

[sessions]
auto_save = true
save_interval_minutes = 5
max_history = 100
```

---

## DATA STRUCTURES

### Core Types

```python
# Session state
@dataclass
class Session:
    id: str
    created_at: datetime
    binary_path: Path | None
    provider: str
    model: str
    messages: list[Message]
    tool_states: dict[str, ToolState]

@dataclass
class Message:
    role: Literal["user", "assistant", "system", "tool"]
    content: str
    tool_calls: list[ToolCall] | None
    tool_results: list[ToolResult] | None
    timestamp: datetime

@dataclass
class ToolCall:
    id: str
    tool_name: str
    function_name: str
    arguments: dict[str, Any]

@dataclass
class ToolResult:
    call_id: str
    success: bool
    result: Any
    error: str | None
    duration_ms: float

# Tool definitions for LLM
@dataclass
class ToolDefinition:
    name: str
    description: str
    parameters: dict[str, ParameterSpec]
    returns: ReturnSpec

@dataclass
class ParameterSpec:
    type: str
    description: str
    required: bool
    enum: list[str] | None = None
    default: Any = None

# Provider types
@dataclass
class ModelInfo:
    id: str
    name: str
    provider: str
    context_window: int
    supports_tools: bool
    supports_vision: bool
    input_cost_per_1k: float
    output_cost_per_1k: float

@dataclass
class ProviderCredentials:
    api_key: str | None
    oauth_token: str | None
    oauth_refresh: str | None
    expires_at: datetime | None
```

---

## DIRECTORY STRUCTURE

```
D:/Intellicrack/
├── pyproject.toml
├── pixi.toml
├── pixi.lock
├── README.md
├── LICENSE
│
├── src/
│   └── intellicrack/
│       ├── __init__.py
│       ├── __main__.py
│       ├── main.py                 # Entry point
│       │
│       ├── core/
│       │   ├── __init__.py
│       │   ├── orchestrator.py     # Main AI agent loop
│       │   ├── session.py          # Session state management
│       │   ├── tools.py            # Tool registry and schema generation
│       │   ├── config.py           # Configuration management
│       │   └── types.py            # Core data types
│       │
│       ├── providers/
│       │   ├── __init__.py
│       │   ├── base.py             # Provider protocol/interface
│       │   ├── registry.py         # Provider registry
│       │   ├── anthropic.py        # Claude implementation
│       │   ├── openai.py           # OpenAI/compatible implementation
│       │   ├── google.py           # Gemini implementation
│       │   ├── ollama.py           # Local Ollama implementation
│       │   ├── openrouter.py       # OpenRouter implementation
│       │   └── discovery.py        # Dynamic model discovery
│       │
│       ├── bridges/
│       │   ├── __init__.py
│       │   ├── base.py             # Bridge protocol/interface
│       │   ├── ghidra.py           # Ghidra bridge
│       │   ├── x64dbg.py           # x64dbg bridge
│       │   ├── frida.py            # Frida bridge
│       │   ├── radare2.py          # radare2 bridge
│       │   ├── process.py          # Windows process control
│       │   └── binary.py           # Binary file operations
│       │
│       ├── sandbox/
│       │   ├── __init__.py
│       │   ├── base.py             # Sandbox protocol/interface
│       │   ├── manager.py          # Sandbox lifecycle management
│       │   ├── windows.py          # Windows Sandbox implementation
│       │   ├── qemu.py             # QEMU implementation
│       │   └── docker.py           # Docker implementation
│       │
│       ├── credentials/
│       │   ├── __init__.py
│       │   ├── store.py            # Keyring-based credential storage
│       │   └── oauth.py            # OAuth flow handling
│       │
│       └── ui/
│           ├── __init__.py
│           ├── app.py              # Main application window
│           ├── chat.py             # Chat panel widget
│           ├── tools.py            # Tool output panel widget
│           ├── settings.py         # Settings dialogs
│           ├── provider_config.py  # Provider configuration dialog
│           ├── sandbox_config.py   # Sandbox configuration dialog
│           └── resources/          # Icons, styles, etc.
│
├── tests/
│   ├── conftest.py
│   ├── test_providers/
│   ├── test_bridges/
│   ├── test_sandbox/
│   └── test_integration/
│
└── scripts/
    └── setup_sandbox.py           # One-time sandbox setup script
```

---

## IMPLEMENTATION ORDER

The specification must define the exact order of implementation to ensure dependencies are built first:

### Phase 1: Foundation
1. Project setup (pixi.toml, pyproject.toml, directory structure)
2. Core types and data structures
3. Configuration system
4. Credential storage

### Phase 2: LLM Providers
5. Provider base protocol
6. Provider registry
7. Anthropic provider (first, as reference implementation)
8. OpenAI-compatible provider (covers many providers)
9. Ollama provider (local models)
10. Dynamic model discovery

### Phase 3: Tool Bridges
11. Bridge base protocol
12. Binary file operations bridge
13. Frida bridge (easiest, native Python)
14. radare2 bridge (r2pipe is simple)
15. Ghidra bridge (ghidra_bridge)
16. x64dbg bridge (most complex, requires plugin or integration)
17. Process control bridge

### Phase 4: Sandbox
18. Sandbox base protocol
19. Windows Sandbox implementation
20. QEMU implementation (fallback)
21. Sandbox auto-setup

### Phase 5: Orchestrator
22. Tool schema generation (for LLM function calling)
23. Main orchestrator agent loop
24. Session management
25. Error handling and recovery

### Phase 6: GUI
26. Main window skeleton
27. Chat panel
28. Tool output panel
29. Settings dialogs
30. Provider configuration
31. Sandbox configuration

### Phase 7: Integration & Polish
32. Full integration testing
33. Error handling refinement
34. Performance optimization
35. Documentation

---

## SPECIFICATION DELIVERABLES

Your specification document must include:

1. **Architecture Overview** - System diagram, component interactions, data flow

2. **Module Specifications** - For EVERY module:
   - Purpose and responsibility
   - All classes with full method signatures
   - All data types/dataclasses
   - All public interfaces/protocols
   - Error handling strategy
   - Dependencies

3. **API Contracts** - Every interface between components defined precisely

4. **Tool Schemas** - Complete JSON schema for every tool capability (for LLM function calling)

5. **State Machines** - For orchestrator, sandbox lifecycle, session management

6. **Error Taxonomy** - All error types, their meanings, recovery strategies

7. **Configuration Schema** - Complete TOML schema with all options

8. **UI Wireframes** - Layout and behavior for all windows/dialogs

9. **Test Strategy** - What tests are needed, how to test against real tools

10. **pixi.toml** - Complete project configuration

---

## CONSTRAINTS SUMMARY

- Python 3.13
- pixi for project management
- PyQt6 for GUI
- mypy strict mode
- ruff for linting
- Windows-first
- NO stubs, mocks, or placeholders
- ALL tool operations must be REAL and FUNCTIONAL
- Dynamic LLM model discovery (no hardcoded model names)
- Secure credential storage (OS keyring)
- Automatic sandbox setup
- Full agentic control over all tools

---

## OUTPUT FORMAT

Produce a single, comprehensive markdown document that serves as the complete specification for Intellicrack. This document must be detailed enough that:

1. A developer could implement any component without asking clarifying questions
2. All interfaces between components are precisely defined
3. All data structures are complete with types
4. All method signatures include parameter types and return types
5. The implementation order is unambiguous

The specification should be structured as a reference document that implementation can proceed from directly.

---

**BEGIN SPECIFICATION NOW.**
