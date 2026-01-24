# Intellicrack Stubbed/Incomplete Implementation Plan

## Executive Summary

This plan addresses **11 stubbed/incomplete implementations** across the Intellicrack codebase, providing production-ready solutions with full mypy --strict, darglint, and ruff compliance.

---

## Implementation Items Overview

| # | Component | File | Priority | Effort |
|---|-----------|------|----------|--------|
| 1 | x64dbg Named Pipe IPC | bridges/x64dbg.py + new plugin | Critical | High |
| 2 | x64dbg Watchpoint Tracking | bridges/x64dbg.py | High | Medium |
| 3 | x64dbg Command Line Retrieval | bridges/x64dbg.py | Medium | Low |
| 4 | Ghidra get_data_type/set_data_type | bridges/ghidra.py | High | Medium |
| 5 | Ghidra load_binary Metadata | bridges/ghidra.py | High | Medium |
| 6 | Analysis-Driven Keygen | core/script_gen.py + core/types.py | Critical | High |
| 7 | LLM Dual-Mode Streaming | core/orchestrator.py | High | Medium |
| 8 | LLM Provider Base Fix | providers/base.py | Medium | Low |
| 9 | Remove Docker Sandbox | sandbox/manager.py | Low | Trivial |
| 10 | Ghidra Post-Install Hook | ui/tool_config.py | Medium | Medium |
| 11 | radare2 Post-Install Hook | ui/tool_config.py | Medium | Medium |

---

## 1. x64dbg Named Pipe IPC Implementation

### Problem

- `_connect()` (line 439-455): Attempts socket connection to port 27015 - x64dbg doesn't support this
- `_send_command()` (line 466-497): File-based IPC with no consumer in x64dbg
- 18+ methods depend on broken transport

### Solution Architecture

#### 1.1 New Files to Create

**`src/intellicrack/plugins/x64dbg_plugin/` directory:**

```
CMakeLists.txt
intellicrack_x64dbg.cpp    # Plugin entry points
pipe_server.h/.cpp         # Named pipe server
command_handler.h/.cpp     # Command execution
event_handler.h/.cpp       # Debug event callbacks
protocol.h                 # Protocol constants
third_party/nlohmann/json.hpp
```

**`src/intellicrack/bridges/named_pipe_client.py`** - New async named pipe client

#### 1.2 Protocol Specification

**Pipe Name:** `\\.\pipe\intellicrack_x64dbg`

**Request Format:**

```json
{
  "id": "uuid",
  "type": "command",
  "command": "bp_set",
  "params": {"address": 140701256378368, "type": "software"}
}
```

**Response Format:**

```json
{
  "id": "uuid",
  "success": true,
  "type": "result",
  "data": {"breakpoint_id": 1}
}
```

**Commands:** run, pause, stop, step_into, step_over, step_out, bp_set, bp_remove, bp_list, wp_set, wp_remove, wp_list, reg_all, reg_get, reg_set, disasm, asm, exec

#### 1.3 Python Bridge Modifications

**File:** `src/intellicrack/bridges/x64dbg.py`

- Add import: `from .named_pipe_client import NamedPipeClient, PipeConfig`
- Add instance variable: `self._pipe_client: NamedPipeClient | None = None`
- Replace `_connect()` method with named pipe connection logic
- Replace `_send_command()` method with pipe-based JSON request/response
- Add `_handle_event()` method for async event handling
- Replace `get_registers()` to use single `reg_all` command instead of 24 separate calls

---

## 2. x64dbg Watchpoint Tracking

### Problem

- `remove_watchpoint()` (line 748-758): Logs and returns True without sending command
- `get_watchpoints()` (line 760-766): Returns hardcoded empty list

### Solution

**File:** `src/intellicrack/bridges/x64dbg.py`

Add instance variables:

```python
self._watchpoints: dict[int, WatchpointInfo] = {}
self._next_wp_id: int = 1
```

Implement methods:

- `set_watchpoint()`: Send wp_set command, store in `_watchpoints`
- `remove_watchpoint()`: Send wp_remove command, delete from `_watchpoints`
- `get_watchpoints()`: Return `list(self._watchpoints.values())`

---

## 3. x64dbg Command Line Retrieval

### Problem

- `_get_command_line()` (line 1634): Always returns None after querying PEB

### Solution

**File:** `src/intellicrack/bridges/x64dbg.py`

Fix implementation to:

1. Read ProcessParameters pointer from PEB (offset 0x20 for 64-bit, 0x10 for 32-bit)
2. Read CommandLine UNICODE_STRING (offset 0x70 for 64-bit, 0x40 for 32-bit)
3. Read buffer contents and decode UTF-16-LE

---

## 4. Ghidra Data Type Operations

### Problem

- Tool schemas defined at lines 268-298 but no implementations exist

### Solution

**File:** `src/intellicrack/bridges/ghidra.py`

Add new methods:

```python
async def get_data_type(self, address: int) -> DataTypeInfo | None:
    """Get data type at address via Ghidra DataTypeManager."""
    # Execute Jython: currentProgram.getListing().getDataAt(toAddr(address))
    # Return DataTypeInfo with name, category, size, is_pointer, is_array

async def set_data_type(self, address: int, data_type: str) -> bool:
    """Set data type at address."""
    # Execute Jython: Search DataTypeManager, apply via getListing().createData()
```

**File:** `src/intellicrack/core/types.py`

Add new dataclass:

```python
@dataclass
class DataTypeInfo:
    address: int
    name: str
    category: str
    size: int
    is_pointer: bool
    is_array: bool
    array_length: int | None
    base_type: str | None
```

---

## 5. Ghidra Binary Metadata Enhancement

### Problem

- `load_binary()` (line 454-508): Returns entry_point=0, empty sections/imports/exports

### Solution

**File:** `src/intellicrack/bridges/ghidra.py`

Add new method `_extract_binary_metadata()` that executes Jython to:

1. Get entry point from `currentProgram.getSymbolTable()`
2. Get sections from `currentProgram.getMemory().getBlocks()`
3. Get imports from `getExternalSymbols()`
4. Get exports from entry point symbols

Modify `load_binary()` to call `_extract_binary_metadata()` when Ghidra is connected.

---

## 6. Analysis-Driven Keygen Generation

### Problem

- `generate_keygen_template()` (line 746-908): Generic template with random generation
- Line 768: Comment says "This is a template - implement the actual algorithm"
- Line 805: Uses `random.choices()` for key generation

### Solution

**File:** `src/intellicrack/core/types.py`

Add new types:

```python
class AlgorithmType(enum.Enum):
    UNKNOWN, MD5, SHA1, SHA256, CRC32, XOR, RSA, AES, DES,
    CUSTOM_HASH, CHECKSUM, HWID_BASED, TIME_BASED, FEATURE_FLAG

class KeyFormat(enum.Enum):
    UNKNOWN, SERIAL_DASHED, SERIAL_PLAIN, ALPHANUMERIC,
    NUMERIC_ONLY, HEX_STRING, BASE64, NAME_SERIAL_PAIR, HARDWARE_LOCKED

@dataclass
class CryptoAPICall:
    api_name: str
    address: int
    dll: str
    caller_function: str | None
    parameters_hint: str | None

@dataclass
class ValidationFunctionInfo:
    address: int
    name: str
    return_type: str
    comparison_addresses: list[int]
    string_references: list[str]
    calls_crypto_api: bool
    complexity_score: int

@dataclass
class MagicConstant:
    value: int
    address: int
    usage_context: str
    bit_width: int

@dataclass
class LicensingAnalysis:
    binary_name: str
    algorithm_type: AlgorithmType
    secondary_algorithms: list[AlgorithmType]
    key_format: KeyFormat
    key_length: int
    group_size: int | None
    group_separator: str | None
    validation_functions: list[ValidationFunctionInfo]
    crypto_api_calls: list[CryptoAPICall]
    magic_constants: list[MagicConstant]
    checksum_algorithm: str | None
    checksum_position: Literal["prefix", "suffix", "embedded", None]
    hardware_id_apis: list[str]
    time_check_present: bool
    feature_flags: dict[str, int]
    blacklist_present: bool
    online_validation: bool
    confidence_score: float
    analysis_notes: list[str]
```

**File:** `src/intellicrack/core/script_gen.py`

Add new methods:

```python
def generate_keygen_from_analysis(self, analysis: LicensingAnalysis) -> GeneratedScript:
    """Route to algorithm-specific generator based on analysis."""

def _generate_md5_keygen(self, analysis: LicensingAnalysis) -> GeneratedScript:
def _generate_sha1_keygen(self, analysis: LicensingAnalysis) -> GeneratedScript:
def _generate_crc32_keygen(self, analysis: LicensingAnalysis) -> GeneratedScript:
def _generate_xor_keygen(self, analysis: LicensingAnalysis) -> GeneratedScript:
def _generate_checksum_keygen(self, analysis: LicensingAnalysis) -> GeneratedScript:
def _generate_hwid_keygen(self, analysis: LicensingAnalysis) -> GeneratedScript:
def _generate_time_based_keygen(self, analysis: LicensingAnalysis) -> GeneratedScript:
def _generate_feature_flag_keygen(self, analysis: LicensingAnalysis) -> GeneratedScript:
def _generate_rsa_keygen(self, analysis: LicensingAnalysis) -> GeneratedScript:
def _generate_custom_hash_keygen(self, analysis: LicensingAnalysis) -> GeneratedScript:
```

**New File:** `src/intellicrack/core/license_analyzer.py`

Create `LicenseAnalyzer` class that:

1. Detects crypto API calls from imports
2. Finds license-related strings and their xrefs
3. Identifies validation functions
4. Extracts magic constants
5. Returns populated `LicensingAnalysis`

---

## 7. LLM Dual-Mode Streaming

### Problem

- `orchestrator.py` line 510: Streaming path always returns `None` for tool_calls
- Tools are effectively disabled during streaming

### Solution

**File:** `src/intellicrack/core/orchestrator.py`

Add to `OrchestratorConfig`:

```python
stream_mode: Literal["auto", "always", "never"] = "auto"
```

Refactor `_call_llm()` into:

```python
def _should_use_streaming(self, tools_available: bool, is_final_response: bool) -> bool:
    """Auto mode: non-streaming when tools available, streaming for final response."""

async def _stream_response(...) -> tuple[Message, None]:
    """Streaming path - returns None for tool_calls."""

async def _non_stream_response(...) -> tuple[Message, list[ToolCall] | None]:
    """Non-streaming path - properly returns tool_calls."""

async def _call_llm(self, ..., is_final_response: bool = False):
    """Route to streaming or non-streaming based on context."""
```

Modify `_run_agent_loop()` to detect when final response is expected.

---

## 8. LLM Provider Base Fix

### Problem

- `base.py` line 206: Abstract method has `yield ""` placeholder

### Solution

**File:** `src/intellicrack/providers/base.py`

Change from:

```python
@abstractmethod
async def chat_stream(...) -> AsyncIterator[str]:
    yield ""  # Problematic
```

To proper abstract method pattern:

```python
@abstractmethod
def chat_stream(
    self,
    messages: list[Message],
    tools: list[ToolDefinition] | None = None,
) -> AsyncIterator[str]:
    """Stream chat completion responses.

    Args:
        messages: Conversation history.
        tools: Optional tool definitions.

    Yields:
        Streamed response text chunks.

    Raises:
        NotImplementedError: Must be implemented by subclasses.
    """
    raise NotImplementedError("Subclasses must implement chat_stream")
    yield  # Type hint: this is a generator
```

Note: The `yield` after `raise` is unreachable but required by Python to make the return type `AsyncIterator[str]` valid. This is the standard pattern for abstract generators - the raise ensures subclasses override it, while the yield satisfies the type checker.

---

## 9. Remove Docker Sandbox

### Problem

- `manager.py` line 28: `SandboxType = Literal["windows", "docker", "qemu"]` includes docker
- `manager.py` line 187: Docker creation raises "Unsupported sandbox type"

### Solution

**File:** `src/intellicrack/sandbox/manager.py`

Change line 28:

```python
SandboxType = Literal["windows", "qemu"]
```

---

## 10. Ghidra Post-Install Hook

### Problem

- `tool_config.py` lines 173-177: Empty loop with break, does nothing

### Solution

**File:** `src/intellicrack/ui/tool_config.py`

Implement `_post_install_ghidra()`:

1. Locate extracted Ghidra directory
2. Install ghidra_bridge Python package via pip
3. Create bridge server installation script in Extensions folder
4. Create headless analysis startup script (.bat for Windows)
5. Create bridge server Jython script for Ghidra
6. Create verification script

---

## 11. radare2 Post-Install Hook

### Problem

- `tool_config.py` lines 179-185: Checks PATH but just `pass`

### Solution

**File:** `src/intellicrack/ui/tool_config.py`

Implement `_post_install_radare2()`:

1. Locate bin directory (may be in versioned subdirectory)
2. Add to Windows user PATH via registry (HKEY_CURRENT_USER\Environment)
3. Broadcast WM_SETTINGCHANGE to notify running processes
4. Update current process PATH for immediate use
5. Verify by running `radare2 -v`
6. Create default ~/.radare2/radare2rc configuration

---

## Critical Files Summary

| File | Changes |
|------|---------|
| `src/intellicrack/bridges/x64dbg.py` | Named pipe client, watchpoints, command line fix |
| `src/intellicrack/bridges/named_pipe_client.py` | NEW - Async Windows named pipe client |
| `src/intellicrack/plugins/x64dbg_plugin/*` | NEW - C++ x64dbg plugin (6+ files) |
| `src/intellicrack/bridges/ghidra.py` | get_data_type, set_data_type, _extract_binary_metadata |
| `src/intellicrack/core/types.py` | DataTypeInfo, LicensingAnalysis, AlgorithmType, etc. |
| `src/intellicrack/core/script_gen.py` | Analysis-driven keygen generators |
| `src/intellicrack/core/license_analyzer.py` | NEW - LicenseAnalyzer class |
| `src/intellicrack/core/orchestrator.py` | Dual-mode streaming logic |
| `src/intellicrack/providers/base.py` | Fix abstract chat_stream method |
| `src/intellicrack/sandbox/manager.py` | Remove "docker" from SandboxType |
| `src/intellicrack/ui/tool_config.py` | Ghidra and radare2 post-install hooks |

---

## Verification Plan

### Linting

```bash
pixi run ruff check src/intellicrack/bridges/x64dbg.py
pixi run ruff check src/intellicrack/bridges/ghidra.py
pixi run ruff check src/intellicrack/core/types.py
pixi run ruff check src/intellicrack/core/script_gen.py
pixi run ruff check src/intellicrack/core/orchestrator.py
pixi run ruff check src/intellicrack/providers/base.py
pixi run ruff check src/intellicrack/sandbox/manager.py
pixi run ruff check src/intellicrack/ui/tool_config.py
```

### Type Checking

```bash
pixi run mypy --strict src/intellicrack/bridges/x64dbg.py
pixi run mypy --strict src/intellicrack/bridges/ghidra.py
pixi run mypy --strict src/intellicrack/core/types.py
pixi run mypy --strict src/intellicrack/core/script_gen.py
pixi run mypy --strict src/intellicrack/core/orchestrator.py
```

### Docstring Validation

```bash
pixi run darglint src/intellicrack/bridges/x64dbg.py
pixi run darglint src/intellicrack/bridges/ghidra.py
pixi run darglint src/intellicrack/core/script_gen.py
```

### Integration Testing

1. **x64dbg**: Load x64dbg with plugin, verify pipe connection, test breakpoints/stepping
2. **Ghidra**: Connect to Ghidra bridge, test data type operations, verify binary metadata
3. **Keygen**: Generate keygens from sample analysis, verify output validity
4. **Streaming**: Test chat with tools enabled/disabled, verify dual-mode behavior
5. **Post-install**: Run tool installation, verify PATH updates and scripts created

---

## Implementation Order

1. **Phase 1** - Types and Infrastructure
   - Add new types to `core/types.py`
   - Fix `providers/base.py` abstract method
   - Remove docker from `sandbox/manager.py`

2. **Phase 2** - Ghidra Enhancements
   - Implement `get_data_type()` and `set_data_type()`
   - Implement `_extract_binary_metadata()`
   - Update `load_binary()`

3. **Phase 3** - Keygen System
   - Create `license_analyzer.py`
   - Implement algorithm-specific keygen generators
   - Update `script_gen.py`

4. **Phase 4** - Orchestrator Streaming
   - Implement dual-mode streaming logic
   - Update agent loop for final response detection

5. **Phase 5** - Tool Post-Install Hooks
   - Implement `_post_install_ghidra()`
   - Implement `_post_install_radare2()`

6. **Phase 6** - x64dbg Named Pipe (Largest)
   - Create `named_pipe_client.py`
   - Create C++ plugin project
   - Update `x64dbg.py` bridge
   - Implement watchpoint tracking
   - Fix command line retrieval
