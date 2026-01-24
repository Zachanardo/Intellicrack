# Intellicrack Bridge Plugin for x64dbg

This plugin provides a named pipe IPC interface for x64dbg/x32dbg, enabling
Intellicrack to programmatically control the debugger for automated binary
analysis and protection defeat operations.

## Features

- Named pipe server at `\\.\pipe\intellicrack_x64dbg`
- JSON-RPC style protocol with 4-byte length prefix
- Full execution control (run, pause, step, breakpoints)
- Register and memory access
- Module enumeration
- Disassembly and assembly
- Event broadcasting (breakpoints, exceptions, DLL loading)

## Building

### Prerequisites

- Visual Studio 2019 or later with C++ support
- CMake 3.16 or later
- x64dbg installed in `tools/x64dbg/`

### Build Commands

```powershell
# Create build directory
mkdir build
cd build

# Configure for 64-bit
cmake .. -G "Visual Studio 17 2022" -A x64 -DBUILD_X64=ON

# Build
cmake --build . --config Release

# Or for 32-bit
cmake .. -G "Visual Studio 17 2022" -A Win32 -DBUILD_X64=OFF
cmake --build . --config Release
```

### Build Both Architectures

```powershell
# Build x64
mkdir build_x64 && cd build_x64
cmake .. -G "Visual Studio 17 2022" -A x64 -DBUILD_X64=ON
cmake --build . --config Release
cd ..

# Build x32
mkdir build_x32 && cd build_x32
cmake .. -G "Visual Studio 17 2022" -A Win32 -DBUILD_X64=OFF
cmake --build . --config Release
cd ..
```

## Installation

Copy the built plugins to the x64dbg plugins directory:

```powershell
# 64-bit plugin
copy build_x64\plugins\intellicrack_bridge_x64.dp64 ..\x64dbg\release\x64\plugins\

# 32-bit plugin
copy build_x32\plugins\intellicrack_bridge_x32.dp32 ..\x64dbg\release\x32\plugins\
```

Or use the `just install-x64dbg-plugin` command from the project root.

## Protocol

### Message Format

All messages use a 4-byte little-endian length prefix followed by JSON:

```
[4 bytes: length][JSON payload]
```

### Request Format

```json
{
  "id": 1,
  "type": "command",
  "command": "bp_set",
  "params": {
    "address": "0x00401000"
  }
}
```

### Response Format

Success:
```json
{
  "id": 1,
  "success": true,
  "result": "0x00401000"
}
```

Error:
```json
{
  "id": 1,
  "success": false,
  "error": "Failed to set breakpoint"
}
```

### Event Format

```json
{
  "type": "event",
  "event": "breakpoint",
  "address": "0x00401000"
}
```

## Supported Commands

### Execution Control

| Command | Parameters | Description |
|---------|------------|-------------|
| `exec` | `cmd` | Execute x64dbg command |
| `run` | - | Continue execution |
| `pause` | - | Pause execution |
| `stop` | - | Stop debugging |
| `step_into` | - | Step into (F7) |
| `step_over` | - | Step over (F8) |
| `step_out` | - | Step out/return |
| `run_to` | `address` | Run to address |

### Breakpoints

| Command | Parameters | Description |
|---------|------------|-------------|
| `bp_set` | `address` | Set breakpoint |
| `bp_remove` | `address` | Remove breakpoint |
| `bp_list` | - | List all breakpoints |
| `bp_enable` | `address` | Enable breakpoint |
| `bp_disable` | `address` | Disable breakpoint |

### Watchpoints

| Command | Parameters | Description |
|---------|------------|-------------|
| `wp_set` | `address`, `size`, `type` | Set hardware watchpoint |
| `wp_remove` | `address` | Remove watchpoint |
| `wp_list` | - | List all watchpoints |

### Registers

| Command | Parameters | Description |
|---------|------------|-------------|
| `reg_all` | - | Get all registers |
| `reg_get` | `name` | Get register value |
| `reg_set` | `name`, `value` | Set register value |

### Memory

| Command | Parameters | Description |
|---------|------------|-------------|
| `mem_read` | `address`, `size` | Read memory (hex) |
| `mem_write` | `address`, `data` | Write memory (hex) |
| `mem_map` | - | Get memory map |

### Modules

| Command | Parameters | Description |
|---------|------------|-------------|
| `mod_list` | - | List loaded modules |
| `mod_base` | `name` | Get module base address |
| `mod_exports` | `name` | Get module exports |
| `mod_imports` | `name` | Get module imports |

### Disassembly

| Command | Parameters | Description |
|---------|------------|-------------|
| `disasm` | `address`, `count` | Disassemble instructions |
| `assemble` | `address`, `instruction` | Assemble instruction |

### Misc

| Command | Parameters | Description |
|---------|------------|-------------|
| `goto` | `address` | Navigate to address |
| `status` | - | Get debugger status |
| `ping` | - | Ping server |

## Events

The plugin broadcasts events for:

- `process_start` - Process started debugging
- `process_exit` - Process exited
- `dll_load` - DLL loaded
- `dll_unload` - DLL unloaded
- `breakpoint` - Breakpoint hit
- `exception` - Exception occurred

## Integration with Intellicrack

The plugin works with `X64DbgBridge` in `src/intellicrack/bridges/x64dbg.py`
and `NamedPipeClient` in `src/intellicrack/bridges/named_pipe_client.py`.

Example usage:

```python
from intellicrack.bridges.x64dbg import X64DbgBridge

async with X64DbgBridge() as bridge:
    await bridge.connect()
    await bridge.set_breakpoint(0x00401000)
    await bridge.run()
```
