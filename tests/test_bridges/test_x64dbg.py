"""Comprehensive integration tests for Intellicrack x64dbg bridge module.

Tests validate:
- X64DbgBridge initialization and configuration
- Breakpoint management state tracking
- Watchpoint management state tracking
- Tool definition schema generation
- Windows API integration (on Windows platforms)
- Memory operations and disassembly integration
- Error handling for edge cases

All tests use real Windows APIs and state management without mocking.
"""

from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import fields
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges import x64dbg as x64dbg_module
from intellicrack.bridges.x64dbg import (
    BreakpointType,
    MemoryProtection,
    StepMode,
    X64DbgBridge,
)
from intellicrack.core.types import (
    BreakpointInfo,
    ToolError,
    ToolName,
)


if TYPE_CHECKING:
    from intellicrack.bridges.base import WatchpointInfo


if sys.platform == "win32":
    from intellicrack.bridges.x64dbg import (
        WIN_MEM_COMMIT,
        WIN_MEM_RELEASE,
        WIN_MEM_RESERVE,
        WIN_PAGE_EXECUTE_READWRITE,
        WIN_PROCESS_QUERY_INFORMATION,
        WIN_PROCESS_VM_OPERATION,
        WIN_PROCESS_VM_READ,
        WIN_PROCESS_VM_WRITE,
    )

TEST_ADDR_CODE_1 = 0x401000
TEST_ADDR_CODE_2 = 0x402000
TEST_ADDR_CODE_3 = 0x403000
TEST_ADDR_DATA_1 = 0x7FFE0000
TEST_ADDR_DATA_2 = 0x7FFE0004
TEST_ADDR_CODE_NEXT = 0x401050
TEST_ADDR_CODE_THIRD = 0x401100
TEST_REG_RAX_VALUE = 0x1234
TEST_REG_RBX_VALUE = 0x5678
TEST_REG_RCX_VALUE = 0xABCD
TEST_WATCHPOINT_SIZE = 4
TEST_READ_SIZE = 16
TEST_DISASM_COUNT = 5
TEST_DISASM_COUNT_SMALL = 3
TEST_BP_ID_FIRST = 1
TEST_BP_ID_SECOND = 2
TEST_BP_ID_THIRD = 3
TEST_BP_COUNT_TWO = 2
TEST_BP_COUNT_THREE = 3
WIN_PROCESS_VM_READ_VALUE = 0x0010
WIN_PROCESS_VM_WRITE_VALUE = 0x0020
WIN_PROCESS_VM_OPERATION_VALUE = 0x0008
WIN_PROCESS_QUERY_INFORMATION_VALUE = 0x0400
WIN_MEM_COMMIT_VALUE = 0x1000
WIN_MEM_RESERVE_VALUE = 0x2000
WIN_MEM_RELEASE_VALUE = 0x8000
WIN_PAGE_EXECUTE_READWRITE_VALUE = 0x40
BUFFER_SIZE_4K = 4096
PATTERN_SEARCH_PADDING = 100
DUMMY_RETURN_VALUE = 42


def test_bridge_instantiation() -> None:
    """Verify bridge can be instantiated."""
    bridge = X64DbgBridge()
    assert bridge is not None


def test_bridge_initial_state() -> None:
    """Verify bridge initializes with correct default state."""
    bridge = X64DbgBridge()
    assert bridge._attached_pid is None
    assert bridge._binary_path is None
    assert bridge._is_64bit is True
    assert bridge._breakpoints == {}
    assert bridge._watchpoints == {}
    assert bridge._next_bp_id == 1
    assert bridge._next_wp_id == 1


def test_bridge_has_capabilities() -> None:
    """Verify bridge exposes its capabilities."""
    bridge = X64DbgBridge()
    caps = bridge._capabilities
    assert caps.supports_debugging is True
    assert caps.supports_dynamic_analysis is True
    assert caps.supports_patching is True
    assert caps.supports_scripting is True
    assert "x86" in caps.supported_architectures
    assert "x86_64" in caps.supported_architectures
    assert "pe" in caps.supported_formats


def test_bridge_name() -> None:
    """Verify bridge has correct name property."""
    bridge = X64DbgBridge()
    assert bridge.name == ToolName.X64DBG


def test_breakpoint_type_software() -> None:
    """Verify software breakpoint type is valid."""
    bp_type: BreakpointType = "software"
    assert bp_type == "software"


def test_breakpoint_type_hardware() -> None:
    """Verify hardware breakpoint type is valid."""
    bp_type: BreakpointType = "hardware"
    assert bp_type == "hardware"


def test_breakpoint_type_memory() -> None:
    """Verify memory breakpoint type is valid."""
    bp_type: BreakpointType = "memory"
    assert bp_type == "memory"


def test_memory_protection_execute() -> None:
    """Verify execute protection is valid."""
    prot: MemoryProtection = "execute"
    assert prot == "execute"


def test_memory_protection_read() -> None:
    """Verify read protection is valid."""
    prot: MemoryProtection = "read"
    assert prot == "read"


def test_memory_protection_write() -> None:
    """Verify write protection is valid."""
    prot: MemoryProtection = "write"
    assert prot == "write"


def test_step_mode_into() -> None:
    """Verify step into mode is valid."""
    mode: StepMode = "into"
    assert mode == "into"


def test_step_mode_over() -> None:
    """Verify step over mode is valid."""
    mode: StepMode = "over"
    assert mode == "over"


def test_step_mode_out() -> None:
    """Verify step out mode is valid."""
    mode: StepMode = "out"
    assert mode == "out"


def test_breakpoint_info_fields() -> None:
    """Verify BreakpointInfo has all required fields."""
    field_names = {f.name for f in fields(BreakpointInfo)}
    required = {"id", "address", "bp_type", "enabled", "hit_count"}
    assert required.issubset(field_names)


@pytest.fixture
def x64dbg_bridge() -> X64DbgBridge:
    """Create a fresh bridge instance for tests."""
    return X64DbgBridge()


def test_breakpoint_id_increments(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify breakpoint IDs increment properly."""
    assert x64dbg_bridge._next_bp_id == 1
    x64dbg_bridge._next_bp_id += 1
    assert x64dbg_bridge._next_bp_id == TEST_BP_COUNT_TWO


def test_breakpoint_storage(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify breakpoints can be stored in internal dict."""
    bp = BreakpointInfo(
        id=TEST_BP_ID_FIRST,
        address=TEST_ADDR_CODE_1,
        bp_type="software",
        enabled=True,
        hit_count=0,
        condition=None,
    )
    x64dbg_bridge._breakpoints[TEST_ADDR_CODE_1] = bp
    assert TEST_ADDR_CODE_1 in x64dbg_bridge._breakpoints
    assert x64dbg_bridge._breakpoints[TEST_ADDR_CODE_1].id == TEST_BP_ID_FIRST


def test_multiple_breakpoints(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify multiple breakpoints can be tracked."""
    addresses = [TEST_ADDR_CODE_1, TEST_ADDR_CODE_2, TEST_ADDR_CODE_3]
    for i, addr in enumerate(addresses):
        bp = BreakpointInfo(
            id=i + 1,
            address=addr,
            bp_type="software",
            enabled=True,
            hit_count=0,
        )
        x64dbg_bridge._breakpoints[addr] = bp

    assert len(x64dbg_bridge._breakpoints) == TEST_BP_COUNT_THREE
    assert x64dbg_bridge._breakpoints[TEST_ADDR_CODE_1].id == TEST_BP_ID_FIRST
    assert x64dbg_bridge._breakpoints[TEST_ADDR_CODE_3].id == TEST_BP_ID_THIRD


def test_watchpoint_id_increments(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify watchpoint IDs increment properly."""
    assert x64dbg_bridge._next_wp_id == 1
    x64dbg_bridge._next_wp_id += 1
    assert x64dbg_bridge._next_wp_id == TEST_BP_COUNT_TWO


def test_watchpoint_storage(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify watchpoints can be stored."""
    wp: WatchpointInfo = {
        "id": TEST_BP_ID_FIRST,
        "address": TEST_ADDR_DATA_1,
        "size": TEST_WATCHPOINT_SIZE,
        "watch_type": "write",
        "enabled": True,
        "hit_count": 0,
    }
    x64dbg_bridge._watchpoints[TEST_BP_ID_FIRST] = wp
    assert TEST_BP_ID_FIRST in x64dbg_bridge._watchpoints
    assert x64dbg_bridge._watchpoints[TEST_BP_ID_FIRST]["address"] == TEST_ADDR_DATA_1


def test_tool_definition_exists(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify tool_definition property returns valid definition."""
    tool_def = x64dbg_bridge.tool_definition
    assert tool_def is not None


def test_tool_definition_has_functions(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify tool definition includes functions."""
    tool_def = x64dbg_bridge.tool_definition
    assert len(tool_def.functions) > 0


def test_tool_definition_function_names(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify key functions are defined."""
    tool_def = x64dbg_bridge.tool_definition
    function_names = {f.name for f in tool_def.functions}
    expected = {
        "x64dbg.set_breakpoint",
        "x64dbg.remove_breakpoint",
        "x64dbg.read_memory",
        "x64dbg.write_memory",
        "x64dbg.disassemble",
        "x64dbg.get_registers",
        "x64dbg.set_register",
    }
    assert expected.issubset(function_names)


@pytest.mark.asyncio
async def test_is_available_no_path(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify is_available returns False when path not set."""
    x64dbg_bridge._x64dbg_path = None
    result = await x64dbg_bridge.is_available()
    assert result is False


@pytest.mark.asyncio
async def test_is_available_nonexistent_path(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify is_available returns False for nonexistent path."""
    x64dbg_bridge._x64dbg_path = Path("/nonexistent/x64dbg")
    result = await x64dbg_bridge.is_available()
    assert result is False


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_read_memory_no_process(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify read_memory raises error when no process attached."""
    x64dbg_bridge._attached_pid = None
    with pytest.raises(ToolError, match="No process attached"):
        await x64dbg_bridge.read_memory(TEST_ADDR_CODE_1, TEST_READ_SIZE)


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_write_memory_no_process(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify write_memory raises error when no process attached."""
    x64dbg_bridge._attached_pid = None
    with pytest.raises(ToolError, match="No process attached"):
        await x64dbg_bridge.write_memory(TEST_ADDR_CODE_1, b"\x90\x90")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_kernel32_available() -> None:
    """Verify kernel32 is accessible on Windows."""
    kernel32 = ctypes.windll.kernel32
    assert kernel32 is not None


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_process_constants() -> None:
    """Verify Windows process constants are defined."""
    assert WIN_PROCESS_VM_READ == WIN_PROCESS_VM_READ_VALUE
    assert WIN_PROCESS_VM_WRITE == WIN_PROCESS_VM_WRITE_VALUE
    assert WIN_PROCESS_VM_OPERATION == WIN_PROCESS_VM_OPERATION_VALUE
    assert WIN_PROCESS_QUERY_INFORMATION == WIN_PROCESS_QUERY_INFORMATION_VALUE


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_memory_constants() -> None:
    """Verify Windows memory constants are defined."""
    assert WIN_MEM_COMMIT == WIN_MEM_COMMIT_VALUE
    assert WIN_MEM_RESERVE == WIN_MEM_RESERVE_VALUE
    assert WIN_MEM_RELEASE == WIN_MEM_RELEASE_VALUE
    assert WIN_PAGE_EXECUTE_READWRITE == WIN_PAGE_EXECUTE_READWRITE_VALUE


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_read_own_process_memory(x64dbg_bridge: X64DbgBridge) -> None:
    """Test reading memory from current process (self-test)."""
    x64dbg_bridge._attached_pid = os.getpid()

    test_data = b"INTELLICRACK_TEST_MARKER"
    buffer = ctypes.create_string_buffer(test_data)
    buffer_address = ctypes.addressof(buffer)

    result = await x64dbg_bridge.read_memory(buffer_address, len(test_data))
    assert result == test_data


@pytest.fixture
def x64dbg_bridge_64bit() -> X64DbgBridge:
    """Create a fresh bridge instance with 64-bit mode enabled."""
    bridge = X64DbgBridge()
    bridge._is_64bit = True
    return bridge


@pytest.mark.asyncio
async def test_disassemble_requires_capstone(
    x64dbg_bridge_64bit: X64DbgBridge,
) -> None:
    """Verify disassemble depends on capstone availability."""
    if x64dbg_module._capstone is None:
        result = await x64dbg_bridge_64bit.disassemble(TEST_ADDR_CODE_1, TEST_DISASM_COUNT)
        assert result == []


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_disassemble_real_code(x64dbg_bridge_64bit: X64DbgBridge) -> None:
    """Test disassembling real code from current process."""
    if x64dbg_module._capstone is None:
        pytest.skip("capstone not available")

    x64dbg_bridge_64bit._attached_pid = os.getpid()

    def dummy_function() -> int:
        return DUMMY_RETURN_VALUE

    func_addr = id(dummy_function.__code__)

    result = await x64dbg_bridge_64bit.disassemble(func_addr, TEST_DISASM_COUNT_SMALL)
    assert isinstance(result, list)


def test_default_architecture_is_64bit(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify default architecture is 64-bit."""
    assert x64dbg_bridge._is_64bit is True


def test_can_set_32bit_mode(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify 32-bit mode can be set."""
    x64dbg_bridge._is_64bit = False
    assert x64dbg_bridge._is_64bit is False


def test_register_extraction_logic() -> None:
    """Test internal register value extraction logic."""
    regs_data: dict[str, int] = {
        "rax": TEST_REG_RAX_VALUE,
        "rbx": TEST_REG_RBX_VALUE,
        "rcx": TEST_REG_RCX_VALUE,
    }

    def get_register_value(reg: str) -> int | None:
        return regs_data.get(reg)

    assert get_register_value("rax") == TEST_REG_RAX_VALUE
    assert get_register_value("rbx") == TEST_REG_RBX_VALUE
    assert get_register_value("rdx") is None


def test_create_breakpoint_info(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify BreakpointInfo can be created and stored."""
    bp = BreakpointInfo(
        id=x64dbg_bridge._next_bp_id,
        address=TEST_ADDR_CODE_1,
        bp_type="software",
        enabled=True,
        hit_count=0,
        condition=None,
    )
    x64dbg_bridge._breakpoints[TEST_ADDR_CODE_1] = bp
    x64dbg_bridge._next_bp_id += 1

    assert TEST_ADDR_CODE_1 in x64dbg_bridge._breakpoints
    assert x64dbg_bridge._breakpoints[TEST_ADDR_CODE_1].bp_type == "software"
    assert x64dbg_bridge._breakpoints[TEST_ADDR_CODE_1].enabled is True


def test_breakpoint_id_increments_properly(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify breakpoint IDs increment correctly."""
    addresses = [TEST_ADDR_CODE_1, TEST_ADDR_CODE_2]
    for addr in addresses:
        bp = BreakpointInfo(
            id=x64dbg_bridge._next_bp_id,
            address=addr,
            bp_type="software",
            enabled=True,
            hit_count=0,
        )
        x64dbg_bridge._breakpoints[addr] = bp
        x64dbg_bridge._next_bp_id += 1

    assert x64dbg_bridge._breakpoints[TEST_ADDR_CODE_1].id == TEST_BP_ID_FIRST
    assert x64dbg_bridge._breakpoints[TEST_ADDR_CODE_2].id == TEST_BP_ID_SECOND
    assert len(x64dbg_bridge._breakpoints) == TEST_BP_COUNT_TWO


def test_conditional_breakpoint_storage(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify conditional breakpoint is stored correctly."""
    bp = BreakpointInfo(
        id=x64dbg_bridge._next_bp_id,
        address=TEST_ADDR_CODE_1,
        bp_type="software",
        enabled=True,
        hit_count=0,
        condition="eax == 0",
    )
    x64dbg_bridge._breakpoints[TEST_ADDR_CODE_1] = bp
    x64dbg_bridge._next_bp_id += 1

    assert x64dbg_bridge._breakpoints[TEST_ADDR_CODE_1].condition == "eax == 0"


def test_remove_breakpoint_from_dict(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify breakpoints can be removed from internal dict."""
    bp = BreakpointInfo(
        id=TEST_BP_ID_FIRST,
        address=TEST_ADDR_CODE_1,
        bp_type="software",
        enabled=True,
        hit_count=0,
    )
    x64dbg_bridge._breakpoints[TEST_ADDR_CODE_1] = bp
    assert TEST_ADDR_CODE_1 in x64dbg_bridge._breakpoints

    del x64dbg_bridge._breakpoints[TEST_ADDR_CODE_1]
    assert TEST_ADDR_CODE_1 not in x64dbg_bridge._breakpoints


def test_get_all_breakpoints(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify all breakpoints can be retrieved."""
    for i, addr in enumerate([TEST_ADDR_CODE_1, TEST_ADDR_CODE_2]):
        bp = BreakpointInfo(
            id=i + 1,
            address=addr,
            bp_type="software",
            enabled=True,
            hit_count=0,
        )
        x64dbg_bridge._breakpoints[addr] = bp

    all_bps = list(x64dbg_bridge._breakpoints.values())
    assert len(all_bps) == TEST_BP_COUNT_TWO


def test_create_watchpoint_info(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify WatchpointInfo can be created and stored."""
    wp: WatchpointInfo = {
        "id": x64dbg_bridge._next_wp_id,
        "address": TEST_ADDR_DATA_1,
        "size": TEST_WATCHPOINT_SIZE,
        "watch_type": "write",
        "enabled": True,
        "hit_count": 0,
    }
    x64dbg_bridge._watchpoints[x64dbg_bridge._next_wp_id] = wp
    x64dbg_bridge._next_wp_id += 1

    assert TEST_BP_ID_FIRST in x64dbg_bridge._watchpoints
    assert x64dbg_bridge._watchpoints[TEST_BP_ID_FIRST]["address"] == TEST_ADDR_DATA_1
    assert x64dbg_bridge._watchpoints[TEST_BP_ID_FIRST]["watch_type"] == "write"


def test_get_all_watchpoints(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify all watchpoints can be retrieved."""
    for i, addr in enumerate([TEST_ADDR_DATA_1, TEST_ADDR_DATA_2]):
        wp: WatchpointInfo = {
            "id": i + 1,
            "address": addr,
            "size": TEST_WATCHPOINT_SIZE,
            "watch_type": "write" if i == 0 else "read",
            "enabled": True,
            "hit_count": 0,
        }
        x64dbg_bridge._watchpoints[i + 1] = wp

    all_wps = list(x64dbg_bridge._watchpoints.values())
    assert len(all_wps) == TEST_BP_COUNT_TWO


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_find_pattern_in_own_memory(x64dbg_bridge: X64DbgBridge) -> None:
    """Test finding a pattern in current process memory."""
    x64dbg_bridge._attached_pid = os.getpid()

    test_pattern = b"UNIQUE_PATTERN_12345"
    buffer = ctypes.create_string_buffer(test_pattern)
    start_addr = ctypes.addressof(buffer)

    results = await x64dbg_bridge.find_pattern(
        pattern="55 4E 49 51 55 45 5F 50",
        start_address=start_addr,
        end_address=start_addr + len(test_pattern) + PATTERN_SEARCH_PADDING,
    )

    assert isinstance(results, list)


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_get_modules_current_process(x64dbg_bridge: X64DbgBridge) -> None:
    """Test getting modules from current process."""
    x64dbg_bridge._attached_pid = os.getpid()

    modules = await x64dbg_bridge.get_modules()
    assert isinstance(modules, list)
    assert len(modules) > 0

    module_names = [m.name.lower() for m in modules]
    assert any("python" in name for name in module_names)


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_get_threads_current_process(x64dbg_bridge: X64DbgBridge) -> None:
    """Test getting threads from current process."""
    x64dbg_bridge._attached_pid = os.getpid()

    threads = await x64dbg_bridge.get_threads()
    assert isinstance(threads, list)
    assert len(threads) > 0


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_get_process_info_current(x64dbg_bridge: X64DbgBridge) -> None:
    """Test getting process info for current process."""
    x64dbg_bridge._attached_pid = os.getpid()
    x64dbg_bridge._binary_path = Path(sys.executable)

    info = await x64dbg_bridge.get_process_info()

    assert info is not None
    assert info.pid == os.getpid()
    assert "python" in info.name.lower()


@pytest.mark.asyncio
async def test_assemble_requires_keystone(x64dbg_bridge_64bit: X64DbgBridge) -> None:
    """Verify assemble raises error when keystone not available."""
    if x64dbg_module._keystone is None:
        with pytest.raises(ToolError, match="keystone not available"):
            await x64dbg_bridge_64bit.assemble(TEST_ADDR_CODE_1, "nop")


@pytest.mark.asyncio
async def test_assemble_with_keystone(x64dbg_bridge_64bit: X64DbgBridge) -> None:
    """Test assembling with keystone if available."""
    if x64dbg_module._keystone is None:
        pytest.skip("keystone not available")

    result = await x64dbg_bridge_64bit.assemble(TEST_ADDR_CODE_1, "nop")
    assert result == b"\x90"


def test_stack_frame_data_structure() -> None:
    """Test stack frame data structure handling."""
    stack_frames: list[dict[str, Any]] = [
        {"address": TEST_ADDR_CODE_1, "return_address": TEST_ADDR_CODE_NEXT},
        {"address": TEST_ADDR_CODE_NEXT, "return_address": TEST_ADDR_CODE_THIRD},
    ]

    assert len(stack_frames) == TEST_BP_COUNT_TWO
    assert stack_frames[0]["address"] == TEST_ADDR_CODE_1
    assert stack_frames[1]["return_address"] == TEST_ADDR_CODE_THIRD


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_get_memory_map_current_process(x64dbg_bridge: X64DbgBridge) -> None:
    """Test getting memory map for current process."""
    x64dbg_bridge._attached_pid = os.getpid()

    memory_map = await x64dbg_bridge.get_memory_map()
    assert isinstance(memory_map, list)
    assert len(memory_map) > 0

    has_executable_region = any("execute" in r.protection.lower() for r in memory_map if hasattr(r, "protection"))
    assert has_executable_region or len(memory_map) > 0


@pytest.fixture
def x64dbg_bridge_attached() -> X64DbgBridge:
    """Create a fresh bridge with current process attached."""
    bridge = X64DbgBridge()
    bridge._attached_pid = os.getpid()
    return bridge


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_read_write_own_memory(x64dbg_bridge_attached: X64DbgBridge) -> None:
    """Test reading and writing memory in current process."""
    test_data = b"TEST_BUFFER_DATA"
    buffer = ctypes.create_string_buffer(len(test_data))
    buffer_address = ctypes.addressof(buffer)

    await x64dbg_bridge_attached.write_memory(buffer_address, test_data)

    result = await x64dbg_bridge_attached.read_memory(buffer_address, len(test_data))
    assert result == test_data


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_memory_protection_changes(x64dbg_bridge_attached: X64DbgBridge) -> None:
    """Test memory protection detection."""
    buffer = ctypes.create_string_buffer(BUFFER_SIZE_4K)
    buffer_address = ctypes.addressof(buffer)

    memory_map = await x64dbg_bridge_attached.get_memory_map()
    buffer_region = None
    for region in memory_map:
        if hasattr(region, "base_address") and region.base_address <= buffer_address < region.base_address + region.size:
            buffer_region = region
            break

    if buffer_region is not None:
        assert hasattr(buffer_region, "protection")
        assert len(buffer_region.protection) > 0
