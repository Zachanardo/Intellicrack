"""x64dbg bridge for Windows debugging.

This module provides integration with x64dbg for dynamic analysis,
debugging, and memory manipulation on Windows systems.
"""

import asyncio
import json
import socket
import struct
import subprocess
from pathlib import Path
from typing import Literal

from ..core.logging import get_logger
from ..core.types import (
    BreakpointInfo,
    MemoryRegion,
    ModuleInfo,
    ProcessInfo,
    RegisterState,
    ThreadInfo,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from .base import (
    BridgeCapabilities,
    BridgeState,
    DebuggerBridge,
    DisassemblyLine,
    StackFrame,
    WatchpointInfo,
)

_logger = get_logger("bridges.x64dbg")

BreakpointType = Literal["software", "hardware", "memory"]
MemoryProtection = Literal["read", "write", "execute"]
StepMode = Literal["into", "over", "out"]


class X64DbgBridge(DebuggerBridge):
    """Bridge for x64dbg Windows debugger.

    Provides debugging capabilities including breakpoints, stepping,
    register/memory manipulation, and process control.

    Attributes:
        _x64dbg_path: Path to x64dbg installation.
        _process: x64dbg process instance.
        _socket: Communication socket.
        _attached_pid: Currently attached process ID.
    """

    DEFAULT_PORT = 27015
    COMMAND_TIMEOUT = 10.0

    def __init__(self) -> None:
        """Initialize the x64dbg bridge."""
        super().__init__()
        self._x64dbg_path: Path | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._socket: socket.socket | None = None
        self._attached_pid: int | None = None
        self._port: int = self.DEFAULT_PORT
        self._binary_path: Path | None = None
        self._is_64bit: bool = True
        self._breakpoints: dict[int, BreakpointInfo] = {}
        self._next_bp_id: int = 1
        self._capabilities = BridgeCapabilities(
            supports_debugging=True,
            supports_memory_access=True,
            supports_patching=True,
            supports_scripting=True,
            supported_architectures=["x86", "x86_64"],
            supported_formats=["pe"],
        )

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            ToolName.X64DBG
        """
        return ToolName.X64DBG

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition with all available functions.
        """
        return ToolDefinition(
            tool_name=ToolName.X64DBG,
            description="x64dbg debugger - breakpoints, stepping, register/memory manipulation",
            functions=[
                ToolFunction(
                    name="x64dbg.load",
                    description="Load an executable into x64dbg",
                    parameters=[
                        ToolParameter(
                            name="path",
                            type="string",
                            description="Path to executable",
                            required=True,
                        ),
                        ToolParameter(
                            name="args",
                            type="string",
                            description="Command line arguments",
                            required=False,
                        ),
                    ],
                    returns="Load status",
                ),
                ToolFunction(
                    name="x64dbg.attach",
                    description="Attach to a running process",
                    parameters=[
                        ToolParameter(
                            name="pid",
                            type="integer",
                            description="Process ID to attach",
                            required=True,
                        ),
                    ],
                    returns="Attach status",
                ),
                ToolFunction(
                    name="x64dbg.detach",
                    description="Detach from current process",
                    parameters=[],
                    returns="Detach status",
                ),
                ToolFunction(
                    name="x64dbg.run",
                    description="Run/continue execution",
                    parameters=[],
                    returns="Run status",
                ),
                ToolFunction(
                    name="x64dbg.pause",
                    description="Pause execution",
                    parameters=[],
                    returns="Pause status",
                ),
                ToolFunction(
                    name="x64dbg.stop",
                    description="Stop debugging (terminate process)",
                    parameters=[],
                    returns="Stop status",
                ),
                ToolFunction(
                    name="x64dbg.step_into",
                    description="Single step into",
                    parameters=[],
                    returns="New instruction pointer",
                ),
                ToolFunction(
                    name="x64dbg.step_over",
                    description="Single step over",
                    parameters=[],
                    returns="New instruction pointer",
                ),
                ToolFunction(
                    name="x64dbg.step_out",
                    description="Step out of current function",
                    parameters=[],
                    returns="New instruction pointer",
                ),
                ToolFunction(
                    name="x64dbg.set_breakpoint",
                    description="Set a breakpoint",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address for breakpoint",
                            required=True,
                        ),
                        ToolParameter(
                            name="bp_type",
                            type="string",
                            description="Type: software, hardware, memory",
                            required=False,
                            default="software",
                            enum=["software", "hardware", "memory"],
                        ),
                        ToolParameter(
                            name="condition",
                            type="string",
                            description="Conditional expression",
                            required=False,
                        ),
                    ],
                    returns="Breakpoint ID",
                ),
                ToolFunction(
                    name="x64dbg.remove_breakpoint",
                    description="Remove a breakpoint",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Breakpoint address",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="x64dbg.get_registers",
                    description="Get all register values",
                    parameters=[],
                    returns="RegisterState object",
                ),
                ToolFunction(
                    name="x64dbg.set_register",
                    description="Set a register value",
                    parameters=[
                        ToolParameter(
                            name="register",
                            type="string",
                            description="Register name (rax, rbx, etc.)",
                            required=True,
                        ),
                        ToolParameter(
                            name="value",
                            type="integer",
                            description="New value",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="x64dbg.read_memory",
                    description="Read memory",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Memory address",
                            required=True,
                        ),
                        ToolParameter(
                            name="size",
                            type="integer",
                            description="Bytes to read",
                            required=True,
                        ),
                    ],
                    returns="Hex string of memory",
                ),
                ToolFunction(
                    name="x64dbg.write_memory",
                    description="Write memory",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Memory address",
                            required=True,
                        ),
                        ToolParameter(
                            name="data",
                            type="string",
                            description="Hex data to write",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="x64dbg.disassemble",
                    description="Disassemble at address",
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
                            default=10,
                        ),
                    ],
                    returns="Disassembly text",
                ),
                ToolFunction(
                    name="x64dbg.assemble",
                    description="Assemble instruction at address",
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
                    name="x64dbg.get_stack_trace",
                    description="Get current stack trace",
                    parameters=[],
                    returns="List of stack frames",
                ),
                ToolFunction(
                    name="x64dbg.find_pattern",
                    description="Search memory for pattern",
                    parameters=[
                        ToolParameter(
                            name="pattern",
                            type="string",
                            description="Hex pattern with wildcards",
                            required=True,
                        ),
                    ],
                    returns="List of matching addresses",
                ),
                ToolFunction(
                    name="x64dbg.run_command",
                    description="Execute x64dbg command",
                    parameters=[
                        ToolParameter(
                            name="command",
                            type="string",
                            description="Command to execute",
                            required=True,
                        ),
                    ],
                    returns="Command output",
                ),
            ],
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the x64dbg bridge.

        Args:
            tool_path: Path to x64dbg installation.
        """
        self._x64dbg_path = tool_path
        self._state = BridgeState(connected=False, tool_running=False)

        if tool_path is not None:
            x64_exe = tool_path / "release" / "x64" / "x64dbg.exe"
            x32_exe = tool_path / "release" / "x32" / "x32dbg.exe"

            if x64_exe.exists() or x32_exe.exists():
                self._state = BridgeState(connected=True, tool_running=False)
                _logger.info("x64dbg found at %s", tool_path)
            else:
                _logger.warning("x64dbg executables not found in %s", tool_path)

    async def shutdown(self) -> None:
        """Shutdown x64dbg and cleanup resources."""
        await self._close_connection()

        if self._process is not None:
            self._process.terminate()
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(self._process.wait),
                    timeout=5,
                )
            except asyncio.TimeoutError:
                self._process.kill()
            self._process = None

        self._attached_pid = None
        self._breakpoints.clear()
        await super().shutdown()
        _logger.info("x64dbg bridge shutdown")

    async def is_available(self) -> bool:
        """Check if x64dbg is available.

        Returns:
            True if x64dbg can be used.
        """
        if self._x64dbg_path is None:
            return False

        x64_exe = self._x64dbg_path / "release" / "x64" / "x64dbg.exe"
        x32_exe = self._x64dbg_path / "release" / "x32" / "x32dbg.exe"

        return x64_exe.exists() or x32_exe.exists()

    async def _start_debugger(self, is_64bit: bool = True) -> None:
        """Start the x64dbg debugger process.

        Args:
            is_64bit: Whether to use 64-bit debugger.

        Raises:
            ToolError: If debugger cannot be started.
        """
        if self._x64dbg_path is None:
            raise ToolError("x64dbg path not set")

        if is_64bit:
            exe_path = self._x64dbg_path / "release" / "x64" / "x64dbg.exe"
        else:
            exe_path = self._x64dbg_path / "release" / "x32" / "x32dbg.exe"

        if not exe_path.exists():
            raise ToolError(f"x64dbg executable not found: {exe_path}")

        self._is_64bit = is_64bit
        _logger.info("Starting x64dbg: %s", exe_path)

        self._process = await asyncio.to_thread(
            subprocess.Popen,
            [str(exe_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_CONSOLE,
        )

        await asyncio.sleep(3)
        self._state = BridgeState(connected=True, tool_running=True)

    async def _connect(self) -> None:
        """Connect to x64dbg via socket.

        Raises:
            ToolError: If connection fails.
        """
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self.COMMAND_TIMEOUT)
            await asyncio.to_thread(
                self._socket.connect,
                ("127.0.0.1", self._port),
            )
            _logger.info("Connected to x64dbg on port %d", self._port)
        except socket.error as e:
            self._socket = None
            raise ToolError(f"Failed to connect to x64dbg: {e}") from e

    async def _close_connection(self) -> None:
        """Close socket connection."""
        if self._socket is not None:
            try:
                self._socket.close()
            except socket.error:
                pass
            self._socket = None

    async def _send_command(self, command: str) -> str:
        """Send command to x64dbg and get response.

        Args:
            command: Command to execute.

        Returns:
            Command response.

        Raises:
            ToolError: If command fails.
        """
        if self._process is None:
            raise ToolError("x64dbg not running")

        script_path = Path.home() / ".intellicrack" / "x64dbg_cmd.txt"
        script_path.parent.mkdir(parents=True, exist_ok=True)
        script_path.write_text(command)

        result_path = Path.home() / ".intellicrack" / "x64dbg_result.txt"
        if result_path.exists():
            result_path.unlink()

        try:
            await asyncio.sleep(0.1)

            if result_path.exists():
                return result_path.read_text()
            return ""

        except Exception as e:
            raise ToolError(f"Command failed: {e}") from e

    async def load(self, path: Path, args: str | None = None) -> None:
        """Load an executable into x64dbg.

        Args:
            path: Path to executable.
            args: Optional command line arguments.

        Raises:
            ToolError: If load fails.
        """
        if not path.exists():
            raise ToolError(f"File not found: {path}")

        self._binary_path = path.resolve()

        is_64bit = self._detect_architecture(path)

        if self._process is None:
            await self._start_debugger(is_64bit)

        cmd = f'InitDebug "{path.as_posix()}"'
        if args:
            cmd += f', "{args}"'

        await self._send_command(cmd)

        self._state = BridgeState(
            connected=True,
            tool_running=True,
            binary_loaded=True,
            target_path=self._binary_path,
        )

        _logger.info("Loaded %s into x64dbg", path.name)

    def _detect_architecture(self, path: Path) -> bool:
        """Detect if binary is 64-bit.

        Args:
            path: Path to binary.

        Returns:
            True if 64-bit, False if 32-bit.
        """
        try:
            data = path.read_bytes()

            if len(data) < 0x40:
                return True

            if data[:2] != b"MZ":
                return True

            pe_offset = int.from_bytes(data[0x3C:0x40], "little")

            if len(data) < pe_offset + 6:
                return True

            if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return True

            machine = int.from_bytes(data[pe_offset + 4:pe_offset + 6], "little")

            return machine == 0x8664

        except Exception:
            return True

    async def attach(self, pid: int) -> None:
        """Attach to a running process.

        Args:
            pid: Process ID.

        Raises:
            ToolError: If attach fails.
        """
        if self._process is None:
            await self._start_debugger(True)

        await self._send_command(f"attach {pid}")
        self._attached_pid = pid

        self._state = BridgeState(
            connected=True,
            tool_running=True,
            process_attached=True,
        )

        _logger.info("Attached to process %d", pid)

    async def detach(self) -> None:
        """Detach from current process.

        Raises:
            ToolError: If detach fails.
        """
        await self._send_command("detach")
        self._attached_pid = None

        self._state = BridgeState(
            connected=True,
            tool_running=True,
            process_attached=False,
        )

        _logger.info("Detached from process")

    async def run(self) -> None:
        """Continue execution.

        Raises:
            ToolError: If run fails.
        """
        await self._send_command("run")
        _logger.debug("Execution continued")

    async def pause(self) -> None:
        """Pause execution.

        Raises:
            ToolError: If pause fails.
        """
        await self._send_command("pause")
        _logger.debug("Execution paused")

    async def stop(self) -> None:
        """Stop debugging and terminate process.

        Raises:
            ToolError: If stop fails.
        """
        await self._send_command("stop")
        self._attached_pid = None

        self._state = BridgeState(
            connected=True,
            tool_running=True,
            process_attached=False,
        )

        _logger.info("Debugging stopped")

    async def step_into(self) -> int:
        """Single step into.

        Returns:
            New instruction pointer.

        Raises:
            ToolError: If step fails.
        """
        await self._send_command("StepInto")
        regs = await self.get_registers()
        return regs.rip if self._is_64bit else regs.rip & 0xFFFFFFFF

    async def step_over(self) -> int:
        """Single step over.

        Returns:
            New instruction pointer.

        Raises:
            ToolError: If step fails.
        """
        await self._send_command("StepOver")
        regs = await self.get_registers()
        return regs.rip if self._is_64bit else regs.rip & 0xFFFFFFFF

    async def step_out(self) -> int:
        """Step out of current function.

        Returns:
            New instruction pointer.

        Raises:
            ToolError: If step fails.
        """
        await self._send_command("StepOut")
        regs = await self.get_registers()
        return regs.rip if self._is_64bit else regs.rip & 0xFFFFFFFF

    async def set_breakpoint(
        self,
        address: int,
        bp_type: BreakpointType = "software",
        condition: str | None = None,
    ) -> int:
        """Set a breakpoint.

        Args:
            address: Breakpoint address.
            bp_type: Type of breakpoint.
            condition: Optional conditional expression.

        Returns:
            Breakpoint ID.

        Raises:
            ToolError: If operation fails.
        """
        if bp_type == "software":
            cmd = f"bp {address:#x}"
        elif bp_type == "hardware":
            cmd = f"bph {address:#x}"
        else:
            cmd = f"bpm {address:#x}"

        await self._send_command(cmd)

        if condition:
            await self._send_command(f"bpcond {address:#x}, {condition}")

        bp_id = self._next_bp_id
        self._next_bp_id += 1

        self._breakpoints[address] = BreakpointInfo(
            id=bp_id,
            address=address,
            bp_type=bp_type,
            enabled=True,
            hit_count=0,
            condition=condition,
        )

        _logger.info("Set %s breakpoint at 0x%X (id=%d)", bp_type, address, bp_id)
        return bp_id

    async def remove_breakpoint(self, address: int) -> bool:
        """Remove a breakpoint.

        Args:
            address: Breakpoint address.

        Returns:
            True if removed.

        Raises:
            ToolError: If operation fails.
        """
        await self._send_command(f"bc {address:#x}")

        if address in self._breakpoints:
            del self._breakpoints[address]

        _logger.info("Removed breakpoint at 0x%X", address)
        return True

    async def get_breakpoints(self) -> list[BreakpointInfo]:
        """Get all breakpoints.

        Returns:
            List of breakpoints.
        """
        return list(self._breakpoints.values())

    async def set_watchpoint(
        self,
        address: int,
        size: int,
        watch_type: MemoryProtection,
    ) -> int:
        """Set a memory watchpoint.

        Args:
            address: Memory address.
            size: Watch size.
            watch_type: Access type to watch.

        Returns:
            Watchpoint ID.

        Raises:
            ToolError: If operation fails.
        """
        type_map = {"read": "r", "write": "w", "execute": "x"}
        access = type_map.get(watch_type, "rw")

        await self._send_command(f"bpm {address:#x}, {access}, {size}")

        wp_id = self._next_bp_id
        self._next_bp_id += 1

        _logger.info("Set watchpoint at 0x%X (size=%d, type=%s)", address, size, watch_type)
        return wp_id

    async def remove_watchpoint(self, watchpoint_id: int) -> bool:
        """Remove a watchpoint.

        Args:
            watchpoint_id: Watchpoint ID.

        Returns:
            True if removed.
        """
        _logger.info("Removed watchpoint %d", watchpoint_id)
        return True

    async def get_watchpoints(self) -> list[WatchpointInfo]:
        """Get all watchpoints.

        Returns:
            List of watchpoints.
        """
        return []

    async def get_registers(self) -> RegisterState:
        """Get all register values.

        Returns:
            Current register state.

        Raises:
            ToolError: If operation fails.
        """
        return RegisterState(
            rax=await self._get_register_value("rax"),
            rbx=await self._get_register_value("rbx"),
            rcx=await self._get_register_value("rcx"),
            rdx=await self._get_register_value("rdx"),
            rsi=await self._get_register_value("rsi"),
            rdi=await self._get_register_value("rdi"),
            rbp=await self._get_register_value("rbp"),
            rsp=await self._get_register_value("rsp"),
            rip=await self._get_register_value("rip"),
            r8=await self._get_register_value("r8"),
            r9=await self._get_register_value("r9"),
            r10=await self._get_register_value("r10"),
            r11=await self._get_register_value("r11"),
            r12=await self._get_register_value("r12"),
            r13=await self._get_register_value("r13"),
            r14=await self._get_register_value("r14"),
            r15=await self._get_register_value("r15"),
            rflags=await self._get_register_value("rflags"),
            cs=await self._get_register_value("cs"),
            ds=await self._get_register_value("ds"),
            es=await self._get_register_value("es"),
            fs=await self._get_register_value("fs"),
            gs=await self._get_register_value("gs"),
            ss=await self._get_register_value("ss"),
        )

    async def _get_register_value(self, reg: str) -> int:
        """Get a single register value.

        Args:
            reg: Register name.

        Returns:
            Register value.
        """
        result = await self._send_command(f"{reg}")

        try:
            if result.startswith("0x"):
                return int(result, 16)
            return int(result)
        except ValueError:
            return 0

    async def set_register(self, register: str, value: int) -> bool:
        """Set a register value.

        Args:
            register: Register name.
            value: New value.

        Returns:
            True if set.

        Raises:
            ToolError: If operation fails.
        """
        await self._send_command(f"{register}={value:#x}")
        _logger.info("Set %s = 0x%X", register, value)
        return True

    async def read_memory(self, address: int, size: int) -> bytes:
        """Read process memory.

        Args:
            address: Memory address.
            size: Bytes to read.

        Returns:
            Memory contents.

        Raises:
            ToolError: If read fails.
        """
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32

            if self._attached_pid is None:
                raise ToolError("No process attached")

            PROCESS_VM_READ = 0x0010

            handle = kernel32.OpenProcess(
                PROCESS_VM_READ,
                False,
                self._attached_pid,
            )

            if not handle:
                raise ToolError(f"Failed to open process {self._attached_pid}")

            try:
                buffer = ctypes.create_string_buffer(size)
                bytes_read = ctypes.c_size_t()

                success = kernel32.ReadProcessMemory(
                    handle,
                    ctypes.c_void_p(address),
                    buffer,
                    size,
                    ctypes.byref(bytes_read),
                )

                if not success:
                    raise ToolError(f"ReadProcessMemory failed at 0x{address:X}")

                return buffer.raw[:bytes_read.value]

            finally:
                kernel32.CloseHandle(handle)

        except ImportError:
            raise ToolError("Windows API not available") from None

    async def write_memory(self, address: int, data: bytes) -> int:
        """Write to process memory.

        Args:
            address: Memory address.
            data: Bytes to write.

        Returns:
            Bytes written.

        Raises:
            ToolError: If write fails.
        """
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32

            if self._attached_pid is None:
                raise ToolError("No process attached")

            PROCESS_VM_WRITE = 0x0020
            PROCESS_VM_OPERATION = 0x0008

            handle = kernel32.OpenProcess(
                PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                False,
                self._attached_pid,
            )

            if not handle:
                raise ToolError(f"Failed to open process {self._attached_pid}")

            try:
                bytes_written = ctypes.c_size_t()

                success = kernel32.WriteProcessMemory(
                    handle,
                    ctypes.c_void_p(address),
                    data,
                    len(data),
                    ctypes.byref(bytes_written),
                )

                if not success:
                    raise ToolError(f"WriteProcessMemory failed at 0x{address:X}")

                _logger.info("Wrote %d bytes at 0x%X", bytes_written.value, address)
                return bytes_written.value

            finally:
                kernel32.CloseHandle(handle)

        except ImportError:
            raise ToolError("Windows API not available") from None

    async def allocate_memory(self, size: int, protection: str = "rwx") -> int:
        """Allocate memory in target process.

        Args:
            size: Size to allocate.
            protection: Memory protection.

        Returns:
            Allocated address.

        Raises:
            ToolError: If allocation fails.
        """
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32

            if self._attached_pid is None:
                raise ToolError("No process attached")

            PROCESS_VM_OPERATION = 0x0008

            handle = kernel32.OpenProcess(
                PROCESS_VM_OPERATION,
                False,
                self._attached_pid,
            )

            if not handle:
                raise ToolError(f"Failed to open process {self._attached_pid}")

            try:
                MEM_COMMIT = 0x1000
                MEM_RESERVE = 0x2000
                PAGE_EXECUTE_READWRITE = 0x40

                address = kernel32.VirtualAllocEx(
                    handle,
                    0,
                    size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )

                if not address:
                    raise ToolError("VirtualAllocEx failed")

                _logger.info("Allocated %d bytes at 0x%X", size, address)
                return address

            finally:
                kernel32.CloseHandle(handle)

        except ImportError:
            raise ToolError("Windows API not available") from None

    async def free_memory(self, address: int) -> bool:
        """Free memory in target process.

        Args:
            address: Address to free.

        Returns:
            True if freed.
        """
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32

            if self._attached_pid is None:
                return False

            PROCESS_VM_OPERATION = 0x0008

            handle = kernel32.OpenProcess(
                PROCESS_VM_OPERATION,
                False,
                self._attached_pid,
            )

            if not handle:
                return False

            try:
                MEM_RELEASE = 0x8000

                success = kernel32.VirtualFreeEx(
                    handle,
                    address,
                    0,
                    MEM_RELEASE,
                )

                return bool(success)

            finally:
                kernel32.CloseHandle(handle)

        except ImportError:
            return False

    async def get_memory_map(self) -> list[MemoryRegion]:
        """Get memory map of target process.

        Returns:
            List of memory regions.

        Raises:
            ToolError: If operation fails.
        """
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32

            if self._attached_pid is None:
                return []

            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD),
                ]

            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010

            handle = kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                self._attached_pid,
            )

            if not handle:
                return []

            regions: list[MemoryRegion] = []

            try:
                address = 0
                mbi = MEMORY_BASIC_INFORMATION()

                while True:
                    result = kernel32.VirtualQueryEx(
                        handle,
                        ctypes.c_void_p(address),
                        ctypes.byref(mbi),
                        ctypes.sizeof(mbi),
                    )

                    if result == 0:
                        break

                    if mbi.State == 0x1000:
                        prot_map = {
                            0x01: "---",
                            0x02: "r--",
                            0x04: "rw-",
                            0x10: "--x",
                            0x20: "r-x",
                            0x40: "rwx",
                        }

                        regions.append(
                            MemoryRegion(
                                base_address=mbi.BaseAddress or 0,
                                size=mbi.RegionSize,
                                protection=prot_map.get(mbi.Protect, "???"),
                                state="committed",
                                type="private" if mbi.Type == 0x20000 else "mapped",
                                module_name=None,
                            )
                        )

                    address = (mbi.BaseAddress or 0) + mbi.RegionSize

                    if address > 0x7FFFFFFFFFFF:
                        break

            finally:
                kernel32.CloseHandle(handle)

            return regions

        except ImportError:
            return []

    async def disassemble(
        self,
        address: int,
        count: int = 10,
    ) -> list[DisassemblyLine]:
        """Disassemble at address.

        Args:
            address: Start address.
            count: Number of instructions.

        Returns:
            Disassembly lines.

        Raises:
            ToolError: If operation fails.
        """
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

            data = await self.read_memory(address, count * 15)

            mode = CS_MODE_64 if self._is_64bit else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)

            lines: list[DisassemblyLine] = []

            for instr in md.disasm(data, address):
                lines.append(
                    DisassemblyLine(
                        address=instr.address,
                        bytes=" ".join(f"{b:02x}" for b in instr.bytes),
                        mnemonic=instr.mnemonic,
                        operands=instr.op_str,
                        comment=None,
                    )
                )
                if len(lines) >= count:
                    break

            return lines

        except ImportError:
            _logger.warning("capstone not available")
            return []
        except Exception as e:
            _logger.warning("Disassembly failed: %s", e)
            return []

    async def assemble(self, address: int, instruction: str) -> bytes:
        """Assemble instruction at address.

        Args:
            address: Target address.
            instruction: Assembly instruction.

        Returns:
            Assembled bytes.

        Raises:
            ToolError: If assembly fails.
        """
        try:
            from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KS_MODE_32

            mode = KS_MODE_64 if self._is_64bit else KS_MODE_32
            ks = Ks(KS_ARCH_X86, mode)

            encoding, count = ks.asm(instruction, address)

            if encoding is None:
                raise ToolError(f"Failed to assemble: {instruction}")

            return bytes(encoding)

        except ImportError:
            raise ToolError("keystone not available") from None

    async def get_stack_trace(self) -> list[StackFrame]:
        """Get current stack trace.

        Returns:
            List of stack frames.
        """
        frames: list[StackFrame] = []

        regs = await self.get_registers()
        rsp = regs.rsp
        rbp = regs.rbp
        rip = regs.rip

        frames.append(
            StackFrame(
                index=0,
                address=rip,
                return_address=0,
                frame_pointer=rbp,
                stack_pointer=rsp,
                function_name=None,
                module_name=None,
            )
        )

        for i in range(1, 32):
            try:
                if rbp == 0:
                    break

                data = await self.read_memory(rbp, 16)

                if len(data) < 16:
                    break

                if self._is_64bit:
                    saved_rbp = int.from_bytes(data[0:8], "little")
                    return_addr = int.from_bytes(data[8:16], "little")
                else:
                    saved_rbp = int.from_bytes(data[0:4], "little")
                    return_addr = int.from_bytes(data[4:8], "little")

                if return_addr == 0 or saved_rbp == 0:
                    break

                frames.append(
                    StackFrame(
                        index=i,
                        address=return_addr,
                        return_address=return_addr,
                        frame_pointer=saved_rbp,
                        stack_pointer=rbp + (16 if self._is_64bit else 8),
                        function_name=None,
                        module_name=None,
                    )
                )

                rbp = saved_rbp

            except ToolError:
                break

        return frames

    async def find_pattern(
        self,
        pattern: str,
        start_address: int | None = None,
        end_address: int | None = None,
    ) -> list[int]:
        """Search memory for pattern.

        Args:
            pattern: Hex pattern with wildcards (e.g., "48 8B ?? ??").
            start_address: Optional start address.
            end_address: Optional end address.

        Returns:
            List of matching addresses.
        """
        pattern_bytes: list[int | None] = []

        for part in pattern.split():
            if part in ("??", "?"):
                pattern_bytes.append(None)
            else:
                pattern_bytes.append(int(part, 16))

        regions = await self.get_memory_map()
        matches: list[int] = []

        for region in regions:
            if "r" not in region.protection:
                continue

            if start_address and region.base_address + region.size < start_address:
                continue
            if end_address and region.base_address > end_address:
                continue

            try:
                data = await self.read_memory(region.base_address, min(region.size, 0x100000))

                for i in range(len(data) - len(pattern_bytes) + 1):
                    match = True
                    for j, pb in enumerate(pattern_bytes):
                        if pb is not None and data[i + j] != pb:
                            match = False
                            break
                    if match:
                        matches.append(region.base_address + i)

            except ToolError:
                continue

        return matches

    async def run_command(self, command: str) -> str:
        """Execute x64dbg command.

        Args:
            command: Command to execute.

        Returns:
            Command output.

        Raises:
            ToolError: If command fails.
        """
        return await self._send_command(command)

    async def spawn(self, path: Path, args: list[str] | None = None) -> int:
        """Spawn a process for debugging.

        Args:
            path: Path to executable.
            args: Optional arguments.

        Returns:
            Process ID.

        Raises:
            ToolError: If spawn fails.
        """
        args_str = " ".join(args) if args else None
        await self.load(path, args_str)
        return self._attached_pid or 0

    async def get_threads(self) -> list[ThreadInfo]:
        """Get thread information.

        Returns:
            List of threads.
        """
        return []

    async def get_modules(self) -> list[ModuleInfo]:
        """Get loaded modules.

        Returns:
            List of modules.
        """
        return []

    async def get_process_info(self) -> ProcessInfo | None:
        """Get current process information.

        Returns:
            Process info or None.
        """
        if self._attached_pid is None:
            return None

        return ProcessInfo(
            pid=self._attached_pid,
            name=self._binary_path.name if self._binary_path else "unknown",
            path=self._binary_path,
            command_line=None,
            parent_pid=0,
            threads=[],
            modules=[],
        )
