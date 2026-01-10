"""Frida instrumentation bridge for dynamic analysis.

This module provides runtime instrumentation capabilities using Frida
for function hooking, memory manipulation, and process control.
"""

import asyncio
import uuid
from collections.abc import Callable
from pathlib import Path

import frida

from ..core.logging import get_logger
from ..core.types import (
    ExportInfo,
    HookInfo,
    MemoryRegion,
    ModuleInfo,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from .base import (
    BridgeCapabilities,
    BridgeState,
    InstrumentationBridge,
    MemorySearchResult,
)

_logger = get_logger("bridges.frida")


class FridaBridge(InstrumentationBridge):
    """Bridge for Frida dynamic instrumentation.

    Provides function hooking, memory manipulation, and script execution
    capabilities using the Frida framework.

    Attributes:
        _device: Frida device connection.
        _session: Active Frida session.
        _scripts: Active scripts by ID.
        _hooks: Active hooks by ID.
        _message_handler: Handler for script messages.
    """

    def __init__(self) -> None:
        """Initialize the Frida bridge."""
        super().__init__()
        self._device: frida.core.Device | None = None
        self._session: frida.core.Session | None = None
        self._scripts: dict[str, frida.core.Script] = {}
        self._hooks: dict[str, HookInfo] = {}
        self._message_handler: Callable[[dict[str, object]], None] | None = None
        self._pid: int | None = None
        self._capabilities = BridgeCapabilities(
            supports_dynamic_analysis=True,
            supports_patching=True,
            supports_scripting=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64"],
            supported_formats=["pe", "elf", "macho"],
        )

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            ToolName.FRIDA
        """
        return ToolName.FRIDA

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition with all available functions.
        """
        return ToolDefinition(
            tool_name=ToolName.FRIDA,
            description="Frida dynamic instrumentation - hooking, tracing, memory manipulation",
            functions=[
                ToolFunction(
                    name="frida.spawn",
                    description="Spawn a process with Frida instrumentation",
                    parameters=[
                        ToolParameter(
                            name="path",
                            type="string",
                            description="Path to executable",
                            required=True,
                        ),
                        ToolParameter(
                            name="args",
                            type="array",
                            description="Command line arguments",
                            required=False,
                        ),
                    ],
                    returns="Process ID of spawned process",
                ),
                ToolFunction(
                    name="frida.attach",
                    description="Attach Frida to a running process",
                    parameters=[
                        ToolParameter(
                            name="target",
                            type="string",
                            description="Process name or PID",
                            required=True,
                        ),
                    ],
                    returns="Session information",
                ),
                ToolFunction(
                    name="frida.detach",
                    description="Detach Frida from current process",
                    parameters=[],
                    returns="Success status",
                ),
                ToolFunction(
                    name="frida.resume",
                    description="Resume a spawned process that was paused",
                    parameters=[],
                    returns="Success status",
                ),
                ToolFunction(
                    name="frida.enumerate_modules",
                    description="List all loaded modules in the process",
                    parameters=[],
                    returns="List of ModuleInfo objects",
                ),
                ToolFunction(
                    name="frida.enumerate_exports",
                    description="List exports of a module",
                    parameters=[
                        ToolParameter(
                            name="module_name",
                            type="string",
                            description="Name of the module",
                            required=True,
                        ),
                    ],
                    returns="List of export names and addresses",
                ),
                ToolFunction(
                    name="frida.enumerate_imports",
                    description="List imports of a module",
                    parameters=[
                        ToolParameter(
                            name="module_name",
                            type="string",
                            description="Name of the module",
                            required=True,
                        ),
                    ],
                    returns="List of import names and addresses",
                ),
                ToolFunction(
                    name="frida.hook_function",
                    description="Hook a function by name or address",
                    parameters=[
                        ToolParameter(
                            name="target",
                            type="string",
                            description="Function name (module!func) or hex address",
                            required=True,
                        ),
                        ToolParameter(
                            name="on_enter",
                            type="string",
                            description="JavaScript code to run on function entry",
                            required=False,
                        ),
                        ToolParameter(
                            name="on_leave",
                            type="string",
                            description="JavaScript code to run on function exit",
                            required=False,
                        ),
                    ],
                    returns="Hook ID",
                ),
                ToolFunction(
                    name="frida.remove_hook",
                    description="Remove a previously installed hook",
                    parameters=[
                        ToolParameter(
                            name="hook_id",
                            type="string",
                            description="ID of the hook to remove",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="frida.read_memory",
                    description="Read memory from the target process",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Memory address to read",
                            required=True,
                        ),
                        ToolParameter(
                            name="size",
                            type="integer",
                            description="Number of bytes to read",
                            required=True,
                        ),
                    ],
                    returns="Hex string of memory contents",
                ),
                ToolFunction(
                    name="frida.write_memory",
                    description="Write memory in the target process",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Memory address to write",
                            required=True,
                        ),
                        ToolParameter(
                            name="hex_data",
                            type="string",
                            description="Hex string of data to write",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="frida.scan_memory",
                    description="Scan process memory for a pattern",
                    parameters=[
                        ToolParameter(
                            name="pattern",
                            type="string",
                            description="Hex pattern with wildcards (e.g., '48 8B ?? ??')",
                            required=True,
                        ),
                        ToolParameter(
                            name="module_name",
                            type="string",
                            description="Optional module to limit search",
                            required=False,
                        ),
                    ],
                    returns="List of addresses where pattern found",
                ),
                ToolFunction(
                    name="frida.execute_script",
                    description="Execute custom Frida JavaScript code",
                    parameters=[
                        ToolParameter(
                            name="script",
                            type="string",
                            description="JavaScript code to execute",
                            required=True,
                        ),
                    ],
                    returns="Script execution result",
                ),
                ToolFunction(
                    name="frida.intercept_return",
                    description="Hook a function and modify its return value",
                    parameters=[
                        ToolParameter(
                            name="target",
                            type="string",
                            description="Function to hook",
                            required=True,
                        ),
                        ToolParameter(
                            name="return_value",
                            type="integer",
                            description="Value to return instead",
                            required=True,
                        ),
                    ],
                    returns="Hook ID",
                ),
                ToolFunction(
                    name="frida.call_function",
                    description="Call a function in the target process",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Function address",
                            required=True,
                        ),
                        ToolParameter(
                            name="args",
                            type="array",
                            description="Function arguments (integers)",
                            required=False,
                        ),
                    ],
                    returns="Function return value",
                ),
                ToolFunction(
                    name="frida.get_memory_ranges",
                    description="Get memory map of the process",
                    parameters=[
                        ToolParameter(
                            name="protection",
                            type="string",
                            description="Filter by protection (e.g., 'r-x')",
                            required=False,
                        ),
                    ],
                    returns="List of memory regions",
                ),
                ToolFunction(
                    name="frida.allocate_memory",
                    description="Allocate memory in the target process",
                    parameters=[
                        ToolParameter(
                            name="size",
                            type="integer",
                            description="Size in bytes",
                            required=True,
                        ),
                    ],
                    returns="Address of allocated memory",
                ),
            ],
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the Frida bridge.

        Args:
            tool_path: Not used for Frida (uses frida-python).
        """
        try:
            self._device = await asyncio.to_thread(frida.get_local_device)
            self._state = BridgeState(connected=True, tool_running=True)
            _logger.info("Frida bridge initialized")
        except Exception as e:
            raise ToolError(f"Failed to initialize Frida: {e}") from e

    async def shutdown(self) -> None:
        """Shutdown Frida and cleanup resources."""
        for script_id in list(self._scripts.keys()):
            try:
                await self._unload_script(script_id)
            except Exception as e:
                _logger.warning("Error unloading script %s: %s", script_id, e)

        if self._session is not None:
            try:
                await asyncio.to_thread(self._session.detach)
            except Exception as e:
                _logger.warning("Error detaching session: %s", e)
            self._session = None

        self._device = None
        self._pid = None
        self._hooks = {}
        await super().shutdown()
        _logger.info("Frida bridge shutdown")

    async def is_available(self) -> bool:
        """Check if Frida is available.

        Returns:
            True if Frida is installed and working.
        """
        try:
            await asyncio.to_thread(frida.get_local_device)
            return True
        except Exception:
            return False

    async def attach(self, pid: int) -> None:
        """Attach to a running process.

        Args:
            pid: Process ID to attach to.

        Raises:
            ToolError: If attachment fails.
        """
        if self._device is None:
            await self.initialize()

        try:
            self._session = await asyncio.to_thread(
                self._device.attach,  # type: ignore[union-attr]
                pid,
            )
            self._pid = pid
            self._state = BridgeState(
                connected=True,
                tool_running=True,
                process_attached=True,
                target_pid=pid,
            )
            _logger.info("Attached to process %d", pid)
        except frida.ProcessNotFoundError as e:
            raise ToolError(f"Process {pid} not found") from e
        except Exception as e:
            raise ToolError(f"Failed to attach to process {pid}: {e}") from e

    async def attach_by_name(self, name: str) -> None:
        """Attach to a process by name.

        Args:
            name: Process name to attach to.

        Raises:
            ToolError: If attachment fails.
        """
        if self._device is None:
            await self.initialize()

        try:
            self._session = await asyncio.to_thread(
                self._device.attach,  # type: ignore[union-attr]
                name,
            )
            self._pid = self._session.pid
            self._state = BridgeState(
                connected=True,
                tool_running=True,
                process_attached=True,
                target_pid=self._pid,
            )
            _logger.info("Attached to process '%s' (PID: %d)", name, self._pid)
        except frida.ProcessNotFoundError as e:
            raise ToolError(f"Process '{name}' not found") from e
        except Exception as e:
            raise ToolError(f"Failed to attach to process '{name}': {e}") from e

    async def spawn(
        self,
        path: Path,
        args: list[str] | None = None,
    ) -> int:
        """Spawn a new process with Frida instrumentation.

        Args:
            path: Path to executable.
            args: Command line arguments.

        Returns:
            PID of spawned process.

        Raises:
            ToolError: If spawn fails.
        """
        if self._device is None:
            await self.initialize()

        try:
            spawn_args: list[str] = [str(path)]
            if args:
                spawn_args.extend(args)

            pid = await asyncio.to_thread(
                self._device.spawn,  # type: ignore[union-attr]
                spawn_args,
            )
            self._session = await asyncio.to_thread(
                self._device.attach,  # type: ignore[union-attr]
                pid,
            )
            self._pid = pid
            self._state = BridgeState(
                connected=True,
                tool_running=True,
                process_attached=True,
                target_path=path,
                target_pid=pid,
            )
            _logger.info("Spawned process %s (PID: %d)", path.name, pid)
            return pid
        except Exception as e:
            raise ToolError(f"Failed to spawn {path}: {e}") from e

    async def resume(self) -> None:
        """Resume a spawned process.

        Raises:
            ToolError: If resume fails.
        """
        if self._device is None or self._pid is None:
            raise ToolError("No process to resume")

        try:
            await asyncio.to_thread(self._device.resume, self._pid)
            _logger.info("Resumed process %d", self._pid)
        except Exception as e:
            raise ToolError(f"Failed to resume process: {e}") from e

    async def detach(self) -> None:
        """Detach from the current process.

        Raises:
            ToolError: If detachment fails.
        """
        if self._session is None:
            _logger.warning("No session to detach")
            return

        try:
            for script_id in list(self._scripts.keys()):
                await self._unload_script(script_id)

            await asyncio.to_thread(self._session.detach)
            self._session = None
            self._pid = None
            self._hooks = {}
            self._state = BridgeState(connected=True, tool_running=True)
            _logger.info("Detached from process")
        except Exception as e:
            raise ToolError(f"Failed to detach: {e}") from e

    async def read_memory(self, address: int, size: int) -> bytes:
        """Read memory from the target process.

        Args:
            address: Memory address.
            size: Number of bytes to read.

        Returns:
            Memory contents.

        Raises:
            ToolError: If read fails.
        """
        if self._session is None:
            raise ToolError("Not attached to a process")

        script_code = f"""
        var data = Memory.readByteArray(ptr({address}), {size});
        send({{ type: 'memory', data: data }});
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(f"Memory read failed: {result['error']}")

        data = result.get("data")
        if isinstance(data, (list, bytes, bytearray)):
            return bytes(data)

        raise ToolError("Invalid memory read result")

    async def write_memory(self, address: int, data: bytes) -> None:
        """Write memory in the target process.

        Args:
            address: Memory address.
            data: Bytes to write.

        Raises:
            ToolError: If write fails.
        """
        if self._session is None:
            raise ToolError("Not attached to a process")

        hex_array = ", ".join(f"0x{b:02x}" for b in data)
        script_code = f"""
        var bytes = [{hex_array}];
        Memory.writeByteArray(ptr({address}), bytes);
        send({{ type: 'success' }});
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(f"Memory write failed: {result['error']}")

        _logger.debug("Wrote %d bytes to 0x%X", len(data), address)

    async def get_memory_regions(self) -> list[MemoryRegion]:
        """Get process memory map.

        Returns:
            List of memory regions.

        Raises:
            ToolError: If operation fails.
        """
        if self._session is None:
            raise ToolError("Not attached to a process")

        script_code = """
        var ranges = Process.enumerateRanges('---');
        var result = ranges.map(function(r) {
            return {
                base: r.base.toString(),
                size: r.size,
                protection: r.protection,
                file: r.file ? r.file.path : null
            };
        });
        send({ type: 'ranges', data: result });
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(f"Failed to get memory ranges: {result['error']}")

        regions: list[MemoryRegion] = []
        for r in result.get("data", []):
            base_str = r.get("base", "0")
            base = int(base_str, 16) if base_str.startswith("0x") else int(base_str)
            regions.append(
                MemoryRegion(
                    base_address=base,
                    size=r.get("size", 0),
                    protection=r.get("protection", ""),
                    state="MEM_COMMIT",
                    type="MEM_PRIVATE",
                    module_name=r.get("file"),
                )
            )

        return regions

    async def scan_memory(self, pattern: bytes) -> list[MemorySearchResult]:
        """Scan process memory for a pattern.

        Args:
            pattern: Byte pattern to search for.

        Returns:
            List of matches with context.

        Raises:
            ToolError: If scan fails.
        """
        if self._session is None:
            raise ToolError("Not attached to a process")

        hex_pattern = " ".join(f"{b:02x}" for b in pattern)

        script_code = f"""
        var ranges = Process.enumerateRanges('r--');
        var results = [];
        ranges.forEach(function(range) {{
            try {{
                var matches = Memory.scanSync(range.base, range.size, '{hex_pattern}');
                matches.forEach(function(m) {{
                    results.push({{
                        address: m.address.toString(),
                        size: m.size
                    }});
                }});
            }} catch (e) {{}}
        }});
        send({{ type: 'scan', data: results }});
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(f"Memory scan failed: {result['error']}")

        matches: list[MemorySearchResult] = []
        for m in result.get("data", []):
            addr_str = m.get("address", "0")
            addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
            matches.append(
                MemorySearchResult(
                    address=addr,
                    matched_bytes=hex_pattern,
                    context_before="",
                    context_after="",
                )
            )

        return matches

    async def enumerate_modules(self) -> list[ModuleInfo]:
        """List all loaded modules in the process.

        Returns:
            List of module information.

        Raises:
            ToolError: If operation fails.
        """
        if self._session is None:
            raise ToolError("Not attached to a process")

        script_code = """
        var modules = Process.enumerateModules();
        var result = modules.map(function(m) {
            return {
                name: m.name,
                path: m.path,
                base: m.base.toString(),
                size: m.size
            };
        });
        send({ type: 'modules', data: result });
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(f"Failed to enumerate modules: {result['error']}")

        modules: list[ModuleInfo] = []
        for m in result.get("data", []):
            base_str = m.get("base", "0")
            base = int(base_str, 16) if base_str.startswith("0x") else int(base_str)
            modules.append(
                ModuleInfo(
                    name=m.get("name", ""),
                    path=Path(m.get("path", "")),
                    base_address=base,
                    size=m.get("size", 0),
                    entry_point=0,
                )
            )

        return modules

    async def enumerate_exports(self, module_name: str) -> list[ExportInfo]:
        """List exports of a module.

        Args:
            module_name: Name of the module.

        Returns:
            List of export information.

        Raises:
            ToolError: If operation fails.
        """
        if self._session is None:
            raise ToolError("Not attached to a process")

        script_code = f"""
        var exports = Module.enumerateExports('{module_name}');
        var result = exports.map(function(e) {{
            return {{
                name: e.name,
                type: e.type,
                address: e.address.toString()
            }};
        }});
        send({{ type: 'exports', data: result }});
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(f"Failed to enumerate exports: {result['error']}")

        exports: list[ExportInfo] = []
        for idx, e in enumerate(result.get("data", [])):
            addr_str = e.get("address", "0")
            addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
            exports.append(
                ExportInfo(
                    name=e.get("name", ""),
                    ordinal=idx,
                    address=addr,
                )
            )

        return exports

    async def hook_function(
        self,
        target: str,
        on_enter: str | None = None,
        on_leave: str | None = None,
    ) -> HookInfo:
        """Hook a function by name or address.

        Args:
            target: Function name (module!func) or hex address.
            on_enter: JavaScript code for function entry.
            on_leave: JavaScript code for function exit.

        Returns:
            Hook information.

        Raises:
            ToolError: If hooking fails.
        """
        if self._session is None:
            raise ToolError("Not attached to a process")

        hook_id = str(uuid.uuid4())[:8]

        if target.startswith("0x"):
            addr_resolve = f"ptr({target})"
        elif "!" in target:
            module, func = target.split("!", 1)
            addr_resolve = f"Module.getExportByName('{module}', '{func}')"
        else:
            addr_resolve = f"Module.getExportByName(null, '{target}')"

        on_enter_code = on_enter or "console.log('[+] Called ' + this.context.pc);"
        on_leave_code = on_leave or ""

        script_code = f"""
        var target = {addr_resolve};
        Interceptor.attach(target, {{
            onEnter: function(args) {{
                {on_enter_code}
            }},
            onLeave: function(retval) {{
                {on_leave_code}
            }}
        }});
        send({{ type: 'hooked', address: target.toString() }});
        """

        script = await asyncio.to_thread(self._session.create_script, script_code)

        messages: list[dict[str, object]] = []

        def on_message(message: dict[str, object], data: bytes | None) -> None:
            messages.append(message)
            if self._message_handler:
                self._message_handler(message)

        script.on("message", on_message)
        await asyncio.to_thread(script.load)

        await asyncio.sleep(0.1)

        address: int | None = None
        for msg in messages:
            if msg.get("type") == "send":
                payload = msg.get("payload", {})
                if isinstance(payload, dict) and payload.get("type") == "hooked":
                    addr_str = payload.get("address", "0")
                    if isinstance(addr_str, str):
                        address = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)

        self._scripts[hook_id] = script

        hook_info = HookInfo(
            id=hook_id,
            target=target,
            address=address,
            script_id=hook_id,
            active=True,
        )
        self._hooks[hook_id] = hook_info

        _logger.info("Installed hook %s on %s", hook_id, target)
        return hook_info

    async def remove_hook(self, hook_id: str) -> bool:
        """Remove a previously installed hook.

        Args:
            hook_id: ID of the hook to remove.

        Returns:
            True if removed successfully.

        Raises:
            ToolError: If operation fails.
        """
        if hook_id not in self._scripts:
            _logger.warning("Hook %s not found", hook_id)
            return False

        await self._unload_script(hook_id)
        del self._hooks[hook_id]

        _logger.info("Removed hook %s", hook_id)
        return True

    async def get_hooks(self) -> list[HookInfo]:
        """Get all active hooks.

        Returns:
            List of hook information.
        """
        return list(self._hooks.values())

    async def execute_script(self, script: str) -> str:
        """Execute custom Frida JavaScript code.

        Args:
            script: JavaScript code to execute.

        Returns:
            Script execution result.

        Raises:
            ToolError: If execution fails.
        """
        if self._session is None:
            raise ToolError("Not attached to a process")

        result = await self._execute_script_and_wait(script)

        if "error" in result:
            raise ToolError(f"Script execution failed: {result['error']}")

        return str(result)

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
        on_leave = f"retval.replace({return_value});"
        return await self.hook_function(
            target=target,
            on_leave=on_leave,
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
        if self._session is None:
            raise ToolError("Not attached to a process")

        args_list = args or []
        args_code = ", ".join(f"ptr({a})" for a in args_list)

        script_code = f"""
        var func = new NativeFunction(ptr({address}), 'pointer', [{', '.join(["'pointer'"] * len(args_list))}]);
        var result = func({args_code});
        send({{ type: 'call_result', value: result.toInt32() }});
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(f"Function call failed: {result['error']}")

        return int(result.get("value", 0))

    async def _execute_script_and_wait(
        self,
        script_code: str,
        timeout: float = 5.0,
    ) -> dict[str, object]:
        """Execute a script and wait for result.

        Args:
            script_code: JavaScript code to execute.
            timeout: Timeout in seconds.

        Returns:
            Script result as dictionary.
        """
        if self._session is None:
            raise ToolError("Not attached to a process")

        result: dict[str, object] = {}
        event = asyncio.Event()

        def on_message(message: dict[str, object], data: bytes | None) -> None:
            if message.get("type") == "send":
                payload = message.get("payload", {})
                if isinstance(payload, dict):
                    result.update(payload)
                    if data:
                        result["data"] = list(data)
            elif message.get("type") == "error":
                result["error"] = message.get("description", "Unknown error")
            event.set()

        script = await asyncio.to_thread(self._session.create_script, script_code)
        script.on("message", on_message)
        await asyncio.to_thread(script.load)

        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            result["error"] = "Script execution timed out"

        await asyncio.to_thread(script.unload)

        return result

    async def _unload_script(self, script_id: str) -> None:
        """Unload a script.

        Args:
            script_id: Script ID to unload.
        """
        if script_id in self._scripts:
            script = self._scripts[script_id]
            try:
                await asyncio.to_thread(script.unload)
            except Exception as e:
                _logger.warning("Error unloading script %s: %s", script_id, e)
            del self._scripts[script_id]

    def set_message_handler(
        self,
        handler: Callable[[dict[str, object]], None],
    ) -> None:
        """Set handler for script messages.

        Args:
            handler: Callback function for messages.
        """
        self._message_handler = handler
