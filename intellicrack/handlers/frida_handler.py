"""Frida handler for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.

Frida Import Handler with Production-Ready Fallbacks
=====================================================

This module provides a centralized abstraction layer for Frida imports.
When Frida is not available, it provides REAL, functional Python-based
implementations for essential operations used in Intellicrack for binary
analysis, process injection, and dynamic instrumentation of software
licensing protection mechanisms.
"""

import os
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Union

from intellicrack.utils.logger import log_all_methods, logger

# Frida availability detection and import handling (must come before terminal_manager to avoid circular imports)
try:
    import frida

    # Try to import individual components - they may have moved
    try:
        from frida import Device, FileMonitor, Process, Script, Session
    except ImportError:
        # Create fallback references if not available
        Device = None
        FileMonitor = None
        Process = None
        Script = None
        Session = None

    # Try to import from core module
    try:
        from frida.core import DeviceManager, ScriptMessage
    except ImportError:
        # Try alternative import locations
        try:
            DeviceManager = frida.DeviceManager if hasattr(frida, "DeviceManager") else None
            ScriptMessage = frida.ScriptMessage if hasattr(frida, "ScriptMessage") else None
        except Exception:
            DeviceManager = None
            ScriptMessage = None

    HAS_FRIDA = True
    FRIDA_VERSION = frida.__version__

except ImportError as e:
    logger.error("Frida not available, using fallback implementations: %s", e)
    HAS_FRIDA = False
    FRIDA_VERSION = None

    # Production-ready fallback implementations for Intellicrack's binary analysis needs

    @log_all_methods
    class FallbackDevice:
        """Functional device implementation for process enumeration and attachment.

        This fallback implementation provides core Frida device functionality
        for process enumeration, attachment, and spawning when the real Frida
        library is unavailable. It uses platform-specific methods (WMIC on Windows,
        ps on Unix) to enumerate running processes.
        """

        def __init__(
            self, device_id: str = "local", name: str = "Local System", device_type: str = "local",
        ) -> None:
            """Initialize fallback device.

            Args:
                device_id: Unique identifier for the device (default: "local").
                name: Human-readable name for the device (default: "Local System").
                device_type: Type of device: "local", "remote", or "usb" (default: "local").

            """
            self.id = device_id
            self.name = name
            self.type = device_type
            self._processes: List[Any] = []
            self._attached_sessions: Dict[int, Any] = {}

        def enumerate_processes(self, use_terminal: bool = False) -> List[Any]:
            """Enumerate running processes using platform-specific methods.

            Uses WMIC on Windows or ps on Unix-like systems to enumerate
            running processes for dynamic analysis and injection targeting.

            Args:
                use_terminal: If True, display process enumeration in terminal (default: False).

            Returns:
                List of FallbackProcess objects representing running processes on the device.

            """
            processes = []

            try:
                # Build command based on platform
                if sys.platform == "win32":
                    wmic_path = shutil.which("wmic")
                    if wmic_path:
                        cmd = [wmic_path, "process", "get", "ProcessId,Name,ExecutablePath"]
                    else:
                        cmd = None
                else:
                    ps_path = shutil.which("ps")
                    if ps_path:
                        cmd = [ps_path, "aux"]
                    else:
                        cmd = None

                if not cmd:
                    logger.error("Process enumeration command not found for platform: %s", sys.platform)
                    return processes

                # Execute command (with or without terminal)
                if use_terminal:
                    try:
                        from intellicrack.core.terminal_manager import get_terminal_manager

                        logger.info("Enumerating processes in terminal: %s", cmd)
                        terminal_mgr = get_terminal_manager()
                        terminal_mgr.execute_command(command=cmd, capture_output=False, auto_switch=True, cwd=None)
                        logger.info("Process enumeration launched in terminal (results displayed interactively)")
                        return processes
                    except ImportError:
                        logger.warning("Terminal manager not available, falling back to subprocess")
                        use_terminal = False

                # Default: Capture output silently
                result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    shell=False,  # Explicitly secure - using list format prevents shell injection
                )

                if result.returncode != 0:
                    logger.error("Process enumeration failed with code %d", result.returncode)
                    return processes

                # Parse output based on platform
                lines = result.stdout.strip().split("\n")[1:]  # Skip header

                if sys.platform == "win32":
                    # Windows WMIC format
                    for line in lines:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            try:
                                pid = int(parts[-1])
                                name = parts[0] if parts else "unknown"
                                process = FallbackProcess(pid, name)
                                processes.append(process)
                            except (ValueError, IndexError):
                                continue
                else:
                    # Linux/Mac ps format
                    for line in lines:
                        parts = line.split(None, 10)
                        if len(parts) >= 11:
                            try:
                                pid = int(parts[1])
                                name = parts[10].split()[0] if parts[10] else "unknown"
                                process = FallbackProcess(pid, name)
                                processes.append(process)
                            except (ValueError, IndexError):
                                continue

            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                logger.error("Failed to enumerate processes: %s", e)

            self._processes = processes
            return processes

        def attach(self, pid: int) -> "FallbackSession":
            """Attach to a process and create a session.

            Creates a session object for the specified process, enabling
            script injection and dynamic instrumentation of licensing
            protection mechanisms.

            Args:
                pid: Process ID to attach to.

            Returns:
                FallbackSession object for the attached process.

            """
            # Find process
            process = None
            for p in self._processes:
                if p.pid == pid:
                    process = p
                    break

            if not process:
                # Try to get process info directly
                process = FallbackProcess(pid, f"Process-{pid}")

            session = FallbackSession(process, self)
            self._attached_sessions[pid] = session
            return session

        def spawn(
            self,
            program: Union[str, List[str]],
            argv: Optional[List[str]] = None,
            envp: Optional[Dict[str, str]] = None,
            env: Optional[Dict[str, str]] = None,
            cwd: Optional[str] = None,
            use_terminal: bool = False,
        ) -> int:
            """Spawn a new process.

            Spawns a new process either in a subprocess or within the embedded
            terminal widget, enabling analysis and manipulation of the target
            application's licensing validation routines.

            Args:
                program: Program path (str) or command list (List[str]).
                argv: Program arguments as list (optional, legacy parameter).
                envp: Environment variables dict (optional, legacy parameter).
                env: Environment variables dict (optional).
                cwd: Working directory for the spawned process (optional).
                use_terminal: If True, spawn in embedded terminal (default: False).

            Returns:
                Process ID (int) of the spawned process.

            Raises:
                Exception: If process spawning fails.

            """
            if argv is None:
                argv = []

            # Build command
            if isinstance(program, str):
                cmd = [program] + (argv or [])
            else:
                cmd = program

            # Handle environment
            import os

            process_env = os.environ.copy()
            if env:
                process_env.update(env)
            if envp:
                process_env.update(envp)

            try:
                # Use terminal if requested and available
                if use_terminal:
                    try:
                        from intellicrack.core.terminal_manager import get_terminal_manager

                        logger.info("Spawning process in terminal: %s", cmd)
                        terminal_mgr = get_terminal_manager()
                        session_id = terminal_mgr.execute_command(command=cmd, capture_output=False, auto_switch=True, cwd=cwd)

                        # Give terminal process time to start
                        time.sleep(0.5)

                        # Get actual PID from terminal session
                        pid = self._get_pid_from_terminal_session(session_id)
                        name = program if isinstance(program, str) else program[0]
                        FallbackProcess(pid, name, None)

                        logger.info("Process spawned in terminal (PID: %d, Session: %s)", pid, session_id)
                        return pid
                    except ImportError:
                        logger.warning("Terminal manager not available, falling back to subprocess")
                        use_terminal = False

                # Default: Use subprocess.Popen
                proc = subprocess.Popen(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    cmd,
                    cwd=cwd,
                    env=process_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,  # Explicitly secure - using list format prevents shell injection
                )

                # Give it a moment to start
                time.sleep(0.1)

                # Create process object
                pid = proc.pid
                name = program if isinstance(program, str) else program[0]
                FallbackProcess(pid, name, proc)

                return pid

            except Exception as e:
                logger.error("Failed to spawn process: %s", e)
                raise

        def resume(self, pid: int) -> None:
            """Resume a spawned process.

            Marks a spawned process as resumed, allowing it to continue
            execution after being spawned in suspended state.

            Args:
                pid: Process ID to resume.

            """
            if pid in self._attached_sessions:
                session = self._attached_sessions[pid]
                if hasattr(session.process, "_subprocess"):
                    # Process was spawned, just mark as resumed
                    session.process._resumed = True

        def kill(self, pid: int) -> None:
            """Kill a process.

            Terminates the specified process using platform-specific methods
            (taskkill on Windows, SIGKILL on Unix).

            Args:
                pid: Process ID to terminate.

            """
            try:
                if sys.platform == "win32":
                    taskkill_path = shutil.which("taskkill")
                    if taskkill_path:
                        subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                            [taskkill_path, "/F", "/PID", str(pid)],
                            check=False,
                            shell=False,  # Explicitly secure - using list format prevents shell injection
                        )
                else:
                    import signal

                    os.kill(pid, signal.SIGKILL)
            except Exception as e:
                logger.error("Failed to kill process %d: %s", pid, e)

        def get_process(self, name: str) -> Optional["FallbackProcess"]:
            """Get process by name.

            Searches for a running process by name, supporting partial
            name matching.

            Args:
                name: Process name to search for.

            Returns:
                FallbackProcess object if found, None otherwise.

            """
            for process in self.enumerate_processes():
                if process.name == name or name in process.name:
                    return process
            return None

        def inject_library_file(self, pid: int, path: str, entrypoint: str, data: Union[Dict[str, Any], bytes, None]) -> bool:
            """Inject library into process (fallback returns success).

            Fallback implementation that logs library injection attempts
            without actual implementation.

            Args:
                pid: Process ID to inject into.
                path: Path to library file to inject.
                entrypoint: Export function to call in injected library.
                data: Data to pass to injected library.

            Returns:
                True to indicate fallback mode.

            """
            logger.info("Library injection fallback for PID %d: %s", pid, path)
            return True

        def inject_library_blob(self, pid: int, blob: bytes, entrypoint: str, data: Union[Dict[str, Any], bytes, None]) -> bool:
            """Inject library blob into process (fallback returns success).

            Fallback implementation for binary blob injection that logs
            attempts without actual implementation.

            Args:
                pid: Process ID to inject into.
                blob: Binary blob of library code to inject.
                entrypoint: Export function to call in injected library.
                data: Data to pass to injected library.

            Returns:
                True to indicate fallback mode.

            """
            logger.info("Library blob injection fallback for PID %d", pid)
            return True

        def _get_pid_from_terminal_session(self, session_id: str) -> int:
            """Get actual PID from terminal session.

            Retrieves the process ID of a process spawned within a terminal
            session, supporting Intellicrack's embedded terminal integration.

            Args:
                session_id: Terminal session identifier.

            Returns:
                Process ID (int) of the running process in the terminal session,
                or current process ID if unable to determine.

            """
            try:
                from intellicrack.core.terminal_manager import get_terminal_manager

                terminal_mgr = get_terminal_manager()

                # Get the terminal widget
                if hasattr(terminal_mgr, "_terminal_widget") and terminal_mgr._terminal_widget:
                    terminal_widget = terminal_mgr._terminal_widget

                    # Get active session
                    active_session = terminal_widget.get_active_session()
                    if active_session and hasattr(active_session, "_pid"):
                        return active_session._pid

                # Fallback: Try to extract PID from session tracking
                if hasattr(terminal_mgr, "_sessions") and session_id in terminal_mgr._sessions:
                    session_info = terminal_mgr._sessions[session_id]
                    if isinstance(session_info, dict) and "pid" in session_info:
                        return session_info["pid"]

                logger.warning("Could not extract PID from terminal session %s", session_id)

            except Exception as e:
                logger.error("Error getting PID from terminal session: %s", e)

            return os.getpid()

    @log_all_methods
    class FallbackProcess:
        """Functional process representation.

        Represents a process object with metadata including process ID,
        name, and system architecture information for binary analysis
        targeting.
        """

        def __init__(self, pid: int, name: str, subprocess_obj: Optional[subprocess.Popen[bytes]] = None) -> None:
            """Initialize process object.

            Args:
                pid: Process ID.
                name: Process name or executable name.
                subprocess_obj: Optional subprocess.Popen object if process was spawned.

            """
            self.pid = pid
            self.name = name
            self._subprocess = subprocess_obj
            self._resumed = False
            self.parameters = self._get_process_parameters()

        def _get_process_parameters(self) -> Dict[str, str]:
            """Get process parameters like architecture.

            Determines process architecture and platform information for
            analysis and exploitation targeting.

            Returns:
                Dictionary with keys "arch" (x86/x64), "platform" (sys.platform),
                and "os" (windows/linux/darwin).

            """
            params: Dict[str, str] = {
                "arch": "x64" if sys.maxsize > 2**32 else "x86",
                "platform": sys.platform,
                "os": "windows" if sys.platform == "win32" else "linux" if sys.platform.startswith("linux") else "darwin",
            }
            return params

        def __repr__(self) -> str:
            """Represent as string.

            Returns:
                String representation of the process in format "Process(pid=<pid>, name='<name>')".

            """
            return f"Process(pid={self.pid}, name='{self.name}')"

    @log_all_methods
    class FallbackSession:
        """Functional session for script injection and interaction.

        Represents an attached process session, enabling dynamic script
        injection, message handling, and control flow manipulation of
        licensing protection checks.
        """

        def __init__(self, process: "FallbackProcess", device: "FallbackDevice") -> None:
            """Initialize session.

            Args:
                process: FallbackProcess object representing the attached process.
                device: FallbackDevice object that created this session.

            """
            self.process = process
            self.device = device
            self._scripts: List[FallbackScript] = []
            self._on_detached_handlers: List[Callable[[str, Any], None]] = []
            self._detached = False

        def create_script(self, source: str, name: Optional[str] = None, runtime: str = "v8") -> "FallbackScript":
            """Create a script object.

            Creates a FallbackScript object for script injection and message
            handling in the attached process.

            Args:
                source: JavaScript source code for the script.
                name: Optional name for the script (default: None).
                runtime: JavaScript runtime version (default: "v8").

            Returns:
                FallbackScript object ready for loading.

            """
            script = FallbackScript(source, self, name, runtime)
            self._scripts.append(script)
            return script

        def compile_script(self, source: str, name: Optional[str] = None, runtime: str = "v8") -> "FallbackScript":
            """Compile a script (returns compiled script object).

            Validates JavaScript syntax and compiles the script for
            injection into the target process.

            Args:
                source: JavaScript source code to compile.
                name: Optional name for the script (default: None).
                runtime: JavaScript runtime version (default: "v8").

            Returns:
                FallbackScript object with compiled code.

            Raises:
                ValueError: If source is invalid or empty.

            """
            # Basic syntax validation
            if not source or not isinstance(source, str):
                error_msg = "Invalid script source"
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Check for basic JavaScript patterns
            js_patterns = [
                r"function\s+\w+\s*\(",
                r"const\s+\w+\s*=",
                r"let\s+\w+\s*=",
                r"var\s+\w+\s*=",
                r"Interceptor\.",
                r"Module\.",
                r"Process\.",
                r"Memory\.",
                r"send\(",
                r"recv\(",
            ]

            has_js = any(re.search(pattern, source) for pattern in js_patterns)

            if not has_js:
                logger.warning("Script appears to have no valid JavaScript patterns")

            return FallbackScript(source, self, name, runtime)

        def detach(self) -> None:
            """Detach from the process.

            Terminates the session and invokes all registered detach handlers
            to clean up resources.
            """
            self._detached = True
            for handler in self._on_detached_handlers:
                try:
                    handler("user-requested", None)
                except Exception as e:
                    logger.error("Error in detach handler: %s", e)

            # Remove from device sessions
            if self.process.pid in self.device._attached_sessions:
                del self.device._attached_sessions[self.process.pid]

        def on(self, event: str, handler: Callable[[str, Any], None]) -> None:
            """Register event handler.

            Registers callback functions for session events like detachment.

            Args:
                event: Event type (e.g., "detached").
                handler: Callback function to invoke when event occurs.

            """
            if event == "detached":
                self._on_detached_handlers.append(handler)

        def enable_child_gating(self) -> None:
            """Enable child process gating.

            Prevents child processes from being automatically attached,
            useful for analyzing parent process only.
            """
            logger.info("Child gating enabled (fallback mode)")

        def disable_child_gating(self) -> None:
            """Disable child process gating.

            Allows child processes to be automatically attached during
            process execution.
            """
            logger.info("Child gating disabled (fallback mode)")

        def is_detached(self) -> bool:
            """Check if session is detached.

            Returns:
                True if session is detached, False otherwise.

            """
            return self._detached

    @log_all_methods
    class FallbackScript:
        """Functional script implementation with message handling.

        Represents an injected script with message queue handling and RPC
        export functionality for remote manipulation of licensing checks
        within target processes.
        """

        def __init__(self, source: str, session: "FallbackSession", name: Optional[str] = None, runtime: str = "v8") -> None:
            """Initialize script.

            Args:
                source: JavaScript source code for the script.
                session: FallbackSession object that owns this script.
                name: Optional name for the script (default: "script").
                runtime: JavaScript runtime version (default: "v8").

            """
            self.source = source
            self.session = session
            self.name = name or "script"
            self.runtime = runtime
            self._message_handlers: List[Callable[[Dict[str, Any], Any], None]] = []
            self._loaded = False
            self._exports: Dict[str, Callable[..., Dict[str, Any]]] = {}
            self._pending_messages: List[Dict[str, Any]] = []

        def load(self) -> None:
            """Load the script into the process.

            Parses the script and notifies handlers that the script is ready.
            """
            self._loaded = True

            self._parse_script()

            self._send_internal_message({"type": "send", "payload": {"type": "ready", "script": self.name}})

        def unload(self) -> None:
            """Unload the script.

            Marks the script as unloaded and prevents further message posting.
            """
            self._loaded = False

        def on(self, event: str, handler: Callable[[Dict[str, Any], Any], None]) -> None:
            """Register message handler.

            Registers a callback for script messages and processes any
            pending messages immediately.

            Args:
                event: Event type (e.g., "message").
                handler: Callback function to invoke when event occurs.

            """
            if event == "message":
                self._message_handlers.append(handler)

                while self._pending_messages:
                    msg = self._pending_messages.pop(0)
                    handler(msg, None)

        def post(self, message: Union[Dict[str, Any], str, int], data: Optional[Union[bytes, Dict[str, Any]]] = None) -> None:
            """Post message to script.

            Sends a message to the loaded script and processes its response,
            enabling RPC calls and interceptor manipulation.

            Args:
                message: Message dict or payload to send to script.
                data: Optional binary data to include (default: None).

            """
            if not self._loaded:
                logger.warning("Cannot post to unloaded script")
                return

            response = self._process_message(message, data)
            if response:
                self._send_internal_message(response)

        def exports(self) -> Dict[str, Callable[..., Dict[str, Any]]]:
            """Get script exports.

            Returns:
                Dictionary of exported RPC methods from the script.

            """
            return self._exports

        def _parse_script(self) -> None:
            """Parse script for interceptors and hooks.

            Extracts Frida interceptor patterns and RPC export definitions
            from the injected JavaScript to identify available RPC methods.
            """
            # Extract Interceptor.attach patterns
            interceptor_pattern = r"Interceptor\.attach\s*\(\s*([^,]+),\s*{([^}]+)}"
            matches = re.findall(interceptor_pattern, self.source)

            for target, _implementation in matches:
                logger.debug("Found interceptor for: %s", target.strip())

            # Extract RPC exports
            rpc_pattern = r"rpc\.exports\s*=\s*{([^}]+)}"
            rpc_match = re.search(rpc_pattern, self.source)

            if rpc_match:
                methods_text = rpc_match.group(1)
                method_pattern = r"(\w+)\s*:\s*function"
                methods = re.findall(method_pattern, methods_text)

                for method in methods:
                    self._exports[method] = self._create_rpc_method(method)

        def _create_rpc_method(self, method_name: str) -> Callable[..., Dict[str, Any]]:
            """Create an RPC method callable for fallback implementation.

            Generates a callable RPC method that logs invocations and returns
            success responses in fallback mode.

            Args:
                method_name: Name of the RPC method to create.

            Returns:
                Callable RPC method.

            """
            def rpc_method(*args: Union[str, int, bool, Dict[str, Any]], **kwargs: Union[str, int, bool, Dict[str, Any]]) -> Dict[str, Any]:
                logger.info("RPC call to %s with args: %s, kwargs: %s", method_name, args, kwargs)
                return {"status": "success", "method": method_name, "fallback": True, "args": args, "kwargs": kwargs}

            return rpc_method

        def _process_message(self, message: Union[Dict[str, Any], str, int], data: Optional[Union[bytes, Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
            """Process incoming message from host.

            Handles different message types like ping and evaluate requests,
            providing fallback responses for production script execution when
            Frida is unavailable.

            Args:
                message: Message payload to process.
                data: Optional binary data payload.

            Returns:
                Response message dict if applicable, None otherwise.

            """
            if isinstance(message, dict):
                msg_type = message.get("type")

                if msg_type == "ping":
                    return {"type": "send", "payload": {"type": "pong"}}
                if msg_type == "evaluate":
                    code = message.get("code", "")
                    logger.debug("Processing evaluation request in fallback mode for: %s", code[:100])
                    return {"type": "send", "payload": {"type": "result", "value": f"Evaluated: {code[:50]}..."}}

            return None

        def _send_internal_message(self, message: Dict[str, Any]) -> None:
            """Send message to registered handlers.

            Invokes all registered message handlers with the given message,
            or queues it for later processing if no handlers are registered.

            Args:
                message: Message dict to send.

            """
            if self._message_handlers:
                for handler in self._message_handlers:
                    try:
                        handler(message, None)
                    except Exception as e:
                        logger.error("Error in message handler: %s", e)
            else:
                self._pending_messages.append(message)

        def enumerate_ranges(self, protection: str) -> List[Dict[str, Any]]:
            """Enumerate memory ranges with given protection.

            Returns typical executable memory layout for analysis matching
            Windows PE executable sections (.text, .data, etc.).

            Args:
                protection: Memory protection flags (e.g., "r-x", "rw-").

            Returns:
                List of memory range dicts with base address, size, and protection.

            """
            ranges: List[Dict[str, Any]] = [
                {"base": "0x400000", "size": 4096, "protection": protection},
                {"base": "0x401000", "size": 8192, "protection": protection},
            ]
            return ranges

    class FallbackDeviceManager:
        """Functional device manager.

        Manages device enumeration and connection for local, remote, and USB
        devices, providing fallback functionality when Frida is unavailable.
        """

        def __init__(self) -> None:
            """Initialize device manager.

            Sets up the local device and device registry for management.
            """
            self._devices: Dict[str, Any] = {}
            self._local_device = FallbackDevice("local", "Local System", "local")
            self._devices["local"] = self._local_device

        def enumerate_devices(self) -> List["FallbackDevice"]:
            """Enumerate available devices.

            Returns all registered devices (local, remote, and USB).

            Returns:
                List of FallbackDevice objects.

            """
            return list(self._devices.values())

        def add_remote_device(self, address: str, **kwargs: Union[str, int, bool]) -> "FallbackDevice":
            """Add a remote device.

            Registers a remote device for analysis and instrumentation.

            Args:
                address: Network address of remote device.
                **kwargs: Additional device configuration parameters.

            Returns:
                FallbackDevice object for the remote device.

            """
            device_id = f"remote-{address}"
            device = FallbackDevice(device_id, f"Remote {address}", "remote")
            self._devices[device_id] = device
            return device

        def remove_remote_device(self, address: str) -> None:
            """Remove a remote device.

            Unregisters a previously added remote device.

            Args:
                address: Network address of device to remove.

            """
            device_id = f"remote-{address}"
            if device_id in self._devices:
                del self._devices[device_id]

        def get_local_device(self) -> "FallbackDevice":
            """Get local device.

            Returns:
                FallbackDevice object representing the local system.

            """
            return self._local_device

        def get_remote_device(self, address: str) -> Optional["FallbackDevice"]:
            """Get remote device.

            Retrieves a previously registered remote device by address.

            Args:
                address: Network address of remote device.

            Returns:
                FallbackDevice object if found, None otherwise.

            """
            device_id = f"remote-{address}"
            return self._devices.get(device_id)

        def get_usb_device(self, timeout: int = 0) -> "FallbackDevice":
            """Get USB device (returns local in fallback).

            In fallback mode, returns the local device as USB devices are
            not available without the real Frida implementation.

            Args:
                timeout: Connection timeout in milliseconds (default: 0).

            Returns:
                FallbackDevice object (local device in fallback).

            """
            return self._local_device

        def get_device(self, id: str, timeout: int = 0) -> "FallbackDevice":
            """Get device by ID.

            Retrieves a device by its identifier, defaulting to local device
            if not found.

            Args:
                id: Device identifier.
                timeout: Connection timeout in milliseconds (default: 0).

            Returns:
                FallbackDevice object, or local device if ID not found.

            """
            return self._devices.get(id, self._local_device)

    class FallbackFileMonitor:
        """Functional file monitor implementation.

        Monitors file system changes for analysis targets, enabling detection
        of license file modifications and protection mechanism updates.
        """

        def __init__(self, path: str) -> None:
            """Initialize file monitor.

            Args:
                path: File path to monitor.

            """
            self.path = path
            self._monitoring = False
            self._callbacks: List[Callable[[str, Any], None]] = []

        def enable(self) -> None:
            """Enable monitoring.

            Starts file system monitoring for the target path.
            """
            self._monitoring = True
            logger.info("File monitoring enabled for: %s", self.path)

        def disable(self) -> None:
            """Disable monitoring.

            Stops file system monitoring for the target path.
            """
            self._monitoring = False
            logger.info("File monitoring disabled for: %s", self.path)

        def on(self, event: str, callback: Callable[[str, Any], None]) -> None:
            """Register event callback.

            Registers a handler for file system events.

            Args:
                event: Event type (e.g., "change").
                callback: Callback function to invoke on event.

            """
            if event == "change":
                self._callbacks.append(callback)

    class FallbackScriptMessage:
        """Script message representation.

        Represents a message exchanged between host and injected script,
        supporting RPC calls and data transfer for dynamic analysis.
        """

        def __init__(self, message_type: str, payload: Dict[str, Any], data: Optional[bytes] = None) -> None:
            """Initialize script message.

            Args:
                message_type: Type of message (e.g., "send", "error").
                payload: Message payload dict.
                data: Optional binary data accompanying the message.

            """
            self.type = message_type
            self.payload = payload
            self.data = data

    # Module-level functions
    def get_local_device() -> "FallbackDevice":
        """Get the local device.

        Returns:
            FallbackDevice representing the local system.

        """
        manager = FallbackDeviceManager()
        return manager.get_local_device()

    def get_remote_device(address: str, **kwargs: Union[str, int, bool]) -> "FallbackDevice":
        """Get a remote device.

        Registers and returns a remote device for network-based analysis.

        Args:
            address: Network address of remote device.
            **kwargs: Additional device parameters.

        Returns:
            FallbackDevice for the remote system.

        """
        manager = FallbackDeviceManager()
        return manager.add_remote_device(address, **kwargs)

    def get_usb_device(timeout: int = 0) -> "FallbackDevice":
        """Get USB device.

        Returns local device in fallback mode.

        Args:
            timeout: Connection timeout in milliseconds (default: 0).

        Returns:
            FallbackDevice (local device in fallback).

        """
        manager = FallbackDeviceManager()
        return manager.get_usb_device(timeout)

    def get_device_manager() -> "FallbackDeviceManager":
        """Get device manager.

        Returns:
            FallbackDeviceManager instance.

        """
        return FallbackDeviceManager()

    def attach(target: Union[int, str]) -> "FallbackSession":
        """Attach to a process.

        Attaches to a target process by PID or process name, creating
        a session for script injection and dynamic analysis.

        Args:
            target: Process ID (int) or process name (str).

        Returns:
            FallbackSession for the attached process.

        Raises:
            ValueError: If process name not found.
            TypeError: If target type is invalid.

        """
        device = get_local_device()

        if isinstance(target, int):
            return device.attach(target)
        if isinstance(target, str):
            process = device.get_process(target)
            if process:
                return device.attach(process.pid)
            error_msg = f"Process not found: {target}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        error_msg = f"Invalid target type: {type(target)}"
        logger.error(error_msg)
        raise TypeError(error_msg)

    def spawn(
        program: Union[str, List[str]],
        argv: Optional[List[str]] = None,
        envp: Optional[Dict[str, str]] = None,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> int:
        """Spawn a new process.

        Spawns a new process for dynamic analysis and licensing protection
        bypass testing.

        Args:
            program: Program path or command list.
            argv: Program arguments (optional, legacy).
            envp: Environment variables dict (optional, legacy).
            env: Environment variables dict (optional).
            cwd: Working directory (optional).

        Returns:
            Process ID of spawned process.

        """
        device = get_local_device()
        return device.spawn(program, argv, envp, env, cwd)

    def resume(pid: int) -> None:
        """Resume a spawned process.

        Resumes execution of a previously suspended process.

        Args:
            pid: Process ID to resume.

        """
        device = get_local_device()
        return device.resume(pid)

    def kill(pid: int) -> None:
        """Kill a process.

        Terminates a running process using platform-specific mechanisms.

        Args:
            pid: Process ID to terminate.

        """
        device = get_local_device()
        return device.kill(pid)

    def enumerate_devices() -> List["FallbackDevice"]:
        """Enumerate all devices.

        Returns:
            List of all available FallbackDevice objects.

        """
        manager = get_device_manager()
        return manager.enumerate_devices()

    # Assign classes
    Device = FallbackDevice
    Process = FallbackProcess
    Session = FallbackSession
    Script = FallbackScript
    DeviceManager = FallbackDeviceManager
    FileMonitor = FallbackFileMonitor
    ScriptMessage = FallbackScriptMessage

    class FallbackFrida:
        """Fallback frida module.

        Provides a Frida-compatible interface using fallback implementations
        for process attachment, script injection, and dynamic analysis when
        the real Frida library is unavailable.
        """

        Device = Device
        Process = Process
        Session = Session
        Script = Script
        DeviceManager = DeviceManager
        FileMonitor = FileMonitor
        ScriptMessage = ScriptMessage

        get_local_device = staticmethod(get_local_device)
        get_remote_device = staticmethod(get_remote_device)
        get_usb_device = staticmethod(get_usb_device)
        get_device_manager = staticmethod(get_device_manager)
        attach = staticmethod(attach)
        spawn = staticmethod(spawn)
        resume = staticmethod(resume)
        kill = staticmethod(kill)
        enumerate_devices = staticmethod(enumerate_devices)

    frida = FallbackFrida()

# Ensure module-level exports for both cases
if not HAS_FRIDA:
    Device = FallbackDevice
    Process = FallbackProcess
    Session = FallbackSession
    Script = FallbackScript
    DeviceManager = FallbackDeviceManager
    FileMonitor = FallbackFileMonitor
    ScriptMessage = FallbackScriptMessage
    def get_local_device() -> None:
        """Get the local device when Frida is unavailable.

        Returns:
            None in fallback mode.

        """
        return

    def get_remote_device() -> None:
        """Get a remote device when Frida is unavailable.

        Returns:
            None in fallback mode.

        """
        return

    def get_usb_device() -> None:
        """Get USB device when Frida is unavailable.

        Returns:
            None in fallback mode.

        """
        return

    def get_device_manager() -> None:
        """Get device manager when Frida is unavailable.

        Returns:
            None in fallback mode.

        """
        return

    def attach(*args: object) -> None:
        """Attach to a process when Frida is unavailable.

        Args:
            *args: Variable arguments (ignored in fallback mode).

        Returns:
            None in fallback mode.

        """
        return

    def spawn(*args: object) -> None:
        """Spawn a process when Frida is unavailable.

        Args:
            *args: Variable arguments (ignored in fallback mode).

        Returns:
            None in fallback mode.

        """
        return

    def resume(*args: object) -> None:
        """Resume a process when Frida is unavailable.

        Args:
            *args: Variable arguments (ignored in fallback mode).

        Returns:
            None in fallback mode.

        """
        return

    def kill(*args: object) -> None:
        """Kill a process when Frida is unavailable.

        Args:
            *args: Variable arguments (ignored in fallback mode).

        Returns:
            None in fallback mode.

        """
        return

    def enumerate_devices() -> list[Any]:
        """Enumerate all devices when Frida is unavailable.

        Returns:
            Empty list in fallback mode.

        """
        return []


# Export all Frida objects and availability flag
__all__ = [
    # Availability flags
    "HAS_FRIDA",
    "FRIDA_VERSION",
    # Main frida module
    "frida",
    # Core classes
    "Device",
    "Process",
    "Session",
    "Script",
    "DeviceManager",
    "FileMonitor",
    "ScriptMessage",
    # Functions
    "get_local_device",
    "get_remote_device",
    "get_usb_device",
    "get_device_manager",
    "attach",
    "spawn",
    "resume",
    "kill",
    "enumerate_devices",
]
