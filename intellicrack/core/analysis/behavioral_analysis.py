"""Behavioral Analysis Module with QEMU Integration for Runtime Monitoring.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import contextlib
import ctypes
import json
import os
import platform
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypedDict

import psutil

from intellicrack.utils.type_safety import get_typed_item, validate_type

from ...utils.logger import get_logger


ARG_INDEX_1 = 1
ARG_INDEX_2 = 2
ARG_INDEX_3 = 3
MIN_SAMPLE_COUNT = 2
REGISTRY_ARG_COUNT = 3
API_ARG_COUNT = 2
READ_BUFFER_SIZE = 1024
BASELINE_SAMPLE_COUNT = 10
ANOMALY_THRESHOLD_MULTIPLIER = 5

HEX_PREVIEW_SIZE = 64
HIGH_ENTROPY_THRESHOLD = 7.5
PRINTABLE_CHAR_MIN = 0x20
PRINTABLE_CHAR_MAX = 0x7E
MIN_STRING_LENGTH = 4
MIN_KEY_SIZE = 16
MAX_KEY_SIZE = 512
MAX_EXTRACTED_STRINGS = 20
TIMING_THRESHOLD_MS = 100
THREAD_TIME_THRESHOLD_RATIO = 0.1
TIMESTAMP_SIZE = 8
HASH_SIZE = 20
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
FILE_SHARE_DELETE = 4

AF_INET = 2
AF_INET6 = 10
SOCKADDR_INET_SIZE = 16
SOCKADDR_INET6_SIZE = 28
HIGH_FD_THRESHOLD = 20
RAPID_CPU_THRESHOLD = 0.5
MIN_UPTIME = 1.0
TIMING_TOLERANCE_SECONDS = 0.01
TIMING_BASELINE_RATIO = 2.0
CPU_IDLE_THRESHOLD = 5.0

EXCESSIVE_EXEC_REGIONS = 10
OBFUSCATION_ENTROPY_THRESHOLD = 7.0
PE_HEADER_OFFSET_POS = 0x40
UNUSUAL_PE_OFFSET_THRESHOLD = 0x1000
LARGE_NETWORK_THRESHOLD = 1024
HIGH_SUSPICIOUS_THRESHOLD = 10
MEDIUM_SUSPICIOUS_THRESHOLD = 5


class QemuAnalysisResults(TypedDict, total=False):
    """QEMU VM analysis results.

    Represents the output of a QEMU virtual machine analysis including
    startup status, captured snapshots, monitor communications, events,
    and VM information.

    Attributes:
        started: Whether the QEMU VM started successfully.
        snapshots: List of snapshot names created during analysis.
        monitor_output: List of responses from QEMU monitor commands.
        events: List of events captured during VM execution.
        vm_info: Dictionary containing VM information from QMP queries.
        error: Error message if analysis failed.
    """

    started: bool
    snapshots: list[str]
    monitor_output: list[str]
    events: list[Any]
    vm_info: dict[str, Any]
    error: str


class NativeAnalysisResults(TypedDict, total=False):
    """Native analysis results.

    Represents the output of native (non-virtualized) binary analysis
    including process execution metrics and resource usage data.

    Attributes:
        process_started: Whether the target process started successfully.
        pid: Process ID of the launched binary, or None if failed.
        memory_usage: Dictionary with memory statistics (RSS, VMS, timestamp).
        cpu_usage: List of CPU usage percentages sampled during execution.
        error: Error message if analysis failed.
    """

    process_started: bool
    pid: int | None
    memory_usage: dict[str, Any]
    cpu_usage: list[float]
    error: str


class ApiMonitoringResults(TypedDict, total=False):
    """API monitoring results.

    Represents the output of API hook monitoring during binary execution,
    tracking installed hooks, captured events, and API function calls.

    Attributes:
        hooks_installed: Number of API hooks successfully installed.
        events_captured: Number of API call events recorded during execution.
        unique_apis_called: Set of unique API function names that were called.
        frida_attached: Whether Frida successfully attached to process.
        error: Error message if monitoring failed.
    """

    hooks_installed: int
    events_captured: int
    unique_apis_called: set[str]
    frida_attached: bool
    error: str


class AnalysisSummary(TypedDict, total=False):
    """Analysis summary results.

    Aggregated summary of behavioral analysis findings including event
    counts, activity classification, and risk assessment.

    Attributes:
        total_events: Total number of monitored events captured.
        unique_event_types: Count of distinct event type categories observed.
        suspicious_activities: Count of potentially suspicious behaviors detected.
        risk_level: Risk assessment level: 'low', 'medium', or 'high'.
        key_findings: List of descriptive strings summarizing key analysis results.
        bypass_recommendations: List of recommended bypass techniques based on findings.
    """

    total_events: int
    unique_event_types: int
    suspicious_activities: int
    risk_level: str
    key_findings: list[str]
    bypass_recommendations: list[str]


logger = get_logger(__name__)


@dataclass
class QEMUConfig:
    """Configuration for QEMU virtual machine.

    Defines all parameters needed to configure and launch a QEMU virtual
    machine for sandboxed binary analysis.

    Attributes:
        machine_type: QEMU machine type (default: 'pc').
        cpu_model: CPU model to emulate (default: 'max').
        memory_size: Memory allocation for the VM (default: '2G').
        kernel: Path to kernel image for the VM, or None to use defaults.
        initrd: Path to initial ramdisk, or None to use defaults.
        disk_image: Path to disk image file for the VM, or None for no disk.
        network_mode: Network mode configuration (default: 'user').
        enable_kvm: Enable KVM acceleration if available (default: True).
        enable_gdb: Enable GDB debugging interface (default: True).
        gdb_port: Port for GDB debugging connection (default: 1234).
        monitor_port: Port for QEMU monitor connection (default: 4444).
        qmp_port: Port for QMP interface connection (default: 5555).
        vnc_display: VNC display number, or None to disable VNC (default: 0).
        extra_args: Additional QEMU command-line arguments (default: empty list).
    """

    machine_type: str = "pc"
    cpu_model: str = "max"
    memory_size: str = "2G"
    kernel: Path | None = None
    initrd: Path | None = None
    disk_image: Path | None = None
    network_mode: str = "user"
    enable_kvm: bool = True
    enable_gdb: bool = True
    gdb_port: int = 1234
    monitor_port: int = 4444
    qmp_port: int = 5555
    vnc_display: int | None = 0
    extra_args: list[str] = field(default_factory=list)


@dataclass
class HookPoint:
    """Definition of an API hook point.

    Represents a single API function hook with callbacks for entry and
    exit monitoring, used to track licensing and protection mechanisms.

    Attributes:
        module: Module or DLL name containing the function.
        function: Name of the API function to hook.
        on_enter: Optional callback invoked when the function is called.
        on_exit: Optional callback invoked when the function returns.
        enabled: Whether this hook is currently active (default: True).
        priority: Execution priority for hook ordering, higher priority executes first
                  (default: 0).
    """

    module: str
    function: str
    on_enter: Callable[[list[Any], dict[str, Any]], None] | None = None
    on_exit: Callable[[list[Any], dict[str, Any]], None] | None = None
    enabled: bool = True
    priority: int = 0


@dataclass
class MonitorEvent:
    """Event captured during monitoring.

    Represents a single API call, file operation, network communication,
    registry access, or process interaction event captured during analysis.

    Attributes:
        timestamp: Unix timestamp when the event was captured.
        event_type: Type of event (e.g., 'file_read', 'network_connect', 'registry_set').
        process_id: Process ID of the process that generated the event.
        thread_id: Thread ID of the thread that generated the event.
        data: Dictionary containing event-specific data and parameters.
        context: Optional dictionary with additional context information.
    """

    timestamp: float
    event_type: str
    process_id: int
    thread_id: int
    data: dict[str, Any]
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert monitor event to dictionary representation.

        Returns:
            dict[str, Any]: Dictionary containing timestamp, event_type, pid,
            tid, data, and context fields that represent the complete
            monitor event in serializable form.
        """
        return {
            "timestamp": self.timestamp,
            "type": self.event_type,
            "pid": self.process_id,
            "tid": self.thread_id,
            "data": self.data,
            "context": self.context,
        }


class QEMUController:
    """Controller for QEMU virtual machine operations.

    Manages lifecycle and communication with a QEMU virtual machine including
    startup, shutdown, snapshot management, and interface communication via
    monitor, QMP, and GDB protocols.
    """

    def __init__(self, config: QEMUConfig) -> None:
        """Initialize QEMU controller with configuration.

        Args:
            config (QEMUConfig): QEMU configuration object with machine
            parameters and interface settings for VM control.
        """
        self.config = config
        self.process: subprocess.Popen[bytes] | None = None
        self.monitor_socket: socket.socket | None = None
        self.qmp_socket: socket.socket | None = None
        self.gdb_socket: socket.socket | None = None
        self.is_running = False
        self._lock = threading.Lock()

    def start(self, binary_path: Path) -> bool:
        """Start QEMU virtual machine with target binary.

        Args:
            binary_path (Path): Path to the binary executable to run within
                the QEMU virtual machine environment.

        Returns:
            bool: True if QEMU virtual machine started successfully and
                connections established, False if startup failed.

        Raises:
            ValueError: If the command list contains unsafe arguments or
                non-string values that could indicate command injection.
        """
        try:
            qemu_binary = self._find_qemu_binary()
            if not qemu_binary:
                logger.error("QEMU binary not found")
                return False

            cmd = [
                qemu_binary,
                *["-machine", self.config.machine_type],
                *["-cpu", self.config.cpu_model],
                *["-m", self.config.memory_size],
            ]

            if self.config.enable_kvm and self._check_kvm_available():
                cmd.append("-enable-kvm")

            if self.config.disk_image:
                self._prepare_disk_image(binary_path)
                cmd.extend(["-hda", str(self.config.disk_image)])

            if self.config.kernel:
                cmd.extend(["-kernel", str(self.config.kernel)])
            if self.config.initrd:
                cmd.extend(["-initrd", str(self.config.initrd)])

            cmd.extend([
                "-netdev",
                "user,id=net0",
                "-device",
                "e1000,netdev=net0",
                "-monitor",
                f"tcp:127.0.0.1:{self.config.monitor_port},server,nowait",
                "-qmp",
                f"tcp:127.0.0.1:{self.config.qmp_port},server,nowait",
            ])
            if self.config.enable_gdb:
                cmd.extend(["-gdb", f"tcp:127.0.0.1:{self.config.gdb_port}", "-S"])
            if self.config.vnc_display is not None:
                cmd.extend(["-vnc", f":{self.config.vnc_display}"])
            else:
                cmd.append("-nographic")

            cmd.extend(self.config.extra_args)

            logger.info("Starting QEMU: %s", " ".join(cmd))

            if not isinstance(cmd, list) or not all(isinstance(arg, str) for arg in cmd):
                raise ValueError(f"Unsafe command: {cmd}")
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                shell=False,
            )

            time.sleep(2)

            if not self._connect_to_qemu():
                self.stop()
                return False

            self.is_running = True
            logger.info("QEMU started successfully")
            return True

        except Exception:
            logger.exception("Failed to start QEMU")
            return False

    def stop(self) -> None:
        """Stop QEMU virtual machine.

        Gracefully terminates the QEMU process and closes all control
        interfaces.
        """
        with self._lock:
            if self.monitor_socket:
                with contextlib.suppress(ConnectionError, OSError):
                    self.send_monitor_command("quit")
                self.monitor_socket.close()
                self.monitor_socket = None

            if self.qmp_socket:
                self.qmp_socket.close()
                self.qmp_socket = None

            if self.gdb_socket:
                self.gdb_socket.close()
                self.gdb_socket = None

            if self.process:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                self.process = None

            self.is_running = False
            logger.info("QEMU stopped")

    def send_monitor_command(self, command: str) -> str:
        """Send command to QEMU monitor.

        Args:
            command (str): Monitor command string to execute on the running
                QEMU virtual machine.

        Returns:
            str: Response from the QEMU monitor command execution, or empty
                string if no connection or command execution failed.
        """
        if not self.monitor_socket:
            return ""

        try:
            self.monitor_socket.send(f"{command}\n".encode())
            return self.monitor_socket.recv(4096).decode()
        except Exception:
            logger.exception("Monitor command failed")
            return ""

    def send_qmp_command(self, command: dict[str, Any]) -> dict[str, Any]:
        """Send QMP command to QEMU.

        Args:
            command (dict[str, Any]): QMP (QEMU Machine Protocol) command
                dictionary containing execute field and optional arguments.

        Returns:
            dict[str, Any]: Response from QMP interface as a dictionary, or
                empty dict if no connection or command execution failed.
        """
        if not self.qmp_socket:
            return {}

        try:
            cmd_json = json.dumps(command) + "\n"
            self.qmp_socket.send(cmd_json.encode())
            response = self.qmp_socket.recv(8192).decode()
            result = json.loads(response)
            return result if isinstance(result, dict) else {}
        except Exception:
            logger.exception("QMP command failed")
            return {}

    def _find_qemu_binary(self) -> str | None:
        """Find QEMU binary on system.

        Searches PATH and common installation directories for QEMU executable
        across Windows and Linux platforms.

        Returns:
            str | None: Full path to QEMU binary executable if found, None
            if QEMU is not available on the system.
        """
        possible_names = [
            "qemu-system-x86_64",
            "qemu-system-i386",
            "qemu",
            "qemu-system-x86_64.exe",
            "qemu-system-i386.exe",
        ]

        for name in possible_names:
            if path := shutil.which(name):
                return path

        if platform.system() == "Windows":
            common_paths = [
                r"C:\Program Files\qemu",
                r"C:\Program Files (x86)\qemu",
                r"C:\qemu",
            ]
            for base_path in common_paths:
                for name in possible_names:
                    full_path = os.path.join(base_path, name)
                    if os.path.exists(full_path):
                        return full_path

        return None

    def _check_kvm_available(self) -> bool:
        """Check if KVM acceleration is available.

        Returns:
            bool: True if /dev/kvm exists and is readable/writable on Linux
            systems, False otherwise or on non-Linux platforms.
        """
        if platform.system() != "Linux":
            return False
        return os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)

    def _prepare_disk_image(self, binary_path: Path) -> None:
        """Prepare disk image with target binary.

        Args:
            binary_path (Path): Path to the binary executable to copy into
            the configured disk image for QEMU execution.
        """
        if not self.config.disk_image or not self.config.disk_image.exists():
            return

        mount_dir = tempfile.mkdtemp(prefix="qemu_mount_")
        try:
            if platform.system() == "Linux":
                disk_image_path = str(self.config.disk_image).replace(";", "").replace("|", "").replace("&", "")
                mount_path = mount_dir.replace(";", "").replace("|", "").replace("&", "")
                subprocess.run(
                    ["sudo", "mount", "-o", "loop,offset=1048576", disk_image_path, mount_path],
                    check=False,
                    shell=False,
                )

                target_path = Path(mount_dir) / "target" / binary_path.name
                target_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(binary_path, target_path)

                mount_path = mount_dir.replace(";", "").replace("|", "").replace("&", "")
                subprocess.run(["sudo", "umount", mount_path], check=False, shell=False)

        finally:
            shutil.rmtree(mount_dir, ignore_errors=True)

    def _connect_to_qemu(self) -> bool:
        """Connect to QEMU control interfaces.

        Establishes TCP connections to monitor, QMP, and GDB sockets based on
        configured ports.

        Returns:
            bool: True if successfully connected to all configured interfaces
            and initialized QMP, False if connection setup failed.
        """
        try:
            self.monitor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.monitor_socket.connect(("127.0.0.1", self.config.monitor_port))

            self.qmp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.qmp_socket.connect(("127.0.0.1", self.config.qmp_port))

            self.qmp_socket.recv(4096)
            self.send_qmp_command({"execute": "qmp_capabilities"})

            if self.config.enable_gdb:
                self.gdb_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.gdb_socket.connect(("127.0.0.1", self.config.gdb_port))

            return True

        except Exception:
            logger.exception("Failed to connect to QEMU")
            return False

    def take_snapshot(self, name: str) -> bool:
        """Take VM snapshot.

        Args:
            name (str): Name identifier for the snapshot to be created.

        Returns:
            bool: True if snapshot was created successfully, False if QMP
            command failed or no connection available.
        """
        response = self.send_qmp_command({"execute": "savevm", "arguments": {"name": name}})
        return response.get("return") is not None

    def restore_snapshot(self, name: str) -> bool:
        """Restore VM snapshot.

        Args:
            name (str): Name identifier of the snapshot to restore to.

        Returns:
            bool: True if snapshot was restored successfully, False if QMP
            command failed or no connection available.
        """
        response = self.send_qmp_command({"execute": "loadvm", "arguments": {"name": name}})
        return response.get("return") is not None


class FridaAPIHookingFramework:
    """Framework for hooking Windows and Linux API calls using Frida.

    Provides platform-specific API hooking infrastructure using Frida dynamic
    instrumentation to monitor Windows kernel32, advapi32, ws2_32, ntdll APIs
    and Linux libc functions during binary execution to track licensing validation
    and protection mechanisms.
    """

    def __init__(self) -> None:
        """Initialize Frida API hooking framework.

        Sets up platform-specific hooks for monitoring API calls on Windows and
        Linux systems using Frida dynamic instrumentation.
        """
        self.hooks: dict[str, list[HookPoint]] = defaultdict(list)
        self.events: list[MonitorEvent] = []
        self.active_hooks: set[str] = set()
        self._lock = threading.Lock()
        self.frida_session: Any = None
        self.frida_script: Any = None
        self._setup_platform_hooks()

    def _setup_platform_hooks(self) -> None:
        """Set up platform-specific hooking infrastructure.

        Configures Windows or Linux API hooks based on the current platform.
        """
        system = platform.system()

        if system == "Windows":
            self._setup_windows_hooks()
        elif system == "Linux":
            self._setup_linux_hooks()
        else:
            logger.warning("Platform %s not fully supported for API hooking", system)

    def _setup_windows_hooks(self) -> None:
        """Set up Windows API hooks.

        Registers monitoring hooks for common Windows kernel32, advapi32, ws2_32,
        and ntdll API functions used in licensing and anti-analysis checks.
        """
        self.add_hook(
            HookPoint(
                module="kernel32.dll",
                function="CreateFileW",
                on_enter=self._hook_create_file,
                priority=100,
            )
        )

        self.add_hook(
            HookPoint(
                module="kernel32.dll",
                function="ReadFile",
                on_enter=self._hook_read_file,
                priority=90,
            )
        )

        self.add_hook(
            HookPoint(
                module="kernel32.dll",
                function="WriteFile",
                on_enter=self._hook_write_file,
                priority=90,
            )
        )

        self.add_hook(
            HookPoint(
                module="advapi32.dll",
                function="RegOpenKeyExW",
                on_enter=self._hook_reg_open_key,
                priority=100,
            )
        )

        self.add_hook(
            HookPoint(
                module="advapi32.dll",
                function="RegQueryValueExW",
                on_enter=self._hook_reg_query_value,
                priority=90,
            )
        )

        self.add_hook(
            HookPoint(
                module="advapi32.dll",
                function="RegSetValueExW",
                on_enter=self._hook_reg_set_value,
                priority=90,
            )
        )

        self.add_hook(HookPoint(module="ws2_32.dll", function="connect", on_enter=self._hook_connect, priority=100))

        self.add_hook(HookPoint(module="ws2_32.dll", function="send", on_enter=self._hook_send, priority=90))

        self.add_hook(HookPoint(module="ws2_32.dll", function="recv", on_enter=self._hook_recv, priority=90))

        self.add_hook(
            HookPoint(
                module="ntdll.dll",
                function="NtCreateProcess",
                on_enter=self._hook_create_process,
                priority=110,
            )
        )

        self.add_hook(
            HookPoint(
                module="ntdll.dll",
                function="NtOpenProcess",
                on_enter=self._hook_open_process,
                priority=110,
            )
        )

    def _setup_linux_hooks(self) -> None:
        """Set up Linux syscall hooks.

        Registers monitoring hooks for common libc functions used in file I/O
        and network operations on Linux systems.
        """
        self.add_hook(HookPoint(module="libc.so.6", function="open", on_enter=self._hook_open, priority=100))

        self.add_hook(HookPoint(module="libc.so.6", function="read", on_enter=self._hook_read, priority=90))

        self.add_hook(HookPoint(module="libc.so.6", function="write", on_enter=self._hook_write, priority=90))

        self.add_hook(HookPoint(module="libc.so.6", function="socket", on_enter=self._hook_socket, priority=100))

        self.add_hook(
            HookPoint(
                module="libc.so.6",
                function="connect",
                on_enter=self._hook_connect_linux,
                priority=100,
            )
        )

    def attach_to_process(self, pid: int) -> bool:
        """Attach Frida to target process and install hooks.

        Args:
            pid (int): Process ID to attach Frida instrumentation to.

        Returns:
            bool: True if Frida attached successfully and hooks were installed,
            False if attachment or hook installation failed.
        """
        try:
            import frida

            try:
                self.frida_session = frida.attach(pid)
            except frida.ProcessNotFoundError:
                logger.warning("Process %d not found for Frida attachment", pid)
                return False
            except frida.ServerNotRunningError:
                logger.warning("Frida server not running")
                return False

            frida_script_code = self._generate_frida_script()
            self.frida_script = self.frida_session.create_script(frida_script_code)
            self.frida_script.on("message", self._on_frida_message)
            self.frida_script.load()

            logger.info("Frida attached to process %d with hooks installed", pid)
            return True

        except ImportError:
            logger.warning("Frida not available, falling back to ctypes-based monitoring")
            return False
        except Exception:
            logger.exception("Failed to attach Frida")
            return False

    def detach_from_process(self) -> None:
        """Detach Frida from process and clean up resources.

        Unloads Frida script and detaches from the target process, releasing
        all instrumentation resources.
        """
        if self.frida_script:
            try:
                self.frida_script.unload()
            except Exception as e:
                logger.debug("Error unloading Frida script: %s", e)
            self.frida_script = None

        if self.frida_session:
            try:
                self.frida_session.detach()
            except Exception as e:
                logger.debug("Error detaching Frida session: %s", e)
            self.frida_session = None

    def _generate_frida_script(self) -> str:
        """Generate Frida JavaScript instrumentation script.

        Creates a Frida script that installs hooks for all enabled API
        functions to capture licensing and protection mechanism calls.

        Returns:
            str: JavaScript code for Frida instrumentation with API hooks.
        """
        hooks_js: list[str] = []

        string_reading_funcs = {
            "CreateFileW": {"args": [0], "type": "utf16"},
            "RegOpenKeyExW": {"args": [1], "type": "utf16"},
            "RegQueryValueExW": {"args": [1], "type": "utf16"},
            "RegSetValueExW": {"args": [1], "type": "utf16"},
            "LoadLibraryW": {"args": [0], "type": "utf16"},
            "LoadLibraryExW": {"args": [0], "type": "utf16"},
            "GetProcAddress": {"args": [1], "type": "utf8"},
        }

        for key, hook_list in self.hooks.items():
            if self.active_hooks and key not in self.active_hooks:
                continue

            module_name, func_name = key.split(":")
            for hook in hook_list:
                if not hook.enabled:
                    continue

                string_config = string_reading_funcs.get(func_name, {})
                string_indices = string_config.get("args", [])
                string_type = string_config.get("type", "utf16")

                hook_template = f"""
(function() {{
    var addr = Module.findExportByName("{module_name}", "{func_name}");
    if (addr === null) {{
        console.log("Warning: Could not find {module_name}:{func_name}");
        return;
    }}
    Interceptor.attach(addr, {{
        onEnter: function(args) {{
            var safeArgs = [];
            for (var i = 0; i < 4; i++) {{
                if (i < args.length && args[i]) {{
                    try {{
                        var shouldReadString = {string_indices!s}.indexOf(i) !== -1;
                        if (shouldReadString && !args[i].isNull()) {{
                            try {{
                                if ("{string_type}" === "utf16") {{
                                    safeArgs.push(args[i].readUtf16String());
                                }} else {{
                                    safeArgs.push(args[i].readUtf8String());
                                }}
                            }} catch (e) {{
                                safeArgs.push(args[i].toString());
                            }}
                        }} else {{
                            safeArgs.push(args[i].toString());
                        }}
                    }} catch (e) {{
                        safeArgs.push(null);
                    }}
                }} else {{
                    safeArgs.push(null);
                }}
            }}
            send({{
                type: "api_call",
                module: "{module_name}",
                function: "{func_name}",
                args: safeArgs,
                timestamp: Date.now() / 1000,
                pid: Process.id,
                tid: Process.getCurrentThreadId()
            }});
        }},
        onLeave: function(retval) {{
            send({{
                type: "api_return",
                module: "{module_name}",
                function: "{func_name}",
                retval: retval ? retval.toString() : null,
                timestamp: Date.now() / 1000,
                pid: Process.id,
                tid: Process.getCurrentThreadId()
            }});
        }}
    }});
}})();
"""
                hooks_js.append(hook_template)

        return "\n".join(hooks_js)

    def _on_frida_message(self, message: dict[str, Any], data: bytes | None) -> None:
        """Handle messages from Frida script.

        Processes API call and return events from Frida instrumentation and
        converts them into MonitorEvent objects for analysis. Binary data
        payloads are processed for memory dumps, buffer contents, and
        cryptographic material extraction.

        Args:
            message (dict[str, Any]): Message dictionary from Frida containing
                event type and payload data.
            data (bytes | None): Binary data payload from Frida containing
                memory dumps, buffer contents, or other binary information.
        """
        if message.get("type") != "send":
            return

        payload = message.get("payload", {})
        if not isinstance(payload, dict):
            return

        binary_info: dict[str, Any] = {}
        if data is not None and len(data) > 0:
            binary_info = self._process_binary_payload(data, payload)

        event_type = payload.get("type")
        if event_type == "api_call":
            module = payload.get("module", "")
            function = payload.get("function", "")

            event_data: dict[str, Any] = {
                "module": module,
                "function": function,
                "args": payload.get("args", []),
            }
            if binary_info:
                event_data["binary_payload"] = binary_info

            event = MonitorEvent(
                timestamp=float(payload.get("timestamp", time.time())),
                event_type=f"api_{function.lower()}",
                process_id=int(payload.get("pid", 0)),
                thread_id=int(payload.get("tid", 0)),
                data=event_data,
                context=payload,
            )

            with self._lock:
                self.events.append(event)

            key = f"{module}:{function}"
            if key in self.hooks:
                for hook in self.hooks[key]:
                    if hook.on_enter:
                        try:
                            hook.on_enter(payload.get("args", []), payload)
                        except Exception as e:
                            logger.debug("Hook callback error: %s", e)

    def _process_binary_payload(self, data: bytes, context: dict[str, Any]) -> dict[str, Any]:
        """Process binary data payload from Frida hooks.

        Analyzes binary payloads for memory dumps, buffer contents, potential
        cryptographic keys, license data, and other protection-relevant binary
        information.

        Args:
            data: Raw binary data from Frida hook.
            context: Context dictionary with function name and other metadata.

        Returns:
            Dictionary containing analyzed binary payload information including
            size, entropy, detected patterns, and extracted strings.
        """
        result: dict[str, Any] = {
            "size": len(data),
            "hex_preview": (
                data[:HEX_PREVIEW_SIZE].hex()
                if len(data) >= HEX_PREVIEW_SIZE
                else data.hex()
            ),
        }

        entropy = self._calculate_entropy(data)
        result["entropy"] = round(entropy, 3)

        if entropy > HIGH_ENTROPY_THRESHOLD:
            result["high_entropy"] = True
            result["potential_encrypted"] = True

        extracted_strings: list[str] = []
        current_string = bytearray()
        for byte in data:
            if PRINTABLE_CHAR_MIN <= byte <= PRINTABLE_CHAR_MAX:
                current_string.append(byte)
            elif len(current_string) >= MIN_STRING_LENGTH:
                extracted_strings.append(current_string.decode("ascii", errors="ignore"))
                current_string = bytearray()
            else:
                current_string = bytearray()
        if len(current_string) >= MIN_STRING_LENGTH:
            extracted_strings.append(current_string.decode("ascii", errors="ignore"))

        if extracted_strings:
            result["strings"] = extracted_strings[:MAX_EXTRACTED_STRINGS]

        license_patterns = [b"LICENSE", b"SERIAL", b"KEY=", b"ACTIV", b"REGIST", b"TRIAL"]
        for pattern in license_patterns:
            if pattern in data.upper():
                result["license_data_detected"] = True
                break

        crypto_signatures = [
            (b"\x30\x82", "ASN.1/DER structure"),
            (b"-----BEGIN", "PEM encoded"),
            (b"\x00\x00\x00\x00\x00\x00\x00\x00", "Null padding (potential key material)"),
        ]
        for sig, desc in crypto_signatures:
            if sig in data:
                result.setdefault("crypto_indicators", []).append(desc)

        func_name = context.get("function", "").lower()
        if any(api in func_name for api in ["crypt", "rsa", "aes", "hash", "sign", "verify"]):
            result["crypto_api_context"] = True
            if MIN_KEY_SIZE <= len(data) <= MAX_KEY_SIZE:
                result["potential_key_material"] = True

        return result

    def add_hook(self, hook: HookPoint) -> None:
        """Add a hook point.

        Registers a new API hook with platform-specific monitoring capabilities
        and sorts hooks by priority for execution order.

        Args:
            hook (HookPoint): Hook point definition containing module, function,
                callbacks, and priority settings for API interception.
        """
        key = f"{hook.module}:{hook.function}"
        with self._lock:
            self.hooks[key].append(hook)
            self.hooks[key].sort(key=lambda h: h.priority, reverse=True)

    def remove_hook(self, module: str, function: str) -> None:
        """Remove hooks for a function.

        Unregisters all hooks associated with a specific module function pair,
        removing monitoring from that API.

        Args:
            module (str): Module or DLL name containing the function to unhook.
            function (str): Function name to unhook from monitoring.
        """
        key = f"{module}:{function}"
        with self._lock:
            if key in self.hooks:
                del self.hooks[key]

    def enable_hook(self, module: str, function: str) -> None:
        """Enable hooks for a function.

        Activates monitoring for the specified module function pair, allowing
        events to be captured when this API is called.

        Args:
            module (str): Module or DLL name containing the function.
            function (str): Function name to enable for monitoring.
        """
        key = f"{module}:{function}"
        with self._lock:
            self.active_hooks.add(key)

    def disable_hook(self, module: str, function: str) -> None:
        """Disable hooks for a function.

        Deactivates monitoring for the specified module function pair, preventing
        events from being captured for this API.

        Args:
            module (str): Module or DLL name containing the function.
            function (str): Function name to disable from monitoring.
        """
        key = f"{module}:{function}"
        with self._lock:
            self.active_hooks.discard(key)

    def _hook_create_file(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor CreateFileW calls.

        Args:
            args (list[Any]): Function arguments array from the CreateFileW hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            filename = str(args[0]) if args and args[0] else "<unknown>"
            access = args[ARG_INDEX_1] if len(args) > ARG_INDEX_1 else "0"
            share_mode = args[ARG_INDEX_2] if len(args) > ARG_INDEX_2 else "0"
            creation = args[ARG_INDEX_3] if len(args) > ARG_INDEX_3 else "0"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="file_create",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "filename": filename,
                    "access": str(access),
                    "share_mode": str(share_mode),
                    "creation": str(creation),
                },
                context=context,
            )
            with self._lock:
                self.events.append(event)
            logger.debug("File create: %s", filename)

        except Exception:
            logger.exception("Hook error")

    def _hook_read_file(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor ReadFile calls.

        Args:
            args (list[Any]): Function arguments array from the ReadFile hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            handle = args[0] if args else "0"
            size = args[ARG_INDEX_2] if len(args) > ARG_INDEX_2 else "0"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="file_read",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "handle": str(handle),
                    "size": str(size),
                },
                context=context,
            )
            with self._lock:
                self.events.append(event)

        except Exception:
            logger.exception("Hook error")

    def _hook_write_file(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor WriteFile calls to track file writes.

        Args:
            args (list[Any]): Function arguments array from the WriteFile hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            handle = args[0] if args else "0"
            buffer = args[ARG_INDEX_1] if len(args) > ARG_INDEX_1 else "0"
            size = args[ARG_INDEX_2] if len(args) > ARG_INDEX_2 else "0"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="file_write",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "handle": str(handle),
                    "size": str(size),
                    "buffer": str(buffer),
                },
                context=context,
            )
            with self._lock:
                self.events.append(event)

        except Exception:
            logger.exception("Hook error")

    def _hook_reg_open_key(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor RegOpenKeyExW calls to track registry access.

        Args:
            args (list[Any]): Function arguments array from RegOpenKeyExW hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            hkey = args[0] if args else "0"
            subkey = str(args[ARG_INDEX_1]) if len(args) > ARG_INDEX_1 and args[ARG_INDEX_1] else "<unknown>"
            access = args[ARG_INDEX_3] if len(args) > ARG_INDEX_3 else "0"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="registry_open",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "hkey": str(hkey),
                    "subkey": subkey,
                    "access": str(access),
                },
                context=context,
            )
            with self._lock:
                self.events.append(event)
            logger.debug("Registry open: %s", subkey)

        except Exception:
            logger.exception("Hook error")

    def _hook_reg_query_value(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor registry queries via RegQueryValueExW hook.

        Args:
            args (list[Any]): Function arguments array from RegQueryValueExW
            hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            hkey = args[0] if args else "0"
            value_name = str(args[ARG_INDEX_1]) if len(args) > ARG_INDEX_1 and args[ARG_INDEX_1] else "<unknown>"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="registry_query",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "hkey": str(hkey),
                    "value": value_name,
                },
                context=context,
            )
            with self._lock:
                self.events.append(event)

        except Exception:
            logger.exception("Hook error")

    def _hook_reg_set_value(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor registry writes via RegSetValueExW hook.

        Args:
            args (list[Any]): Function arguments array from RegSetValueExW
            hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            hkey = args[0] if args else "0"
            value_name = str(args[ARG_INDEX_1]) if len(args) > ARG_INDEX_1 and args[ARG_INDEX_1] else "<unknown>"
            data_type = args[ARG_INDEX_3] if len(args) > ARG_INDEX_3 else "0"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="registry_set",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "hkey": str(hkey),
                    "value": value_name,
                    "type": str(data_type),
                },
                context=context,
            )
            with self._lock:
                self.events.append(event)
            logger.debug("Registry set: %s", value_name)

        except Exception:
            logger.exception("Hook error")

    def _hook_connect(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor network connections via connect hook (Windows).

        Args:
            args (list[Any]): Function arguments array from the connect hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            socket_fd = args[0] if args else "0"
            sockaddr = args[ARG_INDEX_1] if len(args) > ARG_INDEX_1 else "0"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="network_connect",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "socket": str(socket_fd),
                    "sockaddr": str(sockaddr),
                },
                context=context,
            )
            with self._lock:
                self.events.append(event)
            logger.debug("Network connect: socket=%s", socket_fd)

        except Exception:
            logger.exception("Hook error")

    def _hook_send(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor network data transmission via send hook.

        Args:
            args (list[Any]): Function arguments array from the send hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            socket_fd = args[0] if args else "0"
            buffer = args[ARG_INDEX_1] if len(args) > ARG_INDEX_1 else "0"
            length = args[ARG_INDEX_2] if len(args) > ARG_INDEX_2 else "0"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="network_send",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "socket": str(socket_fd),
                    "length": str(length),
                    "buffer": str(buffer),
                },
                context=context,
            )
            with self._lock:
                self.events.append(event)

        except Exception:
            logger.exception("Hook error")

    def _hook_recv(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor network data reception via recv hook.

        Args:
            args (list[Any]): Function arguments array from the recv hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            socket_fd = args[0] if args else "0"
            length = args[ARG_INDEX_2] if len(args) > ARG_INDEX_2 else "0"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="network_recv",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={"socket": str(socket_fd), "length": str(length)},
                context=context,
            )
            with self._lock:
                self.events.append(event)

        except Exception:
            logger.exception("Hook error")

    def _hook_create_process(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor process creation via NtCreateProcess hook.

        Args:
            args (list[Any]): Function arguments array from NtCreateProcess
            hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            process_handle = args[0] if args else "0"
            desired_access = args[ARG_INDEX_1] if len(args) > ARG_INDEX_1 else "0"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="process_create",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "handle": str(process_handle),
                    "access": str(desired_access),
                },
                context=context,
            )
            with self._lock:
                self.events.append(event)
            logger.debug("Process create detected")

        except Exception:
            logger.exception("Hook error")

    def _hook_open_process(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor process access via NtOpenProcess hook.

        Args:
            args (list[Any]): Function arguments array from NtOpenProcess hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            desired_access = args[ARG_INDEX_1] if len(args) > ARG_INDEX_1 else "0"
            process_id = args[ARG_INDEX_3] if len(args) > ARG_INDEX_3 else "0"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="process_open",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "target_pid": str(process_id),
                    "access": str(desired_access),
                },
                context=context,
            )
            with self._lock:
                self.events.append(event)
            logger.debug("Process open: PID %s", process_id)

        except Exception:
            logger.exception("Hook error")

    def _hook_open(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor file opening via open hook (Linux).

        Args:
            args (list[Any]): Function arguments array from the open hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            pathname = str(args[0]) if args and args[0] else "<unknown>"
            flags = args[1] if len(args) > 1 else "0"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="file_open",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "path": pathname,
                    "flags": str(flags),
                },
                context=context,
            )
            with self._lock:
                self.events.append(event)

        except Exception:
            logger.exception("Hook error")

    def _hook_read(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor file reading via read hook (Linux).

        Args:
            args (list[Any]): Function arguments array from the read hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            fd = args[0] if args else "0"
            count = args[ARG_INDEX_2] if len(args) > ARG_INDEX_2 else "0"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="file_read",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={"fd": str(fd), "count": str(count)},
                context=context,
            )
            with self._lock:
                self.events.append(event)

        except Exception:
            logger.exception("Hook error")

    def _hook_write(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor file writing via write hook (Linux).

        Args:
            args (list[Any]): Function arguments array from the write hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            fd = args[0] if args else "0"
            buffer = args[ARG_INDEX_1] if len(args) > ARG_INDEX_1 else "0"
            count = args[ARG_INDEX_2] if len(args) > ARG_INDEX_2 else "0"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="file_write",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "fd": str(fd),
                    "count": str(count),
                    "buffer": str(buffer),
                },
                context=context,
            )
            with self._lock:
                self.events.append(event)

        except Exception:
            logger.exception("Hook error")

    def _hook_socket(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor network socket creation via socket hook (Linux).

        Args:
            args (list[Any]): Function arguments array from the socket hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            domain = args[0] if args else "0"
            socket_type = args[ARG_INDEX_1] if len(args) > ARG_INDEX_1 else "0"
            protocol = args[ARG_INDEX_2] if len(args) > ARG_INDEX_2 else "0"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="socket_create",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={"domain": str(domain), "type": str(socket_type), "protocol": str(protocol)},
                context=context,
            )
            with self._lock:
                self.events.append(event)

        except Exception:
            logger.exception("Hook error")

    def _hook_connect_linux(self, args: list[Any], context: dict[str, Any]) -> None:
        """Monitor network connections via connect hook (Linux).

        Args:
            args (list[Any]): Function arguments array from the connect hook.
            context (dict[str, Any]): Execution context dictionary containing
            process ID (pid) and thread ID (tid) of the calling thread.
        """
        try:
            sockfd = args[0] if args else "0"
            addr = args[1] if len(args) > 1 else "0"

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="network_connect",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "socket": str(sockfd),
                    "addr": str(addr),
                },
                context=context,
            )
            with self._lock:
                self.events.append(event)

        except Exception:
            logger.exception("Hook error")

    def _read_wide_string(self, address: int, max_length: int = 260) -> str:
        """Read a wide string from memory.

        Attempts to read a Unicode (wide character) string from the specified
        memory address using Windows API calls. Falls back to address
        representations if reading fails.

        Args:
            address (int): Memory address to read the wide string from.
            max_length (int): Maximum string length to read in characters
            (default: 260).

        Returns:
            str: Wide string from memory, or formatted address/error string
            if reading failed.
        """
        try:
            if platform.system() == "Windows":
                buffer = (ctypes.c_wchar * max_length)()
                kernel32 = ctypes.windll.kernel32
                bytes_read = ctypes.c_size_t()

                if kernel32.ReadProcessMemory(
                    kernel32.GetCurrentProcess(),
                    ctypes.c_void_p(address),
                    buffer,
                    max_length * 2,
                    ctypes.byref(bytes_read),
                ):
                    return buffer.value

            return f"<address: 0x{address:x}>"

        except Exception:
            return f"<unreadable: 0x{address:x}>"

    def _read_string(self, address: int, max_length: int = 260) -> str:
        """Read a string from memory.

        Attempts to read an ASCII/UTF-8 string from the specified memory address
        using Windows API calls. Falls back to address representations if reading
        fails.

        Args:
            address (int): Memory address to read the string from.
            max_length (int): Maximum string length to read in bytes
            (default: 260).

        Returns:
            str: ASCII/UTF-8 string from memory, or formatted address/error
            string if reading failed.
        """
        try:
            if platform.system() == "Windows":
                buffer = (ctypes.c_char * max_length)()
                kernel32 = ctypes.windll.kernel32
                bytes_read = ctypes.c_size_t()

                if kernel32.ReadProcessMemory(
                    kernel32.GetCurrentProcess(),
                    ctypes.c_void_p(address),
                    buffer,
                    max_length,
                    ctypes.byref(bytes_read),
                ):
                    return buffer.value.decode("utf-8", errors="replace")

            return f"<address: 0x{address:x}>"

        except Exception:
            return f"<unreadable: 0x{address:x}>"

    def _read_bytes(self, address: int, size: int) -> bytes | None:
        """Read bytes from memory.

        Attempts to read raw bytes from the specified memory address using
        Windows ReadProcessMemory API. Returns None if the operation fails.

        Args:
            address (int): Memory address to read the bytes from.
            size (int): Number of bytes to read from the address.

        Returns:
            bytes | None: Raw bytes from memory, or None if read operation
            failed.
        """
        try:
            if platform.system() == "Windows":
                buffer = (ctypes.c_byte * size)()
                kernel32 = ctypes.windll.kernel32
                bytes_read = ctypes.c_size_t()

                if kernel32.ReadProcessMemory(
                    kernel32.GetCurrentProcess(),
                    ctypes.c_void_p(address),
                    buffer,
                    size,
                    ctypes.byref(bytes_read),
                ):
                    return bytes(buffer)

            return None

        except Exception:
            return None

    def _parse_sockaddr(self, address: int) -> dict[str, Any]:
        """Parse sockaddr structure.

        Reads and interprets socket address structures (AF_INET, AF_INET6) from
        memory, extracting address family, IP address, and port information.

        Args:
            address (int): Memory address of the sockaddr structure to parse.

        Returns:
            dict[str, Any]: Dictionary with family, address, and port
            information for AF_INET/AF_INET6, or empty dict if parsing
            failed.
        """
        try:
            family_bytes = self._read_bytes(address, 2)
            if not family_bytes:
                return {}

            family = struct.unpack("<H", family_bytes)[0]

            if family == AF_INET:
                if sockaddr_bytes := self._read_bytes(address, SOCKADDR_INET_SIZE):
                    port = struct.unpack(">H", sockaddr_bytes[2:4])[0]
                    ip = ".".join(str(b) for b in sockaddr_bytes[4:8])
                    return {"family": "AF_INET", "address": ip, "port": port}

            elif family == AF_INET6:
                if sockaddr_bytes := self._read_bytes(address, SOCKADDR_INET6_SIZE):
                    port = struct.unpack(">H", sockaddr_bytes[2:4])[0]
                    ip = ":".join(f"{sockaddr_bytes[i]:02x}{sockaddr_bytes[i + 1]:02x}" for i in range(8, 24, 2))
                    return {"family": "AF_INET6", "address": ip, "port": port}

            return {"family": family}

        except Exception:
            return {}


class AntiAnalysisDetector:
    """Detector for anti-analysis techniques.

    Analyzes running processes for indicators of anti-debugging, anti-VM, and
    anti-analysis protection mechanisms used in software licensing protection
    to identify evasion and obfuscation strategies.
    """

    def __init__(self) -> None:
        """Initialize anti-analysis detector.

        Sets up detection methods for various anti-analysis techniques
        including debugger checks, VM artifacts, timing attacks, process
        hollowing, API hooks, sandbox indicators, memory protections, and
        code obfuscation.
        """
        self.detections: list[dict[str, Any]] = []
        self.detection_methods = [
            self._detect_debugger_presence,
            self._detect_vm_artifacts,
            self._detect_timing_attacks,
            self._detect_process_hollowing,
            self._detect_api_hooks,
            self._detect_sandbox_artifacts,
            self._detect_memory_protections,
            self._detect_code_obfuscation,
        ]

    def scan(self, process_id: int) -> list[dict[str, Any]]:
        """Scan process for anti-analysis techniques.

        Args:
            process_id (int): Process ID to scan for anti-analysis indicators.

        Returns:
            list[dict[str, Any]]: List of detection results, each containing
            type of anti-analysis technique, indicators/methods detected, and
            severity level assessment.
        """
        self.detections.clear()

        for method in self.detection_methods:
            try:
                method(process_id)
            except Exception:
                logger.exception("Detection method failed")

        return self.detections

    def _detect_debugger_presence(self, process_id: int) -> None:
        """Detect debugger presence checks.

        Checks for common Windows and Linux debugger detection mechanisms
        including IsDebuggerPresent, CheckRemoteDebuggerPresent, PEB.BeingDebugged,
        and Linux TracerPid monitoring.

        Args:
            process_id (int): Process ID to analyze for debugger detection
            mechanisms.
        """
        checks = []

        if platform.system() == "Windows":
            try:
                kernel32 = ctypes.windll.kernel32
                ntdll = ctypes.windll.ntdll

                is_debugger_present = kernel32.IsDebuggerPresent()
                if is_debugger_present:
                    checks.append("IsDebuggerPresent")

                remote_debugger = ctypes.c_bool()
                kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(remote_debugger))
                if remote_debugger.value:
                    checks.append("CheckRemoteDebuggerPresent")

                class PEB(ctypes.Structure):
                    _fields_ = [
                        ("Reserved1", ctypes.c_byte * 2),
                        ("BeingDebugged", ctypes.c_byte),
                        ("Reserved2", ctypes.c_byte * 21),
                    ]

                peb = PEB()
                if process_handle := kernel32.OpenProcess(0x0400 | 0x0010, False, process_id):
                    process_basic_info = ctypes.c_void_p()
                    return_length = ctypes.c_ulong()

                    ntdll.NtQueryInformationProcess(
                        process_handle,
                        0,
                        ctypes.byref(process_basic_info),
                        ctypes.sizeof(process_basic_info),
                        ctypes.byref(return_length),
                    )

                    if process_basic_info.value:
                        kernel32.ReadProcessMemory(
                            process_handle,
                            process_basic_info,
                            ctypes.byref(peb),
                            ctypes.sizeof(peb),
                            None,
                        )

                        if peb.BeingDebugged:
                            checks.append("PEB.BeingDebugged")

                    kernel32.CloseHandle(process_handle)

            except Exception:
                logger.exception("Debugger detection failed")

        elif platform.system() == "Linux":
            try:
                status_file = f"/proc/{process_id}/status"
                if os.path.exists(status_file):
                    with open(status_file, encoding="utf-8") as f:
                        status = f.read()
                        if "TracerPid:" in status:
                            tracer_line = next(line for line in status.split("\n") if "TracerPid:" in line)
                            tracer_pid = int(tracer_line.split(":")[1].strip())
                            if tracer_pid != 0:
                                checks.append(f"TracerPid: {tracer_pid}")

                if os.path.exists("/proc/self/fd"):
                    fd_count = len(os.listdir("/proc/self/fd"))
                    if fd_count > HIGH_FD_THRESHOLD:
                        checks.append(f"High FD count: {fd_count}")

            except Exception:
                logger.exception("Linux debugger detection failed")

        if checks:
            self.detections.append({"type": "debugger_presence", "methods": checks, "severity": "high"})

    def _detect_vm_artifacts(self, process_id: int) -> None:
        """Detect virtual machine artifacts.

        Scans for VM-specific processes (vmtoolsd, vboxservice, qemu-ga, xenservice)
        and files (vmci.sys, vmmouse.sys, vboxguest.sys, /proc/xen, DMI product
        strings).

        Args:
            process_id (int): Process ID to analyze for VM indicators.
        """
        vm_indicators: list[str] = []

        try:
            psutil.Process(process_id)

            vm_processes = [
                "vmtoolsd",
                "vmwaretray",
                "vmwareuser",
                "vboxservice",
                "vboxtray",
                "qemu-ga",
                "spice-vdagent",
                "xenservice",
                "xen-detect",
            ]

            vm_indicators.extend(
                f"VM process: {p.info['name']}"
                for p in psutil.process_iter(["name"])
                if p.info["name"] and any(vm in p.info["name"].lower() for vm in vm_processes)
            )
            vm_files = [
                r"C:\Windows\System32\drivers\vmci.sys",
                r"C:\Windows\System32\drivers\vmmouse.sys",
                r"C:\Windows\System32\drivers\vboxmouse.sys",
                r"C:\Windows\System32\drivers\vboxguest.sys",
                "/proc/xen",
                "/sys/class/dmi/id/product_name",
            ]

            vm_indicators.extend(f"VM file: {file_path}" for file_path in vm_files if os.path.exists(file_path))
            if platform.system() == "Linux" and os.path.exists("/sys/class/dmi/id/product_name"):
                with open("/sys/class/dmi/id/product_name", encoding="utf-8") as f:
                    product = f.read().strip()
                    if any(vm in product.lower() for vm in ["vmware", "virtualbox", "qemu", "xen"]):
                        vm_indicators.append(f"DMI product: {product}")

        except Exception:
            logger.exception("VM detection failed")

        if vm_indicators:
            self.detections.append({"type": "vm_artifacts", "indicators": vm_indicators, "severity": "medium"})

    def _detect_timing_attacks(self, process_id: int) -> None:
        """Detect timing-based anti-debugging in a specific process.

        Analyzes timing anomalies using process-specific CPU times, thread
        execution patterns, and timing APIs to identify timing-based evasion
        techniques used by the target process.

        Args:
            process_id: Process ID to analyze for timing-based anti-debugging.
        """
        timing_checks: list[str] = []

        try:
            proc = psutil.Process(process_id)

            cpu_times = proc.cpu_times()
            if cpu_times.user > 0:
                timing_checks.append(f"Process CPU user time: {cpu_times.user:.3f}s")

            create_time = proc.create_time()
            uptime = time.time() - create_time
            if uptime < MIN_UPTIME and cpu_times.user > RAPID_CPU_THRESHOLD:
                timing_checks.append(f"Rapid CPU consumption: {cpu_times.user:.3f}s in {uptime:.3f}s")

            threads = proc.threads()
            if len(threads) > ARG_INDEX_1:
                thread_times = [(t.id, t.user_time, t.system_time) for t in threads]
                max_user_time = max(t[ARG_INDEX_1] for t in thread_times)
                if max_user_time > MIN_UPTIME:
                    timing_checks.append(f"High thread CPU time detected: {max_user_time:.3f}s")

            start_time = time.perf_counter()
            time.sleep(0.001)
            elapsed = time.perf_counter() - start_time

            if elapsed > TIMING_TOLERANCE_SECONDS:
                timing_checks.append(f"Sleep timing anomaly: {elapsed:.6f}s")

            if platform.system() == "Windows":
                kernel32 = ctypes.windll.kernel32

                tick1 = kernel32.GetTickCount()
                time.sleep(0.001)
                tick2 = kernel32.GetTickCount()

                tick_anomaly_threshold = 10
                if tick2 - tick1 > tick_anomaly_threshold:
                    timing_checks.append(f"GetTickCount anomaly: {tick2 - tick1}ms")

                class LargeInteger(ctypes.Structure):
                    _fields_ = [("QuadPart", ctypes.c_longlong)]

                freq = LargeInteger()
                counter1 = LargeInteger()
                counter2 = LargeInteger()

                kernel32.QueryPerformanceFrequency(ctypes.byref(freq))
                kernel32.QueryPerformanceCounter(ctypes.byref(counter1))
                time.sleep(0.001)
                kernel32.QueryPerformanceCounter(ctypes.byref(counter2))

                elapsed_qpc = (counter2.QuadPart - counter1.QuadPart) / freq.QuadPart
                if elapsed_qpc > TIMING_TOLERANCE_SECONDS:
                    timing_checks.append(f"QueryPerformanceCounter anomaly: {elapsed_qpc:.6f}s")

            elif platform.system() == "Linux":
                with contextlib.suppress(ImportError, AttributeError):
                    import resource

                    rusage1 = resource.getrusage(resource.RUSAGE_SELF)
                    time.sleep(0.001)
                    rusage2 = resource.getrusage(resource.RUSAGE_SELF)

                    cpu_time = rusage2.ru_utime - rusage1.ru_utime
                    if cpu_time > TIMING_TOLERANCE_SECONDS:
                        timing_checks.append(f"CPU time anomaly: {cpu_time:.6f}s")
        except Exception:
            logger.exception("Timing detection failed")

        if timing_checks:
            self.detections.append({"type": "timing_attacks", "checks": timing_checks, "severity": "medium"})

    def _detect_process_hollowing(self, process_id: int) -> None:
        """Detect process hollowing indicators.

        Analyzes executable memory regions, unmapped code sections, and memory
        usage ratios to identify process hollowing or code injection attacks.

        Args:
            process_id (int): Process ID to analyze for process hollowing.
        """
        hollowing_indicators = []

        try:
            proc = psutil.Process(process_id)

            memory_maps = proc.memory_maps() if hasattr(proc, "memory_maps") else []
            executable_regions = [m for m in memory_maps if "x" in getattr(m, "perms", "")]

            if len(executable_regions) > EXCESSIVE_EXEC_REGIONS:
                hollowing_indicators.append(f"Excessive executable regions: {len(executable_regions)}")

            if unmapped_exec := [m for m in executable_regions if not getattr(m, "path", None)]:
                hollowing_indicators.append(f"Unmapped executable regions: {len(unmapped_exec)}")

            memory_info = proc.memory_info()
            if memory_info.rss > memory_info.vms * 0.8:
                hollowing_indicators.append("Suspicious memory usage ratio")

        except Exception:
            logger.exception("Process hollowing detection failed")

        if hollowing_indicators:
            self.detections.append({
                "type": "process_hollowing",
                "indicators": hollowing_indicators,
                "severity": "high",
            })

    def _detect_api_hooks(self, process_id: int) -> None:
        """Detect API hooking.

        Scans common licensing and protection APIs (IsDebuggerPresent,
        CreateFileW, RegOpenKeyExW) for hook signatures (jump instructions)
        indicating API interception.

        Args:
            process_id (int): Process ID to analyze for API hooks.
        """
        hooked_apis = []

        if platform.system() == "Windows":
            try:
                kernel32 = ctypes.windll.kernel32
                if process_handle := kernel32.OpenProcess(0x0010, False, process_id):
                    common_apis = [
                        ("ntdll.dll", "NtQueryInformationProcess"),
                        ("kernel32.dll", "IsDebuggerPresent"),
                        ("kernel32.dll", "CheckRemoteDebuggerPresent"),
                        ("kernel32.dll", "CreateFileW"),
                        ("advapi32.dll", "RegOpenKeyExW"),
                    ]

                    for dll_name, func_name in common_apis:
                        try:
                            if dll_handle := kernel32.LoadLibraryW(dll_name):
                                if func_addr := kernel32.GetProcAddress(dll_handle, func_name.encode()):
                                    first_bytes = (ctypes.c_byte * 5)()
                                    bytes_read = ctypes.c_size_t()

                                    if kernel32.ReadProcessMemory(
                                        process_handle,
                                        ctypes.c_void_p(func_addr),
                                        first_bytes,
                                        5,
                                        ctypes.byref(bytes_read),
                                    ) and first_bytes[0] in {0xE9, 0xE8}:
                                        hooked_apis.append(f"{dll_name}!{func_name}")

                                kernel32.FreeLibrary(dll_handle)
                        except Exception as e:
                            logger.debug("Failed to free library handle: %s", e)

                    kernel32.CloseHandle(process_handle)

            except Exception:
                logger.exception("API hook detection failed")

        if hooked_apis:
            self.detections.append({"type": "api_hooks", "hooked_functions": hooked_apis, "severity": "high"})

    def _detect_sandbox_artifacts(self, process_id: int) -> None:
        """Detect sandbox environment indicators for a specific process.

        Analyzes the target process and its environment for sandbox indicators
        including parent process analysis, command line inspection, loaded
        modules, and system-wide sandbox artifacts.

        Args:
            process_id: Process ID to analyze for sandbox indicators.
        """
        sandbox_indicators: list[str] = []

        try:
            proc = psutil.Process(process_id)

            try:
                parent = proc.parent()
                if parent:
                    parent_name = parent.name().lower()
                    sandbox_parents = ["python", "cmd", "powershell", "sandbox", "analyzer", "agent"]
                    if any(s in parent_name for s in sandbox_parents):
                        sandbox_indicators.append(f"Suspicious parent process: {parent.name()} (PID: {parent.pid})")

                    try:
                        parent_cmdline = " ".join(parent.cmdline())
                        if any(s in parent_cmdline.lower() for s in ["sandbox", "analysis", "malware", "test"]):
                            sandbox_indicators.append("Sandbox keywords in parent cmdline")
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                cmdline = proc.cmdline()
                if cmdline and any("sandbox" in arg.lower() or "analysis" in arg.lower() for arg in cmdline if arg):
                    sandbox_indicators.append("Sandbox keywords in process command line")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                environ = proc.environ()
                sandbox_env_vars = ["SANDBOX", "MALWARE", "ANALYSIS", "CUCKOO", "CAPE"]
                for var in sandbox_env_vars:
                    if var in environ:
                        sandbox_indicators.append(f"Sandbox environment variable: {var}")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            import tempfile

            temp_dir = tempfile.gettempdir()
            sandbox_files = [
                r"C:\agent\agent.py",
                r"C:\sandbox\starter.exe",
                os.path.join(temp_dir, ".X11-unix"),
                os.path.join(temp_dir, ".wine-"),
            ]

            sandbox_indicators.extend(f"Sandbox file: {file_path}" for file_path in sandbox_files if os.path.exists(file_path))
            sandbox_processes = ["python", "analyzer", "agent", "monitor"]
            for p in psutil.process_iter(["name", "cmdline"]):
                if p.info["name"] and any(s in p.info["name"].lower() for s in sandbox_processes):
                    cmdline = p.info.get("cmdline", [])
                    if cmdline and any("sandbox" in arg.lower() for arg in cmdline if arg):
                        sandbox_indicators.append(f"Sandbox process: {p.info['name']}")

            try:
                hostname = socket.gethostname()
                if any(s in hostname.lower() for s in ["sandbox", "malware", "virus", "analysis"]):
                    sandbox_indicators.append(f"Suspicious hostname: {hostname}")
            except Exception as e:
                logger.debug("Hostname analysis failed: %s", e)

            try:
                username = os.environ.get("USERNAME", os.environ.get("USER", ""))
                if any(s in username.lower() for s in ["sandbox", "admin", "test", "malware"]):
                    sandbox_indicators.append(f"Suspicious username: {username}")
            except Exception as e:
                logger.debug("Username analysis failed: %s", e)

        except Exception:
            logger.exception("Sandbox detection failed")

        if sandbox_indicators:
            self.detections.append({
                "type": "sandbox_artifacts",
                "indicators": sandbox_indicators,
                "severity": "medium",
            })

    def _detect_memory_protections(self, process_id: int) -> None:
        """Detect memory protection mechanisms.

        Identifies NX/DEP regions, guard pages, and DEP policy status to detect
        advanced memory protection and code integrity mechanisms.

        Args:
            process_id (int): Process ID to analyze for memory protections.
        """
        protections = []

        try:
            proc = psutil.Process(process_id)

            memory_maps = proc.memory_maps() if hasattr(proc, "memory_maps") else []

            if nx_regions := [m for m in memory_maps if "x" not in getattr(m, "perms", "") and "w" in getattr(m, "perms", "")]:
                protections.append(f"NX/DEP regions: {len(nx_regions)}")

            if guard_pages := [m for m in memory_maps if getattr(m, "rss", 0) == 0 and getattr(m, "size", 0) > 0]:
                protections.append(f"Guard pages: {len(guard_pages)}")

            if platform.system() == "Windows":
                try:
                    kernel32 = ctypes.windll.kernel32
                    if process_handle := kernel32.OpenProcess(0x0400, False, process_id):
                        dep_flags = ctypes.c_ulong()
                        permanent = ctypes.c_bool()

                        result = kernel32.GetProcessDEPPolicy(process_handle, ctypes.byref(dep_flags), ctypes.byref(permanent))

                        if result and dep_flags.value:
                            protections.append(f"DEP enabled: {hex(dep_flags.value)}")

                        kernel32.CloseHandle(process_handle)

                except Exception as e:
                    logger.debug("Error during memory protection detection cleanup: %s", e)

        except Exception:
            logger.exception("Memory protection detection failed")

        if protections:
            self.detections.append({"type": "memory_protections", "mechanisms": protections, "severity": "low"})

    def _detect_code_obfuscation(self, process_id: int) -> None:
        """Detect code obfuscation techniques.

        Analyzes binary entropy, packer signatures (UPX, ASPack, Themida), PE
        header offsets, and runtime memory entropy to identify code obfuscation
        and packing.

        Args:
            process_id (int): Process ID to analyze for obfuscation indicators.
        """
        obfuscation_indicators = []

        try:
            proc = psutil.Process(process_id)

            try:
                exe_path = proc.exe()
                if os.path.exists(exe_path):
                    with open(exe_path, "rb") as f:
                        header = f.read(4096)

                        entropy = self._calculate_entropy(header)
                        if entropy > HIGH_ENTROPY_THRESHOLD:
                            obfuscation_indicators.append(f"High entropy: {entropy:.2f}")

                        if b"UPX" in header or b"ASPack" in header or b"Themida" in header:
                            obfuscation_indicators.append("Known packer signatures")

                        pe_header_offset = struct.unpack("<I", header[0x3C:PE_HEADER_OFFSET_POS])[0] if len(header) > PE_HEADER_OFFSET_POS else 0
                        if pe_header_offset > UNUSUAL_PE_OFFSET_THRESHOLD:
                            obfuscation_indicators.append(f"Unusual PE header offset: {pe_header_offset:#x}")
            except Exception as e:
                logger.debug("PE header analysis failed: %s", e)

            memory_maps = proc.memory_maps() if hasattr(proc, "memory_maps") else []
            exec_regions = [m for m in memory_maps if "x" in getattr(m, "perms", "")]

            for region in exec_regions[:5]:
                if hasattr(region, "rss") and region.rss > 0:
                    try:
                        if platform.system() == "Windows":
                            kernel32 = ctypes.windll.kernel32
                            if process_handle := kernel32.OpenProcess(0x0010, False, process_id):
                                buffer = (ctypes.c_byte * 1024)()
                                bytes_read = ctypes.c_size_t()

                                base_addr = int(region.addr.split("-")[0], 16) if isinstance(region.addr, str) else region.addr

                                if kernel32.ReadProcessMemory(
                                    process_handle,
                                    ctypes.c_void_p(base_addr),
                                    buffer,
                                    1024,
                                    ctypes.byref(bytes_read),
                                ):
                                    entropy = self._calculate_entropy(bytes(buffer))
                                    if entropy > OBFUSCATION_ENTROPY_THRESHOLD:
                                        obfuscation_indicators.append(f"High entropy region: {region.addr} ({entropy:.2f})")

                                kernel32.CloseHandle(process_handle)
                    except Exception as e:
                        logger.debug("Error during obfuscation detection cleanup: %s", e)

        except Exception:
            logger.exception("Obfuscation detection failed")

        if obfuscation_indicators:
            self.detections.append({
                "type": "code_obfuscation",
                "indicators": obfuscation_indicators,
                "severity": "medium",
            })

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data.

        Computes Shannon entropy for binary data to detect obfuscation and
        code packing signatures. Higher entropy indicates compression or
        encryption.

        Args:
            data (bytes): Binary data to analyze for Shannon entropy.

        Returns:
            float: Shannon entropy value between 0 and 8 indicating data
            randomness, where values above 7.5 suggest compression or
            encryption.
        """
        import math

        if not data:
            return 0.0

        frequency: dict[int, int] = defaultdict(int)
        for byte in data:
            frequency[byte] += 1

        entropy = 0.0
        data_len = len(data)

        for count in frequency.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy


class BehavioralAnalyzer:
    """Comprehensive behavioral analysis orchestrator for licensing protection research.

    Coordinates QEMU virtualization, Frida API hooking, anti-analysis detection, and event
    monitoring to identify licensing validation mechanisms and protection strategies
    used in software copy protection systems.
    """

    def __init__(self, binary_path: Path) -> None:
        """Initialize behavioral analyzer with target binary.

        Args:
            binary_path (Path): Path to the binary executable to analyze
            behaviorally.
        """
        self.binary_path = binary_path
        self.qemu_config = QEMUConfig()
        self.qemu_controller = QEMUController(self.qemu_config)
        self.api_hooks = FridaAPIHookingFramework()
        self.anti_analysis = AntiAnalysisDetector()
        self.events: list[MonitorEvent] = []
        self.analysis_thread: threading.Thread | None = None
        self.stop_flag = threading.Event()

    def run_analysis(self, duration: int = 60, use_qemu: bool = False) -> dict[str, Any]:
        """Run comprehensive behavioral analysis on target binary.

        Executes multi-component analysis including QEMU virtualization (optional),
        Frida API monitoring, anti-analysis detection, and behavioral pattern analysis
        to identify licensing validation and protection mechanisms.

        Args:
            duration (int): Time in seconds to monitor the binary execution
                (default: 60).
            use_qemu (bool): Whether to use QEMU virtualization or native execution
                (default: False).

        Returns:
            dict[str, Any]: Dictionary containing QEMU/native results, API monitoring
                data, anti-analysis detections, behavioral patterns, network/file/
                registry/process activity, and comprehensive summary with risk
                assessment and bypass recommendations.
        """
        logger.info("Starting behavioral analysis of %s", self.binary_path)

        results: dict[str, Any] = {
            "binary": str(self.binary_path),
            "start_time": time.time(),
            "qemu_analysis": {},
            "native_analysis": {},
            "api_monitoring": {},
            "anti_analysis": {},
            "behavioral_patterns": {},
            "network_activity": [],
            "file_operations": [],
            "registry_activity": [],
            "process_activity": [],
            "summary": {},
        }

        try:
            if use_qemu and self.qemu_config.disk_image and self.qemu_config.disk_image.exists():
                logger.info("Starting QEMU-based analysis")
                results["qemu_analysis"] = self._run_qemu_analysis(duration)
            else:
                logger.info("Using native analysis with Frida")
                results["native_analysis"] = self._run_native_analysis(duration)

            logger.info("Performing API monitoring with Frida")
            results["api_monitoring"] = self._run_api_monitoring(duration)

            logger.info("Detecting anti-analysis techniques")
            if process_id := self._get_target_process_id():
                anti_analysis_results = validate_type(results["anti_analysis"], dict)
                anti_analysis_results["detections"] = self.anti_analysis.scan(process_id)

            results["behavioral_patterns"] = self._analyze_behavioral_patterns()

            results["network_activity"] = [e.to_dict() for e in self.events if e.event_type.startswith("network_")]
            results["file_operations"] = [e.to_dict() for e in self.events if e.event_type.startswith("file_")]
            results["registry_activity"] = [e.to_dict() for e in self.events if e.event_type.startswith("registry_")]
            results["process_activity"] = [e.to_dict() for e in self.events if e.event_type.startswith("process_")]

            end_time = time.time()
            start_time_val = get_typed_item(results, "start_time", float)
            results["end_time"] = end_time
            results["duration"] = end_time - start_time_val

            results["summary"] = self._generate_summary(results)

        except Exception as e:
            logger.exception("Behavioral analysis failed")
            results["error"] = str(e)

        finally:
            self.cleanup()

        logger.info("Behavioral analysis complete")
        return results

    def _run_qemu_analysis(self, duration: int) -> QemuAnalysisResults:
        """Run analysis in QEMU virtual machine.

        Initializes QEMU VM, takes system snapshots (before and after execution),
        monitors execution via QEMU interfaces, and captures VM state information
        during binary execution.

        Args:
            duration (int): Time in seconds to run the binary within the VM.

        Returns:
            QemuAnalysisResults: TypedDict with startup status, snapshots,
            monitor output, events, VM information, and any errors encountered
            during QEMU execution.
        """
        snapshots: list[str] = []
        monitor_output_list: list[str] = []
        qemu_results: QemuAnalysisResults = {
            "started": False,
            "snapshots": snapshots,
            "monitor_output": monitor_output_list,
            "events": [],
        }

        try:
            if self.qemu_controller.start(self.binary_path):
                qemu_results["started"] = True

                initial_snapshot = "clean_state"
                if self.qemu_controller.take_snapshot(initial_snapshot):
                    snapshots.append(initial_snapshot)

                monitor_output = self.qemu_controller.send_monitor_command("info registers")
                monitor_output_list.append(monitor_output)

                vm_info = self.qemu_controller.send_qmp_command({"execute": "query-status"})
                qemu_results["vm_info"] = vm_info

                time.sleep(duration)

                infected_snapshot = "post_execution"
                if self.qemu_controller.take_snapshot(infected_snapshot):
                    snapshots.append(infected_snapshot)

                self.qemu_controller.stop()

        except Exception as e:
            logger.exception("QEMU analysis failed")
            qemu_results["error"] = str(e)

        return qemu_results

    def _run_native_analysis(self, duration: int) -> NativeAnalysisResults:
        """Run analysis natively without virtualization.

        Launches the target binary directly, monitors CPU and memory usage over
        the specified duration, and captures resource utilization data.

        Args:
            duration (int): Time in seconds to monitor the native process
            execution.

        Returns:
            NativeAnalysisResults: TypedDict with process startup status,
            process ID, memory usage snapshots, CPU usage samples, and any
            errors encountered.

        Raises:
            ValueError: If the binary path is not absolute or contains directory
            traversal sequences.
        """
        cpu_usage_list: list[float] = []
        native_results: NativeAnalysisResults = {
            "process_started": False,
            "pid": None,
            "memory_usage": {},
            "cpu_usage": cpu_usage_list,
        }

        try:
            binary_path_str = str(self.binary_path)
            if not Path(binary_path_str).is_absolute() or ".." in binary_path_str:
                raise ValueError(f"Unsafe binary path: {binary_path_str}")
            process = subprocess.Popen([binary_path_str], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

            native_results["process_started"] = True
            native_results["pid"] = process.pid

            proc = psutil.Process(process.pid)

            start_time = time.time()
            while time.time() - start_time < duration and process.poll() is None:
                try:
                    cpu_usage_list.append(proc.cpu_percent())
                    mem_info = proc.memory_info()
                    native_results["memory_usage"] = {
                        "rss": mem_info.rss,
                        "vms": mem_info.vms,
                        "timestamp": time.time(),
                    }
                    time.sleep(1)
                except psutil.NoSuchProcess:
                    break

            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

        except Exception as e:
            logger.exception("Native analysis failed")
            native_results["error"] = str(e)

        return native_results

    def _run_api_monitoring(self, duration: int) -> ApiMonitoringResults:
        """Run API monitoring during binary execution using Frida.

        Activates Frida API hooks, launches the target binary, and captures all API
        calls made during execution to identify licensing and protection mechanisms.

        Args:
            duration (int): Time in seconds to monitor API calls during binary
            execution.

        Returns:
            ApiMonitoringResults: TypedDict with count of installed hooks,
            captured events, unique API types called, Frida attachment status,
            and any errors encountered.

        Raises:
            ValueError: If the binary path is not absolute or contains directory
            traversal sequences.
        """
        unique_apis: set[str] = set()
        monitoring_results: ApiMonitoringResults = {
            "hooks_installed": 0,
            "events_captured": 0,
            "unique_apis_called": unique_apis,
            "frida_attached": False,
        }

        try:
            hooks_count = 0
            for key in self.api_hooks.hooks:
                self.api_hooks.enable_hook(*key.split(":"))
                hooks_count += 1
            monitoring_results["hooks_installed"] = hooks_count

            binary_path_str = str(self.binary_path)
            if not Path(binary_path_str).is_absolute() or ".." in binary_path_str:
                raise ValueError(f"Unsafe binary path: {binary_path_str}")
            process = subprocess.Popen([binary_path_str], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

            time.sleep(1)

            frida_attached = self.api_hooks.attach_to_process(process.pid)
            monitoring_results["frida_attached"] = frida_attached

            start_time = time.time()
            while time.time() - start_time < duration and process.poll() is None:
                time.sleep(0.1)

            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

            self.api_hooks.detach_from_process()

            with self.api_hooks._lock:
                self.events.extend(list(self.api_hooks.events))
                monitoring_results["events_captured"] = len(self.api_hooks.events)

            for event in self.api_hooks.events:
                unique_apis.add(event.event_type)

        except Exception as e:
            logger.exception("API monitoring failed")
            monitoring_results["error"] = str(e)

        return monitoring_results

    def _analyze_behavioral_patterns(self) -> dict[str, Any]:
        """Analyze captured events for behavioral patterns.

        Processes captured API events to identify licensing checks, network
        communications, persistence mechanisms, data exfiltration, and evasion
        techniques used in software protection. Correlates events with licensing
        keywords and suspicious patterns.

        Returns:
            dict[str, Any]: Dictionary with categorized behavioral patterns
            including license checks, network communications, persistence
            mechanisms, data exfiltration attempts, and evasion techniques
            detected.
        """
        patterns: dict[str, Any] = {
            "license_checks": [],
            "network_communications": [],
            "persistence_mechanisms": [],
            "data_exfiltration": [],
            "evasion_techniques": [],
        }

        license_keywords = ["license", "serial", "key", "activation", "registration", "trial"]
        persistence_locations = [
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        ]

        for event in self.events:
            event_data = event.data

            if event.event_type in {"file_read", "file_write", "registry_query", "registry_set"}:
                for keyword in license_keywords:
                    if keyword in str(event_data).lower():
                        patterns["license_checks"].append(event.to_dict())
                        break

            if event.event_type.startswith("network_"):
                patterns["network_communications"].append(event.to_dict())

                if event.event_type == "network_send" and event_data.get("length", 0) > LARGE_NETWORK_THRESHOLD:
                    patterns["data_exfiltration"].append(event.to_dict())

            if event.event_type in {"registry_set", "file_write"}:
                for location in persistence_locations:
                    if location.lower() in str(event_data).lower():
                        patterns["persistence_mechanisms"].append(event.to_dict())
                        break

        if self.anti_analysis.detections:
            patterns["evasion_techniques"] = self.anti_analysis.detections

        return patterns

    def _get_target_process_id(self) -> int | None:
        """Get the process ID of the target binary.

        Searches running processes to find the process ID matching the target
        binary by name and executable path.

        Returns:
            int | None: Process ID if found, None if not found or error occurs.
        """
        target_name = self.binary_path.name.lower()

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                proc_name = proc.info.get("name")
                if proc_name and target_name in proc_name.lower():
                    pid = proc.info.get("pid")
                    if isinstance(pid, int):
                        return pid
                proc_exe = proc.info.get("exe")
                if proc_exe and target_name in proc_exe.lower():
                    pid = proc.info.get("pid")
                    if isinstance(pid, int):
                        return pid
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return None

    def _generate_summary(self, results: dict[str, Any]) -> AnalysisSummary:
        """Generate analysis summary from complete behavioral analysis results.

        Synthesizes findings from all analysis components to produce a comprehensive
        summary with total events, event type counts, suspicious activity tallies,
        risk level assessment, and bypass recommendations based on detected protection
        mechanisms.

        Args:
            results (dict[str, Any]): Complete results dictionary from
            run_analysis().

        Returns:
            AnalysisSummary: TypedDict with total events, unique event types,
            suspicious activity count, risk level assessment, key findings, and
            bypass recommendations for identified licensing protections.
        """
        key_findings: list[str] = []
        bypass_recommendations: list[str] = []
        suspicious_count = 0

        summary: AnalysisSummary = {
            "total_events": len(self.events),
            "unique_event_types": len({e.event_type for e in self.events}),
            "suspicious_activities": 0,
            "risk_level": "low",
            "key_findings": key_findings,
            "bypass_recommendations": bypass_recommendations,
        }

        anti_analysis = results.get("anti_analysis", {})
        if isinstance(anti_analysis, dict) and anti_analysis.get("detections"):
            detections = anti_analysis["detections"]
            suspicious_count += len(detections)
            key_findings.append("Anti-analysis techniques detected")

            for detection in detections:
                if detection.get("type") == "debugger_presence":
                    bypass_recommendations.append(
                        "Use Frida ScriptStalker to bypass debugger detection checks in licensing validation"
                    )
                elif detection.get("type") == "vm_artifacts":
                    bypass_recommendations.append("Spoof VM indicators using QEMU snapshot masking and artifact removal")
                elif detection.get("type") == "timing_attacks":
                    bypass_recommendations.append("Patch timing checks or use time acceleration to bypass trial limitations")
                elif detection.get("type") == "api_hooks":
                    bypass_recommendations.append("Remove inline hooks or redirect to original API implementations")

        behavioral_patterns = results.get("behavioral_patterns", {})
        if isinstance(behavioral_patterns, dict):
            if behavioral_patterns.get("license_checks"):
                key_findings.append("License validation mechanisms identified")
                bypass_recommendations.append(
                    "Patch license validation logic or emulate valid license server responses"
                )

            if behavioral_patterns.get("network_communications"):
                network_comms = behavioral_patterns["network_communications"]
                if network_comms:
                    key_findings.append(f"Network-based license validation detected ({len(network_comms)} connections)")
                    bypass_recommendations.append(
                        "Intercept and replay license server responses or implement offline activation emulator"
                    )

            if behavioral_patterns.get("persistence_mechanisms"):
                persistence = behavioral_patterns["persistence_mechanisms"]
                suspicious_count += len(persistence)
                key_findings.append("Persistence mechanisms detected")
                bypass_recommendations.append("Remove registry persistence entries and startup hooks")

            if behavioral_patterns.get("data_exfiltration"):
                exfiltration = behavioral_patterns["data_exfiltration"]
                suspicious_count += len(exfiltration)
                key_findings.append("Potential data exfiltration detected")
                bypass_recommendations.append("Block outbound data transmission to prevent telemetry and tracking")

        summary["suspicious_activities"] = suspicious_count
        if suspicious_count > HIGH_SUSPICIOUS_THRESHOLD:
            summary["risk_level"] = "high"
        elif suspicious_count > MEDIUM_SUSPICIOUS_THRESHOLD:
            summary["risk_level"] = "medium"

        return summary

    def cleanup(self) -> None:
        """Clean up resources and gracefully shutdown analysis components.

        Stops the QEMU VM if running, detaches Frida from process, and waits for
        the analysis thread to terminate, releasing all acquired resources.
        """
        self.stop_flag.set()

        self.api_hooks.detach_from_process()

        if self.qemu_controller.is_running:
            self.qemu_controller.stop()

        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=5)


def create_behavioral_analyzer(binary_path: Path) -> BehavioralAnalyzer:
    """Create behavioral analyzer instance for a target binary.

    Factory function to instantiate a BehavioralAnalyzer with default
    QEMU and Frida API hooking configuration for licensing protection analysis.

    Args:
        binary_path (Path): Path to the binary executable to analyze
            behaviorally.

    Returns:
        BehavioralAnalyzer: Configured BehavioralAnalyzer instance ready for
            analysis.
    """
    return BehavioralAnalyzer(binary_path)


def run_behavioral_analysis(binary_path: Path, duration: int = 60, use_qemu: bool = False) -> dict[str, Any]:
    """Run comprehensive behavioral analysis on a binary.

    Convenience function that creates a behavioral analyzer and executes
    complete analysis pipeline including optional QEMU virtualization, Frida
    API monitoring, anti-analysis detection, behavioral pattern analysis, and
    summary reporting with bypass recommendations.

    Args:
        binary_path (Path): Path to the binary executable to analyze
            behaviorally.
        duration (int): Time in seconds to monitor binary execution
            (default: 60).
        use_qemu (bool): Whether to use QEMU virtualization or native execution
            (default: False).

    Returns:
        dict[str, Any]: Comprehensive analysis results dictionary containing
            QEMU/native analysis, API monitoring, anti-analysis detections,
            behavioral patterns, and activity summary with risk assessment and
            bypass recommendations.
    """
    analyzer = create_behavioral_analyzer(binary_path)
    return analyzer.run_analysis(duration, use_qemu)
