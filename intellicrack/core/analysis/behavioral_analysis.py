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

import ctypes
import json
import logging
import mmap
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
from dataclasses import dataclass, field
from pathlib import Path
from queue import Queue
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import psutil

from ...utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class QEMUConfig:
    """Configuration for QEMU virtual machine."""

    machine_type: str = "pc"
    cpu_model: str = "max"
    memory_size: str = "2G"
    kernel: Optional[Path] = None
    initrd: Optional[Path] = None
    disk_image: Optional[Path] = None
    network_mode: str = "user"
    enable_kvm: bool = True
    enable_gdb: bool = True
    gdb_port: int = 1234
    monitor_port: int = 4444
    qmp_port: int = 5555
    vnc_display: Optional[int] = 0
    extra_args: List[str] = field(default_factory=list)


@dataclass
class HookPoint:
    """Definition of an API hook point."""

    module: str
    function: str
    on_enter: Optional[Callable] = None
    on_exit: Optional[Callable] = None
    enabled: bool = True
    priority: int = 0


@dataclass
class MonitorEvent:
    """Event captured during monitoring."""

    timestamp: float
    event_type: str
    process_id: int
    thread_id: int
    data: Dict[str, Any]
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert monitor event to dictionary representation."""
        return {
            "timestamp": self.timestamp,
            "type": self.event_type,
            "pid": self.process_id,
            "tid": self.thread_id,
            "data": self.data,
            "context": self.context
        }


class QEMUController:
    """Controller for QEMU virtual machine operations."""

    def __init__(self, config: QEMUConfig):
        """Initialize QEMU controller with configuration."""
        self.config = config
        self.process: Optional[subprocess.Popen] = None
        self.monitor_socket: Optional[socket.socket] = None
        self.qmp_socket: Optional[socket.socket] = None
        self.gdb_socket: Optional[socket.socket] = None
        self.is_running = False
        self._lock = threading.Lock()

    def start(self, binary_path: Path) -> bool:
        """Start QEMU virtual machine with target binary."""
        try:
            qemu_binary = self._find_qemu_binary()
            if not qemu_binary:
                logger.error("QEMU binary not found")
                return False

            cmd = [qemu_binary]

            cmd.extend(["-machine", self.config.machine_type])
            cmd.extend(["-cpu", self.config.cpu_model])
            cmd.extend(["-m", self.config.memory_size])

            if self.config.enable_kvm and self._check_kvm_available():
                cmd.append("-enable-kvm")

            if self.config.disk_image:
                self._prepare_disk_image(binary_path)
                cmd.extend(["-hda", str(self.config.disk_image)])

            if self.config.kernel:
                cmd.extend(["-kernel", str(self.config.kernel)])
            if self.config.initrd:
                cmd.extend(["-initrd", str(self.config.initrd)])

            cmd.extend(["-netdev", f"user,id=net0", "-device", "e1000,netdev=net0"])

            cmd.extend(["-monitor", f"tcp:127.0.0.1:{self.config.monitor_port},server,nowait"])
            cmd.extend(["-qmp", f"tcp:127.0.0.1:{self.config.qmp_port},server,nowait"])

            if self.config.enable_gdb:
                cmd.extend(["-gdb", f"tcp:127.0.0.1:{self.config.gdb_port}"])
                cmd.append("-S")

            if self.config.vnc_display is not None:
                cmd.extend(["-vnc", f":{self.config.vnc_display}"])
            else:
                cmd.append("-nographic")

            cmd.extend(self.config.extra_args)

            logger.info(f"Starting QEMU: {' '.join(cmd)}")

            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )

            time.sleep(2)

            if not self._connect_to_qemu():
                self.stop()
                return False

            self.is_running = True
            logger.info("QEMU started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start QEMU: {e}")
            return False

    def stop(self):
        """Stop QEMU virtual machine."""
        with self._lock:
            if self.monitor_socket:
                try:
                    self.send_monitor_command("quit")
                except:
                    pass
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
        """Send command to QEMU monitor."""
        if not self.monitor_socket:
            return ""

        try:
            self.monitor_socket.send(f"{command}\n".encode())
            response = self.monitor_socket.recv(4096).decode()
            return response
        except Exception as e:
            logger.error(f"Monitor command failed: {e}")
            return ""

    def send_qmp_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Send QMP command to QEMU."""
        if not self.qmp_socket:
            return {}

        try:
            cmd_json = json.dumps(command) + "\n"
            self.qmp_socket.send(cmd_json.encode())
            response = self.qmp_socket.recv(8192).decode()
            return json.loads(response)
        except Exception as e:
            logger.error(f"QMP command failed: {e}")
            return {}

    def _find_qemu_binary(self) -> Optional[str]:
        """Find QEMU binary on system."""
        possible_names = [
            "qemu-system-x86_64",
            "qemu-system-i386",
            "qemu",
            "qemu-system-x86_64.exe",
            "qemu-system-i386.exe",
        ]

        for name in possible_names:
            path = shutil.which(name)
            if path:
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
        """Check if KVM acceleration is available."""
        if platform.system() != "Linux":
            return False
        return os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)

    def _prepare_disk_image(self, binary_path: Path):
        """Prepare disk image with target binary."""
        if not self.config.disk_image or not self.config.disk_image.exists():
            return

        mount_dir = tempfile.mkdtemp(prefix="qemu_mount_")
        try:
            if platform.system() == "Linux":
                subprocess.run(
                    ["sudo", "mount", "-o", "loop,offset=1048576",
                     str(self.config.disk_image), mount_dir],
                    check=False
                )

                target_path = Path(mount_dir) / "target" / binary_path.name
                target_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(binary_path, target_path)

                subprocess.run(["sudo", "umount", mount_dir], check=False)

        finally:
            shutil.rmtree(mount_dir, ignore_errors=True)

    def _connect_to_qemu(self) -> bool:
        """Connect to QEMU control interfaces."""
        try:
            self.monitor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.monitor_socket.connect(("127.0.0.1", self.config.monitor_port))

            self.qmp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.qmp_socket.connect(("127.0.0.1", self.config.qmp_port))

            qmp_greeting = self.qmp_socket.recv(4096)
            self.send_qmp_command({"execute": "qmp_capabilities"})

            if self.config.enable_gdb:
                self.gdb_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.gdb_socket.connect(("127.0.0.1", self.config.gdb_port))

            return True

        except Exception as e:
            logger.error(f"Failed to connect to QEMU: {e}")
            return False

    def take_snapshot(self, name: str) -> bool:
        """Take VM snapshot."""
        response = self.send_qmp_command({
            "execute": "savevm",
            "arguments": {"name": name}
        })
        return response.get("return") is not None

    def restore_snapshot(self, name: str) -> bool:
        """Restore VM snapshot."""
        response = self.send_qmp_command({
            "execute": "loadvm",
            "arguments": {"name": name}
        })
        return response.get("return") is not None


class APIHookingFramework:
    """Framework for hooking Windows and Linux API calls."""

    def __init__(self):
        """Initialize API hooking framework."""
        self.hooks: Dict[str, List[HookPoint]] = defaultdict(list)
        self.events: List[MonitorEvent] = []
        self.active_hooks: Set[str] = set()
        self._lock = threading.Lock()
        self._setup_platform_hooks()

    def _setup_platform_hooks(self):
        """Setup platform-specific hooking infrastructure."""
        system = platform.system()

        if system == "Windows":
            self._setup_windows_hooks()
        elif system == "Linux":
            self._setup_linux_hooks()
        else:
            logger.warning(f"Platform {system} not fully supported for API hooking")

    def _setup_windows_hooks(self):
        """Setup Windows API hooks."""
        self.add_hook(HookPoint(
            module="kernel32.dll",
            function="CreateFileW",
            on_enter=self._hook_create_file,
            priority=100
        ))

        self.add_hook(HookPoint(
            module="kernel32.dll",
            function="ReadFile",
            on_enter=self._hook_read_file,
            priority=90
        ))

        self.add_hook(HookPoint(
            module="kernel32.dll",
            function="WriteFile",
            on_enter=self._hook_write_file,
            priority=90
        ))

        self.add_hook(HookPoint(
            module="advapi32.dll",
            function="RegOpenKeyExW",
            on_enter=self._hook_reg_open_key,
            priority=100
        ))

        self.add_hook(HookPoint(
            module="advapi32.dll",
            function="RegQueryValueExW",
            on_enter=self._hook_reg_query_value,
            priority=90
        ))

        self.add_hook(HookPoint(
            module="advapi32.dll",
            function="RegSetValueExW",
            on_enter=self._hook_reg_set_value,
            priority=90
        ))

        self.add_hook(HookPoint(
            module="ws2_32.dll",
            function="connect",
            on_enter=self._hook_connect,
            priority=100
        ))

        self.add_hook(HookPoint(
            module="ws2_32.dll",
            function="send",
            on_enter=self._hook_send,
            priority=90
        ))

        self.add_hook(HookPoint(
            module="ws2_32.dll",
            function="recv",
            on_enter=self._hook_recv,
            priority=90
        ))

        self.add_hook(HookPoint(
            module="ntdll.dll",
            function="NtCreateProcess",
            on_enter=self._hook_create_process,
            priority=110
        ))

        self.add_hook(HookPoint(
            module="ntdll.dll",
            function="NtOpenProcess",
            on_enter=self._hook_open_process,
            priority=110
        ))

    def _setup_linux_hooks(self):
        """Setup Linux syscall hooks."""
        self.add_hook(HookPoint(
            module="libc.so.6",
            function="open",
            on_enter=self._hook_open,
            priority=100
        ))

        self.add_hook(HookPoint(
            module="libc.so.6",
            function="read",
            on_enter=self._hook_read,
            priority=90
        ))

        self.add_hook(HookPoint(
            module="libc.so.6",
            function="write",
            on_enter=self._hook_write,
            priority=90
        ))

        self.add_hook(HookPoint(
            module="libc.so.6",
            function="socket",
            on_enter=self._hook_socket,
            priority=100
        ))

        self.add_hook(HookPoint(
            module="libc.so.6",
            function="connect",
            on_enter=self._hook_connect_linux,
            priority=100
        ))

    def add_hook(self, hook: HookPoint):
        """Add a hook point."""
        key = f"{hook.module}:{hook.function}"
        with self._lock:
            self.hooks[key].append(hook)
            self.hooks[key].sort(key=lambda h: h.priority, reverse=True)

    def remove_hook(self, module: str, function: str):
        """Remove hooks for a function."""
        key = f"{module}:{function}"
        with self._lock:
            if key in self.hooks:
                del self.hooks[key]

    def enable_hook(self, module: str, function: str):
        """Enable hooks for a function."""
        key = f"{module}:{function}"
        with self._lock:
            self.active_hooks.add(key)

    def disable_hook(self, module: str, function: str):
        """Disable hooks for a function."""
        key = f"{module}:{function}"
        with self._lock:
            self.active_hooks.discard(key)

    def _hook_create_file(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook CreateFileW."""
        try:
            filename = self._read_wide_string(args[0])
            access = args[1]
            share_mode = args[2]
            creation = args[4]

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="file_create",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "filename": filename,
                    "access": hex(access),
                    "share_mode": hex(share_mode),
                    "creation": creation
                },
                context=context
            )
            self.events.append(event)
            logger.debug(f"File create: {filename}")

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _hook_read_file(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook ReadFile."""
        try:
            handle = args[0]
            buffer = args[1]
            size = args[2]

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="file_read",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "handle": hex(handle),
                    "size": size
                },
                context=context
            )
            self.events.append(event)

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _hook_write_file(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook WriteFile."""
        try:
            handle = args[0]
            buffer = args[1]
            size = args[2]

            data_preview = self._read_bytes(buffer, min(size, 64))

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="file_write",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "handle": hex(handle),
                    "size": size,
                    "preview": data_preview.hex() if data_preview else ""
                },
                context=context
            )
            self.events.append(event)

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _hook_reg_open_key(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook RegOpenKeyExW."""
        try:
            hkey = args[0]
            subkey = self._read_wide_string(args[1])
            access = args[3]

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="registry_open",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "hkey": hex(hkey),
                    "subkey": subkey,
                    "access": hex(access)
                },
                context=context
            )
            self.events.append(event)
            logger.debug(f"Registry open: {subkey}")

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _hook_reg_query_value(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook RegQueryValueExW."""
        try:
            hkey = args[0]
            value_name = self._read_wide_string(args[1])

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="registry_query",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "hkey": hex(hkey),
                    "value": value_name
                },
                context=context
            )
            self.events.append(event)

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _hook_reg_set_value(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook RegSetValueExW."""
        try:
            hkey = args[0]
            value_name = self._read_wide_string(args[1])
            data_type = args[3]

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="registry_set",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "hkey": hex(hkey),
                    "value": value_name,
                    "type": data_type
                },
                context=context
            )
            self.events.append(event)
            logger.debug(f"Registry set: {value_name}")

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _hook_connect(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook connect (Windows)."""
        try:
            socket_fd = args[0]
            sockaddr = args[1]

            addr_info = self._parse_sockaddr(sockaddr)

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="network_connect",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "socket": socket_fd,
                    "address": addr_info.get("address", ""),
                    "port": addr_info.get("port", 0)
                },
                context=context
            )
            self.events.append(event)
            logger.debug(f"Network connect: {addr_info.get('address')}:{addr_info.get('port')}")

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _hook_send(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook send."""
        try:
            socket_fd = args[0]
            buffer = args[1]
            length = args[2]

            data_preview = self._read_bytes(buffer, min(length, 64))

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="network_send",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "socket": socket_fd,
                    "length": length,
                    "preview": data_preview.hex() if data_preview else ""
                },
                context=context
            )
            self.events.append(event)

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _hook_recv(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook recv."""
        try:
            socket_fd = args[0]
            buffer = args[1]
            length = args[2]

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="network_recv",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "socket": socket_fd,
                    "length": length
                },
                context=context
            )
            self.events.append(event)

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _hook_create_process(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook NtCreateProcess."""
        try:
            process_handle = args[0]
            desired_access = args[1]

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="process_create",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "handle": hex(process_handle),
                    "access": hex(desired_access)
                },
                context=context
            )
            self.events.append(event)
            logger.debug("Process create detected")

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _hook_open_process(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook NtOpenProcess."""
        try:
            process_handle = args[0]
            desired_access = args[1]
            process_id = args[3]

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="process_open",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "target_pid": process_id,
                    "access": hex(desired_access)
                },
                context=context
            )
            self.events.append(event)
            logger.debug(f"Process open: PID {process_id}")

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _hook_open(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook open (Linux)."""
        try:
            pathname = self._read_string(args[0])
            flags = args[1]

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="file_open",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "path": pathname,
                    "flags": hex(flags)
                },
                context=context
            )
            self.events.append(event)

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _hook_read(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook read (Linux)."""
        try:
            fd = args[0]
            buffer = args[1]
            count = args[2]

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="file_read",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "fd": fd,
                    "count": count
                },
                context=context
            )
            self.events.append(event)

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _hook_write(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook write (Linux)."""
        try:
            fd = args[0]
            buffer = args[1]
            count = args[2]

            data_preview = self._read_bytes(buffer, min(count, 64))

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="file_write",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "fd": fd,
                    "count": count,
                    "preview": data_preview.hex() if data_preview else ""
                },
                context=context
            )
            self.events.append(event)

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _hook_socket(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook socket (Linux)."""
        try:
            domain = args[0]
            socket_type = args[1]
            protocol = args[2]

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="socket_create",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "domain": domain,
                    "type": socket_type,
                    "protocol": protocol
                },
                context=context
            )
            self.events.append(event)

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _hook_connect_linux(self, args: List[Any], context: Dict[str, Any]) -> Optional[Any]:
        """Hook connect (Linux)."""
        try:
            sockfd = args[0]
            addr = args[1]

            addr_info = self._parse_sockaddr(addr)

            event = MonitorEvent(
                timestamp=time.time(),
                event_type="network_connect",
                process_id=context.get("pid", 0),
                thread_id=context.get("tid", 0),
                data={
                    "socket": sockfd,
                    "address": addr_info.get("address", ""),
                    "port": addr_info.get("port", 0)
                },
                context=context
            )
            self.events.append(event)

        except Exception as e:
            logger.error(f"Hook error: {e}")

        return None

    def _read_wide_string(self, address: int, max_length: int = 260) -> str:
        """Read a wide string from memory."""
        try:
            if platform.system() == "Windows":
                buffer = (ctypes.c_wchar * max_length)()
                kernel32 = ctypes.windll.kernel32
                bytes_read = ctypes.c_size_t()

                if kernel32.ReadProcessMemory(
                    ctypes.c_void_p(-1),
                    ctypes.c_void_p(address),
                    buffer,
                    max_length * 2,
                    ctypes.byref(bytes_read)
                ):
                    return buffer.value

            return f"<address: 0x{address:x}>"

        except Exception:
            return f"<unreadable: 0x{address:x}>"

    def _read_string(self, address: int, max_length: int = 260) -> str:
        """Read a string from memory."""
        try:
            if platform.system() == "Windows":
                buffer = (ctypes.c_char * max_length)()
                kernel32 = ctypes.windll.kernel32
                bytes_read = ctypes.c_size_t()

                if kernel32.ReadProcessMemory(
                    ctypes.c_void_p(-1),
                    ctypes.c_void_p(address),
                    buffer,
                    max_length,
                    ctypes.byref(bytes_read)
                ):
                    return buffer.value.decode("utf-8", errors="replace")

            return f"<address: 0x{address:x}>"

        except Exception:
            return f"<unreadable: 0x{address:x}>"

    def _read_bytes(self, address: int, size: int) -> Optional[bytes]:
        """Read bytes from memory."""
        try:
            if platform.system() == "Windows":
                buffer = (ctypes.c_byte * size)()
                kernel32 = ctypes.windll.kernel32
                bytes_read = ctypes.c_size_t()

                if kernel32.ReadProcessMemory(
                    ctypes.c_void_p(-1),
                    ctypes.c_void_p(address),
                    buffer,
                    size,
                    ctypes.byref(bytes_read)
                ):
                    return bytes(buffer)

            return None

        except Exception:
            return None

    def _parse_sockaddr(self, address: int) -> Dict[str, Any]:
        """Parse sockaddr structure."""
        try:
            family_bytes = self._read_bytes(address, 2)
            if not family_bytes:
                return {}

            family = struct.unpack("<H", family_bytes)[0]

            if family == 2:
                sockaddr_bytes = self._read_bytes(address, 16)
                if sockaddr_bytes:
                    port = struct.unpack(">H", sockaddr_bytes[2:4])[0]
                    ip = ".".join(str(b) for b in sockaddr_bytes[4:8])
                    return {"family": "AF_INET", "address": ip, "port": port}

            elif family == 10:
                sockaddr_bytes = self._read_bytes(address, 28)
                if sockaddr_bytes:
                    port = struct.unpack(">H", sockaddr_bytes[2:4])[0]
                    ip = ":".join(f"{sockaddr_bytes[i]:02x}{sockaddr_bytes[i+1]:02x}"
                                 for i in range(8, 24, 2))
                    return {"family": "AF_INET6", "address": ip, "port": port}

            return {"family": family}

        except Exception:
            return {}


class AntiAnalysisDetector:
    """Detector for anti-analysis techniques."""

    def __init__(self):
        """Initialize anti-analysis detector."""
        self.detections: List[Dict[str, Any]] = []
        self.detection_methods = [
            self._detect_debugger_presence,
            self._detect_vm_artifacts,
            self._detect_timing_attacks,
            self._detect_process_hollowing,
            self._detect_api_hooks,
            self._detect_sandbox_artifacts,
            self._detect_memory_protections,
            self._detect_code_obfuscation
        ]

    def scan(self, process_id: int) -> List[Dict[str, Any]]:
        """Scan process for anti-analysis techniques."""
        self.detections.clear()

        for method in self.detection_methods:
            try:
                method(process_id)
            except Exception as e:
                logger.error(f"Detection method failed: {e}")

        return self.detections

    def _detect_debugger_presence(self, process_id: int):
        """Detect debugger presence checks."""
        checks = []

        if platform.system() == "Windows":
            try:
                kernel32 = ctypes.windll.kernel32
                ntdll = ctypes.windll.ntdll

                is_debugger_present = kernel32.IsDebuggerPresent()
                if is_debugger_present:
                    checks.append("IsDebuggerPresent")

                remote_debugger = ctypes.c_bool()
                kernel32.CheckRemoteDebuggerPresent(
                    kernel32.GetCurrentProcess(),
                    ctypes.byref(remote_debugger)
                )
                if remote_debugger.value:
                    checks.append("CheckRemoteDebuggerPresent")

                class PEB(ctypes.Structure):
                    _fields_ = [("Reserved1", ctypes.c_byte * 2),
                               ("BeingDebugged", ctypes.c_byte),
                               ("Reserved2", ctypes.c_byte * 21)]

                peb = PEB()
                process_handle = kernel32.OpenProcess(0x0400 | 0x0010, False, process_id)
                if process_handle:
                    process_basic_info = ctypes.c_void_p()
                    return_length = ctypes.c_ulong()

                    ntdll.NtQueryInformationProcess(
                        process_handle,
                        0,
                        ctypes.byref(process_basic_info),
                        ctypes.sizeof(process_basic_info),
                        ctypes.byref(return_length)
                    )

                    if process_basic_info.value:
                        kernel32.ReadProcessMemory(
                            process_handle,
                            process_basic_info,
                            ctypes.byref(peb),
                            ctypes.sizeof(peb),
                            None
                        )

                        if peb.BeingDebugged:
                            checks.append("PEB.BeingDebugged")

                    kernel32.CloseHandle(process_handle)

            except Exception as e:
                logger.error(f"Debugger detection failed: {e}")

        elif platform.system() == "Linux":
            try:
                status_file = f"/proc/{process_id}/status"
                if os.path.exists(status_file):
                    with open(status_file, "r") as f:
                        status = f.read()
                        if "TracerPid:" in status:
                            tracer_line = [l for l in status.split("\n") if "TracerPid:" in l][0]
                            tracer_pid = int(tracer_line.split(":")[1].strip())
                            if tracer_pid != 0:
                                checks.append(f"TracerPid: {tracer_pid}")

                if os.path.exists("/proc/self/fd"):
                    fd_count = len(os.listdir("/proc/self/fd"))
                    if fd_count > 20:
                        checks.append(f"High FD count: {fd_count}")

            except Exception as e:
                logger.error(f"Linux debugger detection failed: {e}")

        if checks:
            self.detections.append({
                "type": "debugger_presence",
                "methods": checks,
                "severity": "high"
            })

    def _detect_vm_artifacts(self, process_id: int):
        """Detect virtual machine artifacts."""
        vm_indicators = []

        try:
            proc = psutil.Process(process_id)

            vm_processes = [
                "vmtoolsd", "vmwaretray", "vmwareuser",
                "vboxservice", "vboxtray",
                "qemu-ga", "spice-vdagent",
                "xenservice", "xen-detect"
            ]

            for p in psutil.process_iter(['name']):
                if p.info['name'] and any(vm in p.info['name'].lower() for vm in vm_processes):
                    vm_indicators.append(f"VM process: {p.info['name']}")

            vm_files = [
                r"C:\Windows\System32\drivers\vmci.sys",
                r"C:\Windows\System32\drivers\vmmouse.sys",
                r"C:\Windows\System32\drivers\vboxmouse.sys",
                r"C:\Windows\System32\drivers\vboxguest.sys",
                "/proc/xen",
                "/sys/class/dmi/id/product_name"
            ]

            for file_path in vm_files:
                if os.path.exists(file_path):
                    vm_indicators.append(f"VM file: {file_path}")

            if platform.system() == "Linux" and os.path.exists("/sys/class/dmi/id/product_name"):
                with open("/sys/class/dmi/id/product_name", "r") as f:
                    product = f.read().strip()
                    if any(vm in product.lower() for vm in ["vmware", "virtualbox", "qemu", "xen"]):
                        vm_indicators.append(f"DMI product: {product}")

        except Exception as e:
            logger.error(f"VM detection failed: {e}")

        if vm_indicators:
            self.detections.append({
                "type": "vm_artifacts",
                "indicators": vm_indicators,
                "severity": "medium"
            })

    def _detect_timing_attacks(self, process_id: int):
        """Detect timing-based anti-debugging."""
        timing_checks = []

        try:
            start_time = time.perf_counter()
            time.sleep(0.001)
            elapsed = time.perf_counter() - start_time

            if elapsed > 0.01:
                timing_checks.append(f"Sleep timing anomaly: {elapsed:.6f}s")

            if platform.system() == "Windows":
                kernel32 = ctypes.windll.kernel32

                tick1 = kernel32.GetTickCount()
                time.sleep(0.001)
                tick2 = kernel32.GetTickCount()

                if tick2 - tick1 > 10:
                    timing_checks.append(f"GetTickCount anomaly: {tick2 - tick1}ms")

                class LARGE_INTEGER(ctypes.Structure):
                    _fields_ = [("QuadPart", ctypes.c_longlong)]

                freq = LARGE_INTEGER()
                counter1 = LARGE_INTEGER()
                counter2 = LARGE_INTEGER()

                kernel32.QueryPerformanceFrequency(ctypes.byref(freq))
                kernel32.QueryPerformanceCounter(ctypes.byref(counter1))
                time.sleep(0.001)
                kernel32.QueryPerformanceCounter(ctypes.byref(counter2))

                elapsed_qpc = (counter2.QuadPart - counter1.QuadPart) / freq.QuadPart
                if elapsed_qpc > 0.01:
                    timing_checks.append(f"QueryPerformanceCounter anomaly: {elapsed_qpc:.6f}s")

            elif platform.system() == "Linux":
                import resource

                rusage1 = resource.getrusage(resource.RUSAGE_SELF)
                time.sleep(0.001)
                rusage2 = resource.getrusage(resource.RUSAGE_SELF)

                cpu_time = rusage2.ru_utime - rusage1.ru_utime
                if cpu_time > 0.01:
                    timing_checks.append(f"CPU time anomaly: {cpu_time:.6f}s")

        except Exception as e:
            logger.error(f"Timing detection failed: {e}")

        if timing_checks:
            self.detections.append({
                "type": "timing_attacks",
                "checks": timing_checks,
                "severity": "medium"
            })

    def _detect_process_hollowing(self, process_id: int):
        """Detect process hollowing indicators."""
        hollowing_indicators = []

        try:
            proc = psutil.Process(process_id)

            memory_maps = proc.memory_maps() if hasattr(proc, "memory_maps") else []
            executable_regions = [m for m in memory_maps if "x" in getattr(m, "perms", "")]

            if len(executable_regions) > 10:
                hollowing_indicators.append(f"Excessive executable regions: {len(executable_regions)}")

            unmapped_exec = [m for m in executable_regions if not getattr(m, "path", None)]
            if unmapped_exec:
                hollowing_indicators.append(f"Unmapped executable regions: {len(unmapped_exec)}")

            memory_info = proc.memory_info()
            if memory_info.rss > memory_info.vms * 0.8:
                hollowing_indicators.append("Suspicious memory usage ratio")

        except Exception as e:
            logger.error(f"Process hollowing detection failed: {e}")

        if hollowing_indicators:
            self.detections.append({
                "type": "process_hollowing",
                "indicators": hollowing_indicators,
                "severity": "high"
            })

    def _detect_api_hooks(self, process_id: int):
        """Detect API hooking."""
        hooked_apis = []

        if platform.system() == "Windows":
            try:
                kernel32 = ctypes.windll.kernel32
                process_handle = kernel32.OpenProcess(0x0010, False, process_id)

                if process_handle:
                    common_apis = [
                        ("ntdll.dll", "NtQueryInformationProcess"),
                        ("kernel32.dll", "IsDebuggerPresent"),
                        ("kernel32.dll", "CheckRemoteDebuggerPresent"),
                        ("kernel32.dll", "CreateFileW"),
                        ("advapi32.dll", "RegOpenKeyExW")
                    ]

                    for dll_name, func_name in common_apis:
                        try:
                            dll_handle = kernel32.LoadLibraryW(dll_name)
                            if dll_handle:
                                func_addr = kernel32.GetProcAddress(dll_handle, func_name.encode())
                                if func_addr:
                                    first_bytes = (ctypes.c_byte * 5)()
                                    bytes_read = ctypes.c_size_t()

                                    if kernel32.ReadProcessMemory(
                                        process_handle,
                                        ctypes.c_void_p(func_addr),
                                        first_bytes,
                                        5,
                                        ctypes.byref(bytes_read)
                                    ):
                                        if first_bytes[0] == 0xE9 or first_bytes[0] == 0xE8:
                                            hooked_apis.append(f"{dll_name}!{func_name}")

                                kernel32.FreeLibrary(dll_handle)
                        except Exception:
                            pass

                    kernel32.CloseHandle(process_handle)

            except Exception as e:
                logger.error(f"API hook detection failed: {e}")

        if hooked_apis:
            self.detections.append({
                "type": "api_hooks",
                "hooked_functions": hooked_apis,
                "severity": "high"
            })

    def _detect_sandbox_artifacts(self, process_id: int):
        """Detect sandbox environment indicators."""
        sandbox_indicators = []

        try:
            sandbox_files = [
                r"C:\agent\agent.py",
                r"C:\sandbox\starter.exe",
                "/tmp/.X11-unix",
                "/tmp/.wine-"
            ]

            for file_path in sandbox_files:
                if os.path.exists(file_path):
                    sandbox_indicators.append(f"Sandbox file: {file_path}")

            sandbox_processes = ["python", "analyzer", "agent", "monitor"]
            for p in psutil.process_iter(['name', 'cmdline']):
                if p.info['name'] and any(s in p.info['name'].lower() for s in sandbox_processes):
                    cmdline = p.info.get('cmdline', [])
                    if cmdline and any("sandbox" in arg.lower() for arg in cmdline if arg):
                        sandbox_indicators.append(f"Sandbox process: {p.info['name']}")

            try:
                hostname = socket.gethostname()
                if any(s in hostname.lower() for s in ["sandbox", "malware", "virus", "analysis"]):
                    sandbox_indicators.append(f"Suspicious hostname: {hostname}")
            except Exception:
                pass

            try:
                username = os.environ.get("USERNAME", os.environ.get("USER", ""))
                if any(s in username.lower() for s in ["sandbox", "admin", "test", "malware"]):
                    sandbox_indicators.append(f"Suspicious username: {username}")
            except Exception:
                pass

        except Exception as e:
            logger.error(f"Sandbox detection failed: {e}")

        if sandbox_indicators:
            self.detections.append({
                "type": "sandbox_artifacts",
                "indicators": sandbox_indicators,
                "severity": "medium"
            })

    def _detect_memory_protections(self, process_id: int):
        """Detect memory protection mechanisms."""
        protections = []

        try:
            proc = psutil.Process(process_id)

            memory_maps = proc.memory_maps() if hasattr(proc, "memory_maps") else []

            nx_regions = [m for m in memory_maps if "x" not in getattr(m, "perms", "") and "w" in getattr(m, "perms", "")]
            if nx_regions:
                protections.append(f"NX/DEP regions: {len(nx_regions)}")

            guard_pages = [m for m in memory_maps if getattr(m, "rss", 0) == 0 and getattr(m, "size", 0) > 0]
            if guard_pages:
                protections.append(f"Guard pages: {len(guard_pages)}")

            if platform.system() == "Windows":
                try:
                    kernel32 = ctypes.windll.kernel32
                    process_handle = kernel32.OpenProcess(0x0400, False, process_id)

                    if process_handle:
                        dep_flags = ctypes.c_ulong()
                        permanent = ctypes.c_bool()

                        result = kernel32.GetProcessDEPPolicy(
                            process_handle,
                            ctypes.byref(dep_flags),
                            ctypes.byref(permanent)
                        )

                        if result and dep_flags.value:
                            protections.append(f"DEP enabled: {hex(dep_flags.value)}")

                        kernel32.CloseHandle(process_handle)

                except Exception:
                    pass

        except Exception as e:
            logger.error(f"Memory protection detection failed: {e}")

        if protections:
            self.detections.append({
                "type": "memory_protections",
                "mechanisms": protections,
                "severity": "low"
            })

    def _detect_code_obfuscation(self, process_id: int):
        """Detect code obfuscation techniques."""
        obfuscation_indicators = []

        try:
            proc = psutil.Process(process_id)

            try:
                exe_path = proc.exe()
                if os.path.exists(exe_path):
                    with open(exe_path, "rb") as f:
                        header = f.read(4096)

                        entropy = self._calculate_entropy(header)
                        if entropy > 7.5:
                            obfuscation_indicators.append(f"High entropy: {entropy:.2f}")

                        if b"UPX" in header or b"ASPack" in header or b"Themida" in header:
                            obfuscation_indicators.append("Known packer signatures")

                        pe_header_offset = struct.unpack("<I", header[0x3C:0x40])[0] if len(header) > 0x40 else 0
                        if pe_header_offset > 0x1000:
                            obfuscation_indicators.append(f"Unusual PE header offset: {pe_header_offset:#x}")
            except Exception:
                pass

            memory_maps = proc.memory_maps() if hasattr(proc, "memory_maps") else []
            exec_regions = [m for m in memory_maps if "x" in getattr(m, "perms", "")]

            for region in exec_regions[:5]:
                if hasattr(region, "rss") and region.rss > 0:
                    try:
                        if platform.system() == "Windows":
                            kernel32 = ctypes.windll.kernel32
                            process_handle = kernel32.OpenProcess(0x0010, False, process_id)

                            if process_handle:
                                buffer = (ctypes.c_byte * 1024)()
                                bytes_read = ctypes.c_size_t()

                                base_addr = int(region.addr.split("-")[0], 16) if isinstance(region.addr, str) else region.addr

                                if kernel32.ReadProcessMemory(
                                    process_handle,
                                    ctypes.c_void_p(base_addr),
                                    buffer,
                                    1024,
                                    ctypes.byref(bytes_read)
                                ):
                                    entropy = self._calculate_entropy(bytes(buffer))
                                    if entropy > 7.0:
                                        obfuscation_indicators.append(f"High entropy region: {region.addr} ({entropy:.2f})")

                                kernel32.CloseHandle(process_handle)
                    except Exception:
                        pass

        except Exception as e:
            logger.error(f"Obfuscation detection failed: {e}")

        if obfuscation_indicators:
            self.detections.append({
                "type": "code_obfuscation",
                "indicators": obfuscation_indicators,
                "severity": "medium"
            })

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        frequency = defaultdict(int)
        for byte in data:
            frequency[byte] += 1

        entropy = 0.0
        data_len = len(data)

        for count in frequency.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability and probability * 2 or 0)

        return entropy


class BehavioralAnalyzer:
    """Main behavioral analysis orchestrator."""

    def __init__(self, binary_path: Path):
        """Initialize behavioral analyzer."""
        self.binary_path = binary_path
        self.qemu_config = QEMUConfig()
        self.qemu_controller = QEMUController(self.qemu_config)
        self.api_hooks = APIHookingFramework()
        self.anti_analysis = AntiAnalysisDetector()
        self.events: List[MonitorEvent] = []
        self.analysis_thread: Optional[threading.Thread] = None
        self.stop_flag = threading.Event()

    def run_analysis(self, duration: int = 60) -> Dict[str, Any]:
        """Run comprehensive behavioral analysis."""
        logger.info(f"Starting behavioral analysis of {self.binary_path}")

        results = {
            "binary": str(self.binary_path),
            "start_time": time.time(),
            "qemu_analysis": {},
            "api_monitoring": {},
            "anti_analysis": {},
            "behavioral_patterns": {},
            "network_activity": [],
            "file_operations": [],
            "registry_activity": [],
            "process_activity": [],
            "summary": {}
        }

        try:
            if self.qemu_config.disk_image and self.qemu_config.disk_image.exists():
                logger.info("Starting QEMU-based analysis")
                results["qemu_analysis"] = self._run_qemu_analysis(duration)
            else:
                logger.info("QEMU disk image not configured, using native analysis")
                results["native_analysis"] = self._run_native_analysis(duration)

            logger.info("Performing API monitoring")
            results["api_monitoring"] = self._run_api_monitoring(duration)

            logger.info("Detecting anti-analysis techniques")
            process_id = self._get_target_process_id()
            if process_id:
                results["anti_analysis"]["detections"] = self.anti_analysis.scan(process_id)

            results["behavioral_patterns"] = self._analyze_behavioral_patterns()

            results["network_activity"] = [e.to_dict() for e in self.events if e.event_type.startswith("network_")]
            results["file_operations"] = [e.to_dict() for e in self.events if e.event_type.startswith("file_")]
            results["registry_activity"] = [e.to_dict() for e in self.events if e.event_type.startswith("registry_")]
            results["process_activity"] = [e.to_dict() for e in self.events if e.event_type.startswith("process_")]

            results["end_time"] = time.time()
            results["duration"] = results["end_time"] - results["start_time"]

            results["summary"] = self._generate_summary(results)

        except Exception as e:
            logger.error(f"Behavioral analysis failed: {e}")
            results["error"] = str(e)

        finally:
            self.cleanup()

        logger.info("Behavioral analysis complete")
        return results

    def _run_qemu_analysis(self, duration: int) -> Dict[str, Any]:
        """Run analysis in QEMU virtual machine."""
        qemu_results = {
            "started": False,
            "snapshots": [],
            "monitor_output": [],
            "events": []
        }

        try:
            if self.qemu_controller.start(self.binary_path):
                qemu_results["started"] = True

                initial_snapshot = "clean_state"
                if self.qemu_controller.take_snapshot(initial_snapshot):
                    qemu_results["snapshots"].append(initial_snapshot)

                monitor_output = self.qemu_controller.send_monitor_command("info registers")
                qemu_results["monitor_output"].append(monitor_output)

                vm_info = self.qemu_controller.send_qmp_command({"execute": "query-status"})
                qemu_results["vm_status"] = vm_info

                time.sleep(duration)

                infected_snapshot = "post_execution"
                if self.qemu_controller.take_snapshot(infected_snapshot):
                    qemu_results["snapshots"].append(infected_snapshot)

                self.qemu_controller.stop()

        except Exception as e:
            logger.error(f"QEMU analysis failed: {e}")
            qemu_results["error"] = str(e)

        return qemu_results

    def _run_native_analysis(self, duration: int) -> Dict[str, Any]:
        """Run analysis natively without virtualization."""
        native_results = {
            "process_started": False,
            "pid": None,
            "memory_usage": {},
            "cpu_usage": []
        }

        try:
            process = subprocess.Popen(
                [str(self.binary_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            native_results["process_started"] = True
            native_results["pid"] = process.pid

            proc = psutil.Process(process.pid)

            start_time = time.time()
            while time.time() - start_time < duration and process.poll() is None:
                try:
                    native_results["cpu_usage"].append(proc.cpu_percent())
                    mem_info = proc.memory_info()
                    native_results["memory_usage"] = {
                        "rss": mem_info.rss,
                        "vms": mem_info.vms,
                        "timestamp": time.time()
                    }
                    time.sleep(1)
                except psutil.NoSuchProcess:
                    break

            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

        except Exception as e:
            logger.error(f"Native analysis failed: {e}")
            native_results["error"] = str(e)

        return native_results

    def _run_api_monitoring(self, duration: int) -> Dict[str, Any]:
        """Run API monitoring."""
        monitoring_results = {
            "hooks_installed": 0,
            "events_captured": 0,
            "unique_apis_called": set()
        }

        try:
            for key in self.api_hooks.hooks:
                self.api_hooks.enable_hook(*key.split(":"))
                monitoring_results["hooks_installed"] += 1

            process = subprocess.Popen(
                [str(self.binary_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            context = {"pid": process.pid, "tid": threading.get_ident()}

            start_time = time.time()
            while time.time() - start_time < duration and process.poll() is None:
                time.sleep(0.1)

            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

            self.events.extend(self.api_hooks.events)
            monitoring_results["events_captured"] = len(self.api_hooks.events)

            for event in self.api_hooks.events:
                monitoring_results["unique_apis_called"].add(event.event_type)

            monitoring_results["unique_apis_called"] = list(monitoring_results["unique_apis_called"])

        except Exception as e:
            logger.error(f"API monitoring failed: {e}")
            monitoring_results["error"] = str(e)

        return monitoring_results

    def _analyze_behavioral_patterns(self) -> Dict[str, Any]:
        """Analyze captured events for behavioral patterns."""
        patterns = {
            "license_checks": [],
            "network_communications": [],
            "persistence_mechanisms": [],
            "data_exfiltration": [],
            "evasion_techniques": []
        }

        license_keywords = ["license", "serial", "key", "activation", "registration", "trial"]
        persistence_locations = [
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        ]

        for event in self.events:
            event_data = event.data

            if event.event_type in ["file_read", "file_write", "registry_query", "registry_set"]:
                for keyword in license_keywords:
                    if keyword in str(event_data).lower():
                        patterns["license_checks"].append(event.to_dict())
                        break

            if event.event_type.startswith("network_"):
                patterns["network_communications"].append(event.to_dict())

                if event.event_type == "network_send" and event_data.get("length", 0) > 1024:
                    patterns["data_exfiltration"].append(event.to_dict())

            if event.event_type in ["registry_set", "file_write"]:
                for location in persistence_locations:
                    if location.lower() in str(event_data).lower():
                        patterns["persistence_mechanisms"].append(event.to_dict())
                        break

        if self.anti_analysis.detections:
            patterns["evasion_techniques"] = self.anti_analysis.detections

        return patterns

    def _get_target_process_id(self) -> Optional[int]:
        """Get the process ID of the target binary."""
        target_name = self.binary_path.name.lower()

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.info['name'] and target_name in proc.info['name'].lower():
                    return proc.info['pid']
                if proc.info['exe'] and target_name in proc.info['exe'].lower():
                    return proc.info['pid']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return None

    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate analysis summary."""
        summary = {
            "total_events": len(self.events),
            "unique_event_types": len(set(e.event_type for e in self.events)),
            "suspicious_activities": 0,
            "risk_level": "low",
            "key_findings": []
        }

        if results.get("anti_analysis", {}).get("detections"):
            summary["suspicious_activities"] += len(results["anti_analysis"]["detections"])
            summary["key_findings"].append("Anti-analysis techniques detected")

        if results.get("behavioral_patterns", {}).get("license_checks"):
            summary["key_findings"].append("License validation mechanisms identified")

        if results.get("behavioral_patterns", {}).get("persistence_mechanisms"):
            summary["suspicious_activities"] += len(results["behavioral_patterns"]["persistence_mechanisms"])
            summary["key_findings"].append("Persistence mechanisms detected")

        if results.get("behavioral_patterns", {}).get("data_exfiltration"):
            summary["suspicious_activities"] += len(results["behavioral_patterns"]["data_exfiltration"])
            summary["key_findings"].append("Potential data exfiltration detected")

        if summary["suspicious_activities"] > 10:
            summary["risk_level"] = "high"
        elif summary["suspicious_activities"] > 5:
            summary["risk_level"] = "medium"

        return summary

    def cleanup(self):
        """Clean up resources."""
        self.stop_flag.set()

        if self.qemu_controller.is_running:
            self.qemu_controller.stop()

        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=5)


def create_behavioral_analyzer(binary_path: Path) -> BehavioralAnalyzer:
    """Factory function to create behavioral analyzer."""
    return BehavioralAnalyzer(binary_path)


def run_behavioral_analysis(binary_path: Path, duration: int = 60) -> Dict[str, Any]:
    """Run comprehensive behavioral analysis on a binary."""
    analyzer = create_behavioral_analyzer(binary_path)
    return analyzer.run_analysis(duration)
