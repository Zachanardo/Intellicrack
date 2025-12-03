#!/usr/bin/env python3
"""Qiling emulator interface for advanced binary emulation and analysis.

Qiling Binary Emulation Framework Integration.

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

import logging
import os
import tempfile
import threading
import time
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

from intellicrack.utils.logger import logger

from ...config import get_config


"""
Qiling Binary Emulation Framework Integration.

This module provides Qiling-based binary emulation capabilities for lightweight
dynamic analysis, API hooking, and runtime behavior monitoring without full
system emulation overhead.
"""


# Try to import Qiling
try:
    from qiling import Qiling
    from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
    from qiling.os.mapper import QlFsMappedObject

    QILING_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in qiling_emulator: %s", e)
    QILING_AVAILABLE = False
    Qiling = None
    QL_ARCH = None
    QL_OS = None
    QL_VERBOSE = None
    QlFsMappedObject = None

UNIX_TEMP_DIR = os.environ.get("UNIX_TEMP_DIR") or (tempfile.gettempdir() if os.name != "nt" else tempfile.gettempdir().replace("\\", "/"))


class QilingEmulator:
    """Lightweight binary emulator using Qiling framework.

    Provides fast binary-level emulation with API hooking, memory monitoring,
    and behavior analysis without the overhead of full system emulation.

    Features:
        - Multi-architecture support (x86, x64, ARM, MIPS)
        - API hooking and instrumentation
        - Memory access monitoring
        - File/Registry/Network emulation
        - License check detection
        - Fast execution compared to full VM
    """

    ARCH_MAPPING = {
        "x86": "x86" if QILING_AVAILABLE else None,
        "x64": "x86" if QILING_AVAILABLE else None,
        "x86_64": "x86" if QILING_AVAILABLE else None,
        "arm": "arm" if QILING_AVAILABLE else None,
        "arm64": "arm64" if QILING_AVAILABLE else None,
        "mips": "mips" if QILING_AVAILABLE else None,
    }

    OS_MAPPING = {
        "windows": "windows" if QILING_AVAILABLE else None,
        "linux": "linux" if QILING_AVAILABLE else None,
        "macos": "macos" if QILING_AVAILABLE else None,
        "freebsd": "freebsd" if QILING_AVAILABLE else None,
    }

    def __init__(
        self,
        binary_path: str,
        rootfs: str | None = None,
        ostype: str = "windows",
        arch: str = "x86_64",
        verbose: bool = False,
    ) -> None:
        """Initialize Qiling emulator.

        Args:
            binary_path: Path to binary to emulate
            rootfs: Root filesystem path (optional, auto-detected if None)
            ostype: Operating system type
            arch: Architecture type
            verbose: Enable verbose output

        """
        if not QILING_AVAILABLE:
            raise ImportError("Qiling framework not available. Install with: pip install qiling")

        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        self.binary_path = os.path.abspath(binary_path)
        self.ostype = ostype.lower()
        self.arch = arch.lower()
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)

        # Validate and map architecture using QL_ARCH constants
        self.ql_arch = self._get_ql_arch(self.arch)
        self.ql_os = self._get_ql_os(self.ostype)

        # Hooks storage
        self.api_hooks = {}
        self.memory_hooks = []
        self.code_hooks = []

        # Analysis results
        self.api_calls = []
        self.memory_accesses = []
        self.suspicious_behaviors = []
        self.license_checks = []
        self.mapped_files = []  # Track mapped files

        # Determine rootfs
        self.rootfs = rootfs or self._get_default_rootfs()
        # Qiling instance (created on run)
        self.ql = None

        self.logger.info("Qiling emulator initialized for %s/%s", self.ostype, self.arch)

    def _get_ql_arch(self, arch: str) -> int | None:
        """Convert architecture string to QL_ARCH constant."""
        if not QILING_AVAILABLE or not QL_ARCH:
            return None

        arch_map = {
            "x86": QL_ARCH.X86,
            "x64": QL_ARCH.X8664,
            "x86_64": QL_ARCH.X8664,
            "arm": QL_ARCH.ARM,
            "arm64": QL_ARCH.ARM64,
            "aarch64": QL_ARCH.ARM64,
            "mips": QL_ARCH.MIPS,
            "mips64": QL_ARCH.MIPS64,
            "ppc": QL_ARCH.PPC,
            "ppc64": QL_ARCH.PPC64,
            "riscv": QL_ARCH.RISCV,
            "riscv64": QL_ARCH.RISCV64,
        }

        return arch_map.get(arch.lower(), QL_ARCH.X8664)

    def _get_ql_os(self, ostype: str) -> int | None:
        """Convert OS type string to QL_OS constant."""
        if not QILING_AVAILABLE or not QL_OS:
            return None

        os_map = {
            "windows": QL_OS.WINDOWS,
            "linux": QL_OS.LINUX,
            "macos": QL_OS.MACOS,
            "darwin": QL_OS.MACOS,
            "freebsd": QL_OS.FREEBSD,
            "qnx": QL_OS.QNX,
            "dos": QL_OS.DOS,
            "uefi": QL_OS.UEFI,
        }

        return os_map.get(ostype.lower(), QL_OS.WINDOWS)

    def _get_default_rootfs(self) -> str:
        """Get default rootfs path for the OS type."""
        # Get config instance
        config = get_config()

        # Retrieve configured paths from vm_framework.qiling_rootfs based on ostype
        config_key = f"vm_framework.qiling_rootfs.{self.ostype}"
        configured_paths = config.get(config_key, [])

        # Iterate through configured paths
        for path in configured_paths:
            # Apply os.path.expanduser to each path
            expanded_path = os.path.expanduser(path)
            # Check if path exists
            if os.path.exists(expanded_path):
                return expanded_path

        # If no configured path exists, fallback to current logic
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        rootfs_dirs = [
            os.path.join(os.path.dirname(__file__), "rootfs", self.ostype),
            os.path.join(str(Path.cwd()), "rootfs", self.ostype),
            os.path.join(project_root, "tools", "qiling", "rootfs", self.ostype),
            os.path.join(os.path.expanduser("~"), ".qiling", "rootfs", self.ostype),
        ]

        for rootfs in rootfs_dirs:
            if os.path.exists(rootfs):
                return rootfs

        # Return default path for Qiling to handle
        return os.path.join(os.path.dirname(__file__), "rootfs", self.ostype)

    def add_api_hook(self, api_name: str, hook_func: Callable) -> None:
        """Add hook for specific API call.

        Args:
            api_name: Name of API to hook (e.g., 'CreateFileW')
            hook_func: Function to call when API is invoked

        """
        self.api_hooks[api_name.lower()] = hook_func

    def map_file_to_fs(self, host_path: str, guest_path: str) -> None:
        """Map a host file or directory to the emulated filesystem.

        Args:
            host_path: Path on the host system
            guest_path: Path in the emulated filesystem

        """
        if not QILING_AVAILABLE or not QlFsMappedObject:
            self.logger.warning("QlFsMappedObject not available")
            return

        if not os.path.exists(host_path):
            raise FileNotFoundError(f"Host path not found: {host_path}")

        self.mapped_files.append(
            {
                "host": host_path,
                "guest": guest_path,
                "type": "directory" if Path(host_path).is_dir() else "file",
            },
        )

        self.logger.info("Mapped %s -> %s", host_path, guest_path)

    def setup_filesystem_mappings(self) -> None:
        """Set up common filesystem mappings for license files."""
        if not self.ql:
            return

        # Map common license file locations
        license_paths = [
            # Windows common paths
            ("C:\\ProgramData", "/ProgramData"),
            ("C:\\Windows\\System32\\drivers\\etc", "/Windows/System32/drivers/etc"),
            # Linux common paths
            ("/etc", "/etc"),
            ("/usr/share", "/usr/share"),
            ("/var/lib", "/var/lib"),
        ]

        for host, guest in license_paths:
            if self.ql_os == QL_OS.WINDOWS and guest.startswith("/"):
                guest = "C:" + guest.replace("/", "\\")

            try:
                if hasattr(self.ql, "os") and hasattr(self.ql.os, "fs_mapper"):
                    # Use QlFsMappedObject for advanced mapping
                    mapped_obj = QlFsMappedObject(host, guest)
                    self.ql.os.fs_mapper.add_fs_mapping(mapped_obj)
                    self.mapped_files.append(
                        {
                            "host": host,
                            "guest": guest,
                            "mapped_object": mapped_obj,
                        },
                    )
            except (AttributeError, OSError) as e:
                self.logger.debug("Could not map %s: %s", host, e)

    def add_license_detection_hooks(self) -> None:
        """Add hooks for common license check patterns."""
        license_apis = [
            # Windows Registry APIs
            "RegOpenKeyExA",
            "RegOpenKeyExW",
            "RegQueryValueExA",
            "RegQueryValueExW",
            "RegCreateKeyExA",
            "RegCreateKeyExW",
            "RegSetValueExA",
            "RegSetValueExW",
            # File APIs (license files)
            "CreateFileA",
            "CreateFileW",
            "ReadFile",
            "WriteFile",
            # Network APIs (license servers)
            "connect",
            "send",
            "recv",
            "InternetOpenA",
            "InternetOpenW",
            "HttpSendRequestA",
            "HttpSendRequestW",
            # Crypto APIs (license validation)
            "CryptHashData",
            "CryptVerifySignature",
            "CryptDecrypt",
            "CryptEncrypt",
            # Time APIs (trial periods)
            "GetSystemTime",
            "GetLocalTime",
            "GetTickCount",
            "GetTickCount64",
            # Hardware ID APIs
            "GetVolumeInformationA",
            "GetVolumeInformationW",
            "GetComputerNameA",
            "GetComputerNameW",
        ]

        for api in license_apis:
            self.add_api_hook(api, self._license_api_hook)

    def _license_api_hook(self, ql: Qiling, address: int, params: dict) -> None:
        """Monitor license-related API calls."""
        api_name = ql.os.user_defined_api_name or "Unknown"

        # Log the API call
        self.api_calls.append(
            {
                "api": api_name,
                "address": hex(address),
                "params": params,
                "timestamp": time.time(),
            },
        )

        # Check for suspicious patterns
        if any(keyword in str(params).lower() for keyword in ["license", "serial", "key", "trial", "activation", "registration"]):
            self.license_checks.append(
                {
                    "api": api_name,
                    "address": hex(address),
                    "params": params,
                    "type": "direct_check",
                },
            )

        # Log potential license check
        self.logger.info(f"Potential license API: {api_name} at {hex(address)}")

    def hook_memory_access(self, ql: Qiling, access: int, address: int, size: int, value: int) -> None:
        """Monitor memory access with detailed analysis."""
        access_type = "READ" if access == 1 else "WRITE"

        # Extract current CPU state from Qiling object
        cpu_state = {}
        try:
            if hasattr(ql, "arch") and hasattr(ql.arch, "regs"):
                if hasattr(ql.arch.regs, "eip"):  # x86
                    cpu_state["pc"] = hex(ql.arch.regs.eip)
                elif hasattr(ql.arch.regs, "rip"):  # x64
                    cpu_state["pc"] = hex(ql.arch.regs.rip)
                elif hasattr(ql.arch.regs, "pc"):  # ARM
                    cpu_state["pc"] = hex(ql.arch.regs.pc)

                # Get stack pointer
                if hasattr(ql.arch.regs, "esp"):
                    cpu_state["sp"] = hex(ql.arch.regs.esp)
                elif hasattr(ql.arch.regs, "rsp"):
                    cpu_state["sp"] = hex(ql.arch.regs.rsp)
                elif hasattr(ql.arch.regs, "sp"):
                    cpu_state["sp"] = hex(ql.arch.regs.sp)
        except Exception as e:
            self.logger.debug(f"Failed to extract CPU state: {e}")

        # Try to read memory content around the access
        memory_content = None
        try:
            if access == 1 and size <= 32:  # READ access, reasonable size
                memory_content = ql.mem.read(address, size).hex()
        except Exception as e:
            self.logger.debug(f"Failed to read memory at {hex(address)}: {e}")

        # Check if this is a stack access
        is_stack_access = False
        if cpu_state.get("sp"):
            try:
                stack_addr = int(cpu_state["sp"], 16)
                is_stack_access = abs(address - stack_addr) < 0x10000  # Within 64KB of stack
            except (ValueError, TypeError):
                pass

        self.memory_accesses.append(
            {
                "type": access_type,
                "address": hex(address),
                "size": size,
                "value": hex(value) if access == 2 else None,
                "memory_content": memory_content,
                "cpu_state": cpu_state,
                "is_stack_access": is_stack_access,
                "timestamp": time.time(),
            },
        )

    def hook_code_execution(self, ql: Qiling, address: int, size: int) -> None:
        """Monitor code execution."""
        # Could add disassembly here if needed

    def run(self, timeout: int | None = 60, until_address: int | None = None) -> dict[str, Any]:
        """Run the binary emulation.

        Args:
            timeout: Maximum execution time in seconds
            until_address: Run until this address is reached

        Returns:
            Dictionary containing analysis results

        """
        start_time = time.time()
        timeout_occurred = False
        timeout_timer = None

        def timeout_handler() -> None:
            """Handle timeout by stopping emulation."""
            nonlocal timeout_occurred
            timeout_occurred = True
            if self.ql:
                try:
                    self.ql.emu_stop()
                    self.logger.warning(
                        "Emulation stopped due to timeout after %d seconds",
                        timeout,
                    )
                except (RuntimeError, AttributeError) as e:
                    logger.error("Error in qiling_emulator: %s", e)

        try:
            # Create Qiling instance
            argv = [self.binary_path]

            # Set verbosity
            verbose = QL_VERBOSE.DEBUG if self.verbose else QL_VERBOSE.OFF

            # Initialize Qiling with proper arch and OS constants
            init_params = {
                "argv": argv,
                "verbose": verbose,
            }

            # Add architecture and OS if available
            if self.ql_arch is not None:
                init_params["archtype"] = self.ql_arch
            if self.ql_os is not None:
                init_params["ostype"] = self.ql_os

            # Add rootfs if exists
            if os.path.exists(self.rootfs):
                init_params["rootfs"] = self.rootfs

            self.ql = Qiling(**init_params)

            # Setup filesystem mappings
            self.setup_filesystem_mappings()

            # Add license detection hooks
            self.add_license_detection_hooks()

            # Set up memory hooks
            self.ql.hook_mem_read(self.hook_memory_access)
            self.ql.hook_mem_write(self.hook_memory_access)

            # Set up code hooks
            self.ql.hook_code(self.hook_code_execution)

            # Apply API hooks
            for api_name, hook_func in self.api_hooks.items():
                try:
                    self.ql.set_api(api_name, hook_func)
                except (AttributeError, KeyError, RuntimeError) as e:
                    logger.error("Error in qiling_emulator: %s", e)
                    # API might not exist for this OS

            # Set up timeout if specified
            if timeout and timeout > 0:
                timeout_timer = threading.Timer(timeout, timeout_handler)
                timeout_timer.daemon = True
                timeout_timer.start()
                self.logger.debug("Set emulation timeout to %d seconds", timeout)

            # Run emulation
            if until_address:
                self.ql.run(end=until_address)
            else:
                self.ql.run()

            # Cancel timeout timer if emulation completed before timeout
            if timeout_timer and timeout_timer.is_alive():
                timeout_timer.cancel()

            execution_time = time.time() - start_time

            # Analyze results
            results = self._analyze_results()
            results["execution_time"] = execution_time
            results["timeout_occurred"] = timeout_occurred
            results["timeout_limit"] = timeout or None

            if timeout_occurred:
                results["status"] = "timeout"
                self.logger.info("Emulation timed out after %.2f seconds", execution_time)
            else:
                results["status"] = "success"

            return results

        except (OSError, ValueError, RuntimeError) as e:
            # Cancel timeout timer if it's still running
            if timeout_timer and timeout_timer.is_alive():
                timeout_timer.cancel()

            self.logger.error("Qiling emulation error: %s", e)
            self.logger.debug(traceback.format_exc())

            return {
                "status": "error",
                "error": str(e),
                "execution_time": time.time() - start_time,
                "timeout_occurred": timeout_occurred,
                "timeout_limit": timeout or None,
                "api_calls": self.api_calls,
                "memory_accesses": self.memory_accesses,
                "license_checks": self.license_checks,
            }

        finally:
            # Cancel timeout timer if it's still running
            if timeout_timer and timeout_timer.is_alive():
                timeout_timer.cancel()

            # Cleanup
            if self.ql:
                try:
                    self.ql.emu_stop()
                except (RuntimeError, AttributeError) as e:
                    logger.error("Error in qiling_emulator: %s", e)

    def get_arch_info(self) -> dict[str, Any]:
        """Get detailed architecture information using QL_ARCH constants."""
        if not QILING_AVAILABLE or not QL_ARCH or not self.ql_arch:
            return {"arch": self.arch, "bits": 32 if "86" in self.arch else 64}

        arch_info = {
            "arch_string": self.arch,
            "ql_arch": self.ql_arch,
            "bits": 32,
            "endianness": "little",
            "instruction_set": "unknown",
        }

        # Determine architecture details
        if self.ql_arch in [QL_ARCH.X86]:
            arch_info |= {
                "bits": 32,
                "instruction_set": "x86",
                "registers": [
                    "eax",
                    "ebx",
                    "ecx",
                    "edx",
                    "esi",
                    "edi",
                    "ebp",
                    "esp",
                ],
            }
        elif self.ql_arch in [QL_ARCH.X8664]:
            arch_info |= {
                "bits": 64,
                "instruction_set": "x86_64",
                "registers": [
                    "rax",
                    "rbx",
                    "rcx",
                    "rdx",
                    "rsi",
                    "rdi",
                    "rbp",
                    "rsp",
                    "r8",
                    "r9",
                    "r10",
                    "r11",
                    "r12",
                    "r13",
                    "r14",
                    "r15",
                ],
            }
        elif self.ql_arch in [QL_ARCH.ARM]:
            arch_info |= {
                "bits": 32,
                "instruction_set": "arm",
                "registers": [
                    "r0",
                    "r1",
                    "r2",
                    "r3",
                    "r4",
                    "r5",
                    "r6",
                    "r7",
                    "r8",
                    "r9",
                    "r10",
                    "r11",
                    "r12",
                    "sp",
                    "lr",
                    "pc",
                ],
            }
        elif self.ql_arch in [QL_ARCH.ARM64]:
            arch_info |= {
                "bits": 64,
                "instruction_set": "aarch64",
                "registers": [
                    "x0",
                    "x1",
                    "x2",
                    "x3",
                    "x4",
                    "x5",
                    "x6",
                    "x7",
                    "x8",
                    "x9",
                    "x10",
                    "x11",
                    "x12",
                    "x13",
                    "x14",
                    "x15",
                    "x16",
                    "x17",
                    "x18",
                    "x19",
                    "x20",
                    "x21",
                    "x22",
                    "x23",
                    "x24",
                    "x25",
                    "x26",
                    "x27",
                    "x28",
                    "x29",
                    "x30",
                    "sp",
                ],
            }
        elif self.ql_arch in [QL_ARCH.MIPS, QL_ARCH.MIPS64]:
            arch_info |= {
                "bits": 64 if self.ql_arch == QL_ARCH.MIPS64 else 32,
                "instruction_set": "mips",
                "endianness": "big",  # MIPS is typically big-endian
                "registers": [
                    "zero",
                    "at",
                    "v0",
                    "v1",
                    "a0",
                    "a1",
                    "a2",
                    "a3",
                    "t0",
                    "t1",
                    "t2",
                    "t3",
                    "t4",
                    "t5",
                    "t6",
                    "t7",
                    "s0",
                    "s1",
                    "s2",
                    "s3",
                    "s4",
                    "s5",
                    "s6",
                    "s7",
                    "t8",
                    "t9",
                    "k0",
                    "k1",
                    "gp",
                    "sp",
                    "fp",
                    "ra",
                ],
            }

        return arch_info

    def get_os_info(self) -> dict[str, Any]:
        """Get detailed OS information using QL_OS constants."""
        if not QILING_AVAILABLE or not QL_OS or not self.ql_os:
            return {"os": self.ostype, "family": "unknown"}

        os_info = {
            "os_string": self.ostype,
            "ql_os": self.ql_os,
            "family": "unknown",
            "syscall_convention": "unknown",
            "executable_format": "unknown",
        }

        # Determine OS details
        if self.ql_os == QL_OS.WINDOWS:
            os_info |= {
                "family": "windows",
                "syscall_convention": "stdcall",
                "executable_format": "PE",
                "path_separator": "\\",
                "common_dirs": [
                    "C:\\Windows",
                    "C:\\Program Files",
                    "C:\\ProgramData",
                ],
            }
        elif self.ql_os == QL_OS.LINUX:
            os_info |= {
                "family": "unix",
                "syscall_convention": "sysv",
                "executable_format": "ELF",
                "path_separator": "/",
                "common_dirs": [
                    "/usr",
                    "/etc",
                    "/var",
                    UNIX_TEMP_DIR,
                    "/home",
                ],
            }
        elif self.ql_os == QL_OS.MACOS:
            os_info |= {
                "family": "unix",
                "syscall_convention": "sysv",
                "executable_format": "Mach-O",
                "path_separator": "/",
                "common_dirs": ["/Applications", "/Library", "/System", "/Users"],
            }
        elif self.ql_os == QL_OS.FREEBSD:
            os_info |= {
                "family": "bsd",
                "syscall_convention": "sysv",
                "executable_format": "ELF",
                "path_separator": "/",
                "common_dirs": ["/usr", "/etc", "/var", "/tmp"],  # noqa: S108
            }

        return os_info

    def _analyze_results(self) -> dict[str, Any]:
        """Analyze emulation results for suspicious behavior."""
        # Count API categories
        api_categories = {
            "registry": 0,
            "file": 0,
            "network": 0,
            "crypto": 0,
            "time": 0,
            "hardware": 0,
        }

        for api_call in self.api_calls:
            api_name = api_call["api"].lower()

            if "reg" in api_name:
                api_categories["registry"] += 1
            elif any(x in api_name for x in ["file", "read", "write"]):
                api_categories["file"] += 1
            elif any(x in api_name for x in ["connect", "send", "recv", "internet", "http"]):
                api_categories["network"] += 1
            elif "crypt" in api_name:
                api_categories["crypto"] += 1
            elif any(x in api_name for x in ["time", "tick"]):
                api_categories["time"] += 1
            elif any(x in api_name for x in ["volume", "computer", "hardware"]):
                api_categories["hardware"] += 1

        # Detect suspicious patterns
        if api_categories["registry"] > 5 and api_categories["crypto"] > 0:
            self.suspicious_behaviors.append(
                {
                    "type": "license_check",
                    "confidence": "high",
                    "reason": "Heavy registry access with cryptography",
                },
            )

        if api_categories["network"] > 0 and api_categories["hardware"] > 0:
            self.suspicious_behaviors.append(
                {
                    "type": "online_activation",
                    "confidence": "medium",
                    "reason": "Network communication with hardware ID access",
                },
            )

        if api_categories["time"] > 3:
            self.suspicious_behaviors.append(
                {
                    "type": "trial_check",
                    "confidence": "medium",
                    "reason": "Multiple time-related API calls",
                },
            )

        return {
            "api_calls": self.api_calls,
            "api_categories": api_categories,
            "memory_accesses": len(self.memory_accesses),
            "license_checks": self.license_checks,
            "suspicious_behaviors": self.suspicious_behaviors,
            "total_api_calls": len(self.api_calls),
            "arch_info": self.get_arch_info(),
            "os_info": self.get_os_info(),
            "mapped_files": self.mapped_files,
        }

    def emulate_with_patches(self, patches: list[dict[str, Any]]) -> dict[str, Any]:
        r"""Run emulation with runtime patches applied.

        Args:
            patches: List of patches to apply
                    [{'address': 0x1000, 'bytes': b'\x90\x90'}, ...]

        Returns:
            Analysis results after patching

        """

        # Apply patches during emulation
        def apply_patches(ql: Qiling) -> None:
            """Apply memory patches to the emulated process.

            Args:
                ql: Qiling instance to apply patches to

            Iterates through the patches list and writes the specified bytes
            to the given memory addresses in the emulated process.

            """
            for patch in patches:
                addr = patch["address"]
                data = patch["bytes"]
                ql.mem.write(addr, data)
                self.logger.info(f"Applied patch at {hex(addr)}: {data.hex()}")

        # Hook to apply patches after loading
        self.ql.hook_code(apply_patches, begin=0, end=0, user_data=None)

        # Run normal emulation
        return self.run()

    def detect_binary_format(self) -> dict[str, Any]:
        """Detect binary format using architecture and OS information.

        Returns:
            Dictionary with format details including:
            - format: PE/ELF/Mach-O/etc
            - arch: Architecture details
            - os: OS details
            - entry_point: Entry point if detectable

        """
        format_info = {
            "format": "unknown",
            "arch": self.get_arch_info(),
            "os": self.get_os_info(),
            "entry_point": None,
            "sections": [],
            "imports": [],
        }

        try:
            # Try PE format detection
            from intellicrack.handlers.pefile_handler import pefile

            pe = pefile.PE(self.binary_path)
            format_info["format"] = "PE"
            format_info["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

            # Get sections
            for section in pe.sections:
                format_info["sections"].append(
                    {
                        "name": section.Name.decode("utf-8").rstrip("\x00"),
                        "virtual_address": hex(section.VirtualAddress),
                        "size": section.SizeOfRawData,
                    },
                )

            # Get imports
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8")
                    format_info["imports"].append(
                        {
                            "dll": dll_name,
                            "functions": [imp.name.decode("utf-8") if imp.name else f"Ordinal_{imp.ordinal}" for imp in entry.imports],
                        },
                    )

        except (ImportError, pefile.PEFormatError):
            # Try ELF format
            try:
                with open(self.binary_path, "rb") as f:
                    magic = f.read(4)
                    if magic == b"\x7fELF":
                        format_info["format"] = "ELF"
                        # Basic ELF parsing
                        f.seek(0x18)  # e_entry offset for 64-bit
                        entry = int.from_bytes(f.read(8), "little")
                        format_info["entry_point"] = hex(entry)
                    elif magic[:2] == b"MZ":
                        format_info["format"] = "PE"  # DOS header
                    elif magic in [
                        b"\xce\xfa\xed\xfe",
                        b"\xfe\xed\xfa\xce",
                        b"\xce\xfa\xed\xfe",
                        b"\xfe\xed\xfa\xcf",
                    ]:
                        format_info["format"] = "Mach-O"
            except Exception as e:
                logger.debug("Error reading binary file for format detection: %s", e)

        return format_info


def run_qiling_emulation(binary_path: str, options: dict[str, Any] = None) -> dict[str, Any]:
    """High-level function to run Qiling emulation on a binary.

    Args:
        binary_path: Path to binary file
        options: Emulation options

    Returns:
        Dictionary with emulation results

    """
    if not QILING_AVAILABLE:
        return {
            "status": "error",
            "error": "Qiling not installed. Run: pip install qiling",
        }

    options = options or {}

    try:
        # Detect OS and architecture
        try:
            from intellicrack.handlers.pefile_handler import pefile
        except ImportError as e:
            logger.error("Import error in qiling_emulator: %s", e)
            pefile = None

        ostype = "windows"  # Default
        arch = "x86_64"  # Default

        # Try to detect from binary
        try:
            pe = pefile.PE(binary_path)
            if pe.FILE_HEADER.Machine == 0x14C:
                arch = "x86"
            elif pe.FILE_HEADER.Machine == 0x8664:
                arch = "x86_64"
            ostype = "windows"
        except (OSError, pefile.PEFormatError, AttributeError) as e:
            logger.error("Error in qiling_emulator: %s", e)
            # Try ELF
            with open(binary_path, "rb") as f:
                magic = f.read(4)
                if magic[:4] == b"\x7fELF":
                    ostype = "linux"
                    # Could parse ELF header for arch

        # Create emulator
        emulator = QilingEmulator(
            binary_path=binary_path,
            ostype=options.get("ostype", ostype),
            arch=options.get("arch", arch),
            verbose=options.get("verbose", False),
        )

        # Get binary format info
        format_info = emulator.detect_binary_format()

        # Run emulation
        results = emulator.run(
            timeout=options.get("timeout", 60),
            until_address=options.get("until_address"),
        )

        # Add format info to results
        results["binary_format"] = format_info

        return results

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Qiling emulation failed: %s", e)
        return {
            "status": "error",
            "error": str(e),
        }


# Export public API
__all__ = ["QILING_AVAILABLE", "QilingEmulator", "run_qiling_emulation"]
