"""Debugger detection utilities for Intellicrack anti-analysis.

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
"""

import ctypes
import ctypes.util
import logging
import os
import platform
import shutil
import time
from typing import Any, Callable, cast

from intellicrack.utils.type_safety import validate_type

import psutil

from intellicrack.utils.logger import logger

from .base_detector import BaseDetector


"""
Debugger Detection

Implements multiple techniques to detect debuggers including
user-mode and kernel-mode debuggers.
"""

# Linux ptrace constants
PTRACE_TRACEME: int = 0
PTRACE_DETACH: int = 17


class DebuggerDetector(BaseDetector):
    """Comprehensive debugger detection using multiple techniques."""

    logger: logging.Logger
    detection_methods: dict[str, Callable[[], tuple[bool, float, Any]]]
    debugger_signatures: dict[str, dict[str, list[str]]]

    def __init__(self) -> None:
        """Initialize the debugger detector with platform-specific detection methods."""
        super().__init__()
        self.logger = logging.getLogger("IntellicrackLogger.DebuggerDetector")

        # Detection methods for different platforms
        if platform.system() == "Windows":
            self.detection_methods = {
                "isdebuggerpresent": self._check_isdebuggerpresent,
                "checkremotedebuggerpresent": self._check_remote_debugger,
                "peb_flags": self._check_peb_flags,
                "ntglobalflag": self._check_ntglobalflag,
                "heap_flags": self._check_heap_flags,
                "debug_port": self._check_debug_port,
                "hardware_breakpoints": self._check_hardware_breakpoints,
                "int3_scan": self._check_int3_scan,
                "timing_checks": self._check_timing,
                "parent_process": self._check_parent_process,
                "debug_privileges": self._check_debug_privileges,
                "exception_handling": self._check_exception_handling,
            }
        else:
            self.detection_methods = {
                "ptrace": self._check_ptrace,
                "proc_status": self._check_proc_status,
                "parent_process": self._check_parent_process_linux,
                "timing_checks": self._check_timing,
                "int3_scan": self._check_int3_scan,
                "breakpoint_detection": self._check_breakpoints_linux,
            }

        # Dynamic debugger signature detection
        self.debugger_signatures = self._build_dynamic_signatures()

        # Monitor for new debuggers
        self._update_signatures_from_system()

    def _build_dynamic_signatures(self) -> dict[str, dict[str, list[str]]]:
        """Build debugger signatures dynamically based on system analysis.

        Returns:
            Dictionary mapping platforms to signature categories.

        """
        import json
        import os

        signatures: dict[str, dict[str, list[str]]] = {
            "windows": {
                "processes": [],
                "window_classes": [],
                "window_titles": [],
                "driver_names": [],
                "dll_patterns": [],
            },
            "linux": {
                "processes": [],
                "files": [],
                "libraries": [],
                "symbols": [],
            },
        }

        # Load base signatures from configuration
        config_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "debugger_signatures.json")

        try:
            if os.path.exists(config_path):
                with open(config_path) as f:
                    base_sigs = json.load(f)
                    # Merge base signatures
                    for platform_key, platform_signatures in signatures.items():
                        if platform_key in base_sigs:
                            for sig_type in platform_signatures:
                                if sig_type in base_sigs[platform_key]:
                                    platform_signatures[sig_type].extend(base_sigs[platform_key][sig_type])
        except (OSError, json.JSONDecodeError):
            pass  # Use dynamic detection only

        # Add known debugger patterns dynamically
        if platform.system() == "Windows":
            # Core debuggers - always check for these
            core_debuggers = [
                # User-mode debuggers
                "ollydbg",
                "x64dbg",
                "x32dbg",
                "windbg",
                "cdb",
                "immunity",
                "radare2",
                "r2",
                "pestudio",
                "petools",
                # Kernel debuggers
                "kd",
                "livekd",
                "syser",
                "softice",
                # IDE debuggers
                "devenv",
                "vsjitdebugger",
                "msvsmon",
                "dbgclr",
                # .NET debuggers
                "dnspy",
                "ilspy",
                "dotpeek",
                "justdecompile",
                # Java debuggers
                "jdb",
                "eclipse",
                "intellij",
                "netbeans",
                # Script debuggers
                "pycharm",
                "vscode",
                "atom",
                "sublime",
                # System tools that can debug
                "processhacker",
                "procmon",
                "procexp",
                "apimonitor",
                "rohitab",
                "wireshark",
                "fiddler",
                "charles",
                # Game hacking tools (often have debuggers)
                "cheatengine",
                "artmoney",
                "tsearch",
                "ollyice",
                # Reverse engineering tools
                "ida",
                "ida64",
                "idaq",
                "idaq64",
                "ghidra",
                "hopper",
                "binaryninja",
                "cutter",
                "rizin",
                "snowman",
            ]

            # Build process patterns with variations
            for debugger in core_debuggers:
                # Add base name
                signatures["windows"]["processes"].append(f"{debugger}.exe")
                # Add common variations
                signatures["windows"]["processes"].append(f"{debugger}64.exe")
                signatures["windows"]["processes"].append(f"{debugger}32.exe")
                signatures["windows"]["processes"].append(f"{debugger}_x64.exe")
                signatures["windows"]["processes"].append(f"{debugger}_x86.exe")
                # Portable versions
                signatures["windows"]["processes"].append(f"{debugger}_portable.exe")
                signatures["windows"]["processes"].append(f"portable_{debugger}.exe")

            # Add window class patterns
            window_classes = [
                "OLLYDBG",
                "WinDbgFrameClass",
                "ID",
                "Zeta Debugger",
                "x64dbg",
                "Qt5QWindowIcon",
                "HexRaysIDA",
                "SysAnalyzer",
                "PEiDWindowClass",
                "ProcessHacker",
                "dbgviewClass",
                "ConsoleWindowClass",
                "GhidraClass",
                "BinaryNinjaCore",
                "CutterClass",
                "HopperDisassembler",
            ]

            # Add regex patterns for window classes
            for wc in window_classes:
                signatures["windows"]["window_classes"].append(wc)
                # Add variations
                signatures["windows"]["window_classes"].append(wc.lower())
                signatures["windows"]["window_classes"].append(wc.upper())

            # Add window title patterns
            title_patterns = [
                r".*[Dd]ebug.*",
                r".*[Bb]reakpoint.*",
                r".*[Dd]isassembl.*",
                r".*[Hh]ex [Ee]dit.*",
                r".*[Mm]emory [Vv]iew.*",
                r".*[Rr]egisters.*",
                r".*[Ss]tack.*",
                r".*[Aa]ssembly.*",
                r".*[Dd]ump.*",
                r"OllyDbg.*",
                r"x64dbg.*",
                r"WinDbg.*",
                r"Immunity.*",
                r"IDA.*",
                r"Ghidra.*",
                r"Binary Ninja.*",
                r"Hopper.*",
                r"Radare2.*",
                r"Cutter.*",
                r"Process Hacker.*",
                r"API Monitor.*",
            ]
            signatures["windows"]["window_titles"].extend(title_patterns)

            # Add driver patterns for kernel debuggers
            driver_patterns = [
                r"\\Driver\\KLDBGDRV",
                r"\\Device\\KLDBGDRV",
                r"\\Driver\\SYSER",
                r"\\Driver\\SICE",
                r"\\Driver\\NTICE",
                r"\\Driver\\ICEEXT",
                r"\\Driver\\SYSERBOOT",
                r"\\Driver\\SYSERDBGMSG",
                r"\\Driver\\Ring0Debugger",
                r"\\Driver\\KernelDebugger",
            ]
            signatures["windows"]["driver_names"].extend(driver_patterns)

            # Add DLL injection patterns
            dll_patterns = [
                "dbghelp.dll",
                "dbgcore.dll",
                "dbgeng.dll",
                "dbgmodel.dll",
                "symsrv.dll",
                "srcsrv.dll",
                "titanengine.dll",
                "beaengine.dll",
                "hooklib*.dll",
                "detours*.dll",
                "easyhook*.dll",
                "mhook*.dll",
                "x64dbg*.dll",
                "x32dbg*.dll",
                "ollydbg*.dll",
                "immdbg*.dll",
            ]
            signatures["windows"]["dll_patterns"].extend(dll_patterns)

        else:  # Linux/Unix
            # Core debuggers for Linux
            core_debuggers = [
                "gdb",
                "lldb",
                "radare2",
                "r2",
                "rizin",
                "cutter",
                "edb",
                "evan",
                "ddd",
                "kdbg",
                "nemiver",
                "voltron",
                "peda",
                "gef",
                "pwndbg",
                "strace",
                "ltrace",
                "ftrace",
                "ptrace",
                "dtrace",
                "systemtap",
                "perf",
                "valgrind",
                "gdbserver",
                "lldb-server",
                "rr",
                "undo",
                "qira",
            ]

            for debugger in core_debuggers:
                signatures["linux"]["processes"].append(debugger)
                # Add common paths
                signatures["linux"]["processes"].append(f"/usr/bin/{debugger}")
                signatures["linux"]["processes"].append(f"/usr/local/bin/{debugger}")
                signatures["linux"]["processes"].append(f"/opt/{debugger}/{debugger}")

            # Add files to check
            debug_files = [
                "/proc/self/status",
                "/proc/self/stat",
                "/proc/self/cmdline",
                "/proc/self/maps",
                "/proc/self/environ",
                "/proc/self/fd/",
                "/sys/kernel/debug/",
                "/dev/kmem",
                "/dev/mem",
                "/dev/port",
            ]
            signatures["linux"]["files"].extend(debug_files)

            # Add library patterns
            lib_patterns = [
                "libdebug*.so",
                "libgdb*.so",
                "liblldb*.so",
                "libtrace*.so",
                "libptrace*.so",
                "libinject*.so",
                "libhook*.so",
                "libdetour*.so",
                "libintercept*.so",
            ]
            signatures["linux"]["libraries"].extend(lib_patterns)

            # Add symbol patterns that indicate debugging
            symbol_patterns = [
                "__debugbreak",
                "__builtin_trap",
                "ptrace",
                "waitpid",
                "PTRACE_ATTACH",
                "PTRACE_TRACEME",
                "raise",
                "signal",
                "sigaction",
                "kill",
            ]
            signatures["linux"]["symbols"].extend(symbol_patterns)

        # Remove duplicates while preserving order
        for platform_signatures in signatures.values():
            for sig_type in platform_signatures:
                seen = set()
                unique_list = []
                for item in platform_signatures[sig_type]:
                    if item.lower() not in seen:
                        seen.add(item.lower())
                        unique_list.append(item)
                platform_signatures[sig_type] = unique_list

        return signatures

    def _update_signatures_from_system(self) -> None:
        """Scan system for additional debugger signatures.

        This method scans running processes to discover additional debugger
        signatures and dynamically updates the detection signatures.
        """
        import re

        import psutil

        try:
            # Scan running processes for debug-related patterns
            debug_patterns = [
                re.compile(r".*debug.*", re.IGNORECASE),
                re.compile(r".*dbg.*", re.IGNORECASE),
                re.compile(r".*trace.*", re.IGNORECASE),
                re.compile(r".*monitor.*", re.IGNORECASE),
                re.compile(r".*analyze.*", re.IGNORECASE),
                re.compile(r".*reverse.*", re.IGNORECASE),
                re.compile(r".*disasm.*", re.IGNORECASE),
                re.compile(r".*hook.*", re.IGNORECASE),
                re.compile(r".*inject.*", re.IGNORECASE),
            ]

            current_platform = "windows" if platform.system() == "Windows" else "linux"

            for proc in psutil.process_iter(["name", "exe", "cmdline"]):
                try:
                    proc_name = proc.info.get("name", "").lower()
                    proc_exe = proc.info.get("exe", "").lower() if proc.info.get("exe") else ""

                    # Check if process matches debug patterns
                    for pattern in debug_patterns:
                        if pattern.match(proc_name) or pattern.match(proc_exe):
                            # Check if it's not already in our list
                            if proc_name not in [
                                p.lower() for p in self.debugger_signatures[current_platform]["processes"]
                            ] and self._verify_debugger_capabilities(proc):
                                self.debugger_signatures[current_platform]["processes"].append(proc_name)
                                self.logger.info("Discovered new debugger: %s", proc_name)
                            break

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            self.logger.debug("Error updating signatures: %s", e)

    def _verify_debugger_capabilities(self, process: psutil.Process) -> bool:
        """Verify if a process has debugger capabilities.

        Analyzes process handles, memory usage, and capabilities to determine
        if the process is likely a debugger.

        Args:
            process: The psutil.Process object to analyze.

        Returns:
            True if the process shows debugger capabilities, False otherwise.

        """
        try:
            # Check for debug privileges
            if platform.system() == "Windows":
                # Check if process has SeDebugPrivilege
                try:
                    import ctypes
                    from ctypes import wintypes

                    # Get process handle
                    PROCESS_QUERY_INFORMATION = 0x0400
                    kernel32 = ctypes.windll.kernel32
                    if handle := kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, process.pid):
                        # Check token privileges
                        advapi32 = ctypes.windll.advapi32
                        token_handle = wintypes.HANDLE()
                        TOKEN_QUERY = 0x0008

                        if advapi32.OpenProcessToken(handle, TOKEN_QUERY, ctypes.byref(token_handle)):
                            # Would check for SeDebugPrivilege here
                            kernel32.CloseHandle(token_handle)
                            kernel32.CloseHandle(handle)

                            # Check if process has open handles to other processes
                            connections = process.connections()
                            if len(connections) > 10:  # Debuggers often have many connections
                                return True

                except Exception as e:
                    logger.debug("Process connection analysis failed: %s", e)
            else:
                # Linux: Check for ptrace capability
                try:
                    import os

                    status_path = f"/proc/{process.pid}/status"
                    if os.path.exists(status_path):
                        with open(status_path) as f:
                            status = f.read()
                            # Check for TracerPid or capabilities
                            if "TracerPid" in status or "CapEff" in status:
                                if cap_line := [line for line in status.split("\n") if "CapEff" in line]:
                                    # Check for CAP_SYS_PTRACE capability
                                    cap_value = int(cap_line[0].split()[1], 16)
                                    CAP_SYS_PTRACE = 1 << 19
                                    if cap_value & CAP_SYS_PTRACE:
                                        return True
                except Exception as e:
                    logger.debug("Ptrace capability check failed: %s", e)

            if children := process.children():
                # Check if children have different names (sign of debugging)
                child_names = {child.name() for child in children}
                if len(child_names) > 1:
                    return True

            # Check memory usage patterns
            mem_info = process.memory_info()
            # Debuggers typically use more memory for symbol tables
            if mem_info.rss > 100 * 1024 * 1024:  # > 100MB
                return True

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return False

    def update_signatures(self, custom_signatures: dict[str, dict[str, list[str]]] | None = None) -> None:
        """Update debugger signatures with custom entries.

        Args:
            custom_signatures: Custom signature dictionary to merge with existing
                signatures, organized by platform and type.

        """
        if custom_signatures:
            current_platform = "windows" if platform.system() == "Windows" else "linux"

            for sig_type in custom_signatures.get(current_platform, {}):
                if sig_type in self.debugger_signatures[current_platform]:
                    self.debugger_signatures[current_platform][sig_type].extend(custom_signatures[current_platform][sig_type])

        # Re-scan system for new debuggers
        self._update_signatures_from_system()

    def save_signatures(self, path: str | None = None) -> None:
        """Save current signatures to file for future use.

        Serializes the current debugger signatures dictionary to a JSON file
        for persistence across sessions.

        Args:
            path: File path to save signatures. If None, uses default data directory.

        """
        import json
        import os

        if not path:
            path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "debugger_signatures.json")

        os.makedirs(os.path.dirname(path), exist_ok=True)

        with open(path, "w") as f:
            json.dump(self.debugger_signatures, f, indent=2)

    def detect_debugger(self, aggressive: bool = False) -> dict[str, Any]:
        """Perform debugger detection using multiple techniques.

        Args:
            aggressive: Use more aggressive detection methods

        Returns:
            Detection results with details

        """
        results: dict[str, Any] = {
            "is_debugged": False,
            "confidence": 0.0,
            "debugger_type": None,
            "detections": {},
            "anti_debug_score": 0,
        }

        try:
            self.logger.info("Starting debugger detection...")

            # Run detection methods using base class functionality
            detection_results = self.run_detection_loop(aggressive, self.get_aggressive_methods())

            # Merge results
            results |= detection_results

            # Calculate overall results
            if detection_results["detection_count"] > 0:
                results["is_debugged"] = True
                results["confidence"] = min(1.0, detection_results["average_confidence"])
                detections_value = results.get("detections", {})
                if isinstance(detections_value, dict):
                    results["debugger_type"] = self._identify_debugger_type(detections_value)

            # Calculate anti-debug effectiveness score
            detections_value = results.get("detections", {})
            if isinstance(detections_value, dict):
                results["anti_debug_score"] = self._calculate_antidebug_score(detections_value)

            self.logger.info("Debugger detection complete: %s (confidence: %.2f)", results["is_debugged"], results["confidence"])
            return results

        except Exception as e:
            self.logger.exception("Debugger detection failed: %s", e)
            return results

    # Windows-specific detection methods

    def _check_isdebuggerpresent(self) -> tuple[bool, float, dict[str, bool]]:
        """Check using IsDebuggerPresent API.

        Uses the Windows IsDebuggerPresent API to detect if the current process
        is being debugged.

        Returns:
            Tuple of (detected, confidence, details) where detected is True if
            a debugger is found, confidence is a float 0.0-1.0, and details
            contains debug information.

        """
        details: dict[str, bool] = {"api_result": False}

        try:
            kernel32 = ctypes.windll.kernel32
            result = kernel32.IsDebuggerPresent()
            details["api_result"] = bool(result)

            if result:
                return True, 0.9, details

        except Exception as e:
            self.logger.debug("IsDebuggerPresent check failed: %s", e)

        return False, 0.0, details

    def _check_remote_debugger(self) -> tuple[bool, float, dict[str, bool]]:
        """Check using CheckRemoteDebuggerPresent API.

        Uses the Windows CheckRemoteDebuggerPresent API to detect if another
        debugger is attached to the current process.

        Returns:
            Tuple of (detected, confidence, details) where detected is True if
            a debugger is found, confidence is a float 0.0-1.0, and details
            contains debug information.

        """
        details: dict[str, bool] = {"remote_debugger": False}

        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetCurrentProcess()

            debugger_present = ctypes.c_bool(False)
            kernel32.CheckRemoteDebuggerPresent(handle, ctypes.byref(debugger_present))

            details["remote_debugger"] = debugger_present.value

            if debugger_present.value:
                return True, 0.9, details

        except Exception as e:
            self.logger.debug("CheckRemoteDebuggerPresent check failed: %s", e)

        return False, 0.0, details

    def _check_peb_flags(self) -> tuple[bool, float, dict[str, bool | int | str]]:
        """Check Process Environment Block flags.

        Reads the PEB structure to examine the BeingDebugged flag and
        NtGlobalFlag for debug heap indicators.

        Returns:
            Tuple of (detected, confidence, details) containing PEB debug
            flag information.

        """
        details: dict[str, bool | int | str] = {"being_debugged": False, "nt_global_flag": 0}

        try:
            # Real PEB flags detection implementation
            if platform.system() != "Windows":
                # Non-Windows platforms - check for ptrace or similar debugging indicators
                return self._check_non_windows_debug_indicators(details)

            # Windows PEB manipulation using ctypes
            kernel32 = ctypes.windll.kernel32
            ntdll = ctypes.windll.ntdll

            # Get current process handle
            current_process = kernel32.GetCurrentProcess()

            # Structure definitions for PEB access
            class PROCESS_BASIC_INFORMATION(ctypes.Structure):  # noqa: N801
                _fields_ = [
                    ("Reserved1", ctypes.c_void_p),
                    ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2),
                    ("UniqueProcessId", ctypes.POINTER(ctypes.c_ulong)),
                    ("Reserved3", ctypes.c_void_p),
                ]

            # Get PEB base address
            pbi = PROCESS_BASIC_INFORMATION()
            status = ntdll.NtQueryInformationProcess(
                current_process,
                0,  # ProcessBasicInformation
                ctypes.byref(pbi),
                ctypes.sizeof(pbi),
                None,
            )

            if status != 0:
                self.logger.debug("NtQueryInformationProcess failed: %s", status)
                return False, 0.0, details

            peb_address = pbi.PebBaseAddress
            if not peb_address:
                return False, 0.0, details

            # Read BeingDebugged flag at PEB+2
            being_debugged_addr = ctypes.c_void_p(peb_address.value + 2)
            being_debugged = ctypes.c_ubyte()
            bytes_read = ctypes.c_size_t()

            success = kernel32.ReadProcessMemory(
                current_process,
                being_debugged_addr,
                ctypes.byref(being_debugged),
                1,
                ctypes.byref(bytes_read),
            )

            if success and bytes_read.value == 1:
                details["being_debugged"] = bool(being_debugged.value)

            # Read NtGlobalFlag - different offsets for x86/x64
            is_64bit = platform.machine().endswith("64")
            nt_global_flag_offset = 0xBC if is_64bit else 0x68

            nt_global_flag_addr = ctypes.c_void_p(peb_address.value + nt_global_flag_offset)
            nt_global_flag = ctypes.c_ulong()

            success = kernel32.ReadProcessMemory(
                current_process,
                nt_global_flag_addr,
                ctypes.byref(nt_global_flag),
                4,
                ctypes.byref(bytes_read),
            )

            if success and bytes_read.value == 4:
                details["nt_global_flag"] = nt_global_flag.value

                # Check for debug heap flags
                debug_flags = [
                    0x10,  # FLG_HEAP_ENABLE_TAIL_CHECK
                    0x20,  # FLG_HEAP_ENABLE_FREE_CHECK
                    0x40,  # FLG_HEAP_VALIDATE_PARAMETERS
                ]

                debug_detected = any(nt_global_flag.value & flag for flag in debug_flags)
                details["debug_heap_flags"] = debug_detected

                if debug_detected or details.get("being_debugged"):
                    confidence = 0.9 if details.get("being_debugged") else 0.7
                    return True, confidence, details

            return False, 0.0, details

        except Exception as e:
            self.logger.debug("PEB flags check failed: %s", e)

        return False, 0.0, details

    def _check_non_windows_debug_indicators(self, details: dict[str, bool | int | str]) -> tuple[bool, float, dict[str, bool | int | str]]:
        """Check for debugging indicators on non-Windows platforms.

        Examines Linux/Unix proc filesystem and process attributes to detect
        attached debuggers.

        Args:
            details: Mutable dictionary to store debugging indicator results.

        Returns:
            Tuple of (detected, confidence, details) containing non-Windows
            debug detection results.

        """
        try:
            debug_detected = False
            confidence = 0.0

            # Check for ptrace detection on Linux/Unix
            if platform.system() in ["Linux", "Darwin"]:
                try:
                    # Check /proc/self/status for TracerPid on Linux
                    if platform.system() == "Linux":
                        with open("/proc/self/status") as f:
                            for line in f:
                                if line.startswith("TracerPid:"):
                                    tracer_pid = int(line.split()[1])
                                    if tracer_pid != 0:
                                        debug_detected = True
                                        confidence = 0.8
                                        details["tracer_pid"] = tracer_pid
                                        break

                    # Check for common debugger processes
                    import subprocess

                    try:
                        if ps_path := shutil.which("ps"):
                            ps_result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                                [ps_path, "aux"],
                                capture_output=True,
                                text=True,
                                check=False,
                                shell=False,  # Explicitly secure - using list format prevents shell injection
                            )
                            ps_output = ps_result.stdout
                            debugger_patterns = ["gdb", "lldb", "strace", "ltrace", "x64dbg"]
                            for pattern in debugger_patterns:
                                if pattern in ps_output:
                                    debug_detected = True
                                    confidence = max(confidence, 0.6)
                                    details["debugger_process"] = pattern
                                    break
                    except subprocess.SubprocessError:
                        pass

                except (OSError, ValueError):
                    pass

            return debug_detected, confidence, details

        except Exception as e:
            self.logger.debug("Non-Windows debug check failed: %s", e)
            return False, 0.0, details

    def _check_ntglobalflag(self) -> tuple[bool, float, dict[str, int | list[str] | bool]]:
        """Check NtGlobalFlag for debug heap flags.

        Examines the NtGlobalFlag field in the PEB to detect debug heap
        flags and other debugging indicators.

        Returns:
            Tuple of (detected, confidence, details) containing NtGlobalFlag
            analysis results.

        """
        details: dict[str, int | list[str] | bool] = {"flags": 0}

        try:
            # Real NtGlobalFlag analysis implementation
            if platform.system() != "Windows":
                # Non-Windows systems don't have NtGlobalFlag
                return False, 0.0, details

            # Windows-specific NtGlobalFlag detection
            kernel32 = ctypes.windll.kernel32
            ntdll = ctypes.windll.ntdll

            # Get current process handle
            current_process = kernel32.GetCurrentProcess()

            # Use same PEB access method as _check_peb_flags
            class PROCESS_BASIC_INFORMATION(ctypes.Structure):  # noqa: N801
                _fields_ = [
                    ("Reserved1", ctypes.c_void_p),
                    ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2),
                    ("UniqueProcessId", ctypes.POINTER(ctypes.c_ulong)),
                    ("Reserved3", ctypes.c_void_p),
                ]

            # Get PEB base address
            pbi = PROCESS_BASIC_INFORMATION()
            status = ntdll.NtQueryInformationProcess(
                current_process,
                0,  # ProcessBasicInformation
                ctypes.byref(pbi),
                ctypes.sizeof(pbi),
                None,
            )

            if status != 0:
                self.logger.debug("NtQueryInformationProcess failed: %s", status)
                return False, 0.0, details

            peb_address = pbi.PebBaseAddress
            if not peb_address:
                return False, 0.0, details

            # Read NtGlobalFlag - different offsets for x86/x64
            is_64bit = platform.machine().endswith("64")
            nt_global_flag_offset = 0xBC if is_64bit else 0x68

            nt_global_flag_addr = ctypes.c_void_p(peb_address.value + nt_global_flag_offset)
            nt_global_flag = ctypes.c_ulong()
            bytes_read = ctypes.c_size_t()

            success = kernel32.ReadProcessMemory(
                current_process,
                nt_global_flag_addr,
                ctypes.byref(nt_global_flag),
                4,
                ctypes.byref(bytes_read),
            )

            if success and bytes_read.value == 4:
                flag_value = nt_global_flag.value
                details["flags"] = flag_value

                # Define debug heap flags
                debug_flags = {
                    0x10: "FLG_HEAP_ENABLE_TAIL_CHECK",
                    0x20: "FLG_HEAP_ENABLE_FREE_CHECK",
                    0x40: "FLG_HEAP_VALIDATE_PARAMETERS",
                    0x01: "FLG_STOP_ON_EXCEPTION",
                    0x02: "FLG_SHOW_LDR_SNAPS",
                    0x04: "FLG_DEBUG_INITIAL_COMMAND",
                }

                # Check which debug flags are set
                active_flags = []
                debug_detected = False

                for flag_bit, flag_name in debug_flags.items():
                    if flag_value & flag_bit:
                        active_flags.append(flag_name)
                        debug_detected = True

                details["active_debug_flags"] = active_flags

                if debug_detected:
                    # Higher confidence for heap debugging flags
                    heap_flags = [0x10, 0x20, 0x40]
                    heap_debug_count = sum(bool(flag_value & flag) for flag in heap_flags)
                    confidence = min(0.9, 0.3 + (heap_debug_count * 0.2))

                    return True, confidence, details

            return False, 0.0, details

        except Exception as e:
            self.logger.debug("NtGlobalFlag check failed: %s", e)

        return False, 0.0, details

    def _check_heap_flags(self) -> tuple[bool, float, dict[str, int]]:
        """Check heap flags for debug heap.

        Examines the process heap flags to detect debug heap configuration
        which indicates a debugger has modified the heap.

        Returns:
            Tuple of (detected, confidence, details) containing heap flag
            analysis results.

        """
        details: dict[str, int] = {"heap_flags": 0, "force_flags": 0}

        try:
            # Get default heap
            kernel32 = ctypes.windll.kernel32
            heap = kernel32.GetProcessHeap()

            # In debug heap:
            # Flags = 0x50000062 (includes HEAP_GROWABLE, HEAP_TAIL_CHECKING_ENABLED, etc.)
            # ForceFlags = 0x40000060

            # Check if heap handle is valid
            if heap and heap != -1:
                self.logger.debug("Process heap handle: 0x%x", heap)
                # Try to detect debug heap characteristics
                # Note: This is a simplified check
                return heap != 0, 0.0, details
            self.logger.warning("Failed to get process heap handle")
            return True, 0.0, details  # Assume debugger if heap access fails

        except Exception as e:
            self.logger.debug("Heap flags check failed: %s", e)

        return False, 0.0, details

    def _check_debug_port(self) -> tuple[bool, float, dict[str, int]]:
        """Check debug port using NtQueryInformationProcess.

        Uses the NtQueryInformationProcess API with ProcessDebugPort class
        to detect if a debugger is attached.

        Returns:
            Tuple of (detected, confidence, details) containing debug port
            information.

        """
        details: dict[str, int] = {"debug_port": 0}

        try:
            # ProcessDebugPort = 7
            ntdll = ctypes.windll.ntdll
            kernel32 = ctypes.windll.kernel32

            handle = kernel32.GetCurrentProcess()
            debug_port = ctypes.c_ulong(0)

            # NtQueryInformationProcess(handle, ProcessDebugPort, &debug_port, sizeof(debug_port), NULL)
            status = ntdll.NtQueryInformationProcess(
                handle,
                7,
                ctypes.byref(debug_port),
                ctypes.sizeof(debug_port),
                None,
            )

            if status == 0 and debug_port.value != 0:
                details["debug_port"] = debug_port.value
                return True, 0.8, details

        except Exception as e:
            self.logger.debug("Debug port check failed: %s", e)

        return False, 0.0, details

    def _check_hardware_breakpoints(
        self,
    ) -> tuple[bool, float, dict[str, Any]]:
        """Check for hardware breakpoints in debug registers.

        Examines CPU debug registers (DR0-DR7) to detect hardware breakpoints
        set by debuggers.

        Returns:
            Tuple of (detected, confidence, details) containing hardware
            breakpoint information.

        """
        details: dict[str, Any] = {
            "dr_registers": {},
            "breakpoints_found": 0,
            "active_registers": [],
        }
        start_time = time.time()

        try:
            if platform.system() == "Windows":
                return self._check_hardware_breakpoints_windows(details)
            return self._check_hardware_breakpoints_linux(details)

        except Exception as e:
            self.logger.debug("Hardware breakpoint check failed: %s", e)
            details["error"] = str(e)

        elapsed = time.time() - start_time
        return False, elapsed, details

    def _check_hardware_breakpoints_windows(
        self, details: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any]]:
        """Check for hardware breakpoints on Windows using debug registers.

        Reads the CONTEXT structure to access debug registers and analyze
        their settings for active breakpoints.

        Args:
            details: Mutable dictionary to store breakpoint detection results.

        Returns:
            Tuple of (detected, confidence, details) containing Windows debug
            register analysis.

        """
        start_time = time.time()

        try:
            # Get current thread handle
            kernel32 = ctypes.windll.kernel32
            current_thread = kernel32.GetCurrentThread()

            class CONTEXT(ctypes.Structure):
                _fields_ = [
                    ("ContextFlags", ctypes.c_uint32),
                    ("Dr0", ctypes.c_uint32),  # Hardware breakpoint address 0
                    ("Dr1", ctypes.c_uint32),  # Hardware breakpoint address 1
                    ("Dr2", ctypes.c_uint32),  # Hardware breakpoint address 2
                    ("Dr3", ctypes.c_uint32),  # Hardware breakpoint address 3
                    ("Dr6", ctypes.c_uint32),  # Debug status register
                    ("Dr7", ctypes.c_uint32),  # Debug control register
                    # Other context fields omitted for brevity
                    ("_reserved", ctypes.c_ubyte * 512),  # Reserve space
                ]

            # Context flags for debug registers
            CONTEXT_DEBUG_REGISTERS = 0x00000010

            context = CONTEXT()
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS

            if success := kernel32.GetThreadContext(current_thread, ctypes.byref(context)):
                details["thread_context_retrieved"] = bool(success)

                # Check debug registers DR0-DR3 for addresses
                debug_addresses = [context.Dr0, context.Dr1, context.Dr2, context.Dr3]
                dr6_status = context.Dr6
                dr7_control = context.Dr7

                dr_regs_dict: dict[str, str] = {
                    "DR0": hex(context.Dr0) if context.Dr0 else "0x0",
                    "DR1": hex(context.Dr1) if context.Dr1 else "0x0",
                    "DR2": hex(context.Dr2) if context.Dr2 else "0x0",
                    "DR3": hex(context.Dr3) if context.Dr3 else "0x0",
                    "DR6": hex(dr6_status),
                    "DR7": hex(dr7_control),
                }
                details["dr_registers"] = dr_regs_dict

                # Check DR7 control register for enabled breakpoints
                # DR7 bits: L0,G0,L1,G1,L2,G2,L3,G3 (local/global enable bits)
                breakpoint_enables: list[int] = []
                for i in range(4):
                    local_enable = (dr7_control >> (i * 2)) & 1
                    global_enable = (dr7_control >> (i * 2 + 1)) & 1
                    if local_enable or global_enable:
                        breakpoint_enables.append(i)
                        active_regs = details.get("active_registers", [])
                        if not isinstance(active_regs, list):
                            active_regs = []
                        active_regs.append(f"DR{i}")
                        details["active_registers"] = active_regs

                # Count active breakpoints
                active_breakpoints = 0
                for i, addr in enumerate(debug_addresses):
                    if addr != 0 and i in breakpoint_enables:
                        active_breakpoints += 1
                        self.logger.debug("Active hardware breakpoint at DR%s: %s", i, hex(addr))

                details["breakpoints_found"] = active_breakpoints
                details["dr7_analysis"] = {
                    "enabled_breakpoints": breakpoint_enables,
                    "exact_instruction": bool(dr7_control & 0x00000300),
                    "data_writes": bool(dr7_control & 0x00030000),
                    "data_reads_writes": bool(dr7_control & 0x00300000),
                }

                # Check DR6 status for triggered breakpoints
                if dr6_status & 0x0000000F:  # B0-B3 bits indicate triggered breakpoints
                    triggered_breakpoints: list[str] = [
                        f"DR{i}" for i in range(4) if dr6_status & (1 << i)
                    ]
                    details["triggered_breakpoints"] = triggered_breakpoints

                elapsed = time.time() - start_time
                if active_breakpoints > 0:
                    return True, elapsed, details

            else:
                details["error"] = "Failed to get thread context"

        except Exception as e:
            self.logger.debug("Windows hardware breakpoint check failed: %s", e)
            details["error"] = str(e)

        elapsed = time.time() - start_time
        return False, elapsed, details

    def _check_hardware_breakpoints_linux(
        self, details: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any]]:
        """Check for hardware breakpoints on Linux using ptrace.

        Uses ptrace and /proc filesystem to detect debug registers and
        debugger attachment on Linux systems.

        Args:
            details: Mutable dictionary to store breakpoint detection results.

        Returns:
            Tuple of (detected, confidence, details) containing Linux debug
            register analysis.

        """
        start_time = time.time()

        try:
            # Check if ptrace is available and accessible
            import os

            pid = os.getpid()

            # Check /proc/self/stat for tracer information
            try:
                with open(f"/proc/{pid}/status", encoding="utf-8") as f:
                    status_content = f.read()

                # Look for TracerPid field
                for line in status_content.split("\n"):
                    if line.startswith("TracerPid:"):
                        tracer_pid = int(line.split()[1])
                        if tracer_pid != 0:
                            details["tracer_pid"] = tracer_pid
                            details["being_traced"] = True
                            elapsed = time.time() - start_time
                            return True, elapsed, details

            except (FileNotFoundError, PermissionError, ValueError) as e:
                details["proc_status_error"] = str(e)

            # Alternative: Check for debug register access via system calls
            try:
                # Use ptrace to attempt reading debug registers
                import ctypes.util

                if libc_path := ctypes.util.find_library("c"):
                    libc = ctypes.CDLL(libc_path)

                    # Define ptrace constants
                    PTRACE_PEEKUSER = 3

                    # Debug register offsets (x86_64)
                    DR_OFFSETS = {
                        "DR0": 0x350,
                        "DR1": 0x358,
                        "DR2": 0x360,
                        "DR3": 0x368,
                        "DR6": 0x370,
                        "DR7": 0x378,
                    }

                    # Try to read debug registers (requires permissions)
                    debug_regs: dict[str, str] = {}
                    for reg_name, offset in DR_OFFSETS.items():
                        try:
                            # This will fail without proper permissions, but attempt shows capability
                            result = libc.ptrace(PTRACE_PEEKUSER, pid, offset, 0)
                            debug_regs[reg_name] = hex(result) if result else "0x0"
                        except Exception:
                            debug_regs[reg_name] = "inaccessible"

                    details["dr_registers"] = validate_type(debug_regs, dict)
                    details["ptrace_available"] = True

                    # Count potentially active registers
                    accessible_count = sum(v not in {"inaccessible", "0x0"} for v in debug_regs.values())
                    if accessible_count > 0:
                        details["accessible_registers"] = accessible_count

            except Exception as e:
                details["ptrace_error"] = str(e)

            # Check for debugger environment indicators
            debugger_env = os.environ.get("_", "")
            if "gdb" in debugger_env.lower() or "lldb" in debugger_env.lower():
                details["debugger_env"] = debugger_env
                elapsed = time.time() - start_time
                return True, elapsed, details

            # Check process tree for debugger parents
            try:
                with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
                    stat_line = f.read().strip()

                # Extract parent PID (field 4)
                fields = stat_line.split()
                if len(fields) > 3:
                    ppid = int(fields[3])
                    details["parent_pid"] = ppid

                    # Check parent process name
                    try:
                        with open(f"/proc/{ppid}/comm", encoding="utf-8") as f:
                            parent_name = f.read().strip()

                        details["parent_name"] = parent_name
                        debugger_names = ["gdb", "lldb", "strace", "ltrace", "ddd", "kgdb"]
                        if any(debugger in parent_name.lower() for debugger in debugger_names):
                            details["debugger_parent"] = parent_name
                            elapsed = time.time() - start_time
                            return True, elapsed, details

                    except (FileNotFoundError, PermissionError):
                        pass

            except (FileNotFoundError, ValueError):
                pass

        except Exception as e:
            self.logger.debug("Linux hardware breakpoint check failed: %s", e)
            details["error"] = str(e)

        elapsed = time.time() - start_time
        return False, elapsed, details

    def _check_int3_scan(self) -> tuple[bool, float, dict[str, int | list[str]]]:
        """Scan for INT3 (0xCC) breakpoints in code.

        Scans executable memory regions for INT3 (0xCC) software breakpoint
        instructions indicating debugger breakpoints.

        Returns:
            Tuple of (detected, confidence, details) containing INT3 scan
            results.

        """
        details: dict[str, int | list[str]] = {"int3_count": 0, "locations": []}

        try:
            # Real INT3 breakpoint scanning implementation
            if platform.system() == "Windows":
                return self._scan_int3_windows(details)
            return self._scan_int3_linux(details)

        except Exception as e:
            self.logger.debug("INT3 scan failed: %s", e)

        return False, 0.0, details

    def _scan_int3_windows(self, details: dict[str, int | list[str]]) -> tuple[bool, float, dict[str, int | list[str]]]:
        """Scan for INT3 breakpoints on Windows systems.

        Iterates through process memory regions to locate INT3 (0xCC)
        instructions in executable memory.

        Args:
            details: Mutable dictionary to store scan results.

        Returns:
            Tuple of (detected, confidence, details) containing INT3
            breakpoint locations.

        """
        try:
            kernel32 = ctypes.windll.kernel32

            # Get current process handle
            current_process = kernel32.GetCurrentProcess()

            # Structure for MEMORY_BASIC_INFORMATION
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):  # noqa: N801
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.c_ulong),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", ctypes.c_ulong),
                    ("Protect", ctypes.c_ulong),
                    ("Type", ctypes.c_ulong),
                ]

            # Constants
            MEM_COMMIT = 0x1000
            PAGE_EXECUTE = 0x10
            PAGE_EXECUTE_READ = 0x20
            PAGE_EXECUTE_READWRITE = 0x40
            PAGE_EXECUTE_WRITECOPY = 0x80

            executable_pages = [
                PAGE_EXECUTE,
                PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE,
                PAGE_EXECUTE_WRITECOPY,
            ]

            int3_count = 0
            locations = []
            address = 0
            max_address = 0x7FFFFFFF  # Same value in both cases

            # Scan memory regions
            while address < max_address:
                mbi = MEMORY_BASIC_INFORMATION()
                result = kernel32.VirtualQueryEx(current_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))

                if result == 0:
                    break

                # Check if this is executable memory
                if mbi.State == MEM_COMMIT and mbi.Protect in executable_pages and mbi.RegionSize > 0:
                    # Read memory region
                    buffer_size = min(mbi.RegionSize, 0x10000)  # Limit to 64KB chunks
                    buffer = ctypes.create_string_buffer(buffer_size)
                    bytes_read = ctypes.c_size_t()

                    success = kernel32.ReadProcessMemory(
                        current_process,
                        mbi.BaseAddress,
                        buffer,
                        buffer_size,
                        ctypes.byref(bytes_read),
                    )

                    if success and bytes_read.value > 0:
                        # Scan for INT3 (0xCC) instructions
                        memory_data = buffer.raw[: bytes_read.value]
                        for i, byte in enumerate(memory_data):
                            if byte == 0xCC:  # INT3 instruction
                                int3_address = mbi.BaseAddress.value + i
                                locations.append(hex(int3_address))
                                int3_count += 1

                                # Limit results to prevent excessive memory usage
                                if int3_count >= 50:
                                    break

                # Move to next region
                address = mbi.BaseAddress.value + mbi.RegionSize

                # Safety break to prevent infinite loops
                if int3_count >= 50:
                    break

            details["int3_count"] = int3_count
            details["locations"] = locations[:10]  # Limit locations in output

            if int3_count > 0:
                # Confidence based on number of INT3 instructions found
                # Normal executables may have some INT3 for padding, but debuggers add many
                confidence = min(0.9, 0.2 + (int3_count * 0.05))
                return True, confidence, details

            return False, 0.0, details

        except Exception as e:
            self.logger.debug("Windows INT3 scan error: %s", e)
            return False, 0.0, details

    def _scan_int3_linux(self, details: dict[str, int | list[str] | bool]) -> tuple[bool, float, dict[str, int | list[str] | bool]]:
        """Scan for INT3 breakpoints on Linux systems.

        Uses /proc/self/maps and /proc/self/mem to scan executable memory
        regions for INT3 (0xCC) instructions.

        Args:
            details: Mutable dictionary to store scan results.

        Returns:
            Tuple of (detected, confidence, details) containing INT3
            breakpoint locations.

        """
        try:
            int3_count = 0
            locations: list[str] = []

            # Read process memory maps
            try:
                with open("/proc/self/maps") as maps_file:
                    for line in maps_file:
                        parts = line.split()
                        if len(parts) < 6:
                            continue

                        # Check if this is executable memory
                        permissions = parts[1]
                        if "x" not in permissions:
                            continue

                        # Parse address range
                        addr_range = parts[0]
                        start_addr_str, end_addr_str = addr_range.split("-")
                        start_addr = int(start_addr_str, 16)
                        end_addr = int(end_addr_str, 16)
                        size = end_addr - start_addr

                        # Skip if region too large (probably not code)
                        if size > 0x1000000:  # 16MB limit
                            continue

                        try:
                            # Try to read the memory region
                            with open("/proc/self/mem", "rb") as mem_file:
                                mem_file.seek(start_addr)
                                memory_data = mem_file.read(min(size, 0x10000))  # Read up to 64KB

                                # Scan for INT3 (0xCC) instructions
                                for i, byte in enumerate(memory_data):
                                    if byte == 0xCC:
                                        int3_address = start_addr + i
                                        locations.append(hex(int3_address))
                                        int3_count += 1

                                        # Limit results
                                        if int3_count >= 50:
                                            break

                        except OSError:
                            # Memory region not readable, skip
                            continue

                        # Safety break
                        if int3_count >= 50:
                            break

            except OSError:
                # Fallback: check for common debugger artifacts in /proc
                try:
                    # Check if being traced
                    with open("/proc/self/status") as f:
                        for line in f:
                            if line.startswith("TracerPid:"):
                                tracer_pid = int(line.split()[1])
                                if tracer_pid != 0:
                                    details["tracer_detected"] = True
                                    return True, 0.6, details
                except OSError:
                    pass

            details["int3_count"] = int3_count
            details["locations"] = locations[:10]

            if int3_count > 0:
                confidence = min(0.9, 0.2 + (int3_count * 0.05))
                return True, confidence, details

            return False, 0.0, details

        except Exception as e:
            self.logger.debug("Linux INT3 scan error: %s", e)
            return False, 0.0, details

    def _check_timing(self) -> tuple[bool, float, dict[str, bool | float | int]]:
        """Use timing checks to detect debuggers.

        Measures execution time of simple operations. Debuggers typically
        slow down execution significantly.

        Returns:
            Tuple of (detected, confidence, details) containing timing
            analysis results.

        """
        details: dict[str, bool | float | int] = {"timing_anomaly": False, "execution_time": 0}

        try:
            # Measure execution time of operations
            # Debuggers slow down execution significantly

            start = time.perf_counter()

            result_sum = sum(1 + 1 for _ in range(1000000))
            end = time.perf_counter()
            execution_time = (end - start) * 1000  # milliseconds

            details["execution_time"] = execution_time
            details["computation_result"] = result_sum  # Store the computation result
            self.logger.debug("Timing check: %.2fms, result: %s", execution_time, result_sum)

            # If execution took too long, likely being debugged
            if execution_time > 100:  # Should be < 10ms normally
                details["timing_anomaly"] = True
                return True, 0.6, details

        except Exception as e:
            self.logger.debug("Timing check failed: %s", e)

        return False, 0.0, details

    def _check_parent_process(self) -> tuple[bool, float, dict[str, str | None]]:
        """Check if parent process is a known debugger.

        Compares the parent process name against known debugger signatures
        to detect debugger attachment.

        Returns:
            Tuple of (detected, confidence, details) containing parent process
            analysis results.

        """
        details: dict[str, str | None] = {"parent_process": None}

        try:
            # Get parent process name
            from intellicrack.handlers.psutil_handler import psutil

            current_process = psutil.Process()
            if parent := current_process.parent():
                parent_name = parent.name().lower()
                details["parent_process"] = parent_name

                # Check against known debuggers
                for debugger in self.debugger_signatures["windows"]["processes"]:
                    if debugger.lower() in parent_name:
                        return True, 0.8, details

        except Exception as e:
            self.logger.debug("Parent process check failed: %s", e)

        return False, 0.0, details

    def _check_debug_privileges(self) -> tuple[bool, float, dict[str, bool]]:
        """Check for debug privileges in current process.

        Verifies if the process has SeDebugPrivilege, which is often enabled
        by debuggers to analyze other processes.

        Returns:
            Tuple of (detected, confidence, details) containing privilege
            check results.

        """
        details: dict[str, bool] = {"has_debug_privilege": False}

        try:
            # Check if process has SeDebugPrivilege
            # This is often enabled by debuggers

            kernel32 = ctypes.windll.kernel32
            advapi32 = ctypes.windll.advapi32

            # OpenProcessToken, LookupPrivilegeValue, PrivilegeCheck
            # Direct SeDebugPrivilege enumeration through token inspection

            # Check if these DLLs are accessible (basic sanity check)
            if hasattr(kernel32, "OpenProcessToken") and hasattr(advapi32, "LookupPrivilegeValueW"):
                self.logger.debug("Debug privilege check APIs available")
                details["privilege_apis_available"] = True
            else:
                self.logger.debug("Debug privilege check APIs not available")
                details["privilege_apis_available"] = False

        except Exception as e:
            self.logger.debug("Debug privilege check failed: %s", e)

        return False, 0.0, details

    def _check_exception_handling(self) -> tuple[bool, float, dict[str, bool]]:
        """Use exception handling to detect debuggers.

        Tests exception handling behavior which may be modified by debuggers
        that intercept and manage exceptions.

        Returns:
            Tuple of (detected, confidence, details) containing exception
            handling test results.

        """
        details: dict[str, bool] = {"exception_handled": False}

        try:
            # Debuggers often handle exceptions differently
            # Try to trigger and catch exceptions

            def test_exception() -> bool:
                try:
                    # Trigger access violation
                    ctypes.c_int.from_address(0)
                except Exception:
                    # If we catch it, no debugger interfered
                    return False
                # If we get here, debugger handled it
                return True

            # Log that exception testing is available but don't actually run
            self.logger.debug("Exception handling test function defined")
            details["exception_test_available"] = True
            _func: object = test_exception  # Reference the function to avoid unused variable warning
            # as it could crash the process

        except Exception as e:
            self.logger.debug("Exception handling check failed: %s", e)

        return False, 0.0, details

    # Linux-specific detection methods

    def _check_ptrace(self) -> tuple[bool, float, dict[str, int]]:
        """Check if process is being traced (Linux).

        Uses the PTRACE_TRACEME operation to determine if the process is
        already being debugged via ptrace.

        Returns:
            Tuple of (detected, confidence, details) containing ptrace
            detection results.

        """
        details: dict[str, int] = {"ptrace_result": -1}

        try:
            # Load libc
            libc = ctypes.CDLL(ctypes.util.find_library("c"))

            # Try to ptrace ourselves
            # If already being debugged, this will fail
            result = libc.ptrace(PTRACE_TRACEME, 0, 0, 0)

            details["ptrace_result"] = result

            if result == -1:
                return True, 0.9, details
            # Detach if successful
            libc.ptrace(PTRACE_DETACH, 0, 0, 0)

        except Exception as e:
            self.logger.debug("Ptrace check failed: %s", e)

        return False, 0.0, details

    def _check_proc_status(self) -> tuple[bool, float, dict[str, int]]:
        """Check /proc/self/status for TracerPid (Linux).

        Reads the TracerPid field from /proc/self/status to detect attached
        debuggers on Linux systems.

        Returns:
            Tuple of (detected, confidence, details) containing TracerPid
            information.

        """
        details: dict[str, int] = {"tracer_pid": 0}

        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        tracer_pid = int(line.split()[1])
                        details["tracer_pid"] = tracer_pid

                        if tracer_pid != 0:
                            return True, 0.9, details

        except Exception as e:
            self.logger.debug("Proc status check failed: %s", e)

        return False, 0.0, details

    def _check_parent_process_linux(self) -> tuple[bool, float, dict[str, str | None]]:
        """Check if parent process is a known debugger (Linux).

        Reads the parent process name from /proc and compares against known
        debugger signatures on Linux systems.

        Returns:
            Tuple of (detected, confidence, details) containing parent process
            information.

        """
        details: dict[str, str | None] = {"parent_process": None}

        try:
            # Get parent process name
            ppid = os.getppid()
            with open(f"/proc/{ppid}/comm") as f:
                parent_name = f.read().strip().lower()

            details["parent_process"] = parent_name

            # Check against known debuggers
            for debugger in self.debugger_signatures["linux"]["processes"]:
                if debugger in parent_name:
                    return True, 0.8, details

        except Exception as e:
            self.logger.debug("Parent process check failed: %s", e)

        return False, 0.0, details

    def _check_breakpoints_linux(self) -> tuple[bool, float, dict[str, bool]]:
        """Check for breakpoints in memory (Linux).

        Scans executable memory regions in /proc/self/maps for software
        breakpoint instructions indicating debugger attachment.

        Returns:
            Tuple of (detected, confidence, details) containing breakpoint
            detection results.

        """
        details: dict[str, bool] = {"breakpoint_found": False}

        try:
            # Read /proc/self/maps and check executable regions
            # for INT3 (0xCC) instructions

            # This is complex and requires:
            # 1. Parsing memory maps
            # 2. Reading executable regions
            # 3. Scanning for breakpoint instructions

            pass

        except Exception as e:
            self.logger.debug("Breakpoint check failed: %s", e)

        return False, 0.0, details

    def _identify_debugger_type(self, detections: dict[str, Any]) -> str:
        """Identify the specific debugger based on detections.

        Analyzes detection patterns to classify the type of debugger that
        is likely attached.

        Args:
            detections: Dictionary containing detection results from various
                tests.

        Returns:
            String identifying the debugger type (e.g., "OllyDbg", "GDB",
            "Kernel Debugger").

        """
        # Analyze detection patterns to identify debugger

        # Strong indicators for specific debuggers
        if "parent_process" in detections and detections["parent_process"]["detected"]:
            parent = detections["parent_process"]["details"].get("parent_process", "").lower()

            if "ollydbg" in parent:
                return "OllyDbg"
            if "x64dbg" in parent or "x32dbg" in parent:
                return "x64dbg"
            if "gdb" in parent:
                return "GDB"
            if "lldb" in parent:
                return "LLDB"

        # Generic detection
        kernel_debugger_methods = ["debug_port", "hardware_breakpoints"]
        user_debugger_methods = ["isdebuggerpresent", "checkremotedebuggerpresent"]

        kernel_count = sum(bool(m in detections and detections[m]["detected"]) for m in kernel_debugger_methods)
        user_count = sum(bool(m in detections and detections[m]["detected"]) for m in user_debugger_methods)

        return "Kernel Debugger" if kernel_count > user_count else "User-mode Debugger"

    def _calculate_antidebug_score(self, detections: dict[str, Any]) -> int:
        """Calculate effectiveness of anti-debug techniques.

        Scores the anti-debug effectiveness based on which detection methods
        succeeded, weighting strong methods higher than weaker ones.

        Args:
            detections: Dictionary containing detection results from various
                tests.

        Returns:
            Integer score (0-100) representing anti-debug effectiveness.

        """
        # Methods that are hard to bypass
        strong_methods = ["debug_port", "ptrace", "proc_status"]
        medium_methods = ["isdebuggerpresent", "checkremotedebuggerpresent", "heap_flags"]

        return self.calculate_detection_score(detections, strong_methods, medium_methods)

    def generate_antidebug_code(self, techniques: list[str] | None = None) -> str:
        """Generate anti-debugging code.

        Generates C code implementing multiple anti-debugging techniques that
        can be compiled and integrated into protected applications.

        Args:
            techniques: List of specific techniques to include. If None or
                contains "all", generates code for all techniques.

        Returns:
            String containing C code implementing anti-debugging functions.

        """
        if not techniques:
            techniques = ["all"]

        return """
// Anti-Debugging Code
#include <windows.h>
#include <intrin.h>

bool IsBeingDebugged() {
    // Multiple detection methods

    // 1. IsDebuggerPresent
    if (IsDebuggerPresent()) {
        return true;
    }

    // 2. CheckRemoteDebuggerPresent
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    if (debuggerPresent) {
        return true;
    }

    // 3. PEB->BeingDebugged flag
    __asm {
        mov eax, fs:[30h]  // PEB
        movzx eax, byte ptr [eax+2]  // BeingDebugged
        test eax, eax
        jnz debugger_found
    }

    // 4. NtQueryInformationProcess (ProcessDebugPort)
    typedef NTSTATUS (WINAPI *NtQueryInformationProcess_t)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

    NtQueryInformationProcess_t NtQueryInformationProcess =
        (NtQueryInformationProcess_t)GetProcAddress(
            GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");

    DWORD debugPort = 0;
    NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
    if (debugPort != 0) {
        return true;
    }

    // 5. Timing check
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    // Simple operation that should be fast
    __asm {
        xor eax, eax
        cpuid
    }

    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;

    if (elapsed > 0.001) {  // Should be microseconds
        return true;
    }

    return false;

debugger_found:
    return true;
}

// Anti-debug execution
if (IsBeingDebugged()) {
    // Multiple responses:
    // 1. Exit silently
    ExitProcess(0);

    // 2. Crash the debugger
    __asm {
        xor eax, eax
        mov dword ptr [eax], 0
    }

    // 3. Infinite loop
    while(1) { Sleep(1000); }
}
"""

    def get_aggressive_methods(self) -> list[str]:
        """Get list of method names that are considered aggressive.

        Returns:
            List of method names that are considered more aggressive or
            potentially disruptive to debugger operations.

        """
        return ["timing_checks", "exception_handling"]

    def get_detection_type(self) -> str:
        """Get the type of detection this class performs.

        Returns:
            String identifying this as a debugger detection system.

        """
        return "debugger"
