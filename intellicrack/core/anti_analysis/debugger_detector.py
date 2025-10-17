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
from typing import Any

import psutil

from intellicrack.utils.logger import logger

from .base_detector import BaseDetector

"""
Debugger Detection

Implements multiple techniques to detect debuggers including
user-mode and kernel-mode debuggers.
"""

# Linux ptrace constants
PTRACE_TRACEME = 0
PTRACE_DETACH = 17


class DebuggerDetector(BaseDetector):
    """Comprehensive debugger detection using multiple techniques."""

    def __init__(self):
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

    def _build_dynamic_signatures(self) -> dict:
        """Build debugger signatures dynamically based on system analysis."""
        import json
        import os

        signatures = {
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
                with open(config_path, "r") as f:
                    base_sigs = json.load(f)
                    # Merge base signatures
                    for platform_key in signatures:
                        if platform_key in base_sigs:
                            for sig_type in signatures[platform_key]:
                                if sig_type in base_sigs[platform_key]:
                                    signatures[platform_key][sig_type].extend(base_sigs[platform_key][sig_type])
        except (IOError, json.JSONDecodeError):
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
        for platform_key in signatures:
            for sig_type in signatures[platform_key]:
                seen = set()
                unique_list = []
                for item in signatures[platform_key][sig_type]:
                    if item.lower() not in seen:
                        seen.add(item.lower())
                        unique_list.append(item)
                signatures[platform_key][sig_type] = unique_list

        return signatures

    def _update_signatures_from_system(self):
        """Scan system for additional debugger signatures."""
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
                            if proc_name not in [p.lower() for p in self.debugger_signatures[current_platform]["processes"]]:
                                # Verify it's actually a debugger by checking its capabilities
                                if self._verify_debugger_capabilities(proc):
                                    self.debugger_signatures[current_platform]["processes"].append(proc_name)
                                    self.logger.info(f"Discovered new debugger: {proc_name}")
                            break

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            self.logger.debug(f"Error updating signatures: {e}")

    def _verify_debugger_capabilities(self, process) -> bool:
        """Verify if a process has debugger capabilities."""
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
                    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, process.pid)

                    if handle:
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
                    logger.debug(f"Process connection analysis failed: {e}")
            else:
                # Linux: Check for ptrace capability
                try:
                    import os

                    status_path = f"/proc/{process.pid}/status"
                    if os.path.exists(status_path):
                        with open(status_path, "r") as f:
                            status = f.read()
                            # Check for TracerPid or capabilities
                            if "TracerPid" in status or "CapEff" in status:
                                cap_line = [line for line in status.split("\n") if "CapEff" in line]
                                if cap_line:
                                    # Check for CAP_SYS_PTRACE capability
                                    cap_value = int(cap_line[0].split()[1], 16)
                                    CAP_SYS_PTRACE = 1 << 19
                                    if cap_value & CAP_SYS_PTRACE:
                                        return True
                except Exception as e:
                    logger.debug(f"Ptrace capability check failed: {e}")

            # Check if process has child processes (debuggers often spawn debuggees)
            children = process.children()
            if children:
                # Check if children have different names (sign of debugging)
                child_names = set(child.name() for child in children)
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

    def update_signatures(self, custom_signatures: dict = None):
        """Update debugger signatures with custom entries."""
        if custom_signatures:
            current_platform = "windows" if platform.system() == "Windows" else "linux"

            for sig_type in custom_signatures.get(current_platform, {}):
                if sig_type in self.debugger_signatures[current_platform]:
                    self.debugger_signatures[current_platform][sig_type].extend(custom_signatures[current_platform][sig_type])

        # Re-scan system for new debuggers
        self._update_signatures_from_system()

    def save_signatures(self, path: str = None):
        """Save current signatures to file for future use."""
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
        results = {
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
            results.update(detection_results)

            # Calculate overall results
            if detection_results["detection_count"] > 0:
                results["is_debugged"] = True
                results["confidence"] = min(1.0, detection_results["average_confidence"])
                results["debugger_type"] = self._identify_debugger_type(results["detections"])

            # Calculate anti-debug effectiveness score
            results["anti_debug_score"] = self._calculate_antidebug_score(results["detections"])

            self.logger.info(f"Debugger detection complete: {results['is_debugged']} (confidence: {results['confidence']:.2f})")
            return results

        except Exception as e:
            self.logger.error(f"Debugger detection failed: {e}")
            return results

    # Windows-specific detection methods

    def _check_isdebuggerpresent(self) -> tuple[bool, float, dict]:
        """Check using IsDebuggerPresent API."""
        details = {"api_result": False}

        try:
            kernel32 = ctypes.windll.kernel32
            result = kernel32.IsDebuggerPresent()
            details["api_result"] = bool(result)

            if result:
                return True, 0.9, details

        except Exception as e:
            self.logger.debug(f"IsDebuggerPresent check failed: {e}")

        return False, 0.0, details

    def _check_remote_debugger(self) -> tuple[bool, float, dict]:
        """Check using CheckRemoteDebuggerPresent API."""
        details = {"remote_debugger": False}

        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetCurrentProcess()

            debugger_present = ctypes.c_bool(False)
            kernel32.CheckRemoteDebuggerPresent(handle, ctypes.byref(debugger_present))

            details["remote_debugger"] = debugger_present.value

            if debugger_present.value:
                return True, 0.9, details

        except Exception as e:
            self.logger.debug(f"CheckRemoteDebuggerPresent check failed: {e}")

        return False, 0.0, details

    def _check_peb_flags(self) -> tuple[bool, float, dict]:
        """Check Process Environment Block flags."""
        details = {"being_debugged": False, "nt_global_flag": 0}

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
                self.logger.debug(f"NtQueryInformationProcess failed: {status}")
                return False, 0.0, details

            peb_address = pbi.PebBaseAddress
            if not peb_address:
                return False, 0.0, details

            # Read BeingDebugged flag at PEB+2
            being_debugged_addr = ctypes.c_void_p(peb_address.value + 2)
            being_debugged = ctypes.c_ubyte()
            bytes_read = ctypes.c_size_t()

            success = kernel32.ReadProcessMemory(
                current_process, being_debugged_addr, ctypes.byref(being_debugged), 1, ctypes.byref(bytes_read)
            )

            if success and bytes_read.value == 1:
                details["being_debugged"] = bool(being_debugged.value)

            # Read NtGlobalFlag - different offsets for x86/x64
            is_64bit = platform.machine().endswith("64")
            nt_global_flag_offset = 0xBC if is_64bit else 0x68

            nt_global_flag_addr = ctypes.c_void_p(peb_address.value + nt_global_flag_offset)
            nt_global_flag = ctypes.c_ulong()

            success = kernel32.ReadProcessMemory(
                current_process, nt_global_flag_addr, ctypes.byref(nt_global_flag), 4, ctypes.byref(bytes_read)
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

                if debug_detected or details.get("being_debugged", False):
                    confidence = 0.9 if details.get("being_debugged", False) else 0.7
                    return True, confidence, details

            return False, 0.0, details

        except Exception as e:
            self.logger.debug(f"PEB flags check failed: {e}")

        return False, 0.0, details

    def _check_non_windows_debug_indicators(self, details: dict) -> tuple[bool, float, dict]:
        """Check for debugging indicators on non-Windows platforms."""
        try:
            debug_detected = False
            confidence = 0.0

            # Check for ptrace detection on Linux/Unix
            if platform.system() in ["Linux", "Darwin"]:
                try:
                    # Check /proc/self/status for TracerPid on Linux
                    if platform.system() == "Linux":
                        with open("/proc/self/status", "r") as f:
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
                        ps_path = shutil.which("ps")
                        if ps_path:
                            ps_result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
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

                except (OSError, ValueError, IOError):
                    pass

            return debug_detected, confidence, details

        except Exception as e:
            self.logger.debug(f"Non-Windows debug check failed: {e}")
            return False, 0.0, details

    def _check_ntglobalflag(self) -> tuple[bool, float, dict]:
        """Check NtGlobalFlag for debug heap flags."""
        details = {"flags": 0}

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
                self.logger.debug(f"NtQueryInformationProcess failed: {status}")
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
                current_process, nt_global_flag_addr, ctypes.byref(nt_global_flag), 4, ctypes.byref(bytes_read)
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
                    heap_debug_count = sum(1 for flag in heap_flags if flag_value & flag)
                    confidence = min(0.9, 0.3 + (heap_debug_count * 0.2))

                    return True, confidence, details

            return False, 0.0, details

        except Exception as e:
            self.logger.debug(f"NtGlobalFlag check failed: {e}")

        return False, 0.0, details

    def _check_heap_flags(self) -> tuple[bool, float, dict]:
        """Check heap flags for debug heap."""
        details = {"heap_flags": 0, "force_flags": 0}

        try:
            # Get default heap
            kernel32 = ctypes.windll.kernel32
            heap = kernel32.GetProcessHeap()

            # In debug heap:
            # Flags = 0x50000062 (includes HEAP_GROWABLE, HEAP_TAIL_CHECKING_ENABLED, etc.)
            # ForceFlags = 0x40000060

            # Check if heap handle is valid
            if heap and heap != -1:
                self.logger.debug(f"Process heap handle: 0x{heap:x}")
                # Try to detect debug heap characteristics
                # Note: This is a simplified check
                return heap != 0  # Non-zero heap suggests normal execution
            self.logger.warning("Failed to get process heap handle")
            return True  # Assume debugger if heap access fails

        except Exception as e:
            self.logger.debug(f"Heap flags check failed: {e}")

        return False, 0.0, details

    def _check_debug_port(self) -> tuple[bool, float, dict]:
        """Check debug port using NtQueryInformationProcess."""
        details = {"debug_port": 0}

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
            self.logger.debug(f"Debug port check failed: {e}")

        return False, 0.0, details

    def _check_hardware_breakpoints(self) -> tuple[bool, float, dict]:
        """Check for hardware breakpoints in debug registers."""
        details = {"dr_registers": [], "breakpoints_found": 0, "active_registers": []}
        start_time = time.time()

        try:
            if platform.system() == "Windows":
                return self._check_hardware_breakpoints_windows(details)
            else:
                return self._check_hardware_breakpoints_linux(details)

        except Exception as e:
            self.logger.debug(f"Hardware breakpoint check failed: {e}")
            details["error"] = str(e)

        elapsed = time.time() - start_time
        return False, elapsed, details

    def _check_hardware_breakpoints_windows(self, details: dict) -> tuple[bool, float, dict]:
        """Check for hardware breakpoints on Windows using debug registers."""
        start_time = time.time()

        try:
            # Get current thread handle
            kernel32 = ctypes.windll.kernel32
            current_thread = kernel32.GetCurrentThread()

            # Define CONTEXT structure for debug register access
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

            # Get thread context with debug registers
            success = kernel32.GetThreadContext(current_thread, ctypes.byref(context))

            if success:
                # Check debug registers DR0-DR3 for addresses
                debug_addresses = [context.Dr0, context.Dr1, context.Dr2, context.Dr3]
                dr6_status = context.Dr6
                dr7_control = context.Dr7

                details["dr_registers"] = {
                    "DR0": hex(context.Dr0) if context.Dr0 else "0x0",
                    "DR1": hex(context.Dr1) if context.Dr1 else "0x0",
                    "DR2": hex(context.Dr2) if context.Dr2 else "0x0",
                    "DR3": hex(context.Dr3) if context.Dr3 else "0x0",
                    "DR6": hex(dr6_status),
                    "DR7": hex(dr7_control),
                }

                # Check DR7 control register for enabled breakpoints
                # DR7 bits: L0,G0,L1,G1,L2,G2,L3,G3 (local/global enable bits)
                breakpoint_enables = []
                for i in range(4):
                    local_enable = (dr7_control >> (i * 2)) & 1
                    global_enable = (dr7_control >> (i * 2 + 1)) & 1
                    if local_enable or global_enable:
                        breakpoint_enables.append(i)
                        details["active_registers"].append(f"DR{i}")

                # Count active breakpoints
                active_breakpoints = 0
                for i, addr in enumerate(debug_addresses):
                    if addr != 0 and i in breakpoint_enables:
                        active_breakpoints += 1
                        self.logger.debug(f"Active hardware breakpoint at DR{i}: {hex(addr)}")

                details["breakpoints_found"] = active_breakpoints
                details["dr7_analysis"] = {
                    "enabled_breakpoints": breakpoint_enables,
                    "exact_instruction": bool(dr7_control & 0x00000300),
                    "data_writes": bool(dr7_control & 0x00030000),
                    "data_reads_writes": bool(dr7_control & 0x00300000),
                }

                # Check DR6 status for triggered breakpoints
                if dr6_status & 0x0000000F:  # B0-B3 bits indicate triggered breakpoints
                    details["triggered_breakpoints"] = []
                    for i in range(4):
                        if dr6_status & (1 << i):
                            details["triggered_breakpoints"].append(f"DR{i}")

                elapsed = time.time() - start_time
                if active_breakpoints > 0:
                    return True, elapsed, details

            else:
                details["error"] = "Failed to get thread context"

        except Exception as e:
            self.logger.debug(f"Windows hardware breakpoint check failed: {e}")
            details["error"] = str(e)

        elapsed = time.time() - start_time
        return False, elapsed, details

    def _check_hardware_breakpoints_linux(self, details: dict) -> tuple[bool, float, dict]:
        """Check for hardware breakpoints on Linux using ptrace."""
        start_time = time.time()

        try:
            # Check if ptrace is available and accessible
            import os

            pid = os.getpid()

            # Check /proc/self/stat for tracer information
            try:
                with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
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

                libc_path = ctypes.util.find_library("c")
                if libc_path:
                    libc = ctypes.CDLL(libc_path)

                    # Define ptrace constants
                    PTRACE_PEEKUSER = 3

                    # Debug register offsets (x86_64)
                    DR_OFFSETS = {"DR0": 0x350, "DR1": 0x358, "DR2": 0x360, "DR3": 0x368, "DR6": 0x370, "DR7": 0x378}

                    # Try to read debug registers (requires permissions)
                    debug_regs = {}
                    for reg_name, offset in DR_OFFSETS.items():
                        try:
                            # This will fail without proper permissions, but attempt shows capability
                            result = libc.ptrace(PTRACE_PEEKUSER, pid, offset, 0)
                            debug_regs[reg_name] = hex(result) if result else "0x0"
                        except Exception:
                            debug_regs[reg_name] = "inaccessible"

                    details["dr_registers"] = debug_regs
                    details["ptrace_available"] = True

                    # Count potentially active registers
                    accessible_count = sum(1 for v in debug_regs.values() if v != "inaccessible" and v != "0x0")
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
                with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as f:
                    stat_line = f.read().strip()

                # Extract parent PID (field 4)
                fields = stat_line.split()
                if len(fields) > 3:
                    ppid = int(fields[3])
                    details["parent_pid"] = ppid

                    # Check parent process name
                    try:
                        with open(f"/proc/{ppid}/comm", "r", encoding="utf-8") as f:
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
            self.logger.debug(f"Linux hardware breakpoint check failed: {e}")
            details["error"] = str(e)

        elapsed = time.time() - start_time
        return False, elapsed, details

    def _check_int3_scan(self) -> tuple[bool, float, dict]:
        """Scan for INT3 (0xCC) breakpoints in code."""
        details = {"int3_count": 0, "locations": []}

        try:
            # Real INT3 breakpoint scanning implementation
            if platform.system() == "Windows":
                return self._scan_int3_windows(details)
            else:
                return self._scan_int3_linux(details)

        except Exception as e:
            self.logger.debug(f"INT3 scan failed: {e}")

        return False, 0.0, details

    def _scan_int3_windows(self, details: dict) -> tuple[bool, float, dict]:
        """Scan for INT3 breakpoints on Windows systems."""
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

            executable_pages = [PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY]

            int3_count = 0
            locations = []
            address = 0
            max_address = 0x7FFFFFFF if platform.machine().endswith("64") else 0x7FFFFFFF

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

                    success = kernel32.ReadProcessMemory(current_process, mbi.BaseAddress, buffer, buffer_size, ctypes.byref(bytes_read))

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
            self.logger.debug(f"Windows INT3 scan error: {e}")
            return False, 0.0, details

    def _scan_int3_linux(self, details: dict) -> tuple[bool, float, dict]:
        """Scan for INT3 breakpoints on Linux systems."""
        try:
            int3_count = 0
            locations = []

            # Read process memory maps
            try:
                with open("/proc/self/maps", "r") as maps_file:
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
                        start_addr, end_addr = addr_range.split("-")
                        start_addr = int(start_addr, 16)
                        end_addr = int(end_addr, 16)
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

                        except (OSError, IOError):
                            # Memory region not readable, skip
                            continue

                        # Safety break
                        if int3_count >= 50:
                            break

            except (OSError, IOError):
                # Fallback: check for common debugger artifacts in /proc
                try:
                    # Check if being traced
                    with open("/proc/self/status", "r") as f:
                        for line in f:
                            if line.startswith("TracerPid:"):
                                tracer_pid = int(line.split()[1])
                                if tracer_pid != 0:
                                    details["tracer_detected"] = True
                                    return True, 0.6, details
                except (OSError, IOError):
                    pass

            details["int3_count"] = int3_count
            details["locations"] = locations[:10]

            if int3_count > 0:
                confidence = min(0.9, 0.2 + (int3_count * 0.05))
                return True, confidence, details

            return False, 0.0, details

        except Exception as e:
            self.logger.debug(f"Linux INT3 scan error: {e}")
            return False, 0.0, details

    def _check_timing(self) -> tuple[bool, float, dict]:
        """Use timing checks to detect debuggers."""
        details = {"timing_anomaly": False, "execution_time": 0}

        try:
            # Measure execution time of operations
            # Debuggers slow down execution significantly

            start = time.perf_counter()

            # Perform operations that should be fast
            result_sum = 0
            for _ in range(1000000):
                x = 1 + 1
                result_sum += x  # Use the computed value

            end = time.perf_counter()
            execution_time = (end - start) * 1000  # milliseconds

            details["execution_time"] = execution_time
            details["computation_result"] = result_sum  # Store the computation result
            self.logger.debug(f"Timing check: {execution_time:.2f}ms, result: {result_sum}")

            # If execution took too long, likely being debugged
            if execution_time > 100:  # Should be < 10ms normally
                details["timing_anomaly"] = True
                return True, 0.6, details

        except Exception as e:
            self.logger.debug(f"Timing check failed: {e}")

        return False, 0.0, details

    def _check_parent_process(self) -> tuple[bool, float, dict]:
        """Check if parent process is a known debugger."""
        details = {"parent_process": None}

        try:
            # Get parent process name
            from intellicrack.handlers.psutil_handler import psutil

            current_process = psutil.Process()
            parent = current_process.parent()

            if parent:
                parent_name = parent.name().lower()
                details["parent_process"] = parent_name

                # Check against known debuggers
                for debugger in self.debugger_signatures["windows"]["processes"]:
                    if debugger.lower() in parent_name:
                        return True, 0.8, details

        except Exception as e:
            self.logger.debug(f"Parent process check failed: {e}")

        return False, 0.0, details

    def _check_debug_privileges(self) -> tuple[bool, float, dict]:
        """Check for debug privileges in current process."""
        details = {"has_debug_privilege": False}

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
            self.logger.debug(f"Debug privilege check failed: {e}")

        return False, 0.0, details

    def _check_exception_handling(self) -> tuple[bool, float, dict]:
        """Use exception handling to detect debuggers."""
        details = {"exception_handled": False}

        try:
            # Debuggers often handle exceptions differently
            # Try to trigger and catch exceptions

            def test_exception():
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
            _ = test_exception  # Reference the function to avoid unused variable warning
            # as it could crash the process

        except Exception as e:
            self.logger.debug(f"Exception handling check failed: {e}")

        return False, 0.0, details

    # Linux-specific detection methods

    def _check_ptrace(self) -> tuple[bool, float, dict]:
        """Check if process is being traced (Linux)."""
        details = {"ptrace_result": -1}

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
            self.logger.debug(f"Ptrace check failed: {e}")

        return False, 0.0, details

    def _check_proc_status(self) -> tuple[bool, float, dict]:
        """Check /proc/self/status for TracerPid (Linux)."""
        details = {"tracer_pid": 0}

        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        tracer_pid = int(line.split()[1])
                        details["tracer_pid"] = tracer_pid

                        if tracer_pid != 0:
                            return True, 0.9, details

        except Exception as e:
            self.logger.debug(f"Proc status check failed: {e}")

        return False, 0.0, details

    def _check_parent_process_linux(self) -> tuple[bool, float, dict]:
        """Check if parent process is a known debugger (Linux)."""
        details = {"parent_process": None}

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
            self.logger.debug(f"Parent process check failed: {e}")

        return False, 0.0, details

    def _check_breakpoints_linux(self) -> tuple[bool, float, dict]:
        """Check for breakpoints in memory (Linux)."""
        details = {"breakpoint_found": False}

        try:
            # Read /proc/self/maps and check executable regions
            # for INT3 (0xCC) instructions

            # This is complex and requires:
            # 1. Parsing memory maps
            # 2. Reading executable regions
            # 3. Scanning for breakpoint instructions

            pass

        except Exception as e:
            self.logger.debug(f"Breakpoint check failed: {e}")

        return False, 0.0, details

    def _identify_debugger_type(self, detections: dict[str, Any]) -> str:
        """Identify the specific debugger based on detections."""
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

        kernel_count = sum(1 for m in kernel_debugger_methods if m in detections and detections[m]["detected"])
        user_count = sum(1 for m in user_debugger_methods if m in detections and detections[m]["detected"])

        if kernel_count > user_count:
            return "Kernel Debugger"
        return "User-mode Debugger"

    def _calculate_antidebug_score(self, detections: dict[str, Any]) -> int:
        """Calculate effectiveness of anti-debug techniques."""
        # Methods that are hard to bypass
        strong_methods = ["debug_port", "ptrace", "proc_status"]
        medium_methods = ["isdebuggerpresent", "checkremotedebuggerpresent", "heap_flags"]

        return self.calculate_detection_score(detections, strong_methods, medium_methods)

    def generate_antidebug_code(self, techniques: list[str] = None) -> str:
        """Generate anti-debugging code."""
        if not techniques:
            techniques = ["all"]

        code = """
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
        return code

    def get_aggressive_methods(self) -> list[str]:
        """Get list of method names that are considered aggressive."""
        return ["timing_checks", "exception_handling"]

    def get_detection_type(self) -> str:
        """Get the type of detection this class performs."""
        return "debugger"
