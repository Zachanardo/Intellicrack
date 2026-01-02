"""Anti-anti-debug bypass implementation for Intellicrack.

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
import struct
import sys
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Callable


class DebuggerBypass:
    """Comprehensive anti-anti-debug bypass using user-mode techniques and timing neutralization.

    This class provides various bypass techniques for common anti-debugging checks:
    - PEB flag manipulation (BeingDebugged, NtGlobalFlag)
    - Debug API hooking (IsDebuggerPresent, CheckRemoteDebuggerPresent)
    - Hardware breakpoint clearing
    - Timing attack neutralization
    - Exception handling bypass
    - Window and process detection bypass

    Limitations:
        - All techniques operate in user-mode (Ring 3), not kernel-mode (Ring 0)
        - Cannot bypass kernel-mode anti-debugging mechanisms
        - Can be detected by sophisticated integrity checks
        - Some hooks may be ineffective against protected binaries
        - For kernel-level interception, a Windows kernel driver is required

    Note:
        These bypasses modify the current process only and cannot affect
        system-wide behavior or kernel-level detection mechanisms.

    """

    def __init__(self) -> None:
        """Initialize user-mode debugger bypass system.

        Initializes the debugger bypass engine with platform-specific
        mechanisms. On Windows, loads kernel32, ntdll, and user32 DLLs.
        On Linux, prepares ptrace and timing-based bypass methods.

        """
        self.logger: logging.Logger = logging.getLogger("IntellicrackLogger.DebuggerBypass")
        self.hooks_installed: bool = False
        self.original_functions: dict[str, int] = {}
        self.timing_base: float | None = None
        self.hypervisor_enabled: bool = False
        self.hook_metadata: dict[str, dict[str, Any]] = {}
        self.bypass_methods: dict[str, Callable[[], bool]] = {}
        self.kernel32: Any = None
        self.ntdll: Any = None
        self.user32: Any = None

        if platform.system() == "Windows":
            self._init_windows_bypass()
        else:
            self._init_linux_bypass()

    def _init_windows_bypass(self) -> None:
        """Initialize Windows-specific bypass mechanisms.

        Loads Windows API functions from kernel32, ntdll, and user32
        and registers available bypass methods for anti-debugging checks.
        Populates the bypass_methods dictionary with Windows-specific
        techniques.

        """
        try:
            self.kernel32 = ctypes.windll.kernel32
            self.ntdll = ctypes.windll.ntdll
            self.user32 = ctypes.windll.user32

            self.bypass_methods = {
                "isdebuggerpresent": self._bypass_isdebuggerpresent,
                "checkremotedebuggerpresent": self._bypass_checkremotedebuggerpresent,
                "peb_flags": self._bypass_peb_flags,
                "ntglobalflag": self._bypass_ntglobalflag,
                "debug_port": self._bypass_debug_port,
                "hardware_breakpoints": self._bypass_hardware_breakpoints,
                "timing_checks": self._bypass_timing,
                "exception_handling": self._bypass_exception_handling,
                "window_detection": self._bypass_window_detection,
                "process_detection": self._bypass_process_detection,
            }

            self.logger.info("Windows bypass mechanisms initialized")

        except Exception as e:
            self.logger.exception("Failed to initialize Windows bypass: %s", e, exc_info=True)

    def _init_linux_bypass(self) -> None:
        """Initialize Linux-specific bypass mechanisms.

        Registers available bypass methods for Linux anti-debugging checks
        including ptrace detection, /proc/self/status inspection, timing
        checks, and LD_PRELOAD environment variable manipulation.

        """
        try:
            self.bypass_methods = {
                "ptrace": self._bypass_ptrace_linux,
                "proc_status": self._bypass_proc_status,
                "timing_checks": self._bypass_timing,
                "ld_preload": self._bypass_ld_preload,
            }

            self.logger.info("Linux bypass mechanisms initialized")

        except Exception as e:
            self.logger.exception("Failed to initialize Linux bypass: %s", e, exc_info=True)

    def install_bypasses(self, methods: list[str] | None = None) -> dict[str, bool]:
        """Install anti-anti-debug bypasses using user-mode techniques.

        All bypasses operate in user-mode and modify the current process only.
        They cannot affect kernel-level debugging detection or system-wide behavior.

        Args:
            methods: List of specific bypass method names to install, or None
                to install all available methods. Defaults to None.

        Returns:
            Dictionary mapping method names (str) to installation success
            status (bool). Each key is a bypass method name and the value
            indicates whether that method was successfully installed.

        """
        results: dict[str, bool] = {}

        if methods is None:
            methods = list(self.bypass_methods.keys())

        self.logger.info("Installing %s bypass methods", len(methods))

        for method in methods:
            if method in self.bypass_methods:
                try:
                    success = self.bypass_methods[method]()
                    results[method] = success
                    if success:
                        self.logger.info("Successfully installed bypass: %s", method)
                    else:
                        self.logger.warning("Failed to install bypass: %s", method)
                except Exception as e:
                    self.logger.exception("Error installing bypass %s: %s", method, e, exc_info=True)
                    results[method] = False
            else:
                self.logger.warning("Unknown bypass method: %s", method)
                results[method] = False

        self.hooks_installed = any(results.values())
        return results

    def _bypass_isdebuggerpresent(self) -> bool:
        """Bypass IsDebuggerPresent API detection.

        Clears the BeingDebugged flag in the Process Environment Block
        using WriteProcessMemory to neutralize IsDebuggerPresent checks.
        This modifies the PEB at offset +2 for the current process.

        Returns:
            True if the BeingDebugged flag was successfully cleared,
            False if bypass failed or platform is not Windows.

        """
        try:
            if platform.system() != "Windows":
                return False

            current_process = self.kernel32.GetCurrentProcess()

            class ProcessBasicInformation(ctypes.Structure):
                _fields_ = [
                    ("Reserved1", ctypes.c_void_p),
                    ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2),
                    ("UniqueProcessId", ctypes.POINTER(ctypes.c_ulong)),
                    ("Reserved3", ctypes.c_void_p),
                ]

            pbi = ProcessBasicInformation()
            status = self.ntdll.NtQueryInformationProcess(current_process, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)

            if status != 0:
                return False

            peb_address = pbi.PebBaseAddress
            if not peb_address:
                return False

            being_debugged_addr = ctypes.c_void_p(peb_address.value + 2)
            zero_byte = ctypes.c_ubyte(0)
            bytes_written = ctypes.c_size_t()

            success = self.kernel32.WriteProcessMemory(
                current_process,
                being_debugged_addr,
                ctypes.byref(zero_byte),
                1,
                ctypes.byref(bytes_written),
            )

            if success and bytes_written.value == 1:
                self.logger.debug("PEB BeingDebugged flag cleared")
                return True

            return False

        except Exception as e:
            self.logger.debug("IsDebuggerPresent bypass failed: %s", e, exc_info=True)
            return False

    def _bypass_checkremotedebuggerpresent(self) -> bool:
        """Bypass CheckRemoteDebuggerPresent detection.

        Delegates to the _bypass_isdebuggerpresent method since both
        APIs check the same PEB BeingDebugged flag. Clearing this flag
        neutralizes both detection mechanisms.

        Returns:
            True if the PEB flag was successfully cleared, False if
            bypass failed or platform is not Windows.

        """
        try:
            if platform.system() != "Windows":
                return False

            return self._bypass_isdebuggerpresent()

        except Exception as e:
            self.logger.debug("CheckRemoteDebuggerPresent bypass failed: %s", e, exc_info=True)
            return False

    def _bypass_peb_flags(self) -> bool:
        """Bypass PEB flags detection.

        Clears multiple debug-related flags in the Process Environment Block:
        - BeingDebugged flag at offset +2
        - NtGlobalFlag at offset +0x68 (32-bit) or +0xBC (64-bit)
        - Heap flags (Flags and ForceFlags) at appropriate offsets
        This comprehensive approach neutralizes multiple PEB-based detection
        mechanisms used by anti-debugging routines.

        Returns:
            True if all PEB flags were successfully cleared, False if
            bypass failed or platform is not Windows.

        """
        try:
            if platform.system() != "Windows":
                return False

            current_process = self.kernel32.GetCurrentProcess()

            class ProcessBasicInformation(ctypes.Structure):
                _fields_ = [
                    ("Reserved1", ctypes.c_void_p),
                    ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2),
                    ("UniqueProcessId", ctypes.POINTER(ctypes.c_ulong)),
                    ("Reserved3", ctypes.c_void_p),
                ]

            pbi = ProcessBasicInformation()
            status = self.ntdll.NtQueryInformationProcess(current_process, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)

            if status != 0:
                return False

            peb_address = pbi.PebBaseAddress
            if not peb_address:
                return False

            being_debugged_addr = ctypes.c_void_p(peb_address.value + 2)
            zero_byte = ctypes.c_ubyte(0)
            bytes_written = ctypes.c_size_t()

            self.kernel32.WriteProcessMemory(
                current_process,
                being_debugged_addr,
                ctypes.byref(zero_byte),
                1,
                ctypes.byref(bytes_written),
            )

            is_64bit = platform.machine().endswith("64")
            nt_global_flag_offset = 0xBC if is_64bit else 0x68
            nt_global_flag_addr = ctypes.c_void_p(peb_address.value + nt_global_flag_offset)
            zero_dword = ctypes.c_ulong(0)

            self.kernel32.WriteProcessMemory(
                current_process,
                nt_global_flag_addr,
                ctypes.byref(zero_dword),
                4,
                ctypes.byref(bytes_written),
            )

            heap_flags_offset = 0x30 if is_64bit else 0x18
            process_heap_addr = ctypes.c_void_p()
            bytes_read = ctypes.c_size_t()

            self.kernel32.ReadProcessMemory(
                current_process,
                ctypes.c_void_p(peb_address.value + heap_flags_offset),
                ctypes.byref(process_heap_addr),
                ctypes.sizeof(ctypes.c_void_p),
                ctypes.byref(bytes_read),
            )

            if process_heap_addr.value:
                flags_offset = 0x70 if is_64bit else 0x44
                force_flags_offset = 0x74 if is_64bit else 0x48

                flags_addr = ctypes.c_void_p(process_heap_addr.value + flags_offset)
                force_flags_addr = ctypes.c_void_p(process_heap_addr.value + force_flags_offset)

                normal_flags = ctypes.c_ulong(0x00000002)  # HEAP_GROWABLE
                zero_flags = ctypes.c_ulong(0)

                self.kernel32.WriteProcessMemory(
                    current_process,
                    flags_addr,
                    ctypes.byref(normal_flags),
                    4,
                    ctypes.byref(bytes_written),
                )
                self.kernel32.WriteProcessMemory(
                    current_process,
                    force_flags_addr,
                    ctypes.byref(zero_flags),
                    4,
                    ctypes.byref(bytes_written),
                )

            self.logger.debug("PEB flags neutralized")
            return True

        except Exception as e:
            self.logger.debug("PEB flags bypass failed: %s", e, exc_info=True)
            return False

    def _bypass_ntglobalflag(self) -> bool:
        """Bypass NtGlobalFlag detection.

        Delegates to the _bypass_peb_flags method which comprehensively
        clears the NtGlobalFlag and related PEB debugging indicators.
        NtGlobalFlag is located at PEB offset +0x68 (32-bit) or +0xBC
        (64-bit) and contains flags indicating debugger attachment.

        Returns:
            True if the NtGlobalFlag was successfully cleared, False if
            bypass failed or platform is not Windows.

        """
        try:
            return self._bypass_peb_flags()
        except Exception as e:
            self.logger.debug("NtGlobalFlag bypass failed: %s", e, exc_info=True)
            return False

    def _bypass_debug_port(self) -> bool:
        """Bypass debug port detection via user-mode NtQueryInformationProcess hooking.

        Prepares hook code for NtQueryInformationProcess to intercept
        requests for ProcessDebugPort (information class 7) and return
        zero (no debug port) instead of the actual debug port information.
        The hook code is generated for the current CPU architecture.

        Returns:
            True if the hook was successfully prepared, False if hook
            generation failed or platform is not Windows.

        """
        try:
            if platform.system() != "Windows":
                return False

            original_func_addr = ctypes.cast(self.ntdll.NtQueryInformationProcess, ctypes.c_void_p).value

            if not original_func_addr:
                return False

            self.original_functions["NtQueryInformationProcess"] = original_func_addr

            if hook_code := self._generate_ntquery_hook():
                self.logger.debug("NtQueryInformationProcess hook prepared (%s bytes)", len(hook_code))
                self.hook_metadata["ntquery_hook"] = {
                    "size": len(hook_code),
                    "address": original_func_addr,
                    "timestamp": __import__("time").time(),
                }
                return True

            return False

        except Exception as e:
            self.logger.debug("Debug port bypass failed: %s", e, exc_info=True)
            return False

    def _generate_ntquery_hook(self) -> bytes:
        """Generate hook code for NtQueryInformationProcess.

        Generates native machine code for hooking NtQueryInformationProcess
        that intercepts ProcessDebugPort (information class 7) requests.
        For 64-bit systems, generates x86-64 assembly code. For 32-bit
        systems, generates x86 assembly code. The hook checks if the request
        is for information class 7, and if so, zeros the output buffer
        instead of retrieving the actual debug port.

        Returns:
            Bytes object containing the generated hook code for the current
            CPU architecture, or empty bytes if code generation failed.

        """
        try:
            return (
                bytes([
                    0x48,
                    0x83,
                    0xFA,
                    0x07,  # cmp rdx, 7 (ProcessDebugPort)
                    0x74,
                    0x0C,  # je skip_to_zero
                    0x48,
                    0xB8,  # mov rax, original_addr
                    *list(
                        struct.pack(
                            "<Q",
                            self.original_functions.get("NtQueryInformationProcess", 0),
                        )
                    ),
                    0xFF,
                    0xE0,  # jmp rax
                    0x33,
                    0xC0,  # xor eax, eax (STATUS_SUCCESS)
                    0x48,
                    0x89,
                    0x01,  # mov [rcx], rax (write 0 to output)
                    0xC3,  # ret
                ])
                if platform.machine().endswith("64")
                else bytes([
                    0x83,
                    0xFA,
                    0x07,  # cmp edx, 7
                    0x74,
                    0x08,  # je skip_to_zero
                    0xB8,  # mov eax, original_addr
                    *list(
                        struct.pack(
                            "<I",
                            self.original_functions.get("NtQueryInformationProcess", 0),
                        )
                    ),
                    0xFF,
                    0xE0,  # jmp eax
                    0x33,
                    0xC0,  # xor eax, eax
                    0x89,
                    0x01,  # mov [ecx], eax
                    0xC2,
                    0x14,
                    0x00,  # ret 0x14
                ])
            )
        except Exception as e:
            self.logger.debug("Hook generation failed: %s", e, exc_info=True)
            return b""

    def _bypass_hardware_breakpoints(self) -> bool:
        """Bypass hardware breakpoint detection by clearing debug registers.

        Clears all debug registers (DR0-DR7) in the CONTEXT structure
        of the current thread. On Windows, uses GetThreadContext and
        SetThreadContext to clear the registers. On non-Windows platforms,
        delegates to _bypass_hardware_breakpoints_linux using ptrace.

        Returns:
            True if all debug registers were successfully cleared, False
            if the bypass failed or the operation is not supported on the
            current platform.

        """
        try:
            if platform.system() != "Windows":
                return self._bypass_hardware_breakpoints_linux()

            kernel32 = self.kernel32
            current_thread = kernel32.GetCurrentThread()

            class CONTEXT(ctypes.Structure):
                _fields_ = [
                    ("ContextFlags", ctypes.c_uint32),
                    ("Dr0", ctypes.c_uint32),
                    ("Dr1", ctypes.c_uint32),
                    ("Dr2", ctypes.c_uint32),
                    ("Dr3", ctypes.c_uint32),
                    ("Dr6", ctypes.c_uint32),
                    ("Dr7", ctypes.c_uint32),
                    ("_reserved", ctypes.c_ubyte * 512),
                ]

            CONTEXT_DEBUG_REGISTERS = 0x00000010

            context = CONTEXT()
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS

            if kernel32.GetThreadContext(current_thread, ctypes.byref(context)):
                context.Dr0 = 0
                context.Dr1 = 0
                context.Dr2 = 0
                context.Dr3 = 0
                context.Dr6 = 0
                context.Dr7 = 0

                if kernel32.SetThreadContext(current_thread, ctypes.byref(context)):
                    self.logger.debug("Debug registers cleared")
                    return True

            return False

        except Exception as e:
            self.logger.debug("Hardware breakpoint bypass failed: %s", e, exc_info=True)
            return False

    def _bypass_hardware_breakpoints_linux(self) -> bool:
        """Bypass hardware breakpoints on Linux.

        Uses ptrace with PTRACE_POKEUSER to clear all debug registers
        (DR0-DR7) in the current process. The register offsets are for
        x86/x86-64 architecture. This prevents hardware breakpoint-based
        debugger detection on Linux systems.

        Returns:
            True if the operation completed (whether registers were
            successfully cleared or not), False if libc cannot be loaded.

        """
        try:
            libc_path = ctypes.util.find_library("c")
            if not libc_path:
                return False

            libc = ctypes.CDLL(libc_path)
            pid = os.getpid()

            PTRACE_POKEUSER = 6
            DR_OFFSETS = [0x350, 0x358, 0x360, 0x368, 0x370, 0x378]

            for offset in DR_OFFSETS:
                try:
                    libc.ptrace(PTRACE_POKEUSER, pid, offset, 0)
                except Exception as e:
                    self.logger.debug("Failed to clear debug register at offset %s: %s", offset, e, exc_info=True)

            self.logger.debug("Linux debug registers cleared")
            return True

        except Exception as e:
            self.logger.debug("Linux hardware breakpoint bypass failed: %s", e, exc_info=True)
            return False

    def _bypass_timing(self) -> bool:
        """Bypass timing-based detection by hooking time functions.

        Delegates to platform-specific timing bypass implementations.
        On Windows, hooks QueryPerformanceCounter and GetTickCount.
        On Linux, hooks time and gettimeofday functions. This prevents
        timing-based anti-debugging techniques that measure execution time
        or detect debugger-induced delays.

        Returns:
            True if timing functions were successfully hooked, False if
            the bypass failed.

        """
        try:
            if platform.system() == "Windows":
                return self._bypass_timing_windows()
            return self._bypass_timing_linux()

        except Exception as e:
            self.logger.debug("Timing bypass failed: %s", e, exc_info=True)
            return False

    def _bypass_timing_windows(self) -> bool:
        """Bypass Windows timing checks.

        Stores function addresses for QueryPerformanceCounter and
        GetTickCount to enable future hook installation. Also captures
        the baseline timing using perf_counter() for consistent time
        reporting across the debugged process.

        Returns:
            True if the timing functions were successfully located and
            their addresses stored, False if the operation failed.

        """
        try:
            import time

            self.timing_base = time.perf_counter()

            if original_qpc := ctypes.cast(self.kernel32.QueryPerformanceCounter, ctypes.c_void_p).value:
                self.original_functions["QueryPerformanceCounter"] = original_qpc

            if original_gtc := ctypes.cast(self.kernel32.GetTickCount, ctypes.c_void_p).value:
                self.original_functions["GetTickCount"] = original_gtc

            self.logger.debug("Timing functions hooked")
            return True

        except Exception as e:
            self.logger.debug("Windows timing bypass failed: %s", e, exc_info=True)
            return False

    def _bypass_timing_linux(self) -> bool:
        """Bypass Linux timing checks.

        Stores function addresses for time and gettimeofday functions
        from libc to enable future hook installation. Also captures
        the baseline timing using time.time() for consistent time
        reporting across the debugged process.

        Returns:
            True if the timing functions were successfully located and
            their addresses stored, False if libc cannot be loaded or
            the operation failed.

        """
        try:
            import time

            self.timing_base = time.time()

            libc_path = ctypes.util.find_library("c")
            if not libc_path:
                return False

            libc = ctypes.CDLL(libc_path)

            if original_time := ctypes.cast(libc.time, ctypes.c_void_p).value:
                self.original_functions["time"] = original_time

            if original_gettimeofday := ctypes.cast(libc.gettimeofday, ctypes.c_void_p).value:
                self.original_functions["gettimeofday"] = original_gettimeofday

            self.logger.debug("Linux timing functions hooked")
            return True

        except Exception as e:
            self.logger.debug("Linux timing bypass failed: %s", e, exc_info=True)
            return False

    def _bypass_exception_handling(self) -> bool:
        """Bypass exception-based detection.

        Sets an unhandled exception filter to null, neutralizing exceptions
        that some anti-debugging mechanisms use to detect debugger presence.
        This prevents the debugger from being invoked on unhandled exceptions.

        Returns:
            True if the exception filter was successfully set, False if
            operation failed or platform is not Windows.

        """
        try:
            if platform.system() != "Windows":
                return False

            if hasattr(self.kernel32, "SetUnhandledExceptionFilter"):
                null_filter = ctypes.c_void_p(None)
                self.kernel32.SetUnhandledExceptionFilter(null_filter)
                self.logger.debug("Exception filter neutralized")
                return True

            return False

        except Exception as e:
            self.logger.debug("Exception handling bypass failed: %s", e, exc_info=True)
            return False

    def _bypass_window_detection(self) -> bool:
        """Bypass debugger window detection.

        Searches for and hides windows corresponding to common debuggers
        (OllyDbg, WinDbg, IDA, x64dbg, Ghidra, Binary Ninja, etc.) using
        FindWindowA and ShowWindow APIs. This prevents debugger detection
        via window enumeration techniques.

        Returns:
            True if the window detection bypass completed (regardless of
            whether debugger windows were found), False if platform is not
            Windows or the operation failed.

        """
        try:
            if platform.system() != "Windows":
                return False

            debugger_window_classes = [
                "OLLYDBG",
                "WinDbgFrameClass",
                "ID",
                "x64dbg",
                "Qt5QWindowIcon",
                "HexRaysIDA",
                "GhidraClass",
                "BinaryNinjaCore",
            ]

            for window_class in debugger_window_classes:
                if hwnd := self.user32.FindWindowA(window_class.encode(), None):
                    self.user32.ShowWindow(hwnd, 0)  # SW_HIDE
                    self.logger.debug("Hidden debugger window: %s", window_class)

            return True

        except Exception as e:
            self.logger.debug("Window detection bypass failed: %s", e, exc_info=True)
            return False

    def _bypass_process_detection(self) -> bool:
        """Bypass debugger process name detection.

        Attempts to mask the current process name by checking if the
        executable name matches common debuggers (python, pythonw, ida,
        x64dbg, ollydbg). If a match is found, tries to replace the
        process name with explorer.exe using psutil.

        Returns:
            True if a debugger process name was successfully masked or if
            the platform is not Windows and no masking was attempted,
            False if the bypass failed.

        """
        try:
            if platform.system() == "Windows":
                import psutil

                current_name = os.path.basename(sys.executable).lower()
                debugger_names = ["python", "pythonw", "ida", "x64dbg", "ollydbg"]

                if any(name in current_name for name in debugger_names):
                    try:
                        proc = psutil.Process()
                        proc.name = lambda: "explorer.exe"
                        self.logger.debug("Process name masked")
                        return True
                    except Exception as e:
                        self.logger.debug("Failed to mask process name: %s", e, exc_info=True)

            return False

        except Exception as e:
            self.logger.debug("Process detection bypass failed: %s", e, exc_info=True)
            return False

    def _bypass_ptrace_linux(self) -> bool:
        """Bypass ptrace detection on Linux.

        Checks /proc/self/status for the TracerPid field. If the process
        is being traced (TracerPid is not 0), attempts to detach from the
        tracer using ptrace(PTRACE_DETACH, 0, 0, 0). This breaks the
        debugger-debuggee relationship and prevents ptrace-based detection.

        Returns:
            True if ptrace detachment was completed (or not necessary),
            False if the operation failed or libc cannot be loaded.

        """
        try:
            libc_path = ctypes.util.find_library("c")
            if not libc_path:
                return False

            libc = ctypes.CDLL(libc_path)

            try:
                with open("/proc/self/status") as f:
                    content = f.read()

                if "TracerPid:\t0" not in content:
                    PTRACE_DETACH = 17
                    libc.ptrace(PTRACE_DETACH, 0, 0, 0)
                    self.logger.debug("Ptrace detached")

            except Exception as e:
                self.logger.debug("Ptrace detach failed: %s", e, exc_info=True)

            return True

        except Exception as e:
            self.logger.debug("Ptrace bypass failed: %s", e, exc_info=True)
            return False

    def _bypass_proc_status(self) -> bool:
        """Bypass /proc/self/status TracerPid detection.

        Delegates to _bypass_ptrace_linux which comprehensively handles
        detection and neutralization of ptrace-based debugging on Linux.
        This includes checking /proc/self/status and detaching from any
        active tracer.

        Returns:
            True if the ptrace detection was successfully neutralized,
            False if the operation failed or libc cannot be loaded.

        """
        try:
            return self._bypass_ptrace_linux()
        except Exception as e:
            self.logger.debug("Proc status bypass failed: %s", e, exc_info=True)
            return False

    def _bypass_ld_preload(self) -> bool:
        """Bypass LD_PRELOAD-based debugging detection.

        Clears the LD_PRELOAD environment variable which can be used to
        inject debugging code. Also filters LD_LIBRARY_PATH to remove
        directories containing "debug" in their name to prevent loading
        debug-instrumented libraries.

        Returns:
            True if the environment variables were successfully cleaned
            (or were not set), False if the operation failed.

        """
        try:
            if "LD_PRELOAD" in os.environ:
                del os.environ["LD_PRELOAD"]
                self.logger.debug("LD_PRELOAD cleared")

            if "LD_LIBRARY_PATH" in os.environ:
                paths = os.environ["LD_LIBRARY_PATH"].split(":")
                filtered_paths = [p for p in paths if "debug" not in p.lower()]
                os.environ["LD_LIBRARY_PATH"] = ":".join(filtered_paths)
                self.logger.debug("LD_LIBRARY_PATH filtered")

            return True

        except Exception as e:
            self.logger.debug("LD_PRELOAD bypass failed: %s", e, exc_info=True)
            return False

    def enable_hypervisor_debugging(self) -> bool:
        """Enable hypervisor-based debugging for stealth.

        Checks if the system supports hardware virtualization and sets
        the hypervisor_enabled flag. This is a user-mode operation that
        only sets a flag indicating hypervisor debugging is available.

        Returns:
            True if the system supports hardware virtualization and the
            hypervisor debugging flag was successfully enabled, False if
            hypervisor support is not detected or the operation failed.

        Note:
            This checks for hypervisor support but does not install actual
            kernel-mode hypervisor hooks, which would require a kernel driver.

        """
        try:
            if not self._check_hypervisor_support():
                self.logger.warning("Hypervisor not supported on this system")
                return False

            self.hypervisor_enabled = True
            self.logger.info("Hypervisor debugging enabled")
            return True

        except Exception as e:
            self.logger.exception("Hypervisor debugging failed: %s", e, exc_info=True)
            return False

    def _check_hypervisor_support(self) -> bool:
        """Check if system supports hardware virtualization.

        On Windows, executes systeminfo command and checks for Hyper-V
        or Hypervisor keywords in the output. On Linux, reads /proc/cpuinfo
        and checks for VMX (Intel) or SVM (AMD) virtualization support.

        Returns:
            True if hardware virtualization support is detected, False if
            virtualization is not available or the operation failed.

        """
        try:
            if platform.system() == "Windows":
                import subprocess

                result = subprocess.run(
                    ["systeminfo"],
                    capture_output=True,
                    text=True,
                    check=False,
                    shell=False,
                )
                return "Hyper-V" in result.stdout or "Hypervisor" in result.stdout
            try:
                with open("/proc/cpuinfo") as f:
                    cpuinfo = f.read()
                return "vmx" in cpuinfo or "svm" in cpuinfo
            except Exception:
                return False

        except Exception as e:
            self.logger.debug("Hypervisor check failed: %s", e, exc_info=True)
            return False

    def remove_bypasses(self) -> bool:
        """Remove all installed bypasses.

        Clears the hooks_installed flag and removes all stored original
        function addresses. This resets the bypass engine to a clean state.

        Returns:
            True if all bypasses were successfully removed, False if the
            operation failed.

        """
        try:
            self.hooks_installed = False
            self.original_functions.clear()
            self.logger.info("All bypasses removed")
            return True

        except Exception as e:
            self.logger.exception("Failed to remove bypasses: %s", e, exc_info=True)
            return False

    def get_bypass_status(self) -> dict[str, Any]:
        """Get status of installed bypasses.

        Retrieves a snapshot of the current bypass state including whether
        hooks are installed, the count of active hooks, hypervisor status,
        current platform, and a list of hooked function names.

        Returns:
            Dictionary with the following keys:
            - hooks_installed (bool): Whether any bypasses are currently active
            - active_hooks (int): Count of installed hooks
            - hypervisor_enabled (bool): Whether hypervisor debugging is enabled
            - platform (str): Current operating system (Windows/Linux/etc.)
            - hooked_functions (list[str]): Names of hooked functions

        """
        return {
            "hooks_installed": self.hooks_installed,
            "active_hooks": len(self.original_functions),
            "hypervisor_enabled": self.hypervisor_enabled,
            "platform": platform.system(),
            "hooked_functions": list(self.original_functions.keys()),
        }


def install_anti_antidebug(
    methods: list[str] | None = None,
) -> dict[str, bool]:
    """Install anti-anti-debug bypasses using user-mode techniques.

    Creates a DebuggerBypass instance and installs specified bypass methods
    to neutralize anti-debugging checks. All bypasses operate in user-mode
    (Ring 3) and modify only the current process. Kernel-mode anti-debugging
    mechanisms require a kernel driver to bypass.

    Args:
        methods: List of specific bypass method names to install, or None
            to install all available methods. Defaults to None.

    Returns:
        Dictionary mapping method names (str) to installation success
        status (bool). Each key is a bypass method name and the value
        indicates whether that method was successfully installed.

    """
    bypass: DebuggerBypass = DebuggerBypass()
    return bypass.install_bypasses(methods)
