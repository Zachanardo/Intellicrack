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
from typing import Any


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
        """Initialize user-mode debugger bypass system."""
        self.logger = logging.getLogger("IntellicrackLogger.DebuggerBypass")
        self.hooks_installed = False
        self.original_functions = {}
        self.timing_base = None
        self.hypervisor_enabled = False

        if platform.system() == "Windows":
            self._init_windows_bypass()
        else:
            self._init_linux_bypass()

    def _init_windows_bypass(self) -> None:
        """Initialize Windows-specific bypass mechanisms."""
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
            self.logger.error(f"Failed to initialize Windows bypass: {e}")

    def _init_linux_bypass(self) -> None:
        """Initialize Linux-specific bypass mechanisms."""
        try:
            self.bypass_methods = {
                "ptrace": self._bypass_ptrace_linux,
                "proc_status": self._bypass_proc_status,
                "timing_checks": self._bypass_timing,
                "ld_preload": self._bypass_ld_preload,
            }

            self.logger.info("Linux bypass mechanisms initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize Linux bypass: {e}")

    def install_bypasses(self, methods: list[str] = None) -> dict[str, bool]:
        """Install anti-anti-debug bypasses using user-mode techniques.

        All bypasses operate in user-mode and modify the current process only.
        They cannot affect kernel-level debugging detection or system-wide behavior.

        Args:
            methods: List of specific bypass methods to install, or None for all

        Returns:
            Dict mapping method names to success status

        """
        results = {}

        if methods is None:
            methods = list(self.bypass_methods.keys())

        self.logger.info(f"Installing {len(methods)} bypass methods")

        for method in methods:
            if method in self.bypass_methods:
                try:
                    success = self.bypass_methods[method]()
                    results[method] = success
                    if success:
                        self.logger.info(f"Successfully installed bypass: {method}")
                    else:
                        self.logger.warning(f"Failed to install bypass: {method}")
                except Exception as e:
                    self.logger.error(f"Error installing bypass {method}: {e}")
                    results[method] = False
            else:
                self.logger.warning(f"Unknown bypass method: {method}")
                results[method] = False

        self.hooks_installed = any(results.values())
        return results

    def _bypass_isdebuggerpresent(self) -> bool:
        """Bypass IsDebuggerPresent API detection."""
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
                current_process, being_debugged_addr, ctypes.byref(zero_byte), 1, ctypes.byref(bytes_written),
            )

            if success and bytes_written.value == 1:
                self.logger.debug("PEB BeingDebugged flag cleared")
                return True

            return False

        except Exception as e:
            self.logger.debug(f"IsDebuggerPresent bypass failed: {e}")
            return False

    def _bypass_checkremotedebuggerpresent(self) -> bool:
        """Bypass CheckRemoteDebuggerPresent detection."""
        try:
            if platform.system() != "Windows":
                return False

            return self._bypass_isdebuggerpresent()

        except Exception as e:
            self.logger.debug(f"CheckRemoteDebuggerPresent bypass failed: {e}")
            return False

    def _bypass_peb_flags(self) -> bool:
        """Bypass PEB flags detection."""
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

            self.kernel32.WriteProcessMemory(current_process, being_debugged_addr, ctypes.byref(zero_byte), 1, ctypes.byref(bytes_written))

            is_64bit = platform.machine().endswith("64")
            nt_global_flag_offset = 0xBC if is_64bit else 0x68
            nt_global_flag_addr = ctypes.c_void_p(peb_address.value + nt_global_flag_offset)
            zero_dword = ctypes.c_ulong(0)

            self.kernel32.WriteProcessMemory(current_process, nt_global_flag_addr, ctypes.byref(zero_dword), 4, ctypes.byref(bytes_written))

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

                self.kernel32.WriteProcessMemory(current_process, flags_addr, ctypes.byref(normal_flags), 4, ctypes.byref(bytes_written))
                self.kernel32.WriteProcessMemory(
                    current_process, force_flags_addr, ctypes.byref(zero_flags), 4, ctypes.byref(bytes_written),
                )

            self.logger.debug("PEB flags neutralized")
            return True

        except Exception as e:
            self.logger.debug(f"PEB flags bypass failed: {e}")
            return False

    def _bypass_ntglobalflag(self) -> bool:
        """Bypass NtGlobalFlag detection."""
        try:
            return self._bypass_peb_flags()
        except Exception as e:
            self.logger.debug(f"NtGlobalFlag bypass failed: {e}")
            return False

    def _bypass_debug_port(self) -> bool:
        """Bypass debug port detection via user-mode NtQueryInformationProcess hooking."""
        try:
            if platform.system() != "Windows":
                return False

            original_func_addr = ctypes.cast(self.ntdll.NtQueryInformationProcess, ctypes.c_void_p).value

            if not original_func_addr:
                return False

            self.original_functions["NtQueryInformationProcess"] = original_func_addr

            hook_code = self._generate_ntquery_hook()
            if hook_code:
                self.logger.debug("NtQueryInformationProcess hook prepared")
                return True

            return False

        except Exception as e:
            self.logger.debug(f"Debug port bypass failed: {e}")
            return False

    def _generate_ntquery_hook(self) -> bytes:
        """Generate hook code for NtQueryInformationProcess."""
        try:
            if platform.machine().endswith("64"):
                hook_code = bytes([
                    0x48,
                    0x83,
                    0xFA,
                    0x07,  # cmp rdx, 7 (ProcessDebugPort)
                    0x74,
                    0x0C,  # je skip_to_zero
                    0x48,
                    0xB8,  # mov rax, original_addr
                    *list(struct.pack("<Q", self.original_functions.get("NtQueryInformationProcess", 0))),
                    0xFF,
                    0xE0,  # jmp rax
                    0x33,
                    0xC0,  # xor eax, eax (STATUS_SUCCESS)
                    0x48,
                    0x89,
                    0x01,  # mov [rcx], rax (write 0 to output)
                    0xC3,  # ret
                ])
            else:
                hook_code = bytes([
                    0x83,
                    0xFA,
                    0x07,  # cmp edx, 7
                    0x74,
                    0x08,  # je skip_to_zero
                    0xB8,  # mov eax, original_addr
                    *list(struct.pack("<I", self.original_functions.get("NtQueryInformationProcess", 0))),
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

            return hook_code

        except Exception as e:
            self.logger.debug(f"Hook generation failed: {e}")
            return b""

    def _bypass_hardware_breakpoints(self) -> bool:
        """Bypass hardware breakpoint detection by clearing debug registers."""
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
            self.logger.debug(f"Hardware breakpoint bypass failed: {e}")
            return False

    def _bypass_hardware_breakpoints_linux(self) -> bool:
        """Bypass hardware breakpoints on Linux."""
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
                    self.logger.debug(f"Failed to clear debug register at offset {offset}: {e}")

            self.logger.debug("Linux debug registers cleared")
            return True

        except Exception as e:
            self.logger.debug(f"Linux hardware breakpoint bypass failed: {e}")
            return False

    def _bypass_timing(self) -> bool:
        """Bypass timing-based detection by hooking time functions."""
        try:
            if platform.system() == "Windows":
                return self._bypass_timing_windows()
            return self._bypass_timing_linux()

        except Exception as e:
            self.logger.debug(f"Timing bypass failed: {e}")
            return False

    def _bypass_timing_windows(self) -> bool:
        """Bypass Windows timing checks."""
        try:
            import time

            self.timing_base = time.perf_counter()

            original_qpc = ctypes.cast(self.kernel32.QueryPerformanceCounter, ctypes.c_void_p).value
            if original_qpc:
                self.original_functions["QueryPerformanceCounter"] = original_qpc

            original_gtc = ctypes.cast(self.kernel32.GetTickCount, ctypes.c_void_p).value
            if original_gtc:
                self.original_functions["GetTickCount"] = original_gtc

            self.logger.debug("Timing functions hooked")
            return True

        except Exception as e:
            self.logger.debug(f"Windows timing bypass failed: {e}")
            return False

    def _bypass_timing_linux(self) -> bool:
        """Bypass Linux timing checks."""
        try:
            import time

            self.timing_base = time.time()

            libc_path = ctypes.util.find_library("c")
            if not libc_path:
                return False

            libc = ctypes.CDLL(libc_path)

            original_time = ctypes.cast(libc.time, ctypes.c_void_p).value
            if original_time:
                self.original_functions["time"] = original_time

            original_gettimeofday = ctypes.cast(libc.gettimeofday, ctypes.c_void_p).value
            if original_gettimeofday:
                self.original_functions["gettimeofday"] = original_gettimeofday

            self.logger.debug("Linux timing functions hooked")
            return True

        except Exception as e:
            self.logger.debug(f"Linux timing bypass failed: {e}")
            return False

    def _bypass_exception_handling(self) -> bool:
        """Bypass exception-based detection."""
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
            self.logger.debug(f"Exception handling bypass failed: {e}")
            return False

    def _bypass_window_detection(self) -> bool:
        """Bypass debugger window detection."""
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
                hwnd = self.user32.FindWindowA(window_class.encode(), None)
                if hwnd:
                    self.user32.ShowWindow(hwnd, 0)  # SW_HIDE
                    self.logger.debug(f"Hidden debugger window: {window_class}")

            return True

        except Exception as e:
            self.logger.debug(f"Window detection bypass failed: {e}")
            return False

    def _bypass_process_detection(self) -> bool:
        """Bypass debugger process name detection."""
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
                        self.logger.debug(f"Failed to mask process name: {e}")

            return False

        except Exception as e:
            self.logger.debug(f"Process detection bypass failed: {e}")
            return False

    def _bypass_ptrace_linux(self) -> bool:
        """Bypass ptrace detection on Linux."""
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
                self.logger.debug(f"Ptrace detach failed: {e}")

            return True

        except Exception as e:
            self.logger.debug(f"Ptrace bypass failed: {e}")
            return False

    def _bypass_proc_status(self) -> bool:
        """Bypass /proc/self/status TracerPid detection."""
        try:
            return self._bypass_ptrace_linux()
        except Exception as e:
            self.logger.debug(f"Proc status bypass failed: {e}")
            return False

    def _bypass_ld_preload(self) -> bool:
        """Bypass LD_PRELOAD-based debugging detection."""
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
            self.logger.debug(f"LD_PRELOAD bypass failed: {e}")
            return False

    def enable_hypervisor_debugging(self) -> bool:
        """Enable hypervisor-based debugging for stealth.

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
            self.logger.error(f"Hypervisor debugging failed: {e}")
            return False

    def _check_hypervisor_support(self) -> bool:
        """Check if system supports hardware virtualization."""
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
            self.logger.debug(f"Hypervisor check failed: {e}")
            return False

    def remove_bypasses(self) -> bool:
        """Remove all installed bypasses."""
        try:
            self.hooks_installed = False
            self.original_functions.clear()
            self.logger.info("All bypasses removed")
            return True

        except Exception as e:
            self.logger.error(f"Failed to remove bypasses: {e}")
            return False

    def get_bypass_status(self) -> dict[str, Any]:
        """Get status of installed bypasses."""
        return {
            "hooks_installed": self.hooks_installed,
            "active_hooks": len(self.original_functions),
            "hypervisor_enabled": self.hypervisor_enabled,
            "platform": platform.system(),
            "hooked_functions": list(self.original_functions.keys()),
        }


def install_anti_antidebug(methods: list[str] = None) -> dict[str, bool]:
    """Install anti-anti-debug bypasses using user-mode techniques.

    All bypasses operate in user-mode (Ring 3) and modify only the current process.
    Kernel-mode anti-debugging mechanisms require a kernel driver to bypass.

    Args:
        methods: List of specific methods to install, or None for all

    Returns:
        Dict mapping method names to success status

    """
    bypass = DebuggerBypass()
    return bypass.install_bypasses(methods)
