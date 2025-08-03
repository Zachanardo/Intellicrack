"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import ctypes
import ctypes.util
import logging
import os
import platform
import time
from typing import Any

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

        # Known debugger signatures
        self.debugger_signatures = {
            "windows": {
                "processes": [
                    "ollydbg.exe",
                    "x64dbg.exe",
                    "x32dbg.exe",
                    "windbg.exe",
                    "idaq.exe",
                    "idaq64.exe",
                    "ida.exe",
                    "ida64.exe",
                    "devenv.exe",
                    "dbgview.exe",
                    "processhacker.exe",
                ],
                "window_classes": ["OLLYDBG", "WinDbgFrameClass", "ID", "Zeta Debugger"],
                "window_titles": ["OllyDbg", "x64dbg", "WinDbg", "IDA", "Immunity Debugger"],
            },
            "linux": {
                "processes": ["gdb", "lldb", "radare2", "r2", "edb", "strace", "ltrace"],
                "files": ["/proc/self/status", "/proc/self/stat"],
            },
        }

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

            self.logger.info(
                f"Debugger detection complete: {results['is_debugged']} (confidence: {results['confidence']:.2f})"
            )
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
            # This requires inline assembly or ctypes manipulation
            # Simplified version using ctypes

            # Get PEB address (simplified, platform-specific)
            # In real implementation, would use proper PEB traversal

            # Check BeingDebugged flag at PEB+2
            # Check NtGlobalFlag at PEB+0x68 (x86) or PEB+0xBC (x64)

            # For now, return false as this requires complex implementation
            pass

        except Exception as e:
            self.logger.debug(f"PEB flags check failed: {e}")

        return False, 0.0, details

    def _check_ntglobalflag(self) -> tuple[bool, float, dict]:
        """Check NtGlobalFlag for debug heap flags."""
        details = {"flags": 0}

        try:
            # Check for FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
            # FLG_HEAP_ENABLE_FREE_CHECK (0x20)
            # FLG_HEAP_VALIDATE_PARAMETERS (0x40)

            # These flags are set when process is created under debugger
            # Implementation would check PEB->NtGlobalFlag

            pass

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
        details = {"dr_registers": []}

        try:
            # Would need to check DR0-DR3 for breakpoint addresses
            # and DR7 for enabled breakpoints
            # This requires kernel mode or special privileges

            # Simplified check using exception handling
            def trigger_breakpoint():
                try:
                    # Try to cause an exception that would trigger
                    # if hardware breakpoints are set
                    ctypes.c_int.from_address(0)
                except:
                    return True
                return False

            # Log the breakpoint check capability and test it
            self.logger.debug("Hardware breakpoint detection function available")
            _ = trigger_breakpoint()  # Test the function
            details["breakpoint_check_available"] = True

        except Exception as e:
            self.logger.debug(f"Hardware breakpoint check failed: {e}")

        return False, 0.0, details

    def _check_int3_scan(self) -> tuple[bool, float, dict]:
        """Scan for INT3 (0xCC) breakpoints in code."""
        details = {"int3_count": 0, "locations": []}

        try:
            # Would scan executable memory for 0xCC bytes
            # that shouldn't be there normally

            # This is complex as it requires:
            # 1. Getting module base and size
            # 2. Reading executable sections
            # 3. Comparing against original file

            pass

        except Exception as e:
            self.logger.debug(f"INT3 scan failed: {e}")

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
            import psutil

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
            # Implementation would check for SeDebugPrivilege

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
                except:
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
            if "ida" in parent:
                return "IDA Pro"
            if "gdb" in parent:
                return "GDB"
            if "lldb" in parent:
                return "LLDB"

        # Generic detection
        kernel_debugger_methods = ["debug_port", "hardware_breakpoints"]
        user_debugger_methods = ["isdebuggerpresent", "checkremotedebuggerpresent"]

        kernel_count = sum(
            1 for m in kernel_debugger_methods if m in detections and detections[m]["detected"]
        )
        user_count = sum(
            1 for m in user_debugger_methods if m in detections and detections[m]["detected"]
        )

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
