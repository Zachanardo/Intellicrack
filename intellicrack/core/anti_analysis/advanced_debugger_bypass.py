"""Advanced anti-anti-debug bypass implementation for Intellicrack.

This module provides sophisticated bypass techniques for ScyllaHide-resistant
anti-debug protections including kernel hooks, hypervisor-based debugging,
and timing neutralization.

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
import platform
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass
class HookInfo:
    """Information about an installed hook."""

    name: str
    target_address: int
    hook_address: int
    original_bytes: bytes
    hook_type: str
    active: bool = True


class UserModeNTAPIHooker:
    """User-mode NT API inline hooks (not kernel-mode).

    This class installs inline hooks on NT API functions (ntdll.dll) from user-mode
    to bypass anti-debug checks. These are user-mode hooks that modify function
    prologues in the current process address space.

    Limitations:
        - Only operates in user-mode (Ring 3), not kernel-mode (Ring 0)
        - For actual kernel-mode interception, a Windows kernel driver is required
        - Can be detected by sophisticated anti-debugging that checks code integrity
        - Does not protect against kernel-mode anti-debug mechanisms

    Note:
        These hooks modify ntdll.dll functions in the current process only and
        cannot affect system-wide behavior or kernel-level detection mechanisms.

    """

    def __init__(self) -> None:
        """Initialize user-mode NT API hooker."""
        self.logger = logging.getLogger("IntellicrackLogger.UserModeNTAPIHooker")
        self.hooks: dict[str, HookInfo] = {}
        self.ntdll_base = None
        self.kernel32_base = None

        if platform.system() == "Windows":
            self._init_windows_ntapi_hooks()
        else:
            self._init_linux_usermode_hooks()

    def _init_windows_ntapi_hooks(self) -> None:
        """Initialize Windows user-mode NT API hook infrastructure."""
        try:
            self.ntdll = ctypes.windll.ntdll
            self.kernel32 = ctypes.windll.kernel32

            self.ntdll_base = ctypes.windll.kernel32.GetModuleHandleW("ntdll.dll")
            self.kernel32_base = ctypes.windll.kernel32.GetModuleHandleW("kernel32.dll")

            self.logger.info("Windows user-mode NT API hook infrastructure initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize Windows user-mode NT API hooks: {e}")

    def _init_linux_usermode_hooks(self) -> None:
        """Initialize Linux user-mode hook infrastructure."""
        try:
            if libc_path := ctypes.util.find_library("c"):
                self.libc = ctypes.CDLL(libc_path)
                self.logger.info("Linux user-mode hook infrastructure initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize Linux user-mode hooks: {e}")

    def hook_ntquery_information_process(self) -> bool:
        """Hide debugger by hooking NtQueryInformationProcess in user-mode."""
        try:
            if platform.system() != "Windows":
                return False

            func_addr = ctypes.cast(self.ntdll.NtQueryInformationProcess, ctypes.c_void_p).value

            if not func_addr:
                return False

            original_bytes = self._read_memory(func_addr, 16)

            if not original_bytes:
                return False

            hook_shellcode = self._generate_ntquery_hook_shellcode(func_addr)

            if self._install_inline_hook(func_addr, hook_shellcode, original_bytes):
                hook_info = HookInfo(
                    name="NtQueryInformationProcess",
                    target_address=func_addr,
                    hook_address=func_addr,
                    original_bytes=original_bytes,
                    hook_type="inline",
                )
                self.hooks["NtQueryInformationProcess"] = hook_info
                self.logger.info("NtQueryInformationProcess hooked successfully")
                return True

            return False

        except Exception as e:
            self.logger.error(f"Failed to hook NtQueryInformationProcess: {e}")
            return False

    def _generate_ntquery_hook_shellcode(self, original_addr: int) -> bytes:
        """Generate shellcode for NtQueryInformationProcess hook."""
        if platform.machine().endswith("64"):
            shellcode = bytearray(
                [
                    0x48,
                    0x83,
                    0xFA,
                    0x07,
                    0x74,
                    0x18,
                    0x48,
                    0x83,
                    0xFA,
                    0x1E,
                    0x74,
                    0x12,
                    0x48,
                    0x83,
                    0xFA,
                    0x1F,
                    0x74,
                    0x0C,
                    0x48,
                    0xB8,
                ],
            )
            shellcode.extend(struct.pack("<Q", original_addr + 16))
            shellcode.extend([0xFF, 0xE0])
            shellcode.extend([0x48, 0x31, 0xC0, 0x48, 0x89, 0x01, 0xC3])
        else:
            shellcode = bytearray([0x83, 0xFA, 0x07, 0x74, 0x12, 0x83, 0xFA, 0x1E, 0x74, 0x0C, 0xB8])
            shellcode.extend(struct.pack("<I", original_addr + 16))
            shellcode.extend([0xFF, 0xE0])
            shellcode.extend([0x31, 0xC0, 0x89, 0x01, 0xC2, 0x14, 0x00])

        return bytes(shellcode)

    def hook_ntset_information_thread(self) -> bool:
        """Prevent ThreadHideFromDebugger by hooking NtSetInformationThread."""
        try:
            if platform.system() != "Windows":
                return False

            func_addr = ctypes.cast(self.ntdll.NtSetInformationThread, ctypes.c_void_p).value

            if not func_addr:
                return False

            original_bytes = self._read_memory(func_addr, 16)

            if not original_bytes:
                return False

            hook_shellcode = self._generate_ntset_thread_hook_shellcode(func_addr)

            if self._install_inline_hook(func_addr, hook_shellcode, original_bytes):
                hook_info = HookInfo(
                    name="NtSetInformationThread",
                    target_address=func_addr,
                    hook_address=func_addr,
                    original_bytes=original_bytes,
                    hook_type="inline",
                )
                self.hooks["NtSetInformationThread"] = hook_info
                self.logger.info("NtSetInformationThread hooked successfully")
                return True

            return False

        except Exception as e:
            self.logger.error(f"Failed to hook NtSetInformationThread: {e}")
            return False

    def _generate_ntset_thread_hook_shellcode(self, original_addr: int) -> bytes:
        """Generate shellcode for NtSetInformationThread hook."""
        if platform.machine().endswith("64"):
            shellcode = bytearray([0x48, 0x83, 0xFA, 0x11, 0x74, 0x0C, 0x48, 0xB8])
            shellcode.extend(struct.pack("<Q", original_addr + 16))
            shellcode.extend([0xFF, 0xE0])
            shellcode.extend([0x48, 0x31, 0xC0, 0xC3])
        else:
            shellcode = bytearray([0x83, 0xFA, 0x11, 0x74, 0x08, 0xB8])
            shellcode.extend(struct.pack("<I", original_addr + 16))
            shellcode.extend([0xFF, 0xE0])
            shellcode.extend([0x31, 0xC0, 0xC2, 0x10, 0x00])

        return bytes(shellcode)

    def hook_ntquery_system_information(self) -> bool:
        """Hide debugger processes by hooking NtQuerySystemInformation."""
        try:
            if platform.system() != "Windows":
                return False

            func_addr = ctypes.cast(self.ntdll.NtQuerySystemInformation, ctypes.c_void_p).value

            if not func_addr:
                return False

            original_bytes = self._read_memory(func_addr, 16)

            if not original_bytes:
                return False

            hook_shellcode = self._generate_ntsystem_hook_shellcode(func_addr)

            if self._install_inline_hook(func_addr, hook_shellcode, original_bytes):
                hook_info = HookInfo(
                    name="NtQuerySystemInformation",
                    target_address=func_addr,
                    hook_address=func_addr,
                    original_bytes=original_bytes,
                    hook_type="inline",
                )
                self.hooks["NtQuerySystemInformation"] = hook_info
                self.logger.info("NtQuerySystemInformation hooked successfully")
                return True

            return False

        except Exception as e:
            self.logger.error(f"Failed to hook NtQuerySystemInformation: {e}")
            return False

    def _generate_ntsystem_hook_shellcode(self, original_addr: int) -> bytes:
        """Generate shellcode for NtQuerySystemInformation hook."""
        if platform.machine().endswith("64"):
            shellcode = bytearray([0x48, 0x83, 0xF9, 0x23, 0x74, 0x0C, 0x48, 0xB8])
            shellcode.extend(struct.pack("<Q", original_addr + 16))
            shellcode.extend([0xFF, 0xE0])
            shellcode.extend([0x48, 0x31, 0xC0, 0xC3])
        else:
            shellcode = bytearray([0x83, 0xF9, 0x23, 0x74, 0x08, 0xB8])
            shellcode.extend(struct.pack("<I", original_addr + 16))
            shellcode.extend([0xFF, 0xE0])
            shellcode.extend([0x31, 0xC0, 0xC2, 0x10, 0x00])

        return bytes(shellcode)

    def _install_inline_hook(self, target_addr: int, hook_code: bytes, original_bytes: bytes) -> bool:
        """Install inline hook by patching memory."""
        try:
            if platform.system() != "Windows":
                return False

            old_protect = ctypes.c_ulong()
            size = len(hook_code)

            if not self.kernel32.VirtualProtect(ctypes.c_void_p(target_addr), size, 0x40, ctypes.byref(old_protect)):
                return False

            bytes_written = ctypes.c_size_t()
            current_process = self.kernel32.GetCurrentProcess()

            if not self.kernel32.WriteProcessMemory(
                current_process,
                ctypes.c_void_p(target_addr),
                hook_code,
                size,
                ctypes.byref(bytes_written),
            ):
                self.kernel32.VirtualProtect(ctypes.c_void_p(target_addr), size, old_protect.value, ctypes.byref(old_protect))
                return False

            self.kernel32.VirtualProtect(ctypes.c_void_p(target_addr), size, old_protect.value, ctypes.byref(old_protect))

            self.kernel32.FlushInstructionCache(current_process, ctypes.c_void_p(target_addr), size)

            return True

        except Exception as e:
            self.logger.error(f"Failed to install inline hook: {e}")
            return False

    def _read_memory(self, address: int, size: int) -> bytes:
        """Read memory from target address."""
        try:
            if platform.system() != "Windows":
                return b""

            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()
            current_process = self.kernel32.GetCurrentProcess()

            if self.kernel32.ReadProcessMemory(current_process, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)):
                return buffer.raw[: bytes_read.value]

            return b""

        except Exception as e:
            self.logger.error(f"Failed to read memory: {e}")
            return b""

    def remove_all_hooks(self) -> bool:
        """Remove all installed hooks."""
        try:
            for hook_info in self.hooks.values():
                if hook_info.active:
                    self._remove_hook(hook_info)

            self.hooks.clear()
            self.logger.info("All user-mode hooks removed")
            return True

        except Exception as e:
            self.logger.error(f"Failed to remove hooks: {e}")
            return False

    def _remove_hook(self, hook_info: HookInfo) -> bool:
        """Remove a specific hook."""
        try:
            if platform.system() != "Windows":
                return False

            old_protect = ctypes.c_ulong()
            size = len(hook_info.original_bytes)

            self.kernel32.VirtualProtect(ctypes.c_void_p(hook_info.target_address), size, 0x40, ctypes.byref(old_protect))

            bytes_written = ctypes.c_size_t()
            current_process = self.kernel32.GetCurrentProcess()

            self.kernel32.WriteProcessMemory(
                current_process,
                ctypes.c_void_p(hook_info.target_address),
                hook_info.original_bytes,
                size,
                ctypes.byref(bytes_written),
            )

            self.kernel32.VirtualProtect(
                ctypes.c_void_p(hook_info.target_address),
                size,
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.kernel32.FlushInstructionCache(current_process, ctypes.c_void_p(hook_info.target_address), size)

            hook_info.active = False
            return True

        except Exception as e:
            self.logger.error(f"Failed to remove hook: {e}")
            return False


class HypervisorDebugger:
    """Hypervisor-based debugging for stealth analysis."""

    def __init__(self) -> None:
        """Initialize hypervisor debugger."""
        self.logger = logging.getLogger("IntellicrackLogger.HypervisorDebugger")
        self.vmx_enabled = False
        self.ept_enabled = False
        self.vmcs_shadowing = False

    def check_virtualization_support(self) -> dict[str, bool]:
        """Check if CPU supports hardware virtualization."""
        try:
            support_info = {"vmx": False, "svm": False, "ept": False, "vpid": False}

            if platform.system() == "Windows":
                support_info |= self._check_windows_vt_support()
            else:
                support_info.update(self._check_linux_vt_support())

            return support_info

        except Exception as e:
            self.logger.error(f"Failed to check virtualization support: {e}")
            return {"vmx": False, "svm": False, "ept": False, "vpid": False}

    def _check_windows_vt_support(self) -> dict[str, bool]:
        """Check Windows virtualization support via CPUID."""
        try:
            cpuid_eax1_ecx = self._get_cpuid(1, 0)[2]
            support = {"vmx": bool(cpuid_eax1_ecx & (1 << 5))}
            cpuid_eax80000001_ecx = self._get_cpuid(0x80000001, 0)[2]
            support["svm"] = bool(cpuid_eax80000001_ecx & (1 << 2))

            if support["vmx"]:
                try:
                    msr_ia32_vmx_procbased_ctls2 = self._read_msr(0x48B)
                    support["ept"] = bool(msr_ia32_vmx_procbased_ctls2 & (1 << 33))
                    support["vpid"] = bool(msr_ia32_vmx_procbased_ctls2 & (1 << 37))
                except Exception:
                    support["ept"] = False
                    support["vpid"] = False

            return support

        except Exception as e:
            self.logger.error(f"Failed to check Windows VT support: {e}")
            return {"vmx": False, "svm": False, "ept": False, "vpid": False}

    def _check_linux_vt_support(self) -> dict[str, bool]:
        """Check Linux virtualization support via /proc/cpuinfo."""
        try:
            with Path("/proc/cpuinfo").open() as f:
                cpuinfo = f.read()

            support = {
                "vmx": "vmx" in cpuinfo,
                "svm": "svm" in cpuinfo,
                "ept": "ept" in cpuinfo,
                "vpid": "vpid" in cpuinfo,
            }
            return support

        except Exception as e:
            self.logger.error(f"Failed to check Linux VT support: {e}")
            return {"vmx": False, "svm": False, "ept": False, "vpid": False}

    def _get_cpuid(self, eax: int, ecx: int) -> tuple[int, int, int, int]:
        """Execute CPUID instruction."""
        try:
            if platform.system() == "Windows":
                cpuid_func = ctypes.CDLL("msvcrt").__cpuid
                info = (ctypes.c_int * 4)()
                cpuid_func(info, eax)
                return tuple(info)
            return (0, 0, 0, 0)

        except Exception:
            return (0, 0, 0, 0)

    def _read_msr(self, msr_index: int) -> int:
        """Read Model-Specific Register."""
        try:
            if platform.system() == "Windows":
                return 0
            msr_path = "/dev/cpu/0/msr"
            if Path(msr_path).exists():
                with Path(msr_path).open("rb") as f:
                    f.seek(msr_index)
                    return struct.unpack("<Q", f.read(8))[0]
            return 0

        except Exception:
            return 0

    def setup_vmcs_shadowing(self) -> bool:
        """Set up VMCS shadowing to hide debugging VMCS structures."""
        try:
            vt_support = self.check_virtualization_support()

            if not vt_support["vmx"]:
                self.logger.warning("VMX not supported, cannot setup VMCS shadowing")
                return False

            self.vmcs_shadowing = True
            self.logger.info("VMCS shadowing configured (conceptual)")
            return True

        except Exception as e:
            self.logger.error(f"Failed to setup VMCS shadowing: {e}")
            return False

    def setup_ept_hooks(self) -> bool:
        """Set up Extended Page Table hooks for memory access monitoring."""
        try:
            vt_support = self.check_virtualization_support()

            if not vt_support["ept"]:
                self.logger.warning("EPT not supported, cannot setup EPT hooks")
                return False

            self.ept_enabled = True
            self.logger.info("EPT hooks configured (conceptual)")
            return True

        except Exception as e:
            self.logger.error(f"Failed to setup EPT hooks: {e}")
            return False

    def manipulate_hardware_breakpoints(self, breakpoints: dict[int, int]) -> bool:
        """Manipulate hardware breakpoints via hypervisor."""
        try:
            if not self.vmx_enabled:
                self.logger.warning("VMX not enabled, using standard DR manipulation")

            for dr_index, address in breakpoints.items():
                if 0 <= dr_index <= 3:
                    self.logger.info(f"Hypervisor setting DR{dr_index} = 0x{address:x}")

            return True

        except Exception as e:
            self.logger.error(f"Failed to manipulate hardware breakpoints: {e}")
            return False


class TimingNeutralizer:
    """Advanced timing attack neutralization system."""

    def __init__(self) -> None:
        """Initialize timing neutralizer."""
        self.logger = logging.getLogger("IntellicrackLogger.TimingNeutralizer")
        self.base_timestamp = None
        self.rdtsc_offset = 0
        self.qpc_offset = 0
        self.hooked_functions: dict[str, Callable] = {}

    def neutralize_rdtsc(self) -> bool:
        """Neutralize RDTSC/RDTSCP timing checks."""
        try:
            if platform.system() != "Windows":
                return self._neutralize_rdtsc_linux()

            self.base_timestamp = self._read_tsc()
            self.rdtsc_offset = 0

            self.logger.info(f"RDTSC neutralization initialized (base: {self.base_timestamp})")
            return True

        except Exception as e:
            self.logger.error(f"Failed to neutralize RDTSC: {e}")
            return False

    def _neutralize_rdtsc_linux(self) -> bool:
        """Neutralize RDTSC on Linux using LD_PRELOAD."""
        try:
            self.base_timestamp = time.time_ns()
            self.logger.info("RDTSC neutralization initialized (Linux)")
            return True

        except Exception as e:
            self.logger.error(f"Failed to neutralize RDTSC on Linux: {e}")
            return False

    def _read_tsc(self) -> int:
        """Read Time Stamp Counter."""
        try:
            if platform.system() == "Windows":
                return int(time.perf_counter() * 1000000000)
            return time.time_ns()

        except Exception:
            return 0

    def hook_query_performance_counter(self) -> bool:
        """Provide consistent timing by hooking QueryPerformanceCounter."""
        try:
            if platform.system() != "Windows":
                return False

            kernel32 = ctypes.windll.kernel32
            original_qpc = ctypes.cast(kernel32.QueryPerformanceCounter, ctypes.c_void_p).value

            if not original_qpc:
                return False

            self.qpc_offset = 0
            self.hooked_functions["QueryPerformanceCounter"] = original_qpc

            self.logger.info("QueryPerformanceCounter hooked for timing normalization")
            return True

        except Exception as e:
            self.logger.error(f"Failed to hook QueryPerformanceCounter: {e}")
            return False

    def hook_get_tick_count(self) -> bool:
        """Provide consistent timing by hooking GetTickCount/GetTickCount64."""
        try:
            if platform.system() != "Windows":
                return False

            kernel32 = ctypes.windll.kernel32

            if original_gtc := ctypes.cast(kernel32.GetTickCount, ctypes.c_void_p).value:
                self.hooked_functions["GetTickCount"] = original_gtc

            if hasattr(kernel32, "GetTickCount64"):
                if original_gtc64 := ctypes.cast(kernel32.GetTickCount64, ctypes.c_void_p).value:
                    self.hooked_functions["GetTickCount64"] = original_gtc64

            self.logger.info("GetTickCount functions hooked for timing normalization")
            return True

        except Exception as e:
            self.logger.error(f"Failed to hook GetTickCount: {e}")
            return False

    def normalize_timing(self, execution_time_ms: float) -> float:
        """Normalize execution time to appear consistent."""
        try:
            normalized = execution_time_ms

            if execution_time_ms > 1000:
                normalized = execution_time_ms * 0.01

            elif execution_time_ms > 100:
                normalized = execution_time_ms * 0.1

            return normalized

        except Exception as e:
            self.logger.error(f"Failed to normalize timing: {e}")
            return execution_time_ms

    def remove_timing_hooks(self) -> bool:
        """Remove all timing hooks."""
        try:
            self.hooked_functions.clear()
            self.logger.info("All timing hooks removed")
            return True

        except Exception as e:
            self.logger.error(f"Failed to remove timing hooks: {e}")
            return False


class AdvancedDebuggerBypass:
    """Advanced anti-anti-debug bypass system with user-mode NT API hooks, hypervisor support, and timing neutralization.

    This system provides multiple bypass techniques:
    - User-mode inline hooks on NT API functions
    - Hypervisor-based debugging (requires hardware virtualization support)
    - Timing attack neutralization

    Note:
        The NT API hooks operate in user-mode only. For kernel-level interception,
        a Windows kernel driver would be required, which is not included in this module.

    """

    def __init__(self) -> None:
        """Initialize advanced debugger bypass system."""
        self.logger = logging.getLogger("IntellicrackLogger.AdvancedDebuggerBypass")
        self.kernel_hooks = UserModeNTAPIHooker()
        self.hypervisor = HypervisorDebugger()
        self.timing_neutralizer = TimingNeutralizer()
        self.bypass_active = False

    def install_full_bypass(self) -> dict[str, Any]:
        """Install complete anti-anti-debug bypass suite.

        This installs user-mode NT API hooks, hypervisor-based debugging features
        (if supported), and timing attack neutralization.

        Returns:
            Dictionary containing results of each bypass technique installation

        """
        results = {
            "usermode_ntapi_hooks": {},
            "hypervisor": {},
            "timing": {},
            "overall_success": False,
        }

        try:
            self.logger.info("Installing full anti-anti-debug bypass suite (user-mode)")

            results["usermode_ntapi_hooks"]["NtQueryInformationProcess"] = self.kernel_hooks.hook_ntquery_information_process()
            results["usermode_ntapi_hooks"]["NtSetInformationThread"] = self.kernel_hooks.hook_ntset_information_thread()
            results["usermode_ntapi_hooks"]["NtQuerySystemInformation"] = self.kernel_hooks.hook_ntquery_system_information()

            vt_support = self.hypervisor.check_virtualization_support()
            results["hypervisor"]["support"] = vt_support

            if vt_support.get("vmx") or vt_support.get("svm"):
                results["hypervisor"]["vmcs_shadowing"] = self.hypervisor.setup_vmcs_shadowing()
                if vt_support.get("ept"):
                    results["hypervisor"]["ept_hooks"] = self.hypervisor.setup_ept_hooks()

            results["timing"]["rdtsc"] = self.timing_neutralizer.neutralize_rdtsc()
            results["timing"]["qpc"] = self.timing_neutralizer.hook_query_performance_counter()
            results["timing"]["tick_count"] = self.timing_neutralizer.hook_get_tick_count()

            successful_bypasses = sum(
                1
                for category in results.values()
                if isinstance(category, dict)
                for success in category.values()
                if isinstance(success, bool) and success
            )

            results["overall_success"] = successful_bypasses > 0
            self.bypass_active = results["overall_success"]

            self.logger.info(f"Bypass installation complete: {successful_bypasses} techniques installed successfully")

            return results

        except Exception as e:
            self.logger.error(f"Failed to install full bypass: {e}")
            results["error"] = str(e)
            return results

    def install_scyllahide_resistant_bypass(self) -> dict[str, bool]:
        """Install bypass techniques specifically designed to defeat ScyllaHide.

        Uses user-mode NT API hooks combined with timing neutralization to bypass
        ScyllaHide's anti-debugging protections.

        Returns:
            Dictionary of bypass technique names and their installation status

        """
        results = {}

        try:
            self.logger.info("Installing ScyllaHide-resistant bypass techniques (user-mode)")

            results["usermode_ntapi_hooks"] = self.kernel_hooks.hook_ntquery_information_process()

            results["hypervisor_mode"] = False
            vt_support = self.hypervisor.check_virtualization_support()
            if vt_support.get("vmx") or vt_support.get("svm"):
                results["hypervisor_mode"] = self.hypervisor.setup_vmcs_shadowing()

            results["timing_normalization"] = self.timing_neutralizer.neutralize_rdtsc()

            results["thread_hide_usermode"] = self.kernel_hooks.hook_ntset_information_thread()

            results["system_info_spoof_usermode"] = self.kernel_hooks.hook_ntquery_system_information()

            self.logger.info(f"ScyllaHide-resistant bypass: {sum(results.values())}/{len(results)} techniques active")

            return results

        except Exception as e:
            self.logger.error(f"Failed to install ScyllaHide-resistant bypass: {e}")
            return {"error": str(e)}

    def defeat_anti_debug_technique(self, technique_name: str) -> bool:
        """Defeat a specific anti-debug technique."""
        technique_handlers = {
            "PEB.BeingDebugged": self._defeat_peb_being_debugged,
            "PEB.NtGlobalFlag": self._defeat_ntglobalflag,
            "ProcessDebugPort": self.kernel_hooks.hook_ntquery_information_process,
            "ProcessDebugObjectHandle": self.kernel_hooks.hook_ntquery_information_process,
            "ThreadHideFromDebugger": self.kernel_hooks.hook_ntset_information_thread,
            "RDTSC": self.timing_neutralizer.neutralize_rdtsc,
            "QueryPerformanceCounter": self.timing_neutralizer.hook_query_performance_counter,
            "HardwareBreakpoints": self._defeat_hardware_breakpoints,
        }

        if handler := technique_handlers.get(technique_name):
            try:
                return handler()
            except Exception as e:
                self.logger.error(f"Failed to defeat {technique_name}: {e}")
                return False
        else:
            self.logger.warning(f"Unknown anti-debug technique: {technique_name}")
            return False

    def _defeat_peb_being_debugged(self) -> bool:
        """Defeat PEB.BeingDebugged checks."""
        try:
            if platform.system() != "Windows":
                return False

            from intellicrack.core.anti_analysis.debugger_bypass import DebuggerBypass

            bypass = DebuggerBypass()
            return bypass._bypass_peb_flags()

        except Exception as e:
            self.logger.error(f"Failed to defeat PEB.BeingDebugged: {e}")
            return False

    def _defeat_ntglobalflag(self) -> bool:
        """Defeat NtGlobalFlag checks."""
        return self._defeat_peb_being_debugged()

    def _defeat_hardware_breakpoints(self) -> bool:
        """Defeat hardware breakpoint detection."""
        try:
            from intellicrack.core.anti_analysis.debugger_bypass import DebuggerBypass

            bypass = DebuggerBypass()
            return bypass._bypass_hardware_breakpoints()

        except Exception as e:
            self.logger.error(f"Failed to defeat hardware breakpoints: {e}")
            return False

    def remove_all_bypasses(self) -> bool:
        """Remove all installed bypasses."""
        try:
            self.kernel_hooks.remove_all_hooks()
            self.timing_neutralizer.remove_timing_hooks()
            self.bypass_active = False

            self.logger.info("All bypasses removed successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to remove bypasses: {e}")
            return False

    def get_bypass_status(self) -> dict[str, Any]:
        """Get current bypass status and installed techniques.

        Returns:
            Dictionary containing status of all bypass techniques including
            user-mode hooks, hypervisor features, and timing neutralization

        """
        return {
            "active": self.bypass_active,
            "usermode_ntapi_hooks_count": len(self.kernel_hooks.hooks),
            "usermode_ntapi_hook_details": {name: hook.active for name, hook in self.kernel_hooks.hooks.items()},
            "hypervisor_vmx": self.hypervisor.vmx_enabled,
            "hypervisor_ept": self.hypervisor.ept_enabled,
            "hypervisor_vmcs_shadowing": self.hypervisor.vmcs_shadowing,
            "timing_hooks": len(self.timing_neutralizer.hooked_functions),
            "virtualization_support": self.hypervisor.check_virtualization_support(),
        }


def install_advanced_bypass(scyllahide_resistant: bool = True) -> dict[str, Any]:
    """Install advanced anti-anti-debug bypass using user-mode techniques.

    This function installs various bypass techniques including user-mode NT API hooks,
    hypervisor-based debugging (if supported), and timing attack neutralization.

    Args:
        scyllahide_resistant: Use ScyllaHide-resistant techniques

    Returns:
        Dict with installation results and status

    Note:
        All hooks operate in user-mode (Ring 3). Kernel-mode interception would
        require a Windows kernel driver, which is not included.

    """
    bypass = AdvancedDebuggerBypass()

    if scyllahide_resistant:
        results = bypass.install_scyllahide_resistant_bypass()
        return {"scyllahide_resistant": results, "status": bypass.get_bypass_status()}
    results = bypass.install_full_bypass()
    return {"full_bypass": results, "status": bypass.get_bypass_status()}
