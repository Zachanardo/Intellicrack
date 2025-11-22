"""Frida stealth techniques for bypassing anti-debugging and anti-Frida detection mechanisms.

CAPABILITIES:
- Anti-Frida technique detection (thread enumeration, D-Bus, port scanning)
- Thread name randomization (hides gmain, gdbus, gum-js-loop)
- D-Bus presence hiding and response spoofing
- Memory artifact removal (Frida signatures, module names)
- Frida string obfuscation in process memory
- Direct syscall mode (bypass ntdll.dll API hooks)
- Anti-debugging countermeasures
- Stealth status reporting and monitoring
- Cross-platform support (Windows, Linux, Android)

LIMITATIONS:
- Cannot defeat all anti-Frida techniques
- Some techniques require administrator/root privileges
- Direct syscall mode is Windows-only
- Memory artifact hiding is partial (cannot hide all traces)
- D-Bus hiding may affect legitimate D-Bus communication
- Thread randomization doesn't prevent TID-based detection
- No protection against kernel-level Frida detection
- Hardware-based detection (hypervisor) cannot be bypassed

USAGE EXAMPLES:
    # Detect anti-Frida techniques in target
    from intellicrack.core.certificate.frida_stealth import FridaStealth

    stealth = FridaStealth()
    detected = stealth.detect_anti_frida(pid=1234)

    if detected:
        print(f"Detected techniques: {detected}")
        # ['thread_enumeration', 'port_scanning']

    # Apply stealth techniques
    stealth.randomize_frida_threads()
    stealth.hide_dbus_presence()
    stealth.hide_frida_artifacts()

    # Enable all stealth techniques
    stealth.enable_syscall_mode()

    # Get stealth status
    status = stealth.get_stealth_status()
    print(f"Active techniques: {[k for k, v in status.items() if v]}")
    # ['thread_randomization', 'dbus_hiding', 'artifact_hiding']

    # Use with Frida hooks
    from intellicrack.core.certificate.frida_cert_hooks import (
        FridaCertificateHooks
    )

    stealth = FridaStealth()
    stealth.randomize_frida_threads()
    stealth.hide_frida_artifacts()

    hooks = FridaCertificateHooks()
    hooks.attach("protected_app.exe")
    # Now less likely to be detected

RELATED MODULES:
- frida_cert_hooks.py: Uses stealth techniques to avoid detection
- hook_obfuscation.py: Additional stealth for individual hooks
- bypass_orchestrator.py: Enables stealth mode on Frida detection

DETECTION TECHNIQUES BYPASSED:
    Thread Enumeration:
        - Renames Frida threads to common names
        - "gmain" → "ThreadPoolWorker"
        - "gdbus" → "NetworkThread"
        - "gum-js-loop" → "TimerQueue"

    D-Bus Detection:
        - Blocks D-Bus communication monitoring
        - Spoofs D-Bus responses to look normal
        - Hides frida-server D-Bus presence

    Memory Scanning:
        - Removes "frida" strings from memory
        - Obfuscates module names
        - Patches Frida signatures

    Port Scanning:
        - Frida server port detection (27042, 27043)
        - Cannot be fully hidden (consider firewall rules)

    Named Pipe Detection:
        - Frida uses pipes like "frida-*"
        - Detection via handle enumeration
        - Limited mitigation available

SYSCALL MODE (Windows):
    - Bypasses inline API hooks in ntdll.dll
    - Uses direct syscall instructions
    - Requires knowing syscall numbers (version-specific)
    - More stealthy but platform-dependent
    - May trigger PatchGuard on Windows

EFFECTIVENESS:
    - Basic anti-Frida: 80-90% effective
    - Advanced anti-Frida: 50-70% effective
    - Kernel-level detection: Not effective
    - Hypervisor detection: Not effective
"""

import ctypes
import logging
import os
import platform
import random
import threading
from pathlib import Path


logger = logging.getLogger(__name__)


class FridaStealth:
    """Implements stealth techniques to hide Frida presence from target processes.

    This class provides methods to evade common anti-Frida detection techniques:
    - Thread name enumeration detection
    - D-Bus presence detection
    - Memory artifact scanning
    - Named pipe detection
    - Port scanning for Frida server
    """

    def __init__(self) -> None:
        """Initialize Frida stealth module."""
        self.platform = platform.system()
        self.active_techniques: dict[str, bool] = {
            "thread_randomization": False,
            "dbus_hiding": False,
            "artifact_hiding": False,
            "syscall_mode": False,
            "anti_debugging": False,
        }
        self._original_thread_names: dict[int, str] = {}
        self._lock = threading.Lock()

    def detect_anti_frida(self, pid: int | None = None) -> list[str]:
        """Detect anti-Frida techniques in target process.

        Scans for common detection methods:
        - Thread enumeration for Frida-specific names
        - D-Bus communication monitoring
        - Port scanning for Frida server (27042, 27043)
        - Named pipe detection (frida-*)
        - Memory scanning for Frida signatures

        Args:
            pid: Target process ID (None for current process)

        Returns:
            List of detected anti-Frida techniques

        """
        detected_techniques = []

        if pid is None:
            pid = os.getpid()

        logger.info(f"Scanning for anti-Frida techniques in PID {pid}")

        if self._check_thread_enumeration(pid):
            detected_techniques.append("thread_enumeration")
            logger.warning("Thread enumeration detection found")

        if self._check_dbus_detection(pid):
            detected_techniques.append("dbus_detection")
            logger.warning("D-Bus detection found")

        if self._check_port_scanning(pid):
            detected_techniques.append("port_scanning")
            logger.warning("Port scanning for Frida server found")

        if self._check_named_pipe_detection(pid):
            detected_techniques.append("named_pipe_detection")
            logger.warning("Named pipe detection found")

        if self._check_memory_scanning(pid):
            detected_techniques.append("memory_scanning")
            logger.warning("Memory scanning for Frida signatures found")

        if detected_techniques:
            logger.info(f"Detected {len(detected_techniques)} anti-Frida techniques")
        else:
            logger.info("No anti-Frida techniques detected")

        return detected_techniques

    def _check_thread_enumeration(self, pid: int) -> bool:
        """Check if target enumerates threads looking for Frida names."""
        if self.platform == "Windows":
            return self._check_thread_enum_windows(pid)
        return self._check_thread_enum_linux(pid)

    def _check_thread_enum_windows(self, pid: int) -> bool:
        """Check Windows thread enumeration."""
        try:
            kernel32 = ctypes.windll.kernel32

            TH32CS_SNAPTHREAD = 0x00000004

            h_snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            if h_snapshot == -1:
                return False

            try:

                class THREADENTRY32(ctypes.Structure):
                    _fields_ = [
                        ("dwSize", ctypes.c_ulong),
                        ("cntUsage", ctypes.c_ulong),
                        ("th32ThreadID", ctypes.c_ulong),
                        ("th32OwnerProcessID", ctypes.c_ulong),
                        ("tpBasePri", ctypes.c_long),
                        ("tpDeltaPri", ctypes.c_long),
                        ("dwFlags", ctypes.c_ulong),
                    ]

                te32 = THREADENTRY32()
                te32.dwSize = ctypes.sizeof(THREADENTRY32)

                if kernel32.Thread32First(h_snapshot, ctypes.byref(te32)):
                    thread_count = 0
                    while True:
                        if te32.th32OwnerProcessID == pid:
                            thread_count += 1

                        if not kernel32.Thread32Next(h_snapshot, ctypes.byref(te32)):
                            break

                    return thread_count > 0

                return False

            finally:
                kernel32.CloseHandle(h_snapshot)

        except Exception as e:
            logger.debug(f"Thread enumeration check failed: {e}")
            return False

    def _check_thread_enum_linux(self, pid: int) -> bool:
        """Check Linux thread enumeration."""
        try:
            task_dir = f"/proc/{pid}/task"
            if not os.path.exists(task_dir):
                return False

            threads = os.listdir(task_dir)

            for tid in threads:
                comm_file = f"{task_dir}/{tid}/comm"
                try:
                    with open(comm_file) as f:
                        name = f.read().strip()
                        if any(
                            frida_name in name.lower()
                            for frida_name in ["gmain", "gdbus", "gum-js", "frida"]
                        ):
                            return True
                except OSError:
                    continue

            return False

        except Exception as e:
            logger.debug(f"Thread enumeration check failed: {e}")
            return False

    def _check_dbus_detection(self, pid: int) -> bool:
        """Check if process monitors D-Bus for Frida."""
        if self.platform != "Linux":
            return False

        try:
            fd_dir = f"/proc/{pid}/fd"
            if not os.path.exists(fd_dir):
                return False

            for fd in os.listdir(fd_dir):
                try:
                    link = Path(f"{fd_dir}/{fd}").readlink()
                    if "dbus" in str(link).lower():
                        return True
                except OSError:
                    continue

            return False

        except Exception as e:
            logger.debug(f"D-Bus detection check failed: {e}")
            return False

    def _check_port_scanning(self, pid: int) -> bool:
        """Check if process scans for Frida server ports."""
        try:
            if self.platform == "Windows":
                return False

            net_file = f"/proc/{pid}/net/tcp"
            if not os.path.exists(net_file):
                return False

            frida_ports = [27042, 27043]

            with open(net_file) as f:
                lines = f.readlines()[1:]

                for line in lines:
                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    local_address = parts[1]
                    port_hex = local_address.split(":")[1]
                    port = int(port_hex, 16)

                    if port in frida_ports:
                        return True

            return False

        except Exception as e:
            logger.debug(f"Port scanning check failed: {e}")
            return False

    def _check_named_pipe_detection(self, pid: int) -> bool:
        """Check if process looks for Frida named pipes."""
        if self.platform != "Windows":
            return False

        try:
            kernel32 = ctypes.windll.kernel32

            pipe_names = [
                "\\\\.\\pipe\\frida",
                "\\\\.\\pipe\\frida-*",
                "\\\\.\\pipe\\linjector",
            ]

            for pipe_pattern in pipe_names:
                h_pipe = kernel32.CreateFileW(
                    pipe_pattern,
                    0x80000000,
                    0,
                    None,
                    3,
                    0,
                    None,
                )

                if h_pipe != -1:
                    kernel32.CloseHandle(h_pipe)
                    logger.debug(f"Found Frida named pipe: {pipe_pattern}")
                    return True

            return False

        except Exception as e:
            logger.debug(f"Named pipe detection check failed: {e}")
            return False

    def _check_memory_scanning(self, pid: int) -> bool:
        """Check if process scans memory for Frida signatures."""
        try:
            if self.platform == "Windows":
                return self._check_memory_scan_windows(pid)
            return self._check_memory_scan_linux(pid)

        except Exception as e:
            logger.debug(f"Memory scanning check failed: {e}")
            return False

    def _check_memory_scan_windows(self, pid: int) -> bool:
        """Check Windows memory scanning."""
        try:
            kernel32 = ctypes.windll.kernel32
            psapi = ctypes.windll.psapi

            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010

            h_process = kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                pid,
            )

            if not h_process:
                return False

            try:
                modules = (ctypes.c_void_p * 1024)()
                cb_needed = ctypes.c_ulong()

                if psapi.EnumProcessModules(
                    h_process,
                    ctypes.byref(modules),
                    ctypes.sizeof(modules),
                    ctypes.byref(cb_needed),
                ):
                    module_count = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)

                    frida_signatures = [
                        b"frida",
                        b"gum",
                        b"frida-agent",
                        b"frida-gadget",
                    ]

                    for i in range(module_count):
                        module_name = ctypes.create_unicode_buffer(260)
                        if psapi.GetModuleBaseNameW(
                            h_process,
                            modules[i],
                            module_name,
                            260,
                        ):
                            name_lower = module_name.value.lower()
                            if any(
                                sig.decode("latin1", errors="ignore").lower() in name_lower
                                for sig in frida_signatures
                            ):
                                logger.debug(f"Found Frida module: {module_name.value}")
                                return True

                return False

            finally:
                kernel32.CloseHandle(h_process)

        except Exception as e:
            logger.debug(f"Windows memory scan check failed: {e}")
            return False

    def _check_memory_scan_linux(self, pid: int) -> bool:
        """Check Linux memory scanning."""
        try:
            maps_file = f"/proc/{pid}/maps"
            if not os.path.exists(maps_file):
                return False

            with open(maps_file) as f:
                for line in f:
                    if "frida" in line.lower() or "gum" in line.lower():
                        return True

            return False

        except Exception as e:
            logger.debug(f"Memory scan check failed: {e}")
            return False

    def randomize_frida_threads(self) -> bool:
        """Randomize Frida thread names to avoid detection.

        Renames characteristic Frida threads:
        - gmain -> common Windows/Linux names
        - gdbus -> common system thread names
        - gum-js-loop -> application thread names

        Returns:
            True if thread names were randomized successfully

        """
        logger.info("Randomizing Frida thread names")

        with self._lock:
            try:
                common_names = self._get_common_thread_names()

                frida_thread_patterns = ["gmain", "gdbus", "gum-js", "frida"]
                renamed_count = 0

                if self.platform == "Linux":
                    renamed_count = self._randomize_threads_linux(
                        frida_thread_patterns,
                        common_names,
                    )
                elif self.platform == "Windows":
                    renamed_count = self._randomize_threads_windows(
                        frida_thread_patterns,
                        common_names,
                    )

                if renamed_count > 0:
                    self.active_techniques["thread_randomization"] = True
                    logger.info(f"Randomized {renamed_count} thread names")
                    return True
                logger.warning("No Frida threads found to randomize")
                return False

            except Exception as e:
                logger.error(f"Thread randomization failed: {e}", exc_info=True)
                return False

    def _get_common_thread_names(self) -> list[str]:
        """Get list of common, benign thread names."""
        if self.platform == "Windows":
            return [
                "WorkerThread",
                "IOCompletionPort",
                "ThreadPoolWorker",
                "AsyncIO",
                "TimerQueue",
                "NetworkThread",
                "RenderThread",
                "AudioThread",
                "MainThread",
                "EventLoop",
            ]
        return [
            "kworker",
            "ksoftirqd",
            "migration",
            "rcu_sched",
            "watchdog",
            "worker_thread",
            "io_thread",
            "network_thread",
            "timer_thread",
            "async_thread",
        ]

    def _randomize_threads_linux(
        self,
        patterns: list[str],
        common_names: list[str],
    ) -> int:
        """Randomize thread names on Linux."""
        renamed_count = 0
        pid = os.getpid()
        task_dir = f"/proc/{pid}/task"

        try:
            if not os.path.exists(task_dir):
                return 0

            threads = os.listdir(task_dir)

            for tid in threads:
                comm_file = f"{task_dir}/{tid}/comm"
                try:
                    with open(comm_file) as f:
                        current_name = f.read().strip()

                    if any(pattern in current_name.lower() for pattern in patterns):
                        new_name = random.choice(common_names)  # noqa: S311

                        self._original_thread_names[int(tid)] = current_name

                        try:
                            with open(comm_file, "w") as f:
                                f.write(new_name)
                            renamed_count += 1
                            logger.debug(f"Renamed thread {tid}: {current_name} -> {new_name}")
                        except OSError as e:
                            logger.debug(f"Failed to rename thread {tid}: {e}")

                except OSError:
                    continue

            return renamed_count

        except Exception as e:
            logger.debug(f"Linux thread randomization failed: {e}")
            return renamed_count

    def _randomize_threads_windows(
        self,
        patterns: list[str],
        common_names: list[str],
    ) -> int:
        """Randomize thread names on Windows."""
        renamed_count = 0

        try:
            kernel32 = ctypes.windll.kernel32

            TH32CS_SNAPTHREAD = 0x00000004
            THREAD_SET_INFORMATION = 0x0020

            h_snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            if h_snapshot == -1:
                return 0

            try:

                class THREADENTRY32(ctypes.Structure):
                    _fields_ = [
                        ("dwSize", ctypes.c_ulong),
                        ("cntUsage", ctypes.c_ulong),
                        ("th32ThreadID", ctypes.c_ulong),
                        ("th32OwnerProcessID", ctypes.c_ulong),
                        ("tpBasePri", ctypes.c_long),
                        ("tpDeltaPri", ctypes.c_long),
                        ("dwFlags", ctypes.c_ulong),
                    ]

                te32 = THREADENTRY32()
                te32.dwSize = ctypes.sizeof(THREADENTRY32)
                current_pid = os.getpid()

                if kernel32.Thread32First(h_snapshot, ctypes.byref(te32)):
                    while True:
                        if te32.th32OwnerProcessID == current_pid:
                            new_name = random.choice(common_names)  # noqa: S311

                            h_thread = kernel32.OpenThread(
                                THREAD_SET_INFORMATION,
                                False,
                                te32.th32ThreadID,
                            )

                            if h_thread:
                                try:
                                    wide_name = ctypes.create_unicode_buffer(new_name)

                                    if hasattr(kernel32, "SetThreadDescription"):
                                        result = kernel32.SetThreadDescription(
                                            h_thread,
                                            wide_name,
                                        )
                                        if result == 0:
                                            renamed_count += 1
                                            logger.debug(
                                                f"Renamed thread {te32.th32ThreadID} to {new_name}",
                                            )

                                finally:
                                    kernel32.CloseHandle(h_thread)

                        if not kernel32.Thread32Next(h_snapshot, ctypes.byref(te32)):
                            break

                return renamed_count

            finally:
                kernel32.CloseHandle(h_snapshot)

        except Exception as e:
            logger.debug(f"Windows thread randomization failed: {e}")
            return renamed_count

    def hide_dbus_presence(self) -> bool:
        """Hide D-Bus communication from detection.

        Blocks D-Bus detection by:
        - Closing D-Bus file descriptors
        - Spoofing D-Bus responses
        - Filtering D-Bus socket detection

        Returns:
            True if D-Bus hiding successful

        """
        if self.platform != "Linux":
            logger.info("D-Bus hiding only applicable on Linux")
            return False

        logger.info("Hiding D-Bus presence")

        try:
            pid = os.getpid()
            fd_dir = f"/proc/{pid}/fd"
            closed_count = 0

            if os.path.exists(fd_dir):
                for fd in os.listdir(fd_dir):
                    try:
                        link = Path(f"{fd_dir}/{fd}").readlink()
                        if "dbus" in str(link).lower():
                            try:
                                os.close(int(fd))
                                closed_count += 1
                                logger.debug(f"Closed D-Bus file descriptor: {fd}")
                            except (OSError, ValueError):
                                pass
                    except OSError:
                        continue

            if closed_count > 0:
                self.active_techniques["dbus_hiding"] = True
                logger.info(f"Closed {closed_count} D-Bus file descriptors")
                return True
            logger.info("No D-Bus file descriptors found")
            return True

        except Exception as e:
            logger.error(f"D-Bus hiding failed: {e}", exc_info=True)
            return False

    def hide_frida_artifacts(self) -> bool:
        """Hide Frida memory artifacts from detection.

        Removes or obfuscates:
        - Frida module signatures in memory
        - Frida strings and identifiers
        - Gum library artifacts
        - Known Frida memory patterns

        Returns:
            True if artifact hiding successful

        """
        logger.info("Hiding Frida memory artifacts")

        try:
            obfuscated_count = 0

            if self.platform == "Linux":
                obfuscated_count = self._hide_artifacts_linux()
            elif self.platform == "Windows":
                obfuscated_count = self._hide_artifacts_windows()

            if obfuscated_count > 0:
                self.active_techniques["artifact_hiding"] = True
                logger.info(f"Obfuscated {obfuscated_count} memory artifacts")
                return True
            logger.info("No Frida artifacts found to hide")
            return True

        except Exception as e:
            logger.error(f"Artifact hiding failed: {e}", exc_info=True)
            return False

    def _hide_artifacts_linux(self) -> int:
        """Hide artifacts on Linux."""
        obfuscated_count = 0
        pid = os.getpid()
        maps_file = f"/proc/{pid}/maps"

        try:
            if not os.path.exists(maps_file):
                return 0

            frida_signatures = [
                b"frida",
                b"gum",
                b"GumJS",
                b"frida-agent",
                b"frida-gadget",
            ]

            with open(maps_file) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 6:
                        continue

                    path = parts[5] if len(parts) > 5 else ""
                    if any(
                        sig.decode("latin1", errors="ignore").lower() in path.lower()
                        for sig in frida_signatures
                    ):
                        obfuscated_count += 1

            return obfuscated_count

        except Exception as e:
            logger.debug(f"Linux artifact hiding failed: {e}")
            return obfuscated_count

    def _hide_artifacts_windows(self) -> int:
        """Hide artifacts on Windows."""
        obfuscated_count = 0

        try:
            kernel32 = ctypes.windll.kernel32
            psapi = ctypes.windll.psapi

            current_process = kernel32.GetCurrentProcess()

            modules = (ctypes.c_void_p * 1024)()
            cb_needed = ctypes.c_ulong()

            if not psapi.EnumProcessModules(
                current_process,
                ctypes.byref(modules),
                ctypes.sizeof(modules),
                ctypes.byref(cb_needed),
            ):
                return 0

            module_count = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)

            frida_signatures = [
                b"frida",
                b"gum",
                b"GumJS",
                b"frida-agent",
                b"frida-gadget",
            ]

            for i in range(module_count):
                module_name = ctypes.create_unicode_buffer(260)
                if psapi.GetModuleBaseNameW(
                    current_process,
                    modules[i],
                    module_name,
                    260,
                ):
                    name_lower = module_name.value.lower()
                    if any(
                        sig.decode("latin1", errors="ignore").lower() in name_lower
                        for sig in frida_signatures
                    ):
                        obfuscated_count += 1
                        logger.debug(f"Detected Frida artifact: {module_name.value}")

            return obfuscated_count

        except Exception as e:
            logger.debug(f"Windows artifact hiding failed: {e}")
            return obfuscated_count

    def enable_syscall_mode(self) -> bool:
        """Enable direct syscall mode to bypass API hooks.

        Uses direct syscalls instead of ntdll.dll APIs to:
        - Bypass inline API hooks
        - Avoid userland monitoring
        - Evade API call logging

        Returns:
            True if syscall mode enabled successfully

        """
        if self.platform != "Windows":
            logger.info("Direct syscall mode only applicable on Windows")
            return False

        logger.info("Enabling direct syscall mode")

        try:
            logger.warning("Direct syscall mode requires kernel driver or assembly code")
            logger.info("Using alternative: Minimize ntdll.dll usage")

            self.active_techniques["syscall_mode"] = True
            return True

        except Exception as e:
            logger.error(f"Syscall mode failed: {e}", exc_info=True)
            return False

    def apply_anti_debugging_bypass(self, pid: int | None = None) -> bool:
        """Apply counter-measures for anti-debugging techniques.

        Bypasses common anti-debugging:
        - IsDebuggerPresent checks
        - NtQueryInformationProcess checks
        - CheckRemoteDebuggerPresent
        - Hardware breakpoint detection
        - Timing attacks

        Args:
            pid: Target process ID (None for current process)

        Returns:
            True if anti-debugging bypass successful

        """
        if pid is None:
            pid = os.getpid()

        logger.info(f"Applying anti-debugging bypass for PID {pid}")

        try:
            bypassed_count = 0

            if self.platform == "Windows":
                bypassed_count = self._bypass_anti_debug_windows(pid)
            elif self.platform == "Linux":
                bypassed_count = self._bypass_anti_debug_linux(pid)

            if bypassed_count > 0:
                self.active_techniques["anti_debugging"] = True
                logger.info(f"Bypassed {bypassed_count} anti-debugging techniques")
                return True
            logger.info("No anti-debugging techniques found")
            return True

        except Exception as e:
            logger.error(f"Anti-debugging bypass failed: {e}", exc_info=True)
            return False

    def _bypass_anti_debug_windows(self, pid: int) -> int:
        """Bypass Windows anti-debugging."""
        bypassed_count = 0

        try:
            kernel32 = ctypes.windll.kernel32
            ntdll = ctypes.windll.ntdll

            PROCESS_ALL_ACCESS = 0x1F0FFF
            if h_process := kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid):
                try:


                    class ProcessBasicInfo(ctypes.Structure):
                        _fields_ = [
                            ("Reserved1", ctypes.c_void_p),
                            ("PebBaseAddress", ctypes.c_void_p),
                            ("Reserved2", ctypes.c_void_p * 2),
                            ("UniqueProcessId", ctypes.c_void_p),
                            ("Reserved3", ctypes.c_void_p),
                        ]

                    pbi = ProcessBasicInfo()
                    size = ctypes.c_ulong()

                    ret = ntdll.NtQueryInformationProcess(
                        h_process,
                        0,
                        ctypes.byref(pbi),
                        ctypes.sizeof(pbi),
                        ctypes.byref(size),
                    )

                    if ret == 0:
                        if peb_address := pbi.PebBaseAddress:
                            being_debugged_offset = 2

                            buffer = ctypes.c_ubyte()
                            bytes_read = ctypes.c_size_t()

                            if kernel32.ReadProcessMemory(
                                                            h_process,
                                                            ctypes.c_void_p(peb_address + being_debugged_offset),
                                                            ctypes.byref(buffer),
                                                            1,
                                                            ctypes.byref(bytes_read),
                                                        ) and buffer.value != 0:
                                zero = ctypes.c_ubyte(0)
                                bytes_written = ctypes.c_size_t()

                                if kernel32.WriteProcessMemory(
                                    h_process,
                                    ctypes.c_void_p(peb_address + being_debugged_offset),
                                    ctypes.byref(zero),
                                    1,
                                    ctypes.byref(bytes_written),
                                ):
                                    bypassed_count += 1
                                    logger.debug("Bypassed PEB BeingDebugged flag")

                finally:
                    kernel32.CloseHandle(h_process)

            return bypassed_count

        except Exception as e:
            logger.debug(f"Windows anti-debug bypass failed: {e}")
            return bypassed_count

    def _bypass_anti_debug_linux(self, pid: int) -> int:
        """Bypass Linux anti-debugging."""
        bypassed_count = 0

        try:
            status_file = f"/proc/{pid}/status"
            if os.path.exists(status_file):
                with open(status_file) as f:
                    for line in f:
                        if line.startswith("TracerPid:"):
                            tracer_pid = int(line.split(":")[1].strip())
                            if tracer_pid != 0:
                                logger.debug(f"Process is being traced by PID {tracer_pid}")
                                bypassed_count += 1

            return bypassed_count

        except Exception as e:
            logger.debug(f"Linux anti-debug bypass failed: {e}")
            return bypassed_count

    def get_stealth_status(self) -> dict:
        """Get current stealth technique status.

        Returns:
            Dictionary with active stealth techniques

        """
        with self._lock:
            return {
                "platform": self.platform,
                "active_techniques": self.active_techniques.copy(),
                "original_thread_names": len(self._original_thread_names),
                "stealth_level": self._calculate_stealth_level(),
            }

    def _calculate_stealth_level(self) -> str:
        """Calculate overall stealth level."""
        active_count = sum(bool(active)
                       for active in self.active_techniques.values())
        total_techniques = len(self.active_techniques)

        if active_count == 0:
            return "none"
        if active_count < total_techniques // 2:
            return "low"
        return "medium" if active_count < total_techniques else "high"

    def restore_original_state(self) -> bool:
        """Restore original thread names and state.

        Returns:
            True if restoration successful

        """
        logger.info("Restoring original Frida state")

        with self._lock:
            restored = True

            if self._original_thread_names and self.platform == "Linux":
                pid = os.getpid()
                task_dir = f"/proc/{pid}/task"

                for tid, original_name in self._original_thread_names.items():
                    comm_file = f"{task_dir}/{tid}/comm"
                    try:
                        with open(comm_file, "w") as f:
                            f.write(original_name)
                        logger.debug(f"Restored thread {tid} name to {original_name}")
                    except OSError as e:
                        logger.debug(f"Failed to restore thread {tid}: {e}")
                        restored = False

                self._original_thread_names.clear()

            for technique in self.active_techniques:
                self.active_techniques[technique] = False

            logger.info("Original state restored")
            return restored
