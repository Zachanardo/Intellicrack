"""Hook obfuscation techniques to prevent detection and maintain integrity."""

import ctypes
import hashlib
import logging
import random
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class HookInfo:
    """Information about an installed hook."""

    target_address: int
    handler_address: int
    original_bytes: bytes
    hook_type: str
    installed_at: float
    callback_name: str
    integrity_hash: str
    tamper_count: int = 0


class HookObfuscator:
    """Implements hook obfuscation and integrity monitoring techniques.

    Provides methods to:
    - Generate random, benign-looking callback names
    - Create indirect hooks via function pointer chains
    - Monitor hook integrity and detect tampering
    - Use hardware breakpoint hooks (DR0-DR3)
    - Utilize code caves for trampoline placement
    - Rotate hooks periodically to avoid signature detection
    """

    def __init__(self):
        """Initialize hook obfuscator."""
        self.installed_hooks: Dict[int, HookInfo] = {}
        self.code_caves: Dict[str, List[int]] = {}
        self.integrity_monitor_active = False
        self._lock = threading.Lock()
        self._integrity_thread: Optional[threading.Thread] = None
        self._stop_monitoring = threading.Event()

    def generate_random_callback_name(self) -> str:
        """Generate random, benign-looking callback name.

        Creates names that blend in with normal application code:
        - process_data_handler
        - handle_network_response
        - update_ui_state
        - validate_input_data

        Returns:
            Random benign callback name

        """
        prefixes = [
            "process", "handle", "update", "validate", "check", "parse",
            "format", "convert", "transform", "filter", "sort", "calculate"
        ]

        subjects = [
            "data", "response", "request", "input", "output", "state",
            "config", "settings", "buffer", "packet", "message", "event",
            "notification", "callback", "handler", "processor"
        ]

        suffixes = [
            "handler", "processor", "manager", "controller", "validator",
            "formatter", "converter", "filter", "sorter", "calculator"
        ]

        prefix = random.choice(prefixes)  # noqa: S311
        subject = random.choice(subjects)  # noqa: S311
        suffix = random.choice(suffixes)  # noqa: S311

        name = f"{prefix}_{subject}_{suffix}"

        logger.debug(f"Generated callback name: {name}")
        return name

    def create_indirect_hook(
        self,
        target: int,
        handler: int,
        chain_length: int = 3
    ) -> bool:
        """Create indirect hook using function pointer chains.

        Instead of direct Interceptor.attach, creates a chain of trampolines:
        target -> trampoline1 -> trampoline2 -> ... -> handler

        This makes it harder to trace the hook to its actual destination.

        Args:
            target: Target function address
            handler: Handler function address
            chain_length: Number of trampolines in chain (default 3)

        Returns:
            True if indirect hook created successfully

        """
        logger.info(f"Creating indirect hook: {hex(target)} -> {hex(handler)} (chain: {chain_length})")

        try:
            with self._lock:
                if target in self.installed_hooks:
                    logger.warning(f"Hook already exists at {hex(target)}")
                    return False

                code_cave = self._find_code_cave(chain_length * 32)
                if not code_cave:
                    logger.warning("No suitable code cave found, using allocated memory")
                    code_cave = self._allocate_trampoline_space(chain_length * 32)

                original_bytes = self._read_memory(target, 16)
                if not original_bytes:
                    logger.error("Failed to read original bytes")
                    return False

                chain_addresses = self._build_trampoline_chain(
                    code_cave, handler, chain_length
                )

                if not chain_addresses:
                    logger.error("Failed to build trampoline chain")
                    return False

                if not self._install_jump_to_chain(target, chain_addresses[0]):
                    logger.error("Failed to install initial jump")
                    return False

                callback_name = self.generate_random_callback_name()
                integrity_hash = self._calculate_hook_hash(target, handler, original_bytes)

                hook_info = HookInfo(
                    target_address=target,
                    handler_address=handler,
                    original_bytes=original_bytes,
                    hook_type="indirect_chain",
                    installed_at=time.time(),
                    callback_name=callback_name,
                    integrity_hash=integrity_hash,
                )

                self.installed_hooks[target] = hook_info

                logger.info(f"Indirect hook installed successfully at {hex(target)}")
                return True

        except Exception as e:
            logger.error(f"Failed to create indirect hook: {e}", exc_info=True)
            return False

    def _find_code_cave(self, min_size: int) -> Optional[int]:
        """Find code cave in loaded modules.

        Code caves are unused sections of memory in executable modules,
        typically padding between functions or sections.

        Args:
            min_size: Minimum required size in bytes

        Returns:
            Address of suitable code cave or None

        """
        logger.debug(f"Searching for code cave of size {min_size}")

        try:
            caves = self.code_caves.get("available", [])

            for cave_addr in caves:
                cave_size = self._get_cave_size(cave_addr)
                if cave_size >= min_size:
                    logger.debug(f"Found suitable code cave at {hex(cave_addr)}")
                    return cave_addr

            return None

        except Exception as e:
            logger.debug(f"Code cave search failed: {e}")
            return None

    def _get_cave_size(self, address: int) -> int:
        """Get size of code cave at address."""
        try:
            data = self._read_memory(address, 1024)
            if not data:
                return 0

            null_count = 0
            for byte in data:
                if byte == 0 or byte == 0xCC:
                    null_count += 1
                else:
                    break

            return null_count

        except Exception:
            return 0

    def _allocate_trampoline_space(self, size: int) -> int:
        """Allocate memory for trampoline code."""
        logger.debug(f"Allocating {size} bytes for trampoline")

        try:
            if hasattr(ctypes, 'windll'):
                kernel32 = ctypes.windll.kernel32

                MEM_COMMIT = 0x1000
                MEM_RESERVE = 0x2000
                PAGE_EXECUTE_READWRITE = 0x40

                addr = kernel32.VirtualAlloc(
                    None,
                    size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                )

                if addr:
                    logger.debug(f"Allocated trampoline space at {hex(addr)}")
                    return addr

            return 0

        except Exception as e:
            logger.debug(f"Trampoline allocation failed: {e}")
            return 0

    def _build_trampoline_chain(
        self,
        start_address: int,
        final_handler: int,
        chain_length: int
    ) -> List[int]:
        """Build chain of trampolines."""
        chain_addresses = []
        current_addr = start_address

        try:
            for i in range(chain_length):
                chain_addresses.append(current_addr)

                if i == chain_length - 1:
                    next_target = final_handler
                else:
                    next_target = current_addr + 32

                jmp_code = self._generate_jmp_code(next_target)

                if not self._write_memory(current_addr, jmp_code):
                    logger.error(f"Failed to write trampoline {i}")
                    return []

                current_addr += 32

            logger.debug(f"Built trampoline chain: {[hex(a) for a in chain_addresses]}")
            return chain_addresses

        except Exception as e:
            logger.error(f"Trampoline chain build failed: {e}")
            return []

    def _generate_jmp_code(self, target: int) -> bytes:
        """Generate x86/x64 JMP instruction."""
        import platform
        is_64bit = platform.machine().endswith('64')

        if is_64bit:
            return bytes([
                0x48, 0xB8,
                *target.to_bytes(8, 'little'),
                0xFF, 0xE0
            ])
        else:
            return bytes([
                0xE9,
                *((target - 5) & 0xFFFFFFFF).to_bytes(4, 'little')
            ])

    def _install_jump_to_chain(self, target: int, chain_start: int) -> bool:
        """Install initial jump from target to trampoline chain."""
        try:
            jmp_code = self._generate_jmp_code(chain_start)

            if not self._write_memory(target, jmp_code):
                return False

            self._flush_instruction_cache(target, len(jmp_code))
            return True

        except Exception as e:
            logger.error(f"Failed to install jump: {e}")
            return False

    def _read_memory(self, address: int, size: int) -> Optional[bytes]:
        """Read memory at address."""
        try:
            if hasattr(ctypes, 'windll'):
                kernel32 = ctypes.windll.kernel32

                buffer = (ctypes.c_ubyte * size)()
                bytes_read = ctypes.c_size_t()

                current_process = kernel32.GetCurrentProcess()

                if kernel32.ReadProcessMemory(
                    current_process,
                    ctypes.c_void_p(address),
                    ctypes.byref(buffer),
                    size,
                    ctypes.byref(bytes_read)
                ):
                    return bytes(buffer)

            return None

        except Exception as e:
            logger.debug(f"Memory read failed: {e}")
            return None

    def _write_memory(self, address: int, data: bytes) -> bool:
        """Write memory at address."""
        try:
            if hasattr(ctypes, 'windll'):
                kernel32 = ctypes.windll.kernel32

                old_protect = ctypes.c_ulong()
                PAGE_EXECUTE_READWRITE = 0x40

                current_process = kernel32.GetCurrentProcess()

                if not kernel32.VirtualProtect(
                    ctypes.c_void_p(address),
                    len(data),
                    PAGE_EXECUTE_READWRITE,
                    ctypes.byref(old_protect)
                ):
                    return False

                buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
                bytes_written = ctypes.c_size_t()

                success = kernel32.WriteProcessMemory(
                    current_process,
                    ctypes.c_void_p(address),
                    ctypes.byref(buffer),
                    len(data),
                    ctypes.byref(bytes_written)
                )

                kernel32.VirtualProtect(
                    ctypes.c_void_p(address),
                    len(data),
                    old_protect.value,
                    ctypes.byref(old_protect)
                )

                return success

            return False

        except Exception as e:
            logger.debug(f"Memory write failed: {e}")
            return False

    def _flush_instruction_cache(self, address: int, size: int) -> None:
        """Flush instruction cache."""
        try:
            if hasattr(ctypes, 'windll'):
                kernel32 = ctypes.windll.kernel32
                current_process = kernel32.GetCurrentProcess()
                kernel32.FlushInstructionCache(
                    current_process,
                    ctypes.c_void_p(address),
                    size
                )
        except Exception as e:
            logger.debug(f"Failed to flush instruction cache: {e}")

    def _calculate_hook_hash(
        self,
        target: int,
        handler: int,
        original_bytes: bytes
    ) -> str:
        """Calculate integrity hash for hook."""
        data = f"{target}{handler}{original_bytes.hex()}".encode()
        return hashlib.sha256(data).hexdigest()

    def monitor_hook_integrity(self) -> None:
        """Continuously monitor hook integrity.

        Periodically checks if hooks are still active and haven't been
        tampered with. Re-applies hooks if removed by target.
        """
        if self.integrity_monitor_active:
            logger.warning("Integrity monitor already running")
            return

        logger.info("Starting hook integrity monitor")

        self.integrity_monitor_active = True
        self._stop_monitoring.clear()

        self._integrity_thread = threading.Thread(
            target=self._integrity_monitor_loop,
            daemon=True
        )
        self._integrity_thread.start()

    def _integrity_monitor_loop(self) -> None:
        """Run integrity monitoring loop."""
        logger.info("Integrity monitor loop started")

        check_interval = 2.0

        while not self._stop_monitoring.is_set():
            try:
                with self._lock:
                    for target, hook_info in list(self.installed_hooks.items()):
                        if self._check_hook_integrity(hook_info):
                            logger.debug(f"Hook at {hex(target)} is intact")
                        else:
                            logger.warning(f"Hook at {hex(target)} was tampered with!")
                            hook_info.tamper_count += 1

                            if self._reinstall_hook(hook_info):
                                logger.info(f"Hook at {hex(target)} reinstalled")
                            else:
                                logger.error(f"Failed to reinstall hook at {hex(target)}")

                time.sleep(check_interval)

            except Exception as e:
                logger.error(f"Integrity monitor error: {e}", exc_info=True)
                time.sleep(check_interval)

        logger.info("Integrity monitor loop stopped")

    def _check_hook_integrity(self, hook_info: HookInfo) -> bool:
        """Check if hook is still intact."""
        try:
            current_bytes = self._read_memory(hook_info.target_address, 16)
            if not current_bytes:
                return False

            if current_bytes == hook_info.original_bytes:
                return False

            return True

        except Exception as e:
            logger.debug(f"Integrity check failed: {e}")
            return False

    def _reinstall_hook(self, hook_info: HookInfo) -> bool:
        """Reinstall tampered hook."""
        try:
            logger.info(f"Reinstalling hook at {hex(hook_info.target_address)}")

            if hook_info.hook_type == "indirect_chain":
                return self.create_indirect_hook(
                    hook_info.target_address,
                    hook_info.handler_address
                )

            return False

        except Exception as e:
            logger.error(f"Hook reinstall failed: {e}")
            return False

    def stop_integrity_monitor(self) -> None:
        """Stop integrity monitoring."""
        if not self.integrity_monitor_active:
            return

        logger.info("Stopping hook integrity monitor")

        self._stop_monitoring.set()

        if self._integrity_thread:
            self._integrity_thread.join(timeout=5.0)

        self.integrity_monitor_active = False
        logger.info("Integrity monitor stopped")

    def install_hwbp_hook(self, address: int, handler: Callable) -> bool:
        """Install hardware breakpoint hook using debug registers.

        Uses DR0-DR3 debug registers to set hardware breakpoints.
        Alternative to inline hooks, harder to detect.

        Args:
            address: Address to hook
            handler: Handler function

        Returns:
            True if hardware breakpoint installed successfully

        """
        logger.info(f"Installing hardware breakpoint hook at {hex(address)}")

        try:
            if not hasattr(ctypes, 'windll'):
                logger.warning("Hardware breakpoints only supported on Windows")
                return False

            kernel32 = ctypes.windll.kernel32

            current_thread = kernel32.GetCurrentThread()

            class CONTEXT(ctypes.Structure):
                _fields_ = [
                    ("ContextFlags", ctypes.c_ulong),
                    ("Dr0", ctypes.c_ulonglong),
                    ("Dr1", ctypes.c_ulonglong),
                    ("Dr2", ctypes.c_ulonglong),
                    ("Dr3", ctypes.c_ulonglong),
                    ("Dr6", ctypes.c_ulonglong),
                    ("Dr7", ctypes.c_ulonglong),
                ]

            context = CONTEXT()
            context.ContextFlags = 0x00010000 | 0x00000010

            if not kernel32.GetThreadContext(current_thread, ctypes.byref(context)):
                logger.error("Failed to get thread context")
                return False

            if context.Dr0 == 0:
                context.Dr0 = address
                context.Dr7 |= (1 << 0)
                logger.debug("Set hardware breakpoint in DR0")
            elif context.Dr1 == 0:
                context.Dr1 = address
                context.Dr7 |= (1 << 2)
                logger.debug("Set hardware breakpoint in DR1")
            elif context.Dr2 == 0:
                context.Dr2 = address
                context.Dr7 |= (1 << 4)
                logger.debug("Set hardware breakpoint in DR2")
            elif context.Dr3 == 0:
                context.Dr3 = address
                context.Dr7 |= (1 << 6)
                logger.debug("Set hardware breakpoint in DR3")
            else:
                logger.error("All debug registers in use")
                return False

            if not kernel32.SetThreadContext(current_thread, ctypes.byref(context)):
                logger.error("Failed to set thread context")
                return False

            logger.info("Hardware breakpoint hook installed successfully")
            return True

        except Exception as e:
            logger.error(f"Hardware breakpoint hook failed: {e}", exc_info=True)
            return False

    def find_code_caves(self, module: str) -> List[int]:
        """Find code caves in specified module.

        Scans for sequences of null bytes or INT3 instructions (0xCC)
        that can be used for trampoline placement.

        Args:
            module: Module name to scan

        Returns:
            List of code cave addresses

        """
        logger.info(f"Scanning for code caves in module: {module}")

        caves = []

        try:
            if not hasattr(ctypes, 'windll'):
                logger.warning("Code cave detection only supported on Windows")
                return caves

            kernel32 = ctypes.windll.kernel32

            h_module = kernel32.GetModuleHandleW(module)
            if not h_module:
                logger.error(f"Module not found: {module}")
                return caves

            class MODULEINFO(ctypes.Structure):
                _fields_ = [
                    ("lpBaseOfDll", ctypes.c_void_p),
                    ("SizeOfImage", ctypes.c_ulong),
                    ("EntryPoint", ctypes.c_void_p),
                ]

            psapi = ctypes.windll.psapi
            mod_info = MODULEINFO()

            if not psapi.GetModuleInformation(
                kernel32.GetCurrentProcess(),
                h_module,
                ctypes.byref(mod_info),
                ctypes.sizeof(mod_info)
            ):
                logger.error("Failed to get module information")
                return caves

            base_addr = mod_info.lpBaseOfDll
            size = mod_info.SizeOfImage

            logger.debug(f"Scanning module: base={hex(base_addr)}, size={size}")

            scan_size = 4096
            for offset in range(0, size, scan_size):
                addr = base_addr + offset
                data = self._read_memory(addr, min(scan_size, size - offset))

                if data:
                    cave_addr = self._find_cave_in_data(addr, data)
                    if cave_addr:
                        caves.append(cave_addr)

            logger.info(f"Found {len(caves)} code caves in {module}")
            self.code_caves[module] = caves

            return caves

        except Exception as e:
            logger.error(f"Code cave search failed: {e}", exc_info=True)
            return caves

    def _find_cave_in_data(self, base_addr: int, data: bytes) -> Optional[int]:
        """Find code cave in memory data."""
        min_cave_size = 32
        current_cave_start = None
        current_cave_size = 0

        for i, byte in enumerate(data):
            if byte == 0 or byte == 0xCC:
                if current_cave_start is None:
                    current_cave_start = base_addr + i
                current_cave_size += 1
            else:
                if current_cave_size >= min_cave_size:
                    return current_cave_start
                current_cave_start = None
                current_cave_size = 0

        if current_cave_size >= min_cave_size:
            return current_cave_start

        return None

    def rotate_hooks(self) -> bool:
        """Rotate hooks to different locations.

        Periodically moves hooks to prevent signature-based detection.
        Creates new trampolines at different addresses.

        Returns:
            True if hooks rotated successfully

        """
        logger.info("Rotating hooks to avoid detection")

        try:
            with self._lock:
                rotated_count = 0

                for target, hook_info in list(self.installed_hooks.items()):
                    if self._rotate_single_hook(hook_info):
                        rotated_count += 1
                    else:
                        logger.warning(f"Failed to rotate hook at {hex(target)}")

                logger.info(f"Rotated {rotated_count}/{len(self.installed_hooks)} hooks")
                return rotated_count > 0

        except Exception as e:
            logger.error(f"Hook rotation failed: {e}", exc_info=True)
            return False

    def _rotate_single_hook(self, hook_info: HookInfo) -> bool:
        """Rotate a single hook to new location."""
        try:
            new_cave = self._find_code_cave(96)
            if not new_cave:
                return False

            if not self._write_memory(hook_info.target_address, hook_info.original_bytes):
                return False

            return self.create_indirect_hook(
                hook_info.target_address,
                hook_info.handler_address
            )

        except Exception as e:
            logger.debug(f"Single hook rotation failed: {e}")
            return False

    def get_hook_status(self) -> Dict:
        """Get status of all installed hooks.

        Returns:
            Dictionary with hook statistics

        """
        with self._lock:
            return {
                "total_hooks": len(self.installed_hooks),
                "active_hooks": [hex(addr) for addr in self.installed_hooks.keys()],
                "integrity_monitor_active": self.integrity_monitor_active,
                "total_tampering_attempts": sum(
                    h.tamper_count for h in self.installed_hooks.values()
                ),
                "code_caves_found": sum(len(caves) for caves in self.code_caves.values()),
            }

    def remove_all_hooks(self) -> bool:
        """Remove all installed hooks and restore original code.

        Returns:
            True if all hooks removed successfully

        """
        logger.info("Removing all hooks")

        with self._lock:
            removed_count = 0

            for target, hook_info in list(self.installed_hooks.items()):
                if self._write_memory(target, hook_info.original_bytes):
                    self._flush_instruction_cache(target, len(hook_info.original_bytes))
                    removed_count += 1
                    del self.installed_hooks[target]
                else:
                    logger.error(f"Failed to remove hook at {hex(target)}")

            logger.info(f"Removed {removed_count} hooks")
            return removed_count == len(self.installed_hooks)
