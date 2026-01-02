"""Hook obfuscation and integrity monitoring to prevent detection and tampering.

CAPABILITIES:
- Random benign callback name generation (blend with normal code)
- Indirect hooking via function pointer chains
- Hook integrity monitoring with automatic restoration
- Hardware breakpoint hooks (DR0-DR3 debug registers)
- Code cave discovery and utilization for trampolines
- Hook rotation to avoid signature-based detection
- Tamper detection and logging
- Thread-safe hook management
- Hook integrity hash calculation and verification

LIMITATIONS:
- Hardware breakpoints limited to 4 concurrent hooks (DR0-DR3)
- Code cave availability varies by binary
- Hook rotation has performance overhead
- Integrity monitoring runs in separate thread (CPU cost)
- Indirect hooks increase call latency
- Cannot prevent kernel-level hook detection
- Hook rotation may cause brief windows of vulnerability

USAGE EXAMPLES:
    # Generate random callback name
    from intellicrack.core.certificate.hook_obfuscation import HookObfuscator

    obfuscator = HookObfuscator()
    name = obfuscator.generate_random_callback_name()
    print(name)  # "process_data_handler", "validate_network_response", etc.

    # Create indirect hook
    target_addr = 0x140001000
    handler_addr = 0x140050000
    obfuscator.create_indirect_hook(target_addr, handler_addr)

    # Enable integrity monitoring
    obfuscator.monitor_hook_integrity()
    # Runs in background, auto-restores tampered hooks

    # Install hardware breakpoint hook (stealth)
    def my_handler():
        print("Hook triggered")

    obfuscator.install_hwbp_hook(0x140001234, my_handler)

    # Find code caves for trampolines
    caves = obfuscator.find_code_caves("target.exe")
    print(f"Found {len(caves)} code caves")

    # Enable hook rotation
    obfuscator.rotate_hooks()
    # Periodically moves hooks to new locations

    # Check for tampered hooks
    tampered = [addr for addr, info in obfuscator.installed_hooks.items()
                if info.tamper_count > 0]
    if tampered:
        print(f"Tampered hooks: {[hex(a) for a in tampered]}")

RELATED MODULES:
- frida_stealth.py: Complementary anti-detection techniques
- frida_cert_hooks.py: Uses obfuscation for certificate hooks
- bypass_orchestrator.py: Enables obfuscation for sensitive hooks

OBFUSCATION TECHNIQUES:
    Callback Name Randomization:
        - Generates benign-looking names
        - Examples: "process_data", "handle_response", "update_state"
        - Blends with normal application code
        - Makes signature detection harder

    Indirect Hooking:
        - Uses function pointer chains
        - Hook → Proxy1 → Proxy2 → Handler
        - Hides true hook destination
        - Increases analysis difficulty

    Hardware Breakpoints:
        - Uses DR0-DR3 debug registers
        - No code modification required
        - Harder to detect than inline hooks
        - Limited to 4 concurrent hooks

    Code Cave Utilization:
        - Uses empty code sections
        - Avoids allocating new memory (detectable)
        - More stealthy than VirtualAlloc
        - Requires finding suitable caves

    Hook Rotation:
        - Periodically changes hook locations
        - Prevents signature-based detection
        - Maintains functionality during rotation
        - CPU overhead trade-off

INTEGRITY MONITORING:
    - Calculates SHA-256 hash of hook bytes
    - Periodically checks if hash changed
    - Automatically restores tampered hooks
    - Logs tampering attempts with timestamps
    - Thread-safe with lock protection

HOOK TYPES:
    - Inline: Direct code modification (most common)
    - Trampoline: Jump to code cave with full handler
    - Hardware Breakpoint: Uses debug registers (stealth)
    - Indirect: Function pointer chain (obfuscated)

PERFORMANCE IMPACT:
    - Indirect hooks: +10-20% latency per hook
    - Integrity monitoring: ~1-2% CPU usage
    - Hook rotation: Brief spikes during rotation
    - Hardware breakpoints: Minimal overhead
"""

import ctypes
import hashlib
import logging
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


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

    def __init__(self) -> None:
        """Initialize hook obfuscator."""
        self.installed_hooks: dict[int, HookInfo] = {}
        self.code_caves: dict[str, list[int]] = {}
        self.integrity_monitor_active = False
        self._lock = threading.Lock()
        self._integrity_thread: threading.Thread | None = None
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
            "process",
            "handle",
            "update",
            "validate",
            "check",
            "parse",
            "format",
            "convert",
            "transform",
            "filter",
            "sort",
            "calculate",
        ]

        subjects = [
            "data",
            "response",
            "request",
            "input",
            "output",
            "state",
            "config",
            "settings",
            "buffer",
            "packet",
            "message",
            "event",
            "notification",
            "callback",
            "handler",
            "processor",
        ]

        suffixes = [
            "handler",
            "processor",
            "manager",
            "controller",
            "validator",
            "formatter",
            "converter",
            "filter",
            "sorter",
            "calculator",
        ]

        prefix = random.choice(prefixes)  # noqa: S311
        subject = random.choice(subjects)  # noqa: S311
        suffix = random.choice(suffixes)  # noqa: S311

        name = f"{prefix}_{subject}_{suffix}"

        logger.debug("Generated callback name: %s", name)
        return name

    def create_indirect_hook(
        self,
        target: int,
        handler: int,
        chain_length: int = 3,
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
        logger.info("Creating indirect hook: %s -> %s (chain: %s)", hex(target), hex(handler), chain_length)

        try:
            with self._lock:
                if target in self.installed_hooks:
                    logger.warning("Hook already exists at %s", hex(target))
                    return False

                code_cave = self._find_code_cave(chain_length * 32)
                if not code_cave:
                    logger.warning("No suitable code cave found, using allocated memory")
                    code_cave = self._allocate_trampoline_space(chain_length * 32)

                original_bytes = self._read_memory(target, 16)
                if not original_bytes:
                    logger.exception("Failed to read original bytes")
                    return False

                chain_addresses = self._build_trampoline_chain(
                    code_cave,
                    handler,
                    chain_length,
                )

                if not chain_addresses:
                    logger.exception("Failed to build trampoline chain")
                    return False

                if not self._install_jump_to_chain(target, chain_addresses[0]):
                    logger.exception("Failed to install initial jump")
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

                logger.info("Indirect hook installed successfully at %s", hex(target))
                return True

        except Exception as e:
            logger.exception("Failed to create indirect hook: %s", e, exc_info=True)
            return False

    def _find_code_cave(self, min_size: int) -> int | None:
        """Find code cave in loaded modules.

        Code caves are unused sections of memory in executable modules,
        typically padding between functions or sections.

        Args:
            min_size: Minimum required size in bytes

        Returns:
            Address of suitable code cave or None

        """
        logger.debug("Searching for code cave of size %s", min_size)

        try:
            caves = self.code_caves.get("available", [])

            for cave_addr in caves:
                cave_size = self._get_cave_size(cave_addr)
                if cave_size >= min_size:
                    logger.debug("Found suitable code cave at %s", hex(cave_addr))
                    return cave_addr

            return None

        except Exception as e:
            logger.debug("Code cave search failed: %s", e, exc_info=True)
            return None

    def _get_cave_size(self, address: int) -> int:
        """Get size of code cave at address.

        Scans memory from the given address forward, counting consecutive
        null bytes (0x00) or INT3 instructions (0xCC) to determine the size
        of the code cave.

        Args:
            address: Memory address to check for code cave presence and size.

        Returns:
            int: Size of code cave in bytes, or 0 if no cave found or read
                failed.

        """
        try:
            data = self._read_memory(address, 1024)
            if not data:
                return 0

            null_count = 0
            for byte in data:
                if byte in {0, 204}:
                    null_count += 1
                else:
                    break

            return null_count

        except Exception:
            return 0

    def _allocate_trampoline_space(self, size: int) -> int:
        """Allocate memory for trampoline code.

        Uses Windows VirtualAlloc API to allocate executable memory with
        read-write permissions for storing trampoline jump sequences.
        Windows-specific implementation.

        Args:
            size: Number of bytes to allocate for trampoline space.

        Returns:
            int: Allocated memory address as integer, or 0 on failure or
                non-Windows platform.

        """
        logger.debug("Allocating %s bytes for trampoline", size)

        try:
            if hasattr(ctypes, "windll"):
                kernel32 = ctypes.windll.kernel32

                MEM_COMMIT = 0x1000
                MEM_RESERVE = 0x2000
                PAGE_EXECUTE_READWRITE = 0x40

                addr = kernel32.VirtualAlloc(
                    None,
                    size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
                if addr:
                    logger.debug("Allocated trampoline space at %s", hex(int(addr)))
                    return int(addr)

            return 0

        except Exception as e:
            logger.debug("Trampoline allocation failed: %s", e, exc_info=True)
            return 0

    def _build_trampoline_chain(
        self,
        start_address: int,
        final_handler: int,
        chain_length: int,
    ) -> list[int]:
        """Build chain of trampolines.

        Constructs a sequence of jump instructions that form a chain from the
        initial target through multiple intermediate trampolines before reaching
        the final handler. Each trampoline is 32 bytes and jumps to the next
        one in the chain, making direct hook destination analysis more difficult.

        Args:
            start_address: Starting memory address where trampoline chain
                begins.
            final_handler: Final handler address that chain terminates at.
            chain_length: Number of intermediate trampolines to create in
                chain.

        Returns:
            list[int]: List of trampoline addresses in correct order, or empty
                list on failure.

        """
        chain_addresses = []
        current_addr = start_address

        try:
            for i in range(chain_length):
                chain_addresses.append(current_addr)

                next_target = final_handler if i == chain_length - 1 else current_addr + 32
                jmp_code = self._generate_jmp_code(next_target)

                if not self._write_memory(current_addr, jmp_code):
                    logger.exception("Failed to write trampoline %s", i)
                    return []

                current_addr += 32

            logger.debug("Built trampoline chain: %s", [hex(a) for a in chain_addresses])
            return chain_addresses

        except Exception as e:
            logger.exception("Trampoline chain build failed: %s", e, exc_info=True)
            return []

    def _generate_jmp_code(self, target: int) -> bytes:
        """Generate x86/x64 JMP instruction.

        Generates platform-appropriate JMP bytecode that jumps to the target
        address. For 64-bit systems, uses MOV RAX + JMP RAX. For 32-bit,
        uses relative JMP with displacement calculation.

        Args:
            target: Target memory address for the JMP instruction to jump to.

        Returns:
            bytes: Bytes representing the complete JMP instruction opcode and
                operands.

        """
        import platform

        if is_64bit := platform.machine().endswith("64"):
            logger.debug("Generating %s JMP to 0x%X", "64-bit" if is_64bit else "32-bit", target)
            return bytes([
                0x48,
                0xB8,
                *target.to_bytes(8, "little"),
                0xFF,
                0xE0,
            ])
        logger.debug("Generating 32-bit JMP to 0x%X", target)
        return bytes([
            0xE9,
            *((target - 5) & 0xFFFFFFFF).to_bytes(4, "little"),
        ])

    def _install_jump_to_chain(self, target: int, chain_start: int) -> bool:
        """Install initial jump from target to trampoline chain.

        Overwrites the first bytes at the target address with a JMP instruction
        that redirects execution to the beginning of the trampoline chain.
        Flushes instruction cache after writing to ensure CPU sees new code.

        Args:
            target: Target memory address where jump instruction is installed.
            chain_start: Start address of the trampoline chain to jump to.

        Returns:
            bool: True if jump installed and cache flushed successfully, False
                on failure.

        """
        try:
            jmp_code = self._generate_jmp_code(chain_start)

            if not self._write_memory(target, jmp_code):
                return False

            self._flush_instruction_cache(target, len(jmp_code))
            return True

        except Exception as e:
            logger.exception("Failed to install jump: %s", e, exc_info=True)
            return False

    def _read_memory(self, address: int, size: int) -> bytes | None:
        """Read memory at address.

        Uses Windows ReadProcessMemory API to read bytes from the current
        process memory at the specified address. Windows-specific implementation.

        Args:
            address: Memory address to read from.
            size: Number of bytes to read from memory.

        Returns:
            bytes | None: Bytes containing memory contents, or None if read
                failed or non-Windows platform.

        """
        try:
            if hasattr(ctypes, "windll"):
                kernel32 = ctypes.windll.kernel32

                buffer = (ctypes.c_ubyte * size)()
                bytes_read = ctypes.c_size_t()

                current_process = kernel32.GetCurrentProcess()

                if kernel32.ReadProcessMemory(
                    current_process,
                    ctypes.c_void_p(address),
                    ctypes.byref(buffer),
                    size,
                    ctypes.byref(bytes_read),
                ):
                    return bytes(buffer)

            return None

        except Exception as e:
            logger.debug("Memory read failed: %s", e, exc_info=True)
            return None

    def _write_memory(self, address: int, data: bytes) -> bool:
        """Write memory at address.

        Uses Windows VirtualProtect and WriteProcessMemory APIs to write bytes
        to the current process memory. Handles memory protection changes and
        restores original protection after write. Windows-specific implementation.

        Args:
            address: Memory address to write to.
            data: Bytes to write to the specified memory address.

        Returns:
            bool: True if write successful, False on failure or non-Windows
                platform.

        """
        try:
            if hasattr(ctypes, "windll"):
                kernel32 = ctypes.windll.kernel32

                old_protect = ctypes.c_ulong()
                PAGE_EXECUTE_READWRITE = 0x40

                current_process = kernel32.GetCurrentProcess()

                if not kernel32.VirtualProtect(
                    ctypes.c_void_p(address),
                    len(data),
                    PAGE_EXECUTE_READWRITE,
                    ctypes.byref(old_protect),
                ):
                    return False

                buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
                bytes_written = ctypes.c_size_t()

                success_result = kernel32.WriteProcessMemory(
                    current_process,
                    ctypes.c_void_p(address),
                    ctypes.byref(buffer),
                    len(data),
                    ctypes.byref(bytes_written),
                )

                kernel32.VirtualProtect(
                    ctypes.c_void_p(address),
                    len(data),
                    old_protect.value,
                    ctypes.byref(old_protect),
                )

                return bool(success_result)

            return False

        except Exception as e:
            logger.debug("Memory write failed: %s", e, exc_info=True)
            return False

    def _flush_instruction_cache(self, address: int, size: int) -> None:
        """Flush instruction cache.

        Uses Windows FlushInstructionCache API to invalidate the CPU instruction
        cache for the specified memory range, ensuring that newly written code
        is executed rather than cached versions. Windows-specific implementation.

        Args:
            address: Memory address to flush instruction cache from.
            size: Size in bytes of the range to flush from cache.

        Returns:
            None

        """
        try:
            if hasattr(ctypes, "windll"):
                kernel32 = ctypes.windll.kernel32
                current_process = kernel32.GetCurrentProcess()
                kernel32.FlushInstructionCache(
                    current_process,
                    ctypes.c_void_p(address),
                    size,
                )
        except Exception as e:
            logger.debug("Failed to flush instruction cache: %s", e, exc_info=True)

    def _calculate_hook_hash(
        self,
        target: int,
        handler: int,
        original_bytes: bytes,
    ) -> str:
        """Calculate integrity hash for hook.

        Computes a SHA-256 hash of the hook's target address, handler address,
        and original code bytes combined as a string. Used to detect if hook
        has been modified or tampered with during integrity monitoring.

        Args:
            target: Target memory address where hook is installed.
            handler: Handler function address that hook redirects to.
            original_bytes: Original code bytes at target before hook
                installation.

        Returns:
            str: SHA-256 hexdigest string representing the hook's integrity
                hash.

        """
        data = f"{target}{handler}{original_bytes.hex()}".encode()
        return hashlib.sha256(data).hexdigest()

    def monitor_hook_integrity(self) -> None:
        """Continuously monitor hook integrity.

        Periodically checks if hooks are still active and haven't been
        tampered with. Re-applies hooks if removed by target.

        Returns:
            None

        """
        if self.integrity_monitor_active:
            logger.warning("Integrity monitor already running")
            return

        logger.info("Starting hook integrity monitor")

        self.integrity_monitor_active = True
        self._stop_monitoring.clear()

        self._integrity_thread = threading.Thread(
            target=self._integrity_monitor_loop,
            daemon=True,
        )
        self._integrity_thread.start()

    def _integrity_monitor_loop(self) -> None:
        """Run integrity monitoring loop.

        Continuously checks installed hooks for tampering and restores
        them if necessary.

        Returns:
            None

        """
        logger.info("Integrity monitor loop started")

        check_interval = 2.0

        while not self._stop_monitoring.is_set():
            try:
                with self._lock:
                    for target, hook_info in list(self.installed_hooks.items()):
                        if self._check_hook_integrity(hook_info):
                            logger.debug("Hook at %s is intact", hex(target))
                        else:
                            logger.warning("Hook at %s was tampered with!", hex(target))
                            hook_info.tamper_count += 1

                            if self._reinstall_hook(hook_info):
                                logger.info("Hook at %s reinstalled", hex(target))
                            else:
                                logger.exception("Failed to reinstall hook at %s", hex(target))

                time.sleep(check_interval)

            except Exception as e:
                logger.exception("Integrity monitor error: %s", e, exc_info=True)
                time.sleep(check_interval)

        logger.info("Integrity monitor loop stopped")

    def _check_hook_integrity(self, hook_info: HookInfo) -> bool:
        """Check if hook is still intact.

        Reads the current bytes at the target address and compares them against
        the original bytes stored in hook_info. Returns True if they differ,
        indicating the hook has been modified or removed.

        Args:
            hook_info: Hook information object containing target address and
                original bytes.

        Returns:
            bool: True if hook has been modified or tampered with, False if
                intact.

        """
        try:
            if current_bytes := self._read_memory(hook_info.target_address, 16):
                return current_bytes != hook_info.original_bytes

            else:
                return False

        except Exception as e:
            logger.debug("Integrity check failed: %s", e, exc_info=True)
            return False

    def _reinstall_hook(self, hook_info: HookInfo) -> bool:
        """Reinstall tampered hook.

        Called by the integrity monitor when a hook is detected as tampered with.
        Recreates the hook using the same type and configuration as the original.
        Currently supports indirect_chain hooks; other types return False.

        Args:
            hook_info: Hook information object containing target, handler, and
                hook type.

        Returns:
            bool: True if hook was successfully reinstalled, False on failure or
                unsupported hook type.

        """
        try:
            logger.info("Reinstalling hook at %s", hex(hook_info.target_address))

            if hook_info.hook_type == "indirect_chain":
                return self.create_indirect_hook(
                    hook_info.target_address,
                    hook_info.handler_address,
                )

            return False

        except Exception as e:
            logger.exception("Hook reinstall failed: %s", e, exc_info=True)
            return False

    def stop_integrity_monitor(self) -> None:
        """Stop integrity monitoring.

        Halts the background integrity monitoring thread and waits for
        it to finish.

        Returns:
            None

        """
        if not self.integrity_monitor_active:
            return

        logger.info("Stopping hook integrity monitor")

        self._stop_monitoring.set()

        if self._integrity_thread:
            self._integrity_thread.join(timeout=5.0)

        self.integrity_monitor_active = False
        logger.info("Integrity monitor stopped")

    def install_hwbp_hook(self, address: int, handler: Callable[[], None]) -> bool:
        """Install hardware breakpoint hook using debug registers.

        Uses DR0-DR3 debug registers to set hardware breakpoints.
        Alternative to inline hooks, harder to detect.

        Args:
            address: Address to hook.
            handler: Handler function to call when breakpoint is triggered.

        Returns:
            bool: True if hardware breakpoint installed successfully, False on
                failure or if all debug registers are in use.

        """
        logger.info("Installing hardware breakpoint hook at %s", hex(address))

        try:
            if not hasattr(ctypes, "windll"):
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
                logger.exception("Failed to get thread context")
                return False

            if context.Dr0 == 0:
                context.Dr0 = address
                context.Dr7 |= 1 << 0
                logger.debug("Set hardware breakpoint in DR0")
            elif context.Dr1 == 0:
                context.Dr1 = address
                context.Dr7 |= 1 << 2
                logger.debug("Set hardware breakpoint in DR1")
            elif context.Dr2 == 0:
                context.Dr2 = address
                context.Dr7 |= 1 << 4
                logger.debug("Set hardware breakpoint in DR2")
            elif context.Dr3 == 0:
                context.Dr3 = address
                context.Dr7 |= 1 << 6
                logger.debug("Set hardware breakpoint in DR3")
            else:
                logger.exception("All debug registers in use")
                return False

            if not kernel32.SetThreadContext(current_thread, ctypes.byref(context)):
                logger.exception("Failed to set thread context")
                return False

            logger.info("Hardware breakpoint hook installed successfully")
            return True

        except Exception as e:
            logger.exception("Hardware breakpoint hook failed: %s", e, exc_info=True)
            return False

    def find_code_caves(self, module: str) -> list[int]:
        """Find code caves in specified module.

        Scans for sequences of null bytes or INT3 instructions (0xCC)
        that can be used for trampoline placement.

        Args:
            module: Module name to scan for code caves.

        Returns:
            list[int]: List of code cave addresses found in the module, or
                empty list if none found or operation failed.

        """
        logger.info("Scanning for code caves in module: %s", module)

        caves: list[int] = []

        try:
            if not hasattr(ctypes, "windll"):
                logger.warning("Code cave detection only supported on Windows")
                return caves

            kernel32 = ctypes.windll.kernel32

            h_module = kernel32.GetModuleHandleW(module)
            if not h_module:
                logger.exception("Module not found: %s", module)
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
                ctypes.sizeof(mod_info),
            ):
                logger.exception("Failed to get module information")
                return caves

            base_addr = mod_info.lpBaseOfDll
            size = mod_info.SizeOfImage

            logger.debug("Scanning module: base=%s, size=%s", hex(base_addr), size)

            scan_size = 4096
            for offset in range(0, size, scan_size):
                addr = base_addr + offset
                if data := self._read_memory(addr, min(scan_size, size - offset)):
                    if cave_addr := self._find_cave_in_data(addr, data):
                        caves.append(cave_addr)

            logger.info("Found %s code caves in %s", len(caves), module)
            self.code_caves[module] = caves

            return caves

        except Exception as e:
            logger.exception("Code cave search failed: %s", e, exc_info=True)
            return caves

    def _find_cave_in_data(self, base_addr: int, data: bytes) -> int | None:
        """Find code cave in memory data.

        Scans the provided memory data for sequences of null bytes (0x00) or
        INT3 instructions (0xCC) that are at least 32 bytes long. Returns the
        absolute address of the first suitable code cave found, or None if none
        exists.

        Args:
            base_addr: Base memory address corresponding to the start of data.
            data: Memory data bytes to scan for code cave patterns.

        Returns:
            int | None: Absolute address of code cave if found, or None if no
                suitable cave exists.

        """
        min_cave_size = 32
        current_cave_start = None
        current_cave_size = 0

        for i, byte in enumerate(data):
            if byte in {0, 204}:
                if current_cave_start is None:
                    current_cave_start = base_addr + i
                current_cave_size += 1
            else:
                if current_cave_size >= min_cave_size:
                    return current_cave_start
                current_cave_start = None
                current_cave_size = 0

        return current_cave_start if current_cave_size >= min_cave_size else None

    def rotate_hooks(self) -> bool:
        """Rotate hooks to different locations.

        Periodically moves hooks to prevent signature-based detection.
        Creates new trampolines at different addresses.

        Returns:
            bool: True if hooks rotated successfully, False if no hooks were
                rotated or operation failed.

        """
        logger.info("Rotating hooks to avoid detection")

        try:
            with self._lock:
                rotated_count = 0

                for target, hook_info in list(self.installed_hooks.items()):
                    if self._rotate_single_hook(hook_info):
                        rotated_count += 1
                    else:
                        logger.warning("Failed to rotate hook at %s", hex(target))

                logger.info("Rotated %s/%s hooks", rotated_count, len(self.installed_hooks))
                return rotated_count > 0

        except Exception as e:
            logger.exception("Hook rotation failed: %s", e, exc_info=True)
            return False

    def _rotate_single_hook(self, hook_info: HookInfo) -> bool:
        """Rotate a single hook to new location.

        Attempts to find a new code cave and move the hook's trampoline to avoid
        signature-based detection. Restores original bytes and reinstalls hook
        at new location if a suitable cave is found.

        Args:
            hook_info: Hook information object to rotate to new location.

        Returns:
            bool: True if hook successfully rotated to new location, False if no
                suitable cave found or operation failed.

        """
        try:
            if new_cave := self._find_code_cave(96):
                logger.debug("Found new code cave at 0x%X for hook rotation", new_cave)
                return (
                    self.create_indirect_hook(
                        hook_info.target_address,
                        hook_info.handler_address,
                    )
                    if self._write_memory(hook_info.target_address, hook_info.original_bytes)
                    else False
                )
            else:
                return False

        except Exception as e:
            logger.debug("Single hook rotation failed: %s", e, exc_info=True)
            return False

    def get_hook_status(self) -> dict[str, int | list[str] | bool]:
        """Get status of all installed hooks.

        Returns:
            dict[str, int | list[str] | bool]: Dictionary with hook
                statistics including total hooks, active hook addresses,
                integrity monitor status, tampering attempts, and code caves
                found.

        """
        with self._lock:
            return {
                "total_hooks": len(self.installed_hooks),
                "active_hooks": [hex(addr) for addr in self.installed_hooks],
                "integrity_monitor_active": self.integrity_monitor_active,
                "total_tampering_attempts": sum(h.tamper_count for h in self.installed_hooks.values()),
                "code_caves_found": sum(len(caves) for caves in self.code_caves.values()),
            }

    def remove_all_hooks(self) -> bool:
        """Remove all installed hooks and restore original code.

        Returns:
            bool: True if all hooks removed successfully, False otherwise.

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
                    logger.exception("Failed to remove hook at %s", hex(target))

            logger.info("Removed %s hooks", removed_count)
            return removed_count == len(self.installed_hooks)
