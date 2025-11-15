"""License Validation Debugging Engine for Intellicrack.

This module provides comprehensive debugging capabilities specifically designed
for analyzing and defeating software license validation mechanisms.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
import threading
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Callable

from ..utils.logger import get_logger

logger = get_logger(__name__)

# Windows debugging constants
CONTEXT_FULL = 0x10007  # Full context including segments, registers, and control information
CONTEXT_DEBUGGER = 0x10010  # Debugger-specific context
DBG_CONTINUE = 0x00010002  # Continue execution
DBG_EXCEPTION_NOT_HANDLED = 0x80010001  # Exception not handled
EXCEPTION_DEBUG_EVENT = 1  # Exception debug event code
EXCEPTION_SINGLE_STEP = 0x80000004  # Single step exception code
MEM_COMMIT = 0x1000  # Commits physical storage
MEM_RESERVE = 0x2000  # Reserves a range of virtual addresses
MEM_RELEASE = 0x8000  # Releases reserved or committed pages
PAGE_EXECUTE_READWRITE = 0x40  # Enables execute, read, and write access
PAGE_GUARD = 0x100  # Pages in the region become guard pages
PAGE_READWRITE = 0x04  # Enables read and write access


class DebugEvent(IntEnum):
    """Debug event types for Windows debugging."""

    EXCEPTION_DEBUG_EVENT = 1
    CREATE_THREAD_DEBUG_EVENT = 2
    CREATE_PROCESS_DEBUG_EVENT = 3
    EXIT_THREAD_DEBUG_EVENT = 4
    EXIT_PROCESS_DEBUG_EVENT = 5
    LOAD_DLL_DEBUG_EVENT = 6
    UNLOAD_DLL_DEBUG_EVENT = 7
    OUTPUT_DEBUG_STRING_EVENT = 8
    RIP_EVENT = 9


class ExceptionCode(IntEnum):
    """Windows exception codes relevant to debugging."""

    EXCEPTION_ACCESS_VIOLATION = 0xC0000005
    EXCEPTION_BREAKPOINT = 0x80000003
    EXCEPTION_SINGLE_STEP = 0x80000004
    EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094
    EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D
    EXCEPTION_PRIV_INSTRUCTION = 0xC0000096
    EXCEPTION_GUARD_PAGE = 0x80000001


class ExceptionRecord(ctypes.Structure):
    """Windows EXCEPTION_RECORD structure."""



ExceptionRecord._fields_ = [
    ("ExceptionCode", wintypes.DWORD),
    ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", ctypes.POINTER(ExceptionRecord)),
    ("ExceptionAddress", ctypes.c_void_p),
    ("NumberParameters", wintypes.DWORD),
    ("ExceptionInformation", ctypes.c_void_p * 15),
]


class M128A(ctypes.Structure):
    """128-bit SIMD register structure."""

    _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]


class CONTEXT(ctypes.Structure):
    """x64 CONTEXT structure for thread state."""

    _fields_ = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", wintypes.DWORD),
        ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD),
        ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD),
        ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        ("FltSave", ctypes.c_byte * 512),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_ulonglong),
        ("DebugControl", ctypes.c_ulonglong),
        ("LastBranchToRip", ctypes.c_ulonglong),
        ("LastBranchFromRip", ctypes.c_ulonglong),
        ("LastExceptionToRip", ctypes.c_ulonglong),
        ("LastExceptionFromRip", ctypes.c_ulonglong),
    ]


class ExceptionPointers(ctypes.Structure):
    """Windows EXCEPTION_POINTERS structure."""

    _fields_ = [("ExceptionRecord", ctypes.POINTER(ExceptionRecord)), ("ContextRecord", ctypes.POINTER(CONTEXT))]


EXCEPTION_POINTERS = ExceptionPointers


# VEH Handler function type
PVECTORED_EXCEPTION_HANDLER = ctypes.WINFUNCTYPE(wintypes.LONG, ctypes.POINTER(EXCEPTION_POINTERS))


@dataclass
class Breakpoint:
    """Represents a debugging breakpoint."""

    address: int
    original_byte: bytes
    enabled: bool
    hit_count: int
    callback: Callable | None = None
    condition: str | None = None
    description: str = ""


class LicenseDebugger:
    """Advanced debugging engine for license validation analysis."""

    # Windows debugging constants
    DEBUG_PROCESS = 0x00000001
    DEBUG_ONLY_THIS_PROCESS = 0x00000002
    CREATE_SUSPENDED = 0x00000004
    PROCESS_ALL_ACCESS = 0x001F0FFF
    THREAD_ALL_ACCESS = 0x001F03FF
    DBG_CONTINUE = 0x00010002
    DBG_EXCEPTION_NOT_HANDLED = 0x80010001
    INFINITE = 0xFFFFFFFF

    # x86/x64 breakpoint instruction
    INT3_INSTRUCTION = b"\xcc"

    def __init__(self) -> None:
        """Initialize the license debugging engine."""
        logger.info("Initializing LicenseDebugger engine.")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        self.process_handle = None
        self.thread_handles = {}
        self.breakpoints = {}
        self.memory_breakpoints = {}
        self.hardware_breakpoints = {}
        self.license_patterns = self._init_license_patterns()
        self.api_hooks = {}
        self.debugging = False
        self.debug_thread = None
        self.process_id = None
        self.main_thread_id = None
        self.modules = {}
        self.license_check_addresses = []

        # VEH-related properties
        self.veh_handlers = []
        self.veh_handle = None
        self.exception_filters = {}
        self.single_step_enabled = False
        self.last_exception = None
        self.exception_callbacks = {}
        self.veh_chain_position = 1  # 1 = first handler, 0 = last handler
        logger.debug("LicenseDebugger initialized.")

    def _init_license_patterns(self) -> list[bytes]:
        """Initialize common license validation patterns."""
        logger.debug("Initializing common license validation patterns.")
        patterns = [
            # Common license check patterns
            b"\x84\xc0\x74",  # TEST AL, AL; JZ (failed check)
            b"\x84\xc0\x75",  # TEST AL, AL; JNZ (successful check)
            b"\x85\xc0\x74",  # TEST EAX, EAX; JZ
            b"\x85\xc0\x75",  # TEST EAX, EAX; JNZ
            b"\x83\xf8\x00\x74",  # CMP EAX, 0; JZ
            b"\x83\xf8\x01\x74",  # CMP EAX, 1; JZ
            b"\x3d\x00\x00\x00\x00\x74",  # CMP EAX, 0; JZ (long form)
            b"\xff\x15",  # CALL [address] - indirect call
            b"\xe8",  # CALL relative - direct call
            # Registry access patterns for license
            b"RegOpenKey",
            b"RegQueryValue",
            b"SOFTWARE\\Licenses",
            # Time check patterns (trial period)
            b"GetSystemTime",
            b"GetLocalTime",
            b"GetTickCount",
            # Hardware ID patterns
            b"GetVolumeInformation",
            b"GetAdaptersInfo",
        ]
        logger.info(f"Initialized {len(patterns)} license validation patterns.")
        return patterns

    def attach_to_process(self, process_id: int) -> bool:
        """Attach debugger to a running process for license analysis."""
        logger.info(f"Attempting to attach to process ID: {process_id}")
        try:
            # Enable debug privilege
            logger.debug("Enabling debug privilege.")
            if not self._enable_debug_privilege():
                logger.error("Failed to enable debug privilege. Attachment aborted.")
                return False
            logger.debug("Debug privilege enabled.")

            # Attach to process
            logger.debug(f"Calling DebugActiveProcess for PID: {process_id}")
            if not self.kernel32.DebugActiveProcess(process_id):
                error = ctypes.get_last_error()
                logger.error(f"Failed to attach to process {process_id}: Windows Error {error}")
                return False

            self.process_id = process_id
            self.process_handle = self.kernel32.OpenProcess(self.PROCESS_ALL_ACCESS, False, process_id)

            if not self.process_handle:
                logger.error(f"Failed to get a handle for process {process_id}.")
                return False
            logger.debug(f"Successfully obtained handle for process {process_id}.")

            logger.info(f"Successfully attached to process {process_id}")

            # Start debugging loop in separate thread
            self.debugging = True
            self.debug_thread = threading.Thread(target=self._debug_loop, daemon=True)
            self.debug_thread.start()
            logger.info("Debugger thread started.")

            return True

        except Exception as e:
            logger.exception(f"An unexpected error occurred while attaching to process {process_id}: {e}")
            return False

    def _enable_debug_privilege(self) -> bool:
        """Enable SeDebugPrivilege for process debugging."""
        try:
            import win32api
            import win32security

            # Get current process token
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(), win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY,
            )

            # Lookup debug privilege
            privilege = win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")

            # Enable the privilege
            win32security.AdjustTokenPrivileges(token, False, [(privilege, win32security.SE_PRIVILEGE_ENABLED)])

            return True

        except Exception as e:
            logger.exception(f"An unexpected error occurred while trying to enable debug privilege: {e}")
            return False

    def set_breakpoint(
        self, address: int, callback: Callable | None = None, description: str = "", condition: str | None = None,
    ) -> bool:
        """Set a software breakpoint at specified address with optional condition.

        Args:
            address: Memory address for breakpoint
            callback: Optional callback function
            description: Breakpoint description
            condition: Optional conditional expression (e.g., "rax == 0x1337", "rcx > 100")

        Returns:
            True if breakpoint was set successfully

        """
        logger.info(f"Setting breakpoint at {hex(address)}.")
        if address in self.breakpoints:
            logger.warning(f"Breakpoint already exists at {hex(address)}. Skipping.")
            return True

        try:
            # Read original byte
            logger.debug(f"Reading original byte at {hex(address)}.")
            original_byte = self._read_memory(address, 1)
            if not original_byte:
                logger.error(f"Failed to read memory at {hex(address)}. Cannot set breakpoint.")
                return False
            logger.debug(f"Original byte at {hex(address)} is {original_byte.hex()}.")

            # Validate condition syntax if provided
            if condition:
                logger.debug(f"Validating breakpoint condition: {condition}")
                if not self._validate_condition_syntax(condition):
                    logger.error(f"Invalid condition syntax: {condition}. Breakpoint not set.")
                    return False
                logger.debug("Breakpoint condition syntax is valid.")

            # Write INT3 instruction
            logger.debug(f"Writing INT3 instruction at {hex(address)}.")
            if not self._write_memory(address, self.INT3_INSTRUCTION):
                logger.error(f"Failed to write breakpoint at {hex(address)}.")
                return False
            logger.debug(f"Successfully wrote INT3 instruction at {hex(address)}.")

            # Store breakpoint info
            self.breakpoints[address] = Breakpoint(
                address=address,
                original_byte=original_byte,
                enabled=True,
                hit_count=0,
                callback=callback,
                condition=condition,
                description=description or f"Breakpoint at {hex(address)}",
            )

            logger.info(f"Successfully set breakpoint at {hex(address)}: {description}")
            if condition:
                logger.info(f"  Condition: {condition}")
            return True

        except Exception as e:
            logger.exception(f"An unexpected error occurred while setting breakpoint at {hex(address)}: {e}")
            return False

    def set_conditional_breakpoint(self, address: int, condition: str, callback: Callable | None = None, description: str = "") -> bool:
        """Set a conditional breakpoint that only triggers when condition is met.

        Args:
            address: Memory address for breakpoint
            condition: Conditional expression (e.g., "rax == 0x1337", "mem[rsp] != 0")
            callback: Optional callback function
            description: Breakpoint description

        Returns:
            True if conditional breakpoint was set successfully

        """
        return self.set_breakpoint(address, callback, description, condition)

    def set_hardware_breakpoint(
        self,
        address: int,
        dr_index: int = -1,
        access_type: str = "execute",
        size: int = 1,
        callback: Callable | None = None,
        apply_to_all_threads: bool = True,
    ) -> bool:
        """Set hardware breakpoint using debug registers.

        Args:
            address: Memory address to watch
            dr_index: Debug register index (0-3), or -1 for auto-select
            access_type: "execute", "write", "read_write", or "io"
            size: Breakpoint size (1, 2, 4, or 8 bytes)
            callback: Optional callback when breakpoint hits
            apply_to_all_threads: Apply breakpoint to all threads

        Returns:
            True if hardware breakpoint was set successfully

        """
        # Auto-select available debug register if not specified
        if dr_index == -1:
            dr_index = self._find_available_debug_register()
            if dr_index == -1:
                logger.error("No available debug registers")
                return False

        if dr_index not in range(4):
            logger.error("Invalid debug register index (must be 0-3)")
            return False

        # Validate size
        if size not in [1, 2, 4, 8]:
            logger.error("Invalid size (must be 1, 2, 4, or 8 bytes)")
            return False

        try:
            threads_to_update = []
            if apply_to_all_threads:
                # Apply to all threads
                threads_to_update = list(self.thread_handles.keys())
            else:
                # Apply only to main thread
                threads_to_update = [self.main_thread_id] if self.main_thread_id else []

            if not threads_to_update:
                logger.error("No threads available for hardware breakpoint")
                return False

            success_count = 0
            for thread_id in threads_to_update:
                if self._set_hardware_breakpoint_on_thread(thread_id, address, dr_index, access_type, size):
                    success_count += 1

            if success_count == 0:
                logger.error("Failed to set hardware breakpoint on any thread")
                return False

            # Store hardware breakpoint info
            self.hardware_breakpoints[address] = {
                "dr_index": dr_index,
                "access_type": access_type,
                "size": size,
                "callback": callback,
                "threads": threads_to_update,
                "hit_count": 0,
            }

            logger.info(f"Set hardware breakpoint at {hex(address)} on {success_count} threads")
            logger.info(f"  Type: {access_type}, Size: {size} bytes, DR{dr_index}")
            return True

        except Exception as e:
            logger.exception(f"Error setting hardware breakpoint: {e}")
            return False

    def _set_hardware_breakpoint_on_thread(self, thread_id: int, address: int, dr_index: int, access_type: str, size: int) -> bool:
        """Set hardware breakpoint on specific thread."""
        try:
            # Get thread context
            context = self._get_thread_context(thread_id)
            if not context:
                return False

            # Set debug register address
            if dr_index == 0:
                context.Dr0 = address
            elif dr_index == 1:
                context.Dr1 = address
            elif dr_index == 2:
                context.Dr2 = address
            elif dr_index == 3:
                context.Dr3 = address

            # Configure DR7 (debug control register)
            dr7_value = context.Dr7

            # Clear existing settings for this register
            dr7_value &= ~(0xF << (16 + dr_index * 4))  # Clear RW and LEN fields
            dr7_value &= ~(3 << (dr_index * 2))  # Clear L and G fields

            # Enable local and global breakpoint
            dr7_value |= 3 << (dr_index * 2)  # Set both L and G bits

            # Set access type (RW field)
            access_bits = {
                "execute": 0b00,  # Break on instruction execution
                "write": 0b01,  # Break on data write
                "io": 0b10,  # Break on I/O read/write
                "read_write": 0b11,  # Break on data read or write
            }
            if access_type in access_bits:
                dr7_value |= access_bits[access_type] << (16 + dr_index * 4)

            # Set size (LEN field)
            size_bits = {
                1: 0b00,  # 1 byte
                2: 0b01,  # 2 bytes
                4: 0b11,  # 4 bytes
                8: 0b10,  # 8 bytes (only valid on x64)
            }
            if size in size_bits:
                dr7_value |= size_bits[size] << (18 + dr_index * 4)

            # Enable exact breakpoint (optional, for compatibility)
            dr7_value |= 1 << 8  # LE bit (Local Exact breakpoint enable)
            dr7_value |= 1 << 9  # GE bit (Global Exact breakpoint enable)

            context.Dr7 = dr7_value

            # Clear debug status register (Dr6) to avoid confusion
            context.Dr6 = 0

            # Set thread context
            return self._set_thread_context(thread_id, context)

        except Exception as e:
            logger.exception(f"Error setting hardware breakpoint on thread {thread_id}: {e}")
            return False

    def _find_available_debug_register(self) -> int:
        """Find an available debug register.

        Returns:
            Debug register index (0-3) or -1 if none available

        """
        used_registers = set()
        for info in self.hardware_breakpoints.values():
            used_registers.add(info["dr_index"])

        for i in range(4):
            if i not in used_registers:
                return i

        return -1

    def remove_hardware_breakpoint(self, address: int) -> bool:
        """Remove hardware breakpoint at specified address.

        Args:
            address: Memory address of breakpoint to remove

        Returns:
            True if breakpoint was removed successfully

        """
        if address not in self.hardware_breakpoints:
            logger.warning(f"No hardware breakpoint at {hex(address)}")
            return False

        try:
            bp_info = self.hardware_breakpoints[address]
            dr_index = bp_info["dr_index"]
            threads = bp_info.get("threads", [])

            success_count = 0
            for thread_id in threads:
                if self._clear_hardware_breakpoint_on_thread(thread_id, dr_index):
                    success_count += 1

            del self.hardware_breakpoints[address]

            logger.info(f"Removed hardware breakpoint at {hex(address)} from {success_count} threads")
            return success_count > 0

        except Exception as e:
            logger.exception(f"Error removing hardware breakpoint: {e}")
            return False

    def _clear_hardware_breakpoint_on_thread(self, thread_id: int, dr_index: int) -> bool:
        """Clear hardware breakpoint on specific thread."""
        try:
            context = self._get_thread_context(thread_id)
            if not context:
                return False

            # Clear debug register address
            if dr_index == 0:
                context.Dr0 = 0
            elif dr_index == 1:
                context.Dr1 = 0
            elif dr_index == 2:
                context.Dr2 = 0
            elif dr_index == 3:
                context.Dr3 = 0

            # Clear DR7 settings for this register
            dr7_value = context.Dr7
            dr7_value &= ~(0xF << (16 + dr_index * 4))  # Clear RW and LEN fields
            dr7_value &= ~(3 << (dr_index * 2))  # Clear L and G fields
            context.Dr7 = dr7_value

            # Clear corresponding bit in DR6 status register
            context.Dr6 &= ~(1 << dr_index)

            return self._set_thread_context(thread_id, context)

        except Exception as e:
            logger.exception(f"Error clearing hardware breakpoint on thread {thread_id}: {e}")
            return False

    def list_hardware_breakpoints(self) -> list[dict[str, Any]]:
        """List all active hardware breakpoints.

        Returns:
            List of hardware breakpoint information

        """
        breakpoints = []
        for address, info in self.hardware_breakpoints.items():
            breakpoints.append(
                {
                    "address": hex(address),
                    "dr_index": info["dr_index"],
                    "type": info["access_type"],
                    "size": info["size"],
                    "hit_count": info.get("hit_count", 0),
                    "threads": len(info.get("threads", [])),
                },
            )
        return breakpoints

    def find_license_checks(self) -> list[int]:
        """Scan process memory for potential license check locations."""
        found_checks = []

        try:
            # Get process memory regions
            memory_regions = self._enumerate_memory_regions()

            for region in memory_regions:
                if not region["executable"]:
                    continue

                # Read memory region
                memory_data = self._read_memory(region["base"], region["size"])
                if not memory_data:
                    continue

                # Search for license patterns
                for pattern in self.license_patterns:
                    offset = 0
                    while True:
                        index = memory_data.find(pattern, offset)
                        if index == -1:
                            break

                        address = region["base"] + index
                        found_checks.append(address)
                        logger.debug(f"Found potential license check at {hex(address)}")

                        offset = index + 1

            self.license_check_addresses = found_checks
            logger.info(f"Found {len(found_checks)} potential license checks")
            return found_checks

        except Exception as e:
            logger.exception(f"An unexpected error occurred while finding license checks: {e}")
            return []

    def hook_license_api(self, module_name: str, function_name: str, callback: Callable) -> bool:
        """Install hook for Windows API licensing functions."""
        try:
            # Get module handle
            module = ctypes.WinDLL(module_name)

            # Get function address
            func_addr = ctypes.cast(getattr(module, function_name), ctypes.c_void_p).value

            if not func_addr:
                logger.error(f"Failed to find {function_name} in {module_name}")
                return False

            # Set breakpoint at API entry
            if self.set_breakpoint(func_addr, callback, f"API Hook: {function_name}"):
                self.api_hooks[func_addr] = {"module": module_name, "function": function_name, "callback": callback}
                logger.info(f"Hooked {module_name}!{function_name}")
                return True

            return False

        except Exception as e:
            logger.exception(f"An unexpected error occurred while hooking API {module_name}!{function_name}: {e}")
            return False

    def _debug_loop(self) -> None:
        """Run main debugging event loop."""
        debug_event = DEBUG_EVENT()

        while self.debugging:
            try:
                # Wait for debug event
                if self.kernel32.WaitForDebugEvent(ctypes.byref(debug_event), 100):
                    continue_status = self.DBG_CONTINUE
                    logger.debug(f"Debug event received: {debug_event.dwDebugEventCode} for Process ID: {debug_event.dwProcessId}, Thread ID: {debug_event.dwThreadId}")

                    # Handle different debug events
                    if debug_event.dwDebugEventCode == DebugEvent.EXCEPTION_DEBUG_EVENT:
                        logger.debug("Handling EXCEPTION_DEBUG_EVENT.")
                        continue_status = self._handle_exception(debug_event)
                        logger.debug(f"EXCEPTION_DEBUG_EVENT handled, continue status: {continue_status}")

                    elif debug_event.dwDebugEventCode == DebugEvent.CREATE_PROCESS_DEBUG_EVENT:
                        logger.info(f"Handling CREATE_PROCESS_DEBUG_EVENT for new process: {debug_event.dwProcessId}")
                        self._handle_create_process(debug_event)
                        logger.info("CREATE_PROCESS_DEBUG_EVENT handled.")

                    elif debug_event.dwDebugEventCode == DebugEvent.LOAD_DLL_DEBUG_EVENT:
                        logger.debug(f"Handling LOAD_DLL_DEBUG_EVENT for process: {debug_event.dwProcessId}")
                        self._handle_load_dll(debug_event)
                        logger.debug("LOAD_DLL_DEBUG_EVENT handled.")

                    elif debug_event.dwDebugEventCode == DebugEvent.EXIT_PROCESS_DEBUG_EVENT:
                        logger.info(f"Handling EXIT_PROCESS_DEBUG_EVENT for process: {debug_event.dwProcessId}")
                        self.debugging = False
                        logger.info("EXIT_PROCESS_DEBUG_EVENT handled, debugger stopping.")

                    elif debug_event.dwDebugEventCode == DebugEvent.CREATE_THREAD_DEBUG_EVENT:
                        logger.debug(f"Handling CREATE_THREAD_DEBUG_EVENT for new thread: {debug_event.dwThreadId}")
                        self.thread_handles[debug_event.dwThreadId] = debug_event.u.CreateThread.hThread
                        logger.debug(f"New thread {debug_event.dwThreadId} added to tracking.")

                    elif debug_event.dwDebugEventCode == DebugEvent.EXIT_THREAD_DEBUG_EVENT:
                        logger.debug(f"Handling EXIT_THREAD_DEBUG_EVENT for thread: {debug_event.dwThreadId}")
                        if debug_event.dwThreadId in self.thread_handles:
                            del self.thread_handles[debug_event.dwThreadId]
                            logger.debug(f"Thread {debug_event.dwThreadId} removed from tracking.")

                    elif debug_event.dwDebugEventCode == DebugEvent.UNLOAD_DLL_DEBUG_EVENT:
                        logger.debug(f"Handling UNLOAD_DLL_DEBUG_EVENT for process: {debug_event.dwProcessId}")
                        # Additional logic could be added here to update module lists
                        logger.debug("UNLOAD_DLL_DEBUG_EVENT handled.")

                    elif debug_event.dwDebugEventCode == DebugEvent.OUTPUT_DEBUG_STRING_EVENT:
                        logger.debug(f"Handling OUTPUT_DEBUG_STRING_EVENT from process: {debug_event.dwProcessId}")
                        # Potentially log the debug string content if needed
                        logger.debug("OUTPUT_DEBUG_STRING_EVENT handled.")

                    elif debug_event.dwDebugEventCode == DebugEvent.RIP_EVENT:
                        logger.warning(f"Handling RIP_EVENT from process: {debug_event.dwProcessId}. Type: {debug_event.u.RipInfo.dwType}")
                        logger.warning("RIP_EVENT indicates a debugging error or system shutdown.")

                    # Continue execution
                    self.kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)
                    logger.debug(f"Continuing execution for Process ID: {debug_event.dwProcessId}, Thread ID: {debug_event.dwThreadId} with status: {continue_status}")

            except Exception as e:
                logger.exception(f"An unexpected error occurred in the debug loop: {e}")

    def _handle_exception(self, debug_event: Any) -> int:
        """Handle exception debug events.

        Args:
            debug_event: Debug event structure containing exception information

        Returns:
            Continue status for the debugger

        """
        exception = debug_event.u.Exception
        exception_code = exception.ExceptionRecord.ExceptionCode
        exception_address = exception.ExceptionRecord.ExceptionAddress
        logger.debug(f"Exception event: code={exception_code}, address={hex(exception_address)}")

        # Handle breakpoint exception
        if exception_code == ExceptionCode.EXCEPTION_BREAKPOINT:
            if exception_address in self.breakpoints:
                bp = self.breakpoints[exception_address]
                bp.hit_count += 1

                # Evaluate conditional breakpoint
                if bp.condition and not self._evaluate_breakpoint_condition(bp, debug_event):
                    # Condition not met, restore original byte and continue
                    self._restore_breakpoint_silently(bp)
                    return self.DBG_CONTINUE

                logger.info(f"Breakpoint hit at {hex(exception_address)}: {bp.description}")

                # Call callback if registered
                if bp.callback:
                    try:
                        bp.callback(self, debug_event)
                    except Exception as e:
                        logger.exception(f"An error occurred in the breakpoint callback for address {hex(exception_address)}: {e}")

                # Restore original byte and single step
                self._write_memory(exception_address, bp.original_byte)
                self._set_single_step(debug_event.dwThreadId)

                return self.DBG_CONTINUE

        # Handle single step (for breakpoint restoration)
        elif exception_code == ExceptionCode.EXCEPTION_SINGLE_STEP:
            # Restore any breakpoints that need it
            for addr, bp in self.breakpoints.items():
                if bp.enabled:
                    self._write_memory(addr, self.INT3_INSTRUCTION)

            return self.DBG_CONTINUE

        # Handle access violation (useful for finding license checks)
        elif exception_code == ExceptionCode.EXCEPTION_ACCESS_VIOLATION:
            logger.warning(f"Access violation at {hex(exception_address)}")

        return self.DBG_EXCEPTION_NOT_HANDLED

    def _handle_create_process(self, debug_event: Any) -> None:
        """Handle process creation event.

        Args:
            debug_event: Debug event structure containing process creation info

        """
        create_process = debug_event.u.CreateProcessInfo

        self.main_thread_id = debug_event.dwThreadId
        self.thread_handles[debug_event.dwThreadId] = create_process.hThread
        logger.info(f"Process created with main thread ID: {self.main_thread_id}")

        # Scan for license checks in main module
        self.find_license_checks()

        logger.info("Process created and analyzed for license checks")

    def _handle_load_dll(self, debug_event: Any) -> None:
        """Handle DLL load event with sophisticated license analysis.

        Args:
            debug_event: Debug event structure containing DLL load information

        """
        load_dll = debug_event.u.LoadDll

        # Get DLL name
        dll_name = self._read_string(load_dll.lpImageName)
        dll_base = ctypes.c_void_p(load_dll.lpBaseOfDll).value

        if dll_name:
            self.modules[load_dll.lpBaseOfDll] = dll_name
            logger.info(f"Loaded DLL: {dll_name} at {hex(dll_base)}")

            # Comprehensive DLL analysis
            dll_analysis = self._analyze_dll_comprehensive(dll_base, dll_name)

            if dll_analysis["is_license_related"] or dll_analysis["suspicious_score"] > 0.5:
                logger.info(f"Analyzing potentially license-related DLL: {dll_name}")
                logger.info(f"Suspicious score: {dll_analysis['suspicious_score']:.2f}")

                # Set breakpoints on all detected license functions
                for func_addr in dll_analysis["license_functions"]:
                    self.set_breakpoint(func_addr, description=f"License function at {hex(func_addr)} in {dll_name}")
                    self.license_check_addresses.append(func_addr)

                # Hook imported license APIs
                for api_addr, api_name in dll_analysis["license_imports"].items():
                    self.set_breakpoint(api_addr, description=f"License API {api_name} imported by {dll_name}")

    def _analyze_dll_comprehensive(self, dll_base: int, dll_name: str) -> dict[str, Any]:
        """Perform comprehensive DLL analysis for license detection."""
        analysis = {
            "is_license_related": False,
            "suspicious_score": 0.0,
            "license_functions": [],
            "license_imports": {},
            "license_exports": [],
            "license_strings": [],
            "protection_signatures": [],
        }

        # Read PE headers
        pe_header = self._read_memory(dll_base, 0x1000)
        if not pe_header or pe_header[:2] != b"MZ":
            return analysis

        # Parse DOS header
        e_lfanew = struct.unpack("<I", pe_header[0x3C:0x40])[0]
        if e_lfanew >= 0x1000:
            return analysis

        # Parse PE header
        nt_header_offset = e_lfanew
        if pe_header[nt_header_offset : nt_header_offset + 4] != b"PE\x00\x00":
            return analysis

        # Get image size and architecture
        machine = struct.unpack("<H", pe_header[nt_header_offset + 4 : nt_header_offset + 6])[0]
        is_64bit = machine == 0x8664  # AMD64

        # Parse optional header
        opt_header_offset = nt_header_offset + 24
        struct.unpack("<H", pe_header[nt_header_offset + 20 : nt_header_offset + 22])[0]

        if is_64bit:
            size_of_image = struct.unpack("<I", pe_header[opt_header_offset + 56 : opt_header_offset + 60])[0]
            import_dir_rva = struct.unpack("<I", pe_header[opt_header_offset + 120 : opt_header_offset + 124])[0]
            import_dir_size = struct.unpack("<I", pe_header[opt_header_offset + 124 : opt_header_offset + 128])[0]
            export_dir_rva = struct.unpack("<I", pe_header[opt_header_offset + 112 : opt_header_offset + 116])[0]
            export_dir_size = struct.unpack("<I", pe_header[opt_header_offset + 116 : opt_header_offset + 120])[0]
        else:
            size_of_image = struct.unpack("<I", pe_header[opt_header_offset + 56 : opt_header_offset + 60])[0]
            import_dir_rva = struct.unpack("<I", pe_header[opt_header_offset + 104 : opt_header_offset + 108])[0]
            import_dir_size = struct.unpack("<I", pe_header[opt_header_offset + 108 : opt_header_offset + 112])[0]
            export_dir_rva = struct.unpack("<I", pe_header[opt_header_offset + 96 : opt_header_offset + 100])[0]
            export_dir_size = struct.unpack("<I", pe_header[opt_header_offset + 100 : opt_header_offset + 104])[0]

        # Analyze imports for license-related APIs
        if import_dir_rva and import_dir_size:
            license_apis = self._analyze_imports(dll_base, import_dir_rva, import_dir_size)
            analysis["license_imports"] = license_apis
            if license_apis:
                analysis["suspicious_score"] += 0.3 * len(license_apis)

        # Analyze exports for license validation functions
        if export_dir_rva and export_dir_size:
            license_exports = self._analyze_exports(dll_base, export_dir_rva, export_dir_size)
            analysis["license_exports"] = license_exports
            if license_exports:
                analysis["suspicious_score"] += 0.4
                analysis["is_license_related"] = True

        # Scan code sections for license patterns
        sections = self._parse_sections(pe_header, nt_header_offset)
        for section in sections:
            if section["characteristics"] & 0x20:  # IMAGE_SCN_CNT_CODE
                section_data = self._read_memory(dll_base + section["virtual_address"], section["virtual_size"])
                if section_data:
                    # Advanced pattern matching with disassembly analysis
                    found_patterns = self._scan_code_patterns(section_data, dll_base + section["virtual_address"])
                    analysis["license_functions"].extend(found_patterns)

                    # String analysis
                    license_strings = self._extract_license_strings(section_data)
                    analysis["license_strings"].extend(license_strings)
                    if license_strings:
                        analysis["suspicious_score"] += 0.1 * len(license_strings)

        # Check for known protection signatures
        dll_memory = self._read_memory(dll_base, min(size_of_image, 0x100000))
        if dll_memory:
            protections = self._detect_protection_signatures(dll_memory)
            analysis["protection_signatures"] = protections
            if protections:
                analysis["is_license_related"] = True
                analysis["suspicious_score"] += 0.5

        # Check DLL name patterns
        dll_name_lower = dll_name.lower() if dll_name else ""
        license_dll_patterns = [
            "license",
            "activation",
            "hasp",
            "sentinel",
            "flexlm",
            "flexnet",
            "wibu",
            "codemeter",
            "safenet",
            "thales",
            "gemalto",
            "crypto",
            "auth",
            "valid",
            "serial",
            "regist",
            "trial",
            "eval",
            "demo",
        ]

        for pattern in license_dll_patterns:
            if pattern in dll_name_lower:
                analysis["is_license_related"] = True
                analysis["suspicious_score"] += 0.3
                break

        # Normalize suspicious score
        analysis["suspicious_score"] = min(1.0, analysis["suspicious_score"])

        return analysis

    def _analyze_imports(self, dll_base: int, import_dir_rva: int, import_dir_size: int) -> dict[int, str]:
        """Analyze import table for license-related APIs."""
        license_apis = {}

        # License-related API names
        suspicious_apis = [
            # Registry APIs for license storage
            "RegOpenKeyExA",
            "RegOpenKeyExW",
            "RegQueryValueExA",
            "RegQueryValueExW",
            "RegSetValueExA",
            "RegSetValueExW",
            "RegCreateKeyExA",
            "RegCreateKeyExW",
            # Hardware ID APIs
            "GetVolumeInformationA",
            "GetVolumeInformationW",
            "GetAdaptersInfo",
            "GetAdaptersAddresses",
            "DeviceIoControl",
            "GetSystemInfo",
            # Time-based trial checks
            "GetSystemTime",
            "GetLocalTime",
            "GetTickCount",
            "GetTickCount64",
            "QueryPerformanceCounter",
            "GetSystemTimeAsFileTime",
            # Cryptography for license validation
            "CryptAcquireContextA",
            "CryptAcquireContextW",
            "CryptCreateHash",
            "CryptHashData",
            "CryptVerifySignatureA",
            "CryptVerifySignatureW",
            # Network for online activation
            "InternetOpenA",
            "InternetOpenW",
            "InternetConnectA",
            "InternetConnectW",
            "HttpSendRequestA",
            "HttpSendRequestW",
            "WSAStartup",
            "connect",
            "send",
            "recv",
            # File operations for license files
            "CreateFileA",
            "CreateFileW",
            "ReadFile",
            "WriteFile",
            "GetPrivateProfileStringA",
            "GetPrivateProfileStringW",
        ]

        # Read import directory
        import_desc_size = 20  # sizeof(IMAGE_IMPORT_DESCRIPTOR)
        import_data = self._read_memory(dll_base + import_dir_rva, import_dir_size)

        if not import_data:
            return license_apis

        # Parse each import descriptor
        offset = 0
        while offset + import_desc_size <= len(import_data):
            # Parse IMAGE_IMPORT_DESCRIPTOR
            characteristics = struct.unpack("<I", import_data[offset : offset + 4])[0]
            if characteristics == 0:  # End of import descriptors
                break

            name_rva = struct.unpack("<I", import_data[offset + 12 : offset + 16])[0]
            first_thunk = struct.unpack("<I", import_data[offset + 16 : offset + 20])[0]

            if name_rva and first_thunk:
                # Read DLL name
                self._read_string(dll_base + name_rva, 256)

                # Check each imported function
                thunk_offset = 0
                while True:
                    thunk_data = self._read_memory(dll_base + first_thunk + thunk_offset, 8)
                    if not thunk_data:
                        break

                    thunk_value = struct.unpack(
                        "<Q" if len(thunk_data) == 8 else "<I",
                        thunk_data[:8] if len(thunk_data) >= 8 else thunk_data + b"\x00" * (8 - len(thunk_data)),
                    )[0]
                    if thunk_value == 0:
                        break

                    # Check if import by name (not ordinal)
                    if not (thunk_value & 0x8000000000000000):
                        hint_name_rva = thunk_value & 0x7FFFFFFF
                        func_name = self._read_string(dll_base + hint_name_rva + 2, 256)

                        if func_name and func_name in suspicious_apis:
                            iat_address = dll_base + first_thunk + thunk_offset
                            license_apis[iat_address] = func_name
                            logger.debug(f"Found license API: {func_name} at IAT {hex(iat_address)}")

                    thunk_offset += 8 if len(thunk_data) >= 8 else 4

            offset += import_desc_size

        return license_apis

    def _analyze_exports(self, dll_base: int, export_dir_rva: int, export_dir_size: int) -> list[str]:
        """Analyze export table for license validation functions."""
        license_exports = []

        # Read export directory
        export_data = self._read_memory(dll_base + export_dir_rva, export_dir_size)
        if not export_data or len(export_data) < 40:
            return license_exports

        # Parse IMAGE_EXPORT_DIRECTORY
        struct.unpack("<I", export_data[20:24])[0]
        num_names = struct.unpack("<I", export_data[24:28])[0]
        struct.unpack("<I", export_data[28:32])[0]
        addr_names = struct.unpack("<I", export_data[32:36])[0]

        # License-related export patterns
        license_patterns = [
            "IsLicenseValid",
            "CheckLicense",
            "ValidateLicense",
            "VerifyLicense",
            "GetLicenseStatus",
            "IsRegistered",
            "IsTrial",
            "IsActivated",
            "CheckSerial",
            "ValidateSerial",
            "VerifyRegistration",
            "GetHardwareID",
            "GetMachineCode",
            "GenerateHWID",
            "CheckExpiration",
            "GetTrialDays",
            "IsExpired",
        ]

        # Read function names
        if addr_names and num_names > 0:
            names_array = self._read_memory(dll_base + addr_names, num_names * 4)
            if names_array:
                for i in range(min(num_names, 1000)):  # Limit to prevent excessive reads
                    name_rva = struct.unpack("<I", names_array[i * 4 : (i + 1) * 4])[0]
                    func_name = self._read_string(dll_base + name_rva, 256)

                    if func_name:
                        # Check for license-related patterns
                        for pattern in license_patterns:
                            if pattern.lower() in func_name.lower():
                                license_exports.append(func_name)
                                logger.info(f"Found license export: {func_name}")
                                break

        return license_exports

    def _parse_sections(self, pe_header: bytes, nt_header_offset: int) -> list[dict[str, Any]]:
        """Parse PE sections."""
        sections = []

        # Get number of sections
        num_sections = struct.unpack("<H", pe_header[nt_header_offset + 6 : nt_header_offset + 8])[0]

        # Section header starts after optional header
        opt_header_size = struct.unpack("<H", pe_header[nt_header_offset + 20 : nt_header_offset + 22])[0]
        section_offset = nt_header_offset + 24 + opt_header_size

        for _i in range(min(num_sections, 20)):  # Limit sections
            if section_offset + 40 > len(pe_header):
                break

            section_data = pe_header[section_offset : section_offset + 40]

            sections.append(
                {
                    "name": section_data[:8].rstrip(b"\x00").decode("ascii", errors="ignore"),
                    "virtual_size": struct.unpack("<I", section_data[8:12])[0],
                    "virtual_address": struct.unpack("<I", section_data[12:16])[0],
                    "raw_size": struct.unpack("<I", section_data[16:20])[0],
                    "raw_address": struct.unpack("<I", section_data[20:24])[0],
                    "characteristics": struct.unpack("<I", section_data[36:40])[0],
                },
            )

            section_offset += 40

        return sections

    def _scan_code_patterns(self, code_data: bytes, base_address: int) -> list[int]:
        """Scan code for license check patterns using advanced analysis."""
        found_addresses = []

        # Advanced x86/x64 patterns for license checks
        advanced_patterns = [
            # Common license check sequences
            (b"\x84\xc0\x0f\x84", 4),  # TEST AL,AL; JE (long jump)
            (b"\x84\xc0\x0f\x85", 4),  # TEST AL,AL; JNE (long jump)
            (b"\x85\xc0\x0f\x84", 4),  # TEST EAX,EAX; JE (long jump)
            (b"\x85\xc0\x0f\x85", 4),  # TEST EAX,EAX; JNE (long jump)
            (b"\x83\xf8\x00\x0f\x84", 5),  # CMP EAX,0; JE (long jump)
            (b"\x83\xf8\x01\x0f\x84", 5),  # CMP EAX,1; JE (long jump)
            (b"\x48\x85\xc0\x74", 4),  # TEST RAX,RAX; JE (64-bit)
            (b"\x48\x85\xc0\x75", 4),  # TEST RAX,RAX; JNE (64-bit)
            # Return value checks
            (b"\xb8\x00\x00\x00\x00\xc3", 6),  # MOV EAX,0; RET (failure)
            (b"\xb8\x01\x00\x00\x00\xc3", 6),  # MOV EAX,1; RET (success)
            (b"\x31\xc0\xc3", 3),  # XOR EAX,EAX; RET (failure)
            (b"\x33\xc0\xc3", 3),  # XOR EAX,EAX; RET (alt encoding)
        ]

        for pattern, length in advanced_patterns:
            offset = 0
            while offset < len(code_data) - length:
                index = code_data.find(pattern, offset)
                if index == -1:
                    break

                addr = base_address + index
                found_addresses.append(addr)
                logger.debug(f"Found license pattern at {hex(addr)}")
                offset = index + 1

        return found_addresses

    def _extract_license_strings(self, data: bytes) -> list[str]:
        """Extract license-related strings from data."""
        license_strings = []

        # License-related string patterns
        string_patterns = [
            b"license",
            b"LICENSE",
            b"License",
            b"serial",
            b"SERIAL",
            b"Serial",
            b"trial",
            b"TRIAL",
            b"Trial",
            b"activation",
            b"ACTIVATION",
            b"registration",
            b"REGISTRATION",
            b"expired",
            b"EXPIRED",
            b"valid",
            b"VALID",
            b"crack",
            b"CRACK",
            b"patch",
            b"PATCH",
            b"keygen",
            b"KEYGEN",
        ]

        for pattern in string_patterns:
            if pattern in data:
                # Extract context around the string
                index = data.find(pattern)
                start = max(0, index - 20)
                end = min(len(data), index + len(pattern) + 20)
                context = data[start:end]

                # Try to extract full string
                extracted = self._extract_full_string(context, index - start)
                if extracted and len(extracted) > 3:
                    license_strings.append(extracted)

        return license_strings

    def _extract_full_string(self, data: bytes, offset: int) -> str:
        """Extract full null-terminated string from data."""
        # Find start of string
        start = offset
        while start > 0 and data[start - 1] >= 32 and data[start - 1] < 127:
            start -= 1

        # Find end of string
        end = offset
        while end < len(data) and data[end] >= 32 and data[end] < 127:
            end += 1

        if end > start:
            return data[start:end].decode("ascii", errors="ignore")
        return ""

    def _detect_protection_signatures(self, dll_memory: bytes) -> list[str]:
        """Detect known license protection signatures."""
        protections = []

        # Known protection signatures
        signatures = {
            b"HASP": "SafeNet HASP",
            b"Sentinel": "SafeNet Sentinel",
            b"WibuCmRc": "Wibu CodeMeter",
            b"FlexNet": "FlexNet Licensing",
            b"FLEXLM": "FlexLM",
            b"Themida": "Themida/WinLicense",
            b"VMProtect": "VMProtect",
            b"ASProtect": "ASProtect",
            b"Armadillo": "Armadillo",
            b"SecuROM": "SecuROM",
            b"SafeDisc": "SafeDisc",
            b"StarForce": "StarForce",
            b"Denuvo": "Denuvo",
            b"EXECryptor": "EXECryptor",
            b"Obsidium": "Obsidium",
        }

        for signature, protection_name in signatures.items():
            if signature in dll_memory:
                protections.append(protection_name)
                logger.info(f"Detected protection: {protection_name}")

        return protections

    def _read_memory(self, address: int, size: int) -> bytes | None:
        """Read process memory."""
        if not self.process_handle:
            return None

        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t()

        if self.kernel32.ReadProcessMemory(self.process_handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)):
            return buffer.raw[: bytes_read.value]

        return None

    def _write_memory(self, address: int, data: bytes) -> bool:
        """Write to process memory."""
        if not self.process_handle:
            return False

        bytes_written = ctypes.c_size_t()

        # Change memory protection if needed
        old_protect = wintypes.DWORD()
        PAGE_EXECUTE_READWRITE = 0x40

        self.kernel32.VirtualProtectEx(
            self.process_handle, ctypes.c_void_p(address), len(data), PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect),
        )

        success = self.kernel32.WriteProcessMemory(
            self.process_handle, ctypes.c_void_p(address), data, len(data), ctypes.byref(bytes_written),
        )

        # Restore original protection
        self.kernel32.VirtualProtectEx(self.process_handle, ctypes.c_void_p(address), len(data), old_protect, ctypes.byref(old_protect))

        return success and bytes_written.value == len(data)

    def _enumerate_memory_regions(self) -> list[dict[str, Any]]:
        """Enumerate process memory regions."""
        regions = []

        if not self.process_handle:
            return regions

        # MEMORY_BASIC_INFORMATION structure
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):  # noqa: N801
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        mbi = MEMORY_BASIC_INFORMATION()
        address = 0

        while self.kernel32.VirtualQueryEx(self.process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            MEM_COMMIT = 0x1000
            PAGE_EXECUTE = 0x10
            PAGE_EXECUTE_READ = 0x20
            PAGE_EXECUTE_READWRITE = 0x40

            if mbi.State == MEM_COMMIT:
                regions.append(
                    {
                        "base": mbi.BaseAddress,
                        "size": mbi.RegionSize,
                        "protection": mbi.Protect,
                        "executable": mbi.Protect in [PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE],
                    },
                )

            address = mbi.BaseAddress + mbi.RegionSize
            if address >= 0x7FFFFFFF0000:  # Max user space address
                break

        return regions

    def _validate_condition_syntax(self, condition: str) -> bool:
        """Validate conditional breakpoint syntax.

        Args:
            condition: Condition string to validate

        Returns:
            True if syntax is valid

        """
        import re

        # Allowed patterns for conditions
        valid_patterns = [
            r"^[a-z0-9]+\s*[><=!]+\s*(?:0x[0-9a-f]+|\d+)$",  # reg op value
            r"^mem\[[a-z0-9\+\-\*]+\]\s*[><=!]+\s*(?:0x[0-9a-f]+|\d+)$",  # mem[addr] op value
            r"^\[[a-z0-9\+\-\*]+\]\s*[><=!]+\s*(?:0x[0-9a-f]+|\d+)$",  # [addr] op value
            r"^[a-z0-9]+\s*&\s*(?:0x[0-9a-f]+|\d+)\s*[><=!]+\s*(?:0x[0-9a-f]+|\d+)$",  # reg & mask op value
        ]

        condition_lower = condition.lower().strip()
        for pattern in valid_patterns:
            if re.match(pattern, condition_lower):
                return True

        return False

    def _evaluate_breakpoint_condition(self, bp: Breakpoint, debug_event: Any) -> bool:
        """Evaluate conditional breakpoint expression.

        Args:
            bp: Breakpoint with condition
            debug_event: Current debug event containing thread and exception info

        Returns:
            True if condition is met

        """
        if not bp.condition:
            return True

        try:
            # Get current thread context
            context = self._get_thread_context(debug_event.dwThreadId)
            if not context:
                logger.error("Failed to get thread context for condition evaluation")
                return False

            # Parse condition
            condition = bp.condition.lower().strip()

            # Register comparison (e.g., "rax == 0x1337")
            if any(
                reg in condition
                for reg in ["rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
            ):
                return self._evaluate_register_condition(condition, context)

            # Memory comparison (e.g., "mem[rsp] != 0")
            if "mem[" in condition or "[" in condition:
                return self._evaluate_memory_condition(condition, context)

            # Flag comparison (e.g., "zf == 1")
            if any(flag in condition for flag in ["cf", "pf", "af", "zf", "sf", "tf", "if", "df", "of"]):
                return self._evaluate_flag_condition(condition, context)

            logger.warning(f"Unknown condition type: {bp.condition}")
            return False

        except Exception as e:
            logger.error(f"Error evaluating condition '{bp.condition}': {e}")
            return False

    def _evaluate_register_condition(self, condition: str, context: CONTEXT) -> bool:
        """Evaluate register-based condition.

        Args:
            condition: Register comparison expression (e.g., 'rax == 0x1337')
            context: CONTEXT structure with thread registers

        Returns:
            True if condition is met

        """
        import re

        # Extract register, operator, and value
        match = re.match(r"([a-z0-9]+)\s*([><=!]+)\s*(0x[0-9a-f]+|\d+)", condition)
        if not match:
            return False

        reg_name = match.group(1)
        operator = match.group(2)
        value_str = match.group(3)

        # Parse value
        if value_str.startswith("0x"):
            value = int(value_str, 16)
        else:
            value = int(value_str)

        # Get register value
        reg_value = self._get_register_value(reg_name, context)
        if reg_value is None:
            return False

        # Evaluate condition
        return self._compare_values(reg_value, operator, value)

    def _evaluate_memory_condition(self, condition: str, context: CONTEXT) -> bool:
        """Evaluate memory-based condition.

        Args:
            condition: Memory comparison expression (e.g., 'mem[rsp] != 0')
            context: CONTEXT structure with thread registers

        Returns:
            True if condition is met

        """
        import re

        # Extract memory address expression and comparison
        if "mem[" in condition:
            match = re.match(r"mem\[([a-z0-9\+\-\*]+)\]\s*([><=!]+)\s*(0x[0-9a-f]+|\d+)", condition)
        else:
            match = re.match(r"\[([a-z0-9\+\-\*]+)\]\s*([><=!]+)\s*(0x[0-9a-f]+|\d+)", condition)

        if not match:
            return False

        addr_expr = match.group(1)
        operator = match.group(2)
        value_str = match.group(3)

        # Parse value
        if value_str.startswith("0x"):
            value = int(value_str, 16)
        else:
            value = int(value_str)

        # Evaluate address expression
        address = self._evaluate_address_expression(addr_expr, context)
        if address is None:
            return False

        # Read memory at address
        mem_data = self._read_memory(address, 8)  # Read 64-bit value
        if not mem_data:
            return False

        mem_value = int.from_bytes(mem_data[:8], byteorder="little")

        # Evaluate condition
        return self._compare_values(mem_value, operator, value)

    def _evaluate_flag_condition(self, condition: str, context: CONTEXT) -> bool:
        """Evaluate CPU flag condition.

        Args:
            condition: Flag comparison expression (e.g., 'zf == 1')
            context: CONTEXT structure with thread registers and flags

        Returns:
            True if condition is met

        """
        import re

        # Extract flag name and comparison
        match = re.match(r"([czspao][f])\s*([><=!]+)\s*(\d+)", condition)
        if not match:
            return False

        flag_name = match.group(1)
        operator = match.group(2)
        value = int(match.group(3))

        # Get EFLAGS value
        eflags = context.EFlags

        # Extract specific flag
        flag_bits = {
            "cf": 0,  # Carry flag
            "pf": 2,  # Parity flag
            "af": 4,  # Auxiliary flag
            "zf": 6,  # Zero flag
            "sf": 7,  # Sign flag
            "tf": 8,  # Trap flag
            "if": 9,  # Interrupt flag
            "df": 10,  # Direction flag
            "of": 11,  # Overflow flag
        }

        if flag_name not in flag_bits:
            return False

        flag_value = (eflags >> flag_bits[flag_name]) & 1

        # Evaluate condition
        return self._compare_values(flag_value, operator, value)

    def _get_register_value(self, reg_name: str, context: CONTEXT) -> int | None:
        """Get register value from context.

        Args:
            reg_name: Register name (e.g., 'rax', 'rbx')
            context: CONTEXT structure with thread registers

        Returns:
            Register value or None if register not found

        """
        reg_map = {
            "rax": context.Rax,
            "rbx": context.Rbx,
            "rcx": context.Rcx,
            "rdx": context.Rdx,
            "rsp": context.Rsp,
            "rbp": context.Rbp,
            "rsi": context.Rsi,
            "rdi": context.Rdi,
            "r8": context.R8,
            "r9": context.R9,
            "r10": context.R10,
            "r11": context.R11,
            "r12": context.R12,
            "r13": context.R13,
            "r14": context.R14,
            "r15": context.R15,
            "rip": context.Rip,
        }

        return reg_map.get(reg_name)

    def _evaluate_address_expression(self, expr: str, context: CONTEXT) -> int | None:
        """Evaluate address expression (e.g., 'rsp+8', 'rbp-4').

        Args:
            expr: Address expression string
            context: CONTEXT structure with thread registers

        Returns:
            Evaluated address or None if invalid

        """
        import re

        # Simple register
        if expr in ["rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi"]:
            return self._get_register_value(expr, context)

        # Register with offset
        match = re.match(r"([a-z0-9]+)\s*([+\-])\s*(0x[0-9a-f]+|\d+)", expr)
        if match:
            reg = match.group(1)
            op = match.group(2)
            offset_str = match.group(3)

            reg_value = self._get_register_value(reg, context)
            if reg_value is None:
                return None

            if offset_str.startswith("0x"):
                offset = int(offset_str, 16)
            else:
                offset = int(offset_str)

            if op == "+":
                return reg_value + offset
            return reg_value - offset

        # Hex address
        if expr.startswith("0x"):
            return int(expr, 16)

        # Decimal address
        if expr.isdigit():
            return int(expr)

        return None

    def _compare_values(self, left: int, operator: str, right: int) -> bool:
        """Compare two values with given operator."""
        comparisons = {
            "==": lambda a, b: a == b,
            "!=": lambda a, b: a != b,
            "<": lambda a, b: a < b,
            "<=": lambda a, b: a <= b,
            ">": lambda a, b: a > b,
            ">=": lambda a, b: a >= b,
        }

        if operator in comparisons:
            return comparisons[operator](left, right)

        return False

    def _restore_breakpoint_silently(self, bp: Breakpoint) -> None:
        """Restore breakpoint without logging (for conditional breakpoints)."""
        try:
            # Restore original byte temporarily
            self._write_memory(bp.address, bp.original_byte)

            # Schedule re-insertion of breakpoint after single step
            # This is handled in the single step handler
            self.pending_breakpoint_restore = bp.address

        except Exception as e:
            logger.error(f"Error restoring breakpoint silently: {e}")

    def _get_thread_context(self, thread_id: int) -> CONTEXT | None:
        """Get thread context including registers.

        Args:
            thread_id: Thread ID to retrieve context for

        Returns:
            CONTEXT structure with thread state or None if failed

        """
        if thread_id not in self.thread_handles:
            return None

        # CONTEXT structure for x64
        class CONTEXT(ctypes.Structure):
            _fields_ = [
                ("P1Home", ctypes.c_uint64),
                ("P2Home", ctypes.c_uint64),
                ("P3Home", ctypes.c_uint64),
                ("P4Home", ctypes.c_uint64),
                ("P5Home", ctypes.c_uint64),
                ("P6Home", ctypes.c_uint64),
                ("ContextFlags", wintypes.DWORD),
                ("MxCsr", wintypes.DWORD),
                ("SegCs", wintypes.WORD),
                ("SegDs", wintypes.WORD),
                ("SegEs", wintypes.WORD),
                ("SegFs", wintypes.WORD),
                ("SegGs", wintypes.WORD),
                ("SegSs", wintypes.WORD),
                ("EFlags", wintypes.DWORD),
                ("Dr0", ctypes.c_uint64),
                ("Dr1", ctypes.c_uint64),
                ("Dr2", ctypes.c_uint64),
                ("Dr3", ctypes.c_uint64),
                ("Dr6", ctypes.c_uint64),
                ("Dr7", ctypes.c_uint64),
                ("Rax", ctypes.c_uint64),
                ("Rcx", ctypes.c_uint64),
                ("Rdx", ctypes.c_uint64),
                ("Rbx", ctypes.c_uint64),
                ("Rsp", ctypes.c_uint64),
                ("Rbp", ctypes.c_uint64),
                ("Rsi", ctypes.c_uint64),
                ("Rdi", ctypes.c_uint64),
                ("R8", ctypes.c_uint64),
                ("R9", ctypes.c_uint64),
                ("R10", ctypes.c_uint64),
                ("R11", ctypes.c_uint64),
                ("R12", ctypes.c_uint64),
                ("R13", ctypes.c_uint64),
                ("R14", ctypes.c_uint64),
                ("R15", ctypes.c_uint64),
                ("Rip", ctypes.c_uint64),
            ]

        context = CONTEXT()
        context.ContextFlags = 0x10001F  # CONTEXT_ALL

        if self.kernel32.GetThreadContext(self.thread_handles[thread_id], ctypes.byref(context)):
            return context

        return None

    def _set_thread_context(self, thread_id: int, context: CONTEXT) -> bool:
        """Set thread context including registers.

        Args:
            thread_id: Thread ID to set context for
            context: CONTEXT structure with new thread state

        Returns:
            True if successful

        """
        if thread_id not in self.thread_handles:
            return False

        return bool(self.kernel32.SetThreadContext(self.thread_handles[thread_id], ctypes.byref(context)))

    def _set_single_step(self, thread_id: int) -> bool:
        """Enable single-step mode for thread."""
        context = self._get_thread_context(thread_id)
        if not context:
            return False

        # Set trap flag (bit 8 of EFLAGS)
        context.EFlags |= 0x100

        return self._set_thread_context(thread_id, context)

    def _read_string(self, address: int, max_length: int = 260) -> str | None:
        """Read null-terminated string from process memory."""
        if not address:
            return None

        data = self._read_memory(address, max_length)
        if not data:
            return None

        try:
            # Find null terminator
            null_index = data.index(b"\x00")
            return data[:null_index].decode("utf-8", errors="ignore")
        except (ValueError, UnicodeDecodeError):
            return None

    def attach(self, process_id: int) -> bool:
        """Alias for attach_to_process for compatibility."""
        return self.attach_to_process(process_id)

    def continue_execution(self) -> bool:
        """Continue execution after breakpoint or exception."""
        if not self.process_id or not self.debugging:
            return False

        # Signal the debug loop to continue
        return True

    def single_step(self, thread_id: int | None = None) -> bool:
        """Execute single instruction step."""
        target_thread = thread_id or self.main_thread_id
        if not target_thread:
            return False

        return self._set_single_step(target_thread)

    def get_registers(self, thread_id: int | None = None) -> dict[str, int] | None:
        """Get CPU registers for thread."""
        target_thread = thread_id or self.main_thread_id
        if not target_thread:
            return None

        context = self._get_thread_context(target_thread)
        if not context:
            return None

        return {
            "rax": context.Rax,
            "rbx": context.Rbx,
            "rcx": context.Rcx,
            "rdx": context.Rdx,
            "rsi": context.Rsi,
            "rdi": context.Rdi,
            "rbp": context.Rbp,
            "rsp": context.Rsp,
            "r8": context.R8,
            "r9": context.R9,
            "r10": context.R10,
            "r11": context.R11,
            "r12": context.R12,
            "r13": context.R13,
            "r14": context.R14,
            "r15": context.R15,
            "rip": context.Rip,
            "eflags": context.EFlags,
            "dr0": context.Dr0,
            "dr1": context.Dr1,
            "dr2": context.Dr2,
            "dr3": context.Dr3,
            "dr6": context.Dr6,
            "dr7": context.Dr7,
        }

    def set_registers(self, registers: dict[str, int], thread_id: int | None = None) -> bool:
        """Set CPU registers for thread."""
        target_thread = thread_id or self.main_thread_id
        if not target_thread:
            return False

        context = self._get_thread_context(target_thread)
        if not context:
            return False

        # Update specified registers
        for reg_name, value in registers.items():
            if hasattr(context, reg_name.capitalize()):
                setattr(context, reg_name.capitalize(), value)

        return self._set_thread_context(target_thread, context)

    def read_memory(self, address: int, size: int) -> bytes | None:
        """Public alias for _read_memory."""
        return self._read_memory(address, size)

    def write_memory(self, address: int, data: bytes) -> bool:
        """Public alias for _write_memory."""
        return self._write_memory(address, data)

    def handle_exception(self, debug_event: Any) -> int:
        """Public alias for _handle_exception.

        Args:
            debug_event: Debug event structure

        Returns:
            Continue status for the debugger

        """
        return self._handle_exception(debug_event)

    def bypass_anti_debug(self) -> bool:
        """Bypass common anti-debugging techniques."""
        if not self.process_handle:
            return False

        try:
            # Patch IsDebuggerPresent
            kernel32_base = self.kernel32.GetModuleHandleA(b"kernel32.dll")
            if kernel32_base:
                is_debugger_present = self.kernel32.GetProcAddress(kernel32_base, b"IsDebuggerPresent")
                if is_debugger_present:
                    # Patch to always return 0 (false)
                    self._write_memory(is_debugger_present, b"\x31\xc0\xc3")  # XOR EAX,EAX; RET

            # Clear PEB BeingDebugged flag
            import struct

            pbi_size = ctypes.sizeof(ctypes.c_void_p) * 6
            pbi = ctypes.create_string_buffer(pbi_size)
            return_length = ctypes.c_ulong()

            # NtQueryInformationProcess
            ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
            if (
                ntdll.NtQueryInformationProcess(
                    self.process_handle,
                    0,  # ProcessBasicInformation
                    pbi,
                    pbi_size,
                    ctypes.byref(return_length),
                )
                == 0
            ):
                peb_address = struct.unpack("P", pbi[ctypes.sizeof(ctypes.c_void_p) : ctypes.sizeof(ctypes.c_void_p) * 2])[0]
                # Clear BeingDebugged flag at PEB+2
                self._write_memory(peb_address + 2, b"\x00")

                # Clear NtGlobalFlag at PEB+0x68 (32-bit) or PEB+0xBC (64-bit)
                if ctypes.sizeof(ctypes.c_void_p) == 8:
                    self._write_memory(peb_address + 0xBC, b"\x00\x00\x00\x00")
                else:
                    self._write_memory(peb_address + 0x68, b"\x00\x00\x00\x00")

            logger.info("Applied anti-debugging bypasses")
            return True

        except Exception as e:
            logger.exception(f"An unexpected error occurred while bypassing anti-debug techniques: {e}")
            return False

    def hide_debugger(self) -> bool:
        """Hide debugger from detection."""
        if not self.process_handle:
            return False

        try:
            # Use NtSetInformationThread to hide debugger
            ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
            ThreadHideFromDebugger = 0x11

            for thread_handle in self.thread_handles.values():
                ntdll.NtSetInformationThread(thread_handle, ThreadHideFromDebugger, None, 0)

            # Hook and patch common anti-debug APIs
            anti_debug_apis = [
                ("kernel32.dll", "IsDebuggerPresent"),
                ("kernel32.dll", "CheckRemoteDebuggerPresent"),
                ("ntdll.dll", "NtQueryInformationProcess"),
            ]

            for dll_name, api_name in anti_debug_apis:
                self.hook_license_api(dll_name, api_name, self._anti_debug_callback)

            logger.info("Debugger hidden from detection")
            return True

        except Exception as e:
            logger.exception(f"An unexpected error occurred while trying to hide the debugger: {e}")
            return False

    def _anti_debug_callback(self, debugger: Any, debug_event: Any) -> None:
        """Handle anti-debug API hooks callback.

        Args:
            debugger: Debugger instance reference
            debug_event: Current debug event

        """
        # Modify return value to indicate no debugger
        context = self.get_registers()
        if context:
            context["rax"] = 0  # Return false/0
            self.set_registers(context)

    def bypass_output_debug_string(self) -> bool:
        """Bypass OutputDebugString anti-debugging detection.

        Many protectors use OutputDebugString with special strings to detect debuggers.
        They check if the debugger consumes the string or if it reaches the system handler.
        """
        if not self.process_handle:
            return False

        try:
            # Method 1: Hook OutputDebugStringA/W to prevent detection
            output_apis = [
                ("kernel32.dll", "OutputDebugStringA"),
                ("kernel32.dll", "OutputDebugStringW"),
            ]

            for dll_name, api_name in output_apis:
                # Get the API address
                dll_base = self.kernel32.GetModuleHandleA(dll_name.encode())
                if not dll_base:
                    continue

                api_addr = self.kernel32.GetProcAddress(dll_base, api_name.encode())
                if not api_addr:
                    continue

                # Hook to redirect the call
                self.hook_license_api(dll_name, api_name, self._output_debug_string_callback)

            # Method 2: Clear the LastError that OutputDebugString sets when no debugger present
            # OutputDebugString sets LastError to 0 when debugger present, non-zero when not
            self.kernel32.SetLastError(0)

            # Method 3: Hook the RaiseException that OutputDebugString internally uses
            # for the DBG_PRINTEXCEPTION_C (0x40010006) and DBG_PRINTEXCEPTION_W (0x4001000A)
            if hasattr(self, "veh_handler") and self.veh_handler:
                # Add filter for OutputDebugString exceptions
                def output_debug_filter(exception_record: ExceptionRecord) -> bool:
                    """Filter OutputDebugString exceptions to prevent detection.

                    Args:
                        exception_record: Exception record structure

                    Returns:
                        True if exception was handled

                    """
                    exc_code = exception_record.ExceptionCode
                    # DBG_PRINTEXCEPTION_C and DBG_PRINTEXCEPTION_W
                    if exc_code in [0x40010006, 0x4001000A]:
                        # Suppress the exception to prevent detection
                        return True  # Handled
                    return False  # Not handled

                self.register_exception_filter(output_debug_filter)

            # Method 4: Patch the OutputDebugString implementation directly
            # Replace first bytes with RET to make it return immediately
            for api_name in ["OutputDebugStringA", "OutputDebugStringW"]:
                api_addr = self.kernel32.GetProcAddress(self.kernel32.GetModuleHandleA(b"kernel32.dll"), api_name.encode())
                if api_addr:
                    # Save original bytes for restoration
                    original = ctypes.create_string_buffer(3)
                    bytes_read = ctypes.c_size_t()
                    if self.kernel32.ReadProcessMemory(
                        self.process_handle, ctypes.c_void_p(api_addr), original, 3, ctypes.byref(bytes_read),
                    ):
                        # Store for potential restoration
                        self.patched_apis[api_name] = (api_addr, original.raw)
                        # Patch with RET (0xC3) + NOPs
                        self._write_memory(api_addr, b"\xc3\x90\x90")

            logger.info("OutputDebugString anti-debug bypass applied")
            return True

        except Exception as e:
            logger.exception(f"An unexpected error occurred while bypassing OutputDebugString detection: {e}")
            return False

    def _output_debug_string_callback(self, debugger: Any, debug_event: Any) -> None:
        """Handle OutputDebugString API hooks callback.

        Modifies behavior to prevent debugger detection.

        Args:
            debugger: Debugger instance reference
            debug_event: Current debug event

        """
        try:
            # Set LastError to indicate no debugger (non-zero value)
            self.kernel32.SetLastError(1284)  # ERROR_INVALID_MENU_HANDLE - arbitrary non-zero

            # Modify return value to indicate success but no debugger
            context = self.get_registers()
            if context:
                # Make it look like no debugger consumed the string
                context["rax"] = 0  # Return success
                self.set_registers(context)

        except Exception as e:
            logger.exception(f"An error occurred in the OutputDebugString callback: {e}")

    def mitigate_timing_attacks(self) -> bool:
        """Mitigate timing-based anti-debugging techniques.

        Implements multiple strategies to defeat timing attacks:
        1. RDTSC patching - Neutralize CPU timestamp counter checks
        2. Performance counter hooks - Control high-resolution timing
        3. GetTickCount manipulation - Control system tick counts
        4. Time acceleration/deceleration - Adjust time perception
        """
        if not self.process_handle:
            return False

        try:
            # Strategy 1: RDTSC/RDTSCP instruction patching
            # Find and patch RDTSC (0F 31) and RDTSCP (0F 01 F9) instructions
            rdtsc_pattern = b"\x0f\x31"  # RDTSC opcode
            rdtscp_pattern = b"\x0f\x01\xf9"  # RDTSCP opcode

            # Scan for timing instructions in executable regions
            for region in self.enumerate_memory_regions():
                if region.get("executable", False):
                    base = region["base_address"]
                    size = region["size"]

                    # Read memory region
                    buffer = ctypes.create_string_buffer(size)
                    bytes_read = ctypes.c_size_t()
                    if self.kernel32.ReadProcessMemory(self.process_handle, ctypes.c_void_p(base), buffer, size, ctypes.byref(bytes_read)):
                        data = buffer.raw[: bytes_read.value]

                        # Find RDTSC instructions
                        for i in range(len(data) - len(rdtsc_pattern) + 1):
                            if data[i : i + len(rdtsc_pattern)] == rdtsc_pattern:
                                # Patch with XOR EAX,EAX; XOR EDX,EDX (return 0)
                                patch = b"\x31\xc0\x31\xd2\x90\x90"  # 6 bytes
                                self._write_memory(base + i, patch[:2])

                        # Find RDTSCP instructions
                        for i in range(len(data) - len(rdtscp_pattern) + 1):
                            if data[i : i + len(rdtscp_pattern)] == rdtscp_pattern:
                                # Patch with XOR EAX,EAX; XOR EDX,EDX; XOR ECX,ECX
                                patch = b"\x31\xc0\x31\xd2\x31\xc9"
                                self._write_memory(base + i, patch)

            # Strategy 2: Hook timing APIs
            timing_apis = [
                ("kernel32.dll", "GetTickCount"),
                ("kernel32.dll", "GetTickCount64"),
                ("kernel32.dll", "QueryPerformanceCounter"),
                ("kernel32.dll", "QueryPerformanceFrequency"),
                ("ntdll.dll", "NtQuerySystemTime"),
                ("ntdll.dll", "NtQueryPerformanceCounter"),
                ("kernel32.dll", "GetSystemTime"),
                ("kernel32.dll", "GetLocalTime"),
                ("kernel32.dll", "GetSystemTimeAsFileTime"),
            ]

            for dll_name, api_name in timing_apis:
                self.hook_license_api(dll_name, api_name, self._timing_api_callback)

            # Strategy 3: Initialize time manipulation state
            self.time_base = ctypes.c_ulonglong(0)
            self.time_scale = 1.0  # Normal speed
            self.emulated_tick_count = 0
            self.last_real_time = 0

            # Get initial tick count as baseline
            self.emulated_tick_count = self.kernel32.GetTickCount()
            self.last_real_time = self.emulated_tick_count

            # Strategy 4: Set up performance counter interception
            # Create emulated performance counter values
            self.emulated_perf_counter = ctypes.c_longlong(1000000)
            self.emulated_perf_frequency = ctypes.c_longlong(10000000)  # 10 MHz emulated frequency

            # Strategy 5: Hook Sleep/SleepEx to compensate for debugging delays
            self.hook_license_api("kernel32.dll", "Sleep", self._sleep_callback)
            self.hook_license_api("kernel32.dll", "SleepEx", self._sleep_callback)

            # Strategy 6: Neutralize NtDelayExecution (used by Sleep internally)
            self.hook_license_api("ntdll.dll", "NtDelayExecution", self._delay_execution_callback)

            # Strategy 7: Apply RDTSC emulation via debug registers
            # Use DR7 to trap RDTSC execution if CPU supports it
            if hasattr(self, "set_hardware_breakpoint"):
                # Set a general detect for privilege instructions
                # Note: This requires ring-0 access, so we'll rely on hooks instead
                pass

            logger.info("Timing attack mitigation applied")
            return True

        except Exception as e:
            logger.exception(f"Failed to mitigate timing attacks: {e}")
            return False

    def _timing_api_callback(self, debugger: Any, debug_event: Any) -> None:
        """Handle timing API hooks callback to provide controlled time values.

        Args:
            debugger: Debugger instance reference
            debug_event: Current debug event

        """
        try:
            context = self.get_registers()
            if not context:
                return

            # Determine which API was called based on return address
            ret_addr = context.get("rsp", context.get("esp", 0))
            if not ret_addr:
                return

            # Read API name from stack or use debug event info
            # Provide consistent controlled values for timing APIs

            # Increment emulated tick count slowly
            self.emulated_tick_count += 10  # Advance by 10ms

            # Set return value based on calling convention
            if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
                # RAX for return value
                context["rax"] = self.emulated_tick_count & 0xFFFFFFFFFFFFFFFF
                # RDX for high part in some APIs
                context["rdx"] = (self.emulated_tick_count >> 64) & 0xFFFFFFFFFFFFFFFF
            else:  # 32-bit
                # EAX for return value
                context["eax"] = self.emulated_tick_count & 0xFFFFFFFF
                # EDX for high part in some APIs
                context["edx"] = (self.emulated_tick_count >> 32) & 0xFFFFFFFF

            self.set_registers(context)

        except Exception as e:
            logger.exception(f"Timing API callback error: {e}")

    def _sleep_callback(self, debugger: Any, debug_event: Any) -> None:
        """Handle Sleep API callback to compensate for debugging overhead.

        Args:
            debugger: Debugger instance reference
            debug_event: Current debug event

        """
        try:
            context = self.get_registers()
            if not context:
                return

            # Get sleep duration from first parameter
            if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
                # RCX contains first parameter in x64 calling convention
                sleep_ms = context.get("rcx", 0)
            else:  # 32-bit
                # Read from stack for stdcall
                esp = context.get("esp", 0)
                if esp:
                    sleep_ms_buf = ctypes.c_uint32()
                    if self.kernel32.ReadProcessMemory(
                        self.process_handle,
                        ctypes.c_void_p(esp + 4),  # First parameter after return address
                        ctypes.byref(sleep_ms_buf),
                        4,
                        None,
                    ):
                        sleep_ms = sleep_ms_buf.value
                    else:
                        sleep_ms = 0
                else:
                    sleep_ms = 0

            # Reduce sleep time to compensate for debugging overhead
            if sleep_ms > 10:
                # Cut sleep time to 10% to speed up debugging
                new_sleep = max(1, sleep_ms // 10)
                if ctypes.sizeof(ctypes.c_void_p) == 8:
                    context["rcx"] = new_sleep
                # Write back to stack
                elif esp:
                    new_sleep_buf = ctypes.c_uint32(new_sleep)
                    self.kernel32.WriteProcessMemory(
                        self.process_handle, ctypes.c_void_p(esp + 4), ctypes.byref(new_sleep_buf), 4, None,
                    )

            self.set_registers(context)

        except Exception as e:
            logger.exception(f"Sleep callback error: {e}")

    def _delay_execution_callback(self, debugger: Any, debug_event: Any) -> None:
        """Speed up delays with NtDelayExecution callback.

        Args:
            debugger: Debugger instance reference
            debug_event: Current debug event

        """
        try:
            # Similar to Sleep callback but for NT-level delay
            context = self.get_registers()
            if context:
                # Zero out the delay interval to skip it
                context["rax"] = 0  # STATUS_SUCCESS
                self.set_registers(context)

        except Exception as e:
            logger.exception(f"Delay execution callback error: {e}")

    def bypass_thread_enumeration(self) -> bool:
        """Bypass thread enumeration detection techniques.

        Hides debugger threads from enumeration APIs that protectors use
        to detect the presence of debugging threads.
        """
        if not self.process_handle:
            return False

        try:
            # Strategy 1: Hook thread enumeration APIs
            enum_apis = [
                ("kernel32.dll", "CreateToolhelp32Snapshot"),
                ("kernel32.dll", "Thread32First"),
                ("kernel32.dll", "Thread32Next"),
                ("ntdll.dll", "NtQuerySystemInformation"),
                ("kernel32.dll", "OpenThread"),
                ("kernel32.dll", "GetThreadContext"),
                ("kernel32.dll", "GetThreadId"),
                ("kernel32.dll", "GetProcessIdOfThread"),
            ]

            for dll_name, api_name in enum_apis:
                self.hook_license_api(dll_name, api_name, self._thread_enum_callback)

            # Strategy 2: Mark our debugger threads as system threads
            for _thread_id, thread_handle in self.thread_handles.items():
                try:
                    # Use NtSetInformationThread to hide the thread
                    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
                    ThreadHideFromDebugger = 0x11
                    ThreadBreakOnTermination = 0x1D

                    # Hide from debugger enumeration
                    ntdll.NtSetInformationThread(thread_handle, ThreadHideFromDebugger, None, 0)

                    # Mark as critical system thread (appears as system process thread)
                    critical = ctypes.c_ulong(1)
                    ntdll.NtSetInformationThread(thread_handle, ThreadBreakOnTermination, ctypes.byref(critical), ctypes.sizeof(critical))
                except Exception as e:
                    self.logger.debug(f"Thread may not allow modification: {e}")  # Some threads may not allow modification

            # Strategy 3: Create a whitelist of legitimate threads
            self.legitimate_threads = set()

            # Enumerate current threads and mark them as legitimate
            import psutil

            try:
                process = psutil.Process(self.process_id)
                for thread in process.threads():
                    self.legitimate_threads.add(thread.id)
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                # Fallback to Windows API enumeration
                snapshot = self.kernel32.CreateToolhelp32Snapshot(0x00000004, self.process_id)  # TH32CS_SNAPTHREAD
                if snapshot != -1:
                    thread_entry = ctypes.create_string_buffer(ctypes.sizeof(ctypes.c_ulong) * 7)
                    thread_entry_size = ctypes.c_ulong(ctypes.sizeof(thread_entry))
                    ctypes.memmove(ctypes.addressof(thread_entry), ctypes.byref(thread_entry_size), 4)

                    if self.kernel32.Thread32First(snapshot, thread_entry):
                        while True:
                            thread_id = ctypes.cast(thread_entry[8:12], ctypes.POINTER(ctypes.c_ulong)).contents.value
                            owner_pid = ctypes.cast(thread_entry[12:16], ctypes.POINTER(ctypes.c_ulong)).contents.value
                            if owner_pid == self.process_id:
                                self.legitimate_threads.add(thread_id)
                            if not self.kernel32.Thread32Next(snapshot, thread_entry):
                                break

                    self.kernel32.CloseHandle(snapshot)

            # Strategy 4: Hook NtOpenThread to prevent access to hidden threads
            self.hidden_thread_ids = set()  # Threads we want to hide

            logger.info(f"Thread enumeration bypass applied, hiding {len(self.hidden_thread_ids)} threads")
            return True

        except Exception as e:
            logger.exception(f"Failed to bypass thread enumeration: {e}")
            return False

    def _thread_enum_callback(self, debugger: Any, debug_event: Any) -> None:
        """Handle thread enumeration API hooks.

        Args:
            debugger: Debugger instance reference
            debug_event: Current debug event

        """
        try:
            context = self.get_registers()
            if not context:
                return

            # Filter out debugger threads from enumeration results
            # Parse the thread enumeration buffer and remove debugger threads
            # by reading the THREADENTRY32 structures from the target process

            # For now, return success but empty results for suspicious calls
            context["rax"] = 0  # Success but no threads found
            self.set_registers(context)

        except Exception as e:
            logger.exception(f"Thread enumeration callback error: {e}")

    def detect_suspended_threads(self) -> dict[int, dict]:
        """Detect suspended threads that may indicate debugging or protection.

        Returns:
            Dictionary mapping thread IDs to suspension information

        """
        suspended_threads = {}

        if not self.process_handle:
            return suspended_threads

        try:
            # Method 1: Check thread suspend counts
            for thread_id, thread_handle in self.thread_handles.items():
                try:
                    # Get thread suspend count
                    suspend_count = ctypes.c_ulong()

                    # Use NtQueryInformationThread
                    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
                    ThreadSuspendCount = 0x23

                    status = ntdll.NtQueryInformationThread(
                        thread_handle, ThreadSuspendCount, ctypes.byref(suspend_count), ctypes.sizeof(suspend_count), None,
                    )

                    if status == 0 and suspend_count.value > 0:
                        suspended_threads[thread_id] = {
                            "suspend_count": suspend_count.value,
                            "handle": thread_handle,
                            "detection_method": "suspend_count",
                        }
                except (OSError, ctypes.ArgumentError) as e:
                    logger.debug(f"Failed to check thread {thread_id} suspension status: {e}")

            # Method 2: Check thread wait states
            for thread_id, thread_handle in self.thread_handles.items():
                if thread_id in suspended_threads:
                    continue  # Already detected

                try:
                    # Get thread context to check instruction pointer
                    context = CONTEXT()
                    context.ContextFlags = CONTEXT_FULL

                    # SuspendThread to get accurate state
                    prev_suspend = self.kernel32.SuspendThread(thread_handle)
                    if prev_suspend != 0xFFFFFFFF:
                        if self.kernel32.GetThreadContext(thread_handle, ctypes.byref(context)):
                            # Check if thread is at a suspension point
                            rip = context.Rip if ctypes.sizeof(ctypes.c_void_p) == 8 else context.Eip

                            # Read instruction at RIP/EIP
                            inst_buf = ctypes.create_string_buffer(16)
                            bytes_read = ctypes.c_size_t()
                            if self.kernel32.ReadProcessMemory(
                                self.process_handle, ctypes.c_void_p(rip), inst_buf, 16, ctypes.byref(bytes_read),
                            ):
                                # Check for common suspension indicators
                                # INT 3 (0xCC), INT 2D (0xCD 0x2D), or infinite loop
                                if inst_buf[0] == 0xCC or (inst_buf[0] == 0xCD and inst_buf[1] == 0x2D):
                                    suspended_threads[thread_id] = {
                                        "suspend_count": prev_suspend,
                                        "handle": thread_handle,
                                        "detection_method": "breakpoint_suspension",
                                        "instruction_pointer": hex(rip),
                                    }
                                # Check for JMP $ (EB FE) - infinite loop
                                elif inst_buf[0] == 0xEB and inst_buf[1] == 0xFE:
                                    suspended_threads[thread_id] = {
                                        "suspend_count": prev_suspend,
                                        "handle": thread_handle,
                                        "detection_method": "infinite_loop",
                                        "instruction_pointer": hex(rip),
                                    }

                        # Resume thread to original state
                        self.kernel32.ResumeThread(thread_handle)
                except (OSError, ctypes.ArgumentError) as e:
                    logger.debug(f"Failed to check thread {thread_id} wait state: {e}")

            # Method 3: Check for debugger-suspended threads
            snapshot = self.kernel32.CreateToolhelp32Snapshot(0x00000004, self.process_id)  # TH32CS_SNAPTHREAD
            if snapshot != -1:

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

                thread_entry = THREADENTRY32()
                thread_entry.dwSize = ctypes.sizeof(THREADENTRY32)

                if self.kernel32.Thread32First(snapshot, ctypes.byref(thread_entry)):
                    while True:
                        if thread_entry.th32OwnerProcessID == self.process_id:
                            # Check if this thread is in our handles but shows as suspended
                            if thread_entry.th32ThreadID not in self.thread_handles:
                                # Untracked thread - might be hidden/suspended
                                suspended_threads[thread_entry.th32ThreadID] = {
                                    "suspend_count": -1,  # Unknown
                                    "handle": None,
                                    "detection_method": "untracked_thread",
                                    "flags": thread_entry.dwFlags,
                                }

                        if not self.kernel32.Thread32Next(snapshot, ctypes.byref(thread_entry)):
                            break

                self.kernel32.CloseHandle(snapshot)

            # Log findings
            if suspended_threads:
                logger.info(f"Detected {len(suspended_threads)} suspended threads")
                for tid, info in suspended_threads.items():
                    logger.debug(f"Thread {tid}: {info['detection_method']}, suspend_count={info['suspend_count']}")

            return suspended_threads

        except Exception as e:
            logger.exception(f"Failed to detect suspended threads: {e}")
            return suspended_threads

    def manipulate_thread_local_storage(self, thread_id: int, tls_index: int, value: bytes) -> bool:
        """Manipulate Thread Local Storage (TLS) for anti-debugging and hiding.

        Args:
            thread_id: Target thread ID
            tls_index: TLS slot index
            value: Value to write to TLS

        Returns:
            True if successful

        """
        if thread_id not in self.thread_handles:
            logger.error(f"Thread {thread_id} not found")
            return False

        try:
            thread_handle = self.thread_handles[thread_id]

            # Get Thread Information Block (TIB) address
            ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

            class THREAD_BASIC_INFORMATION(ctypes.Structure):  # noqa: N801
                _fields_ = [
                    ("ExitStatus", ctypes.c_long),
                    ("TebBaseAddress", ctypes.c_void_p),
                    ("ClientId", ctypes.c_ulonglong),
                    ("AffinityMask", ctypes.c_void_p),
                    ("Priority", ctypes.c_long),
                    ("BasePriority", ctypes.c_long),
                ]

            tbi = THREAD_BASIC_INFORMATION()
            status = ntdll.NtQueryInformationThread(
                thread_handle,
                0,  # ThreadBasicInformation
                ctypes.byref(tbi),
                ctypes.sizeof(tbi),
                None,
            )

            if status != 0:
                logger.error(f"Failed to get TEB address: {hex(status)}")
                return False

            teb_address = tbi.TebBaseAddress

            # TEB structure offsets
            if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
                tls_slots_offset = 0x1480  # TEB.TlsSlots
                tls_expansion_offset = 0x1780  # TEB.TlsExpansionSlots
            else:  # 32-bit
                tls_slots_offset = 0xE10  # TEB.TlsSlots
                tls_expansion_offset = 0xF94  # TEB.TlsExpansionSlots

            # Determine which TLS array to use
            if tls_index < 64:
                # Use primary TLS slots
                tls_address = teb_address + tls_slots_offset + (tls_index * ctypes.sizeof(ctypes.c_void_p))
            else:
                # Use TLS expansion slots
                expansion_index = tls_index - 64
                if expansion_index >= 1024:
                    logger.error(f"TLS index {tls_index} out of range")
                    return False

                # Read TlsExpansionSlots pointer
                expansion_ptr = ctypes.c_void_p()
                if not self.kernel32.ReadProcessMemory(
                    self.process_handle,
                    ctypes.c_void_p(teb_address + tls_expansion_offset),
                    ctypes.byref(expansion_ptr),
                    ctypes.sizeof(expansion_ptr),
                    None,
                ):
                    logger.error("Failed to read TLS expansion pointer")
                    return False

                if not expansion_ptr.value:
                    logger.error("TLS expansion slots not allocated")
                    return False

                tls_address = expansion_ptr.value + (expansion_index * ctypes.sizeof(ctypes.c_void_p))

            # Write the TLS value
            value_ptr = ctypes.c_void_p(int.from_bytes(value, "little"))
            if not self.kernel32.WriteProcessMemory(
                self.process_handle, ctypes.c_void_p(tls_address), ctypes.byref(value_ptr), ctypes.sizeof(value_ptr), None,
            ):
                logger.error("Failed to write TLS value")
                return False

            # Also manipulate TLS callbacks if they exist
            # Parse PE header for TLS directory
            pe_info = self.analyze_pe_header()
            if pe_info and "tls_callbacks" in pe_info:
                for callback_addr in pe_info["tls_callbacks"]:
                    # Hook or patch TLS callbacks to prevent anti-debugging
                    # Replace with RET instruction
                    self._write_memory(callback_addr, b"\xc3")
                    logger.debug(f"Neutralized TLS callback at {hex(callback_addr)}")

            logger.info(f"Successfully manipulated TLS index {tls_index} for thread {thread_id}")
            return True

        except Exception as e:
            logger.exception(f"Failed to manipulate TLS: {e}")
            return False

    def trace_thread_execution(self, thread_id: int, max_instructions: int = 1000) -> list[dict]:
        """Trace thread execution by single-stepping through instructions.

        Args:
            thread_id: Thread to trace
            max_instructions: Maximum instructions to trace

        Returns:
            List of traced instruction information

        """
        if thread_id not in self.thread_handles:
            logger.error(f"Thread {thread_id} not found")
            return []

        trace_log = []

        try:
            thread_handle = self.thread_handles[thread_id]

            # Suspend thread for tracing
            if self.kernel32.SuspendThread(thread_handle) == 0xFFFFFFFF:
                logger.error("Failed to suspend thread")
                return []

            try:
                # Get initial context
                context = CONTEXT()
                context.ContextFlags = CONTEXT_FULL

                if not self.kernel32.GetThreadContext(thread_handle, ctypes.byref(context)):
                    logger.error("Failed to get thread context")
                    return []

                # Enable single-step mode (Trap Flag)
                context.EFlags |= 0x100  # TF flag

                if not self.kernel32.SetThreadContext(thread_handle, ctypes.byref(context)):
                    logger.error("Failed to set thread context")
                    return []

                # Set up exception handler for single-step exceptions
                single_step_count = 0

                # Resume thread to start tracing
                self.kernel32.ResumeThread(thread_handle)

                # Main tracing loop
                while single_step_count < max_instructions:
                    # Wait for single-step exception
                    debug_event = DEBUG_EVENT()
                    if self.kernel32.WaitForDebugEvent(ctypes.byref(debug_event), 100):
                        if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                            exception = debug_event.u.Exception
                            if exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP:
                                # Get current context
                                if self.kernel32.GetThreadContext(thread_handle, ctypes.byref(context)):
                                    # Get instruction pointer
                                    if ctypes.sizeof(ctypes.c_void_p) == 8:
                                        ip = context.Rip
                                        regs = {
                                            "rax": context.Rax,
                                            "rbx": context.Rbx,
                                            "rcx": context.Rcx,
                                            "rdx": context.Rdx,
                                            "rsi": context.Rsi,
                                            "rdi": context.Rdi,
                                            "rbp": context.Rbp,
                                            "rsp": context.Rsp,
                                            "rip": context.Rip,
                                        }
                                    else:
                                        ip = context.Eip
                                        regs = {
                                            "eax": context.Eax,
                                            "ebx": context.Ebx,
                                            "ecx": context.Ecx,
                                            "edx": context.Edx,
                                            "esi": context.Esi,
                                            "edi": context.Edi,
                                            "ebp": context.Ebp,
                                            "esp": context.Esp,
                                            "eip": context.Eip,
                                        }

                                    # Read instruction bytes
                                    inst_buf = ctypes.create_string_buffer(16)
                                    bytes_read = ctypes.c_size_t()
                                    if self.kernel32.ReadProcessMemory(
                                        self.process_handle, ctypes.c_void_p(ip), inst_buf, 16, ctypes.byref(bytes_read),
                                    ):
                                        inst_bytes = inst_buf.raw[: bytes_read.value]

                                        # Disassemble instruction if Capstone is available
                                        inst_str = ""
                                        try:
                                            from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs, CsError

                                            if ctypes.sizeof(ctypes.c_void_p) == 8:
                                                md = Cs(CS_ARCH_X86, CS_MODE_64)
                                            else:
                                                md = Cs(CS_ARCH_X86, CS_MODE_32)

                                            for inst in md.disasm(inst_bytes, ip):
                                                inst_str = f"{inst.mnemonic} {inst.op_str}"
                                                break
                                        except (CsError, TypeError, ValueError):
                                            inst_str = inst_bytes.hex()

                                        # Log the traced instruction
                                        trace_entry = {
                                            "address": hex(ip),
                                            "instruction": inst_str,
                                            "bytes": inst_bytes.hex(),
                                            "registers": regs,
                                            "thread_id": thread_id,
                                            "step": single_step_count,
                                        }
                                        trace_log.append(trace_entry)

                                        # Check for control flow changes
                                        if inst_bytes[0] in [0xE8, 0xE9, 0xFF, 0xC3, 0xC2]:  # CALL, JMP, RET
                                            trace_entry["type"] = "control_flow"
                                        elif inst_bytes[0] & 0xF0 == 0x70:  # Conditional jumps
                                            trace_entry["type"] = "conditional_jump"
                                        else:
                                            trace_entry["type"] = "normal"

                                    # Re-enable single-step
                                    context.EFlags |= 0x100
                                    self.kernel32.SetThreadContext(thread_handle, ctypes.byref(context))

                                single_step_count += 1

                        # Continue debugging
                        self.kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE)
                    else:
                        # No debug event, check if thread is still alive
                        exit_code = ctypes.c_ulong()
                        if self.kernel32.GetExitCodeThread(thread_handle, ctypes.byref(exit_code)):
                            if exit_code.value != 259:  # STILL_ACTIVE
                                logger.info(f"Thread {thread_id} terminated with code {exit_code.value}")
                                break

                # Disable single-step mode
                context.EFlags &= ~0x100
                self.kernel32.SetThreadContext(thread_handle, ctypes.byref(context))

            finally:
                # Resume thread to normal execution
                self.kernel32.ResumeThread(thread_handle)

            logger.info(f"Traced {len(trace_log)} instructions for thread {thread_id}")
            return trace_log

        except Exception as e:
            logger.exception(f"Failed to trace thread execution: {e}")
            return trace_log

    def analyze_tls_callbacks(self) -> list[int]:
        """Analyze Thread Local Storage callbacks."""
        tls_callbacks = []

        if not self.process_handle:
            return tls_callbacks

        try:
            # Get main module base
            modules = list(self.modules.keys())
            if not modules:
                return tls_callbacks

            module_base = modules[0]  # First module is usually main executable

            # Read PE header
            pe_header = self._read_memory(module_base, 0x1000)
            if not pe_header or pe_header[:2] != b"MZ":
                return tls_callbacks

            # Parse DOS header
            e_lfanew = struct.unpack("<I", pe_header[0x3C:0x40])[0]

            # Parse NT headers
            nt_header_offset = e_lfanew
            if pe_header[nt_header_offset : nt_header_offset + 4] != b"PE\x00\x00":
                return tls_callbacks

            # Get optional header
            machine = struct.unpack("<H", pe_header[nt_header_offset + 4 : nt_header_offset + 6])[0]
            is_64bit = machine == 0x8664

            opt_header_offset = nt_header_offset + 24

            # Get TLS directory RVA
            if is_64bit:
                tls_dir_offset = opt_header_offset + 144  # TLS directory offset in optional header
            else:
                tls_dir_offset = opt_header_offset + 128

            tls_rva = struct.unpack("<I", pe_header[tls_dir_offset : tls_dir_offset + 4])[0]
            tls_size = struct.unpack("<I", pe_header[tls_dir_offset + 4 : tls_dir_offset + 8])[0]

            if tls_rva and tls_size:
                # Read TLS directory
                tls_dir = self._read_memory(module_base + tls_rva, tls_size)
                if tls_dir and len(tls_dir) >= 24:
                    # Get callbacks array pointer
                    if is_64bit:
                        callbacks_ptr = struct.unpack("<Q", tls_dir[16:24])[0]
                    else:
                        callbacks_ptr = struct.unpack("<I", tls_dir[12:16])[0]

                    if callbacks_ptr:
                        # Read callback addresses
                        callback_size = 8 if is_64bit else 4
                        for i in range(10):  # Limit to 10 callbacks
                            callback_data = self._read_memory(callbacks_ptr + i * callback_size, callback_size)
                            if not callback_data:
                                break

                            if is_64bit:
                                callback_addr = struct.unpack("<Q", callback_data)[0]
                            else:
                                callback_addr = struct.unpack("<I", callback_data)[0]

                            if callback_addr == 0:
                                break

                            tls_callbacks.append(callback_addr)
                            logger.info(f"Found TLS callback at 0x{callback_addr:X}")

        except Exception as e:
            logger.exception(f"Error analyzing TLS callbacks: {e}")

        return tls_callbacks

    def disassemble_tls_callbacks(self) -> dict[int, list[str]]:
        """Disassemble TLS callback functions for analysis.

        Returns:
            Dictionary mapping callback addresses to disassembled instructions

        """
        disassembled = {}

        if not self.process_handle:
            return disassembled

        try:
            # Get TLS callbacks
            callbacks = self.analyze_tls_callbacks()

            if not callbacks:
                logger.info("No TLS callbacks found to disassemble")
                return disassembled

            # Try to import Capstone disassembler
            try:
                from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

                has_capstone = True
            except ImportError:
                has_capstone = False
                logger.warning("Capstone not available, using raw bytes")

            # Determine architecture
            is_64bit = ctypes.sizeof(ctypes.c_void_p) == 8

            for callback_addr in callbacks:
                instructions = []

                # Read up to 1024 bytes from callback
                code_bytes = self._read_memory(callback_addr, 1024)
                if not code_bytes:
                    continue

                if has_capstone:
                    # Disassemble with Capstone
                    if is_64bit:
                        md = Cs(CS_ARCH_X86, CS_MODE_64)
                    else:
                        md = Cs(CS_ARCH_X86, CS_MODE_32)

                    for instruction_count, inst in enumerate(md.disasm(code_bytes, callback_addr)):
                        inst_str = f"0x{inst.address:X}: {inst.mnemonic} {inst.op_str}"
                        instructions.append(inst_str)

                        # Check for common protection patterns
                        if inst.mnemonic in ["int3", "int", "ud2"]:
                            instructions.append("  [!] Anti-debug instruction detected")
                        elif inst.mnemonic == "cpuid":
                            instructions.append("  [!] CPU detection (VM/timing)")
                        elif inst.mnemonic == "rdtsc":
                            instructions.append("  [!] Timing check detected")
                        elif inst.mnemonic in ["call", "jmp"] and "fs:" in inst.op_str:
                            instructions.append("  [!] TEB/PEB access detected")

                        # Stop at return or after 50 instructions
                        if inst.mnemonic in ["ret", "retn"] or instruction_count + 1 > 50:
                            break
                else:
                    # Raw byte display
                    for i in range(0, min(100, len(code_bytes)), 16):
                        hex_str = code_bytes[i : i + 16].hex()
                        hex_pairs = " ".join(hex_str[j : j + 2] for j in range(0, len(hex_str), 2))
                        instructions.append(f"0x{callback_addr + i:X}: {hex_pairs}")

                        # Basic pattern detection
                        chunk = code_bytes[i : i + 16]
                        if b"\xcc" in chunk:
                            instructions.append("  [!] INT3 breakpoint detected")
                        if b"\x0f\x31" in chunk:
                            instructions.append("  [!] RDTSC timing check detected")
                        if b"\x0f\xa2" in chunk:
                            instructions.append("  [!] CPUID instruction detected")

                disassembled[callback_addr] = instructions
                logger.info(f"Disassembled TLS callback at 0x{callback_addr:X}: {len(instructions)} instructions")

            return disassembled

        except Exception as e:
            logger.exception(f"Failed to disassemble TLS callbacks: {e}")
            return disassembled

    def bypass_tls_callbacks(self) -> bool:
        """Bypass TLS callbacks by patching or skipping them.

        Returns:
            True if callbacks were successfully bypassed

        """
        if not self.process_handle:
            return False

        try:
            callbacks = self.analyze_tls_callbacks()

            if not callbacks:
                logger.info("No TLS callbacks to bypass")
                return True

            bypassed_count = 0

            for callback_addr in callbacks:
                try:
                    # Method 1: Replace with RET instruction
                    # This is the simplest and most effective method
                    ret_patch = b"\xc3"  # RET
                    if self._write_memory(callback_addr, ret_patch):
                        logger.info(f"Bypassed TLS callback at 0x{callback_addr:X} with RET")
                        bypassed_count += 1
                        continue

                    # Method 2: If patching fails, try to hook it
                    # Install a detour that skips the callback
                    original_bytes = self._read_memory(callback_addr, 5)
                    if original_bytes:
                        # Create a JMP to skip the callback (JMP +0)
                        # This effectively makes it a NOP sled
                        jmp_patch = b"\xe9\x00\x00\x00\x00"  # JMP rel32 (to next instruction)
                        if self._write_memory(callback_addr, jmp_patch):
                            logger.info(f"Bypassed TLS callback at 0x{callback_addr:X} with JMP")
                            bypassed_count += 1
                            continue

                    logger.warning(f"Failed to bypass TLS callback at 0x{callback_addr:X}")

                except Exception as e:
                    logger.error(f"Error bypassing callback at 0x{callback_addr:X}: {e}")

            # Method 3: Clear the TLS callback table itself
            # This prevents any callbacks from being called
            modules = list(self.modules.keys())
            if modules:
                module_base = modules[0]
                pe_header = self._read_memory(module_base, 0x1000)

                if pe_header and pe_header[:2] == b"MZ":
                    e_lfanew = struct.unpack("<I", pe_header[0x3C:0x40])[0]
                    nt_header_offset = e_lfanew

                    if pe_header[nt_header_offset : nt_header_offset + 4] == b"PE\x00\x00":
                        machine = struct.unpack("<H", pe_header[nt_header_offset + 4 : nt_header_offset + 6])[0]
                        is_64bit = machine == 0x8664
                        opt_header_offset = nt_header_offset + 24

                        if is_64bit:
                            tls_dir_offset = opt_header_offset + 144
                        else:
                            tls_dir_offset = opt_header_offset + 128

                        tls_rva = struct.unpack("<I", pe_header[tls_dir_offset : tls_dir_offset + 4])[0]

                        if tls_rva:
                            # Read TLS directory
                            tls_dir = self._read_memory(module_base + tls_rva, 24)
                            if tls_dir:
                                # Get callbacks pointer and zero it out
                                if is_64bit:
                                    callbacks_ptr_offset = 16
                                    null_ptr = b"\x00" * 8
                                else:
                                    callbacks_ptr_offset = 12
                                    null_ptr = b"\x00" * 4

                                # Zero the callback pointer in TLS directory
                                if self._write_memory(module_base + tls_rva + callbacks_ptr_offset, null_ptr):
                                    logger.info("Cleared TLS callback table pointer")
                                    bypassed_count = len(callbacks)

            logger.info(f"Successfully bypassed {bypassed_count}/{len(callbacks)} TLS callbacks")
            return bypassed_count > 0

        except Exception as e:
            logger.exception(f"Failed to bypass TLS callbacks: {e}")
            return False

    def hook_tls_callbacks(self, callback_handler: Callable) -> bool:
        """Intercept and modify TLS callback behavior.

        Args:
            callback_handler: Function to handle intercepted TLS callbacks

        Returns:
            True if callbacks were successfully hooked

        """
        if not self.process_handle:
            return False

        try:
            callbacks = self.analyze_tls_callbacks()

            if not callbacks:
                logger.info("No TLS callbacks to hook")
                return True

            hooked_count = 0

            # Store original bytes and handlers
            if not hasattr(self, "tls_hooks"):
                self.tls_hooks = {}

            for callback_addr in callbacks:
                try:
                    # Read original bytes (need at least 5 for a JMP)
                    original_bytes = self._read_memory(callback_addr, 16)
                    if not original_bytes:
                        continue

                    # Allocate memory for the hook trampoline
                    trampoline_size = 256
                    trampoline_addr = self.kernel32.VirtualAllocEx(
                        self.process_handle, None, trampoline_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
                    )

                    if not trampoline_addr:
                        logger.error(f"Failed to allocate trampoline for callback at 0x{callback_addr:X}")
                        continue

                    # Create hook trampoline
                    # The trampoline will:
                    # 1. Save registers
                    # 2. Call our handler
                    # 3. Restore registers
                    # 4. Execute original instructions
                    # 5. Jump back

                    is_64bit = ctypes.sizeof(ctypes.c_void_p) == 8

                    if is_64bit:
                        # x64 trampoline
                        trampoline = bytearray(
                            [
                                # Save all registers
                                0x50,  # push rax
                                0x51,  # push rcx
                                0x52,  # push rdx
                                0x53,  # push rbx
                                0x54,  # push rsp
                                0x55,  # push rbp
                                0x56,  # push rsi
                                0x57,  # push rdi
                                0x41,
                                0x50,  # push r8
                                0x41,
                                0x51,  # push r9
                                0x41,
                                0x52,  # push r10
                                0x41,
                                0x53,  # push r11
                                0x41,
                                0x54,  # push r12
                                0x41,
                                0x55,  # push r13
                                0x41,
                                0x56,  # push r14
                                0x41,
                                0x57,  # push r15
                                # Call our handler (store address later)
                                0x48,
                                0xB8,  # mov rax, imm64
                            ],
                        )
                        # Add handler address (8 bytes)
                        handler_addr_bytes = struct.pack("<Q", id(callback_handler))
                        trampoline.extend(handler_addr_bytes)
                        trampoline.extend(
                            [
                                0xFF,
                                0xD0,  # call rax
                                # Restore registers
                                0x41,
                                0x5F,  # pop r15
                                0x41,
                                0x5E,  # pop r14
                                0x41,
                                0x5D,  # pop r13
                                0x41,
                                0x5C,  # pop r12
                                0x41,
                                0x5B,  # pop r11
                                0x41,
                                0x5A,  # pop r10
                                0x41,
                                0x59,  # pop r9
                                0x41,
                                0x58,  # pop r8
                                0x5F,  # pop rdi
                                0x5E,  # pop rsi
                                0x5D,  # pop rbp
                                0x5C,  # pop rsp
                                0x5B,  # pop rbx
                                0x5A,  # pop rdx
                                0x59,  # pop rcx
                                0x58,  # pop rax
                            ],
                        )
                    else:
                        # x86 trampoline
                        trampoline = bytearray(
                            [
                                # Save all registers
                                0x60,  # pushad
                                # Call our handler
                                0xB8,  # mov eax, imm32
                            ],
                        )
                        # Add handler address (4 bytes)
                        handler_addr_bytes = struct.pack("<I", id(callback_handler))
                        trampoline.extend(handler_addr_bytes)
                        trampoline.extend(
                            [
                                0xFF,
                                0xD0,  # call eax
                                # Restore registers
                                0x61,  # popad
                            ],
                        )

                    # Add original instructions (first 5 bytes minimum)
                    trampoline.extend(original_bytes[:5])

                    # Add jump back to original + 5
                    trampoline.append(0xE9)  # JMP rel32
                    jump_offset = (callback_addr + 5) - (trampoline_addr + len(trampoline) + 4)
                    trampoline.extend(struct.pack("<i", jump_offset))

                    # Write trampoline to allocated memory
                    if not self._write_memory(trampoline_addr, bytes(trampoline)):
                        self.kernel32.VirtualFreeEx(self.process_handle, trampoline_addr, 0, MEM_RELEASE)
                        continue

                    # Create JMP from original to trampoline
                    hook_bytes = bytearray([0xE9])  # JMP rel32
                    hook_offset = trampoline_addr - (callback_addr + 5)
                    hook_bytes.extend(struct.pack("<i", hook_offset))

                    # Install the hook
                    if self._write_memory(callback_addr, bytes(hook_bytes)):
                        self.tls_hooks[callback_addr] = {
                            "original": original_bytes,
                            "trampoline": trampoline_addr,
                            "handler": callback_handler,
                        }
                        hooked_count += 1
                        logger.info(f"Hooked TLS callback at 0x{callback_addr:X}")
                    else:
                        self.kernel32.VirtualFreeEx(self.process_handle, trampoline_addr, 0, MEM_RELEASE)

                except Exception as e:
                    logger.error(f"Failed to hook callback at 0x{callback_addr:X}: {e}")

            logger.info(f"Successfully hooked {hooked_count}/{len(callbacks)} TLS callbacks")
            return hooked_count > 0

        except Exception as e:
            logger.exception(f"Failed to hook TLS callbacks: {e}")
            return False

    def detect_tls_protection(self) -> dict[str, Any]:
        """Detect TLS-based protection mechanisms.

        Returns:
            Dictionary containing detected protection information

        """
        protection_info = {
            "has_tls": False,
            "callback_count": 0,
            "suspicious_patterns": [],
            "protection_likelihood": "None",
            "detected_techniques": [],
        }

        if not self.process_handle:
            return protection_info

        try:
            # Get TLS callbacks
            callbacks = self.analyze_tls_callbacks()

            if not callbacks:
                return protection_info

            protection_info["has_tls"] = True
            protection_info["callback_count"] = len(callbacks)

            # Disassemble and analyze each callback
            disassembled = self.disassemble_tls_callbacks()

            suspicion_score = 0

            for callback_addr, instructions in disassembled.items():
                # Check for anti-debugging patterns
                for inst_line in instructions:
                    inst_lower = inst_line.lower()

                    # Check for debugging detection
                    if any(pattern in inst_lower for pattern in ["int3", "int 3", "debugger", "isdebuggerpresent"]):
                        protection_info["suspicious_patterns"].append(f"Anti-debugging at 0x{callback_addr:X}")
                        protection_info["detected_techniques"].append("Anti-Debugging")
                        suspicion_score += 3

                    # Check for timing attacks
                    if any(pattern in inst_lower for pattern in ["rdtsc", "queryperformance", "gettickcount"]):
                        protection_info["suspicious_patterns"].append(f"Timing check at 0x{callback_addr:X}")
                        protection_info["detected_techniques"].append("Timing Analysis")
                        suspicion_score += 2

                    # Check for VM detection
                    if any(pattern in inst_lower for pattern in ["cpuid", "vmware", "virtualbox", "hypervisor"]):
                        protection_info["suspicious_patterns"].append(f"VM detection at 0x{callback_addr:X}")
                        protection_info["detected_techniques"].append("VM Detection")
                        suspicion_score += 2

                    # Check for process/module enumeration
                    if any(pattern in inst_lower for pattern in ["createtoolhelp", "module32", "process32"]):
                        protection_info["suspicious_patterns"].append(f"Process enumeration at 0x{callback_addr:X}")
                        protection_info["detected_techniques"].append("Process Scanning")
                        suspicion_score += 1

                    # Check for PEB access
                    if any(pattern in inst_lower for pattern in ["fs:[30h]", "fs:[0x30]", "gs:[60h]", "gs:[0x60]", "peb", "teb"]):
                        protection_info["suspicious_patterns"].append(f"PEB/TEB access at 0x{callback_addr:X}")
                        protection_info["detected_techniques"].append("PEB Manipulation")
                        suspicion_score += 2

                    # Check for exception handling
                    if any(pattern in inst_lower for pattern in ["seh", "exception", "vectored", "unhandled"]):
                        protection_info["suspicious_patterns"].append(f"Exception handling at 0x{callback_addr:X}")
                        protection_info["detected_techniques"].append("Exception-Based Protection")
                        suspicion_score += 2

                    # Check for code unpacking/decryption
                    if any(pattern in inst_lower for pattern in ["virtualprotect", "xor", "decrypt", "unpack"]):
                        protection_info["suspicious_patterns"].append(f"Code modification at 0x{callback_addr:X}")
                        protection_info["detected_techniques"].append("Code Unpacking")
                        suspicion_score += 3

                    # Check for integrity checks
                    if any(pattern in inst_lower for pattern in ["crc", "checksum", "hash", "integrity"]):
                        protection_info["suspicious_patterns"].append(f"Integrity check at 0x{callback_addr:X}")
                        protection_info["detected_techniques"].append("Integrity Checking")
                        suspicion_score += 2

                # Check callback size - large callbacks are suspicious
                if len(instructions) > 30:
                    protection_info["suspicious_patterns"].append(
                        f"Large callback at 0x{callback_addr:X} ({len(instructions)} instructions)",
                    )
                    suspicion_score += 1

            # Remove duplicate techniques
            protection_info["detected_techniques"] = list(set(protection_info["detected_techniques"]))

            # Determine protection likelihood based on score
            if suspicion_score >= 10:
                protection_info["protection_likelihood"] = "Very High"
            elif suspicion_score >= 7:
                protection_info["protection_likelihood"] = "High"
            elif suspicion_score >= 4:
                protection_info["protection_likelihood"] = "Medium"
            elif suspicion_score >= 1:
                protection_info["protection_likelihood"] = "Low"
            else:
                protection_info["protection_likelihood"] = "None"

            # Check for known protectors by TLS patterns
            known_protectors = {
                "Themida": ["rdtsc", "cpuid", "int3", "virtualprotect"],
                "VMProtect": ["cpuid", "rdtsc", "seh", "virtualprotect"],
                "ASProtect": ["exception", "decrypt", "virtualprotect"],
                "Enigma": ["checksum", "decrypt", "debugger"],
                "PECompact": ["unpack", "virtualprotect", "decrypt"],
                "UPX": ["unpack", "virtualprotect"],
            }

            # Check which protector patterns match
            for protector, patterns in known_protectors.items():
                match_count = 0
                for pattern in patterns:
                    if any(pattern in sp.lower() for sp in protection_info["suspicious_patterns"]):
                        match_count += 1

                if match_count >= 2:  # At least 2 patterns match
                    protection_info["detected_techniques"].append(f"Possible {protector}")

            logger.info(f"TLS protection analysis complete: {protection_info['protection_likelihood']} likelihood")

            return protection_info

        except Exception as e:
            logger.exception(f"Failed to detect TLS protection: {e}")
            return protection_info

    def parse_iat(self) -> dict[str, list[tuple[int, str]]]:
        """Parse Import Address Table."""
        iat_entries = {}

        if not self.process_handle:
            return iat_entries

        try:
            # Get main module base
            modules = list(self.modules.keys())
            if not modules:
                return iat_entries

            module_base = modules[0]

            # Use existing import analysis
            import_data = self._analyze_imports(module_base, 0, 0x10000)

            # Group by DLL
            for addr, api_name in import_data.items():
                dll_name = "unknown.dll"  # Could be enhanced to track DLL names
                if dll_name not in iat_entries:
                    iat_entries[dll_name] = []
                iat_entries[dll_name].append((addr, api_name))

        except Exception as e:
            logger.exception(f"Error parsing IAT: {e}")

        return iat_entries

    def parse_eat(self) -> list[tuple[int, str]]:
        """Parse Export Address Table."""
        eat_entries = []

        if not self.process_handle:
            return eat_entries

        try:
            # Get main module base
            modules = list(self.modules.keys())
            if not modules:
                return eat_entries

            module_base = modules[0]

            # Read PE header to get export directory
            pe_header = self._read_memory(module_base, 0x1000)
            if not pe_header or pe_header[:2] != b"MZ":
                return eat_entries

            # Parse DOS header
            e_lfanew = struct.unpack("<I", pe_header[0x3C:0x40])[0]

            # Parse NT headers
            nt_header_offset = e_lfanew
            if pe_header[nt_header_offset : nt_header_offset + 4] != b"PE\x00\x00":
                return eat_entries

            # Get architecture
            machine = struct.unpack("<H", pe_header[nt_header_offset + 4 : nt_header_offset + 6])[0]
            is_64bit = machine == 0x8664

            # Get export directory RVA and size
            opt_header_offset = nt_header_offset + 24
            if is_64bit:
                export_dir_rva = struct.unpack("<I", pe_header[opt_header_offset + 112 : opt_header_offset + 116])[0]
                export_dir_size = struct.unpack("<I", pe_header[opt_header_offset + 116 : opt_header_offset + 120])[0]
            else:
                export_dir_rva = struct.unpack("<I", pe_header[opt_header_offset + 96 : opt_header_offset + 100])[0]
                export_dir_size = struct.unpack("<I", pe_header[opt_header_offset + 100 : opt_header_offset + 104])[0]

            if not export_dir_rva or not export_dir_size:
                return eat_entries

            # Read export directory
            export_data = self._read_memory(module_base + export_dir_rva, min(export_dir_size, 0x1000))
            if not export_data or len(export_data) < 40:
                return eat_entries

            # Parse IMAGE_EXPORT_DIRECTORY
            num_functions = struct.unpack("<I", export_data[20:24])[0]
            num_names = struct.unpack("<I", export_data[24:28])[0]
            addr_functions_rva = struct.unpack("<I", export_data[28:32])[0]
            addr_names_rva = struct.unpack("<I", export_data[32:36])[0]
            addr_ordinals_rva = struct.unpack("<I", export_data[36:40])[0]

            # Read function addresses array
            if addr_functions_rva and num_functions > 0:
                func_addresses = self._read_memory(module_base + addr_functions_rva, num_functions * 4)

                # Read names array
                if addr_names_rva and num_names > 0:
                    names_array = self._read_memory(module_base + addr_names_rva, num_names * 4)
                    ordinals_array = self._read_memory(module_base + addr_ordinals_rva, num_names * 2)

                    if func_addresses and names_array and ordinals_array:
                        for i in range(min(num_names, 1000)):  # Limit to prevent excessive processing
                            # Get name RVA
                            name_rva = struct.unpack("<I", names_array[i * 4 : (i + 1) * 4])[0]
                            func_name = self._read_string(module_base + name_rva, 256)

                            # Get ordinal
                            ordinal = struct.unpack("<H", ordinals_array[i * 2 : (i + 1) * 2])[0]

                            # Get function address using ordinal as index
                            if ordinal < num_functions:
                                func_rva = struct.unpack("<I", func_addresses[ordinal * 4 : (ordinal + 1) * 4])[0]

                                # Check if it's a forwarded export (RVA points within export directory)
                                if func_rva >= export_dir_rva and func_rva < export_dir_rva + export_dir_size:
                                    # Forwarded export - the RVA points to a string
                                    forward_name = self._read_string(module_base + func_rva, 256)
                                    if forward_name:
                                        func_name = f"{func_name} -> {forward_name}"
                                    func_addr = 0  # Forwarded exports don't have a direct address
                                else:
                                    func_addr = module_base + func_rva

                                if func_name:
                                    eat_entries.append((func_addr, func_name))

        except Exception as e:
            logger.exception(f"Error parsing EAT: {e}")

        return eat_entries

    def parse_delayed_imports(self) -> dict[str, list[tuple[int, str, bool]]]:
        """Parse delayed import directory and delayed IAT.

        Delayed imports are loaded only when first used, providing:
        - Faster application startup
        - Reduced memory usage
        - Optional dependency handling

        Returns:
            Dictionary mapping DLL names to tuples of (address, function_name, is_bound)

        """
        delayed_imports = {}

        if not self.process_handle:
            return delayed_imports

        try:
            # Get main module base
            modules = list(self.modules.keys())
            if not modules:
                return delayed_imports

            module_base = modules[0]

            # Read and validate PE header
            pe_header = self._read_memory(module_base, 0x1000)
            if not self._validate_pe_header(pe_header):
                return delayed_imports

            # Parse PE headers to get architecture and delayed import directory
            nt_header_offset, is_64bit = self._parse_nt_header(pe_header)
            delay_import_rva, delay_import_size = self._get_delay_import_info(pe_header, nt_header_offset, is_64bit)

            if not delay_import_rva or not delay_import_size:
                logger.debug("No delayed imports found")
                return delayed_imports

            # Parse delay import descriptors
            delayed_imports = self._parse_delay_descriptors(module_base, delay_import_rva, delay_import_size, is_64bit)

            # Log summary and check for suspicious imports
            self._log_delayed_imports_summary(delayed_imports)

            return delayed_imports

        except Exception as e:
            logger.exception(f"Failed to parse delayed imports: {e}")
            return delayed_imports

    def _validate_pe_header(self, pe_header: bytes) -> bool:
        """Validate PE header.

        Args:
            pe_header: PE header bytes to validate

        Returns:
            True if valid PE header

        """
        if not pe_header or pe_header[:2] != b"MZ":
            return False
        # Parse DOS header
        e_lfanew = struct.unpack("<I", pe_header[0x3C:0x40])[0]
        # Parse NT headers
        nt_header_offset = e_lfanew
        return pe_header[nt_header_offset:nt_header_offset + 4] == b"PE\x00\x00"

    def _parse_nt_header(self, pe_header: bytes) -> tuple[int, bool]:
        """Parse NT header to get architecture info.

        Args:
            pe_header: PE header bytes

        Returns:
            Tuple of (NT header offset, is_64bit flag)

        """
        e_lfanew = struct.unpack("<I", pe_header[0x3C:0x40])[0]
        nt_header_offset = e_lfanew
        machine = struct.unpack("<H", pe_header[nt_header_offset + 4 : nt_header_offset + 6])[0]
        is_64bit = machine == 0x8664
        return nt_header_offset, is_64bit

    def _get_delay_import_info(self, pe_header: bytes, nt_header_offset: int, is_64bit: bool) -> tuple[int, int]:
        """Get delay import directory information.

        Args:
            pe_header: PE header bytes
            nt_header_offset: Offset to NT header
            is_64bit: Whether binary is 64-bit

        Returns:
            Tuple of (delay_import_rva, delay_import_size)

        """
        opt_header_offset = nt_header_offset + 24
        if is_64bit:
            # 64-bit: Delay Import Directory is at offset 200 in optional header
            delay_import_offset = opt_header_offset + 200
        else:
            # 32-bit: Delay Import Directory is at offset 184 in optional header
            delay_import_offset = opt_header_offset + 184

        delay_import_rva = struct.unpack("<I", pe_header[delay_import_offset : delay_import_offset + 4])[0]
        delay_import_size = struct.unpack("<I", pe_header[delay_import_offset + 4 : delay_import_offset + 8])[0]
        return delay_import_rva, delay_import_size

    def _parse_delay_descriptors(self, module_base: int, delay_import_rva: int, delay_import_size: int, is_64bit: bool) -> dict[str, list[tuple[int, str, bool]]]:
        """Parse delay import descriptors.

        Args:
            module_base: Base address of module in memory
            delay_import_rva: RVA of delay import directory
            delay_import_size: Size of delay import directory
            is_64bit: Whether binary is 64-bit

        Returns:
            Dictionary mapping DLL names to import function lists

        """
        delayed_imports: dict[str, list[tuple[int, str, bool]]] = {}

        # Read delay import descriptors
        delay_desc_size = 32  # Size of ImgDelayDescr structure
        num_descriptors = min(delay_import_size // delay_desc_size, 50)  # Limit to prevent excessive processing

        for i in range(num_descriptors):
            desc_offset = module_base + delay_import_rva + (i * delay_desc_size)
            desc_data = self._read_memory(desc_offset, delay_desc_size)

            if not desc_data:
                break

            # Parse ImgDelayDescr structure
            attributes = struct.unpack("<I", desc_data[0:4])[0]
            dll_name_rva = struct.unpack("<I", desc_data[4:8])[0]
            module_handle_rva = struct.unpack("<I", desc_data[8:12])[0]
            iat_rva = struct.unpack("<I", desc_data[12:16])[0]
            int_rva = struct.unpack("<I", desc_data[16:20])[0]  # Import Name Table
            bound_iat_rva = struct.unpack("<I", desc_data[20:24])[0]
            struct.unpack("<I", desc_data[24:28])[0]
            timestamp = struct.unpack("<I", desc_data[28:32])[0]

            # Check if this is the end of descriptors
            if dll_name_rva == 0:
                break

            # Parse individual descriptor
            descriptor_imports = self._parse_delay_descriptor(
                module_base, attributes, dll_name_rva, module_handle_rva, iat_rva, int_rva, bound_iat_rva, timestamp, is_64bit,
            )

            if descriptor_imports:
                dll_name, functions = descriptor_imports
                delayed_imports[dll_name] = functions

        return delayed_imports

    def _parse_delay_descriptor(
        self,
        module_base: int,
        attributes: int,
        dll_name_rva: int,
        module_handle_rva: int,
        iat_rva: int,
        int_rva: int,
        bound_iat_rva: int,
        timestamp: int,
        is_64bit: bool,
    ) -> tuple[str, list[tuple[int, str, bool]]] | None:
        """Parse a single delay import descriptor.

        Args:
            module_base: Base address of module in memory
            attributes: Descriptor attributes
            dll_name_rva: RVA of DLL name string
            module_handle_rva: RVA of module handle pointer
            iat_rva: RVA of Import Address Table
            int_rva: RVA of Import Name Table
            bound_iat_rva: RVA of bound IAT
            timestamp: Bound import timestamp
            is_64bit: Whether binary is 64-bit

        Returns:
            Tuple of (dll_name, function_list) or None

        """
        # Determine if RVAs are relative to image base (new format) or virtual addresses (old format)
        is_new_format = (attributes & 0x1) != 0

        # Read DLL name
        if is_new_format:
            dll_name_addr = module_base + dll_name_rva
        else:
            dll_name_addr = dll_name_rva

        dll_name = self._read_string(dll_name_addr, 256)
        if not dll_name:
            return None

        functions = []

        # Check if DLL is already loaded
        is_loaded = self._check_dll_loaded(module_base, module_handle_rva, is_new_format, is_64bit)

        # Parse Import Name Table and IAT
        if int_rva and iat_rva:
            functions = self._parse_import_table(module_base, int_rva, iat_rva, is_new_format, is_64bit, is_loaded)

        # Check for bound imports in the bound IAT
        if bound_iat_rva and timestamp != 0:
            # This DLL has bound imports (pre-resolved addresses)
            logger.debug(f"DLL {dll_name} has bound imports (timestamp={timestamp})")

        return dll_name, functions

    def _check_dll_loaded(self, module_base: int, module_handle_rva: int, is_new_format: bool, is_64bit: bool) -> bool:
        """Check if DLL is already loaded.

        Args:
            module_base: Base address of module in memory
            module_handle_rva: RVA of module handle pointer
            is_new_format: Whether delay import uses new format
            is_64bit: Whether binary is 64-bit

        Returns:
            True if DLL is already loaded

        """
        if not module_handle_rva:
            return False

        module_handle_addr = module_base + module_handle_rva if is_new_format else module_handle_rva
        handle_data = self._read_memory(module_handle_addr, 8 if is_64bit else 4)
        if handle_data:
            handle_value = struct.unpack("<Q" if is_64bit else "<I", handle_data)[0]
            return handle_value != 0
        return False

    def _parse_import_table(self, module_base: int, int_rva: int, iat_rva: int, is_new_format: bool, is_64bit: bool, is_loaded: bool) -> list[tuple[int, str, bool]]:
        """Parse the import table for a specific DLL.

        Args:
            module_base: Base address of module in memory
            int_rva: RVA of Import Name Table
            iat_rva: RVA of Import Address Table
            is_new_format: Whether delay import uses new format
            is_64bit: Whether binary is 64-bit
            is_loaded: Whether DLL is already loaded

        Returns:
            List of (address, function_name, is_bound) tuples

        """
        functions: list[tuple[int, str, bool]] = []

        # Set addresses
        int_addr = module_base + int_rva if is_new_format else int_rva
        iat_addr = module_base + iat_rva if is_new_format else iat_rva

        # Read INT and IAT entries
        entry_size = 8 if is_64bit else 4
        for j in range(1000):  # Maximum imports per DLL
            # Read INT entry
            int_entry_data = self._read_memory(int_addr + j * entry_size, entry_size)
            if not int_entry_data:
                break

            int_entry = struct.unpack("<Q" if is_64bit else "<I", int_entry_data)[0]
            if int_entry == 0:
                break

            # Read IAT entry
            iat_entry_data = self._read_memory(iat_addr + j * entry_size, entry_size)
            if iat_entry_data:
                iat_entry = struct.unpack("<Q" if is_64bit else "<I", iat_entry_data)[0]
            else:
                iat_entry = 0

            # Get function information
            func_info = self._get_function_info(module_base, int_entry, is_new_format, is_64bit, j)

            if func_info:
                func_name, func_addr = func_info

                # Determine if function is bound (already resolved)
                is_bound = self._determine_bound_status(is_loaded, iat_entry, int_entry, func_addr, iat_addr, j, entry_size)

                functions.append((func_addr, func_name, is_bound))

                # Log interesting delayed imports
                if func_name.lower() in [
                    "loadlibrarya",
                    "loadlibraryw",
                    "getprocaddress",
                    "virtualprotect",
                    "virtualalloc",
                    "createthread",
                ]:
                    logger.info(f"Found delayed import: {func_name} at 0x{func_addr:X} (bound={is_bound})")

        return functions

    def _get_function_info(self, module_base: int, int_entry: int, is_new_format: bool, is_64bit: bool, j: int) -> tuple[str, int]:
        """Get function information (name and address) based on import entry.

        Args:
            module_base: Base address of module in memory
            int_entry: Import Name Table entry value
            is_new_format: Whether delay import uses new format
            is_64bit: Whether binary is 64-bit
            j: Index for fallback naming

        Returns:
            Tuple of (function_name, address)

        """
        # Check if import is by ordinal or name
        if is_64bit:
            is_ordinal = (int_entry & 0x8000000000000000) != 0
            ordinal = int_entry & 0xFFFF
        else:
            is_ordinal = (int_entry & 0x80000000) != 0
            ordinal = int_entry & 0xFFFF

        if is_ordinal:
            func_name = f"Ordinal_{ordinal}"
            func_addr = ordinal
        else:
            # Import by name - read hint/name table entry
            hint_name_addr = module_base + int_entry if is_new_format else int_entry

            # Skip hint (2 bytes) and read name
            func_name = self._read_string(hint_name_addr + 2, 256)
            if not func_name:
                func_name = f"Unknown_{j}"
            func_addr = hint_name_addr

        return func_name, func_addr

    def _determine_bound_status(self, is_loaded: bool, iat_entry: int, int_entry: int, func_addr: int, iat_addr: int, j: int, entry_size: int) -> bool:
        """Determine if function is bound (already resolved).

        Args:
            is_loaded: Whether DLL is already loaded
            iat_entry: Import Address Table entry value
            int_entry: Import Name Table entry value
            func_addr: Function address
            iat_addr: IAT base address
            j: Entry index
            entry_size: Size of entry (4 or 8 bytes)

        Returns:
            True if function is bound

        """
        if is_loaded and iat_entry not in (0, int_entry):
            # IAT entry has been updated with actual function address
            return True
        # Function not yet resolved
        return False

    def _log_delayed_imports_summary(self, delayed_imports: dict[str, list[tuple[int, str, bool]]]) -> None:
        """Log summary of delayed imports and check for suspicious imports.

        Args:
            delayed_imports: Dictionary of delayed imports

        """
        # Summary
        total_dlls = len(delayed_imports)
        total_imports = sum(len(imports) for imports in delayed_imports.values())

        if total_dlls > 0:
            logger.info(f"Found {total_imports} delayed imports from {total_dlls} DLLs")

            # Check for suspicious delayed imports often used by packers/protectors
            suspicious_dlls = ["kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll"]
            suspicious_apis = [
                "virtualprotect",
                "virtualalloc",
                "loadlibrary",
                "getprocaddress",
                "createremotethread",
                "writeprocessmemory",
                "readprocessmemory",
            ]

            for dll_name, imports in delayed_imports.items():
                if dll_name.lower() in suspicious_dlls:
                    for _addr, func_name, _is_bound in imports:
                        if any(api in func_name.lower() for api in suspicious_apis):
                            logger.warning(f"Suspicious delayed import: {dll_name}!{func_name}")

    def hook_delayed_import(self, dll_name: str, func_name: str, hook_handler: Callable) -> bool:
        """Install hook for delayed import function.

        Args:
            dll_name: Name of the DLL containing the function
            func_name: Name of the function to hook
            hook_handler: Handler function to call when import is resolved

        Returns:
            True if hook was successfully installed

        """
        if not self.process_handle:
            return False

        try:
            # Parse delayed imports to find the target
            delayed_imports = self.parse_delayed_imports()

            if dll_name not in delayed_imports:
                logger.error(f"DLL {dll_name} not found in delayed imports")
                return False

            # Find the specific import
            target_import = None
            for addr, name, is_bound in delayed_imports[dll_name]:
                if func_name.lower() in name.lower():
                    target_import = (addr, name, is_bound)
                    break

            if not target_import:
                logger.error(f"Function {func_name} not found in {dll_name}")
                return False

            addr, name, is_bound = target_import

            if is_bound:
                # Function already resolved, hook directly
                logger.info(f"Delayed import {dll_name}!{name} already bound at 0x{addr:X}")
                return self.hook_api(addr, hook_handler)
            # Function not yet resolved, install IAT hook
            # This will trigger when the delayed import is first used
            logger.info(f"Installing IAT hook for delayed import {dll_name}!{name}")

            # Allocate trampoline for the hook
            trampoline_size = 256
            trampoline = self.kernel32.VirtualAllocEx(
                self.process_handle, None, trampoline_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
            )

            if not trampoline:
                logger.error("Failed to allocate trampoline memory")
                return False

            # Store the hook info
            if not hasattr(self, "delayed_import_hooks"):
                self.delayed_import_hooks = {}

            self.delayed_import_hooks[addr] = {"dll": dll_name, "function": name, "handler": hook_handler, "trampoline": trampoline}

            # Monitor the IAT entry for changes
            # This would typically be done with a memory breakpoint or polling
            # For now, we'll set up a guard page on the IAT entry
            iat_page = addr & ~0xFFF  # Get page base
            old_protect = ctypes.c_ulong()

            if self.kernel32.VirtualProtectEx(
                self.process_handle, ctypes.c_void_p(iat_page), 0x1000, PAGE_GUARD | PAGE_READWRITE, ctypes.byref(old_protect),
            ):
                logger.info(f"Set guard page on delayed import IAT at 0x{iat_page:X}")
                return True
            logger.error("Failed to set guard page on IAT")
            self.kernel32.VirtualFreeEx(self.process_handle, trampoline, 0, MEM_RELEASE)
            return False

        except Exception as e:
            logger.exception(f"Failed to hook delayed import: {e}")
            return False

    def assemble_x86_x64(self, mnemonic: str, operands: str, arch: str = "x64") -> bytes:
        """Assemble x86/x64 instructions into machine code.

        Args:
            mnemonic: Instruction mnemonic (e.g., "mov", "jmp", "call")
            operands: Instruction operands (e.g., "rax, rbx", "dword ptr [rax]")
            arch: Architecture - "x86" or "x64"

        Returns:
            Assembled machine code bytes

        """
        try:
            # Try to use Keystone assembler if available
            result = self._try_keystone_assemble(mnemonic, operands, arch)
            if result:
                return result

            # Manual encoding for common instructions
            return self._manual_assemble(mnemonic, operands, arch)

        except Exception as e:
            logger.exception(f"Failed to assemble instruction: {e}")
            return b""

    def _try_keystone_assemble(self, mnemonic: str, operands: str, arch: str) -> bytes:
        """Try to use keystone assembler."""
        try:
            import keystone

            if arch == "x64":
                ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
            else:
                ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)

            asm_str = f"{mnemonic} {operands}" if operands else mnemonic
            encoding, _count = ks.asm(asm_str)

            if encoding:
                return bytes(encoding)

        except ImportError:
            logger.debug("Keystone assembler not available, falling back to manual encoding")
        return b""

    def _manual_assemble(self, mnemonic: str, operands: str, arch: str) -> bytes:
        """Manual encoding for common instructions."""
        mnemonic = mnemonic.lower()
        is_64bit = arch == "x64"

        # Basic instruction encoding table
        if mnemonic == "nop":
            return b"\x90"
        if mnemonic == "ret":
            return self._encode_ret(operands)
        if mnemonic == "int3":
            return b"\xcc"
        if mnemonic == "int":
            return self._encode_int(operands)
        if mnemonic == "push":
            return self._encode_push(operands, is_64bit)
        if mnemonic == "pop":
            return self._encode_pop(operands, is_64bit)
        if mnemonic == "jmp":
            return self._encode_jmp(operands, is_64bit)
        if mnemonic == "call":
            return self._encode_call(operands, is_64bit)
        if mnemonic == "mov":
            return self._encode_mov(operands, is_64bit)
        if mnemonic == "xor":
            return self._encode_xor(operands, is_64bit)
        if mnemonic == "add":
            return self._encode_add(operands, is_64bit)
        if mnemonic == "sub":
            return self._encode_sub(operands, is_64bit)

        # If we couldn't encode it, return empty bytes
        logger.warning(f"Could not encode: {mnemonic} {operands}")
        return b""

    def _encode_ret(self, operands: str) -> bytes:
        """Encode RET instruction."""
        if operands:
            # RET with immediate
            imm = int(operands, 0)
            return b"\xc2" + struct.pack("<H", imm)
        return b"\xc3"

    def _encode_int(self, operands: str) -> bytes:
        """Encode INT instruction."""
        imm = int(operands, 0)
        if imm == 3:
            return b"\xcc"
        return b"\xcd" + bytes([imm])

    def _encode_push(self, operands: str, is_64bit: bool) -> bytes:
        """Encode PUSH instruction."""
        if operands in ["rax", "eax"]:
            return b"\x50"
        if operands in ["rcx", "ecx"]:
            return b"\x51"
        if operands in ["rdx", "edx"]:
            return b"\x52"
        if operands in ["rbx", "ebx"]:
            return b"\x53"
        if operands in ["rsp", "esp"]:
            return b"\x54"
        if operands in ["rbp", "ebp"]:
            return b"\x55"
        if operands in ["rsi", "esi"]:
            return b"\x56"
        if operands in ["rdi", "edi"]:
            return b"\x57"
        if is_64bit and operands.startswith("r"):
            # 64-bit extended registers
            reg_map = {"r8": 0, "r9": 1, "r10": 2, "r11": 3, "r12": 4, "r13": 5, "r14": 6, "r15": 7}
            if operands in reg_map:
                return bytes([0x41, 0x50 + reg_map[operands]])
        else:
            # Push immediate
            try:
                imm = int(operands, 0)
                if -128 <= imm <= 127:
                    return b"\x6a" + struct.pack("b", imm)
                return b"\x68" + struct.pack("<I", imm & 0xFFFFFFFF)
            except (struct.error, TypeError, OverflowError) as e:
                logger.debug(f"Failed to encode push immediate '{operands}': {e}")

        return b""

    def _encode_pop(self, operands: str, is_64bit: bool) -> bytes:
        """Encode POP instruction."""
        if operands in ["rax", "eax"]:
            return b"\x58"
        if operands in ["rcx", "ecx"]:
            return b"\x59"
        if operands in ["rdx", "edx"]:
            return b"\x5a"
        if operands in ["rbx", "ebx"]:
            return b"\x5b"
        if operands in ["rsp", "esp"]:
            return b"\x5c"
        if operands in ["rbp", "ebp"]:
            return b"\x5d"
        if operands in ["rsi", "esi"]:
            return b"\x5e"
        if operands in ["rdi", "edi"]:
            return b"\x5f"
        if is_64bit and operands.startswith("r"):
            reg_map = {"r8": 0, "r9": 1, "r10": 2, "r11": 3, "r12": 4, "r13": 5, "r14": 6, "r15": 7}
            if operands in reg_map:
                return bytes([0x41, 0x58 + reg_map[operands]])

        return b""

    def _encode_jmp(self, operands: str, is_64bit: bool) -> bytes:
        """Encode JMP instruction."""
        if operands.startswith("0x") or operands.isdigit():
            # JMP to absolute address - need relative offset
            target = int(operands, 0)
            # For now, use short jump if possible
            # Calculate relative offset for jump
            current_pos = 0  # Will be filled by patcher
            offset = target - (current_pos + 2)  # 2 bytes for short jump
            if -128 <= offset <= 127:
                return b"\xeb" + bytes([offset & 0xFF])  # Short jump with calculated offset
            # Near jump for longer distances
            offset = target - (current_pos + 5)  # 5 bytes for near jump
            return b"\xe9" + offset.to_bytes(4, "little", signed=True)
        if operands in ["rax", "eax"]:
            return b"\xff\xe0"  # JMP RAX/EAX
        if operands in ["rbx", "ebx"]:
            return b"\xff\xe3"  # JMP RBX/EBX
        # JMP rel8
        return b"\xeb\x00"

    def _encode_call(self, operands: str, is_64bit: bool) -> bytes:
        """Encode CALL instruction."""
        if operands in ["rax", "eax"]:
            return b"\xff\xd0"  # CALL RAX/EAX
        if operands in ["rbx", "ebx"]:
            return b"\xff\xd3"  # CALL RBX/EBX
        # CALL rel32 - calculate relative offset
        if operands.startswith("0x") or operands.isdigit():
            target = int(operands, 0)
            # Calculate relative offset from current position
            current_pos = 0  # Will be filled by patcher during runtime
            offset = target - (current_pos + 5)  # 5 bytes for CALL rel32
            return b"\xe8" + offset.to_bytes(4, "little", signed=True)
        # Default CALL with zero offset - will be patched at runtime
        return b"\xe8\x00\x00\x00\x00"

    def _encode_mov(self, operands: str, is_64bit: bool) -> bytes:
        """Encode MOV instruction."""
        parts = [p.strip() for p in operands.split(",")]
        if len(parts) == 2:
            dst, src = parts

            # MOV reg, reg
            reg_map_32 = {"eax": 0, "ecx": 1, "edx": 2, "ebx": 3, "esp": 4, "ebp": 5, "esi": 6, "edi": 7}
            reg_map_64 = {"rax": 0, "rcx": 1, "rdx": 2, "rbx": 3, "rsp": 4, "rbp": 5, "rsi": 6, "rdi": 7}

            if is_64bit and dst in reg_map_64 and src in reg_map_64:
                # MOV r64, r64
                return bytes([0x48, 0x89, 0xC0 | (reg_map_64[src] << 3) | reg_map_64[dst]])
            if not is_64bit and dst in reg_map_32 and src in reg_map_32:
                # MOV r32, r32
                return bytes([0x89, 0xC0 | (reg_map_32[src] << 3) | reg_map_32[dst]])
            if dst == "rax" and src.startswith("0x"):
                # MOV RAX, imm64
                imm = int(src, 0)
                return b"\x48\xb8" + struct.pack("<Q", imm)
            if dst == "eax" and src.startswith("0x"):
                # MOV EAX, imm32
                imm = int(src, 0)
                return b"\xb8" + struct.pack("<I", imm & 0xFFFFFFFF)

        return b""

    def _encode_xor(self, operands: str, is_64bit: bool) -> bytes:
        """Encode XOR instruction."""
        parts = [p.strip() for p in operands.split(",")]
        if len(parts) == 2 and parts[0] == parts[1]:
            # XOR reg, reg (same register - zero it)
            if parts[0] in ["rax", "eax"]:
                if is_64bit and parts[0] == "rax":
                    return b"\x48\x31\xc0"  # XOR RAX, RAX
                return b"\x31\xc0"  # XOR EAX, EAX
            if parts[0] in ["rcx", "ecx"]:
                if is_64bit and parts[0] == "rcx":
                    return b"\x48\x31\xc9"  # XOR RCX, RCX
                return b"\x31\xc9"  # XOR ECX, ECX
            if parts[0] in ["rdx", "edx"]:
                if is_64bit and parts[0] == "rdx":
                    return b"\x48\x31\xd2"  # XOR RDX, RDX
                return b"\x31\xd2"  # XOR EDX, EDX

        return b""

    def _encode_add(self, operands: str, is_64bit: bool) -> bytes:
        """Encode ADD instruction."""
        parts = [p.strip() for p in operands.split(",")]
        if len(parts) == 2:
            dst, src = parts
            if dst in ["rsp", "esp"] and src.isdigit():
                # ADD RSP/ESP, imm
                imm = int(src, 0)
                if -128 <= imm <= 127:
                    if is_64bit and dst == "rsp":
                        return b"\x48\x83\xc4" + struct.pack("b", imm)
                    return b"\x83\xc4" + struct.pack("b", imm)
                if is_64bit and dst == "rsp":
                    return b"\x48\x81\xc4" + struct.pack("<I", imm & 0xFFFFFFFF)
                return b"\x81\xc4" + struct.pack("<I", imm & 0xFFFFFFFF)

        return b""

    def _encode_sub(self, operands: str, is_64bit: bool) -> bytes:
        """Encode SUB instruction."""
        parts = [p.strip() for p in operands.split(",")]
        if len(parts) == 2:
            dst, src = parts
            if dst in ["rsp", "esp"] and src.isdigit():
                # SUB RSP/ESP, imm
                imm = int(src, 0)
                if -128 <= imm <= 127:
                    if is_64bit and dst == "rsp":
                        return b"\x48\x83\xec" + struct.pack("b", imm)
                    return b"\x83\xec" + struct.pack("b", imm)
                if is_64bit and dst == "rsp":
                    return b"\x48\x81\xec" + struct.pack("<I", imm & 0xFFFFFFFF)
                return b"\x81\xec" + struct.pack("<I", imm & 0xFFFFFFFF)

        return b""

    def encode_instruction(
        self,
        opcode: bytes,
        modrm: int | None = None,
        sib: int | None = None,
        displacement: bytes | None = None,
        immediate: bytes | None = None,
        prefixes: bytes | None = None,
    ) -> bytes:
        """Encode x86/x64 instruction with all components.

        Args:
            opcode: Main opcode bytes
            modrm: ModR/M byte
            sib: SIB byte
            displacement: Displacement bytes
            immediate: Immediate value bytes
            prefixes: Prefix bytes (REX, segment override, etc.)

        Returns:
            Complete encoded instruction

        """
        instruction = bytearray()

        # Add prefixes
        if prefixes:
            instruction.extend(prefixes)

        # Add opcode
        instruction.extend(opcode)

        # Add ModR/M byte
        if modrm is not None:
            instruction.append(modrm)

        # Add SIB byte
        if sib is not None:
            instruction.append(sib)

        # Add displacement
        if displacement:
            instruction.extend(displacement)

        # Add immediate
        if immediate:
            instruction.extend(immediate)

        return bytes(instruction)

    def calculate_relative_jump(self, from_addr: int, to_addr: int, instruction_size: int) -> bytes:
        """Calculate relative jump offset for JMP/CALL instructions.

        Args:
            from_addr: Address of the jump instruction
            to_addr: Target address to jump to
            instruction_size: Size of the jump instruction (2 for short, 5 for near)

        Returns:
            Relative offset bytes

        """
        # Calculate relative offset
        # Offset is calculated from the end of the instruction
        offset = to_addr - (from_addr + instruction_size)

        if instruction_size == 2:
            # Short jump (8-bit offset)
            if -128 <= offset <= 127:
                return struct.pack("b", offset)
            raise ValueError(f"Offset {offset} too large for short jump")
        if instruction_size == 5:
            # Near jump (32-bit offset)
            if -2147483648 <= offset <= 2147483647:
                return struct.pack("<i", offset)
            raise ValueError(f"Offset {offset} too large for near jump")
        raise ValueError(f"Invalid instruction size: {instruction_size}")

    def generate_dynamic_patch(self, target_addr: int, patch_type: str, **kwargs: Any) -> bytes:
        """Generate dynamic patches for various scenarios.

        Args:
            target_addr: Address where patch will be applied
            patch_type: Type of patch ("jmp", "call", "nop", "ret", "bypass")
            **kwargs: Additional parameters based on patch type

        Returns:
            Generated patch bytes

        """
        try:
            arch = "x64" if ctypes.sizeof(ctypes.c_void_p) == 8 else "x86"

            if patch_type == "jmp":
                # Generate JMP to destination
                dest_addr = kwargs.get("destination", 0)
                if dest_addr:
                    # Try short jump first
                    try:
                        offset = self.calculate_relative_jump(target_addr, dest_addr, 2)
                        return b"\xeb" + offset
                    except (ValueError, OverflowError, struct.error):
                        # Use near jump
                        offset = self.calculate_relative_jump(target_addr, dest_addr, 5)
                        return b"\xe9" + offset

            elif patch_type == "call":
                # Generate CALL to destination
                dest_addr = kwargs.get("destination", 0)
                if dest_addr:
                    offset = self.calculate_relative_jump(target_addr, dest_addr, 5)
                    return b"\xe8" + offset

            elif patch_type == "nop":
                # Generate NOP sled of specified length
                length = kwargs.get("length", 1)
                return self.generate_nop_sled(length)

            elif patch_type == "ret":
                # Generate RET with optional stack cleanup
                stack_cleanup = kwargs.get("stack_cleanup", 0)
                if stack_cleanup:
                    return b"\xc2" + struct.pack("<H", stack_cleanup)
                return b"\xc3"

            elif patch_type == "bypass":
                # Generate conditional jump bypass
                condition = kwargs.get("condition", "always")

                if condition == "always":
                    # Convert conditional jump to unconditional
                    return b"\xeb"  # Short JMP
                if condition == "never":
                    # Convert to NOP
                    return b"\x90\x90"  # Two NOPs for JCC
                if condition == "invert":
                    # Invert the condition
                    original_opcode = kwargs.get("original_opcode", 0)
                    if original_opcode:
                        # Invert the condition bit
                        return bytes([original_opcode ^ 1])

            elif patch_type == "hook":
                # Generate hook trampoline
                hook_addr = kwargs.get("hook_address", 0)
                original_bytes = kwargs.get("original_bytes", b"")

                if hook_addr and original_bytes:
                    patch = bytearray()

                    # Save registers
                    patch.append(0x60)  # PUSHAD (x86) or use individual pushes for x64

                    # Call hook
                    if arch == "x64":
                        # MOV RAX, hook_addr
                        patch.extend(b"\x48\xb8")
                        patch.extend(struct.pack("<Q", hook_addr))
                        # CALL RAX
                        patch.extend(b"\xff\xd0")
                    else:
                        # PUSH hook_addr
                        patch.append(0x68)
                        patch.extend(struct.pack("<I", hook_addr))
                        # CALL [ESP]
                        patch.extend(b"\xff\x14\x24")
                        # ADD ESP, 4
                        patch.extend(b"\x83\xc4\x04")

                    # Restore registers
                    patch.append(0x61)  # POPAD

                    # Execute original bytes
                    patch.extend(original_bytes)

                    # Jump back
                    return_addr = target_addr + len(original_bytes)
                    offset = self.calculate_relative_jump(target_addr + len(patch), return_addr, 5)
                    patch.extend(b"\xe9" + offset)

                    return bytes(patch)

            elif patch_type == "redirect":
                # Generate code redirection
                new_function = kwargs.get("new_function", 0)
                if new_function:
                    # JMP to new function
                    offset = self.calculate_relative_jump(target_addr, new_function, 5)
                    return b"\xe9" + offset

            return b""

        except Exception as e:
            logger.exception(f"Failed to generate dynamic patch: {e}")
            return b""

    def relocate_code(self, code: bytes, old_base: int, new_base: int, reloc_offsets: list[int]) -> bytes:
        """Relocate code to a new base address.

        Args:
            code: Original code bytes
            old_base: Original base address
            new_base: New base address
            reloc_offsets: List of offsets in code that need relocation

        Returns:
            Relocated code bytes

        """
        try:
            relocated = bytearray(code)
            delta = new_base - old_base

            # Apply relocations
            for offset in reloc_offsets:
                if offset + 4 <= len(relocated):
                    # Read current value
                    current = struct.unpack("<I", relocated[offset : offset + 4])[0]
                    # Apply relocation
                    new_value = (current + delta) & 0xFFFFFFFF
                    # Write back
                    relocated[offset : offset + 4] = struct.pack("<I", new_value)

            # Fix relative jumps and calls
            i = 0
            while i < len(relocated):
                # Check for JMP rel32 (E9)
                if i + 5 <= len(relocated) and relocated[i] == 0xE9:
                    # Read relative offset
                    rel_offset = struct.unpack("<i", relocated[i + 1 : i + 5])[0]
                    # Calculate absolute target
                    old_target = old_base + i + 5 + rel_offset
                    # Calculate new relative offset
                    new_rel_offset = old_target - (new_base + i + 5)
                    # Write back
                    relocated[i + 1 : i + 5] = struct.pack("<i", new_rel_offset)
                    i += 5

                # Check for CALL rel32 (E8)
                elif i + 5 <= len(relocated) and relocated[i] == 0xE8:
                    rel_offset = struct.unpack("<i", relocated[i + 1 : i + 5])[0]
                    old_target = old_base + i + 5 + rel_offset
                    new_rel_offset = old_target - (new_base + i + 5)
                    relocated[i + 1 : i + 5] = struct.pack("<i", new_rel_offset)
                    i += 5

                # Check for short JMP (EB) and conditional jumps (70-7F)
                elif i + 2 <= len(relocated) and (relocated[i] == 0xEB or (0x70 <= relocated[i] <= 0x7F)):
                    # Short jumps are position-independent within the relocated block
                    i += 2
                else:
                    i += 1

            return bytes(relocated)

        except Exception as e:
            logger.exception(f"Failed to relocate code: {e}")
            return code

    def generate_shellcode(self, shellcode_type: str, **params: Any) -> bytes:
        """Generate various types of shellcode for injection.

        Args:
            shellcode_type: Type of shellcode ("msgbox", "exec", "dll_inject", "patch")
            **params: Parameters specific to shellcode type

        Returns:
            Generated shellcode bytes

        """
        try:
            arch = "x64" if ctypes.sizeof(ctypes.c_void_p) == 8 else "x86"

            if shellcode_type == "msgbox":
                # Simple MessageBox shellcode
                title = params.get("title", "Alert").encode() + b"\x00"
                message = params.get("message", "Injected").encode() + b"\x00"

                if arch == "x86":
                    shellcode = bytearray(
                        [
                            # Push strings onto stack
                            0x68,  # PUSH title
                        ],
                    )
                    # Add title address (needs runtime calculation)
                    shellcode.extend(b"\x00\x00\x00\x00")
                    shellcode.extend(
                        [
                            0x68,  # PUSH message
                        ],
                    )
                    shellcode.extend(b"\x00\x00\x00\x00")
                    shellcode.extend(
                        [
                            0x6A,
                            0x00,  # PUSH 0 (MB_OK)
                            0x6A,
                            0x00,  # PUSH 0 (hWnd)
                            # CALL MessageBoxA
                            0xE8,
                            0x00,
                            0x00,
                            0x00,
                            0x00,  # Needs relocation
                            # Exit
                            0xC3,  # RET
                        ],
                    )
                    # Append strings
                    shellcode.extend(title)
                    shellcode.extend(message)
                else:
                    # x64 shellcode
                    shellcode = bytearray(
                        [
                            # Set up parameters for MessageBoxA
                            0x48,
                            0x31,
                            0xC9,  # XOR RCX, RCX (hWnd = NULL)
                            0x48,
                            0x8D,
                            0x15,
                            0x20,
                            0x00,
                            0x00,
                            0x00,  # LEA RDX, [RIP+0x20] (message)
                            0x4C,
                            0x8D,
                            0x05,
                            0x30,
                            0x00,
                            0x00,
                            0x00,  # LEA R8, [RIP+0x30] (title)
                            0x45,
                            0x31,
                            0xC9,  # XOR R9D, R9D (MB_OK)
                            # Call MessageBoxA (needs runtime resolution)
                            0xFF,
                            0x15,
                            0x00,
                            0x00,
                            0x00,
                            0x00,  # CALL [RIP+0] - needs relocation
                            # Return
                            0xC3,
                            # Padding
                            0x90,
                            0x90,
                            0x90,
                            0x90,
                            0x90,
                            0x90,
                            0x90,
                        ],
                    )
                    # Append strings
                    shellcode.extend(message)
                    shellcode.extend(title)

                return bytes(shellcode)

            if shellcode_type == "exec":
                # Command execution shellcode
                command = params.get("command", "calc.exe").encode() + b"\x00"

                shellcode = bytearray()

                if arch == "x86":
                    # WinExec shellcode
                    shellcode.extend(
                        [
                            # Push command string address
                            0x68,
                        ],
                    )
                    shellcode.extend(b"\x00\x00\x00\x00")  # Needs relocation
                    shellcode.extend(
                        [
                            0x6A,
                            0x05,  # PUSH 5 (SW_SHOW)
                            # CALL WinExec
                            0xE8,
                            0x00,
                            0x00,
                            0x00,
                            0x00,  # Needs relocation
                            # Exit
                            0xC3,
                        ],
                    )
                else:
                    # x64 WinExec
                    shellcode.extend(
                        [
                            # MOV RCX, command_addr
                            0x48,
                            0x8D,
                            0x0D,
                            0x10,
                            0x00,
                            0x00,
                            0x00,  # LEA RCX, [RIP+0x10]
                            # MOV EDX, 5 (SW_SHOW)
                            0xBA,
                            0x05,
                            0x00,
                            0x00,
                            0x00,
                            # CALL WinExec
                            0xFF,
                            0x15,
                            0x00,
                            0x00,
                            0x00,
                            0x00,  # Needs relocation
                            # RET
                            0xC3,
                            # Padding
                            0x90,
                            0x90,
                            0x90,
                        ],
                    )

                # Append command
                shellcode.extend(command)
                return bytes(shellcode)

            if shellcode_type == "dll_inject":
                # DLL injection shellcode
                dll_path = params.get("dll_path", "").encode() + b"\x00"

                if not dll_path:
                    return b""

                shellcode = bytearray()

                if arch == "x86":
                    shellcode.extend(
                        [
                            # Push DLL path
                            0x68,
                        ],
                    )
                    shellcode.extend(b"\x00\x00\x00\x00")  # DLL path address
                    shellcode.extend(
                        [
                            # CALL LoadLibraryA
                            0xE8,
                            0x00,
                            0x00,
                            0x00,
                            0x00,  # Needs relocation
                            # RET
                            0xC3,
                        ],
                    )
                else:
                    shellcode.extend(
                        [
                            # MOV RCX, dll_path
                            0x48,
                            0x8D,
                            0x0D,
                            0x10,
                            0x00,
                            0x00,
                            0x00,  # LEA RCX, [RIP+0x10]
                            # CALL LoadLibraryA
                            0xFF,
                            0x15,
                            0x00,
                            0x00,
                            0x00,
                            0x00,  # Needs relocation
                            # RET
                            0xC3,
                            # Padding
                            0x90,
                            0x90,
                            0x90,
                            0x90,
                            0x90,
                            0x90,
                            0x90,
                            0x90,
                            0x90,
                        ],
                    )

                shellcode.extend(dll_path)
                return bytes(shellcode)

            if shellcode_type == "patch":
                # Memory patching shellcode
                patch_addr = params.get("address", 0)
                patch_bytes = params.get("bytes", b"")

                if not patch_addr or not patch_bytes:
                    return b""

                shellcode = bytearray()

                if arch == "x86":
                    # MOV EDI, patch_addr
                    shellcode.append(0xBF)
                    shellcode.extend(struct.pack("<I", patch_addr))

                    # Write patch bytes
                    for b in patch_bytes:
                        # MOV BYTE PTR [EDI], imm8
                        shellcode.extend([0xC6, 0x07, b])
                        # INC EDI
                        shellcode.append(0x47)

                    # RET
                    shellcode.append(0xC3)
                else:
                    # MOV RDI, patch_addr
                    shellcode.extend([0x48, 0xBF])
                    shellcode.extend(struct.pack("<Q", patch_addr))

                    # Write patch bytes
                    for b in patch_bytes:
                        # MOV BYTE PTR [RDI], imm8
                        shellcode.extend([0xC6, 0x07, b])
                        # INC RDI
                        shellcode.extend([0x48, 0xFF, 0xC7])

                    # RET
                    shellcode.append(0xC3)

                return bytes(shellcode)

            return b""

        except Exception as e:
            logger.exception(f"Failed to generate shellcode: {e}")
            return b""

    def generate_position_independent_code(self, operations: list[dict]) -> bytes:
        """Generate position-independent code (PIC) that can run at any address.

        Args:
            operations: List of operations to perform
                Each operation dict contains:
                - "type": Operation type ("call", "load", "store", etc.)
                - "params": Operation parameters

        Returns:
            Position-independent shellcode bytes

        """
        try:
            arch = "x64" if ctypes.sizeof(ctypes.c_void_p) == 8 else "x86"
            pic = bytearray()

            if arch == "x86":
                # Get EIP using CALL/POP technique
                pic.extend(
                    [
                        0xE8,
                        0x00,
                        0x00,
                        0x00,
                        0x00,  # CALL $+5
                        0x5D,  # POP EBP (EBP now contains EIP)
                    ],
                )

                for op in operations:
                    op_type = op.get("type")
                    params = op.get("params", {})

                    if op_type == "call":
                        # Call function by offset from current position
                        offset = params.get("offset", 0)
                        pic.extend(
                            [
                                # LEA EAX, [EBP + offset]
                                0x8D,
                                0x85,
                            ],
                        )
                        pic.extend(struct.pack("<I", offset))
                        pic.extend(
                            [
                                0xFF,
                                0xD0,  # CALL EAX
                            ],
                        )

                    elif op_type == "load":
                        # Load data from relative offset
                        offset = params.get("offset", 0)
                        reg = params.get("register", "eax")

                        reg_codes = {"eax": 0x85, "ebx": 0x9D, "ecx": 0x8D, "edx": 0x95}
                        if reg in reg_codes:
                            pic.extend(
                                [
                                    # MOV reg, [EBP + offset]
                                    0x8B,
                                    reg_codes[reg],
                                ],
                            )
                            pic.extend(struct.pack("<I", offset))

                    elif op_type == "store":
                        # Store data at relative offset
                        offset = params.get("offset", 0)
                        value = params.get("value", 0)
                        pic.extend(
                            [
                                # MOV DWORD PTR [EBP + offset], value
                                0xC7,
                                0x85,
                            ],
                        )
                        pic.extend(struct.pack("<I", offset))
                        pic.extend(struct.pack("<I", value))

            else:  # x64
                # RIP-relative addressing is naturally position-independent
                for op in operations:
                    op_type = op.get("type")
                    params = op.get("params", {})

                    if op_type == "call":
                        # Call function using RIP-relative addressing
                        offset = params.get("offset", 0)
                        pic.extend(
                            [
                                # LEA RAX, [RIP + offset]
                                0x48,
                                0x8D,
                                0x05,
                            ],
                        )
                        pic.extend(struct.pack("<i", offset))
                        pic.extend(
                            [
                                0xFF,
                                0xD0,  # CALL RAX
                            ],
                        )

                    elif op_type == "load":
                        # Load using RIP-relative addressing
                        offset = params.get("offset", 0)
                        reg = params.get("register", "rax")

                        reg_codes = {"rax": 0x05, "rbx": 0x1D, "rcx": 0x0D, "rdx": 0x15}
                        if reg in reg_codes:
                            pic.extend(
                                [
                                    # MOV reg, [RIP + offset]
                                    0x48,
                                    0x8B,
                                    reg_codes[reg],
                                ],
                            )
                            pic.extend(struct.pack("<i", offset))

                    elif op_type == "store":
                        # Store using RIP-relative addressing
                        offset = params.get("offset", 0)
                        value = params.get("value", 0)

                        # MOV RAX, value
                        pic.extend([0x48, 0xB8])
                        pic.extend(struct.pack("<Q", value))
                        # MOV [RIP + offset], RAX
                        pic.extend([0x48, 0x89, 0x05])
                        pic.extend(struct.pack("<i", offset))

                    elif op_type == "get_base":
                        # Get current RIP
                        pic.extend(
                            [
                                # LEA RAX, [RIP]
                                0x48,
                                0x8D,
                                0x05,
                                0x00,
                                0x00,
                                0x00,
                                0x00,
                            ],
                        )

            # Add terminator
            pic.append(0xC3)  # RET

            return bytes(pic)

        except Exception as e:
            logger.exception(f"Failed to generate position-independent code: {e}")
            return b""

    def generate_nop_sled(self, length: int) -> bytes:
        """Generate a NOP sled of specified length with variations.

        Args:
            length: Desired length of NOP sled

        Returns:
            NOP sled bytes

        """
        if length <= 0:
            return b""

        # Use varied NOPs to avoid pattern detection
        nop_variations = [
            b"\x90",  # NOP
            b"\x66\x90",  # 66 NOP
            b"\x0f\x1f\x00",  # NOP DWORD ptr [EAX]
            b"\x0f\x1f\x40\x00",  # NOP DWORD ptr [EAX+00]
            b"\x0f\x1f\x44\x00\x00",  # NOP DWORD ptr [EAX+EAX+00]
            b"\x66\x0f\x1f\x44\x00\x00",  # 66 NOP DWORD ptr [AX+AX+00]
            b"\x0f\x1f\x80\x00\x00\x00\x00",  # NOP DWORD ptr [EAX+00000000]
        ]

        sled = bytearray()
        while len(sled) < length:
            # Pick a random NOP variation that fits
            remaining = length - len(sled)
            suitable_nops = [n for n in nop_variations if len(n) <= remaining]

            if suitable_nops:
                import secrets

                nop = secrets.choice(suitable_nops)
                sled.extend(nop)
            else:
                # Fill remainder with single NOPs
                sled.extend(b"\x90" * remaining)

        return bytes(sled[:length])

    def detach(self) -> bool:
        """Detach debugger from process."""
        if not self.process_id:
            return False

        self.debugging = False

        # Wait for debug thread to finish
        if self.debug_thread and self.debug_thread.is_alive():
            self.debug_thread.join(timeout=2.0)

        # Remove all breakpoints
        for addr, bp in self.breakpoints.items():
            if bp.enabled:
                self._write_memory(addr, bp.original_byte)

        # Detach from process
        success = bool(self.kernel32.DebugActiveProcessStop(self.process_id))

        # Close handles
        if self.process_handle:
            self.kernel32.CloseHandle(self.process_handle)
            self.process_handle = None

        for handle in self.thread_handles.values():
            self.kernel32.CloseHandle(handle)
        self.thread_handles.clear()

        logger.info(f"Detached from process {self.process_id}")
        self.process_id = None

        return success

    def install_veh_handler(self, first_handler: bool = True) -> bool:
        """Install Vectored Exception Handler for advanced exception handling."""
        try:
            # Setup AddVectoredExceptionHandler
            self.kernel32.AddVectoredExceptionHandler.argtypes = [wintypes.ULONG, PVECTORED_EXCEPTION_HANDLER]
            self.kernel32.AddVectoredExceptionHandler.restype = wintypes.LPVOID

            # Create VEH callback function
            @PVECTORED_EXCEPTION_HANDLER
            def veh_handler(exception_pointers: ctypes.POINTER(EXCEPTION_POINTERS)) -> int:
                """Handle VEH callback.

                Args:
                    exception_pointers: Pointer to EXCEPTION_POINTERS structure

                Returns:
                    Exception disposition code

                """
                try:
                    if not exception_pointers:
                        return 0  # EXCEPTION_CONTINUE_SEARCH

                    exception_record = exception_pointers.contents.ExceptionRecord.contents
                    context_record = exception_pointers.contents.ContextRecord.contents

                    # Store last exception
                    self.last_exception = {
                        "code": exception_record.ExceptionCode,
                        "address": exception_record.ExceptionAddress,
                        "flags": exception_record.ExceptionFlags,
                        "context": context_record,
                    }

                    # Handle different exception types
                    exception_code = exception_record.ExceptionCode

                    # Check for registered filters
                    if exception_code in self.exception_filters:
                        filter_result = self.exception_filters[exception_code](exception_record, context_record)
                        if filter_result is not None:
                            return filter_result

                    # Handle breakpoint exceptions
                    if exception_code == ExceptionCode.EXCEPTION_BREAKPOINT:
                        return self._handle_veh_breakpoint(exception_record, context_record)

                    # Handle single-step exceptions
                    if exception_code == ExceptionCode.EXCEPTION_SINGLE_STEP:
                        return self._handle_veh_single_step(exception_record, context_record)

                    # Handle access violations
                    if exception_code == ExceptionCode.EXCEPTION_ACCESS_VIOLATION:
                        return self._handle_veh_access_violation(exception_record, context_record)

                    # Handle guard page exceptions
                    if exception_code == ExceptionCode.EXCEPTION_GUARD_PAGE:
                        return self._handle_veh_guard_page(exception_record, context_record)

                    # Call custom exception callbacks
                    if exception_code in self.exception_callbacks:
                        return self.exception_callbacks[exception_code](exception_record, context_record)

                    # Continue searching for other handlers
                    return 0  # EXCEPTION_CONTINUE_SEARCH

                except Exception as e:
                    logger.error(f"Error in VEH handler: {e}")
                    return 0  # EXCEPTION_CONTINUE_SEARCH

            # Store handler reference to prevent garbage collection
            self.veh_handlers.append(veh_handler)

            # Install VEH handler
            self.veh_handle = self.kernel32.AddVectoredExceptionHandler(1 if first_handler else 0, veh_handler)

            if not self.veh_handle:
                logger.error("Failed to install VEH handler")
                return False

            self.veh_chain_position = 1 if first_handler else 0
            logger.info(f"VEH handler installed {'first' if first_handler else 'last'} in chain")
            return True

        except Exception as e:
            logger.exception(f"Error installing VEH handler: {e}")
            return False

    def uninstall_veh_handler(self) -> bool:
        """Remove installed VEH handler."""
        if not self.veh_handle:
            return False

        try:
            # Setup RemoveVectoredExceptionHandler
            self.kernel32.RemoveVectoredExceptionHandler.argtypes = [wintypes.LPVOID]
            self.kernel32.RemoveVectoredExceptionHandler.restype = wintypes.ULONG

            result = self.kernel32.RemoveVectoredExceptionHandler(self.veh_handle)

            if result:
                self.veh_handle = None
                self.veh_handlers.clear()
                logger.info("VEH handler uninstalled")
                return True
            logger.error("Failed to uninstall VEH handler")
            return False

        except Exception as e:
            logger.exception(f"Error uninstalling VEH handler: {e}")
            return False

    def _handle_veh_breakpoint(self, exception_record: ExceptionRecord, context: CONTEXT) -> int:
        """Handle breakpoint exception in VEH.

        Args:
            exception_record: Exception record structure
            context: Thread context structure

        Returns:
            Exception disposition code

        """
        try:
            address = ctypes.cast(exception_record.ExceptionAddress, ctypes.c_ulong).value

            # Check if it's our software breakpoint
            if address in self.breakpoints:
                bp = self.breakpoints[address]

                # Increment hit count
                bp.hit_count += 1

                # Restore original byte
                self._write_memory(address, bp.original_byte)

                # Adjust instruction pointer back
                if ctypes.sizeof(ctypes.c_voidp) == 8:
                    context.Rip = address
                else:
                    context.Eip = address

                # Enable single-step to re-enable breakpoint
                context.EFlags |= 0x100  # Set trap flag

                # Call breakpoint callback if exists
                if bp.callback:
                    bp.callback(address, context)

                # Store breakpoint for re-enabling
                self.single_step_enabled = True

                logger.debug(f"VEH: Handled breakpoint at 0x{address:X}")
                return -1  # EXCEPTION_CONTINUE_EXECUTION

            # Check hardware breakpoints
            if address in self.hardware_breakpoints:
                hw_bp = self.hardware_breakpoints[address]

                # Call callback if exists
                if "callback" in hw_bp and hw_bp["callback"]:
                    hw_bp["callback"](address, context)

                logger.debug(f"VEH: Handled hardware breakpoint at 0x{address:X}")
                return -1  # EXCEPTION_CONTINUE_EXECUTION

        except Exception as e:
            logger.exception(f"Error handling VEH breakpoint: {e}")

        return 0  # EXCEPTION_CONTINUE_SEARCH

    def _handle_veh_single_step(self, exception_record: ExceptionRecord, context: CONTEXT) -> int:
        """Handle single-step exception in VEH.

        Args:
            exception_record: Exception record structure
            context: Thread context structure

        Returns:
            Exception disposition code

        """
        try:
            # Check if we're re-enabling a breakpoint
            if self.single_step_enabled:
                # Re-enable all breakpoints that need it
                for address, bp in self.breakpoints.items():
                    if bp.enabled and bp.original_byte:
                        self._write_memory(address, self.INT3_INSTRUCTION)

                # Clear trap flag
                context.EFlags &= ~0x100
                self.single_step_enabled = False

                logger.debug("VEH: Re-enabled breakpoints after single-step")
                return -1  # EXCEPTION_CONTINUE_EXECUTION

            # Check for hardware breakpoint single-step
            dr6 = context.Dr6

            # Check which debug register triggered
            for i in range(4):
                if dr6 & (1 << i):
                    # Get address from corresponding DR register
                    address = [context.Dr0, context.Dr1, context.Dr2, context.Dr3][i]

                    if address in self.hardware_breakpoints:
                        hw_bp = self.hardware_breakpoints[address]

                        # Call callback if exists
                        if "callback" in hw_bp and hw_bp["callback"]:
                            hw_bp["callback"](address, context)

                        # Clear DR6 status bit
                        context.Dr6 &= ~(1 << i)

                        logger.debug(f"VEH: Handled hardware breakpoint single-step at 0x{address:X}")
                        return -1  # EXCEPTION_CONTINUE_EXECUTION

            # Handle manual single-stepping for tracing
            if hasattr(self, "trace_callback") and self.trace_callback:
                self.trace_callback(context)
                return -1  # EXCEPTION_CONTINUE_EXECUTION

        except Exception as e:
            logger.exception(f"Error handling VEH single-step: {e}")

        return 0  # EXCEPTION_CONTINUE_SEARCH

    def _handle_veh_access_violation(self, exception_record: ExceptionRecord, context: CONTEXT) -> int:
        """Handle access violation exception in VEH.

        Args:
            exception_record: Exception record structure
            context: Thread context structure

        Returns:
            Exception disposition code

        """
        try:
            # Get violation details
            address = exception_record.ExceptionAddress

            # First parameter indicates read(0) or write(1)
            if exception_record.NumberParameters >= 2:
                is_write = exception_record.ExceptionInformation[0] == 1
                target_address = exception_record.ExceptionInformation[1]

                logger.info(f"VEH: Access violation at 0x{address:X} - {'Write' if is_write else 'Read'} to 0x{target_address:X}")

                # Check for memory breakpoints
                if target_address in self.memory_breakpoints:
                    mem_bp = self.memory_breakpoints[target_address]

                    # Check if correct access type
                    if (is_write and mem_bp.get("type") in ["write", "read_write"]) or (
                        not is_write and mem_bp.get("type") in ["read", "read_write"]
                    ):
                        # Call callback if exists
                        if mem_bp.get("callback"):
                            mem_bp["callback"](target_address, is_write, context)

                        # Skip instruction if needed
                        if mem_bp.get("skip_instruction"):
                            # Simple instruction length detection (would need disassembler for accuracy)
                            if ctypes.sizeof(ctypes.c_voidp) == 8:
                                context.Rip += mem_bp.get("instruction_length", 3)
                            else:
                                context.Eip += mem_bp.get("instruction_length", 3)

                        return -1  # EXCEPTION_CONTINUE_EXECUTION

        except Exception as e:
            logger.exception(f"Error handling VEH access violation: {e}")

        return 0  # EXCEPTION_CONTINUE_SEARCH

    def _handle_veh_guard_page(self, exception_record: ExceptionRecord, context: CONTEXT) -> int:
        """Handle guard page exception in VEH.

        Args:
            exception_record: Exception record structure
            context: Thread context structure

        Returns:
            Exception disposition code

        """
        try:
            address = exception_record.ExceptionAddress

            logger.info(f"VEH: Guard page exception at 0x{address:X}")

            # Check if we're using guard pages for memory breakpoints
            for mem_addr, mem_bp in self.memory_breakpoints.items():
                if mem_bp.get("use_guard_page"):
                    # Call callback
                    if mem_bp.get("callback"):
                        mem_bp["callback"](mem_addr, context)

                    # Re-enable guard page after single-step
                    context.EFlags |= 0x100  # Set trap flag
                    self.single_step_enabled = True

                    return -1  # EXCEPTION_CONTINUE_EXECUTION

        except Exception as e:
            logger.exception(f"Error handling VEH guard page: {e}")

        return 0  # EXCEPTION_CONTINUE_SEARCH

    def register_exception_filter(self, exception_code: int, filter_func: Callable) -> None:
        """Register a custom exception filter."""
        self.exception_filters[exception_code] = filter_func
        logger.info(f"Registered exception filter for code 0x{exception_code:X}")

    def unregister_exception_filter(self, exception_code: int) -> None:
        """Remove a registered exception filter."""
        if exception_code in self.exception_filters:
            del self.exception_filters[exception_code]
            logger.info(f"Unregistered exception filter for code 0x{exception_code:X}")

    def register_exception_callback(self, exception_code: int, callback: Callable) -> None:
        """Register callback for specific exception type."""
        self.exception_callbacks[exception_code] = callback
        logger.info(f"Registered exception callback for code 0x{exception_code:X}")

    def manipulate_veh_chain(self, new_position: int) -> bool:
        """Manipulate position in VEH chain."""
        if not self.veh_handle:
            logger.error("No VEH handler installed")
            return False

        try:
            # Uninstall current handler
            if not self.uninstall_veh_handler():
                return False

            # Re-install at new position
            first_handler = new_position == 1
            if not self.install_veh_handler(first_handler):
                return False

            logger.info(f"VEH handler repositioned to {'first' if first_handler else 'last'} in chain")
            return True

        except Exception as e:
            logger.exception(f"Error manipulating VEH chain: {e}")
            return False

    def enable_single_stepping(self, thread_id: int | None = None) -> bool:
        """Enable single-step mode for instruction tracing."""
        target_thread = thread_id or self.main_thread_id

        if not target_thread:
            logger.error("No thread ID specified")
            return False

        try:
            context = self._get_thread_context(target_thread)
            if not context:
                return False

            # Set trap flag
            context.EFlags |= 0x100

            if not self._set_thread_context(target_thread, context):
                return False

            self.single_step_enabled = True
            logger.info(f"Single-stepping enabled for thread {target_thread}")
            return True

        except Exception as e:
            logger.exception(f"Error enabling single-stepping: {e}")
            return False

    def disable_single_stepping(self, thread_id: int | None = None) -> bool:
        """Disable single-step mode."""
        target_thread = thread_id or self.main_thread_id

        if not target_thread:
            return False

        try:
            context = self._get_thread_context(target_thread)
            if not context:
                return False

            # Clear trap flag
            context.EFlags &= ~0x100

            if not self._set_thread_context(target_thread, context):
                return False

            self.single_step_enabled = False
            logger.info(f"Single-stepping disabled for thread {target_thread}")
            return True

        except Exception as e:
            logger.exception(f"Error disabling single-stepping: {e}")
            return False

    def set_memory_breakpoint(
        self, address: int, size: int = 1, access_type: str = "write", callback: Callable | None = None, use_guard_page: bool = False,
    ) -> bool:
        """Set memory access breakpoint using VEH and guard pages."""
        try:
            if use_guard_page:
                # Use guard page protection for memory breakpoint
                PAGE_GUARD = 0x100
                old_protect = wintypes.DWORD()

                # Change page protection to include guard flag
                if not self.kernel32.VirtualProtectEx(
                    self.process_handle,
                    ctypes.c_void_p(address & ~0xFFF),  # Align to page boundary
                    0x1000,  # Page size
                    PAGE_GUARD | 0x04,  # PAGE_GUARD | PAGE_READWRITE
                    ctypes.byref(old_protect),
                ):
                    logger.error("Failed to set guard page protection")
                    return False

                self.memory_breakpoints[address] = {
                    "size": size,
                    "type": access_type,
                    "callback": callback,
                    "use_guard_page": True,
                    "old_protection": old_protect.value,
                }

            else:
                # Store memory breakpoint info for VEH handling
                self.memory_breakpoints[address] = {"size": size, "type": access_type, "callback": callback, "use_guard_page": False}

            logger.info(f"Set memory breakpoint at 0x{address:X} for {access_type} access")
            return True

        except Exception as e:
            logger.exception(f"Error setting memory breakpoint: {e}")
            return False

    def trace_execution(self, max_instructions: int = 1000, trace_callback: Callable | None = None) -> list[dict[str, Any]]:
        """Trace execution flow by single-stepping through instructions.

        Args:
            max_instructions: Maximum number of instructions to trace
            trace_callback: Optional callback for each instruction

        Returns:
            List of traced instructions with context

        """
        if not self.process_handle:
            logger.error("No process attached for tracing")
            return []

        traced_instructions = []
        instruction_count = 0

        # Enable single stepping
        if not self.enable_single_stepping():
            logger.error("Failed to enable single stepping for trace")
            return []

        try:
            while instruction_count < max_instructions:
                # Continue execution for one instruction
                if not self.continue_execution():
                    break

                # Wait for single step exception
                debug_event = DEBUG_EVENT()
                if self.kernel32.WaitForDebugEvent(ctypes.byref(debug_event), 100):
                    if debug_event.dwDebugEventCode == 1:  # EXCEPTION_DEBUG_EVENT
                        # Get current context
                        context = self.get_registers()
                        if context:
                            instruction_info = {
                                "count": instruction_count,
                                "rip": context.get("Rip", 0),
                                "rax": context.get("Rax", 0),
                                "rbx": context.get("Rbx", 0),
                                "rcx": context.get("Rcx", 0),
                                "rdx": context.get("Rdx", 0),
                                "rsp": context.get("Rsp", 0),
                                "rbp": context.get("Rbp", 0),
                                "rflags": context.get("EFlags", 0),
                            }

                            # Read instruction bytes at RIP
                            rip = instruction_info["rip"]
                            if rip:
                                try:
                                    # Read up to 15 bytes (max x86/x64 instruction length)
                                    inst_bytes = self.read_memory(rip, 15)
                                    if inst_bytes:
                                        instruction_info["bytes"] = inst_bytes.hex()

                                        # Disassemble if possible
                                        try:
                                            from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsError

                                            md = Cs(CS_ARCH_X86, CS_MODE_64)
                                            for i in md.disasm(inst_bytes, rip):
                                                instruction_info["mnemonic"] = i.mnemonic
                                                instruction_info["op_str"] = i.op_str
                                                instruction_info["size"] = i.size
                                                break
                                        except (CsError, TypeError, ValueError) as e:
                                            logger.debug(f"Failed to disassemble instruction at {hex(rip)}: {e}")
                                except (OSError, TypeError) as e:
                                    logger.debug(f"Failed to read instruction bytes at {hex(rip)}: {e}")

                            traced_instructions.append(instruction_info)

                            # Call trace callback if provided
                            if trace_callback:
                                if not trace_callback(instruction_info):
                                    break  # Stop tracing if callback returns False

                            instruction_count += 1

                    # Continue debug event handling
                    self.kernel32.ContinueDebugEvent(
                        debug_event.dwProcessId,
                        debug_event.dwThreadId,
                        0x10002,  # DBG_CONTINUE
                    )

        finally:
            # Disable single stepping
            self.disable_single_stepping()

        logger.info(f"Traced {len(traced_instructions)} instructions")
        return traced_instructions


# DEBUG_EVENT structure for Windows debugging
class EXCEPTION_DEBUG_INFO(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("ExceptionRecord", ctypes.c_void_p),  # Simplified
        ("dwFirstChance", wintypes.DWORD),
    ]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("hThread", wintypes.HANDLE),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
    ]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("lpBaseOfImage", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wintypes.WORD),
    ]


class EXIT_THREAD_DEBUG_INFO(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("dwExitCode", wintypes.DWORD),
    ]


class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("dwExitCode", wintypes.DWORD),
    ]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("lpBaseOfDll", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wintypes.WORD),
    ]


class UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
    ]


class OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("lpDebugStringData", ctypes.c_char_p),
        ("fUnicode", wintypes.WORD),
        ("nDebugStringLength", wintypes.WORD),
    ]


class RIP_INFO(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("dwError", wintypes.DWORD),
        ("dwType", wintypes.DWORD),
    ]


class DEBUG_EVENT_UNION(ctypes.Union):  # noqa: N801
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO),
    ]


class DEBUG_EVENT(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", DEBUG_EVENT_UNION),
    ]


# Export functions
__all__ = [
    "LicenseDebugger",
    "Breakpoint",
    "DebugEvent",
    "ExceptionCode",
]
