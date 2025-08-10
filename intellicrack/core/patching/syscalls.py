"""Direct syscall implementations for bypassing API hooks

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import ctypes
import struct
import sys

from ...utils.logger import get_logger

logger = get_logger(__name__)

# Only available on Windows
if sys.platform == "win32":
    try:
        import ctypes.wintypes

        AVAILABLE = True
    except ImportError as e:
        logger.error("Import error in syscalls: %s", e)
        AVAILABLE = False
else:
    AVAILABLE = False

# Windows memory constants
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
MEM_RELEASE = 0x8000

# Thread information constants
THREAD_BASIC_INFORMATION = 0


# Windows structures
if sys.platform == "win32" and AVAILABLE:

    class THREAD_BASIC_INFORMATION_32(ctypes.Structure):
        """Thread basic information structure for 32-bit processes."""

        _fields_ = [
            ("ExitStatus", ctypes.c_ulong),
            ("TebBaseAddress", ctypes.c_void_p),
            ("ClientId", ctypes.c_ulonglong),
            ("AffinityMask", ctypes.c_ulong),
            ("Priority", ctypes.c_long),
            ("BasePriority", ctypes.c_long),
        ]
else:
    THREAD_BASIC_INFORMATION_32 = None


class DirectSyscalls:
    """Direct syscall implementation to bypass usermode hooks"""

    def __init__(self):
        """Initialize the syscall manager with syscall number mapping and NTDLL base detection."""
        self.syscall_numbers = {}
        self.ntdll_base = None
        self.logger = get_logger(__name__)
        self._load_syscall_numbers()

    def _initialize(self):
        """Initialize syscall numbers and addresses"""
        if not AVAILABLE:
            return

        try:
            # Get NTDLL base
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self.ntdll_base = kernel32.GetModuleHandleW("ntdll.dll")

            # Detect if we're in WOW64
            is_wow64 = ctypes.c_bool(False)
            kernel32.IsWow64Process(kernel32.GetCurrentProcess(), ctypes.byref(is_wow64))
            self.is_wow64 = is_wow64.value

            # Extract syscall numbers
            self._extract_syscall_numbers()

            # Find wow64 transition if needed
            if self.is_wow64:
                self._find_wow64_transition()

        except Exception as e:
            logger.error(f"Failed to initialize direct syscalls: {e}")

    def _extract_syscall_numbers(self):
        """Extract syscall numbers from NTDLL exports"""
        if not self.ntdll_base:
            return

        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            # Common syscalls we need
            syscalls = [
                "NtAllocateVirtualMemory",
                "NtProtectVirtualMemory",
                "NtWriteVirtualMemory",
                "NtCreateThreadEx",
                "NtOpenProcess",
                "NtClose",
                "NtQuerySystemInformation",
            ]

            for syscall_name in syscalls:
                # Get function address
                func_addr = kernel32.GetProcAddress(self.ntdll_base, syscall_name.encode("utf-8"))
                if func_addr:
                    # Read first few bytes to get syscall number
                    syscall_num = self._get_syscall_number(func_addr)
                    if syscall_num is not None:
                        self.syscall_numbers[syscall_name] = syscall_num
                        logger.debug(f"{syscall_name} = 0x{syscall_num:X}")

        except Exception as e:
            logger.error(f"Failed to extract syscall numbers: {e}")

    def _get_syscall_number(self, func_addr: int) -> int | None:
        """Extract syscall number from function prologue"""
        try:
            # Read first 8 bytes
            buffer = (ctypes.c_ubyte * 8)()
            ctypes.memmove(buffer, func_addr, 8)

            # Check for MOV EAX, syscall_number pattern
            # 32-bit: B8 XX XX XX XX (MOV EAX, imm32)
            # 64-bit: 4C 8B D1 B8 XX XX XX XX (MOV R10, RCX; MOV EAX, imm32)

            if buffer[0] == 0xB8:  # 32-bit
                return struct.unpack("<I", bytes(buffer[1:5]))[0]
            if buffer[0] == 0x4C and buffer[3] == 0xB8:  # 64-bit
                return struct.unpack("<I", bytes(buffer[4:8]))[0]

        except Exception as e:
            logger.debug(f"Failed to get syscall number: {e}")

        return None

    def _find_wow64_transition(self):
        """Find Wow64Transition address for WOW64 processes"""
        try:
            # In WOW64, syscalls go through Wow64SystemServiceCall
            # This is stored in TEB->WOW64Reserved at offset 0xC0

            # Get TEB address through NtCurrentTeb()
            if sys.platform != "win32":
                return

            # Define TEB structure offsets
            if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
                TEB_WOW64_RESERVED_OFFSET = 0x1488
            else:  # 32-bit
                TEB_WOW64_RESERVED_OFFSET = 0xC0

            # Get current TEB
            ntdll = ctypes.WinDLL("ntdll.dll")

            # Get TEB through GS/FS segment
            if ctypes.sizeof(ctypes.c_void_p) == 8:
                # 64-bit: TEB is at GS:[0x30]
                teb_addr = ctypes.c_void_p()
                asm_code = bytes(
                    [
                        0x65,
                        0x48,
                        0x8B,
                        0x04,
                        0x25,
                        0x30,
                        0x00,
                        0x00,
                        0x00,  # mov rax, gs:[0x30]
                        0xC3,  # ret
                    ]
                )

                # Allocate executable memory for shellcode
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

                shellcode_addr = kernel32.VirtualAlloc(
                    None,
                    len(asm_code),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )

                if shellcode_addr:
                    ctypes.memmove(shellcode_addr, asm_code, len(asm_code))
                    get_teb = ctypes.CFUNCTYPE(ctypes.c_void_p)(shellcode_addr)
                    teb_addr = get_teb()
                    kernel32.VirtualFree(shellcode_addr, 0, MEM_RELEASE)

                    # Read WOW64Reserved from TEB
                    wow64_reserved = ctypes.c_void_p()
                    ctypes.memmove(
                        ctypes.byref(wow64_reserved),
                        teb_addr.value + TEB_WOW64_RESERVED_OFFSET,
                        ctypes.sizeof(ctypes.c_void_p),
                    )

                    if wow64_reserved.value:
                        # Read the actual transition address (first QWORD in WOW64Reserved)
                        transition_addr = ctypes.c_void_p()
                        ctypes.memmove(
                            ctypes.byref(transition_addr),
                            wow64_reserved.value,
                            ctypes.sizeof(ctypes.c_void_p),
                        )

                        self.wow64_transition = transition_addr.value
                        logger.debug(f"Found WOW64 transition at 0x{self.wow64_transition:X}")
            else:
                # 32-bit: TEB is at FS:[0x18]
                # For 32-bit WOW64 processes, we can read it directly

                # Use NtQueryInformationThread to get TEB
                tbi = THREAD_BASIC_INFORMATION_32()
                status = ntdll.NtQueryInformationThread(
                    kernel32.GetCurrentThread(),
                    THREAD_BASIC_INFORMATION,
                    ctypes.byref(tbi),
                    ctypes.sizeof(tbi),
                    None,
                )

                if status == 0:  # STATUS_SUCCESS
                    # Store TEB pointer for potential future use
                    teb_ptr = tbi.TebBaseAddress

                    # Read WOW64Reserved from TEB
                    wow64_reserved = ctypes.c_void_p()
                    kernel32.ReadProcessMemory(
                        kernel32.GetCurrentProcess(),
                        teb_ptr + TEB_WOW64_RESERVED_OFFSET,
                        ctypes.byref(wow64_reserved),
                        ctypes.sizeof(ctypes.c_void_p),
                        None,
                    )

                    if wow64_reserved.value:
                        self.wow64_transition = wow64_reserved.value
                        logger.debug(f"Found WOW64 transition at 0x{self.wow64_transition:X}")

        except Exception as e:
            logger.debug(f"Failed to find WOW64 transition: {e}")

    def nt_allocate_virtual_memory(
        self,
        process_handle: int,
        base_address: int,
        size: int,
        allocation_type: int,
        protection: int,
    ) -> tuple[int, int]:
        """Direct syscall for NtAllocateVirtualMemory"""
        if not AVAILABLE or "NtAllocateVirtualMemory" not in self.syscall_numbers:
            return -1, 0

        syscall_num = self.syscall_numbers["NtAllocateVirtualMemory"]

        # Prepare parameters
        base_addr_ptr = ctypes.c_ulonglong(base_address)
        region_size = ctypes.c_ulonglong(size)

        # Execute syscall
        if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
            status = self._syscall_64(
                syscall_num,
                process_handle,
                ctypes.byref(base_addr_ptr),
                0,  # ZeroBits
                ctypes.byref(region_size),
                allocation_type,
                protection,
            )
        else:  # 32-bit
            status = self._syscall_32(
                syscall_num,
                process_handle,
                ctypes.byref(base_addr_ptr),
                0,
                ctypes.byref(region_size),
                allocation_type,
                protection,
            )

        # Return status and the allocated base address
        allocated_base = base_addr_ptr.value
        return status, allocated_base

    def nt_write_virtual_memory(self, process_handle: int, base_address: int, buffer: bytes) -> int:
        """Direct syscall for NtWriteVirtualMemory"""
        if not AVAILABLE or "NtWriteVirtualMemory" not in self.syscall_numbers:
            return -1

        syscall_num = self.syscall_numbers["NtWriteVirtualMemory"]
        bytes_written = ctypes.c_size_t(0)

        # Execute syscall
        if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
            status = self._syscall_64(
                syscall_num,
                process_handle,
                base_address,
                buffer,
                len(buffer),
                ctypes.byref(bytes_written),
            )
        else:  # 32-bit
            status = self._syscall_32(
                syscall_num,
                process_handle,
                base_address,
                buffer,
                len(buffer),
                ctypes.byref(bytes_written),
            )

        return status

    def nt_create_thread_ex(
        self, process_handle: int, start_address: int, parameter: int = 0
    ) -> tuple[int, int]:
        """Direct syscall for NtCreateThreadEx"""
        if not AVAILABLE or "NtCreateThreadEx" not in self.syscall_numbers:
            return -1, 0

        syscall_num = self.syscall_numbers["NtCreateThreadEx"]
        thread_handle = ctypes.c_void_p(0)

        # THREAD_ALL_ACCESS
        desired_access = 0x1FFFFF

        # Execute syscall (simplified parameters)
        if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
            status = self._syscall_64(
                syscall_num,
                ctypes.byref(thread_handle),
                desired_access,
                None,  # ObjectAttributes
                process_handle,
                start_address,
                parameter,
                0,  # CreateFlags
                0,  # ZeroBits
                0,  # StackSize
                0,  # MaximumStackSize
                None,  # AttributeList
            )
        else:  # 32-bit
            status = self._syscall_32(
                syscall_num,
                ctypes.byref(thread_handle),
                desired_access,
                None,
                process_handle,
                start_address,
                parameter,
                0,
                0,
                0,
                0,
                None,
            )

        return status, thread_handle.value

    def _syscall_64(self, syscall_num: int, *args) -> int:
        """Execute 64-bit syscall"""
        try:
            if not AVAILABLE or sys.platform != "win32":
                return self._fallback_syscall(syscall_num, *args)

            # Windows x64 syscall convention:
            # RAX = syscall number
            # RCX = 1st argument
            # RDX = 2nd argument
            # R8  = 3rd argument
            # R9  = 4th argument
            # Stack = 5th+ arguments
            # Then execute: syscall instruction

            # Build shellcode for syscall
            shellcode = bytearray()

            # mov rax, syscall_num
            shellcode.extend(b"\x48\xb8")  # mov rax, imm64
            shellcode.extend(struct.pack("<Q", syscall_num))

            # Setup first 4 arguments if present
            if len(args) >= 1 and args[0] is not None:
                # mov rcx, arg1
                if isinstance(args[0], int):
                    shellcode.extend(b"\x48\xb9")  # mov rcx, imm64
                    shellcode.extend(struct.pack("<Q", args[0]))

            if len(args) >= 2 and args[1] is not None:
                # mov rdx, arg2
                if isinstance(args[1], int):
                    shellcode.extend(b"\x48\xba")  # mov rdx, imm64
                    shellcode.extend(struct.pack("<Q", args[1]))

            if len(args) >= 3 and args[2] is not None:
                # mov r8, arg3
                if isinstance(args[2], int):
                    shellcode.extend(b"\x49\xb8")  # mov r8, imm64
                    shellcode.extend(struct.pack("<Q", args[2]))

            if len(args) >= 4 and args[3] is not None:
                # mov r9, arg4
                if isinstance(args[3], int):
                    shellcode.extend(b"\x49\xb9")  # mov r9, imm64
                    shellcode.extend(struct.pack("<Q", args[3]))

            # For 5+ arguments, we'd need to set up stack, but for now we'll handle up to 4
            if len(args) > 4:
                logger.warning("Syscall with more than 4 arguments, using fallback")
                return self._fallback_syscall(syscall_num, *args)

            # Add syscall instruction
            shellcode.extend(b"\x0f\x05")  # syscall

            # Add return
            shellcode.extend(b"\xc3")  # ret

            # Allocate executable memory
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            code_addr = kernel32.VirtualAlloc(
                None,
                len(shellcode),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )

            if not code_addr:
                logger.error("Failed to allocate memory for syscall")
                return self._fallback_syscall(syscall_num, *args)

            try:
                # Copy shellcode to allocated memory
                ctypes.memmove(code_addr, bytes(shellcode), len(shellcode))

                # Create function from shellcode
                syscall_func = ctypes.CFUNCTYPE(ctypes.c_long)(code_addr)

                # Execute syscall
                result = syscall_func()

                return result

            finally:
                # Free allocated memory
                kernel32.VirtualFree(code_addr, 0, MEM_RELEASE)

        except Exception as e:
            logger.debug(f"Failed to execute 64-bit syscall: {e}")
            return self._fallback_syscall(syscall_num, *args)

    def _syscall_32(self, syscall_num: int, *args) -> int:
        """Execute 32-bit syscall"""
        try:
            if not AVAILABLE or sys.platform != "win32":
                return self._fallback_syscall(syscall_num, *args)

            # Windows x86 syscall convention:
            # EAX = syscall number
            # EDX = pointer to arguments on stack
            # Then execute: sysenter or int 0x2e (for older systems)
            # OR for WOW64: call to Wow64SystemServiceCall

            # Build shellcode
            shellcode = bytearray()

            # For WOW64 processes, use the transition
            if self.is_wow64 and self.wow64_transition:
                # Build argument array on stack
                # push arguments in reverse order
                for i in range(len(args) - 1, -1, -1):
                    if isinstance(args[i], int):
                        # push arg
                        shellcode.append(0x68)  # push imm32
                        shellcode.extend(struct.pack("<I", args[i] & 0xFFFFFFFF))

                # mov eax, syscall_num
                shellcode.append(0xB8)  # mov eax, imm32
                shellcode.extend(struct.pack("<I", syscall_num))

                # call [wow64_transition]
                shellcode.extend(b"\xff\x15")  # call dword ptr [addr]
                shellcode.extend(struct.pack("<I", self.wow64_transition))

                # Clean up stack (stdcall convention)
                if len(args) > 0:
                    # add esp, num_args * 4
                    shellcode.extend(b"\x83\xc4")  # add esp, imm8
                    shellcode.append(len(args) * 4)

            else:
                # Native 32-bit syscall (non-WOW64)
                # Set up arguments on stack
                for i in range(len(args) - 1, -1, -1):
                    if isinstance(args[i], int):
                        # push arg
                        shellcode.append(0x68)  # push imm32
                        shellcode.extend(struct.pack("<I", args[i] & 0xFFFFFFFF))

                # mov eax, syscall_num
                shellcode.append(0xB8)  # mov eax, imm32
                shellcode.extend(struct.pack("<I", syscall_num))

                # Get stack pointer for arguments
                # mov edx, esp
                shellcode.extend(b"\x89\xe2")  # mov edx, esp

                # Perform syscall using int 0x2e (works on most Windows versions)
                shellcode.extend(b"\xcd\x2e")  # int 0x2e

                # Clean up stack
                if len(args) > 0:
                    # add esp, num_args * 4
                    shellcode.extend(b"\x83\xc4")  # add esp, imm8
                    shellcode.append(len(args) * 4)

            # Add return
            shellcode.append(0xC3)  # ret

            # Allocate executable memory
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            code_addr = kernel32.VirtualAlloc(
                None,
                len(shellcode),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )

            if not code_addr:
                logger.error("Failed to allocate memory for syscall")
                return self._fallback_syscall(syscall_num, *args)

            try:
                # Copy shellcode to allocated memory
                ctypes.memmove(code_addr, bytes(shellcode), len(shellcode))

                # Create function from shellcode
                syscall_func = ctypes.CFUNCTYPE(ctypes.c_long)(code_addr)

                # Execute syscall
                result = syscall_func()

                return result

            finally:
                # Free allocated memory
                kernel32.VirtualFree(code_addr, 0, MEM_RELEASE)

        except Exception as e:
            logger.debug(f"Failed to execute 32-bit syscall: {e}")
            return self._fallback_syscall(syscall_num, *args)

    def _fallback_syscall(self, syscall_num: int, *args) -> int:
        """Fallback to regular NTDLL calls"""
        # Map syscall numbers back to function names
        for name, num in self.syscall_numbers.items():
            if num == syscall_num:
                # Call the regular NTDLL function
                ntdll = ctypes.WinDLL("ntdll.dll")
                if hasattr(ntdll, name):
                    func = getattr(ntdll, name)
                    return func(*args)
        return -1


# Global instance
_direct_syscalls = None


def get_direct_syscalls() -> DirectSyscalls | None:
    """Get global DirectSyscalls instance"""
    global _direct_syscalls
    if _direct_syscalls is None and AVAILABLE:
        _direct_syscalls = DirectSyscalls()
    return _direct_syscalls


def inject_using_syscalls(process_handle: int, dll_path: str) -> bool:
    """Inject DLL using direct syscalls to bypass hooks

    Args:
        process_handle: Handle to target process
        dll_path: Path to DLL to inject

    Returns:
        True if successful, False otherwise

    """
    syscalls = get_direct_syscalls()
    if not syscalls:
        logger.error("Direct syscalls not available")
        return False

    try:
        # Prepare DLL path
        dll_path_bytes = dll_path.encode("utf-8") + b"\x00"
        path_size = len(dll_path_bytes)

        # Allocate memory using syscall
        status, remote_addr = syscalls.nt_allocate_virtual_memory(
            process_handle,
            0,  # Let system choose address
            path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )

        if status != 0:
            logger.error(f"NtAllocateVirtualMemory failed: 0x{status:X}")
            return False

        # Write DLL path using syscall
        status = syscalls.nt_write_virtual_memory(
            process_handle,
            remote_addr,
            dll_path_bytes,
        )

        if status != 0:
            logger.error(f"NtWriteVirtualMemory failed: 0x{status:X}")
            return False

        # Get LoadLibraryA address (still need this from kernel32)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32_handle = kernel32.GetModuleHandleW("kernel32.dll")
        load_library_addr = kernel32.GetProcAddress(kernel32_handle, b"LoadLibraryA")

        if not load_library_addr:
            logger.error("Failed to get LoadLibraryA address")
            return False

        # Create thread using syscall
        status, thread_handle = syscalls.nt_create_thread_ex(
            process_handle,
            load_library_addr,
            remote_addr,
        )

        if status != 0:
            logger.error(f"NtCreateThreadEx failed: 0x{status:X}")
            return False

        # Wait for thread completion and clean up
        if thread_handle:
            kernel32.WaitForSingleObject(thread_handle, 5000)  # Wait up to 5 seconds
            kernel32.CloseHandle(thread_handle)

        logger.info("Successfully injected using direct syscalls")
        return True

    except Exception as e:
        logger.error(f"Syscall injection failed: {e}")
        return False
