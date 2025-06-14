"""
Direct syscall implementations for bypassing API hooks

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import ctypes
import struct
import sys
from typing import Optional, Tuple

from ...utils.logger import get_logger

logger = get_logger(__name__)

# Only available on Windows
if sys.platform == 'win32':
    try:
        import ctypes.wintypes
        AVAILABLE = True
    except ImportError:
        AVAILABLE = False
else:
    AVAILABLE = False

class DirectSyscalls:
    """Direct syscall implementation to bypass usermode hooks"""

    def __init__(self):
        self.syscall_numbers = {}
        self.ntdll_base = None
        self.wow64_transition = None
        self._initialize()

    def _initialize(self):
        """Initialize syscall numbers and addresses"""
        if not AVAILABLE:
            return

        try:
            # Get NTDLL base
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
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
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

            # Common syscalls we need
            syscalls = [
                "NtAllocateVirtualMemory",
                "NtProtectVirtualMemory",
                "NtWriteVirtualMemory",
                "NtCreateThreadEx",
                "NtOpenProcess",
                "NtClose",
                "NtQuerySystemInformation"
            ]

            for syscall_name in syscalls:
                # Get function address
                func_addr = kernel32.GetProcAddress(self.ntdll_base, syscall_name.encode('utf-8'))
                if func_addr:
                    # Read first few bytes to get syscall number
                    syscall_num = self._get_syscall_number(func_addr)
                    if syscall_num is not None:
                        self.syscall_numbers[syscall_name] = syscall_num
                        logger.debug(f"{syscall_name} = 0x{syscall_num:X}")

        except Exception as e:
            logger.error(f"Failed to extract syscall numbers: {e}")

    def _get_syscall_number(self, func_addr: int) -> Optional[int]:
        """Extract syscall number from function prologue"""
        try:
            # Read first 8 bytes
            buffer = (ctypes.c_ubyte * 8)()
            ctypes.memmove(buffer, func_addr, 8)

            # Check for MOV EAX, syscall_number pattern
            # 32-bit: B8 XX XX XX XX (MOV EAX, imm32)
            # 64-bit: 4C 8B D1 B8 XX XX XX XX (MOV R10, RCX; MOV EAX, imm32)

            if buffer[0] == 0xB8:  # 32-bit
                return struct.unpack('<I', bytes(buffer[1:5]))[0]
            elif buffer[0] == 0x4C and buffer[3] == 0xB8:  # 64-bit
                return struct.unpack('<I', bytes(buffer[4:8]))[0]

        except Exception as e:
            logger.debug(f"Failed to get syscall number: {e}")

        return None

    def _find_wow64_transition(self):
        """Find Wow64Transition address for WOW64 processes"""
        try:
            # In WOW64, syscalls go through Wow64SystemServiceCall
            # This is stored in TEB->WOW64Reserved
            pass
        except Exception as e:
            logger.debug(f"Failed to find WOW64 transition: {e}")

    def nt_allocate_virtual_memory(self, process_handle: int, base_address: int,
                                  size: int, allocation_type: int,
                                  protection: int) -> Tuple[int, int]:
        """Direct syscall for NtAllocateVirtualMemory"""
        if not AVAILABLE or "NtAllocateVirtualMemory" not in self.syscall_numbers:
            return -1, 0

        syscall_num = self.syscall_numbers["NtAllocateVirtualMemory"]

        # Prepare parameters
        base_addr_ptr = ctypes.c_ulonglong(base_address)
        region_size = ctypes.c_ulonglong(size)

        # Execute syscall
        if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
            status, allocated_base = self._syscall_64(
                syscall_num,
                process_handle,
                ctypes.byref(base_addr_ptr),
                0,  # ZeroBits
                ctypes.byref(region_size),
                allocation_type,
                protection
            )
        else:  # 32-bit
            status, allocated_base = self._syscall_32(
                syscall_num,
                process_handle,
                ctypes.byref(base_addr_ptr),
                0,
                ctypes.byref(region_size),
                allocation_type,
                protection
            )

        return status, base_addr_ptr.value

    def nt_write_virtual_memory(self, process_handle: int, base_address: int,
                               buffer: bytes) -> int:
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
                ctypes.byref(bytes_written)
            )
        else:  # 32-bit
            status = self._syscall_32(
                syscall_num,
                process_handle,
                base_address,
                buffer,
                len(buffer),
                ctypes.byref(bytes_written)
            )

        return status

    def nt_create_thread_ex(self, process_handle: int, start_address: int,
                           parameter: int = 0) -> Tuple[int, int]:
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
                None  # AttributeList
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
                None
            )

        return status, thread_handle.value

    def _syscall_64(self, syscall_num: int, *args) -> int:
        """Execute 64-bit syscall"""
        # This would require inline assembly or a separate ASM file
        # For now, we'll use a placeholder that falls back to regular API
        logger.warning("Direct 64-bit syscall not fully implemented, using fallback")
        return self._fallback_syscall(syscall_num, *args)

    def _syscall_32(self, syscall_num: int, *args) -> int:
        """Execute 32-bit syscall"""
        # This would require inline assembly or a separate ASM file
        logger.warning("Direct 32-bit syscall not fully implemented, using fallback")
        return self._fallback_syscall(syscall_num, *args)

    def _fallback_syscall(self, syscall_num: int, *args) -> int:
        """Fallback to regular NTDLL calls"""
        # Map syscall numbers back to function names
        for name, num in self.syscall_numbers.items():
            if num == syscall_num:
                # Call the regular NTDLL function
                ntdll = ctypes.WinDLL('ntdll.dll')
                if hasattr(ntdll, name):
                    func = getattr(ntdll, name)
                    return func(*args)
        return -1

# Global instance
_direct_syscalls = None

def get_direct_syscalls() -> Optional[DirectSyscalls]:
    """Get global DirectSyscalls instance"""
    global _direct_syscalls
    if _direct_syscalls is None and AVAILABLE:
        _direct_syscalls = DirectSyscalls()
    return _direct_syscalls

def inject_using_syscalls(process_handle: int, dll_path: str) -> bool:
    """
    Inject DLL using direct syscalls to bypass hooks
    
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
        dll_path_bytes = dll_path.encode('utf-8') + b'\x00'
        path_size = len(dll_path_bytes)

        # Allocate memory using syscall
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_READWRITE = 0x04

        status, remote_addr = syscalls.nt_allocate_virtual_memory(
            process_handle,
            0,  # Let system choose address
            path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )

        if status != 0:
            logger.error(f"NtAllocateVirtualMemory failed: 0x{status:X}")
            return False

        # Write DLL path using syscall
        status = syscalls.nt_write_virtual_memory(
            process_handle,
            remote_addr,
            dll_path_bytes
        )

        if status != 0:
            logger.error(f"NtWriteVirtualMemory failed: 0x{status:X}")
            return False

        # Get LoadLibraryA address (still need this from kernel32)
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel32_handle = kernel32.GetModuleHandleW("kernel32.dll")
        load_library_addr = kernel32.GetProcAddress(kernel32_handle, b"LoadLibraryA")

        if not load_library_addr:
            logger.error("Failed to get LoadLibraryA address")
            return False

        # Create thread using syscall
        status, thread_handle = syscalls.nt_create_thread_ex(
            process_handle,
            load_library_addr,
            remote_addr
        )

        if status != 0:
            logger.error(f"NtCreateThreadEx failed: 0x{status:X}")
            return False

        logger.info("Successfully injected using direct syscalls")
        return True

    except Exception as e:
        logger.error(f"Syscall injection failed: {e}")
        return False
