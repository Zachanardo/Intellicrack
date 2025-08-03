"""Early Bird injection - inject before main thread starts

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
from typing import Any

from ...utils.logger import get_logger
from ...utils.system.windows_common import is_windows_available
from .base_patcher import BaseWindowsPatcher

logger = get_logger(__name__)

# Check Windows availability using common utility
AVAILABLE = is_windows_available()

class EarlyBirdInjector(BaseWindowsPatcher):
    """Early Bird injection - inject code before main thread executes"""

    def __init__(self):
        """Initialize the Early Bird injector with Windows platform validation and logging setup."""
        if not AVAILABLE:
            raise RuntimeError("Early Bird injection requires Windows")

        super().__init__()
        self.logger = get_logger(__name__)

    def get_required_libraries(self) -> list:
        """Get list of required Windows libraries for this patcher."""
        return ["kernel32"]

    def inject_early_bird(self, target_exe: str, dll_path: str,
                         command_line: str = None) -> bool:
        """Perform Early Bird injection

        Args:
            target_exe: Path to target executable
            dll_path: Path to DLL to inject
            command_line: Optional command line arguments

        Returns:
            True if successful, False otherwise

        """
        try:
            # Create process in suspended state
            process_info = self._create_suspended_process(target_exe, command_line)
            if not process_info:
                logger.error("Failed to create suspended process")
                return False

            try:
                # Allocate memory for DLL path
                dll_path_addr = self._allocate_and_write_dll_path(
                    process_info["process_handle"],
                    dll_path,
                )

                if not dll_path_addr:
                    logger.error("Failed to write DLL path")
                    return False

                # Get LoadLibraryA address
                load_library_addr = self._get_load_library_address()
                if not load_library_addr:
                    logger.error("Failed to get LoadLibraryA address")
                    return False

                # Queue APC to main thread
                if not self._queue_user_apc(
                    process_info["thread_handle"],
                    load_library_addr,
                    dll_path_addr,
                ):
                    logger.error("Failed to queue APC")
                    return False

                # Resume thread - APC will execute before main entry point
                self.kernel32.ResumeThread(process_info["thread_handle"])

                logger.info("Early Bird injection successful")
                return True

            finally:
                # Clean up handles
                from ...utils.system.windows_common import cleanup_process_handles
                cleanup_process_handles(self.kernel32, process_info, logger)

        except Exception as e:
            logger.error(f"Early Bird injection failed: {e}")
            return False

    def inject_early_bird_shellcode(self, target_exe: str, shellcode: bytes,
                                   command_line: str = None) -> bool:
        """Inject shellcode using Early Bird technique

        Args:
            target_exe: Path to target executable
            shellcode: Shellcode to inject
            command_line: Optional command line arguments

        Returns:
            True if successful, False otherwise

        """
        try:
            # Create process in suspended state
            process_info = self._create_suspended_process(target_exe, command_line)
            if not process_info:
                logger.error("Failed to create suspended process")
                return False

            try:
                # Allocate memory for shellcode
                shellcode_addr = self._allocate_and_write_shellcode(
                    process_info["process_handle"],
                    shellcode,
                )

                if not shellcode_addr:
                    logger.error("Failed to write shellcode")
                    return False

                # Queue APC to execute shellcode
                if not self._queue_user_apc(
                    process_info["thread_handle"],
                    shellcode_addr,
                    0,  # No parameter for shellcode
                ):
                    logger.error("Failed to queue APC")
                    return False

                # Resume thread - shellcode executes before main
                self.kernel32.ResumeThread(process_info["thread_handle"])

                logger.info("Early Bird shellcode injection successful")
                return True

            finally:
                # Clean up handles
                from ...utils.system.windows_common import cleanup_process_handles
                cleanup_process_handles(self.kernel32, process_info, logger)

        except Exception as e:
            logger.error(f"Early Bird shellcode injection failed: {e}")
            return False

    def inject_early_bird_with_context(self, target_exe: str, dll_path: str,
                                      modify_entry_point: bool = True) -> bool:
        """Advanced Early Bird with entry point modification

        Args:
            target_exe: Path to target executable
            dll_path: Path to DLL to inject
            modify_entry_point: Whether to modify entry point

        Returns:
            True if successful, False otherwise

        """
        try:
            # Create suspended process and handle result
            success, process_info, context = self.create_and_handle_suspended_process(target_exe, logger)
            if not success:
                return False

            try:

                # Allocate memory for injection stub
                stub_addr = self._create_injection_stub(
                    process_info["process_handle"],
                    dll_path,
                    context,
                )

                if not stub_addr:
                    logger.error("Failed to create injection stub")
                    return False

                if modify_entry_point:
                    # Modify entry point to our stub
                    self._set_entry_point(context, stub_addr)

                    # Set thread context
                    if not self._set_thread_context(
                        process_info["thread_handle"],
                        context,
                    ):
                        logger.error("Failed to set thread context")
                        return False
                else:
                    # Just queue APC
                    load_library_addr = self._get_load_library_address()
                    dll_path_addr = self._allocate_and_write_dll_path(
                        process_info["process_handle"],
                        dll_path,
                    )

                    if not self._queue_user_apc(
                        process_info["thread_handle"],
                        load_library_addr,
                        dll_path_addr,
                    ):
                        return False

                # Resume thread
                self.kernel32.ResumeThread(process_info["thread_handle"])

                logger.info("Advanced Early Bird injection successful")
                return True

            finally:
                # Clean up handles
                from ...utils.system.windows_common import cleanup_process_handles
                cleanup_process_handles(self.kernel32, process_info, logger)

        except Exception as e:
            logger.error(f"Advanced Early Bird injection failed: {e}")
            return False

    def _create_suspended_process(self, exe_path: str,
                                 command_line: str = None) -> dict | None:
        """Create a process in suspended state"""
        from ...utils.system.windows_structures import WindowsProcessStructures
        structures = WindowsProcessStructures()
        return structures.create_suspended_process(exe_path, command_line)

    def _allocate_and_write_dll_path(self, process_handle: int,
                                     dll_path: str) -> int:
        """Allocate memory and write DLL path"""
        try:
            dll_path_bytes = dll_path.encode("utf-8") + b"\x00"
            path_size = len(dll_path_bytes)

            # Allocate memory
            addr = self.kernel32.VirtualAllocEx(
                process_handle,
                None,
                path_size,
                self.MEM_COMMIT | self.MEM_RESERVE,
                self.PAGE_EXECUTE_READWRITE,
            )

            if not addr:
                return 0

            # Write DLL path
            bytes_written = ctypes.c_size_t(0)
            success = self.kernel32.WriteProcessMemory(
                process_handle,
                addr,
                dll_path_bytes,
                path_size,
                ctypes.byref(bytes_written),
            )

            if success and bytes_written.value == path_size:
                return addr
            return 0

        except Exception as e:
            logger.error(f"Failed to write DLL path: {e}")
            return 0

    def _allocate_and_write_shellcode(self, process_handle: int,
                                     shellcode: bytes) -> int:
        """Allocate memory and write shellcode"""
        try:
            # Allocate memory
            addr = self.kernel32.VirtualAllocEx(
                process_handle,
                None,
                len(shellcode),
                self.MEM_COMMIT | self.MEM_RESERVE,
                self.PAGE_EXECUTE_READWRITE,
            )

            if not addr:
                return 0

            # Write shellcode
            bytes_written = ctypes.c_size_t(0)
            success = self.kernel32.WriteProcessMemory(
                process_handle,
                addr,
                shellcode,
                len(shellcode),
                ctypes.byref(bytes_written),
            )

            if success and bytes_written.value == len(shellcode):
                return addr
            return 0

        except Exception as e:
            logger.error(f"Failed to write shellcode: {e}")
            return 0

    def _get_load_library_address(self) -> int:
        """Get address of LoadLibraryA"""
        try:
            kernel32_handle = self.kernel32.GetModuleHandleW("kernel32.dll")
            if not kernel32_handle:
                return 0

            addr = self.kernel32.GetProcAddress(kernel32_handle, b"LoadLibraryA")
            return addr

        except Exception as e:
            logger.error(f"Failed to get LoadLibraryA address: {e}")
            return 0

    def _queue_user_apc(self, thread_handle: int, function_addr: int,
                       parameter: int) -> bool:
        """Queue user APC to thread"""
        try:
            # QueueUserAPC
            success = self.kernel32.QueueUserAPC(
                function_addr,
                thread_handle,
                parameter,
            )

            if not success:
                error = ctypes.get_last_error()
                logger.error(f"QueueUserAPC failed: {error}")
                return False

            logger.info("Successfully queued APC")
            return True

        except Exception as e:
            logger.error(f"Failed to queue APC: {e}")
            return False

    def _get_thread_context(self, thread_handle: int) -> Any | None:
        """Get thread context"""
        from ...utils.system.windows_structures import WindowsContext
        context_helper = WindowsContext()
        return context_helper.get_thread_context(thread_handle)

    def _set_thread_context(self, thread_handle: int, context: Any) -> bool:
        """Set thread context"""
        from ...utils.system.windows_structures import WindowsContext
        context_helper = WindowsContext()
        return context_helper.set_thread_context(thread_handle, context)

    def _get_entry_point(self, context: Any) -> int:
        """Get entry point from context"""
        from ...utils.system.windows_structures import WindowsContext
        context_helper = WindowsContext()
        return context_helper.get_entry_point(context)

    def _set_entry_point(self, context: Any, new_entry: int):
        """Set entry point in context"""
        if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
            context.Rcx = new_entry
        else:  # 32-bit
            context.Eax = new_entry

    def _create_injection_stub(self, process_handle: int, dll_path: str,
                              context: Any) -> int:
        """Create injection stub that loads DLL then jumps to original entry"""
        try:
            # Get original entry point
            original_entry = self._get_entry_point(context)

            # Write DLL path
            dll_path_addr = self._allocate_and_write_dll_path(process_handle, dll_path)
            if not dll_path_addr:
                return 0

            # Get LoadLibraryA address
            load_library_addr = self._get_load_library_address()
            if not load_library_addr:
                return 0

            # Create stub
            if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
                stub = bytearray()

                # Save registers
                stub += b"\x50"                      # push rax
                stub += b"\x51"                      # push rcx
                stub += b"\x52"                      # push rdx
                stub += b"\x41\x50"                  # push r8
                stub += b"\x41\x51"                  # push r9

                # Load DLL
                stub += b"\x48\xB9" + struct.pack("<Q", dll_path_addr)     # mov rcx, dll_path_addr
                stub += b"\x48\xB8" + struct.pack("<Q", load_library_addr) # mov rax, LoadLibraryA
                stub += b"\xFF\xD0"                  # call rax

                # Restore registers
                stub += b"\x41\x59"                  # pop r9
                stub += b"\x41\x58"                  # pop r8
                stub += b"\x5A"                      # pop rdx
                stub += b"\x59"                      # pop rcx
                stub += b"\x58"                      # pop rax

                # Jump to original entry
                stub += b"\x48\xB8" + struct.pack("<Q", original_entry)    # mov rax, original_entry
                stub += b"\xFF\xE0"                  # jmp rax

            else:  # 32-bit
                stub = bytearray()

                # Save registers
                stub += b"\x60"                      # pushad

                # Load DLL
                stub += b"\x68" + struct.pack("<I", dll_path_addr)     # push dll_path_addr
                stub += b"\xB8" + struct.pack("<I", load_library_addr) # mov eax, LoadLibraryA
                stub += b"\xFF\xD0"                  # call eax

                # Restore registers
                stub += b"\x61"                      # popad

                # Jump to original entry
                stub += b"\xB8" + struct.pack("<I", original_entry)    # mov eax, original_entry
                stub += b"\xFF\xE0"                  # jmp eax

            # Allocate and write stub
            stub_addr = self._allocate_and_write_shellcode(process_handle, bytes(stub))
            return stub_addr

        except Exception as e:
            logger.error(f"Failed to create injection stub: {e}")
            return 0


def perform_early_bird_injection(target_exe: str, dll_path: str,
                               command_line: str = None) -> bool:
    """Convenience function to perform Early Bird injection

    Args:
        target_exe: Path to target executable
        dll_path: Path to DLL to inject
        command_line: Optional command line arguments

    Returns:
        True if successful, False otherwise

    """
    if not AVAILABLE:
        logger.error("Early Bird injection not available on this platform")
        return False

    try:
        injector = EarlyBirdInjector()
        return injector.inject_early_bird(target_exe, dll_path, command_line)
    except Exception as e:
        logger.error(f"Early Bird injection failed: {e}")
        return False
