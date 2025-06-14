"""
Early Bird injection - inject before main thread starts

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
import sys
import struct
from typing import Optional, Tuple, Any

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

class EarlyBirdInjector:
    """Early Bird injection - inject code before main thread executes"""
    
    def __init__(self):
        if not AVAILABLE:
            raise RuntimeError("Early Bird injection requires Windows")
            
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.ntdll = ctypes.WinDLL('ntdll.dll')
        
        # Process creation flags
        self.CREATE_SUSPENDED = 0x00000004
        self.CREATE_NO_WINDOW = 0x08000000
        
        # Memory constants
        self.MEM_COMMIT = 0x1000
        self.MEM_RESERVE = 0x2000
        self.PAGE_EXECUTE_READWRITE = 0x40
        
        # Thread constants
        self.THREAD_SET_CONTEXT = 0x0010
        self.THREAD_GET_CONTEXT = 0x0008
        
    def inject_early_bird(self, target_exe: str, dll_path: str, 
                         command_line: str = None) -> bool:
        """
        Perform Early Bird injection
        
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
                    process_info['process_handle'],
                    dll_path
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
                    process_info['thread_handle'],
                    load_library_addr,
                    dll_path_addr
                ):
                    logger.error("Failed to queue APC")
                    return False
                    
                # Resume thread - APC will execute before main entry point
                self.kernel32.ResumeThread(process_info['thread_handle'])
                
                logger.info("Early Bird injection successful")
                return True
                
            finally:
                # Clean up handles
                self.kernel32.CloseHandle(process_info['thread_handle'])
                self.kernel32.CloseHandle(process_info['process_handle'])
                
        except Exception as e:
            logger.error(f"Early Bird injection failed: {e}")
            return False
            
    def inject_early_bird_shellcode(self, target_exe: str, shellcode: bytes,
                                   command_line: str = None) -> bool:
        """
        Inject shellcode using Early Bird technique
        
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
                    process_info['process_handle'],
                    shellcode
                )
                
                if not shellcode_addr:
                    logger.error("Failed to write shellcode")
                    return False
                    
                # Queue APC to execute shellcode
                if not self._queue_user_apc(
                    process_info['thread_handle'],
                    shellcode_addr,
                    0  # No parameter for shellcode
                ):
                    logger.error("Failed to queue APC")
                    return False
                    
                # Resume thread - shellcode executes before main
                self.kernel32.ResumeThread(process_info['thread_handle'])
                
                logger.info("Early Bird shellcode injection successful")
                return True
                
            finally:
                # Clean up handles
                self.kernel32.CloseHandle(process_info['thread_handle'])
                self.kernel32.CloseHandle(process_info['process_handle'])
                
        except Exception as e:
            logger.error(f"Early Bird shellcode injection failed: {e}")
            return False
            
    def inject_early_bird_with_context(self, target_exe: str, dll_path: str,
                                      modify_entry_point: bool = True) -> bool:
        """
        Advanced Early Bird with entry point modification
        
        Args:
            target_exe: Path to target executable
            dll_path: Path to DLL to inject
            modify_entry_point: Whether to modify entry point
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create process in suspended state
            process_info = self._create_suspended_process(target_exe)
            if not process_info:
                return False
                
            try:
                # Get thread context
                context = self._get_thread_context(process_info['thread_handle'])
                if not context:
                    logger.error("Failed to get thread context")
                    return False
                    
                # Allocate memory for injection stub
                stub_addr = self._create_injection_stub(
                    process_info['process_handle'],
                    dll_path,
                    context
                )
                
                if not stub_addr:
                    logger.error("Failed to create injection stub")
                    return False
                    
                if modify_entry_point:
                    # Modify entry point to our stub
                    original_entry = self._get_entry_point(context)
                    self._set_entry_point(context, stub_addr)
                    
                    # Set thread context
                    if not self._set_thread_context(
                        process_info['thread_handle'],
                        context
                    ):
                        logger.error("Failed to set thread context")
                        return False
                else:
                    # Just queue APC
                    load_library_addr = self._get_load_library_address()
                    dll_path_addr = self._allocate_and_write_dll_path(
                        process_info['process_handle'],
                        dll_path
                    )
                    
                    if not self._queue_user_apc(
                        process_info['thread_handle'],
                        load_library_addr,
                        dll_path_addr
                    ):
                        return False
                        
                # Resume thread
                self.kernel32.ResumeThread(process_info['thread_handle'])
                
                logger.info("Advanced Early Bird injection successful")
                return True
                
            finally:
                # Clean up handles
                self.kernel32.CloseHandle(process_info['thread_handle'])
                self.kernel32.CloseHandle(process_info['process_handle'])
                
        except Exception as e:
            logger.error(f"Advanced Early Bird injection failed: {e}")
            return False
            
    def _create_suspended_process(self, exe_path: str, 
                                 command_line: str = None) -> Optional[dict]:
        """Create a process in suspended state"""
        try:
            # STARTUPINFO structure
            class STARTUPINFO(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.wintypes.DWORD),
                    ("lpReserved", ctypes.wintypes.LPWSTR),
                    ("lpDesktop", ctypes.wintypes.LPWSTR),
                    ("lpTitle", ctypes.wintypes.LPWSTR),
                    ("dwX", ctypes.wintypes.DWORD),
                    ("dwY", ctypes.wintypes.DWORD),
                    ("dwXSize", ctypes.wintypes.DWORD),
                    ("dwYSize", ctypes.wintypes.DWORD),
                    ("dwXCountChars", ctypes.wintypes.DWORD),
                    ("dwYCountChars", ctypes.wintypes.DWORD),
                    ("dwFillAttribute", ctypes.wintypes.DWORD),
                    ("dwFlags", ctypes.wintypes.DWORD),
                    ("wShowWindow", ctypes.wintypes.WORD),
                    ("cbReserved2", ctypes.wintypes.WORD),
                    ("lpReserved2", ctypes.wintypes.LPBYTE),
                    ("hStdInput", ctypes.wintypes.HANDLE),
                    ("hStdOutput", ctypes.wintypes.HANDLE),
                    ("hStdError", ctypes.wintypes.HANDLE)
                ]
                
            # PROCESS_INFORMATION structure
            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("hProcess", ctypes.wintypes.HANDLE),
                    ("hThread", ctypes.wintypes.HANDLE),
                    ("dwProcessId", ctypes.wintypes.DWORD),
                    ("dwThreadId", ctypes.wintypes.DWORD)
                ]
                
            startup_info = STARTUPINFO()
            startup_info.cb = ctypes.sizeof(STARTUPINFO)
            process_info = PROCESS_INFORMATION()
            
            # Prepare command line
            if command_line:
                cmd_line = f'"{exe_path}" {command_line}'
            else:
                cmd_line = None
                
            # Create process
            success = self.kernel32.CreateProcessW(
                exe_path,
                cmd_line,
                None,
                None,
                False,
                self.CREATE_SUSPENDED | self.CREATE_NO_WINDOW,
                None,
                None,
                ctypes.byref(startup_info),
                ctypes.byref(process_info)
            )
            
            if not success:
                error = ctypes.get_last_error()
                logger.error(f"CreateProcess failed: {error}")
                return None
                
            return {
                'process_handle': process_info.hProcess,
                'thread_handle': process_info.hThread,
                'process_id': process_info.dwProcessId,
                'thread_id': process_info.dwThreadId
            }
            
        except Exception as e:
            logger.error(f"Failed to create suspended process: {e}")
            return None
            
    def _allocate_and_write_dll_path(self, process_handle: int, 
                                     dll_path: str) -> int:
        """Allocate memory and write DLL path"""
        try:
            dll_path_bytes = dll_path.encode('utf-8') + b'\x00'
            path_size = len(dll_path_bytes)
            
            # Allocate memory
            addr = self.kernel32.VirtualAllocEx(
                process_handle,
                None,
                path_size,
                self.MEM_COMMIT | self.MEM_RESERVE,
                self.PAGE_EXECUTE_READWRITE
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
                ctypes.byref(bytes_written)
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
                self.PAGE_EXECUTE_READWRITE
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
                ctypes.byref(bytes_written)
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
                parameter
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
            
    def _get_thread_context(self, thread_handle: int) -> Optional[Any]:
        """Get thread context"""
        try:
            if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
                # Simplified CONTEXT structure
                class CONTEXT(ctypes.Structure):
                    _fields_ = [
                        ("P1Home", ctypes.c_ulonglong),
                        ("P2Home", ctypes.c_ulonglong),
                        ("P3Home", ctypes.c_ulonglong),
                        ("P4Home", ctypes.c_ulonglong),
                        ("P5Home", ctypes.c_ulonglong),
                        ("P6Home", ctypes.c_ulonglong),
                        ("ContextFlags", ctypes.wintypes.DWORD),
                        ("MxCsr", ctypes.wintypes.DWORD),
                        ("SegCs", ctypes.wintypes.WORD),
                        ("SegDs", ctypes.wintypes.WORD),
                        ("SegEs", ctypes.wintypes.WORD),
                        ("SegFs", ctypes.wintypes.WORD),
                        ("SegGs", ctypes.wintypes.WORD),
                        ("SegSs", ctypes.wintypes.WORD),
                        ("EFlags", ctypes.wintypes.DWORD),
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
                    ]
                CONTEXT_FULL = 0x10000B
            else:  # 32-bit
                class CONTEXT(ctypes.Structure):
                    _fields_ = [
                        ("ContextFlags", ctypes.wintypes.DWORD),
                        ("Dr0", ctypes.wintypes.DWORD),
                        ("Dr1", ctypes.wintypes.DWORD),
                        ("Dr2", ctypes.wintypes.DWORD),
                        ("Dr3", ctypes.wintypes.DWORD),
                        ("Dr6", ctypes.wintypes.DWORD),
                        ("Dr7", ctypes.wintypes.DWORD),
                        ("FloatSave", ctypes.c_byte * 112),
                        ("SegGs", ctypes.wintypes.DWORD),
                        ("SegFs", ctypes.wintypes.DWORD),
                        ("SegEs", ctypes.wintypes.DWORD),
                        ("SegDs", ctypes.wintypes.DWORD),
                        ("Edi", ctypes.wintypes.DWORD),
                        ("Esi", ctypes.wintypes.DWORD),
                        ("Ebx", ctypes.wintypes.DWORD),
                        ("Edx", ctypes.wintypes.DWORD),
                        ("Ecx", ctypes.wintypes.DWORD),
                        ("Eax", ctypes.wintypes.DWORD),
                        ("Ebp", ctypes.wintypes.DWORD),
                        ("Eip", ctypes.wintypes.DWORD),
                        ("SegCs", ctypes.wintypes.DWORD),
                        ("EFlags", ctypes.wintypes.DWORD),
                        ("Esp", ctypes.wintypes.DWORD),
                        ("SegSs", ctypes.wintypes.DWORD),
                    ]
                CONTEXT_FULL = 0x10007
                
            context = CONTEXT()
            context.ContextFlags = CONTEXT_FULL
            
            success = self.kernel32.GetThreadContext(thread_handle, ctypes.byref(context))
            if not success:
                error = ctypes.get_last_error()
                logger.error(f"GetThreadContext failed: {error}")
                return None
                
            return context
            
        except Exception as e:
            logger.error(f"Failed to get thread context: {e}")
            return None
            
    def _set_thread_context(self, thread_handle: int, context: Any) -> bool:
        """Set thread context"""
        try:
            success = self.kernel32.SetThreadContext(thread_handle, ctypes.byref(context))
            if not success:
                error = ctypes.get_last_error()
                logger.error(f"SetThreadContext failed: {error}")
                return False
            return True
        except Exception as e:
            logger.error(f"Failed to set thread context: {e}")
            return False
            
    def _get_entry_point(self, context: Any) -> int:
        """Get entry point from context"""
        if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
            return context.Rcx
        else:  # 32-bit
            return context.Eax
            
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
                stub += b'\x50'                      # push rax
                stub += b'\x51'                      # push rcx
                stub += b'\x52'                      # push rdx
                stub += b'\x41\x50'                  # push r8
                stub += b'\x41\x51'                  # push r9
                
                # Load DLL
                stub += b'\x48\xB9' + struct.pack('<Q', dll_path_addr)     # mov rcx, dll_path_addr
                stub += b'\x48\xB8' + struct.pack('<Q', load_library_addr) # mov rax, LoadLibraryA
                stub += b'\xFF\xD0'                  # call rax
                
                # Restore registers
                stub += b'\x41\x59'                  # pop r9
                stub += b'\x41\x58'                  # pop r8
                stub += b'\x5A'                      # pop rdx
                stub += b'\x59'                      # pop rcx
                stub += b'\x58'                      # pop rax
                
                # Jump to original entry
                stub += b'\x48\xB8' + struct.pack('<Q', original_entry)    # mov rax, original_entry
                stub += b'\xFF\xE0'                  # jmp rax
                
            else:  # 32-bit
                stub = bytearray()
                
                # Save registers
                stub += b'\x60'                      # pushad
                
                # Load DLL
                stub += b'\x68' + struct.pack('<I', dll_path_addr)     # push dll_path_addr
                stub += b'\xB8' + struct.pack('<I', load_library_addr) # mov eax, LoadLibraryA
                stub += b'\xFF\xD0'                  # call eax
                
                # Restore registers
                stub += b'\x61'                      # popad
                
                # Jump to original entry
                stub += b'\xB8' + struct.pack('<I', original_entry)    # mov eax, original_entry
                stub += b'\xFF\xE0'                  # jmp eax
                
            # Allocate and write stub
            stub_addr = self._allocate_and_write_shellcode(process_handle, bytes(stub))
            return stub_addr
            
        except Exception as e:
            logger.error(f"Failed to create injection stub: {e}")
            return 0


def perform_early_bird_injection(target_exe: str, dll_path: str,
                               command_line: str = None) -> bool:
    """
    Convenience function to perform Early Bird injection
    
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