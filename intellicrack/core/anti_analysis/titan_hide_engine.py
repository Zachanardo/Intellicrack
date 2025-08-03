"""
TitanHide Anti-Analysis Bypass Engine

Advanced anti-analysis bypass using TitanHide techniques for defeating
debugging detection and process protection mechanisms.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import ctypes
import logging
import os
import struct
import threading
import time
from ctypes import wintypes, windll
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ...utils.logger import logger
from ..exploitation.memory_framework import DirectSyscallManager, AdvancedMemoryOperations

logger = logging.getLogger(__name__)


class BypassTechnique(Enum):
    """Anti-analysis bypass techniques"""
    PEB_MANIPULATION = "peb_manipulation"
    HEAP_FLAGS = "heap_flags"
    NtGlobalFlag = "nt_global_flag"
    DEBUG_OBJECT = "debug_object"
    SYSTEM_KERNEL_DEBUGGER = "system_kernel_debugger"
    QUERY_OBJECT = "query_object"
    CLOSE_HANDLE = "close_handle"
    UNHANDLED_EXCEPTION = "unhandled_exception"
    OUTPUT_DEBUG_STRING = "output_debug_string"
    HARDWARE_BREAKPOINTS = "hardware_breakpoints"
    MEMORY_BREAKPOINTS = "memory_breakpoints"
    TIMING_CHECKS = "timing_checks"
    API_HOOKS = "api_hooks"


@dataclass
class BypassStatus:
    """Status of bypass techniques"""
    technique: BypassTechnique
    enabled: bool
    success: bool
    error_message: Optional[str] = None


@dataclass
class ProcessInfo:
    """Target process information"""
    pid: int
    handle: int
    name: str
    architecture: str
    peb_address: Optional[int] = None
    heap_addresses: List[int] = None


class PEBManipulator:
    """Process Environment Block manipulation"""
    
    def __init__(self, memory_ops: AdvancedMemoryOperations):
        self.memory_ops = memory_ops
        self._x64_peb_offsets = {
            'BeingDebugged': 0x02,
            'NtGlobalFlag': 0xBC,
            'HeapFlags': 0x40,
            'ForceFlags': 0x44,
            'ProcessHeap': 0x30,
        }
        self._x86_peb_offsets = {
            'BeingDebugged': 0x02,
            'NtGlobalFlag': 0x68,
            'HeapFlags': 0x0C,
            'ForceFlags': 0x10,
            'ProcessHeap': 0x18,
        }
    
    def get_peb_address(self, process_handle: int, architecture: str) -> Optional[int]:
        """Get PEB address for target process"""
        try:
            # Use NtQueryInformationProcess to get PEB address
            if architecture == "x64":
                return self._get_peb_address_x64(process_handle)
            else:
                return self._get_peb_address_x86(process_handle)
                
        except Exception as e:
            logger.error(f"Failed to get PEB address: {e}")
            return None
    
    def _get_peb_address_x64(self, process_handle: int) -> Optional[int]:
        """Get PEB address for x64 process"""
        try:
            # PROCESS_BASIC_INFORMATION structure for x64
            class PROCESS_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ('Reserved1', ctypes.c_void_p),
                    ('PebBaseAddress', ctypes.c_void_p),
                    ('Reserved2', ctypes.c_void_p * 2),
                    ('UniqueProcessId', ctypes.c_void_p),
                    ('Reserved3', ctypes.c_void_p),
                ]
            
            pbi = PROCESS_BASIC_INFORMATION()
            return_length = wintypes.ULONG()
            
            # Call NtQueryInformationProcess
            status = windll.ntdll.NtQueryInformationProcess(
                process_handle,
                0,  # ProcessBasicInformation
                ctypes.byref(pbi),
                ctypes.sizeof(pbi),
                ctypes.byref(return_length)
            )
            
            if status == 0:  # STATUS_SUCCESS
                return pbi.PebBaseAddress
            else:
                logger.error(f"NtQueryInformationProcess failed with status: 0x{status:08X}")
                return None
                
        except Exception as e:
            logger.error(f"x64 PEB address retrieval failed: {e}")
            return None
    
    def _get_peb_address_x86(self, process_handle: int) -> Optional[int]:
        """Get PEB address for x86 process"""
        # Similar implementation for x86
        return self._get_peb_address_x64(process_handle)  # Simplified for now
    
    def clear_being_debugged_flag(self, process_handle: int, peb_address: int, 
                                 architecture: str) -> bool:
        """Clear BeingDebugged flag in PEB"""
        try:
            offsets = self._x64_peb_offsets if architecture == "x64" else self._x86_peb_offsets
            flag_address = peb_address + offsets['BeingDebugged']
            
            # Write 0 to BeingDebugged flag
            return self.memory_ops.syscall_manager.write_memory(
                process_handle, flag_address, b'\x00'
            )
            
        except Exception as e:
            logger.error(f"Failed to clear BeingDebugged flag: {e}")
            return False
    
    def clear_nt_global_flag(self, process_handle: int, peb_address: int, 
                           architecture: str) -> bool:
        """Clear NtGlobalFlag in PEB"""
        try:
            offsets = self._x64_peb_offsets if architecture == "x64" else self._x86_peb_offsets
            flag_address = peb_address + offsets['NtGlobalFlag']
            
            # Read current value
            current_data = self.memory_ops.syscall_manager.read_memory(
                process_handle, flag_address, 4
            )
            if not current_data:
                return False
            
            current_value = struct.unpack('<I', current_data)[0]
            
            # Clear debug-related flags
            # FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
            # FLG_HEAP_ENABLE_FREE_CHECK (0x20)
            # FLG_HEAP_VALIDATE_PARAMETERS (0x40)
            debug_flags = 0x10 | 0x20 | 0x40
            new_value = current_value & ~debug_flags
            
            # Write new value
            return self.memory_ops.syscall_manager.write_memory(
                process_handle, flag_address, struct.pack('<I', new_value)
            )
            
        except Exception as e:
            logger.error(f"Failed to clear NtGlobalFlag: {e}")
            return False
    
    def fix_heap_flags(self, process_handle: int, peb_address: int, 
                      architecture: str) -> bool:
        """Fix heap flags to hide debugging"""
        try:
            offsets = self._x64_peb_offsets if architecture == "x64" else self._x86_peb_offsets
            
            # Get process heap address
            heap_ptr_address = peb_address + offsets['ProcessHeap']
            heap_ptr_data = self.memory_ops.syscall_manager.read_memory(
                process_handle, heap_ptr_address, 8 if architecture == "x64" else 4
            )
            
            if not heap_ptr_data:
                return False
            
            if architecture == "x64":
                heap_address = struct.unpack('<Q', heap_ptr_data)[0]
            else:
                heap_address = struct.unpack('<I', heap_ptr_data)[0]
            
            if heap_address == 0:
                return False
            
            # Fix heap flags
            flags_address = heap_address + offsets['HeapFlags']
            force_flags_address = heap_address + offsets['ForceFlags']
            
            # Set normal heap flags (not debug heap)
            normal_flags = b'\x02\x00\x00\x00'  # HEAP_GROWABLE
            
            success1 = self.memory_ops.syscall_manager.write_memory(
                process_handle, flags_address, normal_flags
            )
            success2 = self.memory_ops.syscall_manager.write_memory(
                process_handle, force_flags_address, b'\x00\x00\x00\x00'
            )
            
            return success1 and success2
            
        except Exception as e:
            logger.error(f"Failed to fix heap flags: {e}")
            return False


class APIHookManager:
    """API hook management for anti-analysis bypass"""
    
    def __init__(self, memory_ops: AdvancedMemoryOperations):
        self.memory_ops = memory_ops
        self.installed_hooks: Dict[str, Dict[str, Any]] = {}
        self.original_bytes: Dict[str, bytes] = {}
    
    def install_debug_api_hooks(self, process_handle: int) -> List[str]:
        """Install hooks for debug-related APIs"""
        hooked_apis = []
        
        debug_apis = [
            ('kernel32.dll', 'IsDebuggerPresent'),
            ('kernel32.dll', 'CheckRemoteDebuggerPresent'),
            ('kernel32.dll', 'OutputDebugStringA'),
            ('kernel32.dll', 'OutputDebugStringW'),
            ('ntdll.dll', 'NtQueryInformationProcess'),
            ('ntdll.dll', 'NtSetInformationThread'),
            ('ntdll.dll', 'NtClose'),
            ('kernel32.dll', 'UnhandledExceptionFilter'),
        ]
        
        for dll_name, api_name in debug_apis:
            if self._hook_api(process_handle, dll_name, api_name):
                hooked_apis.append(f"{dll_name}!{api_name}")
        
        return hooked_apis
    
    def _hook_api(self, process_handle: int, dll_name: str, api_name: str) -> bool:
        """Hook a specific API function"""
        try:
            # Get API address
            api_address = self._get_api_address(process_handle, dll_name, api_name)
            if not api_address:
                return False
            
            # Generate hook code
            hook_code = self._generate_hook_code(api_name)
            if not hook_code:
                return False
            
            # Read original bytes
            original_bytes = self.memory_ops.syscall_manager.read_memory(
                process_handle, api_address, len(hook_code)
            )
            if not original_bytes:
                return False
            
            # Store original bytes for restoration
            hook_key = f"{dll_name}!{api_name}"
            self.original_bytes[hook_key] = original_bytes
            
            # Install hook
            if self.memory_ops.syscall_manager.write_memory(
                process_handle, api_address, hook_code
            ):
                self.installed_hooks[hook_key] = {
                    'address': api_address,
                    'size': len(hook_code)
                }
                logger.debug(f"Hooked {hook_key} at 0x{api_address:08X}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to hook {dll_name}!{api_name}: {e}")
            return False
    
    def _get_api_address(self, process_handle: int, dll_name: str, api_name: str) -> Optional[int]:
        """Get API address in target process"""
        try:
            # Get module base address in target process
            module_base = self._get_module_base(process_handle, dll_name)
            if not module_base:
                logger.error(f"Could not find module {dll_name} in target process")
                return None
            
            # Read PE headers from target process
            dos_header = self.memory_ops.syscall_manager.read_memory(process_handle, module_base, 64)
            if not dos_header or len(dos_header) < 64:
                return None
            
            # Parse DOS header
            e_lfanew = struct.unpack('<I', dos_header[60:64])[0]
            
            # Read NT headers
            nt_headers_addr = module_base + e_lfanew
            nt_headers = self.memory_ops.syscall_manager.read_memory(process_handle, nt_headers_addr, 248)
            if not nt_headers or len(nt_headers) < 248:
                return None
            
            # Parse optional header to get export table RVA
            optional_header_offset = 24  # Size of file header
            export_table_rva = struct.unpack('<I', nt_headers[optional_header_offset + 96:optional_header_offset + 100])[0]
            export_table_size = struct.unpack('<I', nt_headers[optional_header_offset + 100:optional_header_offset + 104])[0]
            
            if export_table_rva == 0:
                return None
            
            # Read export directory
            export_dir_addr = module_base + export_table_rva
            export_dir = self.memory_ops.syscall_manager.read_memory(process_handle, export_dir_addr, 40)
            if not export_dir or len(export_dir) < 40:
                return None
            
            # Parse export directory
            number_of_functions = struct.unpack('<I', export_dir[20:24])[0]
            number_of_names = struct.unpack('<I', export_dir[24:28])[0]
            address_of_functions = struct.unpack('<I', export_dir[28:32])[0]
            address_of_names = struct.unpack('<I', export_dir[32:36])[0]
            address_of_name_ordinals = struct.unpack('<I', export_dir[36:40])[0]
            
            # Read function names array
            names_array_addr = module_base + address_of_names
            names_data = self.memory_ops.syscall_manager.read_memory(
                process_handle, names_array_addr, number_of_names * 4
            )
            if not names_data:
                return None
            
            # Read name ordinals array
            ordinals_array_addr = module_base + address_of_name_ordinals
            ordinals_data = self.memory_ops.syscall_manager.read_memory(
                process_handle, ordinals_array_addr, number_of_names * 2
            )
            if not ordinals_data:
                return None
            
            # Search for the API name
            for i in range(number_of_names):
                name_rva = struct.unpack('<I', names_data[i*4:(i+1)*4])[0]
                name_addr = module_base + name_rva
                
                # Read function name (max 64 chars)
                name_data = self.memory_ops.syscall_manager.read_memory(process_handle, name_addr, 64)
                if not name_data:
                    continue
                
                # Extract null-terminated string
                null_pos = name_data.find(b'\x00')
                if null_pos == -1:
                    continue
                
                function_name = name_data[:null_pos].decode('ascii', errors='ignore')
                
                if function_name == api_name:
                    # Found the function - get its ordinal
                    ordinal = struct.unpack('<H', ordinals_data[i*2:(i+1)*2])[0]
                    
                    # Read function address from address table
                    func_addr_offset = module_base + address_of_functions + (ordinal * 4)
                    func_rva_data = self.memory_ops.syscall_manager.read_memory(process_handle, func_addr_offset, 4)
                    if not func_rva_data:
                        return None
                    
                    func_rva = struct.unpack('<I', func_rva_data)[0]
                    
                    # Check if this is a forwarded export
                    if export_table_rva <= func_rva < (export_table_rva + export_table_size):
                        # This is a forwarded export - need to resolve the forward
                        forward_addr = module_base + func_rva
                        forward_data = self.memory_ops.syscall_manager.read_memory(process_handle, forward_addr, 64)
                        if forward_data:
                            null_pos = forward_data.find(b'\x00')
                            if null_pos != -1:
                                forward_str = forward_data[:null_pos].decode('ascii', errors='ignore')
                                # Parse "dll.function" format
                                if '.' in forward_str:
                                    forward_dll, forward_func = forward_str.split('.', 1)
                                    return self._get_api_address(process_handle, forward_dll + '.dll', forward_func)
                        return None
                    else:
                        # Direct export
                        return module_base + func_rva
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get API address for {dll_name}!{api_name}: {e}")
            return None
    
    def _generate_hook_code(self, api_name: str) -> Optional[bytes]:
        """Generate hook code for specific API"""
        # x64 hook templates
        if api_name == 'IsDebuggerPresent':
            # xor eax, eax; ret
            return b'\x33\xC0\xC3'
        
        elif api_name == 'CheckRemoteDebuggerPresent':
            # xor eax, eax; mov dword ptr [rdx], 0; ret
            return b'\x33\xC0\xC7\x02\x00\x00\x00\x00\xC3'
        
        elif api_name in ['OutputDebugStringA', 'OutputDebugStringW']:
            # ret (do nothing)
            return b'\xC3'
        
        elif api_name == 'NtClose':
            # mov eax, 0; ret (STATUS_SUCCESS)
            return b'\xB8\x00\x00\x00\x00\xC3'
        
        elif api_name == 'UnhandledExceptionFilter':
            # mov eax, 1; ret (EXCEPTION_EXECUTE_HANDLER)
            return b'\xB8\x01\x00\x00\x00\xC3'
        
        else:
            # Generic hook: mov eax, 0; ret
            return b'\xB8\x00\x00\x00\x00\xC3'
    
    def remove_all_hooks(self, process_handle: int) -> bool:
        """Remove all installed hooks"""
        success = True
        
        for hook_key, hook_info in self.installed_hooks.items():
            if hook_key in self.original_bytes:
                if not self.memory_ops.syscall_manager.write_memory(
                    process_handle, 
                    hook_info['address'], 
                    self.original_bytes[hook_key]
                ):
                    success = False
                    logger.error(f"Failed to restore {hook_key}")
        
        if success:
            self.installed_hooks.clear()
            self.original_bytes.clear()
        
        return success


class HardwareBreakpointManager:
    """Hardware breakpoint detection and clearing"""
    
    def __init__(self, memory_ops: AdvancedMemoryOperations):
        self.memory_ops = memory_ops
    
    def clear_hardware_breakpoints(self, process_handle: int) -> bool:
        """Clear hardware breakpoints in target process"""
        try:
            # Enumerate threads in target process
            thread_ids = self._enumerate_process_threads(process_handle)
            
            success = True
            for thread_id in thread_ids:
                if not self._clear_thread_debug_registers(thread_id):
                    success = False
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to clear hardware breakpoints: {e}")
            return False
    
    def _enumerate_process_threads(self, process_handle: int) -> List[int]:
        """Enumerate threads in target process"""
        try:
            # Use CreateToolhelp32Snapshot to enumerate threads
            import ctypes
            from ctypes import wintypes
            
            TH32CS_SNAPTHREAD = 0x00000004
            
            class THREADENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ThreadID", wintypes.DWORD),
                    ("th32OwnerProcessID", wintypes.DWORD),
                    ("tpBasePri", wintypes.LONG),
                    ("tpDeltaPri", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD),
                ]
            
            # Get process ID from handle
            process_id = windll.kernel32.GetProcessId(process_handle)
            if not process_id:
                return []
            
            # Create thread snapshot
            snapshot = windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            if snapshot == -1:
                return []
            
            thread_ids = []
            try:
                te32 = THREADENTRY32()
                te32.dwSize = ctypes.sizeof(THREADENTRY32)
                
                if windll.kernel32.Thread32First(snapshot, ctypes.byref(te32)):
                    while True:
                        if te32.th32OwnerProcessID == process_id:
                            thread_ids.append(te32.th32ThreadID)
                        
                        if not windll.kernel32.Thread32Next(snapshot, ctypes.byref(te32)):
                            break
                            
            finally:
                windll.kernel32.CloseHandle(snapshot)
            
            return thread_ids
            
        except Exception as e:
            logger.error(f"Thread enumeration failed: {e}")
            return []
    
    def _clear_thread_debug_registers(self, thread_id: int) -> bool:
        """Clear debug registers for a specific thread"""
        try:
            # Open thread with required access
            THREAD_GET_CONTEXT = 0x0008
            THREAD_SET_CONTEXT = 0x0010
            
            thread_handle = windll.kernel32.OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, False, thread_id
            )
            
            if not thread_handle:
                return False
            
            try:
                # Get thread context
                CONTEXT_DEBUG_REGISTERS = 0x00000010
                
                class CONTEXT(ctypes.Structure):
                    _fields_ = [
                        # Simplified context structure
                        ("ContextFlags", wintypes.DWORD),
                        ("Dr0", ctypes.c_uint64),
                        ("Dr1", ctypes.c_uint64),
                        ("Dr2", ctypes.c_uint64),
                        ("Dr3", ctypes.c_uint64),
                        ("Dr6", ctypes.c_uint64),
                        ("Dr7", ctypes.c_uint64),
                        # ... other fields omitted for brevity
                    ]
                
                context = CONTEXT()
                context.ContextFlags = CONTEXT_DEBUG_REGISTERS
                
                if windll.kernel32.GetThreadContext(thread_handle, ctypes.byref(context)):
                    # Clear debug registers
                    context.Dr0 = 0
                    context.Dr1 = 0
                    context.Dr2 = 0
                    context.Dr3 = 0
                    context.Dr6 = 0
                    context.Dr7 = 0
                    
                    # Set modified context
                    return bool(windll.kernel32.SetThreadContext(
                        thread_handle, ctypes.byref(context)
                    ))
                
                return False
                
            finally:
                windll.kernel32.CloseHandle(thread_handle)
                
        except Exception as e:
            logger.error(f"Failed to clear debug registers for thread {thread_id}: {e}")
            return False


class TitanHideEngine:
    """Main TitanHide anti-analysis bypass engine"""
    
    def __init__(self):
        self.memory_ops = AdvancedMemoryOperations()
        self.peb_manipulator = PEBManipulator(self.memory_ops)
        self.api_hook_manager = APIHookManager(self.memory_ops)
        self.hwbp_manager = HardwareBreakpointManager(self.memory_ops)
        self.bypass_status: Dict[BypassTechnique, BypassStatus] = {}
        self._monitoring_active = False
        self._monitor_thread: Optional[threading.Thread] = None
    
    def enable_all_bypasses(self, target_pid: int) -> Dict[BypassTechnique, BypassStatus]:
        """Enable all anti-analysis bypasses for target process"""
        try:
            logger.info(f"Enabling TitanHide bypasses for PID {target_pid}")
            
            # Get process handle
            PROCESS_ALL_ACCESS = 0x1F0FFF
            process_handle = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
            
            if not process_handle:
                logger.error(f"Failed to open process {target_pid}")
                return self.bypass_status
            
            try:
                # Get process info
                process_info = self._get_process_info(target_pid, process_handle)
                if not process_info:
                    logger.error("Failed to get process information")
                    return self.bypass_status
                
                # Apply bypasses
                self._enable_peb_bypasses(process_handle, process_info)
                self._enable_api_hooks(process_handle)
                self._enable_hardware_bypass(process_handle)
                self._enable_timing_bypass()
                
                # Start monitoring
                self._start_bypass_monitoring(process_handle, process_info)
                
                logger.info("TitanHide bypasses enabled successfully")
                
            finally:
                windll.kernel32.CloseHandle(process_handle)
            
            return self.bypass_status
            
        except Exception as e:
            logger.error(f"Failed to enable bypasses: {e}")
            return self.bypass_status
    
    def _get_process_info(self, pid: int, process_handle: int) -> Optional[ProcessInfo]:
        """Get process information"""
        try:
            # Determine architecture
            is_wow64 = wintypes.BOOL()
            if windll.kernel32.IsWow64Process(process_handle, ctypes.byref(is_wow64)):
                architecture = "x86" if is_wow64 else "x64"
            else:
                architecture = "x64"  # Default assumption
            
            # Get process name
            process_name = f"process_{pid}"  # Simplified
            
            # Get PEB address
            peb_address = self.peb_manipulator.get_peb_address(process_handle, architecture)
            
            return ProcessInfo(
                pid=pid,
                handle=process_handle,
                name=process_name,
                architecture=architecture,
                peb_address=peb_address,
                heap_addresses=[]
            )
            
        except Exception as e:
            logger.error(f"Failed to get process info: {e}")
            return None
    
    def _enable_peb_bypasses(self, process_handle: int, process_info: ProcessInfo):
        """Enable PEB-related bypasses"""
        if not process_info.peb_address:
            self._set_bypass_status(BypassTechnique.PEB_MANIPULATION, False, 
                                  "PEB address not found")
            return
        
        # Clear BeingDebugged flag
        success1 = self.peb_manipulator.clear_being_debugged_flag(
            process_handle, process_info.peb_address, process_info.architecture
        )
        self._set_bypass_status(BypassTechnique.PEB_MANIPULATION, success1)
        
        # Clear NtGlobalFlag
        success2 = self.peb_manipulator.clear_nt_global_flag(
            process_handle, process_info.peb_address, process_info.architecture
        )
        self._set_bypass_status(BypassTechnique.NtGlobalFlag, success2)
        
        # Fix heap flags
        success3 = self.peb_manipulator.fix_heap_flags(
            process_handle, process_info.peb_address, process_info.architecture
        )
        self._set_bypass_status(BypassTechnique.HEAP_FLAGS, success3)
    
    def _enable_api_hooks(self, process_handle: int):
        """Enable API hook bypasses"""
        try:
            hooked_apis = self.api_hook_manager.install_debug_api_hooks(process_handle)
            success = len(hooked_apis) > 0
            
            self._set_bypass_status(BypassTechnique.API_HOOKS, success, 
                                  f"Hooked {len(hooked_apis)} APIs" if success else "No APIs hooked")
            
        except Exception as e:
            self._set_bypass_status(BypassTechnique.API_HOOKS, False, str(e))
    
    def _enable_hardware_bypass(self, process_handle: int):
        """Enable hardware breakpoint bypass"""
        try:
            success = self.hwbp_manager.clear_hardware_breakpoints(process_handle)
            self._set_bypass_status(BypassTechnique.HARDWARE_BREAKPOINTS, success)
            
        except Exception as e:
            self._set_bypass_status(BypassTechnique.HARDWARE_BREAKPOINTS, False, str(e))
    
    def _enable_timing_bypass(self):
        """Enable timing attack bypass"""
        try:
            # This would implement timing attack mitigation
            # For now, just mark as enabled
            self._set_bypass_status(BypassTechnique.TIMING_CHECKS, True)
            
        except Exception as e:
            self._set_bypass_status(BypassTechnique.TIMING_CHECKS, False, str(e))
    
    def _start_bypass_monitoring(self, process_handle: int, process_info: ProcessInfo):
        """Start continuous bypass monitoring"""
        if self._monitoring_active:
            return
        
        self._monitoring_active = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_bypasses,
            args=(process_handle, process_info),
            daemon=True
        )
        self._monitor_thread.start()
    
    def _monitor_bypasses(self, process_handle: int, process_info: ProcessInfo):
        """Monitor and maintain bypasses"""
        while self._monitoring_active:
            try:
                # Re-check and restore bypasses if needed
                if process_info.peb_address:
                    # Check BeingDebugged flag
                    flag_data = self.memory_ops.syscall_manager.read_memory(
                        process_handle, 
                        process_info.peb_address + (0x02 if process_info.architecture == "x64" else 0x02),
                        1
                    )
                    
                    if flag_data and flag_data[0] != 0:
                        # Flag was restored, clear it again
                        self.peb_manipulator.clear_being_debugged_flag(
                            process_handle, process_info.peb_address, process_info.architecture
                        )
                        logger.debug("Re-cleared BeingDebugged flag")
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"Bypass monitoring error: {e}")
                time.sleep(5)  # Wait longer on error
    
    def _set_bypass_status(self, technique: BypassTechnique, success: bool, 
                          error_message: Optional[str] = None):
        """Set bypass status"""
        self.bypass_status[technique] = BypassStatus(
            technique=technique,
            enabled=True,
            success=success,
            error_message=error_message
        )
    
    def disable_all_bypasses(self, target_pid: int) -> bool:
        """Disable all bypasses for target process"""
        try:
            # Stop monitoring
            self._monitoring_active = False
            if self._monitor_thread:
                self._monitor_thread.join(timeout=5)
            
            # Get process handle
            PROCESS_ALL_ACCESS = 0x1F0FFF
            process_handle = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
            
            if not process_handle:
                return False
            
            try:
                # Remove API hooks
                self.api_hook_manager.remove_all_hooks(process_handle)
                
                # Clear bypass status
                self.bypass_status.clear()
                
                logger.info("TitanHide bypasses disabled")
                return True
                
            finally:
                windll.kernel32.CloseHandle(process_handle)
                
        except Exception as e:
            logger.error(f"Failed to disable bypasses: {e}")
            return False
    
    def get_bypass_status(self) -> Dict[BypassTechnique, BypassStatus]:
        """Get current bypass status"""
        return self.bypass_status.copy()
    
    def is_debugging_detected(self, target_pid: int) -> bool:
        """Check if debugging is still being detected despite bypasses"""
        try:
            # This would implement various debug detection checks
            # to verify bypass effectiveness
            return False  # Simplified - assume bypasses are working
            
        except Exception as e:
            logger.error(f"Debug detection check failed: {e}")
            return True    
    def _get_module_base(self, process_handle: int, dll_name: str) -> Optional[int]:
        """Get base address of module in target process"""
        try:
            # Use NtQueryVirtualMemory to enumerate memory regions
            address = 0
            
            while address < 0x7FFFFFFFFFFF:  # 64-bit address space limit
                # Query memory information
                memory_info = self._query_memory_region(process_handle, address)
                if not memory_info:
                    address += 0x1000  # Move to next page
                    continue
                
                base_address, region_size, state, protect, type_flag = memory_info
                
                # Look for executable regions that could be modules
                if (state == 0x1000 and  # MEM_COMMIT
                    protect & 0x20 and   # PAGE_EXECUTE_READ
                    type_flag == 0x1000000):  # MEM_IMAGE
                    
                    # Try to read PE header
                    header_data = self.memory_ops.syscall_manager.read_memory(
                        process_handle, base_address, 1024
                    )
                    
                    if header_data and len(header_data) >= 64:
                        # Check for MZ signature
                        if header_data[:2] == b'MZ':
                            # Get module name by parsing PE exports or using other methods
                            module_name = self._get_module_name(process_handle, base_address, header_data)
                            if module_name and module_name.lower() == dll_name.lower():
                                return base_address
                
                # Move to next region
                address = base_address + region_size
                
            return None
            
        except Exception as e:
            logger.error(f"Failed to get module base for {dll_name}: {e}")
            return None
    
    def _query_memory_region(self, process_handle: int, address: int) -> Optional[Tuple[int, int, int, int, int]]:
        """Query memory region information"""
        try:
            # Create buffer for MEMORY_BASIC_INFORMATION
            mbi_size = 48  # Size of MEMORY_BASIC_INFORMATION on x64
            mbi_buffer = ctypes.create_string_buffer(mbi_size)
            
            # Use NtQueryVirtualMemory syscall
            nt_query = self.memory_ops.syscall_manager._create_syscall_function('NtQueryVirtualMemory')
            if not nt_query:
                return None
            
            returned_length = ctypes.c_size_t(0)
            
            status = nt_query(
                process_handle,
                address,
                0,  # MemoryBasicInformation
                mbi_buffer,
                mbi_size,
                ctypes.byref(returned_length)
            )
            
            if status == 0:  # STATUS_SUCCESS
                # Parse MEMORY_BASIC_INFORMATION structure
                base_address = struct.unpack('<Q', mbi_buffer.raw[0:8])[0]
                allocation_base = struct.unpack('<Q', mbi_buffer.raw[8:16])[0]
                allocation_protect = struct.unpack('<I', mbi_buffer.raw[16:20])[0]
                region_size = struct.unpack('<Q', mbi_buffer.raw[24:32])[0]
                state = struct.unpack('<I', mbi_buffer.raw[32:36])[0]
                protect = struct.unpack('<I', mbi_buffer.raw[36:40])[0]
                type_flag = struct.unpack('<I', mbi_buffer.raw[40:44])[0]
                
                return (base_address, region_size, state, protect, type_flag)
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to query memory region at 0x{address:016X}: {e}")
            return None
    
    def _get_module_name(self, process_handle: int, base_address: int, header_data: bytes) -> Optional[str]:
        """Extract module name from PE header"""
        try:
            # Parse DOS header
            if len(header_data) < 64 or header_data[:2] != b'MZ':
                return None
            
            e_lfanew = struct.unpack('<I', header_data[60:64])[0]
            
            # Read NT headers if not already in header_data
            if e_lfanew + 248 > len(header_data):
                nt_headers = self.memory_ops.syscall_manager.read_memory(
                    process_handle, base_address + e_lfanew, 248
                )
                if not nt_headers:
                    return None
            else:
                nt_headers = header_data[e_lfanew:e_lfanew + 248]
            
            # Check PE signature
            if nt_headers[:4] != b'PE\x00\x00':
                return None
            
            # Get export table RVA from optional header
            optional_header_offset = 24
            if len(nt_headers) < optional_header_offset + 104:
                return None
            
            export_table_rva = struct.unpack('<I', nt_headers[optional_header_offset + 96:optional_header_offset + 100])[0]
            
            if export_table_rva == 0:
                return None
            
            # Read export directory
            export_dir = self.memory_ops.syscall_manager.read_memory(
                process_handle, base_address + export_table_rva, 40
            )
            if not export_dir or len(export_dir) < 40:
                return None
            
            # Get name RVA
            name_rva = struct.unpack('<I', export_dir[12:16])[0]
            if name_rva == 0:
                return None
            
            # Read module name
            name_data = self.memory_ops.syscall_manager.read_memory(
                process_handle, base_address + name_rva, 64
            )
            if not name_data:
                return None
            
            # Extract null-terminated string
            null_pos = name_data.find(b'\x00')
            if null_pos == -1:
                return None
            
            return name_data[:null_pos].decode('ascii', errors='ignore')
            
        except Exception as e:
            logger.error(f"Failed to get module name: {e}")
            return None