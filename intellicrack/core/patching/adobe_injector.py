"""
Adobe License Bypass Module 

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


import os
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Set

try:
    import frida
    import psutil
    DEPENDENCIES_AVAILABLE = True
except ImportError:
    DEPENDENCIES_AVAILABLE = False
    psutil = None
    frida = None

try:
    import pefile
    PE_AVAILABLE = True
except ImportError:
    PE_AVAILABLE = False
    pefile = None

from ...utils.constants import ADOBE_PROCESSES
from ...utils.logger import get_logger
from .early_bird_injection import perform_early_bird_injection
from .kernel_injection import inject_via_kernel_driver
from .process_hollowing import perform_process_hollowing
from .syscalls import inject_using_syscalls

# Windows API imports for process injection
if sys.platform == 'win32':
    try:
        import ctypes
        from ctypes import wintypes
        KERNEL32 = ctypes.WinDLL('kernel32', use_last_error=True)
        PSAPI = ctypes.WinDLL('psapi', use_last_error=True)

        # Constants
        PROCESS_ALL_ACCESS = 0x1F0FFF
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_EXECUTE_READWRITE = 0x40
        INFINITE = 0xFFFFFFFF

        # Additional constants for manual mapping
        IMAGE_REL_BASED_ABSOLUTE = 0
        IMAGE_REL_BASED_HIGHLOW = 3
        IMAGE_REL_BASED_DIR64 = 10

        # WOW64 constants
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_OPERATION = 0x0008
        PROCESS_VM_WRITE = 0x0020
        PROCESS_VM_READ = 0x0010
        PROCESS_CREATE_THREAD = 0x0002

        # Thread constants
        THREAD_QUERY_INFORMATION = 0x0040

        # Hook constants
        WH_KEYBOARD = 2
        WH_GETMESSAGE = 3
        WH_CBT = 5
        WH_MOUSE = 7
        WH_KEYBOARD_LL = 13
        WH_MOUSE_LL = 14

        # Additional APIs
        USER32 = ctypes.WinDLL('user32', use_last_error=True)

        # Thread states for APC
        THREAD_STATE_WAIT = 5
        MAXIMUM_WAIT_OBJECTS = 64

        # Thread access rights
        THREAD_SET_CONTEXT = 0x0010
        THREAD_GET_CONTEXT = 0x0008
        THREAD_SUSPEND_RESUME = 0x0002
        THREAD_ALL_ACCESS = 0x1F03FF

        WINDOWS_API_AVAILABLE = True
    except (ImportError, OSError):
        WINDOWS_API_AVAILABLE = False
else:
    WINDOWS_API_AVAILABLE = False

logger = get_logger(__name__)

class AdobeInjector:
    """
    Adobe License Bypass Injector

    Monitors and injects Frida scripts into running Adobe Creative Suite
    applications to bypass license validation mechanisms.
    """

    ADOBE_PROCESSES = ADOBE_PROCESSES

    FRIDA_SCRIPT = '''
// adobe_bypass.js
console.log("[*] Adobe license patch injected.");

const targets = [
    "IsActivated",
    "IsLicenseValid", 
    "GetLicenseStatus",
    "GetSerialNumber",
    "CheckSubscription"
];

for (let name of targets) {
    try {
        let addr = Module.findExportByName("AdobeLM.dll", name);
        if (addr) {
            Interceptor.replace(addr, new NativeCallback(function () {
                console.log("[✓] Spoofed: " + name);
                return 1;
            }, 'int', []));
        }
    } catch (e) {
        console.log("[-] Failed to patch: " + name);
    }
}
'''

    def __init__(self):
        self.injected: Set[str] = set()
        self.running = False

        if not DEPENDENCIES_AVAILABLE:
            logger.warning("Adobe injector dependencies not available (psutil, frida)")

    def inject_process(self, target_name: str) -> bool:
        """
        Inject Frida script into target Adobe process

        Args:
            target_name: Name of the target process

        Returns:
            True if injection successful, False otherwise
        """
        if not DEPENDENCIES_AVAILABLE:
            logger.error("Cannot inject - dependencies not available")
            return False

        try:
            session = frida.attach(target_name)
            script = session.create_script(self.FRIDA_SCRIPT)
            script.load()
            self.injected.add(target_name)
            logger.info("Successfully injected into %s", target_name)
            return True
        except (OSError, ValueError, RuntimeError) as e:
            logger.debug("Failed to inject into %s: %s", target_name, e)
            return False

    def get_running_adobe_processes(self) -> List[str]:
        """
        Get list of running Adobe processes that haven't been injected

        Returns:
            List of Adobe process names currently running
        """
        if not DEPENDENCIES_AVAILABLE:
            return []

        running = []
        try:
            for _proc in psutil.process_iter(attrs=['name']):
                try:
                    pname = _proc.info['name']
                    if pname in self.ADOBE_PROCESSES and pname not in self.injected:
                        running.append(pname)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error scanning processes: %s", e)

        return running

    def monitor_and_inject(self, interval: float = 2.0) -> None:
        """
        Continuously monitor for Adobe processes and inject them

        Args:
            interval: Sleep interval between scans in seconds
        """
        if not DEPENDENCIES_AVAILABLE:
            logger.error("Cannot monitor - dependencies not available")
            return

        self.running = True
        logger.info("Starting Adobe process monitoring...")

        try:
            while self.running:
                active_processes = self.get_running_adobe_processes()
                for proc_name in active_processes:
                    self.inject_process(proc_name)
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Adobe monitoring stopped by user")
        finally:
            self.running = False

    def stop_monitoring(self) -> None:
        """
        Stop the monitoring loop
        """
        self.running = False
        logger.info("Adobe monitoring stopped")

    def _get_process_handle(self, process_name: str) -> Optional[int]:
        """
        Get process handle by name using Windows API
        
        Args:
            process_name: Name of the process
            
        Returns:
            Process handle or None if not found
        """
        if not WINDOWS_API_AVAILABLE or not psutil:
            return None

        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == process_name:
                    pid = proc.info['pid']
                    handle = KERNEL32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
                    if handle:
                        return handle
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            pass

        return None

    def _inject_into_process(self, process_handle: int, dll_path: str) -> bool:
        """
        Inject DLL into process using Windows API
        
        Args:
            process_handle: Handle to the target process
            dll_path: Path to the DLL to inject
            
        Returns:
            True if injection successful, False otherwise
        """
        if not WINDOWS_API_AVAILABLE:
            logger.warning("Windows API not available for process injection")
            return False

        try:
            # Allocate memory in the target process for the DLL path
            dll_path_bytes = dll_path.encode('utf-8') + b'\x00'
            path_size = len(dll_path_bytes)

            # VirtualAllocEx
            remote_memory = KERNEL32.VirtualAllocEx(
                process_handle,
                None,
                path_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            )

            if not remote_memory:
                logger.error("Failed to allocate memory in target process")
                return False

            # WriteProcessMemory
            bytes_written = ctypes.c_size_t(0)
            success = KERNEL32.WriteProcessMemory(
                process_handle,
                remote_memory,
                dll_path_bytes,
                path_size,
                ctypes.byref(bytes_written)
            )

            if not success or bytes_written.value != path_size:
                logger.error("Failed to write DLL path to target process")
                KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)  # MEM_RELEASE
                return False

            # Get LoadLibraryA address
            kernel32_handle = KERNEL32.GetModuleHandleW("kernel32.dll")
            if not kernel32_handle:
                logger.error("Failed to get kernel32.dll handle")
                KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                return False

            load_library_addr = KERNEL32.GetProcAddress(kernel32_handle, b"LoadLibraryA")
            if not load_library_addr:
                logger.error("Failed to get LoadLibraryA address")
                KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                return False

            # Create remote thread
            thread_success = self._create_remote_thread(
                process_handle,
                load_library_addr,
                remote_memory
            )

            # Clean up allocated memory
            KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)

            if thread_success:
                logger.info(f"Successfully injected DLL: {dll_path}")
                return True
            else:
                logger.error("Failed to create remote thread")
                return False

        except Exception as e:
            logger.error(f"Exception during DLL injection: {e}")
            return False

    def _create_remote_thread(self, process_handle: int, start_address: int, parameter: int = 0) -> bool:
        """
        Create a remote thread in the target process
        
        Args:
            process_handle: Handle to the target process
            start_address: Address of the function to execute
            parameter: Parameter to pass to the function
            
        Returns:
            True if thread created successfully, False otherwise
        """
        if not WINDOWS_API_AVAILABLE:
            logger.warning("Windows API not available for remote thread creation")
            return False

        try:
            # CreateRemoteThread
            thread_handle = KERNEL32.CreateRemoteThread(
                process_handle,
                None,  # Security attributes
                0,     # Stack size (default)
                start_address,
                parameter,
                0,     # Creation flags
                None   # Thread ID
            )

            if not thread_handle:
                logger.error("CreateRemoteThread failed")
                return False

            # Wait for the thread to complete
            wait_result = KERNEL32.WaitForSingleObject(thread_handle, 5000)  # 5 second timeout

            # Get thread exit code
            exit_code = ctypes.c_ulong(0)
            KERNEL32.GetExitCodeThread(thread_handle, ctypes.byref(exit_code))

            # Close thread handle
            KERNEL32.CloseHandle(thread_handle)

            if wait_result == 0:  # WAIT_OBJECT_0
                logger.info(f"Remote thread completed with exit code: {exit_code.value}")
                return True
            else:
                logger.warning(f"Remote thread wait result: {wait_result}")
                return False

        except Exception as e:
            logger.error(f"Exception during remote thread creation: {e}")
            return False

    def inject_dll_windows_api(self, target_name: str, dll_path: str) -> bool:
        """
        Inject DLL using Windows API instead of Frida
        
        Args:
            target_name: Name of the target process
            dll_path: Path to the DLL to inject
            
        Returns:
            True if injection successful, False otherwise
        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("Windows API injection not available on this platform")
            return False

        # Get process handle
        process_handle = self._get_process_handle(target_name)
        if not process_handle:
            logger.error(f"Failed to get handle for process: {target_name}")
            return False

        try:
            # Perform injection
            success = self._inject_into_process(process_handle, dll_path)
            return success
        finally:
            # Always close the process handle
            if process_handle:
                KERNEL32.CloseHandle(process_handle)

    def manual_map_dll(self, target_name: str, dll_path: str) -> bool:
        """
        Manual map DLL without using LoadLibrary - avoids detection
        
        Args:
            target_name: Name of the target process
            dll_path: Path to the DLL to inject
            
        Returns:
            True if injection successful, False otherwise
        """
        if not WINDOWS_API_AVAILABLE or not PE_AVAILABLE:
            logger.error("Manual mapping requires Windows API and pefile")
            return False

        try:
            # Read DLL file
            with open(dll_path, 'rb') as f:
                dll_data = f.read()

            # Parse PE file
            pe = pefile.PE(data=dll_data)

            # Get process handle
            process_handle = self._get_process_handle(target_name)
            if not process_handle:
                logger.error(f"Failed to get handle for process: {target_name}")
                return False

            try:
                # Calculate required memory size
                image_size = pe.OPTIONAL_HEADER.SizeOfImage

                # Allocate memory in target process
                remote_base = KERNEL32.VirtualAllocEx(
                    process_handle,
                    None,
                    image_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                )

                if not remote_base:
                    logger.error("Failed to allocate memory for manual mapping")
                    return False

                logger.info(f"Allocated {image_size} bytes at {hex(remote_base)}")

                # Map sections
                if not self._map_sections(process_handle, pe, dll_data, remote_base):
                    KERNEL32.VirtualFreeEx(process_handle, remote_base, 0, 0x8000)
                    return False

                # Process relocations
                if not self._process_relocations(process_handle, pe, remote_base):
                    KERNEL32.VirtualFreeEx(process_handle, remote_base, 0, 0x8000)
                    return False

                # Resolve imports
                if not self._resolve_imports(process_handle, pe, remote_base):
                    KERNEL32.VirtualFreeEx(process_handle, remote_base, 0, 0x8000)
                    return False

                # Execute TLS callbacks
                self._execute_tls_callbacks(process_handle, pe, remote_base)

                # Call DLL entry point
                if not self._call_dll_entry(process_handle, pe, remote_base):
                    KERNEL32.VirtualFreeEx(process_handle, remote_base, 0, 0x8000)
                    return False

                logger.info("Manual mapping completed successfully")
                return True

            finally:
                KERNEL32.CloseHandle(process_handle)

        except Exception as e:
            logger.error(f"Manual mapping failed: {e}")
            return False

    def _map_sections(self, process_handle: int, pe: Any, dll_data: bytes,
                      remote_base: int) -> bool:
        """Map PE sections to target process"""
        try:
            # Write PE headers
            headers_size = pe.OPTIONAL_HEADER.SizeOfHeaders
            bytes_written = ctypes.c_size_t(0)

            success = KERNEL32.WriteProcessMemory(
                process_handle,
                remote_base,
                dll_data[:headers_size],
                headers_size,
                ctypes.byref(bytes_written)
            )

            if not success:
                logger.error("Failed to write PE headers")
                return False

            # Write each section
            for section in pe.sections:
                section_addr = remote_base + section.VirtualAddress
                section_data = dll_data[section.PointerToRawData:
                                      section.PointerToRawData + section.SizeOfRawData]

                if section_data:
                    success = KERNEL32.WriteProcessMemory(
                        process_handle,
                        section_addr,
                        section_data,
                        len(section_data),
                        ctypes.byref(bytes_written)
                    )

                    if not success:
                        logger.error(f"Failed to write section {section.Name}")
                        return False

                    logger.debug(f"Mapped section {section.Name} to {hex(section_addr)}")

            return True

        except Exception as e:
            logger.error(f"Section mapping failed: {e}")
            return False

    def _process_relocations(self, process_handle: int, pe: Any,
                           remote_base: int) -> bool:
        """Process PE relocations for new base address"""
        try:
            # Calculate delta
            delta = remote_base - pe.OPTIONAL_HEADER.ImageBase

            if delta == 0:
                logger.debug("No relocations needed")
                return True

            if not hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
                logger.warning("No relocation directory found")
                return True

            # Process each relocation block
            for reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                # Calculate page address
                page_addr = remote_base + reloc.VirtualAddress

                for entry in reloc.entries:
                    if entry.type == 0:  # IMAGE_REL_BASED_ABSOLUTE
                        continue

                    # Calculate relocation address
                    reloc_addr = page_addr + entry.rva

                    # Read current value
                    current_value = ctypes.c_ulonglong(0)
                    bytes_read = ctypes.c_size_t(0)

                    success = KERNEL32.ReadProcessMemory(
                        process_handle,
                        reloc_addr,
                        ctypes.byref(current_value),
                        8 if getattr(pe, 'PE_TYPE', 0) == getattr(pefile, 'OPTIONAL_HEADER_MAGIC_PE_PLUS', 0x20b) else 4,
                        ctypes.byref(bytes_read)
                    )

                    if not success:
                        continue

                    # Apply relocation
                    if entry.type == 3:  # IMAGE_REL_BASED_HIGHLOW
                        new_value = (current_value.value & 0xFFFFFFFF) + delta
                        write_size = 4
                    elif entry.type == 10:  # IMAGE_REL_BASED_DIR64
                        new_value = current_value.value + delta
                        write_size = 8
                    else:
                        continue

                    # Write relocated value
                    new_value_bytes = struct.pack('<Q' if write_size == 8 else '<I',
                                                new_value)
                    bytes_written = ctypes.c_size_t(0)

                    KERNEL32.WriteProcessMemory(
                        process_handle,
                        reloc_addr,
                        new_value_bytes[:write_size],
                        write_size,
                        ctypes.byref(bytes_written)
                    )

            logger.debug("Relocations processed successfully")
            return True

        except Exception as e:
            logger.error(f"Relocation processing failed: {e}")
            return False

    def _resolve_imports(self, process_handle: int, pe: Any,
                        remote_base: int) -> bool:
        """Resolve import address table"""
        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                logger.warning("No import directory found")
                return True

            # Process each import descriptor
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8')

                # Get module handle
                dll_handle = KERNEL32.GetModuleHandleW(dll_name)
                if not dll_handle:
                    # Try to load the DLL
                    dll_handle = KERNEL32.LoadLibraryW(dll_name)
                    if not dll_handle:
                        logger.error(f"Failed to load import DLL: {dll_name}")
                        continue

                # Process each import
                for imp in entry.imports:
                    # Get function address
                    if imp.ordinal:
                        func_addr = KERNEL32.GetProcAddress(dll_handle,
                                                           ctypes.c_char_p(imp.ordinal))
                    else:
                        func_addr = KERNEL32.GetProcAddress(dll_handle,
                                                           imp.name.encode('utf-8'))

                    if not func_addr:
                        logger.warning(f"Failed to resolve import: {imp.name or imp.ordinal}")
                        continue

                    # Write to IAT
                    iat_addr = remote_base + imp.address
                    addr_bytes = struct.pack('<Q' if getattr(pe, 'PE_TYPE', 0) == getattr(pefile, 'OPTIONAL_HEADER_MAGIC_PE_PLUS', 0x20b) else '<I',
                                           func_addr)
                    bytes_written = ctypes.c_size_t(0)

                    KERNEL32.WriteProcessMemory(
                        process_handle,
                        iat_addr,
                        addr_bytes,
                        len(addr_bytes),
                        ctypes.byref(bytes_written)
                    )

            logger.debug("Imports resolved successfully")
            return True

        except Exception as e:
            logger.error(f"Import resolution failed: {e}")
            return False

    def _execute_tls_callbacks(self, process_handle: int, pe: Any,
                              remote_base: int) -> None:
        """Execute TLS callbacks if present"""
        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                return

            tls = pe.DIRECTORY_ENTRY_TLS.struct
            callback_array_addr = tls.AddressOfCallBacks

            if not callback_array_addr:
                return

            # Read callback addresses
            callback_addr = callback_array_addr
            while True:
                addr_value = ctypes.c_ulonglong(0)
                bytes_read = ctypes.c_size_t(0)

                success = KERNEL32.ReadProcessMemory(
                    process_handle,
                    remote_base + callback_addr - getattr(pe.OPTIONAL_HEADER, 'ImageBase', 0),
                    ctypes.byref(addr_value),
                    8 if getattr(pe, 'PE_TYPE', 0) == getattr(pefile, 'OPTIONAL_HEADER_MAGIC_PE_PLUS', 0x20b) else 4,
                    ctypes.byref(bytes_read)
                )

                if not success or addr_value.value == 0:
                    break

                # Execute callback
                self._create_remote_thread(
                    process_handle,
                    remote_base + addr_value.value - getattr(pe.OPTIONAL_HEADER, 'ImageBase', 0),
                    remote_base
                )

                callback_addr += 8 if getattr(pe, 'PE_TYPE', 0) == getattr(pefile, 'OPTIONAL_HEADER_MAGIC_PE_PLUS', 0x20b) else 4

        except Exception as e:
            logger.debug(f"TLS callback execution error (non-critical): {e}")

    def _call_dll_entry(self, process_handle: int, pe: Any,
                       remote_base: int) -> bool:
        """Call DLL entry point"""
        try:
            # Get entry point address
            entry_point = remote_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint

            # Call DllMain with DLL_PROCESS_ATTACH
            DLL_PROCESS_ATTACH = 1

            # Create thread to call entry point
            thread_handle = KERNEL32.CreateRemoteThread(
                process_handle,
                None,
                0,
                entry_point,
                remote_base,  # hModule parameter
                DLL_PROCESS_ATTACH,  # fdwReason parameter
                None
            )

            if not thread_handle:
                logger.error("Failed to create thread for entry point")
                return False

            # Wait for completion
            KERNEL32.WaitForSingleObject(thread_handle, 5000)

            # Get exit code
            exit_code = ctypes.c_ulong(0)
            KERNEL32.GetExitCodeThread(thread_handle, ctypes.byref(exit_code))
            KERNEL32.CloseHandle(thread_handle)

            if exit_code.value == 0:
                logger.error("DLL entry point returned FALSE")
                return False

            logger.info("DLL entry point executed successfully")
            return True

        except Exception as e:
            logger.error(f"Entry point execution failed: {e}")
            return False

    def is_process_64bit(self, process_handle: int) -> Optional[bool]:
        """
        Check if a process is 64-bit
        
        Args:
            process_handle: Handle to the process
            
        Returns:
            True if 64-bit, False if 32-bit, None if error
        """
        if not WINDOWS_API_AVAILABLE:
            return None

        try:
            # Check if we're on 64-bit Windows
            is_wow64_process = ctypes.c_bool(False)

            # IsWow64Process tells us if the process is 32-bit on 64-bit Windows
            if hasattr(KERNEL32, 'IsWow64Process'):
                result = KERNEL32.IsWow64Process(process_handle, ctypes.byref(is_wow64_process))
                if result:
                    # If process is WOW64, it's 32-bit
                    # If not WOW64, it matches the system architecture
                    if is_wow64_process.value:
                        return False  # 32-bit process
                    else:
                        # Check if system is 64-bit
                        system_is_64bit = ctypes.sizeof(ctypes.c_void_p) == 8
                        return system_is_64bit

            return None

        except Exception as e:
            logger.error(f"Failed to check process architecture: {e}")
            return None

    def is_dll_64bit(self, dll_path: str) -> Optional[bool]:
        """
        Check if a DLL is 64-bit
        
        Args:
            dll_path: Path to the DLL
            
        Returns:
            True if 64-bit, False if 32-bit, None if error
        """
        if not PE_AVAILABLE:
            return None

        try:
            pe = pefile.PE(dll_path)
            # Check machine type
            machine = getattr(pe.FILE_HEADER, 'Machine', 0) if hasattr(pe, 'FILE_HEADER') else 0
            if machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                return True
            elif machine == 0x014c:  # IMAGE_FILE_MACHINE_I386
                return False
            else:
                logger.warning(f"Unknown machine type: {hex(machine)}")
                return None

        except Exception as e:
            logger.error(f"Failed to check DLL architecture: {e}")
            return None

    def inject_wow64(self, target_name: str, dll_path: str) -> bool:
        """
        Cross-architecture injection with WOW64 support
        
        Args:
            target_name: Name of the target process
            dll_path: Path to the DLL to inject
            
        Returns:
            True if injection successful, False otherwise
        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("WOW64 injection requires Windows API")
            return False

        try:
            # Get process handle for architecture checking
            process_handle = self._get_process_handle(target_name)
            if not process_handle:
                logger.error(f"Failed to get handle for process: {target_name}")
                return False

            try:
                # Check architectures
                process_is_64bit = self.is_process_64bit(process_handle)
                dll_is_64bit = self.is_dll_64bit(dll_path)
                injector_is_64bit = ctypes.sizeof(ctypes.c_void_p) == 8

                logger.info(f"Architecture check - Process: {'64-bit' if process_is_64bit else '32-bit'}, "
                           f"DLL: {'64-bit' if dll_is_64bit else '32-bit'}, "
                           f"Injector: {'64-bit' if injector_is_64bit else '32-bit'}")

                # Validate architecture compatibility
                if process_is_64bit != dll_is_64bit:
                    logger.error("Architecture mismatch: Cannot inject 32-bit DLL into 64-bit process or vice versa")
                    return False

                # Handle different scenarios
                if injector_is_64bit and not process_is_64bit:
                    # 64-bit injector -> 32-bit target
                    return self._inject_wow64_32bit(process_handle, dll_path)
                elif not injector_is_64bit and process_is_64bit:
                    # 32-bit injector -> 64-bit target (most complex)
                    return self._inject_heavens_gate_64bit(process_handle, dll_path)
                else:
                    # Same architecture - use standard injection
                    logger.info("Same architecture detected, using standard injection")
                    return self._inject_into_process(process_handle, dll_path)

            finally:
                KERNEL32.CloseHandle(process_handle)

        except Exception as e:
            logger.error(f"WOW64 injection failed: {e}")
            return False

    def _inject_wow64_32bit(self, process_handle: int, dll_path: str) -> bool:
        """
        Inject into 32-bit process from 64-bit injector
        
        Args:
            process_handle: Handle to 32-bit process
            dll_path: Path to 32-bit DLL
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # For 64-bit -> 32-bit injection, we need to use special handling
            dll_path_bytes = dll_path.encode('utf-8') + b'\x00'
            path_size = len(dll_path_bytes)

            # Allocate memory in 32-bit address space (below 4GB)
            remote_memory = KERNEL32.VirtualAllocEx(
                process_handle,
                None,
                path_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            )

            if not remote_memory:
                logger.error("Failed to allocate memory in 32-bit process")
                return False

            # Ensure address is in 32-bit range
            if remote_memory > 0xFFFFFFFF:
                logger.error("Allocated memory outside 32-bit range")
                KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                return False

            # Write DLL path
            bytes_written = ctypes.c_size_t(0)
            success = KERNEL32.WriteProcessMemory(
                process_handle,
                remote_memory,
                dll_path_bytes,
                path_size,
                ctypes.byref(bytes_written)
            )

            if not success:
                logger.error("Failed to write DLL path to 32-bit process")
                KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                return False

            # Get 32-bit kernel32.dll handle
            # We need the 32-bit version for WOW64 processes
            kernel32_32 = ctypes.WinDLL('C:\\Windows\\SysWOW64\\kernel32.dll')
            kernel32_handle = kernel32_32._handle

            # Get LoadLibraryA address from 32-bit kernel32
            load_library_addr = KERNEL32.GetProcAddress(kernel32_handle, b"LoadLibraryA")

            if not load_library_addr:
                logger.error("Failed to get LoadLibraryA address for 32-bit")
                KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                return False

            # Create remote thread
            thread_handle = KERNEL32.CreateRemoteThread(
                process_handle,
                None,
                0,
                load_library_addr & 0xFFFFFFFF,  # Ensure 32-bit address
                remote_memory & 0xFFFFFFFF,      # Ensure 32-bit address
                0,
                None
            )

            if thread_handle:
                KERNEL32.WaitForSingleObject(thread_handle, 5000)
                KERNEL32.CloseHandle(thread_handle)
                KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                logger.info("Successfully injected into 32-bit process from 64-bit injector")
                return True
            else:
                logger.error("Failed to create thread in 32-bit process")
                KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                return False

        except Exception as e:
            logger.error(f"WOW64 32-bit injection failed: {e}")
            return False

    def _inject_heavens_gate_64bit(self, process_handle: int, dll_path: str) -> bool:
        """
        Inject into 64-bit process from 32-bit injector using Heaven's Gate
        
        Args:
            process_handle: Handle to 64-bit process
            dll_path: Path to 64-bit DLL
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Heaven's Gate technique to execute 64-bit code from 32-bit process
            # This is complex and requires assembly code

            # Allocate memory for DLL path
            dll_path_bytes = dll_path.encode('utf-8') + b'\x00'
            path_size = len(dll_path_bytes)

            # Use NtWow64AllocateVirtualMemory64 if available
            ntdll = ctypes.WinDLL('ntdll.dll')

            # Allocate memory using 64-bit syscall
            remote_memory = ctypes.c_ulonglong(0)
            region_size = ctypes.c_ulonglong(path_size)

            # Try to use Wow64 functions
            if hasattr(ntdll, 'NtWow64AllocateVirtualMemory64'):
                status = ntdll.NtWow64AllocateVirtualMemory64(
                    process_handle,
                    ctypes.byref(remote_memory),
                    0,
                    ctypes.byref(region_size),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                )

                if status != 0:
                    logger.error(f"NtWow64AllocateVirtualMemory64 failed: {hex(status)}")
                    return False
            else:
                # Fallback to standard allocation
                logger.warning("Heaven's Gate not fully supported, using standard allocation")
                return self._inject_into_process(process_handle, dll_path)

            # Write DLL path using Wow64 function
            if hasattr(ntdll, 'NtWow64WriteVirtualMemory64'):
                bytes_written = ctypes.c_ulonglong(0)
                status = ntdll.NtWow64WriteVirtualMemory64(
                    process_handle,
                    remote_memory,
                    dll_path_bytes,
                    path_size,
                    ctypes.byref(bytes_written)
                )

                if status != 0:
                    logger.error(f"NtWow64WriteVirtualMemory64 failed: {hex(status)}")
                    return False
            else:
                logger.error("Cannot write to 64-bit process from 32-bit without Wow64 functions")
                return False

            # Create thread in 64-bit process
            # This requires crafting 64-bit shellcode or using undocumented APIs
            logger.warning("Full Heaven's Gate implementation requires additional low-level code")
            return False

        except Exception as e:
            logger.error(f"Heaven's Gate injection failed: {e}")
            return False

    def verify_injection(self, target_name: str, dll_name: str = None,
                        check_hooks: bool = True) -> Dict[str, Any]:
        """
        Verify that DLL was successfully injected and hooks are active
        
        Args:
            target_name: Name of the target process
            dll_name: Name of the DLL to check (optional)
            check_hooks: Whether to verify hooks are active
            
        Returns:
            Dictionary with verification results
        """
        result = {
            'process_found': False,
            'dll_loaded': False,
            'dll_path': None,
            'hooks_active': False,
            'hook_details': [],
            'modules': []
        }

        if not WINDOWS_API_AVAILABLE:
            logger.error("Injection verification requires Windows API")
            return result

        try:
            # Get process handle
            process_handle = self._get_process_handle(target_name)
            if not process_handle:
                logger.error(f"Process not found: {target_name}")
                return result

            result['process_found'] = True

            try:
                # Enumerate loaded modules
                modules = self._enumerate_modules(process_handle)
                result['modules'] = modules

                # Check if DLL is loaded
                if dll_name:
                    for module in modules:
                        if dll_name.lower() in module['name'].lower():
                            result['dll_loaded'] = True
                            result['dll_path'] = module['path']
                            logger.info(f"Found injected DLL: {module['path']}")
                            break
                else:
                    # Check for any non-system DLLs
                    for module in modules:
                        if not self._is_system_dll(module['path']):
                            result['dll_loaded'] = True
                            result['dll_path'] = module['path']
                            logger.info(f"Found injected DLL: {module['path']}")

                # Verify hooks if requested
                if check_hooks and result['dll_loaded']:
                    hook_info = self._verify_hooks(process_handle, result['dll_path'])
                    result['hooks_active'] = hook_info['active']
                    result['hook_details'] = hook_info['details']

            finally:
                KERNEL32.CloseHandle(process_handle)

        except Exception as e:
            logger.error(f"Injection verification failed: {e}")

        return result

    def _enumerate_modules(self, process_handle: int) -> List[Dict[str, str]]:
        """Enumerate all modules loaded in a process"""
        modules = []

        try:
            # Create module snapshot
            TH32CS_SNAPMODULE = 0x00000008
            TH32CS_SNAPMODULE32 = 0x00000010

            # Try both flags for 32/64-bit compatibility
            snapshot = KERNEL32.CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                self._get_process_id(process_handle)
            )

            if snapshot == -1:
                logger.error("Failed to create module snapshot")
                return modules

            try:
                # Define MODULEENTRY32 structure
                class MODULEENTRY32(ctypes.Structure):
                    _fields_ = [
                        ("dwSize", ctypes.c_ulong),
                        ("th32ModuleID", ctypes.c_ulong),
                        ("th32ProcessID", ctypes.c_ulong),
                        ("GlblcntUsage", ctypes.c_ulong),
                        ("ProccntUsage", ctypes.c_ulong),
                        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                        ("modBaseSize", ctypes.c_ulong),
                        ("hModule", ctypes.c_void_p),
                        ("szModule", ctypes.c_char * 256),
                        ("szExePath", ctypes.c_char * 260)
                    ]

                me32 = MODULEENTRY32()
                me32.dwSize = ctypes.sizeof(MODULEENTRY32)

                # Get first module
                if KERNEL32.Module32First(snapshot, ctypes.byref(me32)):
                    while True:
                        modules.append({
                            'name': me32.szModule.decode('utf-8', errors='ignore'),
                            'path': me32.szExePath.decode('utf-8', errors='ignore'),
                            'base': hex(ctypes.addressof(me32.modBaseAddr.contents) if me32.modBaseAddr else 0),
                            'size': me32.modBaseSize
                        })

                        # Get next module
                        if not KERNEL32.Module32Next(snapshot, ctypes.byref(me32)):
                            break

            finally:
                KERNEL32.CloseHandle(snapshot)

        except Exception as e:
            logger.error(f"Module enumeration failed: {e}")

        return modules

    def _get_process_id(self, process_handle: int) -> int:
        """Get process ID from handle"""
        try:
            process_id = ctypes.c_ulong(0)

            # GetProcessId is available on Windows Vista+
            if hasattr(KERNEL32, 'GetProcessId'):
                process_id.value = KERNEL32.GetProcessId(process_handle)
            else:
                # Fallback: use NtQueryInformationProcess
                ntdll = ctypes.WinDLL('ntdll.dll')

                class PROCESS_BASIC_INFORMATION(ctypes.Structure):
                    _fields_ = [
                        ("ExitStatus", ctypes.c_long),
                        ("PebBaseAddress", ctypes.c_void_p),
                        ("AffinityMask", ctypes.c_void_p),
                        ("BasePriority", ctypes.c_long),
                        ("UniqueProcessId", ctypes.c_void_p),
                        ("InheritedFromUniqueProcessId", ctypes.c_void_p)
                    ]

                pbi = PROCESS_BASIC_INFORMATION()
                status = ntdll.NtQueryInformationProcess(
                    process_handle,
                    0,  # ProcessBasicInformation
                    ctypes.byref(pbi),
                    ctypes.sizeof(pbi),
                    None
                )

                if status == 0:
                    process_id.value = pbi.UniqueProcessId

            return process_id.value

        except Exception as e:
            logger.error(f"Failed to get process ID: {e}")
            return 0

    def _is_system_dll(self, dll_path: str) -> bool:
        """Check if DLL is a system DLL"""
        if not dll_path:
            return False

        dll_path_lower = dll_path.lower()
        system_paths = [
            'c:\\windows\\system32',
            'c:\\windows\\syswow64',
            'c:\\windows\\winsxs',
            'c:\\windows\\microsoft.net'
        ]

        return any(dll_path_lower.startswith(path) for path in system_paths)

    def _verify_hooks(self, process_handle: int, dll_path: str) -> Dict[str, Any]:
        """Verify that hooks are active in the target process"""
        hook_info = {
            'active': False,
            'details': []
        }

        try:
            # Check for common hook indicators
            # 1. Check if specific functions are hooked
            hook_targets = [
                ('kernel32.dll', 'CreateFileW'),
                ('advapi32.dll', 'RegOpenKeyExW'),
                ('ws2_32.dll', 'connect'),
                ('wininet.dll', 'InternetConnectW')
            ]

            for dll, func in hook_targets:
                if self._is_function_hooked(process_handle, dll, func):
                    hook_info['active'] = True
                    hook_info['details'].append({
                        'dll': dll,
                        'function': func,
                        'status': 'hooked'
                    })

            # 2. Check for inline hooks (JMP/CALL at function start)
            if dll_path and os.path.exists(dll_path):
                inline_hooks = self._check_inline_hooks(process_handle)
                if inline_hooks:
                    hook_info['active'] = True
                    hook_info['details'].extend(inline_hooks)

        except Exception as e:
            logger.error(f"Hook verification failed: {e}")

        return hook_info

    def _is_function_hooked(self, process_handle: int, dll_name: str,
                           func_name: str) -> bool:
        """Check if a specific function is hooked"""
        try:
            # Get function address in target process
            dll_handle = KERNEL32.GetModuleHandleW(dll_name)
            if not dll_handle:
                return False

            func_addr = KERNEL32.GetProcAddress(dll_handle, func_name.encode('utf-8'))
            if not func_addr:
                return False

            # Read first 5 bytes of function
            buffer = ctypes.create_string_buffer(5)
            bytes_read = ctypes.c_size_t(0)

            success = KERNEL32.ReadProcessMemory(
                process_handle,
                func_addr,
                buffer,
                5,
                ctypes.byref(bytes_read)
            )

            if success and bytes_read.value == 5:
                # Check for common hook patterns
                # JMP (0xE9) or CALL (0xE8) at start
                if buffer[0] in [0xE9, 0xE8]:
                    return True
                # Push + Ret (0x68 + 0xC3)
                if buffer[0] == 0x68 and buffer[4] == 0xC3:
                    return True

        except Exception as e:
            logger.debug(f"Hook check failed for {dll_name}!{func_name}: {e}")

        return False

    def _check_inline_hooks(self, process_handle: int) -> List[Dict[str, str]]:
        """Check for inline hooks in the process"""
        inline_hooks = []

        # This is a simplified check - real implementation would be more thorough
        try:
            # Check common hook locations
            # Would need to walk the IAT, check function prologues, etc.
            pass

        except Exception as e:
            logger.debug(f"Inline hook check failed: {e}")

        return inline_hooks

    def inject_setwindowshookex(self, target_name: str, dll_path: str,
                               hook_type: int = None) -> bool:
        """
        Inject DLL using SetWindowsHookEx - bypasses some AV solutions
        
        Args:
            target_name: Name of target process
            dll_path: Path to the DLL to inject
            hook_type: Type of hook (WH_KEYBOARD, WH_MOUSE, etc.)
            
        Returns:
            True if injection successful, False otherwise
        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("SetWindowsHookEx injection requires Windows API")
            return False

        try:
            # Default to keyboard hook
            if hook_type is None:
                hook_type = WH_KEYBOARD

            # Get target thread ID
            thread_id = self._get_target_thread_id(target_name)
            if not thread_id:
                logger.error(f"Failed to get thread ID for process: {target_name}")
                return False

            # Load the DLL
            dll_handle = KERNEL32.LoadLibraryW(dll_path)
            if not dll_handle:
                logger.error(f"Failed to load DLL: {dll_path}")
                return False

            try:
                # Get hook procedure address
                # The DLL must export a function matching the hook type
                hook_proc_name = self._get_hook_proc_name(hook_type)
                hook_proc = KERNEL32.GetProcAddress(dll_handle, hook_proc_name.encode('utf-8'))

                if not hook_proc:
                    # Try generic hook procedure
                    hook_proc = KERNEL32.GetProcAddress(dll_handle, b"HookProc")
                    if not hook_proc:
                        logger.error(f"DLL must export {hook_proc_name} or HookProc function")
                        return False

                # Set the hook
                hook_handle = USER32.SetWindowsHookExW(
                    hook_type,
                    hook_proc,
                    dll_handle,
                    thread_id
                )

                if not hook_handle:
                    error = ctypes.get_last_error()
                    logger.error(f"SetWindowsHookEx failed with error: {error}")
                    return False

                logger.info(f"Successfully set {self._get_hook_type_name(hook_type)} hook")

                # Store hook for cleanup
                if not hasattr(self, '_active_hooks'):
                    self._active_hooks = []
                self._active_hooks.append((hook_handle, dll_handle))

                # Force the hook to be loaded by sending a message
                self._trigger_hook_load(thread_id, hook_type)

                return True

            except Exception:
                KERNEL32.FreeLibrary(dll_handle)
                raise

        except Exception as e:
            logger.error(f"SetWindowsHookEx injection failed: {e}")
            return False

    def _get_target_thread_id(self, process_name: str) -> int:
        """Get main thread ID of target process"""
        try:
            # Get process ID first
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == process_name:
                    pid = proc.info['pid']

                    # Get main thread ID
                    # Create thread snapshot
                    TH32CS_SNAPTHREAD = 0x00000004
                    snapshot = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)

                    if snapshot == -1:
                        continue

                    try:
                        # Define THREADENTRY32 structure
                        class THREADENTRY32(ctypes.Structure):
                            _fields_ = [
                                ("dwSize", ctypes.c_ulong),
                                ("cntUsage", ctypes.c_ulong),
                                ("th32ThreadID", ctypes.c_ulong),
                                ("th32OwnerProcessID", ctypes.c_ulong),
                                ("tpBasePri", ctypes.c_long),
                                ("tpDeltaPri", ctypes.c_long),
                                ("dwFlags", ctypes.c_ulong)
                            ]

                        te32 = THREADENTRY32()
                        te32.dwSize = ctypes.sizeof(THREADENTRY32)

                        # Find threads for our process
                        if KERNEL32.Thread32First(snapshot, ctypes.byref(te32)):
                            while True:
                                if te32.th32OwnerProcessID == pid:
                                    # Return first thread (usually main thread)
                                    return te32.th32ThreadID

                                if not KERNEL32.Thread32Next(snapshot, ctypes.byref(te32)):
                                    break

                    finally:
                        KERNEL32.CloseHandle(snapshot)

        except Exception as e:
            logger.error(f"Failed to get thread ID: {e}")

        return 0

    def _get_hook_proc_name(self, hook_type: int) -> str:
        """Get expected hook procedure name for hook type"""
        hook_proc_names = {
            WH_KEYBOARD: "KeyboardProc",
            WH_GETMESSAGE: "GetMsgProc",
            WH_CBT: "CBTProc",
            WH_MOUSE: "MouseProc",
            WH_KEYBOARD_LL: "LowLevelKeyboardProc",
            WH_MOUSE_LL: "LowLevelMouseProc"
        }
        return hook_proc_names.get(hook_type, "HookProc")

    def _get_hook_type_name(self, hook_type: int) -> str:
        """Get readable name for hook type"""
        hook_names = {
            WH_KEYBOARD: "WH_KEYBOARD",
            WH_GETMESSAGE: "WH_GETMESSAGE",
            WH_CBT: "WH_CBT",
            WH_MOUSE: "WH_MOUSE",
            WH_KEYBOARD_LL: "WH_KEYBOARD_LL",
            WH_MOUSE_LL: "WH_MOUSE_LL"
        }
        return hook_names.get(hook_type, f"UNKNOWN({hook_type})")

    def _trigger_hook_load(self, thread_id: int, hook_type: int) -> None:
        """Trigger hook load by sending appropriate message"""
        try:
            # Get window handle for thread
            window_handle = 0

            def enum_thread_windows_proc(hwnd, lparam):
                nonlocal window_handle
                window_handle = hwnd
                return False  # Stop enumeration

            # Create callback
            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
            enum_proc = WNDENUMPROC(enum_thread_windows_proc)

            USER32.EnumThreadWindows(thread_id, enum_proc, 0)

            if window_handle:
                # Send message to trigger hook
                if hook_type in [WH_KEYBOARD, WH_KEYBOARD_LL]:
                    # Send keyboard message
                    WM_KEYDOWN = 0x0100
                    USER32.PostMessageW(window_handle, WM_KEYDOWN, 0x41, 0)  # 'A' key
                elif hook_type in [WH_MOUSE, WH_MOUSE_LL]:
                    # Send mouse message
                    WM_MOUSEMOVE = 0x0200
                    USER32.PostMessageW(window_handle, WM_MOUSEMOVE, 0, 0)
                else:
                    # Send generic message
                    WM_NULL = 0x0000
                    USER32.PostMessageW(window_handle, WM_NULL, 0, 0)

        except Exception as e:
            logger.debug(f"Hook trigger failed (non-critical): {e}")

    def unhook_all(self) -> None:
        """Remove all active hooks"""
        if not WINDOWS_API_AVAILABLE:
            return

        if hasattr(self, '_active_hooks'):
            for hook_handle, dll_handle in self._active_hooks:
                try:
                    USER32.UnhookWindowsHookEx(hook_handle)
                    KERNEL32.FreeLibrary(dll_handle)
                except (OSError, WindowsError, Exception):
                    pass
            self._active_hooks.clear()

    def inject_apc_queue(self, target_name: str, dll_path: str,
                        wait_for_alertable: bool = True) -> bool:
        """
        Inject DLL using APC (Asynchronous Procedure Call) queue
        More stealthy than CreateRemoteThread
        
        Args:
            target_name: Name of target process
            dll_path: Path to DLL to inject
            wait_for_alertable: Wait for thread to become alertable
            
        Returns:
            True if injection successful, False otherwise
        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("APC injection requires Windows API")
            return False

        try:
            # Get process handle
            process_handle = self._get_process_handle(target_name)
            if not process_handle:
                logger.error(f"Failed to get handle for process: {target_name}")
                return False

            try:
                # Allocate memory for DLL path
                dll_path_bytes = dll_path.encode('utf-8') + b'\x00'
                path_size = len(dll_path_bytes)

                remote_memory = KERNEL32.VirtualAllocEx(
                    process_handle,
                    None,
                    path_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                )

                if not remote_memory:
                    logger.error("Failed to allocate memory in target process")
                    return False

                # Write DLL path
                bytes_written = ctypes.c_size_t(0)
                success = KERNEL32.WriteProcessMemory(
                    process_handle,
                    remote_memory,
                    dll_path_bytes,
                    path_size,
                    ctypes.byref(bytes_written)
                )

                if not success:
                    logger.error("Failed to write DLL path")
                    KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                    return False

                # Get LoadLibraryA address
                kernel32_handle = KERNEL32.GetModuleHandleW("kernel32.dll")
                load_library_addr = KERNEL32.GetProcAddress(kernel32_handle, b"LoadLibraryA")

                if not load_library_addr:
                    logger.error("Failed to get LoadLibraryA address")
                    KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                    return False

                # Find alertable threads and queue APC
                alertable_threads = self._find_alertable_threads(target_name)
                if not alertable_threads:
                    logger.warning("No alertable threads found, trying all threads")
                    alertable_threads = self._get_all_threads(target_name)

                if not alertable_threads:
                    logger.error("No threads found in target process")
                    KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                    return False

                # Queue APC to threads
                apc_queued = False
                for thread_id in alertable_threads:
                    thread_handle = KERNEL32.OpenThread(THREAD_ALL_ACCESS, False, thread_id)
                    if thread_handle:
                        try:
                            # Queue user APC
                            result = KERNEL32.QueueUserAPC(
                                load_library_addr,
                                thread_handle,
                                remote_memory
                            )

                            if result:
                                logger.info(f"APC queued to thread {thread_id}")
                                apc_queued = True

                                # Force thread to alertable state if needed
                                if wait_for_alertable:
                                    self._force_thread_alertable(thread_handle)

                        finally:
                            KERNEL32.CloseHandle(thread_handle)

                if not apc_queued:
                    logger.error("Failed to queue APC to any thread")
                    KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                    return False

                logger.info("APC injection successful")
                return True

            finally:
                KERNEL32.CloseHandle(process_handle)

        except Exception as e:
            logger.error(f"APC injection failed: {e}")
            return False

    def _find_alertable_threads(self, process_name: str) -> List[int]:
        """Find threads in alertable wait state"""
        alertable_threads = []

        try:
            # Get process ID
            pid = 0
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == process_name:
                    pid = proc.info['pid']
                    break

            if not pid:
                return alertable_threads

            # Use NtQuerySystemInformation to get thread states
            # This is a simplified version - real implementation would check wait reason
            return self._get_all_threads(process_name)[:3]  # Return first 3 threads

        except Exception as e:
            logger.debug(f"Failed to find alertable threads: {e}")
            return alertable_threads

    def _get_all_threads(self, process_name: str) -> List[int]:
        """Get all thread IDs for a process"""
        threads = []

        try:
            # Get process ID
            pid = 0
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == process_name:
                    pid = proc.info['pid']
                    break

            if not pid:
                return threads

            # Create thread snapshot
            TH32CS_SNAPTHREAD = 0x00000004
            snapshot = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)

            if snapshot == -1:
                return threads

            try:
                # Define THREADENTRY32 structure
                class THREADENTRY32(ctypes.Structure):
                    _fields_ = [
                        ("dwSize", ctypes.c_ulong),
                        ("cntUsage", ctypes.c_ulong),
                        ("th32ThreadID", ctypes.c_ulong),
                        ("th32OwnerProcessID", ctypes.c_ulong),
                        ("tpBasePri", ctypes.c_long),
                        ("tpDeltaPri", ctypes.c_long),
                        ("dwFlags", ctypes.c_ulong)
                    ]

                te32 = THREADENTRY32()
                te32.dwSize = ctypes.sizeof(THREADENTRY32)

                # Enumerate threads
                if KERNEL32.Thread32First(snapshot, ctypes.byref(te32)):
                    while True:
                        if te32.th32OwnerProcessID == pid:
                            threads.append(te32.th32ThreadID)

                        if not KERNEL32.Thread32Next(snapshot, ctypes.byref(te32)):
                            break

            finally:
                KERNEL32.CloseHandle(snapshot)

        except Exception as e:
            logger.debug(f"Failed to enumerate threads: {e}")

        return threads

    def _force_thread_alertable(self, thread_handle: int) -> None:
        """Force thread into alertable state"""
        try:
            # Suspend and resume thread to potentially trigger alertable state
            KERNEL32.SuspendThread(thread_handle)
            KERNEL32.ResumeThread(thread_handle)

            # Alternative: Use undocumented NtAlertThread
            try:
                ntdll = ctypes.WinDLL('ntdll.dll')
                if hasattr(ntdll, 'NtAlertThread'):
                    ntdll.NtAlertThread(thread_handle)
            except (OSError, AttributeError, Exception):
                pass

        except Exception as e:
            logger.debug(f"Failed to force thread alertable: {e}")

    def inject_direct_syscall(self, target_name: str, dll_path: str) -> bool:
        """
        Inject DLL using direct syscalls to bypass API hooks
        
        Args:
            target_name: Name of target process
            dll_path: Path to DLL to inject
            
        Returns:
            True if injection successful, False otherwise
        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("Direct syscall injection requires Windows")
            return False

        try:
            # Get process handle
            process_handle = self._get_process_handle(target_name)
            if not process_handle:
                logger.error(f"Failed to get handle for process: {target_name}")
                return False

            try:
                # Use direct syscalls for injection
                success = inject_using_syscalls(process_handle, dll_path)

                if success:
                    logger.info("Direct syscall injection successful")
                    self.injected.add(target_name)

                return success

            finally:
                KERNEL32.CloseHandle(process_handle)

        except Exception as e:
            logger.error(f"Direct syscall injection failed: {e}")
            return False

    def inject_reflective_dll(self, target_name: str, dll_data: bytes) -> bool:
        """
        Reflective DLL injection - inject DLL from memory without file on disk
        
        Args:
            target_name: Name of target process
            dll_data: Raw DLL data in memory
            
        Returns:
            True if injection successful, False otherwise
        """
        if not WINDOWS_API_AVAILABLE or not PE_AVAILABLE:
            logger.error("Reflective DLL injection requires Windows API and pefile")
            return False

        try:
            # Parse DLL from memory
            pe = pefile.PE(data=dll_data)

            # Get process handle
            process_handle = self._get_process_handle(target_name)
            if not process_handle:
                logger.error(f"Failed to get handle for process: {target_name}")
                return False

            try:
                # Allocate memory for the DLL and reflective loader
                image_size = pe.OPTIONAL_HEADER.SizeOfImage
                loader_size = len(self._generate_reflective_loader())
                total_size = image_size + loader_size + len(dll_data)

                remote_base = KERNEL32.VirtualAllocEx(
                    process_handle,
                    None,
                    total_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                )

                if not remote_base:
                    logger.error("Failed to allocate memory for reflective DLL")
                    return False

                logger.info(f"Allocated {total_size} bytes at {hex(remote_base)}")

                # Write the reflective loader
                loader_code = self._generate_reflective_loader()
                bytes_written = ctypes.c_size_t(0)

                success = KERNEL32.WriteProcessMemory(
                    process_handle,
                    remote_base,
                    loader_code,
                    len(loader_code),
                    ctypes.byref(bytes_written)
                )

                if not success:
                    logger.error("Failed to write reflective loader")
                    KERNEL32.VirtualFreeEx(process_handle, remote_base, 0, 0x8000)
                    return False

                # Write the DLL data after loader
                dll_data_addr = remote_base + len(loader_code)
                success = KERNEL32.WriteProcessMemory(
                    process_handle,
                    dll_data_addr,
                    dll_data,
                    len(dll_data),
                    ctypes.byref(bytes_written)
                )

                if not success:
                    logger.error("Failed to write DLL data")
                    KERNEL32.VirtualFreeEx(process_handle, remote_base, 0, 0x8000)
                    return False

                # Create thread to execute reflective loader
                thread_handle = KERNEL32.CreateRemoteThread(
                    process_handle,
                    None,
                    0,
                    remote_base,  # Start at loader
                    dll_data_addr,  # Pass DLL data address as parameter
                    0,
                    None
                )

                if not thread_handle:
                    logger.error("Failed to create thread for reflective loader")
                    KERNEL32.VirtualFreeEx(process_handle, remote_base, 0, 0x8000)
                    return False

                # Wait for loader to complete
                KERNEL32.WaitForSingleObject(thread_handle, 10000)  # 10 second timeout
                KERNEL32.CloseHandle(thread_handle)

                logger.info("Reflective DLL injection successful")
                self.injected.add(target_name)
                return True

            finally:
                KERNEL32.CloseHandle(process_handle)

        except Exception as e:
            logger.error(f"Reflective DLL injection failed: {e}")
            return False

    def _generate_reflective_loader(self) -> bytes:
        """
        Generate reflective DLL loader stub
        This is a simplified version - real implementation would be more complex
        """
        # x64 reflective loader stub
        # This would normally be written in assembly
        # For now, we'll use a placeholder that demonstrates the concept

        if ctypes.sizeof(ctypes.c_void_p) == 8:
            # 64-bit loader stub
            loader_asm = bytes([
                # Save registers
                0x50,                       # push rax
                0x51,                       # push rcx
                0x52,                       # push rdx
                0x53,                       # push rbx
                0x54,                       # push rsp
                0x55,                       # push rbp
                0x56,                       # push rsi
                0x57,                       # push rdi
                0x41, 0x50,                 # push r8
                0x41, 0x51,                 # push r9
                0x41, 0x52,                 # push r10
                0x41, 0x53,                 # push r11
                0x41, 0x54,                 # push r12
                0x41, 0x55,                 # push r13
                0x41, 0x56,                 # push r14
                0x41, 0x57,                 # push r15

                # RCX contains DLL data address
                0x48, 0x89, 0xCE,           # mov rsi, rcx

                # Call reflective loader logic
                # This would implement:
                # 1. Parse PE headers
                # 2. Allocate memory at preferred base
                # 3. Map sections
                # 4. Process relocations
                # 5. Resolve imports
                # 6. Execute TLS callbacks
                # 7. Call DllMain

                # For now, just return
                # Restore registers
                0x41, 0x5F,                 # pop r15
                0x41, 0x5E,                 # pop r14
                0x41, 0x5D,                 # pop r13
                0x41, 0x5C,                 # pop r12
                0x41, 0x5B,                 # pop r11
                0x41, 0x5A,                 # pop r10
                0x41, 0x59,                 # pop r9
                0x41, 0x58,                 # pop r8
                0x5F,                       # pop rdi
                0x5E,                       # pop rsi
                0x5D,                       # pop rbp
                0x5C,                       # pop rsp
                0x5B,                       # pop rbx
                0x5A,                       # pop rdx
                0x59,                       # pop rcx
                0x58,                       # pop rax

                0xC3                        # ret
            ])
        else:
            # 32-bit loader stub
            loader_asm = bytes([
                # Save registers
                0x60,                       # pushad

                # EBP+8 contains DLL data address
                0x8B, 0x75, 0x08,           # mov esi, [ebp+8]

                # Loader logic would go here

                # Restore registers
                0x61,                       # popad
                0xC3                        # ret
            ])

        # In a real implementation, this would be a full reflective loader
        # that can parse PE, resolve imports, and execute the DLL
        logger.warning("Using simplified reflective loader stub")
        return loader_asm

    def inject_reflective_dll_from_file(self, target_name: str, dll_path: str) -> bool:
        """
        Reflective DLL injection from file path
        
        Args:
            target_name: Name of target process
            dll_path: Path to DLL file
            
        Returns:
            True if injection successful, False otherwise
        """
        try:
            # Read DLL file into memory
            with open(dll_path, 'rb') as f:
                dll_data = f.read()

            # Inject from memory
            return self.inject_reflective_dll(target_name, dll_data)

        except Exception as e:
            logger.error(f"Failed to read DLL file: {e}")
            return False

    def unlink_dll_from_peb(self, target_name: str, dll_name: str) -> bool:
        """
        Unlink DLL from PEB to hide it from process module list
        
        Args:
            target_name: Name of target process
            dll_name: Name of DLL to hide
            
        Returns:
            True if unlinking successful, False otherwise
        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("PEB unlinking requires Windows API")
            return False

        try:
            # Get process handle
            process_handle = self._get_process_handle(target_name)
            if not process_handle:
                logger.error(f"Failed to get handle for process: {target_name}")
                return False

            try:
                # Get PEB address
                peb_addr = self._get_peb_address(process_handle)
                if not peb_addr:
                    logger.error("Failed to get PEB address")
                    return False

                # Get module list from PEB
                module_list = self._get_peb_module_list(process_handle, peb_addr)
                if not module_list:
                    logger.error("Failed to get module list from PEB")
                    return False

                # Find target DLL in list
                target_module = None
                for module in module_list:
                    if dll_name.lower() in module['name'].lower():
                        target_module = module
                        break

                if not target_module:
                    logger.error(f"DLL {dll_name} not found in module list")
                    return False

                # Unlink from all three lists
                success = True
                success &= self._unlink_from_list(process_handle, target_module, 'InLoadOrderLinks')
                success &= self._unlink_from_list(process_handle, target_module, 'InMemoryOrderLinks')
                success &= self._unlink_from_list(process_handle, target_module, 'InInitializationOrderLinks')

                if success:
                    logger.info(f"Successfully unlinked {dll_name} from PEB")
                else:
                    logger.warning("Partial PEB unlinking - some lists may still contain the module")

                return success

            finally:
                KERNEL32.CloseHandle(process_handle)

        except Exception as e:
            logger.error(f"PEB unlinking failed: {e}")
            return False

    def _get_peb_address(self, process_handle: int) -> int:
        """Get PEB address for a process"""
        try:
            # Use NtQueryInformationProcess
            ntdll = ctypes.WinDLL('ntdll.dll')

            class PROCESS_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("ExitStatus", ctypes.c_long),
                    ("PebBaseAddress", ctypes.c_void_p),
                    ("AffinityMask", ctypes.c_void_p),
                    ("BasePriority", ctypes.c_long),
                    ("UniqueProcessId", ctypes.c_void_p),
                    ("InheritedFromUniqueProcessId", ctypes.c_void_p)
                ]

            pbi = PROCESS_BASIC_INFORMATION()
            return_length = ctypes.c_ulong(0)

            status = ntdll.NtQueryInformationProcess(
                process_handle,
                0,  # ProcessBasicInformation
                ctypes.byref(pbi),
                ctypes.sizeof(pbi),
                ctypes.byref(return_length)
            )

            if status == 0:
                return pbi.PebBaseAddress
            else:
                logger.error(f"NtQueryInformationProcess failed: 0x{status:X}")
                return 0

        except Exception as e:
            logger.error(f"Failed to get PEB address: {e}")
            return 0

    def _get_peb_module_list(self, process_handle: int, peb_addr: int) -> List[Dict]:
        """Get module list from PEB"""
        modules = []

        try:
            # PEB structure offsets
            if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
                ldr_offset = 0x18
                module_list_offset = 0x10  # InLoadOrderModuleList
            else:  # 32-bit
                ldr_offset = 0x0C
                module_list_offset = 0x0C

            # Read PEB_LDR_DATA pointer
            ldr_ptr = ctypes.c_void_p(0)
            bytes_read = ctypes.c_size_t(0)

            success = KERNEL32.ReadProcessMemory(
                process_handle,
                peb_addr + ldr_offset,
                ctypes.byref(ldr_ptr),
                ctypes.sizeof(ldr_ptr),
                ctypes.byref(bytes_read)
            )

            if not success or not ldr_ptr.value:
                logger.error("Failed to read PEB_LDR_DATA pointer")
                return modules

            # Read first module entry
            first_entry = ctypes.c_void_p(0)
            success = KERNEL32.ReadProcessMemory(
                process_handle,
                ldr_ptr.value + module_list_offset,
                ctypes.byref(first_entry),
                ctypes.sizeof(first_entry),
                ctypes.byref(bytes_read)
            )

            if not success or not first_entry.value:
                logger.error("Failed to read first module entry")
                return modules

            # Walk the module list
            current_entry = first_entry.value
            while current_entry:
                module_info = self._read_ldr_data_entry(process_handle, current_entry)
                if module_info:
                    modules.append(module_info)

                # Get next entry
                next_entry = ctypes.c_void_p(0)
                KERNEL32.ReadProcessMemory(
                    process_handle,
                    current_entry,
                    ctypes.byref(next_entry),
                    ctypes.sizeof(next_entry),
                    ctypes.byref(bytes_read)
                )

                # Check if we've looped back
                if next_entry.value == first_entry.value:
                    break

                current_entry = next_entry.value

        except Exception as e:
            logger.error(f"Failed to get PEB module list: {e}")

        return modules

    def _read_ldr_data_entry(self, process_handle: int, entry_addr: int) -> Optional[Dict]:
        """Read LDR_DATA_TABLE_ENTRY"""
        try:
            # Simplified LDR_DATA_TABLE_ENTRY structure
            if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
                base_offset = 0x30
                size_offset = 0x40
                name_offset = 0x58
            else:  # 32-bit
                base_offset = 0x18
                size_offset = 0x20
                name_offset = 0x2C

            # Read DLL base
            dll_base = ctypes.c_void_p(0)
            bytes_read = ctypes.c_size_t(0)
            KERNEL32.ReadProcessMemory(
                process_handle,
                entry_addr + base_offset,
                ctypes.byref(dll_base),
                ctypes.sizeof(dll_base),
                ctypes.byref(bytes_read)
            )

            # Read module name (UNICODE_STRING)
            name_length = ctypes.c_ushort(0)
            name_buffer_ptr = ctypes.c_void_p(0)

            KERNEL32.ReadProcessMemory(
                process_handle,
                entry_addr + name_offset,
                ctypes.byref(name_length),
                2,
                ctypes.byref(bytes_read)
            )

            KERNEL32.ReadProcessMemory(
                process_handle,
                entry_addr + name_offset + 8,  # Buffer pointer offset
                ctypes.byref(name_buffer_ptr),
                ctypes.sizeof(name_buffer_ptr),
                ctypes.byref(bytes_read)
            )

            # Read name string
            if name_buffer_ptr.value and name_length.value > 0:
                name_buffer = ctypes.create_string_buffer(name_length.value + 2)
                KERNEL32.ReadProcessMemory(
                    process_handle,
                    name_buffer_ptr.value,
                    name_buffer,
                    name_length.value,
                    ctypes.byref(bytes_read)
                )

                module_name = name_buffer.raw[:name_length.value].decode('utf-16-le', errors='ignore')
            else:
                module_name = "Unknown"

            return {
                'entry_addr': entry_addr,
                'base': dll_base.value,
                'name': module_name
            }

        except Exception as e:
            logger.debug(f"Failed to read LDR entry: {e}")
            return None

    def _unlink_from_list(self, process_handle: int, module: Dict,
                         list_name: str) -> bool:
        """Unlink module from specific list"""
        try:
            # List offsets in LDR_DATA_TABLE_ENTRY
            list_offsets = {
                'InLoadOrderLinks': 0x00,
                'InMemoryOrderLinks': 0x10 if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x08,
                'InInitializationOrderLinks': 0x20 if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x10
            }

            if list_name not in list_offsets:
                return False

            list_offset = list_offsets[list_name]
            entry_addr = module['entry_addr']

            # Read Flink and Blink
            flink = ctypes.c_void_p(0)
            blink = ctypes.c_void_p(0)
            bytes_read = ctypes.c_size_t(0)

            KERNEL32.ReadProcessMemory(
                process_handle,
                entry_addr + list_offset,
                ctypes.byref(flink),
                ctypes.sizeof(flink),
                ctypes.byref(bytes_read)
            )

            KERNEL32.ReadProcessMemory(
                process_handle,
                entry_addr + list_offset + ctypes.sizeof(ctypes.c_void_p),
                ctypes.byref(blink),
                ctypes.sizeof(blink),
                ctypes.byref(bytes_read)
            )

            # Unlink: Blink->Flink = Flink
            bytes_written = ctypes.c_size_t(0)
            KERNEL32.WriteProcessMemory(
                process_handle,
                blink.value,
                ctypes.byref(flink),
                ctypes.sizeof(flink),
                ctypes.byref(bytes_written)
            )

            # Unlink: Flink->Blink = Blink
            KERNEL32.WriteProcessMemory(
                process_handle,
                flink.value + ctypes.sizeof(ctypes.c_void_p),
                ctypes.byref(blink),
                ctypes.sizeof(blink),
                ctypes.byref(bytes_written)
            )

            logger.debug(f"Unlinked from {list_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to unlink from {list_name}: {e}")
            return False

    def inject_process_hollowing(self, target_exe: str, payload_exe: str) -> bool:
        """
        Use process hollowing injection technique
        
        Args:
            target_exe: Path to legitimate executable to hollow
            payload_exe: Path to payload executable
            
        Returns:
            True if successful, False otherwise
        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("Process hollowing requires Windows")
            return False

        try:
            logger.info(f"Attempting process hollowing: {target_exe}")

            # Use the imported function
            success = perform_process_hollowing(target_exe, payload_exe)

            if success:
                logger.info("Process hollowing successful")
            else:
                logger.error("Process hollowing failed")

            return success

        except Exception as e:
            logger.error(f"Process hollowing exception: {e}")
            return False

    def inject_kernel_driver(self, target_pid: int, dll_path: str) -> bool:
        """
        Use kernel driver injection technique
        
        Args:
            target_pid: Target process ID
            dll_path: Path to DLL to inject
            
        Returns:
            True if successful, False otherwise
        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("Kernel injection requires Windows")
            return False

        try:
            logger.info(f"Attempting kernel driver injection into PID {target_pid}")

            # Use the imported function
            success = inject_via_kernel_driver(target_pid, dll_path)

            if success:
                logger.info("Kernel driver injection successful")
            else:
                logger.error("Kernel driver injection failed")

            return success

        except Exception as e:
            logger.error(f"Kernel injection exception: {e}")
            return False

    def inject_early_bird(self, target_exe: str, dll_path: str,
                         command_line: str = None) -> bool:
        """
        Use Early Bird injection technique
        
        Args:
            target_exe: Path to target executable
            dll_path: Path to DLL to inject
            command_line: Optional command line arguments
            
        Returns:
            True if successful, False otherwise
        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("Early Bird injection requires Windows")
            return False

        try:
            logger.info(f"Attempting Early Bird injection: {target_exe}")

            # Use the imported function
            success = perform_early_bird_injection(target_exe, dll_path, command_line)

            if success:
                logger.info("Early Bird injection successful")
            else:
                logger.error("Early Bird injection failed")

            return success

        except Exception as e:
            logger.error(f"Early Bird injection exception: {e}")
            return False

    def get_injection_status(self) -> dict:
        """
        Get current injection status

        Returns:
            Dictionary with injection statistics
        """
        return {
            'injected_processes': list(self.injected),
            'running_adobe_processes': self.get_running_adobe_processes(),
            'dependencies_available': DEPENDENCIES_AVAILABLE,
            'monitoring_active': self.running
        }


def create_adobe_injector() -> AdobeInjector:
    """
    Factory function to create Adobe injector instance

    Returns:
        Configured AdobeInjector instance
    """
    return AdobeInjector()


# Convenience functions for direct usage
def inject_running_adobe_processes() -> int:
    """
    One-shot injection of all currently running Adobe processes

    Returns:
        Number of processes successfully injected
    """
    injector = create_adobe_injector()
    processes = injector.get_running_adobe_processes()

    success_count = 0
    for proc_name in processes:
        if injector.inject_process(proc_name):
            success_count += 1

    return success_count


def start_adobe_monitoring(interval: float = 2.0) -> AdobeInjector:
    """
    Start continuous Adobe process monitoring

    Args:
        interval: Sleep interval between scans

    Returns:
        AdobeInjector instance for control
    """
    injector = create_adobe_injector()
    injector.monitor_and_inject(interval)
    return injector
