"""
Kernel-level injection using Windows driver

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
import os
import struct
import tempfile
from typing import Optional, Tuple

from ...utils.logger import get_logger
from ...utils.windows_common import is_windows_available, get_windows_kernel32

logger = get_logger(__name__)

# Check Windows availability using common utility
AVAILABLE = is_windows_available()

class KernelInjector:
    """Kernel-level injection using Windows driver"""
    
    def __init__(self):
        if not AVAILABLE:
            raise RuntimeError("Kernel injection requires Windows")
            
        self.driver_handle = None
        self.driver_path = None
        self.service_name = "IntellicrackDrv"
        self._setup_api()
        
    def _setup_api(self):
        """Setup Windows API for driver operations"""
        self.kernel32 = get_windows_kernel32()
        if not self.kernel32:
            raise RuntimeError("Failed to load kernel32")
        try:
            self.advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        except Exception as e:
            logger.error(f"Failed to load advapi32: {e}")
            raise RuntimeError("Failed to load advapi32")
        
        # Service control constants
        self.SC_MANAGER_ALL_ACCESS = 0xF003F
        self.SERVICE_ALL_ACCESS = 0xF01FF
        self.SERVICE_KERNEL_DRIVER = 0x00000001
        self.SERVICE_DEMAND_START = 0x00000003
        self.SERVICE_ERROR_NORMAL = 0x00000001
        self.SERVICE_CONTROL_STOP = 0x00000001
        
        # Device IO control codes
        self.FILE_DEVICE_UNKNOWN = 0x00000022
        self.METHOD_BUFFERED = 0
        self.FILE_ANY_ACCESS = 0
        
        # Custom IOCTL codes
        self.IOCTL_INJECT_DLL = self._ctl_code(
            self.FILE_DEVICE_UNKNOWN,
            0x800,
            self.METHOD_BUFFERED,
            self.FILE_ANY_ACCESS
        )
        
    def _ctl_code(self, device_type: int, function: int, method: int, access: int) -> int:
        """Calculate Windows IOCTL code"""
        return (device_type << 16) | (access << 14) | (function << 2) | method
        
    def inject_kernel_mode(self, target_pid: int, dll_path: str) -> bool:
        """
        Inject DLL using kernel driver
        
        Args:
            target_pid: Target process ID
            dll_path: Path to DLL to inject
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create driver if not exists
            if not self._create_driver():
                logger.error("Failed to create kernel driver")
                return False
                
            # Install and start driver
            if not self._install_driver():
                logger.error("Failed to install driver")
                return False
                
            # Open handle to driver
            if not self._open_driver():
                logger.error("Failed to open driver")
                return False
                
            # Send injection command
            if not self._send_injection_command(target_pid, dll_path):
                logger.error("Failed to send injection command")
                return False
                
            logger.info(f"Successfully injected via kernel driver into PID {target_pid}")
            return True
            
        except Exception as e:
            logger.error(f"Kernel injection failed: {e}")
            return False
        finally:
            self._cleanup()
            
    def _create_driver(self) -> bool:
        """Create kernel driver binary"""
        try:
            # Driver binary (simplified stub - real driver would need proper development)
            # This is a minimal driver that accepts IOCTL for injection
            driver_code = self._get_driver_stub()
            
            # Save to temp file
            temp_dir = tempfile.gettempdir()
            self.driver_path = os.path.join(temp_dir, f"{self.service_name}.sys")
            
            with open(self.driver_path, 'wb') as f:
                f.write(driver_code)
                
            logger.info(f"Created driver at {self.driver_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create driver: {e}")
            return False
            
    def _get_driver_stub(self) -> bytes:
        """Get minimal driver stub (would need real driver development)"""
        # This is a placeholder - real implementation would require:
        # 1. Proper Windows kernel driver development
        # 2. Digital signature for x64 systems
        # 3. Injection routines in kernel space
        
        # For now, return a minimal valid PE driver structure
        # Real driver would implement:
        # - DriverEntry routine
        # - Device creation
        # - IOCTL handling
        # - APC injection or other kernel techniques
        
        logger.warning("Using placeholder driver stub - real implementation needed")
        
        # Minimal DOS header
        dos_header = b'MZ' + b'\x00' * 58 + struct.pack('<I', 0x80)  # PE offset
        
        # Minimal PE header
        pe_header = b'PE\x00\x00'
        pe_header += struct.pack('<H', 0x8664)  # Machine (x64)
        pe_header += struct.pack('<H', 1)       # Number of sections
        pe_header += b'\x00' * 12               # Timestamps
        pe_header += struct.pack('<H', 0xA0)    # Size of optional header
        pe_header += struct.pack('<H', 0x22)    # Characteristics (driver)
        
        # Optional header
        opt_header = struct.pack('<H', 0x20B)   # Magic (PE32+)
        opt_header += b'\x00' * 158              # Simplified optional header
        
        # Section header (.text)
        section = b'.text\x00\x00\x00'
        section += struct.pack('<I', 0x1000)     # Virtual size
        section += struct.pack('<I', 0x1000)     # Virtual address
        section += struct.pack('<I', 0x200)      # Size of raw data
        section += struct.pack('<I', 0x200)      # Pointer to raw data
        section += b'\x00' * 16                  # Relocations/line numbers
        section += struct.pack('<I', 0x60000020) # Characteristics
        
        # Padding
        padding = b'\x00' * (0x200 - len(dos_header) - len(pe_header) - len(opt_header) - len(section))
        
        # Driver code (minimal - just returns)
        # Real driver would implement full injection logic
        driver_code = b'\xC3' * 0x200  # RET instructions
        
        return dos_header + pe_header + opt_header + section + padding + driver_code
        
    def _install_driver(self) -> bool:
        """Install driver as Windows service"""
        try:
            # Open service control manager
            sc_manager = self.advapi32.OpenSCManagerW(
                None,
                None,
                self.SC_MANAGER_ALL_ACCESS
            )
            
            if not sc_manager:
                error = ctypes.get_last_error()
                logger.error(f"OpenSCManager failed: {error}")
                return False
                
            try:
                # Create service
                service = self.advapi32.CreateServiceW(
                    sc_manager,
                    self.service_name,
                    self.service_name,
                    self.SERVICE_ALL_ACCESS,
                    self.SERVICE_KERNEL_DRIVER,
                    self.SERVICE_DEMAND_START,
                    self.SERVICE_ERROR_NORMAL,
                    self.driver_path,
                    None,
                    None,
                    None,
                    None,
                    None
                )
                
                if not service:
                    error = ctypes.get_last_error()
                    # ERROR_SERVICE_EXISTS = 1073
                    if error == 1073:
                        # Service exists, open it
                        service = self.advapi32.OpenServiceW(
                            sc_manager,
                            self.service_name,
                            self.SERVICE_ALL_ACCESS
                        )
                        if not service:
                            logger.error("Failed to open existing service")
                            return False
                    else:
                        logger.error(f"CreateService failed: {error}")
                        return False
                        
                # Start service
                success = self.advapi32.StartServiceW(service, 0, None)
                if not success:
                    error = ctypes.get_last_error()
                    # ERROR_SERVICE_ALREADY_RUNNING = 1056
                    if error != 1056:
                        logger.error(f"StartService failed: {error}")
                        self.advapi32.CloseServiceHandle(service)
                        return False
                        
                self.advapi32.CloseServiceHandle(service)
                logger.info("Driver service installed and started")
                return True
                
            finally:
                self.advapi32.CloseServiceHandle(sc_manager)
                
        except Exception as e:
            logger.error(f"Failed to install driver: {e}")
            return False
            
    def _open_driver(self) -> bool:
        """Open handle to driver device"""
        try:
            # Device name for our driver
            device_name = f"\\\\.\\{self.service_name}"
            
            # Open device
            self.driver_handle = self.kernel32.CreateFileW(
                device_name,
                0xC0000000,  # GENERIC_READ | GENERIC_WRITE
                0,           # No sharing
                None,
                3,           # OPEN_EXISTING
                0,           # Normal attributes
                None
            )
            
            if self.driver_handle == -1:
                error = ctypes.get_last_error()
                logger.error(f"CreateFile failed: {error}")
                self.driver_handle = None
                return False
                
            logger.info("Opened handle to driver")
            return True
            
        except Exception as e:
            logger.error(f"Failed to open driver: {e}")
            return False
            
    def _send_injection_command(self, target_pid: int, dll_path: str) -> bool:
        """Send injection command to driver"""
        try:
            if not self.driver_handle:
                return False
                
            # Prepare injection structure
            class INJECTION_INFO(ctypes.Structure):
                _fields_ = [
                    ("ProcessId", ctypes.c_ulong),
                    ("DllPath", ctypes.c_wchar * 260)
                ]
                
            info = INJECTION_INFO()
            info.ProcessId = target_pid
            info.DllPath = dll_path
            
            bytes_returned = ctypes.c_ulong()
            
            # Send IOCTL to driver
            success = self.kernel32.DeviceIoControl(
                self.driver_handle,
                self.IOCTL_INJECT_DLL,
                ctypes.byref(info),
                ctypes.sizeof(info),
                None,
                0,
                ctypes.byref(bytes_returned),
                None
            )
            
            if not success:
                error = ctypes.get_last_error()
                logger.error(f"DeviceIoControl failed: {error}")
                return False
                
            logger.info("Injection command sent to driver")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send injection command: {e}")
            return False
            
    def _cleanup(self):
        """Clean up driver resources"""
        try:
            # Close driver handle
            if self.driver_handle:
                self.kernel32.CloseHandle(self.driver_handle)
                self.driver_handle = None
                
            # Stop and remove service
            self._remove_driver_service()
            
            # Delete driver file
            if self.driver_path and os.path.exists(self.driver_path):
                try:
                    os.remove(self.driver_path)
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
            
    def _remove_driver_service(self):
        """Remove driver service"""
        try:
            sc_manager = self.advapi32.OpenSCManagerW(
                None,
                None,
                self.SC_MANAGER_ALL_ACCESS
            )
            
            if not sc_manager:
                return
                
            try:
                service = self.advapi32.OpenServiceW(
                    sc_manager,
                    self.service_name,
                    self.SERVICE_ALL_ACCESS
                )
                
                if service:
                    # Stop service
                    service_status = ctypes.c_byte * 36
                    self.advapi32.ControlService(
                        service,
                        self.SERVICE_CONTROL_STOP,
                        ctypes.byref(service_status())
                    )
                    
                    # Delete service
                    self.advapi32.DeleteService(service)
                    self.advapi32.CloseServiceHandle(service)
                    
            finally:
                self.advapi32.CloseServiceHandle(sc_manager)
                
        except Exception as e:
            logger.error(f"Failed to remove service: {e}")


def inject_via_kernel_driver(target_pid: int, dll_path: str) -> bool:
    """
    Convenience function for kernel-level injection
    
    Args:
        target_pid: Target process ID
        dll_path: Path to DLL
        
    Returns:
        True if successful, False otherwise
    """
    if not AVAILABLE:
        logger.error("Kernel injection not available on this platform")
        return False
        
    try:
        injector = KernelInjector()
        return injector.inject_kernel_mode(target_pid, dll_path)
    except Exception as e:
        logger.error(f"Kernel injection failed: {e}")
        return False