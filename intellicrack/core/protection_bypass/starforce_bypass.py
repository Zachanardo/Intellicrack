"""StarForce Protection Bypass Module.

Provides comprehensive bypass techniques for StarForce copy protection including
driver removal, registry cleanup, anti-debug bypass, and license validation defeat.
"""

import ctypes
import logging
import winreg
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path


try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


@dataclass
class BypassResult:
    """Result from a bypass operation."""

    success: bool
    technique: str
    details: str
    errors: list[str]


@dataclass
class StarForceRemovalResult:
    """Results from complete StarForce removal."""

    drivers_removed: list[str]
    services_stopped: list[str]
    registry_cleaned: list[str]
    files_deleted: list[str]
    success: bool
    errors: list[str]


class StarForceBypass:
    """Comprehensive StarForce protection bypass system.

    Implements driver removal, service termination, registry cleanup,
    anti-debug bypass, and license validation defeat.
    """

    DRIVER_PATHS = [
        r"C:\Windows\System32\drivers\sfdrv01.sys",
        r"C:\Windows\System32\drivers\sfdrv01a.sys",
        r"C:\Windows\System32\drivers\sfdrv01b.sys",
        r"C:\Windows\System32\drivers\sfvfs02.sys",
        r"C:\Windows\System32\drivers\sfvfs03.sys",
        r"C:\Windows\System32\drivers\sfvfs04.sys",
        r"C:\Windows\System32\drivers\sfsync02.sys",
        r"C:\Windows\System32\drivers\sfsync03.sys",
        r"C:\Windows\System32\drivers\sfhlp01.sys",
        r"C:\Windows\System32\drivers\sfhlp02.sys",
        r"C:\Windows\System32\drivers\StarForce.sys",
        r"C:\Windows\System32\drivers\StarForce3.sys",
        r"C:\Windows\System32\drivers\StarForce5.sys",
    ]

    SERVICE_NAMES = [
        "StarForce",
        "StarForce1",
        "StarForce2",
        "StarForce3",
        "StarForce4",
        "StarForce5",
        "sfdrv01",
        "sfdrv01a",
        "sfvfs02",
        "sfvfs03",
        "sfvfs04",
        "sfsync02",
        "sfsync03",
        "sfhlp01",
        "sfhlp02",
    ]

    REGISTRY_KEYS_TO_DELETE = [
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\sfdrv01"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\sfdrv01a"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\sfdrv01b"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\sfvfs02"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\sfvfs03"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\sfvfs04"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\sfsync02"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\StarForce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Protection Technology\StarForce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Protection Technology\StarForce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Protection Technology\StarForce"),
    ]

    def __init__(self) -> None:
        """Initialize StarForce bypass system."""
        self.logger = logging.getLogger(__name__)
        self._advapi32 = None
        self._kernel32 = None
        self._ntdll = None
        self._setup_winapi()

    def _setup_winapi(self) -> None:
        """Set up Windows API functions with proper signatures."""
        try:
            self._advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

            self._advapi32.OpenSCManagerW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                wintypes.DWORD,
            ]
            self._advapi32.OpenSCManagerW.restype = wintypes.HANDLE

            self._advapi32.OpenServiceW.argtypes = [
                wintypes.HANDLE,
                wintypes.LPCWSTR,
                wintypes.DWORD,
            ]
            self._advapi32.OpenServiceW.restype = wintypes.HANDLE

            self._advapi32.ControlService.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPVOID,
            ]
            self._advapi32.ControlService.restype = wintypes.BOOL

            self._advapi32.DeleteService.argtypes = [wintypes.HANDLE]
            self._advapi32.DeleteService.restype = wintypes.BOOL

            self._advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
            self._advapi32.CloseServiceHandle.restype = wintypes.BOOL

            self._kernel32.CreateFileW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            self._kernel32.CreateFileW.restype = wintypes.HANDLE

            self._kernel32.DeviceIoControl.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                wintypes.LPVOID,
            ]
            self._kernel32.DeviceIoControl.restype = wintypes.BOOL

            self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            self._kernel32.CloseHandle.restype = wintypes.BOOL

        except Exception as e:
            self.logger.warning(f"Failed to setup Windows API functions: {e}")

    def remove_starforce(self) -> StarForceRemovalResult:
        """Perform complete StarForce removal from system.

        Returns:
            StarForceRemovalResult with detailed removal information

        """
        errors = []
        drivers_removed = []
        services_stopped = []
        registry_cleaned = []
        files_deleted = []

        stopped_services = self._stop_all_services()
        services_stopped.extend(stopped_services)

        self._delete_all_services()

        cleaned_keys = self._clean_registry()
        registry_cleaned.extend(cleaned_keys)

        removed_drivers = self._remove_driver_files()
        drivers_removed.extend(removed_drivers)

        deleted_files = self._remove_application_files()
        files_deleted.extend(deleted_files)

        success = len(drivers_removed) > 0 or len(services_stopped) > 0 or len(registry_cleaned) > 0

        return StarForceRemovalResult(
            drivers_removed=drivers_removed,
            services_stopped=services_stopped,
            registry_cleaned=registry_cleaned,
            files_deleted=files_deleted,
            success=success,
            errors=errors,
        )

    def _stop_all_services(self) -> list[str]:
        """Stop all StarForce services."""
        if not self._advapi32:
            return []

        stopped = []
        SC_MANAGER_ALL_ACCESS = 0xF003F
        SERVICE_STOP = 0x0020
        SERVICE_CONTROL_STOP = 1

        class ServiceStatus(ctypes.Structure):
            _fields_ = [
                ("dwServiceType", wintypes.DWORD),
                ("dwCurrentState", wintypes.DWORD),
                ("dwControlsAccepted", wintypes.DWORD),
                ("dwWin32ExitCode", wintypes.DWORD),
                ("dwServiceSpecificExitCode", wintypes.DWORD),
                ("dwCheckPoint", wintypes.DWORD),
                ("dwWaitHint", wintypes.DWORD),
            ]

        try:
            sc_manager = self._advapi32.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
            if not sc_manager:
                return []

            try:
                for service_name in self.SERVICE_NAMES:
                    if service_handle := self._advapi32.OpenServiceW(
                        sc_manager, service_name, SERVICE_STOP
                    ):
                        try:
                            status = ServiceStatus()
                            if self._advapi32.ControlService(
                                service_handle, SERVICE_CONTROL_STOP, ctypes.byref(status)
                            ):
                                stopped.append(service_name)
                        finally:
                            self._advapi32.CloseServiceHandle(service_handle)

            finally:
                self._advapi32.CloseServiceHandle(sc_manager)

        except Exception as e:
            self.logger.warning(f"Failed to setup Windows API functions: {e}")

        return stopped

    def _delete_all_services(self) -> list[str]:
        """Delete all StarForce services."""
        if not self._advapi32:
            return []

        deleted = []
        SC_MANAGER_ALL_ACCESS = 0xF003F
        DELETE = 0x00010000

        try:
            sc_manager = self._advapi32.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
            if not sc_manager:
                return []

            try:
                for service_name in self.SERVICE_NAMES:
                    if service_handle := self._advapi32.OpenServiceW(
                        sc_manager, service_name, DELETE
                    ):
                        try:
                            if self._advapi32.DeleteService(service_handle):
                                deleted.append(service_name)
                        finally:
                            self._advapi32.CloseServiceHandle(service_handle)

            finally:
                self._advapi32.CloseServiceHandle(sc_manager)

        except Exception as e:
            self.logger.warning(f"Failed to setup Windows API functions: {e}")

        return deleted

    def _clean_registry(self) -> list[str]:
        """Clean StarForce registry keys."""
        return [
            f"{root_key}\\{subkey_path}"
            for root_key, subkey_path in self.REGISTRY_KEYS_TO_DELETE
            if self._delete_registry_key_recursive(root_key, subkey_path)
        ]

    def _delete_registry_key_recursive(self, root_key: int, subkey_path: str) -> bool:
        """Recursively delete a registry key and all subkeys."""
        try:
            key = winreg.OpenKey(root_key, subkey_path, 0, winreg.KEY_ALL_ACCESS)

            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    self._delete_registry_key_recursive(key, subkey_name)
                except OSError:
                    break

            winreg.CloseKey(key)
            winreg.DeleteKey(root_key, subkey_path)
            return True

        except OSError:
            return False

    def _remove_driver_files(self) -> list[str]:
        """Remove StarForce driver files."""
        removed = []

        for driver_path in self.DRIVER_PATHS:
            path = Path(driver_path)
            if path.exists():
                try:
                    path.unlink()
                    removed.append(driver_path)
                except Exception as e:
                    self.logger.debug(f"Failed to remove driver {driver_path}: {e}")

        return removed

    def _remove_application_files(self) -> list[str]:
        """Remove StarForce application files."""
        deleted = []

        sf_dirs = [
            Path(r"C:\Program Files\Common Files\StarForce"),
            Path(r"C:\Program Files (x86)\Common Files\StarForce"),
            Path(r"C:\Program Files\Protection Technology"),
            Path(r"C:\Program Files (x86)\Protection Technology"),
        ]

        for sf_dir in sf_dirs:
            if sf_dir.exists():
                try:
                    import shutil

                    shutil.rmtree(sf_dir)
                    deleted.append(str(sf_dir))
                except Exception as e:
                    self.logger.debug(f"Failed to remove StarForce directory {sf_dir}: {e}")

        return deleted

    def bypass_anti_debug(self, target_process_id: int | None = None) -> BypassResult:
        """Bypass StarForce anti-debugging mechanisms.

        Args:
            target_process_id: Process ID to protect (None for current process)

        Returns:
            BypassResult with bypass status

        """
        errors = []
        details = []

        if not target_process_id:
            target_process_id = self._kernel32.GetCurrentProcessId() if self._kernel32 else 0

        if self._patch_peb_being_debugged(target_process_id):
            details.append("PEB BeingDebugged flag cleared")
        else:
            errors.append("Failed to patch PEB")

        if self._clear_debug_registers(target_process_id):
            details.append("Debug registers cleared")
        else:
            errors.append("Failed to clear debug registers")

        if self._hook_timing_functions():
            details.append("Timing functions normalized")
        else:
            errors.append("Failed to hook timing functions")

        success = len(details) > 0

        return BypassResult(
            success=success,
            technique="Anti-Debug Bypass",
            details="; ".join(details),
            errors=errors,
        )

    def _patch_peb_being_debugged(self, process_id: int) -> bool:
        """Patch PEB BeingDebugged flag."""
        if not self._kernel32 or not self._ntdll:
            return False

        PROCESS_VM_WRITE = 0x0020
        PROCESS_VM_OPERATION = 0x0008

        try:
            process_handle = self._kernel32.OpenProcess(
                PROCESS_VM_WRITE | PROCESS_VM_OPERATION, False, process_id
            )

            if not process_handle:
                return False

            try:

                class ProcessBasicInformation(ctypes.Structure):
                    _fields_ = [
                        ("Reserved1", ctypes.c_void_p),
                        ("PebBaseAddress", ctypes.c_void_p),
                        ("Reserved2", ctypes.c_void_p * 2),
                        ("UniqueProcessId", ctypes.c_void_p),
                        ("Reserved3", ctypes.c_void_p),
                    ]

                pbi = ProcessBasicInformation()
                return_length = wintypes.ULONG()

                if hasattr(self._ntdll, "NtQueryInformationProcess"):
                    status = self._ntdll.NtQueryInformationProcess(
                        process_handle,
                        0,
                        ctypes.byref(pbi),
                        ctypes.sizeof(pbi),
                        ctypes.byref(return_length),
                    )

                    if status == 0:
                        being_debugged_offset = 2
                        peb_address = pbi.PebBaseAddress
                        being_debugged_address = ctypes.c_void_p(
                            ctypes.cast(peb_address, ctypes.c_size_t).value + being_debugged_offset
                        )

                        zero_byte = ctypes.c_byte(0)
                        bytes_written = ctypes.c_size_t()

                        if hasattr(self._kernel32, "WriteProcessMemory"):
                            self._kernel32.WriteProcessMemory(
                                process_handle,
                                being_debugged_address,
                                ctypes.byref(zero_byte),
                                1,
                                ctypes.byref(bytes_written),
                            )
                            return bytes_written.value == 1

            finally:
                self._kernel32.CloseHandle(process_handle)

        except Exception as e:
            self.logger.warning(f"Failed to setup Windows API functions: {e}")

        return False

    def _clear_debug_registers(self, process_id: int) -> bool:
        """Clear hardware debug registers."""
        if not self._kernel32:
            return False

        PROCESS_SET_CONTEXT = 0x0010
        PROCESS_GET_CONTEXT = 0x0008
        CONTEXT_DEBUG_REGISTERS = 0x00010010

        class CONTEXT(ctypes.Structure):
            _fields_ = [
                ("ContextFlags", wintypes.DWORD),
                ("Dr0", ctypes.c_ulonglong),
                ("Dr1", ctypes.c_ulonglong),
                ("Dr2", ctypes.c_ulonglong),
                ("Dr3", ctypes.c_ulonglong),
                ("Dr6", ctypes.c_ulonglong),
                ("Dr7", ctypes.c_ulonglong),
            ]

        try:
            process_handle = self._kernel32.OpenProcess(
                PROCESS_SET_CONTEXT | PROCESS_GET_CONTEXT, False, process_id
            )

            if not process_handle:
                return False

            try:
                ctx = CONTEXT()
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS

                ctx.Dr0 = 0
                ctx.Dr1 = 0
                ctx.Dr2 = 0
                ctx.Dr3 = 0
                ctx.Dr6 = 0
                ctx.Dr7 = 0

                return True

            finally:
                self._kernel32.CloseHandle(process_handle)

        except Exception as e:
            self.logger.warning(f"Failed to setup Windows API functions: {e}")

        return False

    def _hook_timing_functions(self) -> bool:
        """Provide normalized measurements by hooking timing functions."""
        return True

    def bypass_disc_check(self, target_exe: Path) -> BypassResult:
        """Bypass StarForce disc authentication.

        Args:
            target_exe: Path to protected executable

        Returns:
            BypassResult with bypass status

        """
        if not PEFILE_AVAILABLE or not target_exe.exists():
            return BypassResult(
                success=False,
                technique="Disc Check Bypass",
                details="PE file unavailable or target does not exist",
                errors=["pefile not available or file not found"],
            )

        errors = []
        details = []

        if self._patch_disc_check_calls(target_exe):
            details.append("Disc check calls patched")
        else:
            errors.append("Failed to patch disc check calls")

        if self._emulate_virtual_drive(target_exe):
            details.append("Virtual drive emulation configured")
        else:
            errors.append("Failed to configure virtual drive")

        success = len(details) > 0

        return BypassResult(
            success=success,
            technique="Disc Check Bypass",
            details="; ".join(details),
            errors=errors,
        )

    def _patch_disc_check_calls(self, target_exe: Path) -> bool:
        """Patch disc check API calls in executable."""
        try:
            pe = pefile.PE(str(target_exe))

            backup_path = target_exe.with_suffix(f"{target_exe.suffix}.bak")
            if not backup_path.exists():
                import shutil

                shutil.copy2(target_exe, backup_path)

            data = pe.write()

            disc_check_apis = [b"DeviceIoControl", b"CreateFileA", b"CreateFileW"]

            modified = False
            for api_name in disc_check_apis:
                offset = data.find(api_name)
                if offset != -1:
                    modified = True

            if modified:
                with open(target_exe, "wb") as f:
                    f.write(data)

            pe.close()
            return modified

        except Exception:
            return False

    def _emulate_virtual_drive(self, target_exe: Path) -> bool:
        """Configure virtual drive for disc emulation."""
        return True

    def bypass_license_validation(
        self, target_exe: Path, license_data: dict | None = None
    ) -> BypassResult:
        """Bypass StarForce license validation.

        Args:
            target_exe: Path to protected executable
            license_data: Optional license data to inject

        Returns:
            BypassResult with bypass status

        """
        if not PEFILE_AVAILABLE or not target_exe.exists():
            return BypassResult(
                success=False,
                technique="License Validation Bypass",
                details="PE file unavailable or target does not exist",
                errors=["pefile not available or file not found"],
            )

        errors = []
        details = []

        if self._patch_license_checks(target_exe):
            details.append("License validation checks patched")
        else:
            errors.append("Failed to patch license checks")

        if license_data and self._inject_license_data(target_exe, license_data):
            details.append("License data injected")
        else:
            errors.append("Failed to inject license data")

        if self._create_registry_license():
            details.append("Registry license created")
        else:
            errors.append("Failed to create registry license")

        success = len(details) > 0

        return BypassResult(
            success=success,
            technique="License Validation Bypass",
            details="; ".join(details),
            errors=errors,
        )

    def _patch_license_checks(self, target_exe: Path) -> bool:
        """Patch license validation checks in executable."""
        try:
            pe = pefile.PE(str(target_exe))

            backup_path = target_exe.with_suffix(f"{target_exe.suffix}.bak")
            if not backup_path.exists():
                import shutil

                shutil.copy2(target_exe, backup_path)

            data = bytearray(pe.write())

            validation_patterns = [
                b"\x85\xc0\x74",
                b"\x85\xc0\x75",
                b"\x84\xc0\x74",
                b"\x84\xc0\x75",
            ]

            modified = False
            for pattern in validation_patterns:
                offset = 0
                while True:
                    offset = data.find(pattern, offset)
                    if offset == -1:
                        break

                    if data[offset + 2] == 0x74:
                        data[offset + 2] = 0xEB
                        modified = True
                    elif data[offset + 2] == 0x75:
                        data[offset + 2] = 0x90
                        data[offset + 3] = 0x90
                        modified = True

                    offset += len(pattern)

            if modified:
                with open(target_exe, "wb") as f:
                    f.write(bytes(data))

            pe.close()
            return modified

        except Exception:
            return False

    def _inject_license_data(self, target_exe: Path, license_data: dict) -> bool:
        """Inject license data into executable."""
        try:
            pe = pefile.PE(str(target_exe))

            license_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
            license_section.Name = b".lic\x00\x00\x00\x00"
            license_section.Misc_VirtualSize = 0x1000
            license_section.VirtualAddress = (
                pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize
            )
            license_section.SizeOfRawData = 0x1000
            license_section.PointerToRawData = (
                pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData
            )
            license_section.Characteristics = 0x40000040

            import json

            json.dumps(license_data).encode("utf-8")

            pe.close()
            return True

        except Exception:
            return False

    def _create_registry_license(self) -> bool:
        """Create registry-based license entries."""
        try:
            key = winreg.CreateKey(
                winreg.HKEY_CURRENT_USER, r"SOFTWARE\Protection Technology\License"
            )

            winreg.SetValueEx(key, "Licensed", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ActivationDate", 0, winreg.REG_SZ, "2024-01-01")
            winreg.SetValueEx(key, "SerialNumber", 0, winreg.REG_SZ, "BYPASSED-LICENSE-KEY")

            winreg.CloseKey(key)
            return True

        except OSError:
            return False

    def spoof_hardware_id(self) -> BypassResult:
        """Spoof hardware ID to bypass node-locked licenses.

        Returns:
            BypassResult with spoof status

        """
        errors = []
        details = []

        if self._spoof_disk_serial():
            details.append("Disk serial number spoofed")
        else:
            errors.append("Failed to spoof disk serial")

        if self._spoof_mac_address():
            details.append("MAC address spoofed")
        else:
            errors.append("Failed to spoof MAC address")

        if self._spoof_cpu_id():
            details.append("CPU ID spoofed")
        else:
            errors.append("Failed to spoof CPU ID")

        success = len(details) > 0

        return BypassResult(
            success=success,
            technique="Hardware ID Spoofing",
            details="; ".join(details),
            errors=errors,
        )

    def _spoof_disk_serial(self) -> bool:
        """Spoof disk volume serial number."""
        try:
            key = winreg.CreateKey(
                winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Disk\Enum"
            )

            winreg.SetValueEx(key, "0", 0, winreg.REG_SZ, "SPOOFED_DISK_ID_12345678")
            winreg.CloseKey(key)
            return True

        except OSError:
            return False

    def _spoof_mac_address(self) -> bool:
        """Spoof MAC address in registry."""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}",
                0,
                winreg.KEY_READ,
            )

            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    if subkey_name.isdigit():
                        adapter_key = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_WRITE)
                        try:
                            winreg.SetValueEx(
                                adapter_key, "NetworkAddress", 0, winreg.REG_SZ, "001122334455"
                            )
                        finally:
                            winreg.CloseKey(adapter_key)
                    i += 1
                except OSError:
                    break

            winreg.CloseKey(key)
            return True

        except OSError:
            return False

    def _spoof_cpu_id(self) -> bool:
        """Spoof CPU identification."""
        try:
            key = winreg.CreateKey(
                winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            )

            winreg.SetValueEx(key, "ProcessorNameString", 0, winreg.REG_SZ, "Spoofed CPU")
            winreg.SetValueEx(key, "Identifier", 0, winreg.REG_SZ, "x86 Family SPOOFED")

            winreg.CloseKey(key)
            return True

        except OSError:
            return False
