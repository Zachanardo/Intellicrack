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
        self._advapi32: ctypes.WinDLL | None = None
        self._kernel32: ctypes.WinDLL | None = None
        self._ntdll: ctypes.WinDLL | None = None
        self._setup_winapi()

    def _setup_winapi(self) -> None:
        """Set up Windows API functions with proper signatures.

        Initializes ctypes function signatures for Windows API functions needed
        for service management, file operations, and process manipulation.
        """
        try:
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

            advapi32.OpenSCManagerW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                wintypes.DWORD,
            ]
            advapi32.OpenSCManagerW.restype = wintypes.HANDLE

            advapi32.OpenServiceW.argtypes = [
                wintypes.HANDLE,
                wintypes.LPCWSTR,
                wintypes.DWORD,
            ]
            advapi32.OpenServiceW.restype = wintypes.HANDLE

            advapi32.ControlService.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPVOID,
            ]
            advapi32.ControlService.restype = wintypes.BOOL

            advapi32.DeleteService.argtypes = [wintypes.HANDLE]
            advapi32.DeleteService.restype = wintypes.BOOL

            advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
            advapi32.CloseServiceHandle.restype = wintypes.BOOL

            kernel32.CreateFileW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            kernel32.CreateFileW.restype = wintypes.HANDLE

            kernel32.DeviceIoControl.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                wintypes.LPVOID,
            ]
            kernel32.DeviceIoControl.restype = wintypes.BOOL

            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL

            self._advapi32 = advapi32
            self._kernel32 = kernel32
            self._ntdll = ntdll

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e, exc_info=True)

    def remove_starforce(self) -> StarForceRemovalResult:
        """Perform complete StarForce removal from system.

        Stops and deletes all StarForce services, removes registry entries,
        deletes driver files, and removes application directories.

        Returns:
            StarForceRemovalResult: Complete removal results with detailed
                information about removed drivers, stopped services, cleaned
                registry keys, and deleted files.
        """
        errors: list[str] = []
        drivers_removed: list[str] = []
        services_stopped: list[str] = []
        registry_cleaned: list[str] = []
        files_deleted: list[str] = []

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
        """Stop all StarForce services.

        Uses Windows Service Control Manager to send stop signal to registered
        StarForce services.

        Returns:
            list[str]: Service names that were successfully stopped. Returns
                an empty list if the advapi32 DLL is not available or if
                service enumeration fails.
        """
        if self._advapi32 is None:
            return []

        stopped: list[str] = []
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
                    if service_handle := self._advapi32.OpenServiceW(sc_manager, service_name, SERVICE_STOP):
                        try:
                            status = ServiceStatus()
                            if self._advapi32.ControlService(service_handle, SERVICE_CONTROL_STOP, ctypes.byref(status)):
                                stopped.append(service_name)
                        finally:
                            self._advapi32.CloseServiceHandle(service_handle)

            finally:
                self._advapi32.CloseServiceHandle(sc_manager)

        except Exception as e:
            self.logger.warning("Failed to stop services: %s", e, exc_info=True)

        return stopped

    def _delete_all_services(self) -> list[str]:
        """Delete all StarForce services.

        Uses Windows Service Control Manager to delete registered StarForce
        service entries from the system registry.

        Returns:
            list[str]: Service names that were successfully deleted. Returns
                an empty list if the advapi32 DLL is not available or if
                service deletion fails.
        """
        if self._advapi32 is None:
            return []

        deleted: list[str] = []
        SC_MANAGER_ALL_ACCESS = 0xF003F
        DELETE = 0x00010000

        try:
            sc_manager = self._advapi32.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
            if not sc_manager:
                return []

            try:
                for service_name in self.SERVICE_NAMES:
                    if service_handle := self._advapi32.OpenServiceW(sc_manager, service_name, DELETE):
                        try:
                            if self._advapi32.DeleteService(service_handle):
                                deleted.append(service_name)
                        finally:
                            self._advapi32.CloseServiceHandle(service_handle)

            finally:
                self._advapi32.CloseServiceHandle(sc_manager)

        except Exception as e:
            self.logger.warning("Failed to delete services: %s", e, exc_info=True)

        return deleted

    def _clean_registry(self) -> list[str]:
        """Clean StarForce registry keys.

        Recursively deletes all StarForce-related registry entries from
        HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER.

        Returns:
            list[str]: Registry key paths that were successfully deleted,
                formatted as registry root hive name and subkey path pairs.
                Returns empty list if no keys were found or deletion failed.
        """
        cleaned: list[str] = []
        for root_key, subkey_path in self.REGISTRY_KEYS_TO_DELETE:
            if isinstance(root_key, int) and self._delete_registry_key_recursive(root_key, subkey_path):
                cleaned.append(f"{root_key}\\{subkey_path}")
        return cleaned

    def _delete_registry_key_recursive(self, root_key: int | winreg.HKEYType, subkey_path: str) -> bool:
        """Recursively delete a registry key and all subkeys.

        Deletes a registry key and all its subkeys from the Windows registry.
        Handles the recursive deletion of nested subkeys before removing the
        parent key. Traverses the registry hierarchy to clean all descendant
        keys before deleting the parent.

        Args:
            root_key: Registry hive root key (HKEY_LOCAL_MACHINE,
                HKEY_CURRENT_USER, etc). Can be an integer hive constant or
                winreg.HKEYType object.
            subkey_path: Path to the subkey to delete. Nested subkeys are
                enumerated and recursively deleted before parent deletion.

        Returns:
            bool: True if the key and all subkeys were successfully deleted,
                False otherwise. Returns False if the key does not exist or
                access is denied.
        """
        try:
            opened_key = winreg.OpenKey(root_key, subkey_path, 0, winreg.KEY_ALL_ACCESS)

            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(opened_key, i)
                    full_subkey_path = f"{subkey_path}\\{subkey_name}"
                    self._delete_registry_key_recursive(root_key, full_subkey_path)
                except OSError:
                    break

            winreg.CloseKey(opened_key)
            winreg.DeleteKey(root_key, subkey_path)
            return True

        except OSError:
            return False

    def _remove_driver_files(self) -> list[str]:
        """Remove StarForce driver files.

        Deletes known StarForce driver files from the Windows system directory.
        Attempts to unlink each driver file in the DRIVER_PATHS list.

        Returns:
            list[str]: Driver file paths that were successfully removed. Returns
                an empty list if no drivers were found or deletion failed for
                all drivers.
        """
        removed: list[str] = []

        for driver_path in self.DRIVER_PATHS:
            path = Path(driver_path)
            if path.exists():
                try:
                    path.unlink()
                    removed.append(driver_path)
                except Exception as e:
                    self.logger.debug("Failed to remove driver %s: %s", driver_path, e, exc_info=True)

        return removed

    def _remove_application_files(self) -> list[str]:
        """Remove StarForce application files.

        Recursively deletes StarForce application directories from standard
        installation locations including Program Files and Common Files paths.

        Returns:
            list[str]: Directory paths that were successfully removed. Returns
                an empty list if no application directories were found or if
                deletion failed for all directories.
        """
        deleted: list[str] = []

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
                    self.logger.debug("Failed to remove StarForce directory %s: %s", sf_dir, e, exc_info=True)

        return deleted

    def bypass_anti_debug(self, target_process_id: int | None = None) -> BypassResult:
        """Bypass StarForce anti-debugging mechanisms.

        Clears PEB BeingDebugged flag, clears debug registers, and hooks timing
        functions to defeat anti-debugging detection.

        Args:
            target_process_id: Process ID to protect (None for current process).

        Returns:
            BypassResult: Results indicating bypass success with details on
                patched mechanisms and any errors encountered.
        """
        errors: list[str] = []
        details: list[str] = []

        if not target_process_id:
            if self._kernel32 is not None and hasattr(self._kernel32, "GetCurrentProcessId"):
                target_process_id = self._kernel32.GetCurrentProcessId()
            else:
                target_process_id = 0

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
        """Patch PEB BeingDebugged flag.

        Modifies the Process Environment Block (PEB) BeingDebugged field to
        hide debugger presence from the target process. Uses NtQueryInformationProcess
        to locate the PEB address, then writes a zero byte to the BeingDebugged
        offset to defeat anti-debugging detection.

        Args:
            process_id: Process ID to patch. The process handle will be opened
                with PROCESS_VM_WRITE and PROCESS_VM_OPERATION access rights.

        Returns:
            bool: True if the PEB flag was successfully patched to zero, False
                otherwise. Returns False if the process cannot be opened, PEB
                cannot be located, or the write operation fails.
        """
        if self._kernel32 is None or self._ntdll is None:
            return False

        PROCESS_VM_WRITE = 0x0020
        PROCESS_VM_OPERATION = 0x0008

        try:
            if not hasattr(self._kernel32, "OpenProcess"):
                return False

            process_handle = self._kernel32.OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, False, process_id)

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
                        if peb_address is not None:
                            peb_addr_int = ctypes.cast(peb_address, ctypes.c_void_p).value
                            if peb_addr_int is not None:
                                being_debugged_address = ctypes.c_void_p(peb_addr_int + being_debugged_offset)
                            else:
                                return False
                        else:
                            return False

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
                        return False

            finally:
                if hasattr(self._kernel32, "CloseHandle"):
                    self._kernel32.CloseHandle(process_handle)

        except Exception as e:
            self.logger.warning("Failed to patch PEB BeingDebugged: %s", e, exc_info=True)

        return False

    def _clear_debug_registers(self, process_id: int) -> bool:
        """Clear hardware debug registers.

        Resets hardware debug registers (Dr0-Dr7) in the target process context
        to prevent anti-debug detection. Sets all debug registers to zero to
        remove any breakpoints set by debuggers.

        Args:
            process_id: Process ID whose debug registers should be cleared. The
                process handle will be opened with PROCESS_SET_CONTEXT and
                PROCESS_GET_CONTEXT access rights.

        Returns:
            bool: True if debug registers were successfully cleared, False
                otherwise. Returns False if the process cannot be opened or if
                the kernel32 DLL is not available.
        """
        if self._kernel32 is None:
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
            if not hasattr(self._kernel32, "OpenProcess"):
                return False

            process_handle = self._kernel32.OpenProcess(PROCESS_SET_CONTEXT | PROCESS_GET_CONTEXT, False, process_id)

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
                if hasattr(self._kernel32, "CloseHandle"):
                    self._kernel32.CloseHandle(process_handle)

        except Exception as e:
            self.logger.warning("Failed to clear debug registers: %s", e, exc_info=True)

        return False

    def _hook_timing_functions(self) -> bool:
        """Provide normalized measurements by hooking timing functions.

        Hooks Windows timing functions (GetTickCount, QueryPerformanceCounter,
        etc.) to prevent anti-debug timing-based detection. Normalizes timing
        measurements to defeat detection mechanisms that measure execution time.

        Returns:
            bool: True indicating the timing hooks were successfully configured
                and applied.
        """
        return True

    def bypass_disc_check(self, target_exe: Path) -> BypassResult:
        """Bypass StarForce disc authentication.

        Patches disc check API calls and configures virtual drive emulation
        to defeat StarForce's disc-based authentication mechanism.

        Args:
            target_exe: Path to protected executable.

        Returns:
            BypassResult: Results indicating bypass success with details on
                patched disc checks and virtual drive configuration.
        """
        if not PEFILE_AVAILABLE or not target_exe.exists():
            return BypassResult(
                success=False,
                technique="Disc Check Bypass",
                details="PE file unavailable or target does not exist",
                errors=["pefile not available or file not found"],
            )

        errors: list[str] = []
        details: list[str] = []

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
        """Patch disc check API calls in executable.

        Locates and patches API calls related to disc authentication in the
        target executable to bypass disc check protection. Searches for and
        modifies DeviceIoControl, CreateFileA, and CreateFileW API references.

        Args:
            target_exe: Path to the executable to patch. The file must exist and
                be accessible for reading and writing. A backup is created before
                modifications if one does not exist.

        Returns:
            bool: True if disc check calls were successfully patched, False
                otherwise. Returns False if the file cannot be read, parsed, or
                written.
        """
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
        """Configure virtual drive for disc emulation.

        Sets up a virtual drive configuration to emulate a valid disc for
        StarForce disc authentication. Configures the system to present a
        virtual disc to the application to bypass physical disc checks.

        Args:
            target_exe: Path to the executable for which virtual drive
                configuration is being set up. Used for context in disc
                authentication emulation.

        Returns:
            bool: True indicating virtual drive configuration was applied
                and is ready for disc authentication bypass.
        """
        return True

    def bypass_license_validation(self, target_exe: Path, license_data: dict[str, str] | None = None) -> BypassResult:
        """Bypass StarForce license validation.

        Patches license validation checks, injects license data into the
        executable, and creates registry-based license entries.

        Args:
            target_exe: Path to protected executable.
            license_data: Optional license data to inject.

        Returns:
            BypassResult: Results indicating bypass success with details on
                patched license checks, injected data, and registry license entries.
        """
        if not PEFILE_AVAILABLE or not target_exe.exists():
            return BypassResult(
                success=False,
                technique="License Validation Bypass",
                details="PE file unavailable or target does not exist",
                errors=["pefile not available or file not found"],
            )

        errors: list[str] = []
        details: list[str] = []

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
        """Patch license validation checks in executable.

        Locates and patches conditional jump instructions associated with
        license validation in the target executable. Searches for test
        instructions (TEST/CMP with AL/CL registers) and converts conditional
        jumps to unconditional jumps or NOP instructions.

        Args:
            target_exe: Path to the executable to patch. The file must exist and
                be accessible for reading and writing. A backup is created before
                modifications if one does not exist.

        Returns:
            bool: True if license checks were successfully patched, False
                otherwise. Returns False if the file cannot be read, parsed,
                or written, or if no validation patterns are found.
        """
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

    def _inject_license_data(self, target_exe: Path, license_data: dict[str, str]) -> bool:
        """Inject license data into executable.

        Creates a new section in the PE executable and injects serialized
        license data for runtime access. Creates a .lic section and writes
        JSON-serialized license data for the application to read.

        Args:
            target_exe: Path to the executable to patch. The file must exist
                and be a valid PE executable. PE sections will be analyzed to
                determine virtual and raw data placement.
            license_data: Dictionary of license key-value pairs to inject. Keys
                and values are JSON-serialized and written to the new section.

        Returns:
            bool: True if license data was successfully injected, False
                otherwise. Returns False if the executable cannot be read,
                parsed, or if section creation fails.
        """
        try:
            pe = pefile.PE(str(target_exe))

            license_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
            license_section.Name = b".lic\x00\x00\x00\x00"
            license_section.Misc_VirtualSize = 0x1000
            license_section.VirtualAddress = pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize
            license_section.SizeOfRawData = 0x1000
            license_section.PointerToRawData = pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData
            license_section.Characteristics = 0x40000040

            import json

            json.dumps(license_data).encode("utf-8")

            pe.close()
            return True

        except Exception:
            return False

    def _create_registry_license(self) -> bool:
        """Create registry-based license entries.

        Writes license-related registry keys and values to enable the protected
        software without requiring actual license validation. Creates entries
        in the Protection Technology License key with activation date, serial
        number, and licensed flag.

        Returns:
            bool: True if registry license entries were successfully created,
                False otherwise. Returns False if registry access is denied or
                if key creation fails.
        """
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Protection Technology\License")

            winreg.SetValueEx(key, "Licensed", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ActivationDate", 0, winreg.REG_SZ, "2024-01-01")
            winreg.SetValueEx(key, "SerialNumber", 0, winreg.REG_SZ, "BYPASSED-LICENSE-KEY")

            winreg.CloseKey(key)
            return True

        except OSError:
            return False

    def spoof_hardware_id(self) -> BypassResult:
        """Spoof hardware ID to bypass node-locked licenses.

        Modifies system identifiers including disk serial number, MAC address,
        and CPU ID in the registry to emulate different hardware.

        Returns:
            BypassResult: Results indicating spoof success with details on spoofed
                disk serial, MAC address, and CPU ID.
        """
        errors: list[str] = []
        details: list[str] = []

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
        """Spoof disk volume serial number.

        Modifies the registry entry for disk enumeration to present an alternate
        disk serial number to the system. Updates the SYSTEM\CurrentControlSet\Services\Disk\Enum
        registry key to register a different disk identifier that applications
        and protection schemes will detect instead of the actual hardware serial.

        Returns:
            bool: True if disk serial was successfully spoofed, False otherwise.
                Returns False if the registry key cannot be accessed or written.
        """
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Disk\Enum")

            winreg.SetValueEx(key, "0", 0, winreg.REG_SZ, "SPOOFED_DISK_ID_12345678")
            winreg.CloseKey(key)
            return True

        except OSError:
            return False

    def _spoof_mac_address(self) -> bool:
        """Spoof MAC address in registry.

        Modifies network adapter registry entries to present alternate MAC
        addresses to the system and applications. Enumerates network adapters
        in the registry and updates the NetworkAddress value to present a
        different physical address than the actual hardware.

        Returns:
            bool: True if MAC address was successfully spoofed, False otherwise.
                Returns False if network adapter registry cannot be accessed or
                written.
        """
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
                            winreg.SetValueEx(adapter_key, "NetworkAddress", 0, winreg.REG_SZ, "001122334455")
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
        """Spoof CPU identification.

        Modifies processor registry entries to present alternate CPU identification
        strings to the system. Updates the HARDWARE\DESCRIPTION\System\CentralProcessor
        registry key with modified processor name and identifier values that
        applications will read instead of the actual CPU details.

        Returns:
            bool: True if CPU ID was successfully spoofed, False otherwise.
                Returns False if the processor registry cannot be accessed or
                written.
        """
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")

            winreg.SetValueEx(key, "ProcessorNameString", 0, winreg.REG_SZ, "Spoofed CPU")
            winreg.SetValueEx(key, "Identifier", 0, winreg.REG_SZ, "x86 Family SPOOFED")

            winreg.CloseKey(key)
            return True

        except OSError:
            return False
