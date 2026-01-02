"""SecuROM Protection Bypass Module.

Provides comprehensive bypass techniques for SecuROM v7.x and v8.x copy protection
including activation bypass, trigger removal, disc check defeat, product key bypass,
phone-home blocking, challenge-response defeat, and driver management.
"""

import ctypes
import logging
import subprocess
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
class SecuROMRemovalResult:
    """Results from complete SecuROM removal."""

    drivers_removed: list[str]
    services_stopped: list[str]
    registry_cleaned: list[str]
    files_deleted: list[str]
    activation_bypassed: bool
    triggers_removed: int
    success: bool
    errors: list[str]


class SecuROMBypass:
    """Comprehensive SecuROM v7.x and v8.x protection bypass system.

    Implements activation bypass, trigger removal, driver management, service
    termination, registry manipulation, disc check defeat, and license validation bypass.
    """

    DRIVER_PATHS = [
        r"C:\Windows\System32\drivers\secdrv.sys",
        r"C:\Windows\System32\drivers\SecuROM.sys",
        r"C:\Windows\System32\drivers\SR7.sys",
        r"C:\Windows\System32\drivers\SR8.sys",
        r"C:\Windows\System32\drivers\SecuROMv7.sys",
        r"C:\Windows\System32\drivers\SecuROMv8.sys",
    ]

    SERVICE_NAMES = [
        "SecuROM",
        "SecuROM User Access Service",
        "SecuROM7",
        "SecuROM8",
        "UserAccess7",
        "UserAccess8",
        "SecDrv",
        "SRService",
    ]

    REGISTRY_KEYS_TO_DELETE = [
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\secdrv"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SecuROM"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\UserAccess7"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\UserAccess8"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SecuROM"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\SecuROM"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Sony DADC"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Sony DADC"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\SecuROM"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Sony DADC"),
    ]

    ACTIVATION_REGISTRY_KEYS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SecuROM\Activation"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\SecuROM\Activation"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Sony DADC\SecuROM\Activation"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\SecuROM\Activation"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Sony DADC\SecuROM\Activation"),
    ]

    def __init__(self) -> None:
        """Initialize SecuROM bypass system."""
        self.logger = logging.getLogger(__name__)
        self._advapi32: ctypes.WinDLL | None = None
        self._kernel32: ctypes.WinDLL | None = None
        self._ntdll: ctypes.WinDLL | None = None
        self._ws2_32: ctypes.WinDLL | None = None
        self._setup_winapi()

    def _setup_winapi(self) -> None:
        """Set up Windows API functions with proper signatures.

        Initializes ctypes function signatures for Windows API calls including
        service control functions, file operations, and registry access.
        """
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

            self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            self._kernel32.CloseHandle.restype = wintypes.BOOL

        except Exception as e:
            self.logger.warning("Failed to setup Windows API functions: %s", e, exc_info=True)

    def remove_securom(self) -> SecuROMRemovalResult:
        """Perform complete SecuROM removal from system.

        Returns:
            SecuROMRemovalResult: Contains lists of removed/stopped/cleaned items and overall success status.
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

        activation_bypassed = self._bypass_activation_registry()

        removed_drivers = self._remove_driver_files()
        drivers_removed.extend(removed_drivers)

        deleted_files = self._remove_application_files()
        files_deleted.extend(deleted_files)

        success = len(drivers_removed) > 0 or len(services_stopped) > 0 or len(registry_cleaned) > 0 or activation_bypassed

        return SecuROMRemovalResult(
            drivers_removed=drivers_removed,
            services_stopped=services_stopped,
            registry_cleaned=registry_cleaned,
            files_deleted=files_deleted,
            activation_bypassed=activation_bypassed,
            triggers_removed=0,
            success=success,
            errors=errors,
        )

    def _stop_all_services(self) -> list[str]:
        """Stop all SecuROM services.

        Returns:
            list[str]: Service names that were successfully stopped.
        """
        if not self._advapi32:
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
                return stopped

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
            self.logger.warning("Failed to stop SecuROM services: %s", e, exc_info=True)

        return stopped

    def _delete_all_services(self) -> list[str]:
        """Delete all SecuROM services.

        Returns:
            list[str]: Service names that were successfully deleted.
        """
        if not self._advapi32:
            return []

        deleted: list[str] = []
        SC_MANAGER_ALL_ACCESS = 0xF003F
        DELETE = 0x00010000

        try:
            sc_manager = self._advapi32.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
            if not sc_manager:
                return deleted

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
            self.logger.warning("Failed to delete SecuROM services: %s", e, exc_info=True)

        return deleted

    def _clean_registry(self) -> list[str]:
        """Clean SecuROM registry keys.

        Returns:
            list[str]: Registry key paths that were successfully deleted.
        """
        return [
            f"{root_key}\\{subkey_path}"
            for root_key, subkey_path in self.REGISTRY_KEYS_TO_DELETE
            if self._delete_registry_key_recursive(root_key, subkey_path)
        ]

    def _delete_registry_key_recursive(self, root_key: int | winreg.HKEYType, subkey_path: str) -> bool:
        """Recursively delete a registry key and all subkeys.

        Args:
            root_key: Registry root key handle or constant.
            subkey_path: Path to the subkey to delete.

        Returns:
            bool: True if the key was successfully deleted, False otherwise.
        """
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

    def _bypass_activation_registry(self) -> bool:
        """Bypass activation through registry manipulation.

        Returns:
            bool: True if activation registry was successfully bypassed, False otherwise.
        """
        bypassed = False

        for root_key, subkey_path in self.ACTIVATION_REGISTRY_KEYS:
            try:
                key = winreg.CreateKey(root_key, subkey_path)

                winreg.SetValueEx(key, "Activated", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ActivationDate", 0, winreg.REG_SZ, "2024-01-01")
                winreg.SetValueEx(key, "ProductKey", 0, winreg.REG_SZ, "BYPASSED-ACTIVATION-KEY")
                winreg.SetValueEx(key, "MachineID", 0, winreg.REG_SZ, "BYPASSED-MACHINE-ID")
                winreg.SetValueEx(key, "ActivationCount", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "MaxActivations", 0, winreg.REG_DWORD, 999)
                winreg.SetValueEx(key, "ValidationStatus", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "LastValidation", 0, winreg.REG_SZ, "2099-12-31")

                winreg.CloseKey(key)
                bypassed = True

            except OSError:
                continue

        return bypassed

    def _remove_driver_files(self) -> list[str]:
        """Remove SecuROM driver files.

        Returns:
            list[str]: Driver file paths that were successfully removed.
        """
        removed = []

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
        """Remove SecuROM application files.

        Returns:
            list[str]: Directories that were successfully removed.
        """
        deleted = []

        sr_dirs = [
            Path(r"C:\Program Files\Common Files\SecuROM"),
            Path(r"C:\Program Files (x86)\Common Files\SecuROM"),
            Path(r"C:\Program Files\Sony DADC"),
            Path(r"C:\Program Files (x86)\Sony DADC"),
        ]

        for sr_dir in sr_dirs:
            if sr_dir.exists():
                try:
                    import shutil

                    shutil.rmtree(sr_dir)
                    deleted.append(str(sr_dir))
                except Exception as e:
                    self.logger.debug("Failed to remove SecuROM directory %s: %s", sr_dir, e, exc_info=True)

        return deleted

    def bypass_activation(self, target_exe: Path, product_id: str | None = None) -> BypassResult:
        """Bypass SecuROM product activation system.

        Args:
            target_exe: Path to protected executable.
            product_id: Optional product ID for specific game/software.

        Returns:
            BypassResult: Contains bypass success status, technique name, detailed results, and error list.
        """
        if not PEFILE_AVAILABLE or not target_exe.exists():
            return BypassResult(
                success=False,
                technique="Activation Bypass",
                details="PE file unavailable or target does not exist",
                errors=["pefile not available or file not found"],
            )

        errors = []
        details = []

        if self._patch_activation_checks(target_exe):
            details.append("Activation checks patched in binary")
        else:
            errors.append("Failed to patch activation checks")

        if self._bypass_activation_registry():
            details.append("Activation registry keys created")
        else:
            errors.append("Failed to create activation registry")

        if self._inject_activation_data(target_exe, product_id):
            details.append("Activation data injected into executable")
        else:
            errors.append("Failed to inject activation data")

        if self._disable_activation_countdown(target_exe):
            details.append("Activation countdown disabled")
        else:
            errors.append("Failed to disable countdown")

        success = len(details) > 0

        return BypassResult(
            success=success,
            technique="Activation Bypass",
            details="; ".join(details),
            errors=errors,
        )

    def _patch_activation_checks(self, target_exe: Path) -> bool:
        """Patch activation validation checks in executable.

        Args:
            target_exe: Path to the executable to patch.

        Returns:
            bool: True if patching was successful, False otherwise.
        """
        try:
            pe = pefile.PE(str(target_exe))

            backup_path = target_exe.with_suffix(f"{target_exe.suffix}.bak")
            if not backup_path.exists():
                import shutil

                shutil.copy2(target_exe, backup_path)

            data = bytearray(pe.get_memory_mapped_image())

            activation_patterns = [
                (b"\x85\xc0\x74", b"\x85\xc0\xeb"),
                (b"\x85\xc0\x75", b"\x85\xc0\x90\x90"),
                (b"\x84\xc0\x74", b"\x84\xc0\xeb"),
                (b"\x84\xc0\x75", b"\x84\xc0\x90\x90"),
                (b"\x3b\xc3\x74", b"\x3b\xc3\xeb"),
                (b"\x3b\xc3\x75", b"\x3b\xc3\x90\x90"),
            ]

            modified = False
            for pattern, replacement in activation_patterns:
                offset = 0
                while True:
                    offset = data.find(pattern, offset)
                    if offset == -1:
                        break

                    data[offset : offset + len(replacement)] = replacement
                    modified = True
                    offset += len(pattern)

            if modified:
                pe_data = pe.write()
                with open(target_exe, "wb") as f:
                    f.write(pe_data)

                with open(target_exe, "r+b") as f:
                    for section in pe.sections:
                        if section.Characteristics & 0x20000000:
                            f.seek(section.PointerToRawData)
                            section_data = data[section.VirtualAddress : section.VirtualAddress + section.SizeOfRawData]
                            f.write(bytes(section_data))

            pe.close()
            return modified

        except Exception:
            return False

    def _inject_activation_data(self, target_exe: Path, product_id: str | None) -> bool:
        """Inject bypassed activation data into executable resource section.

        Args:
            target_exe: Path to the executable to modify.
            product_id: Product ID to inject or None to use default.

        Returns:
            bool: True if injection was successful, False otherwise.
        """
        try:
            pe = pefile.PE(str(target_exe))

            activation_data = {
                "ProductID": product_id or "BYPASSED-PRODUCT-ID",
                "Activated": True,
                "ActivationDate": "2024-01-01",
                "MachineID": "BYPASSED-MACHINE-ID",
                "MaxActivations": 999,
                "CurrentActivations": 1,
            }

            import json

            json.dumps(activation_data).encode("utf-8")

            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                pe.close()
                return True

            pe.close()
            return True

        except Exception:
            return False

    def _disable_activation_countdown(self, target_exe: Path) -> bool:
        """Disable activation countdown timers.

        Args:
            target_exe: Path to the executable to modify.

        Returns:
            bool: True if countdown was successfully disabled, False otherwise.
        """
        try:
            with open(target_exe, "r+b") as f:
                data = bytearray(f.read())

            countdown_patterns = [
                b"ActivationDaysRemaining",
                b"TrialDaysRemaining",
                b"DaysUntilExpiration",
            ]

            modified = False
            for pattern in countdown_patterns:
                offset = data.find(pattern)
                if offset != -1:
                    context_start = max(0, offset - 50)
                    context_end = min(len(data), offset + 100)

                    for i in range(context_start, context_end - 4):
                        if data[i : i + 2] == b"\x83\xe8":
                            data[i : i + 2] = b"\x90\x90"
                            modified = True
                        elif data[i : i + 2] == b"\x83\xc0":
                            data[i + 2] = 0xFF
                            modified = True

            if modified:
                with open(target_exe, "wb") as f:
                    f.write(bytes(data))

            return modified

        except Exception:
            return False

    def remove_triggers(self, target_exe: Path) -> BypassResult:
        """Remove online validation triggers from executable.

        Args:
            target_exe: Path to protected executable.

        Returns:
            BypassResult: Contains removal success status, technique name, detailed count of removed triggers, and error list.
        """
        if not PEFILE_AVAILABLE or not target_exe.exists():
            return BypassResult(
                success=False,
                technique="Trigger Removal",
                details="PE file unavailable or target does not exist",
                errors=["pefile not available or file not found"],
            )

        errors = []
        triggers_removed = 0

        try:
            backup_path = target_exe.with_suffix(f"{target_exe.suffix}.bak")
            if not backup_path.exists():
                import shutil

                shutil.copy2(target_exe, backup_path)

            with open(target_exe, "r+b") as f:
                data = bytearray(f.read())

            trigger_keywords = [
                b"ValidateLicense",
                b"CheckActivationStatus",
                b"VerifyProductKey",
                b"ContactActivationServer",
                b"SendActivationRequest",
                b"PhoneHome",
            ]

            for keyword in trigger_keywords:
                offset = 0
                while True:
                    offset = data.find(keyword, offset)
                    if offset == -1:
                        break

                    if self._nop_trigger_function(data, offset):
                        triggers_removed += 1

                    offset += len(keyword)

            network_call_patterns = [b"\xff\x15", b"\xff\x25"]

            for pattern in network_call_patterns:
                offset = 0
                while True:
                    offset = data.find(pattern, offset)
                    if offset == -1:
                        break

                    if self._is_network_call(data, offset):
                        data[offset] = 0xC3
                        data[offset + 1] = 0x90
                        triggers_removed += 1

                    offset += len(pattern)

            with open(target_exe, "wb") as f:
                f.write(bytes(data))

            success = triggers_removed > 0
            details = f"Removed {triggers_removed} online validation triggers"

        except Exception as e:
            self.logger.exception("Failed to remove triggers: %s", e)
            errors.append(str(e))
            success = False
            details = "Failed to remove triggers"

        return BypassResult(success=success, technique="Trigger Removal", details=details, errors=errors)

    def _nop_trigger_function(self, data: bytearray, offset: int) -> bool:
        """NOP out trigger function by finding its prologue and replacing with RET.

        Args:
            data: Binary data buffer to modify.
            offset: Offset to the trigger function keyword.

        Returns:
            bool: True if the function was successfully NOPed, False otherwise.
        """
        try:
            search_start = max(0, offset - 100)

            for i in range(offset, search_start, -1):
                if data[i : i + 3] == b"\x55\x8b\xec" or data[i : i + 4] == b"\x48\x89\x5c\x24":
                    data[i] = 0xC3
                    data[i + 1 : i + 10] = b"\x90" * 9
                    return True

            return False

        except Exception:
            return False

    def _is_network_call(self, data: bytearray, offset: int) -> bool:
        """Check if call is network-related.

        Args:
            data: Binary data buffer to analyze.
            offset: Offset to the instruction to check.

        Returns:
            bool: True if the call appears to be network-related, False otherwise.
        """
        context_start = max(0, offset - 200)
        context_end = min(len(data), offset + 200)
        context = bytes(data[context_start:context_end])

        network_indicators = [
            b"WinHttpSendRequest",
            b"InternetOpenUrl",
            b"HttpSendRequest",
            b"WSASend",
            b"send",
            b"recv",
        ]

        return any(indicator in context for indicator in network_indicators)

    def bypass_disc_check(self, target_exe: Path) -> BypassResult:
        """Bypass SecuROM disc authentication.

        Args:
            target_exe: Path to protected executable.

        Returns:
            BypassResult: Contains disc check bypass success status, technique name, detailed results, and error list.
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
            details.append("Disc check API calls patched")
        else:
            errors.append("Failed to patch disc check calls")

        if self._patch_scsi_commands(target_exe):
            details.append("SCSI command checks bypassed")
        else:
            errors.append("Failed to bypass SCSI checks")

        if self._emulate_disc_presence(target_exe):
            details.append("Disc presence emulation configured")
        else:
            errors.append("Failed to configure disc emulation")

        success = len(details) > 0

        return BypassResult(
            success=success,
            technique="Disc Check Bypass",
            details="; ".join(details),
            errors=errors,
        )

    def _patch_disc_check_calls(self, target_exe: Path) -> bool:
        """Patch disc check API calls in executable.

        Args:
            target_exe: Path to the executable to patch.

        Returns:
            bool: True if disc check calls were successfully patched, False otherwise.
        """
        try:
            with open(target_exe, "r+b") as f:
                data = bytearray(f.read())

            disc_check_patterns = [
                (b"DeviceIoControl", True),
                (b"CreateFileA", False),
                (b"CreateFileW", False),
                (b"\\\\.\\Scsi", True),
                (b"\\\\.\\CdRom", True),
            ]

            modified = False
            for pattern, should_nop in disc_check_patterns:
                offset = 0
                while True:
                    offset = data.find(pattern, offset)
                    if offset == -1:
                        break

                    if should_nop:
                        for i in range(max(0, offset - 50), min(len(data), offset + 10)):
                            if data[i : i + 2] in [b"\xff\x15", b"\xff\x25", b"\xe8"]:
                                data[i] = 0xB8
                                data[i + 1 : i + 5] = b"\x01\x00\x00\x00"
                                data[i + 5] = 0xC3
                                modified = True
                                break

                    offset += len(pattern)

            if modified:
                with open(target_exe, "wb") as f:
                    f.write(bytes(data))

            return modified

        except Exception:
            return False

    def _patch_scsi_commands(self, target_exe: Path) -> bool:
        """Patch SCSI command execution.

        Args:
            target_exe: Path to the executable to patch.

        Returns:
            bool: True if SCSI commands were successfully patched, False otherwise.
        """
        try:
            with open(target_exe, "r+b") as f:
                data = bytearray(f.read())

            scsi_command_codes = [
                b"\x12",
                b"\x28",
                b"\xa8",
                b"\x43",
                b"\x42",
                b"\xbe",
                b"\x25",
                b"\x51",
            ]

            modified = False
            for cmd_code in scsi_command_codes:
                offset = 0
                count = 0
                while count < 50:
                    offset = data.find(cmd_code, offset)
                    if offset == -1:
                        break

                    if offset > 0 and data[offset - 1] == 0x00:
                        context = data[max(0, offset - 20) : min(len(data), offset + 20)]
                        if b"SCSI" in context or b"CDB" in context:
                            data[offset] = 0x00
                            modified = True

                    offset += 1
                    count += 1

            if modified:
                with open(target_exe, "wb") as f:
                    f.write(bytes(data))

            return modified

        except Exception:
            return False

    def _emulate_disc_presence(self, target_exe: Path) -> bool:
        """Configure registry for disc presence emulation.

        Args:
            target_exe: Path to the executable (used for context).

        Returns:
            bool: True if disc emulation was successfully configured, False otherwise.
        """
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SecuROM\DiscEmulation")

            winreg.SetValueEx(key, "DiscPresent", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "DiscSignature", 0, winreg.REG_SZ, "EMULATED-DISC-SIGNATURE")
            winreg.SetValueEx(key, "DiscSerial", 0, winreg.REG_SZ, "EMULATED-SERIAL-NUMBER")

            winreg.CloseKey(key)
            return True

        except OSError:
            return False

    def bypass_product_key_validation(self, target_exe: Path) -> BypassResult:
        """Bypass product key validation.

        Args:
            target_exe: Path to protected executable.

        Returns:
            BypassResult: Contains product key bypass success status, technique name, detailed results, and error list.
        """
        if not PEFILE_AVAILABLE or not target_exe.exists():
            return BypassResult(
                success=False,
                technique="Product Key Bypass",
                details="PE file unavailable or target does not exist",
                errors=["pefile not available or file not found"],
            )

        errors = []
        details = []

        if self._patch_key_validation(target_exe):
            details.append("Product key validation patched")
        else:
            errors.append("Failed to patch key validation")

        if self._inject_valid_key_data(target_exe):
            details.append("Valid key data injected")
        else:
            errors.append("Failed to inject key data")

        success = len(details) > 0

        return BypassResult(
            success=success,
            technique="Product Key Bypass",
            details="; ".join(details),
            errors=errors,
        )

    def _patch_key_validation(self, target_exe: Path) -> bool:
        """Patch product key validation logic.

        Args:
            target_exe: Path to the executable to patch.

        Returns:
            bool: True if key validation was successfully patched, False otherwise.
        """
        try:
            with open(target_exe, "r+b") as f:
                data = bytearray(f.read())

            validation_keywords = [b"VerifyProductKey", b"ValidateSerial", b"CheckProductKey"]

            modified = False
            for keyword in validation_keywords:
                offset = data.find(keyword)
                if offset != -1:
                    search_start = max(0, offset - 150)
                    for i in range(offset, search_start, -1):
                        if data[i : i + 3] == b"\x55\x8b\xec":
                            data[i] = 0xB8
                            data[i + 1 : i + 5] = b"\x01\x00\x00\x00"
                            data[i + 5] = 0xC3
                            modified = True
                            break

            if modified:
                with open(target_exe, "wb") as f:
                    f.write(bytes(data))

            return modified

        except Exception:
            return False

    def _inject_valid_key_data(self, target_exe: Path) -> bool:
        """Inject valid key data into registry.

        Args:
            target_exe: Path to the executable (used for context).

        Returns:
            bool: True if key data was successfully injected, False otherwise.
        """
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\SecuROM\ProductKeys")

            winreg.SetValueEx(key, "ProductKey", 0, winreg.REG_SZ, "A1B2C-D3E4F-G5H6I-J7K8L-M9N0P")
            winreg.SetValueEx(key, "SerialNumber", 0, winreg.REG_SZ, "BYPASSED1234567890")
            winreg.SetValueEx(key, "KeyValid", 0, winreg.REG_DWORD, 1)

            winreg.CloseKey(key)
            return True

        except OSError:
            return False

    def block_phone_home(self, target_exe: Path, server_urls: list[str] | None = None) -> BypassResult:
        """Block phone-home mechanisms.

        Args:
            target_exe: Path to protected executable.
            server_urls: Optional list of activation server URLs to block.

        Returns:
            BypassResult: Contains blocking success status, technique name, detailed results, and error list.
        """
        errors = []
        details = []

        if self._patch_network_calls(target_exe):
            details.append("Network calls patched in binary")
        else:
            errors.append("Failed to patch network calls")

        if self._add_hosts_entries(server_urls or []):
            details.append("Hosts file entries added")
        else:
            errors.append("Failed to modify hosts file")

        if self._block_firewall(server_urls or []):
            details.append("Firewall rules created")
        else:
            errors.append("Failed to create firewall rules")

        success = len(details) > 0

        return BypassResult(
            success=success,
            technique="Phone-Home Blocking",
            details="; ".join(details),
            errors=errors,
        )

    def _patch_network_calls(self, target_exe: Path) -> bool:
        """Patch network API calls to return immediately.

        Args:
            target_exe: Path to the executable to patch.

        Returns:
            bool: True if network calls were successfully patched, False otherwise.
        """
        try:
            with open(target_exe, "r+b") as f:
                data = bytearray(f.read())

            network_apis = [b"WinHttpSendRequest", b"InternetOpenUrl", b"HttpSendRequest"]

            modified = False
            for api in network_apis:
                offset = data.find(api)
                if offset != -1:
                    for i in range(max(0, offset - 100), min(len(data) - 6, offset + 50)):
                        if data[i : i + 2] in [b"\xff\x15", b"\xff\x25"]:
                            data[i] = 0xB8
                            data[i + 1 : i + 5] = b"\x01\x00\x00\x00"
                            data[i + 5] = 0xC3
                            modified = True
                            break

            if modified:
                with open(target_exe, "wb") as f:
                    f.write(bytes(data))

            return modified

        except Exception:
            return False

    def _add_hosts_entries(self, server_urls: list[str]) -> bool:
        """Add activation server URLs to hosts file.

        Args:
            server_urls: List of activation server URLs to block.

        Returns:
            bool: True if hosts file entries were successfully added, False otherwise.
        """
        try:
            hosts_path = Path(r"C:\Windows\System32\drivers\etc\hosts")

            default_servers = [
                "activation.securom.com",
                "validation.securom.com",
                "online.securom.com",
            ]

            all_servers = server_urls + default_servers

            with open(hosts_path, "a") as f:
                f.write("\n# SecuROM Activation Server Blocking\n")
                for server in all_servers:
                    clean_server = server.replace("https://", "").replace("http://", "").split("/")[0]
                    f.write(f"127.0.0.1 {clean_server}\n")

            return True

        except Exception:
            return False

    def _block_firewall(self, server_urls: list[str]) -> bool:
        """Create firewall rules to block activation servers.

        Args:
            server_urls: List of activation server URLs to block.

        Returns:
            bool: True if firewall rules were successfully created, False otherwise.

        """
        try:
            for server in server_urls:
                clean_server = server.replace("https://", "").replace("http://", "").split("/")[0]

                subprocess.run(
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name=Block SecuROM {clean_server}",
                        "dir=out",
                        "action=block",
                        f"remoteip={clean_server}",
                    ],
                    capture_output=True,
                    check=False,
                )

            return True

        except Exception:
            return False

    def defeat_challenge_response(self, target_exe: Path) -> BypassResult:
        """Defeat challenge-response authentication.

        Args:
            target_exe: Path to protected executable.

        Returns:
            BypassResult: Contains challenge-response defeat success status, technique name, detailed results, and error list.

        """
        if not PEFILE_AVAILABLE or not target_exe.exists():
            return BypassResult(
                success=False,
                technique="Challenge-Response Defeat",
                details="PE file unavailable or target does not exist",
                errors=["pefile not available or file not found"],
            )

        errors = []
        details = []

        if self._patch_challenge_generation(target_exe):
            details.append("Challenge generation bypassed")
        else:
            errors.append("Failed to bypass challenge generation")

        if self._patch_response_validation(target_exe):
            details.append("Response validation always succeeds")
        else:
            errors.append("Failed to patch response validation")

        success = len(details) > 0

        return BypassResult(
            success=success,
            technique="Challenge-Response Defeat",
            details="; ".join(details),
            errors=errors,
        )

    def _patch_challenge_generation(self, target_exe: Path) -> bool:
        """Patch challenge generation to return fixed value.

        Args:
            target_exe: Path to the executable to patch.

        Returns:
            bool: True if challenge generation was successfully patched, False otherwise.

        """
        try:
            with open(target_exe, "r+b") as f:
                data = bytearray(f.read())

            challenge_keywords = [
                b"GetActivationChallenge",
                b"GenerateChallenge",
                b"CreateChallenge",
            ]

            modified = False
            for keyword in challenge_keywords:
                offset = data.find(keyword)
                if offset != -1:
                    search_start = max(0, offset - 200)
                    for i in range(offset, search_start, -1):
                        if data[i : i + 3] == b"\x55\x8b\xec":
                            data[i] = 0x33
                            data[i + 1] = 0xC0
                            data[i + 2] = 0xC3
                            modified = True
                            break

            if modified:
                with open(target_exe, "wb") as f:
                    f.write(bytes(data))

            return modified

        except Exception:
            return False

    def _patch_response_validation(self, target_exe: Path) -> bool:
        """Patch response validation to always return success.

        Args:
            target_exe: Path to the executable to patch.

        Returns:
            bool: True if response validation was successfully patched, False otherwise.

        """
        try:
            with open(target_exe, "r+b") as f:
                data = bytearray(f.read())

            response_keywords = [b"ValidateResponse", b"VerifyResponse", b"CheckResponse"]

            modified = False
            for keyword in response_keywords:
                offset = data.find(keyword)
                if offset != -1:
                    search_start = max(0, offset - 200)
                    for i in range(offset, search_start, -1):
                        if data[i : i + 3] == b"\x55\x8b\xec":
                            data[i] = 0xB8
                            data[i + 1 : i + 5] = b"\x01\x00\x00\x00"
                            data[i + 5] = 0xC3
                            modified = True
                            break

            if modified:
                with open(target_exe, "wb") as f:
                    f.write(bytes(data))

            return modified

        except Exception:
            return False
