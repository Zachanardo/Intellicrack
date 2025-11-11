"""Windows Service Management Utilities.

Provides comprehensive Windows service control functionality for managing
protection driver services, querying status, and performing administrative operations.
"""

import ctypes
import logging
from ctypes import wintypes
from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional


class ServiceState(IntEnum):
    """Windows service states."""

    STOPPED = 1
    START_PENDING = 2
    STOP_PENDING = 3
    RUNNING = 4
    CONTINUE_PENDING = 5
    PAUSE_PENDING = 6
    PAUSED = 7


class ServiceType(IntEnum):
    """Windows service types."""

    KERNEL_DRIVER = 0x00000001
    FILE_SYSTEM_DRIVER = 0x00000002
    ADAPTER = 0x00000004
    RECOGNIZER_DRIVER = 0x00000008
    WIN32_OWN_PROCESS = 0x00000010
    WIN32_SHARE_PROCESS = 0x00000020
    INTERACTIVE_PROCESS = 0x00000100


class ServiceStartType(IntEnum):
    """Windows service start types."""

    BOOT_START = 0
    SYSTEM_START = 1
    AUTO_START = 2
    DEMAND_START = 3
    DISABLED = 4


@dataclass
class ServiceInfo:
    """Windows service information."""

    name: str
    display_name: str
    state: ServiceState
    service_type: ServiceType
    start_type: ServiceStartType
    binary_path: str
    dependencies: List[str]


class ServiceStatus(ctypes.Structure):
    """SERVICE_STATUS structure."""

    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


class QueryServiceConfig(ctypes.Structure):
    """QUERY_SERVICE_CONFIG structure."""

    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwStartType", wintypes.DWORD),
        ("dwErrorControl", wintypes.DWORD),
        ("lpBinaryPathName", wintypes.LPWSTR),
        ("lpLoadOrderGroup", wintypes.LPWSTR),
        ("dwTagId", wintypes.DWORD),
        ("lpDependencies", wintypes.LPWSTR),
        ("lpServiceStartName", wintypes.LPWSTR),
        ("lpDisplayName", wintypes.LPWSTR),
    ]


class WindowsServiceManager:
    """Comprehensive Windows service management system.

    Provides service enumeration, control, configuration query,
    and administrative operations for managing Windows services.
    """

    SC_MANAGER_ALL_ACCESS = 0xF003F
    SC_MANAGER_ENUMERATE_SERVICE = 0x0004
    SC_MANAGER_QUERY_LOCK_STATUS = 0x0010

    SERVICE_QUERY_CONFIG = 0x0001
    SERVICE_CHANGE_CONFIG = 0x0002
    SERVICE_QUERY_STATUS = 0x0004
    SERVICE_ENUMERATE_DEPENDENTS = 0x0008
    SERVICE_START = 0x0010
    SERVICE_STOP = 0x0020
    SERVICE_PAUSE_CONTINUE = 0x0040
    SERVICE_INTERROGATE = 0x0080
    SERVICE_USER_DEFINED_CONTROL = 0x0100
    SERVICE_ALL_ACCESS = 0xF01FF

    SERVICE_CONTROL_STOP = 1
    SERVICE_CONTROL_PAUSE = 2
    SERVICE_CONTROL_CONTINUE = 3
    SERVICE_CONTROL_INTERROGATE = 4

    def __init__(self) -> None:
        """Initialize Windows service manager."""
        self.logger = logging.getLogger(__name__)
        self._advapi32 = None
        self._setup_winapi()

    def _setup_winapi(self) -> None:
        """Set up Windows API functions."""
        try:
            self._advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

            self._advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
            self._advapi32.OpenSCManagerW.restype = wintypes.HANDLE

            self._advapi32.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
            self._advapi32.OpenServiceW.restype = wintypes.HANDLE

            self._advapi32.QueryServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(ServiceStatus)]
            self._advapi32.QueryServiceStatus.restype = wintypes.BOOL

            self._advapi32.QueryServiceConfigW.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(QueryServiceConfig),
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            self._advapi32.QueryServiceConfigW.restype = wintypes.BOOL

            self._advapi32.ControlService.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(ServiceStatus)]
            self._advapi32.ControlService.restype = wintypes.BOOL

            self._advapi32.StartServiceW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.LPCWSTR)]
            self._advapi32.StartServiceW.restype = wintypes.BOOL

            self._advapi32.DeleteService.argtypes = [wintypes.HANDLE]
            self._advapi32.DeleteService.restype = wintypes.BOOL

            self._advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
            self._advapi32.CloseServiceHandle.restype = wintypes.BOOL

        except Exception as e:
            self.logger.debug(f"Failed to setup Windows API functions: {e}")
            pass

    def get_service_info(self, service_name: str) -> Optional[ServiceInfo]:
        """Get detailed information about a service.

        Args:
            service_name: Name of the service

        Returns:
            ServiceInfo or None if service not found

        """
        if not self._advapi32:
            return None

        try:
            sc_manager = self._advapi32.OpenSCManagerW(None, None, self.SC_MANAGER_ALL_ACCESS)
            if not sc_manager:
                return None

            try:
                service_handle = self._advapi32.OpenServiceW(
                    sc_manager, service_name, self.SERVICE_QUERY_CONFIG | self.SERVICE_QUERY_STATUS,
                )

                if not service_handle:
                    return None

                try:
                    status = ServiceStatus()
                    if not self._advapi32.QueryServiceStatus(service_handle, ctypes.byref(status)):
                        return None

                    bytes_needed = wintypes.DWORD()
                    self._advapi32.QueryServiceConfigW(service_handle, None, 0, ctypes.byref(bytes_needed))

                    buffer = ctypes.create_string_buffer(bytes_needed.value)
                    config = ctypes.cast(buffer, ctypes.POINTER(QueryServiceConfig)).contents

                    if self._advapi32.QueryServiceConfigW(
                        service_handle, ctypes.byref(config), bytes_needed.value, ctypes.byref(bytes_needed),
                    ):
                        return ServiceInfo(
                            name=service_name,
                            display_name=config.lpDisplayName if config.lpDisplayName else service_name,
                            state=ServiceState(status.dwCurrentState),
                            service_type=ServiceType(config.dwServiceType),
                            start_type=ServiceStartType(config.dwStartType),
                            binary_path=config.lpBinaryPathName if config.lpBinaryPathName else "",
                            dependencies=self._parse_dependencies(config.lpDependencies),
                        )

                finally:
                    self._advapi32.CloseServiceHandle(service_handle)

            finally:
                self._advapi32.CloseServiceHandle(sc_manager)

        except Exception as e:
            self.logger.debug(f"Error enumerating services: {e}")
            pass

        return None

    def _parse_dependencies(self, deps_ptr: wintypes.LPWSTR) -> List[str]:
        """Parse double-null terminated dependency string."""
        if not deps_ptr:
            return []

        dependencies = []
        try:
            offset = 0
            while True:
                dep = ctypes.wstring_at(ctypes.addressof(deps_ptr) + offset * 2)
                if not dep:
                    break
                dependencies.append(dep)
                offset += len(dep) + 1
        except Exception as e:
            self.logger.debug(f"Error parsing dependencies: {e}")
            pass

        return dependencies

    def start_service(self, service_name: str, args: Optional[List[str]] = None) -> bool:
        """Start a Windows service.

        Args:
            service_name: Name of the service
            args: Optional service arguments

        Returns:
            True if successful

        """
        if not self._advapi32:
            return False

        try:
            sc_manager = self._advapi32.OpenSCManagerW(None, None, self.SC_MANAGER_ALL_ACCESS)
            if not sc_manager:
                return False

            try:
                service_handle = self._advapi32.OpenServiceW(sc_manager, service_name, self.SERVICE_START)

                if not service_handle:
                    return False

                try:
                    argc = len(args) if args else 0
                    argv = None

                    if args:
                        argv_array = (wintypes.LPCWSTR * argc)()
                        for i, arg in enumerate(args):
                            argv_array[i] = arg
                        argv = ctypes.cast(argv_array, ctypes.POINTER(wintypes.LPCWSTR))

                    result = self._advapi32.StartServiceW(service_handle, argc, argv)
                    return bool(result)

                finally:
                    self._advapi32.CloseServiceHandle(service_handle)

            finally:
                self._advapi32.CloseServiceHandle(sc_manager)

        except Exception as e:
            self.logger.debug(f"Error starting service {service_name}: {e}")
            pass

        return False

    def stop_service(self, service_name: str) -> bool:
        """Stop a Windows service.

        Args:
            service_name: Name of the service

        Returns:
            True if successful

        """
        if not self._advapi32:
            return False

        try:
            sc_manager = self._advapi32.OpenSCManagerW(None, None, self.SC_MANAGER_ALL_ACCESS)
            if not sc_manager:
                return False

            try:
                service_handle = self._advapi32.OpenServiceW(sc_manager, service_name, self.SERVICE_STOP)

                if not service_handle:
                    return False

                try:
                    status = ServiceStatus()
                    result = self._advapi32.ControlService(service_handle, self.SERVICE_CONTROL_STOP, ctypes.byref(status))
                    return bool(result)

                finally:
                    self._advapi32.CloseServiceHandle(service_handle)

            finally:
                self._advapi32.CloseServiceHandle(sc_manager)

        except Exception as e:
            self.logger.debug(f"Error stopping service {service_name}: {e}")
            pass

        return False

    def pause_service(self, service_name: str) -> bool:
        """Pause a Windows service.

        Args:
            service_name: Name of the service

        Returns:
            True if successful

        """
        if not self._advapi32:
            return False

        try:
            sc_manager = self._advapi32.OpenSCManagerW(None, None, self.SC_MANAGER_ALL_ACCESS)
            if not sc_manager:
                return False

            try:
                service_handle = self._advapi32.OpenServiceW(sc_manager, service_name, self.SERVICE_PAUSE_CONTINUE)

                if not service_handle:
                    return False

                try:
                    status = ServiceStatus()
                    result = self._advapi32.ControlService(service_handle, self.SERVICE_CONTROL_PAUSE, ctypes.byref(status))
                    return bool(result)

                finally:
                    self._advapi32.CloseServiceHandle(service_handle)

            finally:
                self._advapi32.CloseServiceHandle(sc_manager)

        except Exception as e:
            self.logger.debug(f"Error pausing service {service_name}: {e}")
            pass

        return False

    def continue_service(self, service_name: str) -> bool:
        """Continue a paused Windows service.

        Args:
            service_name: Name of the service

        Returns:
            True if successful

        """
        if not self._advapi32:
            return False

        try:
            sc_manager = self._advapi32.OpenSCManagerW(None, None, self.SC_MANAGER_ALL_ACCESS)
            if not sc_manager:
                return False

            try:
                service_handle = self._advapi32.OpenServiceW(sc_manager, service_name, self.SERVICE_PAUSE_CONTINUE)

                if not service_handle:
                    return False

                try:
                    status = ServiceStatus()
                    result = self._advapi32.ControlService(service_handle, self.SERVICE_CONTROL_CONTINUE, ctypes.byref(status))
                    return bool(result)

                finally:
                    self._advapi32.CloseServiceHandle(service_handle)

            finally:
                self._advapi32.CloseServiceHandle(sc_manager)

        except Exception as e:
            self.logger.debug(f"Error continuing service {service_name}: {e}")
            pass

        return False

    def delete_service(self, service_name: str) -> bool:
        """Delete a Windows service.

        Args:
            service_name: Name of the service

        Returns:
            True if successful

        """
        if not self._advapi32:
            return False

        try:
            sc_manager = self._advapi32.OpenSCManagerW(None, None, self.SC_MANAGER_ALL_ACCESS)
            if not sc_manager:
                return False

            try:
                DELETE = 0x00010000
                service_handle = self._advapi32.OpenServiceW(sc_manager, service_name, DELETE)

                if not service_handle:
                    return False

                try:
                    result = self._advapi32.DeleteService(service_handle)
                    return bool(result)

                finally:
                    self._advapi32.CloseServiceHandle(service_handle)

            finally:
                self._advapi32.CloseServiceHandle(sc_manager)

        except Exception as e:
            self.logger.debug(f"Error deleting service {service_name}: {e}")
            pass

        return False

    def get_service_state(self, service_name: str) -> Optional[ServiceState]:
        """Get current state of a service.

        Args:
            service_name: Name of the service

        Returns:
            ServiceState or None if service not found

        """
        if not self._advapi32:
            return None

        try:
            sc_manager = self._advapi32.OpenSCManagerW(None, None, self.SC_MANAGER_ALL_ACCESS)
            if not sc_manager:
                return None

            try:
                service_handle = self._advapi32.OpenServiceW(sc_manager, service_name, self.SERVICE_QUERY_STATUS)

                if not service_handle:
                    return None

                try:
                    status = ServiceStatus()
                    if self._advapi32.QueryServiceStatus(service_handle, ctypes.byref(status)):
                        return ServiceState(status.dwCurrentState)

                finally:
                    self._advapi32.CloseServiceHandle(service_handle)

            finally:
                self._advapi32.CloseServiceHandle(sc_manager)

        except Exception as e:
            self.logger.debug(f"Error querying service status {service_name}: {e}")
            pass

        return None

    def is_service_running(self, service_name: str) -> bool:
        """Check if a service is running.

        Args:
            service_name: Name of the service

        Returns:
            True if service is running

        """
        state = self.get_service_state(service_name)
        return state == ServiceState.RUNNING if state else False

    def wait_for_state(self, service_name: str, target_state: ServiceState, timeout_ms: int = 30000) -> bool:
        """Wait for service to reach target state.

        Args:
            service_name: Name of the service
            target_state: Desired service state
            timeout_ms: Timeout in milliseconds

        Returns:
            True if target state reached

        """
        import time

        start_time = time.time()
        timeout_seconds = timeout_ms / 1000.0

        while time.time() - start_time < timeout_seconds:
            current_state = self.get_service_state(service_name)

            if current_state == target_state:
                return True

            time.sleep(0.1)

        return False
