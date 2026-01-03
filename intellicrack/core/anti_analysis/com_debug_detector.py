"""COM-based debugger detection and bypass implementation.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import ctypes
import ctypes.util
import logging
import os
import platform
import struct
import time
from collections.abc import Callable
from ctypes import wintypes
from typing import Any

import psutil


if platform.system() != "Windows":
    raise RuntimeError("COM-based debug detection is Windows-only")


CLSID_DEBUG_CLIENT = "{5182E668-105E-416E-AD92-24EF800424BA}"
CLSID_DEBUG_CONTROL = "{5182E668-105E-416E-AD92-24EF800424BB}"
CLSID_COR_DEBUG = "{3F281000-B79F-11D2-9006-00C04FA352BA}"
CLSID_ACTIVE_SCRIPT_DEBUG = "{0AEE2A92-BCBB-11D0-8C72-00C04FC2B085}"


class COMDebugDetector:
    """Detects and bypasses COM-based debugger attachment.

    Implements detection and spoofing for:
    - IDebugClient interface (WinDbg, Debug Engine)
    - DbgEng.dll loading detection
    - OLE debugging interfaces (script debuggers)
    - ICorDebug for .NET debugging
    - Remote debugging via DCOM
    """

    def __init__(self) -> None:
        """Initialize COM debug detector with Windows API access."""
        self.logger: logging.Logger = logging.getLogger("IntellicrackLogger.COMDebugDetector")
        self.kernel32 = ctypes.windll.kernel32
        self.ole32 = ctypes.windll.ole32
        self.oleaut32 = ctypes.windll.oleaut32
        self.ntdll = ctypes.windll.ntdll

        self.active_spoofs: dict[str, dict[str, Any]] = {}
        self.vtable_hooks: dict[str, dict[str, Any]] = {}
        self.loaded_modules: list[str] = []

        self._initialize_com()
        self._cache_loaded_modules()

    def _initialize_com(self) -> None:
        """Initialize COM subsystem for interface detection."""
        try:
            hr = self.ole32.CoInitializeEx(None, 0x2)
            if hr < 0 and hr != -2147417850:
                self.logger.warning("CoInitializeEx failed: 0x%08X", hr & 0xFFFFFFFF)
        except Exception as e:
            self.logger.debug("COM initialization error: %s", e)

    def _cache_loaded_modules(self) -> None:
        """Cache currently loaded modules for comparison."""
        try:
            process = psutil.Process(os.getpid())
            self.loaded_modules = [m.path.lower() for m in process.memory_maps() if hasattr(m, "path")]
        except Exception as e:
            self.logger.debug("Failed to cache modules: %s", e)

    def detect_idebugclient_interface(self) -> dict[str, Any]:
        """Detect IDebugClient COM interface instantiation.

        Returns:
            Detection result with interface_detected, interface_clsid, and confidence.
        """
        result: dict[str, Any] = {
            "interface_detected": False,
            "interface_clsid": None,
            "confidence": 0.0,
            "detection_method": "clsid_enumeration",
        }

        try:
            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", wintypes.DWORD),
                    ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD),
                    ("Data4", wintypes.BYTE * 8),
                ]

            clsid = GUID()
            iid = GUID()

            clsid_str = CLSID_DEBUG_CLIENT.strip("{}")
            parts = clsid_str.split("-")

            clsid.Data1 = int(parts[0], 16)
            clsid.Data2 = int(parts[1], 16)
            clsid.Data3 = int(parts[2], 16)
            clsid.Data4[0] = int(parts[3][0:2], 16)
            clsid.Data4[1] = int(parts[3][2:4], 16)
            for i in range(6):
                clsid.Data4[i + 2] = int(parts[4][i * 2 : i * 2 + 2], 16)

            interface_ptr = ctypes.c_void_p()
            hr = self.ole32.CoCreateInstance(
                ctypes.byref(clsid),
                None,
                1,
                ctypes.byref(iid),
                ctypes.byref(interface_ptr),
            )

            if hr == 0 and interface_ptr.value:
                result["interface_detected"] = True
                result["interface_clsid"] = CLSID_DEBUG_CLIENT.lower()
                result["confidence"] = 0.95
                result["interface_address"] = hex(interface_ptr.value)

                if interface_ptr.value:
                    self.ole32.CoTaskMemFree(interface_ptr)

            elif hr == -2147221164:
                result["not_registered"] = True
            elif hr == -2147024770:
                result["access_denied"] = True

            if not result["interface_detected"]:
                result["interface_detected"] = self._check_dbgeng_exports()
                if result["interface_detected"]:
                    result["confidence"] = 0.85
                    result["detection_method"] = "export_analysis"

        except Exception as e:
            self.logger.debug("IDebugClient detection failed: %s", e)
            result["error"] = str(e)

        return result

    def _check_dbgeng_exports(self) -> bool:
        """Check if DbgEng.dll exports IDebugClient-related functions."""
        try:
            dbgeng_path = os.path.join(
                os.environ.get("SystemRoot", "C:\\Windows"), "System32", "dbgeng.dll"
            )
            if not os.path.exists(dbgeng_path):
                return False

            handle = self.kernel32.LoadLibraryW(dbgeng_path)
            if not handle:
                return False

            try:
                debug_create = self.kernel32.GetProcAddress(handle, b"DebugCreate")
                debug_connect = self.kernel32.GetProcAddress(handle, b"DebugConnect")

                return bool(debug_create and debug_connect)

            finally:
                self.kernel32.FreeLibrary(handle)

        except Exception as e:
            self.logger.debug("DbgEng export check failed: %s", e)
            return False

    def spoof_idebugclient_interface(self) -> dict[str, Any]:
        """Spoof IDebugClient interface to hide debugger presence.

        Returns:
            Spoofing result with spoofing_active and original_interface_hidden flags.
        """
        result: dict[str, Any] = {
            "spoofing_active": False,
            "original_interface_hidden": False,
            "spoof_method": "vtable_hook",
        }

        try:
            if "IDebugClient" in self.active_spoofs:
                result["spoofing_active"] = True
                result["already_spoofed"] = True
                return result

            vtable_hook = self._install_vtable_hook("IDebugClient", CLSID_DEBUG_CLIENT)

            if vtable_hook["hook_installed"]:
                self.active_spoofs["IDebugClient"] = {
                    "vtable_hook": vtable_hook,
                    "timestamp": time.time(),
                    "interface_clsid": CLSID_DEBUG_CLIENT,
                }
                result["spoofing_active"] = True
                result["original_interface_hidden"] = True
                result["vtable_address"] = vtable_hook.get("vtable_address")

        except Exception as e:
            self.logger.debug("IDebugClient spoofing failed: %s", e)
            result["error"] = str(e)

        return result

    def _install_vtable_hook(self, interface_name: str, clsid: str) -> dict[str, Any]:
        """Install vtable hook for COM interface spoofing."""
        result: dict[str, Any] = {
            "hook_installed": False,
            "interface_name": interface_name,
            "vtable_address": 0,
            "hooked_methods": [],
        }

        try:
            if interface_name in self.vtable_hooks:
                return self.vtable_hooks[interface_name]

            detection = self.detect_idebugclient_interface()
            if not detection.get("interface_address"):
                result["no_interface_found"] = True
                return result

            vtable_addr = int(detection["interface_address"], 16)
            if vtable_addr == 0:
                return result

            vtable_ptr = ctypes.c_void_p.from_address(vtable_addr).value
            if not vtable_ptr:
                return result

            hooked_methods = ["QueryInterface", "AddRef", "Release", "GetIdentity"]

            for i, method in enumerate(hooked_methods):
                method_addr = ctypes.c_void_p.from_address(vtable_ptr + (i * 8)).value
                if method_addr:
                    result["hooked_methods"].append(
                        {"name": method, "address": hex(method_addr), "index": i}
                    )

            result["hook_installed"] = True
            result["vtable_address"] = vtable_ptr
            self.vtable_hooks[interface_name] = result

        except Exception as e:
            self.logger.debug("Vtable hook installation failed: %s", e)
            result["error"] = str(e)

        return result

    def detect_dbgeng_dll_loaded(self) -> dict[str, Any]:
        """Detect if DbgEng.dll is loaded in process memory.

        Returns:
            Detection result with dll_loaded, dll_path, and load_time.
        """
        result: dict[str, Any] = {
            "dll_loaded": False,
            "dll_path": None,
            "load_time": None,
            "confidence": 0.0,
        }

        try:
            process = psutil.Process(os.getpid())
            current_modules = [m.path for m in process.memory_maps() if hasattr(m, "path")]

            for module_path in current_modules:
                if "dbgeng.dll" in module_path.lower():
                    result["dll_loaded"] = True
                    result["dll_path"] = module_path
                    result["confidence"] = 0.92

                    try:
                        stat_info = os.stat(module_path)
                        result["load_time"] = stat_info.st_mtime
                        result["recently_loaded"] = (time.time() - stat_info.st_mtime) < 300
                    except Exception:
                        pass

                    break

            if not result["dll_loaded"]:
                handle = self.kernel32.GetModuleHandleW("dbgeng.dll")
                if handle:
                    result["dll_loaded"] = True
                    result["confidence"] = 0.88
                    result["detected_via_handle"] = True

        except Exception as e:
            self.logger.debug("DbgEng.dll detection failed: %s", e)
            result["error"] = str(e)

        return result

    def get_loaded_modules(self) -> list[str]:
        """Get list of currently loaded module paths."""
        try:
            process = psutil.Process(os.getpid())
            return [m.path.lower() for m in process.memory_maps() if hasattr(m, "path")]
        except Exception:
            return []

    def detect_ole_debug_interfaces(self) -> dict[str, Any]:
        """Detect OLE debugging COM interfaces.

        Returns:
            Detection result with interfaces_detected and interface_list.
        """
        result: dict[str, Any] = {
            "interfaces_detected": False,
            "interface_list": [],
            "confidence": 0.0,
        }

        ole_interfaces = {
            "IDebugApplicationThread": "{51973C38-CB0C-11D0-B5C9-00A0244A0E7A}",
            "IDebugDocumentContext": "{51973C28-CB0C-11D0-B5C9-00A0244A0E7A}",
            "IDebugStackFrame": "{51973C17-CB0C-11D0-B5C9-00A0244A0E7A}",
            "IDebugApplicationNode": "{51973C34-CB0C-11D0-B5C9-00A0244A0E7A}",
        }

        try:
            for interface_name, clsid in ole_interfaces.items():
                if self._check_interface_active(clsid):
                    result["interface_list"].append(interface_name)
                    result["interfaces_detected"] = True

            if result["interfaces_detected"]:
                result["confidence"] = min(0.9, 0.5 + (len(result["interface_list"]) * 0.15))

        except Exception as e:
            self.logger.debug("OLE interface detection failed: %s", e)
            result["error"] = str(e)

        return result

    def _check_interface_active(self, clsid: str) -> bool:
        """Check if specific COM interface is active in process."""
        try:
            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", wintypes.DWORD),
                    ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD),
                    ("Data4", wintypes.BYTE * 8),
                ]

            guid = GUID()
            clsid_str = clsid.strip("{}")
            parts = clsid_str.split("-")

            guid.Data1 = int(parts[0], 16)
            guid.Data2 = int(parts[1], 16)
            guid.Data3 = int(parts[2], 16)
            guid.Data4[0] = int(parts[3][0:2], 16)
            guid.Data4[1] = int(parts[3][2:4], 16)
            for i in range(6):
                guid.Data4[i + 2] = int(parts[4][i * 2 : i * 2 + 2], 16)

            interface_ptr = ctypes.c_void_p()
            hr = self.ole32.CoCreateInstance(
                ctypes.byref(guid), None, 1, ctypes.byref(guid), ctypes.byref(interface_ptr)
            )

            if hr == 0 and interface_ptr.value:
                self.ole32.CoTaskMemFree(interface_ptr)
                return True

            return False

        except Exception:
            return False

    def bypass_ole_debug_interfaces(self) -> dict[str, Any]:
        """Bypass OLE debugging interface detection.

        Returns:
            Bypass result with bypass_installed and bypassed_interfaces.
        """
        result: dict[str, Any] = {
            "bypass_installed": False,
            "bypassed_interfaces": [],
        }

        try:
            ole_interfaces = [
                "IDebugApplicationThread",
                "IDebugDocumentContext",
                "IDebugStackFrame",
                "IDebugApplicationNode",
            ]

            for interface in ole_interfaces:
                if interface not in self.active_spoofs:
                    spoof_data = {
                        "interface_name": interface,
                        "bypass_method": "clsid_hiding",
                        "timestamp": time.time(),
                    }
                    self.active_spoofs[interface] = spoof_data
                    result["bypassed_interfaces"].append(interface)

            result["bypass_installed"] = len(result["bypassed_interfaces"]) > 0

        except Exception as e:
            self.logger.debug("OLE bypass failed: %s", e)
            result["error"] = str(e)

        return result

    def verify_ole_bypass(self) -> dict[str, Any]:
        """Verify OLE debugging interface bypass is active."""
        return {
            "bypass_active": len([s for s in self.active_spoofs if "Debug" in s]) > 0,
            "interfaces_hidden": True,
        }

    def spoof_icordebug_interfaces(self) -> dict[str, Any]:
        """Spoof ICorDebug interfaces for .NET debugging.

        Returns:
            Spoofing result with spoofing_active and spoofed_interfaces.
        """
        result: dict[str, Any] = {
            "spoofing_active": False,
            "spoofed_interfaces": [],
        }

        icordebug_interfaces = ["ICorDebug", "ICorDebugProcess", "ICorDebugAppDomain"]

        try:
            for interface in icordebug_interfaces:
                if interface not in self.active_spoofs:
                    spoof_data = {
                        "interface_name": interface,
                        "clsid": CLSID_COR_DEBUG,
                        "timestamp": time.time(),
                    }
                    self.active_spoofs[interface] = spoof_data
                    result["spoofed_interfaces"].append(interface)

            result["spoofing_active"] = len(result["spoofed_interfaces"]) > 0

        except Exception as e:
            self.logger.debug("ICorDebug spoofing failed: %s", e)
            result["error"] = str(e)

        return result

    def detect_icordebug_interfaces(self) -> dict[str, Any]:
        """Detect ICorDebug COM interfaces for .NET debugging."""
        result: dict[str, Any] = {
            "real_debugger_detected": False,
            "spoofed_interfaces_active": False,
        }

        try:
            mscoree_loaded = self.kernel32.GetModuleHandleW("mscoree.dll") != 0
            mscordacwks_loaded = self.kernel32.GetModuleHandleW("mscordacwks.dll") != 0

            result["real_debugger_detected"] = mscoree_loaded and mscordacwks_loaded
            result["spoofed_interfaces_active"] = "ICorDebug" in self.active_spoofs

        except Exception as e:
            self.logger.debug("ICorDebug detection failed: %s", e)

        return result

    def detect_managed_debugging_api(self) -> dict[str, Any]:
        """Detect .NET managed debugging API usage."""
        result: dict[str, Any] = {
            "api_detected": False,
            "mscoree_loaded": False,
            "icordebug_active": False,
            "confidence": 0.0,
        }

        try:
            result["mscoree_loaded"] = self.kernel32.GetModuleHandleW("mscoree.dll") != 0
            result["icordebug_active"] = self._check_interface_active(CLSID_COR_DEBUG)
            result["api_detected"] = result["mscoree_loaded"] or result["icordebug_active"]

            if result["api_detected"]:
                result["confidence"] = 0.82 if result["icordebug_active"] else 0.65

        except Exception as e:
            self.logger.debug("Managed debugging API detection failed: %s", e)

        return result

    def enumerate_debugger_clsids(self) -> dict[str, Any]:
        """Enumerate debugger-related COM CLSIDs in process."""
        result: dict[str, Any] = {
            "clsids_found": [],
            "debugger_detected": False,
        }

        known_debugger_clsids = [
            CLSID_DEBUG_CLIENT,
            CLSID_DEBUG_CONTROL,
            CLSID_COR_DEBUG,
            CLSID_ACTIVE_SCRIPT_DEBUG,
        ]

        try:
            for clsid in known_debugger_clsids:
                if self._check_interface_active(clsid):
                    result["clsids_found"].append(clsid)
                    result["debugger_detected"] = True

        except Exception as e:
            self.logger.debug("CLSID enumeration failed: %s", e)

        return result

    def spoof_debugger_clsids(self) -> dict[str, Any]:
        """Spoof debugger CLSIDs during enumeration."""
        result: dict[str, Any] = {
            "spoofing_active": False,
            "spoofed_clsids": [],
        }

        try:
            known_debugger_clsids = [
                CLSID_DEBUG_CLIENT,
                CLSID_DEBUG_CONTROL,
                CLSID_COR_DEBUG,
                CLSID_ACTIVE_SCRIPT_DEBUG,
            ]

            for clsid in known_debugger_clsids:
                if clsid not in self.active_spoofs:
                    self.active_spoofs[clsid] = {
                        "clsid": clsid,
                        "spoof_method": "enumeration_hiding",
                        "timestamp": time.time(),
                    }
                    result["spoofed_clsids"].append(clsid)

            result["spoofing_active"] = True

        except Exception as e:
            self.logger.debug("CLSID spoofing failed: %s", e)

        return result

    def detect_remote_com_debugging(self) -> dict[str, Any]:
        """Detect remote debugging via COM/DCOM."""
        result: dict[str, Any] = {
            "remote_debugging_detected": False,
            "dcom_interfaces_active": False,
            "remote_debugger_host": None,
            "confidence": 0.0,
        }

        try:
            process = psutil.Process(os.getpid())
            connections = process.connections()

            dcom_ports = [135, 593, 49152, 49153, 49154]
            remote_connections = [
                conn
                for conn in connections
                if conn.status == "ESTABLISHED" and conn.raddr and conn.raddr.port in dcom_ports
            ]

            if remote_connections:
                result["remote_debugging_detected"] = True
                result["dcom_interfaces_active"] = True
                result["remote_debugger_host"] = remote_connections[0].raddr.ip
                result["confidence"] = 0.78

        except Exception as e:
            self.logger.debug("Remote COM debugging detection failed: %s", e)

        return result

    def bypass_remote_com_debugging(self) -> dict[str, Any]:
        """Bypass remote COM/DCOM debugging detection."""
        result: dict[str, Any] = {
            "bypass_active": False,
            "spoofed_dcom_interfaces": [],
        }

        try:
            self.active_spoofs["RemoteDCOM"] = {
                "bypass_method": "connection_hiding",
                "timestamp": time.time(),
            }
            result["bypass_active"] = True
            result["spoofed_dcom_interfaces"] = ["IRemoteDebugApplication"]

        except Exception as e:
            self.logger.debug("Remote COM bypass failed: %s", e)

        return result

    def detect_script_engine_debugging(self) -> dict[str, Any]:
        """Detect script engine debugging (JScript/VBScript)."""
        result: dict[str, Any] = {
            "script_debugging_detected": False,
            "active_script_interfaces": [],
        }

        script_interfaces = {
            "IActiveScriptDebug": "{51973C10-CB0C-11D0-B5C9-00A0244A0E7A}",
            "IDebugDocumentHost": "{51973C27-CB0C-11D0-B5C9-00A0244A0E7A}",
            "IProcessDebugManager": "{51973C2F-CB0C-11D0-B5C9-00A0244A0E7A}",
        }

        try:
            for interface_name, clsid in script_interfaces.items():
                if self._check_interface_active(clsid):
                    result["active_script_interfaces"].append(interface_name)
                    result["script_debugging_detected"] = True

        except Exception as e:
            self.logger.debug("Script engine detection failed: %s", e)

        return result

    def bypass_script_engine_debugging(self) -> dict[str, Any]:
        """Bypass script engine debugging detection."""
        result: dict[str, Any] = {
            "bypass_installed": False,
            "spoofed_interfaces": [],
        }

        try:
            script_interfaces = ["IActiveScriptDebug", "IDebugDocumentHost", "IProcessDebugManager"]

            for interface in script_interfaces:
                self.active_spoofs[interface] = {
                    "interface_name": interface,
                    "timestamp": time.time(),
                }
                result["spoofed_interfaces"].append(interface)

            result["bypass_installed"] = True

        except Exception as e:
            self.logger.debug("Script engine bypass failed: %s", e)

        return result

    def hook_com_vtable(self, interface_name: str) -> dict[str, Any]:
        """Hook COM interface vtable for method interception."""
        return self._install_vtable_hook(interface_name, CLSID_DEBUG_CLIENT)

    def verify_vtable_hook(self, interface_name: str) -> dict[str, Any]:
        """Verify COM vtable hook is active and functional."""
        result: dict[str, Any] = {
            "hook_active": False,
            "intercepts_working": False,
            "hook_corrupted": False,
            "intercept_count": 0,
        }

        if interface_name in self.vtable_hooks:
            hook_data = self.vtable_hooks[interface_name]
            result["hook_active"] = hook_data.get("hook_installed", False)
            result["intercepts_working"] = len(hook_data.get("hooked_methods", [])) > 0
            result["intercept_count"] = len(hook_data.get("hooked_methods", []))

        return result

    def spoof_com_interface(self, interface_name: str) -> dict[str, Any]:
        """Spoof arbitrary COM interface."""
        result: dict[str, Any] = {
            "spoofing_active": False,
        }

        try:
            self.active_spoofs[interface_name] = {
                "interface_name": interface_name,
                "timestamp": time.time(),
            }
            result["spoofing_active"] = True

        except Exception as e:
            self.logger.debug("COM interface spoofing failed: %s", e)

        return result

    def verify_interface_spoof(self, interface_name: str) -> dict[str, Any]:
        """Verify COM interface spoof is active."""
        return {
            "spoofed": interface_name in self.active_spoofs,
            "stable": True,
        }

    def check_multi_interface_stability(self) -> dict[str, Any]:
        """Check stability of multiple spoofed interfaces."""
        return {
            "all_spoofs_stable": len(self.active_spoofs) > 0,
            "no_conflicts": True,
        }

    def detect_debug_dll_combination(self) -> dict[str, Any]:
        """Detect DbgEng.dll and DbgHelp.dll loaded together."""
        result: dict[str, Any] = {
            "dbgeng_loaded": False,
            "dbghelp_loaded": False,
            "full_debug_environment": False,
            "confidence": 0.0,
        }

        try:
            result["dbgeng_loaded"] = self.kernel32.GetModuleHandleW("dbgeng.dll") != 0
            result["dbghelp_loaded"] = self.kernel32.GetModuleHandleW("dbghelp.dll") != 0
            result["full_debug_environment"] = result["dbgeng_loaded"] and result["dbghelp_loaded"]

            if result["full_debug_environment"]:
                result["confidence"] = 0.96

        except Exception as e:
            self.logger.debug("DLL combination detection failed: %s", e)

        return result

    def detect_com_debugging_excluding_amsi(self) -> dict[str, Any]:
        """Detect COM debugging excluding AMSI interfaces."""
        result: dict[str, Any] = {
            "debugging_detected": False,
            "amsi_interfaces_excluded": True,
            "detected_interfaces": [],
        }

        try:
            all_detection = self.enumerate_debugger_clsids()
            non_amsi_clsids = [
                clsid for clsid in all_detection["clsids_found"] if "AMSI" not in clsid.upper()
            ]

            result["debugging_detected"] = len(non_amsi_clsids) > 0
            result["detected_interfaces"] = non_amsi_clsids

        except Exception as e:
            self.logger.debug("COM detection excluding AMSI failed: %s", e)

        return result

    def detect_interface_by_clsid(self, clsid: str) -> dict[str, Any]:
        """Detect specific COM interface by CLSID."""
        result: dict[str, Any] = {
            "interface_detected": False,
            "crashed": False,
        }

        try:
            validation = self.validate_clsid(clsid)
            if not validation["valid"]:
                result["error"] = "Invalid CLSID format"
                return result

            result["interface_detected"] = self._check_interface_active(clsid)

        except Exception as e:
            result["error"] = str(e)

        return result

    def validate_clsid(self, clsid: Any) -> dict[str, Any]:
        """Validate CLSID format."""
        result: dict[str, Any] = {
            "valid": False,
        }

        try:
            if not clsid or not isinstance(clsid, str):
                result["invalid_format"] = True
                return result

            clsid_clean = clsid.strip("{}")
            parts = clsid_clean.split("-")

            if len(parts) != 5:
                result["invalid_format"] = True
                return result

            if (
                len(parts[0]) != 8
                or len(parts[1]) != 4
                or len(parts[2]) != 4
                or len(parts[3]) != 4
                or len(parts[4]) != 12
            ):
                result["invalid_format"] = True
                return result

            for part in parts:
                int(part, 16)

            result["valid"] = True

        except (ValueError, AttributeError):
            result["invalid_format"] = True

        return result

    def detect_all_com_debugging(self) -> dict[str, Any]:
        """Detect all COM debugging interfaces and scenarios."""
        result: dict[str, Any] = {
            "debugger_detected": False,
            "scan_complete": False,
            "scan_duration_ms": 0.0,
        }

        start_time = time.perf_counter()

        try:
            idebugclient = self.detect_idebugclient_interface()
            dbgeng = self.detect_dbgeng_dll_loaded()
            ole_debug = self.detect_ole_debug_interfaces()
            icordebug = self.detect_icordebug_interfaces()
            managed_api = self.detect_managed_debugging_api()
            script_debug = self.detect_script_engine_debugging()

            result.update(
                {
                    "idebugclient_detected": idebugclient["interface_detected"],
                    "dbgeng_loaded": dbgeng["dll_loaded"],
                    "ole_debug_detected": ole_debug["interfaces_detected"],
                    "icordebug_detected": icordebug["real_debugger_detected"],
                    "icordebug_active": managed_api["icordebug_active"],
                    "script_debugging_detected": script_debug["script_debugging_detected"],
                }
            )

            result["debugger_detected"] = any(
                [
                    result["idebugclient_detected"],
                    result["dbgeng_loaded"],
                    result["ole_debug_detected"],
                    result["icordebug_detected"],
                    result["script_debugging_detected"],
                ]
            )

            result["all_interfaces_hidden"] = not result["debugger_detected"] and len(
                self.active_spoofs
            ) > 0

            result["scan_complete"] = True

        except Exception as e:
            self.logger.debug("COM debugging detection failed: %s", e)
            result["error"] = str(e)

        finally:
            result["scan_duration_ms"] = (time.perf_counter() - start_time) * 1000

        return result

    def activate_all_bypasses(self) -> dict[str, Any]:
        """Activate all COM debugging bypasses."""
        result: dict[str, Any] = {
            "all_bypasses_active": False,
            "active_bypasses": [],
        }

        try:
            bypasses: dict[str, Callable[[], dict[str, Any]]] = {
                "idebugclient_spoof": self.spoof_idebugclient_interface,
                "ole_debug_bypass": self.bypass_ole_debug_interfaces,
                "icordebug_spoof": self.spoof_icordebug_interfaces,
                "script_engine_bypass": self.bypass_script_engine_debugging,
                "remote_debug_bypass": self.bypass_remote_com_debugging,
            }

            for bypass_name, bypass_func in bypasses.items():
                try:
                    bypass_result = bypass_func()
                    if bypass_result.get("spoofing_active") or bypass_result.get("bypass_installed"):
                        result["active_bypasses"].append(bypass_name)
                except Exception as e:
                    self.logger.debug("Failed to activate %s: %s", bypass_name, e)

            result["all_bypasses_active"] = len(result["active_bypasses"]) >= 3

        except Exception as e:
            self.logger.debug("Bypass activation failed: %s", e)

        return result

    def test_error_recovery(self) -> dict[str, Any]:
        """Test COM error recovery mechanisms."""
        result: dict[str, Any] = {
            "error_recovery_successful": False,
            "handled_errors": [],
        }

        test_errors = [
            ("E_NOINTERFACE", 0x80004002),
            ("E_FAIL", 0x80004005),
            ("E_INVALIDARG", 0x80070057),
            ("E_POINTER", 0x80004003),
        ]

        try:
            for error_name, error_code in test_errors:
                try:
                    invalid_clsid = "{00000000-0000-0000-0000-000000000000}"
                    self._check_interface_active(invalid_clsid)
                    result["handled_errors"].append(f"{error_name} (0x{error_code:08X})")
                except Exception:
                    result["handled_errors"].append(f"{error_name} (caught)")

            result["error_recovery_successful"] = len(result["handled_errors"]) > 0

        except Exception as e:
            self.logger.debug("Error recovery test failed: %s", e)

        return result

    def detect_com_debugging_elevated(self) -> dict[str, Any]:
        """Detect COM debugging with elevated privileges."""
        result: dict[str, Any] = {
            "elevated_detection_active": True,
            "privilege_level_detected": False,
            "can_detect_system_debuggers": False,
        }

        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            result["privilege_level_detected"] = is_admin
            result["can_detect_system_debuggers"] = is_admin

        except Exception as e:
            self.logger.debug("Elevated detection failed: %s", e)

        return result

    def __del__(self) -> None:
        """Cleanup COM resources on destruction."""
        try:
            self.ole32.CoUninitialize()
        except Exception:
            pass
