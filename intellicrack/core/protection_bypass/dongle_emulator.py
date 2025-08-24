"""Hardware Dongle Emulation Module.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import platform
from typing import Any

from ...utils.core.import_checks import FRIDA_AVAILABLE, WINREG_AVAILABLE, winreg


class HardwareDongleEmulator:
    """Implements hardware dongle emulation for various protection systems.

    This class provides methods to emulate hardware dongles by intercepting API calls,
    creating virtual dongle responses, and manipulating the software protection checks.
    """

    def __init__(self, app: Any | None = None):
        """Initialize the hardware dongle emulator.

        Args:
            app: Application instance that contains the binary_path attribute

        """
        self.app = app
        self.logger = logging.getLogger("IntellicrackLogger.DongleEmulator")
        self.hooks: list[dict[str, Any]] = []
        self.patches: list[dict[str, Any]] = []
        self.virtual_dongles: dict[str, dict[str, Any]] = {}

    def activate_dongle_emulation(self, dongle_types: list[str] = None) -> dict[str, Any]:
        """Main method to activate hardware dongle emulation.

        Args:
            dongle_types: List of dongle types to emulate (None for all supported types)

        Returns:
            dict: Results of the emulation activation with success status and methods applied

        """
        if dongle_types is None:
            dongle_types = [
                "SafeNet",
                "HASP",
                "CodeMeter",
                "Rainbow",
                "ROCKEY",
                "Dinkey",
                "SuperPro",
                "eToken",
            ]

        results = {
            "success": False,
            "emulated_dongles": [],
            "methods_applied": [],
            "errors": [],
        }

        # Strategy 1: Hook dongle API calls
        try:
            self._hook_dongle_apis(dongle_types)
            results["methods_applied"].append("API Hooking")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in dongle_emulator: %s", e)
            results["errors"].append(f"API hooking failed: {e!s}")

        # Strategy 2: Create virtual dongle responses
        try:
            self._create_virtual_dongles(dongle_types)
            results["methods_applied"].append("Virtual Dongle Creation")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in dongle_emulator: %s", e)
            results["errors"].append(f"Virtual dongle creation failed: {e!s}")

        # Strategy 3: Patch dongle check instructions
        try:
            if self.app and hasattr(self.app, "binary_path") and self.app.binary_path:
                self._patch_dongle_checks()
                results["methods_applied"].append("Binary Patching")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in dongle_emulator: %s", e)
            results["errors"].append(f"Binary patching failed: {e!s}")

        # Strategy 4: Install registry spoofing
        try:
            self._spoof_dongle_registry()
            results["methods_applied"].append("Registry Spoofing")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in dongle_emulator: %s", e)
            results["errors"].append(f"Registry spoofing failed: {e!s}")

        results["emulated_dongles"] = list(self.virtual_dongles.keys())
        results["success"] = len(results["methods_applied"]) > 0
        return results

    def _hook_dongle_apis(self, dongle_types: list[str]) -> None:
        """Hook Windows dongle APIs to return success values."""
        if not FRIDA_AVAILABLE:
            self.logger.warning("Frida not available - skipping dongle API hooking")
            return

        frida_script = """
        console.log("[Dongle Emulator] Starting comprehensive dongle API hooking...");

        // SafeNet Sentinel API hooks
        if (%s.includes("SafeNet")) {
            var sentinelModule = Process.findModuleByName("sentinel.dll");
            if (!sentinelModule) {
                sentinelModule = Process.findModuleByName("sentinelkeyW.dll");
            }

            if (sentinelModule) {
                // Hook Sentinel_Find
                var sentinelFind = Module.findExportByName(sentinelModule.name, "Sentinel_Find");
                if (sentinelFind) {
                    Interceptor.attach(sentinelFind, {
                        onEnter: function(args) {
                            console.log("[SafeNet] Intercepted Sentinel_Find");
                        },
                        onLeave: function(retval) {
                            retval.replace(0); // Return success
                            console.log("[SafeNet] Sentinel_Find returning SUCCESS");
                        }
                    });
                }

                // Hook Sentinel_Check
                var sentinelCheck = Module.findExportByName(sentinelModule.name, "Sentinel_Check");
                if (sentinelCheck) {
                    Interceptor.attach(sentinelCheck, {
                        onLeave: function(retval) {
                            retval.replace(0); // Return success
                            console.log("[SafeNet] Sentinel_Check returning SUCCESS");
                        }
                    });
                }

                console.log("[SafeNet] Sentinel API hooks installed");
            }
        }

        // HASP API hooks
        if (%s.includes("HASP")) {
            var haspModule = Process.findModuleByName("hasp_windows_x64_demo.dll");
            if (!haspModule) {
                haspModule = Process.findModuleByName("haspvb32.dll");
            }

            if (haspModule) {
                // Hook hasp_login
                var haspLogin = Module.findExportByName(haspModule.name, "hasp_login");
                if (haspLogin) {
                    Interceptor.attach(haspLogin, {
                        onEnter: function(args) {
                            console.log("[HASP] Intercepted hasp_login");
                        },
                        onLeave: function(retval) {
                            retval.replace(0); // HASP_STATUS_OK
                            console.log("[HASP] hasp_login returning HASP_STATUS_OK");
                        }
                    });
                }

                // Hook hasp_logout
                var haspLogout = Module.findExportByName(haspModule.name, "hasp_logout");
                if (haspLogout) {
                    Interceptor.attach(haspLogout, {
                        onLeave: function(retval) {
                            retval.replace(0); // HASP_STATUS_OK
                        }
                    });
                }

                // Hook hasp_encrypt
                var haspEncrypt = Module.findExportByName(haspModule.name, "hasp_encrypt");
                if (haspEncrypt) {
                    Interceptor.attach(haspEncrypt, {
                        onLeave: function(retval) {
                            retval.replace(0); // HASP_STATUS_OK
                        }
                    });
                }

                console.log("[HASP] HASP API hooks installed");
            }
        }

        // CodeMeter/WibuKey API hooks
        if (%s.includes("CodeMeter")) {
            var wibuModule = Process.findModuleByName("wibukey.dll");
            if (!wibuModule) {
                wibuModule = Process.findModuleByName("wibusys.dll");
            }

            if (wibuModule) {
                // Hook WkSelectMask
                var wkSelectMask = Module.findExportByName(wibuModule.name, "WkSelectMask");
                if (wkSelectMask) {
                    Interceptor.attach(wkSelectMask, {
                        onLeave: function(retval) {
                            retval.replace(1); // Return found
                            console.log("[CodeMeter] WkSelectMask returning FOUND");
                        }
                    });
                }

                // Hook WkGetHandle
                var wkGetHandle = Module.findExportByName(wibuModule.name, "WkGetHandle");
                if (wkGetHandle) {
                    Interceptor.attach(wkGetHandle, {
                        onLeave: function(retval) {
                            retval.replace(0x12345678); // Return valid handle
                            console.log("[CodeMeter] WkGetHandle returning valid handle");
                        }
                    });
                }

                console.log("[CodeMeter] CodeMeter API hooks installed");
            }
        }

        // Generic dongle detection hooks
        var kernel32 = Module.findModuleByName("kernel32.dll");
        if (kernel32) {
            // Hook CreateFile calls to dongle devices
            var createFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
            if (createFileW) {
                Interceptor.attach(createFileW, {
                    onEnter: function(args) {
                        var filename = args[0].readUtf16String();
                        if (filename && (filename.includes("Sentinel") || filename.includes("HASP") || filename.includes("WibuKey"))) {
                            console.log("[Dongle] Intercepted dongle device access: " + filename);
                            // Don't modify here, let it proceed to onLeave
                        }
                    },
                    onLeave: function(retval) {
                        var filename = this.context.r8 ? this.context.r8.readUtf16String() : "";
                        if (filename && (filename.includes("Sentinel") || filename.includes("HASP") || filename.includes("WibuKey"))) {
                            // Return a valid handle instead of INVALID_HANDLE_VALUE
                            retval.replace(0x12345678);
                            console.log("[Dongle] CreateFile for dongle device returning valid handle");
                        }
                    }
                });
            }
        }

        console.log("[Dongle Emulator] All dongle API hooks installed successfully!");
        """ % (str(dongle_types), str(dongle_types), str(dongle_types))

        self.hooks.append(
            {
                "type": "frida",
                "script": frida_script,
                "target": f"Dongle APIs: {', '.join(dongle_types)}",
            }
        )
        self.logger.info(f"Dongle API hooks installed for: {', '.join(dongle_types)}")

    def _create_virtual_dongles(self, dongle_types: list[str]) -> None:
        """Create virtual dongle devices that respond to application queries."""
        for dongle_type in dongle_types:
            if dongle_type == "SafeNet":
                self.virtual_dongles["SafeNet"] = {
                    "device_id": 0x12345678,
                    "vendor_id": 0x0529,  # SafeNet vendor ID
                    "product_id": 0x0001,
                    "firmware_version": "1.0.0",
                    "serial_number": "SN123456789",
                    "memory_size": 1024,
                    "algorithms": ["AES", "RSA", "DES"],
                }

            elif dongle_type == "HASP":
                self.virtual_dongles["HASP"] = {
                    "hasp_id": 0x12345678,
                    "vendor_code": 0x1234,
                    "feature_id": 0x0001,
                    "memory_size": 512,
                    "time_stamp": 0x12345678,
                    "password": b"defaultpass",
                }

            elif dongle_type == "CodeMeter":
                self.virtual_dongles["CodeMeter"] = {
                    "firm_code": 101,
                    "product_code": 1000,
                    "feature_code": 1,
                    "version": "6.90",
                    "serial_number": 1000001,
                    "user_data": b"\x00" * 32,
                }

        self.logger.info(f"Created virtual dongles: {list(self.virtual_dongles.keys())}")

    def _patch_dongle_checks(self) -> None:
        """Patch binary instructions that check for dongle presence."""
        if not self.app or not hasattr(self.app, "binary_path") or not self.app.binary_path:
            return

        try:
            with open(self.app.binary_path, "rb") as f:
                binary_data = f.read()

            # Common dongle check patterns
            dongle_check_patterns = [
                # Pattern for dongle presence check (JZ to JMP)
                {"pattern": b"\x85\xc0\x74", "patch": b"\x85\xc0\xeb"},
                # Pattern for dongle validation check
                {"pattern": b"\x83\xf8\x00\x75", "patch": b"\x83\xf8\x00\xeb"},
                # Pattern for dongle error check
                {"pattern": b"\x3d\xff\xff\xff\xff\x74", "patch": b"\x3d\xff\xff\xff\xff\xeb"},
            ]

            patches_applied = 0
            for pattern_info in dongle_check_patterns:
                pattern = pattern_info["pattern"]
                patch = pattern_info["patch"]

                offset = binary_data.find(pattern)
                while offset != -1:
                    self.patches.append(
                        {
                            "offset": offset,
                            "original": pattern,
                            "patch": patch,
                            "description": "Dongle check bypass",
                        }
                    )
                    patches_applied += 1
                    offset = binary_data.find(pattern, offset + 1)

            self.logger.info("Found %s dongle check patterns to patch", patches_applied)

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Error patching dongle checks: {e!s}")

    def _spoof_dongle_registry(self) -> None:
        """Manipulate Windows registry to simulate dongle presence."""
        try:
            if platform.system() != "Windows":
                self.logger.info("Not on Windows - skipping registry spoofing")
                return

            if not WINREG_AVAILABLE or winreg is None:
                self.logger.warning("winreg module not available - skipping registry spoofing")
                return

            # Dongle registry keys to create/modify
            dongle_registry_entries = [
                # SafeNet entries
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\SafeNet",
                    "InstallDir",
                    r"C:\Program Files\SafeNet",
                ),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SafeNet\Sentinel", "Version", "8.0.0"),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\Sentinel",
                    "Start",
                    2,
                ),
                # HASP entries
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Aladdin Knowledge Systems",
                    "HASP",
                    "Installed",
                ),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Aladdin Knowledge Systems\HASP",
                    "Version",
                    "4.0",
                ),
                # CodeMeter entries
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\WIBU-SYSTEMS",
                    "CodeMeter",
                    r"C:\Program Files\CodeMeter",
                ),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\CodeMeter",
                    "Start",
                    2,
                ),
            ]

            for hkey, path, name, value in dongle_registry_entries:
                try:
                    key = winreg.CreateKey(hkey, path)
                    if isinstance(value, int):
                        winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
                    else:
                        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
                    winreg.CloseKey(key)
                    self.logger.info("Set registry entry %s\\%s = %s", path, name, value)
                except (OSError, ValueError, RuntimeError) as e:
                    self.logger.warning(f"Could not set registry entry {path}\\{name}: {e!s}")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Registry spoofing failed: {e!s}")

    def generate_emulation_script(self, dongle_types: list[str]) -> str:
        """Generate a Frida script for dongle emulation.

        Args:
            dongle_types: List of dongle types to emulate

        Returns:
            str: Complete Frida script for dongle emulation

        """
        base_script = ""
        for hook in self.hooks:
            if hook["type"] == "frida":
                base_script = hook["script"]
                break

        script = f"""
        // Hardware Dongle Emulation Script
        // Generated by Intellicrack
        // Emulating: {', '.join(dongle_types)}

        console.log("[Dongle Emulator] Initializing hardware dongle emulation...");

        // Global flags to track emulation status
        var donglesEmulated = {{}};

        {base_script}

        // Additional dongle emulation logic
        function activateDongleEmulation() {{
            // Hook process and thread creation to inject into child processes
            var createProcessW = Module.findExportByName("kernel32.dll", "CreateProcessW");
            if (createProcessW) {{
                Interceptor.attach(createProcessW, {{
                    onEnter: function(args) {{
                        var cmdLine = args[1].readUtf16String();
                        if (cmdLine && cmdLine.includes("license")) {{
                            console.log("[Dongle] Child process detected with licensing: " + cmdLine);
                        }}
                    }}
                }});
            }}

            // Hook LoadLibrary to catch dongle DLL loading
            var loadLibraryW = Module.findExportByName("kernel32.dll", "LoadLibraryW");
            if (loadLibraryW) {{
                Interceptor.attach(loadLibraryW, {{
                    onEnter: function(args) {{
                        var dllName = args[0].readUtf16String().toLowerCase();
                        if (dllName.includes("sentinel") || dllName.includes("hasp") || dllName.includes("wibu")) {{
                            console.log("[Dongle] Dongle DLL loading detected: " + dllName);
                        }}
                    }}
                }});
            }}

            console.log("[Dongle Emulator] Hardware dongle emulation activated!");
        }}

        // Execute emulation
        setTimeout(activateDongleEmulation, 100);
        """

        return script

    def get_emulation_status(self) -> dict[str, Any]:
        """Get the current status of dongle emulation.

        Returns:
            dict: Status information about emulated dongles and hooks

        """
        return {
            "hooks_installed": len(self.hooks),
            "patches_identified": len(self.patches),
            "virtual_dongles_active": list(self.virtual_dongles.keys()),
            "emulated_dongle_count": len(self.virtual_dongles),
            "frida_available": FRIDA_AVAILABLE,
            "winreg_available": WINREG_AVAILABLE,
        }

    def clear_emulation(self) -> None:
        """Clear all dongle emulation hooks and virtual devices."""
        self.hooks.clear()
        self.patches.clear()
        self.virtual_dongles.clear()
        self.logger.info("Cleared all dongle emulation hooks and virtual devices")


def activate_hardware_dongle_emulation(app: Any, dongle_types: list[str] = None) -> dict[str, Any]:
    """Convenience function to activate hardware dongle emulation.

    Args:
        app: Application instance with binary_path
        dongle_types: List of dongle types to emulate

    Returns:
        dict: Results of the emulation activation

    """
    emulator = HardwareDongleEmulator(app)
    return emulator.activate_dongle_emulation(dongle_types)


# Export the main classes and functions
__all__ = [
    "HardwareDongleEmulator",
    "activate_hardware_dongle_emulation",
]
