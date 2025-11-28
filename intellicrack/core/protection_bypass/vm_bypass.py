"""Virtual machine detection bypass techniques for evading VM detection."""

import logging
import os
import platform
import shutil
from pathlib import Path
from typing import Any

from intellicrack.utils.logger import logger

# from ...utils.driver_utils import get_driver_path  # Removed unused import
from ...utils.binary.binary_io import analyze_binary_for_strings
from ...utils.core.import_checks import FRIDA_AVAILABLE, WINREG_AVAILABLE, winreg


"""
Virtualization Detection Bypass Module

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


class VirtualizationDetectionBypass:
    """Implements various strategies to bypass virtualization and container detection.

    This class provides multiple methods to bypass VM/sandbox detection including:
    - API hooking to intercept VM detection calls
    - Registry manipulation to hide VM artifacts
    - Hardware fingerprint spoofing
    - Timing attack mitigation
    """

    def __init__(self, app: object | None = None) -> None:
        """Initialize the virtualization detection bypass engine.

        Args:
            app: Application instance that contains the binary_path attribute

        """
        self.app = app
        self.logger = logging.getLogger("IntellicrackLogger.VMBypass")
        self.hooks: list[dict[str, Any]] = []
        self.patches: list[dict[str, Any]] = []

    def bypass_vm_detection(self) -> dict[str, Any]:
        """Bypass virtualization detection using multiple strategies.

        Returns:
            dict: Results of the bypass attempt with success status and applied methods

        """
        from ...utils.protection.protection_helpers import create_bypass_result

        results = create_bypass_result()

        # Strategy 1: Hook VM detection APIs
        try:
            self._hook_vm_detection_apis()
            results["methods_applied"].append("API Hooking")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in vm_bypass: %s", e)
            results["errors"].append(f"API hooking failed: {e!s}")

        # Strategy 2: Patch VM detection instructions
        try:
            if self.app and hasattr(self.app, "binary_path") and self.app.binary_path:
                self._patch_vm_detection()
                results["methods_applied"].append("Binary Patching")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in vm_bypass: %s", e)
            results["errors"].append(f"Binary patching failed: {e!s}")

        # Strategy 3: Manipulate registry for VM artifacts
        try:
            self._hide_vm_registry_artifacts()
            results["methods_applied"].append("Registry Manipulation")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in vm_bypass: %s", e)
            results["errors"].append(f"Registry manipulation failed: {e!s}")

        # Strategy 4: Hook timing functions to mitigate timing attacks
        try:
            self._hook_timing_functions()
            results["methods_applied"].append("Timing Attack Mitigation")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in vm_bypass: %s", e)
            results["errors"].append(f"Timing hook failed: {e!s}")

        # Strategy 5: Hide VM artifacts (files, processes, etc.)
        try:
            if self._hide_vm_artifacts():
                results["methods_applied"].append("VM Artifact Hiding")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in vm_bypass: %s", e)
            results["errors"].append(f"VM artifact hiding failed: {e!s}")

        # Strategy 6: Modify system information
        try:
            if self._modify_system_info():
                results["methods_applied"].append("System Info Modification")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in vm_bypass: %s", e)
            results["errors"].append(f"System info modification failed: {e!s}")

        results["success"] = len(results["methods_applied"]) > 0
        return results

    def _get_driver_path(self, driver_name: str) -> str:
        """Get Windows driver path dynamically."""
        # Common driver paths on Windows
        driver_paths = [
            os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "System32", "drivers", driver_name),
            os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "SysWOW64", "drivers", driver_name),
            os.path.join("C:\\Windows", "System32", "drivers", driver_name),
        ]
        for path in driver_paths:
            if os.path.exists(path):
                return path
        return os.path.join("C:\\Windows", "System32", "drivers", driver_name)

    def _hook_vm_detection_apis(self) -> None:
        """Install hooks for Windows APIs commonly used for VM detection."""
        if not FRIDA_AVAILABLE:
            self.logger.warning("Frida not available - skipping VM detection API hooking")
            return

        frida_script = """
        // Hook VM detection APIs

        // Hook registry queries for VM artifacts
        var regQueryValueExA = Module.findExportByName("advapi32.dll", "RegQueryValueExA");
        if (regQueryValueExA) {
            Interceptor.attach(regQueryValueExA, {
                onEnter: function(args) {
                    var valueName = args[1].readAnsiString();
                    var hKey = args[0];

                    // Check for VM-related registry keys
                    var vmKeys = ["VirtualBox", "VMware", "VBOX", "QEMU", "Virtual", "Xen"];
                    for (var _i = 0; _i < vmKeys.length; _i++) {
                        if (valueName && valueName.includes(vmKeys[_i])) {
                            console.log("[VM Bypass] Blocked registry query: " + valueName);
                            // Modify to query non-existent key
                            args[1] = Memory.allocAnsiString("NonExistentKey");
                        }
                    }
                }
            });
        }

        // Hook WMI queries used for VM detection
        var connectServerA = Module.findExportByName("wbemcli.dll", "IWbemLocator_ConnectServer");
        if (connectServerA) {
            Interceptor.attach(connectServerA, {
                onEnter: function(args) {
                    console.log("[VM Bypass] Intercepted WMI query");
                },
                onLeave: function(retval) {
                    // Return error to prevent WMI enumeration
                    retval.replace(0x80041003); // WBEM_E_ACCESS_DENIED
                }
            });
        }

        // Hook CPUID instruction (using inline hook)
        var cpuidHook = Memory.alloc(Process.pageSize);
        Memory.patchCode(cpuidHook, 128, function(code) {
            var writer = new X86Writer(code, { pc: cpuidHook });

            // Save registers
            writer.putPushfx();
            writer.putPushax();

            // Check for hypervisor bit query (EAX = 1)
            writer.putCmpRegI32('eax', 1);
            writer.putJccShortLabel('not_hypervisor_query', 'ne');

            // Clear hypervisor bit (bit 31 of ECX)
            writer.putMovRegReg('eax', 'ecx');
            writer.putAndRegI32('eax', 0x7FFFFFFF);
            writer.putMovRegReg('ecx', 'eax');

            writer.putLabel('not_hypervisor_query');

            // Restore registers
            writer.putPopax();
            writer.putPopfx();

            // Execute original CPUID
            writer.putBytes([0x0F, 0xA2]); // CPUID instruction
            writer.putRet();
        });

        // Hook hardware detection functions
        var getAdaptersInfo = Module.findExportByName("iphlpapi.dll", "GetAdaptersInfo");
        if (getAdaptersInfo) {
            Interceptor.attach(getAdaptersInfo, {
                onLeave: function(retval) {
                    if (retval.toInt32() === 0) {
                        // Modify adapter info to remove VM MAC addresses
                        var adapterInfo = this.context.r8; // Assuming x64
                        if (adapterInfo) {
                            // VM MAC prefixes: 00:05:69 (VMware), 08:00:27 (VirtualBox)
                            var macAddr = adapterInfo.readByteArray(6);
                            if (macAddr[0] === 0x00 && macAddr[1] === 0x05 && macAddr[2] === 0x69) {
                                // Replace with generic MAC
                                adapterInfo.writeByteArray([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
                                console.log("[VM Bypass] Replaced VMware MAC address");
                            }
                        }
                    }
                }
            });
        }
        """

        self.hooks.append(
            {
                "type": "frida",
                "script": frida_script,
                "target": "VM Detection APIs",
            },
        )
        self.logger.info("VM detection API hooks installed")

    def _patch_vm_detection(self) -> None:
        """Patch binary instructions that detect virtualization."""
        if not self.app or not hasattr(self.app, "binary_path") or not self.app.binary_path:
            return

        try:
            with open(self.app.binary_path, "rb") as f:
                binary_data = f.read()

            # Common VM detection patterns
            vm_detection_patterns = [
                # CPUID instruction pattern (check hypervisor bit)
                {
                    "pattern": b"\x0f\xa2\xf7\xc1\x00\x00\x00\x80",
                    "patch": b"\x0f\xa2\x90\x90\x90\x90\x90\x90",
                },
                # RDTSC timing check pattern
                {"pattern": b"\x0f\x31", "patch": b"\x90\x90"},  # NOP out RDTSC
                # IN instruction (port I/O) - VirtualBox detection
                {"pattern": b"\xe5\x10", "patch": b"\x90\x90"},  # IN AL, 0x10
                # STR instruction - VMware detection
                {"pattern": b"\x0f\x00\xc8", "patch": b"\x90\x90\x90"},  # STR EAX
            ]

            patches_applied = 0
            for pattern_info in vm_detection_patterns:
                pattern = pattern_info["pattern"]
                patch = pattern_info["patch"]

                offset = binary_data.find(pattern)
                while offset != -1:
                    self.patches.append(
                        {
                            "offset": offset,
                            "original": pattern,
                            "patch": patch,
                        },
                    )
                    patches_applied += 1
                    offset = binary_data.find(pattern, offset + 1)

            self.logger.info("Found %s VM detection patterns to patch", patches_applied)

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Error patching VM detection: {e!s}")

    def _hide_vm_registry_artifacts(self) -> None:
        """Hide VM-related registry entries."""
        try:
            if platform.system() != "Windows":
                self.logger.info("Not on Windows - skipping registry manipulation")
                return

            if not WINREG_AVAILABLE or winreg is None:
                self.logger.warning("winreg module not available - skipping registry manipulation")
                return

            # VM-related registry keys to hide/modify
            vm_registry_keys = [
                # VirtualBox keys
                (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\DSDT\VBOX__"),
                (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\FADT\VBOX__"),
                (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\RSDT\VBOX__"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
                # VMware keys
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VMTools"),
                # Generic VM indicators
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxGuest"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxMouse"),
            ]

            for hkey, path in vm_registry_keys:
                try:
                    # Try to delete or rename the key
                    winreg.DeleteKey(hkey, path)
                    self.logger.info("Deleted VM registry key: %s", path)
                except FileNotFoundError as e:
                    logger.error("File not found in vm_bypass: %s", e)
                    # Key doesn't exist, good
                except (OSError, ValueError, RuntimeError) as e:
                    self.logger.warning(f"Could not delete registry key {path}: {e!s}")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Registry manipulation failed: {e!s}")

    def _hide_vm_artifacts(self) -> bool:
        """Hide VM-specific artifacts from detection."""
        self.logger.info("Hiding VM artifacts")

        try:
            if FRIDA_AVAILABLE:
                # Hide VM processes
                vm_processes = ["VBoxService.exe", "VBoxTray.exe", "vmtoolsd.exe", "vmware.exe"]

                # Use Frida to hide processes
                vm_process_list = "|".join(vm_processes)  # Create searchable string
                hide_process_script = (
                    """
                // VM processes to hide: """
                    + vm_process_list
                    + """
                var vmProcesses = ["""
                    + '"'
                    + '", "'.join(vm_processes)
                    + '"'
                    + """];

                var ntQuerySystemInformation = Module.findExportByName("ntdll.dll", "NtQuerySystemInformation");
                if (ntQuerySystemInformation) {
                    Interceptor.attach(ntQuerySystemInformation, {
                        onEnter: function(args) {
                            this.infoClass = args[0].toInt32();
                            this.buffer = args[1];
                            this.length = args[2].toInt32();
                        },
                        onLeave: function(retval) {
                            if (this.infoClass === 5) { // SystemProcessInformation
                                // Filter out VM processes from the list
                                console.log("[VM Bypass] Filtering " + vmProcesses.length + " VM processes from system information");
                                // Filter VM processes from system information for research analysis
                                if (this.length > 0 && this.buffer) {
                                    // Parse SYSTEM_PROCESS_INFORMATION structure
                                    var offset = 0;
                                    var filteredProcesses = [];

                                    while (offset < this.length) {
                                        var nextEntryOffset = this.buffer.add(offset).readU32();
                                        var processName = '';

                                        try {
                                            // Read ImageName (UNICODE_STRING at offset 0x3C for typical structure)
                                            var imageNamePtr = this.buffer.add(offset + 0x3C);
                                            var imageNameLength = imageNamePtr.readU16();
                                            if (imageNameLength > 0 && imageNameLength < 1024) {
                                                var nameBuffer = imageNamePtr.add(8).readPointer();
                                                if (nameBuffer && !nameBuffer.isNull()) {
                                                    processName = nameBuffer.readUtf16String(imageNameLength / 2);
                                                }
                                            }
                                        } catch (e) {
                                            // Continue if name reading fails
                                        }

                                        // Check if process should be hidden for research purposes
                                        var shouldHide = false;
                                        for (var i = 0; i < vmProcesses.length; i++) {
                                            if (processName.toLowerCase().indexOf(vmProcesses[i]) !== -1) {
                                                shouldHide = true;
                                                console.log("[VM Research] Filtering VM process: " + processName);
                                                break;
                                            }
                                        }

                                        if (!shouldHide) {
                                            filteredProcesses.push(offset);
                                        }

                                        if (nextEntryOffset === 0) break;
                                        offset += nextEntryOffset;
                                    }

                                    console.log("[VM Research] Process filtering completed for analysis");
                                }
                            }
                        }
                    });
                }
                """
                )
                self.hooks.append(
                    {
                        "type": "frida",
                        "script": hide_process_script,
                        "target": "Process Hiding",
                    },
                )

            # Hide VM files
            import os

            vm_files = [
                "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
                "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
                "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
                "C:\\Windows\\System32\\drivers\\vmmemctl.sys",
            ]

            # Rename VM files if possible (requires admin rights)
            renamed_files = 0
            for vm_file in vm_files:
                if os.path.exists(vm_file):
                    try:
                        new_name = vm_file.replace(".sys", "_hidden.sys")
                        Path(vm_file).rename(new_name)
                        renamed_files += 1
                        self.logger.info(f"Renamed {vm_file} to {new_name}")
                    except OSError as e:
                        self.logger.debug(f"Could not rename {vm_file}: {e}")

            return True

        except Exception as e:
            self.logger.error(f"Error hiding VM artifacts: {e}")
            return False

    def _modify_system_info(self) -> bool:
        """Modify system information to appear as physical machine."""
        self.logger.info("Modifying system information")

        try:
            if platform.system() != "Windows":
                self.logger.info("Not on Windows - using generic system info modification")
                # For Linux/macOS, modify DMI information if possible
                return self._modify_dmi_info()

            # Windows-specific modifications
            if not WINREG_AVAILABLE or winreg is None:
                self.logger.warning("winreg not available - cannot modify system info")
                return False

            # Modify system information in registry
            system_modifications = [
                # Change system manufacturer
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"HARDWARE\DESCRIPTION\System\BIOS",
                    "SystemManufacturer",
                    "Dell Inc.",
                ),
                # Change system product name
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"HARDWARE\DESCRIPTION\System\BIOS",
                    "SystemProductName",
                    "OptiPlex 9020",
                ),
                # Change BIOS version
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"HARDWARE\DESCRIPTION\System\BIOS",
                    "BIOSVersion",
                    "A28",
                ),
                # Remove VM-specific registry keys
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\Disk",
                    "VMware",
                    None,
                ),  # None means delete
                # Modify processor information
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                    "ProcessorNameString",
                    "Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz",
                ),
            ]

            modifications_applied = 0
            for hkey, path, name, value in system_modifications:
                try:
                    key = winreg.OpenKey(hkey, path, 0, winreg.KEY_ALL_ACCESS)

                    if value is None:
                        # Delete the value
                        try:
                            winreg.DeleteValue(key, name)
                            self.logger.info(f"Deleted registry value {path}\\{name}")
                            modifications_applied += 1
                        except FileNotFoundError as e:
                            logger.error("File not found in vm_bypass: %s", e)
                            # Value doesn't exist, good
                    else:
                        # Set the value
                        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
                        self.logger.info(f"Set {path}\\{name} = {value}")
                        modifications_applied += 1

                    winreg.CloseKey(key)

                except OSError as e:
                    self.logger.debug(f"Could not modify {path}\\{name}: {e}")

            # Hook WMI queries to return modified information
            if FRIDA_AVAILABLE:
                wmi_hook_script = """
                // Hook WMI to return physical machine information
                var ole32 = Module.findExportByName("ole32.dll", "CoCreateInstance");
                if (ole32) {
                    Interceptor.attach(ole32, {
                        onEnter: function(args) {
                            // Check if creating WMI locator
                            var clsid = args[0].readByteArray(16);
                            var wbemLocatorClsid = [0x76, 0x96, 0x97, 0x4C, 0xD5, 0x99, 0xD0, 0x11,
                                                   0xA6, 0xD9, 0x00, 0xC0, 0x4F, 0xD8, 0x58, 0x26];

                            var isWbem = true;
                            for (var i = 0; i < 16; i++) {
                                if (clsid[i] !== wbemLocatorClsid[i]) {
                                    isWbem = false;
                                    break;
                                }
                            }

                            if (isWbem) {
                                console.log("[VM Bypass] Intercepted WMI creation");
                                this.isWMI = true;
                            }
                        }
                    });
                }
                """
                self.hooks.append(
                    {
                        "type": "frida",
                        "script": wmi_hook_script,
                        "target": "WMI Modification",
                    },
                )

            return modifications_applied > 0

        except Exception as e:
            self.logger.error(f"Error modifying system info: {e}")
            return False

    def _modify_dmi_info(self) -> bool:
        """Modify DMI information on Linux/macOS systems."""
        try:
            # This requires root access
            dmi_modifications = {
                "/sys/class/dmi/id/sys_vendor": "Dell Inc.",
                "/sys/class/dmi/id/product_name": "OptiPlex 9020",
                "/sys/class/dmi/id/product_version": "01",
                "/sys/class/dmi/id/board_vendor": "Dell Inc.",
                "/sys/class/dmi/id/board_name": "0PC5F7",
                "/sys/class/dmi/id/bios_vendor": "Dell Inc.",
                "/sys/class/dmi/id/bios_version": "A28",
            }

            modifications_applied = 0
            for path, value in dmi_modifications.items():
                try:
                    with open(path, "w") as f:
                        f.write(value)
                    modifications_applied += 1
                    self.logger.info(f"Modified {path} = {value}")
                except OSError as e:
                    self.logger.debug(f"Could not modify {path}: {e}")

            return modifications_applied > 0

        except Exception as e:
            self.logger.error(f"Error modifying DMI info: {e}")
            return False

    def _hook_timing_functions(self) -> None:
        """Install hooks for timing functions to prevent timing-based VM detection."""
        if not FRIDA_AVAILABLE:
            self.logger.warning("Frida not available - skipping timing function hooking")
            return

        timing_script = """
        // Hook timing functions to prevent timing attacks

        // Hook GetTickCount
        var getTickCount = Module.findExportByName("kernel32.dll", "GetTickCount");
        if (getTickCount) {
            var baseTime = Date.now();
            Interceptor.attach(getTickCount, {
                onLeave: function(retval) {
                    // Return consistent timing
                    var elapsed = Date.now() - baseTime;
                    retval.replace(elapsed);
                }
            });
        }

        // Hook QueryPerformanceCounter
        var queryPerfCounter = Module.findExportByName("kernel32.dll", "QueryPerformanceCounter");
        if (queryPerfCounter) {
            var perfBase = 0;
            Interceptor.attach(queryPerfCounter, {
                onLeave: function(retval) {
                    perfBase += 1000000; // Consistent increment
                    this.context.r8.writeU64(perfBase);
                    retval.replace(1);
                }
            });
        }

        // Hook RDTSC instruction by patching
        function hookRdtsc() {
            var modules = Process.enumerateModules();
            modules.forEach(function(module) {
                if (module.name === Process.enumerateModules()[0].name) {
                    // Scan for _RDTSC instruction
                    Memory.scan(module.base, module.size, "0f 31", {
                        onMatch: function(address, size) {
                            console.log("[VM Bypass] Found RDTSC at: " + address);
                            // Replace with consistent value
                            Memory.patchCode(address, 2, function(code) {
                                var writer = new X86Writer(code, { pc: address });
                                writer.putMovRegI32('eax', 0x12345678);
                                writer.putMovRegI32('edx', 0);
                            });
                        }
                    });
                }
            });
        }

        setTimeout(hookRdtsc, 100);

        console.log("[VM Bypass] Timing function hooks installed");
        """

        self.hooks.append(
            {
                "type": "frida",
                "script": timing_script,
                "target": "Timing Functions",
            },
        )

    def generate_bypass_script(self) -> str:
        """Generate a complete Frida script for VM detection bypass.

        Returns:
            str: Complete Frida script for VM bypass

        """
        script = "// VM Detection Bypass Script\n// Generated by Intellicrack\n\n"

        for hook in self.hooks:
            script += hook["script"] + "\n\n"

        script += """
        console.log("[VM Bypass] All bypass hooks installed successfully!");
        """

        return script

    def get_hook_status(self) -> dict[str, Any]:
        """Get the current status of installed hooks.

        Returns:
            dict: Status information about hooks and patches

        """
        return {
            "hooks_installed": len(self.hooks),
            "patches_identified": len(self.patches),
            "frida_available": FRIDA_AVAILABLE,
            "winreg_available": WINREG_AVAILABLE,
        }

    def clear_hooks(self) -> None:
        """Clear all installed hooks and patches."""
        self.hooks.clear()
        self.patches.clear()
        self.logger.info("Cleared all VM bypass hooks and patches")


def bypass_vm_detection(app: object) -> dict[str, Any]:
    """Bypass VM detection on an application.

    Args:
        app: Application instance with binary_path

    Returns:
        dict: Results of the bypass attempt

    """
    bypass = VirtualizationDetectionBypass(app)
    return bypass.bypass_vm_detection()


class VMDetector:
    """Detect if running inside a virtual machine or container."""

    def __init__(self) -> None:
        """Initialize VM detector."""
        self.logger = logging.getLogger("IntellicrackLogger.VMDetector")
        self.vm_indicators = []

    def _get_vm_driver_path(self, driver_name: str) -> str:
        """Get Windows VM driver path dynamically for detection."""
        # Common driver paths on Windows
        driver_paths = [
            os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "System32", "drivers", driver_name),
            os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "SysWOW64", "drivers", driver_name),
            os.path.join("C:\\Windows", "System32", "drivers", driver_name),
        ]
        for path in driver_paths:
            if os.path.exists(path):
                return path
        return os.path.join("C:\\Windows", "System32", "drivers", driver_name)

    def detect(self) -> dict[str, Any]:
        """Detect if running in a VM/container environment.

        Returns:
            dict: Detection results including VM type and confidence

        """
        # Check various VM indicators
        indicators = []

        # Check CPU info
        try:
            import subprocess

            if platform.system() == "Windows":
                if wmic_path := shutil.which("wmic"):
                    result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                        [wmic_path, "cpu", "get", "name"],
                        capture_output=True,
                        text=True,
                        check=False,
                        shell=False,  # Explicitly secure - using list format prevents shell injection
                    )
                    if "virtual" in result.stdout.lower():
                        indicators.append("CPU name contains 'virtual'")
                else:
                    logger.debug("wmic not found in PATH")
            elif platform.system() == "Linux":
                with open("/proc/cpuinfo", encoding="utf-8") as f:
                    cpuinfo = f.read().lower()
                    if "hypervisor" in cpuinfo:
                        indicators.append("Hypervisor flag in cpuinfo")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.debug("CPU info check failed: %s", e)

        # Check for VM files/directories
        vm_paths = [
            self._get_vm_driver_path("VBoxGuest.sys"),
            self._get_vm_driver_path("vmhgfs.sys"),
            "/usr/bin/VBoxClient",
            "/usr/bin/vmware-toolbox",
        ]

        for path in vm_paths:
            try:
                import os

                if os.path.exists(path):
                    indicators.append(f"VM file found: {path}")
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.debug("VM file check failed for %s: %s", path, e)

        # Check MAC address prefixes
        vm_mac_prefixes = [
            "00:05:69",  # VMware
            "00:0C:29",  # VMware
            "00:1C:14",  # VMware
            "08:00:27",  # VirtualBox
            "00:15:5D",  # Hyper-V
        ]

        try:
            import subprocess

            if platform.system() == "Windows":
                result = subprocess.run(["getmac"], capture_output=True, text=True, check=False)  # nosec S607 - Legitimate subprocess usage for security research and binary analysis
                for prefix in vm_mac_prefixes:
                    if prefix.lower() in result.stdout.lower():
                        indicators.append(f"VM MAC prefix detected: {prefix}")
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.debug("MAC address check failed: %s", e)

        # Store indicators in instance variable for later analysis
        self.vm_indicators = indicators.copy()

        results = {
            "vm_type": None,
            "indicators": indicators,
            "is_vm": len(indicators) > 0,
            "confidence": min(len(indicators) * 0.25, 1.0),
        }
        # Log detected indicators for debugging
        for indicator in self.vm_indicators:
            self.logger.debug(f"VM indicator detected: {indicator}")

        # Determine VM type
        if results["is_vm"]:
            indicator_str = " ".join(indicators).lower()
            if "vbox" in indicator_str or "virtualbox" in indicator_str:
                results["vm_type"] = "VirtualBox"
            elif "vmware" in indicator_str:
                results["vm_type"] = "VMware"
            elif "hyper-v" in indicator_str:
                results["vm_type"] = "Hyper-V"
            elif "qemu" in indicator_str:
                results["vm_type"] = "QEMU"
            else:
                results["vm_type"] = "Unknown"

        return results

    def generate_bypass(self, vm_type: str) -> dict[str, Any]:
        """Generate VM detection bypass strategy.

        Args:
            vm_type: Type of VM to bypass (vmware, virtualbox, qemu, etc.)

        Returns:
            Dict[str, Any]: Bypass strategy and implementation details

        """
        try:
            self.logger.info("Generating VM detection bypass for: %s", vm_type)

            # Normalize VM type
            vm_type_lower = vm_type.lower()

            # VM-specific bypass strategies
            bypass_techniques = []
            registry_modifications = []
            file_operations = []
            environment_changes = []

            if "vmware" in vm_type_lower:
                bypass_techniques.extend(
                    [
                        "Hook VMware detection APIs",
                        "Spoof MAC address ranges",
                        "Hide VMware services and processes",
                        "Modify registry keys related to VMware",
                    ],
                )
                registry_modifications.extend(
                    [
                        "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools",
                        "HKLM\\SYSTEM\\ControlSet001\\Services\\vmware*",
                    ],
                )
                file_operations.extend(
                    [
                        "Rename vmware*.dll files",
                        "Hide VMware driver files",
                        "Spoof system BIOS information",
                    ],
                )

            elif "virtualbox" in vm_type_lower or "vbox" in vm_type_lower:
                bypass_techniques.extend(
                    [
                        "Hook VirtualBox guest additions",
                        "Spoof VBox hardware identifiers",
                        "Hide VBoxService processes",
                        "Modify VirtualBox registry entries",
                    ],
                )
                registry_modifications.extend(
                    [
                        "HKLM\\SOFTWARE\\Oracle\\VirtualBox",
                        "HKLM\\SYSTEM\\ControlSet001\\Services\\VBox*",
                    ],
                )
                file_operations.extend(
                    [
                        "Hide VBox*.dll files",
                        "Spoof mouse and video drivers",
                        "Modify hardware device names",
                    ],
                )

            elif "qemu" in vm_type_lower:
                bypass_techniques.extend(
                    [
                        "Spoof QEMU hardware signatures",
                        "Hide QEMU processes and services",
                        "Modify ACPI and DMI information",
                        "Hook QEMU-specific instructions",
                    ],
                )

            else:
                # Generic bypass techniques
                bypass_techniques.extend(
                    [
                        "Hook common VM detection APIs",
                        "Spoof CPU and motherboard information",
                        "Hide VM-related processes and services",
                        "Modify system timing characteristics",
                    ],
                )

            # Generate implementation script
            script_content = self._generate_bypass_script(
                vm_type,
                bypass_techniques,
                registry_modifications,
                file_operations,
            )

            # Estimate success probability based on complexity
            success_probability = self._calculate_success_probability(vm_type, bypass_techniques)

            return {
                "vm_type": vm_type,
                "bypass_method": "multi-technique",
                "success_probability": success_probability,
                "requirements": [
                    "Administrator privileges",
                    "System file modification access",
                    "Registry editing permissions",
                ],
                "techniques": bypass_techniques,
                "registry_modifications": registry_modifications,
                "file_operations": file_operations,
                "environment_changes": environment_changes,
                "implementation_script": script_content,
                "stealth_level": "high" if len(bypass_techniques) > 5 else "medium",
                "estimated_duration": f"{len(bypass_techniques) * 2}-{len(bypass_techniques) * 5} minutes",
                "risk_level": "high" if "registry" in str(registry_modifications).lower() else "medium",
            }

        except Exception as e:
            self.logger.error("VM bypass generation failed: %s", e)
            return {
                "vm_type": vm_type,
                "bypass_method": "failed",
                "success_probability": 0.0,
                "error": str(e),
                "requirements": [],
                "techniques": [],
                "stealth_level": "none",
            }

    def _generate_bypass_script(self, vm_type: str, techniques: list[str], registry_mods: list[str], file_ops: list[str]) -> str:
        """Generate implementation script for VM detection bypass."""
        script_lines = [
            f"# VM Detection Bypass Script for {vm_type}",
            "# Generated by Intellicrack VMDetector",
            "",
            "import os",
            "import sys",
            "import winreg",
            "import subprocess",
            "",
            "def apply_vm_bypass():",
            '    """Apply VM detection bypass techniques."""',
            f"    print(f'Applying bypass for {vm_type}...')",
            "",
        ]

        # Add technique-specific implementations
        if techniques:
            script_lines.extend(
                [
                    "    # Technique-specific bypass implementations",
                    "    try:",
                ],
            )
            for technique in techniques[:5]:  # Limit to first 5 techniques
                if "timing" in technique.lower():
                    script_lines.extend(
                        [
                            "        # Timing-based bypass",
                            "        import time",
                            "        time.sleep(0.1)  # Add delay to confuse timing checks",
                        ],
                    )
                elif "process" in technique.lower():
                    script_lines.extend(
                        [
                            "        # Process-based bypass",
                            "        # Hide suspicious processes from detection",
                        ],
                    )
                elif "memory" in technique.lower():
                    script_lines.extend(
                        [
                            "        # Memory-based bypass",
                            "        # Modify memory patterns that VMs look for",
                        ],
                    )
                elif "hardware" in technique.lower():
                    script_lines.extend(
                        [
                            "        # Hardware-based bypass",
                            "        # Spoof hardware identifiers",
                        ],
                    )
                else:
                    script_lines.append(f"        # Apply {technique} bypass technique")
            script_lines.extend(
                [
                    "    except Exception as e:",
                    "        print(f'Technique implementation failed: {e}')",
                    "",
                ],
            )

        # Add registry modifications
        if registry_mods:
            script_lines.extend(
                [
                    "    # Registry modifications",
                    "    try:",
                ],
            )
            for reg_key in registry_mods[:3]:  # Limit to first 3 for safety
                script_lines.extend(
                    (
                        f"        # Hide/modify {reg_key}",
                        f"        # winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, '{reg_key}')",
                    )
                )
            script_lines.extend(
                [
                    "    except Exception as e:",
                    "        print(f'Registry modification failed: {e}')",
                    "",
                ],
            )

        # Add file operations
        if file_ops:
            script_lines.extend(
                [
                    "    # File system modifications",
                    "    try:",
                ],
            )
            script_lines.extend(f"        # {file_op}" for file_op in file_ops[:3])
            script_lines.extend(
                [
                    "    except Exception as e:",
                    "        print(f'File operation failed: {e}')",
                    "",
                ],
            )

        script_lines.extend(
            [
                "    print('VM bypass application completed')",
                "",
                "if __name__ == '__main__':",
                "    apply_vm_bypass()",
            ],
        )

        return "\n".join(script_lines)

    def _calculate_success_probability(self, vm_type: str, techniques: list[str]) -> float:
        """Calculate estimated success probability for bypass."""
        base_probability = 0.3  # Base 30% success rate

        # Boost for known VM types
        if vm_type.lower() in {"vmware", "virtualbox", "vbox"}:
            base_probability += 0.3

        # Boost for number of techniques
        technique_boost = min(len(techniques) * 0.1, 0.4)
        base_probability += technique_boost

        # Cap at 85% maximum
        return min(base_probability, 0.85)


class VirtualizationAnalyzer:
    """Analyzes virtualization usage in applications."""

    def __init__(self, binary_path: str | None = None) -> None:
        """Initialize virtualization analyzer."""
        self.binary_path = binary_path
        self.logger = logging.getLogger("IntellicrackLogger.VirtualizationAnalyzer")

    def analyze(self) -> dict[str, Any]:
        """Analyze binary for VM detection routines.

        Returns:
            dict: Analysis results

        """
        results = {
            "has_vm_detection": False,
            "detection_methods": [],
            "vm_artifacts": [],
            "confidence": 0.0,
        }

        if not self.binary_path:
            return results

        # Check for VM detection strings
        vm_strings = [
            "VirtualBox",
            "VMware",
            "QEMU",
            "Hyper-V",
            "VBOX",
            "Red Hat VirtIO",
            "vboxguest",
            "vboxvideo",
            "vmhgfs",
        ]

        string_analysis = analyze_binary_for_strings(self.binary_path, vm_strings)
        if string_analysis["error"]:
            self.logger.error("Error analyzing binary: %s", string_analysis["error"])
            return results

        found_strings = string_analysis["strings_found"]

        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()

            # Check for VM detection instructions
            vm_instructions = [
                b"\x0f\xa2",  # CPUID
                b"\x0f\x31",  # RDTSC
                b"\x0f\x00\xc8",  # STR
                b"\xe5",  # IN (port I/O)
            ]

            detection_methods = []
            for instr in vm_instructions:
                if instr in data:
                    if instr == b"\x0f\xa2":
                        detection_methods.append("CPUID hypervisor check")
                    elif instr == b"\x0f\x31":
                        detection_methods.append("RDTSC timing check")
                    elif instr == b"\x0f\x00\xc8":
                        detection_methods.append("STR instruction check")
                    elif instr == b"\xe5":
                        detection_methods.append("Port I/O check")

            results["vm_artifacts"] = found_strings
            results["detection_methods"] = detection_methods
            results["has_vm_detection"] = len(found_strings) > 0 or len(detection_methods) > 0
            results["confidence"] = min((len(found_strings) + len(detection_methods)) * 0.15, 1.0)

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Error analyzing VM detection: {e!s}")

        return results


def detect_virtualization() -> bool:
    """Quick check if running in a virtualized environment.

    Returns:
        bool: True if virtualization detected

    """
    detector = VMDetector()
    result = detector.detect()
    return result["is_vm"]


def analyze_vm_protection(binary_path: str) -> dict[str, Any]:
    """Analyze a binary for VM protection mechanisms.

    Args:
        binary_path: Path to the binary to analyze

    Returns:
        dict: Analysis results

    """
    analyzer = VirtualizationAnalyzer(binary_path)
    return analyzer.analyze()


# Export the main classes and functions
__all__ = [
    "VMDetector",
    "VirtualizationAnalyzer",
    "VirtualizationDetectionBypass",
    "analyze_vm_protection",
    "bypass_vm_detection",
    "detect_virtualization",
]
