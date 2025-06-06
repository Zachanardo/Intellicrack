"""
Virtualization Detection Bypass Module

This module provides comprehensive strategies to bypass virtualization and container detection
in software applications. It implements multiple approaches including API hooking, registry
manipulation, hardware fingerprint spoofing, and timing attack mitigation.

Core Features:
- VM detection API interception
- Registry manipulation to hide VM artifacts
- Hardware fingerprint spoofing (MAC addresses, CPUID)
- Timing attack mitigation
- Binary instruction patching for VM detection

Author: Intellicrack Team
License: MIT
"""

import logging
import platform
from typing import Any, Dict, List, Optional

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

try:
    if platform.system() == "Windows":
        import winreg
        WINREG_AVAILABLE = True
    else:
        WINREG_AVAILABLE = False
        winreg = None
except ImportError:
    WINREG_AVAILABLE = False
    winreg = None


class VirtualizationDetectionBypass:
    """
    Implements various strategies to bypass virtualization and container detection.

    This class provides multiple methods to bypass VM/sandbox detection including:
    - API hooking to intercept VM detection calls
    - Registry manipulation to hide VM artifacts
    - Hardware fingerprint spoofing
    - Timing attack mitigation
    """

    def __init__(self, app: Optional[Any] = None):
        """
        Initialize the virtualization detection bypass engine.

        Args:
            app: Application instance that contains the binary_path attribute
        """
        self.app = app
        self.logger = logging.getLogger("IntellicrackLogger.VMBypass")
        self.hooks: List[Dict[str, Any]] = []
        self.patches: List[Dict[str, Any]] = []

    def bypass_vm_detection(self) -> Dict[str, Any]:
        """
        Main method to bypass virtualization detection using multiple strategies.

        Returns:
            dict: Results of the bypass attempt with success status and applied methods
        """
        from ...utils.protection_helpers import create_bypass_result
        results = create_bypass_result()

        # Strategy 1: Hook VM detection APIs
        try:
            self._hook_vm_detection_apis()
            results["methods_applied"].append("API Hooking")
        except Exception as e:
            results["errors"].append(f"API hooking failed: {str(e)}")

        # Strategy 2: Patch VM detection instructions
        try:
            if self.app and hasattr(self.app, 'binary_path') and self.app.binary_path:
                self._patch_vm_detection()
                results["methods_applied"].append("Binary Patching")
        except Exception as e:
            results["errors"].append(f"Binary patching failed: {str(e)}")

        # Strategy 3: Manipulate registry for VM artifacts
        try:
            self._hide_vm_registry_artifacts()
            results["methods_applied"].append("Registry Manipulation")
        except Exception as e:
            results["errors"].append(f"Registry manipulation failed: {str(e)}")

        # Strategy 4: Hook timing functions to mitigate timing attacks
        try:
            self._hook_timing_functions()
            results["methods_applied"].append("Timing Attack Mitigation")
        except Exception as e:
            results["errors"].append(f"Timing hook failed: {str(e)}")

        results["success"] = len(results["methods_applied"]) > 0
        return results

    def _get_driver_path(self, driver_name: str) -> str:
        """Get Windows driver path dynamically."""
        try:
            from ...utils.path_discovery import get_system_path
            drivers_dir = get_system_path('windows_drivers')
            if drivers_dir:
                return os.path.join(drivers_dir, driver_name)
        except ImportError:
            pass
        
        # Fallback
        return os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'drivers', driver_name)
    
    def _hook_vm_detection_apis(self) -> None:
        """
        Hook Windows APIs commonly used for VM detection.
        """
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
                    for (var i = 0; i < vmKeys.length; i++) {
                        if (valueName && valueName.includes(vmKeys[i])) {
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

        self.hooks.append({
            "type": "frida",
            "script": frida_script,
            "target": "VM Detection APIs"
        })
        self.logger.info("VM detection API hooks installed")

    def _patch_vm_detection(self) -> None:
        """
        Patch binary instructions that detect virtualization.
        """
        if not self.app or not hasattr(self.app, 'binary_path') or not self.app.binary_path:
            return

        try:
            with open(self.app.binary_path, 'rb') as f:
                binary_data = f.read()

            # Common VM detection patterns
            vm_detection_patterns = [
                # CPUID instruction pattern (check hypervisor bit)
                {"pattern": b"\x0F\xA2\xF7\xC1\x00\x00\x00\x80", "patch": b"\x0F\xA2\x90\x90\x90\x90\x90\x90"},
                # RDTSC timing check pattern
                {"pattern": b"\x0F\x31", "patch": b"\x90\x90"},  # NOP out RDTSC
                # IN instruction (port I/O) - VirtualBox detection
                {"pattern": b"\xE5\x10", "patch": b"\x90\x90"},  # IN AL, 0x10
                # STR instruction - VMware detection
                {"pattern": b"\x0F\x00\xC8", "patch": b"\x90\x90\x90"},  # STR EAX
            ]

            patches_applied = 0
            for pattern_info in vm_detection_patterns:
                pattern = pattern_info["pattern"]
                patch = pattern_info["patch"]

                offset = binary_data.find(pattern)
                while offset != -1:
                    self.patches.append({
                        "offset": offset,
                        "original": pattern,
                        "patch": patch
                    })
                    patches_applied += 1
                    offset = binary_data.find(pattern, offset + 1)

            self.logger.info(f"Found {patches_applied} VM detection patterns to patch")

        except Exception as e:
            self.logger.error(f"Error patching VM detection: {str(e)}")

    def _hide_vm_registry_artifacts(self) -> None:
        """
        Hide VM-related registry entries.
        """
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
                    self.logger.info(f"Deleted VM registry key: {path}")
                except FileNotFoundError:
                    pass  # Key doesn't exist, good
                except Exception as e:
                    self.logger.warning(f"Could not delete registry key {path}: {str(e)}")

        except Exception as e:
            self.logger.error(f"Registry manipulation failed: {str(e)}")

    def _hook_timing_functions(self) -> None:
        """
        Hook timing functions to prevent timing-based VM detection.
        """
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
                    // Scan for RDTSC instruction
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

        self.hooks.append({
            "type": "frida",
            "script": timing_script,
            "target": "Timing Functions"
        })

    def generate_bypass_script(self) -> str:
        """
        Generate a complete Frida script for VM detection bypass.

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

    def get_hook_status(self) -> Dict[str, Any]:
        """
        Get the current status of installed hooks.

        Returns:
            dict: Status information about hooks and patches
        """
        return {
            "hooks_installed": len(self.hooks),
            "patches_identified": len(self.patches),
            "frida_available": FRIDA_AVAILABLE,
            "winreg_available": WINREG_AVAILABLE
        }

    def clear_hooks(self) -> None:
        """
        Clear all installed hooks and patches.
        """
        self.hooks.clear()
        self.patches.clear()
        self.logger.info("Cleared all VM bypass hooks and patches")


def bypass_vm_detection(app: Any) -> Dict[str, Any]:
    """
    Convenience function to bypass VM detection on an application.

    Args:
        app: Application instance with binary_path

    Returns:
        dict: Results of the bypass attempt
    """
    bypass = VirtualizationDetectionBypass(app)
    return bypass.bypass_vm_detection()


class VMDetector:
    """
    Detects if running inside a virtual machine or container.
    """
    
    def __init__(self):
        """Initialize VM detector."""
        self.logger = logging.getLogger("IntellicrackLogger.VMDetector")
        self.vm_indicators = []
        
    def detect(self) -> Dict[str, Any]:
        """
        Detect if running in a VM/container environment.
        
        Returns:
            dict: Detection results including VM type and confidence
        """
        results = {
            "is_vm": False,
            "vm_type": None,
            "indicators": [],
            "confidence": 0.0
        }
        
        # Check various VM indicators
        indicators = []
        
        # Check CPU info
        try:
            import subprocess
            if platform.system() == "Windows":
                result = subprocess.run(["wmic", "cpu", "get", "name"], 
                                      capture_output=True, text=True)
                if "virtual" in result.stdout.lower():
                    indicators.append("CPU name contains 'virtual'")
            elif platform.system() == "Linux":
                with open("/proc/cpuinfo", "r") as f:
                    cpuinfo = f.read().lower()
                    if "hypervisor" in cpuinfo:
                        indicators.append("Hypervisor flag in cpuinfo")
        except Exception:
            pass
            
        # Check for VM files/directories
        vm_paths = [
            self._get_driver_path("VBoxGuest.sys"),
            self._get_driver_path("vmhgfs.sys"),
            "/usr/bin/VBoxClient",
            "/usr/bin/vmware-toolbox"
        ]
        
        for path in vm_paths:
            try:
                import os
                if os.path.exists(path):
                    indicators.append(f"VM file found: {path}")
            except Exception:
                pass
                
        # Check MAC address prefixes
        vm_mac_prefixes = [
            "00:05:69",  # VMware
            "00:0C:29",  # VMware
            "00:1C:14",  # VMware
            "08:00:27",  # VirtualBox
            "00:15:5D"   # Hyper-V
        ]
        
        try:
            import subprocess
            if platform.system() == "Windows":
                result = subprocess.run(["getmac"], capture_output=True, text=True)
                for prefix in vm_mac_prefixes:
                    if prefix.lower() in result.stdout.lower():
                        indicators.append(f"VM MAC prefix detected: {prefix}")
        except Exception:
            pass
            
        results["indicators"] = indicators
        results["is_vm"] = len(indicators) > 0
        results["confidence"] = min(len(indicators) * 0.25, 1.0)
        
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


class VirtualizationAnalyzer:
    """
    Analyzes virtualization usage in applications.
    """
    
    def __init__(self, binary_path: Optional[str] = None):
        """Initialize virtualization analyzer."""
        self.binary_path = binary_path
        self.logger = logging.getLogger("IntellicrackLogger.VirtualizationAnalyzer")
        
    def analyze(self) -> Dict[str, Any]:
        """
        Analyze binary for VM detection routines.
        
        Returns:
            dict: Analysis results
        """
        results = {
            "has_vm_detection": False,
            "detection_methods": [],
            "vm_artifacts": [],
            "confidence": 0.0
        }
        
        if not self.binary_path:
            return results
            
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
                
            # Check for VM detection strings
            vm_strings = [
                b"VirtualBox",
                b"VMware",
                b"QEMU",
                b"Hyper-V",
                b"VBOX",
                b"Red Hat VirtIO",
                b"vboxguest",
                b"vboxvideo",
                b"vmhgfs"
            ]
            
            found_strings = []
            for s in vm_strings:
                if s in data:
                    found_strings.append(s.decode('utf-8', errors='ignore'))
                    
            # Check for VM detection instructions
            vm_instructions = [
                b"\x0F\xA2",  # CPUID
                b"\x0F\x31",  # RDTSC
                b"\x0F\x00\xC8",  # STR
                b"\xE5",  # IN (port I/O)
            ]
            
            detection_methods = []
            for instr in vm_instructions:
                if instr in data:
                    if instr == b"\x0F\xA2":
                        detection_methods.append("CPUID hypervisor check")
                    elif instr == b"\x0F\x31":
                        detection_methods.append("RDTSC timing check")
                    elif instr == b"\x0F\x00\xC8":
                        detection_methods.append("STR instruction check")
                    elif instr == b"\xE5":
                        detection_methods.append("Port I/O check")
                        
            results["vm_artifacts"] = found_strings
            results["detection_methods"] = detection_methods
            results["has_vm_detection"] = len(found_strings) > 0 or len(detection_methods) > 0
            results["confidence"] = min((len(found_strings) + len(detection_methods)) * 0.15, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error analyzing VM detection: {str(e)}")
            
        return results


def detect_virtualization() -> bool:
    """
    Quick check if running in a virtualized environment.
    
    Returns:
        bool: True if virtualization detected
    """
    detector = VMDetector()
    result = detector.detect()
    return result["is_vm"]


def analyze_vm_protection(binary_path: str) -> Dict[str, Any]:
    """
    Analyze a binary for VM protection mechanisms.
    
    Args:
        binary_path: Path to the binary to analyze
        
    Returns:
        dict: Analysis results
    """
    analyzer = VirtualizationAnalyzer(binary_path)
    return analyzer.analyze()


# Export the main classes and functions
__all__ = [
    'VirtualizationDetectionBypass',
    'bypass_vm_detection',
    'VMDetector',
    'VirtualizationAnalyzer',
    'detect_virtualization',
    'analyze_vm_protection'
]
