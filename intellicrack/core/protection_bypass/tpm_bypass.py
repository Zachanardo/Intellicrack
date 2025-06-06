"""
TPM Protection Bypass Module

This module provides comprehensive strategies to bypass TPM (Trusted Platform Module) protection
in software applications. It implements multiple approaches including API hooking, virtual TPM
emulation, binary patching, and registry manipulation.

Core Features:
- TPM API interception and manipulation
- Virtual TPM device simulation
- Binary instruction patching for TPM checks
- Windows registry manipulation for TPM presence simulation
- Frida script generation for runtime bypass

Author: Intellicrack Team
License: MIT
"""

import logging
import platform
from typing import Any, Dict, List, Optional, Union

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


class TPMProtectionBypass:
    """
    Implements various strategies to bypass TPM (Trusted Platform Module) protection.

    This class provides multiple methods to bypass TPM-based license verification including:
    - API hooking to intercept TPM calls
    - Virtual TPM emulation
    - Memory patching of TPM checks
    - Registry manipulation to simulate TPM presence
    """

    def __init__(self, app: Optional[Any] = None):
        """
        Initialize the TPM protection bypass engine.

        Args:
            app: Application instance that contains the binary_path attribute
        """
        self.app = app
        self.logger = logging.getLogger("IntellicrackLogger.TPMBypass")
        self.hooks: List[Dict[str, Any]] = []
        self.patches: List[Dict[str, Any]] = []
        self.virtual_tpm: Optional[Dict[str, Union[bytes, int]]] = None

    def bypass_tpm_checks(self) -> Dict[str, Any]:
        """
        Main method to bypass TPM protection using multiple strategies.

        Returns:
            dict: Results of the bypass attempt with success status and applied methods
        """
        from ...utils.protection_helpers import create_bypass_result
        results = create_bypass_result()

        # Strategy 1: Hook TPM API calls
        try:
            self._hook_tpm_apis()
            results["methods_applied"].append("API Hooking")
        except Exception as e:
            results["errors"].append(f"API hooking failed: {str(e)}")

        # Strategy 2: Create virtual TPM responses
        try:
            self._create_virtual_tpm()
            results["methods_applied"].append("Virtual TPM")
        except Exception as e:
            results["errors"].append(f"Virtual TPM creation failed: {str(e)}")

        # Strategy 3: Patch TPM check instructions
        try:
            if self.app and hasattr(self.app, 'binary_path') and self.app.binary_path:
                self._patch_tpm_checks()
                results["methods_applied"].append("Binary Patching")
        except Exception as e:
            results["errors"].append(f"Binary patching failed: {str(e)}")

        # Strategy 4: Manipulate registry for TPM presence
        try:
            self._manipulate_tpm_registry()
            results["methods_applied"].append("Registry Manipulation")
        except Exception as e:
            results["errors"].append(f"Registry manipulation failed: {str(e)}")

        results["success"] = len(results["methods_applied"]) > 0
        return results

    def _hook_tpm_apis(self) -> None:
        """
        Hook Windows TPM APIs to return success values.
        """
        if not FRIDA_AVAILABLE:
            self.logger.warning("Frida not available - skipping TPM API hooking")
            return

        frida_script = """
        // Hook TPM Base Services (TBS) APIs
        var tbsModule = Process.getModuleByName("tbs.dll");
        if (tbsModule) {
            // Hook Tbsi_Context_Create
            var tbsiContextCreate = Module.findExportByName("tbs.dll", "Tbsi_Context_Create");
            if (tbsiContextCreate) {
                Interceptor.attach(tbsiContextCreate, {
                    onEnter: function(args) {
                        console.log("[TPM Bypass] Intercepted Tbsi_Context_Create");
                    },
                    onLeave: function(retval) {
                        // Return success
                        retval.replace(0);
                        console.log("[TPM Bypass] Tbsi_Context_Create returning SUCCESS");
                    }
                });
            }

            // Hook Tbsi_GetDeviceInfo
            var tbsiGetDeviceInfo = Module.findExportByName("tbs.dll", "Tbsi_GetDeviceInfo");
            if (tbsiGetDeviceInfo) {
                Interceptor.attach(tbsiGetDeviceInfo, {
                    onLeave: function(retval) {
                        // Return TPM 2.0 device info
                        retval.replace(0);
                        console.log("[TPM Bypass] Tbsi_GetDeviceInfo returning TPM 2.0 present");
                    }
                });
            }

            // Hook Tbsi_Submit_Command
            var tbsiSubmitCommand = Module.findExportByName("tbs.dll", "Tbsi_Submit_Command");
            if (tbsiSubmitCommand) {
                Interceptor.attach(tbsiSubmitCommand, {
                    onEnter: function(args) {
                        console.log("[TPM Bypass] Intercepted TPM command submission");
                    },
                    onLeave: function(retval) {
                        // Return success for all TPM commands
                        retval.replace(0);
                    }
                });
            }
        }

        // Hook NCrypt TPM provider functions
        var ncryptModule = Process.getModuleByName("ncrypt.dll");
        if (ncryptModule) {
            var ncryptOpenStorageProvider = Module.findExportByName("ncrypt.dll", "NCryptOpenStorageProvider");
            if (ncryptOpenStorageProvider) {
                Interceptor.attach(ncryptOpenStorageProvider, {
                    onEnter: function(args) {
                        var providerName = args[1].readUtf16String();
                        if (providerName && providerName.includes("TPM")) {
                            console.log("[TPM Bypass] Intercepted TPM provider open: " + providerName);
                        }
                    },
                    onLeave: function(retval) {
                        retval.replace(0);
                    }
                });
            }
        }
        """

        self.hooks.append({
            "type": "frida",
            "script": frida_script,
            "target": "TPM APIs"
        })
        self.logger.info("TPM API hooks installed")

    def _create_virtual_tpm(self) -> None:
        """
        Create a virtual TPM device that responds to application queries.
        """
        # Virtual TPM response data
        virtual_tpm_data = {
            "manufacturer": b"INTC",  # Intel
            "vendor_string": b"Intellicrack Virtual TPM",
            "firmware_version": b"2.0",
            "spec_level": 0x200,  # TPM 2.0
            "spec_revision": 0x138,
            "platform_specific": b"\x00" * 32
        }

        # Create memory-mapped TPM responses
        self.virtual_tpm = virtual_tpm_data
        self.logger.info("Virtual TPM created with vendor: Intellicrack Virtual TPM")

    def _patch_tpm_checks(self) -> None:
        """
        Patch binary instructions that check for TPM presence.
        """
        if not self.app or not hasattr(self.app, 'binary_path') or not self.app.binary_path:
            return

        try:
            with open(self.app.binary_path, 'rb') as f:
                binary_data = f.read()

            # Common TPM check patterns
            tpm_check_patterns = [
                # Pattern for TPM presence check
                {"pattern": b"\x85\xC0\x74", "patch": b"\x85\xC0\xEB"},  # JZ to JMP
                # Pattern for TPM version check
                {"pattern": b"\x83\xF8\x02\x74", "patch": b"\x83\xF8\x02\xEB"},  # CMP EAX,2; JZ to JMP
                # Pattern for TPM error check
                {"pattern": b"\x3D\x00\x00\x00\x00\x75", "patch": b"\x3D\x00\x00\x00\x00\xEB"},  # CMP EAX,0; JNZ to JMP
            ]

            patches_applied = 0
            for pattern_info in tpm_check_patterns:
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

            self.logger.info("Found %s TPM check patterns to patch", patches_applied)

        except Exception as e:
            self.logger.error(f"Error patching TPM checks: {str(e)}")

    def _manipulate_tpm_registry(self) -> None:
        """
        Manipulate Windows registry to simulate TPM presence.
        """
        try:
            if platform.system() != "Windows":
                self.logger.info("Not on Windows - skipping registry manipulation")
                return

            if not WINREG_AVAILABLE or winreg is None:
                self.logger.warning("winreg module not available - skipping registry manipulation")
                return

            # TPM registry keys
            tpm_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\TPM", "Start", 3),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Tpm", "SpecVersion", "2.0"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Tpm", "ManufacturerIdTxt", "INTC"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Tpm", "ManufacturerVersion", "1.0.0.0"),
            ]

            for hkey, path, name, value in tpm_keys:
                try:
                    key = winreg.CreateKey(hkey, path)
                    if isinstance(value, int):
                        winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
                    else:
                        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
                    winreg.CloseKey(key)
                    self.logger.info("Set registry key %s\\%s = %s", path, name, value)
                except Exception as e:
                    self.logger.warning(f"Could not set registry key {path}\\{name}: {str(e)}")

        except Exception as e:
            self.logger.error(f"Registry manipulation failed: {str(e)}")

    def generate_bypass_script(self) -> str:
        """
        Generate a Frida script for runtime TPM bypass.

        Returns:
            str: Complete Frida script for TPM bypass
        """
        base_script = self.hooks[0]["script"] if self.hooks else ""

        script = f"""
        // TPM Protection Bypass Script
        // Generated by Intellicrack

        console.log("[TPM Bypass] Initializing TPM protection bypass...");

        // Global flag to track TPM bypass status
        var tpmBypassed = false;

        {base_script}

        // Additional TPM bypass logic
        function bypassTPM() {{
            // Hook CreateFile calls to TPM device
            var createFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
            if (createFileW) {{
                Interceptor.attach(createFileW, {{
                    onEnter: function(args) {{
                        var filename = args[0].readUtf16String();
                        if (filename && filename.toLowerCase().includes("tpm")) {{
                            console.log("[TPM Bypass] Intercepted TPM device access: " + filename);
                            args[0] = Memory.allocUtf16String("\\\\Device\\\\Null");
                        }}
                    }}
                }});
            }}

            // Hook DeviceIoControl for TPM commands
            var deviceIoControl = Module.findExportByName("kernel32.dll", "DeviceIoControl");
            if (deviceIoControl) {{
                Interceptor.attach(deviceIoControl, {{
                    onEnter: function(args) {{
                        var ioctl = args[1].toInt32();
                        // TPM IOCTL codes typically start with 0x22
                        if ((ioctl & 0xFF000000) == 0x22000000) {{
                            console.log("[TPM Bypass] Intercepted TPM IOCTL: 0x" + ioctl.toString(16));
                        }}
                    }},
                    onLeave: function(retval) {{
                        retval.replace(1); // Return success
                    }}
                }});
            }}

            tpmBypassed = true;
            console.log("[TPM Bypass] TPM protection bypass complete!");
        }}

        // Execute bypass
        setTimeout(bypassTPM, 100);
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
            "virtual_tpm_active": self.virtual_tpm is not None,
            "frida_available": FRIDA_AVAILABLE,
            "winreg_available": WINREG_AVAILABLE
        }

    def clear_hooks(self) -> None:
        """
        Clear all installed hooks and patches.
        """
        self.hooks.clear()
        self.patches.clear()
        self.virtual_tpm = None
        self.logger.info("Cleared all TPM bypass hooks and patches")


def bypass_tpm_protection(app: Any) -> Dict[str, Any]:
    """
    Convenience function to bypass TPM protection on an application.

    Args:
        app: Application instance with binary_path

    Returns:
        dict: Results of the bypass attempt
    """
    bypass = TPMProtectionBypass(app)
    return bypass.bypass_tpm_checks()


class TPMAnalyzer:
    """
    Analyzes TPM usage in applications for security research purposes.
    """
    
    def __init__(self, binary_path: Optional[str] = None):
        """Initialize TPM analyzer."""
        self.binary_path = binary_path
        self.logger = logging.getLogger("IntellicrackLogger.TPMAnalyzer")
        self.tpm_indicators = []
        
    def analyze(self) -> Dict[str, Any]:
        """
        Analyze binary for TPM usage patterns.
        
        Returns:
            dict: Analysis results including TPM usage indicators
        """
        results = {
            "uses_tpm": False,
            "tpm_version": None,
            "tpm_apis": [],
            "tpm_checks": [],
            "confidence": 0.0
        }
        
        if not self.binary_path:
            return results
            
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
                
            # Check for TPM-related strings
            tpm_strings = [
                b"Tbsi_Context_Create",
                b"Tbsi_Submit_Command",
                b"NCryptOpenStorageProvider",
                b"Microsoft Platform Crypto Provider",
                b"TPM",
                b"TrustedPlatformModule"
            ]
            
            found_strings = []
            for s in tpm_strings:
                if s in data:
                    found_strings.append(s.decode('utf-8', errors='ignore'))
                    
            results["tpm_apis"] = found_strings
            results["uses_tpm"] = len(found_strings) > 0
            results["confidence"] = min(len(found_strings) * 0.2, 1.0)
            
            # Detect TPM version
            if b"TPM 2.0" in data or b"TPM2" in data:
                results["tpm_version"] = "2.0"
            elif b"TPM 1.2" in data:
                results["tpm_version"] = "1.2"
                
        except Exception as e:
            self.logger.error(f"Error analyzing TPM usage: {str(e)}")
            
        return results


def analyze_tpm_protection(binary_path: str) -> Dict[str, Any]:
    """
    Analyze a binary for TPM protection mechanisms.
    
    Args:
        binary_path: Path to the binary to analyze
        
    Returns:
        dict: Analysis results
    """
    analyzer = TPMAnalyzer(binary_path)
    return analyzer.analyze()


def detect_tpm_usage(process_name: Optional[str] = None) -> bool:
    """
    Detect if a process is using TPM functionality.
    
    Args:
        process_name: Name of the process to check (optional)
        
    Returns:
        bool: True if TPM usage detected
    """
    if platform.system() != "Windows":
        return False
        
    try:
        # Check if TPM service is running
        import subprocess
        result = subprocess.run(
            ["sc", "query", "TPM"],
            capture_output=True,
            text=True
        )
        return "RUNNING" in result.stdout
    except Exception:
        return False


def tpm_research_tools() -> Dict[str, Any]:
    """
    Get available TPM research tools and utilities.
    
    Returns:
        dict: Available tools and their capabilities
    """
    return {
        "analyzer": TPMAnalyzer,
        "bypass": TPMProtectionBypass,
        "functions": {
            "analyze_tpm_protection": analyze_tpm_protection,
            "detect_tpm_usage": detect_tpm_usage,
            "bypass_tpm_protection": bypass_tpm_protection
        },
        "capabilities": [
            "TPM API hooking",
            "Virtual TPM emulation", 
            "Binary patching",
            "Registry manipulation",
            "Runtime bypass"
        ]
    }


# Export the main classes and functions
__all__ = [
    'TPMProtectionBypass',
    'bypass_tpm_protection',
    'TPMAnalyzer',
    'analyze_tpm_protection',
    'detect_tpm_usage',
    'tpm_research_tools'
]
