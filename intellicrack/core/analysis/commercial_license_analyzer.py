"""Commercial License Protocol Analyzer for FlexLM, HASP, and CodeMeter.

This module provides comprehensive analysis and bypass generation for
commercial license protection systems used in enterprise software.
"""

import struct
import time
from pathlib import Path
from typing import Any

from ...utils.logger import get_logger
from ..network.protocol_fingerprinter import ProtocolFingerprinter
from ..network.protocols.flexlm_parser import FlexLMProtocolParser
from ..protection_bypass.dongle_emulator import HardwareDongleEmulator

logger = get_logger(__name__)


class CommercialLicenseAnalyzer:
    """Comprehensive analyzer for commercial license protection systems."""

    def __init__(self, binary_path: str | None = None):
        """Initialize the commercial license analyzer.

        Args:
            binary_path: Path to the binary to analyze
        """
        self.binary_path = binary_path
        self.flexlm_parser = FlexLMProtocolParser()
        self.dongle_emulator = HardwareDongleEmulator()
        self.protocol_fingerprinter = ProtocolFingerprinter()

        # Detection results
        self.detected_systems = []
        self.license_servers = []
        self.protection_features = {}

        # Bypass strategies
        self.bypass_strategies = {}

    def analyze_binary(self, binary_path: str | None = None) -> dict[str, Any]:
        """Analyze binary for commercial license protections.

        Args:
            binary_path: Optional path to binary (uses self.binary_path if not provided)

        Returns:
            Analysis results including detected systems and bypass strategies
        """
        if binary_path:
            self.binary_path = binary_path

        results = {
            "detected_systems": [],
            "license_servers": [],
            "protection_features": {},
            "bypass_strategies": {},
            "confidence": 0.0,
        }

        if not self.binary_path or not Path(self.binary_path).exists():
            logger.warning(f"Binary path invalid: {self.binary_path}")
            return results

        # Detect FlexLM
        flexlm_detected = self._detect_flexlm()
        if flexlm_detected:
            results["detected_systems"].append("FlexLM")
            results["bypass_strategies"]["flexlm"] = self._generate_flexlm_bypass()

        # Detect HASP
        hasp_detected = self._detect_hasp()
        if hasp_detected:
            results["detected_systems"].append("HASP")
            results["bypass_strategies"]["hasp"] = self._generate_hasp_bypass()

        # Detect CodeMeter
        codemeter_detected = self._detect_codemeter()
        if codemeter_detected:
            results["detected_systems"].append("CodeMeter")
            results["bypass_strategies"]["codemeter"] = self._generate_codemeter_bypass()

        # Analyze network protocols
        protocol_analysis = self._analyze_network_protocols()
        results["license_servers"] = protocol_analysis.get("servers", [])
        results["protection_features"] = protocol_analysis.get("features", {})

        # Calculate confidence
        results["confidence"] = self._calculate_confidence(results)

        return results

    def analyze(self) -> dict[str, Any]:
        """Wrapper method for API compatibility with tests."""
        return self.analyze_binary(self.binary_path)

    def _detect_flexlm(self) -> bool:
        """Detect FlexLM license system in binary.

        Returns:
            True if FlexLM detected
        """
        flexlm_indicators = [
            b"FLEXlm",
            b"lmgrd",
            b"lmutil",
            b"lmstat",
            b"FLEXLM_DIAGNOSTICS",
            b"@(#)FLEXlm",
            b"license.dat",
            b"license.lic",
            b"VENDOR_LICENSE_FILE",
            b"LM_LICENSE_FILE",
        ]

        flexlm_apis = [
            b"lc_checkout",
            b"lc_checkin",
            b"lc_init",
            b"lc_set_attr",
            b"lc_get_attr",
            b"lc_cryptstr",
            b"lc_new_job",
            b"lc_free_job",
        ]

        try:
            with open(self.binary_path, "rb") as f:
                binary_data = f.read()

            # Check for FlexLM indicators
            for indicator in flexlm_indicators:
                if indicator in binary_data:
                    logger.info(f"FlexLM indicator found: {indicator}")
                    return True

            # Check for FlexLM API calls
            for api in flexlm_apis:
                if api in binary_data:
                    logger.info(f"FlexLM API found: {api}")
                    return True

        except Exception as e:
            logger.error(f"Error detecting FlexLM: {e}")

        return False

    def _detect_hasp(self) -> bool:
        """Detect HASP dongle protection in binary.

        Returns:
            True if HASP detected
        """
        hasp_indicators = [
            b"hasp_login",
            b"hasp_logout",
            b"hasp_encrypt",
            b"hasp_decrypt",
            b"hasp_get_info",
            b"hasp_update",
            b"HASP",
            b"Sentinel",
            b"hasplms.exe",
            b"aksusbd.sys",
        ]

        hasp_dlls = [
            b"hasp_windows",
            b"hasp_net_windows",
            b"hasp_windows_x64",
            b"haspvlib",
            b"hasp_api",
        ]

        try:
            with open(self.binary_path, "rb") as f:
                binary_data = f.read()

            # Check for HASP indicators
            for indicator in hasp_indicators:
                if indicator in binary_data:
                    logger.info(f"HASP indicator found: {indicator}")
                    return True

            # Check for HASP DLLs
            for dll in hasp_dlls:
                if dll in binary_data:
                    logger.info(f"HASP DLL reference found: {dll}")
                    return True

        except Exception as e:
            logger.error(f"Error detecting HASP: {e}")

        return False

    def _detect_codemeter(self) -> bool:
        """Detect CodeMeter protection in binary.

        Returns:
            True if CodeMeter detected
        """
        codemeter_indicators = [
            b"CodeMeter",
            b"CmDongle",
            b"CmStick",
            b"WibuKey",
            b"WIBU-SYSTEMS",
            b"CmContainer",
            b"CmActLicense",
            b"CodeMeterRuntime",
        ]

        codemeter_apis = [
            b"CmGetInfo",
            b"CmGetLicenseInfo",
            b"CmGetVersion",
            b"CmAccess",
            b"CmCrypt",
            b"CmDecrypt",
            b"CmEncrypt",
            b"CmRelease",
        ]

        try:
            with open(self.binary_path, "rb") as f:
                binary_data = f.read()

            # Check for CodeMeter indicators
            for indicator in codemeter_indicators:
                if indicator in binary_data:
                    logger.info(f"CodeMeter indicator found: {indicator}")
                    return True

            # Check for CodeMeter APIs
            for api in codemeter_apis:
                if api in binary_data:
                    logger.info(f"CodeMeter API found: {api}")
                    return True

        except Exception as e:
            logger.error(f"Error detecting CodeMeter: {e}")

        return False

    def _analyze_network_protocols(self) -> dict[str, Any]:
        """Analyze network protocols for license communication.

        Returns:
            Network protocol analysis results
        """
        analysis = {"servers": [], "features": {}, "protocols": []}

        # Use protocol fingerprinter to detect license servers
        if self.binary_path:
            fingerprint = self.protocol_fingerprinter.fingerprint_packet(b"", {"binary_path": self.binary_path})

            if fingerprint and fingerprint.get("protocol_type") in [
                "FlexLM",
                "HASP Network",
                "CodeMeter Network",
            ]:
                analysis["protocols"].append(fingerprint.get("protocol_type"))

                # Extract server information
                if fingerprint.get("server_port"):
                    analysis["servers"].append(
                        {
                            "type": fingerprint.get("protocol_type"),
                            "port": fingerprint.get("server_port"),
                            "hostname": fingerprint.get("server_hostname", "localhost"),
                        }
                    )

                # Extract feature information
                analysis["features"] = fingerprint.get("features", {})

        return analysis

    def _generate_flexlm_bypass(self) -> dict[str, Any]:
        """Generate FlexLM bypass strategy.

        Returns:
            FlexLM bypass configuration
        """
        bypass = {
            "method": "flexlm_emulation",
            "server_port": 27000,  # Default FlexLM port
            "vendor_daemon": "vendor",
            "features": [],
            "patches": [],
            "hooks": [],
            "emulation_script": "",
        }

        # Generate API hooks
        bypass["hooks"] = [
            {
                "api": "lc_checkout",
                "replacement": b"\x31\xc0\xc3",  # xor eax,eax; ret (return success)
                "description": "Always return successful checkout",
            },
            {
                "api": "lc_init",
                "replacement": b"\xb8\x01\x00\x00\x00\xc3",  # mov eax,1; ret
                "description": "Always return initialized",
            },
            {
                "api": "lc_cryptstr",
                "replacement": b"\x48\x89\xf0\xc3",  # mov rax,rsi; ret (return input)
                "description": "Bypass encryption check",
            },
        ]

        # Generate binary patches
        bypass["patches"] = [
            {
                "pattern": b"\x74.\x8b\x45.\x85\xc0",  # Common license check pattern
                "replacement": b"\x90\x90" + b"\x8b\x45.\x85\xc0",  # NOP the conditional jump
                "description": "Remove license validation jump",
            }
        ]

        # Generate emulation script
        bypass["emulation_script"] = self._generate_flexlm_script()
        bypass["frida_script"] = self._generate_flexlm_script()

        return bypass

    def _generate_hasp_bypass(self) -> dict[str, Any]:
        """Generate HASP bypass strategy.

        Returns:
            HASP bypass configuration
        """
        bypass = {
            "method": "hasp_emulation",
            "dongle_type": "HASP HL",
            "vendor_id": 0x0529,
            "product_id": 0x0001,
            "features": [],
            "hooks": [],
            "virtual_device": {},
            "emulation_script": "",
        }

        # Get dongle configuration
        dongle_config = self.dongle_emulator.get_dongle_config("hasp")
        bypass["vendor_id"] = dongle_config["vendor_id"]
        bypass["product_id"] = dongle_config["product_id"]
        bypass["features"] = dongle_config["features"]

        # Generate API hooks
        bypass["hooks"] = [
            {
                "api": "hasp_login",
                "replacement": b"\x31\xc0\xc3",  # xor eax,eax; ret (return 0/success)
                "description": "Always return successful login",
            },
            {
                "api": "hasp_encrypt",
                "replacement": b"\x48\x89\xf7\xf3\xa4\x31\xc0\xc3",  # Copy buffer and return success
                "description": "Fake encryption (copy input to output)",
            },
            {
                "api": "hasp_get_info",
                "replacement": self._generate_hasp_info_response(),
                "description": "Return valid dongle info",
            },
        ]

        # Configure virtual device
        bypass["virtual_device"] = {
            "type": "USB",
            "vendor_id": bypass["vendor_id"],
            "product_id": bypass["product_id"],
            "serial": dongle_config["serial"],
            "memory_size": dongle_config["memory_size"],
        }

        # Generate emulation script
        bypass["emulation_script"] = self._generate_hasp_script()
        bypass["frida_script"] = self._generate_hasp_script()
        bypass["api_hooks"] = bypass["hooks"]  # Alias for compatibility

        return bypass

    def _generate_codemeter_bypass(self) -> dict[str, Any]:
        """Generate CodeMeter bypass strategy.

        Returns:
            CodeMeter bypass configuration
        """
        bypass = {
            "method": "codemeter_emulation",
            "container_type": "CmStick",
            "firm_code": 100000,
            "product_code": 1,
            "features": [],
            "hooks": [],
            "patches": [],
            "emulation_script": "",
        }

        # Get dongle configuration
        dongle_config = self.dongle_emulator.get_dongle_config("codemeter")
        bypass["features"] = dongle_config["features"]

        # Generate API hooks
        bypass["hooks"] = [
            {
                "api": "CmAccess",
                "replacement": b"\x31\xc0\xc3",  # xor eax,eax; ret (return 0/success)
                "description": "Always return successful access",
            },
            {
                "api": "CmGetLicenseInfo",
                "replacement": self._generate_codemeter_license_info(),
                "description": "Return valid license info",
            },
            {
                "api": "CmCrypt",
                "replacement": b"\x31\xc0\xc3",  # xor eax,eax; ret
                "description": "Bypass encryption/decryption",
            },
        ]

        # Generate binary patches
        bypass["patches"] = [
            {
                "pattern": b"\xff\x15....\x85\xc0\x75",  # Call CmAccess and check result
                "replacement": b"\x31\xc0\x90\x90\x90\x90\x90\x90\x90",  # xor eax,eax + NOPs
                "description": "Bypass CmAccess check",
            }
        ]

        # Generate emulation script
        bypass["emulation_script"] = self._generate_codemeter_script()
        bypass["frida_script"] = self._generate_codemeter_script()

        return bypass

    def _generate_hasp_info_response(self) -> bytes:
        """Generate HASP info response bytes.

        Returns:
            Binary response for hasp_get_info
        """
        # HASP info structure
        info = struct.pack(
            "<IIIIIIII",
            0x4D535048,  # Magic "HPSM"
            0x00000001,  # Version
            0x00000529,  # Vendor ID
            0x00000001,  # Product ID
            0x12345678,  # Serial number
            0x00000100,  # Memory size
            0x00000000,  # RTC (Real-time clock)
            0xFFFFFFFF,  # Features bitmap
        )
        return info

    def _generate_codemeter_license_info(self) -> bytes:
        """Generate CodeMeter license info response.

        Returns:
            Binary response for CmGetLicenseInfo
        """
        # CodeMeter license structure
        info = struct.pack(
            "<IIIIIHHBBBB",
            0x434D4C49,  # Magic "ILMC"
            100000,  # Firm code
            1,  # Product code
            0xFFFFFFFF,  # Feature map
            0x00000000,  # Options
            1,  # Major version
            0,  # Minor version
            1,  # Count
            0,  # Reserved
            0,  # Reserved
            0,  # Reserved
        )
        return info

    def _generate_flexlm_script(self) -> str:
        """Generate Frida script for FlexLM bypass.

        Returns:
            Frida script as string
        """
        return """
// FlexLM License Bypass Script
Interceptor.attach(Module.findExportByName(null, "lc_checkout"), {
    onEnter: function(args) {
        console.log("[FlexLM] lc_checkout called");
        console.log("  Feature: " + args[1].readCString());
        console.log("  Version: " + args[2].readCString());
    },
    onLeave: function(retval) {
        console.log("[FlexLM] Bypassing license check");
        retval.replace(0);  // Return success
    }
});

Interceptor.attach(Module.findExportByName(null, "lc_init"), {
    onLeave: function(retval) {
        console.log("[FlexLM] Forcing initialization success");
        retval.replace(1);
    }
});

Interceptor.attach(Module.findExportByName(null, "lc_cryptstr"), {
    onEnter: function(args) {
        this.input = args[1];
    },
    onLeave: function(retval) {
        console.log("[FlexLM] Bypassing encryption check");
        retval.replace(this.input);  // Return input unchanged
    }
});

console.log("[FlexLM] Bypass hooks installed");
"""

    def _generate_hasp_script(self) -> str:
        """Generate Frida script for HASP bypass.

        Returns:
            Frida script as string
        """
        return """
// HASP Dongle Emulation Script
var hasp_handle = Memory.alloc(4);
hasp_handle.writeU32(0x12345678);  // Fake handle

Interceptor.attach(Module.findExportByName(null, "hasp_login"), {
    onEnter: function(args) {
        console.log("[HASP] hasp_login called");
        this.handle_ptr = args[4];  // Handle output pointer
    },
    onLeave: function(retval) {
        console.log("[HASP] Emulating successful login");
        if (this.handle_ptr) {
            this.handle_ptr.writePointer(hasp_handle);
        }
        retval.replace(0);  // HASP_STATUS_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "hasp_encrypt"), {
    onEnter: function(args) {
        this.buffer = args[1];
        this.length = args[2].toInt32();
    },
    onLeave: function(retval) {
        console.log("[HASP] Bypassing encryption");
        // Data stays unchanged (fake encryption)
        retval.replace(0);  // HASP_STATUS_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "hasp_get_info"), {
    onEnter: function(args) {
        this.info_ptr = args[3];
    },
    onLeave: function(retval) {
        console.log("[HASP] Providing fake dongle info");
        if (this.info_ptr) {
            var info = '<?xml version="1.0"?><info><dongle><id>12345678</id></dongle></info>';
            this.info_ptr.writeUtf8String(info);
        }
        retval.replace(0);  // HASP_STATUS_OK
    }
});

console.log("[HASP] Dongle emulation active");
"""

    def _generate_codemeter_script(self) -> str:
        """Generate Frida script for CodeMeter bypass.

        Returns:
            Frida script as string
        """
        return """
// CodeMeter License Bypass Script
var cm_handle = Memory.alloc(8);
cm_handle.writeU64(0xDEADBEEF);  // Fake handle

Interceptor.attach(Module.findExportByName(null, "CmAccess"), {
    onEnter: function(args) {
        console.log("[CodeMeter] CmAccess called");
        console.log("  FirmCode: " + args[0].toInt32());
        console.log("  ProductCode: " + args[1].toInt32());
        this.handle_ptr = args[3];
    },
    onLeave: function(retval) {
        console.log("[CodeMeter] Bypassing license check");
        if (this.handle_ptr) {
            this.handle_ptr.writePointer(cm_handle);
        }
        retval.replace(0);  // Success
    }
});

Interceptor.attach(Module.findExportByName(null, "CmGetLicenseInfo"), {
    onEnter: function(args) {
        this.info_ptr = args[1];
    },
    onLeave: function(retval) {
        console.log("[CodeMeter] Providing fake license info");
        if (this.info_ptr) {
            // Write fake license structure
            this.info_ptr.writeU32(100000);  // FirmCode
            this.info_ptr.add(4).writeU32(1);  // ProductCode
            this.info_ptr.add(8).writeU32(0xFFFFFFFF);  // Features
        }
        retval.replace(0);  // Success
    }
});

Interceptor.attach(Module.findExportByName(null, "CmCrypt"), {
    onLeave: function(retval) {
        console.log("[CodeMeter] Bypassing encryption");
        retval.replace(0);  // Success without actual encryption
    }
});

console.log("[CodeMeter] License bypass active");
"""

    def _calculate_confidence(self, results: dict[str, Any]) -> float:
        """Calculate confidence score for analysis results.

        Args:
            results: Analysis results

        Returns:
            Confidence score between 0.0 and 1.0
        """
        confidence = 0.0

        # Add confidence for each detected system
        confidence += len(results["detected_systems"]) * 0.25

        # Add confidence for bypass strategies
        confidence += len(results["bypass_strategies"]) * 0.15

        # Add confidence for detected servers
        confidence += min(len(results["license_servers"]) * 0.1, 0.3)

        # Add confidence for protection features
        confidence += min(len(results["protection_features"]) * 0.05, 0.2)

        return min(confidence, 1.0)

    def generate_bypass_report(self, analysis: dict[str, Any]) -> str:
        """Generate detailed bypass report.

        Args:
            analysis: Analysis results

        Returns:
            Formatted report string
        """
        report = "=" * 60 + "\n"
        report += "COMMERCIAL LICENSE PROTECTION ANALYSIS REPORT\n"
        report += "=" * 60 + "\n\n"

        report += f"Binary: {self.binary_path}\n"
        report += f"Analysis Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Confidence: {analysis['confidence']:.1%}\n\n"

        report += "DETECTED SYSTEMS:\n"
        report += "-" * 30 + "\n"
        for system in analysis["detected_systems"]:
            report += f"  • {system}\n"

        if analysis["license_servers"]:
            report += "\nLICENSE SERVERS:\n"
            report += "-" * 30 + "\n"
            for server in analysis["license_servers"]:
                report += f"  • Type: {server['type']}\n"
                report += f"    Port: {server['port']}\n"
                report += f"    Host: {server['hostname']}\n"

        if analysis["bypass_strategies"]:
            report += "\nBYPASS STRATEGIES:\n"
            report += "-" * 30 + "\n"
            for system, strategy in analysis["bypass_strategies"].items():
                report += f"\n{system.upper()}:\n"
                report += f"  Method: {strategy['method']}\n"
                report += f"  Hooks: {len(strategy.get('hooks', []))} API hooks\n"
                if "patches" in strategy:
                    report += f"  Patches: {len(strategy['patches'])} binary patches\n"
                if "emulation_script" in strategy:
                    report += "  Script: Frida script available\n"

        report += "\n" + "=" * 60 + "\n"

        return report


# Export main class
__all__ = ["CommercialLicenseAnalyzer"]
