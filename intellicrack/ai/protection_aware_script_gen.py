#!/usr/bin/env python3
"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
from typing import Any

from ..models.protection_knowledge_base import get_protection_knowledge_base
from ..protection.unified_protection_engine import get_unified_engine

"""
Protection-Aware AI Script Generation

This module enhances AI script generation by using ML-detected protection
information to generate targeted bypass scripts.
"""

logger = logging.getLogger(__name__)


class ProtectionAwareScriptGenerator:
    """Generate targeted scripts based on detected protection schemes"""

    def __init__(self):
        """Initialize the protection-aware script generator.

        Sets up the generator with protection-specific script templates
        for various software protection systems including Sentinel HASP,
        FlexLM, WinLicense, Steam CEG, VMProtect, Denuvo, and Microsoft
        activation systems.
        """
        self.logger = logging.getLogger(__name__ + ".ProtectionAwareScriptGenerator")
        self.unified_engine = get_unified_engine()
        self.kb = get_protection_knowledge_base()

        # Protection-specific script templates
        self.script_templates = {
            "sentinel_hasp": self._get_hasp_scripts(),
            "flexlm": self._get_flexlm_scripts(),
            "winlicense": self._get_winlicense_scripts(),
            "steam_ceg": self._get_steam_scripts(),
            "vmprotect": self._get_vmprotect_scripts(),
            "denuvo": self._get_denuvo_scripts(),
            "microsoft_activation": self._get_ms_activation_scripts(),
        }

    def generate_bypass_script(
        self, binary_path: str, script_type: str = "frida"
    ) -> dict[str, Any]:
        """Generate a bypass script tailored to the detected protection.

        Args:
            binary_path: Path to the protected binary
            script_type: Type of script to generate (frida, ghidra, ida)

        Returns:
            Dict containing script and metadata

        """
        # Use unified engine for comprehensive analysis
        try:
            result = self.unified_engine.analyze_file(binary_path, deep_scan=True)
        except Exception as e:
            self.logger.error("Exception in protection_aware_script_gen: %s", e)
            return {
                "success": False,
                "error": f"Failed to analyze protection: {e!s}",
                "script": self._get_generic_analysis_script(script_type),
            }

        # Early exit if no protection detected
        if not result or not result.is_protected:
            return {
                "success": True,
                "protection_type": "None",
                "confidence": 1.0,
                "script": self._get_basic_analysis_script(script_type),
                "approach": "Basic analysis - no protection detected",
                "metadata": {
                    "file_type": result.file_type if result else "Unknown",
                    "architecture": result.architecture if result else "Unknown",
                },
            }

        # Build prioritized protection list
        protections_to_process = {}
        primary_protection = None
        highest_confidence = 0.0

        # Prioritize ICP results for accuracy
        if result.icp_analysis and not result.icp_analysis.error:
            for detection in result.icp_analysis.all_detections:
                if detection.name != "Unknown":
                    protections_to_process[detection.name] = {
                        "source": "ICP",
                        "type": detection.type,
                        "confidence": detection.confidence,
                        "version": detection.version,
                    }
                    # Track highest confidence protection
                    if detection.confidence > highest_confidence:
                        highest_confidence = detection.confidence
                        primary_protection = detection.name

        # Add other protections from unified analysis
        for protection in result.protections:
            name = protection.get("name", "Unknown")
            if name not in protections_to_process and name != "Unknown":
                protections_to_process[name] = {
                    "source": protection.get("source", "Unknown"),
                    "type": protection.get("type", "unknown"),
                    "confidence": protection.get("confidence", 50.0) / 100.0,
                    "version": protection.get("version", ""),
                }
                # Update primary if higher confidence
                conf = protection.get("confidence", 50.0) / 100.0
                if conf > highest_confidence:
                    highest_confidence = conf
                    primary_protection = name

        # If no primary protection found, use first one
        if not primary_protection and protections_to_process:
            primary_protection = list(protections_to_process.keys())[0]
            highest_confidence = protections_to_process[primary_protection]["confidence"]

        # Get protection info from knowledge base
        protection_info = (
            self.kb.get_protection_info(primary_protection) if primary_protection else None
        )

        # Generate script sections for each protection
        script_sections = []
        bypass_techniques = []

        for protection_name, details in protections_to_process.items():
            # Get protection-specific scripts
            protection_key = protection_name.lower().replace("/", "_").replace(" ", "_")

            if protection_key in self.script_templates:
                scripts = self.script_templates[protection_key]
                script_section = scripts.get(
                    script_type, self._get_generic_bypass_script(script_type)
                )
                script_sections.append(
                    f"// Bypass for {protection_name} (Source: {details['source']})\n{script_section}"
                )

                # Get bypass techniques from knowledge base
                techniques = self.kb.get_bypass_techniques(protection_name)
                if techniques:
                    bypass_techniques.extend(techniques)
            else:
                # Generic bypass for unknown protections
                generic_script = self._get_generic_bypass_script(script_type)
                script_sections.append(f"// Generic bypass for {protection_name}\n{generic_script}")

        # Combine all script sections
        combined_script = "\n\n".join(script_sections)

        # Add file metadata to script header
        header = f"""// Intellicrack Bypass Script
// Target: {binary_path}
// File Type: {result.file_type}
// Architecture: {result.architecture}
// Primary Protection: {primary_protection or 'Unknown'}
// Total Protections Detected: {len(protections_to_process)}

"""

        final_script = header + combined_script

        # Add AI-enhanced instructions
        ai_prompt = self._generate_ai_prompt(
            result, primary_protection, highest_confidence, protection_info
        )

        # Generate approach description
        approach = f"Multi-layered analysis detected {len(protections_to_process)} protection(s). "
        if primary_protection:
            approach += f"Primary target: {primary_protection}. "
        approach += f"Using {'ICP engine' if result.icp_analysis else 'unified'} detection."

        return {
            "success": True,
            "protection_detected": primary_protection or "Unknown",
            "confidence": highest_confidence,
            "script": final_script,
            "approach": approach,
            "ai_prompt": ai_prompt,
            "bypass_techniques": self._get_recommended_techniques(protection_info),
            "estimated_time": self.kb.estimate_bypass_time(primary_protection, "intermediate")
            if primary_protection
            else "Variable",
            "tools_needed": self.kb.get_tools_for_protection(primary_protection)
            if primary_protection
            else [],
            "die_analysis": result.icp_analysis,
        }

    def _generate_ai_prompt(
        self, result, protection_type: str, confidence: float, protection_info: Any
    ) -> str:
        """Generate AI prompt for script enhancement"""
        prompt = f"""Generate a bypass script for {protection_type} protection.

Protection Details:
- Type: {protection_type}
- Confidence: {confidence:.2%}
- File Type: {result.file_type}
- Architecture: {result.architecture}
- Is Packed: {result.is_packed}
- Is Protected: {result.is_protected}

Detected Components:
{self._format_detections(result)}

"""

        if protection_info:
            prompt += f"""
Known Protection Information:
- Vendor: {protection_info.vendor}
- Description: {protection_info.description}
- Common in: {', '.join(protection_info.common_applications[:3])}

Recommended Bypass Techniques:
"""
            for technique in protection_info.bypass_techniques[:2]:
                prompt += f"""
- {technique.name}:
  - Success Rate: {technique.success_rate:.0%}
  - Time Estimate: {technique.time_estimate}
  - Tools: {', '.join(technique.tools_required[:3])}
"""

        prompt += """
Generate a script that:
1. Identifies key protection checks
2. Hooks/patches validation functions
3. Handles anti-debugging if present
4. Provides detailed logging
5. Is resilient to protection updates

Focus on the most effective approach for this specific protection type.
"""

        return prompt

    def _format_detections(self, result) -> str:
        """Format detections for display"""
        lines = []

        # Format ICP detections if available
        if result.icp_analysis and result.icp_analysis.all_detections:
            lines.append("ICP Engine Detections:")
            for detection in result.icp_analysis.all_detections:
                ver_str = f" v{detection.version}" if detection.version else ""
                lines.append(f"- {detection.name}{ver_str} ({detection.type})")

        # Format unified protections
        if result.protections:
            if lines:
                lines.append("\nUnified Analysis:")
            for protection in result.protections:
                ver_str = f" v{protection.get('version', '')}" if protection.get("version") else ""
                source = protection.get("source", "Unknown")
                lines.append(f"- {protection['name']}{ver_str} ({protection['type']}) [{source}]")

        if not lines:
            return "- None detected"

        return "\n".join(lines)

    def _get_recommended_techniques(self, protection_info: Any) -> list[dict[str, Any]]:
        """Get recommended bypass techniques"""
        if not protection_info:
            return []

        techniques = []
        for technique in protection_info.bypass_techniques:
            techniques.append(
                {
                    "name": technique.name,
                    "description": technique.description,
                    "difficulty": technique.difficulty.value,
                    "success_rate": technique.success_rate,
                    "time_estimate": technique.time_estimate,
                    "tools": technique.tools_required,
                }
            )

        return techniques

    def _get_hasp_scripts(self) -> dict[str, str]:
        """Sentinel HASP specific scripts"""
        return {
            "frida": """// Sentinel HASP Bypass Script
// Targets: hasp_login, hasp_encrypt, hasp_decrypt

// Hook hasp_login to always return success
Interceptor.attach(Module.findExportByName(null, "hasp_login"), {
    onEnter: function(args) {
        console.log("[HASP] hasp_login called");
        console.log("  Feature ID: " + args[0]);
        console.log("  Vendor Code: " + args[1]);
        this.handle = args[2];
    },
    onLeave: function(retval) {
        console.log("[HASP] hasp_login returned: " + retval);
        // HASP_STATUS_OK = 0
        retval.replace(0);
        // Set valid handle
        if (this.handle) {
            Memory.writeU32(this.handle, 0x12345678);
        }
    }
});

// Hook hasp_get_info to return valid dongle info
Interceptor.attach(Module.findExportByName(null, "hasp_get_info"), {
    onLeave: function(retval) {
        console.log("[HASP] hasp_get_info bypassed");
        retval.replace(0);
    }
});

// Hook hasp_encrypt/decrypt
var hasp_encrypt = Module.findExportByName(null, "hasp_encrypt");
if (hasp_encrypt) {
    Interceptor.attach(hasp_encrypt, {
        onEnter: function(args) {
            this.buffer = args[1];
            this.length = args[2].toInt32();
        },
        onLeave: function(retval) {
            console.log("[HASP] hasp_encrypt bypassed");
            // Just XOR with 0xAA for simple "encryption"
            for (var i = 0; i < this.length; i++) {
                var byte = Memory.readU8(this.buffer.add(i));
                Memory.writeU8(this.buffer.add(i), byte ^ 0xAA);
            }
            retval.replace(0);
        }
    });
}

console.log("[+] Sentinel HASP hooks installed");
""",
            "ghidra": """// Sentinel HASP Analysis Script for Ghidra
// Identifies HASP API usage and patches validation

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class SentinelHASPBypass extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== Sentinel HASP Protection Analysis ===");

        // Find HASP imports
        String[] haspAPIs = {
            "hasp_login", "hasp_logout", "hasp_encrypt", "hasp_decrypt",
            "hasp_get_info", "hasp_get_sessioninfo", "hasp_update"
        };

        for (String api : haspAPIs) {
            Symbol sym = getSymbol(api, null);
            if (sym != null) {
                println("Found " + api + " at: " + sym.getAddress());

                // Find references
                Reference[] refs = getReferencesTo(sym.getAddress());
                for (Reference ref : refs) {
                    Address callAddr = ref.getFromAddress();
                    println("  Called from: " + callAddr);

                    // Patch the call result check
                    patchHASPCheck(callAddr);
                }
            }
        }

        // Find and patch dongle check patterns
        findAndPatchDongleChecks();
    }

    private void patchHASPCheck(Address callAddr) throws Exception {
        // Pattern: call hasp_login; test eax, eax; jnz error
        Instruction inst = getInstructionAt(callAddr);
        if (inst == null) return;

        Address nextAddr = inst.getNext().getAddress();
        inst = getInstructionAt(nextAddr);

        if (inst.getMnemonicString().equals("TEST")) {
            // Found test after HASP call, patch the jump
            inst = getInstructionAt(inst.getNext().getAddress());
            if (inst.getMnemonicString().startsWith("J")) {
                println("    Patching jump at: " + inst.getAddress());
                // NOP out the conditional jump
                clearListing(inst.getAddress(), inst.getAddress().add(inst.getLength()-1));
                setBytes(inst.getAddress(), new byte[]{(byte)0x90, (byte)0x90});
            }
        }
    }
}
""",
        }

    def _get_flexlm_scripts(self) -> dict[str, str]:
        """FlexLM/FlexNet specific scripts"""
        return {
            "frida": """// FlexLM/FlexNet License Bypass Script
// Targets license checkout and validation

// Hook lc_checkout
Interceptor.attach(Module.findExportByName(null, "lc_checkout"), {
    onEnter: function(args) {
        console.log("[FlexLM] lc_checkout called");
        console.log("  Feature: " + Memory.readCString(args[1]));
        console.log("  Version: " + Memory.readCString(args[2]));
    },
    onLeave: function(retval) {
        console.log("[FlexLM] lc_checkout returned: " + retval);
        // Success = 0
        retval.replace(0);
    }
});

// Hook license file reading
var fopen = Module.findExportByName(null, "fopen");
Interceptor.attach(fopen, {
    onEnter: function(args) {
        var filename = Memory.readCString(args[0]);
        if (filename.includes("license.dat") || filename.includes(".lic")) {
            console.log("[FlexLM] License file access: " + filename);
            // Could redirect to custom license file
        }
    }
});

// Hook environment variable access for LM_LICENSE_FILE
var getenv = Module.findExportByName(null, "getenv");
Interceptor.attach(getenv, {
    onEnter: function(args) {
        var varname = Memory.readCString(args[0]);
        if (varname === "LM_LICENSE_FILE") {
            console.log("[FlexLM] LM_LICENSE_FILE requested");
        }
    },
    onLeave: function(retval) {
        // Could return custom license path
    }
});

console.log("[+] FlexLM hooks installed");
""",
        }

    def _get_winlicense_scripts(self) -> dict[str, str]:
        """WinLicense/Themida specific scripts"""
        return {
            "frida": """// WinLicense/Themida Analysis Script
// Note: This protection uses heavy virtualization

console.warn("[!] WinLicense/Themida detected - Complex protection!");
console.warn("[!] This script provides analysis helpers only");

// Detect SecureEngine initialization
var patterns = [
    "53 65 63 75 72 65 45 6E 67 69 6E 65", // "SecureEngine"
    "57 69 6E 4C 69 63 65 6E 73 65"        // "WinLicense"
];

Process.enumerateModules().forEach(function(module) {
    patterns.forEach(function(pattern) {
        Memory.scan(module.base, module.size, pattern, {
            onMatch: function(address, size) {
                console.log("[WinLicense] Pattern found at: " + address);
                console.log("  Module: " + module.name);
            }
        });
    });
});

// Hook VirtualProtect to detect unpacking
Interceptor.attach(Module.findExportByName("kernel32.dll", "VirtualProtect"), {
    onEnter: function(args) {
        var addr = args[0];
        var size = args[1].toInt32();
        var newProtect = args[2].toInt32();

        // PAGE_EXECUTE_READWRITE = 0x40
        if (newProtect === 0x40 && size > 0x1000) {
            console.log("[WinLicense] Large VirtualProtect call:");
            console.log("  Address: " + addr);
            console.log("  Size: 0x" + size.toString(16));
            console.log("  [!] Possible unpacking happening");
        }
    }
});

// Monitor exception handlers (used for anti-debug)
Interceptor.attach(Module.findExportByName("ntdll.dll", "RtlAddVectoredExceptionHandler"), {
    onEnter: function(args) {
        console.log("[WinLicense] Exception handler registered at: " + args[1]);
    }
});

console.log("[+] WinLicense analysis hooks installed");
console.log("[!] Manual unpacking likely required");
""",
        }

    def _get_steam_scripts(self) -> dict[str, str]:
        """Steam CEG specific scripts"""
        return {
            "frida": """// Steam CEG Bypass Script
// Targets Steam API initialization and checks

// Hook SteamAPI_Init
var steamapi_init = Module.findExportByName("steam_api.dll", "SteamAPI_Init") ||
                   Module.findExportByName("steam_api64.dll", "SteamAPI_Init");

if (steamapi_init) {
    Interceptor.attach(steamapi_init, {
        onLeave: function(retval) {
            console.log("[Steam] SteamAPI_Init -> forcing success");
            retval.replace(1); // true
        }
    });
}

// Hook SteamAPI_RestartAppIfNecessary
var restart_check = Module.findExportByName(null, "SteamAPI_RestartAppIfNecessary");
if (restart_check) {
    Interceptor.attach(restart_check, {
        onEnter: function(args) {
            console.log("[Steam] App ID check: " + args[0]);
        },
        onLeave: function(retval) {
            console.log("[Steam] Bypassing restart check");
            retval.replace(0); // false - no restart needed
        }
    });
}

// Hook SteamUser interface
var steamuser_pattern = "48 89 5C 24 08 57 48 83 EC 20 48 8B F9 E8"; // SteamUser()
Memory.scan(Process.enumerateModules()[0].base, 0x1000000, steamuser_pattern, {
    onMatch: function(address, size) {
        console.log("[Steam] Found SteamUser at: " + address);

        Interceptor.attach(address, {
            onLeave: function(retval) {
                // Return valid SteamUser interface
                if (retval.isNull()) {
                    console.log("[Steam] Providing fake SteamUser interface");
                    // Would need to implement fake interface
                }
            }
        });
    }
});

console.log("[+] Steam CEG bypass hooks installed");
""",
        }

    def _get_vmprotect_scripts(self) -> dict[str, str]:
        """VMProtect specific scripts"""
        return {
            "frida": """// VMProtect Analysis Helper
// Note: VMProtect uses heavy virtualization - full bypass is complex

console.warn("[!] VMProtect detected - Extreme protection!");
console.warn("[!] This provides analysis assistance only");

// Detect VMProtect sections
Process.enumerateModules().forEach(function(module) {
    if (module.name === Process.enumerateModules()[0].name) {
        console.log("[VMProtect] Analyzing main module: " + module.name);

        // Look for .vmp sections
        // This is platform specific - example for Windows
        try {
            var peHeader = Memory.readU32(module.base.add(0x3C));
            var sectionsOffset = module.base.add(peHeader).add(0xF8);
            var numSections = Memory.readU16(module.base.add(peHeader).add(0x6));

            for (var i = 0; i < numSections; i++) {
                var sectionName = Memory.readCString(sectionsOffset.add(i * 0x28), 8);
                if (sectionName.includes("vmp")) {
                    console.log("[VMProtect] Found VMP section: " + sectionName);
                    var virtAddr = Memory.readU32(sectionsOffset.add(i * 0x28).add(0xC));
                    var virtSize = Memory.readU32(sectionsOffset.add(i * 0x28).add(0x8));
                    console.log("  Virtual Address: 0x" + virtAddr.toString(16));
                    console.log("  Size: 0x" + virtSize.toString(16));
                }
            }
        } catch (e) {
            console.log("[VMProtect] Error parsing PE: " + e);
        }
    }
});

// Monitor VMProtect SDK calls if present
var vmprotect_apis = [
    "VMProtectBegin",
    "VMProtectEnd",
    "VMProtectIsDebuggerPresent",
    "VMProtectIsVirtualMachinePresent"
];

vmprotect_apis.forEach(function(api) {
    var addr = Module.findExportByName(null, api);
    if (addr) {
        console.log("[VMProtect] Found API: " + api + " at " + addr);

        Interceptor.attach(addr, {
            onEnter: function(args) {
                console.log("[VMProtect] " + api + " called");
            },
            onLeave: function(retval) {
                if (api.includes("Present")) {
                    console.log("[VMProtect] Returning false for: " + api);
                    retval.replace(0);
                }
            }
        });
    }
});

console.log("[+] VMProtect analysis hooks installed");
console.log("[!] Full devirtualization required for complete bypass");
""",
        }

    def _get_denuvo_scripts(self) -> dict[str, str]:
        """Denuvo specific scripts"""
        return {
            "frida": """// Denuvo Analysis Helper
// WARNING: Denuvo is extremely complex protection

console.error("[!!!] DENUVO DETECTED [!!!]");
console.error("[!] This is one of the most advanced protections");
console.error("[!] Full bypass requires months of expert work");

// Denuvo characteristics monitoring
console.log("[Denuvo] Monitoring for characteristic behavior...");

// High CPU usage from VM
var highCpuThreads = [];
Process.enumerateThreads().forEach(function(thread) {
    // Monitor thread CPU usage - Denuvo VMs are CPU intensive
    // This is conceptual - Frida doesn't directly provide CPU per thread
    console.log("[Denuvo] Thread " + thread.id + " at " + thread.context.pc);
});

// Monitor for excessive memory allocations (VM tables)
var virtualAlloc = Module.findExportByName("kernel32.dll", "VirtualAlloc");
if (virtualAlloc) {
    Interceptor.attach(virtualAlloc, {
        onEnter: function(args) {
            var size = args[1].toInt32();
            if (size > 0x100000) { // > 1MB
                console.log("[Denuvo] Large allocation: 0x" + size.toString(16));
                console.log("  Possible VM table allocation");
            }
        }
    });
}

// Denuvo typically has hundreds of triggers
console.log("[Denuvo] Bypass approach:");
console.log("  1. Identify all trigger points (100+)");
console.log("  2. Understand VM architecture");
console.log("  3. Reconstruct original code flow");
console.log("  4. Remove/bypass all triggers");
console.log("  5. Fix any broken functionality");
console.log("");
console.log("[!] This is a professional-level challenge");
console.log("[!] Consider waiting for scene release");
""",
        }

    def _get_ms_activation_scripts(self) -> dict[str, str]:
        """Microsoft Activation specific scripts"""
        return {
            "frida": """// Microsoft Activation Bypass Helper
// For educational/testing purposes only

// Software Licensing API hooks
var slc = Process.getModuleByName("slc.dll");
if (slc) {
    console.log("[MS-Activation] Found Software Licensing Client");

    // Hook SLOpen
    var slopen = Module.findExportByName("slc.dll", "SLOpen");
    if (slopen) {
        Interceptor.attach(slopen, {
            onLeave: function(retval) {
                console.log("[MS-Activation] SLOpen -> success");
                retval.replace(0); // S_OK
            }
        });
    }

    // Hook SLGetWindowsInformation
    var slgetinfo = Module.findExportByName("slc.dll", "SLGetWindowsInformation");
    if (slgetinfo) {
        Interceptor.attach(slgetinfo, {
            onEnter: function(args) {
                var valueName = Memory.readUtf16String(args[1]);
                console.log("[MS-Activation] Querying: " + valueName);
            }
        });
    }
}

// Hook registry access to licensing keys
var regOpenKeyEx = Module.findExportByName("advapi32.dll", "RegOpenKeyExW");
Interceptor.attach(regOpenKeyEx, {
    onEnter: function(args) {
        var keyName = Memory.readUtf16String(args[1]);
        if (keyName.includes("SoftwareProtectionPlatform") ||
            keyName.includes("ProductOptions")) {
            console.log("[MS-Activation] Registry access: " + keyName);
        }
    }
});

// Monitor WMI queries (often used for activation)
var connectServer = Module.findExportByName("wbemprox.dll", "IWbemLocator_ConnectServer");
if (connectServer) {
    console.log("[MS-Activation] WMI monitoring active");
}

console.log("[+] Microsoft Activation hooks installed");
""",
        }

    def _get_basic_analysis_script(self, script_type: str) -> str:
        """Basic analysis script for unprotected binaries"""
        if script_type == "frida":
            return """// Basic Binary Analysis Script
// No protection detected - standard analysis

// Monitor file operations
var fopen = Module.findExportByName(null, "fopen");
Interceptor.attach(fopen, {
    onEnter: function(args) {
        console.log("[File] Opening: " + Memory.readCString(args[0]));
    }
});

// Monitor registry operations
var regOpen = Module.findExportByName("advapi32.dll", "RegOpenKeyExW");
if (regOpen) {
    Interceptor.attach(regOpen, {
        onEnter: function(args) {
            console.log("[Registry] Opening: " + Memory.readUtf16String(args[1]));
        }
    });
}

// Monitor network operations
var connect = Module.findExportByName(null, "connect");
if (connect) {
    Interceptor.attach(connect, {
        onEnter: function(args) {
            console.log("[Network] Connecting to socket");
        }
    });
}

console.log("[+] Basic analysis hooks installed");
"""
        return "// Basic analysis script"

    def _get_generic_bypass_script(self, script_type: str) -> str:
        """Generic bypass script for unknown protections"""
        if script_type == "frida":
            return """// Generic Protection Bypass Script
// For unknown/custom protection schemes

// Common protection checks to bypass
var commonChecks = [
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "GetTickCount",
    "QueryPerformanceCounter"
];

commonChecks.forEach(function(funcName) {
    var addr = Module.findExportByName(null, funcName);
    if (addr) {
        console.log("[Generic] Hooking: " + funcName);

        Interceptor.attach(addr, {
            onLeave: function(retval) {
                if (funcName.includes("Debugger")) {
                    retval.replace(0); // No debugger
                }
            }
        });
    }
});

// Monitor common validation patterns
Process.enumerateModules().forEach(function(module) {
    // Look for common license/serial strings
    var patterns = [
        "6C 69 63 65 6E 73 65", // "license"
        "73 65 72 69 61 6C",     // "serial"
        "6B 65 79",              // "key"
        "76 61 6C 69 64"         // "valid"
    ];

    patterns.forEach(function(pattern) {
        Memory.scan(module.base, Math.min(module.size, 0x100000), pattern, {
            onMatch: function(address, size) {
                console.log("[Generic] Found pattern at: " + address);

                // Set read watch on the address
                Process.setExceptionHandler(function(details) {
                    if (details.address.equals(address)) {
                        console.log("[Generic] Access to validation string at: " + address);
                        return true; // Continue execution
                    }
                });
            }
        });
    });
});

console.log("[+] Generic bypass hooks installed");
"""
        return "// Generic bypass script"

    def _get_generic_analysis_script(self, script_type: str) -> str:
        """Generic analysis script when protection detection fails"""
        script_type_upper = script_type.upper()

        if script_type.lower() == "frida":
            return f"""// {script_type_upper} Protection Analysis Script
// Failed to detect specific protection - running generic analysis

console.log("[?] Protection type could not be determined");
console.log("[*] Running comprehensive {script_type} analysis...");

// Generic function hooking for {script_type}
Process.enumerateModules().forEach(module => {{
    module.enumerateExports().forEach(exp => {{
        if (exp.name && (exp.name.includes('license') || exp.name.includes('check'))) {{
            console.log("[*] Found potential protection function: " + exp.name);
        }}
    }});
}});

console.log("[+] Generic {script_type} analysis started");
"""
        return f"""// {script_type_upper} Protection Analysis Script
// Failed to detect specific protection - running generic analysis

// Generic analysis for {script_type}
print("[?] Protection type could not be determined")
print("[*] Running comprehensive {script_type} analysis...")

// Add {script_type}-specific analysis code here

print("[+] Generic {script_type} analysis started")
"""


# Integration function
def enhance_ai_script_generation(ai_generator, binary_path: str) -> dict[str, Any]:
    """Enhance existing AI script generation with protection awareness.

    This function would be integrated into the existing AI system to provide
    protection-specific script generation.
    """
    protection_gen = ProtectionAwareScriptGenerator()

    # Generate protection-aware script
    result = protection_gen.generate_bypass_script(binary_path)

    # Use the AI prompt to enhance the script further
    if hasattr(ai_generator, "generate_script"):
        enhanced_script = ai_generator.generate_script(
            prompt=result["ai_prompt"],
            base_script=result["script"],
            context={
                "protection": result["protection_detected"],
                "difficulty": result["difficulty"],
                "techniques": result["bypass_techniques"],
            },
        )
        result["enhanced_script"] = enhanced_script

    return result
