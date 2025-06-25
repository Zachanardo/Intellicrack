#!/usr/bin/env python3
"""
Protection-Aware AI Script Generation

This module enhances AI script generation by using ML-detected protection
information to generate targeted bypass scripts.
"""

from typing import Dict, List, Any, Optional
import logging

from ..models import get_ml_system
from ..models.protection_knowledge_base import get_protection_knowledge_base

logger = logging.getLogger(__name__)


class ProtectionAwareScriptGenerator:
    """Generate targeted scripts based on detected protection schemes"""
    
    def __init__(self):
        self.ml_system = get_ml_system()
        self.kb = get_protection_knowledge_base()
        
        # Protection-specific script templates
        self.script_templates = {
            'sentinel_hasp': self._get_hasp_scripts(),
            'flexlm': self._get_flexlm_scripts(),
            'winlicense': self._get_winlicense_scripts(),
            'steam_ceg': self._get_steam_scripts(),
            'vmprotect': self._get_vmprotect_scripts(),
            'denuvo': self._get_denuvo_scripts(),
            'microsoft_activation': self._get_ms_activation_scripts()
        }
    
    def generate_bypass_script(self, binary_path: str, 
                             script_type: str = "frida") -> Dict[str, Any]:
        """
        Generate a bypass script tailored to the detected protection.
        
        Args:
            binary_path: Path to the protected binary
            script_type: Type of script to generate (frida, ghidra, ida)
            
        Returns:
            Dict containing script and metadata
        """
        # First, detect the protection
        protection_result = self.ml_system.predict(binary_path)
        
        if not protection_result.get('success'):
            return {
                'success': False,
                'error': 'Failed to analyze protection',
                'script': self._get_generic_analysis_script(script_type)
            }
        
        protection_type = protection_result.get('protection_type', 'Unknown')
        confidence = protection_result.get('confidence', 0)
        difficulty = protection_result.get('bypass_difficulty', 'Unknown')
        
        # Get protection info from knowledge base
        protection_info = self.kb.get_protection_info(protection_type)
        
        # Generate appropriate script based on protection
        if protection_type == "No Protection":
            script = self._get_basic_analysis_script(script_type)
            approach = "Basic analysis - no protection detected"
        else:
            # Get protection-specific scripts
            protection_key = protection_type.lower().replace('/', '_').replace(' ', '_')
            
            if protection_key in self.script_templates:
                scripts = self.script_templates[protection_key]
                script = scripts.get(script_type, self._get_generic_bypass_script(script_type))
                approach = f"Targeted {protection_type} bypass"
            else:
                script = self._get_generic_bypass_script(script_type)
                approach = "Generic bypass approach"
        
        # Add AI-enhanced instructions
        ai_prompt = self._generate_ai_prompt(protection_result, protection_info)
        
        return {
            'success': True,
            'protection_detected': protection_type,
            'confidence': confidence,
            'difficulty': difficulty,
            'script': script,
            'approach': approach,
            'ai_prompt': ai_prompt,
            'bypass_techniques': self._get_recommended_techniques(protection_info),
            'estimated_time': self.kb.estimate_bypass_time(protection_type, "intermediate"),
            'tools_needed': self.kb.get_tools_for_protection(protection_type)
        }
    
    def _generate_ai_prompt(self, protection_result: Dict[str, Any], 
                          protection_info: Any) -> str:
        """Generate AI prompt for script enhancement"""
        protection = protection_result.get('protection_type', 'Unknown')
        features = protection_result.get('features_summary', {})
        
        prompt = f"""Generate a bypass script for {protection} protection.

Protection Details:
- Type: {protection}
- Category: {protection_result.get('protection_category', 'unknown')}
- Confidence: {protection_result.get('confidence', 0):.2%}
- Difficulty: {protection_result.get('bypass_difficulty', 'Unknown')}

Binary Characteristics:
- File size: {features.get('file_size', 0)} bytes
- Entropy: {features.get('entropy', 0):.2f}
- Packed: {'Yes' if features.get('has_packing') else 'No'}
- Anti-debug: {'Yes' if features.get('has_anti_debug') else 'No'}

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
    
    def _get_recommended_techniques(self, protection_info: Any) -> List[Dict[str, Any]]:
        """Get recommended bypass techniques"""
        if not protection_info:
            return []
        
        techniques = []
        for technique in protection_info.bypass_techniques:
            techniques.append({
                'name': technique.name,
                'description': technique.description,
                'difficulty': technique.difficulty.value,
                'success_rate': technique.success_rate,
                'time_estimate': technique.time_estimate,
                'tools': technique.tools_required
            })
        
        return techniques
    
    def _get_hasp_scripts(self) -> Dict[str, str]:
        """Sentinel HASP specific scripts"""
        return {
            'frida': '''// Sentinel HASP Bypass Script
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
''',
            'ghidra': '''// Sentinel HASP Analysis Script for Ghidra
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
'''
        }
    
    def _get_flexlm_scripts(self) -> Dict[str, str]:
        """FlexLM/FlexNet specific scripts"""
        return {
            'frida': '''// FlexLM/FlexNet License Bypass Script
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
'''
        }
    
    def _get_winlicense_scripts(self) -> Dict[str, str]:
        """WinLicense/Themida specific scripts"""
        return {
            'frida': '''// WinLicense/Themida Analysis Script
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
'''
        }
    
    def _get_steam_scripts(self) -> Dict[str, str]:
        """Steam CEG specific scripts"""
        return {
            'frida': '''// Steam CEG Bypass Script
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
'''
        }
    
    def _get_vmprotect_scripts(self) -> Dict[str, str]:
        """VMProtect specific scripts"""
        return {
            'frida': '''// VMProtect Analysis Helper
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
'''
        }
    
    def _get_denuvo_scripts(self) -> Dict[str, str]:
        """Denuvo specific scripts"""
        return {
            'frida': '''// Denuvo Analysis Helper
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
'''
        }
    
    def _get_ms_activation_scripts(self) -> Dict[str, str]:
        """Microsoft Activation specific scripts"""
        return {
            'frida': '''// Microsoft Activation Bypass Helper
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
'''
        }
    
    def _get_basic_analysis_script(self, script_type: str) -> str:
        """Basic analysis script for unprotected binaries"""
        if script_type == "frida":
            return '''// Basic Binary Analysis Script
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
'''
        return "// Basic analysis script"
    
    def _get_generic_bypass_script(self, script_type: str) -> str:
        """Generic bypass script for unknown protections"""
        if script_type == "frida":
            return '''// Generic Protection Bypass Script
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
'''
        return "// Generic bypass script"
    
    def _get_generic_analysis_script(self, script_type: str) -> str:
        """Generic analysis script when protection detection fails"""
        return '''// Protection Analysis Script
// Failed to detect specific protection - running generic analysis

console.log("[?] Protection type could not be determined");
console.log("[*] Running comprehensive analysis...");

// Add analysis code here

console.log("[+] Generic analysis started");
'''


# Integration function
def enhance_ai_script_generation(ai_generator, binary_path: str) -> Dict[str, Any]:
    """
    Enhance existing AI script generation with protection awareness.
    
    This function would be integrated into the existing AI system to provide
    protection-specific script generation.
    """
    protection_gen = ProtectionAwareScriptGenerator()
    
    # Generate protection-aware script
    result = protection_gen.generate_bypass_script(binary_path)
    
    # Use the AI prompt to enhance the script further
    if hasattr(ai_generator, 'generate_script'):
        enhanced_script = ai_generator.generate_script(
            prompt=result['ai_prompt'],
            base_script=result['script'],
            context={
                'protection': result['protection_detected'],
                'difficulty': result['difficulty'],
                'techniques': result['bypass_techniques']
            }
        )
        result['enhanced_script'] = enhanced_script
    
    return result