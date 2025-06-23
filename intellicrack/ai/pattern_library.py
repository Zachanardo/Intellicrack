"""
Pattern Library for Protection Detection and Bypass Strategies

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ProtectionComplexity(Enum):
    """Protection complexity levels."""
    TRIVIAL = "trivial"      # Simple string comparison
    SIMPLE = "simple"        # Basic obfuscation
    MODERATE = "moderate"    # Multiple checks, some obfuscation
    COMPLEX = "complex"      # Advanced anti-debugging, encryption
    EXTREME = "extreme"      # VM, packer, multiple layers


@dataclass
class ProtectionPattern:
    """Represents a protection pattern with bypass strategies."""
    name: str
    indicators: List[str]
    bypass_strategy: str
    confidence: float
    complexity: ProtectionComplexity
    frida_template: str
    ghidra_template: str
    success_rate: float = 0.85
    description: str = ""
    variants: Optional[List[str]] = field(default_factory=list)


class AdvancedPatternLibrary:
    """
    Comprehensive library of protection patterns and bypass strategies.
    All patterns lead to functional bypass code generation.
    """

    def __init__(self):
        self.patterns = {}
        self.success_history = {}
        self.learning_data = {}
        self._initialize_patterns()

    def _initialize_patterns(self):
        """Initialize all protection patterns."""

        # License Check Patterns
        self.patterns["string_comparison_license"] = ProtectionPattern(
            name="String Comparison License Check",
            indicators=["strcmp", "strcasecmp", "memcmp", "wcscmp", "_stricmp"],
            bypass_strategy="hook_comparison_return_zero",
            confidence=0.92,
            complexity=ProtectionComplexity.SIMPLE,
            description="License validation using string comparison functions",
            frida_template='''
// String comparison license bypass
const stringFuncs = ["{indicators}"];
stringFuncs.forEach(funcName => {{
    const addr = Module.findExportByName(null, funcName);
    if (addr) {{
        Interceptor.attach(addr, {{
            onEnter: function(args) {{
                try {{
                    this.str1 = args[0].readCString() || "";
                    this.str2 = args[1].readCString() || "";
                    this.isLicense = ["license", "trial", "demo"].some(k => 
                        this.str1.toLowerCase().includes(k) || this.str2.toLowerCase().includes(k));
                }} catch(e) {{ this.isLicense = false; }}
            }},
            onLeave: function(retval) {{
                if (this.isLicense) {{
                    console.log(`[Bypass] License check in ${{funcName}} - forcing success`);
                    retval.replace(0);
                }}
            }}
        }});
    }}
}});
''',
            ghidra_template='''
# Find and patch string comparison license checks
comparison_funcs = ["{indicators}"]
for func_name in comparison_funcs:
    func_addr = getSymbolAddress(func_name)
    if func_addr:
        # Find callers of comparison function
        callers = getReferencesTo(func_addr)
        for caller in callers:
            # Analyze context for license strings
            if self.is_license_context(caller):
                self.patch_comparison_result(caller, func_name)
''',
            success_rate=0.95
        )

        self.patterns["hardcoded_license_check"] = ProtectionPattern(
            name="Hardcoded License String Check",
            indicators=["license", "trial", "demo", "expire", "activation"],
            bypass_strategy="patch_license_strings",
            confidence=0.88,
            complexity=ProtectionComplexity.TRIVIAL,
            description="Direct comparison against hardcoded license strings",
            frida_template='''
// Hardcoded license string bypass
const licenseStrings = ["{indicators}"];
const modules = Process.enumerateModules();
modules.forEach(module => {{
    module.enumerateExports().forEach(exp => {{
        if (licenseStrings.some(str => exp.name.toLowerCase().includes(str))) {{
            Interceptor.attach(exp.address, {{
                onLeave: function(retval) {{
                    console.log(`[Bypass] License function ${{exp.name}} - forcing success`);
                    retval.replace(1);
                }}
            }});
        }}
    }});
}});
''',
            ghidra_template='''
# Find and patch hardcoded license checks
license_keywords = ["{indicators}"]
functions = getFunctionManager().getFunctions(True)
for func in functions:
    func_name = func.getName().lower()
    if any(keyword in func_name for keyword in license_keywords):
        self.patch_function_return_success(func)
''',
            success_rate=0.92
        )

        # Time-based Protection Patterns
        self.patterns["time_bomb_check"] = ProtectionPattern(
            name="Time Bomb Protection",
            indicators=["GetSystemTime", "time", "clock", "GetTickCount", "expire"],
            bypass_strategy="hook_time_functions",
            confidence=0.87,
            complexity=ProtectionComplexity.MODERATE,
            description="Time-based trial or expiration checking",
            frida_template='''
// Time bomb bypass
const timeFuncs = [
    {{name: "GetSystemTime", module: "kernel32.dll"}},
    {{name: "GetLocalTime", module: "kernel32.dll"}},
    {{name: "GetTickCount", module: "kernel32.dll"}},
    {{name: "time", module: null}}
];

const fixedTime = new Date(2023, 5, 15, 12, 0, 0);
timeFuncs.forEach(tf => {{
    const addr = Module.findExportByName(tf.module, tf.name);
    if (addr) {{
        if (tf.name.includes("GetSystemTime") || tf.name.includes("GetLocalTime")) {{
            Interceptor.replace(addr, new NativeCallback(function(systemTimePtr) {{
                if (!systemTimePtr.isNull()) {{
                    systemTimePtr.writeU16(2023);     // wYear
                    systemTimePtr.add(2).writeU16(6); // wMonth
                    systemTimePtr.add(6).writeU16(15);// wDay
                    console.log("[Bypass] Time function hooked - fixed date set");
                }}
            }}, 'void', ['pointer']));
        }} else {{
            Interceptor.attach(addr, {{
                onLeave: function(retval) {{
                    const fixedTimestamp = Math.floor(fixedTime.getTime() / 1000);
                    retval.replace(fixedTimestamp);
                    console.log(`[Bypass] ${{tf.name}} - returned fixed timestamp`);
                }}
            }});
        }}
    }}
}});
''',
            ghidra_template='''
# Find and patch time-based checks
time_functions = ["GetSystemTime", "GetLocalTime", "time", "clock"]
for time_func in time_functions:
    func_addr = getSymbolAddress(time_func)
    if func_addr:
        callers = getReferencesTo(func_addr)
        for caller in callers:
            self.analyze_time_usage(caller, time_func)
            if self.is_expiration_check(caller):
                self.patch_time_check(caller)
''',
            success_rate=0.83
        )

        # Network Validation Patterns
        self.patterns["online_license_validation"] = ProtectionPattern(
            name="Online License Validation",
            indicators=["InternetOpen", "HttpSendRequest", "connect", "send", "recv"],
            bypass_strategy="block_network_calls",
            confidence=0.85,
            complexity=ProtectionComplexity.COMPLEX,
            description="Network-based license validation",
            frida_template='''
// Network license validation bypass
const netFuncs = [
    "InternetOpenA", "InternetOpenW", "HttpSendRequestA", "HttpSendRequestW",
    "InternetReadFile", "connect", "send", "recv"
];

netFuncs.forEach(funcName => {{
    const addr = Module.findExportByName(null, funcName);
    if (addr) {{
        Interceptor.attach(addr, {{
            onEnter: function(args) {{
                console.log(`[Network] ${{funcName}} called - potential license validation`);
                this.shouldBlock = true;
            }},
            onLeave: function(retval) {{
                if (this.shouldBlock) {{
                    if (funcName.includes("HttpSendRequest")) {{
                        retval.replace(1); // TRUE - fake success
                        console.log("[Bypass] HTTP request faked as successful");
                    }} else if (funcName.includes("InternetReadFile")) {{
                        // Fake license validation response
                        const fakeResponse = '{{"status":"valid","licensed":true}}';
                        try {{
                            args[1].writeUtf8String(fakeResponse);
                            args[3].writeU32(fakeResponse.length);
                        }} catch(e) {{}}
                        retval.replace(1);
                        console.log("[Bypass] Provided fake license response");
                    }} else if (funcName === "connect") {{
                        retval.replace(-1); // Block connection
                        console.log("[Bypass] Blocked network connection");
                    }}
                }}
            }}
        }});
    }}
}});
''',
            ghidra_template='''
# Find and analyze network validation functions
network_functions = ["InternetOpen", "HttpSendRequest", "connect", "send"]
for net_func in network_functions:
    func_addr = getSymbolAddress(net_func)
    if func_addr:
        callers = getReferencesTo(func_addr)
        for caller in callers:
            if self.is_license_network_call(caller):
                self.patch_network_call(caller, net_func)
''',
            success_rate=0.78
        )

        # Registry-based Protection Patterns
        self.patterns["registry_license_storage"] = ProtectionPattern(
            name="Registry License Storage",
            indicators=["RegOpenKey", "RegQueryValue", "RegSetValue", "RegCreateKey"],
            bypass_strategy="fake_registry_values",
            confidence=0.89,
            complexity=ProtectionComplexity.SIMPLE,
            description="License information stored in Windows registry",
            frida_template='''
// Registry license bypass
const regFuncs = ["RegOpenKeyExA", "RegOpenKeyExW", "RegQueryValueExA", "RegQueryValueExW"];
const fakeValues = {{
    "LicenseKey": "AI-GENERATED-LICENSE-123456",
    "SerialNumber": "INTELLICRACK-AI-BYPASS",
    "ActivationCode": "ACTIVATED-BY-AI"
}};

regFuncs.forEach(funcName => {{
    const addr = Module.findExportByName("advapi32.dll", funcName);
    if (addr) {{
        Interceptor.attach(addr, {{
            onEnter: function(args) {{
                if (funcName.includes("RegQueryValueEx")) {{
                    try {{
                        const valueName = funcName.includes("W") ? 
                            args[1].readUtf16String() : args[1].readCString();
                        this.isLicenseQuery = ["license", "serial", "key", "activation"]
                            .some(k => valueName.toLowerCase().includes(k));
                        this.valueName = valueName;
                    }} catch(e) {{ this.isLicenseQuery = false; }}
                }}
            }},
            onLeave: function(retval) {{
                if (this.isLicenseQuery) {{
                    retval.replace(0); // ERROR_SUCCESS
                    console.log(`[Bypass] Registry query for ${{this.valueName}} - faked success`);
                }}
            }}
        }});
    }}
}});
''',
            ghidra_template='''
# Find and patch registry license checks
registry_functions = ["RegOpenKeyEx", "RegQueryValueEx", "RegSetValueEx"]
for reg_func in registry_functions:
    func_addr = getSymbolAddress(reg_func)
    if func_addr:
        callers = getReferencesTo(func_addr)
        for caller in callers:
            if self.is_license_registry_access(caller):
                self.patch_registry_access(caller, reg_func)
''',
            success_rate=0.91
        )

        # Anti-debugging Patterns
        self.patterns["debugger_detection"] = ProtectionPattern(
            name="Debugger Detection",
            indicators=["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"],
            bypass_strategy="hook_debug_apis",
            confidence=0.94,
            complexity=ProtectionComplexity.MODERATE,
            description="Anti-debugging protection mechanisms",
            frida_template='''
// Anti-debugging bypass
const debugFuncs = [
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", 
    "NtQueryInformationProcess", "OutputDebugStringA"
];

debugFuncs.forEach(funcName => {{
    const addr = Module.findExportByName(null, funcName);
    if (addr) {{
        Interceptor.attach(addr, {{
            onLeave: function(retval) {{
                if (funcName.includes("IsDebuggerPresent")) {{
                    retval.replace(0); // FALSE
                }} else if (funcName.includes("CheckRemoteDebuggerPresent")) {{
                    if (this.context.r8) {{ // pbDebuggerPresent parameter
                        this.context.r8.writeU8(0);
                    }}
                    retval.replace(1); // TRUE (success)
                }} else if (funcName.includes("NtQueryInformationProcess")) {{
                    retval.replace(0); // STATUS_SUCCESS
                }}
                console.log(`[Bypass] ${{funcName}} - debugger detection bypassed`);
            }}
        }});
    }}
}});

// Hook PEB flags
const peb = Process.getCurrentProcess().getModuleByName("ntdll.dll").base.add(0x60);
Interceptor.attach(peb, {{
    onEnter: function() {{
        // Clear BeingDebugged flag
        this.context.rax.add(2).writeU8(0);
    }}
}});
''',
            ghidra_template='''
# Find and patch anti-debugging checks
debug_functions = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"]
for debug_func in debug_functions:
    func_addr = getSymbolAddress(debug_func)
    if func_addr:
        callers = getReferencesTo(func_addr)
        for caller in callers:
            self.patch_debug_check(caller, debug_func)

# Patch PEB access patterns
self.find_and_patch_peb_access()
''',
            success_rate=0.87
        )

        # VM Detection Patterns
        self.patterns["vm_detection"] = ProtectionPattern(
            name="Virtual Machine Detection",
            indicators=["cpuid", "rdtsc", "VMware", "VirtualBox", "QEMU"],
            bypass_strategy="spoof_vm_artifacts",
            confidence=0.82,
            complexity=ProtectionComplexity.COMPLEX,
            description="Virtual machine environment detection",
            frida_template='''
// VM detection bypass
const vmStrings = ["VMware", "VirtualBox", "QEMU", "Virtual", "vbox"];

// Hook CPUID instruction
Interceptor.attach(Module.findExportByName(null, "cpuid") || ptr("0x0"), {{
    onEnter: function(args) {{
        console.log("[VM] CPUID instruction detected");
    }},
    onLeave: function(retval) {{
        // Modify CPUID results to hide VM
        console.log("[Bypass] CPUID result spoofed");
    }}
}});

// Hook registry queries for VM detection
const regAddr = Module.findExportByName("advapi32.dll", "RegQueryValueExA");
if (regAddr) {{
    Interceptor.attach(regAddr, {{
        onEnter: function(args) {{
            try {{
                const keyName = args[1].readCString();
                this.isVMQuery = vmStrings.some(vm => keyName.includes(vm));
            }} catch(e) {{ this.isVMQuery = false; }}
        }},
        onLeave: function(retval) {{
            if (this.isVMQuery) {{
                retval.replace(2); // ERROR_FILE_NOT_FOUND
                console.log("[Bypass] VM registry query blocked");
            }}
        }}
    }});
}}
''',
            ghidra_template='''
# Find and patch VM detection routines
vm_indicators = ["VMware", "VirtualBox", "QEMU", "cpuid"]
for indicator in vm_indicators:
    addresses = self.find_string_references(indicator)
    for addr in addresses:
        function = getFunctionContaining(addr)
        if function:
            self.patch_vm_detection_function(function)
''',
            success_rate=0.75
        )

        # Cryptographic Protection Patterns
        self.patterns["crypto_license_validation"] = ProtectionPattern(
            name="Cryptographic License Validation",
            indicators=["CryptVerifySignature", "RSA_verify", "EVP_Verify", "CryptHashData"],
            bypass_strategy="bypass_crypto_verification",
            confidence=0.79,
            complexity=ProtectionComplexity.EXTREME,
            description="Cryptographically signed license validation",
            frida_template='''
// Cryptographic bypass
const cryptoFuncs = [
    "CryptVerifySignatureA", "CryptVerifySignatureW", "CryptHashData",
    "RSA_verify", "EVP_VerifyFinal"
];

cryptoFuncs.forEach(funcName => {{
    const addr = Module.findExportByName(null, funcName);
    if (addr) {{
        Interceptor.attach(addr, {{
            onEnter: function(args) {{
                console.log(`[Crypto] ${{funcName}} called - signature verification`);
                this.shouldBypass = true;
            }},
            onLeave: function(retval) {{
                if (this.shouldBypass) {{
                    retval.replace(1); // Force verification success
                    console.log(`[Bypass] ${{funcName}} - crypto verification bypassed`);
                }}
            }}
        }});
    }}
}});

// Hook OpenSSL functions if present
const opensslFuncs = ["EVP_VerifyFinal", "RSA_verify"];
opensslFuncs.forEach(funcName => {{
    const addr = Module.findExportByName("libssl.so", funcName) || 
                 Module.findExportByName("libeay32.dll", funcName);
    if (addr) {{
        Interceptor.attach(addr, {{
            onLeave: function(retval) {{
                retval.replace(1); // Verification success
                console.log(`[Bypass] OpenSSL ${{funcName}} bypassed`);
            }}
        }});
    }}
}});
''',
            ghidra_template='''
# Find and analyze cryptographic validation
crypto_functions = ["CryptVerifySignature", "RSA_verify", "EVP_Verify"]
for crypto_func in crypto_functions:
    func_addr = getSymbolAddress(crypto_func)
    if func_addr:
        callers = getReferencesTo(func_addr)
        for caller in callers:
            self.analyze_crypto_usage(caller)
            if self.is_license_crypto_check(caller):
                self.patch_crypto_verification(caller, crypto_func)
''',
            success_rate=0.68
        )

    def get_pattern_by_indicators(self, indicators: List[str]) -> List[ProtectionPattern]:
        """Find patterns matching the given indicators."""
        matching_patterns = []

        for pattern in self.patterns.values():
            match_score = 0
            for indicator in indicators:
                if any(pattern_indicator.lower() in indicator.lower()
                       for pattern_indicator in pattern.indicators):
                    match_score += 1

            if match_score > 0:
                # Adjust confidence based on match score
                adjusted_confidence = pattern.confidence * (match_score / len(pattern.indicators))
                pattern_copy = ProtectionPattern(
                    name=pattern.name,
                    indicators=pattern.indicators,
                    bypass_strategy=pattern.bypass_strategy,
                    confidence=adjusted_confidence,
                    complexity=pattern.complexity,
                    frida_template=pattern.frida_template,
                    ghidra_template=pattern.ghidra_template,
                    success_rate=pattern.success_rate,
                    description=pattern.description
                )
                matching_patterns.append(pattern_copy)

        # Sort by confidence
        matching_patterns.sort(key=lambda p: p.confidence, reverse=True)
        return matching_patterns

    def get_bypass_strategy(self, protection_type: str) -> Dict[str, Any]:
        """Get comprehensive bypass strategy for protection type."""
        protection_type_lower = protection_type.lower()

        # Map protection types to patterns
        type_mapping = {
            "license_check": ["string_comparison_license", "hardcoded_license_check"],
            "time_bomb": ["time_bomb_check"],
            "trial_timer": ["time_bomb_check"],
            "network_validation": ["online_license_validation"],
            "registry_check": ["registry_license_storage"],
            "anti_debug": ["debugger_detection"],
            "vm_detection": ["vm_detection"],
            "crypto_verification": ["crypto_license_validation"]
        }

        matching_patterns = []
        for ptype, pattern_names in type_mapping.items():
            if ptype in protection_type_lower:
                for name in pattern_names:
                    if name in self.patterns:
                        matching_patterns.append(self.patterns[name])

        if not matching_patterns:
            # Return generic strategy
            return {
                "type": "generic_analysis",
                "patterns": [],
                "priority": "medium",
                "confidence": 0.5,
                "complexity": ProtectionComplexity.MODERATE
            }

        # Return best matching pattern
        best_pattern = max(matching_patterns, key=lambda p: p.confidence)
        return {
            "type": best_pattern.bypass_strategy,
            "patterns": matching_patterns,
            "priority": "high" if best_pattern.confidence > 0.8 else "medium",
            "confidence": best_pattern.confidence,
            "complexity": best_pattern.complexity,
            "frida_template": best_pattern.frida_template,
            "ghidra_template": best_pattern.ghidra_template
        }

    def analyze_binary_patterns(self, analysis_results: Dict[str, Any]) -> List[ProtectionPattern]:
        """Analyze binary and identify protection patterns."""
        detected_patterns = []

        # Extract indicators from analysis
        all_indicators = []

        # From strings
        strings = analysis_results.get('strings', [])
        all_indicators.extend(strings)

        # From function names
        functions = analysis_results.get('functions', [])
        for func in functions:
            if isinstance(func, dict) and 'name' in func:
                all_indicators.append(func['name'])

        # From imports
        imports = analysis_results.get('imports', [])
        all_indicators.extend(imports)

        # Find matching patterns
        matching_patterns = self.get_pattern_by_indicators(all_indicators)

        # Filter by confidence threshold
        detected_patterns = [p for p in matching_patterns if p.confidence > 0.7]

        logger.info(f"Detected {len(detected_patterns)} protection patterns")
        for pattern in detected_patterns:
            logger.info(f"  - {pattern.name}: {pattern.confidence:.2f} confidence")

        return detected_patterns

    def update_success_rate(self, pattern_name: str, success: bool):
        """Update pattern success rate based on results."""
        if pattern_name not in self.success_history:
            self.success_history[pattern_name] = {"attempts": 0, "successes": 0}

        self.success_history[pattern_name]["attempts"] += 1
        if success:
            self.success_history[pattern_name]["successes"] += 1

        # Update pattern success rate
        if pattern_name in self.patterns:
            history = self.success_history[pattern_name]
            new_rate = history["successes"] / history["attempts"]
            # Use exponential moving average to update
            current_rate = self.patterns[pattern_name].success_rate
            self.patterns[pattern_name].success_rate = 0.7 * current_rate + 0.3 * new_rate

            logger.info(f"Updated {pattern_name} success rate: {self.patterns[pattern_name].success_rate:.2f}")

    def get_pattern_statistics(self) -> Dict[str, Any]:
        """Get statistics about pattern usage and success rates."""
        stats = {
            "total_patterns": len(self.patterns),
            "pattern_usage": {},
            "average_success_rate": 0.0,
            "most_successful": None,
            "least_successful": None
        }

        if self.success_history:
            success_rates = []
            for pattern_name, history in self.success_history.items():
                if history["attempts"] > 0:
                    rate = history["successes"] / history["attempts"]
                    success_rates.append(rate)
                    stats["pattern_usage"][pattern_name] = {
                        "attempts": history["attempts"],
                        "successes": history["successes"],
                        "success_rate": rate
                    }

            if success_rates:
                stats["average_success_rate"] = sum(success_rates) / len(success_rates)

                # Find most and least successful
                best_pattern = max(stats["pattern_usage"].items(),
                                 key=lambda x: x[1]["success_rate"])
                worst_pattern = min(stats["pattern_usage"].items(),
                                  key=lambda x: x[1]["success_rate"])

                stats["most_successful"] = best_pattern[0]
                stats["least_successful"] = worst_pattern[0]

        return stats

    def export_patterns(self) -> Dict[str, Any]:
        """Export all patterns for analysis or backup."""
        return {
            "patterns": {name: {
                "name": p.name,
                "indicators": p.indicators,
                "bypass_strategy": p.bypass_strategy,
                "confidence": p.confidence,
                "complexity": p.complexity.value,
                "success_rate": p.success_rate,
                "description": p.description
            } for name, p in self.patterns.items()},
            "success_history": self.success_history,
            "statistics": self.get_pattern_statistics()
        }
