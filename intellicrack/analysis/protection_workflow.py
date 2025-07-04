"""
Protection Analysis Workflow

Provides seamless, integrated workflows for protection analysis that hide
the complexity of multiple engines and present a unified experience.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

try:
    from ..llm.llm_manager import LLMManager
except ImportError:
    LLMManager = None

try:
    from ..protection.unified_protection_engine import UnifiedProtectionResult, get_unified_engine
except ImportError:
    UnifiedProtectionResult = None
    get_unified_engine = None

try:
    from ..scripting.frida_generator import FridaScriptGenerator
except ImportError:
    FridaScriptGenerator = None

try:
    from ..scripting.ghidra_generator import GhidraScriptGenerator
except ImportError:
    GhidraScriptGenerator = None

try:
    from ..utils.logger import get_logger
except ImportError:
    import logging

    def get_logger(name):
        return logging.getLogger(name)

logger = get_logger(__name__)


class WorkflowStep(Enum):
    """Workflow steps"""
    QUICK_SCAN = "quick_scan"
    DEEP_ANALYSIS = "deep_analysis"
    BYPASS_GENERATION = "bypass_generation"
    SCRIPT_CREATION = "script_creation"
    VALIDATION = "validation"


@dataclass
class WorkflowResult:
    """Result of a protection analysis workflow"""
    success: bool
    # UnifiedProtectionResult if available
    protection_analysis: Optional[Any] = None
    bypass_scripts: Dict[str, str] = None  # protection_name -> script
    recommendations: List[str] = None
    next_steps: List[str] = None
    confidence: float = 0.0


class ProtectionAnalysisWorkflow:
    """
    Manages the complete protection analysis workflow
    """

    def __init__(self):
        """Initialize workflow manager"""
        self.engine = get_unified_engine() if get_unified_engine else None
        self.frida_gen = FridaScriptGenerator() if FridaScriptGenerator else None
        self.ghidra_gen = GhidraScriptGenerator() if GhidraScriptGenerator else None
        self.llm_manager = LLMManager() if LLMManager else None

        # Workflow callbacks
        self.progress_callback: Optional[Callable[[str, int], None]] = None

    def analyze_and_bypass(self, file_path: str,
                           auto_generate_scripts: bool = True,
                           target_protections: Optional[List[str]] = None) -> WorkflowResult:
        """
        Complete workflow: analyze protections and generate bypass scripts

        Args:
            file_path: Path to binary file
            auto_generate_scripts: Automatically generate bypass scripts
            target_protections: Specific protections to target (None = all)

        Returns:
            Complete workflow result
        """
        result = WorkflowResult(success=False)

        try:
            # Step 1: Quick scan
            self._report_progress("Starting quick protection scan...", 10)
            quick_summary = self.engine.get_quick_summary(file_path)

            if not quick_summary['protected']:
                result.success = True
                result.recommendations = [
                    "No protections detected. The binary appears to be unprotected."]
                result.confidence = 100.0
                return result

            # Step 2: Deep analysis
            self._report_progress(
                f"Found {quick_summary['protection_count']} protections, performing deep analysis...", 30)
            analysis = self.engine.analyze(file_path, deep_scan=True)
            result.protection_analysis = analysis

            # Step 3: Generate bypass recommendations
            self._report_progress("Analyzing bypass strategies...", 50)
            recommendations = self._generate_recommendations(analysis)
            result.recommendations = recommendations

            # Step 4: Generate bypass scripts if requested
            if auto_generate_scripts and analysis.protections:
                self._report_progress("Generating bypass scripts...", 70)
                scripts = self._generate_bypass_scripts(
                    analysis, target_protections)
                result.bypass_scripts = scripts

            # Step 5: Generate next steps
            self._report_progress("Finalizing analysis...", 90)
            next_steps = self._generate_next_steps(analysis)
            result.next_steps = next_steps

            result.confidence = analysis.confidence_score
            result.success = True

            self._report_progress("Analysis complete!", 100)

        except Exception as e:
            logger.error(f"Workflow error: {e}")
            result.recommendations = [f"Analysis failed: {str(e)}"]

        return result

    def _generate_recommendations(self, analysis: UnifiedProtectionResult) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []

        # Check protection types
        protection_types = set(p['type'] for p in analysis.protections)

        # Priority recommendations
        if analysis.is_packed:
            recommendations.append(
                "🎯 Priority: Unpack the binary first. The file is packed which obscures the real code."
            )

        if analysis.has_anti_debug:
            recommendations.append(
                "⚠️ Anti-debugging detected. Use ScyllaHide or similar tools to bypass debugger checks."
            )

        if analysis.has_licensing:
            recommendations.append(
                "🔑 License protection found. Focus on identifying and patching license validation routines."
            )

        # Tool recommendations
        tools_needed = set()
        if 'packer' in protection_types:
            tools_needed.update(['x64dbg', 'Scylla', 'Process Dump'])
        if 'antidebug' in protection_types:
            tools_needed.update(['ScyllaHide', 'TitanHide'])
        if 'license' in protection_types:
            tools_needed.update(['IDA Pro', 'API Monitor'])

        if tools_needed:
            recommendations.append(
                f"📦 Recommended tools: {', '.join(sorted(tools_needed))}"
            )

        # Difficulty assessment
        if len(analysis.protections) > 3:
            recommendations.append(
                "⚡ Multiple protections detected. Consider tackling them one at a time, starting with the outermost layer."
            )

        # AI assistance
        if self.llm_manager.has_active_backend():
            recommendations.append(
                "🤖 AI assistance available. Use the Script Generation feature for automated bypass script creation."
            )

        return recommendations

    def _generate_bypass_scripts(self,
                                 analysis: UnifiedProtectionResult,
                                 target_protections: Optional[List[str]] = None) -> Dict[str, str]:
        """Generate bypass scripts for detected protections"""
        scripts = {}

        # Filter protections if targets specified
        protections = analysis.protections
        if target_protections:
            protections = [p for p in protections if p['name']
                           in target_protections]

        for protection in protections:
            try:
                # Generate Frida script for dynamic analysis
                script = self._generate_single_bypass_script(
                    analysis, protection)
                if script:
                    scripts[protection['name']] = script
            except Exception as e:
                logger.error(
                    f"Failed to generate script for {protection['name']}: {e}")

        return scripts

    def _generate_single_bypass_script(self,
                                       analysis: UnifiedProtectionResult,
                                       protection: Dict[str, Any]) -> Optional[str]:
        """Generate bypass script for a single protection"""
        context = {
            'file_path': analysis.file_path,
            'file_type': analysis.file_type,
            'architecture': analysis.architecture,
            'protection_name': protection['name'],
            'protection_type': protection['type'],
            'protection_details': protection.get('details', {}),
            'bypass_recommendations': protection.get('bypass_recommendations', [])
        }

        # Use AI if available
        if self.llm_manager.has_active_backend():
            try:
                prompt = self._build_bypass_prompt(context)
                response = self.llm_manager.generate(prompt)
                if response and response.get('success'):
                    return response.get('content', '')
            except Exception as e:
                logger.warning(f"AI generation failed: {e}")

        # Fallback to template-based generation
        protection_type = protection['type'].lower()

        if 'pack' in protection_type:
            return self._generate_unpacking_script(context)
        elif 'debug' in protection_type:
            return self._generate_antidebug_script(context)
        elif 'licens' in protection_type or 'dongle' in protection_type:
            return self._generate_license_bypass_script(context)
        else:
            return self._generate_generic_bypass_script(context)

    def _build_bypass_prompt(self, context: Dict[str, Any]) -> str:
        """Build prompt for AI bypass script generation"""
        return f"""Generate a Frida script to bypass the following protection:

Protection: {context['protection_name']}
Type: {context['protection_type']}
File Type: {context['file_type']}
Architecture: {context['architecture']}

Bypass recommendations:
{chr(10).join('- ' + rec for rec in context.get('bypass_recommendations', ['No specific recommendations']))}

Generate a practical, working Frida script that implements these bypass techniques.
Include comments explaining each bypass method used."""

    def _generate_unpacking_script(self, context: Dict[str, Any]) -> str:
        """Generate unpacking script"""
        return f"""// Unpacking script for {context['protection_name']}
// Generated by Intellicrack

// Hook common unpacking points
var targetModule = Process.enumerateModules()[0];

// Hook VirtualProtect to catch unpacking
Interceptor.attach(Module.findExportByName("kernel32.dll", "VirtualProtect"), {{
    onEnter: function(args) {{
        var address = args[0];
        var size = args[1].toInt32();
        var protection = args[2].toInt32();

        // Check if making memory executable
        if (protection & 0x20) {{ // PAGE_EXECUTE_READ
            console.log("[*] VirtualProtect making memory executable:");
            console.log("    Address: " + address);
            console.log("    Size: " + size);
            console.log("    Protection: 0x" + protection.toString(16));

            // This might be the unpacked code
            this.unpacked = {{
                address: address,
                size: size
            }};
        }}
    }},
    onLeave: function(retval) {{
        if (retval != 0 && this.unpacked) {{
            console.log("[+] Potential unpacked region at: " + this.unpacked.address);

            // Set breakpoint at potential OEP
            Process.setExceptionHandler(function(details) {{
                console.log("[!] Hit potential OEP at: " + details.address);
                return false; // Pass to debugger
            }});
        }}
    }}
}});

// Monitor for common packer signatures
var signatures = [
    {{pattern: "60 E8 00 00 00 00", name: "Generic PUSHAD"}},
    {{pattern: "EB 02 ?? ?? E8", name: "Jump obfuscation"}}
];

console.log("[*] Unpacking monitor active for {context['protection_name']}");
"""

    def _generate_antidebug_script(self, context: Dict[str, Any]) -> str:
        """Generate anti-debug bypass script"""
        return f"""// Anti-debug bypass script for {context['protection_name']}
// Generated by Intellicrack

// Bypass IsDebuggerPresent
Interceptor.attach(Module.findExportByName("kernel32.dll", "IsDebuggerPresent"), {{
    onLeave: function(retval) {{
        console.log("[*] IsDebuggerPresent called, returning FALSE");
        retval.replace(0);
    }}
}});

// Bypass CheckRemoteDebuggerPresent
Interceptor.attach(Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent"), {{
    onEnter: function(args) {{
        this.pDebuggerPresent = args[1];
    }},
    onLeave: function(retval) {{
        console.log("[*] CheckRemoteDebuggerPresent called, returning FALSE");
        this.pDebuggerPresent.writeU8(0);
        retval.replace(1);
    }}
}});

// Bypass NtQueryInformationProcess (ProcessDebugPort)
var ntdll = Process.getModuleByName("ntdll.dll");
var NtQueryInformationProcess = ntdll.getExportByName("NtQueryInformationProcess");

Interceptor.attach(NtQueryInformationProcess, {{
    onEnter: function(args) {{
        this.processInformationClass = args[1].toInt32();
        this.pProcessInformation = args[2];
    }},
    onLeave: function(retval) {{
        if (this.processInformationClass === 7) {{ // ProcessDebugPort
            console.log("[*] NtQueryInformationProcess(ProcessDebugPort) bypassed");
            this.pProcessInformation.writeU32(0);
        }}
    }}
}});

// Patch PEB.BeingDebugged flag
var peb = Process.enumerateModules()[0].base.add(ptr(Process.pointerSize === 8 ? 0x60 : 0x30)).readPointer();
var beingDebuggedOffset = Process.pointerSize === 8 ? 0x2 : 0x2;
peb.add(beingDebuggedOffset).writeU8(0);
console.log("[*] PEB.BeingDebugged patched");

console.log("[+] Anti-debug bypasses active for {context['protection_name']}");
"""

    def _generate_license_bypass_script(self, context: Dict[str, Any]) -> str:
        """Generate license bypass script"""
        return f"""// License bypass script for {context['protection_name']}
// Generated by Intellicrack

// Common license check patterns
var licensePatterns = [
    "license", "serial", "key", "registration", "activate",
    "trial", "demo", "expire", "validate", "check"
];

// Hook functions containing license keywords
Process.enumerateModules().forEach(function(module) {{
    module.enumerateExports().forEach(function(exp) {{
        var name = exp.name.toLowerCase();

        licensePatterns.forEach(function(pattern) {{
            if (name.indexOf(pattern) !== -1) {{
                console.log("[*] Hooking potential license function: " + exp.name);

                try {{
                    Interceptor.attach(exp.address, {{
                        onEnter: function(args) {{
                            console.log("[>] " + exp.name + " called");
                        }},
                        onLeave: function(retval) {{
                            // Common success values: 1, TRUE, S_OK (0)
                            if (retval.toInt32() === 0 || retval.toInt32() === -1) {{
                                console.log("[!] Forcing success for " + exp.name);
                                retval.replace(1);
                            }}
                        }}
                    }});
                }} catch(e) {{
                    // Some exports might not be functions
                }}
            }}
        }});
    }});
}});

// Hook registry access for license keys
var advapi32 = Process.getModuleByName("advapi32.dll");
if (advapi32) {{
    var RegQueryValueEx = advapi32.getExportByName("RegQueryValueExW");
    if (RegQueryValueEx) {{
        Interceptor.attach(RegQueryValueEx, {{
            onEnter: function(args) {{
                var valueName = args[1].readUtf16String();
                if (valueName && valueName.toLowerCase().indexOf("license") !== -1) {{
                    console.log("[*] Registry query for: " + valueName);
                    this.isLicenseQuery = true;
                }}
            }},
            onLeave: function(retval) {{
                if (this.isLicenseQuery && retval.toInt32() !== 0) {{
                    console.log("[!] Faking successful registry read");
                    retval.replace(0); // ERROR_SUCCESS
                }}
            }}
        }});
    }}
}}

console.log("[+] License bypass hooks active for {context['protection_name']}");
"""

    def _generate_generic_bypass_script(self, context: Dict[str, Any]) -> str:
        """Generate generic bypass script"""
        return f"""// Generic bypass script for {context['protection_name']}
// Generated by Intellicrack

// Monitor for protection checks
var protectionName = "{context['protection_name']}";
var targetModule = Process.enumerateModules()[0];

console.log("[*] Monitoring for " + protectionName + " protection checks");

// Hook common protection patterns
var patterns = [
    {{
        name: "Integrity Check",
        apis: ["GetModuleFileNameW", "CreateFileW", "ReadFile", "CryptHashData"]
    }},
    {{
        name: "Anti-Tamper",
        apis: ["VirtualQuery", "VirtualProtect", "GetModuleHandleW"]
    }}
];

patterns.forEach(function(pattern) {{
    console.log("[*] Setting up hooks for: " + pattern.name);

    pattern.apis.forEach(function(api) {{
        try {{
            var addr = Module.findExportByName(null, api);
            if (addr) {{
                Interceptor.attach(addr, {{
                    onEnter: function(args) {{
                        console.log("[>] " + api + " called");
                    }}
                }});
            }}
        }} catch(e) {{
            // API might not exist
        }}
    }});
}});

// Generic success forcing for unknown protection functions
targetModule.enumerateExports().forEach(function(exp) {{
    if (exp.name.toLowerCase().indexOf('check') !== -1 ||
        exp.name.toLowerCase().indexOf('verify') !== -1 ||
        exp.name.toLowerCase().indexOf('validate') !== -1) {{

        try {{
            Interceptor.attach(exp.address, {{
                onLeave: function(retval) {{
                    var result = retval.toInt32();
                    if (result === 0 || result === -1) {{
                        console.log("[!] Forcing success for: " + exp.name);
                        retval.replace(1);
                    }}
                }}
            }});
        }} catch(e) {{
            // Not a function
        }}
    }}
}});

console.log("[+] Generic bypass active for " + protectionName);
"""

    def _generate_next_steps(self, analysis: UnifiedProtectionResult) -> List[str]:
        """Generate next steps for the user"""
        steps = []

        if analysis.is_packed:
            steps.append(
                "1. Run the unpacking script in Frida to dump the unpacked code")
            steps.append("2. Use Scylla to rebuild the import table")
            steps.append("3. Re-analyze the unpacked binary")

        elif analysis.has_anti_debug:
            steps.append("1. Apply the anti-debug bypass script")
            steps.append("2. Attach debugger with ScyllaHide enabled")
            steps.append("3. Set breakpoints at key decision points")

        elif analysis.has_licensing:
            steps.append(
                "1. Run the license bypass script to identify check locations")
            steps.append("2. Analyze the validation logic in IDA Pro")
            steps.append("3. Patch the license checks or generate valid keys")

        else:
            steps.append("1. Load the binary in your preferred debugger")
            steps.append("2. Apply the generated bypass scripts")
            steps.append("3. Analyze the protection implementation")

        # Always add verification step
        steps.append(
            f"{len(steps) + 1}. Verify the bypass by testing the patched binary")

        return steps

    def _report_progress(self, message: str, percentage: int):
        """Report workflow progress"""
        if self.progress_callback is not None and callable(self.progress_callback):
            self.progress_callback(message, percentage)
        logger.debug(f"Workflow progress: {message} ({percentage}%)")


# Convenience functions
def quick_protection_analysis(file_path: str) -> Dict[str, Any]:
    """Quick protection analysis with summary"""
    workflow = ProtectionAnalysisWorkflow()
    result = workflow.analyze_and_bypass(
        file_path, auto_generate_scripts=False)

    if result.success and result.protection_analysis:
        return {
            'protected': bool(result.protection_analysis.protections),
            'protections': [p['name'] for p in result.protection_analysis.protections],
            'recommendations': result.recommendations,
            'confidence': result.confidence
        }
    else:
        return {
            'protected': False,
            'protections': [],
            'recommendations': result.recommendations or ["Analysis failed"],
            'confidence': 0.0
        }


def generate_protection_report(file_path: str) -> str:
    """Generate a comprehensive protection analysis report"""
    workflow = ProtectionAnalysisWorkflow()
    result = workflow.analyze_and_bypass(file_path)

    report = f"""# Protection Analysis Report

**File:** {os.path.basename(file_path)}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary

- **Protected:** {'Yes' if result.protection_analysis and result.protection_analysis.protections else 'No'}
- **Confidence:** {result.confidence:.0f}%

"""

    if result.protection_analysis and result.protection_analysis.protections:
        report += "## Detected Protections\n\n"
        for protection in result.protection_analysis.protections:
            report += f"### {protection['name']}\n\n"
            report += f"- **Type:** {protection['type']}\n"
            report += f"- **Confidence:** {protection.get('confidence', 0):.0f}%\n"
            report += f"- **Source:** {protection.get('source', 'Unknown')}\n\n"

    if result.recommendations:
        report += "## Recommendations\n\n"
        for rec in result.recommendations:
            report += f"- {rec}\n"
        report += "\n"

    if result.next_steps:
        report += "## Next Steps\n\n"
        for step in result.next_steps:
            report += f"- {step}\n"

    return report


# Import for datetime
