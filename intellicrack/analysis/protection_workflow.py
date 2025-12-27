"""Protection Analysis Workflow.

Provides seamless, integrated workflows for protection analysis that hide
the complexity of multiple engines and present a unified experience.

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

import os
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, TypeVar


if TYPE_CHECKING:
    from collections.abc import Callable

C = TypeVar("C", bound=type[Any])

try:
    from ..llm.llm_manager import LLMManager

    LLM_MANAGER_TYPE: type[LLMManager] | None = LLMManager
except ImportError:
    LLM_MANAGER_TYPE = None

try:
    from collections.abc import Callable as CallableType

    from ..protection.unified_protection_engine import UnifiedProtectionEngine, UnifiedProtectionResult, get_unified_engine

    UNIFIED_PROTECTION_RESULT_TYPE: type[UnifiedProtectionResult] | None = UnifiedProtectionResult
    GET_UNIFIED_ENGINE_FUNC: CallableType[[], UnifiedProtectionEngine] | None = get_unified_engine
except ImportError:
    UNIFIED_PROTECTION_RESULT_TYPE = None
    GET_UNIFIED_ENGINE_FUNC = None

try:
    from collections.abc import Callable as CallableType

    from ..core.analysis.yara_pattern_engine import YaraPatternEngine, get_yara_engine, is_yara_available

    GET_YARA_ENGINE_FUNC: CallableType[[], YaraPatternEngine | None] | None = get_yara_engine
    IS_YARA_AVAILABLE_FUNC: CallableType[[], bool] | None = is_yara_available
except ImportError:
    GET_YARA_ENGINE_FUNC = None
    IS_YARA_AVAILABLE_FUNC = None

try:
    from collections.abc import Callable as CallableType

    from ..core.analysis.firmware_analyzer import FirmwareAnalyzer, get_firmware_analyzer, is_binwalk_available

    GET_FIRMWARE_ANALYZER_FUNC: CallableType[[], FirmwareAnalyzer | None] | None = get_firmware_analyzer
    IS_BINWALK_AVAILABLE_FUNC: CallableType[[], bool] | None = is_binwalk_available
except ImportError:
    GET_FIRMWARE_ANALYZER_FUNC = None
    IS_BINWALK_AVAILABLE_FUNC = None

try:
    from collections.abc import Callable as CallableType

    from ..core.analysis.memory_forensics_engine import MemoryForensicsEngine, get_memory_forensics_engine, is_volatility3_available

    GET_MEMORY_FORENSICS_ENGINE_FUNC: CallableType[[], MemoryForensicsEngine | None] | None = get_memory_forensics_engine
    IS_VOLATILITY3_AVAILABLE_FUNC: CallableType[[], bool] | None = is_volatility3_available
except ImportError:
    GET_MEMORY_FORENSICS_ENGINE_FUNC = None
    IS_VOLATILITY3_AVAILABLE_FUNC = None

try:
    from ..scripting.frida_generator import FridaScriptGenerator

    FRIDA_SCRIPT_GENERATOR_TYPE: type[FridaScriptGenerator] | None = FridaScriptGenerator
except ImportError:
    FRIDA_SCRIPT_GENERATOR_TYPE = None

try:
    from ..scripting.ghidra_generator import GhidraScriptGenerator

    GHIDRA_SCRIPT_GENERATOR_TYPE: type[GhidraScriptGenerator] | None = GhidraScriptGenerator
except ImportError:
    GHIDRA_SCRIPT_GENERATOR_TYPE = None

try:
    from ..utils.logger import get_logger, log_all_methods
except ImportError:
    import logging

    def get_logger(name: str | None = None) -> logging.Logger:
        """Create a logger instance with the given name.

        Args:
            name: The name for the logger instance

        Returns:
            A logging.Logger instance

        """
        return logging.getLogger(name)

    def log_all_methods[C: type[Any]](cls: C) -> C:
        """Fallback decorator that does nothing.

        Args:
            cls: The class to decorate

        Returns:
            The unmodified class

        """
        return cls


logger = get_logger(__name__)


class WorkflowStep(Enum):
    """Workflow steps."""

    QUICK_SCAN = "quick_scan"
    DEEP_ANALYSIS = "deep_analysis"
    BYPASS_GENERATION = "bypass_generation"
    SCRIPT_CREATION = "script_creation"
    VALIDATION = "validation"


@dataclass
class WorkflowResult:
    """Result of a protection analysis workflow."""

    success: bool
    protection_analysis: Any | None = None
    bypass_scripts: dict[str, str] | None = None
    recommendations: list[str] | None = None
    next_steps: list[str] | None = None
    confidence: float = 0.0


@log_all_methods
class ProtectionAnalysisWorkflow:
    """Manages the complete protection analysis workflow."""

    def __init__(self) -> None:
        """Initialize workflow manager."""
        self.engine = GET_UNIFIED_ENGINE_FUNC() if GET_UNIFIED_ENGINE_FUNC is not None else None
        self.frida_gen = FRIDA_SCRIPT_GENERATOR_TYPE() if FRIDA_SCRIPT_GENERATOR_TYPE is not None else None
        self.ghidra_gen = GHIDRA_SCRIPT_GENERATOR_TYPE() if GHIDRA_SCRIPT_GENERATOR_TYPE is not None else None
        self.llm_manager = LLM_MANAGER_TYPE() if LLM_MANAGER_TYPE is not None else None

        # Supplemental analysis engines
        self.yara_engine = GET_YARA_ENGINE_FUNC() if GET_YARA_ENGINE_FUNC is not None else None
        self.firmware_analyzer = GET_FIRMWARE_ANALYZER_FUNC() if GET_FIRMWARE_ANALYZER_FUNC is not None else None
        self.memory_forensics = GET_MEMORY_FORENSICS_ENGINE_FUNC() if GET_MEMORY_FORENSICS_ENGINE_FUNC is not None else None

        # Workflow callbacks
        self.progress_callback: Callable[[str, int], None] | None = None

    def analyze_and_bypass(
        self,
        file_path: str,
        auto_generate_scripts: bool = True,
        target_protections: list[str] | None = None,
    ) -> WorkflowResult:
        """Complete workflow: analyze protections and generate bypass scripts.

        Args:
            file_path: Path to binary file
            auto_generate_scripts: Automatically generate bypass scripts
            target_protections: Specific protections to target (None = all)

        Returns:
            Complete workflow result

        """
        result = WorkflowResult(success=False)

        try:
            if self.engine is None:
                result.recommendations = ["Unified protection engine not available."]
                return result

            # Step 1: Quick scan
            self._report_progress("Starting quick protection scan...", 10)
            quick_summary = self.engine.get_quick_summary(file_path)

            if not quick_summary.get("protected", False):
                result.success = True
                result.recommendations = ["No protections detected. The binary appears to be unprotected."]
                result.confidence = 100.0
                return result

            # Step 2: Deep analysis
            protection_count = quick_summary.get("protection_count", 0)
            self._report_progress(
                f"Found {protection_count} protections, performing deep analysis...",
                30,
            )
            analysis = self.engine.analyze(file_path, deep_scan=True)
            result.protection_analysis = analysis

            # Step 2.5: Supplemental analysis with YARA, Binwalk, and Volatility3
            self._report_progress("Running supplemental analysis engines...", 40)
            supplemental_data = self._run_supplemental_analysis(file_path)
            if supplemental_data and hasattr(analysis, "supplemental_data"):
                analysis.supplemental_data = supplemental_data

            # Step 3: Generate bypass recommendations
            self._report_progress("Analyzing bypass strategies...", 55)
            recommendations = self._generate_recommendations(analysis)
            result.recommendations = recommendations

            # Step 4: Generate bypass scripts if requested
            protections = getattr(analysis, "protections", [])
            if auto_generate_scripts and protections:
                self._report_progress("Generating bypass scripts...", 75)
                scripts = self._generate_bypass_scripts(analysis, target_protections)
                result.bypass_scripts = scripts

            # Step 5: Generate next steps
            self._report_progress("Finalizing analysis...", 90)
            next_steps = self._generate_next_steps(analysis)
            result.next_steps = next_steps

            confidence_score = getattr(analysis, "confidence_score", 0.0)
            result.confidence = confidence_score
            result.success = True

            self._report_progress("Analysis complete!", 100)

        except Exception as e:
            logger.exception("Workflow error: %s", e)
            result.recommendations = [f"Analysis failed: {e!s}"]

        return result

    def _run_supplemental_analysis(self, file_path: str) -> dict[str, Any]:
        """Run supplemental analysis with YARA, Binwalk, and Volatility3.

        Args:
            file_path: Path to the binary file

        Returns:
            Dictionary containing supplemental analysis results

        """
        supplemental_data = {}

        try:
            # YARA pattern analysis
            if self.yara_engine and IS_YARA_AVAILABLE_FUNC is not None and IS_YARA_AVAILABLE_FUNC():
                logger.debug("Running YARA pattern analysis...")
                yara_result = self.yara_engine.scan_file(file_path, timeout=30)
                if not yara_result.error:
                    yara_supplemental = self.yara_engine.generate_icp_supplemental_data(yara_result)
                    supplemental_data["yara_analysis"] = {
                        "matches_found": len(yara_result.matches),
                        "total_rules": yara_result.total_rules,
                        "scan_time": yara_result.scan_time,
                        "supplemental_data": yara_supplemental,
                    }
                    logger.debug("YARA analysis complete: %d matches found", len(yara_result.matches))
                else:
                    logger.warning("YARA analysis failed: %s", yara_result.error)

        except Exception as e:
            logger.exception("YARA analysis error: %s", e)

        try:
            # Binwalk firmware analysis
            if self.firmware_analyzer and IS_BINWALK_AVAILABLE_FUNC is not None and IS_BINWALK_AVAILABLE_FUNC():
                logger.debug("Running Binwalk firmware analysis...")
                firmware_result = self.firmware_analyzer.analyze_firmware(
                    file_path=file_path,
                    extract_files=False,  # Don't extract for workflow performance
                    analyze_security=True,
                    extraction_depth=1,
                )
                if not firmware_result.error:
                    firmware_supplemental = self.firmware_analyzer.generate_icp_supplemental_data(firmware_result)
                    supplemental_data["firmware_analysis"] = {
                        "signatures_found": len(firmware_result.signatures),
                        "security_findings": len(firmware_result.security_findings),
                        "firmware_type": firmware_result.firmware_type.value,
                        "analysis_time": firmware_result.analysis_time,
                        "supplemental_data": firmware_supplemental,
                    }
                    logger.debug("Binwalk analysis complete: %d signatures found", len(firmware_result.signatures))
                else:
                    logger.warning("Binwalk analysis failed: %s", firmware_result.error)

        except Exception as e:
            logger.exception("Binwalk analysis error: %s", e)

        try:
            # Volatility3 memory forensics (for memory dumps)
            if (
                self.memory_forensics
                and IS_VOLATILITY3_AVAILABLE_FUNC is not None
                and IS_VOLATILITY3_AVAILABLE_FUNC()
                and self._is_memory_dump(file_path)
            ):
                logger.debug("Running Volatility3 memory forensics...")
                memory_result = self.memory_forensics.analyze_memory_dump(
                    dump_path=file_path,
                    deep_analysis=False,  # Quick analysis for workflow performance
                )
                if not memory_result.error:
                    memory_supplemental = self.memory_forensics.generate_icp_supplemental_data(memory_result)
                    supplemental_data["memory_analysis"] = {
                        "artifacts_found": sum(memory_result.artifacts_found.values()),
                        "analysis_profile": memory_result.analysis_profile,
                        "has_suspicious_activity": memory_result.has_suspicious_activity,
                        "analysis_time": memory_result.analysis_time,
                        "supplemental_data": memory_supplemental,
                    }
                    logger.debug("Volatility3 analysis complete: %d artifacts found", sum(memory_result.artifacts_found.values()))
                else:
                    logger.warning("Volatility3 analysis failed: %s", memory_result.error)

        except Exception as e:
            logger.exception("Volatility3 analysis error: %s", e)

        if supplemental_data:
            logger.info("Supplemental analysis complete with %d engines", len(supplemental_data))
        else:
            logger.debug("No supplemental analysis results available")

        return supplemental_data

    def _is_memory_dump(self, file_path: str) -> bool:
        """Check if file appears to be a memory dump.

        Args:
            file_path: Path to file

        Returns:
            True if file appears to be a memory dump

        """
        try:
            # Check file extension
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in [".dmp", ".vmem", ".raw", ".mem", ".dd"]:
                return True

            # Check file size (memory dumps are typically large)
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:  # > 100MB
                # Check for memory dump signatures
                with open(file_path, "rb") as f:
                    header = f.read(4096)
                    # Look for common memory dump patterns
                    if b"PAGEDUMP" in header or b"PAGEDU64" in header:
                        return True
                    # Windows crash dump signatures
                    if header.startswith(b"PAGEDUMP") or header.startswith(b"PAGE"):
                        return True

            return False

        except Exception as e:
            logger.debug("Memory dump detection error: %s", e)
            return False

    def _generate_recommendations(self, analysis: Any) -> list[str]:
        """Generate actionable recommendations based on analysis."""
        recommendations: list[str] = []

        # Check protection types
        protections = getattr(analysis, "protections", [])
        protection_types = {p.get("type", "") for p in protections}

        # Priority recommendations
        is_packed = getattr(analysis, "is_packed", False)
        has_anti_debug = getattr(analysis, "has_anti_debug", False)
        has_licensing = getattr(analysis, "has_licensing", False)

        if is_packed:
            recommendations.append(
                " Priority: Unpack the binary first. The file is packed which obscures the real code.",
            )

        if has_anti_debug:
            recommendations.append(
                "WARNING️ Anti-debugging detected. Use ScyllaHide or similar tools to bypass debugger checks.",
            )

        if has_licensing:
            recommendations.append(
                "🔑 License protection found. Focus on identifying and patching license validation routines.",
            )

        # Tool recommendations
        tools_needed: set[str] = set()
        if "packer" in protection_types:
            tools_needed.update(["x64dbg", "Scylla", "Process Dump"])
        if "antidebug" in protection_types:
            tools_needed.update(["ScyllaHide", "TitanHide"])
        if "license" in protection_types:
            tools_needed.update(["Ghidra", "API Monitor"])

        if tools_needed:
            recommendations.append(
                f" Recommended tools: {', '.join(sorted(tools_needed))}",
            )

        # Difficulty assessment
        if len(protections) > 3:
            recommendations.append(
                "[FAST] Multiple protections detected. Consider tackling them one at a time, starting with the outermost layer.",
            )

        # Supplemental analysis recommendations
        if hasattr(analysis, "supplemental_data") and analysis.supplemental_data:
            supplemental_recs = self._generate_supplemental_recommendations(analysis.supplemental_data)
            recommendations.extend(supplemental_recs)

        # AI assistance
        if self.llm_manager is not None and hasattr(self.llm_manager, "has_active_backend") and self.llm_manager.has_active_backend():
            recommendations.append(
                " AI assistance available. Use the Script Generation feature for automated bypass script creation.",
            )

        return recommendations

    def _generate_supplemental_recommendations(self, supplemental_data: dict[str, Any]) -> list[str]:
        """Generate recommendations based on supplemental analysis results.

        Args:
            supplemental_data: Results from YARA, Binwalk, and Volatility3

        Returns:
            List of recommendations based on supplemental findings

        """
        recommendations = []

        # YARA pattern analysis recommendations
        if "yara_analysis" in supplemental_data:
            yara_data = supplemental_data["yara_analysis"]
            matches_found = yara_data.get("matches_found", 0)

            if matches_found > 0:
                recommendations.append(
                    f" YARA detected {matches_found} protection patterns. Check for packing, anti-debug, and licensing signatures.",
                )

                # Look for specific pattern types in supplemental data
                yara_supplemental = yara_data.get("supplemental_data", {})
                protection_categories = yara_supplemental.get("protection_categories", {})

                if protection_categories.get("packer", 0) > 0:
                    recommendations.append(
                        " YARA identified packer signatures. Consider unpacking before further analysis.",
                    )
                if protection_categories.get("anti_debug", 0) > 0:
                    recommendations.append(
                        "🛡️ YARA found anti-debug patterns. Use stealth debugging techniques.",
                    )
                if protection_categories.get("licensing", 0) > 0:
                    recommendations.append(
                        "🔑 YARA detected licensing patterns. Focus on license validation bypass.",
                    )
            else:
                recommendations.append(
                    "OK YARA found no known protection patterns. Binary may use custom or unknown protections.",
                )

        # Binwalk firmware analysis recommendations
        if "firmware_analysis" in supplemental_data:
            firmware_data = supplemental_data["firmware_analysis"]
            signatures_found = firmware_data.get("signatures_found", 0)
            security_findings = firmware_data.get("security_findings", 0)
            firmware_type = firmware_data.get("firmware_type", "unknown")

            if signatures_found > 0:
                recommendations.append(
                    f" Binwalk identified {signatures_found} embedded components. This may be firmware or contain embedded files.",
                )

                if firmware_type != "unknown":
                    recommendations.append(
                        f"🖥️ Detected {firmware_type} firmware. Consider firmware-specific analysis techniques.",
                    )

            if security_findings > 0:
                recommendations.append(
                    f"WARNING️ Binwalk found {security_findings} security issues in embedded components. Review for hardcoded credentials or keys.",
                )

            # Look for specific firmware findings
            firmware_supplemental = firmware_data.get("supplemental_data", {})
            if embedded_files := firmware_supplemental.get("embedded_files", []):
                recommendations.append(
                    f" Found {len(embedded_files)} embedded files. Extract and analyze individual components.",
                )

        # Volatility3 memory forensics recommendations
        if "memory_analysis" in supplemental_data:
            memory_data = supplemental_data["memory_analysis"]
            artifacts_found = memory_data.get("artifacts_found", 0)
            has_suspicious = memory_data.get("has_suspicious_activity", False)

            if artifacts_found > 0:
                recommendations.append(
                    f"🧠 Memory analysis found {artifacts_found} runtime artifacts. This provides insight into dynamic behavior.",
                )

                if has_suspicious:
                    recommendations.append(
                        "🚨 Memory forensics detected suspicious activity. Review process injection and hidden processes.",
                    )

                # Look for specific memory findings
                memory_supplemental = memory_data.get("supplemental_data", {})
                if protection_indicators := memory_supplemental.get("protection_indicators", []):
                    recommendations.append(
                        f" Memory analysis revealed {len(protection_indicators)} protection indicators in runtime.",
                    )

        return recommendations

    def _generate_bypass_scripts(self, analysis: Any, target_protections: list[str] | None = None) -> dict[str, str]:
        """Generate bypass scripts for detected protections."""
        scripts: dict[str, str] = {}

        # Filter protections if targets specified
        protections = getattr(analysis, "protections", [])
        if target_protections:
            protections = [p for p in protections if p.get("name") in target_protections]

        for protection in protections:
            try:
                if script := self._generate_single_bypass_script(analysis, protection):
                    scripts[protection["name"]] = script
            except Exception as e:
                logger.exception("Failed to generate script for %s: %s", protection.get("name", "unknown"), e)

        return scripts

    def _generate_single_bypass_script(self, analysis: Any, protection: dict[str, Any]) -> str | None:
        """Generate bypass script for a single protection."""
        context = {
            "file_path": getattr(analysis, "file_path", "unknown"),
            "file_type": getattr(analysis, "file_type", "unknown"),
            "architecture": getattr(analysis, "architecture", "unknown"),
            "protection_name": protection["name"],
            "protection_type": protection["type"],
            "protection_details": protection.get("details", {}),
            "bypass_recommendations": protection.get("bypass_recommendations", []),
        }

        # Use AI if available
        if self.llm_manager is not None and hasattr(self.llm_manager, "has_active_backend") and self.llm_manager.has_active_backend():
            try:
                prompt = self._build_bypass_prompt(context)
                if hasattr(self.llm_manager, "generate"):
                    response = self.llm_manager.generate(prompt)
                    if response and isinstance(response, dict) and response.get("success"):
                        content = response.get("content", "")
                        if isinstance(content, str):
                            return content
            except Exception as e:
                logger.warning("AI generation failed: %s", e)

        # Fallback to template-based generation
        protection_type = protection["type"].lower()

        if "pack" in protection_type:
            return self._generate_unpacking_script(context)
        if "debug" in protection_type:
            return self._generate_antidebug_script(context)
        if "licens" in protection_type or "dongle" in protection_type:
            return self._generate_license_bypass_script(context)
        return self._generate_generic_bypass_script(context)

    def _build_bypass_prompt(self, context: dict[str, Any]) -> str:
        """Build prompt for AI bypass script generation."""
        return f"""Generate a Frida script to bypass the following protection:

Protection: {context["protection_name"]}
Type: {context["protection_type"]}
File Type: {context["file_type"]}
Architecture: {context["architecture"]}

Bypass recommendations:
{chr(10).join(f"- {rec}" for rec in context.get("bypass_recommendations", ["No specific recommendations"]))}

Generate a practical, working Frida script that implements these bypass techniques.
Include comments explaining each bypass method used."""

    def _generate_unpacking_script(self, context: dict[str, Any]) -> str:
        """Generate unpacking script."""
        return f"""// Unpacking script for {context["protection_name"]}
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

console.log("[*] Unpacking monitor active for {context["protection_name"]}");
"""

    def _generate_antidebug_script(self, context: dict[str, Any]) -> str:
        """Generate anti-debug bypass script."""
        return f"""// Anti-debug bypass script for {context["protection_name"]}
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

console.log("[+] Anti-debug bypasses active for {context["protection_name"]}");
"""

    def _generate_license_bypass_script(self, context: dict[str, Any]) -> str:
        """Generate license bypass script."""
        return f"""// License bypass script for {context["protection_name"]}
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

console.log("[+] License bypass hooks active for {context["protection_name"]}");
"""

    def _generate_generic_bypass_script(self, context: dict[str, Any]) -> str:
        """Generate generic bypass script."""
        return f"""// Generic bypass script for {context["protection_name"]}
// Generated by Intellicrack

// Monitor for protection checks
var protectionName = "{context["protection_name"]}";
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

    def _generate_next_steps(self, analysis: Any) -> list[str]:
        """Generate next steps for the user."""
        steps: list[str] = []

        is_packed = getattr(analysis, "is_packed", False)
        has_anti_debug = getattr(analysis, "has_anti_debug", False)
        has_licensing = getattr(analysis, "has_licensing", False)

        if is_packed:
            steps.extend((
                "1. Run the unpacking script in Frida to dump the unpacked code",
                "2. Use Scylla to rebuild the import table",
                "3. Re-analyze the unpacked binary",
            ))
        elif has_anti_debug:
            steps.extend((
                "1. Apply the anti-debug bypass script",
                "2. Attach debugger with ScyllaHide enabled",
                "3. Set breakpoints at key decision points",
            ))
        elif has_licensing:
            steps.extend((
                "1. Run the license bypass script to identify check locations",
                "2. Analyze the validation logic in Ghidra",
                "3. Patch the license checks or generate valid keys",
            ))
        else:
            steps.extend((
                "1. Load the binary in your preferred debugger",
                "2. Apply the generated bypass scripts",
                "3. Analyze the protection implementation",
            ))
        # Always add verification step
        steps.append(f"{len(steps) + 1}. Verify the bypass by testing the patched binary")

        return steps

    def _report_progress(self, message: str, percentage: int) -> None:
        """Report workflow progress."""
        if self.progress_callback is not None and callable(self.progress_callback):
            self.progress_callback(message, percentage)
        logger.debug("Workflow progress: %s (%d%%)", message, percentage)


# Convenience functions
def quick_protection_analysis(file_path: str) -> dict[str, Any]:
    """Quick protection analysis with summary."""
    workflow = ProtectionAnalysisWorkflow()
    result = workflow.analyze_and_bypass(file_path, auto_generate_scripts=False)

    if result.success and result.protection_analysis:
        return {
            "protected": bool(result.protection_analysis.protections),
            "protections": [p["name"] for p in result.protection_analysis.protections],
            "recommendations": result.recommendations,
            "confidence": result.confidence,
        }
    return {
        "protected": False,
        "protections": [],
        "recommendations": result.recommendations or ["Analysis failed"],
        "confidence": 0.0,
    }


def generate_protection_report(file_path: str) -> str:
    """Generate a comprehensive protection analysis report."""
    workflow = ProtectionAnalysisWorkflow()
    result = workflow.analyze_and_bypass(file_path)

    report = f"""# Protection Analysis Report

**File:** {os.path.basename(file_path)}
**Date:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Summary

- **Protected:** {"Yes" if result.protection_analysis and result.protection_analysis.protections else "No"}
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
