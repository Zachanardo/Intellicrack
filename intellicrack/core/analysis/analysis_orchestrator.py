"""Comprehensive Analysis Orchestrator.

Coordinates multiple analysis engines to perform deep binary analysis,
including static analysis, dynamic analysis, entropy analysis, structure
analysis, and more.

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
import os
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from intellicrack.handlers.pyqt6_handler import QObject, pyqtSignal


logger = logging.getLogger(__name__)

from ...ai.common_types import ExecutionResult
from ...ai.qemu_manager import QEMUManager
from ...utils.tools.ghidra_script_manager import GhidraScript, GhidraScriptManager
from .binary_analyzer import BinaryAnalyzer
from .entropy_analyzer import EntropyAnalyzer
from .multi_format_analyzer import MultiFormatBinaryAnalyzer as MultiFormatAnalyzer
from .vulnerability_engine import AdvancedVulnerabilityEngine as VulnerabilityEngine
from .yara_pattern_engine import YaraPatternEngine


class AnalysisPhase(Enum):
    """Analysis phases."""

    PREPARATION = "preparation"
    BASIC_INFO = "basic_info"
    STATIC_ANALYSIS = "static_analysis"
    GHIDRA_ANALYSIS = "ghidra_analysis"
    ENTROPY_ANALYSIS = "entropy_analysis"
    STRUCTURE_ANALYSIS = "structure_analysis"
    VULNERABILITY_SCAN = "vulnerability_scan"
    PATTERN_MATCHING = "pattern_matching"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    FINALIZATION = "finalization"


@dataclass
class OrchestrationResult:
    """Result of orchestrated analysis."""

    binary_path: str
    success: bool
    phases_completed: list[AnalysisPhase] = field(default_factory=list)
    results: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_result(self, phase: AnalysisPhase, result: dict[str, Any]) -> None:
        """Add result for a phase.

        Args:
            phase: The analysis phase to add result for
            result: Dictionary containing phase analysis results

        """
        self.phases_completed.append(phase)
        self.results[phase.value] = result

    def add_error(self, phase: AnalysisPhase, error: str) -> None:
        """Add error for a phase."""
        self.errors.append(f"{phase.value}: {error}")

    def add_warning(self, phase: AnalysisPhase, warning: str) -> None:
        """Add warning for a phase."""
        self.warnings.append(f"{phase.value}: {warning}")


class AnalysisOrchestrator(QObject):
    """Orchestrates comprehensive binary analysis using multiple engines."""

    # Signals
    #: phase_name (type: str)
    phase_started = pyqtSignal(str)
    #: phase_name, result (type: str, dict)
    phase_completed = pyqtSignal(str, dict)
    #: phase_name, error (type: str, str)
    phase_failed = pyqtSignal(str, str)
    #: current, total (type: int, int)
    progress_updated = pyqtSignal(int, int)
    #: Signal emitted when analysis is completed (type: OrchestrationResult)
    analysis_completed = pyqtSignal(OrchestrationResult)

    def __init__(self, binary_path: str | None = None) -> None:
        """Initialize the analysis orchestrator.

        Sets up all analysis engines including binary analyzer, entropy analyzer,
        multi-format analyzer, dynamic analyzer, vulnerability engine, YARA pattern
        engine, and radare2 integration for comprehensive binary analysis orchestration.

        Args:
            binary_path: Optional path to the binary file to analyze. If provided,
                the orchestrator will use this path when orchestrate() is called.

        """
        super().__init__()

        self.binary_path = binary_path

        self.binary_analyzer = BinaryAnalyzer()
        self.entropy_analyzer = EntropyAnalyzer()
        self.multi_format_analyzer = MultiFormatAnalyzer()
        self.dynamic_analyzer: Any = None
        self.vulnerability_engine = VulnerabilityEngine()
        self.yara_engine = YaraPatternEngine()
        self.radare2: Any = None

        self.ghidra_script_manager = GhidraScriptManager()
        self.qemu_manager: QEMUManager | None = None

        self.enabled_phases: list[AnalysisPhase] = list(AnalysisPhase)
        self.timeout_per_phase: int = 300

    def orchestrate(self) -> OrchestrationResult:
        """Execute orchestrated analysis using the configured binary path.

        This method runs the complete analysis pipeline on the binary file
        specified during initialization or via the binary_path attribute.
        It coordinates all enabled analysis phases and collects results.

        Returns:
            OrchestrationResult containing all analysis data, including
            completed phases, results, errors, and warnings.

        """
        if not self.binary_path:
            result = OrchestrationResult(binary_path="", success=False)
            result.add_error(
                AnalysisPhase.PREPARATION,
                "No binary path configured. Set binary_path before calling orchestrate().",
            )
            self.analysis_completed.emit(result)
            return result

        return self.analyze_binary(self.binary_path, self.enabled_phases)

    def analyze_binary(self, binary_path: str, phases: list[AnalysisPhase] | None = None) -> OrchestrationResult:
        """Perform orchestrated analysis on a binary.

        Args:
            binary_path: Path to the binary file
            phases: Optional list of phases to run (runs all if None)

        Returns:
            OrchestrationResult with all analysis data

        """
        result = OrchestrationResult(binary_path=binary_path, success=True)

        # Use provided phases or all phases
        phases_to_run = phases or self.enabled_phases
        total_phases = len(phases_to_run)

        # Validate file exists
        if not os.path.exists(binary_path):
            result.success = False
            result.add_error(AnalysisPhase.PREPARATION, f"File not found: {binary_path}")
            self.analysis_completed.emit(result)
            return result

        # Run each phase
        for idx, phase in enumerate(phases_to_run):
            self.progress_updated.emit(idx, total_phases)

            try:
                self.phase_started.emit(phase.value)

                if phase == AnalysisPhase.PREPARATION:
                    phase_result = self._prepare_analysis(binary_path)
                elif phase == AnalysisPhase.BASIC_INFO:
                    phase_result = self._analyze_basic_info(binary_path)
                elif phase == AnalysisPhase.STATIC_ANALYSIS:
                    phase_result = self._perform_static_analysis(binary_path)
                elif phase == AnalysisPhase.GHIDRA_ANALYSIS:
                    phase_result = self._perform_ghidra_analysis(binary_path)
                elif phase == AnalysisPhase.ENTROPY_ANALYSIS:
                    phase_result = self._perform_entropy_analysis(binary_path)
                elif phase == AnalysisPhase.STRUCTURE_ANALYSIS:
                    phase_result = self._analyze_structure(binary_path)
                elif phase == AnalysisPhase.VULNERABILITY_SCAN:
                    phase_result = self._scan_vulnerabilities(binary_path)
                elif phase == AnalysisPhase.PATTERN_MATCHING:
                    phase_result = self._match_patterns(binary_path)
                elif phase == AnalysisPhase.DYNAMIC_ANALYSIS:
                    phase_result = self._perform_dynamic_analysis(binary_path)
                elif phase == AnalysisPhase.FINALIZATION:
                    phase_result = self._finalize_analysis(result)
                else:
                    phase_result = {"status": "skipped", "reason": "Unknown phase"}

                result.add_result(phase, phase_result)
                self.phase_completed.emit(phase.value, phase_result)

            except Exception as e:
                error_msg = f"Phase {phase.value} failed: {e!s}"
                result.add_error(phase, str(e))
                self.phase_failed.emit(phase.value, error_msg)
                # Continue with other phases even if one fails

        self.progress_updated.emit(total_phases, total_phases)
        self.analysis_completed.emit(result)
        return result

    def _prepare_analysis(self, binary_path: str) -> dict[str, Any]:
        """Prepare for analysis."""
        file_stat = Path(binary_path).stat()
        return {
            "file_size": file_stat.st_size,
            "file_path": os.path.abspath(binary_path),
            "file_name": os.path.basename(binary_path),
            "modified_time": file_stat.st_mtime,
        }

    def _analyze_basic_info(self, binary_path: str) -> dict[str, Any]:
        """Get basic binary information."""
        try:
            # Use binary analyzer for basic info
            return self.binary_analyzer.analyze(binary_path)
        except Exception as e:
            return {"error": str(e), "fallback": True}

    def _perform_static_analysis(self, binary_path: str) -> dict[str, Any]:
        """Perform static analysis using radare2."""
        try:
            result = {}

            # Initialize radare2 if not already done
            if self.radare2 is None:
                from .radare2_enhanced_integration import EnhancedR2Integration as Radare2EnhancedIntegration

                try:
                    self.radare2 = Radare2EnhancedIntegration(binary_path)
                except Exception as init_error:
                    return {"error": f"Radare2 initialization failed: {init_error}"}

            # Run comprehensive analysis using the correct method
            analysis_result = self.radare2.run_comprehensive_analysis(
                analysis_types=["imports", "strings", "signatures", "decompiler", "esil"],
            )

            # Extract relevant information from the comprehensive analysis result
            if analysis_result and "components" in analysis_result:
                components = analysis_result["components"]

                if imports_data := components.get("imports"):
                    result["imports"] = imports_data.get("imports", [])
                    result["exports"] = imports_data.get("exports", [])
                    result["sections"] = imports_data.get("sections", [])

                if strings_data := components.get("strings"):
                    result["strings"] = strings_data.get("strings", [])

                if decompiler_data := components.get("decompiler"):
                    result["functions"] = decompiler_data.get("functions", [])

                if signatures_data := components.get("signatures"):
                    result["signatures"] = signatures_data

                if esil_data := components.get("esil"):
                    result["esil_analysis"] = esil_data

            if errors := analysis_result.get("errors"):
                result["analysis_errors"] = errors

            return result
        except Exception as e:
            return {"error": str(e)}

    def _perform_ghidra_analysis(self, binary_path: str) -> dict[str, Any]:
        """Perform Ghidra analysis in sandboxed QEMU environment.

        This method integrates Ghidra analysis into the main pipeline by:
        1. Initializing QEMUManager if not already done
        2. Selecting appropriate Ghidra script based on binary characteristics
        3. Executing the script in a sandboxed environment
        4. Parsing and returning the results
        """
        try:
            result: dict[str, Any] = {
                "ghidra_executed": False,
                "script_used": None,
                "analysis_results": {},
                "errors": [],
            }

            # Initialize QEMU Test Manager on demand
            if self.qemu_manager is None:
                try:
                    self.qemu_manager = QEMUManager()
                    # Start the VM if not already running
                    if self.qemu_manager is not None and not self.qemu_manager.is_vm_running():
                        vm_started = self.qemu_manager.start_vm(timeout=120)
                        if not vm_started:
                            errors = result.get("errors")
                            if isinstance(errors, list):
                                errors.append("Failed to start QEMU VM for Ghidra analysis")
                            return result
                except Exception as vm_error:
                    errors = result.get("errors")
                    if isinstance(errors, list):
                        errors.append(f"QEMU VM initialization failed: {vm_error!s}")
                    return result

            if selected_script := self._select_ghidra_script(binary_path):
                result["script_used"] = selected_script.name

                vm_binary_path = f"{tempfile.gettempdir()}/analysis_{os.path.basename(binary_path)}"
                if self.qemu_manager is not None:
                    if copy_success := self.qemu_manager.copy_file_to_vm(binary_path, vm_binary_path):
                        logger.debug("Binary copied to VM successfully: %s", copy_success)
                        ghidra_command = self._build_ghidra_command(selected_script.path, vm_binary_path)

                        execution_result: ExecutionResult | None = self.qemu_manager.execute_in_vm(
                            ghidra_command,
                            timeout=300,
                        )

                        if execution_result and execution_result.success:
                            result["ghidra_executed"] = True
                            parsed_results = self._parse_ghidra_output(execution_result.output)
                            result["analysis_results"] = parsed_results

                            if "license_checks" in parsed_results:
                                result["license_validation_found"] = True
                                result["license_checks"] = parsed_results["license_checks"]

                            if "crypto_routines" in parsed_results:
                                result["cryptographic_analysis"] = parsed_results["crypto_routines"]

                            if "protection_mechanisms" in parsed_results:
                                result["detected_protections"] = parsed_results["protection_mechanisms"]

                            if "keygen_patterns" in parsed_results:
                                result["keygen_candidates"] = parsed_results["keygen_patterns"]
                        else:
                            error_msg = execution_result.error if execution_result else "Unknown execution error"
                            errors = result.get("errors")
                            if isinstance(errors, list):
                                errors.append(f"Ghidra script execution failed: {error_msg}")
                    else:
                        errors = result.get("errors")
                        if isinstance(errors, list):
                            errors.append("Failed to copy binary to VM")
            else:
                errors = result.get("errors")
                if isinstance(errors, list):
                    errors.append("No suitable Ghidra script found for this binary type")

            return result

        except Exception as e:
            return {"error": str(e), "ghidra_executed": False}

    def _select_ghidra_script(self, binary_path: str) -> GhidraScript | None:
        """Select the most appropriate Ghidra script for the binary.

        Analyzes binary characteristics and selects the best matching
        Ghidra script from the available scripts.

        Args:
            binary_path: Path to the binary file to analyze

        Returns:
            The best matching Ghidra script object or None if no suitable script found

        """
        try:
            # Discover available scripts
            self.ghidra_script_manager.discover_scripts()
            available_scripts = self.ghidra_script_manager.list_scripts()

            if not available_scripts:
                return None

            # Analyze binary to determine best script
            with open(binary_path, "rb") as f:
                header = f.read(1024)

            # Check for PE signature (Windows executable)
            if b"MZ" in header[:2] and b"PE\x00\x00" in header:
                # Look for license-related scripts for Windows binaries
                for script in available_scripts:
                    if "License" in script.name or "Keygen" in script.name:
                        return script
                # Fallback to advanced analysis script
                for script in available_scripts:
                    if "AdvancedAnalysis" in script.name:
                        return script

            # Check for ELF signature (Linux executable)
            elif header[:4] == b"\x7fELF":
                # Look for Linux-specific scripts
                for script in available_scripts:
                    if "NetworkAnalysis" in script.name:
                        return script

            # Default to most comprehensive script available
            for script in available_scripts:
                if "AdvancedAnalysis" in script.name or "Comprehensive" in script.name:
                    return script

            # Return first available script as last resort
            return available_scripts[0] if available_scripts else None

        except Exception:
            return None

    def _build_ghidra_command(self, script_path: str, binary_path: str) -> str:
        """Build the Ghidra headless analysis command.

        Constructs the command line for running Ghidra in headless mode
        with the selected script and binary.
        """
        ghidra_home = "/opt/ghidra"  # Standard Ghidra installation path in VM
        project_location = f"{tempfile.gettempdir()}/ghidra_projects"
        project_name = f"analysis_{os.path.basename(binary_path)}"

        return f"{ghidra_home}/support/analyzeHeadless {project_location} {project_name} -import {binary_path} -postScript {script_path} -deleteProject"

    def _parse_ghidra_output(self, output: str) -> dict[str, Any]:
        """Parse Ghidra script output into structured data.

        Extracts meaningful information from Ghidra analysis output
        and structures it for integration into the analysis pipeline.
        """
        parsed: dict[str, Any] = {
            "raw_output": output,
            "functions_analyzed": 0,
            "license_checks": [],
            "crypto_routines": [],
            "protection_mechanisms": [],
            "keygen_patterns": [],
            "interesting_strings": [],
        }

        try:
            lines = output.split("\n")

            for line in lines:
                # Parse license check detection
                if ("LICENSE_CHECK" in line and "Function:" in line) or (
                    "LICENSE_CHECK" not in line and "license" in line.lower() and "Function:" in line
                ):
                    func_match = line.split("Function:")[1].strip()
                    license_checks = parsed.get("license_checks")
                    if isinstance(license_checks, list):
                        license_checks.append(
                            {
                                "function": func_match,
                                "address": self._extract_address(line),
                                "confidence": "high" if "LICENSE_CHECK" in line else "medium",
                            },
                        )

                # Parse cryptographic routine detection
                if any(crypto in line.lower() for crypto in ["aes", "rsa", "crypto", "hash", "md5", "sha"]):
                    crypto_routines = parsed.get("crypto_routines")
                    if isinstance(crypto_routines, list):
                        crypto_routines.append(
                            {
                                "type": self._identify_crypto_type(line),
                                "location": self._extract_address(line),
                                "details": line.strip(),
                            },
                        )

                # Parse protection mechanism detection
                if any(prot in line.lower() for prot in ["anti-debug", "obfuscat", "pack", "encrypt", "protect"]):
                    protection_mechanisms = parsed.get("protection_mechanisms")
                    if isinstance(protection_mechanisms, list):
                        protection_mechanisms.append({"type": self._identify_protection_type(line), "details": line.strip()})

                # Parse potential keygen patterns
                if "keygen" in line.lower() or "serial" in line.lower() or "algorithm" in line.lower():
                    keygen_patterns = parsed.get("keygen_patterns")
                    if isinstance(keygen_patterns, list):
                        keygen_patterns.append(
                            {
                                "pattern": line.strip(),
                                "type": "algorithmic" if "algorithm" in line.lower() else "serial",
                            },
                        )

                # Count analyzed functions
                if "Function analyzed:" in line or "Function:" in line:
                    functions_analyzed = parsed.get("functions_analyzed")
                    if isinstance(functions_analyzed, int):
                        parsed["functions_analyzed"] = functions_analyzed + 1

                # Extract interesting strings
                if "String:" in line and len(line) > 20:
                    string_val = line.split("String:")[1].strip()
                    if self._is_interesting_string(string_val):
                        interesting_strings = parsed.get("interesting_strings")
                        if isinstance(interesting_strings, list):
                            interesting_strings.append(string_val)

        except Exception as parse_error:
            parsed["parse_error"] = str(parse_error)

        return parsed

    def _extract_address(self, line: str) -> str:
        """Extract memory address from Ghidra output line."""
        import re

        # Look for hex addresses like 0x401000 or 00401000h
        hex_pattern = r"(0x[0-9a-fA-F]+|[0-9a-fA-F]+h)"
        match = re.search(hex_pattern, line)
        return match.group(1) if match else "unknown"

    def _identify_crypto_type(self, line: str) -> str:
        """Identify the type of cryptographic routine from output."""
        line_lower = line.lower()
        if "aes" in line_lower:
            return "AES"
        if "rsa" in line_lower:
            return "RSA"
        if "md5" in line_lower:
            return "MD5"
        if "sha256" in line_lower:
            return "SHA256"
        if "sha1" in line_lower:
            return "SHA1"
        return "Generic Hash" if "hash" in line_lower else "Unknown Crypto"

    def _identify_protection_type(self, line: str) -> str:
        """Identify the type of protection mechanism from output."""
        line_lower = line.lower()
        if "anti-debug" in line_lower:
            return "Anti-Debugging"
        if "obfuscat" in line_lower:
            return "Obfuscation"
        if "pack" in line_lower:
            return "Packing"
        if "encrypt" in line_lower:
            return "Encryption"
        return "Virtualization" if "virtualiz" in line_lower else "Generic Protection"

    def _is_interesting_string(self, string_val: str) -> bool:
        """Determine if a string is interesting for license analysis."""
        interesting_keywords = [
            "license",
            "serial",
            "key",
            "trial",
            "expire",
            "register",
            "activation",
            "validate",
            "crack",
            "patch",
            "bypass",
            "evaluation",
            "demo",
            "full version",
            "pro version",
        ]
        string_lower = string_val.lower()
        return any(keyword in string_lower for keyword in interesting_keywords)

    def _perform_entropy_analysis(self, binary_path: str) -> dict[str, Any]:
        """Perform entropy analysis."""
        try:
            with open(binary_path, "rb") as f:
                data = f.read()

            # Overall entropy
            overall_entropy = self.entropy_analyzer.calculate_entropy(data)
            result = {"sections": [], "overall_entropy": overall_entropy}
            # Analyze in chunks
            chunk_size = 1024
            chunks = []
            for i in range(0, len(data), chunk_size):
                if chunk_data := data[i : i + chunk_size]:
                    entropy = self.entropy_analyzer.calculate_entropy(chunk_data)
                    chunks.append(
                        {
                            "offset": i,
                            "size": len(chunk_data),
                            "entropy": entropy,
                            "suspicious": entropy > self.entropy_analyzer.high_entropy_threshold,
                        },
                    )

            result["chunks"] = chunks
            result["high_entropy_chunks"] = [c for c in chunks if c["suspicious"]]

            return result
        except Exception as e:
            return {"error": str(e)}

    def _analyze_structure(self, binary_path: str) -> dict[str, Any]:
        """Analyze binary structure."""
        try:
            # Use multi-format analyzer
            return self.multi_format_analyzer.analyze(binary_path)
        except Exception as e:
            return {"error": str(e)}

    def _scan_vulnerabilities(self, binary_path: str) -> dict[str, Any]:
        """Scan for vulnerabilities."""
        try:
            vulnerabilities = self.vulnerability_engine.scan_binary(binary_path)
            return {"vulnerabilities": vulnerabilities}
        except Exception as e:
            return {"error": str(e)}

    def _match_patterns(self, binary_path: str) -> dict[str, Any]:
        """Match YARA patterns."""
        try:
            # Load rules if available
            rules_path = "data/yara_rules"
            if os.path.exists(rules_path):
                self.yara_engine.load_rules(rules_path)

            return self.yara_engine.scan(binary_path)
        except Exception as e:
            return {"error": str(e)}

    def _perform_dynamic_analysis(self, binary_path: str) -> dict[str, Any]:
        """Perform dynamic analysis if possible."""
        try:
            # Initialize dynamic analyzer if not already done
            if self.dynamic_analyzer is None:
                from .dynamic_analyzer import AdvancedDynamicAnalyzer as DynamicAnalyzer

                try:
                    self.dynamic_analyzer = DynamicAnalyzer(binary_path)
                except Exception as init_error:
                    return {
                        "status": "skipped",
                        "reason": f"Dynamic analyzer initialization failed: {init_error}",
                    }

            # Check if dynamic analysis is available
            if hasattr(self.dynamic_analyzer, "is_available") and callable(getattr(self.dynamic_analyzer, "is_available", None)):
                is_available_method = getattr(self.dynamic_analyzer, "is_available")
                if is_available_method():
                    analyze_method = getattr(self.dynamic_analyzer, "analyze", None)
                    if analyze_method is not None and callable(analyze_method):
                        analysis_result: dict[str, Any] = analyze_method(binary_path)
                        return analysis_result
            elif hasattr(self.dynamic_analyzer, "run_comprehensive_analysis") and callable(
                getattr(self.dynamic_analyzer, "run_comprehensive_analysis", None)
            ):
                run_method = getattr(self.dynamic_analyzer, "run_comprehensive_analysis")
                if callable(run_method):
                    comprehensive_result: dict[str, Any] = run_method()
                    return comprehensive_result
            return {"status": "skipped", "reason": "Dynamic analysis not available"}
        except Exception as e:
            return {"error": str(e)}

    def _finalize_analysis(self, result: OrchestrationResult) -> dict[str, Any]:
        """Finalize and summarize analysis."""
        summary: dict[str, Any] = {
            "total_phases": len(self.enabled_phases),
            "completed_phases": len(result.phases_completed),
            "errors": len(result.errors),
            "warnings": len(result.warnings),
        }

        # Add key findings
        findings: list[str] = []

        # Check entropy results
        if AnalysisPhase.ENTROPY_ANALYSIS in result.phases_completed:
            entropy_data = result.results.get("entropy_analysis", {})
            if entropy_data.get("overall_entropy", 0) > 7.0:
                findings.append("High entropy detected - possible packing/encryption")

        # Check vulnerability results
        if AnalysisPhase.VULNERABILITY_SCAN in result.phases_completed:
            vuln_data = result.results.get("vulnerability_scan", {})
            if vulnerabilities := vuln_data.get("vulnerabilities"):
                if isinstance(vulnerabilities, list):
                    findings.append(f"Found {len(vulnerabilities)} potential vulnerabilities")
                else:
                    findings.append("Vulnerabilities detected")

        summary["key_findings"] = findings
        return summary


def run_selected_analysis(binary_path: str, analysis_types: list[str] | None = None) -> dict[str, Any]:
    """Run selected analysis on a binary file.

    Orchestrates binary analysis using multiple analysis engines including static,
    dynamic, vulnerability scanning, entropy analysis, pattern matching, and structure
    analysis. Supports selective execution of analysis phases based on provided types.

    Args:
        binary_path: Path to the binary to analyze
        analysis_types: List of analysis types to run. Supported types: "static",
            "dynamic", "vulnerability", "entropy", "pattern", "structure". If None,
            all analysis types are executed.

    Returns:
        Analysis results dictionary containing:
            - success: Boolean indicating if analysis completed
            - binary_path: Path to analyzed binary
            - results: Dictionary mapping phase names to results
            - phases_completed: List of completed analysis phases
            - errors: List of errors encountered during analysis
            - warnings: List of warnings from analysis phases

    """
    orchestrator = AnalysisOrchestrator(binary_path)

    # Configure which analyses to run
    if analysis_types:
        orchestrator.enabled_phases = []
        for analysis_type in analysis_types:
            if analysis_type.lower() == "static":
                orchestrator.enabled_phases.append(AnalysisPhase.STATIC_ANALYSIS)
            elif analysis_type.lower() == "dynamic":
                orchestrator.enabled_phases.append(AnalysisPhase.DYNAMIC_ANALYSIS)
            elif analysis_type.lower() == "vulnerability":
                orchestrator.enabled_phases.append(AnalysisPhase.VULNERABILITY_SCAN)
            elif analysis_type.lower() == "entropy":
                orchestrator.enabled_phases.append(AnalysisPhase.ENTROPY_ANALYSIS)
            elif analysis_type.lower() == "pattern":
                orchestrator.enabled_phases.append(AnalysisPhase.PATTERN_MATCHING)
            elif analysis_type.lower() == "structure":
                orchestrator.enabled_phases.append(AnalysisPhase.STRUCTURE_ANALYSIS)

    # Run the orchestrated analysis
    result = orchestrator.orchestrate()

    # Convert result to dictionary
    return {
        "success": result.success,
        "binary_path": result.binary_path,
        "results": result.results,
        "phases_completed": [phase.value for phase in result.phases_completed],
        "errors": result.errors,
        "warnings": result.warnings,
    }
