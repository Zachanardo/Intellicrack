"""Comprehensive Analysis Orchestrator.

Coordinates multiple analysis engines to perform deep binary analysis,
including static analysis, dynamic analysis, entropy analysis, structure
analysis, and more.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from PyQt6.QtCore import QObject, pyqtSignal

from ...ai.qemu_manager import QEMUManager
from ...utils.tools.ghidra_script_manager import GhidraScriptManager
from .binary_analyzer import BinaryAnalyzer
from .entropy_analyzer import EntropyAnalyzer
from .multi_format_analyzer import MultiFormatBinaryAnalyzer as MultiFormatAnalyzer
from .vulnerability_engine import VulnerabilityEngine
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

    def add_result(self, phase: AnalysisPhase, result: Any):
        """Add result for a phase."""
        self.phases_completed.append(phase)
        self.results[phase.value] = result

    def add_error(self, phase: AnalysisPhase, error: str):
        """Add error for a phase."""
        self.errors.append(f"{phase.value}: {error}")

    def add_warning(self, phase: AnalysisPhase, warning: str):
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

    def __init__(self):
        """Initialize the analysis orchestrator.

        Sets up all analysis engines including binary analyzer, entropy analyzer,
        multi-format analyzer, dynamic analyzer, vulnerability engine, YARA pattern
        engine, and radare2 integration for comprehensive binary analysis orchestration.
        """
        super().__init__()

        # Initialize analyzers (some will be created lazily)
        self.binary_analyzer = BinaryAnalyzer()
        self.entropy_analyzer = EntropyAnalyzer()
        self.multi_format_analyzer = MultiFormatAnalyzer()
        self.dynamic_analyzer = None  # Will be created when binary_path is available
        self.vulnerability_engine = VulnerabilityEngine()
        self.yara_engine = YaraPatternEngine()
        self.radare2 = None  # Will be created when binary_path is available

        # Initialize Ghidra integration components
        self.ghidra_script_manager = GhidraScriptManager()
        self.qemu_manager = None  # Initialized on demand to avoid resource overhead

        # Analysis configuration
        self.enabled_phases = list(AnalysisPhase)
        self.timeout_per_phase = 300  # 5 minutes per phase

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
        file_stat = os.stat(binary_path)
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
                from .radare2_enhanced_integration import (
                    EnhancedR2Integration as Radare2EnhancedIntegration,
                )

                try:
                    self.radare2 = Radare2EnhancedIntegration(binary_path)
                except Exception as init_error:
                    return {"error": f"Radare2 initialization failed: {init_error}"}

            # Run comprehensive analysis using the correct method
            analysis_result = self.radare2.run_comprehensive_analysis(
                analysis_types=["imports", "strings", "signatures", "decompiler", "esil"]
            )

            # Extract relevant information from the comprehensive analysis result
            if analysis_result and "components" in analysis_result:
                components = analysis_result["components"]

                # Extract imports and exports from the imports component
                if "imports" in components and components["imports"]:
                    imports_data = components["imports"]
                    result["imports"] = imports_data.get("imports", [])
                    result["exports"] = imports_data.get("exports", [])
                    result["sections"] = imports_data.get("sections", [])

                # Extract strings from the strings component
                if "strings" in components and components["strings"]:
                    strings_data = components["strings"]
                    result["strings"] = strings_data.get("strings", [])

                # Extract functions from decompiler component
                if "decompiler" in components and components["decompiler"]:
                    decompiler_data = components["decompiler"]
                    result["functions"] = decompiler_data.get("functions", [])

                # Include signatures for additional static analysis data
                if "signatures" in components and components["signatures"]:
                    result["signatures"] = components["signatures"]

                # Include ESIL analysis for advanced static analysis
                if "esil" in components and components["esil"]:
                    result["esil_analysis"] = components["esil"]

            # Include any errors from the analysis
            if "errors" in analysis_result and analysis_result["errors"]:
                result["analysis_errors"] = analysis_result["errors"]

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
            result = {
                "ghidra_executed": False,
                "script_used": None,
                "analysis_results": {},
                "errors": [],
            }

            # Initialize QEMU Test Manager on demand
            if self.qemu_manager is None:
                try:
                    self.qemu_manager = QEMUManager(vm_name="ghidra_analysis_vm", vm_type="ubuntu", memory="4096", cpu_cores=2)
                    # Start the VM if not already running
                    if not self.qemu_manager.is_vm_running():
                        vm_started = self.qemu_manager.start_vm(timeout=120)
                        if not vm_started:
                            result["errors"].append("Failed to start QEMU VM for Ghidra analysis")
                            return result
                except Exception as vm_error:
                    result["errors"].append(f"QEMU VM initialization failed: {str(vm_error)}")
                    return result

            # Select appropriate Ghidra script based on binary
            selected_script = self._select_ghidra_script(binary_path)
            if selected_script:
                result["script_used"] = selected_script.name

                # Copy binary to VM
                vm_binary_path = f"{tempfile.gettempdir()}/analysis_{os.path.basename(binary_path)}"
                copy_success = self.qemu_manager.copy_file_to_vm(binary_path, vm_binary_path)

                if copy_success:
                    # Execute Ghidra script in VM
                    ghidra_command = self._build_ghidra_command(selected_script.path, vm_binary_path)

                    execution_result = self.qemu_manager.execute_in_vm(
                        ghidra_command,
                        timeout=300,  # 5 minutes for Ghidra analysis
                    )

                    if execution_result and execution_result.success:
                        result["ghidra_executed"] = True
                        # Parse Ghidra output
                        parsed_results = self._parse_ghidra_output(execution_result.output)
                        result["analysis_results"] = parsed_results

                        # Extract key findings
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
                        result["errors"].append(f"Ghidra script execution failed: {error_msg}")
                else:
                    result["errors"].append("Failed to copy binary to VM")
            else:
                result["errors"].append("No suitable Ghidra script found for this binary type")

            return result

        except Exception as e:
            return {"error": str(e), "ghidra_executed": False}

    def _select_ghidra_script(self, binary_path: str):
        """Select the most appropriate Ghidra script for the binary.

        Analyzes binary characteristics and selects the best matching
        Ghidra script from the available scripts.
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

        # Build headless analyzer command
        command = (
            f"{ghidra_home}/support/analyzeHeadless "
            f"{project_location} {project_name} "
            f"-import {binary_path} "
            f"-postScript {script_path} "
            f"-deleteProject"  # Clean up after analysis
        )

        return command

    def _parse_ghidra_output(self, output: str) -> dict[str, Any]:
        """Parse Ghidra script output into structured data.

        Extracts meaningful information from Ghidra analysis output
        and structures it for integration into the analysis pipeline.
        """
        parsed = {
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
                if "LICENSE_CHECK" in line or "license" in line.lower():
                    if "Function:" in line:
                        func_match = line.split("Function:")[1].strip()
                        parsed["license_checks"].append(
                            {
                                "function": func_match,
                                "address": self._extract_address(line),
                                "confidence": "high" if "LICENSE_CHECK" in line else "medium",
                            }
                        )

                # Parse cryptographic routine detection
                if any(crypto in line.lower() for crypto in ["aes", "rsa", "crypto", "hash", "md5", "sha"]):
                    parsed["crypto_routines"].append(
                        {
                            "type": self._identify_crypto_type(line),
                            "location": self._extract_address(line),
                            "details": line.strip(),
                        }
                    )

                # Parse protection mechanism detection
                if any(prot in line.lower() for prot in ["anti-debug", "obfuscat", "pack", "encrypt", "protect"]):
                    parsed["protection_mechanisms"].append({"type": self._identify_protection_type(line), "details": line.strip()})

                # Parse potential keygen patterns
                if "keygen" in line.lower() or "serial" in line.lower() or "algorithm" in line.lower():
                    parsed["keygen_patterns"].append(
                        {
                            "pattern": line.strip(),
                            "type": "algorithmic" if "algorithm" in line.lower() else "serial",
                        }
                    )

                # Count analyzed functions
                if "Function analyzed:" in line or "Function:" in line:
                    parsed["functions_analyzed"] += 1

                # Extract interesting strings
                if "String:" in line and len(line) > 20:
                    string_val = line.split("String:")[1].strip()
                    if self._is_interesting_string(string_val):
                        parsed["interesting_strings"].append(string_val)

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
        elif "rsa" in line_lower:
            return "RSA"
        elif "md5" in line_lower:
            return "MD5"
        elif "sha256" in line_lower:
            return "SHA256"
        elif "sha1" in line_lower:
            return "SHA1"
        elif "hash" in line_lower:
            return "Generic Hash"
        else:
            return "Unknown Crypto"

    def _identify_protection_type(self, line: str) -> str:
        """Identify the type of protection mechanism from output."""
        line_lower = line.lower()
        if "anti-debug" in line_lower:
            return "Anti-Debugging"
        elif "obfuscat" in line_lower:
            return "Obfuscation"
        elif "pack" in line_lower:
            return "Packing"
        elif "encrypt" in line_lower:
            return "Encryption"
        elif "virtualiz" in line_lower:
            return "Virtualization"
        else:
            return "Generic Protection"

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
            result = {"sections": []}

            with open(binary_path, "rb") as f:
                data = f.read()

            # Overall entropy
            overall_entropy = self.entropy_analyzer.calculate_entropy(data)
            result["overall_entropy"] = overall_entropy

            # Analyze in chunks
            chunk_size = 1024
            chunks = []
            for i in range(0, len(data), chunk_size):
                chunk_data = data[i : i + chunk_size]
                if chunk_data:
                    entropy = self.entropy_analyzer.calculate_entropy(chunk_data)
                    chunks.append(
                        {
                            "offset": i,
                            "size": len(chunk_data),
                            "entropy": entropy,
                            "suspicious": entropy > self.entropy_analyzer.high_entropy_threshold,
                        }
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
            return self.vulnerability_engine.scan(binary_path)
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
            if hasattr(self.dynamic_analyzer, "is_available") and self.dynamic_analyzer.is_available():
                return self.dynamic_analyzer.analyze(binary_path)
            return {"status": "skipped", "reason": "Dynamic analysis not available"}
        except Exception as e:
            return {"error": str(e)}

    def _finalize_analysis(self, result: OrchestrationResult) -> dict[str, Any]:
        """Finalize and summarize analysis."""
        summary = {
            "total_phases": len(self.enabled_phases),
            "completed_phases": len(result.phases_completed),
            "errors": len(result.errors),
            "warnings": len(result.warnings),
        }

        # Add key findings
        findings = []

        # Check entropy results
        if AnalysisPhase.ENTROPY_ANALYSIS in result.phases_completed:
            entropy_data = result.results.get("entropy_analysis", {})
            if entropy_data.get("overall_entropy", 0) > 7.0:
                findings.append("High entropy detected - possible packing/encryption")

        # Check vulnerability results
        if AnalysisPhase.VULNERABILITY_SCAN in result.phases_completed:
            vuln_data = result.results.get("vulnerability_scan", {})
            if vuln_data.get("vulnerabilities"):
                findings.append(f"Found {len(vuln_data['vulnerabilities'])} potential vulnerabilities")

        summary["key_findings"] = findings
        return summary


def run_selected_analysis(binary_path: str, analysis_types: list[str] | None = None) -> dict[str, Any]:
    """Run selected analysis on a binary file.

    Args:
        binary_path: Path to the binary to analyze
        analysis_types: List of analysis types to run (optional)

    Returns:
        Analysis results dictionary

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
