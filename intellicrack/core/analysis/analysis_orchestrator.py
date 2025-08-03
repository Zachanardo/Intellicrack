"""
Comprehensive Analysis Orchestrator

Coordinates multiple analysis engines to perform deep binary analysis,
including static analysis, dynamic analysis, entropy analysis, structure
analysis, and more.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import QObject, pyqtSignal

from .binary_analyzer import BinaryAnalyzer
from .dynamic_analyzer import DynamicAnalyzer
from .entropy_analyzer import EntropyAnalyzer
from .multi_format_analyzer import MultiFormatAnalyzer
from .radare2_enhanced_integration import Radare2EnhancedIntegration
from .vulnerability_engine import VulnerabilityEngine
from .yara_pattern_engine import YaraPatternEngine


class AnalysisPhase(Enum):
    """Analysis phases"""
    PREPARATION = "preparation"
    BASIC_INFO = "basic_info"
    STATIC_ANALYSIS = "static_analysis"
    ENTROPY_ANALYSIS = "entropy_analysis"
    STRUCTURE_ANALYSIS = "structure_analysis"
    VULNERABILITY_SCAN = "vulnerability_scan"
    PATTERN_MATCHING = "pattern_matching"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    FINALIZATION = "finalization"


@dataclass
class OrchestrationResult:
    """Result of orchestrated analysis"""
    binary_path: str
    success: bool
    phases_completed: List[AnalysisPhase] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_result(self, phase: AnalysisPhase, result: Any):
        """Add result for a phase"""
        self.phases_completed.append(phase)
        self.results[phase.value] = result

    def add_error(self, phase: AnalysisPhase, error: str):
        """Add error for a phase"""
        self.errors.append(f"{phase.value}: {error}")

    def add_warning(self, phase: AnalysisPhase, warning: str):
        """Add warning for a phase"""
        self.warnings.append(f"{phase.value}: {warning}")


class AnalysisOrchestrator(QObject):
    """
    Orchestrates comprehensive binary analysis using multiple engines
    """

    # Signals
    phase_started = pyqtSignal(str)  # phase_name
    phase_completed = pyqtSignal(str, dict)  # phase_name, result
    phase_failed = pyqtSignal(str, str)  # phase_name, error
    progress_updated = pyqtSignal(int, int)  # current, total
    analysis_completed = pyqtSignal(OrchestrationResult)

    def __init__(self):
        """Initialize the analysis orchestrator.

        Sets up all analysis engines including binary analyzer, entropy analyzer,
        multi-format analyzer, dynamic analyzer, vulnerability engine, YARA pattern
        engine, and radare2 integration for comprehensive binary analysis orchestration.
        """
        super().__init__()

        # Initialize analyzers
        self.binary_analyzer = BinaryAnalyzer()
        self.entropy_analyzer = EntropyAnalyzer()
        self.multi_format_analyzer = MultiFormatAnalyzer()
        self.dynamic_analyzer = DynamicAnalyzer()
        self.vulnerability_engine = VulnerabilityEngine()
        self.yara_engine = YaraPatternEngine()
        self.radare2 = Radare2EnhancedIntegration()

        # Analysis configuration
        self.enabled_phases = list(AnalysisPhase)
        self.timeout_per_phase = 300  # 5 minutes per phase

    def analyze_binary(self, binary_path: str, phases: Optional[List[AnalysisPhase]] = None) -> OrchestrationResult:
        """
        Perform orchestrated analysis on a binary

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
                error_msg = f"Phase {phase.value} failed: {str(e)}"
                result.add_error(phase, str(e))
                self.phase_failed.emit(phase.value, error_msg)
                # Continue with other phases even if one fails

        self.progress_updated.emit(total_phases, total_phases)
        self.analysis_completed.emit(result)
        return result

    def _prepare_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Prepare for analysis"""
        file_stat = os.stat(binary_path)
        return {
            "file_size": file_stat.st_size,
            "file_path": os.path.abspath(binary_path),
            "file_name": os.path.basename(binary_path),
            "modified_time": file_stat.st_mtime,
        }

    def _analyze_basic_info(self, binary_path: str) -> Dict[str, Any]:
        """Get basic binary information"""
        try:
            # Use binary analyzer for basic info
            return self.binary_analyzer.analyze(binary_path)
        except Exception as e:
            return {"error": str(e), "fallback": True}

    def _perform_static_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Perform static analysis using radare2"""
        try:
            result = {}

            # Initialize radare2 session
            if self.radare2.open_binary(binary_path):
                # Get imports
                result["imports"] = self.radare2.get_imports()

                # Get exports
                result["exports"] = self.radare2.get_exports()

                # Get sections
                result["sections"] = self.radare2.get_sections()

                # Get strings
                result["strings"] = self.radare2.get_strings(min_length=5)

                # Get functions
                result["functions"] = self.radare2.get_functions()

                # Close session
                self.radare2.close()

            return result
        except Exception as e:
            return {"error": str(e)}

    def _perform_entropy_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Perform entropy analysis"""
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
                chunk_data = data[i:i+chunk_size]
                if chunk_data:
                    entropy = self.entropy_analyzer.calculate_entropy(chunk_data)
                    chunks.append({
                        "offset": i,
                        "size": len(chunk_data),
                        "entropy": entropy,
                        "suspicious": entropy > self.entropy_analyzer.high_entropy_threshold
                    })

            result["chunks"] = chunks
            result["high_entropy_chunks"] = [c for c in chunks if c["suspicious"]]

            return result
        except Exception as e:
            return {"error": str(e)}

    def _analyze_structure(self, binary_path: str) -> Dict[str, Any]:
        """Analyze binary structure"""
        try:
            # Use multi-format analyzer
            return self.multi_format_analyzer.analyze(binary_path)
        except Exception as e:
            return {"error": str(e)}

    def _scan_vulnerabilities(self, binary_path: str) -> Dict[str, Any]:
        """Scan for vulnerabilities"""
        try:
            return self.vulnerability_engine.scan(binary_path)
        except Exception as e:
            return {"error": str(e)}

    def _match_patterns(self, binary_path: str) -> Dict[str, Any]:
        """Match YARA patterns"""
        try:
            # Load rules if available
            rules_path = "data/yara_rules"
            if os.path.exists(rules_path):
                self.yara_engine.load_rules(rules_path)

            return self.yara_engine.scan(binary_path)
        except Exception as e:
            return {"error": str(e)}

    def _perform_dynamic_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Perform dynamic analysis if possible"""
        try:
            # Check if dynamic analysis is available
            if hasattr(self.dynamic_analyzer, "is_available") and self.dynamic_analyzer.is_available():
                return self.dynamic_analyzer.analyze(binary_path)
            else:
                return {"status": "skipped", "reason": "Dynamic analysis not available"}
        except Exception as e:
            return {"error": str(e)}

    def _finalize_analysis(self, result: OrchestrationResult) -> Dict[str, Any]:
        """Finalize and summarize analysis"""
        summary = {
            "total_phases": len(self.enabled_phases),
            "completed_phases": len(result.phases_completed),
            "errors": len(result.errors),
            "warnings": len(result.warnings)
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
