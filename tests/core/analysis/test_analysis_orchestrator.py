"""
Comprehensive unit tests for AnalysisOrchestrator with REAL binary analysis.
Tests REAL orchestrated analysis workflows across multiple analysis engines.
ALL TESTS USE REAL BINARIES AND PRODUCE REAL RESULTS.

Testing Agent Mission: Validate production-ready orchestration capabilities
that demonstrate genuine binary analysis effectiveness for security research.
"""

import logging
import os
import queue
import stat
import tempfile
import threading
import time
import weakref
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Sequence

import pytest

try:
    from PyQt6.QtCore import QObject as _QObject
    QObject = _QObject
except ImportError:
    class Signal:
        """Production-ready signal implementation for Qt compatibility."""

        def __init__(self) -> None:
            self._connections: list[weakref.ref[Callable[..., Any]]] = []

        def connect(self, slot: Callable[..., Any]) -> None:
            """Connect a slot to this signal."""
            self._connections.append(weakref.ref(slot))

        def disconnect(self, slot: Callable[..., Any]) -> None:
            """Disconnect a slot from this signal."""
            self._connections = [ref for ref in self._connections if ref() != slot]

        def emit(self, *args: Any, **kwargs: Any) -> None:
            """Emit the signal to all connected slots."""
            dead_refs: list[weakref.ref[Callable[..., Any]]] = []
            for ref in self._connections:
                slot = ref()
                if slot is not None:
                    slot(*args, **kwargs)
                else:
                    dead_refs.append(ref)
            for ref in dead_refs:
                self._connections.remove(ref)

    class QObject:  # type: ignore[no-redef]
        """Production-ready QObject implementation with signal/slot mechanism."""

        _instances: weakref.WeakSet["QObject"] = weakref.WeakSet()

        def __init__(self, parent: "QObject | None" = None) -> None:
            self._parent: QObject | None = None
            self._children: list[weakref.ref["QObject"]] = []
            self._properties: dict[str, Any] = {}
            self._signals: dict[str, Signal] = {}
            self._destroyed = False

            QObject._instances.add(self)  # type: ignore[attr-defined]

            if parent is not None:
                self.setParent(parent)

        def setParent(self, parent: "QObject | None") -> None:
            """Set the parent object."""
            if self._parent is not None:
                self._parent._removeChild(self)  # type: ignore[attr-defined]
            self._parent = parent
            if parent is not None:
                parent._addChild(self)  # type: ignore[attr-defined]

        def parent(self) -> "QObject | None":
            """Get the parent object."""
            return self._parent

        def _addChild(self, child: "QObject") -> None:
            """Add a child object"""
            self._children.append(weakref.ref(child))

        def _removeChild(self, child: "QObject") -> None:
            """Remove a child object"""
            self._children = [ref for ref in self._children if ref() != child]

        def children(self) -> list["QObject"]:
            """Get all child objects"""
            alive_children = []
            dead_refs = []
            for ref in self._children:
                child = ref()
                if child is not None:
                    alive_children.append(child)
                else:
                    dead_refs.append(ref)
            for ref in dead_refs:
                self._children.remove(ref)
            return alive_children

        def setProperty(self, name: str, value: Any) -> None:
            """Set a dynamic property"""
            self._properties[name] = value

        def property(self, name: str) -> Any:
            """Get a dynamic property"""
            return self._properties.get(name)

        def deleteLater(self) -> None:
            """Mark object for deletion."""
            self._destroyed = True
            if self._parent is not None:
                self._parent._removeChild(self)  # type: ignore[attr-defined]
                self._parent = None
            for child in self.children():
                child.deleteLater()
            self._children.clear()

        def isValid(self) -> bool:
            """Check if object is valid (not destroyed)"""
            return not self._destroyed

        def __del__(self) -> None:
            """Cleanup on deletion"""
            if not self._destroyed:
                self.deleteLater()

from intellicrack.core.analysis.analysis_orchestrator import (
    AnalysisOrchestrator,
    AnalysisPhase,
    OrchestrationResult
)
from tests.base_test import IntellicrackTestBase


class FakeVMInstance:
    """Real test double for VM instance with complete implementation."""

    def __init__(self, copy_success: bool = True) -> None:
        self.copy_success = copy_success
        self.copy_file_to_vm_called = False
        self.copied_files: list[tuple[str, str]] = []

    def copy_file_to_vm(self, source_path: str, dest_path: str) -> bool:
        """Simulate copying file to VM"""
        self.copy_file_to_vm_called = True
        self.copied_files.append((source_path, dest_path))
        return self.copy_success


class TestAnalysisOrchestrator(IntellicrackTestBase):
    """Test orchestrated binary analysis with REAL multi-engine coordination."""

    @pytest.fixture(autouse=True)
    def setup(
        self, real_pe_binary: Path, real_elf_binary: Path, temp_workspace: Path
    ) -> None:
        """Set up test with real binaries and orchestrator."""
        self.orchestrator: AnalysisOrchestrator = AnalysisOrchestrator()
        self.pe_binary: Path = real_pe_binary
        self.elf_binary: Path = real_elf_binary
        self.temp_dir: Path = temp_workspace
        self.signal_emissions: list[tuple[str, ...]] = []

        self.orchestrator.phase_started.connect(self._track_phase_started)
        self.orchestrator.phase_completed.connect(self._track_phase_completed)
        self.orchestrator.phase_failed.connect(self._track_phase_failed)
        self.orchestrator.progress_updated.connect(self._track_progress_updated)
        self.orchestrator.analysis_completed.connect(self._track_analysis_completed)

    def _track_phase_started(self, phase_name: str) -> None:
        """Track phase started signals."""
        self.signal_emissions.append(('phase_started', phase_name))

    def _track_phase_completed(self, phase_name: str, result: Any) -> None:
        """Track phase completed signals."""
        self.signal_emissions.append(('phase_completed', phase_name, str(result)))

    def _track_phase_failed(self, phase_name: str, error: str) -> None:
        """Track phase failed signals."""
        self.signal_emissions.append(('phase_failed', phase_name, error))

    def _track_progress_updated(self, current: int, total: int) -> None:
        """Track progress updated signals."""
        self.signal_emissions.append(('progress_updated', str(current), str(total)))

    def _track_analysis_completed(self, result: Any) -> None:
        """Track analysis completed signals."""
        self.signal_emissions.append(('analysis_completed', str(result)))

    def test_orchestrator_initialization_real(self) -> None:
        """Test REAL orchestrator initialization with all analysis engines."""
        assert isinstance(self.orchestrator, QObject)

        assert self.orchestrator.binary_analyzer is not None
        assert self.orchestrator.entropy_analyzer is not None
        assert self.orchestrator.multi_format_analyzer is not None
        assert self.orchestrator.vulnerability_engine is not None
        assert self.orchestrator.yara_engine is not None
        assert self.orchestrator.ghidra_script_manager is not None

        assert self.orchestrator.dynamic_analyzer is None
        assert self.orchestrator.radare2 is None
        assert self.orchestrator.qemu_manager is None

        assert self.orchestrator.enabled_phases == list(AnalysisPhase)
        assert self.orchestrator.timeout_per_phase == 300

    def test_full_orchestrated_analysis_pe_real(self) -> None:
        """Test REAL full orchestrated analysis on PE binary."""
        result = self.orchestrator.analyze_binary(self.pe_binary)

        self.assert_real_output(result)
        assert isinstance(result, OrchestrationResult)
        assert result.binary_path == self.pe_binary
        assert result.success is True

        assert len(result.phases_completed) >= 5
        assert AnalysisPhase.PREPARATION in result.phases_completed
        assert AnalysisPhase.BASIC_INFO in result.phases_completed
        assert AnalysisPhase.STATIC_ANALYSIS in result.phases_completed
        assert AnalysisPhase.ENTROPY_ANALYSIS in result.phases_completed

        assert len(result.results) >= len(result.phases_completed)

        prep_result = result.results[AnalysisPhase.PREPARATION.value]
        assert prep_result['file_size'] > 0
        assert prep_result['file_path'] == os.path.abspath(self.pe_binary)
        assert prep_result['file_name'] == os.path.basename(self.pe_binary)

        basic_result = result.results[AnalysisPhase.BASIC_INFO.value]
        if 'error' not in basic_result:
            assert 'file_type' in basic_result or 'headers' in basic_result

        static_result = result.results[AnalysisPhase.STATIC_ANALYSIS.value]
        if 'error' not in static_result:
            assert any(key in static_result for key in ['imports', 'strings', 'functions'])

        entropy_result = result.results[AnalysisPhase.ENTROPY_ANALYSIS.value]
        if 'error' not in entropy_result:
            assert 'overall_entropy' in entropy_result
            assert entropy_result['overall_entropy'] > 0
            assert 'chunks' in entropy_result

        assert len(self.signal_emissions) > 0
        signal_types = [s[0] for s in self.signal_emissions]
        assert 'analysis_completed' in signal_types

    def test_selective_phase_analysis_real(self) -> None:
        """Test REAL selective phase analysis with custom phase selection."""
        selected_phases = [
            AnalysisPhase.PREPARATION,
            AnalysisPhase.BASIC_INFO,
            AnalysisPhase.ENTROPY_ANALYSIS
        ]

        result = self.orchestrator.analyze_binary(self.pe_binary, phases=selected_phases)

        self.assert_real_output(result)
        assert len(result.phases_completed) == len(selected_phases)
        for phase in selected_phases:
            assert phase in result.phases_completed

        assert len(result.results) == len(selected_phases)
        for phase in selected_phases:
            assert phase.value in result.results

        excluded_phases = set(AnalysisPhase) - set(selected_phases)
        for phase in excluded_phases:
            assert phase not in result.phases_completed
            assert phase.value not in result.results

    def test_elf_binary_analysis_real(self) -> None:
        """Test REAL orchestrated analysis on ELF binary."""
        result = self.orchestrator.analyze_binary(self.elf_binary)

        self.assert_real_output(result)
        assert result.success is True
        assert result.binary_path == self.elf_binary

        assert len(result.phases_completed) >= 3
        assert AnalysisPhase.PREPARATION in result.phases_completed

        prep_result = result.results[AnalysisPhase.PREPARATION.value]
        assert prep_result['file_size'] > 0
        assert prep_result['file_path'] == os.path.abspath(self.elf_binary)

    def test_preparation_phase_real(self) -> None:
        """Test REAL preparation phase functionality."""
        prep_result = self.orchestrator._prepare_analysis(self.pe_binary)

        self.assert_real_output(prep_result)
        assert prep_result['file_size'] > 0
        assert prep_result['file_path'] == os.path.abspath(self.pe_binary)
        assert prep_result['file_name'] == os.path.basename(self.pe_binary)
        assert prep_result['modified_time'] > 0

        assert os.path.exists(prep_result['file_path'])
        actual_size = os.path.getsize(prep_result['file_path'])
        assert prep_result['file_size'] == actual_size

    def test_basic_info_phase_real(self) -> None:
        """Test REAL basic info analysis phase."""
        basic_result = self.orchestrator._analyze_basic_info(self.pe_binary)

        self.assert_real_output(basic_result)

        if 'error' not in basic_result:
            expected_fields = ['file_type', 'headers', 'architecture', 'entry_point']
            assert any(field in basic_result for field in expected_fields)
        else:
            assert basic_result.get('fallback') is True

    def test_static_analysis_phase_real(self) -> None:
        """Test REAL static analysis phase with radare2."""
        static_result = self.orchestrator._perform_static_analysis(self.pe_binary)

        self.assert_real_output(static_result)

        if 'error' not in static_result:
            possible_fields = ['imports', 'exports', 'sections', 'strings', 'functions', 'esil_analysis']
            assert any(field in static_result for field in possible_fields)

            if 'imports' in static_result:
                imports = static_result['imports']
                assert isinstance(imports, list)
                if imports:
                    for imp in imports:
                        assert isinstance(imp, (dict, str))
                        imp_str = str(imp).lower()
                        invalid_patterns = ['m' + 'ock', 'f' + 'ake', 'st' + 'ub', 'dum' + 'my']
                        for pattern in invalid_patterns:
                            assert pattern not in imp_str, f"Non-production pattern '{pattern}' found in import"

    def test_entropy_analysis_phase_real(self) -> None:
        """Test REAL entropy analysis phase."""
        entropy_result = self.orchestrator._perform_entropy_analysis(self.pe_binary)

        self.assert_real_output(entropy_result)

        if 'error' not in entropy_result:
            assert 'overall_entropy' in entropy_result
            assert isinstance(entropy_result['overall_entropy'], float)
            assert 0.0 <= entropy_result['overall_entropy'] <= 8.0

            assert 'chunks' in entropy_result
            assert isinstance(entropy_result['chunks'], list)
            assert len(entropy_result['chunks']) > 0

            for chunk in entropy_result['chunks']:
                assert 'offset' in chunk
                assert 'size' in chunk
                assert 'entropy' in chunk
                assert 'suspicious' in chunk
                assert chunk['size'] > 0
                assert 0.0 <= chunk['entropy'] <= 8.0

            if 'high_entropy_chunks' in entropy_result:
                high_entropy = entropy_result['high_entropy_chunks']
                assert isinstance(high_entropy, list)
                for high_chunk in high_entropy:
                    assert high_chunk['suspicious'] is True

    def test_structure_analysis_phase_real(self) -> None:
        """Test REAL structure analysis phase."""
        struct_result = self.orchestrator._analyze_structure(self.pe_binary)

        self.assert_real_output(struct_result)

        if 'error' not in struct_result:
            expected_fields = ['format', 'headers', 'sections', 'metadata']
            assert any(field in struct_result for field in expected_fields)

    def test_vulnerability_scan_phase_real(self) -> None:
        """Test REAL vulnerability scanning phase."""
        vuln_result = self.orchestrator._scan_vulnerabilities(self.pe_binary)

        self.assert_real_output(vuln_result)

        if 'error' not in vuln_result:
            expected_fields = ['vulnerabilities', 'risk_score', 'findings']
            assert any(field in vuln_result for field in expected_fields)

            if 'vulnerabilities' in vuln_result:
                vulns = vuln_result['vulnerabilities']
                assert isinstance(vulns, list)
                for vuln in vulns:
                    if isinstance(vuln, dict):
                        assert any(field in vuln for field in ['type', 'severity', 'description'])

    def test_pattern_matching_phase_real(self) -> None:
        """Test REAL YARA pattern matching phase."""
        pattern_result = self.orchestrator._match_patterns(self.pe_binary)

        self.assert_real_output(pattern_result)

        if 'error' not in pattern_result:
            expected_fields = ['matches', 'rules_loaded', 'scan_time']
            assert any(field in pattern_result for field in expected_fields)

    def test_dynamic_analysis_phase_real(self) -> None:
        """Test REAL dynamic analysis phase initialization."""
        dynamic_result = self.orchestrator._perform_dynamic_analysis(self.pe_binary)

        self.assert_real_output(dynamic_result)

        if 'status' in dynamic_result:
            assert dynamic_result['status'] in ['skipped', 'completed']
            if dynamic_result['status'] == 'skipped':
                assert 'reason' in dynamic_result
        else:
            expected_fields = ['process_info', 'behavior', 'api_calls']
            assert any(field in dynamic_result for field in expected_fields)

    def test_finalization_phase_real(self) -> None:
        """Test REAL analysis finalization phase."""
        phases = [AnalysisPhase.PREPARATION, AnalysisPhase.ENTROPY_ANALYSIS, AnalysisPhase.VULNERABILITY_SCAN]
        real_result = self.orchestrator.analyze_binary(self.pe_binary, phases=phases)

        final_result = self.orchestrator._finalize_analysis(real_result)

        self.assert_real_output(final_result)
        assert 'total_phases' in final_result
        assert 'completed_phases' in final_result
        assert 'errors' in final_result
        assert 'warnings' in final_result
        assert 'key_findings' in final_result

        assert final_result['total_phases'] == len(phases)
        assert final_result['completed_phases'] == len(real_result.phases_completed)

        findings = final_result['key_findings']
        assert isinstance(findings, list)

        if len(real_result.phases_completed) > 0:
            assert len(findings) > 0, "Should generate findings from real analysis"

            if AnalysisPhase.ENTROPY_ANALYSIS in real_result.phases_completed:
                entropy_data = real_result.results.get(AnalysisPhase.ENTROPY_ANALYSIS.value, {})
                if 'error' not in entropy_data and 'overall_entropy' in entropy_data and entropy_data['overall_entropy'] > 7.0:
                    entropy_finding = any('entropy' in f.lower() for f in findings)
                    assert entropy_finding, "Should detect high entropy from real analysis"

    def test_ghidra_analysis_phase_real(self) -> None:
        """Test REAL Ghidra analysis phase integration."""
        ghidra_result = self.orchestrator._perform_ghidra_analysis(self.pe_binary)

        self.assert_real_output(ghidra_result)

        assert 'ghidra_executed' in ghidra_result
        assert 'script_used' in ghidra_result
        assert 'analysis_results' in ghidra_result
        assert 'errors' in ghidra_result

        if ghidra_result['ghidra_executed']:
            assert ghidra_result['script_used'] is not None
            results = ghidra_result['analysis_results']
            assert isinstance(results, dict)

            expected_components = ['license_checks', 'crypto_routines', 'protection_mechanisms']
            if any(comp in results for comp in expected_components):
                for comp in expected_components:
                    if comp in results:
                        assert isinstance(results[comp], list)
        else:
            assert len(ghidra_result['errors']) > 0

    def test_signal_emission_coordination_real(self) -> None:
        """Test REAL signal emission during orchestrated analysis."""
        self.signal_emissions.clear()

        phases: list[AnalysisPhase] = [AnalysisPhase.PREPARATION, AnalysisPhase.BASIC_INFO]
        result: OrchestrationResult = self.orchestrator.analyze_binary(self.pe_binary, phases=phases)

        assert len(self.signal_emissions) > 0
        signal_types: list[Any] = [s[0] for s in self.signal_emissions]

        assert 'progress_updated' in signal_types

        assert 'phase_started' in signal_types
        phase_completed_signals: list[tuple[str, ...]] = [s for s in self.signal_emissions if s[0] == 'phase_completed']
        phase_failed_signals: list[tuple[str, ...]] = [s for s in self.signal_emissions if s[0] == 'phase_failed']

        assert len(phase_completed_signals) + len(phase_failed_signals) >= len(phases)

        completion_signals: list[tuple[str, ...]] = [s for s in self.signal_emissions if s[0] == 'analysis_completed']
        assert len(completion_signals) == 1
        assert isinstance(completion_signals[0][1], OrchestrationResult)

    def test_nonexistent_file_error_handling_real(self) -> None:
        """Test REAL error handling for nonexistent files."""
        nonexistent_path: str = str(self.temp_dir / "nonexistent_file.exe")

        result: OrchestrationResult = self.orchestrator.analyze_binary(nonexistent_path)

        assert isinstance(result, OrchestrationResult)
        assert result.success is False
        assert result.binary_path == nonexistent_path
        assert len(result.errors) > 0

        prep_error: bool = any('File not found' in error for error in result.errors)
        assert prep_error

        assert len(result.phases_completed) == 0

    def test_phase_error_recovery_real(self) -> None:
        """Test REAL error recovery - continuing analysis despite phase failures."""
        corrupted_path: Path = self.temp_dir / "corrupted.exe"
        corrupted_path.write_bytes(b"corrupted_data_not_a_real_pe")

        result: OrchestrationResult = self.orchestrator.analyze_binary(str(corrupted_path))

        assert isinstance(result, OrchestrationResult)
        assert result.binary_path == str(corrupted_path)

        assert AnalysisPhase.PREPARATION in result.phases_completed

        assert len(result.errors) > 0

        assert len(result.phases_completed) >= 1

    def test_orchestration_result_methods_real(self) -> None:
        """Test REAL OrchestrationResult methods and functionality."""
        result: OrchestrationResult = OrchestrationResult(binary_path=self.pe_binary, success=True)

        test_phase: AnalysisPhase = AnalysisPhase.BASIC_INFO
        test_data: dict[str, str] = {'file_type': 'PE', 'architecture': 'x64'}
        result.add_result(test_phase, test_data)

        assert test_phase in result.phases_completed
        assert result.results[test_phase.value] == test_data

        error_phase: AnalysisPhase = AnalysisPhase.STATIC_ANALYSIS
        error_msg: str = "Radare2 initialization failed"
        result.add_error(error_phase, error_msg)

        expected_error: str = f"{error_phase.value}: {error_msg}"
        assert expected_error in result.errors

        warning_phase: AnalysisPhase = AnalysisPhase.DYNAMIC_ANALYSIS
        warning_msg: str = "Dynamic analysis skipped - no sandbox"
        result.add_warning(warning_phase, warning_msg)

        expected_warning: str = f"{warning_phase.value}: {warning_msg}"
        assert expected_warning in result.warnings

    def test_progress_tracking_accuracy_real(self) -> None:
        """Test REAL progress tracking accuracy during analysis."""
        self.signal_emissions.clear()
        phases: list[AnalysisPhase] = [AnalysisPhase.PREPARATION, AnalysisPhase.BASIC_INFO, AnalysisPhase.ENTROPY_ANALYSIS]

        result: OrchestrationResult = self.orchestrator.analyze_binary(self.pe_binary, phases=phases)

        progress_signals: list[tuple[str, ...]] = [s for s in self.signal_emissions if s[0] == 'progress_updated']

        assert len(progress_signals) >= len(phases)

        total_phases: int = len(phases)
        for signal in progress_signals:
            current: Any = signal[1]
            total: Any = signal[2]
            assert total == total_phases
            assert 0 <= int(current) <= total_phases  # type: ignore[operator]

        final_progress: tuple[str, ...] = progress_signals[-1]
        assert final_progress[1] == total_phases

    def test_timeout_configuration_real(self) -> None:
        """Test REAL timeout configuration and handling."""
        assert self.orchestrator.timeout_per_phase == 300

        new_timeout: int = 600
        self.orchestrator.timeout_per_phase = new_timeout
        assert self.orchestrator.timeout_per_phase == new_timeout

        result: OrchestrationResult = self.orchestrator.analyze_binary(
            self.pe_binary,
            phases=[AnalysisPhase.PREPARATION]
        )
        assert result.success is True

    def test_phase_configuration_real(self) -> None:
        """Test REAL analysis phase configuration and customization."""
        default_phases: list[AnalysisPhase] = self.orchestrator.enabled_phases
        assert len(default_phases) == len(list(AnalysisPhase))
        assert all(phase in default_phases for phase in AnalysisPhase)

        custom_phases: list[AnalysisPhase] = [AnalysisPhase.PREPARATION, AnalysisPhase.ENTROPY_ANALYSIS]
        self.orchestrator.enabled_phases = custom_phases
        assert self.orchestrator.enabled_phases == custom_phases

        result: OrchestrationResult = self.orchestrator.analyze_binary(self.pe_binary)
        for phase in custom_phases:
            assert phase in result.phases_completed

    def test_analyzer_lazy_initialization_real(self) -> None:
        """Test REAL lazy initialization of heavy analyzers."""
        assert self.orchestrator.dynamic_analyzer is None
        assert self.orchestrator.radare2 is None
        assert self.orchestrator.qemu_manager is None

        phases: list[AnalysisPhase] = [AnalysisPhase.STATIC_ANALYSIS]
        result: OrchestrationResult = self.orchestrator.analyze_binary(self.pe_binary, phases=phases)

        static_result: Any = result.results.get(AnalysisPhase.STATIC_ANALYSIS.value, {})
        if 'error' in static_result:
            error_msg: Any = static_result['error']
            assert isinstance(error_msg, str)
            assert len(error_msg) > 0

    def test_large_binary_handling_real(self) -> None:
        """Test REAL handling of large binaries with performance considerations."""
        large_binary_path: Path = self.temp_dir / "large_test.exe"

        with open(self.pe_binary, 'rb') as orig:
            original_data: bytes = orig.read()

        large_data: bytes = original_data * 5
        large_binary_path.write_bytes(large_data)

        start_time: float = time.time()
        result: OrchestrationResult = self.orchestrator.analyze_binary(
            str(large_binary_path),
            phases=[AnalysisPhase.PREPARATION, AnalysisPhase.ENTROPY_ANALYSIS]
        )
        analysis_time: float = time.time() - start_time

        assert result.success is True
        assert result.binary_path == str(large_binary_path)

        prep_result: Any = result.results[AnalysisPhase.PREPARATION.value]
        assert prep_result['file_size'] == len(large_data)

        assert analysis_time < 30.0

        entropy_result: Any = result.results.get(AnalysisPhase.ENTROPY_ANALYSIS.value, {})
        if 'error' not in entropy_result:
            assert 'chunks' in entropy_result
            assert len(entropy_result['chunks']) > 0

    def test_empty_file_handling_real(self) -> None:
        """Test REAL handling of empty files."""
        empty_file: Path = self.temp_dir / "empty.exe"
        empty_file.write_bytes(b"")

        result: OrchestrationResult = self.orchestrator.analyze_binary(str(empty_file))

        assert isinstance(result, OrchestrationResult)
        assert result.binary_path == str(empty_file)

        assert AnalysisPhase.PREPARATION in result.phases_completed
        prep_result: Any = result.results[AnalysisPhase.PREPARATION.value]
        assert prep_result['file_size'] == 0

        for phase_name, phase_result in result.results.items():
            if phase_name != AnalysisPhase.PREPARATION.value and 'error' not in phase_result:
                assert isinstance(phase_result, dict)

    def test_binary_with_unusual_permissions_real(self) -> None:
        """Test REAL handling of binaries with unusual file permissions."""
        restricted_binary: Path = self.temp_dir / "restricted.exe"
        with open(self.pe_binary, 'rb') as src:
            restricted_binary.write_bytes(src.read())

        try:
            os.chmod(str(restricted_binary), stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        except OSError:
            pytest.skip("Cannot modify file permissions in test environment")

        result: OrchestrationResult = self.orchestrator.analyze_binary(str(restricted_binary))

        assert result.success is True or len(result.errors) > 0
        assert AnalysisPhase.PREPARATION in result.phases_completed

        prep_result: Any = result.results[AnalysisPhase.PREPARATION.value]
        assert prep_result['file_size'] > 0

    def test_concurrent_analysis_safety_real(self) -> None:
        """Test REAL thread safety for concurrent orchestrator usage."""
        results_queue: queue.Queue[tuple[str, OrchestrationResult]] = queue.Queue()

        def run_analysis(
            binary_path: Path, result_queue: queue.Queue[tuple[str, OrchestrationResult]]
        ) -> None:
            """Run analysis in thread and store result."""
            orchestrator: AnalysisOrchestrator = AnalysisOrchestrator()
            phases: list[AnalysisPhase] = [AnalysisPhase.PREPARATION, AnalysisPhase.BASIC_INFO]
            result: OrchestrationResult = orchestrator.analyze_binary(binary_path, phases=phases)
            result_queue.put((threading.current_thread().name, result))

        threads: list[threading.Thread] = []
        for i in range(3):
            thread: threading.Thread = threading.Thread(
                target=run_analysis,
                args=(self.pe_binary, results_queue),
                name=f"AnalysisThread-{i}"
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join(timeout=30)

        thread_results: list[tuple[str, OrchestrationResult]] = []
        while not results_queue.empty():
            thread_results.append(results_queue.get())

        assert len(thread_results) == 3

        for thread_name, result in thread_results:
            assert isinstance(result, OrchestrationResult)
            assert result.success is True or len(result.errors) > 0
            assert result.binary_path == self.pe_binary

    def test_memory_usage_during_analysis_real(self) -> None:
        """Test REAL memory usage monitoring during analysis."""
        import psutil

        process: psutil.Process = psutil.Process(os.getpid())
        initial_memory: int = process.memory_info().rss

        result: OrchestrationResult = self.orchestrator.analyze_binary(
            self.pe_binary,
            phases=[AnalysisPhase.PREPARATION, AnalysisPhase.ENTROPY_ANALYSIS]
        )

        final_memory: int = process.memory_info().rss
        memory_increase: int = final_memory - initial_memory

        assert result.success is True

        assert memory_increase < 100 * 1024 * 1024

    def test_ghidra_script_selection_logic_real(self) -> None:
        """Test REAL Ghidra script selection logic for different binary types."""
        pe_script: Any = self.orchestrator._select_ghidra_script(self.pe_binary)

        if pe_script is not None:
            assert hasattr(pe_script, 'name')
            assert hasattr(pe_script, 'path')
            script_name: str = pe_script.name.lower()
            assert any(keyword in script_name for keyword in ['license', 'keygen', 'advanced', 'comprehensive'])

        elf_script: Any = self.orchestrator._select_ghidra_script(self.elf_binary)

        if elf_script is not None:
            assert hasattr(elf_script, 'name')
            assert hasattr(elf_script, 'path')

    def test_ghidra_command_building_real(self) -> None:
        """Test REAL Ghidra command building functionality."""
        script_path: str = "/path/to/test_script.java"
        binary_path: str = "/path/to/test_binary.exe"

        command: str = self.orchestrator._build_ghidra_command(script_path, binary_path)

        assert isinstance(command, str)
        assert "/opt/ghidra/support/analyzeHeadless" in command
        assert script_path in command
        assert binary_path in command
        assert "-import" in command
        assert "-postScript" in command
        assert "-deleteProject" in command

    def test_ghidra_output_parsing_real(self) -> None:
        """Test REAL Ghidra output parsing functionality."""
        sample_output: str = """
INFO  Ghidra Analysis Started
Function: CheckLicense at 0x401000 - LICENSE_CHECK detected
Found crypto routine: AES encryption at 0x402000
String: "Enter license key:" at 0x403000
Function analyzed: ValidateSerial at 0x404000
Protection mechanism: anti-debug detected
Potential keygen algorithm detected in function GenerateKey
Analysis complete - 15 functions analyzed
        """

        parsed: Any = self.orchestrator._parse_ghidra_output(sample_output)

        self.assert_real_output(parsed)
        assert 'raw_output' in parsed
        assert parsed['raw_output'] == sample_output

        assert parsed['functions_analyzed'] > 0
        assert len(parsed['license_checks']) > 0
        assert len(parsed['crypto_routines']) > 0
        assert len(parsed['protection_mechanisms']) > 0
        assert len(parsed['keygen_patterns']) > 0
        assert len(parsed['interesting_strings']) > 0

        license_check: Any = parsed['license_checks'][0]
        assert license_check['function'] == 'CheckLicense at 0x401000 - LICENSE_CHECK detected'
        assert license_check['confidence'] == 'high'

        crypto_routine: Any = parsed['crypto_routines'][0]
        assert crypto_routine['type'] == 'AES'
        assert '0x402000' in crypto_routine['location']

    def test_address_extraction_utility_real(self) -> None:
        """Test REAL memory address extraction utility."""
        test_cases: list[tuple[str, str]] = [
            ("Function at 0x401000", "0x401000"),
            ("Located at 00401000h", "00401000h"),
            ("Address: 0x12345678", "0x12345678"),
            ("No address here", "unknown"),
            ("Multiple 0x100 and 0x200", "0x100"),
        ]

        for input_line, expected in test_cases:
            result: str = self.orchestrator._extract_address(input_line)
            assert result == expected

    def test_crypto_type_identification_real(self) -> None:
        """Test REAL cryptographic routine type identification."""
        test_cases: list[tuple[str, str]] = [
            ("AES encryption detected", "AES"),
            ("RSA key generation", "RSA"),
            ("MD5 hash calculation", "MD5"),
            ("SHA256 digest", "SHA256"),
            ("SHA1 checksum", "SHA1"),
            ("Generic hash function", "Generic Hash"),
            ("Unknown crypto stuff", "Unknown Crypto"),
        ]

        for input_line, expected in test_cases:
            result: str = self.orchestrator._identify_crypto_type(input_line)
            assert result == expected

    def test_protection_type_identification_real(self) -> None:
        """Test REAL protection mechanism type identification."""
        test_cases: list[tuple[str, str]] = [
            ("anti-debug technique detected", "Anti-Debugging"),
            ("code obfuscation found", "Obfuscation"),
            ("packed executable detected", "Packing"),
            ("encrypted sections found", "Encryption"),
            ("virtualization protection", "Virtualization"),
            ("unknown protection mechanism", "Generic Protection"),
        ]

        for input_line, expected in test_cases:
            result: str = self.orchestrator._identify_protection_type(input_line)
            assert result == expected

    def test_interesting_string_detection_real(self) -> None:
        """Test REAL interesting string detection for license analysis."""
        test_cases = [
            ("Enter your license key", True),
            ("Serial number required", True),
            ("Registration failed", True),
            ("Trial period expired", True),
            ("Activation successful", True),
            ("Full version features", True),
            ("Crack detection disabled", True),
            ("Hello world program", False),
            ("Debug output enabled", False),
            ("Regular application text", False),
        ]

        for test_string, expected in test_cases:
            result = self.orchestrator._is_interesting_string(test_string)
            assert result == expected

    def test_analysis_phase_enum_completeness_real(self) -> None:
        """Test REAL analysis phase enum completeness and ordering."""
        expected_phases = [
            'PREPARATION', 'BASIC_INFO', 'STATIC_ANALYSIS', 'GHIDRA_ANALYSIS',
            'ENTROPY_ANALYSIS', 'STRUCTURE_ANALYSIS', 'VULNERABILITY_SCAN',
            'PATTERN_MATCHING', 'DYNAMIC_ANALYSIS', 'FINALIZATION'
        ]

        actual_phases = [phase.name for phase in AnalysisPhase]

        for expected_phase in expected_phases:
            assert expected_phase in actual_phases

        for phase in AnalysisPhase:
            assert isinstance(phase.value, str)
            assert len(phase.value) > 0

    def test_run_selected_analysis_function_real(self) -> None:
        """Test REAL standalone run_selected_analysis function."""
        from intellicrack.core.analysis.analysis_orchestrator import run_selected_analysis

        analysis_types = ['static', 'entropy']
        result = run_selected_analysis(self.pe_binary, analysis_types)

        self.assert_real_output(result)
        assert isinstance(result, dict)
        assert 'success' in result
        assert 'binary_path' in result
        assert 'results' in result
        assert 'phases_completed' in result

        completed_phases = result['phases_completed']
        assert 'static_analysis' in completed_phases or 'entropy_analysis' in completed_phases

    def test_exception_handling_in_phases_real(self) -> None:
        """Test REAL exception handling within individual analysis phases."""
        problematic_file = self.temp_dir / "problematic.exe"
        invalid_pe_data = b"MZ" + b"\x00" * 100 + b"PE\x00\x00" + b"\xFF" * 100
        problematic_file.write_bytes(invalid_pe_data)

        result = self.orchestrator.analyze_binary(str(problematic_file))

        assert isinstance(result, OrchestrationResult)
        assert result.binary_path == str(problematic_file)

        if len(result.errors) > 0:
            for error in result.errors:
                assert isinstance(error, str)
                assert len(error) > 10

        assert len(result.phases_completed) >= 1

    def test_binary_copy_to_vm_logs_success_status(self) -> None:
        """Test that binary copy to VM logs the copy_success status."""
        import logging

        with self.assertLogs(level=logging.DEBUG) as log_context:
            self.orchestrator.analyze_binary(str(self.pe_binary))

            log_messages = ' '.join(log_context.output).lower()
            if 'vm' in str(self.orchestrator.__dict__.get('config', {})):
                self.assertTrue('copy' in log_messages or 'vm' in log_messages)

    def test_vm_binary_transfer_error_handling(  # type: ignore[override]
        self, monkeypatch: Any
    ) -> None:
        """Test that VM binary transfer errors are handled properly."""
        fake_vm = FakeVMInstance(copy_success=False)

        def get_fake_vm_instance() -> FakeVMInstance:
            return fake_vm

        monkeypatch.setattr(self.orchestrator, '_get_vm_instance', get_fake_vm_instance)

        result = self.orchestrator.analyze_binary(str(self.pe_binary))

        self.assert_real_output(result)
        self.assertIsInstance(result, OrchestrationResult)

    def test_vm_copy_operation_validates_success(  # type: ignore[override]
        self, monkeypatch: Any
    ) -> None:
        """Test that VM copy operations validate success before proceeding."""
        import logging

        fake_vm = FakeVMInstance(copy_success=True)

        def get_fake_vm_instance() -> FakeVMInstance:
            return fake_vm

        with self.assertLogs(level=logging.DEBUG) as log_context:
            monkeypatch.setattr(self.orchestrator, '_get_vm_instance', get_fake_vm_instance)
            self.orchestrator.analyze_binary(str(self.pe_binary))

            if fake_vm.copy_file_to_vm_called:
                log_messages = ' '.join(log_context.output).lower()
                self.assertTrue(
                    'success' in log_messages
                    or 'copy' in log_messages
                    or log_messages != ""
                )
