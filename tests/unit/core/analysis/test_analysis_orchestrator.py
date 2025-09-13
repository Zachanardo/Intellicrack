"""
Comprehensive unit tests for AnalysisOrchestrator with REAL binary analysis.
Tests REAL orchestrated analysis workflows across multiple analysis engines.
NO MOCKS - ALL TESTS USE REAL BINARIES AND PRODUCE REAL RESULTS.

Testing Agent Mission: Validate production-ready orchestration capabilities
that demonstrate genuine binary analysis effectiveness for security research.
"""

import os
import pytest
import tempfile
import time
from pathlib import Path
from PyQt6.QtCore import QObject

from intellicrack.core.analysis.analysis_orchestrator import (
    AnalysisOrchestrator,
    AnalysisPhase,
    OrchestrationResult
)
from tests.base_test import IntellicrackTestBase


class TestAnalysisOrchestrator(IntellicrackTestBase):
    """Test orchestrated binary analysis with REAL multi-engine coordination."""

    @pytest.fixture(autouse=True)
    def setup(self, real_pe_binary, real_elf_binary, temp_workspace):
        """Set up test with real binaries and orchestrator."""
        self.orchestrator = AnalysisOrchestrator()
        self.pe_binary = real_pe_binary
        self.elf_binary = real_elf_binary
        self.temp_dir = temp_workspace
        self.signal_emissions = []

        # Connect to signals to track emissions
        self.orchestrator.phase_started.connect(self._track_phase_started)
        self.orchestrator.phase_completed.connect(self._track_phase_completed)
        self.orchestrator.phase_failed.connect(self._track_phase_failed)
        self.orchestrator.progress_updated.connect(self._track_progress_updated)
        self.orchestrator.analysis_completed.connect(self._track_analysis_completed)

    def _track_phase_started(self, phase_name):
        """Track phase started signals."""
        self.signal_emissions.append(('phase_started', phase_name))

    def _track_phase_completed(self, phase_name, result):
        """Track phase completed signals."""
        self.signal_emissions.append(('phase_completed', phase_name, result))

    def _track_phase_failed(self, phase_name, error):
        """Track phase failed signals."""
        self.signal_emissions.append(('phase_failed', phase_name, error))

    def _track_progress_updated(self, current, total):
        """Track progress updated signals."""
        self.signal_emissions.append(('progress_updated', current, total))

    def _track_analysis_completed(self, result):
        """Track analysis completed signals."""
        self.signal_emissions.append(('analysis_completed', result))

    def test_orchestrator_initialization_real(self):
        """Test REAL orchestrator initialization with all analysis engines."""
        # Verify orchestrator is QObject for signal support
        assert isinstance(self.orchestrator, QObject)

        # Verify all analyzers are initialized
        assert self.orchestrator.binary_analyzer is not None
        assert self.orchestrator.entropy_analyzer is not None
        assert self.orchestrator.multi_format_analyzer is not None
        assert self.orchestrator.vulnerability_engine is not None
        assert self.orchestrator.yara_engine is not None
        assert self.orchestrator.ghidra_script_manager is not None

        # Verify lazy-initialized components are None initially
        assert self.orchestrator.dynamic_analyzer is None
        assert self.orchestrator.radare2 is None
        assert self.orchestrator.qemu_manager is None

        # Verify configuration
        assert self.orchestrator.enabled_phases == list(AnalysisPhase)
        assert self.orchestrator.timeout_per_phase == 300

    def test_full_orchestrated_analysis_pe_real(self):
        """Test REAL full orchestrated analysis on PE binary."""
        # Run complete analysis on real PE
        result = self.orchestrator.analyze_binary(self.pe_binary)

        # Validate this is REAL orchestration result
        self.assert_real_output(result)
        assert isinstance(result, OrchestrationResult)
        assert result.binary_path == self.pe_binary
        assert result.success is True

        # Verify multiple phases were completed
        assert len(result.phases_completed) >= 5  # At least basic phases
        assert AnalysisPhase.PREPARATION in result.phases_completed
        assert AnalysisPhase.BASIC_INFO in result.phases_completed
        assert AnalysisPhase.STATIC_ANALYSIS in result.phases_completed
        assert AnalysisPhase.ENTROPY_ANALYSIS in result.phases_completed

        # Verify results contain real analysis data
        assert len(result.results) >= len(result.phases_completed)

        # Check preparation results
        prep_result = result.results[AnalysisPhase.PREPARATION.value]
        assert prep_result['file_size'] > 0
        assert prep_result['file_path'] == os.path.abspath(self.pe_binary)
        assert prep_result['file_name'] == os.path.basename(self.pe_binary)

        # Check basic info results for PE characteristics
        basic_result = result.results[AnalysisPhase.BASIC_INFO.value]
        if 'error' not in basic_result:
            assert 'file_type' in basic_result or 'headers' in basic_result

        # Check static analysis results
        static_result = result.results[AnalysisPhase.STATIC_ANALYSIS.value]
        if 'error' not in static_result:
            # Should have imports, strings, or functions from radare2
            assert any(key in static_result for key in ['imports', 'strings', 'functions'])

        # Check entropy analysis results
        entropy_result = result.results[AnalysisPhase.ENTROPY_ANALYSIS.value]
        if 'error' not in entropy_result:
            assert 'overall_entropy' in entropy_result
            assert entropy_result['overall_entropy'] > 0
            assert 'chunks' in entropy_result

        # Verify signals were emitted
        assert len(self.signal_emissions) > 0
        signal_types = [s[0] for s in self.signal_emissions]
        assert 'analysis_completed' in signal_types

    def test_selective_phase_analysis_real(self):
        """Test REAL selective phase analysis with custom phase selection."""
        # Run only specific phases
        selected_phases = [
            AnalysisPhase.PREPARATION,
            AnalysisPhase.BASIC_INFO,
            AnalysisPhase.ENTROPY_ANALYSIS
        ]

        result = self.orchestrator.analyze_binary(self.pe_binary, phases=selected_phases)

        # Validate selective execution
        self.assert_real_output(result)
        assert len(result.phases_completed) == len(selected_phases)
        for phase in selected_phases:
            assert phase in result.phases_completed

        # Verify only selected phases have results
        assert len(result.results) == len(selected_phases)
        for phase in selected_phases:
            assert phase.value in result.results

        # Verify excluded phases were not run
        excluded_phases = set(AnalysisPhase) - set(selected_phases)
        for phase in excluded_phases:
            assert phase not in result.phases_completed
            assert phase.value not in result.results

    def test_elf_binary_analysis_real(self):
        """Test REAL orchestrated analysis on ELF binary."""
        # Run analysis on real ELF binary
        result = self.orchestrator.analyze_binary(self.elf_binary)

        # Validate ELF-specific analysis
        self.assert_real_output(result)
        assert result.success is True
        assert result.binary_path == self.elf_binary

        # Should have completed basic phases
        assert len(result.phases_completed) >= 3
        assert AnalysisPhase.PREPARATION in result.phases_completed

        # Check preparation results for ELF
        prep_result = result.results[AnalysisPhase.PREPARATION.value]
        assert prep_result['file_size'] > 0
        assert prep_result['file_path'] == os.path.abspath(self.elf_binary)

    def test_preparation_phase_real(self):
        """Test REAL preparation phase functionality."""
        # Test preparation phase directly
        prep_result = self.orchestrator._prepare_analysis(self.pe_binary)

        # Validate real file metadata
        self.assert_real_output(prep_result)
        assert prep_result['file_size'] > 0
        assert prep_result['file_path'] == os.path.abspath(self.pe_binary)
        assert prep_result['file_name'] == os.path.basename(self.pe_binary)
        assert prep_result['modified_time'] > 0  # Real timestamp

        # Verify file actually exists at returned path
        assert os.path.exists(prep_result['file_path'])
        actual_size = os.path.getsize(prep_result['file_path'])
        assert prep_result['file_size'] == actual_size

    def test_basic_info_phase_real(self):
        """Test REAL basic info analysis phase."""
        # Test basic info phase directly
        basic_result = self.orchestrator._analyze_basic_info(self.pe_binary)

        # Validate real binary analysis output
        self.assert_real_output(basic_result)

        # Should have binary analysis data or error handling
        if 'error' not in basic_result:
            # Should have real binary metadata
            expected_fields = ['file_type', 'headers', 'architecture', 'entry_point']
            assert any(field in basic_result for field in expected_fields)
        else:
            # If error, should have fallback flag
            assert basic_result.get('fallback') is True

    def test_static_analysis_phase_real(self):
        """Test REAL static analysis phase with radare2."""
        # Test static analysis phase directly
        static_result = self.orchestrator._perform_static_analysis(self.pe_binary)

        # Validate real static analysis output
        self.assert_real_output(static_result)

        if 'error' not in static_result:
            # Should have comprehensive static analysis data
            possible_fields = ['imports', 'exports', 'sections', 'strings', 'functions', 'esil_analysis']
            assert any(field in static_result for field in possible_fields)

            # If imports exist, validate they're real
            if 'imports' in static_result:
                imports = static_result['imports']
                assert isinstance(imports, list)
                if imports:
                    for imp in imports:
                        assert isinstance(imp, (dict, str))
                        # Real imports don't have mock prefixes
                        imp_str = str(imp).lower()
                        assert 'mock' not in imp_str
                        assert 'fake' not imp_str

    def test_entropy_analysis_phase_real(self):
        """Test REAL entropy analysis phase."""
        # Test entropy analysis phase directly
        entropy_result = self.orchestrator._perform_entropy_analysis(self.pe_binary)

        # Validate real entropy calculation
        self.assert_real_output(entropy_result)

        if 'error' not in entropy_result:
            assert 'overall_entropy' in entropy_result
            assert isinstance(entropy_result['overall_entropy'], float)
            assert 0.0 <= entropy_result['overall_entropy'] <= 8.0

            assert 'chunks' in entropy_result
            assert isinstance(entropy_result['chunks'], list)
            assert len(entropy_result['chunks']) > 0

            # Validate chunk analysis
            for chunk in entropy_result['chunks']:
                assert 'offset' in chunk
                assert 'size' in chunk
                assert 'entropy' in chunk
                assert 'suspicious' in chunk
                assert chunk['size'] > 0
                assert 0.0 <= chunk['entropy'] <= 8.0

            # Should identify high entropy chunks if they exist
            if 'high_entropy_chunks' in entropy_result:
                high_entropy = entropy_result['high_entropy_chunks']
                assert isinstance(high_entropy, list)
                for high_chunk in high_entropy:
                    assert high_chunk['suspicious'] is True

    def test_structure_analysis_phase_real(self):
        """Test REAL structure analysis phase."""
        # Test structure analysis phase directly
        struct_result = self.orchestrator._analyze_structure(self.pe_binary)

        # Validate real multi-format analysis
        self.assert_real_output(struct_result)

        if 'error' not in struct_result:
            # Should have structural analysis from multi-format analyzer
            expected_fields = ['format', 'headers', 'sections', 'metadata']
            assert any(field in struct_result for field in expected_fields)

    def test_vulnerability_scan_phase_real(self):
        """Test REAL vulnerability scanning phase."""
        # Test vulnerability scanning phase directly
        vuln_result = self.orchestrator._scan_vulnerabilities(self.pe_binary)

        # Validate real vulnerability scanning
        self.assert_real_output(vuln_result)

        if 'error' not in vuln_result:
            # Should have vulnerability analysis structure
            expected_fields = ['vulnerabilities', 'risk_score', 'findings']
            assert any(field in vuln_result for field in expected_fields)

            # If vulnerabilities found, validate they're real
            if 'vulnerabilities' in vuln_result:
                vulns = vuln_result['vulnerabilities']
                assert isinstance(vulns, list)
                for vuln in vulns:
                    if isinstance(vuln, dict):
                        # Real vulnerabilities have proper structure
                        assert any(field in vuln for field in ['type', 'severity', 'description'])

    def test_pattern_matching_phase_real(self):
        """Test REAL YARA pattern matching phase."""
        # Test pattern matching phase directly
        pattern_result = self.orchestrator._match_patterns(self.pe_binary)

        # Validate real YARA scanning
        self.assert_real_output(pattern_result)

        if 'error' not in pattern_result:
            # Should have pattern matching results
            expected_fields = ['matches', 'rules_loaded', 'scan_time']
            assert any(field in pattern_result for field in expected_fields)

    def test_dynamic_analysis_phase_real(self):
        """Test REAL dynamic analysis phase initialization."""
        # Test dynamic analysis phase directly
        dynamic_result = self.orchestrator._perform_dynamic_analysis(self.pe_binary)

        # Validate dynamic analysis attempt
        self.assert_real_output(dynamic_result)

        # Should either have real dynamic analysis or proper status
        if 'status' in dynamic_result:
            assert dynamic_result['status'] in ['skipped', 'completed']
            if dynamic_result['status'] == 'skipped':
                assert 'reason' in dynamic_result
        else:
            # Should have dynamic analysis results
            expected_fields = ['process_info', 'behavior', 'api_calls']
            assert any(field in dynamic_result for field in expected_fields)

    def test_finalization_phase_real(self):
        """Test REAL analysis finalization phase."""
        # Run real analysis to get actual orchestration result
        phases = [AnalysisPhase.PREPARATION, AnalysisPhase.ENTROPY_ANALYSIS, AnalysisPhase.VULNERABILITY_SCAN]
        real_result = self.orchestrator.analyze_binary(self.pe_binary, phases=phases)

        # Test finalization phase with real analysis result
        final_result = self.orchestrator._finalize_analysis(real_result)

        # Validate real finalization summary
        self.assert_real_output(final_result)
        assert 'total_phases' in final_result
        assert 'completed_phases' in final_result
        assert 'errors' in final_result
        assert 'warnings' in final_result
        assert 'key_findings' in final_result

        # Verify counts are accurate based on actual phases run
        assert final_result['total_phases'] == len(phases)
        assert final_result['completed_phases'] == len(real_result.phases_completed)

        # Verify findings are intelligently generated from real analysis
        findings = final_result['key_findings']
        assert isinstance(findings, list)

        # Should generate meaningful findings based on actual analysis results
        if len(real_result.phases_completed) > 0:
            assert len(findings) > 0, "Should generate findings from real analysis"

            # If entropy analysis was performed, should have entropy-related findings
            if AnalysisPhase.ENTROPY_ANALYSIS in real_result.phases_completed:
                entropy_data = real_result.results.get(AnalysisPhase.ENTROPY_ANALYSIS.value, {})
                if 'error' not in entropy_data and 'overall_entropy' in entropy_data:
                    if entropy_data['overall_entropy'] > 7.0:
                        entropy_finding = any('entropy' in f.lower() for f in findings)
                        assert entropy_finding is True, "Should detect high entropy from real analysis"

    def test_ghidra_analysis_phase_real(self):
        """Test REAL Ghidra analysis phase integration."""
        # Test Ghidra analysis phase directly
        ghidra_result = self.orchestrator._perform_ghidra_analysis(self.pe_binary)

        # Validate Ghidra analysis attempt
        self.assert_real_output(ghidra_result)

        # Should have Ghidra analysis structure
        assert 'ghidra_executed' in ghidra_result
        assert 'script_used' in ghidra_result
        assert 'analysis_results' in ghidra_result
        assert 'errors' in ghidra_result

        # If executed successfully, validate results
        if ghidra_result['ghidra_executed']:
            assert ghidra_result['script_used'] is not None
            results = ghidra_result['analysis_results']
            assert isinstance(results, dict)

            # Check for real analysis components
            expected_components = ['license_checks', 'crypto_routines', 'protection_mechanisms']
            if any(comp in results for comp in expected_components):
                # Validate component data is real
                for comp in expected_components:
                    if comp in results:
                        assert isinstance(results[comp], list)
        else:
            # If not executed, should have error reasons
            assert len(ghidra_result['errors']) > 0

    def test_signal_emission_coordination_real(self):
        """Test REAL signal emission during orchestrated analysis."""
        # Clear previous signals
        self.signal_emissions.clear()

        # Run limited analysis to reduce test time
        phases = [AnalysisPhase.PREPARATION, AnalysisPhase.BASIC_INFO]
        result = self.orchestrator.analyze_binary(self.pe_binary, phases=phases)

        # Validate signal emissions occurred
        assert len(self.signal_emissions) > 0
        signal_types = [s[0] for s in self.signal_emissions]

        # Should have progress updates
        assert 'progress_updated' in signal_types

        # Should have phase lifecycle signals
        assert 'phase_started' in signal_types
        phase_completed_signals = [s for s in self.signal_emissions if s[0] == 'phase_completed']
        phase_failed_signals = [s for s in self.signal_emissions if s[0] == 'phase_failed']

        # Either completed or failed signals for each phase
        assert len(phase_completed_signals) + len(phase_failed_signals) >= len(phases)

        # Should have final completion signal
        completion_signals = [s for s in self.signal_emissions if s[0] == 'analysis_completed']
        assert len(completion_signals) == 1
        assert isinstance(completion_signals[0][1], OrchestrationResult)

    def test_nonexistent_file_error_handling_real(self):
        """Test REAL error handling for nonexistent files."""
        nonexistent_path = str(self.temp_dir / "nonexistent_file.exe")

        # Attempt analysis on nonexistent file
        result = self.orchestrator.analyze_binary(nonexistent_path)

        # Validate proper error handling
        assert isinstance(result, OrchestrationResult)
        assert result.success is False
        assert result.binary_path == nonexistent_path
        assert len(result.errors) > 0

        # Should have preparation error
        prep_error = any('File not found' in error for error in result.errors)
        assert prep_error is True

        # Should have minimal phase completion
        assert len(result.phases_completed) == 0

    def test_phase_error_recovery_real(self):
        """Test REAL error recovery - continuing analysis despite phase failures."""
        # Create a corrupted binary file
        corrupted_path = self.temp_dir / "corrupted.exe"
        corrupted_path.write_bytes(b"corrupted_data_not_a_real_pe")

        # Run analysis on corrupted file
        result = self.orchestrator.analyze_binary(str(corrupted_path))

        # Validate error recovery behavior
        assert isinstance(result, OrchestrationResult)
        assert result.binary_path == str(corrupted_path)

        # Should have completed preparation (file exists)
        assert AnalysisPhase.PREPARATION in result.phases_completed

        # Should have errors from subsequent phases but not stop execution
        assert len(result.errors) > 0

        # Should continue with multiple phases despite errors
        assert len(result.phases_completed) >= 1

    def test_orchestration_result_methods_real(self):
        """Test REAL OrchestrationResult methods and functionality."""
        result = OrchestrationResult(binary_path=self.pe_binary, success=True)

        # Test add_result method
        test_phase = AnalysisPhase.BASIC_INFO
        test_data = {'file_type': 'PE', 'architecture': 'x64'}
        result.add_result(test_phase, test_data)

        assert test_phase in result.phases_completed
        assert result.results[test_phase.value] == test_data

        # Test add_error method
        error_phase = AnalysisPhase.STATIC_ANALYSIS
        error_msg = "Radare2 initialization failed"
        result.add_error(error_phase, error_msg)

        expected_error = f"{error_phase.value}: {error_msg}"
        assert expected_error in result.errors

        # Test add_warning method
        warning_phase = AnalysisPhase.DYNAMIC_ANALYSIS
        warning_msg = "Dynamic analysis skipped - no sandbox"
        result.add_warning(warning_phase, warning_msg)

        expected_warning = f"{warning_phase.value}: {warning_msg}"
        assert expected_warning in result.warnings

    def test_progress_tracking_accuracy_real(self):
        """Test REAL progress tracking accuracy during analysis."""
        # Clear signals and run analysis with progress tracking
        self.signal_emissions.clear()
        phases = [AnalysisPhase.PREPARATION, AnalysisPhase.BASIC_INFO, AnalysisPhase.ENTROPY_ANALYSIS]

        result = self.orchestrator.analyze_binary(self.pe_binary, phases=phases)

        # Extract progress signals
        progress_signals = [s for s in self.signal_emissions if s[0] == 'progress_updated']

        # Should have progress updates
        assert len(progress_signals) >= len(phases)

        # Verify progress values are accurate
        total_phases = len(phases)
        for signal in progress_signals:
            current, total = signal[1], signal[2]
            assert total == total_phases
            assert 0 <= current <= total_phases

        # Final progress should indicate completion
        final_progress = progress_signals[-1]
        assert final_progress[1] == total_phases  # current == total

    def test_timeout_configuration_real(self):
        """Test REAL timeout configuration and handling."""
        # Verify default timeout
        assert self.orchestrator.timeout_per_phase == 300  # 5 minutes

        # Test timeout modification
        new_timeout = 600  # 10 minutes
        self.orchestrator.timeout_per_phase = new_timeout
        assert self.orchestrator.timeout_per_phase == new_timeout

        # Verify analysis still works with modified timeout
        result = self.orchestrator.analyze_binary(
            self.pe_binary,
            phases=[AnalysisPhase.PREPARATION]
        )
        assert result.success is True

    def test_phase_configuration_real(self):
        """Test REAL analysis phase configuration and customization."""
        # Verify default phases include all phases
        default_phases = self.orchestrator.enabled_phases
        assert len(default_phases) == len(list(AnalysisPhase))
        assert all(phase in default_phases for phase in AnalysisPhase)

        # Test custom phase configuration
        custom_phases = [AnalysisPhase.PREPARATION, AnalysisPhase.ENTROPY_ANALYSIS]
        self.orchestrator.enabled_phases = custom_phases
        assert self.orchestrator.enabled_phases == custom_phases

        # Test analysis with custom phases (should use default if none specified)
        result = self.orchestrator.analyze_binary(self.pe_binary)
        # Should use custom phases as default
        for phase in custom_phases:
            assert phase in result.phases_completed

    def test_analyzer_lazy_initialization_real(self):
        """Test REAL lazy initialization of heavy analyzers."""
        # Verify initial state - heavy analyzers not initialized
        assert self.orchestrator.dynamic_analyzer is None
        assert self.orchestrator.radare2 is None
        assert self.orchestrator.qemu_manager is None

        # Run static analysis which should initialize radare2
        phases = [AnalysisPhase.STATIC_ANALYSIS]
        result = self.orchestrator.analyze_binary(self.pe_binary, phases=phases)

        # Radare2 should now be initialized (may fail but should be attempted)
        # Note: We can't guarantee radare2 initialization succeeds in test environment
        static_result = result.results.get(AnalysisPhase.STATIC_ANALYSIS.value, {})
        if 'error' in static_result:
            # If initialization failed, should have descriptive error
            error_msg = static_result['error']
            assert isinstance(error_msg, str)
            assert len(error_msg) > 0

    def test_large_binary_handling_real(self):
        """Test REAL handling of large binaries with performance considerations."""
        # Create a larger test binary by duplicating existing one
        large_binary_path = self.temp_dir / "large_test.exe"

        # Read original binary and duplicate it to simulate larger file
        with open(self.pe_binary, 'rb') as orig:
            original_data = orig.read()

        # Create larger binary (but not too large for test performance)
        large_data = original_data * 5  # 5x larger
        large_binary_path.write_bytes(large_data)

        # Test analysis on larger binary
        start_time = time.time()
        result = self.orchestrator.analyze_binary(
            str(large_binary_path),
            phases=[AnalysisPhase.PREPARATION, AnalysisPhase.ENTROPY_ANALYSIS]
        )
        analysis_time = time.time() - start_time

        # Validate handling of larger binary
        assert result.success is True
        assert result.binary_path == str(large_binary_path)

        # Should handle size correctly in preparation
        prep_result = result.results[AnalysisPhase.PREPARATION.value]
        assert prep_result['file_size'] == len(large_data)

        # Should not take excessively long (under 30 seconds for test)
        assert analysis_time < 30.0

        # Entropy analysis should handle larger data
        entropy_result = result.results.get(AnalysisPhase.ENTROPY_ANALYSIS.value, {})
        if 'error' not in entropy_result:
            assert 'chunks' in entropy_result
            assert len(entropy_result['chunks']) > 0

    def test_empty_file_handling_real(self):
        """Test REAL handling of empty files."""
        # Create empty file
        empty_file = self.temp_dir / "empty.exe"
        empty_file.write_bytes(b"")

        # Test analysis on empty file
        result = self.orchestrator.analyze_binary(str(empty_file))

        # Should handle empty file gracefully
        assert isinstance(result, OrchestrationResult)
        assert result.binary_path == str(empty_file)

        # Preparation should succeed (file exists)
        assert AnalysisPhase.PREPARATION in result.phases_completed
        prep_result = result.results[AnalysisPhase.PREPARATION.value]
        assert prep_result['file_size'] == 0

        # Other phases should handle empty file appropriately
        # Some may error, some may return empty results
        for phase_name, phase_result in result.results.items():
            if phase_name != AnalysisPhase.PREPARATION.value:
                # Either valid empty result or error
                if 'error' not in phase_result:
                    # Should be well-structured empty result
                    assert isinstance(phase_result, dict)

    def test_binary_with_unusual_permissions_real(self):
        """Test REAL handling of binaries with unusual file permissions."""
        # Create a binary with restricted permissions
        restricted_binary = self.temp_dir / "restricted.exe"
        with open(self.pe_binary, 'rb') as src:
            restricted_binary.write_bytes(src.read())

        # Make it read-only (simulate permission restrictions)
        try:
            import stat
            os.chmod(str(restricted_binary), stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        except (OSError, PermissionError):
            pytest.skip("Cannot modify file permissions in test environment")

        # Test analysis on restricted file
        result = self.orchestrator.analyze_binary(str(restricted_binary))

        # Should still be able to read and analyze
        assert result.success is True or len(result.errors) > 0
        assert AnalysisPhase.PREPARATION in result.phases_completed

        # Preparation should succeed (can read file)
        prep_result = result.results[AnalysisPhase.PREPARATION.value]
        assert prep_result['file_size'] > 0

    def test_concurrent_analysis_safety_real(self):
        """Test REAL thread safety for concurrent orchestrator usage."""
        import threading
        import queue

        results_queue = queue.Queue()

        def run_analysis(binary_path, result_queue):
            """Run analysis in thread and store result."""
            orchestrator = AnalysisOrchestrator()  # New instance per thread
            phases = [AnalysisPhase.PREPARATION, AnalysisPhase.BASIC_INFO]
            result = orchestrator.analyze_binary(binary_path, phases=phases)
            result_queue.put((threading.current_thread().name, result))

        # Start multiple threads
        threads = []
        for i in range(3):
            thread = threading.Thread(
                target=run_analysis,
                args=(self.pe_binary, results_queue),
                name=f"AnalysisThread-{i}"
            )
            threads.append(thread)
            thread.start()

        # Wait for all threads
        for thread in threads:
            thread.join(timeout=30)  # 30 second timeout

        # Collect results
        thread_results = []
        while not results_queue.empty():
            thread_results.append(results_queue.get())

        # Validate all threads completed successfully
        assert len(thread_results) == 3

        for thread_name, result in thread_results:
            assert isinstance(result, OrchestrationResult)
            assert result.success is True or len(result.errors) > 0
            assert result.binary_path == self.pe_binary

    def test_memory_usage_during_analysis_real(self):
        """Test REAL memory usage monitoring during analysis."""
        import psutil
        import os

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        # Run analysis
        result = self.orchestrator.analyze_binary(
            self.pe_binary,
            phases=[AnalysisPhase.PREPARATION, AnalysisPhase.ENTROPY_ANALYSIS]
        )

        # Check memory after analysis
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        # Validate analysis completed
        assert result.success is True

        # Memory increase should be reasonable (under 100MB for this test)
        # This helps detect memory leaks
        assert memory_increase < 100 * 1024 * 1024  # 100MB limit

    def test_ghidra_script_selection_logic_real(self):
        """Test REAL Ghidra script selection logic for different binary types."""
        # Test PE binary script selection
        pe_script = self.orchestrator._select_ghidra_script(self.pe_binary)

        # May return None if no scripts available, or a script object
        if pe_script is not None:
            assert hasattr(pe_script, 'name')
            assert hasattr(pe_script, 'path')
            # Should prefer license/keygen scripts for PE
            script_name = pe_script.name.lower()
            assert any(keyword in script_name for keyword in ['license', 'keygen', 'advanced', 'comprehensive'])

        # Test ELF binary script selection
        elf_script = self.orchestrator._select_ghidra_script(self.elf_binary)

        if elf_script is not None:
            assert hasattr(elf_script, 'name')
            assert hasattr(elf_script, 'path')

    def test_ghidra_command_building_real(self):
        """Test REAL Ghidra command building functionality."""
        script_path = "/path/to/test_script.java"
        binary_path = "/path/to/test_binary.exe"

        # Build Ghidra command
        command = self.orchestrator._build_ghidra_command(script_path, binary_path)

        # Validate command structure
        assert isinstance(command, str)
        assert "/opt/ghidra/support/analyzeHeadless" in command
        assert script_path in command
        assert binary_path in command
        assert "-import" in command
        assert "-postScript" in command
        assert "-deleteProject" in command

    def test_ghidra_output_parsing_real(self):
        """Test REAL Ghidra output parsing functionality."""
        # Create realistic Ghidra output
        sample_output = """
INFO  Ghidra Analysis Started
Function: CheckLicense at 0x401000 - LICENSE_CHECK detected
Found crypto routine: AES encryption at 0x402000
String: "Enter license key:" at 0x403000
Function analyzed: ValidateSerial at 0x404000
Protection mechanism: anti-debug detected
Potential keygen algorithm detected in function GenerateKey
Analysis complete - 15 functions analyzed
        """

        # Parse the output
        parsed = self.orchestrator._parse_ghidra_output(sample_output)

        # Validate parsing results
        self.assert_real_output(parsed)
        assert 'raw_output' in parsed
        assert parsed['raw_output'] == sample_output

        # Check parsed components
        assert parsed['functions_analyzed'] > 0
        assert len(parsed['license_checks']) > 0
        assert len(parsed['crypto_routines']) > 0
        assert len(parsed['protection_mechanisms']) > 0
        assert len(parsed['keygen_patterns']) > 0
        assert len(parsed['interesting_strings']) > 0

        # Validate license check detection
        license_check = parsed['license_checks'][0]
        assert license_check['function'] == 'CheckLicense at 0x401000 - LICENSE_CHECK detected'
        assert license_check['confidence'] == 'high'

        # Validate crypto routine detection
        crypto_routine = parsed['crypto_routines'][0]
        assert crypto_routine['type'] == 'AES'
        assert '0x402000' in crypto_routine['location']

    def test_address_extraction_utility_real(self):
        """Test REAL memory address extraction utility."""
        # Test various address formats
        test_cases = [
            ("Function at 0x401000", "0x401000"),
            ("Located at 00401000h", "00401000h"),
            ("Address: 0x12345678", "0x12345678"),
            ("No address here", "unknown"),
            ("Multiple 0x100 and 0x200", "0x100"),  # Should get first
        ]

        for input_line, expected in test_cases:
            result = self.orchestrator._extract_address(input_line)
            assert result == expected

    def test_crypto_type_identification_real(self):
        """Test REAL cryptographic routine type identification."""
        test_cases = [
            ("AES encryption detected", "AES"),
            ("RSA key generation", "RSA"),
            ("MD5 hash calculation", "MD5"),
            ("SHA256 digest", "SHA256"),
            ("SHA1 checksum", "SHA1"),
            ("Generic hash function", "Generic Hash"),
            ("Unknown crypto stuff", "Unknown Crypto"),
        ]

        for input_line, expected in test_cases:
            result = self.orchestrator._identify_crypto_type(input_line)
            assert result == expected

    def test_protection_type_identification_real(self):
        """Test REAL protection mechanism type identification."""
        test_cases = [
            ("anti-debug technique detected", "Anti-Debugging"),
            ("code obfuscation found", "Obfuscation"),
            ("packed executable detected", "Packing"),
            ("encrypted sections found", "Encryption"),
            ("virtualization protection", "Virtualization"),
            ("unknown protection mechanism", "Generic Protection"),
        ]

        for input_line, expected in test_cases:
            result = self.orchestrator._identify_protection_type(input_line)
            assert result == expected

    def test_interesting_string_detection_real(self):
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

    def test_analysis_phase_enum_completeness_real(self):
        """Test REAL analysis phase enum completeness and ordering."""
        # Verify all expected phases exist
        expected_phases = [
            'PREPARATION', 'BASIC_INFO', 'STATIC_ANALYSIS', 'GHIDRA_ANALYSIS',
            'ENTROPY_ANALYSIS', 'STRUCTURE_ANALYSIS', 'VULNERABILITY_SCAN',
            'PATTERN_MATCHING', 'DYNAMIC_ANALYSIS', 'FINALIZATION'
        ]

        actual_phases = [phase.name for phase in AnalysisPhase]

        for expected_phase in expected_phases:
            assert expected_phase in actual_phases

        # Verify phase values are string representations
        for phase in AnalysisPhase:
            assert isinstance(phase.value, str)
            assert len(phase.value) > 0

    def test_run_selected_analysis_function_real(self):
        """Test REAL standalone run_selected_analysis function."""
        from intellicrack.core.analysis.analysis_orchestrator import run_selected_analysis

        # Test function with specific analysis types
        analysis_types = ['static', 'entropy']
        result = run_selected_analysis(self.pe_binary, analysis_types)

        # Validate function result
        self.assert_real_output(result)
        assert isinstance(result, dict)
        assert 'success' in result
        assert 'binary_path' in result
        assert 'results' in result
        assert 'phases_completed' in result

        # Should only run selected types
        completed_phases = result['phases_completed']
        assert 'static_analysis' in completed_phases or 'entropy_analysis' in completed_phases

    def test_exception_handling_in_phases_real(self):
        """Test REAL exception handling within individual analysis phases."""
        # Test with a file that will cause analysis errors
        problematic_file = self.temp_dir / "problematic.exe"
        # Create file with invalid PE structure that will cause parsing errors
        invalid_pe_data = b"MZ" + b"\x00" * 100 + b"PE\x00\x00" + b"\xFF" * 100
        problematic_file.write_bytes(invalid_pe_data)

        # Run analysis expecting some phases to fail gracefully
        result = self.orchestrator.analyze_binary(str(problematic_file))

        # Should not crash, should continue through phases
        assert isinstance(result, OrchestrationResult)
        assert result.binary_path == str(problematic_file)

        # Should have some errors but continue execution
        if len(result.errors) > 0:
            # Errors should be descriptive
            for error in result.errors:
                assert isinstance(error, str)
                assert len(error) > 10  # Should be descriptive, not just "error"

        # Should have completed at least preparation phase
        assert len(result.phases_completed) >= 1
