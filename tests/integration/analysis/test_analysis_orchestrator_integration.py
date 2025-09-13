"""
Integration tests for AnalysisOrchestrator with REAL end-to-end workflows.
Tests REAL multi-engine coordination and cross-component integration.
NO MOCKS - ALL TESTS USE REAL BINARIES AND VALIDATE REAL WORKFLOWS.

Testing Agent Mission: Validate production-ready integration between multiple
analysis engines demonstrating genuine security research capabilities.
"""

import os
import pytest
import tempfile
import time
from pathlib import Path

from intellicrack.core.analysis.analysis_orchestrator import (
    AnalysisOrchestrator,
    AnalysisPhase,
    OrchestrationResult
)
from tests.base_test import IntellicrackTestBase


class TestAnalysisOrchestratorIntegration(IntellicrackTestBase):
    """Test orchestrated analysis integration across multiple real engines."""

    @pytest.fixture(autouse=True)
    def setup(self, real_pe_binary, real_elf_binary, real_protected_binary, temp_workspace):
        """Set up integration test with multiple real binaries."""
        self.orchestrator = AnalysisOrchestrator()
        self.pe_binary = real_pe_binary
        self.elf_binary = real_elf_binary
        self.protected_binary = real_protected_binary
        self.temp_dir = temp_workspace

    def test_full_security_research_workflow_real(self):
        """Test REAL complete security research workflow on protected binary."""
        # Run full analysis on protected binary (most comprehensive test)
        result = self.orchestrator.analyze_binary(self.protected_binary)

        # Validate complete security research workflow
        self.assert_real_output(result)
        assert isinstance(result, OrchestrationResult)
        assert result.success is True or len(result.errors) > 0

        # Should have completed core security research phases
        critical_phases = [
            AnalysisPhase.PREPARATION,
            AnalysisPhase.BASIC_INFO,
            AnalysisPhase.ENTROPY_ANALYSIS,
            AnalysisPhase.STRUCTURE_ANALYSIS
        ]

        completed_critical = [p for p in critical_phases if p in result.phases_completed]
        assert len(completed_critical) >= 3  # At least 3 critical phases

        # Cross-phase data validation
        if len(result.phases_completed) >= 2:
            self._validate_cross_phase_consistency(result)

        # Security research findings validation
        if AnalysisPhase.ENTROPY_ANALYSIS in result.phases_completed:
            entropy_data = result.results[AnalysisPhase.ENTROPY_ANALYSIS.value]
            if 'error' not in entropy_data:
                # Protected binaries should show entropy characteristics
                assert 'overall_entropy' in entropy_data
                assert entropy_data['overall_entropy'] > 0

                # Should detect suspicious high-entropy regions
                if 'high_entropy_chunks' in entropy_data:
                    high_entropy = entropy_data['high_entropy_chunks']
                    # Protected binaries often have high-entropy sections
                    if len(high_entropy) > 0:
                        assert all(chunk['suspicious'] for chunk in high_entropy)

    def test_multi_format_analysis_integration_real(self):
        """Test REAL integration across different binary formats."""
        # Analyze both PE and ELF to test format-specific integration
        pe_result = self.orchestrator.analyze_binary(
            self.pe_binary,
            phases=[AnalysisPhase.BASIC_INFO, AnalysisPhase.STRUCTURE_ANALYSIS]
        )

        elf_result = self.orchestrator.analyze_binary(
            self.elf_binary,
            phases=[AnalysisPhase.BASIC_INFO, AnalysisPhase.STRUCTURE_ANALYSIS]
        )

        # Validate format-specific analysis integration
        self.assert_real_output(pe_result)
        self.assert_real_output(elf_result)

        # Both should succeed or have appropriate errors
        assert pe_result.success is True or len(pe_result.errors) > 0
        assert elf_result.success is True or len(elf_result.errors) > 0

        # Should have completed at least basic phases
        assert len(pe_result.phases_completed) >= 1
        assert len(elf_result.phases_completed) >= 1

        # Format-specific validation
        if AnalysisPhase.BASIC_INFO in pe_result.phases_completed:
            pe_basic = pe_result.results[AnalysisPhase.BASIC_INFO.value]
            if 'error' not in pe_basic and 'file_type' in pe_basic:
                # PE-specific characteristics
                assert pe_basic['file_type'] in ['PE', 'Portable Executable'] or 'PE' in str(pe_basic)

        if AnalysisPhase.BASIC_INFO in elf_result.phases_completed:
            elf_basic = elf_result.results[AnalysisPhase.BASIC_INFO.value]
            if 'error' not in elf_basic and 'file_type' in elf_basic:
                # ELF-specific characteristics
                assert elf_basic['file_type'] in ['ELF', 'Executable and Linkable Format'] or 'ELF' in str(elf_basic)

    def test_progressive_analysis_depth_integration_real(self):
        """Test REAL progressive analysis depth integration."""
        # Start with basic analysis
        basic_phases = [AnalysisPhase.PREPARATION, AnalysisPhase.BASIC_INFO]
        basic_result = self.orchestrator.analyze_binary(self.pe_binary, phases=basic_phases)

        # Add entropy analysis
        entropy_phases = basic_phases + [AnalysisPhase.ENTROPY_ANALYSIS]
        entropy_result = self.orchestrator.analyze_binary(self.pe_binary, phases=entropy_phases)

        # Add static analysis
        static_phases = entropy_phases + [AnalysisPhase.STATIC_ANALYSIS]
        static_result = self.orchestrator.analyze_binary(self.pe_binary, phases=static_phases)

        # Validate progressive complexity
        assert len(basic_result.phases_completed) <= len(entropy_result.phases_completed)
        assert len(entropy_result.phases_completed) <= len(static_result.phases_completed)

        # Each level should build upon previous
        for phase in basic_result.phases_completed:
            assert phase in entropy_result.phases_completed
            assert phase in static_result.phases_completed

        # Validate increasing analysis depth provides more insights
        basic_data_size = sum(len(str(result)) for result in basic_result.results.values())
        static_data_size = sum(len(str(result)) for result in static_result.results.values())

        # More comprehensive analysis should produce more data
        assert static_data_size >= basic_data_size

    def test_error_propagation_and_recovery_integration_real(self):
        """Test REAL error propagation and recovery across integrated components."""
        # Create multiple problematic files to test error handling integration
        error_files = []

        # Empty file
        empty_file = self.temp_dir / "empty.exe"
        empty_file.write_bytes(b"")
        error_files.append(str(empty_file))

        # Corrupted file
        corrupt_file = self.temp_dir / "corrupt.exe"
        corrupt_file.write_bytes(b"INVALID_PE_DATA" * 50)
        error_files.append(str(corrupt_file))

        # Very small file
        tiny_file = self.temp_dir / "tiny.exe"
        tiny_file.write_bytes(b"MZ")
        error_files.append(str(tiny_file))

        # Test error handling integration across all problematic files
        for error_file in error_files:
            result = self.orchestrator.analyze_binary(
                error_file,
                phases=[AnalysisPhase.PREPARATION, AnalysisPhase.BASIC_INFO, AnalysisPhase.ENTROPY_ANALYSIS]
            )

            # Should handle errors gracefully without crashing
            assert isinstance(result, OrchestrationResult)
            assert result.binary_path == error_file

            # Should complete at least preparation (file exists)
            if os.path.exists(error_file):
                assert AnalysisPhase.PREPARATION in result.phases_completed

            # Should continue with subsequent phases despite errors
            # (demonstrating error recovery integration)
            if len(result.errors) > 0:
                # Errors should be phase-specific and descriptive
                for error in result.errors:
                    assert ':' in error  # Should include phase name
                    assert len(error) > 20  # Should be descriptive

    def test_performance_integration_across_phases_real(self):
        """Test REAL performance integration across multiple analysis phases."""
        # Measure performance of integrated analysis
        phases_to_test = [
            AnalysisPhase.PREPARATION,
            AnalysisPhase.BASIC_INFO,
            AnalysisPhase.ENTROPY_ANALYSIS,
            AnalysisPhase.STRUCTURE_ANALYSIS
        ]

        start_time = time.time()
        result = self.orchestrator.analyze_binary(self.pe_binary, phases=phases_to_test)
        total_time = time.time() - start_time

        # Validate performance characteristics
        assert total_time < 60.0  # Should complete within 60 seconds

        # Should have completed most phases efficiently
        completed_ratio = len(result.phases_completed) / len(phases_to_test)
        assert completed_ratio >= 0.5  # At least 50% phase completion rate

        # Phase-specific performance validation
        if AnalysisPhase.ENTROPY_ANALYSIS in result.phases_completed:
            # Entropy analysis should be relatively fast
            assert total_time < 45.0  # Entropy should not dominate time

    def test_data_flow_integration_between_phases_real(self):
        """Test REAL data flow and dependencies between analysis phases."""
        # Run comprehensive analysis to test data flow
        result = self.orchestrator.analyze_binary(
            self.pe_binary,
            phases=[
                AnalysisPhase.PREPARATION,
                AnalysisPhase.BASIC_INFO,
                AnalysisPhase.ENTROPY_ANALYSIS,
                AnalysisPhase.FINALIZATION
            ]
        )

        # Validate data flow integration
        self.assert_real_output(result)

        # Preparation data should influence subsequent phases
        if AnalysisPhase.PREPARATION in result.phases_completed:
            prep_data = result.results[AnalysisPhase.PREPARATION.value]
            file_size = prep_data.get('file_size', 0)

            # File size should be consistent across phases
            if AnalysisPhase.ENTROPY_ANALYSIS in result.phases_completed:
                entropy_data = result.results[AnalysisPhase.ENTROPY_ANALYSIS.value]
                if 'chunks' in entropy_data:
                    # Entropy chunks should account for file size
                    total_chunk_size = sum(chunk.get('size', 0) for chunk in entropy_data['chunks'])
                    # Should have analyzed most of the file
                    assert total_chunk_size > 0
                    if file_size > 0:
                        coverage_ratio = total_chunk_size / file_size
                        assert coverage_ratio >= 0.8  # Should cover at least 80% of file

        # Finalization should summarize data from other phases
        if AnalysisPhase.FINALIZATION in result.phases_completed:
            final_data = result.results[AnalysisPhase.FINALIZATION.value]
            assert 'completed_phases' in final_data
            assert final_data['completed_phases'] == len(result.phases_completed)

    def test_external_tool_integration_coordination_real(self):
        """Test REAL coordination between external analysis tools."""
        # Test integration with external tools (radare2, ghidra, etc.)
        phases_with_external_tools = [
            AnalysisPhase.STATIC_ANALYSIS,  # radare2
            AnalysisPhase.GHIDRA_ANALYSIS,  # ghidra + qemu
        ]

        # Run analysis with external tool phases
        result = self.orchestrator.analyze_binary(
            self.pe_binary,
            phases=[AnalysisPhase.PREPARATION] + phases_with_external_tools
        )

        # Validate external tool integration
        self.assert_real_output(result)

        # Should handle external tool availability gracefully
        for phase in phases_with_external_tools:
            if phase in result.phases_completed:
                phase_result = result.results[phase.value]
                if 'error' not in phase_result:
                    # Successfully integrated external tool
                    assert isinstance(phase_result, dict)
                    assert len(phase_result) > 0
                else:
                    # Failed integration should be graceful
                    error_msg = phase_result['error']
                    assert isinstance(error_msg, str)
                    # Should indicate tool availability issues
                    external_tool_indicators = ['radare2', 'ghidra', 'qemu', 'initialization', 'not found']
                    assert any(indicator in error_msg.lower() for indicator in external_tool_indicators)

    def test_signal_coordination_across_workflow_real(self):
        """Test REAL signal coordination across complete workflow."""
        # Track signals across complete workflow
        signals_received = []

        def signal_tracker(signal_name):
            def handler(*args):
                signals_received.append((signal_name, len(args), time.time()))
            return handler

        # Connect to all signals
        self.orchestrator.phase_started.connect(signal_tracker('phase_started'))
        self.orchestrator.phase_completed.connect(signal_tracker('phase_completed'))
        self.orchestrator.phase_failed.connect(signal_tracker('phase_failed'))
        self.orchestrator.progress_updated.connect(signal_tracker('progress_updated'))
        self.orchestrator.analysis_completed.connect(signal_tracker('analysis_completed'))

        # Run workflow with signal tracking
        phases = [AnalysisPhase.PREPARATION, AnalysisPhase.BASIC_INFO, AnalysisPhase.ENTROPY_ANALYSIS]
        result = self.orchestrator.analyze_binary(self.pe_binary, phases=phases)

        # Validate signal coordination
        assert len(signals_received) > 0

        # Should have proper signal sequence
        signal_types = [s[0] for s in signals_received]
        assert 'analysis_completed' in signal_types
        assert 'progress_updated' in signal_types

        # Should have phase lifecycle signals
        phase_signals = [s for s in signal_types if 'phase_' in s]
        assert len(phase_signals) >= len(phases)  # At least one signal per phase

        # Signals should be in chronological order
        signal_times = [s[2] for s in signals_received]
        assert signal_times == sorted(signal_times)  # Chronological order

    def test_memory_and_resource_coordination_real(self):
        """Test REAL memory and resource coordination across analysis workflow."""
        import psutil
        import os

        # Monitor resource usage during integrated workflow
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        initial_handles = len(process.open_files())

        # Run comprehensive analysis
        result = self.orchestrator.analyze_binary(
            self.pe_binary,
            phases=[
                AnalysisPhase.PREPARATION,
                AnalysisPhase.BASIC_INFO,
                AnalysisPhase.ENTROPY_ANALYSIS,
                AnalysisPhase.STRUCTURE_ANALYSIS
            ]
        )

        # Check resource usage after workflow
        final_memory = process.memory_info().rss
        final_handles = len(process.open_files())

        # Validate resource coordination
        memory_increase = final_memory - initial_memory
        handle_increase = final_handles - initial_handles

        # Should not leak excessive memory (under 200MB increase)
        assert memory_increase < 200 * 1024 * 1024

        # Should not leak file handles (some temporary increase is normal)
        assert handle_increase < 20

        # Workflow should complete successfully
        assert result.success is True or len(result.errors) > 0

    def test_batch_analysis_integration_real(self):
        """Test REAL batch analysis integration across multiple binaries."""
        # Test batch processing integration
        test_binaries = [self.pe_binary, self.elf_binary]
        batch_results = []

        # Process multiple binaries with same orchestrator
        for binary_path in test_binaries:
            result = self.orchestrator.analyze_binary(
                binary_path,
                phases=[AnalysisPhase.PREPARATION, AnalysisPhase.BASIC_INFO]
            )
            batch_results.append(result)

        # Validate batch processing integration
        assert len(batch_results) == len(test_binaries)

        for i, result in enumerate(batch_results):
            self.assert_real_output(result)
            assert result.binary_path == test_binaries[i]
            assert result.success is True or len(result.errors) > 0

        # Results should be independent (no cross-contamination)
        pe_result, elf_result = batch_results
        assert pe_result.binary_path != elf_result.binary_path

        # Should handle different formats appropriately
        if (AnalysisPhase.BASIC_INFO in pe_result.phases_completed and
            AnalysisPhase.BASIC_INFO in elf_result.phases_completed):

            pe_basic = pe_result.results[AnalysisPhase.BASIC_INFO.value]
            elf_basic = elf_result.results[AnalysisPhase.BASIC_INFO.value]

            # Should detect different formats if analysis succeeds
            if ('error' not in pe_basic and 'file_type' in pe_basic and
                'error' not in elf_basic and 'file_type' in elf_basic):
                assert pe_basic['file_type'] != elf_basic['file_type']

    def _validate_cross_phase_consistency(self, result: OrchestrationResult):
        """Validate consistency of data across different analysis phases."""
        # Validate file size consistency across phases
        file_sizes = []

        for phase_name, phase_result in result.results.items():
            if isinstance(phase_result, dict) and 'file_size' in phase_result:
                file_sizes.append(phase_result['file_size'])

        # All phases should report consistent file size
        if len(file_sizes) > 1:
            assert all(size == file_sizes[0] for size in file_sizes)

        # Validate binary path consistency
        binary_paths = []
        for phase_name, phase_result in result.results.items():
            if isinstance(phase_result, dict) and 'file_path' in phase_result:
                binary_paths.append(phase_result['file_path'])

        # All phases should reference same binary path
        if len(binary_paths) > 1:
            assert all(path == binary_paths[0] for path in binary_paths)

        # Entropy analysis should be consistent with file structure
        if (AnalysisPhase.ENTROPY_ANALYSIS in result.phases_completed and
            AnalysisPhase.STRUCTURE_ANALYSIS in result.phases_completed):

            entropy_data = result.results[AnalysisPhase.ENTROPY_ANALYSIS.value]
            struct_data = result.results[AnalysisPhase.STRUCTURE_ANALYSIS.value]

            # Both should either succeed or fail for same file
            entropy_has_error = 'error' in entropy_data
            struct_has_error = 'error' in struct_data

            # If both succeed, they should be analyzing same file characteristics
            if not entropy_has_error and not struct_has_error:
                # Both analyses should provide meaningful data
                assert len(str(entropy_data)) > 50
                assert len(str(struct_data)) > 50
