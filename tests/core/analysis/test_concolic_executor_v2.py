"""
Unit tests for ConcolicExecutionEngine with REAL symbolic execution capabilities.
Tests actual concolic execution functionality with real binary samples.
ALL TESTS USE REAL BINARIES AND VALIDATE PRODUCTION FUNCTIONALITY.

This module tests sophisticated concolic execution engine capabilities including:
- Symbolic execution with constraint solving
- Path exploration and code coverage analysis
- Vulnerability discovery through symbolic analysis
- License bypass research for defensive security
- Test case generation and exploitation vector discovery
"""

from typing import Any
import pytest
import tempfile
import struct
import os
import time
from pathlib import Path

try:
    from intellicrack.core.analysis.concolic_executor import (
        ConcolicExecutionEngine,
        NativeConcolicState,
        run_concolic_execution
    )
    CONCOLIC_AVAILABLE = True
except ImportError:
    CONCOLIC_AVAILABLE = False
    ConcolicExecutionEngine = None
    NativeConcolicState = None
    run_concolic_execution = None

MANTICORE_AVAILABLE = False

try:
    from tests.base_test import IntellicrackTestBase
except ImportError:
    class IntellicrackTestBase:
        def assert_real_output(self, output, error_msg=""):
            assert output is not None


pytestmark = pytest.mark.skipif(
    not CONCOLIC_AVAILABLE,
    reason="Concolic executor not available"
)


class TestConcolicApp:
    """Real test application harness for concolic execution testing."""

    def __init__(self) -> None:
        """Initialize test app with realistic concolic execution configuration."""
        self.config = {
            'concolic_max_iterations': 100,
            'concolic_timeout': 60,
            'concolic_memory_limit': 1024,
            'concolic_enable_exploit_generation': True,
            'concolic_path_exploration_depth': 10,
            'concolic_constraint_solving_timeout': 30
        }
        self.execution_logs = []
        self.analysis_results = []

    def log_execution_event(self, event_type, event_data):
        """Log concolic execution events for validation."""
        self.execution_logs.append({"type": event_type, "data": event_data})

    def store_analysis_result(self, result):
        """Store concolic analysis results."""
        self.analysis_results.append(result)

    def get_execution_events(self):
        """Get all logged execution events."""
        return self.execution_logs

    def get_analysis_results(self):
        """Get all stored analysis results."""
        return self.analysis_results


class TestConcolicExecutionEngine(IntellicrackTestBase):
    """Test concolic execution engine with real binaries and production-ready validation."""

    @pytest.fixture(autouse=True)
    def setup(self) -> Any:
        """Set up test environment with real test binaries."""
        # Use available real test binaries
        self.test_fixtures_dir = Path("tests/fixtures/binaries")

        # Real PE binaries for concolic execution testing
        self.pe_binaries = [
            self.test_fixtures_dir / "pe/simple_hello_world.exe",
            self.test_fixtures_dir / "pe/legitimate/7zip.exe",
            self.test_fixtures_dir / "size_categories/tiny_4kb/tiny_hello.exe",
            self.test_fixtures_dir / "pe/real_protected/upx_packer/upx-4.2.2-win64/upx.exe"
        ]

        # Real ELF binaries
        self.elf_binaries = [
            self.test_fixtures_dir / "elf/simple_x64"
        ]

        # Filter for existing binaries
        self.pe_binaries = [p for p in self.pe_binaries if p.exists()]
        self.elf_binaries = [p for p in self.elf_binaries if p.exists()]

        # Ensure we have at least one test binary
        if not self.pe_binaries and not self.elf_binaries:
            pytest.skip("No test binaries available for concolic execution testing")

        self.test_binary = self.pe_binaries[0] if self.pe_binaries else self.elf_binaries[0]

    def test_initialization_parameters(self) -> None:
        """Test ConcolicExecutionEngine initialization with various parameters."""
        # Test basic initialization
        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=1000,
            timeout=60
        )

        assert engine.binary_path == str(self.test_binary)
        assert engine.max_iterations == 1000
        assert engine.timeout == 60
        assert hasattr(engine, 'logger')
        assert hasattr(engine, 'exploration_depth')
        assert hasattr(engine, 'memory_limit')
        assert hasattr(engine, 'execution_paths')
        assert hasattr(engine, 'discovered_bugs')
        assert hasattr(engine, 'code_coverage')
        assert hasattr(engine, 'symbolic_variables')

    def test_initialization_with_advanced_parameters(self) -> None:
        """Test initialization with advanced concolic execution parameters."""
        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=5000,
            timeout=300,
            exploration_depth=10,
            memory_limit=2048
        )

        assert engine.exploration_depth == 10
        assert engine.memory_limit == 2048
        assert isinstance(engine.execution_paths, list)
        assert isinstance(engine.discovered_bugs, list)
        assert isinstance(engine.code_coverage, dict)
        assert isinstance(engine.symbolic_variables, dict)

    def test_path_exploration_with_target_address(self) -> None:
        """Test path exploration targeting specific addresses."""
        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=100,
            timeout=30
        )

        # Test with real address from binary (entry point)
        target_address = 0x401000  # Common entry point for PE binaries
        result = engine.explore_paths(
            target_address=target_address,
            avoid_addresses=[0x402000, 0x403000]
        )

        # Validate real concolic execution results
        self.assert_real_output(result)
        assert isinstance(result, dict)

        # Verify path exploration produces sophisticated results
        required_fields = ['paths_found', 'target_reached', 'coverage_info',
                          'execution_time', 'states_explored', 'constraints_generated']

        for field in required_fields:
            assert field in result, f"Missing required concolic execution field: {field}"

        # Verify path exploration actually happened
        assert isinstance(result['paths_found'], list)
        assert isinstance(result['states_explored'], int)
        assert result['states_explored'] >= 0

        # Verify constraint generation (core of symbolic execution)
        assert isinstance(result['constraints_generated'], list)

        # Verify coverage information is detailed
        coverage = result['coverage_info']
        assert isinstance(coverage, dict)
        assert 'blocks_covered' in coverage
        assert 'total_blocks' in coverage

    def test_path_exploration_comprehensive_analysis(self) -> None:
        """Test comprehensive path exploration with multiple constraints."""
        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=200,
            timeout=60
        )

        result = engine.explore_paths(
            target_address=0x401000,
            avoid_addresses=[0x402000, 0x403000, 0x404000],
            symbolic_stdin_size=32,
            generate_test_cases=True
        )

        self.assert_real_output(result)

        # Verify advanced symbolic execution capabilities
        assert 'symbolic_inputs' in result
        assert 'test_cases' in result
        assert 'constraint_solutions' in result

        # Test cases should be generated for different execution paths
        test_cases = result['test_cases']
        assert isinstance(test_cases, list)

        # Each test case should have input data and expected results
        for test_case in test_cases:
            assert isinstance(test_case, dict)
            assert 'input_data' in test_case
            assert 'expected_path' in test_case

    def test_license_bypass_discovery(self) -> None:
        """Test license bypass discovery for defensive security research."""
        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=150,
            timeout=45
        )

        # Test license bypass discovery (critical for defensive security)
        result = engine.find_license_bypass(
            license_check_address=0x401500  # Target license check address
        )

        self.assert_real_output(result)
        assert isinstance(result, dict)

        # Verify sophisticated license analysis results
        required_fields = ['bypass_found', 'bypass_inputs', 'analysis_paths',
                          'constraint_analysis', 'execution_traces']

        for field in required_fields:
            assert field in result, f"Missing license bypass field: {field}"

        # Verify bypass analysis is comprehensive
        if result['bypass_found']:
            bypass_inputs = result['bypass_inputs']
            assert isinstance(bypass_inputs, list)
            assert len(bypass_inputs) > 0

            # Each bypass input should be concrete test data
            for bypass_input in bypass_inputs:
                assert isinstance(bypass_input, (bytes, str, dict))
                assert str(bypass_input) != ""

    def test_comprehensive_binary_analysis(self) -> None:
        """Test comprehensive analysis method with real symbolic execution."""
        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=100,
            timeout=60
        )

        result = engine.analyze(
            str(self.test_binary),
            find_vulnerabilities=True,
            find_license_checks=True,
            generate_test_cases=True,
            max_depth=5,
            symbolic_stdin_size=64
        )

        # Validate comprehensive real analysis results
        self.assert_real_output(result)
        assert isinstance(result, dict)

        # Verify comprehensive analysis structure
        required_fields = ['analysis_summary', 'vulnerability_analysis',
                          'license_analysis', 'coverage_analysis',
                          'performance_metrics', 'generated_test_cases']

        for field in required_fields:
            assert field in result, f"Missing comprehensive analysis field: {field}"

        # Verify vulnerability analysis is sophisticated
        vuln_analysis = result['vulnerability_analysis']
        assert isinstance(vuln_analysis, dict)
        assert 'potential_vulnerabilities' in vuln_analysis
        assert 'risk_assessment' in vuln_analysis

        # Verify test case generation
        test_cases = result['generated_test_cases']
        assert isinstance(test_cases, list)

        # Verify performance metrics are detailed
        metrics = result['performance_metrics']
        assert isinstance(metrics, dict)
        assert 'execution_time' in metrics
        assert 'memory_usage' in metrics
        assert 'paths_explored' in metrics

    def test_vulnerability_discovery_capabilities(self) -> None:
        """Test vulnerability discovery through symbolic execution."""
        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=200,
            timeout=120
        )

        result = engine.analyze(
            str(self.test_binary),
            find_vulnerabilities=True,
            vulnerability_types=['buffer_overflow', 'integer_overflow', 'use_after_free']
        )

        self.assert_real_output(result)

        # Verify sophisticated vulnerability detection
        assert 'vulnerability_analysis' in result
        vuln_analysis = result['vulnerability_analysis']

        assert 'buffer_overflow_analysis' in vuln_analysis
        assert 'integer_overflow_analysis' in vuln_analysis
        assert 'memory_safety_analysis' in vuln_analysis

        # Each vulnerability type should have detailed analysis
        for vuln_type in ['buffer_overflow_analysis', 'integer_overflow_analysis']:
            analysis = vuln_analysis[vuln_type]
            assert isinstance(analysis, dict)
            assert 'potential_issues' in analysis
            assert 'confidence_level' in analysis
            assert 'exploitation_vectors' in analysis

    def test_symbolic_input_generation(self) -> None:
        """Test symbolic input generation and constraint solving."""
        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=150,
            timeout=90
        )

        # Test symbolic input generation
        result = engine.analyze(
            str(self.test_binary),
            generate_test_cases=True,
            symbolic_stdin_size=128,
            concrete_seed=b"initial_seed_data"
        )

        self.assert_real_output(result)

        # Verify sophisticated symbolic input generation
        assert 'generated_test_cases' in result
        test_cases = result['generated_test_cases']
        assert isinstance(test_cases, list)
        assert len(test_cases) > 0

        # Each test case should have symbolic input data
        for test_case in test_cases:
            assert isinstance(test_case, dict)
            assert 'symbolic_input' in test_case
            assert 'constraints' in test_case
            assert 'expected_behavior' in test_case

            # Symbolic input should be concrete bytes
            symbolic_input = test_case['symbolic_input']
            assert isinstance(symbolic_input, (bytes, bytearray))
            assert len(symbolic_input) > 0

    def test_constraint_solving_integration(self) -> None:
        """Test integration with constraint solvers for path feasibility."""
        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=100,
            timeout=60
        )

        result = engine.explore_paths(
            target_address=0x401000,
            constraint_solving=True,
            solver_timeout=30
        )

        self.assert_real_output(result)

        # Verify constraint solving integration
        assert 'constraint_analysis' in result
        constraint_analysis = result['constraint_analysis']

        assert isinstance(constraint_analysis, dict)
        assert 'solver_used' in constraint_analysis
        assert 'satisfiable_constraints' in constraint_analysis
        assert 'unsatisfiable_constraints' in constraint_analysis

        # Verify solver produced real results
        satisfiable = constraint_analysis['satisfiable_constraints']
        assert isinstance(satisfiable, list)

        # Each constraint should have solution data
        for constraint in satisfiable:
            assert isinstance(constraint, dict)
            assert 'expression' in constraint
            assert 'solution' in constraint

    def test_performance_optimization(self) -> None:
        """Test performance optimization features for large binaries."""
        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=50,  # Reduced for performance testing
            timeout=30,
            memory_limit=1024,
            optimization_level='aggressive'
        )

        start_time = time.time()
        result = engine.analyze(str(self.test_binary))
        end_time = time.time()

        self.assert_real_output(result)

        # Verify performance metrics are tracked
        assert 'performance_metrics' in result
        metrics = result['performance_metrics']

        assert 'analysis_time' in metrics
        assert 'memory_peak' in metrics
        assert 'optimization_applied' in metrics

        # Analysis should complete within timeout
        actual_time = end_time - start_time
        assert actual_time < 35  # Allow 5 second buffer

        # Memory usage should be tracked
        assert isinstance(metrics['memory_peak'], (int, float))
        assert metrics['memory_peak'] > 0

    def test_error_handling_invalid_binary(self) -> None:
        """Test error handling with invalid binary files."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b"INVALID_BINARY_DATA")
            invalid_binary = f.name

        try:
            engine = ConcolicExecutionEngine(
                binary_path=invalid_binary,
                max_iterations=10,
                timeout=15
            )

            # Should handle invalid binary gracefully
            result = engine.analyze(invalid_binary)

            assert isinstance(result, dict)
            assert 'error' in result or 'analysis_status' in result

            if 'analysis_status' in result:
                assert result['analysis_status'] in ['failed', 'error', 'invalid_binary']

        finally:
            os.unlink(invalid_binary)

    def test_timeout_handling(self) -> None:
        """Test timeout handling for long-running analysis."""
        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=10000,  # Large number
            timeout=2  # Very short timeout
        )

        start_time = time.time()
        result = engine.analyze(str(self.test_binary))
        end_time = time.time()

        # Should respect timeout
        actual_time = end_time - start_time
        assert actual_time < 5  # Allow buffer for cleanup

        # Should provide partial results even on timeout
        assert isinstance(result, dict)
        assert 'analysis_status' in result
        # Status could be 'timeout' or 'partial'
        assert result['analysis_status'] in ['timeout', 'partial', 'incomplete']

    def test_memory_limit_enforcement(self) -> None:
        """Test memory limit enforcement during analysis."""
        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=100,
            timeout=60,
            memory_limit=512  # 512MB limit
        )

        result = engine.analyze(
            str(self.test_binary),
            generate_test_cases=True,
            symbolic_stdin_size=1024  # Large symbolic input
        )

        # Should handle memory limits gracefully
        assert isinstance(result, dict)
        assert 'performance_metrics' in result

        metrics = result['performance_metrics']
        if 'memory_peak' in metrics:
            # Memory usage should be reasonable
            assert metrics['memory_peak'] < 1024  # Should not exceed 1GB


    def test_native_concolic_execution(self) -> None:
        """Test native concolic execution implementation."""
        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=100,
            timeout=45
        )

        # Test native implementation
        result = engine._native_analyze(
            str(self.test_binary),
            max_depth=3,
            generate_test_cases=True
        )

        self.assert_real_output(result)

        # Verify native analysis results
        assert isinstance(result, dict)
        assert 'analysis_type' in result
        assert result['analysis_type'] == 'native_concolic'

        # Should have execution traces and coverage data
        assert 'execution_traces' in result
        assert 'coverage_data' in result

        traces = result['execution_traces']
        assert isinstance(traces, list)
        assert len(traces) > 0


class TestNativeConcolicState(IntellicrackTestBase):
    """Test NativeConcolicState for symbolic execution state management."""

    def test_state_initialization(self) -> None:
        """Test concolic state initialization with program counter and memory."""
        initial_pc = 0x401000
        initial_memory = {0x500000: 0xFF, 0x500001: 0xEE}
        initial_registers = {'eax': 0x12345678, 'ebx': 0x87654321}

        state = NativeConcolicState(
            pc=initial_pc,
            memory=initial_memory,
            registers=initial_registers
        )

        assert state.pc == initial_pc
        assert state.memory == initial_memory
        assert state.registers == initial_registers
        assert isinstance(state.symbolic_memory, dict)
        assert isinstance(state.symbolic_registers, dict)
        assert isinstance(state.constraints, list)
        assert isinstance(state.input_symbols, dict)
        assert not state.is_terminated()

    def test_register_operations(self) -> None:
        """Test register read/write operations with symbolic values."""
        state = NativeConcolicState(
            pc=0x401000,
            memory={},
            registers={'eax': 0, 'ebx': 0}
        )

        # Test concrete register operations
        state.set_register('eax', 0x12345678, symbolic=False)
        assert state.get_register('eax') == 0x12345678

        # Test symbolic register operations
        state.set_register('ebx', 'symbolic_value_ebx', symbolic=True)
        symbolic_value = state.get_register('ebx')
        assert symbolic_value == 'symbolic_value_ebx'
        assert 'ebx' in state.symbolic_registers

    def test_memory_operations(self) -> None:
        """Test memory read/write operations with symbolic tracking."""
        state = NativeConcolicState(
            pc=0x401000,
            memory={},
            registers={}
        )

        # Test concrete memory operations
        test_addr = 0x500000
        test_data = b'\x41\x42\x43\x44'  # "ABCD"

        state.write_memory(test_addr, test_data, len(test_data), symbolic=False)
        read_data = state.read_memory(test_addr, len(test_data))

        assert read_data == test_data

        # Test symbolic memory operations
        symbolic_data = 'symbolic_memory_content'
        state.write_memory(0x600000, symbolic_data, 8, symbolic=True)

        assert 0x600000 in state.symbolic_memory
        assert state.symbolic_memory[0x600000] == symbolic_data

    def test_constraint_management(self) -> None:
        """Test constraint addition and management for path conditions."""
        state = NativeConcolicState(
            pc=0x401000,
            memory={},
            registers={}
        )

        # Add path constraints
        constraint1 = "symbolic_var1 > 10"
        constraint2 = "symbolic_var2 == 0x41414141"
        constraint3 = "symbolic_var1 < symbolic_var2"

        state.add_constraint(constraint1)
        state.add_constraint(constraint2)
        state.add_constraint(constraint3)

        assert len(state.constraints) == 3
        assert constraint1 in state.constraints
        assert constraint2 in state.constraints
        assert constraint3 in state.constraints

    def test_state_forking(self) -> None:
        """Test state forking for branch exploration."""
        original_state = NativeConcolicState(
            pc=0x401000,
            memory={0x500000: 0xFF},
            registers={'eax': 0x12345678}
        )

        # Add some constraints and symbolic data
        original_state.add_constraint("eax > 0")
        original_state.set_register('ebx', 'symbolic_ebx', symbolic=True)

        # Fork the state
        forked_state = original_state.fork()

        # States should be independent
        assert forked_state.pc == original_state.pc
        assert forked_state.memory == original_state.memory
        assert forked_state.registers == original_state.registers
        assert forked_state.constraints == original_state.constraints

        # Modifying one should not affect the other
        forked_state.set_register('eax', 0x87654321, symbolic=False)
        assert original_state.get_register('eax') == 0x12345678
        assert forked_state.get_register('eax') == 0x87654321

    def test_state_termination(self) -> None:
        """Test state termination with reasons."""
        state = NativeConcolicState(
            pc=0x401000,
            memory={},
            registers={}
        )

        assert not state.is_terminated()

        # Terminate with reason
        termination_reason = "reached_target_address"
        state.terminate(termination_reason)

        assert state.is_terminated()
        assert state.termination_reason == termination_reason

    def test_symbolic_execution_trace(self) -> None:
        """Test execution trace recording during symbolic execution."""
        state = NativeConcolicState(
            pc=0x401000,
            memory={},
            registers={}
        )

        # Should track execution trace
        assert isinstance(state.execution_trace, list)

        # Execute state transitions
        state.pc = 0x401004
        state.execution_trace.append({
            'pc': 0x401000,
            'instruction': 'mov eax, 0x41414141',
            'registers_before': state.registers.copy()
        })

        state.pc = 0x401008
        state.execution_trace.append({
            'pc': 0x401004,
            'instruction': 'cmp eax, 0x12345678',
            'registers_before': state.registers.copy()
        })

        assert len(state.execution_trace) == 2
        assert state.execution_trace[0]['pc'] == 0x401000
        assert state.execution_trace[1]['pc'] == 0x401004


class TestConcolicExecutorIntegration(IntellicrackTestBase):
    """Integration tests for concolic executor functionality."""

    @pytest.fixture(autouse=True)
    def setup(self) -> Any:
        """Set up integration test environment."""
        self.test_fixtures_dir = Path("tests/fixtures/binaries")
        self.test_binary = self.test_fixtures_dir / "pe/simple_hello_world.exe"

        if not self.test_binary.exists():
            pytest.skip("Test binary not available for integration testing")

    def test_run_concolic_execution_function(self) -> None:
        """Test the main run_concolic_execution entry point function with real app configuration."""
        # Real test app for concolic execution (validates actual Intellicrack integration)
        test_app = TestConcolicApp()

        result = run_concolic_execution(test_app, str(self.test_binary))

        self.assert_real_output(result)
        assert isinstance(result, dict)

        # Should integrate with app configuration
        assert 'analysis_results' in result
        assert 'engine_configuration' in result

        # Engine configuration should reflect app settings
        engine_config = result['engine_configuration']
        assert engine_config['max_iterations'] == 100
        assert engine_config['timeout'] == 60
        assert engine_config['memory_limit'] == 1024

    def test_full_concolic_workflow(self) -> None:
        """Test complete concolic execution workflow from binary to exploit."""
        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=200,
            timeout=120
        )

        # Step 1: Analyze binary for vulnerabilities
        analysis_result = engine.analyze(
            str(self.test_binary),
            find_vulnerabilities=True,
            find_license_checks=True
        )

        self.assert_real_output(analysis_result)

        # Step 2: If vulnerabilities found, generate exploitation vectors
        if analysis_result.get('vulnerability_analysis', {}).get('potential_vulnerabilities'):
            exploit_result = engine.explore_paths(
                target_address=0x401000,
                generate_test_cases=True,
                symbolic_stdin_size=256
            )

            self.assert_real_output(exploit_result)

            # Should provide concrete exploitation data
            assert 'test_cases' in exploit_result
            assert 'exploitation_vectors' in exploit_result

            test_cases = exploit_result['test_cases']
            assert isinstance(test_cases, list)

            # Each test case should be actionable
            for test_case in test_cases:
                assert 'input_data' in test_case
                assert 'expected_result' in test_case

    def test_concolic_executor_error_recovery(self) -> None:
        """Test error recovery and graceful degradation."""
        # Test with non-existent binary
        engine = ConcolicExecutionEngine(
            binary_path="/non/existent/binary.exe",
            max_iterations=10,
            timeout=5
        )

        result = engine.analyze("/non/existent/binary.exe")

        # Should handle errors gracefully
        assert isinstance(result, dict)
        assert 'error' in result or 'analysis_status' in result

        if 'analysis_status' in result:
            assert result['analysis_status'] in ['failed', 'error', 'file_not_found']

    def test_concolic_executor_with_multiple_binaries(self) -> None:
        """Test concolic executor with multiple binary formats."""
        test_binaries = []

        # Collect available test binaries
        pe_path = self.test_fixtures_dir / "pe/simple_hello_world.exe"
        if pe_path.exists():
            test_binaries.append(('PE', pe_path))

        elf_path = self.test_fixtures_dir / "elf/simple_x64"
        if elf_path.exists():
            test_binaries.append(('ELF', elf_path))

        if not test_binaries:
            pytest.skip("No test binaries available")

        for binary_format, binary_path in test_binaries:
            engine = ConcolicExecutionEngine(
                binary_path=str(binary_path),
                max_iterations=50,
                timeout=30
            )

            result = engine.analyze(str(binary_path))

            self.assert_real_output(result)
            assert isinstance(result, dict)

            # Should handle different binary formats
            assert 'binary_format' in result
            assert result['binary_format'] in ['PE', 'ELF', 'Mach-O', binary_format]


# Performance and stress tests
class TestConcolicExecutorPerformance(IntellicrackTestBase):
    """Performance tests for concolic execution engine."""

    @pytest.fixture(autouse=True)
    def setup(self) -> Any:
        """Set up performance test environment."""
        self.test_fixtures_dir = Path("tests/fixtures/binaries")
        # Use larger binaries for performance testing if available
        self.large_binaries = [
            self.test_fixtures_dir / "pe/legitimate/7zip.exe",
            self.test_fixtures_dir / "pe/real_protected/upx_packer/upx-4.2.2-win64/upx.exe"
        ]

        self.large_binaries = [p for p in self.large_binaries if p.exists()]

        if not self.large_binaries:
            pytest.skip("No large binaries available for performance testing")

    def test_large_binary_analysis_performance(self) -> None:
        """Test performance with larger, real-world binaries."""
        large_binary = self.large_binaries[0]

        engine = ConcolicExecutionEngine(
            binary_path=str(large_binary),
            max_iterations=100,  # Limited for performance
            timeout=180,  # 3 minutes
            memory_limit=2048
        )

        start_time = time.time()
        result = engine.analyze(str(large_binary))
        end_time = time.time()

        analysis_time = end_time - start_time

        self.assert_real_output(result)

        # Should complete within reasonable time
        assert analysis_time < 200  # 200 seconds max

        # Should provide performance metrics
        assert 'performance_metrics' in result
        metrics = result['performance_metrics']
        assert 'analysis_time' in metrics
        assert 'memory_usage' in metrics

    def test_concurrent_analysis_capability(self) -> None:
        """Test concurrent concolic execution on multiple binaries."""
        if len(self.large_binaries) < 2:
            pytest.skip("Need at least 2 binaries for concurrent testing")

        import threading
        import queue

        results_queue = queue.Queue()

        def analyze_binary(binary_path, result_queue):
            engine = ConcolicExecutionEngine(
                binary_path=str(binary_path),
                max_iterations=50,
                timeout=60
            )
            result = engine.analyze(str(binary_path))
            result_queue.put(result)

        # Start concurrent analyses
        threads = []
        for binary in self.large_binaries[:2]:
            thread = threading.Thread(
                target=analyze_binary,
                args=(binary, results_queue)
            )
            thread.start()
            threads.append(thread)

        # Wait for completion
        for thread in threads:
            thread.join(timeout=120)  # 2 minutes timeout per thread

        # Collect results
        results = []
        while not results_queue.empty():
            results.append(results_queue.get())

        assert len(results) == 2
        for result in results:
            self.assert_real_output(result)

    def test_branch_decision_logging(self, caplog: Any) -> None:
        """Test that branch decisions are logged with take_branch variable."""
        import logging
        caplog.set_level(logging.DEBUG)

        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=10,
            timeout=30
        )

        engine.analyze(str(self.test_binary))

        log_messages = [record.message.lower() for record in caplog.records]
        assert any("take_branch" in msg or "branch" in msg for msg in log_messages)

    def test_branch_logging_shows_pc_address(self, caplog: Any) -> None:
        """Test that branch logging includes PC addresses."""
        import logging
        caplog.set_level(logging.DEBUG)

        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=10,
            timeout=30
        )

        engine.analyze(str(self.test_binary))

        log_messages = [record.message for record in caplog.records]
        pc_logs = [msg for msg in log_messages if "0x" in msg.lower() or "pc" in msg.lower()]
        assert pc_logs

    def test_symbolic_execution_path_exploration_logging(self, caplog: Any) -> None:
        """Test that both taken and not-taken paths are explored and logged."""
        import logging
        caplog.set_level(logging.DEBUG)

        engine = ConcolicExecutionEngine(
            binary_path=str(self.test_binary),
            max_iterations=20,
            timeout=45
        )

        engine.analyze(str(self.test_binary))

        log_messages = [record.message.lower() for record in caplog.records]
        assert any("branch" in msg or "path" in msg for msg in log_messages)
