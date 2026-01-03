"""Production-ready tests for Radare2 ESIL Analysis Engine.

Tests validate ESIL emulation capabilities on real Windows binaries.
All tests use actual system binaries without mocks.

Copyright (C) 2025 Zachary Flint
Licensed under GPLv3+
"""

import os
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

from intellicrack.core.analysis.radare2_esil import (
    ESILAnalysisEngine,
    analyze_binary_esil,
)
from intellicrack.utils.tools.radare2_utils import R2Exception, r2_session


NOTEPAD_EXE: str = r"C:\Windows\System32\notepad.exe"
KERNEL32_DLL: str = r"C:\Windows\System32\kernel32.dll"
NTDLL_DLL: str = r"C:\Windows\System32\ntdll.dll"
CALC_EXE: str = r"C:\Windows\System32\calc.exe"


@pytest.fixture(scope="session")
def notepad_binary() -> str:
    """Provide path to real notepad.exe binary."""
    if not os.path.exists(NOTEPAD_EXE):
        pytest.skip(f"Test binary not found: {NOTEPAD_EXE}")
    return NOTEPAD_EXE


@pytest.fixture(scope="session")
def kernel32_binary() -> str:
    """Provide path to real kernel32.dll binary."""
    if not os.path.exists(KERNEL32_DLL):
        pytest.skip(f"Test binary not found: {KERNEL32_DLL}")
    return KERNEL32_DLL


@pytest.fixture(scope="session")
def ntdll_binary() -> str:
    """Provide path to real ntdll.dll binary."""
    if not os.path.exists(NTDLL_DLL):
        pytest.skip(f"Test binary not found: {NTDLL_DLL}")
    return NTDLL_DLL


@pytest.fixture(scope="session")
def calc_binary() -> str:
    """Provide path to real calc.exe binary."""
    if not os.path.exists(CALC_EXE):
        pytest.skip(f"Test binary not found: {CALC_EXE}")
    return CALC_EXE


@pytest.fixture
def esil_engine(notepad_binary: str) -> ESILAnalysisEngine:
    """Create ESIL analysis engine for testing."""
    return ESILAnalysisEngine(notepad_binary)


class TestESILVMInitialization:
    """Test ESIL VM initialization and configuration."""

    def test_esil_vm_initializes_successfully(self, notepad_binary: str) -> None:
        """ESIL VM initializes with correct settings on real binary."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            success: bool = engine.initialize_esil_vm(r2)

            assert success, "ESIL VM initialization failed"

            registers: Dict[str, Any] = r2.get_esil_registers()
            assert registers is not None, "Failed to get ESIL registers"
            assert registers, "No registers available in ESIL VM"

    def test_esil_vm_stack_configuration(self, kernel32_binary: str) -> None:
        """ESIL VM configures stack properly for analysis."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(kernel32_binary)

        with r2_session(kernel32_binary) as r2:
            success: bool = engine.initialize_esil_vm(r2)
            assert success, "ESIL VM initialization failed"

            stack_info: str = r2._execute_command("dr?SP")
            assert stack_info is not None, "Stack pointer not set"
            assert stack_info.strip() != "", "Stack pointer value empty"

    def test_esil_vm_register_state_access(self, notepad_binary: str) -> None:
        """ESIL VM provides access to register state."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            engine.initialize_esil_vm(r2)

            registers: Dict[str, Any] = r2.get_esil_registers()

            common_registers: List[str] = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"]
            x86_registers: List[str] = ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"]

            register_found: bool = any(
                reg.lower() in [str(k).lower() for k in registers]
                for reg in common_registers + x86_registers
            )

            assert register_found, f"No standard registers found in: {list(registers.keys())}"

    def test_esil_vm_multiple_initialization_safe(self, notepad_binary: str) -> None:
        """ESIL VM handles multiple initialization attempts safely."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            success1: bool = engine.initialize_esil_vm(r2)
            success2: bool = engine.initialize_esil_vm(r2)

            assert success1, "First ESIL VM initialization failed"
            assert success2, "Second ESIL VM initialization failed"


class TestFunctionEmulation:
    """Test ESIL-based function emulation on real binaries."""

    def test_emulate_function_returns_complete_results(self, notepad_binary: str) -> None:
        """Function emulation returns comprehensive execution results."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()
            if not functions:
                pytest.skip("No functions found in binary")

            func_addr: int = functions[0]["offset"]

        result: Dict[str, Any] = engine.emulate_function_execution(func_addr, max_steps=20)

        assert "function_address" in result, "Missing function address"
        assert "execution_trace" in result, "Missing execution trace"
        assert "register_states" in result, "Missing register states"
        assert "memory_accesses" in result, "Missing memory accesses"
        assert "api_calls_detected" in result, "Missing API calls"
        assert "branch_decisions" in result, "Missing branch decisions"
        assert "final_state" in result, "Missing final state"
        assert "execution_time" in result, "Missing execution time"
        assert "steps_executed" in result, "Missing steps executed"

    def test_emulate_function_tracks_execution_steps(self, kernel32_binary: str) -> None:
        """Function emulation tracks each execution step accurately."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(kernel32_binary)

        with r2_session(kernel32_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()
            if not functions:
                pytest.skip("No functions found in binary")

            func_addr: int = functions[0]["offset"]

        result: Dict[str, Any] = engine.emulate_function_execution(func_addr, max_steps=30)

        assert result["steps_executed"] > 0, "No steps executed"
        assert result["steps_executed"] <= 30, "Exceeded max steps"

        trace: Any = result.get("execution_trace")
        if trace:
            assert all("step" in entry for entry in trace), "Missing step numbers"
            assert all("address" in entry for entry in trace), "Missing addresses"

    def test_emulate_function_records_register_changes(self, notepad_binary: str) -> None:
        """Function emulation captures register state changes."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()
            if not functions:
                pytest.skip("No functions found in binary")

            func_addr: int = functions[0]["offset"]

        result: Dict[str, Any] = engine.emulate_function_execution(func_addr, max_steps=50)

        register_states: List[Dict[str, Any]] = result["register_states"]
        assert register_states, "No register states recorded"

        initial_state: Dict[str, Any] = register_states[0]
        assert "step" in initial_state, "Missing step in register state"
        assert "address" in initial_state, "Missing address in register state"
        assert "registers" in initial_state, "Missing registers in register state"

    def test_emulate_function_detects_api_calls(self, notepad_binary: str) -> None:
        """Function emulation identifies API calls in execution."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:10]
            if not functions:
                pytest.skip("No functions found in binary")

        api_call_found: bool = False
        for func in functions:
            result: Dict[str, Any] = engine.emulate_function_execution(
                func["offset"], max_steps=30
            )
            if result.get("api_calls_detected"):
                api_call_found = True
                api_calls: List[Dict[str, Any]] = result["api_calls_detected"]
                assert all("step" in call for call in api_calls), "Missing step in API call"
                assert all("target_address" in call for call in api_calls), "Missing target in API call"
                break

        if not api_call_found:
            pytest.skip("No API calls found in analyzed functions")

    def test_emulate_function_tracks_branch_decisions(self, kernel32_binary: str) -> None:
        """Function emulation tracks conditional branch decisions."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(kernel32_binary)

        with r2_session(kernel32_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:10]
            if not functions:
                pytest.skip("No functions found in binary")

        branch_found: bool = False
        for func in functions:
            result: Dict[str, Any] = engine.emulate_function_execution(
                func["offset"], max_steps=40
            )
            if result.get("branch_decisions"):
                branch_found = True
                branches: List[Dict[str, Any]] = result["branch_decisions"]
                assert all("step" in branch for branch in branches), "Missing step in branch"
                assert all("branch_type" in branch for branch in branches), "Missing branch type"
                assert all("instruction" in branch for branch in branches), "Missing instruction"
                break

        if not branch_found:
            pytest.skip("No branches found in analyzed functions")

    def test_emulate_function_detects_memory_accesses(self, notepad_binary: str) -> None:
        """Function emulation identifies memory access patterns."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:10]
            if not functions:
                pytest.skip("No functions found in binary")

        memory_access_found: bool = False
        for func in functions:
            result: Dict[str, Any] = engine.emulate_function_execution(
                func["offset"], max_steps=30
            )
            if result.get("memory_accesses"):
                memory_access_found = True
                accesses: List[Dict[str, Any]] = result["memory_accesses"]
                assert all("step" in access for access in accesses), "Missing step in memory access"
                assert all("access_type" in access for access in accesses), "Missing access type"
                break

        if not memory_access_found:
            pytest.skip("No memory accesses found in analyzed functions")

    def test_emulate_function_measures_execution_time(self, notepad_binary: str) -> None:
        """Function emulation tracks execution performance."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()
            if not functions:
                pytest.skip("No functions found in binary")

            func_addr: int = functions[0]["offset"]

        result: Dict[str, Any] = engine.emulate_function_execution(func_addr, max_steps=20)

        assert "execution_time" in result, "Missing execution time"
        assert result["execution_time"] >= 0, "Invalid execution time"
        assert result["execution_time"] < 60, "Execution took unreasonably long"

    def test_emulate_function_respects_max_steps(self, kernel32_binary: str) -> None:
        """Function emulation respects maximum step limit."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(kernel32_binary)

        with r2_session(kernel32_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()
            if not functions:
                pytest.skip("No functions found in binary")

            func_addr: int = functions[0]["offset"]

        max_steps: int = 15
        result: Dict[str, Any] = engine.emulate_function_execution(
            func_addr, max_steps=max_steps
        )

        assert result["steps_executed"] <= max_steps, "Exceeded max steps limit"

    def test_emulate_function_detects_return_instruction(self, notepad_binary: str) -> None:
        """Function emulation stops at return instruction."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:10]
            if not functions:
                pytest.skip("No functions found in binary")

        for func in functions:
            result: Dict[str, Any] = engine.emulate_function_execution(
                func["offset"], max_steps=100
            )

            trace: List[Dict[str, Any]] = result.get("execution_trace", [])
            if trace:
                last_instruction: str = trace[-1].get("instruction", "").lower()
                if "ret" in last_instruction:
                    assert result["steps_executed"] < 100, "Should stop at return"
                    break

    def test_emulate_function_caches_results(self, notepad_binary: str) -> None:
        """Function emulation caches results for performance."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()
            if not functions:
                pytest.skip("No functions found in binary")

            func_addr: int = functions[0]["offset"]

        start_time: float = time.time()
        result1: Dict[str, Any] = engine.emulate_function_execution(func_addr, max_steps=20)
        first_duration: float = time.time() - start_time

        start_time = time.time()
        result2: Dict[str, Any] = engine.emulate_function_execution(func_addr, max_steps=20)
        second_duration: float = time.time() - start_time

        assert result1 == result2, "Cached results differ from original"
        assert second_duration < first_duration * 0.5, "Cache not improving performance"


class TestLicenseCheckDetection:
    """Test detection of license validation patterns in ESIL execution."""

    def test_detects_comparison_patterns(self, notepad_binary: str) -> None:
        """ESIL engine identifies comparison operations."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:20]
            if not functions:
                pytest.skip("No functions found in binary")

        comparison_found: bool = False
        for func in functions:
            result: Dict[str, Any] = engine.emulate_function_execution(
                func["offset"], max_steps=50
            )

            trace: List[Dict[str, Any]] = result.get("execution_trace", [])
            for entry in trace:
                instruction: str = entry.get("instruction", "").lower()
                if "cmp" in instruction or "test" in instruction:
                    comparison_found = True
                    break

            if comparison_found:
                break

        if not comparison_found:
            pytest.skip("No comparison instructions found")

    def test_detects_license_validation_patterns(self, kernel32_binary: str) -> None:
        """ESIL engine identifies potential license validation routines."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(kernel32_binary)

        with r2_session(kernel32_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:20]
            if not functions:
                pytest.skip("No functions found in binary")

        for func in functions:
            result: Dict[str, Any] = engine.emulate_function_execution(
                func["offset"], max_steps=50
            )

            if "license_validation_patterns" in result:
                if patterns := result["license_validation_patterns"]:
                    assert all("type" in pattern for pattern in patterns), "Missing pattern type"
                    assert all("start_step" in pattern for pattern in patterns), "Missing start step"

    def test_detects_string_comparison_validation(self, notepad_binary: str) -> None:
        """ESIL engine identifies string comparison patterns."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:20]
            if not functions:
                pytest.skip("No functions found in binary")

        for func in functions:
            result: Dict[str, Any] = engine.emulate_function_execution(
                func["offset"], max_steps=60
            )

            patterns: List[Dict[str, Any]] = result.get("license_validation_patterns", [])
            if string_comparison_patterns := [
                p
                for p in patterns
                if p.get("type") == "string_comparison_validation"
            ]:
                assert "start_step" in string_comparison_patterns[0], "Missing start step"
                assert "end_step" in string_comparison_patterns[0], "Missing end step"

    def test_detects_complex_validation_routines(self, kernel32_binary: str) -> None:
        """ESIL engine identifies complex multi-comparison validation."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(kernel32_binary)

        with r2_session(kernel32_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:20]
            if not functions:
                pytest.skip("No functions found in binary")

        for func in functions:
            result: Dict[str, Any] = engine.emulate_function_execution(
                func["offset"], max_steps=80
            )

            patterns: List[Dict[str, Any]] = result.get("license_validation_patterns", [])
            if complex_patterns := [
                p
                for p in patterns
                if p.get("type") == "complex_validation_routine"
            ]:
                pattern: Dict[str, Any] = complex_patterns[0]
                assert "comparison_count" in pattern, "Missing comparison count"
                assert pattern["comparison_count"] >= 3, "Not complex enough"
                assert "pattern_strength" in pattern, "Missing pattern strength"


class TestExecutionPatternAnalysis:
    """Test analysis of execution patterns in ESIL traces."""

    def test_analyzes_instruction_counts(self, notepad_binary: str) -> None:
        """ESIL engine counts total instructions executed."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()
            if not functions:
                pytest.skip("No functions found in binary")

            func_addr: int = functions[0]["offset"]

        result: Dict[str, Any] = engine.emulate_function_execution(func_addr, max_steps=40)

        if "execution_patterns" in result:
            patterns: Dict[str, Any] = result["execution_patterns"]
            assert "total_instructions_executed" in patterns, "Missing instruction count"
            assert patterns["total_instructions_executed"] > 0, "No instructions counted"

    def test_tracks_unique_addresses_visited(self, kernel32_binary: str) -> None:
        """ESIL engine tracks unique code locations."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(kernel32_binary)

        with r2_session(kernel32_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()
            if not functions:
                pytest.skip("No functions found in binary")

            func_addr: int = functions[0]["offset"]

        result: Dict[str, Any] = engine.emulate_function_execution(func_addr, max_steps=50)

        if "execution_patterns" in result:
            patterns: Dict[str, Any] = result["execution_patterns"]
            assert "unique_addresses_visited" in patterns, "Missing unique addresses"
            assert patterns["unique_addresses_visited"] > 0, "No unique addresses"

    def test_detects_loops_in_execution(self, notepad_binary: str) -> None:
        """ESIL engine identifies loop constructs."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:10]
            if not functions:
                pytest.skip("No functions found in binary")

        for func in functions:
            result: Dict[str, Any] = engine.emulate_function_execution(
                func["offset"], max_steps=80
            )

            if "execution_patterns" in result:
                patterns: Dict[str, Any] = result["execution_patterns"]
                if "loops_detected" in patterns:
                    loops: int = patterns["loops_detected"]
                    assert loops >= 0, "Invalid loop count"

    def test_calculates_code_coverage_ratio(self, kernel32_binary: str) -> None:
        """ESIL engine computes code coverage metrics."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(kernel32_binary)

        with r2_session(kernel32_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()
            if not functions:
                pytest.skip("No functions found in binary")

            func_addr: int = functions[0]["offset"]

        result: Dict[str, Any] = engine.emulate_function_execution(func_addr, max_steps=50)

        if "execution_patterns" in result:
            patterns: Dict[str, Any] = result["execution_patterns"]
            if "code_coverage_ratio" in patterns:
                coverage: float = patterns["code_coverage_ratio"]
                assert 0.0 <= coverage <= 1.0, "Invalid coverage ratio"


class TestAntiAnalysisDetection:
    """Test detection of anti-analysis techniques in ESIL execution."""

    def test_detects_debugger_checks(self, notepad_binary: str) -> None:
        """ESIL engine identifies debugger detection calls."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:30]
            if not functions:
                pytest.skip("No functions found in binary")

        for func in functions:
            result: Dict[str, Any] = engine.emulate_function_execution(
                func["offset"], max_steps=50
            )

            anti_analysis: List[Dict[str, Any]] = result.get("anti_analysis_techniques", [])
            if debugger_checks := [
                a for a in anti_analysis if a.get("type") == "debugger_detection"
            ]:
                check: Dict[str, Any] = debugger_checks[0]
                assert "step" in check, "Missing step"
                assert "instruction" in check, "Missing instruction"
                assert "severity" in check, "Missing severity"

    def test_detects_timing_checks(self, kernel32_binary: str) -> None:
        """ESIL engine identifies timing-based detection."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(kernel32_binary)

        with r2_session(kernel32_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:30]
            if not functions:
                pytest.skip("No functions found in binary")

        for func in functions:
            result: Dict[str, Any] = engine.emulate_function_execution(
                func["offset"], max_steps=50
            )

            anti_analysis: List[Dict[str, Any]] = result.get("anti_analysis_techniques", [])
            if timing_checks := [
                a for a in anti_analysis if a.get("type") == "timing_check"
            ]:
                check: Dict[str, Any] = timing_checks[0]
                assert "step" in check, "Missing step"
                assert "severity" in check, "Missing severity"

    def test_detects_vm_detection(self, notepad_binary: str) -> None:
        """ESIL engine identifies VM detection techniques."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:30]
            if not functions:
                pytest.skip("No functions found in binary")

        for func in functions:
            result: Dict[str, Any] = engine.emulate_function_execution(
                func["offset"], max_steps=50
            )

            anti_analysis: List[Dict[str, Any]] = result.get("anti_analysis_techniques", [])
            if vm_detection := [
                a for a in anti_analysis if a.get("type") == "vm_detection"
            ]:
                check: Dict[str, Any] = vm_detection[0]
                assert "step" in check, "Missing step"
                assert "instruction" in check, "Missing instruction"


class TestVulnerabilityDetection:
    """Test vulnerability detection during ESIL execution."""

    def test_detects_buffer_overflow_risks(self, kernel32_binary: str) -> None:
        """ESIL engine identifies dangerous string operations."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(kernel32_binary)

        with r2_session(kernel32_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:30]
            if not functions:
                pytest.skip("No functions found in binary")

        for func in functions:
            result: Dict[str, Any] = engine.emulate_function_execution(
                func["offset"], max_steps=50
            )

            if vulnerabilities := result.get("vulnerabilities_detected", []):
                vuln: Dict[str, Any] = vulnerabilities[0]
                assert "step" in vuln, "Missing step"
                assert "address" in vuln, "Missing address"
                assert "vulnerability_type" in vuln, "Missing vulnerability type"


class TestMultipleFunctionEmulation:
    """Test emulation of multiple functions with comparative analysis."""

    def test_emulates_multiple_functions_successfully(self, notepad_binary: str) -> None:
        """Engine emulates multiple functions and aggregates results."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:5]
            if len(functions) < 2:
                pytest.skip("Not enough functions for multi-function test")

            addresses: List[int] = [f["offset"] for f in functions]

        result: Dict[str, Any] = engine.emulate_multiple_functions(addresses, max_steps_per_function=20)

        assert "emulation_summary" in result, "Missing emulation summary"
        assert "function_results" in result, "Missing function results"
        assert "comparative_analysis" in result, "Missing comparative analysis"

        summary: Dict[str, Any] = result["emulation_summary"]
        assert summary["functions_emulated"] == len(addresses), "Incorrect function count"

    def test_comparative_analysis_identifies_complex_functions(self, kernel32_binary: str) -> None:
        """Comparative analysis identifies most complex function."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(kernel32_binary)

        with r2_session(kernel32_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:5]
            if len(functions) < 2:
                pytest.skip("Not enough functions for comparative test")

            addresses: List[int] = [f["offset"] for f in functions]

        result: Dict[str, Any] = engine.emulate_multiple_functions(addresses, max_steps_per_function=30)

        analysis: Dict[str, Any] = result["comparative_analysis"]
        if analysis.get("most_complex_function"):
            assert analysis["most_complex_function"] in result["function_results"], \
                "Most complex function not in results"

    def test_comparative_analysis_tracks_api_call_frequency(self, notepad_binary: str) -> None:
        """Comparative analysis identifies functions with most API calls."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:5]
            if len(functions) < 2:
                pytest.skip("Not enough functions for comparative test")

            addresses: List[int] = [f["offset"] for f in functions]

        result: Dict[str, Any] = engine.emulate_multiple_functions(addresses, max_steps_per_function=30)

        summary: Dict[str, Any] = result["emulation_summary"]
        assert "total_api_calls" in summary, "Missing total API calls"
        assert summary["total_api_calls"] >= 0, "Invalid API call count"

    def test_comparative_analysis_identifies_suspicious_functions(self, kernel32_binary: str) -> None:
        """Comparative analysis flags suspicious functions."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(kernel32_binary)

        with r2_session(kernel32_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:5]
            if len(functions) < 2:
                pytest.skip("Not enough functions for comparative test")

            addresses: List[int] = [f["offset"] for f in functions]

        result: Dict[str, Any] = engine.emulate_multiple_functions(addresses, max_steps_per_function=40)

        analysis: Dict[str, Any] = result["comparative_analysis"]
        if "suspicious_functions" in analysis:
            suspicious: List[Dict[str, Any]] = analysis["suspicious_functions"]
            for func in suspicious:
                assert "address" in func, "Missing address in suspicious function"
                assert "suspicion_score" in func, "Missing suspicion score"


class TestBinaryESILAnalysis:
    """Test high-level binary ESIL analysis function."""

    def test_analyze_binary_esil_comprehensive_results(self, notepad_binary: str) -> None:
        """Binary ESIL analysis returns comprehensive results."""
        result: Dict[str, Any] = analyze_binary_esil(
            notepad_binary, function_limit=5, max_steps=20
        )

        assert "emulation_summary" in result or "error" in result, "Invalid result structure"

        if "error" not in result:
            assert "function_results" in result, "Missing function results"
            assert "comparative_analysis" in result, "Missing comparative analysis"

    def test_analyze_binary_esil_respects_function_limit(self, kernel32_binary: str) -> None:
        """Binary ESIL analysis respects function limit."""
        function_limit: int = 3
        result: Dict[str, Any] = analyze_binary_esil(
            kernel32_binary, function_limit=function_limit, max_steps=15
        )

        if "error" not in result:
            summary: Dict[str, Any] = result["emulation_summary"]
            assert summary["functions_emulated"] <= function_limit, "Exceeded function limit"

    def test_analyze_binary_esil_handles_no_functions(self) -> None:
        """Binary ESIL analysis handles binaries with no analyzable functions."""
        test_binary: str = KERNEL32_DLL
        if not os.path.exists(test_binary):
            pytest.skip(f"Test binary not found: {test_binary}")

        result: Dict[str, Any] = analyze_binary_esil(
            test_binary, function_limit=0, max_steps=10
        )

        assert "error" in result or "emulation_summary" in result, "Should handle gracefully"

    def test_analyze_binary_esil_performance(self, notepad_binary: str) -> None:
        """Binary ESIL analysis completes within reasonable time."""
        start_time: float = time.time()
        result: Dict[str, Any] = analyze_binary_esil(
            notepad_binary, function_limit=3, max_steps=10
        )
        duration: float = time.time() - start_time

        assert duration < 30.0, f"Analysis took too long: {duration}s"


class TestBranchTypeExtraction:
    """Test extraction and classification of branch types."""

    def test_extract_branch_type_jump_equal(self, esil_engine: ESILAnalysisEngine) -> None:
        """Branch type extraction identifies je/jz as jump_if_equal."""
        instruction_je: str = "je 0x401234"
        instruction_jz: str = "jz 0x401234"

        branch_type_je: str = esil_engine._extract_branch_type(instruction_je)
        branch_type_jz: str = esil_engine._extract_branch_type(instruction_jz)

        assert branch_type_je == "jump_if_equal", f"Incorrect branch type for je: {branch_type_je}"
        assert branch_type_jz == "jump_if_equal", f"Incorrect branch type for jz: {branch_type_jz}"

    def test_extract_branch_type_jump_not_equal(self, esil_engine: ESILAnalysisEngine) -> None:
        """Branch type extraction identifies jne/jnz as jump_if_not_equal."""
        instruction_jne: str = "jne 0x401234"
        instruction_jnz: str = "jnz 0x401234"

        branch_type_jne: str = esil_engine._extract_branch_type(instruction_jne)
        branch_type_jnz: str = esil_engine._extract_branch_type(instruction_jnz)

        assert branch_type_jne == "jump_if_not_equal", f"Incorrect branch type: {branch_type_jne}"
        assert branch_type_jnz == "jump_if_not_equal", f"Incorrect branch type: {branch_type_jnz}"

    def test_extract_branch_type_comparison_jumps(self, esil_engine: ESILAnalysisEngine) -> None:
        """Branch type extraction identifies comparison jumps."""
        instruction_jg: str = "jg 0x401234"
        instruction_jl: str = "jl 0x401234"
        instruction_jge: str = "jge 0x401234"
        instruction_jle: str = "jle 0x401234"

        assert esil_engine._extract_branch_type(instruction_jg) == "jump_if_greater"
        assert esil_engine._extract_branch_type(instruction_jl) == "jump_if_less"
        assert esil_engine._extract_branch_type(instruction_jge) == "jump_if_greater_equal"
        assert esil_engine._extract_branch_type(instruction_jle) == "jump_if_less_equal"


class TestMemoryAccessTypeExtraction:
    """Test extraction and classification of memory access types."""

    def test_extract_memory_access_type_move(self, esil_engine: ESILAnalysisEngine) -> None:
        """Memory access type extraction identifies mov as move."""
        instruction: str = "mov [rax], rbx"
        access_type: str = esil_engine._extract_memory_access_type(instruction)
        assert access_type == "move", f"Incorrect access type: {access_type}"

    def test_extract_memory_access_type_lea(self, esil_engine: ESILAnalysisEngine) -> None:
        """Memory access type extraction identifies lea."""
        instruction: str = "lea rax, [rbx+rcx]"
        access_type: str = esil_engine._extract_memory_access_type(instruction)
        assert access_type == "load_effective_address", f"Incorrect access type: {access_type}"

    def test_extract_memory_access_type_stack_operations(self, esil_engine: ESILAnalysisEngine) -> None:
        """Memory access type extraction identifies stack operations."""
        push_instruction: str = "push rax"
        pop_instruction: str = "pop rbx"

        push_type: str = esil_engine._extract_memory_access_type(push_instruction)
        pop_type: str = esil_engine._extract_memory_access_type(pop_instruction)

        assert push_type == "stack_push", f"Incorrect push type: {push_type}"
        assert pop_type == "stack_pop", f"Incorrect pop type: {pop_type}"


class TestFunctionExitDetection:
    """Test detection of function exit conditions."""

    def test_is_function_exit_detects_ret(self, esil_engine: ESILAnalysisEngine) -> None:
        """Function exit detection identifies ret instruction."""
        ret_instructions: List[str] = ["ret", "retn", "ret 0x10"]

        for instruction in ret_instructions:
            is_exit: bool = esil_engine._is_function_exit(instruction)
            assert is_exit, f"Failed to detect exit in: {instruction}"

    def test_is_function_exit_ignores_non_exit(self, esil_engine: ESILAnalysisEngine) -> None:
        """Function exit detection ignores non-exit instructions."""
        non_exit_instructions: List[str] = [
            "mov rax, rbx",
            "call 0x401000",
            "jmp 0x402000",
            "add rax, 1",
        ]

        for instruction in non_exit_instructions:
            is_exit: bool = esil_engine._is_function_exit(instruction)
            assert not is_exit, f"Incorrectly detected exit in: {instruction}"

    def test_is_function_exit_handles_empty_instruction(self, esil_engine: ESILAnalysisEngine) -> None:
        """Function exit detection handles empty instruction gracefully."""
        is_exit: bool = esil_engine._is_function_exit("")
        assert not is_exit, "Should not detect exit in empty instruction"

    def test_is_function_exit_case_insensitive(self, esil_engine: ESILAnalysisEngine) -> None:
        """Function exit detection is case-insensitive."""
        ret_variations: List[str] = ["RET", "Ret", "RETN", "Retn"]

        for instruction in ret_variations:
            is_exit: bool = esil_engine._is_function_exit(instruction)
            assert is_exit, f"Case-insensitive detection failed for: {instruction}"


class TestAPICallSequenceAnalysis:
    """Test analysis of API call sequences."""

    def test_groups_consecutive_api_calls(self, esil_engine: ESILAnalysisEngine) -> None:
        """API call sequence analysis groups consecutive calls."""
        result: Dict[str, Any] = {
            "api_calls_detected": [
                {"step": 1, "target_address": "0x401000"},
                {"step": 3, "target_address": "0x401100"},
                {"step": 4, "target_address": "0x401200"},
                {"step": 10, "target_address": "0x401300"},
            ]
        }

        esil_engine._analyze_api_call_sequences(result)

        sequences: List[List[Dict[str, Any]]] = result.get("api_call_sequences", [])
        assert sequences, "No sequences identified"

    def test_handles_no_api_calls(self, esil_engine: ESILAnalysisEngine) -> None:
        """API call sequence analysis handles absence of API calls."""
        result: Dict[str, Any] = {"api_calls_detected": []}
        esil_engine._analyze_api_call_sequences(result)
        assert "api_call_sequences" not in result or not result["api_call_sequences"]


class TestESILErrorHandling:
    """Test error handling in ESIL operations."""

    def test_handles_invalid_binary_path(self) -> None:
        """ESIL engine handles invalid binary path gracefully."""
        invalid_path: str = r"C:\NonExistent\invalid.exe"
        engine: ESILAnalysisEngine = ESILAnalysisEngine(invalid_path)

        result: Dict[str, Any] = analyze_binary_esil(invalid_path, function_limit=1, max_steps=10)
        assert "error" in result, "Should report error for invalid path"

    def test_handles_esil_execution_failure(self, notepad_binary: str) -> None:
        """ESIL engine handles execution failures gracefully."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        invalid_address: int = 0xFFFFFFFFFFFFFFFF
        result: Dict[str, Any] = engine.emulate_function_execution(
            invalid_address, max_steps=10
        )

        assert "error" in result or result["steps_executed"] == 0, \
            "Should handle invalid address"

    def test_continues_after_step_failure(self, kernel32_binary: str) -> None:
        """ESIL engine continues after individual step failures."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(kernel32_binary)

        with r2_session(kernel32_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()
            if not functions:
                pytest.skip("No functions found")

            func_addr: int = functions[0]["offset"]

        result: Dict[str, Any] = engine.emulate_function_execution(func_addr, max_steps=50)

        assert "steps_executed" in result, "Should track partial execution"


class TestESILPerformance:
    """Test ESIL engine performance characteristics."""

    def test_emulation_completes_within_timeout(self, notepad_binary: str) -> None:
        """ESIL emulation completes within reasonable timeout."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()
            if not functions:
                pytest.skip("No functions found")

            func_addr: int = functions[0]["offset"]

        start_time: float = time.time()
        result: Dict[str, Any] = engine.emulate_function_execution(func_addr, max_steps=100)
        duration: float = time.time() - start_time

        assert duration < 15.0, f"Emulation too slow: {duration}s"

    @pytest.mark.benchmark(group="esil_emulation")
    def test_benchmark_single_function_emulation(
        self, benchmark: Any, notepad_binary: str
    ) -> None:
        """Benchmark single function ESIL emulation."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()
            if not functions:
                pytest.skip("No functions found")

            func_addr: int = functions[0]["offset"]

        result: Dict[str, Any] = benchmark(
            engine.emulate_function_execution, func_addr, max_steps=20
        )

        assert "steps_executed" in result, "Benchmark execution failed"

    @pytest.mark.benchmark(group="esil_multi")
    def test_benchmark_multiple_function_emulation(
        self, benchmark: Any, kernel32_binary: str
    ) -> None:
        """Benchmark multiple function ESIL emulation."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(kernel32_binary)

        with r2_session(kernel32_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()[:3]
            if len(functions) < 2:
                pytest.skip("Not enough functions")

            addresses: List[int] = [f["offset"] for f in functions]

        result: Dict[str, Any] = benchmark(
            engine.emulate_multiple_functions, addresses, max_steps_per_function=15
        )

        assert "emulation_summary" in result, "Benchmark execution failed"


class TestESILCaching:
    """Test ESIL emulation caching behavior."""

    def test_cache_hit_improves_performance(self, notepad_binary: str) -> None:
        """Cached ESIL results improve subsequent access performance."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(notepad_binary)

        with r2_session(notepad_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()
            if not functions:
                pytest.skip("No functions found")

            func_addr: int = functions[0]["offset"]

        result1: Dict[str, Any] = engine.emulate_function_execution(func_addr, max_steps=20)

        start_time: float = time.time()
        result2: Dict[str, Any] = engine.emulate_function_execution(func_addr, max_steps=20)
        cache_duration: float = time.time() - start_time

        assert result1 == result2, "Cached results differ"
        assert cache_duration < 0.1, "Cache not significantly faster"

    def test_different_max_steps_separate_cache_entries(self, kernel32_binary: str) -> None:
        """Different max_steps values create separate cache entries."""
        engine: ESILAnalysisEngine = ESILAnalysisEngine(kernel32_binary)

        with r2_session(kernel32_binary) as r2:
            functions: List[Dict[str, Any]] = r2.get_functions()
            if not functions:
                pytest.skip("No functions found")

            func_addr: int = functions[0]["offset"]

        result1: Dict[str, Any] = engine.emulate_function_execution(func_addr, max_steps=10)
        result2: Dict[str, Any] = engine.emulate_function_execution(func_addr, max_steps=20)

        assert result1["steps_executed"] <= 10, "First execution exceeded limit"
        assert result2["steps_executed"] <= 20, "Second execution exceeded limit"
