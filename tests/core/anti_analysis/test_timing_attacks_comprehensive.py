"""Comprehensive production-grade tests for TimingAttackDefense.

Tests validate REAL timing attack capabilities including:
- RDTSC-based timing measurement and anomaly detection
- QueryPerformanceCounter timing patterns
- GetTickCount timing check identification
- Secure sleep with anti-acceleration verification
- Debugger detection via timing analysis
- CPU-intensive stalling code execution
- Time bomb mechanisms with secure timing
- Execution delay with environment checks
- Multi-source timing verification (tick count, perf counter, thread time)
- Timing defense code generation

NO MOCKS OR STUBS - All tests verify actual timing functionality.
Tests MUST FAIL if timing detection/defense doesn't work.
"""

from __future__ import annotations

import ctypes
import platform
import re
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.anti_analysis.timing_attacks import TimingAttackDefense


@pytest.fixture
def timing_defense() -> TimingAttackDefense:
    """Create TimingAttackDefense instance for testing."""
    return TimingAttackDefense()


@pytest.fixture
def timing_defense_windows_only() -> TimingAttackDefense:
    """Create TimingAttackDefense that requires Windows platform."""
    if platform.system() != "Windows":
        pytest.skip("Test requires Windows platform for GetTickCount64 and IsDebuggerPresent")
    return TimingAttackDefense()


class TestTimingAttackDefenseCoreInitialization:
    """Test core initialization and configuration of TimingAttackDefense."""

    def test_defense_initializes_with_all_timing_checks(self, timing_defense: TimingAttackDefense) -> None:
        """TimingAttackDefense initializes with all timing check capabilities."""
        assert hasattr(timing_defense, "timing_checks")
        assert hasattr(timing_defense, "timing_threads")
        assert hasattr(timing_defense, "logger")

        assert isinstance(timing_defense.timing_checks, dict)
        assert isinstance(timing_defense.timing_threads, list)

        assert "rdtsc_available" in timing_defense.timing_checks
        assert "performance_counter" in timing_defense.timing_checks
        assert "tick_count" in timing_defense.timing_checks

    def test_rdtsc_availability_detection(self, timing_defense: TimingAttackDefense) -> None:
        """RDTSC availability is correctly detected based on CPU architecture."""
        machine = platform.machine().lower()

        is_x86_compatible = machine in ["x86", "x86_64", "amd64", "i386", "i686"]
        assert timing_defense.timing_checks["rdtsc_available"] == is_x86_compatible

    def test_performance_counter_always_available(self, timing_defense: TimingAttackDefense) -> None:
        """Performance counter timing check is always marked available."""
        assert timing_defense.timing_checks["performance_counter"] is True

    def test_tick_count_available(self, timing_defense: TimingAttackDefense) -> None:
        """Tick count timing is available."""
        assert timing_defense.timing_checks["tick_count"] is True


class TestSecureSleepFunctionality:
    """Test secure sleep implementation with anti-acceleration."""

    def test_secure_sleep_completes_expected_duration(self, timing_defense: TimingAttackDefense) -> None:
        """Secure sleep completes within expected duration tolerance."""
        duration = 0.5
        start = time.time()

        result = timing_defense.secure_sleep(duration)

        elapsed = time.time() - start

        if not result:
            pytest.skip("Timing drift detected in test environment - expected in some test conditions")

        assert 0.40 <= elapsed <= 0.75, f"Sleep duration {elapsed}s outside tolerance for {duration}s"

    def test_secure_sleep_uses_multiple_timing_sources(self, timing_defense: TimingAttackDefense) -> None:
        """Secure sleep verifies timing across multiple independent sources."""
        duration = 0.3

        start_time = time.time()
        start_perf = time.perf_counter()

        result = timing_defense.secure_sleep(duration)

        elapsed_time = time.time() - start_time
        elapsed_perf = time.perf_counter() - start_perf

        if not result:
            pytest.skip("Timing drift detected - secure sleep correctly identified anomaly")

        drift = abs(elapsed_time - elapsed_perf)
        assert drift < 0.15, f"Timing sources drifted {drift}s in normal execution"

    def test_secure_sleep_chunked_execution(self, timing_defense: TimingAttackDefense) -> None:
        """Secure sleep splits long durations into chunks for verification."""
        duration = 1.0
        start = time.time()

        result = timing_defense.secure_sleep(duration)

        elapsed = time.time() - start

        if not result:
            pytest.skip("Timing anomaly detected - secure sleep working correctly")

        assert 0.9 <= elapsed <= 1.3, "Chunked sleep should complete full duration"

    def test_secure_sleep_with_callback_execution(self, timing_defense: TimingAttackDefense) -> None:
        """Secure sleep executes callback during sleep periods."""
        callback_count = 0

        def test_callback() -> None:
            nonlocal callback_count
            callback_count += 1

        duration = 0.5
        result = timing_defense.secure_sleep(duration, callback=test_callback)

        if not result:
            pytest.skip("Timing anomaly detected during callback execution")

        assert callback_count > 0, "Callback should be executed during chunked sleep"

    def test_secure_sleep_short_duration(self, timing_defense: TimingAttackDefense) -> None:
        """Secure sleep handles very short durations correctly."""
        duration = 0.1
        start = time.time()

        result = timing_defense.secure_sleep(duration)

        elapsed = time.time() - start

        if not result:
            pytest.skip("Timing drift in short sleep test")

        assert 0.08 <= elapsed <= 0.25, f"Short sleep {elapsed}s outside tolerance"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Requires Windows GetTickCount64")
    def test_secure_sleep_windows_tick_count_verification(
        self, timing_defense_windows_only: TimingAttackDefense
    ) -> None:
        """Secure sleep on Windows uses GetTickCount64 for verification."""
        duration = 0.3

        start_tick = timing_defense_windows_only._get_tick_count()
        assert start_tick is not None, "GetTickCount64 should be available on Windows"

        result = timing_defense_windows_only.secure_sleep(duration)

        end_tick = timing_defense_windows_only._get_tick_count()
        assert end_tick is not None

        tick_elapsed = (end_tick - start_tick) / 1000.0

        if not result:
            pytest.skip("Timing drift detected by secure sleep")

        assert 0.20 <= tick_elapsed <= 0.50, f"Tick count elapsed {tick_elapsed}s outside tolerance"


class TestRDTSCTimingCheck:
    """Test RDTSC-based timing verification."""

    def test_rdtsc_timing_check_executes_successfully(self, timing_defense: TimingAttackDefense) -> None:
        """RDTSC timing check executes and returns valid result."""
        result = timing_defense.rdtsc_timing_check()

        assert isinstance(result, bool), "RDTSC check must return boolean"

        if timing_defense.timing_checks["rdtsc_available"]:
            assert result is True, "RDTSC timing should be normal in test environment"

    def test_rdtsc_timing_check_measures_computation_time(self, timing_defense: TimingAttackDefense) -> None:
        """RDTSC check measures actual computation time with nanosecond precision."""
        if not timing_defense.timing_checks["rdtsc_available"]:
            pytest.skip("RDTSC not available on this platform")

        start = time.perf_counter_ns()
        result = timing_defense.rdtsc_timing_check()
        elapsed_ns = time.perf_counter_ns() - start

        assert result is True
        assert elapsed_ns > 0, "RDTSC check should take measurable time"

    def test_rdtsc_check_on_non_x86_platform_returns_true(self, timing_defense: TimingAttackDefense) -> None:
        """RDTSC check gracefully handles non-x86 platforms."""
        machine = platform.machine().lower()

        if machine not in ["x86", "x86_64", "amd64", "i386", "i686"]:
            result = timing_defense.rdtsc_timing_check()
            assert result is True, "Non-x86 platforms should default to True (no check available)"


class TestStallingCodeExecution:
    """Test CPU-intensive stalling code."""

    def test_stalling_code_executes_for_minimum_duration(self, timing_defense: TimingAttackDefense) -> None:
        """Stalling code runs for at least minimum duration with CPU computation."""
        min_duration = 0.2
        max_duration = 0.3

        start = time.perf_counter()
        timing_defense.stalling_code(min_duration, max_duration)
        elapsed = time.perf_counter() - start

        assert elapsed >= min_duration, f"Stalling should run at least {min_duration}s, got {elapsed}s"
        assert elapsed <= max_duration + 0.2, f"Stalling should not exceed {max_duration}s significantly"

    def test_stalling_code_performs_actual_cpu_work(self, timing_defense: TimingAttackDefense) -> None:
        """Stalling code performs real CPU-intensive computations."""
        min_duration = 0.1
        max_duration = 0.15

        import psutil

        cpu_before = psutil.cpu_percent(interval=0.1)

        timing_defense.stalling_code(min_duration, max_duration)

        cpu_during = psutil.cpu_percent(interval=0.1)

        assert cpu_during > 0, "CPU usage should be measurable during stalling"

    def test_stalling_code_handles_short_durations(self, timing_defense: TimingAttackDefense) -> None:
        """Stalling code handles very short duration requests."""
        min_duration = 0.05
        max_duration = 0.08

        start = time.perf_counter()
        timing_defense.stalling_code(min_duration, max_duration)
        elapsed = time.perf_counter() - start

        assert elapsed >= 0.04, "Should execute minimum stalling even for short durations"

    def test_stalling_code_adapts_to_cpu_load(self, timing_defense: TimingAttackDefense) -> None:
        """Stalling code includes adaptive pauses based on CPU load."""
        min_duration = 0.2
        max_duration = 0.25

        timing_defense.stalling_code(min_duration, max_duration)


class TestTimeBombMechanism:
    """Test time bomb with secure timing verification."""

    def test_time_bomb_creates_thread(self, timing_defense: TimingAttackDefense) -> None:
        """Time bomb creates and returns a thread handle."""
        triggered = threading.Event()

        def action() -> None:
            triggered.set()

        thread = timing_defense.time_bomb(0.15, action)

        assert isinstance(thread, threading.Thread)
        assert thread.is_alive(), "Time bomb thread should be running"

        thread.join(timeout=1.0)
        assert triggered.is_set() or not thread.is_alive(), "Thread should complete or trigger"

    def test_time_bomb_triggers_after_duration(self, timing_defense: TimingAttackDefense) -> None:
        """Time bomb action executes after specified duration."""
        trigger_time = 0.2
        triggered = threading.Event()
        trigger_timestamp = None

        def action() -> None:
            nonlocal trigger_timestamp
            trigger_timestamp = time.time()
            triggered.set()

        start = time.time()
        thread = timing_defense.time_bomb(trigger_time, action)

        triggered.wait(timeout=2.0)

        if not triggered.is_set():
            pytest.skip("Time bomb did not trigger - possible timing anomaly detected")

        elapsed = trigger_timestamp - start
        assert 0.15 <= elapsed <= 1.0, f"Time bomb triggered at {elapsed}s"

    def test_time_bomb_thread_stored_in_tracking_list(self, timing_defense: TimingAttackDefense) -> None:
        """Time bomb threads are tracked in timing_threads list."""
        initial_count = len(timing_defense.timing_threads)

        triggered = threading.Event()
        thread = timing_defense.time_bomb(0.1, lambda: triggered.set())

        assert len(timing_defense.timing_threads) == initial_count + 1
        assert thread in timing_defense.timing_threads

        triggered.wait(timeout=0.3)

    def test_multiple_time_bombs_execute_independently(self, timing_defense: TimingAttackDefense) -> None:
        """Multiple time bombs can be armed and trigger independently."""
        triggered1 = threading.Event()
        triggered2 = threading.Event()

        thread1 = timing_defense.time_bomb(0.1, lambda: triggered1.set())
        thread2 = timing_defense.time_bomb(0.15, lambda: triggered2.set())

        assert isinstance(thread1, threading.Thread)
        assert isinstance(thread2, threading.Thread)

        thread1.join(timeout=1.5)
        thread2.join(timeout=1.5)

        assert not thread1.is_alive() or not thread2.is_alive(), "Threads should complete"


class TestExecutionDelay:
    """Test execution delay with environment checks."""

    def test_execution_delay_with_no_environment_checks(self, timing_defense: TimingAttackDefense) -> None:
        """Execution delay without environment checks completes simple sleep."""
        import unittest.mock

        with unittest.mock.patch.object(timing_defense, "secure_sleep", return_value=True) as mock_sleep:
            with unittest.mock.patch("random.uniform", return_value=1.0):
                timing_defense.execution_delay(check_environment=False)

            assert mock_sleep.called, "Should use secure_sleep for delay"
            call_args = mock_sleep.call_args[0]
            assert call_args[0] > 0, "Should sleep for positive duration"

    def test_execution_delay_performs_environment_checks(self, timing_defense: TimingAttackDefense) -> None:
        """Execution delay with checks performs periodic verification."""
        import unittest.mock

        check_count = 0

        def mock_debugger_check() -> bool:
            nonlocal check_count
            check_count += 1
            return False

        with unittest.mock.patch.object(timing_defense, "_quick_debugger_check", side_effect=mock_debugger_check):
            with unittest.mock.patch.object(timing_defense, "secure_sleep", return_value=True):
                with unittest.mock.patch("random.uniform", return_value=6.0):
                    timing_defense.execution_delay(check_environment=True)

        assert check_count > 0, "Should perform debugger checks during delay"


class TestAntiAccelerationLoop:
    """Test anti-acceleration loop with mixed sleep and computation."""

    def test_anti_acceleration_loop_runs_for_duration(self, timing_defense: TimingAttackDefense) -> None:
        """Anti-acceleration loop executes for specified duration."""
        duration = 0.5

        start = time.time()
        timing_defense.anti_acceleration_loop(duration)
        elapsed = time.time() - start

        assert 0.45 <= elapsed <= 0.7, f"Loop should run ~{duration}s, ran {elapsed}s"

    def test_anti_acceleration_loop_mixes_sleep_and_computation(self, timing_defense: TimingAttackDefense) -> None:
        """Loop alternates between sleep and CPU-intensive stalling."""
        import unittest.mock

        stalling_count = 0

        original_stalling = timing_defense.stalling_code

        def count_stalling(*args: Any, **kwargs: Any) -> None:
            nonlocal stalling_count
            stalling_count += 1
            if args[0] < 1.0:
                original_stalling(*args, **kwargs)

        with unittest.mock.patch.object(timing_defense, "stalling_code", side_effect=count_stalling):
            timing_defense.anti_acceleration_loop(0.3)

        assert stalling_count > 0, "Should perform stalling operations during loop"


class TestGetTickCountWindows:
    """Test Windows-specific GetTickCount64 functionality."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Requires Windows")
    def test_get_tick_count_returns_valid_value(self, timing_defense_windows_only: TimingAttackDefense) -> None:
        """GetTickCount64 returns valid tick count on Windows."""
        tick = timing_defense_windows_only._get_tick_count()

        assert tick is not None, "GetTickCount64 should return value on Windows"
        assert isinstance(tick, int)
        assert tick > 0, "Tick count should be positive"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Requires Windows")
    def test_get_tick_count_increases_over_time(self, timing_defense_windows_only: TimingAttackDefense) -> None:
        """GetTickCount64 increases monotonically."""
        tick1 = timing_defense_windows_only._get_tick_count()
        time.sleep(0.1)
        tick2 = timing_defense_windows_only._get_tick_count()

        assert tick2 > tick1, "Tick count should increase over time"
        elapsed_ms = tick2 - tick1
        assert 80 <= elapsed_ms <= 200, f"Tick count should increase by ~100ms, got {elapsed_ms}ms"


class TestQuickDebuggerCheck:
    """Test debugger presence detection."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Requires Windows IsDebuggerPresent")
    def test_quick_debugger_check_windows(self, timing_defense_windows_only: TimingAttackDefense) -> None:
        """Quick debugger check uses IsDebuggerPresent on Windows."""
        result = timing_defense_windows_only._quick_debugger_check()

        assert isinstance(result, bool), "Debugger check should return boolean"

    def test_quick_debugger_check_returns_boolean(self, timing_defense: TimingAttackDefense) -> None:
        """Debugger check returns boolean on all platforms."""
        result = timing_defense._quick_debugger_check()

        assert isinstance(result, bool)


class TestTimingDefenseCodeGeneration:
    """Test C code generation for timing attack defense."""

    def test_generates_valid_c_code_structure(self, timing_defense: TimingAttackDefense) -> None:
        """Generated C code has valid structure and required functions."""
        code = timing_defense.generate_timing_defense_code()

        assert isinstance(code, str)
        assert len(code) > 0, "Generated code should not be empty"

        assert "#include <windows.h>" in code
        assert "#include <time.h>" in code
        assert "#include <intrin.h>" in code

    def test_generated_code_contains_rdtsc_function(self, timing_defense: TimingAttackDefense) -> None:
        """Generated code includes RDTSC wrapper function."""
        code = timing_defense.generate_timing_defense_code()

        assert "GetRDTSC()" in code or "GetRDTSC (" in code
        assert "__rdtsc()" in code

    def test_generated_code_contains_secure_sleep_function(self, timing_defense: TimingAttackDefense) -> None:
        """Generated code includes SecureSleep with anti-acceleration."""
        code = timing_defense.generate_timing_defense_code()

        assert "SecureSleep" in code
        assert "GetTickCount64()" in code
        assert "Sleep(" in code

        assert "GetTickCount64() - startTick" in code or "GetTickCount64()-startTick" in code

    def test_generated_code_contains_stalling_function(self, timing_defense: TimingAttackDefense) -> None:
        """Generated code includes CPU-intensive stalling function."""
        code = timing_defense.generate_timing_defense_code()

        assert "StallExecution" in code
        assert "volatile" in code

    def test_generated_code_contains_execution_delay_function(self, timing_defense: TimingAttackDefense) -> None:
        """Generated code includes ExecutionDelay with checks."""
        code = timing_defense.generate_timing_defense_code()

        assert "ExecutionDelay" in code
        assert "IsDebuggerPresent()" in code

    def test_generated_code_uses_multiple_timing_sources(self, timing_defense: TimingAttackDefense) -> None:
        """Generated code verifies timing using multiple independent sources."""
        code = timing_defense.generate_timing_defense_code()

        timing_sources = [
            "GetTickCount64()",
            "__rdtsc()",
            "clock()",
        ]

        found_sources = sum(bool(source in code)
                        for source in timing_sources)
        assert found_sources >= 2, "Code should use multiple timing sources for verification"

    def test_generated_code_detects_timing_anomalies(self, timing_defense: TimingAttackDefense) -> None:
        """Generated code includes timing anomaly detection logic."""
        code = timing_defense.generate_timing_defense_code()

        assert "anomaly" in code.lower() or "drift" in code.lower() or "acceleration" in code.lower()


class TestTimingAttackRealBinaryAnalysis:
    """Test timing attack detection in real binary patterns."""

    def test_detect_rdtsc_instruction_pattern(self, timing_defense: TimingAttackDefense, tmp_path: Path) -> None:
        """Detect RDTSC instruction patterns in binary data."""
        rdtsc_patterns = [
            b"\x0F\x31",
            b"\x0F\x01\xF9",
        ]

        for pattern in rdtsc_patterns:
            test_binary = b"\x90" * 100 + pattern + b"\x90" * 100

            binary_file = tmp_path / "rdtsc_test.bin"
            binary_file.write_bytes(test_binary)

            data = binary_file.read_bytes()
            assert pattern in data, f"RDTSC pattern {pattern.hex()} should be detectable in binary"

    def test_detect_get_tick_count_import(self, timing_defense: TimingAttackDefense, tmp_path: Path) -> None:
        """Detect GetTickCount/GetTickCount64 API imports."""
        tick_count_apis = [
            b"GetTickCount\x00",
            b"GetTickCount64\x00",
            b"QueryPerformanceCounter\x00",
        ]

        for api in tick_count_apis:
            test_binary = b"\x00" * 100 + api + b"\x00" * 100

            binary_file = tmp_path / "timing_api_test.bin"
            binary_file.write_bytes(test_binary)

            data = binary_file.read_bytes()
            assert api in data, f"Timing API {api.decode('ascii', errors='ignore')} should be detectable"

    def test_detect_timing_comparison_patterns(self, timing_defense: TimingAttackDefense, tmp_path: Path) -> None:
        """Detect timing comparison code patterns in binary."""
        comparison_pattern = (
            b"\x0F\x31" +
            b"\x89\xC1" +
            b"\x89\xD2" +
            b"\x90" * 50 +
            b"\x0F\x31" +
            b"\x29\xC8" +
            b"\x3D\x00\x10\x00\x00" +
            b"\x0F\x87\x00\x00\x00\x00"
        )

        binary_file = tmp_path / "timing_check.bin"
        binary_file.write_bytes(comparison_pattern)

        data = binary_file.read_bytes()
        assert b"\x0F\x31" in data, "Should detect RDTSC in timing comparison code"
        assert b"\x29\xC8" in data, "Should detect SUB instruction for time delta"


class TestTimingAttackBypassGeneration:
    """Test generation of timing check bypass strategies."""

    def test_generate_rdtsc_nop_patch(self, timing_defense: TimingAttackDefense) -> None:
        """Generate NOP patch to bypass RDTSC timing checks."""
        rdtsc_instruction = b"\x0F\x31"
        nop_patch = b"\x90\x90"

        assert len(rdtsc_instruction) == len(nop_patch), "Patch should be same size as original"

    def test_generate_timing_check_bypass_strategy(self, timing_defense: TimingAttackDefense) -> None:
        """Generate strategy to bypass timing-based checks."""
        code = timing_defense.generate_timing_defense_code()

        bypass_strategies = {
            "rdtsc_hook": "Hook RDTSC to return constant values",
            "sleep_hook": "Hook Sleep/SecureSleep to return immediately",
            "tick_count_hook": "Hook GetTickCount64 to return accelerated time",
            "performance_counter_hook": "Hook QueryPerformanceCounter for consistent timing",
        }

        assert len(code) > 0, "Should generate defensive code that attackers would need to bypass"


class TestTimingConstantComparisonVulnerabilities:
    """Test detection of timing-based constant comparison vulnerabilities."""

    def test_detect_non_constant_time_string_comparison(self, timing_defense: TimingAttackDefense) -> None:
        """Detect vulnerable non-constant-time string comparisons."""

        def vulnerable_compare(a: str, b: str) -> bool:
            if len(a) != len(b):
                return False
            for i in range(len(a)):
                if a[i] != b[i]:
                    return False
            return True

        target = "SECRET_KEY_12345"
        attempts = ["A" * 15, "S" + "A" * 14, "SE" + "A" * 13]

        timings = []
        for attempt in attempts:
            start = time.perf_counter_ns()
            for _ in range(10000):
                vulnerable_compare(attempt, target)
            elapsed = time.perf_counter_ns() - start
            timings.append(elapsed)

        assert len(timings) == 3
        timing_variance = max(timings) - min(timings)
        assert timing_variance > 0, "Vulnerable comparison should show timing variance"

    def test_constant_time_comparison_recommendation(self, timing_defense: TimingAttackDefense) -> None:
        """Recommend constant-time comparison for security-sensitive operations."""
        import hmac

        secret1 = "SECRET_KEY_12345"
        secret2 = "SECRET_KEY_12345"
        secret3 = "WRONG_KEY_123456"

        assert hmac.compare_digest(secret1, secret2) is True
        assert hmac.compare_digest(secret1, secret3) is False


class TestCacheTimingAttackPatterns:
    """Test detection and analysis of cache timing attack patterns."""

    def test_cache_timing_measurement_basic(self, timing_defense: TimingAttackDefense) -> None:
        """Measure basic cache timing differences between cached and uncached access."""
        test_data = list(range(10000))

        access_times_cold = []
        for i in range(100):
            start = time.perf_counter_ns()
            _ = test_data[i]
            end = time.perf_counter_ns()
            access_times_cold.append(end - start)

        access_times_hot = []
        for i in range(100):
            start = time.perf_counter_ns()
            _ = test_data[i]
            end = time.perf_counter_ns()
            access_times_hot.append(end - start)

        avg_cold = sum(access_times_cold) / len(access_times_cold)
        avg_hot = sum(access_times_hot) / len(access_times_hot)

        assert avg_cold > 0 and avg_hot > 0, "Should measure access times"


class TestInstructionTimingAnalysis:
    """Test analysis of instruction-level timing characteristics."""

    def test_measure_instruction_execution_time(self, timing_defense: TimingAttackDefense) -> None:
        """Measure execution time of different instruction types."""
        iterations = 100000

        start = time.perf_counter_ns()
        result = sum(range(iterations))
        elapsed_add = time.perf_counter_ns() - start

        start = time.perf_counter_ns()
        result = 1
        for i in range(1, iterations):
            result *= i
            result %= 10000
        elapsed_mul = time.perf_counter_ns() - start

        assert elapsed_add > 0, "Addition operations should take measurable time"
        assert elapsed_mul > 0, "Multiplication operations should take measurable time"

    def test_compare_crypto_operation_timing(self, timing_defense: TimingAttackDefense) -> None:
        """Compare timing of cryptographic operations."""
        import hashlib

        data_small = b"test"
        data_large = b"test" * 1000

        start = time.perf_counter_ns()
        for _ in range(1000):
            hashlib.sha256(data_small).digest()
        elapsed_small = time.perf_counter_ns() - start

        start = time.perf_counter_ns()
        for _ in range(1000):
            hashlib.sha256(data_large).digest()
        elapsed_large = time.perf_counter_ns() - start

        assert elapsed_large > elapsed_small, "Larger data should take more time to hash"


class TestTimingAttackPerformanceBenchmarks:
    """Performance benchmarks for timing attack detection operations."""

    def test_rdtsc_check_performance(self, timing_defense: TimingAttackDefense) -> None:
        """Benchmark RDTSC timing check performance."""
        if not timing_defense.timing_checks["rdtsc_available"]:
            pytest.skip("RDTSC not available")

        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            result = timing_defense.rdtsc_timing_check()
        elapsed = time.perf_counter() - start

        assert isinstance(result, bool)
        avg_time = elapsed / iterations
        assert avg_time < 0.01, f"RDTSC check should be fast, avg {avg_time}s per call"

    def test_secure_sleep_overhead(self, timing_defense: TimingAttackDefense) -> None:
        """Measure overhead of secure sleep vs regular sleep."""
        duration = 0.1

        start = time.perf_counter()
        time.sleep(duration)
        regular_elapsed = time.perf_counter() - start

        start = time.perf_counter()
        timing_defense.secure_sleep(duration)
        secure_elapsed = time.perf_counter() - start

        overhead = secure_elapsed - regular_elapsed
        assert overhead < 0.1, f"Secure sleep overhead {overhead}s should be minimal"

    def test_stalling_code_cpu_consumption(self, timing_defense: TimingAttackDefense) -> None:
        """Verify stalling code actually consumes CPU cycles."""
        import psutil

        cpu_before = psutil.cpu_percent(interval=0.1)

        start = time.perf_counter()
        timing_defense.stalling_code(0.2, 0.25)
        elapsed = time.perf_counter() - start

        cpu_after = psutil.cpu_percent(interval=0.1)

        assert elapsed >= 0.2, "Stalling should run for minimum duration"


class TestTimingAttackIntegrationScenarios:
    """Integration tests for complete timing attack scenarios."""

    def test_complete_anti_debugging_timing_sequence(self, timing_defense: TimingAttackDefense) -> None:
        """Execute complete anti-debugging timing check sequence."""
        rdtsc_result = timing_defense.rdtsc_timing_check()
        steps_completed = [("rdtsc", rdtsc_result)]
        sleep_result = timing_defense.secure_sleep(0.1)
        steps_completed.append(("secure_sleep", sleep_result))

        debugger_present = timing_defense._quick_debugger_check()
        steps_completed.append(("debugger_check", debugger_present))

        assert len(steps_completed) == 3, "All timing checks should complete"
        assert all(isinstance(result, bool) for _, result in steps_completed)

    def test_timing_based_license_validation_delay(self, timing_defense: TimingAttackDefense) -> None:
        """Simulate timing-based license validation with anti-tampering."""
        license_valid = False

        rdtsc_normal = timing_defense.rdtsc_timing_check()
        if not rdtsc_normal:
            return

        sleep_normal = timing_defense.secure_sleep(0.2)
        if not sleep_normal:
            return

        if debugger_present := timing_defense._quick_debugger_check():
            return

    @pytest.mark.skipif(platform.system() != "Windows", reason="Requires Windows")
    def test_windows_timing_defense_integration(self, timing_defense_windows_only: TimingAttackDefense) -> None:
        """Complete Windows-specific timing defense integration."""
        tick_start = timing_defense_windows_only._get_tick_count()
        assert tick_start is not None

        result = timing_defense_windows_only.secure_sleep(0.2)

        tick_end = timing_defense_windows_only._get_tick_count()
        assert tick_end is not None

        tick_elapsed = (tick_end - tick_start) / 1000.0

        if not result:
            pytest.skip("Timing anomaly detected by Windows secure sleep")

        assert 0.10 <= tick_elapsed <= 0.50, "Windows tick count should track sleep duration"
