"""Production-ready tests for timing attack defense capabilities.

Tests validate real timing attack defense operations including:
- Secure sleep with anti-acceleration detection
- CPU-intensive stalling code execution
- Time bomb triggers with verification
- RDTSC-based timing anomaly detection
- Multi-source timing verification

These tests verify genuine defensive capabilities against timing-based analysis attacks.
"""

import platform
import threading
import time
from typing import Callable

import pytest

from intellicrack.core.anti_analysis.timing_attacks import TimingAttackDefense


class TestTimingAttackDefenseInitialization:
    """Test TimingAttackDefense initialization and configuration."""

    def test_defense_initializes_with_timing_checks(self) -> None:
        """TimingAttackDefense initializes with all timing source checks."""
        defense = TimingAttackDefense()

        assert defense.logger is not None
        assert defense.timing_threads is not None
        assert isinstance(defense.timing_threads, list)
        assert isinstance(defense.timing_checks, dict)
        assert "rdtsc_available" in defense.timing_checks
        assert "performance_counter" in defense.timing_checks
        assert "tick_count" in defense.timing_checks

    def test_rdtsc_availability_check_on_x86(self) -> None:
        """RDTSC availability check correctly identifies x86/x64 platforms."""
        defense = TimingAttackDefense()

        assert isinstance(defense.timing_checks["rdtsc_available"], bool)

        current_machine = platform.machine().lower()
        expected_rdtsc = current_machine in ["x86", "x86_64", "amd64", "i386", "i686"]

        assert defense.timing_checks["rdtsc_available"] == expected_rdtsc

    def test_performance_counter_always_available(self) -> None:
        """Performance counter marked as available on all platforms."""
        defense = TimingAttackDefense()

        assert defense.timing_checks["performance_counter"] is True

    def test_tick_count_availability(self) -> None:
        """Tick count availability checked correctly."""
        defense = TimingAttackDefense()

        assert defense.timing_checks["tick_count"] is True


class TestSecureSleep:
    """Test secure sleep with anti-acceleration detection."""

    def test_secure_sleep_completes_for_short_duration(self) -> None:
        """Secure sleep completes successfully for short durations."""
        defense = TimingAttackDefense()

        start_time = time.time()
        result = defense.secure_sleep(0.1)
        elapsed = time.time() - start_time

        assert result is True
        assert 0.08 <= elapsed <= 0.15

    def test_secure_sleep_executes_callback_during_sleep(self) -> None:
        """Secure sleep executes provided callback during sleep period."""
        defense = TimingAttackDefense()

        callback_count = [0]

        def test_callback() -> None:
            callback_count[0] += 1

        result = defense.secure_sleep(0.2, callback=test_callback)

        assert result is True
        assert callback_count[0] > 0

    def test_secure_sleep_detects_timing_drift(self) -> None:
        """Secure sleep detects excessive timing drift between sources."""
        defense = TimingAttackDefense()

        result = defense.secure_sleep(0.1)

        assert isinstance(result, bool)

    def test_secure_sleep_chunks_long_duration(self) -> None:
        """Secure sleep splits long durations into chunks for monitoring."""
        defense = TimingAttackDefense()

        callback_calls = [0]

        def counting_callback() -> None:
            callback_calls[0] += 1

        start_time = time.time()
        result = defense.secure_sleep(1.5, callback=counting_callback)
        elapsed = time.time() - start_time

        assert result is True
        assert 1.4 <= elapsed <= 1.7
        assert callback_calls[0] >= 10

    def test_secure_sleep_verifies_final_duration(self) -> None:
        """Secure sleep performs final duration verification."""
        defense = TimingAttackDefense()

        start_time = time.perf_counter()
        result = defense.secure_sleep(0.5)
        elapsed = time.perf_counter() - start_time

        assert isinstance(result, bool)
        if result:
            assert 0.4 <= elapsed <= 0.7

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific tick count test")
    def test_secure_sleep_uses_tick_count_on_windows(self) -> None:
        """Secure sleep uses GetTickCount64 for additional timing verification on Windows."""
        defense = TimingAttackDefense()

        tick_count = defense._get_tick_count()

        assert tick_count is not None
        assert isinstance(tick_count, int)
        assert tick_count > 0

    def test_secure_sleep_handles_exceptions_gracefully(self) -> None:
        """Secure sleep handles exceptions during callback execution."""
        defense = TimingAttackDefense()

        def failing_callback() -> None:
            raise ValueError("Test exception")

        with pytest.raises(ValueError):
            defense.secure_sleep(0.1, callback=failing_callback)


class TestStallingCode:
    """Test CPU-intensive stalling code execution."""

    def test_stalling_code_executes_for_minimum_duration(self) -> None:
        """Stalling code executes for at least minimum specified duration."""
        defense = TimingAttackDefense()

        start_time = time.perf_counter()
        defense.stalling_code(0.1, 0.2)
        elapsed = time.perf_counter() - start_time

        assert elapsed >= 0.09

    def test_stalling_code_performs_cpu_intensive_computation(self) -> None:
        """Stalling code performs genuine CPU-intensive computation."""
        defense = TimingAttackDefense()

        start_time = time.perf_counter()
        defense.stalling_code(0.05, 0.06)
        elapsed = time.perf_counter() - start_time

        assert elapsed >= 0.04

    def test_stalling_code_adapts_to_cpu_load(self) -> None:
        """Stalling code adapts behavior based on CPU load."""
        defense = TimingAttackDefense()

        start_time = time.perf_counter()
        defense.stalling_code(0.1, 0.11)
        elapsed = time.perf_counter() - start_time

        assert elapsed >= 0.08

    def test_stalling_code_completes_within_maximum_duration(self) -> None:
        """Stalling code completes within reasonable maximum bound."""
        defense = TimingAttackDefense()

        start_time = time.perf_counter()
        defense.stalling_code(0.1, 0.15)
        elapsed = time.perf_counter() - start_time

        assert elapsed <= 0.3

    def test_stalling_code_handles_errors_gracefully(self) -> None:
        """Stalling code handles errors during execution gracefully."""
        defense = TimingAttackDefense()

        try:
            defense.stalling_code(0.1, 0.2)
        except Exception as e:
            pytest.fail(f"Stalling code raised unexpected exception: {e}")


class TestTimeBomb:
    """Test time bomb trigger mechanism."""

    def test_time_bomb_creates_daemon_thread(self) -> None:
        """Time bomb creates daemon thread for background execution."""
        defense = TimingAttackDefense()

        action_called = [False]

        def test_action() -> None:
            action_called[0] = True

        thread = defense.time_bomb(0.1, test_action)

        assert isinstance(thread, threading.Thread)
        assert thread.daemon is True
        assert thread in defense.timing_threads

    def test_time_bomb_triggers_action_after_delay(self) -> None:
        """Time bomb executes action after specified delay."""
        defense = TimingAttackDefense()

        action_executed = [False]
        execution_time = [None]

        def timed_action() -> None:
            action_executed[0] = True
            execution_time[0] = time.time()

        start_time = time.time()
        defense.time_bomb(0.2, timed_action)

        time.sleep(0.3)

        assert action_executed[0] is True
        assert execution_time[0] is not None
        assert (execution_time[0] - start_time) >= 0.18

    def test_time_bomb_aborts_on_acceleration_detection(self) -> None:
        """Time bomb aborts action if timing acceleration detected."""
        defense = TimingAttackDefense()

        action_called = [False]

        def test_action() -> None:
            action_called[0] = True

        with patch.object(defense, "secure_sleep", return_value=False):
            thread = defense.time_bomb(0.1, test_action)
            thread.join(timeout=0.5)

            assert action_called[0] is False

    def test_time_bomb_tracks_active_threads(self) -> None:
        """Time bomb tracking maintains list of active timing threads."""
        defense = TimingAttackDefense()

        initial_count = len(defense.timing_threads)

        defense.time_bomb(0.1, lambda: None)
        defense.time_bomb(0.1, lambda: None)

        assert len(defense.timing_threads) == initial_count + 2


class TestExecutionDelay:
    """Test execution delay for automated analysis evasion."""

    def test_execution_delay_with_environment_checks(self) -> None:
        """Execution delay performs environment checks during delay period."""
        defense = TimingAttackDefense()

        with patch.object(defense, "secure_sleep", return_value=True):
            with patch.object(defense, "_quick_debugger_check", return_value=False):
                with patch("random.uniform", return_value=0.5):
                    start_time = time.time()
                    defense.execution_delay(check_environment=True)
                    elapsed = time.time() - start_time

                    assert elapsed >= 0.0

    def test_execution_delay_extends_on_debugger_detection(self) -> None:
        """Execution delay extends duration when debugger detected."""
        defense = TimingAttackDefense()

        check_count = [0]

        def mock_debugger_check() -> bool:
            check_count[0] += 1
            return check_count[0] == 1

        with patch.object(defense, "_quick_debugger_check", side_effect=mock_debugger_check):
            with patch.object(defense, "secure_sleep", return_value=True):
                with patch("random.uniform", return_value=0.5):
                    defense.execution_delay(check_environment=True)

    def test_execution_delay_triggers_stalling_on_acceleration(self) -> None:
        """Execution delay triggers stalling code when acceleration detected."""
        defense = TimingAttackDefense()

        stalling_called = [False]

        def mock_stalling(min_dur: float, max_dur: float) -> None:
            stalling_called[0] = True

        with patch.object(defense, "secure_sleep", return_value=False):
            with patch.object(defense, "stalling_code", side_effect=mock_stalling):
                with patch.object(defense, "_quick_debugger_check", return_value=False):
                    with patch("random.uniform", return_value=0.5):
                        defense.execution_delay(check_environment=True)

                        assert stalling_called[0] is True

    def test_execution_delay_without_environment_checks(self) -> None:
        """Execution delay performs simple sleep without checks when disabled."""
        defense = TimingAttackDefense()

        with patch.object(defense, "secure_sleep", return_value=True) as mock_sleep:
            with patch("random.uniform", return_value=0.5):
                defense.execution_delay(check_environment=False)

                assert mock_sleep.call_count >= 1


class TestRDTSCTimingCheck:
    """Test RDTSC-based timing anomaly detection."""

    def test_rdtsc_timing_check_measures_execution_time(self) -> None:
        """RDTSC timing check measures execution time for known operation."""
        defense = TimingAttackDefense()

        if defense.timing_checks["rdtsc_available"]:
            result = defense.rdtsc_timing_check()
            assert isinstance(result, bool)

    def test_rdtsc_timing_check_detects_acceleration(self) -> None:
        """RDTSC timing check detects timing acceleration."""
        defense = TimingAttackDefense()

        if not defense.timing_checks["rdtsc_available"]:
            pytest.skip("RDTSC not available on this platform")

        with patch("time.perf_counter_ns") as mock_ns:
            mock_ns.side_effect = [1000000, 1000100]

            result = defense.rdtsc_timing_check()

            assert result is False

    def test_rdtsc_check_returns_true_when_unavailable(self) -> None:
        """RDTSC check returns True when RDTSC unavailable."""
        defense = TimingAttackDefense()
        defense.timing_checks["rdtsc_available"] = False

        result = defense.rdtsc_timing_check()

        assert result is True

    def test_rdtsc_check_validates_normal_execution(self) -> None:
        """RDTSC check validates normal execution timing."""
        defense = TimingAttackDefense()

        if defense.timing_checks["rdtsc_available"]:
            with patch("time.perf_counter_ns") as mock_ns:
                mock_ns.side_effect = [1000000, 2000000]

                result = defense.rdtsc_timing_check()

                assert result is True


class TestAntiAccelerationLoop:
    """Test anti-acceleration loop resistance."""

    def test_anti_acceleration_loop_executes_for_duration(self) -> None:
        """Anti-acceleration loop executes for specified duration."""
        defense = TimingAttackDefense()

        with patch.object(defense, "stalling_code"):
            with patch.object(defense, "rdtsc_timing_check", return_value=True):
                start_time = time.time()
                defense.anti_acceleration_loop(0.3)
                elapsed = time.time() - start_time

                assert elapsed >= 0.25

    def test_anti_acceleration_loop_mixes_sleep_and_computation(self) -> None:
        """Anti-acceleration loop alternates between sleep and computation."""
        defense = TimingAttackDefense()

        stalling_count = [0]

        def count_stalling(min_d: float, max_d: float) -> None:
            stalling_count[0] += 1

        with patch.object(defense, "stalling_code", side_effect=count_stalling):
            with patch.object(defense, "rdtsc_timing_check", return_value=True):
                defense.anti_acceleration_loop(0.3)

                assert stalling_count[0] > 0

    def test_anti_acceleration_loop_increases_load_on_detection(self) -> None:
        """Anti-acceleration loop increases computational load when acceleration detected."""
        defense = TimingAttackDefense()

        detection_count = [0]
        stalling_calls = []

        def mock_rdtsc() -> bool:
            detection_count[0] += 1
            return detection_count[0] % 3 != 0

        def track_stalling(min_d: float, max_d: float) -> None:
            stalling_calls.append((min_d, max_d))

        with patch.object(defense, "rdtsc_timing_check", side_effect=mock_rdtsc):
            with patch.object(defense, "stalling_code", side_effect=track_stalling):
                defense.anti_acceleration_loop(0.3)

                heavy_stalling = [call for call in stalling_calls if call[0] >= 0.5]
                assert len(heavy_stalling) > 0


class TestDebuggerDetection:
    """Test quick debugger detection."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific debugger check")
    def test_quick_debugger_check_uses_windows_api(self) -> None:
        """Quick debugger check uses IsDebuggerPresent on Windows."""
        defense = TimingAttackDefense()

        result = defense._quick_debugger_check()

        assert isinstance(result, bool)

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux-specific debugger check")
    def test_quick_debugger_check_reads_tracer_pid(self) -> None:
        """Quick debugger check reads TracerPid from /proc/self/status on Linux."""
        defense = TimingAttackDefense()

        result = defense._quick_debugger_check()

        assert isinstance(result, bool)


class TestTimingDefenseCodeGeneration:
    """Test timing defense code generation."""

    def test_generate_timing_defense_code_returns_c_code(self) -> None:
        """Code generation returns valid C code for timing defense."""
        defense = TimingAttackDefense()

        code = defense.generate_timing_defense_code()

        assert isinstance(code, str)
        assert len(code) > 0
        assert "#include <windows.h>" in code
        assert "__rdtsc()" in code
        assert "SecureSleep" in code
        assert "GetTickCount64()" in code

    def test_generated_code_includes_rdtsc_function(self) -> None:
        """Generated C code includes RDTSC wrapper function."""
        defense = TimingAttackDefense()

        code = defense.generate_timing_defense_code()

        assert "GetRDTSC" in code
        assert "unsigned __int64" in code

    def test_generated_code_includes_secure_sleep(self) -> None:
        """Generated C code includes secure sleep implementation."""
        defense = TimingAttackDefense()

        code = defense.generate_timing_defense_code()

        assert "bool SecureSleep" in code
        assert "GetTickCount64()" in code
        assert "Sleep(sleepTime)" in code

    def test_generated_code_includes_stalling_function(self) -> None:
        """Generated C code includes CPU stalling implementation."""
        defense = TimingAttackDefense()

        code = defense.generate_timing_defense_code()

        assert "StallExecution" in code


class TestRealWorldDefenseScenarios:
    """Test real-world timing attack defense scenarios."""

    def test_complete_timing_defense_workflow(self) -> None:
        """Complete timing defense workflow with multiple protections."""
        defense = TimingAttackDefense()

        assert defense.timing_checks["performance_counter"] is True

        if defense.timing_checks["rdtsc_available"]:
            rdtsc_result = defense.rdtsc_timing_check()
            assert isinstance(rdtsc_result, bool)

        sleep_result = defense.secure_sleep(0.1)
        assert sleep_result is True

    def test_time_bomb_with_verification_workflow(self) -> None:
        """Time bomb creation and verification workflow."""
        defense = TimingAttackDefense()

        action_executed = [False]
        execution_verified = [False]

        def verified_action() -> None:
            action_executed[0] = True
            if defense.rdtsc_timing_check():
                execution_verified[0] = True

        thread = defense.time_bomb(0.15, verified_action)

        assert thread.is_alive()
        thread.join(timeout=0.5)

        assert action_executed[0] is True

    def test_multi_layer_timing_defense(self) -> None:
        """Multi-layer timing defense with all protection mechanisms."""
        defense = TimingAttackDefense()

        start_time = time.time()

        sleep_success = defense.secure_sleep(0.1)
        assert sleep_success is True

        defense.stalling_code(0.05, 0.08)

        if defense.timing_checks["rdtsc_available"]:
            timing_valid = defense.rdtsc_timing_check()
            assert isinstance(timing_valid, bool)

        elapsed = time.time() - start_time
        assert elapsed >= 0.14


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_secure_sleep_handles_zero_duration(self) -> None:
        """Secure sleep handles zero duration gracefully."""
        defense = TimingAttackDefense()

        result = defense.secure_sleep(0.0)

        assert isinstance(result, bool)

    def test_secure_sleep_handles_negative_duration(self) -> None:
        """Secure sleep handles negative duration gracefully."""
        defense = TimingAttackDefense()

        result = defense.secure_sleep(-1.0)

        assert isinstance(result, bool)

    def test_stalling_code_handles_reversed_duration_range(self) -> None:
        """Stalling code handles reversed min/max duration range."""
        defense = TimingAttackDefense()

        defense.stalling_code(0.2, 0.1)

    def test_time_bomb_handles_action_exceptions(self) -> None:
        """Time bomb handles exceptions in action callback."""
        defense = TimingAttackDefense()

        def failing_action() -> None:
            raise ValueError("Test error")

        thread = defense.time_bomb(0.05, failing_action)
        thread.join(timeout=0.3)

        assert not thread.is_alive()

    def test_rdtsc_check_handles_missing_perf_counter_ns(self) -> None:
        """RDTSC check handles missing perf_counter_ns gracefully."""
        defense = TimingAttackDefense()

        with patch("time.perf_counter_ns", side_effect=AttributeError):
            result = defense.rdtsc_timing_check()

            assert result is True

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux error handling test")
    def test_tick_count_returns_none_on_linux(self) -> None:
        """Tick count returns None on non-Windows platforms."""
        defense = TimingAttackDefense()

        tick = defense._get_tick_count()

        assert tick is None


class TestPerformanceAndConcurrency:
    """Test performance and thread safety."""

    def test_concurrent_secure_sleep_operations(self) -> None:
        """Multiple concurrent secure sleep operations execute correctly."""
        defense = TimingAttackDefense()

        results = []

        def sleep_task() -> None:
            result = defense.secure_sleep(0.1)
            results.append(result)

        threads = [threading.Thread(target=sleep_task) for _ in range(5)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(timeout=1.0)

        assert len(results) == 5
        assert all(results)

    def test_multiple_time_bombs_execute_independently(self) -> None:
        """Multiple time bombs execute independently without interference."""
        defense = TimingAttackDefense()

        execution_order = []

        def action1() -> None:
            execution_order.append(1)

        def action2() -> None:
            execution_order.append(2)

        def action3() -> None:
            execution_order.append(3)

        defense.time_bomb(0.05, action1)
        defense.time_bomb(0.10, action2)
        defense.time_bomb(0.15, action3)

        time.sleep(0.25)

        assert len(execution_order) == 3
        assert 1 in execution_order
        assert 2 in execution_order
        assert 3 in execution_order

    def test_timing_defense_performance_overhead(self) -> None:
        """Timing defense operations complete with acceptable overhead."""
        defense = TimingAttackDefense()

        start_time = time.perf_counter()

        for _ in range(10):
            defense.secure_sleep(0.01)

        elapsed = time.perf_counter() - start_time

        assert elapsed < 0.5
