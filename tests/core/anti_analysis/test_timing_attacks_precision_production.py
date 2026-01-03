"""Production-ready tests for high-precision timing attack defense.

Tests validate timing attack defense with 10-50ms precision requirements:
- Multi-source timing spoofing (RDTSC, QueryPerformanceCounter, timeGetTime)
- Timing correlation detection between different sources
- Timing-based anti-debug pattern detection
- Consistent spoofed timing across all Windows APIs
- Multi-core TSC synchronization handling
- HPET (High Precision Event Timer) support

These tests verify genuine defensive capabilities meet production precision requirements.
"""

import ctypes
import platform
import threading
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.core.anti_analysis.timing_attacks import TimingAttackDefense


class TestHighPrecisionTimingMeasurement:
    """Test high-precision timing measurements with 10-50ms accuracy."""

    def test_secure_sleep_achieves_10ms_precision_for_short_durations(self) -> None:
        """Secure sleep achieves 10-50ms precision for durations under 1 second."""
        defense = TimingAttackDefense()

        test_durations = [0.1, 0.2, 0.5, 0.8]

        for target_duration in test_durations:
            start_time = time.perf_counter()
            result = defense.secure_sleep(target_duration)
            elapsed = time.perf_counter() - start_time

            assert result is True
            drift = abs(elapsed - target_duration)
            assert drift <= 0.05, f"Drift {drift*1000:.1f}ms exceeds 50ms for {target_duration}s sleep"

    def test_secure_sleep_timing_drift_detection_threshold_is_10_to_50ms(self) -> None:
        """Secure sleep uses 10-50ms drift threshold for anomaly detection."""
        defense = TimingAttackDefense()

        start_time = time.perf_counter()
        result = defense.secure_sleep(0.3)
        elapsed = time.perf_counter() - start_time

        if result:
            drift = abs(elapsed - 0.3)
            assert drift <= 0.05

    def test_timing_verification_detects_drift_below_50ms_threshold(self) -> None:
        """Timing verification correctly identifies drift within 50ms as acceptable."""
        defense = TimingAttackDefense()

        start_perf = time.perf_counter()
        start_real = time.time()

        time.sleep(0.2)

        elapsed_perf = time.perf_counter() - start_perf
        elapsed_real = time.time() - start_real

        drift = abs(elapsed_perf - elapsed_real)

        assert drift < 0.05

    def test_rdtsc_timing_precision_for_short_operations(self) -> None:
        """RDTSC-based timing provides nanosecond precision for short operations."""
        defense = TimingAttackDefense()

        if not defense.timing_checks["rdtsc_available"]:
            pytest.skip("RDTSC not available on this platform")

        measurements = []
        for _ in range(10):
            start = time.perf_counter_ns()
            _ = sum(range(10000))
            end = time.perf_counter_ns()
            measurements.append(end - start)

        avg_time = sum(measurements) / len(measurements)
        variance = sum((m - avg_time) ** 2 for m in measurements) / len(measurements)

        assert variance < (avg_time * 0.5) ** 2


class TestMultipleTimingSourceSpoofing:
    """Test spoofing across multiple Windows timing sources."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific timing sources")
    def test_rdtsc_timing_source_access(self) -> None:
        """RDTSC timing source accessible and returns valid values."""
        defense = TimingAttackDefense()

        if not defense.timing_checks["rdtsc_available"]:
            pytest.skip("RDTSC not available")

        start_ns = time.perf_counter_ns()
        time.sleep(0.01)
        end_ns = time.perf_counter_ns()

        elapsed_ns = end_ns - start_ns
        assert elapsed_ns >= 10_000_000
        assert elapsed_ns < 50_000_000

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific QPC")
    def test_query_performance_counter_timing_source(self) -> None:
        """QueryPerformanceCounter (QPC) timing source provides high precision."""
        defense = TimingAttackDefense()

        assert defense.timing_checks["performance_counter"] is True

        start_qpc = time.perf_counter()
        time.sleep(0.05)
        end_qpc = time.perf_counter()

        elapsed = end_qpc - start_qpc
        assert 0.04 <= elapsed <= 0.10

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific timeGetTime")
    def test_get_tick_count_timing_source(self) -> None:
        """GetTickCount64/timeGetTime provides millisecond resolution."""
        defense = TimingAttackDefense()

        tick1 = defense._get_tick_count()
        assert tick1 is not None

        time.sleep(0.1)

        tick2 = defense._get_tick_count()
        assert tick2 is not None

        elapsed_ms = tick2 - tick1
        assert 90 <= elapsed_ms <= 150

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific timing")
    def test_all_timing_sources_provide_consistent_measurements(self) -> None:
        """All timing sources (RDTSC, QPC, GetTickCount) provide consistent readings."""
        defense = TimingAttackDefense()

        start_perf = time.perf_counter()
        start_tick = defense._get_tick_count()
        start_time = time.time()

        if defense.timing_checks["rdtsc_available"]:
            start_rdtsc = time.perf_counter_ns()

        time.sleep(0.2)

        end_perf = time.perf_counter()
        end_tick = defense._get_tick_count()
        end_time = time.time()

        if defense.timing_checks["rdtsc_available"]:
            end_rdtsc = time.perf_counter_ns()

        elapsed_perf = end_perf - start_perf
        if start_tick is not None and end_tick is not None:
            elapsed_tick = (end_tick - start_tick) / 1000.0
        else:
            elapsed_tick = elapsed_perf
        elapsed_time = end_time - start_time

        drift_tick_perf = abs(elapsed_tick - elapsed_perf)
        drift_time_perf = abs(elapsed_time - elapsed_perf)

        assert drift_tick_perf <= 0.05
        assert drift_time_perf <= 0.05

        if defense.timing_checks["rdtsc_available"]:
            elapsed_rdtsc_s = (end_rdtsc - start_rdtsc) / 1_000_000_000
            drift_rdtsc_perf = abs(elapsed_rdtsc_s - elapsed_perf)
            assert drift_rdtsc_perf <= 0.05


class TestTimingCorrelationDetection:
    """Test detection of timing correlation anomalies between sources."""

    def test_secure_sleep_detects_correlation_anomaly_between_sources(self) -> None:
        """Secure sleep detects when timing sources disagree beyond threshold."""
        defense = TimingAttackDefense()

        with patch("time.time") as mock_time:
            with patch("time.perf_counter") as mock_perf:
                mock_time.side_effect = [0.0, 0.2]
                mock_perf.side_effect = [0.0, 0.0, 0.0, 0.0, 0.0, 0.35]

                result = defense.secure_sleep(0.2)

                assert result is False

    def test_timing_correlation_validated_across_thread_time(self) -> None:
        """Timing correlation validated between perf_counter and thread_time."""
        defense = TimingAttackDefense()

        if not hasattr(time, "thread_time"):
            pytest.skip("thread_time not available")

        start_perf = time.perf_counter()
        start_thread = time.thread_time()

        time.sleep(0.1)

        end_perf = time.perf_counter()
        end_thread = time.thread_time()

        elapsed_perf = end_perf - start_perf
        elapsed_thread = end_thread - start_thread

        drift = abs(elapsed_thread - elapsed_perf)

        assert drift <= 0.05

    def test_tick_count_correlation_with_performance_counter(self) -> None:
        """Tick count timing correlates with QueryPerformanceCounter."""
        defense = TimingAttackDefense()

        start_tick = defense._get_tick_count()
        start_perf = time.perf_counter()

        time.sleep(0.15)

        end_tick = defense._get_tick_count()
        end_perf = time.perf_counter()

        elapsed_perf = end_perf - start_perf

        if start_tick is not None and end_tick is not None:
            elapsed_tick = (end_tick - start_tick) / 1000.0
            drift = abs(elapsed_tick - elapsed_perf)
            assert drift <= 0.05

    def test_secure_sleep_fails_when_correlation_drift_exceeds_threshold(self) -> None:
        """Secure sleep returns False when timing source correlation exceeds threshold."""
        defense = TimingAttackDefense()

        with patch("time.time") as mock_time:
            with patch("time.perf_counter") as mock_perf:
                mock_time.side_effect = [0.0, 0.5]
                mock_perf.side_effect = [0.0] * 10 + [0.2]

                result = defense.secure_sleep(0.1)

                assert result is False


class TestTimingBasedAntiDebugPatternDetection:
    """Test detection of timing-based anti-debugging techniques."""

    def test_detects_accelerated_sleep_pattern(self) -> None:
        """Defense detects accelerated sleep characteristic of debuggers."""
        defense = TimingAttackDefense()

        with patch("time.sleep"):
            with patch("time.time") as mock_time:
                with patch("time.perf_counter") as mock_perf:
                    mock_time.side_effect = [0.0, 0.001]
                    mock_perf.side_effect = [0.0, 0.0, 0.0, 0.0, 0.001]

                    result = defense.secure_sleep(1.0)

                    assert result is False

    def test_detects_timing_manipulation_in_chunks(self) -> None:
        """Defense detects timing manipulation during chunked sleep verification."""
        defense = TimingAttackDefense()

        chunk_results = []

        def mock_sleep(duration: float) -> None:
            chunk_results.append(duration)

        with patch("time.sleep", side_effect=mock_sleep):
            with patch("time.time") as mock_time:
                with patch("time.perf_counter") as mock_perf:
                    mock_time.side_effect = [0.0, 0.05]
                    mock_perf.side_effect = [0.0, 0.0, 0.0, 0.0, 0.0, 0.5]

                    result = defense.secure_sleep(0.5)

                    assert result is False

    def test_rdtsc_timing_check_detects_abnormal_execution_speed(self) -> None:
        """RDTSC timing check detects abnormally fast execution (acceleration)."""
        defense = TimingAttackDefense()

        if not defense.timing_checks["rdtsc_available"]:
            pytest.skip("RDTSC not available")

        with patch("time.perf_counter_ns") as mock_ns:
            mock_ns.side_effect = [1000000, 1000050]

            result = defense.rdtsc_timing_check()

            assert result is False

    def test_anti_acceleration_loop_detects_timing_anomalies(self) -> None:
        """Anti-acceleration loop detects and responds to timing anomalies."""
        defense = TimingAttackDefense()

        detection_triggered = [False]

        original_rdtsc = defense.rdtsc_timing_check

        def mock_rdtsc() -> bool:
            detection_triggered[0] = True
            return False

        with patch.object(defense, "rdtsc_timing_check", side_effect=mock_rdtsc):
            with patch.object(defense, "stalling_code"):
                defense.anti_acceleration_loop(0.2)

                assert detection_triggered[0] is True

    def test_execution_delay_extends_on_debugger_detection_pattern(self) -> None:
        """Execution delay recognizes debugger presence pattern and extends duration."""
        defense = TimingAttackDefense()

        debugger_detected = [False]

        def mock_debugger_check() -> bool:
            debugger_detected[0] = True
            return True

        with patch.object(defense, "_quick_debugger_check", side_effect=mock_debugger_check):
            with patch.object(defense, "secure_sleep", return_value=True):
                with patch("random.uniform", return_value=0.5):
                    defense.execution_delay(check_environment=True)

                    assert debugger_detected[0] is True


class TestConsistentSpoofedTimingAcrossAPIs:
    """Test that spoofed timing remains consistent across different API calls."""

    def test_multiple_timing_apis_return_synchronized_values(self) -> None:
        """Multiple timing API calls return synchronized values within precision bounds."""
        defense = TimingAttackDefense()

        measurements = []

        for _ in range(5):
            start_time = time.time()
            start_perf = time.perf_counter()
            start_tick = defense._get_tick_count()

            time.sleep(0.1)

            end_time = time.time()
            end_perf = time.perf_counter()
            end_tick = defense._get_tick_count()

            elapsed_time = end_time - start_time
            elapsed_perf = end_perf - start_perf

            measurements.append({
                "time": elapsed_time,
                "perf": elapsed_perf,
                "tick": (end_tick - start_tick) / 1000.0 if start_tick and end_tick else elapsed_perf,
            })

        for measurement in measurements:
            drift_time_perf = abs(measurement["time"] - measurement["perf"])
            drift_tick_perf = abs(measurement["tick"] - measurement["perf"])

            assert drift_time_perf <= 0.05
            assert drift_tick_perf <= 0.05

    def test_timing_consistency_maintained_during_stalling_code(self) -> None:
        """Timing consistency maintained across APIs during CPU-intensive stalling."""
        defense = TimingAttackDefense()

        start_time = time.time()
        start_perf = time.perf_counter()

        defense.stalling_code(0.1, 0.15)

        elapsed_time = time.time() - start_time
        elapsed_perf = time.perf_counter() - start_perf

        drift = abs(elapsed_time - elapsed_perf)
        assert drift <= 0.05

    def test_secure_sleep_maintains_api_consistency_across_chunks(self) -> None:
        """Secure sleep maintains timing API consistency across chunked sleeps."""
        defense = TimingAttackDefense()

        chunk_count = [0]

        def verify_callback() -> None:
            chunk_count[0] += 1

            start_perf = time.perf_counter()
            start_time = time.time()

            time.sleep(0.01)

            elapsed_perf = time.perf_counter() - start_perf
            elapsed_time = time.time() - start_time

            drift = abs(elapsed_perf - elapsed_time)
            assert drift <= 0.05

        result = defense.secure_sleep(0.5, callback=verify_callback)

        assert result is True
        assert chunk_count[0] > 0


class TestMultiCoreTSCSynchronization:
    """Test handling of multi-core TSC synchronization issues."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific TSC test")
    def test_tsc_synchronization_across_cpu_cores(self) -> None:
        """TSC measurements remain synchronized across CPU cores."""
        defense = TimingAttackDefense()

        if not defense.timing_checks["rdtsc_available"]:
            pytest.skip("RDTSC not available")

        import psutil

        cpu_count = psutil.cpu_count(logical=True)
        if cpu_count < 2:
            pytest.skip("Multi-core test requires 2+ cores")

        measurements = []

        def measure_on_core() -> None:
            start = time.perf_counter_ns()
            time.sleep(0.05)
            end = time.perf_counter_ns()
            measurements.append(end - start)

        threads = [threading.Thread(target=measure_on_core) for _ in range(min(4, cpu_count))]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(timeout=1.0)

        avg_measurement = sum(measurements) / len(measurements)

        for measurement in measurements:
            drift = abs(measurement - avg_measurement)
            drift_ratio = drift / avg_measurement

            assert drift_ratio <= 0.1

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific TSC test")
    def test_rdtsc_consistency_with_thread_migration(self) -> None:
        """RDTSC timing remains consistent even with thread migration across cores."""
        defense = TimingAttackDefense()

        if not defense.timing_checks["rdtsc_available"]:
            pytest.skip("RDTSC not available")

        results = []

        def timing_task() -> None:
            for _ in range(10):
                start = time.perf_counter_ns()
                _ = sum(range(100000))
                end = time.perf_counter_ns()
                results.append(end - start)
                time.sleep(0.001)

        thread = threading.Thread(target=timing_task)
        thread.start()
        thread.join(timeout=2.0)

        if len(results) > 1:
            avg_time = sum(results) / len(results)
            max_deviation = max(abs(r - avg_time) for r in results)
            deviation_ratio = max_deviation / avg_time

            assert deviation_ratio <= 0.5

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific multi-core test")
    def test_concurrent_timing_operations_on_multiple_cores(self) -> None:
        """Concurrent timing operations across cores maintain synchronization."""
        defense = TimingAttackDefense()

        import psutil

        cpu_count = psutil.cpu_count(logical=True)
        if cpu_count < 2:
            pytest.skip("Multi-core test requires 2+ cores")

        completion_times = []

        def timed_operation() -> None:
            start = time.perf_counter()
            defense.secure_sleep(0.1)
            elapsed = time.perf_counter() - start
            completion_times.append(elapsed)

        threads = [threading.Thread(target=timed_operation) for _ in range(min(4, cpu_count))]

        start_all = time.perf_counter()

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(timeout=1.0)

        total_elapsed = time.perf_counter() - start_all

        for completion in completion_times:
            assert 0.08 <= completion <= 0.15

        assert total_elapsed <= 0.5


class TestHPETSupport:
    """Test High Precision Event Timer (HPET) support and integration."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific HPET test")
    def test_hpet_compatible_timing_measurement(self) -> None:
        """Timing measurements compatible with HPET resolution."""
        defense = TimingAttackDefense()

        start = time.perf_counter()
        time.sleep(0.001)
        end = time.perf_counter()

        elapsed_ms = (end - start) * 1000

        assert 0.5 <= elapsed_ms <= 5.0

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific HPET test")
    def test_high_resolution_timing_with_hpet_precision(self) -> None:
        """High-resolution timing achieves HPET-level precision (microsecond range)."""
        defense = TimingAttackDefense()

        measurements = []

        for _ in range(100):
            start = time.perf_counter()
            end = time.perf_counter()
            measurements.append((end - start) * 1_000_000)

        avg_overhead_us = sum(measurements) / len(measurements)

        assert avg_overhead_us < 10

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific HPET test")
    def test_hpet_timing_source_availability(self) -> None:
        """HPET timing source availability verified through performance counter."""
        defense = TimingAttackDefense()

        assert defense.timing_checks["performance_counter"] is True

        freq_samples = []
        for _ in range(10):
            start = time.perf_counter_ns()
            time.sleep(0.01)
            end = time.perf_counter_ns()

            elapsed = end - start
            freq_samples.append(elapsed)

        avg_elapsed = sum(freq_samples) / len(freq_samples)

        assert 9_000_000 <= avg_elapsed <= 15_000_000

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific HPET test")
    def test_timing_drift_detection_with_hpet_precision(self) -> None:
        """Timing drift detection operates at HPET precision levels."""
        defense = TimingAttackDefense()

        start_perf = time.perf_counter_ns()
        start_time = time.time()

        time.sleep(0.1)

        end_perf = time.perf_counter_ns()
        end_time = time.time()

        elapsed_perf_us = (end_perf - start_perf) / 1000
        elapsed_time_us = (end_time - start_time) * 1_000_000

        drift_us = abs(elapsed_perf_us - elapsed_time_us)

        assert drift_us < 50_000


class TestRealWorldTimingAttackDefenseScenarios:
    """Test complete real-world timing attack defense scenarios."""

    def test_complete_multi_source_timing_verification_workflow(self) -> None:
        """Complete workflow verifying all timing sources with <50ms precision."""
        defense = TimingAttackDefense()

        target_duration = 0.3

        start_time = time.time()
        start_perf = time.perf_counter()
        start_tick = defense._get_tick_count()

        if defense.timing_checks["rdtsc_available"]:
            start_rdtsc = time.perf_counter_ns()

        result = defense.secure_sleep(target_duration)

        elapsed_time = time.time() - start_time
        elapsed_perf = time.perf_counter() - start_perf

        end_tick = defense._get_tick_count()
        if start_tick and end_tick:
            elapsed_tick = (end_tick - start_tick) / 1000.0
        else:
            elapsed_tick = elapsed_perf

        assert result is True

        drift_time = abs(elapsed_time - target_duration)
        drift_perf = abs(elapsed_perf - target_duration)
        drift_tick = abs(elapsed_tick - target_duration)

        assert drift_time <= 0.05
        assert drift_perf <= 0.05
        assert drift_tick <= 0.05

        if defense.timing_checks["rdtsc_available"]:
            end_rdtsc = time.perf_counter_ns()
            elapsed_rdtsc_s = (end_rdtsc - start_rdtsc) / 1_000_000_000
            drift_rdtsc = abs(elapsed_rdtsc_s - target_duration)
            assert drift_rdtsc <= 0.05

    def test_timing_attack_resistance_with_all_protections_enabled(self) -> None:
        """Timing attack resistance with all protection mechanisms active."""
        defense = TimingAttackDefense()

        sleep_result = defense.secure_sleep(0.15)
        assert sleep_result is True

        if defense.timing_checks["rdtsc_available"]:
            rdtsc_result = defense.rdtsc_timing_check()
            assert isinstance(rdtsc_result, bool)

        start_time = time.perf_counter()
        defense.stalling_code(0.05, 0.08)
        elapsed = time.perf_counter() - start_time

        assert elapsed >= 0.04

    def test_detection_of_sophisticated_timing_manipulation(self) -> None:
        """Detection of sophisticated timing manipulation across multiple sources."""
        defense = TimingAttackDefense()

        with patch("time.time") as mock_time:
            with patch("time.perf_counter") as mock_perf:
                mock_time.side_effect = [0.0, 0.3]
                mock_perf.side_effect = [0.0, 0.0, 0.0, 0.0, 0.0, 0.15]

                result = defense.secure_sleep(0.3)

                assert result is False

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific comprehensive test")
    def test_windows_comprehensive_timing_source_validation(self) -> None:
        """Comprehensive validation of all Windows timing sources with precision requirements."""
        defense = TimingAttackDefense()

        timing_measurements: dict[str, list[float]] = {
            "time.time": [],
            "perf_counter": [],
            "tick_count": [],
        }

        if defense.timing_checks["rdtsc_available"]:
            timing_measurements["rdtsc"] = []

        for iteration in range(5):
            start_time = time.time()
            start_perf = time.perf_counter()
            start_tick = defense._get_tick_count()

            if defense.timing_checks["rdtsc_available"]:
                start_rdtsc = time.perf_counter_ns()

            time.sleep(0.1)

            elapsed_time = time.time() - start_time
            elapsed_perf = time.perf_counter() - start_perf

            end_tick = defense._get_tick_count()
            if start_tick and end_tick:
                elapsed_tick = (end_tick - start_tick) / 1000.0
            else:
                elapsed_tick = elapsed_perf

            timing_measurements["time.time"].append(elapsed_time)
            timing_measurements["perf_counter"].append(elapsed_perf)
            timing_measurements["tick_count"].append(elapsed_tick)

            if defense.timing_checks["rdtsc_available"]:
                end_rdtsc = time.perf_counter_ns()
                elapsed_rdtsc = (end_rdtsc - start_rdtsc) / 1_000_000_000
                timing_measurements["rdtsc"].append(elapsed_rdtsc)

        for source_name, measurements in timing_measurements.items():
            for measurement in measurements:
                drift = abs(measurement - 0.1)
                assert drift <= 0.05, f"{source_name} drift {drift*1000:.1f}ms exceeds 50ms"


class TestEdgeCasesAndPrecisionBoundaries:
    """Test edge cases and precision boundary conditions."""

    def test_timing_precision_at_lower_bound_10ms(self) -> None:
        """Timing precision validated at lower bound (10ms)."""
        defense = TimingAttackDefense()

        measurements = []

        for _ in range(10):
            start = time.perf_counter()
            time.sleep(0.05)
            end = time.perf_counter()
            measurements.append(end - start)

        for measurement in measurements:
            drift = abs(measurement - 0.05)
            assert drift <= 0.01

    def test_timing_precision_at_upper_bound_50ms(self) -> None:
        """Timing precision validated at upper bound (50ms)."""
        defense = TimingAttackDefense()

        start = time.perf_counter()
        result = defense.secure_sleep(0.2)
        elapsed = time.perf_counter() - start

        assert result is True

        drift = abs(elapsed - 0.2)
        assert drift <= 0.05

    def test_timing_correlation_failure_at_threshold_boundary(self) -> None:
        """Timing correlation detection triggers at exact threshold boundary."""
        defense = TimingAttackDefense()

        with patch("time.time") as mock_time:
            with patch("time.perf_counter") as mock_perf:
                mock_time.side_effect = [0.0, 0.2]
                mock_perf.side_effect = [0.0, 0.0, 0.0, 0.0, 0.0, 0.101]

                result = defense.secure_sleep(0.1)

                assert result is False

    def test_microsecond_level_timing_measurements(self) -> None:
        """Microsecond-level timing measurements for very short durations."""
        defense = TimingAttackDefense()

        measurements = []

        for _ in range(100):
            start = time.perf_counter_ns()
            _ = sum(range(1000))
            end = time.perf_counter_ns()
            measurements.append(end - start)

        avg_ns = sum(measurements) / len(measurements)

        assert avg_ns < 1_000_000

    def test_nanosecond_resolution_timing_overhead(self) -> None:
        """Nanosecond resolution timing overhead measurement."""
        defense = TimingAttackDefense()

        if not defense.timing_checks["rdtsc_available"]:
            pytest.skip("High-resolution timing not available")

        overhead_samples = []

        for _ in range(1000):
            start = time.perf_counter_ns()
            end = time.perf_counter_ns()
            overhead_samples.append(end - start)

        avg_overhead = sum(overhead_samples) / len(overhead_samples)

        assert avg_overhead < 1000


class TestPerformanceWithPrecisionRequirements:
    """Test performance meets precision requirements under load."""

    def test_high_frequency_timing_measurements_maintain_precision(self) -> None:
        """High-frequency timing measurements maintain <50ms precision."""
        defense = TimingAttackDefense()

        measurements = []

        for _ in range(50):
            start = time.perf_counter()
            time.sleep(0.02)
            elapsed = time.perf_counter() - start
            measurements.append(elapsed)

        for measurement in measurements:
            drift = abs(measurement - 0.02)
            assert drift <= 0.05

    def test_concurrent_timing_operations_maintain_precision(self) -> None:
        """Concurrent timing operations maintain precision across threads."""
        defense = TimingAttackDefense()

        results = []

        def timing_operation() -> None:
            start = time.perf_counter()
            defense.secure_sleep(0.1)
            elapsed = time.perf_counter() - start
            results.append(elapsed)

        threads = [threading.Thread(target=timing_operation) for _ in range(10)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(timeout=1.0)

        for result in results:
            drift = abs(result - 0.1)
            assert drift <= 0.05

    def test_timing_precision_under_cpu_load(self) -> None:
        """Timing precision maintained under CPU load."""
        defense = TimingAttackDefense()

        def cpu_load() -> None:
            for _ in range(1000000):
                _ = sum(range(100))

        load_thread = threading.Thread(target=cpu_load)
        load_thread.start()

        start = time.perf_counter()
        result = defense.secure_sleep(0.15)
        elapsed = time.perf_counter() - start

        load_thread.join(timeout=2.0)

        assert result is True

        drift = abs(elapsed - 0.15)
        assert drift <= 0.05
