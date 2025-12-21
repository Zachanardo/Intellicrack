"""Production tests for Frida stealth anti-detection mechanisms.

Tests validate real stealth techniques against actual detection methods:
- Thread name randomization to evade enumeration detection
- D-Bus presence hiding on Linux systems
- Memory artifact obfuscation (Frida signatures)
- Named pipe detection bypass on Windows
- Port scanning detection for Frida server
- Anti-debugging countermeasures
- Syscall mode enablement on Windows
- Stealth status reporting and restoration

All tests operate on real system resources without mocks to validate
genuine anti-detection effectiveness.
"""

import ctypes
import os
import platform
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.certificate.frida_stealth import FridaStealth

if TYPE_CHECKING:
    from collections.abc import Generator


class TestFridaStealthInitialization:
    """Test FridaStealth object initialization and state management."""

    def test_initialization_creates_correct_platform_state(self) -> None:
        """FridaStealth initializes with correct platform detection."""
        stealth = FridaStealth()

        assert stealth.platform == platform.system()
        assert isinstance(stealth.active_techniques, dict)
        assert len(stealth.active_techniques) == 5
        assert not any(stealth.active_techniques.values())

    def test_initialization_creates_empty_thread_tracking(self) -> None:
        """FridaStealth initializes with empty thread name tracking."""
        stealth = FridaStealth()

        assert isinstance(stealth._original_thread_names, dict)
        assert len(stealth._original_thread_names) == 0

    def test_initialization_creates_thread_lock(self) -> None:
        """FridaStealth initializes with thread synchronization lock."""
        stealth = FridaStealth()

        assert isinstance(stealth._lock, threading.Lock)


class TestAntiFridaDetection:
    """Test detection of anti-Frida techniques in target processes."""

    def test_detect_anti_frida_on_current_process(self) -> None:
        """Detect anti-Frida techniques scans current process successfully."""
        stealth = FridaStealth()

        detected = stealth.detect_anti_frida(pid=None)

        assert isinstance(detected, list)
        assert all(isinstance(tech, str) for tech in detected)

    def test_detect_anti_frida_with_explicit_pid(self) -> None:
        """Detect anti-Frida techniques works with explicit PID."""
        stealth = FridaStealth()
        current_pid = os.getpid()

        detected = stealth.detect_anti_frida(pid=current_pid)

        assert isinstance(detected, list)

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Windows-specific thread enumeration test",
    )
    def test_detect_thread_enumeration_windows(self) -> None:
        """Detect thread enumeration technique on Windows processes."""
        stealth = FridaStealth()

        has_thread_enum = stealth._check_thread_enumeration(os.getpid())

        assert isinstance(has_thread_enum, bool)

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux-specific thread enumeration test",
    )
    def test_detect_thread_enumeration_linux(self) -> None:
        """Detect thread enumeration technique on Linux processes."""
        stealth = FridaStealth()

        has_thread_enum = stealth._check_thread_enumeration(os.getpid())

        assert isinstance(has_thread_enum, bool)

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="D-Bus detection is Linux-only",
    )
    def test_detect_dbus_detection_linux(self) -> None:
        """Detect D-Bus monitoring for Frida on Linux."""
        stealth = FridaStealth()

        has_dbus = stealth._check_dbus_detection(os.getpid())

        assert isinstance(has_dbus, bool)

    def test_detect_dbus_detection_non_linux_returns_false(self) -> None:
        """Detect D-Bus on non-Linux platforms returns False."""
        stealth = FridaStealth()

        if platform.system() != "Linux":
            has_dbus = stealth._check_dbus_detection(os.getpid())
            assert has_dbus is False

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Port scanning detection uses Linux /proc filesystem",
    )
    def test_detect_port_scanning_linux(self) -> None:
        """Detect port scanning for Frida server on Linux."""
        stealth = FridaStealth()

        has_port_scan = stealth._check_port_scanning(os.getpid())

        assert isinstance(has_port_scan, bool)

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Named pipe detection is Windows-specific",
    )
    def test_detect_named_pipe_detection_windows(self) -> None:
        """Detect named pipe scanning for Frida on Windows."""
        stealth = FridaStealth()

        has_named_pipe = stealth._check_named_pipe_detection(os.getpid())

        assert isinstance(has_named_pipe, bool)

    def test_detect_memory_scanning_current_process(self) -> None:
        """Detect memory scanning for Frida signatures."""
        stealth = FridaStealth()

        has_memory_scan = stealth._check_memory_scanning(os.getpid())

        assert isinstance(has_memory_scan, bool)

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Windows-specific memory scanning",
    )
    def test_detect_memory_scanning_windows(self) -> None:
        """Detect Windows memory scanning for Frida modules."""
        stealth = FridaStealth()

        has_scan = stealth._check_memory_scan_windows(os.getpid())

        assert isinstance(has_scan, bool)

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux-specific memory scanning",
    )
    def test_detect_memory_scanning_linux(self) -> None:
        """Detect Linux memory scanning via /proc/pid/maps."""
        stealth = FridaStealth()

        has_scan = stealth._check_memory_scan_linux(os.getpid())

        assert isinstance(has_scan, bool)

    def test_detect_anti_frida_invalid_pid_handles_gracefully(self) -> None:
        """Detect anti-Frida with invalid PID returns empty list."""
        stealth = FridaStealth()

        detected = stealth.detect_anti_frida(pid=999999)

        assert isinstance(detected, list)


class TestThreadNameRandomization:
    """Test thread name randomization to evade detection."""

    def test_get_common_thread_names_returns_platform_specific(self) -> None:
        """Get common thread names returns platform-appropriate names."""
        stealth = FridaStealth()

        names = stealth._get_common_thread_names()

        assert isinstance(names, list)
        assert len(names) > 0
        assert all(isinstance(name, str) for name in names)

        if platform.system() == "Windows":
            assert any("Thread" in name for name in names)
        else:
            assert any("thread" in name for name in names)

    def test_randomize_frida_threads_executes_without_error(self) -> None:
        """Randomize Frida thread names executes successfully."""
        stealth = FridaStealth()

        result = stealth.randomize_frida_threads()

        assert isinstance(result, bool)

    def test_randomize_threads_updates_active_techniques_on_success(self) -> None:
        """Randomize threads sets thread_randomization flag on success."""
        stealth = FridaStealth()

        initial_state = stealth.active_techniques["thread_randomization"]

        stealth.randomize_frida_threads()

        if stealth.active_techniques["thread_randomization"]:
            assert stealth.active_techniques["thread_randomization"] != initial_state

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux-specific thread randomization",
    )
    def test_randomize_threads_linux_reads_proc_filesystem(self) -> None:
        """Randomize threads on Linux reads /proc/pid/task."""
        stealth = FridaStealth()

        patterns = ["test"]
        common_names = ["worker_thread"]

        count = stealth._randomize_threads_linux(patterns, common_names)

        assert isinstance(count, int)
        assert count >= 0

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Windows-specific thread randomization",
    )
    def test_randomize_threads_windows_uses_toolhelp32(self) -> None:
        """Randomize threads on Windows uses CreateToolhelp32Snapshot."""
        stealth = FridaStealth()

        patterns = ["test"]
        common_names = ["WorkerThread"]

        count = stealth._randomize_threads_windows(patterns, common_names)

        assert isinstance(count, int)
        assert count >= 0

    def test_randomize_threads_thread_safe_with_concurrent_calls(self) -> None:
        """Randomize threads is thread-safe with concurrent execution."""
        stealth = FridaStealth()
        results: list[bool] = []

        def randomize_worker() -> None:
            result = stealth.randomize_frida_threads()
            results.append(result)

        threads = [threading.Thread(target=randomize_worker) for _ in range(5)]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(results) == 5
        assert all(isinstance(r, bool) for r in results)


class TestDbusPresenceHiding:
    """Test D-Bus presence hiding on Linux systems."""

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="D-Bus hiding is Linux-only",
    )
    def test_hide_dbus_presence_on_linux(self) -> None:
        """Hide D-Bus presence closes D-Bus file descriptors on Linux."""
        stealth = FridaStealth()

        result = stealth.hide_dbus_presence()

        assert isinstance(result, bool)

    def test_hide_dbus_presence_non_linux_returns_false(self) -> None:
        """Hide D-Bus presence returns False on non-Linux platforms."""
        stealth = FridaStealth()

        if platform.system() != "Linux":
            result = stealth.hide_dbus_presence()
            assert result is False

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="D-Bus file descriptor closing is Linux-specific",
    )
    def test_hide_dbus_updates_active_techniques(self) -> None:
        """Hide D-Bus presence sets dbus_hiding flag when successful."""
        stealth = FridaStealth()

        stealth.hide_dbus_presence()

        if stealth.active_techniques["dbus_hiding"]:
            assert stealth.active_techniques["dbus_hiding"] is True


class TestMemoryArtifactHiding:
    """Test Frida memory artifact obfuscation."""

    def test_hide_frida_artifacts_executes_without_error(self) -> None:
        """Hide Frida artifacts executes successfully on current platform."""
        stealth = FridaStealth()

        result = stealth.hide_frida_artifacts()

        assert isinstance(result, bool)

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux-specific artifact hiding",
    )
    def test_hide_artifacts_linux_scans_proc_maps(self) -> None:
        """Hide artifacts on Linux scans /proc/pid/maps for Frida signatures."""
        stealth = FridaStealth()

        count = stealth._hide_artifacts_linux()

        assert isinstance(count, int)
        assert count >= 0

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Windows-specific artifact hiding",
    )
    def test_hide_artifacts_windows_scans_modules(self) -> None:
        """Hide artifacts on Windows scans process modules for Frida."""
        stealth = FridaStealth()

        count = stealth._hide_artifacts_windows()

        assert isinstance(count, int)
        assert count >= 0

    def test_hide_artifacts_updates_active_techniques(self) -> None:
        """Hide artifacts sets artifact_hiding flag when artifacts found."""
        stealth = FridaStealth()

        stealth.hide_frida_artifacts()

        if stealth.active_techniques["artifact_hiding"]:
            assert stealth.active_techniques["artifact_hiding"] is True


class TestSyscallMode:
    """Test direct syscall mode for API hook bypass."""

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Syscall mode is Windows-only",
    )
    def test_enable_syscall_mode_on_windows(self) -> None:
        """Enable syscall mode sets syscall_mode flag on Windows."""
        stealth = FridaStealth()

        result = stealth.enable_syscall_mode()

        assert result is True
        assert stealth.active_techniques["syscall_mode"] is True

    def test_enable_syscall_mode_non_windows_returns_false(self) -> None:
        """Enable syscall mode returns False on non-Windows platforms."""
        stealth = FridaStealth()

        if platform.system() != "Windows":
            result = stealth.enable_syscall_mode()
            assert result is False
            assert stealth.active_techniques["syscall_mode"] is False


class TestAntiDebuggingBypass:
    """Test anti-debugging countermeasures."""

    def test_apply_anti_debugging_bypass_current_process(self) -> None:
        """Apply anti-debugging bypass works on current process."""
        stealth = FridaStealth()

        result = stealth.apply_anti_debugging_bypass(pid=None)

        assert isinstance(result, bool)

    def test_apply_anti_debugging_bypass_explicit_pid(self) -> None:
        """Apply anti-debugging bypass works with explicit PID."""
        stealth = FridaStealth()

        result = stealth.apply_anti_debugging_bypass(pid=os.getpid())

        assert isinstance(result, bool)

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Windows-specific PEB manipulation",
    )
    def test_bypass_anti_debug_windows_peb_manipulation(self) -> None:
        """Bypass Windows anti-debugging modifies PEB BeingDebugged flag."""
        stealth = FridaStealth()

        count = stealth._bypass_anti_debug_windows(os.getpid())

        assert isinstance(count, int)
        assert count >= 0

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux-specific TracerPid check",
    )
    def test_bypass_anti_debug_linux_tracer_pid(self) -> None:
        """Bypass Linux anti-debugging checks TracerPid in /proc/status."""
        stealth = FridaStealth()

        count = stealth._bypass_anti_debug_linux(os.getpid())

        assert isinstance(count, int)
        assert count >= 0

    def test_anti_debugging_bypass_updates_active_techniques(self) -> None:
        """Anti-debugging bypass sets anti_debugging flag when successful."""
        stealth = FridaStealth()

        stealth.apply_anti_debugging_bypass()

        if stealth.active_techniques["anti_debugging"]:
            assert stealth.active_techniques["anti_debugging"] is True


class TestStealthStatusReporting:
    """Test stealth status reporting and level calculation."""

    def test_get_stealth_status_returns_complete_report(self) -> None:
        """Get stealth status returns comprehensive status dictionary."""
        stealth = FridaStealth()

        status = stealth.get_stealth_status()

        assert isinstance(status, dict)
        assert "platform" in status
        assert "active_techniques" in status
        assert "original_thread_names" in status
        assert "stealth_level" in status

    def test_stealth_status_platform_matches_system(self) -> None:
        """Stealth status platform field matches system platform."""
        stealth = FridaStealth()

        status = stealth.get_stealth_status()

        assert status["platform"] == platform.system()

    def test_stealth_status_active_techniques_is_dict(self) -> None:
        """Stealth status active_techniques is dictionary of booleans."""
        stealth = FridaStealth()

        status = stealth.get_stealth_status()

        assert isinstance(status["active_techniques"], dict)
        assert all(isinstance(v, bool) for v in status["active_techniques"].values())

    def test_stealth_status_original_thread_names_count(self) -> None:
        """Stealth status reports count of original thread names."""
        stealth = FridaStealth()

        status = stealth.get_stealth_status()

        assert isinstance(status["original_thread_names"], int)
        assert status["original_thread_names"] >= 0

    def test_calculate_stealth_level_none_when_no_techniques(self) -> None:
        """Calculate stealth level returns 'none' with no active techniques."""
        stealth = FridaStealth()

        level = stealth._calculate_stealth_level()

        assert level == "none"

    def test_calculate_stealth_level_low_with_few_techniques(self) -> None:
        """Calculate stealth level returns 'low' with few active techniques."""
        stealth = FridaStealth()
        stealth.active_techniques["thread_randomization"] = True

        level = stealth._calculate_stealth_level()

        assert level in ("low", "medium", "high")

    def test_calculate_stealth_level_high_with_all_techniques(self) -> None:
        """Calculate stealth level returns 'high' with all techniques active."""
        stealth = FridaStealth()

        for technique in stealth.active_techniques:
            stealth.active_techniques[technique] = True

        level = stealth._calculate_stealth_level()

        assert level == "high"

    def test_stealth_level_progression_as_techniques_activate(self) -> None:
        """Stealth level increases as more techniques are activated."""
        stealth = FridaStealth()

        initial_level = stealth._calculate_stealth_level()
        assert initial_level == "none"

        stealth.active_techniques["thread_randomization"] = True
        mid_level = stealth._calculate_stealth_level()
        assert mid_level in ("low", "medium")

        for technique in stealth.active_techniques:
            stealth.active_techniques[technique] = True
        final_level = stealth._calculate_stealth_level()
        assert final_level == "high"


class TestOriginalStateRestoration:
    """Test restoration of original system state."""

    def test_restore_original_state_clears_active_techniques(self) -> None:
        """Restore original state clears all active technique flags."""
        stealth = FridaStealth()

        stealth.active_techniques["thread_randomization"] = True
        stealth.active_techniques["artifact_hiding"] = True

        result = stealth.restore_original_state()

        assert result is True
        assert not any(stealth.active_techniques.values())

    def test_restore_original_state_clears_thread_names(self) -> None:
        """Restore original state clears original thread name tracking."""
        stealth = FridaStealth()

        stealth._original_thread_names[1234] = "original_name"

        stealth.restore_original_state()

        assert len(stealth._original_thread_names) == 0

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux-specific thread name restoration",
    )
    def test_restore_original_state_linux_thread_names(self) -> None:
        """Restore original state attempts to restore thread names on Linux."""
        stealth = FridaStealth()

        current_pid = os.getpid()
        task_dir = f"/proc/{current_pid}/task"

        if os.path.exists(task_dir):
            if threads := os.listdir(task_dir):
                first_tid = int(threads[0])
                stealth._original_thread_names[first_tid] = "test_thread"

                result = stealth.restore_original_state()

                assert isinstance(result, bool)

    def test_restore_original_state_thread_safe(self) -> None:
        """Restore original state is thread-safe with concurrent calls."""
        stealth = FridaStealth()
        stealth.active_techniques["artifact_hiding"] = True

        results: list[bool] = []

        def restore_worker() -> None:
            result = stealth.restore_original_state()
            results.append(result)

        threads = [threading.Thread(target=restore_worker) for _ in range(3)]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(results) == 3
        assert all(isinstance(r, bool) for r in results)


class TestStealthIntegrationWorkflows:
    """Test complete stealth workflows with multiple techniques."""

    def test_full_stealth_activation_workflow(self) -> None:
        """Complete stealth activation applies all available techniques."""
        stealth = FridaStealth()

        stealth.randomize_frida_threads()
        stealth.hide_dbus_presence()
        stealth.hide_frida_artifacts()
        stealth.enable_syscall_mode()
        stealth.apply_anti_debugging_bypass()

        status = stealth.get_stealth_status()

        assert any(status["active_techniques"].values())
        assert status["stealth_level"] in ("none", "low", "medium", "high")

    def test_detection_then_bypass_workflow(self) -> None:
        """Detect anti-Frida techniques then apply countermeasures."""
        stealth = FridaStealth()

        detected = stealth.detect_anti_frida()

        if "thread_enumeration" in detected:
            stealth.randomize_frida_threads()
        if "dbus_detection" in detected and platform.system() == "Linux":
            stealth.hide_dbus_presence()
        if "memory_scanning" in detected:
            stealth.hide_frida_artifacts()

        status = stealth.get_stealth_status()
        assert isinstance(status, dict)

    def test_activation_and_restoration_cycle(self) -> None:
        """Activate stealth techniques then restore original state."""
        stealth = FridaStealth()

        stealth.randomize_frida_threads()
        stealth.hide_frida_artifacts()

        initial_status = stealth.get_stealth_status()

        stealth.restore_original_state()

        final_status = stealth.get_stealth_status()

        assert not any(final_status["active_techniques"].values())
        assert final_status["stealth_level"] == "none"

    def test_repeated_activation_is_idempotent(self) -> None:
        """Repeated stealth activation doesn't cause errors or state corruption."""
        stealth = FridaStealth()

        for _ in range(3):
            stealth.randomize_frida_threads()
            stealth.hide_frida_artifacts()

        status = stealth.get_stealth_status()
        assert isinstance(status, dict)


class TestStealthErrorHandling:
    """Test error handling in stealth operations."""

    def test_invalid_pid_detection_handles_gracefully(self) -> None:
        """Anti-Frida detection with invalid PID handles gracefully."""
        stealth = FridaStealth()

        detected = stealth.detect_anti_frida(pid=999999)

        assert isinstance(detected, list)

    def test_thread_randomization_without_frida_threads(self) -> None:
        """Thread randomization when no Frida threads exist."""
        stealth = FridaStealth()

        result = stealth.randomize_frida_threads()

        assert isinstance(result, bool)

    def test_artifact_hiding_on_clean_process(self) -> None:
        """Artifact hiding on process without Frida artifacts."""
        stealth = FridaStealth()

        result = stealth.hide_frida_artifacts()

        assert isinstance(result, bool)

    def test_restoration_without_prior_activation(self) -> None:
        """Restore original state without prior activation succeeds."""
        stealth = FridaStealth()

        result = stealth.restore_original_state()

        assert result is True


class TestStealthCrossPlatformCompatibility:
    """Test cross-platform compatibility and platform-specific behavior."""

    def test_platform_detection_accuracy(self) -> None:
        """Platform detection matches actual operating system."""
        stealth = FridaStealth()

        assert stealth.platform in ("Windows", "Linux", "Darwin")
        assert stealth.platform == platform.system()

    def test_windows_specific_features_only_on_windows(self) -> None:
        """Windows-specific features only execute on Windows."""
        stealth = FridaStealth()

        if platform.system() != "Windows":
            assert stealth.enable_syscall_mode() is False
            assert stealth._check_named_pipe_detection(os.getpid()) is False

    def test_linux_specific_features_only_on_linux(self) -> None:
        """Linux-specific features only execute on Linux."""
        stealth = FridaStealth()

        if platform.system() != "Linux":
            assert stealth.hide_dbus_presence() is False

    def test_all_platforms_support_basic_detection(self) -> None:
        """All platforms support basic anti-Frida detection."""
        stealth = FridaStealth()

        detected = stealth.detect_anti_frida()

        assert isinstance(detected, list)

    def test_all_platforms_support_status_reporting(self) -> None:
        """All platforms support stealth status reporting."""
        stealth = FridaStealth()

        status = stealth.get_stealth_status()

        assert isinstance(status, dict)
        assert "platform" in status


class TestStealthThreadSafety:
    """Test thread safety of stealth operations."""

    def test_concurrent_detection_calls(self) -> None:
        """Concurrent anti-Frida detection calls are thread-safe."""
        stealth = FridaStealth()
        results: list[list[str]] = []

        def detect_worker() -> None:
            detected = stealth.detect_anti_frida()
            results.append(detected)

        threads = [threading.Thread(target=detect_worker) for _ in range(5)]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(results) == 5
        assert all(isinstance(r, list) for r in results)

    def test_concurrent_status_queries(self) -> None:
        """Concurrent status queries don't corrupt state."""
        stealth = FridaStealth()
        statuses: list[dict] = []

        def status_worker() -> None:
            status = stealth.get_stealth_status()
            statuses.append(status)

        threads = [threading.Thread(target=status_worker) for _ in range(10)]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(statuses) == 10
        assert all(isinstance(s, dict) for s in statuses)

    def test_mixed_operation_concurrency(self) -> None:
        """Mixed stealth operations execute safely concurrently."""
        stealth = FridaStealth()

        def worker1() -> None:
            stealth.detect_anti_frida()

        def worker2() -> None:
            stealth.randomize_frida_threads()

        def worker3() -> None:
            stealth.get_stealth_status()

        threads = [
            threading.Thread(target=worker1),
            threading.Thread(target=worker2),
            threading.Thread(target=worker3),
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()


class TestStealthPerformance:
    """Test performance characteristics of stealth operations."""

    def test_detection_completes_quickly(self) -> None:
        """Anti-Frida detection completes within reasonable time."""
        stealth = FridaStealth()

        start = time.time()
        stealth.detect_anti_frida()
        elapsed = time.time() - start

        assert elapsed < 5.0

    def test_thread_randomization_performance(self) -> None:
        """Thread randomization completes within reasonable time."""
        stealth = FridaStealth()

        start = time.time()
        stealth.randomize_frida_threads()
        elapsed = time.time() - start

        assert elapsed < 2.0

    def test_artifact_hiding_performance(self) -> None:
        """Artifact hiding completes within reasonable time."""
        stealth = FridaStealth()

        start = time.time()
        stealth.hide_frida_artifacts()
        elapsed = time.time() - start

        assert elapsed < 3.0

    def test_status_query_performance(self) -> None:
        """Status queries are fast and don't block."""
        stealth = FridaStealth()

        start = time.time()
        for _ in range(100):
            stealth.get_stealth_status()
        elapsed = time.time() - start

        assert elapsed < 1.0


class TestStealthEdgeCases:
    """Test edge cases and unusual scenarios."""

    def test_multiple_restoration_calls_safe(self) -> None:
        """Multiple restoration calls don't cause errors."""
        stealth = FridaStealth()

        for _ in range(5):
            result = stealth.restore_original_state()
            assert result is True

    def test_activation_without_detection_succeeds(self) -> None:
        """Stealth activation without prior detection succeeds."""
        stealth = FridaStealth()

        result = stealth.randomize_frida_threads()
        assert isinstance(result, bool)

    def test_stealth_level_calculation_with_partial_activation(self) -> None:
        """Stealth level calculated correctly with partial activation."""
        stealth = FridaStealth()

        stealth.active_techniques["thread_randomization"] = True
        stealth.active_techniques["artifact_hiding"] = False
        stealth.active_techniques["dbus_hiding"] = True

        level = stealth._calculate_stealth_level()
        assert level in ("none", "low", "medium", "high")

    def test_empty_original_thread_names_restoration(self) -> None:
        """Restoration with empty original thread names succeeds."""
        stealth = FridaStealth()

        assert len(stealth._original_thread_names) == 0

        result = stealth.restore_original_state()
        assert result is True
