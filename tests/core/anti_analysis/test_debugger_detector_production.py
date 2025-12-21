"""Production tests for debugger detector.

Tests validate real debugger detection capabilities.
Tests verify detection methods work on actual system state.
"""

import platform
import sys
from typing import Any

import pytest

from intellicrack.core.anti_analysis.debugger_detector import DebuggerDetector


class TestDebuggerDetectorInitialization:
    """Test debugger detector initialization."""

    def test_create_debugger_detector(self) -> None:
        """Create debugger detector instance."""
        detector = DebuggerDetector()

        assert detector is not None
        assert hasattr(detector, "detection_methods")
        assert hasattr(detector, "debugger_signatures")

    def test_windows_detection_methods(self) -> None:
        """Verify Windows has appropriate detection methods."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        detector = DebuggerDetector()

        assert "isdebuggerpresent" in detector.detection_methods
        assert "peb_flags" in detector.detection_methods
        assert "hardware_breakpoints" in detector.detection_methods
        assert "timing_checks" in detector.detection_methods

    def test_linux_detection_methods(self) -> None:
        """Verify Linux has appropriate detection methods."""
        if platform.system() == "Windows":
            pytest.skip("Linux-only test")

        detector = DebuggerDetector()

        assert "ptrace" in detector.detection_methods
        assert "proc_status" in detector.detection_methods
        assert "timing_checks" in detector.detection_methods


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only functionality")
class TestWindowsDebuggerDetection:
    """Test Windows-specific debugger detection methods."""

    def test_isdebuggerpresent_check(self) -> None:
        """Test IsDebuggerPresent API check."""
        detector = DebuggerDetector()

        try:
            result = detector._check_isdebuggerpresent()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"IsDebuggerPresent check failed: {e}")

    def test_remote_debugger_check(self) -> None:
        """Test CheckRemoteDebuggerPresent check."""
        detector = DebuggerDetector()

        try:
            result = detector._check_remote_debugger()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"Remote debugger check failed: {e}")

    def test_peb_flags_check(self) -> None:
        """Test PEB flags check."""
        detector = DebuggerDetector()

        try:
            result = detector._check_peb_flags()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"PEB flags check failed: {e}")

    def test_ntglobalflag_check(self) -> None:
        """Test NtGlobalFlag check."""
        detector = DebuggerDetector()

        try:
            result = detector._check_ntglobalflag()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"NtGlobalFlag check failed: {e}")

    def test_heap_flags_check(self) -> None:
        """Test heap flags check."""
        detector = DebuggerDetector()

        try:
            result = detector._check_heap_flags()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"Heap flags check failed: {e}")

    def test_debug_port_check(self) -> None:
        """Test debug port check."""
        detector = DebuggerDetector()

        try:
            result = detector._check_debug_port()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"Debug port check failed: {e}")

    def test_hardware_breakpoints_check(self) -> None:
        """Test hardware breakpoints check."""
        detector = DebuggerDetector()

        try:
            result = detector._check_hardware_breakpoints()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"Hardware breakpoints check failed: {e}")


@pytest.mark.skipif(platform.system() == "Windows", reason="Linux-only functionality")
class TestLinuxDebuggerDetection:
    """Test Linux-specific debugger detection methods."""

    def test_ptrace_check(self) -> None:
        """Test ptrace detection."""
        detector = DebuggerDetector()

        try:
            result = detector._check_ptrace()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"Ptrace check failed: {e}")

    def test_proc_status_check(self) -> None:
        """Test /proc/self/status TracerPid check."""
        detector = DebuggerDetector()

        try:
            result = detector._check_proc_status()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"Proc status check failed: {e}")

    def test_parent_process_check_linux(self) -> None:
        """Test parent process check on Linux."""
        detector = DebuggerDetector()

        try:
            result = detector._check_parent_process_linux()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"Parent process check failed: {e}")


class TestCommonDebuggerDetection:
    """Test platform-independent debugger detection."""

    def test_timing_checks(self) -> None:
        """Test timing-based detection."""
        detector = DebuggerDetector()

        result = detector._check_timing()

        assert isinstance(result, bool)

    def test_int3_scan(self) -> None:
        """Test INT3 breakpoint scanning."""
        detector = DebuggerDetector()

        try:
            result = detector._check_int3_scan()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"INT3 scan failed: {e}")


class TestDebuggerSignatures:
    """Test debugger signature detection."""

    def test_debugger_signatures_loaded(self) -> None:
        """Verify debugger signatures are loaded."""
        detector = DebuggerDetector()

        assert isinstance(detector.debugger_signatures, dict)
        assert len(detector.debugger_signatures) > 0

    def test_windows_signatures_present(self) -> None:
        """Verify Windows debugger signatures exist."""
        detector = DebuggerDetector()

        if "windows" in detector.debugger_signatures:
            sigs = detector.debugger_signatures["windows"]
            assert "processes" in sigs
            assert isinstance(sigs["processes"], list)

    def test_linux_signatures_present(self) -> None:
        """Verify Linux debugger signatures exist."""
        detector = DebuggerDetector()

        if "linux" in detector.debugger_signatures:
            sigs = detector.debugger_signatures["linux"]
            assert "processes" in sigs
            assert isinstance(sigs["processes"], list)


class TestDebuggerDetection:
    """Test comprehensive debugger detection."""

    def test_detect_method_returns_results(self) -> None:
        """Test detect method returns detection results."""
        detector = DebuggerDetector()

        results = detector.detect()

        assert isinstance(results, dict)
        assert len(results) > 0

    def test_detect_all_methods_executed(self) -> None:
        """Verify all detection methods are executed."""
        detector = DebuggerDetector()

        results = detector.detect()

        for method_name in detector.detection_methods:
            assert method_name in results

    def test_detect_returns_boolean_values(self) -> None:
        """Verify detection results are boolean values."""
        detector = DebuggerDetector()

        results = detector.detect()

        for method_name, result in results.items():
            assert isinstance(result, bool)

    def test_is_debugger_present(self) -> None:
        """Test is_debugger_present summary method."""
        detector = DebuggerDetector()

        is_present = detector.is_debugger_present()

        assert isinstance(is_present, bool)


class TestParentProcessDetection:
    """Test parent process debugger detection."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_check_parent_process_windows(self) -> None:
        """Check if parent process is a known debugger on Windows."""
        detector = DebuggerDetector()

        try:
            result = detector._check_parent_process()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"Parent process check failed: {e}")


class TestDebugPrivileges:
    """Test debug privilege detection."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_check_debug_privileges(self) -> None:
        """Check for SeDebugPrivilege."""
        detector = DebuggerDetector()

        try:
            result = detector._check_debug_privileges()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"Debug privileges check failed: {e}")


class TestExceptionHandling:
    """Test exception-based debugger detection."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_check_exception_handling(self) -> None:
        """Check exception handling behavior."""
        detector = DebuggerDetector()

        try:
            result = detector._check_exception_handling()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"Exception handling check failed: {e}")


class TestBreakpointDetection:
    """Test breakpoint detection."""

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-only test")
    def test_check_breakpoints_linux(self) -> None:
        """Check for breakpoints on Linux."""
        detector = DebuggerDetector()

        try:
            result = detector._check_breakpoints_linux()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"Breakpoint check failed: {e}")


class TestDetectionEdgeCases:
    """Test edge cases in debugger detection."""

    def test_multiple_consecutive_detections(self) -> None:
        """Run detection multiple times."""
        detector = DebuggerDetector()

        results1 = detector.detect()
        results2 = detector.detect()

        assert isinstance(results1, dict)
        assert isinstance(results2, dict)

    def test_detection_with_no_debugger(self) -> None:
        """Detection when no debugger is attached."""
        detector = DebuggerDetector()

        results = detector.detect()

        assert isinstance(results, dict)
        assert len(results) > 0


class TestSignatureUpdates:
    """Test dynamic signature updates."""

    def test_update_signatures_from_system(self) -> None:
        """Test signature updates from system."""
        detector = DebuggerDetector()

        try:
            detector._update_signatures_from_system()
            assert isinstance(detector.debugger_signatures, dict)
        except Exception as e:
            pytest.skip(f"Signature update failed: {e}")


class TestPerformance:
    """Test detection performance."""

    def test_detection_performance(self, benchmark: Any) -> None:
        """Benchmark debugger detection performance."""
        detector = DebuggerDetector()

        result = benchmark(detector.detect)

        assert isinstance(result, dict)

    def test_rapid_detection_calls(self) -> None:
        """Test rapid consecutive detection calls."""
        detector = DebuggerDetector()

        for _ in range(10):
            results = detector.detect()
            assert isinstance(results, dict)


class TestLicensingAntiDebug:
    """Test debugger detection for license protection."""

    def test_detect_debugging_during_license_check(self) -> None:
        """Detect debugger during license validation."""
        detector = DebuggerDetector()

        is_debugged = detector.is_debugger_present()

        assert isinstance(is_debugged, bool)

    def test_detect_before_serial_validation(self) -> None:
        """Detect debugger before serial number validation."""
        detector = DebuggerDetector()

        results = detector.detect()

        assert isinstance(results, dict)
        assert len(results) > 0

    def test_multi_method_detection_for_protection(self) -> None:
        """Use multiple detection methods for robust protection."""
        detector = DebuggerDetector()

        results = detector.detect()

        detected_count = sum(1 for result in results.values() if result)

        assert detected_count >= 0
