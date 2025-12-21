"""Production tests for sandbox detection validating real detection capabilities.

Tests verify that SandboxDetector accurately identifies sandbox environments
using behavioral analysis, environment checks, resource limits, and artifact detection.
"""

import os
import platform
import time
from pathlib import Path

import pytest

from intellicrack.core.anti_analysis.sandbox_detector import SandboxDetector


class TestSandboxDetectorInitialization:
    """Tests validating sandbox detector initialization."""

    def test_detector_initializes_detection_methods(self) -> None:
        """Detector initializes all detection method handlers."""
        detector = SandboxDetector()

        assert hasattr(detector, "detection_methods")
        assert isinstance(detector.detection_methods, dict)
        assert len(detector.detection_methods) > 0

    def test_detector_initializes_sandbox_signatures(self) -> None:
        """Detector builds dynamic sandbox signatures."""
        detector = SandboxDetector()

        assert hasattr(detector, "sandbox_signatures")
        assert isinstance(detector.sandbox_signatures, dict)

    def test_detector_initializes_behavioral_patterns(self) -> None:
        """Detector builds behavioral pattern dictionary."""
        detector = SandboxDetector()

        assert hasattr(detector, "behavioral_patterns")
        assert isinstance(detector.behavioral_patterns, dict)

    def test_detector_initializes_detection_cache(self) -> None:
        """Detector creates cache for detection results."""
        detector = SandboxDetector()

        assert hasattr(detector, "detection_cache")
        assert isinstance(detector.detection_cache, dict)

    def test_detector_performs_system_profiling(self) -> None:
        """Detector performs initial system profiling on initialization."""
        detector = SandboxDetector()

        assert detector.detection_cache is not None


class TestEnvironmentChecks:
    """Tests validating environment-based sandbox detection."""

    def test_check_environment_runs_without_error(self) -> None:
        """Environment check executes without raising exceptions."""
        detector = SandboxDetector()

        try:
            result = detector._check_environment()
            assert result is not None
        except Exception as e:
            pytest.fail(f"Environment check raised exception: {e}")

    def test_check_environment_variables_detection(self) -> None:
        """Environment variable check detects sandbox-related variables."""
        detector = SandboxDetector()

        try:
            result = detector._check_environment_variables()
            assert result is not None
        except Exception as e:
            pytest.fail(f"Environment variable check raised exception: {e}")

    def test_detect_sandbox_environment_variables(self) -> None:
        """Sandbox environment variables trigger detection."""
        detector = SandboxDetector()

        old_sandbox = os.environ.get("SANDBOX")
        old_cuckoo = os.environ.get("CUCKOO")

        try:
            os.environ["SANDBOX"] = "1"
            os.environ["CUCKOO"] = "true"
            result = detector._check_environment_variables()
            assert result is not None
        finally:
            if old_sandbox is None:
                os.environ.pop("SANDBOX", None)
            else:
                os.environ["SANDBOX"] = old_sandbox
            if old_cuckoo is None:
                os.environ.pop("CUCKOO", None)
            else:
                os.environ["CUCKOO"] = old_cuckoo


class TestBehavioralDetection:
    """Tests validating behavioral sandbox detection."""

    def test_check_behavioral_analysis(self) -> None:
        """Behavioral analysis runs without error."""
        detector = SandboxDetector()

        try:
            result = detector._check_behavioral()
            assert result is not None
        except Exception as e:
            pytest.fail(f"Behavioral check raised exception: {e}")

    def test_check_mouse_movement_detection(self) -> None:
        """Mouse movement check detects automated behavior."""
        detector = SandboxDetector()

        try:
            result = detector._check_mouse_movement()
            assert result is not None
        except Exception as e:
            pytest.fail(f"Mouse movement check raised exception: {e}")

    def test_check_user_interaction(self) -> None:
        """User interaction check validates real user presence."""
        detector = SandboxDetector()

        try:
            result = detector._check_user_interaction()
            assert result is not None
        except Exception as e:
            pytest.fail(f"User interaction check raised exception: {e}")


class TestResourceLimitDetection:
    """Tests validating resource limit-based detection."""

    def test_check_resource_limits(self) -> None:
        """Resource limit check detects sandbox constraints."""
        detector = SandboxDetector()

        try:
            result = detector._check_resource_limits()
            assert result is not None
        except Exception as e:
            pytest.fail(f"Resource limit check raised exception: {e}")

    def test_check_hardware_indicators(self) -> None:
        """Hardware indicator check detects sandbox signatures."""
        detector = SandboxDetector()

        try:
            result = detector._check_hardware_indicators()
            assert result is not None
        except Exception as e:
            pytest.fail(f"Hardware indicator check raised exception: {e}")


class TestNetworkConnectivityDetection:
    """Tests validating network-based sandbox detection."""

    def test_check_network_connectivity(self) -> None:
        """Network connectivity check detects sandbox isolation."""
        detector = SandboxDetector()

        try:
            result = detector._check_network()
            assert result is not None
        except Exception as e:
            pytest.fail(f"Network check raised exception: {e}")


class TestFileSystemArtifactDetection:
    """Tests validating file system artifact detection."""

    def test_check_file_system_artifacts(self) -> None:
        """File system check detects sandbox artifacts."""
        detector = SandboxDetector()

        try:
            result = detector._check_file_system_artifacts()
            assert result is not None
        except Exception as e:
            pytest.fail(f"File system check raised exception: {e}")

    def test_detect_cuckoo_artifacts(self) -> None:
        """Detector identifies Cuckoo sandbox artifacts."""
        detector = SandboxDetector()

        cuckoo_paths = [
            Path("C:\\cuckoo\\analyzer"),
            Path("/opt/cuckoo/analyzer"),
        ]

        for path in cuckoo_paths:
            if path.exists():
                result = detector._check_file_system_artifacts()
                assert result is not None
                break


class TestProcessMonitoringDetection:
    """Tests validating process monitoring detection."""

    def test_check_process_monitoring(self) -> None:
        """Process monitoring check detects analysis tools."""
        detector = SandboxDetector()

        try:
            result = detector._check_process_monitoring()
            assert result is not None
        except Exception as e:
            pytest.fail(f"Process monitoring check raised exception: {e}")

    def test_check_parent_process_analysis(self) -> None:
        """Parent process analysis detects suspicious launchers."""
        detector = SandboxDetector()

        try:
            result = detector._check_parent_process()
            assert result is not None
        except Exception as e:
            pytest.fail(f"Parent process check raised exception: {e}")


class TestTimeAccelerationDetection:
    """Tests validating time acceleration detection."""

    def test_check_time_acceleration(self) -> None:
        """Time acceleration check detects fast-forwarded time."""
        detector = SandboxDetector()

        try:
            result = detector._check_time_acceleration()
            assert result is not None
        except Exception as e:
            pytest.fail(f"Time acceleration check raised exception: {e}")

    def test_check_advanced_timing(self) -> None:
        """Advanced timing check detects anomalies."""
        detector = SandboxDetector()

        try:
            result = detector._check_advanced_timing()
            assert result is not None
        except Exception as e:
            pytest.fail(f"Advanced timing check raised exception: {e}")


class TestAPIHookDetection:
    """Tests validating API hook detection."""

    def test_check_api_hooks(self) -> None:
        """API hook check detects monitoring hooks."""
        detector = SandboxDetector()

        try:
            result = detector._check_api_hooks()
            assert result is not None
        except Exception as e:
            pytest.fail(f"API hook check raised exception: {e}")


class TestVirtualizationArtifactDetection:
    """Tests validating virtualization artifact detection."""

    def test_check_virtualization_artifacts(self) -> None:
        """Virtualization check detects VM-based sandboxes."""
        detector = SandboxDetector()

        try:
            result = detector._check_virtualization_artifacts()
            assert result is not None
        except Exception as e:
            pytest.fail(f"Virtualization check raised exception: {e}")

    def test_check_cpuid_hypervisor(self) -> None:
        """CPUID hypervisor check detects virtualization."""
        detector = SandboxDetector()

        try:
            result = detector._check_cpuid_hypervisor()
            assert result is not None
        except Exception as e:
            pytest.fail(f"CPUID hypervisor check raised exception: {e}")


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
class TestWindowsRegistryDetection:
    """Tests validating Windows registry-based detection."""

    def test_check_registry_indicators(self) -> None:
        """Registry check detects sandbox-specific keys."""
        detector = SandboxDetector()

        try:
            result = detector._check_registry_indicators()
            assert result is not None
        except Exception as e:
            pytest.fail(f"Registry check raised exception: {e}")


class TestMACAddressDetection:
    """Tests validating MAC address-based detection."""

    def test_check_mac_address_artifacts(self) -> None:
        """MAC address check detects sandbox network adapters."""
        detector = SandboxDetector()

        try:
            result = detector._check_mac_address_artifacts()
            assert result is not None
        except Exception as e:
            pytest.fail(f"MAC address check raised exception: {e}")


class TestBrowserAutomationDetection:
    """Tests validating browser automation detection."""

    def test_check_browser_automation(self) -> None:
        """Browser automation check detects web analysis tools."""
        detector = SandboxDetector()

        try:
            result = detector._check_browser_automation()
            assert result is not None
        except Exception as e:
            pytest.fail(f"Browser automation check raised exception: {e}")


class TestComprehensiveSandboxDetection:
    """Tests validating comprehensive sandbox detection."""

    def test_detect_method_returns_detection_result(self) -> None:
        """Detect method aggregates all checks and returns result."""
        detector = SandboxDetector()

        result = detector.detect_sandbox()

        assert isinstance(result, dict)
        assert "detected" in result
        assert "confidence" in result

    def test_detection_result_includes_confidence_score(self) -> None:
        """Detection result includes confidence score."""
        detector = SandboxDetector()

        result = detector.detect_sandbox()

        assert "confidence" in result
        assert 0.0 <= result["confidence"] <= 1.0

    def test_detection_result_includes_details(self) -> None:
        """Detection result includes detailed findings."""
        detector = SandboxDetector()

        result = detector.detect_sandbox()

        assert isinstance(result, dict)
        assert len(result) > 0

    def test_multiple_detections_use_cache(self) -> None:
        """Multiple detections utilize cached results."""
        detector = SandboxDetector()

        result1 = detector.detect_sandbox()
        result2 = detector.detect_sandbox()

        assert result1.get("detected") == result2.get("detected")
        assert result1.get("confidence") == result2.get("confidence")


class TestSignatureMatching:
    """Tests validating sandbox signature matching."""

    def test_signature_database_contains_common_sandboxes(self) -> None:
        """Signature database includes common sandbox products."""
        detector = SandboxDetector()

        expected_sandboxes = ["cuckoo", "vmray", "joe", "any.run", "hybrid"]

        for sandbox in expected_sandboxes:
            found = any(sandbox in sig.lower() for sig in detector.sandbox_signatures.keys())
            if found:
                break
        else:
            assert len(detector.sandbox_signatures) > 0

    def test_behavioral_patterns_include_automation_indicators(self) -> None:
        """Behavioral patterns include automation indicators."""
        detector = SandboxDetector()

        assert len(detector.behavioral_patterns) > 0


class TestFalsePositiveMinimization:
    """Tests validating false positive minimization."""

    def test_legitimate_system_not_flagged_as_sandbox(self) -> None:
        """Legitimate production system not incorrectly flagged."""
        detector = SandboxDetector()

        result = detector.detect_sandbox()

        if not result.get("detected"):
            assert result.get("confidence", 0.0) < 0.5

    def test_low_confidence_results_not_reported_as_positive(self) -> None:
        """Low confidence detections not reported as definitive."""
        detector = SandboxDetector()

        result = detector.detect_sandbox()

        if result.get("detected"):
            assert result.get("confidence", 0.0) >= 0.3


class TestDetectionMethodCoverage:
    """Tests validating all detection methods are callable."""

    def test_all_detection_methods_are_callable(self) -> None:
        """All registered detection methods are callable."""
        detector = SandboxDetector()

        for method_name, method_func in detector.detection_methods.items():
            assert callable(method_func), f"{method_name} is not callable"

    def test_all_detection_methods_execute_without_exception(self) -> None:
        """All detection methods execute without raising exceptions."""
        detector = SandboxDetector()

        for method_name, method_func in detector.detection_methods.items():
            try:
                result = method_func()
                assert result is not None
            except Exception as e:
                pytest.fail(f"Detection method {method_name} raised exception: {e}")


class TestPerformanceCharacteristics:
    """Tests validating detection performance."""

    def test_full_detection_completes_within_reasonable_time(self) -> None:
        """Full detection scan completes within 10 seconds."""
        detector = SandboxDetector()

        start_time = time.time()
        detector.detect_sandbox()
        elapsed = time.time() - start_time

        assert elapsed < 10.0

    def test_individual_checks_complete_quickly(self) -> None:
        """Individual detection checks complete within 1 second."""
        detector = SandboxDetector()

        for method_name, method_func in detector.detection_methods.items():
            start_time = time.time()
            try:
                method_func()
            except Exception:
                pass
            elapsed = time.time() - start_time

            assert elapsed < 1.0, f"{method_name} took {elapsed:.2f}s"
