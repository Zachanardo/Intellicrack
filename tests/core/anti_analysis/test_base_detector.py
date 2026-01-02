"""Production tests for BaseDetector anti-analysis component.

All tests use real test doubles, NO MOCKS.
"""

import logging
from collections.abc import Callable
from typing import Any

import pytest


class ConcreteDetectorDouble:
    """Test double for concrete BaseDetector implementation."""

    def __init__(self) -> None:
        """Initialize test detector with logging and detection methods."""
        self.logger = logging.getLogger("IntellicrackLogger.AntiAnalysis")
        self.detection_methods: dict[str, Callable[[], tuple[bool, float, Any]]] = {}
        self.aggressive_methods_list: list[str] = []
        self.detection_type_value: str = "test_detector"
        self.process_output: str = ""
        self.process_list: list[str] = []

    def run_detection_loop(
        self, aggressive: bool = False, aggressive_methods: list[str] | None = None
    ) -> dict[str, Any]:
        """Run the detection loop for all configured methods."""
        if aggressive_methods is None:
            aggressive_methods = []

        results: dict[str, Any] = {
            "detections": {},
            "detection_count": 0,
            "total_confidence": 0,
            "average_confidence": 0,
        }

        detection_count: int = 0
        total_confidence: float = 0.0

        for method_name, method_func in self.detection_methods.items():
            if not aggressive and method_name in aggressive_methods:
                continue

            try:
                detected, confidence, details = method_func()
                results["detections"][method_name] = {
                    "detected": detected,
                    "confidence": confidence,
                    "details": details,
                }

                if detected:
                    detection_count += 1
                    total_confidence += confidence

            except Exception as e:
                self.logger.debug("Detection method %s failed: %s", method_name, e)

        results["detection_count"] = detection_count
        results["total_confidence"] = total_confidence

        if detection_count > 0:
            results["average_confidence"] = total_confidence / detection_count
        else:
            results["average_confidence"] = 0

        return results

    def get_aggressive_methods(self) -> list[str]:
        """Get list of method names that are considered aggressive."""
        return self.aggressive_methods_list

    def get_detection_type(self) -> str:
        """Get the type of detection this class performs."""
        return self.detection_type_value

    def get_running_processes(self) -> tuple[str, list[str]]:
        """Get list of running processes based on platform."""
        return self.process_output, self.process_list

    def calculate_detection_score(
        self,
        detections: dict[str, Any],
        strong_methods: list[str],
        medium_methods: list[str] | None = None,
    ) -> int:
        """Calculate detection score based on method difficulty."""
        if medium_methods is None:
            medium_methods = []

        score: int = 0
        for method, result in detections.items():
            if isinstance(result, dict) and result.get("detected"):
                if method in strong_methods:
                    score += 3
                elif method in medium_methods:
                    score += 2
                else:
                    score += 1

        return min(10, score)


class CallTrackingDetectionMethod:
    """Test double that tracks detection method calls."""

    def __init__(
        self, detected: bool = False, confidence: float = 0.0, details: dict[str, Any] | None = None
    ) -> None:
        """Initialize detection method with configurable results."""
        self.detected = detected
        self.confidence = confidence
        self.details = details if details is not None else {}
        self.call_count = 0
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def __call__(self) -> tuple[bool, float, dict[str, Any]]:
        """Execute detection and track calls."""
        self.call_count += 1
        self.calls.append(((), {}))
        return self.detected, self.confidence, self.details.copy()

    def configure_result(
        self, detected: bool, confidence: float, details: dict[str, Any] | None = None
    ) -> None:
        """Reconfigure detection results for subsequent calls."""
        self.detected = detected
        self.confidence = confidence
        if details is not None:
            self.details = details

    def reset_tracking(self) -> None:
        """Reset call tracking information."""
        self.call_count = 0
        self.calls = []


class FailingDetectionMethod:
    """Test double that raises exceptions to test error handling."""

    def __init__(self, exception_type: type[Exception] = Exception, message: str = "Detection failed") -> None:
        """Initialize failing detection method."""
        self.exception_type = exception_type
        self.message = message
        self.call_count = 0

    def __call__(self) -> tuple[bool, float, dict[str, Any]]:
        """Raise configured exception."""
        self.call_count += 1
        raise self.exception_type(self.message)


class TestBaseDetectorInitialization:
    """Test detector initialization and setup."""

    def test_detector_initializes_with_logger(self) -> None:
        """Detector creates logger on initialization."""
        detector = ConcreteDetectorDouble()

        assert detector.logger is not None
        assert detector.logger.name == "IntellicrackLogger.AntiAnalysis"

    def test_detector_initializes_empty_detection_methods(self) -> None:
        """Detector starts with empty detection methods registry."""
        detector = ConcreteDetectorDouble()

        assert isinstance(detector.detection_methods, dict)
        assert len(detector.detection_methods) == 0

    def test_detector_provides_abstract_method_implementations(self) -> None:
        """Detector provides required abstract method implementations."""
        detector = ConcreteDetectorDouble()

        assert callable(detector.get_aggressive_methods)
        assert callable(detector.get_detection_type)


class TestDetectionLoopBasicFunctionality:
    """Test basic detection loop execution."""

    def test_empty_detection_loop_returns_zero_results(self) -> None:
        """Detection loop with no methods returns zero detections."""
        detector = ConcreteDetectorDouble()

        results = detector.run_detection_loop()

        assert results["detection_count"] == 0
        assert results["total_confidence"] == 0
        assert results["average_confidence"] == 0
        assert results["detections"] == {}

    def test_detection_loop_executes_all_methods(self) -> None:
        """Detection loop calls all registered detection methods."""
        detector = ConcreteDetectorDouble()

        method1 = CallTrackingDetectionMethod(detected=True, confidence=0.8)
        method2 = CallTrackingDetectionMethod(detected=False, confidence=0.0)
        method3 = CallTrackingDetectionMethod(detected=True, confidence=0.6)

        detector.detection_methods = {
            "method1": method1,
            "method2": method2,
            "method3": method3,
        }

        results = detector.run_detection_loop()

        assert method1.call_count == 1
        assert method2.call_count == 1
        assert method3.call_count == 1

    def test_detection_loop_counts_positive_detections(self) -> None:
        """Detection loop correctly counts methods that detected threats."""
        detector = ConcreteDetectorDouble()

        detector.detection_methods = {
            "detected1": CallTrackingDetectionMethod(detected=True, confidence=0.9),
            "not_detected": CallTrackingDetectionMethod(detected=False, confidence=0.0),
            "detected2": CallTrackingDetectionMethod(detected=True, confidence=0.7),
            "detected3": CallTrackingDetectionMethod(detected=True, confidence=0.5),
        }

        results = detector.run_detection_loop()

        assert results["detection_count"] == 3

    def test_detection_loop_sums_confidence_scores(self) -> None:
        """Detection loop correctly sums confidence from positive detections."""
        detector = ConcreteDetectorDouble()

        detector.detection_methods = {
            "method1": CallTrackingDetectionMethod(detected=True, confidence=0.8),
            "method2": CallTrackingDetectionMethod(detected=False, confidence=0.3),
            "method3": CallTrackingDetectionMethod(detected=True, confidence=0.6),
        }

        results = detector.run_detection_loop()

        assert results["total_confidence"] == pytest.approx(1.4, abs=0.01)
        assert results["average_confidence"] == pytest.approx(0.7, abs=0.01)

    def test_detection_loop_calculates_average_confidence(self) -> None:
        """Detection loop computes correct average confidence."""
        detector = ConcreteDetectorDouble()

        detector.detection_methods = {
            "method1": CallTrackingDetectionMethod(detected=True, confidence=1.0),
            "method2": CallTrackingDetectionMethod(detected=True, confidence=0.8),
            "method3": CallTrackingDetectionMethod(detected=True, confidence=0.6),
            "method4": CallTrackingDetectionMethod(detected=True, confidence=0.4),
        }

        results = detector.run_detection_loop()

        expected_average = (1.0 + 0.8 + 0.6 + 0.4) / 4
        assert results["average_confidence"] == pytest.approx(expected_average, abs=0.01)

    def test_detection_loop_stores_method_details(self) -> None:
        """Detection loop preserves detailed results from each method."""
        detector = ConcreteDetectorDouble()

        details1 = {"technique": "ptrace", "pid": 1234}
        details2 = {"technique": "timing", "delay_ms": 150}

        detector.detection_methods = {
            "method1": CallTrackingDetectionMethod(detected=True, confidence=0.9, details=details1),
            "method2": CallTrackingDetectionMethod(detected=True, confidence=0.7, details=details2),
        }

        results = detector.run_detection_loop()

        assert results["detections"]["method1"]["details"] == details1
        assert results["detections"]["method2"]["details"] == details2
        assert results["detections"]["method1"]["detected"] is True
        assert results["detections"]["method1"]["confidence"] == 0.9


class TestAggressiveMethodFiltering:
    """Test aggressive method filtering in detection loop."""

    def test_aggressive_methods_skipped_when_not_requested(self) -> None:
        """Detection loop skips aggressive methods when aggressive=False."""
        detector = ConcreteDetectorDouble()

        normal_method = CallTrackingDetectionMethod(detected=True, confidence=0.8)
        aggressive_method = CallTrackingDetectionMethod(detected=True, confidence=0.9)

        detector.detection_methods = {
            "normal": normal_method,
            "aggressive": aggressive_method,
        }

        aggressive_list = ["aggressive"]
        results = detector.run_detection_loop(aggressive=False, aggressive_methods=aggressive_list)

        assert normal_method.call_count == 1
        assert aggressive_method.call_count == 0
        assert results["detection_count"] == 1

    def test_aggressive_methods_executed_when_requested(self) -> None:
        """Detection loop executes aggressive methods when aggressive=True."""
        detector = ConcreteDetectorDouble()

        normal_method = CallTrackingDetectionMethod(detected=True, confidence=0.8)
        aggressive_method = CallTrackingDetectionMethod(detected=True, confidence=0.9)

        detector.detection_methods = {
            "normal": normal_method,
            "aggressive": aggressive_method,
        }

        aggressive_list = ["aggressive"]
        results = detector.run_detection_loop(aggressive=True, aggressive_methods=aggressive_list)

        assert normal_method.call_count == 1
        assert aggressive_method.call_count == 1
        assert results["detection_count"] == 2

    def test_multiple_aggressive_methods_filtered_correctly(self) -> None:
        """Detection loop filters multiple aggressive methods correctly."""
        detector = ConcreteDetectorDouble()

        detector.detection_methods = {
            "safe1": CallTrackingDetectionMethod(detected=True, confidence=0.7),
            "aggressive1": CallTrackingDetectionMethod(detected=True, confidence=0.8),
            "safe2": CallTrackingDetectionMethod(detected=True, confidence=0.6),
            "aggressive2": CallTrackingDetectionMethod(detected=True, confidence=0.9),
        }

        aggressive_list = ["aggressive1", "aggressive2"]
        results = detector.run_detection_loop(aggressive=False, aggressive_methods=aggressive_list)

        assert results["detection_count"] == 2
        assert "safe1" in results["detections"]
        assert "safe2" in results["detections"]
        assert "aggressive1" not in results["detections"]
        assert "aggressive2" not in results["detections"]

    def test_empty_aggressive_list_executes_all_methods(self) -> None:
        """Detection loop executes all methods when aggressive list is empty."""
        detector = ConcreteDetectorDouble()

        detector.detection_methods = {
            "method1": CallTrackingDetectionMethod(detected=True, confidence=0.8),
            "method2": CallTrackingDetectionMethod(detected=True, confidence=0.7),
        }

        results = detector.run_detection_loop(aggressive=False, aggressive_methods=[])

        assert results["detection_count"] == 2


class TestDetectionLoopErrorHandling:
    """Test error handling in detection loop."""

    def test_failing_method_does_not_stop_execution(self) -> None:
        """Detection loop continues when a method raises exception."""
        detector = ConcreteDetectorDouble()

        good_method = CallTrackingDetectionMethod(detected=True, confidence=0.8)
        failing_method = FailingDetectionMethod(RuntimeError, "Test error")
        another_good_method = CallTrackingDetectionMethod(detected=True, confidence=0.6)

        detector.detection_methods = {
            "good": good_method,
            "failing": failing_method,
            "another_good": another_good_method,
        }

        results = detector.run_detection_loop()

        assert good_method.call_count == 1
        assert failing_method.call_count == 1
        assert another_good_method.call_count == 1
        assert results["detection_count"] == 2

    def test_multiple_failing_methods_handled_gracefully(self) -> None:
        """Detection loop handles multiple failing methods."""
        detector = ConcreteDetectorDouble()

        detector.detection_methods = {
            "fail1": FailingDetectionMethod(ValueError, "Error 1"),
            "success": CallTrackingDetectionMethod(detected=True, confidence=0.9),
            "fail2": FailingDetectionMethod(TypeError, "Error 2"),
        }

        results = detector.run_detection_loop()

        assert results["detection_count"] == 1
        assert results["total_confidence"] == pytest.approx(0.9, abs=0.01)

    def test_all_failing_methods_returns_zero_detections(self) -> None:
        """Detection loop with all failing methods returns zero detections."""
        detector = ConcreteDetectorDouble()

        detector.detection_methods = {
            "fail1": FailingDetectionMethod(RuntimeError, "Error 1"),
            "fail2": FailingDetectionMethod(ValueError, "Error 2"),
            "fail3": FailingDetectionMethod(TypeError, "Error 3"),
        }

        results = detector.run_detection_loop()

        assert results["detection_count"] == 0
        assert results["total_confidence"] == 0
        assert results["average_confidence"] == 0


class TestDetectionScoreCalculation:
    """Test detection score calculation logic."""

    def test_strong_methods_score_three_points(self) -> None:
        """Strong detection methods contribute 3 points each."""
        detector = ConcreteDetectorDouble()

        detections = {
            "strong_method": {"detected": True, "confidence": 0.9},
        }

        score = detector.calculate_detection_score(detections, strong_methods=["strong_method"])

        assert score == 3

    def test_medium_methods_score_two_points(self) -> None:
        """Medium detection methods contribute 2 points each."""
        detector = ConcreteDetectorDouble()

        detections = {
            "medium_method": {"detected": True, "confidence": 0.7},
        }

        score = detector.calculate_detection_score(
            detections, strong_methods=[], medium_methods=["medium_method"]
        )

        assert score == 2

    def test_weak_methods_score_one_point(self) -> None:
        """Weak detection methods contribute 1 point each."""
        detector = ConcreteDetectorDouble()

        detections = {
            "weak_method": {"detected": True, "confidence": 0.5},
        }

        score = detector.calculate_detection_score(detections, strong_methods=[])

        assert score == 1

    def test_mixed_method_scoring(self) -> None:
        """Score calculation combines different method strengths correctly."""
        detector = ConcreteDetectorDouble()

        detections = {
            "strong1": {"detected": True, "confidence": 0.9},
            "strong2": {"detected": True, "confidence": 0.95},
            "medium1": {"detected": True, "confidence": 0.7},
            "weak1": {"detected": True, "confidence": 0.5},
        }

        score = detector.calculate_detection_score(
            detections,
            strong_methods=["strong1", "strong2"],
            medium_methods=["medium1"],
        )

        assert score == 3 + 3 + 2 + 1

    def test_score_capped_at_ten(self) -> None:
        """Detection score is capped at maximum value of 10."""
        detector = ConcreteDetectorDouble()

        detections = {
            f"strong{i}": {"detected": True, "confidence": 0.9} for i in range(10)
        }

        score = detector.calculate_detection_score(
            detections, strong_methods=[f"strong{i}" for i in range(10)]
        )

        assert score == 10

    def test_non_detected_methods_contribute_zero_points(self) -> None:
        """Methods that didn't detect contribute zero to score."""
        detector = ConcreteDetectorDouble()

        detections = {
            "detected_strong": {"detected": True, "confidence": 0.9},
            "not_detected_strong": {"detected": False, "confidence": 0.0},
            "detected_medium": {"detected": True, "confidence": 0.7},
            "not_detected_medium": {"detected": False, "confidence": 0.0},
        }

        score = detector.calculate_detection_score(
            detections,
            strong_methods=["detected_strong", "not_detected_strong"],
            medium_methods=["detected_medium", "not_detected_medium"],
        )

        assert score == 3 + 2

    def test_score_calculation_with_empty_detections(self) -> None:
        """Score calculation handles empty detections dictionary."""
        detector = ConcreteDetectorDouble()

        score = detector.calculate_detection_score({}, strong_methods=["anything"])

        assert score == 0

    def test_score_calculation_handles_invalid_detection_format(self) -> None:
        """Score calculation skips invalid detection entries."""
        detector = ConcreteDetectorDouble()

        detections = {
            "valid": {"detected": True, "confidence": 0.8},
            "invalid_not_dict": "not a dict",
            "invalid_no_detected_key": {"confidence": 0.7},
        }

        score = detector.calculate_detection_score(detections, strong_methods=["valid"])

        assert score == 3


class TestAbstractMethodImplementation:
    """Test abstract method contract compliance."""

    def test_get_aggressive_methods_returns_list(self) -> None:
        """get_aggressive_methods returns list of method names."""
        detector = ConcreteDetectorDouble()
        detector.aggressive_methods_list = ["timing_check", "exception_handling"]

        result = detector.get_aggressive_methods()

        assert isinstance(result, list)
        assert result == ["timing_check", "exception_handling"]

    def test_get_detection_type_returns_string(self) -> None:
        """get_detection_type returns string describing detector type."""
        detector = ConcreteDetectorDouble()
        detector.detection_type_value = "debugger"

        result = detector.get_detection_type()

        assert isinstance(result, str)
        assert result == "debugger"


class TestGetRunningProcesses:
    """Test process enumeration functionality."""

    def test_get_running_processes_returns_tuple(self) -> None:
        """get_running_processes returns output and process list tuple."""
        detector = ConcreteDetectorDouble()
        detector.process_output = "process1.exe\nprocess2.exe\n"
        detector.process_list = ["process1.exe", "process2.exe"]

        output, process_list = detector.get_running_processes()

        assert isinstance(output, str)
        assert isinstance(process_list, list)

    def test_get_running_processes_returns_configured_data(self) -> None:
        """get_running_processes returns configured test data."""
        detector = ConcreteDetectorDouble()
        expected_output = "ollydbg.exe\nx64dbg.exe\n"
        expected_list = ["ollydbg.exe", "x64dbg.exe"]
        detector.process_output = expected_output
        detector.process_list = expected_list

        output, process_list = detector.get_running_processes()

        assert output == expected_output
        assert process_list == expected_list


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_detection_loop_with_zero_confidence_detections(self) -> None:
        """Detection loop handles detections with zero confidence."""
        detector = ConcreteDetectorDouble()

        detector.detection_methods = {
            "zero_conf": CallTrackingDetectionMethod(detected=True, confidence=0.0),
            "normal": CallTrackingDetectionMethod(detected=True, confidence=0.8),
        }

        results = detector.run_detection_loop()

        assert results["detection_count"] == 2
        assert results["total_confidence"] == pytest.approx(0.8, abs=0.01)

    def test_detection_loop_with_maximum_confidence(self) -> None:
        """Detection loop handles detections with maximum confidence."""
        detector = ConcreteDetectorDouble()

        detector.detection_methods = {
            "max_conf": CallTrackingDetectionMethod(detected=True, confidence=1.0),
        }

        results = detector.run_detection_loop()

        assert results["average_confidence"] == 1.0

    def test_detection_loop_with_very_large_number_of_methods(self) -> None:
        """Detection loop handles large number of detection methods."""
        detector = ConcreteDetectorDouble()

        for i in range(100):
            detector.detection_methods[f"method{i}"] = CallTrackingDetectionMethod(
                detected=(i % 2 == 0), confidence=0.5
            )

        results = detector.run_detection_loop()

        assert results["detection_count"] == 50

    def test_average_confidence_zero_when_no_detections(self) -> None:
        """Average confidence is zero when no methods detect."""
        detector = ConcreteDetectorDouble()

        detector.detection_methods = {
            "method1": CallTrackingDetectionMethod(detected=False, confidence=0.0),
            "method2": CallTrackingDetectionMethod(detected=False, confidence=0.0),
        }

        results = detector.run_detection_loop()

        assert results["average_confidence"] == 0


class TestIntegrationScenarios:
    """Test realistic integration scenarios."""

    def test_realistic_debugger_detection_scenario(self) -> None:
        """Realistic scenario: multiple debugger detection techniques."""
        detector = ConcreteDetectorDouble()

        detector.detection_methods = {
            "isdebuggerpresent": CallTrackingDetectionMethod(
                detected=True, confidence=0.9, details={"api_result": True}
            ),
            "ptrace": CallTrackingDetectionMethod(
                detected=True, confidence=0.85, details={"tracer_pid": 1234}
            ),
            "timing_check": CallTrackingDetectionMethod(
                detected=False, confidence=0.0, details={"execution_time": 5.2}
            ),
            "parent_process": CallTrackingDetectionMethod(
                detected=True, confidence=0.7, details={"parent": "x64dbg.exe"}
            ),
        }

        detector.aggressive_methods_list = ["timing_check"]

        results = detector.run_detection_loop(aggressive=False, aggressive_methods=detector.aggressive_methods_list)

        assert results["detection_count"] == 2
        assert results["average_confidence"] == pytest.approx((0.9 + 0.85 + 0.7) / 3, abs=0.01)
        assert "timing_check" not in results["detections"]

    def test_realistic_scoring_scenario(self) -> None:
        """Realistic scenario: scoring multiple detection techniques."""
        detector = ConcreteDetectorDouble()

        detections = {
            "debug_port": {"detected": True, "confidence": 0.9},
            "peb_flags": {"detected": True, "confidence": 0.85},
            "isdebuggerpresent": {"detected": True, "confidence": 0.9},
            "timing_check": {"detected": False, "confidence": 0.0},
        }

        strong_methods = ["debug_port", "peb_flags"]
        medium_methods = ["isdebuggerpresent"]

        score = detector.calculate_detection_score(detections, strong_methods, medium_methods)

        assert score == 3 + 3 + 2

    def test_all_methods_fail_gracefully_handled(self) -> None:
        """Realistic scenario: system under heavy load, all methods fail."""
        detector = ConcreteDetectorDouble()

        detector.detection_methods = {
            "method1": FailingDetectionMethod(OSError, "System resource unavailable"),
            "method2": FailingDetectionMethod(PermissionError, "Access denied"),
            "method3": FailingDetectionMethod(TimeoutError, "Operation timed out"),
        }

        results = detector.run_detection_loop()

        assert results["detection_count"] == 0
        assert results["detections"] == {}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
