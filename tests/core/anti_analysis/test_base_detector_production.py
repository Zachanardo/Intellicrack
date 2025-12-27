"""Production tests for BaseDetector anti-analysis component.

Tests the base detector functionality with real detection methods
and process scanning on Windows platform.
"""

import platform
from typing import Any

import pytest

from intellicrack.core.anti_analysis.base_detector import BaseDetector


class ConcreteDetector(BaseDetector):
    """Concrete implementation of BaseDetector for testing."""

    def __init__(self) -> None:
        """Initialize concrete detector with test methods."""
        super().__init__()
        self.detection_methods = {
            "test_method_1": self.test_detection_1,
            "test_method_2": self.test_detection_2,
            "aggressive_method": self.aggressive_detection,
        }

    def test_detection_1(self) -> tuple[bool, float, Any]:
        """Simple detection that always succeeds."""
        return True, 0.95, {"detail": "Test detection 1 fired"}

    def test_detection_2(self) -> tuple[bool, float, Any]:
        """Simple detection that always fails."""
        return False, 0.0, {"detail": "Test detection 2 clean"}

    def aggressive_detection(self) -> tuple[bool, float, Any]:
        """Aggressive detection method."""
        return True, 0.85, {"detail": "Aggressive detection fired"}

    def get_aggressive_methods(self) -> list[str]:
        """Return list of aggressive method names."""
        return ["aggressive_method"]

    def get_detection_type(self) -> str:
        """Return detection type identifier."""
        return "test_detector"


class FailingDetector(BaseDetector):
    """Detector with methods that raise exceptions."""

    def __init__(self) -> None:
        """Initialize failing detector."""
        super().__init__()
        self.detection_methods = {
            "failing_method": self.failing_detection,
            "working_method": self.working_detection,
        }

    def failing_detection(self) -> tuple[bool, float, Any]:
        """Detection method that raises exception."""
        raise RuntimeError("Simulated detection failure")

    def working_detection(self) -> tuple[bool, float, Any]:
        """Detection method that works."""
        return True, 0.90, {"detail": "Working detection"}

    def get_aggressive_methods(self) -> list[str]:
        """Return empty list."""
        return []

    def get_detection_type(self) -> str:
        """Return detection type."""
        return "failing_detector"


class FailingProcess:
    """Simple class to simulate a failed subprocess result."""

    stdout: str = ""
    stderr: str = "Access denied"
    returncode: int = 1


@pytest.fixture
def concrete_detector() -> ConcreteDetector:
    """Create concrete detector instance."""
    return ConcreteDetector()


@pytest.fixture
def failing_detector() -> FailingDetector:
    """Create failing detector instance."""
    return FailingDetector()


class TestBaseDetectorInitialization:
    """Test BaseDetector initialization."""

    def test_detector_initializes_with_logger(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Detector initializes with logger instance."""
        assert concrete_detector.logger is not None
        assert concrete_detector.logger.name == "IntellicrackLogger.AntiAnalysis"

    def test_detector_initializes_with_empty_detection_methods(self) -> None:
        """Base detector starts with empty detection methods dict."""

        class EmptyDetector(BaseDetector):
            def get_aggressive_methods(self) -> list[str]:
                return []

            def get_detection_type(self) -> str:
                return "empty"

        detector = EmptyDetector()
        assert detector.detection_methods == {}

    def test_detector_has_detection_methods(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Concrete detector has configured detection methods."""
        assert len(concrete_detector.detection_methods) == 3
        assert "test_method_1" in concrete_detector.detection_methods
        assert "test_method_2" in concrete_detector.detection_methods
        assert "aggressive_method" in concrete_detector.detection_methods


class TestDetectionLoop:
    """Test detection loop execution."""

    def test_run_detection_loop_executes_all_methods(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Detection loop executes all non-aggressive methods."""
        results = concrete_detector.run_detection_loop(aggressive=False)

        assert "detections" in results
        assert "test_method_1" in results["detections"]
        assert "test_method_2" in results["detections"]
        assert "aggressive_method" not in results["detections"]

    def test_run_detection_loop_with_aggressive(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Detection loop executes aggressive methods when requested."""
        results = concrete_detector.run_detection_loop(aggressive=True)

        assert "aggressive_method" in results["detections"]
        assert results["detections"]["aggressive_method"]["detected"] is True

    def test_detection_results_structure(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Detection results have correct structure."""
        results = concrete_detector.run_detection_loop()

        assert "detections" in results
        assert "detection_count" in results
        assert "total_confidence" in results
        assert "average_confidence" in results

        for method_name, detection in results["detections"].items():
            assert "detected" in detection
            assert "confidence" in detection
            assert "details" in detection

    def test_detection_count_calculation(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Detection count is calculated correctly."""
        results = concrete_detector.run_detection_loop()

        assert results["detection_count"] == 1

    def test_confidence_calculation(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Confidence scores are calculated correctly."""
        results = concrete_detector.run_detection_loop()

        assert results["total_confidence"] == 0.95
        assert results["average_confidence"] == 0.95

    def test_average_confidence_with_no_detections(self) -> None:
        """Average confidence is 0 when no detections occur."""

        class NoDetectionDetector(BaseDetector):
            def __init__(self) -> None:
                super().__init__()
                self.detection_methods = {
                    "clean_method": lambda: (False, 0.0, {})
                }

            def get_aggressive_methods(self) -> list[str]:
                return []

            def get_detection_type(self) -> str:
                return "clean"

        detector = NoDetectionDetector()
        results = detector.run_detection_loop()

        assert results["detection_count"] == 0
        assert results["average_confidence"] == 0

    def test_detection_loop_handles_exceptions(
        self, failing_detector: FailingDetector
    ) -> None:
        """Detection loop continues when method raises exception."""
        results = failing_detector.run_detection_loop()

        assert "working_method" in results["detections"]
        assert results["detections"]["working_method"]["detected"] is True


class TestProcessScanning:
    """Test process scanning functionality."""

    def test_get_running_processes_returns_tuple(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """get_running_processes returns tuple of (output, process_list)."""
        raw_output, process_list = concrete_detector.get_running_processes()

        assert isinstance(raw_output, str)
        assert isinstance(process_list, list)

    def test_get_running_processes_on_windows(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """get_running_processes works on Windows platform."""
        if platform.system() != "Windows":
            pytest.skip("Test only runs on Windows")

        raw_output, process_list = concrete_detector.get_running_processes()

        assert len(raw_output) > 0
        assert len(process_list) > 0
        assert all(isinstance(p, str) for p in process_list)

    def test_process_list_contains_system_processes(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Process list contains expected system processes on Windows."""
        if platform.system() != "Windows":
            pytest.skip("Test only runs on Windows")

        _, process_list = concrete_detector.get_running_processes()

        assert len(process_list) > 0
        assert any("system" in p or "svchost" in p for p in process_list)

    def test_process_names_are_lowercase(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Process names are converted to lowercase."""
        if platform.system() != "Windows":
            pytest.skip("Test only runs on Windows")

        _, process_list = concrete_detector.get_running_processes()

        for process in process_list:
            assert process == process.lower()

    def test_get_running_processes_handles_errors(
        self, concrete_detector: ConcreteDetector, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """get_running_processes handles subprocess errors gracefully."""
        import subprocess

        def mock_run(*args: Any, **kwargs: Any) -> None:
            raise OSError("Subprocess error")

        monkeypatch.setattr(subprocess, "run", mock_run)

        raw_output, process_list = concrete_detector.get_running_processes()

        assert raw_output == ""
        assert process_list == []


class TestDetectionScoreCalculation:
    """Test detection score calculation."""

    def test_calculate_detection_score_with_strong_methods(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Strong detection methods score 3 points."""
        detections = {
            "strong_detection": {"detected": True, "confidence": 0.95},
        }
        strong_methods = ["strong_detection"]

        score = concrete_detector.calculate_detection_score(
            detections, strong_methods
        )

        assert score == 3

    def test_calculate_detection_score_with_medium_methods(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Medium detection methods score 2 points."""
        detections = {
            "medium_detection": {"detected": True, "confidence": 0.80},
        }
        strong_methods: list[str] = []
        medium_methods = ["medium_detection"]

        score = concrete_detector.calculate_detection_score(
            detections, strong_methods, medium_methods
        )

        assert score == 2

    def test_calculate_detection_score_with_weak_methods(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Weak detection methods score 1 point."""
        detections = {
            "weak_detection": {"detected": True, "confidence": 0.60},
        }
        strong_methods: list[str] = []
        medium_methods: list[str] = []

        score = concrete_detector.calculate_detection_score(
            detections, strong_methods, medium_methods
        )

        assert score == 1

    def test_calculate_detection_score_capped_at_10(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Detection score is capped at 10."""
        detections = {
            f"strong_detection_{i}": {"detected": True, "confidence": 0.95}
            for i in range(10)
        }
        strong_methods = [f"strong_detection_{i}" for i in range(10)]

        score = concrete_detector.calculate_detection_score(
            detections, strong_methods
        )

        assert score == 10

    def test_calculate_detection_score_ignores_non_detected(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Non-detected methods don't contribute to score."""
        detections = {
            "detected_method": {"detected": True, "confidence": 0.95},
            "clean_method": {"detected": False, "confidence": 0.0},
        }
        strong_methods = ["detected_method", "clean_method"]

        score = concrete_detector.calculate_detection_score(
            detections, strong_methods
        )

        assert score == 3

    def test_calculate_detection_score_mixed_methods(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Mixed detection methods score correctly."""
        detections = {
            "strong_1": {"detected": True, "confidence": 0.95},
            "strong_2": {"detected": True, "confidence": 0.92},
            "medium_1": {"detected": True, "confidence": 0.85},
            "weak_1": {"detected": True, "confidence": 0.70},
        }
        strong_methods = ["strong_1", "strong_2"]
        medium_methods = ["medium_1"]

        score = concrete_detector.calculate_detection_score(
            detections, strong_methods, medium_methods
        )

        assert score == 9

    def test_calculate_detection_score_with_empty_detections(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """Empty detections return score of 0."""
        detections: dict[str, Any] = {}
        strong_methods: list[str] = []

        score = concrete_detector.calculate_detection_score(
            detections, strong_methods
        )

        assert score == 0


class TestAbstractMethods:
    """Test abstract method enforcement."""

    def test_get_aggressive_methods_returns_list(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """get_aggressive_methods returns list of method names."""
        aggressive = concrete_detector.get_aggressive_methods()

        assert isinstance(aggressive, list)
        assert "aggressive_method" in aggressive

    def test_get_detection_type_returns_string(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """get_detection_type returns string identifier."""
        detection_type = concrete_detector.get_detection_type()

        assert isinstance(detection_type, str)
        assert detection_type == "test_detector"


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_detection_loop_with_empty_methods(self) -> None:
        """Detection loop works with no methods registered."""

        class EmptyDetector(BaseDetector):
            def __init__(self) -> None:
                super().__init__()
                self.detection_methods = {}

            def get_aggressive_methods(self) -> list[str]:
                return []

            def get_detection_type(self) -> str:
                return "empty"

        detector = EmptyDetector()
        results = detector.run_detection_loop()

        assert results["detection_count"] == 0
        assert results["total_confidence"] == 0
        assert results["average_confidence"] == 0

    def test_detection_loop_all_methods_fail(
        self, failing_detector: FailingDetector
    ) -> None:
        """Detection loop handles all methods failing."""

        class AllFailingDetector(BaseDetector):
            def __init__(self) -> None:
                super().__init__()
                self.detection_methods = {
                    "fail_1": lambda: (_ for _ in ()).throw(RuntimeError("Fail 1")),
                    "fail_2": lambda: (_ for _ in ()).throw(ValueError("Fail 2")),
                }

            def get_aggressive_methods(self) -> list[str]:
                return []

            def get_detection_type(self) -> str:
                return "all_failing"

        detector = AllFailingDetector()
        results = detector.run_detection_loop()

        assert results["detection_count"] == 0

    def test_calculate_score_with_none_medium_methods(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """calculate_detection_score handles None medium_methods parameter."""
        detections = {
            "test_method": {"detected": True, "confidence": 0.90},
        }
        strong_methods: list[str] = []

        score = concrete_detector.calculate_detection_score(
            detections, strong_methods, None
        )

        assert score == 1

    def test_run_detection_loop_with_none_aggressive_methods(
        self, concrete_detector: ConcreteDetector
    ) -> None:
        """run_detection_loop handles None aggressive_methods parameter."""
        results = concrete_detector.run_detection_loop(
            aggressive=False, aggressive_methods=None
        )

        assert "detections" in results
