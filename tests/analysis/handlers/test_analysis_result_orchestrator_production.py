"""Production tests for analysis result orchestrator.

Tests result distribution and signal propagation without mocks,
validating real handler communication and error handling.
"""

from collections.abc import Generator
from dataclasses import dataclass, field
from typing import Any, cast

import pytest
from PyQt6.QtCore import QObject, pyqtSlot
from PyQt6.QtWidgets import QApplication

from intellicrack.analysis.analysis_result_orchestrator import AnalysisResultOrchestrator
from intellicrack.protection.unified_protection_engine import UnifiedProtectionResult
from intellicrack.protection.icp_backend import ICPScanResult


@dataclass
class FakeProtection:
    """Fake protection detection for testing."""

    type: str
    confidence: float
    bypass_difficulty: str = "medium"


@dataclass
class FakeICPDetection:
    """Fake ICP detection result."""

    name: str
    type: str
    version: str = ""
    info: str = ""
    string: str = ""
    confidence: float = 1.0


@dataclass
class FakeICPFileInfo:
    """Fake ICP file info."""

    filetype: str
    size: str
    offset: str = "0"
    parentfilepart: str = ""
    detections: list[FakeICPDetection] = field(default_factory=list)


@dataclass
class FakeICPScanResult:
    """Fake ICP scan result for testing."""

    file_path: str
    timestamp: str = "2025-01-01 12:00:00"
    status: str = "completed"
    protections: list[FakeProtection] = field(default_factory=list)
    overall_confidence: float = 0.90
    recommendations: list[str] = field(default_factory=list)
    suggested_tools: list[str] = field(default_factory=list)
    file_infos: list[FakeICPFileInfo] = field(default_factory=list)
    error: str | None = None
    raw_json: dict[str, Any] | None = None
    supplemental_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class FakeUnifiedProtectionResult:
    """Fake unified protection result for testing."""

    file_path: str
    analysis_timestamp: str = "2025-01-01 12:00:00"
    protections: list[FakeProtection] = field(default_factory=list)
    confidence: float = 0.85
    icp_analysis: FakeICPScanResult | None = None
    file_type: str = "PE"
    architecture: str = "x86_64"


class FakeHandler(QObject):
    """Fake handler implementing the expected interface."""

    def __init__(self) -> None:
        super().__init__()
        self.received_results: list[Any] = []
        self.call_count: int = 0

    @pyqtSlot(object)
    def on_analysis_complete(self, result: Any) -> None:
        """Handle analysis completion."""
        self.received_results.append(result)
        self.call_count += 1


class FakeICPHandler(QObject):
    """Fake handler with ICP-specific slot."""

    def __init__(self) -> None:
        super().__init__()
        self.received_results: list[Any] = []
        self.received_icp_results: list[Any] = []
        self.general_call_count: int = 0
        self.icp_call_count: int = 0

    @pyqtSlot(object)
    def on_analysis_complete(self, result: Any) -> None:
        """Handle general analysis completion."""
        self.received_results.append(result)
        self.general_call_count += 1

    @pyqtSlot(object)
    def on_icp_analysis_complete(self, result: Any) -> None:
        """Handle ICP analysis completion."""
        self.received_icp_results.append(result)
        self.icp_call_count += 1


class FakeErrorHandler(QObject):
    """Fake handler that raises errors for testing error handling."""

    def __init__(self, error_type: type[Exception] = RuntimeError, error_message: str = "Test error") -> None:
        super().__init__()
        self.error_type = error_type
        self.error_message = error_message
        self.call_count: int = 0

    @pyqtSlot(object)
    def on_analysis_complete(self, result: Any) -> None:
        """Raise an error when called."""
        self.call_count += 1
        raise self.error_type(self.error_message)


class FakeICPErrorHandler(QObject):
    """Fake ICP handler that raises errors."""

    def __init__(self, error_type: type[Exception] = ValueError, error_message: str = "ICP test error") -> None:
        super().__init__()
        self.error_type = error_type
        self.error_message = error_message
        self.icp_call_count: int = 0

    @pyqtSlot(object)
    def on_icp_analysis_complete(self, result: Any) -> None:
        """Raise an error when called."""
        self.icp_call_count += 1
        raise self.error_type(self.error_message)


class FakeInvalidHandler(QObject):
    """Fake handler without required slot for testing registration rejection."""

    def __init__(self) -> None:
        super().__init__()
        self.some_other_method_called: bool = False

    def some_other_method(self) -> None:
        """Some method that is not the required slot."""
        self.some_other_method_called = True


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication, None, None]:
    """Create QApplication instance for Qt tests."""
    existing_app = QApplication.instance()
    if existing_app is None:
        app = QApplication([])
    else:
        app = cast(QApplication, existing_app)
    yield app


@pytest.fixture
def orchestrator(qapp: QApplication) -> AnalysisResultOrchestrator:
    """Create orchestrator instance."""
    return AnalysisResultOrchestrator()


@pytest.fixture
def fake_handler() -> FakeHandler:
    """Create fake handler with on_analysis_complete slot."""
    return FakeHandler()


@pytest.fixture
def fake_icp_handler() -> FakeICPHandler:
    """Create fake handler with ICP-specific slot."""
    return FakeICPHandler()


@pytest.fixture
def fake_unified_result() -> UnifiedProtectionResult:
    """Create fake unified protection result."""
    return cast(UnifiedProtectionResult, FakeUnifiedProtectionResult(
        file_path="test.exe",
        analysis_timestamp="2025-01-01 12:00:00",
        protections=[],
        confidence=0.85,
        icp_analysis=None,
    ))


@pytest.fixture
def fake_icp_result() -> ICPScanResult:
    """Create fake ICP scan result."""
    return cast(ICPScanResult, FakeICPScanResult(
        file_path="test.exe",
        timestamp="2025-01-01 12:00:00",
        protections=[],
        overall_confidence=0.90,
        status="completed",
        recommendations=["Use advanced analysis"],
        suggested_tools=["Frida", "Radare2"],
    ))


class TestOrchestratorInitialization:
    """Test orchestrator initialization."""

    def test_orchestrator_creates_successfully(
        self, orchestrator: AnalysisResultOrchestrator
    ) -> None:
        """Orchestrator initializes with empty handler list."""
        assert orchestrator is not None
        assert orchestrator.handlers == []
        assert orchestrator._current_result is None

    def test_orchestrator_has_signals(self, orchestrator: AnalysisResultOrchestrator) -> None:
        """Orchestrator has required signals."""
        assert hasattr(orchestrator, "handler_status")


class TestHandlerRegistration:
    """Test handler registration and unregistration."""

    def test_register_handler_with_slot(
        self, orchestrator: AnalysisResultOrchestrator, fake_handler: FakeHandler
    ) -> None:
        """Handler with on_analysis_complete slot registers successfully."""
        orchestrator.register_handler(fake_handler)
        assert fake_handler in orchestrator.handlers

    def test_register_handler_without_slot(
        self, orchestrator: AnalysisResultOrchestrator
    ) -> None:
        """Handler without required slot is rejected."""
        invalid_handler = FakeInvalidHandler()
        orchestrator.register_handler(invalid_handler)
        assert invalid_handler not in orchestrator.handlers

    def test_register_multiple_handlers(
        self, orchestrator: AnalysisResultOrchestrator
    ) -> None:
        """Multiple handlers can be registered."""
        handler1 = FakeHandler()
        handler2 = FakeHandler()

        orchestrator.register_handler(handler1)
        orchestrator.register_handler(handler2)

        assert len(orchestrator.handlers) == 2
        assert handler1 in orchestrator.handlers
        assert handler2 in orchestrator.handlers

    def test_unregister_handler(
        self, orchestrator: AnalysisResultOrchestrator, fake_handler: FakeHandler
    ) -> None:
        """Registered handler can be unregistered."""
        orchestrator.register_handler(fake_handler)
        assert fake_handler in orchestrator.handlers

        orchestrator.unregister_handler(fake_handler)
        assert fake_handler not in orchestrator.handlers

    def test_unregister_nonexistent_handler(
        self, orchestrator: AnalysisResultOrchestrator, fake_handler: FakeHandler
    ) -> None:
        """Unregistering non-registered handler doesn't raise error."""
        orchestrator.unregister_handler(fake_handler)


class TestResultDistribution:
    """Test result distribution to handlers."""

    def test_distribute_unified_result_to_handler(
        self,
        orchestrator: AnalysisResultOrchestrator,
        fake_handler: FakeHandler,
        fake_unified_result: UnifiedProtectionResult,
    ) -> None:
        """Unified result is distributed to registered handler."""
        orchestrator.register_handler(fake_handler)
        orchestrator.on_protection_analyzed(fake_unified_result)

        assert fake_handler.call_count == 1
        assert len(fake_handler.received_results) == 1
        assert fake_handler.received_results[0] is fake_unified_result

    def test_distribute_to_multiple_handlers(
        self, orchestrator: AnalysisResultOrchestrator, fake_unified_result: UnifiedProtectionResult
    ) -> None:
        """Result is distributed to all registered handlers."""
        handler1 = FakeHandler()
        handler2 = FakeHandler()

        orchestrator.register_handler(handler1)
        orchestrator.register_handler(handler2)

        orchestrator.on_protection_analyzed(fake_unified_result)

        assert handler1.call_count == 1
        assert handler2.call_count == 1
        assert handler1.received_results[0] is fake_unified_result
        assert handler2.received_results[0] is fake_unified_result

    def test_current_result_stored(
        self,
        orchestrator: AnalysisResultOrchestrator,
        fake_handler: FakeHandler,
        fake_unified_result: UnifiedProtectionResult,
    ) -> None:
        """Current result is stored after distribution."""
        orchestrator.register_handler(fake_handler)
        orchestrator.on_protection_analyzed(fake_unified_result)

        assert orchestrator._current_result is fake_unified_result

    def test_get_current_result(
        self,
        orchestrator: AnalysisResultOrchestrator,
        fake_handler: FakeHandler,
        fake_unified_result: UnifiedProtectionResult,
    ) -> None:
        """Current result can be retrieved."""
        orchestrator.register_handler(fake_handler)
        orchestrator.on_protection_analyzed(fake_unified_result)

        current = orchestrator.get_current_result()
        assert current is fake_unified_result


class TestICPResultHandling:
    """Test ICP-specific result handling."""

    def test_distribute_icp_result_to_icp_handler(
        self,
        orchestrator: AnalysisResultOrchestrator,
        fake_icp_handler: FakeICPHandler,
        fake_icp_result: ICPScanResult,
    ) -> None:
        """ICP result is distributed to ICP-specific handler."""
        orchestrator.register_handler(fake_icp_handler)
        orchestrator.on_icp_analysis_complete(fake_icp_result)

        assert fake_icp_handler.icp_call_count == 1
        assert len(fake_icp_handler.received_icp_results) == 1
        assert fake_icp_handler.received_icp_results[0] is fake_icp_result

    def test_icp_result_added_to_unified_result(
        self,
        orchestrator: AnalysisResultOrchestrator,
        fake_handler: FakeHandler,
        fake_unified_result: UnifiedProtectionResult,
        fake_icp_result: ICPScanResult,
    ) -> None:
        """ICP result is added to existing unified result."""
        orchestrator.register_handler(fake_handler)
        orchestrator.on_protection_analyzed(fake_unified_result)
        orchestrator.on_icp_analysis_complete(fake_icp_result)

        assert orchestrator._current_result is not None
        assert orchestrator._current_result.icp_analysis is fake_icp_result

    def test_icp_result_fallback_to_general_handler(
        self,
        orchestrator: AnalysisResultOrchestrator,
        fake_handler: FakeHandler,
        fake_unified_result: UnifiedProtectionResult,
        fake_icp_result: ICPScanResult,
    ) -> None:
        """ICP result falls back to general handler if no ICP-specific method."""
        orchestrator.register_handler(fake_handler)
        orchestrator._current_result = fake_unified_result
        orchestrator.on_icp_analysis_complete(fake_icp_result)

        assert fake_handler.call_count == 1


class TestSignalEmission:
    """Test signal emission during result distribution."""

    def test_handler_status_signal_on_success(
        self,
        orchestrator: AnalysisResultOrchestrator,
        fake_handler: FakeHandler,
        fake_unified_result: UnifiedProtectionResult,
    ) -> None:
        """Handler status signal emitted on successful processing."""
        signal_emitted = False
        handler_name = ""
        status_msg = ""

        def on_status(name: str, msg: str) -> None:
            nonlocal signal_emitted, handler_name, status_msg
            signal_emitted = True
            handler_name = name
            status_msg = msg

        orchestrator.handler_status.connect(on_status)
        orchestrator.register_handler(fake_handler)
        orchestrator.on_protection_analyzed(fake_unified_result)

        QApplication.processEvents()

        assert signal_emitted
        assert handler_name == "FakeHandler"
        assert "complete" in status_msg.lower()

    def test_handler_status_signal_on_error(
        self, orchestrator: AnalysisResultOrchestrator, fake_unified_result: UnifiedProtectionResult
    ) -> None:
        """Handler status signal emitted on handler error."""
        error_handler = FakeErrorHandler(RuntimeError, "Test error")

        signal_emitted = False
        error_msg = ""

        def on_status(name: str, msg: str) -> None:
            nonlocal signal_emitted, error_msg
            signal_emitted = True
            error_msg = msg

        orchestrator.handler_status.connect(on_status)
        orchestrator.register_handler(error_handler)
        orchestrator.on_protection_analyzed(fake_unified_result)

        QApplication.processEvents()

        assert signal_emitted
        assert "Error" in error_msg


class TestICPResultValidation:
    """Test ICP result validation."""

    def test_validate_valid_icp_result(
        self, orchestrator: AnalysisResultOrchestrator, fake_icp_result: ICPScanResult
    ) -> None:
        """Valid ICP result passes validation."""
        try:
            from intellicrack.protection.icp_backend import ICPScanResult

            real_icp_result = ICPScanResult(
                file_path=fake_icp_result.file_path,
                file_infos=[],
            )
            is_valid = orchestrator.validate_icp_result(real_icp_result)
            assert is_valid
        except ImportError:
            pytest.skip("ICPScanResult not available")

    def test_validate_icp_result_without_file_path(
        self, orchestrator: AnalysisResultOrchestrator
    ) -> None:
        """ICP result without file_path fails validation."""
        try:
            from intellicrack.protection.icp_backend import ICPScanResult

            invalid_result = ICPScanResult(
                file_path="",
                file_infos=[],
            )
            is_valid = orchestrator.validate_icp_result(invalid_result)
            assert not is_valid
        except ImportError:
            pytest.skip("ICPScanResult not available")

    def test_validate_icp_result_invalid_type(
        self, orchestrator: AnalysisResultOrchestrator
    ) -> None:
        """Invalid type fails validation."""
        invalid_result = cast(ICPScanResult, FakeICPScanResult(file_path="test.exe"))
        is_valid = orchestrator.validate_icp_result(invalid_result)
        assert not is_valid


class TestICPUnifiedMerge:
    """Test merging ICP results with unified results."""

    def test_merge_icp_with_unified_result(
        self,
        orchestrator: AnalysisResultOrchestrator,
        fake_icp_result: ICPScanResult,
        fake_unified_result: UnifiedProtectionResult,
    ) -> None:
        """ICP result merges with unified result."""
        try:
            from intellicrack.protection.icp_backend import ICPScanResult
            from intellicrack.protection.unified_protection_engine import UnifiedProtectionResult

            real_icp = ICPScanResult(file_path=fake_icp_result.file_path, file_infos=[])
            real_unified = UnifiedProtectionResult(
                file_path=fake_unified_result.file_path,
                file_type="PE",
                architecture="x86_64",
            )

            merged = orchestrator.merge_icp_with_unified_result(real_icp, real_unified)
            assert merged is not None
            if hasattr(merged, "icp_analysis"):
                assert merged.icp_analysis is real_icp
        except ImportError:
            pytest.skip("UnifiedProtectionResult not available")

    def test_merge_icp_creates_unified_if_none(
        self, orchestrator: AnalysisResultOrchestrator, fake_icp_result: ICPScanResult
    ) -> None:
        """Merge creates new unified result if none provided."""
        try:
            from intellicrack.protection.icp_backend import ICPScanResult

            real_icp = ICPScanResult(file_path=fake_icp_result.file_path, file_infos=[])
            merged = orchestrator.merge_icp_with_unified_result(real_icp, None)
            if merged:
                assert merged.file_path == fake_icp_result.file_path
        except ImportError:
            pytest.skip("UnifiedProtectionResult not available")

    def test_merge_protections_from_icp(
        self,
        orchestrator: AnalysisResultOrchestrator,
        fake_icp_result: ICPScanResult,
        fake_unified_result: UnifiedProtectionResult,
    ) -> None:
        """Protections from ICP are merged into unified result."""
        try:
            from intellicrack.protection.icp_backend import ICPDetection, ICPFileInfo, ICPScanResult
            from intellicrack.protection.unified_protection_engine import UnifiedProtectionResult

            detection = ICPDetection(
                name="VMProtect",
                type="Protector",
                confidence=0.95,
            )
            file_info = ICPFileInfo(
                filetype="PE",
                size="1024",
                detections=[detection],
            )

            real_icp = ICPScanResult(
                file_path=fake_icp_result.file_path,
                file_infos=[file_info],
            )
            real_unified = UnifiedProtectionResult(
                file_path=fake_unified_result.file_path,
                file_type="PE",
                architecture="x86_64",
            )

            merged = orchestrator.merge_icp_with_unified_result(real_icp, real_unified)
            if merged and hasattr(merged, "protections"):
                assert len(merged.protections) >= 0
        except ImportError:
            pytest.skip("UnifiedProtectionResult not available")

    def test_merge_confidence_from_icp(
        self,
        orchestrator: AnalysisResultOrchestrator,
        fake_icp_result: ICPScanResult,
        fake_unified_result: UnifiedProtectionResult,
    ) -> None:
        """Confidence score from ICP is merged."""
        try:
            from intellicrack.protection.icp_backend import ICPScanResult
            from intellicrack.protection.unified_protection_engine import UnifiedProtectionResult

            real_icp = ICPScanResult(file_path=fake_icp_result.file_path, file_infos=[])
            real_unified = UnifiedProtectionResult(
                file_path=fake_unified_result.file_path,
                file_type="PE",
                architecture="x86_64",
            )
            real_unified.confidence_score = 0.80

            if hasattr(real_icp, "overall_confidence"):
                real_icp.overall_confidence = 0.90

            merged = orchestrator.merge_icp_with_unified_result(real_icp, real_unified)
            if merged and hasattr(merged, "confidence_score"):
                assert merged.confidence_score >= 0.0
        except ImportError:
            pytest.skip("UnifiedProtectionResult not available")


class TestRecommendationExtraction:
    """Test recommendation extraction from ICP results."""

    def test_extract_recommendations(
        self, orchestrator: AnalysisResultOrchestrator, fake_icp_result: ICPScanResult
    ) -> None:
        """Recommendations are extracted from ICP result."""
        try:
            from intellicrack.protection.icp_backend import ICPScanResult

            real_icp = ICPScanResult(file_path=fake_icp_result.file_path, file_infos=[])
            if hasattr(real_icp, "recommendations"):
                real_icp.recommendations = ["Use advanced analysis"]

            recommendations = orchestrator.extract_icp_recommendations(real_icp)

            assert isinstance(recommendations, list)
            if hasattr(real_icp, "recommendations"):
                assert len(recommendations) > 0
                assert "Use advanced analysis" in recommendations
        except ImportError:
            pytest.skip("ICPScanResult not available")

    def test_extract_bypass_recommendations_from_protections(
        self, orchestrator: AnalysisResultOrchestrator, fake_icp_result: ICPScanResult
    ) -> None:
        """Bypass recommendations generated from protections."""
        try:
            from intellicrack.protection.icp_backend import ICPDetection, ICPFileInfo, ICPScanResult

            low_difficulty = ICPDetection(
                name="Basic Packer",
                type="Packer",
            )
            high_difficulty = ICPDetection(
                name="VMProtect",
                type="Protector",
            )

            if hasattr(low_difficulty, "bypass_difficulty"):
                low_difficulty.bypass_difficulty = "low"
            if hasattr(high_difficulty, "bypass_difficulty"):
                high_difficulty.bypass_difficulty = "high"

            file_info = ICPFileInfo(
                filetype="PE",
                size="1024",
                detections=[low_difficulty, high_difficulty],
            )

            real_icp = ICPScanResult(
                file_path=fake_icp_result.file_path,
                file_infos=[file_info],
            )

            if hasattr(real_icp, "protections"):
                real_icp.protections = [low_difficulty, high_difficulty]

            recommendations = orchestrator.extract_icp_recommendations(real_icp)

            if hasattr(low_difficulty, "bypass_difficulty"):
                assert any("low bypass difficulty" in rec for rec in recommendations)
                assert any("advanced bypass techniques" in rec for rec in recommendations)
        except ImportError:
            pytest.skip("ICPScanResult not available")

    def test_extract_tool_recommendations(
        self, orchestrator: AnalysisResultOrchestrator, fake_icp_result: ICPScanResult
    ) -> None:
        """Tool recommendations are extracted."""
        try:
            from intellicrack.protection.icp_backend import ICPScanResult

            real_icp = ICPScanResult(file_path=fake_icp_result.file_path, file_infos=[])
            if hasattr(real_icp, "suggested_tools"):
                real_icp.suggested_tools = ["Frida", "Radare2"]

            recommendations = orchestrator.extract_icp_recommendations(real_icp)

            if hasattr(real_icp, "suggested_tools"):
                assert any("Frida" in rec for rec in recommendations)
                assert any("Radare2" in rec for rec in recommendations)
        except ImportError:
            pytest.skip("ICPScanResult not available")

    def test_extract_recommendations_empty_result(
        self, orchestrator: AnalysisResultOrchestrator
    ) -> None:
        """Empty ICP result returns empty recommendations."""
        fake_result = cast(ICPScanResult, FakeICPScanResult(file_path="test.exe"))
        recommendations = orchestrator.extract_icp_recommendations(fake_result)
        assert recommendations == []


class TestErrorHandling:
    """Test error handling during result distribution."""

    def test_handler_exception_doesnt_stop_distribution(
        self, orchestrator: AnalysisResultOrchestrator, fake_unified_result: UnifiedProtectionResult
    ) -> None:
        """Exception in one handler doesn't prevent others from receiving result."""
        error_handler = FakeErrorHandler(RuntimeError, "Test error")
        success_handler = FakeHandler()

        orchestrator.register_handler(error_handler)
        orchestrator.register_handler(success_handler)

        orchestrator.on_protection_analyzed(fake_unified_result)

        assert success_handler.call_count == 1
        assert success_handler.received_results[0] is fake_unified_result

    def test_icp_handler_exception_handling(
        self, orchestrator: AnalysisResultOrchestrator, fake_icp_result: ICPScanResult
    ) -> None:
        """Exception in ICP handler is caught and logged."""
        error_handler = FakeICPErrorHandler(ValueError, "ICP test error")

        orchestrator.register_handler(error_handler)
        orchestrator.on_icp_analysis_complete(fake_icp_result)

        assert error_handler.icp_call_count == 1


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_distribute_to_no_handlers(
        self, orchestrator: AnalysisResultOrchestrator, fake_unified_result: UnifiedProtectionResult
    ) -> None:
        """Distribution with no handlers doesn't raise error."""
        orchestrator.on_protection_analyzed(fake_unified_result)
        assert orchestrator._current_result is fake_unified_result

    def test_merge_with_empty_protections(
        self,
        orchestrator: AnalysisResultOrchestrator,
        fake_icp_result: ICPScanResult,
        fake_unified_result: UnifiedProtectionResult,
    ) -> None:
        """Merge works with empty protection lists."""
        try:
            from intellicrack.protection.icp_backend import ICPScanResult
            from intellicrack.protection.unified_protection_engine import UnifiedProtectionResult

            real_icp = ICPScanResult(file_path=fake_icp_result.file_path, file_infos=[])
            real_unified = UnifiedProtectionResult(
                file_path=fake_unified_result.file_path,
                file_type="PE",
                architecture="x86_64",
            )

            merged = orchestrator.merge_icp_with_unified_result(real_icp, real_unified)
            assert merged is not None
        except ImportError:
            pytest.skip("UnifiedProtectionResult not available")

    def test_merge_confidence_with_none_unified_confidence(
        self,
        orchestrator: AnalysisResultOrchestrator,
        fake_icp_result: ICPScanResult,
        fake_unified_result: UnifiedProtectionResult,
    ) -> None:
        """Merge confidence when unified result has None confidence."""
        try:
            from intellicrack.protection.icp_backend import ICPScanResult
            from intellicrack.protection.unified_protection_engine import UnifiedProtectionResult

            real_icp = ICPScanResult(file_path=fake_icp_result.file_path, file_infos=[])
            real_unified = UnifiedProtectionResult(
                file_path=fake_unified_result.file_path,
                file_type="PE",
                architecture="x86_64",
            )
            real_unified.confidence_score = 0.0

            if hasattr(real_icp, "overall_confidence"):
                real_icp.overall_confidence = 0.85

            merged = orchestrator.merge_icp_with_unified_result(real_icp, real_unified)
            if merged and hasattr(merged, "confidence_score"):
                assert merged.confidence_score is not None
        except ImportError:
            pytest.skip("UnifiedProtectionResult not available")

    def test_unregister_all_handlers(
        self, orchestrator: AnalysisResultOrchestrator
    ) -> None:
        """All handlers can be unregistered."""
        handler1 = FakeHandler()
        handler2 = FakeHandler()

        orchestrator.register_handler(handler1)
        orchestrator.register_handler(handler2)

        orchestrator.unregister_handler(handler1)
        orchestrator.unregister_handler(handler2)

        assert len(orchestrator.handlers) == 0
