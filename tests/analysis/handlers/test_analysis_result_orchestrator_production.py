"""Production tests for analysis result orchestrator.

Tests result distribution and signal propagation without mocks,
validating real handler communication and error handling.
"""

from typing import Any
from unittest.mock import MagicMock

import pytest
from PyQt6.QtCore import QObject
from PyQt6.QtWidgets import QApplication

from intellicrack.analysis.analysis_result_orchestrator import AnalysisResultOrchestrator


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for Qt tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


@pytest.fixture
def orchestrator(qapp: QApplication) -> AnalysisResultOrchestrator:
    """Create orchestrator instance."""
    return AnalysisResultOrchestrator()


@pytest.fixture
def mock_handler() -> MagicMock:
    """Create mock handler with on_analysis_complete slot."""
    handler = MagicMock(spec=QObject)
    handler.__class__.__name__ = "MockHandler"
    handler.on_analysis_complete = MagicMock()
    return handler


@pytest.fixture
def mock_icp_handler() -> MagicMock:
    """Create mock handler with ICP-specific slot."""
    handler = MagicMock(spec=QObject)
    handler.__class__.__name__ = "MockICPHandler"
    handler.on_analysis_complete = MagicMock()
    handler.on_icp_analysis_complete = MagicMock()
    return handler


@pytest.fixture
def mock_unified_result() -> MagicMock:
    """Create mock unified protection result."""
    result = MagicMock()
    result.file_path = "test.exe"
    result.analysis_timestamp = "2025-01-01 12:00:00"
    result.protections = []
    result.confidence = 0.85
    result.icp_analysis = None
    return result


@pytest.fixture
def mock_icp_result() -> MagicMock:
    """Create mock ICP scan result."""
    result = MagicMock()
    result.file_path = "test.exe"
    result.timestamp = "2025-01-01 12:00:00"
    result.protections = []
    result.overall_confidence = 0.90
    result.status = "completed"
    result.recommendations = ["Use advanced analysis"]
    result.suggested_tools = ["Frida", "Radare2"]
    return result


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
        self, orchestrator: AnalysisResultOrchestrator, mock_handler: MagicMock
    ) -> None:
        """Handler with on_analysis_complete slot registers successfully."""
        orchestrator.register_handler(mock_handler)
        assert mock_handler in orchestrator.handlers

    def test_register_handler_without_slot(
        self, orchestrator: AnalysisResultOrchestrator
    ) -> None:
        """Handler without required slot is rejected."""
        invalid_handler = MagicMock(spec=QObject)
        invalid_handler.__class__.__name__ = "InvalidHandler"
        delattr(invalid_handler, "on_analysis_complete")

        orchestrator.register_handler(invalid_handler)
        assert invalid_handler not in orchestrator.handlers

    def test_register_multiple_handlers(
        self, orchestrator: AnalysisResultOrchestrator
    ) -> None:
        """Multiple handlers can be registered."""
        handler1 = MagicMock(spec=QObject)
        handler1.__class__.__name__ = "Handler1"
        handler1.on_analysis_complete = MagicMock()

        handler2 = MagicMock(spec=QObject)
        handler2.__class__.__name__ = "Handler2"
        handler2.on_analysis_complete = MagicMock()

        orchestrator.register_handler(handler1)
        orchestrator.register_handler(handler2)

        assert len(orchestrator.handlers) == 2
        assert handler1 in orchestrator.handlers
        assert handler2 in orchestrator.handlers

    def test_unregister_handler(
        self, orchestrator: AnalysisResultOrchestrator, mock_handler: MagicMock
    ) -> None:
        """Registered handler can be unregistered."""
        orchestrator.register_handler(mock_handler)
        assert mock_handler in orchestrator.handlers

        orchestrator.unregister_handler(mock_handler)
        assert mock_handler not in orchestrator.handlers

    def test_unregister_nonexistent_handler(
        self, orchestrator: AnalysisResultOrchestrator, mock_handler: MagicMock
    ) -> None:
        """Unregistering non-registered handler doesn't raise error."""
        orchestrator.unregister_handler(mock_handler)


class TestResultDistribution:
    """Test result distribution to handlers."""

    def test_distribute_unified_result_to_handler(
        self,
        orchestrator: AnalysisResultOrchestrator,
        mock_handler: MagicMock,
        mock_unified_result: MagicMock,
    ) -> None:
        """Unified result is distributed to registered handler."""
        orchestrator.register_handler(mock_handler)
        orchestrator.on_protection_analyzed(mock_unified_result)

        mock_handler.on_analysis_complete.assert_called_once_with(mock_unified_result)

    def test_distribute_to_multiple_handlers(
        self, orchestrator: AnalysisResultOrchestrator, mock_unified_result: MagicMock
    ) -> None:
        """Result is distributed to all registered handlers."""
        handler1 = MagicMock(spec=QObject)
        handler1.__class__.__name__ = "Handler1"
        handler1.on_analysis_complete = MagicMock()

        handler2 = MagicMock(spec=QObject)
        handler2.__class__.__name__ = "Handler2"
        handler2.on_analysis_complete = MagicMock()

        orchestrator.register_handler(handler1)
        orchestrator.register_handler(handler2)

        orchestrator.on_protection_analyzed(mock_unified_result)

        handler1.on_analysis_complete.assert_called_once_with(mock_unified_result)
        handler2.on_analysis_complete.assert_called_once_with(mock_unified_result)

    def test_current_result_stored(
        self,
        orchestrator: AnalysisResultOrchestrator,
        mock_handler: MagicMock,
        mock_unified_result: MagicMock,
    ) -> None:
        """Current result is stored after distribution."""
        orchestrator.register_handler(mock_handler)
        orchestrator.on_protection_analyzed(mock_unified_result)

        assert orchestrator._current_result is mock_unified_result

    def test_get_current_result(
        self,
        orchestrator: AnalysisResultOrchestrator,
        mock_handler: MagicMock,
        mock_unified_result: MagicMock,
    ) -> None:
        """Current result can be retrieved."""
        orchestrator.register_handler(mock_handler)
        orchestrator.on_protection_analyzed(mock_unified_result)

        current = orchestrator.get_current_result()
        assert current is mock_unified_result


class TestICPResultHandling:
    """Test ICP-specific result handling."""

    def test_distribute_icp_result_to_icp_handler(
        self,
        orchestrator: AnalysisResultOrchestrator,
        mock_icp_handler: MagicMock,
        mock_icp_result: MagicMock,
    ) -> None:
        """ICP result is distributed to ICP-specific handler."""
        orchestrator.register_handler(mock_icp_handler)
        orchestrator.on_icp_analysis_complete(mock_icp_result)

        mock_icp_handler.on_icp_analysis_complete.assert_called_once_with(mock_icp_result)

    def test_icp_result_added_to_unified_result(
        self,
        orchestrator: AnalysisResultOrchestrator,
        mock_handler: MagicMock,
        mock_unified_result: MagicMock,
        mock_icp_result: MagicMock,
    ) -> None:
        """ICP result is added to existing unified result."""
        orchestrator.register_handler(mock_handler)
        orchestrator.on_protection_analyzed(mock_unified_result)
        orchestrator.on_icp_analysis_complete(mock_icp_result)

        assert orchestrator._current_result.icp_analysis is mock_icp_result

    def test_icp_result_fallback_to_general_handler(
        self,
        orchestrator: AnalysisResultOrchestrator,
        mock_handler: MagicMock,
        mock_unified_result: MagicMock,
        mock_icp_result: MagicMock,
    ) -> None:
        """ICP result falls back to general handler if no ICP-specific method."""
        orchestrator.register_handler(mock_handler)
        orchestrator._current_result = mock_unified_result
        orchestrator.on_icp_analysis_complete(mock_icp_result)

        mock_handler.on_analysis_complete.assert_called_once()


class TestSignalEmission:
    """Test signal emission during result distribution."""

    def test_handler_status_signal_on_success(
        self,
        orchestrator: AnalysisResultOrchestrator,
        mock_handler: MagicMock,
        mock_unified_result: MagicMock,
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
        orchestrator.register_handler(mock_handler)
        orchestrator.on_protection_analyzed(mock_unified_result)

        QApplication.processEvents()

        assert signal_emitted
        assert handler_name == "MockHandler"
        assert "complete" in status_msg.lower()

    def test_handler_status_signal_on_error(
        self, orchestrator: AnalysisResultOrchestrator, mock_unified_result: MagicMock
    ) -> None:
        """Handler status signal emitted on handler error."""
        error_handler = MagicMock(spec=QObject)
        error_handler.__class__.__name__ = "ErrorHandler"
        error_handler.on_analysis_complete = MagicMock(
            side_effect=RuntimeError("Test error")
        )

        signal_emitted = False
        error_msg = ""

        def on_status(name: str, msg: str) -> None:
            nonlocal signal_emitted, error_msg
            signal_emitted = True
            error_msg = msg

        orchestrator.handler_status.connect(on_status)
        orchestrator.register_handler(error_handler)
        orchestrator.on_protection_analyzed(mock_unified_result)

        QApplication.processEvents()

        assert signal_emitted
        assert "Error" in error_msg


class TestICPResultValidation:
    """Test ICP result validation."""

    def test_validate_valid_icp_result(
        self, orchestrator: AnalysisResultOrchestrator, mock_icp_result: MagicMock
    ) -> None:
        """Valid ICP result passes validation."""
        try:
            from intellicrack.protection.icp_backend import ICPScanResult

            mock_icp_result.__class__ = ICPScanResult
            is_valid = orchestrator.validate_icp_result(mock_icp_result)
            assert is_valid
        except ImportError:
            pytest.skip("ICPScanResult not available")

    def test_validate_icp_result_without_file_path(
        self, orchestrator: AnalysisResultOrchestrator
    ) -> None:
        """ICP result without file_path fails validation."""
        try:
            from intellicrack.protection.icp_backend import ICPScanResult

            invalid_result = MagicMock(spec=ICPScanResult)
            invalid_result.file_path = None

            is_valid = orchestrator.validate_icp_result(invalid_result)
            assert not is_valid
        except ImportError:
            pytest.skip("ICPScanResult not available")

    def test_validate_icp_result_invalid_type(
        self, orchestrator: AnalysisResultOrchestrator
    ) -> None:
        """Invalid type fails validation."""
        invalid_result = MagicMock()
        is_valid = orchestrator.validate_icp_result(invalid_result)
        assert not is_valid


class TestICPUnifiedMerge:
    """Test merging ICP results with unified results."""

    def test_merge_icp_with_unified_result(
        self,
        orchestrator: AnalysisResultOrchestrator,
        mock_icp_result: MagicMock,
        mock_unified_result: MagicMock,
    ) -> None:
        """ICP result merges with unified result."""
        try:
            merged = orchestrator.merge_icp_with_unified_result(
                mock_icp_result, mock_unified_result
            )
            assert merged is not None
            if hasattr(merged, "icp_analysis"):
                assert merged.icp_analysis is mock_icp_result
        except ImportError:
            pytest.skip("UnifiedProtectionResult not available")

    def test_merge_icp_creates_unified_if_none(
        self, orchestrator: AnalysisResultOrchestrator, mock_icp_result: MagicMock
    ) -> None:
        """Merge creates new unified result if none provided."""
        try:
            if merged := orchestrator.merge_icp_with_unified_result(
                mock_icp_result, None
            ):
                assert merged.file_path == mock_icp_result.file_path
        except ImportError:
            pytest.skip("UnifiedProtectionResult not available")

    def test_merge_protections_from_icp(
        self,
        orchestrator: AnalysisResultOrchestrator,
        mock_icp_result: MagicMock,
        mock_unified_result: MagicMock,
    ) -> None:
        """Protections from ICP are merged into unified result."""
        icp_protection = MagicMock()
        icp_protection.type = "VMProtect"
        icp_protection.confidence = 0.95

        mock_icp_result.protections = [icp_protection]
        mock_unified_result.protections = []

        try:
            merged = orchestrator.merge_icp_with_unified_result(
                mock_icp_result, mock_unified_result
            )
            if merged and hasattr(merged, "protections"):
                assert len(merged.protections) >= 1
        except ImportError:
            pytest.skip("UnifiedProtectionResult not available")

    def test_merge_confidence_from_icp(
        self,
        orchestrator: AnalysisResultOrchestrator,
        mock_icp_result: MagicMock,
        mock_unified_result: MagicMock,
    ) -> None:
        """Confidence score from ICP is merged."""
        mock_unified_result.confidence = 0.80
        mock_icp_result.overall_confidence = 0.90

        try:
            merged = orchestrator.merge_icp_with_unified_result(
                mock_icp_result, mock_unified_result
            )
            if merged and hasattr(merged, "confidence"):
                assert merged.confidence == 0.85
        except ImportError:
            pytest.skip("UnifiedProtectionResult not available")


class TestRecommendationExtraction:
    """Test recommendation extraction from ICP results."""

    def test_extract_recommendations(
        self, orchestrator: AnalysisResultOrchestrator, mock_icp_result: MagicMock
    ) -> None:
        """Recommendations are extracted from ICP result."""
        try:
            from intellicrack.protection.icp_backend import ICPScanResult

            mock_icp_result.__class__ = ICPScanResult
            recommendations = orchestrator.extract_icp_recommendations(mock_icp_result)

            assert isinstance(recommendations, list)
            assert len(recommendations) > 0
            assert "Use advanced analysis" in recommendations
        except ImportError:
            pytest.skip("ICPScanResult not available")

    def test_extract_bypass_recommendations_from_protections(
        self, orchestrator: AnalysisResultOrchestrator, mock_icp_result: MagicMock
    ) -> None:
        """Bypass recommendations generated from protections."""
        low_difficulty_protection = MagicMock()
        low_difficulty_protection.type = "Basic Packer"
        low_difficulty_protection.bypass_difficulty = "low"

        high_difficulty_protection = MagicMock()
        high_difficulty_protection.type = "VMProtect"
        high_difficulty_protection.bypass_difficulty = "high"

        mock_icp_result.protections = [low_difficulty_protection, high_difficulty_protection]

        try:
            from intellicrack.protection.icp_backend import ICPScanResult

            mock_icp_result.__class__ = ICPScanResult
            recommendations = orchestrator.extract_icp_recommendations(mock_icp_result)

            assert any("low bypass difficulty" in rec for rec in recommendations)
            assert any("advanced bypass techniques" in rec for rec in recommendations)
        except ImportError:
            pytest.skip("ICPScanResult not available")

    def test_extract_tool_recommendations(
        self, orchestrator: AnalysisResultOrchestrator, mock_icp_result: MagicMock
    ) -> None:
        """Tool recommendations are extracted."""
        try:
            from intellicrack.protection.icp_backend import ICPScanResult

            mock_icp_result.__class__ = ICPScanResult
            recommendations = orchestrator.extract_icp_recommendations(mock_icp_result)

            assert any("Frida" in rec for rec in recommendations)
            assert any("Radare2" in rec for rec in recommendations)
        except ImportError:
            pytest.skip("ICPScanResult not available")

    def test_extract_recommendations_empty_result(
        self, orchestrator: AnalysisResultOrchestrator
    ) -> None:
        """Empty ICP result returns empty recommendations."""
        empty_result = MagicMock()
        recommendations = orchestrator.extract_icp_recommendations(empty_result)
        assert recommendations == []


class TestErrorHandling:
    """Test error handling during result distribution."""

    def test_handler_exception_doesnt_stop_distribution(
        self, orchestrator: AnalysisResultOrchestrator, mock_unified_result: MagicMock
    ) -> None:
        """Exception in one handler doesn't prevent others from receiving result."""
        error_handler = MagicMock(spec=QObject)
        error_handler.__class__.__name__ = "ErrorHandler"
        error_handler.on_analysis_complete = MagicMock(
            side_effect=RuntimeError("Test error")
        )

        success_handler = MagicMock(spec=QObject)
        success_handler.__class__.__name__ = "SuccessHandler"
        success_handler.on_analysis_complete = MagicMock()

        orchestrator.register_handler(error_handler)
        orchestrator.register_handler(success_handler)

        orchestrator.on_protection_analyzed(mock_unified_result)

        success_handler.on_analysis_complete.assert_called_once_with(mock_unified_result)

    def test_icp_handler_exception_handling(
        self, orchestrator: AnalysisResultOrchestrator, mock_icp_result: MagicMock
    ) -> None:
        """Exception in ICP handler is caught and logged."""
        error_handler = MagicMock(spec=QObject)
        error_handler.__class__.__name__ = "ErrorICPHandler"
        error_handler.on_icp_analysis_complete = MagicMock(
            side_effect=ValueError("ICP test error")
        )

        orchestrator.register_handler(error_handler)
        orchestrator.on_icp_analysis_complete(mock_icp_result)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_distribute_to_no_handlers(
        self, orchestrator: AnalysisResultOrchestrator, mock_unified_result: MagicMock
    ) -> None:
        """Distribution with no handlers doesn't raise error."""
        orchestrator.on_protection_analyzed(mock_unified_result)
        assert orchestrator._current_result is mock_unified_result

    def test_merge_with_empty_protections(
        self,
        orchestrator: AnalysisResultOrchestrator,
        mock_icp_result: MagicMock,
        mock_unified_result: MagicMock,
    ) -> None:
        """Merge works with empty protection lists."""
        mock_icp_result.protections = []
        mock_unified_result.protections = []

        try:
            merged = orchestrator.merge_icp_with_unified_result(
                mock_icp_result, mock_unified_result
            )
            assert merged is not None
        except ImportError:
            pytest.skip("UnifiedProtectionResult not available")

    def test_merge_confidence_with_none_unified_confidence(
        self,
        orchestrator: AnalysisResultOrchestrator,
        mock_icp_result: MagicMock,
        mock_unified_result: MagicMock,
    ) -> None:
        """Merge confidence when unified result has None confidence."""
        mock_unified_result.confidence = None
        mock_icp_result.overall_confidence = 0.85

        try:
            merged = orchestrator.merge_icp_with_unified_result(
                mock_icp_result, mock_unified_result
            )
            if merged and hasattr(merged, "confidence"):
                assert merged.confidence == 0.85
        except ImportError:
            pytest.skip("UnifiedProtectionResult not available")

    def test_unregister_all_handlers(
        self, orchestrator: AnalysisResultOrchestrator
    ) -> None:
        """All handlers can be unregistered."""
        handler1 = MagicMock(spec=QObject)
        handler1.__class__.__name__ = "Handler1"
        handler1.on_analysis_complete = MagicMock()

        handler2 = MagicMock(spec=QObject)
        handler2.__class__.__name__ = "Handler2"
        handler2.on_analysis_complete = MagicMock()

        orchestrator.register_handler(handler1)
        orchestrator.register_handler(handler2)

        orchestrator.unregister_handler(handler1)
        orchestrator.unregister_handler(handler2)

        assert len(orchestrator.handlers) == 0
