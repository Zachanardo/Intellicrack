"""
Analysis Result Orchestrator

Coordinates the distribution of protection analysis results to various handlers
for LLM integration, script generation, and report generation.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Optional

from PyQt6.QtCore import QObject, pyqtSignal

try:
    from ..protection.unified_protection_engine import UnifiedProtectionResult
except ImportError:
    UnifiedProtectionResult = None

try:
    from ..protection.icp_backend import ICPScanResult
except ImportError:
    ICPScanResult = None

try:
    from ..utils.logger import get_logger
except ImportError:
    import logging

    def get_logger(name):
        """Create a logger instance for the given name."""
        return logging.getLogger(name)

logger = get_logger(__name__)


class AnalysisResultOrchestrator(QObject):
    """
    Central orchestrator that distributes analysis results to specialized handlers.

    This class follows the orchestrator pattern to maintain separation of concerns
    and keep the UI components decoupled from business logic.
    """

    # Signals for status updates
    handler_status = pyqtSignal(str, str)  # handler_name, status_message

    def __init__(self, parent=None):
        """Initialize the analysis result orchestrator.

        Args:
            parent: Optional parent widget for Qt integration.
        """
        super().__init__(parent)
        self.handlers = []
        self._current_result: Optional[UnifiedProtectionResult] = None

    def register_handler(self, handler: QObject):
        """
        Register a handler to receive analysis results.

        Args:
            handler: A QObject with an on_analysis_complete(result) slot
        """
        if hasattr(handler, "on_analysis_complete"):
            self.handlers.append(handler)
            logger.info(f"Registered handler: {handler.__class__.__name__}")
        else:
            logger.warning(
                f"Handler {handler.__class__.__name__} missing on_analysis_complete slot")

    def unregister_handler(self, handler: QObject):
        """Remove a handler from the registry.

        Args:
            handler: The QObject handler to remove from the registry
        """
        if handler in self.handlers:
            self.handlers.remove(handler)
            logger.info(f"Unregistered handler: {handler.__class__.__name__}")

    def on_protection_analyzed(self, result: UnifiedProtectionResult):
        """
        Main slot connected to UnifiedProtectionWidget.protection_analyzed signal.

        Distributes the result to all registered handlers.
        """
        self._current_result = result
        logger.info(
            f"Orchestrator received analysis result for: {result.file_path}")

        # Distribute to all handlers
        for handler in self.handlers:
            try:
                handler.on_analysis_complete(result)
                self.handler_status.emit(
                    handler.__class__.__name__,
                    "Processing complete"
                )
            except Exception as e:
                logger.error(
                    f"Handler {handler.__class__.__name__} error: {e}")
                self.handler_status.emit(
                    handler.__class__.__name__,
                    f"Error: {str(e)}"
                )

    def on_icp_analysis_complete(self, result: "ICPScanResult"):
        """
        Handle ICP analysis completion and distribute to relevant handlers.

        Args:
            result: ICPScanResult object from ICP analysis
        """
        logger.info(f"Orchestrator received ICP analysis result for: {result.file_path}")

        # Store ICP result for handlers that need it
        if hasattr(self, "_current_result") and self._current_result:
            # Add ICP data to existing result
            self._current_result.icp_analysis = result

        # Distribute to handlers that support ICP analysis
        for handler in self.handlers:
            try:
                # Check if handler has ICP-specific method
                if hasattr(handler, "on_icp_analysis_complete"):
                    handler.on_icp_analysis_complete(result)
                    self.handler_status.emit(
                        handler.__class__.__name__,
                        "ICP processing complete"
                    )
                # Fallback to general analysis method if ICP result can be converted
                elif hasattr(handler, "on_analysis_complete") and hasattr(self, "_current_result") and self._current_result:
                    handler.on_analysis_complete(self._current_result)
                    self.handler_status.emit(
                        handler.__class__.__name__,
                        "Analysis processing complete"
                    )
            except Exception as e:
                logger.error(f"Handler {handler.__class__.__name__} ICP error: {e}")
                self.handler_status.emit(
                    handler.__class__.__name__,
                    f"ICP Error: {str(e)}"
                )

    def get_current_result(self) -> Optional[UnifiedProtectionResult]:
        """Get the most recent analysis result"""
        return self._current_result

    def validate_icp_result(self, result: "ICPScanResult") -> bool:
        """Validate an ICP scan result for consistency and completeness.

        Args:
            result: ICPScanResult to validate

        Returns:
            True if valid, False otherwise
        """
        if not ICPScanResult:
            logger.warning("ICPScanResult class not available for validation")
            return False

        if not isinstance(result, ICPScanResult):
            logger.error(f"Invalid result type: expected ICPScanResult, got {type(result)}")
            return False

        # Validate required fields
        if not hasattr(result, "file_path") or not result.file_path:
            logger.error("ICPScanResult missing required file_path")
            return False

        # Validate protection data if present
        if hasattr(result, "protections") and result.protections:
            for protection in result.protections:
                if not hasattr(protection, "type") or not hasattr(protection, "confidence"):
                    logger.warning(f"Incomplete protection data in ICPScanResult: {protection}")

        # Check for analysis status
        if hasattr(result, "status"):
            if result.status not in ["completed", "partial", "failed", "in_progress"]:
                logger.warning(f"Unexpected ICPScanResult status: {result.status}")

        logger.info(f"ICPScanResult validation passed for {result.file_path}")
        return True

    def merge_icp_with_unified_result(self, icp_result: "ICPScanResult", unified_result: Optional[UnifiedProtectionResult] = None) -> UnifiedProtectionResult:
        """Merge ICP scan results with unified protection result.

        Args:
            icp_result: ICPScanResult to merge
            unified_result: Existing UnifiedProtectionResult or None

        Returns:
            Updated UnifiedProtectionResult
        """
        if unified_result is None:
            if UnifiedProtectionResult:
                # Create new unified result from ICP data
                unified_result = UnifiedProtectionResult()
                unified_result.file_path = icp_result.file_path if hasattr(icp_result, "file_path") else None
                unified_result.analysis_timestamp = getattr(icp_result, "timestamp", None)
            else:
                logger.error("UnifiedProtectionResult not available")
                return None

        # Merge ICP data into unified result
        if hasattr(unified_result, "icp_analysis"):
            unified_result.icp_analysis = icp_result

        # Extract and merge protection data
        if hasattr(icp_result, "protections") and hasattr(unified_result, "protections"):
            # Merge protection lists, avoiding duplicates
            existing_types = {p.type for p in unified_result.protections if hasattr(p, "type")}

            for protection in icp_result.protections:
                if hasattr(protection, "type") and protection.type not in existing_types:
                    unified_result.protections.append(protection)
                    existing_types.add(protection.type)

        # Update confidence scores
        if hasattr(icp_result, "overall_confidence") and hasattr(unified_result, "confidence"):
            # Average the confidence scores
            if unified_result.confidence:
                unified_result.confidence = (unified_result.confidence + icp_result.overall_confidence) / 2
            else:
                unified_result.confidence = icp_result.overall_confidence

        logger.info(f"Merged ICPScanResult with UnifiedProtectionResult for {unified_result.file_path}")
        return unified_result

    def extract_icp_recommendations(self, result: "ICPScanResult") -> list:
        """Extract bypass recommendations from ICP scan result.

        Args:
            result: ICPScanResult containing analysis data

        Returns:
            List of recommendation strings
        """
        recommendations = []

        if not ICPScanResult or not isinstance(result, ICPScanResult):
            return recommendations

        # Extract direct recommendations
        if hasattr(result, "recommendations"):
            recommendations.extend(result.recommendations)

        # Generate recommendations based on protections found
        if hasattr(result, "protections"):
            for protection in result.protections:
                if hasattr(protection, "type") and hasattr(protection, "bypass_difficulty"):
                    if protection.bypass_difficulty == "low":
                        recommendations.append(f"Protection '{protection.type}' has low bypass difficulty - standard techniques should work")
                    elif protection.bypass_difficulty == "high":
                        recommendations.append(f"Protection '{protection.type}' requires advanced bypass techniques")

        # Add tool-specific recommendations
        if hasattr(result, "suggested_tools"):
            for tool in result.suggested_tools:
                recommendations.append(f"Consider using {tool} for analysis")

        return recommendations
