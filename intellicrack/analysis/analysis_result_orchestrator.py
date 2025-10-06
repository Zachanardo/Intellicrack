"""Analysis Result Orchestrator.

Coordinates the distribution of protection analysis results to various handlers
for LLM integration, script generation, and report generation.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
from typing import TYPE_CHECKING, Optional

from PyQt6.QtCore import QObject, pyqtSignal

if TYPE_CHECKING:
    from ..protection.icp_backend import ICPScanResult
    from ..protection.unified_protection_engine import UnifiedProtectionResult


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

    def get_logger(name: str) -> logging.Logger:
        """Create a logger instance for the given name."""
        return logging.getLogger(name)


logger = get_logger(__name__)


class AnalysisResultOrchestrator(QObject):
    """Central orchestrator that distributes analysis results to specialized handlers.

    This class follows the orchestrator pattern to maintain separation of concerns
    and keep the UI components decoupled from business logic.
    """

    # Signals for status updates
    #: Signal for handler status updates (type: handler_name: str, status_message: str)
    handler_status = pyqtSignal(str, str)

    def __init__(self, parent: Optional[QObject] = None) -> None:
        """Initialize the analysis result orchestrator.

        Args:
            parent: Optional parent widget for Qt integration.

        """
        super().__init__(parent)
        self.handlers = []
        self._current_result: Optional[UnifiedProtectionResult] = None

    def register_handler(self, handler: QObject):
        """Register a handler to receive analysis results.

        Args:
            handler: A QObject with an on_analysis_complete(result) slot

        """
        if hasattr(handler, "on_analysis_complete"):
            self.handlers.append(handler)
            logger.info(f"Registered handler: {handler.__class__.__name__}")
        else:
            logger.warning(f"Handler {handler.__class__.__name__} missing on_analysis_complete slot")

    def unregister_handler(self, handler: QObject):
        """Remove a handler from the registry.

        Args:
            handler: The QObject handler to remove from the registry

        """
        if handler in self.handlers:
            self.handlers.remove(handler)
            logger.info(f"Unregistered handler: {handler.__class__.__name__}")

    def on_protection_analyzed(self, result: UnifiedProtectionResult):
        """Main slot connected to UnifiedProtectionWidget.protection_analyzed signal.

        Distributes the result to all registered handlers.
        """
        self._current_result = result
        logger.info(f"Orchestrator received analysis result for: {result.file_path}")

        # Distribute to all handlers
        for handler in self.handlers:
            try:
                handler.on_analysis_complete(result)
                self.handler_status.emit(
                    handler.__class__.__name__,
                    "Processing complete",
                )
            except Exception as e:
                logger.error(f"Handler {handler.__class__.__name__} error: {e}")
                self.handler_status.emit(
                    handler.__class__.__name__,
                    f"Error: {e!s}",
                )

    def on_icp_analysis_complete(self, result: ICPScanResult):
        """Handle ICP analysis completion and distribute to relevant handlers.

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
                        "ICP processing complete",
                    )
                # Fallback to general analysis method if ICP result can be converted
                elif hasattr(handler, "on_analysis_complete") and hasattr(self, "_current_result") and self._current_result:
                    handler.on_analysis_complete(self._current_result)
                    self.handler_status.emit(
                        handler.__class__.__name__,
                        "Analysis processing complete",
                    )
            except Exception as e:
                logger.error(f"Handler {handler.__class__.__name__} ICP error: {e}")
                self.handler_status.emit(
                    handler.__class__.__name__,
                    f"ICP Error: {e!s}",
                )

    def get_current_result(self) -> Optional[UnifiedProtectionResult]:
        """Get the most recent analysis result."""
        return self._current_result

    def validate_icp_result(self, result: ICPScanResult) -> bool:
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

    def merge_icp_with_unified_result(
        self, icp_result: ICPScanResult, unified_result: Optional[UnifiedProtectionResult] = None
    ) -> Optional[UnifiedProtectionResult]:
        """Merge ICP scan results with unified protection result.

        Args:
            icp_result: ICPScanResult to merge
            unified_result: Existing UnifiedProtectionResult or None

        Returns:
            Updated UnifiedProtectionResult

        """
        unified_result = self._create_or_get_unified_result(icp_result, unified_result)
        if not unified_result:
            return None

        if hasattr(unified_result, "icp_analysis"):
            unified_result.icp_analysis = icp_result

        self._merge_protections_from_icp(icp_result, unified_result)
        self._merge_confidence_from_icp(icp_result, unified_result)

        logger.info(f"Merged ICPScanResult with UnifiedProtectionResult for {unified_result.file_path}")
        return unified_result

    def _create_or_get_unified_result(
        self, icp_result: ICPScanResult, unified_result: Optional[UnifiedProtectionResult]
    ) -> Optional[UnifiedProtectionResult]:
        """Create a new UnifiedProtectionResult if one is not provided."""
        if unified_result:
            return unified_result
        if UnifiedProtectionResult:
            new_result = UnifiedProtectionResult()
            new_result.file_path = getattr(icp_result, "file_path", None)
            new_result.analysis_timestamp = getattr(icp_result, "timestamp", None)
            return new_result
        logger.error("UnifiedProtectionResult not available")
        return None

    def _merge_protections_from_icp(self, icp_result: ICPScanResult, unified_result: UnifiedProtectionResult):
        """Merge protection data from ICP result into unified result."""
        if hasattr(icp_result, "protections") and hasattr(unified_result, "protections"):
            existing_types = {p.type for p in unified_result.protections if hasattr(p, "type")}
            for protection in icp_result.protections:
                if hasattr(protection, "type") and protection.type not in existing_types:
                    unified_result.protections.append(protection)
                    existing_types.add(protection.type)

    def _merge_confidence_from_icp(self, icp_result: ICPScanResult, unified_result: UnifiedProtectionResult):
        """Merge confidence score from ICP result into unified result."""
        if hasattr(icp_result, "overall_confidence") and hasattr(unified_result, "confidence"):
            if unified_result.confidence:
                unified_result.confidence = (unified_result.confidence + icp_result.overall_confidence) / 2
            else:
                unified_result.confidence = icp_result.overall_confidence

    def extract_icp_recommendations(self, result: ICPScanResult) -> list:
        """Extract bypass recommendations from ICP scan result.

        Args:
            result: ICPScanResult containing analysis data

        Returns:
            List of recommendation strings

        """
        if not ICPScanResult or not isinstance(result, ICPScanResult):
            return []

        recommendations = []
        if hasattr(result, "recommendations"):
            recommendations.extend(result.recommendations)

        recommendations.extend(self._get_bypass_recommendations_from_protections(result))
        recommendations.extend(self._get_tool_recommendations(result))

        return recommendations

    def _get_bypass_recommendations_from_protections(self, result: ICPScanResult) -> list[str]:
        """Generate bypass recommendations based on detected protections."""
        recommendations = []
        if hasattr(result, "protections"):
            for protection in result.protections:
                if hasattr(protection, "type") and hasattr(protection, "bypass_difficulty"):
                    if protection.bypass_difficulty == "low":
                        recommendations.append(
                            f"Protection '{protection.type}' has low bypass difficulty - standard techniques should work"
                        )
                    elif protection.bypass_difficulty == "high":
                        recommendations.append(f"Protection '{protection.type}' requires advanced bypass techniques")
        return recommendations

    def _get_tool_recommendations(self, result: ICPScanResult) -> list[str]:
        """Generate tool recommendations from the analysis result."""
        if hasattr(result, "suggested_tools"):
            return [f"Consider using {tool} for analysis" for tool in result.suggested_tools]
        return []
