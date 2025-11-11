"""Intelligent strategy selection for certificate validation bypass operations.

CAPABILITIES:
- Automatic bypass method selection based on detection results
- Target state awareness (static binary vs running process)
- Risk-based strategy selection (low/medium/high risk)
- Multi-library handling (selects appropriate method for complexity)
- Packed binary detection and strategy adjustment
- Fallback strategy recommendation on failure
- Network-based licensing detection for MITM proxy selection
- Hybrid strategy selection for complex validation layers

LIMITATIONS:
- Strategy selection is heuristic-based (not ML-based)
- No learning from past bypass attempts
- Limited consideration of performance impact
- No cost-benefit analysis (time vs success rate)
- Cannot predict success rate accurately
- No user preference incorporation
- Static rule-based decision making

USAGE EXAMPLES:
    # Basic strategy selection
    from intellicrack.core.certificate.bypass_strategy import (
        BypassStrategySelector
    )
    from intellicrack.core.certificate.validation_detector import (
        CertificateValidationDetector
    )

    detector = CertificateValidationDetector()
    report = detector.detect_certificate_validation("target.exe")

    selector = BypassStrategySelector()
    method = selector.select_optimal_strategy(report, target_state="static")
    print(f"Recommended method: {method.value}")

    # For running process
    method = selector.select_optimal_strategy(report, target_state="running")
    # Will prefer FRIDA_HOOK for running targets

    # Risk assessment
    risk = selector.assess_patch_risk(report)
    print(f"Patch risk level: {risk}")
    # high/medium/low

    # Fallback on failure
    fallback = selector.get_fallback_strategy(BypassMethod.BINARY_PATCH)
    print(f"Fallback method: {fallback.value if fallback else 'None'}")
    # BINARY_PATCH → FRIDA_HOOK → MITM_PROXY → None

RELATED MODULES:
- detection_report.py: Provides input detection results
- bypass_orchestrator.py: Uses selected strategy for bypass execution
- cert_patcher.py: Used for BINARY_PATCH strategy
- frida_cert_hooks.py: Used for FRIDA_HOOK strategy

STRATEGY DECISION LOGIC:
    Static Target (binary not running):
        - Simple validation (1-2 functions, low risk) → BINARY_PATCH
        - Complex validation (3+ functions) → HYBRID
        - Packed binary detected → FRIDA_HOOK (avoid unpacking)
        - High risk (critical code) → FRIDA_HOOK (reversible)

    Running Target:
        - Any configuration → FRIDA_HOOK (runtime patching)
        - Network licensing detected → MITM_PROXY
        - Multiple validation layers → HYBRID

    Fallback Chain:
        BINARY_PATCH → FRIDA_HOOK → MITM_PROXY → NONE

RISK ASSESSMENT:
    High Risk:
        - Validation in tight loop
        - Validation with side effects
        - Multiple cross-references to validation
        - Validation in exception handler

    Medium Risk:
        - Validation with some side effects
        - Moderate cross-reference count
        - Validation near critical code

    Low Risk:
        - Standalone validation function
        - Single call site
        - Clear return value check
        - No side effects detected
"""

import logging
from typing import Optional

from intellicrack.core.certificate.detection_report import (
    BypassMethod,
    DetectionReport,
)

logger = logging.getLogger(__name__)


class BypassStrategySelector:
    """Selects optimal bypass strategy based on detection results and target state."""

    def select_optimal_strategy(
        self,
        detection_report: DetectionReport,
        target_state: str = "static",
    ) -> BypassMethod:
        """Select optimal bypass strategy for target.

        Args:
            detection_report: Certificate validation detection results
            target_state: Target state - "static" (not running) or "running"

        Returns:
            Recommended BypassMethod

        """
        if not detection_report.validation_functions:
            logger.info("No validation functions detected, no bypass needed")
            return BypassMethod.NONE

        num_functions = len(detection_report.validation_functions)
        num_libraries = len(detection_report.detected_libraries)
        risk_level = detection_report.risk_level

        logger.info(
            f"Selecting strategy: {num_functions} functions, "
            f"{num_libraries} libraries, {risk_level} risk, {target_state} state",
        )

        if target_state == "static":
            return self._select_static_strategy(
                detection_report, num_functions, num_libraries, risk_level,
            )
        else:
            return self._select_running_strategy(
                detection_report, num_functions, num_libraries,
            )

    def _select_static_strategy(
        self,
        detection_report: DetectionReport,
        num_functions: int,
        num_libraries: int,
        risk_level: str,
    ) -> BypassMethod:
        """Select strategy for static (non-running) target.

        Args:
            detection_report: Detection results
            num_functions: Number of validation functions
            num_libraries: Number of TLS libraries
            risk_level: Risk level from detection

        Returns:
            Recommended BypassMethod

        """
        if self._is_packed_binary(detection_report):
            logger.info("Packed binary detected, preferring Frida hook")
            return BypassMethod.FRIDA_HOOK

        if num_libraries >= 3:
            logger.info("Multiple TLS libraries detected, using hybrid approach")
            return BypassMethod.HYBRID

        if num_functions <= 3 and risk_level == "low":
            high_confidence = sum(
                1 for func in detection_report.validation_functions
                if func.confidence >= 0.8
            )
            if high_confidence == num_functions:
                logger.info("Simple validation with high confidence, using binary patch")
                return BypassMethod.BINARY_PATCH

        if num_functions > 5 or risk_level == "high":
            logger.info("Complex or high-risk validation, using hybrid approach")
            return BypassMethod.HYBRID

        logger.info("Default to binary patch for static target")
        return BypassMethod.BINARY_PATCH

    def _select_running_strategy(
        self,
        detection_report: DetectionReport,
        num_functions: int,
        num_libraries: int,
    ) -> BypassMethod:
        """Select strategy for running target.

        Args:
            detection_report: Detection results
            num_functions: Number of validation functions
            num_libraries: Number of TLS libraries

        Returns:
            Recommended BypassMethod

        """
        if num_libraries >= 3:
            logger.info("Multiple TLS libraries in running process, using hybrid")
            return BypassMethod.HYBRID

        if self._is_network_based_licensing(detection_report):
            logger.info("Network-based licensing detected, using MITM proxy")
            return BypassMethod.MITM_PROXY

        logger.info("Running process with standard validation, using Frida hook")
        return BypassMethod.FRIDA_HOOK

    def _is_packed_binary(self, detection_report: DetectionReport) -> bool:
        """Check if binary appears to be packed.

        Args:
            detection_report: Detection results

        Returns:
            True if binary appears packed

        """
        if hasattr(detection_report, 'is_packed'):
            return detection_report.is_packed

        low_confidence_count = sum(
            1 for func in detection_report.validation_functions
            if func.confidence < 0.5
        )

        return low_confidence_count > len(detection_report.validation_functions) * 0.5

    def _is_network_based_licensing(self, detection_report: DetectionReport) -> bool:
        """Check if licensing appears to be network-based.

        Args:
            detection_report: Detection results

        Returns:
            True if network-based licensing is likely

        """
        network_indicators = [
            "winhttp", "wininet", "curl", "https", "http",
            "activation", "online", "server",
        ]

        for func in detection_report.validation_functions:
            func_lower = func.api_name.lower()
            context_lower = func.context.lower() if func.context else ""

            if any(indicator in func_lower or indicator in context_lower
                   for indicator in network_indicators):
                return True

        return False

    def assess_patch_risk(self, detection_report: DetectionReport) -> str:
        """Assess risk level of patching detected validation functions.

        Args:
            detection_report: Detection results

        Returns:
            Risk level: "low", "medium", or "high"

        """
        if not detection_report.validation_functions:
            return "low"

        total_refs = sum(
            len(func.references) for func in detection_report.validation_functions
        )
        avg_refs = total_refs / len(detection_report.validation_functions)

        if avg_refs > 15:
            logger.debug("High risk: Many cross-references detected")
            return "high"
        elif avg_refs > 8:
            logger.debug("Medium risk: Moderate cross-references")
            return "medium"

        critical_keywords = ["critical", "security", "kernel", "system", "exception"]

        for func in detection_report.validation_functions:
            context_lower = func.context.lower() if func.context else ""
            if any(keyword in context_lower for keyword in critical_keywords):
                logger.debug(f"High risk: Critical keyword in {func.api_name}")
                return "high"

        if len(detection_report.validation_functions) > 10:
            logger.debug("High risk: Many validation functions")
            return "high"
        elif len(detection_report.validation_functions) > 5:
            logger.debug("Medium risk: Several validation functions")
            return "medium"

        logger.debug("Low risk: Simple validation structure")
        return "low"

    def get_fallback_strategy(
        self,
        failed_method: BypassMethod,
    ) -> Optional[BypassMethod]:
        """Get fallback strategy if primary method fails.

        Args:
            failed_method: The method that failed

        Returns:
            Alternative BypassMethod or None if no alternatives

        """
        fallback_chain = {
            BypassMethod.BINARY_PATCH: BypassMethod.FRIDA_HOOK,
            BypassMethod.FRIDA_HOOK: BypassMethod.MITM_PROXY,
            BypassMethod.HYBRID: BypassMethod.FRIDA_HOOK,
            BypassMethod.MITM_PROXY: None,
            BypassMethod.NONE: None,
        }

        fallback = fallback_chain.get(failed_method)

        if fallback:
            logger.info(f"Fallback from {failed_method.value} to {fallback.value}")
        else:
            logger.warning(f"No fallback available for {failed_method.value}")

        return fallback
