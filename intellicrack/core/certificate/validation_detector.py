"""Main certificate validation detector module."""

import logging
from pathlib import Path
from typing import List

from intellicrack.core.certificate.api_signatures import (
    APISignature,
    get_library_type,
    get_signatures_by_library,
)
from intellicrack.core.certificate.binary_scanner import BinaryScanner
from intellicrack.core.certificate.detection_report import (
    BypassMethod,
    DetectionReport,
    ValidationFunction,
)

logger = logging.getLogger(__name__)


class CertificateValidationDetector:
    """Detects certificate validation functions in binaries.

    This class analyzes binaries to identify certificate validation APIs
    and provides recommendations for bypass strategies.
    """

    def __init__(self):
        """Initialize the certificate validation detector."""
        self.min_confidence = 0.3

    def detect_certificate_validation(self, binary_path: str) -> DetectionReport:
        """Detect certificate validation in a binary.

        This is the main entry point for detection. It performs a comprehensive
        analysis of the binary to identify all certificate validation functions.

        Args:
            binary_path: Path to the binary to analyze

        Returns:
            DetectionReport containing all detected validation functions

        Raises:
            FileNotFoundError: If binary doesn't exist
            RuntimeError: If binary cannot be parsed

        """
        logger.info(f"Starting certificate validation detection for: {binary_path}")

        binary_path_obj = Path(binary_path)
        if not binary_path_obj.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        try:
            with BinaryScanner(binary_path) as scanner:
                imports = scanner.scan_imports()
                logger.debug(f"Found {len(imports)} imports")

                tls_libraries = scanner.detect_tls_libraries(imports)
                logger.info(f"Detected TLS libraries: {tls_libraries}")

                validation_functions = self._find_validation_functions(
                    scanner, tls_libraries
                )
                logger.info(f"Found {len(validation_functions)} validation functions")

                filtered_functions = self._filter_low_confidence(validation_functions)
                logger.info(f"After filtering: {len(filtered_functions)} functions")

                recommended_method = self._recommend_bypass_method(
                    filtered_functions, tls_libraries
                )
                logger.debug(f"Recommended bypass method: {recommended_method.value}")

                risk_level = self._assess_risk_level(filtered_functions)
                logger.debug(f"Assessed risk level: {risk_level}")

                report = DetectionReport(
                    binary_path=str(binary_path_obj),
                    detected_libraries=tls_libraries,
                    validation_functions=filtered_functions,
                    recommended_method=recommended_method,
                    risk_level=risk_level,
                )

                logger.info("Detection complete")
                return report

        except Exception as e:
            logger.error(f"Detection failed: {e}")
            raise RuntimeError(f"Failed to detect certificate validation: {e}")

    def _find_validation_functions(
        self,
        scanner: BinaryScanner,
        tls_libraries: List[str]
    ) -> List[ValidationFunction]:
        """Find all certificate validation functions in the binary.

        Args:
            scanner: BinaryScanner instance
            tls_libraries: List of detected TLS libraries

        Returns:
            List of ValidationFunction objects

        """
        validation_functions = []

        for library in tls_libraries:
            signatures = get_signatures_by_library(library)

            for signature in signatures:
                addresses = scanner.find_api_calls(signature.name)

                for address in addresses:
                    context = scanner.analyze_call_context(address)
                    confidence = scanner.calculate_confidence(context)

                    is_licensing = self._analyze_licensing_context(context)
                    if is_licensing:
                        confidence = min(confidence + 0.2, 1.0)

                    validation_func = ValidationFunction(
                        address=address,
                        api_name=signature.name,
                        library=library,
                        confidence=confidence,
                        context=context.surrounding_code[:500],
                        references=context.cross_references[:10],
                    )
                    validation_functions.append(validation_func)

        for func in validation_functions:
            logger.debug(f"Found: {func}")

        return validation_functions

    def _filter_low_confidence(
        self,
        validation_functions: List[ValidationFunction]
    ) -> List[ValidationFunction]:
        """Filter out low-confidence detections.

        Args:
            validation_functions: List of all detected functions

        Returns:
            List of functions with confidence >= min_confidence

        """
        return [
            func for func in validation_functions
            if func.confidence >= self.min_confidence
        ]

    def _analyze_licensing_context(self, context) -> bool:
        """Determine if an API call is in a licensing-related context.

        Args:
            context: ContextInfo object

        Returns:
            True if the context suggests licensing validation

        """
        licensing_keywords = [
            "license", "licensing", "activation", "activate", "register",
            "registration", "serial", "key", "trial", "validate", "verification"
        ]

        if context.function_name:
            func_lower = context.function_name.lower()
            if any(kw in func_lower for kw in licensing_keywords):
                return True

        if context.surrounding_code:
            code_lower = context.surrounding_code.lower()
            keyword_count = sum(
                1 for kw in licensing_keywords if kw in code_lower
            )
            if keyword_count >= 2:
                return True

        return False

    def _assess_patch_safety(self, address: int, context) -> str:
        """Assess the risk level of patching at a specific address.

        Args:
            address: Address of the function to patch
            context: Context information

        Returns:
            Risk level string: "low", "medium", or "high"

        """
        risk_indicators = {
            "high": ["__security", "critical", "kernel", "system"],
            "medium": ["loop", "exception", "handler", "callback"],
        }

        code_lower = context.surrounding_code.lower() if context.surrounding_code else ""

        for indicator in risk_indicators["high"]:
            if indicator in code_lower:
                return "high"

        for indicator in risk_indicators["medium"]:
            if indicator in code_lower:
                return "medium"

        if len(context.cross_references) > 10:
            return "medium"

        return "low"

    def _recommend_bypass_method(
        self,
        validation_functions: List[ValidationFunction],
        tls_libraries: List[str]
    ) -> BypassMethod:
        """Recommend the best bypass method based on detection results.

        Args:
            validation_functions: List of detected validation functions
            tls_libraries: List of detected TLS libraries

        Returns:
            Recommended BypassMethod

        """
        if not validation_functions:
            return BypassMethod.NONE

        high_confidence_count = sum(
            1 for func in validation_functions if func.confidence >= 0.7
        )

        library_types = set(
            get_library_type(lib) for lib in tls_libraries
            if get_library_type(lib)
        )

        if len(library_types) >= 3:
            return BypassMethod.HYBRID

        if "openssl" in library_types or "nss" in library_types:
            return BypassMethod.FRIDA_HOOK

        if high_confidence_count <= 3 and len(validation_functions) <= 5:
            if all(func.confidence >= 0.8 for func in validation_functions):
                return BypassMethod.BINARY_PATCH

        if "winhttp" in library_types or "schannel" in library_types:
            if high_confidence_count <= 2:
                return BypassMethod.BINARY_PATCH
            else:
                return BypassMethod.FRIDA_HOOK

        return BypassMethod.HYBRID

    def _assess_risk_level(self, validation_functions: List[ValidationFunction]) -> str:
        """Assess overall risk level of bypassing certificate validation.

        Args:
            validation_functions: List of detected validation functions

        Returns:
            Risk level: "low", "medium", or "high"

        """
        if not validation_functions:
            return "low"

        total_refs = sum(len(func.references) for func in validation_functions)
        avg_refs = total_refs / len(validation_functions) if validation_functions else 0

        if avg_refs > 10:
            return "high"
        elif avg_refs > 5:
            return "medium"

        if len(validation_functions) > 10:
            return "high"
        elif len(validation_functions) > 5:
            return "medium"

        high_confidence_count = sum(
            1 for func in validation_functions if func.confidence >= 0.8
        )

        if high_confidence_count >= len(validation_functions) * 0.8:
            return "low"

        return "medium"

    def detect_with_custom_signatures(
        self,
        binary_path: str,
        custom_signatures: List[APISignature]
    ) -> DetectionReport:
        """Detect validation functions using custom API signatures.

        Args:
            binary_path: Path to binary
            custom_signatures: List of custom API signatures to search for

        Returns:
            DetectionReport with custom signature detection results

        """
        logger.info(f"Detection with {len(custom_signatures)} custom signatures")

        report = self.detect_certificate_validation(binary_path)

        with BinaryScanner(binary_path) as scanner:
            for signature in custom_signatures:
                addresses = scanner.find_api_calls(signature.name)

                for address in addresses:
                    context = scanner.analyze_call_context(address)
                    confidence = scanner.calculate_confidence(context)

                    validation_func = ValidationFunction(
                        address=address,
                        api_name=signature.name,
                        library=signature.library,
                        confidence=confidence,
                        context=context.surrounding_code[:500],
                        references=context.cross_references[:10],
                    )

                    if validation_func.confidence >= self.min_confidence:
                        report.validation_functions.append(validation_func)

        return report
