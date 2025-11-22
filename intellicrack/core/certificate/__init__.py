"""Certificate validation bypass and detection module.

This module provides comprehensive capabilities for detecting and bypassing
certificate validation in software licensing protection mechanisms.
"""

from intellicrack.core.certificate.api_signatures import APISignature, get_all_signatures, get_signature_by_name, get_signatures_by_library
from intellicrack.core.certificate.detection_report import DetectionReport, ValidationFunction
from intellicrack.core.certificate.validation_detector import CertificateValidationDetector


__all__ = [
    "APISignature",
    "CertificateValidationDetector",
    "DetectionReport",
    "ValidationFunction",
    "get_all_signatures",
    "get_signature_by_name",
    "get_signatures_by_library",
]
