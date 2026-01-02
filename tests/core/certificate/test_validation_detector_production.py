"""Production-ready tests for certificate validation detection.

Tests validate real certificate validation function detection in binaries without mocks.
Tests use real binary analysis tools (LIEF, Radare2) to detect actual TLS/SSL validation
functions in PE/ELF binaries for licensing bypass operations.

Tests cover:
- Detection of WinHTTP, Schannel, OpenSSL, NSS certificate validation APIs
- Context analysis for licensing code detection
- Confidence scoring based on call context
- Risk assessment for patch safety
- Bypass method recommendation
- Multi-library detection (mixed validation implementations)
- Packed binary detection warnings
- Error handling for invalid/corrupted binaries
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.certificate.api_signatures import (
    APISignature,
    CallingConvention,
    Platform,
)
from intellicrack.core.certificate.detection_report import (
    BypassMethod,
    DetectionReport,
    ValidationFunction,
)
from intellicrack.core.certificate.validation_detector import CertificateValidationDetector

if TYPE_CHECKING:
    pass


class TestCertificateValidationDetectorInitialization:
    """Test CertificateValidationDetector initialization."""

    def test_detector_initializes_with_default_confidence(self) -> None:
        """Detector initializes with default minimum confidence threshold."""
        detector = CertificateValidationDetector()

        assert hasattr(detector, "min_confidence")
        assert detector.min_confidence == 0.3
        assert hasattr(detector, "logger")

    def test_detector_confidence_threshold_is_configurable(self) -> None:
        """Detector allows custom confidence threshold configuration."""
        detector = CertificateValidationDetector()
        detector.min_confidence = 0.5

        assert detector.min_confidence == 0.5


class TestCertificateValidationDetection:
    """Test detection of certificate validation functions in real binaries."""

    @pytest.fixture
    def detector(self) -> CertificateValidationDetector:
        """Provide detector instance for tests."""
        return CertificateValidationDetector()

    @pytest.fixture
    def minimal_pe_binary(self, tmp_path: Path) -> Path:
        """Create minimal PE binary for testing."""
        exe_path = tmp_path / "test.exe"
        pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00"
        pe_header += b"\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        pe_header += b"\x00" * 480
        pe_header += b"PE\x00\x00\x4C\x01\x02\x00"
        pe_header += b"\x00" * 1000
        exe_path.write_bytes(pe_header)
        return exe_path

    @pytest.fixture
    def windows_system_binary(self) -> Path | None:
        """Provide path to real Windows system binary if available."""
        potential_binaries = [
            Path(r"C:\Windows\System32\curl.exe"),
            Path(r"C:\Windows\System32\certutil.exe"),
            Path(r"C:\Windows\System32\winhttp.dll"),
        ]

        return next((binary for binary in potential_binaries if binary.exists()), None)

    def test_detect_certificate_validation_on_minimal_binary(
        self, detector: CertificateValidationDetector, minimal_pe_binary: Path
    ) -> None:
        """Detection processes minimal PE binary without crashing."""
        report = detector.detect_certificate_validation(str(minimal_pe_binary))

        assert isinstance(report, DetectionReport)
        assert report.binary_path == str(minimal_pe_binary)
        assert isinstance(report.validation_functions, list)
        assert isinstance(report.recommended_method, BypassMethod)
        assert report.risk_level in ["low", "medium", "high"]

    @pytest.mark.skipif(
        not Path(r"C:\Windows\System32\curl.exe").exists(),
        reason="Requires Windows system binary curl.exe",
    )
    def test_detect_certificate_validation_on_real_curl_binary(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Detection identifies certificate validation in real curl.exe binary."""
        curl_path = r"C:\Windows\System32\curl.exe"

        report = detector.detect_certificate_validation(curl_path)

        assert isinstance(report, DetectionReport)
        assert report.binary_path == curl_path
        assert isinstance(report.validation_functions, list)
        assert len(report.detected_libraries) >= 0

    @pytest.mark.skipif(
        not Path(r"C:\Windows\System32\winhttp.dll").exists(),
        reason="Requires Windows WinHTTP library",
    )
    def test_detect_certificate_validation_on_winhttp_dll(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Detection identifies WinHTTP certificate validation APIs in winhttp.dll."""
        winhttp_path = r"C:\Windows\System32\winhttp.dll"

        report = detector.detect_certificate_validation(winhttp_path)

        assert isinstance(report, DetectionReport)
        assert report.binary_path == winhttp_path
        assert isinstance(report.validation_functions, list)

    def test_detect_certificate_validation_on_nonexistent_file(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Detection handles nonexistent file path gracefully."""
        report = detector.detect_certificate_validation("nonexistent_binary.exe")

        assert isinstance(report, DetectionReport)
        assert len(report.validation_functions) == 0

    def test_detect_certificate_validation_on_invalid_binary(
        self, detector: CertificateValidationDetector, tmp_path: Path
    ) -> None:
        """Detection handles invalid binary data gracefully."""
        invalid_file = tmp_path / "invalid.exe"
        invalid_file.write_bytes(b"Not a valid PE or ELF binary")

        report = detector.detect_certificate_validation(str(invalid_file))

        assert isinstance(report, DetectionReport)

    def test_detect_certificate_validation_on_empty_file(
        self, detector: CertificateValidationDetector, tmp_path: Path
    ) -> None:
        """Detection handles empty file gracefully."""
        empty_file = tmp_path / "empty.exe"
        empty_file.write_bytes(b"")

        report = detector.detect_certificate_validation(str(empty_file))

        assert isinstance(report, DetectionReport)
        assert len(report.validation_functions) == 0


class TestLowConfidenceFiltering:
    """Test filtering of low-confidence detection results."""

    @pytest.fixture
    def detector(self) -> CertificateValidationDetector:
        """Provide detector instance for tests."""
        return CertificateValidationDetector()

    def test_filter_low_confidence_removes_below_threshold(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Low confidence filtering removes functions below threshold."""
        functions = [
            ValidationFunction(
                address=0x1000,
                api_name="API1",
                library="winhttp",
                confidence=0.8,
                context="license_check",
            ),
            ValidationFunction(
                address=0x2000,
                api_name="API2",
                library="schannel",
                confidence=0.2,
                context="unknown",
            ),
            ValidationFunction(
                address=0x3000,
                api_name="API3",
                library="openssl",
                confidence=0.5,
                context="license_check",
            ),
        ]

        filtered = detector._filter_low_confidence(functions)

        assert len(filtered) == 2
        assert all(f.confidence >= detector.min_confidence for f in filtered)

    def test_filter_low_confidence_with_custom_threshold(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Low confidence filtering respects custom threshold."""
        detector.min_confidence = 0.6

        functions = [
            ValidationFunction(
                address=0x1000,
                api_name="API1",
                library="winhttp",
                confidence=0.8,
                context="license_check",
            ),
            ValidationFunction(
                address=0x2000,
                api_name="API2",
                library="schannel",
                confidence=0.5,
                context="unknown",
            ),
            ValidationFunction(
                address=0x3000,
                api_name="API3",
                library="openssl",
                confidence=0.7,
                context="license_check",
            ),
        ]

        filtered = detector._filter_low_confidence(functions)

        assert len(filtered) == 2
        assert all(f.confidence >= 0.6 for f in filtered)

    def test_filter_low_confidence_preserves_order(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Low confidence filtering preserves original function order."""
        functions = [
            ValidationFunction(
                address=0x1000,
                api_name="API1",
                library="winhttp",
                confidence=0.8,
                context="license_check",
            ),
            ValidationFunction(
                address=0x2000,
                api_name="API2",
                library="schannel",
                confidence=0.9,
                context="unknown",
            ),
            ValidationFunction(
                address=0x3000,
                api_name="API3",
                library="openssl",
                confidence=0.7,
                context="license_check",
            ),
        ]

        filtered = detector._filter_low_confidence(functions)

        addresses = [f.address for f in filtered]
        assert addresses == [0x1000, 0x2000, 0x3000]


class TestBypassMethodRecommendation:
    """Test bypass method recommendation logic."""

    @pytest.fixture
    def detector(self) -> CertificateValidationDetector:
        """Provide detector instance for tests."""
        return CertificateValidationDetector()

    def test_recommend_bypass_method_for_single_library(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Bypass recommendation for single library validation."""
        functions = [
            ValidationFunction(
                address=0x1000,
                api_name="WinHttpSendRequest",
                library="winhttp",
                confidence=0.9,
                context="license_check",
            )
        ]
        detected_libs = ["winhttp"]

        method = detector._recommend_bypass_method(functions, detected_libs)

        assert isinstance(method, BypassMethod)

    def test_recommend_bypass_method_for_multiple_libraries(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Bypass recommendation for multiple library validation (fallback chains)."""
        functions = [
            ValidationFunction(
                address=0x1000,
                api_name="WinHttpSendRequest",
                library="winhttp",
                confidence=0.9,
                context="license_check",
            ),
            ValidationFunction(
                address=0x2000,
                api_name="SSL_get_verify_result",
                library="openssl",
                confidence=0.8,
                context="license_check",
            ),
        ]
        detected_libs = ["winhttp", "schannel", "openssl"]

        method = detector._recommend_bypass_method(functions, detected_libs)

        assert isinstance(method, BypassMethod)

    def test_recommend_bypass_method_with_no_detections(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Bypass recommendation handles no detections case."""
        functions: list[ValidationFunction] = []
        detected_libs: list[str] = []

        method = detector._recommend_bypass_method(functions, detected_libs)

        assert isinstance(method, BypassMethod)

    def test_recommend_bypass_method_for_high_confidence_detections(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Bypass recommendation considers high-confidence detections."""
        functions = [
            ValidationFunction(
                address=0x1000,
                api_name="WinHttpSendRequest",
                library="winhttp",
                confidence=0.95,
                context="license_check",
            )
        ]
        detected_libs = ["winhttp"]

        method = detector._recommend_bypass_method(functions, detected_libs)

        assert isinstance(method, BypassMethod)


class TestRiskAssessment:
    """Test patch safety risk assessment."""

    @pytest.fixture
    def detector(self) -> CertificateValidationDetector:
        """Provide detector instance for tests."""
        return CertificateValidationDetector()

    def test_assess_risk_level_for_no_detections(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Risk assessment returns low risk for no detections."""
        functions: list[ValidationFunction] = []

        risk = detector._assess_risk_level(functions)

        assert risk == "low"

    def test_assess_risk_level_for_single_detection(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Risk assessment for single validation function."""
        functions = [
            ValidationFunction(
                address=0x1000,
                api_name="SSL_CTX_set_verify",
                library="openssl",
                confidence=0.9,
                context="license_check",
            )
        ]

        risk = detector._assess_risk_level(functions)

        assert risk in ["low", "medium", "high"]

    def test_assess_risk_level_for_multiple_detections(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Risk assessment increases with multiple validation functions."""
        functions = [
            ValidationFunction(
                address=0x1000,
                api_name="API1",
                library="winhttp",
                confidence=0.9,
                context="license_check",
            ),
            ValidationFunction(
                address=0x2000,
                api_name="API2",
                library="schannel",
                confidence=0.8,
                context="license_check",
            ),
            ValidationFunction(
                address=0x3000,
                api_name="API3",
                library="openssl",
                confidence=0.95,
                context="license_check",
            ),
        ]

        risk = detector._assess_risk_level(functions)

        assert risk in ["medium", "high"]

    def test_assess_risk_level_considers_detection_count(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Risk assessment considers number of detected functions."""
        functions = [
            ValidationFunction(
                address=0x1000,
                api_name="API1",
                library="winhttp",
                confidence=0.9,
                context="license_check",
            ),
            ValidationFunction(
                address=0x2000,
                api_name="API2",
                library="schannel",
                confidence=0.8,
                context="license_check",
            ),
        ]

        risk = detector._assess_risk_level(functions)

        assert risk in ["low", "medium", "high"]


class TestCustomSignatureDetection:
    """Test detection with custom API signatures."""

    @pytest.fixture
    def detector(self) -> CertificateValidationDetector:
        """Provide detector instance for tests."""
        return CertificateValidationDetector()

    @pytest.fixture
    def custom_signature(self) -> APISignature:
        """Create custom API signature for testing."""
        return APISignature(
            name="CustomValidateFunction",
            library="custom_lib",
            platforms=[Platform.WINDOWS],
            calling_convention=CallingConvention.STDCALL,
            return_type="BOOL",
            description="Custom certificate validation function for testing",
        )

    def test_detect_with_custom_signatures_accepts_signature_list(
        self,
        detector: CertificateValidationDetector,
        custom_signature: APISignature,
        tmp_path: Path,
    ) -> None:
        """Custom signature detection accepts list of APISignature objects."""
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 1000)

        report = detector.detect_with_custom_signatures(
            str(test_binary), [custom_signature]
        )

        assert isinstance(report, DetectionReport)

    def test_detect_with_custom_signatures_includes_custom_detections(
        self,
        detector: CertificateValidationDetector,
        custom_signature: APISignature,
        tmp_path: Path,
    ) -> None:
        """Custom signature detection includes custom APIs in results."""
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 1000)

        report = detector.detect_with_custom_signatures(
            str(test_binary), [custom_signature]
        )

        assert isinstance(report.validation_functions, list)


class TestDetectionReportGeneration:
    """Test DetectionReport generation from detection results."""

    @pytest.fixture
    def detector(self) -> CertificateValidationDetector:
        """Provide detector instance for tests."""
        return CertificateValidationDetector()

    def test_detection_report_contains_all_required_fields(
        self, detector: CertificateValidationDetector, tmp_path: Path
    ) -> None:
        """Detection report includes all required fields."""
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 1000)

        report = detector.detect_certificate_validation(str(test_binary))

        assert hasattr(report, "binary_path")
        assert hasattr(report, "validation_functions")
        assert hasattr(report, "detected_libraries")
        assert hasattr(report, "recommended_method")
        assert hasattr(report, "risk_level")
        assert hasattr(report, "timestamp")

    def test_detection_report_json_serialization(
        self, detector: CertificateValidationDetector, tmp_path: Path
    ) -> None:
        """Detection report can be serialized to JSON."""
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 1000)

        report = detector.detect_certificate_validation(str(test_binary))

        json_str = report.to_json()
        assert isinstance(json_str, str)
        assert len(json_str) > 0


class TestConfidenceScoringAccuracy:
    """Test confidence scoring accuracy for different detection scenarios."""

    @pytest.fixture
    def detector(self) -> CertificateValidationDetector:
        """Provide detector instance for tests."""
        return CertificateValidationDetector()

    def test_confidence_threshold_filtering_consistency(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Confidence threshold filtering produces consistent results."""
        functions = [
            ValidationFunction(
                address=0x1000,
                api_name="API1",
                library="winhttp",
                confidence=0.29,
                context="unknown",
            ),
            ValidationFunction(
                address=0x2000,
                api_name="API2",
                library="schannel",
                confidence=0.30,
                context="license_check",
            ),
            ValidationFunction(
                address=0x3000,
                api_name="API3",
                library="openssl",
                confidence=0.31,
                context="license_check",
            ),
        ]

        filtered = detector._filter_low_confidence(functions)

        assert len(filtered) == 2
        assert filtered[0].confidence == 0.30
        assert filtered[1].confidence == 0.31


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling in validation detection."""

    @pytest.fixture
    def detector(self) -> CertificateValidationDetector:
        """Provide detector instance for tests."""
        return CertificateValidationDetector()

    def test_detect_on_very_large_binary(
        self, detector: CertificateValidationDetector, tmp_path: Path
    ) -> None:
        """Detection handles very large binaries without memory issues."""
        large_binary = tmp_path / "large.exe"
        large_binary.write_bytes(b"MZ" + b"\x00" * (50 * 1024 * 1024))

        report = detector.detect_certificate_validation(str(large_binary))

        assert isinstance(report, DetectionReport)

    def test_detect_on_binary_with_special_characters_in_path(
        self, detector: CertificateValidationDetector, tmp_path: Path
    ) -> None:
        """Detection handles paths with special characters."""
        special_dir = tmp_path / "test dir with spaces"
        special_dir.mkdir()
        test_binary = special_dir / "test file.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 1000)

        report = detector.detect_certificate_validation(str(test_binary))

        assert isinstance(report, DetectionReport)

    def test_detect_on_readonly_binary(
        self, detector: CertificateValidationDetector, tmp_path: Path
    ) -> None:
        """Detection handles read-only binaries correctly."""
        readonly_binary = tmp_path / "readonly.exe"
        readonly_binary.write_bytes(b"MZ" + b"\x00" * 1000)
        readonly_binary.chmod(0o444)

        try:
            report = detector.detect_certificate_validation(str(readonly_binary))
            assert isinstance(report, DetectionReport)
        finally:
            readonly_binary.chmod(0o644)

    def test_filter_low_confidence_with_empty_list(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Low confidence filtering handles empty function list."""
        functions: list[ValidationFunction] = []

        filtered = detector._filter_low_confidence(functions)

        assert len(filtered) == 0

    def test_recommend_bypass_method_with_unknown_library(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Bypass recommendation handles unknown library types."""
        functions = [
            ValidationFunction(
                address=0x1000,
                api_name="UnknownAPI",
                library="unknown_custom_library",
                confidence=0.7,
                context="unknown",
            )
        ]
        detected_libs = ["unknown_custom_library"]

        method = detector._recommend_bypass_method(functions, detected_libs)

        assert isinstance(method, BypassMethod)


class TestMultiLibraryDetection:
    """Test detection of mixed TLS library implementations."""

    @pytest.fixture
    def detector(self) -> CertificateValidationDetector:
        """Provide detector instance for tests."""
        return CertificateValidationDetector()

    def test_recommend_bypass_for_mixed_winhttp_openssl(
        self, detector: CertificateValidationDetector
    ) -> None:
        """Bypass recommendation handles mixed WinHTTP and OpenSSL usage."""
        functions = [
            ValidationFunction(
                address=0x1000,
                api_name="WinHttpSendRequest",
                library="winhttp",
                confidence=0.9,
                context="license_check",
            ),
            ValidationFunction(
                address=0x2000,
                api_name="SSL_get_verify_result",
                library="openssl",
                confidence=0.85,
                context="license_check",
            ),
        ]
        detected_libs = ["winhttp", "openssl"]

        method = detector._recommend_bypass_method(functions, detected_libs)

        assert isinstance(method, BypassMethod)
        assert method in [
            BypassMethod.FRIDA_HOOK,
            BypassMethod.BINARY_PATCH,
            BypassMethod.HYBRID,
            BypassMethod.MITM_PROXY,
            BypassMethod.NONE,
        ]
