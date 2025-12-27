"""Unit tests for certificate validation detector module.

This test suite validates the functionality of CertificateValidationDetector
with comprehensive coverage of detection scenarios, edge cases, and error handling.
Tests use mocking to avoid dependencies on real binaries and external tools.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch, mock_open

import pytest

try:
    from intellicrack.core.certificate.api_signatures import (
        APISignature,
        CallingConvention,
        Platform,
    )
    from intellicrack.core.certificate.binary_scanner import ContextInfo
    from intellicrack.core.certificate.detection_report import (
        BypassMethod,
        DetectionReport,
        ValidationFunction,
    )
    from intellicrack.core.certificate.validation_detector import (
        CertificateValidationDetector,
    )
    MODULE_AVAILABLE = True
except ImportError:
    APISignature = None
    CallingConvention = None
    Platform = None
    ContextInfo = None
    BypassMethod = None
    DetectionReport = None
    ValidationFunction = None
    CertificateValidationDetector = None
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


@pytest.fixture
def detector():
    """Create detector instance for testing."""
    return CertificateValidationDetector()


@pytest.fixture
def mock_binary_scanner():
    """Create mock BinaryScanner instance."""
    scanner = Mock()
    scanner.__enter__ = Mock(return_value=scanner)
    scanner.__exit__ = Mock(return_value=False)
    return scanner


@pytest.fixture
def sample_winhttp_context():
    """Create sample context for WinHTTP call."""
    return ContextInfo(
        address=0x140001234,
        function_name="CheckLicenseValidation",
        surrounding_code="""
            call WinHttpSetOption
            test eax, eax
            jz license_failed
            mov [rbp-8], rax
        """,
        cross_references=[0x140005000, 0x140006000]
    )


@pytest.fixture
def sample_openssl_context():
    """Create sample context for OpenSSL call."""
    return ContextInfo(
        address=0x401234,
        function_name="verify_server_certificate",
        surrounding_code="""
            call SSL_get_verify_result
            cmp eax, 0
            jne cert_invalid
            mov [ebp-4], eax
        """,
        cross_references=[0x405000]
    )


class TestDetectorInitialization:
    """Tests for detector initialization and configuration."""

    def test_detector_creates_with_default_confidence(self, detector):
        """Test detector initializes with default minimum confidence."""
        assert detector.min_confidence == 0.3

    def test_detector_allows_custom_confidence(self):
        """Test detector can be configured with custom confidence threshold."""
        detector = CertificateValidationDetector()
        detector.min_confidence = 0.5
        assert detector.min_confidence == 0.5


class TestBasicDetection:
    """Tests for basic certificate validation detection."""

    @patch("intellicrack.core.certificate.validation_detector.Path")
    @patch("intellicrack.core.certificate.validation_detector.BinaryScanner")
    def test_detect_nonexistent_binary_raises_error(self, mock_scanner_cls, mock_path):
        """Test detection fails gracefully for non-existent binary."""
        detector = CertificateValidationDetector()
        mock_path.return_value.exists.return_value = False

        with pytest.raises(FileNotFoundError) as exc_info:
            detector.detect_certificate_validation("nonexistent.exe")

        assert "Binary not found" in str(exc_info.value)

    @patch("intellicrack.core.certificate.validation_detector.Path")
    @patch("intellicrack.core.certificate.validation_detector.BinaryScanner")
    def test_detect_with_no_tls_libraries(self, mock_scanner_cls, mock_path, mock_binary_scanner):
        """Test detection when no TLS libraries are found."""
        mock_path.return_value.exists.return_value = True
        mock_scanner_cls.return_value = mock_binary_scanner

        mock_binary_scanner.scan_imports.return_value = ["kernel32.dll", "user32.dll"]
        mock_binary_scanner.detect_tls_libraries.return_value = []

        detector = CertificateValidationDetector()
        report = detector.detect_certificate_validation("test.exe")

        assert report.binary_path == "test.exe"
        assert len(report.detected_libraries) == 0
        assert len(report.validation_functions) == 0
        assert report.recommended_method == BypassMethod.NONE

    @patch("intellicrack.core.certificate.validation_detector.Path")
    @patch("intellicrack.core.certificate.validation_detector.BinaryScanner")
    @patch("intellicrack.core.certificate.validation_detector.get_signatures_by_library")
    def test_detect_winhttp_validation(
        self, mock_get_sigs, mock_scanner_cls, mock_path,
        mock_binary_scanner, sample_winhttp_context
    ):
        """Test detection of WinHTTP certificate validation."""
        mock_path.return_value.exists.return_value = True
        mock_scanner_cls.return_value = mock_binary_scanner

        mock_binary_scanner.scan_imports.return_value = ["winhttp.dll"]
        mock_binary_scanner.detect_tls_libraries.return_value = ["winhttp.dll"]

        winhttp_sig = APISignature(
            name="WinHttpSetOption",
            library="winhttp.dll",
            platforms=[Platform.WINDOWS],
            calling_convention=CallingConvention.STDCALL,
            return_type="BOOL",
            description="Sets WinHTTP options"
        )
        mock_get_sigs.return_value = [winhttp_sig]

        mock_binary_scanner.find_api_calls.return_value = [0x140001234]
        mock_binary_scanner.analyze_call_context.return_value = sample_winhttp_context
        mock_binary_scanner.calculate_confidence.return_value = 0.85

        detector = CertificateValidationDetector()
        report = detector.detect_certificate_validation("test.exe")

        assert len(report.detected_libraries) == 1
        assert "winhttp.dll" in report.detected_libraries
        assert len(report.validation_functions) == 1

        func = report.validation_functions[0]
        assert func.api_name == "WinHttpSetOption"
        assert func.address == 0x140001234
        assert func.confidence >= 0.85
        assert func.library == "winhttp.dll"

    @patch("intellicrack.core.certificate.validation_detector.Path")
    @patch("intellicrack.core.certificate.validation_detector.BinaryScanner")
    @patch("intellicrack.core.certificate.validation_detector.get_signatures_by_library")
    def test_detect_openssl_validation(
        self, mock_get_sigs, mock_scanner_cls, mock_path,
        mock_binary_scanner, sample_openssl_context
    ):
        """Test detection of OpenSSL certificate validation."""
        mock_path.return_value.exists.return_value = True
        mock_scanner_cls.return_value = mock_binary_scanner

        mock_binary_scanner.scan_imports.return_value = ["libssl.so"]
        mock_binary_scanner.detect_tls_libraries.return_value = ["libssl.so"]

        openssl_sig = APISignature(
            name="SSL_get_verify_result",
            library="libssl.so",
            platforms=[Platform.LINUX],
            calling_convention=CallingConvention.CDECL,
            return_type="long",
            description="Gets certificate verification result"
        )
        mock_get_sigs.return_value = [openssl_sig]

        mock_binary_scanner.find_api_calls.return_value = [0x401234]
        mock_binary_scanner.analyze_call_context.return_value = sample_openssl_context
        mock_binary_scanner.calculate_confidence.return_value = 0.75

        detector = CertificateValidationDetector()
        report = detector.detect_certificate_validation("test")

        assert len(report.validation_functions) == 1
        func = report.validation_functions[0]
        assert func.api_name == "SSL_get_verify_result"


class TestConfidenceScoring:
    """Tests for confidence calculation and scoring logic."""

    @patch("intellicrack.core.certificate.validation_detector.Path")
    @patch("intellicrack.core.certificate.validation_detector.BinaryScanner")
    @patch("intellicrack.core.certificate.validation_detector.get_signatures_by_library")
    def test_licensing_context_boosts_confidence(
        self, mock_get_sigs, mock_scanner_cls, mock_path, mock_binary_scanner
    ):
        """Test that licensing context increases confidence score."""
        mock_path.return_value.exists.return_value = True
        mock_scanner_cls.return_value = mock_binary_scanner

        licensing_context = ContextInfo(
            address=0x140001234,
            function_name="ValidateLicense",
            surrounding_code="call CheckActivation; call WinHttpSetOption; license validation",
            cross_references=[0x140005000]
        )

        mock_binary_scanner.scan_imports.return_value = ["winhttp.dll"]
        mock_binary_scanner.detect_tls_libraries.return_value = ["winhttp.dll"]
        mock_get_sigs.return_value = [APISignature(
            name="WinHttpSetOption", library="winhttp.dll",
            platforms=[Platform.WINDOWS], calling_convention=CallingConvention.STDCALL,
            return_type="BOOL", description="Test"
        )]
        mock_binary_scanner.find_api_calls.return_value = [0x140001234]
        mock_binary_scanner.analyze_call_context.return_value = licensing_context
        mock_binary_scanner.calculate_confidence.return_value = 0.65

        detector = CertificateValidationDetector()
        report = detector.detect_certificate_validation("test.exe")

        assert len(report.validation_functions) == 1
        func = report.validation_functions[0]
        assert func.confidence >= 0.85

    def test_analyze_licensing_context_detects_keywords(self, detector):
        """Test licensing context detection with various keywords."""
        licensing_contexts = [
            ContextInfo(0x1234, "CheckLicenseValidation", "", []),
            ContextInfo(0x1235, "VerifyActivation", "", []),
            ContextInfo(0x1236, "ValidateSerialKey", "", []),
            ContextInfo(0x1237, "", "license validation registration check", []),
        ]

        for context in licensing_contexts:
            result = detector._analyze_licensing_context(context)
            assert result is True

    def test_analyze_licensing_context_rejects_non_licensing(self, detector):
        """Test licensing context detection rejects non-licensing code."""
        non_licensing_contexts = [
            ContextInfo(0x1234, "ProcessHTTPRequest", "", []),
            ContextInfo(0x1235, "", "network connection established", []),
            ContextInfo(0x1236, "ParseConfiguration", "", []),
        ]

        for context in non_licensing_contexts:
            result = detector._analyze_licensing_context(context)
            assert result is False


class TestConfidenceFiltering:
    """Tests for filtering low-confidence detections."""

    @patch("intellicrack.core.certificate.validation_detector.Path")
    @patch("intellicrack.core.certificate.validation_detector.BinaryScanner")
    @patch("intellicrack.core.certificate.validation_detector.get_signatures_by_library")
    def test_low_confidence_functions_filtered(
        self, mock_get_sigs, mock_scanner_cls, mock_path, mock_binary_scanner
    ):
        """Test that low-confidence detections are filtered out."""
        mock_path.return_value.exists.return_value = True
        mock_scanner_cls.return_value = mock_binary_scanner

        mock_binary_scanner.scan_imports.return_value = ["winhttp.dll"]
        mock_binary_scanner.detect_tls_libraries.return_value = ["winhttp.dll"]
        mock_get_sigs.return_value = [APISignature(
            name="WinHttpSetOption", library="winhttp.dll",
            platforms=[Platform.WINDOWS], calling_convention=CallingConvention.STDCALL,
            return_type="BOOL", description="Test"
        )]

        mock_binary_scanner.find_api_calls.return_value = [0x1234, 0x5678]

        low_confidence_context = ContextInfo(0x1234, "generic_function", "generic code", [])
        high_confidence_context = ContextInfo(0x5678, "CheckLicense", "license validation", [])

        mock_binary_scanner.analyze_call_context.side_effect = [
            low_confidence_context, high_confidence_context
        ]
        mock_binary_scanner.calculate_confidence.side_effect = [0.2, 0.8]

        detector = CertificateValidationDetector()
        report = detector.detect_certificate_validation("test.exe")

        assert len(report.validation_functions) == 1
        assert report.validation_functions[0].address == 0x5678
        assert report.validation_functions[0].confidence >= 0.8

    def test_custom_confidence_threshold(self, detector, mock_binary_scanner):
        """Test custom confidence threshold filtering."""
        functions = [
            ValidationFunction(0x1000, "API1", "lib.dll", 0.4, "", []),
            ValidationFunction(0x2000, "API2", "lib.dll", 0.6, "", []),
            ValidationFunction(0x3000, "API3", "lib.dll", 0.8, "", []),
        ]

        detector.min_confidence = 0.5
        filtered = detector._filter_low_confidence(functions)

        assert len(filtered) == 2
        assert all(f.confidence >= 0.5 for f in filtered)


class TestBypassMethodRecommendation:
    """Tests for bypass method selection logic."""

    def test_recommend_none_for_no_validation(self, detector):
        """Test NONE recommended when no validation detected."""
        result = detector._recommend_bypass_method([], [])
        assert result == BypassMethod.NONE

    def test_recommend_frida_for_openssl(self, detector):
        """Test FRIDA_HOOK recommended for OpenSSL libraries."""
        functions = [
            ValidationFunction(0x1234, "SSL_CTX_set_verify", "libssl.so", 0.8, "", [])
        ]
        result = detector._recommend_bypass_method(functions, ["libssl.so"])
        assert result == BypassMethod.FRIDA_HOOK

    def test_recommend_binary_patch_for_simple_winhttp(self, detector):
        """Test BINARY_PATCH for simple WinHTTP validation."""
        functions = [
            ValidationFunction(0x1234, "WinHttpSetOption", "winhttp.dll", 0.9, "", []),
            ValidationFunction(0x5678, "WinHttpSendRequest", "winhttp.dll", 0.85, "", []),
        ]
        result = detector._recommend_bypass_method(functions, ["winhttp.dll"])
        assert result == BypassMethod.BINARY_PATCH

    def test_recommend_hybrid_for_multiple_libraries(self, detector):
        """Test HYBRID for multiple TLS libraries."""
        functions = [
            ValidationFunction(0x1000, "WinHttpSetOption", "winhttp.dll", 0.8, "", []),
            ValidationFunction(0x2000, "SSL_get_verify_result", "libssl.so", 0.7, "", []),
            ValidationFunction(0x3000, "CertVerifyCertificateChainPolicy", "crypt32.dll", 0.75, "", []),
        ]
        result = detector._recommend_bypass_method(
            functions, ["winhttp.dll", "libssl.so", "crypt32.dll"]
        )
        assert result == BypassMethod.HYBRID

    def test_recommend_frida_for_complex_validation(self, detector):
        """Test FRIDA_HOOK for complex validation with many functions."""
        functions = [
            ValidationFunction(0x1000 + i, f"API{i}", "winhttp.dll", 0.7, "", [])
            for i in range(6)
        ]
        result = detector._recommend_bypass_method(functions, ["winhttp.dll"])
        assert result == BypassMethod.FRIDA_HOOK


class TestRiskAssessment:
    """Tests for risk level assessment."""

    def test_assess_low_risk_for_few_functions(self, detector):
        """Test low risk for small number of simple functions."""
        functions = [
            ValidationFunction(0x1234, "API1", "lib.dll", 0.9, "", [0x5000]),
            ValidationFunction(0x5678, "API2", "lib.dll", 0.85, "", [0x6000]),
        ]
        risk = detector._assess_risk_level(functions)
        assert risk == "low"

    def test_assess_medium_risk_for_moderate_refs(self, detector):
        """Test medium risk for moderate cross-references."""
        functions = [
            ValidationFunction(
                0x1234, "API1", "lib.dll", 0.7, "",
                [0x5000 + i for i in range(7)]
            ),
        ]
        risk = detector._assess_risk_level(functions)
        assert risk == "medium"

    def test_assess_high_risk_for_many_refs(self, detector):
        """Test high risk for many cross-references."""
        functions = [
            ValidationFunction(
                0x1234, "API1", "lib.dll", 0.7, "",
                [0x5000 + i for i in range(15)]
            ),
        ]
        risk = detector._assess_risk_level(functions)
        assert risk == "high"

    def test_assess_high_risk_for_many_functions(self, detector):
        """Test high risk for large number of validation functions."""
        functions = [
            ValidationFunction(0x1000 + i, f"API{i}", "lib.dll", 0.7, "", [])
            for i in range(12)
        ]
        risk = detector._assess_risk_level(functions)
        assert risk == "high"


class TestCustomSignatureDetection:
    """Tests for custom signature detection functionality."""

    @patch("intellicrack.core.certificate.validation_detector.Path")
    @patch("intellicrack.core.certificate.validation_detector.BinaryScanner")
    def test_detect_with_custom_signatures(self, mock_scanner_cls, mock_path, mock_binary_scanner):
        """Test detection with user-provided custom signatures."""
        mock_path.return_value.exists.return_value = True
        mock_scanner_cls.return_value = mock_binary_scanner

        mock_binary_scanner.scan_imports.return_value = []
        mock_binary_scanner.detect_tls_libraries.return_value = []

        custom_sig = APISignature(
            name="CustomValidateFunc",
            library="custom.dll",
            platforms=[Platform.WINDOWS],
            calling_convention=CallingConvention.STDCALL,
            return_type="int",
            description="Custom validation"
        )

        custom_context = ContextInfo(0x9000, "custom_func", "validation code", [])
        mock_binary_scanner.find_api_calls.return_value = [0x9000]
        mock_binary_scanner.analyze_call_context.return_value = custom_context
        mock_binary_scanner.calculate_confidence.return_value = 0.7

        detector = CertificateValidationDetector()
        report = detector.detect_with_custom_signatures("test.exe", [custom_sig])

        custom_funcs = [f for f in report.validation_functions if f.api_name == "CustomValidateFunc"]
        assert len(custom_funcs) == 1
        assert custom_funcs[0].library == "custom.dll"


class TestErrorHandling:
    """Tests for error handling and edge cases."""

    @patch("intellicrack.core.certificate.validation_detector.Path")
    @patch("intellicrack.core.certificate.validation_detector.BinaryScanner")
    def test_scanner_exception_raises_runtime_error(self, mock_scanner_cls, mock_path):
        """Test that scanner exceptions are converted to RuntimeError."""
        mock_path.return_value.exists.return_value = True
        mock_scanner = Mock()
        mock_scanner.__enter__ = Mock(side_effect=Exception("Scanner failed"))
        mock_scanner_cls.return_value = mock_scanner

        detector = CertificateValidationDetector()

        with pytest.raises(RuntimeError) as exc_info:
            detector.detect_certificate_validation("test.exe")

        assert "Failed to detect certificate validation" in str(exc_info.value)

    @patch("intellicrack.core.certificate.validation_detector.Path")
    @patch("intellicrack.core.certificate.validation_detector.BinaryScanner")
    @patch("intellicrack.core.certificate.validation_detector.get_signatures_by_library")
    def test_handles_empty_api_call_results(
        self, mock_get_sigs, mock_scanner_cls, mock_path, mock_binary_scanner
    ):
        """Test graceful handling when no API calls found."""
        mock_path.return_value.exists.return_value = True
        mock_scanner_cls.return_value = mock_binary_scanner

        mock_binary_scanner.scan_imports.return_value = ["winhttp.dll"]
        mock_binary_scanner.detect_tls_libraries.return_value = ["winhttp.dll"]
        mock_get_sigs.return_value = [APISignature(
            name="WinHttpSetOption", library="winhttp.dll",
            platforms=[Platform.WINDOWS], calling_convention=CallingConvention.STDCALL,
            return_type="BOOL", description="Test"
        )]
        mock_binary_scanner.find_api_calls.return_value = []

        detector = CertificateValidationDetector()
        report = detector.detect_certificate_validation("test.exe")

        assert len(report.validation_functions) == 0
        assert report.recommended_method == BypassMethod.NONE


class TestReportGeneration:
    """Tests for detection report generation and validation."""

    @patch("intellicrack.core.certificate.validation_detector.Path")
    @patch("intellicrack.core.certificate.validation_detector.BinaryScanner")
    @patch("intellicrack.core.certificate.validation_detector.get_signatures_by_library")
    def test_report_contains_all_required_fields(
        self, mock_get_sigs, mock_scanner_cls, mock_path, mock_binary_scanner
    ):
        """Test that generated report contains all required fields."""
        mock_path.return_value.exists.return_value = True
        mock_scanner_cls.return_value = mock_binary_scanner

        mock_binary_scanner.scan_imports.return_value = ["winhttp.dll"]
        mock_binary_scanner.detect_tls_libraries.return_value = ["winhttp.dll"]
        mock_get_sigs.return_value = [APISignature(
            name="WinHttpSetOption", library="winhttp.dll",
            platforms=[Platform.WINDOWS], calling_convention=CallingConvention.STDCALL,
            return_type="BOOL", description="Test"
        )]
        mock_binary_scanner.find_api_calls.return_value = [0x1234]
        mock_binary_scanner.analyze_call_context.return_value = ContextInfo(
            0x1234, "test_func", "test code", [0x5000]
        )
        mock_binary_scanner.calculate_confidence.return_value = 0.8

        detector = CertificateValidationDetector()
        report = detector.detect_certificate_validation("test.exe")

        assert hasattr(report, 'binary_path')
        assert hasattr(report, 'detected_libraries')
        assert hasattr(report, 'validation_functions')
        assert hasattr(report, 'recommended_method')
        assert hasattr(report, 'risk_level')
        assert hasattr(report, 'timestamp')

        assert isinstance(report.binary_path, str)
        assert isinstance(report.detected_libraries, list)
        assert isinstance(report.validation_functions, list)
        assert isinstance(report.recommended_method, BypassMethod)
        assert report.risk_level in ["low", "medium", "high"]

    @patch("intellicrack.core.certificate.validation_detector.Path")
    @patch("intellicrack.core.certificate.validation_detector.BinaryScanner")
    @patch("intellicrack.core.certificate.validation_detector.get_signatures_by_library")
    def test_report_can_be_serialized_to_json(
        self, mock_get_sigs, mock_scanner_cls, mock_path, mock_binary_scanner
    ):
        """Test that detection report can be exported to JSON."""
        mock_path.return_value.exists.return_value = True
        mock_scanner_cls.return_value = mock_binary_scanner

        mock_binary_scanner.scan_imports.return_value = ["winhttp.dll"]
        mock_binary_scanner.detect_tls_libraries.return_value = ["winhttp.dll"]
        mock_get_sigs.return_value = []

        detector = CertificateValidationDetector()
        report = detector.detect_certificate_validation("test.exe")

        json_str = report.to_json()
        data = json.loads(json_str)

        assert "binary_path" in data
        assert "detected_libraries" in data
        assert "validation_functions" in data
        assert "recommended_method" in data
        assert "risk_level" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
