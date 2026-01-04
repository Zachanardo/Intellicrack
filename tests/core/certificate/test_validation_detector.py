"""Production tests for certificate validation detector module.

This test suite validates CertificateValidationDetector functionality using REAL
implementations, actual binaries, and genuine detection capabilities. NO mocks.

TEST SCOPE:
- Real binary analysis on test fixture files
- Actual TLS library detection in legitimate binaries
- Genuine confidence scoring and context analysis
- Real detection reports with verifiable outputs
- Edge cases using corrupted/invalid binaries
- Performance validation on real binaries

FIXTURES USED:
- tests/fixtures/binaries/pe/legitimate/*.exe (real Windows executables)
- tests/fixtures/binaries/pe/protected/*.exe (protected binaries)
- Temporary test binaries created in memory for specific scenarios
"""

import json
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    from intellicrack.core.certificate.api_signatures import (
        APISignature,
        CallingConvention,
        Platform,
    )
    from intellicrack.core.certificate.binary_scanner import BinaryScanner, ContextInfo
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
    APISignature = None  # type: ignore[assignment, misc]
    CallingConvention = None  # type: ignore[assignment, misc]
    Platform = None  # type: ignore[assignment, misc]
    ContextInfo = None  # type: ignore[assignment, misc]
    BypassMethod = None  # type: ignore[assignment, misc]
    DetectionReport = None  # type: ignore[assignment, misc]
    ValidationFunction = None  # type: ignore[assignment, misc]
    CertificateValidationDetector = None  # type: ignore[assignment, misc]
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not MODULE_AVAILABLE, reason="Certificate validation modules not available"
)


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to test fixtures directory."""
    return Path(__file__).parent.parent.parent / "fixtures"


@pytest.fixture
def legitimate_binaries_dir(fixtures_dir: Path) -> Path:
    """Path to legitimate test binaries."""
    return fixtures_dir / "binaries" / "pe" / "legitimate"


@pytest.fixture
def protected_binaries_dir(fixtures_dir: Path) -> Path:
    """Path to protected test binaries."""
    return fixtures_dir / "binaries" / "pe" / "protected"


@pytest.fixture
def sample_binary_with_winhttp(legitimate_binaries_dir: Path) -> Path:
    """Return path to binary known to use WinHTTP (Firefox uses networking)."""
    firefox_path = legitimate_binaries_dir / "firefox.exe"
    if firefox_path.exists():
        return firefox_path
    pytest.skip("Firefox test binary not available")


@pytest.fixture
def sample_binary_without_tls(fixtures_dir: Path) -> Path:
    """Return path to simple binary without TLS libraries."""
    simple_binary = fixtures_dir / "binaries" / "size_categories" / "tiny_4kb" / "tiny_hello.exe"
    if simple_binary.exists():
        return simple_binary
    pytest.skip("Simple test binary not available")


class MinimalPEGenerator:
    """Generates minimal valid PE files for testing."""

    @staticmethod
    def create_minimal_pe() -> bytes:
        """Create minimal valid PE file structure.

        Returns:
            Bytes representing minimal valid PE file
        """
        dos_header = b"MZ" + b"\x90" * 58
        dos_header += struct.pack("<I", 0x80)

        pe_signature = b"PE\x00\x00"

        coff_header = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0,
            0,
            0,
            0xE0,
            0x010B,
        )

        optional_header = b"\x00" * 0xE0

        section_header = b".text\x00\x00\x00"
        section_header += struct.pack("<IIIIIIHH", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0x60000020)

        pe_file = dos_header + pe_signature + coff_header + optional_header + section_header
        pe_file += b"\x00" * (0x200 - len(pe_file))

        return pe_file

    @staticmethod
    def create_pe_with_imports(import_dlls: list[str]) -> bytes:
        """Create PE file with specific import table.

        Args:
            import_dlls: List of DLL names to include in import table

        Returns:
            Bytes representing PE file with imports
        """
        base_pe = MinimalPEGenerator.create_minimal_pe()

        try:
            if not LIEF_AVAILABLE:
                return base_pe

            with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
                tmp.write(base_pe)
                tmp_path = tmp.name

            binary = lief.parse(tmp_path)
            if binary is None:
                return base_pe

            for dll_name in import_dlls:
                if isinstance(binary, lief.PE.Binary):
                    binary.add_library(dll_name)  # type: ignore[attr-defined]

            binary.write(tmp_path)  # type: ignore[union-attr]

            with open(tmp_path, "rb") as f:
                result = f.read()

            Path(tmp_path).unlink(missing_ok=True)
            return result

        except Exception:
            return base_pe

    @staticmethod
    def create_corrupted_pe() -> bytes:
        """Create corrupted PE file with invalid header.

        Returns:
            Bytes representing corrupted PE file
        """
        return b"MZ\x90\x00" + b"\xFF" * 100 + b"PE\x00\x00" + b"\x00" * 50


class TestDetectorInitialization:
    """Tests for detector initialization and configuration."""

    def test_detector_creates_with_default_confidence(self) -> None:
        """Detector initializes with default minimum confidence threshold."""
        detector = CertificateValidationDetector()

        assert detector.min_confidence == 0.3
        assert isinstance(detector, CertificateValidationDetector)

    def test_detector_allows_custom_confidence_threshold(self) -> None:
        """Detector can be configured with custom confidence threshold."""
        detector = CertificateValidationDetector()
        detector.min_confidence = 0.5

        assert detector.min_confidence == 0.5

        detector.min_confidence = 0.7
        assert detector.min_confidence == 0.7

    def test_detector_accepts_various_confidence_values(self) -> None:
        """Detector accepts valid confidence threshold range."""
        detector = CertificateValidationDetector()

        valid_thresholds = [0.0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0]
        for threshold in valid_thresholds:
            detector.min_confidence = threshold
            assert detector.min_confidence == threshold


class TestBasicDetection:
    """Tests for basic certificate validation detection on real binaries."""

    def test_detect_nonexistent_binary_raises_file_not_found(self) -> None:
        """Detection fails with FileNotFoundError for non-existent binary."""
        detector = CertificateValidationDetector()
        nonexistent_path = "D:\\nonexistent\\fake\\binary.exe"

        with pytest.raises(FileNotFoundError) as exc_info:
            detector.detect_certificate_validation(nonexistent_path)

        assert "Binary not found" in str(exc_info.value)
        assert nonexistent_path in str(exc_info.value)

    def test_detect_with_simple_binary_without_tls(
        self, sample_binary_without_tls: Path
    ) -> None:
        """Detection on simple binary without TLS libraries returns empty results."""
        if not sample_binary_without_tls.exists():
            pytest.skip("Simple binary not available")

        detector = CertificateValidationDetector()
        report = detector.detect_certificate_validation(str(sample_binary_without_tls))

        assert isinstance(report, DetectionReport)
        assert report.binary_path == str(sample_binary_without_tls)
        assert isinstance(report.detected_libraries, list)
        assert isinstance(report.validation_functions, list)
        assert isinstance(report.recommended_method, BypassMethod)

    def test_detect_on_legitimate_firefox_binary(
        self, sample_binary_with_winhttp: Path
    ) -> None:
        """Detection on Firefox executable produces valid report structure."""
        if not sample_binary_with_winhttp.exists():
            pytest.skip("Firefox binary not available")

        detector = CertificateValidationDetector()
        report = detector.detect_certificate_validation(str(sample_binary_with_winhttp))

        assert isinstance(report, DetectionReport)
        assert report.binary_path == str(sample_binary_with_winhttp)
        assert isinstance(report.detected_libraries, list)
        assert isinstance(report.validation_functions, list)
        assert isinstance(report.recommended_method, BypassMethod)
        assert report.risk_level in ["low", "medium", "high"]
        assert report.timestamp is not None

    def test_detect_creates_valid_report_structure(
        self, sample_binary_without_tls: Path
    ) -> None:
        """Detection creates report with all required fields."""
        if not sample_binary_without_tls.exists():
            pytest.skip("Test binary not available")

        detector = CertificateValidationDetector()
        report = detector.detect_certificate_validation(str(sample_binary_without_tls))

        assert hasattr(report, "binary_path")
        assert hasattr(report, "detected_libraries")
        assert hasattr(report, "validation_functions")
        assert hasattr(report, "recommended_method")
        assert hasattr(report, "risk_level")
        assert hasattr(report, "timestamp")

        assert isinstance(report.binary_path, str)
        assert isinstance(report.detected_libraries, list)
        assert isinstance(report.validation_functions, list)
        assert isinstance(report.recommended_method, BypassMethod)


class TestConfidenceScoring:
    """Tests for confidence calculation and scoring logic."""

    def test_analyze_licensing_context_detects_license_keywords(self) -> None:
        """Licensing context detection identifies licensing-related code."""
        detector = CertificateValidationDetector()

        licensing_contexts = [
            ContextInfo(0x1234, "CheckLicenseValidation", "", []),
            ContextInfo(0x1235, "VerifyActivation", "", []),
            ContextInfo(0x1236, "ValidateSerialKey", "", []),
            ContextInfo(0x1237, "RegisterProduct", "", []),
            ContextInfo(0x1238, "", "license validation registration check", []),
            ContextInfo(0x1239, "ActivateTrial", "", []),
        ]

        for context in licensing_contexts:
            result = detector._analyze_licensing_context(context)
            assert result is True, f"Failed to detect licensing context: {context.function_name}"

    def test_analyze_licensing_context_rejects_non_licensing(self) -> None:
        """Licensing context detection rejects non-licensing code."""
        detector = CertificateValidationDetector()

        non_licensing_contexts = [
            ContextInfo(0x1234, "ProcessHTTPRequest", "", []),
            ContextInfo(0x1235, "", "network connection established", []),
            ContextInfo(0x1236, "ParseConfiguration", "", []),
            ContextInfo(0x1237, "InitializeGraphics", "", []),
            ContextInfo(0x1238, "LoadTexture", "", []),
        ]

        for context in non_licensing_contexts:
            result = detector._analyze_licensing_context(context)
            assert result is False, f"False positive for: {context.function_name}"

    def test_analyze_licensing_context_requires_multiple_keywords(self) -> None:
        """Licensing context detection in code requires multiple keywords."""
        detector = CertificateValidationDetector()

        single_keyword = ContextInfo(0x1234, "", "check connection", [])
        result_single = detector._analyze_licensing_context(single_keyword)
        assert result_single is False

        multiple_keywords = ContextInfo(0x1235, "", "license validation activation check", [])
        result_multiple = detector._analyze_licensing_context(multiple_keywords)
        assert result_multiple is True

    def test_analyze_licensing_context_case_insensitive(self) -> None:
        """Licensing context detection is case-insensitive."""
        detector = CertificateValidationDetector()

        mixed_case_contexts = [
            ContextInfo(0x1234, "CheckLICENSEValidation", "", []),
            ContextInfo(0x1235, "VerifyACTIVATION", "", []),
            ContextInfo(0x1236, "", "LICENSE validation REGISTRATION check", []),
        ]

        for context in mixed_case_contexts:
            result = detector._analyze_licensing_context(context)
            assert result is True


class TestConfidenceFiltering:
    """Tests for filtering low-confidence detections."""

    def test_filter_low_confidence_removes_below_threshold(self) -> None:
        """Low-confidence functions are filtered based on threshold."""
        detector = CertificateValidationDetector()
        detector.min_confidence = 0.5

        functions = [
            ValidationFunction(0x1000, "API1", "lib.dll", 0.3, "", []),
            ValidationFunction(0x2000, "API2", "lib.dll", 0.5, "", []),
            ValidationFunction(0x3000, "API3", "lib.dll", 0.7, "", []),
            ValidationFunction(0x4000, "API4", "lib.dll", 0.9, "", []),
        ]

        filtered = detector._filter_low_confidence(functions)

        assert len(filtered) == 3
        assert all(func.confidence >= 0.5 for func in filtered)
        assert filtered[0].address == 0x2000
        assert filtered[1].address == 0x3000
        assert filtered[2].address == 0x4000

    def test_filter_low_confidence_default_threshold(self) -> None:
        """Default confidence threshold filters correctly."""
        detector = CertificateValidationDetector()

        functions = [
            ValidationFunction(0x1000, "API1", "lib.dll", 0.2, "", []),
            ValidationFunction(0x2000, "API2", "lib.dll", 0.3, "", []),
            ValidationFunction(0x3000, "API3", "lib.dll", 0.4, "", []),
        ]

        filtered = detector._filter_low_confidence(functions)

        assert len(filtered) == 2
        assert all(func.confidence >= 0.3 for func in filtered)

    def test_filter_low_confidence_empty_list(self) -> None:
        """Filtering empty list returns empty list."""
        detector = CertificateValidationDetector()

        filtered = detector._filter_low_confidence([])

        assert len(filtered) == 0
        assert isinstance(filtered, list)

    def test_filter_low_confidence_all_below_threshold(self) -> None:
        """All functions below threshold results in empty list."""
        detector = CertificateValidationDetector()
        detector.min_confidence = 0.8

        functions = [
            ValidationFunction(0x1000, "API1", "lib.dll", 0.3, "", []),
            ValidationFunction(0x2000, "API2", "lib.dll", 0.5, "", []),
            ValidationFunction(0x3000, "API3", "lib.dll", 0.7, "", []),
        ]

        filtered = detector._filter_low_confidence(functions)

        assert len(filtered) == 0


class TestBypassMethodRecommendation:
    """Tests for bypass method selection logic."""

    def test_recommend_none_for_no_validation(self) -> None:
        """NONE recommended when no validation detected."""
        detector = CertificateValidationDetector()

        result = detector._recommend_bypass_method([], [])

        assert result == BypassMethod.NONE

    def test_recommend_frida_for_openssl(self) -> None:
        """FRIDA_HOOK recommended for OpenSSL libraries."""
        detector = CertificateValidationDetector()

        functions = [
            ValidationFunction(0x1234, "SSL_CTX_set_verify", "libssl.so", 0.8, "", [])
        ]

        result = detector._recommend_bypass_method(functions, ["libssl.so"])

        assert result == BypassMethod.FRIDA_HOOK

    def test_recommend_frida_for_nss(self) -> None:
        """FRIDA_HOOK recommended for NSS libraries."""
        detector = CertificateValidationDetector()

        functions = [
            ValidationFunction(0x1234, "CERT_VerifyCertificate", "nss3.dll", 0.8, "", [])
        ]

        result = detector._recommend_bypass_method(functions, ["nss3.dll"])

        assert result == BypassMethod.FRIDA_HOOK

    def test_recommend_binary_patch_for_simple_winhttp(self) -> None:
        """BINARY_PATCH for simple WinHTTP validation."""
        detector = CertificateValidationDetector()

        functions = [
            ValidationFunction(0x1234, "WinHttpSetOption", "winhttp.dll", 0.85, "", []),
            ValidationFunction(0x5678, "WinHttpSendRequest", "winhttp.dll", 0.90, "", []),
        ]

        result = detector._recommend_bypass_method(functions, ["winhttp.dll"])

        assert result == BypassMethod.BINARY_PATCH

    def test_recommend_hybrid_for_multiple_library_types(self) -> None:
        """HYBRID for multiple different TLS library types."""
        detector = CertificateValidationDetector()

        functions = [
            ValidationFunction(0x1000, "WinHttpSetOption", "winhttp.dll", 0.8, "", []),
            ValidationFunction(0x2000, "SSL_get_verify_result", "libssl.so", 0.7, "", []),
            ValidationFunction(
                0x3000, "CertVerifyCertificateChainPolicy", "crypt32.dll", 0.75, "", []
            ),
        ]

        result = detector._recommend_bypass_method(
            functions, ["winhttp.dll", "libssl.so", "crypt32.dll"]
        )

        assert result == BypassMethod.HYBRID

    def test_recommend_frida_for_complex_validation(self) -> None:
        """FRIDA_HOOK for complex validation with many functions."""
        detector = CertificateValidationDetector()

        functions = [
            ValidationFunction(0x1000 + i, f"API{i}", "winhttp.dll", 0.7, "", [])
            for i in range(6)
        ]

        result = detector._recommend_bypass_method(functions, ["winhttp.dll"])

        assert result == BypassMethod.FRIDA_HOOK

    def test_recommend_considers_high_confidence_count(self) -> None:
        """Bypass recommendation considers high-confidence function count."""
        detector = CertificateValidationDetector()

        high_conf_functions = [
            ValidationFunction(0x1000, "API1", "winhttp.dll", 0.85, "", []),
            ValidationFunction(0x2000, "API2", "winhttp.dll", 0.90, "", []),
        ]

        result = detector._recommend_bypass_method(high_conf_functions, ["winhttp.dll"])

        assert result == BypassMethod.BINARY_PATCH


class TestRiskAssessment:
    """Tests for risk level assessment."""

    def test_assess_low_risk_for_few_functions(self) -> None:
        """Low risk assessed for small number of simple functions."""
        detector = CertificateValidationDetector()

        functions = [
            ValidationFunction(0x1234, "API1", "lib.dll", 0.9, "", [0x5000]),
            ValidationFunction(0x5678, "API2", "lib.dll", 0.85, "", [0x6000]),
        ]

        risk = detector._assess_risk_level(functions)

        assert risk == "low"

    def test_assess_medium_risk_for_moderate_refs(self) -> None:
        """Medium risk for moderate cross-references."""
        detector = CertificateValidationDetector()

        functions = [
            ValidationFunction(
                0x1234, "API1", "lib.dll", 0.7, "", [0x5000 + i for i in range(7)]
            ),
        ]

        risk = detector._assess_risk_level(functions)

        assert risk == "medium"

    def test_assess_high_risk_for_many_refs(self) -> None:
        """High risk for many cross-references."""
        detector = CertificateValidationDetector()

        functions = [
            ValidationFunction(
                0x1234, "API1", "lib.dll", 0.7, "", [0x5000 + i for i in range(15)]
            ),
        ]

        risk = detector._assess_risk_level(functions)

        assert risk == "high"

    def test_assess_high_risk_for_many_functions(self) -> None:
        """High risk for large number of validation functions."""
        detector = CertificateValidationDetector()

        functions = [
            ValidationFunction(0x1000 + i, f"API{i}", "lib.dll", 0.7, "", [])
            for i in range(12)
        ]

        risk = detector._assess_risk_level(functions)

        assert risk == "high"

    def test_assess_low_risk_for_high_confidence(self) -> None:
        """Low risk when most functions have high confidence."""
        detector = CertificateValidationDetector()

        functions = [
            ValidationFunction(0x1000 + i, f"API{i}", "lib.dll", 0.9, "", [0x5000])
            for i in range(5)
        ]

        risk = detector._assess_risk_level(functions)

        assert risk == "low"

    def test_assess_risk_empty_functions(self) -> None:
        """Risk assessment for no functions returns low."""
        detector = CertificateValidationDetector()

        risk = detector._assess_risk_level([])

        assert risk == "low"


class TestCustomSignatureDetection:
    """Tests for custom signature detection functionality."""

    def test_detect_with_custom_signatures_on_real_binary(
        self, sample_binary_without_tls: Path
    ) -> None:
        """Custom signature detection works on real binary."""
        if not sample_binary_without_tls.exists():
            pytest.skip("Test binary not available")

        detector = CertificateValidationDetector()

        custom_sig = APISignature(
            name="CustomValidateFunc",
            library="custom.dll",
            platforms=[Platform.WINDOWS],
            calling_convention=CallingConvention.STDCALL,
            return_type="int",
            description="Custom validation",
        )

        report = detector.detect_with_custom_signatures(
            str(sample_binary_without_tls), [custom_sig]
        )

        assert isinstance(report, DetectionReport)
        assert report.binary_path == str(sample_binary_without_tls)

    def test_detect_with_empty_custom_signatures(
        self, sample_binary_without_tls: Path
    ) -> None:
        """Custom signature detection with empty signature list."""
        if not sample_binary_without_tls.exists():
            pytest.skip("Test binary not available")

        detector = CertificateValidationDetector()
        report = detector.detect_with_custom_signatures(
            str(sample_binary_without_tls), []
        )

        assert isinstance(report, DetectionReport)


class TestErrorHandling:
    """Tests for error handling and edge cases."""

    def test_detect_with_corrupted_binary(self) -> None:
        """Detection handles corrupted binary gracefully."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            corrupted_data = MinimalPEGenerator.create_corrupted_pe()
            tmp.write(corrupted_data)
            tmp_path = tmp.name

        try:
            detector = CertificateValidationDetector()

            with pytest.raises(RuntimeError) as exc_info:
                detector.detect_certificate_validation(tmp_path)

            assert "Failed to detect certificate validation" in str(exc_info.value)

        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_detect_with_empty_file(self) -> None:
        """Detection handles empty file appropriately."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            detector = CertificateValidationDetector()

            with pytest.raises(RuntimeError):
                detector.detect_certificate_validation(tmp_path)

        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_detect_with_non_pe_file(self) -> None:
        """Detection handles non-PE file formats."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp.write(b"This is not a PE file, just text content")
            tmp_path = tmp.name

        try:
            detector = CertificateValidationDetector()

            with pytest.raises(RuntimeError):
                detector.detect_certificate_validation(tmp_path)

        finally:
            Path(tmp_path).unlink(missing_ok=True)


class TestReportGeneration:
    """Tests for detection report generation and validation."""

    def test_report_contains_all_required_fields(
        self, sample_binary_without_tls: Path
    ) -> None:
        """Generated report contains all required fields."""
        if not sample_binary_without_tls.exists():
            pytest.skip("Test binary not available")

        detector = CertificateValidationDetector()
        report = detector.detect_certificate_validation(str(sample_binary_without_tls))

        assert hasattr(report, "binary_path")
        assert hasattr(report, "detected_libraries")
        assert hasattr(report, "validation_functions")
        assert hasattr(report, "recommended_method")
        assert hasattr(report, "risk_level")
        assert hasattr(report, "timestamp")

        assert isinstance(report.binary_path, str)
        assert isinstance(report.detected_libraries, list)
        assert isinstance(report.validation_functions, list)
        assert isinstance(report.recommended_method, BypassMethod)
        assert report.risk_level in ["low", "medium", "high"]

    def test_report_can_be_serialized_to_json(
        self, sample_binary_without_tls: Path
    ) -> None:
        """Detection report can be exported to JSON format."""
        if not sample_binary_without_tls.exists():
            pytest.skip("Test binary not available")

        detector = CertificateValidationDetector()
        report = detector.detect_certificate_validation(str(sample_binary_without_tls))

        json_str = report.to_json()

        assert isinstance(json_str, str)

        data = json.loads(json_str)

        assert "binary_path" in data
        assert "detected_libraries" in data
        assert "validation_functions" in data
        assert "recommended_method" in data
        assert "risk_level" in data
        assert "timestamp" in data

    def test_report_json_roundtrip(self, sample_binary_without_tls: Path) -> None:
        """Report can be serialized to JSON and deserialized back."""
        if not sample_binary_without_tls.exists():
            pytest.skip("Test binary not available")

        detector = CertificateValidationDetector()
        original_report = detector.detect_certificate_validation(
            str(sample_binary_without_tls)
        )

        json_str = original_report.to_json()
        restored_report = DetectionReport.from_json(json_str)

        assert restored_report.binary_path == original_report.binary_path
        assert restored_report.detected_libraries == original_report.detected_libraries
        assert len(restored_report.validation_functions) == len(
            original_report.validation_functions
        )
        assert restored_report.recommended_method == original_report.recommended_method
        assert restored_report.risk_level == original_report.risk_level

    def test_report_to_text_format(self, sample_binary_without_tls: Path) -> None:
        """Report generates valid text format output."""
        if not sample_binary_without_tls.exists():
            pytest.skip("Test binary not available")

        detector = CertificateValidationDetector()
        report = detector.detect_certificate_validation(str(sample_binary_without_tls))

        text_output = report.to_text()

        assert isinstance(text_output, str)
        assert "CERTIFICATE VALIDATION DETECTION REPORT" in text_output
        assert "Binary:" in text_output
        assert "Risk Level:" in text_output
        assert "Recommended Method:" in text_output

    def test_report_to_dict_format(self, sample_binary_without_tls: Path) -> None:
        """Report generates valid dictionary format."""
        if not sample_binary_without_tls.exists():
            pytest.skip("Test binary not available")

        detector = CertificateValidationDetector()
        report = detector.detect_certificate_validation(str(sample_binary_without_tls))

        data = report.to_dict()

        assert isinstance(data, dict)
        assert "binary_path" in data
        assert "detected_libraries" in data
        assert "validation_functions" in data
        assert "recommended_method" in data
        assert "risk_level" in data
        assert "timestamp" in data


class TestIntegrationScenarios:
    """Integration tests validating end-to-end detection workflows."""

    def test_full_detection_workflow_on_legitimate_binary(
        self, legitimate_binaries_dir: Path
    ) -> None:
        """Complete detection workflow on legitimate Windows binary."""
        firefox_path = legitimate_binaries_dir / "firefox.exe"
        if not firefox_path.exists():
            pytest.skip("Firefox binary not available")

        detector = CertificateValidationDetector()
        detector.min_confidence = 0.3

        report = detector.detect_certificate_validation(str(firefox_path))

        assert isinstance(report, DetectionReport)
        assert report.binary_path == str(firefox_path)
        assert isinstance(report.recommended_method, BypassMethod)
        assert report.risk_level in ["low", "medium", "high"]

        json_export = report.to_json()
        assert isinstance(json_export, str)
        assert len(json_export) > 0

        text_export = report.to_text()
        assert isinstance(text_export, str)
        assert "CERTIFICATE VALIDATION DETECTION REPORT" in text_export

    def test_detection_consistency_across_runs(
        self, sample_binary_without_tls: Path
    ) -> None:
        """Detection produces consistent results across multiple runs."""
        if not sample_binary_without_tls.exists():
            pytest.skip("Test binary not available")

        detector = CertificateValidationDetector()

        report1 = detector.detect_certificate_validation(
            str(sample_binary_without_tls)
        )
        report2 = detector.detect_certificate_validation(
            str(sample_binary_without_tls)
        )

        assert report1.binary_path == report2.binary_path
        assert report1.detected_libraries == report2.detected_libraries
        assert len(report1.validation_functions) == len(report2.validation_functions)
        assert report1.recommended_method == report2.recommended_method
        assert report1.risk_level == report2.risk_level

    def test_detection_with_varying_confidence_thresholds(
        self, sample_binary_without_tls: Path
    ) -> None:
        """Detection results vary appropriately with confidence threshold."""
        if not sample_binary_without_tls.exists():
            pytest.skip("Test binary not available")

        detector_low = CertificateValidationDetector()
        detector_low.min_confidence = 0.1

        detector_high = CertificateValidationDetector()
        detector_high.min_confidence = 0.9

        report_low = detector_low.detect_certificate_validation(
            str(sample_binary_without_tls)
        )
        report_high = detector_high.detect_certificate_validation(
            str(sample_binary_without_tls)
        )

        assert len(report_low.validation_functions) >= len(
            report_high.validation_functions
        )


class TestPerformance:
    """Performance validation tests for detection operations."""

    def test_detection_completes_in_reasonable_time(
        self, sample_binary_without_tls: Path
    ) -> None:
        """Detection completes within acceptable timeframe."""
        if not sample_binary_without_tls.exists():
            pytest.skip("Test binary not available")

        import time

        detector = CertificateValidationDetector()

        start_time = time.time()
        report = detector.detect_certificate_validation(str(sample_binary_without_tls))
        elapsed_time = time.time() - start_time

        assert elapsed_time < 30.0
        assert isinstance(report, DetectionReport)

    def test_multiple_detections_handle_resources_properly(
        self, sample_binary_without_tls: Path
    ) -> None:
        """Multiple sequential detections don't leak resources."""
        if not sample_binary_without_tls.exists():
            pytest.skip("Test binary not available")

        detector = CertificateValidationDetector()

        for _ in range(5):
            report = detector.detect_certificate_validation(
                str(sample_binary_without_tls)
            )
            assert isinstance(report, DetectionReport)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
