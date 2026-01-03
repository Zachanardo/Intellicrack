"""Production tests for detection report data structures.

CRITICAL: These tests validate REAL data structure integrity and serialization.
Tests MUST fail if report generation, JSON export, or querying breaks.

Test Coverage:
- ValidationFunction creation and serialization
- DetectionReport creation and export
- JSON serialization/deserialization
- Dictionary conversion
- Text report generation
- Query methods (high confidence, unique APIs)
- Data integrity validation
"""

import json
from datetime import datetime, timedelta
from typing import Any

import pytest

from intellicrack.core.certificate.detection_report import BypassMethod, DetectionReport, ValidationFunction


class TestValidationFunction:
    """Test ValidationFunction data structure."""

    def test_validation_function_creation(self) -> None:
        """Create ValidationFunction with all fields."""
        func = ValidationFunction(
            address=0x140001234,
            api_name="WinHttpSetOption",
            library="winhttp.dll",
            confidence=0.95,
            context="Located in license check routine",
            references=[0x140005678, 0x14000ABCD],
        )

        assert func.address == 0x140001234
        assert func.api_name == "WinHttpSetOption"
        assert func.library == "winhttp.dll"
        assert func.confidence == 0.95
        assert func.context == "Located in license check routine"
        assert len(func.references) == 2

    def test_validation_function_minimal_creation(self) -> None:
        """Create ValidationFunction with required fields only."""
        func = ValidationFunction(
            address=0x140001000,
            api_name="SSL_CTX_set_verify",
            library="libssl.so",
            confidence=0.80,
        )

        assert func.address == 0x140001000
        assert func.api_name == "SSL_CTX_set_verify"
        assert func.library == "libssl.so"
        assert func.confidence == 0.80
        assert func.context == ""
        assert len(func.references) == 0

    def test_validation_function_to_dict(self) -> None:
        """ValidationFunction converts to dictionary correctly."""
        func = ValidationFunction(
            address=0x7FF1234567,
            api_name="CertVerifyCertificateChainPolicy",
            library="crypt32.dll",
            confidence=0.92,
            context="Called from TLS handshake",
            references=[0x7FF1000000, 0x7FF1000100],
        )

        result = func.to_dict()

        assert isinstance(result, dict)
        assert result["address"] == 0x7FF1234567
        assert result["api_name"] == "CertVerifyCertificateChainPolicy"
        assert result["library"] == "crypt32.dll"
        assert result["confidence"] == 0.92
        assert result["context"] == "Called from TLS handshake"
        assert result["references"] == [0x7FF1000000, 0x7FF1000100]

    def test_validation_function_str_representation(self) -> None:
        """ValidationFunction has readable string representation."""
        func = ValidationFunction(
            address=0x140001234,
            api_name="WinHttpSetOption",
            library="winhttp.dll",
            confidence=0.95,
        )

        str_repr = str(func)

        assert "WinHttpSetOption" in str_repr
        assert "0x140001234" in str_repr
        assert "winhttp.dll" in str_repr
        assert "0.95" in str_repr

    def test_validation_function_empty_references(self) -> None:
        """ValidationFunction handles empty references list."""
        func = ValidationFunction(
            address=0x100000,
            api_name="test_api",
            library="test.dll",
            confidence=0.5,
        )

        assert isinstance(func.references, list)
        assert len(func.references) == 0

    def test_validation_function_with_zero_confidence(self) -> None:
        """ValidationFunction accepts zero confidence."""
        func = ValidationFunction(
            address=0x100000,
            api_name="unknown_api",
            library="unknown.dll",
            confidence=0.0,
        )

        assert func.confidence == 0.0


class TestBypassMethod:
    """Test BypassMethod enum."""

    def test_bypass_method_values(self) -> None:
        """BypassMethod enum has correct values."""
        assert BypassMethod.BINARY_PATCH.value == "binary_patch"
        assert BypassMethod.FRIDA_HOOK.value == "frida_hook"
        assert BypassMethod.HYBRID.value == "hybrid"
        assert BypassMethod.MITM_PROXY.value == "mitm_proxy"
        assert BypassMethod.NONE.value == "none"

    def test_bypass_method_from_string(self) -> None:
        """BypassMethod can be created from string value."""
        method = BypassMethod("frida_hook")
        assert method == BypassMethod.FRIDA_HOOK

    def test_bypass_method_comparison(self) -> None:
        """BypassMethod enum members are comparable."""
        assert BypassMethod.BINARY_PATCH == BypassMethod.BINARY_PATCH
        assert BypassMethod.FRIDA_HOOK != BypassMethod.BINARY_PATCH


class TestDetectionReport:
    """Test DetectionReport data structure."""

    @pytest.fixture
    def sample_functions(self) -> list[ValidationFunction]:
        """Create sample validation functions."""
        return [
            ValidationFunction(
                address=0x140001000,
                api_name="WinHttpSetOption",
                library="winhttp.dll",
                confidence=0.95,
                context="License validation",
                references=[0x140002000],
            ),
            ValidationFunction(
                address=0x140001500,
                api_name="WinHttpSendRequest",
                library="winhttp.dll",
                confidence=0.90,
                context="Network communication",
                references=[0x140002100, 0x140002200],
            ),
            ValidationFunction(
                address=0x140002000,
                api_name="SSL_CTX_set_verify",
                library="libssl.so",
                confidence=0.85,
                context="SSL setup",
                references=[],
            ),
        ]

    def test_detection_report_creation(self, sample_functions: list[ValidationFunction]) -> None:
        """Create DetectionReport with all fields."""
        report = DetectionReport(
            binary_path="C:/Program Files/App/target.exe",
            detected_libraries=["winhttp.dll", "crypt32.dll", "libssl.so"],
            validation_functions=sample_functions,
            recommended_method=BypassMethod.FRIDA_HOOK,
            risk_level="medium",
        )

        assert report.binary_path == "C:/Program Files/App/target.exe"
        assert len(report.detected_libraries) == 3
        assert len(report.validation_functions) == 3
        assert report.recommended_method == BypassMethod.FRIDA_HOOK
        assert report.risk_level == "medium"
        assert isinstance(report.timestamp, datetime)

    def test_detection_report_to_dict(self, sample_functions: list[ValidationFunction]) -> None:
        """DetectionReport converts to dictionary correctly."""
        report = DetectionReport(
            binary_path="/usr/bin/protected_app",
            detected_libraries=["libssl.so.1.1"],
            validation_functions=sample_functions,
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
        )

        result = report.to_dict()

        assert isinstance(result, dict)
        assert result["binary_path"] == "/usr/bin/protected_app"
        assert result["detected_libraries"] == ["libssl.so.1.1"]
        assert len(result["validation_functions"]) == 3
        assert result["recommended_method"] == "binary_patch"
        assert result["risk_level"] == "low"
        assert "timestamp" in result

    def test_detection_report_to_json(self, sample_functions: list[ValidationFunction]) -> None:
        """DetectionReport exports valid JSON."""
        report = DetectionReport(
            binary_path="/home/user/app",
            detected_libraries=["libcrypto.so"],
            validation_functions=sample_functions,
            recommended_method=BypassMethod.HYBRID,
            risk_level="high",
        )

        json_str = report.to_json()

        assert isinstance(json_str, str)

        parsed = json.loads(json_str)
        assert parsed["binary_path"] == "/home/user/app"
        assert parsed["detected_libraries"] == ["libcrypto.so"]
        assert parsed["recommended_method"] == "hybrid"
        assert parsed["risk_level"] == "high"
        assert len(parsed["validation_functions"]) == 3

    def test_detection_report_from_dict(self, sample_functions: list[ValidationFunction]) -> None:
        """DetectionReport can be created from dictionary."""
        original = DetectionReport(
            binary_path="/path/to/binary",
            detected_libraries=["lib1.so", "lib2.so"],
            validation_functions=sample_functions,
            recommended_method=BypassMethod.FRIDA_HOOK,
            risk_level="medium",
        )

        data = original.to_dict()
        restored = DetectionReport.from_dict(data)

        assert restored.binary_path == original.binary_path
        assert restored.detected_libraries == original.detected_libraries
        assert len(restored.validation_functions) == len(original.validation_functions)
        assert restored.recommended_method == original.recommended_method
        assert restored.risk_level == original.risk_level

    def test_detection_report_from_json(self, sample_functions: list[ValidationFunction]) -> None:
        """DetectionReport can be created from JSON string."""
        original = DetectionReport(
            binary_path="/usr/local/bin/app",
            detected_libraries=["ssl", "crypto"],
            validation_functions=sample_functions,
            recommended_method=BypassMethod.MITM_PROXY,
            risk_level="low",
        )

        json_str = original.to_json()
        restored = DetectionReport.from_json(json_str)

        assert restored.binary_path == original.binary_path
        assert restored.detected_libraries == original.detected_libraries
        assert len(restored.validation_functions) == len(original.validation_functions)
        assert restored.recommended_method == original.recommended_method

    def test_detection_report_to_text(self, sample_functions: list[ValidationFunction]) -> None:
        """DetectionReport generates readable text report."""
        report = DetectionReport(
            binary_path="C:/Test/app.exe",
            detected_libraries=["winhttp.dll"],
            validation_functions=sample_functions[:2],
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="high",
        )

        text = report.to_text()

        assert isinstance(text, str)
        assert "CERTIFICATE VALIDATION DETECTION REPORT" in text
        assert "C:/Test/app.exe" in text
        assert "HIGH" in text
        assert "binary_patch" in text
        assert "winhttp.dll" in text
        assert "WinHttpSetOption" in text
        assert "0x140001000" in text

    def test_detection_report_has_validation(self, sample_functions: list[ValidationFunction]) -> None:
        """has_validation method detects presence of validation functions."""
        report_with_validation = DetectionReport(
            binary_path="/path/to/app",
            detected_libraries=[],
            validation_functions=sample_functions,
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        report_without_validation = DetectionReport(
            binary_path="/path/to/app",
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        assert report_with_validation.has_validation() is True
        assert report_without_validation.has_validation() is False

    def test_detection_report_get_high_confidence_functions(
        self,
        sample_functions: list[ValidationFunction],
    ) -> None:
        """get_high_confidence_functions filters by threshold."""
        report = DetectionReport(
            binary_path="/app",
            detected_libraries=[],
            validation_functions=sample_functions,
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        high_confidence = report.get_high_confidence_functions(threshold=0.90)

        assert len(high_confidence) == 2
        assert all(func.confidence >= 0.90 for func in high_confidence)

        very_high_confidence = report.get_high_confidence_functions(threshold=0.95)

        assert len(very_high_confidence) == 1
        assert very_high_confidence[0].confidence >= 0.95

    def test_detection_report_get_unique_apis(
        self,
        sample_functions: list[ValidationFunction],
    ) -> None:
        """get_unique_apis returns list of unique API names."""
        report = DetectionReport(
            binary_path="/app",
            detected_libraries=[],
            validation_functions=sample_functions,
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        apis = report.get_unique_apis()

        assert isinstance(apis, list)
        assert "WinHttpSetOption" in apis
        assert "WinHttpSendRequest" in apis
        assert "SSL_CTX_set_verify" in apis
        assert len(apis) == 3

    def test_detection_report_get_unique_libraries(
        self,
        sample_functions: list[ValidationFunction],
    ) -> None:
        """get_unique_libraries returns list of unique library names."""
        report = DetectionReport(
            binary_path="/app",
            detected_libraries=[],
            validation_functions=sample_functions,
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        libraries = report.get_unique_libraries()

        assert isinstance(libraries, list)
        assert "winhttp.dll" in libraries
        assert "libssl.so" in libraries
        assert len(libraries) == 2

    def test_detection_report_empty_validation_functions(self) -> None:
        """DetectionReport handles empty validation functions."""
        report = DetectionReport(
            binary_path="/app",
            detected_libraries=["lib.so"],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        assert report.has_validation() is False
        assert len(report.get_unique_apis()) == 0
        assert len(report.get_unique_libraries()) == 0
        assert len(report.get_high_confidence_functions()) == 0

    def test_detection_report_serialization_roundtrip(
        self,
        sample_functions: list[ValidationFunction],
    ) -> None:
        """DetectionReport survives JSON serialization roundtrip."""
        original = DetectionReport(
            binary_path="/complex/path/to/binary.exe",
            detected_libraries=["lib1.dll", "lib2.so", "lib3.dylib"],
            validation_functions=sample_functions,
            recommended_method=BypassMethod.HYBRID,
            risk_level="medium",
        )

        json_str = original.to_json()
        restored = DetectionReport.from_json(json_str)

        assert restored.binary_path == original.binary_path
        assert restored.detected_libraries == original.detected_libraries
        assert len(restored.validation_functions) == len(original.validation_functions)
        assert restored.recommended_method == original.recommended_method
        assert restored.risk_level == original.risk_level

        for original_func, restored_func in zip(
            original.validation_functions,
            restored.validation_functions,
        ):
            assert restored_func.address == original_func.address
            assert restored_func.api_name == original_func.api_name
            assert restored_func.library == original_func.library
            assert restored_func.confidence == original_func.confidence

    def test_detection_report_invalid_bypass_method_defaults_to_none(self) -> None:
        """DetectionReport handles invalid bypass method gracefully."""
        data: dict[str, Any] = {
            "binary_path": "/app",
            "detected_libraries": [],
            "validation_functions": [],
            "recommended_method": "invalid_method",
            "risk_level": "low",
        }

        report = DetectionReport.from_dict(data)

        assert report.recommended_method == BypassMethod.NONE

    def test_detection_report_text_format_includes_all_sections(
        self,
        sample_functions: list[ValidationFunction],
    ) -> None:
        """Text report includes all required sections."""
        report = DetectionReport(
            binary_path="/path/to/app",
            detected_libraries=["winhttp.dll", "crypt32.dll"],
            validation_functions=sample_functions,
            recommended_method=BypassMethod.FRIDA_HOOK,
            risk_level="high",
        )

        text = report.to_text()

        assert "Binary:" in text
        assert "Timestamp:" in text
        assert "Risk Level:" in text
        assert "Recommended Method:" in text
        assert "DETECTED TLS LIBRARIES:" in text
        assert "DETECTED VALIDATION FUNCTIONS:" in text

        for func in sample_functions:
            assert func.api_name in text
            assert func.library in text

    def test_detection_report_text_truncates_long_context(self) -> None:
        """Text report truncates very long context strings."""
        long_context = "x" * 500

        func = ValidationFunction(
            address=0x100000,
            api_name="test_api",
            library="test.dll",
            confidence=0.8,
            context=long_context,
        )

        report = DetectionReport(
            binary_path="/app",
            detected_libraries=[],
            validation_functions=[func],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        text = report.to_text()

        assert "..." in text
        assert len(text) < len(long_context) + 1000

    def test_detection_report_missing_timestamp_uses_current_time(self) -> None:
        """DetectionReport without timestamp uses current time."""
        data: dict[str, Any] = {
            "binary_path": "/app",
            "detected_libraries": [],
            "validation_functions": [],
            "recommended_method": "none",
            "risk_level": "low",
        }

        report = DetectionReport.from_dict(data)

        assert isinstance(report.timestamp, datetime)
        time_diff: timedelta = datetime.now() - report.timestamp
        assert time_diff.total_seconds() < 5


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_validation_function_with_very_high_confidence(self) -> None:
        """ValidationFunction accepts confidence above 1.0 (though unusual)."""
        func = ValidationFunction(
            address=0x100000,
            api_name="test",
            library="test.dll",
            confidence=1.5,
        )

        assert func.confidence == 1.5

    def test_validation_function_with_negative_confidence(self) -> None:
        """ValidationFunction accepts negative confidence (though unusual)."""
        func = ValidationFunction(
            address=0x100000,
            api_name="test",
            library="test.dll",
            confidence=-0.5,
        )

        assert func.confidence == -0.5

    def test_detection_report_with_duplicate_libraries(self) -> None:
        """DetectionReport handles duplicate library names."""
        report = DetectionReport(
            binary_path="/app",
            detected_libraries=["lib.so", "lib.so", "lib.so"],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        assert len(report.detected_libraries) == 3

    def test_detection_report_get_high_confidence_with_zero_threshold(self) -> None:
        """get_high_confidence_functions with zero threshold returns all."""
        functions = [
            ValidationFunction(0x1000, "api1", "lib.dll", 0.1),
            ValidationFunction(0x2000, "api2", "lib.dll", 0.5),
            ValidationFunction(0x3000, "api3", "lib.dll", 0.9),
        ]

        report = DetectionReport(
            binary_path="/app",
            detected_libraries=[],
            validation_functions=functions,
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        high_conf = report.get_high_confidence_functions(threshold=0.0)

        assert len(high_conf) == 3

    def test_detection_report_get_high_confidence_with_threshold_above_all(self) -> None:
        """get_high_confidence_functions with high threshold returns none."""
        functions = [
            ValidationFunction(0x1000, "api1", "lib.dll", 0.1),
            ValidationFunction(0x2000, "api2", "lib.dll", 0.5),
            ValidationFunction(0x3000, "api3", "lib.dll", 0.9),
        ]

        report = DetectionReport(
            binary_path="/app",
            detected_libraries=[],
            validation_functions=functions,
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        high_conf = report.get_high_confidence_functions(threshold=1.0)

        assert len(high_conf) == 0
