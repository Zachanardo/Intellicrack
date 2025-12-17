"""Production tests for detection report data structures and serialization.

Tests validate real data structure integrity, JSON serialization/deserialization,
dictionary conversion, text report generation, and query functionality.
"""

import json
import pytest
from datetime import datetime, timedelta

from intellicrack.core.certificate.detection_report import (
    BypassMethod,
    DetectionReport,
    ValidationFunction,
)


class TestValidationFunctionDataStructure:
    """Tests validating ValidationFunction data structure and methods."""

    def test_validation_function_creation_with_all_fields(self) -> None:
        """ValidationFunction stores all provided fields correctly."""
        func = ValidationFunction(
            address=0x140001000,
            api_name="CertVerifyCertificateChainPolicy",
            library="crypt32.dll",
            confidence=0.95,
            context="Located in license validation routine near serial check",
            references=[0x140002000, 0x140003000, 0x140004000],
        )

        assert func.address == 0x140001000
        assert func.api_name == "CertVerifyCertificateChainPolicy"
        assert func.library == "crypt32.dll"
        assert func.confidence == 0.95
        assert func.context == "Located in license validation routine near serial check"
        assert len(func.references) == 3

    def test_validation_function_to_dict_conversion(self) -> None:
        """ValidationFunction converts to dictionary correctly."""
        func = ValidationFunction(
            address=0x401000,
            api_name="SSL_CTX_set_verify",
            library="libssl.so.1.1",
            confidence=0.88,
            context="OpenSSL callback setup",
            references=[0x402000],
        )

        func_dict = func.to_dict()

        assert func_dict["address"] == 0x401000
        assert func_dict["api_name"] == "SSL_CTX_set_verify"
        assert func_dict["library"] == "libssl.so.1.1"
        assert func_dict["confidence"] == 0.88
        assert func_dict["context"] == "OpenSSL callback setup"
        assert func_dict["references"] == [0x402000]

    def test_validation_function_string_representation(self) -> None:
        """ValidationFunction produces readable string representation."""
        func = ValidationFunction(
            address=0x140001234,
            api_name="WinHttpSetOption",
            library="winhttp.dll",
            confidence=0.92,
            context="Network validation",
            references=[0x140005678],
        )

        str_repr = str(func)

        assert "WinHttpSetOption" in str_repr
        assert "0x140001234" in str_repr
        assert "winhttp.dll" in str_repr
        assert "0.92" in str_repr

    def test_validation_function_with_minimal_fields(self) -> None:
        """ValidationFunction works with minimal required fields."""
        func = ValidationFunction(
            address=0x401000,
            api_name="ValidateFunc",
            library="app.dll",
            confidence=0.75,
        )

        assert func.context == ""
        assert func.references == []


class TestDetectionReportCreation:
    """Tests validating DetectionReport creation and field storage."""

    def test_detection_report_creation_with_complete_data(self) -> None:
        """DetectionReport stores complete detection data correctly."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="CertVerifyCertificateChainPolicy",
                library="crypt32.dll",
                confidence=0.93,
                context="Main validation",
                references=[0x402000],
            ),
            ValidationFunction(
                address=0x405000,
                api_name="CertGetCertificateChain",
                library="crypt32.dll",
                confidence=0.89,
                context="Chain building",
                references=[0x406000, 0x407000],
            ),
        ]

        report = DetectionReport(
            binary_path="C:\\Program Files\\App\\protected.exe",
            detected_libraries=["crypt32.dll", "sspicli.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
        )

        assert report.binary_path == "C:\\Program Files\\App\\protected.exe"
        assert len(report.detected_libraries) == 2
        assert len(report.validation_functions) == 2
        assert report.recommended_method == BypassMethod.BINARY_PATCH
        assert report.risk_level == "low"
        assert isinstance(report.timestamp, datetime)

    def test_detection_report_with_no_validation_functions(self) -> None:
        """DetectionReport handles empty validation function list."""
        report = DetectionReport(
            binary_path="no_validation.exe",
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        assert len(report.validation_functions) == 0
        assert report.has_validation() is False
        assert report.recommended_method == BypassMethod.NONE


class TestJSONSerialization:
    """Tests validating JSON export and import functionality."""

    def test_detection_report_to_json_serialization(self) -> None:
        """DetectionReport serializes to valid JSON."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="SSL_CTX_set_verify",
                library="libssl.so",
                confidence=0.91,
                context="SSL verification",
                references=[0x402000],
            ),
        ]

        report = DetectionReport(
            binary_path="/usr/bin/app",
            detected_libraries=["libssl.so"],
            validation_functions=funcs,
            recommended_method=BypassMethod.FRIDA_HOOK,
            risk_level="medium",
        )

        json_str = report.to_json()

        assert isinstance(json_str, str)

        parsed = json.loads(json_str)

        assert parsed["binary_path"] == "/usr/bin/app"
        assert len(parsed["detected_libraries"]) == 1
        assert len(parsed["validation_functions"]) == 1
        assert parsed["recommended_method"] == "frida_hook"
        assert parsed["risk_level"] == "medium"

    def test_detection_report_from_json_deserialization(self) -> None:
        """DetectionReport deserializes from JSON correctly."""
        json_data = {
            "binary_path": "app.exe",
            "detected_libraries": ["crypt32.dll"],
            "validation_functions": [
                {
                    "address": 0x401000,
                    "api_name": "CertVerifyCertificateChainPolicy",
                    "library": "crypt32.dll",
                    "confidence": 0.95,
                    "context": "Validation routine",
                    "references": [0x402000],
                }
            ],
            "recommended_method": "binary_patch",
            "risk_level": "low",
            "timestamp": "2025-01-15T10:30:00",
        }

        json_str = json.dumps(json_data)
        report = DetectionReport.from_json(json_str)

        assert report.binary_path == "app.exe"
        assert len(report.validation_functions) == 1
        assert report.validation_functions[0].api_name == "CertVerifyCertificateChainPolicy"
        assert report.recommended_method == BypassMethod.BINARY_PATCH
        assert report.risk_level == "low"

    def test_json_roundtrip_preserves_data(self) -> None:
        """JSON serialization and deserialization preserves all data."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="ValidateFunc",
                library="app.dll",
                confidence=0.87,
                context="Test context",
                references=[0x402000, 0x403000],
            ),
        ]

        original_report = DetectionReport(
            binary_path="test.exe",
            detected_libraries=["app.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.HYBRID,
            risk_level="medium",
        )

        json_str = original_report.to_json()
        restored_report = DetectionReport.from_json(json_str)

        assert restored_report.binary_path == original_report.binary_path
        assert len(restored_report.validation_functions) == len(original_report.validation_functions)
        assert restored_report.validation_functions[0].address == original_report.validation_functions[0].address
        assert restored_report.recommended_method == original_report.recommended_method
        assert restored_report.risk_level == original_report.risk_level


class TestDictionaryConversion:
    """Tests validating dictionary export and import functionality."""

    def test_detection_report_to_dict_conversion(self) -> None:
        """DetectionReport converts to dictionary correctly."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="TestFunc",
                library="test.dll",
                confidence=0.80,
                context="Context",
                references=[],
            ),
        ]

        report = DetectionReport(
            binary_path="test.exe",
            detected_libraries=["test.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
        )

        report_dict = report.to_dict()

        assert isinstance(report_dict, dict)
        assert report_dict["binary_path"] == "test.exe"
        assert isinstance(report_dict["validation_functions"], list)
        assert len(report_dict["validation_functions"]) == 1
        assert report_dict["recommended_method"] == "binary_patch"

    def test_detection_report_from_dict_construction(self) -> None:
        """DetectionReport constructs from dictionary correctly."""
        data = {
            "binary_path": "app.exe",
            "detected_libraries": ["lib1.dll", "lib2.dll"],
            "validation_functions": [
                {
                    "address": 0x401000,
                    "api_name": "Func1",
                    "library": "lib1.dll",
                    "confidence": 0.85,
                    "context": "",
                    "references": [],
                }
            ],
            "recommended_method": "frida_hook",
            "risk_level": "medium",
            "timestamp": "2025-01-15T12:00:00",
        }

        report = DetectionReport.from_dict(data)

        assert report.binary_path == "app.exe"
        assert len(report.detected_libraries) == 2
        assert len(report.validation_functions) == 1
        assert report.recommended_method == BypassMethod.FRIDA_HOOK


class TestTextReportGeneration:
    """Tests validating human-readable text report generation."""

    def test_text_report_generation_complete_report(self) -> None:
        """Text report generates complete human-readable output."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="CertVerifyCertificateChainPolicy",
                library="crypt32.dll",
                confidence=0.93,
                context="Primary certificate validation in license check routine",
                references=[0x402000, 0x403000],
            ),
        ]

        report = DetectionReport(
            binary_path="protected_app.exe",
            detected_libraries=["crypt32.dll", "sspicli.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
        )

        text = report.to_text()

        assert "CERTIFICATE VALIDATION DETECTION REPORT" in text
        assert "protected_app.exe" in text
        assert "binary_patch" in text
        assert "LOW" in text
        assert "crypt32.dll" in text
        assert "sspicli.dll" in text
        assert "CertVerifyCertificateChainPolicy" in text
        assert "0x00401000" in text
        assert "93%" in text

    def test_text_report_with_long_context_truncation(self) -> None:
        """Text report truncates long context strings."""
        long_context = "A" * 250

        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="ValidateFunc",
                library="app.dll",
                confidence=0.85,
                context=long_context,
                references=[],
            ),
        ]

        report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=["app.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.FRIDA_HOOK,
            risk_level="medium",
        )

        text = report.to_text()

        assert "..." in text
        assert len([line for line in text.split("\n") if "Context:" in line][0]) < 300

    def test_text_report_with_no_libraries(self) -> None:
        """Text report handles no detected libraries."""
        report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        text = report.to_text()

        assert "(none)" in text

    def test_text_report_with_no_functions(self) -> None:
        """Text report handles no validation functions."""
        report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=["crypt32.dll"],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        text = report.to_text()

        assert "(none detected)" in text


class TestQueryFunctionality:
    """Tests validating report query methods."""

    def test_get_high_confidence_functions_with_default_threshold(self) -> None:
        """Get high confidence functions with default 0.7 threshold."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="HighConfidence",
                library="app.dll",
                confidence=0.95,
                context="",
                references=[],
            ),
            ValidationFunction(
                address=0x402000,
                api_name="MediumConfidence",
                library="app.dll",
                confidence=0.65,
                context="",
                references=[],
            ),
            ValidationFunction(
                address=0x403000,
                api_name="LowConfidence",
                library="app.dll",
                confidence=0.30,
                context="",
                references=[],
            ),
        ]

        report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=["app.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
        )

        high_conf = report.get_high_confidence_functions()

        assert len(high_conf) == 1
        assert high_conf[0].api_name == "HighConfidence"

    def test_get_high_confidence_functions_with_custom_threshold(self) -> None:
        """Get high confidence functions with custom threshold."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="Func1",
                library="app.dll",
                confidence=0.95,
                context="",
                references=[],
            ),
            ValidationFunction(
                address=0x402000,
                api_name="Func2",
                library="app.dll",
                confidence=0.85,
                context="",
                references=[],
            ),
            ValidationFunction(
                address=0x403000,
                api_name="Func3",
                library="app.dll",
                confidence=0.75,
                context="",
                references=[],
            ),
        ]

        report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=["app.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
        )

        high_conf = report.get_high_confidence_functions(threshold=0.80)

        assert len(high_conf) == 2
        assert all(func.confidence >= 0.80 for func in high_conf)

    def test_has_validation_returns_true_when_functions_present(self) -> None:
        """has_validation returns True when functions are present."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="ValidateFunc",
                library="app.dll",
                confidence=0.85,
                context="",
                references=[],
            ),
        ]

        report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=["app.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
        )

        assert report.has_validation() is True

    def test_has_validation_returns_false_when_no_functions(self) -> None:
        """has_validation returns False when no functions detected."""
        report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        assert report.has_validation() is False

    def test_get_unique_apis_returns_distinct_api_names(self) -> None:
        """get_unique_apis returns distinct API names."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="CertVerify",
                library="crypt32.dll",
                confidence=0.90,
                context="",
                references=[],
            ),
            ValidationFunction(
                address=0x402000,
                api_name="CertVerify",
                library="crypt32.dll",
                confidence=0.85,
                context="",
                references=[],
            ),
            ValidationFunction(
                address=0x403000,
                api_name="SSL_CTX_set_verify",
                library="libssl.so",
                confidence=0.88,
                context="",
                references=[],
            ),
        ]

        report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=["crypt32.dll", "libssl.so"],
            validation_functions=funcs,
            recommended_method=BypassMethod.HYBRID,
            risk_level="medium",
        )

        unique_apis = report.get_unique_apis()

        assert len(unique_apis) == 2
        assert "CertVerify" in unique_apis
        assert "SSL_CTX_set_verify" in unique_apis

    def test_get_unique_libraries_returns_distinct_libraries(self) -> None:
        """get_unique_libraries returns distinct library names."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="Func1",
                library="crypt32.dll",
                confidence=0.90,
                context="",
                references=[],
            ),
            ValidationFunction(
                address=0x402000,
                api_name="Func2",
                library="crypt32.dll",
                confidence=0.85,
                context="",
                references=[],
            ),
            ValidationFunction(
                address=0x403000,
                api_name="Func3",
                library="libssl.so",
                confidence=0.88,
                context="",
                references=[],
            ),
            ValidationFunction(
                address=0x404000,
                api_name="Func4",
                library="libnss3.so",
                confidence=0.82,
                context="",
                references=[],
            ),
        ]

        report = DetectionReport(
            binary_path="app",
            detected_libraries=["crypt32.dll", "libssl.so", "libnss3.so"],
            validation_functions=funcs,
            recommended_method=BypassMethod.HYBRID,
            risk_level="high",
        )

        unique_libs = report.get_unique_libraries()

        assert len(unique_libs) == 3
        assert "crypt32.dll" in unique_libs
        assert "libssl.so" in unique_libs
        assert "libnss3.so" in unique_libs


class TestBypassMethodEnum:
    """Tests validating BypassMethod enum values."""

    def test_bypass_method_enum_values(self) -> None:
        """BypassMethod enum contains expected values."""
        assert BypassMethod.BINARY_PATCH.value == "binary_patch"
        assert BypassMethod.FRIDA_HOOK.value == "frida_hook"
        assert BypassMethod.HYBRID.value == "hybrid"
        assert BypassMethod.MITM_PROXY.value == "mitm_proxy"
        assert BypassMethod.NONE.value == "none"

    def test_bypass_method_from_string(self) -> None:
        """BypassMethod can be constructed from string value."""
        method = BypassMethod("binary_patch")
        assert method == BypassMethod.BINARY_PATCH

        method2 = BypassMethod("frida_hook")
        assert method2 == BypassMethod.FRIDA_HOOK
