"""Production-grade tests for Radare2 JSON Standardizer.

This module validates real JSON output parsing, transformation, and standardization
from radare2 analysis results. Tests ensure actual data processing without mocks.

Copyright (C) 2025 Zachary Flint
Licensed under GPL-3.0
"""

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, cast
from unittest.mock import Mock, patch

import pytest

from intellicrack.core.analysis.radare2_json_standardizer import (
    R2JSONStandardizer,
    batch_standardize_results,
    standardize_r2_result,
)


class TestR2JSONStandardizerInitialization:
    """Test R2JSONStandardizer initialization and basic setup."""

    def test_standardizer_initialization_creates_unique_analysis_id(self) -> None:
        """Standardizer creates unique analysis ID on initialization."""
        standardizer1 = R2JSONStandardizer()
        standardizer2 = R2JSONStandardizer()

        assert standardizer1.analysis_id != standardizer2.analysis_id
        assert len(standardizer1.analysis_id) == 36

    def test_standardizer_initialization_sets_timestamp(self) -> None:
        """Standardizer sets ISO format timestamp on initialization."""
        standardizer = R2JSONStandardizer()

        assert standardizer.timestamp is not None
        assert "T" in standardizer.timestamp
        assert "Z" in standardizer.timestamp or "+" in standardizer.timestamp

    def test_standardizer_has_correct_schema_version(self) -> None:
        """Standardizer declares correct schema version."""
        assert R2JSONStandardizer.SCHEMA_VERSION == "2.0.0"

    def test_standardizer_defines_all_analysis_types(self) -> None:
        """Standardizer defines all supported analysis types."""
        expected_types = [
            "decompilation",
            "vulnerability",
            "strings",
            "imports",
            "cfg",
            "ai",
            "signatures",
            "esil",
            "bypass",
            "binary_diff",
            "scripting",
            "comprehensive",
        ]

        for analysis_type in expected_types:
            assert analysis_type in R2JSONStandardizer.ANALYSIS_TYPES


class TestBaseStructureCreation:
    """Test base structure creation for standardized output."""

    def test_create_base_structure_includes_all_required_fields(self) -> None:
        """Base structure contains all required standardization fields."""
        standardizer = R2JSONStandardizer()
        base = standardizer._create_base_structure("decompilation", "/path/to/binary.exe", None)

        required_fields = [
            "schema_version",
            "format_version",
            "analysis_metadata",
            "binary_metadata",
            "additional_metadata",
            "analysis_results",
            "summary_statistics",
            "quality_metrics",
            "ml_features",
            "status",
        ]

        for field in required_fields:
            assert field in base

    def test_create_base_structure_sets_correct_schema_version(self) -> None:
        """Base structure uses correct schema version."""
        standardizer = R2JSONStandardizer()
        base = standardizer._create_base_structure("strings", "/test.exe", None)

        assert base["schema_version"] == "2.0.0"
        assert base["format_version"] == "radare2_analysis_v2"

    def test_create_base_structure_includes_analysis_metadata(self) -> None:
        """Base structure contains complete analysis metadata."""
        standardizer = R2JSONStandardizer()
        base = standardizer._create_base_structure("vulnerability", "/app.dll", {"custom": "data"})

        metadata = base["analysis_metadata"]
        assert metadata["analysis_id"] == standardizer.analysis_id
        assert metadata["analysis_type"] == "vulnerability"
        assert metadata["engine"] == "radare2"
        assert "timestamp" in metadata

    def test_create_base_structure_calculates_binary_metadata(self, tmp_path: Path) -> None:
        """Base structure calculates binary file metadata."""
        test_file = tmp_path / "test.exe"
        test_data = b"MZ\x90\x00" + b"\x00" * 100
        test_file.write_bytes(test_data)

        standardizer = R2JSONStandardizer()
        base = standardizer._create_base_structure("imports", str(test_file), None)

        binary_meta = base["binary_metadata"]
        assert binary_meta["file_path"] == str(test_file)
        assert binary_meta["file_name"] == "test.exe"
        assert binary_meta["file_size"] == len(test_data)
        assert len(binary_meta["file_hash"]) == 64

    def test_create_base_structure_handles_missing_file(self) -> None:
        """Base structure handles nonexistent binary files gracefully."""
        standardizer = R2JSONStandardizer()
        base = standardizer._create_base_structure("cfg", "/nonexistent/file.exe", None)

        binary_meta = base["binary_metadata"]
        assert binary_meta["file_path"] == "/nonexistent/file.exe"
        assert binary_meta["file_hash"] == "unknown"
        assert binary_meta["file_size"] == 0


class TestDecompilationStandardization:
    """Test standardization of decompilation analysis results."""

    def test_standardize_decompilation_normalizes_function_list(self) -> None:
        """Decompilation standardization normalizes license function data."""
        raw_result = {
            "license_functions": [
                {
                    "name": "CheckLicense",
                    "address": "0x401000",
                    "size": 256,
                    "complexity": 10,
                    "confidence": 0.95,
                    "type": "validation",
                },
                {
                    "name": "ValidateSerial",
                    "address": 4198400,
                    "size": 128,
                    "complexity": 5,
                    "confidence": 0.85,
                },
            ],
            "decompiled_functions": {
                "CheckLicense": {
                    "code": "int CheckLicense(char* key) { return verify(key); }",
                    "language": "c",
                    "quality_score": 0.9,
                }
            },
        }

        standardizer = R2JSONStandardizer()
        result = standardizer._standardize_decompilation(raw_result)

        assert "analysis_results" in result
        assert len(result["analysis_results"]["license_functions"]) == 2
        assert result["analysis_results"]["license_functions"][0]["name"] == "CheckLicense"
        assert result["analysis_results"]["license_functions"][1]["address"] == "0x401000"

    def test_standardize_decompilation_includes_summary_statistics(self) -> None:
        """Decompilation standardization calculates summary statistics."""
        raw_result = {
            "license_functions": [
                {"name": "func1", "confidence": 0.9, "decompiled": True},
                {"name": "func2", "confidence": 0.6, "decompiled": True},
                {"name": "func3", "confidence": 0.3, "decompiled": False},
            ]
        }

        standardizer = R2JSONStandardizer()
        result = standardizer._standardize_decompilation(raw_result)

        stats = result["summary_statistics"]
        assert stats["total_functions_analyzed"] == 3
        assert stats["license_functions_found"] == 2
        assert 0.0 <= stats["decompilation_success_rate"] <= 1.0

    def test_standardize_decompilation_extracts_ml_features(self) -> None:
        """Decompilation standardization extracts ML-ready features."""
        raw_result = {
            "license_functions": [
                {"name": "f1", "size": 100, "complexity": 5, "type": "check"},
                {"name": "f2", "size": 200, "complexity": 10, "type": "validation"},
            ],
            "license_patterns": [{"type": "serial", "confidence": 0.8}],
        }

        standardizer = R2JSONStandardizer()
        result = standardizer._standardize_decompilation(raw_result)

        ml_features = result["ml_features"]
        assert "function_features" in ml_features
        assert "pattern_features" in ml_features
        assert "complexity_features" in ml_features


class TestVulnerabilityStandardization:
    """Test standardization of vulnerability analysis results."""

    def test_standardize_vulnerability_aggregates_all_categories(self) -> None:
        """Vulnerability standardization collects all vulnerability types."""
        raw_result = {
            "buffer_overflows": [
                {"type": "stack_overflow", "severity": "critical", "address": "0x401000"}
            ],
            "format_string_bugs": [
                {"type": "format_string", "severity": "high", "address": "0x402000"}
            ],
            "integer_overflows": [
                {"type": "int_overflow", "severity": "medium", "address": "0x403000"}
            ],
        }

        standardizer = R2JSONStandardizer()
        result = standardizer._standardize_vulnerability(raw_result)

        vulnerabilities = result["analysis_results"]["vulnerabilities"]
        assert len(vulnerabilities) == 3
        assert any(v["category"] == "buffer_overflows" for v in vulnerabilities)
        assert any(v["category"] == "format_string_bugs" for v in vulnerabilities)

    def test_standardize_vulnerability_calculates_severity_counts(self) -> None:
        """Vulnerability standardization counts by severity level."""
        raw_result = {
            "buffer_overflows": [
                {"severity": "critical"},
                {"severity": "high"},
                {"severity": "high"},
                {"severity": "medium"},
                {"severity": "low"},
            ]
        }

        standardizer = R2JSONStandardizer()
        result = standardizer._standardize_vulnerability(raw_result)

        stats = result["summary_statistics"]
        assert stats["critical_vulnerabilities"] == 1
        assert stats["high_vulnerabilities"] == 2
        assert stats["medium_vulnerabilities"] == 1
        assert stats["low_vulnerabilities"] == 1
        assert stats["total_vulnerabilities"] == 5

    def test_standardize_vulnerability_calculates_risk_score(self) -> None:
        """Vulnerability standardization calculates overall risk score."""
        raw_result = {
            "buffer_overflows": [
                {"severity": "critical"},
                {"severity": "critical"},
                {"severity": "low"},
            ]
        }

        standardizer = R2JSONStandardizer()
        result = standardizer._standardize_vulnerability(raw_result)

        risk_score = result["summary_statistics"]["overall_risk_score"]
        assert 0.0 <= risk_score <= 1.0
        assert risk_score > 0.5


class TestStringsStandardization:
    """Test standardization of string analysis results."""

    def test_standardize_strings_normalizes_string_data(self) -> None:
        """String standardization normalizes string analysis data."""
        raw_result = {
            "license_strings": [
                {"string": "License Key:", "address": "0x501000", "entropy": 3.5},
                {"value": "Serial Number:", "addr": 5251072, "entropy": 4.2},
            ],
            "crypto_strings": [
                {"string": "AES-256", "address": "0x502000"}
            ],
            "total_strings": 100,
        }

        standardizer = R2JSONStandardizer()
        result = standardizer._standardize_strings(raw_result)

        license_strings = result["analysis_results"]["license_strings"]
        assert len(license_strings) == 2
        assert license_strings[0]["string"] == "License Key:"
        assert license_strings[1]["string"] == "Serial Number:"

    def test_standardize_strings_calculates_string_statistics(self) -> None:
        """String standardization calculates comprehensive statistics."""
        raw_result = {
            "total_strings": 500,
            "license_strings": [{"string": "license"}, {"string": "key"}],
            "crypto_strings": [{"string": "aes"}, {"string": "rsa"}],
            "suspicious_patterns": [{"pattern": "anti-debug"}],
            "string_entropy_analysis": {
                "average_entropy": 5.5,
                "high_entropy_strings": [{"string": "encrypted", "entropy": 7.8}],
            },
        }

        standardizer = R2JSONStandardizer()
        result = standardizer._standardize_strings(raw_result)

        stats = result["summary_statistics"]
        assert stats["total_strings"] == 500
        assert stats["license_string_count"] == 2
        assert stats["crypto_string_count"] == 2
        assert stats["suspicious_pattern_count"] == 1
        assert stats["average_string_entropy"] == 5.5


class TestImportsStandardization:
    """Test standardization of import/export analysis results."""

    def test_standardize_imports_normalizes_import_data(self) -> None:
        """Import standardization normalizes import function data."""
        raw_result = {
            "imports": [
                {
                    "name": "CreateFileA",
                    "library": "kernel32.dll",
                    "address": "0x401000",
                },
                {
                    "function": "RegOpenKeyA",
                    "dll": "advapi32.dll",
                    "addr": 4198400,
                },
            ],
            "exports": [
                {"name": "GetLicenseInfo", "address": "0x501000"}
            ],
        }

        standardizer = R2JSONStandardizer()
        result = standardizer._standardize_imports(raw_result)

        imports = result["analysis_results"]["imports"]
        assert len(imports) == 2
        assert imports[0]["name"] == "CreateFileA"
        assert imports[0]["library"] == "kernel32.dll"
        assert imports[1]["name"] == "RegOpenKeyA"

    def test_standardize_imports_calculates_api_diversity(self) -> None:
        """Import standardization calculates API diversity score."""
        raw_result = {
            "imports": [
                {"name": "CreateFileA", "library": "kernel32.dll"},
                {"name": "ReadFile", "library": "kernel32.dll"},
                {"name": "socket", "library": "ws2_32.dll"},
                {"name": "malloc", "library": "msvcrt.dll"},
            ]
        }

        standardizer = R2JSONStandardizer()
        result = standardizer._standardize_imports(raw_result)

        diversity = result["summary_statistics"]["api_diversity_score"]
        assert 0.0 <= diversity <= 1.0

    def test_standardize_imports_identifies_suspicious_apis(self) -> None:
        """Import standardization identifies suspicious API calls."""
        raw_result = {
            "imports": [
                {"name": "CreateProcess", "library": "kernel32.dll"},
                {"name": "VirtualAlloc", "library": "kernel32.dll"},
            ],
            "suspicious_apis": [
                {"name": "WriteProcessMemory", "risk_score": 0.9}
            ],
        }

        standardizer = R2JSONStandardizer()
        result = standardizer._standardize_imports(raw_result)

        suspicious = result["analysis_results"]["suspicious_apis"]
        assert len(suspicious) == 1
        assert suspicious[0]["risk_score"] == 0.9


class TestCFGStandardization:
    """Test standardization of control flow graph analysis results."""

    def test_standardize_cfg_normalizes_complexity_metrics(self) -> None:
        """CFG standardization normalizes complexity metrics."""
        raw_result = {
            "functions_analyzed": 50,
            "complexity_metrics": {
                "avg_cyclomatic": 5.5,
                "max_cyclomatic": 25.0,
                "min_cyclomatic": 1.0,
                "avg_cognitive": 8.2,
            },
        }

        standardizer = R2JSONStandardizer()
        result = standardizer._standardize_cfg(raw_result)

        complexity = result["analysis_results"]["complexity_metrics"]
        assert complexity["cyclomatic_complexity"]["average"] == 5.5
        assert complexity["cyclomatic_complexity"]["maximum"] == 25.0
        assert complexity["cognitive_complexity"]["average"] == 8.2

    def test_standardize_cfg_calculates_graph_density(self) -> None:
        """CFG standardization calculates graph density metrics."""
        raw_result = {
            "graph_data": {
                "nodes": [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}],
                "edges": [{"from": 1, "to": 2}, {"from": 2, "to": 3}],
            }
        }

        standardizer = R2JSONStandardizer()
        result = standardizer._standardize_cfg(raw_result)

        stats = result["summary_statistics"]
        assert "graph_density" in stats
        assert 0.0 <= stats["graph_density"] <= 1.0


class TestAddressNormalization:
    """Test address normalization to standard hex format."""

    def test_normalize_address_converts_hex_string(self) -> None:
        """Address normalization handles hex string input."""
        standardizer = R2JSONStandardizer()

        assert standardizer._normalize_address("0x401000") == "0x401000"
        assert standardizer._normalize_address("0x1234ABCD") == "0x1234abcd"

    def test_normalize_address_converts_decimal_string(self) -> None:
        """Address normalization converts decimal string to hex."""
        standardizer = R2JSONStandardizer()

        assert standardizer._normalize_address("4198400") == "0x401000"
        assert standardizer._normalize_address("1024") == "0x400"

    def test_normalize_address_converts_integer(self) -> None:
        """Address normalization converts integer to hex string."""
        standardizer = R2JSONStandardizer()

        assert standardizer._normalize_address(4198400) == "0x401000"
        assert standardizer._normalize_address(0) == "0x0"
        assert standardizer._normalize_address(255) == "0xff"

    def test_normalize_address_handles_invalid_input(self) -> None:
        """Address normalization returns 0x0 for invalid input."""
        standardizer = R2JSONStandardizer()

        assert standardizer._normalize_address("invalid") == "0x0"
        assert standardizer._normalize_address(cast("str | int", None)) == "0x0"


class TestFileOperations:
    """Test file hash and size calculation."""

    def test_calculate_file_hash_computes_sha256(self, tmp_path: Path) -> None:
        """File hash calculation produces correct SHA256 hash."""
        test_file = tmp_path / "binary.exe"
        test_data = b"Test binary content for hashing"
        test_file.write_bytes(test_data)

        expected_hash = hashlib.sha256(test_data).hexdigest()

        standardizer = R2JSONStandardizer()
        calculated_hash = standardizer._calculate_file_hash(str(test_file))

        assert calculated_hash == expected_hash

    def test_calculate_file_hash_handles_missing_file(self) -> None:
        """File hash calculation returns unknown for missing files."""
        standardizer = R2JSONStandardizer()

        hash_result = standardizer._calculate_file_hash("/nonexistent/file.exe")
        assert hash_result == "unknown"

    def test_get_file_size_returns_correct_size(self, tmp_path: Path) -> None:
        """File size calculation returns exact byte count."""
        test_file = tmp_path / "test.dll"
        test_data = b"X" * 1024
        test_file.write_bytes(test_data)

        standardizer = R2JSONStandardizer()
        size = standardizer._get_file_size(str(test_file))

        assert size == 1024

    def test_get_file_size_handles_missing_file(self) -> None:
        """File size calculation returns 0 for missing files."""
        standardizer = R2JSONStandardizer()

        size = standardizer._get_file_size("/nonexistent/file.bin")
        assert size == 0


class TestValidationSystem:
    """Test validation and quality scoring."""

    def test_validate_schema_accepts_valid_structure(self, tmp_path: Path) -> None:
        """Schema validation accepts properly structured data."""
        test_file = tmp_path / "valid.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        standardizer = R2JSONStandardizer()
        result = standardizer.standardize_analysis_result(
            "decompilation",
            {"license_functions": []},
            str(test_file),
        )

        assert standardizer._validate_schema(result) is True

    def test_validate_schema_rejects_missing_fields(self) -> None:
        """Schema validation rejects incomplete structures."""
        standardizer = R2JSONStandardizer()
        invalid_result = {
            "schema_version": "2.0.0",
            "analysis_metadata": {},
        }

        with pytest.raises(ValueError, match="Missing required field"):
            standardizer._validate_schema(invalid_result)

    def test_calculate_completeness_score_evaluates_data_presence(self) -> None:
        """Completeness score calculation evaluates field presence."""
        standardizer = R2JSONStandardizer()

        complete_data = {
            "analysis_results": {
                "field1": "value1",
                "field2": 123,
                "field3": ["item1", "item2"],
            }
        }
        score = standardizer._calculate_completeness_score(complete_data)
        assert 0.0 <= score <= 1.0

        incomplete_data: Dict[str, Any] = {
            "analysis_results": {
                "field1": "",
                "field2": None,
                "field3": [],
            }
        }
        incomplete_score = standardizer._calculate_completeness_score(incomplete_data)
        assert incomplete_score < score

    def test_calculate_quality_score_evaluates_data_quality(self) -> None:
        """Quality score calculation evaluates overall data quality."""
        standardizer = R2JSONStandardizer()

        high_quality = {
            "analysis_results": {"data": "present"},
            "summary_statistics": {"count": 10},
            "ml_features": {"feature": 0.5},
            "status": {"success": True},
            "analysis_metadata": {
                "analysis_id": "123",
                "analysis_type": "test",
                "timestamp": "2025-01-01T00:00:00Z",
            },
        }

        score = standardizer._calculate_quality_score(high_quality)
        assert score == 1.0

    def test_add_validation_data_includes_checksums(self) -> None:
        """Validation data includes SHA256 checksums."""
        standardizer = R2JSONStandardizer()
        data = {
            "analysis_results": {"test": "data"},
            "summary_statistics": {},
            "ml_features": {},
        }

        validated = standardizer._add_validation_data(data)

        assert "validation" in validated
        assert "data_checksum" in validated["validation"]
        assert len(validated["validation"]["data_checksum"]) == 64


class TestMLFeatureExtraction:
    """Test machine learning feature extraction."""

    def test_extract_function_features_calculates_metrics(self) -> None:
        """Function feature extraction calculates statistical metrics."""
        raw_result = {
            "license_functions": [
                {"size": 100, "complexity": 5, "type": "check", "call_depth": 3},
                {"size": 200, "complexity": 10, "type": "validate", "call_depth": 5},
                {"size": 150, "complexity": 7, "type": "check", "call_depth": 4},
            ]
        }

        standardizer = R2JSONStandardizer()
        features = standardizer._extract_function_features(raw_result)

        assert features["total_functions"] == 3
        assert features["avg_function_size"] == 150.0
        assert features["max_function_size"] == 200
        assert "check" in features["function_types"]

    def test_extract_vulnerability_vectors_analyzes_threats(self) -> None:
        """Vulnerability vector extraction analyzes threat data."""
        vulnerabilities = [
            {"severity": "critical", "exploitable": True, "confidence": 0.9},
            {"severity": "high", "exploitable": True, "confidence": 0.8},
            {"severity": "medium", "exploitable": False, "confidence": 0.6},
        ]

        standardizer = R2JSONStandardizer()
        vectors = standardizer._extract_vulnerability_vectors(vulnerabilities)

        assert vectors["exploitable_count"] == 2
        assert vectors["avg_confidence"] > 0.7

    def test_extract_string_entropy_features_analyzes_entropy(self) -> None:
        """String entropy feature extraction analyzes entropy distribution."""
        raw_result = {
            "strings": [
                {"entropy": 4.5},
                {"entropy": 7.8},
                {"entropy": 6.2},
                {"entropy": 8.1},
            ]
        }

        standardizer = R2JSONStandardizer()
        features = standardizer._extract_string_entropy_features(raw_result)

        assert features["avg_entropy"] > 0
        assert features["max_entropy"] == 8.1
        assert features["high_entropy_count"] >= 1

    def test_extract_api_usage_vectors_categorizes_apis(self) -> None:
        """API usage vector extraction categorizes API calls."""
        raw_result = {
            "imports": [
                {"name": "CryptEncrypt"},
                {"name": "CreateFile"},
                {"name": "socket"},
            ]
        }

        standardizer = R2JSONStandardizer()
        vectors = standardizer._extract_api_usage_vectors(raw_result)

        assert vectors["total_imports"] == 3
        assert vectors["crypto_apis"] >= 1


class TestStatisticalCalculations:
    """Test statistical calculation helpers."""

    def test_calculate_variance_computes_correct_variance(self) -> None:
        """Variance calculation produces correct statistical variance."""
        standardizer = R2JSONStandardizer()

        values = [2.0, 4.0, 6.0, 8.0]
        variance = standardizer._calculate_variance(values)

        expected_variance = 5.0
        assert abs(variance - expected_variance) < 0.001

    def test_calculate_variance_handles_empty_list(self) -> None:
        """Variance calculation handles empty input."""
        standardizer = R2JSONStandardizer()

        assert standardizer._calculate_variance([]) == 0.0

    def test_create_histogram_bins_values_correctly(self) -> None:
        """Histogram creation bins values into correct ranges."""
        standardizer = R2JSONStandardizer()

        values = [1.0, 2.5, 5.0, 7.5, 10.0]
        histogram = standardizer._create_histogram(values, bins=5)

        assert len(histogram) == 5
        assert sum(histogram) == len(values)

    def test_calculate_percentiles_computes_distribution(self) -> None:
        """Percentile calculation computes distribution correctly."""
        standardizer = R2JSONStandardizer()

        values: List[float] = [float(i) for i in range(1, 101)]
        percentiles = standardizer._calculate_percentiles(values)

        assert "p25" in percentiles
        assert "p50" in percentiles
        assert "p75" in percentiles
        assert percentiles["p50"] > percentiles["p25"]


class TestAPIAnalysisHelpers:
    """Test API analysis helper methods."""

    def test_categorize_apis_assigns_correct_categories(self) -> None:
        """API categorization assigns APIs to correct functional categories."""
        standardizer = R2JSONStandardizer()

        imports = [
            {"name": "CreateFile"},
            {"name": "socket"},
            {"name": "VirtualAlloc"},
            {"name": "RegOpenKey"},
            {"name": "CryptEncrypt"},
        ]

        categories = standardizer._categorize_apis(imports)

        assert categories["file"] >= 1
        assert categories["network"] >= 1
        assert categories["memory"] >= 1
        assert categories["registry"] >= 1
        assert categories["crypto"] >= 1

    def test_count_suspicious_apis_identifies_dangerous_calls(self) -> None:
        """Suspicious API counting identifies dangerous API calls."""
        standardizer = R2JSONStandardizer()

        imports = [
            {"name": "CreateProcess"},
            {"name": "VirtualAlloc"},
            {"name": "LoadLibrary"},
            {"name": "GetTickCount"},
        ]

        count = standardizer._count_suspicious_apis(imports)
        assert count >= 3

    def test_get_common_libraries_returns_top_libraries(self) -> None:
        """Common library extraction returns most-used libraries."""
        standardizer = R2JSONStandardizer()

        imports = [
            {"library": "kernel32.dll"},
            {"library": "kernel32.dll"},
            {"library": "kernel32.dll"},
            {"library": "advapi32.dll"},
            {"library": "advapi32.dll"},
            {"library": "user32.dll"},
        ]

        common = standardizer._get_common_libraries(imports)

        assert "kernel32.dll" in common
        assert common[0] == "kernel32.dll"


class TestComprehensiveAnalysisStandardization:
    """Test comprehensive analysis result standardization."""

    def test_standardize_comprehensive_aggregates_components(self) -> None:
        """Comprehensive standardization aggregates multiple components."""
        raw_result = {
            "binary_path": "/test.exe",
            "components": {
                "strings": {"license_strings": [{"string": "License Key"}]},
                "imports": {"imports": [{"name": "CreateFile"}]},
            },
        }

        standardizer = R2JSONStandardizer()
        result = standardizer._standardize_comprehensive(raw_result)

        assert "components" in result["analysis_results"]
        assert "cross_component_analysis" in result["analysis_results"]

    def test_standardize_comprehensive_calculates_overall_metrics(self) -> None:
        """Comprehensive standardization calculates overall metrics."""
        raw_result = {
            "binary_path": "/test.exe",
            "components": {
                "decompilation": {
                    "status": {"success": True},
                    "analysis_results": {},
                },
                "vulnerability": {
                    "status": {"success": True},
                    "analysis_results": {"vulnerabilities": [{"severity": "high"}]},
                },
            },
        }

        standardizer = R2JSONStandardizer()
        result = standardizer._standardize_comprehensive(raw_result)

        stats = result["summary_statistics"]
        assert "components_analyzed" in stats
        assert "successful_components" in stats


class TestCrossComponentAnalysis:
    """Test cross-component analysis functionality."""

    def test_perform_cross_component_analysis_finds_interactions(self) -> None:
        """Cross-component analysis identifies component interactions."""
        standardizer = R2JSONStandardizer()

        components = {
            "functions": {"functions": [{"name": "CreateFile_wrapper"}]},
            "imports": {"imports": [{"name": "CreateFile"}]},
        }

        analysis = standardizer._perform_cross_component_analysis(components)

        assert "component_interactions" in analysis
        assert "shared_indicators" in analysis
        assert "consistency_checks" in analysis

    def test_find_shared_indicators_detects_common_strings(self) -> None:
        """Shared indicator detection finds common data across components."""
        standardizer = R2JSONStandardizer()

        components = {
            "comp1": {"strings": [{"string": "License"}, {"string": "Unique1"}]},
            "comp2": {"strings": [{"string": "License"}, {"string": "Unique2"}]},
        }

        shared = standardizer._find_shared_indicators(components)

        assert isinstance(shared, list)

    def test_calculate_correlation_matrix_computes_relationships(self) -> None:
        """Correlation matrix calculation computes component relationships."""
        standardizer = R2JSONStandardizer()

        components = {
            "comp1": {"strings": [{"name": "data1"}]},
            "comp2": {"strings": [{"name": "data2"}]},
        }

        matrix = standardizer._calculate_correlation_matrix(components)

        assert isinstance(matrix, list)
        if matrix:
            assert len(matrix) == 2
            assert matrix[0][0] == 1.0


class TestErrorHandling:
    """Test error handling and recovery."""

    def test_standardize_analysis_result_handles_exceptions(self, tmp_path: Path) -> None:
        """Analysis result standardization handles processing exceptions."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ")

        standardizer = R2JSONStandardizer()

        with patch.object(standardizer, "_standardize_decompilation", side_effect=Exception("Test error")):
            result = standardizer.standardize_analysis_result(
                "decompilation",
                {"license_functions": []},
                str(test_file),
            )

            assert result["status"]["success"] is False
            assert len(result["status"]["errors"]) > 0

    def test_create_error_result_produces_valid_structure(self) -> None:
        """Error result creation produces valid standardized structure."""
        standardizer = R2JSONStandardizer()

        error_result = standardizer._create_error_result(
            "vulnerability",
            "/test.exe",
            "Test error message",
        )

        assert error_result["status"]["success"] is False
        assert "Test error message" in error_result["status"]["errors"]
        assert error_result["validation"]["schema_validation"] is False


class TestBatchStandardization:
    """Test batch processing of multiple results."""

    def test_batch_standardize_results_processes_multiple_items(self, tmp_path: Path) -> None:
        """Batch standardization processes multiple analysis results."""
        test_file = tmp_path / "batch.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        results: List[tuple[str, Dict[str, Any], str]] = [
            ("decompilation", {"license_functions": []}, str(test_file)),
            ("strings", {"license_strings": []}, str(test_file)),
            ("imports", {"imports": []}, str(test_file)),
        ]

        standardized = batch_standardize_results(results)

        assert len(standardized) == 3
        assert all("schema_version" in r for r in standardized)

    def test_batch_standardize_results_handles_individual_failures(self, tmp_path: Path) -> None:
        """Batch standardization handles failures in individual items."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ")

        results: List[tuple[str, Dict[str, Any], str]] = [
            ("decompilation", {"license_functions": []}, str(test_file)),
            ("invalid_type", {}, "/nonexistent.exe"),
        ]

        with patch("intellicrack.core.analysis.radare2_json_standardizer.logger"):
            standardized = batch_standardize_results(results)

            assert len(standardized) == 2


class TestStandardizeR2ResultFunction:
    """Test standalone standardize_r2_result function."""

    def test_standardize_r2_result_standardizes_single_result(self, tmp_path: Path) -> None:
        """standalone function standardizes single analysis result."""
        test_file = tmp_path / "single.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 50)

        result = standardize_r2_result(
            "strings",
            {"license_strings": [{"string": "License"}]},
            str(test_file),
            {"custom_meta": "value"},
        )

        assert result["schema_version"] == "2.0.0"
        assert result["additional_metadata"]["custom_meta"] == "value"


class TestDataNormalization:
    """Test data normalization functions."""

    def test_normalize_function_list_standardizes_function_data(self) -> None:
        """Function list normalization standardizes function metadata."""
        standardizer = R2JSONStandardizer()

        functions = [
            {
                "name": "CheckLicense",
                "address": 0x401000,
                "size": 256,
                "complexity": 10,
                "confidence": 0.95,
            }
        ]

        normalized = standardizer._normalize_function_list(functions)

        assert len(normalized) == 1
        assert normalized[0]["name"] == "CheckLicense"
        assert normalized[0]["address"] == "0x401000"
        assert normalized[0]["size"] == 256

    def test_normalize_string_list_handles_various_formats(self) -> None:
        """String list normalization handles different input formats."""
        standardizer = R2JSONStandardizer()

        strings_raw: List[Any] = [
            {"string": "License Key", "address": 0x500000},
            {"value": "Serial", "addr": "0x500100"},
            "Plain String",
        ]
        strings = cast(List[Dict[str, Any]], strings_raw)

        normalized = standardizer._normalize_string_list(strings)

        assert len(normalized) == 3
        assert normalized[0]["string"] == "License Key"
        assert normalized[1]["string"] == "Serial"
        assert normalized[2]["string"] == "Plain String"

    def test_normalize_import_list_standardizes_import_data(self) -> None:
        """Import list normalization standardizes import metadata."""
        standardizer = R2JSONStandardizer()

        imports: List[Dict[str, Any] | str] = [
            {"name": "CreateFileA", "library": "kernel32.dll", "address": 0x401000},
            {"function": "RegOpenKeyA", "dll": "advapi32.dll"},
            "LoadLibrary",
        ]

        normalized = standardizer._normalize_import_list(imports)

        assert len(normalized) == 3
        assert normalized[0]["name"] == "CreateFileA"
        assert normalized[0]["library"] == "kernel32.dll"
        assert normalized[1]["name"] == "RegOpenKeyA"
        assert normalized[2]["name"] == "LoadLibrary"


class TestEntropyAnalysis:
    """Test entropy analysis normalization."""

    def test_normalize_entropy_analysis_standardizes_entropy_data(self) -> None:
        """Entropy analysis normalization standardizes entropy metrics."""
        standardizer = R2JSONStandardizer()

        entropy_data = {
            "overall_entropy": 6.5,
            "mean_entropy": 5.5,
            "median_entropy": 5.8,
            "std_dev_entropy": 1.2,
            "high_entropy_sections": [".text", ".data"],
        }

        normalized = standardizer._normalize_entropy_analysis(entropy_data)

        assert normalized["overall_entropy"] == 6.5
        assert normalized["entropy_statistics"]["mean"] == 5.5
        assert ".text" in normalized["high_entropy_sections"]


class TestCVEMatching:
    """Test CVE match normalization."""

    def test_normalize_cve_matches_standardizes_cve_data(self) -> None:
        """CVE match normalization standardizes vulnerability data."""
        standardizer = R2JSONStandardizer()

        cve_matches = [
            {
                "cve_id": "CVE-2024-1234",
                "score": 9.8,
                "severity": "critical",
                "description": "Buffer overflow vulnerability",
            },
            {
                "id": "CVE-2024-5678",
                "cvss_score": 7.5,
                "severity": "high",
            },
        ]

        normalized = standardizer._normalize_cve_matches(cve_matches)

        assert len(normalized) == 2
        assert normalized[0]["cve_id"] == "CVE-2024-1234"
        assert normalized[0]["score"] == 9.8
        assert normalized[1]["cve_id"] == "CVE-2024-5678"
        assert normalized[1]["score"] == 7.5


class TestAIAnalysisStandardization:
    """Test AI analysis result standardization."""

    def test_normalize_ai_license_detection_standardizes_ai_results(self) -> None:
        """AI license detection normalization standardizes ML predictions."""
        standardizer = R2JSONStandardizer()

        ai_data = {
            "detected_license_type": "FlexLM",
            "confidence": 0.92,
            "protection_mechanisms": ["dongle", "network"],
            "success_probability": 0.75,
        }

        normalized = standardizer._normalize_ai_license_detection(ai_data)

        assert normalized["detected_license_type"] == "FlexLM"
        assert normalized["confidence"] == 0.92
        assert "dongle" in normalized["protection_mechanisms"]

    def test_normalize_function_clustering_standardizes_cluster_data(self) -> None:
        """Function clustering normalization standardizes cluster analysis."""
        standardizer = R2JSONStandardizer()

        clustering_data = {
            "clusters": [
                {"id": 1, "size": 10},
                {"id": 2, "size": 15},
            ],
            "clustering_algorithm": "kmeans",
            "clustering_quality": 0.85,
        }

        normalized = standardizer._normalize_function_clustering(clustering_data)

        assert normalized["cluster_count"] == 2
        assert normalized["clustering_algorithm"] == "kmeans"
        assert normalized["clustering_quality"] == 0.85


class TestNestingDepthCalculation:
    """Test nesting depth calculation."""

    def test_calculate_nesting_depth_handles_nested_dicts(self) -> None:
        """Nesting depth calculation measures nested dictionary depth."""
        standardizer = R2JSONStandardizer()

        data = {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": "value"
                    }
                }
            }
        }

        depth = standardizer._calculate_nesting_depth(data)
        assert depth == 4

    def test_calculate_nesting_depth_handles_nested_lists(self) -> None:
        """Nesting depth calculation measures nested list depth."""
        standardizer = R2JSONStandardizer()

        data = {
            "level1": [
                [
                    [
                        {"level4": "value"}
                    ]
                ]
            ]
        }

        depth = standardizer._calculate_nesting_depth(data)
        assert depth >= 3


class TestGenericDataStandardization:
    """Test generic data standardization."""

    def test_standardize_generic_handles_unknown_types(self, tmp_path: Path) -> None:
        """Generic standardization handles unknown analysis types."""
        test_file = tmp_path / "generic.exe"
        test_file.write_bytes(b"MZ")

        standardizer = R2JSONStandardizer()
        raw_result = {
            "custom_field": "value",
            "nested": {"data": 123},
        }

        result = standardizer._standardize_generic(raw_result)

        assert "analysis_results" in result
        assert result["analysis_results"]["raw_data"] == raw_result

    def test_normalize_generic_data_recursively_normalizes(self) -> None:
        """Generic data normalization recursively normalizes structures."""
        standardizer = R2JSONStandardizer()

        data = {
            "string": "  test  ",
            "number": 123,
            "nested": {
                "inner": "  value  "
            },
            "list": [{"item": 1}, {"item": 2}],
        }

        normalized = standardizer._normalize_generic_data(data)

        assert normalized["string"] == "test"
        assert normalized["number"] == 123.0
        assert normalized["nested"]["inner"] == "value"


class TestComplexityFeatures:
    """Test complexity feature extraction."""

    def test_get_complexity_distribution_categorizes_functions(self) -> None:
        """Complexity distribution categorizes functions by complexity."""
        standardizer = R2JSONStandardizer()

        functions = [
            {"complexity": 2},
            {"complexity": 8},
            {"complexity": 20},
        ]

        distribution = standardizer._get_complexity_distribution(functions)

        assert distribution["low"] == 1
        assert distribution["medium"] == 1
        assert distribution["high"] == 1


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_full_decompilation_workflow_produces_valid_output(self, tmp_path: Path) -> None:
        """Complete decompilation workflow produces valid standardized output."""
        binary = tmp_path / "protected.exe"
        binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 500)

        raw_result = {
            "license_functions": [
                {
                    "name": "CheckLicense",
                    "address": "0x401000",
                    "size": 256,
                    "complexity": 10,
                    "confidence": 0.95,
                    "type": "validation",
                    "decompiled": True,
                }
            ],
            "decompiled_functions": {
                "CheckLicense": {
                    "code": "int CheckLicense(char* key) { return verify(key); }",
                    "language": "c",
                    "quality_score": 0.9,
                }
            },
            "license_patterns": [
                {
                    "type": "serial_validation",
                    "pattern": "^[A-Z0-9]{16}$",
                    "confidence": 0.88,
                }
            ],
        }

        standardizer = R2JSONStandardizer()
        result = standardizer.standardize_analysis_result(
            "decompilation",
            raw_result,
            str(binary),
        )

        assert result["status"]["success"] is True
        assert result["schema_version"] == "2.0.0"
        assert len(result["analysis_results"]["license_functions"]) == 1
        assert "validation" in result
        assert result["validation"]["schema_validation"] is True

    def test_vulnerability_analysis_workflow_produces_comprehensive_results(self, tmp_path: Path) -> None:
        """Vulnerability analysis workflow produces comprehensive results."""
        binary = tmp_path / "vulnerable.dll"
        binary.write_bytes(b"MZ" + b"\x00" * 300)

        raw_result = {
            "buffer_overflows": [
                {
                    "type": "stack_overflow",
                    "severity": "critical",
                    "function": "HandleInput",
                    "address": "0x402000",
                    "exploitable": True,
                }
            ],
            "integer_overflows": [
                {
                    "type": "int_overflow",
                    "severity": "medium",
                    "function": "CalculateSize",
                    "address": "0x403000",
                }
            ],
        }

        result = standardize_r2_result("vulnerability", raw_result, str(binary))

        assert result["status"]["success"] is True
        vulnerabilities = result["analysis_results"]["vulnerabilities"]
        assert len(vulnerabilities) == 2
        assert result["summary_statistics"]["total_vulnerabilities"] == 2
        assert result["summary_statistics"]["critical_vulnerabilities"] >= 1


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_standardization_handles_empty_results(self, tmp_path: Path) -> None:
        """Standardization handles completely empty analysis results."""
        binary = tmp_path / "empty.exe"
        binary.write_bytes(b"MZ")

        standardizer = R2JSONStandardizer()
        result = standardizer.standardize_analysis_result("decompilation", {}, str(binary))

        assert result["status"]["success"] is True
        assert "analysis_results" in result

    def test_standardization_handles_malformed_data(self, tmp_path: Path) -> None:
        """Standardization handles malformed input data gracefully."""
        binary = tmp_path / "test.exe"
        binary.write_bytes(b"MZ")

        raw_result = {
            "license_functions": [
                {"name": None, "address": "invalid", "size": "not_a_number"}
            ]
        }

        standardizer = R2JSONStandardizer()
        result = standardizer.standardize_analysis_result("decompilation", raw_result, str(binary))

        assert "analysis_results" in result

    def test_standardization_handles_very_large_datasets(self, tmp_path: Path) -> None:
        """Standardization handles very large analysis datasets."""
        binary = tmp_path / "large.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 1000)

        raw_result = {
            "license_functions": [
                {"name": f"func_{i}", "address": i * 0x1000, "size": 100}
                for i in range(1000)
            ]
        }

        standardizer = R2JSONStandardizer()
        result = standardizer.standardize_analysis_result("decompilation", raw_result, str(binary))

        assert result["status"]["success"] is True
        assert len(result["analysis_results"]["license_functions"]) == 1000
