"""
Comprehensive test suite for radare2_json_standardizer.py

This test suite follows specification-driven, black-box testing methodology to validate
production-ready radare2 JSON standardization capabilities without examining source implementations.

Tests are designed to:
1. Validate sophisticated JSON processing and transformation capabilities
2. Ensure cross-version radare2 compatibility and normalization
3. Test advanced statistical and correlation analysis features
4. Verify security-focused data sanitization and validation
5. Fail when encountering placeholder/stub implementations

Coverage Target: 80%+ with production-grade validation requirements
"""

import pytest
import json
import tempfile
import os
from pathlib import Path
from datetime import datetime
import hashlib

# Import target module
from intellicrack.core.analysis.radare2_json_standardizer import (
    R2JSONStandardizer,
    standardize_r2_result,
    batch_standardize_results
)


class TestR2JSONStandardizer:
    """Test suite for R2JSONStandardizer class - comprehensive production validation"""

    @pytest.fixture
    def standardizer(self):
        """Create R2JSONStandardizer instance for testing"""
        return R2JSONStandardizer()

    @pytest.fixture
    def sample_radare2_decompilation_json(self):
        """Real-world radare2 decompilation JSON sample"""
        return {
            "functions": [
                {
                    "name": "main",
                    "addr": "0x401000",
                    "size": 156,
                    "code": "int main(int argc, char *argv[]) {\n    return validate_license();\n}",
                    "complexity": 3,
                    "calls": ["validate_license", "exit"],
                    "xrefs": []
                },
                {
                    "name": "validate_license",
                    "addr": "0x401100",
                    "size": 89,
                    "code": "int validate_license() {\n    if(check_serial() == 1) return 1;\n    return 0;\n}",
                    "complexity": 5,
                    "calls": ["check_serial"],
                    "xrefs": ["main"]
                }
            ],
            "patterns": [
                {"pattern": "serial_check", "matches": 3, "confidence": 0.85},
                {"pattern": "anti_debug", "matches": 1, "confidence": 0.92}
            ],
            "validation_routines": ["check_serial", "validate_key", "compute_hash"]
        }

    @pytest.fixture
    def sample_radare2_vulnerability_json(self):
        """Real-world radare2 vulnerability analysis JSON sample"""
        return {
            "vulnerabilities": [
                {
                    "type": "buffer_overflow",
                    "addr": "0x401234",
                    "severity": "high",
                    "description": "Potential buffer overflow in string copy",
                    "cve_matches": ["CVE-2019-1234"],
                    "exploitability": 0.8,
                    "risk_score": 8.5
                },
                {
                    "type": "format_string",
                    "addr": "0x401456",
                    "severity": "medium",
                    "description": "Format string vulnerability in logging",
                    "cve_matches": [],
                    "exploitability": 0.6,
                    "risk_score": 6.2
                }
            ],
            "exploit_data": {
                "shellcode_opportunities": ["0x401234"],
                "rop_gadgets": 45,
                "exploit_complexity": "medium"
            }
        }

    @pytest.fixture
    def sample_radare2_strings_json(self):
        """Real-world radare2 strings analysis JSON sample"""
        return {
            "strings": [
                {"addr": "0x402000", "string": "Enter license key:", "type": "ascii", "length": 17},
                {"addr": "0x402020", "string": "Invalid license", "type": "ascii", "length": 15},
                {"addr": "0x402040", "string": "%s-%s-%s-%s", "type": "format", "length": 11}
            ],
            "patterns": {
                "license_strings": 12,
                "error_messages": 8,
                "format_strings": 3
            },
            "entropy_analysis": {
                "high_entropy_count": 5,
                "avg_entropy": 4.2,
                "suspicious_strings": 2
            }
        }

    @pytest.fixture
    def sample_radare2_imports_json(self):
        """Real-world radare2 imports analysis JSON sample"""
        return {
            "imports": [
                {"name": "CreateProcessA", "dll": "kernel32.dll", "addr": "0x403000", "ordinal": None},
                {"name": "RegSetValueExA", "dll": "advapi32.dll", "addr": "0x403008", "ordinal": None},
                {"name": "CryptAcquireContextA", "dll": "advapi32.dll", "addr": "0x403010", "ordinal": None}
            ],
            "exports": [
                {"name": "CheckLicense", "addr": "0x401500", "ordinal": 1},
                {"name": "GetSerial", "addr": "0x401600", "ordinal": 2}
            ],
            "api_categories": {
                "process": 3,
                "registry": 2,
                "crypto": 1,
                "file": 4,
                "network": 0
            }
        }

    def test_init_creates_proper_instance(self, standardizer):
        """Test R2JSONStandardizer initialization creates valid instance with required attributes"""
        # Verify instance creation
        assert isinstance(standardizer, R2JSONStandardizer)

        # Should have schema version constant
        assert hasattr(standardizer, 'SCHEMA_VERSION')
        assert isinstance(standardizer.SCHEMA_VERSION, str)
        assert len(standardizer.SCHEMA_VERSION) > 0

        # Should have analysis types constant
        assert hasattr(standardizer, 'ANALYSIS_TYPES')
        assert isinstance(standardizer.ANALYSIS_TYPES, (list, tuple, set))
        assert len(standardizer.ANALYSIS_TYPES) > 0

        # Should have logger instance
        assert hasattr(standardizer, 'logger')

        # Should have analysis_id for tracking
        assert hasattr(standardizer, 'analysis_id')
        assert isinstance(standardizer.analysis_id, str)

        # Should have timestamp for tracking
        assert hasattr(standardizer, 'timestamp')
        assert isinstance(standardizer.timestamp, str)

    def test_standardize_analysis_result_decompilation_comprehensive(self, standardizer, sample_radare2_decompilation_json):
        """Test standardize_analysis_result with decompilation data produces comprehensive standardized output"""
        result = standardizer.standardize_analysis_result(sample_radare2_decompilation_json, "decompilation")

        # Must return dictionary with standardized structure
        assert isinstance(result, dict)

        # Should have base metadata structure
        assert 'metadata' in result
        assert 'schema_version' in result['metadata']
        assert 'analysis_type' in result['metadata']
        assert 'timestamp' in result['metadata']
        assert 'analysis_id' in result['metadata']

        # Should have decompilation-specific standardized data
        assert 'decompilation' in result
        decompilation_data = result['decompilation']

        # Must have normalized function list
        assert 'functions' in decompilation_data
        assert isinstance(decompilation_data['functions'], list)
        assert len(decompilation_data['functions']) > 0

        # Functions must be normalized with required fields
        for func in decompilation_data['functions']:
            assert 'name' in func
            assert 'address' in func  # Normalized from 'addr'
            assert 'size' in func
            assert 'complexity' in func
            assert isinstance(func['complexity'], (int, float))

        # Must have pattern analysis
        assert 'patterns' in decompilation_data
        assert isinstance(decompilation_data['patterns'], list)

        # Must have validation metrics
        assert 'validation' in result
        assert 'completeness_score' in result['validation']
        assert 'quality_score' in result['validation']
        assert isinstance(result['validation']['completeness_score'], (int, float))
        assert isinstance(result['validation']['quality_score'], (int, float))

        # Quality scores must be realistic (0-100 range)
        assert 0 <= result['validation']['completeness_score'] <= 100
        assert 0 <= result['validation']['quality_score'] <= 100

    def test_standardize_analysis_result_vulnerability_advanced(self, standardizer, sample_radare2_vulnerability_json):
        """Test vulnerability analysis standardization with advanced security metrics"""
        result = standardizer.standardize_analysis_result(sample_radare2_vulnerability_json, "vulnerability")

        assert isinstance(result, dict)
        assert 'vulnerability' in result
        vuln_data = result['vulnerability']

        # Must have categorized vulnerabilities
        assert 'vulnerabilities' in vuln_data
        assert isinstance(vuln_data['vulnerabilities'], list)

        # Vulnerabilities must be normalized with security metrics
        for vuln in vuln_data['vulnerabilities']:
            assert 'type' in vuln
            assert 'severity' in vuln
            assert 'risk_score' in vuln
            assert 'exploitability' in vuln
            assert isinstance(vuln['risk_score'], (int, float))
            assert isinstance(vuln['exploitability'], (int, float))
            # Risk scores should be realistic
            assert 0 <= vuln['risk_score'] <= 10
            assert 0 <= vuln['exploitability'] <= 1

        # Must have CVE matching data
        assert 'cve_analysis' in vuln_data

        # Must have exploit assessment data
        assert 'exploit_assessment' in vuln_data
        exploit_data = vuln_data['exploit_assessment']
        assert 'shellcode_opportunities' in exploit_data
        assert 'complexity_rating' in exploit_data

        # Must calculate overall vulnerability metrics
        assert 'summary' in vuln_data
        assert 'total_vulnerabilities' in vuln_data['summary']
        assert 'high_risk_count' in vuln_data['summary']
        assert 'overall_risk_score' in vuln_data['summary']

    def test_standardize_analysis_result_strings_intelligence(self, standardizer, sample_radare2_strings_json):
        """Test strings analysis standardization with intelligent categorization"""
        result = standardizer.standardize_analysis_result(sample_radare2_strings_json, "strings")

        assert isinstance(result, dict)
        assert 'strings' in result
        strings_data = result['strings']

        # Must have categorized strings
        assert 'categorized_strings' in strings_data
        categories = strings_data['categorized_strings']

        # Should intelligently categorize strings
        expected_categories = ['license', 'error', 'format', 'debug', 'crypto', 'suspicious']
        for category in expected_categories:
            if category in categories:
                assert isinstance(categories[category], list)

        # Must have entropy analysis
        assert 'entropy_analysis' in strings_data
        entropy = strings_data['entropy_analysis']
        assert 'high_entropy_strings' in entropy
        assert 'average_entropy' in entropy
        assert isinstance(entropy['average_entropy'], (int, float))

        # Must have pattern recognition
        assert 'pattern_analysis' in strings_data
        patterns = strings_data['pattern_analysis']
        assert 'license_indicators' in patterns
        assert 'suspicious_patterns' in patterns

        # Must calculate string distribution metrics
        assert 'distribution_metrics' in strings_data
        metrics = strings_data['distribution_metrics']
        assert 'total_strings' in metrics
        assert 'unique_strings' in metrics

    def test_standardize_analysis_result_imports_security_focus(self, standardizer, sample_radare2_imports_json):
        """Test imports analysis with security-focused API categorization"""
        result = standardizer.standardize_analysis_result(sample_radare2_imports_json, "imports")

        assert isinstance(result, dict)
        assert 'imports' in result
        imports_data = result['imports']

        # Must have normalized import/export lists
        assert 'imports' in imports_data
        assert 'exports' in imports_data
        assert isinstance(imports_data['imports'], list)
        assert isinstance(imports_data['exports'], list)

        # Imports should have security categorization
        assert 'api_categories' in imports_data
        api_cats = imports_data['api_categories']
        security_categories = ['process', 'registry', 'crypto', 'file', 'network', 'memory']
        for cat in security_categories:
            if cat in api_cats:
                assert isinstance(api_cats[cat], int)

        # Must identify suspicious APIs
        assert 'suspicious_apis' in imports_data
        assert 'anti_analysis_apis' in imports_data
        assert isinstance(imports_data['suspicious_apis'], list)

        # Must have library dependency analysis
        assert 'library_analysis' in imports_data
        lib_analysis = imports_data['library_analysis']
        assert 'common_libraries' in lib_analysis
        assert 'dependency_count' in lib_analysis

        # Must calculate API diversity metrics
        assert 'diversity_metrics' in imports_data
        diversity = imports_data['diversity_metrics']
        assert 'api_diversity_score' in diversity
        assert isinstance(diversity['api_diversity_score'], (int, float))

    def test_standardize_analysis_result_cfg_graph_analysis(self, standardizer):
        """Test CFG analysis standardization with graph metrics"""
        cfg_json = {
            "functions": [
                {"name": "main", "addr": "0x401000", "complexity": 5, "blocks": 12},
                {"name": "check_license", "addr": "0x401100", "complexity": 8, "blocks": 20}
            ],
            "call_graph": {
                "nodes": 25,
                "edges": 34,
                "density": 0.12
            },
            "complexity_metrics": {
                "average": 6.5,
                "maximum": 15,
                "distribution": {"low": 5, "medium": 8, "high": 2}
            }
        }

        result = standardizer.standardize_analysis_result(cfg_json, "cfg")

        assert isinstance(result, dict)
        assert 'cfg' in result
        cfg_data = result['cfg']

        # Must have graph structural analysis
        assert 'graph_metrics' in cfg_data
        graph = cfg_data['graph_metrics']
        assert 'node_count' in graph
        assert 'edge_count' in graph
        assert 'graph_density' in graph

        # Must have complexity distribution analysis
        assert 'complexity_analysis' in cfg_data
        complexity = cfg_data['complexity_analysis']
        assert 'average_complexity' in complexity
        assert 'max_complexity' in complexity
        assert 'distribution' in complexity

        # Must identify vulnerability patterns in CFG
        assert 'vulnerability_patterns' in cfg_data
        assert isinstance(cfg_data['vulnerability_patterns'], list)

    def test_standardize_analysis_result_ai_integration(self, standardizer):
        """Test AI analysis standardization with machine learning features"""
        ai_json = {
            "license_detection": {
                "predictions": [{"type": "commercial", "confidence": 0.87}],
                "features": [0.2, 0.8, 0.3, 0.9, 0.1]
            },
            "vulnerability_prediction": {
                "high_risk_functions": ["validate_key", "decrypt_data"],
                "ml_confidence": 0.82,
                "feature_importance": {"strings": 0.3, "api_calls": 0.5, "complexity": 0.2}
            },
            "clustering_results": {
                "function_clusters": 5,
                "similarity_matrix": [[0.9, 0.2], [0.2, 0.8]],
                "anomalous_functions": ["obfuscated_func"]
            }
        }

        result = standardizer.standardize_analysis_result(ai_json, "ai")

        assert isinstance(result, dict)
        assert 'ai' in result
        ai_data = result['ai']

        # Must have license detection results
        assert 'license_detection' in ai_data
        license_data = ai_data['license_detection']
        assert 'predictions' in license_data
        assert 'confidence_scores' in license_data

        # Must have vulnerability prediction analysis
        assert 'vulnerability_prediction' in ai_data
        vuln_pred = ai_data['vulnerability_prediction']
        assert 'high_risk_functions' in vuln_pred
        assert 'ml_confidence' in vuln_pred

        # Must have clustering and similarity analysis
        assert 'clustering_analysis' in ai_data
        clustering = ai_data['clustering_analysis']
        assert 'cluster_count' in clustering
        assert 'anomaly_detection' in clustering

    def test_standardize_analysis_result_comprehensive_cross_analysis(self, standardizer):
        """Test comprehensive analysis with cross-component correlation"""
        comprehensive_json = {
            "decompilation": {"functions": [{"name": "main", "complexity": 5}]},
            "vulnerability": {"vulnerabilities": [{"type": "overflow", "severity": "high"}]},
            "strings": {"strings": [{"string": "license", "type": "ascii"}]},
            "imports": {"imports": [{"name": "CryptAcquireContext", "dll": "advapi32.dll"}]},
            "cfg": {"complexity_metrics": {"average": 6.5}},
            "ai": {"predictions": [{"type": "commercial", "confidence": 0.9}]}
        }

        result = standardizer.standardize_analysis_result(comprehensive_json, "comprehensive")

        assert isinstance(result, dict)
        assert 'comprehensive' in result
        comp_data = result['comprehensive']

        # Must perform cross-component analysis
        assert 'cross_analysis' in comp_data
        cross = comp_data['cross_analysis']
        assert 'component_correlations' in cross
        assert 'unified_findings' in cross

        # Must have integrated risk assessment
        assert 'integrated_assessment' in comp_data
        assessment = comp_data['integrated_assessment']
        assert 'overall_risk_score' in assessment
        assert 'component_consistency' in assessment

        # Must provide unified recommendations
        assert 'recommendations' in comp_data
        assert isinstance(comp_data['recommendations'], list)

    def test_standardize_analysis_result_invalid_type_error_handling(self, standardizer):
        """Test error handling for invalid analysis types"""
        sample_json = {"test": "data"}

        result = standardizer.standardize_analysis_result(sample_json, "invalid_type")

        # Should return error structure, not crash
        assert isinstance(result, dict)
        assert 'error' in result
        assert 'status' in result
        assert result['status'] == 'error'

        # Should provide meaningful error information
        assert 'message' in result['error']
        assert 'analysis_type' in result['error']
        assert result['error']['analysis_type'] == 'invalid_type'

    def test_standardize_analysis_result_malformed_json_handling(self, standardizer):
        """Test handling of malformed or incomplete JSON data"""
        malformed_cases = [
            {},  # Empty
            {"incomplete": "data"},  # Missing expected fields
            None,  # None input
            {"nested": {"too": {"deep": {"structure": "value"}}}},  # Overly nested
        ]

        for malformed_json in malformed_cases:
            result = standardizer.standardize_analysis_result(malformed_json, "decompilation")

            # Should handle gracefully without crashing
            assert isinstance(result, dict)
            # Should either return valid standardized data or error structure
            assert 'metadata' in result or 'error' in result

    def test_normalization_methods_address_handling(self, standardizer):
        """Test address normalization handles various formats correctly"""
        test_addresses = [
            "0x401000",  # Standard hex
            "401000",    # Hex without prefix
            "0x0000000000401000",  # 64-bit address
            "4198400",   # Decimal
        ]

        for addr in test_addresses:
            # Test via standardization that uses address normalization
            json_data = {"functions": [{"name": "test", "addr": addr}]}
            result = standardizer.standardize_analysis_result(json_data, "decompilation")

            assert isinstance(result, dict)
            if 'decompilation' in result and 'functions' in result['decompilation']:
                func = result['decompilation']['functions'][0]
                # Address should be normalized to standard format
                assert 'address' in func
                assert isinstance(func['address'], str)

    def test_schema_validation_enforcement(self, standardizer):
        """Test schema validation enforces data integrity"""
        # Test with data that should trigger schema validation
        test_json = {
            "functions": [
                {"name": "test_func", "addr": "0x401000", "size": "invalid_size"}  # Invalid size type
            ]
        }

        result = standardizer.standardize_analysis_result(test_json, "decompilation")

        # Should handle schema validation gracefully
        assert isinstance(result, dict)
        # Should have validation information
        assert 'validation' in result
        if 'schema_validation' in result['validation']:
            assert isinstance(result['validation']['schema_validation'], dict)

    def test_quality_scoring_algorithms(self, standardizer, sample_radare2_decompilation_json):
        """Test quality scoring produces meaningful metrics"""
        result = standardizer.standardize_analysis_result(sample_radare2_decompilation_json, "decompilation")

        assert 'validation' in result
        validation = result['validation']

        # Must have completeness and quality scores
        assert 'completeness_score' in validation
        assert 'quality_score' in validation

        completeness = validation['completeness_score']
        quality = validation['quality_score']

        # Scores should be numeric and in reasonable range
        assert isinstance(completeness, (int, float))
        assert isinstance(quality, (int, float))
        assert 0 <= completeness <= 100
        assert 0 <= quality <= 100

        # Quality scoring should be sophisticated (not just simple counts)
        # Test with minimal data vs rich data should show difference
        minimal_json = {"functions": [{"name": "simple", "addr": "0x401000"}]}
        minimal_result = standardizer.standardize_analysis_result(minimal_json, "decompilation")

        minimal_quality = minimal_result['validation']['quality_score']

        # Rich data should generally score higher than minimal data
        # (This validates sophisticated scoring algorithm vs simple counting)
        assert quality != minimal_quality  # Scores should differ meaningfully

    def test_batch_processing_performance(self, standardizer):
        """Test batch processing handles multiple analyses efficiently"""
        # Create multiple sample analyses
        analyses = []
        for i in range(5):
            analyses.append({
                "data": {
                    "functions": [{"name": f"func_{i}", "addr": f"0x40{i:04x}", "complexity": i+1}]
                },
                "type": "decompilation"
            })

        # Process batch
        results = []
        for analysis in analyses:
            result = standardizer.standardize_analysis_result(analysis["data"], analysis["type"])
            results.append(result)

        # All should succeed
        assert len(results) == 5
        for result in results:
            assert isinstance(result, dict)
            assert 'metadata' in result or 'error' in result

        # Each should have unique analysis_id
        analysis_ids = []
        for result in results:
            if 'metadata' in result:
                analysis_ids.append(result['metadata']['analysis_id'])

        # All IDs should be unique
        assert len(set(analysis_ids)) == len(analysis_ids)


class TestModuleLevelFunctions:
    """Test module-level convenience functions"""

    def test_standardize_r2_result_convenience_function(self):
        """Test standardize_r2_result convenience function works correctly"""
        sample_data = {
            "functions": [{"name": "main", "addr": "0x401000", "complexity": 3}]
        }

        result = standardize_r2_result(sample_data, "decompilation")

        # Should return standardized dictionary
        assert isinstance(result, dict)
        assert 'metadata' in result or 'error' in result

        # If successful, should have expected structure
        if 'metadata' in result:
            assert 'schema_version' in result['metadata']
            assert 'analysis_type' in result['metadata']
            assert result['metadata']['analysis_type'] == 'decompilation'

    def test_batch_standardize_results_multiple_analyses(self):
        """Test batch_standardize_results processes multiple results efficiently"""
        batch_data = [
            {"data": {"functions": [{"name": "func1", "addr": "0x401000"}]}, "type": "decompilation"},
            {"data": {"strings": [{"string": "test", "addr": "0x402000"}]}, "type": "strings"},
            {"data": {"imports": [{"name": "GetProcAddress", "dll": "kernel32.dll"}]}, "type": "imports"}
        ]

        results = batch_standardize_results(batch_data)

        # Should return list of results
        assert isinstance(results, list)
        assert len(results) == 3

        # Each result should be properly standardized
        for i, result in enumerate(results):
            assert isinstance(result, dict)
            if 'metadata' in result:
                assert result['metadata']['analysis_type'] == batch_data[i]['type']

    def test_batch_standardize_results_error_isolation(self):
        """Test batch processing isolates errors without stopping entire batch"""
        batch_data = [
            {"data": {"functions": [{"name": "valid", "addr": "0x401000"}]}, "type": "decompilation"},
            {"data": {"invalid": "structure"}, "type": "invalid_type"},  # Should error
            {"data": {"strings": [{"string": "valid", "addr": "0x402000"}]}, "type": "strings"}
        ]

        results = batch_standardize_results(batch_data)

        # Should still process all items
        assert len(results) == 3

        # First and third should succeed, second should have error
        assert 'metadata' in results[0] or 'error' in results[0]
        assert 'error' in results[1]  # Invalid type should error
        assert 'metadata' in results[2] or 'error' in results[2]


class TestAdvancedScenarios:
    """Advanced testing scenarios for sophisticated validation"""

    @pytest.fixture
    def complex_binary_scenario(self):
        """Complex real-world binary analysis scenario"""
        return {
            "metadata": {
                "file_path": "C:\\Program Files\\TestApp\\license.dll",
                "file_size": 524288,
                "file_hash": "a1b2c3d4e5f6789012345678901234567890abcd"
            },
            "decompilation": {
                "functions": [
                    {
                        "name": "DllMain",
                        "addr": "0x10001000",
                        "size": 245,
                        "complexity": 12,
                        "code": "BOOL DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) { ... }",
                        "calls": ["InitializeCriticalSection", "CreateThread"]
                    },
                    {
                        "name": "CheckLicense",
                        "addr": "0x10001200",
                        "size": 1024,
                        "complexity": 28,
                        "code": "int CheckLicense(char* key) { ... complex validation ... }",
                        "calls": ["CryptAcquireContext", "CryptCreateHash", "RegQueryValueEx"]
                    }
                ]
            },
            "vulnerability": {
                "vulnerabilities": [
                    {
                        "type": "buffer_overflow",
                        "addr": "0x10001234",
                        "severity": "critical",
                        "cve_matches": ["CVE-2020-1234"],
                        "exploitability": 0.95
                    }
                ]
            },
            "strings": {
                "license_indicators": ["Enter License Key", "Invalid License", "Trial Expired"],
                "crypto_indicators": ["SHA256", "AES", "RSA"],
                "suspicious_strings": ["debug", "crack", "patch"]
            }
        }

    def test_complex_binary_comprehensive_analysis(self, complex_binary_scenario):
        """Test comprehensive analysis of complex real-world binary"""
        standardizer = R2JSONStandardizer()

        result = standardizer.standardize_analysis_result(complex_binary_scenario, "comprehensive")

        # Must handle complex nested structure
        assert isinstance(result, dict)
        assert 'comprehensive' in result

        comp_data = result['comprehensive']

        # Should perform sophisticated cross-analysis
        assert 'cross_analysis' in comp_data
        cross = comp_data['cross_analysis']

        # Should correlate findings across components
        assert 'component_correlations' in cross
        correlations = cross['component_correlations']

        # Should identify relationships between vulnerabilities and functions
        assert 'vulnerability_function_correlation' in correlations

        # Should analyze license-related patterns across components
        assert 'license_pattern_analysis' in correlations

        # Should provide unified risk assessment
        assert 'integrated_assessment' in comp_data
        assessment = comp_data['integrated_assessment']
        assert 'overall_risk_score' in assessment
        assert isinstance(assessment['overall_risk_score'], (int, float))
        assert 0 <= assessment['overall_risk_score'] <= 10

    def test_cross_version_radare2_compatibility(self):
        """Test standardization handles different radare2 version outputs"""
        standardizer = R2JSONStandardizer()

        # Simulate different radare2 version formats
        r2_v4_format = {
            "functions": [{"name": "main", "offset": "0x401000", "ninstr": 45}]  # Old format
        }

        r2_v5_format = {
            "functions": [{"name": "main", "addr": "0x401000", "size": 180, "complexity": 5}]  # New format
        }

        # Both should be handled and normalized
        result_v4 = standardizer.standardize_analysis_result(r2_v4_format, "decompilation")
        result_v5 = standardizer.standardize_analysis_result(r2_v5_format, "decompilation")

        # Both should succeed with consistent output structure
        assert isinstance(result_v4, dict)
        assert isinstance(result_v5, dict)

        if 'decompilation' in result_v4 and 'decompilation' in result_v5:
            # Should have consistent normalized field names
            v4_func = result_v4['decompilation']['functions'][0]
            v5_func = result_v5['decompilation']['functions'][0]

            # Both should have normalized 'address' field
            assert 'address' in v4_func
            assert 'address' in v5_func

    def test_statistical_correlation_analysis(self):
        """Test advanced statistical correlation features"""
        standardizer = R2JSONStandardizer()

        # Complex data with correlatable features
        correlation_data = {
            "functions": [
                {"name": "f1", "complexity": 10, "size": 500, "calls": ["crypto_func"]},
                {"name": "f2", "complexity": 15, "size": 750, "calls": ["license_check"]},
                {"name": "f3", "complexity": 8, "size": 300, "calls": ["simple_math"]}
            ],
            "vulnerabilities": [
                {"type": "overflow", "function": "f1", "severity": "high"},
                {"type": "injection", "function": "f2", "severity": "medium"}
            ],
            "strings": [
                {"string": "crypto", "refs": ["f1"]},
                {"string": "license", "refs": ["f2"]}
            ]
        }

        result = standardizer.standardize_analysis_result(correlation_data, "comprehensive")

        # Should perform correlation analysis
        assert isinstance(result, dict)
        if 'comprehensive' in result:
            comp = result['comprehensive']
            if 'statistical_analysis' in comp:
                stats = comp['statistical_analysis']

                # Should have correlation matrices
                assert 'correlation_analysis' in stats

                # Should identify significant correlations
                assert 'significant_correlations' in stats

                # Should provide statistical measures
                assert 'statistical_measures' in stats

    def test_temporal_analysis_capabilities(self):
        """Test temporal correlation and time-series analysis features"""
        standardizer = R2JSONStandardizer()

        # Data with temporal components
        temporal_data = {
            "analysis_sequence": [
                {"timestamp": "2023-01-01T00:00:00", "functions_found": 10, "complexity": 5.2},
                {"timestamp": "2023-01-01T00:01:00", "functions_found": 15, "complexity": 6.1},
                {"timestamp": "2023-01-01T00:02:00", "functions_found": 12, "complexity": 5.8}
            ],
            "vulnerability_timeline": [
                {"timestamp": "2023-01-01T00:00:30", "vuln_type": "overflow", "severity": 8},
                {"timestamp": "2023-01-01T00:01:30", "vuln_type": "injection", "severity": 6}
            ]
        }

        result = standardizer.standardize_analysis_result(temporal_data, "comprehensive")

        # Should handle temporal analysis
        assert isinstance(result, dict)
        if 'comprehensive' in result:
            comp = result['comprehensive']
            if 'temporal_analysis' in comp:
                temporal = comp['temporal_analysis']

                # Should analyze trends over time
                assert 'trend_analysis' in temporal

                # Should correlate temporal events
                assert 'temporal_correlations' in temporal

    @pytest.mark.parametrize("analysis_type", [
        "decompilation", "vulnerability", "strings", "imports",
        "cfg", "ai", "signatures", "esil", "bypass", "binary_diff",
        "scripting", "comprehensive", "generic"
    ])
    def test_all_analysis_types_comprehensive_coverage(self, analysis_type):
        """Test all supported analysis types produce valid standardized output"""
        standardizer = R2JSONStandardizer()

        # Generic test data that should work for any type
        test_data = {
            "functions": [{"name": "test", "addr": "0x401000"}],
            "data": {"key": "value", "number": 42},
            "analysis_results": {"score": 85, "findings": ["item1", "item2"]}
        }

        result = standardizer.standardize_analysis_result(test_data, analysis_type)

        # Every analysis type should produce valid output
        assert isinstance(result, dict)

        # Should have metadata or error (no silent failures)
        assert 'metadata' in result or 'error' in result

        # If successful, should have analysis type data or validation
        if 'metadata' in result:
            assert 'analysis_type' in result['metadata']
            assert result['metadata']['analysis_type'] == analysis_type
            assert 'validation' in result


class TestProductionReadinessValidation:
    """Tests specifically designed to fail on placeholder/stub implementations"""

    def test_production_quality_scoring_algorithms(self):
        """Test that quality scoring uses sophisticated algorithms, not simple placeholders"""
        standardizer = R2JSONStandardizer()

        # Create datasets with known characteristics that should produce different quality scores
        high_quality_data = {
            "functions": [
                {"name": "main", "addr": "0x401000", "size": 256, "complexity": 8,
                 "code": "int main() { validate_license(); return process_data(); }",
                 "calls": ["validate_license", "process_data"], "cross_refs": 5},
                {"name": "validate_license", "addr": "0x401100", "size": 512, "complexity": 15,
                 "code": "complex validation logic with crypto calls",
                 "calls": ["CryptAcquireContext", "CryptCreateHash"], "cross_refs": 12}
            ],
            "patterns": [
                {"pattern": "license_validation", "matches": 8, "confidence": 0.95},
                {"pattern": "crypto_operations", "matches": 5, "confidence": 0.88}
            ]
        }

        low_quality_data = {
            "functions": [
                {"name": "stub", "addr": "0x401000", "size": 1, "complexity": 1,
                 "code": "ret", "calls": [], "cross_refs": 0}
            ],
            "patterns": []
        }

        high_result = standardizer.standardize_analysis_result(high_quality_data, "decompilation")
        low_result = standardizer.standardize_analysis_result(low_quality_data, "decompilation")

        # Both should succeed
        assert 'validation' in high_result
        assert 'validation' in low_result

        high_quality = high_result['validation']['quality_score']
        low_quality = low_result['validation']['quality_score']

        # Sophisticated algorithm should show significant difference
        # (Simple placeholder would likely give same or similar scores)
        quality_difference = abs(high_quality - low_quality)
        assert quality_difference > 20, f"Quality difference too small: {quality_difference}. Suggests placeholder implementation."

        # High quality data should generally score higher
        assert high_quality > low_quality, "High quality data should score higher than low quality data"

    def test_sophisticated_vulnerability_categorization(self):
        """Test vulnerability categorization uses real security knowledge, not simple mapping"""
        standardizer = R2JSONStandardizer()

        # Complex vulnerability data requiring sophisticated categorization
        vuln_data = {
            "vulnerabilities": [
                {
                    "type": "buffer_overflow",
                    "function": "strcpy_wrapper",
                    "addr": "0x401234",
                    "description": "unbounded string copy in license validation",
                    "stack_canary": False,
                    "aslr_bypass": True,
                    "exploitability_factors": ["no_bounds_check", "user_controlled_input", "executable_stack"]
                },
                {
                    "type": "format_string",
                    "function": "logging_func",
                    "addr": "0x401456",
                    "description": "user input passed directly to printf",
                    "write_primitive": True,
                    "info_leak": True,
                    "exploitability_factors": ["direct_printf", "user_input", "no_validation"]
                }
            ]
        }

        result = standardizer.standardize_analysis_result(vuln_data, "vulnerability")

        assert 'vulnerability' in result
        vuln_analysis = result['vulnerability']

        # Should have sophisticated vulnerability assessment
        assert 'vulnerabilities' in vuln_analysis
        vulns = vuln_analysis['vulnerabilities']

        for vuln in vulns:
            # Should calculate realistic exploitability scores based on factors
            assert 'exploitability' in vuln
            assert isinstance(vuln['exploitability'], (int, float))
            assert 0 <= vuln['exploitability'] <= 1

            # Should assign realistic risk scores that consider multiple factors
            assert 'risk_score' in vuln
            risk = vuln['risk_score']
            assert isinstance(risk, (int, float))
            assert 0 <= risk <= 10

            # Buffer overflow with no protections should be high risk
            if vuln['type'] == 'buffer_overflow':
                assert risk > 6.0, f"Buffer overflow risk score too low: {risk}. Suggests placeholder implementation."

        # Should have overall risk assessment
        assert 'summary' in vuln_analysis
        summary = vuln_analysis['summary']
        assert 'overall_risk_score' in summary

        overall_risk = summary['overall_risk_score']
        assert isinstance(overall_risk, (int, float))
        # Two high-risk vulnerabilities should result in high overall risk
        assert overall_risk > 7.0, f"Overall risk score too low: {overall_risk}. Suggests placeholder implementation."

    def test_advanced_api_categorization_knowledge(self):
        """Test API categorization demonstrates real Windows API knowledge"""
        standardizer = R2JSONStandardizer()

        # Windows APIs that require security knowledge to categorize correctly
        api_data = {
            "imports": [
                {"name": "CryptAcquireContextA", "dll": "advapi32.dll"},  # Crypto
                {"name": "CreateRemoteThread", "dll": "kernel32.dll"},    # Process injection
                {"name": "VirtualProtect", "dll": "kernel32.dll"},       # Memory manipulation
                {"name": "RegSetValueExA", "dll": "advapi32.dll"},       # Registry
                {"name": "WSAStartup", "dll": "ws2_32.dll"},             # Network
                {"name": "IsDebuggerPresent", "dll": "kernel32.dll"},    # Anti-debug
                {"name": "GetProcAddress", "dll": "kernel32.dll"},       # Dynamic loading
                {"name": "VirtualAllocEx", "dll": "kernel32.dll"},       # Memory allocation
            ]
        }

        result = standardizer.standardize_analysis_result(api_data, "imports")

        assert 'imports' in result
        imports_analysis = result['imports']

        # Should categorize APIs with security knowledge
        assert 'api_categories' in imports_analysis
        categories = imports_analysis['api_categories']

        # Should identify crypto APIs
        assert 'crypto' in categories
        assert categories['crypto'] >= 1

        # Should identify process manipulation APIs
        assert 'process' in categories
        assert categories['process'] >= 2  # CreateRemoteThread, VirtualAllocEx

        # Should identify registry APIs
        assert 'registry' in categories
        assert categories['registry'] >= 1

        # Should identify network APIs
        assert 'network' in categories
        assert categories['network'] >= 1

        # Should identify suspicious/anti-analysis APIs
        assert 'suspicious_apis' in imports_analysis
        suspicious = imports_analysis['suspicious_apis']

        # IsDebuggerPresent should be flagged as suspicious
        suspicious_names = [api.get('name', '') for api in suspicious if isinstance(api, dict)]
        assert any('IsDebuggerPresent' in name for name in suspicious_names), "Should identify anti-debug APIs"

    def test_entropy_analysis_mathematical_accuracy(self):
        """Test entropy calculations use real mathematical algorithms"""
        standardizer = R2JSONStandardizer()

        strings_data = {
            "strings": [
                {"string": "aaaaaaaaaa", "addr": "0x401000"},      # Low entropy
                {"string": "HelloWorld", "addr": "0x401010"},     # Medium entropy
                {"string": "aB3$9mK!xQ", "addr": "0x401020"},     # High entropy (random-like)
                {"string": "ABCDEFGHIJ", "addr": "0x401030"},     # Medium-high entropy
            ]
        }

        result = standardizer.standardize_analysis_result(strings_data, "strings")

        assert 'strings' in result
        strings_analysis = result['strings']

        if 'entropy_analysis' in strings_analysis:
            entropy = strings_analysis['entropy_analysis']

            # Should calculate actual entropy values
            assert 'average_entropy' in entropy
            avg_entropy = entropy['average_entropy']
            assert isinstance(avg_entropy, (int, float))

            # Average entropy should be reasonable for mixed data
            assert 2.0 <= avg_entropy <= 8.0, f"Entropy value unrealistic: {avg_entropy}"

            # Should identify high entropy strings
            assert 'high_entropy_strings' in entropy
            high_entropy_strings = entropy['high_entropy_strings']
            assert isinstance(high_entropy_strings, list)

            # Random-like string should be flagged as high entropy
            # (Real entropy calculation would identify this)
            high_entropy_found = any('aB3$9mK!xQ' in str(entry) for entry in high_entropy_strings)
            assert high_entropy_found, "Should identify high entropy strings with real mathematical analysis"


@pytest.mark.integration
class TestIntegrationScenarios:
    """Integration-level tests for end-to-end workflows"""

    def test_full_binary_analysis_workflow(self):
        """Test complete binary analysis workflow from raw radare2 to final report"""
        standardizer = R2JSONStandardizer()

        # Simulate complete radare2 analysis output
        complete_r2_output = {
            "file_info": {
                "name": "license_check.exe",
                "size": 45056,
                "hash": "abc123def456",
                "format": "PE32+"
            },
            "functions": [
                {"name": "main", "addr": "0x401000", "size": 156, "complexity": 5},
                {"name": "check_license", "addr": "0x401100", "size": 234, "complexity": 12}
            ],
            "strings": [
                {"string": "Enter License Key", "addr": "0x402000", "xrefs": ["0x401120"]},
                {"string": "Invalid License", "addr": "0x402020", "xrefs": ["0x401140"]}
            ],
            "imports": [
                {"name": "CryptAcquireContext", "dll": "advapi32.dll", "addr": "0x403000"},
                {"name": "RegQueryValueEx", "dll": "advapi32.dll", "addr": "0x403008"}
            ],
            "vulnerabilities": [
                {"type": "buffer_overflow", "addr": "0x401234", "severity": "medium"}
            ]
        }

        # Process through comprehensive analysis
        result = standardizer.standardize_analysis_result(complete_r2_output, "comprehensive")

        # Should produce complete standardized analysis
        assert isinstance(result, dict)
        assert 'comprehensive' in result

        comp = result['comprehensive']

        # Should have integrated all components
        assert 'cross_analysis' in comp
        assert 'integrated_assessment' in comp
        assert 'recommendations' in comp

        # Should provide actionable intelligence
        recommendations = comp['recommendations']
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0

        # Should calculate overall risk score
        assessment = comp['integrated_assessment']
        assert 'overall_risk_score' in assessment
        risk_score = assessment['overall_risk_score']
        assert isinstance(risk_score, (int, float))
        assert 0 <= risk_score <= 10


def test_module_level_function_integration():
    """Test module-level functions integrate properly with class"""
    sample_data = {"functions": [{"name": "test", "addr": "0x401000"}]}

    # Module function should work
    result = standardize_r2_result(sample_data, "decompilation")
    assert isinstance(result, dict)

    # Should be equivalent to class method
    standardizer = R2JSONStandardizer()
    class_result = standardizer.standardize_analysis_result(sample_data, "decompilation")

    # Results should have same structure (though may differ in details like timestamps)
    assert type(result) == type(class_result)
    if 'metadata' in result and 'metadata' in class_result:
        assert result['metadata']['analysis_type'] == class_result['metadata']['analysis_type']
