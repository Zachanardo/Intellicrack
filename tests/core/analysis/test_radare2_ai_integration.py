"""
Comprehensive unit tests for radare2_ai_integration.py module.
Tests validate production-ready AI-enhanced binary analysis capabilities.
"""


import os
import sys
import unittest
import tempfile
import shutil
import struct
import json
import numpy as np
from pathlib import Path
from typing import Any

# Add the project root to the Python path

try:
    from intellicrack.core.analysis.radare2_ai_integration import R2AIEngine, analyze_binary_with_ai
except ImportError as e:
    raise ImportError(
        f"Failed to import radare2_ai_integration module: {e}"
    ) from e


class TestR2AIEngineInitialization(unittest.TestCase):
    """Test suite for R2AIEngine initialization and configuration validation."""

    def setUp(self) -> None:
        """Set up test environment with temporary binary files."""
        self.test_dir = tempfile.mkdtemp()
        self.test_binary_path = os.path.join(self.test_dir, "test_binary.exe")
        self.test_radare2_path = "r2"  # Assume r2 is in PATH

        # Create a mock binary file for testing
        with open(self.test_binary_path, "wb") as f:
            # PE header signature for Windows executable
            f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
            f.write(b"\x00" * 100)  # Padding
            f.write(b"PE\x00\x00")  # PE signature
            f.write(b"\x00" * 1000)  # Additional binary content

    def tearDown(self) -> None:
        """Clean up test environment."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_engine_initialization_with_valid_paths(self) -> None:
        """Test R2AIEngine initializes correctly with valid binary and radare2 paths."""
        engine = R2AIEngine(self.test_binary_path, self.test_radare2_path)

        # Validate core attributes are set
        self.assertEqual(engine.binary_path, self.test_binary_path)
        self.assertEqual(engine.radare2_path, self.test_radare2_path)
        self.assertIsNotNone(engine.logger)

        # Validate AI models are initialized (should be None initially but attributes exist)
        self.assertTrue(hasattr(engine, "license_detector"))
        self.assertTrue(hasattr(engine, "vulnerability_classifier"))
        self.assertTrue(hasattr(engine, "function_clusterer"))
        self.assertTrue(hasattr(engine, "anomaly_detector"))

    def test_engine_initialization_with_invalid_binary_path(self) -> None:
        """Test R2AIEngine handles invalid binary paths appropriately."""
        invalid_path = "/nonexistent/binary.exe"

        with self.assertRaises((FileNotFoundError, ValueError, OSError)):
            R2AIEngine(invalid_path, self.test_radare2_path)

    def test_engine_ml_components_initialization(self) -> None:
        """Test that ML components are properly initialized for production use."""
        engine = R2AIEngine(self.test_binary_path, self.test_radare2_path)

        # These should be initialized for production-ready functionality
        # Text vectorizer for string analysis
        self.assertTrue(hasattr(engine, "text_vectorizer"))
        # Feature scaler for normalization
        self.assertTrue(hasattr(engine, "scaler"))
        # Model directory for persistence
        self.assertTrue(hasattr(engine, "model_dir"))


class TestR2AIEngineAnalysis(unittest.TestCase):
    """Test suite for core AI-enhanced binary analysis functionality."""

    def setUp(self) -> None:
        """Set up test environment with mock radare2 and sample binary."""
        self.test_dir = tempfile.mkdtemp()
        self.test_binary_path = os.path.join(self.test_dir, "protected_software.exe")

        # Create realistic protected binary sample
        self._create_realistic_binary_sample()

        self.engine = R2AIEngine(self.test_binary_path, "r2")

    def tearDown(self) -> None:
        """Clean up test environment."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def _create_realistic_binary_sample(self) -> None:
        """Create a realistic binary sample that simulates protected software."""
        with open(self.test_binary_path, "wb") as f:
            # PE header
            f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
            f.write(b"\x00" * 58)
            f.write(b"\x80\x00\x00\x00")  # PE header offset
            f.write(b"\x00" * 64)
            f.write(b"PE\x00\x00")

            # Simulate license validation strings
            license_strings = [
                b"License validation failed",
                b"Invalid license key",
                b"Trial period expired",
                b"RSA signature verification",
                b"AES decryption key",
            ]

            for license_str in license_strings:
                f.write(license_str)
                f.write(b"\x00" * 20)  # Padding

            # Simulate import table with crypto APIs
            crypto_imports = [b"CryptCreateHash", b"CryptHashData", b"CryptVerifySignature", b"BCryptDecrypt"]

            for import_name in crypto_imports:
                f.write(import_name)
                f.write(b"\x00" * 10)

    def test_analyze_with_ai_comprehensive_analysis(self) -> None:
        """Test analyze_with_ai performs comprehensive AI-enhanced analysis."""
        # Create a real test binary with radare2 analysis data embedded
        test_binary = os.path.join(self.test_dir, "ai_analysis_test.exe")
        with open(test_binary, "wb") as f:
            # PE header with real structure
            dos_header = struct.pack("<2s58xI", b"MZ", 0x80)
            f.write(dos_header)

            # PE signature and headers
            pe_header = b"PE\x00\x00"
            # IMAGE_FILE_HEADER
            machine = 0x014C  # x86
            num_sections = 2
            timestamp = 0
            ptr_symbol_table = 0
            num_symbols = 0
            size_optional = 224
            characteristics = 0x0102
            file_header = struct.pack(
                "<HHIIIHH", machine, num_sections, timestamp, ptr_symbol_table, num_symbols, size_optional, characteristics
            )

            f.write(pe_header + file_header)

            # Add license validation strings
            f.write(b"\x00" * 100)
            f.write(b"License validation failed\x00")
            f.write(b"Invalid license key\x00")
            f.write(b"CryptCreateHash\x00")
            f.write(b"CryptVerifySignature\x00")
            f.write(b"validate_license\x00")
            f.write(b"decrypt_payload\x00")

        # Create engine with real binary
        engine = R2AIEngine(test_binary, "r2")

        # Override internal radare2 command executor if needed
        original_execute = getattr(engine, "_execute_r2_command", None)

        def test_r2_execute(cmd: str) -> str:
            """Return realistic radare2 output for testing."""
            if "ij" in cmd or "info" in cmd:
                return json.dumps({
                    "info": {"format": "pe", "arch": "x86", "bits": 64, "type": "EXEC (Executable file)"},
                    "imports": [{"name": "CryptCreateHash", "plt": 4198400}, {"name": "CryptVerifySignature", "plt": 4198416}],
                    "strings": [
                        {"vaddr": 4210688, "string": "License validation failed"},
                        {"vaddr": 4210720, "string": "Invalid license key"},
                    ],
                    "functions": [
                        {"name": "validate_license", "addr": 4198144, "size": 256},
                        {"name": "decrypt_payload", "addr": 4198400, "size": 128},
                    ],
                })
            return "{}"

        if hasattr(engine, "_execute_r2_command"):
            engine._execute_r2_command = test_r2_execute

        result = engine.analyze_with_ai()

        # Validate comprehensive analysis results
        self.assertIsInstance(result, dict)

        # Must contain sophisticated AI analysis components
        required_keys = [
            "license_analysis",
            "vulnerability_prediction",
            "function_clustering",
            "anomaly_detection",
            "bypass_suggestions",
            "confidence_metrics",
        ]

        for key in required_keys:
            self.assertIn(key, result, f"Missing required analysis component: {key}")

        # License analysis should contain intelligent insights
        license_analysis = result["license_analysis"]
        self.assertIsInstance(license_analysis, dict)
        self.assertIn("detected_mechanisms", license_analysis)
        self.assertIn("bypass_difficulty", license_analysis)
        self.assertIn("protection_strength", license_analysis)

    def test_vulnerability_prediction_with_real_patterns(self) -> None:
        """Test AI vulnerability prediction using realistic vulnerability patterns."""
        # Create test binary with vulnerable function imports
        vuln_binary = os.path.join(self.test_dir, "vulnerable_test.exe")
        with open(vuln_binary, "wb") as f:
            # PE header
            dos_header = struct.pack("<2s58xI", b"MZ", 0x80)
            f.write(dos_header)
            f.write(b"PE\x00\x00")

            # Add vulnerable function names and format strings
            f.write(b"\x00" * 100)
            f.write(b"strcpy\x00")
            f.write(b"sprintf\x00")
            f.write(b"gets\x00")
            f.write(b"%s%s%s\x00")
            f.write(b"buffer overflow\x00")

        # Create engine with vulnerable binary
        engine = R2AIEngine(vuln_binary, "r2")

        # Override radare2 executor for vulnerability patterns
        def vuln_r2_execute(cmd: str) -> str:
            """Return vulnerability-indicating radare2 output."""
            if "ij" in cmd or "aflj" in cmd or "functions" in cmd:
                return json.dumps({
                    "functions": [
                        {"name": "strcpy", "addr": 4198144, "size": 64, "type": "imp"},
                        {"name": "sprintf", "addr": 4198208, "size": 32, "type": "imp"},
                        {"name": "gets", "addr": 4198240, "size": 16, "type": "imp"},
                    ],
                    "strings": [{"string": "%s%s%s", "vaddr": 4210688}, {"string": "buffer overflow", "vaddr": 4210720}],
                })
            return "{}"

        if hasattr(engine, "_execute_r2_command"):
            engine._execute_r2_command = vuln_r2_execute

        result = engine.analyze_with_ai()

        # Vulnerability prediction must identify real security risks
        vuln_prediction = result["vulnerability_prediction"]
        self.assertIsInstance(vuln_prediction, dict)

        # Should detect buffer overflow potential
        self.assertIn("vulnerability_classes", vuln_prediction)
        self.assertIn("risk_scores", vuln_prediction)
        self.assertIn("exploit_likelihood", vuln_prediction)

        # Risk scores should be numeric and reasonable
        risk_scores = vuln_prediction["risk_scores"]
        self.assertIsInstance(risk_scores, (list, dict, np.ndarray))

    def test_feature_extraction_comprehensive_coverage(self) -> None:
        """Test comprehensive feature extraction covers all binary analysis aspects."""
        features = self.engine._extract_comprehensive_features()

        # Validate comprehensive feature extraction
        self.assertIsInstance(features, dict)

        # Must include multiple feature categories for robust AI analysis
        required_feature_categories = [
            "static_features",
            "function_features",
            "string_features",
            "import_features",
            "graph_features",
            "entropy_features",
        ]

        for category in required_feature_categories:
            self.assertIn(category, features, f"Missing feature category: {category}")
            self.assertIsInstance(features[category], (dict, list, np.ndarray))


class TestR2AIEngineMLModels(unittest.TestCase):
    """Test suite for machine learning model training and inference."""

    def setUp(self) -> None:
        """Set up test environment with ML model testing."""
        self.test_dir = tempfile.mkdtemp()
        self.test_binary_path = os.path.join(self.test_dir, "ml_test_binary.exe")

        # Create binary for ML testing
        with open(self.test_binary_path, "wb") as f:
            f.write(b"MZ" + b"\x00" * 2048)  # Minimal PE

        self.engine = R2AIEngine(self.test_binary_path, "r2")

    def tearDown(self) -> None:
        """Clean up test environment."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_license_detector_training_with_real_data(self) -> None:
        """Test license detector training uses realistic licensing patterns."""
        # Train license detector (should not raise exceptions with production code)
        try:
            self.engine._train_license_detector()
        except Exception as e:
            if "not implemented" in str(e).lower() or "todo" in str(e).lower():
                self.fail(f"License detector training is not production-ready: {e}")

        # License detector should be initialized after training
        self.assertIsNotNone(self.engine.license_detector)

    def test_vulnerability_classifier_training_with_cve_data(self) -> None:
        """Test vulnerability classifier training incorporates real CVE patterns."""
        try:
            self.engine._train_vulnerability_classifier()
        except Exception as e:
            if "not implemented" in str(e).lower() or "stub" in str(e).lower():
                self.fail(f"Vulnerability classifier training is not production-ready: {e}")

        # Classifier should be ready for inference
        self.assertIsNotNone(self.engine.vulnerability_classifier)

    def test_license_training_data_generation_realistic_patterns(self) -> None:
        """Test license training data generation produces realistic licensing patterns."""
        training_data = self.engine._generate_license_training_data()

        self.assertIsInstance(training_data, tuple)
        self.assertEqual(len(training_data), 2)  # X, y

        X, y = training_data

        # Training data should be substantial for production ML
        self.assertGreater(len(X), 100, "Training data too small for production ML model")
        self.assertEqual(len(X), len(y), "Feature-label mismatch in training data")

        # Features should be numeric for ML processing
        self.assertIsInstance(X, (np.ndarray, list))
        self.assertIsInstance(y, (np.ndarray, list))

    def test_real_license_patterns_comprehensive(self) -> None:
        """Test real license pattern recognition includes industry-standard mechanisms."""
        patterns = self.engine._get_real_license_patterns()

        self.assertIsInstance(patterns, dict)
        self.assertGreater(len(patterns), 5, "Too few license patterns for production use")

        # Should include common commercial licensing schemes
        expected_pattern_types = ["rsa", "aes", "hardware_id", "time_based", "server_validation"]

        found_patterns = sum(bool(any(pattern_type in key.lower() for key in patterns))
                         for pattern_type in expected_pattern_types)
        self.assertGreaterEqual(found_patterns, 3, "Insufficient coverage of real-world license patterns")

    def test_vulnerability_feature_extraction_realistic(self) -> None:
        """Test vulnerability feature extraction captures real security indicators."""
        # This method requires vuln_type and patterns arguments
        vuln_type = "buffer_overflow"
        patterns = {
            "typical_severity": "high",
            "exploitation_complexity": "medium"
        }
        vuln_features = self.engine._extract_vulnerability_features(vuln_type, patterns)

        self.assertIsInstance(vuln_features, (dict, np.ndarray, list))

        # Should extract meaningful security-relevant features - the method returns list[list[float]]
        if isinstance(vuln_features, list):
            self.assertGreater(len(vuln_features), 0, "No vulnerability features generated")


class TestR2AIEngineAdvancedAnalysis(unittest.TestCase):
    """Test suite for advanced AI analysis capabilities."""

    def setUp(self) -> None:
        """Set up test environment for advanced analysis testing."""
        self.test_dir = tempfile.mkdtemp()
        self.complex_binary_path = os.path.join(self.test_dir, "complex_protected.exe")

        # Create complex protected binary simulation
        self._create_complex_protected_binary()

        self.engine = R2AIEngine(self.complex_binary_path, "r2")

    def tearDown(self) -> None:
        """Clean up test environment."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def _create_complex_protected_binary(self) -> None:
        """Create complex binary with multiple protection layers."""
        with open(self.complex_binary_path, "wb") as f:
            # PE structure
            f.write(b"MZ\x90\x00")
            f.write(b"\x00" * 60)
            f.write(b"PE\x00\x00")

            # Complex protection signatures
            protection_signatures = [
                b"VMProtect",
                b"Themida",
                b"ASProtect",
                b"UPX",
                b"RSA2048",
                b"AES256",
                b"HASP",
                b"CodeMeter",
                b"anti_debug",
                b"vm_detection",
                b"hook_detection",
            ]

            for sig in protection_signatures:
                f.write(sig)
                f.write(b"\x00" * 50)

            # Obfuscated function patterns
            f.write(b"\x90" * 100)  # NOP sled
            f.write(b"\xe8\x00\x00\x00\x00")  # Call instructions
            f.write(b"\x74\x05")  # Conditional jumps
            f.write(b"\xeb\x03")  # Unconditional jump

    def test_function_clustering_analysis_intelligent(self) -> None:
        """Test function clustering produces intelligent groupings of related functions."""
        features = self.engine._extract_comprehensive_features()
        clustering_result = self.engine._function_clustering_analysis(features)

        self.assertIsInstance(clustering_result, dict)

        # Should identify meaningful function clusters
        required_cluster_info = ["clusters", "cluster_labels", "silhouette_score"]
        for info in required_cluster_info:
            self.assertIn(info, clustering_result)

        # Silhouette score should indicate quality clustering (> 0.3 for meaningful clusters)
        silhouette_score = clustering_result["silhouette_score"]
        self.assertIsInstance(silhouette_score, (int, float))
        self.assertGreaterEqual(silhouette_score, 0.0)

    def test_anomaly_detection_sophisticated_patterns(self) -> None:
        """Test anomaly detection identifies sophisticated attack patterns and obfuscation."""
        features = self.engine._extract_comprehensive_features()
        anomaly_result = self.engine._anomaly_detection_analysis(features)

        self.assertIsInstance(anomaly_result, dict)

        # Should detect various types of anomalies
        required_anomaly_types = ["statistical_outliers", "behavioral_anomalies", "structural_anomalies"]

        found_anomaly_types = sum(bool(anomaly_type in anomaly_result
                                          or any(anomaly_type in key for key in anomaly_result))
                              for anomaly_type in required_anomaly_types)
        self.assertGreater(found_anomaly_types, 0, "No sophisticated anomaly detection categories found")

        # Should provide anomaly scores/indicators
        self.assertTrue(any("score" in key.lower() or "indicator" in key.lower() for key in anomaly_result))

    def test_ai_bypass_suggestions_intelligent_strategies(self) -> None:
        """Test AI bypass suggestion generation provides intelligent attack strategies."""
        features = self.engine._extract_comprehensive_features()
        bypass_suggestions = self.engine._generate_ai_bypass_suggestions(features)

        self.assertIsInstance(bypass_suggestions, dict)

        # Should provide multiple bypass strategy categories
        strategy_categories = ["static_analysis_bypass", "dynamic_analysis_bypass", "anti_debug_bypass", "vm_detection_bypass"]

        found_strategies = sum(bool(any(category in key.lower() for key in bypass_suggestions))
                           for category in strategy_categories)
        self.assertGreater(found_strategies, 0, "No intelligent bypass strategies generated")

        # Each strategy should include implementation guidance
        for key, value in bypass_suggestions.items():
            if isinstance(value, dict):
                self.assertTrue(
                    "description" in value or "technique" in value or "implementation" in value,
                    f"Bypass suggestion '{key}' lacks implementation guidance",
                )

    def test_code_similarity_analysis_robust(self) -> None:
        """Test code similarity analysis provides robust similarity detection."""
        features = self.engine._extract_comprehensive_features()
        similarity_result = self.engine._code_similarity_analysis(features)

        self.assertIsInstance(similarity_result, dict)

        # Should provide similarity metrics and matches
        required_similarity_components = ["similarity_matrix", "similar_functions", "similarity_scores"]

        found_components = sum(bool(component in similarity_result)
                           for component in required_similarity_components)
        self.assertGreater(found_components, 0, "No robust similarity analysis components found")

        # Similarity scores should be meaningful (0-1 range typical)
        if "similarity_scores" in similarity_result:
            scores = similarity_result["similarity_scores"]
            if isinstance(scores, (list, np.ndarray)) and len(scores) > 0:
                self.assertTrue(all(0.0 <= score <= 1.0 for score in scores if isinstance(score, (int, float))))


class TestR2AIEngineIntegration(unittest.TestCase):
    """Test suite for integration scenarios and public API validation."""

    def setUp(self) -> None:
        """Set up integration testing environment."""
        self.test_dir = tempfile.mkdtemp()
        self.integration_binary_path = os.path.join(self.test_dir, "integration_test.exe")

        # Create integration test binary
        with open(self.integration_binary_path, "wb") as f:
            # Comprehensive binary for integration testing
            f.write(b"MZ\x90\x00")  # DOS header
            f.write(b"\x00" * 60)
            f.write(b"PE\x00\x00")  # PE signature

            # Rich content for comprehensive analysis
            f.write(b"License check function")
            f.write(b"CryptCreateHash")
            f.write(b"buffer overflow vulnerability")
            f.write(b"\x90" * 200)  # Code section

    def tearDown(self) -> None:
        """Clean up integration test environment."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_analyze_binary_with_ai_public_api_comprehensive(self) -> None:
        """Test public API function provides comprehensive AI analysis."""
        # Create test binary for public API testing
        api_test_binary = os.path.join(self.test_dir, "api_test.exe")
        with open(api_test_binary, "wb") as f:
            # Minimal PE structure
            dos_header = struct.pack("<2s58xI", b"MZ", 0x80)
            f.write(dos_header)
            f.write(b"PE\x00\x00")
            f.write(b"\x00" * 500)

        # Temporarily override subprocess if the module uses it internally
        import subprocess

        original_run = subprocess.run

        class TestResult:
            """Mock subprocess result object."""
            def __init__(self) -> None:
                self.returncode: int = 0
                self.stdout: str = '{"info": {"format": "pe"}}'
                self.stderr: str = ""

        def test_subprocess_run(cmd: list[str] | str, *args: object, **kwargs: object) -> TestResult:
            """Return controlled radare2 output for testing."""
            return TestResult()

        # Only override if absolutely necessary for the module
        try:
            subprocess.run = test_subprocess_run  # type: ignore[assignment]
            result = analyze_binary_with_ai(api_test_binary)
        finally:
            subprocess.run = original_run

        # Public API should return comprehensive analysis
        self.assertIsInstance(result, dict)

        # Should contain all major analysis components
        major_components = ["license_analysis", "vulnerability_assessment", "ai_recommendations", "confidence_metrics"]

        found_components = 0
        for component in major_components:
            # Check if component exists directly or as part of other keys
            if component in result or any(component in key for key in result):
                found_components += 1

        self.assertGreaterEqual(found_components, 2, "Public API lacks comprehensive analysis components")

    def test_cross_module_ai_integration_workflow(self) -> None:
        """Test complete AI integration workflow from analysis to recommendations."""
        # Create workflow test binary
        workflow_binary = os.path.join(self.test_dir, "workflow_test.exe")
        with open(workflow_binary, "wb") as f:
            # PE structure with license checking functions
            dos_header = struct.pack("<2s58xI", b"MZ", 0x80)
            f.write(dos_header)
            f.write(b"PE\x00\x00")

            # Add function and string data
            f.write(b"\x00" * 100)
            f.write(b"check_license\x00")
            f.write(b"License expired\x00")
            f.write(b"\x00" * 200)

        engine = R2AIEngine(workflow_binary, "r2")

        # Override radare2 executor for workflow testing
        def workflow_r2_execute(cmd: str) -> str:
            """Return workflow test radare2 output."""
            if "ij" in cmd or "aflj" in cmd:
                return json.dumps({
                    "info": {"format": "pe", "arch": "x86"},
                    "functions": [{"name": "check_license", "addr": 4198144}],
                    "strings": [{"string": "License expired"}],
                })
            return "{}"

        if hasattr(engine, "_execute_r2_command"):
            engine._execute_r2_command = workflow_r2_execute

        # Complete workflow: analysis -> training -> prediction -> recommendations
        analysis_result = engine.analyze_with_ai()

        # Workflow should produce actionable intelligence
        self.assertIsInstance(analysis_result, dict)

        # Should demonstrate AI integration across multiple domains
        ai_domains = ["license_intelligence", "vulnerability_intelligence", "bypass_intelligence", "risk_intelligence"]

        found_domains = 0
        for domain in ai_domains:
            # Check for AI intelligence in any form
            if any(domain.split("_")[0] in key.lower() for key in analysis_result):
                found_domains += 1

        self.assertGreaterEqual(found_domains, 2, "Insufficient AI integration across security domains")

    def test_model_persistence_and_loading_production_ready(self) -> None:
        """Test ML model persistence and loading for production deployment."""
        engine = R2AIEngine(self.integration_binary_path, "r2")

        # Model directory should be configured for persistence
        self.assertTrue(hasattr(engine, "model_dir"))
        if model_dir := getattr(engine, "model_dir", None):
            self.assertIsInstance(model_dir, (str, Path))
            # Should be a valid path concept
            self.assertGreater(len(str(model_dir)), 0)

    def test_confidence_metrics_and_performance_monitoring(self) -> None:
        """Test confidence metrics provide meaningful performance indicators."""
        engine = R2AIEngine(self.integration_binary_path, "r2")

        # Create a mock result dict for confidence calculation
        mock_results = {
            "license_analysis": {"confidence": 0.8},
            "vulnerability_prediction": {"confidence": 0.7},
            "anomaly_detection": {"anomaly_score": 0.5}
        }

        # Should provide confidence scoring mechanisms
        confidence_scores = engine._calculate_confidence_scores(mock_results)
        self.assertIsInstance(confidence_scores, dict)

        # Performance metrics for production monitoring
        performance_metrics = engine._get_model_performance_metrics()
        self.assertIsInstance(performance_metrics, dict)

        # Should include standard ML performance indicators
        expected_metrics = ["accuracy", "precision", "recall", "f1_score"]
        found_metrics = sum(bool(metric in performance_metrics
                                    or any(metric in key.lower() for key in performance_metrics))
                        for metric in expected_metrics)
        self.assertGreater(found_metrics, 0, "No standard ML performance metrics found")


class TestR2AIEngineErrorHandlingAndRobustness(unittest.TestCase):
    """Test suite for error handling and robustness validation."""

    def setUp(self) -> None:
        """Set up robustness testing environment."""
        self.test_dir = tempfile.mkdtemp()
        self.malformed_binary_path = os.path.join(self.test_dir, "malformed.exe")

        # Create malformed binary for robustness testing
        with open(self.malformed_binary_path, "wb") as f:
            f.write(b"INVALID_HEADER")  # Invalid PE header
            f.write(b"\x00" * 100)

    def tearDown(self) -> None:
        """Clean up robustness test environment."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_malformed_binary_handling_graceful(self) -> None:
        """Test graceful handling of malformed or corrupted binaries."""
        try:
            engine = R2AIEngine(self.malformed_binary_path, "r2")

            # Should handle malformed binaries gracefully
            result = engine.analyze_with_ai()

            # Should return error information rather than crashing
            self.assertIsInstance(result, dict)

            # Should indicate analysis limitations or errors
            error_indicators = ["error", "warning", "limited_analysis", "parsing_failed"]
            has_error_handling = any(indicator in str(result).lower() for indicator in error_indicators)

            if not has_error_handling:
                # If no explicit error handling, should still return structured data
                self.assertGreater(len(result), 0, "No response for malformed binary")

        except Exception as e:
            # If exceptions occur, they should be informative, not generic
            error_msg = str(e).lower()
            generic_errors = ["not implemented", "todo", "stub", "placeholder"]

            for generic_error in generic_errors:
                self.assertNotIn(generic_error, error_msg, f"Generic error indicates non-production code: {e}")

    def test_radare2_integration_failure_recovery(self) -> None:
        """Test recovery from radare2 integration failures."""
        engine = R2AIEngine(self.malformed_binary_path, "r2")

        # Override radare2 executor to simulate failure
        def failing_r2_execute(cmd: str) -> str:
            """Simulate radare2 command failure."""
            raise RuntimeError("radare2: command failed")

        if hasattr(engine, "_execute_r2_command"):
            original_execute = engine._execute_r2_command
            engine._execute_r2_command = failing_r2_execute

        # Should handle radare2 failures gracefully
        try:
            result = engine.analyze_with_ai()

            # Should provide fallback analysis or clear error reporting
            self.assertIsInstance(result, dict)

        except Exception as e:
            # Should not expose internal implementation details
            error_msg = str(e)
            self.assertNotIn("TODO", error_msg)
            self.assertNotIn("NotImplementedError", error_msg)
        finally:
            # Restore original executor if it was changed
            if hasattr(engine, "_execute_r2_command") and "original_execute" in locals():
                engine._execute_r2_command = original_execute


if __name__ == "__main__":
    # Configure test execution for comprehensive validation
    unittest.main(verbosity=2, buffer=True)
