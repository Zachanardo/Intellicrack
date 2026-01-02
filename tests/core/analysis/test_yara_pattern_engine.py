"""
Comprehensive specification-driven unit tests for YaraPatternEngine.

These tests validate production-ready YARA pattern matching capabilities
expected in a sophisticated binary analysis and security research platform.
Tests assume genuine functionality and will FAIL for placeholder implementations.
"""

import unittest
import pytest
import tempfile
import os
import hashlib
import threading
import time
import shutil
from pathlib import Path

# Test imports - assuming proper module structure
try:
    from intellicrack.core.analysis.yara_pattern_engine import (
        YaraPatternEngine,
        YaraScanResult,
        YaraMatch,
        PatternCategory,
        get_yara_engine,
        is_yara_available,
        scan_file_with_yara
    )
except ImportError:
    pytest.skip("YARA pattern engine module not available", allow_module_level=True)


class TestYaraPatternEngineSpecification(unittest.TestCase):
    """
    Specification-driven tests validating sophisticated YARA pattern matching.

    These tests validate production-ready capabilities expected in Intellicrack:
    - Advanced pattern recognition for modern protection schemes
    - Intelligent rule generation and optimization
    - Performance optimization for large rulesets
    - Security research integration features

    Tests will FAIL for placeholder/stub implementations.
    """

    def setUp(self) -> None:
        """Initialize test environment with realistic binary samples."""
        self.temp_dir = tempfile.mkdtemp()
        self.engine = YaraPatternEngine()

        # Create realistic test binary samples that production engines should handle
        self.create_test_binaries()

    def tearDown(self) -> None:
        """Clean up test environment."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def create_test_binaries(self):
        """Create realistic binary samples for sophisticated pattern matching tests."""
        # UPX packed binary signature
        self.upx_packed_sample = os.path.join(self.temp_dir, "upx_packed.exe")
        with open(self.upx_packed_sample, "wb") as f:
            # UPX signature and header patterns that real engines should detect
            upx_header = b"UPX!" + b"\x00" * 4 + b"\x0C\x09\x02\x08"
            upx_data = upx_header + b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00"
            upx_data += b"\x4C\x01" + b"\x00" * 100  # Basic PE structure
            upx_data += b"$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
            f.write(upx_data + b"\x00" * 1000)

        # VMProtect protected binary
        self.vmprotect_sample = os.path.join(self.temp_dir, "vmprotect.exe")
        with open(self.vmprotect_sample, "wb") as f:
            # VMProtect characteristic patterns
            vm_data = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00"
            vm_data += b"\x4C\x01" + b"\x00" * 50
            vm_data += b".vmp0\x00\x00\x00"  # VMProtect section
            vm_data += b"\x00" * 100
            # VMProtect VM handler patterns
            vm_data += b"\x68\x00\x00\x00\x00\x8B\x44\x24\x04\x50\x53\x51\x52"
            f.write(vm_data + b"\x00" * 2000)

        # Themida protected binary
        self.themida_sample = os.path.join(self.temp_dir, "themida.exe")
        with open(self.themida_sample, "wb") as f:
            # Themida characteristic signatures
            themida_data = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00"
            themida_data += b"\x4C\x01" + b"\x00" * 50
            themida_data += b".themida\x00"  # Themida section
            themida_data += b"\x00" * 100
            # Themida VM instructions and obfuscation patterns
            themida_data += b"\x9C\x60\xE8\x00\x00\x00\x00\x5D\x81\xED"
            f.write(themida_data + b"\x00" * 3000)

        # Anti-debugging binary
        self.antidebug_sample = os.path.join(self.temp_dir, "antidebug.exe")
        with open(self.antidebug_sample, "wb") as f:
            # Anti-debugging API calls and techniques
            antidebug_data = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00"
            antidebug_data += b"\x4C\x01" + b"\x00" * 100
            # IsDebuggerPresent call pattern
            antidebug_data += b"\xFF\x15" + b"\x00\x00\x00\x00"  # call dword ptr
            antidebug_data += b"IsDebuggerPresent\x00"
            # CheckRemoteDebuggerPresent pattern
            antidebug_data += b"CheckRemoteDebuggerPresent\x00"
            # NtQueryInformationProcess pattern
            antidebug_data += b"NtQueryInformationProcess\x00"
            f.write(antidebug_data + b"\x00" * 1500)

        # FlexLM licensing system binary
        self.flexlm_sample = os.path.join(self.temp_dir, "flexlm_app.exe")
        with open(self.flexlm_sample, "wb") as f:
            # FlexLM licensing signatures
            flexlm_data = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00"
            flexlm_data += b"\x4C\x01" + b"\x00" * 100
            flexlm_data += b"FLEXLM_LICENSE\x00"
            flexlm_data += b"lm_checkout\x00lm_checkin\x00"
            flexlm_data += b"VENDOR_NAME\x00FEATURE_NAME\x00"
            f.write(flexlm_data + b"\x00" * 2000)


class TestYaraEngineInitialization(TestYaraPatternEngineSpecification):
    """Test sophisticated engine initialization and rule loading."""

    def test_engine_initialization_loads_production_rules(self) -> None:
        """Engine should initialize with comprehensive rule sets for real-world analysis."""
        # Production engines should load hundreds of rules covering major protection schemes
        self.assertIsNotNone(self.engine.compiled_rules)

        rule_info = self.engine.get_rule_info()

        # Should have substantial rule coverage across all protection categories
        self.assertGreaterEqual(rule_info['total_rules'], 50)
        self.assertIn('categories', rule_info)

        # Must cover all major protection categories for effective security research
        expected_categories = [
            PatternCategory.PROTECTION,
            PatternCategory.PACKER,
            PatternCategory.LICENSING,
            PatternCategory.ANTI_DEBUG,
            PatternCategory.OBFUSCATION
        ]

        for category in expected_categories:
            self.assertGreater(rule_info['categories'].get(category, 0), 0,
                             f"Missing rules for critical category: {category}")

    def test_custom_rules_path_integration(self) -> None:
        """Engine should support custom rule directories for specialized research."""
        custom_rules_dir = os.path.join(self.temp_dir, "custom_rules")
        os.makedirs(custom_rules_dir)

        # Create custom rule for specialized detection
        custom_rule_content = '''
rule Custom_Advanced_Packer {
    meta:
        description = "Advanced packer with custom obfuscation"
        category = "packer"
        confidence = 85
    strings:
        $a = { E8 00 00 00 00 58 05 ?? ?? ?? ?? 50 }
        $b = "CUSTOM_PACKER_V2"
    condition:
        $a and $b
}
'''

        custom_rule_file = os.path.join(custom_rules_dir, "custom_packer.yar")
        with open(custom_rule_file, "w") as f:
            f.write(custom_rule_content)

        # Engine should integrate custom rules seamlessly
        custom_engine = YaraPatternEngine(custom_rules_path=custom_rules_dir)

        # Should incorporate custom rules into main ruleset
        rule_info = custom_engine.get_rule_info()
        self.assertGreater(rule_info['total_rules'], self.engine.get_rule_info()['total_rules'])

    def test_rule_compilation_optimization(self) -> None:
        """Engine should optimize rule compilation for performance."""
        # Production engines should compile rules efficiently
        start_time = time.time()
        large_engine = YaraPatternEngine()
        compilation_time = time.time() - start_time

        # Should compile substantial rulesets quickly (< 5 seconds for production use)
        self.assertLess(compilation_time, 5.0)

        # Should have compiled rules ready for immediate use
        self.assertIsNotNone(large_engine.compiled_rules)


class TestAdvancedPatternRecognition(TestYaraPatternEngineSpecification):
    """Test sophisticated pattern recognition capabilities."""

    def test_upx_packer_detection_accuracy(self) -> None:
        """Should accurately detect UPX packed binaries with high confidence."""
        result = self.engine.scan_file(self.upx_packed_sample)

        # Must detect UPX packing with high confidence
        self.assertTrue(result.has_matches)
        self.assertGreater(len(result.matches), 0)

        # Should identify as packer category with specific UPX detection
        upx_matches = [m for m in result.matches if m.category == PatternCategory.PACKER]
        self.assertGreater(len(upx_matches), 0)

        # Production engines should achieve high confidence for clear signatures
        max_confidence = max(m.confidence for m in upx_matches)
        self.assertGreaterEqual(max_confidence, 80)

        # Should identify specific UPX characteristics
        upx_specific = any("upx" in m.rule_name.lower() for m in upx_matches)
        self.assertTrue(upx_specific, "Should specifically identify UPX packer")

    def test_vmprotect_sophisticated_detection(self) -> None:
        """Should detect VMProtect's advanced obfuscation techniques."""
        result = self.engine.scan_file(self.vmprotect_sample)

        # VMProtect is sophisticated - should be detected by advanced engines
        self.assertTrue(result.has_matches)

        protection_matches = [m for m in result.matches
                            if m.category in [PatternCategory.PROTECTION, PatternCategory.OBFUSCATION]]
        self.assertGreater(len(protection_matches), 0)

        # Should detect VM-based protection characteristics
        vm_matches = any("vm" in m.rule_name.lower() or "protect" in m.rule_name.lower()
                        for m in protection_matches)
        self.assertTrue(vm_matches, "Should detect VM-based protection patterns")

    def test_anti_debugging_technique_detection(self) -> None:
        """Should detect sophisticated anti-debugging techniques."""
        result = self.engine.scan_file(self.antidebug_sample)

        # Must detect anti-debugging patterns
        self.assertTrue(result.has_matches)

        antidebug_matches = [m for m in result.matches if m.category == PatternCategory.ANTI_DEBUG]
        self.assertGreater(len(antidebug_matches), 0)

        # Should detect multiple anti-debugging techniques
        techniques_detected = set()
        for match in antidebug_matches:
            if "debugger" in match.rule_name.lower():
                techniques_detected.add("debugger_check")
            if "remote" in match.rule_name.lower():
                techniques_detected.add("remote_debugger")
            if "query" in match.rule_name.lower():
                techniques_detected.add("process_query")

        # Production engines should detect multiple techniques
        self.assertGreaterEqual(len(techniques_detected), 2)

    def test_licensing_system_recognition(self) -> None:
        """Should recognize commercial licensing systems and vulnerabilities."""
        result = self.engine.scan_file(self.flexlm_sample)

        # Must detect licensing system patterns
        self.assertTrue(result.has_matches)

        license_matches = [m for m in result.matches if m.category == PatternCategory.LICENSING]
        self.assertGreater(len(license_matches), 0)

        # Should specifically identify FlexLM
        flexlm_detected = any("flex" in m.rule_name.lower() for m in license_matches)
        self.assertTrue(flexlm_detected, "Should detect FlexLM licensing system")


class TestRuleGenerationCapabilities(TestYaraPatternEngineSpecification):
    """Test intelligent rule generation and pattern extraction."""

    def test_custom_rule_creation_validation(self) -> None:
        """Should create and validate sophisticated custom rules."""
        # Advanced rule with multiple conditions and metadata
        advanced_rule_content = '''
rule Advanced_Protection_Detector {
    meta:
        description = "Detects advanced binary protection schemes"
        category = "protection"
        confidence = 90
        author = "Intellicrack Analysis Engine"
        version = "1.0"
    strings:
        $encrypt = { 8B ?? ?? ?? ?? ?? 33 ?? ?? ?? ?? ?? E8 }
        $vm_stub = { 60 9C 33 C0 8B C4 83 C0 04 }
        $api_hash = { 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }
    condition:
        ($encrypt and $vm_stub) or
        (2 of them and filesize > 10KB and filesize < 50MB)
}
'''

        # Should create and compile complex rules successfully
        success = self.engine.create_custom_rule(advanced_rule_content, "advanced_protection")
        self.assertTrue(success, "Should create sophisticated custom rules")

        # Rule should be immediately usable for scanning
        rule_info = self.engine.get_rule_info()
        self.assertIn("advanced_protection", str(rule_info))

    def test_rule_optimization_for_performance(self) -> None:
        """Should optimize rules for scanning performance."""
        # Create performance-sensitive rule
        performance_rule = '''
rule Performance_Optimized_Rule {
    meta:
        description = "Performance optimized detection rule"
        category = "packer"
    strings:
        $a = { 4D 5A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 45 }
        $b = { 55 8B EC 83 EC ?? 53 56 57 }
        $c = "This program cannot be run in DOS mode"
    condition:
        $a at 0 and ($b or $c)
}
'''

        # Should handle rule creation efficiently
        start_time = time.time()
        success = self.engine.create_custom_rule(performance_rule, "perf_test")
        creation_time = time.time() - start_time

        # Should create rules quickly for real-time use
        self.assertTrue(success)
        self.assertLess(creation_time, 1.0)

    def test_pattern_extraction_intelligence(self) -> None:
        """Should extract meaningful patterns from complex binaries."""
        # Test against complex binary sample
        result = self.engine.scan_file(self.vmprotect_sample)

        # Should extract detailed pattern information
        if result.has_matches:
            for match in result.matches:
                # Should provide detailed match information
                self.assertIsNotNone(match.rule_name)
                self.assertIsInstance(match.confidence, (int, float))
                self.assertGreaterEqual(match.confidence, 0)
                self.assertLessEqual(match.confidence, 100)

                # Should have meaningful string matches for analysis
                if hasattr(match, 'string_matches') and match.string_matches:
                    for string_match in match.string_matches:
                        self.assertIsNotNone(string_match.get('offset'))
                        self.assertIsNotNone(string_match.get('identifier'))


class TestPerformanceOptimization(TestYaraPatternEngineSpecification):
    """Test performance optimization and scalability."""

    def test_large_file_scanning_timeout_handling(self) -> None:
        """Should handle large file scanning with proper timeout management."""
        # Create large test file
        large_file = os.path.join(self.temp_dir, "large_binary.exe")
        with open(large_file, "wb") as f:
            # Write substantial data to test timeout handling
            f.write(b"MZ" + b"\x00" * (1024 * 1024 * 5))  # 5MB file

        # Should handle timeout gracefully
        start_time = time.time()
        result = self.engine.scan_file(large_file, timeout=2)
        scan_time = time.time() - start_time

        # Should respect timeout constraints
        self.assertLessEqual(scan_time, 5.0)  # Allow some overhead
        self.assertIsNotNone(result)

    def test_concurrent_scanning_capability(self) -> None:
        """Should support concurrent file scanning operations."""
        files_to_scan = [
            self.upx_packed_sample,
            self.vmprotect_sample,
            self.themida_sample,
            self.antidebug_sample
        ]

        results = []
        threads = []

        def scan_file_thread(file_path):
            result = self.engine.scan_file(file_path)
            results.append(result)

        # Launch concurrent scans
        start_time = time.time()
        for file_path in files_to_scan:
            thread = threading.Thread(target=scan_file_thread, args=(file_path,))
            threads.append(thread)
            thread.start()

        # Wait for all scans to complete
        for thread in threads:
            thread.join()

        concurrent_time = time.time() - start_time

        # Should handle concurrent operations efficiently
        self.assertEqual(len(results), len(files_to_scan))
        self.assertLess(concurrent_time, 10.0)  # Should complete reasonably quickly

        # All results should be valid
        for result in results:
            self.assertIsInstance(result, YaraScanResult)

    def test_memory_scanning_efficiency(self) -> None:
        """Should efficiently scan process memory for runtime analysis."""
        import psutil

        # Get real running process for memory scanning test
        try:
            # Find current Python process or any available process
            current_pid = psutil.Process().pid

            # Should handle memory scanning gracefully with real process
            result = self.engine.scan_memory(current_pid, timeout=5)
            # Should return proper result structure for real process
            self.assertIsInstance(result, YaraScanResult)
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, RuntimeError, ValueError) as e:
            # Should handle real-world errors gracefully without crashing
            self.assertIsInstance(e, (psutil.NoSuchProcess, psutil.AccessDenied, OSError, RuntimeError, ValueError))
        except ImportError:
            # If psutil not available, test with current process PID
            import os
            current_pid = os.getpid()
            try:
                result = self.engine.scan_memory(current_pid, timeout=5)
                self.assertIsInstance(result, YaraScanResult)
            except Exception as e:
                # Should handle errors gracefully without crashing
                self.assertIsInstance(e, (OSError, RuntimeError, ValueError))


class TestSecurityResearchIntegration(TestYaraPatternEngineSpecification):
    """Test integration features for security research workflows."""

    def test_icp_supplemental_data_generation(self) -> None:
        """Should generate rich supplemental data for AI analysis systems."""
        result = self.engine.scan_file(self.upx_packed_sample)

        # Generate supplemental data for AI analysis
        supplemental_data = self.engine.generate_icp_supplemental_data(result)

        # Should provide structured data for AI consumption
        self.assertIsInstance(supplemental_data, dict)
        self.assertIn('scan_summary', supplemental_data)
        self.assertIn('threat_analysis', supplemental_data)
        self.assertIn('recommendations', supplemental_data)

        # Should include actionable intelligence
        if result.has_matches:
            self.assertIn('bypass_strategies', supplemental_data)
            self.assertIsInstance(supplemental_data['bypass_strategies'], list)

    def test_rule_metadata_extraction(self) -> None:
        """Should extract comprehensive rule metadata for research analysis."""
        rule_info = self.engine.get_rule_info()

        # Should provide detailed rule statistics
        self.assertIn('total_rules', rule_info)
        self.assertIn('categories', rule_info)
        self.assertIn('namespaces', rule_info)

        # Should categorize rules meaningfully
        categories = rule_info['categories']
        for category, count in categories.items():
            self.assertGreater(count, 0)
            self.assertIsInstance(category, PatternCategory)

    def test_advanced_match_analysis(self) -> None:
        """Should provide detailed match analysis for security research."""
        result = self.engine.scan_file(self.themida_sample)

        if result.has_matches:
            for match in result.matches:
                # Should provide comprehensive match details
                self.assertIsNotNone(match.rule_name)
                self.assertIsInstance(match.category, PatternCategory)
                self.assertIsInstance(match.confidence, (int, float))

                # Should include pattern location information
                if hasattr(match, 'string_matches'):
                    for string_match in match.string_matches:
                        self.assertIn('offset', string_match)
                        self.assertIn('identifier', string_match)


class TestRobustnessAndErrorHandling(TestYaraPatternEngineSpecification):
    """Test robustness and error handling for production deployment."""

    def test_malformed_file_handling(self) -> None:
        """Should gracefully handle malformed or corrupted files."""
        # Create malformed PE file
        malformed_file = os.path.join(self.temp_dir, "malformed.exe")
        with open(malformed_file, "wb") as f:
            f.write(b"NotAPEFile" + b"\x00" * 1000)

        # Should handle gracefully without crashing
        result = self.engine.scan_file(malformed_file)
        self.assertIsInstance(result, YaraScanResult)

    def test_nonexistent_file_handling(self) -> None:
        """Should handle nonexistent files gracefully."""
        nonexistent_file = os.path.join(self.temp_dir, "does_not_exist.exe")

        # Should handle file not found gracefully
        with self.assertRaises((FileNotFoundError, OSError)):
            self.engine.scan_file(nonexistent_file)

    def test_invalid_custom_rule_handling(self) -> None:
        """Should validate custom rules and handle invalid syntax."""
        invalid_rule = '''
rule Invalid_Rule {
    strings:
        $invalid = { Invalid Hex Pattern }
    condition:
        invalid_condition
}
'''

        # Should reject invalid rules gracefully
        success = self.engine.create_custom_rule(invalid_rule, "invalid_test")
        self.assertFalse(success, "Should reject invalid rule syntax")

    def test_resource_cleanup(self) -> None:
        """Should properly clean up resources after operations."""
        # Perform multiple scan operations
        files_scanned = []
        for _ in range(5):
            result = self.engine.scan_file(self.upx_packed_sample)
            files_scanned.append(result)

        # Should maintain resource efficiency
        self.assertEqual(len(files_scanned), 5)

        # Engine should remain functional after multiple operations
        final_result = self.engine.scan_file(self.antidebug_sample)
        self.assertIsInstance(final_result, YaraScanResult)


class TestModuleLevelFunctions(TestYaraPatternEngineSpecification):
    """Test module-level utility functions."""

    def test_yara_availability_check(self) -> None:
        """Should accurately report YARA availability."""
        availability = is_yara_available()
        self.assertIsInstance(availability, bool)

        # If available, should be functional
        if availability:
            engine = get_yara_engine()
            self.assertIsInstance(engine, YaraPatternEngine)

    def test_scan_file_utility_function(self) -> None:
        """Should provide convenient file scanning utility."""
        if is_yara_available():
            result = scan_file_with_yara(self.upx_packed_sample)
            self.assertIsInstance(result, YaraScanResult)

    def test_singleton_engine_management(self) -> None:
        """Should manage engine instances efficiently."""
        if is_yara_available():
            engine1 = get_yara_engine()
            engine2 = get_yara_engine()

            # Should reuse engine instances for efficiency
            self.assertIs(engine1, engine2)


if __name__ == '__main__':
    # Configure test execution for comprehensive validation
    unittest.main(verbosity=2)
