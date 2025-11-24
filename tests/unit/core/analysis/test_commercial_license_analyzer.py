"""
Unit tests for CommercialLicenseAnalyzer with REAL license protection analysis.
Tests actual implementation methods with real binary samples and license systems.
NO MOCKS - ALL TESTS USE REAL BINARIES AND VALIDATE PRODUCTION FUNCTIONALITY.

This module tests defensive security research capabilities for helping developers
identify vulnerabilities in their own licensing protection mechanisms.
"""

import pytest
import tempfile
import struct
from pathlib import Path

from intellicrack.core.analysis.commercial_license_analyzer import CommercialLicenseAnalyzer
from tests.base_test import IntellicrackTestBase


class TestCommercialLicenseAnalyzer(IntellicrackTestBase):
    """Test commercial license analyzer with real binaries and production-ready validation."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test environment with real test binaries and license samples."""
        self.analyzer = CommercialLicenseAnalyzer()

        # Create test fixtures directory
        self.test_fixtures_dir = Path("tests/fixtures/license_protection")
        self.test_fixtures_dir.mkdir(parents=True, exist_ok=True)

        # Create real binary test samples with license protection signatures
        self.flexlm_binary = self._create_flexlm_test_binary()
        self.hasp_binary = self._create_hasp_test_binary()
        self.codemeter_binary = self._create_codemeter_test_binary()
        self.clean_binary = self._create_clean_test_binary()

        # Path for non-existent binary testing
        self.nonexistent_binary = "non_existent_file.exe"

    def _create_flexlm_test_binary(self) -> Path:
        """Create a test binary with FlexLM protection signatures."""
        binary_path = self.test_fixtures_dir / "flexlm_protected.exe"

        # Create binary with FlexLM indicators
        flexlm_content = (
            b"PE\x00\x00" + b"\x00" * 100 +  # PE header
            b"FLEXlm" + b"\x00" * 50 +  # FlexLM signature
            b"lc_checkout" + b"\x00" * 30 +  # API call
            b"license.dat" + b"\x00" * 40 +  # License file reference
            b"LM_LICENSE_FILE" + b"\x00" * 200 +  # Environment variable
            b"lmgrd" + b"\x00" * 100  # License manager daemon
        )

        with open(binary_path, "wb") as f:
            f.write(flexlm_content)

        return binary_path

    def _create_hasp_test_binary(self) -> Path:
        """Create a test binary with HASP protection signatures."""
        binary_path = self.test_fixtures_dir / "hasp_protected.exe"

        # Create binary with HASP indicators
        hasp_content = (
            b"PE\x00\x00" + b"\x00" * 100 +  # PE header
            b"hasp_login" + b"\x00" * 50 +  # HASP API
            b"hasp_encrypt" + b"\x00" * 30 +  # Encryption API
            b"HASP" + b"\x00" * 40 +  # HASP signature
            b"Sentinel" + b"\x00" * 60 +  # Sentinel reference
            b"hasplms.exe" + b"\x00" * 100 +  # License manager
            b"hasp_windows_x64" + b"\x00" * 80  # DLL reference
        )

        with open(binary_path, "wb") as f:
            f.write(hasp_content)

        return binary_path

    def _create_codemeter_test_binary(self) -> Path:
        """Create a test binary with CodeMeter protection signatures."""
        binary_path = self.test_fixtures_dir / "codemeter_protected.exe"

        # Create binary with CodeMeter indicators
        codemeter_content = (
            b"PE\x00\x00" + b"\x00" * 100 +  # PE header
            b"CodeMeter" + b"\x00" * 50 +  # CodeMeter signature
            b"CmAccess" + b"\x00" * 30 +  # API call
            b"WIBU-SYSTEMS" + b"\x00" * 40 +  # Company signature
            b"CmContainer" + b"\x00" * 60 +  # Container reference
            b"CodeMeterRuntime" + b"\x00" * 100  # Runtime reference
        )

        with open(binary_path, "wb") as f:
            f.write(codemeter_content)

        return binary_path

    def _create_clean_test_binary(self) -> Path:
        """Create a clean test binary without license protection."""
        binary_path = self.test_fixtures_dir / "clean_binary.exe"

        # Create basic PE binary without protection signatures
        clean_content = (
            b"PE\x00\x00" + b"\x00" * 200 +  # PE header
            b"Hello World Program" + b"\x00" * 300 +  # Regular content
            b"kernel32.dll" + b"\x00" * 100 +  # Standard imports
            b"user32.dll" + b"\x00" * 200  # More standard content
        )

        with open(binary_path, "wb") as f:
            f.write(clean_content)

        return binary_path

    def test_initialization_default(self):
        """Test CommercialLicenseAnalyzer initialization without binary path."""
        analyzer = CommercialLicenseAnalyzer()

        assert analyzer.binary_path is None
        assert analyzer.detected_systems == []
        assert analyzer.license_servers == []
        assert analyzer.protection_features == {}
        assert analyzer.bypass_strategies == {}

        # Verify components are initialized
        assert analyzer.flexlm_parser is not None
        assert analyzer.dongle_emulator is not None
        assert analyzer.protocol_fingerprinter is not None

    def test_initialization_with_binary_path(self):
        """Test CommercialLicenseAnalyzer initialization with binary path."""
        test_path = str(self.flexlm_binary)
        analyzer = CommercialLicenseAnalyzer(test_path)

        assert analyzer.binary_path == test_path
        assert analyzer.detected_systems == []
        assert analyzer.license_servers == []

    def test_analyze_binary_flexlm_detection(self):
        """Test FlexLM license protection detection in real binary."""
        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary(str(self.flexlm_binary))

        # Validate FlexLM detection
        assert "FlexLM" in results["detected_systems"]
        assert "flexlm" in results["bypass_strategies"]
        assert results["confidence"] > 0.0

        # Validate bypass strategy structure
        flexlm_bypass = results["bypass_strategies"]["flexlm"]
        assert flexlm_bypass["method"] == "flexlm_emulation"
        assert "hooks" in flexlm_bypass
        assert "patches" in flexlm_bypass
        assert "emulation_script" in flexlm_bypass
        assert flexlm_bypass["server_port"] == 27000

        # Validate API hooks are present
        hooks = flexlm_bypass["hooks"]
        assert len(hooks) >= 3
        hook_apis = [hook["api"] for hook in hooks]
        assert "lc_checkout" in hook_apis
        assert "lc_init" in hook_apis

    def test_analyze_binary_hasp_detection(self):
        """Test HASP dongle protection detection in real binary."""
        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary(str(self.hasp_binary))

        # Validate HASP detection
        assert "HASP" in results["detected_systems"]
        assert "hasp" in results["bypass_strategies"]
        assert results["confidence"] > 0.0

        # Validate bypass strategy structure
        hasp_bypass = results["bypass_strategies"]["hasp"]
        assert hasp_bypass["method"] == "hasp_emulation"
        assert hasp_bypass["dongle_type"] == "HASP HL"
        assert "vendor_id" in hasp_bypass
        assert "product_id" in hasp_bypass
        assert "hooks" in hasp_bypass
        assert "virtual_device" in hasp_bypass

        # Validate virtual device configuration
        virtual_device = hasp_bypass["virtual_device"]
        assert virtual_device["type"] == "USB"
        assert "vendor_id" in virtual_device
        assert "product_id" in virtual_device

    def test_analyze_binary_codemeter_detection(self):
        """Test CodeMeter protection detection in real binary."""
        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary(str(self.codemeter_binary))

        # Validate CodeMeter detection
        assert "CodeMeter" in results["detected_systems"]
        assert "codemeter" in results["bypass_strategies"]
        assert results["confidence"] > 0.0

        # Validate bypass strategy structure
        codemeter_bypass = results["bypass_strategies"]["codemeter"]
        assert codemeter_bypass["method"] == "codemeter_emulation"
        assert codemeter_bypass["container_type"] == "CmStick"
        assert codemeter_bypass["firm_code"] == 100000
        assert codemeter_bypass["product_code"] == 1
        assert "hooks" in codemeter_bypass
        assert "patches" in codemeter_bypass

    def test_analyze_binary_clean_binary(self):
        """Test analysis of clean binary without license protection."""
        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary(str(self.clean_binary))

        # Should detect no protection systems
        assert len(results["detected_systems"]) == 0
        assert len(results["bypass_strategies"]) == 0
        assert results["confidence"] == 0.0
        assert results["license_servers"] == []

    def test_analyze_binary_nonexistent_file(self):
        """Test analysis with non-existent binary file."""
        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary(self.nonexistent_binary)

        # Should return empty results
        assert results["detected_systems"] == []
        assert results["bypass_strategies"] == {}
        assert results["confidence"] == 0.0
        assert results["license_servers"] == []

    def test_analyze_binary_invalid_path(self):
        """Test analysis with invalid binary path."""
        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary("")

        # Should handle gracefully
        assert results["detected_systems"] == []
        assert results["confidence"] == 0.0

    def test_analyze_wrapper_method(self):
        """Test analyze() wrapper method for API compatibility."""
        analyzer = CommercialLicenseAnalyzer(str(self.flexlm_binary))
        results = analyzer.analyze()

        # Should produce same results as analyze_binary()
        assert "FlexLM" in results["detected_systems"]
        assert results["confidence"] > 0.0

    def test_file_read_error_handling(self):
        """Test error handling during binary file reading with inaccessible file."""
        # Create a directory with same name as expected file to trigger read error
        error_binary = self.test_fixtures_dir / "read_error_test"
        error_binary.mkdir(exist_ok=True)  # Directory can't be read as file

        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary(str(error_binary))

        # Should handle file read errors gracefully
        assert results["detected_systems"] == []
        assert results["confidence"] == 0.0

        # Clean up
        error_binary.rmdir()

    def test_confidence_calculation_single_system(self):
        """Test confidence calculation with single detected system."""
        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary(str(self.flexlm_binary))

        # Single system should give base confidence
        expected_confidence = 0.25 + 0.15  # system + bypass strategy
        assert abs(results["confidence"] - expected_confidence) < 0.1

    def test_multiple_protection_detection(self):
        """Test detection when binary contains multiple protection systems."""
        # Create binary with multiple protection signatures
        multi_binary = self.test_fixtures_dir / "multi_protected.exe"
        multi_content = (
            b"PE\x00\x00" + b"\x00" * 100 +
            b"FLEXlm" + b"\x00" * 30 +  # FlexLM
            b"hasp_login" + b"\x00" * 30 +  # HASP
            b"CodeMeter" + b"\x00" * 30 +  # CodeMeter
            b"lc_checkout" + b"\x00" * 100
        )

        with open(multi_binary, "wb") as f:
            f.write(multi_content)

        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary(str(multi_binary))

        # Should detect multiple systems
        assert len(results["detected_systems"]) >= 2
        assert len(results["bypass_strategies"]) >= 2
        assert results["confidence"] > 0.5

    def test_bypass_strategy_hook_generation(self):
        """Test that bypass strategies contain functional hook information."""
        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary(str(self.flexlm_binary))

        flexlm_bypass = results["bypass_strategies"]["flexlm"]
        hooks = flexlm_bypass["hooks"]

        # Validate hook structure
        for hook in hooks:
            assert "api" in hook
            assert "replacement" in hook
            assert "description" in hook
            assert isinstance(hook["replacement"], bytes)
            assert len(hook["replacement"]) > 0

    def test_frida_script_generation(self):
        """Test that Frida scripts are generated for bypass strategies."""
        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary(str(self.hasp_binary))

        hasp_bypass = results["bypass_strategies"]["hasp"]

        # Validate Frida script presence and structure
        assert "frida_script" in hasp_bypass
        assert "emulation_script" in hasp_bypass
        script = hasp_bypass["frida_script"]

        assert isinstance(script, str)
        assert len(script) > 100  # Should be substantial script
        assert "Interceptor.attach" in script
        assert "hasp_login" in script

    def test_network_protocol_analysis(self):
        """Test network protocol analysis for license servers using real detection."""
        # Create binary with network license server references
        network_binary = self.test_fixtures_dir / "network_license.exe"
        network_content = (
            b"PE\x00\x00" + b"\x00" * 100 +
            b"FLEXlm" + b"\x00" * 30 +
            b"license-server.company.com" + b"\x00" * 50 +
            b"27000" + b"\x00" * 30 +  # Port reference
            b"LM_LICENSE_FILE" + b"\x00" * 100
        )

        with open(network_binary, "wb") as f:
            f.write(network_content)

        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary(str(network_binary))

        # Should detect FlexLM system and potentially server info
        assert "FlexLM" in results["detected_systems"]
        assert results["confidence"] > 0.0

        # Clean up
        network_binary.unlink()

    def test_generate_bypass_report(self):
        """Test comprehensive bypass report generation."""
        analyzer = CommercialLicenseAnalyzer(str(self.flexlm_binary))
        results = analyzer.analyze_binary()
        report = analyzer.generate_bypass_report(results)

        # Validate report structure and content
        assert isinstance(report, str)
        assert len(report) > 500  # Should be comprehensive
        assert "COMMERCIAL LICENSE PROTECTION ANALYSIS REPORT" in report
        assert "DETECTED SYSTEMS:" in report
        assert "BYPASS STRATEGIES:" in report
        assert str(self.flexlm_binary) in report
        assert "FlexLM" in report

    def test_generate_bypass_report_with_servers(self):
        """Test bypass report generation with license server information using real detection."""
        # Create HASP binary with network server references
        hasp_network_binary = self.test_fixtures_dir / "hasp_network.exe"
        hasp_network_content = (
            b"PE\x00\x00" + b"\x00" * 100 +
            b"hasp_login" + b"\x00" * 30 +
            b"HASP" + b"\x00" * 30 +
            b"hasp-server.local" + b"\x00" * 50 +
            b":1947" + b"\x00" * 30 +  # Port reference
            b"Sentinel" + b"\x00" * 100
        )

        with open(hasp_network_binary, "wb") as f:
            f.write(hasp_network_content)

        analyzer = CommercialLicenseAnalyzer(str(hasp_network_binary))
        results = analyzer.analyze_binary()
        report = analyzer.generate_bypass_report(results)

        # Should include HASP detection and comprehensive report
        assert "COMMERCIAL LICENSE PROTECTION ANALYSIS REPORT" in report
        assert "HASP" in report
        assert "DETECTED SYSTEMS:" in report

        # Clean up
        hasp_network_binary.unlink()

    def test_hasp_info_response_generation(self):
        """Test HASP dongle info response generation."""
        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary(str(self.hasp_binary))

        hasp_bypass = results["bypass_strategies"]["hasp"]
        hooks = hasp_bypass["hooks"]

        # Find hasp_get_info hook
        info_hook = next((h for h in hooks if h["api"] == "hasp_get_info"), None)
        assert info_hook is not None

        # Validate response structure
        response = info_hook["replacement"]
        assert isinstance(response, bytes)
        assert len(response) >= 32  # HASP info structure size

    def test_codemeter_license_info_generation(self):
        """Test CodeMeter license info response generation."""
        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary(str(self.codemeter_binary))

        codemeter_bypass = results["bypass_strategies"]["codemeter"]
        hooks = codemeter_bypass["hooks"]

        # Find CmGetLicenseInfo hook
        info_hook = next((h for h in hooks if h["api"] == "CmGetLicenseInfo"), None)
        assert info_hook is not None

        # Validate license info structure
        response = info_hook["replacement"]
        assert isinstance(response, bytes)
        assert len(response) >= 24  # CodeMeter license structure size

    def test_confidence_calculation_maximum(self):
        """Test confidence calculation doesn't exceed 1.0."""
        # Create a binary with many protection indicators
        max_binary = self.test_fixtures_dir / "max_protection.exe"
        max_content = (
            b"PE\x00\x00" + b"\x00" * 100 +
            # Multiple FlexLM indicators
            b"FLEXlm" + b"lmgrd" + b"lc_checkout" + b"license.dat" + b"\x00" * 50 +
            # Multiple HASP indicators
            b"hasp_login" + b"hasp_encrypt" + b"HASP" + b"Sentinel" + b"\x00" * 50 +
            # Multiple CodeMeter indicators
            b"CodeMeter" + b"CmAccess" + b"WIBU-SYSTEMS" + b"CmContainer" + b"\x00" * 100
        )

        with open(max_binary, "wb") as f:
            f.write(max_content)

        # Test with real network analysis capability
        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary(str(max_binary))

        # Confidence should not exceed 1.0 even with multiple systems
        assert results["confidence"] <= 1.0
        assert results["confidence"] > 0.8  # Should be high with multiple systems

    def test_binary_path_update_during_analysis(self):
        """Test binary path update when providing different path to analyze_binary."""
        analyzer = CommercialLicenseAnalyzer(str(self.clean_binary))

        # Analyze different binary
        results = analyzer.analyze_binary(str(self.flexlm_binary))

        # Binary path should be updated
        assert analyzer.binary_path == str(self.flexlm_binary)
        assert "FlexLM" in results["detected_systems"]

    def test_error_handling_corrupted_binary(self):
        """Test error handling with corrupted or invalid binary data."""
        corrupted_binary = self.test_fixtures_dir / "corrupted.exe"

        # Create binary with invalid/corrupted data
        with open(corrupted_binary, "wb") as f:
            f.write(b"\xFF" * 1000)  # Invalid binary data

        analyzer = CommercialLicenseAnalyzer()
        results = analyzer.analyze_binary(str(corrupted_binary))

        # Should handle gracefully without crashing
        assert isinstance(results, dict)
        assert "detected_systems" in results
        assert "confidence" in results

    def test_detection_logging_for_flexlm(self, caplog):
        """Test that FlexLM detection status is properly logged."""
        import logging
        caplog.set_level(logging.DEBUG)

        analyzer = CommercialLicenseAnalyzer(str(self.flexlm_binary))
        results = analyzer.analyze()

        # Verify FlexLM was detected and logged
        assert "FlexLM" in results["detected_systems"]
        log_messages = [record.message.lower() for record in caplog.records]
        assert any("flexlm" in msg and "detected" in msg for msg in log_messages)

    def test_detection_logging_for_hasp(self, caplog):
        """Test that HASP detection status is properly logged."""
        import logging
        caplog.set_level(logging.DEBUG)

        analyzer = CommercialLicenseAnalyzer(str(self.hasp_binary))
        results = analyzer.analyze()

        # Verify HASP was detected and logged
        assert "HASP" in results["detected_systems"]
        log_messages = [record.message.lower() for record in caplog.records]
        assert any("hasp" in msg and "detected" in msg for msg in log_messages)

    def test_detection_logging_for_codemeter(self, caplog):
        """Test that CodeMeter detection status is properly logged."""
        import logging
        caplog.set_level(logging.DEBUG)

        analyzer = CommercialLicenseAnalyzer(str(self.codemeter_binary))
        results = analyzer.analyze()

        # Verify CodeMeter was detected and logged
        assert "CodeMeter" in results["detected_systems"]
        log_messages = [record.message.lower() for record in caplog.records]
        assert any("codemeter" in msg and "detected" in msg for msg in log_messages)

    def test_multiple_protections_all_logged(self, caplog):
        """Test that multiple protection systems are all logged."""
        import logging
        caplog.set_level(logging.DEBUG)

        # Create binary with multiple protection indicators
        multi_protected = self.test_fixtures_dir / "multi_protected.exe"
        content = b"PE\x00\x00" + b"\x00" * 100
        content += b"FLEXlm" + b"\x00" * 50
        content += b"haspvlib" + b"\x00" * 50
        content += b"CodeMeter" + b"\x00" * 100
        multi_protected.write_bytes(content)

        analyzer = CommercialLicenseAnalyzer(str(multi_protected))
        results = analyzer.analyze()

        # All detections should be logged
        log_messages = [record.message.lower() for record in caplog.records]
        assert any("flexlm" in msg and "detected" in msg for msg in log_messages)
        assert any("hasp" in msg and "detected" in msg for msg in log_messages)
        assert any("codemeter" in msg and "detected" in msg for msg in log_messages)

        multi_protected.unlink()

    def test_corrupted_binary_handled_gracefully(self):
        """Test that corrupted binaries are handled without crashing."""
        corrupted = self.test_fixtures_dir / "corrupted.exe"
        corrupted.write_bytes(b"\xff\xfe\xfd" * 100)

        analyzer = CommercialLicenseAnalyzer(str(corrupted))
        results = analyzer.analyze()

        # Should not crash, should return valid structure
        assert "detected_systems" in results
        assert isinstance(results["detected_systems"], list)

        corrupted.unlink()

    def test_no_false_positives_on_clean_binary(self):
        """Test that clean binaries don't trigger false positive detections."""
        analyzer = CommercialLicenseAnalyzer(str(self.clean_binary))
        results = analyzer.analyze()

        # Must not detect any protection systems
        assert len(results["detected_systems"]) == 0, \
            f"False positive detection on clean binary: {results['detected_systems']}"

    def teardown_method(self):
        """Clean up test fixtures after each test."""
        # Remove test files
        for binary_file in [self.flexlm_binary, self.hasp_binary, self.codemeter_binary, self.clean_binary]:
            if binary_file.exists():
                binary_file.unlink()

        # Clean up any additional test files
        if self.test_fixtures_dir.exists():
            for test_file in self.test_fixtures_dir.glob("*.exe"):
                if test_file.exists():
                    test_file.unlink()
