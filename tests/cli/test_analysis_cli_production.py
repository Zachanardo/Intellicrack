"""Production tests for analysis_cli module.

Tests comprehensive binary analysis CLI functionality with real binaries,
validating file analysis, report generation, and batch processing capabilities.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from intellicrack.cli.analysis_cli import AnalysisCLI, main


@pytest.fixture
def temp_binary(tmp_path: Path) -> Path:
    """Create temporary test binary with known content."""
    binary_path = tmp_path / "test_binary.exe"
    content = b"MZ\x90\x00" + b"A" * 1000 + b"license_key_check" + b"B" * 500
    binary_path.write_bytes(content)
    return binary_path


@pytest.fixture
def temp_dir_with_binaries(tmp_path: Path) -> Path:
    """Create temporary directory with multiple test binaries."""
    test_dir = tmp_path / "test_binaries"
    test_dir.mkdir()

    for i in range(3):
        binary_path = test_dir / f"test_{i}.exe"
        content = b"MZ\x90\x00" + bytes([i % 256]) * 100 + b"test_string_" + str(i).encode()
        binary_path.write_bytes(content)

    (test_dir / "test.dll").write_bytes(b"MZ\x90\x00" + b"DLL_content" * 50)
    (test_dir / "readme.txt").write_text("This is not a binary")

    return test_dir


@pytest.fixture
def cli_instance() -> AnalysisCLI:
    """Create AnalysisCLI instance."""
    return AnalysisCLI()


class TestAnalysisCLIInitialization:
    """Test AnalysisCLI initialization and configuration."""

    def test_cli_initializes_with_components(self, cli_instance: AnalysisCLI) -> None:
        """AnalysisCLI initializes with all required components."""
        assert cli_instance.binary_analyzer is not None
        assert cli_instance.protection_analyzer is not None
        assert cli_instance.vulnerability_scanner is not None
        assert cli_instance.report_generator is not None
        assert cli_instance.logger is not None

    def test_cli_creates_log_directory(self, cli_instance: AnalysisCLI) -> None:
        """AnalysisCLI creates logs directory on initialization."""
        log_dir = Path("logs")
        assert log_dir.exists()
        assert log_dir.is_dir()


class TestBinaryAnalysis:
    """Test binary analysis functionality."""

    def test_analyze_binary_with_real_file(self, cli_instance: AnalysisCLI, temp_binary: Path) -> None:
        """Analyze binary returns complete results structure."""
        options = {
            "binary_analysis": True,
            "protection_analysis": True,
            "vulnerability_scan": True,
            "pe_analysis": True,
            "extract_strings": True,
        }

        results = cli_instance.analyze_binary(str(temp_binary), options)

        assert results is not None
        assert "timestamp" in results
        assert "target_file" in results
        assert "file_hash" in results
        assert "file_size" in results
        assert "analysis_type" in results
        assert "findings" in results
        assert "metadata" in results
        assert "vulnerabilities" in results
        assert "protections" in results
        assert "recommendations" in results

        assert results["target_file"] == str(temp_binary)
        assert results["file_size"] == temp_binary.stat().st_size
        assert results["analysis_type"] == "Comprehensive"

    def test_analyze_binary_calculates_correct_hash(self, cli_instance: AnalysisCLI, temp_binary: Path) -> None:
        """Analyze binary calculates correct SHA256 hash."""
        options = {"binary_analysis": True}
        results = cli_instance.analyze_binary(str(temp_binary), options)

        expected_hash = hashlib.sha256(temp_binary.read_bytes()).hexdigest()
        assert results["file_hash"] == expected_hash

    def test_analyze_binary_detects_file_type(self, cli_instance: AnalysisCLI, temp_binary: Path) -> None:
        """Analyze binary detects file type correctly."""
        options = {"binary_analysis": True}
        results = cli_instance.analyze_binary(str(temp_binary), options)

        assert "metadata" in results
        assert "file_type" in results["metadata"]
        assert results["metadata"]["file_type"] in ["PE", "Unknown", "Binary"]

    def test_analyze_binary_with_nonexistent_file_raises_error(self, cli_instance: AnalysisCLI) -> None:
        """Analyze binary raises FileNotFoundError for nonexistent file."""
        with pytest.raises(FileNotFoundError, match="File not found"):
            cli_instance.analyze_binary("nonexistent_file.exe", {})

    def test_analyze_binary_extracts_strings(self, cli_instance: AnalysisCLI, temp_binary: Path) -> None:
        """Analyze binary extracts strings from binary."""
        options = {"extract_strings": True}
        results = cli_instance.analyze_binary(str(temp_binary), options)

        assert "metadata" in results
        assert "strings_count" in results["metadata"]
        assert results["metadata"]["strings_count"] > 0

        if "findings" in results:
            if string_findings := [
                f
                for f in results["findings"]
                if f.get("type") == "interesting_strings"
            ]:
                assert "details" in string_findings[0]
                assert isinstance(string_findings[0]["details"], list)

    def test_analyze_binary_with_selective_options(self, cli_instance: AnalysisCLI, temp_binary: Path) -> None:
        """Analyze binary respects analysis option flags."""
        options = {
            "binary_analysis": False,
            "protection_analysis": False,
            "vulnerability_scan": False,
            "extract_strings": True,
        }

        results = cli_instance.analyze_binary(str(temp_binary), options)

        assert "metadata" in results
        assert "strings_count" in results["metadata"]

        assert "binary_analysis" not in results.get("metadata", {})


class TestStringExtraction:
    """Test string extraction functionality."""

    def test_extract_strings_finds_ascii_strings(self) -> None:
        """Extract strings finds ASCII strings in binary data."""
        test_file = Path("test_string_extraction.bin")
        test_file.write_bytes(b"\x00\x00Hello World\x00\x00Test String\x00\x00")

        try:
            strings = AnalysisCLI._extract_strings(str(test_file), min_length=4)

            assert "Hello World" in strings
            assert "Test String" in strings
            assert len(strings) >= 2
        finally:
            test_file.unlink()

    def test_extract_strings_respects_minimum_length(self) -> None:
        """Extract strings respects minimum length parameter."""
        test_file = Path("test_minlen.bin")
        test_file.write_bytes(b"AB\x00ABCD\x00ABCDEFGH\x00")

        try:
            strings_min4 = AnalysisCLI._extract_strings(str(test_file), min_length=4)
            strings_min8 = AnalysisCLI._extract_strings(str(test_file), min_length=8)

            assert "ABCD" in strings_min4
            assert "ABCDEFGH" in strings_min4
            assert "ABCDEFGH" in strings_min8
            assert "ABCD" not in strings_min8
        finally:
            test_file.unlink()

    def test_find_interesting_strings_identifies_license_keywords(self) -> None:
        """Find interesting strings identifies license-related keywords."""
        test_strings = [
            "normal_string",
            "check_license_validity",
            "serial_number_validation",
            "crack_prevention_check",
            "http://license.server.com",
            "api_key_verification",
        ]

        interesting = AnalysisCLI._find_interesting_strings(test_strings)

        assert "check_license_validity" in interesting
        assert "serial_number_validation" in interesting
        assert "crack_prevention_check" in interesting
        assert "http://license.server.com" in interesting
        assert "api_key_verification" in interesting
        assert "normal_string" not in interesting


class TestSuspiciousAPIDetection:
    """Test suspicious API call detection."""

    def test_check_suspicious_apis_detects_protection_apis(self) -> None:
        """Check suspicious APIs identifies protection-related API calls."""
        imports = {
            "kernel32.dll": ["VirtualProtect", "VirtualAlloc", "LoadLibrary"],
            "user32.dll": ["SetWindowsHookEx", "GetAsyncKeyState"],
            "advapi32.dll": ["RegSetValueEx", "CryptEncrypt"],
        }

        suspicious = AnalysisCLI._check_suspicious_apis(imports)

        assert "VirtualProtect" in suspicious
        assert "VirtualAlloc" in suspicious
        assert "SetWindowsHookEx" in suspicious
        assert "GetAsyncKeyState" in suspicious
        assert "RegSetValueEx" in suspicious
        assert "CryptEncrypt" in suspicious
        assert "LoadLibrary" not in suspicious

    def test_check_suspicious_apis_detects_network_apis(self) -> None:
        """Check suspicious APIs identifies network-related calls."""
        imports = {
            "wininet.dll": ["InternetOpen", "URLDownloadToFile"],
            "ws2_32.dll": ["connect", "send", "recv"],
        }

        suspicious = AnalysisCLI._check_suspicious_apis(imports)

        assert "InternetOpen" in suspicious
        assert "URLDownloadToFile" in suspicious


class TestReportGeneration:
    """Test report generation functionality."""

    def test_generate_report_creates_json_report(self, cli_instance: AnalysisCLI, temp_binary: Path, tmp_path: Path) -> None:
        """Generate report creates valid JSON report file."""
        results = cli_instance.analyze_binary(str(temp_binary), {"binary_analysis": True})
        output_file = tmp_path / "report.json"

        report_path = cli_instance.generate_report(results, "json", str(output_file))

        assert Path(report_path).exists()

        with open(report_path) as f:
            report_data = json.load(f)

        assert report_data is not None
        assert isinstance(report_data, dict)

    def test_generate_report_creates_html_report(self, cli_instance: AnalysisCLI, temp_binary: Path, tmp_path: Path) -> None:
        """Generate report creates HTML report file."""
        results = cli_instance.analyze_binary(str(temp_binary), {"binary_analysis": True})
        output_file = tmp_path / "report.html"

        report_path = cli_instance.generate_report(results, "html", str(output_file))

        assert Path(report_path).exists()
        content = Path(report_path).read_text()
        assert len(content) > 0
        assert "<html" in content.lower() or "<!DOCTYPE" in content


class TestBatchAnalysis:
    """Test batch analysis functionality."""

    def test_run_batch_analysis_processes_multiple_files(
        self, cli_instance: AnalysisCLI, temp_dir_with_binaries: Path
    ) -> None:
        """Batch analysis processes multiple binary files."""
        file_list = [
            str(temp_dir_with_binaries / "test_0.exe"),
            str(temp_dir_with_binaries / "test_1.exe"),
            str(temp_dir_with_binaries / "test_2.exe"),
        ]

        options = {"binary_analysis": True, "extract_strings": True}
        results = cli_instance.run_batch_analysis(file_list, options)

        assert len(results) == 3

        for result in results:
            assert "target_file" in result
            assert "timestamp" in result
            assert result["target_file"] in file_list

    def test_run_batch_analysis_handles_errors_gracefully(
        self, cli_instance: AnalysisCLI, temp_dir_with_binaries: Path
    ) -> None:
        """Batch analysis handles errors without stopping processing."""
        file_list = [
            str(temp_dir_with_binaries / "test_0.exe"),
            "nonexistent_file.exe",
            str(temp_dir_with_binaries / "test_1.exe"),
        ]

        options = {"binary_analysis": True}
        results = cli_instance.run_batch_analysis(file_list, options)

        assert len(results) == 3

        error_results = [r for r in results if "error" in r]
        assert len(error_results) == 1
        assert error_results[0]["target_file"] == "nonexistent_file.exe"

        success_results = [r for r in results if "error" not in r]
        assert len(success_results) == 2


class TestHashCalculation:
    """Test file hash calculation."""

    def test_calculate_hash_computes_correct_sha256(self, temp_binary: Path) -> None:
        """Calculate hash computes correct SHA256 hash."""
        expected_hash = hashlib.sha256(temp_binary.read_bytes()).hexdigest()

        calculated_hash = AnalysisCLI._calculate_hash(str(temp_binary))

        assert calculated_hash == expected_hash
        assert len(calculated_hash) == 64

    def test_calculate_hash_handles_large_files(self, tmp_path: Path) -> None:
        """Calculate hash handles large files efficiently."""
        large_file = tmp_path / "large_file.bin"

        with open(large_file, "wb") as f:
            for _ in range(1000):
                f.write(b"A" * 4096)

        hash_value = AnalysisCLI._calculate_hash(str(large_file))

        assert len(hash_value) == 64
        assert hash_value.isalnum()


class TestCLIEdgeCases:
    """Test CLI edge cases and error handling."""

    def test_analyze_empty_file(self, cli_instance: AnalysisCLI, tmp_path: Path) -> None:
        """Analyze empty file completes without errors."""
        empty_file = tmp_path / "empty.bin"
        empty_file.touch()

        options = {"binary_analysis": True}
        results = cli_instance.analyze_binary(str(empty_file), options)

        assert results is not None
        assert results["file_size"] == 0
        assert "file_hash" in results

    def test_analyze_corrupted_pe_file(self, cli_instance: AnalysisCLI, tmp_path: Path) -> None:
        """Analyze corrupted PE file handles errors gracefully."""
        corrupted_pe = tmp_path / "corrupted.exe"
        corrupted_pe.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

        options = {
            "binary_analysis": True,
            "pe_analysis": True,
            "protection_analysis": True,
        }

        results = cli_instance.analyze_binary(str(corrupted_pe), options)

        assert results is not None
        assert "findings" in results or "metadata" in results


class TestFindingsFormatting:
    """Test findings formatting functionality."""

    def test_format_findings_from_dict(self) -> None:
        """Format findings converts dictionary data to findings list."""
        data = {
            "architecture": "x64",
            "entry_point": "0x1000",
            "sections": 5,
        }

        findings = AnalysisCLI._format_findings(data, "Test Analysis")

        assert len(findings) > 0
        for finding in findings:
            assert "type" in finding
            assert "description" in finding
            assert "impact" in finding
            assert finding["type"] == "test_analysis"

    def test_format_findings_handles_nested_data(self) -> None:
        """Format findings handles nested dictionary data."""
        data = {
            "string_value": "test",
            "int_value": 42,
            "float_value": 3.14,
            "bool_value": True,
            "nested_dict": {"key": "value"},
        }

        findings = AnalysisCLI._format_findings(data, "Complex Analysis")

        string_findings = [f for f in findings if isinstance(f.get("description"), str) and "string_value" in f["description"]]
        assert string_findings


class TestCLIIntegration:
    """Integration tests for complete CLI workflows."""

    def test_full_analysis_workflow(self, cli_instance: AnalysisCLI, temp_binary: Path, tmp_path: Path) -> None:
        """Complete analysis workflow from binary to report."""
        options = {
            "binary_analysis": True,
            "protection_analysis": True,
            "vulnerability_scan": True,
            "extract_strings": True,
        }

        results = cli_instance.analyze_binary(str(temp_binary), options)

        assert results is not None
        assert len(results["findings"]) >= 0
        assert "metadata" in results

        output_file = tmp_path / "final_report.json"
        report_path = cli_instance.generate_report(results, "json", str(output_file))

        assert Path(report_path).exists()

        with open(report_path) as f:
            report_data = json.load(f)

        assert "timestamp" in report_data or "target_file" in report_data
