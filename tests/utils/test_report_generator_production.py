"""Production tests for binary analysis report generation system.

Tests validate that report generator creates properly formatted reports for
licensing analysis results across all supported formats (JSON, HTML, PDF, XML,
CSV, Markdown, TXT).

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import csv
import datetime
import json
import os
import shutil
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.report_generator import (
    AnalysisResult,
    ComparisonReportGenerator,
    ReportGenerator,
    export_report,
    generate_comparison_report,
    generate_report,
)


@pytest.fixture
def temp_report_dir() -> Path:
    """Create temporary directory for report output."""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    if temp_dir.exists():
        shutil.rmtree(temp_dir)


@pytest.fixture
def sample_analysis_data() -> dict[str, Any]:
    """Create realistic analysis data for licensing analysis testing."""
    return {
        "timestamp": "2025-01-15T14:30:00.000000",
        "target_file": "protected_software.exe",
        "file_hash": "sha256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2",
        "file_size": 2048576,
        "analysis_type": "License Protection Analysis",
        "findings": [
            {
                "description": "VMProtect 3.5 license validation routine detected at 0x00401000",
                "type": "Protection Detection",
                "impact": "High",
            },
            {
                "description": "RSA-2048 license key verification found",
                "type": "Cryptographic Protection",
                "impact": "High",
            },
            {
                "description": "Hardware ID binding mechanism identified",
                "type": "Anti-Sharing Protection",
                "impact": "Medium",
            },
        ],
        "metadata": {
            "analyzer_version": "1.0.0",
            "analysis_duration": 45.3,
            "pe_architecture": "x64",
        },
        "vulnerabilities": [
            {
                "type": "License Check Bypass",
                "severity": "Critical",
                "description": "License validation can be bypassed by patching conditional jump at 0x00401234",
                "location": "0x00401234",
            },
            {
                "type": "Trial Reset",
                "severity": "High",
                "description": "Trial period stored in registry without integrity protection",
                "location": "HKEY_CURRENT_USER\\Software\\Vendor\\TrialData",
            },
            {
                "type": "Key Generation",
                "severity": "Critical",
                "description": "License key algorithm uses predictable seed from timestamp",
                "location": "0x00402000",
            },
        ],
        "protections": [
            {
                "type": "VMProtect",
                "status": "Active",
                "details": "Version 3.5, code virtualization applied to license validation",
            },
            {
                "type": "Anti-Debug",
                "status": "Partial",
                "details": "IsDebuggerPresent check detected, easily bypassed",
            },
            {
                "type": "Code Signing",
                "status": "Valid",
                "details": "Authenticode signature present but does not protect license logic",
            },
        ],
        "recommendations": [
            "Patch conditional jump at 0x00401234 to bypass license validation",
            "Generate keygen using reversed algorithm from 0x00402000",
            "Reset trial by deleting registry key at HKEY_CURRENT_USER\\Software\\Vendor\\TrialData",
            "Consider implementing hardware breakpoint-based debugger detection",
        ],
    }


@pytest.fixture
def minimal_analysis_data() -> dict[str, Any]:
    """Create minimal analysis data for edge case testing."""
    return {
        "target_file": "simple.exe",
        "file_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "file_size": 1024,
    }


class TestAnalysisResultDataclass:
    """Test AnalysisResult dataclass structure."""

    def test_analysis_result_creation_with_full_data(self, sample_analysis_data: dict[str, Any]) -> None:
        """AnalysisResult dataclass stores complete analysis information."""
        result = AnalysisResult(
            timestamp=sample_analysis_data["timestamp"],
            target_file=sample_analysis_data["target_file"],
            file_hash=sample_analysis_data["file_hash"],
            file_size=sample_analysis_data["file_size"],
            analysis_type=sample_analysis_data["analysis_type"],
            findings=sample_analysis_data["findings"],
            metadata=sample_analysis_data["metadata"],
            vulnerabilities=sample_analysis_data["vulnerabilities"],
            protections=sample_analysis_data["protections"],
            recommendations=sample_analysis_data["recommendations"],
        )

        assert result.target_file == "protected_software.exe"
        assert result.file_size == 2048576
        assert len(result.findings) == 3
        assert len(result.vulnerabilities) == 3
        assert len(result.protections) == 3
        assert len(result.recommendations) == 4

    def test_analysis_result_handles_empty_collections(self) -> None:
        """AnalysisResult accepts empty findings and vulnerabilities lists."""
        result = AnalysisResult(
            timestamp="2025-01-15T14:30:00",
            target_file="test.exe",
            file_hash="abc123",
            file_size=1024,
            analysis_type="Basic",
            findings=[],
            metadata={},
            vulnerabilities=[],
            protections=[],
            recommendations=[],
        )

        assert result.findings == []
        assert result.vulnerabilities == []
        assert result.protections == []
        assert result.recommendations == []


class TestReportGeneratorInitialization:
    """Test ReportGenerator initialization and setup."""

    def test_report_generator_creates_output_directory(self, temp_report_dir: Path) -> None:
        """ReportGenerator creates output directory if it doesn't exist."""
        output_dir = temp_report_dir / "new_reports"
        assert not output_dir.exists()

        generator = ReportGenerator(str(output_dir))

        assert output_dir.exists()
        assert output_dir.is_dir()
        assert generator.output_dir == output_dir

    def test_report_generator_creates_template_directory(self, temp_report_dir: Path) -> None:
        """ReportGenerator creates template directory structure."""
        generator = ReportGenerator(str(temp_report_dir))

        assert generator.template_dir.exists()
        assert generator.template_dir.is_dir()

    def test_report_generator_initializes_jinja_if_available(self, temp_report_dir: Path) -> None:
        """ReportGenerator initializes Jinja2 environment when available."""
        generator = ReportGenerator(str(temp_report_dir))

        try:
            import jinja2

            _ = jinja2.__version__
            assert generator.jinja_env is not None
        except ImportError:
            assert generator.jinja_env is None


class TestJSONReportGeneration:
    """Test JSON format report generation."""

    def test_generate_json_report_with_complete_data(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """JSON report contains all licensing analysis data."""
        generator = ReportGenerator(str(temp_report_dir))

        report_path = generator.generate_report(sample_analysis_data, format="json", output_file="test_report.json")

        assert Path(report_path).exists()
        with open(report_path, encoding="utf-8") as f:
            report_data = json.load(f)

        assert report_data["target_file"] == "protected_software.exe"
        assert report_data["file_size"] == 2048576
        assert report_data["analysis_type"] == "License Protection Analysis"
        assert len(report_data["vulnerabilities"]) == 3
        assert report_data["vulnerabilities"][0]["type"] == "License Check Bypass"

    def test_json_report_handles_unicode_characters(self, temp_report_dir: Path) -> None:
        """JSON report properly encodes unicode characters in analysis results."""
        generator = ReportGenerator(str(temp_report_dir))
        data = {
            "target_file": "test™.exe",
            "file_hash": "abc",
            "file_size": 1024,
            "findings": [{"description": "License key: ĂBĆDĔFĞ-12345"}],
            "vulnerabilities": [],
            "protections": [],
            "recommendations": [],
        }

        report_path = generator.generate_report(data, format="json")

        with open(report_path, encoding="utf-8") as f:
            report_data = json.load(f)

        assert "™" in report_data["target_file"]
        assert "ĂBĆDĔFĞ" in report_data["findings"][0]["description"]

    def test_json_report_uses_default_filename_with_timestamp(self, temp_report_dir: Path) -> None:
        """JSON report generates timestamped filename when not specified."""
        generator = ReportGenerator(str(temp_report_dir))
        data = {"target_file": "test.exe", "file_hash": "abc", "file_size": 1024}

        report_path = generator.generate_report(data, format="json")

        assert "report_" in Path(report_path).name
        assert report_path.endswith(".json")


class TestHTMLReportGeneration:
    """Test HTML format report generation."""

    def test_generate_html_report_contains_licensing_vulnerabilities(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """HTML report displays licensing vulnerabilities in formatted table."""
        generator = ReportGenerator(str(temp_report_dir))

        report_path = generator.generate_report(sample_analysis_data, format="html", output_file="test_report.html")

        assert Path(report_path).exists()
        with open(report_path, encoding="utf-8") as f:
            html_content = f.read()

        assert "<!DOCTYPE html>" in html_content
        assert "Binary Analysis Report" in html_content
        assert "protected_software.exe" in html_content
        assert "License Check Bypass" in html_content
        assert "VMProtect" in html_content
        assert "Trial Reset" in html_content

    def test_html_report_includes_css_styling(self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]) -> None:
        """HTML report includes CSS for vulnerability highlighting."""
        generator = ReportGenerator(str(temp_report_dir))

        report_path = generator.generate_report(sample_analysis_data, format="html")

        with open(report_path, encoding="utf-8") as f:
            html_content = f.read()

        assert "<style>" in html_content
        assert ".vulnerability" in html_content
        assert ".protection" in html_content
        assert "background-color" in html_content

    def test_html_report_escapes_dangerous_content(self, temp_report_dir: Path) -> None:
        """HTML report properly escapes potentially dangerous HTML in analysis data."""
        generator = ReportGenerator(str(temp_report_dir))
        data = {
            "target_file": "<script>alert('xss')</script>",
            "file_hash": "abc",
            "file_size": 1024,
            "vulnerabilities": [
                {
                    "type": "Test",
                    "severity": "High",
                    "description": "<img src=x onerror=alert('xss')>",
                    "location": "0x1000",
                }
            ],
            "protections": [],
            "findings": [],
            "recommendations": [],
        }

        report_path = generator.generate_report(data, format="html")

        with open(report_path, encoding="utf-8") as f:
            html_content = f.read()

        assert "&lt;script&gt;" in html_content or "<script>" not in html_content


class TestPDFReportGeneration:
    """Test PDF format report generation."""

    def test_generate_pdf_report_with_reportlab(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """PDF report generated successfully when reportlab available."""
        generator = ReportGenerator(str(temp_report_dir))

        report_path = generator.generate_report(sample_analysis_data, format="pdf", output_file="test_report.pdf")

        assert Path(report_path).exists()
        file_size = Path(report_path).stat().st_size
        assert file_size > 0

    def test_pdf_report_falls_back_to_html_without_reportlab(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PDF report falls back to HTML when reportlab unavailable."""
        import intellicrack.utils.report_generator

        monkeypatch.setattr(intellicrack.utils.report_generator, "HAS_REPORTLAB", False)

        generator = ReportGenerator(str(temp_report_dir))
        report_path = generator.generate_report(sample_analysis_data, format="pdf", output_file="test_report.pdf")

        assert report_path.endswith(".html")
        assert Path(report_path).exists()


class TestXMLReportGeneration:
    """Test XML format report generation."""

    def test_generate_xml_report_with_valid_structure(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """XML report has valid structure with all analysis elements."""
        generator = ReportGenerator(str(temp_report_dir))

        report_path = generator.generate_report(sample_analysis_data, format="xml", output_file="test_report.xml")

        assert Path(report_path).exists()
        tree = ET.parse(report_path)
        root = tree.getroot()

        assert root.tag == "BinaryAnalysisReport"
        assert root.find(".//TargetFile").text == "protected_software.exe"
        assert root.find(".//FileSize").text == "2048576"

    def test_xml_report_contains_all_vulnerabilities(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """XML report includes all licensing vulnerabilities with details."""
        generator = ReportGenerator(str(temp_report_dir))

        report_path = generator.generate_report(sample_analysis_data, format="xml")

        tree = ET.parse(report_path)
        root = tree.getroot()

        vulnerabilities = root.findall(".//Vulnerability")
        assert len(vulnerabilities) == 3
        assert vulnerabilities[0].find("Type").text == "License Check Bypass"
        assert vulnerabilities[0].find("Severity").text == "Critical"

    def test_xml_report_includes_protections(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """XML report lists detected protection mechanisms."""
        generator = ReportGenerator(str(temp_report_dir))

        report_path = generator.generate_report(sample_analysis_data, format="xml")

        tree = ET.parse(report_path)
        root = tree.getroot()

        protections = root.findall(".//Protection")
        assert len(protections) == 3
        vmprotect = protections[0]
        assert vmprotect.find("Type").text == "VMProtect"
        assert vmprotect.find("Status").text == "Active"


class TestCSVReportGeneration:
    """Test CSV format report generation."""

    def test_generate_csv_report_with_proper_structure(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """CSV report contains properly formatted rows and columns."""
        generator = ReportGenerator(str(temp_report_dir))

        report_path = generator.generate_report(sample_analysis_data, format="csv", output_file="test_report.csv")

        assert Path(report_path).exists()
        with open(report_path, encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert len(rows) > 0
        assert rows[0][0] == "File Information"
        assert any("protected_software.exe" in row for row in rows)

    def test_csv_report_includes_vulnerabilities_section(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """CSV report has vulnerabilities section with all findings."""
        generator = ReportGenerator(str(temp_report_dir))

        report_path = generator.generate_report(sample_analysis_data, format="csv")

        with open(report_path, encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        vuln_header_idx = next(i for i, row in enumerate(rows) if row and row[0] == "Vulnerabilities")
        assert vuln_header_idx >= 0

        vuln_data_rows = [row for row in rows[vuln_header_idx + 2 :] if row and row[0] and row[0] != ""]
        assert len(vuln_data_rows) >= 3


class TestMarkdownReportGeneration:
    """Test Markdown format report generation."""

    def test_generate_markdown_report_with_proper_formatting(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Markdown report uses proper markdown syntax for headers and tables."""
        generator = ReportGenerator(str(temp_report_dir))

        report_path = generator.generate_report(sample_analysis_data, format="markdown", output_file="test_report.md")

        assert Path(report_path).exists()
        with open(report_path, encoding="utf-8") as f:
            md_content = f.read()

        assert "# Binary Analysis Report" in md_content
        assert "## File Information" in md_content
        assert "## Vulnerabilities Found" in md_content
        assert "| Type | Severity | Description | Location |" in md_content
        assert "|------|----------|-------------|----------|" in md_content

    def test_markdown_report_contains_licensing_analysis_results(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Markdown report includes all licensing vulnerability details."""
        generator = ReportGenerator(str(temp_report_dir))

        report_path = generator.generate_report(sample_analysis_data, format="markdown")

        with open(report_path, encoding="utf-8") as f:
            md_content = f.read()

        assert "License Check Bypass" in md_content
        assert "Trial Reset" in md_content
        assert "VMProtect" in md_content
        assert "0x00401234" in md_content


class TestTextReportGeneration:
    """Test plain text report generation."""

    def test_generate_text_report_with_readable_format(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Text report has readable plain text formatting."""
        generator = ReportGenerator(str(temp_report_dir))

        report_path = generator.generate_report(sample_analysis_data, format="txt", output_file="test_report.txt")

        assert Path(report_path).exists()
        with open(report_path, encoding="utf-8") as f:
            text_content = f.read()

        assert "BINARY ANALYSIS REPORT" in text_content
        assert "=" * 50 in text_content
        assert "FILE INFORMATION" in text_content
        assert "VULNERABILITIES FOUND" in text_content

    def test_text_report_includes_all_sections(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Text report includes all analysis sections."""
        generator = ReportGenerator(str(temp_report_dir))

        report_path = generator.generate_report(sample_analysis_data, format="txt")

        with open(report_path, encoding="utf-8") as f:
            text_content = f.read()

        assert "protected_software.exe" in text_content
        assert "License Check Bypass" in text_content
        assert "VMProtect" in text_content
        assert "RECOMMENDATIONS" in text_content


class TestBatchReportGeneration:
    """Test batch report generation for multiple analyses."""

    def test_generate_batch_report_creates_multiple_files(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Batch report generation creates separate report for each analysis."""
        generator = ReportGenerator(str(temp_report_dir))

        analysis_results = [
            sample_analysis_data,
            {**sample_analysis_data, "target_file": "protected_app2.exe"},
            {**sample_analysis_data, "target_file": "protected_app3.exe"},
        ]

        archive_path = generator.generate_batch_report(analysis_results, format="json")

        assert Path(archive_path).exists()
        assert archive_path.endswith(".zip")

        with zipfile.ZipFile(archive_path) as zf:
            files = zf.namelist()
            assert len(files) == 3
            assert all("report_" in f and f.endswith(".json") for f in files)

    def test_batch_report_archive_contains_valid_reports(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Batch report archive contains valid JSON reports."""
        generator = ReportGenerator(str(temp_report_dir))

        analysis_results = [sample_analysis_data, sample_analysis_data]
        archive_path = generator.generate_batch_report(analysis_results, format="json")

        with zipfile.ZipFile(archive_path) as zf:
            for filename in zf.namelist():
                content = zf.read(filename)
                data = json.loads(content)
                assert "target_file" in data
                assert "vulnerabilities" in data


class TestReportArchiving:
    """Test report export to archive functionality."""

    def test_export_to_archive_creates_zip(self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]) -> None:
        """Export creates zip archive containing all specified reports."""
        generator = ReportGenerator(str(temp_report_dir))

        report1 = generator.generate_report(sample_analysis_data, format="json", output_file="report1.json")
        report2 = generator.generate_report(sample_analysis_data, format="xml", output_file="report2.xml")

        archive_path = generator.export_to_archive([report1, report2])

        assert Path(archive_path).exists()
        with zipfile.ZipFile(archive_path) as zf:
            files = zf.namelist()
            assert "report1.json" in files
            assert "report2.xml" in files

    def test_export_to_archive_with_custom_name(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Export uses custom archive name when provided."""
        generator = ReportGenerator(str(temp_report_dir))

        report1 = generator.generate_report(sample_analysis_data, format="json")
        archive_path = generator.export_to_archive([report1], archive_name="custom_archive.zip")

        assert "custom_archive.zip" in archive_path
        assert Path(archive_path).exists()


class TestComparisonReportGenerator:
    """Test comparison report generation between multiple binaries."""

    def test_comparison_generator_initialization(self, temp_report_dir: Path) -> None:
        """ComparisonReportGenerator creates output directory."""
        output_dir = temp_report_dir / "comparisons"
        generator = ComparisonReportGenerator(str(output_dir))

        assert output_dir.exists()
        assert generator.output_dir == output_dir

    def test_generate_comparison_analyzes_differences(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Comparison report identifies common and unique vulnerabilities."""
        generator = ComparisonReportGenerator(str(temp_report_dir))

        data2 = {
            **sample_analysis_data,
            "target_file": "app2.exe",
            "vulnerabilities": [
                sample_analysis_data["vulnerabilities"][0],
                {"type": "Unique Vuln", "severity": "Medium", "description": "Only in app2", "location": "0x5000"},
            ],
        }

        results = [sample_analysis_data, data2]
        report_path = generator.generate_comparison(results, format="html")

        assert Path(report_path).exists()
        with open(report_path, encoding="utf-8") as f:
            html_content = f.read()

        assert "Binary Comparison Report" in html_content
        assert "protected_software.exe" in html_content
        assert "app2.exe" in html_content

    def test_comparison_calculates_similarity_score(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Comparison report calculates similarity score between binaries."""
        generator = ComparisonReportGenerator(str(temp_report_dir))

        data2 = {**sample_analysis_data, "vulnerabilities": sample_analysis_data["vulnerabilities"][:2]}

        results = [sample_analysis_data, data2]
        report_path = generator.generate_comparison(results, format="json")

        with open(report_path, encoding="utf-8") as f:
            comparison_data = json.load(f)

        assert "similarity_score" in comparison_data
        assert 0 <= comparison_data["similarity_score"] <= 100

    def test_comparison_identifies_common_vulnerabilities(self, temp_report_dir: Path) -> None:
        """Comparison report finds vulnerabilities common to all binaries."""
        generator = ComparisonReportGenerator(str(temp_report_dir))

        data1 = {
            "target_file": "app1.exe",
            "file_hash": "hash1",
            "file_size": 1024,
            "vulnerabilities": [
                {"type": "Common Vuln 1", "severity": "High"},
                {"type": "Common Vuln 2", "severity": "Medium"},
                {"type": "Unique1", "severity": "Low"},
            ],
        }

        data2 = {
            "target_file": "app2.exe",
            "file_hash": "hash2",
            "file_size": 2048,
            "vulnerabilities": [
                {"type": "Common Vuln 1", "severity": "High"},
                {"type": "Common Vuln 2", "severity": "Medium"},
                {"type": "Unique2", "severity": "Low"},
            ],
        }

        report_path = generator.generate_comparison([data1, data2], format="json")

        with open(report_path, encoding="utf-8") as f:
            comparison_data = json.load(f)

        assert len(comparison_data["common_vulnerabilities"]) == 2
        assert "Common Vuln 1" in comparison_data["common_vulnerabilities"]


class TestHelperFunctions:
    """Test module-level helper functions."""

    def test_generate_report_function_creates_report(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """generate_report helper function creates report successfully."""
        report_path = generate_report(sample_analysis_data, format="json", output_dir=str(temp_report_dir))

        assert Path(report_path).exists()
        assert report_path.endswith(".json")

    def test_export_report_function_with_custom_path(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """export_report helper creates report at specified path."""
        output_path = temp_report_dir / "custom_report.html"

        report_path = export_report(sample_analysis_data, format="html", output_path=str(output_path))

        assert Path(report_path).exists()
        assert report_path == str(output_path)

    def test_generate_comparison_report_function(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """generate_comparison_report helper creates comparison report."""
        results = [sample_analysis_data, sample_analysis_data]

        report_path = generate_comparison_report(results, format="html", output_dir=str(temp_report_dir))

        assert Path(report_path).exists()
        assert "comparison_" in Path(report_path).name


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_unsupported_format_raises_error(self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]) -> None:
        """ReportGenerator raises ValueError for unsupported format."""
        generator = ReportGenerator(str(temp_report_dir))

        with pytest.raises(ValueError, match="Unsupported format"):
            generator.generate_report(sample_analysis_data, format="unsupported_format")

    def test_report_generation_with_missing_data_uses_defaults(self, temp_report_dir: Path) -> None:
        """ReportGenerator uses default values for missing data fields."""
        generator = ReportGenerator(str(temp_report_dir))
        minimal_data: dict[str, Any] = {}

        report_path = generator.generate_report(minimal_data, format="json")

        with open(report_path, encoding="utf-8") as f:
            report_data = json.load(f)

        assert report_data["target_file"] == "Unknown"
        assert report_data["file_size"] == 0
        assert report_data["analysis_type"] == "General"

    def test_export_to_archive_handles_nonexistent_files(self, temp_report_dir: Path) -> None:
        """Export to archive skips nonexistent files without error."""
        generator = ReportGenerator(str(temp_report_dir))

        archive_path = generator.export_to_archive(["/nonexistent/file1.json", "/nonexistent/file2.xml"])

        assert Path(archive_path).exists()
        with zipfile.ZipFile(archive_path) as zf:
            assert len(zf.namelist()) == 0


class TestIntegrationScenarios:
    """Test complete reporting workflows."""

    def test_complete_licensing_analysis_workflow(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Complete workflow from analysis to multi-format report generation."""
        generator = ReportGenerator(str(temp_report_dir))

        json_report = generator.generate_report(sample_analysis_data, format="json")
        html_report = generator.generate_report(sample_analysis_data, format="html")
        xml_report = generator.generate_report(sample_analysis_data, format="xml")

        assert Path(json_report).exists()
        assert Path(html_report).exists()
        assert Path(xml_report).exists()

        archive_path = generator.export_to_archive([json_report, html_report, xml_report])

        assert Path(archive_path).exists()
        with zipfile.ZipFile(archive_path) as zf:
            assert len(zf.namelist()) == 3

    def test_batch_analysis_comparison_workflow(
        self, temp_report_dir: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Workflow for analyzing multiple protected binaries and comparing results."""
        results = [
            {**sample_analysis_data, "target_file": "app1.exe"},
            {**sample_analysis_data, "target_file": "app2.exe"},
            {**sample_analysis_data, "target_file": "app3.exe"},
        ]

        batch_generator = ReportGenerator(str(temp_report_dir / "batch"))
        batch_archive = batch_generator.generate_batch_report(results, format="json")

        comparison_generator = ComparisonReportGenerator(str(temp_report_dir / "comparisons"))
        comparison_report = comparison_generator.generate_comparison(results, format="html")

        assert Path(batch_archive).exists()
        assert Path(comparison_report).exists()

        with zipfile.ZipFile(batch_archive) as zf:
            assert len(zf.namelist()) == 3
