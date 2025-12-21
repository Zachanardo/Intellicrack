"""Production tests for ReportGenerator analysis reporting.

This test suite validates ReportGenerator's ability to create comprehensive
reports from real analysis data for license bypass, protection detection,
and vulnerability research results.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.reporting.report_generator import ReportGenerator


@pytest.fixture
def real_analysis_data() -> dict[str, Any]:
    """Create realistic analysis data from actual licensing research.

    Returns:
        dict[str, Any]: Analysis data representing real licensing bypass results
    """
    return {
        "summary": (
            "Analyzed commercial software protection scheme. "
            "Identified multiple licensing bypasses and trial reset vulnerabilities."
        ),
        "binary_info": {
            "Path": r"C:\Program Files\TestApp\protected.exe",
            "Size": 2457600,
            "Architecture": "x86-64",
            "Compiler": "MSVC 19.28",
            "EntryPoint": "0x401000",
        },
        "protections": [
            {
                "name": "VMProtect 3.5",
                "description": "Commercial virtualization-based protection",
                "bypassed": True,
                "method": "Devirtualization via symbolic execution",
            },
            {
                "name": "Themida 3.1",
                "description": "Code obfuscation and anti-debugging",
                "bypassed": True,
                "method": "Anti-debug bypass via exception handler manipulation",
            },
            {
                "name": "Custom License Validation",
                "description": "RSA-2048 signature verification",
                "bypassed": False,
                "method": "Signature verification not yet bypassed",
            },
        ],
        "vulnerabilities": [
            {
                "severity": "critical",
                "type": "trial_reset",
                "description": "Trial period stored in plaintext registry key",
                "location": r"HKCU\Software\TestApp\InstallDate",
                "exploit": "Registry key deletion resets trial",
            },
            {
                "severity": "high",
                "type": "license_bypass",
                "description": "License check can be patched",
                "location": "0x402A45 - CMP EAX, EAX",
                "exploit": "NOP instruction at validation address",
            },
            {
                "severity": "medium",
                "type": "keygen_possible",
                "description": "Serial algorithm uses weak checksum",
                "location": "0x403B12",
                "exploit": "Reverse engineered serial generation algorithm",
            },
        ],
        "exploitation": [
            {
                "technique": "Trial Reset",
                "status": "success",
                "payload": "reg delete 'HKCU\\Software\\TestApp\\InstallDate' /f",
                "output": "Registry key deleted successfully. Trial period reset to 30 days.",
            },
            {
                "technique": "License Patch",
                "status": "success",
                "payload": "90 90 90 90 90",
                "output": "License validation bypassed via NOP sled at 0x402A45",
            },
            {
                "technique": "Keygen",
                "status": "partial",
                "payload": "Generated key: ABCD-1234-5678-EFGH-WXYZ",
                "output": "Key validates but some features remain locked",
            },
        ],
        "recommendations": [
            "Implement hardware-based license binding",
            "Use stronger cryptographic signature verification (ECDSA P-384)",
            "Add tamper detection for critical validation routines",
            "Store trial information in encrypted format with HMAC",
            "Implement multi-layer protection with periodic online validation",
        ],
    }


@pytest.fixture
def report_generator() -> ReportGenerator:
    """Create report generator instance.

    Returns:
        ReportGenerator: Initialized report generator
    """
    return ReportGenerator()


class TestReportGeneratorInitialization:
    """Tests for ReportGenerator initialization."""

    def test_initialization_creates_reports_directory(self, report_generator: ReportGenerator) -> None:
        """ReportGenerator creates reports directory on initialization."""
        assert report_generator.reports_dir is not None
        assert report_generator.reports_dir.exists()
        assert report_generator.reports_dir.is_dir()

    def test_initialization_finds_templates_directory(self, report_generator: ReportGenerator) -> None:
        """ReportGenerator locates or creates templates directory."""
        assert report_generator.templates_dir is not None
        assert report_generator.templates_dir.exists()

    def test_initialization_configures_jinja_if_available(self, report_generator: ReportGenerator) -> None:
        """ReportGenerator configures Jinja2 environment if available."""
        try:
            import importlib.util

            if importlib.util.find_spec("jinja2") is not None:
                if report_generator.templates_dir.exists():
                    assert report_generator.jinja_env is not None
        except (ImportError, ValueError):
            assert report_generator.jinja_env is None


class TestHTMLReportGeneration:
    """Tests for HTML report generation."""

    def test_generate_html_report_creates_valid_html(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """generate_html_report creates valid HTML document."""
        html = report_generator.generate_html_report(real_analysis_data)

        assert "<!DOCTYPE html>" in html
        assert "<html>" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "<body>" in html
        assert "Intellicrack Analysis Report" in html

    def test_html_report_includes_summary_section(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """HTML report includes analysis summary section."""
        html = report_generator.generate_html_report(real_analysis_data)

        assert "Summary" in html
        assert real_analysis_data["summary"] in html
        assert "Identified multiple licensing bypasses" in html

    def test_html_report_includes_binary_information(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """HTML report includes binary information section."""
        html = report_generator.generate_html_report(real_analysis_data)

        assert "Binary Information" in html
        assert "protected.exe" in html
        assert "2457600" in html
        assert "x86-64" in html

    def test_html_report_includes_protection_analysis(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """HTML report includes protection analysis with bypass status."""
        html = report_generator.generate_html_report(real_analysis_data)

        assert "Protection Analysis" in html
        assert "VMProtect 3.5" in html
        assert "Themida 3.1" in html
        assert "Devirtualization" in html

    def test_html_report_includes_vulnerabilities_table(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """HTML report includes vulnerabilities in formatted table."""
        html = report_generator.generate_html_report(real_analysis_data)

        assert "Vulnerabilities Found" in html
        assert "trial_reset" in html
        assert "license_bypass" in html
        assert "keygen_possible" in html
        assert "critical" in html
        assert "Registry key deletion resets trial" in html

    def test_html_report_includes_exploitation_results(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """HTML report includes exploitation results section."""
        html = report_generator.generate_html_report(real_analysis_data)

        assert "Exploitation Results" in html
        assert "Trial Reset" in html
        assert "License Patch" in html
        assert "Keygen" in html
        assert "success" in html

    def test_html_report_includes_recommendations(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """HTML report includes security recommendations."""
        html = report_generator.generate_html_report(real_analysis_data)

        assert "Security Recommendations" in html
        assert "hardware-based license binding" in html
        assert "tamper detection" in html

    def test_html_report_includes_timestamp(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """HTML report includes generation timestamp."""
        html = report_generator.generate_html_report(real_analysis_data)

        assert "Generated:" in html

    def test_html_report_includes_css_styling(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """HTML report includes CSS styles."""
        html = report_generator.generate_html_report(real_analysis_data)

        assert "<style>" in html
        assert "font-family" in html
        assert "severity-critical" in html
        assert "severity-high" in html

    def test_html_report_with_minimal_data(self, report_generator: ReportGenerator) -> None:
        """HTML report handles minimal data gracefully."""
        minimal_data: dict[str, Any] = {}

        html = report_generator.generate_html_report(minimal_data)

        assert "<!DOCTYPE html>" in html
        assert "<html>" in html
        assert "Intellicrack Analysis Report" in html


class TestJSONReportGeneration:
    """Tests for JSON report generation."""

    def test_generate_json_report_creates_valid_json(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """generate_json_report creates valid JSON document."""
        json_str = report_generator.generate_json_report(real_analysis_data)

        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_json_report_includes_metadata(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """JSON report includes metadata section."""
        json_str = report_generator.generate_json_report(real_analysis_data)
        report = json.loads(json_str)

        assert "metadata" in report
        assert report["metadata"]["generator"] == "Intellicrack Report Generator"
        assert "version" in report["metadata"]
        assert "timestamp" in report["metadata"]

    def test_json_report_preserves_analysis_data(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """JSON report preserves all analysis data accurately."""
        json_str = report_generator.generate_json_report(real_analysis_data)
        report = json.loads(json_str)

        assert "data" in report
        assert report["data"]["summary"] == real_analysis_data["summary"]
        assert len(report["data"]["protections"]) == 3
        assert len(report["data"]["vulnerabilities"]) == 3
        assert len(report["data"]["exploitation"]) == 3

    def test_json_report_maintains_data_types(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """JSON report maintains correct data types."""
        json_str = report_generator.generate_json_report(real_analysis_data)
        report = json.loads(json_str)

        assert isinstance(report["data"]["binary_info"]["Size"], int)
        assert isinstance(report["data"]["protections"], list)
        assert isinstance(report["data"]["protections"][0]["bypassed"], bool)

    def test_json_report_with_datetime_objects(self, report_generator: ReportGenerator) -> None:
        """JSON report handles datetime objects via default serialization."""
        data_with_datetime: dict[str, Any] = {
            "timestamp": datetime.now(),
            "analysis_date": datetime(2025, 1, 15, 10, 30, 0),
        }

        json_str = report_generator.generate_json_report(data_with_datetime)
        report = json.loads(json_str)

        assert "timestamp" in report["data"]


class TestTextReportGeneration:
    """Tests for text report generation."""

    def test_generate_text_report_creates_formatted_text(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """generate_text_report creates properly formatted text."""
        text = report_generator.generate_text_report(real_analysis_data)

        assert "INTELLICRACK ANALYSIS REPORT" in text
        assert "=" * 80 in text
        assert "Generated:" in text
        assert "END OF REPORT" in text

    def test_text_report_includes_summary_section(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """Text report includes summary section."""
        text = report_generator.generate_text_report(real_analysis_data)

        assert "SUMMARY" in text
        assert real_analysis_data["summary"] in text

    def test_text_report_includes_binary_information(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """Text report includes binary information section."""
        text = report_generator.generate_text_report(real_analysis_data)

        assert "BINARY INFORMATION" in text
        assert "Path:" in text
        assert "protected.exe" in text
        assert "Size:" in text

    def test_text_report_includes_protection_analysis(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """Text report includes protection analysis with bypass status."""
        text = report_generator.generate_text_report(real_analysis_data)

        assert "PROTECTION ANALYSIS" in text
        assert "[BYPASSED]" in text
        assert "VMProtect 3.5" in text
        assert "[ACTIVE]" in text

    def test_text_report_includes_vulnerabilities(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """Text report includes vulnerabilities section."""
        text = report_generator.generate_text_report(real_analysis_data)

        assert "VULNERABILITIES FOUND" in text
        assert "[critical]" in text.lower()
        assert "trial_reset" in text
        assert "Location:" in text

    def test_text_report_includes_exploitation_results(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """Text report includes exploitation results."""
        text = report_generator.generate_text_report(real_analysis_data)

        assert "EXPLOITATION RESULTS" in text
        assert "Technique:" in text
        assert "Status:" in text
        assert "Trial Reset" in text

    def test_text_report_includes_recommendations(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """Text report includes security recommendations."""
        text = report_generator.generate_text_report(real_analysis_data)

        assert "SECURITY RECOMMENDATIONS" in text
        assert "1." in text
        assert "hardware-based license binding" in text


class TestReportSaving:
    """Tests for report saving functionality."""

    def test_save_report_creates_file(self, report_generator: ReportGenerator) -> None:
        """save_report creates report file successfully."""
        content = "<html><body>Test Report</body></html>"

        filepath = report_generator.save_report(content, "html")

        assert Path(filepath).exists()
        assert Path(filepath).suffix == ".html"

        Path(filepath).unlink()

    def test_save_report_with_custom_filename(self, report_generator: ReportGenerator) -> None:
        """save_report uses custom filename when provided."""
        content = '{"test": "data"}'

        filepath = report_generator.save_report(content, "json", "custom_report.json")

        assert Path(filepath).exists()
        assert Path(filepath).name == "custom_report.json"

        Path(filepath).unlink()

    def test_save_report_creates_timestamped_filename(self, report_generator: ReportGenerator) -> None:
        """save_report creates timestamped filename when none provided."""
        content = "Test Report\n"

        filepath = report_generator.save_report(content, "txt")

        assert Path(filepath).exists()
        assert "intellicrack_report_" in Path(filepath).name
        assert Path(filepath).suffix == ".txt"

        Path(filepath).unlink()

    def test_save_report_writes_correct_content(self, report_generator: ReportGenerator) -> None:
        """save_report writes correct content to file."""
        expected_content = "Test analysis report content"

        filepath = report_generator.save_report(expected_content, "txt")

        with open(filepath) as f:
            actual_content = f.read()

        assert actual_content == expected_content

        Path(filepath).unlink()

    def test_save_html_report_preserves_formatting(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """Saved HTML report preserves all formatting and content."""
        html_content = report_generator.generate_html_report(real_analysis_data)

        filepath = report_generator.save_report(html_content, "html")

        with open(filepath) as f:
            saved_content = f.read()

        assert saved_content == html_content
        assert "VMProtect 3.5" in saved_content
        assert "trial_reset" in saved_content

        Path(filepath).unlink()


class TestTemporaryReportCreation:
    """Tests for temporary report creation."""

    def test_create_temporary_report_creates_file(self, report_generator: ReportGenerator) -> None:
        """create_temporary_report creates temporary file."""
        content = "<html><body>Temporary Report</body></html>"

        temp_path = report_generator.create_temporary_report(content, "html")

        try:
            assert Path(temp_path).exists()
            assert Path(temp_path).suffix == ".html"
            assert "intellicrack_temp_" in Path(temp_path).name
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_create_temporary_report_writes_content(self, report_generator: ReportGenerator) -> None:
        """create_temporary_report writes correct content."""
        expected_content = '{"test": "temporary data"}'

        temp_path = report_generator.create_temporary_report(expected_content, "json")

        try:
            with open(temp_path) as f:
                actual_content = f.read()

            assert actual_content == expected_content
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestSupportedFormats:
    """Tests for supported format queries."""

    def test_get_supported_formats_includes_basic_formats(self, report_generator: ReportGenerator) -> None:
        """get_supported_formats includes all basic formats."""
        formats = report_generator.get_supported_formats()

        assert "html" in formats
        assert "json" in formats
        assert "txt" in formats

    def test_get_format_mime_types_returns_correct_types(self, report_generator: ReportGenerator) -> None:
        """get_format_mime_types returns correct MIME types."""
        mime_types = report_generator.get_format_mime_types()

        assert mime_types["html"] == "text/html"
        assert mime_types["json"] == "application/json"
        assert mime_types["txt"] == "text/plain"
        assert mime_types["pdf"] == "application/pdf"


class TestEdgeCases:
    """Edge case tests for ReportGenerator."""

    def test_html_report_with_empty_sections(self, report_generator: ReportGenerator) -> None:
        """HTML report handles empty data sections gracefully."""
        data: dict[str, Any] = {
            "protections": [],
            "vulnerabilities": [],
            "exploitation": [],
        }

        html = report_generator.generate_html_report(data)

        assert "<!DOCTYPE html>" in html
        assert "Intellicrack Analysis Report" in html

    def test_report_with_special_characters(self, report_generator: ReportGenerator) -> None:
        """Report handles special characters in data correctly."""
        data: dict[str, Any] = {
            "summary": "Analysis of <script>alert('XSS')</script> binary",
            "vulnerabilities": [
                {
                    "type": "test & vulnerability",
                    "description": "Contains <tags> and & ampersands",
                    "severity": "high",
                }
            ],
        }

        html = report_generator.generate_html_report(data)

        assert "alert" in html

    def test_json_report_with_nested_structures(self, report_generator: ReportGenerator) -> None:
        """JSON report handles deeply nested structures."""
        data: dict[str, Any] = {
            "analysis": {
                "level1": {"level2": {"level3": {"data": "deep"}}},
                "array": [[1, 2], [3, 4]],
            }
        }

        json_str = report_generator.generate_json_report(data)
        parsed = json.loads(json_str)

        assert parsed["data"]["analysis"]["level1"]["level2"]["level3"]["data"] == "deep"

    def test_text_report_with_long_content(self, report_generator: ReportGenerator) -> None:
        """Text report handles long content appropriately."""
        data: dict[str, Any] = {
            "exploitation": [
                {
                    "technique": "Test",
                    "status": "success",
                    "output": "A" * 500,
                }
            ]
        }

        text = report_generator.generate_text_report(data)

        assert "Output:" in text
        assert len(text) > 200


class TestIntegrationScenarios:
    """Integration tests combining multiple operations."""

    def test_full_report_generation_workflow(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """Complete workflow from generation to saving."""
        html = report_generator.generate_html_report(real_analysis_data)
        filepath = report_generator.save_report(html, "html")

        try:
            assert Path(filepath).exists()

            with open(filepath) as f:
                saved_html = f.read()

            assert "VMProtect 3.5" in saved_html
            assert "trial_reset" in saved_html
            assert "Exploitation Results" in saved_html
        finally:
            Path(filepath).unlink()

    def test_multiple_format_generation(
        self, report_generator: ReportGenerator, real_analysis_data: dict[str, Any]
    ) -> None:
        """Generate same data in multiple formats."""
        html = report_generator.generate_html_report(real_analysis_data)
        json_str = report_generator.generate_json_report(real_analysis_data)
        text = report_generator.generate_text_report(real_analysis_data)

        assert "<!DOCTYPE html>" in html
        json_data = json.loads(json_str)
        assert "metadata" in json_data
        assert "INTELLICRACK ANALYSIS REPORT" in text

        assert "VMProtect" in html
        assert "VMProtect" in text
