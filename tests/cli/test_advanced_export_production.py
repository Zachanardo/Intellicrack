"""Production tests for advanced_export module.

Tests advanced export functionality with real file generation across multiple
formats (JSON, CSV, XML, HTML, YAML, Excel) and validates report content.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import csv
import json
from pathlib import Path
from typing import Any

import pytest

try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

from intellicrack.cli.advanced_export import (
    AdvancedExporter,
    export_analysis_results,
    get_available_formats,
)


@pytest.fixture
def temp_binary(tmp_path: Path) -> Path:
    """Create temporary test binary."""
    binary_path = tmp_path / "test_binary.exe"
    content = b"MZ\x90\x00" + b"TEST" * 100
    binary_path.write_bytes(content)
    return binary_path


@pytest.fixture
def sample_analysis_results() -> dict[str, Any]:
    """Create sample analysis results."""
    return {
        "basic_info": {
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "size": 1024,
            "file_type": "PE",
        },
        "vulnerabilities": {
            "vulnerabilities": [
                {
                    "severity": "high",
                    "type": "buffer_overflow",
                    "location": "0x1000",
                    "description": "Stack buffer overflow detected",
                    "impact": "Code execution",
                    "recommendation": "Use safe string functions",
                },
                {
                    "severity": "medium",
                    "type": "format_string",
                    "location": "0x2000",
                    "description": "Format string vulnerability",
                    "impact": "Information disclosure",
                    "recommendation": "Validate format strings",
                },
            ]
        },
        "protections": {
            "aslr": True,
            "dep": True,
            "canary": False,
        },
        "strings": [
            {"value": "license_key", "address": "0x3000", "section": ".data", "type": "ascii", "length": 11},
            {"value": "serial_check", "address": "0x3100", "section": ".data", "type": "ascii", "length": 12},
        ],
        "imports": {
            "kernel32.dll": [
                {"name": "VirtualProtect", "address": "0x4000", "ordinal": 1},
                {"name": "VirtualAlloc", "address": "0x4010", "ordinal": 2},
            ],
            "user32.dll": [{"name": "MessageBoxA", "address": "0x5000", "ordinal": 100}],
        },
    }


@pytest.fixture
def exporter_instance(temp_binary: Path, sample_analysis_results: dict[str, Any]) -> AdvancedExporter:
    """Create AdvancedExporter instance."""
    return AdvancedExporter(str(temp_binary), sample_analysis_results)


class TestAdvancedExporterInitialization:
    """Test AdvancedExporter initialization."""

    def test_exporter_initializes_with_metadata(self, exporter_instance: AdvancedExporter, temp_binary: Path) -> None:
        """Exporter initializes with correct metadata."""
        assert exporter_instance.binary_path == str(temp_binary)
        assert exporter_instance.analysis_results is not None
        assert exporter_instance.export_metadata is not None

        metadata = exporter_instance.export_metadata
        assert "export_time" in metadata
        assert "binary_path" in metadata
        assert "binary_name" in metadata
        assert "export_version" in metadata
        assert "tool" in metadata

        assert metadata["binary_name"] == temp_binary.name


class TestJSONExport:
    """Test JSON export functionality."""

    def test_export_detailed_json_creates_file(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """JSON export creates valid JSON file."""
        output_file = tmp_path / "report.json"

        success = exporter_instance.export_detailed_json(str(output_file))

        assert success is True
        assert output_file.exists()

    def test_export_detailed_json_contains_required_sections(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """JSON export contains all required sections."""
        output_file = tmp_path / "report.json"
        exporter_instance.export_detailed_json(str(output_file))

        with open(output_file) as f:
            data = json.load(f)

        assert "metadata" in data
        assert "summary" in data
        assert "analysis_results" in data
        assert "statistics" in data
        assert "recommendations" in data

    def test_export_detailed_json_with_raw_data(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """JSON export includes raw data samples when requested."""
        output_file = tmp_path / "report_with_raw.json"

        success = exporter_instance.export_detailed_json(str(output_file), include_raw_data=True)

        assert success is True

        with open(output_file) as f:
            data = json.load(f)

        assert "raw_data_samples" in data

    def test_export_detailed_json_without_raw_data(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """JSON export excludes raw data when not requested."""
        output_file = tmp_path / "report_no_raw.json"

        exporter_instance.export_detailed_json(str(output_file), include_raw_data=False)

        with open(output_file) as f:
            data = json.load(f)

        assert "raw_data_samples" not in data


class TestCSVExport:
    """Test CSV export functionality."""

    def test_export_vulnerabilities_csv_creates_file(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """CSV export creates vulnerabilities file."""
        output_file = tmp_path / "vulnerabilities.csv"

        success = exporter_instance.export_csv_data(str(output_file), data_type="vulnerabilities")

        assert success is True
        assert output_file.exists()

    def test_export_vulnerabilities_csv_contains_data(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """CSV export contains vulnerability data."""
        output_file = tmp_path / "vulnerabilities.csv"
        exporter_instance.export_csv_data(str(output_file), data_type="vulnerabilities")

        with open(output_file, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 2
        assert rows[0]["severity"] == "high"
        assert rows[0]["type"] == "buffer_overflow"
        assert rows[1]["severity"] == "medium"

    def test_export_strings_csv_creates_file(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """CSV export creates strings file."""
        output_file = tmp_path / "strings.csv"

        success = exporter_instance.export_csv_data(str(output_file), data_type="strings")

        assert success is True
        assert output_file.exists()

    def test_export_imports_csv_creates_file(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """CSV export creates imports file."""
        output_file = tmp_path / "imports.csv"

        success = exporter_instance.export_csv_data(str(output_file), data_type="imports")

        assert success is True
        assert output_file.exists()

    def test_export_comprehensive_csv_creates_multiple_files(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """CSV comprehensive export creates multiple files."""
        output_file = tmp_path / "comprehensive.csv"

        success = exporter_instance.export_csv_data(str(output_file), data_type="all")

        assert success is True

        base_path = tmp_path / "comprehensive"
        assert Path(f"{base_path}_vulnerabilities.csv").exists()
        assert Path(f"{base_path}_strings.csv").exists()
        assert Path(f"{base_path}_imports.csv").exists()
        assert Path(f"{base_path}_summary.csv").exists()


class TestXMLExport:
    """Test XML export functionality."""

    def test_export_xml_report_creates_file(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """XML export creates valid XML file."""
        output_file = tmp_path / "report.xml"

        success = exporter_instance.export_xml_report(str(output_file))

        assert success is True
        assert output_file.exists()

    def test_export_xml_report_is_valid_xml(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """XML export creates valid parseable XML."""
        output_file = tmp_path / "report.xml"
        exporter_instance.export_xml_report(str(output_file))

        tree = ET.parse(output_file)
        root = tree.getroot()

        assert root.tag == "intellicrack_report"

    def test_export_xml_report_contains_required_sections(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """XML export contains required sections."""
        output_file = tmp_path / "report.xml"
        exporter_instance.export_xml_report(str(output_file))

        tree = ET.parse(output_file)
        root = tree.getroot()

        assert root.find("metadata") is not None
        assert root.find("analysis_results") is not None
        assert root.find("summary") is not None


class TestHTMLExport:
    """Test HTML export functionality."""

    def test_export_html_report_creates_file(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """HTML export creates HTML file."""
        output_file = tmp_path / "report.html"

        success = exporter_instance.export_html_report(str(output_file))

        if success:
            assert output_file.exists()
            content = output_file.read_text()
            assert "<!DOCTYPE html>" in content or "<html>" in content

    def test_export_html_report_contains_analysis_data(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """HTML export contains analysis data."""
        output_file = tmp_path / "report.html"

        success = exporter_instance.export_html_report(str(output_file))

        if success:
            content = output_file.read_text()
            assert "Intellicrack" in content or "Analysis" in content


class TestExecutiveSummary:
    """Test executive summary export."""

    def test_export_executive_summary_markdown(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """Executive summary exports to Markdown."""
        output_file = tmp_path / "summary.md"

        success = exporter_instance.export_executive_summary(str(output_file), "markdown")

        assert success is True
        assert output_file.exists()

        content = output_file.read_text()
        assert "Security Analysis Report" in content or "Binary Information" in content

    def test_export_executive_summary_html(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """Executive summary exports to HTML."""
        output_file = tmp_path / "summary.html"

        success = exporter_instance.export_executive_summary(str(output_file), "html")

        assert success is True
        assert output_file.exists()

        content = output_file.read_text()
        assert "<html>" in content.lower() or "<!DOCTYPE" in content

    def test_export_executive_summary_text(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """Executive summary exports to plain text."""
        output_file = tmp_path / "summary.txt"

        success = exporter_instance.export_executive_summary(str(output_file), "txt")

        assert success is True
        assert output_file.exists()

        content = output_file.read_text()
        assert len(content) > 0


class TestVulnerabilityReport:
    """Test vulnerability report export."""

    def test_export_vulnerability_report_creates_file(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """Vulnerability report creates JSON file."""
        output_file = tmp_path / "vuln_report.json"

        success = exporter_instance.export_vulnerability_report(str(output_file))

        assert success is True
        assert output_file.exists()

    def test_export_vulnerability_report_contains_required_sections(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """Vulnerability report contains required sections."""
        output_file = tmp_path / "vuln_report.json"
        exporter_instance.export_vulnerability_report(str(output_file))

        with open(output_file) as f:
            data = json.load(f)

        assert "metadata" in data
        assert "executive_summary" in data
        assert "detailed_findings" in data
        assert "mitigation_strategies" in data
        assert "compliance_notes" in data

    def test_vulnerability_report_calculates_risk_score(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """Vulnerability report calculates risk score."""
        output_file = tmp_path / "vuln_report.json"
        exporter_instance.export_vulnerability_report(str(output_file))

        with open(output_file) as f:
            data = json.load(f)

        summary = data["executive_summary"]
        assert "risk_score" in summary
        assert isinstance(summary["risk_score"], (int, float))


class TestYAMLExport:
    """Test YAML export functionality."""

    def test_export_yaml_config_creates_file_if_available(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """YAML export creates file if YAML available."""
        output_file = tmp_path / "config.yaml"

        success = exporter_instance.export_yaml_config(str(output_file))

        if success:
            assert output_file.exists()

    def test_export_yaml_config_handles_unavailable_yaml(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """YAML export handles unavailable YAML library."""
        output_file = tmp_path / "config.yaml"

        success = exporter_instance.export_yaml_config(str(output_file))

        assert isinstance(success, bool)


class TestExcelExport:
    """Test Excel export functionality."""

    def test_export_excel_workbook_creates_file_if_available(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """Excel export creates file if xlsxwriter available."""
        output_file = tmp_path / "report.xlsx"

        success = exporter_instance.export_excel_workbook(str(output_file))

        if success:
            assert output_file.exists()

    def test_export_excel_workbook_handles_unavailable_xlsxwriter(
        self, exporter_instance: AdvancedExporter, tmp_path: Path
    ) -> None:
        """Excel export handles unavailable xlsxwriter library."""
        output_file = tmp_path / "report.xlsx"

        success = exporter_instance.export_excel_workbook(str(output_file))

        assert isinstance(success, bool)


class TestHelperMethods:
    """Test helper methods."""

    def test_generate_summary_creates_complete_summary(self, exporter_instance: AdvancedExporter) -> None:
        """Generate summary creates complete summary structure."""
        summary = exporter_instance._generate_summary()

        assert "file_info" in summary
        assert "analysis_overview" in summary
        assert "key_findings" in summary
        assert "security_assessment" in summary

    def test_generate_statistics_calculates_metrics(self, exporter_instance: AdvancedExporter) -> None:
        """Generate statistics calculates correct metrics."""
        stats = exporter_instance._generate_statistics()

        assert "analysis_time" in stats
        assert "total_categories" in stats
        assert "data_points" in stats
        assert "categories" in stats

    def test_generate_recommendations_returns_list(self, exporter_instance: AdvancedExporter) -> None:
        """Generate recommendations returns list of recommendations."""
        recommendations = exporter_instance._generate_recommendations()

        assert isinstance(recommendations, list)
        assert len(recommendations) > 0

    def test_assess_overall_risk_returns_risk_level(self, exporter_instance: AdvancedExporter) -> None:
        """Assess overall risk returns risk level."""
        risk = exporter_instance._assess_overall_risk()

        assert "level" in risk
        assert "description" in risk
        assert risk["level"] in ["HIGH", "MEDIUM", "LOW"]

    def test_count_vulnerabilities_by_severity(self, exporter_instance: AdvancedExporter) -> None:
        """Count vulnerabilities by severity works correctly."""
        vuln_data = exporter_instance.analysis_results.get("vulnerabilities", {})

        high_count = exporter_instance._count_vulnerabilities_by_severity(vuln_data, "high")
        medium_count = exporter_instance._count_vulnerabilities_by_severity(vuln_data, "medium")

        assert high_count == 1
        assert medium_count == 1

    def test_calculate_risk_score_computes_score(self, exporter_instance: AdvancedExporter) -> None:
        """Calculate risk score computes correct score."""
        vuln_data = exporter_instance.analysis_results.get("vulnerabilities", {})

        score = exporter_instance._calculate_risk_score(vuln_data)

        assert isinstance(score, float)
        assert 0.0 <= score <= 100.0


class TestExportAnalysisResults:
    """Test export_analysis_results function."""

    def test_export_analysis_results_json(
        self, temp_binary: Path, sample_analysis_results: dict[str, Any], tmp_path: Path
    ) -> None:
        """Export analysis results exports JSON format."""
        output_file = tmp_path / "export.json"

        success = export_analysis_results(
            str(temp_binary), sample_analysis_results, str(output_file), "json"
        )

        assert success is True
        assert output_file.exists()

    def test_export_analysis_results_csv(
        self, temp_binary: Path, sample_analysis_results: dict[str, Any], tmp_path: Path
    ) -> None:
        """Export analysis results exports CSV format."""
        output_file = tmp_path / "export.csv"

        success = export_analysis_results(
            str(temp_binary), sample_analysis_results, str(output_file), "csv"
        )

        assert success is True

    def test_export_analysis_results_unsupported_format(
        self, temp_binary: Path, sample_analysis_results: dict[str, Any], tmp_path: Path
    ) -> None:
        """Export analysis results handles unsupported format."""
        output_file = tmp_path / "export.unknown"

        success = export_analysis_results(
            str(temp_binary), sample_analysis_results, str(output_file), "unsupported"
        )

        assert success is False


class TestGetAvailableFormats:
    """Test get_available_formats function."""

    def test_get_available_formats_returns_list(self) -> None:
        """Get available formats returns list of formats."""
        formats = get_available_formats()

        assert isinstance(formats, list)
        assert len(formats) > 0

    def test_get_available_formats_contains_core_formats(self) -> None:
        """Get available formats contains core formats."""
        formats = get_available_formats()

        assert "json" in formats
        assert "markdown" in formats
        assert "html" in formats
        assert "txt" in formats
        assert "csv" in formats
        assert "xml" in formats


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_export_with_empty_analysis_results(self, temp_binary: Path, tmp_path: Path) -> None:
        """Export handles empty analysis results."""
        empty_results: dict[str, Any] = {}
        exporter = AdvancedExporter(str(temp_binary), empty_results)

        output_file = tmp_path / "empty_report.json"
        success = exporter.export_detailed_json(str(output_file))

        assert success is True
        assert output_file.exists()

    def test_export_with_malformed_vulnerability_data(self, temp_binary: Path, tmp_path: Path) -> None:
        """Export handles malformed vulnerability data."""
        malformed_results = {
            "vulnerabilities": "not_a_dict_or_list",
        }

        exporter = AdvancedExporter(str(temp_binary), malformed_results)
        output_file = tmp_path / "malformed_report.json"

        success = exporter.export_detailed_json(str(output_file))

        assert success is True

    def test_export_handles_nonexistent_binary(self, tmp_path: Path, sample_analysis_results: dict[str, Any]) -> None:
        """Export handles nonexistent binary file."""
        nonexistent_binary = tmp_path / "nonexistent.exe"

        exporter = AdvancedExporter(str(nonexistent_binary), sample_analysis_results)
        output_file = tmp_path / "report.json"

        success = exporter.export_detailed_json(str(output_file))

        assert success is True
