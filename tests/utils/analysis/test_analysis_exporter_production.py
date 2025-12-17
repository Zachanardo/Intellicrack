"""Production-ready tests for analysis_exporter.py.

Tests validate REAL export functionality for JSON, HTML, CSV, and text formats.
All tests use realistic analysis data and verify correct output generation.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import csv
import json
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.analysis.analysis_exporter import AnalysisExporter


class TestJSONExport:
    """Test JSON export functionality."""

    def test_exports_vulnerability_analysis_to_json(self, tmp_path: Path) -> None:
        """JSON exporter creates valid vulnerability analysis output."""
        result = {
            "vulnerabilities": [
                {
                    "type": "buffer_overflow",
                    "file": "license.dll",
                    "line": 42,
                    "severity": "high",
                    "confidence": 0.95,
                    "description": "Unsafe strcpy usage",
                },
                {
                    "type": "format_string",
                    "file": "activation.dll",
                    "line": 128,
                    "severity": "medium",
                    "confidence": 0.78,
                    "description": "Unvalidated format string",
                },
            ],
            "statistics": {"total": 2, "high": 1, "medium": 1, "low": 0},
        }

        output_file = tmp_path / "vuln.json"
        success = AnalysisExporter.export_analysis(result, str(output_file), format="json")

        assert success is True
        assert output_file.exists()

        with open(output_file) as f:
            exported_data = json.load(f)

        assert len(exported_data["vulnerabilities"]) == 2
        assert exported_data["statistics"]["total"] == 2
        assert exported_data["vulnerabilities"][0]["type"] == "buffer_overflow"

    def test_exports_complex_nested_structures(self, tmp_path: Path) -> None:
        """JSON exporter handles deeply nested data structures."""
        result = {
            "analysis": {
                "protections": {
                    "vmprotect": {"version": "3.5", "detected": True, "features": ["virtualization", "mutation"]},
                    "themida": {"version": None, "detected": False, "features": []},
                },
                "license_checks": [
                    {"address": "0x401000", "type": "online", "bypassed": False},
                    {"address": "0x402500", "type": "offline", "bypassed": True},
                ],
            },
            "metadata": {"scan_time": 42.5, "file_size": 1024000},
        }

        output_file = tmp_path / "complex.json"
        success = AnalysisExporter.export_analysis(result, str(output_file), format="json")

        assert success is True

        with open(output_file) as f:
            exported_data = json.load(f)

        assert exported_data["analysis"]["protections"]["vmprotect"]["detected"] is True
        assert len(exported_data["analysis"]["license_checks"]) == 2

    def test_handles_special_json_types(self, tmp_path: Path) -> None:
        """JSON exporter handles dates, bytes, and custom types."""
        from datetime import datetime

        result = {
            "timestamp": datetime(2025, 1, 15, 10, 30, 0),
            "binary_data": b"\x90\x90\x90",
            "normal_string": "test",
        }

        output_file = tmp_path / "special_types.json"
        success = AnalysisExporter.export_analysis(result, str(output_file), format="json")

        assert success is True

        with open(output_file) as f:
            exported_data = json.load(f)

        assert "timestamp" in exported_data
        assert "binary_data" in exported_data


class TestHTMLExport:
    """Test HTML export functionality."""

    def test_exports_vulnerability_html_report(self, tmp_path: Path) -> None:
        """HTML exporter generates vulnerability report with styling."""
        result = {
            "vulnerabilities": [
                {
                    "type": "license_bypass",
                    "file": "protection.dll",
                    "line": 256,
                    "severity": "high",
                    "confidence": "high",
                    "description": "Trial check can be bypassed",
                },
                {
                    "type": "weak_crypto",
                    "file": "encryption.dll",
                    "line": 89,
                    "severity": "medium",
                    "confidence": "medium",
                    "description": "Weak XOR encryption",
                },
                {
                    "type": "hardcoded_key",
                    "file": "license.dll",
                    "line": 12,
                    "severity": "low",
                    "confidence": "low",
                    "description": "Potential hardcoded license key",
                },
            ],
        }

        output_file = tmp_path / "vuln.html"
        success = AnalysisExporter.export_analysis(
            result, str(output_file), format="html", analysis_type="vulnerability"
        )

        assert success is True
        assert output_file.exists()

        html_content = output_file.read_text()

        assert "<!DOCTYPE html>" in html_content
        assert "Vulnerability Analysis Report" in html_content
        assert "license_bypass" in html_content
        assert "high" in html_content.lower()
        assert "medium" in html_content.lower()
        assert "low" in html_content.lower()
        assert "Total Vulnerabilities:" in html_content

    def test_exports_binary_diff_html_report(self, tmp_path: Path) -> None:
        """HTML exporter generates binary diff report."""
        result = {
            "differences": [
                {
                    "type": "function_added",
                    "description": "New license validation function",
                    "old_value": "N/A",
                    "new_value": "validate_license_v2",
                },
                {
                    "type": "function_removed",
                    "description": "Old trial check removed",
                    "old_value": "check_trial_period",
                    "new_value": "N/A",
                },
                {
                    "type": "function_modified",
                    "description": "Activation logic changed",
                    "old_value": "activate_v1",
                    "new_value": "activate_v2",
                },
            ],
        }

        output_file = tmp_path / "diff.html"
        success = AnalysisExporter.export_analysis(result, str(output_file), format="html", analysis_type="binary_diff")

        assert success is True

        html_content = output_file.read_text()

        assert "Binary Diff Analysis Report" in html_content
        assert "function_added" in html_content
        assert "function_removed" in html_content
        assert "function_modified" in html_content
        assert "Total Differences:" in html_content

    def test_exports_generic_html_report(self, tmp_path: Path) -> None:
        """HTML exporter generates generic report for unknown types."""
        result = {
            "custom_analysis": {
                "protection_detected": "VMProtect 3.5",
                "license_type": "node-locked",
                "bypass_difficulty": "hard",
            },
        }

        output_file = tmp_path / "generic.html"
        success = AnalysisExporter.export_analysis(result, str(output_file), format="html", analysis_type="custom")

        assert success is True

        html_content = output_file.read_text()

        assert "<!DOCTYPE html>" in html_content
        assert "Analysis Report" in html_content
        assert "VMProtect 3.5" in html_content

    def test_html_vulnerability_severity_styling(self, tmp_path: Path) -> None:
        """HTML exporter applies correct CSS classes for severity levels."""
        result = {
            "vulnerabilities": [
                {"type": "high_vuln", "severity": "high", "description": "Critical issue"},
                {"type": "med_vuln", "severity": "medium", "description": "Moderate issue"},
                {"type": "low_vuln", "severity": "low", "description": "Minor issue"},
            ],
        }

        output_file = tmp_path / "severity.html"
        AnalysisExporter.export_analysis(result, str(output_file), format="html", analysis_type="vulnerability")

        html_content = output_file.read_text()

        assert 'class="vulnerability high"' in html_content
        assert 'class="vulnerability medium"' in html_content
        assert 'class="vulnerability low"' in html_content


class TestCSVExport:
    """Test CSV export functionality."""

    def test_exports_vulnerability_csv(self, tmp_path: Path) -> None:
        """CSV exporter creates vulnerability spreadsheet."""
        result = {
            "vulnerabilities": [
                {
                    "type": "sql_injection",
                    "file": "database.dll",
                    "line": 45,
                    "severity": "high",
                    "confidence": "high",
                    "description": "Unescaped SQL query",
                },
                {
                    "type": "path_traversal",
                    "file": "file_handler.dll",
                    "line": 78,
                    "severity": "medium",
                    "confidence": "medium",
                    "description": "User input in file path",
                },
            ],
        }

        output_file = tmp_path / "vuln.csv"
        success = AnalysisExporter.export_analysis(result, str(output_file), format="csv", analysis_type="vulnerability")

        assert success is True
        assert output_file.exists()

        with open(output_file, newline="") as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert rows[0] == ["Type", "File", "Line", "Severity", "Confidence", "Description"]
        assert rows[1][0] == "sql_injection"
        assert rows[2][0] == "path_traversal"

    def test_exports_binary_diff_csv(self, tmp_path: Path) -> None:
        """CSV exporter creates binary diff spreadsheet."""
        result = {
            "differences": [
                {
                    "type": "import_added",
                    "old_value": "",
                    "new_value": "CryptDecrypt",
                    "severity": "medium",
                    "description": "New crypto import",
                },
                {
                    "type": "section_modified",
                    "old_value": ".text:4096",
                    "new_value": ".text:8192",
                    "severity": "low",
                    "description": "Code section size changed",
                },
            ],
        }

        output_file = tmp_path / "diff.csv"
        success = AnalysisExporter.export_analysis(result, str(output_file), format="csv", analysis_type="binary_diff")

        assert success is True

        with open(output_file, newline="") as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert rows[0] == ["Type", "Old_Value", "New_Value", "Severity", "Description"]
        assert rows[1][0] == "import_added"
        assert rows[1][2] == "CryptDecrypt"

    def test_csv_handles_special_characters(self, tmp_path: Path) -> None:
        """CSV exporter properly escapes special characters."""
        result = {
            "vulnerabilities": [
                {
                    "type": "injection",
                    "file": 'file_with_"quotes".dll',
                    "line": 1,
                    "severity": "high",
                    "confidence": "high",
                    "description": "Contains, commas, and\nnewlines",
                },
            ],
        }

        output_file = tmp_path / "special.csv"
        success = AnalysisExporter.export_analysis(result, str(output_file), format="csv", analysis_type="vulnerability")

        assert success is True

        with open(output_file, newline="") as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert 'file_with_"quotes".dll' in rows[1][1] or 'file_with_"quotes".dll' == rows[1][1]

    def test_exports_generic_csv(self, tmp_path: Path) -> None:
        """CSV exporter handles generic data structures."""
        result = {
            "item1": {"name": "check1", "status": "pass", "score": 95},
            "item2": {"name": "check2", "status": "fail", "score": 42},
        }

        output_file = tmp_path / "generic.csv"
        success = AnalysisExporter.export_analysis(result, str(output_file), format="csv", analysis_type="generic")

        assert success is True


class TestTextExport:
    """Test text export functionality."""

    def test_exports_text_representation(self, tmp_path: Path) -> None:
        """Text exporter creates readable text output."""
        result = {
            "analysis": "Complete",
            "protections": ["VMProtect", "Themida"],
            "license_type": "time-based",
        }

        output_file = tmp_path / "result.txt"
        success = AnalysisExporter.export_analysis(result, str(output_file), format="text")

        assert success is True
        assert output_file.exists()

        text_content = output_file.read_text()

        assert "analysis" in text_content.lower()
        assert "protections" in text_content.lower()


class TestErrorHandling:
    """Test error handling in export operations."""

    def test_handles_invalid_format(self, tmp_path: Path) -> None:
        """Exporter returns False for unsupported format."""
        result = {"test": "data"}
        output_file = tmp_path / "test.xyz"

        success = AnalysisExporter.export_analysis(result, str(output_file), format="unsupported")

        assert success is False

    def test_handles_write_permission_error(self, tmp_path: Path) -> None:
        """Exporter handles file permission errors gracefully."""
        result = {"test": "data"}
        output_file = tmp_path / "readonly.json"
        output_file.write_text("existing")
        output_file.chmod(0o444)

        try:
            success = AnalysisExporter.export_analysis(result, str(output_file), format="json")
            assert success is False or output_file.read_text() != "existing"
        finally:
            output_file.chmod(0o644)

    def test_handles_invalid_output_path(self) -> None:
        """Exporter handles invalid output paths."""
        result = {"test": "data"}

        success = AnalysisExporter.export_analysis(result, "/nonexistent/directory/file.json", format="json")

        assert success is False

    def test_handles_empty_result(self, tmp_path: Path) -> None:
        """Exporter handles empty analysis results."""
        result: dict[str, Any] = {}
        output_file = tmp_path / "empty.json"

        success = AnalysisExporter.export_analysis(result, str(output_file), format="json")

        assert success is True

        with open(output_file) as f:
            exported_data = json.load(f)

        assert exported_data == {}

    def test_handles_none_values(self, tmp_path: Path) -> None:
        """Exporter handles None values in data."""
        result = {"key1": None, "key2": "value", "key3": None}
        output_file = tmp_path / "none_values.json"

        success = AnalysisExporter.export_analysis(result, str(output_file), format="json")

        assert success is True


class TestMultipleExportFormats:
    """Test exporting same data to multiple formats."""

    def test_exports_same_data_all_formats(self, tmp_path: Path) -> None:
        """Data can be exported successfully to all supported formats."""
        result = {
            "vulnerabilities": [
                {
                    "type": "test_vuln",
                    "file": "test.dll",
                    "line": 10,
                    "severity": "high",
                    "confidence": "high",
                    "description": "Test vulnerability",
                },
            ],
        }

        json_success = AnalysisExporter.export_analysis(
            result, str(tmp_path / "export.json"), format="json", analysis_type="vulnerability"
        )
        html_success = AnalysisExporter.export_analysis(
            result, str(tmp_path / "export.html"), format="html", analysis_type="vulnerability"
        )
        csv_success = AnalysisExporter.export_analysis(
            result, str(tmp_path / "export.csv"), format="csv", analysis_type="vulnerability"
        )
        text_success = AnalysisExporter.export_analysis(
            result, str(tmp_path / "export.txt"), format="text", analysis_type="vulnerability"
        )

        assert json_success is True
        assert html_success is True
        assert csv_success is True
        assert text_success is True

        assert (tmp_path / "export.json").exists()
        assert (tmp_path / "export.html").exists()
        assert (tmp_path / "export.csv").exists()
        assert (tmp_path / "export.txt").exists()


class TestPerformance:
    """Test export performance with large datasets."""

    def test_large_vulnerability_export(self, tmp_path: Path) -> None:
        """Exporter handles large vulnerability lists efficiently."""
        result = {
            "vulnerabilities": [
                {
                    "type": f"vuln_{i}",
                    "file": f"file_{i}.dll",
                    "line": i,
                    "severity": "medium",
                    "confidence": "medium",
                    "description": f"Vulnerability number {i}",
                }
                for i in range(1000)
            ],
        }

        import time

        output_file = tmp_path / "large.json"
        start_time = time.time()
        success = AnalysisExporter.export_analysis(result, str(output_file), format="json")
        duration = time.time() - start_time

        assert success is True
        assert duration < 5.0

        with open(output_file) as f:
            exported_data = json.load(f)

        assert len(exported_data["vulnerabilities"]) == 1000

    def test_deeply_nested_export(self, tmp_path: Path) -> None:
        """Exporter handles deeply nested structures."""
        result = {"level1": {"level2": {"level3": {"level4": {"level5": {"data": "deep"}}}}}}

        output_file = tmp_path / "nested.json"
        success = AnalysisExporter.export_analysis(result, str(output_file), format="json")

        assert success is True

        with open(output_file) as f:
            exported_data = json.load(f)

        assert exported_data["level1"]["level2"]["level3"]["level4"]["level5"]["data"] == "deep"
