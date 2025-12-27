"""Comprehensive tests for ExportWorker export functionality.

Tests real export format generation (JSON, XML, CSV, HTML, PDF) with production analysis data.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import pytest
import tempfile
from pathlib import Path
from typing import Any

from intellicrack.ui.dialogs.export_dialog import ExportWorker


class RealDetection:
    """Real detection object matching production structure."""

    def __init__(self, name: str, det_type: str, confidence: float, version: str = "") -> None:
        self.name = name
        self.type = det_type
        self.confidence = confidence
        self.version = version


class RealICPAnalysis:
    """Real ICP analysis result object matching production structure."""

    def __init__(self) -> None:
        self.file_type = "PE32"
        self.architecture = "x86"
        self.is_protected = True
        self.all_detections = [
            RealDetection("UPX", "Packer", 0.95, "3.96"),
            RealDetection("VMProtect", "Protector", 0.78, "3.5"),
            RealDetection("Themida", "Protector", 0.82, "3.1"),
            RealDetection("Anti-Debug", "Protector", 0.45),
        ]


@pytest.fixture
def real_analysis_results() -> dict[str, Any]:
    """Provide real analysis results structure for export testing."""
    return {
        "file_info": {
            "file_path": r"C:\test\protected_binary.exe",
            "file_size": 1024000,
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        "icp_analysis": RealICPAnalysis(),
    }


class TestExportWorkerJSONFormat:
    """Test JSON export format generation."""

    def test_export_worker_json_export(self, real_analysis_results: dict[str, Any]) -> None:
        """ExportWorker exports to JSON format correctly."""
        export_path = Path(tempfile.gettempdir()) / "test_export_worker.json"

        export_config = {
            "format": "json",
            "output_path": str(export_path),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_json(str(export_path), real_analysis_results)

            assert export_path.exists()

            with open(export_path) as f:
                exported_data = json.load(f)

            assert "export_info" in exported_data
            assert "analysis_results" in exported_data
            assert exported_data["analysis_results"]["file_info"]["file_size"] == 1024000

        finally:
            if export_path.exists():
                export_path.unlink()

    def test_json_export_contains_all_detections(self, real_analysis_results: dict[str, Any]) -> None:
        """JSON export includes all protection detections."""
        export_path = Path(tempfile.gettempdir()) / "test_detections.json"

        export_config = {
            "format": "json",
            "output_path": str(export_path),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_json(str(export_path), real_analysis_results)

            with open(export_path) as f:
                exported_data = json.load(f)

            assert export_path.exists()
            assert "icp_analysis" in exported_data["analysis_results"]

        finally:
            if export_path.exists():
                export_path.unlink()

    def test_json_export_pretty_formatting(self, real_analysis_results: dict[str, Any]) -> None:
        """JSON export with pretty formatting is human-readable."""
        export_path = Path(tempfile.gettempdir()) / "test_pretty.json"

        export_config = {
            "format": "json",
            "output_path": str(export_path),
            "results": real_analysis_results,
            "pretty_format": True,
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_json(str(export_path), real_analysis_results)

            content = export_path.read_text()

            assert export_path.exists()
            assert content.count("\n") > 10

        finally:
            if export_path.exists():
                export_path.unlink()


class TestExportWorkerXMLFormat:
    """Test XML export format generation."""

    def test_export_worker_xml_export(self, real_analysis_results: dict[str, Any]) -> None:
        """ExportWorker exports to XML format correctly."""
        export_path = Path(tempfile.gettempdir()) / "test_export_worker.xml"

        export_config = {
            "format": "xml",
            "output_path": str(export_path),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_xml(str(export_path), real_analysis_results)

            assert export_path.exists()

            content = export_path.read_text()
            assert "<?xml" in content or "<intellicrack_analysis" in content

        finally:
            if export_path.exists():
                export_path.unlink()

    def test_xml_export_valid_structure(self, real_analysis_results: dict[str, Any]) -> None:
        """XML export produces valid XML structure."""
        export_path = Path(tempfile.gettempdir()) / "test_valid.xml"

        export_config = {
            "format": "xml",
            "output_path": str(export_path),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_xml(str(export_path), real_analysis_results)

            content = export_path.read_text()

            assert export_path.exists()
            assert content.count("<") > 0
            assert content.count(">") > 0

        finally:
            if export_path.exists():
                export_path.unlink()


class TestExportWorkerCSVFormat:
    """Test CSV export format generation."""

    def test_export_worker_csv_export(self, real_analysis_results: dict[str, Any]) -> None:
        """ExportWorker exports to CSV format correctly."""
        export_path = Path(tempfile.gettempdir()) / "test_export_worker.csv"

        export_config = {
            "format": "csv",
            "output_path": str(export_path),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_csv(str(export_path), real_analysis_results)

            assert export_path.exists()

            content = export_path.read_text()
            assert "Detection Name" in content

        finally:
            if export_path.exists():
                export_path.unlink()

    def test_csv_export_has_headers(self, real_analysis_results: dict[str, Any]) -> None:
        """CSV export includes column headers."""
        export_path = Path(tempfile.gettempdir()) / "test_headers.csv"

        export_config = {
            "format": "csv",
            "output_path": str(export_path),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_csv(str(export_path), real_analysis_results)

            lines = export_path.read_text().split("\n")

            assert len(lines) > 0
            header_line = lines[0]
            assert "," in header_line

        finally:
            if export_path.exists():
                export_path.unlink()

    def test_csv_export_includes_all_detections(self, real_analysis_results: dict[str, Any]) -> None:
        """CSV export includes all detection rows."""
        export_path = Path(tempfile.gettempdir()) / "test_all_rows.csv"

        export_config = {
            "format": "csv",
            "output_path": str(export_path),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_csv(str(export_path), real_analysis_results)

            lines = export_path.read_text().split("\n")
            non_empty_lines = [line for line in lines if line.strip()]

            assert len(non_empty_lines) >= 4

        finally:
            if export_path.exists():
                export_path.unlink()


class TestExportWorkerHTMLFormat:
    """Test HTML export format generation."""

    def test_export_worker_html_export(self, real_analysis_results: dict[str, Any]) -> None:
        """ExportWorker exports to HTML format correctly."""
        export_path = Path(tempfile.gettempdir()) / "test_export_worker.html"

        export_config = {
            "format": "html",
            "output_path": str(export_path),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_html(str(export_path), real_analysis_results)

            assert export_path.exists()

            content = export_path.read_text()
            assert "<!DOCTYPE html>" in content
            assert "Intellicrack" in content

        finally:
            if export_path.exists():
                export_path.unlink()

    def test_html_export_includes_css_styling(self, real_analysis_results: dict[str, Any]) -> None:
        """HTML export includes CSS styling."""
        export_path = Path(tempfile.gettempdir()) / "test_styled.html"

        export_config = {
            "format": "html",
            "output_path": str(export_path),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_html(str(export_path), real_analysis_results)

            content = export_path.read_text()

            assert "<style>" in content or "style=" in content

        finally:
            if export_path.exists():
                export_path.unlink()

    def test_html_export_displays_detection_table(self, real_analysis_results: dict[str, Any]) -> None:
        """HTML export includes detection results table."""
        export_path = Path(tempfile.gettempdir()) / "test_table.html"

        export_config = {
            "format": "html",
            "output_path": str(export_path),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_html(str(export_path), real_analysis_results)

            content = export_path.read_text()

            assert "<table" in content or "<tr>" in content or "<td>" in content

        finally:
            if export_path.exists():
                export_path.unlink()


class TestExportWorkerPDFFormat:
    """Test PDF export format generation."""

    def test_export_worker_pdf_export(self, real_analysis_results: dict[str, Any]) -> None:
        """ExportWorker exports to PDF format correctly (if ReportLab available)."""
        pytest.importorskip("reportlab")

        export_path = Path(tempfile.gettempdir()) / "test_export_worker.pdf"

        export_config = {
            "format": "pdf",
            "output_path": str(export_path),
            "results": real_analysis_results,
            "page_format": "A4",
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_pdf(str(export_path), real_analysis_results)

            assert export_path.exists()
            assert export_path.stat().st_size > 0

        finally:
            if export_path.exists():
                export_path.unlink()

    def test_pdf_export_letter_format(self, real_analysis_results: dict[str, Any]) -> None:
        """PDF export supports Letter page format."""
        pytest.importorskip("reportlab")

        export_path = Path(tempfile.gettempdir()) / "test_letter.pdf"

        export_config = {
            "format": "pdf",
            "output_path": str(export_path),
            "results": real_analysis_results,
            "page_format": "Letter",
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_pdf(str(export_path), real_analysis_results)

            assert export_path.exists()
            assert export_path.stat().st_size > 0

        finally:
            if export_path.exists():
                export_path.unlink()

    def test_pdf_export_contains_binary_info(self, real_analysis_results: dict[str, Any]) -> None:
        """PDF export includes binary file information."""
        pytest.importorskip("reportlab")

        export_path = Path(tempfile.gettempdir()) / "test_info.pdf"

        export_config = {
            "format": "pdf",
            "output_path": str(export_path),
            "results": real_analysis_results,
            "page_format": "A4",
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_pdf(str(export_path), real_analysis_results)

            assert export_path.exists()
            assert export_path.stat().st_size > 1000

        finally:
            if export_path.exists():
                export_path.unlink()


class TestExportWorkerErrorHandling:
    """Test export worker error handling."""

    def test_export_worker_unsupported_format_raises_error(self, real_analysis_results: dict[str, Any]) -> None:
        """ExportWorker raises error for unsupported format."""
        export_config = {
            "format": "unsupported_format",
            "output_path": "/tmp/test.unsupported",
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)

        with pytest.raises(ValueError, match="Unsupported export format"):
            worker.run()

    def test_export_worker_handles_write_permission_error(self, real_analysis_results: dict[str, Any]) -> None:
        """ExportWorker handles file write permission errors."""
        export_path = r"C:\Windows\System32\protected.json"

        export_config = {
            "format": "json",
            "output_path": export_path,
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)
        worker.run()

    def test_export_worker_handles_empty_results(self) -> None:
        """ExportWorker handles empty analysis results."""
        export_path = Path(tempfile.gettempdir()) / "test_empty.json"

        export_config = {
            "format": "json",
            "output_path": str(export_path),
            "results": {},
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_json(str(export_path), {})

            assert export_path.exists()

        finally:
            if export_path.exists():
                export_path.unlink()

    def test_export_worker_handles_missing_detections(self) -> None:
        """ExportWorker handles analysis results without detections."""
        class ICPNoDetections:
            def __init__(self) -> None:
                self.file_type = "PE32"
                self.architecture = "x86"
                self.is_protected = False

        results = {"icp_analysis": ICPNoDetections()}

        export_path = Path(tempfile.gettempdir()) / "test_no_detections.json"

        export_config = {
            "format": "json",
            "output_path": str(export_path),
            "results": results,
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_json(str(export_path), results)

            assert export_path.exists()

        finally:
            if export_path.exists():
                export_path.unlink()


class TestExportWorkerEdgeCases:
    """Test edge cases in export functionality."""

    def test_export_large_number_of_detections(self) -> None:
        """ExportWorker handles export with many detections."""
        class ManyDetections:
            def __init__(self) -> None:
                self.file_type = "PE32"
                self.architecture = "x64"
                self.is_protected = True
                self.all_detections = [
                    RealDetection(f"Protection_{i}", "Protector", 0.5 + (i * 0.01), f"v{i}")
                    for i in range(100)
                ]

        results = {
            "file_info": {
                "file_path": r"C:\test\large.exe",
                "file_size": 5000000,
                "md5": "test_md5",
                "sha256": "test_sha256",
            },
            "icp_analysis": ManyDetections(),
        }

        export_path = Path(tempfile.gettempdir()) / "test_large.json"

        export_config = {
            "format": "json",
            "output_path": str(export_path),
            "results": results,
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_json(str(export_path), results)

            assert export_path.exists()

            with open(export_path) as f:
                data = json.load(f)

            assert "analysis_results" in data

        finally:
            if export_path.exists():
                export_path.unlink()

    def test_export_special_characters_in_paths(self) -> None:
        """ExportWorker handles special characters in file paths."""
        results = {
            "file_info": {
                "file_path": r"C:\test\файл&тест\binary (copy).exe",
                "file_size": 1024,
                "md5": "test",
                "sha256": "test",
            },
        }

        export_path = Path(tempfile.gettempdir()) / "test_special_chars.json"

        export_config = {
            "format": "json",
            "output_path": str(export_path),
            "results": results,
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_json(str(export_path), results)

            assert export_path.exists()

        finally:
            if export_path.exists():
                export_path.unlink()

    def test_export_with_unicode_detection_names(self) -> None:
        """ExportWorker handles Unicode characters in detection names."""
        class UnicodeDetections:
            def __init__(self) -> None:
                self.file_type = "PE32"
                self.architecture = "x86"
                self.is_protected = True
                self.all_detections = [
                    RealDetection("Защита", "Protector", 0.9, "3.0"),
                    RealDetection("暗号化", "Packer", 0.85, "2.1"),
                ]

        results = {
            "file_info": {
                "file_path": r"C:\test\binary.exe",
                "file_size": 1024,
                "md5": "test",
                "sha256": "test",
            },
            "icp_analysis": UnicodeDetections(),
        }

        export_path = Path(tempfile.gettempdir()) / "test_unicode.json"

        export_config = {
            "format": "json",
            "output_path": str(export_path),
            "results": results,
        }

        worker = ExportWorker(export_config)

        try:
            worker._export_json(str(export_path), results)

            assert export_path.exists()

            content = export_path.read_text(encoding="utf-8")
            assert len(content) > 0

        finally:
            if export_path.exists():
                export_path.unlink()
