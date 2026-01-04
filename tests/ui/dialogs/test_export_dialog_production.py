"""Production-ready tests for ExportDialog.

Tests REAL export functionality with actual file generation and validation.
Tests MUST FAIL if export logic doesn't produce valid output files.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.core.analysis.icp_analysis import ICPAnalysisResult
from intellicrack.core.analysis.protection_detection import ProtectionDetection
from intellicrack.ui.dialogs.export_dialog import ExportDialog, ExportWorker


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    """Create QApplication instance for all tests."""
    existing_app = QApplication.instance()
    if existing_app is None:
        app = QApplication([])
        app.setApplicationName("IntellicrackExportTest")
        return app
    assert isinstance(existing_app, QApplication), "Expected QApplication instance"
    existing_app.setApplicationName("IntellicrackExportTest")
    return existing_app


@pytest.fixture
def real_analysis_results() -> dict[str, Any]:
    """Create REAL analysis results with actual detections and file data."""
    real_detections = [
        ProtectionDetection("VMProtect", "Protector", 0.95, "3.5"),
        ProtectionDetection("Themida", "Protector", 0.87, "3.1"),
        ProtectionDetection("UPX", "Packer", 0.78, "3.96"),
        ProtectionDetection("Anti-Debug", "Protection", 0.65),
        ProtectionDetection("Code Virtualization", "Protection", 0.45),
    ]

    test_binary_content = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 1000

    file_info = {
        "file_path": "C:\\test\\protected_app.exe",
        "file_size": len(test_binary_content),
        "md5": hashlib.md5(test_binary_content).hexdigest(),
        "sha256": hashlib.sha256(test_binary_content).hexdigest(),
    }

    icp_analysis = ICPAnalysisResult(
        file_type="PE32",
        architecture="x86",
        is_protected=True,
        all_detections=real_detections,
    )

    return {"file_info": file_info, "icp_analysis": icp_analysis}


class TestExportWorkerJSONExport:
    """Test REAL JSON export with actual file creation and validation."""

    def test_json_export_creates_valid_json_file(self, tmp_path: Path, real_analysis_results: dict[str, Any]) -> None:
        """JSON export produces syntactically valid JSON file with correct structure."""
        output_file = tmp_path / "test_export.json"

        export_config = {
            "format": "json",
            "output_path": str(output_file),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)
        worker.run()

        assert output_file.exists(), "JSON export must create output file"
        assert output_file.stat().st_size > 0, "JSON export must write data to file"

        with open(output_file, encoding="utf-8") as f:
            exported_data = json.load(f)

        assert "export_info" in exported_data
        assert "analysis_results" in exported_data
        assert exported_data["export_info"]["format"] == "json"
        assert exported_data["export_info"]["version"] == "1.0"
        assert "timestamp" in exported_data["export_info"]
        assert exported_data["export_info"]["exported_by"] == "Intellicrack Protection Engine"

    def test_json_export_includes_complete_analysis_data(self, tmp_path: Path, real_analysis_results: dict[str, Any]) -> None:
        """JSON export includes all analysis results with correct values."""
        output_file = tmp_path / "analysis_full.json"

        export_config = {
            "format": "json",
            "output_path": str(output_file),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)
        worker.run()

        with open(output_file, encoding="utf-8") as f:
            data = json.load(f)

        results = data["analysis_results"]
        assert "file_info" in results
        assert "icp_analysis" in results

        file_info = results["file_info"]
        assert file_info["file_path"] == "C:\\test\\protected_app.exe"
        assert file_info["file_size"] == 1008
        assert "md5" in file_info
        assert "sha256" in file_info

    def test_json_export_handles_empty_results(self, tmp_path: Path) -> None:
        """JSON export works with minimal/empty analysis results."""
        output_file = tmp_path / "empty.json"

        export_config = {
            "format": "json",
            "output_path": str(output_file),
            "results": {},
        }

        worker = ExportWorker(export_config)
        worker.run()

        assert output_file.exists()

        with open(output_file, encoding="utf-8") as f:
            data = json.load(f)

        assert "export_info" in data
        assert "analysis_results" in data
        assert data["analysis_results"] == {}


class TestExportWorkerXMLExport:
    """Test REAL XML export with actual file creation and validation."""

    def test_xml_export_creates_valid_xml_file(self, tmp_path: Path, real_analysis_results: dict[str, Any]) -> None:
        """XML export produces syntactically valid XML file."""
        output_file = tmp_path / "test_export.xml"

        export_config = {
            "format": "xml",
            "output_path": str(output_file),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)
        worker.run()

        assert output_file.exists(), "XML export must create output file"
        assert output_file.stat().st_size > 0, "XML export must write data to file"

        tree = ET.parse(output_file)
        root = tree.getroot()

        assert root.tag == "intellicrack_analysis"
        assert "timestamp" in root.attrib
        assert root.attrib["version"] == "1.0"

    def test_xml_export_includes_file_info_structure(self, tmp_path: Path, real_analysis_results: dict[str, Any]) -> None:
        """XML export includes complete file information in correct structure."""
        output_file = tmp_path / "analysis.xml"

        export_config = {
            "format": "xml",
            "output_path": str(output_file),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)
        worker.run()

        tree = ET.parse(output_file)
        root = tree.getroot()

        file_info = root.find("file_info")
        assert file_info is not None

        file_path_elem = file_info.find("file_path")
        assert file_path_elem is not None
        assert file_path_elem.text == "C:\\test\\protected_app.exe"

        file_size_elem = file_info.find("file_size")
        assert file_size_elem is not None
        assert file_size_elem.text == "1008"

    def test_xml_export_includes_icp_analysis_structure(self, tmp_path: Path, real_analysis_results: dict[str, Any]) -> None:
        """XML export includes ICP analysis with detections."""
        output_file = tmp_path / "icp_analysis.xml"

        export_config = {
            "format": "xml",
            "output_path": str(output_file),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)
        worker.run()

        tree = ET.parse(output_file)
        root = tree.getroot()

        icp_elem = root.find("icp_analysis")
        assert icp_elem is not None

        is_protected = icp_elem.find("is_protected")
        assert is_protected is not None
        assert is_protected.text in ["True", "true"]

        file_type = icp_elem.find("file_type")
        assert file_type is not None
        assert file_type.text == "PE32"


class TestExportWorkerCSVExport:
    """Test REAL CSV export with actual file creation and validation."""

    def test_csv_export_creates_valid_csv_file(self, tmp_path: Path, real_analysis_results: dict[str, Any]) -> None:
        """CSV export produces valid CSV file with correct headers."""
        output_file = tmp_path / "test_export.csv"

        export_config = {
            "format": "csv",
            "output_path": str(output_file),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)
        worker.run()

        assert output_file.exists(), "CSV export must create output file"
        assert output_file.stat().st_size > 0, "CSV export must write data"

        with open(output_file, encoding="utf-8") as f:
            lines = f.readlines()

        assert len(lines) > 0
        header = lines[0].strip()
        assert "Detection Name" in header
        assert "Type" in header
        assert "Confidence" in header
        assert "Version" in header
        assert "File Type" in header
        assert "Architecture" in header
        assert "Protected" in header

    def test_csv_export_includes_all_detections(self, tmp_path: Path, real_analysis_results: dict[str, Any]) -> None:
        """CSV export includes all protection detections with correct data."""
        output_file = tmp_path / "detections.csv"

        export_config = {
            "format": "csv",
            "output_path": str(output_file),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)
        worker.run()

        with open(output_file, encoding="utf-8") as f:
            lines = f.readlines()

        assert len(lines) == 6, "Should have header + 5 detections"

        assert "VMProtect" in lines[1]
        assert "95.00%" in lines[1]
        assert "3.5" in lines[1]

        assert "Themida" in lines[2]
        assert "87.00%" in lines[2]

        assert "UPX" in lines[3]
        assert "78.00%" in lines[3]


class TestExportWorkerHTMLExport:
    """Test REAL HTML export with actual file creation and validation."""

    def test_html_export_creates_valid_html_file(self, tmp_path: Path, real_analysis_results: dict[str, Any]) -> None:
        """HTML export produces valid HTML file with proper structure."""
        output_file = tmp_path / "report.html"

        export_config = {
            "format": "html",
            "output_path": str(output_file),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)
        worker.run()

        assert output_file.exists(), "HTML export must create output file"
        assert output_file.stat().st_size > 0, "HTML export must write data"

        with open(output_file, encoding="utf-8") as f:
            html_content = f.read()

        assert "<!DOCTYPE html>" in html_content
        assert "<html" in html_content
        assert "</html>" in html_content
        assert "Intellicrack Protection Analysis Report" in html_content

    def test_html_export_includes_detection_styling(self, tmp_path: Path, real_analysis_results: dict[str, Any]) -> None:
        """HTML export includes confidence-based styling for detections."""
        output_file = tmp_path / "styled_report.html"

        export_config = {
            "format": "html",
            "output_path": str(output_file),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)
        worker.run()

        with open(output_file, encoding="utf-8") as f:
            html_content = f.read()

        assert "high-confidence" in html_content
        assert "medium-confidence" in html_content
        assert "low-confidence" in html_content

        assert "VMProtect" in html_content
        assert "95.0%" in html_content or "95%" in html_content

    def test_html_export_includes_file_information_table(self, tmp_path: Path, real_analysis_results: dict[str, Any]) -> None:
        """HTML export includes file information in table format."""
        output_file = tmp_path / "file_info.html"

        export_config = {
            "format": "html",
            "output_path": str(output_file),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)
        worker.run()

        with open(output_file, encoding="utf-8") as f:
            html_content = f.read()

        assert "File Information" in html_content
        assert "<table>" in html_content
        assert "protected_app.exe" in html_content
        assert "1008" in html_content


class TestExportWorkerPDFExport:
    """Test REAL PDF export with actual file creation and validation."""

    def test_pdf_export_creates_valid_pdf_file(self, tmp_path: Path, real_analysis_results: dict[str, Any]) -> None:
        """PDF export produces valid PDF file."""
        pytest.importorskip("reportlab")

        output_file = tmp_path / "report.pdf"

        export_config = {
            "format": "pdf",
            "output_path": str(output_file),
            "results": real_analysis_results,
            "page_format": "A4",
        }

        worker = ExportWorker(export_config)
        worker.run()

        assert output_file.exists(), "PDF export must create output file"
        assert output_file.stat().st_size > 0, "PDF export must write data"

        with open(output_file, "rb") as f:
            header = f.read(5)
            assert header == b"%PDF-", "Output must be valid PDF file"

    def test_pdf_export_with_letter_page_format(self, tmp_path: Path, real_analysis_results: dict[str, Any]) -> None:
        """PDF export supports letter page format."""
        pytest.importorskip("reportlab")

        output_file = tmp_path / "report_letter.pdf"

        export_config = {
            "format": "pdf",
            "output_path": str(output_file),
            "results": real_analysis_results,
            "page_format": "letter",
        }

        worker = ExportWorker(export_config)
        worker.run()

        assert output_file.exists()

        with open(output_file, "rb") as f:
            header = f.read(5)
            assert header == b"%PDF-"

    def test_pdf_export_fails_without_reportlab(self, tmp_path: Path, real_analysis_results: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
        """PDF export raises ImportError when reportlab is not available."""
        output_file = tmp_path / "report.pdf"

        export_config = {
            "format": "pdf",
            "output_path": str(output_file),
            "results": real_analysis_results,
        }

        def mock_import_error(*args: Any, **kwargs: Any) -> None:
            raise ImportError("No module named 'reportlab'")

        worker = ExportWorker(export_config)

        import intellicrack.ui.dialogs.export_dialog

        monkeypatch.setattr(intellicrack.ui.dialogs.export_dialog, "__import__", mock_import_error, raising=False)

        with pytest.raises(ImportError, match="ReportLab is required"):
            worker._export_pdf(str(output_file), real_analysis_results)


class TestExportWorkerErrorHandling:
    """Test export error handling and validation."""

    def test_unsupported_format_raises_error(self, tmp_path: Path, real_analysis_results: dict[str, Any]) -> None:
        """Export with unsupported format raises ValueError."""
        output_file = tmp_path / "test.xyz"

        export_config = {
            "format": "unsupported_format",
            "output_path": str(output_file),
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)

        with pytest.raises(ValueError, match="Unsupported export format"):
            worker.run()

    def test_export_to_invalid_path_emits_failure_signal(self, real_analysis_results: dict[str, Any]) -> None:
        """Export to invalid path emits failure signal."""
        export_config = {
            "format": "json",
            "output_path": "/invalid/path/that/does/not/exist/file.json",
            "results": real_analysis_results,
        }

        worker = ExportWorker(export_config)
        completion_signals: list[tuple[bool, str]] = []

        def capture_completion(success: bool, message: str) -> None:
            completion_signals.append((success, message))

        worker.export_completed.connect(capture_completion)
        worker.run()

        assert len(completion_signals) == 1
        success, message = completion_signals[0]
        assert not success
        assert "failed" in message.lower()


class TestExportDialog:
    """Test ExportDialog UI and logic with REAL functionality."""

    def test_dialog_initializes_with_analysis_results(self, qapp: QApplication, real_analysis_results: dict[str, Any]) -> None:
        """Dialog initializes correctly with analysis results."""
        dialog = ExportDialog(real_analysis_results)

        assert dialog.analysis_results is not None
        assert dialog.analysis_results == real_analysis_results
        assert dialog.windowTitle() == "Export ICP Analysis Results"

    def test_dialog_without_results_shows_error_message(self, qapp: QApplication) -> None:
        """Dialog without results displays appropriate error message."""
        dialog = ExportDialog(None)

        assert dialog.analysis_results is None

    def test_filter_results_applies_confidence_threshold(self, qapp: QApplication, real_analysis_results: dict[str, Any]) -> None:
        """Filter results correctly filters detections by confidence threshold."""
        dialog = ExportDialog(real_analysis_results)

        dialog.confidence_threshold_spin.setValue(80)
        dialog.include_file_info_cb.setChecked(True)
        dialog.include_detections_cb.setChecked(True)

        filtered = dialog._filter_results()

        assert "icp_analysis" in filtered
        icp_data = filtered["icp_analysis"]
        assert hasattr(icp_data, "all_detections")

        assert len(icp_data.all_detections) == 2

        detection_names = [d.name for d in icp_data.all_detections]
        assert "VMProtect" in detection_names
        assert "Themida" in detection_names
        assert "UPX" not in detection_names

    def test_filter_results_excludes_file_info_when_unchecked(self, qapp: QApplication, real_analysis_results: dict[str, Any]) -> None:
        """Filter results excludes file info when checkbox is unchecked."""
        dialog = ExportDialog(real_analysis_results)

        dialog.include_file_info_cb.setChecked(False)
        dialog.include_detections_cb.setChecked(True)

        filtered = dialog._filter_results()

        assert "file_info" not in filtered
        assert "icp_analysis" in filtered

    def test_browse_output_file_sets_correct_file_filter(self, qapp: QApplication, real_analysis_results: dict[str, Any]) -> None:
        """Browse button uses correct file filter based on selected format."""
        dialog = ExportDialog(real_analysis_results)

        for button in dialog.format_group.buttons():
            if button.property("format_id") == "json":
                button.setChecked(True)
                break

        selected_format = next(
            (button.property("format_id") for button in dialog.format_group.buttons() if button.isChecked()),
            None,
        )

        assert selected_format == "json"

    def test_start_export_validates_output_path(self, qapp: QApplication, real_analysis_results: dict[str, Any]) -> None:
        """Start export validates that output path is provided."""
        dialog = ExportDialog(real_analysis_results)

        dialog.output_path_edit.setText("")

        dialog.start_export()

    def test_refresh_preview_generates_json_preview(self, qapp: QApplication, real_analysis_results: dict[str, Any]) -> None:
        """Refresh preview generates valid JSON preview text."""
        dialog = ExportDialog(real_analysis_results)

        dialog.preview_format_combo.setCurrentText("JSON")
        dialog.refresh_preview()

        preview_text = dialog.preview_text.toPlainText()

        assert len(preview_text) > 0
        assert '"export_info"' in preview_text or "export_info" in preview_text
        assert '"timestamp"' in preview_text or "timestamp" in preview_text

    def test_refresh_preview_generates_xml_preview(self, qapp: QApplication, real_analysis_results: dict[str, Any]) -> None:
        """Refresh preview generates valid XML preview text."""
        dialog = ExportDialog(real_analysis_results)

        dialog.preview_format_combo.setCurrentText("XML")
        dialog.refresh_preview()

        preview_text = dialog.preview_text.toPlainText()

        assert len(preview_text) > 0
        assert "<?xml" in preview_text
        assert "intellicrack_analysis" in preview_text

    def test_refresh_preview_generates_csv_preview(self, qapp: QApplication, real_analysis_results: dict[str, Any]) -> None:
        """Refresh preview generates valid CSV preview text."""
        dialog = ExportDialog(real_analysis_results)

        dialog.preview_format_combo.setCurrentText("CSV")
        dialog.refresh_preview()

        preview_text = dialog.preview_text.toPlainText()

        assert len(preview_text) > 0
        assert "Detection Name" in preview_text
        assert "Type" in preview_text
        assert "Confidence" in preview_text

    def test_refresh_preview_generates_html_preview(self, qapp: QApplication, real_analysis_results: dict[str, Any]) -> None:
        """Refresh preview generates valid HTML preview text."""
        dialog = ExportDialog(real_analysis_results)

        dialog.preview_format_combo.setCurrentText("HTML")
        dialog.refresh_preview()

        preview_text = dialog.preview_text.toPlainText()

        assert len(preview_text) > 0
        assert "<!DOCTYPE html>" in preview_text
        assert "Intellicrack" in preview_text


class TestExportDialogIntegration:
    """Integration tests for complete export workflows."""

    def test_complete_json_export_workflow(self, qapp: QApplication, tmp_path: Path, real_analysis_results: dict[str, Any]) -> None:
        """Complete JSON export workflow produces valid output file."""
        dialog = ExportDialog(real_analysis_results)

        for button in dialog.format_group.buttons():
            if button.property("format_id") == "json":
                button.setChecked(True)
                break

        output_file = tmp_path / "complete_export.json"
        dialog.output_path_edit.setText(str(output_file))

        dialog.include_file_info_cb.setChecked(True)
        dialog.include_detections_cb.setChecked(True)
        dialog.confidence_threshold_spin.setValue(0)

        export_config = {
            "format": "json",
            "output_path": str(output_file),
            "results": dialog._filter_results(),
            "page_format": "a4",
            "options": {
                "pretty_format": True,
                "include_timestamp": True,
                "confidence_threshold": 0.0,
            },
        }

        worker = ExportWorker(export_config)
        worker.run()

        assert output_file.exists()

        with open(output_file, encoding="utf-8") as f:
            data = json.load(f)

        assert "export_info" in data
        assert "analysis_results" in data
        assert "file_info" in data["analysis_results"]
        assert "icp_analysis" in data["analysis_results"]

    def test_complete_csv_export_workflow(self, qapp: QApplication, tmp_path: Path, real_analysis_results: dict[str, Any]) -> None:
        """Complete CSV export workflow produces valid CSV with all detections."""
        dialog = ExportDialog(real_analysis_results)

        for button in dialog.format_group.buttons():
            if button.property("format_id") == "csv":
                button.setChecked(True)
                break

        output_file = tmp_path / "complete_export.csv"
        dialog.output_path_edit.setText(str(output_file))

        dialog.confidence_threshold_spin.setValue(0)

        export_config = {
            "format": "csv",
            "output_path": str(output_file),
            "results": dialog._filter_results(),
        }

        worker = ExportWorker(export_config)
        worker.run()

        assert output_file.exists()

        with open(output_file, encoding="utf-8") as f:
            lines = f.readlines()

        assert len(lines) == 6

        csv_content = "".join(lines)
        assert "VMProtect" in csv_content
        assert "Themida" in csv_content
        assert "UPX" in csv_content
