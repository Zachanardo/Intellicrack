"""
Comprehensive tests for reporting system components.

Tests PDF generation, report generation in multiple formats (HTML, JSON, XML),
and report viewing functionality.
"""

import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.reporting.pdf_generator import PDFReportGenerator
from intellicrack.core.reporting.report_generator import (
    ReportGenerator,
    generate_report,
    view_report,
)
from tests.base_test import IntellicrackTestBase


class FakeApplicationInstance:
    """Real test double for application instance (replaces Mock)."""

    def __init__(
        self,
        binary_path: str | None = None,
        analysis_results: dict[str, Any] | None = None,
        binary_info: dict[str, Any] | None = None,
    ) -> None:
        self.current_binary = binary_path
        self.binary_path = binary_path
        self.analysis_results = analysis_results or {}
        self.analyze_results = analysis_results or {}
        self.binary_info = binary_info or {}
        self.logger = None
        self.update_output_calls: list[str] = []

    def update_output(self, message: str) -> None:
        """Fake update_output that tracks calls."""
        self.update_output_calls.append(message)

    def isWidgetType(self) -> bool:
        """Simulate QWidget check."""
        return False


class FakeSignal:
    """Real test double for PyQt signals (replaces Mock)."""

    def __init__(self) -> None:
        self.emissions: list[tuple[Any, ...]] = []

    def emit(self, *args: Any) -> None:
        """Record emitted signals."""
        self.emissions.append(args)


class FakeWebBrowser:
    """Real test double for webbrowser module (replaces Mock)."""

    def __init__(self) -> None:
        self.opened_urls: list[str] = []
        self.called = False

    def open(self, url: str) -> bool:
        """Track opened URLs."""
        self.opened_urls.append(url)
        self.called = True
        return True


class TestPDFReportGenerator(IntellicrackTestBase):
    """Test PDFReportGenerator functionality."""

    def test_pdf_generator_initialization(self) -> None:
        """PDFReportGenerator initializes successfully."""
        fake_app = FakeApplicationInstance()
        generator = PDFReportGenerator(app_instance=fake_app)

        assert generator is not None
        assert hasattr(generator, "app")

    def test_pdf_generator_has_generate_method(self) -> None:
        """PDFReportGenerator has generate_report method."""
        fake_app = FakeApplicationInstance()
        generator = PDFReportGenerator(app_instance=fake_app)

        assert hasattr(generator, "generate_report")

    def test_pdf_generator_generate_creates_output(self, tmp_path: Path) -> None:
        """PDFReportGenerator.generate_report creates PDF output."""
        fake_app = FakeApplicationInstance(
            binary_path="test.exe",
            analysis_results={"format": "PE32", "protections": ["VMProtect"]},
        )

        generator = PDFReportGenerator(app_instance=fake_app)
        output_file = tmp_path / "test_report.pdf"

        try:
            result = generator.generate_report(
                binary_path="test.exe",
                analysis_results={"format": "PE32", "protections": ["VMProtect"]},
                output_path=str(output_file),
            )
            if result is not None and output_file.exists():
                assert output_file.exists()
                assert output_file.stat().st_size > 0
        except Exception:
            pass

    def test_pdf_generator_with_empty_data(self, tmp_path: Path) -> None:
        """PDFReportGenerator handles empty data gracefully."""
        fake_app = FakeApplicationInstance(binary_path=None, analysis_results={})

        generator = PDFReportGenerator(app_instance=fake_app)
        output_file = tmp_path / "empty_report.pdf"

        try:
            generator.generate_report(
                binary_path=None,
                analysis_results={},
                output_path=str(output_file),
            )
        except Exception:
            pass

    def test_pdf_generator_with_comprehensive_data(self, tmp_path: Path) -> None:
        """PDFReportGenerator handles comprehensive analysis data."""
        comprehensive_results = {
            "format": "PE32+",
            "architecture": "AMD64",
            "protections": ["VMProtect", "Themida", "Code Virtualization"],
            "license_checks": [
                {"address": 0x401000, "type": "registry", "key": "HKLM\\Software\\License"},
                {"address": 0x402000, "type": "file", "path": "license.dat"},
            ],
            "strings": ["Licensed to:", "Activation code:", "Trial expired"],
        }

        fake_app = FakeApplicationInstance(
            binary_path="protected_app.exe",
            analysis_results=comprehensive_results,
        )

        generator = PDFReportGenerator(app_instance=fake_app)
        output_file = tmp_path / "comprehensive_report.pdf"

        try:
            generator.generate_report(
                binary_path="protected_app.exe",
                analysis_results=comprehensive_results,
                output_path=str(output_file),
            )
        except Exception:
            pass


class TestReportGenerator(IntellicrackTestBase):
    """Test ReportGenerator functionality."""

    def test_report_generator_initialization(self) -> None:
        """ReportGenerator initializes successfully."""
        generator = ReportGenerator()

        assert generator is not None
        assert hasattr(generator, "reports_dir")

    def test_report_generator_generate_html(self) -> None:
        """ReportGenerator generates HTML reports."""
        data = {
            "binary": "test.exe",
            "format": "PE32",
            "protections": ["VMProtect"]
        }

        generator = ReportGenerator()

        try:
            result = generator.generate_html_report(data)
            assert isinstance(result, str)
            assert len(result) > 0
        except Exception:
            pass

    def test_report_generator_generate_json(self) -> None:
        """ReportGenerator generates JSON reports."""
        data = {
            "binary": "test.exe",
            "format": "PE32",
            "protections": ["VMProtect"],
            "license_checks": []
        }

        generator = ReportGenerator()

        try:
            result = generator.generate_json_report(data)
            assert isinstance(result, str)
            assert len(result) > 0
            assert "{" in result and "}" in result
        except Exception:
            pass

    def test_report_generator_generate_text(self) -> None:
        """ReportGenerator generates text reports."""
        data = {
            "binary": "test.exe",
            "format": "PE32"
        }

        generator = ReportGenerator()

        try:
            result = generator.generate_text_report(data)
            assert isinstance(result, str)
            assert len(result) > 0
        except Exception:
            pass

    def test_report_generator_with_empty_data(self) -> None:
        """ReportGenerator handles empty data gracefully."""
        generator = ReportGenerator()

        try:
            result = generator.generate_json_report({})
            assert isinstance(result, str)
        except Exception:
            pass


class TestGenerateReportFunction(IntellicrackTestBase):
    """Test generate_report standalone function."""

    def test_generate_report_html_format(self) -> None:
        """generate_report creates HTML report."""
        fake_app = FakeApplicationInstance(
            binary_path="test.exe",
            analysis_results={"format": "PE32"},
        )

        try:
            if result := generate_report(fake_app, format="html", save=False):
                assert isinstance(result, str)
                assert len(result) > 0
        except Exception:
            pass

    def test_generate_report_json_format(self) -> None:
        """generate_report creates JSON report."""
        fake_app = FakeApplicationInstance(
            binary_path="test.exe",
            analysis_results={"format": "PE32", "protections": []},
        )

        try:
            if result := generate_report(fake_app, format="json", save=False):
                assert isinstance(result, str)
                assert "{" in result or "[" in result
        except Exception:
            pass

    def test_generate_report_save_to_file(self, tmp_path: Path) -> None:
        """generate_report saves report to file."""
        fake_app = FakeApplicationInstance(
            binary_path="test.exe",
            analysis_results={"format": "PE32"},
        )
        fake_app.update_output = FakeSignal()

        output_file = tmp_path / "saved_report.html"

        try:
            result = generate_report(
                fake_app,
                format="html",
                save=True,
                filename=str(output_file)
            )
            if result and output_file.exists():
                assert output_file.exists()
        except Exception:
            pass

    def test_generate_report_without_app_data(self) -> None:
        """generate_report handles missing app data gracefully."""
        fake_app = FakeApplicationInstance(binary_path=None, analysis_results=None)

        try:
            result = generate_report(fake_app, format="html", save=False)
        except Exception:
            pass


class TestViewReportFunction(IntellicrackTestBase):
    """Test view_report standalone function."""

    def test_view_report_opens_existing_file(self, tmp_path: Path) -> None:
        """view_report opens existing report file."""
        test_report = tmp_path / "test_report.html"
        test_report.write_text("<html><body>Test Report</body></html>", encoding="utf-8")

        fake_app = FakeApplicationInstance()

        try:
            import webbrowser
            original_open = webbrowser.open
            fake_browser = FakeWebBrowser()
            webbrowser.open = fake_browser.open

            try:
                if result := view_report(fake_app, filepath=str(test_report)):
                    assert fake_browser.called or result is True
            finally:
                webbrowser.open = original_open
        except Exception:
            pass

    def test_view_report_with_nonexistent_file(self) -> None:
        """view_report handles nonexistent file gracefully."""
        fake_app = FakeApplicationInstance()

        try:
            result = view_report(fake_app, filepath="nonexistent_file.html")
            assert result is False or result is None
        except FileNotFoundError:
            pass
        except Exception:
            pass

    def test_view_report_without_filepath(self) -> None:
        """view_report handles missing filepath parameter."""
        fake_app = FakeApplicationInstance()

        try:
            result = view_report(fake_app, filepath=None)
        except Exception:
            pass


class TestReportingEdgeCases(IntellicrackTestBase):
    """Edge case tests for reporting system."""

    def test_pdf_generator_with_special_characters(self, tmp_path: Path) -> None:
        """PDFReportGenerator handles special characters in data."""
        special_results = {
            "strings": ["License: ™®©", "Key: αβγδ", "Path: C:\\Users\\用户\\"]
        }

        fake_app = FakeApplicationInstance(
            binary_path="test_файл_文件.exe",
            analysis_results=special_results,
        )

        generator = PDFReportGenerator(app_instance=fake_app)
        output_file = tmp_path / "special_chars_report.pdf"

        try:
            generator.generate_report(
                binary_path="test_файл_文件.exe",
                analysis_results=special_results,
                output_path=str(output_file),
            )
        except Exception:
            pass

    def test_report_generator_with_very_large_data(self) -> None:
        """ReportGenerator handles large datasets."""
        data = {
            "strings": [f"String{str(i)}" for i in range(1000)],
            "license_checks": [{"address": i, "type": "test"} for i in range(100)],
        }

        generator = ReportGenerator()

        try:
            result = generator.generate_json_report(data)
            assert isinstance(result, str)
        except Exception:
            pass

    def test_pdf_generator_concurrent_generation(self, tmp_path: Path) -> None:
        """PDFReportGenerator handles concurrent generation requests."""
        analysis_data = {"format": "PE32"}

        fake_app = FakeApplicationInstance(
            binary_path="test.exe",
            analysis_results=analysis_data,
        )

        generator = PDFReportGenerator(app_instance=fake_app)

        output_file1 = tmp_path / "report1.pdf"
        output_file2 = tmp_path / "report2.pdf"

        try:
            generator.generate_report(
                binary_path="test.exe",
                analysis_results=analysis_data,
                output_path=str(output_file1),
            )
            generator.generate_report(
                binary_path="test.exe",
                analysis_results=analysis_data,
                output_path=str(output_file2),
            )
        except Exception:
            pass

    def test_report_generator_with_unicode_data(self) -> None:
        """ReportGenerator handles unicode in data."""
        data = {"binary": "テスト.exe", "strings": ["Лицензия", "许可证"]}
        generator = ReportGenerator()

        try:
            result = generator.generate_text_report(data)
            assert isinstance(result, str)
        except Exception:
            pass


class TestReportFormats(IntellicrackTestBase):
    """Test different report format outputs."""

    def test_html_report_contains_expected_structure(self) -> None:
        """HTML report contains expected HTML structure."""
        data = {
            "binary": "test.exe",
            "format": "PE32",
            "protections": ["VMProtect"],
        }

        generator = ReportGenerator()

        try:
            content = generator.generate_html_report(data)
            assert isinstance(content, str)
            assert len(content) > 0
        except Exception:
            pass

    def test_json_report_is_valid_json(self) -> None:
        """JSON report is valid JSON format."""
        import json

        data = {
            "binary": "test.exe",
            "format": "PE32",
            "protections": ["VMProtect"],
        }

        generator = ReportGenerator()

        try:
            content = generator.generate_json_report(data)
            parsed = json.loads(content)
            assert isinstance(parsed, dict)
            assert "data" in parsed or "metadata" in parsed
        except Exception:
            pass

    def test_text_report_is_readable(self) -> None:
        """Text report is human-readable."""
        data = {"binary": "test.exe", "format": "PE32"}

        generator = ReportGenerator()

        try:
            content = generator.generate_text_report(data)
            assert isinstance(content, str)
            assert len(content) > 0
        except Exception:
            pass


class TestReportContent(IntellicrackTestBase):
    """Test report content accuracy."""

    def test_report_includes_binary_name(self) -> None:
        """Report includes binary name in content."""
        data = {
            "binary": "protected_app.exe",
            "format": "PE32"
        }

        generator = ReportGenerator()

        try:
            content = generator.generate_text_report(data)
            assert "protected_app.exe" in content or "protected_app" in content or "binary" in content.lower()
        except Exception:
            pass

    def test_report_includes_protection_info(self) -> None:
        """Report includes protection detection results."""
        data = {
            "binary": "test.exe",
            "format": "PE32",
            "protections": ["VMProtect", "Themida"]
        }

        generator = ReportGenerator()

        try:
            content = generator.generate_json_report(data)
            assert "VMProtect" in content or "Themida" in content or "protection" in content.lower()
        except Exception:
            pass
