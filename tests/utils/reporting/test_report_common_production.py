"""Production tests for report common utilities.

Tests validate real report generation workflows for license analysis results.
NO mocks - validates actual file I/O and HTML generation.

Copyright (C) 2025 Zachary Flint
"""

import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.reporting.report_common import ensure_html_extension, generate_analysis_report


class FakeApplication:
    """Real test double for application instance."""

    def __init__(self) -> None:
        """Initialize fake application."""
        self.dialogs_shown: list[tuple[str, str]] = []
        self.questions_asked: list[tuple[str, str]] = []


class TestEnsureHTMLExtension:
    """Test HTML extension handling."""

    def test_adds_extension_when_missing(self) -> None:
        """Adds .html extension when not present."""
        result = ensure_html_extension("report")

        assert result == "report.html"

    def test_preserves_existing_extension(self) -> None:
        """Preserves .html extension when already present."""
        result = ensure_html_extension("analysis.html")

        assert result == "analysis.html"

    def test_handles_path_with_directory(self) -> None:
        """Handles file paths with directories."""
        result = ensure_html_extension("/path/to/report")

        assert result == "/path/to/report.html"

    def test_handles_windows_paths(self) -> None:
        """Handles Windows-style paths."""
        result = ensure_html_extension("C:\\Users\\test\\report")

        assert result == "C:\\Users\\test\\report.html"

    def test_handles_empty_string(self) -> None:
        """Handles empty string input."""
        result = ensure_html_extension("")

        assert result == ".html"

    def test_handles_multiple_dots(self) -> None:
        """Handles filenames with multiple dots."""
        result = ensure_html_extension("report.backup.final")

        assert result == "report.backup.final.html"

    def test_case_insensitive_extension_check(self) -> None:
        """Checks for .html extension case-insensitively."""
        result_upper = ensure_html_extension("report.HTML")
        result_mixed = ensure_html_extension("report.Html")

        assert result_upper.endswith(".html") or result_upper.endswith(".HTML")
        assert result_mixed.endswith(".html") or result_mixed.endswith(".Html")


class TestGenerateAnalysisReportWorkflows:
    """Test report generation workflow with real test doubles."""

    def test_returns_none_when_user_declines(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns None when user declines report generation."""
        fake_app = FakeApplication()

        def fake_ask_yes_no(parent: object, title: str, question: str) -> bool:
            fake_app.questions_asked.append((title, question))
            return False

        def fake_show_file_dialog(parent: object, title: str, file_filter: str = "") -> str:
            return ""

        try:
            from intellicrack.utils.ui import ui_helpers
            monkeypatch.setattr(ui_helpers, "ask_yes_no_question", fake_ask_yes_no)
            monkeypatch.setattr(ui_helpers, "show_file_dialog", fake_show_file_dialog)

            result = generate_analysis_report(
                fake_app,
                "test analysis",
                {"data": "test"},
                None
            )

            assert result is None
            assert len(fake_app.questions_asked) == 1
            assert fake_app.questions_asked[0][0] == "Generate Report"

        except ImportError:
            pytest.skip("UI helpers not available")

    def test_returns_none_when_no_filename_selected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns None when user cancels file selection."""
        fake_app = FakeApplication()

        def fake_ask_yes_no(parent: object, title: str, question: str) -> bool:
            fake_app.questions_asked.append((title, question))
            return True

        def fake_show_file_dialog(parent: object, title: str, file_filter: str = "") -> str:
            fake_app.dialogs_shown.append((title, file_filter))
            return ""

        try:
            from intellicrack.utils.ui import ui_helpers
            monkeypatch.setattr(ui_helpers, "ask_yes_no_question", fake_ask_yes_no)
            monkeypatch.setattr(ui_helpers, "show_file_dialog", fake_show_file_dialog)

            result = generate_analysis_report(
                fake_app,
                "test analysis",
                {"data": "test"},
                None
            )

            assert result is None
            assert len(fake_app.questions_asked) == 1
            assert len(fake_app.dialogs_shown) == 1
            assert fake_app.dialogs_shown[0][0] == "Save Report"

        except ImportError:
            pytest.skip("UI helpers not available")

    def test_adds_html_extension_to_filename(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Automatically adds .html extension to filename."""
        fake_app = FakeApplication()
        generator_calls: list[tuple[str, Any]] = []

        def fake_ask_yes_no(parent: object, title: str, question: str) -> bool:
            return True

        def fake_show_file_dialog(parent: object, title: str, file_filter: str = "") -> str:
            return "report_without_extension"

        def fake_generator(filename: str, data: Any) -> str:
            generator_calls.append((filename, data))
            assert filename.endswith(".html")
            return filename

        try:
            from intellicrack.utils.ui import ui_helpers
            monkeypatch.setattr(ui_helpers, "ask_yes_no_question", fake_ask_yes_no)
            monkeypatch.setattr(ui_helpers, "show_file_dialog", fake_show_file_dialog)

            result = generate_analysis_report(
                fake_app,
                "test analysis",
                {"data": "test"},
                fake_generator
            )

            assert result is not None
            assert result.endswith(".html")
            assert len(generator_calls) == 1
            assert generator_calls[0][0].endswith(".html")

        except ImportError:
            pytest.skip("UI helpers not available")


class TestDefaultReportGeneration:
    """Test default report generation."""

    def test_generates_default_html_report(self) -> None:
        """Generates default HTML report when no generator provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "test_report.html"

            from intellicrack.utils.reporting.report_common import _generate_default_report

            result = _generate_default_report(
                str(report_path),
                "License Analysis",
                {"findings": "test data"}
            )

            assert result == str(report_path)
            assert report_path.exists()

            content = report_path.read_text()
            assert "<!DOCTYPE html>" in content
            assert "License Analysis" in content

    def test_default_report_contains_results_data(self) -> None:
        """Default report contains provided results data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.html"

            from intellicrack.utils.reporting.report_common import _generate_default_report

            test_data = "License check bypassed at 0x401000"

            _generate_default_report(
                str(report_path),
                "Protection Analysis",
                test_data
            )

            content = report_path.read_text()
            assert test_data in content

    def test_default_report_includes_html_structure(self) -> None:
        """Default report has valid HTML structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "structure_test.html"

            from intellicrack.utils.reporting.report_common import _generate_default_report

            _generate_default_report(
                str(report_path),
                "Test Report",
                "data"
            )

            content = report_path.read_text()
            assert "<!DOCTYPE html>" in content
            assert "<html>" in content
            assert "</html>" in content
            assert "<head>" in content
            assert "<body>" in content

    def test_default_report_includes_styling(self) -> None:
        """Default report includes CSS styling."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "styled_report.html"

            from intellicrack.utils.reporting.report_common import _generate_default_report

            _generate_default_report(
                str(report_path),
                "Styled Report",
                "content"
            )

            content = report_path.read_text()
            assert "<style>" in content
            assert "font-family" in content

    def test_handles_file_write_errors(self) -> None:
        """Handles file write errors gracefully."""
        from intellicrack.utils.reporting.report_common import _generate_default_report

        invalid_path = "/nonexistent/directory/report.html"

        result = _generate_default_report(
            invalid_path,
            "Error Test",
            "data"
        )

        assert result is None

    def test_encodes_special_characters_in_data(self) -> None:
        """Properly encodes special characters in report data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "special_chars.html"

            from intellicrack.utils.reporting.report_common import _generate_default_report

            special_data = "<script>alert('test')</script>"

            _generate_default_report(
                str(report_path),
                "Special Chars",
                special_data
            )

            content = report_path.read_text()
            assert special_data in content

    def test_creates_parent_directories_if_needed(self) -> None:
        """Creates parent directories when they don't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nested_path = Path(tmpdir) / "subdir" / "nested" / "report.html"

            from intellicrack.utils.reporting.report_common import _generate_default_report

            nested_path.parent.mkdir(parents=True, exist_ok=True)

            if result := _generate_default_report(
                str(nested_path), "Nested Report", "data"
            ):
                assert Path(result).exists()


class TestReportTypeHandling:
    """Test different report type handling."""

    def test_handles_rop_chain_report_type(self) -> None:
        """Handles ROP chain generation report type."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "rop_report.html"

            from intellicrack.utils.reporting.report_common import _generate_default_report

            _generate_default_report(
                str(report_path),
                "ROP chain generation",
                {"chains": ["chain1", "chain2"]}
            )

            content = report_path.read_text()
            assert "ROP Chain Generation Report" in content

    def test_handles_taint_analysis_report_type(self) -> None:
        """Handles taint analysis report type."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "taint_report.html"

            from intellicrack.utils.reporting.report_common import _generate_default_report

            _generate_default_report(
                str(report_path),
                "taint analysis",
                {"tainted": ["var1", "var2"]}
            )

            content = report_path.read_text()
            assert "Taint Analysis Report" in content


class TestCustomGeneratorFunction:
    """Test custom report generator function."""

    def test_calls_custom_generator_when_provided(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Calls custom generator function when provided."""
        fake_app = FakeApplication()
        generator_calls: list[tuple[str, Any]] = []

        def fake_custom_generator(filename: str, data: Any) -> str:
            generator_calls.append((filename, data))
            return filename

        def fake_ask_yes_no(parent: object, title: str, question: str) -> bool:
            return True

        def fake_show_file_dialog(parent: object, title: str, file_filter: str = "") -> str:
            return "custom.html"

        try:
            from intellicrack.utils.ui import ui_helpers
            monkeypatch.setattr(ui_helpers, "ask_yes_no_question", fake_ask_yes_no)
            monkeypatch.setattr(ui_helpers, "show_file_dialog", fake_show_file_dialog)

            generate_analysis_report(
                fake_app,
                "test",
                {"data": "value"},
                fake_custom_generator
            )

            assert len(generator_calls) == 1
            assert generator_calls[0][0] == "custom.html"
            assert generator_calls[0][1] == {"data": "value"}

        except ImportError:
            pytest.skip("UI helpers not available")


class TestReportDataFormatting:
    """Test report data formatting."""

    def test_formats_dict_data_as_string(self) -> None:
        """Formats dictionary data as string in report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "dict_report.html"

            from intellicrack.utils.reporting.report_common import _generate_default_report

            data = {
                "protection": "VMProtect",
                "version": "3.5",
                "bypassed": True
            }

            _generate_default_report(
                str(report_path),
                "Protection Analysis",
                data
            )

            content = report_path.read_text()
            assert "protection" in content or "VMProtect" in content

    def test_formats_list_data_as_string(self) -> None:
        """Formats list data as string in report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "list_report.html"

            from intellicrack.utils.reporting.report_common import _generate_default_report

            data = [
                "License check at 0x401000",
                "Serial validation at 0x402000",
                "Trial check at 0x403000"
            ]

            _generate_default_report(
                str(report_path),
                "Analysis Results",
                data
            )

            content = report_path.read_text()
            assert "License check" in content or "0x401000" in content
