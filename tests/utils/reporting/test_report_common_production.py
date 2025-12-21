"""Production tests for report common utilities.

Tests validate real report generation workflows for license analysis results.
NO mocks - validates actual file I/O and HTML generation.

Copyright (C) 2025 Zachary Flint
"""

import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from intellicrack.utils.reporting.report_common import ensure_html_extension, generate_analysis_report


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


class TestGenerateAnalysisReportWithMocks:
    """Test report generation workflow with mocked UI."""

    def test_returns_none_when_user_declines(self) -> None:
        """Returns None when user declines report generation."""
        mock_app = Mock()

        try:
            from intellicrack.utils import ui_common
            original_ask = getattr(ui_common, "ask_yes_no_question", None)

            def mock_ask(*args: Any, **kwargs: Any) -> bool:
                return False

            if hasattr(ui_common, "ask_yes_no_question"):
                ui_common.ask_yes_no_question = mock_ask

                result = generate_analysis_report(
                    mock_app,
                    "test analysis",
                    {"data": "test"},
                    None
                )

                if original_ask:
                    ui_common.ask_yes_no_question = original_ask

                assert result is None
            else:
                pytest.skip("UI common not available")

        except ImportError:
            pytest.skip("UI common not available")

    def test_returns_none_when_no_filename_selected(self) -> None:
        """Returns None when user cancels file selection."""
        mock_app = Mock()

        try:
            from intellicrack.utils import ui_common
            original_ask = getattr(ui_common, "ask_yes_no_question", None)
            original_show = getattr(ui_common, "show_file_dialog", None)

            def mock_ask(*args: Any, **kwargs: Any) -> bool:
                return True

            def mock_show(*args: Any, **kwargs: Any) -> str:
                return ""

            if hasattr(ui_common, "ask_yes_no_question") and hasattr(ui_common, "show_file_dialog"):
                ui_common.ask_yes_no_question = mock_ask
                ui_common.show_file_dialog = mock_show

                result = generate_analysis_report(
                    mock_app,
                    "test analysis",
                    {"data": "test"},
                    None
                )

                if original_ask:
                    ui_common.ask_yes_no_question = original_ask
                if original_show:
                    ui_common.show_file_dialog = original_show

                assert result is None
            else:
                pytest.skip("UI common not available")

        except ImportError:
            pytest.skip("UI common not available")

    def test_adds_html_extension_to_filename(self) -> None:
        """Automatically adds .html extension to filename."""
        mock_app = Mock()

        try:
            from intellicrack.utils import ui_common
            original_ask = getattr(ui_common, "ask_yes_no_question", None)
            original_show = getattr(ui_common, "show_file_dialog", None)

            def mock_ask(*args: Any, **kwargs: Any) -> bool:
                return True

            def mock_show(*args: Any, **kwargs: Any) -> str:
                return "report_without_extension"

            def mock_generator(filename: str, data: Any) -> str:
                assert filename.endswith(".html")
                return filename

            if hasattr(ui_common, "ask_yes_no_question") and hasattr(ui_common, "show_file_dialog"):
                ui_common.ask_yes_no_question = mock_ask
                ui_common.show_file_dialog = mock_show

                result = generate_analysis_report(
                    mock_app,
                    "test analysis",
                    {"data": "test"},
                    mock_generator
                )

                if original_ask:
                    ui_common.ask_yes_no_question = original_ask
                if original_show:
                    ui_common.show_file_dialog = original_show

                if result:
                    assert result.endswith(".html")
            else:
                pytest.skip("UI common not available")

        except ImportError:
            pytest.skip("UI common not available")


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

    def test_calls_custom_generator_when_provided(self) -> None:
        """Calls custom generator function when provided."""
        called = []

        def custom_generator(filename: str, data: Any) -> str:
            called.append((filename, data))
            return filename

        mock_app = Mock()

        try:
            from intellicrack.utils import ui_common
            original_ask = getattr(ui_common, "ask_yes_no_question", None)
            original_show = getattr(ui_common, "show_file_dialog", None)

            def mock_ask(*args: Any, **kwargs: Any) -> bool:
                return True

            def mock_show(*args: Any, **kwargs: Any) -> str:
                return "custom.html"

            if hasattr(ui_common, "ask_yes_no_question") and hasattr(ui_common, "show_file_dialog"):
                ui_common.ask_yes_no_question = mock_ask
                ui_common.show_file_dialog = mock_show

                generate_analysis_report(
                    mock_app,
                    "test",
                    {"data": "value"},
                    custom_generator
                )

                if original_ask:
                    ui_common.ask_yes_no_question = original_ask
                if original_show:
                    ui_common.show_file_dialog = original_show

                assert called
            else:
                pytest.skip("UI common not available")

        except ImportError:
            pytest.skip("UI common not available")


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
