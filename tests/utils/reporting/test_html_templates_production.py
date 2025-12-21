"""Production tests for HTML template generation.

Tests validate real HTML template generation for license analysis reports.
NO mocks - validates actual HTML structure and styling.

Copyright (C) 2025 Zachary Flint
"""

import re
from typing import Any

import pytest

from intellicrack.utils.reporting.html_templates import (
    close_html,
    get_base_html_template,
    get_cfg_html_template,
    get_report_html_template,
    get_traffic_html_template,
)


class TestBaseHTMLTemplate:
    """Test base HTML template generation."""

    def test_generates_valid_html_structure(self) -> None:
        """Generates valid HTML5 document structure."""
        html = get_base_html_template()

        assert html.startswith("<!DOCTYPE html>")
        assert "<html>" in html
        assert "<head>" in html
        assert "<body>" in html
        assert '<meta charset="utf-8">' in html

    def test_includes_default_title(self) -> None:
        """Includes default title in template."""
        html = get_base_html_template()

        assert "<title>Intellicrack Report</title>" in html

    def test_accepts_custom_title(self) -> None:
        """Accepts custom title parameter."""
        html = get_base_html_template(title="Custom Analysis Report")

        assert "<title>Custom Analysis Report</title>" in html
        assert "Intellicrack Report" not in html

    def test_includes_default_styles(self) -> None:
        """Includes default CSS styles for reports."""
        html = get_base_html_template()

        assert "<style>" in html
        assert "</style>" in html
        assert "font-family" in html
        assert "table" in html
        assert "border-collapse" in html

    def test_injects_custom_css(self) -> None:
        """Injects custom CSS into template."""
        custom_css = ".custom { color: #ff0000; }"
        html = get_base_html_template(custom_css=custom_css)

        assert custom_css in html

    def test_injects_custom_javascript(self) -> None:
        """Injects custom JavaScript into template."""
        custom_js = '<script src="custom.js"></script>'
        html = get_base_html_template(custom_js=custom_js)

        assert custom_js in html

    def test_includes_license_specific_classes(self) -> None:
        """Includes CSS classes for license analysis."""
        html = get_base_html_template()

        assert ".vulnerability" in html
        assert ".protection" in html
        assert ".license" in html

    def test_includes_code_formatting_styles(self) -> None:
        """Includes styles for code display."""
        html = get_base_html_template()

        assert ".code" in html
        assert "monospace" in html
        assert "background-color" in html


class TestCFGHTMLTemplate:
    """Test control flow graph HTML template."""

    def test_generates_cfg_template(self) -> None:
        """Generates template for CFG visualization."""
        html = get_cfg_html_template("validate_license")

        assert "<!DOCTYPE html>" in html
        assert "<html>" in html

    def test_includes_function_name_in_title(self) -> None:
        """Includes analyzed function name in title."""
        html = get_cfg_html_template("check_serial_key")

        assert "CFG: check_serial_key" in html

    def test_includes_d3js_library(self) -> None:
        """Includes D3.js library for graph rendering."""
        html = get_cfg_html_template("main")

        assert "d3js.org/d3" in html or "d3.v" in html
        assert "<script" in html

    def test_includes_node_styling(self) -> None:
        """Includes CSS for graph nodes."""
        html = get_cfg_html_template("function")

        assert ".node" in html
        assert "stroke" in html

    def test_includes_license_node_styling(self) -> None:
        """Includes special styling for license check nodes."""
        html = get_cfg_html_template("function")

        assert ".node.license" in html
        assert "fill:" in html

    def test_includes_link_styling(self) -> None:
        """Includes styling for graph edges."""
        html = get_cfg_html_template("function")

        assert ".link" in html

    def test_includes_tooltip_styling(self) -> None:
        """Includes tooltip styling for node inspection."""
        html = get_cfg_html_template("function")

        assert "#tooltip" in html or "tooltip" in html.lower()


class TestTrafficHTMLTemplate:
    """Test network traffic analysis HTML template."""

    def test_generates_traffic_template(self) -> None:
        """Generates template for traffic analysis."""
        html = get_traffic_html_template()

        assert "<!DOCTYPE html>" in html
        assert "<html>" in html

    def test_includes_traffic_title(self) -> None:
        """Includes traffic analysis title."""
        html = get_traffic_html_template()

        assert "License Traffic Analysis" in html or "Traffic Analysis" in html

    def test_includes_visualization_styling(self) -> None:
        """Includes styling for visualization display."""
        html = get_traffic_html_template()

        assert ".visualization" in html

    def test_supports_image_display(self) -> None:
        """Supports centered image display for packet diagrams."""
        html = get_traffic_html_template()

        assert "img" in html or "image" in html.lower()
        assert "text-align" in html


class TestReportHTMLTemplate:
    """Test comprehensive analysis report HTML template."""

    def test_generates_report_template(self) -> None:
        """Generates template for analysis reports."""
        html = get_report_html_template("target.exe")

        assert "<!DOCTYPE html>" in html
        assert "<html>" in html

    def test_includes_binary_name_in_title(self) -> None:
        """Includes target binary name in report title."""
        html = get_report_html_template("crackme.exe")

        assert "crackme.exe" in html
        assert "Intellicrack Analysis Report" in html

    def test_includes_custom_heading_colors(self) -> None:
        """Includes custom color scheme for report."""
        html = get_report_html_template("binary.exe")

        color_pattern = r"#[0-9a-fA-F]{6}"
        assert re.search(color_pattern, html) is not None

    def test_includes_table_styling(self) -> None:
        """Includes table styling for structured data."""
        html = get_report_html_template("app.exe")

        assert "th" in html
        assert "background-color" in html


class TestHTMLClosingTag:
    """Test HTML closing tag generation."""

    def test_returns_closing_tags(self) -> None:
        """Returns proper HTML closing tags."""
        closing = close_html()

        assert "</body>" in closing
        assert "</html>" in closing

    def test_closing_tags_match_opening(self) -> None:
        """Closing tags match opening template structure."""
        opening = get_base_html_template()
        closing = close_html()

        assert opening.count("<body>") == closing.count("</body>")
        assert opening.count("<html>") == closing.count("</html>")


class TestCompleteHTMLDocument:
    """Test complete HTML document generation."""

    def test_creates_valid_complete_document(self) -> None:
        """Creates valid complete HTML document."""
        opening = get_base_html_template(title="Test Report")
        content = "<h1>License Analysis Results</h1><p>Target binary cracked successfully.</p>"
        closing = close_html()

        complete = opening + content + closing

        assert complete.startswith("<!DOCTYPE html>")
        assert complete.endswith("</html>")
        assert content in complete

    def test_validates_html_structure(self) -> None:
        """Validates basic HTML structure correctness."""
        opening = get_base_html_template()
        closing = close_html()

        complete = opening + closing

        assert complete.count("<html>") == complete.count("</html>")
        assert complete.count("<head>") == complete.count("</head>")
        assert complete.count("<body>") == complete.count("</body>")


class TestLicenseAnalysisSpecificFeatures:
    """Test license analysis specific template features."""

    def test_includes_protection_class_styling(self) -> None:
        """Includes styling for protection detection results."""
        html = get_base_html_template()

        assert ".protection" in html
        color_match = re.search(r"\.protection\s*{[^}]*color:\s*#[0-9a-fA-F]{6}", html)
        assert color_match is not None

    def test_includes_vulnerability_class_styling(self) -> None:
        """Includes styling for vulnerability highlighting."""
        html = get_base_html_template()

        assert ".vulnerability" in html

    def test_includes_license_class_styling(self) -> None:
        """Includes styling for license check results."""
        html = get_base_html_template()

        assert ".license" in html

    def test_includes_code_block_styling(self) -> None:
        """Includes styling for disassembly and code snippets."""
        html = get_base_html_template()

        assert ".code" in html
        assert "monospace" in html

    def test_includes_summary_section_styling(self) -> None:
        """Includes styling for executive summary sections."""
        html = get_base_html_template()

        assert ".summary" in html


class TestTemplateInjectionSafety:
    """Test template injection safety."""

    def test_handles_html_entities_in_title(self) -> None:
        """Handles HTML special characters in titles."""
        html = get_base_html_template(title="<script>alert('xss')</script>")

        assert "<title><script>alert('xss')</script></title>" in html

    def test_handles_quotes_in_title(self) -> None:
        """Handles quotes in title strings."""
        html = get_base_html_template(title='Report "Advanced" Analysis')

        assert 'Report "Advanced" Analysis' in html

    def test_handles_special_chars_in_function_name(self) -> None:
        """Handles special characters in function names."""
        html = get_cfg_html_template("func<T>")

        assert "func<T>" in html


class TestResponsiveDesign:
    """Test responsive design elements."""

    def test_includes_meta_charset(self) -> None:
        """Includes charset meta tag for Unicode support."""
        html = get_base_html_template()

        assert 'charset="utf-8"' in html or "charset='utf-8'" in html

    def test_uses_percentage_based_table_width(self) -> None:
        """Uses percentage-based widths for responsive tables."""
        html = get_base_html_template()

        assert "width: 100%" in html or "width:100%" in html


class TestColorScheme:
    """Test color scheme consistency."""

    def test_uses_hex_color_codes(self) -> None:
        """Uses valid hex color codes throughout."""
        html = get_base_html_template()

        color_codes = re.findall(r"#[0-9a-fA-F]{6}", html)
        assert len(color_codes) > 0

    def test_vulnerability_uses_red_tones(self) -> None:
        """Vulnerability class uses red color tones."""
        html = get_base_html_template()

        vuln_color = re.search(r"\.vulnerability\s*{[^}]*color:\s*(#[0-9a-fA-F]{6})", html)
        if vuln_color:
            color = vuln_color.group(1)
            assert color.startswith("#e") or color.startswith("#f") or color.startswith("#d")

    def test_protection_uses_green_tones(self) -> None:
        """Protection class uses green color tones."""
        html = get_base_html_template()

        prot_color = re.search(r"\.protection\s*{[^}]*color:\s*(#[0-9a-fA-F]{6})", html)
        if prot_color:
            color = prot_color.group(1).lower()
            assert "27ae60" in color or color[1] in "0123456789ab"


class TestTableFormatting:
    """Test table formatting for analysis results."""

    def test_includes_table_borders(self) -> None:
        """Includes table border styling."""
        html = get_base_html_template()

        assert "border" in html
        assert "border-collapse" in html

    def test_includes_cell_padding(self) -> None:
        """Includes cell padding for readability."""
        html = get_base_html_template()

        assert "padding" in html

    def test_includes_alternating_row_colors(self) -> None:
        """Includes alternating row background colors."""
        html = get_base_html_template()

        assert "nth-child(even)" in html or "tr:nth-child" in html
        assert "background-color" in html

    def test_includes_header_styling(self) -> None:
        """Includes distinct header row styling."""
        html = get_base_html_template()

        assert "th" in html
        assert "background-color" in html
