"""Production tests for AI parsing utilities.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import re
from typing import Any

import pytest

from intellicrack.ai.parsing_utils import ResponseLineParser


class TestParseLinesBySections:
    """Test section-based line parsing."""

    def test_parse_lines_basic_sections(self) -> None:
        """Parser correctly groups lines into sections."""
        response = """
        Findings:
        Critical vulnerability at 0x401000
        Weak encryption detected

        Recommendations:
        Use stronger algorithms
        Add integrity checks
        """

        section_keywords = {
            "findings": ["findings", "vulnerability"],
            "recommendations": ["recommendations"],
        }

        result = ResponseLineParser.parse_lines_by_sections(response, section_keywords)

        assert len(result["findings"]) > 0
        assert len(result["recommendations"]) > 0
        assert any("0x401000" in line for line in result["findings"])
        assert any("algorithms" in line for line in result["recommendations"])

    def test_parse_lines_with_processor(self) -> None:
        """Parser applies line processor function correctly."""
        response = """
        Vulnerabilities:
        - License bypass at offset 0x1234
        - Weak serial validation
        """

        section_keywords = {"vulnerabilities": ["vulnerabilities"]}

        def remove_dash(line: str, section: str) -> str | None:
            """Remove leading dash from lines."""
            if line.startswith("-"):
                return line[1:].strip()
            return line

        result = ResponseLineParser.parse_lines_by_sections(
            response,
            section_keywords,
            line_processor=remove_dash,
        )

        assert len(result["vulnerabilities"]) > 0
        assert all(not line.startswith("-") for line in result["vulnerabilities"])
        assert any("License bypass" in line for line in result["vulnerabilities"])

    def test_parse_lines_processor_returns_none(self) -> None:
        """Parser skips lines when processor returns None."""
        response = """
        Results:
        Important finding
        [DEBUG] Ignore this line
        Another important finding
        [INFO] Also ignore
        """

        section_keywords = {"results": ["results"]}

        def filter_debug_lines(line: str, section: str) -> str | None:
            """Filter out debug/info lines."""
            if line.startswith("[DEBUG]") or line.startswith("[INFO]"):
                return None
            return line

        result = ResponseLineParser.parse_lines_by_sections(
            response,
            section_keywords,
            line_processor=filter_debug_lines,
        )

        assert len(result["results"]) == 2
        assert all("[DEBUG]" not in line and "[INFO]" not in line for line in result["results"])

    def test_parse_lines_multiple_sections(self) -> None:
        """Parser handles multiple sections in single response."""
        response = """
        Vulnerabilities:
        Buffer overflow at 0x2000
        Integer overflow at 0x3000

        Mitigations:
        Add bounds checking
        Use safe integer operations

        Attack Vectors:
        Craft malicious license file
        Bypass validation routine
        """

        section_keywords = {
            "vulnerabilities": ["vulnerabilities"],
            "mitigations": ["mitigations"],
            "attack_vectors": ["attack vectors"],
        }

        result = ResponseLineParser.parse_lines_by_sections(response, section_keywords)

        assert len(result["vulnerabilities"]) == 2
        assert len(result["mitigations"]) == 2
        assert len(result["attack_vectors"]) == 2

    def test_parse_lines_ignores_blank_lines(self) -> None:
        """Parser correctly ignores blank lines."""
        response = """
        Section:

        Content line 1


        Content line 2

        """

        section_keywords = {"section": ["section"]}

        result = ResponseLineParser.parse_lines_by_sections(response, section_keywords)

        assert len(result["section"]) == 2
        assert "Content line 1" in result["section"]
        assert "Content line 2" in result["section"]

    def test_parse_lines_without_section_context(self) -> None:
        """Parser handles lines before first section marker."""
        response = """
        Orphaned line before section
        Another orphaned line

        Section:
        Proper section content
        """

        section_keywords = {"section": ["section"]}

        result = ResponseLineParser.parse_lines_by_sections(response, section_keywords)

        assert len(result["section"]) == 1
        assert "Proper section content" in result["section"]


class TestParseLinesWithCategorization:
    """Test categorization-based line parsing."""

    def test_categorize_lines_basic(self) -> None:
        """Parser categorizes lines based on keywords."""
        response = """
        Critical vulnerability in license check
        Warning about weak encryption
        Error in serial validation
        Info about trial period
        """

        category_keywords = {
            "critical": ["critical"],
            "warnings": ["warning"],
            "errors": ["error"],
            "info": ["info"],
        }

        result = ResponseLineParser.parse_lines_with_categorization(response, category_keywords)

        assert len(result["critical"]) == 1
        assert len(result["warnings"]) == 1
        assert len(result["errors"]) == 1
        assert len(result["info"]) == 1

    def test_categorize_lines_with_default_category(self) -> None:
        """Parser uses default category for unmatched lines."""
        response = """
        Matched line with keyword vulnerability
        Unmatched line without keywords
        Another unmatched line
        """

        category_keywords = {"matched": ["vulnerability"]}

        result = ResponseLineParser.parse_lines_with_categorization(
            response,
            category_keywords,
            default_category="unmatched",
        )

        assert len(result["matched"]) == 1
        assert len(result["unmatched"]) == 2

    def test_categorize_lines_case_insensitive(self) -> None:
        """Parser performs case-insensitive categorization."""
        response = """
        CRITICAL ERROR IN LICENSE
        critical warning detected
        CrItIcAl issue found
        """

        category_keywords = {"critical": ["critical"]}

        result = ResponseLineParser.parse_lines_with_categorization(response, category_keywords)

        assert len(result["critical"]) == 3

    def test_categorize_lines_first_match_wins(self) -> None:
        """Parser assigns line to first matching category."""
        response = """
        Error vulnerability in license validation
        """

        category_keywords = {
            "errors": ["error"],
            "vulnerabilities": ["vulnerability"],
        }

        result = ResponseLineParser.parse_lines_with_categorization(response, category_keywords)

        assert len(result["errors"]) == 1
        assert len(result["vulnerabilities"]) == 0

    def test_categorize_lines_empty_response(self) -> None:
        """Parser handles empty response."""
        response = ""

        category_keywords = {"test": ["test"]}

        result = ResponseLineParser.parse_lines_with_categorization(response, category_keywords)

        assert result["test"] == []


class TestExtractStructuredContent:
    """Test structured content extraction using regex."""

    def test_extract_with_simple_patterns(self) -> None:
        """Parser extracts content matching regex patterns."""
        response = """
        Address: 0x401234
        Offset: 0x5678
        Function at 0xABCD
        """

        patterns = [r"0x[0-9A-Fa-f]+"]

        result = ResponseLineParser.extract_structured_content(response, patterns)

        assert len(result) == 3
        assert all("match" in item for item in result)
        assert all(re.match(r"0x[0-9A-Fa-f]+", item["match"]) for item in result)

    def test_extract_with_capturing_groups(self) -> None:
        """Parser captures regex groups correctly."""
        response = """
        License: ABC-123-DEF
        Serial: XYZ-456-GHI
        """

        patterns = [r"([A-Z]{3})-(\d{3})-([A-Z]{3})"]

        result = ResponseLineParser.extract_structured_content(response, patterns)

        assert len(result) == 2
        assert all(len(item["groups"]) == 3 for item in result)
        assert result[0]["groups"][0] == "ABC"
        assert result[0]["groups"][1] == "123"

    def test_extract_with_section_separators(self) -> None:
        """Parser tracks sections using separators."""
        response = """
        ## Vulnerabilities
        Critical issue at 0x1000

        ## Recommendations
        Fix buffer overflow at 0x2000
        """

        patterns = [r"0x[0-9A-Fa-f]+"]
        section_separators = [r"##\s+\w+"]

        result = ResponseLineParser.extract_structured_content(
            response,
            patterns,
            section_separators,
        )

        assert len(result) == 2
        assert any("Vulnerabilities" in item["section"] for item in result)
        assert any("Recommendations" in item["section"] for item in result)

    def test_extract_with_multiple_patterns(self) -> None:
        """Parser matches multiple different patterns."""
        response = """
        Memory address: 0x401000
        Email: admin@example.com
        Version: 1.2.3
        """

        patterns = [
            r"0x[0-9A-Fa-f]+",
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            r"\d+\.\d+\.\d+",
        ]

        result = ResponseLineParser.extract_structured_content(response, patterns)

        assert len(result) == 3
        assert any(item["pattern_index"] == 0 for item in result)
        assert any(item["pattern_index"] == 1 for item in result)
        assert any(item["pattern_index"] == 2 for item in result)

    def test_extract_empty_response(self) -> None:
        """Parser handles empty response."""
        response = ""
        patterns = [r"test"]

        result = ResponseLineParser.extract_structured_content(response, patterns)

        assert result == []

    def test_extract_no_matches(self) -> None:
        """Parser returns empty list when no patterns match."""
        response = """
        Some text without patterns
        More text here
        """

        patterns = [r"0x[0-9A-Fa-f]+"]

        result = ResponseLineParser.extract_structured_content(response, patterns)

        assert result == []


class TestCleanAndFilterLines:
    """Test line cleaning and filtering."""

    def test_clean_basic_filtering(self) -> None:
        """Cleaner removes short lines and blank lines."""
        lines = [
            "This is a valid line",
            "OK",
            "",
            "Another valid line",
            "  ",
            "X",
        ]

        result = ResponseLineParser.clean_and_filter_lines(lines, min_length=3)

        assert len(result) == 2
        assert "This is a valid line" in result
        assert "Another valid line" in result

    def test_clean_with_filter_patterns(self) -> None:
        """Cleaner filters lines matching regex patterns."""
        lines = [
            "Important finding",
            "[DEBUG] Debug message",
            "Critical vulnerability",
            "[INFO] Info message",
            "Security issue",
        ]

        filter_patterns = [r"\[DEBUG\]", r"\[INFO\]"]

        result = ResponseLineParser.clean_and_filter_lines(
            lines,
            min_length=3,
            filter_patterns=filter_patterns,
        )

        assert len(result) == 3
        assert "Important finding" in result
        assert "Critical vulnerability" in result
        assert "Security issue" in result

    def test_clean_strips_whitespace(self) -> None:
        """Cleaner strips leading and trailing whitespace."""
        lines = [
            "  Line with leading spaces",
            "Line with trailing spaces  ",
            "   Line with both   ",
        ]

        result = ResponseLineParser.clean_and_filter_lines(lines)

        assert "Line with leading spaces" in result
        assert "Line with trailing spaces" in result
        assert "Line with both" in result
        assert all(line == line.strip() for line in result)

    def test_clean_custom_min_length(self) -> None:
        """Cleaner respects custom minimum length."""
        lines = [
            "A",
            "AB",
            "ABC",
            "ABCD",
            "ABCDE",
        ]

        result = ResponseLineParser.clean_and_filter_lines(lines, min_length=4)

        assert len(result) == 2
        assert "ABCD" in result
        assert "ABCDE" in result

    def test_clean_with_complex_filter_patterns(self) -> None:
        """Cleaner handles complex regex patterns."""
        lines = [
            "Valid line",
            "Line with http://example.com",
            "Another valid line",
            "Line with https://test.org",
            "Final valid line",
        ]

        filter_patterns = [r"https?://\S+"]

        result = ResponseLineParser.clean_and_filter_lines(
            lines,
            filter_patterns=filter_patterns,
        )

        assert len(result) == 3
        assert "Valid line" in result
        assert "Another valid line" in result
        assert "Final valid line" in result

    def test_clean_empty_list(self) -> None:
        """Cleaner handles empty line list."""
        lines: list[str] = []

        result = ResponseLineParser.clean_and_filter_lines(lines)

        assert result == []

    def test_clean_no_filter_patterns(self) -> None:
        """Cleaner works without filter patterns."""
        lines = [
            "Line one",
            "Line two",
            "",
            "Line three",
        ]

        result = ResponseLineParser.clean_and_filter_lines(lines, filter_patterns=None)

        assert len(result) == 3


class TestDetectSection:
    """Test section detection helper."""

    def test_detect_section_exact_match(self) -> None:
        """Section detector finds exact keyword matches."""
        line = "Vulnerabilities section"
        section_keywords = {
            "vulnerabilities": ["vulnerabilities"],
            "recommendations": ["recommendations"],
        }

        result = ResponseLineParser._detect_section(line, section_keywords)

        assert result == "vulnerabilities"

    def test_detect_section_partial_match(self) -> None:
        """Section detector finds partial keyword matches."""
        line = "Found vulnerability in code"
        section_keywords = {"vulnerabilities": ["vulnerability", "vuln"]}

        result = ResponseLineParser._detect_section(line, section_keywords)

        assert result == "vulnerabilities"

    def test_detect_section_case_insensitive(self) -> None:
        """Section detector performs case-insensitive matching."""
        line = "RECOMMENDATIONS FOR MITIGATION"
        section_keywords = {"recommendations": ["recommendations"]}

        result = ResponseLineParser._detect_section(line, section_keywords)

        assert result == "recommendations"

    def test_detect_section_no_match(self) -> None:
        """Section detector returns None when no match found."""
        line = "Random text without keywords"
        section_keywords = {
            "vulnerabilities": ["vulnerability"],
            "recommendations": ["recommendation"],
        }

        result = ResponseLineParser._detect_section(line, section_keywords)

        assert result is None

    def test_detect_section_first_match_wins(self) -> None:
        """Section detector returns first matching section."""
        line = "Error vulnerability in license"
        section_keywords = {
            "errors": ["error"],
            "vulnerabilities": ["vulnerability"],
        }

        result = ResponseLineParser._detect_section(line, section_keywords)

        assert result == "errors"
