"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import re
from typing import Callable, Dict, List, Optional

"""
AI Response Parsing Utilities

Shared utilities for parsing AI responses to eliminate code duplication.
"""


class ResponseLineParser:
    """
    Utility class for parsing AI responses line by line.
    Eliminates duplication across AI parsing modules.
    """

    @staticmethod
    def parse_lines_by_sections(response: str,
                                section_keywords: Dict[str, List[str]],
                                line_processor: Optional[Callable[[str, str], Optional[str]]] = None) -> Dict[str, List[str]]:
        """
        Parse response lines into sections based on keywords.

        Args:
            response: Raw response text to parse
            section_keywords: Dictionary mapping section names to keyword lists
            line_processor: Optional function to process each line (line, section) -> processed_line

        Returns:
            Dictionary mapping section names to lists of content
        """
        sections = {section: [] for section in section_keywords.keys()}
        current_section = None

        lines = response.split("\n")

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Detect section changes
            detected_section = ResponseLineParser._detect_section(
                line, section_keywords)
            if detected_section:
                current_section = detected_section
                continue

            # Process line if we're in a section
            if current_section:
                processed_line = line
                if line_processor:
                    processed_result = line_processor(line, current_section)
                    if processed_result is not None:
                        processed_line = processed_result
                    else:
                        continue  # Skip this line if processor returns None

                sections[current_section].append(processed_line)

        return sections

    @staticmethod
    def parse_lines_with_categorization(response: str,
                                        category_keywords: Dict[str, List[str]],
                                        default_category: str = "other") -> Dict[str, List[str]]:
        """
        Parse response lines and categorize them based on content.

        Args:
            response: Raw response text to parse
            category_keywords: Dictionary mapping categories to detection keywords
            default_category: Default category for unmatched lines

        Returns:
            Dictionary mapping categories to lists of lines
        """
        categories = {cat: [] for cat in category_keywords.keys()}
        if default_category not in categories:
            categories[default_category] = []

        lines = response.split("\n")

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Find matching category
            matched_category = default_category
            for category, keywords in category_keywords.items():
                if any(keyword.lower() in line.lower() for keyword in keywords):
                    matched_category = category
                    break

            categories[matched_category].append(line)

        return categories

    @staticmethod
    def extract_structured_content(response: str,
                                   patterns: List[str],
                                   section_separators: Optional[List[str]] = None) -> List[Dict[str, str]]:
        """
        Extract structured content using regex patterns.

        Args:
            response: Raw response text to parse
            patterns: List of regex patterns to match
            section_separators: Optional list of section separator patterns

        Returns:
            List of dictionaries containing matched content
        """
        extracted = []
        lines = response.split("\n")
        current_section = "content"

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Check for section separators
            if section_separators:
                for separator in section_separators:
                    if re.match(separator, line, re.IGNORECASE):
                        current_section = line
                        continue

            # Try to match patterns
            for i, pattern in enumerate(patterns):
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    content = {
                        "pattern_index": i,
                        "section": current_section,
                        "line": line,
                        "match": match.group(),
                        "groups": match.groups() if match.groups() else []
                    }
                    extracted.append(content)

        return extracted

    @staticmethod
    def _detect_section(line: str, section_keywords: Dict[str, List[str]]) -> Optional[str]:
        """
        Detect which section a line belongs to based on keywords.

        Args:
            line: Line to analyze
            section_keywords: Dictionary mapping section names to keyword lists

        Returns:
            Section name if detected, None otherwise
        """
        line_lower = line.lower()

        for section, keywords in section_keywords.items():
            if any(keyword.lower() in line_lower for keyword in keywords):
                return section

        return None

    @staticmethod
    def clean_and_filter_lines(lines: List[str],
                               min_length: int = 3,
                               filter_patterns: Optional[List[str]] = None) -> List[str]:
        """
        Clean and filter lines based on criteria.

        Args:
            lines: List of lines to clean
            min_length: Minimum line length to keep
            filter_patterns: Optional regex patterns to filter out

        Returns:
            List of cleaned and filtered lines
        """
        cleaned = []

        for line in lines:
            line = line.strip()

            # Skip empty or too short lines
            if not line or len(line) < min_length:
                continue

            # Apply filter patterns
            if filter_patterns:
                skip_line = False
                for pattern in filter_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        skip_line = True
                        break
                if skip_line:
                    continue

            cleaned.append(line)

        return cleaned
