"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.

Binary I/O utilities for reading and writing binary data.

This module provides shared utilities for reading and analyzing binary files.
"""

import os
from typing import Any

from intellicrack.utils.logger import logger


def find_all_pattern_offsets(data: bytes, pattern: bytes) -> list[int]:
    """Find all occurrences of a pattern in binary data.

    Args:
        data: Binary data to search
        pattern: Pattern to find

    Returns:
        List of offsets where pattern was found

    """
    offsets = []
    offset = 0
    while True:
        pos = data.find(pattern, offset)
        if pos == -1:
            break
        offsets.append(pos)
        offset = pos + 1
    return offsets


def analyze_binary_for_strings(binary_path: str, search_strings: list) -> dict[str, Any]:
    """Analyze a binary file for specific strings.

    Args:
        binary_path: Path to the binary file
        search_strings: List of strings to search for

    Returns:
        Dictionary with analysis results

    """
    results = {
        "strings_found": [],
        "confidence": 0.0,
        "error": None,
    }

    if not binary_path or not os.path.exists(binary_path):
        results["error"] = "Invalid binary path"
        return results

    try:
        with open(binary_path, "rb") as f:
            data = f.read()

        # Search for strings
        found_count = 0
        for search_str in search_strings:
            if search_str.encode() in data:
                results["strings_found"].append(search_str)
                found_count += 1

        # Calculate confidence based on strings found
        if search_strings:
            results["confidence"] = (found_count / len(search_strings)) * 100.0

    except Exception as e:
        logger.error("Exception in binary_io: %s", e)
        results["error"] = str(e)

    return results
