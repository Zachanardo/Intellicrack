"""This file is part of Intellicrack.
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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

"""
Common Ghidra utilities and command builders for Intellicrack.

This module consolidates Ghidra-related utilities to avoid code duplication.
"""

import logging
import os
from typing import List, Optional

logger = logging.getLogger(__name__)


def build_ghidra_command(
    ghidra_headless_path: str,
    temp_dir: str,
    project_name: str,
    binary_path: str,
    script_path: str,
    script_name: str,
    overwrite: bool = True,
) -> list[str]:
    """Build a standard Ghidra headless command.

    Args:
        ghidra_headless_path: Path to analyzeHeadless script
        temp_dir: Temporary directory for Ghidra project
        project_name: Name of the Ghidra project
        binary_path: Path to binary to analyze
        script_path: Directory containing the script
        script_name: Name of the script to run
        overwrite: Whether to overwrite existing project

    Returns:
        List of command arguments

    """
    cmd = [
        ghidra_headless_path,
        temp_dir,
        project_name,
        "-import",
        binary_path,
        "-scriptPath",
        script_path,
        "-postScript",
        script_name,
    ]

    if overwrite:
        cmd.append("-overwrite")

    return cmd


def get_ghidra_headless_path() -> str | None:
    """Find the Ghidra headless analyzer path.

    Returns:
        Path to analyzeHeadless or None if not found

    """
    # First, try to get from config
    try:
        from intellicrack.config import get_config

        config = get_config()
        ghidra_path = config.get_ghidra_path()
        if ghidra_path and os.path.exists(ghidra_path):
            # Check if it's the base directory or the script path
            if os.path.isdir(ghidra_path):
                # If it's a directory, look for analyzeHeadless
                headless_path = os.path.join(ghidra_path, "support", "analyzeHeadless")
                if os.path.exists(headless_path):
                    return headless_path
                headless_path_bat = f"{headless_path}.bat"
                if os.path.exists(headless_path_bat):
                    return headless_path_bat
            else:
                # If it's a file, use it directly
                return ghidra_path
    except ImportError:
        logger.debug("Config module not available, skipping config-based path")

    try:
        from .core.path_discovery import find_tool

        return find_tool("analyzeHeadless")
    except ImportError:
        # Intentionally silent - fall back to manual path checking
        # This is expected when path_discovery module is not available
        logger.debug("path_discovery module not available, using fallback path detection")

    # Common locations to check
    common_paths = [
        "/opt/ghidra/support/analyzeHeadless",
        "/usr/share/ghidra/support/analyzeHeadless",
        "C:\\ghidra\\support\\analyzeHeadless.bat",
        "C:\\Program Files\\ghidra\\support\\analyzeHeadless.bat",
    ]

    return next((path for path in common_paths if os.path.exists(path)), None)
