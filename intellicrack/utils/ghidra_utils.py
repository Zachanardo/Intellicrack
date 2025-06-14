"""
Common Ghidra utilities and command builders for Intellicrack.

This module consolidates Ghidra-related utilities to avoid code duplication.
"""

import logging
import os
from typing import List, Optional

logger = logging.getLogger(__name__)


def build_ghidra_command(ghidra_headless_path: str,
                        temp_dir: str,
                        project_name: str,
                        binary_path: str,
                        script_path: str,
                        script_name: str,
                        overwrite: bool = True) -> List[str]:
    """
    Build a standard Ghidra headless command.
    
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
        "-import", binary_path,
        "-scriptPath", script_path,
        "-postScript", script_name
    ]

    if overwrite:
        cmd.append("-overwrite")

    return cmd


def get_ghidra_headless_path() -> Optional[str]:
    """
    Find the Ghidra headless analyzer path.
    
    Returns:
        Path to analyzeHeadless or None if not found
    """
    try:
        from .path_discovery import find_tool
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
        "C:\\Program Files\\ghidra\\support\\analyzeHeadless.bat"
    ]

    for path in common_paths:
        if os.path.exists(path):
            return path

    return None
